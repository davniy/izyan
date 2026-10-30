package filesystem

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fedorovmv/izyan/internal/domain"
)

type Store struct {
	Root string
}

func New(root string) *Store { return &Store{Root: root} }

func (s *Store) Create(ctx context.Context, c *domain.AnalysisCase) error {
	return s.Save(ctx, c)
}

// Load decodes one persisted case and enforces the structural result contract.
// A pending root and a legacy single-assessment case stay loadable; publication
// is gated separately (domain.ValidateFinalizedCase and finding.Project).
func (s *Store) Load(_ context.Context, id domain.CaseID) (*domain.AnalysisCase, error) {
	b, err := os.ReadFile(s.path(id))
	if err != nil {
		return nil, err
	}
	var c domain.AnalysisCase
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	recognizeWithdrawnEvidence(&c)
	if err := domain.ValidateCaseResult(&c); err != nil {
		return nil, fmt.Errorf("load case %q: %w", id, err)
	}
	return &c, nil
}

// recognizeWithdrawnEvidence marks the evaluation copy with every historical
// proof the stored case carries but the current contract no longer admits.
//
// A stored content-derived fix binding is the case that matters. The payload is
// preserved verbatim on the model — a load/save cycle must not rewrite history
// — so the loader must also say what it is. Without this marker a replay sees
// an ordinary root-cause model whose derived absence flags and saved verdict
// look checked, and the withdrawal could decay into whatever weaker route the
// record happens to still offer (a retained coordinate binding, a duplicated
// manual label). The marker is never persisted and authorises nothing: the
// shared absence gate refuses the subjects the withdrawn binding names.
func recognizeWithdrawnEvidence(c *domain.AnalysisCase) {
	if c == nil || c.RootCause == nil || c.RootCause.FixBinding == nil {
		return
	}
	c.WithdrawnEvidence = append(c.WithdrawnEvidence, domain.WithdrawnProof{
		Kind:   domain.WithdrawnContentDerivedFixBinding,
		Detail: c.RootCause.FixBinding.Notice(),
	})
}

// Save refuses to persist a case result that violates the result contract. A
// case carrying a FINAL analysis-case/2 envelope must additionally pass the
// publication gate, so a malformed final result is never written as durable
// history. Envelope status — not the workflow position — decides: the pipeline
// finalizes the envelope before BUILD_REPORT and reaches the terminal state
// afterwards.
func (s *Store) Save(_ context.Context, c *domain.AnalysisCase) error {
	if err := domain.ValidateCaseResult(c); err != nil {
		return fmt.Errorf("refuse to save case %q: %w", c.ID, err)
	}
	if c.Schema == domain.CaseSchemaV2 && c.RequestedFinding != nil &&
		c.RequestedFinding.Status == domain.FindingFinal {
		if err := domain.ValidateFinalizedCase(c); err != nil {
			return fmt.Errorf("refuse to save finalized case %q: %w", c.ID, err)
		}
	}
	if err := os.MkdirAll(s.Root, 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path(c.ID) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path(c.ID)); err != nil {
		return fmt.Errorf("atomic save: %w", err)
	}
	return nil
}

func (s *Store) path(id domain.CaseID) string {
	return filepath.Join(s.Root, string(id)+".json")
}

// PriorCase loads the most recently started stored case for the same
// vulnerability and repository, excluding excludeID — the baseline a
// rerun's tool-execution hashes are diffed against. Returns nil when no
// prior run exists or stored cases cannot be read.
func (s *Store) PriorCase(ctx context.Context, vulnID, repo string, excludeID domain.CaseID) *domain.AnalysisCase {
	entries, err := filepath.Glob(filepath.Join(s.Root, "*.json"))
	if err != nil {
		return nil
	}
	var best *domain.AnalysisCase
	for _, p := range entries {
		c, err := s.Load(ctx, domain.CaseID(strings.TrimSuffix(filepath.Base(p), ".json")))
		if err != nil || c.ID == excludeID {
			continue
		}
		if c.Vulnerability.ID != vulnID || c.Product.Repository != repo {
			continue
		}
		if best == nil || c.Workflow.StartedAt.After(best.Workflow.StartedAt) {
			best = c
		}
	}
	return best
}

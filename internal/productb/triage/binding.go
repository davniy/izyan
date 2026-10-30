package triage

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/fedorovmv/izyan/internal/evidencetools"
	"github.com/fedorovmv/izyan/internal/fix"
	domain "github.com/fedorovmv/izyan/internal/productb/domain"
	pbvuln "github.com/fedorovmv/izyan/internal/productb/vulnerability"
	"github.com/fedorovmv/izyan/internal/vulnerability"
)

// DetToolInfo is the adapter-local tool descriptor the deterministic
// broker advertises. It is the canonical evidencetools.ToolContract plus
// this session's resolved availability: name, description, argument schema,
// permission requirement, repeat/cost bounds and observation class are
// copied verbatim from the session CheckSpec, and Available/
// UnavailableReason carry the session-resolved capability answer. Nothing is
// re-derived here — a second capability list, limit constant or
// classification map would be a second contract.
type DetToolInfo struct {
	evidencetools.ToolContract
	Available         bool
	UnavailableReason string
}

// CatalogFromCheckCatalog projects the Shadow evidencetools check catalog
// onto the broker's catalog DTO. Every field — name, agent-facing
// description, argument schema, permission, limits, observation class and
// session availability — comes from the same CheckSpec, so the advertised
// surface, the call gate, the broker's cost bound, the audit classification
// and the MCP registration read one registry.
func CatalogFromCheckCatalog(c evidencetools.CheckCatalog) []DetToolInfo {
	if c == nil {
		return nil
	}
	specs := c.List()
	out := make([]DetToolInfo, 0, len(specs))
	for _, s := range specs {
		out = append(out, DetToolInfo{
			ToolContract:      s.Contract(),
			Available:         s.Available,
			UnavailableReason: s.UnavailableReason,
		})
	}
	return out
}

// ClientCaller adapts an in-memory evidencetools session client
// (*evidencetools.Client) to DetCaller. The session has no direct CallTool
// surface: every call crosses the MCP boundary inside the session, so the
// broker's per-call deadline, catalog gate and audit wrap the same audited
// Observation contract an external agent would see.
type ClientCaller struct {
	Client *evidencetools.Client
}

var _ DetCaller = ClientCaller{}

// CallTool invokes one session tool and returns its Observation verbatim.
func (c ClientCaller) CallTool(ctx context.Context, name string, args json.RawMessage) (*evidencetools.Observation, error) {
	return c.Client.Call(ctx, name, args)
}

// CapturedAdvisorySource serves an evidencetools session's advisory
// research from the run's verified captured record set — nothing else. The
// records were digest-verified by the loader (or by Stage 0 for the selected
// frozen document), so a lookup either returns exactly those bytes or an
// ErrRecordUnavailable answer; there is no transport, no alias search outside
// the set and no fallback to an OSV endpoint.
type CapturedAdvisorySource struct {
	Inputs InvestigationInputs
}

var _ vulnerability.Source = CapturedAdvisorySource{}

// Get returns the advisory record captured under id, its record_id or one of
// its declared aliases. An id outside the captured set is unavailable, never
// a network lookup.
func (s CapturedAdvisorySource) Get(ctx context.Context, id string) (*domain.Vulnerability, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rec, ok := s.Inputs.FindRecord(id)
	if !ok {
		return nil, fmt.Errorf("%w: advisory %q is not in this run's captured record set", evidencetools.ErrRecordUnavailable, strings.TrimSpace(id))
	}
	if len(rec.Raw) == 0 {
		return nil, fmt.Errorf("%w: advisory %q is captured as metadata only", evidencetools.ErrRecordUnavailable, rec.RecordID)
	}
	// A captured record may be non-advisory material — the compatibility
	// transport captures the finding projection itself. Without an OSV `id`
	// member it is not an advisory document and must not be served as one:
	// the answer is a local unavailable, never an invented record. The probe
	// runs before the parser so "not an advisory" stays distinct from
	// "corrupt advisory".
	var probe struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Raw, &probe); err != nil || strings.TrimSpace(probe.ID) == "" {
		return nil, fmt.Errorf("%w: captured material for %q is not an advisory document (no OSV identity)", evidencetools.ErrRecordUnavailable, rec.RecordID)
	}
	v, err := pbvuln.ParseAdvisoryDoc(rec.Raw)
	if err != nil {
		return nil, fmt.Errorf("captured advisory %q: %w", rec.RecordID, err)
	}
	if !capturedRecordOwnsID(rec, v.ID) {
		return nil, fmt.Errorf("%w: captured record %q holds a document identifying %q, which that record does not declare", evidencetools.ErrRecordUnavailable, rec.RecordID, v.ID)
	}
	if v.Provenance == nil {
		v.Provenance = map[string]string{}
	}
	v.Provenance["document"] = "captured:" + rec.RecordID
	if rec.Source != "" {
		v.Provenance["advisory_source"] = rec.Source
	}
	if rec.Partial && v.Provenance["advisory_partial"] == "" {
		v.Provenance["advisory_partial"] = "projection"
	}
	return v, nil
}

// capturedRecordOwnsID reports whether the document's own identity is the
// record's identity or one of its declared aliases. A document claiming an
// identity the captured set does not declare can never be served: aliases
// resolve inside the captured set only.
func capturedRecordOwnsID(rec CapturedRecord, id string) bool {
	if id == "" {
		return false
	}
	want := canonicalVulnID(id)
	if want == rec.RecordID {
		return true
	}
	for _, alias := range rec.Aliases {
		if alias == want {
			return true
		}
	}
	return false
}

// CapturedFixProvider serves evidencetools' fix-diff research from the
// captured fix set only. It implements fix.Provider so the standard
// get_fix_diff handler keeps its contract while the acquisition is the
// recorded bytes: a locator the set does not hold, or one recorded as
// missing/unavailable, is an ErrRecordUnavailable answer — never an HTTP
// fetch.
type CapturedFixProvider struct {
	Inputs InvestigationInputs
}

var _ fix.Provider = CapturedFixProvider{}

// Fetch returns the complete captured bytes of one exact locator. A bare
// locator declared by more than one captured record is ambiguous and
// therefore unavailable: the caller cannot be told which record's bytes it
// received.
func (p CapturedFixProvider) Fetch(ctx context.Context, ref fix.Reference) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	locator := strings.TrimSpace(ref.URL)
	var matched *CapturedFix
	for i := range p.Inputs.Fixes {
		f := &p.Inputs.Fixes[i]
		if f.Locator != locator {
			continue
		}
		if matched != nil {
			return "", fmt.Errorf("%w: fix locator %q is declared by more than one captured record", evidencetools.ErrRecordUnavailable, locator)
		}
		matched = f
	}
	if matched == nil {
		return "", fmt.Errorf("%w: no captured fix for locator %q", evidencetools.ErrRecordUnavailable, locator)
	}
	switch matched.Outcome {
	case CapturedFixCaptured:
		if len(matched.Raw) == 0 {
			return "", fmt.Errorf("%w: fix locator %q is captured as metadata only", evidencetools.ErrRecordUnavailable, locator)
		}
		return string(matched.Raw), nil
	case CapturedFixMissing, CapturedFixUnavailable:
		return "", fmt.Errorf("%w: fix locator %q was recorded as %s for record %q", evidencetools.ErrRecordUnavailable, locator, matched.Outcome, matched.RecordID)
	default:
		return "", fmt.Errorf("%w: fix locator %q has no recorded acquisition outcome", evidencetools.ErrRecordUnavailable, locator)
	}
}

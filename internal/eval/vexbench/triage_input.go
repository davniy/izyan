package vexbench

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/productb/repository"
	"github.com/fedorovmv/izyan/internal/productb/triage"
)

// PreparedCaseSchemaVersion pins the prepared case bundle schema.
const PreparedCaseSchemaVersion = "prepared-case.v1"

// PreparedCase is the shared, blinded input bundle prepared for both Product A and Product B.
// It has NO ground-truth or scorer labels, uses an opaque finding ID, binds exact
// snapshot/commit/content identity, exact advisory/fix/material digests and build selection.
type PreparedCase struct {
	SchemaVersion string                    `json:"schema_version"`
	FindingID     string                    `json:"finding_id"` // opaque hash-based finding ID
	CVEID         string                    `json:"cve_id"`
	RepoPath      string                    `json:"repo_path"`
	CommitSHA     string                    `json:"commit_sha"`
	ContentHash   string                    `json:"content_hash"`
	AdvisoryFile  string                    `json:"advisory_file"`
	AdvisorySHA   string                    `json:"advisory_sha256"`
	AdvisoryCanon string                    `json:"advisory_canonical_sha256"`
	BuildTarget   *domain.ProductTarget     `json:"build_target,omitempty"`
	ProductAInput AgentInput                `json:"product_a_input"`
	ProductBInput triage.FindingInput       `json:"product_b_input"`
	Investigation triage.InvestigationInputs `json:"investigation_inputs"`
}

// ControlJoin records the control-plane link between the benchmark TaskID
// and the opaque FindingID used in PreparedCase. It must be stored outside the agent bundle.
type ControlJoin struct {
	TaskID    string `json:"task_id"`
	FindingID string `json:"finding_id"`
	CVEID     string `json:"cve_id"`
	CommitSHA string `json:"commit_sha"`
}

// OpaqueFindingID computes a deterministic, opaque finding ID from CVE and commit SHA.
// Crucially, it never incorporates TaskID or benchmark metadata, preventing label or task-name leaks.
func OpaqueFindingID(cveID, commitSHA string) string {
	h := sha256.New()
	fmt.Fprintf(h, "finding:%s:%s", strings.TrimSpace(strings.ToUpper(cveID)), strings.TrimSpace(strings.ToLower(commitSHA)))
	sum := h.Sum(nil)
	return fmt.Sprintf("vex-%x", sum[:12])
}

// CaptureRawAdvisory fetches/reads the advisory document without Product A usability filtering.
// Product B receives the captured record even for partial/unsupported advisory documents.
func CaptureRawAdvisory(cve string, fetch Fetcher) (id string, aliases []string, body []byte, sha string, canon string, err error) {
	if fetch == nil {
		fetch = FetchOSV
	}
	body, err = fetch(nil, cve)
	if err != nil {
		return "", nil, nil, "", "", fmt.Errorf("fetch %s: %w", cve, err)
	}
	doc, err := parseAdvisory(body)
	if err != nil {
		return "", nil, nil, "", "", fmt.Errorf("parse %s: %w", cve, err)
	}
	if !identityMatches(doc, cve) {
		return "", nil, nil, "", "", fmt.Errorf("document id %q does not match requested %s", doc.ID, cve)
	}
	sum := sha256.Sum256(body)
	sha = hex.EncodeToString(sum[:])
	canon, err = CanonicalSHA256(body)
	if err != nil {
		return "", nil, nil, "", "", fmt.Errorf("canonical sha256 %s: %w", cve, err)
	}
	return doc.ID, doc.Aliases, body, sha, canon, nil
}

// PrepareTriageCase prepares an immutable PreparedCase bundle from label-free inputs.
func PrepareTriageCase(
	cveID string,
	repoURL string,
	commitSHA string,
	reposDir string,
	frozenAdvisoryDir string,
	bundleDir string,
	buildTarget *domain.ProductTarget,
) (PreparedCase, error) {
	if strings.TrimSpace(cveID) == "" {
		return PreparedCase{}, errors.New("prepare triage case: cve_id is required")
	}
	if strings.TrimSpace(commitSHA) == "" {
		return PreparedCase{}, errors.New("prepare triage case: commit_sha is required")
	}

	// Locate snapshot using the layout: reposDir / owner / repo / commit_sha
	repoPath, err := LocateSnapshotPath(reposDir, repoURL, commitSHA)
	if err != nil {
		return PreparedCase{}, fmt.Errorf("locate snapshot: %w", err)
	}

	contentHash, err := repository.ContentHash(repoPath)
	if err != nil {
		return PreparedCase{}, fmt.Errorf("compute content hash: %w", err)
	}

	// Fetch raw advisory bytes
	fetch := FrozenFetcher(frozenAdvisoryDir)
	docID, aliases, body, sha, canon, err := CaptureRawAdvisory(cveID, fetch)
	if err != nil {
		return PreparedCase{}, fmt.Errorf("capture raw advisory: %w", err)
	}

	findingID := OpaqueFindingID(cveID, commitSHA)
	caseDir := filepath.Join(bundleDir, findingID)
	if err := os.MkdirAll(caseDir, 0o755); err != nil {
		return PreparedCase{}, fmt.Errorf("create bundle dir: %w", err)
	}

	// Save advisory file under bundleDir / findingID / advisory / <id>.json
	advisoryDir := filepath.Join(caseDir, "advisory")
	if err := os.MkdirAll(advisoryDir, 0o755); err != nil {
		return PreparedCase{}, fmt.Errorf("create advisory dir: %w", err)
	}
	safeName := strings.Map(func(r rune) rune {
		if r == '/' || r == '\\' {
			return '_'
		}
		return r
	}, docID)
	advFile := filepath.Join(advisoryDir, safeName+".json")
	if err := os.WriteFile(advFile, body, 0o644); err != nil {
		return PreparedCase{}, fmt.Errorf("write advisory: %w", err)
	}

	// Construct Product A input: explicit field allowlist
	prodA := AgentInput{
		TaskID:    findingID,
		CVEID:     cveID,
		RepoPath:  repoPath,
		CommitSHA: commitSHA,
	}

	// Extract fixes from the raw advisory (if any)
	fixes := extractAdvisoryFixes(docID, sha, body)

	// Check if advisory is partial for Product A usability
	doc, _ := parseAdvisory(body)
	usableGo, totalGo := usableGoEntries(doc)
	partial := totalGo > 0 && usableGo < totalGo

	// Construct Product B InvestigationInputs
	rec := triage.CapturedRecord{
		RecordID: docID,
		Aliases:  aliases,
		SHA256:   sha,
		Size:     int64(len(body)),
		Source:   "frozen_dir:" + docID,
		Partial:  partial,
		Raw:      append([]byte(nil), body...),
	}
	inv := triage.InvestigationInputs{
		Records:     []triage.CapturedRecord{rec},
		Fixes:       fixes,
		BuildTarget: buildTarget,
	}

	// Construct Product B FindingInput
	owner, repo, _ := parseRepoURL(repoURL)
	prodB := triage.FindingInput{
		Finding: triage.Finding{
			SchemaVersion: triage.FindingSchemaVersion,
			FindingID:     findingID,
			Vulnerability: triage.Vulnerability{
				IDs: []string{cveID},
			},
			Component: triage.Component{
				Name:      repo,
				Package:   filepath.Join(owner, repo),
				Version:   commitSHA[:min(7, len(commitSHA))],
				Ecosystem: "go",
			},
			Target: triage.Target{
				Repository: repoPath,
				Revision:   commitSHA,
				Build:      buildTarget,
			},
		},
	}
	rawB, err := json.MarshalIndent(prodB.Finding, "", "  ")
	if err != nil {
		return PreparedCase{}, fmt.Errorf("marshal finding input: %w", err)
	}
	prodB.Raw = rawB
	h := sha256.Sum256(rawB)
	prodB.SHA256 = hex.EncodeToString(h[:])

	pc := PreparedCase{
		SchemaVersion: PreparedCaseSchemaVersion,
		FindingID:     findingID,
		CVEID:         cveID,
		RepoPath:      repoPath,
		CommitSHA:     commitSHA,
		ContentHash:   contentHash,
		AdvisoryFile:  advFile,
		AdvisorySHA:   sha,
		AdvisoryCanon: canon,
		BuildTarget:   buildTarget,
		ProductAInput: prodA,
		ProductBInput: prodB,
		Investigation: inv,
	}

	return pc, nil
}

// VerifyPreparedSnapshotDrift checks that the local repository matches the recorded content hash.
func (p PreparedCase) VerifySnapshotDrift() error {
	current, err := repository.ContentHash(p.RepoPath)
	if err != nil {
		return fmt.Errorf("verify snapshot drift: %w", err)
	}
	if current != p.ContentHash {
		return fmt.Errorf("snapshot drift: recorded content hash %s, repository now hashes %s", p.ContentHash, current)
	}
	return nil
}

// extractAdvisoryFixes pulls genuine fix references from the advisory document.
func extractAdvisoryFixes(docID, recordSHA string, body []byte) []triage.CapturedFix {
	var doc struct {
		References []struct {
			Type string `json:"type"`
			URL  string `json:"url"`
		} `json:"references"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil
	}
	var fixes []triage.CapturedFix
	for _, ref := range doc.References {
		if strings.EqualFold(ref.Type, "FIX") && ref.URL != "" {
			fixes = append(fixes, triage.CapturedFix{
				RecordID:     docID,
				RecordSHA256: recordSHA,
				Locator:      ref.URL,
				Outcome:      triage.CapturedFixUnavailable,
				Source:       "advisory_reference",
			})
		}
	}
	return fixes
}

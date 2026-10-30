package vexbench

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// AdvisoryOutcome classifies what PrepareAdvisory could do with the CVE.
type AdvisoryOutcome int

const (
	// AdvisoryUsable: the saved document carries Go-ecosystem content and
	// every kept Go entry is usable (package name + a valid SEMVER range).
	AdvisoryUsable AdvisoryOutcome = iota
	// AdvisoryPartial: the saved document has at least one usable Go entry
	// but another Go entry without valid ranges — it must not ground
	// safe-negative verdicts on the unbacked entry.
	AdvisoryPartial
	// AdvisoryUnsupported: no usable Go entry anywhere (imports without
	// ranges, GIT-only ranges, non-Go ecosystem); nothing is saved and the
	// case must not turn into a safe result.
	AdvisoryUnsupported
	// AdvisoryError: transport/parse/identity failure — the case fails.
	AdvisoryError
)

// AdvisoryResult describes the prepared (or rejected) advisory document.
type AdvisoryResult struct {
	Outcome         AdvisoryOutcome `json:"outcome"`
	Path            string          `json:"path,omitempty"`
	SHA256          string          `json:"sha256,omitempty"` // raw bytes
	CanonicalSHA256 string          `json:"canonical_sha256,omitempty"`
	Source          string          `json:"source,omitempty"`
	Reason          string          `json:"reason,omitempty"`
	Resolved        string          `json:"resolved,omitempty"`
	Modified        string          `json:"modified,omitempty"`
}

func (o AdvisoryOutcome) String() string {
	switch o {
	case AdvisoryUsable:
		return "usable"
	case AdvisoryPartial:
		return "partial"
	case AdvisoryUnsupported:
		return "unsupported"
	default:
		return "error"
	}
}

// Fetcher retrieves a raw OSV document by vulnerability id. It is
// injectable for tests; nil means FetchOSV (HTTPS GET api.osv.dev).
type Fetcher func(ctx context.Context, id string) ([]byte, error)

// FrozenFetcher reads exactly <dir>/<id>.json and never performs network I/O.
func FrozenFetcher(dir string) Fetcher {
	return func(_ context.Context, id string) ([]byte, error) {
		id = canonicalOSVID(id)
		if id == "" || filepath.Base(id) != id || strings.ContainsAny(id, `/\\`) {
			return nil, fmt.Errorf("frozen advisory %q is invalid", id)
		}
		b, err := os.ReadFile(filepath.Join(dir, id+".json"))
		if err != nil {
			return nil, fmt.Errorf("frozen advisory %s: %w", id, err)
		}
		return b, nil
	}
}

// CanonicalSHA256 hashes JSON after removing insignificant object member
// ordering differences. Array order is preserved.
func CanonicalSHA256(body []byte) (string, error) {
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return "", err
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

const defaultOSVBaseURL = "https://api.osv.dev"

// FetchOSV is the default Fetcher: GET {base}/v1/vulns/<id> on api.osv.dev.
func FetchOSV(ctx context.Context, id string) ([]byte, error) {
	url := defaultOSVBaseURL + "/v1/vulns/" + canonicalOSVID(id)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	hc := &http.Client{Timeout: 30 * time.Second}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv get %s: %w", url, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("osv read %s: %w", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv get %s: status %d: %.200s", url, resp.StatusCode, b)
	}
	return b, nil
}

func canonicalOSVID(id string) string {
	id = strings.TrimSpace(id)
	if strings.HasPrefix(strings.ToUpper(id), "GHSA-") && len(id) > 5 {
		return "GHSA-" + strings.ToLower(id[5:])
	}
	return id
}

// advisoryDocument is the OSV-schema subset needed for usability decisions.
type advisoryDocument struct {
	ID       string             `json:"id"`
	Aliases  []string           `json:"aliases"`
	Modified string             `json:"modified"`
	Affected []advisoryAffected `json:"affected"`
}

type advisoryAffected struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Ranges []advisoryRange `json:"ranges"`
}

type advisoryRange struct {
	Type   string          `json:"type"`
	Events []advisoryEvent `json:"events"`
}

type advisoryEvent struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
}

// PrepareAdvisory resolves a usable OSV advisory for cve: it fetches the
// direct document, falls back to its aliases (GO-* first) when the direct
// document carries no usable Go entry, and writes the first usable document
// as a single file into dir — no siblings, so the analyzer's local alias
// search stays inactive. Usability requires a non-empty package name and at
// least one SEMVER range carrying an introduced/fixed/last_affected event;
// imports without ranges and GIT-only ranges never qualify. A document that
// keeps one usable entry but another Go entry without valid ranges is
// reported as AdvisoryPartial: the analyzer cannot consume it, because the
// affected resolver would read the unusable entry as VersionAffected=FALSE;
// callers must treat partial like unsupported (abstain), not feed it to the
// analysis. Advisory-level failures (transport, parse, identity) return
// Outcome=AdvisoryError; a non-nil error is reserved for filesystem
// failures while saving. fetch may be nil for the default OSV transport.
func PrepareAdvisory(ctx context.Context, cve, dir string, fetch Fetcher) (AdvisoryResult, error) {
	return prepareAdvisory(ctx, cve, dir, fetch, "osv:vulns/")
}

// PrepareFrozenAdvisory prepares an advisory from a required local snapshot.
func PrepareFrozenAdvisory(ctx context.Context, cve, dir, frozenDir string) (AdvisoryResult, error) {
	return prepareAdvisory(ctx, cve, dir, FrozenFetcher(frozenDir), "frozen_dir:")
}

func prepareAdvisory(ctx context.Context, cve, dir string, fetch Fetcher, sourcePrefix string) (AdvisoryResult, error) {
	if fetch == nil {
		fetch = FetchOSV
	}

	body, err := fetch(ctx, cve)
	if err != nil {
		return AdvisoryResult{Outcome: AdvisoryError, Reason: err.Error()}, nil
	}
	doc, err := parseAdvisory(body)
	if err != nil {
		return AdvisoryResult{Outcome: AdvisoryError, Reason: fmt.Sprintf("parse %s: %v", cve, err)}, nil
	}
	if !identityMatches(doc, cve) {
		return AdvisoryResult{Outcome: AdvisoryError,
			Reason: fmt.Sprintf("document id %q does not match requested %s", doc.ID, cve)}, nil
	}

	var firstErr error
	if usable, _ := usableGoEntries(doc); usable > 0 {
		return saveAdvisory(doc, body, dir, sourcePrefix)
	}
	for _, alias := range goFirst(doc.Aliases) {
		abody, err := fetch(ctx, alias)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("alias %s: %w", alias, err)
			}
			continue
		}
		adoc, err := parseAdvisory(abody)
		if err != nil || adoc.ID == "" {
			if firstErr == nil {
				firstErr = fmt.Errorf("alias %s: %v", alias, err)
			}
			continue
		}
		if usable, _ := usableGoEntries(adoc); usable > 0 {
			return saveAdvisory(adoc, abody, dir, sourcePrefix)
		}
	}
	if firstErr != nil {
		return AdvisoryResult{Outcome: AdvisoryError, Reason: firstErr.Error()}, nil
	}
	return AdvisoryResult{Outcome: AdvisoryUnsupported,
		Reason: "no usable Go entry (missing package name or valid SEMVER range)"}, nil
}

// parseAdvisory decodes an OSV document. An empty id or invalid JSON is an
// error — the document cannot be identified or trusted.
func parseAdvisory(b []byte) (advisoryDocument, error) {
	var doc advisoryDocument
	if err := json.Unmarshal(b, &doc); err != nil {
		return doc, err
	}
	if doc.ID == "" {
		return doc, fmt.Errorf("document has no id")
	}
	return doc, nil
}

func identityMatches(doc advisoryDocument, requested string) bool {
	if doc.ID == requested || doc.ID == canonicalOSVID(requested) {
		return true
	}
	for _, a := range doc.Aliases {
		if a == requested || a == canonicalOSVID(requested) {
			return true
		}
	}
	return false
}

// goFirst returns aliases ordered so GO-* identifiers come first, keeping
// the document's relative order inside each group.
func goFirst(aliases []string) []string {
	out := append([]string{}, aliases...)
	sort.SliceStable(out, func(i, j int) bool {
		return strings.HasPrefix(out[i], "GO-") && !strings.HasPrefix(out[j], "GO-")
	})
	return out
}

// usableGoEntries counts the document's Go-ecosystem affected entries and
// how many of them are usable; a non-Go entry is ignored entirely.
func usableGoEntries(doc advisoryDocument) (usable, total int) {
	for _, aff := range doc.Affected {
		if aff.Package.Ecosystem != "Go" {
			continue
		}
		total++
		if usableAffected(aff) {
			usable++
		}
	}
	return usable, total
}

// usableAffected reports whether one affected entry carries Go-ecosystem
// semantic content: a non-empty package name and at least one SEMVER range
// holding an introduced/fixed/last_affected event. Imports without ranges
// do not qualify — they are no evidence of unaffectedness.
func usableAffected(aff advisoryAffected) bool {
	if aff.Package.Name == "" {
		return false
	}
	for _, r := range aff.Ranges {
		if r.Type != "SEMVER" {
			continue
		}
		for _, ev := range r.Events {
			if ev.Introduced != "" || ev.Fixed != "" || ev.LastAffected != "" {
				return true
			}
		}
	}
	return false
}

// saveAdvisory writes the chosen document as the sole file of dir and
// reports its outcome: partial when a kept Go entry lacks usable ranges.
func saveAdvisory(doc advisoryDocument, body []byte, dir, sourcePrefix string) (AdvisoryResult, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return AdvisoryResult{}, fmt.Errorf("create advisory dir: %w", err)
	}
	name := strings.Map(func(r rune) rune {
		if r == '/' || r == '\\' {
			return '_'
		}
		return r
	}, doc.ID)
	path := filepath.Join(dir, name+".json")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		return AdvisoryResult{}, fmt.Errorf("write advisory: %w", err)
	}
	sum := sha256.Sum256(body)
	canonical, err := CanonicalSHA256(body)
	if err != nil {
		return AdvisoryResult{}, fmt.Errorf("canonical advisory digest: %w", err)
	}
	usable, total := usableGoEntries(doc)
	outcome := AdvisoryUsable
	if usable < total {
		outcome = AdvisoryPartial
	}
	return AdvisoryResult{
		Outcome: outcome, Path: path, SHA256: hex.EncodeToString(sum[:]), CanonicalSHA256: canonical,
		Source: sourcePrefix + doc.ID, Resolved: doc.ID, Modified: doc.Modified,
	}, nil
}

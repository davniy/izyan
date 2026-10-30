package evidencetools

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/fix"
)

// ErrRecordUnavailable marks a source answer that is definitive and local:
// the configured set (a captured advisory/fix set, a frozen store) holds no
// record for the requested id or locator. The research handlers answer
// UNSUPPORTED for it — nothing was measured in either direction, no network
// fallback exists, and the agent must not read the answer as a claim about
// the upstream advisory or repository. Every other source error stays a
// tool-side ERROR.
var ErrRecordUnavailable = errors.New("record is not available from the configured source set")

// researchFailure maps a source error onto the observation contract: a
// not-in-the-configured-set answer becomes UNSUPPORTED with the reason,
// anything else remains a handler error (recorded as ERROR by the session).
func (s *Session) researchFailure(tool string, err error) (*Observation, error) {
	if errors.Is(err, ErrRecordUnavailable) {
		return s.unsupported(tool, err.Error()), nil
	}
	return nil, err
}

// ---- get_vulnerability ----

type getVulnerabilityArgs struct{}

type vulnerabilityData struct {
	Vulnerability *domain.Vulnerability `json:"vulnerability"`
	// ResolvedID is the id of the document actually returned (alias
	// resolution may fetch a different record than requested).
	ResolvedID string `json:"resolved_id"`
}

func (s *Session) getVulnerability(ctx context.Context) (*Observation, error) {
	if s.VulnSource == nil {
		return s.unsupported("get_vulnerability", "advisory source not configured (network research disabled)"), nil
	}
	v, err := s.sessionVulnerability(ctx)
	if err != nil {
		return s.researchFailure("get_vulnerability", err)
	}
	data := vulnerabilityData{Vulnerability: v, ResolvedID: v.ID}
	return s.ok("get_vulnerability",
		fmt.Sprintf("normalized advisory record for %s (resolved id %s)", s.CVEID, v.ID),
		fmt.Sprintf("OSV-compatible advisory record for %s", s.CVEID),
		CompletenessComplete, data,
		&ScopeDetails{
			SnapshotHash: s.SnapshotHash,
			ExternalSHA:  s.ExternalSHA,
			Subject:      s.CVEID,
			CoverageRule: "single advisory document fetch (osv/v1/vulns/<id>)",
		},
		vulnLimitations(v)), nil
}

// sessionVulnerability lazily fetches and caches the session CVE's
// normalized record; failures are not cached so a transient fetch error
// can be retried by a later call.
func (s *Session) sessionVulnerability(ctx context.Context) (*domain.Vulnerability, error) {
	s.mu.Lock()
	if s.vulnGot {
		v, err := s.vuln, s.vulnErr
		s.mu.Unlock()
		return v, err
	}
	s.mu.Unlock()
	if s.VulnSource == nil {
		return nil, fmt.Errorf("advisory source not configured (network research disabled)")
	}
	if s.CVEID == "" {
		return nil, fmt.Errorf("no CVE/advisory id configured for this session")
	}
	v, err := s.VulnSource.Get(ctx, s.CVEID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		s.vuln = v
		s.vulnGot = true
	}
	return v, err
}

// vulnLimitations records provenance caveats for advisory data.
func vulnLimitations(v *domain.Vulnerability) []string {
	var lims []string
	if len(v.AffectedSymbols) == 0 {
		lims = append(lims, "advisory declares no affected symbols; symbol-level queries need an explicit subject")
	}
	if len(v.AffectedModules) == 0 && v.Module == "" {
		lims = append(lims, "advisory declares no affected module")
	}
	if v.SeveritySource == "" {
		lims = append(lims, "severity provenance not declared by the advisory source")
	}
	return lims
}

// ---- get_advisory ----

type getAdvisoryArgs struct {
	ID string `json:"id"`
}

func (s *Session) getAdvisory(ctx context.Context, a getAdvisoryArgs) (*Observation, error) {
	if s.VulnSource == nil {
		return s.unsupported("get_advisory", "advisory source not configured (network research disabled)"), nil
	}
	if a.ID == "" {
		return nil, fmt.Errorf("advisory id is required")
	}
	v, err := s.VulnSource.Get(ctx, a.ID)
	if err != nil {
		return s.researchFailure("get_advisory", err)
	}
	return s.ok("get_advisory",
		fmt.Sprintf("advisory record %s fetched (resolved id %s)", a.ID, v.ID),
		fmt.Sprintf("single advisory document %s", a.ID),
		CompletenessComplete,
		vulnerabilityData{Vulnerability: v, ResolvedID: v.ID},
		&ScopeDetails{
			SnapshotHash: s.SnapshotHash,
			Subject:      a.ID,
			CoverageRule: "single advisory document fetch (osv/v1/vulns/<id>)",
		},
		vulnLimitations(v)), nil
}

// ---- get_fix_references ----

type getFixReferencesArgs struct{}

type fixReferencesData struct {
	References []fix.Reference `json:"references"`
	ForID      string          `json:"for_id"`
}

func (s *Session) getFixReferences(ctx context.Context) (*Observation, error) {
	if s.VulnSource == nil {
		return s.unsupported("get_fix_references", "advisory source not configured (network research disabled)"), nil
	}
	v, err := s.sessionVulnerability(ctx)
	if err != nil {
		return s.researchFailure("get_fix_references", err)
	}
	refs := (fix.Resolver{}).Resolve(*v)
	fact := fmt.Sprintf("no fix-bearing references in the advisory record for %s", v.ID)
	if len(refs) > 0 {
		fact = fmt.Sprintf("%d fix-bearing reference(s) in the advisory record for %s", len(refs), v.ID)
	}
	return s.ok("get_fix_references", fact,
		fmt.Sprintf("reference list of advisory %s", v.ID),
		CompletenessComplete,
		fixReferencesData{References: refs, ForID: v.ID},
		&ScopeDetails{
			SnapshotHash: s.SnapshotHash,
			Subject:      v.ID,
			CoverageRule: "all references of the fetched advisory record classified fix-bearing",
		},
		nil), nil
}

// ---- get_fix_diff ----

type getFixDiffArgs struct {
	URL string `json:"url"`
}

type fixDiffData struct {
	URL        string    `json:"url"`
	Diff       string    `json:"diff"`
	Patch      fix.Patch `json:"patch,omitempty"`
	Truncated  bool      `json:"truncated"`
	BytesTotal int       `json:"bytes_total"`
}

const maxFixDiffReturn = 256 << 10

func (s *Session) getFixDiff(ctx context.Context, a getFixDiffArgs) (*Observation, error) {
	if s.PatchSource == nil {
		return s.unsupported("get_fix_diff", "patch provider not configured (network research disabled)"), nil
	}
	if err := checkFetchURL(a.URL); err != nil {
		return nil, err
	}
	text, err := s.PatchSource.Fetch(ctx, fix.Reference{URL: a.URL})
	if err != nil {
		return s.researchFailure("get_fix_diff", err)
	}
	data := fixDiffData{URL: a.URL, Diff: text, Patch: fix.Parse(text), BytesTotal: len(text)}
	var lims []string
	if len(text) > maxFixDiffReturn {
		data.Diff = text[:maxFixDiffReturn]
		data.Truncated = true
		lims = append(lims, fmt.Sprintf("diff text truncated to %d bytes for transport; parsed file/symbol list is complete", maxFixDiffReturn))
	}
	fact := fmt.Sprintf("fix patch fetched from %s (%d bytes, %d file(s))", redactedURL(a.URL), len(text), len(data.Patch))
	return s.ok("get_fix_diff", fact,
		fmt.Sprintf("patch bytes of %s", redactedURL(a.URL)),
		CompletenessComplete, data,
		&ScopeDetails{
			SnapshotHash: s.SnapshotHash,
			Subject:      redactedURL(a.URL),
			CoverageRule: "full patch body fetched within size cap; parsed file list covers all files in the diff",
		}, lims), nil
}

// redactedURL strips query/credentials from a reference for scope output.
func redactedURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "<unparsable url>"
	}
	return u.Host + u.Path
}

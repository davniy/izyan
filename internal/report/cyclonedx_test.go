package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

func cdxCase(verdict domain.Verdict) *domain.AnalysisCase {
	c := &domain.AnalysisCase{
		ID: "TEST-1",
		Vulnerability: domain.Vulnerability{
			ID:     "GHSA-xxxx-yyyy-zzzz",
			Module: "example.com/dep",
		},
		Product: domain.ProductSnapshot{
			Repository: "/tmp/product",
			Commit:     "abc123",
		},
		Affected: &domain.AffectedResult{
			Scope: exactEntryScope("GHSA-xxxx-yyyy-zzzz"),
		},
	}
	if verdict != "" {
		c.Verdict = &domain.VerdictResult{Verdict: verdict, Reason: "r"}
	}
	return c
}

func TestCycloneDXMappings(t *testing.T) {
	cases := []struct {
		verdict domain.Verdict
		state   string
		just    string
	}{
		{domain.VerdictExploitable, "exploitable", ""},
		// The fixture's NOT_AFFECTED carries no affected-chain negative and
		// no grounding claim: no justification may be invented for it.
		{domain.VerdictNotAffected, "not_affected", ""},
		// Likewise a NO_EXPLOIT_PATH_FOUND without a recorded proof must not
		// default to code_not_reachable.
		{domain.VerdictNoExploitPathFound, "not_affected", ""},
		{domain.VerdictInconclusive, "in_triage", ""},
	}
	for _, tc := range cases {
		b, err := CycloneDX(cdxCase(tc.verdict))
		if err != nil {
			t.Fatalf("%s: %v", tc.verdict, err)
		}
		var doc struct {
			BOMFormat       string `json:"bomFormat"`
			SpecVersion     string `json:"specVersion"`
			Vulnerabilities []struct {
				ID       string `json:"id"`
				Analysis struct {
					State         string `json:"state"`
					Justification string `json:"justification"`
				} `json:"analysis"`
			} `json:"vulnerabilities"`
		}
		if err := json.Unmarshal(b, &doc); err != nil {
			t.Fatalf("%s: invalid json: %v", tc.verdict, err)
		}
		if doc.BOMFormat != "CycloneDX" || doc.SpecVersion != "1.5" {
			t.Fatalf("%s: bad envelope: %+v", tc.verdict, doc)
		}
		v := doc.Vulnerabilities[0]
		if v.Analysis.State != tc.state || v.Analysis.Justification != tc.just {
			t.Fatalf("%s: analysis=%+v want state=%s just=%s",
				tc.verdict, v.Analysis, tc.state, tc.just)
		}
	}
}

func TestCycloneDXWrite(t *testing.T) {
	dir := t.TempDir()
	if err := Write(dir, cdxCase(domain.VerdictInconclusive)); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"report.json", "report.md", "openvex.json", "cyclonedx.json"} {
		if !strings.Contains(f, ".") {
			t.Fatal("unreachable")
		}
	}
}

func TestCycloneDXTrustGroundedJustification(t *testing.T) {
	cases := []struct {
		basis string
		want  string
	}{
		{domain.BasisDeclaredTrust, "protected_at_perimeter"},
		{domain.BasisAutoPerimeter, "protected_at_perimeter"},
		{domain.BasisConfigOrigin, "protected_by_mitigating_control"},
	}
	for _, tc := range cases {
		c := cdxCase(domain.VerdictNoExploitPathFound)
		c.Verdict.GroundBasis = tc.basis
		b, err := CycloneDX(c)
		if err != nil {
			t.Fatalf("%s: %v", tc.basis, err)
		}
		var doc struct {
			Vulnerabilities []struct {
				Analysis struct {
					Justification string `json:"justification"`
				} `json:"analysis"`
			} `json:"vulnerabilities"`
		}
		if err := json.Unmarshal(b, &doc); err != nil {
			t.Fatalf("%s: invalid json: %v", tc.basis, err)
		}
		if got := doc.Vulnerabilities[0].Analysis.Justification; got != tc.want {
			t.Errorf("basis %s: justification=%s want %s", tc.basis, got, tc.want)
		}
	}
}

func cdxAnalysisOf(t *testing.T, c *domain.AnalysisCase) struct {
	State         string `json:"state"`
	Justification string `json:"justification"`
	Detail        string `json:"detail"`
} {
	t.Helper()
	b, err := CycloneDX(c)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Vulnerabilities []struct {
			Analysis struct {
				State         string `json:"state"`
				Justification string `json:"justification"`
				Detail        string `json:"detail"`
			} `json:"analysis"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("invalid CycloneDX json: %v", err)
	}
	if len(doc.Vulnerabilities) != 1 {
		t.Fatalf("vulnerabilities=%d want 1", len(doc.Vulnerabilities))
	}
	return doc.Vulnerabilities[0].Analysis
}

// A component-scoped version FALSE must not become a CVE-wide safe state.
// The exact-entry control keeps code_not_reachable.
func TestReportScopeAndConditionRepairCycloneDX(t *testing.T) {
	partial := cdxCase(domain.VerdictNotAffected)
	partial.Affected.VersionAffected = domain.ClaimFalse
	partial.Affected.Scope = partialCVEScope("CVE-2023-44487", "GHSA-xxxx-yyyy-zzzz")
	an := cdxAnalysisOf(t, partial)
	if an.State != "in_triage" {
		t.Fatalf("partial scope exported as %q, want in_triage", an.State)
	}
	if an.Justification != "" {
		t.Fatalf("in_triage must not carry a justification: %q", an.Justification)
	}
	if !strings.Contains(an.Detail, "partial advisory scope") {
		t.Fatalf("detail must name the open scope: %q", an.Detail)
	}

	exact := cdxCase(domain.VerdictNoExploitPathFound)
	if an := cdxAnalysisOf(t, exact); an.State != "not_affected" || an.Justification != "" {
		t.Fatalf("exact-entry NO_EXPLOIT_PATH_FOUND control: %+v", an)
	}
}

// TestCycloneDXProjectionVocabulary checks the projected document against the
// CycloneDX 1.5 VEX vocabulary: every analysis.state is a spec value, a
// justification appears only for not_affected, every affects ref resolves to a
// BOM component, and the witness-bound recommendation is present only for an
// exploitable result.
func TestCycloneDXProjectionVocabulary(t *testing.T) {
	c := reportComposedPositive(t)
	raw, err := CycloneDX(c)
	if err != nil {
		t.Fatalf("cyclonedx: %v", err)
	}
	var doc struct {
		BOMFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		Metadata    struct {
			Component struct {
				BOMRef string `json:"bom-ref"`
			} `json:"component"`
		} `json:"metadata"`
		Components []struct {
			BOMRef string `json:"bom-ref"`
		} `json:"components"`
		Vulnerabilities []struct {
			ID             string `json:"id"`
			Recommendation string `json:"recommendation"`
			Affects        []struct {
				Ref string `json:"ref"`
			} `json:"affects"`
			Analysis struct {
				State         string `json:"state"`
				Justification string `json:"justification"`
			} `json:"analysis"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("invalid CycloneDX json: %v", err)
	}
	if doc.BOMFormat != "CycloneDX" || doc.SpecVersion != "1.5" {
		t.Fatalf("document = %q/%q", doc.BOMFormat, doc.SpecVersion)
	}
	refs := map[string]bool{doc.Metadata.Component.BOMRef: true}
	for _, component := range doc.Components {
		refs[component.BOMRef] = true
	}
	allowed := map[string]bool{
		"resolved": true, "resolved_with_pedigree": true, "exploitable": true,
		"in_triage": true, "false_positive": true, "not_affected": true,
	}
	for _, vulnerability := range doc.Vulnerabilities {
		if !allowed[vulnerability.Analysis.State] {
			t.Fatalf("%s: state %q is not CycloneDX vocabulary", vulnerability.ID, vulnerability.Analysis.State)
		}
		if vulnerability.Analysis.State != "not_affected" && vulnerability.Analysis.Justification != "" {
			t.Fatalf("%s: justification %q for state %q",
				vulnerability.ID, vulnerability.Analysis.Justification, vulnerability.Analysis.State)
		}
		if vulnerability.Analysis.Justification != "" {
			allowedJustifications := map[string]bool{
				"code_not_present":                true,
				"code_not_reachable":              true,
				"requires_configuration":          true,
				"requires_dependency":             true,
				"requires_environment":            true,
				"protected_by_compiler":           true,
				"protected_at_runtime":            true,
				"protected_at_perimeter":          true,
				"protected_by_mitigating_control": true,
			}
			if !allowedJustifications[vulnerability.Analysis.Justification] {
				t.Fatalf("%s: non-CycloneDX justification %q",
					vulnerability.ID, vulnerability.Analysis.Justification)
			}
		}
		if vulnerability.Analysis.State != "exploitable" && vulnerability.Recommendation != "" {
			t.Fatalf("%s: recommendation on a non-exploitable entry", vulnerability.ID)
		}
		for _, affect := range vulnerability.Affects {
			if !refs[affect.Ref] {
				t.Fatalf("%s: affects ref %q does not resolve to a BOM component", vulnerability.ID, affect.Ref)
			}
		}
	}
}

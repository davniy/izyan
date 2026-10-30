package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
)

type vexDocOut struct {
	Statements []struct {
		Status          string `json:"status"`
		Justification   string `json:"justification"`
		ImpactStatement string `json:"impact_statement"`
		ActionStatement string `json:"action_statement"`
		Vulnerability   struct {
			ID string `json:"@id"`
		} `json:"vulnerability"`
		Products []struct {
			ID            string `json:"@id"`
			Subcomponents []struct {
				ID   string `json:"@id"`
				Name string `json:"name"`
			} `json:"subcomponents"`
		} `json:"products"`
	} `json:"statements"`
}

func vexCase(t *testing.T, verdict domain.Verdict) *domain.AnalysisCase {
	t.Helper()
	return &domain.AnalysisCase{
		ID: "case-x",
		Vulnerability: domain.Vulnerability{
			ID:     "GO-2024-0001",
			Module: "example.com/dep",
		},
		Product: domain.ProductSnapshot{
			Repository: t.TempDir(), // no go.mod -> falls back to path
			Commit:     "abc123",
		},
		Affected: &domain.AffectedResult{
			ModulePresent:   domain.ClaimTrue,
			ResolvedVersion: "v1.0.0",
			Scope:           exactEntryScope("GO-2024-0001"),
		},
		Verdict: &domain.VerdictResult{Verdict: verdict, Reason: "test reason"},
	}
}

func decodeVex(t *testing.T, c *domain.AnalysisCase) vexDocOut {
	t.Helper()
	b, err := OpenVEX(c)
	if err != nil {
		t.Fatal(err)
	}
	var d vexDocOut
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatalf("invalid OpenVEX json: %v", err)
	}
	if len(d.Statements) != 1 {
		t.Fatalf("statements=%d want 1", len(d.Statements))
	}
	return d
}

func TestOpenVEXExploitable(t *testing.T) {
	d := decodeVex(t, vexCase(t, domain.VerdictExploitable))
	st := d.Statements[0]
	if st.Status != "affected" {
		t.Fatalf("status=%s want affected", st.Status)
	}
	if !strings.HasSuffix(st.Vulnerability.ID, "/vuln/GO-2024-0001") {
		t.Fatalf("vuln ref: %s", st.Vulnerability.ID)
	}
	if len(st.Products) != 1 || len(st.Products[0].Subcomponents) != 1 ||
		st.Products[0].Subcomponents[0].ID != "pkg:golang/example.com/dep@v1.0.0" {
		t.Fatalf("product subcomponents: %+v", st.Products)
	}
	if !strings.Contains(st.Products[0].ID, "@abc123") {
		t.Fatalf("product must pin the analyzed commit: %s", st.Products[0].ID)
	}
}

func TestOpenVEXNotAffectedJustifications(t *testing.T) {
	c := vexCase(t, domain.VerdictNotAffected)
	c.Affected.ModulePresent = domain.ClaimFalse
	if st := decodeVex(t, c).Statements[0]; st.Justification != "component_not_present" {
		t.Fatalf("justification=%s", st.Justification)
	}
	c.Affected.ModulePresent = domain.ClaimTrue
	c.Affected.VersionAffected = domain.ClaimFalse
	if st := decodeVex(t, c).Statements[0]; st.Justification != "vulnerable_code_not_present" {
		t.Fatalf("justification=%s", st.Justification)
	}
}

func TestOpenVEXNoPathIsNotAffected(t *testing.T) {
	// A negative whose grounding claim/basis was not preserved must not be
	// relabelled as unreachability: no vocabulary entry may be invented.
	st := decodeVex(t, vexCase(t, domain.VerdictNoExploitPathFound)).Statements[0]
	if st.Status != "not_affected" || st.Justification != "" {
		t.Fatalf("got %+v", st)
	}
	if !strings.Contains(st.ImpactStatement, "test reason") {
		t.Fatalf("impact statement lacks the admitted reason: %q", st.ImpactStatement)
	}
}

func TestOpenVEXInconclusiveIsUnderInvestigation(t *testing.T) {
	for _, v := range []domain.Verdict{domain.VerdictInconclusive} {
		st := decodeVex(t, vexCase(t, v)).Statements[0]
		if st.Status != "under_investigation" || st.ActionStatement == "" {
			t.Fatalf("verdict %s: %+v", v, st)
		}
		if st.Justification != "" {
			t.Fatalf("under_investigation must not carry a justification: %+v", st)
		}
	}
}

func TestOpenVEXTrustGroundedJustification(t *testing.T) {
	for _, tc := range []struct {
		basis      string
		wantJust   string
		wantSubstr string
	}{
		{domain.BasisDeclaredTrust, "vulnerable_code_cannot_be_controlled_by_adversary", "declared deployment trust"},
		{domain.BasisAutoPerimeter, "vulnerable_code_cannot_be_controlled_by_adversary", "auto-detected cluster-internal perimeter"},
		{domain.BasisConfigOrigin, "vulnerable_code_cannot_be_controlled_by_adversary", "administrator-managed configuration"},
	} {
		c := vexCase(t, domain.VerdictNoExploitPathFound)
		c.Verdict.GroundBasis = tc.basis
		st := decodeVex(t, c).Statements[0]
		if st.Justification != tc.wantJust {
			t.Errorf("basis %s: justification=%s want %s", tc.basis, st.Justification, tc.wantJust)
		}
		if !strings.Contains(st.ImpactStatement, tc.wantSubstr) {
			t.Errorf("basis %s: impact=%q missing %q", tc.basis, st.ImpactStatement, tc.wantSubstr)
		}
	}
}

// The config-origin verdict is trust-grounded: VEX labels it with the
// adversary-control justification, names the declared policy assumption
// in the impact statement, and never presents the assumption as code
// evidence. The basis text must describe administrator-managed
// configuration, not the old local-host-config wording.
func TestOpenVEXConfigOriginBasisSeparatesPolicy(t *testing.T) {
	c := assumptionsCase()
	c.Affected = &domain.AffectedResult{Scope: exactEntryScope("GO-TEST-0001")}
	c.DeclaredAssumptions = reportAssumptionsInput(
		reportAssumption("ASM-CONFIG-TRUST", domain.AssumptionConfigTrust, domain.AssumptionScopeProduct))
	c.Verdict = &domain.VerdictResult{
		Verdict:       domain.VerdictNoExploitPathFound,
		Reason:        "exact post-reach configuration closure verified",
		GroundBasis:   domain.BasisConfigOrigin,
		AssumptionIDs: []string{"ASM-CONFIG-TRUST"},
		EvidenceIDs:   []domain.EvidenceID{"EV-CFG-1"},
	}
	st := decodeVex(t, c).Statements[0]
	if st.Status != "not_affected" || st.Justification != "vulnerable_code_cannot_be_controlled_by_adversary" {
		t.Fatalf("status/justification = %q/%q", st.Status, st.Justification)
	}
	for _, want := range []string{
		"administrator-managed configuration",
		"declared config-trust policy assumption",
		"policy input, not evidence",
		"ASM-CONFIG-TRUST",
	} {
		if !strings.Contains(st.ImpactStatement, want) {
			t.Fatalf("impact statement lacks %q: %q", want, st.ImpactStatement)
		}
	}
	if strings.Contains(st.ImpactStatement, "local host configuration") {
		t.Fatalf("stale local-host wording survived: %q", st.ImpactStatement)
	}
	for _, id := range c.Verdict.AssumptionIDs {
		for _, ev := range evidenceStrings(c.Verdict.EvidenceIDs) {
			if ev == id {
				t.Fatalf("assumption id %q leaked into evidence ids", id)
			}
		}
	}
}

func evidenceStrings(ids []domain.EvidenceID) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, string(id))
	}
	return out
}

// A component-scoped negative must not leave the case as a CVE-wide
// not_affected statement, even when an older case object carries a closure
// verdict. The exact-entry control keeps the negative export intact.
func TestReportScopeAndConditionRepairOpenVEX(t *testing.T) {
	partial := vexCase(t, domain.VerdictNoExploitPathFound)
	partial.Affected.Scope = partialCVEScope("CVE-2023-44487", "GO-2024-0001")
	partial.Affected.VersionAffected = domain.ClaimFalse
	if st := decodeVex(t, partial).Statements[0]; st.Status != "under_investigation" {
		t.Fatalf("partial scope exported as %q, want under_investigation", st.Status)
	} else if st.Justification != "" {
		t.Fatalf("under_investigation must not carry a justification: %q", st.Justification)
	} else if !strings.Contains(st.ActionStatement, "partial advisory scope") {
		t.Fatalf("action statement must name the open scope: %q", st.ActionStatement)
	}

	exactNA := vexCase(t, domain.VerdictNotAffected)
	exactNA.Affected.ModulePresent = domain.ClaimFalse
	if st := decodeVex(t, exactNA).Statements[0]; st.Status != "not_affected" ||
		st.Justification != "component_not_present" {
		t.Fatalf("exact-entry NOT_AFFECTED control: %+v", st)
	}

	exactNEPF := vexCase(t, domain.VerdictNoExploitPathFound)
	if st := decodeVex(t, exactNEPF).Statements[0]; st.Status != "not_affected" || st.Justification != "" {
		t.Fatalf("exact-entry NO_EXPLOIT_PATH_FOUND control: %+v", st)
	}
}

// TestOpenVEXProjectionVocabulary checks the requested-finding projection
// against the OpenVEX v0.2.0 vocabulary: one statement per published identity,
// a justification only for not_affected, no exported aliases and no custom
// fields invented for scope/profile/build.
func TestOpenVEXProjectionVocabulary(t *testing.T) {
	c := reportComposedPositive(t)
	raw, err := OpenVEX(c)
	if err != nil {
		t.Fatalf("openvex: %v", err)
	}
	var doc struct {
		Context    string `json:"@context"`
		Statements []struct {
			Status          string `json:"status"`
			Justification   string `json:"justification"`
			ImpactStatement string `json:"impact_statement"`
			ActionStatement string `json:"action_statement"`
			Aliases         any    `json:"aliases"`
			Vulnerability   struct {
				ID   string `json:"@id"`
				Name string `json:"name"`
			} `json:"vulnerability"`
		} `json:"statements"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("invalid OpenVEX json: %v", err)
	}
	if doc.Context != "https://openvex.dev/ns/v0.2.0" {
		t.Fatalf("context = %q", doc.Context)
	}
	allowed := map[string]bool{"affected": true, "not_affected": true, "under_investigation": true}
	identities := make(map[string]bool, len(doc.Statements))
	for _, statement := range doc.Statements {
		if !allowed[statement.Status] {
			t.Fatalf("status %q is not OpenVEX vocabulary", statement.Status)
		}
		if statement.Aliases != nil {
			t.Fatalf("statement %q exports an aliases field", statement.Vulnerability.Name)
		}
		if statement.Vulnerability.Name == "" || !strings.HasSuffix(statement.Vulnerability.ID, "/"+statement.Vulnerability.Name) {
			t.Fatalf("vulnerability identity is not a resolvable ref: %+v", statement.Vulnerability)
		}
		// A not_affected statement may carry no justification when no enum
		// truthfully describes the proof; its impact statement then carries
		// the reason. A justification on any other status is invalid.
		if statement.Status != "not_affected" && statement.Justification != "" {
			t.Fatalf("statement %q carries justification %q for status %q",
				statement.Vulnerability.Name, statement.Justification, statement.Status)
		}
		if statement.Justification != "" {
			allowed := map[string]bool{
				"component_not_present":                             true,
				"vulnerable_code_not_present":                       true,
				"vulnerable_code_not_in_execute_path":               true,
				"vulnerable_code_cannot_be_controlled_by_adversary": true,
				"inline_mitigations_already_exist":                  true,
			}
			if !allowed[statement.Justification] {
				t.Fatalf("statement %q carries non-OpenVEX justification %q",
					statement.Vulnerability.Name, statement.Justification)
			}
		}
		identities[statement.Vulnerability.Name] = true
	}
	for _, want := range []string{reportCVE, reportPrimaryRecord, reportChildRecord} {
		if !identities[want] {
			t.Fatalf("statement for %q is missing: %v", want, identities)
		}
	}
}

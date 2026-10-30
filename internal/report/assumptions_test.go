package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fedorovmv/izyan/internal/domain"
)

const reportAssumptionsHeading = "## Declared assumptions — policy/scope inputs, not deterministic evidence"

func reportAssumption(id string, kind domain.DeclaredAssumptionKind, scope string) domain.DeclaredAssumption {
	a := domain.DeclaredAssumption{
		ID:         id,
		Kind:       kind,
		Statement:  "statement for " + id,
		Scope:      scope,
		Authority:  "security-owner",
		Owner:      "platform-security",
		SourceRef:  "policy://" + id,
		ReviewDate: "2027-01-01",
	}
	if kind == domain.AssumptionSupportedTargets {
		a.Targets = &domain.ProductTargetScope{GOOS: []string{"linux"}, GOARCH: []string{"amd64"}}
	}
	a.Digest = domain.CanonicalAssumptionDigest(a)
	return a
}

func reportAssumptionsInput(members ...domain.DeclaredAssumption) *domain.DeclaredAssumptionsInput {
	return &domain.DeclaredAssumptionsInput{
		Path: "local:assumptions.json", SHA256: strings.Repeat("ab", 32),
		Schema:        domain.DeclaredAssumptionsSchema,
		ContentDigest: domain.DeclaredAssumptionsContentDigest(domain.DeclaredAssumptionsSchema, members),
		Assumptions:   members,
	}
}

func assumptionsCase() *domain.AnalysisCase {
	return &domain.AnalysisCase{
		ID: "CASE-ASSUMPTIONS",
		Vulnerability: domain.Vulnerability{
			ID: "GO-TEST-0001", Summary: "test advisory",
			Module: "example.com/dep",
		},
		Product: domain.ProductSnapshot{
			Repository: "example.com/product", Commit: "deadbeef",
			GoVersion: "go1.25.0", GOOS: "linux", GOARCH: "amd64",
		},
		EvidenceGraph: domain.EvidenceGraph{
			Version: "1",
			Evidence: []domain.Evidence{{
				ID: "EV-CFG-1", Kind: domain.EvidenceConfiguration, Quality: domain.QualityDeterministic,
				Source: "goanalysis.TraceArgument", Content: "cfg.Expression <- mapstructure tag", File: "cfg.go", StartLine: 10,
			}},
		},
	}
}

// The assumptions section is separate from the evidence dossier and the
// data-flow audit, and verdicts cite assumption ids in their own line.
func TestDeclaredAssumptionsReportSection(t *testing.T) {
	trust := reportAssumption("ASM-CONFIG-TRUST", domain.AssumptionConfigTrust, domain.AssumptionScopeProduct)
	targets := reportAssumption("ASM-LINUX", domain.AssumptionSupportedTargets, domain.AssumptionScopeProduct)
	c := assumptionsCase()
	c.DeclaredAssumptions = reportAssumptionsInput(trust, targets)
	c.Verdict = &domain.VerdictResult{
		Verdict:       domain.VerdictNoExploitPathFound,
		Reason:        "config-origin trigger falsified",
		EvidenceIDs:   []domain.EvidenceID{"EV-CFG-1"},
		GroundBasis:   domain.BasisConfigOrigin,
		AssumptionIDs: []string{trust.ID},
	}
	for _, lang := range []string{"ru", "en"} {
		md := Markdown(c, lang)
		if !strings.Contains(md, reportAssumptionsHeading) {
			t.Fatalf("%s: assumptions section missing:\n%s", lang, md)
		}
		if !strings.Contains(md, trust.Statement) || !strings.Contains(md, targets.ID) ||
			!strings.Contains(md, "goos `linux`") {
			t.Fatalf("%s: declared members missing:\n%s", lang, md)
		}
		if !strings.Contains(md, "policy/scope inputs") || !strings.Contains(md, trust.ID) {
			t.Fatalf("%s: assumptions not distinguished from evidence:\n%s", lang, md)
		}
		// The assumption section sits outside the evidence dossier: when
		// a dossier is rendered, the section follows it.
		sec := strings.Index(md, reportAssumptionsHeading)
		dossier := strings.Index(md, "## Evidence Dossier")
		if lang == "ru" {
			dossier = strings.Index(md, "## Доказательная база")
		}
		if sec < 0 {
			t.Fatalf("%s: assumptions section missing", lang)
		}
		if dossier >= 0 && sec < dossier {
			t.Fatalf("%s: assumptions section %d not after the evidence dossier %d", lang, sec, dossier)
		}
		if strings.Index(md, "## Technical Details & Audit") > 0 && sec > strings.Index(md, "## Technical Details & Audit") {
			t.Fatalf("%s: assumptions section leaked into the audit block", lang)
		}
	}

	// The machine report keeps the assumption under its own member and
	// never inside the evidence graph.
	jb, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		DeclaredAssumptions *domain.DeclaredAssumptionsInput `json:"declared_assumptions"`
		EvidenceGraph       struct {
			Evidence []struct {
				ID   string `json:"id"`
				Kind string `json:"kind"`
			} `json:"evidence"`
		} `json:"evidence_graph"`
	}
	if err := json.Unmarshal(jb, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.DeclaredAssumptions == nil || len(doc.DeclaredAssumptions.Assumptions) != 2 {
		t.Fatalf("declared_assumptions member = %+v", doc.DeclaredAssumptions)
	}
	for _, e := range doc.EvidenceGraph.Evidence {
		if e.ID == trust.ID || e.ID == targets.ID {
			t.Fatalf("assumption promoted into the evidence graph: %+v", e)
		}
	}
}

// A failed intake is rendered as a fail-closed channel, and its members
// remain audit material only.
func TestDeclaredAssumptionsReportFailedIntake(t *testing.T) {
	trust := reportAssumption("ASM-CONFIG-TRUST", domain.AssumptionConfigTrust, domain.AssumptionScopeProduct)
	c := assumptionsCase()
	c.DeclaredAssumptions = &domain.DeclaredAssumptionsInput{
		Path: "local:bad.json", SHA256: strings.Repeat("cd", 32),
		LoadError: domain.AssumptionsLoadInvalid, Assumptions: []domain.DeclaredAssumption{trust},
	}
	c.Verdict = &domain.VerdictResult{Verdict: domain.VerdictInconclusive, Reason: "policy input missing"}
	md := Markdown(c, "en")
	if !strings.Contains(md, reportAssumptionsHeading) ||
		!strings.Contains(md, "intake failed closed") ||
		!strings.Contains(md, domain.AssumptionsLoadInvalid) {
		t.Fatalf("failed intake not rendered:\n%s", md)
	}
}

// --trusted-peer is a separate deployment assertion: it never creates,
// implies or substitutes for a config-trust assumption.
func TestDeclaredAssumptionsTrustedPeerDoesNotSubstitute(t *testing.T) {
	c := assumptionsCase()
	c.Product.TrustedPeer = true
	c.Verdict = &domain.VerdictResult{
		Verdict:     domain.VerdictNoExploitPathFound,
		Reason:      "declared peer trust",
		GroundBasis: domain.BasisDeclaredTrust,
	}
	md := Markdown(c, "en")
	if strings.Contains(md, reportAssumptionsHeading) {
		t.Fatalf("trusted-peer synthesized an assumptions section:\n%s", md)
	}
	if c.DeclaredAssumptions != nil {
		t.Fatal("trusted-peer synthesized a declared-assumptions record")
	}
	// With a targets-only document the config-trust gate still refuses:
	// the operator's peer assertion is not the administrator-config one.
	targets := reportAssumption("ASM-LINUX", domain.AssumptionSupportedTargets, domain.AssumptionScopeProduct)
	da := reportAssumptionsInput(targets)
	if _, err := domain.AdmitAssumption(da, domain.AssumptionConfigTrust, domain.AssumptionScopeProduct,
		time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)); domain.AssumptionRejectionReason(err) != domain.AssumptionRejectAbsent {
		t.Fatalf("trusted-peer substituted for config-trust: %v", err)
	}
}

// Negative control: declared assumptions render as inputs and never
// create a verdict or a claim.
func TestDeclaredAssumptionsAloneProduceNoVerdict(t *testing.T) {
	trust := reportAssumption("ASM-CONFIG-TRUST", domain.AssumptionConfigTrust, domain.AssumptionScopeProduct)
	c := assumptionsCase()
	c.DeclaredAssumptions = reportAssumptionsInput(trust)
	if c.Verdict != nil || len(c.Claims) != 0 {
		t.Fatal("fixture already carries a verdict/claim")
	}
	md := Markdown(c, "en")
	if !strings.Contains(md, reportAssumptionsHeading) {
		t.Fatalf("assumptions section missing:\n%s", md)
	}
	if strings.Contains(md, "## Verdict:") {
		t.Fatalf("assumption alone produced a verdict section:\n%s", md)
	}
	// The machine report carries the input but no verdict member.
	var doc map[string]any
	if err := json.Unmarshal([]byte(mustJSON(t, c)), &doc); err != nil {
		t.Fatal(err)
	}
	if _, ok := doc["verdict"]; ok {
		t.Fatal("assumption alone produced a machine verdict")
	}
	if _, ok := doc["declared_assumptions"]; !ok {
		t.Fatal("declared_assumptions input missing from the machine report")
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// VEX consumers see the assumption ids as labelled policy inputs; the
// justification vocabulary is not upgraded by their presence.
func TestOpenVEXAssumptionRefs(t *testing.T) {
	c := assumptionsCase()
	c.Affected = &domain.AffectedResult{Scope: exactEntryScope("GO-TEST-0001")}
	c.DeclaredAssumptions = reportAssumptionsInput(
		reportAssumption("ASM-CONFIG-TRUST", domain.AssumptionConfigTrust, domain.AssumptionScopeProduct))
	c.Verdict = &domain.VerdictResult{
		Verdict:       domain.VerdictNoExploitPathFound,
		Reason:        "config-origin trigger falsified",
		GroundBasis:   domain.BasisConfigOrigin,
		AssumptionIDs: []string{"ASM-CONFIG-TRUST"},
	}
	st := decodeVex(t, c).Statements[0]
	if st.Justification != "vulnerable_code_cannot_be_controlled_by_adversary" {
		t.Fatalf("justification = %q", st.Justification)
	}
	if !strings.Contains(st.ImpactStatement, "declared assumptions, policy inputs not evidence: ASM-CONFIG-TRUST") {
		t.Fatalf("impact statement lacks assumption provenance: %q", st.ImpactStatement)
	}
}

// Write is the emission boundary: a dangling or evidence-colliding
// assumption reference never reaches disk, while a properly declared one
// writes every artifact.
func TestDeclaredAssumptionsWriteValidatesRefs(t *testing.T) {
	trust := reportAssumption("ASM-CONFIG-TRUST", domain.AssumptionConfigTrust, domain.AssumptionScopeProduct)

	t.Run("dangling ref rejected", func(t *testing.T) {
		c := assumptionsCase()
		c.Verdict = &domain.VerdictResult{Verdict: domain.VerdictInconclusive, Reason: "x",
			AssumptionIDs: []string{trust.ID}}
		if err := Write(t.TempDir(), c); err == nil ||
			!strings.Contains(err.Error(), "does not resolve to the loaded declared-assumptions document") {
			t.Fatalf("dangling assumption ref written: %v", err)
		}
	})
	t.Run("failed channel admits nothing", func(t *testing.T) {
		c := assumptionsCase()
		c.DeclaredAssumptions = &domain.DeclaredAssumptionsInput{
			Path: "local:bad.json", LoadError: domain.AssumptionsLoadInvalid,
			Assumptions: []domain.DeclaredAssumption{trust},
		}
		c.Verdict = &domain.VerdictResult{Verdict: domain.VerdictInconclusive, Reason: "x",
			AssumptionIDs: []string{trust.ID}}
		if err := Write(t.TempDir(), c); err == nil {
			t.Fatal("failed assumptions channel admitted a verdict reference")
		}
	})
	t.Run("evidence collision rejected", func(t *testing.T) {
		c := assumptionsCase()
		// A member whose id equals an existing evidence id is legal at
		// intake (the id namespace is separate) but can never be cited as
		// both policy and evidence.
		collision := trust
		collision.ID = "EV-CFG-1"
		collision.Digest = domain.CanonicalAssumptionDigest(collision)
		c.DeclaredAssumptions = reportAssumptionsInput(collision)
		c.Verdict = &domain.VerdictResult{Verdict: domain.VerdictInconclusive, Reason: "x",
			AssumptionIDs: []string{"EV-CFG-1"}}
		if err := Write(t.TempDir(), c); err == nil || !strings.Contains(err.Error(), "also resolves as evidence") {
			t.Fatalf("evidence/assumption collision written: %v", err)
		}
	})
	t.Run("declared ref writes", func(t *testing.T) {
		c := assumptionsCase()
		c.DeclaredAssumptions = reportAssumptionsInput(trust)
		c.Verdict = &domain.VerdictResult{Verdict: domain.VerdictInconclusive, Reason: "x",
			AssumptionIDs: []string{trust.ID}}
		dir := t.TempDir()
		if err := Write(dir, c); err != nil {
			t.Fatalf("declared assumption ref rejected: %v", err)
		}
		if _, err := os.Stat(filepath.Join(dir, "openvex.json")); err != nil {
			t.Fatalf("report artifacts missing: %v", err)
		}
	})
}

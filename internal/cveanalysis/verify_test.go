package cveanalysis

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/goanalysis"
)

func verifyFixture(t *testing.T) *goanalysis.Index {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("..", "..", "testdata", "constprod"))
	if err != nil {
		t.Fatal(err)
	}
	return &goanalysis.Index{Dir: abs}
}

func proposalCase() *domain.AnalysisCase {
	return &domain.AnalysisCase{
		Vulnerability: domain.Vulnerability{
			ID:     "GO-TEST-1",
			Module: "example.com/dep",
			AffectedPackages: []domain.AffectedPackage{
				{Path: "example.com/dep/vuln"},
			},
		},
		CVEAnalysis: &domain.CVEAnalysisProposal{
			ID:       "PROP-GO-TEST-1",
			Revision: 1,
			Mechanisms: []domain.DefectMechanism{{
				ID:             "M-1",
				Summary:        "defect in parser",
				FaultingSites:  []string{"example.com/dep/vuln Parse"},
				AuxiliarySites: []string{"example.com/dep/vuln Claims.Valid"},
			}},
		},
	}
}

func findVerification(c *domain.AnalysisCase, assertion domain.ProposalAssertion, check domain.ProposalCheckKind, subject string) *domain.ProposalVerification {
	for i := range c.ProposalVerifications {
		rec := &c.ProposalVerifications[i]
		if rec.Assertion != assertion || rec.Check != check {
			continue
		}
		if subject != "" {
			if rec.Subject == nil || rec.Subject.Package+"."+rec.Subject.Symbol != subject {
				continue
			}
		}
		return rec
	}
	return nil
}

func TestNormalizeSite(t *testing.T) {
	pkgs := []string{"example.com/dep", "example.com/dep/vuln", "gopkg.in/yaml.v2"}
	cases := []struct {
		raw    string
		want   domain.SymbolRef
		wantOK bool
	}{
		{"example.com/dep/vuln Parse", domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Parse"}, true},
		{"gopkg.in/yaml.v2 Decoder.Decode", domain.SymbolRef{Package: "gopkg.in/yaml.v2", Symbol: "Decoder.Decode"}, true},
		{"gopkg.in/yaml.v2 (*Decoder).unmarshal", domain.SymbolRef{Package: "gopkg.in/yaml.v2", Symbol: "(*Decoder).unmarshal"}, true},
		// Legacy dotted form splits only at a known package prefix.
		{"example.com/dep/vuln.Claims.Valid", domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Claims.Valid"}, true},
		// Nested package: longest prefix wins.
		{"example.com/dep/vuln.Parse", domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Parse"}, true},
		// Two-token form is trusted directly — the researcher emits
		// "<pkg> <symbol>" and the advisory list need not name the
		// package.
		{"example.com/dep/vuln.Claims.Valid extra", domain.SymbolRef{Package: "example.com/dep/vuln.Claims.Valid", Symbol: "extra"}, true},
		{"justwords here", domain.SymbolRef{Package: "justwords", Symbol: "here"}, true},
		// Single-token dotted with no known package prefix: never
		// last-dot-split an import path.
		{"other.com/lib.Fn", domain.SymbolRef{}, false},
		{"unresolvable.dotted.path.Fn", domain.SymbolRef{}, false},
		{"", domain.SymbolRef{}, false},
		{"   ", domain.SymbolRef{}, false},
		{"one two three", domain.SymbolRef{}, false},
	}
	for _, tc := range cases {
		got, ok := NormalizeSite(tc.raw, pkgs)
		if ok != tc.wantOK || (ok && got != tc.want) {
			t.Errorf("NormalizeSite(%q) = %+v,%v; want %+v,%v", tc.raw, got, ok, tc.want, tc.wantOK)
		}
	}
}

func TestVerifySitesFoundAbsentUnknown(t *testing.T) {
	c := proposalCase()
	c.CVEAnalysis.Mechanisms[0].FaultingSites = append(
		c.CVEAnalysis.Mechanisms[0].FaultingSites,
		"example.com/dep/vuln NoSuchFunc",
	)
	ix := verifyFixture(t)
	if err := VerifySites(context.Background(), c, ix); err != nil {
		t.Fatal(err)
	}

	found := findVerification(c, domain.AssertionFaultingSite, domain.CheckSymbolExists, "example.com/dep/vuln.Parse")
	if found == nil || found.Result != domain.ClaimTrue {
		t.Fatalf("expected SYMBOL_EXISTS TRUE for Parse: %+v", found)
	}
	if len(found.EvidenceIDs) == 0 {
		t.Fatal("TRUE record must cite the presence evidence")
	}
	if site, checked := c.EvidenceGraph.SymbolDeclFor("example.com/dep/vuln.Parse"); !checked || site == nil {
		t.Fatal("found symbol must populate SymbolDecls")
	}

	absent := findVerification(c, domain.AssertionFaultingSite, domain.CheckSymbolExists, "example.com/dep/vuln.NoSuchFunc")
	if absent == nil || absent.Result != domain.ClaimFalse {
		t.Fatalf("typed absent must be FALSE: %+v", absent)
	}
	if site, checked := c.EvidenceGraph.SymbolDeclFor("example.com/dep/vuln.NoSuchFunc"); !checked || site != nil {
		t.Fatal("typed absent must populate SymbolDecls as checked-not-found")
	}

	// Loader failure → UNKNOWN, not absence.
	broken := proposalCase()
	if err := VerifySites(context.Background(), broken, &goanalysis.Index{Dir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	rec := findVerification(broken, domain.AssertionFaultingSite, domain.CheckSymbolExists, "example.com/dep/vuln.Parse")
	if rec == nil || rec.Result != domain.ClaimUnknown {
		t.Fatalf("load failure must stay UNKNOWN: %+v", rec)
	}
}

func TestVerifySitesNilSourceStillRecords(t *testing.T) {
	c := proposalCase()
	if err := VerifySites(context.Background(), c, nil); err != nil {
		t.Fatal(err)
	}
	// Every displayed assertion gets records even without an index:
	// 2 sites × 3 checks + 1 mechanism = 7.
	if len(c.ProposalVerifications) != 7 {
		t.Fatalf("records=%d, want 7: %+v", len(c.ProposalVerifications), c.ProposalVerifications)
	}
	for _, rec := range c.ProposalVerifications {
		if rec.Result != domain.ClaimUnknown {
			t.Fatalf("nil source must yield UNKNOWN, got %s in %+v", rec.Result, rec)
		}
		if rec.Detail == "" {
			t.Fatalf("UNKNOWN record must explain itself: %+v", rec)
		}
	}
}

func TestVerifySitesUnresolvableSite(t *testing.T) {
	c := proposalCase()
	c.CVEAnalysis.Mechanisms[0].FaultingSites = []string{"mystery dangling reference"}
	if err := VerifySites(context.Background(), c, verifyFixture(t)); err != nil {
		t.Fatal(err)
	}
	var rawRec *domain.ProposalVerification
	for i := range c.ProposalVerifications {
		if c.ProposalVerifications[i].SiteText == "mystery dangling reference" {
			rawRec = &c.ProposalVerifications[i]
		}
	}
	if rawRec == nil {
		t.Fatal("unresolvable site produced no records")
	}
	for i := range c.ProposalVerifications {
		rec := &c.ProposalVerifications[i]
		if rec.SiteText != "mystery dangling reference" {
			continue
		}
		if rec.Subject != nil {
			t.Fatalf("ambiguous site must not gain a subject: %+v", rec)
		}
		if rec.Result != domain.ClaimUnknown {
			t.Fatalf("ambiguous site must stay UNKNOWN: %+v", rec)
		}
	}
}

func TestVerifySitesIdempotent(t *testing.T) {
	c := proposalCase()
	ix := verifyFixture(t)
	if err := VerifySites(context.Background(), c, ix); err != nil {
		t.Fatal(err)
	}
	first := len(c.ProposalVerifications)
	if err := VerifySites(context.Background(), c, ix); err != nil {
		t.Fatal(err)
	}
	if len(c.ProposalVerifications) != first {
		t.Fatalf("re-run duplicated records: %d -> %d", first, len(c.ProposalVerifications))
	}
}

func TestVerifySitesRoleAndMechanismUnknown(t *testing.T) {
	c := proposalCase()
	if err := VerifySites(context.Background(), c, verifyFixture(t)); err != nil {
		t.Fatal(err)
	}
	role := findVerification(c, domain.AssertionFaultingSite, domain.CheckSiteRole, "example.com/dep/vuln.Parse")
	if role == nil || role.Result != domain.ClaimUnknown || role.Detail == "" {
		t.Fatalf("SITE_ROLE must be UNKNOWN with a reason: %+v", role)
	}
	// SYMBOL_EXISTS TRUE does not lift the role check.
	if exists := findVerification(c, domain.AssertionFaultingSite, domain.CheckSymbolExists, "example.com/dep/vuln.Parse"); exists.Result != domain.ClaimTrue {
		t.Fatalf("expected TRUE existence for Parse: %+v", exists)
	}
	mech := findVerification(c, domain.AssertionMechanism, domain.CheckMechanism, "")
	if mech == nil || mech.Result != domain.ClaimUnknown {
		t.Fatalf("MECHANISM must be UNKNOWN: %+v", mech)
	}
}

func TestAttributeChecksUpgradesReachability(t *testing.T) {
	c := proposalCase()
	if err := VerifySites(context.Background(), c, nil); err != nil {
		t.Fatal(err)
	}
	// Simulate evidence arriving later (COLLECT_EVIDENCE).
	c.EvidenceGraph.AddModuleReachable("example.com/dep/vuln.Parse",
		[]string{"example.com/dep/vuln.Dial", "example.com/dep/vuln.Parse"})
	c.EvidenceGraph.AddEvidence(domain.Evidence{
		Kind:    domain.EvidenceSourceSnippet,
		Quality: domain.QualityDeterministic,
		Source:  "source index: module-internal call chain",
		Tool:    "goanalysis.Index.ModuleInternalReach",
		Content: "example.com/dep/vuln.Parse reached from product-used API",
	})
	AttributeChecks(c)
	reach := findVerification(c, domain.AssertionFaultingSite, domain.CheckProductReachable, "example.com/dep/vuln.Parse")
	if reach == nil || reach.Result != domain.ClaimTrue {
		t.Fatalf("persisted chain must confirm PRODUCT_REACHABLE: %+v", reach)
	}
	if len(reach.EvidenceIDs) == 0 {
		t.Fatal("reachability confirmation must cite evidence")
	}
	// The auxiliary site with no chain stays UNKNOWN.
	aux := findVerification(c, domain.AssertionAuxiliarySite, domain.CheckProductReachable, "example.com/dep/vuln.Claims.Valid")
	if aux == nil || aux.Result != domain.ClaimUnknown {
		t.Fatalf("no persisted path must stay UNKNOWN, not FALSE: %+v", aux)
	}
	// And existence is not re-fabricated without a recorded check.
	ex := findVerification(c, domain.AssertionAuxiliarySite, domain.CheckSymbolExists, "example.com/dep/vuln.Claims.Valid")
	if ex.Result != domain.ClaimUnknown {
		t.Fatalf("existence upgraded without a check: %+v", ex)
	}
}

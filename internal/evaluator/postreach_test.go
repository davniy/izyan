package evaluator

import (
	"testing"

	"github.com/davniy/izyan/internal/domain"
)

const postReachTestSink = "example.com/postreachdep/transformer.QueryAll"

func postReachTestCase() (*domain.AnalysisCase, domain.Condition, domain.SinkSite) {
	subject := domain.SymbolRef{Package: "example.com/postreachdep/transformer", Symbol: "QueryAll"}
	cond := domain.Condition{
		ID:       "C-INPUT",
		Kind:     domain.ConditionAttackerControl,
		Subjects: []domain.SymbolRef{subject},
		ArgIndex: 1,
	}
	site := domain.SinkSite{
		CallSite: domain.CallSite{
			File:     "main.go",
			Line:     42,
			Function: "run",
			Package:  "example.com/product",
		},
		Sink:   postReachTestSink,
		Arg:    1,
		Live:   true,
		Origin: domain.OriginConfiguration,
	}
	c := &domain.AnalysisCase{Product: admittedProduct(),
		Vulnerability: domain.Vulnerability{
			ID:              "GO-TEST-CONFIG",
			Module:          "example.com/postreachdep",
			AffectedSymbols: []domain.SymbolRef{subject},
		},
		Affected: &domain.AffectedResult{
			ModulePresent:   domain.ClaimTrue,
			ResolvedVersion: "v1.0.0",
			VersionAffected: domain.ClaimTrue,
			PackagePresent:  domain.ClaimTrue,
			BuildRelevant:   domain.ClaimTrue,
		},
		Exploit: &domain.ExploitModel{
			RootCauses:          []domain.SymbolRef{subject},
			MandatoryConditions: []domain.Condition{cond},
		},
	}
	c.EvidenceGraph.DataFlows = []domain.DataFlow{{
		ConditionID: cond.ID,
		Sink:        site.CallSite,
		Arg:         1,
		Origin:      domain.OriginConfiguration,
		Summary:     "field Expression: config-decode tag",
	}}
	c.EvidenceGraph.Evidence = []domain.Evidence{{
		ID: "DF-01", Kind: domain.EvidenceDataFlow,
	}}
	return c, cond, site
}

func postReachTestClosure(cond domain.Condition, sites ...domain.SinkSite) domain.SinkClosure {
	return domain.SinkClosure{
		ConditionID: cond.ID,
		Module:      "example.com/postreachdep",
		Basis:       "advisory GO-TEST-CONFIG: 1 declared sink subject in example.com/postreachdep@v1.0.0",
		Complete:    true,
		Sites:       sites,
	}
}

func configTrustInput(scope, reviewDate string) *domain.DeclaredAssumptionsInput {
	a := domain.DeclaredAssumption{
		ID:         "ASM-CONFIG-TRUST",
		Kind:       domain.AssumptionConfigTrust,
		Statement:  "administrator-managed configuration is outside the attacker model",
		Scope:      scope,
		Authority:  "platform-security",
		Owner:      "platform-security",
		SourceRef:  "policy:threat-model",
		ValidFrom:  "2020-01-01",
		ReviewDate: reviewDate,
	}
	a.Digest = domain.CanonicalAssumptionDigest(a)
	return &domain.DeclaredAssumptionsInput{
		Path:        "local:assumptions.json",
		Schema:      domain.DeclaredAssumptionsSchema,
		Assumptions: []domain.DeclaredAssumption{a},
	}
}

func withConfigTrust(c *domain.AnalysisCase) *domain.AnalysisCase {
	c.DeclaredAssumptions = configTrustInput(domain.AssumptionScopeProduct, "2999-12-31")
	return c
}

func TestPostReachConfigClosesWithExactArgument(t *testing.T) {
	c, cond, site := postReachTestCase()
	c.EvidenceGraph.AddSinkClosure(postReachTestClosure(cond, site))
	withConfigTrust(c)

	claim := (ArgumentOrigin{}).Evaluate(cond, c)
	if claim.Result != domain.ClaimFalse {
		t.Fatalf("result=%s want FALSE (limitations: %v)", claim.Result, claim.Limitations)
	}
	if claim.Falsifier != domain.FalsifierTrustedInfrastructure || claim.FalsifierBasis != domain.BasisConfigOrigin {
		t.Fatalf("falsifier=%s basis=%s", claim.Falsifier, claim.FalsifierBasis)
	}
	if claim.Producer != postReachProducer {
		t.Fatalf("producer=%q want post-reach route", claim.Producer)
	}
	if len(claim.AssumptionIDs) != 1 || claim.AssumptionIDs[0] != "ASM-CONFIG-TRUST" {
		t.Fatalf("assumption ids=%v", claim.AssumptionIDs)
	}
	for _, id := range claim.EvidenceIDs {
		if string(id) == "ASM-CONFIG-TRUST" {
			t.Fatal("assumption id leaked into EvidenceIDs")
		}
	}
}

func TestPostReachConfigRequiresAssumption(t *testing.T) {
	c, cond, site := postReachTestCase()
	c.EvidenceGraph.AddSinkClosure(postReachTestClosure(cond, site))
	claim := (ArgumentOrigin{}).Evaluate(cond, c)
	if claim.Result != domain.ClaimUnknown || claim.Falsifier != "" {
		t.Fatalf("configuration origin without assumption closed: %+v", claim)
	}
}

func TestPostReachConfigExpiredAssumption(t *testing.T) {
	c, cond, site := postReachTestCase()
	c.EvidenceGraph.AddSinkClosure(postReachTestClosure(cond, site))
	c.DeclaredAssumptions = configTrustInput(domain.AssumptionScopeProduct, "2020-01-02")
	claim := (ArgumentOrigin{}).Evaluate(cond, c)
	if claim.Result != domain.ClaimUnknown || claim.Falsifier != "" {
		t.Fatalf("expired assumption closed: %+v", claim)
	}
}

func TestPostReachConfigScopeMismatch(t *testing.T) {
	c, cond, site := postReachTestCase()
	c.EvidenceGraph.AddSinkClosure(postReachTestClosure(cond, site))
	c.DeclaredAssumptions = configTrustInput(domain.AssumptionScopeDeployment, "2999-12-31")
	claim := (ArgumentOrigin{}).Evaluate(cond, c)
	if claim.Result != domain.ClaimUnknown || claim.Falsifier != "" {
		t.Fatalf("deployment-scoped assumption satisfied a product requirement: %+v", claim)
	}
}

func TestPostReachConfigExternalWriteBlocks(t *testing.T) {
	c, cond, site := postReachTestCase()
	site.Origin = domain.OriginExternalUntrusted
	c.EvidenceGraph.DataFlows[0].Origin = domain.OriginExternalUntrusted
	c.EvidenceGraph.SinkClosures = nil
	c.EvidenceGraph.AddSinkClosure(postReachTestClosure(cond, site))
	withConfigTrust(c)

	claim := (ArgumentOrigin{}).Evaluate(cond, c)
	if claim.Result == domain.ClaimFalse && claim.Falsifier == domain.FalsifierTrustedInfrastructure {
		t.Fatalf("external write grounded a config falsifier: %+v", claim)
	}
}

func TestPostReachConfigUnresolvedAliasBlocks(t *testing.T) {
	c, cond, site := postReachTestCase()
	site.Origin = domain.OriginUnknown
	c.EvidenceGraph.DataFlows[0].Origin = domain.OriginUnknown
	c.EvidenceGraph.SinkClosures = nil
	c.EvidenceGraph.AddSinkClosure(postReachTestClosure(cond, site))
	withConfigTrust(c)

	claim := (ArgumentOrigin{}).Evaluate(cond, c)
	if claim.Result != domain.ClaimUnknown || claim.Falsifier != "" {
		t.Fatalf("unresolved alias grounded a config falsifier: %+v", claim)
	}
}

func TestPostReachConfigRequiresPositiveReach(t *testing.T) {
	c, cond, _ := postReachTestCase()
	c.EvidenceGraph.AddSinkClosure(postReachTestClosure(cond))
	withConfigTrust(c)

	claim := (ArgumentOrigin{}).Evaluate(cond, c)
	if claim.Result != domain.ClaimUnknown || claim.Falsifier != "" {
		t.Fatalf("module usage / empty closure grounded a post-reach falsifier: %+v", claim)
	}
}

func TestPostReachConfigRequiresExactArgBinding(t *testing.T) {
	c, cond, site := postReachTestCase()
	site.Arg = 0
	c.EvidenceGraph.SinkClosures = nil
	c.EvidenceGraph.AddSinkClosure(postReachTestClosure(cond, site))
	withConfigTrust(c)

	claim := (ArgumentOrigin{}).Evaluate(cond, c)
	if claim.Result != domain.ClaimUnknown || claim.Falsifier != "" {
		t.Fatalf("wrong-argument site grounded a post-reach falsifier: %+v", claim)
	}
}

func TestPostReachConfigRequiresCompleteSinkCoverage(t *testing.T) {
	c, cond, site := postReachTestCase()
	other := domain.SinkSite{
		CallSite: domain.CallSite{File: "other.go", Line: 9, Function: "runOther", Package: "example.com/product"},
		Sink:     "example.com/postreachdep/transformer.Find",
		Arg:      1,
		Live:     true,
		Origin:   domain.OriginConfiguration,
	}
	closure := postReachTestClosure(cond, site, other)
	closure.Complete = false
	closure.Blockers = []string{"declared sink Find has an unresolved caller"}
	c.EvidenceGraph.AddSinkClosure(closure)
	withConfigTrust(c)

	claim := (ArgumentOrigin{}).Evaluate(cond, c)
	if claim.Result != domain.ClaimUnknown || claim.Falsifier != "" {
		t.Fatalf("incomplete multi-sink closure grounded a post-reach falsifier: %+v", claim)
	}
}

func TestPostReachConfigRequiresAdvisoryBasis(t *testing.T) {
	c, cond, site := postReachTestCase()
	closure := postReachTestClosure(cond, site)
	closure.Basis = ""
	c.EvidenceGraph.AddSinkClosure(closure)
	withConfigTrust(c)

	claim := (ArgumentOrigin{}).Evaluate(cond, c)
	if claim.Result != domain.ClaimUnknown || claim.Falsifier != "" {
		t.Fatalf("KNOWN_ONLY closure grounded a post-reach falsifier: %+v", claim)
	}
}

// Ingress items never substitute for the exact sink/argument closure —
// not even a complete all-safe ingress inventory.
func TestPostReachConfigIngressCannotSubstitute(t *testing.T) {
	c, cond, _ := postReachTestCase()
	c.EvidenceGraph.AddIngressClosure(domain.IngressClosure{
		ConditionID: cond.ID,
		Module:      "example.com/postreachdep",
		Complete:    true,
		Items:       []domain.IngressItem{{Kind: domain.IngressBoundaryArg, Origin: domain.OriginConstant}},
	})
	withConfigTrust(c)

	claim := (ArgumentOrigin{}).Evaluate(cond, c)
	if claim.Result != domain.ClaimUnknown || claim.Falsifier != "" {
		t.Fatalf("ingress closure substituted for the exact sink closure: %+v", claim)
	}
}

// A stored post-reach FALSE is re-validated by closureGate: removing the
// exact-site DataFlow demotes it.
func TestPostReachClosureGateDemotesStaleClaim(t *testing.T) {
	c, cond, site := postReachTestCase()
	c.EvidenceGraph.AddSinkClosure(postReachTestClosure(cond, site))
	withConfigTrust(c)
	claim := (ArgumentOrigin{}).Evaluate(cond, c)
	if claim.Result != domain.ClaimFalse {
		t.Fatalf("setup: %+v", claim)
	}
	// Keep the closure but drop the exact argument flow.
	c.EvidenceGraph.DataFlows = nil
	out := closureGate(c, claim, c.EvidenceGraph.IngressClosureFor(cond.ID),
		c.EvidenceGraph.SinkClosureFor(cond.ID), 0, nil)
	if out.Result != domain.ClaimUnknown || out.Falsifier != "" {
		t.Fatalf("stale post-reach claim survived closureGate: %+v", out)
	}
}

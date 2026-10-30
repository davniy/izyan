package goanalysis

import (
	"context"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

// The verifier gate runs before every verification route: a build-dependent
// negative needs an admitted target and a source index bound to the same
// build, and each route stamps the effective build context.
func TestVerifyFalseTarget(t *testing.T) {
	cond := domain.Condition{
		ID: "C-LOCUS", Params: map[string]string{domain.ParamCheck: domain.CheckLocus},
		Subjects: []domain.SymbolRef{{Package: "example.com/lib/internal/xds/server", Symbol: "RouteAndProcess"}},
	}
	claim := domain.Claim{ID: "CL-C-LOCUS", ConditionID: "C-LOCUS", Result: domain.ClaimFalse,
		Falsifier: domain.FalsifierLocusPackageAbsent}

	host := &domain.AnalysisCase{Product: hostProduct()}
	out := (Verifier{}).VerifyFalse(context.Background(), host, claim, cond)
	if out.NegativeVerification == nil || out.NegativeVerification.Status != domain.NegativeInsufficientScope {
		t.Fatalf("host-default negative verified: %+v", out.NegativeVerification)
	}
	if out.NegativeVerification.BuildContext == nil {
		t.Fatal("early refusal route must stamp the build context")
	}

	c := locusTestCase("example.com/prod")
	out = (Verifier{}).VerifyFalse(context.Background(), c, claim, cond)
	if out.NegativeVerification == nil || out.NegativeVerification.Status != domain.NegativeVerified {
		t.Fatalf("admitted package absence = %+v", out.NegativeVerification)
	}
	if out.NegativeVerification.BuildContext == nil ||
		out.NegativeVerification.BuildContext.Matches(domain.EffectiveBuildContext(c.Product)) != nil {
		t.Fatalf("verified negative context = %+v", out.NegativeVerification.BuildContext)
	}

	// A source index bound to another build cannot ground the case's negative.
	foreign := testProduct()
	foreign.Commit = "another-build"
	ix := boundTestIndex(&Index{Dir: t.TempDir()})
	ix.Build = foreign
	guardCond := domain.Condition{ID: "C-V"}
	guardClaim := domain.Claim{ID: "CL-C-V", ConditionID: "C-V", Result: domain.ClaimFalse,
		Falsifier: domain.FalsifierGuards}
	out = (Verifier{Source: ix}).VerifyFalse(context.Background(),
		&domain.AnalysisCase{Product: testProduct()}, guardClaim, guardCond)
	if out.NegativeVerification == nil || out.NegativeVerification.Status != domain.NegativeInsufficientScope {
		t.Fatalf("mismatched source index verified: %+v", out.NegativeVerification)
	}

	// Independent bases (declared trust) verify without a product target.
	trusted := domain.Claim{ID: "CL-C-I", ConditionID: "C-I", Result: domain.ClaimFalse,
		Falsifier: domain.FalsifierTrustedInfrastructure, FalsifierBasis: domain.BasisDeclaredTrust}
	trustedCase := &domain.AnalysisCase{Product: domain.ProductSnapshot{TrustedPeer: true}}
	trustedIndex := boundTestIndex(&Index{Dir: t.TempDir()})
	out = (Verifier{Source: trustedIndex}).VerifyFalse(context.Background(), trustedCase, trusted,
		domain.Condition{ID: "C-I", Subjects: []domain.SymbolRef{{Package: "example.com/dep", Symbol: "Sink"}}})
	if out.NegativeVerification == nil || out.NegativeVerification.Status != domain.NegativeVerified {
		t.Fatalf("independent negative refused: %+v", out.NegativeVerification)
	}
	if out.NegativeVerification.BuildContext != nil {
		t.Fatal("independent negative must not carry a build context")
	}
}

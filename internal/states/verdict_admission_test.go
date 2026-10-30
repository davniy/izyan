package states_test

import (
	"context"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/evaluator"
	"github.com/fedorovmv/izyan/internal/states"
)

func verdictProduct() domain.ProductSnapshot {
	p := domain.ProductSnapshot{
		Repository: "/test/product", Commit: "verdict-commit",
		GOOS: "linux", GOARCH: "amd64",
	}
	p.Target = &domain.ProductTarget{
		GOOS: "linux", GOARCH: "amd64",
		Source: domain.ProductTargetSourceOperatorDeclared,
		Scope:  domain.ProductTargetScopeOperator,
	}
	return p
}

func verdictScope() *domain.AdvisoryScope {
	return exactScope("GO-TEST-1")
}

func runVerdictCase(t *testing.T, c *domain.AnalysisCase) *domain.AnalysisCase {
	t.Helper()
	if _, err := (states.EvaluateVerdict{Evaluator: evaluator.VerdictEvaluator{}}).Run(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	return c
}

func runVerdict(t *testing.T, c *domain.AnalysisCase) domain.VerdictResult {
	t.Helper()
	c = runVerdictCase(t, c)
	if c.Verdict == nil {
		t.Fatal("verdict state did not set a verdict")
	}
	return *c.Verdict
}

func verdictCase(p domain.ProductSnapshot, claim domain.Claim) *domain.AnalysisCase {
	return &domain.AnalysisCase{
		Product: p,
		Affected: &domain.AffectedResult{
			Scope:           verdictScope(),
			ModulePresent:   domain.ClaimTrue,
			VersionAffected: domain.ClaimTrue,
			PackagePresent:  domain.ClaimTrue,
			BuildRelevant:   domain.ClaimTrue,
		},
		Exploit: &domain.ExploitModel{
			MandatoryConditions: []domain.Condition{{ID: "C1"}},
		},
		Claims: []domain.Claim{claim},
	}
}

// A persisted VERIFIED negative must carry the measurement identity it ran
// under; without it the claim is UNKNOWN and cannot ground NEPF.
func TestPersistedVerifiedRequiresBuildContext(t *testing.T) {
	p := verdictProduct()
	claim := domain.Claim{
		ConditionID: "C1", Result: domain.ClaimFalse,
		Falsifier: domain.FalsifierConstantOrGeneratedInput,
		NegativeVerification: &domain.NegativeVerification{
			Status: domain.NegativeVerified,
		},
	}
	gotCase := runVerdictCase(t, verdictCase(p, claim))
	if gotCase.Verdict != nil {
		t.Fatalf("contextless persisted verification grounded %s", gotCase.Verdict.Verdict)
	}
	if !hasAnalysisGap(gotCase, domain.GapNegativeVerificationIncomplete) {
		t.Fatalf("contextless refusal lacks its typed cause: %+v", gotCase.AnalysisGaps)
	}
	build := domain.EffectiveBuildContext(p)
	claim.NegativeVerification = &domain.NegativeVerification{
		Status: domain.NegativeVerified, BuildContext: &build,
	}
	got := runVerdict(t, verdictCase(p, claim))
	if got.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("admitted persisted verification = %s (%s)", got.Verdict, got.Reason)
	}
}

// Independent negatives (declared trust) do not describe a build and stay
// usable under a host-default snapshot.
func TestIndependentNegativeSurvivesHostDefault(t *testing.T) {
	claim := domain.Claim{
		ConditionID: "C1", Result: domain.ClaimFalse,
		Falsifier:      domain.FalsifierTrustedInfrastructure,
		FalsifierBasis: domain.BasisDeclaredTrust,
		NegativeVerification: &domain.NegativeVerification{
			Status: domain.NegativeVerified,
		},
	}
	host := domain.ProductSnapshot{GOOS: "linux", GOARCH: "amd64"}
	got := runVerdict(t, verdictCase(host, claim))
	if got.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("independent negative refused: %s (%s)", got.Verdict, got.Reason)
	}
}

// A host-default analysis context can never ground a build-dependent
// negative, even when the verification record itself is otherwise complete
// and context-bound. This is the explicit refusal case (no fixture default).
func TestHostDefaultNegativeRefused(t *testing.T) {
	host := domain.ProductSnapshot{GOOS: "linux", GOARCH: "amd64"}
	build := domain.EffectiveBuildContext(host)
	claim := domain.Claim{
		ConditionID: "C1", Result: domain.ClaimFalse,
		Falsifier: domain.FalsifierConstantOrGeneratedInput,
		NegativeVerification: &domain.NegativeVerification{
			Status: domain.NegativeVerified, BuildContext: &build,
		},
	}
	refused := runVerdictCase(t, verdictCase(host, claim))
	if refused.Verdict != nil {
		t.Fatalf("host-default negative grounded %s", refused.Verdict.Verdict)
	}
	if !hasAnalysisGap(refused, domain.GapNegativeVerificationIncomplete) {
		t.Fatalf("host-default refusal lacks its typed cause: %+v", refused.AnalysisGaps)
	}
	found := false
	for _, gap := range refused.AnalysisGaps {
		if strings.Contains(gap.Message, "no product target") || strings.Contains(gap.Message, "host defaults") {
			found = true
		}
	}
	if !found {
		t.Fatalf("refusal reason missing: %+v", refused.AnalysisGaps)
	}
}

package triage

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func composeArbitration(t *testing.T, s0 Stage0Result, verdict Verdict) DecisionPackage {
	t.Helper()
	a := goodAssessment()
	a.Verdict = verdict
	pkg, err := Composer{}.ComposeWithEvidence(context.Background(), s0, a, completeValidation(), EvidenceInput{})
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	return pkg
}

// TestArbitrationAgreementDismisses pins the automatic machine reduction: the
// machine rules and the model judgment agree that nothing is exploitable, and
// the judgment travels verbatim on its own axis.
func TestArbitrationAgreementDismisses(t *testing.T) {
	pkg := composeArbitration(t, versionRangeStage0(CheckVersionConfirmed), VerdictNotExploitable)
	if got := pkg.MachineDisposition.Recommendation; got != RecommendationDismissed {
		t.Fatalf("machine recommendation = %s", got)
	}
	if pkg.MachineDisposition.Arbitration != ArbitrationAgreeDismiss {
		t.Fatalf("arbitration = %s", pkg.MachineDisposition.Arbitration)
	}
	if pkg.Judgment.Verdict != VerdictNotExploitable {
		t.Fatalf("judgment verdict = %q", pkg.Judgment.Verdict)
	}
}

// TestArbitrationDivergenceWithholdsMachineReduction pins the machine
// safeguard: a deterministic reduction the model contradicts is never applied
// automatically. The package is emitted with the machine disposition withheld
// and the proposal preserved.
func TestArbitrationDivergenceWithholdsMachineReduction(t *testing.T) {
	pkg := composeArbitration(t, versionRangeStage0(CheckVersionConfirmed), VerdictExploitable)
	if got := pkg.MachineDisposition.Recommendation; got != RecommendationUnchanged {
		t.Fatalf("machine recommendation = %s (divergence must not reduce)", got)
	}
	if pkg.TechnicalAssessment.Status != TechStatusNeedsArbitration {
		t.Fatalf("status = %s", pkg.TechnicalAssessment.Status)
	}
	if pkg.MachineDisposition.Arbitration != ArbitrationDivergeHuman {
		t.Fatalf("arbitration = %s", pkg.MachineDisposition.Arbitration)
	}
	if pkg.MachineDisposition.Automation != AutomationWarn {
		t.Fatalf("automation = %s, want WARN for a withheld reduction", pkg.MachineDisposition.Automation)
	}
	if pkg.ProposedAction.Instruction != goodAssessment().ProposedAction.Instruction {
		t.Fatalf("the machine divergence rewrote the proposed action: %+v", pkg.ProposedAction)
	}
	md := string(RenderDecisionMarkdown(pkg))
	for _, want := range []string{"## Machine disposition", "DIVERGE_HUMAN", "proposed action above stands unchanged"} {
		if !strings.Contains(md, want) {
			t.Fatalf("markdown lacks %q:\n%s", want, md)
		}
	}
}

// TestArbitrationUnconfirmedNegativeKeepsProposal pins the symmetric case: an
// unproved negative judgment the machine rules cannot confirm is a machine
// limitation, not a request that displaces the human proposal.
func TestArbitrationUnconfirmedNegativeKeepsProposal(t *testing.T) {
	s0 := versionRangeStage0(CheckAffectedRange)
	s0.Materials.Deploy = nil // no lowering basis: the machine layer holds no reduction
	want := goodAssessment()
	pkg := composeArbitration(t, s0, VerdictNotExploitable)
	if got := pkg.MachineDisposition.Recommendation; got != RecommendationUnchanged {
		t.Fatalf("machine recommendation = %s", got)
	}
	if pkg.TechnicalAssessment.Status != TechStatusNeedsArbitration {
		t.Fatalf("status = %s", pkg.TechnicalAssessment.Status)
	}
	found := false
	for _, l := range pkg.TechnicalAssessment.Limitations {
		if strings.Contains(l, "proposed action is unaffected") {
			found = true
		}
	}
	if !found {
		t.Fatalf("limitations = %v", pkg.TechnicalAssessment.Limitations)
	}
	if !reflect.DeepEqual(pkg.ProposedAction, want.ProposedAction) {
		t.Fatalf("the unconfirmed negative replaced the proposed action:\n got %+v\nwant %+v", pkg.ProposedAction, want.ProposedAction)
	}
	if pkg.Judgment.Verdict != VerdictNotExploitable {
		t.Fatalf("judgment verdict = %q", pkg.Judgment.Verdict)
	}
	md := string(RenderDecisionMarkdown(pkg))
	if !strings.Contains(md, want.ProposedAction.Instruction) {
		t.Fatalf("markdown dropped the proposed action:\n%s", md)
	}
}

// TestArbitrationAgreementKeep pins the neutral case: neither side claims a
// reduction, so the machine disposition stays UNCHANGED without divergence.
func TestArbitrationAgreementKeep(t *testing.T) {
	s0 := versionRangeStage0(CheckAffectedRange)
	s0.Materials.Deploy = nil
	pkg := composeArbitration(t, s0, VerdictExploitable)
	if pkg.MachineDisposition.Recommendation != RecommendationUnchanged ||
		pkg.MachineDisposition.Arbitration != ArbitrationAgreeKeep {
		t.Fatalf("package = %s/%s", pkg.MachineDisposition.Recommendation, pkg.MachineDisposition.Arbitration)
	}
	if pkg.TechnicalAssessment.Status == TechStatusNeedsArbitration {
		t.Fatal("neutral agreement escalated")
	}
}

// TestArbitrationLoweringRequiresAgreement pins the LOWERED path: perimeter
// lowering applies only when the model also says the finding is not
// exploitable.
func TestArbitrationLoweringRequiresAgreement(t *testing.T) {
	s0 := goodStage0()
	s0.Materials.Deploy = &DeployFacts{Perimeter: "cluster-internal"}
	pkg := composeArbitration(t, s0, VerdictNotExploitable)
	if pkg.MachineDisposition.Recommendation != RecommendationLowered ||
		pkg.MachineDisposition.Arbitration != ArbitrationAgreeLower {
		t.Fatalf("package = %s/%s", pkg.MachineDisposition.Recommendation, pkg.MachineDisposition.Arbitration)
	}
	pkg = composeArbitration(t, s0, VerdictExploitable)
	if pkg.MachineDisposition.Recommendation != RecommendationUnchanged ||
		pkg.TechnicalAssessment.Status != TechStatusNeedsArbitration {
		t.Fatalf("diverging lowering = %s/%s", pkg.MachineDisposition.Recommendation, pkg.TechnicalAssessment.Status)
	}
}

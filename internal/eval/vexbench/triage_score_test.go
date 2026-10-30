package vexbench_test

import (
	"testing"
	"time"

	"github.com/davniy/izyan/internal/eval/vexbench"
	"github.com/davniy/izyan/internal/productb/triage"
)

func TestTriageScoringSeparatesHumanAndMachine(t *testing.T) {
	pkg := triage.DecisionPackage{
		FindingID: "f-1",
		Judgment:  triage.LLMJudgment{Verdict: triage.VerdictNotExploitable},
		ProposedAction: triage.HumanAction{
			Kind: triage.HumanActionClose,
		},
		Support: triage.DecisionSupport{
			Level: triage.SupportLevelSubstantiated,
		},
		MachineDisposition: triage.MachineDisposition{
			Recommendation: triage.RecommendationUnchanged,
			Automation:     triage.AutomationWarn,
		},
	}
	hash := triage.CanonicalDecisionHash(pkg)

	evalB := triage.DecisionEvaluation{
		FindingID:             "f-1",
		DecisionPackageHash:   hash,
		MachineRecommendation: triage.RecommendationUnchanged,
		Human: triage.HumanEvaluation{
			CloseOnExploitable: 1,
		},
		Machine: triage.MachineEvaluation{
			FalseSafe: 0,
		},
	}

	start := time.Date(2026, 10, 29, 10, 0, 0, 0, time.UTC)
	finish := start.Add(4 * time.Minute)
	identityTrue := true
	mechanismFalse := false
	rev := vexbench.TriageReviewEvent{
		SchemaVersion:          vexbench.TriageReviewEventSchemaVersion,
		DecisionPackageHash:    hash,
		StartedAt:              start,
		FinishedAt:             finish,
		Accepted:               true,
		DecisionReadyConfirmed: true,
		IdentityCorrect:        &identityTrue,
		MechanismCorrect:       &mechanismFalse,
		DecisiveFactualErrors:  1,
	}

	score, err := vexbench.ComputeTriageScore(vexbench.TriageScoreInput{
		InputBundleHash: "bundle-123",
		PreparedCases:   []vexbench.PreparedCase{{FindingID: "f-1"}},
		PackagesB:       []triage.DecisionPackage{pkg},
		EvaluationsB:    []triage.DecisionEvaluation{evalB},
		ReviewEvents:    []vexbench.TriageReviewEvent{rev},
		PredictionsA:    []vexbench.Prediction{{TaskID: "t-1", Verdict: "NOT_AFFECTED"}},
		Tasks:           []vexbench.Task{{TaskID: "t-1", GroundTruth: "exploitable"}},
	})
	if err != nil {
		t.Fatalf("ComputeTriageScore: %v", err)
	}

	// Product A has false-safe on exploitable
	if score.ProductA.FalseSafe != 1 {
		t.Fatalf("Product A FalseSafe = %d, want 1", score.ProductA.FalseSafe)
	}

	// Product B recommendation has CloseOnExploitable human error, but machine FalseSafe = 0
	if score.ProductB.CloseOnExploitable != 1 {
		t.Fatalf("Product B CloseOnExploitable = %d, want 1", score.ProductB.CloseOnExploitable)
	}
	if score.Automation.FalseSafe != 0 {
		t.Fatalf("Automation FalseSafe = %d, want 0 (machine disposition was UNCHANGED)", score.Automation.FalseSafe)
	}
	if score.ProductB.MechanismCorrectReviews != 0 || *score.ProductB.MechanismCorrectRate != 0.0 {
		t.Fatalf("MechanismCorrectReviews = %d, want 0", score.ProductB.MechanismCorrectReviews)
	}
	if score.ProductB.DecisiveFactualErrors != 1 {
		t.Fatalf("DecisiveFactualErrors = %d, want 1", score.ProductB.DecisiveFactualErrors)
	}
}

func TestDecisionReadyRequiresReviewOutcome(t *testing.T) {
	pkg := triage.DecisionPackage{
		FindingID: "f-1",
		ProposedAction: triage.HumanAction{
			Kind: triage.HumanActionKeepOpen,
		},
		Support: triage.DecisionSupport{
			Level: triage.SupportLevelSubstantiated,
		},
		MachineDisposition: triage.MachineDisposition{
			Recommendation: triage.RecommendationUnchanged,
		},
	}

	// An unreviewed package cannot be counted as decision-ready
	score, err := vexbench.ComputeTriageScore(vexbench.TriageScoreInput{
		PreparedCases: []vexbench.PreparedCase{{FindingID: "f-1"}},
		PackagesB:     []triage.DecisionPackage{pkg},
		ReviewEvents:  nil, // No review events
	})
	if err != nil {
		t.Fatalf("ComputeTriageScore: %v", err)
	}

	if score.ProductB.DeliveredPackages != 1 {
		t.Fatalf("DeliveredPackages = %d, want 1", score.ProductB.DeliveredPackages)
	}
	if score.ProductB.ReviewerConfirmedDecisionReady != 0 {
		t.Fatalf("ReviewerConfirmedDecisionReady = %d, want 0 when no review exists", score.ProductB.ReviewerConfirmedDecisionReady)
	}
	if score.ProductB.ReviewerConfirmedDecisionReadyRate != nil {
		t.Fatalf("ReviewerConfirmedDecisionReadyRate should be unassessed (nil) without reviews, got %v", *score.ProductB.ReviewerConfirmedDecisionReadyRate)
	}
}

func TestMissingReviewIsNotSuccess(t *testing.T) {
	pkg := triage.DecisionPackage{
		FindingID: "f-1",
		MachineDisposition: triage.MachineDisposition{
			Recommendation: triage.RecommendationUnchanged,
		},
	}

	score, err := vexbench.ComputeTriageScore(vexbench.TriageScoreInput{
		PreparedCases: []vexbench.PreparedCase{{FindingID: "f-1"}},
		PackagesB:     []triage.DecisionPackage{pkg},
	})
	if err != nil {
		t.Fatalf("ComputeTriageScore: %v", err)
	}

	if score.ProductB.UnreviewedPackages != 1 {
		t.Fatalf("UnreviewedPackages = %d, want 1", score.ProductB.UnreviewedPackages)
	}
	if score.ProductB.IdentityCorrectRate != nil {
		t.Fatalf("IdentityCorrectRate must be unassessed (nil), got %v", score.ProductB.IdentityCorrectRate)
	}
	if score.ProductB.MechanismCorrectRate != nil {
		t.Fatalf("MechanismCorrectRate must be unassessed (nil), got %v", score.ProductB.MechanismCorrectRate)
	}
}

func TestSupportCalibrationUsesAssessedCasesOnly(t *testing.T) {
	pkg1 := triage.DecisionPackage{
		FindingID: "f-1",
		Support:   triage.DecisionSupport{Level: triage.SupportLevelProvedWithinScope},
		MachineDisposition: triage.MachineDisposition{
			Recommendation: triage.RecommendationDismissed,
		},
	}
	pkg2 := triage.DecisionPackage{
		FindingID: "f-2",
		Support:   triage.DecisionSupport{Level: triage.SupportLevelProvedWithinScope},
		MachineDisposition: triage.MachineDisposition{
			Recommendation: triage.RecommendationDismissed,
		},
	}

	// f-1 is evaluated against external control (assessed)
	eval1 := triage.DecisionEvaluation{
		FindingID:             "f-1",
		DecisionPackageHash:   triage.CanonicalDecisionHash(pkg1),
		Support:               triage.SupportLevelProvedWithinScope,
		MachineRecommendation: triage.RecommendationDismissed,
		Coverage: triage.EvaluationCoverage{
			ControlDisposition: triage.ComparisonAssessed,
		},
		Machine: triage.MachineEvaluation{
			FalseSafe: 0,
		},
	}
	// f-2 has no external baseline (unassessed)
	eval2 := triage.DecisionEvaluation{
		FindingID:             "f-2",
		DecisionPackageHash:   triage.CanonicalDecisionHash(pkg2),
		Support:               triage.SupportLevelProvedWithinScope,
		MachineRecommendation: triage.RecommendationDismissed,
		Coverage: triage.EvaluationCoverage{
			ControlDisposition: triage.ComparisonUnassessed,
		},
		Machine: triage.MachineEvaluation{
			UnverifiedReductions: 1,
		},
	}

	score, err := vexbench.ComputeTriageScore(vexbench.TriageScoreInput{
		PreparedCases: []vexbench.PreparedCase{{FindingID: "f-1"}, {FindingID: "f-2"}},
		PackagesB:     []triage.DecisionPackage{pkg1, pkg2},
		EvaluationsB:  []triage.DecisionEvaluation{eval1, eval2},
	})
	if err != nil {
		t.Fatalf("ComputeTriageScore: %v", err)
	}

	cal := score.ProductB.SupportCalibration
	if cal.AssessedCases != 1 {
		t.Fatalf("AssessedCases = %d, want 1", cal.AssessedCases)
	}
	if cal.UnassessedCases != 1 {
		t.Fatalf("UnassessedCases = %d, want 1", cal.UnassessedCases)
	}
	provedCal := cal.ByLevel[triage.SupportLevelProvedWithinScope]
	if provedCal.TotalAssessed != 1 {
		t.Fatalf("TotalAssessed = %d, want 1 (unassessed case must not be included)", provedCal.TotalAssessed)
	}
	if provedCal.Consistent != 1 {
		t.Fatalf("Consistent = %d, want 1", provedCal.Consistent)
	}
}

package vexbench_test

import (
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/eval/vexbench"
)

func task(gt, category string) vexbench.Task {
	return vexbench.Task{TaskID: "t", GroundTruth: gt, GroundTruthCategory: category}
}

func TestClassifyTruthTable(t *testing.T) {
	for _, tc := range []struct {
		name    string
		gt      string
		pred    vexbench.Prediction
		outcome vexbench.CaseOutcome
	}{
		{"exploitable confirmed", "exploitable",
			vexbench.Prediction{Verdict: "EXPLOITABLE"}, vexbench.OutcomeCorrectExploit},
		{"false-safe on exploitable", "exploitable",
			vexbench.Prediction{Verdict: "NOT_AFFECTED"}, vexbench.OutcomeWrong},
		{"nepf on exploitable is false-safe", "exploitable",
			vexbench.Prediction{Verdict: "NO_EXPLOIT_PATH_FOUND"}, vexbench.OutcomeWrong},
		{"inconclusive on exploitable abstains", "exploitable",
			vexbench.Prediction{Verdict: "INCONCLUSIVE"}, vexbench.OutcomeAbstain},
		{"exploitable on safe task is wrong", "not_exploitable",
			vexbench.Prediction{Verdict: "EXPLOITABLE"}, vexbench.OutcomeWrong},
		{"safe verdict on safe task", "not_exploitable",
			vexbench.Prediction{Verdict: "NOT_AFFECTED"}, vexbench.OutcomeCorrectSafe},
		{"nepf on safe task", "not_exploitable",
			vexbench.Prediction{Verdict: "NO_EXPLOIT_PATH_FOUND"}, vexbench.OutcomeCorrectSafe},
		// GT-safety invariant: INCONCLUSIVE is unresolved, never safe.
		{"inconclusive on safe task abstains", "not_exploitable",
			vexbench.Prediction{Verdict: "INCONCLUSIVE"}, vexbench.OutcomeAbstain},
		{"failed flag wins", "not_exploitable",
			vexbench.Prediction{Verdict: "NOT_AFFECTED", Failed: true}, vexbench.OutcomeFailed},
		{"empty verdict is failed", "exploitable",
			vexbench.Prediction{Verdict: ""}, vexbench.OutcomeFailed},
		{"malformed verdict is failed, not safe", "not_exploitable",
			vexbench.Prediction{Verdict: "GARBAGE"}, vexbench.OutcomeFailed},
		{"malformed verdict on exploitable is failed, not false-safe", "exploitable",
			vexbench.Prediction{Verdict: "GARBAGE"}, vexbench.OutcomeFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := vexbench.Classify(task(tc.gt, "any"), tc.pred); got != tc.outcome {
				t.Fatalf("Classify=%q want %q", got, tc.outcome)
			}
		})
	}
}

func TestComputeDenominators(t *testing.T) {
	tasks := []vexbench.Task{
		{TaskID: "e1", GroundTruth: "exploitable", GroundTruthCategory: "vulnerable"},
		{TaskID: "e2", GroundTruth: "exploitable", GroundTruthCategory: "vulnerable"},
		{TaskID: "s1", GroundTruth: "not_exploitable", GroundTruthCategory: "code_not_reachable"},
		{TaskID: "s2", GroundTruth: "not_exploitable", GroundTruthCategory: "code_not_present"},
		{TaskID: "s3", GroundTruth: "not_exploitable", GroundTruthCategory: "requires_configuration"},
		{TaskID: "s4", GroundTruth: "not_exploitable", GroundTruthCategory: "code_not_reachable"},
	}
	preds := []vexbench.Prediction{
		{TaskID: "e1", Verdict: "EXPLOITABLE", Category: "vulnerable"},
		{TaskID: "e2", Verdict: "NOT_AFFECTED", Category: "code_not_present"}, // false-safe
		{TaskID: "s1", Verdict: "NO_EXPLOIT_PATH_FOUND", Category: "code_not_reachable"},
		{TaskID: "s2", Verdict: "NOT_AFFECTED", Category: "code_not_reachable"}, // right status, wrong reason
		{TaskID: "s3", Verdict: "INCONCLUSIVE"},                                 // abstain
		{TaskID: "ghost", Verdict: "EXPLOITABLE"},                               // no matching task: ignored
		// s4 has no prediction at all → failed.
	}
	m := vexbench.Compute(preds, tasks)
	if m.Total != 6 {
		t.Fatalf("total=%d want 6", m.Total)
	}
	if m.FalseSafe != 1 {
		t.Fatalf("false_safe=%d want 1", m.FalseSafe)
	}
	if m.StatusCorrect != 3 {
		t.Fatalf("status_correct=%d want 3", m.StatusCorrect)
	}
	if m.ReasonCorrect != 2 {
		t.Fatalf("reason_correct=%d want 2 (e1 + s1)", m.ReasonCorrect)
	}
	// correct_safe=2 (s1, s2) over 4 non-exploitable → 0.5
	if m.SafeClearRate != 0.5 {
		t.Fatalf("safe_clear_rate=%v want 0.5", m.SafeClearRate)
	}
	// correct_exploitable=1 over 2 exploitable → 0.5
	if m.ExploitableRecall != 0.5 {
		t.Fatalf("exploitable_recall=%v want 0.5", m.ExploitableRecall)
	}
	// abstain=1 over 6
	if m.InconclusiveRate != 1.0/6.0 {
		t.Fatalf("inconclusive_rate=%v want %v", m.InconclusiveRate, 1.0/6.0)
	}
	// failed=1 (s4) → completion 5/6
	if m.CompletionRate != 5.0/6.0 {
		t.Fatalf("completion_rate=%v want %v", m.CompletionRate, 5.0/6.0)
	}
}

func TestComputeEmptyAndDegenerate(t *testing.T) {
	m := vexbench.Compute(nil, nil)
	if m.Total != 0 || m.SafeClearRate != 0 || m.ExploitableRecall != 0 || m.CompletionRate != 0 {
		t.Fatalf("empty metrics must be zero: %+v", m)
	}
	// All tasks abstain: rates defined, nothing correct.
	tasks := []vexbench.Task{
		{TaskID: "a", GroundTruth: "exploitable"},
		{TaskID: "b", GroundTruth: "not_exploitable"},
	}
	preds := []vexbench.Prediction{
		{TaskID: "a", Verdict: "INCONCLUSIVE"},
		{TaskID: "b", Verdict: "INCONCLUSIVE"},
	}
	m = vexbench.Compute(preds, tasks)
	if m.InconclusiveRate != 1.0 || m.CompletionRate != 1.0 || m.FalseSafe != 0 {
		t.Fatalf("abstain-only run: %+v", m)
	}
}

// TestOutcomeAccounting keeps failed analyses and external dependencies out of
// the definitive-answer population: a failed run is not a completion, and an
// external dependency is an abstention even when its verdict is INCONCLUSIVE.
func TestOutcomeAccounting(t *testing.T) {
	tasks := []vexbench.Task{
		{TaskID: "failed-positive", GroundTruth: "exploitable", GroundTruthCategory: "vulnerable"},
		{TaskID: "failed-safe", GroundTruth: "not_affected", GroundTruthCategory: "code_not_present"},
		{TaskID: "external", GroundTruth: "exploitable", GroundTruthCategory: "vulnerable"},
		{TaskID: "decided-exploit", GroundTruth: "exploitable", GroundTruthCategory: "vulnerable"},
		{TaskID: "decided-false-positive", GroundTruth: "not_affected", GroundTruthCategory: "code_not_present"},
		{TaskID: "decided-false-safe", GroundTruth: "exploitable", GroundTruthCategory: "vulnerable"},
	}
	preds := []vexbench.Prediction{
		// A failed analysis publishes no verdict and is classified failed even
		// if a stray verdict string accompanies it.
		{TaskID: "failed-positive", AssessmentOutcome: "FAILED", Failed: true, Category: vexbench.CategoryUncertain},
		{TaskID: "failed-safe", AssessmentOutcome: "FAILED", Verdict: "NOT_AFFECTED", Category: vexbench.CategoryCodeNotPresent},
		// An external dependency abstains.
		{TaskID: "external", AssessmentOutcome: "EXTERNAL_DEPENDENCY", Verdict: "INCONCLUSIVE", Category: vexbench.CategoryUncertain},
		// Decided answers, one of each direction.
		{TaskID: "decided-exploit", AssessmentOutcome: "DECIDED", Verdict: "EXPLOITABLE", Category: vexbench.CategoryVulnerable},
		{TaskID: "decided-false-positive", AssessmentOutcome: "DECIDED", Verdict: "EXPLOITABLE", Category: vexbench.CategoryVulnerable},
		{TaskID: "decided-false-safe", AssessmentOutcome: "DECIDED", Verdict: "NO_EXPLOIT_PATH_FOUND", Category: vexbench.CategoryCodeNotReachable},
	}
	m := vexbench.Compute(preds, tasks)
	if m.Decided != 3 {
		t.Fatalf("decided=%d want 3 (only the DECIDED predictions)", m.Decided)
	}
	if m.ExternalDependency != 1 {
		t.Fatalf("external_dependency=%d want 1", m.ExternalDependency)
	}
	if m.AnalysisFailed != 2 {
		t.Fatalf("analysis_failed=%d want 2", m.AnalysisFailed)
	}
	if m.FalseSafe != 1 || m.FalsePositive != 1 {
		t.Fatalf("false_safe=%d false_positive=%d; want 1/1", m.FalseSafe, m.FalsePositive)
	}
	// failed=2 of 6 → completion 4/6; the external abstention still counts as
	// a completed run but never as a definitive answer.
	if m.CompletionRate != 4.0/6.0 {
		t.Fatalf("completion_rate=%v want %v", m.CompletionRate, 4.0/6.0)
	}
	if got := vexbench.Classify(tasks[0], preds[0]); got != vexbench.OutcomeFailed {
		t.Fatalf("failed analysis classified %q", got)
	}
	if got := vexbench.Classify(tasks[2], preds[2]); got != vexbench.OutcomeAbstain {
		t.Fatalf("external dependency classified %q", got)
	}
}

func TestCompatibilityCategory(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		verdict, falsifier, want string
	}{
		{"exploitable", "EXPLOITABLE", "", "vulnerable"},
		{"inconclusive", "INCONCLUSIVE", "", "uncertain"},
		{"failed/empty verdict", "", "", "uncertain"},
		{"module absent", "NOT_AFFECTED", vexbench.AffectedModuleAbsent, "code_not_present"},
		{"fixed version", "NOT_AFFECTED", vexbench.AffectedVersionFixed, "code_not_present"},
		{"package absent", "NOT_AFFECTED", vexbench.AffectedPackageAbsent, "code_not_reachable"},
		{"build excluded", "NOT_AFFECTED", vexbench.AffectedBuildExcluded, "requires_environment"},
		{"implementation absent", "NOT_AFFECTED", vexbench.AffectedImplementationAbsent, "requires_environment"},
		{"not_affected without discriminator", "NOT_AFFECTED", "", "uncertain"},
		{"nepf package absent", "NO_EXPLOIT_PATH_FOUND", domain.FalsifierPackageAbsent, "code_not_present"},
		{"nepf locus package absent", "NO_EXPLOIT_PATH_FOUND", domain.FalsifierLocusPackageAbsent, "code_not_present"},
		{"nepf locus unreached", "NO_EXPLOIT_PATH_FOUND", domain.FalsifierLocusFunctionUnreached, "code_not_reachable"},
		{"nepf govulncheck silence", "NO_EXPLOIT_PATH_FOUND", domain.FalsifierGovulncheckSilence, "code_not_reachable"},
		{"nepf unreached exported", "NO_EXPLOIT_PATH_FOUND", domain.FalsifierUnreachedExportedSubject, "code_not_reachable"},
		{"nepf config gated", "NO_EXPLOIT_PATH_FOUND", domain.FalsifierConfigGatedOff, "requires_configuration"},
		{"nepf safe config", "NO_EXPLOIT_PATH_FOUND", domain.FalsifierSafeConfigAssignment, "requires_configuration"},
		{"nepf safe config key", "NO_EXPLOIT_PATH_FOUND", domain.FalsifierSafeConfigKey, "requires_configuration"},
		{"nepf zero value", "NO_EXPLOIT_PATH_FOUND", domain.FalsifierZeroValueConfig, "requires_configuration"},
		{"nepf loopback", "NO_EXPLOIT_PATH_FOUND", domain.FalsifierLoopbackOnly, "perimeter_protected"},
		{"nepf protocol role", "NO_EXPLOIT_PATH_FOUND", domain.FalsifierProtocolRoleMismatch, "requires_environment"},
		{"nepf snapshot fact", "NO_EXPLOIT_PATH_FOUND", domain.FalsifierSnapshotFactMismatch, "requires_environment"},
		{"nepf guards", "NO_EXPLOIT_PATH_FOUND", domain.FalsifierGuards, "mitigating_control_protected"},
		{"nepf const input", "NO_EXPLOIT_PATH_FOUND", domain.FalsifierConstantOrGeneratedInput, "mitigating_control_protected"},
		{"nepf pair member", "NO_EXPLOIT_PATH_FOUND", domain.FalsifierMissingPairMember, "mitigating_control_protected"},
		{"nepf source symbol", "NO_EXPLOIT_PATH_FOUND", domain.FalsifierMissingSourceSymbol, "mitigating_control_protected"},
		{"nepf no reader", "NO_EXPLOIT_PATH_FOUND", domain.FalsifierNoProductReader, "mitigating_control_protected"},
		{"nepf trusted infra declared", "NO_EXPLOIT_PATH_FOUND",
			domain.FalsifierTrustedInfrastructure + ":" + domain.BasisDeclaredTrust, "perimeter_protected"},
		{"nepf trusted infra auto", "NO_EXPLOIT_PATH_FOUND",
			domain.FalsifierTrustedInfrastructure + ":" + domain.BasisAutoPerimeter, "perimeter_protected"},
		{"nepf trusted infra config origin", "NO_EXPLOIT_PATH_FOUND",
			domain.FalsifierTrustedInfrastructure + ":" + domain.BasisConfigOrigin, "mitigating_control_protected"},
		{"nepf trusted infra bare is ambiguous", "NO_EXPLOIT_PATH_FOUND",
			domain.FalsifierTrustedInfrastructure, "uncertain"},
		{"nepf unknown falsifier", "NO_EXPLOIT_PATH_FOUND", "no-module-usage", "uncertain"},
		{"nepf missing falsifier", "NO_EXPLOIT_PATH_FOUND", "", "uncertain"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := vexbench.CompatibilityCategory(tc.verdict, tc.falsifier); got != tc.want {
				t.Fatalf("CompatibilityCategory(%q,%q)=%q want %q", tc.verdict, tc.falsifier, got, tc.want)
			}
		})
	}
}

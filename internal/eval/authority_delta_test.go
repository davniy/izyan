package eval

import (
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
)

// authoritativeCase builds one corpus result with the identity a comparison
// pairs on.
func authorityCase(id, verdict string, build string, claims map[string]string) Result {
	return Result{
		Case: Case{
			ID:     id,
			Vuln:   "GO-TEST-" + id,
			Module: "example.com/dep",
			Repo:   "products/" + id,
		},
		Verdict: verdict,
		Claims:  claims,
		Build:   build,
	}
}

// TestAuthorityDeltaKeepsLostPositivesVisible is the measurement contract: the
// authority cutover is expected to lose weak positives, so the comparison
// reports each loss with its own direction and the condition results that
// moved. A net count would hide exactly the fact the measurement exists to
// state.
func TestAuthorityDeltaKeepsLostPositivesVisible(t *testing.T) {
	before := []Result{
		authorityCase("alpha", "EXPLOITABLE", "build-1", map[string]string{
			"C-REACH": "TRUE", "C-PEER-INPUT": "TRUE", "C-EXPOSURE": "TRUE",
		}),
		authorityCase("beta", "NOT_AFFECTED", "build-1", map[string]string{"C-REACH": "FALSE"}),
		authorityCase("gamma", "EXPLOITABLE", "build-1", map[string]string{"C-REACH": "TRUE"}),
	}
	after := []Result{
		authorityCase("alpha", "INCONCLUSIVE", "build-1", map[string]string{
			"C-REACH": "TRUE", "C-INPUT": "UNKNOWN",
		}),
		authorityCase("beta", "NOT_AFFECTED", "build-1", map[string]string{"C-REACH": "FALSE"}),
		authorityCase("gamma", "EXPLOITABLE", "build-1", map[string]string{"C-REACH": "TRUE"}),
	}

	delta, err := CompareAuthorityResults(before, after)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	if delta.Matched != 3 || delta.Unchanged != 2 {
		t.Fatalf("matched=%d unchanged=%d, want 3 matched and the two untouched cases unchanged",
			delta.Matched, delta.Unchanged)
	}
	if delta.BeforeCounts.Positives != 2 || delta.AfterCounts.Positives != 1 {
		t.Fatalf("positives before=%d after=%d, want 2 → 1",
			delta.BeforeCounts.Positives, delta.AfterCounts.Positives)
	}
	if delta.AfterCounts.Inconclusive != 1 {
		t.Fatalf("after inconclusive=%d, want 1", delta.AfterCounts.Inconclusive)
	}

	if len(delta.Transitions) != 1 {
		t.Fatalf("transitions=%+v, want exactly the lost positive", delta.Transitions)
	}
	lost := delta.Transitions[0]
	if lost.Case != "alpha" || lost.Transition != TransitionLostPositive {
		t.Fatalf("transition=%s on %s, want %s on alpha", lost.Transition, lost.Case, TransitionLostPositive)
	}
	if lost.Before.Class != DeltaPositive || lost.After.Class != DeltaInconclusive {
		t.Fatalf("classes=%s → %s, want POSITIVE → INCONCLUSIVE", lost.Before.Class, lost.After.Class)
	}
	if lost.Before.Verdict != "EXPLOITABLE" || lost.After.Verdict != "INCONCLUSIVE" {
		t.Fatalf("recorded verdicts=%q → %q", lost.Before.Verdict, lost.After.Verdict)
	}

	// Per-condition accounting states which facts stopped being established
	// and which the model introduced.
	byCondition := map[string]ConditionTransition{}
	for _, cond := range lost.Conditions {
		byCondition[cond.ConditionID] = cond
	}
	if len(byCondition) != 3 {
		t.Fatalf("condition transitions=%+v, want the two removed and the one added", lost.Conditions)
	}
	if cond := byCondition["C-PEER-INPUT"]; cond.Transition != ConditionRemoved || cond.Before != "TRUE" {
		t.Fatalf("C-PEER-INPUT transition=%+v, want the lost positive recorded as removed", cond)
	}
	if cond := byCondition["C-EXPOSURE"]; cond.Transition != ConditionRemoved {
		t.Fatalf("C-EXPOSURE transition=%+v, want removed", cond)
	}
	if cond := byCondition["C-INPUT"]; cond.Transition != ConditionAdded || cond.After != "UNKNOWN" {
		t.Fatalf("C-INPUT transition=%+v, want the new condition recorded as added", cond)
	}
	if len(delta.Conditions) != 3 {
		t.Fatalf("flat condition accounting=%+v, want the same three transitions", delta.Conditions)
	}
	if delta.Conditions[0].Case != "alpha" {
		t.Fatalf("flat condition entry lost its case identity: %+v", delta.Conditions[0])
	}

	// The summary must state the loss, never a netted number.
	summary := delta.Summary()
	if !strings.Contains(summary, "POSITIVE_LOST") || !strings.Contains(summary, "alpha") {
		t.Fatalf("summary %q does not state the lost positive", summary)
	}
}

// TestAuthorityDeltaRefusesUnmatchedMaterial pins the refusal: two runs that do
// not describe the same population measure nothing, so the comparison rejects
// them instead of pairing what it can.
func TestAuthorityDeltaRefusesUnmatchedMaterial(t *testing.T) {
	base := authorityCase("alpha", "EXPLOITABLE", "build-1", map[string]string{"C-REACH": "TRUE"})

	t.Run("a case present on one side only", func(t *testing.T) {
		before := []Result{base, authorityCase("beta", "EXPLOITABLE", "build-1", nil)}
		after := []Result{base}
		_, err := CompareAuthorityResults(before, after)
		if err == nil {
			t.Fatal("a run pair with a missing case was compared")
		}
		if !strings.Contains(err.Error(), "beta") || !strings.Contains(err.Error(), "not present in both runs") {
			t.Fatalf("refusal %q does not name the unmatched case", err)
		}
	})

	t.Run("the build identity changed", func(t *testing.T) {
		after := []Result{authorityCase("alpha", "EXPLOITABLE", "build-2", map[string]string{"C-REACH": "TRUE"})}
		_, err := CompareAuthorityResults([]Result{base}, after)
		if err == nil {
			t.Fatal("results from different builds were compared as one case")
		}
	})

	t.Run("the recorded input changed", func(t *testing.T) {
		moved := base
		moved.Case.Repo = "products/moved"
		_, err := CompareAuthorityResults([]Result{base}, []Result{moved})
		if err == nil {
			t.Fatal("a case whose input changed was paired with its old result")
		}
	})

	t.Run("one identity recorded twice", func(t *testing.T) {
		_, err := CompareAuthorityResults([]Result{base, base}, []Result{base})
		if err == nil {
			t.Fatal("a duplicated identity was compared")
		}
		if !strings.Contains(err.Error(), "twice") {
			t.Fatalf("refusal %q does not name the duplicate identity", err)
		}
	})
}

// TestAuthorityDeltaCallsOutNewFalseSafe keeps the stop criterion visible: a
// case that becomes false-safe is named separately from the counts, and its
// verdict transition is still reported.
func TestAuthorityDeltaCallsOutNewFalseSafe(t *testing.T) {
	before := authorityCase("alpha", "EXPLOITABLE", "build-1", map[string]string{"C-REACH": "TRUE"})
	before.FalseSafe = false
	after := authorityCase("alpha", "NO_EXPLOIT_PATH_FOUND", "build-1", map[string]string{"C-REACH": "FALSE"})
	after.FalseSafe = true

	delta, err := CompareAuthorityResults([]Result{before}, []Result{after})
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	if len(delta.FalseSafeGained) != 1 || delta.FalseSafeGained[0] != "alpha" {
		t.Fatalf("false-safe gained=%v, want [alpha]", delta.FalseSafeGained)
	}
	if delta.AfterCounts.FalseSafe != 1 || delta.BeforeCounts.FalseSafe != 0 {
		t.Fatalf("false-safe counts before=%d after=%d, want 0 → 1",
			delta.BeforeCounts.FalseSafe, delta.AfterCounts.FalseSafe)
	}
	if len(delta.Transitions) != 1 || delta.Transitions[0].Transition != TransitionLostPositive {
		t.Fatalf("transitions=%+v, want the lost positive alongside the false-safe callout", delta.Transitions)
	}
	cond := delta.Transitions[0].Conditions
	if len(cond) != 1 || cond[0].Transition != ConditionPositiveLost {
		t.Fatalf("condition transitions=%+v, want C-REACH recorded as a lost positive", cond)
	}
}

// TestAuthorityDeltaClassifiesFailures pins the failure direction: a failed
// assessment publishes no answer, so a case that stops failing is a cleared
// failure and not a gained verdict.
func TestAuthorityDeltaClassifiesFailures(t *testing.T) {
	failed := authorityCase("alpha", "", "build-1", nil)
	failed.AssessmentOutcome = string(domain.OutcomeFailed)
	failed.FailureCodes = []string{"PROOF/MEASUREMENT_NOT_COMPLETED"}

	delta, err := CompareAuthorityResults([]Result{failed}, []Result{
		authorityCase("alpha", "INCONCLUSIVE", "build-1", map[string]string{"C-REACH": "UNKNOWN"}),
	})
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	if delta.BeforeCounts.Failures != 1 || delta.AfterCounts.Failures != 0 {
		t.Fatalf("failures before=%d after=%d, want 1 → 0",
			delta.BeforeCounts.Failures, delta.AfterCounts.Failures)
	}
	if len(delta.Transitions) != 1 || delta.Transitions[0].Transition != TransitionClearedFailure {
		t.Fatalf("transitions=%+v, want the cleared failure", delta.Transitions)
	}
	if len(delta.Transitions[0].Before.FailureCodes) != 1 {
		t.Fatalf("the comparison dropped the failed run's typed causes: %+v", delta.Transitions[0].Before)
	}
}

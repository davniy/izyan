package flow

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// TestPolicyMonotonic covers the pure validation: a candidate must
// preserve every baseline member and may only add.
func TestPolicyMonotonic(t *testing.T) {
	base := Policy{
		RequiredRules:       []string{"r1", "r2"},
		RequiredChecks:      []string{"c1"},
		ForbiddenPromotions: []string{"p1"},
	}
	// identical → ok
	if err := ValidateMonotonicPolicy(base, base); err != nil {
		t.Fatalf("identical policy rejected: %v", err)
	}
	// superset → ok
	tightened := Policy{
		RequiredRules:       []string{"r1", "r2", "r3"},
		RequiredChecks:      []string{"c1", "c2"},
		ForbiddenPromotions: []string{"p1", "p2"},
	}
	if err := ValidateMonotonicPolicy(base, tightened); err != nil {
		t.Fatalf("tightened policy rejected: %v", err)
	}
	// removal of a rule → violation
	if err := ValidateMonotonicPolicy(base, Policy{
		RequiredRules:       []string{"r1"},
		RequiredChecks:      []string{"c1"},
		ForbiddenPromotions: []string{"p1"},
	}); err == nil || !strings.Contains(err.Error(), "r2") {
		t.Fatalf("rule removal not rejected: %v", err)
	}
	// removal of a check → violation
	if err := ValidateMonotonicPolicy(base, Policy{
		RequiredRules:       []string{"r1", "r2"},
		ForbiddenPromotions: []string{"p1"},
	}); err == nil || !strings.Contains(err.Error(), "c1") {
		t.Fatalf("check removal not rejected: %v", err)
	}
	// removal of a forbidden promotion → violation
	if err := ValidateMonotonicPolicy(base, Policy{
		RequiredRules:  []string{"r1", "r2"},
		RequiredChecks: []string{"c1"},
	}); err == nil || !strings.Contains(err.Error(), "p1") {
		t.Fatalf("promotion removal not rejected: %v", err)
	}
	// empty base is satisfied by anything well-formed
	if err := ValidateMonotonicPolicy(Policy{}, Policy{RequiredRules: []string{"x"}}); err != nil {
		t.Fatalf("empty base rejected superset: %v", err)
	}
}

func TestPolicyMalformed(t *testing.T) {
	if err := validatePolicy(Policy{RequiredRules: []string{""}}); err == nil {
		t.Fatalf("empty member accepted")
	}
	if err := validatePolicy(Policy{RequiredRules: []string{"a", "a"}}); err == nil {
		t.Fatalf("duplicate member accepted")
	}
	if err := validatePolicy(Policy{RequiredRules: []string{"a"}, MaxSteps: -1}); err == nil {
		t.Fatalf("negative budget accepted")
	}
}

// TestPolicyStartupRelaxation: an engine configured below the caller's
// baseline terminates at run start with POLICY_VIOLATION and never
// invokes the planner.
func TestPolicyStartupRelaxation(t *testing.T) {
	reg := testRegistry(t, testCatalog())
	planner := &fakePlanner{fn: func(step int, in PlanInput) (Plan, error) {
		return Plan{StepID: "s1", Actions: []PlanAction{alphaAction("a1")}}, nil
	}}
	e := newEngine(reg, planner, &fakeReassessor{}, &fakeBroker{})
	e.Policy.RequiredChecks = nil // relaxes the baseline's required check
	in := testInput()
	in.Baseline = testBaseline()
	res, err := e.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Termination != TermPolicyViolation || res.Ready {
		t.Fatalf("termination = %q, want POLICY_VIOLATION", res.Termination)
	}
	if planner.calls != 0 {
		t.Fatalf("planner ran under a relaxed policy")
	}
}

// TestPolicyRuntimeRelaxation: a reassessment that proposes dropping a
// baseline member fails the run with POLICY_VIOLATION.
func TestPolicyRuntimeRelaxation(t *testing.T) {
	reg := testRegistry(t, testCatalog())
	planner := &fakePlanner{fn: func(step int, in PlanInput) (Plan, error) {
		return Plan{StepID: "s1", Actions: []PlanAction{alphaAction("a1")}}, nil
	}}
	reass := &fakeReassessor{fn: func(in ReassessInput) (Reassessment, error) {
		relaxed := testPolicy()
		relaxed.ForbiddenPromotions = nil
		return Reassessment{Status: ReassessContinue, Policy: &relaxed}, nil
	}}
	broker := &fakeBroker{fn: func(a PlanAction) (Observation, error) {
		return okObservation(a.ID), nil
	}}
	res, err := newEngine(reg, planner, reass, broker).Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Termination != TermPolicyViolation || res.Ready {
		t.Fatalf("termination = %q, want POLICY_VIOLATION", res.Termination)
	}
}

// TestPolicyRuntimeTightening: a reassessment may only ever tighten —
// a candidate that adds members is adopted and recorded.
func TestPolicyRuntimeTightening(t *testing.T) {
	reg := testRegistry(t, testCatalog())
	planner := &fakePlanner{fn: func(step int, in PlanInput) (Plan, error) {
		return Plan{StepID: "s1", Actions: []PlanAction{alphaAction("a1")}}, nil
	}}
	n := 0
	reass := &fakeReassessor{fn: func(in ReassessInput) (Reassessment, error) {
		n++
		if n == 1 {
			tightened := testPolicy()
			tightened.RequiredRules = append(tightened.RequiredRules, "r-extra")
			return Reassessment{Status: ReassessContinue, Policy: &tightened}, nil
		}
		if in.Policy.RequiredRules[len(in.Policy.RequiredRules)-1] != "r-extra" {
			t.Fatalf("tightened policy not adopted: %v", in.Policy.RequiredRules)
		}
		return Reassessment{Status: ReassessNotDecisionReady}, nil
	}}
	broker := &fakeBroker{fn: func(a PlanAction) (Observation, error) {
		return okObservation(a.ID), nil
	}}
	res, err := newEngine(reg, planner, reass, broker).Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Termination != TermDecisionReady || !res.Ready {
		t.Fatalf("termination = %q", res.Termination)
	}
	if len(res.Policy.RequiredRules) != 2 {
		t.Fatalf("final policy = %+v", res.Policy)
	}
}

// TestPolicyBudgetConfig: budgets resolve deterministically —
// engine over policy over default.
func TestPolicyBudgetConfig(t *testing.T) {
	e := &Engine{Policy: Policy{MaxSteps: 3}, MaxActions: 5}
	b, err := e.resolveBudget()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if b.MaxSteps != 3 || b.MaxActions != 5 {
		t.Fatalf("budget = %+v", b)
	}
	e2 := &Engine{Policy: Policy{MaxSteps: 3, MaxActions: 4}}
	b2, _ := e2.resolveBudget()
	if b2.MaxSteps != 3 || b2.MaxActions != 4 {
		t.Fatalf("policy budget = %+v", b2)
	}
	e3 := &Engine{}
	b3, _ := e3.resolveBudget()
	if b3.MaxSteps != DefaultMaxSteps || b3.MaxActions != DefaultMaxActions {
		t.Fatalf("default budget = %+v", b3)
	}
}

// TestFailClosedPolicyInputs: the fail-closed entry checks — a missing
// required check on an empty registry degrades the startup claim.
func TestFailClosedPolicyInputs(t *testing.T) {
	reg := testRegistry(t, newFakeCatalog()) // no checks registered
	e := newEngine(reg, &fakePlanner{}, &fakeReassessor{}, &fakeBroker{})
	in := testInput()
	res, err := e.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Termination != TermNotDecisionReady {
		t.Fatalf("termination = %q, want NOT_DECISION_READY", res.Termination)
	}
}

func TestPolicyJSONShape(t *testing.T) {
	p := Policy{RequiredChecks: []string{"c1"}, MaxSteps: 2}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"max_steps":2`) {
		t.Fatalf("policy wire shape lost budgets: %s", raw)
	}
}

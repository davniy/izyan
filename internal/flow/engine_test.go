package flow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/evidencetools"
)

// --- shared fakes -------------------------------------------------------

// fakeCatalog is a minimal evidencetools.CheckCatalog: registered
// specs, a tool name per check, a closed set of allowed argument keys
// plus required keys, and an optional capability denial set. ghosts
// mirrors the production mappedFlowCatalog's lane-internal shape: the
// id is registered (List advertises it) but carries no dispatchable
// spec, so Lookup fails and Validate names the lane-internal reason.
type fakeCatalog struct {
	specs   map[string]evidencetools.CheckSpec
	order   []string
	allowed map[string][]string // check id -> allowed argument keys
	need    map[string][]string // check id -> required argument keys
	denied  map[string]bool     // check id -> capability denied
	ghosts  map[string]bool     // registered, undispatchable ids
}

func newFakeCatalog() *fakeCatalog {
	return &fakeCatalog{
		specs:   map[string]evidencetools.CheckSpec{},
		allowed: map[string][]string{},
		need:    map[string][]string{},
		denied:  map[string]bool{},
		ghosts:  map[string]bool{},
	}
}

func (c *fakeCatalog) add(id, tool string, maxCalls int, allowed, required []string) {
	c.specs[id] = evidencetools.CheckSpec{
		ID: id, Tool: tool, CoverageRule: "test scope", MaxCalls: maxCalls,
	}
	c.order = append(c.order, id)
	c.allowed[id] = allowed
	c.need[id] = required
}

// addGhost registers a lane-carried check id: catalog-listed and
// known to the run-start required gate, but undispatchable — Lookup
// misses and Validate names the lane-internal reason, mirroring
// mappedFlowCatalog.
func (c *fakeCatalog) addGhost(id string) {
	c.order = append(c.order, id)
	c.ghosts[id] = true
}

func (c *fakeCatalog) Lookup(id string) (evidencetools.CheckSpec, bool) {
	s, ok := c.specs[id]
	return s, ok
}

func (c *fakeCatalog) List() []evidencetools.CheckSpec {
	out := make([]evidencetools.CheckSpec, 0, len(c.order))
	for _, id := range c.order {
		if c.ghosts[id] {
			out = append(out, evidencetools.CheckSpec{ID: id, Tool: id})
			continue
		}
		out = append(out, c.specs[id])
	}
	return out
}

func (c *fakeCatalog) Validate(id string, args json.RawMessage) error {
	spec, ok := c.specs[id]
	if !ok {
		if c.ghosts[id] {
			return fmt.Errorf("check %q is a lane-internal check without a dispatchable session tool", id)
		}
		return fmt.Errorf("check %q is not registered", id)
	}
	if c.denied[id] {
		return fmt.Errorf("check %q requires a capability this session denies", id)
	}
	obj := map[string]any{}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &obj); err != nil {
			return fmt.Errorf("check %q arguments are not an object: %v", spec.ID, err)
		}
	}
	allowed := map[string]bool{}
	for _, k := range c.allowed[id] {
		allowed[k] = true
	}
	for k := range obj {
		if !allowed[k] {
			return fmt.Errorf("check %q argument %q is not declared", spec.ID, k)
		}
	}
	for _, k := range c.need[id] {
		if _, ok := obj[k]; !ok {
			return fmt.Errorf("check %q requires argument %q", spec.ID, k)
		}
	}
	return nil
}

// testCatalog registers two generic checks.
func testCatalog() *fakeCatalog {
	c := newFakeCatalog()
	c.add("check-alpha", "tool-alpha", 0, []string{"subject"}, nil)
	c.add("check-beta", "tool-beta", 0, []string{"subject"}, nil)
	return c
}

func testRegistry(t *testing.T, cat evidencetools.CheckCatalog, conds ...string) *CatalogRegistry {
	t.Helper()
	var cs []Condition
	for _, id := range conds {
		cs = append(cs, Condition{ID: id, Role: "supporting", Polarity: "POSITIVE", Statement: "test condition " + id})
	}
	r, err := NewCatalogRegistry(cat, cs)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	return r
}

func testPolicy() Policy {
	return Policy{
		RequiredRules:       []string{"rule-floor"},
		RequiredChecks:      []string{"check-alpha"},
		ForbiddenPromotions: []string{"agent-assertion-to-verified-fact"},
	}
}

func testBaseline() Policy {
	return testPolicy()
}

// fakePlanner serves scripted outcomes in order.
type fakePlanner struct {
	fn    func(step int, in PlanInput) (Plan, error)
	calls int
}

func (p *fakePlanner) Plan(_ context.Context, in PlanInput) (Plan, error) {
	p.calls++
	return p.fn(in.Step, in)
}

// fakeReassessor serves scripted reassessments in order.
type fakeReassessor struct {
	fn    func(in ReassessInput) (Reassessment, error)
	calls int
	seen  []ReassessInput
}

func (r *fakeReassessor) Reassess(_ context.Context, in ReassessInput) (Reassessment, error) {
	r.calls++
	r.seen = append(r.seen, in)
	return r.fn(in)
}

// fakeBroker returns scripted observations per action id.
type fakeBroker struct {
	fn    func(a PlanAction) (Observation, error)
	calls int
	seen  []PlanAction
}

func (b *fakeBroker) Execute(_ context.Context, a PlanAction) (Observation, error) {
	b.calls++
	b.seen = append(b.seen, a)
	return b.fn(a)
}

// okObservation is a complete, digest-bound, audit-bound OK record.
func okObservation(actionID string) Observation {
	return Observation{
		ID: "OBS-" + actionID, ActionID: actionID,
		Status: ObsStatusOK, Completeness: ObsComplete,
		Scope: "closed test scope", DataDigest: strings.Repeat("a", 64),
		AuditBound: true,
	}
}

// alphaAction is the canonical admitted action.
func alphaAction(id string) PlanAction {
	return PlanAction{ID: id, AdapterID: "check-alpha",
		Arguments: json.RawMessage(`{"subject":"s"}`), Purpose: "coverage"}
}

func newEngine(reg Registry, p Planner, r Reassessor, b Broker) *Engine {
	return &Engine{
		Planner: p, Reassessor: r, Broker: b, Registry: reg,
		Policy: testPolicy(), MaxSteps: 4, MaxActions: 8,
	}
}

func testInput() Input {
	return Input{RunID: "run-1", Objective: "probe", Baseline: testBaseline()}
}

// --- tests --------------------------------------------------------------

func TestEngineDecisionReady(t *testing.T) {
	reg := testRegistry(t, testCatalog(), "cond-one")
	planner := &fakePlanner{fn: func(step int, in PlanInput) (Plan, error) {
		return Plan{StepID: "s1", Actions: []PlanAction{alphaAction("a1")}, ConditionIDs: []string{"cond-one"}}, nil
	}}
	reass := &fakeReassessor{fn: func(in ReassessInput) (Reassessment, error) {
		return Reassessment{Status: ReassessReady}, nil
	}}
	broker := &fakeBroker{fn: func(a PlanAction) (Observation, error) {
		return okObservation(a.ID), nil
	}}
	res, err := newEngine(reg, planner, reass, broker).Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Termination != TermDecisionReady || !res.Ready {
		t.Fatalf("termination = %q ready=%v, want DECISION_READY", res.Termination, res.Ready)
	}
	if !res.Complete {
		t.Fatalf("expected complete coverage")
	}
	if broker.calls != 1 || reass.calls != 1 || planner.calls != 1 {
		t.Fatalf("calls planner=%d broker=%d reassessor=%d", planner.calls, broker.calls, reass.calls)
	}
	if len(res.Observations) != 1 || res.Observations[0].Status != ObsStatusOK {
		t.Fatalf("observations = %+v", res.Observations)
	}
	if len(res.Actions) != len(res.Observations) {
		t.Fatalf("actions/observations mismatch %d/%d", len(res.Actions), len(res.Observations))
	}
	if res.Events[len(res.Events)-1].Kind != EventTerminated {
		t.Fatalf("last event = %q", res.Events[len(res.Events)-1].Kind)
	}
}

func TestEngineBranchesComplete(t *testing.T) {
	reg := testRegistry(t, testCatalog(), "cond-one")
	planner := &fakePlanner{fn: func(step int, in PlanInput) (Plan, error) {
		return Plan{StepID: "s1", Actions: []PlanAction{alphaAction("a1")}}, nil
	}}
	reass := &fakeReassessor{fn: func(in ReassessInput) (Reassessment, error) {
		return Reassessment{
			Status: ReassessBranchesComplete,
			Revisions: []BranchRevision{
				{BranchID: "B-1", Status: BranchStatusComplete},
				{BranchID: "B-2", Status: BranchStatusComplete},
			},
		}, nil
	}}
	broker := &fakeBroker{fn: func(a PlanAction) (Observation, error) {
		return okObservation(a.ID), nil
	}}
	res, err := newEngine(reg, planner, reass, broker).Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Termination != TermBranchesComplete || !res.Ready {
		t.Fatalf("termination = %q, want BRANCHES_COMPLETE", res.Termination)
	}
	if len(res.Branches) != 2 || len(res.Revisions) != 2 {
		t.Fatalf("branches=%+v revisions=%+v", res.Branches, res.Revisions)
	}
}

func TestEngineBranchesCompleteUnsupportedClaim(t *testing.T) {
	reg := testRegistry(t, testCatalog())
	planner := &fakePlanner{fn: func(step int, in PlanInput) (Plan, error) {
		return Plan{StepID: "s1", Actions: []PlanAction{alphaAction("a1")}}, nil
	}}
	// A claim of branches-complete with a still-open branch is
	// inconsistent — the recorded state does not support it.
	reass := &fakeReassessor{fn: func(in ReassessInput) (Reassessment, error) {
		return Reassessment{
			Status: ReassessBranchesComplete,
			Revisions: []BranchRevision{
				{BranchID: "B-1", Status: BranchStatusComplete},
				{BranchID: "B-2", Status: BranchStatusNotDecisionReady},
			},
		}, nil
	}}
	broker := &fakeBroker{fn: func(a PlanAction) (Observation, error) {
		return okObservation(a.ID), nil
	}}
	res, err := newEngine(reg, planner, reass, broker).Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Termination != TermNotDecisionReady || res.Ready {
		t.Fatalf("termination = %q, want NOT_DECISION_READY", res.Termination)
	}
}

func TestEngineAwaitingEnvironment(t *testing.T) {
	reg := testRegistry(t, testCatalog(), "cond-env")
	planner := &fakePlanner{fn: func(step int, in PlanInput) (Plan, error) {
		return Plan{StepID: "s1", Actions: []PlanAction{alphaAction("a1")}}, nil
	}}
	reass := &fakeReassessor{fn: func(in ReassessInput) (Reassessment, error) {
		return Reassessment{
			Status:         ReassessAwaitingEnvironment,
			RequiredInputs: []string{"cond-env"},
		}, nil
	}}
	broker := &fakeBroker{fn: func(a PlanAction) (Observation, error) {
		return okObservation(a.ID), nil
	}}
	res, err := newEngine(reg, planner, reass, broker).Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Termination != TermAwaitingEnvironment {
		t.Fatalf("termination = %q, want AWAITING_ENVIRONMENT", res.Termination)
	}
	if len(res.RequiredInputs) != 1 || res.RequiredInputs[0] != "cond-env" {
		t.Fatalf("required inputs = %v", res.RequiredInputs)
	}
	if res.Ready {
		t.Fatalf("awaiting input must not report ready")
	}
}

func TestEngineAwaitingEnvironmentUnknownInput(t *testing.T) {
	reg := testRegistry(t, testCatalog(), "cond-env")
	planner := &fakePlanner{fn: func(step int, in PlanInput) (Plan, error) {
		return Plan{StepID: "s1", Actions: []PlanAction{alphaAction("a1")}}, nil
	}}
	reass := &fakeReassessor{fn: func(in ReassessInput) (Reassessment, error) {
		return Reassessment{
			Status:         ReassessAwaitingEnvironment,
			RequiredInputs: []string{"cond-ghost"},
		}, nil
	}}
	broker := &fakeBroker{fn: func(a PlanAction) (Observation, error) {
		return okObservation(a.ID), nil
	}}
	res, err := newEngine(reg, planner, reass, broker).Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Termination != TermUnsupported {
		t.Fatalf("termination = %q, want UNSUPPORTED_CHECK_OR_CONDITION", res.Termination)
	}
}

func TestEngineTerminalContradiction(t *testing.T) {
	reg := testRegistry(t, testCatalog())
	planner := &fakePlanner{fn: func(step int, in PlanInput) (Plan, error) {
		return Plan{StepID: "s1", Actions: []PlanAction{alphaAction("a1")}}, nil
	}}
	reass := &fakeReassessor{fn: func(in ReassessInput) (Reassessment, error) {
		return Reassessment{
			Status:    ReassessTerminalContradiction,
			Revisions: []BranchRevision{{BranchID: "B-1", Status: BranchStatusContradicted}},
		}, nil
	}}
	broker := &fakeBroker{fn: func(a PlanAction) (Observation, error) {
		return okObservation(a.ID), nil
	}}
	res, err := newEngine(reg, planner, reass, broker).Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Termination != TermTerminalContradiction || res.Ready {
		t.Fatalf("termination = %q, want TERMINAL_CONTRADICTION", res.Termination)
	}
}

func TestEngineTerminalContradictionUnsupported(t *testing.T) {
	reg := testRegistry(t, testCatalog())
	planner := &fakePlanner{fn: func(step int, in PlanInput) (Plan, error) {
		return Plan{StepID: "s1", Actions: []PlanAction{alphaAction("a1")}}, nil
	}}
	reass := &fakeReassessor{fn: func(in ReassessInput) (Reassessment, error) {
		return Reassessment{Status: ReassessTerminalContradiction}, nil
	}}
	broker := &fakeBroker{fn: func(a PlanAction) (Observation, error) {
		return okObservation(a.ID), nil
	}}
	res, err := newEngine(reg, planner, reass, broker).Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Termination != TermNotDecisionReady {
		t.Fatalf("termination = %q, want NOT_DECISION_READY", res.Termination)
	}
}

func TestEngineBudgetExhaustedSteps(t *testing.T) {
	reg := testRegistry(t, testCatalog())
	planner := &fakePlanner{fn: func(step int, in PlanInput) (Plan, error) {
		return Plan{StepID: fmt.Sprintf("s%d", step), Actions: []PlanAction{{
			ID: fmt.Sprintf("a%d", step), AdapterID: "check-beta",
			Arguments: json.RawMessage(`{"subject":"s"}`), Purpose: "explore",
		}}}, nil
	}}
	reass := &fakeReassessor{fn: func(in ReassessInput) (Reassessment, error) {
		return Reassessment{Status: ReassessContinue}, nil
	}}
	broker := &fakeBroker{fn: func(a PlanAction) (Observation, error) {
		return okObservation(a.ID), nil
	}}
	e := newEngine(reg, planner, reass, broker)
	e.MaxSteps = 2
	res, err := e.Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Termination != TermBudgetExhausted {
		t.Fatalf("termination = %q, want BUDGET_EXHAUSTED", res.Termination)
	}
	if planner.calls != 2 {
		t.Fatalf("planner calls = %d, want 2", planner.calls)
	}
	if len(res.Steps) != 2 {
		t.Fatalf("steps = %d", len(res.Steps))
	}
}
func TestEngineBudgetExhaustedActions(t *testing.T) {
	reg := testRegistry(t, testCatalog())
	// The step budget allows two steps; the action budget fits the
	// first plan but not the second — the run ends on
	// BUDGET_EXHAUSTED before the second plan dispatches anything.
	planner := &fakePlanner{fn: func(step int, in PlanInput) (Plan, error) {
		if step == 1 {
			return Plan{StepID: "s1", Actions: []PlanAction{alphaAction("a1"), alphaAction("a2")}}, nil
		}
		return Plan{StepID: "s2", Actions: []PlanAction{alphaAction("a3"), alphaAction("a4")}}, nil
	}}
	reass := &fakeReassessor{fn: func(in ReassessInput) (Reassessment, error) {
		return Reassessment{Status: ReassessContinue}, nil
	}}
	broker := &fakeBroker{fn: func(a PlanAction) (Observation, error) {
		return okObservation(a.ID), nil
	}}
	e := newEngine(reg, planner, reass, broker)
	e.MaxActions = 3
	res, err := e.Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Termination != TermBudgetExhausted {
		t.Fatalf("termination = %q, want BUDGET_EXHAUSTED", res.Termination)
	}
	if broker.calls != 2 {
		t.Fatalf("broker calls = %d, want 2", broker.calls)
	}
}

func TestEngineBudgetPlanOverrun(t *testing.T) {
	reg := testRegistry(t, testCatalog())
	planner := &fakePlanner{fn: func(step int, in PlanInput) (Plan, error) {
		return Plan{StepID: "s1", Actions: []PlanAction{alphaAction("a1"), alphaAction("a2"), alphaAction("a3")}}, nil
	}}
	broker := &fakeBroker{fn: func(a PlanAction) (Observation, error) {
		return okObservation(a.ID), nil
	}}
	e := newEngine(reg, planner, &fakeReassessor{}, broker)
	e.MaxActions = 2
	res, err := e.Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Termination != TermBudgetExhausted {
		t.Fatalf("termination = %q, want BUDGET_EXHAUSTED", res.Termination)
	}
	if broker.calls != 0 {
		t.Fatalf("rejected plan must dispatch nothing, got %d calls", broker.calls)
	}
}

func TestEnginePlannerFailure(t *testing.T) {
	reg := testRegistry(t, testCatalog())
	planner := &fakePlanner{fn: func(step int, in PlanInput) (Plan, error) {
		return Plan{}, errors.New("model unavailable")
	}}
	res, err := newEngine(reg, planner, &fakeReassessor{}, &fakeBroker{}).Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Termination != TermPlannerFailure || res.Ready {
		t.Fatalf("termination = %q, want PLANNER_FAILURE", res.Termination)
	}
	if !strings.Contains(res.Reason, "model unavailable") {
		t.Fatalf("reason = %q", res.Reason)
	}
}

// plannerErrorEvents lists the recorded planner_error events in order.
func plannerErrorEvents(res Result) []Event {
	var out []Event
	for _, ev := range res.Events {
		if ev.Kind == EventPlannerError {
			out = append(out, ev)
		}
	}
	return out
}

// TestEnginePlanContractRepairSucceeds reproduces the recorded live
// failure: a plan answer that placed "module" at action level is a
// PlanContractError, earns exactly one bounded self-repair turn with
// the verbatim verdict and the rejected answer fed back through
// PlanInput, and the corrected plan runs the step normally. The
// recorded stream carries both attempts — the planner_error then the
// plan — inside the same step.
func TestEnginePlanContractRepairSucceeds(t *testing.T) {
	reg := testRegistry(t, testCatalog())
	var seen []PlanInput
	planner := &fakePlanner{fn: func(step int, in PlanInput) (Plan, error) {
		seen = append(seen, in)
		if len(seen) == 1 {
			return Plan{}, &PlanContractError{
				Answer: `{"step_id":"step-1","actions":[{"id":"s1-a1","adapter_id":"check-alpha","module":"example.com/mod","arguments":{}}]}`,
				Err:    errors.New(`plan answer did not decode as the plan contract: answer object does not satisfy the contract: json: unknown field "module"`),
			}
		}
		return Plan{StepID: "s1", Actions: []PlanAction{alphaAction("a1")}}, nil
	}}
	reass := &fakeReassessor{fn: func(in ReassessInput) (Reassessment, error) {
		return Reassessment{Status: ReassessReady}, nil
	}}
	broker := &fakeBroker{fn: func(a PlanAction) (Observation, error) { return okObservation(a.ID), nil }}
	res, err := newEngine(reg, planner, reass, broker).Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if planner.calls != 2 {
		t.Fatalf("planner calls = %d, want exactly one repair turn (2 calls)", planner.calls)
	}
	if len(seen) != 2 || seen[0].RepairError != "" || seen[0].RepairAnswer != "" {
		t.Fatalf("first attempt must carry no repair feedback: %+v", seen[0])
	}
	if !strings.Contains(seen[1].RepairError, `unknown field "module"`) {
		t.Fatalf("repair feedback missing the verbatim verdict: %q", seen[1].RepairError)
	}
	if !strings.Contains(seen[1].RepairAnswer, `"module":"example.com/mod"`) {
		t.Fatalf("repair feedback missing the rejected answer: %q", seen[1].RepairAnswer)
	}
	if res.Termination != TermDecisionReady || !res.Ready {
		t.Fatalf("termination = %q, want DECISION_READY after repair", res.Termination)
	}
	errs := plannerErrorEvents(res)
	if len(errs) != 1 || !strings.Contains(errs[0].Error, `unknown field "module"`) || errs[0].Step != 1 {
		t.Fatalf("recorded planner errors = %+v", errs)
	}
	plans := 0
	for _, ev := range res.Events {
		if ev.Kind == EventPlan {
			plans++
			if ev.Step != 1 {
				t.Fatalf("repaired plan recorded at step %d, want 1", ev.Step)
			}
		}
	}
	if plans != 1 {
		t.Fatalf("plan events = %d, want 1", plans)
	}
}

// TestEnginePlanContractRepairFails proves the bound: a repair answer
// that also fails the contract terminates the run with the ordinary
// PLANNER_FAILURE record — both attempts land in the event stream.
func TestEnginePlanContractRepairFails(t *testing.T) {
	reg := testRegistry(t, testCatalog())
	var seen []PlanInput
	planner := &fakePlanner{fn: func(step int, in PlanInput) (Plan, error) {
		seen = append(seen, in)
		if len(seen) == 1 {
			return Plan{}, &PlanContractError{
				Answer: `{"step_id":"step-1","actions":[{"id":"s1-a1","adapter_id":"check-alpha","module":"m"}]}`,
				Err:    errors.New(`plan answer did not decode as the plan contract: json: unknown field "module"`),
			}
		}
		return Plan{}, &PlanContractError{
			Answer: `{"step_id":"step-1","actions":[{"id":"s1-a1","adapter_id":"check-alpha","symbol":"s"}]}`,
			Err:    errors.New(`plan answer did not decode as the plan contract: json: unknown field "symbol"`),
		}
	}}
	res, err := newEngine(reg, planner, &fakeReassessor{}, &fakeBroker{}).Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if planner.calls != 2 {
		t.Fatalf("planner calls = %d, want exactly one repair turn (2 calls)", planner.calls)
	}
	if res.Termination != TermPlannerFailure || res.Ready {
		t.Fatalf("termination = %q, want PLANNER_FAILURE", res.Termination)
	}
	if !strings.Contains(res.Reason, `unknown field "symbol"`) {
		t.Fatalf("reason = %q, want the second contract failure recorded", res.Reason)
	}
	errs := plannerErrorEvents(res)
	if len(errs) != 2 {
		t.Fatalf("recorded planner errors = %d, want both attempts", len(errs))
	}
	if !strings.Contains(errs[0].Error, `"module"`) || !strings.Contains(errs[1].Error, `"symbol"`) {
		t.Fatalf("planner errors = %+v", errs)
	}
	for _, ev := range res.Events {
		if ev.Kind == EventPlan {
			t.Fatalf("a plan event was recorded for a run with no admitted plan")
		}
	}
}

// TestEnginePlannerErrorNoRepair pins the bound to contract failures:
// any other planner error class terminates on the first failure — a
// planner that produced no answer has nothing to repair from.
func TestEnginePlannerErrorNoRepair(t *testing.T) {
	reg := testRegistry(t, testCatalog())
	planner := &fakePlanner{fn: func(step int, in PlanInput) (Plan, error) {
		return Plan{}, errors.New("provider refused the request")
	}}
	res, err := newEngine(reg, planner, &fakeReassessor{}, &fakeBroker{}).Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if planner.calls != 1 {
		t.Fatalf("planner calls = %d, want no repair turn for a non-contract error", planner.calls)
	}
	if res.Termination != TermPlannerFailure {
		t.Fatalf("termination = %q, want PLANNER_FAILURE", res.Termination)
	}
	if errs := plannerErrorEvents(res); len(errs) != 1 {
		t.Fatalf("recorded planner errors = %d, want 1", len(errs))
	}
}

// TestEnginePositiveAnswerDischargesRequired pins the positive-answer
// discharge path: a produced observation that answers its required
// check's question below COMPLETE — a bounded positive verdict the
// check's own contract stamps — discharges the requirement and keeps
// the ledger clean, so the READY claim holds at DECISION_READY.
// Without it a positive package-usage verdict (PARTIAL by contract)
// would loop: the reassessor could never close the run.
func TestEnginePositiveAnswerDischargesRequired(t *testing.T) {
	reg := testRegistry(t, testCatalog())
	var seen []PlanInput
	planner := &fakePlanner{fn: func(step int, in PlanInput) (Plan, error) {
		seen = append(seen, in)
		return Plan{StepID: "s1", Actions: []PlanAction{alphaAction("a1")}}, nil
	}}
	var seenRe []ReassessInput
	reass := &fakeReassessor{fn: func(in ReassessInput) (Reassessment, error) {
		seenRe = append(seenRe, in)
		return Reassessment{Status: ReassessReady}, nil
	}}
	broker := &fakeBroker{fn: func(a PlanAction) (Observation, error) {
		o := okObservation(a.ID)
		o.Completeness = ObsPartial
		o.DischargePath = DischargePositiveAnswer
		o.Limitations = []string{"positive static usage does not establish runtime execution or attacker reachability"}
		return o, nil
	}}
	res, err := newEngine(reg, planner, reass, broker).Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Termination != TermDecisionReady || !res.Ready {
		t.Fatalf("termination = %q ready=%v, want DECISION_READY", res.Termination, res.Ready)
	}
	if !res.Complete {
		t.Fatal("a positively answered required check leaves the ledger complete")
	}
	if len(res.Observations) != 1 || res.Observations[0].DischargePath != DischargePositiveAnswer {
		t.Fatalf("recorded observation lost the discharge path: %+v", res.Observations)
	}
	if len(seenRe) != 1 || !containsAll(seenRe[0].DischargedChecks, "check-alpha") {
		t.Fatalf("required check not discharged for the reassessor: %+v", seenRe)
	}
	for _, l := range res.Limitations {
		if strings.Contains(l, "coverage is not closed") {
			t.Fatalf("answered positive observation degraded the ledger: %v", res.Limitations)
		}
	}
}

// TestEnginePositiveAnswerStopsRequiring proves a discharged check
// stops being required: step 1's PARTIAL positive observation puts
// check-alpha in discharged_checks, so step 2's planner view no
// longer lists it as missing — the live loop can never re-plan an
// identical call to satisfy the same requirement.
func TestEnginePositiveAnswerStopsRequiring(t *testing.T) {
	reg := testRegistry(t, testCatalog())
	var seen []PlanInput
	planner := &fakePlanner{fn: func(step int, in PlanInput) (Plan, error) {
		seen = append(seen, in)
		return Plan{StepID: fmt.Sprintf("s%d", step), Actions: []PlanAction{alphaAction(fmt.Sprintf("a%d", step))}}, nil
	}}
	reassCalls := 0
	reass := &fakeReassessor{fn: func(in ReassessInput) (Reassessment, error) {
		reassCalls++
		if !containsAll(in.DischargedChecks, "check-alpha") {
			t.Fatalf("step %d reassess view lacks the discharge: %v", in.Step, in.DischargedChecks)
		}
		if reassCalls == 1 {
			return Reassessment{Status: ReassessContinue}, nil
		}
		return Reassessment{Status: ReassessReady}, nil
	}}
	broker := &fakeBroker{fn: func(a PlanAction) (Observation, error) {
		o := okObservation(a.ID)
		o.Completeness = ObsPartial
		o.DischargePath = DischargePositiveAnswer
		return o, nil
	}}
	res, err := newEngine(reg, planner, reass, broker).Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Termination != TermDecisionReady {
		t.Fatalf("termination = %q reason %q", res.Termination, res.Reason)
	}
	if len(seen) != 2 || !containsAll(seen[1].DischargedChecks, "check-alpha") {
		t.Fatalf("step-2 planner view still requires the answered check: %+v", seen)
	}
}

// TestEngineAnswerlessPartialNeverDischarges pins the fail-closed
// side: a produced observation whose payload answers nothing (PARTIAL,
// no stamped path) neither discharges the required check nor keeps the
// ledger clean — the READY claim degrades to NOT_DECISION_READY.
func TestEngineAnswerlessPartialNeverDischarges(t *testing.T) {
	reg := testRegistry(t, testCatalog())
	planner := &fakePlanner{fn: func(step int, in PlanInput) (Plan, error) {
		return Plan{StepID: "s1", Actions: []PlanAction{alphaAction("a1")}}, nil
	}}
	reass := &fakeReassessor{fn: func(in ReassessInput) (Reassessment, error) {
		return Reassessment{Status: ReassessReady}, nil
	}}
	broker := &fakeBroker{fn: func(a PlanAction) (Observation, error) {
		o := okObservation(a.ID)
		o.Completeness = ObsPartial
		return o, nil
	}}
	res, err := newEngine(reg, planner, reass, broker).Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Termination != TermNotDecisionReady || res.Ready {
		t.Fatalf("termination = %q, want NOT_DECISION_READY", res.Termination)
	}
	if !strings.Contains(res.Reason, "degraded") && !strings.Contains(res.Reason, "check-alpha") {
		t.Fatalf("reason = %q, want degraded coverage or undischarged check named", res.Reason)
	}
	if res.Complete {
		t.Fatal("an unanswered required check cannot mark the run complete")
	}
}

// TestEngineInformationalPartialKeepsLedger pins the informational-tool
// carve-out: a bounded OK, audit-bound record below COMPLETE from a
// check the policy does not require (module-usage/module-internal-reach
// report PARTIAL by contract) records its bound as a limitation but
// never degrades the ledger — the more the planner investigates, the
// more evidence it gathers, never less decision-ready.
func TestEngineInformationalPartialKeepsLedger(t *testing.T) {
	reg := testRegistry(t, testCatalog())
	planner := &fakePlanner{fn: func(step int, in PlanInput) (Plan, error) {
		return Plan{StepID: "s1", Actions: []PlanAction{
			alphaAction("a1"),
			{ID: "a2", AdapterID: "check-beta",
				Arguments: json.RawMessage(`{"subject":"s"}`), Purpose: "explore"},
		}}, nil
	}}
	reass := &fakeReassessor{fn: func(in ReassessInput) (Reassessment, error) {
		return Reassessment{Status: ReassessReady}, nil
	}}
	broker := &fakeBroker{fn: func(a PlanAction) (Observation, error) {
		o := okObservation(a.ID)
		if a.AdapterID == "check-beta" {
			o.Completeness = ObsPartial
			o.Limitations = []string{"enumerated sites are a static over-approximation by contract"}
		}
		return o, nil
	}}
	res, err := newEngine(reg, planner, reass, broker).Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Termination != TermDecisionReady || !res.Ready || !res.Complete {
		t.Fatalf("termination = %q ready=%v complete=%v reason %q — informational PARTIAL degraded the run",
			res.Termination, res.Ready, res.Complete, res.Reason)
	}
	// The bound stays recorded: the limitation row exists and the
	// observation's own limitations ride verbatim.
	var recorded bool
	for _, l := range res.Limitations {
		if strings.Contains(l, `action "a2" completeness is PARTIAL`) {
			recorded = true
		}
	}
	if !recorded {
		t.Fatalf("informational bound unrecorded: %v", res.Limitations)
	}
	if len(res.Observations) != 2 || len(res.Observations[1].Limitations) != 1 {
		t.Fatalf("observation limits lost: %+v", res.Observations)
	}
}

// TestEngineRequiredPartialNamesCheck pins the strict side: the same
// PARTIAL record on a policy-required check is an unanswered
// requirement — the run is NOT_DECISION_READY and names the check.
func TestEngineRequiredPartialNamesCheck(t *testing.T) {
	reg := testRegistry(t, testCatalog())
	planner := &fakePlanner{fn: func(step int, in PlanInput) (Plan, error) {
		return Plan{StepID: "s1", Actions: []PlanAction{alphaAction("a1")}}, nil
	}}
	reass := &fakeReassessor{fn: func(in ReassessInput) (Reassessment, error) {
		return Reassessment{Status: ReassessReady}, nil
	}}
	broker := &fakeBroker{fn: func(a PlanAction) (Observation, error) {
		o := okObservation(a.ID)
		o.Completeness = ObsPartial
		return o, nil
	}}
	res, err := newEngine(reg, planner, reass, broker).Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Termination != TermNotDecisionReady || res.Ready || res.Complete {
		t.Fatalf("termination = %q, want NOT_DECISION_READY", res.Termination)
	}
	if !strings.Contains(res.Reason, "check-alpha") {
		t.Fatalf("reason = %q, want the undischarged check named", res.Reason)
	}
}

// TestEngineInformationalBrokenRecordStillCaps proves the carve-out is
// only for complete bounded answers: a non-OK or unbound observation
// from a non-required tool is a genuine defect and still degrades.
func TestEngineInformationalBrokenRecordStillCaps(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(o *Observation)
	}{
		{"errored", func(o *Observation) {
			o.Status = ObsStatusError
			o.Completeness = ObsUnknown
		}},
		{"unbound", func(o *Observation) {
			o.Completeness = ObsPartial
			o.AuditBound = false
		}},
		{"no-digest", func(o *Observation) {
			o.Completeness = ObsPartial
			o.DataDigest = ""
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reg := testRegistry(t, testCatalog())
			planner := &fakePlanner{fn: func(step int, in PlanInput) (Plan, error) {
				return Plan{StepID: "s1", Actions: []PlanAction{
					alphaAction("a1"),
					{ID: "a2", AdapterID: "check-beta",
						Arguments: json.RawMessage(`{"subject":"s"}`), Purpose: "explore"},
				}}, nil
			}}
			reass := &fakeReassessor{fn: func(in ReassessInput) (Reassessment, error) {
				return Reassessment{Status: ReassessReady}, nil
			}}
			broker := &fakeBroker{fn: func(a PlanAction) (Observation, error) {
				o := okObservation(a.ID)
				if a.AdapterID == "check-beta" {
					tc.mut(&o)
				}
				return o, nil
			}}
			res, err := newEngine(reg, planner, reass, broker).Run(context.Background(), testInput())
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			if res.Termination != TermNotDecisionReady || res.Complete {
				t.Fatalf("%s: termination = %q complete=%v — a broken record must degrade",
					tc.name, res.Termination, res.Complete)
			}
		})
	}
}

// TestEngineRequiredUnknownStillCaps pins (d): a required check whose
// observation answers nothing (UNKNOWN completeness) still fails
// closed — the informational carve-out never widens it.
func TestEngineRequiredUnknownStillCaps(t *testing.T) {
	reg := testRegistry(t, testCatalog())
	planner := &fakePlanner{fn: func(step int, in PlanInput) (Plan, error) {
		return Plan{StepID: "s1", Actions: []PlanAction{alphaAction("a1")}}, nil
	}}
	reass := &fakeReassessor{fn: func(in ReassessInput) (Reassessment, error) {
		return Reassessment{Status: ReassessReady}, nil
	}}
	broker := &fakeBroker{fn: func(a PlanAction) (Observation, error) {
		o := okObservation(a.ID)
		o.Completeness = ObsUnknown
		return o, nil
	}}
	res, err := newEngine(reg, planner, reass, broker).Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Termination != TermNotDecisionReady || res.Complete {
		t.Fatalf("termination = %q, want NOT_DECISION_READY", res.Termination)
	}
	if !strings.Contains(res.Reason, "check-alpha") {
		t.Fatalf("reason = %q, want the unanswered check named", res.Reason)
	}
}

// TestEngineAdmissionRejectionRepairSucceeds reproduces the recorded
// live failure: a decoded plan the admission gate refuses (the
// registry's rejected-arguments/unknown-check family or the subject
// gate) earns the same single bounded repair turn the wire-contract
// failure has — the rejected plan is recorded on the plan event's
// Error member, the reason and the re-encoded plan go back through
// PlanInput, and the corrected plan runs the step normally.
func TestEngineAdmissionRejectionRepairSucceeds(t *testing.T) {
	reg := testRegistry(t, testCatalog())
	var seen []PlanInput
	bad := Plan{StepID: "s1", Actions: []PlanAction{{
		ID: "a1", AdapterID: "check-ghost", Arguments: json.RawMessage(`{}`), Purpose: "probe"}}}
	planner := &fakePlanner{fn: func(step int, in PlanInput) (Plan, error) {
		seen = append(seen, in)
		if len(seen) == 1 {
			return bad, nil
		}
		return Plan{StepID: "s1", Actions: []PlanAction{alphaAction("a1")}}, nil
	}}
	reass := &fakeReassessor{fn: func(in ReassessInput) (Reassessment, error) {
		return Reassessment{Status: ReassessReady}, nil
	}}
	broker := &fakeBroker{fn: func(a PlanAction) (Observation, error) { return okObservation(a.ID), nil }}
	res, err := newEngine(reg, planner, reass, broker).Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if planner.calls != 2 {
		t.Fatalf("planner calls = %d, want exactly one repair turn (2 calls)", planner.calls)
	}
	if len(seen) != 2 || seen[0].RepairError != "" || seen[0].RepairAnswer != "" {
		t.Fatalf("first attempt carried repair feedback: %+v", seen[0])
	}
	if !strings.Contains(seen[1].RepairError, "check-ghost") ||
		!strings.Contains(seen[1].RepairAnswer, `"adapter_id":"check-ghost"`) {
		t.Fatalf("repair feedback = %q / %q", seen[1].RepairError, seen[1].RepairAnswer)
	}
	if res.Termination != TermDecisionReady || !res.Ready {
		t.Fatalf("termination = %q, want DECISION_READY after repair", res.Termination)
	}
	if broker.calls != 1 || res.Actions[0].AdapterID != "check-alpha" {
		t.Fatalf("the rejected action executed or the repaired plan lost: broker=%d actions=%+v", broker.calls, res.Actions)
	}
	// The rejected plan stays recorded — the first plan event carries
	// the admission rejection on Error; the repaired one is clean.
	var planErrs, plans int
	for _, ev := range res.Events {
		if ev.Kind != EventPlan {
			continue
		}
		plans++
		if ev.Error != "" {
			planErrs++
			if !strings.Contains(ev.Error, "check-ghost") {
				t.Fatalf("rejected plan event error = %q", ev.Error)
			}
		}
	}
	if plans != 2 || planErrs != 1 {
		t.Fatalf("plan events = %d (rejected %d), want 2 (1)", plans, planErrs)
	}
}

// TestEngineAdmissionRejectionRepairFails proves the bound: when the
// repaired plan is also refused by admission the run terminates with
// the recorded UNSUPPORTED_CHECK_OR_CONDITION reason — the repair turn
// is never repeated.
func TestEngineAdmissionRejectionRepairFails(t *testing.T) {
	reg := testRegistry(t, testCatalog())
	planner := &fakePlanner{fn: func(step int, in PlanInput) (Plan, error) {
		return Plan{StepID: "s1", Actions: []PlanAction{{
			ID: "a1", AdapterID: "check-ghost", Arguments: json.RawMessage(`{}`), Purpose: "probe"}}}, nil
	}}
	broker := &fakeBroker{fn: func(a PlanAction) (Observation, error) { return okObservation(a.ID), nil }}
	res, err := newEngine(reg, planner, &fakeReassessor{}, broker).Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if planner.calls != 2 {
		t.Fatalf("planner calls = %d, want exactly one repair turn (2 calls)", planner.calls)
	}
	if res.Termination != TermUnsupported || res.Ready {
		t.Fatalf("termination = %q, want UNSUPPORTED_CHECK_OR_CONDITION", res.Termination)
	}
	if !strings.Contains(res.Reason, "check-ghost") {
		t.Fatalf("reason = %q, want the admission rejection recorded", res.Reason)
	}
	if broker.calls != 0 || len(res.Actions) != 0 {
		t.Fatalf("a rejected plan executed: broker=%d actions=%d", broker.calls, len(res.Actions))
	}
}

// TestEngineRepairTurnSharedAcrossClasses proves the one-turn bound
// spans both repairable classes: a contract-repaired plan that then
// fails admission terminates immediately — no third planner turn.
func TestEngineRepairTurnSharedAcrossClasses(t *testing.T) {
	reg := testRegistry(t, testCatalog())
	planner := &fakePlanner{fn: func(step int, in PlanInput) (Plan, error) {
		if in.RepairError == "" {
			return Plan{}, &PlanContractError{
				Answer: `{"step_id":"step-1","actions":[{"id":"a1","module":"m"}]}`,
				Err:    errors.New(`plan answer did not decode: json: unknown field "module"`),
			}
		}
		return Plan{StepID: "s1", Actions: []PlanAction{{
			ID: "a1", AdapterID: "check-ghost", Arguments: json.RawMessage(`{}`), Purpose: "probe"}}}, nil
	}}
	res, err := newEngine(reg, planner, &fakeReassessor{}, &fakeBroker{}).Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if planner.calls != 2 {
		t.Fatalf("planner calls = %d, want the shared repair turn used once", planner.calls)
	}
	if res.Termination != TermUnsupported {
		t.Fatalf("termination = %q, want UNSUPPORTED_CHECK_OR_CONDITION", res.Termination)
	}
}

func TestEnginePlannerUnavailable(t *testing.T) {
	reg := testRegistry(t, testCatalog())
	e := newEngine(reg, nil, &fakeReassessor{}, &fakeBroker{})
	res, err := e.Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Termination != TermPlannerFailure || res.Ready {
		t.Fatalf("termination = %q, want PLANNER_FAILURE", res.Termination)
	}
	// An unavailable planner never produces a complete disposition:
	// the run terminates before any action exists.
	if len(res.Actions) != 0 || len(res.Observations) != 0 {
		t.Fatalf("planner-unavailable run produced actions/observations")
	}
}

func TestEnginePlannerMalformed(t *testing.T) {
	reg := testRegistry(t, testCatalog())
	planner := &fakePlanner{fn: func(step int, in PlanInput) (Plan, error) {
		return Plan{StepID: "s1"}, nil // empty plan
	}}
	res, err := newEngine(reg, planner, &fakeReassessor{}, &fakeBroker{}).Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Termination != TermPlannerFailure {
		t.Fatalf("termination = %q, want PLANNER_FAILURE", res.Termination)
	}
}

func TestEngineReassessorFailure(t *testing.T) {
	reg := testRegistry(t, testCatalog())
	planner := &fakePlanner{fn: func(step int, in PlanInput) (Plan, error) {
		return Plan{StepID: "s1", Actions: []PlanAction{alphaAction("a1")}}, nil
	}}
	reass := &fakeReassessor{fn: func(in ReassessInput) (Reassessment, error) {
		return Reassessment{}, errors.New("reassessor exploded")
	}}
	broker := &fakeBroker{fn: func(a PlanAction) (Observation, error) {
		return okObservation(a.ID), nil
	}}
	res, err := newEngine(reg, planner, reass, broker).Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Termination != TermReassessorFailure || res.Ready {
		t.Fatalf("termination = %q, want REASSESSOR_FAILURE", res.Termination)
	}
}

func TestEngineReassessorUnavailable(t *testing.T) {
	reg := testRegistry(t, testCatalog())
	planner := &fakePlanner{fn: func(step int, in PlanInput) (Plan, error) {
		return Plan{StepID: "s1", Actions: []PlanAction{alphaAction("a1")}}, nil
	}}
	broker := &fakeBroker{fn: func(a PlanAction) (Observation, error) {
		return okObservation(a.ID), nil
	}}
	res, err := newEngine(reg, planner, nil, broker).Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Termination != TermReassessorFailure {
		t.Fatalf("termination = %q, want REASSESSOR_FAILURE", res.Termination)
	}
}

func TestEngineUnsupportedAdapter(t *testing.T) {
	reg := testRegistry(t, testCatalog())
	planner := &fakePlanner{fn: func(step int, in PlanInput) (Plan, error) {
		return Plan{StepID: "s1", Actions: []PlanAction{{
			ID: "a1", AdapterID: "check-ghost", Arguments: json.RawMessage(`{}`), Purpose: "probe",
		}}}, nil
	}}
	broker := &fakeBroker{fn: func(a PlanAction) (Observation, error) {
		return okObservation(a.ID), nil
	}}
	res, err := newEngine(reg, planner, &fakeReassessor{}, broker).Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Termination != TermUnsupported || res.Ready {
		t.Fatalf("termination = %q, want UNSUPPORTED_CHECK_OR_CONDITION", res.Termination)
	}
	if broker.calls != 0 {
		t.Fatalf("unregistered action executed %d times", broker.calls)
	}
}

func TestEngineUnsupportedCondition(t *testing.T) {
	reg := testRegistry(t, testCatalog(), "cond-one")
	planner := &fakePlanner{fn: func(step int, in PlanInput) (Plan, error) {
		return Plan{StepID: "s1", ConditionIDs: []string{"cond-ghost"}}, nil
	}}
	res, err := newEngine(reg, planner, &fakeReassessor{}, &fakeBroker{}).Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Termination != TermUnsupported {
		t.Fatalf("termination = %q, want UNSUPPORTED_CHECK_OR_CONDITION", res.Termination)
	}
}

func TestEngineNotDecisionReadyClaim(t *testing.T) {
	reg := testRegistry(t, testCatalog())
	planner := &fakePlanner{fn: func(step int, in PlanInput) (Plan, error) {
		return Plan{StepID: "s1", Actions: []PlanAction{alphaAction("a1")}}, nil
	}}
	reass := &fakeReassessor{fn: func(in ReassessInput) (Reassessment, error) {
		return Reassessment{Status: ReassessNotDecisionReady, Detail: "cannot discharge"}, nil
	}}
	broker := &fakeBroker{fn: func(a PlanAction) (Observation, error) {
		return okObservation(a.ID), nil
	}}
	res, err := newEngine(reg, planner, reass, broker).Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Termination != TermDecisionReady || !res.Ready {
		t.Fatalf("termination = %q ready=%v", res.Termination, res.Ready)
	}
	if res.ModelAdvisory == nil || res.ModelAdvisory.Declaration != ReassessNotDecisionReady || !res.ModelAdvisory.Diverged {
		t.Fatalf("model advisory = %+v", res.ModelAdvisory)
	}
}

func TestEngineReadyClaimDegradedLedger(t *testing.T) {
	reg := testRegistry(t, testCatalog())
	planner := &fakePlanner{fn: func(step int, in PlanInput) (Plan, error) {
		return Plan{StepID: "s1", Actions: []PlanAction{alphaAction("a1")}}, nil
	}}
	reass := &fakeReassessor{fn: func(in ReassessInput) (Reassessment, error) {
		return Reassessment{Status: ReassessReady}, nil
	}}
	// A TIMEOUT observation is a recorded limitation, never a
	// discharge — the READY claim degrades to NOT_DECISION_READY.
	broker := &fakeBroker{fn: func(a PlanAction) (Observation, error) {
		return Observation{ID: "OBS-1", ActionID: a.ID, Status: ObsStatusTimeout,
			Completeness: ObsUnknown, Scope: "check not performed", AuditBound: true}, nil
	}}
	res, err := newEngine(reg, planner, reass, broker).Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Termination != TermNotDecisionReady || res.Ready {
		t.Fatalf("termination = %q, want NOT_DECISION_READY", res.Termination)
	}
	if len(res.Observations) != 1 || res.Observations[0].Status != ObsStatusTimeout {
		t.Fatalf("observation = %+v", res.Observations)
	}
}

func TestEngineReadyClaimUndischargedRequired(t *testing.T) {
	reg := testRegistry(t, testCatalog())
	// check-alpha is policy-required but the planner runs only
	// check-beta — the READY claim cannot hold against undischarged
	// required coverage.
	planner := &fakePlanner{fn: func(step int, in PlanInput) (Plan, error) {
		return Plan{StepID: "s1", Actions: []PlanAction{{
			ID: "a1", AdapterID: "check-beta",
			Arguments: json.RawMessage(`{"subject":"s"}`), Purpose: "explore",
		}}}, nil
	}}
	reass := &fakeReassessor{fn: func(in ReassessInput) (Reassessment, error) {
		return Reassessment{Status: ReassessReady}, nil
	}}
	broker := &fakeBroker{fn: func(a PlanAction) (Observation, error) {
		return okObservation(a.ID), nil
	}}
	res, err := newEngine(reg, planner, reass, broker).Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Termination != TermNotDecisionReady || res.Ready {
		t.Fatalf("termination = %q, want NOT_DECISION_READY", res.Termination)
	}
}

func TestEngineMissingBrokerObservation(t *testing.T) {
	reg := testRegistry(t, testCatalog())
	planner := &fakePlanner{fn: func(step int, in PlanInput) (Plan, error) {
		return Plan{StepID: "s1", Actions: []PlanAction{alphaAction("a1")}}, nil
	}}
	reass := &fakeReassessor{fn: func(in ReassessInput) (Reassessment, error) {
		return Reassessment{Status: ReassessReady}, nil
	}}
	broker := &fakeBroker{fn: func(a PlanAction) (Observation, error) {
		return Observation{}, errors.New("transport lost the observation")
	}}
	res, err := newEngine(reg, planner, reass, broker).Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	// Broker error produces a synthesized ERROR observation — recorded,
	// never absent — and the READY claim cannot hold.
	if res.Termination != TermNotDecisionReady {
		t.Fatalf("termination = %q, want NOT_DECISION_READY", res.Termination)
	}
	if len(res.Observations) != 1 || res.Observations[0].Status != ObsStatusError {
		t.Fatalf("observation = %+v", res.Observations)
	}
}

func TestEngineAppendOnlyRevisions(t *testing.T) {
	reg := testRegistry(t, testCatalog())
	planner := &fakePlanner{fn: func(step int, in PlanInput) (Plan, error) {
		return Plan{StepID: fmt.Sprintf("s%d", step), Actions: []PlanAction{{
			ID: fmt.Sprintf("a%d", step), AdapterID: "check-beta",
			Arguments: json.RawMessage(`{"subject":"s"}`), Purpose: "explore",
		}}}, nil
	}}
	broker := &fakeBroker{fn: func(a PlanAction) (Observation, error) {
		return okObservation(a.ID), nil
	}}
	n := 0
	reass := &fakeReassessor{fn: func(in ReassessInput) (Reassessment, error) {
		n++
		if n == 1 {
			return Reassessment{Status: ReassessContinue,
				Revisions: []BranchRevision{{BranchID: "B-1", Status: BranchStatusAwaitingInput}}}, nil
		}
		return Reassessment{Status: ReassessNotDecisionReady,
			Revisions: []BranchRevision{{BranchID: "B-1", Status: BranchStatusComplete}}}, nil
	}}
	e := newEngine(reg, planner, reass, broker)
	res, err := e.Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(res.Branches) != 1 {
		t.Fatalf("branches = %+v", res.Branches)
	}
	br := res.Branches[0]
	if br.Status != BranchStatusComplete || len(br.Revisions) != 2 {
		t.Fatalf("branch = %+v", br)
	}
	if br.Revisions[0].Status != BranchStatusAwaitingInput {
		t.Fatalf("earlier revision was rewritten: %+v", br.Revisions)
	}
}

func TestEngineEventStreamComplete(t *testing.T) {
	reg := testRegistry(t, testCatalog(), "cond-one")
	planner := &fakePlanner{fn: func(step int, in PlanInput) (Plan, error) {
		return Plan{StepID: "s1", Actions: []PlanAction{alphaAction("a1")}, ConditionIDs: []string{"cond-one"}}, nil
	}}
	reass := &fakeReassessor{fn: func(in ReassessInput) (Reassessment, error) {
		return Reassessment{Status: ReassessReady}, nil
	}}
	broker := &fakeBroker{fn: func(a PlanAction) (Observation, error) {
		return okObservation(a.ID), nil
	}}
	res, err := newEngine(reg, planner, reass, broker).Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	var kinds []string
	for _, ev := range res.Events {
		kinds = append(kinds, ev.Kind)
	}
	want := []string{EventRunStart, EventPlan, EventAction, EventObservation, EventReassessment, EventTerminated}
	if strings.Join(kinds, ",") != strings.Join(want, ",") {
		t.Fatalf("event kinds = %v, want %v", kinds, want)
	}
	for i, ev := range res.Events {
		if ev.Seq != i+1 {
			t.Fatalf("event seq broken at %d", i)
		}
	}
}

// TestEngineRequiredCheckUnregistered: a policy that adds a required
// check no registered adapter can discharge is not a relaxation, but
// it can never be satisfied — the run stops NOT_DECISION_READY.
func TestEngineRequiredCheckUnregistered(t *testing.T) {
	reg := testRegistry(t, testCatalog())
	e := newEngine(reg, &fakePlanner{}, &fakeReassessor{}, &fakeBroker{})
	e.Policy.RequiredChecks = []string{"check-alpha", "check-ghost"}
	res, err := e.Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Termination != TermNotDecisionReady {
		t.Fatalf("termination = %q, want NOT_DECISION_READY", res.Termination)
	}
}

func TestEngineConfigErrors(t *testing.T) {
	if _, err := (&Engine{}).Run(context.Background(), Input{}); err == nil {
		t.Fatalf("missing registry must be a config error")
	}
	reg := testRegistry(t, testCatalog())
	if _, err := (&Engine{Registry: reg}).Run(context.Background(), Input{}); err == nil {
		t.Fatalf("missing broker must be a config error")
	}
	e := newEngine(reg, &fakePlanner{}, &fakeReassessor{}, &fakeBroker{})
	e.MaxSteps = -1
	if _, err := e.Run(context.Background(), Input{}); err == nil {
		t.Fatalf("negative MaxSteps must be a config error")
	}
}

// TestPlanValidation exercises plan admission directly: every verdict
// class — malformed, unsupported, over-budget — fails closed before a
// single action can execute.
func TestPlanValidation(t *testing.T) {
	reg := testRegistry(t, testCatalog(), "cond-one")

	if v, _ := validatePlan(reg, &Plan{StepID: "s"}, 8); v != planMalformed {
		t.Fatalf("empty plan verdict = %v", v)
	}
	dup := Plan{StepID: "s", Actions: []PlanAction{alphaAction("a1"), alphaAction("a1")}}
	if v, _ := validatePlan(reg, &dup, 8); v != planMalformed {
		t.Fatalf("duplicate action id verdict = %v", v)
	}
	unk := Plan{StepID: "s", Actions: []PlanAction{{ID: "a1", AdapterID: "check-ghost", Purpose: "x"}}}
	if v, _ := validatePlan(reg, &unk, 8); v != planUnsupported {
		t.Fatalf("unregistered adapter verdict = %v", v)
	}
	unkCond := Plan{StepID: "s", ConditionIDs: []string{"cond-ghost"}}
	if v, _ := validatePlan(reg, &unkCond, 8); v != planUnsupported {
		t.Fatalf("unknown condition verdict = %v", v)
	}
	badCondRef := Plan{StepID: "s", Actions: []PlanAction{{
		ID: "a1", AdapterID: "check-alpha", Arguments: json.RawMessage(`{"subject":"s"}`),
		Purpose: "x", ConditionID: "cond-ghost",
	}}}
	if v, _ := validatePlan(reg, &badCondRef, 8); v != planUnsupported {
		t.Fatalf("unknown action condition verdict = %v", v)
	}
	over := Plan{StepID: "s", Actions: []PlanAction{alphaAction("a1"), alphaAction("a2")}}
	if v, _ := validatePlan(reg, &over, 1); v != planOverBudget {
		t.Fatalf("over-budget plan verdict = %v", v)
	}
	good := Plan{StepID: "s", Actions: []PlanAction{alphaAction("a1")}, ConditionIDs: []string{"cond-one"}}
	if v, why := validatePlan(reg, &good, 8); v != planAdmit {
		t.Fatalf("valid plan rejected: %v %s", v, why)
	}
}

// TestEngineLaneCarriedCheckDischarged: a policy-required check the
// catalog registers but cannot dispatch discharges from a
// caller-declared completion (the lane's audit record) — the run
// reaches DECISION_READY without the planner ever seeing the
// undispatchable id in available_checks, and the discharged id stays
// visible in discharged_checks.
func TestEngineLaneCarriedCheckDischarged(t *testing.T) {
	cat := testCatalog()
	cat.addGhost("lane-only")
	reg := testRegistry(t, cat)
	var seen PlanInput
	planner := &fakePlanner{fn: func(step int, in PlanInput) (Plan, error) {
		seen = in
		return Plan{StepID: "s1", Actions: []PlanAction{alphaAction("a1")}}, nil
	}}
	reass := &fakeReassessor{fn: func(in ReassessInput) (Reassessment, error) {
		return Reassessment{Status: ReassessReady}, nil
	}}
	broker := &fakeBroker{fn: func(a PlanAction) (Observation, error) {
		return okObservation(a.ID), nil
	}}
	e := newEngine(reg, planner, reass, broker)
	e.Policy.RequiredChecks = []string{"check-alpha", "lane-only"}
	in := testInput()
	in.Baseline.RequiredChecks = []string{"check-alpha", "lane-only"}
	in.CompletedChecks = []string{"lane-only"}
	res, err := e.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Termination != TermDecisionReady || !res.Ready {
		t.Fatalf("termination = %q reason %q, want DECISION_READY", res.Termination, res.Reason)
	}
	for _, id := range seen.AvailableChecks {
		if id == "lane-only" {
			t.Fatalf("undispatchable id advertised in available_checks: %v", seen.AvailableChecks)
		}
	}
	if !containsAll(seen.AvailableChecks, "check-alpha", "check-beta") {
		t.Fatalf("dispatchable checks missing from available_checks: %v", seen.AvailableChecks)
	}
	if !containsAll(seen.RequiredChecks, "check-alpha", "lane-only") {
		t.Fatalf("required surface lost ids: %v", seen.RequiredChecks)
	}
	if !containsAll(seen.DischargedChecks, "lane-only") {
		t.Fatalf("lane discharge not visible: %v", seen.DischargedChecks)
	}
	if !containsAll(res.CompletedChecks, "lane-only") {
		t.Fatalf("completed checks = %v", res.CompletedChecks)
	}
}

// TestEngineLaneCarriedCheckUndischarged: a policy-required check that
// is registered but undispatchable and that no declared completion
// discharged fails closed: the run start names it, a ready claim
// degrades to NOT_DECISION_READY naming the missing requirement, and
// the requirement never leaves the recorded policy.
func TestEngineLaneCarriedCheckUndischarged(t *testing.T) {
	cat := testCatalog()
	cat.addGhost("lane-only")
	reg := testRegistry(t, cat)
	planner := &fakePlanner{fn: func(step int, in PlanInput) (Plan, error) {
		return Plan{StepID: "s1", Actions: []PlanAction{alphaAction("a1")}}, nil
	}}
	reass := &fakeReassessor{fn: func(in ReassessInput) (Reassessment, error) {
		return Reassessment{Status: ReassessReady}, nil
	}}
	broker := &fakeBroker{fn: func(a PlanAction) (Observation, error) {
		return okObservation(a.ID), nil
	}}
	e := newEngine(reg, planner, reass, broker)
	e.Policy.RequiredChecks = []string{"check-alpha", "lane-only"}
	in := testInput()
	in.Baseline.RequiredChecks = []string{"check-alpha", "lane-only"}
	res, err := e.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Termination != TermNotDecisionReady || res.Ready {
		t.Fatalf("termination = %q, want NOT_DECISION_READY", res.Termination)
	}
	if !strings.Contains(res.Reason, "lane-only") {
		t.Fatalf("termination reason must name the undischarged check: %q", res.Reason)
	}
	found := false
	for _, l := range res.Limitations {
		if strings.Contains(l, "lane-only") && strings.Contains(l, "not dispatchable") {
			found = true
		}
	}
	if !found {
		t.Fatalf("run start never named the unreachable requirement: %v", res.Limitations)
	}
	if !containsAll(res.Policy.RequiredChecks, "check-alpha", "lane-only") {
		t.Fatalf("recorded policy lost the requirement: %v", res.Policy.RequiredChecks)
	}
	if res.Complete {
		t.Fatal("an undischarged required check cannot mark the run complete")
	}
}

// TestEngineLaneCarriedPlanRejected: a planner that schedules a
// registered-but-undispatchable id still gets an explicit
// UNSUPPORTED_CHECK_OR_CONDITION — the reason now names why (a
// lane-carried check, not a dispatchable adapter) instead of the bare
// "not registered".
func TestEngineLaneCarriedPlanRejected(t *testing.T) {
	cat := testCatalog()
	cat.addGhost("lane-only")
	reg := testRegistry(t, cat)
	planner := &fakePlanner{fn: func(step int, in PlanInput) (Plan, error) {
		return Plan{StepID: "s1", Actions: []PlanAction{{
			ID: "a1", AdapterID: "lane-only",
			Arguments: json.RawMessage(`{}`), Purpose: "p"}}}, nil
	}}
	reass := &fakeReassessor{fn: func(in ReassessInput) (Reassessment, error) {
		return Reassessment{Status: ReassessReady}, nil
	}}
	broker := &fakeBroker{fn: func(a PlanAction) (Observation, error) {
		return okObservation(a.ID), nil
	}}
	res, err := newEngine(reg, planner, reass, broker).Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Termination != TermUnsupported {
		t.Fatalf("termination = %q, want UNSUPPORTED_CHECK_OR_CONDITION", res.Termination)
	}
	if !strings.Contains(res.Reason, "lane-internal") {
		t.Fatalf("rejection must name the lane-internal reason: %q", res.Reason)
	}
	if broker.calls != 0 {
		t.Fatalf("rejected plan executed %d actions", broker.calls)
	}
}

// containsAll reports whether every member of want appears in have.
func containsAll(have []string, want ...string) bool {
	set := map[string]bool{}
	for _, v := range have {
		set[v] = true
	}
	for _, w := range want {
		if !set[w] {
			return false
		}
	}
	return true
}

func TestPlannerSeesCheckSchemasAndInapplicableRequirements(t *testing.T) {
	cat := testCatalog()
	cat.add("package-usage", "package-usage", 0, []string{"module", "package"}, nil)
	spec := cat.specs["check-alpha"]
	spec.ArgumentSchema = json.RawMessage(`{"type":"object","properties":{"subject":{"type":"string"}},"required":["subject"]}`)
	cat.specs["check-alpha"] = spec
	reg := testRegistry(t, cat)
	var seen PlanInput
	planner := &fakePlanner{fn: func(_ int, in PlanInput) (Plan, error) {
		seen = in
		return Plan{StepID: "s1", Actions: []PlanAction{alphaAction("a1")}}, nil
	}}
	reass := &fakeReassessor{fn: func(ReassessInput) (Reassessment, error) { return Reassessment{Status: ReassessReady}, nil }}
	broker := &fakeBroker{fn: func(a PlanAction) (Observation, error) { return okObservation(a.ID), nil }}
	e := newEngine(reg, planner, reass, broker)
	e.Policy.RequiredChecks = []string{"check-alpha", "package-usage"}
	in := testInput()
	in.Baseline.RequiredChecks = append([]string(nil), e.Policy.RequiredChecks...)
	in.InapplicableChecks = []string{"package-usage"}
	res, err := e.Run(context.Background(), in)
	if err != nil || res.Termination != TermDecisionReady {
		t.Fatalf("run termination=%s err=%v reason=%s", res.Termination, err, res.Reason)
	}
	if len(seen.AvailableCheckSpecs) != 3 || len(seen.AvailableCheckSpecs[0].ArgumentSchema) == 0 {
		t.Fatalf("planner did not receive argument schemas: %+v", seen.AvailableCheckSpecs)
	}
	if !containsAll(seen.InapplicableChecks, "package-usage") || !containsAll(res.InapplicableChecks, "package-usage") {
		t.Fatalf("inapplicable requirement not retained: planner=%v result=%v", seen.InapplicableChecks, res.InapplicableChecks)
	}
	if !strings.Contains(res.Reason, "package-usage") {
		t.Fatalf("terminal evidence does not name inapplicable check: %q", res.Reason)
	}
}

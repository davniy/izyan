package flow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// runRecorded executes a scripted live run and returns its recorded
// result — the replay input.
func runRecorded(t *testing.T, reg *CatalogRegistry, steps []planTurn, reas []Reassessment, obs func(a PlanAction) (Observation, error)) Result {
	t.Helper()
	p := &fakePlanner{fn: func(step int, in PlanInput) (Plan, error) {
		tn := steps[step-1]
		return tn.plan, tn.err
	}}
	r := &fakeReassessor{fn: func(in ReassessInput) (Reassessment, error) {
		return reas[in.Step-1], nil
	}}
	b := &fakeBroker{fn: obs}
	res, err := newEngine(reg, p, r, b).Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("recorded run: %v", err)
	}
	return res
}

type planTurn struct {
	plan Plan
	err  error
}

func TestReplayRoundTrip(t *testing.T) {
	reg := testRegistry(t, testCatalog(), "cond-one")
	live := runRecorded(t, reg,
		[]planTurn{
			{plan: Plan{StepID: "s1", Actions: []PlanAction{alphaAction("a1")}, ConditionIDs: []string{"cond-one"}}},
			{plan: Plan{StepID: "s2", Actions: []PlanAction{{
				ID: "b1", AdapterID: "check-beta",
				Arguments: json.RawMessage(`{"subject":"s2"}`), Purpose: "verify",
			}}}},
		},
		[]Reassessment{
			{Status: ReassessContinue, Revisions: []BranchRevision{{BranchID: "B-1", Status: BranchStatusAwaitingInput}}},
			{Status: ReassessReady, Revisions: []BranchRevision{{BranchID: "B-1", Status: BranchStatusComplete}}},
		},
		func(a PlanAction) (Observation, error) {
			return okObservation(a.ID), nil
		})
	if live.Termination != TermDecisionReady {
		t.Fatalf("live termination = %q", live.Termination)
	}
	got, err := Replay(context.Background(), ReplayInput{Result: live, Input: testInput(), Registry: reg})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !reflect.DeepEqual(live, got) {
		lb, _ := json.Marshal(live)
		gb, _ := json.Marshal(got)
		t.Fatalf("replay diverged:\nlive: %s\nreplay: %s", lb, gb)
	}
}

func TestReplayRoundTripFailurePaths(t *testing.T) {
	reg := testRegistry(t, testCatalog())
	// A run that ends in a planner error replays identically.
	live := runRecorded(t, reg,
		[]planTurn{{err: errRecordedPlanner}},
		nil,
		func(a PlanAction) (Observation, error) { return okObservation(a.ID), nil })
	if live.Termination != TermPlannerFailure {
		t.Fatalf("live termination = %q", live.Termination)
	}
	got, err := Replay(context.Background(), ReplayInput{Result: live, Input: testInput(), Registry: reg})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !reflect.DeepEqual(live, got) {
		t.Fatalf("planner-failure replay diverged: %q vs %q", live.Termination, got.Termination)
	}

	// A run with a broker error replays identically.
	live2 := runRecorded(t, reg,
		[]planTurn{{plan: Plan{StepID: "s1", Actions: []PlanAction{alphaAction("a1")}}}},
		[]Reassessment{{Status: ReassessNotDecisionReady}},
		func(a PlanAction) (Observation, error) { return Observation{}, errRecordedBroker })
	if live2.Termination != TermNotDecisionReady {
		t.Fatalf("live2 termination = %q", live2.Termination)
	}
	got2, err := Replay(context.Background(), ReplayInput{Result: live2, Input: testInput(), Registry: reg})
	if err != nil {
		t.Fatalf("replay2: %v", err)
	}
	if !reflect.DeepEqual(live2, got2) {
		lb, _ := json.Marshal(live2)
		gb, _ := json.Marshal(got2)
		t.Fatalf("broker-failure replay diverged:\nlive: %s\nreplay: %s", lb, gb)
	}
}

// TestReplayRoundTripContractRepair records a live run whose first
// plan answer failed the wire contract and whose single bounded
// self-repair turn produced the admitted plan: replay must feed the
// recorded planner_error back as a repairable PlanContractError and
// consume the recorded repair turn, reproducing the live run
// byte-identically — two planner calls, same events, same verdict.
func TestReplayRoundTripContractRepair(t *testing.T) {
	reg := testRegistry(t, testCatalog())
	calls := 0
	live, err := newEngine(reg,
		&fakePlanner{fn: func(step int, in PlanInput) (Plan, error) {
			calls++
			if calls == 1 {
				return Plan{}, &PlanContractError{
					Answer: `{"step_id":"step-1","actions":[{"id":"a1","adapter_id":"check-alpha","module":"m"}]}`,
					Err:    errors.New(`plan answer did not decode: json: unknown field "module"`),
				}
			}
			if in.RepairError == "" {
				t.Fatal("repair turn received no decoder verdict")
			}
			return Plan{StepID: "s1", Actions: []PlanAction{alphaAction("a1")}}, nil
		}},
		&fakeReassessor{fn: func(in ReassessInput) (Reassessment, error) {
			return Reassessment{Status: ReassessReady}, nil
		}},
		&fakeBroker{fn: func(a PlanAction) (Observation, error) { return okObservation(a.ID), nil }},
	).Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("recorded run: %v", err)
	}
	if live.Termination != TermDecisionReady {
		t.Fatalf("live termination = %q", live.Termination)
	}
	got, err := Replay(context.Background(), ReplayInput{Result: live, Input: testInput(), Registry: reg})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !reflect.DeepEqual(live, got) {
		lb, _ := json.Marshal(live)
		gb, _ := json.Marshal(got)
		t.Fatalf("repaired-run replay diverged:\nlive: %s\nreplay: %s", lb, gb)
	}
}

// TestReplayRoundTripContractRepairFails records a live run whose
// repair answer also failed the contract: the recorded stream is
// planner_error, planner_error, terminated. Replay must consume the
// recorded repair turn as the second failure and terminate
// identically — a record that replays as a single attempt would
// silently rewrite the run.
func TestReplayRoundTripContractRepairFails(t *testing.T) {
	reg := testRegistry(t, testCatalog())
	calls := 0
	live, err := newEngine(reg,
		&fakePlanner{fn: func(step int, in PlanInput) (Plan, error) {
			calls++
			return Plan{}, &PlanContractError{
				Answer: fmt.Sprintf(`{"attempt":%d}`, calls),
				Err:    fmt.Errorf("plan answer did not decode: contract failure %d", calls),
			}
		}},
		&fakeReassessor{},
		&fakeBroker{},
	).Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("recorded run: %v", err)
	}
	if live.Termination != TermPlannerFailure {
		t.Fatalf("live termination = %q", live.Termination)
	}
	got, err := Replay(context.Background(), ReplayInput{Result: live, Input: testInput(), Registry: reg})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !reflect.DeepEqual(live, got) {
		lb, _ := json.Marshal(live)
		gb, _ := json.Marshal(got)
		t.Fatalf("failed-repair replay diverged:\nlive: %s\nreplay: %s", lb, gb)
	}
}

// TestReplayRoundTripAdmissionRepair records a live run whose first
// decoded plan failed admission (an unregistered check): the recorded
// stream carries the rejected plan event (Error set) then the repaired
// plan — no planner_error. Replay replans both turns through the same
// admission gate and reproduces the live run byte-identically.
func TestReplayRoundTripAdmissionRepair(t *testing.T) {
	reg := testRegistry(t, testCatalog())
	calls := 0
	live, err := newEngine(reg,
		&fakePlanner{fn: func(step int, in PlanInput) (Plan, error) {
			calls++
			if calls == 1 {
				return Plan{StepID: "s1", Actions: []PlanAction{{
					ID: "a1", AdapterID: "check-ghost",
					Arguments: json.RawMessage(`{}`), Purpose: "probe"}}}, nil
			}
			if in.RepairError == "" || !strings.Contains(in.RepairAnswer, "check-ghost") {
				t.Fatalf("repair turn lacks the rejection feedback: %+v", in)
			}
			return Plan{StepID: "s1", Actions: []PlanAction{alphaAction("a1")}}, nil
		}},
		&fakeReassessor{fn: func(in ReassessInput) (Reassessment, error) {
			return Reassessment{Status: ReassessReady}, nil
		}},
		&fakeBroker{fn: func(a PlanAction) (Observation, error) { return okObservation(a.ID), nil }},
	).Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("recorded run: %v", err)
	}
	if live.Termination != TermDecisionReady {
		t.Fatalf("live termination = %q", live.Termination)
	}
	got, err := Replay(context.Background(), ReplayInput{Result: live, Input: testInput(), Registry: reg})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !reflect.DeepEqual(live, got) {
		lb, _ := json.Marshal(live)
		gb, _ := json.Marshal(got)
		t.Fatalf("admission-repair replay diverged:\nlive: %s\nreplay: %s", lb, gb)
	}
}

// TestReplayRoundTripAdmissionRepairFails records a live run whose
// repaired plan failed admission a second time: the recorded stream is
// two plan events (first carrying the rejection) then the terminal
// UNSUPPORTED_CHECK_OR_CONDITION — replay terminates identically
// instead of silently rewriting the run.
func TestReplayRoundTripAdmissionRepairFails(t *testing.T) {
	reg := testRegistry(t, testCatalog())
	live := runRecorded(t, reg,
		[]planTurn{{plan: Plan{StepID: "s1", Actions: []PlanAction{{
			ID: "a1", AdapterID: "check-ghost",
			Arguments: json.RawMessage(`{}`), Purpose: "probe"}}}}},
		nil,
		func(a PlanAction) (Observation, error) { return okObservation(a.ID), nil })
	if live.Termination != TermUnsupported {
		t.Fatalf("live termination = %q", live.Termination)
	}
	got, err := Replay(context.Background(), ReplayInput{Result: live, Input: testInput(), Registry: reg})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !reflect.DeepEqual(live, got) {
		lb, _ := json.Marshal(live)
		gb, _ := json.Marshal(got)
		t.Fatalf("failed-admission-repair replay diverged:\nlive: %s\nreplay: %s", lb, gb)
	}
}

var (
	errRecordedPlanner = errors.New("recorded planner failure")
	errRecordedBroker  = errors.New("recorded broker failure")
)

func TestReplayNoModelCalls(t *testing.T) {
	reg := testRegistry(t, testCatalog())
	live := runRecorded(t, reg,
		[]planTurn{{plan: Plan{StepID: "s1", Actions: []PlanAction{alphaAction("a1")}}}},
		[]Reassessment{{Status: ReassessReady}},
		func(a PlanAction) (Observation, error) { return okObservation(a.ID), nil })
	e, ri, err := ReplayEngine(ReplayInput{Result: live, Input: testInput(), Registry: reg})
	if err != nil {
		t.Fatalf("replay engine: %v", err)
	}
	// The replayed components are the recorded ones — assert the types
	// so a future refactor that wires real components in is caught.
	if _, ok := e.Planner.(*replayPlanner); !ok {
		t.Fatalf("replay planner = %T", e.Planner)
	}
	if _, ok := e.Reassessor.(*replayReassessor); !ok {
		t.Fatalf("replay reassessor = %T", e.Reassessor)
	}
	if _, ok := e.Broker.(*replayBroker); !ok {
		t.Fatalf("replay broker = %T", e.Broker)
	}
	got, err := e.Run(context.Background(), ri)
	if err != nil {
		t.Fatalf("replay run: %v", err)
	}
	if got.Termination != live.Termination {
		t.Fatalf("termination = %q, want %q", got.Termination, live.Termination)
	}
}

func TestReplayTamperedRecord(t *testing.T) {
	reg := testRegistry(t, testCatalog())
	live := runRecorded(t, reg,
		[]planTurn{{plan: Plan{StepID: "s1", Actions: []PlanAction{alphaAction("a1")}}}},
		[]Reassessment{{Status: ReassessReady}},
		func(a PlanAction) (Observation, error) { return okObservation(a.ID), nil })
	// Dropping the recorded observation truncates the stream — the
	// record is malformed and the replay errors instead of silently
	// producing a different result.
	bad := live
	var kept []Event
	for _, ev := range bad.Events {
		if ev.Kind == EventObservation {
			continue
		}
		kept = append(kept, ev)
	}
	bad.Events = kept
	if _, err := Replay(context.Background(), ReplayInput{Result: bad, Input: testInput(), Registry: reg}); err == nil {
		t.Fatalf("truncated record replayed")
	}
}

func TestReplayNarrowedRegistry(t *testing.T) {
	reg := testRegistry(t, testCatalog())
	live := runRecorded(t, reg,
		[]planTurn{{plan: Plan{StepID: "s1", Actions: []PlanAction{alphaAction("a1")}}}},
		[]Reassessment{{Status: ReassessReady}},
		func(a PlanAction) (Observation, error) { return okObservation(a.ID), nil })
	// A registry that no longer registers the recorded adapter replays
	// into a fail-closed stop — the recorded run cannot be laundered
	// past a tightened admission. The startup probe reports it first:
	// the policy-required check is no longer a registered adapter.
	narrowed := testRegistry(t, newFakeCatalog())
	got, err := Replay(context.Background(), ReplayInput{Result: live, Input: testInput(), Registry: narrowed})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if got.Termination != TermNotDecisionReady || got.Ready {
		t.Fatalf("termination = %q, want a fail-closed non-ready stop", got.Termination)
	}
}

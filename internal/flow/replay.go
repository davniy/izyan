package flow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
)

// Replay re-executes a recorded run without a model call: the recorded
// event stream supplies every planner output, every broker outcome and
// every reassessment verbatim, and the same engine re-derives plan
// admission, coverage accounting, terminal-claim checks and the
// termination. The replayed run is the recorded one — divergence
// surfaces as the same fail-closed termination the recorded data
// produces under the current registry.
//
// in.Result carries the recorded outcome with its event stream; the
// engine is pinned to the recorded startup policy (the run_start
// event's Policy) and the recorded resolved budgets so replay
// validates under exactly the configuration the live run observed.
// in.Input may supply the original run input (its Baseline restores
// the recorded monotonic floor); when it is absent the recorded
// startup policy stands in as the floor, which preserves every claim
// the live run's baseline already enforced.

// ReplayInput is the replay contract: the recorded result plus the
// admission surface. Registry must admit exactly what the original
// registry admitted — replay re-validates every recorded action and
// reassessment, so a registry that has since narrowed produces the
// fail-closed rejection the same plan would get today.
type ReplayInput struct {
	// Result is the recorded run result (with its event stream).
	Result Result
	// Input is the original run input when available; Baseline
	// restores the recorded monotonic floor and CompletedChecks the
	// recorded discharge declarations.
	Input Input
	// Registry re-admits recorded actions and conditions.
	Registry Registry
}

// Replay runs the recorded event stream through the engine with no
// planner, broker or reassessor behind the recorded inputs. The result
// equals the recorded result — same steps, observations, terminations
// and artifact inputs — or the replay reports a non-ready termination
// when the recorded data no longer validates.
func Replay(ctx context.Context, in ReplayInput) (Result, error) {
	e, ri, err := ReplayEngine(in)
	if err != nil {
		return Result{}, err
	}
	return e.Run(ctx, ri)
}

// ValidateHistoricalRecord checks the recorded playback streams and required
// startup configuration without re-admitting claims under today's registry.
// It never invokes a planner, broker, reassessor or evidence tool.
func ValidateHistoricalRecord(rec Result) error {
	if len(rec.Events) == 0 || rec.Events[0].Kind != EventRunStart ||
		rec.Events[0].Policy == nil || rec.Events[0].Budget == nil {
		return fmt.Errorf("historical flow replay: missing recorded startup policy/budget")
	}
	if rec.Budget.MaxSteps <= 0 || rec.Budget.MaxActions <= 0 {
		return fmt.Errorf("historical flow replay: missing resolved budget pins")
	}
	last := rec.Events[len(rec.Events)-1]
	if last.Kind != EventTerminated || last.Termination != rec.Termination {
		return fmt.Errorf("historical flow replay: missing or conflicting recorded termination")
	}
	var actions []PlanAction
	var observations []Observation
	for i, ev := range rec.Events {
		if i > 0 && (ev.Kind == EventRunStart || ev.Seq != rec.Events[i-1].Seq+1) {
			return fmt.Errorf("historical flow replay: invalid event sequence at %d", i)
		}
		switch ev.Kind {
		case EventRunStart, EventPlan, EventPlannerError, EventAction, EventObservation, EventLimitation, EventReassessment, EventReassessErr, EventTerminated:
		default:
			return fmt.Errorf("historical flow replay: unknown event kind %q", ev.Kind)
		}
		if ev.Kind == EventTerminated && i != len(rec.Events)-1 {
			return fmt.Errorf("historical flow replay: events after termination")
		}
		if ev.Kind == EventAction && ev.Action != nil { actions = append(actions, *ev.Action) }
		if ev.Kind == EventObservation && ev.Observation != nil {
			observations = append(observations, *ev.Observation)
		}
	}
	if len(observations) != len(rec.Observations) || (len(observations) > 0 && !reflect.DeepEqual(observations, rec.Observations)) {
		return fmt.Errorf("historical flow replay: result observations differ from recorded events")
	}
	if len(actions) != len(rec.Actions) || (len(actions) > 0 && !reflect.DeepEqual(actions, rec.Actions)) {
		return fmt.Errorf("historical flow replay: result actions differ from recorded events")
	}
	if _, err := replayPlanStream(rec); err != nil {
		return err
	}
	if _, err := replayReassessStream(rec); err != nil {
		return err
	}
	if _, err := replayObservationStream(rec); err != nil {
		return err
	}
	return nil
}

// ReplayEngine assembles the replaying engine and its run input from a
// recorded result: recorded plans, broker outcomes and reassessments
// replace the live components, the recorded startup policy and
// resolved budgets pin the configuration, and the caller-supplied
// registry re-admits every recorded request.
func ReplayEngine(in ReplayInput) (*Engine, Input, error) {
	if in.Registry == nil {
		return nil, Input{}, fmt.Errorf("flow replay: a registry is required")
	}
	rec := in.Result
	if len(rec.Events) == 0 {
		return nil, Input{}, fmt.Errorf("flow replay: recorded result carries no event stream")
	}
	plans, err := replayPlanStream(rec)
	if err != nil {
		return nil, Input{}, fmt.Errorf("flow replay: %w", err)
	}
	reas, err := replayReassessStream(rec)
	if err != nil {
		return nil, Input{}, fmt.Errorf("flow replay: %w", err)
	}
	obs, err := replayObservationStream(rec)
	if err != nil {
		return nil, Input{}, fmt.Errorf("flow replay: %w", err)
	}
	// The recorded startup policy (run_start) is the configured policy
	// the live engine validated; rec.Policy is the final effective one
	// after mid-run tightenings. Replay starts from the same startup
	// policy so every recorded tightening validates identically.
	policy := rec.Policy
	baseline := in.Input.Baseline
	for _, ev := range rec.Events {
		if ev.Kind == EventRunStart && ev.Policy != nil {
			policy = *ev.Policy
			break
		}
	}
	if baseline.empty() {
		baseline = policy
	}
	completed := rec.CompletedChecks
	if len(completed) == 0 {
		completed = in.Input.CompletedChecks
	}
	e := &Engine{
		Planner:    &replayPlanner{turns: plans},
		Reassessor: &replayReassessor{turns: reas},
		Broker:     &replayBroker{obs: obs},
		Registry:   in.Registry,
		Policy:     policy,
		MaxSteps:   rec.Budget.MaxSteps,
		MaxActions: rec.Budget.MaxActions,
	}
	ri := Input{
		RunID:              rec.RunID,
		Objective:          in.Input.Objective,
		Conditions:         rec.Conditions,
		Evidence:           rec.Evidence,
		CompletedChecks:    completed,
		InapplicableChecks: rec.InapplicableChecks,
		Baseline:           baseline,
	}
	return e, ri, nil
}

type replayPlanTurn struct {
	plan Plan
	err  string
	// repairable marks a recorded planner error that the recorded
	// stream shows was repaired: a planner_error event followed by a
	// further planner turn exists only because the engine granted the
	// one bounded self-repair turn a PlanContractError earns. Replay
	// reconstructs the same error class so the re-run consumes the
	// recorded repair turn instead of terminating early.
	repairable bool
}

// replayPlanStream extracts planner turns — recorded plans and
// recorded planner errors — from the event stream, in order. A
// planner error with no following planner turn is the run's terminal
// failure and replays as an ordinary error; one followed by a further
// turn is a repaired contract failure and replays repairable.
func replayPlanStream(rec Result) ([]replayPlanTurn, error) {
	var turns []replayPlanTurn
	for _, ev := range rec.Events {
		switch ev.Kind {
		case EventPlan:
			if ev.Plan == nil {
				return nil, fmt.Errorf("plan event at seq %d carries no plan", ev.Seq)
			}
			turns = append(turns, replayPlanTurn{plan: *ev.Plan})
		case EventPlannerError:
			turns = append(turns, replayPlanTurn{err: ev.Error})
		}
	}
	for i, t := range turns {
		if t.err != "" && i+1 < len(turns) {
			turns[i].repairable = true
		}
	}
	return turns, nil
}

type replayReassessTurn struct {
	re  Reassessment
	err string
}

// replayReassessStream extracts reassessment turns in order; a
// recorded reassessor error replays as the same error.
func replayReassessStream(rec Result) ([]replayReassessTurn, error) {
	var turns []replayReassessTurn
	for _, ev := range rec.Events {
		switch ev.Kind {
		case EventReassessment:
			if ev.Reassessment == nil {
				return nil, fmt.Errorf("reassessment event at seq %d carries no reassessment", ev.Seq)
			}
			turns = append(turns, replayReassessTurn{re: *ev.Reassessment})
		case EventReassessErr:
			turns = append(turns, replayReassessTurn{err: ev.Error})
		}
	}
	return turns, nil
}

type replayObsTurn struct {
	action *PlanAction
	obs    *Observation
	err    string
}

// replayObservationStream extracts the broker outcome per dispatched
// action in order: each action event is followed by the observation
// the broker produced, and EventAction.Error records a broker failure.
// An observation event without a preceding dispatch, or a dispatch
// with neither outcome nor error, is a malformed record.
func replayObservationStream(rec Result) ([]replayObsTurn, error) {
	var turns []replayObsTurn
	var pending *replayObsTurn
	flush := func() error {
		if pending == nil {
			return nil
		}
		if pending.err == "" && pending.obs == nil {
			return fmt.Errorf("recorded action %q carries neither an observation nor an error — the record is truncated", pending.action.ID)
		}
		turns = append(turns, *pending)
		pending = nil
		return nil
	}
	for i := range rec.Events {
		ev := &rec.Events[i]
		switch ev.Kind {
		case EventAction:
			if err := flush(); err != nil {
				return nil, err
			}
			if ev.Action == nil {
				return nil, fmt.Errorf("action event at seq %d carries no action", ev.Seq)
			}
			pending = &replayObsTurn{action: ev.Action, err: ev.Error}
		case EventObservation:
			if ev.Observation == nil {
				return nil, fmt.Errorf("observation event at seq %d carries no observation", ev.Seq)
			}
			if pending == nil {
				return nil, fmt.Errorf("observation event at seq %d has no recorded dispatch", ev.Seq)
			}
			pending.obs = ev.Observation
		case EventPlan, EventReassessment, EventReassessErr, EventTerminated:
			if err := flush(); err != nil {
				return nil, err
			}
		}
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return turns, nil
}

// replayPlanner feeds recorded plans and recorded planner errors back
// in order — never a model call. Running past the recorded stream is a
// truncated record, reported as a planner error so the run terminates
// with the same fail-closed semantics a live planner failure has.
type replayPlanner struct {
	turns []replayPlanTurn
	pos   int
}

func (p *replayPlanner) Plan(_ context.Context, _ PlanInput) (Plan, error) {
	if p.pos >= len(p.turns) {
		return Plan{}, errors.New("recorded run ended but the engine requested another plan — the record is truncated")
	}
	t := p.turns[p.pos]
	p.pos++
	if t.err != "" {
		if t.repairable {
			return Plan{}, &PlanContractError{Err: errors.New(t.err)}
		}
		return Plan{}, errors.New(t.err)
	}
	return *clonePlan(&t.plan), nil
}

// replayReassessor feeds recorded reassessments and recorded errors.
type replayReassessor struct {
	turns []replayReassessTurn
	pos   int
}

func (r *replayReassessor) Reassess(_ context.Context, _ ReassessInput) (Reassessment, error) {
	if r.pos >= len(r.turns) {
		return Reassessment{}, errors.New("recorded run ended but the engine requested another reassessment")
	}
	t := r.turns[r.pos]
	r.pos++
	if t.err != "" {
		return Reassessment{}, errors.New(t.err)
	}
	return *cloneReassessment(&t.re), nil
}

// replayBroker returns the recorded outcome per dispatched action, in
// dispatch order. An action the record carries an error for produces
// the recorded error — the engine synthesizes the same ERROR
// observation the live run recorded. A dispatch the record does not
// carry, or a mismatched action id, is a divergence and fails closed.
type replayBroker struct {
	obs []replayObsTurn
	pos int
}

func (b *replayBroker) Execute(_ context.Context, a PlanAction) (Observation, error) {
	if b.pos >= len(b.obs) {
		return Observation{}, errors.New("no recorded broker outcome for this dispatch — the record diverged")
	}
	t := b.obs[b.pos]
	b.pos++
	if t.action.ID != a.ID {
		return Observation{}, fmt.Errorf("recorded dispatch %q does not match action %q — the record diverged", t.action.ID, a.ID)
	}
	if t.err != "" {
		return Observation{}, errors.New(t.err)
	}
	return *cloneObservation(t.obs), nil
}

// --- clone helpers: recorded payloads are deep-copied into events and
// results so a caller mutating a returned object can never rewrite the
// run record, and replay emits the same bytes the live run observed. ---

func clonePlan(p *Plan) *Plan {
	if p == nil {
		return nil
	}
	out := *p
	out.Actions = make([]PlanAction, len(p.Actions))
	for i := range p.Actions {
		out.Actions[i] = *cloneAction(&p.Actions[i])
	}
	out.ConditionIDs = append([]string(nil), p.ConditionIDs...)
	return &out
}

func cloneAction(a *PlanAction) *PlanAction {
	if a == nil {
		return nil
	}
	out := *a
	out.Arguments = append(json.RawMessage(nil), a.Arguments...)
	return &out
}

func cloneObservation(o *Observation) *Observation {
	if o == nil {
		return nil
	}
	out := *o
	out.EvidenceRefs = append([]string(nil), o.EvidenceRefs...)
	out.Limitations = append([]string(nil), o.Limitations...)
	return &out
}

func cloneObservations(in []Observation) []Observation {
	out := make([]Observation, len(in))
	for i := range in {
		out[i] = *cloneObservation(&in[i])
	}
	return out
}

func cloneReassessment(r *Reassessment) *Reassessment {
	if r == nil {
		return nil
	}
	out := *r
	out.RequiredInputs = append([]string(nil), r.RequiredInputs...)
	out.Revisions = append([]BranchRevision(nil), r.Revisions...)
	if r.Policy != nil {
		out.Policy = clonePolicy(*r.Policy)
	}
	return &out
}

func clonePolicy(p Policy) *Policy {
	out := p
	out.RequiredRules = append([]string(nil), p.RequiredRules...)
	out.RequiredChecks = append([]string(nil), p.RequiredChecks...)
	out.ForbiddenPromotions = append([]string(nil), p.ForbiddenPromotions...)
	return &out
}

package flow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/davniy/izyan/internal/evidencetools"
)

// Engine is the generic react loop. It owns sequencing only: the
// Planner proposes steps, the Registry admits them, the Broker is the
// single execution path, the Reassessor claims state transitions, and
// the Policy bounds the run. The engine never interprets an
// observation, never invents a fact or a branch, and never lets a
// planner or reassessor write a disposition — the wire types carry no
// field for one.
type Engine struct {
	Planner    Planner
	Reassessor Reassessor
	Broker     Broker
	Registry   Registry
	Policy     SafetyPolicy
	MaxSteps   int
	MaxActions int
}

// runState is the mutable loop ledger for one Run.
type runState struct {
	res              Result
	budget           Budget
	floor            Policy
	policy           Policy
	registry         Registry
	objective        string
	branches         *branchLedger
	engaged          map[string]bool
	step             int
	completedInit    []string
	inapplicableInit []string
	discharged       map[string]bool
	produced         []Observation
	ledgerComplete   bool
}

// Run executes PLAN → validate → ACT → OBSERVE → REASSESS until a
// documented stop condition. A non-nil error means the engine itself
// could not be configured (missing broker/registry, negative budget);
// every in-loop outcome returns a Result with an explicit Termination.
func (e *Engine) Run(ctx context.Context, in Input) (Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	rs, err := e.open(ctx, in)
	if err != nil {
		return Result{}, err
	}
	if rs.res.Termination != "" {
		return rs.res, nil
	}
	return e.loop(ctx, rs), nil
}

// open performs run-start validation: engine shape, budgets, policy
// monotonicity against the baseline floor, engaged conditions and the
// policy-required check surface. Anything invalid ends the run with an
// explicit termination before the planner is ever invoked.
func (e *Engine) open(ctx context.Context, in Input) (*runState, error) {
	if e.Registry == nil {
		return nil, fmt.Errorf("flow: engine requires a registry")
	}
	if e.Broker == nil {
		return nil, fmt.Errorf("flow: engine requires a broker")
	}
	budget, err := e.resolveBudget()
	if err != nil {
		return nil, err
	}
	rs := &runState{
		budget:         budget,
		policy:         e.Policy,
		registry:       e.Registry,
		objective:      in.Objective,
		branches:       newBranchLedger(),
		engaged:        map[string]bool{},
		ledgerComplete: true,
	}
	rs.res.RunID = in.RunID
	rs.res.Budget = budget
	rs.res.Policy = e.Policy
	rs.floor = in.Baseline
	if rs.floor.empty() {
		// No caller floor: the configured policy itself becomes the
		// baseline, so a mid-run reassessment can still never relax the
		// startup configuration.
		rs.floor = e.Policy
	}
	rs.res.CompletedChecks = append([]string(nil), in.CompletedChecks...)
	rs.res.Evidence = cloneObservations(in.Evidence)
	rs.res.InapplicableChecks = append([]string(nil), in.InapplicableChecks...)
	rs.inapplicableInit = append([]string(nil), in.InapplicableChecks...)
	rs.produced = nil
	rs.emit(Event{Kind: EventRunStart, Policy: clonePolicy(e.Policy), Budget: &budget})

	stop := func(term Termination, reason string) *runState {
		rs.finish(term, reason)
		return rs
	}
	if err := validatePolicy(e.Policy); err != nil {
		return stop(TermPolicyViolation, err.Error()), nil
	}
	if err := ValidateMonotonicPolicy(rs.floor, e.Policy); err != nil {
		return stop(TermPolicyViolation, err.Error()), nil
	}
	for _, c := range in.Conditions {
		if c == "" {
			rs.limitation(0, "engaged condition id is empty")
			continue
		}
		if _, ok := e.Registry.Condition(c); !ok {
			return stop(TermUnsupported,
				fmt.Sprintf("engaged condition %q names no known condition", c)), nil
		}
		rs.engaged[c] = true
	}
	for _, c := range in.CompletedChecks {
		if c == "" {
			rs.limitation(0, "completed-check entry is empty")
			continue
		}
		if !rs.checkKnown(c) {
			rs.limitation(0, fmt.Sprintf(
				"completed check %q names no registered adapter — it cannot discharge a requirement", c))
			continue
		}
		rs.completedInit = append(rs.completedInit, c)
	}
	rs.updateDischarged()
	for _, o := range in.Evidence {
		if o.Status == "" {
			continue
		}
		switch {
		case !isObservationStatus(o.Status):
			rs.limitation(0, fmt.Sprintf("prior evidence %q carries unknown status %q", o.ID, o.Status))
			rs.ledgerComplete = false
		case o.Status != ObsStatusOK, !o.AuditBound:
			rs.limitation(0, fmt.Sprintf("prior evidence %q is not an audit-bound OK observation — it stays a limitation", o.ID))
			rs.ledgerComplete = false
		case o.Completeness != ObsComplete && o.DischargePath != DischargePositiveAnswer:
			// Prior rows carry no check identity, so their coverage
			// bound stays a recorded limitation, never a ledger
			// defect — the same informational-tool narrowing the
			// produced-observation rule applies.
			rs.limitation(0, fmt.Sprintf("prior evidence %q completeness is %s — it stays a limitation", o.ID, o.Completeness))
		}
	}

	// A policy-required check the registry does not know at all can
	// never be discharged: fail closed rather than spend budget on a
	// run that cannot complete.
	if cr, ok := e.Registry.(CheckRegistry); ok {
		known := map[string]bool{}
		for _, spec := range cr.Checks() {
			known[spec.ID] = true
		}
		for _, req := range e.Policy.RequiredChecks {
			if !known[req] {
				return stop(TermNotDecisionReady,
					fmt.Sprintf("policy-required check %q is not a registered adapter — the requirement can never be discharged", req)), nil
			}
		}
	}
	// A required check that is registered but undispatchable (a
	// lane-carried id) and that no caller-declared completion
	// discharged can never be satisfied in this run. The requirement
	// stays in the recorded policy and the run proceeds — ready claims
	// degrade to NOT_DECISION_READY — but the run start names the
	// unreachable requirement explicitly instead of letting it sit
	// silently among the required ids.
	for _, req := range rs.requiredMissing() {
		if !rs.checkDispatchable(req) {
			rs.limitation(0, fmt.Sprintf(
				"policy-required check %q is registered but not dispatchable and the lane did not discharge it — it cannot be satisfied in this run", req))
		}
	}
	return rs, nil
}

// loop is the react cycle. Every exit path records the termination and
// returns the recorded result — nothing fails silently.
func (e *Engine) loop(ctx context.Context, rs *runState) Result {
	if e.Planner == nil {
		rs.finish(TermPlannerFailure, "no planner is configured for this run")
		return rs.res
	}
	for step := 1; ; step++ {
		rs.step = step
		if err := ctx.Err(); err != nil {
			rs.finish(TermAborted, "run context ended: "+err.Error())
			return rs.res
		}
		if step > rs.budget.MaxSteps {
			rs.finish(TermBudgetExhausted,
				fmt.Sprintf("step budget %d exhausted", rs.budget.MaxSteps))
			return rs.res
		}
		rs.budget.StepsLeft = rs.budget.MaxSteps - step + 1

		// PLAN — two failure classes earn exactly one bounded
		// self-repair turn shared per step:
		//
		//   - a plan answer that failed the closed wire contract
		//     (PlanContractError) is recorded as planner_error; the
		//     verbatim verdict and the rejected answer go back through
		//     PlanInput.RepairError/RepairAnswer;
		//   - a decoded plan the admission gate refuses (registry or
		//     subject-anchor rejection — the planUnsupported verdict)
		//     is recorded as a plan event carrying the rejection on
		//     Error; the recorded reason and the rejected plan
		//     re-encoded go back through the same repair input.
		//
		// The repaired answer (or the second failure, whatever its
		// class) then stands as this step's planner outcome — the
		// repair consumes no step budget. Every other error class is
		// terminal on the first failure — a planner that did not answer
		// at all has nothing to repair from.
		pin := rs.planInput(step)
		plan, perr := e.Planner.Plan(ctx, pin)
		var cerr *PlanContractError
		repaired := false
		if perr != nil && errors.As(perr, &cerr) {
			repaired = true
			rs.emit(Event{Kind: EventPlannerError, Step: step, Error: perr.Error()})
			pin.RepairError = cerr.Error()
			pin.RepairAnswer = cerr.Answer
			plan, perr = e.Planner.Plan(ctx, pin)
		}
		if perr != nil {
			rs.emit(Event{Kind: EventPlannerError, Step: step, Error: perr.Error()})
			rs.finish(TermPlannerFailure, "planner failed: "+perr.Error())
			return rs.res
		}
		if plan.StepID == "" {
			plan.StepID = fmt.Sprintf("step-%d", step)
		}
		verdict, why := validatePlan(e.Registry, &plan, rs.budget.ActionsLeft)
		if verdict == planUnsupported && !repaired {
			// A decoded plan admission refuses is repairable: the
			// planner sees the recorded plan and the verbatim
			// rejection once, at the same step, and may correct the
			// proposal — never re-run it unchanged. The rejected plan
			// stays recorded on the plan event's Error member.
			repaired = true
			rs.emit(Event{Kind: EventPlan, Step: step, StepID: plan.StepID,
				Plan: clonePlan(&plan), Error: why})
			pin.RepairError = why
			pin.RepairAnswer = rejectedPlanAnswer(&plan)
			plan, perr = e.Planner.Plan(ctx, pin)
			if perr != nil {
				rs.emit(Event{Kind: EventPlannerError, Step: step, Error: perr.Error()})
				rs.finish(TermPlannerFailure, "planner failed: "+perr.Error())
				return rs.res
			}
			if plan.StepID == "" {
				plan.StepID = fmt.Sprintf("step-%d", step)
			}
			verdict, why = validatePlan(e.Registry, &plan, rs.budget.ActionsLeft)
		}
		rs.emit(Event{Kind: EventPlan, Step: step, StepID: plan.StepID, Plan: clonePlan(&plan)})
		switch verdict {
		case planMalformed:
			rs.finish(TermPlannerFailure, "planner returned a malformed plan: "+why)
			return rs.res
		case planUnsupported:
			rs.finish(TermUnsupported, "plan rejected: "+why)
			return rs.res
		case planOverBudget:
			rs.finish(TermBudgetExhausted, "plan exceeds the remaining action budget: "+why)
			return rs.res
		}
		for _, c := range plan.ConditionIDs {
			rs.engaged[c] = true
		}

		// ACT + OBSERVE — every action through the broker, every
		// outcome recorded, nothing skipped silently.
		var stepObs []Observation
		for i := range plan.Actions {
			a := plan.Actions[i]
			if err := ctx.Err(); err != nil {
				rs.limitation(step, fmt.Sprintf(
					"action %q skipped: context ended before dispatch: %v", a.ID, err))
				rs.ledgerComplete = false
				continue
			}
			if err := ctx.Err(); err != nil {
				rs.limitation(step, fmt.Sprintf(
					"action %q skipped: context ended before dispatch: %v", a.ID, err))
				rs.ledgerComplete = false
				continue
			}
			rs.budget.ActionsLeft--
			rs.res.Actions = append(rs.res.Actions, *cloneAction(&a))
			evIdx := len(rs.res.Events)
			rs.emit(Event{Kind: EventAction, Step: step, StepID: plan.StepID, Action: cloneAction(&a)})
			obs, berr := e.Broker.Execute(ctx, a)
			if berr != nil {
				rs.res.Events[evIdx].Error = berr.Error()
				obs = synthesizedError(a, berr)
				rs.limitation(step, fmt.Sprintf("action %q produced no observation: %v", a.ID, berr))
			}
			rs.observe(step, &a, &obs)
			stepObs = append(stepObs, *cloneObservation(&obs))
		}
		rs.res.Steps = append(rs.res.Steps, StepRecord{
			Step:         step,
			StepID:       plan.StepID,
			Plan:         *clonePlan(&plan),
			Observations: stepObs,
		})

		// REASSESS — discharge recomputes first so the reassessor sees
		// this step's answered checks in discharged_checks, not one step
		// stale (StepObservations already carries them).
		rs.updateDischarged()
		if e.Reassessor == nil {
			rs.finish(TermReassessorFailure, "no reassessor is configured for this run")
			return rs.res
		}
		re, rerr := e.Reassessor.Reassess(ctx, rs.reassessInput(step, plan, stepObs))
		if rerr != nil {
			rs.emit(Event{Kind: EventReassessErr, Step: step, Error: rerr.Error()})
			rs.finish(TermReassessorFailure, "reassessor failed: "+rerr.Error())
			return rs.res
		}
		rs.emit(Event{Kind: EventReassessment, Step: step, StepID: plan.StepID, Reassessment: cloneReassessment(&re)})
		problems, unsupported := admitReassessment(e.Registry, &re)
		if len(problems) > 0 {
			term := TermReassessorFailure
			if unsupported {
				term = TermUnsupported
			}
			rs.finish(term, formatProblems("reassessment rejected", problems))
			return rs.res
		}
		for _, rev := range re.Revisions {
			rs.branches.apply(rev)
			rs.res.Revisions = append(rs.res.Revisions, rev)
		}
		if re.Policy != nil {
			if err := validatePolicy(*re.Policy); err != nil {
				rs.finish(TermPolicyViolation,
					"reassessment proposed a malformed policy: "+err.Error())
				return rs.res
			}
			if err := ValidateMonotonicPolicy(rs.floor, *re.Policy); err != nil {
				rs.finish(TermPolicyViolation,
					"reassessment proposed a policy relaxation against the baseline: "+err.Error())
				return rs.res
			}
			if err := ValidateMonotonicPolicy(rs.policy, *re.Policy); err != nil {
				rs.finish(TermPolicyViolation,
					"reassessment proposed a relaxation of the running policy: "+err.Error())
				return rs.res
			}
			rs.policy = normalizePolicyAdoption(*re.Policy, rs.budget)
		}
		rs.res.Policy = rs.policy
		rs.updateDischarged()
		if re.Status != ReassessContinue {
			term, reason := deterministicTermination(&re, rs.branches, rs.ledgerComplete, rs.requiredMissing())
			if reason == "" {
				reason = string(term)
			}
			modelReady := re.Status == ReassessReady || re.Status == ReassessBranchesComplete
			modelNonReady := re.Status == ReassessNotDecisionReady || re.Status == ReassessAwaitingEnvironment || re.Status == ReassessTerminalContradiction
			computedReady := term.Ready()
			rs.res.ModelAdvisory = &ModelAdvisory{
				Declaration: re.Status,
				Diverged:    (modelReady && !computedReady) || (modelNonReady && computedReady),
				Detail:      re.Detail,
			}
			rs.finish(term, reason)
			rs.res.RequiredInputs = append([]string(nil), re.RequiredInputs...)
			return rs.res
		}
	}
}

// observe records one produced observation and applies the coverage
// accounting. An OK, audit-bound, digest-pinned observation below
// COMPLETE records its coverage bound as a limitation but marks the
// produced ledger incomplete only when the action served a
// policy-required check — informational checks report PARTIAL by
// contract (module-usage, module-internal-reach, the scan family), so
// degrading on them would punish exploration: the more the planner
// investigates, the less decision-ready the run becomes. A required
// check's undischarged requirement is enforced by missingRequired,
// which names the check; a stamped positive answer (the check's own
// contract for a bounded yes) is never a defect. Genuine record
// defects degrade for every check: non-OK status, unknown status, a
// missing audit binding or a missing digest.
func (rs *runState) observe(step int, a *PlanAction, o *Observation) {
	rs.produced = append(rs.produced, *cloneObservation(o))
	rs.res.Observations = append(rs.res.Observations, *cloneObservation(o))
	rs.emit(Event{Kind: EventObservation, Step: step, Observation: cloneObservation(o)})
	switch {
	case !isObservationStatus(o.Status):
		rs.limitation(step, fmt.Sprintf("observation for action %q carries unknown status %q", o.ActionID, o.Status))
		rs.ledgerComplete = false
	case o.Status != ObsStatusOK:
		reason := o.Scope
		if len(o.Limitations) > 0 {
			reason = o.Limitations[0]
		}
		rs.limitation(step, fmt.Sprintf("observation for action %q returned %s: %s", o.ActionID, o.Status, reason))
		rs.ledgerComplete = false
	case !o.AuditBound:
		rs.limitation(step, fmt.Sprintf("observation for action %q is not bound to a session audit record", o.ActionID))
		rs.ledgerComplete = false
	case o.DataDigest == "":
		rs.limitation(step, fmt.Sprintf("observation for action %q carries no data digest — it cannot be pinned for replay", o.ActionID))
		rs.ledgerComplete = false
	case o.Completeness != ObsComplete && o.DischargePath != DischargePositiveAnswer:
		// The bound is always recorded; the ledger flag marks coverage
		// degraded only when the bounded record answered a check the
		// policy requires.
		rs.limitation(step, fmt.Sprintf("observation for action %q completeness is %s: coverage is not closed", o.ActionID, o.Completeness))
		if rs.requiredCheck(a.AdapterID) {
			rs.ledgerComplete = false
		}
	}
}

// requiredCheck reports whether adapter is one of the running policy's
// required check ids — the only tools whose partial coverage may mark
// the observation ledger degraded.
func (rs *runState) requiredCheck(adapter string) bool {
	for _, req := range rs.policy.RequiredChecks {
		if req == adapter {
			return true
		}
	}
	return false
}

// updateDischarged recomputes which policy-required check ids are
// discharged: every produced observation that answers its check's
// question — OK, audit-bound, digest-pinned and either COMPLETE
// (closed negative) or a stamped positive answer — counts for its
// action's adapter, plus caller-declared completions.
func (rs *runState) updateDischarged() {
	rs.discharged = dischargedChecks(rs.res.Actions, rs.produced, rs.completedInit)
	rs.res.Complete = rs.ledgerComplete && len(rs.requiredMissing()) == 0
}

// requiredMissing lists policy-required check ids with no discharged
// observation and no explicit inapplicability record.
func (rs *runState) requiredMissing() []string {
	return requiredCoverageWithInapplicable(rs.policy.RequiredChecks, rs.discharged, rs.inapplicableInit)
}

// requiredCovered reports whether every policy-required check is
// discharged; the missing set is recorded at run start by the open
// gate and refreshed by updateDischarged.
func (rs *runState) requiredCovered() bool {
	return len(rs.requiredMissing()) == 0
}

// checkDispatchable reports whether a check id can actually be
// dispatched in this run. A registry without the optional
// dispatchability surface answers yes for every id it advertises — a
// registered-but-undispatchable (lane-carried) check then still
// advertises dispatchable, which the catalog itself rejects at
// admission; the fail-closed path is unaffected either way.
func (rs *runState) checkDispatchable(id string) bool {
	if dr, ok := rs.registry.(DispatchableRegistry); ok {
		return dr.Dispatchable(id)
	}
	return true
}

// checkKnown reports whether a check id resolves to a registered
// adapter; when the registry does not expose a listing, declared
// completions are conservatively inadmissible.
func (rs *runState) checkKnown(id string) bool {
	if cr, ok := rs.registry.(CheckRegistry); ok {
		for _, spec := range cr.Checks() {
			if spec.ID == id {
				return true
			}
		}
	}
	return false
}

// emit appends one event to the stream, assigning the sequence number.
func (rs *runState) emit(ev Event) {
	ev.Seq = len(rs.res.Events) + 1
	rs.res.Events = append(rs.res.Events, ev)
}

// limitation records one run limitation both in the result list and as
// an event, so the stream carries every degradation in order.
func (rs *runState) limitation(step int, msg string) {
	rs.res.Limitations = append(rs.res.Limitations, msg)
	rs.emit(Event{Kind: EventLimitation, Step: step, Detail: msg})
}

// finish seals the result with an explicit termination.
func (rs *runState) finish(term Termination, reason string) {
	rs.updateDischarged()
	if len(rs.inapplicableInit) > 0 {
		msg := fmt.Sprintf("required checks inapplicable by advisory granularity: %s", strings.Join(rs.inapplicableInit, ", "))
		rs.limitation(rs.step, msg)
		if reason == "" {
			reason = msg
		} else if !strings.Contains(reason, msg) {
			reason += "; " + msg
		}
	}
	rs.res.Termination = term
	rs.res.Reason = reason
	rs.res.Ready = term.Ready()
	rs.res.Branches = rs.branches.states()
	rs.res.Conditions = rs.engagedList()
	rs.res.Budget.StepsLeft = rs.budget.StepsLeft
	rs.res.Budget.ActionsLeft = rs.budget.ActionsLeft
	rs.emit(Event{Kind: EventTerminated, Step: rs.step, Termination: term, Detail: reason})
}

// planInput builds the planner's view for the next step.
func (rs *runState) planInput(step int) PlanInput {
	return PlanInput{
		RunID:               rs.res.RunID,
		Objective:           rs.objective,
		Step:                step,
		Conditions:          rs.engagedList(),
		AvailableChecks:     rs.availableChecks(),
		AvailableCheckSpecs: rs.availableCheckSpecs(),
		AvailableConditions: rs.availableConditions(),
		RequiredChecks:      append([]string(nil), rs.policy.RequiredChecks...),
		DischargedChecks:    rs.dischargedList(),
		InapplicableChecks:  append([]string(nil), rs.inapplicableInit...),
		Observations:        rs.ledgerView(),
		Branches:            rs.branches.states(),
		Budget:              rs.budget,
	}
}

// reassessInput builds the reassessor's view after one step.
func (rs *runState) reassessInput(step int, plan Plan, stepObs []Observation) ReassessInput {
	return ReassessInput{
		RunID:              rs.res.RunID,
		Objective:          rs.objective,
		Step:               step,
		StepID:             plan.StepID,
		Plan:               *clonePlan(&plan),
		StepObservations:   stepObs,
		Observations:       rs.ledgerView(),
		Branches:           rs.branches.states(),
		Conditions:         rs.engagedList(),
		RequiredChecks:     append([]string(nil), rs.policy.RequiredChecks...),
		DischargedChecks:   rs.dischargedList(),
		InapplicableChecks: append([]string(nil), rs.inapplicableInit...),
		Policy:             rs.policy,
		Budget:             rs.budget,
	}
}

// ledgerView returns prior evidence followed by produced observations.
func (rs *runState) ledgerView() []Observation {
	out := append([]Observation(nil), rs.res.Evidence...)
	return append(out, rs.produced...)
}

func (rs *runState) engagedList() []string {
	var out []string
	for c := range rs.engaged {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

func (rs *runState) dischargedList() []string {
	var out []string
	for c := range rs.discharged {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// availableChecks advertises only the checks the broker can actually
// dispatch: registered ids the registry also reports dispatchable. A
// registered-but-undispatchable (lane-carried) id never enters the
// planner surface — it discharges through CompletedChecks or stays an
// undischarged requirement, visible in required_checks/
// discharged_checks instead of masquerading as an admissible adapter.
func (rs *runState) availableChecks() []string {
	if cr, ok := rs.registry.(CheckRegistry); ok {
		var out []string
		for _, spec := range cr.Checks() {
			if !rs.checkDispatchable(spec.ID) {
				continue
			}
			out = append(out, spec.ID)
		}
		return out
	}
	return nil
}

func (rs *runState) availableCheckSpecs() []evidencetools.CheckSpec {
	if cr, ok := rs.registry.(CheckRegistry); ok {
		var out []evidencetools.CheckSpec
		for _, spec := range cr.Checks() {
			if rs.checkDispatchable(spec.ID) {
				out = append(out, spec)
			}
		}
		return out
	}
	return nil
}

func (rs *runState) availableConditions() []Condition {
	if cr, ok := rs.registry.(ConditionRegistry); ok {
		return cr.Conditions()
	}
	return nil
}

// rejectedPlanAnswer re-encodes a decoded plan the admission gate
// refused for the repair turn's RepairAnswer — the planner sees the
// plan it proposed in its own wire shape. The marshaling is total for
// this type; an unreachable failure is reported as the payload itself
// rather than dropped.
func rejectedPlanAnswer(p *Plan) string {
	b, err := json.Marshal(p)
	if err != nil {
		return fmt.Sprintf("<plan re-encode failed: %v>", err)
	}
	return string(b)
}

// synthesizedError builds the ERROR observation for an action whose
// broker call produced none — the missing-observation record, never a
// silent skip.
func synthesizedError(a PlanAction, err error) Observation {
	return Observation{
		ActionID:     a.ID,
		Status:       ObsStatusError,
		Completeness: ObsUnknown,
		Scope:        "check not performed",
		Limitations:  []string{"broker returned no observation: " + err.Error()},
	}
}

// Package flow implements the generic Amendment R6 react loop:
// PLAN → validate → ACT → OBSERVE → REASSESS, repeated until a
// documented stop condition. The package knows only the interfaces in
// this file — no CVE-specific branches, no tool semantics, no prompt
// wording and no deployment vocabulary live here; the loop controls
// research sequencing, never truth. Facts, branches and proposed
// dispositions are derived elsewhere (the decision-artifact builder);
// the flow result records exactly what was requested, observed and
// assessed so the run is auditable and replayable without a model.
//
// Fail-closed contract: unregistered or malformed actions and
// conditions, unavailable planners/reassessors, broker failures,
// degraded or missing observations, unsupported terminal claims and
// any relaxation of the safety policy all end the run in an explicit
// non-ready termination — never in a silent success.
package flow

import (
	"context"
	"encoding/json"

	"github.com/davniy/izyan/internal/evidencetools"
)

// PlanAction is one typed, bounded action the planner proposes. The
// registry admits it by AdapterID and arguments before the broker may
// execute it; ConditionID names the catalog condition the action
// serves, when any. Anchor is the optional verbatim advisory-text
// citation the planner must supply when a proposed subject is not part
// of the advisory's structured declaration — the lane's subject gate
// verifies it against the recorded advisory before admission, and the
// field rides the recorded run so the citation survives into the audit
// trail. It is omitted on every earlier prompt revision's wire shape.
type PlanAction struct {
	ID          string          `json:"id"`
	AdapterID   string          `json:"adapter_id"`
	Arguments   json.RawMessage `json:"arguments"`
	Purpose     string          `json:"purpose"`
	ConditionID string          `json:"condition_id"`
	Anchor      string          `json:"anchor,omitempty"`
}

// Plan is one planner step: the actions to execute plus the catalog
// condition ids the planner is engaging.
type Plan struct {
	StepID       string       `json:"step_id"`
	Actions      []PlanAction `json:"actions"`
	ConditionIDs []string     `json:"condition_ids"`
}

// PlanContractError is the planner-side failure class the engine
// repairs once: a plan answer that the closed wire contract rejected
// (decode or member-level contract failure), carrying the rejected
// answer and the verbatim contract verdict. The engine grants exactly
// one bounded self-repair turn per planner invocation — it feeds Err
// and Answer back through PlanInput.RepairError/RepairAnswer — and a
// second failure of any kind terminates PLANNER_FAILURE with the
// ordinary planner-error record. The same single turn is shared with
// the admission-rejection repair (a decoded plan the registry
// refuses): both classes consume it, so a step never repairs twice.
// Every other error class is terminal on the first failure: a
// transport, gate or malformed-plan error earns no repair because it
// is not a shape slip the planner can correct from the verdict alone.
type PlanContractError struct {
	// Answer is the rejected answer verbatim — the planner sees
	// exactly what the contract refused.
	Answer string
	// Err is the contract/decode verdict the planner is fed back.
	Err error
}

func (e *PlanContractError) Error() string { return e.Err.Error() }
func (e *PlanContractError) Unwrap() error { return e.Err }

// Observation is the recorded outcome of one executed action — an
// observation of a bounded query, never a fact and never an absence
// proof. Status/Completeness mirror the evidence-session vocabulary
// (OK/ERROR/TIMEOUT/UNSUPPORTED and COMPLETE/PARTIAL/UNKNOWN); anything
// below a complete, audit-bound OK remains a limitation, and DataDigest
// pins the recorded payload so the stream stays replayable.
type Observation struct {
	ID           string   `json:"id"`
	ActionID     string   `json:"action_id"`
	Status       string   `json:"status"`
	Completeness string   `json:"completeness"`
	Scope        string   `json:"scope"`
	DataDigest   string   `json:"data_digest"`
	EvidenceRefs []string `json:"evidence_refs,omitempty"`
	Limitations  []string `json:"limitations,omitempty"`
	// AuditBound records whether the session audit ledger bound this
	// observation to the executed request. Only audit-bound OK
	// observations whose payload answers the check's question —
	// recorded on DischargePath — discharge a required check.
	AuditBound bool `json:"audit_bound"`
	// DischargePath names which answer path the recorded payload
	// carries — DischargeClosedNegative for a complete closed-scope
	// observation, DischargePositiveAnswer for a positive verdict the
	// check's contract binds below COMPLETE. The producer (the broker's
	// audit binding, or the lane-discharge gate for prior evidence)
	// stamps it; the planner can never write it. An empty value means
	// the payload answers nothing and never discharges; a non-empty
	// value asserts only that an answer exists — the discharge gate
	// still enforces the OK/audit-bound/digest requirements.
	DischargePath string `json:"discharge_path,omitempty"`
}

// Observation DischargePath values. The closed-negative path is the
// ordinary COMPLETE discharge: the check ran a closed scope to a
// negative. The positive-answer path covers checks whose contract
// deliberately binds a positive answer below COMPLETE — package-usage
// reports USED at PARTIAL because positive static usage never claims
// runtime execution or attacker reachability; a required check answered
// positively must still discharge, with the interpretation bound
// recorded in the observation's limitations.
const (
	DischargeClosedNegative = "closed_negative"
	DischargePositiveAnswer = "positive_answer"
)

// Observation Status values.
const (
	ObsStatusOK          = "OK"
	ObsStatusError       = "ERROR"
	ObsStatusTimeout     = "TIMEOUT"
	ObsStatusUnsupported = "UNSUPPORTED"
)

// Observation Completeness values.
const (
	ObsComplete = "COMPLETE"
	ObsPartial  = "PARTIAL"
	ObsUnknown  = "UNKNOWN"
)

func isObservationStatus(s string) bool {
	switch s {
	case ObsStatusOK, ObsStatusError, ObsStatusTimeout, ObsStatusUnsupported:
		return true
	}
	return false
}

// Condition is one registry-known condition entry: the planner and
// reassessor may reference conditions by ID only — they can never
// invent one.
type Condition struct {
	ID          string   `json:"id"`
	Statement   string   `json:"statement"`
	Role        string   `json:"role"`
	SubjectRefs []string `json:"subject_refs,omitempty"`
	Required    bool     `json:"required"`
	Polarity    string   `json:"polarity"`
}

// Branch status values. They mirror the decision-artifact vocabulary
// so reassessor claims land in the same closed enum the artifact
// validator enforces; the loop itself never decides which branch a
// fact supports — it records the reassessor's claimed revisions and
// the artifact builder re-derives truth deterministically.
const (
	BranchStatusComplete         = "COMPLETE"
	BranchStatusAwaitingInput    = "AWAITING_INPUT"
	BranchStatusContradicted     = "CONTRADICTED"
	BranchStatusNotDecisionReady = "NOT_DECISION_READY"
)

func isBranchStatus(s string) bool {
	switch s {
	case BranchStatusComplete, BranchStatusAwaitingInput,
		BranchStatusContradicted, BranchStatusNotDecisionReady:
		return true
	}
	return false
}

// BranchRevision is one append-only reassessor update to a branch's
// claimed status. A revision carries no disposition, no fact and no
// environment value — the agent tracks sequencing state only and can
// never write a proposed disposition through it.
type BranchRevision struct {
	BranchID string `json:"branch_id"`
	Status   string `json:"status"`
	Detail   string `json:"detail,omitempty"`
}

// BranchState is the current claim for one branch plus its full
// revision history; revisions are append-only so earlier claims are
// never rewritten.
type BranchState struct {
	ID        string           `json:"id"`
	Status    string           `json:"status"`
	Revisions []BranchRevision `json:"revisions"`
}

// ReassessStatus is the closed enum of reassessor outcomes.
type ReassessStatus string

const (
	// ReassessContinue asks for another PLAN step.
	ReassessContinue ReassessStatus = "CONTINUE"
	// ReassessReady claims the evidence is decision-ready. The engine
	// admits the claim only when the recorded ledger is clean and every
	// policy-required check is discharged.
	ReassessReady ReassessStatus = "DECISION_READY"
	// ReassessBranchesComplete claims every recorded branch is
	// complete; admitted only when the branch ledger actually is.
	ReassessBranchesComplete ReassessStatus = "BRANCHES_COMPLETE"
	// ReassessAwaitingEnvironment stops the run on declared required
	// environment inputs — an explicit state, never a silent success.
	ReassessAwaitingEnvironment ReassessStatus = "AWAITING_ENVIRONMENT"
	// ReassessTerminalContradiction stops the run on a recorded
	// contradiction the reassessor cannot resolve.
	ReassessTerminalContradiction ReassessStatus = "TERMINAL_CONTRADICTION"
	// ReassessNotDecisionReady stops the run as not decision-ready.
	ReassessNotDecisionReady ReassessStatus = "NOT_DECISION_READY"
)

func isReassessStatus(s ReassessStatus) bool {
	switch s {
	case ReassessContinue, ReassessReady, ReassessBranchesComplete,
		ReassessAwaitingEnvironment, ReassessTerminalContradiction,
		ReassessNotDecisionReady:
		return true
	}
	return false
}

// Reassessment is the reassessor's reply to one OBSERVE step. It may
// carry branch revisions (append-only claims), declared required
// environment inputs, a candidate policy tightening, and a free-form
// detail. It may never carry a proposed disposition — there is no
// field for one.
type Reassessment struct {
	Status         ReassessStatus   `json:"status"`
	RequiredInputs []string         `json:"required_inputs,omitempty"`
	Revisions      []BranchRevision `json:"revisions,omitempty"`
	// Policy is an optional candidate tightening; it is adopted only
	// when it is monotonic over both the run's baseline floor and the
	// current effective policy. A relaxation ends the run in
	// POLICY_VIOLATION.
	Policy *Policy `json:"policy,omitempty"`
	Detail string  `json:"detail,omitempty"`
}

// Policy is the flow-level safety policy: the rules, required checks
// and forbidden promotions a run must preserve, plus the deterministic
// step/action budgets. Configuration may only ever tighten it. The
// type is named Policy (not SafetyPolicy) because it is the runtime
// surface; SafetyPolicy remains an alias matching the Engine contract.
type Policy struct {
	RequiredRules       []string `json:"required_rules"`
	RequiredChecks      []string `json:"required_checks"`
	ForbiddenPromotions []string `json:"forbidden_promotions"`
	// MaxSteps and MaxActions bound the loop deterministically; zero
	// falls back to the engine/default budgets.
	MaxSteps   int `json:"max_steps,omitempty"`
	MaxActions int `json:"max_actions,omitempty"`
}

// SafetyPolicy is the brief's name for the engine's policy field type;
// it is the same type as Policy.
type SafetyPolicy = Policy

// empty reports whether the policy carries no members at all.
func (p Policy) empty() bool {
	return len(p.RequiredRules) == 0 && len(p.RequiredChecks) == 0 &&
		len(p.ForbiddenPromotions) == 0
}

// Budget is the resolved step/action bound pair plus the remaining
// counts exposed to the planner and reassessor each turn.
type Budget struct {
	MaxSteps    int `json:"max_steps"`
	MaxActions  int `json:"max_actions"`
	StepsLeft   int `json:"steps_left"`
	ActionsLeft int `json:"actions_left"`
}

// Default deterministic budgets, applied when neither the engine nor
// the policy declares a bound.
const (
	DefaultMaxSteps   = 8
	DefaultMaxActions = 16
)

// Input is everything a run starts with. Evidence and CompletedChecks
// carry what earlier phases already recorded (they are context, never
// re-executed); InapplicableChecks records required checks that cannot
// apply at the advisory's declared granularity. Baseline is the caller-
// supplied monotonic floor the configured policy must preserve.
type Input struct {
	RunID              string        `json:"run_id"`
	Objective          string        `json:"objective"`
	Conditions         []string      `json:"conditions,omitempty"`
	Evidence           []Observation `json:"evidence,omitempty"`
	CompletedChecks    []string      `json:"completed_checks,omitempty"`
	InapplicableChecks []string      `json:"inapplicable_checks,omitempty"`
	Baseline           Policy        `json:"baseline,omitempty"`
}

// PlanInput is the planner's view of the run at one step: scope,
// engaged conditions, the registry's admissible surface, the exact
// argument schemas for those checks, the recorded ledger, branch claims,
// the remaining budget, and — only on the single bounded self-repair
// turn a repairable plan failure earns — the repair feedback.
type PlanInput struct {
	RunID               string                    `json:"run_id"`
	Objective           string                    `json:"objective"`
	Step                int                       `json:"step"`
	Conditions          []string                  `json:"conditions"`
	AvailableChecks     []string                  `json:"available_checks"`
	AvailableCheckSpecs []evidencetools.CheckSpec `json:"available_check_specs"`
	AvailableConditions []Condition               `json:"available_conditions"`
	RequiredChecks      []string                  `json:"required_checks"`
	DischargedChecks    []string                  `json:"discharged_checks"`
	InapplicableChecks  []string                  `json:"inapplicable_checks,omitempty"`
	Observations        []Observation             `json:"observations"`
	Branches            []BranchState             `json:"branches"`
	Budget              Budget                    `json:"budget"`
	// RepairError/RepairAnswer are populated exactly once per planner
	// invocation — when the first attempt failed a repairable contract:
	// the closed wire decode (PlanContractError) or the plan admission
	// gate (a decoded plan the registry refuses — rejected arguments,
	// a subject-gate failure, an unknown check or condition). They
	// carry the verbatim failure and the rejected payload — the answer
	// text for a contract failure, the re-encoded plan for an
	// admission rejection — so the planner can correct it; both stay
	// empty on every first attempt and on every non-repair turn, and
	// any error on the repair answer is terminal.
	RepairError  string `json:"repair_error,omitempty"`
	RepairAnswer string `json:"repair_answer,omitempty"`
}

// ReassessInput is the reassessor's view after one OBSERVE step. It
// carries the same explicit inapplicability record as the planner view.
type ReassessInput struct {
	RunID              string        `json:"run_id"`
	Objective          string        `json:"objective"`
	Step               int           `json:"step"`
	StepID             string        `json:"step_id"`
	Plan               Plan          `json:"plan"`
	StepObservations   []Observation `json:"step_observations"`
	Observations       []Observation `json:"observations"`
	Branches           []BranchState `json:"branches"`
	Conditions         []string      `json:"conditions"`
	RequiredChecks     []string      `json:"required_checks"`
	DischargedChecks   []string      `json:"discharged_checks"`
	InapplicableChecks []string      `json:"inapplicable_checks,omitempty"`
	Policy             Policy        `json:"policy"`
	Budget             Budget        `json:"budget"`
}

// Planner proposes the next step. An unavailable or erroring planner
// is an unknown outcome, never a complete disposition.
type Planner interface {
	Plan(context.Context, PlanInput) (Plan, error)
}

// Reassessor evaluates the ledger after each step. It may claim
// readiness, continue, stop on environment input, contradiction or
// NOT_DECISION_READY — every claim is gated by the engine against the
// recorded state before it becomes the termination.
type Reassessor interface {
	Reassess(context.Context, ReassessInput) (Reassessment, error)
}

// Broker executes one admitted action inside the confined evidence
// surface. The broker is the only execution path — the engine contains
// no shell or arbitrary process path.
type Broker interface {
	Execute(context.Context, PlanAction) (Observation, error)
}

// Registry is the admission surface: it decides which actions are
// typed, registered and in scope, and which conditions exist.
type Registry interface {
	Check(action PlanAction) error
	Condition(id string) (Condition, bool)
}

// Termination is the explicit stop reason of a run. Every path out of
// the loop produces one; degrading conditions land in an explicit
// non-ready state, never a silent success.
type Termination string

const (
	// TermDecisionReady — the reassessor's ready claim held against a
	// clean ledger with every required check discharged.
	TermDecisionReady Termination = "DECISION_READY"
	// TermBranchesComplete — every recorded branch claimed complete,
	// admitted only when the branch ledger agrees.
	TermBranchesComplete Termination = "BRANCHES_COMPLETE"
	// TermAwaitingEnvironment — the run needs declared environment
	// inputs before it can proceed.
	TermAwaitingEnvironment Termination = "AWAITING_ENVIRONMENT"
	// TermTerminalContradiction — a recorded contradiction the
	// reassessor could not resolve.
	TermTerminalContradiction Termination = "TERMINAL_CONTRADICTION"
	// TermBudgetExhausted — the step or action budget ran out, or a
	// plan exceeded what the remaining budget admits.
	TermBudgetExhausted Termination = "BUDGET_EXHAUSTED"
	// TermPlannerFailure — the planner errored, is unavailable, or
	// returned a malformed plan.
	TermPlannerFailure Termination = "PLANNER_FAILURE"
	// TermReassessorFailure — the reassessor errored, is unavailable,
	// or returned a malformed reassessment.
	TermReassessorFailure Termination = "REASSESSOR_FAILURE"
	// TermUnsupported — a plan or reassessment referenced an
	// unregistered check or condition.
	TermUnsupported Termination = "UNSUPPORTED_CHECK_OR_CONDITION"
	// TermPolicyViolation — a configured or proposed policy would
	// relax the baseline floor or the running policy.
	TermPolicyViolation Termination = "POLICY_VIOLATION"
	// TermNotDecisionReady — explicit non-ready stop: unverifiable
	// claim, degraded coverage, or the reassessor's own verdict.
	TermNotDecisionReady Termination = "NOT_DECISION_READY"
	// TermAborted — the caller's context ended mid-run.
	TermAborted Termination = "ABORTED"
)

// Ready reports whether the termination admits a decision-ready
// outcome claim downstream.
func (t Termination) Ready() bool {
	return t == TermDecisionReady || t == TermBranchesComplete
}

// StepRecord is one admitted step: the plan plus the observations it
// produced, in dispatch order.
type StepRecord struct {
	Step         int           `json:"step"`
	StepID       string        `json:"step_id"`
	Plan         Plan          `json:"plan"`
	Observations []Observation `json:"observations"`
}

// Event kinds recorded in the flow event stream. The stream is the
// replayable record of the run: every request, observation, status,
// digest, limitation, reassessment and termination lands here exactly
// once, in order.
const (
	EventRunStart     = "run_start"
	EventPlan         = "plan"
	EventPlannerError = "planner_error"
	EventAction       = "action"
	EventObservation  = "observation"
	EventLimitation   = "limitation"
	EventReassessment = "reassessment"
	EventReassessErr  = "reassessor_error"
	EventTerminated   = "terminated"
)

// Event is one entry in the flow event stream. Payload fields are
// populated by kind: run_start carries Policy and Budget; plan carries
// Plan — with Error set when admission rejected that plan and the
// single repair turn it earned follows; action carries Action (plus
// Error when the broker failed); observation carries Observation;
// reassessment carries Reassessment; planner_error/reassessor_error
// carry Error; limitation carries Detail; terminated carries
// Termination and Detail.
type Event struct {
	Seq          int           `json:"seq"`
	Step         int           `json:"step"`
	Kind         string        `json:"kind"`
	StepID       string        `json:"step_id,omitempty"`
	Plan         *Plan         `json:"plan,omitempty"`
	Action       *PlanAction   `json:"action,omitempty"`
	Observation  *Observation  `json:"observation,omitempty"`
	Reassessment *Reassessment `json:"reassessment,omitempty"`
	Policy       *Policy       `json:"policy,omitempty"`
	Budget       *Budget       `json:"budget,omitempty"`
	Termination  Termination   `json:"termination,omitempty"`
	Error        string        `json:"error,omitempty"`
	Detail       string        `json:"detail,omitempty"`
}

// Result is the complete recorded outcome of a run: the explicit
// termination, the admitted steps, the dispatched actions and their
// observations (one-to-one, dispatch order), the prior evidence the
// caller supplied, the branch ledger with append-only revisions, the
// final effective policy, every limitation, and the full event stream.
// ModelDeclaration records the latest model view of terminal readiness. It
// is advisory only; Ready and Termination are computed from the recorded
// evidence ledger and branch/condition state.
type ModelAdvisory struct {
	Declaration ReassessStatus `json:"declaration"`
	Diverged    bool           `json:"diverged"`
	Detail      string         `json:"detail,omitempty"`
}

// Result is the complete recorded outcome of a run: the explicit
// termination, the admitted steps, the dispatched actions and their
// observations (one-to-one, dispatch order), the prior evidence the
// caller supplied, the branch ledger with append-only revisions, the final
// effective policy, every limitation, and the full event stream.
type Result struct {
	RunID              string           `json:"run_id"`
	Termination        Termination      `json:"termination"`
	Reason             string           `json:"reason"`
	Ready              bool             `json:"ready"`
	Complete           bool             `json:"complete"`
	ModelAdvisory      *ModelAdvisory   `json:"model_advisory,omitempty"`
	Steps              []StepRecord     `json:"steps"`
	Actions            []PlanAction     `json:"actions"`
	Observations       []Observation    `json:"observations"`
	Evidence           []Observation    `json:"evidence,omitempty"`
	Conditions         []string         `json:"conditions,omitempty"`
	Branches           []BranchState    `json:"branches,omitempty"`
	Revisions          []BranchRevision `json:"revisions,omitempty"`
	RequiredInputs     []string         `json:"required_inputs,omitempty"`
	Policy             Policy           `json:"policy"`
	CompletedChecks    []string         `json:"completed_checks,omitempty"`
	InapplicableChecks []string         `json:"inapplicable_checks,omitempty"`
	Budget             Budget           `json:"budget"`
	Limitations        []string         `json:"limitations,omitempty"`
	Events             []Event          `json:"events"`
}

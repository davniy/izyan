**Status: PROPOSED — not implemented. Plan for review; authorizes no code change by itself.**

Date: 2026-10-15. Doctrine: **Amendment R6** in
`docs/dev/plans/2026-10-15-01-c02-closure-capability-plan.md` (unit-of-output
change: one complete decision or a finite set of complete conditional
branches; human only answers ≤2 environment questions and accepts/rejects).
Producer: OMP `architect` subagent (read-only), session
`HumanMinimalDecisionModel` follow-up, method `skill://writing-plans`.

Reproduced verbatim from the architect's artifact. Baseline it builds on (all
uncommitted in the working tree, all controller-verified): `r0-v4` mandatory
plan prompt, `VerifyDecision` with applicability-first ordering and
advisory-scoped contradictions, the offline `vendorclosure` deriver, the
audited bounded verification runner, `research-report/2`.

Regression guard for the whole plan: the measured **7/18 corporate
`NOT_AFFECTED`** census and the **C09 replay path** must stay green; R6 is
opt-in behind `izyan research --decision-ready` and the legacy route stays
available.

# Decision-Ready Triage Implementation Plan

**Preferred path:** `docs/dev/plans/2026-10-15-02-decision-ready-triage-plan.md`

**Goal:** Implement Amendment R6 as an opt-in decision-ready research lane that produces one complete proposed disposition, or a finite set of complete conditional branches, so a human only answers at most two declared environment questions and selects `Accept` or `Reject`.

**Architecture:** Keep `internal/research` separate from the legacy `analyze` pipeline. Reuse the existing deterministic lane, evidence session, `VerifyDecision`, persisted observation ledger, and replay mechanism. Add a generic `internal/flow` control loop for `PLAN → ACT → OBSERVE → REASSESS`; keep facts, rule evaluation, branch construction, and proposed dispositions deterministic. The agent may propose checks and conditions but cannot create verified facts, branches, environment values, or final dispositions.

**Tech stack:** Go, existing `internal/evidencetools` MCP/session APIs, existing `internal/research` report/replay code, YAML configuration, Python evaluation harness under `eval/decision_ready`.

**Spec:** Amendment R6 in `docs/dev/plans/2026-10-15-01-c02-closure-capability-plan.md`, with supporting contracts in `docs/dev/specs/2026-10-14-Izyan-Autonomous-Evid.md` and `docs/dev/specs/2026-10-10-01-agent-driven-evidence-assessment-design-v2.md`.

## Global Constraints

1. Preserve every `AGENTS.md` invariant:
   - absence of a found path is not proof of absence;
   - `FALSE` requires a typed falsifier and successful negative verification;
   - `NOT_AFFECTED` remains available only from the deterministic applicability chain;
   - deterministic evidence remains authoritative over agent output;
   - incomplete, unsupported, errored, or partial checks fail closed.
2. Do not modify or weaken the existing `VerifyDecision` gates:
   - advisory-wide subject coverage;
   - exact subject identity and granularity;
   - request↔audit argument binding;
   - matching snapshot/build context;
   - digest-resolved evidence references;
   - complete observation coverage;
   - positive-contradiction checks;
   - empty operational limitations for terminal negatives.
3. A user/environment response is always an `EnvironmentAssertion`. It MUST NOT be converted into `domain.Claim{Result: FALSE}` or used as a code-level falsifier.
4. `FalsifierTrustedInfrastructure` may produce only a contextual mitigation branch with `ACCEPT_ENVIRONMENTAL_MITIGATION`; it may never produce `CLOSE_NO_EXPLOIT_PATH`.
5. `BasisConfigOrigin` remains a code-provenance rule and is accepted only when all relevant sink inputs are covered by a complete deterministic provenance result.
6. No CVE-specific branches, IDs, package paths, or private ticket identifiers may be added. New behavior must use generic tool adapters, condition/rule catalog entries, prompts, rubrics, or verification rules.
7. The decision-ready artifact MUST enforce:
   - at most two environment questions;
   - at most seven mandatory first-screen facts;
   - an explicit `unknown` branch;
   - no human-required repository opening, tool rerun, falsifier construction, or free-form environment interpretation.
8. The legacy `izyan research` route remains compatible:
   - `research-report/1` and `research-report/2` remain readable and valid;
   - historical runs remain replayable;
   - the current `7/18` deterministic result and the C09 replay path remain regression guards.
9. The R6 route is opt-in through `izyan research --decision-ready`. The existing one-turn route remains available while R6 validation is completed.
10. Intermediate tasks use only focused tests with `-count=1`. The full repository test and corpus commands run once, during final validation.
11. Live model calls are permitted only in the validation phase. Each live case is bounded by the configured call budget and timeout. If the harness or model is unavailable, the result is `HOLD_UNKNOWN`/`NOT_DECISION_READY`; it MUST NOT be counted as decision-ready.
12. Functional behavior changes require updates to `docs/dev/gap-analysis.md` and `eval/README.md`. No private paths, private IDs, raw corporate findings, or temporary artifacts may be committed.

## Schema and Compatibility Decision

Use two explicit schema levels:

- Existing report schemas remain:
  - `research-report/1`: historical legacy reports;
  - `research-report/2`: current autonomous research reports.
- Add:
  - `research-report/3`: newly emitted decision-ready reports;
  - `decision-artifact/1`: the embedded and sidecar `DecisionArtifact` contract.

A `/3` report contains:

```go
DecisionArtifact *DecisionArtifact `json:"decision_artifact"`
Decision          *EvidenceDecision `json:"decision,omitempty"`
```

`DecisionArtifact` is authoritative for the R6 human-facing contract. `Decision` remains as a compatibility projection for existing `/2` consumers and is derived from the artifact; it is not a second decision writer.

`Report.Disposition` remains:

```json
{
  "class": "REVIEW_REQUIRED",
  "auto_close": false
}
```

even when `DecisionArtifact.ProposedDisposition` is a close or mitigation proposal. R6 prepares a decision for human acceptance; it does not enable tracker updates or automatic close.

`Validate` accepts `/1`, `/2`, and `/3`. A `/3` report requires a valid `decision_artifact` with schema `decision-artifact/1`; `/1` and `/2` do not. Legacy reports render using their existing layout and do not acquire R6 sections during parse/render round trips.

## Entry Gates

Before implementation begins:

- the current uncommitted predecessor work is present;
- B49 `r0-v4` remains byte-stable and pinned;
- the vendor-inventory marker, C09 replay, `ProductSnapshot.VendorMode`, decision-ordering fix, and observation-ledger hardening are present;
- the measured baseline is recorded externally:
  - current corporate subset: `7/18` deterministic `NOT_AFFECTED`;
  - false-safe count: `0`;
  - C09 replay: stable `NOT_AFFECTED`, `COMPLETE`, `AutoClose=false`;
- private baseline inputs are available outside the repository;
- if any predecessor behavior is absent, stop at the affected task and record the blocker rather than weakening R6 gates.

## Non-Goals and Explicitly Out of Scope

- Changing the legacy `analyze` state machine.
- Integrating decision-ready output into tracker close, VEX publication, or automatic remediation.
- Building a universal proof engine, universal condition solver, event store, taint engine, runtime instrumenter, or reflection-complete analyzer.
- Reopening B48 guard/bound capability as part of R6.
- Treating agent prose, confidence, category, or agreement with historical labels as verified facts.
- Supporting arbitrary user-created environment variables or arbitrary branch expressions.
- Supporting more than two environment questions in this change.
- Treating environmental trust as a code-grounded negative.
- Claiming the `[INFERENCE]` human-time targets until the blinded acceptance study measures them.

## Review Focus

| Risk | Owning task/test |
|---|---|
| `/1` and `/2` historical reports stop parsing | Task 1 `TestLegacyReportCompatibility` |
| `/3` artifact is missing or malformed | Task 1 `TestDecisionArtifactSchemaV1` |
| Environment answers become code-level `FALSE` claims | Task 3 `TestEnvironmentAssertionNeverCreatesClaim` |
| A trusted-perimeter branch becomes `NO_EXPLOIT_PATH_FOUND` | Task 3 `TestTrustedInfrastructureOnlyMitigation` |
| A package fact satisfies a module-only advisory subject | Task 2 `TestFactSubjectGranularity` |
| Configuration removes an existing safety gate | Task 1 and Task 4 monotonic-policy tests |
| Agent invents a variable, value, branch, or rule | Task 3 and Task 5 registry-boundary tests |
| A missing model/tool produces a ready artifact | Task 4/5 fail-closed tests |
| Branches borrow facts or perimeter from one another | Task 3 branch-isolation tests |
| Existing C09 and `7/18` behavior changes | Mandatory R6-G0 regression guard |
| More than two questions or seven mandatory facts are emitted | Task 6 human-contract validator |
| Repository opens are needed for an accepted decision | Task 7 metric harness and blinded study |

---

### Task 1: Freeze the R6 contract, schema, and monotonic policy

**Depends on:** None

**Files:**

- Create: `internal/research/decision_artifact.go`
- Create: `internal/research/dispositions.go`
- Create: `internal/research/decision_policy.go`
- Modify: `internal/research/types.go`
- Modify: `internal/research/validate.go`
- Modify: `internal/research/render.go`
- Modify: `internal/research/assemble.go`
- Test: `internal/research/decision_artifact_test.go`
- Test: `internal/research/schema_compat_test.go`
- Test: `internal/research/decision_policy_test.go`
- Create: `configs/research/dispositions.yaml`
- Create: `configs/research/conditions.yaml`
- Create: `configs/research/checks.yaml`
- Create: `rubrics/decision.yaml`
- Create: `eval/decision_ready/regression_guard.py`

**Interfaces:**

Define the following new wire-level types in `internal/research`:

```go
type ProposedDisposition string

const (
    DispositionCloseNotAffected          ProposedDisposition = "CLOSE_NOT_AFFECTED"
    DispositionCloseNoExploitPath        ProposedDisposition = "CLOSE_NO_EXPLOIT_PATH"
    DispositionAcceptEnvironmentalMitigation ProposedDisposition = "ACCEPT_ENVIRONMENTAL_MITIGATION"
    DispositionKeepOpenForRemediation    ProposedDisposition = "KEEP_OPEN_FOR_REMEDIATION"
    DispositionHoldUnknown               ProposedDisposition = "HOLD_UNKNOWN"
)

type BranchStatus string

const (
    BranchComplete          BranchStatus = "COMPLETE"
    BranchAwaitingInput     BranchStatus = "AWAITING_INPUT"
    BranchContradicted      BranchStatus = "CONTRADICTED"
    BranchNotDecisionReady  BranchStatus = "NOT_DECISION_READY"
)

type Condition struct {
    ID          string   `json:"id"`
    Statement   string   `json:"statement"`
    Role        string   `json:"role"`
    SubjectRefs []string `json:"subject_refs"`
    Required    bool     `json:"required"`
    Polarity    string   `json:"polarity"`
}

type Fact struct {
    ID              string   `json:"id"`
    Proposition     string   `json:"proposition"`
    Subject         string   `json:"subject"`
    Scope           string   `json:"scope"`
    SourceTool      string   `json:"source_tool"`
    ToolVersion     string   `json:"tool_version"`
    ObservationRefs []string `json:"observation_refs"`
    DataDigest      string   `json:"data_digest"`
    Coverage        string   `json:"coverage"`
    Freshness       string   `json:"freshness"`
    Limitations     []string `json:"limitations"`
    Status          string   `json:"status"`
}

type EnvironmentAssertion struct {
    Variable   string   `json:"variable"`
    Value      string   `json:"value"`
    Principal  string   `json:"principal"`
    Timestamp  string   `json:"timestamp"`
    Source     string   `json:"source"`
    Freshness  string   `json:"freshness"`
    Supersedes []string `json:"supersedes"`
}

type DecisionVariable struct {
    ID            string   `json:"id"`
    Question      string   `json:"question"`
    AllowedValues []string `json:"allowed_values"`
    Required      bool     `json:"required"`
}

type DecisionBranch struct {
    ID                         string            `json:"id"`
    Assignments               map[string]string `json:"assignments"`
    Conditions                []Condition       `json:"conditions"`
    FactRefs                  []string          `json:"fact_refs"`
    EnvironmentAssertions     []EnvironmentAssertion `json:"environment_assertions"`
    Coverage                  string            `json:"coverage"`
    Status                    BranchStatus      `json:"status"`
    ProposedDisposition       ProposedDisposition `json:"proposed_disposition"`
    Limitations               []string          `json:"limitations"`
    RequiredEnvironmentInputs []string          `json:"required_environment_inputs"`
}

type Justification struct {
    ID                   string   `json:"id"`
    PremiseFactRefs      []string `json:"premise_fact_refs"`
    ConditionRefs        []string `json:"condition_refs"`
    RuleID               string   `json:"rule_id"`
    CoverageBasis        string   `json:"coverage_basis"`
    ContradictionRefs    []string `json:"contradiction_refs"`
    Disposition          ProposedDisposition `json:"disposition"`
    Statement            string   `json:"statement"`
}

type HumanAction struct {
    Mode                    string   `json:"mode"`
    EnvironmentQuestionRefs []string `json:"environment_question_refs"`
    AllowedResponses        []string `json:"allowed_responses"`
    MandatoryFactRefs       []string `json:"mandatory_fact_refs"`
}

type DecisionArtifact struct {
    Schema              string              `json:"schema"`
    FindingIdentity     FindingIdentity     `json:"finding_identity"`
    TargetScope         TargetScope         `json:"target_scope"`
    AdvisoryBinding     AdvisoryBinding     `json:"advisory_binding"`
    SharedFacts         []Fact              `json:"shared_facts"`
    DecisionVariables   []DecisionVariable  `json:"decision_variables"`
    Branches            []DecisionBranch    `json:"branches"`
    ProposedDisposition ProposedDisposition  `json:"proposed_disposition"`
    JustificationGraph  []Justification     `json:"justification_graph"`
    Contradictions      []Contradiction     `json:"contradictions"`
    HumanAction         HumanAction         `json:"human_action"`
    ReplayAndPolicyPins ReplayAndPolicyPins `json:"replay_and_policy_pins"`
}
```

Add:

```go
const (
    ReportSchemaV3          = "research-report/3"
    DecisionArtifactSchemaV1 = "decision-artifact/1"
)
```

Define a policy loader and monotonic validator:

```go
type SafetyPolicy struct {
    RequiredRules []string
    RequiredChecks []string
    ForbiddenPromotions []string
}

func LoadSafetyPolicy(fs fs.FS) (SafetyPolicy, error)
func ValidateMonotonicPolicy(base, candidate SafetyPolicy) error
```

The baseline policy MUST include all currently required decision gates. A configuration is valid only if it preserves every baseline rule and may only add requirements, narrow scope, or add vetoes.

**Steps:**

- [ ] Add the R6 types and constants without removing `EvidenceDecision`, `Disposition`, or legacy report fields.
- [ ] Add `/3` parsing and validation while retaining `/1` and `/2`.
- [ ] Make `decision-artifact/1` mandatory only for `/3`.
- [ ] Validate non-empty fact provenance, digest shape, branch status, disposition enum, variable enum membership, and complete replay/policy pins.
- [ ] Enforce the human contract in validation:
  - no more than two `environment_question_refs`;
  - no more than seven `mandatory_fact_refs`;
  - `allowed_responses` must be exactly `Accept` and `Reject`;
  - a branch set must include an explicit `unknown` branch.
- [ ] Load the initial condition/check/disposition catalogs from the new YAML files. Missing or malformed configuration produces a validation error or `NOT_DECISION_READY`; it MUST NOT load a permissive default.
- [ ] Add the external baseline regression guard. It accepts only sanitized labels and external paths supplied through arguments or environment variables.

**Focused verification:**

```bash
go test -count=1 ./internal/research \
  -run 'Test(DecisionArtifact|LegacyReport|ReportSchema|EnvironmentAssertion|MonotonicPolicy|HumanContract)'
```

Expected final result: all matching tests pass and no `[no tests to run]` message appears.

```bash
python3 -m py_compile eval/decision_ready/regression_guard.py
```

**Acceptance:**

- `/1` and `/2` historical fixtures parse, validate, and render byte-equivalently.
- `/3` requires `decision-artifact/1`.
- Environment assertions have no `Claim` field and cannot be serialized as claims.
- A forged policy that removes an existing required gate is rejected.
- More than two questions or seven mandatory facts makes the artifact invalid or `NOT_DECISION_READY`.
- No disposition enum outside R6 is accepted.

**Out of scope:** no flow loop, agent prompt execution, branch evaluation, CLI flag, or live model call.

---

### Task 2: Build the independent fact envelope and generic check/rule adapters

**Depends on:** Task 1

**Files:**

- Create: `internal/evidencetools/check_specs.go`
- Modify: `internal/evidencetools/mcp.go`
- Modify: `internal/evidencetools/mcp_test.go`
- Create: `internal/research/branch_evidence.go`
- Modify: `internal/research/decision.go`
- Modify: `internal/research/verification.go`
- Create: `internal/evaluator/rule_adapters.go`
- Test: `internal/research/branch_evidence_test.go`
- Test: `internal/evidencetools/check_specs_test.go`
- Test: `internal/evaluator/rule_adapters_test.go`

**Interfaces:**

Expose a typed catalog for existing evidence tools without moving interpretation into `internal/evidencetools`:

```go
type CheckSpec struct {
    ID            string
    Tool          string
    CoverageRule  string
    ArgumentSchema json.RawMessage
    MaxCalls      int
}

type CheckCatalog interface {
    Lookup(id string) (CheckSpec, bool)
    Validate(id string, args json.RawMessage) error
}

func DefaultCheckCatalog() CheckCatalog
```

The catalog must be used by both the existing verification-plan validator and the R6 flow broker. The MCP catalog remains the execution surface; the check catalog describes admissible requests and scope, not verdicts.

Add deterministic fact construction:

```go
type FactBuildInput struct {
    Lane  *LaneResult
    Trace *VerificationTrace
}

func BuildDecisionFacts(in FactBuildInput) ([]Fact, error)
```

`BuildDecisionFacts` may promote only:

- `OK` observations;
- digest-pinned observations;
- observations with explicit scope and coverage;
- observations whose session audit record binds the executed request.

Agent assertions and agent evidence references MUST remain outside `[]Fact`.

Add generic evaluator adapters that do not import `internal/research`:

```go
type RuleFact struct {
    ID       string
    Subject  string
    Scope    string
    Status   string
    Coverage string
    Digest   string
}

type RuleContext struct {
    Facts       []RuleFact
    Conditions  []ConditionInput
    Assignments map[string]string
}

type RuleResult struct {
    RuleID         string
    Status         string
    FactRefs       []string
    Limitations    []string
    Contradictions []string
}

type VerificationRule interface {
    ID() string
    Evaluate(context.Context, RuleContext) (RuleResult, error)
}
```

**Steps:**

- [ ] Move the existing private MCP tool descriptions into the typed check catalog without changing the tool set.
- [ ] Make `ValidateVerificationPlan` reject tools or arguments absent from the catalog.
- [ ] Convert lane facts and audited verification observations into `Fact` values with source tool, tool version, scope, coverage, and digest pins.
- [ ] Reject `ERROR`, `TIMEOUT`, `UNSUPPORTED`, `PARTIAL`, and unbound observations as independent facts.
- [ ] Add adapters for existing deterministic applicability and closure outcomes.
- [ ] Keep `VerifyDecision` as the veto authority. The adapters may produce facts and rule results but cannot emit a terminal verdict directly.
- [ ] Add tests proving module-level facts do not satisfy package-level subjects and package-level facts do not satisfy module-only subjects.

**Focused verification:**

```bash
go test -count=1 ./internal/evidencetools ./internal/research ./internal/evaluator \
  -run 'Test(CheckSpec|Fact|EvidenceDecision|VendorInventory|Applicability|RuleAdapter|SubjectGranularity)'
```

**Acceptance:**

- Existing `usage-scope`, `affected-resolve`, and replay evidence retain their current payload and digest semantics.
- Every R6 fact is independently produced and digest-bound.
- A trace mutation cannot create or alter a fact.
- Missing audit records, mismatched request arguments, or unresolved digests prevent fact promotion.
- Existing `VerifyDecision` tests remain green without relaxed gates.

**Out of scope:** no environment branches, no human artifact rendering, no new evidence tool, no flow engine, and no live model call.

---

### Task 3: Implement branch construction, environment assertions, and safe dispositions

**Depends on:** Task 2

**Files:**

- Modify: `internal/research/decision_artifact.go`
- Modify: `internal/research/dispositions.go`
- Create: `internal/research/branch_evaluator.go`
- Create: `internal/research/environment.go`
- Modify: `internal/evaluator/rule_adapters.go`
- Test: `internal/research/branch_evaluator_test.go`
- Test: `internal/research/environment_test.go`
- Test: `internal/research/dispositions_test.go`

**Interfaces:**

Implement:

```go
type ArtifactInput struct {
    Lane          *LaneResult
    Facts         []Fact
    Conditions    []Condition
    Variables     []DecisionVariable
    RuleResults   []RuleResult
    Policy        SafetyPolicy
    AgentProposals []AgentConditionProposal
}

type AgentConditionProposal struct {
    ConditionID string
    SubjectRefs []string
    Statement   string
    EvidenceRefs []string
}

func BuildDecisionArtifact(ctx context.Context, in ArtifactInput) (DecisionArtifact, error)
func ApplyEnvironmentAssertions(
    artifact DecisionArtifact,
    assertions []EnvironmentAssertion,
) (DecisionArtifact, error)
func ValidateDecisionArtifact(artifact DecisionArtifact) error
```

Phase 1 of branch evaluation supports only:

- `build_variant`, with values derived from the recorded build context;
- `deployment_perimeter`, with values declared by the configuration catalog.

The registry may list future variables, but an unimplemented variable must produce `NOT_DECISION_READY`; it must not be interpreted generically.

**Steps:**

- [ ] Enumerate decision variables in code/configuration, including allowed values and question text. The agent may reference a variable but cannot add a variable or value.
- [ ] Build a branch for every complete allowed assignment that the code can evaluate.
- [ ] Always add an explicit `unknown` branch.
- [ ] Keep branch facts, predicates, coverage, limitations, and status isolated. No branch may borrow facts or environment assertions from another branch.
- [ ] Produce `AWAITING_INPUT` only when the missing value is one of the declared variables and the resulting branch is otherwise complete.
- [ ] Produce `CONTRADICTED` when an operator assertion conflicts with deterministic evidence.
- [ ] Map `FalsifierTrustedInfrastructure` only to `ACCEPT_ENVIRONMENTAL_MITIGATION`.
- [ ] Reject any attempted mapping from `FalsifierTrustedInfrastructure` to `CLOSE_NO_EXPLOIT_PATH`.
- [ ] Accept `BasisConfigOrigin` only when the existing deterministic provenance result has complete sink coverage and no unresolved input source.
- [ ] Record environment answers as `EnvironmentAssertion` with principal, timestamp, source, freshness, and supersession history.
- [ ] Ensure `ApplyEnvironmentAssertions` never mutates `LaneResult`, `domain.Claim`, `EvidenceDecision`, or negative-verification state.

**Focused verification:**

```bash
go test -count=1 ./internal/research ./internal/evaluator \
  -run 'Test(Branch|Environment|TrustedInfrastructure|ConfigOrigin|Disposition|DecisionArtifact)'
```

**Acceptance:**

- A code-grounded `CLOSE_NOT_AFFECTED` or `CLOSE_NO_EXPLOIT_PATH` branch can only be produced from existing deterministic facts/rules.
- An environment-dependent case produces a finite branch set plus `unknown`, with no more than two declared questions.
- A conflicting environment answer produces `CONTRADICTED` and a conservative `HOLD_UNKNOWN` or `KEEP_OPEN_FOR_REMEDIATION`.
- Environment answers never become code-level `FALSE`.
- Trusted infrastructure never produces a safe terminal exploit-path verdict.
- A branch with missing required facts is `NOT_DECISION_READY`, not a complete branch.

**Out of scope:** no agent loop, no CLI wiring, no human study, no new CVE-family logic, and no auto-close.

---

### Task 4: Implement the generic `internal/flow` react loop

**Depends on:** Task 3

**Files:**

- Create: `internal/flow/contract.go`
- Create: `internal/flow/engine.go`
- Create: `internal/flow/planner.go`
- Create: `internal/flow/broker.go`
- Create: `internal/flow/registry.go`
- Create: `internal/flow/policy.go`
- Create: `internal/flow/branch.go`
- Create: `internal/flow/replay.go`
- Test: `internal/flow/engine_test.go`
- Test: `internal/flow/policy_test.go`
- Test: `internal/flow/replay_test.go`
- Test: `internal/flow/registry_test.go`

**Interfaces:**

```go
type PlanAction struct {
    ID          string
    AdapterID   string
    Arguments   json.RawMessage
    Purpose     string
    ConditionID string
}

type Plan struct {
    StepID      string
    Actions     []PlanAction
    ConditionIDs []string
}

type Observation struct {
    ID           string
    ActionID     string
    Status       string
    Completeness string
    Scope        string
    DataDigest   string
    EvidenceRefs []string
    Limitations  []string
}

type Planner interface {
    Plan(context.Context, PlanInput) (Plan, error)
}

type Reassessor interface {
    Reassess(context.Context, ReassessInput) (Reassessment, error)
}

type Broker interface {
    Execute(context.Context, PlanAction) (Observation, error)
}

type Registry interface {
    Check(action PlanAction) error
    Condition(id string) (Condition, bool)
}

type Engine struct {
    Planner    Planner
    Reassessor Reassessor
    Broker     Broker
    Registry   Registry
    Policy     SafetyPolicy
    MaxSteps   int
    MaxActions int
}

func (e *Engine) Run(context.Context, Input) (Result, error)
func Replay(context.Context, ReplayInput) (Result, error)
```

The engine MUST implement:

```text
PLAN → validate plan → ACT through Broker → OBSERVE → REASSESS
```

It stops on:

- decision-ready artifact;
- all branches complete;
- required environment input;
- terminal contradiction;
- exhausted action/step budget;
- planner/reassessor failure;
- unsupported check or condition;
- `NOT_DECISION_READY`.

**Steps:**

- [ ] Validate each proposed action against the registry before execution.
- [ ] Apply monotonic policy validation before the first action and after every reassessment.
- [ ] Execute actions only through the broker; no shell or arbitrary process path is introduced.
- [ ] Record every request, observation, status, digest, and limitation in the flow event stream.
- [ ] Treat broker errors and unavailable planners as unknown outcomes.
- [ ] Do not allow a planner or reassessor to set `ProposedDisposition`.
- [ ] Preserve previous observations and branch revisions; revisions must be append-only in the flow result.
- [ ] Implement replay using recorded requests and observations without a model call.
- [ ] Add deterministic step/action budgets in the policy configuration.

**Focused verification:**

```bash
go test -count=1 ./internal/flow \
  -run 'Test(Engine|PlanValidation|Broker|Policy|Replay|Budget|Registry|FailClosed)'
```

**Acceptance:**

- A valid plan executes only registered bounded actions.
- An invalid tool, unknown condition, unknown variable, policy relaxation, or missing broker observation results in a non-ready result.
- An unavailable planner never produces a complete disposition.
- Replay produces the same flow result and artifact inputs without calling the planner or model.
- No code in `internal/flow` references a CVE, advisory ID, package path, or legacy `FalsifierKind`.

**Out of scope:** no model provider implementation, no report rendering, no direct use of `domain.Claim`, and no modification to the legacy analyzer workflow.

---

### Task 5: Adapt the current research lane and add pinned R6 prompts/configuration

**Depends on:** Task 4

**Files:**

- Create: `internal/research/flow_adapter.go`
- Create: `internal/research/flow_adapter_test.go`
- Modify: `internal/research/replay.go`
- Modify: `internal/research/verification.go`
- Modify: `cmd/izyan/research.go`
- Create: `eval/agent7/prompts/r6-plan-v1.txt`
- Create: `eval/agent7/prompts/r6-reassess-v1.txt`
- Create: `eval/agent7/prompts/r6-counterexample-v1.txt`
- Modify: `eval/agent7/freeze/manifest.json`
- Modify: `configs/research/checks.yaml`
- Modify: `configs/research/conditions.yaml`
- Modify: `configs/research/dispositions.yaml`
- Modify: `rubrics/research.yaml`
- Modify: `rubrics/decision.yaml`

The existing `r0-v1` through `r0-v4` prompt files MUST remain byte-stable.

**Interfaces:**

```go
type DecisionReadyOptions struct {
    LaneOptions LaneOptions
    Agent       AgentDriver
    FlowPolicy  flow.Policy
    ConfigFS    fs.FS
    OutputDir   string
}

type AgentDriver interface {
    Plan(context.Context, flow.PlanInput) (flow.Plan, AgentTurnMetadata, error)
    Reassess(context.Context, flow.ReassessInput) (flow.Reassessment, AgentTurnMetadata, error)
}

func RunDecisionReady(
    context.Context,
    DecisionReadyOptions,
) (*Report, error)
```

The adapter must:

1. run the existing deterministic lane;
2. construct base facts and conditions from code/configuration;
3. invoke the flow engine;
4. execute checks through the existing confined `EvidenceSession`;
5. construct branches and the `DecisionArtifact`;
6. preserve all audit/replay pins.

The agent prompts may propose:

- which registered condition needs checking;
- which registered evidence check to execute;
- which counterexample to investigate;
- whether a declared environment variable appears decision-relevant.

The prompts may not propose:

- arbitrary condition IDs;
- arbitrary variable values;
- branch predicates;
- verified facts;
- final dispositions;
- `Claim{FALSE}`;
- policy changes.

**Steps:**

- [ ] Add `--decision-ready` to `researchFlags`; preserve the existing route when absent.
- [ ] Add `--replay-decision-run` for replaying flow events and observations without a model call.
- [ ] Implement the adapter from flow `PlanAction` to `VerificationRequest` and the existing audited session.
- [ ] Pin all R6 prompt/config/rubric files in the run manifest and `eval/agent7/freeze/manifest.json`.
- [ ] Make missing or invalid R6 config fail closed.
- [ ] Use fake `AgentDriver` implementations in all unit tests.
- [ ] Ensure no live model call occurs in tests.
- [ ] Ensure a model/harness failure produces a report with `HOLD_UNKNOWN` or `NOT_DECISION_READY`, not a proposed close.

**Focused verification:**

```bash
go test -count=1 ./internal/flow ./internal/research ./cmd/izyan \
  -run 'Test(FlowAdapter|DecisionReady|Plan|Reassess|Counterexample|Replay|RunManifest|PromptPin)'
```

**Acceptance:**

- `izyan research --decision-ready` runs the same strict confined evidence session for lane and flow checks.
- Every flow action is present in the persisted audit/event ledger.
- A replay does not invoke the provider/model and reproduces the same branch statuses and proposed disposition.
- R6 prompt/config/rubric hashes are present in the manifest.
- Legacy `izyan research` behavior and historical replay remain unchanged.
- Missing model infrastructure never yields a decision-ready artifact.

**Live-call policy:** no live model calls are made for this task. The adapter is validated with fake planners and replayed observations. Live provider execution is deferred to Task 7.

**Out of scope:** no default switch from legacy mode, no corporate corpus run, no human acceptance study, and no auto-close.

---

### Task 6: Render, validate, persist, and expose the human decision artifact

**Depends on:** Task 5

**Files:**

- Modify: `internal/research/types.go`
- Modify: `internal/research/assemble.go`
- Modify: `internal/research/render.go`
- Modify: `internal/research/validate.go`
- Modify: `internal/research/replay.go`
- Create: `internal/research/decision_artifact_report_test.go`
- Modify: `cmd/izyan/research.go`
- Modify: `cmd/izyan/research_decision_test.go`

**Outputs for decision-ready mode:**

- `report.json` with `schema = research-report/3`;
- `report.md`;
- `decision-artifact.json` containing canonical `decision-artifact/1`;
- `flow-events.jsonl`;
- existing observation/fact/artifact ledgers;
- `run-manifest.json` with policy, config, rubric, prompt, snapshot, advisory, and tool pins.

**Steps:**

- [ ] Add `DecisionArtifact` to `Report` and derive the compatibility `EvidenceDecision` projection from it.
- [ ] Render an inverted-pyramid first screen:
  1. proposed disposition;
  2. accept/reject instruction;
  3. at most seven mandatory fact cards;
  4. at most two environment questions;
  5. branch matrix and contradiction/unknown status;
  6. justification;
  7. replay and policy pins in the appendix.
- [ ] Render all non-mandatory facts and detailed evidence in the appendix, never as mandatory first-screen work.
- [ ] Render environmental mitigation separately from code-grounded closure.
- [ ] Render `HOLD_UNKNOWN`, `KEEP_OPEN_FOR_REMEDIATION`, and `NOT_DECISION_READY` with the exact missing fact or unsupported condition.
- [ ] Validate every `Fact` reference, observation digest, branch fact reference, rule reference, contradiction reference, and artifact pin.
- [ ] Reject a `/3` artifact if:
  - any branch lacks its own coverage/status;
  - the unknown branch is absent;
  - a user answer is represented as a code claim;
  - the proposed disposition is not justified by a deterministic rule;
  - the human action contains anything besides declared questions and accept/reject;
  - the first screen exceeds seven mandatory facts;
  - more than two environment questions are present.
- [ ] Keep `Disposition.Class=REVIEW_REQUIRED` and `AutoClose=false`.
- [ ] Make `decision-artifact.json` byte-stable for identical inputs.
- [ ] Keep `--replay-agent-turn` behavior for historical `/2` runs.

**Focused verification:**

```bash
go test -count=1 ./internal/research ./cmd/izyan \
  -run 'Test(ReportSchemaV3|DecisionArtifact|HumanContract|BranchRender|LegacyReport|Replay|CLI|NoAutoClose)'
```

**Mandatory regression guard R6-G0:**

Run after this task and before the validation sequence:

```bash
python3 eval/decision_ready/regression_guard.py \
  --baseline-manifest "$R6_CORPORATE_BASELINE" \
  --c09-replay-dir "$C09_REPLAY_DIR" \
  --c09-snapshot "$C09_SNAPSHOT" \
  --c09-cve "$C09_CVE" \
  --c09-advisory "$C09_ADVISORY" \
  --output-dir "$TMPDIR/r6-regression-guard"
```

The external baseline manifest contains the existing 18 snapshot-conditioned cases and expected aggregate values. The guard MUST assert:

- current deterministic subset remains `7/18` terminal verified negatives;
- false-safe count remains `0`;
- C09 replay remains `NOT_AFFECTED`, `COMPLETE`, with resolved evidence refs and `AutoClose=false`;
- the legacy replay path makes no model call;
- historical `/1` and `/2` reports remain valid.

If R6-G0 fails, do not proceed to live validation.

**Acceptance:**

- A human can read the first screen without opening the repository or rerunning a tool.
- A complete branch requires only `Accept` or `Reject`, plus zero to two declared answers.
- The artifact says exactly which facts justify the proposed disposition and which branch is selected by each allowed environment value.
- A missing fact or contradiction is explicit and conservative.
- The existing `7/18` and C09 behavior remains green.

**Out of scope:** no human study execution, no provider call, no default-mode switch, and no tracker/VEX write.

---

### Task 7: Add the human-work measurement harness and execute validation

**Depends on:** Task 6 and a passing R6-G0

**Files:**

- Create: `eval/decision_ready/metrics.py`
- Create: `eval/decision_ready/runner.py`
- Create: `eval/decision_ready/events.schema.json`
- Create: `eval/decision_ready/test_metrics.py`
- Create: `eval/decision_ready/README.md`
- Modify: `eval/README.md`
- Modify: `docs/dev/gap-analysis.md`
- Modify: `docs/dev/implementation-status.md`

The harness MUST consume sanitized artifacts and external corporate manifests. Private paths, ticket IDs, reviewer identities, and raw corporate records remain outside the repository.

**Event contract:**

Each human review event records:

```json
{
  "artifact_digest": "sha256:...",
  "started_at": "...",
  "finished_at": "...",
  "accepted": true,
  "environment_answers": [],
  "mandatory_fact_refs_read": [],
  "repository_open_count": 0,
  "tool_rerun_count": 0,
  "technical_follow_up_count": 0,
  "returned_for_remediation": false,
  "reopened": false
}
```

Compute:

- `human_decision_time` median, P75, and P95 by proposed disposition and branch count;
- `facts_read` median/P75/P95;
- `repo_open_rate = artifacts with repository_open_count > 0 / decision-ready artifacts`;
- `missing_fact_rejection_rate`;
- environment question count, answer rate, unknown rate, and branch-change-after-answer rate;
- accepted false-safe count/rate;
- reopen/reversal rate;
- human rerun rate;
- model calls, elapsed time, and provider-reported cost per artifact.

The human contract target is:

- `repo_open_rate = 0` for accepted decision-ready artifacts;
- no accepted artifact with a missing mandatory fact;
- no accepted artifact requiring technical follow-up;
- `[INFERENCE]` median decision time `≤5 min`;
- `[INFERENCE]` P95 decision time `≤10 min`.

**Validation sequence:**

1. **Three to five controls**

   Use sanitized labels corresponding to:
   - one existing complete applicability negative;
   - one mixed/product-linked positive control;
   - one genuinely unresolved case;
   - one environment-dependent case;
   - optionally one second complete negative with a different route.

   Run:

   ```bash
   python3 eval/decision_ready/runner.py \
     --manifest "$R6_CONTROL_MANIFEST" \
     --mode decision-ready \
     --output-dir "$TMPDIR/r6-controls"
   ```

   Live-call cost and failure behavior:

   - maximum four model calls per case: initial plan, reassessment, counterexample, final reassessment;
   - one configured overall timeout per case;
   - provider/model token and monetary cost must be recorded from the harness;
   - if the E6/provider/model is unavailable, the case is `NOT_RUN` for capability measurement and emits `HOLD_UNKNOWN`; it is never counted as decision-ready or as a successful negative.

   Falsification:
   - any accepted false-safe control;
   - a positive control receiving a close disposition;
   - an unresolved control receiving a complete branch;
   - any model assertion promoted to a fact.

2. **All 18 corporate snapshot-conditioned cases**

   Use the external anonymized manifest and saved snapshots. Reuse replayed agent turns where available; do not make live calls merely to fill missing evidence. Cases without sufficient retained inputs are reported separately as `NO_SNAPSHOT`, `NO_REPLAY`, or `NOT_RUN`.

   ```bash
   python3 eval/decision_ready/runner.py \
     --manifest "$R6_CORPORATE_MANIFEST" \
     --mode decision-ready \
     --output-dir "$TMPDIR/r6-corporate-18"
   ```

   Report separately:

   - terminal deterministic verified negatives;
   - decision-ready code-grounded branches;
   - environmental-mitigation branches;
   - `HOLD_UNKNOWN`;
   - `KEEP_OPEN_FOR_REMEDIATION`;
   - `NOT_DECISION_READY`;
   - no-snapshot/data-cap findings;
   - errors and invalid format.

   Falsification:
   - any false-safe result;
   - any decrease in the R6-G0 baseline without a documented input change;
   - any artifact with unresolved evidence references;
   - any artifact requiring repository access after being marked decision-ready.

3. **VEX-Bench safety controls**

   Run the named safety controls first with point-case commands:

   ```bash
   go run ./cmd/izyan eval \
     --corpus eval/corpus-real.json \
     --case "$VEX_CONTROL_CASE_1"
   ```

   Repeat for each selected safety control. The R6 route may be measured alongside the existing evaluator, but false-safe remains zero-tolerance.

   Falsification:
   - any known exploitable control receives `CLOSE_NOT_AFFECTED` or `CLOSE_NO_EXPLOIT_PATH`;
   - a partial/unknown observation is cited as a complete fact;
   - an environment answer changes code-grounded applicability.

4. **Holdout**

   Use a held-out set split by CVE mechanism, repository, and reason class. The split and labels remain outside the implementation tree or use sanitized public fixtures. Do not tune catalog entries, prompts, or branches after seeing holdout labels.

   ```bash
   python3 eval/decision_ready/runner.py \
     --manifest "$R6_HOLDOUT_MANIFEST" \
     --mode decision-ready \
     --output-dir "$TMPDIR/r6-holdout"
   ```

   Falsification:
   - any accepted false-safe;
   - a decision-ready rate that depends on a case-specific rule or identifier;
   - branch behavior that changes when an unrelated variable is added;
   - any policy/configuration change that weakens an existing gate.

5. **Blinded human acceptance study**

   - Randomize artifacts from the decision-ready and control arms.
   - Blind reviewers to arm, ground truth, prior disposition, and model status.
   - Use at least two independent reviewers per artifact.
   - Permit only the declared environment answers and `Accept`/`Reject`.
   - Record the event contract above.
   - Reviewers must not be instructed to inspect the source; any repository opening is recorded as a failure of the decision-ready contract.
   - Analyze acceptance, rejection, decision time, fact cards read, follow-up questions, reruns, returns, and reversals separately for code-grounded closure and environmental mitigation.

   Falsification:
   - any accepted false-safe on the safety holdout;
   - any accepted incomplete branch;
   - nonzero repository-open rate for artifacts claimed decision-ready;
   - technical follow-up required on accepted artifacts;
   - more than two questions or more than seven mandatory facts;
   - human acceptance depends on information absent from the artifact.

**Final repository validation — run once, after all implementation and focused checks:**

```bash
gofmt -w internal cmd/izyan
go vet ./...
go test ./...
```

Then run the full corpus commands exactly once:

```bash
go run ./cmd/izyan eval --corpus eval/corpus-real.json -j 4
VA_PRODUCT_REPO="$VA_PRODUCT_REPO" \
  go run ./cmd/izyan eval --corpus eval/live-corpus.json
```

The full corpus validation fails if `false-safe != 0`.

**Acceptance:**

- The harness reports the human-work metrics separately from T0/code-grounded safety and environmental mitigation.
- The report never conflates `CLOSE_*` proposals with actual auto-close.
- Live-call costs, unavailable-provider outcomes, and skipped cases are explicit.
- The holdout and blinded study have no accepted false-safe.
- `eval/README.md` documents `/3`, `decision-artifact/1`, replay, human metrics, and fail-closed behavior.
- `docs/dev/gap-analysis.md` updates B51 with the measured implementation status. B51 is removed from the open backlog only if the stated artifact, safety, and human-work acceptance criteria are all met; otherwise it remains open with the measured blocker.
- `docs/dev/implementation-status.md` records the final result without claiming stronger automation than measured.

## Dependency / Execution Order

```text
Task 1
  → Task 2
    → R6-G0 baseline guard
      → Task 3
        → Task 4
          → Task 5
            → Task 6
              → R6-G0 repeat
                → Task 7 validation
                  → final repository gates and one-time full corpus run
```

The current `7/18` and C09 replay behavior is a mandatory regression guard, not an optional benchmark. Any failure stops the sequence before live validation.

## Assumptions and Plan-Changing Conditions

- **[INFERENCE]** `research-report/3` can be introduced without breaking consumers once `/1` and `/2` parsing remains supported and downstream consumers are updated to ignore or consume the new `decision_artifact` field.
- **[INFERENCE]** One deployment variable and one build variant are sufficient to validate the branch architecture; they do not establish coverage for all deployment/configuration variables.
- **[INFERENCE]** The ≤5-minute median and ≤10-minute P95 human targets are achievable; they are targets to measure, not implementation facts.
- Existing `VerifyDecision` remains the sole authority for terminal code-grounded negatives. If a new R6 rule appears to require bypassing it, the plan changes by adding a deterministic adapter or remains `NOT_DECISION_READY`.
- If a required environment fact cannot be expressed using a finite catalog variable, the case remains `HOLD_UNKNOWN` or `KEEP_OPEN_FOR_REMEDIATION`; the catalog is not expanded from a single case.
- If a provider or E6 harness is unavailable, no live capability claim is made. Replays and deterministic tests may still validate safety and reproducibility, but they do not substitute for the live-agent validation stage.
- If the blinded study shows that accepted artifacts still require repository inspection or technical follow-up, the human contract is not met even if machine verdict accuracy is high.
- If any holdout or VEX-Bench safety control produces an accepted false-safe, stop rollout, retain `AutoClose=false`, and do not relax the falsifier or branch gates.
# Product B Measurement Lane Tooling Implementation Plan (Phase Five)

**Series:** `docs/dev/plans/2026-10-28-05-remaining-architecture-series.md` (order, prerequisites, series-wide invariants).


**Goal:** Prepare an identity-bound, label-isolated Product B measurement lane with separate human and machine metrics, without executing a benchmark.

**Architecture:** Extend the existing VEX-Bench control-plane package and reuse triage’s runtime/replay and Phase 1 offline evaluation. Preparation creates one immutable input bundle for both products; execution is a separate explicit operation. Human review/scoring inputs never enter model-visible types.

**Tech stack:** Go 1.25; existing `internal/eval/vexbench`, triage artifacts and offline evaluator; Python standard-library metric utilities and pytest fixtures.

**Spec:** Governing review §6 Phase 5; prior dual-product decision.

## Recovery prerequisite / current execution contract (2026-10-29)

Phase 4 Task 2 deletion is superseded by Phase 1 recovery Tasks 8–14. Begin
downstream work only after preservation acceptance plus owner-run integration
and unchanged Product A gates. Task 1/2 goals below remain; consume live
`assessment.v3` / `decision-package.v4`, captured finite `human_review_plan`,
`environment-assertion.v1` and `human-decision.v2` (optional comment, explicit
branch/projection/assertion binding). Prior versions remain history, not upgrades.
No external baseline is required by live triage or replay.
Two-step environment CLI reviews carry the displayed `--projection-hash` into
Accept/Reject; locked comparison rejects superseded presentations. Lane tooling
must not drop that pin or silently accept a newer unseen branch. One-step
answer+decision supplies the complete selected answer set, not inherited answers.

Task 3 modifies the preserved tracked offline controller, rather than creating
one after deletion. Preserve ordinary-research current census and history-only
`eval research-replay`, fresh invocation/run/input/digest validation, indexes,
summaries, failure exits and CI safety gates. Measure answer/unknown counts,
branch changes and extra human work separately from Product A authority.
Synthetic preservation tests do not establish R6 human-time targets or quality.


## Global Constraints

- Apply the series-wide invariants.
- **Do not execute the VEX benchmark, a model arm, B1 or a human study in this phase.**
- Test only synthetic local inputs, scripted clients and fake command executors.
- Do not use `PrepareAdvisory`’s Product A usability filtering as a prerequisite for Product B investigation. Product B receives the captured record, including unsupported/partial shapes.
- Record unavailable measurements as unassessed/null, not zero.
- No benchmark task ID or GT category appears in production dispatch or investigator messages.

## Review Focus

| Concern | Owning task |
|---|---|
| GT, reference PR and task-name hints cannot reach the agent | Task 1 |
| A and B receive identical source/advisory/build material | Task 1 |
| Pins and cost include retries and failed calls | Task 2 |
| Preparation cannot launch an arm | Task 2 |
| Decision readiness is not JSON completion | Task 3 |
| Human negative errors and machine false-safe stay separate | Task 3 |

### Task 1: Build a shared, blinded VEX input preparation contract

**Depends on:** Phase 4

**Files:**
- Create:
  - `internal/eval/vexbench/triage_input.go`
  - `internal/eval/vexbench/triage_input_test.go`
  - `cmd/izyan/vexbench_triage.go`
  - `cmd/izyan/vexbench_triage_test.go`
- Modify:
  - `internal/eval/vexbench/task.go`
  - `internal/eval/vexbench/advisory.go`
  - `internal/eval/vexbench/snapshot.go`
  - `cmd/izyan/vexbench.go`
  - `cmd/izyan/main.go`

**Interfaces:**
- Consumes:
  - `Task`, `LocateSnapshot`, raw frozen advisory bytes
  - Phase 2 `InvestigationInputs` and target/build contract
- Produces:
  - `PreparedCase` with opaque finding ID, snapshot/commit/content identity, exact advisory/fix/material digests and build selection.
  - `PrepareTriageCase(...) (PreparedCase, error)`, accepting only label-free inputs after control-plane selection.
  - Control-plane join from task ID to opaque finding ID, stored outside the agent bundle.
  - CLI `izyan eval vex-triage prepare`; no execution during preparation.

- [ ] Step 1: Add `TestPreparedCaseHasNoLabelFields`, `TestTaskIDCannotLeakThroughFindingID`, `TestPreparedInputsMatchAcrossProducts`, `TestPartialAdvisoryStillPreparesForProductB` and `TestPreparedCaseRejectsSnapshotDrift`.
- [ ] Step 2: Run:
  ```bash
  go test ./internal/eval/vexbench ./cmd/izyan -run 'Test(PreparedCase|TaskIDCannotLeak|PreparedInputs|PartialAdvisoryStill)' -count=1
  ```
  Expected **FAIL**.
- [ ] Step 3: Separate raw capture from Product A capability/usability decisions. Prepare the raw captured record once; Product A may subsequently fail its applicability contract while Product B still investigates it.
- [ ] Step 4: Construct model-visible types from an explicit field allowlist, never by serializing `Task`. Exclude GT, category, PR URL, prior predictions, corpus labels and task-derived filenames. Keep genuine advisory fix references captured from the advisory itself.
- [ ] Step 5: Rerun the focused command; expected **PASS**. Use sentinel labels/PR strings and assert their absence from every model message, tool definition, material and launched argv visible to the arm.

**Acceptance:** The prepared bundle binds both products to identical evidence and contains no scorer-side information.

### Task 2: Pin execution provenance and account for real model usage

**Depends on:** Task 1

**Files:**
- Create:
  - `internal/eval/vexbench/triage_run.go`
  - `internal/eval/vexbench/triage_run_test.go`
- Modify:
  - `internal/llm/client.go`
  - `internal/llm/llm_test.go`
  - `internal/productb/triage/runner.go`
  - `internal/productb/triage/chat.go`
  - `internal/productb/triage/artifacts.go`
  - `internal/productb/triage/replay.go`
  - `internal/productb/registry.go`
  - `cmd/izyan/triage.go`
  - `cmd/izyan/vexbench_triage.go`
  - `cmd/izyan/vexbench_triage_test.go`

**Interfaces:**
- Consumes:
  - Existing `Client.Chat` and `ChatClient` contract
  - `prompt-input.v1`, registry/tool version pins, triage run artifacts
- Produces:
  - `llm.ChatExchange` audit record: requested/returned model ID, provider fingerprint when supplied, usage presence and token counts, elapsed time, finish/error status and request identity.
  - `ClientConfig.ExchangeSink` or equivalent constructor-injected callback; keep the existing `Chat` return signature and migrate callers without a second chat implementation.
  - `vex-triage-run.v1`: input-bundle hash, code/toolchain/tool-registry/prompt/model/config pins, per-exchange usage and arm result references.
  - Explicit `execute` operation guarded by a run authorization flag; default remains preparation only.

- [ ] Step 1: Add `TestUsageRecordsEveryProviderAttempt`, `TestMissingProviderUsageIsUnassessed`, `TestRunPinsExactPromptAndToolSurface`, `TestPrepareCannotExecute` and `TestExecutionRequiresExplicitAuthorization`.
- [ ] Step 2: Run:
  ```bash
  go test ./internal/llm ./internal/eval/vexbench ./cmd/izyan -run 'Test(UsageRecords|MissingProviderUsage|RunPinsExact|PrepareCannot|ExecutionRequires)' -count=1
  ```
  Expected **FAIL**.
- [ ] Step 3: Capture each real HTTP exchange, including retries/errors, without secrets or response-body leakage. Do not estimate missing token usage. Compute cost only from supplied, version-pinned pricing and measured usage; otherwise report cost unavailable.
- [ ] Step 4: Implement separate preparation, explicit execution and offline replay paths. Validate all required pins before launch; use injected executors in tests. A mutable model alias without a returned version/fingerprint is a visible reproducibility limitation, not a fabricated immutable model pin.
- [ ] Step 5: Rerun the focused command; expected **PASS**. Scripted tests assert zero real provider/container/network launches. No benchmark command is run.

**Acceptance:** The lane can later execute a fully pinned arm and account for its observed usage, but preparing or replaying a lane cannot spend model budget.

### Task 3: Implement independent recommendation, authority and human-work scoring

**Depends on:** Tasks 1 and 2

**Files:**
- Create:
  - `internal/eval/vexbench/triage_score.go`
  - `internal/eval/vexbench/triage_score_test.go`
- Modify:
  - `eval/decision_ready/runner.py`
  - `eval/decision_ready/test_runner.py`
  - `internal/productb/triage/evaluation.go`
  - `internal/productb/triage/evaluation_test.go`
  - `cmd/izyan/vexbench_triage.go`
  - `eval/decision_ready/metrics.py`
  - `eval/decision_ready/test_metrics.py`
  - `eval/decision_ready/events.schema.json`
  - `eval/decision_ready/README.md`
  - `docs/cli.md`
  - `docs/dev/gap-analysis.md`
  - `eval/README.md`

**Interfaces:**
- Consumes:
  - Verified `DecisionPackage`, `EvaluateDecisionPackage`
  - Product A `vexbench.Prediction`
  - `HumanDecisionRecord` v2, captured environment assertions, branch/projection hashes and separate blinded review/scoring events; historical v1 remains version-specific
- Produces:
  - Separate `ProductAMetrics`, `ProductBRecommendationMetrics` and `AutomationMetrics`.
  - Versioned `triage-review-event.v1` bound to canonical decision-package hash.
  - Versioned `triage-score.v1` for independent identity/mechanism/factual-error review.
  - A migrated controller that invokes triage/preparation contracts, never retired R6 routes.

- [ ] Step 1: Add `TestTriageScoringSeparatesHumanAndMachine`, `TestDecisionReadyRequiresReviewOutcome`, `TestMissingReviewIsNotSuccess`, `TestSupportCalibrationUsesAssessedCasesOnly` and Python fixtures for review timing, duplicate review events and foreign package hashes.
- [ ] Step 2: Run:
  ```bash
  go test ./internal/eval/vexbench ./internal/productb/triage -run 'Test(TriageScoring|DecisionReadyRequires|MissingReview|SupportCalibration)' -count=1
  python3 -m pytest eval/decision_ready/test_metrics.py eval/decision_ready/test_runner.py -q
  ```
  Expected **FAIL**.
- [ ] Step 3: Measure these axes independently:
  - delivered package rate;
  - reviewer-confirmed decision-ready rate;
  - identity/mechanism correctness;
  - decisive factual errors;
  - incorrect negative judgments and CLOSE/LOWER_PRIORITY recommendations;
  - additional repository opens, tool reruns and technical follow-ups;
  - reviewer time from explicit start to Accept/Reject;
  - declared environment questions, answers, unknowns, supersession and branch changes;
  - support-level calibration against assessed outcomes;
  - observed latency, tokens and cost;
  - Product A false-safe and unverified machine reductions.
- [ ] Step 4: Require external reviews for semantic/factual quality and human-effort metrics. GT’s exploitability category alone cannot establish mechanism correctness. Do not infer review start from package creation, or readiness from successful JSON parsing.
- [ ] Step 5: Rerun the commands; expected **PASS** using synthetic data only. Document required future study inputs and explicit execution authorization; publish no benchmark results.

**Acceptance:** Tooling reports the requested metrics with honest coverage and denominators, without mixing recommendation quality, human acceptance or Product A authority.

## Dependency / Execution Order

Task 1 → Task 2 → Task 3.

**Unexecuted measurement prerequisites:** Real model/provider authorization, pinned benchmark inputs, independent semantic reviewers and recorded human review events. Their absence blocks measurement, not completion of this tooling plan.

---

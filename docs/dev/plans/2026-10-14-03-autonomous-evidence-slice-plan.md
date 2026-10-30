**Status: PROPOSED — not implemented, not approved for execution yet.**
Plan for review. It authorizes no code change by itself.

Date: 2026-10-14. Spec: `docs/dev/specs/2026-10-14-Izyan-Autonomous-Evid.md`.
Producer: OMP `architect` subagent (read-only), session
`CveExploitabilityArchReview`, method `skill://writing-plans`, following
Revision 1 of `docs/dev/reports/2026-10-14-03-cve-exploitability-architecture-review.md`
and the sequencing decision recorded with it.

Reproduced verbatim, with two command corrections requested by the same
architect before persisting:
1. Task 1 Step 4 — the manifest assertion no longer ends in `or True`
   (it validated nothing); it now asserts the id list, the role set and the
   presence of `snapshot_hash`/`advisory_sha256`.
2. Task 9 Step 1 — `gofmt -w <directories>` is not a valid invocation
   (`gofmt` does not recurse); it now passes the explicit changed-file list.

Main pre-flight (2026-10-14), facts only:
- `<VA_TMP>` is the documented private run directory `…/vuln-analyzer/tmp`
  (`docs/dev/agent7-state.md:11`); the case sources exist there
  (`agent7-corp/runs/` and `exploitable/runs/` are populated).
- Advisories named by the matrix exist in-repo:
  `eval/advisories/reviewed/GHSA-rm6m-hrcw-jw33.json`,
  `eval/advisories/reviewed/GHSA-pxq6-2prw-chj9.json`,
  `eval/advisories/reviewed/GO-2026-5942.json`.
- `GO-2026-6355` (C03 positive control) is not in-repo, but it does exist in
  the private run tree: `<VA_TMP>/exploitable/advisories/GO-2026-6355.json`
  (also present under `<VA_TMP>/agent7-exploitable/advisories/` and
  `<VA_TMP>/govulndb/`). Task 1 must pin it from there.

## Amendment R1 — 2026-10-14, after the Task 4 code review

Source: OMP `architect` ruling `GuardRouteRuling` (same read-only session that
produced this plan), issued after an independent `reviewer` found two P0
false-safe paths in the Task 4 implementation. Changes applied to this file:

1. **Gate A / Task 7:** C01 is no longer a fallback. C02 (product
   build-closure absence) is the required negative capability demonstration;
   if it cannot close, the slice stops and records the missing capability.
2. **Task 4 Step 2:** added the advisory-wide subject-coverage rule (the
   required subject set comes from every affected entry of the frozen
   advisory, not from the agent's selected subject; every subject must be
   covered or explicitly resolved, otherwise `INCONCLUSIVE` naming each
   unresolved subject).
3. **Task 4 Step 3:** package absence may never be derived from
   `PACKAGE_USAGE` `NOT_USED` (including `present: true`); only a complete
   product-side build closure or an equivalent closed absence fact is
   admissible.
4. **Task 4 Step 4:** the guard/bound route fails closed in this slice
   (`guard_verification_capability_missing`); `GuardVerification` and
   `DecisionInput.Source` leave the accepted proof contract.
5. **Task 4 Step 5:** added trace-integrity requirements (request/observation
   binding, populated snapshot hash and build context, coverage rule, valid
   evidence refs, empty `Limitations`).
6. **Task 4 Steps 7–8 and Acceptance:** the guard test expectation is inverted
   to fail-closed; the focused command always runs with `-count=1` and must not
   be reported as a pass when the pattern matches no tests.

Consequence for the backlog: the guard/bound proof family becomes a recorded
gap (tool-backed complete sink/flow/guard/bound observation plus an adapter
that re-runs `goanalysis.Verifier`), not a slice deliverable.

## Amendment R2 — 2026-10-14, after the Task 7 capability demonstration

Source: OMP `architect` ruling `CapabilityGapRuling` (same read-only session).
Task 7 ran all four cases through `izyan research` with replayed agent turns.
**Result: controlled stop — `CAPABILITY_GAP_RECORDED`.** All four reports are
`INCONCLUSIVE` with `Disposition=REVIEW_REQUIRED` and `AutoClose=false`
(safety invariants held; no false-safe verdict was produced). The
specification's success criterion — one real case reaching an independently
verified negative — was **not** met.

Observed, artifact-backed blockers:

1. **No plan-bearing agent turn.** Every retained answer predates the proposal
   contract (zero `verification_plan` hits), so `VerifyDecision` stops at
   `Proposal == nil` and the verification path has never run on a real case.
2. **Dead option plumbing.** `LaneOptions.ModCache` / `.GovulnDB` are declared
   (`internal/research/deterministic.go:40-41`) and populated by the CLI
   (`cmd/izyan/research.go:128-129`) but never passed into the evidence
   `SessionConfig`, so the research lane has been running without the frozen
   govulndb/module cache (`run_govulncheck` UNSUPPORTED, `go list -deps`
   ERROR under `GOPROXY=off` on a vendored, non-tidy snapshot).
3. **No offline closure capability.** Nothing derives build-closure membership
   from `vendor/modules.txt` plus source imports when `go list` cannot run.

Rejected alternative: deriving a plan-bearing answer without a live model call
would test the executor but not demonstrate that the research agent
independently formulated a falsifier — calling that the capability
demonstration would be self-deception.

Future route, in order (each item becomes backlog work, not this slice):
fix the option plumbing with strict-session regression tests; implement the
bounded vendor/source closure deriver in `internal/affected` (evidence
execution in `internal/evidencetools`, interpretation only in
`internal/research`), fail-closed on every unsupported shape; then run exactly
one live C02 agent turn whose answer contains a valid verification plan, and
replay it once for reproducibility. Full-corpus validation is deferred to
that follow-up gate.

Changes applied to this file: Gate A observable check and Task 1 acceptance;
Task 7 Step 3 outcomes and acceptance (two distinct outcomes); Task 8 backlog
rows (B32/B40/B41 plus the research option-plumbing row) and `eval/README.md`
wording; Task 9 retitled and rescoped to the capability-gap outcome; the
stale "C02 falls back to C01" assumption replaced.

# Autonomous Evidence Slice Implementation Plan

**Preferred path:** `docs/dev/plans/2026-10-14-03-autonomous-evidence-slice-plan.md`

**Goal:** Add the smallest agent-led research slice that independently verifies at least one substantive negative falsifier, preserves a positive and an insufficient-data control, and emits a ticket-ready evidence justification without integrating Shadow into old `analyze` or enabling auto-close.

**Architecture:** Keep `internal/research` as the research owner. The agent emits a typed research/falsifier proposal and bounded check requests. `internal/evidencetools` executes only those typed checks in the existing confined session. A deterministic adapter validates advisory binding, necessity/completeness, scope and bypasses, then reuses existing falsifier/negative-verification/verdict semantics where they fit. Agent category/reasoning never becomes a verdict by itself. The report carries an evidence-based decision separately from the fixed `REVIEW_REQUIRED`/`AutoClose=false` disposition.

**Tech stack:** Go; existing `internal/research`, `internal/evidencetools`, `internal/domain`, `internal/evaluator`, `internal/goanalysis`; CLI `cmd/izyan`; focused `go test -run`; final `gofmt`, `go vet ./...`, `go test ./...`, and one final corpus validation.

**Spec:** `docs/dev/specs/2026-10-14-Izyan-Autonomous-Evid.md`

## Global Constraints

- Coding-agent remains the main researcher. Do not return research control to old `internal/states`/`cmd/izyan analyze` workflow.
- Do not integrate this lane into old `analyze` in this slice.
- No universal Proof Engine, Event Store, new agent platform, per-role LLM ablation, full VEX-Bench run, or auto-close.
- Preserve raw agent answers, attempt/harness provenance, deterministic observations, evidence references, unknowns, limitations and replayability.
- `NOT_AFFECTED` may only be produced from a deterministic applicability chain.
- `NO_EXPLOIT_PATH_FOUND` requires an independently re-derived falsifier, complete/closed scope, coverage of the asserted subject set, `NegativeVerification=VERIFIED`, and no unresolved dynamic/partial-scope blocker.
- `EXPLOITABLE` requires independently supported positive conditions and no unresolved required subject or coverage blocker. If this cannot be established, return `INCONCLUSIVE`, never a forced positive or negative.
- An existing evidence ID, successful tool call, `OK+empty`, `PARTIAL`, LLM agreement or agent category is not proof.
- Agent locus exclusions remain proposals until independent necessity/scope/completeness verification accepts them. Agent mandatory conditions require advisory binding, necessity, completeness and deterministic evaluability.
- Do not use the old `internal/llm/agent.go:acceptClaim` rule (TRUE/FALSE on existence of any evidence ID) in the new lane.
- New report statuses must be derived from actual authoritative facts/evidence. Never reproduce `internal/report/report.go:2395-2424` default statuses or fixed `EV-006`/`EV-008`/`EV-009` references.
- Private source snapshots, raw tracker exports, unit identifiers and absolute paths remain outside the repository. Committed text uses `C01`… labels and `<VA_TMP>`, `<VA_REPO>`, `<PRIVATE_LABEL_MAP>` placeholders.
- Intermediate verification uses only focused tests (`go test -run <Name> ./...`) and point cases. Do not run full corpora until the final validation task, exactly once.
- Functional changes update `docs/dev/gap-analysis.md`; observable analyzer/report behavior updates `eval/README.md`.

## Review Focus

- **Agent authority:** proposals/assertions are never authoritative without independent checks.
- **Advisory binding:** mechanism, root cause, condition and falsifier must bind to an affected advisory entry; an agent-named unbound component remains `UNKNOWN`.
- **Closed scope:** `COMPLETE` must mean a named closed scope with no skipped packages, truncation, errors or unresolved dynamic dispatch. `PARTIAL`/`UNKNOWN` cannot ground a negative.
- **Negative proof:** verify the falsifier from persisted typed evidence, not from the agent assertion or evaluator pre-filled `NegativeVerification`. Reuse `goanalysis.Verifier` for supported shapes; do not self-certify.
- **Positive safety:** the positive control must never become a safe negative merely because the agent proposed `code_not_reachable`.
- **Unknown safety:** the missing release toolchain or other unresolved material fact must remain `INCONCLUSIVE` with a concrete follow-up.
- **Human report:** every decision shows hypothesis, falsifier, checks, evidence references, scope/coverage, sufficiency reason, limitations, and ticket rationale. No bare `UNKNOWN`.
- **Replay:** live agent and replayed agent turns produce equivalent decision inputs; replay must not call the model.

## Entry gates

### Gate A: frozen case matrix

Create only a local/gitignored manifest under `<VA_TMP>/autonomous-evidence-slice/case-matrix.json`. It maps anonymous `C01`… labels to immutable snapshot content hash, advisory path/hash, saved agent/deterministic artifact directories, and expected *proof role*—not a trusted verdict.

The verified starting matrix is:

| Case | Role | Source and proof route |
|---|---|---|
| C01 | substantive negative candidate: input guard/mechanism | Corporate rejected snapshot hash `affff1b53bfc2aa57fd224d619233f9d604191c7f594da8cf9c7454f2e55fc08`; advisory `GHSA-rm6m-hrcw-jw33`; saved run under `<VA_TMP>/agent7-corp/runs/<C01>/`; agent hypothesis is negative prefetch values clamped before one `Qos` call. Promote only if targeted sink/flow/guard checks and structured negative verification close the scope; otherwise `INCONCLUSIVE`. |
| C02 | substantive negative candidate: product build-closure absence | Same corporate snapshot hash; advisory `GHSA-pxq6-2prw-chj9`; saved run under `<VA_TMP>/agent7-corp/runs/<C02>/`; product source uses Docker SDK only in test scope while advisory is daemon-side. Promote only after complete product build closure is available; current saved run records `go list`/module-cache failure. |
| C03 | exploitable positive control | Saved exploitable snapshot hash `502d9373b0e7f9b411e5ae4842c675d9d90be22efb08e6acff77a1c546a0cdce`; advisory `GO-2026-6355`; saved run under `<VA_TMP>/exploitable/runs/<C03>/`; deterministic lane records affected/reachable `x/crypto/ssh` use while the agent proposed non-reachability. Pin the package-version discrepancy in the local manifest before running. |
| C04 | genuine insufficient-data control | Same corporate snapshot family; advisory `GO-2026-5942`; saved run under `<VA_TMP>/agent7-corp/runs/<C04>/`; release toolchain is empty, stdlib applicability cannot be resolved, and build/tool calls are incomplete/unsupported. Expected result is `INCONCLUSIVE`. |

The private manifest may contain the real unit IDs and paths; the committed plan and reports may not. The corporate raw sets contain 85 safe and 35 exploitable records, but historical `triage_result` and rationale are selection inputs only, not proof. Exclude cancelled records and the fix-only rationale.

**Observable gate check:** for each entry, verify the snapshot content hash, advisory digest, saved raw agent answer, deterministic facts and observations exist; verify C03's resolved version is consistent across the selected artifacts; and verify that C02 is a reproducible negative candidate whose required proof route and current capability status are explicitly recorded. Do not infer proof-route availability from historical labels, source shape, `vendor/modules.txt` presence, or a saved agent hypothesis.

If C02 lacks a closed product build-closure capability, set `first_negative_target=C02`, stop at Task 7, and record the exact missing capability. C01 MUST NOT be substituted. Gate A freezes the case matrix; it does not assert that the Task 7 capability demonstration will succeed. *(2026-10-14 amendment R2 — the slice actually stopped here; see the amendment log.)*

### Gate B: first-slice proof rule

The implementation must be able to say, for any candidate negative:

1. **Re-derivation:** a deterministic verifier recomputed the falsifier from typed observations/source facts; it did not trust the agent category, prose or an evaluator-pre-filled `NegativeVerification`.
2. **Closed scope:** the verification records exact module/package/symbol/build context and complete coverage. For C02 this is a complete product-vs-test build closure/package-absence proof; for C01 it is a complete sink/flow/guard scope plus structured bound exclusion if the candidate is promoted.
3. **Coverage:** the falsifier covers the authoritative advisory-bound subject set and does not leave unresolved subjects, dynamic markers or partial tool scopes.

**Observable gate check:** a unit fixture with one missing evidence reference, one `PARTIAL` observation, one advisory-scope mismatch and one dynamic marker must all return `INCONCLUSIVE` or `INSUFFICIENT_SCOPE`; only a complete, exact-bound fixture may return `NO_EXPLOIT_PATH_FOUND`.

### Gate C: ticket-ready report contract

The first-slice report must contain, for every decision:

- agent hypothesis and raw-answer provenance;
- concrete falsifier and condition it addresses;
- checks performed and their actual tool status;
- evidence IDs/observation IDs and exact scope/coverage;
- why the evidence is sufficient—or the precise blocker;
- final `NOT_AFFECTED`, `NO_EXPLOIT_PATH_FOUND`, `EXPLOITABLE` or `INCONCLUSIVE` decision;
- ticket rationale suitable for copy/paste;
- no auto-close and no claim that an agent assertion is independently verified.

**Observable gate check:** render a negative, positive and unknown fixture and assert the Markdown/JSON contains only actual evidence refs, explicit scope/limitations and a concrete follow-up for unknown; assert no fixed legacy evidence IDs are emitted when absent.

### Task 1: Freeze and validate the anonymous case matrix

**Depends on:** None

**Files:**
- Create outside repository: `<VA_TMP>/autonomous-evidence-slice/case-matrix.json`
- Read-only inputs: `<VA_TMP>/agent7-corp/...`, `<VA_TMP>/exploitable/...`, `eval/advisories/reviewed/...`, `eval/agent7/prompts/...`
- Do not create a committed case file containing private identifiers.

**Interfaces:**
- Consumes: saved snapshot directories, advisory bytes, agent answer artifacts, deterministic facts/observations and manifests.
- Produces: anonymous case records `{id, role, snapshot_root, snapshot_hash, advisory_file, advisory_sha256, agent_run, deterministic_run, proof_route, blockers}` in the local manifest.

- [ ] Step 1: Materialize C01–C04 from the saved artifacts using the private map; exclude cancelled/fix-only records.
- [ ] Step 2: Record immutable snapshot/advisory/agent/deterministic digests and pin C03's resolved-version discrepancy for resolution.
- [ ] Step 3: Verify C01/C02 proof-route feasibility without treating historical tracker labels as evidence; select the first negative target using the Gate A rule.
- [ ] Step 4: Validate the manifest shape and absence of private identifiers from any future committed text:
  ```bash
  python3 -c 'import json,sys; p=json.load(open(sys.argv[1])); assert [x["id"] for x in p["cases"]]==["C01","C02","C03","C04"]; assert {x["role"] for x in p["cases"]} >= {"negative","positive","unknown"}; assert all(x.get("snapshot_hash") and x.get("advisory_sha256") for x in p["cases"])' <VA_TMP>/autonomous-evidence-slice/case-matrix.json
  ```

**Acceptance:** Four immutable, anonymous case records exist; C03 is version-consistent or explicitly blocked; C04 has a concrete unknown; and at least one negative candidate is identified with either a generic closed-scope route or an explicit recorded capability gap. A capability gap blocks the Task 7 success criterion and MUST NOT be converted into a fake successful demonstration.

**Verification:** Manifest inspection only; no Go test/build/corpus command. The local manifest remains outside the repository.

**Out of scope:** changing prompts, production analyzers, old report/risk layers, tracker data or ground-truth labels.

### Task 2: Add typed agent falsifier and verification-plan proposals

**Depends on:** Task 1

**Files:**
- Modify: `internal/research/types.go`
- Modify: `internal/research/agent.go`
- Modify: `eval/agent7/prompts/r0-v1.txt` (and the fallback pinned prompt only if the CLI selects it)
- Test: `internal/research/agent_test.go` or a new focused `internal/research/proposal_test.go`

**Interfaces:**
- Consumes: existing `agentAnswer{category, reasoning, assessment}`, retained raw answer and attempt artifacts.
- Produces:
  ```go
  type FalsifierProposal struct {
      Kind        domain.FalsifierKind `json:"kind"`
      ConditionID string               `json:"condition_id"`
      Module      string               `json:"module,omitempty"`
      Package     string               `json:"package,omitempty"`
      Symbol      string               `json:"symbol,omitempty"`
      ArgIndex    int                  `json:"arg_index,omitempty"`
      Statement   string               `json:"statement"`
      Scope       string               `json:"scope"`
  }

  type VerificationRequest struct {
      ID         string          `json:"id"`
      Tool       string          `json:"tool"`
      Arguments  json.RawMessage `json:"arguments"`
      Purpose    string          `json:"purpose"`
      ConditionID string        `json:"condition_id"`
  }

  type VerificationPlan struct {
      Falsifier FalsifierProposal   `json:"falsifier"`
      Checks    []VerificationRequest `json:"checks"`
  }
  ```
  Add optional `VerificationPlan *VerificationPlan` to the parsed agent answer. Keep it a proposal; it cannot contain or set `NegativeVerification`, a final verdict, or an authoritative claim.

- [ ] Step 1: Add parser tests for a valid plan, absent plan, malformed plan, unknown falsifier kind, empty condition/subject and over-budget check list.
- [ ] Step 2: Update the generic pinned prompt to request at most 8 typed checks from the existing evidence-tool catalog, with tool name/JSON args/purpose/condition ID. State explicitly that the plan is a hypothesis and that `PARTIAL`, `UNKNOWN`, `ERROR`, `TIMEOUT`, `UNSUPPORTED` and empty partial results never prove safety.
- [ ] Step 3: Validate request names/argument JSON and reject unsupported tools or requests outside the session's snapshot/advisory roots before execution.
- [ ] Step 4: Preserve the exact raw answer and source selector in the existing attempt artifacts; never rewrite it into a verdict.
- [ ] Step 5: Run:
  ```bash
  go test -run 'Test(AgentAnswer|VerificationPlan|FalsifierProposal)' ./internal/research
  ```

**Acceptance:** A generic agent answer can propose C01/C02-style checks; malformed, unbound or over-budget plans remain non-authoritative and are recorded as limitations; existing answer replay still parses.

**Out of scope:** executing requests, deciding claims/verdicts, adding case-specific prompt text, changing old `internal/llm`, or enabling auto-close.

### Task 3: Execute bounded verification plans through the existing confined evidence session

**Depends on:** Task 2

**Files:**
- Modify: `internal/evidencetools/mcp.go` or add `internal/evidencetools/call.go` for the smallest public typed-call adapter.
- Modify: `internal/research/deterministic.go` to factor the current in-memory MCP session lifetime into a reusable verification handle without changing the fixed deterministic observation order.
- Create/modify: `internal/research/verification.go`
- Test: `internal/evidencetools/*_test.go`, `internal/research/verification_test.go`

**Interfaces:**
  ```go
  type EvidenceCallFunc func(ctx context.Context, tool string, args json.RawMessage) (*evidencetools.Observation, error)

  type VerificationTrace struct {
      Requests      []VerificationRequest
      Observations  []*evidencetools.Observation
      Limitations   []string
      Complete      bool
  }

  func RunVerificationPlan(ctx context.Context, call EvidenceCallFunc, plan VerificationPlan, maxCalls int) (*VerificationTrace, error)
  ```
  The CLI supplies `EvidenceCallFunc` over the already-created strict confined MCP session/client. Do not create a second unconfined tool path. Existing session audit records remain authoritative for tool execution provenance.

- [ ] Step 1: Factor session/client creation so `RunDeterministic` can keep a strict session available through agent replay/turn and the bounded verification phase, then close it exactly once.
- [ ] Step 2: Implement request execution in declared order with a hard cap of 8 calls for this slice; record skipped requests and tool errors as limitations rather than retrying indefinitely.
- [ ] Step 3: Require returned observation ID, tool status, completeness, scope details, build context and evidence refs to remain attached to the trace. An empty result is never promoted without the observation's closed scope.
- [ ] Step 4: Test `COMPLETE` closed observations, `PARTIAL` empty observations, `ERROR`, `TIMEOUT`, `UNSUPPORTED`, invalid tool names, invalid arguments, traversal/scope rejection and cap exhaustion.
- [ ] Step 5: Run:
  ```bash
  go test -run 'Test(VerificationPlan|EvidenceCall|ObservationScope|ToolRequest)' ./internal/research ./internal/evidencetools
  ```

**Acceptance:** Agent-requested checks execute only inside the existing strict session, all outputs are auditable and replayable, and every degraded/partial result is visible to the later decision function.

**Out of scope:** verdicts, proof acceptance, new tool families, live model calls in tests, `run_build`/`run_tests` and old workflow integration.

### Task 4: Implement independent falsifier verification and deterministic decision projection

**Depends on:** Task 3

**Files:**
- Create: `internal/research/decision.go`
- Modify: `internal/research/types.go` for the decision/proof wire types.
- Reuse without changing authority: `internal/domain`, `internal/evaluator/verdict.go`, `internal/goanalysis/negative.go`, `internal/goanalysis/locusverify.go`, `internal/research/validate.go`.
- If C01 is selected as the first negative target: modify `internal/goanalysis/negative.go` and relevant evaluator tests only to add structured bound verification inside `verifyGuardFalse`; do not accept the existing prose-only `verifyBound` note as proof.
- Test: `internal/research/decision_test.go`, plus focused `internal/goanalysis`/`internal/evaluator` tests if the guard branch is used.

**Interfaces:**
  ```go
  type EvidenceDecision struct {
      Verdict               domain.Verdict                  `json:"verdict"`
      Reason                string                          `json:"reason"`
      ConditionID           string                          `json:"condition_id,omitempty"`
      Falsifier             domain.FalsifierKind            `json:"falsifier,omitempty"`
      NegativeVerification  *domain.NegativeVerification   `json:"negative_verification,omitempty"`
      EvidenceRefs          []string                        `json:"evidence_refs,omitempty"`
      Scope                 string                          `json:"scope"`
      Coverage              string                          `json:"coverage"`
      Limitations           []string                        `json:"limitations,omitempty"`
      HumanQuestions        []string                        `json:"human_questions,omitempty"`
      TicketRationale       string                          `json:"ticket_rationale"`
  }

  type DecisionInput struct {
      Lane          *LaneResult
      Proposal      *FalsifierProposal
      Trace         *VerificationTrace
      AgentTurn     *AgentTurn
      Source        *goanalysis.Index
  }

  func VerifyDecision(ctx context.Context, in DecisionInput) (EvidenceDecision, error)
  ```

- [ ] Step 1: Validate advisory binding. The proposal's module/package/symbol must match an affected advisory entry at the level asserted. If it names an unbound component, return `INCONCLUSIVE` with `advisory_scope_gap` and a concrete follow-up; never analyze that component as this CVE.
- [ ] Step 2: Validate proposal semantics before proof: mandatory condition must be necessary for the named mechanism, complete for the asserted subject set, and supported by a deterministic rule. If necessity cannot be independently established, return `INCONCLUSIVE`; do not copy the agent condition into an authoritative model.
  **Advisory-wide subject coverage (2026-10-14 amendment).** Build the required subject set from **every affected entry of the frozen advisory** — entry ID, module, package, declared symbol — using the existing candidate projection (`internal/research/deterministic.go:1145-1208`); module-only entries keep a module-level subject for the build-closure route (`internal/research/deterministic.go:1267-1341`). The set never comes from the agent's selected subject, `selected_modules`, or whichever entry matched the binding check. Every subject must be either independently covered by the accepted C02 falsifier or explicitly resolved by deterministic applicability evidence as outside the asserted negative scope; otherwise `INCONCLUSIVE`, naming each unresolved subject with its advisory entry ID, identity (module/package/symbol), blocker (`not evaluated` / `partial` / `dynamic` / `unsupported` / applicability unresolved) and concrete follow-up.
- [ ] Step 3: Implement the first generic negative rule for C02-style product absence/build closure. Accept only a complete product-side build closure—or an equivalent closed fact that directly proves the advisory-bound package is absent from that closure—bound to every required advisory subject; never derive package absence from a `PACKAGE_USAGE` product-source non-use result (`NOT_USED`), including when `present: true`. No skipped packages, tool errors, unresolved dynamic scope or build-context mismatch. Translate it to `domain.Claim{Result: FALSE, Falsifier: FalsifierPackageAbsent}` and independently verified `NegativeVerification{Status: VERIFIED}`; then reuse `evaluator.VerdictEvaluator` for the terminal result. Do not treat the B41 `usage-scope` fact alone as a global safety conclusion; require exact advisory binding, full subject coverage and the paired product-absence verification.
- [ ] Step 4: **Do not promote the C01 guard/bound falsifier in this slice (2026-10-14 ruling, option b).** Any `FalsifierGuards` proposal — including structured or pre-filled `GuardVerification` — returns `INCONCLUSIVE` with `guard_verification_capability_missing` and a concrete follow-up: add a tool-backed complete sink/flow/guard/bound observation and an adapter that reconstructs the corresponding evidence graph and re-runs `goanalysis.Verifier`. Agent booleans, unverified bound fields, `DecisionInput.Source` and pre-filled `NegativeVerification` are non-authoritative; `GuardVerification`/`DecisionInput.Source` must not be part of an accepted proof contract for this slice. Rationale: `find_validations` always returns `CompletenessPartial` and states that guard absence is not proof (`internal/evidencetools/dataflow.go:138-154`), while the real verifier needs actual `EvidenceGraph.DataFlows`/`Validations` (`internal/goanalysis/negative.go:819-930`).
- [ ] Step 5: Reject all agent-only negative categories, existing-evidence-ID-only claims, `TrustedPeer`/perimeter self-certification, fixed-version prose and partial observations as proof.
  **Trace integrity (2026-10-14 amendment).** A terminal negative additionally requires the trace to bind: each observation to its request (matching tool and condition id), a populated `snapshot_hash` and non-empty build context, the coverage rule where the route depends on it, syntactically valid evidence references, and empty trace `Limitations`. A forged, replayed or inconsistent trace must fail closed.
- [ ] Step 6: For C03, deterministic reachability/use evidence must prevent a negative promotion. Return `EXPLOITABLE` only if every required positive condition is independently complete; otherwise return `INCONCLUSIVE`. For C04, unresolved release toolchain must force `INCONCLUSIVE` and name the missing `--release-go-version`/binary fact. Never return a safe verdict for either control.
- [ ] Step 7: Test at minimum:
  - complete C02 package/build absence → `NO_EXPLOIT_PATH_FOUND` with `FalsifierPackageAbsent` and `VERIFIED`;
  - same evidence with `PARTIAL`, an error, a skipped package, wrong advisory entry or unresolved subject → `INCONCLUSIVE`;
  - C03 reachability-positive evidence plus agent non-reachability assertion → not safe (`EXPLOITABLE` or `INCONCLUSIVE` only);
  - C04 unknown release toolchain → `INCONCLUSIVE`;
  - C01 guard evidence → must stay `INCONCLUSIVE` in this slice, including synthetic, boolean-only, self-authenticating, partial and pre-filled payloads; assert the fail-closed reason `guard_verification_capability_missing` (do not require or accept a C01 negative demonstration);
  - malformed/missing evidence references → `INCONCLUSIVE`.
- [ ] Step 8: Run (always `-count=1`; a cached `ok` previously masked a broken tree, and a `-run` pattern that matches nothing must not be reported as a pass):
  ```bash
  go test -count=1 -v -run 'Test(VerifyDecision|Falsifier|PackageAbsence|GuardBound|AdvisoryBinding|PositiveControl|UnknownControl)' ./internal/research ./internal/goanalysis ./internal/evaluator
  ```

**Acceptance:** No agent category can produce a terminal verdict. The C02 package/build-closure absence route is the only negative proof family in this slice: it must be generic and independently verified, bound to every advisory subject, and guard-based C01 negatives are out of scope and must fail closed with `guard_verification_capability_missing`. All partial/unknown/dynamic/incomplete variants fail closed.

**Out of scope:** a universal condition-necessity solver, all vulnerability classes, perimeter/config/protocol-role proof families, old `states.NegativeCheck` semantics, and auto-close.

### Task 5: Add the evidence-based decision and ticket rationale to the research report

**Depends on:** Task 4

**Files:**
- Modify: `internal/research/types.go` (`Report`, schema/version constants, `Disposition` comments).
- Modify: `internal/research/assemble.go` to consume `EvidenceDecision` without promoting agent assertions.
- Modify: `internal/research/render.go` for JSON/Markdown decision and ticket rationale sections.
- Modify: `internal/research/validate.go` for decision invariants and legacy report compatibility.
- Test: `internal/research/decision_report_test.go`, `internal/research/validate_test.go`, `internal/research/render_test.go`.

**Interfaces:**
- Add `Decision *EvidenceDecision` to the report contract. Because the current top-level member set is closed and `research-report/1` is already emitted, publish new reports as `research-report/2`; keep `/1` parsing/validation/rendering unchanged for replayed historical reports.
- Keep `Disposition{Class:"REVIEW_REQUIRED", AutoClose:false}` in this slice. `Decision.Verdict` records the independently verified evidence-based result; it does not authorize auto-close.
- Decision fields must include actual evidence refs, `Scope`, `Coverage`, `Falsifier`, `NegativeVerification`, `Limitations`, `HumanQuestions` and `TicketRationale`.

- [ ] Step 1: Add schema-v2 decision serialization and legacy `/1` compatibility tests.
- [ ] Step 2: Validate `NO_EXPLOIT_PATH_FOUND` only when falsifier is recognized, negative verification is `VERIFIED`, evidence refs resolve to deterministic verification observations/facts, coverage is closed and no blocker remains.
- [ ] Step 3: Validate `EXPLOITABLE` only when all required conditions are complete and positive; otherwise reject/demote to `INCONCLUSIVE`.
- [ ] Step 4: Validate all `INCONCLUSIVE` decisions have at least one concrete unknown/question and follow-up. Preserve unknowns from the original lane and agent assessment.
- [ ] Step 5: Render an inverted-pyramid report section before detailed evidence:
  - decision and explicit "no auto-close" note;
  - agent hypothesis;
  - concrete falsifier/condition;
  - checks actually executed and status;
  - evidence refs plus exact scope/coverage;
  - sufficiency proof or blocker;
  - ticket-ready rationale.
- [ ] Step 6: Add tests proving that absent evidence does not render default red/green statuses and no fixed legacy IDs are emitted. Test a decision with no call path as `UNKNOWN`, not "not reachable", when the relevant tool did not run.
- [ ] Step 7: Run:
  ```bash
  go test -run 'Test(DecisionReport|ResearchReportV2|LegacyReportV1|Render.*Decision|NoDefaultEvidence)' ./internal/research
  ```

**Acceptance:** `report.json` and `report.md` are self-contained and ticket-ready; a verified negative is visibly distinguished from agent hypothesis and from `REVIEW_REQUIRED`/no-auto-close disposition; unknowns are actionable.

**Out of scope:** changing `internal/report`/OpenVEX, changing old `risk.Assess`, tracker mutation, auto-close and bilingual old `analyze` reports.

### Task 6: Wire the new decision path into `izyan research` only

**Depends on:** Tasks 3–5

**Files:**
- Modify: `cmd/izyan/research.go`
- Modify: `internal/research/deterministic.go` session-lifetime helper as needed.
- Modify: `internal/research/assemble.go` input to accept verification trace and decision.
- Test: `cmd/izyan/research_decision_test.go`, `internal/research/replay_test.go`.

**Interfaces:**
- `runResearch` must execute: deterministic lane → one live/replayed agent turn → bounded typed verification plan → `VerifyDecision` → `Assemble`/render.
- Replay path must use `--replay-agent-turn` and execute no model/harness call; verification uses the retained plan from the saved answer.
- The existing strict confined session/client remains the only evidence execution path. Close it exactly once after verification and report assembly.

- [ ] Step 1: Factor the current `RunDeterministic` session setup so the strict session can remain available for post-agent checks without changing fixed deterministic fact order or output artifacts.
- [ ] Step 2: In `runResearch`, execute `RunVerificationPlan` only when an agent/replay answer contains a valid plan; otherwise produce an `INCONCLUSIVE` decision explaining no independently verified falsifier was proposed.
- [ ] Step 3: Append verification observations/audit records to new sibling artifacts under the output directory (for example `verification-observations.jsonl` and `verification-facts.json`) without rewriting original deterministic or agent artifacts.
- [ ] Step 4: Pass `EvidenceDecision` into `research.Assemble`, write `report.json`, `report.md`, `run-manifest.json`, validate the report, and retain `AutoClose=false`.
- [ ] Step 5: Test CLI wiring with injected/replayed fixtures; assert no old `internal/states`/`internal/report` workflow is constructed.
- [ ] Step 6: Run:
  ```bash
  go test -run 'Test(ResearchDecisionCLI|ResearchReplayDecision|NoAnalyzeIntegration|VerificationArtifacts)' ./cmd/izyan ./internal/research
  ```

**Acceptance:** `izyan research` is the only changed entry point; old `izyan analyze` behavior and wiring are untouched; replay is deterministic and no raw artifacts are lost.

**Out of scope:** adding new `analyze` flags, integrating with `internal/states`, modifying `cmd/izyan/main.go`'s old analyze composition, tracker API writes, VEX export or auto-close.

### Task 7: Capability demonstration on C01–C04

**Depends on:** Task 6 and Gate A

**Files:**
- Create only outside repository: `<VA_TMP>/autonomous-evidence-slice/runs/C01` … `C04`.
- Optional committed aggregate: `docs/dev/reports/2026-10-14-03-autonomous-evidence-slice.md` containing only C labels, hashes, metrics and placeholders; no raw/private text.

**Interfaces:** Existing `izyan research` CLI and local case matrix.

- [ ] Step 1: Run each saved case using the pinned advisory/snapshot paths from the private matrix. Use replay for saved agent turns so the demonstration is reproducible and does not call the model:
  ```bash
  go run ./cmd/izyan research \
    --snapshot <VA_TMP>/.../C02/snapshot \
    --cve <C02-CVE-ID> \
    --advisory-file <VA_TMP>/.../C02/advisory.json \
    --output-dir <VA_TMP>/autonomous-evidence-slice/runs/C02 \
    --modcache <VA_TMP>/modcache \
    --govulndb <VA_TMP>/govulndb \
    --replay-agent-turn <VA_TMP>/.../C02/agent-v5
  ```
  Repeat the same command with the matrix values for C01, C03 and C04. The exact private unit IDs are resolved only by the local manifest, never committed.
- [ ] Step 2: Inspect each output's `decision`, `disposition`, `verification-observations.jsonl`, `verification-facts.json`, `report.md`, `run-manifest.json`, original deterministic facts and retained raw answer.
- [ ] Step 3: Require the named capability result:
  - **C02 (required capability target):** success requires `Decision.Verdict=NO_EXPLOIT_PATH_FOUND`, exact `Falsifier`, `NegativeVerification=VERIFIED`, complete scope/coverage, concrete advisory binding over every advisory subject, resolving evidence references, and ticket rationale. If the plan-bearing agent turn, offline product closure, or required option plumbing is unavailable, stop with `CAPABILITY_GAP_RECORDED` and name each missing capability. Do not substitute the guard route and do not force the result to match historical triage.
  - **C03:** never `NO_EXPLOIT_PATH_FOUND` or `NOT_AFFECTED`; `EXPLOITABLE` only with complete positive evidence, otherwise `INCONCLUSIVE`. Retain the reachability-positive fact and remaining question. A no-plan run may retain the shared missing-proposal reason.
  - **C04:** `INCONCLUSIVE`, with the unknown release toolchain and incomplete build/package scope retained in the report. If applicability evaluation is reached, the decision reason MUST name the release-toolchain blocker. No safe verdict.
  - **C01:** `INCONCLUSIVE`. A guard/bound proposal MUST fail closed with `guard_verification_capability_missing`; with no proposal, the shared `no independently verifiable falsifier proposal` reason is correct. Never force historical triage.
- [ ] Step 4: Run the point-case checks only:
  ```bash
  go test -run 'Test(ResearchDecisionCLI|CapabilityReport|PositiveControl|UnknownControl)' ./cmd/izyan ./internal/research
  ```
  and, for any corpus-backed regression needed during development:
  ```bash
  go run ./cmd/izyan eval --corpus eval/corpus-real.json --case <specific-case-id>
  ```

**Acceptance:** There are two explicitly distinct outcomes.

**Success outcome:** one previously `REVIEW_REQUIRED` saved case receives an independently verified negative evidence decision; C03 is not falsely dismissed; C04 remains inconclusive; reports contain sufficient evidence and ticket rationale; and no auto-close occurs.

**Controlled-stop outcome:** if C02 cannot satisfy the success outcome, Task 7 records `CAPABILITY_GAP_RECORDED` with the exact missing plan-bearing turn, offline closure capability, and/or option plumbing. All four reports remain fail-closed, C03 remains non-safe, C04 remains inconclusive, C01 remains out-of-scope, and `AutoClose=false`.

The controlled-stop outcome is an honest capability result, not satisfaction of the specification's independently verified negative-demonstration criterion. Task 8 MUST document the gap, and Task 9 MUST NOT use corpus validation to claim that criterion was met.

**Out of scope:** claiming corpus-wide safety, changing saved answers/artifact bytes, full VEX-Bench, production rollout, real tracker updates and statistical LLM claims.

### Task 8: Documentation and backlog synchronization

**Depends on:** Task 7

**Files:**
- Modify: `docs/dev/gap-analysis.md`
- Modify: `eval/README.md` because `izyan research` now emits a new observable decision/report shape.
- Modify if maintained by repository convention: `docs/dev/implementation-status.md` with the first-slice status and explicit blockers.
- Optional Create: sanitized `docs/dev/reports/2026-10-14-03-autonomous-evidence-slice.md` using only C labels/placeholders.

**Interfaces:** Documentation reflects the implemented slice, not the desired future architecture.

- [ ] Step 1: Update B32, B40 and B41 with the observed capability status. Keep all three rows OPEN. Record that Tasks 2–6 provide the typed proposal, bounded verification, advisory-wide coverage, trace-integrity and no-auto-close contracts, but no real plan-bearing case exercised the verification path to a terminal negative.
  - **B32 outcome:** OPEN — Tasks 2–6 implement the typed proposal, bounded verification, advisory-wide subject coverage, trace-integrity checks and no-auto-close report contract. The real-case capability gate remains unproven: every retained C01–C04 answer predates `verification_plan`, so no real verification trace reached `VerifyDecision`. Close only after a live C02 turn and a generic closed product-closure proof produce an independently verified negative.
  - **B40 outcome:** OPEN — Independent verification is covered by unit and CLI fixtures, but no plan-bearing real case exercised the production verification path. The C02 capability gap remains; fixture success is not evidence of real-case capability or production safety.
  - **B41 outcome:** OPEN — `usage-scope` has the paired-closure contract, but C02's strict offline `go list` path fails on the vendored, non-tidy snapshot and no `vendor/modules.txt`-plus-source-import closure fallback exists. Follow-up: implement and validate a generic, build-context-bound offline closure deriver; fail closed on every unsupported or incomplete source shape.
  - **Research option plumbing outcome:** OPEN — `LaneOptions.ModCache` and `LaneOptions.GovulnDB` are populated by the CLI but are not passed into the strict evidence `SessionConfig`. The follow-up is to wire both roots into the session, preserve strict confinement and environment provenance, and add regression coverage proving that `--modcache` and `--govulndb` affect the actual evidence tools. Assign the repository's next unused B-number.
  - Preserve the Amendment R1 guard/bound gap: a tool-backed complete sink/flow/guard/bound observation plus an adapter that re-runs `goanalysis.Verifier` remains a separate backlog item and is not a C02 substitute.
- [ ] Step 2: Record in `eval/README.md` that `izyan research` emits `research-report/2` with a separate evidence decision and fixed `REVIEW_REQUIRED`/`AutoClose=false` disposition; preserve replay and provenance artifacts; document the C01–C04 controlled-stop outcome; and state that no independently verified real-case negative was demonstrated.
- [ ] Step 3: State explicitly that old `analyze`, old `internal/report` and old `risk` are unchanged and that the research lane remains separate.
- [ ] Step 4: Run a privacy/content check over changed documentation:
  ```bash
  ! grep -R -nE '/Users/|STS-[0-9]+|<corporate-provider-host>|vuln-analyzer/tmp' docs/dev/reports/2026-10-14-03-autonomous-evidence-slice.md docs/dev/gap-analysis.md eval/README.md
  ```

**Acceptance:** Docs describe only observed behavior and remaining limitations, contain no private paths/identifiers, and preserve the distinction between evidence decision and no-auto-close disposition.

**Out of scope:** rewriting the architecture review, changing spec constraints, adding a benchmark-wide claim, or documenting old report/risk cleanup as completed.

### Task 9: Final validation of the delivered capability-gap slice

**Depends on:** Tasks 1–8

This task validates the implemented Tasks 1–6 code and the documented capability-gap outcome. It does not claim that the missing C02 capability was demonstrated.

**Files:** All changed Go/docs files; no new source files beyond the tasks above.

- [ ] Step 1: Format only the exact changed Go files (gofmt does not recurse into directories). If no Go file changed after the controller-verified Task 6 state, do not create a formatting-only diff.
- [ ] Step 2: Run the repository checks applicable to the delivered code and documentation: `go vet ./...`, `go test ./...`, and the documentation/privacy check from Task 8 Step 4.
- [ ] Step 3: Do **not** run `eval/corpus-real.json` or `eval/live-corpus.json` as part of this stopped slice. A corpus run cannot replace the missing live plan-bearing C02 turn and cannot establish the required independently verified negative capability.
- [ ] Step 4: Re-inspect the existing C01–C04 reports, the sanitized capability-gap report, the ledger and the backlog changes. Do not rerun the model, alter saved answers, or reinterpret the controlled stop as a successful demonstration.
- [ ] Step 5: Record the final status as `CAPABILITY_GAP_RECORDED`, with `false-safe=0` for the demonstrated point cases and `AutoClose=false`. Defer full-corpus validation until the reopened follow-up completes the live C02 demonstration.

**Acceptance:** The delivered code and documentation pass their applicable repository/privacy checks; all four point-case reports remain fail-closed; the capability-gap report names the missing plan-bearing turn, offline closure capability and option plumbing; no old `analyze` or auto-close behaviour changes; and the final status explicitly remains `CAPABILITY_GAP_RECORDED`.

This acceptance does not satisfy the specification's real-case independently verified negative criterion. Full corpus validation is a follow-up gate after that criterion is actually exercised.

**Out of scope:** any additional refactor discovered during validation. New gaps enter `docs/dev/gap-analysis.md` rather than expanding this slice.

## Dependency / Execution Order

`Task 1 → Task 2 → Task 3 → Task 4 → Task 5 → Task 6 → Task 7 → Task 8 → Task 9`.

Task 2's parser tests and Task 3's observation-scope tests may be developed in parallel after Task 1, but Task 4 cannot begin until both contracts are fixed. Task 5 report tests may be prepared alongside Task 4 but consume its `EvidenceDecision` interface. Task 7 is the required capability demonstration and is the gate before docs are finalized. Task 9 is the only full-repository/full-corpus validation.

## Assumptions and plan-changing conditions

- **assumed:** private `<VA_TMP>` snapshots, advisory bytes and saved agent artifacts remain available and immutable for the implementation window. If not, use the exact saved-artifact replacement named in Gate A; do not regenerate labels from live tracker data.
- **[INFERENCE]:** the MCP SDK session can be factored into a reusable confined call closure without creating a second execution path. If the SDK cannot support this cleanly, keep the current deterministic run intact and add a narrowly scoped second strict session constructor; do not expose unconfined direct tool calls.
- **assumed:** a complete module cache/build context can be supplied for C02. **Observed 2026-10-14: it cannot** — the `--modcache`/`--govulndb` plumbing is dead (populated by the CLI, never passed into the evidence `SessionConfig`) and no offline vendor-tree closure capability exists, so the slice stopped at Task 7 with `CAPABILITY_GAP_RECORDED` (amendment R2). C01 is not a substitute; the follow-up route is recorded in amendment R2.
- **assumed:** C03's snapshot/version discrepancy can be resolved from its saved manifest before Task 7. If it cannot, replace C03 with another saved exploitable control whose snapshot/advisory/version identity is internally consistent; do not silently merge artifacts from different materializations.
- **assumed:** adding a decision field requires a research-report schema revision because the current top-level contract is closed. If maintainers choose an extension marker instead, preserve `/1` compatibility and apply the same validation rules; do not add an unversioned top-level field.
- **[INFERENCE]:** existing report render/validation helpers can be extended without changing the old `internal/report` package. If not, keep the new decision renderer entirely inside `internal/research` and retain old report behavior.

## Handoff rule

Satisfy the accepted decisions and constraints above. If implementation discovers a fact changing the agent/research boundary, evidence scope, negative-verdict safety, report contract, or any P0/P1 assumption, stop the implementation, record the fact and affected interfaces, and return to design review. Do not hide the deviation in a local refactor.

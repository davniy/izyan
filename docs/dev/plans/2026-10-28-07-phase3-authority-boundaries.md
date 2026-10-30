# Product A Authority-Boundary Repair Implementation Plan (Phase Three)

**Series:** `docs/dev/plans/2026-10-28-05-remaining-architecture-series.md` (order, prerequisites, series-wide invariants).


**Goal:** Remove model- and heuristic-derived authority while retaining independently established positive and negative proofs.

**Architecture:** Keep discovery and nomination channels, but prevent them from mutating the authoritative conjunction, establishing claims or narrowing proof scope. Existing deterministic evaluators and typed witness admission remain the only conclusion-producing paths.

**Tech stack:** Go 1.25; existing workflow states, evidence graph, evaluator/verifier tests, synthetic source fixtures and deterministic corpus tooling.

**Spec:** Governing review §2.3, §3 and §6 Phase 3; prior approach decision.

## Global Constraints

- Apply the series-wide invariants.
- Do not preserve a heuristic positive by weakening witness, necessity or completeness admission.
- An unresolved mechanism must not accidentally become `EXPLOITABLE` because its nominated extra conditions were removed.
- Keep expert input explicit and distinguish it from machine-generated material.
- Use existing gap codes: proof/measurement gaps are analyzer work, not invented external dependencies.
- No Product B benchmark is executed in this phase.

## Review Focus

| Concern | Owning task |
|---|---|
| Reviewer agreement cannot shrink the defect locus | Task 1 |
| Existing evidence ID does not establish TRUE | Task 1 |
| LLM params, additions and review actions cannot change necessity | Task 2 |
| Heuristic removal cannot manufacture a complete conjunction | Task 3 |
| Typed positive witnesses survive; weak fallbacks do not | Task 4 |
| Specialized checker is not globally invoked | Task 5 |
| Lost Product A positives are measured honestly | Task 5 |

### Task 1: Remove non-locus auto-adoption and claim-by-citation authority

**Depends on:** None

**Files:**
- Modify:
  - `internal/domain/domain.go`
  - `internal/states/cveanalysis.go`
  - `internal/states/gap.go`
  - `internal/llm/agent.go`
  - `internal/exploit/builder.go`
  - `internal/eval/eval.go`
  - `internal/research/requested_finding.go`
  - `internal/report/report.go`
  - `cmd/izyan/main.go`
  - `cmd/izyan/eval.go`
  - `eval/corpus-real.json`
  - `docs/cli.md`
- Test:
  - `internal/exploit/locus_test.go`
  - `internal/llm/llm_test.go`
  - `internal/states/states_test.go`
  - `internal/report/report_test.go`

**Interfaces:**
- Consumes:
  - `LocusDecision`, `NonLocusBasis`, `ProposedNonLocus`
  - `ClaimEvaluator.acceptClaim`, `GapAnalysis` deterministic reevaluation
- Produces:
  - Removal of `AcceptLocusProposals` and `--accept-locus-proposals` end to end.
  - `Claim.Proposal ClaimResult` as a non-authoritative recorded nomination.
  - LLM-proposed TRUE leaves `Claim.Result=UNKNOWN`; deterministic reevaluation may establish TRUE from newly collected evidence.
  - Non-locus exclusions are accepted only through the existing explicit expert-input channel. A saved machine-origin decision remains a proposal regardless of its authority label.

- [ ] Step 1: Add `TestLocusMachineProposalNeverShrinks`, `TestVerifiedResearchNeverAutoAcceptsLocus`, `TestAgentExistingEvidenceDoesNotProveClaim` and `TestGapReevaluatesAfterAgentEvidence`. Preserve a separate explicit-expert exclusion test.
- [ ] Step 2: Run:
  ```bash
  go test ./internal/exploit ./internal/llm ./internal/states -run 'Test(LocusMachine|VerifiedResearch|AgentExistingEvidence|GapReevaluates)' -count=1
  ```
  Expected **FAIL**: current paths auto-adopt proposals and accept TRUE from evidence-ID existence.
- [ ] Step 3: Remove flag/schema/caller plumbing and automatic `NonLocusBasis` mutation. Do not replace machine authority with a permissive string allowlist such as `"review"` or `"human"`; retain the explicit input provenance.
- [ ] Step 4: Record model claim nominations separately. Keep proposed FALSE subject to independent negative verification; neither TRUE nor FALSE is established by the citation’s existence. Reevaluate with the deterministic chain after model-driven tools add evidence.
- [ ] Step 5: Rerun the focused command; expected **PASS**. Update affected corpus inputs to remove the obsolete flag, without inserting expert exclusions to preserve old answers.

**Acceptance:** Neither LLM agreement nor a valid evidence ID changes the authoritative locus or claim result.

### Task 2: Make model condition additions and review repairs non-authoritative

**Depends on:** Task 1

**Files:**
- Modify:
  - `internal/domain/domain.go`
  - `internal/llm/exploit.go`
  - `internal/llm/review.go`
  - `internal/states/states.go`
  - `internal/exploit/applicability.go`
  - `internal/exploit/patterns.go`
  - `internal/evaluator/provenance.go`
- Test:
  - `internal/llm/exploit_test.go`
  - `internal/llm/review_test.go`
  - `internal/exploit/patterns_test.go`
  - `internal/evaluator/provenance_bound_test.go`
  - `internal/states/states_test.go`

**Interfaces:**
- Consumes:
  - `ExploitModelBuilder.Build`, `routeProposal`, `RepairAnalysis.Run`
  - Existing deterministic `ValidateConditionApplicability`
- Produces:
  - `ExploitModel.ProposedConditions []Condition`, always non-authoritative.
  - Removal of `fillParams`, `admittedParam` and model-to-mandatory `mergeConditions`.
  - Review actions are nominations; unresolved material condition criticism remains in `PendingConditionReviews`.
  - No new general-purpose condition-necessity admission API.

- [ ] Step 1: Add `TestModelConditionsNeverChangeConjunction`, `TestModelBoundNeverChangesConstraint`, `TestReviewActionAloneCannotDemoteMandatory` and `TestReviewActionAloneCannotPromoteSupporting`. Include an all-TRUE baseline where an LLM adds a mandatory FALSE, and a verified-negative baseline where a reviewer asks to remove its condition.
- [ ] Step 2: Run:
  ```bash
  go test ./internal/llm ./internal/states ./internal/evaluator -run 'Test(ModelConditions|ModelBound|ReviewActionAlone)' -count=1
  ```
  Expected **FAIL**.
- [ ] Step 3: Route both model condition buckets into `ProposedConditions`; preserve proposed descriptions, subjects and params only there. Model-proposed datum/pair symbols may remain nominations, but source existence alone must not establish their semantic role.
- [ ] Step 4: Remove review-only conjunction mutations. A deterministic repair may still apply an independently established applicability mismatch; an empty `ValidateConditionApplicability` result means “no mismatch detected,” not “necessity proved.” Keep unestablished review changes pending.
- [ ] Step 5: Rerun the focused command and:
  ```bash
  go test ./internal/exploit ./internal/evaluator -run 'Test(ValidateConditionApplicability|VerifyBound|ConstViolatesBound)' -count=1
  ```
  Expected **PASS** for genuinely deterministic bounds and applicability checks.

**Acceptance:** LLM-only additions, removals, promotions and parameter filling cannot change the conjunction or its evaluated truth.

### Task 3: Demote keyword, protocol-role and name heuristics to nomination

**Depends on:** Task 2

**Files:**
- Modify:
  - `internal/domain/domain.go`
  - `internal/exploit/classify.go`
  - `internal/exploit/patterns.go`
  - `internal/exploit/builder.go`
  - `internal/exploit/semantics.go`
  - `internal/evaluator/authn.go`
  - `internal/evaluator/transport.go`
  - `internal/evaluator/verdict.go`
  - `internal/finding/project.go`
- Test:
  - `internal/exploit/classify_test.go`
  - `internal/exploit/patterns_test.go`
  - `internal/exploit/builder_test.go`
  - `internal/exploit/defect_semantics_test.go`
  - `internal/evaluator/authn_test.go`
  - `internal/evaluator/transport_test.go`
  - `internal/evaluator/verdict_test.go`

**Interfaces:**
- Consumes:
  - `Classify`, `DetectProtocolRole`, `AdvisoryInputRoute`
  - Existing typed defect semantics and transport witnesses
- Produces:
  - Recorded class/role/route nomination provenance.
  - `ExploitModel.UnresolvedMechanism bool`, blocking an all-TRUE positive when necessary semantic modeling remains unestablished.
  - Keyword/fix-text class selection and all prose-regex route detection are nominations only.
  - Existing source-bound defect-semantics contracts remain admissible only through their existing evidence validation.

- [ ] Step 1: Add `TestKeywordPatternCannotEstablishNecessity`, `TestRegexRouteCannotSetAuthoritativePeerInput`, `TestProtocolRoleNameCannotFalsify`, `TestAuthMiddlewareNameDoesNotProveCoverage` and `TestUnresolvedMechanismBlocksAllTruePositive`.
- [ ] Step 2: Run:
  ```bash
  go test ./internal/exploit ./internal/evaluator -run 'Test(KeywordPattern|RegexRoute|ProtocolRoleName|AuthMiddlewareName|UnresolvedMechanism)' -count=1
  ```
  Expected **FAIL**.
- [ ] Step 3: Keep heuristic outputs for research and diagnostics, but stop using them to replace generic conditions, fill authoritative protocol-role params or establish condition necessity. Retain supported class semantics selected from explicit structured advisory data only where the existing contract justifies that template.
- [ ] Step 4: Remove role-mismatch FALSE and auth-name TRUE paths lacking typed evidence. Unknown per-route auth coverage remains UNKNOWN with `GapMeasurementNotCompleted`. Ensure omitted/defective-check selection still requires the existing source/record/fix-bound grounds, not the check-like name that nominated it.
- [ ] Step 5: Rerun the focused command, then:
  ```bash
  go test ./internal/exploit ./internal/evaluator -run 'Test(DefectSemantics|MissingCall|CheckTrigger|ClassifyCWE|Transport.*Witness)' -count=1
  ```
  Expected **PASS**. An independently verified mandatory falsifier may still decide a negative; unresolved extra modeling alone must not fabricate one.

**Acceptance:** Regex class, prose role and function/field names cannot establish necessity, completeness, TRUE or FALSE.

### Task 4: Remove weak positive fallbacks and re-admit persisted positives

**Depends on:** Task 3

**Files:**
- Modify:
  - `internal/evaluator/conditions.go`
  - `internal/evaluator/transport.go`
  - `internal/evaluator/transport_proof.go`
  - `internal/evaluator/library_input.go`
  - `internal/evaluator/verdict.go`
  - `internal/finding/project.go`
  - `docs/agent-rules/provenance-and-bounds.md`
- Test:
  - `internal/evaluator/conditions_test.go`
  - `internal/evaluator/transport_test.go`
  - `internal/evaluator/library_input_test.go`
  - `internal/evaluator/measurement_admission_test.go`
  - `internal/finding/project_test.go`

**Interfaces:**
- Consumes:
  - `libraryUsageVerdict`
  - `ValidateTransportInput`, `ValidateTransportTrigger`, `admittedLibraryWitness`
  - Exact direct-call and intra-module path evidence
- Produces:
  - Unexported-sink plus module usage returns UNKNOWN with the missing path named.
  - Frame-name/server-role fallbacks cannot establish peer input.
  - Persisted claims using retired weak grounds cannot regain authority at verdict/publication boundaries.

- [ ] Step 1: Add `TestUnexportedSinkModuleUsageIsUnknown`, `TestServerFrameWithoutWitnessIsUnknown`, `TestDirectSubjectCallStillProvesReachability` and `TestPersistedWeakPositiveIsNotReadmitted`.
- [ ] Step 2: Run:
  ```bash
  go test ./internal/evaluator ./internal/finding -run 'Test(UnexportedSink|ServerFrameWithoutWitness|DirectSubjectCall|PersistedWeakPositive)' -count=1
  ```
  Expected **FAIL**.
- [ ] Step 3: Delete the weak TRUE branches. Preserve module usage and frames as observations and explanatory limitations. Continue into bounded origin tracing where applicable; an unsupported trace remains UNKNOWN.
- [ ] Step 4: Require the same typed/direct-path basis when consuming saved positives. Do not trust a saved producer string or TRUE value. Preserve independently admitted library and transport witnesses and exact call paths.
- [ ] Step 5: Rerun the focused command and:
  ```bash
  go test ./internal/evaluator -run 'Test(MeasurementAdmission|LibraryInput|TransportProof|ModuleUsage)' -count=1
  ```
  Expected **PASS** with updated weak-positive expectations.

**Acceptance:** Removing a typed witness cannot fall through to a weaker TRUE; real direct-path and typed-witness positives remain available.

### Task 5: Gate specialized capabilities and measure the authority cutover

**Depends on:** Tasks 1–4

**Files:**
- Create:
  - `internal/goanalysis/transport_applicability.go`
  - `internal/goanalysis/transport_applicability_test.go`
  - `internal/eval/authority_delta.go`
  - `internal/eval/authority_delta_test.go`
- Modify:
  - `internal/states/states.go`
  - `internal/goanalysis/transport_proof.go`
  - `internal/rootcause/prooffix.go`
  - `internal/fixbinding/api.go`
  - `internal/fixbinding/proof.go`
  - `internal/eval/eval.go`
  - `cmd/izyan/eval.go`
  - `cmd/izyan/main.go`
  - `docs/architecture.md`
  - `docs/dev/gap-analysis.md`
  - `eval/README.md`
- Test:
  - `internal/states/transport_proof_test.go`
  - `internal/goanalysis/transport_proof_test.go`
  - `internal/fixbinding/activation_test.go`
  - `cmd/izyan/eval_baseline_test.go`

**Interfaces:**
- Consumes:
  - `TransportProofRequest`, exact record/fix/source bindings
  - `fixbinding.APIIdentity`, supported operation declarations
  - Existing `eval.Result` condition/verdict records
- Produces:
  - `Index.TransportProofRequestFor(...) (domain.TransportProofRequest, bool, error)`: returns applicable only after source-bound mechanism/transport prerequisites are established.
  - No implicit rapid-reset mechanism default in `ProveServerTransport`.
  - Fix proof applicability derived from resolved supported operations in captured material; unsupported material stays an observation/obligation.
  - `CompareAuthorityResults(before, after []Result) (AuthorityDelta, error)` and offline CLI `izyan eval compare --before ... --after ... --out ...`.

- [ ] Step 1: Add `TestUnsupportedTransportNeverInvokesSpecializedProof`, `TestTransportApplicabilityRejectsRoleNomination`, `TestTransportMechanismHasNoDefault`, `TestUnsupportedFixDoesNotInvokeSemanticProof` and `TestAuthorityDeltaKeepsLostPositivesVisible`.
- [ ] Step 2: Run:
  ```bash
  go test ./internal/goanalysis ./internal/states ./internal/fixbinding ./internal/eval -run 'Test(UnsupportedTransport|TransportApplicability|TransportMechanismHasNoDefault|UnsupportedFix|AuthorityDelta)' -count=1
  ```
  Expected **FAIL**.
- [ ] Step 3: Split generic observation/nomination from specialized proof dispatch. The applicability probe may inspect source, record and captured fix material, but cannot use model condition params or regex roles as proof. A refused specialized capability must not block Product B’s independent human investigation.
- [ ] Step 4: Implement offline comparison of matched case/input/build identities, reporting lost/gained definitive positives, negatives, failures and per-condition transitions. Reject unmatched comparisons rather than pretending they measure a delta.
- [ ] Step 5: Rerun the focused command; expected **PASS**. At final integration, perform one paired **Product A-only** measurement using a frozen pre-change executable and the candidate, each corpus once per revision. Use:
  ```bash
  "$IZYAN_BEFORE" eval --corpus eval/corpus-real.json --json "$MEASURE_DIR/before-real.json" -j 1
  "$IZYAN_AFTER"  eval --corpus eval/corpus-real.json --json "$MEASURE_DIR/after-real.json" -j 1
  "$IZYAN_AFTER" eval compare --before "$MEASURE_DIR/before-real.json" --after "$MEASURE_DIR/after-real.json" --out "$MEASURE_DIR/delta-real.json"
  ```
  Apply the same final paired procedure to the configured live corpus. Record expectation failures caused by removed weak positives; change a golden expectation only after tracing it to the removed authority path. Never alter safety labels merely to make the suite green.

**Acceptance:** Specialized proof code runs only after applicability is established, and the final report quantifies authority-related losses without weakening admission.

## Dependency / Execution Order

Task 1 → Task 2 → Task 3 → Task 4 → Task 5.

**Measurement prerequisite:** A matched pre-change executable/result set is required for a before/after claim. If it is unavailable, report that exact comparison as unmeasured; tests and post-change distributions do not substitute for it. This does not block the authority repair itself.

---

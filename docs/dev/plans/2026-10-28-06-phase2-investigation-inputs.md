# Investigation Inputs and Tool Surface Implementation Plan (Phase Two)

**Series:** `docs/dev/plans/2026-10-28-05-remaining-architecture-series.md` (order, prerequisites, series-wide invariants).


**Goal:** Give the Product B investigator the captured vulnerability material and identified build it is investigating, with session-permitted read-only tools and truthful proof-capability feedback.

**Architecture:** Extend the existing Stage 0/material/archive path rather than create another intake pipeline. Capture document bytes once, expose them through bounded read-only material access, pass the canonical product-target DTO into evidence sessions, derive tool availability from session permissions, and remove the automatic deadness-proof route that has no premise producer.

**Tech stack:** Go 1.25; existing JSON/YAML DTOs, `evidencetools` MCP sessions, `fix.ArtifactProvider`, scripted `ChatClient`, temporary-file and `httptest` fixtures.

**Spec:** `docs/dev/reports/2026-10-28-04-architecture-review-human-result.md` §5 and §6 Phase 2; `docs/dev/reports/2026-10-20-06-approach-decision.md`.

## Global Constraints

- Apply the series-wide invariants.
- Keep `assessment.v2`, `decision-package.v3`, `human-decision.v1` and the Phase 1 action/support separation.
- Captured material is untrusted data, never system instructions.
- A partial ticket projection remains partial; supplying it to the agent does not make it an authoritative advisory.
- Advisory aliases may resolve only inside the captured set. A `related` record remains a separate record.
- No agent-accessible network or repository-code execution is introduced.
- **Chosen dead-wire resolution:** remove the automatic Product B kernel-minting route. Do not construct an invocation-necessity premise from advisory symbols or model prose.

## Review Focus

| Concern | Owning tests |
|---|---|
| Agent sees exact supplied advisory/fix bytes, not a remembered vulnerability | Task 1 — captured-material and scripted-run tests |
| Wrong digest, foreign record and traversal fail closed | Task 1 — bundle validation/read tests |
| Product target is not the host | Task 2 — cross-target and missing-target tests |
| Availability follows session permissions | Task 3 — catalog/dispatch parity tests |
| Missing catalog cannot cause an unrepairable proposal loop | Task 4 — no-catalog and supplied-catalog tests |
| Replay does not reconstruct a newer prompt/tool surface | Tasks 1 and 3 — persisted prompt-input tests |

### Task 1: Capture and expose the complete investigation material set

**Depends on:** None

**Files:**
- Create:
  - `internal/productb/triage/investigation_inputs.go`
  - `internal/productb/triage/investigation_inputs_test.go`
- Modify:
  - `internal/productb/triage/stage0.go`
  - `internal/productb/triage/materials.go`
  - `internal/productb/triage/agent_materials.go`
  - `internal/productb/triage/tools.go`
  - `internal/productb/triage/prompt.go`
  - `internal/productb/triage/runner.go`
  - `internal/productb/triage/artifacts.go`
  - `internal/productb/triage/replay.go`
  - `internal/productb/triage/support.go`
  - `internal/productb/domain/dto.go`
  - `internal/productb/registry.go`
  - `internal/productb/typemap.go`
  - `cmd/izyan/triage.go`
- Test:
  - `internal/productb/triage/tools_test.go`
  - `internal/productb/triage/prompt_test.go`
  - `internal/productb/triage/replay_test.go`
  - `internal/productb/triage/support_test.go`
  - `cmd/izyan/triage_cli_test.go`
  - `cmd/izyan/triage_human_result_test.go`

**Interfaces:**
- Consumes:
  - `Stage0Result.Advisory`, `AdvisoryResolution`, `MaterialSet`
  - `fix.ArtifactProvider`, `fix.AcquireAll`, `fix.CapturedProvider`
  - `ReadOnlyTools`, `ObservationStore`, `ArtifactWriter`
- Produces:
  - `InvestigationInputs` containing captured records, captured fixes and optional build input.
  - `CapturedRecord`: record ID, explicit aliases, raw bytes, SHA-256 and partial/source provenance.
  - `CapturedFix`: owning record digest, exact locator, acquisition outcome, digest and complete captured bytes.
  - `LoadInvestigationInputs(path string) (InvestigationInputs, error)` for strict `investigation-inputs.v1` manifests. Referenced files resolve relative to the manifest and require declared digests.
  - CLI `--investigation-inputs <manifest>` for both finding and ticket transports.
  - Read-only `read_material` arguments `{material_id, offset, max_bytes}`.
  - `prompt-input.v1`: exact system text, initial data messages and advertised tool definitions, bound by the existing prompt hash.

- [ ] Step 1: Add `TestInvestigationInputsRejectForeignOrChangedMaterial`, covering duplicate identities with different bytes, wrong digest/size, undeclared fix ownership, traversal and symlink escape. Add `TestReadMaterialReturnsCapturedBytes` and `TestAgentReceivesCapturedAdvisoryAndFixSet`; use two records and two different fix locators.
- [ ] Step 2: Run:
  ```bash
  go test ./internal/productb/triage ./cmd/izyan -run 'Test(InvestigationInputs|ReadMaterial|AgentReceivesCaptured)' -count=1
  ```
  Expected **FAIL**: the captured-set input and material-reading contract do not exist.
- [ ] Step 3: Implement strict loading, Stage 0 inclusion of its selected frozen document, metadata projection and bounded material reading. Preserve complete bytes in digest-addressed run artifacts; transport truncation must not truncate the archived source. A missing fix records its acquisition outcome and does not abort the human investigation.
- [ ] Step 4: Persist `prompt-input.v1` before the first investigator exchange. Replay verifies the persisted prompt input rather than rebuilding it from today’s tool definitions. Keep a history-only reader for existing Phase 1 runs; it must not grant new proof authority. Extend record-scope derivation to all captured records actually considered, without treating them as aliases or a declared CVE corpus.
- [ ] Step 5: Add `TestReplayUsesCapturedPromptAndMaterials` and `TestSupportDoesNotMergeSeparateRecords`; rerun the command above plus:
  ```bash
  go test ./internal/productb/triage -run 'Test(ReplayUsesCapturedPromptAndMaterials|SupportDoesNotMergeSeparateRecords)$' -count=1
  ```
  Expected **PASS**, including after deleting the original material files and installing a network transport that fails on every request.

**Acceptance:** Every supplied advisory/fix is discoverable and readable by the scripted investigator with its exact identity and provenance; replay needs neither the original input paths nor network access.

### Task 2: Carry the identified target and build into every attempt

**Depends on:** Task 1

**Files:**
- Modify:
  - `internal/productb/triage/types.go`
  - `internal/productb/triage/input.go`
  - `internal/productb/triage/investigation_inputs.go`
  - `internal/productb/triage/stage0.go`
  - `internal/productb/triage/agent_materials.go`
  - `internal/productb/triage/artifacts.go`
  - `internal/productb/triage/replay.go`
  - `internal/productb/domain/dto.go`
  - `cmd/izyan/triage.go`
- Test:
  - `internal/productb/triage/input_test.go`
  - `internal/productb/triage/stage0_test.go`
  - `internal/productb/triage/replay_test.go`
  - `cmd/izyan/triage_cli_test.go`
  - Create: `cmd/izyan/triage_target_test.go`

**Interfaces:**
- Consumes:
  - Canonical `domain.ProductTarget`, `ProductTarget.Validate`, `EffectiveBuildContext`
  - Existing `evidencetools.SessionConfig` target, declared-platform, tags, CGO and toolchain fields
- Produces:
  - `Target.Build *domain.ProductTarget`, exposed through the permitted Product B data alias.
  - `Stage0Result.BuildTarget` and the matching persisted Stage 0/material projection.
  - One resolved build selection shared by all stability attempts.
  - `detToolExecutor` passes the resolved target, not `runtime.GOOS/runtime.GOARCH` as product declarations.

- [ ] Step 1: Add `TestTriageTargetOverridesHost`, `TestTriageMissingTargetRemainsAnalysisContext`, `TestTriageTargetConflictRejected` and `TestTriageRetriesKeepBuildIdentity`. Cover Linux/amd64 on a different host, tags, explicit CGO and contradictory finding/bundle declarations.
- [ ] Step 2: Run:
  ```bash
  go test ./cmd/izyan ./internal/productb/triage -run 'TestTriage(Target|MissingTarget|RetriesKeepBuildIdentity)' -count=1
  ```
  Expected **FAIL**: finding target/build provenance is not forwarded.
- [ ] Step 3: Resolve the build from supplied captured/operator input before session construction. Validate source/scope/digest bindings; reject conflicting declarations. Artifact-derived authority must remain tied to its artifact/build-info bytes. Do not promote `go.mod`’s language minimum or the analysis toolchain to release identity.
- [ ] Step 4: Preserve absent target as absent. Evidence tools may record their effective analysis platform, but build-dependent proof admission must continue to reject an unidentified product target. Include the distinction in the agent data message and audit.
- [ ] Step 5: Add `TestReplayPreservesProductTarget`; rerun the focused command and:
  ```bash
  go test ./internal/productb/triage -run '^TestReplayPreservesProductTarget$' -count=1
  ```
  Expected **PASS**.

**Acceptance:** Every attempt and replay describes the same identified build; missing target information remains a visible limitation rather than a host-derived product fact.

### Task 3: Expose the existing read-only capabilities by session permissions

**Depends on:** Tasks 1 and 2

**Files:**
- Modify:
  - `internal/evidencetools/check_specs.go`
  - `internal/evidencetools/mcp.go`
  - `internal/evidencetools/research.go`
  - `internal/productb/triage/binding.go`
  - `internal/productb/triage/detools.go`
  - `internal/productb/triage/replay.go`
  - `cmd/izyan/triage.go`
- Test:
  - `internal/evidencetools/check_specs_test.go`
  - `internal/evidencetools/mcp_test.go`
  - `internal/productb/triage/detools_test.go`
  - `internal/productb/triage/tool_audit_test.go`
  - `cmd/izyan/triage_cli_test.go`

**Interfaces:**
- Consumes:
  - `Session.CheckCatalog`, `CheckSpec`, `CheckCatalog.Validate`
  - Existing `trace_argument`, `field_assignments`, `scan_dynamic`, `interface_dispatch_sites`, `find_dep_callers`, `module_internal_reach`, source-reading and advisory/fix handlers
- Produces:
  - Session-resolved availability and unavailable reason on catalog entries.
  - `CatalogFromCheckCatalog` preserves that availability.
  - `DeterministicTools.Definitions` and `Call` use the same session-resolved catalog, not `detAllowlist`.
  - Captured-only implementations of `vulnerability.Source` and `fix.Provider` for the captured record/fix set.

- [ ] Step 1: Add `TestTriageReadOnlySurfaceFollowsSession`, `TestTriageCannotCallUnadvertisedCapability` and `TestCapturedResearchToolsNeverFetch`. Assert that provenance/configuration/dynamic tools are callable, captured advisory/fix lookup cannot escape the captured set, and repository execution remains unavailable.
- [ ] Step 2: Run:
  ```bash
  go test ./internal/evidencetools ./internal/productb/triage ./cmd/izyan -run 'Test(TriageReadOnlySurface|TriageCannotCall|CapturedResearchTools)' -count=1
  ```
  Expected **FAIL**: the broker’s fixed allowlist hides the tools and captured providers are unwired.
- [ ] Step 3: Remove the broker allowlist. Advertise only available entries, validate every call against the same catalog and retain per-tool deadlines, budgets, audit and observation ownership. Preserve `TIMEOUT` separately from `ERROR`.
- [ ] Step 4: Bind advisory research to every verified captured record regardless of whether acquisition originally came from ticket, local freeze or API. Bind fix research to captured bytes only. Unknown IDs/locators yield unavailable/unsupported results, never a network fallback.
- [ ] Step 5: Run the focused command again; expected **PASS**. Assert that changing current session permissions cannot change a saved run’s recorded prompt/tool surface during replay.

**Acceptance:** Adding an existing read-only capability to the session makes it available to Product B without another allowlist edit; no permission expansion grants proof authority.

### Task 4: Make proposal capability truthful and remove the dead automatic proof wire

**Depends on:** Tasks 1–3

**Files:**
- Modify:
  - `internal/productb/triage/conditioncatalog.go`
  - `internal/productb/triage/tools.go`
  - `internal/productb/triage/prompt.go`
  - `internal/productb/triage/falsifier.go`
  - `internal/productb/triage/unreachability_proof.go`
  - `internal/productb/triage/providers.go`
  - `internal/productb/triage/predicates.go`
  - `cmd/izyan/triage.go`
  - `docs/cli.md`
  - `docs/architecture.md`
  - `docs/dev/gap-analysis.md`
  - `eval/README.md`
- Test:
  - `internal/productb/triage/conditioncatalog_test.go`
  - `internal/productb/triage/prompt_test.go`
  - `internal/productb/triage/factfeedback_test.go`
  - `internal/productb/triage/unreachability_proof_test.go`
  - `internal/productb/triage/kernelparity_test.go`
  - `cmd/izyan/triage_human_result_test.go`

**Interfaces:**
- Consumes:
  - `ConditionCatalog`, `CatalogBinding.CheckCatalog`, `GateFalsifierProposals`
  - `UnreachabilityObservationApproved`, retained for observation/proposal verification
- Produces:
  - `ProposalCapabilities{CatalogHash, Conditions, UnavailableReason}` derived only from a successfully bound supplied catalog.
  - Removal of `runUnreachabilityKernel`, its attempt/retry calls and `mergeFalsifierReport`.
  - Removal of unused automatic-mint APIs `UnreachabilityRequestFor`, `MintUnreachabilityProof` and their request-only helpers after caller migration.
  - `symbol-unreachability` remains a read-only observation capability.

- [ ] Step 1: Add `TestNoCatalogRequiresNoProposalRepair`, `TestPromptUsesOnlyBoundCatalogConditions` and `TestDeadnessObservationDoesNotMintProof`. A complete deadness observation without a semantic premise must still allow a human action, but not a machine reduction.
- [ ] Step 2: Run:
  ```bash
  go test ./internal/productb/triage ./cmd/izyan -run 'Test(NoCatalog|PromptUsesOnlyBoundCatalog|DeadnessObservation)' -count=1
  ```
  Expected **FAIL**: prompt/tool hints still name an advisory-derived condition independently of catalog admission.
- [ ] Step 3: Stop advertising `AdvisoryConditionID` as an admissible condition merely because symbols exist. Show actual catalog IDs/kinds/subjects when bound; otherwise state that machine falsifier proposals are unavailable and optional.
- [ ] Step 4: Remove the dead automatic route and its false promise. Preserve observation validation and actual supplied-catalog admission. Missing catalog/source/premise is not agent-repairable feedback; malformed proposal ownership still is.
- [ ] Step 5: Run the focused command again, then:
  ```bash
  go test ./internal/productb/triage -run 'Test(Falsifier|ConditionCatalog|KernelParity|Unreachability)' -count=1
  ```
  Expected **PASS**. Update documentation to distinguish deadness observation, optional proof request and admitted falsifier.

**Acceptance:** A no-catalog investigation terminates without an impossible repair loop; no nil-premise automatic proof machinery remains.

## Dependency / Execution Order

Task 1 → Task 2 → Task 3 → Task 4.

Phase 2 ships without a model run and makes no recommendation-quality or closure-rate claim.

---

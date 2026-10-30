# Runtime, Registry and Admission Consolidation Implementation Plan (Phase Four)

**Series:** `docs/dev/plans/2026-10-28-05-remaining-architecture-series.md` (order, prerequisites, series-wide invariants).


**Goal:** Leave one live Product B investigator, one capability registry and one human decision projection, while preserving Product A proof and replay boundaries.

**Architecture:** Triage is the sole live human investigator. `internal/research` retains deterministic evidence/proof, canonical adapters, pure validators and historical replay; only obsolete live harness/dispatch is retired. B1 stays frozen. Immutable admission reuse is separate downstream work; replay/publication always freshly admit persisted inputs.

**Tech stack:** Go 1.25; existing CLI routing, MCP catalog, triage archives, research proof tests and Python historical evaluation utilities.

**Spec:** Governing review §5.4 and §6 Phase 4.

## Global Constraints

- Apply the series-wide invariants.
- No new `internal/admissions` package and no `sync.Once`/global cache on `AnalysisCase`.
- Replay and publication always freshly re-admit persisted inputs.
- Preserve frozen evaluation assets and their hashes; do not edit old manifests to make retirement appear historically compatible.
- Historical R5/R6 output may remain readable as history, but is not a current human package or admitted proof.
- Remove obsolete live flags and callers; do not leave no-op compatibility flags.

## Review Focus

| Concern | Owning task |
|---|---|
| One registry controls schemas, permissions, descriptions and costs | Task 1 |
| No second live investigator or semantic human compiler | Task 2 |
| B1 remains frozen, not a competing product runtime | Task 2 |
| Proof/replay code survives overlay removal | Task 2 |
| Admission reuse cannot become stale or mutable | Task 3 |

### Task 1: Consolidate capability and observation metadata

**Depends on:** Phase 2 and Phase 3

**Files:**
- Modify:
  - `internal/evidencetools/check_specs.go`
  - `internal/evidencetools/mcp.go`
  - `internal/evidencetools/observation.go`
  - `internal/productb/triage/binding.go`
  - `internal/productb/triage/detools.go`
  - `internal/productb/triage/tools.go`
  - `internal/productb/triage/observation_archive.go`
  - `internal/productb/triage/tool_audit.go`
  - `internal/productb/triage/replay.go`
  - `internal/productb/verify/registry.go`
- Test:
  - `internal/evidencetools/check_specs_test.go`
  - `internal/evidencetools/mcp_test.go`
  - `internal/productb/triage/detools_test.go`
  - `internal/productb/triage/observation_archive_test.go`
  - `internal/productb/triage/replay_test.go`
  - `internal/productb/verify/verification_test.go`

**Interfaces:**
- Consumes:
  - `checkEntryTable`, `CheckSpec`, session availability from Phase 2
  - Existing `ToolObservation`/`RecordedObservation` archive envelope
- Produces:
  - `CheckSpec` publishes description, permission requirements, repeat/cost bound and observation-contract metadata.
  - Snapshot/material tools and evidence-session tools are composed from one registry contract; handlers may remain in their current packages.
  - Removal of `reachTools`; positive-evidence classification is one registry-associated typed classifier, not a second name allowlist.
  - A canonical observation payload is archived once; display/audit projections reference its digest.

- [ ] Step 1: Add `TestRegistryDefinitionsDispatchParity`, `TestObservationClassificationUsesTypedPayload`, `TestToolContractNeedsOneRegistryEdit` and `TestArchiveDoesNotDuplicateFullPayload`.
- [ ] Step 2: Run:
  ```bash
  go test ./internal/evidencetools ./internal/productb/triage -run 'Test(RegistryDefinitions|ObservationClassification|ToolContractNeeds|ArchiveDoesNot)' -count=1
  ```
  Expected **FAIL**.
- [ ] Step 3: Centralize metadata and derive MCP/triage definitions and limits from it. Keep payload interpretation explicit: marking a tool as potentially producing reachability does not make every successful/empty response positive.
- [ ] Step 4: Remove redundant broker lists and registry-equivalent maps. Keep offline proof-shape validators separate, but test their referenced tool IDs against the canonical registry. Do not turn them into a production universal verifier.
- [ ] Step 5: Rerun the focused command and replay/archive tests; expected **PASS**. A registry change alters new-run pins, not saved-run definitions.

**Acceptance:** One tool contract no longer requires synchronized edits to multiple live allowlists, descriptions or confidence maps.

### Task 2: Superseded by recovery Tasks 8–14

**Do not execute the original deletion instructions.** The original Task 2 report
is historical evidence of the faulty cutover, not a preservation acceptance.
The authoritative replacement is
[`2026-10-28-04-phase1-human-result-plan.md`](2026-10-28-04-phase1-human-result-plan.md)
Tasks 8–14. Correct Task 1 and prior Phase 1–3 repairs stay in place.

Recovery preserves canonical exact-record/requested-finding adapters, pure branch
and proof validators, historical `/3`/`/4`/slice2/flow playback and offline producers.
Do not delete `internal/flow`, historical DTOs/validators or `runner.py` by file
ownership. `flow_driver.go` and the old live model harness remain retired.

Current contracts: `assessment.v3`, `decision-package.v4` with complete bounded
`human_review_plan`, `environment-assertion.v1`, `human-decision.v2`; replay copies
verified review/assertion bytes without new Accept/timestamps. Current research
`/5` publishes `finding.Project` and `requested-case.json` with fresh admission.
`eval research-replay` emits history-only originals, not current authority.
Offline probe/recorded-flow switches remain real; tracked census uses ordinary
`research` and must reject failed/stale/foreign reports. B1 remains eval-only.

**Preservation gate:** `TestHumanCapabilityPreservationMatrix`, focused Python
smoke and actual CLI surface checks precede owner-run integration and unchanged
Product A regression/census gates (`false-safe=0`). Paired authority measurement
requires the exact before/after executables and frozen input/result identity;
an older available binary is not an isolated Phase 3 baseline.



### Task 3: Reuse immutable admission results within evaluation boundaries

**Depends on:** Task 1 plus recovery Tasks 8–14 preservation acceptance and integration-owner gates (not the superseded Task 2 deletion report). Preserve restored canonical adapters and fresh replay/publication admission.

**Files:**
- Modify:
  - `internal/domain/absence_admission.go`
  - `internal/fixbinding/persist.go`
  - `internal/exploit/builder.go`
  - `internal/rootcause/rootcause.go`
  - `internal/evaluator/conditions.go`
  - `internal/evaluator/absence_identity.go`
  - `internal/evaluator/verdict.go`
  - `internal/goanalysis/locusverify.go`
  - `internal/goanalysis/sinkclosure.go`
  - `internal/goanalysis/negative.go`
  - `internal/states/states.go`
  - `internal/research/deterministic.go`
  - `internal/finding/outcome.go`
  - `internal/finding/project.go`
  - `internal/report/report.go`
  - `docs/dev/analysis-internals.md`
- Test:
  - `internal/fixbinding/activation_test.go`
  - `internal/evaluator/absence_identity_test.go`
  - `internal/goanalysis/sinkclosure_test.go`
  - `internal/finding/project_test.go`
  - Create: `internal/domain/absence_immutability_test.go`

**Interfaces:**
- Consumes:
  - `fixbinding.AdmitModelProof`
  - `domain.AdmitAbsence`, `domain.AdmitAbsenceFor`, `domain.AbsenceAdmission`
- Produces:
  - Removal of `fixbinding.AdmitAbsence` and `AdmitAbsenceFor` convenience wrappers that hide repeated proof reconstruction.
  - Explicit `proof *domain.ContentAdmission` parameters on `SinkSetBasis`, `ExploitLocusBindingBasis` and internal locus/sink verification helpers.
  - One content admission per unchanged model/input scope, passed explicitly to absence constructors and consumers.
  - `AbsenceAdmission.Cover` returns a defensive projection; callers cannot mutate the admission’s internal cover through the returned pointer.

- [ ] Step 1: Add `TestAbsenceAdmissionCannotBeMutatedThroughCover`, `TestAdmissionReuseMatchesFreshDerivation`, `TestChangedProofRequiresNewAdmission` and `TestPublicationReadmitsInsteadOfReusingRunAdmission`.
- [ ] Step 2: Run:
  ```bash
  go test ./internal/domain ./internal/fixbinding ./internal/evaluator ./internal/finding -run 'Test(AbsenceAdmissionCannot|AdmissionReuse|ChangedProof|PublicationReadmits)' -count=1
  ```
  Expected **FAIL**, including the mutable cover projection.
- [ ] Step 3: Derive content admission once inside each stable evaluation scope and pass it through the listed callers. Keep distinct probe build graphs distinct. Rebuild after root-cause/fix-proof, record, affected scope or package-inventory changes; do not retain a value across mutable workflow stages.
- [ ] Step 4: Remove the wrappers and migrate every caller. Preserve fresh re-admission at `finding.Project`, report publication, replay and different assumption scopes. Do not serialize an admission token or treat a saved token as proof.
- [ ] Step 5: Rerun the focused command and:
  ```bash
  go test ./internal/goanalysis ./internal/evaluator ./internal/finding ./internal/report -run 'Test(Absence|SinkClosure|PersistedProof|RefusedPersisted|Publication)' -count=1
  ```
  Expected **PASS**, with unchanged admission outcomes.

**Acceptance:** Repeated reads within an unchanged evaluation scope reuse a checker-created result; changed inputs and publication/replay boundaries always re-admit.

## Dependency / Execution Order

Task 1 → Task 2 → Task 3.

---

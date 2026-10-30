# Task 5 caller migration report

Status: DONE

## Scope and changes

Migrated only the assigned evaluator/exploit/finding/report/states consumers and their test callers to the approved contextual fixbinding API.

Production files:
- `internal/evaluator/absence_identity.go`: supplies `AdmissionInput` directly from all six independent `VerdictInput` fields: Product, Vulnerability, RecordPin, AdvisoryRecord, Affected and Evidence. Does not substitute `VerdictInput.Case` or proof inputs.
- `internal/evaluator/conditions.go`, `internal/exploit/builder.go`, `internal/finding/project.go`, `internal/report/report.go`, `internal/states/states.go`: use `AdmissionForCase` with the current owning case.

Test caller/helper files:
- `internal/evaluator/absence_cover_test.go`
- `internal/evaluator/absence_identity_test.go`
- `internal/evaluator/binding_admission_test.go`
- `internal/evaluator/measurement_admission_test.go`
- `internal/finding/refusal_domination_test.go`
- `internal/finding/project_test.go`
- `internal/report/requested_finding_test.go`
- `internal/states/verdict_helpers_test.go`

Direct refusal/no-proof tests pass their independently held context, including explicitly incomplete context where the fixture genuinely lacks it. No new proof fixture, model-only authority wrapper, proof-input-derived context, compatibility fallback or test-only bypass was introduced. No existing assertion was removed or weakened. Builder already receives the owning AnalysisCase, so no signature change was necessary.

Preserved pre-existing Phase 6 Tasks 1–4 edits, fresh publication admission and stable scope handling. Did not edit checker/core DTO/domain, goanalysis, research or cmd. No commits, resets, agents, formatters, linters or full suite were run.

## Coordination

Core owner `P6T5FixCaptures` confirmed ctx-first APIs were written and subsequently confirmed production build readiness before checks began. The core's reported build is not counted below as verification performed by this caller task.

## Verification performed

1. Focused affected admission checks:

   `go test ./internal/evaluator ./internal/finding ./internal/report ./internal/exploit ./internal/states -run 'Test(CaptureContext|PersistedProof|Refused|Noncounterpart|SelectedSource|Absence|Binding|RequestedFinding)' -count=1`

   PASS: evaluator, finding, report. Exploit and states compiled successfully but reported no matching tests.

2. Real consumer API/workflow smoke (existing real builder, scope workflow, admission/replay and requested-report tests; no new mocked authority path):

   `go test ./internal/exploit ./internal/states ./internal/finding ./internal/report -run 'Test(BuilderSharedCheckMechanismSmoke|BuilderAbsent|BuilderUnmapped|BuilderUnverifiedStaleAbsentFlagIsChecked|ScopeVersionMixedRecordRegression|RefusedContentDependencyDominatesEveryIdentityLabel|RefusedPersistedProofDoesNotVetoIndependentSameLineRoute|RequestedFindingReports)$' -count=1`

   PASS in all four packages. The exact anchored builder alternatives actually exercised are SharedCheckMechanismSmoke and UnverifiedStaleAbsentFlagIsChecked; abbreviated BuilderAbsent/BuilderUnmapped alternatives do not match longer names.

3. Fresh publication admission regression:

   `go test ./internal/finding -run 'TestPublicationReadmitsInsteadOfReusingRunAdmission$' -count=1`

   PASS.

Inspected the owned file diffs. Existing unrelated changes appearing in those shared-file diffs were retained.

## Remaining integration ownership

No unresolved caller migration issue. Full capture success/foreign-context/source-free `/3` end-to-end fixture coverage remains with the core and fixture owners; the consumer smoke above does not claim to establish new capture producer acceptance or canonical research CLI coverage.

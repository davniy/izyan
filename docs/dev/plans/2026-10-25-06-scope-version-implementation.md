# Scope-Bound Version Negatives Implementation Plan

**Goal:** Preserve deterministic component facts while allowing a negative finding-level conclusion only when the evaluated entries cover the requested scope.

**Architecture:** Capture a digest-bound census of the original OSV `affected[]` array before ecosystem filtering or module merging. Carry it in `domain.AdvisoryScope`, strengthen the existing shared closure predicate, and apply that predicate consistently to workflow, research, persisted-case rendering, and exports.

**Tech stack:** Go 1.25 module, standard-library JSON/SHA-256, existing Go tests, workflow harness, and opt-in VEX-Bench calibration.

**Spec:** `docs/dev/plans/2026-10-25-05-scope-bound-version-negatives.md`

All paths below are relative to the repository root. This is a read-only plan; no implementation or verification commands were run.

## Global Constraints

1. **Do not change version arithmetic.** Preserve resolver union semantics: a fixed first entry must not shield an affected or unresolved second entry.
2. Preserve `x/net@v0.17.0 → VersionAffected=FALSE`. Do not synthesize a gRPC advisory entry, gRPC affectedness, or an x/net reachability probe.
3. `Basis` remains human explanation, never executable policy.
4. Neither an ID prefix nor a single module/ecosystem establishes completeness. The same applies to `github_reviewed`, aliases, feed enrichment, and failure to discover another implementation.
5. Apply the scope gate to **every negative conclusion**, including module/package absence, build/implementation exclusion, and NEPF. Module absence remains a separate component exclusion mechanism—not an exception to finding-scope coverage.
6. Proven positives remain admissible under incomplete advisory coverage. Do not add a blanket scope check before positive verdict evaluation.
7. Missing, malformed, or inconsistent extent/inventory fails closed. Do not reconstruct it from `AffectedModules`, `Basis`, ID prefixes, `AdvisoryRecord.Impls`, or research digests.
8. New persisted fields are optional. Old cases remain decodable, but old `Coverage=COMPLETE` without structural evidence no longer authorizes closure.
9. Preserve the recently landed `VerdictInput`, library-API admission, build-target provenance, measurement completion, and negative-verification gates.
10. Do not implement related-record discovery. It is explicitly outside this fix.
11. Do not change historical benchmark labels or aggregate counts to conceal newly conservative outcomes.

**Validation ownership:** Implementer subagents make their scoped changes without running checks mid-flight. The integration owner runs the focused command after each task lands; full formatting, vet, tests, and corpora run once at final integration. The expected pre-change failure is identified below so no baseline rerun is needed.

## Review Focus

| Edge condition | Owning validation |
|---|---|
| Exact GHSA record containing omitted non-Go entries | Tasks 2 and 6 |
| Two original entries merged into one `AffectedModule` | Tasks 1–2 |
| Fixed first module plus affected/pending second module | Task 3, existing `TestMultiModuleScopeAggregation` |
| `COMPLETE` with missing/inconsistent structural evidence | Tasks 1, 3, and 5 |
| Unsupported or dropped entry data mistaken for exclusion | Task 2 |
| Callback or static-source mutation of nested inventory | Tasks 1–3 |
| Package/NEPF route bypassing the version restriction | Tasks 3–4 |
| Cached research proof or caller-supplied decision bypass | Task 4 |
| Local rule remains `ESTABLISHED`, artifact remains `HOLD_UNKNOWN` | Task 4 |
| Stale negative case exports a safe status | Task 5 |
| Library-API positive or target-admission control regresses | Tasks 3 and 6 |
| Historical “correct-safe” labels treated as current acceptance | Tasks 6–7 |

### Task 1: Freeze the structural domain contract and shared gate

**Depends on:** None

**Files:**
- Modify: `internal/domain/advisory_scope.go`
- Test: `internal/domain/advisory_scope_test.go`

**Interfaces:**

Add the following types and fields:

```go
type RecordExtent string

const (
    RecordExtentFullRecord   RecordExtent = "FULL_RECORD"
    RecordExtentGoProjection RecordExtent = "GO_PROJECTION"
    RecordExtentUnknown      RecordExtent = "UNKNOWN"
)

// Index is the zero-based position in the original OSV affected[] array.
// AdvisoryID + DocumentDigest + Index identify the source entry.
type RecordEntry struct {
    Index     int    `json:"index"`
    Ecosystem string `json:"ecosystem,omitempty"`
    Module    string `json:"module,omitempty"`
}

type RecordInventory struct {
    AdvisoryID         string        `json:"advisory_id"`
    DocumentDigest     string        `json:"document_digest"`
    AffectedEntryCount int           `json:"affected_entry_count"`
    Entries            []RecordEntry `json:"entries"`
    RepresentedRefs    []int         `json:"represented_refs"`
    OmittedRefs        []int         `json:"omitted_refs"`
}
```

Extend `AdvisoryScope`:

```go
RecordExtent    RecordExtent     `json:"record_extent,omitempty"`
RecordInventory *RecordInventory `json:"record_inventory,omitempty"`
```

Produce:

```go
func (i *RecordInventory) Validate(recordID string) error
func (s *AdvisoryScope) Clone() *AdvisoryScope
func (s *AdvisoryScope) AllowsNegativeClosure() bool // existing signature
```

**Contract:**

- `DocumentDigest` is `sha256:<64 lowercase hex characters>` over the exact loaded document bytes.
- `Entries` preserves original order: `Entries[n].Index == n`.
- `AffectedEntryCount == len(Entries)`.
- `RepresentedRefs` and `OmittedRefs` are individually ordered, unique, in bounds, disjoint, and together partition every original entry index.
- `Validate` checks those structural invariants and `AdvisoryID == recordID`. A partial inventory can be structurally valid; validity alone does not authorize closure.
- `Clone` is nil-safe and copies the inventory object and all three slices.
- `AllowsNegativeClosure` retains the existing exact GO/GHSA identity, `ScopeAdvisoryEntries`, and `CoverageComplete` requirements, **and additionally requires**:
  - `RecordExtentFullRecord`;
  - a valid inventory bound to `ResolvedID`;
  - a nonempty original entry set;
  - every original entry represented and none omitted;
  - no represented non-Go or unresolved module identity.
- `ScopeCVE` remains non-closing even with a full single-Go-record inventory. This task adds no CVE-completeness override or producer.
- Use ordered references for linear validation without constructing maps on every successful gate evaluation.

**Implementation steps:**

- [ ] Add tests for valid exact GO and GHSA records; missing extent/inventory; `UNKNOWN`, future extent, and `GO_PROJECTION`; mismatched advisory identity; bad digest; count mismatch; duplicate/out-of-bounds/missing/overlapping refs; empty census.
- [ ] Add a two-entry inventory whose entries share the same module name. Both original refs must be required even though intake later merges them.
- [ ] Assert that changing `Basis` cannot change the decision.
- [ ] Assert that a CVE request cannot close with otherwise valid full-record metadata.
- [ ] Add `Clone` mutation-isolation tests.
- [ ] Implement the types, validation, clone, and strengthened predicate. Leave `AffectedResult.HasNegative()` unchanged.

**Focused validation:**

```bash
go test -count=1 ./internal/domain \
  -run 'Test(AdvisoryScope|RecordInventory)'
```

Expected pre-change failure: projection and missing-inventory cases are currently accepted as exact complete scopes.

**Acceptance:** The shared predicate alone rejects incomplete and legacy structural scope while accepting a consistent, fully represented exact advisory record.

**Do not change:** Version claims, negative-admission APIs, target admission, library scope, or verdict types.

---

### Task 2: Capture the original OSV census and bind scope without inference

**Depends on:** Task 1

**Files:**
- Modify: `internal/vulnerability/osv.go`
- Modify: `internal/vulnerability/source.go`
- Test: `internal/vulnerability/osv_test.go`
- Test: `internal/vulnerability/source_test.go`
- Create: `internal/vulnerability/scope_extent_test.go`
- Reuse unchanged: `eval/agent7/advisories/k8s-44487.json`

**Interfaces:**

Keep the public source interfaces unchanged:

```go
type Source interface {
    Get(ctx context.Context, id string) (*domain.Vulnerability, error)
}

func parseOSV(b []byte) (*domain.Vulnerability, error)
func bindAdvisoryScope(v *domain.Vulnerability, requestedID string)
```

Change the internal conversion boundary:

```go
func vulnerabilityFromOSV(
    doc osvDocument,
    documentDigest string,
) (*domain.Vulnerability, error)
```

Change the HTTP document loader to preserve the bytes being identified:

```go
func fetchOSVDoc(
    ctx context.Context,
    hc *http.Client,
    url string,
) ([]byte, error)
```

Migrate **all** callers in `OSVSource.Get` and `fetchOSVVuln` to pass those bytes through `parseOSV`. Keep existing HTTP error and alias-fallback behavior.

Add an internal census builder:

```go
func recordInventoryFromOSV(
    doc osvDocument,
    documentDigest string,
) (domain.RecordExtent, *domain.RecordInventory)
```

**Data flow:**

```text
file/HTTP bytes
  → parse JSON + SHA-256 exact bytes
  → census original affected[] entries
  → classify represented/omitted original refs
  → existing Go filtering and module merging
  → bind requested identity and coverage
```

**Implementation steps:**

- [ ] Build the census before `isGoOSVEntry` filtering and before `moduleIdx` merging. Record every original ecosystem/module identity and original index.
- [ ] Have the parser attach an **unbound** `AdvisoryScope` containing `ResolvedID`, extent, and inventory. Leave request-kind/coverage binding to `bindAdvisoryScope`.
- [ ] Make representation mean actual retention, not merely “ecosystem is Go.” Non-Go entries, dropped unnamed entries, and unsupported declarations must not be marked excluded or fully represented.
- [ ] Preserve the existing normalized range/package/symbol output. For declarations the current version model discards—such as non-SEMVER ranges, an explicit versions list, or unsupported range events—only downgrade structural coverage; do not extend or rewrite arithmetic. Add the minimal OSV wire fields needed to detect such dropped declarations, including `osvAffected.Versions []string` and `osvEvent.Limit string`.
- [ ] Preserve both source refs when same-module entries merge. For unnamed entries, distinguish actual retained unresolved data from discarded data; neither may silently become a resolved module identity authorizing closure.
- [ ] Bind using only structural evidence:
  - exact GO/GHSA + valid fully represented inventory → `ADVISORY_ENTRIES/COMPLETE/FULL_RECORD`;
  - omitted entries → `KNOWN_ONLY/GO_PROJECTION`;
  - missing/invalid census → `KNOWN_ONLY/UNKNOWN`;
  - any CVE request → `CVE/KNOWN_ONLY`, regardless of record extent.
- [ ] Preserve explicit prior downgrades. Alias/symbol/feed enrichment must not replace the primary document’s census or promote its extent/coverage.
- [ ] In `StaticSource.Get`, clone the scope before rebinding. A bare synthetic vulnerability containing only `Module`/`AffectedModules` remains unknown; it must not acquire a census.
- [ ] Update `TestStaticSourceScopeDoesNotMutateStoredVulnerability`: parser output now contains record metadata, so assert unchanged original metadata rather than `v.Scope == nil`.
- [ ] Keep a genuinely represented alias-enrichment control by supplying ranges in the primary test document. Add a separate unsupported/missing-range case proving enrichment does not manufacture completeness.

**Focused tests to add or extend:**

- `TestOSVRecordInventoryBeforeProjection`
- `TestOSVRecordInventoryBeforeModuleMerge`
- `TestOSVRecordInventoryUnsupportedEntries`
- `TestOSVRecordInventoryDigest`
- `TestFileSourceScope`
- `TestOSVSourceScope`
- `TestStaticSourceScopeDoesNotMutateStoredVulnerability`
- `TestStaticSourceScopeMissingInventoryFailsClosed`
- `TestFileSourceScopeAfterAliasEnrichment`
- `TestScopeExtentKubernetes44487`

For the real fixture, assert:

```text
original entries:       22
ecosystems:             Go=1, Maven=20, SwiftURL=1
Go affected modules:    1, golang.org/x/net
represented refs:       [1]       // Go entry is original affected[1]
omitted refs:           21
extent:                 GO_PROJECTION
```

Test both `CVE-2023-44487` and `GHSA-qppj-fm5r-hxr3`; neither closes.

**Focused validation:**

```bash
go test -count=1 ./internal/vulnerability \
  -run 'Test(OSV|FileSource|StaticSource|ScopeExtent)'
```

Expected pre-change failure: the exact mixed-record GHSA is currently bound as `CoverageComplete`, and the original census/digest is absent.

**Acceptance:** File and HTTP intake identify the same bytes and original entry universe; merging never loses source census information; exact Go-only records remain closable; the mixed GHSA and its CVE alias do not.

**Do not change:** Alias equivalence rules, advisory selection priority, range calculations, or related-record discovery.

---

### Task 3: Preserve component facts through resolver, workflow, verdict, and scan

**Depends on:** Task 2

**Files:**
- Modify: `internal/states/states.go`
- Modify only if needed for propagation/explanation: `internal/affected/resolver.go`
- Modify only if needed for explanation: `internal/evaluator/verdict.go`
- Test: `internal/affected/resolver_test.go`
- Test: `internal/states/states_test.go`
- Test: `internal/states/p0_safety_test.go`
- Test: `internal/states/perimeter_eval_test.go`
- Test: `internal/states/verdict_admission_test.go`
- Test: `internal/states/target_provenance_e2e_test.go`
- Test: `internal/states/library_scope_test.go`
- Test: `internal/evaluator/verdict_test.go`
- Test: `cmd/izyan/scan_test.go`

**Interfaces:**

Preserve:

```go
func (r GoResolver) Resolve(
    ctx context.Context,
    vuln domain.Vulnerability,
    product domain.ProductSnapshot,
) (domain.AffectedResult, []domain.Evidence, error)

func (h CheckAffected) Run(
    ctx context.Context,
    c *domain.AnalysisCase,
) (workflow.Transition, error)

func (VerdictEvaluator) Evaluate(in VerdictInput) domain.VerdictResult
```

Consume `AdvisoryScope.Clone()` and the strengthened `AllowsNegativeClosure()`.

**Implementation steps:**

- [ ] Replace the implementation-axis callback’s shallow scope copy in `CheckAffected.Run` with `scope.Clone()`. Restore the original authoritative scope after the callback as today.
- [ ] Extend callback tests to mutate inventory identity, entries, represented refs, and omitted refs. None may alter the original scope or its closure decision.
- [ ] Preserve `vuln.Scope` through every resolver early return. Do not derive inventory from checked/selected modules or narrow the original inventory when the vulnerability’s package/symbol view is narrowed.
- [ ] Extend `TestMultiModuleScopeAggregation` using a valid full-record census. Preserve fixed+affected, fixed+pending, and all-fixed controls.
- [ ] Extend `TestVerdictPartialScopeNegativeMatrix` to cover projected, missing-inventory, and inconsistent-inventory exact scopes across module/version/package/build/implementation negatives.
- [ ] Extend NEPF tests with those same scopes. Existing measurement/target admission must still run; a scope refusal must not replace those checks with weaker rules.
- [ ] Verify `CheckAffected` sends a projected component negative to `StateResolveRootCause`, records the limitation, and preserves the component claims/evidence.
- [ ] Preserve a full-record exact-negative control that transitions directly to `StateEvaluateVerdict`.
- [ ] Verify both zero-trust and cluster-perimeter profiles remain `INCONCLUSIVE` for scope-refused negatives.
- [ ] Migrate closable synthetic test helpers to explicit valid inventories:
  - evaluator exact scopes and `libraryScopeComplete`;
  - states `exactScope`, `verdictScope`, `provenanceVulnerability`, and perimeter fixtures;
  - scan `completeScope`.
  Keep missing-metadata tests deliberately missing. Do not weaken their expected verdicts just to accommodate stale fixtures.
- [ ] Add scan-prefilter cases proving projected/missing-census negatives survive the prefilter.

**Focused validation:**

```bash
go test -count=1 ./internal/affected \
  -run 'Test(ResolverScopePreservedOnEarlyReturns|MultiModuleScopeAggregation)'

go test -count=1 ./internal/evaluator \
  -run 'Test(Verdict.*Scope|VerdictNotAffected|VerdictImplementation|VerdictPersistedUsage|InsufficientScopeMandatory)'

go test -count=1 ./internal/states \
  -run 'Test(CheckAffected|EvaluateVerdictPartialScopeBothProfiles|PersistedVerifiedRequiresBuildContext|IndependentNegativeSurvivesHostDefault|HostDefaultNegativeRefused)'

go test -count=1 ./cmd/izyan \
  -run '^TestScanPrefilterOnlyFiltersNotAffected$'
```

Expected pre-change failure: an exact projected scope still authorizes negative closure; nested inventory mutation would cross the callback’s shallow-copy boundary.

**Acceptance:** Every negative route uses the same scope authority, but resolver facts and existing positive/negative-admission semantics remain intact.

**Do not change:** `VerdictInput`, arithmetic in `internal/affected/range.go`, package-probe scheduling, target precedence, library witness admission, or positive conjunction rules.

---

### Task 4: Close research-route and publication bypasses

**Depends on:** Task 2  
**Parallel-safe with:** Tasks 3 and 5

**Files:**
- Modify: `internal/research/decision.go`
- Modify: `internal/research/branch_evaluator.go`
- Modify: `internal/research/flow_adapter.go`
- Modify: `internal/research/assemble.go`
- Modify only for scope-copy isolation: `internal/research/deterministic.go`
- Test: `internal/research/decision_test.go`
- Test: `internal/research/branch_evaluator_test.go`
- Test: `internal/research/flow_adapter_test.go`
- Test: `internal/research/assemble_test.go`
- Test: `internal/research/deterministic_test.go`
- Test: `internal/research/replay_test.go`
- Test: `internal/research/schema_compat_test.go`

**Interfaces:**

Retain the existing authorities:

```go
func advisoryScopeAllowsNegativeClosure(l *LaneResult) bool
func laneApplicabilityDecision(l *LaneResult) (EvidenceDecision, bool)

func verifyArtifactClosure(
    ctx context.Context,
    reg *evaluator.AdapterRegistry,
    ruleFacts []evaluator.RuleFact,
    factByID map[string]*Fact,
    subjects, modules []string,
    scopeAllowsClose bool,
) (map[string]evaluator.RuleResult, *closeResult)

func Assemble(in AssembleInput) *Report
```

Add publication guards, using the shared predicate rather than implementing new scope policy:

```go
func scopeBoundDecision(
    lane *LaneResult,
    in *EvidenceDecision,
) *EvidenceDecision

func scopeBoundArtifact(
    lane *LaneResult,
    in *DecisionArtifact,
) *DecisionArtifact
```

**Implementation steps:**

- [ ] Keep `advisoryScopeAllowsNegativeClosure` as a thin wrapper over the domain predicate. The existing applicability, proposal, symbol-authority, config, and cached-proof gates should inherit the new rule.
- [ ] Extend tests for each route with an exact `GO_PROJECTION`, absent inventory, and inconsistent inventory. A cached `COMPLETE` symbol/config decision must not override the current lane scope.
- [ ] Preserve local rule results and fact refs in `verifyArtifactClosure` even when no `closeResult` may be selected.
- [ ] Assert that the mixed-record version rule remains `ESTABLISHED`, while the artifact proposes `HOLD_UNKNOWN`, contains no closing branch, and explains the uncovered requested scope.
- [ ] Re-gate caller-supplied negative `EvidenceDecision` values at `Assemble`: the current `reportDecision` copies them verbatim. Preserve evidence refs, checks, limitations, and hypothesis history; project the conclusion to `INCONCLUSIVE`.
- [ ] Re-gate supplied artifacts at publication. On scope refusal, copy the artifact before changing it:
  - demote any `CLOSE_*` branch to `HOLD_UNKNOWN`/`NOT_DECISION_READY`;
  - add the scope limitation;
  - remove active closing dispositions from justification edges;
  - set the artifact-level proposal to `HOLD_UNKNOWN`;
  - preserve shared facts and their verification status.
  Apply the same guard before sidecar persistence in the flow adapter so embedded and sidecar artifacts agree.
- [ ] Do not modify already admissible or non-closing artifacts. Validate guarded artifacts with the existing `ValidateDecisionArtifact`.
- [ ] Deep-copy scope at research paths that pass copied affected/vulnerability values to mutable proof/implementation processing.
- [ ] Update `exactAdvisoryScope` to contain an explicit valid inventory. Replace `exactEntryScopeFromIntake`’s bare `StaticSource` with `FileSource` over a temporary Go-only OSV document.
- [ ] Leave recorded legacy applicability fixtures without invented census data; they remain refusal controls.
- [ ] In `loadFrozenAdvisory`, consume the parser-produced scope. `Impls`, `RawBytes`, and canonical/raw research digests must not repair or promote it.
- [ ] Do not positionally equate merged `AffectedModules` with raw `Impls`. Where entry IDs are needed for reporting, use the original census index and verify module/ecosystem identity; missing correspondence remains diagnostic/unresolved, not completeness evidence.

**Focused validation:**

```bash
go test -count=1 ./internal/research \
  -run 'Test(ApplicabilityPartialScopeDoesNotClose|ExtentGateBlocksEveryNegativeRoute|ArtifactPartialScopeCannotProposeGlobalClose|ArtifactExactEntryVersionFalseClosesNotAffected|ArtifactRecordedVersionFalseLegacyScopeCannotClose|ArtifactProjectionPartialScopeRejectsCachedClose|DecisionForRecordedRunExtentGate|AssembleRefusesUngatedNegativeDecision|AssembleRefusesUngatedCloseArtifact|LoadFrozenAdvisoryScopeCensus)'

go test -count=1 ./internal/research \
  -run 'Test(ReportSchemaEnum|LegacyReportCompatibility|CompareReplayedArtifact|AdvisoryFeed|DeterministicUsageScope)'
```

Expected pre-change failure: exact projected scopes pass existing research gates, and `Assemble` accepts an externally supplied negative decision without re-gating it.

**Acceptance:** No research route or publication surface promotes an incomplete-universe negative; local facts remain visible and established.

**Do not change:** Research-report schema versions, `EvidenceDecision` wire shape, `AdvisoryInput`, `AdvisoryBinding`, `DecisionArtifact` fields, proposal contracts, positive-linkage vetoes, or replay equality policy. A replayed historical closure that no longer passes current admission must be refused or reported as policy drift—not silently declared equivalent.

---

### Task 5: Fail closed on persisted cases and every report/export surface

**Depends on:** Task 2  
**Parallel-safe with:** Tasks 3 and 4

**Files:**
- Modify: `internal/report/report.go`
- Modify: `internal/report/openvex.go`
- Modify: `internal/report/cyclonedx.go`
- Test: `internal/report/report_test.go`
- Test: `internal/report/openvex_test.go`
- Test: `internal/report/cyclonedx_test.go`
- Test: `internal/report/measurement_admission_test.go`
- Create: `internal/persistence/filesystem/store_test.go`
- Intentionally unchanged: `internal/persistence/filesystem/store.go`

**Interfaces:**

Preserve:

```go
func Write(dir string, c *domain.AnalysisCase) error
func Markdown(c *domain.AnalysisCase, lang ...string) string
func TrackerRationale(c *domain.AnalysisCase) string
func OpenVEX(c *domain.AnalysisCase) ([]byte, error)
func CycloneDX(c *domain.AnalysisCase) ([]byte, error)

func negativeClosureBlocked(c *domain.AnalysisCase) bool
func admitNegativeConclusions(c *domain.AnalysisCase) admissionProjection
```

**Implementation steps:**

- [ ] Remove the legacy exception in `negativeClosureBlocked` that treats an absent scope as a rendering concern owned elsewhere. For a non-nil case, missing affected/scope metadata cannot authorize a negative export.
- [ ] Add scope admission to `admitNegativeConclusions`, not just the VEX status switch. Thus `report.json`, Markdown, tracker rationale, and VEX all project the same current conclusion.
- [ ] Keep module/version component facts intact. Their independence from **build-target** admission is not independence from **advisory-scope** admission.
- [ ] For stale `NOT_AFFECTED` or NEPF:
  - project the verdict to `INCONCLUSIVE`;
  - preserve evidence and verification history;
  - explain “component fact established / requested scope not closed”;
  - do not mutate the caller’s case.
- [ ] Copy and re-project stale negative `Profiles`; otherwise the perimeter matrix can still advertise a safe result. Clear active falsifier/scope labels belonging to a refused profile conclusion.
- [ ] Recompute projected contextual risk using the existing `risk.Assess` when a safe verdict is demoted. Do not leave a stale `DISMISSED`/“no action” assessment beside an inconclusive conclusion.
- [ ] Extend the advisory-scope table with extent and census counts. Missing legacy fields display as unknown, even if the old coverage field says `COMPLETE`.
- [ ] Preserve local outside-range/package-exclusion facts without a whole-finding safe badge. Keep unmeasured package/build facts `UNKNOWN`.
- [ ] Export projected negatives as:
  - OpenVEX: `under_investigation`, no negative justification;
  - CycloneDX: `in_triage`, no negative justification.
- [ ] Update `exactEntryScope` with a valid inventory so existing measurement-admission controls still test their intended gate.
- [ ] Add persistence round-trip tests for both scope copies (`Vulnerability.Scope` and `Affected.Scope`). Verify absent new fields remain absent on legacy decode/re-encode and do not acquire inferred completeness.

**Focused tests:**

- Extend `TestReportScopeAndConditionRepair`, OpenVEX and CycloneDX counterparts.
- Add `TestReportExtentGateStaleNegativeMatrix`: projected/missing/inconsistent inventory × `NOT_AFFECTED`/NEPF.
- Add `TestReportExtentGatePreservesComponentFacts`.
- Add `TestReportExtentGateProjectsProfilesAndRisk`.
- Add `TestScopeInventoryStoreRoundTrip`.
- Add `TestLegacyScopeStoreFailsClosed`.

**Focused validation:**

```bash
go test -count=1 ./internal/report \
  -run 'Test(ReportScopeAndConditionRepair|ReportExtentGate|MeasurementAdmission|OpenVEXLibraryScope|CycloneDXLibraryScope)'

go test -count=1 ./internal/persistence/filesystem \
  -run 'Test(ScopeInventoryStoreRoundTrip|LegacyScopeStoreFailsClosed)'
```

Expected pre-change failure: scope-less stale negatives can export safe statuses, and report admission does not demote stale scope-refused conclusions in persisted JSON/profiles.

**Acceptance:** All artifacts agree on the current scope-bound decision, including when supplied a stale negative case. Legacy cases remain readable without reconstructing missing evidence.

**Do not change:** Persistence schema versions, store load/save behavior, VEX schema versions, positive library-API exports, or measurement-admission requirements.

---

### Task 6: Add the measured-case regression and named calibration controls

**Depends on:** Tasks 3, 4, and 5

**Files:**
- Create: `internal/states/scope_version_integration_test.go`
- Create: `internal/states/testdata/k8s-44487-modules.jsonl`
- Create: `cmd/izyan/scope_version_calibration_test.go`
- Reuse unchanged: `eval/agent7/advisories/k8s-44487.json`
- Reuse unchanged: `eval/agent7/e2e/k8s-44487/run-manifest.json`
- Reuse helpers from: `cmd/izyan/target_provenance_calibration_test.go`
- Reuse controls from:
  - `internal/states/library_scope_e2e_test.go`
  - `internal/states/target_provenance_e2e_test.go`
  - `internal/states/govulncheck_outcome_test.go`

**Test interfaces:**

```go
func TestScopeVersionMixedRecordRegression(t *testing.T)
func TestScopeVersionCalibration(t *testing.T)
```

The hermetic integration test’s GoTool implements:

```go
ListModules(context.Context, string, domain.ProductSnapshot) ([]byte, string, error)
ListPackages(context.Context, string, domain.ProductSnapshot) ([]byte, error)
ListPackagesScope(context.Context, string, domain.ProductSnapshot, bool) ([]byte, error)
```

It supplies only the module-graph input; it must not stub the affected result or verdict.

**Hermetic regression:**

- [ ] Use the actual 22-entry advisory through `FileSource{NoAliasEnrichment: true}`.
- [ ] Pin its raw digest to the recorded value:

  ```text
  sha256:077330160d3adbbb93b2294e3db541c70a746677a4128a1bd8843dab688dae39
  ```

- [ ] Make the small module-graph test input contain the measured versions:
  - `golang.org/x/net v0.17.0`;
  - `google.golang.org/grpc v1.55.0`.
  Label this as a minimal test input based on the measured snapshot, not a captured full tool trace.
- [ ] Run real intake → real `GoResolver` → `CheckAffected` → verdict → persistence → reports/exports for both request IDs.
- [ ] Assert:

  ```text
  requested:                 CVE-2023-44487 or GHSA-qppj-fm5r-hxr3
  resolved:                  GHSA-qppj-fm5r-hxr3
  record extent:             GO_PROJECTION
  coverage:                  KNOWN_ONLY
  original/represented:      22 / 1
  ModulePresent:             TRUE
  ResolvedVersion:           v0.17.0
  VersionAffected:           FALSE
  PackagePresent:            UNKNOWN
  BuildRelevant:             UNKNOWN
  CheckAffected next state:  RESOLVE_ROOT_CAUSE
  verdict:                   INCONCLUSIVE
  OpenVEX:                   under_investigation
  CycloneDX:                 in_triage
  ```

- [ ] Fail the test if either package-list method is invoked on the all-fixed version path.
- [ ] Assert no gRPC module is added to `AffectedModules`, checked advisory modules, selected advisory modules, or invented affectedness.
- [ ] Verify the persisted round trip retains the census and the component facts.
- [ ] Exercise the same loaded scope through research decision/artifact projection, asserting the local version fact remains established and no global close appears.
- [ ] Describe this as an integration slice, not a complete Kubernetes analysis. The real calibration below owns the complete CLI run.

**Real calibration:**

Follow the existing opt-in test convention: `VA_VEX_TASKS`, `VA_SNAPSHOTS`, `VA_FROZEN_OSV`, and `VA_CASES`; named skip reasons when unavailable; no private paths in committed code.

For the primary pair, select **the exact frozen `GHSA-qppj-fm5r-hxr3.json`**, not the generic helper’s preferred GO alias. Verify its census/digest before analysis. Both requests use identical snapshot, document, target, toolchain, and analysis settings.

Pin snapshot commit:

```text
e196d2491087e93bd29f0e5a538aab60667021e3
```

Record ground-truth provenance separately, including Kubernetes PR `121273`; never pass it into analysis.

Include these named control groups:

| Group | Exact task IDs |
|---|---|
| Primary | `kubernetes-kubernetes-e196d24-CVE-2023-44487`, repeated with the exact GHSA request |
| Helm | `helm-helm-b76a950-CVE-2024-25621`; `helm-helm-fbb24fe-CVE-2021-21334` |
| Rancher | `rancher-rancher-4dc4f53-CVE-2025-47914`; `rancher-rancher-4dc4f53-CVE-2025-58181`; `rancher-rancher-8761419-CVE-2026-24051`; `rancher-rancher-8761419-CVE-2026-39883` |
| Istio | `istio-istio-042afc3-CVE-2023-48795`; `istio-istio-8903f65-CVE-2024-45338` |
| Podman | `containers-podman-6a65597-CVE-2023-48795`; `containers-podman-38ccfa2-CVE-2024-37298`; `containers-podman-5ae6347-CVE-2025-47914` |
| Kubernetes 41717 | `kubernetes-kubernetes-6d4b94f-CVE-2022-41717` |
| Library non-admission | `labstack-echo-fdacff0-CVE-2020-26160`, plus the Podman and Kubernetes application controls above |
| Target pair | `cilium-cilium-1228cbc-CVE-2026-35469`, host-default versus explicit `linux/amd64` |

For controls, assert invariants—not historical “correct-safe” labels:

- every retained negative has valid full-record scope and passes existing target/measurement admission;
- incomplete measurements never count as corrected-safe results;
- proven positives and library-API scope are not erased by advisory incompleteness;
- local admissible proofs remain visible even when the requested CVE cannot close;
- unexpected errors/panics fail; recognized infrastructure aborts are recorded separately, never counted as successful analysis.

The ledger must include requested/resolved identity, raw advisory digest, extent, census counts, component claims, target provenance, tool outcomes, verdict, export states, and infrastructure classification.

**Focused validation:**

```bash
go test -count=1 ./internal/states \
  -run '^TestScopeVersionMixedRecordRegression$'

go test -count=1 ./internal/states \
  -run 'Test(E2ELibrary|TargetProvenanceE2E|GovulncheckOutcomeFirstClassRecords)'

go test -count=1 ./internal/evaluator \
  -run 'Test(LibraryInputWitness|VerdictKnownOnlyLibraryPositive|NegativeAdmission|MeasurementAdmission)'
```

Real calibration, once all changes are integrated:

```bash
mkdir -p "$VA_CASES"

PATH="$SHIM:$PATH" \
go test -count=1 ./cmd/izyan \
  -run '^TestScopeVersionCalibration$' \
  -timeout 180m -v
```

Use the environment variables documented by the existing calibration harness; snapshots without `.git` require the benchmark git shim. The test sets `IZYAN_SNAPSHOT_SHA` per task.

**Acceptance:** The primary CVE/GHSA pair demonstrates honest abstention with unchanged x/net arithmetic. Named controls produce an auditable ledger without invented post-change outcomes.

**Do not change:** Frozen advisory bytes, snapshots, ground truth, existing benchmark expectations, or unrelated control logic.

---

### Task 7: Synchronize documentation and perform final integration validation

**Depends on:** Tasks 1–6

**Files:**
- Modify: `docs/cli.md`
- Modify: `docs/architecture.md`
- Modify: `docs/how-it-works.md`
- Modify: `docs/dev/analysis-internals.md`
- Modify: `docs/dev/gap-analysis.md`
- Modify: `eval/README.md`
- Create: `docs/dev/reports/2026-10-25-05-scope-bound-version-negatives-calibration.md`

**Documentation deliverables:**

- [ ] Replace “all declared Go entries” as sufficient exact-record coverage with the full structural rule.
- [ ] Explain the distinct roles of `Kind`, `Coverage`, `RecordExtent`, inventory, and human `Basis`.
- [ ] Document legacy fail-closed behavior and the fact that `COMPLETE` alone is no longer closure authority.
- [ ] Explain that module/version negatives remain independent of build-target admission, but still require finding-scope coverage.
- [ ] Update workflow diagrams/table wording that currently implies any package/version negative immediately closes a finding.
- [ ] Document the mixed-record example: component outside range; package/build unmeasured; requested scope unresolved.
- [ ] Update the relevant B38 scope mechanism description without declaring remaining discovery/entailment work complete.
- [ ] Record calibration inputs, exact commands, actual outcomes, scope/refusal reasons, and missing prerequisites. Preserve historical baseline numbers and distinguish historical labels from newly observed results.
- [ ] State explicitly that the change neither proves gRPC affectedness nor solves all Kubernetes/Podman false alarms.
- [ ] Add no override flag and no separate related-record-discovery commitment.

**Final validation, integration owner only:**

1. Run `gofmt -w` once over the explicit set of changed Go files.
2. Run:

   ```bash
   go vet ./...
   go test -count=1 ./...
   ```

3. Run each full corpus **once**, after focused regressions pass:

   ```bash
   go run ./cmd/izyan eval \
     --corpus eval/corpus-real.json -j 4

   VA_PRODUCT_REPO="$VA_PRODUCT_REPO" \
   go run ./cmd/izyan eval \
     --corpus eval/live-corpus.json
   ```

4. Record actual `false-safe` results. Do not relax expectations to preserve cleared-rate counts. If the live corpus prerequisite is unavailable, name it and report that validation as unexecuted.
5. Record the opt-in Task 6 calibration result separately from corpus metrics.

**Acceptance:** Documentation matches the implemented contract, focused and final results are reported honestly, and no unsupported negative conclusion remains in persisted reports or exports.

## Dependency / Execution Order

```text
Task 1 — domain contract
   ↓
Task 2 — authoritative intake and binding
   ├── Task 3 — resolver/workflow/verdict/scan
   ├── Task 4 — research routes and publication
   └── Task 5 — persisted reports and exports
                ↓
Task 6 — primary regression and named calibration
                ↓
Task 7 — docs and final integration validation
```

Tasks 3–5 may run concurrently after Task 2 lands. Task 6 waits for all three. Maximum concurrent implementation owners: three.

## Serialization and Ownership

| Shared area | Owner and rule |
|---|---|
| `internal/domain/advisory_scope.go` | Task 1 exclusively. Freeze names, JSON shape, reference format, digest format, validation, and clone semantics before downstream work. |
| `internal/vulnerability/{source,osv}.go` | Task 2 exclusively. HTTP/file digest handling, census derivation, binding, and alias-enrichment preservation land together. |
| `internal/affected/resolver.go` | Task 3 exclusively. No arithmetic rewrite or census reconstruction. |
| `internal/states/states.go` and existing states fixtures | Task 3 exclusively. Task 6 adds its integration file only after Task 3. |
| `internal/evaluator/verdict.go`, `verdict_test.go`, scan scope helper | Task 3 exclusively. Preserve `VerdictInput` and admission ordering. |
| `internal/research/*` | One Task 4 integration owner. Do not split decision, artifact, cached-proof, assembly, and replay changes among concurrent editors. |
| `internal/report/*` | One Task 5 owner. Admission, profiles/risk, Markdown, tracker rationale, and both exports are one consistency unit. |
| Persistence store | Production store intentionally unchanged; Task 5 adds compatibility tests only. |
| Calibration helpers | Task 6 reuses existing helpers; avoid refactoring the target-provenance harness while adding this calibration. |
| Docs and benchmark ledger | Task 7 exclusively after measured results exist. |

**Handoff rule:** If implementation discovers evidence that invalidates the frozen representation contract or would require changing version arithmetic, stop that deviation and return it for design review. Do not silently substitute alias discovery, inferred completeness, or a version-only exception.

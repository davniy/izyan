# Product B triage adapter — slice 1 (types/ingress, detools, FactGate, schema registry)

**Branch:** `consolidation/shadow-base`
**Base:** `5bc0a0f` (S-05 baseline, kernel green; case-10 known fail-closed regression)
**Source:** V2 `internal/agenttriage` @ `6bcce89`
**Roadmap refs:** §14.3.2 (type mapping), §14.3.3 (Product B runtime/schema ownership), §14.4 (gates), §14.6/§14.7 (S-06/S-06b/S-07/S-08b/S-17)

## 1. What landed

New package `internal/productb` (S-17 schema registry) and `internal/productb/triage` (Product B triage runtime adapter, ported from V2 `internal/agenttriage`).

| File | Content | Source |
|---|---|---|
| `internal/productb/registry.go` | S-17 code-level schema registry: 20 Product B schemas with version/owner/producer/consumer/artifact/compatibility/replay/phase/ported | new, §14.3.3 |
| `triage/types.go` | `finding.v1`, `assessment.v1`, Verdict/FactStatus/FactValidationStatus/AutomationStatus/FalsifierKind enums, `FalsifierProposal` (proposal-only ingress: forbidden authority fields rejected at decode), Claim/EvidenceRef/feedback DTOs | `types.go` verbatim |
| `triage/input.go` | `ParseFindings` — strict finding.v1 (object/array/JSONL), raw bytes + sha256 preserved | `input.go` verbatim |
| `triage/decode.go` | `DecodeAssessment`/`decodeAssessment` (assessment.v1 ingress incl. falsifier proposal binding: unique ids, declared claim/evidence, canonical `det:` locator), `canonicalDetLocator`, `extractJSON`/`jsonSpan` (V2 balanced-span semantics) | `runner.go` + `llm.ExtractJSON` V2 semantics |
| `triage/detools.go` | `DeterministicTools` broker: 16-tool allowlist, per-call timeout, (name,args) cache, hash-only audit, `ToolSet`, `ObservationIndex` inputs | `detools.go`; `Catalog` retyped to adapter-local `DetToolInfo` |
| `triage/binding.go` | `ClientCaller` (Shadow `*evidencetools.Client` → `DetCaller`), `CatalogFromCheckCatalog` (Shadow `CheckCatalog` → `[]DetToolInfo`) | new (Shadow binding) |
| `triage/toolobs.go` | `ToolObservation`, `ToolStatus`, `ToolExecutor`, `capObservation`, `contextStatus`, `insideRoot`, `deferredTools`, `hashBytes` | `tools.go` subset (no ReadOnlyTools) |
| `triage/tool_audit.go` | `ToolAuditEvent`, `ObservationPin`, `ObservationIndex`, `innerSHA256s`, `toolAuditEvent` | `tool_audit.go` minus `ReadOnlyTools.recordAudit` |
| `triage/observation_archive.go` | `observation-archive.v1`: `RecordedObservation`, run/attempt-bound `ObservationStore`, `WriteObservationArchive`/`ReadObservationArchive` (hash-verified read) | `observation_archive.go` verbatim |
| `triage/factgate.go` | `FactGate`: canonical locator checks (`det:`/`obs:`/bare ids normalized; search:/list_files: pseudo-locators always UNAVAILABLE; file/artifact/advisory/component/revision kinds), `replayRecordedValidation` offline path | `factgate.go` verbatim minus 2 helpers only used by unported files |
| `triage/locator.go` | `fileLocator` parsing (`path[:line[-end]]`, `#L` forms; lexical escape rejection) | `locator.go` verbatim |
| `triage/factfeedback.go` | feedback-pass derivation (`BuildFeedback`), `blocks_risk_reduction` effect, scopes, repair hints | `factfeedback.go` verbatim |
| `triage/snapshot.go` | `snapshot.v1` `SnapshotManifest`/`SnapshotFile`, `LocalSnapshotBuilder` (containment, revision resolve, content hash + stability re-check, artifacts), materialization DTOs | `snapshot.go` verbatim + `MaterializationMode/Metadata/MaterializedSource` DTOs from `materialize.go` |
| `triage/doc.go` | package boundary doc | new |

Tests ported: `types_test.go`, `input_test.go` (verbatim); `detools_test.go` (adapted — `fakeExecutor` replaces `ReadOnlyTools`; real-catalog test binds `evidencetools.DefaultCheckCatalog`); `factgate_test.go` (adapted — observation fixtures fabricated through the same store/audit/index path instead of `ReadOnlyTools`); `snapshot_test.go` (minus 3 materializer tests needing `Materializer`); `observation_archive_test.go` (adapted + tamper test added); `registry_test.go`, `boundary_test.go`, `helpers_test.go` (new).

## 2. Type mapping (§14.3.2)

| V2 type/surface | Shadow target | Rule applied |
|---|---|---|
| `agenttriage.Verdict` | — (Product B only) | Kept Product-B-local; Product A spellings (NOT_AFFECTED, NO_EXPLOIT_PATH_FOUND, FALSE, UNKNOWN) rejected at decode — test-pinned |
| `agenttriage.Claim` / `assessment` | — | adapter-only Product B shape; no mapping to `domain.Claim`; boundary test forbids `internal/domain` imports |
| `FalsifierProposal` | Product B verification input | proposal-only; `status/verified/mandatory/coverage/negative_verification/recommendation/verdict` rejected at decode; condition_id binding to `condition-catalog.v1` deferred (S-16) |
| `evidencetools.Observation` | Shadow `evidencetools.Observation` | same repo/family — used directly (no struct cast across products); missing scope/completeness keeps locator UNAVAILABLE |
| `evidencetools.ToolInfo` | adapter-local `DetToolInfo` DTO | Shadow has no `ToolInfo`; projected from `CheckSpec` via `CatalogFromCheckCatalog` |
| `Session.CallTool` | `*evidencetools.Client.Call` via `ClientCaller` | Shadow session exposes tools only through the audited MCP client; same `(*Observation, error)` contract |
| `evidencetools.ToolCatalog()` | `evidencetools.CheckCatalog` (canonical) | Shadow check catalog is the single tool table; descriptions substituted by `CoverageRule` (deviation, below) |
| `SnapshotManifest`/`Finding`/`Assessment` etc. | Product B schemas (`snapshot.v1`, `finding.v1`, `assessment.v1`, `fact-gate.v1`, `observation-archive.v1`) | Product B owned; registered in `productb` registry |
| `Materializer`/`CatalogEntry`/`RefCandidate`/`MaterializationPolicy` | — | unsupported-and-non-admitting this slice (S-06b); only the `Materialization*` DTOs that `snapshot.v1` carries were ported |
| `ReadOnlyTools`, `stage0`, `checks`, `catalog`, `ref`, `siteconfig`, `input` (LLM intake), `intake_llm`, `materialize`, `artifacts`, `metrics`, `composer`, `policy`, `decision_*`, `runner`, `stability`, `replay`, `falsifier`, `advisory*`, `providers`, `agent_materials`, `prompt`, `chat`, `profiles`, `predicates`, `validation_rules`, `unreachability_proof`, `certificate`, `factfeedback` runner bits | — | unsupported/non-admitting this slice; marked `Ported=false` in the registry where schema-bound |
| `internal/domain`, `internal/affected`, `internal/evaluator` | — | dropped from adapter surface per §14.3.2; import-guard test enforces |

## 3. Deviations recorded

1. **`DetToolInfo` DTO + `CatalogFromCheckCatalog`.** V2 advertised `evidencetools.ToolInfo{Name,Description,InputSchema}` from `ToolCatalog()`. Shadow's canonical table is `CheckCatalog`/`CheckSpec` (no agent-facing description). The broker keeps `Catalog []DetToolInfo`; `CatalogFromCheckCatalog` fills `Description` from `CheckSpec.CoverageRule` (the only descriptive field Shadow publishes). If a later slice wants V2-style descriptions, Shadow `CheckSpec` needs a description field — flagged for S-06b.
2. **`ClientCaller` binding.** `DetCaller` keeps `CallTool(ctx,name,args)`; `ClientCaller` adapts `*evidencetools.Client.Call` (same signature, same audited Observation path — all session calls cross the MCP boundary identically).
3. **`ReadOnlyTools` not ported** (V2 `tools.go` handlers: read_file/list_files/search_text/read_manifest/lookup_advisory + budget plumbing). It is S-06b read-only-surface scope and pulls V2 `domain` via `AdvisoryProjection`. det:/obs: resolution does **not** depend on it — FactGate resolves the recorded-observation index (audit events → `ObservationPin`) which is fully implemented and tested, including archive tamper rejection. obs:/det: foreign-run ids, partial/unknown coverage, pseudo-locators all reject.
4. **`factgate.go` drops 2 helpers** (`hasGitSegment`, `resolveSnapshotPath`) whose only callers live in unported V2 files (`tools.go`, `replay.go`).
5. **`snapshot_test.go` drops 3 materializer tests** (`TestSnapshotMetaFromMaterialized`, `TestSnapshotMetaDrift`, `TestSnapshotMetaSerialization`, `TestSnapshotMetaLocalMode`) — they need the `Materializer`/`CatalogEntry`/`RefCandidate` machinery deferred to S-06b. `BuildMaterialized` itself is ported and compiles.
6. **Error prefix `agenttriage:` → `triage:`** in archive errors; `observation-archive.v1` wire format unchanged.
7. **`extractJSON` ported from V2** (balanced-span `jsonSpan`), not Shadow `llm.ExtractJSON` (first-brace-to-last-brace) — the decode contract (walk candidates until assessment.v1) depends on V2 semantics.

## 4. Authority boundary (acceptance checks)

- `Verdict` decode rejects Product A spellings (`NOT_AFFECTED`, `NO_EXPLOIT_PATH_FOUND`, `FALSE`, `UNKNOWN`) — `TestAssessmentIsNotProductAVerdict`, `TestInvalidEnumRejected`.
- `FalsifierProposal` rejects all 7 reserved verification fields naming them in the error — `TestFalsifierProposalRejected`, `TestProposalCannotSetAuthorityFields`.
- Proposal bindings require canonical `det:<id>` locator + declared claim/evidence + non-empty subjects — `TestFalsifierProposal*` (ported), `TestCanonicalLocatorRejectsNonCanonical`.
- FactGate `VALID` = reproducible reference only; PARTIAL/UNKNOWN coverage and DENIED/ERROR/TIMEOUT/UNSUPPORTED statuses never verify — `TestFactGateDetObservation`.
- Foreign attempt ids (`obs-a2-*`) never resolve — `TestFactGateForeignObservationID`; tampered archive fails read — `TestObservationArchiveRoundTripAndTamper`.
- No `internal/domain`/`affected`/`evaluator`/`agenttriage` imports in the adapter — `TestNoSecondAuthorityContract` (static import scan, non-test files).
- No auto-dismissal, composer, or policy code shipped.

## 5. Commands and results

| Command | Result |
|---|---|
| `go build ./...` | clean |
| `go test -count=1 ./internal/productb/...` | `ok internal/productb`, `ok internal/productb/triage` |
| `go test -count=1 ./internal/goanalysis ./internal/evidencetools` | `ok internal/goanalysis` (101.7s), `ok internal/evidencetools` (14.9s) — unaffected |
| `gofmt -l internal/productb/` | clean |
| `go vet ./internal/productb/...` | clean |

## 6. Blockers / open issues

- **None blocking.** `det:`/`obs:` resolution is bound to the real observation archive/index path implemented here (not a fake). The remaining locator dependency — a live `evidencetools.Session` producing det observations — is wired via `ClientCaller`; an end-to-end `Session → Client → DeterministicTools → archive → FactGate` test is deferred until a session fixture exists (S-06b/S-07 E2E gate `TestDetObsResolutionOnShadowEvidence`).
- `condition-catalog.v1` (S-16) is not part of this slice: `FalsifierProposal.ConditionID` is shape-checked but not yet catalog-checked — the catalog ingest is a prerequisite slice (DAG: S-16 before S-06).
- `CheckSpec` description gap (see deviation 1).

## 7. Next slice (composer/policy + S-06b intake)

1. S-16 prerequisites if not already landed: `condition-catalog.v1`, `proposal-ingest.v1`, generated `port-type-map.v1.json`.
2. S-06b: `ReadOnlyTools` (with `AdvisoryProjection` adapter DTO — no V2 domain import), stage0/catalog/ref/siteconfig/input/intake, `Materializer`, `artifacts` (raw-agent/triage-error/fact-gate documents), `tool_audit` persistence, `checks.go` pre-package checks.
3. S-08: `decision_types.go` (`decision-package.v2`, policy_outcome kept out of package), `composer.go`, `policy.go` (`ALLOW/WARN/BLOCK`, `--fail-on`, exit 1/2 semantics, `UNCHANGED` on unverified reduction), `metrics`, `baselines`, `vex_projection`.
4. S-07 E2E: live session fixture → `TestDetObsResolutionOnShadowEvidence`, falsifier admission chain (S-03b `verify_code_absence` + `symbol-unreachability` proof minting).


---

## 8. Slice 2 addendum — S-16 boundary contracts (2026-10-21, follow-up)

### 8.1 New surface

| File | Content |
|---|---|
| `triage/conditioncatalog.go` | `condition-catalog.v1` per §14.3.4: `ConditionCatalog`/`CatalogCondition`/`CatalogSubject`, canonical `ComputeHash`/`Sign`/`VerifyHash` (hash excludes `catalog_hash` itself), strict `DecodeConditionCatalog`, `CatalogBinding` run-side identity check, `AdmitFalsifierProposal` binding `FalsifierProposal.ConditionID`/`Kind` to catalog entries |
| `triage/proposalingest.go` | `proposal-ingest.v1` per §14.3.5: `ProposalIngest` envelope (case/advisory/snapshot/catalog-hash binding + `payload_digest`), `RunIdentity`, `IngestProposal` → `ProposalProvenance`; `IngestError` unwraps `ErrNonAdmitting` |
| `productb/typemap.go` | `port-type-map.v1`: `PortTypeMap()` 22 rows covering every V2 type the ported adapter touches or deliberately excludes; dispositions `mapped`/`adapter-projection`/`adapter-only`/`unsupported`/`dropped`; `PortTypeMapJSON()` emits the artifact |
| `productb/typemap_test.go` | mechanical completeness: import-allowlist scan over all adapter files (domain/affected/evaluator/agenttriage forbidden), every used internal import must have a mapped row, every mapped row a target |
| `registry.go` | `condition-catalog.v1` + `proposal-ingest.v1` registered (S-16, Ported=true) |

### 8.2 Rules implemented (§14.3.4/§14.3.5)

- Unknown `condition_id` → `ErrUnsupported`; falsifier kind outside the entry's `allowed_falsifier_kinds` → `ErrUnsupported` (closed set, never kind-Valid default).
- No catalog, unverifiable hash, stale hash vs content, run-pin mismatch, advisory/case mismatch → `ErrNonAdmitting` (run fails closed).
- `catalog_hash` = sha256 of canonical marshal of all fields except the hash itself; pinned in `RunIdentity.ConditionCatalogHash`, verified on both catalog decode and ingest.
- `IngestProposal` checks `payload_digest` **before** identity; `case_identity_ref` is an exact match, digests case-insensitive. Verified envelopes yield `ProposalProvenance` only — no Claim/NV/Verdict path exists in the package (import-guard test enforces).
- FactGate `VALID` cannot make a condition mandatory: `mandatory` is catalog-owned, `VALID` is reproducibility only (unchanged).

### 8.3 Tests added (all green)

- `conditioncatalog_test.go`: round-trip/sign/verify, 10 malformed-catalog rejects, unknown-field reject, stale-hash detect, run-pin mismatch, foreign case, advisory id/digest mismatch, admit valid/unknown-condition/disallowed-kind/stale/full-binding.
- `proposalingest_test.go`: matching envelope, foreign snapshot, altered advisory, foreign case, stale catalog hash, tampered payload (digest mismatch before identity), 8 missing-field rejects, authority-field smuggling reject, wrong schema, decode+verify.
- `typemap_test.go`: entry classification, import-graph completeness, artifact round-trip.

### 8.4 Deviations

1. `case_identity_ref` semantics: Shadow has `AnalysisCase.ID` (`domain.CaseID`) but S-01 owns identity derivation; the adapter treats it as an opaque equality string — binding derivation is a later slice.
2. `ProposalProvenance` is produced but **attaching it to `AnalysisCase`** is Product A's call (case file schema is S-01); the adapter returns it, doesn't mutate Product A state.
3. `ProposalKind` constants are advisory labels for provenance; unknown kinds ingest fine and fail at the deterministic verifier.
4. Type map is a Go registry (not a checked-in `.json`) — `PortTypeMapJSON()` emits it; pinning the file to `docs/` deferred until a Phase-0 gate picks a canonical artifact dir.

### 8.5 Slice-2 commands

| Command | Result |
|---|---|
| `go build ./...` | clean |
| `go test -count=1 ./internal/productb/...` | `ok` ×2 |
| `go test -count=1 ./internal/goanalysis ./internal/evidencetools` | unaffected (kernel suite) |
| `gofmt`/`go vet` | clean |

### 8.6 Next slice — S-06b

`ReadOnlyTools` (advisory-projection DTO, no domain import), stage0/catalog/ref/siteconfig/intake, `Materializer`, `artifacts` (raw-agent/triage-error/fact-gate persistence), `checks.go`; then S-08 composer/policy. `condition-catalog` producer side (Product A checker path minting catalogs) is a separate upstream slice — S-16 consumer side is now in place.

---

## 9. Slice 3 addendum — S-06b Product B intake/runtime (2026-10-21, follow-up)

### 9.1 Adapter DTO packages (new)

S-06b's transitive closure needed V2 types with no Shadow equivalent (or with Shadow equivalents inside forbidden packages). Three adapter-local DTO packages now own them; each is a verbatim V2 port with imports rebound:

| Package | Source | Content |
|---|---|---|
| `internal/productb/domain` | V2 `internal/domain` data structs | **Type-alias shim** over identical Shadow structs: `Vulnerability`, `VersionRange`, `AffectedPackage`, `SymbolRef`, `AffectedModule`, `ProductSnapshot`, `GoVersionSource`, `ReplaceDirective`, `ExposureFact`, `CallSite`, `Condition`, `ConditionKind`, `ExploitModel`, `Reference` + scope/perimeter/condition constants. `SourceAnalyzerDefault` is adapter-local (Shadow lacks it). No authority type is exported — `Claim`/`NegativeVerification`/`VerdictResult`/`AnalysisCase` do not exist here. |
| `internal/productb/affected` | V2 `internal/affected/golist.go` | `Module` (V2 superset: `Dir` field), `GoTool` interface, `ExecGoTool`, caching wrapper, `DecodeModules`, `PackageImportPaths`, `ParseVendorModules`. Domain refs → `productb/domain`. |
| `internal/productb/vulnerability` | V2 `internal/vulnerability` (3 files) | `CompositeSource`, `FrozenAdvisory`+schema, `RawDocument`, `OSVSource`, `FrozenOSVSource`, `ParseAdvisoryDoc`, `FreezeAdvisory`, `SourceAttempt`, `AdvisoryError`/classes — Shadow has none of the freeze/composite machinery. |
| `internal/productb/repository` | V2 `internal/repository` (4 files) | `Clone`/`CloneOptions`, `EnumerateRefs`/`RefInfo`, `NewWorktree`, `BinaryBuildInfo`, `CheckPathReplacements`, `DiscoverReleaseEvidence` (V2 `ReleaseEvidence` shape), content hash, snapshot preflight — Shadow's package lacks clone/enumerate and returns a different evidence type. |

Reused Shadow packages unchanged (identical code or canonical surface): `internal/llm`, `internal/toolchain`, `internal/toolaudit`, `internal/risk`, `internal/exposure`, `internal/evidencetools`.

### 9.2 Triage files ported (S-06b)

| File | Surface |
|---|---|
| `tools.go` | `ReadOnlyTools` full surface: `read_file`, `list_files`, `search_text`, `read_manifest`, `lookup_advisory` — bounded, root-confined, budgeted; `AdvisoryProjection` DTO lives in `validation_rules.go`; `det:`/`obs:` resolution still independent (archive index) |
| `stage0.go` | Stage0 resolution pipeline: intake → proposal validation → catalog → bounded ref selection → materialize → snapshot → advisory → materials → package check → toolchain; technical errors on the error channel |
| `intake.go`, `intake_types.go`, `intake_proposal.go`, `intake_validation.go`, `intake_llm.go`, `intake_audit.go` | `RawIntake`/`ParseIntake`/`ParseIntakeRecord`, `IntakeProposal` schema, deterministic `ValidateIntakeProposal` (VALID/UNVERIFIED/CONFLICTING/INVALID/UNAVAILABLE, anti-hallucination), LLM extractor (proposal-only, refusal-safe), intake audit doc |
| `catalog.go`, `ref.go`, `siteconfig.go` | `CatalogEntry`, `RefCandidate`/`RefResolution` with bounded candidates and no current-HEAD fallback, `SiteConfig` (triage-site.v1, YAML — adds `gopkg.in/yaml.v3` to go.mod) |
| `materialize.go` | `Materializer` (local/worktree/clone modes), `MaterializationMetadata`, content-hash pinning, drift re-check |
| `materials.go`, `validation_rules.go`, `agent_materials.go` | `MaterialSet`/`ModuleGraph`/`Material`/`ModuleVersion`, deploy-scan exposure via `internal/exposure`, `CheckPackageVersion` (VERSION_CONFIRMED/IN_AFFECTED_RANGE/MISMATCH/MODULE_ABSENT/UNRESOLVED — facts, never absence proof), `ResolveReleaseToolchain` |
| `artifacts.go`, `audit.go`, `metrics.go` | `ArtifactWriter`: `assessment.json`, `raw-agent.json`, `error.json`, `fact-gate.json`, `stage0.json`, `intake*.json`, `materials.json`, `metrics.json`, `stability.json`, `observation-archive.json`, audit log; `Metrics` (triage-metrics.v2) |
| `advisory.go`, `advisory_conditions.go`, `mandatory_conditions.go` | `ResolveAdvisory` (ticket/frozen/OSV lanes via productb/vulnerability), advisory conditions, `MandatoryConditionSource` binding the condition-catalog contract |
| `falsifier.go`, `falsifier_requirement.go`, `unreachability_proof.go`, `certificate.go` | deterministic falsifier verifier (`falsifier-verification.v1`), mandatory-proposal requirement, symbol-unreachability proof minting, proof certificate |
| `decision_types.go`, `decision_rules.go`, `predicates.go`, `profiles.go`, `providers.go`, `stability.go`, `policy.go`, `decision_render.go` | `decision-package.v2` types + canonical rule/profile sets + predicate evaluator + fact providers + stability projection + deterministic `ApplyAutomation`/policy mechanics. **No composer**: `ComposeDecision`/`Composer{}` are not ported — `decision-package.v2` stays `Ported=false` |
| `runner.go`, `prompt.go`, `chat.go` | `AgentRunner`/`ChatClient`/`AgentRun` agent loop, prompts, bounded chat retry |

Overlapped prior files: `toolobs.go` deleted (superseded by `tools.go`); `decode.go` slimmed to the `DecodeAssessment` wrapper (canonical `decodeAssessment` lives in `runner.go`); `extractJSON`/`jsonSpan`/`looksTruncatedJSON` ported locally because Shadow `llm.ExtractJSON` has different (first/last-brace) semantics; `hasGitSegment` restored in `tools.go`.

### 9.3 Tests

- Ported: 44 V2 test files (all that compile against the ported surface), including the 3 previously dropped materializer tests (`TestSnapshotMetaFromMaterialized`, `TestSnapshotMetaDrift`, `TestSnapshotMetaSerialization`, `TestSnapshotMetaLocalMode`) and `unreachability_proof_test.go` adapted to Shadow's session API (`Session.Connect` → `ClientCaller`, `CatalogFromCheckCatalog`).
- `fixtures_test.go` carries the shared `goodStage0`/`goodAssessment`/`completeValidation`/`versionRangeStage0`/`replayClock*` helpers formerly in `composer_test.go`/`replay_test.go`.
- Dropped: `composer_test.go`, `vex_projection_test.go`, `replay_test.go`, `arbitration_test.go`, `decision_render_test.go`, `test_only_rule_test.go`, `version_range_rule_test.go`, `package_v2_test.go` — composer/vex/replay surfaces are S-08/S-09; `TestCheckMatrixFinalGate` (needs `ComposeDecision`), 8 `TestComposer*` cases in `falsifier_facts_test.go`, `TestStabilityReplayDrift` (needs `recordReplayRun`), `TestUnreachabilityKernelProofDismisses` (needs `Composer`).
- `internal/testdata/unreachability-session` fixture copied from V2 `testdata/` for the kernel session tests.

### 9.4 Deviations

1. `go.mod`/`go.sum` gained `gopkg.in/yaml.v3` (site config loader; V2 already depended on it).
2. `productb/domain` is an alias shim, not a struct copy — the identical-struct finding from §14.3.2 is exploited to make the mapping mechanical and zero-divergence. Only data types are re-exported.
3. `falsifier-verification.v1`, `intake-proposal.v1`, `ref-selection.v1`, `triage-metrics.v2`, `triage-error.v1`, `raw-agent.v1`, `stability-runs.v1`, `intake-record.v1`, `intake-audit.v1`, `stage0.v1`, `triage-site.v1` flipped to `Ported=true`; `decision-package.v2`, `triage-baselines.v1`, `triage-vex-projection.v1`, `replay.v1` stay `Ported=false`.
4. `policy.go`/`decision_render.go`/`providers.go`/`stability.go`/`decision_types.go`/`decision_rules.go` were ported because the artifact writers and pre-package checks require them — they carry mechanics only; package composition (`Composer`), baselines, VEX projection and replay remain S-08/S-09.
5. Shadow `internal/repository` could not serve the materializer (no `Clone`/`EnumerateRefs`; different release-evidence type), so `productb/repository` mirrors V2's — the alternative (rewriting materialize.go against a partial API) would have changed behavior.

### 9.5 Slice-3 commands

| Command | Result |
|---|---|
| `go build ./...` | clean |
| `go test -count=1 ./internal/productb/...` | `ok` ×2 (triage ~14.6s) |
| `go test -count=1 ./internal/goanalysis ./internal/evidencetools` | unaffected (kernel suite) |
| `gofmt`/`go vet` | clean |

### 9.6 Next slice — S-08

`composer.go` (`ComposeDecision`/`Composer.ComposeWithEvidence` — `providers.go`, `decision_rules.go`, `DefaultRules`/`DefaultProfiles`, `collectFacts` already in place), `triage-baselines.v1` loader, `vex_projection.go` (`triage-vex-projection.v1`, default-off/non-authoritative), `decision_render` emission path, dropped composer tests restoration; then S-09 replay.

---

## 10. Slice 4 addendum — S-08 composer, policy, metrics, VEX projection, baselines (2026-10-21, follow-up)

### 10.1 Ports

| File | Surface |
|---|---|
| `composer.go` | `ComposeDecision`/`Composer.Compose`/`Composer.ComposeWithEvidence`, `DecisionRule`/`DecisionProfile`, `composeBaseline` (severity precedence: frozen advisory → verified intake → scanner → operator default; missing baseline = technical error), `collectFacts`, `evaluateDecisionRules`, `decisionFactSet`/`factKey`/`strengthOf`, `DefaultRules()`/`DefaultProfiles()` (merged in from the prior local `decision_rules.go`, now deleted — a single canonical rule/profile source). |
| `vex_projection.go` | `triage-vex-projection.v1` — optional `ProjectVEX(pkg)`/`WriteVEXProjection`; `TriageOnly` pinned true at validate; `not_affected` only; denials return `ErrVEXProjectionDenied` and are audit-recorded, never technical errors; `not_in_execute_path` justification is off-limits (Product A kernel vocabulary). |
| `decision_types.go` (already ported, verified) | `DecisionPackage` carries exactly the §14.5 field set; strict `UnmarshalJSON` (`DisallowUnknownFields`) rejects any smuggled `policy_outcome`. |
| `policy.go` / `metrics.go` (already ported, verified) | `EvaluateAutomation`/`ApplyAutomation` verdict×validation matrix (fail-closed to BLOCK); `PackagePolicyHit` + `ParseFailOn` + exit codes; `LoadBaselines` (`triage-baselines.v1`) + `ComputeMetrics`/`RunRecord` — metrics are read-only projections, `unverified_reduction_count`/`false_safe` counters. |

### 10.2 Policy / exit semantics (pinned)

- Exit 0 pass, exit 1 `ExitCodePolicy` on a `--fail-on` threshold hit, exit 2 `ExitCodeError` on technical/integrity error (bad input, agent run error, fact-gate failure, unknown `--fail-on`).
- `--fail-on` accepts only `unchanged`/`low-support`/`conditional`/`unverified-disposition`; unknown values fail closed at parse.
- `Automation` (ALLOW/WARN/BLOCK) lives on the `assessment.v1` artifact — `DecisionPackage` has no `policy_outcome`/`automation` field, structurally and on the wire (`s08_boundary_test.go`).
- Technical failures return `error` from `ComposeDecision` (e.g. missing baseline), never a packaged `UNCHANGED`.

### 10.3 Tests restored / added

- Restored files: `composer_test.go`, `vex_projection_test.go`, `arbitration_test.go`, `decision_render_test.go`, `package_v2_test.go`, `test_only_rule_test.go`, `version_range_rule_test.go`.
- Restored cases: 8 `TestComposer*` in `falsifier_facts_test.go`, `TestCheckMatrixFinalGate` in `checks_test.go`, `TestUnreachabilityKernelProofDismisses` in `unreachability_proof_test.go`.
- New: `s08_boundary_test.go` — `TestDecisionPackageHasNoPolicyOutcome`, `TestDecisionPackageFieldPresence`, `TestNoAutoDismissalByDefault`, `TestUnverifiedReductionStaysUnchanged`, `TestTechnicalErrorStaysOnErrorChannel`, `TestExitCodeSemantics`, `TestVEXProjectionBoundary`.
- Still dropped (S-09): `replay_test.go`, `TestStabilityReplayDrift` (needs `recordReplayRun`).

### 10.4 Registry

`decision-package.v2`, `triage-baselines.v1`, `triage-vex-projection.v1` → `Ported=true`. Remaining `Ported=false`: `replay.v1` (S-09).

### 10.5 Deviations

1. `decision_rules.go` (my prior local merge file) deleted; canonical `DecisionRule`/`DecisionProfile`/`composeBaseline`/`evaluateDecisionRules`/`factKey` now live in `composer.go` as in V2. `DefaultRules()`/`DefaultProfiles()`/`collectFacts` appended to `composer.go`.
2. `productb/domain` gained `TriagePriority`/`PriorityP0…P3`/`PriorityDismissed` aliases (data constants used by baseline tests — no authority).
3. `replay.go` remains unported: it needs `recordReplayRun`/`jsonEqual` machinery tied to the S-09 sidecar contract.

### 10.6 Slice-4 commands

| Command | Result |
|---|---|
| `go build ./...` | clean |
| `go test -count=1 ./internal/productb/...` | `ok` ×2 (triage ~15.5s) |
| `go test -count=1 ./internal/goanalysis ./internal/evidencetools` | unaffected |

### 10.7 Next slice — S-09

`replay.go` + `replay_test.go` + `TestStabilityReplayDrift`: `replay.v1` artifacts, `ReplayStage0`/`ReplayRun` fail-closed replay, sidecar re-derivation from pinned artifacts only (no git/OSV/network), `stability-runs.v1` replay path.
---

## 11. Slice 5 addendum — S-09 replay, stability, sidecars (2026-10-21, follow-up)

### 11.1 Ports

| File | Surface |
|---|---|
| `replay.go` | `PrepareReplay`/`ReplayRun`/`ReplayStage0`/`VerifySnapshotDrift`/`ReplayDocument` (`replay.v1`), `AuditEventReplay`. Fail-closed: replay consumes only saved artifacts — never resolves refs, re-hashes the working tree or reads the live repository (`VerifySnapshotDrift` is the explicit opt-in live check, outside the replay contract). Persisted `VERIFIED` is recomputed via `NewFalsifierVerifier`+`AdvisoryConditionSource`, never trusted; `decision.json` recomposition requires byte-identical `canonicalDecisionHash`; `decision.md` must byte-match `RenderDecisionMarkdown`; `stability.json`/`fact-gate.json`/`observation-archive.json`/`falsifier-verification.json`/`intake`/`input`/`audit` all verified against recorded pins. |
| `factgate.go` | `resolveSnapshotPath` restored (replay's declared-path resolver). |
| `observation_archive.go` | `ReadObservationArchive` re-verifies `data_sha256` per entry; attempt-qualified `AttemptRunID` id spaces; `NewRunObservationStore` stamps run identity the falsifier verifier rejects foreign stamps against. |

### 11.2 Cross-boundary semantics (pinned)

- `decision.json` requires `stage0.json` provenance; `fact-gate.json` required when a decision is present; drifted stability + decision = technical error.
- Observation index for replay is rebuilt from `audit/events.jsonl` (agent run id) and the archive (attempt-qualified run id) — two different stamps, never interchangeable.
- Foreign/tampered cases fail closed (all are technical errors, not warnings): foreign `decision.json` (hash mismatch), foreign `run_id`-stamped observation feeding a falsifier proof, foreign `stability.json` run binding, tampered observation payload under kept `data_sha256`, persisted `VERIFIED` without recomputation, cross-run falsifier evidence (V2 `TestReplayFalsifierCrossRunRejected`).
- No best-of attempt selection: semantic drift across retries demotes to `UNCHANGED` (`TestStabilityDemotion`), instability without reduction records demotion, drifted sidecars are technical errors.

### 11.3 Tests

- Restored: `replay_test.go` (1447 lines, ~40 cases incl. `TestReplayFalsifierCrossRunRejected`, `TestReplayDoesNotTrustPersistedVerified`, `TestReplayObservationIndexRejectsNonFactStatuses`, `TestReplayDecisionDrift`/`Reproduces`/`AbsentIsLegacy`, `TestReplayFalsifier*` ×5, `TestReplayHonoursAttemptRunIdentity`), `TestStabilityReplayDrift` + 9 Composer-dependent stability cases (`TestStabilityDemotion`, `TestStabilityUnstableWithoutReduction`, `TestStabilityStableRecordsResult`, `TestDriftComposeError`, `TestStabilityAttemptProjection`, `TestStabilityFalsifier{VerifiedToUnknown,SnapshotDrift,RuleVersionDrift,PreservesProofHistory}`).
- New `s09_boundary_test.go`: `TestReplayForeignDecisionRejected`, `TestReplayForeignObservationArchiveRejected` (Product-A-stamped run id = foreign evidence), `TestReplayForeignStabilitySidecarRejected`, `TestReplayTamperedObservationPayloadRejected`.
- `helpers_test.go` deleted — `jsonEqual` moved into `replay.go` (non-test) as in V2.

### 11.4 Registry

`replay.v1` → `Ported=true` (`stability-runs.v1` was already true). All 23 declared Product B schemas now Ported.

### 11.5 Deviations

1. `replay.go`/`replay_test.go` rebind `evidencetools.ToolCatalog()` → `CatalogFromCheckCatalog(evidencetools.DefaultCheckCatalog())` (Shadow has no tool-description catalog; §14.3.2 DTO).
2. `repository`/`vulnerability` imports → `productb/repository`/`productb/vulnerability` adapter DTOs; `internal/llm` reused (Shadow surface identical where replay needs it).
3. Cross-boundary tests assert generic technical-error failure (fail-closed), not specific message text — V2 covers message text for in-run drift cases.

### 11.6 Slice-5 commands

| Command | Result |
|---|---|
| `go build ./...` | clean |
| `go test -count=1 ./internal/productb/...` | `ok` ×2 (triage ~17.8s) |
| `go test -count=1 ./internal/goanalysis ./internal/evidencetools` | unaffected |

### 11.7 Next slice — S-07 E2E / S-10 verification

End-to-end triage driver wiring (Product B `izyan triage` command path against the ported runtime), cross-solution verification of the adapter surface (Product A gate S-07: no second authority contract holds under the full ported runtime), census/eval harness hooks; S-12 `refindex`/research adapters if scheduled.

---

## 12. Slice 6 addendum — S-10 adapters + falsifier payload fix + E2E chain (2026-10-21, follow-up)

### 12.1 Bug fixed in the ported verifier (V2-parity deviation)

`coverageFor` (falsifier.go) parsed `checked_subjects`/`absent_subjects`/`import_closure`
at the top level of `RecordedObservation.Payload`. The detools broker archives the
serialized `evidencetools.Observation`, so those fields live under its `data` member.
Consequence on a real (non-fixture) run: `ClosureHash=""`, `CheckedSubjects=nil` → every
`code_absent` proof stayed UNKNOWN ("subject set incomplete") — an advisory code-absence
condition could never verify end-to-end. V2 `falsifier.go` has the identical parse
(diff: 4 lines, package name only), so the latent bug exists upstream; fixture tests in
V2 seed `Payload` with the inner data object and never exercise the production shape.

**Fix:** when the payload carries a non-empty `data` member, the verifier unwraps it and
parses the typed tool output; envelope-only payloads behave exactly as before. Malformed
payloads still fail closed (PARTIAL + skipped-package note). Commit `6ff57fe`.

### 12.2 E2E chain test (new `e2e_test.go`)

`TestE2ETriageChain` exercises the whole ported runtime on real Shadow plumbing:

stage0 (ghost advisory `example.org/ghostpkg`, module-absent package check) →
`AgentRunner` with a scripted LLM client → one real `verify_code_absence` call through
`evidencetools.Session → ClientCaller → DeterministicTools → ObservationStore` →
FactGate `COMPLETE` with a VALID `det:det-0001` reference (reproducibility, not proof) →
`NewFalsifierVerifier` + `NewAdvisoryConditionSource` → VERIFIED `code_absent` proof →
`Composer` → DISMISSED `decision-package.v2` → `ArtifactWriter` persistence
(stage0/materials/intake/input/assessment/fact-gate/observation-archive/falsifier-verification/decision/audit)
→ `PrepareReplay` fail-closed recomposition byte-identical to the stored package.

`TestE2ENegativeChain`: tampered assessment replay fails closed.

New fixture `internal/testdata/e2e-product` (one-module `package main`, `go 1.23`): the
session import closure stays ~1.3 KB so the recorded observation never hits the 128 KiB
`maxObservationBytes` cap (the earlier `unreachability-session` fixture truncates the
closure payload → proof coverage degrades; kept for its own tests).

### 12.3 S-10 ports

| Package | Surface |
|---|---|
| `internal/productb/claimshape` | canonical claim-shape normalization; UNSUPPORTED is explicit, never a silent admit; no verdict output |
| `internal/productb/verify` | universal verification chain over triage DTOs (graph/evaluate/interpret/live/payload/replay/stability/certificates); a VALID locator is presence in the run record, never proof |

`typemap.go`: composer/vex_projection/replay rows moved to `AdapterOnly` (landed in
slices 4–5); `claimshape.*` and `verification.* → productb/verify` rows added;
`evaluator.*` stays `Dropped`.

### 12.4 Commits

- `875d02e` — S-10 claimshape/verify adapters + typemap update.
- `6ff57fe` — falsifier `data:` unwrap fix + `e2e_test.go` + `internal/testdata/e2e-product`.

### 12.5 Slice-6 commands

| Command | Result |
|---|---|
| `go build ./...` | clean |
| `go test -count=1 ./internal/productb/...` | `ok` productb (0.43s), claimshape (0.44s), triage (19.4s), verify (0.93s); affected/domain/repository/vulnerability no test files |
| `go test -count=1 ./internal/goanalysis ./internal/evidencetools` | `ok` goanalysis (108.6s), evidencetools (15.7s) — unaffected |

### 12.6 Open items

- The same `data:` unwrap is **not** applied upstream in V2 `agenttriage/falsifier.go` —
  flag for the port-integrity record; production-path `code_absent` verification is
  broken there identically.
- Remaining roadmap items: E2E triage driver wiring (`izyan triage` command path),
  cross-solution authority gate under the full runtime, census/eval hooks, S-12
  refindex/research adapters if scheduled.

---

## 13. Slice 7 addendum — `izyan triage` CLI wiring (2026-10-21, follow-up)

### 13.1 Port

| File | Content |
|---|---|
| `cmd/izyan/triage.go` | Full V2 `triage.go` driver (1537 lines) retargeted to `internal/productb/triage`: `runTriage`, `runTriageTicket`, `runTriageFinding`, `runTriageReplay`, `detToolExecutor`, `frozenAdvisorySource`, stability/compose/feedback plumbing, `compatStage0`, final-gate checks, ruleset pinning. |
| `cmd/izyan/main.go` | `triage` case in the dispatch switch, `cliExitError` → exit-code mapping in `main()`, usage line. |
| `cmd/izyan/triage_cli_test.go` | 7 tests over `internal/testdata/e2e-product` with a fake OpenAI-compatible endpoint. |

### 13.2 CLI contract (verified)

- Inputs: `--ticket` / `--input` (finding.v1, file or `-`) / `--config` (triage-site.v1,
  required for `--ticket`) / `--replay-run` / `--baseline` (triage-baselines.v1) /
  `--fail-on` (repeatable) / `--vex-projection` / `--det-tools` / `--llm-env` /
  `--model` / `--osv-url` / `--allow-external-artifacts` / budget flags.
- Outputs per finding: `input.json`, `snapshot.json`, `stage0.json` (+`intake.json`,
  `intake-proposal.json`, `materials.json` when present), `raw-agent.json`,
  `assessment.json`/`assessment.md` (assessment.v1), `fact-gate.json` (fact-gate.v1),
  `decision.json`/`decision.md` (decision-package.v2), `observation-archive.json`,
  `falsifier-verification.json` when proofs run, `stability.json` on retries,
  `audit/events.jsonl`, `error.json` on technical failure, batch `metrics.json`.
- Exit codes: `0` packages pass policy; `1` `--fail-on` hit; `2` technical/integrity
  error (malformed input, bad flags/config, snapshot drift, tampered or foreign
  artifacts, composition failure). Per-finding failures never stop the batch.
- `--vex-projection` default off; inadmissible packages record a denied audit event
  (`"type":"vex_projection","status":"denied"`), never change the decision or exit code.
- No auto/semantic dismissal: without a verified falsifier the package stays
  UNCHANGED regardless of the agent verdict (asserted).

### 13.3 Adaptations (deviations from V2 source)

1. **Session binding.** V2 passed `*Session` straight to `Caller`; Shadow sessions
   expose tools only through `Connect → *evidencetools.Client` (audited MCP
   boundary). `detToolExecutor` returns a cleanup that closes the client; called on
   every exit path incl. stability-retry branches.
2. **Catalog.** `sess.CheckCatalog()` (the session's permission-filtered table)
   replaces `evidencetools.ToolCatalog()` — definitions never advertise a denied
   tool. `CatalogFromCheckCatalog` projects onto `DetToolInfo` (same DTO as §3.1).
3. **Frozen advisory source.** `frozenAdvisorySource` returns
   `internal/vulnerability.Source` backed by `productb/vulnerability.FrozenOSVSource`
   — legal because `productb/domain.Vulnerability` is a type alias for
   `internal/domain.Vulnerability`, so the adapter satisfies the canonical interface
   structurally. Hash check against the freeze record is unchanged.
4. **`rec.Source` kind** comparison uses `pbvuln.AdvisoryFrozenOSV` (the record's own
   kind type); the source handed to evidencetools is the canonical
   `internal/vulnerability.Source` — no second contract.

### 13.4 CLI E2E (`triage_cli_test.go`, all green)

| Test | Asserts |
|---|---|
| `TestTriageCLIFlags` | 7 malformed invocations → exit 2 before LLM traffic |
| `TestTriageCLIE2EChain` | `--input` → snapshot → scripted agent (one real `get_product_snapshot` det call through `Session → Client → DeterministicTools`) → FactGate COMPLETE, `det:det-0001` VALID → decision-package.v2 → all artifacts; `--replay-run` writes byte-identical `decision.json` offline |
| `TestTriageCLIPolicyFailOn` | `--fail-on unchanged` → exit 1, package unchanged |
| `TestTriageCLITechnicalInput` | malformed finding JSON → exit 2 |
| `TestTriageCLIForeignAuthority` | agent replies `NOT_AFFECTED` (Product A spelling) → decode reject → exit 2, `error.json`, no decision |
| `TestTriageCLITamperedReplay` | stored `decision.json` flipped to DISMISSED → replay drift → exit 2 |
| `TestTriageCLIVexProjection` | flag off → no `vex.json`, silent audit; flag on + UNCHANGED → denied event, no `vex.json`, exit unchanged |

### 13.5 Slice-7 commands

| Command | Result |
|---|---|
| `go build ./...` | clean |
| `go test -count=1 ./cmd/izyan` | `ok` (18.2s) |
| `go test -count=1 ./internal/productb/...` | `ok` productb/claimshape/triage(19.6s)/verify |
| `go test -count=1 ./internal/goanalysis ./internal/evidencetools` | `ok` (105.8s / 15.5s) — unaffected |
| `go vet ./cmd/izyan ./internal/productb/...` | clean |

Commit: `9172828`.

### 13.6 Remaining S-11/S-12 items

- S-11 triage driver hardening: `--ticket` site-config path is wired but untested end-
  to-end at the CLI level (needs a frozen-advisory + catalog fixture); baseline
  false-safe violation path covered only via unit tests in `internal/productb/triage`.
- S-12 `refindex`/research adapters not started (DAG permits deferral).
- `izyan triage` is Product B transport only — no Product A gate binding yet
  (cross-solution authority gate is the Phase-3 item, unchanged).

---

## 14. Slice 8 addendum — S-12 research/refindex/reportcheck lane (2026-10-21, follow-up)

### 14.1 Relocation (S-12 isolation rule)

The V2 research lane moved under `internal/productb/` — it is **not** merged into
Shadow's `internal/research` (Product A's own lane keeps that name):

| Package | From | Content |
|---|---|---|
| `internal/productb/refindex` | V2 `internal/refindex` (10 files + testdata) | `izyan-refindex/1` frozen document: advisory digests, build context, resolved defect locus, product-usage stratum, fix-diff summary. Canonical marshal → byte-identical re-runs. |
| `internal/productb/reportcheck` | V2 `internal/reportcheck` (7 files) | `izyan-reportcheck/1` grounding/consistency check: negative-claim extraction, location/classify/verify over the snapshot; a grounding failure is a limitation/error, never a safe-negative. |
| `internal/productb/research` | V2 `internal/research` (17 files incl. 7 test files, b1-plain.txt) | B1 CVE research lane: prompt render with frozen pin, opencode-container launch plan, run audit (`izyan-research-audit/1`), grounding/consistency, offline `--replay-run`. Output is a research judgement — never an authoritative verdict, case or VEX mutation. |

### 14.2 Adaptations

1. **`domain` → `pbdomain`.** Every V2 `internal/domain` import remapped to
   `internal/productb/domain` (alias projection). `productb/domain` gained the
   `ToolExecution` alias (pure audit data type) — the only DTO gap the lane
   exposed.
2. **`repository`/`vulnerability` → productb adapters** (existing S-06b DTOs).
3. **`goanalysis`/`fix`/`toolaudit` stay canonical** — mechanics, not authority;
   the same "map" disposition the detools broker already uses.
4. **`agent7` prompt-integrity surface ported adapter-local** as `promptscan.go`:
   `frozenOfficialSHA256` constant, `scanDataset`, `scanProhibited`. V2's
   `eval/agent7` package is eval-side, not ported; the frozen hash value is the
   same bytes, so a drifted embedded template still fails the render pin.
5. **CLI:** `izyan research-b1` (V2 `runResearch` — renamed because Product A owns
   the `research` subcommand) and standalone `cmd/izyan-refindex` (byte-identical
   determinism test ported). `izyan-reportcheck` exists only as a document schema —
   the V2 lane emits it from `productb/reportcheck`, no separate command upstream.
6. **Registry:** `izyan-refindex/1`, `izyan-reportcheck/1`, `izyan-research-audit/1`
   registered Phase-4; `registry_test.go` accepts `/N` spellings alongside `.vN`
   (the artifacts' `schema` field is frozen V2 text — renaming it would break
   byte-identical replay and downstream joins).

### 14.3 Boundary pins (S-12 DoD)

- `TestS12LaneIsolation` (import guard): `internal/research`, `internal/domain`,
  `internal/affected`, `internal/evaluator`, `agenttriage` are forbidden inside the
  three ported packages — passes.
- `TestS12NoProductAAuthorityMutation`: source scan for `VerdictResult`,
  `EvidenceGraph`, `NegativeVerification`, `AnalysisCase` construction/mutation —
  passes; the lane cannot name authority types (no domain import exists).
- Frozen prompt hash: `renderPrompt` refuses a template whose sha256 ≠
  `frozenOfficialSHA256` — ported `prompt_test.go` verifies.
- Replay is offline: `research --replay-run` re-renders from stored artifacts —
  V2 `replay.go` semantics preserved; no container/network/model call.
- Salvaged categories are marked (`"salvaged"` note + parse-error audit entry);
  research_category never becomes an authoritative verdict.

### 14.4 Coverage

All V2 unit tests ported and green: refindex (`TestRunDeterministic` byte-identical
via `izyan-refindex` binary test), reportcheck (888-line suite), research
(abspath/agentrun/answer/consistency/grounding/prompt/research — 7 files).

### 14.5 Slice-8 commands

| Command | Result |
|---|---|
| `go build ./...` | clean |
| `go test -count=1 ./internal/productb/...` | `ok` ×6 incl. refindex 5.6s, reportcheck 1.3s, research 5.5s |
| `go test -count=1 ./cmd/izyan ./cmd/izyan-refindex` | `ok` 18.6s / 1.5s |
| `go test -count=1 ./internal/goanalysis ./internal/evidencetools` | `ok` 109.7s / 16.1s — unaffected |

Commit: `866ec5d` (73 files, +14,945).

### 14.6 Remaining S-11/S-14/S-15 items

- Root-cause P/R scorer is V2-side Python (`eval/vexbench_rootcause_score.py`) —
  the Go lane produces `izyan-reportcheck/1` for it; scorer join is eval work,
  not a port.
- S-11 heldout gate / corpus admission, S-13 deployment/assumption adapter,
  S-14 case capability specs remain.
- `izyan research-b1 --allow-agent` launches a container: untested in this
  environment (docker absent); `--dry-run` and `--replay-run` paths are covered
  by ported tests.

---
## 15. Slice 9 addendum — S-11 heldout/admission gate (2026-10-21, follow-up)

### 15.1 Port scope

| Unit | V2 source | Shadow target |
|---|---|---|
| gate/replay/stability | `internal/heldoutgate/{gate,replay,stability}.go` | `internal/productb/heldoutgate/` |
| absence probe + §8.4 mutations | `internal/heldoutgate/probe.go` (685) | same, `sess.CallTool` → `sess.Connect`+`cli.Call` |
| §8.3 metrics/report | `internal/heldoutgate/metrics.go`, `types.go` | same; `corpus_sha256` field added |
| CLI | `cmd/heldout-gate` (252) | `cmd/izyan-heldout-gate` |

Dependency rewrite only: `agenttriage`→`productb/triage`, `claimshape`→`productb/claimshape`,
`verification`→`productb/verify`, `evidencetools` canonical. No V2 `domain`/`affected`/
`evaluator`; `boundary_s12_test.go` now covers `heldoutgate` in both scans.

### 15.2 Adaptation delta — `Session.CallTool`

Shadow's evidencetools exposes no `Session.CallTool`: a call must cross the in-memory
MCP boundary (`sess.Connect()` → `*evidencetools.Client` → `cli.Call`). `getSession`
became `getClient` (same per-worktree memoization; the audited Observation contract
the boundary produces is identical to an external agent's call — see `binding.go`).

### 15.3 Gate run on the real corpus (measured, not fixture)

- Corpus: `<VA_REPO>/tmp/agent-triage-live-20261015/v2-corp/out-full`
  — 85 runs, 312 claims; `corpus_sha256 = 323f3da7d0f63a807c246a39bd86071ff4ac52ce1fee98f2753ac0d536cb91e6`.
- Labels: `comparison-pass6.json` (human NE on all 85).
- Stability: `out-variance` 5×3 + `variance.json`.

| Hard gate | Required | Observed |
|---|---|---|
| false_safe_count | 0 | **0** |
| unverified_reduction_count | 0 | **0** |
| reductions_on_partial_unknown_conflict | 0 | **0** |
| reductions_on_unstable_inputs | 0 | **0** |
| foreign_cross_run_admissions | 0 | **0** |
| admission_on_deterministic_eligible | 100% | n/a (no §8.3-eligible records — all carry observed dynamic markers) |
| admission_on_incomplete_conflicting_unstable | 0 | **0** |
| eligible_absence_proofs_admitted | all | 0/0 (absence probe skipped — inputs absent, see below) |
| alarms_not_auto_safe | 0 | **0/9** |
| admitted_reductions_human_aligned | 100% | 6 reductions, all human-NE |
| precision_95_proven | ≥59 | **6 — FAIL (reporting gate)** |

`capability_gate: DEFAULT-OFF — hard gates hold, recall unmeasurable (all-NE corpus),
precision bound unproven`. Exit `0` (report emitted). Matches the V2 eval-README §16
verdict on the same corpus.

### 15.4 Missing inputs — absence probe skipped

`kernel-spec.json` / `absence-matrix.json` / `worktrees.json` are not present in any
reachable directory (searched `vuln-analyzer/tmp/agent-triage-live-20261015/` and all
workspace roots; the spec/matrix are private eval artifacts generated per probe). The
gate records the skip as a `defects[]` entry — never an implicit pass. `probe_groups=0`,
`mutations_total=0` on this run.

### 15.5 Preserved contract

- no auto-dismissal / no admission by default; `false_safe=0` is a gate, not a claim;
- positive-class recall explicitly unmeasured (`recall_exploitable_measurable=false`);
- exit codes: `0` report, `1` runtime, `2` input/config — verbatim from V2;
- `heldout-gate.v1` registered in `productb/registry.go` (Phase-4); `GateReport`
  gained `corpus_sha256` (the only field delta — the gate must name the measured corpus).

### 15.6 Commands

| Command | Result |
|---|---|
| `go build ./...` | clean |
| `go test -count=1 ./internal/productb/...` | ok ×7 incl. heldoutgate |
| `go test -count=1 ./cmd/...` | ok ×4 (heldout-gate cmd has no unit tests upstream) |
| `go test -count=1 ./internal/goanalysis ./internal/evidencetools` | ok 127.3s / 15.7s — unaffected |

Commit: `9838cd4` (11 files, +2,370).

### 15.7 Remaining

- Absence probe real run needs the pinned kernel-spec/matrix/worktrees inputs (eval-side
  artifacts, not in repos).
- S-13 deployment/assumption adapter, S-14 case capability specs remain open.

---

## 16. Slice 10 addendum — S-13 deployment/assumption adapter (2026-10-21, follow-up)

### 16.1 Scope

`internal/productb/deployment` is the explicit adapter binding the V2 deployment
surface (`siteconfig.DeploymentConfig` + `collectDeployFacts`, already ported in
S-06b inside `productb/triage/materials.go`) to Shadow canonical: `internal/exposure`
facts and `ClassifyPerimeter`, `domain.DeclaredAssumption` admission, and the
`BasisDeclaredTrust`/`BasisAutoPerimeter`/`BasisConfigOrigin` vocabulary.

### 16.2 Artifact

`DeploymentProjection` (`deployment-projection.v1`, registered Phase-4): classified
perimeter + rationale, fact count, `facts_digest`/`projection_sha256` pins, disjoint
`basis` block, limitations. `Digest()` is the replay identity over the artifact.

### 16.3 Basis disjointness (the S-13 pins)

| Basis | Lane content | Grounding |
|---|---|---|
| `declared-trust` | `TrustBinding` — kind/required-scope/admitted/assumption_id/scope/rejection_reason | only `domain.AdmitAssumption` on the `productb/repository.LoadDeclaredAssumptions` channel; never evidence, never satisfies a falsifier |
| `auto-perimeter` | bool — set only when the classifier-derived perimeter is non-unknown over real facts | `exposure.ClassifyPerimeter` output pass-through |
| `config-origin` | `config_origin` + `config_origin_facts` (count of traced `config:`/`env:`/`manifest`/`var`/`const` provenance facts) | code-level provenance only |

Missing manifests: `Deploy=nil` or `FactCount=0` projects `PerimeterUnknown` +
explicit non-isolation limitation — never a synthesized isolation claim.
Foreign services: the canonical owner-matching rule is passed through —
unattributed or prefix-sibling public surfaces veto, never ground,
cluster-internal.

### 16.4 Evidence separation (structural)

`TestAssumptionNeverEntersEvidence` proves the marshaled projection carries no
`evidence_ids`/`claim_id`/`verdict`/`claims`/`evidence` field — the adapter's
output cannot become a graph fact. Assumption admission failure surfaces as a
typed `ASSUMPTION_*` rejection reason, never silently skipped.

### 16.5 Strict validation

`DecodeProjection` + `Validate`: `DisallowUnknownFields`, exact schema, perimeter
vocabulary check, lane-consistency (`auto_perimeter` requires resolved perimeter;
admitted declared-trust requires `assumption_id`; facts require a digest).

### 16.6 Commands

| Command | Result |
|---|---|
| `go build ./...` | clean |
| `go test -count=1 ./internal/productb/...` | ok ×7 incl. deployment (7 tests) |
| `go test -count=1 ./cmd/...` | ok ×4 |
| `go test -count=1 ./internal/goanalysis ./internal/evidencetools` | ok 111.8s / 15.6s — unaffected |

Commit: `194cc6d` (7 files, +573).

### 16.7 Remaining

S-14 case capability specs (cases 03/07/08/01/02/17/18) and S-15 remain open.

---
## 17. Slice 11 addendum — S-15 ownership, CI, retention, D17, supersession (2026-10-21)

### 17.1 Owner matrix

`docs/dev/ownership-and-ci.md` publishes the role/agent owner matrix: canonical
case (product-a-case-owner), evidence/verdict (product-a-evidence-owner),
`internal/productb/**` adapters (ProductBTriageMerge), triage runtime,
research lane, deployment adapter, schema registry, retention manifest
(baseline-keeper), CI definition (repo-maintainer). Human approvers marked
`TBD` where unassigned — exactly the assignment the spec asks for.

### 17.2 Named CI gates

| Gate | Proves |
|---|---|
| fmt / vet / test / build | mechanical hygiene; kernel+adapter suites green; cross-compile |
| boundary | `internal/productb/boundary_s12_test.go` + `triage/boundary_test.go`: forbidden imports + authority-type scan + schema-registry completeness |
| heldout-gate | `cmd/izyan-heldout-gate` offline corpus replay — §8.3 hard gates; runs only when `vars.HELDOUT_CORPUS` is provisioned, otherwise the job is explicitly SKIPPED (`::notice`), never a silent pass |
| census (manual/scheduled) | deterministic baseline parity: 18 cases, `false_safe=0` |

### 17.3 Retention

`docs/dev/retention-manifest.template.json` — `retention-manifest/1` template
with sha256 slots per artifact class (baseline corpus permanent; run
artifacts 2-release-cycles; sidecars with-parent-run; replay + admission
evidence permanent-while-referenced). Secrets/private paths prohibited
(provenance-local refs only).

### 17.4 D17 + supersession

- `architecture-decisions.md` + D17 — dual-product authority/adapter boundary:
  Shadow owns Product A verdict/evidence; Product B is adapter-only; no V2
  domain/affected/evaluator merge; mechanical pins named.
- `shadow-analyzer-agent-spec.md` marked **SUPERSEDED** in place
  (provenance retained); `INDEX.md` re-labeled.

### 17.5 Verification

| Command | Result |
|---|---|
| `go build ./...` | clean |
| `go vet ./internal/productb/heldoutgate ./internal/productb/deployment ./cmd/izyan-heldout-gate` | clean |
| `gofmt -l .` (non-testdata) | clean |
| `go test -count=1 ./internal/productb/... ./cmd/...` | ok ×7 productb + ok ×4 cmd |

Commit: `1fa2ff8` (7 files, +245).

### 17.6 Remaining

S-14 case capability specs (03/07/08/01/02/17/18) — external input blockers:
live case inputs + authoritative ticket records for the named cases; heldout
probe kernel-spec/matrix/worktrees pinned artifacts.

## 18. Merge review follow-up (2026-10-21, second pass)

Disposition of the review items recorded against the slice-1 surface.

### P1 — landed

| Item | Change | Files |
|---|---|---|
| P1-1 catalog-gated falsifier path | Live verifier admits each proposal through `AdmitFalsifierProposal` before `Verify`; a missing/foreign/stale `condition-catalog.v1` produces a report of non-admitted proofs (`FalsifierUnknown`/`BasisUnsupported`), never a silent pass or drop. New flags `--condition-catalog` + `--condition-catalog-hash` (required together; rejected under `--replay-run`); registry producer note records "no in-repo producer yet". | `cmd/izyan/triage.go`, `internal/productb/triage/falsifier.go` callers, `internal/productb/registry.go` |
| P1-2 final-attempt persistence | `writer.Write` and the final-gate `CheckInput` now read `finalRun`/`finalAssessment`/`finalFV` — the selected attempt, not attempt 1 — while `finalRun.Attempts` carries the recorded retry history. | `cmd/izyan/triage.go` |
| P1-3 unverified reduction fails closed | `UnverifiedReductionCount > 0` exits 2 alongside `FalseSafeViolation` on all three metrics sites (`runTriage`, `runTriageTicket`, `runTriageReplay`). | `cmd/izyan/triage.go` |
| P1-4 CI split | `boundary-gate` job renamed *Adapter boundary, schema & policy determinism (blocking)*; a second step runs the catalog-admission / partial-binding / stability / decision-determinism test set alongside the boundary pins. (V2-side `TestRunTriadWithEvaGate` is not in this repo — no EVA gate exists here; the Shadow equivalent of the "product boundary" gate is this job.) | `.github/workflows/ci.yml` |
| P1-5 partial bindings fail closed | `RunIdentity.validate` and `CatalogBinding.validate` require every field non-empty before any comparison runs; `IngestProposal` and `CheckCatalog` enforce it, so a skipped check can never pass as a match. | `internal/productb/triage/proposalingest.go`, `conditioncatalog.go` |

### P2 — landed

| Item | Change |
|---|---|
| P2-7 strict decoders | `DecodeConditionCatalog`, `DecodeProposalIngest`, `IngestProposal` reject trailing JSON via `dec.More()`. |
| P2-8 atomic writers | Already unified: `writeFileAtomic`/`writeJSONAtomic` in `artifacts.go` are the only definitions and shared by every writer — no change needed. |
| P2-9 `FalsifierFeedbackFunc` semantics | Parameter contract documented on the type (accepted assessment, matching gate result, run-scoped archive, 1-based pass). |

### P2 — deferred (recorded, non-blocking)

| Item | Reason |
|---|---|
| P2-6 replay attempt selection | `PrepareReplay` recomputes the assessment from the primary transcript; selecting the recorded attempt by `assessment_hash` match is a behavioral change to the replay path, deferred to the replay-adapter slice rather than guessed in this pass. |
| P2-10 process-per-attempt falsifier isolation | Requires a harness; no end-to-end falsifier-run fixture exists in this slice. Recorded as unproven. |

### Verification (this pass)

| Command | Result |
|---|---|
| `go build ./...` | clean |
| `go test -count=1 ./internal/productb/... ./cmd/izyan` | ok ×12 packages |
| `go test -run 'TestConditionCatalog|TestAdmitFalsifier|TestCheckCatalogRejectsPartialBinding|TestIngestProposalRejectsPartialRunIdentity' ./internal/productb/triage -v` | pass, incl. new partial-binding cases |

## 19. Merge review follow-up (2026-10-21, third pass — catalog replay gate, heldout split, kernel parity)

Disposition of the second-review blockers.

### Blocker fixes — landed

| Item | Change | Files |
|---|---|---|
| Replay re-enforces catalog admission (missing/stale/foreign = fail closed) | `PrepareReplay` loads `condition-catalog.json` + `catalog-binding.json` from the run dir; the proposals are partitioned by the shared `GateFalsifierProposals` (same helper the live path uses — identical rejection spelling), only admitted proposals reach the verifier, and rejected proofs are appended before the report hash. Absent catalog ⇒ every proposal non-admitted ⇒ recomposed decision drift error; foreign or tampered catalog ⇒ decode/binding rejection or drift. Legacy runs without `catalog-binding.json` derive the binding from run artifacts (frozen advisory id/digest, finding id, catalog's own hash) — hash-drift since the run is a documented limit of that path. | `internal/productb/triage/replay.go`, `conditioncatalog.go`, `cmd/izyan/triage.go` |
| Catalog provenance persisted | `ArtifactWriter.WriteConditionCatalog` writes `condition-catalog.json` (when a catalog was bound) plus `catalog-binding.json` (`catalog-binding.v1`: advisory id/digest, case ref, expected hash, `catalog_present`) for every completed finding run. `RunArtifacts` gained `ConditionCatalogPath`/`CatalogBindingPath`. | `internal/productb/triage/artifacts.go`, `conditioncatalog.go`, `cmd/izyan/triage.go` |
| `catalog-binding.v1` in S-17 registry | Registered with `Ported: true` (in-repo producer/consumer); `condition-catalog.v1` flipped to `Ported: false` — consumed in-repo but produced only by the external Product A checker/registry. Both added to `requiredSchemas` and the ported-surface test. | `internal/productb/registry.go`, `registry_test.go` |
| Heldout CI split | `heldout-build` (vet+compile, always on) and `heldout-admission` (corpus replay) are separate jobs; the admission job now **fails and names `vars.HELDOUT_CORPUS`** when the pinned corpus is absent — merge-ineligible, no silent skip. New `postport-census` job fails naming `vars.CENSUS_CORPUS`. | `.github/workflows/ci.yml`, `docs/dev/ownership-and-ci.md` |
| Kernel parity + post-port safety (item 7) | `kernelparity_test.go`: real `evidencetools.Session` → `ClientCaller` → `DeterministicTools` → `RecordedObservation` end-to-end over `testdata` fixtures — code-absence admission chain (COMPLETE recorded shape), blocking fixtures for skipped-package, open-dynamic-dispatch, LIVE-referenced, UNKNOWN-unresolved and foreign-snapshot states, and symbol-unreachability payload parity (`UnreachabilityObservationApproved` + `MintUnreachabilityProof` over the producer's exact wire shape). | `internal/productb/triage/kernelparity_test.go` |

### New tests

`replay_catalog_test.go`: `recordProposalRun` fixture (agent scripts a `verify_code_absence` det call + a falsifier proposal) — `TestReplayMissingCatalogFailsClosed`, `TestReplayForeignCatalogFailsClosed`, `TestReplayTamperedCatalogFailsClosed` all assert fail-closed replay; `TestGateFalsifierProposalsParity` pins the shared partition and rejection proof shape; `TestCatalogBindingDocumentRoundTrip` pins the persisted binding decode.

### Verification (this pass)

| Command | Result |
|---|---|
| `go build ./...` | clean |
| `go vet ./...` | clean |
| `gofmt -l .` | clean |
| `go test -count=1 ./internal/productb/...` | ok ×10 packages |
| `go test -count=1 ./internal/goanalysis ./internal/evidencetools` | ok ×2 |
| `go test -count=1 ./cmd/...` | ok ×5 (incl. cmd/izyan) |
| `go test -run 'TestKernelParity' ./internal/productb/triage -v` | 4/4 pass (LIVE/UNKNOWN/PARTIAL/skipped/open-dispatch + payload parity) |
| `go test -run 'TestReplay.*CatalogFailsClosed|TestGateFalsifierProposals|TestCatalogBinding' ./internal/productb/triage -v` | 5/5 pass |

### Notes / limits

- A run persisted **before** this change (no `catalog-binding.json`) replays through the derived-binding path: the catalog's own hash becomes the expected pin, so post-hoc catalog *hash* drift is undetectable there; foreign advisory/case still reject. Documented on the new code path.
- `dynamic_markers` in the symbol-unreachability payload decodes as objects, matching V2's wire shape verbatim — the parity test asserts the recorded observation still approves, so a shape drift is caught by `TestKernelParityUnreachabilityPayload`.
- `postport-census` reuses `izyan-heldout-gate` until a dedicated census runner lands; both corpus jobs fail closed on missing input per the review.

---

## 20. Merge review follow-up (2026-10-21, fourth pass — attempt pinning, worktree flock, secrets redaction, census gate inputs)

Disposition of the third-review findings.

### Fixes — landed

| Item | Change | Files |
|---|---|---|
| Replay attempt ambiguity on multi-attempt runs | `StabilityReport.SelectedAttempt` (1-based, `stability-runs.v1` gain): the run records exactly which attempt composed the decision; `PrepareReplay` resolves the transcript through the pin (response-hash cross-check verifies, never substitutes); legacy runs without the pin fall back to the recorded hash-scan path. Foreign attempt observations filtered by the recorded run id. | `internal/productb/triage/stability.go`, `replay.go`, `runner.go`, `artifacts.go`, `cmd/izyan/triage.go` |
| Cross-process worktree mutation race | `worktreeLock` replaces the in-process `worktreeMu`: an `flock(2)` on `<gitdir>/izyan-worktree.lock` wraps every `git worktree add/prune/remove` critical section — two analyzer processes can no longer race a prune against another's add. | `internal/productb/repository/service.go`, `worktree_test.go` |
| Credential echo into artifacts | `redactSecrets` applied at every persistence boundary: `shortErr` (materials), `writeStage0Files` (stage0.json + materials.json limitations), `appendAuditLog` (audit events.jsonl). A tool stderr echoing a token can no longer land in a persisted document. | `internal/productb/triage/materials.go`, `artifacts.go`, `redact_test.go` |
| Boundary walk frozen list | `TestS12LaneIsolation` now walks `internal/productb` instead of a hardcoded package list — new adapter packages inherit the import guard without a test change. | `internal/productb/boundary_s12_test.go` |
| Falsifier-feedback budget overflow | `TestTotalStepBudgetFalsifierOverflow`: a falsifier callback that never converges hits the single total step counter; the repair turn's own chats count against it and terminal class is `step_budget`, never a hang. | `internal/productb/triage/runner_test.go` (+`sequenceChat` helper) |
| Admission-check vs heldout-gate conflation | `cmd/izyan-heldout-gate` doc comment now states it is the held-out *reporter* (§8.3 metrics; exit code reflects report pass/fail), not the admission check. `izyan triage` usage text names the falsifier-proof final gate as the admission check (non-zero exit when a cited mandatory condition lacks a VERIFIED proof) and explicitly disambiguates from `izyan-heldout-gate`. `TestAdmissionCheckGateSemantics` pins the `fatalFinalGateResult` contract. | `cmd/izyan-heldout-gate/main.go`, `cmd/izyan/triage.go`, `cmd/izyan/triage_cli_test.go` |
| `postport-census` job was a renamed heldout-gate | The job now runs the real Product-A gate: provisioned `run_census.py` (`vars.CENSUS_CORPUS` = harness dir, env-rebound via `IZYAN_REPO`/`IZYAN_CENSUS_BASE`) + `regression_guard.py --baseline-manifest $CENSUS_BASELINE` (`vars.CENSUS_BASELINE`); both inputs fail closed and are named when unprovisioned; artifacts uploaded (run log, guard log, sha256 hashes). | `.github/workflows/ci.yml`, `docs/dev/ownership-and-ci.md`, `docs/dev/retention-manifest.template.json` (`postport_census_inputs` artifact row) |

### Recomputed falsifier exposed

`ReplayReport.RecomputedFalsifier` is now exported (set from the prepared replay's recomputed falsifier run) — callers no longer need to infer the proof surface from internals.

### Tests added this pass

- `TestReplaySelectedAttemptVerifiedProof` / `TestReplaySelectedAttemptRejectsForeignObservation` (`replay_catalog_test.go`) — multi-attempt fixture where the decision composes from attempt 2; replay resolves the pinned attempt's observation set only and ignores foreign-attempt ids.
- `TestTotalStepBudgetFalsifierOverflow` (`runner_test.go`) — falsifier path inside the total step budget.
- `TestAuditLogRedactsLimitations` + material redaction cases (`redact_test.go`) — `ghp_`-style tokens never reach `audit/events.jsonl`, `stage0.json`, `materials.json`.
- `TestAdmissionCheckGateSemantics` (`triage_cli_test.go`) — falsifier `CheckUnverified` non-fatal (recorded limitation), every other non-PASS fatal; `CheckIDFalsifierProof`+`CheckConflicting`/`CheckError` fatal.
- `worktree_test.go` — parallel process-held lock contention.

### Verification (this pass)

| Command | Result |
|---|---|
| `go build ./...` | clean |
| `go vet` (touched pkgs) | clean |
| `go test -count=1 ./internal/productb/... ./cmd/...` | ok ×14 (incl. `triage` 66s, `cmd/izyan` 50s) |
| `go test -run 'TestReplaySelectedAttempt|TestTotalStepBudget|TestAdmissionCheck' -v` | all pass |

### Product-A gate status (item 3 — run, results below)

The `postport-census` job's runtime wiring is in place; the live gate ran on the developer machine against the pinned corpus:

| Gate | Result | Notes |
|---|---|---|
| `regression_guard.py --baseline-manifest r6-guard-baseline.json` | **PASS** | `cases=18 deterministic_safe=7/18 false_safe=0` |
| `run_census.py --jobs 1` (18-case census, exit 1 on drift) | **CHANGED=4, safe_fresh=8 vs safe_baseline=7** | case-03, case-04, case-09, case-10 — every changed row is already attributed in `2026-10-21-09-s05-baseline.md` §37-39 (environment improvement / harness input gap / intended V2 foreign-importer fail-closed). No new drift introduced by this pass. |
| `izyan eval --corpus eval/corpus-real.json -j 1` (38-case merged corpus) | **38/38 expected verdicts, 0 mismatches, false-safe=0** | main sweep aborted at 33/38 on the host `--mem-limit 4GiB` guard (`real-service-wrap-6443`, memory protection — not a verdict failure); tail `--case real-service-pkg-6443,real-unix-access,real-unix-stat,real-unix-fixed,real-ssh-slowpesh --mem-limit 8GiB` completed (`expect pass=5 fail=0`). The `real-yaml-file` INCONCLUSIVE row matches the S-05-attributed environment drift (`C-PEER-INPUT`, `C-CONSTRAINT`) — the corpus `expect` set already encodes it. |

**Changed-case detail (census):**

| Case | Baseline | Fresh | Attribution (S-05 §37-39) |
|---|---|---|---|
| case-03 | INCONCLUSIVE/INSUFFICIENT_SCOPE | NOT_AFFECTED/COMPLETE | environment improvement — resolved version `v1.3.6` outside affected range; matches `verdict_prev` |
| case-04 | INCONCLUSIVE/INSUFFICIENT_SCOPE | NOT_AFFECTED/COMPLETE | environment improvement — resolved version `v1.43.0` outside affected range; matches `verdict_prev` |
| case-09 | NOT_AFFECTED/COMPLETE | INCONCLUSIVE/INSUFFICIENT_SCOPE | harness input gap — baseline used a release artifact the census harness does not forward; not merge-induced |
| case-10 | NO_EXPLOIT_PATH_FOUND/COMPLETE | INCONCLUSIVE/INSUFFICIENT_SCOPE | intended V2 contract — foreign-module importer (`segmentio/kafka-go` → `klauspost/compress/s2`) marked non-enumerable; fail-closed, never false-safe |

Net deterministic-safe count rose 7→8 (03+04 recovered, 09+10 degraded); `false_safe=0` preserved.

---

## 21. Merge review follow-up (2026-10-21, fifth pass — census-gate tolerance, step-budget contract)

### Fixes — landed

| Item | Change | Files |
|---|---|---|
| `postport-census` aborted on census exit=1 before the guard ran | The step now captures `run_census.py`'s status under `set +e` (was: `pipefail` killed the step on the drift signal, skipping guard/artifacts). A hard harness failure (exit>1) fails immediately; the guard always runs; `false_safe=0` is enforced before any drift adjudication; the four S-05-attributed changes (case-03/04 env improvement, case-09 harness input gap, case-10 intended V2 fail-closed) are accepted only with `false_safe=0`; any other change is unexplained drift and fails the job. Census run log, guard log and sha256 bundle still upload `if: always()`. | `.github/workflows/ci.yml`, `docs/dev/ownership-and-ci.md` |
| Step counter checked after the provider call (off-by-one) | `spendStep` is now **reserve-before-call**: a denied exchange never reaches the wire — the provider sees at most `totalStepBudget(...)` calls. `Steps` counts issued exchanges (a reserved-but-failed call still consumed the slot). All five call sites (initial chat, initial repair chat, finalization chat, turn chat, turn repair chat) reserve first. | `internal/productb/triage/runner.go` |
| `--max-steps` contract ambiguity | Code and docs agree: `MaxSteps`/`--max-steps` is the **initial exchange-loop** budget. The run's single total counter adds 1 finalization round + the bounded feedback repair turns (`clampFactFeedbackPasses`/`clampFalsifierFeedbackPasses` at `factFeedbackMaxToolRounds+1` chats each — `+2` in `totalStepBudget` covers the repair chat and is conservative). `totalStepBudget` is now a named helper computing the cap from already-clamped configured values; the gate block reuses those values (no re-clamp, no shadowing). | `runner.go`, `cmd/izyan/triage.go` |
| Overflow tests | `TestTotalStepBudgetCoversFeedbackTurns` now asserts `client.calls == 5` (one provider call per issued step); the two overflow tests assert `calls == run.Steps` (every issued call counted — the old order could issue `totalBudget+1`). `TestTotalStepBudgetFormula` pins the configured-vs-Max formula. All use `totalStepBudget(...)` instead of inline formulas. | `runner_test.go` |

### Commands / results

| Command | Result |
|---|---|
| `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"` | valid |
| `bash -n` on the extracted census step | clean |
| Drift-adjudication script on `census-comparison.json` (4 attributed) | `rc 0 — "4 changed case(s), all S-05-attributed"; false_safe=0` |
| Same script with an injected `case-XX` change | `rc 1 — unexplained verdict drift` |
| `go build ./...` | clean |
| `go test -count=1 ./internal/productb/... ./cmd/...` | ok ×14 packages (triage 36.8s, cmd/izyan 31.7s) |
| `go test -run 'TestTotalStepBudget' -v ./internal/productb/triage` | 4/4 pass |

### Notes

- `totalStepBudget` is deliberately conservative: feedback turns only run on an accepted assessment and finalization only on a rejected one, so the formula over-reserves the worst case — the reserve-before-call counter is the hard stop, the formula is the documented ceiling.
- `--max-steps` stays the initial-loop budget (contract clarification, not a semantic change): runs legitimately exceed it through the finalization round and bounded repair turns; the total is what the step counter enforces.

---

## 22. Merge review follow-up (2026-10-21, sixth pass — worktree flock, audit redaction depth, legacy unbound-catalog replay)

### Fixes — landed

| Item | Change | Files |
|---|---|---|
| Concurrent `git worktree add/remove` across analyzer processes races on `.git/worktrees` metadata | New `internal/gitlock`: OS-flock guard on `<gitdir>/izyan-worktree.lock`, held for the whole add/remove critical section. Wired into **Product-A** `repository.NewWorktree` (add + deferred remove) and **Product-B** `productb/repository.NewWorktree` + `releaseEvidence` checkout + `cmd/izyan remediate` (`--worktree` add). The in-process mutex still guards same-process writers; the flock closes the inter-process hole. | `internal/gitlock/gitlock.go`, `internal/repository/service.go`, `internal/productb/repository/service.go`, `cmd/izyan/remediate.go` |
| Credential-shaped text survived audit persistence inside **nested** projections and intake fields | Recursive redaction extended to stage0 `materialization` metadata, `ref-selection` projections, intake `fields`/`limitations`, and tool-audit `limitations`; token patterns cover `ghp_`/`github_pat_`/`glpat-`/`xox[baprs]-` at realistic lengths plus generic `api_key`/`secret`/`token`/`password` env spellings. Bearer/`Authorization` headers redact too. | `internal/productb/triage/artifacts.go`, `internal/productb/triage/intake_audit.go`, `internal/productb/triage/redact_test.go` |
| Legacy run with `condition-catalog.json` but no `catalog-binding.json` replayed under a **derived** pin | `PrepareReplay` now refuses proof-bearing legacy runs with named `ErrLegacyCatalogUnbound`: self-hash acceptance cannot detect post-run catalog drift. Explicit opt-in `ReplayOptions.AllowLegacyUnboundBinding` (CLI `--replay-legacy-unbound`) proceeds, records the weakened provenance in `rep.Limitations` → `replay.json` `limitations` + the replay audit event. | `internal/productb/triage/replay.go`, `cmd/izyan/triage.go` |

### Tests added this pass

- `internal/gitlock/gitlock_cross_test.go` — `TestCrossProductWorktreeLock` (A-add vs B-add serialize on the same repo), `TestCrossProductInterProcessLock` (subprocess contention, no leaked registrations), `TestAcquireSerializes`/`TestAcquireBlocker` (flock mutual exclusion: child blocked while parent holds, marker lands only after release).
- `internal/productb/triage/redact_test.go` — `TestAuditLogRedactsNestedProjections`, `TestIntakeAuditRedactsNestedFields`, `TestStage0ArtifactsRedactNestedLimitations` (36-char `ghp_`, `github_pat_`, `glpat-` inside nested docs).
- `internal/productb/triage/replay_catalog_test.go` — `TestReplayLegacyUnboundRefusesProof` (default refuses, `errors.Is(ErrLegacyCatalogUnbound)`), `TestReplayLegacyUnboundOptIn` (two-attempt fixture replays VERIFIED + limitation recorded), `TestReplayLegacyNoProofUnaffected` (catalog file without proof surface never reaches the binding branch).

### Commands / results

| Command | Result |
|---|---|
| `go build ./...` | clean |
| `go vet ./internal/gitlock ./internal/repository ./internal/productb/... ./cmd/izyan` | clean |
| `go test -count=1 ./internal/gitlock` | 4/4 (incl. subprocess-lock cases, ~3.4s) |
| `go test -count=1 ./internal/productb/...` | ok ×7 packages |
| `go test -count=1 ./internal/repository ./internal/productb/repository` | ok |
| `go test -count=1 ./cmd/izyan` | ok (27.2s) |
| `go test -run 'TestReplayLegacy' -v ./internal/productb/triage` | 3/3 pass |

### Notes / deviations

- The opt-in is deliberately caller-visible (option struct + CLI flag), never an env toggle: the derived-pin acceptance is a provenance downgrade and must be a decision, not a default.
- `ReplayDocument` gained `limitations` — additive `omitempty` field on a Product-B-owned schema; no replay/parse break.
- The legacy refusal triggers only when the proof surface exists (`replayCatalog != nil` inside the falsifier branch): a run with a stray catalog file and no proposals replays unchanged.
- The single-attempt `recordProposalRun` fixture's persisted report is hand-built (not verifier output), so its replay legitimately drifts at recomposition; the fail-closed tests only need the *refusal/drift* side. The positive opt-in test uses `recordTwoAttemptProposalRun`, whose report is verifier-produced and replays byte-identical under an honest derived binding.

---

## 23. Merge review follow-up (2026-10-21, seventh pass — fail-closed worktree cleanup, portable flock)

Security re-check found two residual issues in the follow-up-6 lock work; both fixed in `a833aa5`.

### Fixes — landed

| Item | Change | Files |
|---|---|---|
| **Unlocked cleanup mutation (Product B)** | `NewWorktree` cleanup ran `git worktree remove --force` even when `gitlock.Acquire` failed — an unlocked mutation of shared `.git/worktrees`. Cleanup is now `func() error`: on lock failure **no** git mutation runs, the worktree's own temp files are still removed (not shared metadata), and the call returns `ErrWorktreeCleanupSkipped` (named error wrapping the acquire failure). The stale registration is reconciled by a later locked `git worktree prune` (the add path already prunes registered-but-dead entries). | `internal/productb/repository/service.go` |
| **Same contract aligned (Product A)** | `internal/repository.NewWorktree` cleanup identical semantics — `func() error`, named `ErrWorktreeCleanupSkipped`, never unlocked. Callers record instead of discarding: `cmd/izyan main.go` both `defer` sites print the named error to stderr; `cmd/izyan triage.go` stage0-failure cleanup logs it; `MaterializedSource.Cleanup` type is `func() error` end to end. | `internal/repository/service.go`, `cmd/izyan/main.go`, `cmd/izyan/triage.go`, `internal/productb/triage/{materialize,stage0,replay}.go` |
| **`syscall.Flock` is unix-only; CI builds windows/amd64** | New `internal/flock`: `flock_unix.go` (`flock(2)` `LOCK_EX`), `flock_windows.go` (`x/sys/windows.LockFileEx` exclusive blocking — same advisory semantics), `flock_other.go` (`ErrUnsupported`, fail-closed — no lock taken, no file created). `gitlock.Acquire` and `triage.claimRunDir` (`.owner.lock`) route through it. `golang.org/x/sys` promoted to a direct dep by `go mod tidy`. | `internal/flock/*`, `internal/gitlock/gitlock.go`, `internal/productb/triage/artifacts.go`, `go.mod` |
| **Failure-injection coverage** | `var acquireWorktreeLock = gitlock.Acquire` seam in both repository packages; new `TestWorktreeCleanupLockFailureFailsClosed` in each asserts: cleanup returns `ErrWorktreeCleanupSkipped`, `worktree list` still shows the registration (no unlocked remove ran), temp dir removed, later `git worktree prune` reconciles. | `internal/productb/repository/worktree_test.go`, `internal/repository/service_test.go` |
| **Adapter import gate** | `internal/flock` added to `allowedInternalImports` + a `MappedToCanonical` typemap row — the mechanical completeness gate pins it as a Shadow-new primitive, not a V2 surface. | `internal/productb/typemap{,_test}.go` |

### Audit — remaining worktree command surface

`git worktree` exec sites (non-test): `internal/repository/service.go` add:510 + remove:527 (both inside `acquireWorktreeLock`), `internal/productb/repository/service.go` add:458/prune:464/retry-add:466 + remove:486 (all lock-gated), `worktree list --porcelain` at :506 (read-only, never mutates), `cmd/izyan/remediate.go:100` add (inside `gitlock.Acquire`). **No unlocked mutation path remains.** Non-cooperating external processes bypassing `gitlock` are outside the contract by construction — the lock is advisory.

### Commands / results

| Command | Result |
|---|---|
| `go build ./...` | clean |
| `GOOS=windows GOARCH=amd64 go build -o izyan-windows-amd64.exe ./cmd/izyan` | **clean** (was: `undefined: syscall.Flock` ×4) |
| `GOOS=plan9 GOARCH=amd64 go build ./internal/{flock,gitlock,repository,productb/repository}` | clean (fail-closed `ErrUnsupported` path) |
| `go vet ./...` | clean |
| `go test -count=1 ./internal/productb/repository ./internal/repository ./internal/gitlock ./cmd/izyan` | ok ×4 |
| `go test -count=1 ./...` | **ok — all packages** (goanalysis 176.8s, research 101.3s, triage 45.9s) |
| `TestWorktreeCleanupLockFailureFailsClosed` (A + B) | pass — named error, registration survives for reconcile, no unlocked remove |
| `go mod tidy` | `x/sys` → direct; no other changes |

### Residual risks

- `flock(2)`/`LockFileEx` block uninterruptibly — the 10s cleanup context bounds `git rev-parse` and the `worktree remove`, but a leaked/hung peer lock can still block an acquirer until the OS releases it (process exit always does). Advisory locking cannot do better.
- A cleanup skipped on lock failure leaves `.git/worktrees/<id>` registration until a later locked prune — bounded, self-healing, and now observable via the returned error.
- `MaterializedSource.Cleanup` type change (`func()` → `func() error`) is an exported-field signature change inside `internal/`; all in-repo callers compile and record.

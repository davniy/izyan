# Evidence Target Provenance and Tool-Run Outcomes Implementation Plan

**Goal:** Admit build-dependent negative evidence only when it describes an identified product build and a successfully completed measurement with the required coverage.

**Architecture:** Keep `ProductSnapshot` as the effective in-flight build context and `ProductTarget` as its provenance authority. Persist compact context and measurement records on evidence, then enforce the same admission rules at producers, negative verification, verdict admission, scan filtering, and exports. Preserve independent positive evidence.

**Tech stack:** Go 1.25, standard-library JSON and testing, existing `go/packages`, govulncheck runner, workflow, and evaluation harness.

**Spec:** `docs/dev/plans/2026-10-25-03-evidence-target-provenance.md`

All paths below are relative to the repository root. This is a read-only plan; none of the validation commands below has been executed.

## Global Constraints

1. **Two independent gates**
   - A build-dependent negative requires a non-nil `ProductTarget` whose `Validate()` succeeds, whose `Scoped()` is true, and whose build facts match the effective context.
   - Its measurement must have completed successfully and covered the subject and scope being negated.
   - Failure of either gate produces `UNKNOWN`, not `FALSE` plus a limitation.

2. **Target precedence remains**
   ```
   artifact-build-info > release-metadata > operator-declared > host-default
   ```
   Plain `--binary` joins the existing digest-bound artifact-build-info route.

3. **No inferred product targets**
   - Do not derive an admitting target from CI, Dockerfiles, `_linux.go`, imports, deployment manifests, release names, or host-filled flag values.
   - Partial `--goos`/`--goarch` and tags-only inputs remain non-admitting.
   - `--release` selects source identity; `--deploy-manifests` supplies perimeter evidence.

4. **Resolve once, before loading**
   Affected resolution, govulncheck, source analysis, root-cause verification, and negative verification must use the same resolved snapshot, platform, tags, CGO, toolchain, vendor/module mode, and workspace context. Never relabel an already-loaded index.

5. **Positive evidence remains independent**
   - A govulncheck failure is not a case-wide veto.
   - Do not remove Podman’s module-chain positive to improve calibration.
   - Do not change library-API admission: **DESERIALIZATION + CWE-502 remains the admitted class**.

6. **Scope remains bounded**
   A negative for one analyzed build does not assert a support matrix. Preserve the additional supported-targets-assumption requirements already used by implementation-presence conclusions.

7. **Clean cutover**
   Remove `AnalysisCase.GovulncheckCoverage`, evidence-presence success inference, raw-output baseline bypasses, and obsolete helpers once their callers migrate. Historical records lacking the new metadata are non-admitting; do not fabricate successful outcomes during load.

8. **Validation discipline**
   Task owners use only the focused commands for their task. The integration owner runs formatting, vet, the complete test suite, and each full corpus once after all tasks land.

---

## Review Focus

| Risk | Owning task and required test |
|---|---|
| Empty, `{}`, bare header, malformed suffix, or failed-process prefix becomes “clean” | Task 1: strict parser and recorder matrix |
| Exit code 3 is treated as failure | Task 1: retain `TestExecRunnerExitCode3IsSuccess` |
| Missing runner or auxiliary-tool budget refusal leaves no durable outcome | Task 1: `not_run` recording |
| Root-cause lookup loads the source index before context binding | Task 2: bind in `SnapshotProduct`, not `CollectEvidence` |
| A shared cache returns output from another build | Task 2: cache-context mismatch tests |
| Plain `--binary` remains host-default | Task 2: digest-bound binary target tests |
| Partial package stdout proves package absence or `RootCause.Absent` | Task 3: execution-error and error-node tests |
| Linked locus packages plus empty collections prove function unreachability | Task 4: independent locus-measurement tests |
| Persisted `VERIFIED` bypasses the new gates | Tasks 4–5: verdict and direct-export replay tests |
| Target gating accidentally blocks module/version/release/deployment facts | Tasks 3–4: explicit independent-fact controls |
| Failure suppresses valid module-chain/direct-call positives | Tasks 1, 4, 6: positive-preservation controls |
| Calibration improves only because a run timed out | Task 6: evidence-level false-alarm ledger |

## Frozen Interfaces

Implement these contracts in Task 1 so later work does not invent competing representations.

### Context and evidence metadata

Create `internal/domain/buildcontext.go`:

```go
type BuildContext struct {
    Repository        string             `json:"repository"`
    Commit            string             `json:"commit"`
    ExternalCommitSHA string             `json:"external_commit_sha,omitempty"`
    ContentHash       string             `json:"content_hash,omitempty"`

    GOOS              string             `json:"goos"`
    GOARCH            string             `json:"goarch"`
    BuildTags         []string           `json:"build_tags,omitempty"`
    CGOEnabled        bool               `json:"cgo_enabled"`

    GoVersion         string             `json:"go_version"`
    GoModDirective    string             `json:"go_mod_directive,omitempty"`
    VendorMode        bool               `json:"vendor_mode"`
    GoWorkFile        string             `json:"go_work_file,omitempty"`
    GoFlags           string             `json:"go_flags,omitempty"`
    ReplaceDirectives []ReplaceDirective `json:"replace_directives,omitempty"`

    BinaryPath        string             `json:"binary_path,omitempty"`
    BinarySHA256      string             `json:"binary_sha256,omitempty"`
}

var ErrBuildContextMismatch error

func EffectiveBuildContext(s ProductSnapshot) BuildContext
func (b BuildContext) Matches(other BuildContext) error
func ValidateNegativeTarget(s ProductSnapshot) error
```

Contracts:

- `BuildContext` is a derived measurement identity, **not another provenance source**. It contains no target `Source` or `Scope`.
- `Matches` compares every recorded field; build tags compare order-insensitively. It returns an error naming the divergent field and wrapping `ErrBuildContextMismatch`.
- Copy mutable slices when capturing a context.
- `ValidateNegativeTarget` validates `s.Target`, rejects host-default, and compares its platform/tags/CGO facts with `s`. It does not require a supported-targets assumption.
- Add `ProductSnapshot.GoFlags string` to record the effective flags used for package loading. Task 2 resolves this field.

Create `internal/domain/measurement.go`:

```go
type GovulncheckOutcome string

const (
    GovulncheckCompletedWithResults GovulncheckOutcome = "completed_with_results"
    GovulncheckCompletedEmpty       GovulncheckOutcome = "completed_empty"
    GovulncheckFailed               GovulncheckOutcome = "failed"
    GovulncheckNotRun               GovulncheckOutcome = "not_run"
)

type GovulncheckAdvisoryCoverage string

const (
    GovulncheckCoverageUnknown GovulncheckAdvisoryCoverage = "unknown"
    GovulncheckCoverageCovered GovulncheckAdvisoryCoverage = "covered"
    GovulncheckCoverageNotInDB GovulncheckAdvisoryCoverage = "not_in_db"
)

type GovulncheckCoverage struct {
    AdvisoryID    string                       `json:"advisory_id"`
    Advisory      GovulncheckAdvisoryCoverage   `json:"advisory"`
    Subjects      []SymbolRef                  `json:"subjects,omitempty"`
    ScopeComplete bool                         `json:"scope_complete"`
}

type GovulncheckRun struct {
    Outcome   GovulncheckOutcome  `json:"outcome"`
    Pattern   string             `json:"pattern,omitempty"`
    Mode      string             `json:"mode,omitempty"`
    ScanLevel string             `json:"scan_level,omitempty"`
    Coverage  GovulncheckCoverage `json:"coverage"`
    Error     string             `json:"error,omitempty"`
}

type PackageListRun struct {
    Completed bool   `json:"completed"`
    Complete  bool   `json:"complete"`
    WithTests bool   `json:"with_tests"`
    Pattern   string `json:"pattern"`
    Error     string `json:"error,omitempty"`
}

type SourceScanRun struct {
    Module       string      `json:"module"`
    Subjects     []SymbolRef `json:"subjects,omitempty"`
    EntrySymbols []string    `json:"entry_symbols,omitempty"`
    Completed    bool        `json:"completed"`
    Complete     bool        `json:"complete"`
    Opaque       bool        `json:"opaque"`
}
```

Extend existing structures in `internal/domain/domain.go`:

```go
// Evidence
BuildContext *BuildContext    `json:"build_context,omitempty"`
Govulncheck  *GovulncheckRun   `json:"govulncheck,omitempty"`
PackageList  *PackageListRun  `json:"package_list,omitempty"`
SourceScan   *SourceScanRun   `json:"source_scan,omitempty"`

// NegativeVerification
BuildContext *BuildContext `json:"build_context,omitempty"`
```

The evidence’s existing `Tool` identifies the source-scan operation. Do not duplicate findings or raw output inside `GovulncheckRun`; keep the raw stream in `Evidence.Content` and findings in the existing parsed/result structures.

Also provide:

```go
func SelectCompletePackageList(
    product ProductSnapshot,
    evidence []Evidence,
) (Evidence, error)
```

This is a pure metadata selector: require completed, complete, matching-context package-list evidence. It does not decode JSON or import `affected`. A consumer still uses the strict package decoder from Task 3.

### Shared govulncheck recorder

Create `internal/goanalysis/govulncheck_record.go`:

```go
func CollectGovulncheck(
    ctx context.Context,
    runner Runner,
    build domain.ProductSnapshot,
    vuln domain.Vulnerability,
) (domain.Evidence, Result)
```

It always returns one `EvidenceGovulncheck` record, including nil-runner, execution-error, cancellation, and parse-error paths. On failure, the returned `Result` contains no consumable findings; the raw prefix remains in evidence for audit.

Keep the existing `Runner.RunGovulncheck` signature. Do not invent an exit code after `ExecRunner` has normalized exit 3 to success; actual exit codes remain in `ToolExecution`.

### Verdict input

Task 4 replaces the current three-argument verdict API with:

```go
type VerdictInput struct {
    Product  domain.ProductSnapshot
    Affected domain.AffectedResult
    Model    domain.ExploitModel
    Claims   []domain.Claim
    Evidence []domain.Evidence
}

func (VerdictEvaluator) Evaluate(in VerdictInput) domain.VerdictResult
```

This supports persisted-evidence admission and the existing perimeter-profile claim override without copying `AnalysisCase` or `EvidenceGraph`, both of which contain mutexes.

---

### Task 1: Durable govulncheck outcomes, strict parsing, and run-aware reachability fallback

**Depends on:** None.

**Files:**
- Create: `internal/domain/buildcontext.go`
- Create: `internal/domain/buildcontext_test.go`
- Create: `internal/domain/measurement.go`
- Create: `internal/domain/measurement_test.go`
- Modify: `internal/domain/domain.go`
- Modify: `internal/goanalysis/govulncheck.go`
- Create: `internal/goanalysis/govulncheck_record.go`
- Modify: `internal/goanalysis/govulncheck_test.go`
- Modify: `internal/states/states.go`
- Create: `internal/states/govulncheck_outcome_test.go`
- Modify: `internal/llm/tools.go`
- Modify: `internal/llm/tools_test.go`
- Modify: `internal/evaluator/conditions.go`
- Modify: `internal/evaluator/conditions_test.go`
- Modify protocol fixtures in:
  - `internal/states/states_test.go`
  - `internal/states/library_scope_e2e_test.go`
  - `internal/eval/baseline_test.go`
  - `internal/evidencetools/hardening_test.go`
  - Other parser fixtures identified by the existing `goanalysis.Parse` callers

**Interfaces:**
- Consumes: existing `Runner`, `Result`, `EvidenceGraph.AddEvidence`, `EvidenceGraph.ComputeHash`.
- Produces: all frozen domain contracts and `CollectGovulncheck`.
- Keep:
  ```go
  func Parse(raw []byte) (Result, error)
  ```
- Extend `Result` with parsed protocol configuration and advisory-declared symbol coverage from the stream’s OSV documents.
- Change the private fallback signature to:
  ```go
  func libraryUsageVerdict(
      claim domain.Claim,
      c *domain.AnalysisCase,
      subjects []domain.SymbolRef,
      why string,
      positiveOnly bool,
  ) domain.Claim
  ```

**Implementation steps:**

- [ ] Add a parser table covering:
  - Empty and whitespace-only input.
  - `{}`, `null`, arrays, bare top-level protocol header.
  - Missing or invalid initial `config.protocol_version`.
  - Malformed finding/OSV payload.
  - Valid prefix followed by malformed or trailing non-JSON content.
  - Valid config-only stream.
  - Valid config + OSV + finding stream.

- [ ] Require the actual stream framing: an initial `config` message with supported `protocol_version`, followed by fully decoded messages through EOF. A valid config-only stream is completed-empty only after successful process completion; it does not establish advisory or symbol coverage.

- [ ] Migrate old fake streams such as:
  ```json
  {"protocol_version":"v1.0.0"}
  ```
  to valid configuration messages. Split fixtures that currently put multiple protocol message types in one object.

- [ ] Implement `CollectGovulncheck`:
  - Nil runner → `not_run`.
  - Process error, timeout/cancellation, or parse failure → `failed`.
  - Successful valid stream with findings → `completed_with_results`.
  - Successful valid stream without findings → `completed_empty`.
  - Preserve raw content, actual pattern, tool version/DB information, context, and failure reason.
  - Determine outcome from the run’s actual findings, not merely findings matching the current advisory.
  - Never publish call paths from a failed process’s parseable prefix.

- [ ] Replace `states.CollectEvidence.runGovulncheck`’s record-before-parse flow with the shared recorder. Invoke it even when the configured runner is nil; attach returned call paths only for completed results and bind each path to the returned evidence ID.

- [ ] Migrate `llm.Tools.Call("run_govulncheck")` to the same recorder. Preserve an evidence ID on failure. Record `not_run` for a requested govulncheck action rejected before execution, including runner absence and exhausted tool budget.

- [ ] Remove `AnalysisCase.GovulncheckCoverage` and migrate all readers/tests to run metadata. Remove `govulncheckRan` as an evidence-presence success test.

- [ ] Make failed/not-run/legacy-untyped run fallback positive-only:
  - Direct calls and existing module-chain positives remain usable.
  - Zero module usage returns `UNKNOWN`.
  - No `no-module-usage`, `unreached-exported-subject`, or dead-code negative is emitted by that fallback.

- [ ] Permit govulncheck-silence only as a candidate from a context-matching `completed_empty` record with full advisory, subject, and scan-scope coverage. A completed-with-results run’s missing paths do not prove other subjects unreachable.

- [ ] Remove the remote `dbKnowsAdvisory` upgrade from negative coverage. A remote OSV listing does not establish coverage in the database actually scanned. Remove its obsolete `CollectEvidence.OSVBase` field and constructor assignment if no longer used.

- [ ] Treat narrowed `./cmd/...` results as partial scope unless a completed, matching build-context census establishes the exact scope being negated. The current directory/main-file heuristic must not grant full coverage. Preserve fallback positives.

- [ ] Add JSON round-trip and hash tests:
  - Outcome, coverage, and context survive serialization.
  - Changing each changes `EvidenceGraph.ComputeHash()`.
  - Legacy evidence without metadata is non-admitting.
  - Separate cases using cached raw output receive separate metadata values.

**What not to change:**
- Exit-3 success handling.
- Runner execution fallback policy.
- Library class/CWE admission.
- Module-chain positive semantics.
- General LLM budget policy.

**Focused validation:**

Run before implementation for the new assertions, expecting failure; repeat after implementation, expecting pass:

```bash
go test -count=1 ./internal/domain \
  -run 'TestBuildContext|TestValidateNegativeTarget|TestMeasurement'

go test -count=1 ./internal/goanalysis \
  -run 'TestParseGovulncheck|TestCollectGovulncheck|TestExecRunnerExitCode3IsSuccess|TestExecRunnerDBInfoPinsDB'

go test -count=1 ./internal/states ./internal/llm ./internal/evaluator \
  -run 'TestGovulncheckOutcome|TestToolRunGovulncheck|TestReachabilityRunOutcome|TestE2EGovulncheckFailureStaysInconclusive'
```

Also run the existing focused parser-consumer tests after fixture migration:

```bash
go test -count=1 ./internal/eval ./internal/evidencetools \
  -run 'TestBaselineSeparates|TestStrictGovuln|TestGovulnDB'
```

**Acceptance:** Every collector/auxiliary invocation path has durable typed outcome evidence. Failed, skipped, malformed, and untyped legacy runs cannot generate silence-derived negatives. Independent positive reachability remains intact.

---

### Task 2: Resolve and bind one effective product build before any package load

**Depends on:** Task 1.

**Files:**
- Modify: `internal/domain/target.go`
- Modify: `internal/domain/buildcontext.go`
- Modify: `internal/repository/service.go`
- Modify: `internal/repository/artifact.go`
- Modify: `internal/repository/service_test.go`
- Modify: `internal/repository/artifact_test.go`
- Create: `internal/repository/binarytarget_test.go`
- Modify: `internal/goanalysis/source.go`
- Modify: `internal/goanalysis/govulncheck.go`
- Modify: `internal/goanalysis/loaderenv_test.go`
- Create: `internal/goanalysis/buildcontext_test.go`
- Modify: `internal/affected/golist.go`
- Create: `internal/affected/buildcontext_test.go`
- Modify: `internal/states/states.go`
- Modify: `internal/states/states_test.go`
- Modify: `cmd/izyan/main.go`
- Create: `cmd/izyan/buildcontext_test.go`
- Modify: `internal/evidencetools/service.go`
- Modify: `internal/evidencetools/dependencies.go`
- Modify corresponding `internal/evidencetools` environment tests where the new snapshot field must be populated.

**Interfaces:**

```go
// internal/goanalysis/source.go
func (ix *Index) BindBuild(snap domain.ProductSnapshot) error
func (ix *Index) BoundBuildContext() (domain.BuildContext, bool)

// internal/domain/buildcontext.go
func BuildEnv(s ProductSnapshot) []string

// internal/repository/artifact.go
func targetFromBuildInfo(
    bi *debug.BuildInfo,
    artifactSHA256, buildInfoSHA256, member string,
) *domain.ProductTarget

func buildInfoTargetFromPath(
    ctx context.Context,
    binaryPath string,
) (*domain.ProductTarget, error)

// internal/repository/service.go
func resolveProductTarget(
    artifact, binary, release *domain.ProductTarget,
    opts SnapshotOptions,
) domain.ProductTarget
```

Extend `states.SnapshotProduct` with:

```go
Source   *goanalysis.Index
Snapshot *domain.ProductSnapshot
```

Extend private `analyzeOpts` with:

```go
snapshot *domain.ProductSnapshot
```

**Implementation steps:**

- [ ] Add precedence tests for artifact, plain binary, release metadata, paired operator flags, partial flags, tags-only, and host default.

- [ ] Extract the existing build-info target logic into `targetFromBuildInfo`; keep its duplicate-setting, CGO, tag, and digest validation.

- [ ] For plain `--binary`, reuse that extraction with:
  - `ArtifactSHA256 == BuildInfoSHA256 ==` the selected binary’s SHA-256.
  - `BinaryMember == ""`, matching the existing bare-artifact convention.
  - Binary target precedence above release metadata and operator flags.
  - A target-only extraction gap recorded separately from release-toolchain availability; it must not invalidate an otherwise measured binary toolchain version.

- [ ] Resolve workspace, effective `GOFLAGS`, vendor/module context, and replacement directives into the snapshot before package loading. An inactive workspace must be recorded/applied as `off`, not inherited differently by different probes.

- [ ] Replace divergent environment builders with `domain.BuildEnv`. Apply:
  ```
  ambient or existing isolation whitelist
      → toolchain/environment policy
      → resolved build-selection environment
  ```
  `GOOS`, `GOARCH`, CGO, workspace, and effective flags must describe the snapshot. Preserve strict egress/cache restrictions and `-mod=readonly` where applicable; do not replace the existing strict policy with an ambient environment.

- [ ] Make `BindBuild` synchronized and idempotent:
  - Matching context → success.
  - Different context before the first load → bind the resolved snapshot.
  - Different context after a load → `ErrBuildContextMismatch`, without mutation.
  - Detect later changes to public `Index.Build` before subsequent loads/queries; a saved loaded context is not relabelled.

- [ ] Bind in `SnapshotProduct.Run` immediately after obtaining `c.Product`, **before** root-cause resolution. Binding in `CollectEvidence` is too late: root-cause lookup already loads the index.

- [ ] On binding failure, transition to `StateFailed`; do not continue with mismatched evidence.

- [ ] Reorder `runScan`:
  ```
  resolveToolchain
      → buildSnapshotOptions
      → Snapshot
      → construct shared index/tool/runner
      → module listing
      → affected prefilter
      → survivor workflows
  ```
  Replace raw `listModules` subprocess execution with the existing affected-tool module listing/decoder under the resolved snapshot.

- [ ] Pass the resolved scan snapshot through `analyzeOpts.snapshot` to `SnapshotProduct`. Validate its repository identity and emit per-case runtime provenance without independently resolving a different snapshot.

- [ ] Guard `CachingRunner` and `CachingTool` against context reuse: capture the first effective context and reject a different context. Keep the current single-build cache model; do not add a multi-key cache.

**What not to change:**
- No new target-inference channels.
- No new artifact/release-metadata CLI feature beyond existing surfaces.
- No supported-targets-assumption relaxation.
- No relabelling loaded ASTs.
- No general tool-execution-policy redesign.

**Focused validation:**

```bash
go test -count=1 ./internal/repository \
  -run 'TestSnapshot_TargetPrecedence|TestSnapshot_BinaryTarget|TestSnapshot_PartialOperator|TestReleaseArtifact_TargetBoundToBuildInfo'

go test -count=1 ./internal/goanalysis ./internal/affected \
  -run 'TestIndexBindBuild|TestBuildContextMutation|TestLoadConfigSharedBuildContext|TestBuildEnv|TestCaching.*BuildContext'

go test -count=1 ./cmd/izyan ./internal/states \
  -run 'TestAnalyzeResolvedBuildContext|TestScanResolvedBuildContext|TestSnapshotBindsBeforeRootCause'

go test -count=1 ./internal/evidencetools \
  -run 'TestStrictHardensToolchainEnv|TestAmbientEnvNotInherited|TestStrictGovuln'
```

**Acceptance:** Root-cause analysis, affected resolution, govulncheck, source analysis, and verification observe one resolved build context. A plain Go binary supplies digest-bound target provenance. Partial operator inputs remain host-default and non-admitting.

---

### Task 3: Complete package inventories and honest affected/root-cause absence

**Depends on:** Task 2.

**Files:**
- Modify: `internal/affected/golist.go`
- Modify: `internal/affected/usage_scope.go`
- Modify: `internal/affected/resolver.go`
- Modify: `internal/affected/resolver_test.go`
- Modify: `internal/affected/usage_scope_test.go`
- Create: `internal/affected/inventory_test.go`
- Modify: `internal/rootcause/rootcause.go`
- Modify: `internal/rootcause/rootcause_test.go`
- Create: `internal/rootcause/partiallist_test.go`

**Interfaces:**

```go
// internal/affected/golist.go
type PackageInventory struct {
    Packages []Package
    Paths    map[string]bool
}

func CompletePackageInventory(
    raw []byte,
    command string,
) (PackageInventory, error)

// Retain signature, strengthen contract:
func PackageImportPaths(raw []byte) (map[string]bool, error)
```

`CompletePackageInventory` reuses the existing `buildPackageGraph` completeness rules; it must not establish a second, weaker graph validator.

**Implementation steps:**

- [ ] Add tests for:
  - Process error plus non-empty valid stdout.
  - Truncated stream and malformed suffix.
  - Empty enumeration.
  - `Incomplete`, `Error`, and `DepsErrors`.
  - Duplicate nodes, dangling edges, orphan nodes, and inconsistent dependency inventories.
  - A valid complete absence control.
  - Partial evidence that still contains a positive package observation.

- [ ] Make the low-level decoder consume the entire input. Preserve supported array/stream inputs where existing callers require them, but never accept a valid prefix as a complete stream.

- [ ] Record package-list evidence on error as well as success. Set `PackageList.Completed` and `Complete` accurately, with the actual command, context, and error.

- [ ] In `resolvePackages`, separate positive observations from absence:
  - Partial stdout may preserve a witnessed package presence.
  - Execution error or incomplete inventory cannot establish absence, test-only exclusion, or a closed build inventory.
  - Require `ValidateNegativeTarget(product)` before setting build-dependent `PackagePresent=FALSE` or `BuildRelevant=FALSE`.

- [ ] Audit the resolver’s `versionSettled` branches. A genuine out-of-range version remains independent; a `VersionAffected=FALSE` reached only because residual subjects were absent must not bypass target/inventory admission.

- [ ] Keep module-graph absence and genuinely out-of-range version conclusions working without product-target inputs.

- [ ] Change root-cause package-list selection to `SelectCompletePackageList` plus the strict decoder. Set `RootCause.Absent` only from an admitted complete matching inventory. A failed lookup with no admitted absence inventory remains unverified/ambiguous.

**What not to change:**
- Version-range arithmetic.
- Advisory identity/scope admission.
- Module-graph absence semantics.
- Existing dynamic/build-exclusion conservatism.
- Positive facts merely because another package failed.

**Focused validation:**

```bash
go test -count=1 ./internal/affected \
  -run 'TestPackageInventory|TestResolvePartialList|TestResolvePackageAbsent|TestVersionInRangePackageAbsent|TestModuleListFailureIsUnknown|TestUsageScope'

go test -count=1 ./internal/rootcause \
  -run 'TestRootCauseAbsent|TestRootCausePartialPackageList'
```

**Acceptance:** Neither partial stdout nor error-bearing package nodes can prove product absence, test-only exclusion, or `RootCause.Absent`. Host-default runs retain unknown build-dependent absence axes; independent module/version negatives remain available.

---

### Task 4: Close evaluator, locus, verifier, persisted-verdict, and scan-prefilter bypasses

**Depends on:** Task 2.  
**Integration prerequisite:** Task 3 before final integration validation. This task can be implemented against the frozen typed package-list records while Task 3 works on their production.

**Files:**
- Create: `internal/domain/negative_admission.go`
- Create: `internal/domain/negative_admission_test.go`
- Modify:
  - `internal/evaluator/conditions.go`
  - `internal/evaluator/locus.go`
  - `internal/evaluator/platform.go`
  - `internal/evaluator/presence.go`
  - `internal/evaluator/configflag.go`
  - `internal/evaluator/provenance.go`
  - `internal/evaluator/validation.go`
  - `internal/evaluator/missingcall.go`
  - `internal/evaluator/transport.go`
  - `internal/evaluator/exposure.go`
  - `internal/evaluator/postreach.go`
  - `internal/evaluator/verdict.go`
- Modify corresponding evaluator tests; create:
  - `internal/evaluator/target_admission_test.go`
  - `internal/evaluator/measurement_admission_test.go`
- Modify:
  - `internal/goanalysis/source.go`
  - `internal/goanalysis/negative.go`
  - `internal/goanalysis/locusverify.go`
  - `internal/goanalysis/dispatch_test.go`
  - `internal/goanalysis/locusverify_test.go`
  - `internal/goanalysis/negative_test.go`
  - `internal/evidencetools/dynamic.go`
  - `internal/states/states.go`
  - `internal/states/module_usage_test.go`
  - `internal/states/states_test.go`
  - `internal/states/p0_safety_test.go`
  - `internal/research/decision.go`
  - `internal/research/deterministic.go`
  - Their affected research tests
  - `cmd/izyan/main.go`
  - `cmd/izyan/scan_test.go`

**Interfaces:**

```go
// internal/domain/negative_admission.go
func NegativeRequiresTarget(claim Claim, cond Condition) bool

func ValidateNegativeEvidence(
    product ProductSnapshot,
    claim Claim,
    cond Condition,
    evidence []Evidence,
) error

func ValidateVerifiedNegative(
    product ProductSnapshot,
    claim Claim,
    cond Condition,
    evidence []Evidence,
) error

func ValidateAffectedNegative(
    product ProductSnapshot,
    affected AffectedResult,
    evidence []Evidence,
) error
```

`ValidateNegativeEvidence` validates candidate prerequisites; `ValidateVerifiedNegative` additionally requires the existing verification status and matching verification context. Neither performs source analysis.

Use the frozen `VerdictInput` API.

Replace `ModuleInternalReach`’s tuple result with:

```go
type ModuleReachabilityResult struct {
    Reachable map[string][]string
    Complete  bool
    Opaque    bool
}

func (ix *Index) ModuleInternalReach(
    ctx context.Context,
    module string,
    entries []string,
    subjects []domain.SymbolRef,
) (ModuleReachabilityResult, error)
```

Migrate its callers in `states`, `evidencetools`, and `dispatch_test.go`; do not retain a compatibility wrapper.

**Implementation steps:**

- [ ] Add a table-driven negative-admission matrix covering every existing falsifier, host/scoped/mismatched context, missing measurement, and persisted verification.

- [ ] Classify by actual basis, not explanation text:
  - **Target-dependent:** govulncheck silence, module/source absence and unreachability, reader/pair/symbol proofs, code-selected configuration/guards/input proofs, code-selected protocol-role/listener inventories.
  - **Independent:** complete module-graph/version facts, release-toolchain-only facts, repository-config-key facts, and actual deployment-policy evidence.
  - `trusted-infrastructure` is independent only for its legitimate declared-trust/auto-perimeter bases; config-origin is build-selected.
  - Missing/unknown basis defaults conservatively.
  - For `loopback-only`, distinguish manifest-derived deployment facts structurally from loaded-code facts using `FalsifierBasis`; add `BasisDeployment` for the manifest-only route.
  - For platform checks, evaluate release-version contradictions separately from platform contradictions. A host GOOS/GOARCH mismatch cannot produce FALSE; an independently measured release-version contradiction must remain usable.

- [ ] Apply admission before each affected evaluator returns a build-dependent FALSE. Direct calls to individual evaluators must receive the same behavior as workflow dispatch.

- [ ] Record typed `SourceScanRun` metadata for module-usage and module-internal checks. Include module, exact subjects, entry symbols, completion, opacity, and matching context.
  - Do not infer coverage solely from a nil error.
  - Use existing skipped-package and budget records.
  - Propagate the existing module graph’s `complete` state through `ModuleReachabilityResult`.
  - Preserve discovered positive chains even when another part of the scan is incomplete.

- [ ] Fix `evalLocus` separately:
  - Keep valid call-path, missing-call, and module-chain positives.
  - Package absence requires complete matching package evidence.
  - Linked packages plus empty `CallPaths`/`ModuleReachable` is `UNKNOWN`.
  - A function-unreached candidate requires a completed, non-opaque, context-matching source measurement covering the entire locus set by owning module.
  - It still requires existing independent negative verification.
  - A govulncheck failure does not disable a separately completed source proof.

- [ ] Gate `Verifier.VerifyFalse` **before** locus/package early returns. Require target admission for the applicable basis and assert that its source index matches the case context.

- [ ] Stamp `NegativeVerification.BuildContext` for build-dependent verification results at the verifier boundary, including early return routes. Preserve `setNeg` demotion behavior and historical verification evidence.

- [ ] Re-admit persisted `VERIFIED` claims in `VerdictEvaluator`. Missing context, failed/not-run measurements, incomplete scope, or wrong subject coverage cannot ground NEPF.
  - Treat refused evidence as `UNKNOWN`.
  - Do not turn govulncheck failure into a global veto over another valid proof.
  - Do not change unrelated mandatory-condition or advisory-scope rules.

- [ ] Migrate every production verdict caller:
  - `states.Review.Run`.
  - Both profiles in `states.EvaluateVerdict.Run`.
  - `research.laneApplicabilityDecision`.
  - `research.packageAbsenceDecision`.
  - Research post-reach evaluation in `deterministic.go`.
  - All direct test callers.
  - Use `EvidenceList()` rather than copying a mutex-bearing graph.

- [ ] In research-created verification records, bind the actual lane snapshot and the actual proof evidence. Do not attach a current context to an older measurement merely to make admission pass.

- [ ] Replace the scan prefilter’s independent `deterministicallyNotAffected`/reason logic with a `VerdictInput` evaluation of the resolved affected evidence. Filter only when the common evaluator returns `NOT_AFFECTED`.

**What not to change:**
- DESERIALIZATION/CWE-502 library admission.
- Podman’s module-chain positive.
- Locus necessity or expert non-locus policy.
- Existing dynamic-marker verification obligations.
- Independent release-toolchain, module/version, or deployment-policy facts.

**Focused validation:**

```bash
go test -count=1 ./internal/domain ./internal/evaluator \
  -run 'TestNegativeAdmission|TestTargetAdmission|TestMeasurementAdmission|TestLocus|TestPlatform|TestVerdict'

go test -count=1 ./internal/goanalysis \
  -run 'TestVerifyFalseTarget|TestVerifyLocus|TestModuleInternalReach|TestRecoverResultIsUnknownAndCannotVerifyFalse'

go test -count=1 ./internal/states ./internal/research ./cmd/izyan \
  -run 'TestModuleUsage|TestPersistedVerified|TestIndependentNegative|TestScanPrefilter|TestApplicabilityTarget|TestPackageAbsenceTarget'
```

**Acceptance:** No named negative producer, verifier early return, persisted verdict, research caller, or scan prefilter can bypass target and measurement admission. Locus unreachability requires a measurement, not empty collections. Independent positives and independent negatives remain usable.

---

### Task 5: Honest reports, exports, and baseline classification

**Depends on:** Tasks 3 and 4.

**Files:**
- Modify:
  - `internal/report/report.go`
  - `internal/report/openvex.go`
  - `internal/report/cyclonedx.go`
  - `internal/report/report_test.go`
  - `internal/report/openvex_test.go`
  - `internal/report/cyclonedx_test.go`
  - `internal/report/library_scope_test.go`
  - `internal/eval/baseline.go`
  - `internal/eval/baseline_test.go`
  - `cmd/izyan/eval.go`
  - `cmd/izyan/vexbench.go`
  - `cmd/izyan/vexbench_test.go`
- Create:
  - `internal/report/measurement_admission_test.go`
  - `cmd/izyan/eval_baseline_test.go`

**Interfaces:**

```go
// Replaces BaselineFromOutput:
func BaselineFromEvidence(
    evidence domain.Evidence,
    vuln domain.Vulnerability,
) string

// Keep signature:
func Baseline(
    ctx context.Context,
    runner goanalysis.Runner,
    dir string,
    vuln domain.Vulnerability,
    build domain.ProductSnapshot,
) string
```

`Baseline` uses the shared recorder/classifier, rather than a separate success interpretation.

Report-local helpers:

```go
func negativeClosureBlockReason(c *domain.AnalysisCase) string
func buildScopeStatement(c *domain.AnalysisCase) string
```

Keep public report/export signatures unchanged.

**Implementation steps:**

- [ ] Add direct-export replay tests for a stored negative verdict with:
  - Host-default target.
  - Valid target but failed run.
  - Completed run with missing subject coverage.
  - Context mismatch.
  - Legacy `VERIFIED` without context.
  - A valid independent version/deployment negative.
  - A valid scoped build negative.

- [ ] Replace report success inference based on `ToolExecutions`, evidence presence, or zero call paths:
  - Failed → failed/unknown.
  - Not run → not run.
  - Completed-empty → completed with no findings in the measured scope; coverage stated separately.
  - Completed-with-results → distinguish module/package findings from actual function call paths.
  - No unconditional “Clean / no call path” claim.

- [ ] Update `formatEvidenceDetail`; a govulncheck evidence record without a matching call path must not be rendered as a call path.

- [ ] Use the same admission rules for `Write`, Markdown, tracker rationale, OpenVEX, and CycloneDX, including direct calls on loaded cases.
  - Preserve historical verification records.
  - Current claims/verdicts and exported statuses must reflect refused admission.
  - Invalid negative exports become `under_investigation`/`in_triage`.

- [ ] Include the analyzed build’s platform, tags, CGO, provenance, and bounded scope in human/export explanations for build-dependent negatives. Do not describe one build as every supported variant.

- [ ] Migrate report package-absence renderers to the complete-record selector and strict decoder; do not retain a raw-content absence inference in explanatory sections.

- [ ] Replace `cmd/izyan/eval.go`’s “first non-empty govulncheck raw output” baseline selection with typed evidence selection.
  - A failed parseable prefix remains an error.
  - An existing failed/not-run record must not trigger an unreported second baseline execution.
  - Run standalone baseline only when no collected run record exists.

- [ ] Keep baseline labels distinct from safety:
  - `silent` requires successful completion and appropriate recorded coverage.
  - Unknown/incomplete coverage is not “clean”.
  - Package-level findings are not symbol reachability.

- [ ] Retain claim/evidence references in benchmark artifacts so calibration can inspect admission reasons, not only final labels.

**What not to change:**
- Positive library-API scope/limitation propagation.
- VEX benchmark target policy or task schema.
- Positive status mappings.
- Unrelated VEX vocabulary or report formatting.

**Focused validation:**

```bash
go test -count=1 ./internal/report \
  -run 'TestMeasurementAdmission|TestReportGovulncheck|TestGovulncheckComparison|TestOpenVEX|TestCycloneDX|TestLibraryScope'

go test -count=1 ./internal/eval ./cmd/izyan \
  -run 'TestBaseline|TestEvalBaseline|TestVex.*Provenance|TestVex.*Artifact'
```

**Acceptance:** A failed invocation never appears as a clean reachability measurement. Reports, persisted JSON, direct exports, and baseline comparisons agree on admission and build scope.

---

### Task 6: End-to-end acceptance, claim-level calibration, and documentation

**Depends on:** Tasks 1–5.

**Files:**
- Create: `internal/states/target_provenance_e2e_test.go`
- Modify: `internal/states/states_test.go`
- Modify: `internal/states/library_scope_e2e_test.go`
- Create: `cmd/izyan/target_provenance_calibration_test.go`
- Modify:
  - `docs/dev/analysis-internals.md`
  - `docs/how-it-works.md`
  - `docs/cli.md`
  - `docs/architecture.md`
  - `docs/dev/gap-analysis.md`
  - `eval/README.md`
- Create: `docs/dev/reports/2026-10-25-evidence-target-provenance-calibration.md`

**Interfaces:**

Extend the existing test-only `engineDeps` with:

```go
SnapshotOptions repository.SnapshotOptions
```

Default remains zero/non-admitting. Existing tests that intentionally verify a particular build must declare that build explicitly; do not globally make test runs operator-declared.

Add an opt-in integration test:

```go
func TestTargetProvenanceCalibration(t *testing.T)
```

Inputs:
- `VA_VEX_TASKS`
- `VA_SNAPSHOTS`
- `VA_FROZEN_OSV`
- `VA_CASES`

Use the existing task loader and snapshot layout. For the explicit-target comparison, call `analyzeCase` with the task’s external commit identity and paired target flags inside the test. This avoids inventing a public external-snapshot CLI flag or modifying the platform-free VEX harness.

**Implementation steps:**

- [ ] Add deterministic small-fixture E2E tests crossing:
  - Host-default/scoped/mismatched target.
  - Completed-results/completed-empty/failed/not-run outcome.
  - Complete/partial package inventory.
  - No usage/direct call/module-chain positive.
  - Missing/complete locus measurement.
  - Persisted verified claim replay.

- [ ] Assert first erroneous claims as well as terminal verdicts:
  - Failed run + zero usage → `C-REACH UNKNOWN`, no silence-derived falsifier.
  - Linked locus package + no completed reachability measurement → `C-LOCUS UNKNOWN`.
  - Independent module chain survives govulncheck failure.
  - Independent complete source proof is not vetoed by that failure.
  - Host-default build absence cannot reach a safe verdict or negative VEX export.

- [ ] Preserve library admission controls with existing library tests. Explicitly test non-DESERIALIZATION and non-CWE-502 controls; do not widen admission to recover calibration counts.

- [ ] Run the pinned real calibration cases:
  - Cilium positive control:  
    `cilium-cilium-1228cbc-CVE-2026-35469`
  - Podman false alarm:  
    `containers-podman-38ccfa2-CVE-2024-37298`
  - Kubernetes false alarm:  
    `kubernetes-kubernetes-6d4b94f-CVE-2022-41717`

- [ ] For the paired Cilium run, keep source identity, advisory, toolchain, database, and execution settings constant; vary only target inputs:
  - Default → host-default, `C-REACH UNKNOWN`, `C-LOCUS UNKNOWN`, `INCONCLUSIVE`.
  - `linux/amd64` → preserve the measured positive and `EXPLOITABLE`.
  - Do not add platform inference to the unchanged VEX harness.

- [ ] Produce a calibration ledger for both named false alarms containing:
  - Task and snapshot identity.
  - Target source/scope and effective context.
  - Run outcome, actual scan pattern, coverage, and evidence IDs.
  - `C-REACH`, `C-LOCUS`, and relevant input claims with producer/falsifier.
  - Verification/admission refusal or success.
  - Final verdict, termination reason, and infrastructure status.
  - Explicit distinction between corrected evidence, unchanged false alarm, abstention, and timeout.

- [ ] Record Podman’s surviving module-chain positive honestly. Do not count its removal as acceptance.

- [ ] Record Kubernetes timeout/cancellation as an incomplete measurement or infrastructure outcome, never a corrected safe result.

- [ ] Update documentation:
  - Replace the case-level coverage description.
  - Explain both gates, precedence, partial-flag behavior, plain-binary provenance, and single-build scope.
  - Document intended safe-to-abstain changes without target inputs.
  - Update the gap-analysis open items only for behavior actually closed.
  - Do not rewrite historical benchmark counts as new measurements.

**Focused validation:**

```bash
go test -count=1 ./internal/states \
  -run 'TestTargetProvenanceE2E|TestE2EGovulncheckFailure|TestE2ELibraryConsumerCalibration'

go test -count=1 ./internal/evaluator ./internal/states ./internal/report \
  -run 'TestLibraryInput|TestE2ELibrary|TestLibraryScope'

go test -count=1 ./cmd/izyan \
  -run '^TestTargetProvenanceCalibration$' -timeout 90m
```

Platform-free harness control, with the external inputs prepared:

```bash
go run ./cmd/izyan eval vex-bench \
  --tasks "$VA_VEX_TASKS" \
  --repos-dir "$VA_SNAPSHOTS" \
  --osv-dir "$VA_FROZEN_OSV" \
  --case 'cilium-cilium-1228cbc-CVE-2026-35469,containers-podman-38ccfa2-CVE-2024-37298,kubernetes-kubernetes-6d4b94f-CVE-2022-41717' \
  -j 1 \
  --mem-limit 24GiB \
  --out "$VA_CASES/target-provenance-host"
```

Missing external assets must produce an explicit skipped integration test with named prerequisites. They do not excuse missing deterministic regressions or permit claiming the real acceptance measurements passed.

**Acceptance:** The specified Cilium pair is demonstrated; both false alarms are tracked at claim/evidence level; positives and library-admission boundaries remain unchanged; documentation describes the actual new semantics.

---

## Dependency / Execution Order

```text
Task 1: model + recorder + parser + run-aware consumers
    ↓
Task 2: target resolution + effective context + early binding
    ├── Task 3: complete package inventories + affected/root cause
    └── Task 4: evaluator/locus/verifier/verdict/prefilter
              ↓
        Tasks 3 and 4 integrated
              ↓
Task 5: reports + exports + baseline
              ↓
Task 6: E2E + real calibration + documentation
```

Tasks 3 and 4 are parallel-safe after Task 2 using the frozen evidence interfaces:

- Task 3 owns `affected/golist.go`, `affected/resolver.go`, and root-cause absence.
- Task 4 owns evaluator/verifier consumers and source-measurement production.
- Task 4 must not invent a weaker package decoder; its consumer tests use complete typed fixture records, and final integration uses Task 3’s strict implementation.

## Shared-File Serialization

| File | Ordered ownership |
|---|---|
| `internal/domain/domain.go` | Task 1 establishes fields; later tasks consume them |
| `internal/domain/target.go` | Task 2 owns target extraction/matching changes |
| `internal/repository/service.go` | Task 2 only |
| `internal/affected/golist.go` | Task 2 environment/cache work → Task 3 inventory work |
| `internal/goanalysis/source.go` | Task 2 context binding/environment → Task 4 source coverage |
| `internal/goanalysis/govulncheck.go` | Task 1 parser/recorder integration → Task 2 environment/cache guards |
| `internal/states/states.go` | Task 1 recorder → Task 2 early binding → Task 4 source measurement and verdict callers |
| `internal/evaluator/conditions.go` | Task 1 outcome/fallback cutover → Task 4 complete target/measurement admission |
| `cmd/izyan/main.go` | Task 1 obsolete coverage-option removal → Task 2 snapshot/resource ordering → Task 4 prefilter |
| `internal/report/report.go` | Task 5 single owner |
| `internal/states/states_test.go` | Follow corresponding task order; no global admitting test default |

## Final Integration Validation

Run once after all implementation tasks have landed, from the repository root:

```bash
gofmt -w <all-changed-Go-files>
go vet ./...
go test -count=1 ./...
```

Then run each full corpus once:

```bash
go run ./cmd/izyan eval --corpus eval/corpus-real.json -j 4

VA_PRODUCT_REPO="$VA_PRODUCT_REPO" \
  go run ./cmd/izyan eval --corpus eval/live-corpus.json
```

Required interpretation:

- `false-safe=0`.
- Do not require the previous cleared-count baseline: safe-to-abstain movement without target provenance is intended.
- Do not blanket-add targets to corpus entries to restore counts.
- Distinguish missing prerequisites and infrastructure failures from analyzer outcomes.
- Preserve the real calibration artifacts and claim/evidence ledger before reporting acceptance.

**Planning gate: READY.** The remaining external dependency is availability of the pinned calibration assets, not an unresolved design decision. If implementation discovers a fact that contradicts the two gates, provenance precedence, or shared-context contract, stop that affected change and report the contradiction rather than weakening admission.

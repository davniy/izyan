# Release Applicability, Artifact Provenance, and Symbol-Unreachability Implementation Plan

**Goal:** Close the version-axis, release-artifact, and release-toolchain-trust gaps without weakening deterministic applicability, negative-verification, monotonic-policy, replay, or `AutoClose=false` guarantees.

**Architecture:** Extend the existing deterministic research lane and R6 flow with (1) typed release-evidence trust classes, (2) a bounded local/HTTPS artifact acquisition and Go build-info channel, and (3) a generic, advisory-bound symbol-unreachability proof assembled from existing `goanalysis` machinery. `VerifyDecision` remains the terminal authority for code-grounded negatives; R6 `/3` artifacts remain proposals for human acceptance only.

**Tech stack:** Go, `debug/buildinfo`, `archive/zip`, existing `internal/repository`, `internal/affected`, `internal/goanalysis`, `internal/evidencetools` MCP/session APIs, `internal/research` R6 flow and `/3` report contracts, Python regression harness.

**Spec:** `docs/dev/plans/2026-10-15-02-decision-ready-triage-plan.md`, Amendment R6 in `docs/dev/plans/2026-10-15-01-c02-closure-capability-plan.md`, the owner’s Gap A/B/C decisions in the assignment context, and `docs/agent-rules/{architecture,coding,testing,security,observability,generality,provenance-and-bounds}.md`.

## Global Constraints

1. Existing R6 implementation is the baseline. Do not repeat or redesign the already implemented flow, artifact contract, replay contract, or human-facing bounds.
2. Preserve:
   - advisory-wide subject coverage;
   - exact module/package/symbol identity and granularity;
   - request-to-audit argument binding;
   - matching snapshot/build context;
   - digest-resolved observations;
   - complete observation coverage;
   - positive-contradiction vetoes;
   - empty limitations for terminal negatives;
   - `AutoClose=false`;
   - monotonic policy behavior;
   - legacy `/1` and `/2` parsing and replay.
3. `NOT_AFFECTED` remains available only from the deterministic applicability chain.
4. Symbol unreachability may produce only `CLOSE_NO_EXPLOIT_PATH`, never `CLOSE_NOT_AFFECTED`.
5. A build-image, CI, `go.mod`, version-file, or release-script declaration is supporting evidence only. It cannot independently resolve stdlib applicability.
6. Binary build info and explicitly supplied ticket/SBOM release metadata are the only authoritative release-toolchain sources.
7. Supporting evidence may corroborate an authoritative version, but may never override it.
8. Conflicting authoritative versions resolve to UNKNOWN/NOT_RUN, not to the first or newest value.
9. Missing artifact credentials, download failure, unsafe archive, ambiguous binary selection, and build-info extraction failure are explicit fail-closed outcomes with named reason codes.
10. Credentials:
    - are read only from the named environment variable;
    - are never included in errors, logs, audit records, reports, manifests, fixtures, or prompts;
    - are never placed in a URL;
    - are never persisted in the artifact cache.
11. Artifacts are outside the repository and output directory. No artifact URL, private path, ticket identifier, or credential may be committed.
12. No CVE-specific branches, module paths, package paths, private IDs, or private URLs.
13. No live model/provider calls are part of implementation or offline validation. The paid live budget is already exhausted (`23/20`); any future live run requires an explicit owner authorization and additional budget.
14. Existing R6 fixtures, the recorded C09 path, the C09 legacy `/2` guard, and the measured `7/18` census are mandatory regression controls.
15. Full repository tests, vet, and corpus validation run once, after focused validation and regression guards pass.

## Design Decisions and Safety Arguments

### Gap A — symbol-unreachability as a negative

#### Reused machinery

The implementation MUST reuse, rather than replace:

- `goanalysis.Index.ProductUsage` and its existing negative contract;
- `Index.SkippedPackages`, `LoadBudgetExhausted`, and `ProductPackagePaths`;
- `FindCallers`/`MayCallSites`;
- `FindDepCallers`;
- `InterfaceDispatchSites`;
- `ScanDynamic`;
- `GatedRefs`;
- `FindEntrypoints`;
- `ModuleInternalReach`;
- `DepInvocationState`;
- the existing locus-function-unreached logic in `internal/goanalysis/locusverify.go`;
- the existing observation/audit/persistence path in `internal/evidencetools` and `internal/research`.

The new proof is an aggregation and validation contract over those mechanisms, not a new universal call-graph or runtime-proof engine.

#### New proof shape

Add a generic `symbol-unreachability` evidence check. It receives an exact advisory-bound module and symbol set and returns a typed payload containing:

- exact requested subjects;
- declaration-resolution results;
- complete product-package inventory;
- entrypoint inventory;
- direct product references;
- may-call candidates;
- dependency-internal callers;
- module-internal reachability;
- interface-dispatch sites;
- dynamic markers;
- build-gated references;
- package-load/skipped-package state;
- unbounded/opaque indicators;
- a derived `COMPLETE`/`PARTIAL`/`UNKNOWN` status.

The observation is `COMPLETE` only when all required subchecks succeed and all relevant gaps are empty. A subcheck error, timeout, unsupported result, partial may-call enumeration, skipped package, load-budget exhaustion, opaque module reachability, dynamic marker, interface-dispatch candidate, or gated reference prevents promotion.

The complete scope is the recorded source/build scope, not universal runtime behavior. The payload MUST state that reflection mechanisms not modeled, plugin loading, generated loading, cgo, external deployment, and unsupported transport registration remain outside proof scope.

#### Advisory-wide rule

The symbol route may close only if:

1. every declared symbol subject is covered at exact module/package/symbol granularity;
2. every declared subject whose applicability is known affected is covered by a complete symbol-unreachability proof or another accepted negative proof;
3. every subject with unresolved applicability is covered by the same complete symbol-unreachability proof;
4. module-only subjects without declared symbols are resolved by applicability or a module/package closure proof;
5. no declared subject has positive product linkage or usage evidence;
6. no unresolved subject is silently omitted.

A stdlib subject with unknown release version is therefore not treated as fixed or not applicable. It is dismissed only because its declared vulnerable symbols are independently proven unreachable. The final disposition is `CLOSE_NO_EXPLOIT_PATH`, not `CLOSE_NOT_AFFECTED`.

#### `VerifyDecision` authority

`VerifyDecision` remains authoritative:

- An agent proposal may request the generic symbol-unreachability route, but cannot set its result.
- R6 artifact construction may produce a candidate closure rule from promoted facts, but `decisionForArtifactWithAuthority` MUST pass a deterministic typed proposal through `VerifyDecision`.
- `VerifyDecision` rechecks exact subject binding, trace completeness, audit binding, snapshot/build identity, evidence references, dynamic markers, positive contradictions, and advisory-wide coverage.
- The unknown-release guard is relaxed only for the explicit symbol-unreachability route and only when every unresolved applicability subject is covered by the complete proof.
- No symbol-unreachability route can produce `NOT_AFFECTED`.
- A symbol absence, source lookup miss, or empty partial search remains UNKNOWN.

#### Not provable today

The route MUST remain UNKNOWN/NOT_DECISION_READY for:

- runtime reflection or generated loading not modeled by the scanner;
- plugin, cgo, linker, or `go:linkname` behavior outside the recognized markers;
- unsupported external transports or deployment entrypoints when the inventory cannot close their scope;
- opaque or unbounded dependency-internal dispatch;
- alternate GOOS/GOARCH/build-tag variants;
- module-only advisory subjects where no exact package/symbol subject is declared;
- a symbol that cannot be resolved in the loaded vulnerable dependency version;
- any partial, errored, skipped, or timeout observation.

### Gap B — release artifact channel

#### CLI surface

Add to `cmd/izyan research`:

```text
--artifact <path>
--artifact-url <https-url>
--artifact-credentials-env <environment-variable>
--artifact-cache-dir <directory>
--artifact-timeout <duration>
--release-metadata <path>
```

Rules:

- `--artifact` and `--artifact-url` are mutually exclusive.
- `--artifact` is preferred for local/on-demand analysis.
- `--artifact-url` requires an HTTPS URL and a non-empty credentials environment variable.
- `--artifact-credentials-env` defaults to `IZYAN_ARTIFACT_CREDENTIALS`.
- The credential value is `username:password` for HTTP Basic authentication.
- `--release-metadata` is a sanitized `release-metadata/1` JSON file for ticket/SBOM metadata. It may contain an authoritative Go version and module list, but no credentials.
- No artifact-related flag is required when artifact evidence is unavailable; the result remains UNKNOWN unless an explicitly requested artifact fails, in which case the run records `NOT_RUN`.

#### Download and cache rules

Use bounded constants with optional lower caller limits:

- maximum compressed/downloaded bytes: 2 GiB;
- maximum extracted bytes: 8 GiB;
- maximum archive entries: 20,000;
- maximum individual candidate file: 512 MiB;
- default download/extraction timeout: 10 minutes;
- cache directory must be outside the snapshot and output directory;
- cache entries are content-addressed by downloaded-file SHA-256;
- cache permissions are owner-only;
- cache metadata contains only source kind, sanitized source reference, size, SHA-256, and extraction/member metadata.

HTTPS behavior:

- normal certificate verification is mandatory;
- redirects are permitted only to HTTPS and the same host;
- credentials are sent through an `Authorization` header only;
- credentials are never included in URL strings;
- URL logging/reporting strips userinfo and query parameters;
- HTTP status, including `401`, maps to a named fail-closed reason without echoing response headers containing authentication details.

#### Archive handling

The channel accepts:

- a regular Go binary;
- a ZIP archive containing one or more candidate Go binaries.

ZIP extraction MUST:

- reject absolute paths;
- reject `..` traversal;
- reject symlink entries;
- enforce entry, compressed, and extracted-size limits;
- extract into the external content-addressed cache;
- never extract into the repository or output directory.

Candidate selection:

1. inspect regular files in stable lexical order using `debug/buildinfo.ReadFile`;
2. retain only files with valid Go build information;
3. prefer a unique candidate whose main module matches the analyzed product module;
4. if multiple candidates have byte-equivalent toolchain and module inventories, select the lexical first and record all candidates;
5. otherwise return `NOT_RUN` with `ARTIFACT_AMBIGUOUS_BINARY`.

#### Build-info evidence

The artifact evidence records:

- artifact SHA-256;
- archive/member identity;
- binary build-info SHA-256;
- Go toolchain version;
- main module;
- complete dependency module list including replacements;
- extraction method (`debug.BuildInfo`, with `go version -m` fallback only if required);
- authoritative trust class;
- sanitized source reference.

The release module list is used for release-version applicability. The source snapshot’s module/package listing remains the source of package/build closure evidence. This prevents source checkout version and shipped binary version from being conflated.

#### Fail-closed outcomes

Named reason codes include:

```text
ARTIFACT_NOT_REQUESTED
ARTIFACT_PATH_MISSING
ARTIFACT_PATH_UNREADABLE
ARTIFACT_CREDENTIALS_MISSING
ARTIFACT_URL_INVALID
ARTIFACT_DOWNLOAD_FAILED
ARTIFACT_HTTP_UNAUTHORIZED
ARTIFACT_SIZE_LIMIT
ARTIFACT_TIMEOUT
ARTIFACT_ARCHIVE_UNSAFE
ARTIFACT_NO_GO_BINARY
ARTIFACT_AMBIGUOUS_BINARY
ARTIFACT_BUILD_INFO_UNREADABLE
RELEASE_METADATA_INVALID
RELEASE_EVIDENCE_CONFLICT
```

An explicitly requested artifact that reaches any failure status MUST NOT silently fall back to source `go list -m` or snapshot-local declarations for release applicability. The run records `NOT_RUN`, and R6 skips paid agent calls for that run.

### Gap C — release-toolchain trust classes

#### Taxonomy

```text
AUTHORITATIVE
SUPPORTING
UNKNOWN
CONFLICTED
NOT_RUN
```

Evidence sources:

| Source | Class | Can ground stdlib applicability? |
|---|---|---:|
| Release binary build info | AUTHORITATIVE | Yes |
| Ticket/SBOM release metadata | AUTHORITATIVE | Yes |
| `go.mod toolchain` directive | SUPPORTING | No, alone |
| Dockerfile `FROM golang:X` | SUPPORTING | No, alone |
| Jenkins/CI setup-go | SUPPORTING | No, alone |
| `.go-version`, mise/asdf, version files | SUPPORTING | No, alone |
| Release scripts/Makefiles | SUPPORTING | No, alone |
| Missing or malformed source | UNKNOWN/NOT_RUN | No |

#### Precedence

1. Collect all evidence items; do not stop at the first match.
2. If authoritative items agree after version normalization, resolve the version.
3. If authoritative items disagree, status is `CONFLICTED`, the selected release version is empty, and applicability stays UNKNOWN.
4. Supporting evidence may corroborate an authoritative version.
5. Supporting disagreement is recorded as a limitation but cannot override authoritative evidence.
6. Supporting evidence without an authoritative item leaves release applicability UNKNOWN.
7. `go.mod` and the analysis toolchain remain minimum/analysis facts, never release-toolchain facts.

Each release evidence item records its trust class, source, location/member, version, and artifact/build-info provenance. R6 `Fact` values for release applicability additionally carry `trust_class`. A supporting fact cannot establish `version-in-range`.

## Integration Points

### `affected-resolve`

- `ProductSnapshot` gains release-evidence status, authoritative release toolchain, release module graph, and artifact provenance.
- `affected.GoResolver` uses the authoritative release module graph for release-version checks when present.
- Source `GoTool.ListModules` continues to provide source/build closure data.
- If an explicitly requested artifact is unavailable, release version checks remain UNKNOWN and source module versions are not substituted for release versions.
- `affected-resolve` observation data includes:
  - aggregate affected result;
  - release evidence status;
  - authoritative/supporting evidence list;
  - artifact SHA/member/build-info digest;
  - release module graph provenance.
- The resolver still evaluates all advisory entries independently. One unresolved subject remains advisory-blocking unless a complete symbol-unreachability or other accepted negative route discharges that exact subject.

### R6 flow, rules, and catalogs

Add generic entries:

- condition: `declared-symbol-unreachable`;
- check: `symbol-unreachability`;
- evaluator predicate: `declared-symbol-reachability`;
- rule: `rule.declared-symbols-unreached`;
- fact kind: `SYMBOL_UNREACHABILITY`.

The new check is dispatchable through the existing `mappedFlowCatalog` and confined `EvidenceSession`. It is not CVE-specific and is not added as a permissive fallback.

The flow planner prompt is updated and hash-pinned to explain:

- exact symbol granularity;
- advisory-wide subject coverage;
- `symbol-unreachability` as the only accepted route for that condition;
- no agent-created branches, facts, values, or dispositions;
- unsupported/partial results remain UNKNOWN.

### `/3` artifact and report

`research-report/3` remains the authoritative human-facing schema. Add optional release provenance to `SnapshotInput` and `Fact`:

- release-evidence status;
- evidence items and trust classes;
- artifact SHA-256;
- sanitized source reference;
- binary/archive member;
- build-info digest;
- selected authoritative toolchain;
- release module graph digest/provenance.

No new human question is introduced for artifact evidence. Missing authoritative evidence is rendered as an explicit UNKNOWN/NOT_RUN limitation.

`DecisionArtifact` changes only add the optional `Fact.TrustClass` field and the new symbol-unreachability fact/rule references. `CLOSE_*` still requires complete verified facts and a justification. The report remains:

```json
"disposition": {
  "class": "REVIEW_REQUIRED",
  "auto_close": false
}
```

### Legacy compatibility

- `/1` and `/2` reports with no new optional fields remain byte-compatible.
- `/2` replay remains available through `--replay-agent-turn`.
- The C09 legacy `/2` replay guard remains mandatory.
- The new artifact channel is opt-in from `research`; existing `analyze --binary` behavior is preserved but receives the new trust-class semantics.

## Review Focus

| Risk | Owning task/test |
|---|---|
| Docker/Jenkins declaration grounds stdlib applicability alone | Task 1 trust-class tests |
| Conflicting authoritative versions select one silently | Task 1 conflict tests |
| Artifact credentials leak into reports or manifests | Task 2 and Task 4 redaction tests |
| ZIP Slip, symlink extraction, decompression/resource bomb | Task 2 archive-bound tests |
| Source module graph substitutes for a failed requested artifact | Task 3 fail-closed resolver tests |
| Release binary module list is ignored in favor of checkout `go.mod` | Task 3 artifact applicability tests |
| A package fact satisfies a symbol subject | Task 5/6 subject-granularity tests |
| Empty `find_callers` result becomes symbol-unreachable proof | Task 5 partial/empty-scope tests |
| Dynamic/interface/gated/opaque markers are ignored | Task 5 negative matrix |
| One advisory subject is omitted from a symbol close | Task 6 advisory-wide tests |
| Symbol unreachability produces `NOT_AFFECTED` | Task 6 authority tests |
| R6 artifact bypasses `VerifyDecision` | Task 6 authority-projection tests |
| `/1` and `/2` historical reports stop parsing | Task 4 compatibility tests |
| C09 `/2` replay or `7/18` census changes | Task 7 regression guard |
| Paid model calls happen after artifact `NOT_RUN` | Task 4 deterministic fail-closed test |

---

### Task 1: Add release-evidence trust classes and precedence

**Depends on:** None

**Files:**

- Create: `internal/domain/release.go`
- Modify: `internal/domain/domain.go`
- Modify: `internal/repository/releaseevidence.go`
- Modify: `internal/repository/service.go`
- Modify: `internal/repository/contenthash_test.go`
- Modify: `internal/repository/service_test.go`
- Test: `internal/repository/releaseevidence_test.go`

**Interfaces:**

```go
type ReleaseTrustClass string

const (
    ReleaseTrustAuthoritative ReleaseTrustClass = "AUTHORITATIVE"
    ReleaseTrustSupporting    ReleaseTrustClass = "SUPPORTING"
)

type ReleaseEvidenceStatus string

const (
    ReleaseStatusNotRequested ReleaseEvidenceStatus = "NOT_REQUESTED"
    ReleaseStatusResolved     ReleaseEvidenceStatus = "RESOLVED"
    ReleaseStatusUnknown       ReleaseEvidenceStatus = "UNKNOWN"
    ReleaseStatusConflicted    ReleaseEvidenceStatus = "CONFLICTED"
    ReleaseStatusNotRun       ReleaseEvidenceStatus = "NOT_RUN"
)

type ReleaseModule struct {
    Path    string         `json:"path"`
    Version string         `json:"version"`
    Main    bool           `json:"main,omitempty"`
    Replace *ReleaseModule `json:"replace,omitempty"`
}

type ReleaseEvidenceItem struct {
    Version        string             `json:"version,omitempty"`
    Source         GoVersionSource    `json:"source"`
    TrustClass     ReleaseTrustClass  `json:"trust_class"`
    Location       string             `json:"location,omitempty"`
    ArtifactSHA256 string             `json:"artifact_sha256,omitempty"`
    BinaryMember   string             `json:"binary_member,omitempty"`
    BuildInfoSHA256 string            `json:"build_info_sha256,omitempty"`
}

type ReleaseEvidenceSummary struct {
    Status         ReleaseEvidenceStatus `json:"status"`
    ReasonCode     string                `json:"reason_code,omitempty"`
    SelectedVersion string               `json:"selected_version,omitempty"`
    SelectedSource  GoVersionSource     `json:"selected_source,omitempty"`
    SelectedTrust   ReleaseTrustClass   `json:"selected_trust,omitempty"`
    Items          []ReleaseEvidenceItem `json:"items,omitempty"`
    Modules        []ReleaseModule      `json:"modules,omitempty"`
    ArtifactSHA256 string               `json:"artifact_sha256,omitempty"`
    BinaryMember   string               `json:"binary_member,omitempty"`
    BuildInfoSHA256 string              `json:"build_info_sha256,omitempty"`
}
```

Add to `domain.ProductSnapshot`:

```go
ReleaseEvidence       *ReleaseEvidenceSummary `json:"release_evidence,omitempty"`
ReleaseModules         []ReleaseModule         `json:"release_modules,omitempty"`
ReleaseEvidenceRequired bool                  `json:"release_evidence_required,omitempty"`
```

Define:

```go
func ResolveReleaseEvidence(items []domain.ReleaseEvidenceItem) domain.ReleaseEvidenceSummary
func DiscoverReleaseEvidence(root string) domain.ReleaseEvidenceSummary
```

**Steps:**

- [ ] Add the trust/status/module types and preserve existing `ReleaseGoVersion` and `GoVersionSource` fields for compatibility.
- [ ] Change snapshot-local discovery to collect all matches rather than returning the first match.
- [ ] Mark all snapshot-local declarations as `SUPPORTING`.
- [ ] Mark explicit ticket/SBOM metadata and binary build info as `AUTHORITATIVE`.
- [ ] Implement authoritative precedence and conflict handling.
- [ ] Update `Service.Snapshot` so static supporting evidence does not populate `ReleaseGoVersion`.
- [ ] Preserve the existing `go.mod` minimum version separately.
- [ ] Add tests for:
  - Dockerfile-only evidence;
  - CI-only evidence;
  - toolchain-directive-only evidence;
  - agreeing binary + Docker evidence;
  - conflicting binary + ticket evidence;
  - conflicting supporting evidence;
  - no evidence;
  - legacy snapshot JSON with omitted new fields.

**Focused verification:**

```bash
go test -count=1 ./internal/repository ./internal/domain \
  -run 'Test(DiscoverReleaseEvidence|ResolveReleaseEvidence|Snapshot|ProductSnapshot)'
```

**Acceptance:**

- A Dockerfile or Jenkins/CI declaration is recorded as supporting evidence but leaves `ReleaseGoVersion` empty when no authoritative source exists.
- Two agreeing authoritative sources resolve the version.
- Two conflicting authoritative sources produce `CONFLICTED` with no selected release version.
- Supporting evidence never overrides an authoritative value.
- Existing callers that read `ReleaseGoVersion` continue to compile and preserve legacy semantics when authoritative evidence is absent.

**Out of scope:** artifact download, ZIP extraction, resolver module-graph selection, CLI flags, symbol reachability, R6 changes.

---

### Task 2: Implement bounded artifact acquisition and Go build-info extraction

**Depends on:** Task 1

**Files:**

- Create: `internal/repository/artifact.go`
- Create: `internal/repository/artifact_test.go`
- Create: `internal/repository/artifact_http_test.go`
- Modify: `internal/repository/service.go`
- Modify: `internal/repository/service_test.go`

**Interfaces:**

```go
type ArtifactOptions struct {
    Path                  string
    URL                   string
    CredentialsEnv        string
    CacheDir              string
    Timeout               time.Duration
    MaxDownloadBytes      int64
    MaxExtractedBytes     int64
    MaxArchiveEntries     int
    ProductModule         string
}

type ArtifactResolution struct {
    Evidence domain.ReleaseEvidenceSummary
    Status   domain.ReleaseEvidenceStatus
    Reason   string
}

func ResolveReleaseArtifact(ctx context.Context, opts ArtifactOptions) (ArtifactResolution, error)
```

`ResolveReleaseArtifact` returns expected input/download/extraction failures in `ArtifactResolution` rather than hiding them in a nil result. Unexpected programmer/I/O errors may still return an error.

**Steps:**

- [ ] Validate mutually exclusive local path and URL inputs.
- [ ] Implement local file hashing with a streaming SHA-256 pass.
- [ ] Implement HTTPS download with timeout, size limit, same-host HTTPS redirects, and normal certificate verification.
- [ ] Read Basic credentials only from `CredentialsEnv`; reject missing credentials with `ARTIFACT_CREDENTIALS_MISSING`.
- [ ] Redact credentials from every error, URL, audit field, and manifest value.
- [ ] Create an external content-addressed cache and reject cache paths inside the snapshot or output directory.
- [ ] Implement ZIP extraction with traversal, symlink, entry-count, compressed-size, extracted-size, and timeout checks.
- [ ] Inspect candidate files with `debug/buildinfo.ReadFile`.
- [ ] Parse main module, Go version, replacements, dependencies, and build settings into `ReleaseModule` values.
- [ ] Apply the unique/product-module/identical-inventory candidate-selection policy.
- [ ] Return explicit reason codes for all expected fail-closed states.
- [ ] Test:
  - regular binary;
  - ZIP with one binary;
  - ZIP with multiple equivalent binaries;
  - ZIP with conflicting binaries;
  - traversal entry;
  - symlink entry;
  - size-limit violation;
  - missing credentials;
  - HTTPS `401`;
  - credential redaction;
  - build-info absence;
  - cache reuse by SHA-256.

**Focused verification:**

```bash
go test -count=1 ./internal/repository \
  -run 'Test(ReleaseArtifact|Artifact|BuildInfo|Zip|Credential|Redact|Cache)'
```

**Acceptance:**

- A valid binary or ZIP produces authoritative release evidence with artifact SHA-256, selected member, build-info digest, Go version, and complete module list.
- A missing credential produces `NOT_RUN/ARTIFACT_CREDENTIALS_MISSING`; no fallback or silent skip occurs.
- No test output, error, or persisted structure contains the credential value.
- Unsafe ZIPs are rejected before extraction outside the cache.
- Ambiguous binaries produce `NOT_RUN/ARTIFACT_AMBIGUOUS_BINARY`.
- No path inside the repository is used for cache or extraction.

**Out of scope:** affected applicability, CLI wiring, report schema, symbol proof, live artifact-mirror calls.

---

### Task 3: Use authoritative artifact module graphs in `affected-resolve`

**Depends on:** Task 1 and Task 2

**Files:**

- Modify: `internal/affected/resolver.go`
- Modify: `internal/affected/golist.go`
- Modify: `internal/affected/resolver_test.go`
- Modify: `internal/research/deterministic.go`
- Modify: `internal/evidencetools/dependencies.go`
- Modify: `internal/evidencetools/scope.go`
- Test: `internal/affected/artifact_resolver_test.go`

**Interfaces:**

Add a release-graph selection helper:

```go
func ReleaseModulesFor(product domain.ProductSnapshot) ([]Module, bool, string)
```

The return values mean:

- module list;
- whether the list is authoritative release evidence;
- reason/status when unavailable.

Resolver rules:

```text
authoritative artifact/SBOM module graph:
    use for release-version applicability
source go list/vendor graph:
    use for package/build closure
explicit artifact requested but unavailable:
    do not use source graph to resolve release versions
no artifact requested:
    retain existing non-stdlib source-module behavior
stdlib:
    resolve only from authoritative ReleaseGoVersion
```

**Steps:**

- [ ] Convert `domain.ReleaseModule` values into the resolver’s internal module representation.
- [ ] Prefer the authoritative release module graph for module-version range checks.
- [ ] Keep source `go list -deps` and vendor closure for package/build relevance.
- [ ] Add a release-evidence status and reason to affected-resolve observation payloads.
- [ ] Add artifact SHA/member/build-info digest to `ScopeDetails.Extra`, never credentials.
- [ ] Ensure an explicitly requested but unavailable artifact prevents release-version resolution instead of falling back.
- [ ] Preserve multi-entry advisory evaluation and `UnresolvedModules`.
- [ ] Add tests where:
  - source graph has `x/net@v0.52.0` but artifact graph has `x/net@v0.55.0`;
  - binary Go version resolves stdlib applicability;
  - Dockerfile-only evidence leaves stdlib UNKNOWN;
  - artifact failure leaves release applicability UNKNOWN;
  - source package closure still resolves independently;
  - one entry is fixed and another affected.

**Focused verification:**

```bash
go test -count=1 ./internal/affected ./internal/evidencetools ./internal/research \
  -run 'Test(Artifact|ReleaseModule|ReleaseGraph|Stdlib|MultiModule|AffectedResolve)'
```

**Acceptance:**

- `affected-resolve` uses the release binary’s module list for release-version checks.
- `x/net` version evidence can differ from the checkout’s source graph without being silently overwritten.
- Stdlib applicability resolves from authoritative binary/ticket Go version only.
- Supporting Docker/CI evidence never changes `VersionAffected`.
- An explicitly requested artifact failure is visible in the observation and leaves the relevant version axis UNKNOWN.
- Package/build closure behavior remains unchanged for the recorded source snapshot.

**Out of scope:** CLI flags, R6 branch rules, symbol-unreachability, docs, live artifact URLs.

---

### Task 4: Wire artifact options, NOT_RUN reporting, and `/3` provenance

**Depends on:** Task 3

**Files:**

- Modify: `internal/research/deterministic.go`
- Modify: `internal/research/types.go`
- Modify: `internal/research/assemble.go`
- Modify: `internal/research/render.go`
- Modify: `internal/research/validate.go`
- Modify: `internal/research/flow_adapter.go`
- Modify: `cmd/izyan/research.go`
- Modify: `cmd/izyan/research_test.go`
- Modify: `cmd/izyan/research_decision_ready_test.go`
- Modify: `internal/research/decision_artifact.go`
- Modify: `internal/research/branch_evidence.go`

**Interfaces:**

Extend `research.LaneOptions`:

```go
type LaneOptions struct {
    ...
    ArtifactOptions   repository.ArtifactOptions
    ReleaseMetadata   string
}
```

Add optional report fields:

```go
type SnapshotInput struct {
    ...
    ReleaseEvidence *ReleaseEvidenceReport `json:"release_evidence,omitempty"`
}

type ReleaseEvidenceReport struct {
    Status          string                 `json:"status"`
    ReasonCode      string                 `json:"reason_code,omitempty"`
    SelectedVersion string                 `json:"selected_version,omitempty"`
    SelectedSource  string                 `json:"selected_source,omitempty"`
    SelectedTrust   string                 `json:"selected_trust,omitempty"`
    Items           []ReleaseEvidenceItem  `json:"items,omitempty"`
    ArtifactSHA256  string                 `json:"artifact_sha256,omitempty"`
    BinaryMember    string                 `json:"binary_member,omitempty"`
    BuildInfoSHA256 string                 `json:"build_info_sha256,omitempty"`
}
```

Extend R6 `Fact`:

```go
TrustClass string `json:"trust_class,omitempty"`
```

Extend `RunInfo` with optional:

```go
Outcome       string `json:"outcome,omitempty"`        // COMPLETED|NOT_RUN
OutcomeReason string `json:"outcome_reason,omitempty"`
```

**Steps:**

- [ ] Add the artifact and release-metadata flags with exact validation.
- [ ] Pass options into the deterministic lane before snapshot creation.
- [ ] Ensure `--artifact-url` requires HTTPS and the credentials environment-variable name.
- [ ] Ensure `optionsManifest` records only the credentials variable name, never its value.
- [ ] Add `NOT_RUN` run outcome when an explicitly requested artifact or metadata channel fails.
- [ ] Skip planner/model calls when the lane reports an artifact `NOT_RUN` outcome.
- [ ] Populate `/3` snapshot release evidence with trust classes and hashes.
- [ ] Persist artifact SHA/member/build-info digest in `run-manifest.json`.
- [ ] Do not persist cache paths or extracted absolute paths.
- [ ] Validate:
  - release evidence status;
  - trust class enum;
  - artifact hash shape;
  - no credential-like fields;
  - `/3` artifact/report consistency.
- [ ] Render supporting evidence as corroboration, not as a release determination.
- [ ] Render `NOT_RUN` with the exact named reason and conservative `HOLD_UNKNOWN`.

**Focused verification:**

```bash
go test -count=1 ./internal/research ./cmd/izyan \
  -run 'Test(ArtifactFlag|ReleaseEvidence|RunManifest|NOT_RUN|Credential|ReportSchemaV3|LegacyReport|DecisionReady)'
```

**Acceptance:**

- Local artifact and URL modes are reachable only through explicit flags.
- Missing credentials produce a valid, explicit `NOT_RUN` report/manifest and no model call.
- `/3` contains artifact SHA-256 and trust-class provenance when available.
- Supporting evidence is visible but cannot establish `VersionAffected`.
- `/1` and `/2` fixtures without release-evidence fields continue to parse, validate, render, and replay.
- Artifact failure never silently falls back to source release-version evidence.

**Out of scope:** symbol-unreachability proof implementation, new flow rule semantics, full corpus validation, live provider/artifact-mirror calls.

---

### Task 5: Add the bounded symbol-unreachability evidence primitive

**Depends on:** Task 3

**Files:**

- Create: `internal/goanalysis/unreachability.go`
- Create: `internal/goanalysis/unreachability_test.go`
- Modify: `internal/goanalysis/locusverify.go`
- Modify: `internal/goanalysis/negative.go`
- Create: `internal/evidencetools/unreachability.go`
- Modify: `internal/evidencetools/check_specs.go`
- Modify: `internal/evidencetools/mcp.go`
- Modify: `internal/evidencetools/mcp_test.go`
- Create: `internal/evidencetools/unreachability_test.go`
- Modify: `internal/evidencetools/scope.go`

**Interfaces:**

Add a reusable `goanalysis` result:

```go
type UnreachabilitySubject struct {
    Package string `json:"package"`
    Symbol  string `json:"symbol"`
}

type UnreachabilityResult struct {
    Module                 string                   `json:"module"`
    Subjects               []UnreachabilitySubject `json:"subjects"`
    DeclarationComplete    bool                     `json:"declaration_complete"`
    EntrypointComplete     bool                     `json:"entrypoint_complete"`
    ProductReferences      []domain.CallSite        `json:"product_references,omitempty"`
    MayCallSites           []MayCallSite            `json:"may_call_sites,omitempty"`
    DependencyCallSites    []domain.CallSite        `json:"dependency_call_sites,omitempty"`
    InterfaceDispatchSites []domain.CallSite        `json:"interface_dispatch_sites,omitempty"`
    DynamicMarkers         []DynamicMarker          `json:"dynamic_markers,omitempty"`
    GatedReferences        []domain.CallSite        `json:"gated_references,omitempty"`
    Opaque                 bool                     `json:"opaque"`
    Unbounded              bool                     `json:"unbounded"`
    Complete               bool                     `json:"complete"`
    Limitations            []string                 `json:"limitations,omitempty"`
}

func (ix *Index) VerifyUnreachable(
    context.Context,
    module string,
    subjects []domain.SymbolRef,
) (UnreachabilityResult, error)
```

Add MCP check:

```go
type SymbolUnreachabilityArgs struct {
    Module   string             `json:"module"`
    Subjects []domain.SymbolRef `json:"subjects"`
}

type SymbolUnreachabilityData struct {
    Result UnreachabilityResult `json:"result"`
}
```

Tool ID:

```text
symbol-unreachability
```

**Steps:**

- [ ] Extract common locus-function-unreached checks into `Index.VerifyUnreachable`.
- [ ] Require exact declaration resolution for every requested symbol.
- [ ] Require no skipped product packages and no load-budget exhaustion.
- [ ] Enumerate all loaded product function roots, plus existing recognized entrypoints, and record the bounded entrypoint scope.
- [ ] Reuse `ProductUsage`, `FindCallers`, `MayCallSites`, `FindDepCallers`, `InterfaceDispatchSites`, `ScanDynamic`, `GatedRefs`, `ModuleInternalReach`, and `DepInvocationState`.
- [ ] Mark `Complete=false` for any error, partial candidate enumeration, opaque dispatch, unbounded exported call surface, dynamic marker, interface-dispatch candidate, gated reference, or unsupported scope.
- [ ] Ensure empty results are not complete unless every required inventory is closed.
- [ ] Register the check in the MCP server and generated check catalog.
- [ ] Add fixture tests for:
  - direct symbol use;
  - function-value use;
  - interface dispatch;
  - reflection marker;
  - build-gated reference;
  - dependency-internal caller;
  - skipped package;
  - opaque/unbounded dispatch;
  - complete unreachable symbol set;
  - unresolved declaration.

**Focused verification:**

```bash
go test -count=1 ./internal/goanalysis ./internal/evidencetools \
  -run 'Test(Unreachability|SymbolUnreachability|Dynamic|Interface|Gated|Entrypoint|Skipped|Opaque)'
```

**Acceptance:**

- A complete unreachable result contains every required subcheck and no limitations.
- Any partial/error/unsupported subcheck prevents `Complete`.
- Existing locus verification reuses the extracted logic without behavior regression.
- The new MCP check is confined, audited, schema-validated, and has no verdict field.
- The check is generic and contains no advisory/CVE/package-specific branch.

**Out of scope:** `VerifyDecision`, R6 close rules, report rendering, artifact acquisition, live calls.

---

### Task 6: Make symbol-unreachability authoritative in `VerifyDecision`

**Depends on:** Task 5

**Files:**

- Modify: `internal/domain/domain.go`
- Modify: `internal/research/types.go`
- Modify: `internal/research/agent.go`
- Modify: `internal/research/decision.go`
- Modify: `internal/research/decision_test.go`
- Modify: `internal/evaluator/verdict.go`
- Modify: `internal/research/branch_evidence_test.go`

**Interfaces:**

Add the generic falsifier:

```go
const FalsifierDeclaredSymbolUnreached domain.FalsifierKind =
    "declared-symbol-unreached"
```

Extend the proposal subject set:

```go
type FalsifierProposal struct {
    ...
    Subjects []FactUsageSubject `json:"subjects,omitempty"`
}
```

Add a deterministic authority input separate from agent proposals:

```go
type VerifiedFalsifierInput struct {
    Kind        domain.FalsifierKind
    ConditionID string
    RuleID      string
    Subjects    []FactUsageSubject
}

type DecisionInput struct {
    ...
    Authority *VerifiedFalsifierInput
}
```

**Steps:**

- [ ] Add the falsifier to the accepted verification-kind registry.
- [ ] Keep agent proposals and deterministic authority inputs structurally distinct.
- [ ] Add a `VerifyDecision` route for `FalsifierDeclaredSymbolUnreached`.
- [ ] Validate exact advisory subject identity and symbol granularity.
- [ ] Validate that every requested symbol is present in the `symbol-unreachability` payload.
- [ ] Validate complete trace/audit binding using the existing `closedTrace` rules.
- [ ] Require the complete entrypoint, dynamic, interface, gated, dependency-internal, and opaque/unbounded gates from Task 5.
- [ ] Add the narrow unknown-release exception:
  - only the declared-symbol-unreached route may continue when `VersionAffected=UNKNOWN`;
  - every unresolved module’s declared symbol set must be covered;
  - module-only unresolved entries remain blocking;
  - no unresolved advisory subject may be omitted.
- [ ] Construct the final `EvidenceDecision` as `NO_EXPLOIT_PATH_FOUND` with `NegativeVerification=VERIFIED`.
- [ ] Never return `NOT_AFFECTED` from this route.
- [ ] Add tests for:
  - stdlib unknown + complete stdlib symbol proof + unresolved x/net subject => INCONCLUSIVE;
  - stdlib unknown + complete stdlib and x/net symbol proofs => `NO_EXPLOIT_PATH_FOUND`;
  - positive x/net usage => INCONCLUSIVE;
  - missing one declared symbol => INCONCLUSIVE;
  - partial/error/timeout/missing-audit trace => INCONCLUSIVE;
  - dynamic/interface/gated/opaque markers => INCONCLUSIVE;
  - module-only unresolved entry => INCONCLUSIVE;
  - proof cannot produce `NOT_AFFECTED`;
  - package-level fact cannot satisfy symbol subject.

**Focused verification:**

```bash
go test -count=1 ./internal/research ./internal/evaluator \
  -run 'Test(VerifyDecision|DeclaredSymbol|Unreachability|UnknownRelease|AdvisoryScope|Negative)'
```

**Acceptance:**

- `VerifyDecision` remains the only authority that can produce the terminal negative.
- The new route can neutralize an unresolved release axis only through complete advisory-wide symbol proof.
- No agent assertion, empty search, source miss, or partial observation promotes.
- Existing package-absence, applicability, C09, and guard-capability tests remain unchanged and green.

**Out of scope:** R6 catalog wiring, artifact CLI, report rendering, docs, live calls.

---

### Task 7: Integrate symbol facts and release trust into R6 rules, flow, and `/3`

**Depends on:** Task 4 and Task 6

**Files:**

- Modify: `internal/evaluator/rule_adapters.go`
- Modify: `internal/research/branch_evidence.go`
- Modify: `internal/research/branch_evaluator.go`
- Modify: `internal/research/flow_adapter.go`
- Modify: `internal/research/decision_artifact.go`
- Modify: `internal/research/flow_adapter_test.go`
- Modify: `internal/research/branch_evaluator_test.go`
- Modify: `internal/research/decision_artifact_test.go`
- Modify: `internal/evidencetools/check_specs.go`
- Modify: `configs/research/checks.yaml`
- Modify: `configs/research/conditions.yaml`
- Modify: `rubrics/decision.yaml`
- Modify: `rubrics/research.yaml`
- Create: `eval/agent7/prompts/r6-plan-v4.txt`
- Modify: `eval/agent7/freeze/manifest.json`

**Interfaces:**

Add evaluator constants:

```go
const (
    PredicateDeclaredSymbolReachability = "declared-symbol-reachability"
    RuleFactKindSymbolUnreachability    = "SYMBOL_UNREACHABILITY"
)
```

Register:

```text
rule.declared-symbols-unreached
declared-symbol-reachability = unreached
contradiction values = reached, used, dynamic, incomplete
```

Add catalog entries:

```json
{
  "id": "declared-symbol-unreachable",
  "role": "path",
  "polarity": "POSITIVE"
}
```

```json
{
  "id": "symbol-unreachability",
  "tool": "symbol-unreachability"
}
```

**Steps:**

- [ ] Promote complete `symbol-unreachability` observations to `Fact` and `RuleFact` only when audit-bound, digest-pinned, snapshot-bound, and complete.
- [ ] Carry `TrustClass` for release evidence facts; reject invalid classes.
- [ ] Add the symbol closure rule to `closeRules`.
- [ ] Ensure symbol subjects cannot close through an ordinary `PACKAGE_USAGE` negative alone; they require the new complete symbol-unreachability predicate.
- [ ] Keep package/module closure rules unchanged for package/module subjects.
- [ ] Add the condition/check to the flow catalog and registry.
- [ ] Update `seededConditions` and planner prompt material so the agent can request the check without inventing subjects.
- [ ] Update `decisionForArtifactWithAuthority` to derive a `VerifiedFalsifierInput` from the code-owned closure rule and pass it to `VerifyDecision`.
- [ ] Ensure an artifact closure candidate without a corresponding authoritative trace is demoted to `HOLD_UNKNOWN`.
- [ ] Ensure a supporting Docker/CI release fact cannot satisfy `version-in-range`.
- [ ] Pin the new prompt revision and update the frozen manifest.
- [ ] Keep `r0-v1` through `r0-v4` byte-stable.

**Focused verification:**

```bash
go test -count=1 ./internal/evaluator ./internal/evidencetools ./internal/research ./internal/flow \
  -run 'Test(Symbol|RuleAdapter|Branch|DecisionArtifact|FlowAdapter|Catalog|PromptPin|TrustClass)'
```

**Acceptance:**

- A complete symbol proof appears as an independently produced, digest-bound R6 fact.
- `rule.declared-symbols-unreached` can establish only from complete facts for every advisory-declared symbol.
- The `/3` artifact’s close candidate is revalidated by `VerifyDecision`.
- Missing trace, missing audit, incomplete proof, or non-authoritative release evidence yields `HOLD_UNKNOWN`.
- The flow remains generic and contains no CVE-specific behavior.
- `AutoClose=false` remains enforced.

**Out of scope:** full corporate census, live model execution, human study, automatic tracker/VEX writes.

---

### Task 8: Add sanitized fixtures, regression guards, documentation, and final validation

**Depends on:** Task 7

**Files:**

- Create: `internal/research/testdata/r6-recorded-symbol-unreachable.json`
- Create: `internal/research/testdata/r6-recorded-release-artifact.json`
- Modify: `internal/research/decision_test.go`
- Modify: `internal/research/branch_evaluator_test.go`
- Modify: `internal/research/replay_test.go`
- Modify: `cmd/izyan/research_decision_ready_test.go`
- Modify: `eval/decision_ready/regression_guard.py`
- Modify: `eval/README.md`
- Modify: `docs/dev/gap-analysis.md`
- Modify: `docs/dev/implementation-status.md`

Fixtures MUST contain only sanitized labels, synthetic modules/packages, synthetic SHA-256 values, and generated temporary artifact data. Do not commit private paths, ticket IDs, real artifact URLs, credentials, or raw corporate reports.

**Steps:**

- [ ] Add a sanitized two-subject fixture where one release version is unresolved and symbol-unreachability evidence is complete only for one subject; assert `HOLD_UNKNOWN`.
- [ ] Add the corresponding fully covered fixture; assert `CLOSE_NO_EXPLOIT_PATH` candidate plus authoritative `VerifyDecision` projection.
- [ ] Add a supporting-Docker contradiction fixture; assert the supporting declaration is visible but cannot resolve stdlib applicability.
- [ ] Add artifact provenance assertions for SHA-256, binary member, build-info digest, and trust class.
- [ ] Add credential-redaction assertions over `report.json`, `report.md`, `run-manifest.json`, `flow-events.jsonl`, and persisted observation ledgers.
- [ ] Preserve the C09 legacy `/2` replay guard.
- [ ] Preserve the measured `7/18` census guard.
- [ ] Update `docs/dev/gap-analysis.md` with new generic backlog/status entries for:
  - symbol-unreachability negative capability;
  - release artifact channel;
  - release-toolchain trust classes.
- [ ] Update `docs/dev/implementation-status.md` only with measured offline results. Do not claim live capability without an authorized live run.
- [ ] Update `eval/README.md` with:
  - artifact flags;
  - credential policy;
  - cache and ZIP limits;
  - trust-class precedence;
  - `NOT_RUN` reason codes;
  - symbol-unreachability scope;
  - replay-only validation procedure;
  - `AutoClose=false` boundary.

**Focused verification:**

```bash
go test -count=1 ./internal/repository ./internal/affected ./internal/goanalysis \
  ./internal/evidencetools ./internal/evaluator ./internal/research ./internal/flow ./cmd/izyan \
  -run 'Test(Release|Artifact|Unreachability|Symbol|Decision|Branch|Flow|Replay|Legacy|Redact|Catalog)'
```

R6-G0 regression guard:

```bash
python3 eval/decision_ready/regression_guard.py \
  --baseline-manifest "$R6_CORPORATE_BASELINE" \
  --c09-replay-dir "$C09_REPLAY_DIR" \
  --c09-snapshot "$C09_SNAPSHOT" \
  --c09-cve "$C09_CVE" \
  --c09-advisory "$C09_ADVISORY" \
  --output-dir "$TMPDIR/r6-gap-regression"
```

The guard MUST assert:

- measured deterministic `7/18` remains unchanged;
- false-safe count remains `0`;
- C09 replay remains `NOT_AFFECTED`, `COMPLETE`;
- C09 has resolved evidence references;
- C09 remains `AutoClose=false`;
- legacy `/2` replay does not acquire `/3` fields;
- no model call occurs in replay;
- existing R6 fixtures remain valid.

Legacy C09 `/2` focused replay:

```bash
go run ./cmd/izyan research \
  --snapshot "$C09_SNAPSHOT" \
  --cve "$C09_CVE" \
  --advisory-file "$C09_ADVISORY" \
  --output-dir "$TMPDIR/c09-legacy-replay" \
  --replay-agent-turn "$C09_REPLAY_DIR"
```

Expected result: a valid legacy report with no `decision_artifact` member and no model/provider call.

**Acceptance:**

- The sanitized fixtures cover every new fail-closed branch.
- R6-G0 remains green.
- The C09 legacy `/2` guard remains green.
- The recorded `7/18` census is unchanged.
- Documentation describes actual behavior, not projected live performance.
- No private or credential-bearing material is committed.

**Out of scope:** live model/provider calls, live artifact-mirror downloads, owner acceptance study, automatic closure.

## Dependency / Execution Order

```text
Task 1
  → Task 2
    → Task 3
      → Task 4
Task 3
  → Task 5
    → Task 6
Task 4 + Task 6
  → Task 7
    → Task 8
      → final validation
```

Tasks 4 and 5 are independent after Task 3 and MAY be implemented in parallel. Task 6 requires both the report/artifact provenance contract and the symbol-authority route.

## Final Validation Sequence

Run only after all focused tests and R6-G0 pass.

1. Focused package suite from Task 8.
2. R6-G0 regression guard.
3. C09 legacy `/2` replay guard.
4. Full repository checks once:

```bash
gofmt -w internal cmd/izyan
go vet ./...
go test ./...
```

5. Run deterministic/replay-only R6 controls. Do not use live provider mode:

```bash
python3 eval/decision_ready/runner.py \
  --manifest "$R6_CONTROL_MANIFEST" \
  --mode deterministic-only \
  --output-dir "$TMPDIR/r6-controls-deterministic"
```

6. Run the recorded 18-case replay/deterministic census without live calls:

```bash
python3 eval/decision_ready/runner.py \
  --manifest "$R6_CORPORATE_MANIFEST" \
  --mode replay \
  --output-dir "$TMPDIR/r6-corporate-replay"
```

7. Run the full non-live evaluator corpus once if it does not invoke paid model/provider calls:

```bash
go run ./cmd/izyan eval \
  --corpus eval/corpus-real.json \
  -j 4
```

The existing live corpus command is **not part of the default validation sequence** while the paid/live budget is exhausted. If it is later requested, it requires explicit owner authorization, a new budget allocation, and a cost record before execution.

## Remaining Owner Decisions

1. **Credential environment-variable format — RESOLVED (2026-10-16, owner).**

   Confirmed contract (owner's injector can supply this format):

   ```text
   --artifact-credentials-env IZYAN_ARTIFACT_CREDENTIALS
   IZYAN_ARTIFACT_CREDENTIALS=username:password
   ```

   This matches the observed Basic-auth challenge from the artifact mirror (`401` + a `WWW-Authenticate: BASIC` challenge). No credential value belongs in the repository, the plan, logs, audit records, reports, manifests, fixtures or prompts.

2. **Paid live validation — REQUIRED before any live capability claim.**

   The current budget is exhausted (`23/20`). This plan intentionally schedules no live model calls and no live artifact-mirror download. The owner must separately authorize:

   - additional paid-call budget;
   - the number of cases and maximum turns per case;
   - whether live artifact retrieval is allowed in that environment.

   Until then, live results remain `NOT_RUN`/`HOLD_UNKNOWN`, and the implementation must not claim live symbol-unreachability or decision-ready yield.

## Assumptions

- **[INFERENCE]** `debug/buildinfo.ReadFile` is sufficient for the supported release binaries; the existing `go version -m` path remains available as a compatibility fallback.
- **[INFERENCE]** A full distribution ZIP can be handled safely by bounded extraction and deterministic candidate selection; ambiguous multi-binary archives remain fail-closed rather than requiring case-specific heuristics.
- **[INFERENCE]** Ticket/SBOM metadata can be represented by a sanitized `release-metadata/1` document or the existing explicit release-version input.
- **[INFERENCE]** The static source/index scope can be made complete for the declared supported inventory while continuing to reject unsupported runtime mechanisms and transports.
- **[INFERENCE]** The existing R6 `Fact`/`RuleFact` envelope can carry release trust class and symbol-unreachability provenance additively without changing the `/1` or `/2` wire contracts when the fields are omitted.

If implementation discovers that a fact changes any of these assumptions, the implementer MUST stop at the affected task, record the discrepancy, and return the design for review rather than weakening a gate or silently broadening the proof scope.
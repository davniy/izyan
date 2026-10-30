# Phase 6 Task 5 — Independent Fix-Source Captures Implementation Plan

**Gate: READY.** The contextual API cutover and canonical research producer integration below are approved engineering changes within Task5. No additional product-owned decision is required.

**Goal:** Produce genuine independently anchored patch-base and effective external-component premises, consume them through the existing fixbinding checker, and re-admit them against current case context without source-tree access.

**Architecture:** A strict local manifest supplies captured artifacts and source candidates, not authority. Runtime acquisition binds checksum and selection metadata to the independently acquired product snapshot. The existing `rootcause.Resolver` constructs proof inputs. Existing fixbinding derivation, correspondence, census and publication consumers remain the only proof machinery.

**Tech stack:** Go 1.25, existing `repository` t1 manifests, `affected` package inventory, `goanalysis` selected-source census, `fix.CapturedProvider`, `fixbinding` persistence/admission.

**Spec:** `docs/dev/plans/2026-10-28-10-phase6-evidence-classes.md`, Task5, replacing its implementation details with this amendment. Tasks1–4 remain accepted prerequisites.

## Global Constraints

- No new semantic patch engine, dependency-version solver, VCS trust scheme, network acquisition, or ambient replay fallback.
- A manifest digest authenticates transport integrity only.
- A product snapshot authenticates captured product metadata; it does not alone identify independent upstream/external source.
- Independent archive authority is the exact module/version h1 from product-authenticated `go.sum`, verified against the complete captured module ZIP.
- Locators are not a patch series.
- Missing or unsupported premises remain explicit obligations, not inferred successes.
- `SourceBundle`, `SourceInventory`, wrapper summaries, source-owner maps, `Complete`, and saved proof projections are not caller assertion channels.
- Preserve the existing selected-source splice route only where its current exact-match contract succeeds.
- All authoritative content-proof APIs require independent current context. No optional context, variadic compatibility signature, or model-only authoritative shim.
- Research must invoke the existing rootcause producer and retain its actual proof in the canonical record case. A parsed-but-unused flag or CLI-only DTO is not acceptance.
- Keep existing negative-admission semantics unchanged. A new source capture can earn a real cover; it does not independently mint a negative claim.
- Preserve accepted uncommitted changes. No commits are required.

## Review Focus

| Risk | Required control |
|---|---|
| ZIP and checksum replaced together | Checksum bytes must match the fixed product manifest under caller-owned `Product.ContentHash` |
| Snapshot hash replaced inside proof inputs | Contextual admission compares against the current case’s acquired product/build |
| Forged external module/version | Anchored selection metadata plus matching admitted raw inventory, not resolver version echo |
| Tree digest promoted to upstream authority | Tree carrier must reconcile exactly with an independent archive; product-only tree identity remains selected-source identity |
| Direct `PatchSources`/`External` injection | Reconstruct these fields from captured premises; do not read them as authority |
| Different fix locators composed into a series | Each capture starts from its own base and exact artifact |
| Replay quietly reads original paths | Remove trees/caches/capture files and exercise actual admission/publication |
| Canonical research ignores captures | Actual `requested-case.json` contains the existing resolver’s re-admittable proof |
| Historical research route accepts unsupported flag | Explicit rejection before execution |

## Decided Contracts

### Authoritative admission API

Add in `internal/fixbinding`:

```go
type AdmissionInput struct {
    Product        domain.ProductSnapshot
    Vulnerability  domain.Vulnerability
    RecordPin      *domain.RecordPin
    AdvisoryRecord *domain.AdvisoryRecordCapture
    Affected       *domain.AffectedResult
    Evidence       []domain.Evidence
}

func AdmissionForCase(c *domain.AnalysisCase) AdmissionInput

func Admit(
    ctx AdmissionInput,
    claimed Binding,
    in Inputs,
) (Binding, error)

func Persist(
    ctx AdmissionInput,
    claimed Binding,
    in Inputs,
) (*domain.FixProof, error)

func Readmit(
    ctx AdmissionInput,
    p *domain.FixProof,
) (Binding, error)

func AdmitModelProof(
    ctx AdmissionInput,
    m *domain.RootCauseModel,
) *domain.ContentAdmission
```

`AdmissionForCase(nil)` returns an empty context, which cannot admit a present proof. `AdmitModelProof(ctx, nil)` and a model without a proof retain the existing nil/no-proof behavior.

Keep:

```go
func Derive(in Inputs) (Binding, error)
```

`Derive` remains pure reconstruction. Its output is not contextual admission and must not bypass the authoritative APIs.

At authoritative admission:

1. Validate current advisory capture against the current record pin.
2. Require the proof’s record and captured document to identify that same record.
3. Require exactly the current affected-entry selection, including effective coordinate, source kind/root, replacement/workspace provenance and content identity.
4. Compare the captured build with `domain.EffectiveBuildContext(ctx.Product)`.
5. Validate the product manifest against **`ctx.Product.ContentHash`**, not an expected hash obtained from proof inputs.
6. Validate all product metadata bytes used for checksum/selection grounds against that manifest.
7. Resolve any captured inventory reference to matching evidence in `ctx.Evidence`; verify full raw payload, run and build, then use existing strict inventory decoding.
8. Reconstruct capture-derived source premises and run existing derivation/comparison.

Use the existing typed refusal system. Missing current context is a refusal, not permission to self-pin.

Bump `domain.FixProofContract` to `fixbinding/re-derivation/3`, reflecting the new required input/admission contract. Keep the existing semantic rules identifier: this amendment changes provenance and contextual admission, not correspondence semantics. Historical `/2` proofs cannot acquire `/3` authority by adding a status or projection.

### Capture data and authority

Introduce these named types in `internal/fixbinding/capture.go`:

- `CapturedFile`: confined relative `Path` and complete `Bytes`.
- `SourceCaptureContext`: captured `Build`, canonical `SnapshotManifest`, product metadata files used as premises, and the full existing inventory evidence when external selection needs it.
- `PatchBaseCapture`: exact `Locator`, `ArtifactDigest`, `ArchiveEvidence`, and optional complete tree-carrier files.
- `ExternalSourceCapture`: imported module namespace, runtime-checked `EffectiveSourceSelection`, independently checked `ArchiveEvidence`, and complete observed selected-source bytes/metadata needed for reconciliation.
- `SourceCaptures`: one entry’s context, selected-source observation premises, patch bases and external captures.

Add:

```go
Captures *SourceCaptures
```

to `fixbinding.Inputs`.

Existing `Inputs.Pin`, `EntryRef`, and `Selection` retain record/entry/selected identity; do not create a competing identity model.

Persist complete source observations where existing `json:"-"` fields would otherwise discard needed bytes. Do not persist only `SourceInventory` and restore arbitrary observations from saved digests or completeness flags.

`Inputs.PatchSources` and `Inputs.External` remain the existing checker-consumed projections, but their authoritative values are reconstructed:

- Patch sources come from independently anchored patch captures or from rerunning the existing selected-source splice against the verified selected inventory.
- External components come only from independently anchored, effectively selected captures.
- Saved or directly supplied projections cannot authorize missing capture premises.
- Reuse existing source census and wrapper derivation. Do not accept submitted owner maps or wrapper summaries.

Bind the capture premises to the canonical binding and cover identity with a checker-computed `CaptureDigest`; compare it during admission. Include the digest in the existing cover-premise identity calculation so capture scope cannot change without changing its proof identity.

### Supported tree boundary

Implement both of these positive cases:

1. Existing product-anchored local/workspace tree inventory and selected-source splice remain supported.
2. A complete captured tree is supported as a Task5 **source carrier** when its full module-relative regular-file set and bytes equal an independently checked module archive.

For the second case, archive/checksum evidence supplies authority. A tree’s digest does not.

Explicitly refuse independent-source authority from:

- tree-only VCS labels or commit strings;
- self-selected t1/content digests;
- product-only local/workspace identity used as an external anchor;
- versionless external sources without a supported independent anchor.

This preserves supported trees without inventing a VCS authenticator or silently reducing Task5 to ZIP-only handling.

### Strict manifest

Add `rootcause.SourceCaptureSet` and:

```go
func LoadSourceCaptures(path string) (*SourceCaptureSet, error)

func (s *SourceCaptureSet) PatchProvider() fix.ArtifactProvider
```

`PatchProvider` returns the existing `fix.CapturedProvider` over the already loaded artifact bytes.

Manifest shape:

```json
{
  "schema": "fix-source-captures.v1",
  "artifacts": [
    {
      "locator": "exact advisory locator",
      "path": "captures/fix.patch",
      "digest": "sha256:..."
    }
  ],
  "captures": [
    {
      "record_id": "exact record identity",
      "document_digest": "sha256:...",
      "entry_ref": 0,
      "selected_source": {},
      "patch_bases": [
        {
          "locator": "exact advisory locator",
          "artifact_digest": "sha256:...",
          "module": "example.com/module",
          "version": "v1.2.3",
          "archive_path": "captures/base.zip",
          "archive_digest": "sha256:...",
          "tree_path": "captures/base-tree"
        }
      ],
      "external": [
        {
          "import_path": "example.com/component",
          "declared_module": "example.com/component",
          "declared_version": "v2.3.4",
          "module": "example.com/effective-component",
          "version": "v2.3.5",
          "archive_path": "captures/component.zip",
          "archive_digest": "sha256:...",
          "tree_path": "captures/component-tree"
        }
      ]
    }
  ]
}
```

`selected_source` uses the existing descriptor shape. It is a selector checked against the actual case selection, not a producer-authored selection authority. `tree_path` is optional; other shown association fields are required for their corresponding entries.

Do **not** accept arbitrary `go_sum_path`, `go_sum_digest`, expected product hash, trust label, `Complete`, submitted inventories, or submitted source bundles. Acquire checksum and product-selection metadata from the current product.

Loader requirements:

- Strict unknown-field and trailing-content rejection.
- Reject ambiguous/duplicate record-entry-selection groups, artifact locators, patch-base associations, external namespaces and tree members.
- Relative paths are resolved under the manifest directory and must remain confined after symlink resolution; no URL inputs or network fallback.
- Reject symlink/nonregular captured files and tree entries.
- Hash complete referenced bytes, not a display prefix.
- Bound manifest, artifact, compressed archive, expanded archive, member count, per-file and aggregate capture sizes. Use package-private documented limits and test their enforcement; never truncate into a usable proof.
- Record groups for other exact records may coexist in a run-wide set, but must never supply premises to the current record.
- A matching record/entry group with a mismatching selected identity or artifact association is a refusal, not a silently ignored capture.

## Task 5.1: Cut Over Contextual Proof Admission and Captured-Premise Reconstruction

**Depends on:** Accepted Task4.

**Files:**
- Create: `internal/fixbinding/capture.go`
- Create: `internal/fixbinding/capture_test.go`
- Modify:
  - `internal/fixbinding/{proof.go,derive.go,admit.go,persist.go,cover.go,selected_source.go}`
  - `internal/domain/fix_proof.go`
  - All authoritative admission consumers listed below
- Test:
  - `internal/fixbinding/{proof_test.go,admit_test.go,activation_test.go,noncounterpart_test.go}`
  - Existing affected consumer tests

**Interfaces:**
- Produces the exact admission signatures and capture types above.
- Consumes existing anchor, inventory, selected-splice, correspondence and persistence implementations.

- [ ] Step 1: Add context-bound tests demonstrating that an otherwise valid proof cannot admit with missing context, a foreign product/build, a different record, a different affected-entry selection, or a proof-internal replacement product pin.
- [ ] Step 2: Run:
  ```bash
  go test ./internal/fixbinding -run 'Test(CaptureContext|PersistedProof|Refused)' -count=1
  ```
  Expected **FAIL** because the existing APIs lack contextual authority checks.
- [ ] Step 3: Implement the required capture context, authenticated product-file reconstruction and authoritative API cutover.
- [ ] Step 4: Make `Derive` reconstruct patch/external projections from captured premises and the verified selected-source route. Reassemble inventory aspects rather than trusting saved completeness.
- [ ] Step 5: Persist capture premises and compare the canonical capture digest. Remove the old authoritative signatures.
- [ ] Step 6: Migrate **every production callsite**:
  - `internal/rootcause/prooffix.go`: contextual `Persist`.
  - `internal/rootcause/rootcause.go`: contextual model admission.
  - `internal/exploit/builder.go`.
  - `internal/evaluator/{absence_identity.go,conditions.go}`.
  - `internal/goanalysis/negative.go`, all three admission paths.
  - `internal/finding/project.go`.
  - `internal/report/report.go`.
  - `internal/research/deterministic.go`.
  - `internal/states/states.go`.
- [ ] Step 7: Case-owning callers use `AdmissionForCase(c)`. `evaluator.absence_identity.go` constructs `AdmissionInput` from `VerdictInput.Product`, `Vulnerability`, `RecordPin`, `AdvisoryRecord`, `Affected`, and `Evidence`. No caller constructs context from `FixProof.Inputs`.
- [ ] Step 8: Update existing direct checker fixtures with genuine capture/context premises. Retain tests proving historical or asserted DTO-only proofs refuse; do not add a test-only authority bypass.
- [ ] Step 9: Run:
  ```bash
  go test ./internal/fixbinding ./internal/evaluator ./internal/finding ./internal/report ./internal/exploit ./internal/states ./internal/goanalysis ./internal/rootcause -run 'Test(CaptureContext|PersistedProof|Refused|Noncounterpart|SelectedSource|Absence|Binding)' -count=1
  ```
  Expected **PASS**.

**Acceptance:** Every authoritative proof consumer supplies independent current context. A valid source-free `/3` proof admits; a self-consistent proof with foreign or missing current context does not. Direct source maps and historical projections confer no authority.

## Task 5.2: Produce Independently Anchored Patch Bases and Effective External Components

**Depends on:** Task5.1.

**Files:**
- Create: `internal/rootcause/capture.go`
- Create: `internal/rootcause/capture_test.go`
- Modify:
  - `internal/rootcause/{rootcause.go,prooffix.go}`
  - `internal/goanalysis/{modulecensus.go,modulecensus_tree.go}`
  - `internal/fixbinding/{capture.go,selected_source.go}`
- Test:
  - `internal/fixbinding/{capture_test.go,proof_test.go,noncounterpart_test.go}`
  - `internal/goanalysis/modulecensus_test.go`

**Interfaces:**

Add to `rootcause.Resolver`:

```go
Captures *SourceCaptureSet
GoTool   affected.GoTool
```

Use the supplied tool/backend or already captured matching evidence; do not instantiate an ambient default tool.

Add:

```go
func (ix *Index) CaptureFixSources(
    ctx context.Context,
    c *domain.AnalysisCase,
    selection domain.EffectiveSourceSelection,
    requested fixbinding.SourceCaptures,
    tool affected.GoTool,
) (fixbinding.SourceCaptures, error)
```

This acquires and validates current product/observation premises and returns a persistable captured bundle. It does not admit a semantic claim.

- [ ] Step 1: Add:
  - `TestPatchBaseCaptureBindsExactLocatorAndArtifact`
  - `TestPatchBaseWrongTreeRefuses`
  - `TestExternalCaptureRequiresIndependentAnchor`
  - `TestTwoFixLocatorsNeverBecomeSeries`
  - `TestCaptureReplayNeedsNoSourceTree`
  - `TestCompleteTreeCarrierMatchesIndependentArchive`
  - `TestExternalCaptureRechecksEffectiveOwner`
- [ ] Step 2: Run:
  ```bash
  go test ./internal/fixbinding ./internal/rootcause ./internal/goanalysis -run 'Test(PatchBaseCapture|PatchBaseWrongTree|ExternalCapture|TwoFixLocators|CaptureReplay|CompleteTreeCarrier)' -count=1
  ```
  Expected **FAIL** because production lacks the independent producer.
- [ ] Step 3: Implement strict bounded local loading and the existing `fix.CapturedProvider` adapter.
- [ ] Step 4: In acquisition, require a bound matching source index. Capture the product manifest and validate it against the already acquired case product hash. Capture exact product `go.sum` and required selection metadata against manifest entries. Detect mutation across acquisition.
- [ ] Step 5: Validate every archive using its exact coordinate and the product-authenticated checksum. Cross-release bases are allowed when that exact base coordinate has such a checksum. Missing checksum remains an obligation; never generate one from the supplied ZIP.
- [ ] Step 6: For a supplied tree carrier, enumerate the complete confined regular-file tree and compare its entire file set and bytes with the independent archive in both directions. Missing, extra or modified files refuse.
- [ ] Step 7: Construct before/after images only after checking exact hunk/preimage positions. Include unchanged files needed for existing package/wrapper resolution. Preserve existing unsupported binary, rename and hunk limitations.
- [ ] Step 8: Reconstruct each locator independently. Neither duplicate artifact bytes nor declaration order imply shared source identity or series application.
- [ ] Step 9: Implement external effective-selection checks:
  - Require an actual imported package/edge from the captured selected implementation.
  - Use a matching admitted raw package inventory for the current non-test build, retaining its full existing evidence in the proof bundle and case.
  - Require inventory owner/coordinate facts to agree with captured product module-selection metadata and recorded replacement/workspace/carrier facts.
  - Support the direct versioned case whose version is explicitly grounded by captured root `go.mod`; apply existing explicit versioned-replacement/vendor selection rules where their captured metadata establishes the same result.
  - Do not infer the selected version from `go.sum`, manifest coordinates, cache presence, or a successful resolver echo.
  - Transitive/MVS-dependent or ambiguous selection that cannot be established by those supported grounds remains unresolved. Do not implement MVS.
  - Local/workspace component selection does not waive the separate independent-source-anchor requirement.
- [ ] Step 10: Use `SelectedSourceCensusFor`, `AssembleInventory`, and existing census/completeness aspects to measure actual selected bytes against the independent source. Discovery scans the full independent implementation, not only linked/vendor subsets.
- [ ] Step 11: In `proveContentBinding`, acquire the current entry’s capture premises, reconstruct projections **before** `FixApplicability`, then call existing `Derive` and contextual `Persist`. Capture failures remain visible limitations/obligations and cannot be replaced by submitted maps.
- [ ] Step 12: Run the focused command from Step2 and:
  ```bash
  go test ./internal/fixbinding -run 'Test(PersistedProof|Refused|Noncounterpart|SelectedSource)' -count=1
  ```
  Expected **PASS**.

**Acceptance:**

- A cross-release archive capture earns a real supported cover.
- A complete tree carrier earns that same capability through independent archive corroboration.
- A genuine independently anchored external component participates in the existing boundary/counterpart analysis.
- Existing selected local/workspace trees and selected-source splice continue working.
- Tree-only, vendor-only, self-pinned, unavailable and unsupported premises remain explicit.

## Task 5.3: Wire Analyze and Canonical Research to the Existing Producer and Prove Publication Replay

**Depends on:** Task5.2.

**Files:**
- Modify:
  - `cmd/izyan/{main.go,research.go}`
  - `internal/research/{deterministic.go,requested_finding.go}`
  - `internal/rootcause/capture.go`
  - Contextual callsites/tests from Task5.1 as needed
  - `docs/{cli.md,architecture.md}`
  - `docs/dev/{gap-analysis.md,analysis-internals.md}`
  - `eval/README.md`
- Create:
  - `cmd/izyan/fix_capture_test.go`
  - `internal/research/fix_capture_test.go`
- Test:
  - Existing requested-finding/publication, rootcause, fixbinding and research fixtures

**Interfaces:**

Add the CLI option:

```text
--fix-source-captures <path>
```

Add to `research.LaneOptions`:

```go
FixSourceCaptures *rootcause.SourceCaptureSet
```

Add to `research.LaneResult`:

```go
RecordRootCause *domain.RootCauseModel
```

Add the internal research helper:

```go
func laneFixSourceCaptures(
    ctx context.Context,
    res *LaneResult,
    sess *evidencetools.Session,
    captures *rootcause.SourceCaptureSet,
) error
```

### Analyze path

- [ ] Step 1: Load the manifest once and pass the loaded set to the actual `rootcause.Resolver` constructed in `cmd/izyan/main.go`.
- [ ] Step 2: When the flag is supplied, configure:
  ```go
  rootcause.Resolver{
      Fix:      fix.Resolver{},
      Patch:    captures.PatchProvider(),
      Source:   srcIndex,
      GoTool:   goTool,
      Captures: captures,
  }
  ```
  Missing captured artifacts remain unavailable through the existing provider. Do not fall back to HTTP.
- [ ] Step 3: Preserve the existing unconfigured analyze behavior; this task adds no new network route.

### Canonical research path

- [ ] Step 4: Parse/load the flag before lane execution and pass the loaded set through the actual `LaneOptions` constructed by `runResearch`.
- [ ] Step 5: Explicitly reject the flag for historical `--decision-ready` / `--replay-decision-run` routes rather than accepting and ignoring it.
- [ ] Step 6: Split existing `RecordCase` construction into:
  ```go
  func recordCase(lane *LaneResult) (*domain.AnalysisCase, error)
  ```
  for the existing assembly without final assessment, and keep exported `RecordCase` as assembly followed by `assessRecordCase`. Do not introduce a separate CLI case model.
- [ ] Step 7: Invoke `laneFixSourceCaptures` after `laneImplementationAxis` has finalized affected selection and before later proof consumers/persistence.
- [ ] Step 8: The helper uses `recordCase(res)` so the actual case has:
  - lane snapshot/build;
  - exact record pin and advisory capture;
  - finalized affected selections;
  - current affected/record evidence.
- [ ] Step 9: Invoke the existing resolver:
  ```go
  rootcause.Resolver{
      Fix:      fix.Resolver{},
      Patch:    captures.PatchProvider(),
      Source:   sess.Source,
      GoTool:   sess.GoTool,
      Captures: captures,
  }.Resolve(ctx, c, c.Vulnerability)
  ```
  Retain the returned model as `RecordRootCause`; add returned and capture-generated evidence to the case using its existing evidence graph, then retain that complete record evidence in the lane.
- [ ] Step 10: `RecordCase` copies the retained rootcause model, including complete proof inputs/artifact bytes, **before** `assessRecordCase`.
- [ ] Step 11: Preserve existing `RecordModel`, claims and semantic ownership. The capture helper must not create a parallel exploit engine, fabricate VERIFIED claims, or replace an existing proof model with a source-capture summary.
- [ ] Step 12: In `requestOwnerCase`, preserve `AdvisoryRecord` as well as the already copied `RootCause`; the current function omits the advisory capture needed by contextual publication.
- [ ] Step 13: Related child lanes receive the run-wide capture set but select only groups matching their own exact record pin, entry and selected identity. No primary-record premise may leak into a child assessment.
- [ ] Step 14: Existing requested-case persistence must carry the real rootcause proof and evidence. Replay uses those persisted premises—not the manifest path.

### Required end-to-end fixtures

- [ ] Step 15: Add a canonical research CLI fixture with local captured patch bytes, independent archive/checksum evidence, and a real supported operation. Assert the resulting `requested-case.json` contains a nonnil existing-resolver `RootCause.FixProof`, and contextual re-admission succeeds.
- [ ] Step 16: Add an independent supported operation fixture with different import aliases/wrapper structure. It must earn a real cover through existing analysis.
- [ ] Step 17: Add the genuine external-component success fixture with actual import and effective-owner grounds. Include a wrong effective owner/version/replacement control.
- [ ] Step 18: Add the complete-tree-carrier success fixture and missing/extra/changed-file refusal controls.
- [ ] Step 19: Add two distinct locator/base fixtures and prove the second cannot consume the first postimage.
- [ ] Step 20: Serialize the canonical case, remove original source trees, manifest files, capture files and caches, then exercise:
  - contextual `Readmit` / `AdmitModelProof`;
  - existing requested-finding projection;
  - existing report/publication admission.
  
  Assert the real capture-derived proof still admits with the persisted current case context. No filesystem rehydration is permitted.
- [ ] Step 21: Add repinned attacks:
  - replace ZIP plus transport digest plus submitted checksum candidate;
  - replace product manifest plus proof-internal expected hash;
  - change external inventory ownership and recompute raw inventory digests;
  - change selected descriptor, entry, record or artifact association.
  
  Keep the independent current case product/record/selection fixed. Each attack must refuse through the relevant provenance/association check.
- [ ] Step 22: Include an independently captured unsupported operation and assert its residual obligation remains. A capture alone must not make it supported.
- [ ] Step 23: Update documentation with the actual schema, contextual API, supported tree boundary, direct-versioned external-selection envelope, no-network behavior and source-free replay requirements.
- [ ] Step 24: Run:
  ```bash
  go test ./internal/fixbinding ./internal/rootcause ./internal/goanalysis ./internal/research ./cmd/izyan \
    -run 'Test(PatchBaseCapture|PatchBaseWrongTree|ExternalCapture|TwoFixLocators|CaptureReplay|CompleteTreeCarrier|CaptureContext|ResearchFixCapture)' \
    -count=1
  ```
  Expected **PASS**.
- [ ] Step 25: Run:
  ```bash
  go test ./internal/fixbinding ./internal/evaluator ./internal/finding ./internal/report ./internal/exploit ./internal/states ./internal/goanalysis ./internal/research ./internal/rootcause ./cmd/izyan \
    -run 'Test(PersistedProof|Refused|Noncounterpart|SelectedSource|Capture|PatchBase|ExternalCapture|TwoFixLocators|CompleteTreeCarrier|ResearchFixCapture|RequestedFinding)' \
    -count=1
  ```
  Expected **PASS**.

**Acceptance:** Both analyze and canonical research deliver the flag’s actual captured premises to the existing producer. A real supported archive, tree-carrier and external-component proof is persisted and contextually re-admitted after all original source/capture/cache paths become unavailable. Unsupported inputs retain obligations. No context-free authority API or ignored runtime flag remains.

## Dependency / Execution Order

**Task5.1 → Task5.2 → Task5.3.**

`P6T5FixCaptures` remains the sole Task5 integration owner. These are implementation units within Task5, not a request to start additional agents.

## Return-to-Design Conditions

Stop and report the precise conflicting source if implementation requires:

- independent tree-only VCS authority;
- checksum authority not grounded in the captured product;
- dependency selection requiring new MVS semantics;
- ambient source/cache/network replay inputs;
- a new semantic rule, wrapper authority or negative-admission shortcut;
- dropping the positive tree carrier, external component, canonical research producer, or source-free publication acceptance.

**No such product-owned blocker is presently identified.** The API and research changes above are required plumbing for the approved Task5 behavior, not a new product capability or parallel proof engine.
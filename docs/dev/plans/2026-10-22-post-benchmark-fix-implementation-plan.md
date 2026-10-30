# Post-Benchmark Fixes Implementation Plan

**Источник:** delegated `architect` artifact `agent://PostBenchArchReview` (2026-10-22), документ 2; сохранён.
**Goal:** restore Product A applicability and merge parity without weakening `false-safe=0` or the Shadow authority boundary.

**Architecture:** Shadow remains Product A authority; V2-derived components remain Product B adapters/research/evaluation.

**Tech stack:** Go, `go/packages`, Go AST/types, existing Shadow tests, existing frozen benchmark artifacts.

**Spec:**
- `docs/dev/roadmaps/2026-10-22-post-benchmark-fix-roadmap.md`
- `docs/dev/roadmaps/2026-10-20-target-architecture-and-roadmap.md` §14
- `docs/dev/spec-workflow.md`
- `docs/dev/specs/s01-identity-and-case-bundle.md`

## Global Constraints

1. Do not create a second verdict/evidence/claim contract.
2. Do not weaken `VersionAffected=UNKNOWN → INCONCLUSIVE`.
3. Do not infer release toolchain from `go.mod` or local analysis Go.
4. Do not classify an empty module name as stdlib.
5. Do not let an unknown unlinked advisory entry poison a linked entry with known applicability.
6. If a malformed entry has a unique linked subject, keep the result non-admitting.
7. Preserve master panic fixes.
8. Preserve fail-closed scope semantics.
9. Do not change Product B into Product A authority.
10. Do not run the full benchmark until all implementation tasks and focused tests are complete.
11. Do not modify or overwrite existing benchmark artifacts.
12. When a contract, identity, or failure semantic is discovered to differ from this plan, stop and return to design review.

## Review Focus

- Empty/malformed OSV entries.
- Duplicate package subjects across advisory entries.
- Multiple valid affected modules.
- Stdlib and third-party entries in one advisory.
- Unknown release toolchain.
- Ticket/package mismatch.
- Pending module with linked package.
- Pending module without linked package.
- Importer closure partiality.
- Context cancellation and timeout.
- Replay and Product B authority boundaries.

---

### Task 1: Freeze the fix inputs and add the roadmap/plan artifacts

**Depends on:** None

**Files:**
- Create: `docs/dev/roadmaps/2026-10-22-post-benchmark-fix-roadmap.md`
- Create: `docs/dev/plans/2026-10-22-post-benchmark-fix-implementation-plan.md`
- Modify: `docs/dev/INDEX.md` if the repository index lists active roadmaps/plans

**Interfaces:**
- Consumes: existing benchmark and S-05 artifacts
- Produces: one canonical fix roadmap and one executable implementation plan

**Steps:**

- [ ] Record branch/master commits and benchmark artifact paths.
- [ ] Record the known Product A/Product B boundary.
- [ ] Record P0/P1/P2 ordering and merge gate.
- [ ] Mark the status `NO-GO until P0 gates pass`.
- [ ] Do not edit existing benchmark results.

**Acceptance:**

The repository has one canonical roadmap and one implementation plan. The plan explicitly says which claims are proven, inferred, or unproven.

---

### Task 2: Add OSV normalization tests for empty and duplicate entries

**Depends on:** Task 1

**Files:**
- Modify: `internal/vulnerability/osv.go`
- Test: `internal/vulnerability/osv_test.go`
- Modify only if required by the existing model: `internal/domain/domain.go`

**Interfaces:**
- Consumes: `osvDocument`, `domain.Vulnerability`, `domain.AffectedModule`
- Produces: normalized affected-entry data with valid module ownership

**Required behavior:**

1. A valid named module remains a separate `AffectedModule`.
2. An empty module name is never treated as stdlib.
3. Duplicate package/symbol subjects from an empty entry may be merged into the valid named entry only when ownership is unambiguous.
4. An empty entry with unique subjects remains represented as unresolved/non-admitting data.
5. Non-Go ecosystem entries are not converted into Go affected modules.

**Tests to add:**

- `TestOSVEmptyModuleDuplicateSubjectsDoNotCreateStdlibEntry`
- `TestOSVEmptyModuleUniqueSubjectsRemainUnresolved`
- `TestOSVMultiModuleEntriesPreserveModuleOwnership`
- `TestOSVNonGoEntryIsNotGoAffectedModule`

**Focused command:**

```bash
go test ./internal/vulnerability
```

**Acceptance:**

The parser never emits an empty entry that the resolver can mistake for stdlib. Tests inspect `AffectedModules` directly.

---

### Task 3: Make stdlib classification exact

**Depends on:** Task 2

**Files:**
- Modify: `internal/affected/resolver.go`
- Review callers: `internal/states/states.go`
- Test: `internal/affected/resolver_test.go`
- Test if needed: `internal/evaluator/platform_test.go`

**Interfaces:**
- Consumes: module path string
- Produces: exact stdlib/toolchain classification

**Required behavior:**

`isStdlibModule` returns true only for the explicitly supported pseudo-modules:

```text
std
stdlib
toolchain
cmd
```

It MUST return false for:

```text
""
"example"
"example/module"
```

Do not broaden classification using “first path segment has no dot”.

**Tests to add:**

- `TestIsStdlibModuleRejectsEmpty`
- `TestIsStdlibModuleRejectsDotlessThirdPartyPath`
- `TestIsStdlibModuleAcceptsKnownPseudoModules`

**Focused command:**

```bash
go test ./internal/affected ./internal/evaluator
```

**Acceptance:**

An empty advisory entry cannot enter the stdlib release-toolchain branch.

---

### Task 4: Fix per-entry resolver ownership and applicability

**Depends on:** Tasks 2–3

**Files:**
- Modify: `internal/affected/resolver.go`
- Modify only if required by report fields: `internal/domain/domain.go`
- Test: `internal/affected/resolver_test.go`
- Test: `internal/affected/artifact_resolver_test.go` if release-entry behavior is covered there

**Interfaces:**
- Consumes: `domain.Vulnerability`, module graph, package graph, `ProductSnapshot`
- Produces: `domain.AffectedResult` with entry-local applicability and package ownership

**Required behavior:**

1. Resolve every valid advisory entry independently.
2. For third-party entries, use the authoritative release module graph when present; otherwise fall back to the source/vendor module graph. A failed required release-artifact channel remains fail-closed: source/vendor must not substitute for the unavailable release version.
3. Use authoritative release **toolchain** evidence only for stdlib/toolchain entries. Release Go evidence does not gate third-party module applicability.
4. Probe packages for pending entries only to determine whether their subjects are linked.
5. An unknown entry with no linked subject MUST NOT poison a valid linked entry.
6. A pending entry with a linked unique subject MUST keep the result `UNKNOWN`.
7. Duplicate subjects shared by an empty/malformed entry and a valid named entry must be owned by the valid named entry.
8. `SelectedModule`, `SelectedModules`, `PendingModules`, `UnresolvedModules`, and `VersionAffectedModules` MUST NOT contain empty module names.
9. `ResolvedVersion` MUST describe the selected linked module, never an unrelated entry.

**Release-evidence axis (normative, architecture decision 2026-10-23):** stdlib/toolchain applicability is resolved only from authoritative release **toolchain** evidence; third-party presence and version applicability prefer the authoritative release **module graph** when it is available and fall back to source/vendor only when it is not. A failed required release-artifact channel is fail-closed and cannot be replaced by source data. Package/build closure continues to use the source/vendor package graph.

**Tests to add:**

- `TestNamedModuleResolvesWithoutReleaseToolchain`
- `TestEmptyDuplicateEntryDoesNotPoisonNamedModule`
- `TestEmptyUniqueLinkedEntryRemainsUnknown`
- `TestEmptyUniqueUnlinkedEntryDoesNotPoisonNamedModule`
- `TestStdlibUnknownReleaseBlocksOnlyLinkedStdlibEntry`
- `TestTwoLinkedModulesKeepIndependentVersions`
- `TestPendingUnlinkedModuleDoesNotBlockConfirmedLinkedModule`
- `TestAffectedResultNeverReportsEmptySelectedModule`
- `TestAbsentNamedModuleWithUnlinkedUnnamedEntryStaysUnknown`

**Focused command:**

```bash
go test ./internal/affected
```

**Acceptance:**

A fixture equivalent to the lost grpc/amqp cases produces:

```text
ModulePresent=TRUE
VersionAffected=TRUE
PackagePresent=TRUE
BuildRelevant=TRUE
ResolvedVersion=<exact resolved version: release module graph when authoritative, else source/vendor>
```

when the named third-party module is linked and its version is known, even if another advisory entry has unknown release applicability. The version source follows the axis rule above; package/build linkage still uses the source/vendor package graph.

---

### Task 5: Verify evaluator precedence remains fail-closed

**Depends on:** Task 4

**Files:**
- Modify only if required: `internal/evaluator/verdict.go`
- Test: `internal/evaluator/verdict_test.go`
- Review: `internal/evaluator/platform.go`

**Interfaces:**
- Consumes: `AffectedResult`, exploit model, claims
- Produces: deterministic `VerdictResult`

**Required behavior:**

Keep these rules unchanged:

1. `VersionAffected=UNKNOWN` blocks positive and falsifier-based negative verdicts for the linked entry.
2. `VulnerableImplementationPresent=FALSE` requires package/build axes to be established.
3. LLM proposals cannot alter evaluator authority.
4. Empty/foreign/malformed applicability cannot produce `NOT_AFFECTED`.
5. A valid third-party module entry may reach exploit evaluation even if a separate stdlib entry remains unresolved.

**Tests to add:**

- `TestUnknownUnlinkedAlternativeDoesNotBlockKnownLinkedModule`
- `TestUnknownLinkedEntryRemainsInconclusive`
- `TestEmptyModuleCannotProduceNotAffected`
- `TestLLMProposalCannotOverrideUnknownApplicability`

**Focused command:**

```bash
go test ./internal/evaluator ./internal/states
```

**Acceptance:**

The evaluator remains conservative while no longer receiving a polluted global `UNKNOWN` from unrelated advisory entries.

---

### Task 6: Add release-evidence input and report contract

**Depends on:** Task 5

**Files:**
- Review/modify: `cmd/izyan/main.go`
- Review/modify: `internal/repository/releaseevidence.go`
- Review/modify: `internal/domain/release.go`
- Review/modify: `docs/cli.md`
- Test: existing release-evidence tests under `internal/affected`
- Test: CLI flag tests under `cmd/izyan`

**Interfaces:**
- Consumes: `--release-go-version`, `--binary`, release metadata
- Produces: authoritative/supporting release evidence and explicit limitations

**Required behavior:**

1. `--release-go-version` remains authoritative for stdlib applicability.
2. Binary build info outranks supporting declarations.
3. `go.mod` remains supporting/minimum evidence only.
4. Local analysis Go is never release evidence.
5. Missing release evidence is reported as `UNKNOWN` for stdlib applicability.
6. Third-party module applicability remains independent of release **Go toolchain** evidence. An authoritative release **module graph**, when present, is the preferred third-party presence/version source; source/vendor is the fallback. A failed required release-artifact channel remains fail-closed.

**Tests to add or confirm:**

- supporting `go.mod` does not populate authoritative release version;
- explicit release version does;
- binary evidence wins;
- conflicting authoritative evidence fails closed;
- third-party module version still resolves without release Go evidence;
- an authoritative release module graph resolves a third-party entry while a separate stdlib entry remains `UNKNOWN` (axis independence).

**Focused commands:**

```bash
go test ./internal/affected ./internal/repository
go test ./cmd/izyan
```

**Acceptance:**

Every report distinguishes:

```text
analysis toolchain
minimum go.mod version
authoritative release toolchain
authoritative release module graph (third-party, when present)
source/vendor module version (fallback)
```

---

### Task 7: Bound and reuse expensive Product A scope work

**Depends on:** Task 5

**Files:**
- Review/modify: `internal/goanalysis/source.go`
- Review/modify: `internal/goanalysis/toolscope.go`
- Review/modify: `internal/goanalysis/unreachability_scope.go`
- Review/modify: `internal/goanalysis/unreachability.go`
- Review/modify: `internal/goanalysis/sinkclosure.go`
- Review/modify: `internal/states/states.go`
- Tests: existing `internal/goanalysis/*_test.go`
- Add focused tests: `internal/goanalysis/budget_regression_test.go`

**Interfaces:**
- Consumes: one `goanalysis.Index` and one analysis context
- Produces: cached, bounded scope/closure observations; incomplete results remain non-admitting

**Required behavior:**

1. Reuse one loaded product/importer closure within a verification session.
2. Do not rerun identical shipping-scope construction for every subject.
3. Propagate context cancellation through package loading and closure queries.
4. Preserve open/partial status when a load/evaluation budget is exhausted.
5. Never convert timeout, skipped package, or open dispatch into safe-negative.
6. Record named budget limitations.
7. Do not increase the external timeout as the only change.

**Focused tests:**

- same index/fixture reuses shipping scope;
- canceled context stops closure work;
- load budget exhaustion returns incomplete result;
- open `MayCallSites` remains non-admitting;
- skipped package remains in scope denominator;
- repeated subject verification does not discard unresolved state.

**Focused command:**

```bash
go test ./internal/goanalysis
```

**Acceptance:**

The code has explicit bounded behavior and no new path from timeout/partial scope to `NOT_AFFECTED` or `NO_EXPLOIT_PATH_FOUND`.

---

### Task 8: Keep Product B outside Product A authority

**Depends on:** Task 1

**Files:**
- Review: `internal/productb/`
- Review: `cmd/izyan/triage.go`
- Review: `cmd/izyan/researchb.go`
- Review: `internal/productb/triage/`
- Test: existing Product B boundary/replay tests
- Modify only documentation if a boundary is unclear

**Interfaces:**
- Consumes: Product B finding/proposal/observation
- Produces: Product B assessment, `DecisionPackage`, policy result, research report

**Required behavior:**

1. Product B cannot construct or mutate Product A `VerdictResult`.
2. Proposal authority fields remain rejected.
3. Product B semantic dismissal remains default-off.
4. Product B replay requires no LLM/network.
5. Product B VEX projection remains non-authoritative.
6. Product B test success is not reported as Product A benchmark improvement.

**Focused commands:**

```bash
go test ./internal/productb/...
go test ./cmd/izyan
go test ./cmd/izyan-heldout-gate
```

**Acceptance:**

Static boundary tests pass and no Product B package imports a second Product A authority contract.

---

### Task 9: Record benchmark input contract without changing historical artifacts

**Depends on:** Tasks 1 and 6

**Files:**
- Modify: `bench/STATUS.md` only if adding a new benchmark manifest is required
- Create: `bench/POST-FIX-MANIFEST.md`
- Do not overwrite: `bench/REPORT.md`, `bench/LLM-ANALYSIS.md`, `bench/metrics.json`, `bench/per-case.jsonl`

**Interfaces:**
- Consumes: frozen corpus, snapshots, advisories, release evidence, timeout profile
- Produces: reproducible post-fix comparison manifest

**Required manifest fields:**

- master/branch commit;
- binary SHA-256;
- corpus and advisory hashes;
- snapshot identity method;
- target GOOS/GOARCH/CGO;
- module cache;
- release evidence per stdlib case;
- timeout;
- workers;
- memory limit;
- deterministic/LLM flags;
- Product A versus Product B lane.

**Acceptance:**

A future run can distinguish:

- analyzer defect;
- missing release input;
- harness timeout;
- honest `INCONCLUSIVE`;
- Product B non-authoritative result.

No existing result is rewritten.

---

### Task 10: Final post-fix verification and merge decision

**Depends on:** Tasks 1–9

**Files:**
- No code changes.
- Verification artifacts under the benchmark output directory.
- Update `docs/dev/reports/2026-10-22-post-fix-verification.md`.

**Checks to run by the verification owner, once, after all implementation changes:**

Focused checks:

```bash
go test ./internal/vulnerability
go test ./internal/affected
go test ./internal/evaluator
go test ./internal/goanalysis
go test ./internal/productb/...
go test ./cmd/izyan
go test ./cmd/izyan-heldout-gate
go build ./...
go vet ./...
```

Then the pinned Product A comparison using the post-fix manifest.

**Product A GO criteria:**

- `false-safe=0`;
- confirmed TP `>=6/35`;
- rejected safe closure `>=16/18`, or approved durable `INCONCLUSIVE` explanation for each difference;
- VEX TP `>=1/7`;
- VEX safe-clear `>=10/23`;
- completion not below master;
- no master-completing case becomes timeout;
- no new panic;
- no empty selected/pending/unresolved module names;
- Product B boundary gates pass.

**Acceptance:**

- If all gates pass: status `GO`, branch may merge.
- If safety passes but detection/performance fails: status `NO-GO`, keep Product B and safety fixes, isolate/revert heavy default scope path.
- If any false-safe appears: immediate `NO-GO`; investigate before any further benchmark interpretation.

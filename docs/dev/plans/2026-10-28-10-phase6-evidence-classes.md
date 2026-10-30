# Ordered Evidence-Class Proof Extensions Implementation Plan (Phase Six)

**Series:** `docs/dev/plans/2026-10-28-05-remaining-architecture-series.md` (order, prerequisites, series-wide invariants).


**Goal:** Extend deterministic proof capability through reusable evidence classes, in the prescribed order, without speculative universal analysis engines.

**Architecture:** First unify complete build inventory, then connect existing bounded unreachability to that inventory, then add narrow configuration writer/override evidence and admission, then capture supported patch-base/external-component premises. Each extension has a closed proposition, counterexamples and an independent fixture.

**Tech stack:** Go 1.25; existing `affected.GoTool`, `goanalysis.Index`, canonical evidence/admission DTOs, source census/anchors, `fixbinding` checker and replay sidecars.

**Spec:** Governing review §6 Phase 6; canonical negative-admission and provenance rules.

## Global Constraints

- Apply the series-wide invariants.
- Required priority: inventory → bounded unreachability → effective configuration/writers/overrides → supported patch-base/external capture.
- No generic taint engine or universal semantic patch engine.
- A package inventory is not whole-upstream-source completeness; vendor membership is not an independent source anchor.
- No new proof capability is accepted solely because a persisted DTO says `Complete=true`.
- Product B may consume new observations immediately; machine admission remains independent.
- This phase does not execute the Phase 5 benchmark.

## Review Focus

| Concern | Owning task |
|---|---|
| Truncated/error/dangling package streams cannot establish absence | Task 1 |
| Deadness requires complete build and correct semantic locus | Task 2 |
| “Safe assignments found” is not a closed effective configuration | Tasks 3–4 |
| Default/alias/copy/escape/override channels remain open unless covered | Tasks 3–4 |
| Patch-base and external component must have independent identity | Task 5 |
| Capability works beyond the motivating case | Every task’s second structural fixture |

### Task 1: Expose and reuse one admitted build/package inventory

**Depends on:** Phases 2–4

**Files:**
- Create:
  - `internal/evidencetools/inventory.go`
  - `internal/evidencetools/inventory_test.go`
- Modify:
  - `internal/affected/golist.go`
  - `internal/domain/measurement.go`
  - `internal/goanalysis/toolscope.go`
  - `internal/goanalysis/product_shape.go`
  - `internal/evidencetools/check_specs.go`
  - `internal/evidencetools/mcp.go`
  - `internal/evidencetools/verify_code_absence.go`
  - `internal/productb/triage/materials.go`
  - `internal/productb/triage/providers.go`
- Test:
  - `internal/affected/golist_test.go`
  - `internal/goanalysis/coverage_test.go`
  - `internal/evidencetools/verify_code_absence_test.go`
  - `internal/productb/triage/materials_test.go`

**Interfaces:**
- Consumes:
  - `GoTool.ListPackagesScope`
  - `CompletePackageInventory`, `SelectCompletePackageList`, `AdmittedBuildGraph`
  - `ImportClosure`, `EnumerateImportClosure`
- Produces:
  - Catalog capability `package-inventory` with `{with_tests}`.
  - `PackageInventoryData`: raw-stream digest/reference, `PackageListRun`, decoded package identities, effective build identity and explicit scope.
  - One strict package-stream decoder/completeness decision reused by inventory consumers.

- [ ] Step 1: Add `TestPackageInventoryComplete`, `TestPackageInventoryRejectsPartialGraph`, `TestPackageInventoryBuildIdentity` and `TestImportClosureUsesAdmittedInventory`. Cover truncated JSON, package errors, duplicate nodes, dangling imports, orphan nodes, test-only packages and foreign build context.
- [ ] Step 2: Run:
  ```bash
  go test ./internal/affected ./internal/goanalysis ./internal/evidencetools -run 'Test(PackageInventory|ImportClosureUsesAdmitted)' -count=1
  ```
  Expected **FAIL**.
- [ ] Step 3: Produce the inventory through the existing Go tool under the identified build. Mark COMPLETE only after command success and strict edge-closed decoding. A vendor-only derivation must keep its existing narrower semantics; do not stamp it as a complete arbitrary Go build.
- [ ] Step 4: Reuse the admitted inventory in source/import-closure and code-absence paths. Preserve full stream bytes as a digest-bound payload and expose bounded display projections. Keep module graph completeness distinct.
- [ ] Step 5: Rerun the focused command; expected **PASS**. Add a second fixture with a different module arrangement, including local replacement or vendoring, and verify that missing source/load coverage cannot be repaired by a complete package list alone.

**Acceptance:** Every absence consumer names the complete matching inventory it used; failed inventory never becomes an empty closed universe.

### Task 2: Integrate existing bounded unreachability with the canonical inventory

**Depends on:** Task 1

**Files:**
- Modify:
  - `internal/goanalysis/unreachability.go`
  - `internal/goanalysis/locusverify.go`
  - `internal/evidencetools/unreachability.go`
  - `internal/productb/triage/unreachability_proof.go`
  - `internal/productb/triage/falsifier.go`
  - `internal/research/deterministic.go`
  - `internal/research/decision.go`
- Test:
  - `internal/goanalysis/unreachability_test.go`
  - `internal/goanalysis/locusverify_test.go`
  - `internal/evidencetools/unreachability_test.go`
  - `internal/productb/triage/kernelparity_test.go`
  - `internal/research/deterministic_symbol_test.go`
  - `internal/research/decision_test.go`

**Interfaces:**
- Consumes:
  - Task 1 inventory
  - `Index.VerifyUnreachable`, `UnreachabilityResult`
  - `ValidateDeadnessPremise`, `RequireDeadnessPremise`
- Produces:
  - Unreachability observations explicitly bound to the admitted inventory/build.
  - Consistent declaration, dispatch, dynamic-marker, dependency and gated-reference closure across existing consumers.
  - No revival of Phase 2’s automatic Product B proof minting.

- [ ] Step 1: Add `TestUnreachabilityRequiresMatchingInventory`, `TestOmittedCheckDeadnessDoesNotRefuteOmission`, `TestUnreachabilityOpenDispatchStaysUnknown` and `TestUnreachabilityReplayRequiresFullPayload`.
- [ ] Step 2: Run:
  ```bash
  go test ./internal/goanalysis ./internal/evidencetools ./internal/productb/triage ./internal/research -run 'Test(UnreachabilityRequires|OmittedCheckDeadness|UnreachabilityOpenDispatch|UnreachabilityReplay)' -count=1
  ```
  Expected **FAIL** for missing shared inventory bindings.
- [ ] Step 3: Reuse the existing bounded kernel; do not create another reachability algorithm. Bind its checked subjects and build to Task 1’s inventory and retain every open scope gate.
- [ ] Step 4: At proof consumers, require the existing admitted semantic premise and exact locus coverage. Ordinary deadness remains an observation where necessity is unavailable. Replay rechecks the persisted complete payload and semantic contract without loading source.
- [ ] Step 5: Rerun the focused command; expected **PASS**. Add an independent two-subject fixture where one subject is live, proving that a closed result for the other cannot close the advisory.

**Acceptance:** Corrected inputs can exercise the existing bounded proof machinery without broadening its semantics or introducing model-derived necessity.

### Task 3: Capture configuration writer, default and override evidence

**Depends on:** Task 2

**Files:**
- Create:
  - `internal/domain/configuration_evidence.go`
  - `internal/goanalysis/configwriters.go`
  - `internal/goanalysis/configwriters_test.go`
- Modify:
  - `internal/domain/domain.go`
  - `internal/goanalysis/config.go`
  - `internal/goanalysis/ingress.go`
  - `internal/evidencetools/dynamic.go`
  - `internal/states/states.go`
- Test:
  - `internal/evidencetools/call_test.go`
  - `internal/evaluator/configflag_test.go`
  - Create: `internal/evidencetools/configwriters_test.go`

**Interfaces:**
- Consumes:
  - `FieldAssignments`, `SymbolFieldType`, existing writer/escape analysis
  - Task 1 build inventory and existing source provenance
- Produces:
  - `ConfigWriterEvidence`: exact field/object identity, consuming sites, assignments/defaults, copies/aliases, override channels, escape/open-scope blockers and source/build pins.
  - `Index.ConfigWriters(ctx, ref) (ConfigWriterEvidence, error)`.
  - `field_assignments` returns the richer observation without claiming effective safety.

- [ ] Step 1: Add `TestConfigWritersRecordDefaultsAndOverrides`, `TestConfigWritersOpenOnEscape`, `TestConfigWritersDistinguishObjects` and `TestConfigWriterObservationDoesNotProveSafety`.
- [ ] Step 2: Run:
  ```bash
  go test ./internal/goanalysis ./internal/evidencetools ./internal/evaluator -run 'Test(ConfigWriters|ConfigWriterObservation)' -count=1
  ```
  Expected **FAIL**.
- [ ] Step 3: Extend bounded typed writer enumeration. Record literal/constant values, constructor/default writes, whole-struct copies, address-taking, unresolved writers, runtime readers and escapes. Environment/flag/config-file discovery records an override channel; its name does not establish its effective value.
- [ ] Step 4: Bind object identity and actual consumption. A scan of all writes to `Type.Field` is not automatically a proof about the instance passed to a vulnerable operation. Unsupported aliases, callbacks, reflection, deserialization, external mutation or scope gaps remain explicit blockers.
- [ ] Step 5: Rerun the focused command; expected **PASS**. Use two independent structures: a locally constructed scalar-boolean configuration and a copied/defaulted configuration with an external override.

**Acceptance:** The evidence explains what writes and overrides were measured and why effective configuration is either closed or still unknown.

### Task 4: Admit a snapshot-replayable boolean configuration falsifier for CHECK_TRIGGER

**Depends on:** Task 3 and the approved narrow `CHECK_TRIGGER` amendment.

**Files:**

- Create:
  - `internal/domain/check_mechanism.go`
  - `internal/domain/check_mechanism_test.go`
  - `internal/goanalysis/configcertificate.go`
  - `internal/goanalysis/negative_config_test.go`
  - `internal/states/config_certificate_test.go`
  - `testdata/configcheckdirectprod/{go.mod,main.go,advisory.json}`
  - `testdata/configcheckcopyprod/{go.mod,main.go,advisory.json}`
  - `testdata/configcheckcopyprod/dep/{go.mod,check/check.go}`
- Modify:
  - `internal/domain/configuration_evidence.go`
  - `internal/domain/negative_admission.go`
  - `internal/exploit/semantics.go`
  - `internal/affected/golist.go`
  - `internal/repository/contenthash.go`
  - `internal/repository/service.go`
  - `internal/goanalysis/negative.go`
  - `internal/goanalysis/negative_admission.go`
  - `internal/evaluator/configflag.go`
  - `internal/evaluator/checktrigger.go`
  - `internal/evaluator/verdict.go`
  - `internal/states/states.go`
  - `internal/finding/project.go`
  - `internal/report/report.go`
  - `internal/research/decision.go`
  - `internal/research/requested_finding.go`
  - `docs/dev/gap-analysis.md`
  - `eval/README.md`
- Test/update existing callers:
  - `internal/exploit/defect_semantics_test.go`
  - `internal/repository/contenthash_test.go`
  - Existing snapshot tests in `internal/repository`
  - `internal/evaluator/configflag_test.go`
  - `internal/evaluator/checktrigger_test.go`
  - `internal/evaluator/measurement_admission_test.go`
  - `internal/evaluator/absence_identity_test.go`
  - `internal/goanalysis/negative_admission_test.go`
  - `internal/goanalysis/locusverify_deadness_test.go`
  - `internal/finding/project_test.go`
  - `internal/report/report_test.go`
  - `cmd/izyan/target_provenance_calibration_test.go`

#### Interfaces

**Consumes:**

- Task 1 canonical complete non-test inventory and its full raw bytes.
- Task 3 `ConfigWritersWithInventory`, exact storage declarations and call-coordinate conventions.
- Existing `AdvisoryRecordCapture`, `RecordPin`, `vulnerability.LoadExactBytes`.
- Existing `DefectSemanticsContract`, `ValidateDefectSemanticsModel`, `CheckConditionMatchesContract`.
- Existing repository `ContentHash` encoding, currently version `t1`.
- Existing `FalsifierSafeConfigAssignment`.

**Produces:**

1. One shared extraction of the existing pure advisory mechanism grammar.
2. A complete snapshot-anchored configuration certificate.
3. One `goanalysis.ValidateConfigWriterEvidence` checker used live and during persisted admission.
4. An explicit-context replacement for `ValidateVerifiedNegative`.
5. A real successful producer → evaluator → verifier → persisted-publication path on two independent fixtures.

#### A. Shared necessary-argument grammar

Move the existing **pure** mechanism extraction from `internal/exploit/semantics.go` into `internal/domain/check_mechanism.go`; do not create a competing recognizer.

Provide:

```go
func CheckMechanismText(v Vulnerability) string
func ParseCheckMechanism(text string, check SymbolRef) CheckMechanismStatements
func BindCheckArgumentPredicate(
    statements CheckMechanismStatements,
    formalNames []string,
) (CheckArgumentPredicate, error)
```

`CheckMechanismStatements` exposes the existing extraction results: invocation, omission, quotations, argument name/value, payload claim/shapes, effect and conflict indicators.

Preserve the existing description-before-summary selection, sentence splitting, invocation grammar, normalization, omission negation and conflict handling. Update the builder to use these functions and remove the superseded local implementation.

The builder supplies formal names from `Index.SymbolSignature`; replay supplies them from the captured `*types.Func` signature. Both use `BindCheckArgumentPredicate`. Domain remains a pure leaf: it imports neither `exploit` nor `goanalysis`.

The new negative requires:

- A validated, nonempty `AdvisoryRecordCapture`.
- Its pin, the independently supplied current `RecordPin`, certificate record and contract record ID/digest to identify the same document.
- `vulnerability.LoadExactBytes` to reparse those captured bytes; no alias-enriched or sibling record substitutes.
- The frozen record’s identity and mechanism text to agree with the assessment’s supplied vulnerability.
- A successful `ValidateDefectSemanticsModel`.
- `DEFECTIVE_CHECK`, an exact mandatory `CHECK_TRIGGER` condition, and `CheckConditionMatchesContract`.
- Explicit condition subjects to resolve exactly to the contracted operation. No root-cause fallback.
- The operation to be record-declared through `RecordDeclaresSubject`, or established by an existing own-record `OperationBinding` re-admitted against the frozen record and current pin.
- Shared parsing of the full mechanism text to establish an invocation predicate without conflicting invocation/omission evidence.
- The invocation ground to cite the matching own-record text and quotation.
- Shared argument binding to reproduce the contract’s name/index/literal.
- The formal parameter and trigger literal to be boolean. Support `true` and `false`; do not interpret `"1"` as a boolean trigger.

Matching quotation bytes alone is insufficient. Editing the contract’s argument and matching condition params must fail replay.

#### B. Independent snapshot source anchor

Add these repository APIs:

```go
func CaptureContentManifest(root string) ([]byte, error)
func ValidateContentManifest(
    raw []byte,
    expectedContentHash string,
) ([]ContentManifestEntry, error)
```

Use the **same canonical entry encoder** as `ContentHash`; do not invent another tree digest or change existing `t1` hashes. Keep ordinary `ContentHash` streaming; manifest allocation occurs only when capture is requested.

The manifest records the existing sorted path/kind/executable-bit/size/payload entries. For regular files, payload is the file digest. Pure validation checks canonical framing, valid confined paths, unique ordered entries and the independently supplied expected root hash. Reject ambiguous/control-character path encodings rather than guessing their interpretation.

At snapshot acquisition, compute `Product.ContentHash` for native source snapshots as well as the already-supported external snapshots, **before** index binding or analysis. Reuse existing containment checks. Do not compute a new hash during proof admission and relabel it as the snapshot’s original identity.

Capture checks the snapshot identity before and after reading proof inputs. Mutation refuses the capture.

This first certificate supports source within the anchored product tree, including nested local replacements and vendored source within that tree. Source from an unanchored external replacement or module cache remains insufficient scope. A commit string or a certificate’s self-generated file hashes do not replace the content anchor.

#### C. Certificate DTOs

Add to `internal/domain/configuration_evidence.go`:

```go
const ConfigWriterCertificateSchema = "effective-config.v1"

type ConfigUseSelector struct {
    ConditionID       ConditionID
    Field             SymbolRef
    ObjectID          string
    ObjectDeclaration CallSite
    Consumer          CallSite
    Callee            SymbolRef
    Argument          int
}

type ConfigCapturedFile struct {
    Path  string // confined snapshot-relative path
    Bytes []byte
}

type ConfigCapturedPackage struct {
    ImportPath      string
    Directory       string // snapshot-relative
    SelectedGoFiles []string
    Files           []ConfigCapturedFile
}

type ConfigWriterCertificate struct {
    Schema              string
    ConditionID         ConditionID
    Record              RecordPin
    Build               BuildContext
    Subjects            []SymbolRef
    InventoryEvidenceID EvidenceID
    InventoryReference  string
    SnapshotManifest    []byte
    Packages            []ConfigCapturedPackage
    Uses                []ConfigUseSelector
}
```

Use normal snake-case JSON tags. No completeness/safety status is an admitting field.

Capture every non-test Go file in each required package directory, including ignored variants. The selected-file set must match the canonical inventory, and directory membership/file bytes must match the snapshot manifest. Missing files, duplicate package/file identities, path escapes, inconsistent package ownership and repinned alternative bytes refuse admission.

Extend `affected.Package` only with the Go-list source-file fields needed for this comparison. Reuse the canonical complete-stream decoder and admission decision; do not create a second inventory decoder.

Preserve the established original source filenames when reconstructing `CallSite` and Task 3 object-ID conventions; use confined snapshot-relative keys for manifest lookup. Ambiguous path aliases or selected symlink paths are unsupported in this bounded case.

#### D. Exact admission context and APIs

Replace the positional verified-negative API with:

```go
type NegativeAdmissionInput struct {
    Product        domain.ProductSnapshot
    Vulnerability  domain.Vulnerability
    RecordPin      *domain.RecordPin
    AdvisoryRecord *domain.AdvisoryRecordCapture
    Model          *domain.ExploitModel
    Evidence       []domain.Evidence
}

func ValidateVerifiedNegative(
    in NegativeAdmissionInput,
    claim domain.Claim,
    cond domain.Condition,
) error

func ValidateConfigWriterEvidence(
    in NegativeAdmissionInput,
    cond domain.Condition,
    cert domain.ConfigWriterCertificate,
) error

func (ix *Index) CaptureConfigWriterCertificate(
    ctx context.Context,
    c *domain.AnalysisCase,
    cond domain.Condition,
) (domain.ConfigWriterCertificate, error)
```

The producer may append measured inventory and Task 3 observations to the case graph. It returns the full certificate; the collection state persists that certificate separately.

Add typed checker causes compatible with `errors.Is`:

- `ErrConfigWriterInsufficientScope`
- `ErrConfigWriterContradicted`

Contradiction errors identify the reconstructed consuming site and unsafe effective value. Other failures identify their failed obligation.

Migrate every existing `ValidateVerifiedNegative` caller; remove the old signature without compatibility shims.

Context plumbing is explicit:

- Add `AdvisoryRecord *domain.AdvisoryRecordCapture` to `evaluator.VerdictInput`.
- `admitVerdictInput` passes product, vulnerability, record pin, advisory capture, model and evidence to the new gate.
- Populate the capture in live review/verdict inputs in `states.go`.
- Populate it in `finding.admitProfileResult`, report admission and research requested-finding projections from the owning case.
- Update the existing research decision caller to the new input form; its unrelated route keeps its existing obligations. Missing configuration context never causes a fallback.
- Migrate tests and the calibration caller. Existing nonconfiguration proof routes must retain their established behavior.

#### E. Bounded captured-source kernel

Implement in `internal/goanalysis/configcertificate.go`.

Replay uses `go/parser` and `go/types`, including `Defs`, `Uses`, `Selections` and expression types/constants. Supply target sizing and supported language-version semantics from the recorded build. A recursive importer resolves captured packages only.

The supported application-source envelope is:

- A complete canonical non-test inventory.
- An application with its relevant nonstandard source packages wholly inside the anchored snapshot.
- All nonstandard inventory packages captured and examined, including dependency-internal callers.
- No explicit standard-library imports in the required source envelope for this first supported subset.
- No cgo, assembly/bodyless external implementations, unsafe/linkname/plugin/reflection surfaces, overlays or unsupported compiler-affecting flags.
- No build-variant interpretation requirement in the required semantic packages: reject build directives and platform-specific alternative source shapes rather than adding a build-constraint engine.

Implicit standard Go runtime nodes remain in the canonical inventory. They are part of the trusted language/runtime boundary, not application callers to be reinterpreted as arbitrary configuration callbacks. Do not require full `go/types` checking of the runtime’s implementation to make an import-free application fixture close. Do not extend this exception to explicit standard-library imports.

The supported value grammar is:

- Local, nonpointer named struct storage.
- Direct boolean field selection, allowing harmless parentheses.
- Keyed literal/typed-constant construction or an explicitly accounted zero default.
- Direct boolean literal/constant field writes.
- Same-function whole-value copies with exact source/destination storage identities.
- Straight-line caller execution through each relevant consume, preserving construction/write/copy order.

A copied value is a snapshot of its source at the copy. Later mutation of the source must not retroactively change the destination.

Reject relevant branches, loops/ranges, goto, deferred/asynchronous consumption, tuple constructors, constructor returns, parameters/receivers as configuration storage, pointers, address-taking, aggregate escape, closure access and unsupported expressions. Calls passing only the boolean field do not grant the callee access to the original configuration object.

Task 3 observations may nominate fields/objects and supply diagnostics. They do not authorize deletion of blockers. Reconstruct actual writer and escape predicates from captured source.

#### F. Full consumer coverage

Reconstruct all direct calls **and non-call references** to the exact contracted operation across the supported captured envelope.

- Require at least one relevant invocation.
- Resolve callee identity through `go/types`, not textual name matching.
- Require every relevant invocation’s necessary argument to be a supported exact object-field use.
- Require certificate selectors to equal the reconstructed invocation set. Reject missing, surplus and duplicate selectors.
- Verify each selector’s field, declaration/object ID, `CallExpr.Lparen` site, callee and declared parameter index.
- Reject receiver selectors. Task 3’s receiver event index `-1` is not `domain.ArgReceiver` (`-2`).
- Function/method values, method expressions, callbacks and interface dispatch remain open.
- Account for initialization, closure and recursive references; unsupported references cannot disappear because they were absent from the submitted selector list.
- Do not use heuristic `DeadCode`, configuration names or observed reachability absence to discard consumers.
- An empty call set belongs to the independent deadness route, not this falsifier.
- An existing admitted positive trigger witness that conflicts with the proposed negative prevents negative admission; do not silently choose the safer record.

#### G. Producer, evaluation and publication behavior

`CollectEvidence.runSourceAnalysis` calls the new producer for eligible `CHECK_TRIGGER` conditions without rewriting those conditions.

The producer:

1. Requires the bound matching index and independently acquired snapshot hash.
2. Reuses or records the canonical matching non-test inventory.
3. Captures manifests and complete supported source payloads.
4. Uses the shared captured-source derivation to construct the full selector set.
5. Persists actual Task 3 observations separately.
6. Returns a certificate without granting it a safety status.

Persist the certificate as full `EvidenceConfiguration` content with tool `goanalysis.Index.CaptureConfigWriterCertificate`, matching `BuildContext`, and a content digest in `ArtifactHash`. Claims and negative verification cite the exact certificate evidence. Digest-check that record before decoding. Bounded report previews must not replace its stored bytes.

In `checktrigger.go`, preserve the existing typed positive route and add the configuration-negative helper implemented in `configflag.go`. That helper calls the shared checker:

| Checker result | Current claim behavior |
|---|---|
| All relevant effective values contradict the admitted trigger literal | FALSE candidate with `FalsifierSafeConfigAssignment`; normal negative verification must still run |
| Proven trigger-enabling value at a relevant consumption | UNKNOWN with CONTRADICTED verification detail; not TRUE merely from that value |
| Unresolved value, unsupported shape, missing premise or provenance | UNKNOWN with INSUFFICIENT_SCOPE detail and a typed analyzer-owned gap |

The live verifier reruns the same checker before marking VERIFIED. Place this route before the generic parametric-check refusal.

An unsafe intermediate/default overwritten before consumption is not automatically a counterexample. An unused opposite-valued object is not one either. A real unsafe value at a covered consuming call contradicts the negative, even though the remaining payload/control predicates may still be unknown.

For arbitrary `config_flag` safe-value/default observations, return UNKNOWN instead of creating a machine-negative from declaration-wide assignments. Preserve independently established package-absence behavior and existing observation collection. Do not promote safe `config_key` observations.

`ValidateVerifiedNegative` dispatches `SAFE_CONFIG_ASSIGNMENT` to the same checker and explicitly refuses `ZERO_VALUE_CONFIG`/`SAFE_CONFIG_KEY` before any generic independent-fact early return. Verdict, report and finding publication reuse this gate and preserve verification history on refusal.

#### H. Independent success fixtures and counterexamples

**Fixture A — `configcheckdirectprod`:**

- Real captured advisory naming a check-like method such as `Claims.VerifyAudience(expected, req)` and requiring `req=false`.
- Existing builder generates the admitted mandatory trigger contract.
- A local `Config.RequireAudience=true` supplies argument 1 at every invocation.
- An unused object with the opposite value must not affect the selected object.
- No explicit standard imports.

**Fixture B — `configcheckcopyprod`:**

- A separate module layout with a local replacement under the anchored product tree.
- Independent advisory and method, such as `Context.VerifyIssuer(skip, expected)`, requiring `skip=true` at argument 0.
- `defaults.Skip=false`; a local value copy; a supported safe constant write; two consuming calls.
- Include a source mutation after a copy to test copy timing separately from mutation of the destination.
- Existing builder, actual inventory and real captured source produce the proof; no fabricated mandatory configflag condition.

Both fixtures must complete the actual producer → evaluator → verifier path and replay successfully with their source directories unavailable.

Required negative controls:

- Missing/LLM-only necessity; supporting condition promoted to mandatory; wrong operation/argument/subject.
- Changed argument literal/name/index with matching edited condition params.
- Changed record bytes/pin, ground digest or quotation; missing advisory capture.
- Second unsafe consuming object/call; omitted, surplus or duplicate selector.
- Unsafe intermediate overwritten before consume; unused unsafe object; copied source changed after copy.
- Unknown runtime value/override; alias/address escape; tuple constructor; range assignment.
- Direct and parenthesized pointer-receiver mutation; captured pointer-receiver method value.
- Callback/interface/non-call reference; dependency caller or source package omitted.
- Missing/tampered source, repinned source bytes that disagree with the snapshot root, forged manifest, foreign build, failed/truncated inventory.
- Explicit unsupported standard import, build variant and unanchored external source.
- Forged historical VERIFIED records for all three configuration falsifier names.
- Publication demotion with the original historical verification retained.

#### Implementation Steps

- [ ] **Step 1:** Add the named acceptance tests: `TestSafeConfigNeedsClosedEffectiveObject`, `TestSafeConfigUnsafeWriterContradicts`, `TestSafeConfigOverrideOrEscapeRefuses`, `TestForgedCompleteConfigEvidenceRefuses`, `TestZeroValueAndConfigKeyRemainInsufficient`, `TestSafeConfigNecessityReplay`, `TestSafeConfigSnapshotManifest`, `TestSafeConfigAllConsumers`, and `TestSafeConfigCapturedReplay`.
- [ ] **Step 2:** Run:
  ```bash
  go test ./internal/domain ./internal/repository ./internal/exploit ./internal/goanalysis ./internal/evaluator ./internal/states ./internal/finding ./internal/report \
    -run 'Test(SafeConfig|ForgedCompleteConfig|ZeroValueAndConfigKey)' -count=1
  ```
  Expected **FAIL** because the shared replayable configuration proof does not exist.
- [ ] **Step 3:** Extract the shared existing mechanism grammar and argument binder; migrate the builder and add builder/replay parity tests, including edited metadata and conflicting statements.
- [ ] **Step 4:** Implement shared-encoding content-manifest capture/replay and source-snapshot hash acquisition. Prove existing `t1` hashes remain unchanged and altered captured source cannot match the independently recorded root.
- [ ] **Step 5:** Add certificate DTOs, canonical source-file inventory projection and the producer’s complete captured inputs. Missing inputs remain explicit failures, not empty captures.
- [ ] **Step 6:** Implement the captured-only typed kernel, straight-line boolean/copy semantics and exact consumer-set comparison. Exercise both success fixtures and every listed refusal category.
- [ ] **Step 7:** Replace `ValidateVerifiedNegative` with explicit context and migrate all callers. Add the shared configuration gate and explicit refusal of unsupported configuration falsifiers.
- [ ] **Step 8:** Connect evidence collection and `CheckTrigger` evaluation; keep arbitrary configflag safety UNKNOWN. Exercise actual collection/evaluation/verification, not only hand-built DTOs.
- [ ] **Step 9:** Connect persisted verdict/report/finding admission and test missing, tampered and semantically forged captures while preserving historical records.
- [ ] **Step 10:** Rerun the Step 2 command; expected **PASS**. Also run:
  ```bash
  go test ./internal/exploit ./internal/goanalysis ./internal/evaluator ./internal/repository \
    -run 'Test(Builder.*(Defective|Omission|Semantics)|UnreachabilityReplay|ValidateVerifiedNegative|ContentHash|SafeConfig|ConfigFlag)' -count=1
  ```
  Expected **PASS**, preserving existing semantic and negative-admission contracts.
- [ ] **Step 11:** Perform an offline integration smoke on both fixtures using actual inventory, producer, evaluator and live verifier; serialize and replay through verdict and requested-finding publication after making the source tree unavailable. Exercise the unsafe second-call and missing-payload variants. Run `go build ./...`.
- [ ] **Step 12:** Update existing behavior/gap docs and `task-4-report.md` with only exercised results, actual supported boundaries and remaining unsupported shapes. Preserve earlier measurements. Do not execute Task 5, a benchmark/model arm or the full corpus.

**Acceptance:** Two independent real fixtures earn a current VERIFIED `SAFE_CONFIG_ASSIGNMENT` on an existing necessary `CHECK_TRIGGER` boolean argument and survive source-tree-free publication replay. Every relevant consumer is covered; semantic metadata and source summaries cannot mint authority. A proven unsafe consumed alternative contradicts the negative; missing necessity, provenance or supported analysis remains UNKNOWN. Arbitrary configflag safety, `ZERO_VALUE_CONFIG` and `SAFE_CONFIG_KEY` cannot publish a machine-negative.

**Return-to-design condition:** Stop and report the source and affected invariant if implementation requires a new necessity rule, ambient replay input, unanchored external source, broader value/control-flow grammar or a consumer exclusion not specified here. Do not replace the deliverable with an all-PARTIAL stub or silently widen the approved subset.

### Task 5: Capture supported patch-base and external-component premises

**Depends on:** Task 4 as amended, including successful producer/live-verifier/persisted-publication acceptance. DTOs or all-PARTIAL results do not satisfy this prerequisite.

**Implementation amendment:** [`2026-10-29-01-phase6-task5-contextual-captures.md`](2026-10-29-01-phase6-task5-contextual-captures.md) supersedes the API, capture-schema and producer details below. Its Task5.1 → Task5.2 → Task5.3 order is binding: independent current-context admission, anchored archive/tree/external capture, and actual analyze/canonical-research producer wiring. The acceptance below is retained and strengthened by the amendment; no scope reduction is authorized.

- Task 4 snapshot manifests anchor only the analyzed product, not patch-base/upstream/external-component identity.
- Shared encoding may be reused; Task 5 still requires independently anchored archive/tree, exact locator/artifact and effective-component grounds.
- No automatic broadening of the configuration proof envelope, value grammar or semantic authority. Configuration certificates, vendor membership, local digests and inventory do not establish an independent external anchor.


**Files:**
- Create:
  - `internal/fixbinding/capture.go`
  - `internal/fixbinding/capture_test.go`
  - `internal/rootcause/capture.go`
  - `internal/rootcause/capture_test.go`
- Modify:
  - `internal/fixbinding/proof.go`
  - `internal/fixbinding/derive.go`
  - `internal/fixbinding/persist.go`
  - `internal/fixbinding/selected_source.go`
  - `internal/rootcause/rootcause.go`
  - `internal/rootcause/prooffix.go`
  - `internal/goanalysis/modulecensus.go`
  - `internal/goanalysis/modulecensus_tree.go`
  - `cmd/izyan/main.go`
  - `cmd/izyan/research.go`
  - `docs/cli.md`
  - `docs/architecture.md`
  - `docs/dev/gap-analysis.md`
  - `eval/README.md`
- Test:
  - `internal/fixbinding/proof_test.go`
  - `internal/fixbinding/noncounterpart_test.go`
  - `internal/fixbinding/activation_test.go`
  - `internal/goanalysis/modulecensus_test.go`
  - Create: `cmd/izyan/fix_capture_test.go`

**Interfaces:**
- Consumes:
  - `fixbinding.Inputs.PatchSources`, `Inputs.External`
  - `SourceBundle`, `SourceInventory`, `CheckArchiveAnchor`, `CheckTreeAnchor`
  - `SelectedSourceCensusFor`, existing captured fix artifacts
- Produces:
  - Strict `fix-source-captures.v1` manifest, supplied through `--fix-source-captures`.
  - Per-locator patch-base capture bound to exact artifact digest, module identity and independently anchored complete source.
  - External-component captures bound to effective selected source identity and imported component identity.
  - `Resolver.Captures` input, consumed by `proveContentBinding`; no new semantic patch engine.

- [ ] Step 1: Add `TestPatchBaseCaptureBindsExactLocatorAndArtifact`, `TestPatchBaseWrongTreeRefuses`, `TestExternalCaptureRequiresIndependentAnchor`, `TestTwoFixLocatorsNeverBecomeSeries` and `TestCaptureReplayNeedsNoSourceTree`.
- [ ] Step 2: Run:
  ```bash
  go test ./internal/fixbinding ./internal/rootcause ./cmd/izyan -run 'Test(PatchBaseCapture|PatchBaseWrongTree|ExternalCapture|TwoFixLocators|CaptureReplay)' -count=1
  ```
  Expected **FAIL**: production has no independent patch-base/external capture producer.
- [ ] Step 3: Load bounded captured archives/trees without network fallback; validate digest, module, file boundary and confinement. Construct before/after patch-side images only after exact hunk/preimage validation. Preserve the existing selected-source splice route only where its current exact-match contract succeeds.
- [ ] Step 4: Populate `Inputs.External` only from independently anchored effective component source, using the existing census and completeness aspects. Missing archive/checksum/tree identity remains an input obligation; a vendor listing is not enough.
- [ ] Step 5: Persist all required captured premises through the existing proof input bundle and rederive at admission/replay. Rerun the focused command and:
  ```bash
  go test ./internal/fixbinding -run 'Test(PersistedProof|Refused|Noncounterpart|SelectedSource)' -count=1
  ```
  Expected **PASS**. Include an independent supported operation fixture with different import aliases/wrapper structure, plus an unsupported operation that must retain its residual obligation.

**Acceptance:** Supported proof capabilities can consume genuine patch-base and external-component captures; unavailable or unsupported premises remain explicit rather than approximated.

## Dependency / Execution Order

Task 1 → Task 2 → Task 3 → Task 4 → Task 5.

The serialization is intentional: later evidence classes must not mask defects in the earlier build and scope foundations.

## Evidence-Dependent Work Not Authorized by This Plan

The review’s final priority—**“then measured gaps”**—cannot honestly be converted into additional implementation tasks before measurements exist.

The missing prerequisite is a matched, identity-bound evidence report showing the remaining failing proposition after the first four evidence classes are implemented. In particular, this plan does not claim:

- that corrected inputs close the previously observed build failures;
- that existing reachability machinery closes any particular real case;
- that networking becomes proved by removing parser noise;
- that permission capture guarantees a supported patch proof;
- that Product B recommendation quality improves by any measured amount.

A later extension must identify its proposition, closed universe or positive witness, unsupported boundary, counterexample and independent case. No speculative engine or case-specific production rule is authorized.

---

## Final Integration Handoff

After the selected plans land, the integration owner should:

1. Run focused task tests as changes are integrated.
2. Run formatting, `go vet ./...`, `go test ./...` and the required race checks once on the completed integration.
3. Perform the final Product A safety/authority measurement described in Phase 3, preserving per-condition deltas and `false-safe=0`.
4. Verify replay with network/model execution disabled.
5. **Do not execute the Product B benchmark or human study.** Phase 5 completes when the lane and synthetic tests are ready, not when benchmark results exist.

The complete deliverable is the five cutovers above, with later evidence-dependent work explicitly bounded—not a scaffold and not an unmeasured claim of improved behavior.

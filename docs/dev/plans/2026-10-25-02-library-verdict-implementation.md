# Library-API Verdict Scope Implementation Plan

**Goal:** Allow a proven public-library payload path to produce `EXPLOITABLE` with `exploitability_scope: library-api` and `control_basis: library-public-api`, without asserting deployment attacker control.

**Architecture:** Add a deterministic product-shape proof and an optional public-formal → vulnerable-sink payload witness. Preserve deployment `DataFlow.Origin=UNKNOWN`; admit the witness only in argument-origin evaluation under the approved narrow gates. Carry the resulting boundary through verdicts, profile summaries, reports, and VEX exports.

**Tech stack:** Go 1.25, existing `go/packages`/`go/types` analysis, `golang.org/x/mod/modfile`, standard Go tests, existing workflow/evaluation harnesses.

**Spec:** `docs/dev/plans/2026-10-25-01-library-verdict-scope.md`

**Intended plan path:** `docs/dev/plans/2026-10-25-02-library-verdict-implementation.md`

## Global Constraints

1. **No new verdict value.** Keep the existing four verdicts and their routing.
2. **No invented external origin.** A library public formal remains deployment-origin `UNKNOWN`; never synthesize `EXTERNAL_UNTRUSTED`.
3. **All admission gates are conjunctive:**
   - proven library-shaped product;
   - genuine product-owned public API;
   - eligible typed payload formal;
   - exact payload-preserving formal → sink argument binding;
   - resolved root-cause sink;
   - exploit class `DESERIALIZATION`;
   - advisory-supplied `CWE-502`;
   - `ATTACKER_CONTROL`;
   - exact nonnegative argument index;
   - ordinary argument input, not peer/config/receiver/whole-argument input.
4. The witness cannot satisfy `INPUT_CONSTRAINT`, exposure, authentication, protocol-role, configuration, reachability, or defect-locus conditions.
5. Failed admission means **no new proof**, not safety. Do not introduce a FALSE claim or negative-closure shortcut.
6. **Module ownership decides product membership.** In particular, testify’s nested `github.com/stretchr/testify/_codegen` module must be excluded because it is a different, non-owned module—not because its pathname is `_codegen`.
7. Do not require or alter `ShippingScope.Complete`. Libraries intentionally have no main roots and remain open in that model.
8. Keep existing affected-chain, negative-verification, advisory-coverage, pending-review, and unresolved-subject gates.
9. `KNOWN_ONLY` must remain `KNOWN_ONLY`. It blocks unsupported negative closure, not an otherwise proven positive path.
10. Do not use `Claim.AssumptionIDs`: library-consumer payload selectability is a code fact, not an operator assumption.
11. Do not change Product B authority boundaries, add CLI flags, expand the vulnerability-class gate, or repair the existing Podman/Kubernetes false alarms.
12. Keep corpus membership and ground truth unchanged. Add focused Go regression fixtures rather than expanding the canonical corpus for this feature.
13. Run only focused tests during implementation. The integration owner runs formatting, vet, full tests, and each full corpus once after all tasks land.

### Mandatory limitation

Define this once and reuse it verbatim in machine-readable output:

> Library-API scope: the payload is selectable by a library consumer; whether a downstream application exposes that payload to an attacker is outside the analyzed product and is not established.

Empty optional scope/basis fields preserve existing serialization and behavior. Their absence does **not** itself prove deployment attacker control.

## Review Focus

| Risk or boundary | Owning task and acceptance test |
|---|---|
| Nested generator `main` incorrectly classified as product | Task 1: module-ownership census tests |
| Hidden/build-excluded/skipped product `main` missed | Task 1: census-negative matrix |
| Library rejected because shipping scope is incomplete | Task 1: library proof with `ShippingScope.Complete=false` |
| Constant-only or test-only callers close a public formal | Task 2: public-boundary terminal tests |
| Origin propagation mistaken for payload preservation | Task 2: strict witness rejection matrix |
| Wrong formal, wrong argument, or two calls on one line | Tasks 1–2: exact-site identity tests |
| Witness/evidence lost during collection or deep tracing | Task 2: graph-writer and gap-analysis tests |
| Transport evaluator bypasses library admission | Task 4: transport-precedence tests |
| Perimeter profile rewrites consumer selectability to FALSE | Task 4: profile-preservation tests |
| Library witness satisfies unrelated conditions | Task 4: admission matrix |
| Bare TRUE input claim produces remote-client wording | Task 3: RU/EN report and tracker tests |
| Positive CVE result incorrectly requires COMPLETE coverage | Tasks 4–5: `KNOWN_ONLY` positive-path tests |
| Existing calibration changes or false alarms gain admission | Task 5: application/test-only controls and real-case checks |

---

### Task 1: Freeze the cross-layer contracts and implement product-shape proof

**Depends on:** None

**Files:**
- Create: `internal/domain/library_scope.go`
- Create: `internal/domain/library_scope_test.go`
- Modify: `internal/domain/domain.go`
- Create: `internal/goanalysis/product_shape.go`
- Create: `internal/goanalysis/product_shape_test.go`
- Modify: `internal/goanalysis/source.go`
- Modify: `internal/states/states.go`
- Create: `internal/states/library_scope_test.go`

**Interfaces:**

Freeze these interfaces before Tasks 2 and 3 start.

```go
// internal/domain/library_scope.go

type ProductShapeKind string

const (
	ProductShapeUnknown     ProductShapeKind = "UNKNOWN"
	ProductShapeLibrary     ProductShapeKind = "LIBRARY"
	ProductShapeApplication ProductShapeKind = "APPLICATION"
)

type ProductModuleShape struct {
	Path      string `json:"path"`
	Directory string `json:"directory"`
}

type ProductPackageShape struct {
	Path           string   `json:"path"`
	Module         string   `json:"module"`
	Directory      string   `json:"directory"`
	PackageNames   []string `json:"package_names,omitempty"`
	Files          []string `json:"files,omitempty"`
	ClauseComplete bool     `json:"clause_complete"`
	Importable     bool     `json:"importable"`
	LoadErrors     []string `json:"load_errors,omitempty"`
}

type ProductShape struct {
	Kind            ProductShapeKind      `json:"kind"`
	CensusComplete  bool                  `json:"census_complete"`
	RootModule      string                `json:"root_module,omitempty"`
	OwnedModules    []ProductModuleShape  `json:"owned_modules,omitempty"`
	ExcludedModules []ProductModuleShape  `json:"excluded_modules,omitempty"`
	WorkspaceFile   string                `json:"workspace_file,omitempty"`
	Packages        []ProductPackageShape `json:"packages,omitempty"`
	Fingerprint     string                `json:"fingerprint"`
	EvidenceIDs     []EvidenceID          `json:"evidence_ids,omitempty"`
	Limitations     []string              `json:"limitations,omitempty"`
}

type LibraryPayloadStepKind string

const (
	LibraryPayloadIdentity       LibraryPayloadStepKind = "identity"
	LibraryPayloadByteConversion LibraryPayloadStepKind = "byte-preserving-conversion"
	LibraryPayloadPreservingCall LibraryPayloadStepKind = "payload-preserving-call"
)

type LibraryPayloadStep struct {
	Kind LibraryPayloadStepKind `json:"kind"`
	Site CallSite               `json:"site"`
}

type LibraryInputWitness struct {
	API              SymbolRef            `json:"api"`
	Declaration      CallSite             `json:"declaration"`
	FormalIndex      int                  `json:"formal_index"`
	FormalName       string               `json:"formal_name,omitempty"`
	FormalType       string               `json:"formal_type"`
	Sink             SymbolRef            `json:"sink"`
	Site             CallSite             `json:"site"`
	Arg              int                  `json:"arg"`
	ShapeFingerprint string               `json:"shape_fingerprint"`
	Steps            []LibraryPayloadStep `json:"steps,omitempty"`
	EvidenceIDs      []EvidenceID         `json:"evidence_ids,omitempty"`
}

type ControlBasis string

const ControlBasisLibraryPublicAPI ControlBasis = "library-public-api"

type ExploitabilityScope string

const ScopeLibraryAPI ExploitabilityScope = "library-api"

const LibraryAPIScopeLimitation = "Library-API scope: the payload is selectable by a library consumer; whether a downstream application exposes that payload to an attacker is outside the analyzed product and is not established."
```

Add these fields in `internal/domain/domain.go`:

```go
// ProductSnapshot
Shape *ProductShape `json:"shape,omitempty"`

// DataFlow
LibraryInput *LibraryInputWitness `json:"library_input,omitempty"`

// Claim
ControlBasis ControlBasis `json:"control_basis,omitempty"`

// VerdictResult
ExploitabilityScope ExploitabilityScope `json:"exploitability_scope,omitempty"`

// ProfileVerdict
ExploitabilityScope ExploitabilityScope `json:"exploitability_scope,omitempty"`
```

`ProfileVerdict` needs its own field because it stores a flattened verdict, not a `VerdictResult`.

Add the graph-writing seam:

```go
func (g *EvidenceGraph) AddArgumentTrace(
	flows []DataFlow,
	evs []Evidence,
) []EvidenceID

func (g *EvidenceGraph) ReplaceArgumentTrace(
	flow DataFlow,
	evs []Evidence,
) []EvidenceID
```

Both methods record evidence first, attach its assigned IDs to each new witness, then append or replace the flow. Do not retain an old witness when replacing it with a newly traced flow without one.

Retain `ReplaceDataFlow(DataFlow)`. Extend its slot identity to include `Sink.Column`, preventing a replacement from matching a different call on the same line.

Produce:

```go
// internal/goanalysis/product_shape.go

func (ix *Index) BuildProductShape(
	ctx context.Context,
) (*domain.ProductShape, []domain.Evidence, error)

func (ix *Index) buildProductShapeLocked(
	ctx context.Context,
) (*domain.ProductShape, []domain.Evidence, error)
```

**Implementation steps:**

- [ ] Add `TestLibraryScopeJSONRoundTrip`, `TestLibraryScopeOptionalFieldsOmitted`, `TestLibraryScopeArgumentTraceEvidence`, and `TestLibraryScopeReplacementUsesColumn`.
- [ ] Add the following product-shape tests using `usageModuleGomod` and existing scope fixtures:
  - `TestProductShapeLibrary`
  - `TestProductShapeNestedModuleOwnership`
  - `TestProductShapeWorkspaceOwnership`
  - `TestProductShapeOwnedMain`
  - `TestProductShapeBuildExcludedMain`
  - `TestProductShapeSkippedMain`
  - `TestProductShapeUnknownCensus`
  - `TestProductShapeIndependentOfShippingCompleteness`
  - `TestProductShapeFingerprint`
- [ ] Run the focused command below; expect failure because the contracts and builder do not exist.
- [ ] Resolve the owning root module and effective workspace using the same directory and environment as `Index.loadConfig`. Account for explicit `GOWORK=off`, an active workspace, and its `use` entries. Use `modfile.Parse`/`ParseWork`; do not infer ownership from import-path prefixes.
- [ ] Reconcile typed roots, `ix.skippedPkgs`, recovered skipped candidates, and a manifest-aware source-directory census:
  - include build-excluded `.go` source and directories invisible to the selected build;
  - exclude `_test.go`, synthetic test variants/drivers, and dependency/vendor source;
  - identify nested module boundaries before directory-name pruning;
  - include every owned non-test command, regardless of directory name;
  - exclude non-owned nested modules and record why they were excluded.
- [ ] Parse package clauses for every inventoried non-test source. Reuse `skippedClauseProof` where its inventory is sufficient, but do not treat the loader’s single `Name` as proof that no sibling file declares `main`.
- [ ] Classify:
  - `LIBRARY`: complete ownership/census, at least one importable product package, no owned `main`;
  - `APPLICATION`: a product-owned `main` is proven;
  - `UNKNOWN`: missing/ambiguous ownership, unreadable clause, incomplete census, unavailable workspace member, or binary analysis.
- [ ] Emit deterministic build/package-census evidence. Fingerprint manifests, ownership, build context, file inventory, and source content used by the proof. Follow existing snapshot-mutation/cancellation behavior: no stale or interrupted proof may be published.
- [ ] Cache the immutable census per index, following existing scope-cache conventions. Revalidate its source/inventory identity at public-query boundaries; do not load a second full dependency AST graph.
- [ ] In `CollectEvidence.Run`, immediately before `runSourceAnalysis`, call `BuildProductShape`, record its evidence, populate `shape.EvidenceIDs`, and assign `c.Product.Shape`. Binary-mode cases remain ineligible even when a source index is present. Do not mutate a shared index’s build configuration per advisory.
- [ ] Add `TestCollectEvidenceProductShapeRecorded` and `TestCollectEvidenceProductShapeBinaryUnknown`.

**Do not change:**
- `ShippingScope`, shipping-root rules, reachability classification, or affected resolution.
- `DataOrigin`, verdict enums, advisory coverage, or Product B aliases.
- Any witness admission behavior yet.

**Focused validation:**

```bash
go test -count=1 ./internal/domain ./internal/goanalysis ./internal/states \
  -run 'LibraryScope|ProductShape'
```

**Acceptance:**
- An ordinary library has a persisted, evidence-backed `LIBRARY` proof despite incomplete shipping scope.
- A nested generator module is excluded by module identity; moving/renaming it does not change that result.
- The same generator source without its separate module boundary prevents library classification.
- Owned mains hidden by build selection or loader failure cannot be missed.
- New fields round-trip and remain omitted on existing cases.
- Distinct same-line calls cannot overwrite each other’s flows.

---

### Task 2: Produce exact library payload witnesses and preserve them through tracing

**Depends on:** Task 1

**Files:**
- Create: `internal/goanalysis/library_input.go`
- Create: `internal/goanalysis/library_input_test.go`
- Modify: `internal/goanalysis/provenance.go`
- Modify: `internal/states/states.go`
- Modify: `internal/states/gap.go`
- Modify: `internal/states/library_scope_test.go`
- Modify: `internal/llm/tools.go`
- Create: `internal/llm/library_scope_test.go`
- Modify: `internal/research/deterministic.go`
- Modify: `testdata/dep/vuln/vuln.go`
- Create: `testdata/libassertprod/go.mod`
- Create: `testdata/libassertprod/assert/assert.go`
- Create: `testdata/libassertprod/require/require.go`

**Interfaces:**

Consumes Task 1’s shape, witness, and graph-writing contracts.

Retain these public signatures unchanged:

```go
func (ix *Index) TraceArgument(
	ctx context.Context, site domain.CallSite, argIndex int,
) (domain.DataFlow, []domain.Evidence, error)

func (ix *Index) TraceArgumentBound(
	ctx context.Context, site domain.CallSite, argIndex, hops int,
) (domain.DataFlow, []domain.Evidence, error)

func (ix *Index) TraceAllArguments(
	ctx context.Context, site domain.CallSite,
) ([]domain.DataFlow, []domain.Evidence, error)

func (ix *Index) TraceAllArgumentsBound(
	ctx context.Context, site domain.CallSite, hops int,
) ([]domain.DataFlow, []domain.Evidence, error)
```

New analysis helpers:

```go
func (ix *Index) publicLibraryFormalLocked(
	pkg *packages.Package,
	enc *ast.FuncDecl,
	param *types.Var,
) (domain.SymbolRef, int, bool)

func libraryPayloadType(t types.Type) (string, bool)

func (ix *Index) traceLibraryInputLocked(
	ctx context.Context,
	pkg *packages.Package,
	enc *ast.FuncDecl,
	call *ast.CallExpr,
	argIndex int,
	shape *domain.ProductShape,
) (*domain.LibraryInputWitness, []domain.Evidence, error)
```

Fixture interfaces:

```go
// testdata/dep/vuln/vuln.go
func ParseBytes(p []byte) string // returns string(p)

// testdata/libassertprod/assert/assert.go
type TestingT interface {
	Errorf(format string, args ...interface{})
}

func YAMLEq(t TestingT, expected, actual string) bool
```

The fixture’s two separate sink calls are:

```go
vuln.ParseBytes([]byte(expected))
vuln.ParseBytes([]byte(actual))
```

The `require` package forwards to the public `assert` API. Its module requires `example.com/dep v1.0.0` and replaces it with `../dep`.

**Implementation steps:**

- [ ] Add `TestLibraryInputPublicFormalBoundary` covering zero callers, test-only callers, constant-only callers, and generated-style forwarding wrappers.
- [ ] Add `TestLibraryInputPublicAPIMatrix` covering:
  - exported functions;
  - exported methods on exported named value/pointer receivers;
  - private functions/methods;
  - exported methods on unexported receivers;
  - `internal`, command, dependency, and test-variant packages;
  - shadowed locals that share a formal’s name.
- [ ] Add `TestLibraryInputPayloadTypeMatrix`:
  - accept string, byte slice, aliases, defined string/byte-slice types with the required underlying representation, and canonical `io.Reader`;
  - reject writer-only types, arbitrary lookalike interfaces, callbacks, pointers, containers, unresolved type parameters, and type-name substring matches.
- [ ] Add `TestLibraryInputPayloadBindingMatrix` with exact formal/argument assertions and rejection of unused/wrong formals, constant replacement, slicing/truncation, numeric/rune conversions, opaque transformations, unresolved dispatch, payload-unproven flows, relevant unmodeled validation/sanitization, and recovery.
- [ ] Run the focused command below; expect failures for missing witnesses and the current caller-based terminal behavior.
- [ ] Add the public-formal terminal in `traceParam` **before caller enumeration and caller-origin merging**. For a proven library public boundary, return `OriginUnknown` with a distinct public-boundary explanation. Do not apply it only to “no callers”; constant-only callers must not close the API.
- [ ] Match formal identity through typed signature objects, not name equality alone. Keep the existing caller-hop and evaluation bounds.
- [ ] Implement a separate strict payload-binding walk. Do not reuse permissive origin propagation as proof of payload preservation:
  - allow identity/local forwarding with verified assignments;
  - allow byte-preserving string/`[]byte` conversions;
  - allow typed direct helper forwarding whose body proves the same binding;
  - support canonical reader input directly and explicitly modeled complete-read/carrier operations, including `io.ReadAll`, without treating general knowledge-base passthrough entries as payload proofs;
  - reject unsupported transforms rather than widening the allowlist heuristically.
- [ ] Inspect relevant control flow. A sink in an `if` initializer executes before the subsequent error test; that test is not a pre-sink sanitization guard. Conversely, a relevant unmodeled payload guard or recovery must prevent admission. Unrelated bookkeeping such as `TestingT.Helper()` must not reject an otherwise proven binding.
- [ ] Attach the witness only to an exact ordinary argument flow. Use the resolved AST call’s file, line, and column; ambiguous line-only call locations cannot produce an exact witness.
- [ ] Keep `Origin=UNKNOWN`. Emit deterministic witness evidence containing the API declaration, formal slot/type, sink symbol/site/argument, and preserving steps.
- [ ] Migrate argument-trace graph writers to Task 1’s evidence-first methods:
  - `CollectEvidence.collectProvenance`;
  - `CollectEvidence.collectSinkClosure`;
  - `GapAnalysis.actDeepTrace`;
  - `llm.Tools.Call`, `trace_argument` branch;
  - the argument-trace writer in `internal/research/deterministic.go`.
- [ ] Include columns in sink-trace deduplication and gap-action keys.
- [ ] In gap planning, explicitly skip flows with `LibraryInput != nil`, even though their origin is UNKNOWN. A deeper trace that newly obtains a witness counts as progress and replaces the whole old flow. Never merge an old witness into a new unwitnessed trace.
- [ ] Add:
  - `TestLibraryInputTraceVariants`;
  - `TestLibraryInputSameLineCalls`;
  - `TestLibraryInputEvidenceReferences`;
  - `TestGapLibraryInputWitnessSkipped`;
  - `TestGapLibraryInputDeeperWitnessRecorded`;
  - `TestToolLibraryInputWitnessRecorded`.
- [ ] Verify by tests that re-tracing a public formal during negative verification remains unresolved and cannot produce a VERIFIED constant-input falsifier.

**Do not change:**
- `maxTraceHops`, global provenance ranking, broad passthrough semantics, or negative-verification rules.
- `ReplaceDataFlow` into a field-merging operation.
- `internal/evidencetools/dataflow.go`: it is observation-only and already serializes complete `DataFlow` values; no authority or graph-writing change is needed.

**Focused validation:**

```bash
go test -count=1 ./internal/goanalysis ./internal/states ./internal/llm \
  -run 'LibraryInput|GapLibrary|ToolLibrary'
```

**Acceptance:**
- The two fixture bindings are distinguishable: formal 1 → first sink argument 0 and formal 2 → second sink argument 0.
- Both flows remain deployment-origin UNKNOWN.
- Public-boundary conclusions do not depend on observed callers.
- Unsupported payload paths have no witness.
- Every persisted witness has resolvable evidence references.
- Collection, tool tracing, and deeper tracing preserve complete, exact bindings without stale-proof retention.

---

### Task 3: Make report, CLI, and VEX projections library-scope aware

**Depends on:** Task 1  
**Parallel-safe with:** Task 2

This task deliberately precedes admission. Landing the evaluator first would immediately let a library TRUE claim trigger today’s remote-client narrative.

**Files:**
- Create: `internal/report/library_scope.go`
- Create: `internal/report/library_scope_test.go`
- Modify: `internal/report/report.go`
- Modify: `internal/report/openvex.go`
- Modify: `internal/report/cyclonedx.go`
- Modify: `cmd/izyan/main.go`
- Create: `cmd/izyan/library_scope_cli_test.go`

**Interfaces:**

Consume the frozen domain contract using synthetic typed cases; this task does not need the real witness producer.

New helpers:

```go
func libraryAPIScope(c *domain.AnalysisCase) bool

func libraryAPIControlProven(c *domain.AnalysisCase) bool

func libraryInputWitnesses(
	c *domain.AnalysisCase,
) []domain.LibraryInputWitness

func libraryAPILimitationText(isRU bool) string

func witnessBindingText(
	w domain.LibraryInputWitness, isRU bool,
) string

func renderLibraryAPIWitness(
	b *strings.Builder, c *domain.AnalysisCase, isRU bool,
) bool

func libraryScopeStatement(c *domain.AnalysisCase) string

func affectedActionStatement(c *domain.AnalysisCase) string
```

Change:

```go
func allLimitations(c *domain.AnalysisCase, isRU bool) []string
```

Retain the signatures of `Write`, `Markdown`, `TrackerRationale`, `OpenVEX`, `CycloneDX`, and CLI `printCase`.

**Implementation steps:**

- [ ] Add synthetic library-scope cases with a TRUE attacker-control claim, exact witness, UNKNOWN origin, and explicit verdict/profile scope.
- [ ] Add:
  - `TestMarkdownLibraryScopeLimitationRUEN`;
  - `TestMarkdownLibraryScopeNoFabricatedRemoteInput`;
  - `TestMarkdownLibraryScopeWitnessBinding`;
  - `TestMarkdownLibraryScopeDeploymentControl`;
  - `TestMarkdownLibraryScopeInconclusiveInputFact`;
  - `TestAllLimitationsAggregatesClaimLimitations`;
  - `TestReportLibraryScopeJSONRoundTrip`;
  - `TestTrackerRationaleLibraryScope`;
  - `TestPerimeterMatrixLibraryScopeRUEN`;
  - `TestOpenVEXLibraryScope`;
  - `TestOpenVEXAffectedActionStatement`;
  - `TestCycloneDXLibraryScope`;
  - `TestPrintCaseLibraryScope`.
- [ ] Run the focused command below; expect failures from missing scope rendering, omitted claim limitations, and existing remote-client wording.
- [ ] Render the verdict’s persisted scope explicitly in Markdown and CLI output. Display profile scope in the existing profile verdict cell, without creating a separate verdict value.
- [ ] Render `ControlBasis` independently of `claimVerification`’s current early return: TRUE claims have neither a falsifier nor negative-verification record.
- [ ] Render a witness block containing API symbol/declaration, formal index/name/type, sink symbol/site/argument, preserving steps, and evidence references.
- [ ] Aggregate claim limitations in `allLimitations`, preserving existing deduplication. Localize the shared library limitation for RU; EN must contain the exact shared constant. Keep it outside the truncated claim-explanation table cell.
- [ ] Update these existing narrative surfaces:
  - `machineAssessment`;
  - `rationaleExploitable`;
  - `rationaleInconclusive` / `writeEstablishedFacts`;
  - `renderVulnerabilityDetails`;
  - `renderKeyVerificationFacts`;
  - `renderPerimeterMatrix`.
- [ ] For library-backed control, state consumer-selectable payload and the proven API → sink path. Do not claim:
  - remote-client input was observed;
  - an inbound service/handler exists;
  - the package was compiled into a product binary;
  - public exposure or `0.0.0.0` was established.
- [ ] Keep `attackerControlProven` and `symbolReachProven` semantically separate. A witness must not manufacture reachability; library input control must not be hidden merely to avoid remote wording.
- [ ] Select library-safe wording for a TRUE library-basis claim even when another unresolved condition keeps the overall verdict INCONCLUSIVE. Projection status still comes exclusively from the verdict.
- [ ] OpenVEX:
  - retain `EXPLOITABLE → affected`;
  - put the library scope and mandatory limitation in the impact/action text;
  - supply a nonempty `action_statement` for affected findings using existing remediation information, with a generic upgrade/mitigation recommendation when no fixed version is available.
- [ ] CycloneDX:
  - retain `analysis.state="exploitable"`;
  - carry scope, basis, and the limitation through existing `analysis.detail`;
  - add no new response/properties schema.
- [ ] Confirm `report.json` and `case.json` retain all new fields through their existing whole-case JSON serialization. No replacement DTO is needed.

**Do not change:**
- Verdict routing or advisory negative-closure projection gates.
- CycloneDX metadata component classification.
- General report localization or unrelated exposure defaults outside the library branch.
- Corpus summary schemas or Product B output.
- Workflow state order: “report first” here is landing order, not runtime execution order.

**Focused validation:**

```bash
go test -count=1 ./internal/report ./cmd/izyan \
  -run 'LibraryScope|AllLimitationsAggregatesClaimLimitations|OpenVEXAffectedActionStatement'
```

**Acceptance:**
- RU/EN reports, tracker rationale, CLI, OpenVEX, and CycloneDX make the library boundary visible.
- The library report contains the exact binding and no fabricated remote-client/public-service facts.
- A deployment-origin positive retains existing wording and mapping.
- Library-scope OpenVEX is `affected`, not `under_investigation`; CycloneDX remains `exploitable`.
- The limitation survives both claim aggregation and verdict/export projection.

---

### Task 4: Admit witnesses in argument evaluation and propagate verdict scope

**Depends on:** Tasks 2 and 3

**Files:**
- Create: `internal/evaluator/library_input.go`
- Create: `internal/evaluator/library_input_test.go`
- Modify: `internal/evaluator/provenance.go`
- Modify: `internal/evaluator/transport.go`
- Modify: `internal/evaluator/verdict.go`
- Modify: `internal/evaluator/verdict_test.go`
- Modify: `internal/states/states.go`
- Modify: `internal/states/library_scope_test.go`

**Interfaces:**

New evaluator helpers:

```go
func admittedLibraryWitness(
	cond domain.Condition,
	c *domain.AnalysisCase,
) (domain.DataFlow, *domain.LibraryInputWitness, bool)

func libraryAdmissionApplies(
	cond domain.Condition,
	c *domain.AnalysisCase,
) bool

func verdictExploitabilityScope(
	model domain.ExploitModel,
	claims []domain.Claim,
) domain.ExploitabilityScope
```

Retain:

```go
func (ArgumentOrigin) Evaluate(
	cond domain.Condition, c *domain.AnalysisCase,
) domain.Claim

func (ServerTransportInput) Evaluate(
	cond domain.Condition, c *domain.AnalysisCase,
) domain.Claim

func (VerdictEvaluator) Evaluate(
	affected domain.AffectedResult,
	model domain.ExploitModel,
	claims []domain.Claim,
) domain.VerdictResult
```

`VerdictEvaluator` remains pure and does not gain filesystem/source access. It consumes the admitted claim basis rather than re-proving product shape.

**Implementation steps:**

- [ ] Add `TestLibraryInputWitnessAdmitsAttackerControl` asserting:
  - `ClaimTrue`;
  - producer remains `evaluator.ArgumentOrigin`;
  - `ControlBasisLibraryPublicAPI`;
  - exact shape/witness evidence references;
  - shared limitation;
  - unchanged UNKNOWN deployment origin;
  - no falsifier, negative-verification record, or assumption IDs.
- [ ] Add `TestLibraryInputWitnessGateMatrix` with independent rejection cases for:
  - missing/wrong class and keyword-only classification without advisory CWE;
  - missing/wrong CWE;
  - unresolved/absent/wrong root-cause sink;
  - mismatched condition subject;
  - `INPUT_CONSTRAINT` and other condition kinds;
  - `ArgAll`, `ArgReceiver`, wrong argument index;
  - explicit peer/config input, read-direction, exposure/config checks, or protocol-role requirement on the condition;
  - missing/UNKNOWN/application shape;
  - incomplete census or owned `main`;
  - binary mode;
  - missing witness or mismatched shape fingerprint;
  - wrong sink site/column;
  - dangling proof references;
  - payload-unproven or unsupported/security-relevant payload transformation.
- [ ] Run the focused command below; expect failure because witnesses currently fall into UNKNOWN-origin counters.
- [ ] Implement admission:
  - accept ordinary argument input when `input_source` is absent—the current generic deserialization model—or exactly `arg`;
  - require exact class string `DESERIALIZATION` and advisory CWE 502, using the repository’s existing CWE normalization convention;
  - match a present resolved sink in the root-cause/model/condition subject sets;
  - match `flow.ConditionID`, `flow.Arg`, witness argument, sink symbol/site, and current shape fingerprint;
  - require the evidence-backed complete library census and witness.
- [ ] In `ArgumentOrigin.Evaluate`, retain package-absence handling first. Preserve genuine external-origin TRUE precedence; use an admitted witness before unresolved-origin handling and before any constant-input FALSE fallback.
- [ ] Do not change input-constraint guard/bound logic or `closureGate`. Do not require a complete ingress/sink closure for this positive witness.
- [ ] In `ServerTransportInput.Evaluate`, delegate an admissible library witness to `ArgumentOrigin` before trusted-peer or transport heuristics can intercept it. Do not gate ordinary argument admission on remote-wording regexes: “malformed YAML” in advisory text is not an explicit peer-input requirement.
- [ ] In the successful all-mandatory-TRUE verdict branch, set `ScopeLibraryAPI` when at least one **mandatory TRUE** claim relies on the library basis. Add the mandatory limitation and relevant claim/evidence references. Keep the existing `Reason` string.
- [ ] Never set verdict scope merely because a supporting claim or raw witness exists. Non-EXPLOITABLE verdicts keep an empty exploitability scope.
- [ ] In `EvaluateVerdict.Run`:
  - exempt admitted library-basis TRUE claims from the cluster-perimeter peer-input rewrite;
  - copy `vZT.ExploitabilityScope` and `vCP.ExploitabilityScope` into their corresponding `ProfileVerdict` values;
  - preserve the selected actual verdict’s scope;
  - ensure any verdict demotion clears an active exploitability scope.
- [ ] Add:
  - `TestLibraryInputConditionDefersTransportHeuristic`;
  - `TestLibraryInputWitnessDefersToPackageAbsence`;
  - `TestLibraryInputWitnessDoesNotSatisfyOtherConditions`;
  - `TestVerdictExploitableLibraryScope`;
  - `TestVerdictKnownOnlyLibraryPositive`;
  - `TestVerdictLibraryScopeRequiresMandatoryClaim`;
  - `TestVerdictNegativesCarryNoLibraryScope`;
  - `TestEvaluateVerdictLibraryClaimSurvivesPerimeterProfile`.
- [ ] Include named Podman/Kubernetes/Echo controls in the admission matrix. Independently test application-shape rejection and wrong-class rejection so neither gate hides a defect in the other.

**Do not change:**
- Exploit patterns, generic condition definitions, protocol-role detection, or class inference.
- `NOT_AFFECTED` routing, NEPF requirements, unresolved-subject checks, or pending-review checks.
- Root-cause resolution or affected resolution.
- Existing application-origin positives and constant-input negatives.

**Focused validation:**

```bash
go test -count=1 ./internal/evaluator ./internal/states \
  -run 'LibraryInput|LibraryScope|LibraryPositive|LibraryClaim|VerdictPartialScopeKeepsProvenPositive|ArgumentOrigin_ConstantPayload'
```

**Acceptance:**
- The new path proves only attacker-control at the library API boundary.
- A library witness cannot close missing reach/locus or unrelated mandatory conditions.
- COMPLETE and KNOWN_ONLY cases can both reach the same scoped positive verdict.
- Both perimeter profiles preserve library consumer selectability.
- Podman/Kubernetes resource-exhaustion cases and the Echo auth-bypass near miss receive zero library admission.

---

### Task 5: Prove end-to-end behavior, preserve calibration, and document the contract

**Depends on:** Tasks 1–4

**Files:**
- Create: `internal/states/library_scope_e2e_test.go`
- Modify: `internal/states/states_test.go`
- Create: `testdata/libasserthttpprod/go.mod`
- Create: `testdata/libasserthttpprod/main.go`
- Create: `testdata/libassertconstprod/go.mod`
- Create: `testdata/libassertconstprod/main.go`
- Create: `testdata/libasserttestprod/go.mod`
- Create: `testdata/libasserttestprod/main.go`
- Create: `testdata/libasserttestprod/main_test.go`
- Modify: `docs/architecture.md`
- Modify: `docs/how-it-works.md`
- Modify: `docs/cli.md`
- Modify: `docs/dev/analysis-internals.md`
- Modify: `docs/dev/gap-analysis.md`
- Modify: `eval/README.md`

**Interfaces:**

Extend the existing test fixture helper, retaining all existing callers:

```go
func initRepoFrom(
	t *testing.T,
	fixture string,
	additional ...string,
) string
```

Continue copying the existing default dependency fixtures; copy each requested additional fixture once. New consumer tests pass `"libassertprod"`.

Use existing `runEngine`, `engineDeps`, `findClaimT`, `vulnerability.StaticSource`, and `affected.GoResolver`.

**Implementation steps:**

- [ ] Add `TestE2ELibraryPublicAPIExploitable`, table-driven over:
  - canonical synthetic GHSA request → COMPLETE;
  - CVE alias request against the same advisory → KNOWN_ONLY.
- [ ] Give the advisory actual CWE-502, affected version/package/sink data for local `ParseBytes`, and run the existing model builder/source verifier rather than hand-setting `C-INPUT`.
- [ ] Assert:
  - affected applicability is TRUE;
  - reach/locus are independently TRUE;
  - both public-formal bindings are persisted;
  - `C-INPUT=TRUE`, basis `library-public-api`;
  - final `EXPLOITABLE`, scope `library-api`;
  - deployment origins stay UNKNOWN;
  - requested/resolved advisory identity and coverage stay correct.
- [ ] Assert the persisted `case.json`, `report.json`, RU/EN Markdown, OpenVEX, and CycloneDX outputs—not only the in-memory case.
- [ ] Add `TestE2ELibraryPublicCallersDoNotCloseBoundary` for constant-only and test-only in-repository callers of the public library API.
- [ ] Add application consumer fixtures:
  - HTTP body forwarded into the library → EXPLOITABLE through ordinary external provenance, with no library basis/scope;
  - fixed literals passed into the library → NEPF with VERIFIED negative evidence and no library basis/scope;
  - library imported only from `_test.go` → NOT_AFFECTED, with `Affected.TestOnlyScope`, no admission, and no test-only mislabeling of shipped library source.
- [ ] Add `TestE2ELibraryConsumerCalibration` with those exact expected outcomes. Use the real affected resolver for the test-only case.
- [ ] Add an integration assertion that missing reach or locus keeps a library-input-positive case INCONCLUSIVE.
- [ ] Run the focused command below.
- [ ] Update documentation with the scope/basis fields, witness contract, mandatory limitation, narrow admission gates, unchanged negative rules, and calibration outcomes. Remove only resolved library-modeling backlog text; preserve unrelated gaps.
- [ ] Document measured results only. Do not present the approved design’s projected recall/accuracy changes as measurements.

**Focused validation:**

```bash
go test -count=1 ./internal/states \
  -run 'TestE2ELibrary'

go test -count=1 ./internal/affected \
  -run 'TestUsageScopeTestOnly|TestUsageScopeModuleTestOnly'

go test -count=1 ./internal/vulnerability \
  -run 'TestFileSourceScopeAfterAliasEnrichment|TestStaticSourceScopeDoesNotMutateStoredVulnerability'
```

#### Real testify calibration

Use an operator-prepared advisory directory containing both:

```text
GHSA-hp87-p4gw-j4gq.json
GO-2022-0603.json
```

The canonical GHSA supplies CWE-502; the GO sibling supplies `Unmarshal` symbols through existing local alias enrichment.

**Important:** requesting the GHSA against the GO document does not establish COMPLETE coverage. COMPLETE requires the requested ID to match the canonical loaded advisory ID.

With the snapshot and dependency cache/toolchain available:

```bash
go run ./cmd/izyan analyze \
  --repo "${VA_SNAPSHOTS}/stretchr/testify/285adcc5ced0bb267a7c874cfa3ca238266ce14f" \
  --vuln GHSA-hp87-p4gw-j4gq \
  --vuln-file "${VA_ADVISORY_DIR}/GHSA-hp87-p4gw-j4gq.json" \
  --case-dir "${VA_CASES}/testify-ghsa" \
  --deterministic-only --lang en

go run ./cmd/izyan analyze \
  --repo "${VA_SNAPSHOTS}/stretchr/testify/285adcc5ced0bb267a7c874cfa3ca238266ce14f" \
  --vuln CVE-2022-28948 \
  --vuln-file "${VA_ADVISORY_DIR}/GHSA-hp87-p4gw-j4gq.json" \
  --case-dir "${VA_CASES}/testify-cve" \
  --deterministic-only --lang en
```

Both must produce the approved scoped positive, including:

- `YAMLEq.expected`, formal 1 → `yaml.Unmarshal` argument 0 at `assert/assertions.go:1573`;
- `YAMLEq.actual`, formal 2 → argument 0 at `assert/assertions.go:1577`;
- nested generator excluded by module ownership;
- UNKNOWN deployment origins;
- COMPLETE for the canonical GHSA request and KNOWN_ONLY for the CVE request.

Do not add `--trusted-peer` or a manual exploit model to make these pass.

#### Existing application calibration

Run only these cases before the final full corpus gate:

```bash
go run ./cmd/izyan eval --corpus eval/corpus-real.json \
  --case real-yaml3-http

go run ./cmd/izyan eval --corpus eval/corpus-real.json \
  --case real-yaml3-const
```

Inspect emitted cases for the required HTTP EXPLOITABLE / constant NEPF calibration and zero library basis/scope. The corpus’s existing permissive `expect` arrays are not sufficient evidence for those stronger assertions; the new Go end-to-end tests enforce exact outcomes.

#### Known false-alarm and near-miss calibration

With the external task file, snapshots, and frozen advisory inputs available:

```bash
go run ./cmd/izyan eval vex-bench \
  --tasks "${VA_VEX_TASKS}" \
  --repos-dir "${VA_SNAPSHOTS}" \
  --osv-dir "${VA_FROZEN_OSV}" \
  --case 'containers-podman-38ccfa2-CVE-2024-37298,kubernetes-kubernetes-6d4b94f-CVE-2022-41717,labstack-echo-fdacff0-CVE-2020-26160' \
  -j 1 \
  --out "${VA_CASES}/library-negative-controls"
```

For each persisted report, assert no claim has `control_basis=library-public-api` and no verdict/profile has `exploitability_scope=library-api`.

The expected feature contribution is **zero admission**, not repair of the existing false alarms. Do not weaken gate D if a prepared benchmark advisory lacks the required CWE or symbol data.

**Acceptance:**
- The complete source-analysis → claim → verdict → persistence → export path works without LLM assistance.
- The public library and its three consumer shapes have the specified distinct outcomes.
- Real testify supports both advisory-coverage modes without changing coverage labels.
- Known false alarms and the auth-bypass near miss receive no incremental admission.
- Documentation accurately distinguishes code-level consumer selectability from unestablished downstream attacker control.

---

## Dependency / Execution Order

```text
Task 1: domain contracts + product-shape proof
    ├── Task 2: strict witness + trace persistence
    └── Task 3: report/CLI/VEX projection
                 │
Tasks 2 + 3 ─────┴──> Task 4: admission + verdict/profile scope
                         │
                         └──> Task 5: end-to-end/calibration/docs
```

### Shared-file serialization

| File | Required ownership/order |
|---|---|
| `internal/domain/domain.go` | Task 1 owns all new fields and graph seams; no concurrent later contract edits |
| `internal/goanalysis/source.go` | Task 1 owns product-shape/cache state |
| `internal/goanalysis/provenance.go` | Task 2 is the sole implementation owner |
| `internal/states/states.go` | Serialize Task 1 shape wiring → Task 2 trace persistence → Task 4 profile/admission integration |
| `internal/report/report.go` | Task 3 is the sole implementation owner |
| `cmd/izyan/main.go` | Task 3 scope-display changes; Task 4 does not reorder evaluator registration |
| `internal/states/states_test.go` | Task 5 changes only the fixture helper after preceding tasks land |

Tasks 2 and 3 may run in parallel after Task 1 freezes the interfaces. Task 4 must not land before Task 3’s narrative protections.

## Final Integration Validation

The integration owner performs this once after all implementation tasks have landed:

1. Format only the changed Go files.
2. Run:

```bash
go vet ./...
go test ./...
```

3. Run each full corpus once:

```bash
go run ./cmd/izyan eval --corpus eval/corpus-real.json -j 4

VA_PRODUCT_REPO="${VA_PRODUCT_REPO}" \
  go run ./cmd/izyan eval --corpus eval/live-corpus.json
```

4. Require `false-safe=0`; compare actual outcomes with the recorded baseline without relabeling pre-existing errors as feature successes.
5. Record the real testify and negative-control evidence separately from unit-test evidence.
6. Treat missing external snapshots, frozen advisories, toolchains, or live-product inputs as explicit unexercised validation prerequisites—not as passes.
7. Preserve the approved design unchanged during implementation. If source evidence contradicts its ownership, payload-preservation, or trust-boundary assumptions, stop the affected implementation slice and report the concrete contradiction rather than silently widening admission.

# Definitive Verdicts and Declared-Corpus Closure Implementation Plan

**Goal:** Answer each requested finding with an earned definitive verdict, a specific external dependency, or an explicit analysis failure, while supporting independently attributed related-record positives and Addendum A’s corpus-bounded CVE negatives.

**Architecture:** Preserve the existing single-record evaluator and admission gates. Add pinned discovery and attribution, run isolated record assessments, compose the requested finding per profile/build, and publish through one shared admission/projection layer.

**Tech stack:** Go 1.25+, existing `testing` tooling, existing state-machine/persistence architecture, OSV feeds, OpenVEX and CycloneDX exporters. No new runtime dependency is required.

**Spec:** `docs/dev/plans/2026-10-26-02-definitive-verdict.md`, including **Addendum A**.  
**Companion:** `docs/dev/plans/2026-10-26-01-related-record-discovery.md`, only where consistent with the definitive-verdict design and Addendum A.

All paths below are relative to the repository root. Interfaces shown below are proposed contracts, not claims about existing implementation. Validation commands are instructions for implementation; none were executed during this read-only planning assignment.

## Global Constraints

1. **Addendum A governs CVE negative completeness.**
   - A declared, digest-pinned, completely enumerated corpus can establish the request-level completeness basis.
   - `AdvisoryScope.AllowsNegativeClosure()` remains unchanged.
   - A configured feed, a finished scan, or an empty result alone is not closure authority.
   - Every decision-changing candidate must receive an independently admitted assessment.
   - The result must state the corpus identity, digest, capture date, and that implementations outside it were not examined.
   - Corpus completeness does not replace semantic proof: an unknown or failed child is not a negative; `NO_EXPLOIT_PATH_FOUND` is not relabeled `NOT_AFFECTED`.

2. **Keep three separate propositions:** discovery, CVE attribution, and product exploitability. `related` establishes only discovery.

3. **Every assessment, including the primary, uses its own document bytes, ranges, census, subjects, conditions, claims, review, severity and remediation.** Alias/feed enrichment is not an assessment-loading mechanism.

4. **Preserve all existing safety gates:** structural scope, product target provenance, completed measurement admission, negative verification, unresolved subjects, review criticism, implementation-axis admission, and library-API admission.

5. **Keep `VerdictInput` and one deterministic verdict evaluator.** Do not introduce a second exploitability evaluator or a verdict-forcing fallback.

6. **Claim uncertainty remains unchanged.** Failed measurements leave claims `UNKNOWN`. The terminal assessment outcome changes; evidence does not.

7. **`transport-peer` is an orthogonal scope**, not a new verdict or threat profile. It requires an admitted mandatory `TRUE` transport-input claim.

8. **Locality does not establish trust.** Unix/loopback binding, ClusterIP topology, missing listeners, or absence of exposure facts cannot alone select a trusted-peer actual profile.

9. **Use one authoritative requested-finding projection** for JSON, Markdown, CLI, scan/eval, tracker, justification, remediation, research, OpenVEX and CycloneDX.

10. **Keep historical evidence and frozen benchmark labels unchanged.** New observations belong in a new calibration report.

## Review Focus

| Risk | Owning tasks and controls |
|---|---|
| Missing work mislabeled environmental | Tasks 1 and 5: typed gap causes, externality validation, mixed-blocker tests |
| Relatedness treated as identity | Task 2: separate indexes and publisher/CNA admission |
| Facts or coverage transferred across records | Tasks 3 and 6: exact intake, record-bound govulncheck projection, independent child graphs |
| Reachable gRPC mistaken for a trigger proof | Task 4: rooted listener/transport witness plus source/fix-bound lifecycle proof |
| Unix/loopback listener selects trust | Task 5: typed perimeter basis and actual-profile controls |
| Corpus enumeration manufactures safety | Task 6: separate corpus gate plus independently earned child negatives |
| Saved composed positive bypasses admission | Task 7: replay, qualified references, digest/build/profile re-admission |
| Outputs show primary x/net remediation | Tasks 8–10: shared projection and witness-bound remediation |
| Reclassification inflates success metrics | Tasks 9 and 11: decided, external, failed, false-safe and false-positive accounting |

### Task 1: Freeze the outcome, requested-finding and scope contracts

**Depends on:** None  
**Ownership:** Domain/schema owner. Land before downstream implementation.

**Files:**
- Create: `internal/domain/assessment.go`
- Create: `internal/domain/finding.go`
- Create: `internal/domain/related_records.go`
- Create: `internal/domain/transport_scope.go`
- Create: `internal/domain/perimeter.go`
- Modify: `internal/domain/domain.go`
- Test: `internal/domain/assessment_test.go`
- Test: `internal/domain/finding_test.go`
- Test: `internal/domain/related_records_test.go`
- Test: `internal/domain/transport_scope_test.go`

**Interfaces:**

Freeze these terminal outcomes and schema discriminator:

```go
type AssessmentOutcome string

const (
    OutcomeDecided  AssessmentOutcome = "DECIDED"
    OutcomeExternal AssessmentOutcome = "EXTERNAL_DEPENDENCY"
    OutcomeFailed   AssessmentOutcome = "FAILED"
)

type FindingStatus string

const (
    FindingPending FindingStatus = "PENDING"
    FindingFinal   FindingStatus = "FINAL"
)

type CaseResultSchema string

const CaseSchemaV2 CaseResultSchema = "analysis-case/2"
```

Freeze the central result types:

```go
type QualifiedRef struct {
    AssessmentID CaseID `json:"assessment_id"`
    Ref          string `json:"ref"`
}

type RecordPin struct {
    RecordID       string `json:"record_id"`
    DocumentDigest string `json:"document_digest"`
    SourceLocator  string `json:"source_locator"`
    Modified       string `json:"modified,omitempty"`
}

type ExternalDependency struct {
    MissingFact             string         `json:"missing_fact"`
    AffectedObligation      string         `json:"affected_obligation"`
    BoundaryEvidenceRefs    []QualifiedRef `json:"boundary_evidence_refs"`
    WhyArtifactCannotSupply string         `json:"why_artifact_cannot_supply"`
    AlternativesChanging    []string       `json:"alternatives_changing_answer"`
    ResolvingEvidence       string         `json:"resolving_evidence"`
}

type GapOwner string // CODE | PROOF | INPUT | SCOPE | EXTERNAL
type GapCode string

type AnalysisGap struct {
    Owner        GapOwner            `json:"owner"`
    Code         GapCode             `json:"code"`
    Obligation   string              `json:"obligation"`
    AssessmentID CaseID              `json:"assessment_id"`
    ConditionID  ConditionID         `json:"condition_id,omitempty"`
    EvidenceRefs []QualifiedRef      `json:"evidence_refs,omitempty"`
    Message      string              `json:"message"`
    External     *ExternalDependency `json:"external_dependency,omitempty"`
}

type AssessmentResult struct {
    Outcome              AssessmentOutcome    `json:"assessment_outcome"`
    Verdict              *VerdictResult       `json:"verdict,omitempty"`
    Gaps                 []AnalysisGap        `json:"gaps,omitempty"`
    ExternalDependencies []ExternalDependency `json:"external_dependencies,omitempty"`
    Limitations          []string             `json:"limitations,omitempty"`
}

type ProfileAssessment struct {
    Profile        ThreatProfile   `json:"profile"`
    IsTargetActual bool            `json:"is_target_actual"`
    Build          BuildContext    `json:"build"`
    Claims         []Claim         `json:"claims"`
    Result         AssessmentResult `json:"result"`
    ContextualRisk *ContextualRisk `json:"contextual_risk,omitempty"`
}
```

`Obligation` is a controlled identifier, not prose to parse. Supported values must include affected-chain axes, root cause, a mandatory condition, discovery, attribution, measurement and negative scope.

Freeze request-level output:

```go
type ProofOrigin struct {
    AssessmentID  CaseID         `json:"assessment_id"`
    Record        RecordPin      `json:"record"`
    EntryRefs     []int          `json:"entry_refs"`
    MechanismID   string         `json:"mechanism_id,omitempty"`
    AttributionID string         `json:"attribution_id,omitempty"`
    Profile       ThreatProfile  `json:"profile"`
    Build         BuildContext   `json:"build"`
    ConditionRefs []QualifiedRef `json:"condition_refs"`
    ClaimRefs     []QualifiedRef `json:"claim_refs"`
    EvidenceRefs  []QualifiedRef `json:"evidence_refs"`
}

type FindingProfile struct {
    Profile              ThreatProfile        `json:"profile"`
    IsTargetActual       bool                 `json:"is_target_actual"`
    Build                BuildContext         `json:"build"`
    Outcome              AssessmentOutcome    `json:"assessment_outcome"`
    Verdict              Verdict              `json:"verdict,omitempty"`
    Reason               string               `json:"reason"`
    ExploitabilityScope  ExploitabilityScope  `json:"exploitability_scope,omitempty"`
    ProofOrigins         []ProofOrigin        `json:"proof_origins,omitempty"`
    CorpusNegativeBasis  *CorpusNegativeBasis `json:"corpus_negative_basis,omitempty"`
    ExternalDependencies []ExternalDependency `json:"external_dependencies,omitempty"`
    Gaps                 []AnalysisGap        `json:"gaps,omitempty"`
    Limitations          []string             `json:"limitations,omitempty"`
}

type RequestedFinding struct {
    Status              FindingStatus     `json:"status"`
    RequestedID         string            `json:"requested_id"`
    RequestedKind       AdvisoryScopeKind `json:"requested_kind"`
    Coverage            AdvisoryCoverage  `json:"coverage"`
    PrimaryAssessmentID CaseID            `json:"primary_assessment_id"`

    FindingProfile
    Profiles []FindingProfile `json:"profiles"`
}

type RelatedRecordAssessment struct {
    ID       CaseID        `json:"id"`
    Record   RecordPin     `json:"record"`
    Analysis *AnalysisCase `json:"analysis,omitempty"`
}
```

Use pointers for child cases; never copy `AnalysisCase` or `EvidenceGraph` by value.

Add these fields to `AnalysisCase`:

```go
Schema             CaseResultSchema          `json:"schema,omitempty"`
RecordPin          *RecordPin                `json:"record_pin,omitempty"`
RequestedFinding   *RequestedFinding         `json:"requested_finding,omitempty"`
RelatedDiscovery   *RelatedDiscovery         `json:"related_discovery,omitempty"`
RelatedRecords     []RelatedRecordAssessment `json:"related_records,omitempty"`
ProfileAssessments []ProfileAssessment       `json:"profile_assessments,omitempty"`
AnalysisGaps       []AnalysisGap             `json:"analysis_gaps,omitempty"`
PerimeterAssessment *PerimeterAssessment     `json:"perimeter_assessment,omitempty"`
```

Also:
- Add `Vulnerability.Related []string`.
- Add structured `AnalysisGaps` carriers to `AffectedResult`, `RootCauseModel`, `Claim` and `NegativeVerification`, so their producers can return typed causes.
- Freeze discovery enumeration values as lowercase `finished`, `partial`, `unavailable`, `not_configured`.
- Freeze candidate dispositions: `evaluated`, `unsupported`, `ambiguous`, `load_failed`, `timed_out`, `not_evaluated`.
- Freeze `CVEAttribution`, `CorpusDeclaration`, `CorpusManifest`, `CorpusNegativeBasis` and `RelatedDiscovery` with the fields specified in Task 2 and Task 6.

Add:

```go
const ScopeTransportPeer ExploitabilityScope = "transport-peer"
const ControlBasisTransportPeerInput ControlBasis = "transport-peer-input"

const TransportPeerScopeLimitation = "Transport-peer scope: a client of the product's affected transport can supply the triggering input. Whether an adversary can access that transport—through socket permissions, placement, ingress or authentication—is not established."
```

Freeze typed perimeter bases: `unknown`, `listener-locality`, `deployment-topology`, `deployment-policy`, `operator-declared`. A topology basis is not a trust basis.

**Invariants:**
- `DECIDED`: non-nil verdict, one of the three definitive verdicts.
- `EXTERNAL_DEPENDENCY`: `INCONCLUSIVE` plus complete evidence-bound external dependencies.
- `FAILED`: nil record-level public verdict; empty/omitted requested-finding verdict.
- `PENDING` is a persistence phase, not a fourth assessment outcome.
- New-schema requests always have a `requested_finding` envelope, including exact requests and requested/resolved IDs that happen to match.
- CVE requested coverage remains `KNOWN_ONLY`; corpus authority is carried separately.

**What NOT to change:** `AllowsNegativeClosure()`, claim truth values, existing verdict values, threat profiles, library-API admission.

- [ ] Step 1: Add schema/serialization tests covering all three outcomes, pending envelopes, qualified references, profile proof sets and scope constants.
- [ ] Step 2: Run:
  ```sh
  go test ./internal/domain -run '^Test(AssessmentOutcome|RequestedFindingSchema|RelatedRecordSchema|TransportScopeContract)$' -count=1
  ```
  Expected initial failure: missing contracts.
- [ ] Step 3: Implement the contracts and structural validation helpers.
- [ ] Step 4: Run the same focused command; expect PASS.
- [ ] Step 5: Assert malformed `FAILED`+verdict, unbound references and unknown enum values are rejected.

**Acceptance:** Downstream tasks can compile against one agreed schema without inventing their own outcome, origin, corpus or scope representation.

### Task 2: Implement pinned discovery and directional attribution

**Depends on:** Task 1  
**Ownership:** Advisory acquisition/discovery owner.

**Files:**
- Create: `internal/advfeed/corpus.go`
- Create: `internal/advfeed/corpus_test.go`
- Create: `internal/vulnerability/record.go`
- Create: `internal/vulnerability/record_test.go`
- Create: `internal/vulnerability/attribution.go`
- Create: `internal/vulnerability/attribution_test.go`
- Modify: `internal/advfeed/advfeed.go`
- Modify: `internal/advfeed/fetch.go`
- Modify: `internal/vulnerability/osv.go`
- Modify: `internal/vulnerability/source.go`
- Test: `internal/vulnerability/osv_test.go`
- Test: `internal/advfeed/advfeed_test.go`

**Interfaces:**

```go
// Exact bytes only: no alias/feed enrichment and no network.
func ParseOSV(raw []byte) (*domain.Vulnerability, string, error)

type LoadedRecord struct {
    Pin  domain.RecordPin
    Raw  []byte
    Vuln *domain.Vulnerability
}

func LoadExactBytes(raw []byte, recordID string, locator string) (LoadedRecord, error)
func (s FileSource) LoadExact(ctx context.Context, recordID string) (LoadedRecord, error)

type Relationship string // record | alias | related

type CorpusOptions struct {
    Feed        Options
    Declaration *domain.CorpusDeclaration
    Selections  []domain.RecordPin
}

func AcquireCorpus(ctx context.Context, o CorpusOptions) (*Corpus, error)
func (c *Corpus) Manifest() domain.CorpusManifest
func (c *Corpus) Lookup(kind Relationship, id string) []domain.RecordPin
func (c *Corpus) Document(ctx context.Context, pin domain.RecordPin) (LoadedRecord, error)
func (c *Corpus) Discover(requestID string, primary *LoadedRecord) domain.RelatedDiscovery
```

`CorpusDeclaration` contains the operator-declared corpus reference, expected digest and capture date. The observed manifest separately contains source provenance, observed digest, enumeration outcome, all document pins and read/decode problems. Do not add another consent flag: the declaration itself supplies the declared completeness boundary.

Maintain independent indexes:
- own record ID → document pins;
- alias → document pins;
- direct related ID → document pins.

Keep existing `Feed.index` ID/alias semantics. Do not insert related IDs into the subject-completion index.

Reuse existing digest conventions:
- ZIP: archive-byte SHA-256;
- directory: existing deterministic sorted path/document-digest representation;
- documents: raw-byte SHA-256, represented as `sha256:<lowercase hex>` in domain pins.

`CVEAttribution` must contain:

```text
ID; CVEID; candidate RecordPin; original EntryRefs; MechanismID;
basis (own_id|own_alias|publisher|cna);
SourceURI; captured source digest; exact field/quote;
publisher advisory identity; module/repository and fix binding;
admission (admitted|related_only|ambiguous).
```

Attribution APIs:

```go
type CapturedMaterial struct {
    URI           string
    DocumentDigest string
    CapturedAt    time.Time
    ContentType   string
    Content       []byte
}

type MaterialSource interface {
    Capture(ctx context.Context, uri string) (CapturedMaterial, error)
}

type AttributionInput struct {
    CVEID       string
    Record      LoadedRecord
    EntryRefs   []int
    MechanismID string
    Materials   []CapturedMaterial
}

func AdmitAttribution(in AttributionInput) (domain.CVEAttribution, error)
```

Implement configured local captures and permitted remote capture behind `MaterialSource`. Remote material must be acquired through the configured source policy, bounded and pinned before admission. Offline operation consumes supplied captures. Do not restrict the feature to manual mappings when permitted publisher evidence is available.

**Required behavior:**
- Inverse `related(CVE-2023-44487)` discovers `GO-2023-2153` without an outgoing primary gRPC edge.
- Nominate direct matches and direct primary neighbors only; no transitive relationship closure.
- Exact requests retain all explicit CVE seeds and their originating fields.
- Identical ID/digest documents deduplicate while retaining discovery edges.
- Conflicting same-ID bytes remain ambiguous unless `Selections` chooses exact bytes.
- Read/decode failures produce partial enumeration and visible dispositions.
- Publisher/CNA admission validates candidate digest, advisory identity, original entry/mechanism, module/repository and fix references.
- The gRPC publisher advisory’s explicit CVE, module and PR 6703 binding is admissible; a bare related edge or free-text CVE URL is not.

**What NOT to change:** `ResolveImports` into an identity API; alias enrichment to accept related IDs; original record census construction; benchmark-directory discovery; primary severity/ranges based on publisher material.

- [ ] Step 1: Add `TestCorpusDiscovery`, `TestExactRecordLoad` and `TestAttributionAdmission` tables covering inverse lookup, non-transitivity, duplicates, conflicts, missing sources and publisher controls.
- [ ] Step 2: Run:
  ```sh
  go test ./internal/advfeed ./internal/vulnerability -run '^Test(CorpusDiscovery|ExactRecordLoad|AttributionAdmission)$' -count=1
  ```
  Expected initial failure: new APIs/behavior absent.
- [ ] Step 3: Implement acquisition, exact loading, discovery and attribution.
- [ ] Step 4: Run the same command; expect PASS.
- [ ] Step 5: Run existing related parser/feed scope controls:
  ```sh
  go test ./internal/advfeed ./internal/vulnerability -run 'Test(.*ResolveImports|.*ScopeExtent|.*RecordInventory|.*Alias)' -count=1
  ```

**Acceptance:** Discovery returns pinned candidates and explicit limitations, but transfers no applicability or proof authority. Publisher attribution can admit the gRPC association without modifying the GO record’s aliases.

### Task 3: Make reusable measurements record-bound

**Depends on:** Tasks 1 and 2  
**Ownership:** Measurement/admission owner.

**Files:**
- Modify: `internal/domain/measurement.go`
- Modify: `internal/goanalysis/govulncheck.go`
- Modify: `internal/goanalysis/govulncheck_record.go`
- Modify: `internal/states/states.go`
- Test: `internal/goanalysis/govulncheck_test.go`
- Test: `internal/states/govulncheck_outcome_test.go`
- Create: `internal/goanalysis/record_projection_test.go`

**Interfaces:**

Retain the existing runner and build-bound caches. Add an emitting-record representation to `goanalysis.Result`:

```go
type EmittedAdvisory struct {
    Record   domain.RecordPin
    Subjects []domain.SymbolRef
    Modules  []string
}

type RecordProjection struct {
    Coverage domain.GovulncheckCoverage
    Findings []Finding
}

func (r Result) ProjectRecord(record LoadedRecord) (RecordProjection, error)
```

Here `LoadedRecord` is `vulnerability.LoadedRecord`; use its qualified package name in code.

Extend durable govulncheck coverage with the emitting record ID/document digest and bound module/package/symbol identities. Coverage of one record is not coverage of another document sharing its CVE.

Migrate authoritative assessment callers of `DeclaredSymbols`, `Covers` and `ForVulnerability` to the exact-record projection. Remove obsolete alias-union coverage logic where no non-authoritative caller still needs it.

**Required behavior:**
- Raw completed tool output may be reused for the same `BuildContext`.
- Each record projects that output against its own subjects.
- An emitted GO record may nominate or support a separately pinned assessment; it cannot silently fill another record’s missing symbols.
- Shared-CVE metadata never creates another record’s coverage.
- Failed, not-run, narrowed and malformed streams retain their existing admission restrictions.
- Independently bound positive traces remain usable even when unrelated scan scope is incomplete.

**What NOT to change:** Measurement completion rules, target provenance requirements, cache build matching, package inventory admission, or absence-to-negative rules.

- [ ] Step 1: Add `TestGovulncheckRecordProjection` with two records sharing a CVE but having disjoint modules/subjects, wrong document digests, matching positive traces and partial scans.
- [ ] Step 2: Run:
  ```sh
  go test ./internal/goanalysis ./internal/states -run '^Test(GovulncheckRecordProjection|GovulncheckOutcome|GovulncheckRecord)' -count=1
  ```
  Expected initial failure: alias-union coverage leaks across records.
- [ ] Step 3: Implement the exact-record projection and migrate evidence collection.
- [ ] Step 4: Run the same command; expect PASS.
- [ ] Step 5: Assert a common CVE key cannot turn `not_in_db` into `covered` for the other candidate.

**Acceptance:** Reusable product measurements remain reusable, but record-specific coverage and findings cannot be inherited.

### Task 4: Prove rooted transport input and the Rapid Reset trigger

**Depends on:** Tasks 1–3  
**Ownership:** Source/transport proof owner.

**Files:**
- Create: `internal/domain/transport_proof.go`
- Create: `internal/goanalysis/transport_proof.go`
- Create: `internal/goanalysis/transport_proof_test.go`
- Create: `internal/evaluator/transport_proof.go`
- Modify: `internal/evaluator/transport.go`
- Modify: `internal/evaluator/verdict.go`
- Modify: `internal/exploit/builder.go`
- Modify: `internal/exploit/patterns.go`
- Modify: `internal/states/states.go`
- Test: `internal/evaluator/transport_test.go`
- Test: `internal/evaluator/verdict_test.go`
- Create: `internal/states/transport_proof_test.go`
- Create: `testdata/transportresetprod/go.mod`
- Create: `testdata/transportresetprod/main.go`
- Create: `testdata/transportresetprod/dep/go.mod`
- Create: `testdata/transportresetprod/dep/server.go`

**Interfaces:**

```go
type TransportProofRequest struct {
    Record      domain.RecordPin
    EntryRefs   []int
    Subjects    []domain.SymbolRef
    Product     domain.ProductSnapshot
    Mechanism   string // currently http2-rapid-reset
    FixURI      string
    FixDigest   string
    FixDiff     string
}

type TransportProof struct {
    Input    *domain.TransportInputWitness
    Trigger  *domain.TransportTriggerWitness
    Evidence []domain.Evidence
    Gaps     []domain.AnalysisGap
}

func (ix *Index) ProveServerTransport(
    ctx context.Context,
    req TransportProofRequest,
) (TransportProof, error)

func ValidateTransportInput(
    product domain.ProductSnapshot,
    model domain.ExploitModel,
    claim domain.Claim,
    evidence []domain.Evidence,
) error

func ValidateTransportTrigger(
    product domain.ProductSnapshot,
    model domain.ExploitModel,
    claim domain.Claim,
    evidence []domain.Evidence,
) error
```

Place validators in `internal/evaluator/transport_proof.go`; witness types belong in domain.

`TransportInputWitness` must pin:
- record/entry and build;
- product-owned production root;
- root-to-server path;
- the same constructed server and listener passed to `Serve`;
- path into the affected transport;
- source artifact digests and evidence IDs.

`TransportTriggerWitness` must additionally pin source/fix evidence for:
1. peer-controlled HTTP/2 frame consumption;
2. open/reset/reopen stream feasibility;
3. handler admission and asynchronous handler lifetime;
4. stream removal before handler completion;
5. the missing fixed handler-quota enforcement;
6. product controls and their position relative to vulnerable dispatch.

These are structured source bindings, not caller-supplied `proven: true` flags.

**Required behavior:**
- `ServerTransportInput` may establish attacker control from an admitted input witness.
- `C-CONSTRAINT` for this mechanism requires the trigger witness. A generic transport frame cannot satisfy it.
- An incomplete proof emits `TRIGGER_PROOF_INCOMPLETE`; it is not an external dependency.
- Scope is assigned only from an admitted mandatory `TRUE` transport-input claim.
- Preserve the existing library-API route and its exact class/CWE admission.
- Do not exempt transport claims from cluster-perimeter rewriting.
- Use supported typed source analysis and existing source primitives. A positive source-slice path may use exact vendored bytes when fully bound; it must not confer whole-build negative completeness.

**Controls:**
- Import-only, dial-only, unserved constructor, test-only and unrooted staging paths do not qualify.
- A handler-level unary rate limiter does not substitute for a pre-dispatch transport quota.
- An effective pre-dispatch quota prevents this positive.
- No runtime condition may branch on Kubernetes identity, the benchmark ID or CVE number.

- [ ] Step 1: Add `TestTransportProof` and `TestTransportTriggerAdmission` tables for the full witness and each missing/mismatched obligation.
- [ ] Step 2: Run:
  ```sh
  go test ./internal/goanalysis ./internal/evaluator ./internal/states -run '^Test(TransportProof|TransportTriggerAdmission|TransportScopeAdmission)$' -count=1
  ```
  Expected initial failure: rooted/trigger witness support absent.
- [ ] Step 3: Implement proof collection, model binding, claim admission and scope projection.
- [ ] Step 4: Run the same command; expect PASS.
- [ ] Step 5: Run library admission near-miss controls:
  ```sh
  go test ./internal/evaluator ./internal/states -run 'Test.*Library' -count=1
  ```

**Acceptance:** A complete rooted transport and source/fix-bound lifecycle proof earns the transport conjunction. Server construction or generic reachability alone does not.

### Task 5: Classify terminal outcomes and remove locality-derived trust

**Depends on:** Task 1; integrate after Tasks 3–4 edits to `states.go`  
**Ownership:** Workflow/outcome owner.

**Files:**
- Create: `internal/finding/outcome.go`
- Create: `internal/finding/outcome_test.go`
- Create: `internal/workflow/engine_test.go`
- Modify: `internal/workflow/engine.go`
- Modify: `internal/states/states.go`
- Modify: `internal/states/gap.go`
- Modify: `internal/affected/resolver.go`
- Modify: `internal/rootcause/rootcause.go`
- Modify: `internal/goanalysis/negative.go`
- Modify: `internal/evaluator/verdict.go`
- Modify: `internal/llm/tools.go`
- Modify: `internal/llm/client.go`
- Modify: `internal/cveanalysis/tools.go`
- Modify: `internal/exposure/perimeter.go`
- Test: `internal/states/states_test.go`
- Test: `internal/states/perimeter_eval_test.go`
- Test: `internal/states/perimeter_target_test.go`
- Test: `internal/exposure/perimeter_test.go`
- Create: `internal/states/assessment_outcome_test.go`

**Interfaces:**

Extend the same evaluator with typed diagnostic output:

```go
type VerdictEvaluation struct {
    Verdict domain.VerdictResult
    Gaps    []domain.AnalysisGap
}

func (VerdictEvaluator) EvaluateDetailed(in VerdictInput) VerdictEvaluation
```

Keep `Evaluate(in VerdictInput) VerdictResult` as the existing API, delegating to the same implementation—not re-running evaluation.

```go
type AssessmentInput struct {
    evaluator.VerdictInput
    RootCause *domain.RootCauseModel
    Gaps      []domain.AnalysisGap
}

func Assess(in AssessmentInput) domain.AssessmentResult
```

Add to `workflow.Engine`:

```go
FailureState domain.WorkflowState
```

This is the registered continuation for recoverable analysis failure/budget exhaustion, not a terminal state. Root orchestration sets it to the related-record/composition continuation; record-only execution sets it to its record-finalization boundary.

Change:

```go
func ClassifyPerimeter(
    facts []domain.ExposureFact,
    productNames []string,
) domain.PerimeterAssessment
```

Migrate all callsites. The result separates exposure classification from its basis; only independently admitted deployment-policy evidence or explicit operator selection can establish actual trusted-profile selection.

**Required behavior:**
- Sufficient admitted proof wins first.
- Otherwise relevant code/proof/input/scope blockers produce `FAILED`, no verdict.
- Only evidence-bound, decision-changing external facts produce `EXTERNAL_DEPENDENCY / INCONCLUSIVE`.
- Mixed external and analyzer blockers remain `FAILED`.
- Unclassified unresolved obligations produce `UNCLASSIFIED_ANALYSIS_GAP`.
- Supporting unknowns irrelevant to a sufficient proof remain limitations.

Emit typed codes at producers, including:
`ANALYSIS_BUDGET_EXHAUSTED`, `ANALYSIS_TIMEOUT`,
`INPUT_RESOLUTION_FAILED`, `MEASUREMENT_NOT_COMPLETED`,
`ROOT_CAUSE_UNRESOLVED`, `REACHABILITY_PROOF_INCOMPLETE`,
`INPUT_TRACE_INCOMPLETE`, `TRIGGER_PROOF_INCOMPLETE`,
`NEGATIVE_VERIFICATION_INCOMPLETE`, `REVIEW_UNRESOLVED`,
`PROOF_ARTIFACT_MISSING`, `UNSUPPORTED_NEGATIVE_SCOPE`.

Do not classify by searching limitation/error strings.

Capture both profile claim sets before the current actual-profile assignment overwrites `c.Claims`. Populate `ProfileAssessments`; failed profiles cannot retain stale safe verdicts or `DISMISSED` risk.

Preserve the controller repair: unresolved root cause reaches evaluation/finalization and reports. Extend that behavior to manual-root-cause rejection, missing resolver, invalid/missing exploit model, strict-LLM failure, budget and timeout paths.

Workflow requirements:
- Analysis failures continue to composition/reporting.
- Finalization/report writing is not repeatedly stopped by an exhausted analysis budget.
- On cancelled analysis contexts, use a bounded cancellation-detached context only for persistence/reporting; do not resume analysis work.
- Persistence/report I/O failures remain explicit errors; do not claim a report was written.
- Unix/loopback or ClusterIP topology alone cannot select actual trusted-peer results or stamp trust as `auto-perimeter`.
- Hypothetical cluster-perimeter results remain explicitly conditional and distinct from deployment facts.

**What NOT to change:** UNKNOWN-to-FALSE rules, existing falsifier verification, reviewer authority, target admission, or explicit operator trust-policy semantics.

- [ ] Step 1: Add `TestAssessmentOutcomePolicy`, `TestWorkflowFailureReporting` and `TestPerimeterTrustBasis` tables.
- [ ] Step 2: Run:
  ```sh
  go test ./internal/finding ./internal/workflow ./internal/states ./internal/exposure -run '^Test(AssessmentOutcomePolicy|WorkflowFailureReporting|PerimeterTrustBasis)$' -count=1
  ```
  Expected initial failure: tool gaps still abstain or terminate before reports.
- [ ] Step 3: Implement producer diagnostics, outcome classification, continuation routing and perimeter basis.
- [ ] Step 4: Run the same command; expect PASS.
- [ ] Step 5: Cover timeout, skipped package, missing sidecar, pending mandatory criticism and failed verification while asserting claims remain `UNKNOWN`.

**Acceptance:** Terminal `INCONCLUSIVE` means a specific external dependency, not unfinished analyzer work. Local listeners remain hostile-peer eligible unless trust is independently established.

### Task 6: Orchestrate isolated record assessments and compose the request

**Depends on:** Tasks 2–5  
**Ownership:** Request orchestration/composition owner.

**Files:**
- Create: `internal/states/related_records.go`
- Create: `internal/states/related_records_test.go`
- Create: `internal/finding/compose.go`
- Create: `internal/finding/compose_test.go`
- Create: `internal/domain/corpus_scope.go`
- Create: `internal/domain/corpus_scope_test.go`
- Create: `cmd/izyan/record_pipeline.go`
- Modify: `internal/domain/domain.go`
- Modify: `internal/states/states.go`
- Modify: `internal/workflow/engine.go`
- Modify: `cmd/izyan/main.go`

**Interfaces:**

Add workflow states:

```text
DISCOVER_RECORDS
ASSESS_RELATED_RECORDS
COMPOSE_REQUESTED_FINDING
```

Add a record-only stop boundary without creating another workflow evaluator:

```go
func (e *Engine) RunUntil(
    ctx context.Context,
    c *domain.AnalysisCase,
    stop domain.WorkflowState,
) error

type RecordRunner func(context.Context, *domain.AnalysisCase) error

func NewRecordCase(
    id domain.CaseID,
    record vulnerability.LoadedRecord,
    product domain.ProductSnapshot,
    limits domain.AnalysisLimits,
    usage domain.AnalysisUsage,
) (*domain.AnalysisCase, error)

func Compose(c *domain.AnalysisCase) (domain.RequestedFinding, error)
func Finalize(c *domain.AnalysisCase) error

func AllowsDeclaredCorpusNegativeClosure(
    c *domain.AnalysisCase,
    profile domain.ThreatProfile,
) error
```

`Finalize` assigns the composed envelope only; composition must not rewrite primary applicability, census, claims, risk or verdict.

Factor the existing record-handler assembly in `main.go` into `record_pipeline.go`. Root and child execution use the same handlers, evaluator chain, root-cause verifier, negative verifier and reviewers. The record runner stops before request discovery/reporting.

**Pipeline:**

```text
snapshot/request intake
→ pinned primary resolution
→ DISCOVER_RECORDS
→ primary record pipeline, if available
→ ASSESS_RELATED_RECORDS
→ COMPOSE_REQUESTED_FINDING
→ BUILD_REPORT
→ terminal state selected from requested outcome
```

Primary resolution failure or primary affected-negative must not bypass candidate evaluation. Exact resolution failure never substitutes another record for the request.

**Isolation and budgets:**
- Create fresh child cases/graphs/claims/reviews from exact record intake.
- Children request their own exact record IDs and never recursively discover.
- Primary manual root-cause, locus, implementation or exploit proposals are not broadcast to children.
- Share immutable snapshot, source index and existing build-bound raw measurement caches—not conclusions.
- Run candidates sequentially in deterministic order initially.
- Seed each child with remaining request budgets/cumulative usage; merge its usage before the next candidate. Do not reset the deadline or grant fresh per-child budgets.
- Preserve sticky source-index truncation; a child cannot erase prior coverage loss.
- Deduplicate primary/candidate identical record pins without altering the primary request scope.

**Composition rules:**
1. Exact request: project only the primary result. Related positives remain separate findings.
2. CVE positive: require one independently `EXPLOITABLE`, admitted-attributed witness for the same profile/build.
3. Never combine partial conditions, profiles or builds.
4. An admitted positive survives unrelated candidate failures; retain their diagnostics.
5. Without a deciding proof, relevant failed/unsupported/unassessed candidates prevent closure.
6. Genuine external dependencies survive only after analyzer-owned blockers are discharged.
7. The Addendum A negative route is separate:
   - configured declaration with matching digest and capture date;
   - enumeration `finished`;
   - all nominated candidates independently assessed;
   - no positive or unresolved decision-changing attribution;
   - every relevant child supplies admitted unaffectedness proof;
   - exact corpus boundary carried verbatim.
8. Missing/partial/unavailable/undeclared corpus gives `FAILED / UNSUPPORTED_NEGATIVE_SCOPE`.
9. Do not aggregate child NEPF into CVE `NOT_AFFECTED`; Addendum A supplies completeness, not a new meaning for unaffectedness. CVE-level NEPF aggregation is not introduced by this plan.
10. A declared finished corpus with no nominated records may state the bounded “no matching records in this corpus” result; it must not claim globally absent implementations.

`CorpusNegativeBasis` contains corpus reference, declared/observed digest, capture date, enumeration, manifest digest, assessed record pins and the boundary statement:

> Corpus boundary: `<reference>`, digest `<digest>`, captured `<date>`; implementations outside this corpus were not examined.

No aggregate `RecordExtent` or `RecordInventory` is created.

**What NOT to change:** Primary GHSA census **22/1/21**, `GO_PROJECTION`, `KNOWN_ONLY`; `AllowsNegativeClosure()`; exact-request identity; record remediation.

- [ ] Step 1: Add `TestIsolatedRecordAssessment`, `TestRequestedFindingComposition` and `TestDeclaredCorpusClosure`.
- [ ] Step 2: Run:
  ```sh
  go test ./internal/states ./internal/finding ./internal/domain -run '^Test(IsolatedRecordAssessment|RequestedFindingComposition|DeclaredCorpusClosure)$' -count=1
  ```
  Expected initial failure: isolated orchestration/composition absent.
- [ ] Step 3: Implement the stages, shared handler assembly and composition.
- [ ] Step 4: Run the same command; expect PASS.
- [ ] Step 5: Test primary failure + candidate positive, exact-request non-substitution, positive + unrelated timeout, all-negative declared corpus, missing corpus, mixed profiles/builds, and request-wide budget exhaustion.

**Acceptance:** The request is answered only by complete independent witnesses or admitted corpus-bounded unaffectedness; child results remain isolated and independently inspectable.

### Task 7: Persist, replay and re-admit one publication projection

**Depends on:** Tasks 1–6  
**Ownership:** Persistence/publication-admission owner.

**Files:**
- Create: `internal/domain/case_result.go`
- Create: `internal/finding/project.go`
- Create: `internal/finding/project_test.go`
- Modify: `internal/persistence/filesystem/store.go`
- Test: `internal/persistence/filesystem/store_test.go`

**Interfaces:**

```go
func ValidateCaseResult(c *AnalysisCase) error
func ValidateFinalizedCase(c *AnalysisCase) error

type WitnessView struct {
    Origin     domain.ProofOrigin
    Assessment *domain.AnalysisCase
    Profile    domain.ProfileAssessment
}

type View struct {
    Requested domain.RequestedFinding
    Primary   *domain.AnalysisCase
    Records   map[domain.CaseID]*domain.AnalysisCase
    Witnesses []WitnessView
}

func Project(c *domain.AnalysisCase) (View, error)
```

`Project` is pure and non-mutating. It:
- validates schema and references;
- re-admits primary/children using the existing evaluator and Task 5 outcome classifier;
- re-admits exact record pins, source captures, attribution and transport witnesses;
- verifies profile/build binding;
- recomposes the requested result;
- refuses saved positives/negatives not supported by current admitted artifacts.

The recomputed projection, not saved `requested_finding` assertions alone, is authoritative.

**Persistence rules:**
- `schema=""`: legacy single-assessment interpretation; no invented discovery, attribution, corpus basis or environmental classification.
- `analysis-case/2`: required requested-finding envelope.
- Pending roots are loadable/resumable but not publishable.
- Terminal new-schema cases require a final envelope.
- Unknown schemas and new fields masquerading as legacy are rejected.
- Children are exact-record cases; nested discovery/children are rejected.
- Child in-progress persistence is allowed while the root is pending; final publication requires finalized children or explicit unassessed dispositions.
- Qualified references resolve only within the named assessment.
- Legacy unclassified `INCONCLUSIVE` must not be presented as a verified external dependency. Preserve its historical status and expose the classification/admission limitation.

**What NOT to change:** Raw historical artifacts or saved evidence to make replay pass; no fallback from invalid new schema to legacy; no mutex-bearing struct copies.

- [ ] Step 1: Add `TestCaseResultPersistence` and `TestFindingProjectionAdmission`.
- [ ] Step 2: Run:
  ```sh
  go test ./internal/persistence/filesystem ./internal/finding -run '^Test(CaseResultPersistence|FindingProjectionAdmission)$' -count=1
  ```
  Expected initial failure: schema/re-admission not enforced.
- [ ] Step 3: Implement structural load/save validation and pure projection.
- [ ] Step 4: Run the same command; expect PASS.
- [ ] Step 5: Tamper record/source digest, attribution, child claim, evidence reference, profile and build; assert no forged composed conclusion publishes.

**Acceptance:** Persistence preserves all independent proof artifacts, and replay cannot publish a conclusion merely because the saved envelope says it was decided.

### Task 8: Cut reports and exports over to the shared projection

**Depends on:** Task 7  
**Ownership:** Report/export owner.

**Files:**
- Modify: `internal/report/report.go`
- Modify: `internal/report/openvex.go`
- Modify: `internal/report/cyclonedx.go`
- Modify: `internal/report/library_scope.go`
- Create: `internal/report/requested_finding.go`
- Create: `internal/report/requested_finding_test.go`
- Test: `internal/report/report_test.go`
- Test: `internal/report/openvex_test.go`
- Test: `internal/report/cyclonedx_test.go`
- Test: `internal/report/measurement_admission_test.go`
- Test: `internal/report/library_scope_test.go`
- Modify: `internal/risk/risk.go`
- Test: `internal/risk/risk_test.go`

**Interfaces:**

Keep existing public report signatures:

```go
func Write(dir string, c *domain.AnalysisCase) error
func Markdown(c *domain.AnalysisCase, lang ...string) string
func TrackerRationale(c *domain.AnalysisCase) string
func OpenVEX(c *domain.AnalysisCase) ([]byte, error)
func CycloneDX(c *domain.AnalysisCase) ([]byte, error)
func FixTarget(c *domain.AnalysisCase) (module, version string, ok bool)
```

Internally, all use `finding.Project`. Add:

```go
type RemediationTarget struct {
    Origin          domain.ProofOrigin
    Module          string
    ResolvedVersion string
    FixedVersion    string
}

func FixTargets(c *domain.AnalysisCase) ([]RemediationTarget, error)
```

Migrate actual multi-witness consumers to `FixTargets`; retain `FixTarget` only where a single exact assessment is intentionally requested.

**Required presentation:**
1. Requested identity/outcome and optional verdict.
2. Actual profile, source/build scope and proof origin.
3. Witness-specific remediation/severity/risk.
4. Unchanged primary assessment/census.
5. Candidate assessments/dispositions.
6. External dependencies, failures and discovery/corpus limitations.

Update the manual `reportCaseCopy` field list or replace its usage with the projection so new fields cannot disappear.

`FAILED` has a failure section and no requested verdict. It must not receive a safe/dismissed risk disposition. Missing exposure facts remain `UNKNOWN`; do not describe them as “no external exposure” or automatically downgrade risk on that basis.

Exports:
- Emit separate primary, candidate and requested-CVE entries, deduplicating identical identities.
- A gRPC witness supplies the requested CVE subcomponent, version, remediation and source attribution.
- Do not export related IDs as aliases.
- Carry scope, profile, build, limitations and corpus boundary in schema-supported text plus companion structured JSON.
- External and failed results may both map to `under_investigation` / `in_triage`, but explanations distinguish them.
- Corpus-bounded negatives must not claim `component_not_present` unless that is actually the proof. Use an accurate schema-valid explanation for the admitted negative.
- RU/EN outputs carry the same claims; the English transport limitation remains verbatim in structured output.

**What NOT to change:** OpenVEX/CycloneDX schemas with custom unsupported fields; primary x/net facts to match gRPC; library-API scope semantics.

- [ ] Step 1: Add `TestRequestedFindingReports` covering composed positive, corpus negative, external, failed, tampered proof and exact request.
- [ ] Step 2: Run:
  ```sh
  go test ./internal/report ./internal/risk -run '^Test(RequestedFindingReports|RiskUnknownExposure|WitnessRemediation)$' -count=1
  ```
  Expected initial failure: outputs still select primary identity/remediation.
- [ ] Step 3: Implement the report/export cutover and risk wording correction.
- [ ] Step 4: Run the same command; expect PASS.
- [ ] Step 5: Extend existing export decoding/schema checks and measurement/library admission tests.

**Acceptance:** All report artifacts agree on the requested result; the worked positive recommends the gRPC fix, never x/net’s fixed version.

### Task 9: Migrate CLI, scan/eval, justification and remediation consumers

**Depends on:** Tasks 7–8  
**Ownership:** Public consumer/calibration-accounting owner.

**Files:**
- Create: `cmd/izyan/advisory_sources.go`
- Create: `cmd/izyan/requested_finding_test.go`
- Modify: `cmd/izyan/main.go`
- Modify: `cmd/izyan/eval.go`
- Modify: `cmd/izyan/vexbench.go`
- Modify: `cmd/izyan/remediate.go`
- Modify: `internal/eval/eval.go`
- Modify: `internal/eval/vexbench/score.go`
- Modify: `internal/justification/justification.go`
- Test: `cmd/izyan/scan_test.go`
- Test: `cmd/izyan/vexbench_test.go`
- Test: `internal/eval/eval_test.go`
- Test: `internal/eval/vexbench/score_test.go`

Before implementation, resolve any declaration filename in `internal/justification` through the directory listing; the modification target is the existing file declaring `Build`, not a newly duplicated builder.

**Interfaces and configuration:**
- Keep `analyzeCase(ctx, opts) (*AnalysisCase, error)`.
- Make `printCase`, scan row extraction and eval/VEX result extraction consume `finding.Project`.
- New analysis failures are ordinary persisted assessment results; CLI exits nonzero for `FAILED` after reporting the case/report path.
- Usage/configuration errors still fail before analysis.
- External-dependency results remain distinct from execution errors.

Reuse the research feed flag convention across authoritative commands:
```text
--osv-feed
--osv-url
--osv-cache-dir
--osv-dump-ttl
--osv-no-proxy
```

Add shared declaration/capture flags:
```text
--corpus-digest <sha256>
--corpus-captured-at <RFC3339>
--record-pin <record-id>=<sha256>     repeatable
--attribution-file <capture-manifest>
```

The capture manifest is a closed-schema list of source URIs, local captured-byte paths and expected digests—not a trusted CVE mapping.

Factor flag-to-`advfeed.CorpusOptions` resolution into `advisory_sources.go`; research adopts it in Task 10. Merely supplying a feed does not create negative authority. Do not repurpose the existing single-record API URL option as a dump source.

Extend eval result/envelope fields with:
```text
assessment_outcome, failure_code(s), requested_id/kind,
primary record/digest, candidate IDs, attribution outcomes,
proof origins, profile/build, corpus digest.
```

Add separate metrics:
```text
decided, external_dependency, analysis_failed,
false_safe, false_positive.
```

Score the requested finding. Do not score an exact-GHSA answer against CVE-wide ground truth. Failed analyses cannot count as successful completion; external dependencies cannot count as definitive answers.

Tracker sink interfaces remain unchanged; their text comes from the shared report projection. Justification and remediation must identify the selected witness rather than reading the primary record directly.

**What NOT to change:** Frozen corpus labels, benchmark input selection based on expected outcomes, scan prefilters into CVE closure authority.

- [ ] Step 1: Add `TestRequestedFindingConsumers` and `TestOutcomeAccounting`.
- [ ] Step 2: Run:
  ```sh
  go test ./cmd/izyan ./internal/eval ./internal/eval/vexbench -run '^Test(RequestedFindingConsumers|OutcomeAccounting|VexVerdict)$' -count=1
  ```
  Expected initial failure: primary-result extraction and old abstention accounting.
- [ ] Step 3: Migrate all consumer callsites and shared configuration.
- [ ] Step 4: Run the same command; expect PASS.
- [ ] Step 5: Assert failed output has no `verdict:` line, external output names the fact, and composed remediation targets gRPC.

**Acceptance:** Public commands and scoring consume the same admitted requested answer as reports/exports.

### Task 10: Extend research publication without weakening record-bound decisions

**Depends on:** Tasks 2, 6–9  
**Ownership:** Research contract/replay owner.

**Files:**
- Create: `internal/research/requested_finding.go`
- Create: `internal/research/requested_finding_test.go`
- Modify: `internal/research/deterministic.go`
- Modify: `internal/research/types.go`
- Modify: `internal/research/assemble.go`
- Modify: `internal/research/validate.go`
- Modify: `internal/research/decision.go`
- Modify: `internal/research/slice2.go`
- Modify: `cmd/izyan/research.go`
- Test: `internal/research/advisory_feed_test.go`
- Test: `internal/research/decision_test.go`
- Test: `cmd/izyan/research_decision_test.go`
- Test: `cmd/izyan/research_feed_test.go`

**Interfaces:**

```go
const ReportSchemaV4 = "research-report/4"
```

Add:
```go
RequestComposition *domain.RequestedFinding `json:"request_composition,omitempty"`
```
to `research.Report`, and the corresponding member to `AssembleInput`.

Add to `LaneOptions` the shared corpus/capture options and a record-only execution mode; add discovery/independent assessments/request composition to `LaneResult`.

Add an adapter:

```go
func ProjectRequestedFinding(
    lane *LaneResult,
    primary *domain.AnalysisCase,
    related []domain.RelatedRecordAssessment,
) (domain.RequestedFinding, error)
```

It constructs the same admissible record/request representation and delegates to `finding.Project`; it does not implement different composition rules.

**Required behavior:**
- Exact primary and candidate intake bypasses `completeAdvisoryImports`/alias subject-merging.
- Record-specific agent proposals and observations remain attached to their record/session.
- Research failures receive typed causes at their producers, including failed observation acquisition, missing proof sidecars, unsupported verification and exhausted bounds.
- New `/4` output requires final request composition.
- Older report schemas do not silently acquire the new authority.
- Keep `decision-artifact/1` advisory binding record-bound.
- Do not mark an old `product_applicability` block `CVE_WIDE/COMPLETE` from corpus enumeration.
- Addendum A authority appears only in request composition’s corpus basis.
- Replay re-admits discovery pins, material captures, child proofs and attribution before publication.
- Deterministic and decision-ready lanes report the same failure/external distinction.

**What NOT to change:** Existing decision-artifact proof gates, closed-schema parsing into permissive parsing, or research observations into cross-record facts.

- [ ] Step 1: Add `TestResearchRequestComposition` and `TestResearchOutcomeClassification`.
- [ ] Step 2: Run:
  ```sh
  go test ./internal/research ./cmd/izyan -run '^Test(ResearchRequestComposition|ResearchOutcomeClassification|Research_Corpus|Research_Attribution)' -count=1
  ```
  Expected initial failure: `/4` and shared composition unavailable.
- [ ] Step 3: Implement the adapters, schema validation and replay/publication changes.
- [ ] Step 4: Run the same command; expect PASS.
- [ ] Step 5: Re-run existing focused decision-artifact/scope controls, ensuring corpus authority does not enter record-bound fields.

**Acceptance:** Research exposes the same requested answer without repurposing its existing advisory-binding or negative-proof authority.

### Task 11: Add the worked-case regression, calibrate and synchronize policy documentation

**Depends on:** Tasks 1–10  
**Ownership:** Integration/calibration/documentation owner.

**Files:**
- Create: `internal/states/definitive_verdict_integration_test.go`
- Create: `cmd/izyan/definitive_verdict_calibration_test.go`
- Modify: `internal/states/scope_version_integration_test.go`
- Modify: `cmd/izyan/scope_version_calibration_test.go`
- Modify: `cmd/izyan/target_provenance_calibration_test.go`
- Reuse unchanged: `eval/agent7/advisories/k8s-44487.json`
- Reuse unchanged: `eval/advisories/reviewed/GO-2023-2153.json`
- Reuse unchanged: `internal/states/testdata/k8s-44487-modules.jsonl`
- Create: `internal/states/testdata/definitive-verdict/corpus-manifest.json`
- Create: `internal/states/testdata/definitive-verdict/grpc-publisher-advisory.html`
- Create: `internal/states/testdata/definitive-verdict/grpc-handler-quota.patch`
- Create: `internal/states/testdata/definitive-verdict/source-manifest.json`
- Modify: `docs/dev/specs/governing-spec.md`
- Modify: `AGENTS.md`
- Modify: `docs/agent-rules/architecture.md`
- Modify: `docs/architecture.md`
- Modify: `docs/how-it-works.md`
- Modify: `docs/cli.md`
- Modify: `docs/dev/gap-analysis.md`
- Modify: `docs/dev/analysis-internals.md`
- Modify: `docs/dev/implementation-status.md`
- Modify: `eval/README.md`
- Create: `docs/dev/reports/2026-10-26-definitive-verdict-calibration.md`

**Interfaces:** No new production API. Consume the frozen contracts and full pipeline.

**Hermetic regression:**
- Preserve the existing actual 22-entry primary document and its digest.
- Preserve x/net `v0.17.0`, `VersionAffected=FALSE`, census **22/1/21**, `GO_PROJECTION`, `KNOWN_ONLY`.
- Load the independent GO record through declared sources, not ambient `eval` lookup.
- Test gRPC interval boundaries:
  ```text
  v1.55.0 affected
  v1.56.3 fixed
  v1.57.0 affected
  v1.57.1 fixed
  v1.58.0 affected
  v1.58.3 fixed
  ```
- Use actual captured publisher/fix bytes with provenance and hashes. Do not manufacture publisher quotations.
- Add a synthetic complete product proof through the real pipeline; label it synthetic rather than a Kubernetes measurement.
- Test positive publication, exact-GHSA non-substitution, corpus closure and all negative admission controls.

**Real worked-case acceptance:**

`TestDefinitiveVerdictCalibration` must run the actual source snapshot:

```text
task:   kubernetes-kubernetes-e196d24-CVE-2023-44487
commit: e196d2491087e93bd29f0e5a538aab60667021e3
```

Assert:
- requested `CVE-2023-44487`;
- `DECIDED / EXPLOITABLE`;
- actual profile `zero_trust`;
- `exploitability_scope=transport-peer`;
- `control_basis=transport-peer-input`;
- proof origin `GO-2023-2153`;
- gRPC `v1.55.0`, x/net `v0.17.0`;
- publisher attribution bound to `GHSA-m425-mq94-257g` and fix PR 6703;
- rooted path through:
  ```text
  cmd/kubelet/app/server.go:1253
  → pkg/kubelet/kubelet.go:2907–2922
  → pkg/kubelet/server/server.go:222–236
  → vendored grpc Server.Serve/transport path
  ```
- admitted Rapid Reset lifecycle witness;
- no primary census/range mutation;
- distinct unresolved deployment socket-access question;
- exact broad GHSA request remains its own scope-capability failure, not a substituted gRPC result.

Missing real snapshot/capture/tool prerequisites must be named. A skipped calibration is not completion of this acceptance criterion.

**Calibration controls:**
- Preserve Testify library-API positive and all library non-admission near misses.
- Preserve Cilium’s explicit `linux/amd64` positive; missing target information remains external where decision-changing.
- Exact-record constant-input and unreachable-locus negatives still require complete scope and verification.
- Stdlib release-toolchain uncertainty remains legitimately external.
- Reachability/loader/root-cause/timeout failures become failures unless completed proof decides them.
- CVE safe-label cases without declared completeness fail scope rather than becoming safe.
- Do not relabel the known Podman/Kubernetes false positives as successes.
- Record definitive correctness, external dependencies, analysis failures, false-safe and false-positive results separately.

**Documentation cutover:**
- Replace “tool failure/budget exhaustion is terminal INCONCLUSIVE” descriptions with the three-outcome contract.
- Explain that claims may remain `UNKNOWN` while the assessment is `FAILED`.
- Document discovery versus attribution, record isolation, requested finding, corpus completeness and boundary text.
- Document transport-peer scope and local≠trusted behavior.
- Update CLI configuration, failure exit behavior, output schema and evaluation accounting.
- Remove only actually closed entries from gap-analysis §2; preserve unrelated backlog.
- Do not rewrite historical calibration tables or the old saved run into a positive.

- [ ] Step 1: Add `TestDefinitiveVerdictIntegration` with composed positive, exact request, tamper, no-trigger and corpus-boundary controls.
- [ ] Step 2: Run:
  ```sh
  go test ./internal/states ./cmd/izyan -run '^Test(DefinitiveVerdictIntegration|DefinitiveVerdictConsumers)$' -count=1
  ```
  Expected initial failure: end-to-end acceptance not yet met.
- [ ] Step 3: Complete integration fixtures and update changed old-policy assertions without weakening their safety assertions.
- [ ] Step 4: Run the same command; expect PASS.
- [ ] Step 5: With the documented external assets configured, run:
  ```sh
  go test ./cmd/izyan -run '^TestDefinitiveVerdictCalibration$' -count=1 -v
  ```
  Expect the actual worked-case result above and a retained claim-level ledger.
- [ ] Step 6: Write the new measured calibration report and synchronize the listed documentation.

**Acceptance:** The actual worked case earns the specified positive through gRPC, safety controls remain intact, and documentation describes the implemented policy rather than the superseded abstention policy.

## Dependency / Execution Order

```text
Task 1
  → Task 2
  → Task 3
  → Task 4
  → Task 6
  → Task 7
  → Task 8
  → Task 9
  → Task 10
  → Task 11

Task 1 → Task 5 → Task 6
```

Task 5’s outcome/perimeter implementation can proceed independently of Task 2’s acquisition work after Task 1. Its `states.go` changes must be integrated in the serialization order below.

Task 7 and Task 8 must land before public consumers begin publishing the new schema. New fields alone are not the feature cutover.

## Shared-File Serialization and Ownership

| Shared file/surface | Integration order |
|---|---|
| `internal/domain/domain.go` | Task 1 schema → Task 6 workflow constants; other owners use dedicated domain files |
| `internal/states/states.go` | Task 3 measurement projection → Task 4 transport collection → Task 5 outcome/profile/perimeter → Task 6 continuation/composition |
| `internal/evaluator/verdict.go` | Task 4 transport admission/scope → Task 5 typed diagnostic result; preserve one evaluator |
| `internal/workflow/engine.go` | Task 5 failure continuation → Task 6 record stop boundary |
| `cmd/izyan/main.go` | Task 6 handler extraction/orchestration → Task 9 public/config cutover |
| `internal/report/report.go` | Task 8 exclusively; later consumers call its public APIs |
| `internal/research/deterministic.go` | Task 10 exclusively after upstream APIs freeze |
| Research schema files | Task 10 changes `types.go`, `assemble.go`, `validate.go` and publication callers together |
| Calibration tests/docs | Task 11 after production interfaces and public output settle |

Do not run shared-worktree checks while these owners are editing overlapping files. Each task’s focused validation is run against its integrated deliverable. The integration owner performs final branch-wide validation once after all tasks land.

## Final Integrated Validation

After task-focused checks and documentation synchronization, the integration owner runs:

```sh
go vet ./...
go test ./...
```

Then run each complete corpus **once**, following repository policy:

```sh
go run ./cmd/izyan eval --corpus eval/corpus-real.json -j 4
VA_PRODUCT_REPO="$VA_PRODUCT_REPO" go run ./cmd/izyan eval --corpus eval/live-corpus.json
```

Retain:
- requested-finding outcome/verdict ledgers;
- `false-safe=0` results for the repository’s analyzer corpora;
- false-positive accounting;
- the separately exercised real worked-case calibration;
- any exact missing prerequisite or failed check.

Do not report a skipped real calibration, moved failure count, or reduced `INCONCLUSIVE` count as increased successful completion.

## Explicit Non-Inferences

The completed feature must **not** make any of these inferable:

- “The analyzer must decide” ⇒ force a verdict.
- `UNKNOWN`, timeout, missing proof, absent tool findings ⇒ safe.
- Same alias/CVE/related component ⇒ shared ranges, claims, coverage or remediation.
- Related record positive ⇒ CVE positive without admitted attribution.
- Partial witnesses across records/profiles/builds ⇒ one exploit conjunction.
- Finished undeclared discovery ⇒ CVE completeness.
- Declared corpus completeness ⇒ proof outside that corpus.
- Child NEPF ⇒ CVE `NOT_AFFECTED`.
- Unix/loopback/ClusterIP ⇒ trusted peers.
- Transport-peer positive ⇒ arbitrary Internet access.
- No exposure facts ⇒ no external exposure.
- Saved composed result ⇒ publication authority without re-admission.
- Reclassifying unfinished work as `FAILED` ⇒ improved correctness or completion.

**Planning result:** Execution-ready, read-only handoff. No implementation, repository writes, tests, builds, linters, formatters or analyzer reruns were performed.

# План: config-trust и target-scope замыкание (03/04)

**Статус:** APPROVED DESIGN (owner facts: админ-конфиг вне модели угроз; продукт только Linux) — исполнимый план, код не изменялся.
**Источник:** delegated `architect` artifacts `agent://ConfigAndPlatformFacts` (дизайн) и `agent://ConfigPlatformPlan` (план), сохранены дословно.
**Измерения:** `va-tmp/r6-final/art-1103/case-0{3,4}-tag/report.json`; сниппет-артефакт `va-tmp/am-1.10.3/package/bh/demo-product`; снапшот тега `va-tmp/demo-product-1.1.1-2397`.
**Дерево:** `785f407`.

---

# Configuration-Trust and Target-Scoped Implementation Closure Plan

**Goal:** Add a typed assumptions channel and two generic deterministic proof routes so the measured case-03 and case-04 inputs can close as `NO_EXPLOIT_PATH_FOUND` and `NOT_AFFECTED` without weakening provenance, coverage, identity, or platform-scope invariants.

**Architecture:** Keep code facts in the existing evidence/provenance graph; carry human-owned trust and product-scope assertions through `declared-assumptions/1`; treat LLM implementation loci as proposals only; use a post-reach exact-argument falsifier for G1 and a new affected-chain “vulnerable implementation present” dimension for G2.

**Tech stack:** Go, `go/packages`, `go/build.Context`, existing `internal/goanalysis`, `internal/evaluator`, `internal/affected`, `internal/research`, JSON report contracts, focused Go tests, corpus/census harnesses.

**Spec:** `agent://ConfigAndPlatformFacts`  
**Repository context:** `docs/dev/plans/2026-10-19-05-inconclusive-closure-plan.md`, `docs/dev/reports/2026-10-19-04-inconclusive-reduction-analysis.md`

## Global Constraints

- Owner facts are explicit inputs only:
  - administrator-managed configuration is outside the attacker model;
  - the product-wide supported target scope is Linux.
- Never infer either fact from:
  - a `mapstructure`/`env` tag;
  - `EvidenceKind.CONFIGURATION`;
  - `--trusted-peer`;
  - the analyzer host OS;
  - a single artifact unless its scope is explicitly artifact-only.
- `DataFlow.Origin=CONFIGURATION` remains a deterministic provenance fact. It is not the policy assertion that administrators are trusted.
- The administrator-trust and supported-target assertions MUST be represented only in `declared-assumptions/1`; they MUST NOT be placed in `--release-metadata`, `EvidenceKind.CONFIGURATION`, or host defaults.
- Every assumption has an explicit id, statement, scope, authority/owner, source reference, digest, and validity/review date. Missing, malformed, expired, digest-mismatched, or scope-mismatched assumptions fail closed to `INCONCLUSIVE`.
- LLM output MAY propose implementation loci, but MUST NOT directly produce `NOT_AFFECTED`, `NO_EXPLOIT_PATH_FOUND`, `ClaimFalse`, `NegativeVerification=VERIFIED`, or an affected-chain FALSE.
- `BuildRelevant` retains its existing meaning: advisory/package platform restriction. Do not reuse it for file/function implementation presence.
- G1 is only a `NO_EXPLOIT_PATH_FOUND` route. It MUST NOT produce `NOT_AFFECTED`.
- G2 is an affected-chain decision. A verified absent vulnerable implementation produces `NOT_AFFECTED`; it MUST NOT be represented as a trusted-input falsifier.
- No case-specific module, package, symbol, advisory, marker, or ticket rule. Case identifiers may appear only in fixtures, external paths, and final re-measurement commands.
- All bounds remain explicit in evidence and reports: trace hops, sink/ingress closure scope, package/load budgets, proposal size, assumption document size, artifact nesting, target matrix, and verifier scan scope.
- The existing artifact safety limit remains in force: `maxArtifactNesting=4`; the measured top-level archive rejection remains a named limitation and MUST NOT be bypassed by raising the bound.

### Rejected shortcuts

| Rejected shortcut | Required invariant |
|---|---|
| Any value in a configuration-tagged field is safe | Tags classify likely configuration decoding; they do not prove complete ownership. |
| A `mapstructure` tag closes the case | Tag-only evidence cannot exclude external writes, aliases, reflection, or callbacks. |
| Configuration plus message-derived data remains configuration | `mergeOrigin` preserves the most attacker-influencing origin; external wins. |
| Evaluate config provenance without positive sink reach | Absence of a proven path is not proof of absence. |
| Ignore `symbol-unreachability=UNKNOWN` globally | Unknown call-graph coverage can hide alternate sinks. |
| One traced sink covers every advisory sink | Argument-bound falsifiers require complete advisory sink coverage. |
| The LLM says the implementation is BSD-only, therefore Linux is safe | LLM proposals require deterministic source/build verification. |
| Package use proves the vulnerable implementation is used | Package presence and implementation presence are separate facts. |
| One Linux artifact proves the product is Linux-only | Artifact scope is not product-wide scope. |
| Reuse `BuildRelevant=FALSE` for an excluded file | The package may still be linked; implementation presence is a distinct axis. |
| Use `NO_EXPLOIT_PATH_FOUND` for an excluded implementation | Deterministic applicability absence is `NOT_AFFECTED`. |
| Use `NOT_AFFECTED` for symbol unreachability | Reachability falsifiers remain no-exploit-path conclusions. |
| Use the host OS or `go.mod` as the release target | Target facts must come from artifact/release evidence or explicit declared scope. |
| Treat an empty enumeration as closed | Empty results after failed or partial loading remain unknown. |
| Treat an artifact-only target declaration as product-wide | Scope must match the claim being made. |

## Review Focus

| Mechanism | Required negative control |
|---|---|
| Assumption admission | Expired, malformed, digest-mismatched, wrong-owner, or wrong-scope assumptions remain inadmissible. |
| Configuration provenance | An external write to the config field blocks the falsifier. |
| Alias/reflection handling | An unresolved alias, address-taken field, reflection write, or unmodeled callback blocks closure. |
| Exact argument binding | A wrong `ArgIndex`, receiver binding, or sink site remains unresolved. |
| Positive reach route | No exact positive vulnerable-sink reach means no post-reach closure. |
| Sink coverage | One known sink with an unresolved advisory sink remains `INCONCLUSIVE`. |
| Implementation proposal | Wrong module/version/file/function/marker/build expression or advisory span fails closed. |
| Build selection | An alternate selected implementation containing the marker blocks absence. |
| Target scope | Artifact-only Linux evidence cannot satisfy a product-wide target assumption. |
| Verdict separation | G1 can only produce `NO_EXPLOIT_PATH_FOUND`; G2 implementation absence can only enter the affected chain. |

### Task 1: Add the `declared-assumptions/1` Channel

**Depends on:** None

**Files:**

- Create: `internal/domain/assumptions.go`
- Modify: `internal/domain/domain.go`
  - `AnalysisCase`
  - `Claim`
  - `AffectedResult`
  - `VerdictResult`
- Create: `internal/repository/assumptions.go`
- Test: `internal/domain/assumptions_test.go`
- Test: `internal/repository/assumptions_test.go`
- Modify: `cmd/izyan/research.go`
  - `researchOpts`
  - `researchFlags`
  - `runResearch`
- Modify: `cmd/izyan/main.go`
  - `analyzeOpts`
  - shared flags/snapshot wiring
- Modify: `internal/research/deterministic.go`
  - `LaneOptions`
  - deterministic session setup
- Modify: `internal/research/types.go`
  - `InputInfo`
  - `SnapshotInput` or a dedicated assumptions projection
  - `Report`
  - `EvidenceDecision`
- Modify: `internal/research/assemble.go`, `render.go`, `validate.go`, `replay.go`
- Modify: `internal/report/report.go`, `openvex.go`
- Test: `internal/research/assumptions_test.go`
- Test: `internal/report/assumptions_test.go`
- Test: `cmd/izyan/research_test.go`

**Interfaces:**

```go
const DeclaredAssumptionsSchema = "declared-assumptions/1"

type DeclaredAssumptionKind string

const (
    AssumptionConfigTrust     DeclaredAssumptionKind = "config-trust"
    AssumptionSupportedTargets DeclaredAssumptionKind = "supported-targets"
)

type DeclaredAssumption struct {
    ID         string                 `json:"id"`
    Kind       DeclaredAssumptionKind `json:"kind"`
    Statement  string                 `json:"statement"`
    Scope      string                 `json:"scope"`
    Authority  string                 `json:"authority"`
    Owner      string                 `json:"owner"`
    SourceRef  string                 `json:"source_ref"`
    Digest     string                 `json:"digest"`
    ValidFrom  string                 `json:"valid_from,omitempty"`
    ReviewDate string                 `json:"review_date"`
    Targets    *ProductTargetScope    `json:"targets,omitempty"`
}

type DeclaredAssumptionsDocument struct {
    Schema        string               `json:"schema"`
    ContentDigest string               `json:"content_digest"`
    Assumptions   []DeclaredAssumption `json:"assumptions"`
}
```

- `repository.LoadDeclaredAssumptions(path)` reads the exact file bytes, computes `ContentDigest`, rejects unknown fields, duplicate ids, invalid dates, invalid digests, unsupported kinds, empty required fields, and target/scope inconsistencies.
- Add an admission helper such as:
  `AdmitAssumption(doc, kind, requiredScope, now) (DeclaredAssumption, error)`.
- Add `AssumptionIDs []string` to `domain.Claim`, `domain.AffectedResult`, `domain.VerdictResult`, and `research.EvidenceDecision`. These are policy references, not evidence ids.
- Add an optional `DeclaredAssumptions` projection under `research.InputInfo`; preserve legacy reports when no document was supplied.
- Add a dedicated rendered section/paragraph:
  `Declared assumptions — policy/scope inputs, not deterministic evidence`.
- Do not add assumptions to `EvidenceGraph.Evidence`, `EvidenceKind`, `VerifiedFacts`, or `EvidenceIDs`.
- Add `--declared-assumptions <path>` to `research`; wire the same document into the legacy analyzer path if that path can emit the affected/verdict result.
- Record only sanitized path, document digest, schema, ids, and admission status in manifests/observations. Never copy secret-bearing source content into reports.

- [ ] Add parser/validator tests for valid config-trust and supported-target documents.
- [ ] Add failing tests for duplicate ids, unknown JSON fields, invalid digest, expired review date, missing owner, empty source reference, and artifact scope used for a product scope.
- [ ] Run:
  `go test -run 'TestDeclaredAssumptions|TestAssumptionAdmission' ./internal/domain ./internal/repository ./internal/research ./internal/report ./cmd/izyan`
  and confirm the new behavior is not yet present.
- [ ] Implement typed loading, digest pinning, admission, and CLI propagation.
- [ ] Add report validation that assumption ids resolve to the admitted document and never resolve through `EvidenceIDs`.
- [ ] Add report assertions that:
  - assumptions appear in their own section;
  - deterministic source/configuration evidence remains under evidence/data-flow sections;
  - verdicts cite assumption ids separately from evidence ids;
  - no assumption is promoted to `EvidenceKind.CONFIGURATION`.
- [ ] Add negative tests proving:
  - missing admin-config-trust leaves G1 inadmissible;
  - missing product-wide target scope leaves G2 product applicability unknown;
  - artifact-only target scope cannot satisfy a product-wide assumption;
  - `--trusted-peer` does not substitute for `AssumptionConfigTrust`.

**Acceptance:** A valid, digest-pinned `declared-assumptions/1` document is available to the analyzer and report, while assumptions remain visibly and semantically distinct from deterministic evidence.

**Unblocks:** All G1/G2 policy gates and their report/verdict references.

### Task 2: Implement G1 Exact-Argument Post-Reach Configuration Closure

**Depends on:** Task 1

**Files:**

- Modify: `internal/states/states.go`
  - `CollectEvidence`
  - `CheckAffected`
- Modify: `internal/states/evidence.go`
  - generalized provenance collection
- Modify: `internal/goanalysis/provenance.go`
  - `TraceArgument`
  - `TraceArgumentBound`
  - `fieldOrigin`
  - `mergeOrigin`
- Modify: `internal/goanalysis/sinkclosure.go`
  - sink-set basis and exact live-site records
- Modify: `internal/goanalysis/ingress.go`
  - unresolved/alias/reflection blockers
- Modify: `internal/goanalysis/negative.go`
  - `verifyInputFalse`
  - `verifySinkClosure`
  - `verifyIngress`
- Modify: `internal/evaluator/provenance.go`
  - `ArgumentOrigin.Evaluate`
  - `closureGate`
- Create or modify: `internal/evaluator/postreach.go`
- Test: `internal/goanalysis/config_test.go`
- Test: `internal/goanalysis/source_test.go`
- Test: `internal/goanalysis/sinkclosure_test.go`
- Test: `internal/goanalysis/ingress_test.go`
- Test: `internal/evaluator/provenance_test.go`
- Test: `internal/evaluator/postreach_test.go`
- Fixtures: generic config-origin, external-write, alias-write, reflection-write, mixed-source, and multi-sink products.

**Interfaces:**

- Keep the mandatory condition attacker-oriented:
  `ConditionKind=ATTACKER_CONTROL` with an exact nonnegative `ArgIndex`.
- Add a post-reach evaluator contract that requires all of:

```text
affected applicability is TRUE
+ exact vulnerable sink has positive reach
+ exact trigger argument is bound by ArgIndex
+ every relevant live sink site is covered
+ every covered argument traces to OriginConfiguration
+ an admissible AssumptionConfigTrust is present
=> ClaimFalse / FalsifierTrustedInfrastructure
```

- Positive reach MUST be sink-specific. Accept only:
  - an exact matching `CallPath`;
  - an exact `ModuleReachable` chain;
  - or a live `SinkSite` in a complete, advisory-bound sink closure.
  Module/package usage alone is insufficient.
- For every live `SinkSite`, require `SinkSite.Sink`, `SinkSite.Arg`, file, line, and function to match the exact condition subject and `ArgIndex`.
- Reuse `TraceArgumentBound` for the exact site/argument. Persist each resulting `DataFlow` with:
  `ConditionID`, `Sink`, `Arg`, `Origin`, `Source`, transformations, and summary.
- Mark the sink closure with a nonempty advisory-bound basis only when the declared subject set is complete. Advisory membership alone MUST NOT authorize a complete closure.
- Preserve `mergeOrigin` ordering so external/authenticated/database/internal-service/unknown origins outrank configuration.
- Tag-only fallback may return `CONFIGURATION` only when no observed external or unresolved write exists. It MUST be suppressed by:
  - an external assignment;
  - an unresolved assignment;
  - address-taken field state;
  - reflection/dynamic write markers;
  - unmodeled callback or function-value escape.
- Do not let `IngressClosure` or `SinkClosure` convert unresolved origins into configuration. Incomplete closure means `NegativeInsufficientScope`.

- [ ] Add a fixture where `cfg.Expression` is `mapstructure`-tagged and reaches the exact vulnerable argument; assert exact `ArgIndex` and `OriginConfiguration`.
- [ ] Add a fixture where the same field is later assigned from external input; assert `OriginExternalUntrusted` and no config falsifier.
- [ ] Add an unresolved pointer alias/reflection write fixture; assert `OriginUnknown` and no closure.
- [ ] Add a wrong-argument test where `doc` is configuration-derived but `expression` is external; assert the exact trigger remains external.
- [ ] Add a positive-reach-negative test with only package/module usage; assert `INCONCLUSIVE`.
- [ ] Add a multi-sink test where one sink is configuration-derived and another is unresolved/external; assert no verified falsifier.
- [ ] Add an assumption-admission test proving configuration origin without `AssumptionConfigTrust` remains `INCONCLUSIVE`.
- [ ] Run focused Go tests and inspect the resulting `DataFlow`, `SinkClosure`, and `IngressClosure` records.
- [ ] Implement the post-reach route without changing the existing constant/generated-input route.

**Acceptance:** Case-independent fixtures can close only when the exact vulnerable sink is positively reached, the exact trigger argument is proven configuration-derived, all declared sinks are covered, and the administrator-trust assumption is admissible.

**Unblocks:** The case-03 `NO_EXPLOIT_PATH_FOUND` route.

### Task 3: Wire G1 Falsifier, Coverage, and Verdict Semantics

**Depends on:** Task 2

**Files:**

- Modify: `internal/evaluator/verdict.go`
  - `VerdictEvaluator.Evaluate`
  - `coversAllDeclared`
  - add a configuration-coverage helper if needed
- Modify: `internal/evaluator/provenance.go`
- Modify: `internal/domain/domain.go`
  - `Claim`
  - `VerdictResult`
  - `NegativeVerification`
- Modify: `internal/report/openvex.go`
- Modify: `internal/report/report.go`
- Modify: `internal/research/decision.go`
- Modify: `internal/research/assemble.go`
- Modify: `internal/research/render.go`
- Test: `internal/evaluator/verdict_test.go`
- Test: `internal/evaluator/provenance_test.go`
- Test: `internal/report/openvex_test.go`
- Test: `internal/research/decision_test.go`
- Test: `internal/research/assemble_test.go`

**Interfaces:**

- The G1 claim uses:
  - `Result=ClaimFalse`;
  - `Falsifier=FalsifierTrustedInfrastructure`;
  - `FalsifierBasis=BasisConfigOrigin`;
  - `NegativeVerification.Status=NegativeVerified`;
  - `AssumptionIDs` containing the admitted config-trust id.
- `VerdictEvaluator` returns:
  - `NO_EXPLOIT_PATH_FOUND`;
  - `GroundBasis=BasisConfigOrigin`;
  - the claim’s `ConditionIDs`, `EvidenceIDs`, and `AssumptionIDs`.
- A configuration-origin falsifier MUST NOT become globally coverage-complete merely because it has an assumption. When `UnresolvedSubjects` is nonempty, the new coverage helper must prove that every unresolved subject belongs to the exact sink set covered by the verified sink closure. Otherwise retain `INCONCLUSIVE`.
- Preserve the existing `coversAllDeclared` behavior for non-configuration falsifiers.
- Report projections must state separately:
  - deterministic evidence: exact data-flow/sink/ingress records;
  - policy assumption: administrator-managed configuration is outside the attacker model;
  - verdict basis: `FalsifierTrustedInfrastructure`, `BasisConfigOrigin`.
- The assumption is a prerequisite for the verdict, not a replacement for evidence.

- [ ] Add a verdict test for positive exact reach + complete config-origin sink closure + valid assumption -> `NO_EXPLOIT_PATH_FOUND`.
- [ ] Add a test for the same claim with an unresolved advisory sink -> `INCONCLUSIVE`.
- [ ] Add a test for an external write despite a valid assumption -> `INCONCLUSIVE` or contradicted, never `NO_EXPLOIT_PATH_FOUND`.
- [ ] Add a test proving the route never returns `NOT_AFFECTED`.
- [ ] Add a test proving assumption ids and evidence ids serialize in separate fields.
- [ ] Add an OpenVEX/report test showing the trust-grounded justification without mislabeling the assumption as code evidence.
- [ ] Run:
  `go test -run 'TestVerdict|TestArgumentOrigin|TestOpenVEX|TestAssumption' ./internal/evaluator ./internal/report ./internal/research`
  and verify all negative controls.

**Acceptance:** The G1 route produces only the named no-exploit verdict with complete sink coverage, exact argument evidence, and a separately identified policy assumption.

**Unblocks:** End-to-end case-03 evaluation and report acceptance.

### Task 4: Add the Typed LLM Implementation-Locus Proposal and Deterministic Verifier

**Depends on:** Task 1

**Files:**

- Create: `internal/domain/implementation.go`
- Modify: `internal/research/agent.go`
  - `agentAnswer`
  - strict extraction/schema checks
- Modify: `internal/research/types.go`
  - proposal/report types
- Modify: `internal/research/assemble.go`
  - proposal projection
- Modify: `internal/research/render.go`
  - proposal audit rendering
- Modify: `internal/research/validate.go`
- Modify: `eval/agent7/prompts/r0-v4.txt` or the current pinned prompt selected by `resolveResearchPrompt`
- Create: `internal/affected/implementation.go`
- Modify: `internal/affected/vendorclosure.go`
  - share the recorded `go/build.Context` construction
- Test: `internal/affected/implementation_test.go`
- Test: `internal/research/implementation_locus_test.go`
- Test: `internal/research/agent_test.go`
- Test: `internal/research/validate_test.go`
- Fixtures: generic package with BSD/Linux implementations and marker-bearing alternates.

**Interfaces:**

```go
type ImplementationLocusProposal struct {
    ID                    string                 `json:"id"`
    Quality               domain.EvidenceQuality `json:"quality"`
    Module                string                 `json:"module"`
    Version               string                 `json:"version"`
    Package               string                 `json:"package"`
    File                  string                 `json:"file"`
    Function              string                 `json:"function"`
    Marker                string                 `json:"marker"`
    BuildExpression       string                 `json:"build_expression"`
    GOOS                  []string               `json:"goos,omitempty"`
    GOARCH                []string               `json:"goarch,omitempty"`
    AdvisoryEvidenceRef   string                 `json:"advisory_evidence_ref"`
    AdvisoryQuotedSpan    string                 `json:"advisory_quoted_span"`
}
```

- The proposal MUST carry `QualityLLMInferred`.
- The advisory reference MUST resolve to the frozen advisory input/digest.
- The quoted span MUST be an exact substring of the frozen advisory bytes; a paraphrase or source-only citation is invalid.
- Proposal parsing MUST reject verdict/claim/negative-verification fields.
- Add `ImplementationLocusProposals []ImplementationLocusProposal` as an explicitly non-authoritative report member.
- The deterministic verifier must:
  1. match module and version to the selected affected entry and resolved version;
  2. verify the snapshot/source identity and content hash;
  3. normalize and confine the proposed package/file path;
  4. verify the file exists under the expected module/package;
  5. locate the proposed function/method in the AST;
  6. verify the marker occurs in the proposed function/body;
  7. parse/compare the proposed build expression with the file’s actual build constraint;
  8. evaluate the file using the same `go/build.Context` as analysis;
  9. scan every alternate implementation file selected by that context for the marker;
  10. require advisory applicability (`ModulePresent`, `VersionAffected`, `PackagePresent`, and applicable build facts) before returning `FALSE`.
- Any failed deterministic check returns `ClaimUnknown`/verification failure, never absence.

- [ ] Add a valid proposal fixture with advisory quote, BSD file, `kenv` marker, and build expression.
- [ ] Add wrong-module, wrong-version, wrong-file, wrong-function, absent-marker, wrong-build-expression, malformed-quote, and wrong-advisory-reference tests.
- [ ] Add a proposal-quality test: `QualityDeterministic` or missing quality cannot be admitted as an LLM proposal.
- [ ] Add a build fixture where the vulnerable file is excluded for Linux and no selected alternate contains the marker -> implementation absence candidate.
- [ ] Add the required negative control where a selected alternate Linux implementation carries the marker -> verifier must remain unknown/present and never return absent.
- [ ] Add a source identity/digest mismatch test.
- [ ] Run focused `internal/affected` and `internal/research` tests before integrating the verdict axis.
- [ ] Ensure the verifier records deterministic source/build evidence with artifact/source hashes, while the proposal remains separately labeled LLM-inferred.

**Acceptance:** A wrong or incomplete LLM locus fails closed; only a correctly quoted, identity-bound proposal whose file/function/marker/build behavior is deterministically verified can feed the implementation-presence axis.

**Unblocks:** Case-04 implementation absence determination.

### Task 5: Bind Artifact/Release Targets and Add the Affected-Chain Dimension

**Depends on:** Tasks 1 and 4

**Files:**

- Create or modify: `internal/domain/target.go`
- Modify: `internal/domain/domain.go`
  - `ProductSnapshot`
  - `AffectedResult`
- Modify: `internal/repository/artifact.go`
  - `artifactCandidate`
  - `inspectCandidates`
  - build-info settings extraction
- Modify: `internal/repository/releasemetadata.go`
  - only release build-target facts, never product policy/supported-target assertions
- Modify: `internal/repository/service.go`
  - target precedence
- Modify: `internal/affected/resolver.go`
  - new implementation axis initialization/propagation
- Modify: `internal/states/states.go`
  - `CheckAffected`
  - implementation verification integration after proposal admission
- Modify: `internal/evaluator/verdict.go`
- Modify: `cmd/izyan/main.go`
  - `deterministicallyNotAffected`
  - `notAffectedReason`
- Modify: `cmd/izyan/vexbench.go`
  - `vexDiscriminator`
- Modify: `internal/research/types.go`
  - `ProductApplicability`
- Modify: `internal/research/assemble.go`, `branch_evidence.go`, `slice2.go`, `render.go`, `validate.go`
- Modify: `configs/research/checks.yaml` if the decision-ready branch catalog requires a new applicability predicate
- Test: `internal/repository/artifact_test.go`
- Test: `internal/repository/service_test.go`
- Test: `internal/affected/resolver_test.go`
- Test: `internal/evaluator/verdict_test.go`
- Test: `cmd/izyan/scan_test.go`
- Test: `cmd/izyan/vexbench_test.go`
- Test: `internal/research/decision_test.go`
- Test: `internal/research/assemble_test.go`

**Interfaces:**

```go
type ProductTarget struct {
    GOOS             string   `json:"goos"`
    GOARCH           string   `json:"goarch"`
    BuildTags        []string `json:"build_tags,omitempty"`
    CGOEnabled       bool     `json:"cgo_enabled"`
    Source           string   `json:"source"` // artifact-build-info|release-metadata|operator-declared|host-default
    Scope            string   `json:"scope"`  // artifact|release|operator
    ArtifactSHA256   string   `json:"artifact_sha256,omitempty"`
    BuildInfoSHA256  string   `json:"build_info_sha256,omitempty"`
    BinaryMember     string   `json:"binary_member,omitempty"`
}
```

- Keep `ProductSnapshot.GOOS`, `GOARCH`, `BuildTags`, and `CGOEnabled` for compatibility, but add a typed target provenance/source.
- Resolve target precedence:
  1. artifact build-info settings bound to artifact SHA, binary member, and build-info digest;
  2. authoritative release target facts, if present;
  3. explicit operator target facts;
  4. host defaults only for ordinary analysis, never for a product-wide G2 conclusion.
- Extract `GOOS`, `GOARCH`, `CGO_ENABLED`, and build tags from `debug.BuildInfo.Settings` where available.
- Add:

```go
VulnerableImplementationPresent ClaimResult `json:"vulnerable_implementation_present"`
```

to `AffectedResult`. Its default is `ClaimUnknown`.
- Do not change `BuildRelevant`.
- `VerdictEvaluator` order becomes:

```text
module present
→ version affected
→ package present
→ build relevant
→ vulnerable implementation present
```

A `FALSE` implementation axis returns `NOT_AFFECTED` with a reason naming the verified locus and target scope.
- The implementation axis may be set FALSE only when:
  - applicability is established;
  - target facts are authoritative or an admissible declared target scope applies;
  - the proposal verifier returns deterministic absence;
  - all selected alternate implementations were scanned.
- Product-wide Linux-only scope requires an admitted `AssumptionSupportedTargets` with `Scope=product` or equivalent product/release scope. An artifact-only assumption cannot close the product-wide axis.
- Add assumption ids to the affected result/verdict so the target-scope policy is visible without becoming evidence.

- [ ] Add artifact build-info tests proving target settings are bound to artifact/build-info digests.
- [ ] Add precedence tests for conflicting artifact, release, operator, and host target values.
- [ ] Add a test proving host `runtime.GOOS` is never used as a product-wide implementation conclusion.
- [ ] Add affected-chain tests:
  - implementation FALSE -> `NOT_AFFECTED`;
  - implementation UNKNOWN -> `INCONCLUSIVE`;
  - package present/build relevant TRUE/implementation FALSE remains `NOT_AFFECTED`;
  - `BuildRelevant` remains unchanged and still means package/platform applicability.
- [ ] Add a product-wide-scope test where a Linux artifact plus product-wide Linux assumption closes the implementation axis.
- [ ] Add the required artifact-only negative control: artifact-scoped Linux evidence cannot produce a product-wide `NOT_AFFECTED`.
- [ ] Add alternate-selected-implementation integration test; marker presence blocks implementation absence.
- [ ] Update research applicability/report projections and decision-ready branch facts so the new axis is visible and validated.
- [ ] Run focused tests for repository, affected, evaluator, CLI, and research packages.

**Acceptance:** Case-04 can produce `NOT_AFFECTED` only through `VulnerableImplementationPresent=FALSE` under an authoritative/admissible target scope; `BuildRelevant` remains semantically unchanged.

**Unblocks:** End-to-end case-04 closure and correct report/VEX/census discrimination.

### Task 6: Integrate CLI/Harness, Report Validation, and Case Fixtures

**Depends on:** Tasks 1–5

**Files:**

- Modify: `cmd/izyan/research.go`
  - `researchOpts`
  - `researchFlags`
  - `LaneOptions` construction
  - `optionsManifest`
- Modify: `cmd/izyan/research_test.go`
- Modify: `internal/research/deterministic.go`
  - assumptions observation
  - implementation proposal/verifier dispatch
- Modify: `internal/research/agent.go`
  - proposal extraction/replay
- Modify: `internal/research/assemble.go`, `render.go`, `validate.go`, `replay.go`
- Modify: `internal/research/decision.go`
- Modify: `internal/report/report.go`, `openvex.go`
- Modify: `docs/dev/cli.md`
- Modify: `eval/README.md`
- Modify: `docs/dev/gap-analysis.md`
- Add generic fixtures under existing test fixture roots; do not add private corporate paths, ticket bodies, or artifacts.

**Interfaces:**

- `research` flags:
  - `--declared-assumptions <path>` — explicit `declared-assumptions/1`;
  - retain `--artifact`, `--artifact-url`, `--ticket`, `--goos`, `--goarch`, and `--build-tags`;
  - if a replayed LLM proposal is needed, accept it only through the retained agent/replay artifact path or a clearly typed proposal artifact whose provenance points to the retained LLM answer and advisory digest.
- Do not add an assumption flag to `--release-metadata`.
- The manifest records the assumptions file digest and proposal artifact digest, not their unbounded contents.
- Deterministic-only runs never invent proposals or assumptions. If the case-04 proposal artifact is absent, the result remains `INCONCLUSIVE`.
- Reports must validate:
  - assumption document digest and ids;
  - proposal quality and advisory quote/ref;
  - implementation axis evidence;
  - target provenance;
  - separate evidence/assumption references;
  - legacy reports without the optional members.
- Replay must preserve the original LLM proposal and its artifact digest; replay cannot upgrade proposal quality or alter its advisory quote.

- [ ] Add CLI flag registration and conflict/invalid-path tests.
- [ ] Add deterministic-only tests proving no LLM call and no proposal synthesis.
- [ ] Add replay tests proving a retained proposal is reused byte-for-byte and remains non-authoritative.
- [ ] Add report round-trip tests for assumptions, proposal, target provenance, implementation axis, verdict evidence refs, and assumption refs.
- [ ] Add generic end-to-end fixtures for:
  - G1 exact config trigger;
  - G1 external-write blocker;
  - G2 wrong locus;
  - G2 alternate selected marker;
  - G2 artifact-only scope blocker.
- [ ] Update CLI/report documentation to explain:
  - assumptions versus evidence;
  - product-wide versus artifact scope;
  - `BuildRelevant` versus implementation presence;
  - the two verdict routes.
- [ ] Run focused CLI/research/report tests.

**Acceptance:** The CLI and reports carry every required input and provenance boundary; a fresh implementer can reproduce both routes without hidden flags, case-specific behavior, or manual report edits.

**Unblocks:** Final tag-case execution and the corpus/census gates.

### Task 7: Final Verification and Re-Measurement

**Depends on:** Tasks 1–6

**Files:**

- No new production files.
- Update only measured documentation/results outside committed private artifact paths.
- Preserve external `va-tmp` inputs and report directories.

**Exact target-case setup:**

Use the already measured frozen advisory files:

```bash
export ADV03=eval/advisories/reviewed/GHSA-65xw-vw82-r86x.json
export ADV04=eval/advisories/reviewed/GHSA-hfvc-g4fc-pqhx.json

export SNAPSHOT=va-tmp/demo-product-1.1.1-2397
export ARTIFACT=va-tmp/am-1.10.3/package/bh/demo-product
export ASSUMPTIONS=va-tmp/r6-final/declared-assumptions/AM-1.10.3.json
export TICKET03=va-tmp/r6-final/tickets/CASE-227168.json
export TICKET04=va-tmp/r6-final/tickets/CASE-238323.json
```

`ASSUMPTIONS` MUST be the owner-supplied `declared-assumptions/1` document containing:

- administrator-managed configuration outside the attacker model;
- product-wide supported targets restricted to Linux.

The case-04 implementation-locus proposal MUST be a retained LLM proposal with the advisory evidence reference and exact quoted span; it MUST NOT be hand-authored as a case rule.

Run case-03:

```bash
go run ./cmd/izyan research \
  --snapshot "$SNAPSHOT" \
  --cve GHSA-65xw-vw82-r86x \
  --advisory-file "$ADV03" \
  --output-dir va-tmp/r6-final/art-1103/case-03-tag \
  --goos linux \
  --goarch amd64 \
  --deterministic-only \
  --ticket "$TICKET03" \
  --artifact "$ARTIFACT" \
  --declared-assumptions "$ASSUMPTIONS"
```

Expected case-03 result:

```text
verdict: NO_EXPLOIT_PATH_FOUND
falsifier: trusted-infrastructure
basis: config-origin
assumption: administrator-managed configuration
coverage: COMPLETE
```

The report MUST show exact sink/argument data-flow evidence and MUST NOT show `NOT_AFFECTED`.

Run case-04 using the retained implementation-locus proposal artifact through the approved proposal/replay input surface:

```bash
go run ./cmd/izyan research \
  --snapshot "$SNAPSHOT" \
  --cve GHSA-hfvc-g4fc-pqhx \
  --advisory-file "$ADV04" \
  --output-dir va-tmp/r6-final/art-1103/case-04-tag \
  --goos linux \
  --goarch amd64 \
  --deterministic-only \
  --ticket "$TICKET04" \
  --artifact "$ARTIFACT" \
  --declared-assumptions "$ASSUMPTIONS" \
  --implementation-locus-proposal va-tmp/r6-final/agent-proposals/case-04-implementation-locus.json
```

Expected case-04 result:

```text
verdict: NOT_AFFECTED
affected.vulnerable_implementation_present: FALSE
affected.build_relevant: TRUE or the pre-existing package/build result
reason: vulnerable implementation absent under authoritative Linux target scope
```

The result MUST NOT be represented as `BuildRelevant=FALSE` merely because `host_id_bsd.go` is excluded.

Run the required final code gates once all focused tests pass:

```bash
gofmt -w <all changed .go files>
go vet ./...
go test ./...
```

Run the corpus exactly once at final validation:

```bash
go run ./cmd/izyan eval --corpus eval/corpus-real.json -j 4
```

Required result:

```text
false-safe=0
```

Run the corporate census exactly once, at the end:

```bash
python3 va-tmp/r6-final/run_census_artifacts.py
```

Run the decision-ready regression guard:

```bash
python3 eval/decision_ready/regression_guard.py \
  --baseline-manifest va-tmp/r6-final/r6-guard-baseline.json
```

Record the measured verdict, falsifier, coverage, implementation axis, target source, assumption ids, and limitations for every affected case. Do not replace conditional forecasts with claims unless the reports show them.

**Stop conditions:**

- Stop if the assumptions document is missing, invalid, expired, digest-mismatched, or not product-wide where required.
- Stop if case-03 lacks positive exact sink reach, exact trigger `ArgIndex`, complete sink coverage, or verified config origin.
- Stop if any external write, unresolved alias, reflection marker, or incomplete closure is present.
- Stop if case-03 emits `NOT_AFFECTED`.
- Stop if case-04’s proposal is wrong, lacks `QualityLLMInferred`, has an invalid advisory quote/ref, or fails any deterministic source/build check.
- Stop if a selected alternate implementation contains the vulnerable marker.
- Stop if target facts come only from the analyzer host or artifact-only scope while the verdict claims product-wide absence.
- Stop if `BuildRelevant` is used to encode implementation absence.
- Stop if any negative lacks complete evidence and the required verified falsifier/affected-chain FALSE.
- Stop if the corpus reports any `false-safe`.
- Stop if the census or regression guard fails.
- Stop if any unrelated case changes verdict, falsifier, coverage, or safety classification.
- Stop if the measured artifact archive still reports `ARTIFACT_ARCHIVE_UNSAFE`; do not increase `maxArtifactNesting=4` to force acceptance.

## Dependency / Execution Order

```text
Task 1
  ├──> Task 2 ───> Task 3
  └──> Task 4 ───> Task 5
Task 3 + Task 5 ───> Task 6 ───> Task 7
```

- **Task 1** is the cheapest shared prerequisite and establishes the policy/evidence boundary.
- **Tasks 2–3** are the first decisive path and unblock case-03.
- **Tasks 4–5** implement the separate LLM-proposal and target-scoped affected path and unblock case-04.
- **Task 6** integrates the contracts across CLI, reports, replay, and harness surfaces.
- **Task 7** is the only full-repository/corpus/census validation phase.
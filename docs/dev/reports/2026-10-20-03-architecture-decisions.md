# Архитектурные решения: auditable vulnerability analyzer

**Назначение:** decision-centric reference для сравнения с архитектурно другим решением. Числа — только там, где они обосновывают решение.
**Источник:** delegated `architect` artifact `agent://ArchitectureDecisions` (2026-10-20), сохранён дословно.
**Смежные документы:** `2026-10-20-02-architecture-status.md` (статус и измерения), `2026-10-20-01-remaining-work-roadmap.md` (остаточные работы).

---

# Architecture Decisions for an Auditable Vulnerability Applicability and Exploitability Analyzer

## Scope and comparison frame

This document describes the architecture as a set of contracts and architectural decisions, not as a Go-specific implementation recipe. A competing solution may use another language, a different static-analysis engine, runtime evidence, a different storage model, or no LLM at all. It remains comparable if it can demonstrate equivalent guarantees.

The unit of analysis is:

> one advisory or ticket, one explicitly identified product snapshot or release artifact, one build/target context, and the deployment/configuration assumptions relevant to the conclusion.

The desired result is not merely “the package is present” or “a function is reachable.” It is an auditable chain:

```text
identity
  → affectedness
  → vulnerable implementation / exploit locus
  → mandatory exploit conditions
  → deterministic evidence
  → TRUE / FALSE / UNKNOWN claims
  → negative verification
  → terminal verdict
  → replayable report
```

Terms used below:

- **Evidence**: a measured, source/build/runtime observation with provenance.
- **Claim**: a typed interpretation of evidence for one mandatory condition.
- **Falsifier**: an explicit observation that makes a mandatory condition false.
- **Negative verification**: an independent completeness and bypass check for a falsifier.
- **Proposal**: a hypothesis supplied by an LLM or human, not authoritative until independently verified.
- **Assumption**: a human-owned policy or scope statement, such as “administrator-managed configuration is outside the attacker model.”
- **Closed scope**: the analyzer has enumerated the relevant universe and can account for both positive and negative results.
- **Open scope**: unresolved candidates, skipped inputs, dynamic behavior, or exhausted bounds may hide relevant evidence.

---

# 1. Requirements as constraints

## 1.1 Hard requirements

These requirements are derived from `AGENTS.md`, `docs/goals-scope.md`, `docs/how-it-works.md`, and the security/evaluator rules. They constrain any acceptable architecture, regardless of language or implementation technique.

| Requirement | Constraint on the architecture | Observable acceptance condition |
|---|---|---|
| **No unsafe negative** | The system MUST NOT infer “not exploitable” from the absence of a discovered path. | Every `NO_EXPLOIT_PATH_FOUND` result names a mandatory condition, a falsifier, evidence, and successful negative verification. |
| **Uncertainty preservation** | Unknown applicability, scope, provenance, dispatch, deployment, or exploit conditions MUST remain unknown. | Incomplete or contradictory evidence produces `INCONCLUSIVE` or an explicit refusal, never a guessed safe verdict. |
| **Affectedness/exploitability separation** | Applicability of vulnerable code and reachability/control of that code are different questions. | Symbol unreachability cannot be represented as `NOT_AFFECTED`; implementation absence can. |
| **Identity correctness** | Evidence MUST be bound to the advisory, product source/artifact, package version, commit/build context, and target being analyzed. | The analyzer refuses to answer a ticket about a different package build. |
| **Auditability** | A reviewer MUST be able to identify what was checked, with which inputs, under which scope and bounds. | Claims reference typed evidence, tool executions, hashes, scope, limitations, and assumptions. |
| **Reproducibility** | A persisted case MUST be replayable without relying on an LLM conversation or unstored operator state. | Replaying the persisted case revalidates inputs and proof artifacts and does not require a new model call. |
| **Independent negative verification** | A negative claim MUST be checked for scope gaps, bypasses, dynamic dispatch, failed loads, and contradictory evidence. | Removing one audit row, opening a may-call enumeration, or tampering with a proof artifact blocks the negative. |
| **Human triage** | The system MUST expose the exact reason an answer is unresolved and what evidence would settle it. | `INCONCLUSIVE` includes named limitations, affected subjects, assumptions, and suggested next evidence. |
| **Policy/evidence separation** | Human-owned trust and scope statements MUST NOT be represented as code facts. | Assumptions have separate IDs and provenance and are not `EvidenceGraph` records. |
| **Genericity** | The analyzer MUST not depend on case-specific product, advisory, package, or symbol rules. | The same contracts apply to generic fixtures and unrelated advisories. |
| **Safe degradation** | Resource, tool, or provider failure MUST fail closed. | A missing SDK, malformed proposal, failed package load, or exhausted bound is reported explicitly and cannot promote a negative. |
| **Machine-readable and human-auditable output** | The result MUST serve both automated VEX/triage consumers and human reviewers. | The report preserves evidence links, limitations, rationale, assumptions, and machine-readable verdict mappings. |

The absolute safety objective is expressed in `docs/goals-scope.md` as `false-safe = 0`: no unsupported safe-negative result may be emitted for an exploitable or unresolved case.

## 1.2 Preferences rather than hard requirements

These are legitimate choices of this solution, but another architecture may satisfy the hard requirements differently:

- Go as the implementation language.
- `go/packages`, Go AST/types/SSA, and `govulncheck` as evidence sensors.
- A staged persistent state machine rather than a single transaction.
- An `EvidenceGraph` as the primary internal evidence representation.
- Optional LLM assistance.
- Content-addressed sidecars for large proof payloads.
- OpenVEX and CycloneDX as report projections.
- A dual-track exposure model (`zero_trust` and `cluster_perimeter`).
- A declarative knowledge base for source, sanitizer, listener, and passthrough semantics.
- Inverted-pyramid Markdown reports in addition to JSON.

A competing architecture can use a database, a formal proof object, runtime traces, a single immutable case bundle, or another report format if it demonstrates equivalent guarantees.

## 1.3 Threat model

The architecture treats the following as possible sources of unsoundness:

- package presence mistaken for vulnerable-code execution;
- an advisory’s broad symbol set mistaken for the defect locus;
- empty call results mistaken for closed absence;
- skipped or failed packages silently removed from analysis;
- function values, interfaces, reflection, plugins, build tags, or callbacks hiding calls;
- an argument’s configuration-looking field mistaken for trusted origin;
- a host OS mistaken for the shipped artifact’s target;
- a ticket’s package/version claims answered using another build;
- LLM confidence or prose treated as proof;
- a truncated display payload treated as the complete authoritative result;
- a deployment assumption treated as source evidence;
- a positive static call path treated as proof of attacker control.

---

# 2. Technology-neutral architecture

## 2.1 Component responsibilities and boundaries

| Component | Responsibility | Must provide | Must not provide |
|---|---|---|---|
| **Input and identity resolver** | Normalize advisory/ticket, source snapshot, artifact, package version, commit, target, and deployment inputs. | Immutable identity record and mismatch/refusal state. | It must not silently substitute another build or infer missing identity. |
| **Applicability resolver** | Determine whether the affected module/version/package/build/implementation applies to the product. | A typed affected chain with evidence for each axis. | It must not use reachability or attacker-control evidence to declare applicability absence. |
| **Root-cause/locus resolver** | Identify the vulnerable implementation and distinguish it from wrappers, transport, and dispatch symbols. | An advisory-bound locus model or an explicit unresolved state. | It must not let a proposal become authoritative without source/build verification. |
| **Exploit-model builder** | Define mandatory exploit conditions and their subjects, arguments, and coverage requirements. | A typed model with explicit TRUE/FALSE/UNKNOWN semantics. | It must not convert a missing proof into a FALSE condition. |
| **Evidence engine** | Collect source, build, call, provenance, dispatch, ingress, deployment, and optional runtime observations. | Typed evidence with provenance, scope, bounds, and tool execution records. | It must not claim completeness when the evidence universe is open. |
| **Claim evaluator** | Interpret evidence for each mandatory condition. | Claims with result, falsifier, evidence IDs, limitations, and assumptions. | It must not elevate prose, confidence, or package presence to proof. |
| **Negative verifier** | Independently re-check a FALSE claim for scope completeness and bypasses. | `VERIFIED`, `CONTRADICTED`, or `INSUFFICIENT_SCOPE`. | It must not merely repeat the initial evaluator’s conclusion. |
| **Decision authority** | Apply the verdict ladder to affected axes and claims. | A pure, deterministic terminal verdict or an explicit unresolved result. | It must not read unstored LLM state or infer a verdict from report prose. |
| **Replay/validation layer** | Rehydrate and validate the persisted case. | A replay result that identifies any digest, schema, identity, or proof mismatch. | It must not trust hand-edited or incomplete authoritative artifacts. |
| **Report/projection layer** | Present the result to humans and machine consumers. | Auditable report, VEX projections, limitations, evidence links, and assumptions. | It must not become a second decision engine. |
| **Proposal layer** | Supply semantic hypotheses or search plans. | Typed, advisory-bound, replayable proposals. | It must not set a claim, falsifier, negative verification, or verdict. |

## 2.2 Control flow

The implementation uses a persistent state-machine shape:

```text
CREATED
  → SNAPSHOT_PRODUCT
  → RESOLVE_VULNERABILITY
  → CHECK_AFFECTED
  → RESOLVE_ROOT_CAUSE
  → BUILD_EXPLOIT_MODEL
  → COLLECT_EVIDENCE
  → EVALUATE_CONDITIONS
  → GAP_ANALYSIS (optional)
  → NEGATIVE_CHECK
  → REVIEW
  → REPAIR_ANALYSIS (optional, demotion only)
  → EVALUATE_VERDICT
  → BUILD_REPORT
  → COMPLETED
```

This is a sequencing choice, but the underlying dependency ordering is architectural:

1. identity before evidence;
2. applicability before exploit-path conclusions;
3. exploit model before condition claims;
4. evidence before claims;
5. negative verification before a safe-negative verdict;
6. deterministic decision before report rendering.

Operational failure and analytic uncertainty are distinct:

- **Operational failure**: the pipeline cannot execute or persist a required operation.
- **Analytic uncertainty**: the operation executed but cannot establish a complete fact.
- **Refusal**: the requested conclusion is not valid for the supplied identity or scope.

All three must be named. None may be silently converted to a safe verdict.

## 2.3 Technology-neutral data model

A minimal equivalent model is:

```text
CaseIdentity
  advisory_id / advisory_digest
  ticket_digest and declared claims
  source_commit / source_digest
  product_module
  resolved_dependency_versions
  artifact_digest / member identity
  target and build context
  deployment-input digests

AffectedResult
  module_present
  version_affected
  package_present
  build_relevant
  vulnerable_implementation_present
  evidence_ids
  assumption_ids
  limitations

LocusModel
  advisory-declared subjects
  verified defect locus
  non-locus/wrapper distinctions
  proposal references
  binding status

ExploitModel
  mandatory conditions
  subject set
  exact argument positions
  required coverage
  protocol/mode/platform predicates

EvidenceRecord
  evidence_id
  subject and case identity
  source/tool/command
  result payload or sidecar reference
  digest
  scope and completeness
  explicit bounds
  limitations

Claim
  condition_id
  TRUE / FALSE / UNKNOWN
  falsifier
  falsifier basis
  evidence_ids
  assumption_ids
  negative-verification record
  explanation and limitations

Decision
  terminal verdict
  reason
  grounding basis
  claim/evidence/assumption references
  coverage
  replay metadata
```

The important distinction is not the exact serialization. It is that the following categories remain separate:

```text
identity ≠ evidence ≠ claim ≠ assumption ≠ proposal ≠ verdict
```

## 2.4 Evidence and scope semantics

A result is not complete merely because an algorithm returned an empty list.

The evidence engine must distinguish:

- **closed empty**: the relevant universe was fully enumerated and no subject was found;
- **open empty**: the result is empty, but failed loads, unresolved candidates, dynamic dispatch, or bounds may hide subjects;
- **positive**: a matching subject or path was found;
- **contradictory**: independent observations disagree;
- **not applicable**: the subject is outside the selected identity or scope.

Evidence records therefore carry completeness, basis, blockers, and bounds. `SinkClosure` and `IngressClosure` implement this in the current system through `Basis`, `Complete`, and `Blockers` (`internal/domain/domain.go`; `internal/goanalysis/sinkclosure.go`).

## 2.5 Failure semantics

The architecture uses the following fail-closed rules:

- malformed advisory/ticket/artifact: named input error or limitation;
- package-version mismatch: identity refusal; no out-of-range conclusion for the analyzed build;
- failed package load: package remains in the scope denominator;
- unresolved function value/interface/reflection path: scope remains open;
- exhausted package, trace, dispatch, or payload bound: named blocker;
- invalid or missing proposal: proposal route does not run;
- missing or altered authoritative proof sidecar: replay/decision becomes `INCONCLUSIVE`;
- missing audit pairing: verification trace is incomplete;
- invalid/expired/wrong-scope assumption: dependent route is inadmissible;
- unresolved advisory coverage: no terminal negative;
- positive static reachability without input control: not automatically `EXPLOITABLE`;
- report rendering failure: report generation fails; it does not alter the underlying decision.

---

# 3. Decision log — ADRs

Each ADR states whether the decision is essential to the requirements or a legitimate implementation choice. “Essential” means every acceptable architecture must preserve the protected guarantee. “Implementation-specific” means another design may satisfy the same requirement differently.

## ADR-001 — Analyze a specifically identified build, not an abstract dependency

**Classification:** Essential requirement; the identity record’s exact fields are implementation-specific.

### Context/problem

A vulnerability conclusion is meaningful only for a particular product snapshot or shipped artifact. Source checkout, dependency version, target, build tags, artifact build information, and ticket claims can disagree.

### Options considered

1. **Chosen:** Bind every conclusion to a case identity containing advisory, product source/artifact, package version, build context, target, and relevant deployment inputs.
2. Analyze the repository’s current checkout as a proxy for every ticket or release.
3. Treat the dependency version alone as the unit of analysis.

### Decision

The case identity is explicit and immutable. All evidence, proposals, assumptions, claims, and reports must refer to that identity.

### Invariant protected

The analyzer must not answer a question about one build using evidence from another build.

### Enforcement

- `domain.AnalysisCase`, `domain.ProductSnapshot`, and advisory/ticket records in `internal/domain`.
- `internal/repository.Service.Snapshot`.
- `internal/repository.ResolveReleaseArtifact`.
- `internal/affected.checkTicketClaims`.
- `internal/research.VerifyDecision` identity gates.

### Cost/trade-off

Identity resolution creates refusals when the required artifact or source is unavailable. This reduces apparent completion but prevents conclusions that are precise-looking and about the wrong binary.

### What a different approach must do instead

A different architecture may use a signed SBOM, container digest, build manifest, reproducible-build attestation, or deployment image digest instead of this case structure. It must still prove that every fact belongs to the exact artifact/build being answered.

---

## ADR-002 — Use a staged, restartable analysis pipeline

**Classification:** Essential dependency ordering; the persistent state-machine representation is implementation-specific.

### Context/problem

Applicability, root cause, exploit conditions, evidence, and verdict depend on one another. Long-running analysis and optional model calls can fail or be interrupted.

### Options considered

1. **Chosen:** Persistent ordered state machine with explicit terminal and unresolved states.
2. Single monolithic analysis function that returns one result.
3. Independent parallel checks with a final heuristic merge.

### Decision

The workflow is staged and persisted. Each stage consumes typed outputs from prior stages and records transitions and limitations.

### Invariant protected

A later conclusion cannot silently bypass an unresolved prerequisite.

### Enforcement

- `internal/states/states.go`.
- Workflow state constants in `internal/domain/domain.go`.
- Persistent `AnalysisCase`.
- `docs/architecture.md` state-machine contract.

### Cost/trade-off

The state model adds serialization and migration burden. It also makes intermediate state visible, which can expose more `INCONCLUSIVE` results than a best-effort monolith.

### What a different approach must do instead

A different architecture may use an immutable event log, a DAG scheduler, or a transactional proof pipeline. It must preserve dependency ordering, restartability, and explicit incomplete states.

---

## ADR-003 — Treat evidence as a first-class, provenance-bearing product

**Classification:** Essential auditability requirement; an evidence graph is implementation-specific.

### Context/problem

A final verdict without the exact observations, commands, scope, hashes, and limitations cannot be independently reviewed or replayed.

### Options considered

1. **Chosen:** Typed evidence records collected in an `EvidenceGraph`, with `ToolExecution` and provenance.
2. Store only a narrative report and final verdict.
3. Store raw tool output without typed subject, scope, or identity binding.

### Decision

Evidence is persisted independently of claims and reports. Every material result has a subject, source/tool, execution metadata, digest, scope, and limitations.

### Invariant protected

A claim cannot outlive or detach from the observation that supports it.

### Enforcement

- `EvidenceGraph` and `ToolExecution` in `internal/domain/domain.go`.
- Evidence collection in `internal/goanalysis`, `internal/evidencetools`, `internal/repository`, and `internal/exposure`.
- Report evidence references in `internal/report`.
- Evidence validation in `internal/research.validate`.

### Cost/trade-off

Typed evidence requires schema maintenance and more storage than a summary-only report. It also requires careful distinction between authoritative and display representations.

### What a different approach must do instead

A competing design may use immutable event streams, signed proof certificates, relational evidence tables, or a content-addressed case bundle. It must preserve subject binding, provenance, scope, completeness, and digest integrity.

---

## ADR-004 — A safe negative requires an explicit falsifier and independent negative verification

**Classification:** Essential safety requirement.

### Context/problem

“No path found” is compatible with an incomplete call graph, missed dynamic dispatch, failed package loading, or an unmodeled input path. Treating an empty search result as impossibility creates false-safe results.

### Options considered

1. **Chosen:** Require `ClaimFalse`, a named falsifier, evidence, and an independent negative-verification pass.
2. Treat an empty call/path search as `FALSE`.
3. Use a confidence score or multiple agreeing heuristics as a negative.
4. Require only a human or LLM assertion that the condition is absent.

### Decision

`NO_EXPLOIT_PATH_FOUND` is permitted only when at least one mandatory condition is explicitly falsified and `NegativeVerification=VERIFIED`.

### Invariant protected

Absence of a discovered path is never itself proof of non-exploitability.

### Enforcement

- `AGENTS.md` and `docs/agent-rules/security.md`.
- `internal/goanalysis.Verifier.VerifyFalse`.
- `internal/goanalysis/negative.go`.
- `internal/evaluator/verdict.go`.
- `internal/research.VerifyDecision`.
- `domain.NegativeVerification`.

### Cost/trade-off

The architecture intentionally retains more `INCONCLUSIVE` results. Verification can repeat expensive source and scope checks.

### What a different approach must do instead

A competing design may use a formal reachability proof, a sound abstract interpreter, model checking, or a runtime counterexample/falsifier. It must demonstrate that the negative is established by a complete proof of a mandatory false condition and that relevant bypasses are covered.

---

## ADR-005 — Deterministic verification is authoritative; LLM output is proposal-only

**Classification:** Essential when an LLM is present; deterministic Go code and the exact call structure are implementation-specific.

### Context/problem

LLMs are useful for patch interpretation, semantic hypotheses, and search planning, but their output is nondeterministic and may contain unsupported claims.

### Options considered

1. **Chosen:** LLMs emit typed proposals; deterministic verifiers decide facts, claims, negative verification, and verdicts.
2. Let the LLM directly select the verdict after reading tool output.
3. Let the LLM vote with deterministic tools and use majority/confidence.
4. Remove LLM assistance entirely.

### Decision

The trust boundary is:

```text
LLM reasoning
  → typed proposal
  → deterministic source/build/evidence verification
  → claim
  → negative verification
  → deterministic verdict
```

The LLM may not create evidence, set `ClaimFalse`, set `NegativeVerification=VERIFIED`, establish either safe-negative verdict, or bypass identity/scope/digest gates.

### Invariant protected

A stochastic or unauditable statement cannot widen a safety conclusion.

### Enforcement

- `internal/llm/client.go`.
- `internal/llm/exploit.go`.
- Strict proposal parsing in `internal/research/agent.go`.
- `internal/research.VerifyDecision`.
- `--deterministic-only` and `--strict-llm` behavior.
- Implementation and exploit-locus verifiers under `internal/affected`.

### Cost/trade-off

The system may fail to resolve cases that an LLM can describe plausibly. It also requires typed schemas, proposal admission, and deterministic re-checks.

### What a different approach must do instead

A no-LLM design satisfies this ADR vacuously if its deterministic or formally checked engine is authoritative. An LLM-centric design is acceptable only if the LLM produces a proof object whose validity is independently checked by a trusted verifier; the model itself cannot be the authority.

---

## ADR-006 — Preserve a four-level verdict ladder

**Classification:** Essential semantic distinction; exact enum names are implementation-specific.

### Context/problem

Applicability, exploitability, negative proof, and uncertainty are different outcomes. Collapsing them causes either false positives or false-safe negatives.

### Options considered

1. **Chosen:** `NOT_AFFECTED`, `EXPLOITABLE`, `NO_EXPLOIT_PATH_FOUND`, and `INCONCLUSIVE`.
2. Binary vulnerable/not-vulnerable output.
3. A single confidence score.
4. A larger taxonomy that does not preserve the affectedness/reachability distinction.

### Decision

The terminal semantics are:

- `NOT_AFFECTED`: the affected chain is deterministically false.
- `EXPLOITABLE`: every mandatory exploit condition is true and no mandatory subject remains unresolved.
- `NO_EXPLOIT_PATH_FOUND`: a mandatory condition is false and the falsifier was independently verified.
- `INCONCLUSIVE`: applicability, evidence, scope, provenance, deployment, or exploit conditions remain unresolved.

### Invariant protected

Applicability absence, reachability falsification, positive exploitability, and unresolved analysis cannot be conflated.

### Enforcement

- Verdict constants in `internal/domain/domain.go`.
- Pure `VerdictEvaluator.Evaluate` in `internal/evaluator/verdict.go`.
- Workflow transitions in `internal/states/states.go`.
- OpenVEX mapping in `internal/report/openvex.go`.

### Cost/trade-off

Consumers must understand four states rather than consume a simple Boolean. VEX projections may map more than one internal state to `not_affected`, so the internal reason and grounding basis must remain visible.

### What a different approach must do instead

A competing design may use more detailed statuses, but it must preserve these semantic partitions and provide a total mapping for automated consumers.

---

## ADR-007 — Model affectedness as an ordered chain, including vulnerable implementation presence

**Classification:** The separation of applicability from reachability is essential; the particular five-axis chain is implementation-specific but strongly aligned with the requirements.

### Context/problem

A package may be present while the vulnerable implementation is excluded by build constraints, target selection, or alternate implementation selection. Conversely, a symbol may be unreachable even though the vulnerable implementation is part of the build.

### Options considered

1. **Chosen:** Evaluate:

   ```text
   module present
     → version affected
     → package present
     → build relevant
     → vulnerable implementation present
   ```

2. Treat package presence as sufficient affectedness.
3. Treat symbol reachability as the final applicability axis.
4. Reuse `BuildRelevant` to encode implementation-file absence.

### Decision

The implementation-presence axis is separate from `BuildRelevant`. A verified false implementation axis may yield `NOT_AFFECTED`; symbol unreachability may not.

### Invariant protected

A selected build cannot be declared affected merely because a package exists, and a linked vulnerable implementation cannot be declared inapplicable merely because no product call was found.

### Enforcement

- `domain.AffectedResult.VulnerableImplementationPresent`.
- `internal/affected.EvaluateImplementationAxis`.
- `internal/affected.VerifyImplementationLocus`.
- `internal/states.CheckAffected`.
- `internal/evaluator.VerdictEvaluator.Evaluate`.

### Cost/trade-off

The analyzer needs target-aware source/build inspection and an additional proof route. It cannot close cases when target identity or implementation selection is unknown.

### What a different approach must do instead

A binary analyzer may use linker maps, symbol tables, object-file provenance, or compiler IR to prove implementation inclusion. It must still keep “vulnerable implementation is absent” separate from “vulnerable symbol is unreachable.”

---

## ADR-008 — Separate defect locus from advisory-wide symbols and wrappers

**Classification:** Essential for sound advisory interpretation; the exact locus data model is implementation-specific.

### Context/problem

Advisories frequently enumerate helper, transport, or wrapper symbols in addition to the code that contains the defect. A broad advisory OR-set can produce a reachable signal even when the vulnerable behavior is not reached.

### Options considered

1. **Chosen:** Maintain advisory-declared subjects, verified defect locus, and non-locus/wrapper relationships separately.
2. Treat every advisory-listed symbol as equally vulnerable.
3. Replace the advisory symbol set with an LLM-selected locus.
4. Use only the first symbol named by the advisory.

### Decision

The advisory declaration remains authoritative as an input scope, but root cause and exploit modeling may distinguish the actual defect locus from transport and dispatch symbols. Any narrowing must be deterministic or explicitly proposal-based and verified.

### Invariant protected

The analyzer cannot silently change advisory coverage while claiming to have checked the advisory as supplied.

### Enforcement

- `domain.RootCauseModel`, `domain.ExploitLocusBinding`.
- `internal/affected.exploitlocus`.
- `internal/goanalysis.FindSymbol`, `ModuleInternalReach`, and locus-related evaluators.
- `internal/research.VerifyDecision` subject-coverage gates.

### Cost/trade-off

A broad advisory may leave more symbols unresolved, producing `INCONCLUSIVE`. Narrowing the locus requires additional source and advisory analysis.

### What a different approach must do instead

Another system may use a vulnerability database’s canonical vulnerable-function metadata, patch-derived semantic slices, or a formal exploit specification. It must preserve the distinction between advisory scope and verified defect behavior.

---

## ADR-009 — Track exact input provenance and exact argument positions

**Classification:** Exact argument identity and separate origin classes are essential for attacker-control claims; the Go data-flow implementation is specific.

### Context/problem

A vulnerable call can receive a constant, generated value, local configuration, internal service data, database data, or external input. A field’s configuration tag does not prove that all writes to it are trusted.

### Options considered

1. **Chosen:** Trace exact sink arguments, preserve transformations, classify origin, and let external/unknown influence override configuration-looking evidence.
2. Classify the entire call as external or trusted based on the sink function.
3. Infer origin from field tags or variable names.
4. Use only a taint bit without argument/site identity.

### Decision

`DataFlow` binds the exact sink, exact argument index, source, transformations, and origin. Configuration origin is admissible only when complete tracing finds no external, unknown, alias, reflection, callback, or opaque write that could influence the same value.

### Invariant protected

A trusted-looking field cannot mask an attacker-controlled write or an unresolved data-flow branch.

### Enforcement

- `internal/goanalysis.TraceArgumentBound`.
- `internal/goanalysis/provenance.go`.
- `internal/evaluator.ArgumentOrigin`.
- `internal/goanalysis.negative.go`.
- `domain.DataFlow`, `domain.Origin*`, and sink/ingress closure types.

### Cost/trade-off

Exact argument tracing is more expensive and more prone to unresolved states than coarse taint labels.

### What a different approach must do instead

A different language or runtime system may use whole-program taint, symbolic execution, dynamic taint, or information-flow types. It must identify the exact vulnerable input and conservatively handle aliases, reflection, callbacks, opaque transformations, and incomplete flows.

---

## ADR-010 — Failed or skipped packages remain in the scope denominator

**Classification:** Essential completeness rule; the exact package-loader diagnostics are implementation-specific.

### Context/problem

A package that fails type-checking may contain a reference to the vulnerable subject. Removing it from the scan makes the empty result an under-approximation.

### Options considered

1. **Chosen:** Exclude failed packages from typed analysis but retain them as explicit skipped scope and block a negative that could depend on them.
2. Drop failed packages and continue with the remaining graph.
3. Treat a failed package as absent from the product.
4. Retry indefinitely until the package loads.

### Decision

Skipped packages are recorded with diagnostics, recovered import edges, and limitations. They remain in the denominator for usage and unreachability decisions.

### Invariant protected

An invisible package cannot be treated as evidence that no call or path exists.

### Enforcement

- `internal/goanalysis.source.Index.load`.
- `loadConfig` and skipped-package diagnostics.
- `Index.SkippedPackages`, `SkippedPackagesImporting`.
- `internal/goanalysis.ProductUsage`.
- `internal/goanalysis.negative.go`.

### Cost/trade-off

Cases with missing SDKs, C headers, generated files, or incompatible environments remain unresolved. Analysis cannot manufacture a complete build scope.

### What a different approach must do instead

A competing system may require a successful reproducible build before analysis, use compiler-produced dependency manifests, or analyze bytecode/object files. It must prove that the complete relevant product scope was included; silently omitting failed inputs is not acceptable.

---

## ADR-011 — Empty may-call results are closed only under an explicit closed/open contract

**Classification:** Essential for negative reachability; the `MayCallSites` API is implementation-specific.

### Context/problem

Function values, callbacks, signature-compatible candidates, generated dependency loads, and analysis churn can hide calls. An empty result may be a partial scan.

### Options considered

1. **Chosen:** `MayCallSites` returns both candidates and a completeness/open flag. Only `([], false, nil)` is a closed empty result.
2. Treat `len(candidates) == 0` as no possible call.
3. Treat all candidate sets as open and never close a negative.
4. Use a fixed maximum candidate count without reporting exhaustion.

### Decision

Possible candidates, sentinels, unresolved candidates, skipped packages, generation churn, load failures, and exhausted bounds keep the enumeration open. A stable, reconciled final generation can close the result.

### Invariant protected

An empty candidate list cannot erase unresolved function-value or callback paths.

### Enforcement

- `internal/goanalysis.MayCallSites`.
- `internal/goanalysis.funcvalues`.
- `internal/goanalysis.toolscope.go`.
- `internal/goanalysis.unreachability.VerifyUnreachable`.
- `internal/goanalysis.ProductUsage`.

### Cost/trade-off

Candidate closure can require multiple passes and stable dependency-extra state. Some cases remain `INCONCLUSIVE` even when no direct call is visible.

### What a different approach must do instead

Another system may compute an exact call graph, use a sound over-approximation, or use runtime call traces. It must distinguish a closed empty set from a partial enumeration and preserve unresolved candidates as blockers.

---

## ADR-012 — Interface-dispatch narrowing requires complete receiver-instantiation evidence

**Classification:** Sound narrowing is essential; the receiver inventory and type-system implementation are specific.

### Context/problem

A syntactic interface call may or may not resolve to the vulnerable implementation. Removing it because the implementation was not found can create a false negative.

### Options considered

1. **Chosen:** Retain interface candidates unless a complete, error-free product-instantiation probe proves the receiver type cannot be materialized.
2. Remove all unresolved interface candidates.
3. Assume every interface implementation is reachable.
4. Use name matching only.

### Decision

`InterfaceDispatchSites` remains conservative. `dispatchGaps` may narrow only with complete receiver-instantiation evidence. An unresolved receiver, skipped package, disabled narrowing, or incomplete inventory remains open.

### Invariant protected

A missing concrete target is not evidence that an interface call cannot reach it.

### Enforcement

- `internal/goanalysis.InterfaceDispatchSites`.
- `internal/goanalysis.dispatchGaps`.
- `internal/goanalysis.receiverTypeInstantiated`.
- `internal/goanalysis.unreachability`.
- Dispatch tests under `internal/goanalysis`.

### Cost/trade-off

The analyzer may retain false-positive candidates and produce more `INCONCLUSIVE` results. Complete receiver inventories can be expensive.

### What a different approach must do instead

A competing architecture may use whole-program type analysis, link-time devirtualization, runtime type profiles, or language-specific sealed-interface guarantees. It must prove the receiver universe is complete before narrowing.

---

## ADR-013 — Bounds are explicit proof boundaries, not silent implementation details

**Classification:** Essential for honest uncertainty; exact numeric limits are implementation-specific.

### Context/problem

Package loads, trace hops, function-value recursion, dispatch probes, artifact size, payload size, and model calls all require bounds. A result after an exhausted bound is not a complete negative.

### Options considered

1. **Chosen:** Record every relevant bound and turn exhaustion into a named limitation/open scope.
2. Silently increase limits until the current case closes.
3. Treat timeout or truncation as an operational error and omit the case.
4. Return the best result obtained before exhaustion.

### Decision

Bounds are part of evidence scope. Exhaustion, truncation, timeout, or incomplete persistence cannot support a safe-negative conclusion.

### Invariant protected

Resource management cannot become an invisible source of false certainty.

### Enforcement

- Bounds and limitations in `internal/goanalysis`, `internal/evidencetools`, and `internal/research`.
- `internal/research.capObservationPayload`.
- Proposal and assumptions size limits.
- `domain.EvidenceGraph` and report limitations.
- `VerifyDecision` completeness gates.

### Cost/trade-off

The system can remain unresolved under large or pathological inputs. Raising a limit requires a deliberate contract and new reproducibility evidence.

### What a different approach must do instead

A different architecture may use unbounded external storage, incremental fixed-point computation, or proof-producing resource accounting. It must still expose exhaustion and distinguish complete from partial evidence.

---

## ADR-014 — Package absence and symbol unreachability are separate facts

**Classification:** Essential verdict semantics.

### Context/problem

A package can be absent from the product closure, present but unused, or present with a particular symbol unreachable. These states support different conclusions and different audit explanations.

### Options considered

1. **Chosen:** Reconcile package/build closure evidence separately from symbol-level unreachability.
2. Treat package absence as proof that every symbol is unused and declare `NOT_AFFECTED`.
3. Treat symbol absence as package absence.
4. Ignore contradictory package and symbol observations.

### Decision

- Complete package absence can support an affected-chain negative where advisory scope permits.
- Symbol unreachability can support `NO_EXPLOIT_PATH_FOUND`.
- Contradictory package/build facts block closure until reconciled.
- A symbol-level no-use result is never `NOT_AFFECTED`.

### Invariant protected

The verdict identifies the proposition actually proven.

### Enforcement

- `internal/research.packageAbsenceDecision`.
- `packagePresenceConflict`, `hasPositiveUse`.
- `internal/goanalysis.ProductUsage`.
- `internal/evaluator.verdict`.
- `internal/states.CheckAffected`.

### Cost/trade-off

The analyzer may retain a case as unresolved even when one layer says “package absent” and another says “mixed” or “used.”

### What a different approach must do instead

A competing design may derive both facts from one authoritative linker graph or SBOM. It must still preserve the semantic distinction and prevent symbol-level reachability from masquerading as applicability absence.

---

## ADR-015 — Missing-call and dynamic-marker checks are safety gates

**Classification:** Essential for sound negative analysis; the specific marker catalog is implementation-specific.

### Context/problem

Some vulnerabilities arise from a missing validation call. A naive “validation function not called” result can be exactly backwards. Reflection, `unsafe`, plugins, build tags, and function values can also hide paths.

### Options considered

1. **Chosen:** Treat relevant missing-call patterns and dynamic markers as explicit blockers or verified conditions.
2. Assume absence of a validation call means the validation condition is false or irrelevant.
3. Ignore dynamic markers outside direct call analysis.
4. Treat every marker as a contradiction and abandon all negatives.

### Decision

The verifier checks known missing-call relationships and dynamic markers. Relevant unresolved markers produce `INSUFFICIENT_SCOPE`; recognized safe forms may be dismissed only by explicit rules.

### Invariant protected

The analyzer must not turn an under-approximation of validation or dispatch into a false-safe result.

### Enforcement

- `internal/goanalysis.DepInvocationState`.
- `internal/goanalysis.negative.go`.
- `docs/agent-rules/dynamic-markers.md`.
- `internal/goanalysis.relevantDynMarkers`.
- Structural repair rules in `internal/evaluator` and `internal/research`.

### Cost/trade-off

The marker catalog requires maintenance and may leave cases unresolved when semantics are opaque.

### What a different approach must do instead

A competing design may use language-level control-flow proofs, runtime instrumentation, or formal API contracts. It must detect missing-call semantics and relevant dynamic behavior rather than assuming direct call absence is safe.

---

## ADR-016 — Authoritative large proofs use complete, hash-bound sidecars

**Classification:** Complete proof persistence and replay are essential; sidecars are implementation-specific.

### Context/problem

A display payload can exceed ordinary observation limits. Persisting only a prefix destroys the proof while leaving an apparently plausible artifact.

### Options considered

1. **Chosen:** Store a bounded observation envelope plus a complete typed, content-addressed sidecar referenced by path, digest, size, and selector.
2. Raise the display cap until current cases fit.
3. Store a truncated prefix and call it the proof.
4. Store only a summary/count and discard the typed result.

### Decision

Authoritative symbol-unreachability results retain their complete typed payload in a sidecar. The authority route rehydrates and verifies it. Missing, altered, undecodable, or digest-mismatched sidecars fail closed.

Ordinary non-authoritative observations may still be truncated and downgraded to partial.

### Invariant protected

A persisted proof must mean the same thing as the in-memory proof that produced the decision.

### Enforcement

- `evidencetools.ObservationPayloadRef`.
- `internal/research.capObservationPayload`.
- `LaneResult.persist`.
- `internal/research.validate`.
- `internal/research.replay`.
- `deterministic_payload_test.go`.

### Cost/trade-off

There are more files and digest relationships to validate. Sidecar lifecycle and retention become operational concerns.

### What a different approach must do instead

A competing design may store a single immutable case bundle, a database BLOB, a Merkle tree, or a signed proof certificate. It must preserve the complete authoritative proof and verify integrity during replay.

---

## ADR-017 — Verification requests, calls, audit rows, and observations pair one-to-one

**Classification:** Essential audit integrity; the exact record types are implementation-specific.

### Context/problem

A verification plan can appear complete if only successful actions are persisted. Missing, duplicated, or mismatched observations can hide skipped checks.

### Options considered

1. **Chosen:** Enforce one-to-one pairing:

   ```text
   declared request
     ↔ dispatched call
     ↔ session audit record
     ↔ observation
   ```

2. Persist only observations that returned useful data.
3. Trust the audit log without comparing it to declared requests.
4. Deduplicate by observation ID alone.

### Decision

Every executed request has exactly one matching observation, including a typed error observation when dispatch fails. Unexecuted requests form an explicit tail. Extra, duplicate, mismatched, or skipped rows make the trace incomplete.

### Invariant protected

The authority route cannot claim complete verification when a planned check was silently omitted or replaced.

### Enforcement

- `internal/research.RunVerificationPlanAudited`.
- `internal/research.verification.go`.
- `flowTraceFromRecords` and `renumberFlowObservations`.
- `internal/research.VerifyDecision`.
- `flow_adapter_test.go`, `verification_test.go`.

### Cost/trade-off

The trace is stricter and more verbose. Provider/tool failures become visible rather than disappearing from the result.

### What a different approach must do instead

A different architecture may use signed workflow events, transaction IDs, or a deterministic execution ledger. It must demonstrate complete correspondence between planned checks, executed checks, recorded observations, and the final decision.

---

## ADR-018 — A ticket package-version mismatch is a refusal, not a conclusion

**Classification:** Essential identity correctness.

### Context/problem

A ticket may describe package version `A` while the analyzed source/artifact contains version `B`. Answering the ticket using `B` can produce a technically correct answer to the wrong question.

### Options considered

1. **Chosen:** Block the package-version axis and require analysis of the ticket’s actual build.
2. Analyze the available build and mention the mismatch as a warning.
3. Use the ticket’s version for the verdict while using the available source for evidence.
4. Treat the mismatch as a normal product-version drift.

### Decision

`TICKET_PACKAGE_VERSION_MISMATCH` blocks an out-of-range or package-version conclusion. The system refuses to answer for the other build. Product-version mismatch alone is informational and does not substitute for package identity.

### Invariant protected

A result cannot be transferred between dependency builds merely because the product ticket appears related.

### Enforcement

- `internal/affected.checkTicketClaims`.
- `domain.AffectedResult.VersionAxisBlocked`.
- `internal/affected.Resolve`.
- Ticket guard tests in `internal/affected` and `internal/research`.

### Cost/trade-off

Operationally, more source/artifact retrieval is required. Some tickets remain unresolved until their actual build is supplied.

### What a different approach must do instead

A competing system may use a signed package manifest, SBOM, or build attestation as the ticket identity. It must refuse when the declared package/build cannot be reconciled with the analyzed artifact.

---

## ADR-019 — Human-owned assumptions use a separate typed channel

**Classification:** Separation is essential; `declared-assumptions/1` is implementation-specific.

### Context/problem

Some conclusions depend on policy or scope statements not derivable from source code: for example, administrator-managed configuration is outside the attacker model, or the product supports only Linux.

### Options considered

1. **Chosen:** Carry assumptions through a digest-pinned, typed, scoped assumptions document.
2. Encode assumptions as configuration evidence.
3. Infer them from field tags, host OS, deployment mode, or CLI convenience flags.
4. Put them in free-form report prose.

### Decision

Assumptions have their own schema, IDs, owners, source references, digest, scope, and review date. They are prerequisites for certain routes but are never evidence by themselves.

### Invariant protected

A policy premise cannot be mistaken for a measured code fact.

### Enforcement

- `internal/domain/assumptions.go`.
- `internal/repository.LoadDeclaredAssumptions`.
- CLI `--declared-assumptions`.
- Separate `AssumptionIDs` in claims, affected results, and verdicts.
- Report sections in `internal/report`.
- Replay integrity tests.

### Cost/trade-off

The operator must supply and maintain structured policy inputs. Expired, malformed, or wrong-scope assumptions block dependent conclusions.

### What a different approach must do instead

Another architecture may use signed policy bundles, an authorization service, deployment control-plane facts, or a formal threat-model document. It must keep policy provenance separate from evidence and enforce scope.

---

## ADR-020 — G1 is an exact post-reach configuration-origin route

**Classification:** The guarantee is essential; the named G1 route and falsifier names are implementation-specific.

### Context/problem

A configuration-derived trigger may be trusted under an explicit threat-model assumption, but configuration tags alone do not prove safety. Conversely, tracing configuration origin without proving that the vulnerable sink is reached says nothing about the vulnerability.

### Options considered

1. **Chosen:** Require all of:
   - affected applicability is true;
   - exact vulnerable sink has positive reach;
   - exact nonnegative trigger `ArgIndex`;
   - complete advisory-bound sink closure;
   - every live sink site has a matching exact-site `DataFlow`;
   - every exact flow is `OriginConfiguration`;
   - valid product-scope `AssumptionConfigTrust`;
   - independent negative verification.
2. Treat any configuration-tagged value as trusted.
3. Use a global “cluster is trusted” flag without exact code provenance.
4. Declare safe from package presence plus a configuration assumption.

### Decision

G1 can produce only:

```text
ClaimFalse
FalsifierTrustedInfrastructure
FalsifierBasis=BasisConfigOrigin
NegativeVerification=VERIFIED
NO_EXPLOIT_PATH_FOUND
```

It can never produce `NOT_AFFECTED`.

### Invariant protected

A trust-grounded negative must be based on exact code evidence, exact argument binding, complete sink coverage, and an explicit policy premise.

### Enforcement

- `internal/evaluator/postreach.go`.
- `internal/goanalysis.TraceArgumentBound`.
- `internal/goanalysis.sinkclosure`.
- `internal/goanalysis.negative.verifySinkClosure`.
- `internal/research.VerifyDecision`.
- `domain.GroundBasis`, `domain.AssumptionIDs`.

### Cost/trade-off

The route is narrow. One unresolved sink, external write, wrong argument, alias, reflection marker, or missing assumption preserves `INCONCLUSIVE`.

### What a different approach must do instead

A competing architecture may use an information-flow proof, runtime configuration provenance, or a policy-aware formal model. It must prove positive vulnerable-sink reach and complete exact trigger coverage before using trusted configuration as a falsifier.

---

## ADR-021 — G2 treats vulnerable implementation presence as an affected-chain fact

**Classification:** The separation from G1 is essential; the implementation-locus proposal schema is implementation-specific.

### Context/problem

An LLM or analyst may identify a platform-specific vulnerable implementation. The system must verify that the proposed file, function, marker, and build expression correspond to the analyzed source and selected target.

### Options considered

1. **Chosen:** Admit a typed LLM implementation-locus proposal, then deterministically verify identity, source, AST location, marker, build expression, target selection, and alternate implementations.
2. Trust the LLM’s claim that the vulnerable file is excluded.
3. Treat any excluded source file as proof that the package is unaffected.
4. Reuse `BuildRelevant` for implementation-file presence.

### Decision

A complete deterministic absence proof sets `VulnerableImplementationPresent=FALSE` in the affected chain and yields `NOT_AFFECTED`. Failed or incomplete verification yields `UNKNOWN`, not absence.

### Invariant protected

Platform-specific implementation absence is neither a trusted-input falsifier nor a package-level shortcut.

### Enforcement

- `internal/domain/implementation.go`.
- `internal/research` strict proposal parsing and admission.
- `internal/affected.VerifyImplementationLocus`.
- `internal/affected.EvaluateImplementationAxis`.
- `internal/domain.ProductTarget`.
- `internal/evaluator.verdict`.

### Cost/trade-off

The verifier must inspect alternate implementations and target provenance. A wrong or incomplete proposal is unusable.

### What a different approach must do instead

A compiler/linker-based design may prove which implementation was selected using object files, symbol maps, or build manifests. It must still establish source identity, target identity, and complete alternate-selection coverage.

---

## ADR-022 — Symbol-less advisories use a distinct exploit-locus binding route

**Classification:** The need for complete advisory-bound coverage is essential; the proposal artifact and binding implementation are specific.

### Context/problem

A symbol-less advisory may describe a vulnerable behavior without structured affected symbols. A product-facing trigger sink can be the right analysis subject, but allowing an LLM to invent one would silently widen authority.

### Options considered

1. **Chosen:** Use a typed `exploit-locus-proposals/1` hypothesis containing vulnerable symbol, product-facing sink, exact trigger argument, and advisory quote/reference; deterministically verify the binding and complete reverse sink enumeration.
2. Put the proposed sink directly into the advisory’s declared symbol set.
3. Bind only the vulnerable implementation symbol.
4. Treat any plausible product call as the complete sink set.
5. Reuse the implementation-locus route even though the required facts differ.

### Decision

The route is admitted only when the selected advisory entry is genuinely symbol-less. The verifier proves:

- advisory and snapshot identity;
- vulnerable symbol existence;
- sink signature and exact argument;
- typed trigger-preservation path;
- complete product-facing sink enumeration;
- absence of unresolved candidates.

If advisory enrichment adds structured symbols, the `symbol-less-entry` gate rejects this route; the ordinary declared-symbol route must be used.

### Invariant protected

A proposal cannot manufacture advisory-wide coverage or substitute a different authority scope.

### Enforcement

- `internal/domain/exploitlocus.go`.
- `internal/affected.VerifyExploitLocus`.
- `internal/goanalysis.triggerpath`.
- `internal/goanalysis.SinkSetBasis`.
- `internal/research.exploitlocus_lane`.
- `symbol-less-entry` validation and exploit-locus tests.

### Cost/trade-off

Symbol-less cases may remain unresolved even when a human can describe a plausible trigger. Cross-module sink binding requires a separate verified relation and cannot be added casually to ordinary advisory coverage.

### What a different approach must do instead

Another architecture may use a vulnerability behavior specification, a manually curated exploit contract, or runtime-derived trigger discovery. It must still bind the trigger to the advisory, prove exact argument flow, and enumerate all relevant product-facing carriers.

---

## ADR-023 — Bind target facts to the artifact/build, not the host

**Classification:** Artifact/build identity is essential; the target precedence and `ProductTarget` type are implementation-specific.

### Context/problem

The analyzer host may run on a different OS/architecture from the shipped product. A source checkout or `go.mod` does not necessarily identify the release toolchain or target.

### Options considered

1. **Chosen:** Prefer target facts from artifact build info, then authoritative release metadata, then explicit operator target; use host defaults only for ordinary analysis and never for a product-wide implementation absence conclusion.
2. Use `runtime.GOOS`/`runtime.GOARCH`.
3. Use the local `go.mod` or current toolchain.
4. Treat one artifact’s target as the complete product target matrix.

### Decision

Target facts record source and scope:

```text
artifact build info
  → release metadata
  → explicit operator declaration
  → host default
```

Artifact target facts are bound to artifact digest, binary member, and build-info digest. Product-wide target conclusions require an admissible product-scope supported-target assumption.

### Invariant protected

A host fact or artifact-local fact cannot silently become a product-wide claim.

### Enforcement

- `internal/domain.ProductTarget`.
- `internal/repository.ResolveReleaseArtifact`.
- `internal/repository.buildInfoTarget`.
- `internal/repository.resolveProductTarget`.
- `internal/affected.implementationTargetScope`.
- `AssumptionSupportedTargets`.

### Cost/trade-off

The system may refuse a product-wide implementation conclusion when only artifact-scoped facts are available.

### What a different approach must do instead

A competing design may use signed release manifests, CI provenance, container metadata, or a full supported-target registry. It must distinguish artifact, release, operator, and host scope.

---

## ADR-024 — Deployment and perimeter facts remain separate from code evidence

**Classification:** Separation of deployment facts, policy, and code evidence is essential; the two named perimeter profiles are implementation-specific.

### Context/problem

A vulnerability may be exploitable under an untrusted-peer model but not reachable from outside a cluster. Missing manifests or sibling-service metadata cannot prove the analyzed product’s perimeter.

### Options considered

1. **Chosen:** Attribute deployment facts to the exact product owner, classify perimeter conservatively, and evaluate separate `zero_trust` and `cluster_perimeter` profiles.
2. Infer isolation from any nearby deployment manifest.
3. Treat missing manifests as internal-only.
4. Merge perimeter assumptions into source-level exploitability.

### Decision

Deployment evidence is separately collected and owner-bound. Perimeter classification distinguishes public, cluster-internal, and unknown. Trust-grounded results retain `ground_basis` so operator assertion, detected perimeter, and code-level configuration origin are not conflated.

### Invariant protected

Deployment uncertainty cannot be silently treated as attacker exclusion.

### Enforcement

- `internal/exposure.ScanDeployWithOptions`.
- `internal/exposure.ClassifyPerimeter`.
- Exact owner matching in `internal/exposure`.
- Profile handling in `internal/states`.
- `domain.GroundBasis`.

### Cost/trade-off

Deployment files may be incomplete or difficult to attribute. The same code can legitimately yield different profile results without changing the code-level evidence.

### What a different approach must do instead

A competing design may consume a service mesh policy, cloud inventory, runtime reachability graph, or authenticated deployment API. It must prove product ownership and distinguish measured topology from operator policy.

---

## ADR-025 — Knowledge semantics are declarative and versioned

**Classification:** Externalizing reusable semantic knowledge is implementation-specific; rejecting silent semantic conflicts is essential for reproducibility.

### Context/problem

Source classification, passthrough functions, sanitizers, listeners, and configuration tags are reusable semantic facts. Hard-coding them throughout the analyzer makes behavior difficult to audit and update.

### Options considered

1. **Chosen:** Maintain a declarative knowledge base with a recorded digest and reject conflicting overrides.
2. Embed all semantics in evaluator code.
3. Allow arbitrary per-case overrides.
4. Ask the LLM to infer semantics at runtime.

### Decision

Knowledge is data with provenance, digest, and deterministic loading. Missing knowledge degrades to `UNKNOWN`; conflicting definitions are rejected rather than silently replaced.

### Invariant protected

A semantic rule used in a proof must be reproducible and inspectable.

### Enforcement

- `internal/goanalysis/knowledge.go`.
- Knowledge digest in evidence.
- Configuration and provenance evaluators.
- Knowledge-base agent rules.

### Cost/trade-off

The knowledge file requires governance and compatibility management. Conservative unknowns remain when the knowledge base lacks a needed semantic.

### What a different approach must do instead

A competing system may use compiler annotations, a formal API contract registry, a proof-producing library model, or a versioned rules database. It must pin and expose the semantics used by the proof.

---

## ADR-026 — Reports are auditable artifacts, not chat answers

**Classification:** Human-auditability requirement; Markdown language and VEX formats are implementation-specific.

### Context/problem

A chat response tends to compress uncertainty, omit provenance, and obscure which facts were measured versus assumed. Security triage requires a durable artifact that can be reviewed later.

### Options considered

1. **Chosen:** Generate a self-contained report with an inverted-pyramid summary, verdict, evidence references, assumptions, limitations, scope, replay metadata, and machine-readable projections.
2. Return only a conversational answer.
3. Return only a machine-readable verdict.
4. Let the report renderer recompute or reinterpret the decision.

### Decision

The report is a projection of the authoritative decision and evidence. It must clearly distinguish:

- conclusion;
- affectedness basis;
- exploit condition status;
- falsifier and negative verification;
- evidence;
- assumptions;
- limitations;
- human triage actions;
- replay identity.

The report layer cannot alter the decision.

### Invariant protected

A reviewer must be able to audit not only what the system concluded, but why it was entitled to conclude it.

### Enforcement

- `internal/report/report.go`.
- `internal/report/openvex.go`.
- `internal/research.render`, `assemble`, and `validate`.
- `report.json`, `report.md`, `report.en.md`, OpenVEX, and CycloneDX projections.

### Cost/trade-off

Reports are longer and require schema compatibility across human and machine consumers. Multiple projections create consistency obligations.

### What a different approach must do instead

A competing design may use a signed JSON proof bundle, an audit database, or a structured case-management record. It must preserve the same distinction between decision, evidence, assumptions, limitations, and replay identity.

---

# 4. Essential versus implementation-specific decisions

The following classification is the core comparison aid.

## 4.1 Requirements that any acceptable architecture must satisfy

A competing solution must preserve these properties even if every component is structurally different:

1. **Exact case identity**: it cannot answer for a different package build, source revision, or artifact.
2. **No absence-to-safety shortcut**: empty search output is insufficient without a complete proof.
3. **Explicit uncertainty**: unresolved scope, provenance, dynamic behavior, or identity remains unresolved.
4. **Affectedness/exploitability distinction**: implementation absence, symbol unreachability, and attacker-control failure remain distinct propositions.
5. **Evidence provenance**: a reviewer can reconstruct the facts used.
6. **Independent negative verification**: a negative is checked for coverage and bypasses independently of the first search.
7. **Complete scope accounting**: failed inputs, omitted packages, unresolved candidates, and bounds are visible.
8. **Policy/evidence distinction**: assumptions are not source facts.
9. **Replayability**: persisted proof and inputs are sufficient to reproduce the decision without an LLM conversation.
10. **Human triage**: unresolved results explain what remains unknown and what evidence would settle it.
11. **Advisory coverage integrity**: the system cannot silently replace the advisory’s subject universe with a narrower or model-selected one.
12. **Deterministic or independently checked authority**: the final conclusion must be controlled by a reproducible authority layer, not unsupported prose.

## 4.2 Legitimate implementation choices

A competing architecture may differ legitimately in:

- language and compiler infrastructure;
- static, dynamic, hybrid, or formal evidence;
- graph representation versus event log or proof certificate;
- sidecar versus database versus monolithic case bundle;
- one-pass versus staged execution;
- LLM use versus no LLM;
- advisory source and normalization format;
- exact verdict enum names;
- target metadata source;
- deployment topology source;
- report format;
- VEX support;
- use of an external sound analyzer instead of custom call/provenance analysis.

## 4.3 Conditional decisions

Some decisions are mandatory only if the corresponding capability exists:

- **LLM proposal-only boundary**: vacuous in a no-LLM design; mandatory if an LLM is used.
- **Runtime evidence identity**: mandatory if runtime traces or reproductions can affect a verdict.
- **Artifact target binding**: mandatory for target-dependent claims; unnecessary for a target-independent advisory.
- **G1 configuration-origin route**: optional as a capability, but any architecture offering this conclusion must satisfy its exact provenance and scope guarantees.
- **G2 implementation-presence route**: optional as a capability, but any architecture offering platform-specific `NOT_AFFECTED` must prove selected implementation absence.

---

# 5. Invariant and guarantee matrix

| Guarantee | Enforcement in this solution | What a competing approach must demonstrate | Black-box comparison test |
|---|---|---|---|
| No safe-negative from an empty search | Falsifier plus `NegativeVerification=VERIFIED`; `internal/goanalysis.Verifier`; `internal/evaluator.verdict` | A complete proof of a mandatory false condition, not merely an empty result | Remove a relevant call from the analyzer’s visible scope or inject a hidden candidate; safe-negative must disappear |
| `NOT_AFFECTED` is applicability-only | Affected chain and `VulnerableImplementationPresent`; verdict order in `internal/evaluator/verdict.go` | Implementation/package/version/build absence is distinct from symbol reachability | Keep package linked but remove product calls; result must not become `NOT_AFFECTED` solely from unreachability |
| Symbol unreachability is not package absence | `packageAbsenceDecision`, `ProductUsage`, `VerifyUnreachable` | Separate propositions and verdict mappings | Compare package absent, package present/symbol unused, and package present/symbol used fixtures |
| Skipped packages remain in scope | `Index.load`, `SkippedPackages`, `ProductUsage` | Failed or omitted inputs must remain visible and block closure | Add a reference only to a package that fails to type-check; negative must be blocked |
| May-call empty is closed only when enumeration is closed | `MayCallSites` open flag and sentinel contract | Explicit closed/open result semantics | Return an empty list with an unresolved candidate; system must remain unresolved |
| Interface narrowing is sound | `InterfaceDispatchSites`, `dispatchGaps`, receiver-instantiation proof | Concrete receiver universe must be complete before removal | Test instantiated receiver, uninstantiated receiver with complete inventory, and unavailable inventory |
| Bounds cannot support hidden certainty | Named limits and limitations | Every exhaustion/truncation/timeout must be visible and non-authoritative | Force a trace or load bound; result must remain unresolved |
| Large authoritative proof survives persistence | Typed sidecar, digest, size, selector, rehydration | Complete proof must be retained and integrity-checked | Delete or mutate proof payload after collection; replay must fail closed |
| Replay does not require the LLM | `internal/research.replay`, retained proposals and policy pins | Persisted inputs and proof must reproduce decision without model invocation | Disable model access and replay a prior case; decision should reproduce or fail explicitly |
| Trace completeness is auditable | One-to-one request/call/audit/observation pairing | Missing, duplicate, extra, or mismatched actions must invalidate completeness | Remove one audit row or alter tool arguments; negative must be refused |
| LLM cannot create authority | Strict typed proposals and `VerifyDecision` | Model output must be independently re-derived | Supply a proposal containing a false verdict or false negative verification; it must be rejected |
| Assumptions are not evidence | Separate assumption schema/IDs and report section | Policy inputs must be scoped, digest-pinned, and distinct from measured facts | Remove config-trust assumption while preserving config-origin data flow; G1 must not close |
| Exact argument provenance | `TraceArgumentBound`, exact `ArgIndex`, per-site `DataFlow` | Must prove the actual trigger argument, not merely sink or field identity | Make argument zero trusted and argument one external; only the exact relevant argument may determine the result |
| G1 requires positive reach and complete coverage | `postreach`, sink closure, config origin, assumption, negative verifier | Exact vulnerable sink reach, exact argument, all live sites, and policy scope | Add an unresolved alternate sink or external write; route must remain unresolved |
| G2 implementation absence is target-bound | `VerifyImplementationLocus`, `EvaluateImplementationAxis`, `ProductTarget` | Must prove selected implementation absence under the shipped target and alternate scan | Put the vulnerable marker in the selected alternate; `NOT_AFFECTED` must disappear |
| Ticket identity is enforced | `checkTicketClaims`, `VersionAxisBlocked` | Must refuse to answer a ticket for another package build | Change only the ticket package version; result must become refusal/unresolved |
| Symbol-less route cannot widen authority | `VerifyExploitLocus`, `symbol-less-entry`, `SinkSetBasis` | Proposal must be advisory-bound and complete; enriched symbol advisories need another route | Add structured symbols to the advisory; symbol-less proposal must no longer close |
| Deployment trust is not source proof | Exposure owner attribution and `GroundBasis` | Topology and policy must remain separate from code-level provenance | Remove manifests or add a sibling service; product isolation must not be inferred |
| Report is a projection, not a decision engine | `assemble`, `render`, `report`, pure verdict evaluator | Editing presentation must not change the underlying decision | Alter report prose or projection fields; authoritative decision digest/result must remain unchanged |
| Human triage remains possible | Explicit limitations, scope, evidence, assumptions, and next blockers | An unresolved result must identify the missing evidence and decision boundary | Create an open dispatch case; reviewer must see the unresolved receiver and required settling evidence |

---

# 6. Where a different architecture could legitimately differ

The owner should not expect structural agreement in the following areas. The comparison should focus on guarantees and evidence.

## 6.1 LLM in or out of the loop

This solution permits LLM assistance for semantic interpretation, root-cause proposals, exploit-locus proposals, gap planning, and review, but not authority.

A competing solution may:

- omit the LLM entirely;
- use an LLM only for intake;
- use an LLM to generate a formal proof obligation;
- use a local model instead of a remote provider;
- use human-authored propositions.

The deciding evidence is whether the final claim and negative verification are independently re-derived from typed evidence.

## 6.2 Static, dynamic, hybrid, or formal evidence

This solution primarily uses deterministic source/build analysis, with optional runtime evidence represented as typed observations.

A competing solution may use:

- dynamic instrumentation;
- sandboxed exploit reproduction;
- symbolic execution;
- model checking;
- compiler/linker metadata;
- signed SBOMs and build attestations;
- a hybrid staged proof.

The deciding evidence is whether the method can establish both positive exploitability and negative falsifiers with reproducible identity and scope. Runtime evidence must itself be bound to the exact artifact, input, environment, and execution trace.

## 6.3 Static call graph versus another reachability model

This solution uses `govulncheck` and custom Go analysis for direct usage, function values, interfaces, provenance, ingress, and sink closure.

A competitor may use:

- whole-program points-to analysis;
- bytecode analysis;
- linker reachability;
- runtime profiles;
- sound over-approximation;
- dynamic call traces.

The deciding evidence is the behavior on hidden calls, failed loads, interface dispatch, callbacks, reflection, and function values. A system that simply returns “no path” for an open scope is not equivalent.

## 6.4 State machine versus single-pass pipeline

This solution persists explicit states and allows restart/replay.

A competitor may use:

- a transactionally persisted DAG;
- an append-only event log;
- a single immutable proof bundle;
- a batch job with deterministic checkpoints.

The deciding evidence is recovery after interruption, preservation of intermediate evidence, and the ability to identify exactly which prerequisite prevented a conclusion.

## 6.5 Evidence graph versus proof certificate or relational store

The `EvidenceGraph` is one representation. A competing design may store:

- signed proof certificates;
- relational evidence rows;
- Merkle-linked events;
- object storage blobs;
- a graph database;
- a single case archive.

The deciding evidence is whether every claim can be traced to immutable, identity-bound, scope-complete observations and whether the artifact can be replayed.

## 6.6 Sidecar versus monolithic artifact

This solution externalizes large authoritative typed payloads while retaining a bounded envelope.

A competing design may:

- store everything in one content-addressed archive;
- put proof objects in a database;
- use chunked Merkle storage;
- serialize a compact formal proof instead of raw enumerations.

The deciding evidence is mutation, truncation, missing-chunk, and replay tests. A display prefix must never be accepted as the complete proof.

## 6.7 Exact verdict names and VEX projection

A competitor may use statuses such as `not_applicable`, `safe_by_proof`, `confirmed`, and `needs_review`.

The deciding evidence is semantic mapping:

- applicability absence is distinct from path falsification;
- positive exploitability is distinct from unresolved reachability;
- policy-grounded safety is distinguishable from code-grounded safety;
- machine consumers receive a stable reason and evidence basis.

## 6.8 Advisory and vulnerability-model source

This solution accepts OSV, Go vulnerability data, and tickets, then keeps advisory-declared subjects separate from verified defect loci.

A competitor may use:

- CVE/CPE;
- vendor advisories;
- SBOM-native vulnerability records;
- manually authored exploit specifications;
- patch-diff semantics;
- behavior-level vulnerability contracts.

The deciding evidence is whether the architecture preserves advisory scope and can explain any narrowing or enrichment without silently changing the question.

## 6.9 Deployment and perimeter evidence

This solution scans deployment artifacts and uses exact owner attribution, with separate trust profiles.

A competitor may use:

- a live cluster API;
- service-mesh authorization policy;
- cloud graph;
- network reachability measurement;
- operator-signed deployment declarations.

The deciding evidence is whether facts are attributed to the product under analysis and whether missing topology remains unknown.

## 6.10 Human answer format

This solution uses auditable JSON, Markdown, OpenVEX, and CycloneDX projections.

A competing design may provide:

- a security case-management record;
- a signed JSON document;
- a dashboard;
- a formal proof package;
- a ticket comment generated from structured data.

The deciding evidence is whether a reviewer can reconstruct the exact conclusion, evidence, assumptions, limitations, and reproduction identity without consulting an ephemeral conversation.

---

# 7. Open architectural questions

These are unresolved questions or owner-gated capabilities. They do not justify weakening current guarantees.

## OQ-001 — What authoritative evidence may establish positive exploitability?

**Decision needed:** Whether to add a production-grade runtime observation, dynamic trace, or reproducible exploit capability.

**Current boundary:** Static reachability/use does not establish attacker control or runtime exploitability. Cases with positive static use but unresolved input control remain `INCONCLUSIVE`.

**Consequence:**

- Without the capability, positive-use cases remain unresolved.
- With it, the system needs artifact-bound runtime identity, attacker-input provenance, sandbox policy, reproducible traces, and replay validation.

The current roadmap explicitly treats this as owner-gated rather than as a reason to infer either `EXPLOITABLE` or `NO_EXPLOIT_PATH_FOUND`.

## OQ-002 — How should cross-module trigger bindings be governed for symbol-enriched advisories?

**Decision needed:** Whether to authorize a generic cross-module exploit-locus binding when an advisory has structured symbols but the product-facing trigger sink is in another module.

**Current boundary:** The symbol-less exploit-locus route is rejected by `symbol-less-entry` once the advisory is enriched with declared symbols. Ordinary sink closure does not accept an unrelated external sink merely because it appears logically connected.

**Consequence:**

- Current architecture remains conservative and may leave such cases `INCONCLUSIVE`.
- A new route would need a typed relation contract, advisory coverage semantics, exact sink/argument identity, and complete reverse enumeration.

## OQ-003 — What is the governance process for declared assumptions?

**Decision needed:** Who may author, review, expire, revoke, and scope `config-trust` and `supported-targets` assumptions?

**Current boundary:** Assumptions are digest-pinned, owner-attributed, scoped, and review-dated. Missing, expired, or wrong-scope assumptions block dependent conclusions.

**Consequence:** Without governance, the technical separation remains correct but operational trust in the policy channel may be insufficient for automated triage.

## OQ-004 — What release artifact is authoritative when source, artifact, and release metadata conflict?

**Decision needed:** Whether artifact build info, signed release metadata, CI provenance, or another source has final precedence for each fact.

**Current boundary:** Artifact build information outranks release metadata and operator target declarations for artifact-bound facts; host defaults cannot ground product-wide implementation conclusions.

**Consequence:** Conflicting authoritative artifact facts must remain a fail-closed condition until the precedence policy is explicit.

## OQ-005 — How should external artifact acquisition be trusted?

**Decision needed:** Whether remote artifacts may be fetched during analysis, and which signatures, credentials, mirrors, and retention rules are required.

**Current boundary:** Artifact acquisition is bounded, digest-recorded, and fail-closed on unsafe archives, size limits, credentials, or identity mismatch.

**Consequence:** Without an authenticated acquisition policy, the analyzer can still operate on local artifacts but cannot silently treat a downloaded artifact as authoritative.

## OQ-006 — What is the acceptable completeness standard for runtime and plugin behavior?

**Decision needed:** Whether runtime evidence can close cases involving plugins, reflection, `unsafe`, generated code, or external callbacks.

**Current boundary:** Unresolved dynamic behavior blocks static negative verification.

**Consequence:** A runtime route could reduce `INCONCLUSIVE`, but only if its observation scope is itself complete enough for the claimed conclusion.

## OQ-007 — How should proof schemas evolve without invalidating historical replay?

**Decision needed:** Versioning and migration policy for evidence, proposal, assumption, and decision artifacts.

**Current boundary:** Schemas are strict and unknown fields are rejected in proposal/assumption channels. Replay revalidates persisted artifacts.

**Consequence:** Future schema changes require explicit versioned validators and preservation of the old verifier for historical cases or a documented migration proof.

## OQ-008 — What level of product-wide target support can be asserted from release evidence?

**Decision needed:** Whether a release manifest can establish a complete supported-target matrix or only facts about one artifact.

**Current boundary:** Artifact-scoped target facts cannot satisfy a product-wide implementation-presence conclusion without a product-scope supported-target assumption.

**Consequence:** The system may require owner declarations even when an artifact’s build info is authoritative for that artifact.

---

# Comparison worksheet

| Requirement | This solution’s decision | Acceptable alternative(s) | Evidence that would settle the comparison |
|---|---|---|---|
| Prevent false-safe negatives | Explicit falsifier plus independent negative verification; no path found is insufficient | Sound abstract interpretation, formal proof, runtime counterexample/falsifier | Hidden-path and incomplete-scope tests; show no safe-negative under omitted or dynamic paths |
| Distinguish applicability from exploitability | Separate affected chain from exploit conditions and reachability | Linker/object proof, SBOM applicability plus separate exploit model | Package-present/symbol-unused/package-absent fixtures with distinct outcomes |
| Preserve uncertainty | `INCONCLUSIVE` for unresolved scope, identity, provenance, or conditions | Equivalent `NEEDS_REVIEW`/`UNKNOWN` states | Inject unresolved dispatch, failed load, expired assumption, or contradictory identity |
| Enforce exact build identity | Refuse ticket package-version mismatch rather than answer for another build | Signed SBOM, image digest, build attestation | Change only ticket package version; result must refuse or remain unanswerable |
| Make evidence auditable | Typed evidence graph, tool executions, hashes, scope, and limitations | Signed proof bundle, event log, evidence database | Reconstruct a verdict from persisted artifacts without console history |
| Replay without the LLM | Persisted proof, proposals, assumptions, and policy pins are revalidated | No-LLM deterministic architecture, formal certificate replay | Disable model access and replay; output must match or fail explicitly |
| Keep LLM non-authoritative | LLM emits typed proposals only | No LLM; proof-producing model with independent checker | Inject forged verdict/claim/negative-verification fields into model output |
| Preserve advisory coverage | Advisory-declared symbols remain authoritative scope; locus narrowing is separate and verified | Behavior-level vulnerability contract or vendor-provided canonical locus | Enrich a symbol-less advisory; verify the old proposal route no longer closes |
| Handle skipped packages safely | Failed packages remain in denominator and block negatives | Require successful reproducible build or use complete binary analysis | Add hidden reference in a package that fails type-checking |
| Handle function values and callbacks | Closed/open may-call contract; open candidates block negatives | Exact whole-program points-to graph or runtime call graph | Return empty results with unresolved candidates; negative must remain unresolved |
| Handle interface dispatch | Narrow only with complete receiver-instantiation proof | Sealed-type proof, linker devirtualization, runtime type profile | Test instantiated, uninstantiated, and unavailable receiver inventories |
| Make bounds honest | Bounds are recorded; exhaustion is a blocker | Unbounded/incremental engine with explicit resource accounting | Force timeout, payload truncation, or trace-hop exhaustion |
| Preserve large proofs | Complete typed authoritative sidecar with digest and replay validation | Monolithic archive, database BLOB, Merkle proof | Delete, mutate, or truncate proof storage and replay |
| Pair audit records | One request ↔ call ↔ audit row ↔ observation | Signed execution ledger or transaction log | Remove, duplicate, or alter one action; authority must refuse closure |
| Separate assumptions from evidence | Typed, scoped, digest-pinned assumptions with separate IDs | Signed policy bundle or threat-model service | Remove/expire config-trust or target-scope assumption |
| Prove config-origin safety | G1 requires positive exact reach, exact `ArgIndex`, complete sink closure, exact flows, and config-trust assumption | Formal information flow or runtime config provenance | Add external write, wrong argument, unresolved sink, or missing assumption |
| Prove platform-specific implementation absence | G2 proposal plus deterministic source/build/alternate verification | Compiler/linker selection proof | Put vulnerable marker in selected alternate implementation |
| Bind target to artifact/build | Artifact build info outranks host; product-wide claims require product scope | Signed release manifest or CI provenance | Analyze artifact built for another OS than the host |
| Keep package absence distinct from symbol unreachability | Package closure and symbol closure have separate falsifiers and verdict routes | Unified authoritative linker graph with separate predicates | Compare absent package, linked unused symbol, and linked used symbol |
| Handle symbol-less advisories | Separate exploit-locus binding with `symbol-less-entry` gate and complete reverse sink enumeration | Manually authored behavior contract or dynamic trigger discovery | Add structured advisory symbols; proposal must no longer be accepted as symbol-less |
| Preserve deployment uncertainty | Exact owner attribution and separate perimeter/trust bases | Live topology graph or signed deployment inventory | Remove manifests or add sibling service; no inferred isolation |
| Produce an auditable human answer | Report is a durable artifact, not an ephemeral chat answer | Signed case record, dashboard backed by immutable evidence | Ask an independent reviewer to reproduce the conclusion from the report alone |
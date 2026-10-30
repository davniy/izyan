# Справка: архитектура и статус vuln-analyzer

**Назначение:** самостоятельный reference для независимого ревью и сравнения с альтернативным решением.
**Источник:** delegated `architect` artifact `agent://ModuleReference` (2026-10-20), сохранён дословно.
**Состояние дерева:** `4b25b64` (цикл: `500b367` → `d3f53c6` → `e22223f` → `785f407` → `4b25b64`).
**Измерения:** census 7 `NOT_AFFECTED` / 1 `NO_EXPLOIT_PATH_FOUND` / 10 `INCONCLUSIVE`; corpus `false-safe=0`; guard PASS.

---

# Vuln-analyzer architecture and status reference

**Repository state:** `4b25b64`  
**Cycle commits:** `500b367` → `d3f53c6` → `e22223f` → `785f407` → `4b25b64`

This document describes the implemented architecture, guarantees, measured status, remaining limits, and review method. It does not introduce a redesign.

## 1. Purpose and invariant contract

### 1.1 Purpose

The module determines whether a specific vulnerability applies to a specific product snapshot and whether the mandatory exploit conditions are established for that snapshot.

The unit of analysis is:

```text
advisory + product source/artifact + commit/build context + deployment/configuration inputs
```

The intended output is not merely “the dependency is present” or “a vulnerable function is reachable.” The output is a reproducible chain:

```text
affectedness
  → root cause / exploit locus
  → mandatory exploit conditions
  → deterministic evidence
  → TRUE / FALSE / UNKNOWN claims
  → negative verification
  → terminal verdict
```

The workflow states are defined in `internal/domain/domain.go:40-53`.

### 1.2 Safety invariant

The governing invariant is:

> Absence of a found exploit path is not evidence that exploitation is impossible.

A safe negative requires an explicit falsifier and an independent negative-verification step. The implementation documents this contract in `AGENTS.md`, `docs/how-it-works.md`, and `internal/evaluator/verdict.go:11-19`.

The safety boundary is therefore:

```text
LLM reasoning / operator assertions
    → typed proposal or policy input
    → deterministic source/build/evidence verification
    → claim
    → negative verification
    → deterministic verdict
```

LLM prose, CVSS, EPSS, PoC availability, package presence, import presence, or an isolated call path do not independently establish exploitability or safety.

### 1.3 Terminal verdicts

| Verdict | Meaning | Required basis |
|---|---|---|
| `NOT_AFFECTED` | The vulnerable component or implementation is not applicable to the analyzed product build. | A deterministic FALSE in the affected chain: module presence, version applicability, package presence, build relevance, or verified vulnerable-implementation presence. |
| `EXPLOITABLE` | Every mandatory exploit condition is TRUE and no unresolved mandatory subject remains. | Deterministic evidence for all mandatory conditions; no unresolved model subjects. |
| `NO_EXPLOIT_PATH_FOUND` | At least one mandatory condition is FALSE and its falsifier passed negative verification. | `ClaimFalse` + named falsifier + `NegativeVerification=VERIFIED`. |
| `INCONCLUSIVE` | Applicability, scope, provenance, dispatch, deployment, advisory coverage, or exploit conditions remain unresolved. | Explicit limitations and incomplete/unknown claims; no forced conclusion. |

`internal/evaluator/verdict.go:11-19` makes the separation explicit:

- `NOT_AFFECTED` is produced only from the affected-resolution chain.
- `NO_EXPLOIT_PATH_FOUND` requires a verified FALSE claim.
- An undecidable version axis remains `INCONCLUSIVE`.
- No LLM or external state is consulted by the final verdict function.

### 1.4 Affectedness contract

The affected chain is:

```text
module present
  → version affected
  → package present
  → build relevant
  → vulnerable implementation present
```

The first four axes are represented in `domain.AffectedResult`; the fifth is the cycle's implementation-presence axis (`internal/domain/domain.go:184-200`). `internal/states/states.go:100-215` stops before root-cause analysis only when one of these axes is deterministically FALSE.

A symbol-level unreachability result is never `NOT_AFFECTED`. It is a `NO_EXPLOIT_PATH_FOUND` route.

### 1.5 Negative-evidence contract

A FALSE claim must identify:

- the mandatory condition;
- the falsifier;
- code evidence IDs;
- any independent negative-verification record;
- limitations and scope;
- separate policy-assumption IDs, where applicable.

`domain.NegativeVerification` deliberately carries code evidence only. Declared assumptions are carried separately on claims and verdicts (`internal/domain/domain.go:592-608`, `635-657`).

Examples of valid falsifiers include:

- `package-absent`;
- `locus-package-absent`;
- `locus-function-unreached`;
- `declared-symbol-unreached`;
- `constant-or-generated-input`;
- `trusted-infrastructure`;
- `config-feature-disabled`;
- `loopback-only`;
- `snapshot-fact-mismatch`;
- `guards`;
- `missing-pair-member`.

Examples of invalid shortcuts include treating an empty result, a missing call, or a package import as a proof without a complete scope contract.

---

## 2. Architecture

### 2.1 Layered component model

| Layer | Main components | Responsibility | Authority |
|---|---|---|---|
| Repository and snapshot | `internal/repository`, `SnapshotProduct`, `repository.Snapshotter` | Pin source path, commit, Go/toolchain/build context, binary metadata, manifests, and product identity. | Authoritative for the selected snapshot and recorded artifact facts. |
| Ticket and advisory intake | `internal/tracker`, `internal/vulnerability`, `internal/advfeed` | Normalize tracker claims and OSV/advisory data; bind package/version claims to the analyzed build. | Parsed, digest-bound input; never silently substitutes another build. |
| Release artifact channel | `internal/repository/artifact.go:ResolveReleaseArtifact` | Read local/HTTPS release artifacts, build info, module graph, and target facts under explicit archive/download bounds. | Artifact build info is authoritative for the selected artifact. |
| Affected resolver | `internal/affected/resolver.go:42`, `GoResolver.Resolve` | Resolve module/version/package/build applicability using Go module and package graph facts. | Deterministic affected chain. |
| Implementation axis | `internal/affected/implementation.go:156-238`, `EvaluateImplementationAxis` | Verify whether a proposed vulnerable implementation is selected under the recorded target/build context. | Deterministic source/build verifier; only complete absence can feed `NOT_AFFECTED`. |
| Root cause and exploit model | `internal/rootcause`, `internal/exploit` | Localize the defect, separate defect locus from transport/dispatch symbols, and construct mandatory conditions. | Deterministic source validation; LLM proposals are hypotheses only. |
| Go evidence tools | `internal/goanalysis`, `internal/evidencetools`, `govulncheck` | Load typed Go source, collect usage/reachability, call paths, provenance, sink/ingress closures, dynamic markers, platform facts, and exposure facts. | Deterministic evidence with explicit completeness and bounds. |
| Evaluators | `internal/evaluator` | Convert evidence into `TRUE`, `FALSE`, or `UNKNOWN` claims. | Deterministic claim semantics. |
| Workflow | `internal/states`, `internal/workflow` | Execute the persistent state machine and preserve honest stop states. | State transitions are deterministic and persisted. |
| Research lane | `internal/research` | Run bounded deterministic checks, optional LLM-assisted proposals, audit pairing, authority verification, replay, and decision assembly. | `VerifyDecision` and deterministic lane authority; proposals do not set verdicts. |
| Exposure and risk | `internal/exposure`, `internal/risk` | Classify inbound exposure and calculate zero-trust versus cluster-perimeter profiles and contextual triage. | Deterministic deployment/code facts; operator policy remains distinguishable. |
| Assumptions | `internal/domain/assumptions.go`, `internal/repository/assumptions.go` | Carry human-owned configuration-trust and supported-target assertions separately from code evidence. | Explicit, digest-pinned policy input; never evidence by itself. |
| Reporting | `internal/report` | Produce `report.json`, Markdown reports, OpenVEX, CycloneDX, tracker-ready rationale, evidence references, limitations, and replay metadata. | Projection of the case; not an independent source of truth. |

### 2.2 Evidence and authority data flow

The effective data flow is:

```text
advisory / ticket / source / artifact / deployment inputs
    ↓
snapshot + advisory normalization
    ↓
affected chain
    ↓
root cause / exploit model
    ↓
goanalysis + govulncheck + exposure + artifact tools
    ↓
EvidenceGraph
    ├── Evidence records
    ├── CallPaths
    ├── DataFlows
    ├── SinkClosures / IngressClosures
    ├── ModuleUsages / ModuleReachable
    ├── ToolExecutions
    └── Limitations
    ↓
deterministic condition evaluators
    ↓
Claims: TRUE / FALSE / UNKNOWN
    ↓
negative verification and structural review
    ↓
VerdictEvaluator
    ↓
report and VEX projections
```

`EvidenceGraph` and its audit fields are defined in `internal/domain/domain.go:757-1033`. Tool invocations record command, arguments, exit code, duration, and output hashes through `ToolExecution`.

An evidence record is not automatically authoritative merely because it exists. The relevant consumer must validate:

- identity;
- subject/module binding;
- completeness;
- scope;
- argument or receiver binding;
- dynamic markers;
- persisted artifact digest;
- audit pairing.

### 2.3 Repository, artifact, and identity layer

The source snapshot records commit, Go version, target platform, release toolchain, module directives, build tags, and optional binary/artifact facts. `internal/states/states.go:45-81` records snapshot evidence before advisory resolution.

The release-artifact channel is bounded and fail-closed:

- local binary or ZIP, or HTTPS artifact;
- SHA-256 artifact identity;
- embedded Go build info;
- binary member identity;
- build-info digest;
- module graph;
- target facts where present.

`internal/repository/artifact.go:19-42` defines artifact bounds and `ResolveReleaseArtifact` at `internal/repository/artifact.go:126-223`.

The ticket-build identity guard is separate from artifact resolution:

- `500b367` added ticket intake/provenance;
- `d3f53c6` added the version-axis refusal;
- `internal/affected/ticket.go:120-228` compares the ticket package/version to the resolved analyzed package/version.

A package-version mismatch blocks the version-axis conclusion. A product-version mismatch alone is informational. The analyzed build must not answer a ticket about a different package build.

### 2.4 Go analysis evidence layer

`internal/goanalysis.Index` is a lazily loaded `go/packages` view of the product and selected dependency packages (`internal/goanalysis/source.go:1-28`).

The cycle established one shared load configuration:

- same `GOOS`, `GOARCH`, and `CGO_ENABLED`;
- same build tags;
- same vendor/toolchain environment;
- same cancellation context;
- same configuration for product loads, dependency extras, importer census, and module reach.

`internal/goanalysis/source.go:359-425` implements `loadConfig` and records failed packages as structured `SkippedPackage` entries rather than silently dropping them.

The tools distinguish:

- a closed empty scan;
- an empty result after failed or incomplete loading;
- a positive reference;
- an open dynamic/dispatch candidate set.

`ProductUsage` is explicitly three-state (`USED`, `NOT_USED`, `UNKNOWN`) and documents the scope required for a verified negative (`internal/goanalysis/usage.go:1-118`). Incomplete product packages, exhausted load budgets, unresolved dispatch, function-value candidates, and dynamic markers retain `UNKNOWN`.

`MayCallSites` has the closed/open contract in `internal/goanalysis/toolscope.go:12-79`:

```text
([], false, nil) = the only closed empty result
```

`Possible` candidates, sentinels, unresolved candidates, load failures, generation churn, or exhausted bounds keep the enumeration open.

Interface dispatch remains conservative in `internal/goanalysis/coverage.go:113-233`; narrowing occurs only after a complete receiver-instantiation probe. `internal/goanalysis/unreachability.go:519-611` propagates incomplete receiver or skipped-package scope as a limitation.

### 2.5 Provenance, sink closure, and ingress closure

`DataFlow` records exact sink argument index, origin, transformations, source, and sink (`internal/domain/domain.go:791-815`).

The relevant origin classes include:

- external/untrusted;
- configuration;
- constant;
- generated;
- internal service;
- database;
- unknown.

A safe origin is not inferred merely from a configuration tag. External writes, unresolved aliases, address-taken fields, reflection/dynamic writes, callbacks, and opaque transformations retain external or unknown influence.

`SinkClosure` and `IngressClosure` make completeness explicit (`internal/domain/domain.go:849-919`):

- `Basis` identifies why a sink set is exhaustive;
- `Complete` identifies whether enumeration closed;
- `Blockers` name missing or unresolved scope;
- a prefix or partial list is not treated as a complete set.

### 2.6 Evaluator and verdict layer

The evaluator order is governed by `docs/agent-rules/evaluators.md` and implemented under `internal/evaluator`.

The important distinction is:

```text
package/module presence ≠ symbol reachability ≠ trigger reachability ≠ attacker control
```

The final verdict is a pure deterministic function (`internal/evaluator/verdict.go:11-19`). It does not access the filesystem, LLM, database, or network.

For incomplete exploit models, a FALSE claim may ground `NO_EXPLOIT_PATH_FOUND` only if it covers all unresolved subjects or uses a route whose coverage semantics explicitly include them. `config-origin` claims cover only the exact, complete sink set that was traced; they do not globally cover unresolved sinks.

### 2.7 Research lane and LLM boundary

The research lane supports:

- deterministic symbol-unreachability checks;
- implementation-locus proposals;
- exploit-locus proposals;
- bounded verification plans;
- agent/research reports;
- audit-bound observations;
- replay.

The LLM layer is proposal-generating only. `internal/llm/client.go:1-5` states the invariant directly. `internal/llm/exploit.go:57-145` shows that model output is merged only after deterministic subject validation, and invalid/failing output either falls back or fails under `--strict-llm`.

The LLM may:

- interpret advisory text and fix diffs;
- propose root causes or loci;
- propose exploit conditions;
- propose a next verification action;
- identify possible gaps;
- review claims and recommend demotion.

The LLM may not:

- create deterministic evidence;
- set `ClaimFalse`;
- set `NegativeVerification=VERIFIED`;
- establish `NOT_AFFECTED`;
- establish `NO_EXPLOIT_PATH_FOUND`;
- widen a safe conclusion;
- bypass a failed identity, scope, digest, or completeness check.

`--deterministic-only` disables model calls. `--strict-llm` fails closed on model/provider failure rather than silently falling back.

### 2.8 Assumptions channel

`declared-assumptions/1` carries two human-owned input classes:

- `config-trust`;
- `supported-targets`.

The contract is defined in `internal/domain/assumptions.go:23-53` and loaded by `internal/repository/assumptions.go:19-30`.

Each assumption carries:

- ID;
- kind;
- statement;
- scope;
- authority and owner;
- source reference;
- digest;
- validity/review date;
- optional target matrix.

Scope is material:

- product-wide scope can satisfy narrower scope requirements;
- artifact/deployment/config scope cannot satisfy a product-wide requirement;
- an artifact target does not prove the supported target matrix of the product.

The CLI exposes the channel at `cmd/izyan/main.go:97-101` and `cmd/izyan/research.go:101-115`.

Assumptions are not added to `EvidenceGraph`, are not `EvidenceKind.CONFIGURATION`, and cannot produce a verdict alone. Reports render them in a separate section (`internal/report/report.go:57-62`, `850-890`).

### 2.9 G1: exact-argument post-reach configuration route

The post-reach route is implemented in `internal/evaluator/postreach.go:75-211,228-304`.

It requires all of:

```text
affected applicability = TRUE
+ exact vulnerable sink has positive reach
+ exact nonnegative trigger ArgIndex
+ complete advisory-bound sink closure
+ every live sink site has CONFIGURATION origin
+ every live sink site has matching persisted DataFlow
+ admissible product-scope config-trust assumption
```

Only then does it produce:

```text
ClaimFalse
FalsifierTrustedInfrastructure
FalsifierBasis=BasisConfigOrigin
NegativeVerification=VERIFIED
NO_EXPLOIT_PATH_FOUND
```

It can never produce `NOT_AFFECTED`.

### 2.10 G2: implementation-presence route

`VerifyImplementationLocus` validates an LLM-inferred implementation proposal against:

- frozen advisory identity and quote;
- snapshot identity;
- module/package/file confinement;
- AST function or binding marker;
- canonical build expression;
- recorded `go/build.Context`;
- selected and alternate implementations.

The verifier is documented in `internal/affected/implementation.go:156-238`. Failed checks return UNKNOWN; only complete absence may feed the affected chain.

`ProductTarget` is the recorded target fact used by this route (`internal/domain/target.go:9-72`). Host defaults do not establish product-wide target support.

### 2.11 Exploit-locus binding for symbol-less advisories

The exploit-locus channel is implemented in:

- `internal/domain/exploitlocus.go`;
- `internal/affected/exploitlocus.go:1-223`;
- `internal/goanalysis/triggerpath.go:1-18,126-176`;
- `internal/research/exploitlocus_lane.go:1-112`.

The proposal names:

- vulnerable package/symbol;
- product-facing sink package/symbol;
- exact trigger argument;
- advisory-bound quote/reference.

The deterministic binder proves:

- proposal/advisory identity;
- vulnerable symbol existence;
- sink signature and argument identity;
- typed trigger-preservation path;
- complete reverse enumeration of product-facing carriers.

A failed or open binding remains `INCONCLUSIVE`. It cannot produce `NOT_AFFECTED`.

### 2.12 Deployment, perimeter, and risk

`internal/exposure/deploy.go:80-82` scans local paths, extra paths, and archives. Facts carry an owner so deployment resources can be attributed to the analyzed product.

`ClassifyPerimeter` in `internal/exposure/perimeter.go:25-47` distinguishes:

- `cluster-internal`;
- `public`;
- `unknown`.

Exact owner matching is required for product attribution (`internal/exposure/perimeter.go:138-168`). Same-prefix sibling services do not establish the product's isolation. Missing manifests do not prove isolation.

The workflow evaluates two profiles in `internal/states/states.go:1811-1944`:

- `zero_trust`;
- `cluster_perimeter`.

Trust-grounded negatives carry `ground_basis` so a deployment assertion or auto-detected perimeter cannot be mistaken for code-level unreachability.

### 2.13 Reporting, replay, and provenance

`internal/report/report.go:20-54` writes:

- `report.json`;
- `report.md`;
- `report.en.md`;
- `openvex.json`;
- `cyclonedx.json`.

OpenVEX maps:

- `EXPLOITABLE` → `affected`;
- `NOT_AFFECTED` → `not_affected`;
- `NO_EXPLOIT_PATH_FOUND` → `not_affected` with a path/grounding justification;
- `INCONCLUSIVE` → `under_investigation`.

`internal/report/openvex.go:1-119` preserves the distinction between code-level unreachability and trust-grounded claims.

#### Authoritative proof sidecars

The persisted observation payload is bounded at 256 KiB for ordinary observations. Non-authoritative oversized observations are explicitly truncated and downgraded to PARTIAL.

Symbol-unreachability payloads are different:

- full typed payload is written to a content-addressed sidecar;
- the wire observation contains only an envelope and `PayloadRef`;
- sidecar SHA-256, size, and selector are persisted;
- the authority route rehydrates and verifies the complete payload;
- missing, altered, undecodable, or digest-mismatched sidecars fail closed.

The mechanism is implemented in `internal/evidencetools/observation.go:69-90` and `internal/research/deterministic.go:2267-2350`.

#### Verification trace pairing

`RunVerificationPlanAudited` requires one-to-one pairing among:

```text
declared request
  ↔ dispatched call
  ↔ session audit record
  ↔ observation
```

Missing requests, extra audit rows, duplicate observation IDs, mismatched tools/arguments, skipped actions, errors, or incomplete observations make the trace incomplete (`internal/research/verification.go:78-155`; authority binding in `internal/research/decision.go:315-383`).

#### Replay

`internal/research/replay.go:19-47` rebuilds persisted runs without a model call. Replay validates:

- report and contract extensions;
- assumptions;
- proposal artifacts;
- persisted agent attempts;
- pinned artifacts and digests;
- externalized observation payloads.

Replay is not a trust shortcut: it revalidates the persisted input and refuses malformed or hand-edited authoritative material.

### 2.14 Knowledge base

`internal/goanalysis/knowledge.go:24-32,96-115,411-418` provides a declarative knowledge base for:

- source functions;
- passthrough functions;
- sanitizers;
- listener APIs;
- configuration tags.

The effective knowledge base has a SHA-256 digest recorded in evidence. Missing knowledge degrades provenance to UNKNOWN; conflicting overrides are rejected rather than silently replacing built-in semantics.

---

## 3. What was built in this cycle

### 3.1 Capability-to-commit matrix

| Commit | Capability | Mechanism and code locations | Status |
|---|---|---|---|
| `500b367` | Ticket intake replaces metadata-sidecar identity | Typed tracker intake in `internal/tracker/intake.go`, ticket projection in `internal/domain/ticket.go` and `internal/research/ticket.go`; ticket claims become persisted input identity. | Built. |
| `d3f53c6` | Ticket-build identity guard | `internal/affected/ticket.go:checkTicketClaims`; package-version mismatch blocks the version axis instead of answering for another build. | Built and retained. |
| `e22223f` | One `go/packages` load context; skipped packages remain in denominator | `internal/goanalysis/source.go:loadConfig`, `load`, `skippedPackageDiagnostic`; `toolscope.go` diagnostics; `usage.go:ProductUsage`. | Built. |
| `e22223f` | Authoritative proof persistence | `internal/evidencetools/observation.go:ObservationPayloadRef`; `internal/research/deterministic.go:capObservationPayload`; replay/validation rehydration. | Built. |
| `785f407` | Closed/open may-call contract | `internal/goanalysis/toolscope.go:MayCallSites`, `funcvalues.go:funcValueCallSites`, extras-generation handling. | Built. |
| `785f407` | Conservative interface-dispatch narrowing | `internal/goanalysis/coverage.go:InterfaceDispatchSites`, `unreachability.go:dispatchGaps`, `source.go:receiverTypeInstantiated`. | Built. |
| `785f407` | Trace pairing and authority binding | `internal/research/flow_adapter.go:flowTraceFromRecords`, `verification.go`, `decision.go`. | Built. |
| `785f407` | Package-absence/build-usage reconciliation | `internal/research/decision.go:packageAbsenceDecision`, `packagePresenceConflict`, `hasPositiveUse`. | Built; case 10 moved to a verified negative. |
| `4b25b64` | `declared-assumptions/1` | `internal/domain/assumptions.go`, `internal/repository/assumptions.go`, CLI/research/report validation. | Built. |
| `4b25b64` | G1 exact post-reach configuration route | `internal/evaluator/postreach.go`, sink closure and provenance verification, separate assumption IDs. | Built; case 03 remains blocked by advisory subject scope. |
| `4b25b64` | G2 implementation-locus route | `internal/domain/implementation.go`, `internal/affected/implementation.go`, `EvaluateImplementationAxis`, `ProductTarget`. | Built; case 04 ticket-backed run closed. |
| `4b25b64` | Exploit-locus proposal and verifier | `internal/domain/exploitlocus.go`, `internal/affected/exploitlocus.go`, `internal/goanalysis/triggerpath.go`, research lane. | Built; enriched case 03 correctly refuses the symbol-less route. |

### 3.2 Case-04 flow

Inputs:

```text
source: va-tmp/demo-product-1.1.1-2397
artifact: va-tmp/am-1.10.3/package/bh/demo-product
target: linux/amd64
assumptions: va-tmp/declared-assumptions-owner-2026-10-20.json
```

The artifact resolves the ticket build identity and records the target. The implementation-locus proposal identifies the vulnerable implementation as platform-specific. The deterministic verifier checks source identity, file/marker, build expression, selected Linux implementation, and alternate implementations.

Measured result:

```text
vulnerable_implementation_present = FALSE
target = linux/amd64
scope = product
assumption = ASM-TARGET-LINUX-001
verdict = NOT_AFFECTED
coverage = COMPLETE
```

The affected chain stops at the implementation-presence axis. This is correctly `NOT_AFFECTED`, not a reachability-based `NO_EXPLOIT_PATH_FOUND`.

Measured artifact:

```text
va-tmp/r6-final/art-1103/case-04-final/report.json
```

The corporate census still lists case 04 as `INCONCLUSIVE` because the census harness did not pass the identity-aligned source, artifact, and assumption inputs. That is a harness-input status, not a contradiction of the ticket-backed run.

### 3.3 Case-03 flow

The same ticket-aligned source/artifact/assumption inputs resolve the package identity. With `--osv-feed`, the advisory is enriched with `GO-2026-4526` and 39 declared symbols.

The exploit-locus proposal route is intentionally rejected:

```text
symbol-less-entry
```

The advisory is no longer structurally symbol-less, so a proposal for the symbol-less `xmlquery.QueryAll` → XPath route cannot be substituted for the ordinary declared-symbol route.

The ordinary declared-symbol route remains open:

```text
may_call = 127
dependency sites = 3
NodeIterator.MoveNext = 2 live dependency call sites
```

Because declared-symbol coverage and may-call closure are unresolved, the G1 exact-argument configuration route is not evaluated as a closing proof. The result remains:

```text
INCONCLUSIVE
```

It must not become `NOT_AFFECTED`, and it must not become `NO_EXPLOIT_PATH_FOUND` from the configuration assumption alone.

Measured artifact:

```text
va-tmp/r6-final/art-1103/case-03-final/report.json
```

### 3.4 Case-10 flow

Case 10 initially had an open may-call/product-usage condition and contradictory package/build facts. The cycle:

1. preserved the complete symbol proof in a sidecar;
2. kept package absence distinct from symbol absence;
3. rejected positive package-usage evidence as a blocker;
4. allowed absence only when the package/build closure was complete and reconciled.

Measured final result:

```text
NO_EXPLOIT_PATH_FOUND / COMPLETE
changed = 1
```

Measured artifact:

```text
va-tmp/r6-final/fresh-artifacts/case-10/report.json
```

### 3.5 Cases 07/08 flow

Cases 07 and 08 load the same general evidence route, but product packages are excluded because the IBM MQ SDK prerequisite is unavailable. The current reports record:

```text
may_call = 1009
dispatch = 14
limitations = 39
```

The concrete blocker is the absent IBM MQ client/C header environment, including `cmqc.h`. The loader now keeps those packages in the scope denominator and reports the compiler/build failure. The result remains `INCONCLUSIVE`.

---

## 4. Verification matrix

The matrix distinguishes controller-run evidence from implementer-reported focused checks. Private artifacts are cited by path only; their contents are not reproduced here.

| Measurement | Command / procedure | Result | Evidence type | Artifact or source path |
|---|---|---|---|---|
| Repository gates | `go vet ./...`; `go test ./...`; repository gofmt gate | Final tree: gofmt clean, vet clean, tests green. | Controller-run | `4b25b64`; source contracts in `AGENTS.md` |
| Corpus expectations | `izyan eval --corpus eval/corpus-real.json -j 4` | All 38 expectations match; `false-safe=0`. A parallel run completed 31 cases; the 7 `SNAPSHOT_PRODUCT=0s` cases pass individually with matching expectations. | Controller-run, with environment artifact noted | `eval/corpus-real.json`; `eval/README.md` |
| Corpus serial controls | `izyan eval --corpus eval/corpus-real.json --case <case-id>` for the 7 parallel-affected cases | Individual runs pass with expected verdicts; the `0s` failures are run-environment artifacts, not verdict changes. | Controller-run | `eval/corpus-real.json`; per-case reports are emitted by the eval runner [INFERENCE: exact output directory is not supplied in the brief] |
| Corporate census | `python3 va-tmp/r6-final/run_census_artifacts.py` [exact controller flags are recorded by the private runner; not available in the repository] | 18 tickets: 7 `NOT_AFFECTED`, 1 `NO_EXPLOIT_PATH_FOUND`, 10 `INCONCLUSIVE`. | Controller-supplied measured run | `va-tmp/r6-final/census-artifacts-comparison.json`; `va-tmp/r6-final/run_census_artifacts.py` |
| Census guard | Same census artifact-generation procedure | `R6-GUARD PASS`; `deterministic_safe=7/18`; `false_safe=0`. | Controller-run | `va-tmp/r6-final/census-artifacts-comparison.json` |
| Case 04 ticket-backed | Research lane with source `va-tmp/demo-product-1.1.1-2397`, artifact `va-tmp/am-1.10.3/package/bh/demo-product`, `--goos linux --goarch amd64`, declared assumptions, and the case-04 advisory/proposal inputs | `NOT_AFFECTED/COMPLETE`; `vulnerable_implementation_present=FALSE`; product-scoped Linux target; `ASM-TARGET-LINUX-001`. | Controller/owner-supplied measured run | `va-tmp/r6-final/art-1103/case-04-final/report.json` |
| Case 03 ticket-backed | Same ticket-backed invocation, plus `--osv-feed <local OSV feed>` | `INCONCLUSIVE`; enriched advisory has 39 symbols; exploit-locus binding refuses `symbol-less-entry`; `may_call=127`, `dep_sites=3`, two live `NodeIterator.MoveNext` sites. | Controller/owner-supplied measured run | `va-tmp/r6-final/art-1103/case-03-final/report.json`; `va-tmp/r6-final/agent-proposals/` |
| Cases 07/08 build prerequisite | Re-run under the recorded Linux/amd64 build context with real IBM MQ SDK headers/libraries; current run used the available environment | Current evidence remains open: `may_call=1009`, `dispatch=14`, 39 limitations; IBM MQ packages excluded because `cmqc.h`/SDK prerequisites are absent. | Controller-supplied measured run | `va-tmp/r6-final/fresh-artifacts/<case>/report.json`; source ticket inputs under `va-tmp/r6-final/tickets/` |
| Case 10 absence reconciliation | `izyan research`/deterministic lane using the case-10 snapshot and advisory | `NO_EXPLOIT_PATH_FOUND/COMPLETE`; package/build facts reconcile; full symbol proof persists in sidecar. | Controller-run | `va-tmp/r6-final/fresh-artifacts/case-10/report.json` |
| Shared load-context negative controls | `go test -run 'TestLoadEnv\|TestSkipped\|TestProductUsage\|TestLoadConfig' ./internal/goanalysis` | Implementer-reported focused load/skip/product-usage controls pass; failed packages remain visible and block negative scope. | Implementer-reported focused test | `internal/goanalysis/source.go:loadConfig`, `internal/goanalysis/toolscope.go`, `internal/goanalysis/usage.go` |
| May-call/function-value controls | `go test ./internal/goanalysis` | Implementer/controller focused suite passes; possible candidates, sentinels, unresolved candidates, and open generation state remain open. | Implementer/controller focused test; final full gate controller-run | `internal/goanalysis/funcvalues.go`, `toolscope.go`, `unreachability.go` |
| Dispatch controls | `go test ./internal/goanalysis` | Receiver-instantiation narrowing is allowed only with complete scope; unresolved receiver or skipped package remains a limitation. | Implementer/controller focused test | `internal/goanalysis/coverage.go`, `unreachability.go`, `source.go` |
| Trace-pairing controls | `go test ./internal/research` | Implementer-reported tests cover missing audit rows, extra rows, duplicate IDs, mismatched arguments, skipped actions, and positive complete control. | Implementer-reported focused test; final full gate controller-run | `internal/research/flow_adapter.go`, `verification.go`, `decision.go` |
| Sidecar controls | `go test ./internal/research ./internal/evidencetools` | Implementer-reported tests cover oversized typed payload round-trip, complete/open symbol proofs, sidecar tamper/removal/digest failure, and ordinary truncation regression. | Implementer-reported focused test | `internal/research/deterministic.go:capObservationPayload`; `internal/evidencetools/observation.go` |
| G2 implementation controls | `go test ./internal/affected ./internal/domain ./internal/research` | Implementer-reported controls cover wrong module/version/file/function/marker/build expression, selected alternate marker, and Linux exclusion. | Implementer-reported focused test | `internal/affected/implementation.go`; `internal/research/implementation_axis_test.go` |
| G1 configuration controls | `go test ./internal/evaluator ./internal/states ./internal/research ./internal/report` | Implementer-reported controls cover missing/expired assumptions, external writes, alias/reflection writes, unresolved subjects, wrong argument, and `--trusted-peer` non-substitution. | Implementer-reported focused test | `internal/evaluator/postreach.go`; `internal/research/decision.go` |

---

## 5. Gap and risk register

The following dispositions are the roadmap's current classifications. They are not forecasts of new results.

| Case | Disposition | Current evidence/status | Stop condition |
|---|---|---|---|
| 01 | **Unapproved capability** | Positive use/reachability is already established: 4 product references and module-internal reach. The missing fact is authoritative attacker-controlled input/runtime exploitability. | Remains `INCONCLUSIVE` unless the owner approves and supplies the positive exploitability/input-control capability. Better absence enumeration cannot safely close it. |
| 02 | **Unapproved capability** | Positive use/reachability is established: 2 product references and 2 module-internal chains. | Same: no `EXPLOITABLE` without approved positive input/control evidence; no safe negative from static reachability. |
| 03 | **Bounded engineering** | Identity-aligned ticket-backed run is valid but remains open on the enriched 39-symbol advisory: `may_call=127`, 3 dependency sites, 2 live `NodeIterator.MoveNext` sites. The symbol-less exploit-locus route correctly refuses. | Any unresolved declared symbol, open may-call/dispatch scope, or positive trigger path keeps `INCONCLUSIVE`. G1 requires exact sink coverage and cannot substitute for the enriched declared-symbol route. |
| 04 | **Bounded engineering / census harness wiring** | Ticket-backed run is already `NOT_AFFECTED/COMPLETE` through G2. The census remains `INCONCLUSIVE` because its invocation did not carry the exact artifact/source/assumption inputs. | Until census wiring supplies identity-aligned inputs, the census status cannot be treated as equivalent to the ticket-backed result. |
| 07 | **External input** | Real IBM MQ SDK/header/library context is missing. Current run has `may_call=1009`, `dispatch=14`, and 39 limitations; failed packages are now named rather than excluded. | Missing `cmqc.h` or any incomplete package load blocks closure. After SDK availability, unresolved may-call, dispatch, dynamic, or trace scope still blocks a negative. |
| 08 | **External input** | Same IBM MQ SDK prerequisite and bounded-closure dependency as case 07. | Same: no syntax-only stub or empty result may close the case. |
| 15 | **External input** | No agent turn and no retained independently verifiable falsifier proposal; `executed=false`, `plan_status=no agent turn`. | Without a typed, advisory-bound proposal and independently verifiable evidence, the case remains `INCONCLUSIVE`. |
| 16 | **External input** | Same state as case 15. | Same. |
| 17 | **Unapproved capability** | `amqp091-go.Channel.Qos` is already `USED`; the unresolved question is whether the relevant negative input is attacker-controlled or operator-controlled. | Static usage cannot answer input control. The case remains `INCONCLUSIVE` unless the owner approves/supplies the positive input-control capability. |
| 18 | **Unapproved capability** | Same positive usage and unresolved input-control question as case 17. | Same. |

### Cases that are not remaining gaps

Case 10 is closed by the final cycle measurement:

```text
NO_EXPLOIT_PATH_FOUND/COMPLETE
```

Under the supplied owner inputs, no case is structurally irreducible. However:

- cases 03 and 04 were correctly refused before identity-aligned ticket artifacts were supplied;
- cases 07 and 08 remain uncloseable without the external IBM MQ SDK;
- cases 01, 02, 17, and 18 remain intentionally unresolved without an approved positive exploitability/input-control capability.

### Rejected shortcuts and broken invariants

| Rejected shortcut | Invariant it breaks |
|---|---|
| Treat `len(MayCallSites)==0` as closed absence. | `internal/goanalysis/toolscope.go:12-79`: only `([], false, nil)` is closed evidence. |
| Ignore `Possible=true` candidates. | Converts an open function-value or dispatch set into a false closed set. |
| Exclude failed packages from the denominator. | References inside failed packages are invisible; absence cannot be proven. `source.go:397-425`. |
| Treat a 256 KiB payload prefix as the full proof. | A display prefix is not an authoritative typed result. |
| Silently raise the observation cap. | Hides explicit resource bounds and does not solve proof completeness. |
| Let LLM prose or category set FALSE/VERIFIED. | Violates the LLM proposal-only boundary and `VerifyDecision` authority contract. |
| Treat static reachability as `EXPLOITABLE`. | Reachability does not prove attacker control, runtime input, or deployment exposure. |
| Treat package presence as implementation presence. | Package use and selected implementation are separate axes. |
| Treat symbol absence as `NOT_AFFECTED`. | Symbol unreachability is a no-exploit-path claim, not affectedness. |
| Answer a ticket with the currently analyzed build after package-version mismatch. | Violates ticket-build identity; the conclusion would describe another build. |
| Treat a configuration tag as proof of trusted input. | Tags classify configuration decoding; they do not exclude external writes or aliases. |
| Treat `--trusted-peer` as the config-origin assumption. | Operator trust and exact code provenance are different bases. |
| Treat one Linux artifact as proof that the whole product supports only Linux. | Artifact scope cannot satisfy a product-wide target assertion. |
| Admit a symbol-less exploit-locus proposal for an advisory that now declares symbols. | Advisory subject coverage and route identity would be silently widened. |
| Treat absent deployment manifests as cluster isolation. | Missing topology is unknown, not proof of isolation. |

---

## 6. Reviewer guide

### 6.1 Reproduction order

1. Check out the exact tree at `4b25b64`.
2. Run repository gates:
   ```bash
   go vet ./...
   go test ./...
   ```
   Apply the repository's gofmt gate as recorded in `AGENTS.md`.
3. Run the corpus sequentially for reproducibility:
   ```bash
   go run ./cmd/izyan eval \
     --corpus eval/corpus-real.json \
     -j 1
   ```
4. Re-run the seven cases affected by the parallel `SNAPSHOT_PRODUCT=0s` artifact individually with `--case`.
5. Re-run the census controller procedure using:
   ```bash
   python3 va-tmp/r6-final/run_census_artifacts.py
   ```
   The exact private invocation and environment are part of that controller artifact; the script itself is outside the repository snapshot.
6. Re-run the ticket-backed cases with the exact source, artifact, target, ticket, advisory, proposal, and assumptions paths. The known identity-aligned inputs are:
   ```text
   source       va-tmp/demo-product-1.1.1-2397
   artifact     va-tmp/am-1.10.3/package/bh/demo-product
   target       --goos linux --goarch amd64
   assumptions  va-tmp/declared-assumptions-owner-2026-10-20.json
   ```
   Case 03 additionally uses the local OSV feed through `--osv-feed`.
7. Inspect `report.json`, not only console summaries. The report must expose subject scope, evidence IDs, limitations, negative verification, target/assumption IDs, and provenance.

### 6.2 Claims to challenge first

#### A. Any safe negative

Check:

- exact falsifier;
- mandatory condition ID;
- `NegativeVerification=VERIFIED`;
- `EvidenceIDs`;
- whether the relevant sink set is complete;
- skipped packages;
- `MayCallSites` partial/open state;
- interface-dispatch narrowing;
- dynamic markers;
- trace/audit pairing;
- sidecar digest and rehydration.

A safe verdict with only “no references found” or “no call path found” is not sufficient.

#### B. `NOT_AFFECTED`

Check the affected chain in order:

```text
module → version → package → build → implementation
```

The report must state which axis was FALSE and what exact graph/build evidence supports it. A symbol-level no-use result must not be projected as `NOT_AFFECTED`.

#### C. Ticket-backed conclusions

Check that:

- ticket package/version matches the resolved analyzed package/version;
- artifact/source identity is recorded;
- a product-version mismatch has not been confused with a package-version match;
- `TICKET_PACKAGE_VERSION_MISMATCH` is absent before relying on an out-of-range conclusion.

#### D. Case 03

Check that the advisory feed's 39 declared symbols are included in the authority scope. The symbol-less exploit-locus proposal must be rejected after enrichment. A reviewer should challenge any result that uses `xmlquery.QueryAll` as a complete sink for the enriched advisory without a separate generic binding contract.

#### E. Case 04

Check that the Linux target is artifact/product-scoped through `ProductTarget` and `ASM-TARGET-LINUX-001`, rather than inferred from the host operating system or `go.mod`. Check the selected and alternate implementation scan.

#### F. Assumptions

Check that:

- the assumption document is digest-pinned;
- scope is product-wide where required;
- review date is valid;
- assumption IDs are separate from evidence IDs;
- no assumption appears in `EvidenceGraph`;
- an assumption alone cannot produce a verdict.

### 6.3 What would falsify the implementation claims

The following controls should remain fail-closed:

| Falsifying change | Required outcome |
|---|---|
| Add a reference in a skipped product package. | Product usage/unreachability remains UNKNOWN; no safe negative. |
| Return a possible function-value candidate or open sentinel. | `MayCallSites` remains partial; no safe negative. |
| Leave an instantiated unresolved interface receiver. | Dispatch remains open; no safe negative. |
| Remove or alter an authoritative symbol-proof sidecar. | Rehydration or digest validation fails; decision becomes `INCONCLUSIVE`. |
| Remove an audit row or add an unbound audit row. | Trace becomes incomplete; authority route refuses closure. |
| Change a request's tool or canonical arguments. | Authority binding fails. |
| Put the implementation marker in the selected Linux file. | G2 reports implementation present; it must not produce `NOT_AFFECTED`. |
| Change product target scope from product-wide to artifact-only. | Product-wide G2 conclusion is not admissible. |
| Add an external write to the config field. | G1 no longer produces the trusted-infrastructure falsifier. |
| Change the advisory feed from symbol-less to declared-symbol. | Exploit-locus route rejects `symbol-less-entry`; ordinary declared-symbol coverage is required. |
| Change ticket package version from the analyzed artifact version. | Version-axis guard refuses the out-of-range conclusion. |

### 6.4 Tests that pin the contract

| Contract | Primary implementation/tests |
|---|---|
| Verdict separation | `internal/evaluator/verdict.go`; `internal/evaluator/verdict_test.go` |
| Affected-chain implementation axis | `internal/affected/implementation.go`; `internal/affected/implementation_test.go`; `internal/evaluator/verdict.go` |
| Ticket identity guard | `internal/affected/ticket.go`; `internal/affected/ticket_test.go`; `internal/research/ticket_guard_test.go` |
| Shared load context and skipped scope | `internal/goanalysis/source.go`; `loaderenv_test.go`, `source_test.go`, `usage_test.go` |
| Closed/open may-call | `internal/goanalysis/toolscope.go`; `funcvalues.go`; `funcvalues_test.go`, `unreachability_test.go` |
| Dispatch narrowing | `internal/goanalysis/coverage.go`, `unreachability.go`, `coverage_test.go` |
| Package absence reconciliation | `internal/research/decision.go`; `decision_test.go`, `deterministic_symbol_test.go` |
| Sidecar authority | `internal/research/deterministic.go`; `deterministic_payload_test.go`; `internal/research/replay.go`, `validate.go` |
| Trace pairing | `internal/research/flow_adapter.go`; `flow_adapter_test.go`; `verification_test.go` |
| G1 exact argument and assumptions | `internal/evaluator/postreach.go`; `postreach_test.go`; `internal/report/assumptions_test.go` |
| G2 implementation verifier | `internal/affected/implementation.go`; `internal/research/implementation_axis_test.go` |
| Exploit-locus binding | `internal/affected/exploitlocus.go`; `internal/goanalysis/triggerpath.go`; `exploitlocus_test.go` |
| Exposure attribution | `internal/exposure/deploy.go`, `perimeter.go`; `deploy_test.go`, `perimeter_test.go` |
| Replay/provenance | `internal/research/replay.go`; `replay_test.go`; `internal/domain/domain.go:958-1005` |

---

## 7. Comparison axes

A competing implementation is comparable only if it demonstrates the same contract, not merely similar verdict counts.

| Axis | Comparable solution must demonstrate | This solution's evidence |
|---|---|---|
| Unsafe-negative guarantee | `NO_EXPLOIT_PATH_FOUND` requires a mandatory-condition falsifier plus independently verified negative evidence; `INCONCLUSIVE` is not counted as safe. | `internal/evaluator/verdict.go`; `docs/how-it-works.md`; corpus and guard `false-safe=0`. |
| Affectedness separation | `NOT_AFFECTED` must come only from deterministic applicability/build/implementation facts, never from symbol reachability. | `internal/domain/domain.go:184-200`; `internal/evaluator/verdict.go`; G2 implementation axis. |
| Scope completeness | Failed packages, incomplete imports, function values, interface dispatch, dynamic markers, bounds, and missing tools remain explicit blockers. | `source.go:397-425`; `toolscope.go:12-79`; `usage.go:80-118`; `unreachability.go`. |
| Provenance | Every claim must identify evidence IDs, source scope, tool, command, version, and output hashes. | `EvidenceGraph` and `ToolExecution` in `internal/domain/domain.go:958-1005`. |
| Audit integrity | A trace must bind declared requests, actual calls, session audit rows, and observations one-to-one. | `internal/research/verification.go`; `flow_adapter.go`; `decision.go`. |
| Large-proof persistence | An oversized authoritative proof must survive as a complete typed, hash-bound artifact; a display prefix must never underwrite a negative. | `ObservationPayloadRef`; `capObservationPayload`; replay/validation. |
| Replay | A persisted run must be replayable without the LLM, with digests and policy/proposal inputs revalidated. | `internal/research/replay.go`; `RunDeterministic`; proposal and assumption validation. |
| Assumption separation | Human policy/scope inputs must be explicit, scoped, digest-pinned, and separate from code evidence. | `declared-assumptions/1`; `ProductTarget`; report/OpenVEX separation. |
| LLM authority limits | LLM output must remain a typed proposal; deterministic verification must control claims, falsifiers, and verdicts. | `internal/llm/client.go`; `VerifyDecision`; implementation/exploit-locus binders. |
| Identity correctness | A result must be tied to the ticket's package version, artifact/source snapshot, target, advisory digest, and build context. | `internal/affected/ticket.go`; artifact channel; `ProductTarget`; advisory/proposal digest binding. |
| Advisory coverage | Symbol-less and symbol-declared advisories must use distinct routes; partial advisory coverage cannot close a negative. | `VerifyExploitLocus`; `SinkSetBasis`; case-03 refusal. |
| Measurement reproducibility | Corpus, census, guard, and ticket-backed runs must expose commands, environment, inputs, artifacts, and known parallel-run artifacts. | `eval/README.md`; private controller artifacts under `va-tmp/r6-final/`; final measured matrix above. |
| External-input handling | Missing SDKs, deployment facts, ticket artifacts, or runtime evidence must remain named blockers rather than become guessed conclusions. | Cases 03/04/07/08/15/16 and the roadmap disposition. |

## Reviewer entry points

| Claim | File / symbol | Reproduce command | Artifact path |
|---|---|---|---|
| Final repository gates are green | `go vet ./...`; `go test ./...` | `go vet ./... && go test ./...` | `4b25b64`; `AGENTS.md` |
| Corpus has no false-safe result | `cmd/izyan/eval.go:runEval`; `eval/eval.go` | `go run ./cmd/izyan eval --corpus eval/corpus-real.json -j 1` | `eval/corpus-real.json`; `eval/README.md` |
| Census distribution is 7/1/10 | `va-tmp/r6-final/run_census_artifacts.py` | `python3 va-tmp/r6-final/run_census_artifacts.py` [controller flags are private] | `va-tmp/r6-final/census-artifacts-comparison.json` |
| Guard is `deterministic_safe=7/18`, `false_safe=0` | Census guard procedure | Same census controller procedure | `va-tmp/r6-final/census-artifacts-comparison.json` |
| Case 04 is implementation-absent on Linux | `affected.VerifyImplementationLocus`; `EvaluateImplementationAxis` | Ticket-backed `izyan research` with artifact, assumptions, `--goos linux --goarch amd64` | `va-tmp/r6-final/art-1103/case-04-final/report.json` |
| Case 03 refuses enriched symbol-less binding | `affected.VerifyExploitLocus`; `research.laneExploitLocus` | Ticket-backed research with `--osv-feed <local feed>` | `va-tmp/r6-final/art-1103/case-03-final/report.json`; `va-tmp/r6-final/agent-proposals/` |
| Skipped packages block negative scope | `goanalysis.Index.load`; `SkippedPackageDiagnostics`; `ProductUsage` | `go test -run 'TestLoadEnv\|TestSkipped\|TestProductUsage\|TestLoadConfig' ./internal/goanalysis` | `internal/goanalysis/source.go`; `toolscope.go`; `usage.go` |
| Oversized authoritative proofs remain replayable | `capObservationPayload`; `ObservationPayloadRef` | `go test ./internal/research ./internal/evidencetools` | `internal/research/deterministic.go`; `internal/evidencetools/observation.go` |
| Case 10 closes only after absence reconciliation | `packageAbsenceDecision`; `packagePresenceConflict` | `go test ./internal/research ./internal/goanalysis` | `va-tmp/r6-final/fresh-artifacts/case-10/report.json` |
| Exposure attribution is exact-owner and fail-closed | `exposure.ClassifyPerimeter`; `ScanDeployWithOptions` | `go test ./internal/exposure` | `internal/exposure/perimeter.go`; `internal/exposure/deploy.go` |
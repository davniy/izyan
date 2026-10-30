# Снижение INCONCLUSIVE: разбор 11 кейсов корп-корпуса

**Статус:** ANALYSIS ONLY — проработка архитектора, код не изменялся.
**Источник:** delegated `architect` artifact `agent://InconclusiveReduction` (2026-10-19), сохранён дословно.
**Вход:** 18 реальных тикетов (`va-tmp/r6-final/tickets/`), отчёты `va-tmp/r6-final/fresh-artifacts/<case>/report.json`, дерево на `500b367`.

---

# Conclusion

The 11 `INCONCLUSIVE` cases are not one problem.

- **3 cases are primarily bounded engineering friction:** 07, 08, 10.
- **6 cases require a new proof capability:** 01, 02, 15, 16, 17, 18.
- **2 cases are correctly refused under the current inputs:** 03, 04.

The smallest safe reduction is therefore to close the deterministic source-scope pipeline first. **[INFERENCE] If those three cases re-run with no newly discovered positive path, they move to `NO_EXPLOIT_PATH_FOUND`, changing the census from 7 negatives / 11 inconclusive to 10 negatives / 8 inconclusive.** That is a forecast, not an observed result: a closed may-call analysis could discover a real call and leave a case inconclusive.

---

## 1. Classification of all 11 cases

Classification is by the blocker that remains after mechanical scope/trace problems are repaired. Cases may also contain secondary friction, but each appears in exactly one primary class.

| Case / ticket | Class | Report limitation / evidence | Producer |
|---|---|---|---|
| 01 / CASE-223852 | **(b) New capability** | `symbol-unreachability for module github.com/antchfx/xpath is disproven: 4 product reference(s) and 32 module-internal chain(s) reach the declared subject(s)`; also `declaration ... could not be resolved...` and payload truncation | `internal/goanalysis/unreachability.go:VerifyUnreachable`; `internal/evidencetools/unreachability.go:symbolUnreachability`; persistence friction in `internal/research/deterministic.go:capObservationPayload` |
| 02 / CASE-223854 | **(b) New capability** | `symbol-unreachability for module google.golang.org/grpc is disproven: 2 product reference(s) and 2 module-internal chain(s) reach the declared subject(s)`; `may-call enumeration ... is partial` | Same as case 01 |
| 03 / CASE-227168 | **(c) Irreducible/forbidden with current evidence** | `TICKET_PACKAGE_VERSION_MISMATCH`: ticket `xpath 1.3.2`, analyzed build `v1.3.6` | `internal/affected/ticket.go:checkTicketClaims`; `internal/affected/resolver.go` version-axis block |
| 04 / CASE-238323 | **(c) Irreducible/forbidden with current evidence** | `TICKET_PACKAGE_VERSION_MISMATCH`: ticket `otel/sdk 1.40.0`, analyzed build `v1.43.0` | Same identity guard |
| 07 / CASE-327060 | **(a) Bounded engineering** | `symbol-unreachability for module golang.org/x/text is UNKNOWN: 38 open limitation(s) (declaration_complete=true references=0 may_call=1011 dep_sites=0 dispatch=14 markers=0 gated=0 opaque=false unbounded=false)`; skipped type-check packages; partial may-call enumeration; payload truncation | `internal/goanalysis/source.go:Index.load`; `usage.go:ProductUsage`; `toolscope.go:MayCallSites`; `funcvalues.go:fvIndex/fvParamCallers`; `coverage.go:InterfaceDispatchSites`; `internal/research:closedTraceFor/capObservationPayload` |
| 08 / CASE-329992 | **(a) Bounded engineering** | Same limitation shape as case 07 | Same paths |
| 10 / CASE-342517 | **(a) Bounded engineering** | `symbol-unreachability ... UNKNOWN: 2 open limitation(s)`; `product usage check could not close its negative verification for github.com/klauspost/compress/s2.NewDict`; `may-call enumeration ... is partial` | `internal/goanalysis/usage.go:ProductUsage`; `toolscope.go:MayCallSites`; `internal/research:closedTraceFor/capObservationPayload` |
| 15 / CASE-547674 | **(b) New capability** | `no independently verifiable falsifier proposal`; `agent category/prose is not authoritative`; `verification-facts.json` records `"executed": false, "plan_status": "no agent turn"` | `internal/research/decision.go:VerifyDecision`, specifically the `in.Proposal == nil` branch |
| 16 / CASE-548288 | **(b) New capability** | Same as case 15 | Same path |
| 17 / CASE-553916 | **(b) New capability** | `symbol-unreachability ... is disproven: 2 product reference(s) and 1 module-internal chain(s)`; `product usage check reports ...Channel.Qos as USED` | `internal/goanalysis/unreachability.go:VerifyUnreachable`; positive-use handling in `decision.go:verifyDeclaredSymbolUnreached` |
| 18 / CASE-554003 | **(b) New capability** | Same as case 17 | Same paths |

### Why cases 01, 02, 17, and 18 are not class (a)

They contain engineering friction, especially the incomplete trace and persisted payload cap. However, the deterministic lane already has positive reachability:

- case 01: `Expr.Evaluate` and `NodeIterator.MoveNext` are used;
- case 02: `Server.Serve` and `Server.handleStream` are reachable;
- cases 17/18: `Channel.Qos` is used and symbolically reachable.

Completing the trace cannot turn positive reachability into a safe negative. The reports also state `exploitation_established.status = NOT_ESTABLISHED`. These cases need a new, authoritative positive exploitability route—such as a verified dynamic reproduction—not better absence enumeration.

---

## 2. Class-(a) cases: exact closure mechanism

### Shared prerequisite: preserve the authoritative proof

All three class-(a) cases have the same persistence problem:

```text
observation payload truncated at 262144 bytes ...
stored bytes are a prefix of the tool result, not the full result
```

The producer is `internal/research/deterministic.go:capObservationPayload`, invoked by `LaneResult.persist`. It replaces the typed payload with a truncation envelope and downgrades `COMPLETE` to `PARTIAL`.

The safe fix is **not** “raise the cap until this run fits.” The authoritative symbol proof needs one of:

1. a complete, content-addressed sidecar/blob containing the full typed result; or
2. a compact proof payload whose closure booleans, counts, subject identities, and any positive paths are complete, with large enumerations stored separately and hash-bound.

The audit/decision path must consume the complete, hash-bound proof—not a display prefix.

Acceptance test:

- persist a synthetic `symbol-unreachability` payload larger than 1 MiB;
- verify the authoritative proof remains decodable and hash-bound;
- verify a closed no-reach result still reaches `NO_EXPLOIT_PATH_FOUND`;
- verify an open or positive result remains open/positive;
- retain the existing `TestPersist_TruncatesOversizedPayload` behavior for non-authoritative observations where truncation is still allowed.

Relevant existing contracts:

- `internal/research/deterministic.go:capObservationPayload`
- `internal/research/deterministic.go:LaneResult.persist`
- `internal/research/decision.go:closedSymbolTrace`
- `internal/research/deterministic_symbol_test.go`

### Case 07 — CASE-327060

#### Current blockers

Verbatim blockers include:

- `2 product package(s) failed to type-check and were excluded from the scanned scope ...; their references are invisible`
- `may-call enumeration for ...Form.Append is partial (unresolved candidates); the caller set is not closed`
- `1011 may-call site(s) can reach the subject(s) through interface dispatch or function values`
- `14 interface-dispatched call site(s) may resolve to the subject — the dynamic receiver is unresolved`

#### Mechanism

1. `internal/goanalysis/source.go:Index.load` drops packages with `p.Errors` or `TypesInfo == nil`. It records skipped import edges, but it cannot claim that references in the failed package were scanned.
2. `internal/goanalysis/usage.go:ProductUsage` converts skipped packages and unresolved symbol/dispatch scope into `UNKNOWN`.
3. `internal/goanalysis/toolscope.go:MayCallSites` marks enumeration partial when `callersOf` returns possible/sentinel sites.
4. `internal/goanalysis/funcvalues.go:fvIndex` and `fvParamCallers` deliberately mark the set open when function-value indexes are built during extras churn or recursively deferred.
5. `internal/goanalysis/coverage.go:InterfaceDispatchSites` plus `internal/goanalysis/unreachability.go:dispatchGaps` retain unresolved receiver candidates as blockers.
6. `internal/research/decision.go:closedTraceFor` refuses any incomplete trace.
7. `internal/research/deterministic.go:capObservationPayload` invalidates the persisted proof independently of the semantic result.

#### What closes it

- Re-run the exact recorded build context with all product packages type-checking successfully. If `providers/ibm` or `test` cannot type-check under the real build, the case must remain `UNKNOWN`; syntax-only recovery is not enough for a negative.
- Freeze the loaded dependency-extra generation before may-call enumeration.
- Build the function-value indexes in a complete two-pass order; require `Possible == false` for every returned candidate and no sentinel/open result.
- Resolve interface receivers soundly. If the receiver remains unresolved, retain `UNKNOWN`.
- Persist the complete proof without payload truncation.
- Re-run the full lane trace so `Requests`, `Observations`, and audit records are one-to-one and complete.

#### Expected verdict

**[INFERENCE]** If all subjects have resolved declarations, the product scope has no skipped packages, may-call and dispatch sets are closed and empty for the declared subjects, and no positive path appears, the case reaches:

```text
NO_EXPLOIT_PATH_FOUND
falsifier = declared-symbol-unreached
coverage = COMPLETE
NegativeVerification = VERIFIED
```

It must never become `NOT_AFFECTED`: symbol unreachability is explicitly only a no-exploit-path proof.

If closing the candidate set discovers a real call, the case does **not** move; it becomes a class-(b) positive-use case.

Acceptance test:

- new end-to-end regression over case 07’s advisory subjects;
- assert `Index.SkippedPackages()` is empty;
- assert every `MayCallSite.Possible == false`;
- assert `InterfaceDispatchSites` is empty or concretely resolved away;
- assert `UnreachabilityResult.Limitations` is empty;
- assert persisted proof is complete and `VerifyDecision` returns `NO_EXPLOIT_PATH_FOUND`;
- retain `TestUnreachabilitySkippedPackage` as the negative control proving that a failed package still stays `UNKNOWN`.

### Case 08 — CASE-329992

Case 08 has the same exact mechanism and acceptance criteria as case 07, but it analyzes the `demo-mq-gateway@2.5.0` snapshot.

Its report has the same `references=0`, `may_call=1011`, `dispatch=14` shape. The expected movement is therefore also conditional on the closed enumeration containing no actual subject path.

Acceptance test:

- run the same regression matrix against case 08’s `2.5.0` snapshot and advisory;
- require the snapshot/build hash and subject set to be case-specific;
- assert no result is accepted merely because the counts remain zero after an incomplete scan.

### Case 10 — CASE-342517

#### Current blockers

Verbatim:

- `product usage check could not close its negative verification for github.com/klauspost/compress/s2.NewDict`
- `may-call enumeration for github.com/klauspost/compress/s2.NewDict is partial (unresolved candidates); the caller set is not closed`
- `observation payload truncated at 262144 bytes ...`

The symbol proof reports:

```text
declaration_complete=true references=0 may_call=0 dep_sites=0 dispatch=0 ...
```

but the caller set is still explicitly open. An empty returned list is not equivalent to a closed empty set.

#### What closes it

- Make the function-value/may-call scan stable and closed.
- Preserve the complete proof payload.
- Reconcile the package-level facts before promoting a negative. The report contains both:
  - package-usage evidence saying `s2` is absent from the linked product closure; and
  - build-usage evidence classified as `mixed`.

Those facts cannot silently be treated as equivalent. If the package is truly absent under a complete product closure, the existing package/build-closure falsifier should be used. If the package is present but `NewDict` is not called, the exact symbol-level may-call proof must close.

The current `ProductUsage` contract explicitly says that a symbol subject cannot be declared unused solely because its package is absent. That is intentional. A safe implementation may compose a separately verified package-absence proof, but it must use the existing `FalsifierPackageAbsent` route and exact advisory subject coverage; it must not change the symbol-level `UNKNOWN` to `NOT_USED` by assumption.

#### Expected verdict

**[INFERENCE]** If the stable scan proves no `NewDict` call and the package-level/build-closure facts reconcile to a closed absence proof, the case reaches `NO_EXPLOIT_PATH_FOUND`. If the package is present and may-call closure is empty, the symbol-unreachability route can reach the same verdict. If either closure remains contradictory or open, the case remains `INCONCLUSIVE`.

Acceptance test:

- construct both controls:
  1. package absent from a complete product closure;
  2. package present but exact `NewDict` symbol unused.
- assert both produce a verified no-exploit-path result through their correct falsifier;
- assert an open `MayCallSites` result remains `INCONCLUSIVE`;
- assert contradictory package/build-closure observations do not promote a negative.

---

## 3. Why the other six do not move through bounded engineering

### Cases 01 and 02

The blocker is not merely the cap or skipped package. The proof payload says reachability is disproven:

- case 01: `4 product reference(s) and 32 module-internal chain(s)`
- case 02: `2 product reference(s) and 2 module-internal chain(s)`

The next missing fact is whether the vulnerable behavior is actually exploitable in the product deployment. Static package use, static entrypoints, and symbol reachability do not establish runtime input delivery or attacker control. `internal/research/slice2.go:slice2Axes` only establishes `exploitation_established` from verified `runtime-observation`, `dynamic-trace`, or `reproduction` facts.

### Cases 17 and 18

The report is even more explicit:

```text
product usage check reports github.com/rabbitmq/amqp091-go.Channel.Qos as USED (1 product site(s))
```

The report’s human question asks whether the negative integer input is attacker-influenced or operator-controlled. A complete unreachability trace cannot answer that; the symbol is already used. These need positive dynamic evidence or an independently verified input-control falsifier.

### Cases 15 and 16

`verification-facts.json` says:

```json
{"executed": false, "plan_status": "no agent turn"}
```

The report limitation is:

```text
no independently verifiable falsifier proposal
agent category/prose is not authoritative
```

This is not a safe negative and not an identity refusal. It requires a new authoritative proposal/evidence path: exact advisory-bound subjects plus either a deterministic falsifier or verified dynamic exploitability evidence. Until then, `UNKNOWN` is correct.

### Cases 03 and 04

The identity guard is working as designed. The reports record:

```text
TICKET_PACKAGE_VERSION_MISMATCH: the ticket declares ... but the analyzed build resolved ...
version axis blocked ...
package/build reachability was not evaluated ...
```

`internal/affected/ticket.go:checkTicketClaims` intentionally sets `VersionAxisBlocked`, and `internal/affected/resolver.go` leaves `VersionAffected=UNKNOWN`. The analyzer must not use the analyzed build to answer a ticket about another package version.

These cases can only be reconsidered after obtaining and analyzing the ticket’s actual package/build artifact. That is a process/input change, not a relaxation of the guard.

---

## 4. Tempting shortcuts that must be rejected

| Shortcut | Why it is tempting | Invariant broken |
|---|---|---|
| Treat an empty `ProductSites` or `MayCallSites` list as `NOT_USED` | It would immediately close 07/08/10 | Absence is not evidence without a complete closure, falsifier, and negative verification. This is explicitly enforced by `ProductUsage`, `MayCallSites`, and `VerifyUnreachable`. |
| Ignore `Possible=true` candidates | It makes the 1011/14 counts disappear | `funcvalues.go` marks possible sites precisely because candidate resolution is incomplete. Ignoring them converts an open caller set into a false closed set. |
| Exclude failed packages from the denominator | It makes type-check failures invisible | `Index.load` records skipped packages because their references are invisible. Exclusion would violate the scope-completeness premise. |
| Treat the 262,144-byte prefix as the full proof | It makes persisted observations appear complete | `capObservationPayload` explicitly says the prefix is not the full result and downgrades completeness. |
| Increase the cap silently | It postpones the same failure to a larger case and hides resource bounds | Provenance/bounds rules require every bound to be explicit. A cap is not a complete scope. |
| Let the LLM’s category or prose produce `FALSE` | It would resolve cases 15/16 cheaply | `VerifyDecision` accepts only independently re-derived deterministic evidence. Agent prose is non-authoritative. |
| Treat static reachability as `EXPLOITABLE` | It would turn 01/02/17/18 into definite findings | `exploitation_established` requires verified dynamic evidence; static use does not prove runtime execution, attacker control, or deployment exposure. |
| Treat “package present but exact symbol unused” as “not affected” | It would collapse several states | A symbol-level no-use claim is a bounded `NO_EXPLOIT_PATH_FOUND` route, not `NOT_AFFECTED`; applicability and reachability are separate axes. |
| Analyze the current build and answer the ticket’s declared version | It would remove the case 03/04 refusal | It answers a different artifact. `TICKET_PACKAGE_VERSION_MISMATCH` must remain a refusal until the ticket build is available. |
| Accept a product-version mismatch as package-version agreement | It conflates release identity with dependency identity | `ANALYZED_BUILD_MISMATCH` is informational; package version mismatch is the only identity mismatch that blocks the version axis. |

---

## 5. Strategy comparison

| Strategy | Cases moved | Unsafe-negative risk | Lifecycle cost |
|---|---:|---|---|
| **Plumbing/observability only**: durable complete payloads, audit/trace pairing, no skipped requests | **0 terminal moves** by itself | Very low if all incomplete data remains open | Medium; required infrastructure work, but reusable for every proof |
| **May-call + dispatch + package-load closure** | **0–3**; target cases 07, 08, 10 | Low if closure requires no skipped packages, `Possible=false`, no unresolved dispatch, and complete audit | Medium-high; touches `go/packages` loading, extras generation, function-value indexes, dispatch narrowing, persistence |
| **Positive exploitability evidence**: runtime observation, dynamic trace, or reproduction | 4 known reachable cases (01, 02, 17, 18); 15/16 are conditional and currently lack exact subjects | Low risk of unsafe negatives; main risk is accepting weak/irreproducible positive evidence | High; requires a confined runtime/reproduction capability, attacker-input provenance, markers, and reproducible artifacts |
| **Analyze the ticket’s own build** | 03 and 04 become analyzable only if exact package/build evidence is supplied | Low if identity is checked before analysis; zero if the refusal remains in place | High operationally; requires artifact retrieval, version provenance, and reproducible build inputs |

### Recommendation

1. **First, fix authoritative proof plumbing.**  
   This alone does not reduce the count, but without it a complete semantic result cannot survive persistence.

2. **Then close the bounded deterministic scope.**  
   Repair the recorded build/load context, make may-call and dispatch enumeration stable, and preserve fail-closed behavior. Apply this to 07, 08, and 10.

3. **Expected outcome:** **[INFERENCE] 2–3 cases move to `NO_EXPLOIT_PATH_FOUND`; census becomes approximately 8–9 `INCONCLUSIVE`.**  
   The optimistic 10-negatives/8-inconclusive result requires all three closed re-runs to show no actual subject path. A newly discovered call would move that case into class (b), not close it.

4. **Do not build positive exploitability capability solely to improve this census.**  
   It is justified only if the owner wants a defensible `EXPLOITABLE` outcome for reached symbols. It is a materially larger project and does not help the two identity refusals.

5. **Handle 03/04 through intake/process, not analyzer relaxation.**  
   Require the exact ticket build/package artifact. Until then, keep the refusal.

---

## 6. Remaining uncertainty and settling evidence

1. **Type-check failures:** the reports name `demo-mq-gateway/providers/ibm` and `demo-mq-gateway/test`, but do not include the compiler diagnostics. The settling evidence is the complete `go/packages` error set under the recorded `GOOS`, `GOARCH`, vendor mode, tags, and toolchain.

2. **The 1011/14 candidates in cases 07/08:** the persisted payload is only a prefix, so the artifacts do not reveal whether any candidate resolves to an actual declared subject. A complete, hash-bound symbol proof or a compact candidate summary with per-subject resolution is required.

3. **Case 10’s package/build facts:** package-level usage says `s2` is absent from the linked product closure, while the build-usage axis says `mixed`. The exact product/test closure membership and package identity must be reconciled before selecting package absence versus symbol unreachability.

4. **Cases 15/16:** no agent turn executed, so the artifacts do not tell whether the blocker is missing advisory subjects, planner failure, or simply no proposal. The settling evidence is an exact advisory-bound subject set and a deterministic or dynamic verification request.

5. **Case 01 unresolved declarations:** the evidence does not establish whether the advisory’s private-symbol list is wrong for the loaded dependency version or whether the wrong dependency version was analyzed. The settling evidence is the frozen advisory symbol list paired with the exact dependency source/version used in the product build.

6. **Cases 17/18:** the static call site is known, but the artifacts do not establish whether `prefetchCount`/`prefetchSize` can receive attacker-controlled negative values. A verified runtime trace or source-level provenance chain from an untrusted input to `Channel.Qos` would settle that question.


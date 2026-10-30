# План: снижение INCONCLUSIVE — детерминированное закрытие 07/08/10 + процесс для 03/04

**Статус:** APPROVED SCOPE (owner, 2026-10-19) — исполнимый план, код не изменялся.
**Источник:** delegated `architect` artifact `agent://ClosureImplementationPlan`, сохранён дословно.
**Основание:** `docs/dev/reports/2026-10-19-04-inconclusive-reduction-analysis.md` (§1 классификация 11 кейсов, §2 механизмы, §4 отвергнутые шорткаты).
**Дерево:** `500b367`.

---

# Corporate-Census `INCONCLUSIVE` Reduction Implementation Plan

**Goal:** Close only the bounded deterministic scope gaps in cases 07, 08, and 10, while preserving fail-closed behavior and retaining the ticket-build refusal for cases 03 and 04 until their declared distributions are supplied.

**Architecture:** Keep deterministic proof authoritative; preserve complete symbol-proof payloads in hash-bound sidecars; treat skipped packages, `Possible` may-call candidates, unresolved dispatch, incomplete traces, and contradictory build-closure facts as blockers; use `FalsifierPackageAbsent` only for exact closed package-absence evidence.

**Tech stack:** Go, `go/packages`, existing `internal/goanalysis` and `internal/research` evidence contracts, focused Go tests, `go vet`, corpus/evaluator runners.

**Spec:** `docs/dev/reports/2026-10-19-04-inconclusive-reduction-analysis.md`; `AGENTS.md`; `docs/agent-rules/security.md`; `docs/agent-rules/provenance-and-bounds.md`.

## Global Constraints

- Approved scope is limited to:
  - bounded deterministic closure for cases 07, 08, and 10;
  - the process path for cases 03 and 04.
- Do not add positive-exploitability capability for cases 01, 02, 17, or 18.
- Do not relax `TICKET_PACKAGE_VERSION_MISMATCH`.
- A symbol-level no-use result is `NO_EXPLOIT_PATH_FOUND`, never `NOT_AFFECTED`.
- `NOT_AFFECTED` remains available only through the deterministic affected chain.
- Empty lists are not closed evidence unless the corresponding scope is complete.
- `UNKNOWN`/`INCONCLUSIVE` remains correct for skipped, partial, contradictory, opaque, dynamic, gated, or unbounded scope.
- Every new bound must be explicit in the observation/report. Do not silently increase:
  - `maxObservationPayloadBytes`;
  - verification-call caps;
  - package-load budgets;
  - function-value recursion/depth/fuel bounds;
  - dispatch narrowing bounds.
- No case-specific product/module/symbol hardcode. Use generic mini-repositories and generic contracts; case IDs appear only in corpus/re-measurement commands and documentation.
- Settling evidence already establishes:
  - case-10’s persisted 293 KB artifact is itself a truncation envelope, not a recoverable full proof;
  - cases 07/08 fail on missing `providers/ibmmq/mqiCBD.go:26: fatal error: 'cmqc.h' file not found`;
  - cases 07/08 currently report `may_call=1011`, `dispatch=14`, `references=0`, `declaration_complete=true`;
  - case 10 currently reports `may_call=0` but a partial enumeration and a package-absence/build-usage contradiction;
  - all affected cases have incomplete verification traces.

## Prerequisite Decision: IBM MQ Headers for Cases 07/08

**Recommendation: install and expose the real IBM MQ client C headers and libraries in the analysis environment.**

The implementation and final census must use the actual IBM MQ SDK/client installation, with the recorded include/library paths and build environment. Before closure is accepted, reproduce the product build using the recorded `GOOS`, `GOARCH`, `CGO_ENABLED=1`, build tags, vendor mode, toolchain, and IBM MQ include/library configuration, for example:

```bash
CGO_ENABLED=1 \
CGO_CFLAGS="-I${IBM_MQ_CLIENT_HOME}/include" \
CGO_LDFLAGS="-L${IBM_MQ_CLIENT_HOME}/lib" \
go build ./...
```

Use the SDK’s supported environment or `pkg-config` configuration where applicable. Record the exact compiler diagnostics, toolchain, cgo state, build tags, vendor mode, and header/library provenance in the build observation.

**Alternative:** If the headers cannot be installed, cases 07/08 must remain permanently `UNKNOWN`/`INCONCLUSIVE` with the explicit limitation `missing prerequisite: IBM MQ client C header cmqc.h`. Do not treat a syntax-only stub as sufficient for a negative proof. A declared stub is permitted only as an explicitly limited compile aid and must never close the affected cases.

## Review Focus

| Mechanism | Required negative control |
|---|---|
| Authoritative proof persistence | Oversized but complete symbol proof survives through a sidecar; missing/altered sidecar remains `INCONCLUSIVE`. |
| `go/packages` loading | A package with type-check errors remains skipped and blocks closure; it is never removed from the denominator. |
| Function-value/may-call closure | `Possible=true`, sentinel, unresolved candidate, or exhausted bound keeps `MayCallSites` partial and the final decision `INCONCLUSIVE`. |
| Interface dispatch | An instantiated unresolved receiver remains a dispatch gap; only soundly absent/uninstantiated receiver types may be narrowed away. |
| Trace pairing | Missing audit row (including a nil/empty observation), unmatched turn/action, skipped request, duplicate observation, argument mismatch, or request subjects/module differing from declared authority makes the trace incomplete. |
| Case-10 reconciliation | Missing/partial/contradictory package-closure evidence or a marker-invalidating typed usage-scope limitation does not promote `FalsifierPackageAbsent`; symbol absence is not inferred from package absence. |
| Cases 03/04 identity | A ticket/package mismatch remains a refusal even when the currently analyzed source happens to be fixed. |

### Task 1: Freeze the `go/packages` Build Context and Preserve Skipped-Package Blockers

**Depends on:** None

**Files:**
- Modify: `internal/goanalysis/source.go` — `Index.load`, `loadExtra`, loader configuration helpers
- Modify: `internal/goanalysis/toolscope.go` — `SkippedPackages`
- Modify: `internal/goanalysis/usage.go` — `ProductUsage`
- Modify: `internal/evidencetools/observation.go` if additional structured skip diagnostics are required
- Test: `internal/goanalysis/loaderenv_test.go`
- Test: `internal/goanalysis/source_test.go`
- Test: `internal/goanalysis/usage_test.go`
- Test fixtures: existing `testdata/skippprod` plus a generic cgo/type-check failure fixture if needed

**Interfaces:**
- Consumes: `Index.Build`, `Index.Env`, `ReplaceEnv`, vendor mode, build tags, toolchain environment.
- Produces: one shared load context for product-root loads and dependency extras; structured skipped-package diagnostics; fail-closed `ProductUsage`.

- [ ] Step 1: Add a focused test proving that `Index.load` and `loadExtra` use the same `GOOS`, `GOARCH`, `CGO_ENABLED`, build tags, vendor mode, toolchain environment, and context cancellation.
- [ ] Step 2: Add a focused test proving that a package with `p.Errors` or missing `TypesInfo` is retained in skipped-package diagnostics, including package path, recovered imports, and compiler error text where available.
- [ ] Step 3: Run `go test -run 'TestLoadEnv|TestSkipped|TestProductUsage' ./internal/goanalysis` and record the expected failures before implementation.
- [ ] Step 4: Centralize the `packages.Config` construction so product roots and extras cannot silently diverge in environment or build flags.
- [ ] Step 5: Keep failed packages out of typed scans but retain them in the scope denominator. `SkippedPackages` must report both recoverable-import and unrecoverable-source failures.
- [ ] Step 6: Make `ProductUsage` return `PackageUsageUnknown` plus `PackageUsageNegativeInsufficientScope` whenever skipped packages, unrecoverable source, or exhausted load budget could hide a reference.
- [ ] Step 7: Include the exact load context and skip diagnostics in the observation’s `ScopeDetails`/limitations without treating them as positive absence evidence.
- [ ] Step 8: Run the focused tests again.

**Acceptance:**

- A fully type-checked product closure reports no skipped packages.
- A failed package is visible in the report and keeps product usage/unreachability open.
- A missing `cmqc.h` failure is reported as a concrete prerequisite/build limitation, not silently excluded.
- The failed-package fixture remains `INCONCLUSIVE`; no empty result is promoted.

**Observable result:** The analyzer can distinguish “closed empty scope” from “empty result after failed package loading,” and the case-07/08 re-run will be decisive once the real IBM MQ headers are installed.

### Task 2: Persist Complete Authoritative Symbol Proofs Without Losing Typed Results

**Depends on:** None; must land before final closure integration

**Files:**
- Modify: `internal/evidencetools/observation.go`
- Modify: `internal/research/deterministic.go` — `capObservationPayload`, `LaneResult.persist`, `CanonicalByObs`, `ArtifactByObs`
- Modify: `internal/research/validate.go` — persisted payload/reference validation
- Modify: `internal/research/replay.go` if replay must rehydrate the full payload
- Test: `internal/research/deterministic_payload_test.go`
- Test: `internal/research/deterministic_symbol_test.go`
- Test: `internal/research/validate_test.go`

**Interfaces:**
- Add a hash-bound persisted payload reference, for example:
  ```go
  type ObservationPayloadRef struct {
      Path      string `json:"path"`
      SHA256    string `json:"sha256"`
      SizeBytes int64  `json:"size_bytes"`
      Selector  string `json:"selector"`
  }
  ```
- Add the reference to `evidencetools.Observation` as an optional field.
- Add an internal loader/rehydrator that verifies the sidecar SHA-256 and decodes the original typed payload.
- `capObservationPayload` must distinguish ordinary display payloads from authoritative `symbol-unreachability` payloads.

- [ ] Step 1: Add a synthetic complete `SymbolUnreachabilityData` payload larger than 1 MiB and assert that its typed `Result` can be encoded and decoded losslessly.
- [ ] Step 2: Run the focused persistence test and confirm the current truncation behavior fails the authoritative-proof assertion.
- [ ] Step 3: Change `LaneResult.persist` to write the complete canonical typed payload for authoritative symbol proofs to a content-addressed sidecar under the observation artifact directory.
- [ ] Step 4: Persist only a bounded envelope/reference in the wire observation and `observations.jsonl`; do not store the prefix as if it were the proof.
- [ ] Step 5: Keep the authoritative in-memory `LaneResult.Records`/trace payload typed, or rehydrate it from the sidecar before `VerifyDecision`. The authority route must consume the complete hash-bound typed result, never `stored_payload_json`.
- [ ] Step 6: Keep existing truncation for non-authoritative observations. Their `COMPLETE`→`PARTIAL` downgrade remains valid.
- [ ] Step 7: Update `CanonicalByObs`, `ArtifactByObs`, facts, validation, and replay so the observation artifact digest, full payload digest, and sidecar digest have unambiguous meanings.
- [ ] Step 8: Require missing, altered, undecodable, or digest-mismatched authoritative sidecars to fail closed.
- [ ] Step 9: Run focused persistence, symbol-proof, validation, and replay tests.

**Acceptance:**

- A complete oversized symbol proof produces:
  - a bounded observation/ledger representation;
  - a full typed payload sidecar;
  - a SHA-256 and size pin;
  - a complete proof that can be rehydrated and passed through `VerifyDecision`.
- Rehydrated complete proof with no positive paths yields `NO_EXPLOIT_PATH_FOUND`, `FalsifierDeclaredSymbolUnreached`, and `NegativeVerification=VERIFIED`.
- A sidecar mutation/removal/decoding failure yields `INCONCLUSIVE`.
- An oversized non-authoritative `listen-sites` observation retains the existing truncation behavior.
- An oversized but semantically open symbol proof remains `INCONCLUSIVE`; persistence does not buy closure.

**Observable result:** Case-10’s 293 KB proof and the 07/08 proof payloads can no longer be dismissed merely because the display observation exceeded 256 KiB; the complete typed result remains auditable and authoritative.

### Task 3: Make Function-Value and May-Call Enumeration Explicitly Closed or Open

**Depends on:** Task 1

**Files:**
- Modify: `internal/goanalysis/funcvalues.go` — `fvIndex`, `fvParamCallers`, candidate resolution
- Modify: `internal/goanalysis/source.go` — caller-cache/extras-generation sentinel handling
- Modify: `internal/goanalysis/toolscope.go` — `MayCallSites`
- Modify: `internal/goanalysis/unreachability.go` — may-call aggregation and completeness
- Modify: `internal/goanalysis/usage.go` where may-call gaps affect `ProductUsage`
- Test: `internal/goanalysis/usage_test.go`
- Test: `internal/goanalysis/unreachability_test.go`
- Test: `internal/goanalysis/funcvalues_test.go` if a dedicated test file is needed

**Interfaces:**
- Preserve `MayCallSites(ctx, ref) ([]MayCallSite, bool, error)`.
- Contract:
  - `Possible=true` means the candidate set is incomplete.
  - An empty `CallSiteRef` sentinel means enumeration coverage is open even if no site is returned.
  - The second return value is true when the final enumeration remains incomplete: a possible candidate, sentinel, unresolved candidate, open function-value index, re-entrant scan, incomplete/evicted scope, skipped package, load-budget exhaustion, or settle-bound exhaustion exists.
  - An extras-generation change invalidates the current pass and requires a retry. Churn that settles on a frozen generation with a complete, reconciled caller scope does not by itself make the result partial. Sites found only in invalidated passes remain `Possible` unless confirmed on the frozen pass.
  - `([], false, nil)` is the only closed empty result.

  *(Amended 2026-10-19 per the architect's churn adjudication — `agent://ChurnContractAdjudication`: a stable generation is sufficient only when the final frozen scope is complete and reconciled; an unaccounted-for eviction or unscanned eligibility must keep the enumeration open.)*

- [ ] Step 1: Add tests for a resolved function-value call, an unresolved signature-compatible candidate, an extras-generation change, and a sentinel.
- [ ] Step 2: Run focused may-call/unreachability tests and confirm the open cases currently fail or are insufficiently asserted.
- [ ] Step 3: Ensure dependency extras are loaded and pinned before the may-call scan starts; do not evict/reload an active advisory module during closure verification.
- [ ] Step 4: Retain the two-pass function-value index construction. Candidate resolution must finish for the frozen extras generation before a closed result is returned.
- [ ] Step 5: Propagate `open` from `fvParamCallers`, `fvIndex`, and `funcCandidates` into `MayCallSites` as `partial=true` and/or `Possible=true`; never discard unresolved candidates to make the list empty.
- [ ] Step 6: Preserve all existing explicit bounds. If a bound is reached, record the named bound and leave the enumeration open.
- [ ] Step 7: Ensure `VerifyUnreachable` and `ProductUsage` treat `partial=true` as a limitation and prevent a negative proof.
- [ ] Step 8: Sort/deduplicate only after closure status has been computed; sorting must not erase the sentinel/open state.
- [ ] Step 9: Run focused tests.

**Acceptance:**

- Closed fixtures return no `Possible` sites, no sentinel, `partial=false`, and may support `Complete=true` if all other gates close.
- Open function-value fixtures retain `Possible=true` or `partial=true` and remain `UNKNOWN`/`INCONCLUSIVE`.
- A positive candidate discovered after closing enumeration is reported as a real path and does not become a negative.
- No code path treats `len(MayCallSites)==0` as sufficient proof.

**Observable result:** The current case-07/08 shape `may_call=1011` can close only after all candidates resolve; if any candidate remains possible, the case remains open rather than being silently reduced to zero.

### Task 4: Narrow Interface Dispatch Only with Sound Receiver Evidence

**Depends on:** Task 1; may be implemented alongside Task 3 but integrated after it

**Files:**
- Modify: `internal/goanalysis/coverage.go` — `InterfaceDispatchSites`
- Modify: `internal/goanalysis/unreachability.go` — `dispatchGaps`
- Modify: `internal/goanalysis/usage.go` — package/symbol dispatch gap handling
- Test: `internal/goanalysis/coverage_test.go`
- Test: `internal/goanalysis/unreachability_test.go`
- Test: `internal/goanalysis/usage_test.go`

**Interfaces:**
- `InterfaceDispatchSites(ctx, ref)` continues to return all syntactic dispatch candidates.
- `dispatchGaps(ctx, ref, sites)` may remove a candidate only when the receiver-instantiation probe is complete and proves the subject receiver type cannot be materialized in the recorded product scope.
- Probe failure, disabled narrowing, skipped packages, unresolved receiver type, or incomplete product inventory leaves the dispatch site open.

- [ ] Step 1: Add semantic tests distinguishing:
  - instantiated receiver behind an interface;
  - uninstantiated receiver with a complete product-instantiation inventory;
  - unavailable/incomplete instantiation inventory.
- [ ] Step 2: Run focused coverage/usage/unreachability tests and confirm the unresolved receiver control remains open.
- [ ] Step 3: Keep `InterfaceDispatchSites` conservative: it must not itself claim that a candidate is unreachable.
- [ ] Step 4: Implement/adjust `dispatchGaps` so narrowing is allowed only after a complete, error-free product-instantiation result.
- [ ] Step 5: Propagate narrowing failure as a named limitation, not as an empty dispatch list.
- [ ] Step 6: Ensure package-level `ProductUsage` applies the same dispatch-gate semantics as symbol-level unreachability.
- [ ] Step 7: Run focused tests.

**Acceptance:**

- `SafeFormatter.String`-style uninstantiated candidates may be narrowed away and permit a closed negative when all other gates pass.
- `URI.String`-style instantiated interface dispatch remains open and prevents `NOT_USED`/unreachability closure.
- An unavailable receiver inventory never narrows dispatch.
- No unresolved interface dispatch is omitted from the result merely because its concrete target was not found.

**Observable result:** The current `dispatch=14` count in cases 07/08 can disappear only through a generic, complete receiver-instantiation proof; unresolved dispatch remains a blocker.

### Task 5: Enforce One-to-One Research Turn, Request, Observation, and Audit Pairing

**Depends on:** Task 2

**Files:**
- Modify: `internal/research/verification.go` — `runVerification`, `callAuditMismatch`
- Modify: `internal/research/flow_adapter.go` — `flowTraceFromRecords`, `renumberFlowObservations`, flow artifact persistence
- Modify: `internal/research/decision.go` — trace gates and authority binding
- Test: `internal/research/verification_test.go`
- Test: `internal/research/flow_adapter_test.go`
- Test: `internal/research/decision_test.go`
- Test: `internal/research/branch_evidence_test.go`
- Test: `internal/research/replay_test.go`

**Interfaces:**
- For each declared verification request/action:
  - one request record;
  - at most one matching audit record;
  - one observation for an executed request, including synthesized `ERROR` when dispatch failed;
  - unexecuted requests form a named contiguous tail;
  - no audit record may become a fact without a matching declared action.
- Pair by action identity plus canonical tool/argument equality. Duplicate actions must be paired deterministically in dispatch order.
- Any mismatch sets `VerificationTrace.Complete=false`.

- [ ] Step 1: Add tests for missing audit rows, extra audit rows, duplicate IDs, mismatched arguments, unexecuted actions, and an empty audit with non-empty planned actions.
- [ ] Step 2: Run focused trace/flow tests and confirm the current projection can incorrectly appear complete when only a subset of flow actions has audit records.
- [ ] Step 3: Make `flowTraceFromRecords` build the full declared request sequence, not only the observed audit subset.
- [ ] Step 4: Mark unmatched/skipped actions as limitations and keep the trace incomplete; do not silently drop them.
- [ ] Step 5: Preserve the existing `RunVerificationPlanAudited` behavior for synthesized error observations and audit mismatch reporting.
- [ ] Step 6: Ensure turn metadata (`AgentTurnMetadata`) remains paired with the flow turn/action that produced it and cannot create an observation by itself.
- [ ] Step 7: Ensure persistence and replay validate that trace observations, audit rows, and pinned artifacts are the same canonical objects.
- [ ] Step 8: Run focused tests.

**Acceptance:**

- A fully executed, audit-bound plan has equal request/observation/audit coverage and `Complete=true`.
- Any skipped request, absent audit row, duplicate observation, mismatched tool/arguments, or extra unbound record yields `Complete=false` and `VerifyDecision=INCONCLUSIVE`.
- A trace copy cannot create authority without its session audit record.
- Persisted/replayed traces retain the same pairing result.

**Observable result:** The affected cases cannot be closed merely because the final trace contains a positive-looking observation while one or more requested checks were skipped or unpaired.

### Task 6: Reconcile Case-10 Package Absence with Symbol Unreachability

**Depends on:** Tasks 1–5

**Files:**
- Modify: `internal/goanalysis/usage.go` — `ProductUsage`
- Modify: `internal/evidencetools/usage_scope.go` if package-closure observations need stronger subject binding
- Modify: `internal/research/decision.go` — `scanAbsence`, `packageUsageBound`, `packageAbsenceDecision`, `hasPositiveUse`
- Test: `internal/goanalysis/usage_test.go`
- Test: `internal/research/decision_test.go`
- Test: `internal/research/deterministic_symbol_test.go`
- Test fixtures: generic package-absent, package-present/symbol-unused, mixed/contradictory closure fixtures

**Interfaces:**
- Use the existing `domain.FalsifierPackageAbsent` route; do not add a case-specific route.
- Package-absence proof requires:
  - exact advisory-declared package/module granularity;
  - complete product build-closure evidence;
  - no contradictory `ProductUsage`/build-usage observation;
  - coverage of every advisory-declared subject;
  - successful negative verification.
- A symbol-level subject never becomes absent solely because its package is absent in a source-usage result.
- A package-present but exact-symbol-unused case uses the complete symbol-unreachability route only after may-call, dispatch, package load, dynamic, gated, and trace gates close.

- [ ] Step 1: Add tests for:
  1. package absent from a complete product closure;
  2. package present but exact `s2.NewDict` symbol unused;
  3. package absent in one partial observation but present/mixed in build usage;
  4. missing package-list evidence;
  5. open may-call result with zero returned sites.
- [ ] Step 2: Run focused decision/usage tests and confirm each open or contradictory control remains `INCONCLUSIVE`.
- [ ] Step 3: Ensure the lane records package-level `usage-scope` evidence with exact module/package identity when the complete build-closure path is used.
- [ ] Step 4: Make `packageAbsenceDecision` reject a bound `ProductUsage` observation with `Present=true`, regardless of its source-usage verdict.
- [ ] Step 5: Make contradictory package/build facts produce a named limitation rather than selecting the apparently favorable fact.
- [ ] Step 6: Require advisory-wide coverage before promoting `FalsifierPackageAbsent`; one absent subject cannot close an advisory with additional uncovered subjects.
- [ ] Step 7: Keep the final verdict `NO_EXPLOIT_PATH_FOUND` for successful package absence or symbol unreachability. Never return `NOT_AFFECTED` from either route.
- [ ] Step 8: Run focused tests.

**Acceptance:**

- The package-absent control closes through `FalsifierPackageAbsent`, with `NegativeVerification=VERIFIED` and `NO_EXPLOIT_PATH_FOUND`.
- The package-present/symbol-unused control closes only through `FalsifierDeclaredSymbolUnreached`.
- Mixed, partial, contradictory, missing, or open observations remain `INCONCLUSIVE`.
- No code interprets case-10’s `may_call=0` as closed while the enumeration is partial.
- The report names whether the result came from package absence or exact symbol unreachability.

**Observable result:** Case 10 can close safely through exactly one of two existing proof bases; it cannot close by conflating “package absent from one fact” with “symbol unused.”

### Task 7: Add the Ticket Distribution Artifact Process Hook for Cases 03/04

**Depends on:** None; independent of closure tasks

**Files:**
- Modify: `internal/tracker/intake.go` — ticket model and text parser
- Modify: `internal/domain/ticket.go` — `TicketClaims`/`TicketCheck` provenance fields as needed
- Modify: `internal/research/ticket.go` — `TicketRecord`, `ticketClaims`
- Modify: `internal/research/types.go` — report input ticket projection if required
- Modify: `internal/research/render.go` — actionable refusal rendering
- Modify: `internal/research/validate.go` — ticket field validation
- Test: `internal/tracker/intake_test.go`
- Test: `internal/research/ticket_test.go`
- Test: `internal/research/ticket_guard_test.go`
- Test: CLI/research tests covering `--ticket` and `--artifact`/`--artifact-url`

**Interfaces:**
- Add an optional `DistributionURL`/equivalent provenance field to the parsed ticket and persisted `Input.Ticket`.
- Parse the dedicated `Ссылка на дистрибутив` label; do not treat arbitrary URLs as the distribution artifact.
- Preserve the exact ticket digest and a sanitized URL; credentials must never be embedded or logged.
- Existing `--artifact`/`--artifact-url` remains the explicit artifact-supply channel.

- [ ] Step 1: Add JSON and Russian-text intake tests for the supplied distribution URL shape:
  `.../_DEMO/1.10.3-1919/_DEMO-1.10.3-1919-distrib.zip`.
- [ ] Step 2: Add a mismatch-report test asserting that cases 03/04 retain `TICKET_PACKAGE_VERSION_MISMATCH`, `VersionAffected=UNKNOWN`, and no fixed/out-of-range conclusion.
- [ ] Step 3: Include the recorded distribution locator and an explicit next action in the report:
  `provide/acquire the exact ticket distribution, then rerun with --artifact or --artifact-url`.
- [ ] Step 4: Do not auto-fetch the URL merely because it appears in the ticket.
- [ ] Step 5: When an artifact is supplied, run the existing bounded release-artifact channel and record artifact SHA-256, selected binary/member, build-info digest, module graph, and trust class.
- [ ] Step 6: Re-run the ticket identity check against the supplied build’s package/version. Clear the refusal only if the supplied build actually matches the ticket-declared package identity; otherwise retain the refusal with the new mismatch.
- [ ] Step 7: Add a negative control proving that analyzing the current source snapshot without the supplied ticket artifact still refuses the version axis.
- [ ] Step 8: Run focused tracker/research/CLI tests.

**Acceptance:**

- Current cases 03/04 remain refused and actionable; the report identifies the ticket’s distribution locator and the exact missing prerequisite.
- A supplied artifact is independently pinned and analyzed before any version-axis conclusion is made.
- A product-version mismatch remains informational; a package-version mismatch remains blocking.
- No source-only or current-build result answers the ticket’s declared package version.

**Observable result:** The refusal remains safe, but an operator can act on the report by supplying the exact distribution named by the ticket.

### Task 8: Documentation, Corpus Guard, and Final Re-Measurement

**Depends on:** Tasks 1–7

**Files:**
- Modify as applicable: `eval/README.md`
- Modify as applicable: `docs/dev/gap-analysis.md`
- Do not add case-specific code or committed private artifact paths.

**Interfaces:**
- Consumes: completed analyzer changes and final census artifacts.
- Produces: synchronized behavior documentation and final measured evidence.

- [ ] Step 1: Update documentation only after the implementation tests pass; describe the sidecar proof contract, explicit closure requirements, skipped-package behavior, and the 03/04 artifact process.
- [ ] Step 2: Run formatting on changed Go files:
  ```bash
  gofmt -w <all changed .go files>
  ```
- [ ] Step 3: Run:
  ```bash
  go vet ./...
  ```
- [ ] Step 4: Run:
  ```bash
  go test ./...
  ```
- [ ] Step 5: Run the real corpus once at the end:
  ```bash
  go run ./cmd/izyan eval --corpus eval/corpus-real.json -j 4
  ```
  Require `false-safe=0`.
- [ ] Step 6: With the IBM MQ headers installed and the recorded build environment active, run the supplied 18-case census exactly once:
  ```bash
  python3 va-tmp/r6-final/run_census_artifacts.py
  ```
- [ ] Step 7: Run the decision-ready regression guard:
  ```bash
  python3 eval/decision_ready/regression_guard.py \
    --baseline-manifest va-tmp/r6-final/r6-guard-baseline.json
  ```
- [ ] Step 8: Record the observed verdict, falsifier, coverage, and limitation for every affected case; do not replace conditional forecasts with claims unless the census actually shows them.

**Expected census movement:**

| Cases | Expected result under complete closure |
|---|---|
| 07, 08 | **Forecast:** `INCONCLUSIVE` → `NO_EXPLOIT_PATH_FOUND` only if real IBM MQ headers permit a complete build, all product packages type-check, may-call candidates are closed, dispatch gaps are resolved/narrowed soundly, and no positive path appears. Never `NOT_AFFECTED`. |
| 10 | **Forecast:** `INCONCLUSIVE` → `NO_EXPLOIT_PATH_FOUND` through either exact symbol-unreachability or verified `FalsifierPackageAbsent`, only after package/build facts reconcile. Never `NOT_AFFECTED`. |
| 03, 04 | No movement in the current census: remain `INCONCLUSIVE` with `TICKET_PACKAGE_VERSION_MISMATCH`. After the exact distribution is supplied, rerun those cases; the resulting verdict is determined by that build and cannot be forecast in this plan. |
| 01, 02 | Remain `INCONCLUSIVE`; static reachability is already positive and this scope does not add exploitability proof. |
| 17, 18 | Remain `INCONCLUSIVE`; static use is already positive and input control is out of scope. |
| 15, 16 | Remain `INCONCLUSIVE`; no authoritative falsifier proposal exists. |
| Existing negative cases | Must remain unchanged and safe. No symbol-proof change may convert an existing result to `NOT_AFFECTED`. |

**Stop conditions:**

- Stop and do not claim reduction if `cmqc.h` is unavailable; record 07/08 as explicitly prerequisite-blocked.
- Stop if any closure is promoted with `COMPLETE` while skipped packages, `Possible=true`, sentinel/open may-call state, unresolved dispatch, or incomplete trace remains.
- Stop if a symbol-unreachability route emits `NOT_AFFECTED`.
- Stop if a negative lacks `NegativeVerification=VERIFIED`, exact falsifier, and complete advisory-bound evidence.
- Stop if cases 03/04 lose `TICKET_PACKAGE_VERSION_MISMATCH` without an analyzed ticket distribution artifact.
- Stop if `eval/corpus-real.json` reports any `false-safe`.
- Stop if the regression guard fails.
- Stop if the final census shows a case-specific hardcode effect or a changed out-of-scope case.
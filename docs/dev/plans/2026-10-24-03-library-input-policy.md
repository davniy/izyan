# Case fix 2 decision: library attacker-control (`stretchr`)

**Source:** architect `agent://LibraryInputPolicy` (2026-10-24, option D). Read-only; no code changed yet.

## Decision

Recover `stretchr-testify-CVE-2022-28948` under an explicit **library-API threat model**. Do not globally reclassify exported parameters as `EXTERNAL_UNTRUSTED`: consumer-supplied ≠ proven attacker control.

## Admission rule (all five required)

1. **Proven library shape** — complete product module/workspace census; ≥1 importable product package; no non-test product package declares `package main` (including skipped packages whose clause is recoverable). Incomplete census / unreadable clause / unaccounted module / build selection hiding a command ⇒ shape UNKNOWN. Empty shipping-root set alone is insufficient. Binary analysis ineligible.
2. **Real public API boundary** — parameter belongs to a product-owned, non-test, externally importable package (not dependency, not `internal`). Enclosing function exported per `go/types`; methods require exported method on exported named receiver. Zero callers is irrelevant.
3. **Payload-shaped parameter** — after alias resolution: `string`, slice of `uint8`, or canonical `io.Reader`. Exclude writers, receivers, callbacks, arbitrary interfaces, pointers, containers, unresolved generics, substring type-name matches.
4. **Exact payload flow** — bind API formal index → sink argument index with source evidence; forwarding only via identity, byte-preserving string/[]byte conversion, or established payload-preserving passthrough. Opaque transform / payload-unproven / unmodeled guard ⇒ no admission.
5. **Narrow claim admission** — resolved root-cause sink; class `DESERIALIZATION` backed by advisory `CWE-502`; condition `ATTACKER_CONTROL` with nonnegative arg index. No remote-peer requirement; does not satisfy `INPUT_CONSTRAINT` or prove network exposure.

For testify: `YAMLEq.expected` formal 1 → `Unmarshal` arg 0, and `YAMLEq.actual` formal 2 → arg 0; existing `[]byte(...)` preserves payload.

## Placement

- `goanalysis`: record structured `DataFlow.LibraryInput` witness (API symbol, formal index/type, sink symbol/site/arg, evidence refs). Deployment origin stays `UNKNOWN`; do not fabricate an observed external source.
- `evaluator.ArgumentOrigin`: admit the witness and set `Claim.ControlBasis = "library-consumer-assumption"`.
- Persist shape + witness + basis; render "library-API scope; consumer-control assumption" in reports, verdict limitations and VEX details. No new CLI flag. Do not use `Claim.AssumptionIDs`.

Mandatory limitation:

> `library entry point: parameter provided by the library consumer; deployment-specific control not verifiable from the library root`

Explanation must say "consumer-controlled under the library-API threat model", never "a remote attacker was observed controlling this input".

## Required tests

| Test | Assertion |
|---|---|
| Testify-shaped library, both YAML calls | Two correctly indexed witnesses; raw origins stay UNKNOWN; `C-INPUT=TRUE` with typed basis + limitation; with TRUE reach/locus ⇒ `EXPLOITABLE` |
| No callers / constant callers / generated wrappers / test-only callers | Boundary stays open; no closed-world constant-input negative |
| Product-shape negatives | Real `main`, skipped/failed `main`, build-hidden command, incomplete census, binary mode ⇒ no admission; vendor/test synthetic mains don't misclassify |
| Export/type matrix | Public funcs and eligible exported methods pass; private/internal/dependency/test and excluded types fail; aliases and defined string/byte-slice types tested |
| Payload binding | Wrong formal/sink arg, writer-only, unused param, constant replacement, opaque transform, unmodeled sanitization ⇒ no admission |
| Admission boundaries | Wrong class, keyword-only, unresolved sink, unspecified arg, peer-only, `INPUT_CONSTRAINT` ⇒ no promotion |
| Safety/persistence/reporting | Missing reach/locus keeps INCONCLUSIVE; witness cannot set those claims; negative verification treats it as unresolved, never VERIFIED; round-trip retains scope/basis/bindings/limitation |
| Both known false alarms (`podman-38ccfa2`, `k8s-6d4b94f`) | No library-consumer admission and no change attributable to this feature — not that they become safe |

## Non-claims

- Library-level evidence under an assumption, not proof an application passes attacker data.
- Cannot apply merely because a subpackage lacks `main`; no bypass of affected/reach/locus/model-completeness gates; no negative closure.
- The two known false alarms are `RESOURCE_EXHAUSTION` class with real product `main` packages — they fail two independent gates and are **not** repaired by this fix.

## Residual risk

Libraries used only with trusted data (especially test libraries) can now reach `EXPLOITABLE` under the assumption. The typed basis and visible scope make the trade-off auditable; it does not remove it. Widening beyond `DESERIALIZATION`/payload shapes/application products requires a separate decision.

**Design gate: READY with bounded library-consumer assumption.** If product shape is incomplete or exact payload binding cannot be preserved, keep UNKNOWN.

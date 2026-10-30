# Library verdict design: `EXPLOITABLE — library API`

**Date:** 2026-10-25. Source: architect `agent://LibraryVerdictDesign` (DESIGN_FOR_REVIEW, READY).
Branch `consolidation/shadow-base`, HEAD `f513ac7`. Not implemented.

## Decision

The testify case should finish **`EXPLOITABLE`**, explicitly scoped to the library's public API.
**No new verdict value.** The four existing verdicts stand; the boundary becomes an orthogonal field:

```text
verdict:              EXPLOITABLE
exploitability_scope: library-api
control_basis:        library-public-api
```

A new value like `LIBRARY_CONDITIONALLY_EXPLOITABLE` would mix two independent axes:
(1) is it exploitable in the measured product; (2) which product boundary the conclusion covers.

Supersedes the earlier `library-consumer-assumption` label (`2026-10-24-03-library-input-policy.md`):
consumer **selectability** is a code fact; deployment attacker control stays unknown.

## Why today's INCONCLUSIVE is a modeling gap

The model demands an application-level fact from an artifact that cannot contain it:

> whether a downstream consumer passes adversary-influenced bytes as `expected`/`actual`.

Two consumers of identical library bytes: one passes a fixed literal, one forwards an HTTP body.
Different application conclusions, identical artifact. No function of the artifact distinguishes them.
Deeper tracing cannot help; `--trusted-peer` cannot help (verified: it does not close `C-INPUT`).

The fact the analyzer **can** establish — public formal → vulnerable sink payload binding — is missing
as a typed capability: `traceParam` has no terminal case for "this is the library's public input boundary"
(`internal/goanalysis/provenance.go:355-357`).

OpenVEX: `affected` (action recommended); `under_investigation` is for genuinely unknown cases.
Once the library's vulnerable public-input path is established, `under_investigation` **underclaims**;
projecting it onto all consumers **overclaims**. CycloneDX stays `exploitable`.

## Admission rule (all gates required; failure = "cannot prove", never "safe")

**A. Library shape.** Owning root module + workspace accounted; non-test product package census
(incl. failed/skipped candidates, build-excluded source); ≥1 importable product package; **no product-owned
`package main`**. Missing ownership / unreadable clause / incomplete census / binary-only ⇒ shape UNKNOWN.

- Correction: "product" ≠ every `.go` below the repo dir. The snapshot has a **nested generator module**
  `github.com/stretchr/testify/_codegen` (`package main`) that must be excluded by **module ownership**,
  not by a testify-specific path exception.
- Do **not** require `ShippingScope.Complete` for a library — that machinery deliberately leaves
  libraries open with no main roots (`internal/goanalysis/unreachability_scope.go:836-886`).

**B. Public API.** Product-owned, non-test, externally importable (not `internal`/command/test variant);
typed exported function, or exported method on exported named receiver. Zero callers, test-only callers,
or constant-only callers do **not** close a public API.

**C. Payload flow.** Formal type `string` / `[]uint8` / canonical `io.Reader` (aliases resolved via type
info; no substring matching). Exact binding `API symbol + formal index → sink call + argument index`
through identity/byte-preserving conversions or verified payload-preserving ops. Reject: constant
replacement, unused/ wrong formal, opaque/lossy transform, unresolved dispatch, payload-unproven flow,
relevant unmodeled guard/sanitization/recovery.

**D. Claim admission.** Resolved root-cause sink AND class `DESERIALIZATION` AND advisory `CWE-502`
AND condition `ATTACKER_CONTROL` AND exact nonnegative arg index AND ordinary argument input.
⇒ `C-INPUT=TRUE`, `ControlBasis=library-public-api`. Does **not** satisfy `INPUT_CONSTRAINT`,
network exposure, authn, protocol-role, or configuration.

**E. Placement.** Typed product-shape record + optional `DataFlow.LibraryInput` witness;
deployment `Origin` stays `UNKNOWN` (never invent `EXTERNAL_UNTRUSTED`); evaluate the witness in
`ArgumentOrigin`; persist `ControlBasis` and `VerdictResult.ExploitabilityScope`.

## Worked testify result

| Public formal | Sink argument |
|---|---|
| `YAMLEq.expected` (1) | `yaml.Unmarshal` arg 0 @ `assert/assertions.go:1573` |
| `YAMLEq.actual` (2) | `yaml.Unmarshal` arg 0 @ `assert/assertions.go:1577` |

Both via byte-preserving `[]byte(...)`. `TestingT` needs only `Errorf`; the function is not test-file-only
and the parsing code is shipped library source.

```text
affected: TRUE · C-REACH: TRUE · C-LOCUS: TRUE · C-INPUT: TRUE (library-public-api)
final:    EXPLOITABLE, scope=library-api · deployment origin: UNKNOWN
```

Applies to GHSA (`COMPLETE`) and CVE (`KNOWN_ONLY`) runs — `KNOWN_ONLY` blocks unsupported *negative
closure*, not a positive path. Never relabel CVE coverage as complete.

Mandatory limitation:

> Library-API scope: the payload is selectable by a library consumer; whether a downstream application
> exposes that payload to an attacker is outside the analyzed product and is not established.

Report wording must never render "remote client input was observed" from this claim. Existing report code
does exactly that (`internal/report/report.go:1308-1317,1460-1493`) — must be updated, and
`allLimitations` currently does not aggregate claim limitations.

## Risk

| Case | Shape gate | Class gate | Incremental admission |
|---|---|---|---|
| Podman `38ccfa2` (CVE-2024-37298) | fails: real `main` | fails: `RESOURCE_EXHAUSTION` | **none** |
| Kubernetes `6d4b94f` (CVE-2022-41717) | fails: real `main` | fails: `RESOURCE_EXHAUSTION` | **none** |

Eligibility 0/2; these existing errors are **not** repaired by this change.

Projected effect on the 30-case VEX corpus (7 positives): +1 correct positive, −1 abstention,
+14.3 pp positive recall, +3.3 pp overall accuracy, zero incremental false-safe.
Single-case accounting, **not measured**. Near-miss kept excluded: Echo CVE-2020-26160
(library-shaped, `AUTH_BYPASS`, negative GT) — shows "library + public surface ⇒ TRUE" is too broad.

Must never imply: every exported API is exploitable; public API = network exposure; failed admission
means safe; test-oriented purpose means test-only source; missing callers means unreachable.

## Implementation notes

Supersedes `2026-10-24-03-library-input-policy.md` (label and several gates).
Blocking dependency for `stretchr`; `Cilium-1228cbc` remains queued behind it.

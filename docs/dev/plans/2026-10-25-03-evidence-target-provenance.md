# Evidence-semantics fix: target provenance and tool-run outcomes

**Date:** 2026-10-25. Source: architect `agent://ToolTargetSemantics` (DESIGN_FOR_REVIEW, READY).
Branch `consolidation/shadow-base`, HEAD `a88c639`. Not implemented.

## Decision

Two independent admission gates for **negative** evidence:

1. The measurement must describe an identified **product build**, not the analyzer host.
2. The measurement must have **completed successfully** and covered the subject and scope being negated.

Failing either gate yields `UNKNOWN`, never `FALSE` with a limitation. Independent positive
evidence stays usable.

Explicitly rejected: heuristically inferring a trusted target from CI config, Dockerfiles,
`unix` imports, or `_linux.go` files.

## D1 — target policy

Preserve precedence: `artifact-build-info` > `release-metadata` > `operator-declared` >
`host-default` (analysis context only, no product scope).

- `--release` selects source identity, not target facts.
- `--deploy-manifests` is perimeter evidence, not build provenance.
- Partial `--goos`/`--goarch` or tags-only stays non-admitting; do not promote the
  host-filled pair to operator-declared.
- Plain `--binary` must reuse the digest-bound build-target extraction it currently skips.

**One effective build context**: resolve target before any build-dependent probe loads
packages; affected resolver, govulncheck, source index and negative verifier must share
snapshot identity, GOOS/GOARCH, tags, CGO and module/vendor/workspace context. Never relabel
an already-loaded index.

Admission rule:

```
admissible = target exists AND Validate succeeds AND Scoped() AND matches effective context
```

Enforce at four boundaries: producers, `Verifier.VerifyFalse` start, verdict admission
(including persisted `VERIFIED`), and scan prefilter/exports. Carry it structurally via the
existing `ProductTarget`, never by parsing explanation strings.

A negative proved this way describes **that analyzed build**, not every supported variant.

## D2 — durable tool-run state

Typed metadata on `EvidenceGovulncheck`, recorded on **every** return path:

| Outcome | Reachability contribution |
|---|---|
| `completed_with_results` | matching call path can prove TRUE; missing subject paths are not FALSE |
| `completed_empty` | not automatically negative; silence candidate only with full coverage |
| `failed` | `UNKNOWN`; no silence-derived falsifier |
| `not_run` | `UNKNOWN`; no silence-derived falsifier |

Keep exit code 3 as a successful findings result. Reject bare/empty/invalid streams as
`completed_empty` — the current parser accepts them. A parseable prefix from a failed
process stays `failed`.

Move coverage from a case-level flag into the typed run record; migrate consumers.

Rules: for `failed`/`not_run`, `libraryUsageVerdict` becomes **positive-only** (zero usage
returns UNKNOWN, never `no-module-usage`). For completed runs, silence is only a **candidate**
negative, still requiring negative verification.

**`evalLocus` fixed separately** — a linked package plus empty trace collections is not a
function-unreachability measurement. A govulncheck failure is not a case-wide veto.

## Blast radius

Changes: every build-context-dependent negative (`govulncheck-silence`, `no-module-usage`,
`unreached-exported-subject`, `package-absent`, `locus-*`, build-selected reader/pair-member/
symbol proofs, affected `PackagePresent=FALSE`/`BuildRelevant=FALSE`, host-GOOS platform
claims).

Unchanged (must NOT become host-target negatives): module-graph absence, out-of-range
versions, release-toolchain facts, deployment-policy evidence.

Adjacent bypass to close: partial package-list stdout after an execution error must not serve
as a complete absence inventory (`resolver.go:570-590`, `golist.go:214-225`).

## Calibration

- **Cilium** default → `C-REACH`/`C-LOCUS` `UNKNOWN`, `INCONCLUSIVE`. Explicit `linux/amd64`
  run keeps the measured positive.
- **Podman `CVE-2024-37298`**: its positive comes from a module chain despite govulncheck
  failure; preserving independent positives means this fix does **not** necessarily remove
  that wrong false alarm. Must not be removed to improve calibration.
- **Kubernetes `CVE-2022-41717`**: timeout is not a corrected safe result.
- Legitimate-safe cases without target inputs will move from safe to abstain. Intended.

Must not become inferable: failure ⇒ no path; success ⇒ coverage; package finding ⇒ symbol
reachability; module use ⇒ every sink reachable; one target ⇒ support matrix; partial load
⇒ product absence; reachability ⇒ attacker control.

Library-API admission is **not** widened (`DESERIALIZATION` + CWE-502 unchanged).

## Benchmark consequence

The VEX task metadata carries no platform (`language`, `pr_url` only), so the unchanged
harness keeps `host-default` and **Cilium stays `INCONCLUSIVE`**. This is evidence
correctness over target guessing — the case is not recovered to `EXPLOITABLE` by this fix.

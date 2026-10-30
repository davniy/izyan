# Scope-bound version negatives

**Date:** 2026-10-25. Source: architect `agent://VersionScopeDesign` (DESIGN_FOR_REVIEW, READY).
Branch `consolidation/shadow-base`, HEAD `f3aa914`. Not implemented.

## Decision

Strengthen the existing shared negative-closure gate with **structural evidence of what the
advisory projection covers**. Do not change the x/net version arithmetic, invent a gRPC entry,
or add a Kubernetes/CVE exception.

Kubernetes CVE-2023-44487 intended outcome:

```text
golang.org/x/net@v0.17.0: outside the declared affected range — preserved
Package/build reachability: not evaluated — preserved
Product-level conclusion: INCONCLUSIVE
```

## 1. Closure rule

A version negative closes a finding only when:

1. the evaluated subject set **covers the scope of the conclusion**, and
2. every entry in that set is deterministically excluded by module presence/version.

An unsupported, unrepresented, or unresolved entry is never treated as excluded. Module
absence remains a separate closure. A present entry with unknown version blocks version
closure. One affected entry blocks it regardless of how many others are fixed.

Preserve the resolver's existing union arithmetic (a fixed first entry must not shield an
affected or pending second entry).

**Two distinct conclusions:**

| Conclusion | Required coverage |
|---|---|
| "Not affected by this exact advisory finding" | Complete coverage of that bounded finding |
| "Not affected by this CVE, including other implementations" | Evidence establishing the CVE's product surface — not mere enumeration of one record |

Single-module is neither necessary nor sufficient for CVE completeness.

## 2. Structural scope model

**Defect:** `AllowsNegativeClosure` (`internal/domain/advisory_scope.go:29-33`) accepts
exact-id + `ADVISORY_ENTRIES` + `COMPLETE`, but `bindAdvisoryScope`
(`internal/vulnerability/source.go:329-354`) derives that from the **Go projection**; the
parser discards non-Go entries before building `AffectedModules`
(`internal/vulnerability/osv.go:110-149`). The gate therefore cannot distinguish a fully
represented record from a broad record reduced to its Go entries. The basis string already
admits this ("not CVE-wide coverage") but nothing structural enforces it.

Add, derived **before filtering and before merging entries by module name** (counting
`AffectedModules` is wrong — entries merge per module):

```text
RecordExtent: FULL_RECORD | GO_PROJECTION | UNKNOWN
RecordInventory: advisory identity + document digest, original affected[] entry refs,
                 entry ecosystem/module identities, represented/omitted refs
```

Field responsibilities: `Kind` = what the caller requested; `Coverage` = completeness of that
assertion; `RecordExtent` = whether the loaded record was fully represented; `Basis` = human
explanation, **never executable policy**.

Intake: exact record + complete pre-filter census + all entries represented ⇒
`ADVISORY_ENTRIES/COMPLETE/FULL_RECORD`. Omitted entries ⇒ `KNOWN_ONLY/GO_PROJECTION`.
CVE resolved to an OSV record ⇒ `CVE/KNOWN_ONLY` regardless of ecosystem count. Missing census
⇒ `UNKNOWN`, no closure.

**Never infer CVE completeness from** a GO/GHSA prefix, one module, one ecosystem,
`github_reviewed`, alias enrichment, or absence of a discovered alternative.

Gate: keep `AllowsNegativeClosure` shared; for an exact-record finding additionally require
`RecordExtent == FULL_RECORD` with a present, consistent inventory. A CVE-wide negative needs
an admitted completeness basis the ordinary OSV intake cannot supply — no override flag.

## 3. Worked case

The checked fixture has 22 affected entries: Go 1 (`golang.org/x/net`), Maven 20, SwiftURL 1.
No gRPC entry ⇒ structurally a Go projection.

Flow: record the census → resolve the Go entry as today (`v0.17.0`, `VersionAffected=FALSE`)
→ keep `PackagePresent`/`BuildRelevant` UNKNOWN → refuse closure → `INCONCLUSIVE`.

Do **not** force an x/net reachability probe (the fixed package cannot prove an unlisted gRPC
implementation is safe), and do **not** synthesize gRPC affectedness from its presence in the
module graph. Honest abstention, not an invented positive.

## 4. Bypass prevention

Apply the same structural decision at every closure surface: `states.go:289-300` early
transition; `evaluator/verdict.go:110-118,299-310`; `research/decision.go` (applicability,
proposal, symbol-authority, config routes); `research/branch_evaluator.go:450-490`;
`research/flow_adapter.go`; `report.go`, `openvex.go`, `cyclonedx.go`.

No version-only exception while leaving package/NEPF closures authorized by the same
incomplete universe. Local rules stay `ESTABLISHED` while the artifact is `HOLD_UNKNOWN`.
Reports must show "component fact established / requested scope not closed"; OpenVEX
`under_investigation`, CycloneDX `in_triage` even for a stale `NOT_AFFECTED` case object.

Persistence: **fail closed**. Missing extent/inventory ⇒ unknown completeness. Do not
reconstruct from `Basis`, id prefixes, or `AffectedModules`.

## 5. Known unenumerated surfaces (optional, not the fix)

Retaining `related` records as **scope-gap candidates** is useful signal (`GO-2023-2153` names
gRPC Rapid Reset as *related*, not an alias). But `related` ≠ equivalent, a candidate needs its
own range evidence, and no discovery proves exhaustiveness. Not a prerequisite: the projection
gate already refuses the unjustified closure without knowing gRPC exists.

Do not treat "has a GO alias" as authorization (Terrapin's GHSA/GO records have different
range representations).

## 6. Blast radius

Changes: exact broad/mixed-record negatives authorized solely via a `COMPLETE` Go projection
become `INCONCLUSIVE`. Unchanged: exact fully-represented Go-only records (version closure
kept), multi-module Go records where every entry is excluded, and all proven positives
(completeness gates universal negatives, not established vulnerable paths).

Several historical "correct-safe" labels are pre-scope/pre-target-gate observations, not
verified current closures — preserve their admissible proofs and bounded closures, not the
old labels. Nothing here claims post-change benchmark outcomes.

# Ownership, CI gates and artifact retention

Статус: actual for `consolidation/shadow-base`. Scope: S-15 — the single
published owner matrix for consolidated contracts, the named CI gates,
the retention policy for external artifacts, and the release/escalation
process. Owners are roles/agent names; human approvers are `TBD` where
not assigned.

## 1. Contract owner matrix

| Contract / surface | Owner | Bounded by | Human approval |
|---|---|---|---|
| Canonical identity & case bundle (`AnalysisCase`, run ids, intake, bundle layout) | product-a-case-owner (S-01 spec `s01-identity-and-case-bundle.md`) | `internal/domain`, `internal/repository`, `internal/case` | TBD |
| Evidence / Claim / NegativeVerification / verdict contract | product-a-evidence-owner | `internal/domain`, `internal/evidencetools`, `internal/goanalysis` | TBD |
| Security verdict semantics (`verdict`, falsifier, mandatory conditions) | product-a-evidence-owner | `internal/domain`, evaluation kernel | TBD (security review required) |
| Product B adapter boundary (type map, proposal-only ingress, FactGate, detools, heldout gate) | ProductBTriageMerge | `internal/productb/**` | TBD |
| Product B triage runtime (runner, intake, stage0, site config, artifacts, replay) | product-b-runtime | `internal/productb/triage` | TBD |
| Research/refindex/reportcheck lane (non-authoritative) | product-b-research | `internal/productb/{research,refindex,reportcheck}` | TBD |
| Deployment/assumption adapter | product-b-deployment-adapter | `internal/productb/deployment`, `productb/repository.LoadDeclaredAssumptions` | TBD |
| Schema registry (all Product B artifacts) | product-b-runtime | `internal/productb/registry.go` (S-17) | TBD |
| Retention manifest & baseline corpus governance | baseline-keeper | `docs/dev/retention-manifest.template.json`, `eval/corpus-real.json` | TBD |
| CI workflow definition & merge policy | repo-maintainer | `.github/workflows/*` | TBD |
| Target architecture & port plan | consolidation-spec-owner | `docs/dev/roadmaps/2026-10-20-target-architecture-and-roadmap.md` | TBD |

Rule of thumb: an artifact's owner is whichever row owns its schema; a
policy input (`declared-assumptions/1`, site config) is owned by the
operator who signs it, *reviewed* by the consuming adapter's owner.

## 2. Named CI gates

| Gate | Command / job | Proves |
|---|---|---|
| `fmt` | `gofmt -l .` empty | mechanical formatting, no review debt |
| `vet` | `go vet ./...` | static hygiene across all packages |
| `test` | `go test -count=1 ./internal/goanalysis ./internal/evidencetools ./internal/productb/... ./cmd/...` (plus repo-wide `./...` on Linux) | kernel + adapter units green; ported V2 suites (triage, claimshape, verify, heldoutgate, research, refindex, reportcheck, deployment) pass |
| `boundary` | `go test -run 'TestS12|TestNoSecondAuthorityContract|TestSchemaRegistry' ./internal/productb/...` | adapter isolation: no `internal/domain`/`affected`/`evaluator`/`agenttriage`/`internal/research` imports inside the productb lane; schema registry complete |
| `build` | `go build ./...` + cross-compile matrix (linux-amd64, darwin-arm64, windows-amd64) | every package + CLI compiles |
| `heldout-build` | `go vet` + `go build ./cmd/izyan-heldout-gate` | the gate binary always compiles, corpus-independent |
| `heldout-admission` | `izyan-heldout-gate` replay over the pinned 85-run corpus (`vars.HELDOUT_CORPUS`) | §8.3 hard gates: `false_safe=0`, unverified/partial/unstable/foreign reductions = 0; capability stays DEFAULT-OFF. **Fails and names the missing input** when the corpus is not provisioned — merge-ineligible, never a silent pass |
| `postport-census` | provisioned `run_census.py` (`vars.CENSUS_CORPUS` = harness dir) + `regression_guard.py --baseline-manifest $CENSUS_BASELINE` | post-port deterministic census proving Product-A verdict preservation (18 cases, `false_safe=0`) (port review item 7); census exit=1 is the drift signal — the four S-05-attributed changes (case-03/04 env improvement, case-09 harness input gap, case-10 intended V2 fail-closed) are accepted **only** with `false_safe=0`; unexplained drift, a hard harness failure (exit>1), a missing input or any false-safe fails the job |
| `census` (manual/scheduled) | `python3 va-tmp/r6-final/run_census.py --jobs 1` + `regression_guard.py` | deterministic baseline parity (18 cases, `false_safe=0`); runs offline from retained inputs |

## 3. Retention policy

External (non-repo) measurement artifacts are pinned by sha256 in the
retention manifest (`docs/dev/retention-manifest.template.json` is the
schema; per-release copies live next to the artifacts). Policy:

| Artifact class | Examples | Retention |
|---|---|---|
| Baseline corpus pin | Sanitized `eval/corpus-real.json` sha256 `d77dcd2199a8abace3bd7c21c5a3980ec8601aa94c93367756be1fd7154a660f` (original-run pin retained privately; no new run implied) | permanent (repo-pinned + hash-recorded) |
| Baseline run artifacts | `corpus-baseline.txt`, `census-output.txt`, `r6-guard-baseline.json`, case-03/04/10 reports | ≥ 2 release cycles; superseded only by a newer *recorded* run |
| Sidecars | advisory freeze, intake audit, snapshot, materials, stage0, fact-gate, observation-archive per corpus case | same cycle as parent run; delete only with the run |
| Replay artifacts | `replay manifest`, `stability-runs.json`, `heldout-gate.json` | permanent; a gate decision must always re-derive |
| Admission evidence | `falsifier-verification.json`, `decision.json`, `deployment-projection.json`, `declared-assumptions/1` records | permanent while the decision they feed is referenced |
| Secrets / private paths | never in any manifest | prohibited — `ProvenanceLocalRef`-style basenames only |

Deletion rule: an artifact is removed only when (a) its retention window
expired, (b) a superseding artifact with equal coverage is recorded with
its own hash, and (c) the supersession is named in the release notes.
Never delete the only evidence behind a published gate.

## 4. Release / merge process and escalation

1. Branch per work package (`consolidation/*`, `feat/*`); never commit
   generated artifacts, credentials or private paths.
2. Required before merge: `fmt`, `vet`, `test`, `boundary`, `build` green;
   `heldout-build` green, and `heldout-admission` + `postport-census`
   green — a corpus-missing failure names the input
   (`vars.HELDOUT_CORPUS` / `vars.CENSUS_CORPUS` + `vars.CENSUS_BASELINE`) and blocks the merge
   until provisioned, never skipped.
3. Changes touching `internal/domain` authority types, `EvidenceGraph`,
   verdict semantics, `internal/evaluator`, or the `det:`/`obs:` contract
   require review by the owning role + a security reviewer; a PR that
   weakens a fail-closed behavior is rejected, not negotiated.
4. Product B adapters may never merge into Product A authority: D17 is
   the standing rule; boundary tests enforce it mechanically.
5. Release notes must name: superseded artifacts (with hashes), schema
   additions to `productb/registry.go`, and any retained-corpus change.
6. Escalation: contract ambiguity → open a revision on the target
   architecture doc §14 (the merged-source-of-truth rule) before
   implementing; security-sensitive drift (admission loosening, evidence
   scope widening, capability defaults) → block the release until a
   `TBD`-security owner signs off.

## 5. Stale documentation policy

A spec superseded by the target architecture is marked `SUPERSEDED` in
place (never deleted — historical provenance retained) and re-labeled in
`docs/INDEX.md`. Implementation specs (S-01…S-17) each name their contract
owner; a spec without an owner row is not plan-ready.

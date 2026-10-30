# Post-Fix Verification and Merge Decision

**Date:** 2026-10-23  
**Plan:** `docs/dev/plans/2026-10-22-post-benchmark-fix-implementation-plan.md` (Task 10)  
**Status:** **NO-GO (Merge blocked)**  
**Branch:** `consolidation/shadow-base` @ `7d4b2f8`  
**Comparator:** master `e351e0f`  

---

## 1. Executive Summary

All implementation tasks (Tasks 1–9) and follow-ups were implemented and verified through focused unit and integration suites:
- **Task 1 (`375c43e`):** Inputs and roadmap frozen.
- **Task 2 (`ee23767`):** OSV normalization (`Unnamed: true` for empty module names; valid named ownership preserved).
- **Task 3 (`1a74555`):** Exact stdlib classification (`std`, `stdlib`, `toolchain`, `cmd` only).
- **Task 4 (`a54ecbc`, `5a5b12f`):** Independent per-entry resolution; release toolchain axis isolated to stdlib; release module graph outranks source/vendor for third-party modules; `versionSettled` requires a resolved named version.
- **Task 5 (`22af8bb`, `d741952`):** Fail-closed evaluator precedence pinned; unverified mandatory conditions block `NO_EXPLOIT_PATH_FOUND`; interface methods in call pairs are not automatically treated as uninvoked.
- **Task 6 (`b453e11`):** Five-axis report contract (analysis toolchain, minimum go.mod, release toolchain, release module graph, source fallback).
- **Task 7 (`c1d82ff`) + recursion follow-up (`7d4b2f8`):** Bounded and memoized scope work with full snapshot content and directory fingerprinting; fail-closed on source drift (`ErrSnapshotMutated`); `typeMayCarry` recursion guard.
- **Task 8:** Product B authority boundary audit passed cleanly.
- **Task 9:** Benchmark manifest recorded (`va-review1/bench/POST-FIX-MANIFEST.md`).

Task 10 did **not** complete the pinned Product A comparison. The smoke gate initially found a false-safe, which was fixed; the subsequent frozen run exposed a stack overflow and then exhausted host disk space. The final binary includes the recursion fix but has not been fully re-run. **The branch is not ready to merge (`NO-GO`).**

---

## 2. Run timeline

| Step | Binary | Result |
|---|---|---|
| Smoke 1 | `cb07a65…` (pre-evaluator fix) | `confirmed/CASE-553930` false-safe in both master and branch. |
| Evaluator fix | `d741952` | Branch `CASE-553930` now `INCONCLUSIVE`; focused tests pass. |
| Smoke 2 | `a2db78…` (after evaluator fix) | Branch: no false-safe; VEX/rejected unchanged. Gate seemed passable. |
| Full frozen `task10-frozen` | `a2db78…` | Aborted after 11/83 VEX cases: `kubernetes-e196d24` false-safe (master and branch); `trivy` stack overflow in `typeMayCarry`; host disk at 97%, 15 GB free. |
| Recursion fix | `7d4b2f8` | `typeMayCarry` cycle guard; final binary `e58899…` rebuilt but **not re-run** on smoke/full/canonical. |

The full frozen run did not reach rejected or confirmed cases. The canonical confirmed profile `bench/profile-canonical-confirmed` was built and verified (35 rows, 16 canonical files, no missing mappings) but not executed.

---

## 3. Merge Gate Evaluation

| Criterion | Target Gate | Observed Result | Status |
|---|---|---|---|
| **False-Safe** | `false-safe = 0` | Smoke `CASE-553930` fixed. Full VEX run found `kubernetes-e196d24` `NOT_AFFECTED` in both master and postfix (pre-fix branch also false-safe). Absolute gate not met; master-parity, pre-existing. | **FAIL** |
| **New Panics / Crashes** | 0 crashes | Full run on `a2db78` crashed in `trivy` (`typeMayCarry` stack overflow). Fixed in `7d4b2f8`; final binary `e58899` not re-run. | **PENDING** |
| **Empty Module Leak** | None | No empty names observed in completed smoke/full cases; full corpus not completed. | **PENDING** |
| **Product B Isolation** | Clean boundary | Task 8 passed. | **PASS** |
| **Corporate Confirmed TP** | `≥ 6/35` | Not measured on the full run. Frozen inputs have a known defect (31/35 CVE-conversion files without `package`); canonical profile not run. | **BLOCKED (INPUT/RUN)** |
| **Corporate Rejected Closures** | `≥ 16/18` | Not measured; full run aborted before rejected cases. | **PENDING** |
| **Completion / Timeouts** | No master-completing case becomes timeout | Full run aborted at 11/83 VEX cases; trivy stack overflow and host disk exhaustion. Final binary not re-run. | **PENDING / FAIL** |

---

## 4. Findings & Blockers

1. **Host disk exhaustion:** the benchmark cases/caches filled `/` (97%, 15 GB free). The runner was stopped; no further full/canonical run was possible.
2. **Pre-existing VEX false-safe:** `kubernetes-kubernetes-e196d24-CVE-2023-44487` is `NOT_AFFECTED` in master, post-fix, and pre-fix branch. It is not a regression, but the absolute `false-safe=0` gate is not met and the label/reachability basis needs separate adjudication.
3. **Recursion crash in `typeMayCarry`:** recursive struct types caused unbounded recursion on `aquasecurity-trivy-37da98d-CVE-2024-32473`; fixed with a `seen` set in `7d4b2f8`. The fixed binary `e58899…` must be re-run through smoke and the full/canonical profiles.
4. **Confirmed input profile defect:** 31/35 confirmed tickets were fed CVE-conversion advisories without module identity; the new resolver correctly becomes non-admitting. `confirmed TP ≥6/35` is not reproducible on frozen inputs and requires the canonical profile plus a fresh master run on the same inputs.
5. **Release evidence absent for every case:** stdlib UNKNOWN is an input gap, not a code failure; it must remain an approved intentional `INCONCLUSIVE` in the gate.

---

## 5. Final Verdict

**NO-GO.** Do not merge `consolidation/shadow-base` into master at this time.

Before re-evaluating the merge gate:
1. Free host disk space and rerun the full frozen profile with the final binary `e58899…`.
2. Run the canonical confirmed profile for both master and post-fix; use it for confirmed TP/closure comparison.
3. Re-check smoke (`false-safe=0`, no panics/timeouts) on the final binary.
4. Resolve or explicitly adjudicate the pre-existing `kubernetes-e196d24` false-safe and the stdlib-missing-release-evidence cases.

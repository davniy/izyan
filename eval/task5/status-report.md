# Task 5 — Status report after T1 rerun (PRELIMINARY)

Date: 2026-10-09. Worktree `vuln-analyzer-shadow`, branch `feat/shadow-analyzer-agent`.

## Question

Does a tuned safety prompt help relative to the historical official prompt, does the Izyan MCP evidence toolset add value on top of the *same frozen tuned base*, and is a deterministic Verification Gate justified? Development corpus: 30 Go VEX-Bench cases (7 exploitable / 23 safe), three repeats in P1 and T1.

## Execution status

| Phase | Status |
|---|---|
| 5.0 Frozen manifest, prompts, boundaries | **Done** |
| Evaluation/collection/scoring machinery (48 unit tests reported) | **Done** |
| 5.1 P1, tuned prompt without MCP | **Done, 90/90** |
| Checkpoint A | **Done, no observed durable improvement** |
| 5.2 T1, same tuned base + MCP | **Done, 90/90** after outage/reconstruction |
| Checkpoint B | **Done**, complete P1 vs T1 comparison |
| 5.3 Verification Gate | **Deferred**, not implemented |
| 5.4 Unseen holdout / final architecture decision | **Not run** |

Frozen prompts:
- P1: `eval/task5/prompts/vuln_safety_v1.txt`, sha256[:12] `14c1396c9094`.
- T1: `eval/task5/prompts/vuln_safety_v1_tools.txt`, sha256[:12] `5d6c640c6945`, extending P1 by a 534-byte `<EVIDENCE_TOOLS>` block.
- P1 vs T1: `qwen3.6-35b`, same 30 cases, snapshots and scoring protocol, `timeout=900`, `parallel=1`, 3 repeats. MCP access and the tool instructions differ by design; **effects of individual tools have not been isolated**.

## Completed results

| Arm | Runs | Official accuracy | False-Safe / exploitable attempts | Safe Clear / safe attempts | Exploitable recall | FAILED | INCONCLUSIVE |
|---|---:|---:|---:|---:|---:|---:|---:|
| P0 (historical; unmatched) | 30 | 83.3% | 1/7 | 19/23 = 82.6% | 6/7 = 85.7% | 2 | 0 |
| P1 tuned, no MCP | **90** | 80.0% | **5/21** | **58/69 = 84.1%** | **13/21 = 61.9%** | 5 | 1 |
| T1 tuned + MCP | **90** | 84.4% | **5/21** | **63/69 = 91.3%** | **13/21 = 61.9%** | 3 | 0 |

`FAILED` is neither a safe conclusion nor a valid abstention. Official accuracy is not equivalent to verified safety. Three repeats of the same seven vulnerable cases are not 21 independent vulnerabilities.

### What changed across cases (P1 → T1)

- **`k8s-44487`**: false-safe **2/3 → 0/3** (all three T1 attempts positive).
- **`cilium-1228cbc`**: false-safe **1/3 → 0/3**. This case was not one of the two shared Task 4 MCP regressions.
- **`k8s-3121`**: false-safe **1/3 → 1/3** (plus a T1 parse failure). This *was* the second shared Task 4 regression and remains unresolved.
- **`testify-28948`**: false-safe **1/3 → 3/3**; repeated new weakness in the T1 configuration.
- **`rancher-47914`**: false-safe **0/3 → 1/3**.
- **`labstack-echo`**: P1 false-alarm 3/3, T1 correct 3/3; the overall +5 safe-correct attempts reflect other offsetting changes as well. Do not attribute the complete +5 to this case.

These data show a **net improvement in safe-GT clearance** and a **redistribution, not elimination, of false-safe**. They do not prove the improvement was caused by any particular tool, nor that the earlier Task 4 regression was solely prompt-induced. The Qwen Task 4 result used a different prompt/runtime.

## Limitations and residual issues

1. **P0 vs P1 is not matched** (historical P0, one repeat and different runtime/budget). Do not claim a causal prompt-only benefit or harm.
2. P1 and T1 are complete, but there are only **seven distinct exploitable cases**, already seen throughout development. Repeats help assess instability, not independent generalization.
3. T1 MCP tools still incur notable failures (`context_canceled`, other errors); see `scoring/tool-failures.jsonl`. No corrected per-tool ablation is available.
4. Four T1 `[RE-RUN]` slots reportedly contained only prompt echo before reconstruction, not completed model replies; see `harness/reconstruction.md`. This is the report's assertion, not independently verified here against the run artifacts.
5. P1 has four `invalid_terminal_answer` failures from trailing prose after JSON; without a matched P0, they cannot be conclusively attributed to the prompt change.
6. No unseen holdout has run, and no Gate has been implemented or measured.

## Current architecture decision

**PRELIMINARY:** Neither P1 nor T1 passes the zero-false-safe target. Do not enable LLM-generated safe closure as an authoritative production action. Keep Agent assessments for research/triage with review, and retain existing deterministic verification invariants. Do not mandate MCP or construct a Gate on these results alone.

## Next controlled work

1. **Audit the saved P1/T1 per-case traces** for `testify-28948`, `k8s-3121`, `rancher-47914`, `k8s-44487`. Identify the precise negative claim and the evidence/scope boundary, rather than only the classification label.
2. **Minimal offline Gate feasibility trial** on the **saved** responses, without new model calls: can a general scope/completeness rule block actual false-safe outputs while preserving correctly safe negative outputs? Score `FS_blocked`, `safe_clear_lost`, `unresolved`, and whether the rule uses generic evidence rather than hardcoded benchmark cases.
3. Evaluate remaining options against a **frozen unseen holdout**, kept away from further prompt/tool/gate tuning. A fresh matched P0 is useful if attributing the prompt effect matters to the architecture decision.

**No requirement to rerun T1**: it is now complete. The earlier `48/90` provisional results and VPN resume instructions are historical and superseded by Checkpoint B.

See: `checkpoint-a.md`, `checkpoint-b.md`, `decision.md`, `scoring/matrix.json`, `scoring/disagreements.jsonl`, `scoring/tool-failures.jsonl`, `harness/reconstruction.md`.

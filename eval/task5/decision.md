# Task 5 — architecture decision (PRELIMINARY)

**Status: PRELIMINARY.** Both arms are complete (30×3 each), but no unseen
holdout has been run. Per spec §5.4 this document therefore **cannot** claim
proven safety or a final architecture. It records the decision the evidence
supports and what would change it.

## Evidence base

| Arm | Design | FS / 21 | SCR | Recall | FAILED |
|---|---|---:|---:|---:|---:|
| P0 | official `vuln`, no MCP | 1 (n=1, historical) | 82.6 % | 85.7 % | 2 |
| P1 | `vuln_safety_v1`, no MCP | **5** | 84.1 % | 61.9 % | 5 |
| T1 | `vuln_safety_v1_tools`, + MCP | **5** | **91.3 %** | 61.9 % | 3 |

Full per-case detail: `checkpoint-a.md`, `checkpoint-b.md`, `scoring/matrix.json`,
`scoring/disagreements.jsonl`, `scoring/tool-failures.jsonl`, `scoring/safety-report.md`.

## Findings

1. **The tuned prompt alone did not produce durable improvement (Checkpoint A).**
   False-safes persisted on the same hard cases that broke the Task 4 tools arm
   (`k8s-44487`, `k8s-3121`) and it exhibited a formatting failure mode
   (`invalid_terminal_answer` ×4: the model appends prose after the JSON).
   Strict recall fell largely because 5 attempts FAILED — and FAILED is never
   safe. The P0↔P1 delta is historical (P0 n=1), so no causal claim.

2. **MCP is a wash on safety, a net gain on the safe side (Checkpoint B,
   complete).** With the tuned prompt, P1 and T1 both score **FS = 5 / 21** —
   MCP did not reduce the total. But the distribution differs decisively: MCP
   **improves two P1 cases** (`k8s-44487` false-safe 2/3 → correct
   3/3; `cilium-1228cbc` 1/3 → correct 3/3). These are observed differences
   between Task 5 arms, not proof of the mechanism. In Task 4 the two shared
   Qwen MCP regressions were `k8s-44487` and `k8s-3121` (not `cilium`), and
   `k8s-3121` remains unresolved. T1 repeatedly answers false-safe on
   `testify-28948` (3/3 vs P1 1/3), and once on `rancher-47914`. Safe Clear Rate rises
   84.1 % → 91.3 % and operational failures fall 5 → 3. MCP cost stays real
   (high `context_canceled`/error rate).

3. **A Gate admission signal now exists, but Gate is still deferred.** A
   concrete, reproducible post-tune unsafe-safe class survives in both arms
   (`code_not_reachable` on an exploitable case; `testify-28948` 3/3 under T1,
   `k8s-3121` in both) — the §5.3 signal. The pattern appears across multiple cases, but "no simpler reliable answer exists" is not established, so
   per plan §9 `internal/verificationgate` is **not** created and `gate-replay` /
   `score-gate` remain stubs.

## Decision (per spec §10 table)

**Row: no variant yet clears the safety bar on a complete matched set — keep the
Agent as a research/triage assistant under human review, with no automatic safe
closure.** Neither arm drives false-safe to zero, so the question of MCP-vs-prompt
is answered "not sufficient" either way.

Concretely:

- **Do not** add MCP to a mandatory production path on this evidence; its safety
  benefit is a redistribution, not a reduction, and it carries tool-failure cost.
- **Do not** treat the tuned prompt as sufficient; it did not clear the
  safety-critical cases on its own.
- **Do not** build the Verification Gate yet — the surviving unsafe-safe cases do not yet demonstrate that simpler remedies fail.
- **Keep** the deterministic invariants regardless of the eventual choice: LLM
  prose, model confidence, a tool `OK`, or an empty result is **not** proof of
  safety, and the product right to auto-close a finding does not follow from any
  benchmark score.

## What would change this

- **An unseen holdout** of new cases/projects, frozen before use, to replace the
  now-known 30-case development set — required before any final architecture call.
- **A Gate admission trial** (plan §9): minimal offline replay targeting the
  observed `code_not_reachable`-on-exploitable pattern, to test whether a general rule
  blocks it without overblocking correct safe answers.
- **A matched P0** under this protocol, if a causal prompt-effect claim is needed
  (P0 is currently n=1 historical).

## Unproven / open

- 7 distinct exploitable cases (21 repeated attempts) is a coarse denominator: one attempt ≈ 4.8 pp and one case wrong in 3/3 repeats shifts the pooled rate by ≈ 14.3 pp; FS=5 tie is coarse.
- P0↔P1 is historical, not matched.
- The known VEX-Bench cases are a development set, not an unseen test.
- No claim of proven safety is made anywhere in Task 5.

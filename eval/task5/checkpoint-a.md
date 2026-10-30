# Task 5 — Checkpoint A (prompt-only arm P1)

Written before starting T1, per `docs/dev/plans/2026-10-09-task5-implementation-plan.md` §7.

## Setup

- Arm **P1**: `vuln_safety_v1` (frozen official `vuln` prefix + `<SAFETY_RULES>`), agent `opencode-b1p`, **no MCP**, model `qwen3.6-35b` (custom-openai), `timeout=900`, `parallel=1`, `repeats=3`.
- Prompt hash (sha256[:12]) `14c1396c9094`; harness registry byte-checked equal to `eval/task5/prompts/vuln_safety_v1.txt`.
- 30 Go cases × 3 attempts = 90 attempts. Layout `eval/task5/results/p1/14c1396c9094/opencode-b1p/qwen3.6-35b/`.
- Reference arm **P0** = historical Task 4 Qwen3.6 plain (`vuln`, no MCP), **n=1 repeat**, different runtime/budget. The comparison below is therefore *historical*, not causal.

## Result

| Arm | Rows | Repeats | Acc (official) | FS strict | SCR strict | Recall strict | INCONCLUSIVE | FAILED |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| p0 (historical) | 30 | 1 | 83.3% | **1** | 82.6% | 85.7% | 0 | 2 |
| p1 | 90 | 3 | 80.0% | **5** (2 / 1 / 2) | 84.1% | **61.9%** | 1 | 5 |

Per-repeat outcome distribution (30 cases each): run_001 positive 8 / safe 22; run_002 positive 6 / safe 19 / abstain 1 / failed 4; run_003 positive 7 / safe 22 / failed 1.

## False-safe cases (GT exploitable, final safe) — P1

| Case | run_001 | run_002 | run_003 |
|---|---|---|---|
| `kubernetes-kubernetes-e196d24-CVE-2023-44487` | positive | **safe: code_not_present** | **safe: code_not_present** |
| `kubernetes-kubernetes-ec78c0f-CVE-2021-3121` | **safe: code_not_reachable** | positive | positive |
| `cilium-cilium-1228cbc-CVE-2026-35469` | positive | failed | **safe: code_not_reachable** |
| `stretchr-testify-285adcc-CVE-2022-28948` | **safe: code_not_reachable** | positive | positive |
| `caddyserver-caddy-8dc7667-CVE-2025-29785` | positive | positive | positive |
| `containers-podman-6a65597-CVE-2023-48795` | positive | failed | positive |
| `rancher-rancher-4dc4f53-CVE-2025-47914` | positive | positive | failed |

Historical P0 had exactly one false-safe on this set (`rancher-47914`).

## Failures (not safe, not INCONCLUSIVE)

| Case / run | `status_overall` | reason |
|---|---|---|
| `aquasecurity-trivy-37da98d-CVE-2024-32473` run_002 | failed | `invalid_terminal_answer` |
| `cilium-cilium-1228cbc-CVE-2026-35469` run_002 | failed | `invalid_terminal_answer` |
| `containers-podman-6a65597-CVE-2023-48795` run_002 | failed | `invalid_terminal_answer` |
| `kubernetes-kubernetes-6d4b94f-CVE-2022-41717` run_002 | failed | `container_nonzero_exit` (inner `timeout 900` → exit 124) |
| `rancher-rancher-4dc4f53-CVE-2025-47914` run_003 | failed | `invalid_terminal_answer` |
| `rancher-rancher-8761419-CVE-2026-24051` run_002 | inconclusive | — |

**Root cause of `invalid_terminal_answer` (inspected raw artifact):** the model emits the required JSON object **and then appends a prose summary**. The official terminal-text rule takes the *last* assistant text part, so the trailing prose is parsed instead of the JSON → parse fail. Parser-audit recovered 0 of these (the last text carries no full JSON object). This is an observed output-format drift under P1, not a scoring defect. Attribution to the prompt specifically is not established because P0 is historical and unmatched.

## Checkpoint A decision

**No durable improvement was observed under P1.** On this set the tuned prompt:

- did **not** reduce false-safes (2/1/2 per repeat, mean 1.67, vs 1 in the n=1 historical baseline);
- left the same hard cases unsafe (`k8s-44487`, `k8s-3121` — the same two that broke the Task 4 tools arm);
- depressed strict recall (61.9%), partly because 5 attempts are FAILED (which recall counts as non-positive, and which are explicitly *not* safe);
- exhibited four `invalid_terminal_answer` failures from trailing prose after JSON; whether this was caused by the revised prompt requires a matched P0 run.

Transition classes (paired observed attempts, p0→p1): `stable_safe` 17, `stable_positive` 4, `false_safe_appeared` 2, `false_safe_cleared` 1, `false_alarm_appeared` 3, `false_alarm_cleared` 2, `safe_gained_from_failed` 1.

**Limitations.** P0 has n=1, a different runtime/budget and a different prompt version; the P0↔P1 delta is historical and cannot isolate the prompt effect. A causal prompt-effect claim requires a fresh matched P0 under this protocol (deferred). 7 exploitable cases give a coarse denominator (one case ≈ 14 pp).

**Consequence for T1.** T1 is still required (§5.2): it answers whether MCP adds value *on top of this same frozen base prompt*, and Task 4 showed the tools arm could be worse. T1 keeps the identical frozen P1 base and differs only by the `<EVIDENCE_TOOLS>` block plus the live `mcp.izyan` server.

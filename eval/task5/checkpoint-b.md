# Task 5 — Checkpoint B (tools arm T1) — COMPLETE

Supersedes the earlier contamination-limited Checkpoint B. T1 finished 90/90 on
2026-10-09 after the harness was reconstructed and moved out of `/tmp`
(see `harness/reconstruction.md`).

## Setup

- **P1**: `vuln_safety_v1`, agent `opencode-b1p`, **no MCP**, `qwen3.6-35b`, 30×3.
- **T1**: `vuln_safety_v1_tools` (= exact P1 bytes + 534-byte `<EVIDENCE_TOOLS>`), agent `opencode-c1`, live `mcp.izyan`, same model/tasks/budget, 30×3.
- Prompt hashes: `14c1396c9094` (P1) / `5d6c640c6945` (T1); identical task manifest, snapshots (28/28 content-verified), timeout=900, parallel=1.

## Headline

| Arm | Rows | Acc (official) | FS strict | SCR strict | Recall strict | FAILED | abstain |
|---|---:|---:|---:|---:|---:|---:|---:|
| p1 | 90 | 80.0 % | **5 / 21** | 84.1 % | 61.9 % | 5 | 1 |
| t1 | 90 | 84.4 % | **5 / 21** | **91.3 %** | 61.9 % | 3 | 0 |

**The false-safe count is identical (5 of 21 exploitable attempts), but the
distribution is not.** MCP did not reduce total false-safes; it moved them.

## False-safe slots, per arm

| Case | P1 (r1/r2/r3) | T1 (r1/r2/r3) |
|---|---|---|
| `kubernetes-kubernetes-e196d24-CVE-2023-44487` | vuln / **cnp** / **cnp** | vuln / vuln / vuln |
| `cilium-cilium-1228cbc-CVE-2026-35469` | vuln / parse_fail / **cnr** | vuln / vuln / vuln |
| `kubernetes-kubernetes-ec78c0f-CVE-2021-3121` | **cnr** / vuln / vuln | vuln / **cnr** / parse_fail |
| `stretchr-testify-285adcc-CVE-2022-28948` | **cnr** / vuln / vuln | **cnr** / **cnr** / **cnr** |
| `rancher-rancher-4dc4f53-CVE-2025-47914` | vuln / vuln / vuln | vuln / **cnr** / vuln |

(cnp = `code_not_present`, cnr = `code_not_reachable`)

### Cases improved in T1; distinction from Task 4

- **`k8s-44487`**: P1 false-safe 2/3 (`code_not_present`); **T1 correct 3/3**. This **is** one of Task 4's shared Qwen false-safe cases after MCP was added.
- **`cilium-1228cbc`**: P1 false-safe 1/3; **T1 correct 3/3**. This is an improvement **relative to P1**, but was **not** one of the two shared Task 4 MCP regressions.
- **`k8s-3121`**, the **other** shared Task 4 regression: P1 false-safe 1/3; T1 false-safe 1/3 plus one parse failure. It **was not fixed**.

The T1 configuration has better outcomes on some specific cases than P1, and
`k8s-44487` no longer reproduces the Task 4 negative. This **does not prove**
that the earlier regression was caused by the prompt, or that a particular MCP
tool corrected it. Task 4 and Task 5 differ in instructions and runtime; no
tool-level ablation isolates the mechanism, and 3 attempts are a small sample.

### MCP introduced a new systematic false-safe

- **`testify-28948`**: P1 false-safe 1/3; **T1 false-safe 3/3** — repeated wrong "not reachable" under MCP. All three sampled attempts failed; this is a concrete recurring defect, not proof of determinism or of its root cause.
- `rancher-47914`: P1 0 FS → T1 1 FS.
- `k8s-3121`: persists in both (P1 1 FS, T1 1 FS).

## Other effects

- **SCR improves materially**: 84.1 % → 91.3 % (58/69 → 63/69 safe-correct).
  Partly `labstack-echo-CVE-2020-26160` (P1 false-alarmed 3/3, T1 correct 3/3).
- **Fewer unsuccessful attempts**: `FAILED` 5 → 3 (their precise categories must be audited separately; not all are necessarily parser failures).
- **Recall unchanged** (13/21 = 61.9 % both). Negative claims on exploitable cases persist, with different case distribution between arms.
- MCP cost is real: high `context_canceled`/error rate again (see
  `tool-failures.jsonl`).

## Checkpoint B decision

**MCP + tuned prompt is a wash on the safety-critical axis, with a clear
redistribution and a better safe side.** Concretely:

- Total false-safe is unchanged (5/21). Do **not** claim MCP improves safety.
- T1 eliminates the observed P1 negatives on `k8s-44487` and `cilium-1228cbc`, while the second Task 4 shared failure (`k8s-3121`) persists. **Do not infer** that the Task 4 regression was prompt-caused or that MCP necessarily fixed it; the mechanism was not isolated.
- T1 exhibits recurrent false-safe on `testify-28948` (3/3), more frequent than P1 (1/3), and costs
  tool-call failures — so it is not free, and not uniformly better.
- The safe side (SCR 91 % vs 84 %) and stability (fewer failures) favor T1.

**Consequence for Gate (5.3).** A concrete, reproducible unsafe-safe class exists
in both arms and survives the tuned prompt (`code_not_reachable` on an
exploitable case, e.g. `testify-28948` 3/3 under T1; `k8s-3121` in both). That is
the admission signal §5.3 asks for. However, there are **multiple** false-safe cases (`testify`, `rancher`, `k8s-3121`), and §5.3 requires also that no simpler reliable answer exists — which has not been established. Gate therefore remains **deferred to a
follow-up decision**, not started; the minimal offline-replay design in plan §9
is the next step if pursued.

## Limitations

- 7 distinct exploitable cases, each repeated three times (21 attempts). One **attempt** is 1/21 ≈ 4.8 percentage points; one case failing in all three repeats is 3/21 ≈ 14.3 points. Repeats are **not independent cases**. The FS=5 tie is coarse and does not imply equal underlying risk.
- P0 is an n=1 historical reference (different runtime/budget), not a matched
  control; no causal prompt-effect claim is made.
- The known VEX-Bench set is a development benchmark, not an unseen holdout.
- Four T1 slots were harness `[RE-RUN]`s; each held no model answer before the
  resume (prompt echo only), so they are genuine first attempts, not replacements
  (see `harness/reconstruction.md`).

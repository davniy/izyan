# Task 6 — development-run findings (P2)

Env: frozen manifest `eval/task6/experiment-manifest.json` (30 tasks, model
`qwen3.6-35b`, timeout 900, `vuln_safety_v2`). P2 = structured prompt, no MCP.
Raw results gitignored; scoring under `eval/task6/scoring/p2/`.

## P2 outcome (90 attempts = 30 × 3)

| status | n | share |
|---|---:|---:|
| `ok` (parsed, scored) | 56 | 62 % |
| `parse_fail` (result present, no parseable category) | 22 | 24 % |
| `no_result` (container timeout, `exit 124`) | 12 | 13 % |

Among the 56 `ok`: **False-Safe = 1** (unique case `rancher-…-CVE-2025-47914`),
safe-clear 39/45, exploitable recall 10/11.

The 12 `no_result` split into a **host/VPN window** (9 consecutive timeouts
00:19–02:20: istio ×4, helm ×3, k8s ×3) plus 3 isolated (`caddy` 21:46,
`podman` 23:41). Not a code defect.

## Headline finding — the structured envelope is NOT sufficient yet

Parse rate regressed sharply versus the Task-5 P1 baseline:

| arm | prompt | `ok` |
|---|---|---:|
| P1 (Task 5) | official + `<SAFETY_RULES>` (category+reasoning) | **85/90 (94 %)** |
| P2 (Task 6) | P1 + `<STRUCTURED_ASSESSMENT>` (large nested object) | **56/90 (62 %)** |

`parse_fail` causes (audited per attempt, generic):

| cause | n | example |
|---|---:|---|
| prose summary instead of the JSON object | 8 | `zeromicro-…-CVE-2022-32149 run_002`: "The output is clean and complete. The JSON assessment has been produced…" — no object in any message |
| JSON emitted as a **double-escaped string** | 1 | `labstack-echo-… run_001`: `"{\"category\":\"vulnerable\",…}"` |
| malformed / brace-breaking object | 13 | large `reasoning` with nested `{}` defeats the official brace-counting parser |

Neither the official parser nor the string-aware `parser_audit` extractor
recovers these (0/22) — the object is genuinely absent or not a JSON object.
`collect` agrees (`assessment_schema == valid` for 0 of the 22).

**Interpretation.** P1 (small object) parses reliably; adding the large
`assessment` object pushes Qwen 3.6 past its reliable-JSON budget in ~1/3 of
answers. This is a property of the *prompt/schema*, not the pipeline (the
parser correctly rejects malformed output) and not the model's analysis (the
`ok` subset is normal). It directly answers completion criterion 1
("достаточно ли структурированного промпта?"): **not yet — the envelope must be
made robust (or the schema simplified) before it can gate real answers.**

Caveat: the official parser is intentionally strict and unchanged (plan §9/§17);
a permissive recovery of the escaped form would change the comparison, so no
parser change is made retroactively.

## Next

T2 (structured prompt + 31 MCP tools, `--repeats 1`) is the matched comparison
for P2 `run_001`. Its parse rate tells whether the ~24 % loss is the prompt
schema (both arms) or MCP-specific.

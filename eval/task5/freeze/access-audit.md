# Task 5 access audit — agent/GT isolation boundary (phase 5.0)

Generated 2026-10-09T01:57:43Z by
`eval/vexbench_task5.py freeze-history`. Sources: the Task-4 synthetic
battery (`eval/c1/freeze/synthetic-checks.json`), the opencode adapter
sources (`src/evaluate/agents/opencode*.py`), and the C1 harness README.

## What reaches the attempt container

| Channel | Content | Boundary |
|---|---|---|
| `/work` | `docker cp` of the snapshot checkout only (`repos/<owner>/<repo>/<commit>/`) | no `.git` is copied into the image namespace beyond what acquisition produced; nothing outside the snapshot tree |
| `/tmp/prompt.txt` | rendered prompt = template + `{cve_id}` only | task_id/repo/commit/GT never rendered (asserted in smoke + unit tests) |
| provider config | synthesized `opencode.json` mounted under the attempt's artifacts dir | api key via `{env:OPENAI_API_KEY}` interpolation — never a literal secret in artifacts |
| env | `opencode.env` credentials only | `container_fs_allowlist` check: no benchmark/GT/results files or host paths inside the attempt FS (synthetic evidence: `forbidden_hits=[]`, `ok=True`) |
| MCP audit | `izyan-audit/tool_calls.jsonl` written inside the container, exported to artifacts | host-side results are never mounted in |

## What never reaches the agent

- `ground_truth`, `ground_truth_category`, reference PR — the harness
  renders ONLY `{cve_id}` into the prompt (`run.py`); the tasks JSONL
  lives host-side at `/tmp/vexbench-agent-ctl/benchmark/` and is not
  mounted.
- Host results/foreign sessions — no bind mounts of `results/` or other
  run roots into the container.
- Neighbour snapshots — only the task's own snapshot is copied.

## MCP traversal evidence (Task-4 synthetic battery, frozen)

`mcp_traversal` probe on `izyan-evidence-tools` (allowexec image):
statuses `{"dotdot": "ERROR", "dotdot_abs": "ERROR", "absolute_etc": "ERROR", "work_parent_escape": "ERROR", "gt_search": "OK"}` — `../`, absolute `/etc`,
`/work/..` escapes all rejected with `tool_status=ERROR`; a
`search_source('ground_truth')` probe matched
`0` files inside the snapshot.

Per-call audit fields recorded: tool, args digest, tool_status,
completeness, subject/scope, limitations, latency, adapter version —
`artifacts/izyan-audit/tool_calls.jsonl` per attempt; missing fields
remain null, never invented.

## Known boundary failures from history (frozen, not re-litigated)

- B2 (Gemini host subagent) read GT in 11/29 transcripts — host-side
  subagents have no FS isolation; cohort excluded from blind evidence.
- Qwen ISO runs: `/tmp/vexbench-baseline` is absent inside the container
  (verified: `find / -name go-tasks.jsonl` → nothing; the read-only
  provider config mount is the only exception, per baseline doc §8).

## Policy carried into Task 5

- Smoke task selection happens controller-side before any answer is
  examined; labels are never rendered to the agent.
- Scorer/GT stay controller-only; any future Gate receives allowlisted
  projections only (manifest `gt_policy`).

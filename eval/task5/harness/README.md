# Task 5 harness diff — `/tmp/vexbench-agent-ctl`

Аддитивный патч поверх **Task-4-patched** harness (HEAD `c71f512`, т.е.
состояние после применения `eval/c1/harness/vexbench-agent-ctl-c1.patch`).
Внешний harness не является частью этого репозитория; патч —
воспроизводимый артефакт.

## Файл

- `vexbench-agent-ctl-task5.patch` — unified diff `c71f512..03648e8`,
  применяется через `git apply` к checkout'у на коммите `c71f512`.

## Что делает патч (минимум, только регистрация промптов)

| Файл | Изменение |
|---|---|
| `src/evaluate/prompts.py` | `PROMPTS["vuln_safety_v1"]` и `PROMPTS["vuln_safety_v1_tools"]` грузятся через существующий `_load_prompt_file` — тот же механизм, что у Task 4 `vuln_assess`/`vuln_c1`/`vuln_tools`. |
| `src/evaluate/prompts_data/vuln_safety_v1.txt` (новый) | P1: замороженный официальный `vuln` (byte-exact префикс) + блок `<SAFETY_RULES>`. |
| `src/evaluate/prompts_data/vuln_safety_v1_tools.txt` (новый) | T1: точные байты P1 + два LF + литеральный блок `<EVIDENCE_TOOLS>`. |

Frozen-копии промптов, sha256 и точный diff — в `eval/task5/prompts/`
(`vuln_safety_v1.txt` `14c1396c9094`, `vuln_safety_v1_tools.txt`
`5d6c640c6945`, `hashes.json`, `p1-t1.diff`); генератор —
`eval/task5/protocol.py` (`python -m eval.task5.protocol`).

## Чего патч НЕ делает

- Нет новых agent-профилей: P1 едет на существующем `opencode-b1p`
  (без `mcp`), T1 — на `opencode-c1` (`mcp.izyan`). Различие рук — ровно
  tool-блок в промпте + `mcp` в синтезируемом opencode.json.
- `run.py`, `parse.py`, `result_parser.py`, `metrics.py`, адаптеры и
  образы неизменны; pyc-кэши синхронизируются отдельным коммитом и в
  патч не входят.
- Нет case-specific hints; оба промпта содержат только общие правила
  (скан prohibited-идентификаторов — в `eval/task5/protocol.py`).

## Применение и проверка

```bash
cd /tmp/vexbench-agent-ctl          # HEAD = c71f512 (task4-patched)
git apply <repo>/eval/task5/harness/vexbench-agent-ctl-task5.patch
# проверено: git apply --check на чистом checkout c71f512 даёт дерево,
# идентичное применённому (prompts.py + 2 data-файла).

# Drift-check промптов против реестра harness:
cd <repo>
/tmp/vexbench-agent-ctl/.venv/bin/python -m eval.task5.protocol \
    --out eval/task5/prompts --harness-dir /tmp/vexbench-agent-ctl

# P1 smoke (без MCP):
uv run --locked --no-sync vex-bench evaluate run \
  --agent opencode-b1p --prompt vuln_safety_v1 --model qwen3.6-35b \
  --benchmark vex_bench --repeats 3 --timeout 900 --parallel 1 \
  --repos-dir /tmp/vexbench-baseline/repos --output-dir <out>/p1

# T1 smoke (с izyan MCP):
uv run --locked --no-sync vex-bench evaluate run \
  --agent opencode-c1 --prompt vuln_safety_v1_tools --model qwen3.6-35b \
  --benchmark vex_bench --repeats 3 --timeout 900 --parallel 1 \
  --repos-dir /tmp/vexbench-baseline/repos --output-dir <out>/t1
```

Коммит в harness: `03648e8 task5-prompts: register
vuln_safety_v1(+_tools) prompt variants`.

## Fixup patch (validate BEFORE applying to a new checkout)

`vexbench-agent-ctl-task5-fixup.patch` carries two corrections that the frozen
Task 4 patch omitted and that the original working tree held only locally. They
are **required for a faithful replay** and were validated during the
2026-10-09 reconstruction (`harness/reconstruction.md`):

| File | Change |
|---|---|
| `src/evaluate/agents/opencode.py` | `MODEL2NAME` gains the self-hosted entries: `qwen3.6-35b → custom-openai/Qwen/Qwen3.6-35B-A3B`, `qwen3.8-27b → custom-openai/Qwen/Qwen3.8-27B`, `gemini-3.8-flash-high → antigravity/gemini-3.8-flash-high`. |
| `benchmark/tasks/vex_bench.jsonl` | replaced by the **Go-filtered 30-task** subset (upstream 75-task file kept as `vex_bench.upstream75.jsonl`); `load_tasks` applies no filter, so the task file itself must be the subset. |

**Apply order** (fresh clone at the pinned upstream commit):

```bash
git clone https://github.com/steven1518/vex-bench && cd vex-bench
git checkout 80cddeac3132826bfd47227ad59b2e6618a681bd
git apply --binary --exclude='*.pyc' --exclude='*__pycache__*' <repo>/eval/c1/harness/vexbench-agent-ctl-c1.patch
git apply --exclude='*.pyc' --exclude='*__pycache__*'        <repo>/eval/task5/harness/vexbench-agent-ctl-task5.patch
git apply <repo>/eval/task5/harness/vexbench-agent-ctl-task5-fixup.patch
uv sync --frozen --python 3.13
```

The fixup patch also carries the Go-subset task file (a data change, so plain
`git apply`; keep the upstream 75-task file aside first if you want it).

The fixup patch applies cleanly on top of the c1+task5 patch chain; the `.pyc`
hunks in the earlier patches are irrelevant on a fresh clone (Python recompiles).
`benchmark/tasks/vex_bench.jsonl` must hash to `60b55373031dca97009d2e89ef8dfdf0ba083f9ce1035470fdf46f0da15384b3`;
the frozen manifest pins that hash, so drift is a hard error at `collect`/`score`.

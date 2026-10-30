# Task 6 harness diff — `vexbench-durable/agent-ctl`

Аддитивный патч поверх **Task-5-patched** harness (т.е. состояние после
применения `eval/c1/harness/vexbench-agent-ctl-c1.patch`,
`eval/task5/harness/vexbench-agent-ctl-task5.patch` и
`eval/task5/harness/vexbench-agent-ctl-task5-fixup.patch`).
Внешний harness не является частью этого репозитория; патч —
воспроизводимый артефакт.

## Файл

- `vexbench-agent-ctl-task6.patch` — unified diff, применяется через
  `git apply` к checkout'у с уже применённой Task-5 цепочкой
  (pre-image `src/evaluate/prompts.py` = blob `116dac0`, т.е. ровно
  пост-состояние Task-5 патча). Проверено: `git apply --check`
  проходит без конфликтов.

## Что делает патч (минимум, только регистрация промптов)

| Файл | Изменение |
|---|---|
| `src/evaluate/prompts.py` | `PROMPTS["vuln_safety_v2"]` и `PROMPTS["vuln_safety_v2_tools"]` грузятся через существующий `_load_prompt_file` — тот же механизм, что у Task 4/5. |
| `src/evaluate/prompts_data/vuln_safety_v2.txt` (новый) | P2: замороженный официальный `vuln` (byte-exact префикс) + `<SAFETY_RULES>` (verbatim из Task 5) + `<STRUCTURED_ASSESSMENT>` (новый блок, spec §3 / schema `agent-assessment/2`; после smoke 6.3 усилен явным правилом «весь ответ — ровно один JSON-объект» и контр-примером `file:` ref). |
| `src/evaluate/prompts_data/vuln_safety_v2_tools.txt` (новый) | T2: точные байты P2 + два LF + task6-локальный `<EVIDENCE_TOOLS>`-блок (binding-rules вариант C1 с именами полей под `agent-assessment/2`, не короткая Task-5 заметка). |

Frozen-копии промптов, sha256 и точный diff — в `eval/task6/prompts/`
(`hashes.json`, `p2-t2.diff`); генератор — `eval/task6/protocol.py`
(`python -m eval.task6.protocol`). Патч генерируется из того же
`build_prompt`, поэтому байты внутри него == frozen-копиям.

## Чего патч НЕ делает

- Нет новых agent-профилей: P2 едет на существующем `opencode-b1p`
  (без `mcp`), T2 — на `opencode-c1` (`mcp.izyan`). Различие рук — ровно
  tool-блок в промпте + top-level `mcp` в синтезируемом opencode.json
  (`config_delta_only_mcp` проверяется в `eval/task6/protocol_test.py`).
- `run.py`, `parse.py`, `result_parser.py`, `metrics.py`, адаптеры и
  образы неизменны. Новых MCP-инструментов нет: T2 использует те же 31
  evidence tools, что и T1.
- Нет case-specific hints: оба промпта содержат только общие правила
  (скан prohibited-идентификаторов — `eval/task6/protocol.py`,
  переиспользует `eval/task5/protocol.py` find_prohibited/scan_prompts).

Примечание: T2-блок `<EVIDENCE_TOOLS>` — task6-локальная копия C1-текста
(`eval.task6.protocol.EVIDENCE_TOOLS_BLOCK_TASK6`, НЕ verbatim C1):
единственная правка — имена полей под схему `agent-assessment/2`
(`assessment.negative_claims[].evidence_refs` вместо v1
`claims[].evidence_refs`/`evidence[]`, которых в контракте Task 6 нет).
Все binding/completeness/scope-правила неизменны.

Задокументированное ограничение: T2 объявляет агенту, что evidence tools
подключены, а arm без инструментов (P2) такого объявления получить не
может — это остаточная P2↔T2 асимметрия промпта (кроме блока инструментов
промпты байт-идентичны), учитывается при интерпретации V-P2 vs V-T2.

## Применение и проверка

```bash
cd <agent-ctl>                    # после Task-4/5 цепочки патчей
git apply --check <repo>/eval/task6/harness/vexbench-agent-ctl-task6.patch
git apply        <repo>/eval/task6/harness/vexbench-agent-ctl-task6.patch

# Drift-check промптов против реестра harness (после применения):
cd <repo>
<agent-ctl>/.venv/bin/python -m eval.task6.protocol \
    --out eval/task6/prompts --harness-dir <agent-ctl>

# P2 (без MCP):
uv run --locked --no-sync vex-bench evaluate run \
  --agent opencode-b1p --prompt vuln_safety_v2 --model qwen3.6-35b \
  --benchmark vex_bench --repeats 3 --timeout 900 --parallel 1 \
  --repos-dir <repos> --output-dir <out>/p2

# T2 (с izyan MCP):
uv run --locked --no-sync vex-bench evaluate run \
  --agent opencode-c1 --prompt vuln_safety_v2_tools --model qwen3.6-35b \
  --benchmark vex_bench --repeats 3 --timeout 900 --parallel 1 \
  --repos-dir <repos> --output-dir <out>/t2
```

Apply order (fresh clone at the pinned upstream commit):

```bash
git clone https://github.com/steven1518/vex-bench && cd vex-bench
git checkout 80cddeac3132826bfd47227ad59b2e6618a681bd
git apply --binary --exclude='*.pyc' --exclude='*__pycache__*' <repo>/eval/c1/harness/vexbench-agent-ctl-c1.patch
git apply --exclude='*.pyc' --exclude='*__pycache__*'        <repo>/eval/task5/harness/vexbench-agent-ctl-task5.patch
git apply <repo>/eval/task5/harness/vexbench-agent-ctl-task5-fixup.patch
git apply <repo>/eval/task6/harness/vexbench-agent-ctl-task6.patch
uv sync --frozen --python 3.13
```

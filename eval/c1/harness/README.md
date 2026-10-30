# C1 harness diff — `/tmp/vexbench-agent-ctl` (Task 4.2)

Внешний VEX-Bench harness (`/tmp/vexbench-agent-ctl`, не git-репозиторий)
расширен additive-патчем для C1. Патч — воспроизводимый артефакт; исходный
checkout можно пересоздать и переприменить.

## Task 4a — shared C1 runtime (first-layer VEX parity)

For the first-layer ablation (architect decision A, 2026-10-24) every arm
A–E runs the **same legacy C1 image and pipeline**:

| Arm | Harness profile | Image | `mcp` block |
|---|---|---|---|
| A–D | `opencode-c1-nomcp` | `vex-bench-<lang>-opencode-c1:latest` | absent (no registration, no server start) |
| E | `opencode-c1` | same tag and digest | exactly `mcp.izyan`, pinned to `/work` + CVE |

`opencode-c1-nomcp` is a direct subclass of `OpenCodeB1PrimeAgent`; it does
not inherit `OpenCodeC1Agent`, so no code path can add the server. Both
profiles inherit the same `OpenCodeAgent.PIPELINE`
(`opencode-run-export/v1`) and report it via
`effective_config_facts()` together with the image suffix, canonical model
binding (`custom-openai/Qwen/Qwen3.6-35B-A3B`), resolved env/config paths, exported
artifact names and the generated config. `build_config(cve_id=...)`
generates the launch config without starting a container, so a controller
can prove A–D configs are identical and E differs only by `mcp.izyan`.

Credential/config paths are resolved **per call** from
`VEXBENCH_HOST_ENV_FILE` / `VEXBENCH_HOST_CONFIG` (unset ⇒ the historical
CWD-relative `env/opencode/*` defaults). The ablation controller sets both
for adapter inspection and for every attempt, so the file it validated is
the file passed to `--env-file` / mounted as the config.

- `vexbench-agent-ctl-c1-runtime.patch` — cumulative runtime diff against
  the harness git baseline **`80cddea`** (tracked agent files + the C1
  adapters/Dockerfiles/build script; `docker/bin/` is a build artifact and
  is not included). It applies cleanly with `git apply` and reproduces the
  sanitized runtime files (patch sha256
  `b6f382841a12741dc1682a28c12d577a0b3196c7afca5ed4211caf6f2a7d4814`).
  It is the patch for the current checkout; `vexbench-agent-ctl-c1.patch`
  remains the historical Task 4.2 artifact and is **not** regenerated (its
  `/tmp` checkout is gone and its provenance is referenced by frozen
  manifests).
- Original pre-redaction external artifact hashes (historical only; not hashes
  of files produced by the sanitized patch):
  `src/evaluate/agents/opencode.py` `7cd3fa88…`,
  `src/evaluate/agents/opencode_c1.py` `a44780e2…`,
  `src/evaluate/agents/__init__.py` `5a658258…`,
  `docker/build-c1.sh` `5a4452e9…`,
  `docker/go.opencode-c1.Dockerfile` `0530fa18…`.
- Build only the image this experiment needs:
  `C1_IMAGES=opencode docker/build-c1.sh <izyan-checkout> <ref>`.
  `go.opencode-c1.Dockerfile` copies `bin/izyan-evidence-tools` relative to
  the `docker/` build context (the pre-4a file said `docker/bin/…`, which
  cannot resolve with that context).
- Do not commit the external harness or `docker/bin/` / `c1-image.stamp`.

## Файлы

- `vexbench-agent-ctl-c1.patch` — cumulative unified diff против baseline-
  состояния harness checkout (base commit `1135cbb` в локальном `git init`
  внутри `/tmp/vexbench-agent-ctl`; baseline = состояние на момент начала
  Task 4.2). Включает изменения Task 4.2 и точечное 4.3-расширение.

## Что делает патч

| Файл | Изменение |
|---|---|
| `src/evaluate/agents/codex_c1.py` (новый) | `CodexB1PrimeAgent` (registry `codex-b1p`) и `CodexC1Agent` (registry `codex-c1`). B1' = B1 + capture; C1 = B1' + `[mcp_servers.izyan]` в синтезируемом config.toml + `--snapshot-root /work --cve <id> --external-sha <commit> --audit-file /tmp/izyan-audit/tool_calls.jsonl --allow-exec`. |
| `src/evaluate/agents/opencode_c1.py` (новый, Task 4.4-ext; B1' добавлен Task 4.4-arms) | `OpenCodeB1PrimeAgent` (registry `opencode-b1p`) и `OpenCodeC1Agent` (registry `opencode-c1`), общий код — `_run_attempt`/`_synthesize_config`/`_extend_config` hook. `opencode-b1p` = контрольная рука: opencode + промпт `vuln_assess`, образ `vex-bench-<lang>-opencode-gw` (корпоративный CA), synthesized `opencode-config.b1p.json` **без** `mcp` — отличие от C1 ровно в tools-блоке. `opencode-c1`: per-attempt синтез `opencode.json` с `mcp.izyan` (`--snapshot-root /work --cve <id> --audit-file /tmp/izyan-audit/tool_calls.jsonl`, `environment.PATH` проброшен — login-shell `sh -lc` сбрасывает PATH и теряет `/usr/local/go/bin`) + provider-блок по модели (`antigravity` → `host.docker.internal:8045`, `custom-openai` → `<corporate-provider-host>`). Образ `vex-bench-<lang>-opencode-c1:latest`. Native tools не урезаны; session export и stdout/stderr — как у `opencode`, плюс `artifacts/izyan-audit/` (у b1p путь тоже пробуется — отсутствие само по себе диагностика). Модели: `gemini-3.8-flash-high`, `qwen3.6-35b`, `qwen3.8-27b` (config key = полный model id со слэшем, e.g. `custom-openai/Qwen/Qwen3.6-35B-A3B`). |
| `src/evaluate/agents/base.py` | `run_in_container(..., io_log_dir=)` — полный stdout/stderr пишутся в `logs/` до удаления контейнера на success/non-zero/timeout; `_copy_container_artifacts` дополнительно пишет `artifacts/export-report.json` (rc/stderr/exported на каждый `docker cp`) — export failure наблюдаема, не silent (Task 4.3). Поведение при `io_log_dir=None` неизменно (codex/opencode/claude не тронуты). **Task 4.4-fix:** timeout теперь исполняется watchdog-таймером, который `docker kill`-ит контейнер (а при необходимости и клиент), — `subprocess.run(..., timeout=)` при объёмном stdout `docker start -a` не завершался (контейнер держал pipe → прогон висел часами, `--timeout` не действовал). Эффективный timeout и срабатывание watchdog логируются (`run_in_container: ... timeout=Ns` / `watchdog firing`), `docker kill` ограничен 60s. `opencode`-профили имеют внутренний `timeout Ns opencode run` и не были затронуты. |
| `src/evaluate/agents/opencode.py` | `_copy_debug_artifacts(..., extra=)` — опциональные дополнительные export-пути (использует `opencode-c1` для `izyan-audit`); дефолтная поверхность артефактов неизменна. |
| `src/evaluate/agents/__init__.py` | Регистрация `codex-b1p`, `codex-c1`, `opencode-b1p` и `opencode-c1` в `AGENTS`. |
| `src/evaluate/prompts.py` | `vuln_assess` и `vuln_c1` грузятся из `prompts_data/` (byte-exact с `eval/vexbench-prompts/*-<hash>.txt` в репо); Task 4.4-arms добавляет `vuln_tools` (Qwen tools-arm). |
| `src/evaluate/prompts_data/` | Frozen тексты новых промптов: `vuln_assess`, `vuln_c1` и `vuln_tools`. `vuln_tools` = официальный `vuln` (byte-exact префикс) + блок `<EVIDENCE_TOOLS>` — единственная treatment-разница Qwen plain-vs-tools. |
| `docker/go.codex-c1.Dockerfile` (новый) | `FROM vex-bench-go-codex:latest` + `bin/izyan-evidence-tools` → `/usr/local/bin/`. |
| `docker/go.opencode-c1.Dockerfile` (новый) | `FROM vex-bench-go-opencode-gw:latest` (корпоративный CA для custom-openai) + тот же бинарь. |
| `docker/build-c1.sh` (новый) | Кросс-сборка бинаря из izyan checkout (GOOS=linux, GOARCH из `docker info` с нормализацией `aarch64`→`arm64`, CGO_ENABLED=0) + `docker build` обоих C1-образов + `c1-image.stamp` (izyan_ref берётся через `git describe --dirty`). |

## Чего патч НЕ делает

- `codex`, `claude` адаптеры, `result_parser.py`, `run.py`,
  `metrics.py`, `parse.py` — семантически неизменны; `opencode` получает
  лишь additive `extra=` kwarg в `_copy_debug_artifacts` (дефолт пуст),
  поведение профиля `opencode` не меняется.
- Нет case-specific hints; промпты C1/B1' — единственное различие output
  protocol, и они общие для обеих сторон сравнения.

## Воспроизведение

```bash
# 1. Получить harness baseline (исходный checkout Task 3/4).
cd /tmp/vexbench-agent-ctl        # либо свежая копия того же состояния

# 2. Применить патч.
git apply <repo>/eval/c1/harness/vexbench-agent-ctl-c1.patch
#    (или: patch -p1 < .../vexbench-agent-ctl-c1.patch)

# 3. Собрать C1-образ (кросс-компилирует бинарь из izyan worktree).
docker/build-c1.sh /path/to/izyan-checkout   # оба C1-образа; stamp: izyan_ref=<describe --dirty>

# 4. Запуск C1-профиля — параметры восстановлены из launch provenance B1
#    (сессия 2026-10-06: --timeout 900 --repeats 3 --parallel 1):
vex-bench evaluate run --agent codex-c1 --prompt vuln_c1 \
    --model gpt-6.1-sol --benchmark vex_bench --repeats 3 \
    --timeout 900 --parallel 1 --output-dir results-task4-c1

#    Контрольный B1' (тот же reporting-протокол, БЕЗ izyan tools):
vex-bench evaluate run --agent codex-b1p --prompt vuln_assess \
    --model gpt-6.1-sol --benchmark vex_bench --repeats 3 \
    --timeout 900 --parallel 1 --output-dir results-task4-b1p

# 5. opencode-c1 (Task 4.4-ext): тот же промпт vuln_c1; модели
#    gemini-3.8-flash-high (antigravity@host.docker.internal:8045),
#    qwen3.6-35b / qwen3.8-27b (custom-openai):
vex-bench evaluate run --agent opencode-c1 --prompt vuln_c1 \
    --model qwen3.6-35b --benchmark vex_bench --repeats 1 \
    --timeout 900 --parallel 1 --output-dir results-task4-opencode-c1

# 6. opencode-b1p (контрольная рука Qwen-сравнения): тот же opencode,
#    промпт vuln_assess, БЕЗ mcp.izyan; единственная переменная — tools:
vex-bench evaluate run --agent opencode-b1p --prompt vuln_assess \
    --model qwen3.6-35b --benchmark vex_bench --repeats 1 \
    --timeout 900 --parallel 1 --output-dir results-task4-opencode-b1p
```

## Проверка профиля (выполнено 2026-10-08, Codex 0.131.0)

Внутри `vex-bench-go-codex-c1:latest`:
- `codex mcp list` → `izyan ... enabled`;
- `codex exec` реально поднимает MCP-сервер и вызывает tool: stdout-NDJSON
  содержит `item.completed` с `item.type="mcp_tool_call"`,
  `server="izyan"`; rollout JSONL — `function_call` с
  `namespace="mcp__izyan__"` и `mcp_tool_call_end` с результатом;
- `tools/call get_product_snapshot` → валидный `Observation`
  (`tool_status=OK`, `completeness=COMPLETE`, `evidence_refs` с `sha256:`);
- `--audit-file` пишет JSONL-запись вызова (экспортируется в
  `artifacts/izyan-audit/tool_calls.jsonl`); бинарь сам создаёт каталог.

## Проверка opencode-c1 (выполнено 2026-10-08, opencode 1.15.5)

Внутри `vex-bench-go-opencode-c1:latest`:
- `opencode mcp list` → `izyan connected` (stdio, synthesized config);
- реальный `opencode run` вызывает tools; `artifacts/izyan-audit/
  tool_calls.jsonl` содержит записи `get_vulnerability`,
  `get_dependency_graph`, `get_module_version`, `find_callers`,
  `find_may_callers`, `find_symbol`, `module_usage`, `find_references`,
  `get_fix_diff`, `get_product_snapshot` — все `tool_status=OK`;
- ⚠ `mcp.izyan.environment.PATH` обязателен: run pipeline opencode
  выполняет скрипт через `sh -lc`, login-shell перезаписывает PATH
  через `/etc/profile` и роняет `/usr/local/go/bin`/`/go/bin` — без
  явного PATH `get_product_snapshot` и go-dependent tools возвращают
  `tool_status=ERROR` ("go: executable file not found in $PATH");
- antigravity (`@ai-sdk/anthropic`) требует host-side proxy на
  `host.docker.internal:8045` (Antigravity Manager); если прокси не
  поднят, opencode ретраит `ConnectionRefused` до timeout — это
  инфраструктурный prereq, не дефект профиля.

## Состав артефактов попытки (run_dir)

```
<run_dir>/
  result.jsonl                 # сырой NDJSON Codex (как у B1);
                               # opencode-c1: result.json = session export
  error.txt                    # при RuntimeError (как у B1)
  artifacts/
    codex-config.c1.toml       # эффективный config с [mcp_servers.izyan] (C1)
    opencode-config.c1.json    # эффективный config с mcp.izyan (opencode-c1)
    opencode-config.b1p.json   # тот же config БЕЗ mcp (opencode-b1p)
    codex-sessions/            # rollout-*.jsonl incl. mcp__izyan__ events
    codex-log/                 # codex log (если есть)
    opencode-export.json, opencode-{stdout.txt,stderr.log},
    session-{list.json,id}, opencode-log/   # opencode pipeline artifacts
    izyan-audit/tool_calls.jsonl  # MCP audit sink (C1; у b1p отсутствует — это и доказывает «no tools»)
    logs/{stdout,stderr}.log   # ПОЛНЫЙ capture (codex-профили)
  agent_assessment.json        # пишет контроллер eval/c1 (вне harness)
  status.json                  # пишет контроллер eval/c1 (вне harness)
```

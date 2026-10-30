# First-layer VEX parity — Implementation Plan

**Источник:** delegated `architect` artifact `agent://VexPipelineGapAnalysis` (2026-10-24), сохранён дословно.  
**Статус:** план подготовлен; код не изменён, живые вызовы не выполнены.  
**Цель:** восстановить качество первого LLM-слоя, отдельно установив, какое изменение prompt, входов или tools ухудшает исследование.

**Architecture:** точный plain-контроль и последовательные ablation-плечи на одном кейсе. Сначала оценивается **исходный ответ исследователя**, независимо от verifier. Authoritative-ядро пока не меняется.

**Tech stack:** Python, существующие OpenCode/Docker adapters и controller `eval/c1/runner.py`.

**Spec:** утверждённое требование в этой беседе; границы authority — `docs/dev/roadmaps/2026-10-20-target-architecture-and-roadmap.md`.

## Global Constraints

- Первый эксперимент — **только Kubernetes `e196d24`, CVE-2023-44487**, не полный benchmark.
- Модель: **Qwen3.6-35B-A3B**, один endpoint и одинаковые параметры во всех плечах.
- **3 заранее назначенных повтора**, timeout **1800 s**, один worker.
- Одинаковые snapshot, image digest, native tools, permissions и доступ к источникам. Нельзя молча расширять shell/network permissions ради результата.
- GT, правильный ответ, подсказки про gRPC и прошлые outputs модели не передавать.
- Все attempts сохранять. Никаких selective retries, перезаписи или выбора лучшего ответа.
- Не менять `internal/evaluator`, negative verification и правила автоматического закрытия.
- Результат одного кейса — диагностика, **не доказательство общей parity**.
- Исполнители готовят изменения без промежуточных проверок; основной исполнитель выполняет согласованный набор проверок после интеграции.

## Review Focus

1. **Равенство полного запроса**, а не только frozen-префикса.
2. Advisory — данные для исследования, а не автоматически исчерпывающая граница CVE.
3. Нельзя смешивать prompt-эффект с заменой agent runtime или permissions.
4. Нельзя считать ошибку parser, timeout или provider failure безопасным ответом.
5. Нельзя выдавать `REVIEW_REQUIRED` за сохранённое качество обнаружения.

### Task 1: Зафиксировать контроль и ablation-плечи

**Depends on:** None

**Files:**
- Create: `eval/first_layer_ablation/__init__.py`
- Create: `eval/first_layer_ablation/protocol.py`
- Test: `eval/first_layer_ablation/protocol_test.py`
- Read-only sources:
  - `eval/vexbench-prompts/official-vuln-c0a5c8458b77.txt`
  - `eval/agent7/prompts/r0-v1.txt`
  - `eval/agent7/advisories/k8s-44487.json`

**Interfaces:**
- Produces: `build_arms(cve_id, advisory_text) -> dict[str, str]`, возвращающий **полные rendered prompts**.
- Produces: manifest с hashes prompts, snapshot, runtime/config и расписанием attempts.

Плечи:

| Плечо | Состав |
|---|---|
| **A** | Точный исходный VEX prompt; только подстановка CVE |
| **B** | A + frozen advisory как данные |
| **C** | B + ограничение исследования advisory entries |
| **D** | C + расширенный assessment |
| **E** | D + описание и подключение Izyan MCP tools |

**Важно:** для C брать только семантические binding rules. В исходном блоке есть также инструкция про восемь assessment-секций — её нельзя переносить в C, иначе одновременно изменятся два фактора.

- [ ] Проверить frozen template hash `c0a5c8458b77015d57b82eefca563d01c870ea027562381715c8ab9d70ffabda` по существующей convention `eval/task5/protocol.py`.
- [ ] Добавить assertions: A не содержит `USE_BASED_VERDICT`, assessment, binding rules или tool-инструкций.
- [ ] Добавить assertions: каждая соседняя пара отличается только заявленным treatment.
- [ ] Фиксировать полный prompt каждого attempt, включая system messages.
- [ ] Проверять отсутствие GT и case-specific подсказок вне штатного CVE/advisory.

**Acceptance:** контроль A действительно воспроизводит исходную постановку; все treatment-дельты проверяемы.

### Task 2: Запускать плечи через один существующий agent runtime

**Depends on:** Task 1

**Files:**
- Create: `eval/first_layer_ablation/runner.py`
- Create: `eval/vexbench_first_layer_ablation.py`
- Test: `eval/first_layer_ablation/runner_test.py`

**Interfaces:**
- Consumes: frozen manifest Task 1.
- Reuses:
  - `eval.c1.runner.run_attempt`
  - `eval.c1.runner.write_controller_artifacts`
  - существующие harness adapters `opencode-c1-nomcp` (A–D) и
    `opencode-c1` (E) — один C1 image/pipeline, различие только в `mcp`.

- [ ] Использовать **один image digest** во всех плечах; доступность MCP менять конфигурацией, а не заменой окружения.
- [ ] До запуска сравнить effective configs: A–D одинаковы; E отличается только MCP treatment. Равенство выводится из adapter-generated фактов (image suffix/tag, pipeline id, canonical model binding, resolved credential/config paths, exported artifacts, config hash без `mcp`), а не только из manifest-деклараций.
- [ ] Проверять provider/model, snapshot identity, native permissions и лимиты.
- [ ] Сохранять raw export, final answer, native tool calls, MCP observations, usage и ошибки.
- [ ] Отказывать при существующем attempt directory; не допускать cache-admission.
- [ ] Передавать credentials через секретный runtime-канал, без записи ключей в manifest/transcript. `VEXBENCH_HOST_ENV_FILE`/`VEXBENCH_HOST_CONFIG` должны указывать на те же файлы, которые валидировал preflight (`--secret-env`/`--secret-config`). `opencode.env` — инфраструктурная предпосылка, а не результат модели.
- [ ] Не продолжать с другим provider/model/image при недоступности заданного.

**Acceptance:** различия между плечами объясняются treatment, а не скрытой заменой runtime. Infrastructure failures явно отделены от ответов модели.

### Task 3: Отдельно оценивать исследователя и формализацию

**Depends on:** Task 1

**Files:**
- Create: `eval/first_layer_ablation/report.py`
- Test: `eval/first_layer_ablation/report_test.py`
- Modify: `eval/README.md`

**Interfaces:**
- Consumes: сохранённые attempts Task 2.
- Produces: `comparison.json`, `comparison.md`.

- [ ] Считать отдельно `vulnerable`, опасный negative, `uncertain`, parse failure, timeout и provider failure.
- [ ] Сохранять official parser result и отдельную full-JSON audit projection; не подменять одно другим.
- [ ] Для каждого ответа приводить ссылки на decisive tool observations и source citations.
- [ ] Различать: модель не исследовала компонент; исследовала, но сделала неверный вывод; правильный ответ потерял parser.
- [ ] Не использовать downstream verifier для исправления оценки первого слоя.
- [ ] В документации явно обозначить эксперимент как single-case diagnostic, без заявления о достигнутой parity.

**Acceptance:** отчёт показывает, на каком treatment меняются **исследование и исходная классификация**, а не только конечный policy status.

### Task 4: Выполнить один контролируемый живой эксперимент

**Depends on:** Tasks 1–3

**Files:**
- New retained artifacts: `bench/llm-first-ablation/<experiment-id>/`
- Production code: intentionally unchanged.

- [ ] Основной исполнитель один раз запускает:
  ```bash
  python -m unittest \
    eval.first_layer_ablation.protocol_test \
    eval.first_layer_ablation.runner_test \
    eval.first_layer_ablation.report_test
  ```
- [ ] Выполняет preflight и фиксирует manifest **до первого ответа модели**.
- [ ] Запускает A–E × 3 повтора по заранее записанному порядку, последовательно.
- [ ] Публикует все 15 исходов, включая failures.
- [ ] Указывает первую наблюдаемую потерю качества и её evidence; если результаты неоднозначны — так и пишет, без заявления о доказанной единственной причине.

**Acceptance:** получен свежий single-case результат. Если контроль A тоже ошибается, сначала разбираются runtime/model drift и вариативность; исторический TP не считается гарантией.

## Dependency / Execution Order

`Task 1 → Tasks 2 и 3 → Task 4`.
Task 4a (shared C1 runtime) — обязательная предпосылка Task 4; выполняется
после Tasks 1–3.

**Решение по production-исправлению принимается по результату эксперимента.** Сейчас нельзя обоснованно выбрать между удалением binding rules, упрощением формата, изменением подачи advisory и исправлением tool interface.

## Runtime decision A (2026-10-24)

Источник: `agent://FirstLayerRuntimeDecision` (option A). Все плечи A–E
используют один legacy C1 runtime: образ `vex-bench-go-opencode-c1:latest`,
один immutable content id, один launch pipeline (`_run_opencode_and_export`,
writable `/work`, `--dangerously-skip-permissions`, `--env-file`). A–D идут
профилем `opencode-c1-nomcp` (без ключа `mcp`), E — `opencode-c1` (ровно
`mcp.izyan`). Agent profile name — метаданные; pipeline и image совпадают.
E6 image/sandbox для этого эксперимента не используется и глобально не
ослабляется. Это **legacy benchmark permissions** (writable workspace,
network, `--dangerously-skip-permissions`), а не E6-safe runtime; называть
его E6-safe нельзя. Любое иное различие permissions/network/source access —
стоп и архитектурный review, а не silent allowance.

Harness-изменение: `eval/c1/harness/vexbench-agent-ctl-c1-runtime.patch`
(baseline `80cddea`; внешний checkout не коммитится). Секретные пути
`VEXBENCH_HOST_ENV_FILE`/`VEXBENCH_HOST_CONFIG` configurable и
bind-ятся контроллером per attempt; preflight проверяет их совпадение с
`--secret-env`/`--secret-config`. Model binding нормализован к каноническому
`custom-openai/Qwen/Qwen3.6-35B-A3B` (alias `qwen3.6-35b` допустим, другой
provider/model — нет). Effective-config equality выводится из
adapter-generated launch facts и config hash без `mcp`.

### Историческая сопоставимость

Прошлый plain-результат Qwen3.6 получен на другой runtime-конфигурации;
идентичность image digest не доказана, cohort был mixed-admission
(28 свежих + 2 cached smoke), provider revision/settings не раскрыты
полностью, сырые outputs отсутствуют. Поэтому A — **exact prompt control +
new matched runtime control**, а не воспроизведение истории. Исторический
plain остаётся descriptive reference; его TP и утверждение об «одном и том
же Docker image» не доказывают parity.



В исходной read-only сессии план был подготовлен без изменений кода.
Task 4a добавил runtime-предпосылку (harness profile, image pin, secret-path
binding, protocol/runner facts и тесты) без живых model/OpenCode/izyan
вызовов; Task 4 остаётся одной контролируемой живой серией.
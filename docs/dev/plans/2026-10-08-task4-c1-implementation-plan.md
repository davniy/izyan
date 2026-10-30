<!-- План реализации Task 4 (C1: Shadow Agent + Evidence Tools).
     Нормативный источник: docs/dev/specs/2026-10-08-task4-agent-evidence-tools-v2.md -->

# План реализации Task 4 — C1: Shadow Agent + Evidence Tools

## 0. Проектное решение и исходная архитектура

**Нормативный источник:** [Task 4 v2](docs/dev/specs/2026-10-08-task4-agent-evidence-tools-v2.md), прочитан целиком. Ограничения Task 3, особенно различие `FAILED` и underlying label, считаются частью протокола.

**Проектный шлюз: CONDITIONAL.** Архитектурные решения определены; реализацию адаптера можно начинать. Допуск к платному smoke и полной серии зависит от проверок версии Codex/MCP, конфигурации модели, сохранения failure-artifacts и изоляции. Неизвестный старый бюджет нельзя молча заменить значением по умолчанию.

### Что действительно уже есть

Важная поправка к первоначальной разведке: поверхность для переиспользования шире, чем только внутренние функции анализатора.

- `internal/goanalysis.Index` уже экспортирует `FindSymbol`, `FindCallers`, `FindDepCallers`, `SearchSymbol`, `ReadFunction`, `ReadSource`, `SearchSource`, `FindEntrypoints`, tracing/validation и ряд dynamic/dependency queries.
- `internal/llm/tools.go:38–390` уже содержит почти весь каталог §6: источники, зависимости, advisory/fix, govulncheck, tracing и dynamic scan. Но `Tools.Call` принимает `*domain.AnalysisCase`, изменяет usage/evidence graph и **не имеет Observation-контракта**. Это образец dispatch и аргументов, а не готовый безопасный MCP endpoint.
- `internal/eval/vexbench/` уже разделяет controller-side `Task` и stripped input, умеет находить snapshot и считать safety-aware outcomes.
- `cmd/izyan/eval.go` запускает production pipeline для регрессионных корпусов; `cmd/izyan/vexbench.go` запускает deterministic baseline. **Не использовать их `runCase`/`runVexCase` как агентный цикл C1.** Оставить действующее поведение этих команд без изменений; использовать их для финальной проверки неизменности production.
- Официальный harness уже имеет artifact-export в `run_in_container(..., artifacts_dir, artifact_paths)`: `src/evaluate/agents/base.py:26–117`. Codex adapter его пока не подключает.

### Выбранная граница компонентов

```text
Host / control plane
  task JSONL + GT + frozen B1
       │
       ├── официальный run / parse / metrics
       └── C1 controller: manifest, assessment validation, audit, comparison
                         │ только разрешённые входы
                         ▼
Disposable Docker container / attempt
  pinned snapshot без .git
  Codex с исходными coding tools
  + локальный MCP stdio процесс Izyan
      → существующие goanalysis / affected / vulnerability / fix
      → Observation, но не Verdict/NegativeVerification
```

**Новый код — адаптер и экспериментальный control plane, не второй анализатор и не новый production workflow.**

---

## 1. Ключевые архитектурные решения

### 1.1. Транспорт: локальный MCP поверх stdio

| Вариант | Оценка |
|---|---|
| CLI bridge через shell-вызовы | Прост в запуске, но агент получает команды, а не полноценный typed tool catalog; сложнее единообразно сохранить аргументы, статусы и schema. Меняет исследуемую способность. |
| Собственный JSON-RPC bridge | Потребует собственного client integration и протокола вместо готового расширения Codex. Не даёт преимуществ для одной попытки в одном контейнере. |
| MCP по HTTP / host-side server | Добавляет порт, authentication и дополнительную доверительную границу. Host-side server опасен доступом к GT и другим snapshots. |
| **MCP stdio внутри контейнера** | **Выбран.** Codex сам запускает дочерний процесс; нет host filesystem API, открытых портов и отдельного agent runner. |

**Интерфейс:** отдельный бинарник `izyan-evidence-tools`, только server-entrypoint и evidence handlers. Предлагаемые новые файлы:

- `cmd/izyan-evidence-tools/main.go`;
- `internal/evidencetools/{observation.go,scope.go,service.go,mcp.go}`;
- небольшие backend-файлы по семействам, например `source.go`, `research.go`, `dependencies.go`.

Не поставлять в sandbox полный Izyan checkout, тесты, eval-корпуса и документы. Предпочесть отдельный slim executable полному CLI `izyan`, чтобы агент не мог случайно вызвать production `analyze` и получить готовые claims/verdict.

MCP-сервер объявляет input/output schemas и только evidence capabilities. Серверные инструкции ограничиваются форматом tools и правилами `Scope/Completeness`; без CVE-specific hints и готовой exploit-модели. Для MCP использовать официальный Go SDK с зафиксированной версией, а не писать протокол вручную; это новая небольшая зависимость, которой сейчас нет в `go.mod`.

Конфигурация добавляет `[mcp_servers.izyan]` к минимальному Codex provider config. Точный supported configuration surface проверить на **замороженном Codex CLI 0.131.0**, не переносить автоматически параметры из более новой документации. Startup MCP должен быть подтверждён до анализа; не допускать тихий запуск C1 фактически без tools. Таймаут вызова tools не может незаметно расширить общий attempt budget.

Референсы: [Codex MCP](https://developers.openai.com/codex/mcp), [официальный Go SDK](https://github.com/modelcontextprotocol/go-sdk).

### 1.2. Observation: отдельный DTO, проверяемая область, консервативная полнота

Сохранить семь обязательных полей §6.1, с enum-типами вместо произвольных значений:

```text
Observation
  id
  fact
  scope
  completeness: COMPLETE | PARTIAL | UNKNOWN
  evidence_refs[]
  limitations[]
  tool_status: OK | ERROR | UNSUPPORTED
```

**Дополнение адаптера:** typed payload семейства инструмента, структурированный `scope_details`, coverage/provenance metadata и error details. Не передавать внутренний `AnalysisCase` или его JSON.

`scope` — краткое описание конкретной области. `scope_details` фиксирует:

- snapshot/content hash и область product/dependency/module;
- реально рассмотренные пакеты/файлы и исключения;
- `GOOS`, `GOARCH`, CGO, build tags, module/vendor mode, tests policy;
- subject/query и поддержанные механизмы вызова;
- depth/load/result limits, skipped packages, load/parse failures, truncation;
- coverage rule/version и ссылку на inventory, если заявлен `COMPLETE`.

Scope формирует backend/adapter **по реально выполненной проверке**, а не модель из аргументов. «Все репозитории», «весь CVE», «все runtime-конфигурации» не являются допустимым расширением локального результата.

**Механика Completeness:**

1. Каждый handler имеет явное правило полноты; default — `PARTIAL`, а при неизвестной области — `UNKNOWN`.
2. `COMPLETE` разрешён только при замкнутом перечислимом наборе, подтверждённом inventory и отсутствием ошибок/пропусков в этой области. Примеры: чтение конкретного диапазона конкретного файла; перечисление записей конкретного manifest. Это полнота данной операции, не глобальная exploitability.
3. Caller/dataflow/dynamic/entrypoint queries в первой версии преимущественно `PARTIAL`: direct product callers не покрывают dependency-internal calls, function values, все реализации интерфейсов и другие build configurations.
4. `ERROR`/`UNSUPPORTED` не получают `COMPLETE`. Пустые данные не являются успешной отрицательной проверкой, если сама проверка не состоялась.
5. Ограничения backend-а нельзя устранять prose-обещанием адаптера. Если backend теряет диагностику, либо добавить небольшой read-only диагностический facade, либо оставить `PARTIAL/UNKNOWN`.

Пример различия:

- `OK`, `call_sites=[]`, `PARTIAL`: «Не найдено прямых вызовов в загруженных product-пакетах; dependency-internal и dynamic coverage не установлены».
- `OK`, `matches=[]`, `COMPLETE`: допустимо только для явно перечисленного закрытого file set и указанного lexical predicate, с доказанной обработкой всех файлов.
- `ERROR`: «Package loading failed» — **не** «вызовов нет».

`Fact` описывает наблюдаемое: найденный site, version, guard, неопределённый origin, отсутствие совпадений в заданном наборе. Запрещены `safe=true`, `VERIFIED FALSE`, готовый `NegativeVerification`, `Verdict` и claim-сводка production-анализатора. Evidence IDs выдаёт адаптер, ссылки резолвятся в сохранённые source/advisory/tool artifacts с хешами.

### 1.3. Docker и tool server

**Сохранять официальный lifecycle:** `docker create → docker cp → docker start → artifact export → docker rm`. Не заменять его host-based агентом.

В контейнер попадают только:

- один snapshot текущей попытки без `.git`;
- минимальный provider config, при необходимости единственный read-only config bind;
- C1 tool binary и необходимые ему executables/универсальная embedded knowledge;
- разрешённая CVE/snapshot identity;
- локальные scratch/cache и журналы **текущей** попытки.

Не монтировать `/tmp/vexbench-*`, controller worktree, JSONL, `eval/`, scoring/results, соседние snapshots, `.env` хоста, Izyan case/report directories и старые sessions. Отдельные конфигурации формируются allowlist-проекцией, не копированием пользовательского HOME.

Tool server:

- работает в том же disposable container, не обращается к host Izyan service;
- имеет один `Index` на attempt и фиксированную build configuration;
- использует существующие `repository.VerifyContained`, `CheckPathReplacements`, `readgate` и `Index.Confine`;
- допускает источники только в product tree и разрешённом **container-local** module cache; доступ к stdlib не обещает, пока backend его действительно не поддерживает;
- не включает config/output/log directories в разрешённые source roots;
- запускается с очищенным process environment и whitelist для Go loader. Одного `ReplaceEnv=true` недостаточно: в текущем `source.go` `loadEnv()` существует, но `load/loadExtra/ModuleInternalReach` непосредственно собирают env через `os.Environ()`;
- не исполняет произвольные команды из tool arguments. Build/test tools, если включаются, требуют явного `--allow-exec` и работают только в sandbox. Нативные coding tools Codex не урезаются относительно выбранного контроля;
- делает публичный advisory/fix research через существующие HTTP backends. Tool HTTP client не должен принимать `file:` или перенаправлять patch-fetch к локальному GT/result service; controller не публикует результаты через доступный агенту HTTP endpoint.

Host snapshot остаётся неизменным. Входные content hashes фиксируются до серии; tool methods не меняют source. Если coding execution меняет анализируемые исходники, это фиксируется как нарушение snapshot protocol с сохранением raw attempt, а не исправляется незаметно или selective retry. Одинаковую политику применять в B1' и C1.

### 1.4. AgentAssessment и production immutability

**Выбор:** отдельная экспериментальная модель на control plane, а не новые поля production `AnalysisCase` и не передача shadow claims в `evaluator.VerdictEvaluator`.

Предлагаемые новые Python-модули `eval/c1/assessment.py` и `eval/c1/protocol.py` используют уже имеющийся в official harness Pydantic. `AgentAssessment` — источник истины только для **экспериментального артефакта**, не для production.

Разделить:

- **модельное содержимое:** root causes, mandatory conditions, `TRUE/FALSE/UNKNOWN` claims, citations, limitations, unresolved questions, конкретный counterexample review, estimate, category/reasoning;
- **controller metadata:** task/attempt identity, snapshot hash, versions, model/revision, prompt/harness/adapter versions, factual tool executions, tokens/calls/cost/wall.

Агент не задаёт себе доверенные версии, затраты или список якобы выполненных tools. Controller проставляет их из manifest/trace. Неизвестные revision/cost/finish flags сохраняются как unavailable, не выдумываются.

**Финальный ответ:** один JSON с существующими top-level `category` и `reasoning` плюс structured assessment content. Официальный parser игнорирует extra fields (`result_parser.py:43–51`). Controller сохраняет полный raw JSON, проверяет schema и собирает отдельный `agent_assessment.json`. Никакого дополнительного LLM-вызова для post-hoc «достраивания» отсутствующих root causes/claims.

Schema validation и проверка evidence references — проверка корректности артефакта, **не Verification Kernel**. Не переименовывать небезопасный raw negative в `INCONCLUSIVE` только потому, что reasoning слабое: сохранять исходную оценку и отражать её в соответствующем scoring/audit.

### 1.5. B1': условия обязательности и выбор для этого плана

Само добавление MCP и деклараций evidence tools не делает B1' автоматически обязательным: это предусмотренная treatment-разница. Но B1' обязателен, если меняется существенная часть harness/interface, общий output protocol, общий security prompt, native tool permissions, модельный runtime или бюджет, которые нельзя восстановить для frozen B1.

**В выбранном плане B1' следует предусмотреть как основной контроль**, по двум причинам:

1. Полный structured assessment и counterexample review требуют общего reporting/output block, которого не было у frozen B1. Добавить его **одинаково B1' и C1**, не давать только C1 более сильную общую security-инструкцию.
2. Требуется полноценное failure capture. Сейчас timeout/non-zero output попадает лишь 4000-символьным tail в `error.txt` (`base.py:119–138`). Это не удовлетворяет §8.2.

Кроме того, freeze-checksums B1 содержит `provenance=null`; точный timeout там не сохранён. Исследованные события содержат успешную длительную попытку более 3600 секунд, поэтому **600 секунд из CLI defaults нельзя объявить бюджетом B1**. Сначала попытаться восстановить effective launch configuration из исходных execution records; если она недоступна — зафиксировать несопоставимость, не угадывать.

**Что делает B1':** те же 30 задач × 3 повтора, та же модель/revision/endpoint, snapshots, common reporting block, capture lifecycle, network/exec permissions и фиксированный бюджет, что у C1, **но без Izyan tool catalog/server/доступного CLI bridge**. Native Codex tools остаются. Не создавать «контроль без MCP», в котором Izyan tools всё равно вызываются через shell из того же image.

Основное сравнение тогда **B1' ↔ C1**, frozen B1 — неизменяемый исторический anchor и отдельная таблица drift. Если удастся сохранить исходный интерфейс и разрешённую prompt delta только в tool declarations, восстановить все budgets и получить полное capture без влияния на анализ, допустимо обоснованно оставить B1 основным контролем. Решение принимается **до freeze**, не после просмотра результатов.

---

## 2. Подзадача 4.1 — Evidence Tools adapter

### Цель

Подключить существующие анализаторы к typed Observation API с честной областью покрытия. Не запускать production pipeline для подготовки ответов.

### Артефакты и переиспользование

| Артефакт | Статус / назначение |
|---|---|
| `internal/llm/tools.go` | Существующий: использовать catalog, argument shapes и dispatch pattern; `Tools.Call` напрямую не вызывать из C1. Production behavior оставить прежним. |
| `internal/goanalysis/{source,provenance,coverage,dispatch,funcvalues,config,govulncheck}.go` | Существующие фактические backends. |
| `internal/affected/golist.go`, `internal/vulnerability/source.go`, `internal/fix/{fix,patch}.go`, `internal/repository/` | Существующие dependencies, public research и snapshot identity. |
| `internal/evidencetools/` и `cmd/izyan-evidence-tools/main.go` | Новые DTO, service, MCP registration и startup wiring. |
| `internal/goanalysis/toolscope.go`, `toolscope_test.go` | Новые **только при необходимости**: read-only facts/diagnostics facade к уже существующим механизмам. Без нового semantic analyzer. |
| `internal/evidencetools/*_test.go` | Новые contract/scope/isolation tests, с существующими `testdata/*prod`. |
| `go.mod`, `go.sum` | Добавление pinned MCP SDK; без случайного обновления остальных зависимостей. |

### Интерфейсы

Локальный `SessionContext`: CVE, canonical snapshot root/hash, external SHA, build context, execution permission и attempt-local audit sink. **Не принимает `Task`, `AnalysisCase`, GT или production claims.**

MCP handlers используют typed inputs/outputs. Нижний service выполняет вызов под `context.Context`, возвращает Observation + typed data и пишет реальное исполнение/исходный ответ в audit sink. Один Index на попытку, последовательные backend queries; не делить `CachingTool`/`CachingRunner` между попытками или build contexts — они запоминают первый вызов, а не произвольный keyed cache.

Минимальный mapping:

- research → `vulnerability.OSVSource.Get`, `fix.Resolver.Resolve`, `fix.HTTPProvider.Fetch`;
- snapshot → `repository.Service.Snapshot` с `ExternalCommitSHA`, без git research;
- modules → `affected.GoTool.ListModules`, `DecodeModules`; показывать vendor fallback и replace/effective version;
- govulncheck → `Runner`, `Parse`, actual pattern и DB coverage;
- source/calls → экспортированные Index methods;
- dataflow/guards → `TraceArgument`/`TraceAllArguments`, `FindValidations`;
- dynamic → `ScanDynamic`, `InterfaceDispatchSites`, `GatedRefs`, `FindDepCallers`, `DepInvocationState`, `ModuleUsage`/`ModuleInternalReach`; для function-value facts — минимальный facade к существующим `funcvalues.go` и `callersOf`.

**Важные ограничения текущего кода:** `FindCallers` ищет статически именованные вызовы product roots; более широкий `callersOf` отдельно добавляет interface/function-value sites. Нельзя обещать dynamic coverage, просто обернув `FindCallers`. `SearchSource` реально обходит product syntax, ограничен 64 matches и молча пропускает некоторые read errors. `FindEntrypoints` распознаёт не все transports. `ModuleInternalReach` создаёт свой loader без явного `BuildFlags`; при tags такая проверка должна иметь честное ограничение или `UNSUPPORTED`, а не называться полной.

При отсутствии способности — настоящий `UNSUPPORTED`. Частичный полезный результат — `OK/PARTIAL`; не объявлять всю попытку `FAILED` из-за одного recoverable tool miss. Отказ сервера/транспорта, из-за которого цикл не завершился, — attempt-level failure.

### Критерий готовности

Весь минимальный каталог §6 объявлен и выдаёт факты либо документированное `UNSUPPORTED`; все ответы имеют scope/status/completeness/evidence. Есть реальная typed MCP регистрация, unit contract coverage и negative isolation test. Ни один handler не вызывает `Verifier.VerifyFalse`, condition evaluator или готовый production verdict path.

---

## 3. Подзадача 4.2 — Shadow loop и AgentAssessment

### Цель

Дать **существующему Codex loop** доступ к новым tools и сохранить его самостоятельное исследование. Не заменять его `internal/llm.ClaimEvaluator` с bounded 8-step loop и не заставлять следовать state machine Izyan.

### Артефакты

- **Новые:** `eval/c1/assessment.py`, общий assessment schema/reporting block в `eval/vexbench-prompts/`, C1 tool-contract declaration block.
- **Новые/тонкое расширение official checkout:** Codex evidence adapter/profile, registry entry в `src/evaluate/agents/__init__.py`, соединение с существующим `run_in_container` и artifact paths.
- **Существующие без изменения semantics:** Codex native toolset, model invocation и category precedence; `internal/evaluator/`, production state machine, case/report persistence и `cmd/izyan/eval.go`.

Не делать runtime зависимым от единственного `/tmp` checkout: небольшой harness diff/overlay и hashes должны быть сохранены как воспроизводимый экспериментальный артефакт. Это не новый самописный agent harness.

### Интерфейсы и поведение

Codex сам исследует advisory/patch, формирует hypotheses, выбирает queries, интерпретирует Observation и перед safe estimate выполняет counterexample pass. Common B1'/C1 assessment block требует записать **что конкретно проверено и что осталось неизвестно**, не просто `review_done=true`.

Estimate и категория согласуются по заранее установленному mapping: `vulnerable → EXPLOITABLE`, `uncertain → INCONCLUSIVE`, safe categories → один из safe estimates с обоснованием. Controller не исправляет оценку модели на желаемую.

В `status.json` разделить execution outcome, official parse status, assessment schema status и parser-audit status. Если официальный parser принял категорию, но дополнительный assessment malformed, это отдельный artifact defect: нельзя незаметно убрать принятую safe-категорию из official/safety аудита. Provider refusal, timeout, transport failure и невалидный terminal answer — failure с причиной; не `uncertain`.

`AgentAssessment` хранится только в `results/task4-c1/<experiment_id>/<task-id>/run_NNN/agent_assessment.json`. Production store и workflow не передаются этому пути исполнения. Для failed attempt не изготовлять фиктивный assessment: сохранять raw/partial artifacts и failure status.

### Критерий готовности

Агент действительно вызывает MCP tools и продолжает использовать native tools; выдаёт самостоятельную модель и полный assessment. Evidence refs проверяемы. Нет второго post-hoc model call, authoritative state mutation или скрытой подачи conclusions текущего Izyan.

---

## 4. Подзадача 4.3 — Protocol, isolation и smoke

### Цель

Проверить работоспособность полного контура и честность сравнения до 90 attempts.

### Артефакты

- **Новые:** `eval/c1/protocol.py`, `eval/c1/runner.py`, entrypoint `eval/vexbench_c1.py`; experiment manifest и private redacted provider profiles.
- **Переиспользуемые:** official `ExperimentConfig`, run/parse/metrics, `run_in_container` artifact export; существующие snapshot/preflight/hash contracts.
- **Точечное symmetric extension:** full stdout/stderr capture и export на success/timeout/non-zero до удаления контейнера. Текущие 4000-char tails и best-effort `docker cp(check=False)` недостаточны: missing required artifacts должны быть явно зафиксированы.

Официальный `result_parser.py` не менять под C1.

### Шаги

1. Сверить frozen B1: 30 ID/CVE/SHA, prompt `c0a5c8458b77`, модель/config, image content identity, Codex/Go versions, timeout/budget, scoring files и hashes. Не пересобирать mutable `latest` и не считать его прежним image.
2. Определить и записать primary comparator B1 либо B1'. Для выбранного общего assessment/capture protocol подготовить B1' без evidence tools.
3. Зафиксировать container input allowlist, native tools, network/exec policy и источник snapshot identity. Task IDs/labels остаются controller metadata; prompt содержит CVE, а не весь task record.
4. Выполнить offline/synthetic integration checks: MCP initialization/catalog, full capture, forced tool error, timeout, refusal, invalid output, export failure, negative isolation. Это не benchmark attempts.
5. Запустить **три benchmark smoke-кейса**, выбранные controller по трём классам: exploitable, non-reachable, configuration. Агенту не передавать класс/ожидаемый ответ. Сохранить все smoke outputs и изменения prompt/tool adapter отдельно.
6. После smoke заморозить final manifest: Izyan/adapter/harness commits и diff hashes, SDK/tool binaries, tool schemas, prompts, image/architecture/toolchain, model/revision/effort, limits, snapshot hashes, parser/scorer versions, attempt policy.

**Первый smoke:** synthetic MCP/container probe сразу после вертикального среза 4.1 + минимальной интеграции 4.2. Не ждать готовности всего отчётного слоя, чтобы обнаружить несовместимость pinned Codex. Трёхкейсовый smoke — после готовности assessment и failure capture; он не входит в final 90.

### Критерий готовности

Три smoke attempts сохранены в отдельном namespace; подтверждены invocation, assessment, evidence export, failure classification и недоступность GT/neighbor outputs **как через coding tools, так и через MCP**. Нет C1-only scorer change. Comparator и protocol зафиксированы до полной серии.

---

## 5. Подзадача 4.4 — Frozen full run

### Цель

Получить полный неизменяемый C1 cohort **30 × 3 = 90 initial attempts**. При B1' — дополнительно его отдельные 90 attempts; не считать контроль частью 90 C1.

### Артефакты и интерфейсы

`eval/c1/runner.py` оркестрирует official harness, не реализует новый model loop. Attempt key: `(experiment_id, task_id, repeat_id)`.

```text
results/task4-c1/<experiment_id>/
  manifest.json
  <task-id>/run_001/
    agent_assessment.json       # только при валидном assessment
    raw_agent_output.txt
    result.jsonl               # оригинальная Codex trajectory
    tool_calls.jsonl
    observations.jsonl
    status.json
    logs/                      # stdout/stderr/provider flags/export evidence
  ...
  scoring/
```

Original official artifacts сохранять рядом; normalized files не заменяют исходники. Доверенные token/call/wall counters извлекать из trace/controller, tool process executions — через существующий `toolaudit.Recorder`, без `AnalysisCase` store.

### Правила выполнения

- Новый контейнер, session и attempt-local caches на каждую попытку.
- Один неизменный input snapshot; не смешивать smoke, старые ответы или context другой попытки.
- Новая output directory на experiment и запрет overwrite/admission в существующий attempt. В official `run.py` есть `[CACHE]` и `[RE-RUN]` unparseable result; **не использовать повторный запуск той же output directory как resume**.
- Все failures остаются исходами. Не делать selective retry, best-of и label recovery вместо initial outcome.
- При инфраструктурном дефекте сохранять весь cohort и запускать **новый полный cohort** под новым ID после исправления. Серию с дефектом не перезаписывать.
- Runtime, resources и model budgets фиксировать одинаково B1'/C1. Увеличивать timeout или менять tools после отдельных тяжёлых кейсов запрещено.
- Provider-side cache, если он управляется сервисом и не отключается, отличать от запрещённого смешивания outputs/sessions; фиксировать cached tokens и ограничения сопоставимости.

### Критерий готовности

Manifest содержит ровно 90 ожидаемых C1 attempt keys, на каждый есть immutable terminal status и доступные raw/failure artifacts; missing outputs объяснены конкретным failure. Все три повторения имеют один task set. Нет выборочных перезапусков или повторного использования smoke. При B1' есть такой же полный контрольный набор.

---

## 6. Подзадача 4.5 — Scoring и инструментальный аудит

### Цель

Проверить H1/H2/H3 и отличить ошибки агента, tools, охвата и инфраструктуры; не доказать заранее пользу инструментов.

### Артефакты и переиспользование

- **Новые:** `eval/c1/parser_audit.py`, `eval/c1/report.py` и соответствующие tests.
- **Существующие:** official `parse.py`/`metrics.py`; `eval/vexbench_plain_report.py` для safety outcome, per-repeat aggregation и coverage-aware telemetry. Переиспользовать функции, а не создавать вторую несовместимую трактовку `uncertain/failed`.
- **Итоговые файлы §11:** `official_metrics.json`, `safety_metrics.json`, `parser_audit_metrics.json`, `case_comparison.jsonl`, `disagreements.md`, `tool_use_summary.md`.
- **Новый итоговый отчёт:** `eval/baselines/vexbench/shadow-agent-evidence-tools-c1.md`. Обновить `eval/README.md` и документацию контрактов/CLI integration; frozen A/B reports не переписывать.

### Две независимые проекции

**Primary / official-strict:** исходный terminal output, зафиксированный неизменённый официальный parser/scorer. `FAILED` не safe verdict и не abstention.

**Secondary / parser-audit:** заранее заданный string-aware JSON decoder только на final assistant text. Допустимо восстановить **полный валидный JSON object**; нельзя брать category из prompt/tool response, усечённой строки, произвольной прозы или label-only regex. Правило применяется всем категориям и одинаково frozen B1/B1'/C1. Хранить decoder version, parse disagreement и recovered full object; исходные метрики не заменять. При исправлении official parser в отдельной работе переоценивать оба frozen набора без model calls.

Refusal/timeout не превращать в valid attempt только из-за напечатанного category token. Ошибку extractor с полным завершённым JSON отличать от provider truncation. Публиковать underlying recovered labels отдельно: Task 3 показал, что parse failure способен скрывать **как positive, так и False-Safe**.

### Метрики и разбор

- False-Safe: завершённые safe negatives на exploitable GT; знаменатель **7/repeat, 21 attempts pooled**.
- Safe Clear Rate: корректные safe negatives / **23/repeat, 69 pooled**.
- Exploitable recall, INCONCLUSIVE, FAILED с failure classes, official compatibility Accuracy/F1, Reason accuracy.
- Per-repeat mean и **sample std**, raw counts по 90; не называть их 90 независимыми CVE.
- Per-case stability `3/3`, `2/3`, `1/3`, особенно для negative estimates.
- Pair `(task_id, repeat_id)`: corrections, regressions, failure/abstention transitions, появление/устранение False-Safe, улучшение основания при прежнем статусе.
- Tool invocations: число, статус/completeness, семейство, затраты, repeated useless calls, пропуски необходимых проверок.
- Decisive evidence: конкретный Observation ID, который агент процитировал в claim/estimate. Наличие вызова само по себе не доказывает пользу или причинность.

Известные risk cases §10 рассматривать **после эксперимента**: configuration/protocol gate, scope с альтернативным affected path, dependency/internal reachability, generator vs generated artifact. Не добавлять их в инструменты и prompt.

Завершить решением **KEEP / REDESIGN / DEFER** по tools и конкретными оставшимися trust gaps. Ablation, если нужна для причинного вывода, — отдельный предварительно описанный experiment, не замена основной серии. Verification Kernel здесь только предмет следующего решения, не реализация.

### Критерий готовности

Есть обе scoring-проекции, все disagreements и отрицательные регрессии, проверяемые trace citations, coverage-aware затраты и честные выводы о сравнении. Task 4 может быть завершён и при отсутствии улучшения; наличие False-Safe запрещает safety/production claims, но не оправдывает скрытие результата или подгонку tools.

---

## 7. Порядок, зависимости и параллельные работы

```text
Freeze B1 inputs + определить comparator/output protocol
                  │
           DTO / Scope contract
             ┌────┴───────────────┐
             ▼                    ▼
       4.1 backends/MCP      4.2 assessment + harness profile
             └────┬───────────────┘
                  ▼
        synthetic vertical smoke
                  ▼
      4.3 isolation/failures + 3 cases
                  ▼
            final protocol freeze
                  ▼
        B1' (если нужен) + 4.4 C1
                  ▼
               4.5 audit/report
```

После согласования DTO, output schema и artifact layout можно параллельно делать 4.1, control-plane часть 4.2 и offline scoring/tests 4.5. Harness integration получает готовый server executable после вертикального среза 4.1. Полный run не параллелен изменению implementation/prompt/scoring rules. Одновременный B1'/C1 запуск допустим только при заранее одинаковой resource policy; проще сохранить sequential execution, как наблюдалось у B1, чтобы не добавлять resource confound.

---

## 8. Риски и способы проверки

| Риск | Проверка / ограничитель |
|---|---|
| **P0: GT, PR metadata или результаты просачиваются в agent/server** | Input type без `Task/AnalysisCase`; mount/copy allowlist; slim image; synthetic host sentinels и запросы через native tools + MCP; inspect effective Docker inputs. Запрещённые файлы отсутствуют либо доступ отвергнут. |
| **P0: пустота превращается в COMPLETE/global safe** | Contract matrix, явный coverage rule и inventory; default PARTIAL; тесты failed/skipped packages, dynamic/build-tag/dependency omissions, пустых и truncated scans. |
| **P0: tools выдают скрытый authoritative conclusion** | Schema/handler audit: нет `NegativeVerification`, `Verdict`, production Claims/RootCauseModel/ExploitModel; service не принимает production case. |
| **P1: новая harness/output политика улучшает B1 сама по себе** | Общая политика B1'/C1; primary pair B1'↔C1; отдельный frozen B1 drift report. Нельзя объяснять treatment-effect одними агрегатами. |
| **P1: неизвестный бюджет frozen B1** | Восстановление launch provenance; если недоступно — новый одинаковый бюджет B1'/C1 и явное историческое положение B1. Не использовать defaults как факт. |
| **P1: scope backend шире в комментариях, чем реально в коде** | Тесты `SearchSource` 64 cap/product-only, direct-only `FindCallers`, entrypoint omissions, `ModuleInternalReach` tags; заявленный capability соответствует выполненным операциям. |
| **P1: loader наследует host/provider environment** | Clean environment процесса сервера; негативные тесты GOWORK/GOFLAGS/local replace/symlink. Не считать неиспользуемый `loadEnv()` доказательством isolation. |
| **P1: failures теряют raw trace или скрывают unsafe label** | Forced timeout/non-zero/refusal; полное capture до container removal; separate official/parser-audit/assessment statuses; exporter failures наблюдаемы. |
| **P1: sticky Index error или cache смешивает snapshots/builds** | Lazy source initialization, error как Observation, не обязательный fail всего research; per-attempt caches, фиксированный build context; unit на второй snapshot/context. |
| **P1: source изменён native execution, cached facts устарели** | Неизменный input hash, read-only tool handlers, scratch для исполнения, source-integrity check; нарушение сохраняется в protocol audit, без selective repair. |
| **P1: pinned Codex не поддерживает выбранные MCP/schema параметры** | Synthetic probe на 0.131.0; фактический catalog и MCP event types в trace; никакого тихого обновления CLI либо запуска C1 без tools. |
| **P2: нулевой False-Safe трактуется как доказанная безопасность** | Явные знаменатели и stability; только 7 exploitable cases; нет production cutover или zero-risk утверждений. |

---

## 9. Тестовый план

### 9.1. Unit и детерминированные component tests

1. **DTO/schema:** enum values, обязательные поля, empty arrays, serialization, валидные evidence refs; `OK+empty+COMPLETE`, `OK+empty+PARTIAL`, `ERROR`, `UNSUPPORTED` различаются.
2. **Completeness:** COMPLETE только при известном closed scope; пустой поиск, success exit code, отсутствие dynamic markers и `govulncheck` silence не повышают полноту. Coverage-ошибка/timeout/cap lowering покрыты тестами.
3. **Scope:** product/direct vs dep-internal; interface/function values; build-tagged sources; skipped packages; 64-match cap; trace hop/load budgets; multi-module advisory; replace/vendor versions; `./cmd/...` govulncheck fallback.
4. **Release Go:** разделять analysis toolchain, `go` directive и snapshot-local release evidence. Неизвестный release для stdlib-CVE остаётся limitation, не fixed version.
5. **Negative isolation:** traversal, sibling-prefix path, external/broken symlink, go.work/local replace, injected GOWORK/GOFLAGS; GT/result sentinel за пределами roots недоступен. Проверить все readers/loaders, не только `read_source`.
6. **Немутируемость:** handlers без production case/store; запуск shadow не меняет существующие `Claims`, `NegativeVerification`, `Verdict` и persisted production artifacts.
7. **Execution gate:** build/test отказ без `--allow-exec`; failure не кодируется empty success. Некорректные line range, regexp, symbol и argument index не приводят к panic.
8. **Assessment/protocol:** schema, category/estimate consistency, metadata stamping, evidence-reference validation, duplicate attempt rejection, запрет overwrite/cache admission.
9. **Parser audit:** braces и escaped quotes внутри reasoning, nesting, fences/prose wrappers, несколько JSON objects, partial/refused outputs. Одинаковые тестовые правила для positive и unsafe-negative labels; брать только terminal assistant output.
10. **Metrics:** FAILED отдельно от uncertain/negative, denominators, paired keys, sample std, stability; artifact-validation failure не стирает official raw accepted category.

Переиспользовать `testdata/*prod`, существующие source/provenance/coverage/dispatch tests и tests `vexbench_plain_report.py`. Не обращаться к live LLM в unit tests.

### 9.2. Synthetic container integration

Без benchmark CVE проверить MCP startup и schema negotiation, наличие native tools, forced tool error, timeout/non-zero/refusal, полное raw capture, artifact export и два канала negative isolation. Credentials не должны попадать в output/logs.

### 9.3. Smoke: 3 кейса

Один exploitable, один non-reachable, один configuration; controller selection и единичные attempts, отдельный experiment ID. При необходимости исправлять implementation между smoke итерациями, сохраняя предыдущие результаты. Критерий — работоспособность протокола и честность evidence, **не три правильных GT-ответа любой ценой**. Ни один smoke output не допускается в final cohort.

### 9.4. Финальная проверка реализации и full experiment

Главный интегратор один раз после завершения всех изменений выполняет `go test ./...` и существующий deterministic regression corpus через `cmd/izyan/eval.go`; live-корпус — при доступном продукте и установленной политике репо. До этого только targeted tests. Frozen external A не пересчитывать ради проверки C1.

После protocol freeze — C1 30×3 и при выбранном B1' ещё 30×3, затем только offline parse/scoring/audit без новых model calls. Неполная серия или потерянные обязательные artifacts не объявляются завершённым Task 4.

---

## 10. Явные границы Task 4

Не делать:

- agent-first production cutover, автоматическое закрытие alerts по `AgentAssessment`;
- изменение authoritative claims, negative verification, verdict evaluator или production state-machine;
- реализацию/выделение Verification Kernel;
- новый большой callgraph/taint/analyzer для недостающих tools — честный `UNSUPPORTED/PARTIAL`;
- переписывание существующих Go-анализаторов, evaluator-chain и eval pipeline;
- урезанный coding-agent loop вместо официального Codex;
- Java/Python analysis и новые model leaderboards;
- hardcode CVE/product/package/expected-answer rules и подсказки по известным ошибочным benchmark кейсам;
- исправление snapshots, advisory scope или production эвристик ради C1 scores;
- C1-only parser repair, label-only/prose recovery как полноценный verdict;
- selective retries, cache mixing, best-of и включение smoke в 90;
- дополнительные Gemini/Qwen full runs как обязательную зависимость;
- вывод о production safety только из `0/7`.

## 11. Итоговая приёмка и передача

Task 4 принимается при наличии полного additive-tools контура, отдельного AgentAssessment, проверенной isolation/Observation semantics, smoke вне 90, frozen C1 и при необходимости B1', двух scoring-проекций, per-case disagreements/False-Safe audit, tool-use/decisive-evidence анализа и решения KEEP/REDESIGN/DEFER. Production behavior и deterministic regression corpus не изменены из-за shadow режима.

**Контракт передачи в реализацию:** соблюдать выбранные границы и ограничения. Если обнаружится факт, меняющий данные, trust boundary, Observation semantics или сопоставимость B1/B1'/C1, остановить затронутую реализацию, зафиксировать источник и отклонение и вернуть эту часть на design review. Не компенсировать расхождение скрытым изменением harness/prompt/scoring.

**В рамках этой работы файлы не изменялись; builds, tests и benchmark/model calls не запускались.**
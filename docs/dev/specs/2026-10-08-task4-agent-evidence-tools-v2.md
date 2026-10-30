# Izyan — Task 4: Shadow Agent + Evidence Tools (C1)

**Статус:** актуализированная спецификация после перепрогонов Task 3, версия 2.  
**Назначение:** единственный рабочий документ для Task 4; заменяет ранее опубликованную в чате спецификацию «Agent + Izyan Evidence Tools — Task 4».  
**Зависимости:** замороженный baseline A; Plain Agent baseline B1 (`gpt-6.1-sol`, официальный VEX-Bench harness, 30 Go-кейсов × 3 повтора); отчёт Task 3 с изолированными перепрогонами Gemini/Qwen.

## 1. Решение по итогам Task 3

Направление **не изменилось**:

```text
B1: Plain Codex (существующие инструменты coding agent)
      ↓ сравнить на одинаковых задачах
C1: тот же Codex + Evidence Tools Izyan
```

Нужно измерить **добавочную пользу инструментов Izyan**, а не качество новой модели, нового промпта или готового Verification Kernel. Результат C1 — `AgentAssessment` для эксперимента, **не authoritative verdict**.

Повторные прогоны Task 3 добавили ограничения к методологии:

- исходный host-based Gemini B2 **скомпрометирован чтением ground truth** и не используется как основной baseline;
- изолированный Gemini B2-ISO — **exploratory retry-composite**, а не строгий first-attempt baseline;
- изолированные Qwen выявили **форматные ошибки, сбои парсера и опасные отрицательные решения в дополнительных повторах**: нулевой False-Safe одного прохода не равен прохождению safety-gate;
- основной контроль для C1 остаётся **B1/Codex**: официальный harness, Docker, три повтора.

**Вывод:** меняются правила проведения и оценки Task 4, а не его назначение.

## 2. Проверяемые гипотезы

**H1 — качество.** Typed evidence tools увеличивают долю корректно разобранных кейсов и/или уменьшают опасные отрицательные выводы при сопоставимом протоколе.

**H2 — механизм.** Улучшение можно привязать к конкретной новой информации (`Observation`), а не только к факту, что агенту выдали другой системный промпт.

**H3 — граница.** Если инструменты не помогают либо агент неверно интерпретирует их неполные ответы, это выявляется до проектирования Verification Kernel.

Нулевой False-Safe на 30 Go-кейсах — необходимый, но **недостаточный** аргумент безопасности: в корпусе всего 7 exploitable-кейсов; внешняя валидация потребуется отдельно.

## 3. Область работ

Входит:

1. Подключение существующих инструментов анализа Izyan к агенту через типизированный интерфейс.
2. Независимый агентный цикл исследования CVE, построения гипотез и вызова инструментов.
3. Отдельный, неавторитетный `AgentAssessment` с доказательствами, ограничениями и собственной оценкой.
4. Изолированный эксперимент C1 на Go-части VEX-Bench, сравнение с замороженным B1.
5. Инструментальный аудит и анализ причин улучшений/регрессий.

Не входит:

- переключение production workflow на agent-first;
- изменение authoritative `AnalysisCase.Claims`, `NegativeVerification` и `Verdict`;
- реализация или выделение Verification Kernel;
- исправления отдельных VEX-Bench CVE/репозиториев через hardcode;
- замена действующего статического анализатора;
- отдельная реализация Java/Python;
- необязательный полный повтор всех Gemini/Qwen: их новые данные уже учтены в методологии.

## 4. Ключевое правило честного сравнения

**C1 строится как B1 + новые Evidence Tools, а не как новый агент с урезанным набором возможностей.**

Для B1 и C1 сохранить:

- модель и конфигурацию `gpt-6.1-sol` (включая endpoint/revision, если доступны);
- официальный VEX-Bench harness и контейнерную изоляцию;
- те же 30 Go task ID, CVE и pinned commit snapshots;
- доступ к публичным advisory/fix через сеть;
- **имеющиеся у plain coding agent инструменты чтения, поиска и допустимого исполнения**; в C1 к ним *добавляются* Izyan tools;
- одинаковые ограничения времени, ресурсные лимиты и по возможности бюджеты модели;
- одинаковую политику сохранения ответов, парсинга, ошибок, повторов и scoring.

Различие инструкций свести к объявлению новых tools, их формату и правилам интерпретации `scope/completeness`. **Не добавлять в C1 подсказки по известным ошибочным кейсам** или более сильные общие security-подсказки, отсутствовавшие в B1, без отдельного ablation.

Если скопировать harness B1 невозможно без существенного изменения его интерфейса, зафиксировать отклонение и провести дополнительный **B1' без Izyan tools в новом harness**. Тогда основное парное сравнение — **B1' ↔ C1**, а исходный B1 остаётся историческим ориентиром.

## 5. Изоляция данных

Controller/scorer видит исходный VEX-Bench JSONL, ground truth, `ground_truth_category`, `metadata.pr_url`, результаты A/B и журналы эксперимента.

**Agent sandbox видит только:**

```text
CVE ID
checkout pinned repository snapshot (без .git)
разрешённые tools
публичные advisory/fix, найденные самим агентом
```

Запрещено передавать агенту или его инструментальному серверу в доступную область:

- benchmark task JSONL с labels/PR;
- отчёты и предсказания A/B/C других запусков;
- эталонные ответы, предыдущие agent traces или подсказки для данного кейса;
- готовые authoritative `Verdict`, `Claims`, `RootCauseModel`, `ExploitModel` текущего Izyan.

Требования к Docker:

- одноразовый контейнер на попытку; только снапшот и конфигурация, необходимые для агента;
- **не** монтировать хостовые `/tmp/vexbench-*`, eval/scoring/results и исходные JSONL;
- конфигурация провайдера — минимальная, без benchmark-секретов; токены не писать в логи;
- Izyan tools работают над **текущим изолированным snapshot**, не могут читать хостовые GT или соседние snapshots;
- выполнить отрицательный тест изоляции: запрос на чтение GT / соседнего результата должен быть отвергнут или не находить файл.

`ExternalCommitSHA`/`ContentHash` допускаются как snapshot identity. Версию release Go не угадывать по директиве `go` из `go.mod`; неизвестную версию учитывать как ограничение для stdlib-CVE.

## 6. Evidence Tools v1

Использовать существующие реализации Izyan, обёрнутые в понятный агенту API. Минимально предоставить способности (названия могут быть уточнены по коду):

| Область | Возможности |
|---|---|
| CVE/research | `get_vulnerability`, `get_advisory`, `get_fix_references`, `get_fix_diff` |
| Зависимости и сборка | `get_product_snapshot`, `get_dependency_graph`, `get_module_version`, `run_govulncheck` |
| Код и вызовы | `find_symbol`, `find_references`, `find_callers`, `find_entrypoints`, `read_function`, `read_source`, `search_source` |
| Dataflow/защита | `trace_argument`, `find_validations` |
| Динамическая достижимость | проверка function values, interface dispatch, dependency-internal calls, reflection, build-tagged references и других поддержанных источником маркеров |

Не разрабатывать под Task 4 новые большие анализаторы. Если нужной способности нет, инструмент возвращает `UNSUPPORTED`/ограничение. Не превращать внутренние форматы стейт-машины в интерфейс агента.

Выполнение сборки/тестов допускается только в sandbox и согласно существующим правилам `--allow-exec`; сетевой поиск публичных advisory разрешён, если разрешён baseline B1.

### 6.1. Контракт ответа

Минимальный семантический контракт (`Observation`, DTO допустимо реализовать адаптером):

```go
type Observation struct {
    ID           string
    Fact         string
    Scope        string
    Completeness string   // COMPLETE | PARTIAL | UNKNOWN
    EvidenceRefs []string
    Limitations  []string
    ToolStatus   string   // OK | ERROR | UNSUPPORTED
}
```

Обязательно различать:

```text
OK + empty + COMPLETE  → отсутствие в указанной замкнутой области
OK + empty + PARTIAL   → в проверенной части ничего не найдено
ERROR/UNSUPPORTED      → проверка не выполнена
```

`COMPLETE` нельзя присваивать на основании пустого поиска или успешного API-ответа; полнота требует правила, определяющего границы рассмотренных вызовов, конфигураций и динамических механизмов.

### 6.2. Никакого скрытого заключения

Инструменты сообщают проверяемые наблюдения и ограничения, а не выдают готовые `VERIFIED FALSE`/safe verdict из текущего анализатора. В частности, нельзя возвращать готовый `NegativeVerification` из authoritative `AnalysisCase` как подсказку модели.

## 7. Агентный цикл и результат

Цикл — адаптивный, без обязательного следования state-machine текущего Izyan:

```text
CVE + snapshot
    → research advisory/patch
    → hypotheses/root cause/conditions
    → выбрать проверку и вызвать tool
    → обработать Observation и ограничения
    → обновить модель
    → counterexample pass перед safe-оценкой
    → AgentAssessment
```

Агент отвечает за исследование; **не** получает право менять production verdict.

`AgentAssessment` содержит:

- `schema_version`, `task_id`, `snapshot_hash`, `cve_id`;
- `model`, `model_revision`, `prompt_version`, `harness_version`, `tool_adapter_version`;
- `root_causes`, `mandatory_conditions`, `claims` (`TRUE | FALSE | UNKNOWN`);
- evidence references, limitations, unresolved questions;
- `counterexample_review` (конкретно что проверено, что осталось неизвестно);
- `verdict_estimate` (`NOT_AFFECTED | NO_EXPLOIT_PATH_FOUND | EXPLOITABLE | INCONCLUSIVE`);
- VEX-Bench `category` (одна из 12) и текстовое обоснование;
- tool executions и затраты (tokens, calls, cost, wall).

`INCONCLUSIVE` считается отдельным безопасным abstention; не превращается в снятый алерт. Отказ провайдера / safety filter, timeout и невалидный ответ записываются как **`FAILED` с причиной**, а не как `uncertain` и не как negative.

## 8. Протокол эксперимента C1

### 8.1. До полного запуска

1. **Сверить frozen B1:** exact task IDs, model config, prompt hash, budget, timeout, Docker image, scoring version и сохранённые артефакты.
2. Поднять tool adapter в контейнере, проверить недоступность GT.
3. Запустить **три smoke-кейса**, покрывающие exploitable, non-reachable и configuration case. Их ответы и prompt/tool changes сохранить, но **не подмешивать** в final 90 attempts.
4. Зафиксировать версию C1 (Izyan commit, adapter, tools, prompt, image, snapshot hashes). После этого не менять реализацию в пределах серии.

### 8.2. Основной прогон

```text
30 Go-кейсов × 3 независимых повтора = 90 attempts
```

Для каждой попытки:

- новый disposable container и чистый контекст агента;
- неизменный снимок репозитория;
- **одна initial attempt**; не выполнять выборочные retries по ошибкам или GT;
- `FAILED` сохранять как исход; не заменять recovered label или «лучшим ответом»;
- повторять **весь** cohort под новым experiment ID, если обнаружен инфраструктурный дефект; оба набора артефактов сохранять;
- не переиспользовать smoke/cache как first-attempt outputs;
- хранить полный raw-output, logs, исходные tool responses, provider finish/refusal flags и parse status.

У каждого attempt должен быть самостоятельный immutable ID: `(task_id, repeat_id, experiment_id)`.

### 8.3. Скоринг без подмен

Вычислять **два вида оценок**, не смешивая их:

1. **Primary / official-strict:** неизменённый исходный ответ и заранее зафиксированный единый официальный parser/scorer. `FAILED` — ошибка выполнения/формата, но **не** safe verdict, не `INCONCLUSIVE` и не False-Safe.
2. **Secondary / parser-audit:** заранее определённый корректный JSON-decoder может восстановить *полный валидный JSON*, если официальный extractor ошибся. Применять одинаково к B1 и C1, хранить исходные метрики рядом; отдельно от label-only recovery, усечённого reasoning и свободного prose-extraction.

Уже известный дефект VEX-Bench parser при `{`/`}` внутри строк: **не исправлять только для C1** и не менять scoring между B1 и C1. Если parser устраняют, переоценить оба frozen набора без новых model calls.

Для Gemini/Qwen ранее наблюдавшиеся post-hoc RECOVERY и retry-composite **не** использовать как эталон C1.

## 9. Метрики

Главные safety-aware метрики, с отдельно показанными знаменателями:

| Метрика | Определение |
|---|---|
| **False-Safe** | `GT exploitable` и завершённый safe-negative (`NOT_AFFECTED`/`NO_EXPLOIT_PATH_FOUND`); знаменатель exploitable attempts |
| **Safe Clear Rate** | корректные завершённые safe-negative / safe attempts |
| **Exploitable recall** | завершённые positive / exploitable attempts |
| **INCONCLUSIVE** | валидный отказ от решения, отдельно от `FAILED` |
| **FAILED** | timeout, provider refusal/filter, no_result, parse_fail, tool/system error (по классам) |
| **Accuracy/F1 compatibility** | официальная binary-проекция VEX-Bench, **не** safety-гарантия |
| **Reason accuracy** | совпадение причины/categorization, отдельно от binary verdict |

Для трёх повторов считать метрики по повторам (**mean, sample std**) и отдельно raw counts по 90 attempts. Не представлять три повтора одного набора как 90 независимых CVE. Указывать per-case stability (`3/3`, `2/3`, `1/3`), прежде всего для отрицательных ответов.

### 9.1. Польза инструментов и регрессии

Для каждой пары `B1 ↔ C1` сравнивать *тот же case и repeat index*, если схема повторов сопоставима:

- `B1 wrong → C1 correct` (correction);
- `B1 correct → C1 wrong` (regression);
- `B1 INCONCLUSIVE/FAILED → C1 valid`, с раздельным учётом причин;
- `B1 False-Safe → C1 non-False-Safe` и наоборот;
- `C1` лучше по основанию при том же статусе.

`Tool Correction Rate` — **наблюдаемое парное улучшение режима**, а не автоматическое доказательство, что причиной стал конкретный tool. Утверждать причинность можно только после проверки raw trace и, при необходимости, ablation (отключить tool и повторить на отдельном наборе).

Дополнительно собирать invocations и **observed decisive evidence**: какое наблюдение агент процитировал при изменении claim/verdict; одно наличие tool call не делает его полезным.

## 10. Обязательный разбор известных рисков

Эти кейсы служат **послеэкспериментальными контрольными точками**, но не встраиваются как подсказки:

- `rancher-47914`: исходный Codex **видел indirect path**, но ошибся на *configuration/protocol gate*. Нельзя заранее считать задачу решённой одним `find_callers`.
- `k8s-44487`: существующий Izyan и один из plain agents сузили scope к `x/net/http2`, пропустив другой affected path через gRPC. Нужно проверить, не приводит ли tool output к преждевременному сужению scope.
- `podman-48795`: ошибочное «нет прямого first-party import, значит недостижимо» — проверить dependency/internal/transitive reachability.
- `k8s-3121`: Qwen 3.8 давала ложное отрицание на генераторе vs сгенерированном артефакте; учитываем как класс риска неверного CVE/package binding.

**Не добавлять** в prompt названия этих CVE, файлов и ожидаемые ответы; не добавлять case-specific rules в продакшен.

## 11. Результаты и отчёт

Сохранить артефакты по каждому attempt:

```text
results/task4-c1/<experiment_id>/
  manifest.json             # versions, task IDs, prompt hash, image/toolchain
  <task-id>/run_001/
    agent_assessment.json
    raw_agent_output.txt
    tool_calls.jsonl
    observations.jsonl
    status.json              # valid | inconclusive | failed (+ reason)
  ...
  scoring/
    official_metrics.json
    safety_metrics.json
    parser_audit_metrics.json
    case_comparison.jsonl
    disagreements.md
    tool_use_summary.md
```

Отчёт должен ответить:

1. Улучшился ли C1 против B1 при сопоставимых условиях?
2. Исправлены ли False-Safe B1 и появились ли новые?
3. Изменилась ли доля корректных safe decisions и реальных exploitable?
4. Какие наблюдения инструменты дали сверх обычного coding agent?
5. Какие ошибки — **интерпретации, охвата, точности tools или планирования Agent**?
6. Какие инструменты оставить, переделать или отложить?

## 12. Порядок реализации

**Подзадача 4.1 — adapter:** экспортировать минимальный набор существующих Evidence Tools; тесты `Scope/Completeness`, `ERROR != empty`, отсутствие обхода sandbox.

**Подзадача 4.2 — shadow loop:** агент вызывает новые tools, ведёт hypotheses, возвращает `AgentAssessment`; authoritative `AnalysisCase` не мутируется.

**Подзадача 4.3 — protocol/smoke:** тот же harness, модель, prompt baseline; проверка доступов, parser, refusal/failure и трех smoke-кейсов.

**Подзадача 4.4 — frozen C1 run:** 30 × 3 first-attempt, фиксированные артефакты.

**Подзадача 4.5 — analysis:** сравнение B1↔C1, safety-aware scoring, trace-based объяснение различий; решение, нужен ли следующий отдельный этап Verification Kernel.

## 13. Критерии готовности

Task 4 завершён, если:

1. C1 — та же модель и та же задача, что B1; отличия harness/prompt/budget явно перечислены и, если существенны, введён B1' в том же harness.
2. Agent + Izyan tools выполняет CVE research с нуля, не получая готовых выводов A/B.
3. Docker/agent tools не имеют доступа к GT, соседним кейсам, историям и результатам.
4. Добавленные tools сохраняют `scope`, `completeness`, `limitations`, `evidence`; пустой поиск не превращается в доказательство отсутствия.
5. Завершён smoke, **не включённый** в итоговые 90 attempts.
6. Выполнены **30 Go cases × 3 повтора**, без selective retry, cache mixing и best-of.
7. Официальный и исправленный (если есть) parser-scoring разведены; `FAILED`, `INCONCLUSIVE`, false-safe различаются.
8. Есть per-case disagreement и наблюдаемые corrections/regressions, включая False-Safe.
9. Есть статистика вызовов tools с анализом решающих observations.
10. Production verdict и существующий deterministic regression corpus не изменились из-за shadow-режима.
11. Нет benchmark-specific exceptions или изменения кода ради конкретного CVE.
12. Итоговое решение: **KEEP / REDESIGN / DEFER** для инструментов; обоснование отдельного Verification Kernel либо перечень открытых вопросов.

## 14. Что не делать после Task 4 автоматически

Даже если C1 покажет `False-Safe = 0/7`, **не переключать production на Agent** и не считать цель доказанной. Если C1 не улучшает B1, **не делать автоматически вывод**, что инструменты бесполезны: проверить, пользовался ли ими Agent и не вводили ли результаты `PARTIAL` в заблуждение. Verification Kernel проектировать **по наблюдённым оставшимся ошибкам и необходимым правилам доверия**, а не как заранее заданный огромный второй анализатор.

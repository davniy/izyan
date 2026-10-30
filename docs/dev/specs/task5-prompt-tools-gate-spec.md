# Izyan — Task 5: Prompt vs Evidence Tools vs Verification Gate

**Статус:** спецификация v2 (пересмотрена по итогам Task 4).  
**Цель:** установить, какое *минимальное* решение повышает безопасность и полезность Agent-first анализа: инструкция агенту, специализированные evidence-инструменты, независимый deterministic Gate или их сочетание.  
**Расположение в репозитории:** `docs/dev/specs/task5-prompt-tools-gate-spec.md`.  
**Заменяет:** `task5-verification-gate-spec.md` v1 в части цели, очередности разработки, экспериментального протокола и критериев завершения. Контракты проверки доказательств из v1 остаются кандидатами для фазы Gate, **но их реализация не предрешена**.

## 1. Почему изменён план

В Task 4 на 30 Go-кейсах VEX-Bench (7 exploitable, 23 safe), при одном основном прогоне на модель наблюдалось:

| Режим | False-Safe | EXPLOITABLE recall | Safe Clear Rate |
|---|---:|---:|---:|
| Qwen 3.6, исходный prompt без MCP | 1 | 6/7 | 19/23 |
| Qwen 3.6, `vuln_tools` + MCP | 3 | 4/7 | 20/23 |
| Qwen 3.8, исходный prompt без MCP | 0* | 7/7* | 20/23 |
| Qwen 3.8, `vuln_tools` + MCP | 3 | 4/7 | 21/23 |

\* Для Qwen 3.8 plain это **аудит-проекция после исправления парсинга полного JSON**, не официальный показатель; отдельные повторы обнаружили False-Safe. У двух моделей по одному основному прогону; результаты не устанавливают истинную частоту ошибок.

Важные ограничения Task 4:

- Поменялись **одновременно** текст prompt (`vuln` → `vuln_tools`), доступность MCP и адаптер агента. Это сравнение *конфигураций*, а не причинно изолированное измерение пользы tools.
- В MCP-плечах суммарно 513 вызовов, из них 100 `ERROR` и 2 `UNSUPPORTED`, включая 65 `context canceled`. Это отдельная возможная причина деградации.
- Наблюдалось превращение локальных наблюдений в глобальное «неэксплуатируемо»; пока не доказано, что именно prompt, инструменты или их сочетание вызвали ошибку.
- Исходные A/B/C и все их артефакты **не переименовываются и не исправляются задним числом**.

**Новый вопрос Task 5:** улучшает ли какой-либо дополнительный слой качество **относительно уже правильно проинструктированного plain Agent**? Нельзя принимать Verification Gate лишь потому, что он блокирует все отрицательные ответы.

## 2. Исследуемые гипотезы и варианты

| Код | Исследователь | Инструменты агента | Post-check | Что измеряет |
|---|---|---|---|---|
| **P0** | Исходный официальный `vuln` | Обычные инструменты coding agent, **без MCP Izyan** | Нет | Исторический benchmark baseline; справочная точка |
| **P1** | **Tuned safety prompt v1** | Те же обычные инструменты, **без MCP Izyan** | Нет | Эффект улучшения инструкций |
| **T1** | **Тот же базовый tuned prompt** | Обычные инструменты **+ MCP Izyan** | Нет | Добавочная польза/вред MCP при одинаковой методике |
| **G-P1** | Ровно те же сохранённые ответы P1 | MCP не предоставлялся агенту | **Verification Gate** | Даёт ли Gate прирост сверх tuned plain Agent |
| **G-T1** | Ровно те же сохранённые ответы T1 | MCP был доступен агенту | **Тот же Verification Gate** | Даёт ли Gate прирост сверх tuned Agent + MCP |

`P1 ↔ T1` — основное сравнение полезности инструментов. `P1 ↔ G-P1` и `T1 ↔ G-T1` — чистое измерение эффекта постпроверки. `G-P1 ↔ G-T1` отвечает, **нужно ли агенту вообще видеть MCP**, если независимая проверка доступна после его ответа.

**Нельзя** сравнивать `P0 ↔ G-T1` и приписывать всё улучшение Gate: между ними одновременно меняется несколько факторов.

Варианты G — *постобработка*. Они не генерируют новый ответ агента, не меняют его prompt и не выполняют LLM retry. Если для Gate потребуется отдельный LLM-экспорт/дополнительные инструкции, это **новый эксперимент со своей парой ungated-контролей**; старый P1/T1 не подменять.

## 3. Принципы честного сравнения

1. **Одна модель внутри пары**, один endpoint/revision, температура/effort по возможности одинаковы; Qwen 3.6 и Qwen 3.8 — отдельные cohorts. Codex/Gemini допустимы как дополнительные независимые cohorts, но результаты моделей не смешивать.
2. Один VEX-Bench task manifest, pinned `repo_url+commit_sha`, Docker-изоляция, одинаковые источники CVE и outbound research, равные `timeout`, `max steps`, лимиты токенов и параллелизм. Сохранять реальные затраты и достигнутые лимиты: MCP-вызовы съедают время и бюджет.
3. `P1` и `T1` **одинаковы в исследовательской инструкции и выходной schema**. Единственное неизбежное различие T1 — наличие инструментов и короткое справочное описание их интерфейса. Это различие фиксируется точным diff и hash prompt/config.
4. **Базовые средства coding agent не отнимать в T1**: это проверка добавочной ценности MCP, а не замены `bash` на меньший набор API.
5. `ground_truth`, `ground_truth_category`, reference PR из task, предыдущие результаты и чужие transcripts физически не доступны ни Agent, ни Gate. Scorer отделён от процесса исследования.
6. **First-attempt**: фиксировать каждую попытку; запрещены outcome-driven retry, смешение smoke и основного набора, перезапись `run_001`, post-hoc best-of и selective caching. Если нужны технические повторные попытки, они публикуются отдельно и одинаково для всех arms.
7. Повторы: smoke на 3 заранее известных диагностических кейсах (не как quality evidence), затем **30 Go-кейсов × 3 attempts на P1 и T1 для каждой выбранной модели**. Для бюджета можно сначала завершить одну модель и только затем повторить на второй.
8. Результаты Task 3/4 остаются frozen. Если версии модели, harness или условия существенно изменились, для свежего `P0 ↔ P1` нужен **новый matched P0**; исторический baseline остаётся справочным.
9. `FAILED`/timeout/refusal/parse_fail — отдельные исходы, **не** safe и не полноценный `INCONCLUSIVE`. Держать отдельно official-strict scoring и parser-repair полного JSON. Усечённый output нельзя считать полным доказательством.
10. Нельзя специально обучать prompt на ответах VEX-Bench и затем называть тот же набор независимым test. Известные кейсы используются как **development/regression set**; для проверки обобщения нужен новый holdout.

## 4. Tuned safety prompt: что именно менять

Нужен **один model-agnostic промпт**, применяемый одинаково в P1 и T1; версии иммутабельны (`safety-v1`, hash). Начинать с умеренного изменения официального `vuln`, а не с длинного перечня подсказок под конкретные CVE.

Обязательные общие правила (формулировать одинаково независимо от MCP):

1. **Отделять локальное наблюдение от итогового вывода.** `no matches`, `not imported`, `fix found`, `default=false` или `OK/COMPLETE` *отдельного запроса* не доказывают неэксплуатируемость CVE.
2. **Проверять альтернативные проявления дефекта.** Advisory package, fix diff и affected symbols могут не исчерпывать runtime manifestations. Проверить известные версии, транзитивные реализации, generated runtime, dependency-internal calls.
3. **Отрицательный вывод требует контрпроверки.** Перед safe-ответом назвать необходимость условия, область, проверенные альтернативы, факты и открытые ограничения. Если существенная альтернатива не проверена, выбрать `uncertain`.
4. **Не преобразовывать сбои в отсутствие.** Ошибка инструмента, timeout, `PARTIAL`, неправильная сборка, отсутствие toolchain или непроверенный deployment fact оставляют релевантное условие открытым.
5. **Эксплуатируемость не равна одному reachability-факту**, равно как отсутствие прямого first-party import не доказывает отсутствие транзитивного пути.
6. **Вывод фиксировать в структурированном ответе** с категорией VEX-Bench и reasoning, без выдуманных evidence IDs. `uncertain` = abstain в safety-scoring.

Запрещено вписывать в prompt названия известных VEX-кейсов, специальные подсказки про конкретный `grpc`, `k8s`, `Rancher`, `generated.pb.go` или фиксы; только общие принципы.

**Важное ограничение:** хороший промпт может повысить *наблюдаемое качество и стабильность*, но сам по себе не создаёт независимой machine-verification гарантии. Это **предмет измерения**, а не причина заранее отвергать prompt-only подход.

### 4.1. Выходной контракт всех агентных arms

Не заставлять P1 выдавать специфические MCP evidence IDs, которых у него нет. Минимум — совместимый с официальным benchmark JSON:

```json
{
  "category": "vulnerable | code_not_reachable | uncertain | ...",
  "reasoning": "Конкретные основания и ограничения"
}
```

Для экспериментального структурированного экспорта допустим дополнительный артефакт **одной и той же schema** в обоих arms (только если не меняет основной ответ или меняет его одинаково):

```json
{
  "claims": [{
    "assertion": "...",
    "subject": "...",
    "scope": "...",
    "evidence_refs": ["file:path:line", "tool:optional-id"],
    "limitations": []
  }],
  "unresolved": ["..."]
}
```

Ссылки на файл/строку и тексты модели — **предложения**, а не доказательства. Ни P1, ни T1 не получают привилегий от наличия конкретного формата ссылки; валидатор разрешает её самостоятельно.

## 5. Что делать с инструментами Izyan

Для T1 оставить доступ ко всем заранее определённым 31 MCP-tool из Task 4 и обычным средствам агента. **Не расширять toolset одновременно с prompt tuning.** Зафиксировать schema версии и фактические вызовы.

Особое внимание:

- `OK` = успешное выполнение конкретного вызова; **не** подтверждение истинности глобального claim.
- `COMPLETE` — полнота **названного subject/query/build scope**, не всей CVE. Если область не указана или не проверена, отрицательная полнота остаётся неизвестной.
- `ERROR`, `UNSUPPORTED`, `PARTIAL`, `UNKNOWN` и `context canceled` не превращаются в отрицательное evidence.
- Проблемы окружения (`govulncheck` отсутствует, `go.mod` требует изменений, tool timeout) документируются отдельно от агентного reasoning. Нельзя тихо чинить только T1 после части прогонов; такой run получает другой `environment_revision/experiment_id`.

**Первое инженерное действие:** записать для P1/T1 одинаковую границу исполнения и полноценные tool traces с `status`, `completeness`, `subject`, `scope`, `limitations`, `tool_version`, `snapshot_hash`, `latency`. Это нужно для объяснения отличий; не требуется немедленно переписывать все API.

## 6. Verification Gate: только после prompt/tools сравнения

**Решение о реализации Gate не принимать заранее.** Сначала провести §2–5 и определить, сохраняются ли False-Safe у P1 и T1 и что они имеют общего.

Если Gate нужен для следующего проверяемого результата, сделать *минимальный экспериментальный* post-processor, независимый от текста prompt:

```text
same completed P1 or T1 assessment
                 │
                 ▼
      evidence/snapshot adapter
                 │
                 ▼
       Verification Gate
        ├─ ACCEPTED (safe)
        └─ BLOCKED (INCONCLUSIVE)
```

### 6.1. Две независимые обязанности

**Scope/model:** доказательства покрывают заявленную CVE в явно зафиксированной области, включая все известные релевантные варианты. Локальный `COMPLETE` не доказывает глобальную замкнутость.

**Negative proof:** для каждого охваченного варианта есть проверяемое обязательное условие эксплуатации, невозможность которого действительно подтверждена в соответствующем build/deployment context. Не путать «не найдено» с «доказано невозможно».

Если доказательство недоступно, `BLOCKED → INCONCLUSIVE`, не безопасный вердикт. Gate также не подтверждает `EXPLOITABLE` только по утверждению LLM.

### 6.2. Общий контракт для G-P1 и G-T1

Gate получает один и тот же тип immutable входа:

```go
type GateInput struct {
    Snapshot      SnapshotRef
    Vulnerability VulnerabilityRef
    Candidate     CandidateDecision
    Scope         ScopeProposal
    Proofs        []ProofProposal
    Observations  []ObservationRef
}

type GateResult struct {
    Status            string // ACCEPTED | BLOCKED | NOT_APPLICABLE | ERROR
    EffectiveEstimate string // accepted safe или INCONCLUSIVE
    Reasons           []BlockReason
    ApprovedProofs    []ProofReceipt
    NeededChecks      []string
    InputHash         string
    GateVersion       string
}
```

Полные DTO и перечень proof rules из `task5-verification-gate-spec.md` v1 разрешается повторно использовать при имплементации, **но не принимать их как обязательный исход Task 5**.

Для **G-P1** валидатор может независимо проверить процитированные P1 факты по *прикреплённому неизменному snapshot* существующими deterministic routines; агент MCP не видел. Для **G-T1** валидатор дополнительно может проверить сохранённые MCP observations. Оба результата проверяются одним набором правил. Разницу затрат на независимую проверку измерять.

Gate **не имеет права** принимать ссылку `file:line`, LLM rationale, существование `ev:` или `scope_closed=true` за достаточный proof. Для каждой безопасной оценки проверить `snapshot hash`, `manifestation/subject`, `necessity`, `coverage` и валидное машинное отрицание. Неизвестное — `BLOCKED`.

**Поддерживаемые v1 rules-кандидаты:** `AFFECTED_VERSION_EXCLUDED`, `PACKAGE_ABSENT_IN_BUILD` и (только если есть надёжная проверка) `REACHABILITY_EXCLUDED`. `CONFIG_PRECONDITION_EXCLUDED` и `INPUT_PRECONDITION_EXCLUDED` — после контрпримеров. По умолчанию не считать доверенным `os.ReadFile`, наличие middleware или отсутствие найденных callers.

Если исторические Task 4 artifacts не содержат структурированных claims, **не реконструировать доказательства из GT или свободного reasoning**. Offline replay может показать только `INSUFFICIENT_INPUT`; это не верификация успеха Gate.

### 6.3. Важная оговорка к выводу

Даже если `G-P1` превосходит P1, это **не доказательство ценности MCP для агента**: улучшение могло быть получено независимой детерминированной постпроверкой. И наоборот, если P1 достигает 0 False-Safe на 30 кейсах, это **не доказательство ненужности Gate во всех условиях**. Решать по совокупности новых контрпримеров, удержанной доли safe-решений, стоимости и требуемого уровня гарантий.

## 7. Известные диагностические случаи

Из Task 4 (использовать для отладки и проверки понятности объяснений; **не** как unseen evidence):

| Кейс | Наблюдавшаяся проблема | Проверяемое общее свойство |
|---|---|---|
| `k8s-44487` | фиксация на одном advisory-компоненте | не объявлять глобальную безопасность при неполном CVE scope |
| `k8s-3121` | generator не вызывается, но поведение присутствует в generated runtime | учитывать форму присутствия vulnerable behavior, а не только исходный generator |
| `rancher-47914` | найденный path отвергнут через предположение о configuration/protocol gate | не выдавать safe без подтверждения effective config/полноты alternative paths |

Контроли без привязки к известным ID: корректно исключённая версия; корректно отсутствующий пакет; `find_callers=[]/PARTIAL`; `tool error`; two manifestations one unknown; generated code; configuration override; snapshot mismatch; правильный `uncertain`; валидный positive. Для Gate обязательно минимум один **принятый** корректный safe-пример и один отвергнутый unsafe-пример для каждого поддержанного rule.

## 8. Протокол выполнения Task 5

### 5.0 — Заморозить и описать исторические результаты

- Сохранить A/B/C, включая Task 4 Qwen, hashes prompt/tool schema/harness, ограничения n=1, parser projections и список `ERROR`.
- Провести code/harness audit границ доступа к GT, идентичности build/runtime и источников CVE. **Не исправлять baseline задним числом**.
- Подготовить единый scorer: `negative`, `positive`, `abstain`, `FAILED`, а также официальный VEX-Bench binary mapping в отдельной колонке.

### 5.1 — Prompt-only experiment (первый обязательный этап)

- Подготовить `vuln_safety_v1` без MCP-специфичных инструкций; зафиксировать hash до scored-прогона.
- Запустить **P1 без MCP** на одной модели в изолированном harness. Для чистого `P0 ↔ P1` при необходимости повторить P0 с тем же harness/runtime, иначе обозначить сравнение историческим.
- 3 diagnostic smoke cases — только для технической валидации, без доводки prompt по ground truth и выбора лучшей версии. Основной run: 30 Go cases × 3 attempts на модель, начиная с одной выбранной модели.
- Посчитать FS, SCR, recall, отказ/format fail, расходы и repeat stability. Сохранить сырые outputs, в том числе незавершённые.

**Checkpoint A:** есть ли реальные, устойчивые улучшения только от инструкции? Не объявлять успех по одному проходу или 0/7 false-safe.

### 5.2 — Matched tools experiment

- Взять *тот же* `vuln_safety_v1`, добавить только короткий tool API block, включить существующий MCP, не менять coding-agent base tools.
- Запустить T1 на той же модели, task list, budget, environment и с тремя попытками/кейс.
- Показать per-case `P1 ↔ T1`, впервые отличив влияние MCP от влияния safety-инструкции. Зафиксировать failed/partial MCP calls и долю misleading evidence.

**Checkpoint B:** есть ли дополнительная польза MCP или он не оправдывает стоимость и сложность? При регрессии не переходить автоматически к Gate, сначала выяснить, не деградирует ли исследование из-за ошибок MCP/конфигурации.

### 5.3 — Gate feasibility (условный этап)

**Начинать только если** после Checkpoint B остаётся конкретный тип опасного safe-вывода, который можно устранить проверяемым правилом, и задача не решается достаточно надёжно более простым способом.

- Изменения production workflow отсутствуют. Первым сделать offline replay с реально имеющимися структурированными evidence.
- Реализовать тонкий Gate для 1–2 обоснованных rule-кандидатов, а не универсальный proof engine.
- Прогнать **G-P1** и **G-T1** над **теми же неизменными исходными ответами**, записать overblocking и accepted-safe, а не только заблокированные FS.
- Если для Gate нужен новый prompt/схема, сначала получить новые matched P1'/T1' без Gate. Нельзя сравнивать G-T1' с историческим P0.

**Checkpoint C:** есть ли самостоятельный выигрыш от Gate относительно tuned plain и tuned tools без потери большинства полезных safe-решений?

### 5.4 — Holdout и архитектурное решение

- Известные 30 VEX-Bench Go-кейсов считаются **development benchmark** после анализа их ответов. Отдельный unseen holdout из новых кейсов/проектов и adversarial tests обязателен до архитектурного решения.
- При недоступности holdout — описать решение как предварительное, не утверждать доказанную безопасность.
- Результат: выбрать минимальную достаточную архитектуру; не переносить experimental safe-verdict в production автоматически.

## 9. Метрики

**Основные safety-aware:**

- `False-Safe`: `GT exploitable ∧ final = safe`; `INCONCLUSIVE` и `FAILED` — отдельно, не false-safe.
- `Safe Clear Rate`: `GT safe ∧ final = safe` / все safe.
- `EXPLOITABLE recall`: `GT exploitable ∧ final = vulnerable` / все exploitable. Если Gate заблокировал false-safe в `INCONCLUSIVE`, это **не TP** и recall не вырос.
- `Abstain rate`: содержательный `uncertain` отдельно от operational failures.
- `Wrong-safe repeat frequency` и `case stability`: результаты 3 независимых attempts по каждому кейсу; дополнительно risk-probes раскрывать отдельно, без подмешивания.

**Качество и стоимость:**

- `FAILED`/refusal/timeout/parse_fail, valid structured output, parser projection.
- Reason/category correctness, scope quality, пропущенные альтернативы, доля verified vs unsupported claims.
- MCP: `OK/PARTIAL/ERROR`, tool timeouts, query-level completeness, actual use of decisive observations, ненужные вызовы.
- Gate: `false-safe blocked`, `safe retained`, `overblocked correct safe`, `invalid proof`, `independent checks`, `wall/tokens/cost`.

**Нельзя** приписывать Gate повышение EXPLOITABLE recall, если он только превратил safe в `INCONCLUSIVE`. Нельзя доказывать отсутствие риска на выборке из семи exploitable-кейсов или путать official compatibility F1 с безопасностью автоматического закрытия тикета.

Отчёт должен показывать *абсолютные counts*, знаменатели, повторы, failure statuses, ранжирование по стоимости, **отдельные** official и audit projections, uncertainty/limitations. Никакого единственного «лучшего accuracy» без контекста.

## 10. Правила принятия решений

| Наблюдение на matched tests и holdout | Архитектурный вывод |
|---|---|
| **P1 улучшает P0**, T1 не приносит добавленной пользы, P1 выдерживает заданный риск/стоимость | Сначала развивать **prompt-only Agent**; MCP не добавлять в обязательный production path |
| **T1 устойчиво лучше P1**, в особенности на сложном reasoning, без роста False-Safe | Использовать MCP **там, где он показал полезность**; не считать полезными все 31 tool по умолчанию |
| P1/T1 допускают опасный safe, а **G-P1 / G-T1** блокирует его с приемлемым overblocking | Сохранять **минимальный Gate**, но не обязательно MCP у самого Agent |
| Gate блокирует все safe и получает False-Safe=0 | **Неуспех как продуктовый эксперимент:** безопасность куплена ценой нулевой автоматизации |
| Никакой вариант не сохраняет достаточную безопасность и пользу | Не разрешать automatic safe closure; оставить Agent как triage/research assistant с human review |

**Инженерный инвариант остаётся обязательным вне зависимости от выбора:** LLM prose, уверенность модели, `OK` инструмента и отсутствие находки не равны доказательству безопасности. **Продуктовое право автоматически закрывать vulnerability finding не появляется само собой** даже при высоком benchmark score.

## 11. Deliverables

```text
docs/dev/specs/task5-prompt-tools-gate-spec.md

eval/task5/
  prompts/
    vuln_safety_v1.txt
  experiment-manifest.json        # versions/hashes/arms/attempt policy
  results/
    p0/                           # historical or new matched baseline
    p1/                           # tuned/no MCP
    t1/                           # tuned/with MCP
    gp1/                          # conditional gate over p1
    gt1/                          # conditional gate over t1
  scoring/
    matrix.json
    disagreements.jsonl
    safety-report.md
  decision.md                     # evidence-based architecture choice
```

Gate modules из прежней v1 (`internal/verificationgate`) **не создавать до Checkpoint B**, если их не оправдывает результат. `gate input`/`receipt` сохранять только при выполнении 5.3.

## 12. Acceptance criteria

### Обязательные для Task 5: prompt/tools эксперимент

- [ ] Исторические A/B/C и отчёт Task 4 сохранены без переписывания.
- [ ] Выполнен новый **P1 без MCP**: единый tuned prompt, frozen hash, воспроизводимый эксперимент.
- [ ] Выполнен **T1**: та же модель и исследовательский prompt, только добавлен/включён MCP; diff и hashes опубликованы.
- [ ] Изоляция от GT, чужих transcripts и результатов подтверждена; один manifest и attempt policy.
- [ ] Есть 3 attempts/case для основного выбранного модельного cohort; все попытки и технические failures видимы.
- [ ] Публикованы **P0 ↔ P1**, **P1 ↔ T1** c per-case differences и классами причин.
- [ ] `INCONCLUSIVE`, `FAILED`, strict parse и parser-audit не смешаны.
- [ ] Подсчитаны FS, SCR, recall, overconfidence/missed-alternatives, stability, latency/cost.
- [ ] Нет case-specific CVE logic/hints и нет заявления о независимости старого VEX-Bench после анализа известных ответов.
- [ ] Выпущено `decision.md`: нужен ли MCP, нужен ли вообще Gate, что осталось недоказанным.

### Дополнительные, **только если** принят переход к 5.3

- [ ] Одна и та же реализация Gate применяется к неизменным P1 и T1 outputs: G-P1 / G-T1.
- [ ] Gate использует независимую проверку snapshot/subject/scope/necessity/negative proofs, не голосование другой LLM.
- [ ] Failed/PARTIAL/UNKNOWN не становится безопасным выводом; неверные refs не принимаются автоматически.
- [ ] Для каждого принятого safe есть проверяемый receipt; существуют реальные accepted-safe и adversarial blocked cases.
- [ ] Публикованы `false-safe blocked` **и** `safe retained/overblocked` и дополнительная стоимость.
- [ ] Gate не меняет обычный `izyan analyze`, VEX export или состояние текущих кейсов.

### Выход Task 5

Не «Kernel реализован», а **решение на основе сравнения**:

> Нужны ли именно MCP-инструменты Izyan в агентном цикле и нужен ли независимый Verification Gate сверх правильно настроенного plain Agent? Если да — какие минимальные правила дают измеримый выигрыш и какой ценой?

**Вопрос автоматического закрытия finding в production остаётся отдельным решением** после проверки на unseen-кейсах и анализа допустимого риска.

# Governing specification: модуль анализа эксплуатируемости уязвимостей

## 1. Назначение

Сервис на Go анализирует уязвимость относительно конкретного snapshot продукта и формирует воспроизводимый verdict с доказательствами.

Ключевой вопрос: не «достижима ли уязвимая функция?», а «выполняются ли обязательные условия эксплуатации конкретной уязвимости?». Reachability является одним из условий, но не заменяет exploitability analysis.

## 2. Архитектура

```text
Task Tracker
  -> Vulnerability Intake
  -> Affected Resolver
  -> Root Cause Resolver
  -> Exploit Condition Builder
  -> Evidence Pipeline
  -> EvidenceGraph
  -> Condition Evaluator
  -> Negative Check
  -> Reviewer
  -> Deterministic Verdict Engine
  -> Report
```

Remediation — отдельный workflow.

## 3. AnalysisCase

```go
type AnalysisCase struct {
    ID            CaseID
    Vulnerability Vulnerability
    Product       ProductSnapshot
    Affected      *AffectedResult
    RootCause     *RootCauseModel
    Exploit       *ExploitModel
    EvidenceGraph EvidenceGraph
    Claims        []Claim
    Reviews       []Review
    Verdict       *VerdictResult
    Workflow      WorkflowStatus
}
```

Persisted `AnalysisCase`, а не LLM conversation, является источником истины.

## 4. ProductSnapshot

Любой вывод привязан к конкретному состоянию продукта:

- repository;
- commit/tag;
- Go version;
- GOOS/GOARCH;
- build tags;
- CGO;
- vendor mode;
- `go.work`;
- `replace` directives.

Без конкретного commit/tag финальный verdict запрещён.

## 5. Vulnerability model

Нормализуются:

- CVE/GO/GHSA и aliases;
- module/package;
- affected ranges;
- fixed versions;
- affected symbols;
- description/summary;
- CWE;
- references;
- provenance каждого существенного поля.

Источники: Go Vulnerability Database, OSV, GHSA/vendor advisory, task tracker, внутренние источники.

## 6. Affected Resolver

Дешёвые детерминированные проверки выполняются первыми:

```text
dependency exists?
 -> affected version?
 -> package present?
 -> relevant build?
```

Используются `go list -m -json all`, `go list -deps -json`, `go mod graph` и build context.

Если версия вне affected range — `NOT_AFFECTED` без LLM-heavy анализа.

## 7. RootCauseModel

Root cause — самостоятельная проверяемая сущность:

```go
type RootCause struct {
    Package     string
    Symbol      string
    Role        RootCauseRole
    Mechanism   string
    EvidenceIDs []EvidenceID
}
```

Статусы: `RESOLVED`, `AMBIGUOUS`, `NOT_FOUND`.

Приоритет источников:

1. явные affected symbols;
2. fix commit/patch;
3. vulnerable source;
4. vendor advisory;
5. CVE description/CWE.

LLM формирует кандидатов, но кандидат обязан пройти verification: symbol exists, принадлежит affected package, patch/source подтверждают механизм. Неоднозначный root cause — это незавершённый анализ кода, поэтому он даёт `assessment_outcome=FAILED` с типизированной причиной (`ROOT_CAUSE_UNRESOLVED`), а не `INCONCLUSIVE` (см. §28).

## 8. ExploitModel

После root cause строится минимальный набор обязательных условий эксплуатации.

```go
type ExploitModel struct {
    Impact              string
    RootCauses          []RootCauseRef
    MandatoryConditions []Condition
    SupportingFactors   []Condition
    EvidenceIDs         []EvidenceID
}
```

Условие должно быть атомарным и проверяемым. Примеры:

- `SYMBOL_REACHABLE`;
- `ATTACKER_CONTROL`;
- `INPUT_CONSTRAINT`;
- `VALIDATION_PRESENT/ABSENT`;
- `CONFIGURATION`;
- `BUILD_CONDITION`;
- `PLATFORM_CONDITION`;
- `AUTHENTICATION/AUTHORIZATION_CONDITION`;
- `RUNTIME_CONDITION`.

`MandatoryConditions` участвуют в verdict. `SupportingFactors` влияют только на risk/priority/report.

## 9. Exploit Pattern Library

Для типовых классов уязвимостей хранятся шаблоны вопросов, а не готовые verdict:

- panic/DoS;
- malformed input/OOB;
- path traversal;
- command injection;
- SSRF;
- unsafe deserialization;
- resource exhaustion;
- auth bypass/XXE/ReDoS по мере необходимости.

LLM адаптирует шаблон по advisory + patch + source.

## 10. Evidence

Факт из инструмента сохраняется как самостоятельный объект:

```go
type Evidence struct {
    ID           EvidenceID
    Kind         EvidenceKind
    Quality      EvidenceQuality
    Source       string
    Repository   string
    Commit       string
    File         string
    StartLine    int
    EndLine      int
    Tool         string
    ToolVersion  string
    Command      string
    Content      string
    ArtifactHash string
    Limitations  []string
}
```

Качество:

- `AUTHORITATIVE` — advisory/fix commit/официальные affected symbols;
- `DETERMINISTIC` — go list/govulncheck/build/runtime trace;
- `STRUCTURAL` — AST/SSA/call graph/data-flow;
- `HEURISTIC` — regex/proximity/pattern search;
- `LLM_INFERRED` — интерпретация модели.

`LLM_INFERRED` не может самостоятельно подтверждать Condition.

## 11. EvidenceGraph

Raw outputs анализаторов нормализуются в стабильный versioned contract:

```text
EvidenceGraph
  - Evidence
  - CallPaths
  - DataFlows
  - Entrypoints
  - Validations
  - Configuration
  - Runtime
  - ToolLimitations
  - Hash
```

Raw tool output хранится отдельно. EvidenceGraph должен быть deterministic, hashable и serializable.

## 12. Claims

Каждый mandatory Condition получает один текущий Claim:

```go
type Claim struct {
    ID                   ClaimID
    ConditionID          ConditionID
    Result               ClaimResult // TRUE/FALSE/UNKNOWN
    EvidenceIDs          []EvidenceID
    Explanation          string
    Limitations          []string
    NegativeVerification *NegativeVerification
}
```

Запрещены промежуточные псевдовердикты `LIKELY_TRUE`, `PROBABLY_SAFE` и т.п.

## 13. Правила TRUE/FALSE/UNKNOWN

`TRUE` требует положительного evidence.

`FALSE` требует более строгого положительного доказательства невозможности обязательного условия.

Главный инвариант:

```text
NO EVIDENCE != FALSE
```

Если путь не найден, но полнота анализа не доказана, Condition остаётся `UNKNOWN`.

Для сильного `FALSE` необходимо покрыть relevant callers/sources/configuration и существенные dynamic alternatives.

`UNKNOWN` — нормальный результат при reflection, unsafe, plugins, unresolved interfaces/function pointers, неизвестной конфигурации, недоступном runtime evidence, tool failure или исчерпании бюджета.

## 14. Go-specific analysis

В MVP основной источник reachability — `govulncheck` + Go Vulnerability Database.

Он используется для:

- affected module/package/symbol;
- call stacks/reachability;
- базовой связи уязвимости с программой.

Собственные `go/packages`, `go/ssa`, `go/callgraph`, `go/ast`, `go/types` применяются только для вопросов, которых `govulncheck` не закрывает: argument provenance, validation, alternate callers, entrypoints, configuration.

Полноценный универсальный taint engine в MVP не нужен.

## 15. Data origin / data flow

Origin классифицируется как:

- `EXTERNAL_UNTRUSTED`;
- `EXTERNAL_AUTHENTICATED`;
- `CONFIGURATION`;
- `DATABASE`;
- `INTERNAL_SERVICE`;
- `CONSTANT`;
- `GENERATED`;
- `UNKNOWN`.

`authenticated != trusted`, если пользователь контролирует значение.

Целевая форма анализа:

```text
source -> transformations -> validation -> sink
```

Важны security-relevant transformations, а не только начало и конец.

## 16. Validation analysis

Название функции `validate()` не является доказательством. Проверяется конкретное свойство, связанное с exploit precondition.

Если CVE требует `len(input) < 4`, доказательством mitigation является логика, гарантирующая `len(input) >= 4` до sink, а не общий факт «input validated».

## 17. Tool API

LLM работает только через типизированные инструменты:

- `get_vulnerability`;
- `get_advisory`;
- `get_fix_references`;
- `get_fix_diff`;
- `get_module_version`;
- `get_dependency_graph`;
- `run_govulncheck`;
- `find_symbol`;
- `find_references`;
- `find_callers`;
- `find_entrypoints`;
- `read_function`;
- `read_source`;
- `trace_argument`;
- `find_validations`;
- `search_source`;
- `run_build`;
- `run_tests`.

Universal shell не является основным интерфейсом агента.

Каждый аналитический tool call привязан к `ConditionID`, `HypothesisID` и purpose.

Tool failure — не отрицательное evidence.

## 18. Hypothesis-driven loop

```text
select UNKNOWN condition
 -> formulate hypothesis
 -> call targeted tool
 -> store Evidence
 -> update EvidenceGraph
 -> evaluate claim
 -> gap analysis
```

Оркестратор на Go управляет state, permissions, budgets, schema validation, persistence, retry/timeout. LLM выбирает, что проверить и как семантически интерпретировать полученный контекст.

## 19. Negative-check

Перед safe verdict каждый `FALSE`, влияющий на него, проходит попытку опровержения:

- альтернативные callers;
- interface implementations;
- function variables;
- runtime registration;
- reflection/unsafe;
- build-tagged implementation;
- alternate entrypoints;
- configuration overrides.

Результаты: `VERIFIED`, `INSUFFICIENT_SCOPE`, `CONTRADICTED`.

Только `VERIFIED` допускает использование `FALSE` для `NO_EXPLOIT_PATH_FOUND`.

## 20. Verdict Engine

Verdict вычисляется чистой Go-функцией:

```text
affected version FALSE (в пределах admitted scope)
    -> NOT_AFFECTED

all mandatory TRUE
    -> EXPLOITABLE

mandatory FALSE + negative verification VERIFIED
    -> NO_EXPLOIT_PATH_FOUND

атрибутированный к CVE независимо доказанный positive другого record
    -> EXPLOITABLE (тот же profile/build; scope = transport-peer или library-api)
```

Confidence, CVSS, EPSS, KEV и PoC availability не участвуют в этом вычислении.

Последний `otherwise` больше не превращается в `INCONCLUSIVE`: вердикт-движок
возвращает отсутствие вердикта вместе со структурированными причинами, а
terminal outcome классифицируется отдельным контрактом (три исхода, §28).
`FAILED` — не пятый вердикт, а отказ анализа ответить.

## 21. Reviewer

Reviewer получает immutable package:

- Vulnerability;
- ProductSnapshot;
- RootCauseModel;
- ExploitModel;
- EvidenceGraph;
- Claims;
- proposed Verdict.

Он проверяет:

- root cause;
- пропущенные mandatory conditions;
- unsupported TRUE/FALSE;
- missed caller/entrypoint;
- неправильную интерпретацию patch;
- scope mismatch;
- dynamic behavior;
- противоречия evidence.

Reviewer возвращает `ACCEPT` или `REVISE` с конкретными findings; новый verdict он не выставляет. Repair loop ограничен 1–2 итерациями.

## 22. Persistence/reproducibility

Сохраняются:

```text
case/
  vulnerability
  product_snapshot
  affected_analysis
  root_cause_model
  exploit_model
  hypotheses
  tool_executions
  evidence_graph
  claims
  reviews
  verdict
  report
```

Для tool execution фиксируются version/input/command/exit status/stdout/stderr/commit/build configuration/hash.

## 23. Autonomy budget

Минимальные лимиты:

- MaxIterations;
- MaxToolCalls;
- MaxLLMCalls;
- MaxSourceReads;
- MaxReviewIterations.

Исчерпание аналитического бюджета приводит к `assessment_outcome=FAILED` с причиной `ANALYSIS_BUDGET_EXHAUSTED`, а не к догадке и не к `INCONCLUSIVE`: бюджет — ограничение инструмента, а не внешний факт. Диагностический отчёт при этом пишется (см. §28).

## 24. Remediation

Не входит в критический путь MVP, но архитектура должна позволять:

```text
EXPLOITABLE
 -> fixed version
 -> isolated worktree
 -> dependency upgrade
 -> go mod tidy
 -> build/tests/govulncheck
 -> minimal compatibility repair if needed
 -> repeat exploitability analysis
```

## 25. Output

Внутренняя модель не должна зависеть от VEX. Выходы:

- JSON artifact;
- human-readable report;
- task tracker comment;
- позднее OpenVEX/CycloneDX VEX.

## 26. MVP acceptance criteria

MVP готов, если:

1. анализ всегда привязан к ProductSnapshot;
2. affected version определяется без LLM;
3. RootCauseModel существует отдельно и имеет evidence;
4. ExploitModel содержит проверяемые mandatory conditions;
5. raw tool output нормализуется в EvidenceGraph;
6. claims только TRUE/FALSE/UNKNOWN;
7. absence of evidence не становится FALSE;
8. safe FALSE проходит negative-check;
9. tool failure не становится negative evidence;
10. confidence/CVSS/EPSS/KEV не участвуют в verdict;
11. LLM не может напрямую задать итоговый verdict;
12. Reviewer проверяет root cause/conditions/claims;
13. `INCONCLUSIVE` — штатный результат, но только для `EXTERNAL_DEPENDENCY`: незавершённый анализ кода даёт `FAILED` без вердикта (§28);
14. persisted state позволяет продолжить анализ без LLM chat history;
15. evidence воспроизводимо;
16. формируется tracker-ready rationale.

## 27. Главные инварианты

```text
dependency present != exploitable
vulnerable function reachable != exploitable
path not found != path impossible
LLM statement != Evidence
high confidence != proof
```

Безопасный verdict требует положительного доказательства невозможности хотя бы одного обязательного условия эксплуатации.

## 28. Terminal outcome, requested finding and record isolation

Настоящий раздел заменяет прежнюю трактовку, в которой ограничение инструмента
или исчерпанный бюджет становились terminal `INCONCLUSIVE`.

### 28.1 Три исхода

| `assessment_outcome` | Публикуемый вердикт | Смысл |
|---|---|---|
| `DECIDED` | `EXPLOITABLE`, `NOT_AFFECTED`, `NO_EXPLOIT_PATH_FOUND` | Правила доказательства дали ответ. |
| `EXTERNAL_DEPENDENCY` | `INCONCLUSIVE` | Названный факт, меняющий ответ, лежит вне артефакта и выбранного профиля. |
| `FAILED` | нет вердикта | Анализ, разрешение входа, возможность доказательства или authority scope недостаточны. |

`FAILED` — не пятый вердикт, а отказ анализа ответить; он несёт
структурированные причины (`AnalysisGap`: owner + code) и диагностический отчёт.
Claim-значения остаются `TRUE`/`FALSE`/`UNKNOWN`: неудавшееся измерение
оставляет claim `UNKNOWN`, а terminal outcome меняет классификация, не evidence.

Правило: незавершённая работа по коду (`• ReACHABILITY_PROOF_INCOMPLETE`,
`• INPUT_TRACE_INCOMPLETE`, `• TRIGGER_PROOF_INCOMPLETE`,
`• NEGATIVE_VERIFICATION_INCOMPLETE`, `• REVIEW_UNRESOLVED`,
`• ANALYSIS_BUDGET_EXHAUSTED`, `• ROOT_CAUSE_UNRESOLVED`,
`• MEASUREMENT_NOT_COMPLETED`, `• UNSUPPORTED_NEGATIVE_SCOPE`) — это `FAILED`.
`EXTERNAL_DEPENDENCY` требует именованного внешнего факта, доказательства
границы, объяснения, почему артефакт его не даёт, и какие варианты меняют ответ.
LLM не может объявить пробел внешним, присвоив ярлык.

### 28.2 Discovery, attribution и изоляция записей

Для запроса CVE `C` discover и attribution — разные propositions:

- discovery номинирует record'ы, чьи собственные `id`/`aliases`/прямые `related`
  называют `C` (без транзитивного замыкания `related` и без объединения
  aliases+related в один класс эквивалентности);
- attribution доказывает «C покрывает именно эту реализацию/механизм» через
  собственный `id`/alias записи **или** захваченный publisher/CNA материал,
  связывающий C с реализацией и fix. Persist: CVE, candidate + digest
  документа, covered entry/mechanism, basis, source URI + digest, поле/цитата,
  implementation/fix binding, admission result. Bare `related` недостаточно и
  никогда не поднимает positive.

Каждая assessment — включая primary — использует собственные точные байты
документа и собственные ranges/modules/packages/symbols, original census,
root cause, mandatory conditions, claims, review, severity и remediation.
Alias/feed-обогащение не является механизмом загрузки assessment. Общими
являются только immutable измерения продукта, которые перепроецируются на
subject'ы каждой записи.

Композиция — только независимо доказанные positives, по profile/build:

```text
Positive(C, p) <=> exists R: Attributed(R, C) and IndependentlyExploitable(R, p)
```

Один admitted positive решает CVE. Кандидатные negatives никогда не закрывают
CVE. Zero-trust positive не устанавливает cluster-perimeter positive.

### 28.3 Границы corpus (Addendum A)

Пустой результат или завершённый scan сами по себе не являются authority
закрытия. CVE-запрос может дать `NOT_AFFECTED` только если: (1) discovery
выполнен по явно сконфигурированному, digest-pinned corpus с завершённой
нумерацией; (2) каждый номинированный candidate оценён независимо; (3) нет
независимо `EXPLOITABLE` кандидата для профиля запроса; (4) нет неразрешённой
атрибуции, способной изменить ответ; (5) результат дословно сообщает corpus,
его digest, дату захвата и что реализации вне corpus не исследовались.
Отсутствующий/частичный/необъявленный corpus даёт
`FAILED / UNSUPPORTED_NEGATIVE_SCOPE`. `AllowsNegativeClosure()` не ослабляется.
Полнота corpus не заменяет семантическое доказательство: неизвестный или
проваленный child — не negative, а `NO_EXPLOIT_PATH_FOUND` не переименовывается
в `NOT_AFFECTED`.

### 28.4 transport-peer scope и «локальный ≠ доверенный»

`transport-peer` — ортогональный scope, а не новый вердикт или профиль. Он
устанавливается только admitted mandatory `TRUE` transport-input claim и
означает: клиент затронутого транспорта продукта может подать триггерные байты.
Вопрос доступа adversary к этому транспорту (права на сокет, размещение,
ingress, аутентификация) остаётся отдельным внешним вопросом и не
устанавливается. Локальность (Unix/loopback binding, ClusterIP, отсутствие
фактов экспозиции) не устанавливает доверенного peer'а: trusted actual profile
требует admitted deployment-policy basis или явного выбора оператора.
`transport-peer` не освобождается от cluster-perimeter перезаписи так, как
освобождаются library-public-api claims.

### 28.5 Один requested finding для всех публикаций

JSON, Markdown, CLI, scan/eval, tracker, justification, remediation, research,
OpenVEX и CycloneDX читают одну авторитетную проекцию `requested_finding`
(FINAL envelope — publish authority, а не позиция в workflow). Для composed
positive экспорт указывает CVE и witness конкретной записи/подкомпонента/
remediation, а не fix primary-записи. OpenVEX/CycloneDX могут использовать
`under_investigation`/`in_triage` и для внешней зависимости, и для failure, но
companion-проекция обязана их различать.

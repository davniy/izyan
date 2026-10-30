# Shadow Analyzer Agent и VEX-Bench evaluation

Статус: **SUPERSEDED** — superseded by `docs/dev/roadmaps/2026-10-20-target-architecture-and-roadmap.md`
(target architecture + S-01…S-17 backlog) and D17 in `docs/dev/decisions/architecture-decisions.md`.
Документ сохранён для исторической прослеживаемости происхождения Shadow/V2.

Предлагаемые файлы:

```text
docs/dev/specs/shadow-analyzer-agent-spec.md
docs/dev/roadmaps/agent-first-analysis-roadmap.md
```

# 1. Цель

Проверить архитектурную гипотезу:

> Может ли современный LLM/coding agent выполнять основную исследовательскую часть анализа эксплуатируемости лучше текущего deterministic pipeline Izyan, если оставить детерминированному коду только проверку фактов и безопасных отрицательных решений?

Целевая архитектура, если гипотеза подтвердится:

```text
Known vulnerability
       ↓
Analyzer Agent
       ↓
hypotheses / exploit conditions
       ↓
typed evidence tools
       ↓
observations
       ↓
Verification Kernel
       ↓
authoritative claims
       ↓
deterministic verdict
```

На первом этапе production-поведение Izyan не меняется.

Добавляется независимый `Shadow Analyzer Agent`.

---

# 2. Зачем нужен внешний benchmark

Текущий `eval/corpus-real.json` полезен как regression suite, но не является достаточным доказательством архитектурного преимущества Izyan.

Причины:

- кейсы развивались одновременно с анализатором;
- отдельные механизмы Izyan создавались для закрытия найденных на этом корпусе пробелов;
- успешный результат на собственном корпусе может означать хорошую регрессионную устойчивость, но не обязательно способность обобщаться.

Поэтому архитектурное сравнение должно включать внешний набор задач, который не использовался при разработке анализатора.

Основной внешний benchmark:

```text
VEX-Bench
```

---

# 3. Что представляет собой VEX-Bench

VEX-Bench проверяет практически тот же продуктовый вопрос, который решает Izyan:

```text
известная vulnerability в dependency
+
конкретный snapshot downstream-проекта
↓
эксплуатируема ли vulnerability именно в этом проекте?
```

Каждый task содержит:

```text
repo_url
commit_sha
cve_id
ground_truth
ground_truth_category
language
```

Но анализатору должны быть доступны только:

```text
repository snapshot
CVE ID
```

Ground truth и reference PR являются данными scorer-а и не должны попадать в Agent.

Текущий benchmark:

```text
75 cases
67 CVE
35 real repositories

Go     30 cases
Java   25 cases
Python 20 cases
```

На первом этапе Izyan использует только:

```text
30 Go cases
```

Это особенно полезно, потому что VEX-Bench работает не с маленькими искусственными fixtures, а с полными реальными репозиториями.

---

# 4. Что именно проверяет VEX-Bench

Исходная постановка:

```text
CVE
+
full repository snapshot
↓
Agent independently researches vulnerability
↓
inspects repository
↓
determines exploitability
↓
returns category + reasoning
```

Agent НЕ получает заранее:

```text
affected file
affected function
fix diff
call graph
root cause
prepared advisory summary
```

Он должен найти эту информацию самостоятельно.

Это делает benchmark хорошей проверкой способности Agent выполнять именно:

```text
research
localization
semantic reasoning
code investigation
exploitability assessment
```

---

# 5. Ground truth VEX-Bench

Основные ground-truth категории текущего набора:

```text
vulnerable
code_not_present
code_not_reachable
requires_configuration
requires_environment
```

Распределение всего benchmark:

```text
22 exploitable
53 not exploitable
```

Среди `not exploitable` преобладает:

```text
code_not_reachable
```

Это важно для Izyan: benchmark особенно хорошо проверяет способность отличать:

```text
dependency present
```

от:

```text
vulnerable functionality actually reachable
```

---

# 6. Расширенная taxonomy VEX-Bench

Текущий prompt VEX-Bench позволяет Agent выбрать одну из 12 категорий:

```text
false_positive
code_not_present
code_not_reachable
requires_configuration
requires_dependency
requires_environment
compiler_protected
runtime_protected
perimeter_protected
mitigating_control_protected
uncertain
vulnerable
```

Они имеют строгий порядок приоритета.

Для сравнения с Izyan эта taxonomy полезна отдельно от binary verdict, поскольку показывает:

> Почему Agent считает vulnerability неэксплуатируемой?

Именно justification является одной из наиболее сложных частей задачи.

---

# 7. Критическое отличие семантики Izyan

НЕЛЬЗЯ напрямую использовать binary mapping VEX-Bench для оценки безопасности Izyan.

В официальном VEX-Bench:

```text
vulnerable
→ exploitable

все остальные категории,
включая uncertain
→ not_exploitable
```

Для Izyan:

```text
uncertain
→ INCONCLUSIVE
```

И никогда:

```text
uncertain
→ safe
```

Поэтому оценка ведётся двумя параллельными способами.

## Compatibility metrics

Официальная метрика VEX-Bench.

Нужна только для сравнения с опубликованными Agent baselines.

## Safety-aware metrics

Собственная основная метрика Izyan.

Именно она используется для принятия архитектурных решений.

---

# 8. Соответствие verdict Izyan и VEX-Bench

Базовое отображение:

| Izyan | VEX-Bench |
|---|---|
| `EXPLOITABLE` | `vulnerable` |
| `NOT_AFFECTED` | обычно `code_not_present` или иной applicability reason |
| `NO_EXPLOIT_PATH_FOUND` | конкретная safe-category |
| `INCONCLUSIVE` | `uncertain` |

Для `NO_EXPLOIT_PATH_FOUND` причина определяется falsifier/condition:

```text
locus/package absent
→ code_not_present

locus unreachable
→ code_not_reachable

configuration disabled
→ requires_configuration

platform/environment condition false
→ requires_environment

required dependency absent
→ requires_dependency

validation/guard blocks exploit
→ mitigating_control_protected

perimeter/auth control
→ perimeter_protected
```

Это отображение используется только для scoring.

Внутренняя модель Izyan от taxonomy VEX-Bench зависеть не должна.

---

# 9. Главный эксперимент

Сравниваются четыре архитектурных режима.

## A. Current Izyan

```text
текущий deterministic-first pipeline
+
существующие optional LLM components
```

Authoritative verdict выдаёт текущий Izyan.

## B. Plain Coding Agent

Обычный coding agent работает в официальном VEX-Bench harness.

Пример:

```text
Codex
Claude Code
OpenCode
```

Agent имеет обычные средства исследования repository.

Verdict полностью принимает Agent.

Этот режим показывает:

> Что даст современный универсальный coding agent без архитектуры Izyan?

## C. Izyan Shadow Agent

LLM Agent исследует vulnerability самостоятельно, но использует typed tools Izyan:

```text
govulncheck
AST/types
callers
references
argument tracing
source search
build graph
dynamic markers
etc.
```

Verdict estimate принимает Agent.

Этот режим показывает:

> Дают ли специализированные инструменты Izyan преимущество обычному Agent?

## D. Agent + Verification Kernel

Будущий целевой вариант:

```text
Agent
→ proposals
→ evidence tools
→ Verification Kernel
→ authoritative verdict
```

Этот режим реализуется только после эксперимента A/B/C.

---

# 10. Главный вопрос benchmark

Не:

```text
у кого выше accuracy?
```

А:

> Какая архитектура автоматически разрешает больше реальных findings при минимальном риске ошибочно признать эксплуатируемую vulnerability безопасной?

Основная продуктовая метрика:

```text
Safe Clear Rate
при
False-Safe = 0
```

---

# 11. False-Safe

False-Safe — критическая ошибка:

```text
ground truth:
EXPLOITABLE

result:
NOT_AFFECTED
или
NO_EXPLOIT_PATH_FOUND
```

Формально:

```text
FalseSafe =
GT == exploitable
AND
result ∈ {NOT_AFFECTED, NO_EXPLOIT_PATH_FOUND}
```

`INCONCLUSIVE` False-Safe не является.

---

# 12. Safe Clear Rate

Из всех действительно неэксплуатируемых findings:

```text
SafeClearRate =
correct safe verdicts
/
all non-exploitable cases
```

Safe verdict:

```text
NOT_AFFECTED
NO_EXPLOIT_PATH_FOUND
```

`INCONCLUSIVE` считается unresolved.

---

# 13. Дополнительные метрики

Для каждого режима собирать:

```text
False-Safe count
False-Safe rate

Safe Clear Rate

EXPLOITABLE recall

INCONCLUSIVE rate

binary accuracy
binary precision
binary recall
binary F1

justification macro-F1

completion rate

tool calls
LLM calls
tokens
cost
wall time
```

Дополнительно для сравнения A/C:

```text
Agent wins
Current Izyan wins
Both correct
Both wrong
Disagreement
```

---

# 14. Отдельно оценивать причину решения

Правильный binary verdict недостаточен.

Например:

```text
Agent:
not exploitable because package absent
```

при фактическом:

```text
package present
but vulnerable function unreachable
```

не должен считаться полноценным успехом reasoning.

Поэтому сохраняются отдельно:

```text
status_correct
reason_correct
```

Это особенно важно для Izyan, поскольку tracker-ready rationale является частью продукта.

---

# 15. Защита от benchmark leakage

Файл:

```text
benchmark/tasks/vex_bench.jsonl
```

содержит одновременно:

```text
input
+
ground truth
+
reference PR
```

Agent никогда не должен иметь доступ к этому файлу.

Benchmark runner должен разделять:

## Control plane

Видит:

```text
task_id
repo_url
commit_sha
cve_id
ground_truth
ground_truth_category
pr_url
```

## Agent sandbox

Видит только:

```text
repository snapshot
cve_id
```

НЕЛЬЗЯ передавать Agent:

```text
ground_truth
ground_truth_category
metadata.pr_url
benchmark JSONL
reference answers
results других Agent
```

---

# 16. Public vulnerability research разрешён

VEX-Bench специально предполагает, что Agent самостоятельно ищет публичную информацию о CVE.

Поэтому Shadow Agent может использовать:

```text
OSV
Go Vulnerability Database
NVD
GitHub Advisory
upstream repository
public fix commits
public issue/PR
vendor advisory
```

Но Agent должен найти эти материалы самостоятельно по CVE/advisory references.

Нельзя брать:

```text
metadata.pr_url
```

из benchmark task.

Если тот же PR самостоятельно найден через advisory или repository research — это допустимо.

---

# 17. Snapshot VEX-Bench

Benchmark фиксирует каждый repository на точный:

```text
commit_sha
```

Официальный downloader после checkout удаляет `.git` history.

Это важно для Izyan.

Izyan не должен получать дополнительное преимущество за счёт локального git history, которого нет у других Agent.

Поэтому benchmark profile должен поддерживать snapshot без `.git`.

Snapshot identity:

```go
type ProductSnapshot struct {
    Repository string

    ExternalCommitSHA string
    ContentHash       string

    ...
}
```

`ExternalCommitSHA` приходит от benchmark controller.

Izyan доверяет controller-у только как источнику идентификатора snapshot.

---

# 18. Нельзя использовать local git history

В benchmark profile запрещено использовать:

```text
git log
git blame
локальные будущие commits
локальный fix commit
локальный reference PR
```

Fix history можно получить только через публичное внешнее исследование vulnerability.

Это сохраняет сопоставимость с VEX-Bench.

---

# 19. Benchmark profile Izyan

Добавить специальный профиль:

```text
--benchmark-profile vex-bench
```

Он задаёт:

```text
snapshot из external commit SHA
нет human overrides
нет NonLocusBasis
нет --trusted-peer
нет корпоративного knowledge overlay
нет deployment facts вне repository
нет ground-truth metadata
```

Разрешены:

```text
OSV/advisory network access
public upstream source
public fix references

go list
govulncheck
AST/types/SSA
source inspection
build/test
```

---

# 20. Выполнение кода

Официальный VEX-Bench запускает coding agents внутри disposable Docker sandbox.

Чтобы сравнение было справедливым, benchmark mode Izyan также должен выполняться в изолированном environment.

Для публичного VEX-Bench допускается:

```text
--allow-exec
```

для:

```text
go list
go build
go test
govulncheck
```

но только внутри disposable benchmark container.

Это отдельная политика benchmark.

Production default Izyan не меняется.

---

# 21. Подготовка VEX-Bench

Официальный setup:

```bash
git clone <vex-bench>
cd vex-bench

uv sync

uv run vex-bench download
```

После этого pinned repository snapshots находятся в:

```text
benchmark/repos/
```

Для Izyan нужен только Go subset.

Можно построить отдельный manifest:

```text
eval/external/vexbench-go.json
```

Он содержит только:

```json
{
  "task_id": "...",
  "repo_path": "...",
  "repo_url": "...",
  "commit_sha": "...",
  "cve_id": "..."
}
```

Без:

```text
ground_truth
ground_truth_category
pr_url
```

Ground truth остаётся только в scorer process.

---

# 22. Предлагаемый adapter

Добавить:

```text
internal/eval/vexbench
```

или отдельный пакет:

```text
eval/vexbench/
```

Ответственность adapter:

```text
read original VEX-Bench tasks
↓
filter language=go
↓
resolve downloaded repo snapshot
↓
construct hidden TestCase
↓
construct stripped AgentInput
↓
run Izyan
↓
score after completion
```

Ground truth не должен попадать в `AnalysisCase`.

---

# 23. Предлагаемый CLI

```text
izyan eval vex-bench \
  --tasks /path/vex-bench/benchmark/tasks/vex_bench.jsonl \
  --repos-dir /path/vex-bench/benchmark/repos \
  --mode deterministic
```

Shadow Agent:

```text
izyan eval vex-bench \
  --tasks ... \
  --repos-dir ... \
  --mode shadow-agent
```

Позднее:

```text
--mode hybrid
```

Дополнительные параметры:

```text
--case <task-id>
--repeats <N>
-j <workers>
--model <model>
--output <dir>
```

---

# 24. Первый smoke test

Не запускать сразу 30 Agent cases.

Сначала выбрать:

```text
1 exploitable
1 code_not_reachable
1 requires_configuration
```

Проверить:

```text
snapshot корректен
CVE разрешается
Agent не видит labels
artifacts сохраняются
output парсится
cost accounting работает
```

После этого запускать полный Go subset.

---

# 25. Первый baseline run

До любых VEX-Bench-specific изменений Izyan зафиксировать:

```text
Izyan commit SHA
VEX-Bench commit SHA
Go version
govulncheck version
OSV data time
model
model endpoint/revision
prompt version
benchmark adapter version
run date
```

И прогнать все:

```text
30 Go cases
```

Это будет:

```text
VEX-Bench External Baseline 1
```

После просмотра результатов этот baseline уже нельзя считать полностью unseen для дальнейшей разработки.

---

# 26. Plain Agent baseline

Отдельно запустить официальный VEX-Bench harness.

Пример:

```bash
uv run vex-bench evaluate run \
  --agent codex \
  --model <model> \
  --repeats 3 \
  --parallel 1

uv run vex-bench evaluate parse \
  --agent codex \
  --model <model> \
  --repeats 3

uv run vex-bench evaluate metrics \
  --agent codex \
  --model <model> \
  --repeats 3
```

Для нашего архитектурного сравнения желательно использовать ту же модель, что и Shadow Agent, если harness позволяет.

Тогда отличие:

```text
Plain Agent
vs
Agent + Izyan tools
```

становится более чистым.

---

# 27. Почему нужны повторы

LLM Agent недетерминирован.

Один прогон может случайно:

```text
найти правильный PR
пропустить caller
выбрать другой search path
```

Поэтому:

```text
1 repeat
```

используется только для smoke/development.

Архитектурное сравнение:

```text
3 repeats
```

на Agent modes.

Deterministic Izyan запускается один раз, если его результат действительно воспроизводим.

---

# 28. Shadow Agent

Запуск:

```text
izyan analyze \
  --repo <snapshot> \
  --vuln <CVE> \
  --shadow-agent \
  --benchmark-profile vex-bench
```

Agent получает:

```text
CVE ID
ProductSnapshot
typed tools
public vulnerability research
```

Он не получает authoritative анализ Izyan.

---

# 29. Изоляция Shadow Agent от Current Izyan

До завершения Shadow Agent ему запрещено видеть:

```text
authoritative Verdict
authoritative Claims
NegativeVerification
готовый RootCauseModel
готовый ExploitModel
Tracker-ready rationale
```

Иначе эксперимент превращается в:

```text
LLM reviews Izyan
```

вместо:

```text
LLM independently analyzes vulnerability
```

---

# 30. Обязанности Shadow Agent

Agent самостоятельно выполняет:

```text
understand CVE
↓
research advisory/fix
↓
determine vulnerability mechanism
↓
locate affected code
↓
build exploit model
↓
inspect downstream usage
↓
investigate input/config/environment
↓
test alternative hypotheses
↓
counterexample pass
↓
assessment
```

---

# 31. Tool API

Первая версия переиспользует существующие typed tools:

```text
get_vulnerability
get_advisory
get_fix_references
get_fix_diff

get_product_snapshot
get_dependency_graph
run_govulncheck

find_symbol
find_references
find_callers
find_entrypoints

read_function
read_source
search_source

trace_argument
find_validations
scan_dynamic
```

При sandboxed exec:

```text
run_build
run_tests
```

Universal shell как часть Izyan Agent не нужен.

---

# 32. Observation contract

Долгосрочно каждый tool должен возвращать не просто результат, а:

```go
type Observation struct {
    ID EvidenceID

    Fact string

    Scope AnalysisScope

    Completeness Completeness

    Limitations []string

    Provenance Provenance
}
```

Completeness:

```text
COMPLETE
PARTIAL
UNKNOWN
```

Главный инвариант:

```text
empty result
+
PARTIAL scope
!=
absence proved
```

---

# 33. Agent exploit model

Agent должен сформировать конкретные условия данной vulnerability.

Например:

```text
C1 affected parser executes
C2 attacker controls input
C3 attacker can provide len(input) < 4
C4 no earlier validation prevents len(input) < 4
```

Запрещено:

```text
vulnerable dependency present
+
network server exists
=
vulnerable
```

---

# 34. Agent claims

Agent возвращает:

```text
TRUE
FALSE
UNKNOWN
```

Но эти состояния являются:

```text
AgentClaim
```

а не authoritative `Claim`.

```go
type AgentClaim struct {
    ConditionID string

    State AgentClaimState

    EvidenceIDs []EvidenceID

    Reason string

    Limitations []string
}
```

Agent имеет право предположить `FALSE`.

Это не создаёт:

```text
Falsifier
NegativeVerification=VERIFIED
```

---

# 35. Counterexample pass

Перед любым собственным safe result:

```text
NOT_AFFECTED
NO_EXPLOIT_PATH_FOUND
```

Agent обязан выполнить отдельную попытку разрушить свой вывод.

Минимальные вопросы:

```text
Есть ли другой caller?
Есть ли dependency-internal invocation?
Есть ли interface dispatch?
Есть ли callback/function value?
Есть ли reflection/runtime registration?
Есть ли другой build variant?
Есть ли configuration override?
Есть ли alternate entrypoint?
Есть ли deployment assumption?
```

Результат сохраняется отдельно.

---

# 36. AgentAssessment

```go
type AgentAssessment struct {
    SchemaVersion string

    CaseID CaseID

    Model         string
    PromptVersion string

    ProductSnapshotHash string
    VulnerabilityID     string

    RootCauses []AgentRootCause

    Conditions []AgentCondition
    Claims     []AgentClaim

    CounterexampleReview AgentCounterexampleReview

    VerdictEstimate AgentVerdict

    Justification AgentJustification

    Uncertainties []AgentUncertainty

    ToolExecutions []ToolExecutionRef

    Usage AgentUsage
}
```

---

# 37. Agent verdict

```text
NOT_AFFECTED
NO_EXPLOIT_PATH_FOUND
EXPLOITABLE
INCONCLUSIVE
```

Поле:

```text
verdict_estimate
```

никогда автоматически не копируется в authoritative verdict.

---

# 38. Agent justification

Для VEX-Bench scoring:

```text
VULNERABLE

CODE_NOT_PRESENT
CODE_NOT_REACHABLE

REQUIRES_CONFIGURATION
REQUIRES_DEPENDENCY
REQUIRES_ENVIRONMENT

COMPILER_PROTECTED
RUNTIME_PROTECTED
PERIMETER_PROTECTED
MITIGATING_CONTROL

FALSE_POSITIVE
UNCERTAIN
```

Это adapter-facing taxonomy.

Внутренняя ExploitModel от неё не зависит.

---

# 39. Результаты одного benchmark case

```text
results/vexbench/<task-id>/
    input.json
    snapshot.json

    deterministic/
        report.json
        verdict.json

    shadow/
        run-001/
            agent_assessment.json
            tool_executions.json
        run-002/
        run-003/

    comparison.json
```

`input.json` внутри Agent-visible каталога не содержит ground truth.

---

# 40. Scorer artifacts

Ground truth хранится отдельно:

```text
results/vexbench/scoring/
```

Scorer после завершения анализа объединяет:

```text
prediction
+
hidden ground truth
```

и создаёт:

```text
metrics.json
cases.jsonl
disagreements.jsonl
```

---

# 41. Safety-aware scoring

Для Izyan считать:

```text
EXPLOITABLE
→ positive

NOT_AFFECTED
NO_EXPLOIT_PATH_FOUND
→ safe negative

INCONCLUSIVE
→ abstain
```

НЕЛЬЗЯ:

```text
INCONCLUSIVE
→ not_exploitable
```

---

# 42. Compatibility scoring

Для публикационного сравнения с VEX-Bench дополнительно можно генерировать официальный category output:

```json
{
  "category": "code_not_reachable",
  "reasoning": "..."
}
```

и прогонять официальный scorer.

Но результаты должны называться:

```text
VEX-Bench compatibility metrics
```

и не использоваться отдельно для оценки безопасности Izyan.

---

# 43. Основная таблица результатов

Итоговый report:

| Metric | Current Izyan | Plain Agent | Shadow Agent | Hybrid |
|---|---:|---:|---:|---:|
| False-Safe | | | | |
| Safe Clear Rate | | | | |
| Exploitable Recall | | | | |
| INCONCLUSIVE | | | | |
| Status F1 | | | | |
| Justification macro-F1 | | | | |
| Completion | | | | |
| Avg tool calls | | | | |
| Avg tokens | | | | |
| Avg time | | | | |
| Avg cost | | | | |

---

# 44. Disagreement analysis

Самые ценные cases:

```text
Agent correct / Izyan wrong
Izyan correct / Agent wrong
Agent safe / Izyan inconclusive
Izyan safe / Agent vulnerable
```

Для каждого divergence сохранять:

```text
ground truth
Izyan reasoning
Agent reasoning
relevant evidence
root cause difference
exploit-model difference
first point of divergence
```

Не просто:

```text
verdict differs
```

а:

> Где именно два подхода начали рассуждать по-разному?

---

# 45. Классификация причин проигрыша

Каждый ошибочный case после ручного review получает одну причину:

```text
ROOT_CAUSE_WRONG

MANDATORY_CONDITION_MISSED

CALL_PATH_MISSED

DATA_PROVENANCE_WRONG

CONFIGURATION_MISREAD

ENVIRONMENT_MISREAD

PATCH_MISINTERPRETED

TOOL_SCOPE_INCOMPLETE

LLM_REASONING_ERROR

FALSE_NEGATIVE_PROOF

BENCHMARK_AMBIGUITY

OTHER
```

Это определяет дальнейший roadmap.

---

# 46. Как использовать результат

Если Plain Agent выигрывает из-за:

```text
semantic reasoning
framework understanding
patch interpretation
```

не надо наращивать эти механизмы в deterministic analyzer.

Эту ответственность следует передать Agent.

Если Current Izyan выигрывает из-за:

```text
build graph
exact version resolution
call/reference completeness
negative verification
```

эти механизмы должны остаться в Verification Kernel.

---

# 47. Критерий Agent-first перехода

Не требуется, чтобы Shadow Agent был лучше Izyan абсолютно по каждой метрике.

Переход оправдан, если одновременно выполняется:

```text
1. Agent существенно улучшает semantic/reasoning cases;

2. typed tools уменьшают ошибки Plain Agent;

3. потенциальные safe-ошибки Agent можно отфильтровать
   небольшим Verification Kernel;

4. итоговый Hybrid сохраняет False-Safe не хуже Current Izyan;

5. Safe Clear Rate или количество корректно разрешённых
   сложных cases становится выше.
```

---

# 48. Что делать после первого VEX-Bench run

Нельзя сразу начинать исправлять все 30 кейсов.

Сначала построить:

```text
failure taxonomy
```

и ответить:

```text
Какие ошибки исправит лучший prompt?

Какие ошибки требуют нового tool?

Какие требуют deterministic proof rule?

Какие требуют deployment information?

Какие принципиально должны оставаться INCONCLUSIVE?
```

Только после этого менять архитектуру.

---

# 49. Защита от overfitting

После того как результаты конкретного VEX-Bench case использованы для изменения Izyan:

```text
этот case больше не считается unseen validation
```

Он становится regression case.

Поэтому:

### Первый прогон

Все 30 Go cases используются для независимого architectural baseline.

### После первого прогона

VEX-Bench становится:

```text
external regression benchmark
```

Для окончательного утверждения качества понадобится новый unseen holdout:

```text
новые CVE
новые проекты
внутренние размеченные findings
или новая версия внешнего benchmark
```

---

# 50. Запрет case-specific fixes

Нельзя добавлять:

```text
if CVE == ...
if repository == ...
knowledge entry только ради benchmark case
```

Любое исправление после VEX-Bench failure должно иметь:

```text
общий semantic rule
или
общий evidence tool
или
общий proof rule
```

и минимум один adversarial counterexample.

---

# 51. Минимальный план реализации

## Task 1. VEX-Bench adapter

Реализовать:

```text
read tasks
filter Go
strip labels
locate snapshot
run one Izyan case
score after completion
```

Без Shadow Agent.

Цель:

```text
Current Izyan vs VEX-Bench
```

---

## Task 2. External baseline

Прогнать текущий Izyan на 30 Go cases.

Никаких VEX-specific fixes до сохранения baseline.

Получить:

```text
False-Safe
Safe Clear Rate
INCONCLUSIVE
reason categories
failure taxonomy
```

---

## Task 3. Plain Agent baseline

Прогнать ту же модель через официальный VEX-Bench harness.

Получить:

```text
Plain Agent baseline
```

---

## Task 4. Shadow Agent core

Реализовать независимый Agent:

```text
research
plan
tool loop
exploit model
claims
counterexample review
assessment
```

Не интегрировать его verdict в основной pipeline.

---

## Task 5. Shadow benchmark run

Прогнать Shadow Agent на тех же 30 Go cases.

Сравнить:

```text
Current Izyan
Plain Agent
Shadow Agent
```

---

## Task 6. Failure analysis

Для divergence cases определить:

```text
Agent advantage
Tool advantage
Proof advantage
Missing information
```

---

## Task 7. Verification Kernel spec

Только после Task 6 определить минимальный набор authoritative proof rules.

Не проектировать заранее универсальный proof framework.

---

# 52. Acceptance criteria v1

Работа считается завершённой, если:

1. VEX-Bench pinned на конкретный commit.
2. Все 30 Go tasks могут быть перечислены adapter-ом.
3. Agent input содержит только CVE и repository snapshot.
4. Ground truth и PR URL физически недоступны Agent.
5. Snapshot анализируется без `.git` history.
6. Current Izyan baseline сохранён до VEX-specific изменений.
7. Plain Agent baseline получен хотя бы для одной общей модели.
8. Shadow Agent выполняет независимый анализ.
9. Shadow Agent не получает authoritative Izyan verdict.
10. Формируется `agent_assessment.json`.
11. Safe estimate проходит counterexample pass.
12. `INCONCLUSIVE` остаётся abstention.
13. Считаются safety-aware metrics.
14. Отдельно считаются VEX-Bench compatibility metrics.
15. Формируется disagreement report.
16. Ни один benchmark-specific exception не добавлен в production logic.
17. Existing `false-safe=0` regression suite Izyan остаётся зелёным.
18. Production verdict без `--shadow-agent` не меняется.

Примечание к п. 18. «Не меняется» означает: добавление Shadow
Analyzer, benchmark-taxonomy и VEX-Bench-профиля не влияет на
production verdict. Из этого исключены **общие** (не benchmark-specific)
исправления безопасности, заранее перечисленные в
[плане VEX-Bench adapter](../plans/2026-10-06-vexbench-adapter-plan.md) как
prerequisites: устранение подстановки `go.mod`/локального Go вместо
неизвестного release toolchain (§2.2, §2.3). Они меняют verdict там, где
ранее выдавался safe-negative по недоказанной applicability, и до baseline
обязаны быть зафиксированы как отдельный commit с опубликованным diff
состава. Baseline A (Current Izyan) определяется как конкретный commit
**после** этих prerequisites, а не как HEAD до них; роадмап Этап 0
сохраняет требование «baseline до изменений production-архитектуры», где
«изменения архитектуры» — Shadow/hybrid-контур, а не устранение
небезопасного fallback.

---

# 53. Архитектурное решение после v1

Результат эксперимента должен привести к одному из трёх решений.

## Вариант A — Agent не даёт преимущества

Сохранить:

```text
deterministic-first Izyan
```

LLM оставить Researcher/Reviewer.

## Вариант B — Agent лучше только в semantic reasoning

Передать Agent:

```text
CVE research
root cause
exploit model
planning
patch interpretation
```

Сохранить текущий deterministic analysis для claims.

## Вариант C — Agent заметно лучше как исследователь

Перейти к:

```text
Agent-first
+
typed evidence tools
+
small Verification Kernel
```

и постепенно удалить из deterministic contour семантическую логику, которую Agent выполняет лучше.

---

# 54. Главный ожидаемый результат

Первый этап не должен доказать:

> «LLM лучше статического анализа».

Он должен дать конкретный ответ:

> Какие части анализа vulnerability выгоднее поручить Agent, какие факты необходимо получать детерминированными инструментами и какой минимальный Verification Kernel нужен, чтобы автоматические safe-verdict оставались достаточно надёжными?

Именно после этого следует менять основную архитектуру Izyan.
# Roadmap: Agent-first анализ в Izyan

## Цель

Проверить и затем перейти к архитектуре:

```text
LLM Agent
   ↓
исследование vulnerability и продукта
   ↓
typed evidence tools
   ↓
structured claims
   ↓
Verification Kernel
   ↓
authoritative verdict
```

LLM отвечает за исследование и выбор направления анализа.

Детерминированный контур отвечает не за полное понимание программы, а за:

- фиксацию анализируемого snapshot;
- воспроизводимые факты;
- проверку области действия отрицательных утверждений;
- запрет небезопасных отрицательных выводов;
- вычисление итогового verdict.

---

# Этап 0. Зафиксировать baseline

До изменения production-архитектуры сохранить текущий Izyan как baseline.

Здесь «изменение production-архитектуры» — переход к Shadow/hybrid-контуру.
Общие исправления безопасности, не являющиеся benchmark-specific (например,
устранение подстановки `go.mod`/локального Go вместо неизвестного release
toolchain), обязаны быть сделаны **до** baseline и зафиксированы отдельным
commit с опубликованным diff: baseline A — конкретный commit после них, а не
HEAD до. Иначе baseline окажется определён на небезопасной семантике, и его
нельзя будет честно сравнивать с Shadow. Подробнее —
[план VEX-Bench adapter](../plans/2026-10-06-vexbench-adapter-plan.md) §2.2–2.3,
спека §52 п. 18.

Сравниваются четыре режима:

| Режим | Исследование | Verdict |
|---|---|---|
| A | текущий deterministic Izyan | deterministic |
| B | обычный coding agent | LLM |
| C | Izyan Agent + typed tools | LLM |
| D | Izyan Agent + typed tools | Verification Kernel |

Главная метрика:

```text
Safe Clear Rate при False-Safe = 0
```

Дополнительно:

```text
exploitability recall
justification accuracy
INCONCLUSIVE rate
human correction rate
повторяемость
стоимость
время анализа
```

Не считать собственные 38 кейсов независимым доказательством качества: они используются при развитии анализатора.

Добавить внешний eval-набор:

```text
VEX-Bench Go cases
+
новые внутренние кейсы, которые не использовались
при разработке анализатора
```

Результат этапа:

```text
eval/
  architecture-baseline.json
  architecture-results.json
```

---

# Этап 1. Shadow Analyzer Agent

Реализовать независимый LLM-анализ кейса.

Он получает:

```text
Vulnerability
ProductSnapshot
repository
typed tools
```

Но НЕ получает:

```text
текущий Verdict
готовые Claims
решения Negative Verification
готовый RootCauseModel текущего анализатора
```

Иначе сравнение будет загрязнено выводами deterministic-контура.

Agent самостоятельно должен:

```text
понять механизм vulnerability
↓
найти root cause
↓
сформировать exploit conditions
↓
исследовать продукт
↓
собрать evidence
↓
дать собственную оценку
```

Результат записывается отдельно:

```text
agent_assessment.json
```

Он никак не влияет на production verdict.

### Решение после этапа

Если Agent:

- заметно лучше разрешает сложные кейсы;
- сохраняет приемлемую стоимость;
- лучше объясняет root cause/conditions;

переходим к Agent-first.

Если нет — остаётся вспомогательным исследователем.

---

# Этап 2. Унифицировать Evidence Tools

Текущие AST/SSA/provenance механизмы перестать рассматривать как части единого «умного deterministic analyzer».

Каждый становится инструментом получения ограниченного факта.

Например:

```text
trace_argument
find_callers
find_references
find_validations
get_build_graph
run_govulncheck
inspect_config
scan_dynamic_dispatch
```

Tool response должен содержать:

```text
Observation
Scope
Completeness
Evidence
Limitations
```

Например:

```text
trace_argument:
  origin: HTTP_REQUEST
  scope: foo.Handler → yaml.Unmarshal
  completeness: PARTIAL
  limitations:
    - unresolved interface dispatch
```

Ключевой принцип:

```text
tool сказал "не найдено"
!=
доказано отсутствие
```

---

# Этап 3. Выделить Verification Kernel

Из существующего deterministic-контура выделить маленькое доверенное ядро.

Kernel должен отвечать только за:

### Snapshot

```text
repo
commit
dependency versions
GOOS
GOARCH
tags
CGO
vendor/workspace
```

### Evidence integrity

Каждое используемое утверждение должно иметь provenance и scope.

### Claim acceptance

LLM предлагает:

```text
Condition
Claim
EvidenceRefs
```

Kernel отвечает:

```text
ACCEPTED
REJECTED
INSUFFICIENT_SCOPE
UNSUPPORTED_RULE
```

### Negative claims

`FALSE` может участвовать в safe verdict только если существует поддерживаемое правило проверки.

Например:

```text
package-not-in-build
constant-input
validated-bound
config-disabled
function-unreachable-in-closed-scope
```

### Verdict

```text
affected == false
    → NOT_AFFECTED

all mandatory conditions == TRUE
    → EXPLOITABLE

exists verified mandatory FALSE
    → NO_EXPLOIT_PATH_FOUND

otherwise
    → INCONCLUSIVE
```

Kernel не должен интерпретировать LLM prose.

---

# Этап 4. Agent-first Hybrid

После validation этапов 1–3 поменять управление workflow.

Было:

```text
deterministic pipeline
   ↓
LLM помогает там, где сложно
```

Станет:

```text
Agent
   ↓
выбирает следующий вопрос
   ↓
вызывает Evidence Tool
   ↓
получает Observation
   ↓
обновляет гипотезу
   ↓
предлагает Claim
   ↓
Verification Kernel
```

Agent самостоятельно решает:

```text
какой patch исследовать
какой root cause вероятен
какие условия mandatory
какой caller посмотреть
какой аргумент трассировать
какую альтернативную гипотезу проверить
```

Kernel решает только:

```text
достаточно ли доказательств,
чтобы утверждение влияло на verdict
```

---

# Этап 5. Сокращение собственного static analyzer

Только после результатов hybrid-eval решить, какой код больше не нужен.

Кандидаты на упрощение:

```text
сложная семантическая классификация API
эвристический RootCause
универсальная классификация data origins
ручное моделирование framework semantics
часть knowledge.json
```

Не удалять:

```text
build graph
govulncheck adapter
AST/type queries
call/reference search
argument tracing
guard checks
dynamic markers
negative verification rules
```

То есть оставить хорошие измерительные инструменты, а не пытаться построить ещё один CodeQL.

---

# Этап 6. Deployment/runtime evidence

Отделить свойства исходного кода от свойств окружения.

Например:

```text
os.ReadFile(...)
```

не означает автоматически:

```text
trusted input
```

Вместо этого:

```text
Observation:
  input comes from file path X

DeploymentFact:
  path X writable only by trusted administrator

Claim:
  attacker_control = FALSE
```

`DeploymentFact` должен иметь собственный provenance:

```text
Kubernetes manifest
Helm values
runtime configuration
explicit operator input
policy
```

Без него:

```text
UNKNOWN
```

---

# Этап 7. Расширение за пределы Go

После отделения Agent от Verification Kernel языковая часть становится набором Evidence Providers:

```text
Go Provider
Java Provider
Python Provider
...
```

Общие части:

```text
Agent
ExploitModel
Evidence contract
Verification Kernel
Verdict
Report
```

Это позволит развивать Izyan как vulnerability-triage engine, а не как Go static analyzer.

---

# Что делать с существующим backlog

`B17 LLM advisory` заменить на Shadow Analyzer Agent.

`B32 proof validation` сохранить, но реализовывать уже как часть Verification Kernel.

`B16 LLM semantic hypotheses` естественно войдёт в Agent-first workflow.

`B15 patch interpretation` перенести в обязанности Agent + независимый Reviewer.

Оставшиеся задачи глубокого static analysis не делать автоматически приоритетными. Сначала проверить, нужен ли соответствующий код после появления Agent-first режима.

---

# Критерий архитектурного перехода

Production workflow переключается с deterministic-first на agent-first только если независимый eval показывает:

```text
False-Safe не хуже текущего контура

и

Safe Clear Rate выше

или

существенно меньше ручного triage
при сопоставимом качестве
```

До этого новый Agent работает только в shadow-режиме.
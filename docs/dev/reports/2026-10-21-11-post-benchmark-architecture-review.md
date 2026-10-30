# Диагностика третьей итерации и план merge/go-no-go

**Источник:** delegated `architect` artifact `agent://PostBenchArchReview` (2026-10-21), сохранён дословно.  
**Benchmarked code:** `consolidation/shadow-base` @ `c73151f`; master `e351e0f`; V2 `6bcce89`.  
**Вердикт:** `NO-GO` до P0 fixes; полный откат не нужен.  
**Входные артефакты:** `va-review1/bench/STATUS.md`, `REPORT.md`, `LLM-ANALYSIS.md`, `metrics.json`, `per-case.jsonl`; S-05 baseline; target/decisions.  

**Режим:** только чтение артефактов и исходников; тесты и бенчмарки повторно не запускались.

## Итоговое решение

**Merge третьей итерации в текущем виде — NO-GO.**  
Ветка должна быть **исправлена до merge**, но полный откат не нужен.

Рекомендуемое решение:

1. **Сохранить**:
   - исправление master-паники в `goanalysis`;
   - снижение `false-safe`;
   - fail-closed semantics;
   - Product B (`triage`, `research-b1`, heldout/replay/evaluation) как отдельный non-authoritative продукт;
   - защитные scope/sidecar/replay-механизмы.
2. **Исправить P0**:
   - multi-entry advisory/version resolver;
   - загрязнение результата неизвестной версией несвязанной advisory-entry;
   - release-evidence contract;
   - timeout/performance regression.
3. **Временно изолировать или частично откатить** V2 shipping-scope путь в стандартном `analyze`, если он не может сохранить master-паритет по времени и результатам. Это должен быть временный compatibility/performance gate, а не возврат к небезопасным safe-negative.
4. **Не откатывать** fail-closed изменение case-10 только ради восстановления одной safe-closure: это целевое усиление safety, хотя и измеренная coverage-регрессия.

---

## 1. Что планировалось и что реально измерено

### Целевая архитектура

В target-документе зафиксирован dual-product:

| Продукт | Назначение | Authority |
|---|---|---|
| Product A, Shadow-based | applicability, affectedness, implementation axis, evidence, negative verification, terminal verdict, VEX | Единственный authoritative security verdict |
| Product B, V2-based | LLM research, triage, proposal, prioritization, heldout/evaluation, CI policy | Не имеет права менять Product A verdict |

Главное правило target:

> LLM may propose; deterministic contracts decide.

Ожидался следующий эффект:

- сохранить или повысить detection и closure относительно master;
- убрать false-safe;
- сохранить `false-safe=0`;
- добавить V2 `ImportClosure`, shipping-scope и `VerifyUnreachable`;
- добавить V2 research/triage/evaluation shell;
- не смешать второй verdict/evidence contract с Shadow.

### Что реально измерено

Бенчмарк из `STATUS.md`/`REPORT.md` запускал:

```text
izyan analyze
```

для master и branch с одинаковыми входами и флагами.

Измерялся прежде всего **Product A deterministic pipeline**:

- `internal/affected`;
- `internal/evaluator`;
- `internal/goanalysis`;
- Shadow evidence/report/VEX;
- в LLM-режиме — тот же `analyze` pipeline с дополнительными LLM proposals.

Не измерялись как отдельные продукты:

- `izyan triage`;
- `izyan research-b1`;
- Product B heldout gate;
- Product B decision/replay lane;
- V2 plain-agent research;
- полноценный V2 LLM-first triage на rejected corpus.

Следовательно, результат `analyze --cve-analysis verified` нельзя интерпретировать как бенчмарк V2 triage/research продукта.

---

## 2. Что доказано результатами

### Deterministic comparison — PROVEN

Для одного и того же harness:

- branch: `c73151f`;
- master: `e351e0f`;
- 83 кейса × 2;
- одинаковые snapshots/advisories/flags;
- timeout 900 секунд;
- 2 workers.

Branch получил **−7.5 case-equivalents** относительно master.

#### Corporate confirmed

| Метрика | master | branch | Изменение |
|---|---:|---:|---:|
| `EXPLOITABLE` | 6/35 | 0/35 | **−6 TP** |
| false-safe | 2 | 0 | +2 safety |
| `INCONCLUSIVE` | 25 | 32 | +7 |
| timeout | 0 | 3 | −3 завершённых ответа |

#### Corporate rejected

| Метрика | master | branch |
|---|---:|---:|
| safe closure | 16/18 | 12/18 |
| inconclusive | 2 | 4 |
| timeout | 0 | 2 |

#### VEX

| Метрика | master | branch |
|---|---:|---:|
| correct exploitable | 1/7 | 1/7 |
| false-safe | 2/7 | 1/7 |
| safe-clear | 10/23 | 9/23 |
| completion | 25/30 | 25/30 |
| failed/timeout | 5 | 5 |

Branch лучше по safety на VEX, но не лучше по recall и хуже по safe-clear.

### Safety improvements — PROVEN

Branch:

- устранил три master nil-pointer panic;
- убрал master `failed_parse` на соответствующих случаях;
- снизил false-safe в VEX и corporate confirmed;
- сохранил `false-safe=0` на сохранённом Shadow corpus gate.

Это реальные улучшения и их следует сохранить.

### S-05/kernel baseline — LIMITED, но важный

`2026-10-21-09-s05-baseline.md` показывает:

- Shadow corpus: `38/38`, `false-safe=0`;
- R6 guard: pass;
- census: branch-induced case-10 regression;
- case-10 стал `INCONCLUSIVE` вместо `NO_EXPLOIT_PATH_FOUND` из-за V2 fail-closed foreign-importer semantics.

Это не противоречит сравнению с master:

- S-05 доказывает safety baseline для другого корпуса/harness;
- benchmark `REPORT.md` доказывает branch-vs-master regression на 83-кейсном корпусе;
- ни один из этих артефактов не доказывает, что branch лучше master как общий analyzer.

---

## 3. Основная причинная цепочка

## 3.1. P0 implementation bug: multi-entry advisory загрязняет version applicability

### Наблюдение — PROVEN

В branch-отчётах для потерянных TP присутствуют одновременно:

```text
affected_modules:
  module: ""
  affected_packages: google.golang.org/grpc/...

  module: google.golang.org/grpc
```

Например, для `CASE-543786`:

```text
resolved module version: ""
version_affected: UNKNOWN
selected_modules: [""]
pending_modules: [""]
unresolved_modules: [""]
version_affected_modules: ["google.golang.org/grpc"]
```

При этом:

- `vendor/modules.txt` содержит точную версию;
- отчет фиксирует `google.golang.org/grpc@v1.82.1`;
- master на том же snapshot получил `resolved_version=v1.82.1`, `version_affected=TRUE`, `EXPLOITABLE`.

То есть branch не просто не получил release-toolchain evidence. Он потерял уже известную версию связанного Go-модуля.

### Кодовый механизм — INFERENCE, хорошо подтверждённый source inspection

В branch:

1. OSV parser сохраняет несколько affected entries.
2. Пустая module name попадает в `AffectedModules`.
3. `isStdlibModule("")` классифицирует пустую строку как dotless stdlib-like module.
4. Для этой entry создаётся pending/unknown version.
5. `resolvePackages` объединяет package subjects нескольких entries.
6. `pathOwner[p.Path] = e` может связать один и тот же package path с последней, пустой entry.
7. `VersionAffected` становится `UNKNOWN`.
8. `VerdictEvaluator` явно блокирует verdict:

```text
ModulePresent == TRUE &&
VersionAffected == UNKNOWN
→ INCONCLUSIVE
```

Это соответствует branch reports и объясняет:

- почему точный grpc/amqp version фактически не используется;
- почему все шесть master TP превращаются в `INCONCLUSIVE`;
- почему LLM не может их восстановить.

### Что здесь ошибочно архитектурно

Не сама политика “unknown applicability → inconclusive”. Она правильна и должна остаться.

Ошибочно:

- глобализировать неизвестность одной advisory-entry на все entries;
- смешивать package subjects альтернативных модулей;
- позволять пустой/невалидной entry стать stdlib entry;
- не хранить applicability per advisory entry/module.

### Исправление

Нужно:

1. Отбрасывать malformed/empty package entries на этапе OSV normalization либо переводить их в явный `UNSUPPORTED`, но не в stdlib.
2. `isStdlibModule` должен распознавать только известные псевдомодули (`std`, `stdlib`, `toolchain`, `cmd`), но не произвольную пустую или любую dotless строку.
3. Хранить applicability отдельно для каждой entry.
4. Не позволять unknown unlinked alternative блокировать linked module с известной версией.
5. Не объединять package subjects разных module owners в один `pathOwner`.
6. Добавить regression fixture именно на advisory с:
   - stdlib/empty entry;
   - third-party module entry;
   - общим набором symbols/packages.

### Атрибуция

| Наблюдение | Статус |
|---|---|
| Все 6 потерянных corporate TP имеют branch version-unknown gate | **PROVEN** |
| Exact versions есть в module/vendor evidence | **PROVEN** |
| Глобальный evaluator превращает unknown version в INCONCLUSIVE | **PROVEN** |
| Empty-entry/path-owner interaction — непосредственный механизм | **INFERENCE**, подтверждается branch JSON и source structure |
| `--release-go-version` сам по себе исправит все 6 TP | **UNPROVEN** |

`--release-go-version` следует использовать как диагностический эксперимент, но не считать исправлением. Для third-party module applicability точная module version уже была в snapshot. Правильный fix — корректная per-entry resolution.

---

## 3.2. Design bug: V2 scope kernel попал в critical path Product A без доказанного parity/performance gate

### Что изменилось

Branch содержит существенно более широкий scope kernel:

- shipping roots;
- LIVE/DEAD/UNKNOWN classification;
- importer closure;
- skipped-package accounting;
- function-value/open may-call semantics;
- interface dispatch;
- dynamic-marker relevance;
- dependency module cones;
- additional closure and provenance work.

В исходном Shadow master таких компонентов в текущей форме не было.

### Архитектурная ошибка

Target действительно планировал перенести scope kernel в Shadow, но порядок требовал:

```text
ImportClosure
→ verify_code_absence
→ shipping-scope filter
→ dynamic relevance
→ adversarial fixtures
→ corporate matrix
```

А Product B должен был оставаться отдельным adapter/research продуктом.

В benchmark branch этот код оказался частью обычного `analyze`, поэтому merge не дал additive benefit. Он изменил:

- semantic closure;
- количество `INCONCLUSIVE`;
- количество выполняемых source/closure операций;
- runtime и timeout profile.

Это не обязательно “неправильная” safety semantics. Это неправильная интеграция без доказанного:

- kernel parity;
- Product A performance budget;
- per-case timeout behavior;
- preservation of master closure.

### Доказанные последствия

- case-10: намеренная fail-closed coverage regression;
- case-01: master safe closure → branch `INCONCLUSIVE` при уже разрешённой affected version;
- branch потерял 4 rejected safe closures;
- branch добавил корпоративные timeouts;
- VEX safe-clear снизился с 10 до 9.

Точная доля, вызванная именно shipping-scope kernel, отдельно не изолирована и поэтому является **UNPROVEN**. Но связь с broad closure — **CLAIMED/INFERENCE**, подтверждаемая source inventory, S-05 и branch timing/limitation artifacts.

---

## 3.3. Performance regression: частично implementation, частично design

### Доказано

В corporate deterministic corpus:

- master: 2 panic/no-answer;
- branch: 5 timeout/no-answer.

В подтверждённых corporate cases branch имеет 3 timeout, master — 0.  
В rejected cases branch имеет 2 timeout, master — 0.

В VEX обе стороны имеют по 5 failures, но branch меняет часть master-completing cases в timeout:

- `kubernetes-kubernetes-1ee2acb-CVE-2024-24786`;
- `kubernetes-kubernetes-6d4b94f-CVE-2022-41717`.

Branch иногда быстрее на простых кейсах, например:

- `CASE-553930`: примерно 114 с → 30 с;
- `CASE-257609`: примерно 217 с → 28 с.

Но на других случаях branch заметно медленнее:

- `CASE-270453`: примерно 37 с → 242 с;
- `CASE-257608`: примерно 379 с → 472 с.

Следовательно, это не просто “branch всегда медленнее”. Это **расширение work surface с плохим tail latency**.

### Что пока не доказано

Не доказано, какая именно операция занимает основное время:

- importer closure;
- dynamic scan;
- dependency cone;
- repeated package loading;
- evidence collection;
- cache eviction;
- interaction с memory budget.

Нельзя объявлять одну из них установленной причиной без отдельного profiling artifact.

### P0 исправление

Нужно:

1. Разделить cheap applicability path и expensive closure path.
2. Кэшировать snapshot/module/package closure между advisory entries.
3. Перенести heavy shipping-scope proof в bounded stage с явным budget.
4. Не повторять полный closure для каждого symbol без reuse.
5. Сохранять timeout как `INCONCLUSIVE`, но не допускать превращения master-completing cases в timeout.
6. Если parity/performance не достигается — временно отключить новый heavy path в default Product A и оставить его явно gated/research-only.

Нельзя решать проблему простым увеличением timeout: это скроет tail-latency defect и не даст продуктовой гарантии.

---

## 3.4. LLM-режим не компенсирует deterministic regression

### Кодовый факт — PROVEN

В `internal/states/cveanalysis.go` профиль `verified` после semantic review только разрешает:

```text
AcceptLocusProposals = true
```

Финальный verdict остаётся в `internal/evaluator/verdict.go`.

То есть:

```text
LLM proposal → deterministic evaluator → terminal verdict
```

LLM не может:

- исправить `VersionAffected=UNKNOWN`;
- создать authoritative evidence;
- заменить `INCONCLUSIVE` на `EXPLOITABLE`;
- заменить `INCONCLUSIVE` на safe-negative.

### Результаты — PROVEN

VEX LLM 30×2:

- branch TP: 1/7;
- master TP: 0/7;
- новых `EXPLOITABLE` на 60 запусках: 0;
- изменились только 6/60 запусков.

Confirmed LLM, 29 общих кейсов:

| | master | branch |
|---|---:|---:|
| TP | 3 | 0 |
| false-safe | 3 | 1 |
| inconclusive | 21 | 27 |

Branch version gate блокирует шесть deterministic TP ещё до того, как proposal может что-либо изменить.

### Ошибка интерпретации

V2 plain-agent `7/7` — это measurement:

```text
LLM отвечает на вопрос напрямую
```

А `analyze --cve-analysis verified` измеряет:

```text
LLM предлагает, deterministic analyzer принимает только доказанное
```

Это разные продукты и разные метрики. Сравнение `7/7` с `1/7` pipeline recall — methodology artifact, а не доказательство, что merge “сломал модель”.

---

## 4. Что было реально портировано, но не участвовало в benchmark value

### Было построено/скомпилировано — PROVEN по source/report artifacts

В branch появились или были адаптированы:

- `internal/productb`;
- Product B triage schemas;
- proposal-only ingress;
- FactGate;
- observation archive;
- decision package/policy;
- replay/stability;
- heldout tooling;
- `izyan triage`;
- `research-b1`;
- `refindex`;
- `reportcheck`;
- Product B boundary/import guards.

Сохранённые reports перечисляют unit/E2E/build checks, включая:

- proposal authority-field rejection;
- foreign/cross-run rejection;
- replay fail-closed;
- kernel parity fixtures;
- synthetic triage E2E;
- Product B import boundary.

### Не доказана продуктовая польза — UNPROVEN

Эти компоненты не были сопоставимо измерены на benchmark corpus:

- `izyan triage` против master;
- `research-b1` против V2 plain-agent;
- rejected LLM triage;
- positive-class recall Product B;
- analyst-hours/manual-review reduction;
- production admission.

Поэтому их наличие в branch нельзя засчитывать как улучшение `analyze`.

### Ownership conclusion

Product B следует оставить:

```text
internal/productb/**
izyan triage
izyan research-b1
heldout/evaluation/replay
```

Но:

- не импортировать его domain/evaluator как Product A authority;
- не считать `DecisionPackage` terminal security verdict;
- не включать semantic dismissal по умолчанию;
- не использовать compile/test success как доказательство benchmark value.

---

## 5. S-01 и S-14

## S-01 — сохранить как P0 prerequisite

S-01 отвечает за:

- `AnalysisCase`;
- advisory/ticket identity;
- source/artifact/build/target binding;
- migration/refusal;
- foreign/cross-run rejection;
- canonical case bundle.

Текущий benchmark использовал harness-level identity shim и snapshots без `.git`; это не заменяет полноценный S-01 production contract.

До merge должны быть явно проверены:

1. exact advisory identity;
2. package/version identity;
3. source content/commit identity;
4. artifact/build-info identity;
5. target/toolchain identity;
6. release-evidence trust class;
7. old persisted case migration/refusal;
8. no adapter path that widens identity.

S-01 не нужно откладывать ради Product B. Наоборот, Product B adapters должны зависеть от S-01, а не создавать собственную identity model.

## S-14 — не превращать в “снизить INCONCLUSIVE”

S-14 должен оставаться case-specific, owner-gated backlog:

| Cases | Правильный scope |
|---|---|
| 03 | отдельная declared-symbol closure capability или durable `INCONCLUSIVE` |
| 07/08 | реальный IBM MQ SDK (`cmqc.h`, headers/libraries); syntax-only stub не принимается |
| 01/02/17/18 | positive attacker-input/control capability; static reachability недостаточна |
| 15/16 | retained advisory-bound proposal + independently verified falsifier |

Для каждого case требуется выбрать:

- verified closure path;
- durable `INCONCLUSIVE`;
- exact external input;
- owner;
- stop condition.

Нельзя включать S-14 в merge gate как требование “закрыть все оставшиеся cases”. Но нельзя и использовать незакрытые cases как аргумент для ослабления safety.

---

## 6. Приоритетный план

## P0-A. Исправить multi-entry applicability

**Работы:**

1. Ввести fixture на реальный multi-entry advisory.
2. Запретить пустой module entry.
3. Разделить stdlib applicability и third-party module applicability.
4. Сделать unknown per-entry, а не глобальным.
5. Исправить package-owner mapping.
6. Добавить test на:
   - известный linked module + unknown unlinked stdlib;
   - два linked module entries;
   - empty/malformed entry;
   - duplicate package path across entries.

**Acceptance:**

- grpc/amqp exact module versions остаются resolvable;
- branch не получает `resolved module version is unknown` при наличии точной vendor/module evidence;
- six lost TP cases больше не деградируют только из-за unrelated unknown entry;
- `false-safe=0` сохраняется.

## P0-B. Зафиксировать release-evidence contract

**Работы:**

1. Для stdlib advisory benchmark manifest должен передавать:
   - `--release-go-version`, либо
   - authoritative release binary/artifact.
2. Если evidence нет, stdlib applicability остаётся `UNKNOWN`.
3. Unknown stdlib entry не должна блокировать независимую third-party module entry.
4. `go.mod` и analysis toolchain не должны использоваться как release truth.
5. В report явно различать:
   - source module version;
   - release toolchain version;
   - supporting vs authoritative evidence.

**Acceptance:**

- нет молчаливого fallback;
- per-entry result объясняет, какая именно entry unresolved;
- release evidence входит в baseline manifest.

## P0-C. Устранить tail-latency regression

**Работы:**

1. Сохранить state timings уже записанных reports как диагностическую базу.
2. Определить, какие closure stages добавлены branch.
3. Добавить bounded/cached execution.
4. Разделить applicability и heavy negative proof.
5. Сохранить open/partial semantics при budget exhaustion.
6. Если default Product A не укладывается в budget — временно gate heavy scope path, не ослабляя verdict safety.

**Acceptance:**

- ни один case, завершившийся master под 900 с, не становится branch timeout;
- branch-specific corporate timeouts устранены;
- нет новых panic;
- timeout не превращается в safe-negative;
- completion не ниже master на matched corpus.

## P0-D. Сохранить safety fixes

Нельзя откатывать:

- nil AST panic fix;
- strict unknown applicability semantics;
- sidecar/replay fail-closed;
- open may-call/interface/dynamic marker semantics;
- case-10 fail-closed outcome без доказательства foreign-importer closure.

---

## P1. Measurement plan

### P1.1. Re-pin deterministic baseline

Сохранить один canonical comparison:

- master `e351e0f`;
- branch post-fix;
- same frozen OSV;
- same 83 cases;
- same timeout/worker/memory settings;
- same artifacts and hashes.

Metrics:

- corporate confirmed TP/FS/INCONCLUSIVE/timeouts;
- corporate rejected safe closure/timeouts;
- VEX TP/FS/SCR/completion;
- per-state timings;
- per-cause timeout taxonomy.

### P1.2. Отдельно измерить Product B

Не смешивать с `analyze`.

Минимальные arms:

1. Product A deterministic `analyze`;
2. `analyze --cve-analysis verified`;
3. `izyan triage`;
4. `research-b1`/research lane;
5. plain-agent research, если сравнение с V2 заявляется.

Для каждого:

- completion;
- TP/FS только на corpus с соответствующей ground truth;
- `INCONCLUSIVE`/`UNCHANGED`;
- verified proof count;
- model calls;
- stability;
- replay;
- manual-review workload;
- policy output отдельно от security verdict.

### P1.3. Запустить rejected LLM measurement

`STATUS.md` прямо фиксирует, что LLM rejected corpus не запускался.

Без него нельзя утверждать, что LLM/triage shell повышает closure value: основная работа по снятию негативов находится именно там.

### P1.4. Отдельно маркировать Baseline A

Baseline A:

- другой commit;
- другой harness;
- live OSV;
- 7200 секунд;
- 3 workers;
- другой execution profile.

Он пригоден как historical context, но не как apples-to-apples merge gate.

---

## P2. Documentation/ownership

После P0/P1:

1. Обновить target status:
   - benchmarked;
   - built but not exercised;
   - proven;
   - claimed;
   - unproven.
2. Зафиксировать S-01 schema/migration evidence.
3. Сохранить S-14 case contracts и external prerequisites.
4. Удалить/пометить stale claims о том, что Product B улучшает `analyze`.
5. Оставить один canonical authority/ownership matrix.
6. В CI разделить:
   - Product A safety/regression gates;
   - Product B boundary/replay gates;
   - Product B admission/heldout gates.

---

## 7. Merge go/no-go

### NO-GO сейчас

Branch нельзя merge без исправления, потому что:

- `0/35` confirmed TP против `6/35` master;
- rejected closure `12/18` против `16/18`;
- branch имеет дополнительные timeouts;
- Product B value в этом benchmark не измерена;
- target implementation status всё ещё содержит unproven integrated port gates.

### Минимальные условия GO

#### Product A deterministic

1. `false-safe=0` на pinned safety corpus.
2. Corporate confirmed TP не ниже master: **не менее 6/35**.
3. Corporate rejected safe closure не ниже master: **не менее 16/18**, либо каждое отличие имеет approved durable-`INCONCLUSIVE` explanation.
4. VEX:
   - TP не ниже `1/7`;
   - safe-clear не ниже `10/23`;
   - completion не ниже `25/30`;
   - false-safe не увеличивается.
5. Ни один master-completing case не становится branch timeout.
6. Нет новых panic.
7. Unknown applicability остаётся `INCONCLUSIVE`, но не распространяется на unrelated linked entries.

#### Product B

1. `internal/productb` не импортирует Product A verdict/evidence authority как второй contract.
2. Proposal-only ingress остаётся enforced.
3. Foreign/cross-run/tampered artifacts fail closed.
4. Offline replay не требует LLM/network.
5. Semantic dismissal остаётся default-off до:
   - positive holdout;
   - measured recall;
   - eligible admissions;
   - mutation/cross-run gates.
6. Product B results не меняют Product A `VerdictResult`/VEX.

#### Ownership

1. S-01 identity contract принят и проверен.
2. S-03/S-04 kernel parity и scope safety gates сохранены.
3. S-14 по каждому открытому case имеет closure path или durable `INCONCLUSIVE`.
4. Release-evidence inputs и benchmark manifest pinned.

---

## Финальный вывод

Третья итерация стала хуже не потому, что сама идея объединения Shadow и V2 неверна. Она хуже потому, что в одну критическую `analyze`-цепочку одновременно попали:

1. **ошибка реализации multi-entry resolver**, превратившая известные module versions в `UNKNOWN`;
2. **глобальный strict evaluator**, который честно заблокировал verdict после этой ошибки;
3. **более широкий V2 scope kernel**, изменивший closure semantics и tail latency;
4. **неразделённые measurement lanes**, из-за чего Product B research value была принята за улучшение Product A analyzer;
5. **benchmark artifacts**, которые не позволяют напрямую сравнивать Baseline A, plain-agent и `analyze`.

Правильная стратегия:

```text
Shadow Product A authority
    + исправленный per-entry applicability/resolver
    + bounded shipping-scope kernel
    + сохранённый fail-closed safety

V2 Product B
    → отдельный triage/research/evaluation/replay продукт
    → default-off semantic admission
    → измеряется отдельным benchmark lane
```

**Итоговый статус: CONDITIONAL / NO-GO до P0 fixes.**
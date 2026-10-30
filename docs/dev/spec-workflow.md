# От тезиса roadmap до проверенной реализации

**Источник:** delegated `architect` artifact `agent://SpecWorkflowAndS01` (2026-10-21), документ 1; сохранён.
**Статус:** `draft` — инструкция для ревью и утверждения.  
**Область:** спецификации консолидации Shadow/V2 из target roadmap.  
**Target:** [`2026-10-20-target-architecture-and-roadmap.md`](roadmaps/2026-10-20-target-architecture-and-roadmap.md), далее — **Target**.

## 1. Решение

Тезис в roadmap — **заявка на разработку спецификации**, а не разрешение писать код.

Для каждой S-XX применяется цикл:

```text
выбор scope и входов
  → draft spec
  → self-check
  → independent review
  → повторное сравнение с goals и target
  → approval
  → implementation plan
  → review плана против spec
  → implementation
  → tests и сохранение evidence
  → post-implementation review
  → verification
```

Для S-XX из текущего backlog отдельный implementation plan обязателен: изменения затрагивают персистентные контракты, интеграционные границы или safety gates.

**План не исправляет недоработанную спецификацию.** Если неизвестны семантика, обязательность полей, переходы состояний, failure behavior или миграция, сначала исправляется spec. План раскрывает уже согласованное решение до файлов, последовательности изменений и проверок.

Нельзя:

- реализовывать непосредственно по строке roadmap;
- переносить нерешённые design decisions в задачи «разобраться при реализации»;
- считать компиляцию доказательством сохранения семантики;
- закрывать product gap косметическим изменением статуса;
- создавать второй identity/evidence/Claim/NV/verdict contract;
- превращать отсутствие evidence, incomplete scope или technical failure в safe-negative.

## 1a. Fast path для текущей консолидации

Для merge Shadow/V2 полный spec/review-цикл применяется только при изменении authority, security boundary, публичного контракта или схемы данных. Остальные компоненты идут по упрощённому автономному пути:

```text
branch → dependency order → port/adapt → build + targeted tests
→ baseline после kernel → reviewer проверяет финальный diff/evidence
```

- Источник scope — Target §14.6; порядок — §14.7 DAG.
- Отдельная spec/plan на каждый компонент не нужна, если контракт уже определён Target §14.
- Implementer выбирает консервативное решение, фиксирует отклонение и продолжает; останавливается только при изменении authority/security/public contract или риске потери данных.
- Acceptance: `go build ./...`, targeted tests, baseline corpus/census после kernel, отсутствие второго verdict/evidence contract.
- Финальный reviewer смотрит diff и evidence, а не каждый промежуточный шаг.

## 2. Роли и ответственность

| Роль | Ответственность | Ограничения |
|---|---|---|
| **Architect** | Разрабатывает spec; фиксирует требования, контракты, состояния, отказы, migration и traceability; закрывает design unknowns | Не утверждает собственную spec вместо owner; не маскирует изменение target локальным решением |
| **Independent reviewer** | Независимо проверяет spec и implementation plan; ищет контрпримеры; проверяет полноту acceptance gates | Автор не является независимым reviewer своего документа |
| **Implementer** | После approval составляет план; реализует согласованный контракт; обновляет затронутые callers/tests/docs; собирает evidence | Не меняет authority boundary, контракт или failure semantics без возврата к architect |
| **Security reviewer** | Проверяет trust boundaries, non-admission, negative controls, миграцию доверия и безопасность replay | Его участие обязательно при условиях ниже |
| **Contract owner / approval owner** | Принимает контракт и совместимость; назначает исполнителя и reviewers; утверждает spec, план и результат | Approval не заменяет independent review и evidence |
| **Verification owner** | Проверяет итоговую реализацию и evidence на согласованной ревизии; разрешает `verified` | Не принимает самоотчёт «всё работает» без артефактов |

До `approved` в review record указываются **конкретные участники**, а не только названия ролей. Пока owner не назначен, документ может оставаться `draft`, но не получает approval.

Security review обязателен, если меняются:

- identity, advisory/ticket/source/artifact/build binding;
- EvidenceGraph, Claim, NegativeVerification, verdict или admission;
- sidecars, hashes, provenance, replay или межпродуктовые ссылки;
- доверие к deployment assumptions;
- доступ инструмента к файлам, сети, исполнению кода или секретам;
- миграция, способная повысить доверие к старым данным;
- VEX, policy/recommendation boundary или failure semantics.

**Для S-01 security review обязателен.**

## 3. Статусы и гейты

Статус относится к **конкретной ревизии** документа и реализации.

| Статус | Условие входа / необходимый результат | Кто переводит | Что запрещено |
|---|---|---|---|
| `draft` | Scope и входы определены; ведётся разработка контракта; неизвестные явно перечислены | Architect | Production implementation; использование draft как утверждённого контракта |
| `reviewed` | Independent review завершён; замечания закрыты; подтверждены spec DoR и goal/architecture comparison | Independent reviewer фиксирует заключение; architect обновляет документ | Код; пропуск owner approval |
| `approved` | Owner утвердил точную ревизию; security review пройден, если обязателен | Contract owner | Код до reviewed/approved implementation plan; самостоятельное изменение контракта исполнителем |
| `planned` | План соответствует утверждённой spec; plan DoR выполнен; план отревьюен и утверждён; prerequisites разрешают начало работ | Owner после заключения reviewer | Работы вне плана/spec; обход отсутствующего upstream/phase gate |
| `implemented` | Согласованные изменения, callers, tests и docs завершены; доступен implementation report | Implementer фиксирует завершение, owner принимает к проверке | Объявлять результат проверенным или включать gated capability без verification |
| `verified` | Implementation DoD выполнен; сохранены результаты acceptance gates и post-implementation review | Verification owner и contract owner; security sign-off при необходимости | Распространять доказанность за пределы проверенной конфигурации/корпуса |

Найденное замечание не обходится сменой статуса:

- блокирующее замечание к spec возвращает её в `draft`;
- изменение утверждённого контракта инвалидирует approval и соответствующую часть плана;
- чисто механическое уточнение плана проходит повторное review затронутых задач;
- неуспешный acceptance gate оставляет реализацию не выше `implemented`;
- неподтверждённое измерение не становится `PROVEN` после approval.

Для каждой смены статуса сохраняются: дата, участник, ревизия spec/plan/code, основание и ссылки на review/evidence.

## 4. Где брать цели и входы

### 4.1. Обязательный порядок чтения

| Порядок | Источник | Что из него извлекать |
|---:|---|---|
| 1 | [`docs/goals-scope.md`](../goals-scope.md) | Продуктовая цель, вопрос пользователя, safety-критерии, ограничения scope |
| 2 | Target §§1, 2, 13, 14 | Target invariants, dual-product topology, authority, canonical contracts, failure semantics |
| 3 | Target §14.6; затем §13.7 и непротиворечивые части §7 | Scope S-XX, зависимости, phase, owner, DoD и input map |
| 4 | Reports [04](reports/2026-10-20-04-cross-solution-decision.md), [05](reports/2026-10-20-05-independent-verification.md), [06](reports/2026-10-20-06-approach-decision.md) | Причины решений, отвергнутые варианты, ограничения измерений |
| 5 | [Port integrity review 07](reports/2026-10-20-07-port-integrity-review.md) и Target §14 | Найденные пропуски и их disposition; прежние findings читать вместе с исправлениями §14 |
| 6 | `governing-spec.md`, ADRs, `architecture.md`, `analysis-internals.md`, `implementation-status.md`, `gap-analysis.md` | Current state, provenance, существующие соглашения, необходимый нормативный delta |
| 7 | Pinned source paths, тесты и конфигурация из input map | Exact API, JSON tags, реальные callers, storage/load behavior, существующие fixtures |
| 8 | Сохранённые baseline/CI artifacts | Что действительно измерено, на каких входах, ревизиях и ограничениях |

### 4.2. Разрешение противоречий

Это не одна линейка приоритета для всех вопросов:

- **Зачем нужен продукт:** `goals-scope.md`.
- **Какая target-семантика должна быть реализована:** Target; §14 уточняет и при конфликте заменяет более ранние разделы, §13 уточняет §§1–12.
- **Что сейчас реализовано:** source/tests/configuration, а не устаревший status report.
- **Что доказано исполнением:** сохранённый результат проверки с provenance.
- **Каковы точные согласованные детали реализации:** approved S-XX.

Current Product A/V2 docs **не являются primary source target-контракта**. Их старые ограничения нельзя молча восстановить вместо Target.

Одновременно нельзя игнорировать действующие repo rules: противоречие между ними и новым контрактом фиксируется в normative delta и устраняется owner до implementation. Для текущего перехода обязательна матрица Target §13.6 — **G-26**.

В частности, правила старого additive JSON compatibility и новый versioned migration/refusal должны быть согласованы явно, а не обойдены изменением `omitempty`.

### 4.3. Минимальная запись входа

Для каждого существенного входа:

```text
path / section / symbol
source role: goal | target | decision | current-state | implementation | evidence
revision / digest, если применимо
какое требование или решение из него следует
PROVEN | CLAIMED | UNPROVEN
```

Refs Shadow `118e10c` и V2 `6bcce89` — integration anchors из Target. Исполнитель отдельно фиксирует фактические refs/hashes исследуемого дерева; совпадение не предполагается.

## 5. Процесс для каждой S-XX

### Шаг 1. Выбрать единицу работы

Взять строку **§14.6**, а не старый заголовок из §7.

Зафиксировать:

- S-XX, phase, scope/non-goals;
- upstream contracts и их ревизии;
- какие зависимости нужны для разработки spec, а какие — для implementation/verification;
- owner и reviewers;
- expected deliverables и phase gates.

Если upstream contract ещё меняется, можно исследовать и готовить draft. Нельзя утверждать зависимый контракт на незафиксированных предположениях.

### Шаг 2. Собрать требования и ограничения

Прочитать источники в порядке §4. Создать требования `SXX-R01…`.

Для каждого требования записать:

```text
source → requirement → contract/flow → acceptance criterion → test/command → artifact
```

Отдельно выписать:

- safety invariants;
- current→target delta;
- неизвестные P0/P1/P2;
- конфликтующие документы/API;
- запрещённые упрощения.

### Шаг 3. Написать spec

Использовать шаблон §7.

Спецификация должна отвечать не только «что добавить», но и:

- кто владеет полем/состоянием;
- когда оно фиксируется;
- кто вправе его менять;
- как различаются missing, unknown, malformed и contradictory;
- что сохраняется при отказе;
- как выполняется replay;
- что происходит со старыми данными;
- какой отрицательный тест опровергнет предполагаемую безопасность.

### Шаг 4. Выполнить self-check

Architect проверяет:

1. Каждое требование вытекает из goals/Target либо обозначено как предлагаемая implementation-spec detail.
2. Нет скрытого расширения scope.
3. Нет второго canonical contract.
4. Ничто не повышает authority LLM/proposal/assessment.
5. Все состояния и отказы имеют наблюдаемый результат.
6. Acceptance criteria покрывают happy path и отрицательные случаи.
7. Нет открытого решения, которое implementer будет вынужден угадывать.

Результат — заполненный self-check и реестр неизвестных, не смена статуса на `reviewed`.

### Шаг 5. Провести independent review

Reviewer получает:

- spec;
- exact upstream revisions;
- current-state/source inventory;
- traceability matrix;
- acceptance/test matrix;
- unknowns и найденные противоречия.

Reviewer возвращает:

```text
PASS | CHANGES_REQUIRED
findings: severity, requirement, source, counterexample, required correction
```

Review сохраняется в `docs/dev/reports/` либо в review record spec. Review другого агента считается независимым только при отдельном исследовании, а не при пересказе self-check автора.

### Шаг 6. Повторить goal/architecture comparison

После исправлений повторно проверить **итоговую**, а не исходную spec:

| Проверка | Обязательный результат |
|---|---|
| Requirements traceability | Нет требований без основания; нет потерянного требования Target |
| Authority/ownership | У каждого authoritative field ровно один canonical owner |
| No second contract | Нет параллельной модели identity/evidence/Claim/NV/verdict |
| Failure semantics | Missing/partial/error/refusal не превращаются в safe-negative |
| Replay | Нет скрытой зависимости от LLM, сети или mutable external state |
| Security | Проверены foreign/cross-run/stale/tamper и повышение доверия при migration |
| Scope | Не решаются соседние capabilities без отдельного основания |

После PASS reviewer фиксирует `reviewed`; owner утверждает точную ревизию — `approved`.

### Шаг 7. Проверить plan-readiness

Если spec не проходит DoR — вернуть architect. **Код и implementation plan запрещены до устранения design-блокеров.**

Если контракт определён, но реализация требует декомпозиции — implementer составляет отдельный plan:

- без новых семантических решений;
- с mapping каждого requirement на задачи;
- с exact file paths, sequencing, tests, rollback и evidence gates.

### Шаг 8. Отревьюить план против spec

Reviewer проверяет в обе стороны:

- каждое требование spec покрыто задачей и проверкой;
- каждая задача плана имеет основание в spec;
- нет новой authority, fallback, compatibility shim или failure semantics;
- порядок не использует consumer раньше producer;
- tests проверяют поведение, а не только форму/компиляцию;
- rollback не возвращает старые данные в новый доверенный путь.

После PASS и owner approval — `planned`.

### Шаг 9. Реализовать согласованный план

Implementer:

- переиспользует существующие canonical types и patterns;
- мигрирует все затронутые callers;
- удаляет ставшие obsolete пути, кроме явно утверждённых legacy/replay-only readers;
- добавляет regression tests и fixtures;
- фиксирует отклонения;
- обновляет документацию и backlog по repo rules.

При изменении контракта работа останавливается по §11.

### Шаг 10. Выполнить acceptance/evidence gates

Проверки запускаются по утверждённому плану. Финальные интеграционные проверки выполняет один назначенный verification owner после интеграции изменений, без параллельных полных прогонов на незавершённом дереве.

Для каждой проверки сохраняются:

- команда/test ID и exit status;
- code/spec/fixture/configuration revisions или hashes;
- stdout/stderr либо structured test result;
- expected и observed outcome;
- ограничения и skipped checks;
- artifact path и digest.

Полные corpus-прогоны организуются согласно `AGENTS.md` и `testing.md`; промежуточная работа не должна многократно запускать полный eval.

### Шаг 11. Провести post-implementation review

Сравнить code + evidence с approved spec и plan:

- проверены ли реальные entry points, а не только helper;
- нет ли caller, обходящего gate;
- не появился ли второй writer authoritative field;
- сохранены ли failure/replay/migration semantics;
- не изменены ли denominator, scope или labels ради прохождения gate.

Материальное отклонение сначала оформляется в spec/architecture и повторно утверждается. Нельзя объявить фактический код новым контрактом задним числом.

### Шаг 12. Завершить цикл

После DoD:

- verification owner фиксирует `verified`;
- review record содержит итоговую ревизию и evidence;
- обновлены `gap-analysis.md`, `implementation-status.md`, `analysis-internals.md`, CLI/architecture docs — где поведение изменилось;
- `eval/README.md` обновлён при изменении наблюдаемого поведения;
- постоянный canonical contract остаётся в `specs/`;
- approved implementation plan сохраняется как immutable snapshot (content digest/revision) в implementation report/review record; рабочая копия может быть удалена после приёмки; ссылки на evidence остаются.

Затем выбирается следующая доступная S-XX.

## 6. Definitions of Ready / Done

### Spec DoR: можно составлять implementation plan

Все условия обязательны:

- [ ] Scope, non-goals, phase и dependency revisions определены.
- [ ] Назначены owner, architect и независимый reviewer.
- [ ] Требования имеют ID и traceability к goals/Target.
- [ ] У каждого поля/контракта определены owner, обязательность, источник и freeze/mutation rules.
- [ ] Определены flows, state transitions и terminal/error outcomes.
- [ ] Определены failure semantics, replay и migration/refusal.
- [ ] Указаны exact source paths и затронутые публичные/persistence surfaces.
- [ ] Acceptance tests **специфицированы**: fixture/input, действие, ожидаемый результат и artifact; существование реализованного теста до кода не требуется.
- [ ] Нет нерешённых design decisions или неоднозначных контрактов.
- [ ] Нет открытых P0/P1, влияющих на данные, доверие, безопасность, compatibility или acceptance.
- [ ] Independent review и goal/architecture comparison завершены.

**Spec не plan-ready**, если отсутствует хотя бы одно из следующего: однозначный контракт, failure semantics, source paths или acceptance tests. Реестр открытых вопросов не заменяет их разрешение.

### Plan DoR: можно начинать код

- [ ] Spec approved; план привязан к её ревизии.
- [ ] Выполнены prerequisites, необходимые для начала implementation.
- [ ] Requirements↔tasks mapping полный в обе стороны.
- [ ] Для каждой задачи указаны файлы, изменение поведения и tests.
- [ ] Последовательность учитывает producers/consumers и миграцию.
- [ ] Описаны rollback, evidence и stop conditions.
- [ ] Нет новых design decisions.
- [ ] План независимо отревьюен и утверждён.

### Implementation DoD: можно ставить `verified`

- [ ] Реализовано end-to-end поведение, а не scaffold/helper.
- [ ] Все affected callers, schemas, fixtures, docs и compatibility rules обновлены.
- [ ] Acceptance gates прошли на зафиксированной ревизии; evidence сохранён.
- [ ] Negative controls подтверждают non-admission.
- [ ] Replay и migration/refusal проверены в требуемом scope.
- [ ] Safety regression gates пройдены; drift объяснён и утверждён.
- [ ] Не осталось неутверждённых отклонений от spec.
- [ ] Post-implementation и обязательный security review завершены.
- [ ] Заявления о доказанности ограничены реально проверенной областью.

## 7. Шаблон спецификации

```markdown
# S-XX. Название

Status:
Revision/date:
Phase:
Dependencies: contract/spec + revision + required gate
Architect:
Contract/approval owner:
Independent reviewer:
Security reviewer: required / not required + reason

## Решение и plan-readiness
PLAN-READY | NOT PLAN-READY
Blocking items:

## Inputs и source inventory
Primary target sections:
Product goals:
Decision context:
Pinned source paths / APIs / current callers:
Current-state/provenance:
Evidence and its limitations:

## Goals traceability
Goal/Target invariant → SXX-Rnn → acceptance criterion

## Scope / Non-goals

## Requirements и invariants
SXX-Rnn: normative observable requirement; owner; source

## Contracts / schemas
Fields, types, required/optional, null/absent rules
Authority, provenance, precedence, freeze/mutation rules
Versioning and producer/consumer boundaries

## Flows / state machine
Entry points, transitions, terminal states, persisted outputs

## Failure semantics
Condition → state/error → persisted artifact → exit/result
What never becomes a safe-negative

## Security / trust boundaries

## Migration / compatibility / rollback constraints

## Observability / audit

## Acceptance criteria
AC-ID → requirement → fixture/action → expected observable → artifact

## Test plan
Unit / contract / integration / replay / migration / regression
Existing tests versus PLANNED tests
Commands or requirement for exact command manifest

## Open questions / design unknowns
ID, priority, affected decision, evidence, owner, closure gate
Blocking plan-readiness: yes/no

## Review record
Revision, self-check, independent findings/disposition
Goal/architecture comparison, security review
Approval and evidence links
```

## 8. Шаблон implementation plan

```markdown
# S-XX implementation plan

Status/revision:
Approved spec path + revision/digest:
Owner / implementer / reviewer:
Prerequisites and phase gates:

## Coverage map
Spec requirement → Task N → test/gate → evidence artifact
Каждое требование покрыто; у каждой задачи есть требование.

## Task N. Один независимо проверяемый результат
Spec requirements:
Dependencies:
Files: exact create/modify/test paths
Change: согласованное поведение и затронутые callers
Tests: positive, negative, regression
Expected observable:
Evidence:
Stop conditions:

## Sequencing / integration
Serial dependencies; safe parallel slices; integration owner

## Migration / rollback
Cutover, old-data handling, safe rollback, forbidden downgrade

## Verification manifest
Commands/tests, expected outcomes, artifact paths and pins
Final integration gates and verification owner

## Risks / assumptions / deviation protocol

## Plan review record
Spec comparison, findings/disposition, approval
```

Это шаблон; он не разрешает составлять S-01 plan до review её spec.

## 9. Review checklist

Reviewer обязан проверить:

- **Goal alignment:** решается исходный продуктовый вопрос; utility metric не заменяет safety criterion.
- **Architecture alignment:** Shadow — единственный Product A authority; Product B не повышает recommendation до verdict.
- **Completeness:** поля, состояния, входы/выходы, ownership, freeze, отказные ветви и зависимости определены.
- **Testability:** каждое MUST проверяемо; известны fixtures, действия и expected outcome.
- **Evidence:** есть сохраняемый результат; source inspection не выдаётся за выполненный runtime test.
- **Scope:** нет незаявленной соседней capability или case-specific обхода.
- **Security:** foreign/cross-run/stale/malformed/tamper, prompt injection и authority escalation закрыты.
- **Migration:** отсутствующие старые поля не становятся доверенными zero values; downgrade не обходит gate.
- **No duplicate contracts:** нет второго `AnalysisCase`, identity, EvidenceGraph, Claim, NV или verdict engine.
- **Failure semantics:** отказ, техническая ошибка и `INCONCLUSIVE` различаются; ни один не маскируется safe-negative.
- **Replay:** hashes, sidecars, provenance и verification recomputed; нет нового LLM/network/mutable-state dependency.
- **Operational completeness:** owner, approvals, artifact paths и phase exit gates определены.

Для каждого неприменимого пункта требуется объяснение, а не пустая отметка.

## 10. Порядок спецификаций и параллелизм

Ниже — рабочая очередь. **Phase подготовки контракта и phase завершения implementation могут различаться.** Источники и зависимости проверяются по Target §14.6; §13.7 дополняет input map.

Сокращения: **A** — Shadow/Product A source; **B** — V2/reference source.

| Очередь | Spec | Upstream по §14.6 | Основные дополнительные входы |
|---|---|---|---|
| Phase 0/1 | **S-01** Identity/case bundle/layout | Phase 0 governance prerequisite | §§2.4.1, 3.3, 13.2.1/4; A `domain`, `repository`, `affected/ticket.go`, `states`, `workflow` |
| Phase 0/1 | **S-02** EvidenceGraph/Claim/NV migration | S-01 | §§2.4.2–7, 13.2.4–5; A `domain`, `evaluator`, `goanalysis/negative.go`, `evidencetools` |
| Phase 0/1 | **S-16** Boundary type map/catalog/ingest | S-01, S-02 | §§13.3.3, 13.4, 14.3.2/4/5; B domain/affected imports и conditions |
| Phase 0/1 | **S-17** Product B schema registry | S-01 | §§2.4.10, 14.3.3; B schema constants, `artifacts.go` |
| Phase 0/1 | **S-05** Baseline/census/retention | S-01 | Phase 1, §13.2.6; A `eval/`, saved artifacts, replay/validation |
| Phase 2 | **S-03** ImportClosure | S-01, S-05 | B `goanalysis/toolscope.go`; A `goanalysis` |
| Phase 2 | **S-03b** Code-absence producer | S-03, S-17 | B `verify_code_absence.go`, `detools.go`, `falsifier.go` |
| Phase 2 | **S-04** Shipping scope/dynamic/parity | S-03b | B scope/dynamic/dispatch; обе версии `unreachability.go` |
| Phase 3 | **S-06** Proposal ingress | S-01, S-02, S-16, S-17 | §13.3.3; B `types.go`, `falsifier.go`, `runner.go` |
| Phase 3 | **S-06b** Intake/runtime | S-01, S-16, S-17 | B Stage0/catalog/ref/snapshot/siteconfig/input/intake/artifacts |
| Phase 3 | **S-07** FactGate/locators/archive | S-02, S-06, S-06b, S-17 | B `factgate.go`, `checks.go`, archive; A EvidenceGraph |
| Phase 3 | **S-08** DecisionPackage/policy | S-07, S-17 | §§14.5, 13.3.5–6; B composer/types/policy |
| Phase 3 | **S-08b** Metrics/audit/VEX projection | S-06b, S-07, S-08 | B metrics/tool audit/VEX/artifacts |
| Phase 3 | **S-09** Replay/stability/sidecars | S-02, S-08, S-08b | A replay/validate/deterministic; B replay/stability |
| Phase 3 | **S-13** Deployment/assumptions | S-02, S-07 | A exposure/assumptions; B siteconfig; §13.2.1/4 |
| Phase 4 | **S-10** Claimshape/verification | S-02, S-07 | B claimshape/verification/evidencetools |
| Phase 4 | **S-12** Separate research lane | S-01, S-02, S-16 | B research/refindex/reportcheck; A `internal/research` collision inventory |
| Phase 5 | **S-11** Heldout/admission | S-09, S-10 | B heldoutgate/eval; G-07/G-08 |
| Phase 5 | **S-14** Product-gap capabilities | S-03, S-04, S-13 | Case artifacts, SDK/input-control prerequisites, scope evidence |
| Phase 5 | **S-15** Ownership/CI/retention | S-01, S-05, S-08b, S-09 | CI workflows, docs registry, §13.6, baseline/replay artifacts |

**Single source of queue:** Target §14.6/§14.7. Таблица выше — projection; перед plan approval dependency manifest механически сверяется с Target. При расхождении действует Target.

### Обязательные оговорки к очереди

1. **Bootstrap Phase 0.** S-01 разрабатывается внутри Phase 0; требование Phase 0 не запрещает её draft/review. Но production implementation S-01/S-02 не начинается до требуемого normative delta и governance approval. Контракты S-02/S-16/S-17 готовятся для завершения Phase 0; нельзя требовать завершённый downstream runtime для написания foundational spec.
2. **S-02/S-16/S-17 имеют implementation span до Phase 3.** Их ранний contract freeze не означает, что миграция, adapters и mechanical gates уже реализованы.
3. **S-13:** пользовательская рабочая очередь ставит завершение в Phase 5, но Target §14.6 относит capability к Phase 3. Её контракт и interface freeze готовятся после S-02/S-07; перенос обязательного phase gate требует отдельного owner decision, а не молчаливой смены roadmap.
4. **S-15:** финальная приёмка — поздняя; D17, owners, reviewers, supersession и начальная retention policy нужны уже в Phase 0. Их нельзя отложить до завершения S-09.
5. **S-03b:** Phase 2 проверяет kernel/producer contract; полноценная falsifier-admission chain проверяется в Phase 3. Нельзя вернуть исправленную зависимость Phase 2 от готового triage adapter.
6. Target §14.6/§14.7 — единственный источник очереди. Projection в этой таблице должна проверяться mechanical dependency manifest; при расхождении действует Target. Зафиксировано: S-04 зависит от S-03b; S-13 — Phase 3.

### Что можно параллелить

После freeze соответствующих upstream contracts:

- S-02, S-17 и подготовку S-05 — после S-01; S-16 — после S-02.
- S-03b и независимую kernel-часть S-04 — после S-03, с общим интеграционным gate.
- S-06 и S-06b — после S-16/S-17.
- S-10 и S-12 — как отдельные Phase 4 ветки после их upstream.
- S-11 и S-13 — после собственных prerequisites; S-14 ждёт S-13.
- Документальную/операционную часть S-15 — с начала, не ожидая runtime.

Параллельные implementers не редактируют общий canonical contract независимо. Назначается один integration owner; финальные integration gates выполняются после объединения работ.

## 11. Правило изменения архитектуры

Если spec, plan или implementation выявляет противоречие goals/Target либо факт, меняющий контракт, данные, trust boundary, migration или ownership:

1. Остановить затронутую implementation.
2. Зафиксировать факт и exact source/evidence.
3. Указать опровергнутое решение и затронутые требования/callers.
4. Сохранить безопасное состояние работы.
5. Вернуть architect на повторный `design-unknowns`.
6. Получить согласованное изменение Target/ADR/spec.
7. Повторить review, approval и проверку плана.

**Запрещено кодировать workaround**, ослаблять verifier, добавлять специальный CVE-case или скрыто менять failure semantics.

## 12. Артефакты и доказанность

### Размещение

| Артефакт | Путь |
|---|---|
| Постоянная canonical spec | `docs/dev/specs/sXX-<topic>.md` |
| Временный implementation plan | `docs/dev/plans/<date>-sXX-<topic>-plan.md` |
| Approved implementation plan snapshot | `docs/dev/plans/<date>-sXX-<topic>-plan.md` + content digest/revision в implementation report |
| Spec/plan/implementation review | `docs/dev/reports/<date>-sXX-<review-kind>.md` либо review record spec |
| ADR / normative decision | `docs/dev/decisions/` |
| Публичные synthetic fixtures | Существующие test locations и `testdata/` по repo conventions |
| Baseline evidence | Retained baseline bundle по S-05 manifest |
| Выполненные gates | CI artifacts с retention policy S-15 |

Приватные source paths, исходные tickets и секреты не коммитятся. В документах используются безопасные refs; приватный bundle хранится в разрешённом evidence storage с manifest и hashes.

### Статусы утверждений

- **PROVEN** — есть проверяемое свидетельство; обязательно указаны scope и источник.
- **CLAIMED** — есть заявление или ограниченное измерение, недостаточное для более широкой гарантии.
- **UNPROVEN** — достаточного evidence нет.
- **PLANNED** — требуемое будущее поведение; это не уровень доказанности implementation.

Например:

- наличие функции в source — `PROVEN` как source fact;
- наличие теста — не доказательство, что он выполнен и прошёл;
- `false-safe=0` на pinned corpus — не универсальная гарантия;
- принятие spec — не evidence её реализации.

Каждый acceptance gate задаётся кортежем:

```text
requirement
+ pinned fixture/input/config
+ command/test
+ expected observable
+ retained artifact
+ pass/fail rule
```

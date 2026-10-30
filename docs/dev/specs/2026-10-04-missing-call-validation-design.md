# Спецификация: Модель уязвимостей Missing-Call (B21)

> **Correction (2026-10-26): omitted vs defective check.**
> Этот документ описывает модель для *действительно* advisory/fix-grounded
> missing-call дефектов. Приведённый ниже пример GO-2020-0017 ошибочен:
> advisory описывает **дефектную проверку** — `MapClaims.VerifyAudience`
> вызывается с `req=false` и неверно обрабатывает массив `aud`. То, что
> `MapClaims.Valid` не вызывает `VerifyAudience`, означает, что дефектная
> операция не исполняется; это основание для exact-record негатива
> (`NO_EXPLOIT_PATH_FOUND`), а не для `C-OMISSION` и не для `EXPLOITABLE`.
> Эвристика «проверочное имя + живой sibling-конвейер» удалена: семантику
> задаёт только допущенный контракт (`DEFECTIVE_CHECK` / `OMITTED_CHECK` /
> `UNRESOLVED`), см.
> [`plans/2026-10-26-05-defect-semantics-omitted-vs-defective.md`](../plans/2026-10-26-05-defect-semantics-omitted-vs-defective.md).
> Пункты ниже, описывающие эвристику (§1 п.3, §3.1, §5 п.3), сохранены как
> исторический дизайн, но больше не отражают поведение кода.

## 1. Контекст и проблема

В классической модели уязвимостей дефектным является *факт вызова* небезопасной функции (sink) с недоверенными входными данными:
- `C-REACH`: TRUE (функция из advisory вызывается в коде продукта или зависимости).
- `C-INPUT`: TRUE (аргумент контролируется злоумышленником).
- При отсутствии вызова функции (`callers == 0` по govulncheck/AST) срабатывает Negative Verification, возвращая `NO_EXPLOIT_PATH_FOUND` (NEPF).

Однако в целом классе уязвимостей (missing validation / authorization bypass) дефект **может** заключаться в **отсутствии вызова** обязательной проверки на активном конвейере обработки недоверенных данных (например, `MapClaims.Valid` внутри `jwt.ParseWithClaims`). Такой режим (`OMITTED_CHECK`) допустим только при явном advisory/fix-доказательстве того, что пропуск вызова и есть уязвимость. Исторический пример этого документа — `jwt-go` [GO-2020-0017](https://pkg.go.dev/vuln/GO-2020-0017), кейс `real-jwt-auth` — к нему **не относится**: там дефектна сама проверка, а не её отсутствие (см. Correction выше).

В таких случаях:
1. Уязвимая функция проверки (`VerifyAudience`) физически не вызывается (в библиотеке разработчики забыли её вызвать в `Valid()`, а продукт полагается на библиотечную валидацию).
2. Трактовка «нет вызова $\implies$ нет эксплуатации» приводит к катастрофическому **false-safe** (ложной безопасности).
3. Исторически (до 2026-10-26) действовал лишь защитный предохранитель `DepInvocationState` в `negative.go`: если целевой метод не вызывается, но родственные методы того же ресивера активны (`siblingLive == true`), отрицательный вывод блокировался, сваливая вердикт в `INCONCLUSIVE`. **Он удалён:** sibling-liveness остаётся наблюдением, а необходимость вызова выводится из допущенного контракта (см. §5).

**Цель B21**: Реализовать полноценную модель обязательного вызова («should-call»): доказать, что если конвейер ресивера доказанно активен и обрабатывает внешний ввод, а обязательный метод проверки доказанно опущен, условие дефекта переходит в **`TRUE`**, а вердикт — в доказанный **`EXPLOITABLE`** с формированием именованного доказательства `EV-MISSING-CALL`. С 2026-10-26 режим `OMITTED_CHECK` выбирается только допущенным advisory/fix-контрактом; `C-OMISSION` TRUE требует typed witness (`MissingCallWitness`), привязанного к контракту, а не evidence-id префикса.

---

## 2. Доменная модель (`internal/domain/`)

### 2.1. Тип условия `ConditionKind`
Вводится новый тип условия:
```go
ConditionMissingCall ConditionKind = "MISSING_CALL"
```
Условие assert'ит: «обязательная проверка безопасности опущена на пути выполнения активного конвейера обработки данных».

### 2.2. Набор обязательных условий эксплойт-модели
Для уязвимостей типа missing-call билдер эксплойт-модели (`internal/exploit/builder.go`) генерирует:

> Приведённые ниже идентичности `jwt-go` — исторический пример. GO-2020-0017
> не является missing-call, поэтому для него эти условия больше не
> строятся. Для genuinely omission-адвизори идентичности берутся из
> допущенного `OMITTED_CHECK` контракта (check + pipeline).

1. **`C-REACH`** (`ConditionSymbolReachable`):
   * *Субъекты*: методы активного конвейера ресивера (receiver pipeline), например `[github.com/dgrijalva/jwt-go.MapClaims.Valid]`.
   * *Параметры*: `{"pipeline": "MapClaims.Valid"}`.
   * *Описание*: достижимость конвейера обработки данных ресивера из кода продукта.

2. **`C-OMISSION`** (`ConditionMissingCall`):
   * *Субъекты*: опущенный метод проверки из advisory, например `[github.com/dgrijalva/jwt-go.MapClaims.VerifyAudience]`.
   * *Параметры*: `{"pipeline": "MapClaims.Valid", "check": "missing_call"}`.
   * *Описание*: обязательная проверка `VerifyAudience` доказанно не вызывается внутри конвейера `MapClaims.Valid` и вызывающего кода продукта.

3. **`C-INPUT`** (`ConditionAttackerControl`):
   * *Описание*: входные данные, поступающие в конвейер (токен из заголовка `Authorization`), контролируются внешним источником.

4. **`C-LOCUS`** (`ConditionSymbolReachable` с `CheckLocus`):
   * *Описание*: пакеты дефектного кода слинкованы в бинарный файл продукта и исполняются.

### 2.3. Идентификатор доказательства (Evidence)
* **`EV-MISSING-CALL`**: структурированное детерминированное доказательство (`QualityDeterministic`), фиксирующее:
  * Ресивер: `github.com/dgrijalva/jwt-go.MapClaims`
  * Вызываемый конвейер: `Valid()`
  * Опущенная проверка: `VerifyAudience()`
  * Точка вызова из продукта: `main.parseToken` $\to$ `jwt.ParseWithClaims`
  * Количество вызовов проверки на пути: 0.

  **Обновлено 2026-10-26:** evidence несёт типизированный `Evidence.MissingCall`
  (`MissingCallWitness` со статусами `OMITTED`/`PRESENT`/`NOT_ESTABLISHED`,
  record/check/pipeline, build-context). Поиск по evidence-id префиксу и
  content-substring удалён; эвалюатор принимает только witness, чей
  record/check/pipeline идентичен допущенному контракту и чей build-context
  совпадает с эффективной сборкой продукта.

---

## 3. Детекция конвейера и доказательство пропуска проверки (`internal/exploit/`, `internal/goanalysis/`)

### 3.1. Распознавание missing-call паттерна
**Исторический дизайн; эвристика удалена 2026-10-26.** Имя проверки и живой sibling-конвейер теперь только *номинируют* кандидата для исследования. Режим дефекта задаёт допущенный контракт из advisory/fix-доказательств; при отсутствии различающих доказательств модель остаётся `UNRESOLVED` и fail-closed. Ниже — исходное описание, не отражающее текущее поведение:
1. Метод является проверочным: `typeName, name := splitSymbol(subj.Symbol)`, `typeName != ""` и `isCheckMember(name) == true` (префиксы `Verify`, `Validate`, `Check`, `Authenticate`, `Authorize`, `Is`, `Has`).
2. Тип `typeName` содержит методы конвейера (sibling methods в методе ресивера, например `Valid()`), которые вызываются из продукта напрямую или через интерфейсы (например, интерфейс `jwt.Claims` и функцию `jwt.ParseWithClaims`).
3. Метод проверки `name` не имеет вызовов внутри тела конвейера и прямого вызова в вызывающем коде продукта.

### 3.2. Доказательство пропуска (`checkOmission`)
В `internal/goanalysis/`:
1. Проводится детерминированный аудит вызывающего поддерева (enclosing tree) от точки входа продукта до конвейера библиотеки.
2. Подтверждается:
   * Конвейер `MapClaims.Valid` вызывается (через `ParseWithClaims`).
   * Вызов `MapClaims.VerifyAudience` отсутствует на всех ветвлениях данного поддерева.
3. Формируется доказательство `EV-MISSING-CALL`.

**Обновлено 2026-10-26:** `Index.CheckMissingCall` возвращает типизированный
статус (`OMITTED`/`PRESENT`/`NOT_ESTABLISHED`), а не bool из текста.
Недостижимый конвейер, неразрешённое объявление и усечённый поиск
каллеров — `NOT_ESTABLISHED`, никогда «проверка присутствует»; такое
измерение остаётся tool limitation, а не evidence.

---

## 4. Эвалюация условий (`internal/evaluator/`)

**Обновлено 2026-10-26:** эвалюатор больше не ищет evidence по id-префиксу
или content-substring. Он принимает только типизированный
`Evidence.MissingCall`, сопоставленный с допущенным контрактом через
`MatchOmissionWitness`: TRUE = контрактный witness со статусом `OMITTED`,
FALSE = контрактный witness `PRESENT` (`FalsifierGuards`), всё остальное
(включая untyped `EV-MISSING-CALL`, чужой build-context и
`NOT_ESTABLISHED`) — UNKNOWN. Ниже — исходное историческое описание.

Создаётся эвалюатор `evaluator.MissingCall` (`internal/evaluator/missingcall.go`):
* `CanEvaluate(cond)`: возвращает `true` для `cond.Kind == domain.ConditionMissingCall`.
* `Evaluate(cond, c)`:
  * Ищет `EV-MISSING-CALL` в `c.EvidenceGraph`.
  * Если доказано, что конвейер активен, а проверка опущена:
    * `claim.Result = domain.ClaimTrue`
    * `claim.Explanation = "обязательная проверка VerifyAudience доказанно опущена в активном конвейере MapClaims.Valid"`
    * `claim.EvidenceIDs = append(claim.EvidenceIDs, "EV-MISSING-CALL")`
  * Если в продукте обнаружен явный вызов проверки:
    * `claim.Result = domain.ClaimFalse`
    * `claim.Falsifier = domain.FalsifierGuards` («проверка выполняется явно в коде продукта»)
  * При неполном графе вызовов:
    * `claim.Result = domain.ClaimUnknown`.

### Итоговый вердикт
Историческое ожидание для genuinely omission-адвизори с допущенным
`OMITTED_CHECK` контрактом и всеми обязательными условиями:
* `C-REACH` (`MapClaims.Valid`): TRUE
* `C-OMISSION` (`VerifyAudience` опущена): TRUE
* `C-INPUT` (внешний токен): TRUE
* `C-LOCUS` (код в сборке): TRUE
* $\implies$ **`domain.VerdictExploitable`** («all mandatory exploit conditions are satisfied: missing validation on active external pipeline»).

Для `DEFECTIVE_CHECK` этот вывод не действует: дефектная операция должна
исполняться, поэтому доказанная мёртвость контрактной проверки ведёт к
`NO_EXPLOIT_PATH_FOUND` после полной негативной верификации, а не к
`EXPLOITABLE`; пример — GO-2020-0017/Echo.

---

## 5. Инварианты безопасности

1. **`false-safe = 0`**:
   Для genuinely omission-адвизори отсутствие вызова проверки **никогда** не может служить основанием для `NO_EXPLOIT_PATH_FOUND`; отрицательный вывод на `C-OMISSION` допустим **только** при наличии явного вызова проверки на всех путях с доказательством его достаточности. Для `DEFECTIVE_CHECK` наоборот: доказанная мёртвость контрактной проверки опровергает обязательный вызов, но негатив допускается только после полной негативной верификации и допущенной invocation-necessity premise. Без контракта (`UNRESOLVED`) мёртвость не даёт ни позитивного, ни отрицательного вывода.
2. **Изоляция обычных уязвимостей**:
   Функции, не являющиеся проверочными методами ресиверов (`isCheckMember == false`), обрабатываются стандартной моделью с традиционным `C-REACH`.
3. **Invocation-necessity admission вместо sibling-live veto**:
   `checkDepInvocation` больше не отказывает в негативе из-за активных sibling-методов: sibling-liveness остаётся наблюдением. Любой deadness-негатив требует допущенного контракта, чей negative locus покрывает мёртвые символы (`ValidateDeadnessPremise` / `RequireDeadnessPremise`) — в main evaluator, research, Product B и replay/publication. `OMITTED_CHECK` использует omission-site на конвейере; мёртвость самой отсутствующей проверки premise не является.

---

## 6. Валидация и Done-критерии

1. Модульные тесты `internal/exploit/` (построение missing-call модели) и `internal/evaluator/` (`missingcall_test.go`).
2. Регрессионный интеграционный тест на сценарии `real-jwt-auth`: **исторический критерий недействителен** — GO-2020-0017 не является missing-call, поэтому перехода в `EXPLOITABLE` быть не должно. Измерено 2026-10-26: host-default — `FAILED` (`REACHABILITY_PROOF_INCOMPLETE`/`TRIGGER_PROOF_INCOMPLETE`); operator-declared target — `DECIDED / NO_EXPLOIT_PATH_FOUND` для точной записи.
3. Прогон всего автономного корпуса `eval/corpus-real.json` (38 кейсов): **исторический критерий; полный корпус после исправления модели не перезапускался**. Целевые метрики `false-safe=0` и снижение `INCONCLUSIVE` относились к ошибочной модели.
4. `gofmt`, `go vet ./...`, `go test ./...` проходят без ошибок.
5. Пункт B21 удаляется из §2 [`docs/dev/gap-analysis.md`](../gap-analysis.md).

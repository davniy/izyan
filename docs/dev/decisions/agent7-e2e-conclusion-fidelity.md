# E2E-заключение research-полосы: достоверность (slice2-fidelity/2)

- **Статус:** реализовано; результаты офлайн-регрессии — §5; records B42 (package-level usage facts) — §7 и B41 (build-closure usage scope) — §8, оба в `slice2-fidelity/3`.
- **Дата:** 2026-10-12.
- **Основание:** три класса проблем, выявленных корпоративной проверкой (Slice 3, см.
  [`agent7-corporate-validation.md`](agent7-corporate-validation.md) §3):
  1. исправленная версия компонента читалась как отсутствие компонента;
  2. наличие потенциальной цепочки вызовов не отделялось от доказанной эксплуатации;
  3. «нет необходимой конфигурации» и «код недостижим» не были независимыми основаниями.
- **Ограничения задачи:** без новой инфраструктуры, без A3/R1/Proof Engine, без правки промптов,
  без новых LLM-экспериментов; только существующие структуры (`verified_facts`, `agent_assertions`,
  `exploitation_conditions`, `unknowns`, `basis[]`, `classification_review`, `exploitation_axes`).

## 1. Что именно было не так (подтверждено на сохранённых отчётах)

| Класс | Наблюдение |
|---|---|
| 1 | `internal/affected/resolver.go`, ветка «resolved version вне affected-диапазонов»: `VersionAffected=FALSE` **и синхронно** `PackagePresent=FALSE`, `BuildRelevant=FALSE` — без запуска пакетного probe. В отчёте это давало `applicability chain … package_present=FALSE build_relevant=FALSE`, условия `affected package reachable = REFUTED`, `affected package build-relevant = REFUTED` и ось `code_reachability=NOT_ESTABLISHED` с формулировкой «no advisory-affected code version is compiled in». Семантика `package_present=FALSE` («все CheckedPackages отсутствуют в транзитивном замыкании сборки») утверждалась без проверки — заключение сильнее фактов. |
| 2 | Агентский шаг сценария попадал в `exploitation_conditions` как `[agent/OPEN]` в одной группе с детерминированными UNKNOWN; секция `attack_scenario` получала `PARTIAL` при `exploitation_established=NOT_ESTABLISHED`. |
| 3 | Для `requires_configuration` не было своего named basis: `classification_review={class:UNCERTAIN,status:UNKNOWN,limitations:[]}`, decision-changing unknowns пусты; агентское утверждение о недостижимости тоже не давало отдельного основания. |

## 2. Детерминированное ядро

`internal/affected/resolver.go`: в fixed-ветке сняты синтетические `PackagePresent=FALSE`/`BuildRelevant=FALSE`;
оба предиката остаются `UNKNOWN`, добавлен limitation «package/build reachability was not evaluated: the resolved
version is outside the affected ranges of every evaluated advisory entry». `VersionAffected=FALSE` сохраняется —
это утверждение о версии, и именно оно (а не отсутствие пакета) даёт `NOT_AFFECTED` в
`internal/evaluator/verdict.go` и переход в `internal/states`. Ветка «модуль отсутствует» намеренно не менялась:
там `package_present=FALSE` — производный, но обоснованный негатив, подтверждаемый basis `component_absent`
(см. §4, границы).

Регрессионный тест: `internal/affected/resolver_test.go:TestFixedVersionDoesNotInferPackageAbsence`.

## 3. Контракт отчёта `slice2-fidelity/2`

Wire-схема остаётся `research-report/1`; расширение рекламируется как `slice2-fidelity/2`, старые отчёты
(`/1`) продолжают валидироваться legacy-веткой, одновременное наличие `/1` и `/2` — ошибка.

**Новые поля (все `omitempty`, существующие не переименованы):**

| Поле | Смысл |
|---|---|
| `product_applicability.evaluated_entry_ids[]` | записи advisory, по которым реально проверялось присутствие (включая отсутствующие модули); `omitempty` — отсутствие/пустой список = пустое оценённое множество ⇒ единственный допустимый агрегат `NOT_EVALUATED` |
| `product_applicability.advisory_entry_status` | `AFFECTED\|FIXED\|UNKNOWN\|NOT_EVALUATED\|MIXED` — статус **оценённых записей**, не CVE целиком; `FIXED` = resolved-версия вне уязвимых диапазонов оценённой записи; `MIXED` = оценённые записи распределены по ≥2 видам вердиктов (affected/fixed/unknown) |
| `product_applicability.unresolved_modules[]` | модули записей advisory с неразрешимой версией независимо от линковки пакета (`pending_modules` — только линкованные); такая запись никогда не `fixed` |
| `product_applicability.vulnerable_code_reachability` | `TRUE\|FALSE\|UNKNOWN\|NOT_EVALUATED` — достижимость уязвимого кода отдельно от статуса исправления; при `FIXED` НИКОГДА не `FALSE` |
| `product_applicability.basis[].check_scope` | область проверки для каждого основания (обязательна в `/2`) |
| `basis[].kind = required_configuration_absent`, `vulnerable_code_not_reachable` | независимые основания «нет необходимой конфигурации» и «недостижимость уязвимого кода»; агентские — `PROVISIONAL`/`source=agent`/`verified_evidence_refs=[]` |
| `agent_output.replayed_from` | провенанс пересборки из сохранённого прогона (§4) |

**Переходы (без новых полей, семантика существующих):** подтверждённый факт = `origin=deterministic` +
`state∈{SUPPORTED,REFUTED}` + verified fact ref (REFUTED только после реально выполненной проверки);
агентская гипотеза = `origin=agent` + `state=OPEN` (никогда не `SUPPORTED`/`REFUTED`); неизвестное условие =
`origin=deterministic` + `state=UNKNOWN`. Для fixed-записи условия «affected package reachable»/«build-relevant» —
`UNKNOWN` с указанием, что probe не запускался, а не `REFUTED`.

**Статус `attack_scenario`:** `SUPPORTED` только при `exploitation_established=ESTABLISHED`; `PARTIAL` — только
при ≥1 подтверждённом детерминированном переходе И ≥1 незакрытом required-переходе, с маркером «exploit path is
not established»; сценарий, состоящий только из агентских гипотез, — `UNKNOWN` (был `PARTIAL`).

**`classification_review`:** provisional-основания никогда не дают `SUPPORTED`; `requires_configuration` с
единственным агентским основанием остаётся `UNCERTAIN/UNKNOWN`, `code_not_reachable` с агентским основанием —
`NON_APPLICABLE/UNKNOWN`; `NON_APPLICABLE/SUPPORTED` возможен только на детерминированном негативном основании
(`component_absent`, `package_not_in_import_closure`) с verified refs.

**Валидатор (`/2`, fail-closed):** обязательные новые поля; `FIXED` требует `module_present=TRUE`,
`version_affected=FALSE`, `resolved_version`; `evaluated_entry_ids` обязаны разрешаться в
`affected_implementations[].id` и точно совпадать с множеством оценённых записей по
checked/selected/pending; `advisory_entry_status` пересчитывается покомпонентно из тех же множеств
(`affected` = модуль в `selected_modules`/`selected_module` при `version_affected=TRUE`, `unknown` =
`pending_modules`, `fixed` = `checked_modules` ∖ (`selected_modules` ∪ `pending_modules`)) и должен
совпадать с записанным агрегатом — `MIXED` требует фиксированной И затронутой записи;
`package_present`/`build_relevant`/`vulnerable_code_reachability = FALSE`
запрещены для присутствующего модуля с неоценённым/исправленным статусом; `vulnerable_code_reachability=FALSE`
требует детерминированного негативного основания с verified refs, согласованного с полями
(`component_absent` — только при `module_present=FALSE`, `package_not_in_import_closure` — только при
`module_present=TRUE` и `package_present`/`build_relevant=FALSE`); `TRUE` — только при `AFFECTED` +
package/build `TRUE` и verified fact от пробы применимости (`affected-resolve`/`get_module_version`) в
`evidence_refs` или ESTABLISHED-основании; `ESTABLISHED` basis ⇒ `source=deterministic` + непустые
fact-refs; `PROVISIONAL` ⇒ `source=agent` + пустые
verified refs; состояние условия — только из закрытого enum, агентское условие — ровно `OPEN`,
детерминированное условие по applicability-предикату обязано совпадать с полем
(`SUPPORTED`↔`TRUE`, `REFUTED`↔`FALSE`, `UNKNOWN`↔`UNKNOWN`);
`exploitation_established=ESTABLISHED` требует `basis=dynamic` и ≥1 verified fact от
`runtime-observation`/`dynamic-trace`/`reproduction`; правила статуса `attack_scenario`; при
`NOT_EVALUATED` ось `code_reachability` обязана нести limitation с
маркером «not evaluated»; `classification_review` — закрытая матрица класс/статус: `SUPPORTED` возможен
только для `APPLICABLE` (`module_present=TRUE` + `version_affected=TRUE` + verified fact пробы
применимости в `basis_refs`) и `NON_APPLICABLE` (ESTABLISHED deterministic
`component_absent`/`package_not_in_import_closure`, чьи verified refs процитированы в `basis_refs`;
`version_fixed` не поддерживает класс неприменимости); `UNCERTAIN`/`NOT_EVALUATED` никогда не `SUPPORTED`.

**Рендер:** обязательный русский `## Резюме` во главе `report.md` (присутствие модуля; оценённые записи и статус
исправления; достижимость уязвимого кода; область применимости advisory; оставшиеся препятствия для триажа),
условия разделены на три группы (подтверждённые факты / гипотезы агента / неизвестные условия). Существующие
английские заголовки не переименовывались.

## 4. Пересборка из сохранённых артефактов (без модели)

Новый вход команды: `izyan research --replay-agent-turn <dir>` — детерминированная полоса выполняется заново
(LLM не вызывается), агентская часть загружается из сохранённого прогона (`report.json` +
`agent/attempt-0002/answer.txt`), все записанные пины артефактов проверяются по sha256 (несовпадение — fail-closed),
`agent_output` сохраняется verbatim (включая `INVALID_FORMAT`/`FAILED`), в отчёт пишется провенанс
`replayed_from`, а в ledger попыток — строка с `reason_code=manual_recheck`. Сочетание с `--deterministic-only` —
ошибка. Это вход для регрессии, а не новая инфраструктура: ни промпты, ни harness, ни модель не задействованы.

Провенанс окружения: у пересобранного отчёта `run.harness` пуст (в этом прогоне harness не запускался), а пины
окружения исходного прогона остаются в сохранённых `run-manifest.json` (`agent_manifest`: harness commit/patch,
дайджест E6-образа, sha256 промпта) и в каталоге `agent/harness/` — оба сохраняются рядом с отчётом; валидатор
`/2` запрещает одновременно `replayed_from` и признаки живого turn'а, чтобы пересборку нельзя было выдать за
новый агентский прогон.

## 5. Офлайн-регрессия (21 кейс, без LLM)

18 корпоративных кейсов (приватно, `runs/<TICKET>/agent` → `runs/<TICKET>/agent-v2`, оригиналы сохранены) и
3 публичных e2e-кейса (`eval/agent7/e2e/*`). Проверки: расширение `/2`; `FIXED` не порождает утверждений об
отсутствии; условия не `REFUTED` на неоценённой цепочке присутствующего модуля; агентские условия не
`SUPPORTED`/`REFUTED`; `exploitation_established` не поднят; сценарий без подтверждённых переходов не
`PARTIAL`/`SUPPORTED`; `classification_review` без `SUPPORTED` на одних агентских ссылках; агентский статус
сохранён; `REVIEW_REQUIRED` сохранён. Результат: **21/21 PASS**, суммарно ~22 мин машинного времени
(детерминированная полоса перезапускается, модель не вызывается).

Что именно изменилось в отчётах (18 корпоративных кейсов):

| Наблюдение | До (`/1`) | После (`/2`) |
|---|---|---|
| Исправленная версия давала утверждение об отсутствии | `package_present=FALSE` + `build_relevant=FALSE` + условия `REFUTED` в 6 кейсах | `package_present=UNKNOWN`, `build_relevant=UNKNOWN`, условия `UNKNOWN`, `vulnerable_code_reachability=NOT_EVALUATED`, `advisory_entry_status=FIXED` |
| Отсутствие модуля (легитимный негатив) | `component_absent`, package/build `FALSE` | без изменений (`component_absent` + `vulnerable_code_reachability=FALSE` с verified refs) |
| Цепочка эксплуатации | `attack_scenario=PARTIAL` при `exploitation_established=NOT_ESTABLISHED` | `attack_scenario=UNKNOWN` во всех 18 кейсах; агентские шаги вынесены в группу «Гипотезы агента» (`PROVISIONAL`, `origin=agent`, `state=OPEN`) |
| Основания | `requires_configuration` → `UNCERTAIN/UNKNOWN` без основания; недостижимость — без своего основания | независимые основания с `check_scope`: `required_configuration_absent` (12 кейсов) и `vulnerable_code_not_reachable` (6) как `PROVISIONAL/agent`, плюс детерминированные `component_absent`/`package_not_in_import_closure`/`version_fixed` |

Распределение после регрессии: `advisory_entry_status` — AFFECTED 9, FIXED 6, MIXED 2, NOT_EVALUATED 1;
`vulnerable_code_reachability` — UNKNOWN 9, NOT_EVALUATED 8, FALSE 1 (модуль отсутствует);
`package_present` — UNKNOWN 17, FALSE 1; `classification_review.status` — SUPPORTED 4, UNKNOWN 7, CONFLICTED 4,
NOT_EVALUATED 3; `disposition` — `REVIEW_REQUIRED` во всех 21 кейсе.

### Перечень оставшихся препятствий для ручного триажа (41 decision-changing unknown на 18 кейсов)

| Класс | Кол-во | Что нужно для закрытия |
|---|---|---|
| Разрыв области advisory: агент называет компонент вне записей замороженного advisory | 19 | определить единицу привязки (модуль как единица, когда пакет/символ не названы) и подтвердить полноту advisory для CVE |
| «Нет необходимой конфигурации» (агентская гипотеза) | 12 | контроллерские deployment/config-факты (`DeploymentEvidence`) как verified evidence с областью проверки |
| «Уязвимый код недостижим» (агентская гипотеза) | 6 | частично закрыто B42 (§7): bounded package-usage fact опровергает гипотезу детерминированно для advisory-declared пакетов/символов в закрытой области; остаток — достижимость вне static product-source scope (runtime/deployment posture) и module-only advisory |
| Агентская оценка не получена (`INVALID_FORMAT`) | 3 | устойчивость формата ответа модели (правка промпта — вне этой работы) |
| Агентское `sdk_vs_daemon`-основание не проверено | 1 | детерминированная проверка SDK-vs-daemon на стороне продукта |
| Использование только в тестах / вне продуктовой сборки | — | ось B41 реализована (§8), но specialist-регрессия не дала test-only: в 17 кейсах offline `go list` не закрыл область; остаток — измеренная test-only ветвь на сохранённых данных |
| `runtime/deployment posture` | 18 (по одному на кейс) | динамическое наблюдение или контроллерский факт; статический скан его не решает |

Публичные e2e-кейсы: `k8s-44487` перегенерирован в `/2` (`advisory_entry_status=FIXED`,
`vulnerable_code_reachability=NOT_EVALUATED`, `attack_scenario=UNKNOWN`) и закоммичен. Для `trivy-32473` и
`rancher-47914` пересборка в этом окружении невозможна: их графы зависимостей не разрешаются
(`go list -m all` → «module lookup disabled by GOPROXY=off», модули отсутствуют в доступном кеше), поэтому их
закоммиченные отчёты остаются `/1` (legacy-ветка валидатора их принимает) — пересборка требует кеша
`agent7-caches/b0-caches/gopath/pkg/mod` исходного прогона. Это ограничение окружения, а не поведения полосы.

## 6. Границы и что осталось

- Ветка «модуль отсутствует» (`package_present=FALSE` как производный негатив при `component_absent`) намеренно
  не менялась — это обоснованный детерминированный негатив с verified refs, а не дефект «fixed→absence».
- Полоса по-прежнему не закрывает кейсы: `disposition=REVIEW_REQUIRED`, `exploitation_established` не поднимается
  без динамического доказательства; агентские гипотезы и provisional-основания остаются гипотезами.
- Оставшиеся препятствия ручного триажа перечислены в §5 и в отчёте (раздел `## Резюме`); класс
  «уязвимый код недостижим» частично закрыт детерминированным package-usage фактом (§7).
- Правка промптов, новые LLM-эксперименты, A3/R1/Proof Engine — вне этой работы.

## 7. B42: факты уровня пакета/использования (`slice2-fidelity/3`)

- **Статус:** реализовано; измеренная регрессия — [`../reports/2026-10-14-01-package-level-facts-regression.md`](../reports/2026-10-14-01-package-level-facts-regression.md).
- **Дата:** 2026-10-14.
- **Основание:** открытый пункт B42 бэклога и план
  [`../plans/2026-10-14-01-package-level-facts-plan.md`](../plans/2026-10-14-01-package-level-facts-plan.md):
  advisory мог объявлять пакет/символ, но «пакет есть, а продуктом не используется» было недостижимо —
  package-level usage оставался `UNKNOWN` без обоснованного факта.

### Контракт

**Примитив и projection.** Новый статический tool `package-usage`
(`internal/evidencetools/usage.go` над `internal/goanalysis.Index.ProductUsage`) отвечает на вопрос
«использует ли продуктовый код advisory-declared пакет или символ» тремя состояниями: `USED` —
конкретный import/reference/call site в продуктовом коде; `NOT_USED` — все условия закрытой negative
verification выполнены; `UNKNOWN` — область не закрыта, субъект не резолвится или есть незакрытый
dynamic escape. Кандидаты строятся детерминированной symbol→package projection из деклараций advisory
(`packageUsageCandidates`): пакетный субъект на каждый объявленный пакет и символьный субъект на каждый
объявленный символ; путь модуля никогда не подставляется вместо пакета, поэтому module-only advisory
(только модуль + диапазон версий) не получает ни observation, ни условия — субъект остаётся `ABSENT`,
а разрыв фиксируется decision-changing unknown.

**Linkage vs usage — разные предикаты.** Присутствие пакета в графе сборки (`present`, linked import
closure) и его использование продуктовым кодом — независимые утверждения: `NOT_USED` утверждается
только для пакета, который присутствует в замыкании, но не используется продуктовыми сурсами. Факт
строго ограничен статическим продуктовым кодом: он не утверждает runtime non-use, отсутствие
reflection/plugin/generated loading, отсутствие deployment/runtime exposure, безопасность продукта
или глобальную неприменимость advisory.

**Negative verification.** `NOT_USED` сообщается только вместе с `negative_verification=VERIFIED`,
что требует одновременно: target в linked import closure; для символьного субъекта — разрешённая
декларация в загруженном dep-пакете; каждый загруженный продуктовый пакет просканирован; ни один
пакет с ошибкой type-check не импортирует target; бюджет загрузки пакетов не исчерпан; нет прямых
import/reference/call, build-gated ссылок, незакрытых interface-dispatch кандидатов и релевантных
dynamic-маркеров. Любой разрыв → `UNKNOWN` + `INSUFFICIENT_SCOPE`. Никогда не являются negative
proof: `ERROR`, `TIMEOUT`, `UNSUPPORTED`, отсутствующий результат, неполный scope, skipped packages,
нулевой результат `module_usage`/`find_callers`/`find_may_callers`/`module_internal_reach`/
`ingress-inventory` и сам по себе пустой список sites.

**Wire (`/3`).** Схема остаётся `research-report/1`; маркеры `/1`, `/2`, `/3` взаимно исключаются;
`/1` и `/2` валидируются legacy-веткой без `role`, `evidence_level` и package-usage полей. Verified
факты получают `kind`: `PACKAGE_USAGE` — носитель вердикта (claim=TRUE при `USED`; claim=FALSE только
при `negative_verification=VERIFIED` + coverage=COMPLETE); `PACKAGE_USAGE_LOWER_BOUND` — отдельный
kind для недетерминированной проверки, записавшей позитивное содержание (всегда claim=TRUE,
coverage=PARTIAL): не `USED`-вердикт и не negative proof, никогда не носитель и не закрывает path
condition. `usage_subject` связывает факт и условие ровно с одним advisory-declared кандидатом
(module/package/symbol): валидатор `/3` отклоняет package-usage факт без subject и SUPPORTED-условие,
ссылающееся на факт с чужим subject; `negative_verification` допустим только на claim=FALSE
package-usage факте.

**Условие и уровни.** Required `role=path` условие `affected package/symbol used by product code`
эмитится по одному на отсортированный кандидат, только `origin=deterministic`: `USED` → `SUPPORTED`;
`NOT_USED` + `VERIFIED` в COMPLETE scope → `REFUTED`; всё остальное (открытый разрыв, отсутствующий
или failed результат, нечитаемый payload) → `UNKNOWN` и blocking. `SUPPORTED` закрывает предикат для
L1 только через промотированный `PACKAGE_USAGE`-факт из статического carrier-allowlist с совпадающим
`usage_subject`; `REFUTED` required path condition всегда блокирует L1. `evidence_level` — производное
поле: assembler вычисляет через `deriveEvidenceLevel`, валидатор пересчитывает тем же helper, mismatch —
validation error.

### Измеренный эффект (saved-data replay, без вызовов модели)

| set | n | до | после |
|---|---|---|---|
| primary | 31 | 7 L1 / 24 L2 / 0 L3 | 0 L1 / 31 L2 / 0 L3 |
| retry | 11 | 2 L1 / 9 L2 / 0 L3 | 0 L1 / 11 L2 / 0 L3 |

Все 9 прогонов с advisory-declared кандидатами (7 primary + 2 retry-копии) ушли L1→L2: минимум один
кандидат верифицирован `NOT_USED` при COMPLETE scope ⇒ required path condition `REFUTED` ⇒ L1
заблокирован по контракту. Это отрицательная ветвь — кандидаты опровергнуты, а не продвинуты;
позитивной ветви (SUPPORTED-закрытие условия) не достиг ни один кейс. 33 module-only кейса остаются
L2 с `ABSENT` usage-субъектом. По 127 per-candidate условиям в 9 отчётах: 15 `SUPPORTED` / 91
`REFUTED` / 21 `UNKNOWN` (напр., package-level субъект `golang.org/x/net/http2` в C01 остаётся
`INSUFFICIENT_SCOPE`). Census наблюдений: 91 `NOT_USED`/VERIFIED, 15 `USED`, 21
`UNKNOWN`/`INSUFFICIENT_SCOPE`.

**`REFUTED` не является заключением о безопасности.** `disposition` остаётся `REVIEW_REQUIRED`/
`auto_close=false` во всех 42 кейсах; `vulnerable_code_reachability` никогда не становится `FALSE`;
REFUTED-условие несёт bounded-scope limitations («path refuted in bounded scope», «никогда не
является заключением о безопасности продукта, auto-close, VEX или not-affected disposition»).
Каноническая агентская path-гипотеза остаётся `OPEN` и blocking; агентское usage-условие не несёт
`usage_subject` и не может ссылаться на verified facts.

## 8. B41: отдельная ось замыкания сборки (`slice2-fidelity/3`)

- **Дата:** 2026-10-14.
- **Статус:** контракт реализован; B41 в бэклоге сужен до незакрытой specialist test-only регрессии.
- **Основание:** [план B41](../plans/2026-10-14-02-usage-scope-plan.md); измерения и воспроизведение —
  [отчёт регрессии](../reports/2026-10-14-02-usage-scope-regression.md).

### Решение и границы

`usage-scope` классифицирует принадлежность замыканиям сборки, а не использование продуктовым
исходным кодом (отдельный B42 `package-usage`). Двойной примитив независимо получает
`go list -deps -json ./...` (product) и `go list -deps -test -json ./...` (test), либо —
на vendored-снапшоте — тот же результат выводится офлайн из `vendor/modules.txt` + source
imports (`closure_source=vendor/modules.txt+source-imports`), с одинаковым записанным
snapshot/build context: GOOS, GOARCH, CGO и build tags.

**Product-root semantics — `product_all_packages`.** Product closure — транзитивное
статическое build/linker-замыкание всех применимых first-party package-директорий,
матчящихся `./...` под записанный build context; это **не** замыкание выбранного shipped
binary и директории не исключаются по именам (`test`, `helper`, `integration`).
Test closure — транзитивное замыкание распознанных internal/external test-вариантов и
синтетических `.test` driver-корней тех же директорий. `usage_scope` классифицирует только
членство в этих двух замыканиях; результат — ограниченный статический факт замыкания,
не source-use, runtime, deployment, reflection/plugin/generated-loading, safety или
shipped-artifact вывод. Поле `closure_semantics` обязательно и равно `product_all_packages`
в typed data и `scope_details.extra`; `coverage_rule` прямо фиксирует ту же семантику.

| Product closure | Test-root closure | `usage_scope` при двух полных проверках |
|---|---|---|
| присутствует | отсутствует | `product` |
| отсутствует | присутствует | `test-only`, `ProductAbsenceVerification=VERIFIED` |
| присутствует | присутствует | `mixed` |
| отсутствует | отсутствует | `unknown`; без маркера — или `VERIFIED_VENDOR_INVENTORY` при выполнении условий ниже |

Отрицательная проверка закрыта только при двух успешно декодированных полных streams с
разрешёнными roots/edges и без skipped/error packages. Пустой результат, отсутствие roots,
`ERROR`, `TIMEOUT`, `UNSUPPORTED`, ошибка декодирования, неполный stream или незакрытый edge
не доказывают отсутствие: observation остаётся неполным/ошибочным и не промотируется в факт.
Успешный absent-from-both результат, напротив, записывается как аудируемый COMPLETE `unknown`.
Для module-only advisory разрешён только aggregate по модульной принадлежности с пустым
`usage_subject.Package`; module path не подставляется как package path и B42 не меняется.

**Маркеры product absence (таблица валидности).** `VERIFIED` валиден только для
`usage_scope=test-only`. `VERIFIED_VENDOR_INVENTORY` валиден только для `usage_scope=unknown`
с `product_linked=false`, `test_linked=false`,
`closure_source=vendor/modules.txt+source-imports`, `closure_semantics=product_all_packages`,
`vendor_mode=true` и полным consistency-checked vendor inventory, доказывающим точное
отсутствие advisory-subject: subject отсутствует в product build closure, а для module-level
subject дополнительно отсутствует в go.mod requires/replaces, в заголовках/пакетах
modules.txt, в vendor-дереве и в first-party package set. `unknown` без валидного маркера
остаётся неопределённой классификацией absent-from-both и никогда не является негативным
доказательством. Ни один маркер не является B42 `NegativeVerification`, applicability carrier,
evidence-level carrier, safety-выводом, VEX-основанием или основанием auto-close.
Вердикт `VerifyDecision` принимает пару `unknown + VERIFIED_VENDOR_INVENTORY` наряду с
`test-only + VERIFIED` — при точной advisory-идентичности на заявленной гранулярности
(module-level entry никогда не удовлетворяется агентским пакетом), полном advisory-wide
покрытии, целостной трассе и отсутствии позитивного опровержения.

**Факт и ось.** Только `OK+COMPLETE` subject-bound observation промотируется в
`BUILD_USAGE_SCOPE` (`claim=TRUE`, scope из закрытого enum, provenance/pins/check scope).
`ProductAbsenceVerification` — собственное поле B41: `VERIFIED` только для `test-only`,
`VERIFIED_VENDOR_INVENTORY` только для `unknown` при валидных vendor-inventory условиях;
существующее B42 `NegativeVerification` пусто. Symbol-bound B41 subject запрещён.
Ось `build_usage_scope` существует только в `/3`: без фактов отсутствует; при любой `unknown`
class — `UNKNOWN`, иначе `ESTABLISHED`, `level=PACKAGE_BUILD`, `basis=deterministic`.
Валидатор пересчитывает её из фактов и отвергает mismatch; агентские claims её не заполняют.
`research-report/1` сохраняется, `/1`, `/2`, `/3` взаимно исключаются; `/1` и `/2` не получают
новых B41 полей и сохраняют legacy parse/validate/render.

**Non-carrier, не safety.** Tool отсутствует в `staticCarrierTools`; B41 не добавляет condition
или role, не закрывает ни одного условия и не повышает `evidence_level`. Ссылки на B41 запрещены
в exploitation conditions, level evidence и applicability carrier bases. Для одного package subject
`test-only` несовместим с carrier `PACKAGE_USAGE`; `PACKAGE_USAGE_LOWER_BOUND` остаётся non-carrier,
module aggregate не участвует в package equality. B42 `USED`/`NOT_USED`/`UNKNOWN` не переопределяются.
Test-only/product absence ограничены записанным build context, не доказывают runtime non-use,
отсутствие reflection/plugin/generated loading или deployment exposure и никогда не являются
`NOT_AFFECTED`, `NO_EXPLOIT_PATH_FOUND`, VEX, auto-close, `vulnerable_code_reachability=FALSE`
или `NON_APPLICABLE+SUPPORTED`. Сохраняются `REVIEW_REQUIRED`, `auto_close=false`.

### Измеренный эффект (не прогноз)

Primary 31 и retry 11: все `L2 → L2`, `evidence_level`, disposition и pins стабильны;
`usage_scope` до отсутствовал, после — 33+12 `mixed` и 2+2 `unknown` факта;
ось — 30+10 `ESTABLISHED` и 1+1 `UNKNOWN`. Specialist 18: preservation slice byte-equal,
исторические уровни `none → L2`; 17 кейсов честно не эмитят факты из-за offline `go list` errors,
единственный успешный кейс даёт `mixed`. **Ноль `test-only`**, следовательно, сохранённый корпус
не подтвердил specialist test-only ветвь и B41 не закрыт целиком. Второй полный census —
60/60 PASS после исправления projection. Маски трёх pre-existing nondeterminism sites
не исправляют tools: ingress count, may-call count и origins order вынесены в отдельный бэклог.

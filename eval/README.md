# Оценка качества и тестовый корпус (Evaluation & Benchmarks)

> **Sanitized historical captures.** Archived artifacts and development reports
> have had private paths and organization-specific labels redacted. These are
> historical captures, not fresh experiment results or byte-identical originals.
> Local payload/file pins updated during redaction identify the sanitized bytes;
> external source, model, module, image and original execution identities remain
> historical. Configure the OpenAI-compatible `custom-openai` endpoint with
> `OPENAI_BASE_URL` and credentials with `OPENAI_API_KEY` (or supply provider options
> through `--agent-config` for `izyan eval research-b1`). The default environment
> forwarding includes both variables; explicitly selected environments must too.

> **Граница recovery Tasks 8–14 (актуально).** Живой человеческий investigator один —
> `izyan triage`. `izyan research` — детерминированная evidence/proof-полоса
> без модели; исторические `/2`–`/4` воспроизводятся отдельно через
> `izyan eval research-replay` без current admission. Offline producers
> `eval/decision_ready/runner.py` сохраняют `runs.jsonl`, artifact index и summary.
> CI census вызывает tracked `eval/decision_ready/run_census.py`; provisioned
> directory содержит только immutable baseline/material inputs. Каждый вызов
> использует новый output, проверяет run/input identity и не читает report после
> command failure. Exit 1 — label drift, exit 2 — technical failure; baseline
> labels и safety gates не переписываются. См. [offline harness](decision_ready/README.md).
> B1 доступен только как `izyan eval research-b1` (evaluation control).
> Записи ниже — исторический журнал, не доказательство завершения консолидации.
>
> Current human contracts: `assessment.v3`, `decision-package.v4` с finite
> prepared branches (0–2 вопроса, unknown, ≤7 обязательных посылок), append-only
> `environment-assertion.v1` и `human-decision.v2` (comment optional). Ответ выбирает
> готовую ветвь без исследования; replay копирует review/assertion bytes без нового
> Accept/timestamp. Human result не меняет Product A, proof, completeness или VEX.
> Current research `/5` публикует canonical `finding.Project`/`requested-case.json`.
> Preservation matrix и Python smoke — не Product A corpus gate и не измерение
> R6 human time. Broad checks/regression/census и exact before/after authority
> measurement принадлежат integration owner; отсутствующие pins не заменяются
> произвольным старым бинарём. Original Task 2 report не переписывается как успех.
> Retained snapshot/advisory digests сравниваются и при прежнем path; recorded
> effective build и analysis toolchain сохраняются, fallback/mismatch — technical
> failure. Только отсутствующий optional commit (`null`/empty) нормализуется;
> nonempty identity mismatch остаётся ошибкой.
> В Phase 5 реализована независимая полоса измерений Product B (`eval vex-triage prepare/execute/score`): подготовка изолированных бандлов без утечки меток GT, фиксация провенанса исполнения (`vex-triage-run.v1`), аудит расходов токенов/стоимости, а также независимый скоринг по трем не смешиваемым осям (`triage-score.v1`: Product A authority, Product B recommendation, Automation).

### Phase 6 Task 1: local evidence smoke, not benchmark results

The `package-inventory` capability now retains full digest-bound stdout,
`PackageListRun`, package identities and effective build/scope. Inventory,
import-closure/code-absence and triage materials share the canonical strict
package-stream completeness decision. A complete package list is not complete
source, successful typed loading, a complete module graph or whole-upstream
source coverage; the vendor-only fallback keeps its narrower contract.

Focused local controls ran on 2026-10-29 (no model/network benchmark arms):

| Fixture/check | Observed result |
| --- | --- |
| `scopetestprod`, real Go listing + absence | 64 packages, 104396 raw bytes; COMPLETE absence names `sha256:6fa9ea5260bcd6f11cd00b97f8efeb04cc64b4ffbd6c51dc05aaa0522e3dfa71` |
| Independent `inventoryreplace`, local replacements | 30 product packages / 42318 raw bytes; test-only dependency absent from product closure |
| Same fixture, `with_tests=true` | 127 packages / 225832 raw bytes; test-only dependency present |
| Same fixture, `brokenload` | Complete package listing, failed typed load; no complete absence universe |
| Missing source; foreign context; truncated/error/duplicate/dangling/orphan streams | Refused as complete matching absence inventory/closure |
| Oversized inventory and code-absence persistence | Full bytes rehydrate from hash-bound sidecars; display envelopes stay bounded |
| Dependency/module/usage → inventory → absence → snapshot → original tool | Real MCP/Go calls all OK/COMPLETE; cache binds final probed identity |
| Persisted absence coverage `5` | Shared raw/run/build/snapshot validation; legacy `4`, missing/foreign/failed and re-pinned malformed graphs refuse current verification |
| Retained paired material inventories | Real test-only module fact SUPPORTS, both inventory references retained; foreign/partial/missing pairs and raw-free `TestOnly=true` refuse SUPPORTS |

The focused Task 1 command passed, as did the focused vendor/catalog/absence/
materials/persistence regressions and `go build ./...`. These are functional
evidence checks, not a corpus run, Phase 5 execution, quality score or latency
comparison.

Current code-absence coverage version `5` includes full effective build identity
inside the archived scope hash. Historical inventory-free version `4` payloads
remain historical; they are not promoted into current VERIFIED proofs. Test-only
facts are re-derived from retained measurements, never trusted from a DTO map.

### Phase 6 Task 2: bounded unreachability offline smoke

`symbol-unreachability` now requires the canonical product inventory under the
same effective build as its checked subjects. Full retained kernel/observation
payloads, not a `Complete` flag or lossy projection, gate research decisions and
Product B proposal/certificate/decision admission. Persisted admission replays
the raw inventory, every closure gate, exact locus coverage and the deadness
contract without loading source. Dead omitted checks do not refute omissions;
ordinary deadness alone remains an observation, with no automatic Product B proof.
Main evaluator verdict replay and report/export publication apply the same full
kernel predicate through `goanalysis.ValidateVerifiedNegative`, relocated from
`domain` without a compatibility shim. Candidate source scans remain prerequisites,
not proofs. Source-free serialized replay requires the NV-cited kernel, independent
build, exact explicit condition subjects and model-level deadness premise; missing,
foreign, malformed, uncited or open-gate payloads demote current authority while
leaving historical evidence and verification bytes unchanged.


The independent local-replacement fixture `unreachinventory` exercised the actual
MCP broker and bounded kernel: `Dead` was COMPLETE; adding invoked subject `Live`
was PARTIAL and could not close the advisory. The captured inventory was 42206
bytes (`sha256:8ebce0b4efb5efcd9b8ea3e796270fa1d05d513e935e90d98d9a1231bad1e2c3`),
and the closed archived observation was 79875 bytes. Replay refused missing,
foreign and re-pinned truncated inventory, flag-only payloads and open dispatch,
dynamic, dependency, gated, declaration, entrypoint and opaque/unbounded gates.
These are offline functional observations, not benchmark/model results or a
measured quality/readiness/latency improvement. Configuration writer observations
are described in the Phase 6 Task 3 section below; effective safety is not implied.


## 1. Резюме (Executive Summary)

Стенд оценки качества предназначен для непрерывной валидации точности и безопасности анализатора `vuln-analyzer` на реальных advisory и кодовой базе продуктов.

### Главные инварианты
* **`false-safe = 0`**: анализатор никогда не объявляет уязвимость безопасной (`NO_EXPLOIT_PATH_FOUND`), если есть хоть малейшая теоретическая возможность её эксплуатации.
* **Отсутствие найденного exploit path не доказывает его отсутствие**: если путь к дефекту не найден синтаксически, вердикт остаётся `UNKNOWN` или `INCONCLUSIVE`, направляя кейс на ручной триаж человеку.
* **Отрицательные вердикты строго доказаны**:
  * `NOT_AFFECTED` — только детерминистической цепочкой сборки (`go list -deps`).
  * `NO_EXPLOIT_PATH_FOUND` — только при наличии верифицированного фальсификатора (`VERIFIED Falsifier`) на обязательном условии эксплуатации.

### Ключевые метрики baseline-прогона

| Метрика | Значение | Описание |
|---|---|---|
| **Всего кейсов** | **38** | Реальные уязвимости в 12 классах зависимостей Go |
| **Cleared Rate** | **20 / 38 (53%)** | Доказанное закрытие алертов без участия человека (`NOT_AFFECTED` + `NO_EXPLOIT_PATH_FOUND`) |
| **Signal-Cleared Rate** | **9 / 27 (33%)** | Безопасное снятие алертов там, где `govulncheck` выдал шумные сигналы (`REACHABLE` / `package-level`) |
| **False-Safe Rate** | **0 / 38 (0%)** | Строгий инвариант: ни одного ложно-безопасного вердикта |
| **Требуют триажа** | **18 / 38 (47%)** | 18 / 38 (47%) доказанно уязвимых (`EXPLOITABLE`), 0 / 38 (0%) с недостаточным контекстом (`INCONCLUSIVE`) |

---

## 2. Быстрый запуск (CLI Quickstart)

### Прогон всего корпуса
Параллельный запуск всех 38 кейсов с автоматической генерацией манифестов `go.mod`/`go.sum` и переиспользованием кэша:
```bash
izyan eval --corpus eval/corpus-real.json -j 4
```

### Offline authority-delta: пара прогонов до/после

Смена авторитетных путей (Phase 3) ожидаемо снимает слабые positives, поэтому
измерение делается парой прогонов на одном корпусе: замороженный исполняемый
файл до изменения и кандидат. Сравнение офлайн, по одному прогону на ревизию:

```bash
"$IZYAN_BEFORE" eval --corpus eval/corpus-real.json --json "$MEASURE_DIR/before-real.json" -j 1
"$IZYAN_AFTER"  eval --corpus eval/corpus-real.json --json "$MEASURE_DIR/after-real.json" -j 1
"$IZYAN_AFTER"  eval compare --before "$MEASURE_DIR/before-real.json" \
    --after "$MEASURE_DIR/after-real.json" --out "$MEASURE_DIR/delta-real.json"
```

`eval compare` сопоставляет результаты по identity кейса, входа и сборки.
Несовпавший набор (кейс только на одной стороне, дубль identity, другая
сборка) — отказ, а не дельта. Отчёт перечисляет каждое направление отдельно:
потерянные/приобретённые definitive positives, потерянные/приобретённые
negatives, новые/снятые failures и переходы по каждому условию, плюс
`false_safe_gained`. Код возврата: 0 — сравнение без нового false-safe,
1 — появился false-safe, 2 — некорректные входы или несопоставимые наборы.
Потеря слабого positive — результат измерения, а не повод вернуть снятые
основания.

### Offline-сравнение сохранённого triage-пакета

`izyan eval triage` сравнивает уже сохранённый `decision-package.v4` с
явно заданным внешним контролем. Это **не** новый benchmark lane и не
live-гейт: команда не вызывает модель, не меняет пакет и не требуется
для `izyan triage`.

```bash
izyan eval triage --run <run-dir> \
    --baseline <triage-baselines.json> --out <eval-dir>
```

`triage-baselines.v1` содержит `finding_id`, `disposition`,
необязательный `expected_judgment` и `source`. Отчёт
`triage-evaluation.v1` фиксирует coverage (`ASSESSED`/`UNASSESSED`),
считает human-ошибки (reduction-предложение, negative judgment, CLOSE при
`EXPLOITABLE`) отдельно от machine `false_safe`/`unverified_reductions` и
завершается exit 1 при измеренном расхождении. Отсутствие контроля —
`UNASSESSED`, а не измеренный ноль ошибок. Результаты этого сравнения не
переписывают существующие baseline-таблицы ниже.

### Запуск и отладка отдельного кейса
Запуск конкретного сценария (занимает 5–9 секунд):
```bash
izyan eval --corpus eval/corpus-real.json --case real-jwt-auth
izyan eval --corpus eval/corpus-real.json --case real-service-plain-6443x
```

### Основные флаги
* `-j <N>` — количество параллельных воркеров (по умолчанию 1).
* `--case <ID>` — фильтрация прогона по идентификатору сценария.
* `--mem-limit <size>` — лимит оперативной памяти с watchdog-контролем (по умолчанию `4GiB`).
* `--cve-analysis <off|assist|verified>` — включение автономного AI-исследователя для формирования структурированного досье:
  * `assist`: автономный исследователь с function calling (`read_patch_diff`, `inspect_source_file`, `analyze_product_scope`) формирует техническое досье и формулирует Human Remainder (точный остаток ручной работы для эксперта);
  * `verified`: строгая валидация обязательств доказательства (Proof Obligations).
* `--strict-llm` — режим fail-fast: при ошибке LLM API или бюджетов модель не переключается скрытно на детерминистический код, а завершает кейс со статусом ошибки.
* `--non-locus-basis <file>` / `--accept-locus-proposals` — утверждение рекомендаций об исключении вспомогательных функций транспорта из дефектного локуса.
* `--deploy-manifests <path>` — пути к каталогам или архивам (`.tgz`, `.tar.gz`, `.zip`) с манифестами развёртывания (Helm/K8s/Compose) с поддержкой защиты от Zip Slip и автопоиском в типовых путях.
* `--perimeter <auto|cluster|public>` — целевой контекст сетевого периметра для разрешения вердикта: `auto` (по умолчанию, разрешает целевой вердикт по обнаруженной топологии), `cluster` (внутрикластерный периметр / доверенная инфраструктура), `public` (публичный контур / Zero Trust).
* `--audit-dir <dir>` — для каждого кейса, где сигнал govulncheck снят safe-вердиктом, пишет audit packet (`<id>.md`) с grounding falsifier, evidence IDs и рецептом ручной проверки для независимого ревьюера.

---

## 3. Бизнес-эффект: сравнение с govulncheck (Decision Impact)

Ключевая ценность `vuln-analyzer` относительно стандартного `govulncheck` — кардинальное снижение операционного шума (false positives) при сохранении абсолютной безопасности.

| Кейс корпуса | Сигнал govulncheck | Вердикт vuln-analyzer | Практический статус и бизнес-эффект для команды |
|---|---|---|---|
| **`real-service-plain-6443x`**<br>(GO-2026-6443 / gRPC authority panic) | 🔴 **`REACHABLE`** *(ложная тревога)* | 🟢 **`NO_EXPLOIT_PATH_FOUND`** *(Not Exploitable)* | **Разделение сайта дефекта и транспорта.** `govulncheck` бьёт тревогу из-за вызова `HandleStreams` в цикле сервера. Без анализатора команда вынуждена экстренно обновлять gRPC во всех сервисах. Анализатор локализует дефект в `RouteAndProcess`, доказывает отсутствие паникующего пакета в бинаре и снимает ложную тревогу с готовым обоснованием. |
| **`real-service-pkg-6443`**<br>(GO-2026-6443 / subpackage) | 🔴 **`REACHABLE`** *(ложная тревога)* | 🟢 **`NO_EXPLOIT_PATH_FOUND`** *(Not Exploitable)* | **Недостижимость дефекта внутри скомпилированного пакета.** Пакет слинкован в бинарь, но дефектный локус `RouteAndProcess` никогда не вызывается продуктом. Анализатор доказывает недостижимость через фальсификатор `locus-function-unreached`. |
| **`real-yaml-const`**<br>**`real-yaml3-const`**<br>**`real-protojson-const`**<br>(DoS парсеров) | 🔴 **`REACHABLE`** *(ложная тревога)* | 🟢 **`NO_EXPLOIT_PATH_FOUND`** *(Not Exploitable)* | **Анализ происхождения данных (Data Provenance).** `govulncheck` видит вызов `yaml.Unmarshal`. Анализатор доказывает, что входной payload — это константа времени компиляции (`const`), изолирует внутреннюю рефлексию парсера по выходной структуре и подтверждает невозможность атаки. |
| **`real-yaml-file`**<br>(GO-2021-0061 / YAML DoS) | 🔴 **`REACHABLE`** *(ложная тревога)* | 🟢 **`NO_EXPLOIT_PATH_FOUND`** *(Not Exploitable)* | **Доверенная инфраструктура.** Аргумент парсера читается из локального файла конфигурации хоста (`os.ReadFile`), что верифицировано как доверенная среда развёртывания (`trusted infrastructure`). |
| **`real-service-plain`**<br>(GO-2026-6441 / gRPC RBAC bypass) | ⚠️ **`module-level`** *(шумная находка)* | 🟢 **`NOT_AFFECTED`** *(Not Affected)* | **Детерминистический анализ сборки.** Модуль gRPC числится уязвимым в манифесте, но пакет `rbac` отсутствует в `go list -deps`. Анализатор детерминированно подтверждает неприменимость уязвимости. |
| **`real-service-plain-6443`**<br>(контроль без исключения локуса) | 🔴 **`REACHABLE`** | 🔴 **`EXPLOITABLE`** | **Консервативный контроль безопасности.** Если сайт дефекта не сужен экспертом или флагом `--accept-locus-proposals`, анализатор не делает эвристических допущений и повторяет консервативный вердикт `govulncheck`. |

---

## 4. Сводная таблица baseline-прогона (38 кейсов)

Результаты последнего прогона на автономном корпусе `eval/corpus-real.json`:

| Кейс | Вердикт анализатора | Сигнал govulncheck | Статус снятия (Cleared) и обоснование |
|---|---|---|---|
| `real-yaml-http` | EXPLOITABLE | reachable | нет — внешний сетевой ввод в unmarshal |
| `real-yaml-file` | NO_EXPLOIT_PATH_FOUND | reachable | **да — чтение локального файла конфигурации хоста (trusted infrastructure) + verified negative check** |
| `real-yaml-http-fixed` | NOT_AFFECTED | silent | **да — детерминистически безопасная версия** |
| `real-md-render` | EXPLOITABLE | reachable | нет — недоверенный ввод рендерится в HTML |
| `real-getter-fetch` | EXPLOITABLE | reachable | нет — аргумент URL передается злоумышленником |
| `real-getter-const` | EXPLOITABLE | reachable | нет — protocol-switch через `X-Terraform-Get` держит `GitGetter` достижимым |
| `real-ssh-server` | EXPLOITABLE | reachable | нет — уязвимый SSH-хэндлер активен |
| `real-ssh-keyparse` | NO_EXPLOIT_PATH_FOUND | package-level | **да — govulncheck-silence + проверка недостижимости неэкспортированных субъектов в коде зависимости** |
| `real-jose-decrypt` | EXPLOITABLE | reachable | нет — парсинг токенов без ограничений |
| `real-jwt-auth` | EXPLOITABLE | package-level | нет — **историческое измерение под неверной missing-call моделью**; GO-2020-0017 — дефектная проверка, продукт не вызывает `VerifyAudience`; см. примечание 2026-10-26 ниже |
| `real-http2-server` | NOT_AFFECTED | silent | **да — детерминистически безопасная версия** |
| `real-dns-zone` | EXPLOITABLE | reachable | нет — сетевой парсер DNS-зон достижим |
| `real-getter-file` | EXPLOITABLE | reachable | нет — file-схема подвержена инъекциям |
| `real-getter-fixed` | NOT_AFFECTED | silent | **да — детерминистически безопасная версия** |
| `real-yaml-const` | NO_EXPLOIT_PATH_FOUND | reachable | **да — compile-time константный payload + verified negative check** |
| `real-yaml3-http` | EXPLOITABLE | reachable | нет — YAML v3 уязвим к DoS на внешнем вводе |
| `real-yaml3-const` | NO_EXPLOIT_PATH_FOUND | reachable | **да — compile-time константный payload + verified negative check** |
| `real-protojson-http` | EXPLOITABLE | reachable | нет — protojson unmarshal уязвим на внешнем вводе |
| `real-protojson-const` | NO_EXPLOIT_PATH_FOUND | reachable | **да — compile-time константный payload + verified negative check** |
| `real-protojson-fixed` | NOT_AFFECTED | silent | **да — детерминистически безопасная версия** |
| `real-dns-fixed` | NOT_AFFECTED | silent | **да — детерминистически безопасная версия** |
| `real-dns-marshal` | NO_EXPLOIT_PATH_FOUND | package-level | **да — dep-internal вызовы отсутствуют, диспетчеризация через интерфейсы исключена** |
| `real-md-fixed` | NOT_AFFECTED | silent | **да — детерминистически безопасная версия** |
| `real-ssh-fixed` | NOT_AFFECTED | silent | **да — детерминистически безопасная версия** |
| `real-jose-fixed` | NOT_AFFECTED | silent | **да — детерминистически безопасная версия** |
| `real-ssh-callback` | EXPLOITABLE | reachable | нет — callback авторизации уязвим |
| `real-service-xds` | EXPLOITABLE | package-level | нет — внутренняя цепочка диспетчеризации фильтров доказана через статическое разрешение функциональных полей и method values в gRPC xDS |
| `real-service-xds-fixed` | NOT_AFFECTED | silent | **да — детерминистически безопасная версия** |
| `real-service-plain` | NOT_AFFECTED | module-level | **да — пакет rbac не входит в build graph продукта** |
| `real-service-plain-6443` | EXPLOITABLE | reachable | нет — консервативный контроль: без сужения локуса транспортный символ в трейсе считается уязвимым |
| `real-service-plain-6443x` | NO_EXPLOIT_PATH_FOUND | reachable | **да — locus-package-absent: транспортные функции исключены из локуса, дефектный xds-пакет вне сборки** |
| `real-service-xds-6443` | EXPLOITABLE | reachable | нет — xDS-режим включен, уязвимый код вызывается |
| `real-service-wrap-6443` | EXPLOITABLE | reachable | нет — xDS через фабричную обертку достигает уязвимого локуса |
| `real-service-pkg-6443` | NO_EXPLOIT_PATH_FOUND | reachable | **да — locus-function-unreached: xds-пакет в сборке, но уязвимая функция `RouteAndProcess` недостижима** |
| `real-unix-access` | EXPLOITABLE | reachable | нет — `unix.Access` вызывается на внешнем пути |
| `real-unix-stat` | NO_EXPLOIT_PATH_FOUND | package-level | **да — zero-refs: уязвимый метод `unix.Faccessat` не используется, а внутренний caller `unix.Access` мертв** |
| `real-unix-fixed` | NOT_AFFECTED | silent | **да — детерминистически безопасная версия** |
| `real-ssh-slowpesh` | EXPLOITABLE | reachable | нет — DoS медленного рукопожатия подтвержден |

**Примечание к `real-jwt-auth` (измерено 2026-10-26; модель исправлена).**
Строка `real-jwt-auth` выше — историческое измерение под удалённой
missing-call эвристикой, которая ошибочно трактовала GO-2020-0017 как
отсутствие вызова. Advisory описывает *дефектную проверку*:
`MapClaims.VerifyAudience`, вызванная с `req=false`, неверно обрабатывает
массив `aud` (string-assertion даёт `""`, и `verifyAud` принимает пустое
значение при `required=false`). Продукт `products/jwt-auth` вызывает
`ParseWithClaims`, но не `VerifyAudience`; его собственная невалидация
`aud` — отдельный продуктовый факт, а не эта CVE. Повторный прогон
исправленным пайплайном: контракт `DEFECTIVE_CHECK`, `C-OMISSION`
отсутствует. При host-default target кейс честно `FAILED`
(`CODE/REACHABILITY_PROOF_INCOMPLETE` + `CODE/TRIGGER_PROOF_INCOMPLETE`:
build-зависимый негатив не допускается без scoped-цели, а typed
trigger-witness producer отсутствует). С operator-declared `darwin/arm64`
целью, совпадающей с effective build, запись получает
`DECIDED / NO_EXPLOIT_PATH_FOUND` (`C-REACH`/`C-LOCUS` FALSE + `VERIFIED`);
`C-INPUT`/`C-CHECK-TRIGGER` остаются `UNKNOWN` и не блокируют
dead-operation негатив. `expect` в `eval/corpus-real.json` сохранён как
исторический и не переписан под новый вердикт; сравнение target-прогона с
этим label даёт `false-safe=1` только в отчёте eval и не является новым
false-safe по семантике advisory. Агрегатные baseline-метрики выше не
пересчитывались.

### Калибровка library-API scope (измерено 2026-10-25)

Изменение не трогает `eval/corpus-real.json` и его ожидания `expect`.
Ниже — точечные измеренные прогоны; полный корпус не перезапускался (это
гейт интеграционного владельца).

| Прогон | Вердикт | Область / основание | Что проверено |
|---|---|---|---|
| `real-yaml3-http` | `EXPLOITABLE` | пусто | обычное внешнее происхождение (`C-PEER-INPUT`/`C-CONSTRAINT` = `EXTERNAL_UNTRUSTED`); `library_input` в `data_flows` отсутствует, `control_basis` нет |
| `real-yaml3-const` | `NO_EXPLOIT_PATH_FOUND` | пусто | `C-PEER-INPUT`/`C-CONSTRAINT` = FALSE `constant-or-generated-input` + `VERIFIED`; `library_input` отсутствует |
| testify snapshot + `GHSA-hp87-p4gw-j4gq` (canonical) | `EXPLOITABLE` | `library-api` / `library-public-api` | witness: `YAMLEq.expected` (формальный №1) → `yaml.Unmarshal` arg 0 @ `assert/assertions.go:1573`; `YAMLEq.actual` (№2) → arg 0 @ `1577`; scope `ADVISORY_ENTRIES`/`COMPLETE`; `_codegen` исключён по владению модулем; deployment origin `UNKNOWN` |
| testify snapshot + `CVE-2022-28948` (алиас) | `EXPLOITABLE` | `library-api` / `library-public-api` | те же две привязки; scope `CVE`/`KNOWN_ONLY` (не переименован в `COMPLETE`) |

`verdict.exploitability_scope`/`claims[].control_basis` в этих прогонах
указаны ровно те, что записаны в `report.json`; оба профиля периметра
(`zero_trust`, `cluster_perimeter`) сохраняют область.

Точные сильные утверждения (persisted `case.json`/`report.json`, RU/EN
Markdown, OpenVEX, CycloneDX) закреплены Go-тестами
`internal/states/library_scope_e2e_test.go`:

* библиотека + синтетический CWE-502 advisory → `EXPLOITABLE`/`library-api`
  для canonical GHSA (`COMPLETE`) и CVE-алиаса (`KNOWN_ONLY`), с двумя
  сохранёнными witness-привязками и `UNKNOWN` deployment-происхождением;
* константные и test-only вызывающие внутри того же репозитория границу
  не закрывают;
* три потребителя одного артефакта: HTTP-тело в публичный API →
  `EXPLOITABLE` без library-области; фиксированные литералы → `NEPF` с
  `VERIFIED` негативом; импорт только из `_test.go` → `NOT_AFFECTED` с
  `TestOnlyScope`;
* отсутствие reach или locus при доказанном library-input оставляет
  `INCONCLUSIVE` без области.

**Контроль нулевого допуска (измерено 2026-10-25).** Известные ложные
тревоги и near-miss не получают ни `control_basis`, ни области вывода:

| Кейс | Вердикт | Форма | Library witness / basis / scope |
|---|---|---|---|
| `containers-podman-38ccfa2-CVE-2024-37298` | `EXPLOITABLE` | `APPLICATION` | 0 / нет / нет |
| `kubernetes-kubernetes-6d4b94f-CVE-2022-41717` | `EXPLOITABLE` | `APPLICATION` | 0 / нет / нет |
| `labstack-echo-fdacff0-CVE-2020-26160` (library-shaped, `AUTH_BYPASS`, negative GT) | `INCONCLUSIVE` (`C-INPUT` UNKNOWN) | `LIBRARY` | 0 / нет / нет |

Ни один claim не несёт `control_basis=library-public-api`, ни один
verdict/profile — `exploitability_scope=library-api`; существующие ошибки
этим изменением не «починены». Прогон выполнен через live OSV (frozen
advisory directory на машине отсутствует); на проверяемое свойство это не
влияет.

**Не измерено:** проектная оценка влияния на recall/accuracy корпуса
(единственный кейс testify в 30-кейсовом VEX-Bench) в этом изменении не
пересчитывалась — таблицы baseline выше отражают прежние прогоны.

**Примечание к `labstack-echo…` (измерено 2026-10-26; модель исправлена).**
Строка echo выше измерена под старой missing-call моделью (`C-OMISSION`
TRUE, `C-LOCUS` TRUE на `VerifyAudience`); эта модель признана неверной.
Повторный прогон исправленным пайплайном: `DEFECTIVE_CHECK`,
`C-OMISSION` отсутствует. Host-default target: `FAILED`
(`SCOPE/UNSUPPORTED_NEGATIVE_SCOPE` + `CODE/REACHABILITY_PROOF_INCOMPLETE`
для `C-REACH`/`C-LOCUS` + `CODE/TRIGGER_PROOF_INCOMPLETE` для
`C-INPUT`/`C-CHECK-TRIGGER`); build-зависимый негатив под host-default не
допускается. С operator-declared `darwin/arm64` (совпадает с effective
build) запись получает `DECIDED / NO_EXPLOIT_PATH_FOUND`:
`C-REACH` FALSE `unreached-exported-subject` + `VERIFIED`, `C-LOCUS` FALSE
`locus-function-unreached` + `VERIFIED`, `C-INPUT`/`C-CHECK-TRIGGER`
остаются `UNKNOWN`. Запрос CVE-2020-26160 при этом остаётся `FAILED /
SCOPE/UNSUPPORTED_NEGATIVE_SCOPE`: объявленный corpus отсутствует, поэтому
CVE-wide закрытие запрещено. Историческое значение в таблице сохранено.

### Калибровка provenance сборки (измерено 2026-10-25)

Отдельное изменение — допуск отрицательных выводов: build-зависимый
`FALSE`/`NOT_AFFECTED`/`NEPF` требует (1) идентифицированной scoped
сборки продукта и (2) завершённого измерения с нужным покрытием
([`how-it-works.md`](../docs/how-it-works.md) §4.5,
[`analysis-internals.md`](../docs/dev/analysis-internals.md) §3a).
30-кейсовый корпус **не** перезапускался; ниже — три закреплённых кейса,
измеренных opt-in тестом `cmd/izyan/target_provenance_calibration_test.go`
(полный ledger: [`reports/2026-10-25-evidence-target-provenance-calibration.md`](../docs/dev/reports/2026-10-25-evidence-target-provenance-calibration.md)).

| Кейс | Target-вход | Записанный target | govulncheck | Вердикт | Класс |
|---|---|---|---|---|---|
| `cilium-cilium-1228cbc-CVE-2026-35469` | нет (host default) | `host-default`, darwin/arm64 | `failed` (type-check Linux-only кода) | `INCONCLUSIVE` (`C-REACH`/`C-LOCUS` UNKNOWN) | abstained (намеренно) |
| тот же снапшот | `--goos linux --goarch amd64` | `operator-declared`/`operator`, linux/amd64 | `completed_with_results`, `./...`, advisory `covered` | `EXPLOITABLE` (`C-REACH`/`C-LOCUS` TRUE) | unchanged positive |
| `containers-podman-38ccfa2-CVE-2024-37298` | нет | `host-default` | `failed` | `EXPLOITABLE` (module-chain `C-REACH` TRUE) | unchanged false alarm |
| `kubernetes-kubernetes-6d4b94f-CVE-2022-41717` | нет | `host-default` | `completed_with_results`, `./...`, `covered` | `EXPLOITABLE` | unchanged false alarm |

Что это утверждает:

* пара Cilium показывает работу гейта: без target-входов Linux-only продукт
  не типизируется, измерение не допускается, кейс абстенируется; с явной
  платформой измеренный позитив сохраняется;
* Podman остаётся прежней ложной тревогой: её `C-REACH`/`C-LOCUS` —
  module-chain позитивы, не зависящие от govulncheck, и удалять их ради
  метрик нельзя (`C-TLS-VERIFY` при этом честно `UNKNOWN`: build-зависимый
  `zero-value-config` отклонён под `host-default`);
* Kubernetes в этом окружении **не** таймаутил (1217 s, `completed`):
  зафиксирован как неизменённая ложная тревога, а не как «исправленный»
  безопасный результат; тест допускает timeout только как infrastructure и
  никогда как safe;
* library-admission (`DESERIALIZATION` + CWE-502) не расширялся: контроли
  без допуска закреплены `TestE2ELibraryAdmissionControls`.

**Не измерено:** агрегатные safe-clear/false-safe метрики корпуса под новым
допуском — таблицы baseline выше не переписаны и не выдаются за новые
измерения.

### Калибровка scope-bound version negatives (измерено 2026-10-26)

Изменение вводит структурный гейт области запроса: точная запись
advisory закрывает finding только при `RecordExtent=FULL_RECORD` и
полной digest-привязанной переписи исходного `affected[]`
([`how-it-works.md`](../docs/how-it-works.md) §3,
[`analysis-internals.md`](../docs/dev/analysis-internals.md) §3b).
`eval/corpus-real.json` и его `expect` не менялись.

Opt-in тест `cmd/izyan/scope_version_calibration_test.go` (внешний
VEX-Bench corpus, frozen OSV, 17 задач в 8 группах; полный ledger:
[`reports/2026-10-25-05-scope-bound-version-negatives-calibration.md`](../docs/dev/reports/2026-10-25-05-scope-bound-version-negatives-calibration.md)):

```bash
PATH=$SHIM:$PATH GOMODCACHE=<module cache> \
VA_VEX_TASKS=<vex_bench_go.jsonl> VA_SNAPSHOTS=<snapshot root> \
VA_FROZEN_OSV=<frozen OSV dir> VA_CASES=<output root> \
go test -count=1 ./cmd/izyan -run '^TestScopeVersionCalibration$' -timeout 180m -v
```

| Прогон | Extent / census | Факты компонента | Вердикт | Класс |
|---|---|---|---|---|
| primary `kubernetes…e196d24-CVE-2023-44487` (CVE и точный GHSA) | `GO_PROJECTION` 22/1/21 | x/net `v0.17.0` вне диапазона; package/build `UNKNOWN` | `INCONCLUSIVE`, `under_investigation`/`in_triage`, отчёты есть | honest abstention |
| helm / rancher / istio / podman / echo (FULL_RECORD) | `FULL_RECORD` | version/package/build измерены | 2 `EXPLOITABLE`, остальные `INCONCLUSIVE` | без изменений / abstained |
| cilium target pair | `FULL_RECORD` | host-default: `UNKNOWN`; linux/amd64: covered | `INCONCLUSIVE` / `EXPLOITABLE` | unchanged positive |

Отказы (refusal) всегда называют причину: `GO_PROJECTION`/`KNOWN_ONLY`
для projected-записей, CVE-wide `Kind`, `INSUFFICIENT_SCOPE`/
incomplete measurement для build-зависимых негативов, unresolved root
cause — limitation в evidence graph. Ни один projected-негатив не
экспортируется как `not_affected`.

**Не измерено / prerequisites:** live corpus (`eval/live-corpus.json`)
требует `VA_PRODUCT_REPO` — не выполнялся (unexecuted, не pass); полный
VEX-Bench прогон не повторялся (multi-hour, диск ~96 %). Полный
`corpus-real.json` выполнен финальной интеграцией 2026-10-26
(`go run ./cmd/izyan eval --corpus eval/corpus-real.json -j 4`):
`false-safe=0`, `errors=0`, 33/38 expect-pass; пять case'ов упали на
`SNAPSHOT_PRODUCT` за 0 s без вердикта (infrastructure under `-j 4`,
не результат анализа) и прошли последовательным перезапуском 5/5 —
итого все 38 кейсов имеют expect-valid вердикт, ни один не стал
false-safe. Исторические baseline-метки выше сохранены как исторические
и не являются новыми измерениями. Изменение **не** доказывает
затронутость gRPC и **не** чинит все ложные тревоги Kubernetes/Podman;
override-флага нет.

---

## 4a. Честная разбивка добавленной ценности (B29)

Число `signal_cleared` само по себе смешивает разные классы доказательств и уровни участия человека. Eval-отчёт раскладывает его:

**По уровню экспертизы** (`signal_cleared_auto` / `signal_cleared_expert`):

* `auto` — вердикт получен без экспертного ввода (`non_locus`, `root_causes`). Только это число сравнимо с govulncheck напрямую — он тоже не получает экспертный ввод.
* `expert` — снятие опирается на записанное экспертное решение (например, сужение дефектного локуса). Ценность — инструмент как проверяющий орган экспертного решения, а не автономный вердикт.

**По классу доказательства** (`cleared_deeper` / `cleared_echo` / `cleared_affectedness`):

* `deeper` — доказательство вне контракта govulncheck: `locus-package-absent`, `package-absent`, `locus-function-unreached`, `constant-or-generated-input`, `config-feature-disabled`, `loopback-only`, `snapshot-fact-mismatch`, `trusted-infrastructure` (с `ground_basis` в выдаче).
* `echo` — фальсификатор, воспроизводящий собственный reachability-контракт govulncheck под другим вызовом: `govulncheck-silence`, `no-module-usage`, `unreached-exported-subject`. Ценно, но не является новым доказательством.
* `affectedness` — `NOT_AFFECTED` детерминистической цепочкой на сигнальном кейсе.

В JSON-отчёте (`--json`) каждый кейс несёт `falsifier`, `ground_basis`, `expert_assisted`, `evidence_ids`; markdown-таблица показывает falsifier per-case (`*` — expert-assisted).

### Границы гарантии false-safe = 0

Инвариант `false-safe = 0` верен **относительно заявленных границ анализа**, а не абсолютно. Анализатор может выдать `NO_EXPLOIT_PATH_FOUND`, не видя реального пути эксплуатации, при:

* dispatch через goroutine/channel и interface-реализации, существующие только внутри dep-кода (B11, deferred by design);
* `plugin.Open`, `unsafe`, reflect-вызовах вне детектируемых маркеров;
* неполноте `AffectedSymbols` в advisory (`KNOWN_ONLY`) — фальсификатор наследует полноту declared-множества;
* экспертных решениях `non_locus` — истинность основания вне машинной проверки;
* `declared-trust` основании периметра — заявление оператора, помечается в `ground_basis` и VEX-экспорте.

### Независимая проверка

* `izyan eval --corpus eval/corpus-real.json --audit-dir eval/audit` — audit packet на каждый signal-cleared кейс: grounding falsifier, evidence IDs, экспертный ввод и рецепт ручной проверки (`govulncheck` baseline + что смотреть для конкретного фальсификатора).
* Протокол слепой разметки для второго аннотатора: [`docs/dev/independent-review-protocol.md`](../docs/dev/independent-review-protocol.md).

---

## 5. Структура тестовых корпусов

### 5.1. Автономный корпус (`eval/corpus-real.json`)
38 сценариев на базе микропродуктов из каталога `eval/products/`. Манифесты `go.mod` и `go.sum` генерируются автоматически в `eval/.gen/<case-id>` на основе полей `module` и `deps`. Стенд полностью автономен и не требует доступа к внешним закрытым репозиториям.

Покрывает 12 классов уязвимостей:
1. **YAML DoS** (v2 GO-2021-0061, v3 GO-2022-0603) — парсинг циклических и глубоких структур;
2. **Markdown XSS / Render** (GO-2023-2074) — экранирование при генерации HTML;
3. **Command / Argument Injection** (GO-2024-2800 в `go-getter`) — инъекция аргументов протокола `git::`;
4. **SSH / Crypto** (GO-2022-0968 паника, GO-2024-3321 обход авторизации, GO-2025-3487 медленное рукопожатие);
5. **JOSE Algorithm Confusion** (GO-2023-2409) — дешифрование токенов с небезопасными заголовками;
6. **JWT Defective Audience Check** (GO-2020-0017 в `jwt-go`) — `VerifyAudience` с `req=false` неверно обрабатывает массив `aud`; продукт, не вызывающий проверку, не исполняет дефектную операцию (это не missing-call);
7. **HTTP/2 Rapid Reset** (GO-2023-2102) — DoS мультиплексирования потоков;
8. **DNS Zone Parse** (GO-2020-0028 в `miekg/dns`) — паника парсера некорректных записей зон;
9. **Protobuf Protojson Loop** (GO-2024-2611) — бесконечный цикл парсера некорректных структур;
10. **gRPC xDS RBAC Bypass** (GO-2026-6441) — дефекты применения политик доступа;
11. **gRPC xDS Authority Panic** (GO-2026-6443) — дефектный локус паники заголовка `:authority`;
12. **Unix Faccessat Privilege Check** (GO-2022-0493) — некорректный опрос прав доступа на Linux.

### 5.2. Интеграционный live-корпус (`eval/live-corpus.json`)
11 advisory против реального монорепозитория (`${VA_PRODUCT_REPO}`) и библиотеки `github.com/rabbitmq/amqp091-go` v1.10.0. Используется для валидации глубоких потоков данных на тяжелом промышленном коде с фоновыми горутинами, рефлексией и сложным маппингом конфигурации.

Запуск:
```bash
PATH=$HOME/go/bin:$PATH VA_PRODUCT_REPO=<product-repo> izyan eval --corpus eval/live-corpus.json
```

Подробная ручная разметка истинности (ground truth), доказательная база и история анализа кейсов вынесены в отдельный документ: [`eval/ground-truth.md`](ground-truth.md).

### 5.3. Корпус человеческих triage-решений (`eval/corpus-reviewed.json`)

Внешний референс-набор: решения по реальным тикетам триажа, уже разобранные человеком с обоснованием. Сырой экспорт — приватные трекер-данные и **не коммитится**; корпус генерируется локально:

```bash
REVIEWED_MAP=<map.json> REVIEWED_RAW=<export.json> python3 eval/gen_reviewed_corpus.py
izyan eval --corpus eval/corpus-reviewed.json --case rev-<id>
```

Всё, что идентифицирует источник — коды полей экспорта, имена компонентов, пути к репозиториям, таблица соответствия версий продуктов и ref'ов — находится в локальном конфиге маппинга и в сгенерированном корпусе; ни то, ни другое в репозиторий не входит. Схема задокументирована в [`eval/reviewed-map.example.json`](reviewed-map.example.json).

Механика:

* **Маппинг версий.** Версия продукта ≠ ref компонента (продукт может поставлять равный или более ранний компонентный ref): таблица `components.<name>.refs` / `default` в конфиге. Кейс пинится к ref через поле `ref` — харнесс материализует дерево `git archive` в `eval/.gen/wt-<id>`, не трогая чекаут исходного репозитория.
* **Версия Go.** Поле кейса `go_version` задаёт release toolchain (`ReleaseGoVersion`); не задано — анализатор ищет release evidence в снапшоте (`toolchain`-директива, Dockerfile, CI, `.go-version`), иначе релизная версия UNKNOWN: `go`/`toolchain` директива `go.mod` (`GoModDirective`/`MinimumGoVersion`) — только минимум языка, и stdlib-applicability/`go_version`-условия остаются UNKNOWN (вердикт не ниже INCONCLUSIVE), а не проверяются против локального toolchain.
* **Деплой-контекст.** `components.<name>.eval_overrides` в конфиге маппинга копируется в кейс — те же поля, что у CLI: `perimeter` (`auto|cluster|public`), `trusted_peer` (bool), `deploy_manifests` (пути через запятую). Так батч-прогон получает деплой-профиль микросервиса, на который опирались человеческие решения; `declared-trust`/`auto-perimeter` остаются размеченными основаниями, а не кодовыми фактами.
* **Expect.** Человеческое «не эксплуатируется» — это экспертное решение, а не машинно доказуемый факт, поэтому ожидание — безопасное множество `[NOT_AFFECTED, NO_EXPLOIT_PATH_FOUND, INCONCLUSIVE]`. `EXPLOITABLE` на таком кейсе — expect-fail и предмет разбора; `INCONCLUSIVE` честно фиксирует обоснования, недостижимые из снапшота (деплой-конфигурация, «не поддерживаемая ОС», заявления о сборке).
* **Advisory.** Публичные OSV-документы лежат в `eval/advisories/reviewed/` (коммитятся — это открытые данные).
* Кейсы без маппинга релиза генератор пропускает — покрытие расширяется добавлением ref в конфиг.

### 5.4. Граница proof capability сохранённого triage-пакета

`decision-package.v4` сохраняет три разных объекта, и offline-оценка не
должна их смешивать:

* **deadness observation** — `symbol-unreachability` observation
  (`COMPLETE`/`PARTIAL`, субъекты, snapshot/build context). Это read-only
  наблюдение: оно информирует `INTERPRETED`-посылку и человеческое
  действие, но не является proof, машинным reduction или VEX-разрешением;
* **proof request** — `falsifier_proposals` опционален; proposal называет
  claim, `condition_id`, `kind`, субъекты и наблюдение и является только
  запросом на детерминированную проверку;
* **admitted falsifier** — `VERIFIED` proof только из proposal, чей
  `condition_id`/`kind` допущен приложенным `condition-catalog.v1` и
  подтверждён verifier'ом; только он может участвовать в
  `machine_disposition`.

Если каталог не приложен, prompt фиксирует, что machine falsifier
proposals недоступны; это ограничение proof capability, а не ошибка
ответа и не repair loop. При оценке сохранённого пакета deadness
observation не засчитывается как reduction, а non-admitted proposal —
как proof. `--condition-catalog`/`--condition-catalog-hash` задают
run-pinned каталог для live-прогона; replay проверяет записанную
`prompt-input.v1`-поверхность и не реадмитит новые capability.

---

## 6. Механика доказательств и масштабируемость

### Контроль неопределенности и безопасные отрицания
* **Инвариант отрицательного вывода**: вердикт `NO_EXPLOIT_PATH_FOUND` выносится только тогда, когда опровергнуто хотя бы одно обязательное условие эксплуатации (`mandatory condition`), а отрицание подтверждено фазой негативной верификации (`Negative Verification: VERIFIED`).
* **Scope-bound closure**: любой отрицательный вывод уровня finding дополнительно требует полного покрытия области запроса — `ADVISORY_ENTRIES`/`COMPLETE`/`FULL_RECORD` и digest-привязанной переписи всех исходных `affected[]` entries ([`analysis-internals.md`](../docs/dev/analysis-internals.md) §3b). Module/version-негативы независимы от build-target допуска, но не от этого гейта: projected-запись (`GO_PROJECTION`) оставляет finding открытым (`INCONCLUSIVE`), сохраняя компонентные факты. Legacy `COMPLETE` без структурной переписи не закрывает (fail closed).
* **Lane-owned symbol proof (B53a)**: детерминистический лейн сам диспатчит bounded `symbol-unreachability` proof, когда advisory объявляет точные symbol-субъекты и applicability даёт module-present=TRUE + version-affected=TRUE. Полный audit-bound proof → `NO_EXPLOIT_PATH_FOUND`/`COMPLETE` без агента и decision artifact; использованный символ, неполный proof, gated-ссылка, ошибка или таймаут → `INCONCLUSIVE` (никогда `NOT_AFFECTED`). `decision.reason` в этом случае несёт вывод самого примитива, а не общую фразу о trace: «is disproven: N product reference(s) and M module-internal chain(s) reach the declared subject(s)», «is UNKNOWN: K open limitation(s)» с перечислением открытых ограничений из payload, либо именованный статус/ошибку проверки; то же утверждение дублируется в `decision.limitations`. Module-only advisory ведёт себя как раньше.
* **Идентичность прежде отсутствия**: отсутствие допускается только для субъекта, чья идентичность установлена в исходниках выбранной версии. Fix-derived кандидат, чей patch-coordinate не резолвится по тому же module-relative пути (vendor или module cache ровно на записанной версии), — `UNMAPPED`, а не `Absent`: его отсутствие в продуктовом closure ничего не доказывает, он остаётся положительно-блокирующим, а кейс завершается `FAILED` с `CODE / ROOT_CAUSE_UNRESOLVED / ROOT_CAUSE`. Сохранённый NEPF на таких субъектах не пере-допускается при публикации (история сохраняется); совпадающее имя функции, суффикс пути или литерал идентичность не доказывают. См. § 13.30.
* **Отсутствие сабпакета модуля — факт, а не амбивалентность**: кандидат корневой причины, чей пакет отсутствует в допущенном полном `go list -deps` снапшота, резолвится как `RootCause.Absent` (код дефекта не включён в сборку), а не как провал верификации. Отсутствие решается **до** поиска в dep source: символ, найденный в module cache/vendor, но не входящий в продуктовый closure, всё равно `Absent`, и кандидат цитирует evidence id инвентаря; ошибка загрузчика отсутствием не является. `SymbolReachable`/`ArgumentOrigin` выносят `FALSE package-absent`, когда все пакеты субъектов вне графа сборки; отсутствие подтверждается по persisted package-list evidence с учётом build-context (теги/GOOS/GOARCH/cgo). Символ, не найденный в *присутствующем* пакете, остаётся `Unverified` и модель неполна.
* **Состояния кандидатов в диагностике**: лимитации сокращённой exploit-модели называют раздельно source-verified, package-absent, source-absent и unverified кандидатов и их происхождение (advisory-declared субъект vs fix-derived кандидат). Верифицированное отсутствие не описывается как «unresolved in source» и не делает модель incomplete самим фактом присутствия в positive-blocking списке.
* **Ключевые факты отчёта не повышают неизмеренное**: строка включения пакета в сборку показывает `Included` только при `PackagePresent=TRUE`; при `UNKNOWN` (и незаписанной оси) выводится «наличие не измерено», а не положительный факт.
* **Субъектно-ориентированная непрозрачность и инстанцирование рефлексии (B19)**:
  В кейсе `ghsa-465g-fh3v-9jw4` (URI confusion) внутренние вызовы зависимостей считаются непрозрачными только если они потенциально достигают дефектного субъекта. Маркер `reflect_method` в негативной верификации фильтруется по наличию инстанцирования типа ресивера (`amqp091.URI`) в продукте или коде зависимостей: отсутствие созданных экземпляров типа не позволяет динамическому вызову опровергнуть безопасность отрицательного условия, подтверждая вердикт `NO_EXPLOIT_PATH_FOUND`.

  #### Эволюция отчёта анализатора (Case Study: GHSA-465g):
  * **До закрытия B19 (`INCONCLUSIVE`):**
    - `C-ROUNDTRIP`: `UNKNOWN` (ограничение: *«pair member(s) ... not statically reached; module dispatch is opaque (func values/dynamic dispatch)»* из-за сетевого диалера и вызовов `error.Error()` в кодовой базе зависимости).
    - `Negative Verification`: даже при потенциальном FALSE общий маркер `reflect_method` в коде продукта порождал ограничение *«reflect method dispatch usage in product widens the call graph»*, приводя к демоции вердикта.
    - **Итог отчёта:** *«Требуется ручной анализ (Inconclusive)»*.
  * **После закрытия B19 (`NO_EXPLOIT_PATH_FOUND`):**
    - `ModuleInternalReach`: доказано, что ни один непрозрачный сайт в `amqp091-go` (сетевые диалеры с сигнатурой `func(string, string) (net.Conn, error)`, дедлайны `SetDeadline`) не совместим по сигнатуре/интерфейсу с методом `URI.String() func() string`. Вызовы predeclared-функций (`error.Error()`) корректно классифицированы как статические. Непрозрачность снята (`opaque = false`).
    - `Negative Verification`: проверено, что именованный тип `amqp091.URI` продуктом не инстанцируется (нет композитных литералов, `new()`, `make()`, явных переменных или возвратов вызываемых API). Динамический вызов метода через `reflect.Value.MethodByName` физически не имеет объекта в памяти. Маркер `reflect_method` отфильтрован без внесения ограничений (`Status: VERIFIED`).
    - `C-ROUNDTRIP`: подтверждён результат **`FALSE`** с фальсификатором `missing-pair-member` на обязательном условии.
    - **Итог отчёта:** чёткий аудируемый вердикт **`NO_EXPLOIT_PATH_FOUND`** (0 fail, 0 false-safe). Раздел `## Резюме` формирует готовый комментарий для закрытия тикета безопасности без необходимости отвлекать инженеров на ручной триаж.
* **Учёт платформы и тулчейна Go (B18)**:
  В кейсе `ghsa-33mj-cw25-m34h` (weak TLS / MinVersion) уязвимость проявляется только при сборке устаревшими компиляторами Go (< 1.18). Анализатор классифицирует дефект как `CRYPTO_DOWNGRADE`, динамически извлекает ограничение версии тулчейна из advisory и формирует обязательное платформенное условие `C-PLATFORM` (`go_version: "<1.18"`). При анализе продукта с современной версией Go (`go1.26.1`, полученной из бинарных метаданных, тикета или окружения) условие детерминированно опровергается (`FalsifierSnapshotFactMismatch`), подтверждая безопасный вердикт **`NO_EXPLOIT_PATH_FOUND`** (0 fail, 0 false-safe). Условие **условное**: floor добавляется только когда advisory сам объявляет TLS minimum-version boundary и resolved root cause не является SSH-механизмом; SSH Downgrade (Terrapin) его не получает, а `go.mod`-минимум/локальный toolchain никогда не подменяют release fact.
* **Контракт семантики дефекта: omitted vs defective check**:
  `real-jwt-auth` — не missing-call. GO-2020-0017 требует вызова
  `MapClaims.VerifyAudience` с `req=false`, где массив `aud` ошибочно
  принимается; продукт вызывает `ParseWithClaims`, но не `VerifyAudience`,
  поэтому дефектная операция не исполняется, а отсутствие собственной
  проверки аудитории в продукте — отдельный факт. Билдер выводит один
  типизированный контракт (`DEFECTIVE_CHECK` / `OMITTED_CHECK` /
  `UNRESOLVED`) из advisory/fix-доказательств; имя проверки и живой
  sibling-конвейер только номинируют кандидата и семантики не дают.
  Доказанная мёртвость контрактной проверки опровергает обязательный вызов
  только под `DEFECTIVE_CHECK`; под `OMITTED_CHECK` дефектный локус — это
  omission-site на якорном конвейере, а не отсутствующая проверка. Любой
  deadness-негатив требует допущенной invocation-necessity premise и
  scoped product target; `UNRESOLVED` не даёт ни позитивного, ни
  отрицательного вердикта и завершается `CODE/ROOT_CAUSE_UNRESOLVED`.
  Измерено 2026-10-26: host-default → `FAILED`; operator-declared
  `darwin/arm64` → `DECIDED / NO_EXPLOIT_PATH_FOUND` для точной записи
  GO-2020-0017 (dead-operation unreachability).
* **Защита константных данных от рефлексии парсеров**:
  В кейсах `real-yaml-const`, `real-yaml3-const`, `real-protojson-const` входные байты строго доказаны как компиляторные константы. Рефлексивные операции парсера по заполнению выходной структуры изолируются и не аннулируют неизменяемость входных данных.
* **Доверенная инфраструктура**:
  В кейсе `real-yaml-file` доказано, что входные данные поступают исключительно из локального файла конфигурации хоста через `os.ReadFile`. При отсутствии внешнего контроля над путем к файлу это признается доверенной средой (`FalsifierTrustedInfrastructure`).
* **Контекстная критичность и триаж CVE с номинальным CVSS 10.0 (B33)**:
  Вместо формальной блокировки релизов из-за номинальной оценки сканеров CVSS 9.8–10.0 (Blocker) детерминированный движок триажа (`internal/risk`) сопоставляет уязвимость с реальной архитектурой и сетевой экспозицией продукта:
  - При `NOT_AFFECTED` или `NO_EXPLOIT_PATH_FOUND` риск полностью снимается (`Priority: DISMISSED`, `Level: NONE`, `Score: 0.0`, SLA: None, блокировка релиза снимается с доказательным обоснованием).
  - При `EXPLOITABLE` на публичном сетевом интерфейсе (`0.0.0.0`) без аутентификации номинальный риск подтверждается как экстренный блокер (`P0 Blocker`, SLA 24h, `Level: CRITICAL`, `Score: 10.0`).
  - При наличии обязательной аутентификации перед уязвимым контуром приоритет понижается до `P1 Critical` (SLA 7 дней, `Score: 7.5`).
  - При локальной изоляции (`127.0.0.1` / loopback) либо в CLI-утилитах без слушателей приоритет детерминированно понижается до `P2 Medium` (SLA 30 дней / плановый спринт, `Score: 4.5`).
  - Во все генерируемые отчёты (`report.md`, `report.json`) включается сводная таблица триажа с аудируемым обоснованием для команд ИБ и разработки.
* **Конфигурационные условия и сетевой периметр Service Mesh (B6)**:
  - **Разрешение сетевых адресов из конфигураций**: детерминированное извлечение адресов слушателей (`net.Listen`, `http.ListenAndServe`) не только из строковых литералов, но и из полей структур конфигурации (`cfg.ListenAddr`, `s.Port`) и пакетных переменных (`var defaultAddr = ...`).
  - **Service Mesh & Istio периметр**: сканирование манифестов Kubernetes и Istio (`AuthorizationPolicy`, `RequestAuthentication`, `Service: ClusterIP`) классифицирует трафик как закрытый внутрикластерный/loopback (`ScopeLoopback`), позволяя безопасно опровергать публичную экспозицию `C-EXPOSURE` (`scope: public`) с фальсификатором `loopback-only` (`NO_EXPLOIT_PATH_FOUND`).
  - **Фича-тогглы и отсечение мёртвого кода**: ветвления под статически выключенными конфигурационными флагами (`if cfg.EnableFeature` при значении `false` или zero-value bool) классифицируются как мёртвый код (`site.DeadCode = true`). Если все пути вызова уязвимого символа перекрыты отключенными флагами, условие `C-REACH` опровергается с фальсификатором `config-feature-disabled` (`NO_EXPLOIT_PATH_FOUND`). Если флаг динамический, условие помечается уточнением `conditional-reachability`.
* **Двухконтурная оценка угроз (Dual-Track Perimeter) и внешние манифесты (B34)**:
  - **Универсальный сканер манифестов (`ScanDeployWithOptions`)**: принимает путь через `--deploy-manifests` (каталог, внешний GitOps-репозиторий или архив чартов `.tgz`, `.tar.gz`, `.zip`) с безопасной распаковкой (защита от Zip Slip) и автоматическим обнаружением чартов в стандартных директориях (`deploy/`, `helm/`, `deployments/`, `manifests/`).
  - **Классификация периметра (`ClassifyPerimeter`)**: анализирует сетевую экспозицию сервиса (наличие `ClusterIP`, Istio `AuthorizationPolicy`, отсутствие внешних `Ingress` / `NodePort` / `LoadBalancer` и опубликованных портов `compose:published-port`), формируя классификацию `cluster-internal` либо `public`. Deploy-факты атрибутируются продукту по `owner` (имя ресурса/сервиса/чарта, требуется точное совпадение с идентификатором продукта): чужие и one-prefix-соседние манифесты из GitOps-бандлов не засчитываются, их объекты внешней маршрутизации удерживают `unknown`. `cluster-internal` требует структурного доказательства (атрибутированный ClusterIP или только loopback/unix listeners); mesh-политики и исходящие вызовы — только корроборация.
  - **Двухконтурная оценка угроз (Zero-Trust vs Cluster Perimeter)**: для каждого анализа формируется параллельная матрица профилей:
    - `zero_trust`: модель недоверенного пира (Hostile Peer) / публичной сети; вход пиров не признаётся доверенным.
    - `cluster_perimeter`: модель доверенной инфраструктуры кластера; при отсутствии публичных маршрутов к брокеру/сервису вход пиров верифицируется как доверенный (`FalsifierTrustedInfrastructure`), снимая обязательные условия эксплуатации (`C-PEER-INPUT`, `C-CONSTRAINT`) и разрешая вердикт в безопасный `NO_EXPLOIT_PATH_FOUND` с приоритетом триажа `DISMISSED`.
  - **Автоматическое разрешение целевого вердикта**: при `--perimeter auto` (по умолчанию) целевой вердикт анализатора автоматически выбирает кластерный профиль при обнаружении кластерной изоляции (`EV-PERIMETER-CLUSTER`), снимая необходимость ручного указания `--trusted-peer`.
  - **Матрица сетевых периметров в отчётах**: раздел `### Матрица сетевых периметров угроз` в `report.md` и консольном выводе визуализирует вердикты и приоритеты для обоих контуров с рекомендациями для команд разработки и ИБ.

* **Целевые P0 safety-регрессии (unit, не benchmark)**:
  Три доказанных механизма false-safe закрыты детерминированными
  регрессиями, которые проверяют изменение именно первого ошибочного
  scope/model-решения, а не только терминальной метки:
  - `TestP0PartialAdvisoryReachesRootCause` (k8s-44487): CVE-wide запрос
    при `KNOWN_ONLY`-coverage и одном исправленном компоненте больше не
    завершает конвейер до `RESOLVE_ROOT_CAUSE`; компонентный version fact и
    второй advisory-entry сохраняются, итог — `INCONCLUSIVE`, не NA/NEPF.
  - `TestP0SSHDowngradeCannotCloseOnTLSFloor` (podman-48795): ни
    deterministic, ни LLM-augmented builder не добавляет TLS-floor для SSH
    root cause; `MinimumGoVersion=1.20` и отдельный `ReleaseGoVersion=1.20`
    не закрывают кейс через автоматически созданное условие; explicit
    optional (`supporting`) VERIFIED FALSE не является основанием NEPF.
  - `TestP0ReviewerRemovesLegacyTLSBlocker`: explicit `demote` снимает
    mandatory `C-PLATFORM`, claim/NV-история сохраняется, оставшиеся
    UNKNOWN дают `INCONCLUSIVE`, а подтверждение оставшихся TRUE даёт
    `EXPLOITABLE`, а не прежний NEPF.
  - `TestReportScopeAndConditionRepair*`: `report.json` сохраняет
    requested/resolved scope, action, supporting membership и NV history;
    RU/EN различают «компонент fixed» и «запрос не закрыт»; condition
    repair показан как изменение mandatory/supporting, а не как
    опровержение факта версии; partial case экспортируется как OpenVEX
    `under_investigation` / CycloneDX `in_triage`, а exact-entry negative
    control сохраняет `not_affected`.
  - `TestScopeVersionMixedRecordRegression` (k8s-44487): реальный intake
    документа с 22 entries даёт `GO_PROJECTION`/`KNOWN_ONLY`, census
    22/1/21; `v0.17.0` остаётся вне диапазона, package/build — `UNKNOWN`;
    вердикт `INCONCLUSIVE`, оба профиля и research-проекция не публикуют
    закрытие; persistence round-trip сохраняет перепись; gRPC-entry не
    синтезируется. Смежные доменные/резолверные/отчётные регрессии
    (`internal/domain`, `internal/affected`, `internal/evaluator`,
    `internal/report`, `internal/research`) закрепляют legacy fail-closed
    и единый гейт на каждой поверхности закрытия.

  Это регрессии *поведения и представления*, а не измерение полноты:
  исторические метрики ниже не пересчитаны, и прохождение этих тестов не
  объявляет восстановленный recall или SCR.

### Масштабируемость и защита от OOM (Memory Management)
Для исключения зависаний и переполнения памяти при сканировании крупных зависимостей (например, `go-getter`, `grpc`, `crypto`):
1. **LRU-эвикция AST**: синтаксические деревья пакетов зависимостей загружаются точечно и выгружаются из памяти при превышении квот (≤40 пакетов / ≤500 файлов), очищая связанные деревья типов.
2. **Ограничение комбинаторного взрыва графа вызовов**: кэш классификации вызовов (`classifyCache`) сворачивает экспоненциальный fan-out трассировки (время анализа `yaml-file` снижено с 413с до 8с).
3. **Лимиты fan-out и бюджетов**: попозиционный бюджет выражений и бюджет сессий трассировки (`evalBudget`) защищают анализ от зацикливания.
4. **Watchdog памяти**: фоновый процесс с порогом `--mem-limit` (по умолчанию 4GiB) выполняет принудительный возврат неиспользуемых страниц памяти операционной системе (`debug.FreeOSMemory()`).

---

## 7. VEX-Bench External Baseline (оркестратор)

`eval/vexbench_baseline.py` — чистый оркестратор External Baseline 1
(план `docs/dev/plans/2026-10-07-vexbench-baseline-plan.md`, Python 3
stdlib, без собственного анализа). Пять подкоманд, разделённых по ролям:

| Подкоманда | Делает |
|---|---|
| `acquire` | Пин-клон `jonathansloth/vex-bench@<40-hex sha>` (depth-1 fetch + `rev-parse HEAD` == pin), фильтр `metadata.language=="go"` (case-insensitive), сверка состава подмножества (30 задач/28 снапшотов/15 репо/24 CVE/GT-классы), скачивание снапшотов через temp-каталог + `os.replace` в `repos/owner/repo/sha`, удаление `.git`, read-only bits, `tree-integrity/<key>.json` + `t1` content hash (порт `repository.ContentHash`). Идемпотентность — только по валидной manifest-записи `ready`+digest. |
| `preflight` | Disk gate (≥25 GiB, warning <40), RAM-предупреждение, проверка всех снапшотов (immutable + contained + path-replace + `vendor/modules.txt`), заморозка `run-manifest.json` (sha256 toolchain/изyan, whitelisted Go-env, workers, deadline). `--out` обязан быть новым/пустым. |
| `run` | Per-case изолированные subprocess-запуски `izyan eval vex-bench -j 1 --case <id> --out attempts/<id>/raw`, atomic ledger `pending→running→finalized` (fsync до exec), process-group kill по дедлайну манифеста, SIGINT/SIGTERM → стоп admission + SIGTERM группе (второй сигнал — SIGKILL), диск-мониторинг (<5 GiB стоп admission, <2 GiB аварийный стоп, `disk_pressure`). `--resume` пропускает ВСЕ finalized (включая failed/abstain), валидирует fingerprint+digests, `running` без полного packet → инфраструктурный `failed`, partial raw сохраняется. |
| `report` | Офлайн-join `attempts/*/raw/**` + пиннед labels → `metrics.json` (знаменатели 30/7/23, `status_correct`/`reason_correct` раздельно), `compatibility-metrics.json`, `cases.jsonl`, `disagreements.jsonl`, `review-needed.jsonl`, `raw-checksums.json`, freeze → `baseline-frozen.json`. |
| `validate-review` | Проверка `scoring/failure-taxonomy.jsonl`: покрытие каждого review-required кейса, enum из плана §9, existence+digest evidence paths. |

```bash
python3 eval/vexbench_baseline.py acquire --worktree <wt> --benchmark-dir <dir> \
    --benchmark-sha <40hex> --repos-dir <repos> --manifest <ctl/acquisition.json>
python3 eval/vexbench_baseline.py preflight --worktree <wt> --benchmark-dir <dir> \
    --repos-dir <repos> --acquisition <ctl/acquisition.json> --out <OUT> \
    --izyan ./izyan --analysis-go 1.26.1 --mem-limit 4GiB --workers 3 \
    --case-timeout-seconds 7200
python3 eval/vexbench_baseline.py run --manifest <OUT>/run-manifest.json [--resume]
python3 eval/vexbench_baseline.py report --manifest <OUT>/run-manifest.json
python3 eval/vexbench_baseline.py validate-review --manifest <OUT>/run-manifest.json
```

Тесты — синтетические фикстуры (без сети и анализа):
```bash
python3 -m unittest eval.vexbench_baseline_test -v
```

Benchmark provenance раннера (`--out`): `provenance/osv-fetches.jsonl` +
`provenance/osv/<sha256>.json` на задачу (точные UTC start/finish, requested/
resolved ID, байт-идентичные тела, rejected/alias fetch'и) и расширенный
блок `provenance` в `metrics.json` (`adapter_version=2`, commit sha + dirty,
digests изyan/go/govulncheck/tasks, env матрица GOOS/GOARCH/CGO/tags,
`llm_calls`/`tokens`). Ошибка захвата — явный `env.error`, не silent.

Результат первого прогона (baseline A, false-safe = 1): [`baselines/vexbench/external-baseline-1.md`](baselines/vexbench/external-baseline-1.md).
Safety-aware: Safe Clear Rate 10/23, EXPLOITABLE recall 2/7, INCONCLUSIVE 40 %,
completion 28/30. False-safe — `kubernetes@e196d24` CVE-2023-44487: OSV-документ
покрывает только `x/net` (уже исправлен), реальный уязвимый компонент —
`google.golang.org/grpc v1.55.0`. Два `failed` — production panic в
`ingressScan` (исправлен после baseline). Набор теперь external regression
benchmark (спека §49).

---

## 8. VEX-Bench Plain Agent — offline reporter (сторона B)

`eval/vexbench_plain_report.py` — офлайн-репортер для plain-agent прогона
официального harness (план `docs/dev/plans/2026-10-08-vexbench-plain-agent-plan.md`
§7). Не вызывает модель и runner, не меняет raw/official metrics/GT, baseline-dir
читается строго read-only.

Две **раздельные именованные** проекции, не смешиваемые:

| Проекция | `uncertain` | missing/failed | Источник |
|---|---|---|---|
| safety-aware | abstain → INCONCLUSIVE, никогда не safe claim и не completion-failure | outcome `failed`, FN при exploitable GT | `safety-metrics.json`, `safety-cases.jsonl` |
| compatibility (official) | `not_exploitable` | `FAILED` — не успешный negative | официальный `metrics.json` + офлайн-пересчёт в `compatibility` блоке |

False-Safe считается только как `GT exploitable ∧ outcome=safe`; знаменатели
фиксированные 30/7/23 на repeat (observed записываются отдельно). Агрегация —
per-repeat векторы → mean ± sample std (ddof=1); pooled 90-row ratio —
secondary и явно помечен; pooled F1 / majority vote не выдаются за repeat mean.
Официальный `binary.totals.fn` не включает cell exploitable→FAILED — recall не
пересчитывается через него.

```bash
python3 eval/vexbench_plain_report.py \
  --parsed <EXP>/vex_bench/parsed.jsonl \
  --official-metrics <EXP>/vex_bench/metrics.json \
  --raw-root <EXP> \
  --baseline-dir <frozen Baseline 1 dir> \
  [--run-log run.log] [--docker-events docker-events.jsonl] \
  [--provenance provenance.json] \
  --out <report dir>
```

Выходы: `safety-cases.jsonl`, `safety-metrics.json`, `comparison.md`
(таблица §43: A — из frozen Baseline 1, B — прогон, Shadow/Hybrid = not run),
`telemetry.json` (coverage-статусы: `steps` ≠ tool calls — считаются
`item.completed` по `item.type` из raw `result.jsonl`; missing → `unavailable`,
не ноль), `freeze-checksums.json` (sha256 входов и выходов).

Тесты — синтетические фикстуры:
```bash
python3 -m unittest eval.vexbench_plain_report_test -v
```

---

## 9. VEX-Bench Plain Agent — субагентные baseline B2/B3 (сторона B)

Помимо официального harness (B1, §8), сторона B измерена через **omp subagent**
харнес: один свежий субагент на кейс, получающий только CVE + путь к снапшоту,
с полным toolset (`bash`/`read`/`grep`/`web_search`) и нативным agent loop
рантайма. Тот же официальный prompt `vuln` (`/tmp/vexbench-plain/official-prompt.txt`),
те же 30 кейсов и GT, что у A и B1.

Отличие B2↔B3 — **только модель**:
- **B2:** `gemini-3.8-flash-high` (модель сессии).
- **B3:** `custom-openai-custom/Qwen/Qwen3.6-35B-A3B` (корпоративный контур, `--model` в `task`).

Метрики safety/compatibility считаются тем же офлайн-скорингом, что и для A:
`GT exploitable ∧ negative-category → False-Safe`, знаменатели 30/7/23.
A — 1 frozen run; B2/B3 — 1 repeat; B1 — 3 repeat **того же корпуса** (не 90 независимых кейсов).
Aggregation: mean ± sample std (ddof=1); counts и rates раздельно.

Итог (n=30, 1 repeat): [`baselines/vexbench/plain-agent-baseline-1.md`](baselines/vexbench/plain-agent-baseline-1.md).

| | A: Izyan | B1: Codex | B2: Gemini (contam.) | B2-ISO: Gemini (Docker) | B3: Qwen3.6-35B-A3B |
|---|---:|---:|---:|---:|---:|
| Повторов | 1 | **3** (90 attempts) | 1 | 1 *(retry-composite)* | 1 |
| Изоляция GT | — | ✅ Docker | ❌ загрязнён | ✅ Docker | ❌ хостовый |
| Усечено фильтром | — | 0/90 | 0/30 | **3/30** | 0/30 |
| False-Safe (из 7) | 1 | 1 | 1 | 1 | 1 |
| Safe Clear Rate (из 23) | 43.5 % | 97.1 % | 100 % | **100 %** *(official: 91.3 %)* | 82.6 % |
| EXPLOITABLE recall (из 7) | 28.6 % | 85.7 % | 85.7 % | **85.7 %** *(official: 57.1 %)* | 85.7 % |
| Binary F1 | 0.333 | 0.901 | 0.923 | **0.923** *(official: 0.727)* | 0.706 |
| False-alarm | 3 | pooled 1/90 | 0 | 0 | 4 |

**Ключевой результат:** **три уникальных** False-Safe case ID: `k8s-e196d24` (A, B3),
`rancher-4dc4f53` (B1, B2-contam.), `podman-6a65597` (B2-ISO). На номинальный repeat —
по одному на режим. Codex проследил путь `git.go→injectAgent→ServeAgent:136`, ошибся
в configuration-gate (`ClientSecret`); Gemini (contam.) — protocol/input-boundary denial;
B2-ISO Rancher-ответ усечён фильтром (trace в нём нет — восстановлена только категория).

**Safety-gate не проходит ни один режим** (включая обе Qwen-конфигурации — у каждой есть
counterexample в probes, §9.6 отчёта). Разделение ролей — **гипотеза**, не доказанный результат: измерений Hybrid нет,
**Ни один режим не проходит safety-gate.** Qwen3.8 one-shot `0/7` — historical single-pass; probes
дали counterexamples: `k8s-3121` FS 2/3 (stability, после parser-repair) и 4/5 (risk). Qwen3.6 — 2/5
на `rancher`. Также обнаружен **дефект harness-парсера** (string-unaware brace-count), теряющий полный
валидный JSON; post-hoc parser-repair — отдельная проекция (отчёт §9.2–9.3). `False-Safe = 0` / `SCR > 90 %` — цели валидации. Наблюдаемые counts равны 1 в обеих
B2-конфигурациях; вклад изоляции/runtime/случайности **не разделён** (ablation нет).

> **⚠ Contamination (P0).** Субагенты B2/B3 бегут на хосте; каталог
> `/tmp/vexbench-baseline/` содержит `go-tasks.jsonl` и `vex_bench.jsonl` с полями
> `ground_truth`/`ground_truth_category`. **B2 (Gemini): 11 из 29 транскриптов
> содержат фактическое значение GT** (все 11 совпали с GT по точной категории,
> GT прочитан до вердикта); `B2_08_rancher47914` дополнительно читал транскрипты
> соседних кейсов. **B3 (Qwen): 0 из 30. B1 (Codex): чист по построению** —
> контейнер создаётся `docker create` + `docker cp` снапшота, хост-пути не
> bind-mount'ятся (`src/evaluate/agents/base.py:43`). Следствие: числа B2
> публикуемы только как дескриптивный **неизолированный host-run**, не как строгая
> слепая оценка. Для blind-статуса нужен отдельный изолированный прогон.

### 9b. Изолированный перепрогон Gemini (B2-ISO)

Gemini прогнан через **официальный harness** (адаптер `opencode`) в **disposable Docker**
контейнере, как B1: GT, истории агентов и каталоги результатов с хоста **не монтируются**
(монтируется только read-only config провайдера). Внутри `/tmp/vexbench-baseline` и
`go-tasks.jsonl` отсутствуют.

**Три числа, которые нельзя смешивать:**

| | Значение |
|---|---|
| Официальный harness | completion **26/30**, FAILED **4**, accuracy 83.3 %, SCR 91.3 %, recall 57.1 % |
| RECOVERY-проекция | completion **30/30** *(coverage labels)*, FAILED 0, accuracy 96.7 %, SCR 100 %, recall 85.7 % |
| Усечено safety-фильтром | **3/30** в финальном наборе |

**RECOVERY** — вторичная post-hoc **label-only** проекция: у 3 ответов фильтр оборвал
`reasoning` **после** напечатанного `category`; категория извлекается GT-blind правилом
(regex + whitelist 12). Восстанавливается **только категория** — не `reasoning`,
не предполагаемое продолжение. **30 labels ≠ 30 полноценных ответов.**

**⚠ Attempt policy:** 7 кейсов переисполнены под тем же `run_001` — это
**retry-composite exploratory**, не first-attempt baseline. План
`docs/dev/plans/2026-10-08-vexbench-plain-agent-plan.md` запрещает outcome-driven retries.

**Фильтры внешней модели (наблюдение):** 3/30 финальных ответов Gemini усечены её
safety-фильтром (`"This request was blocked by Gemini's filters"`). Контур должен
обрабатывать такой refusal **fail-closed**. **Не измерено:** лечится ли промптом,
стохастичность, преимущество self-hosted. Refusal ≠ `uncertain` (отклонение запроса vs
нехватка доказательств); категория до обрыва **не** доказывает достаточность доказательств.

> Оговорка по отброшенному прогону: первая попытка B3 использовала самописный
> Python runner (`max_steps=8`, без `web_search`) — **другая, ограниченная
> конфигурация**. strict correct-status = 11/30 = 36.7 %; official-compatible
> Accuracy (при `uncertain→not_exploitable`) = 22/30 = **73.3 %** — это разные
> метрики. 24 строки `steps=8` (из них 15 с non-`uncertain` категорией), 6
> `uncertain` завершились раньше, `TIMEOUT_STEPS` ровно 1/30. Вклад harness и
> модели **не разделён** (ablation не проводился); отброс основан на фиксированном
> критерии несопоставимости (toolset/step-limit), не на accuracy. Артефакт:
> `/tmp/vexbench-plain/b3-qwen-python-harness/`.

---

## 10. Task 4 C1 — Shadow Agent + Evidence Tools (`eval/c1/`)

Control plane эксперимента C1 (Codex + `izyan` MCP evidence tools) по
спеке `docs/dev/specs/2026-10-08-task4-agent-evidence-tools-v2.md` и плану
`docs/dev/plans/2026-10-08-task4-c1-implementation-plan.md` (§3, подзадача 4.2).

| Модуль | Назначение |
|---|---|
| `eval/c1/protocol.py` | Источник истины для промптов: общий assessment/reporting-блок (B1' и C1) + tool-contract блок (только C1). `python -m eval.c1.protocol eval/vexbench-prompts` регенерирует frozen-файлы. |
| `eval/c1/assessment.py` | Pydantic-схема `AgentAssessment`: модельное содержимое (root_causes, claims TRUE/FALSE/UNKNOWN, counterexample_review, verdict_estimate) строго отделено от controller metadata (версии, затраты, tool executions — штампует контроллер). Проверки: schema, category↔estimate, evidence-ref формат и разрешимость по audit-trail, запрет overwrite. |
| `eval/c1/status.py` | `status.json`: раздельные `execution` / `official_parse` / `assessment_schema` / `parser_audit` + `overall` (`valid`/`failed`) с машиночитаемым `failure_reason`. Refusal/timeout/transport/invalid → `failed`, не `uncertain`. |
| `eval/c1/collect.py` | Сборка артефактов попытки: читает run-dir harness (result.jsonl / error.txt / artifacts/), пишет `agent_assessment.json` + `status.json`. Official-parse только через переданный official parser; audit-decoder (string-aware) — отдельная проекция `parser_audit`. |
| `eval/c1/harness/` | Воспроизводимый diff внешнего harness `/tmp/vexbench-agent-ctl` (см. `eval/c1/harness/README.md`). |
| `eval/c1/runner.py` | Контроллер попыток (Task 4.3): layout `<results_root>/<experiment_id>/<task_id>/<attempt_id>/`, запрет cache/re-run admission (существующий `status.json`/`result.jsonl` → DuplicateAttemptError), controller-артефакты (`raw_agent_output.txt`, `tool_calls.jsonl`, `observations.jsonl`, `usage.json`, `export-report.json`), финализация через `collect.finalize_attempt`. |
| `eval/c1/synthetic.py` | Синтетическая батарея без benchmark CVE (§9.2): MCP handshake/catalog, forced tool error, traversal и exec-gate через MCP, container FS allowlist, реальный container timeout через `run_in_container`, export failure, refusal/invalid/no-output классификация и live isolation probe (один `codex-c1` exec: оба канала). |
| `eval/c1/manifest.py` | Сборка frozen `manifest.json`: izyan/harness commits, sha256 tool binary, image IDs, toolchain, prompt hashes, snapshot content hashes, parser/scorer hashes, attempt policy, comparator. |
| `eval/vexbench_c1.py` | Entrypoint: `synthetic` / `smoke` / `manifest`. Выходы → `results/task4-c1/` (gitignored); frozen-копия manifest → `eval/c1/freeze/manifest.json`. |
| `eval/c1/parser_audit.py` | Secondary parser-audit декодер (spec §8.3.2): `json.JSONDecoder().raw_decode` на каждом `{` последнего assistant terminal text; восстанавливает только полный валидный JSON object с `category`, label-only/prose/truncated — никогда. Terminal text адаптер-осведомлённый: `TERMINAL_TEXT_EXTRACTORS` зеркалит `extract_text` каждого профиля (`codex*` → NDJSON last `agent_message`, `opencode*` → export JSON last assistant `text` part); неизвестный адаптер → явный `no_input` + `input_error`. Статусы: `matched`/`recovered`/`disagreed`/`no_valid_category`/`no_object`/`no_input`; canonical terminal-text и category-object rule (collect.py/assessment.py делегируют сюда). |
| `eval/c1/report.py` | Offline scoring + audit (подзадача 4.5): официальная проекция через `evaluate.parse._parse_run` + `evaluate.metrics.compute_metrics` (byte-check `--check-parsed`/`--official-metrics`), safety-проекция через `eval/vexbench_plain_report` (FS/SCR/recall/INCONCLUSIVE/FAILED classes/stability), parser-audit рескоринг, paired transitions vs baseline cohort, tool-use audit. Выходы §11: `official_metrics.json`, `safety_metrics.json`, `parser_audit_metrics.json`, `case_comparison.jsonl`, `disagreements.md`, `tool_use_summary.md` (+`parsed.jsonl`, `parsed.parser_audit.jsonl`, `tool_use_summary.json`). |
Тесты (venv harness, pydantic v2):
```bash
/tmp/vexbench-agent-ctl/.venv/bin/python -m unittest \
    eval.c1.assessment_test eval.c1.status_test \
    eval.c1.collect_test eval.c1.protocol_test eval.c1.runner_test \
    eval.c1.parser_audit_test eval.c1.report_test -v
```



### Task 4.3 — protocol/isolation/smoke/freeze

```bash
# 1. Синтетическая батарея (без benchmark CVE; один платный live-probe):
cd <worktree>
/tmp/vexbench-agent-ctl/.venv/bin/python eval/vexbench_c1.py synthetic
#    → results/task4-c1/_synthetic/synthetic-checks.json (15 проверок)

# 2. Три smoke-кейса (controller выбирает по GT-классам; класс агенту не
#    передаётся; отдельный experiment_id=c1-smoke, НЕ входят в 90):
/tmp/vexbench-agent-ctl/.venv/bin/python eval/vexbench_c1.py smoke
#    → results/task4-c1/c1-smoke/<task_id>/run_001/{status.json,
#      agent_assessment.json, result.jsonl, artifacts/...}

# 3. Freeze manifest (после smoke; живой + frozen-копия для коммита):
/tmp/vexbench-agent-ctl/.venv/bin/python eval/vexbench_c1.py manifest
#    → results/task4-c1/manifest.json и eval/c1/freeze/manifest.json
```

### Task 4.4-ext — opencode-c1 (Gemini/Qwen через opencode)

Профиль `opencode-c1` в harness (`src/evaluate/agents/opencode_c1.py`):
opencode CLI + тот же `izyan` MCP evidence-tools. Модели:
`gemini-3.8-flash-high` (antigravity → `host.docker.internal:8045`),
`qwen3.6-35b` и `qwen3.8-27b` (custom-openai → `<corp-provider-host>`; ключ модели в config —
полный id со слэшем, `custom-openai/Qwen/Qwen3.6-35B-A3B`).

Контроллер обобщён: `smoke` принимает `--agent/--prompt/--experiment-id/
--task-id/--image`; `finalize_attempt` — `result_filename=` +
`final_text_extractor=` (opencode raw = session-export JSON, а не NDJSON;
терминальный текст извлекается через `agent.extract_text` — та же
«последнее сообщение ассистента» правило).

```bash
# Smoke одного кейса под отдельным namespace (не входит в 90-attempt cohort):
/tmp/vexbench-agent-ctl/.venv/bin/python eval/vexbench_c1.py \
    --model qwen3.6-35b --timeout 900 smoke \
    --agent opencode-c1 --task-id stretchr-testify-285adcc-CVE-2022-28948 \
    --experiment-id c1-smoke-opencode --attempt-id run_qwen36
#    → results/task4-c1/c1-smoke-opencode/<task_id>/<attempt_id>/{status.json,
#      agent_assessment.json, result.json, artifacts/{opencode-config.c1.json,
#      izyan-audit/tool_calls.jsonl, opencode-export.json, ...}}
```

Рядом — контрольная рука `opencode-b1p` (тот же файл): тот же opencode,
тот же synthesized per-attempt config, тот же capture, но образ
`vex-bench-<lang>-opencode-gw` и **без** блока `mcp` в config —
единственное различие рук — наличие izyan evidence tools. Промпт у руки
plain — `vuln_assess`; `opencode-c1` использует `vuln_c1` (= `vuln_assess`
+ блок `<EVIDENCE_TOOLS>`):

```bash
# Plain arm (без izyan tools), тот же кейс/модель:
/tmp/vexbench-agent-ctl/.venv/bin/python eval/vexbench_c1.py \
    --model qwen3.6-35b --timeout 900 smoke \
    --agent opencode-b1p --prompt vuln_assess \
    --task-id stretchr-testify-285adcc-CVE-2022-28948 \
    --experiment-id c1-smoke-qwen-arms --attempt-id run_qwen36_b1p
#    → .../run_qwen36_b1p/artifacts/opencode-config.b1p.json (без mcp),
#      НЕТ artifacts/izyan-audit/; status.json пишет контроллер.
```

`safety_metrics.json` агрегирует `assessment_schema` (`valid`/`invalid`/
`absent` per repeat + pooled, `invalid_attempts`) как отдельное
измерение рядом с verdict — `overall` не меняется (артефактный дефект
не стирает принятую официальную категорию).

### Task 4.5 — offline scoring + audit (`eval/c1/report.py`)

Офлайн-скоринг замороженной когорты (90 attempts), без model calls:

```bash
/tmp/vexbench-agent-ctl/.venv/bin/python -m eval.c1.report \
    [--baseline-run-root <B1 run root> | --baseline-parsed <parsed.jsonl>] \
    [--official-metrics <ref metrics.json>] [--check-parsed <ref parsed.jsonl>] \
```

Две раздельные проекции (spec §8.3): **primary/official-strict** — ровно
`evaluate.parse._parse_run` + `evaluate.metrics.compute_metrics` (официальный
parser/scorer не изменён; `--check-parsed`/`--official-metrics` дают
байт-в-байт проверку воспроизведения, exit code 2 при расхождении) и
**secondary/parser-audit** — `parser_audit.py` (string-aware `raw_decode`,
только последний assistant terminal text, только полный валидный JSON;
`recovered`/`disagreed` записываются отдельно, refusal никогда не
восстанавливается в валидный ответ). Извлечение terminal text
адаптер-осведомлённое: codex-профили читают последний `agent_message`
NDJSON, `opencode`/`opencode-c1` — последний assistant `text` part
export JSON (`result.json`); для каждого профиля зеркалируется его
`Agent.extract_text`, а неизвестный адаптер даёт явный `no_input` +
`input_error`, без молчаливого применения codex-правила.

Метрики (§9): False-Safe (знаменатель 7/repeat, 21 pooled), Safe Clear Rate
(23/repeat), Exploitable recall, INCONCLUSIVE, FAILED по классам причин,
official Accuracy/F1, Reason accuracy; per-repeat mean + sample std, raw
counts по 90, per-case stability 3/3·2/3·1/3, paired `(task_id, run_id)`
corrections/regressions/False-Safe появление-устранение, tool invocations
(семейство/статус/completeness/повторные вызовы/пропущенные reachability
проверки) и decisive evidence (Observation refs, процитированные в
assessment claims).

Dry-run выполнен на сохранённой загрязнённой когорте
(`results/task4-c1/c1-full-capacity-contaminated/`, пометка DRY-RUN в
артефактах — НЕ финальный результат) и на frozen B1 (byte-equal воспроизведение
`metrics.json`/`parsed.jsonl`, safety-агрегаты совпали с
`/tmp/vexbench-plain/full/report/safety-metrics.json`).

## 11. Task 5 — Prompt vs Evidence Tools (`eval/task5/`)

Эксперимент по спецификации
`docs/dev/specs/task5-prompt-tools-gate-spec.md` (= побайтовой копии
`docs/dev/specs/2026-10-09-task5-prompt-tools-gate-comparison-v2.md`) и
плану `docs/dev/plans/2026-10-09-task5-implementation-plan.md`. Вопрос:
закрывает ли tuned safety-prompt (P1) false-safe провал Task 4 без
izyan-MCP, и лежит ли остаток в проверяемой Gate-области.

Руки (v2): **P0** — исторический Qwen3.6 plain когорт (reference only);
**P1** — frozen official `vuln` + `<SAFETY_RULES>` через `opencode-b1p`,
без MCP; **T1** — байт-в-байт P1 + `<EVIDENCE_TOOLS>` через
`opencode-c1`. История до Task 5 заморожена в `eval/task5/freeze/`
(`freeze-history`: task4-reference.json + sha256 артефактов +
access-audit.md; Codex-когорты помечены PARTIAL, contaminated — excluded).

| Файл | Назначение |
|---|---|
| `eval/task5/protocol.py` | Единый источник промптов: P1 = bytes of frozen official file + `<SAFETY_RULES>`; T1 = bytes of P1 + 2×LF + `<EVIDENCE_TOOLS>`. `python -m eval.task5.protocol` регенерирует `eval/task5/prompts/` + `hashes.json` + `p1-t1.diff` и проверяет сканы (prefix equality, точный дельта-блок, запрещённые идентификаторы). |
| `eval/task5/freeze.py` | Фаза 5.0: индекс замороженных когорт Task 3/4 (`/tmp`-корни read-only), пересчёт MCP ERROR-аккаунтинга, проверки provenance-пинов (harness/patch/izyan ancestor+sha). |
| `eval/task5/manifest.py` | `experiment-manifest.json`: связки рук (agent/prompt sha/image), pins модели/датасета/snapshot-хэшей, attempt policy, gt_policy, comparator, docker/MCP probes, limitations. |
| `eval/task5/collect.py` | Финализация попыток через `eval/c1/collect.finalize_attempt` (официальный parser инжектится, никогда не переопределяется); `assessment_schema` "absent" (в Task 5 контракта assessment нет); per-attempt arm-isolation audit (`audit_arm_attempt`: config has_mcp / audit sink / contamination); `mcp_error_accounting` — независимый ERROR-пересчёт. |
| `eval/task5/report.py` | `case_comparison.jsonl` (task×run × arms, matched-механизм c1.report), `disagreements.md` (paired transitions + regret-классы), `tool_failures.jsonl`, `safety_report.md` (official binary + pooled safety + tool-health). |
| `eval/task5/harness/` | Аддитивный diff к Task-4-patched `/tmp/vexbench-agent-ctl`: регистрация `vuln_safety_v1`/`vuln_safety_v1_tools` + два prompt-data файла. |
| `eval/vexbench_task5.py` | Entrypoint: `freeze-history` / `smoke` / `manifest` / `collect` / `score`; `gate-replay`/`score-gate` — явные отложенные заглушки (Checkpoint B, план §9). |

```bash
PY=/tmp/vexbench-agent-ctl/.venv/bin/python

# unit-тесты (быстрые, без docker/LLM):
$PY -m unittest eval.task5.protocol_test eval.task5.manifest_test \
    eval.task5.collect_test eval.task5.report_test eval.task5.freeze_test

# фаза 5.0 — freeze истории:
$PY eval/vexbench_task5.py freeze-history --out eval/task5/freeze

# smoke (3 кейса × arm, вне scored-корней; выбор кейсов controller-side,
# метки GT агенту не доходят):
$PY eval/vexbench_task5.py smoke --arms p1,t1 \
    --out eval/task5/results/smoke

# freeze manifest + финализация + скоринг (scored-прогоны координируются
# отдельно):
$PY eval/vexbench_task5.py manifest \
    --out eval/task5/experiment-manifest.json
$PY eval/vexbench_task5.py collect \
    --manifest eval/task5/experiment-manifest.json --arm p1
$PY eval/vexbench_task5.py score \
    --manifest eval/task5/experiment-manifest.json --arms p0,p1,t1
```

Результаты прогонов — `eval/task5/results/` (gitignored); score-выходы —
`eval/task5/scoring/` (gitignored). Gate не реализован: условный на
Checkpoint B (спека §5.3, план §9).

## 12. Task 6 — Structured Evidence Contract (`eval/task6/`)

Цель: проверить, делает ли **структурированный evidence-контракт** (эмитится
промптом, валидируется offline без LLM) проверяемыми два механизма False-Safe
из Task 5 — `ERROR` как отсутствие пути и обобщение `0 results / PARTIAL scope`
до глобальной недостижимости. Проекции: **P2** (структурированный промпт, без
MCP), **T2** (тот же промпт + 31 MCP-инструмент), **V-P2/V-T2** (offline-валидатор
по тем же сохранённым ответам, модель не вызывается).

Схема: `agent-assessment/2` (`mechanisms[]`, `negative_claims[]` с
`predicate`/`subject`/`scope`/`evidence_refs[]`/`limitations[]`, `unresolved[]`,
`reasoning`); refs: `ev:OBS-NNNN`, `src:<path>#L<n>@<snapshot-hash>`,
`sha256:<hex>`, `file:<path>[:line]`, `url:https://...`.

**Результат (PRELIMINARY — holdout не запускался).** Контракт проверяем
(checkable-negative-claim share 95.6 % у V-P2), но валидатор **непригоден как
gate**: V-P2 блокирует единственный реальный FS и **39/45** верных safe
(SCR→0 %), V-T2 — 15/15. Причина: C4 требует покрытия всего advisory-scope,
которого PARTIAL-доказательства нормальных safe-ответов дать не могут. Плюс
структурированный промпт снизил формат-комплаенс (P1 94 % → P2 62 %). **Решение:
ни один вариант не проходит safety-bar — production Verification Gate не
строим; анализатор остаётся triage-ассистентом под ручным review.**

```bash
PY=/path/to/agent-ctl/.venv/bin/python
$PY eval/vexbench_task6.py freeze-history --out eval/task6/freeze
$PY -m eval.task6.protocol --out eval/task6/prompts --harness-dir <agent-ctl>
# scored-прогоны координируются отдельно (Docker + модель):
$PY eval/vexbench_task6.py manifest --out eval/task6/experiment-manifest.json
$PY eval/vexbench_task6.py collect --manifest eval/task6/experiment-manifest.json --arm p2
$PY eval/vexbench_task6.py score --manifest eval/task6/experiment-manifest.json --arms p2,t2 --out eval/task6/scoring
$PY eval/vexbench_task6.py replay --manifest eval/task6/experiment-manifest.json --arms p2,t2 --repos-dir <repos> --scoring eval/task6/scoring
$PY eval/vexbench_task6.py report --manifest eval/task6/experiment-manifest.json --scoring eval/task6/scoring
```

Спека [2026-10-09-task6-structured-evidence-experiment.md](dev/specs/2026-10-09-task6-structured-evidence-experiment.md);
план [2026-10-09-task6-structured-evidence-implementation-plan.md](dev/plans/2026-10-09-task6-structured-evidence-implementation-plan.md);
решение `eval/task6/scoring/decision.md`. Сырые прогоны gitignored.

## 13. Agent7 — A-серия freeze (PR-0, `eval/agent7/freeze/`)

Замороженный протокол экспериментальной исследовательской линии A0–A10
(дизайн [2026-10-10-01-agent-driven-evidence-assessment-design-v2.md](../docs/dev/specs/2026-10-10-01-agent-driven-evidence-assessment-design-v2.md),
план [2026-10-10-02-agent-driven-evidence-assessment-plan-v2.md](../docs/dev/plans/2026-10-10-02-agent-driven-evidence-assessment-plan-v2.md)):
сравнение B0 (текущий Izyan) / B1 (plain coding-agent) / R0–R2 (research arms) /
PR1 (offline proof projection) на одних snapshot'ах, модели, бюджете и scorer'е.
- `eval/agent7/freeze/manifest.json` — схема `agent7-manifest/1`: пины
  документов/контроллера/harness/images/dataset (30 Go-кейсов, dev-корпус,
  не blind holdout), arms, attempt policy, GT isolation (`gt_paths_denied` —
  политика будущего broker'а, граница — mount-политика контейнера), smoke
  как host-side class-quota rule (2 safe + 2 exploitable + 1 forced infra
  fail, без committed per-case labels), scorer `agent7-scorer/1`,
  `freeze_status: protocol_frozen` + `run_gate` (prompt bytes, ≤5 tool
  subset, holdout manifest и checkpoint sign-offs пинятся в A2/A4/A9 —
  `CheckRunGate` закрыт до этого), checkpoints со статусом `proposed` +
  `requires_operator_signoff`.
- `protocol.md`, `research-rubric.md`, `security-boundary-check.md` —
  порядок сравнений и artifact contract, слепая рубрика (8 разделов,
  2 ревьюера + арбитраж), проверяемые предусловия безопасности для A2.
- Реализация — Go: `internal/eval/agent7/` (`Load`/`Validate`/`RenderAgentInput`,
  `ClassifyAttempt`/`Aggregate`); в `eval/` только JSON/Markdown, без кода.
  Пустые директории `baselines/ arms/ scoring/ decisions/` не создаются (план §7).

**PR-0 не меняет поведение `izyan analyze`** и не добавляет новых флагов.
Проверка: `go test ./internal/eval/agent7/ -v` — тесты датасета
пропускаются (`t.Skip`) с явной причиной на машинах без внешнего harness.

### 13.1 A1.5 — proof feasibility preflight (PR-1)

Детерминированный preflight перед любым proof-кодом: покрытие текущего B0 на
30 dev-кейсах и независимая классификация кандидатов `ARTIFACT_FIXED` /
`COMPONENT_ABSENT` / `BUILD_EXCLUDED`. Код — Go (`internal/eval/agent7/feasibility.go`,
`cmd/agent7-feasibility`), артефакты — данные:

- `eval/agent7/baseline-proof-coverage.json` — per-case B0 вердикты + какие
  детерминированные факты Izyan уже проверяет; агрегаты пересчитаны
  `vexbench.Compute` по merged-сегментам, `infra_error` исключён из всех
  знаменателей, невалидированный прогон (`-j 2 --mem-limit 8GiB`, memguard)
  записан в `invalidated_attempts`;
- `eval/agent7/proof-feasibility.csv` + `.raw.json` — факты по 23 GT-safe
  кейсам + control (known FS) и независимая классификация;
- `eval/agent7/proof-feasibility.md` — метод, provenance, метрики, §6 Task-B
  классификация, §7 проверка устойчивости вердиктов.

Результат PR-1: B0 safe-clear 10/23, known FS 1 (`k8s-44487`),
`possible_incremental_safe = 0` (единственный eligible-safe дублирует B0) →
**proof checkers не строим** (stop-condition плана A1.5); исследовательские
A2–A5 — отдельное решение. Наблюдение о профиле: `--mem-limit` влияет на
вердикты (memguard деградирует evidence), потолок пинится, деградация
объявляется оператором (`--degraded`), не выводится из артефактов.

### 13.2 Agent-lane hardening (PR-2, environment gate E1–E8)

`izyan-evidence-tools --strict` — обязательный профиль для агентских arm'ов
(решение [agent7-checkpoint-0.md](../docs/dev/decisions/agent7-checkpoint-0.md) §3):
confinement обязателен во всех профилях (opt-out удалён), ambient `GOMODCACHE`
не является read-root (нужен явный `--modcache`), для toolchain-подпроцессов
пинятся `GOPROXY=off`/`GOSUMDB=off`/`GOFLAGS=-mod=readonly`, exec-backed
toolchain-инструменты требуют `--allow-toolchain`, per-tool timeout даёт
честный `TIMEOUT` (по умолчанию без границы, в strict — 15m; флаг
`--deterministic-timeout` у `izyan research` имеет тот же дефолт).
`GOCACHE` пинится явно (`--build-cache-dir` / `IZYAN_BUILD_CACHE_DIR`, иначе
платформенный дефолт `os.UserCacheDir()/go-build`): ambient `GOCACHE` не
наследуется, root не может лежать внутри снапшота или output dir, а
повреждённый кэш fail-closed — ERROR `BUILD_CACHE_CORRUPT` с ремедиацией
вместо молчаливой деградации. Разрешённые
read-roots и применённое toolchain-env записываются в `ScopeDetails`.
Статусы «enforced / precondition» и предусловия запуска A2 (E6 контейнерный

For reproducible benchmark arms, pass `izyan eval vex-bench --osv-dir <dir>`
so each requested advisory is read locally with raw and canonical digests;
there is no network fallback. In the strict agent profile,
`izyan-evidence-tools --govulndb <path>` is required for `run_govulncheck` and
exports the pinned local database as `GOVULNDB`; without it the tool is
`UNSUPPORTED`.
sandbox, E7/E7b frozen advisory и govulncheck DB) — в
`eval/agent7/freeze/security-boundary-check.md` §1/§8; пины профиля прогона,
repeat-stability и обязательная декларация degraded/invalidated — в
`eval/agent7/freeze/manifest.json` (`run_profile`, `run_gate`) и `protocol.md` §10.
Поведение `izyan analyze`/`scan` не меняется.

### 13.3 A2 — B1 vs R0 (Checkpoint A)

Сравнение plain coding-agent (B1) и исследовательского промпта (R0) на 10 dev-кейсах × 3 повтора
в E6-sandbox, без MCP и Izyan-инструментов. Материалы: `eval/agent7/a2/` (blind-reference,
две независимые ведомости, агрегаты, метрики попыток), решение и рекомендация —
`docs/dev/decisions/agent7-a2-checkpoint-a.md`.

Итог: подписанные пороги Checkpoint A **не выполнены** (медианные дельты research-рубрики ≈ +0.08
при требуемых ≥0.5; экономии времени аналитика нет), обязательные ограничения по безопасности
выполнены (FS 7 попыток / 3 кейса против 11/4 у B1, новых false-safe на корректно обработанных
кейсах нет). Рекомендация — **REVISE R0**, к A3 не переходить. Отклонения раскрыты в отчёте
(в т.ч. автоматический in-place перезапуск 5 невалидных R0-попыток run-стадией харнесса).

### 13.4 E2E slice 1 — `izyan research` (пользовательский сценарий варианта 1)

Пользовательский запуск исследования CVE по снапшоту Go-проекта: `izyan research --snapshot <path> --cve <id>
--advisory-file <frozen-osv.json> --output-dir <dir>` (есть `--deterministic-only`). Отчёт `report.json`
(schema `research-report/1`) + `report.md` собираются кодом и жёстко разделяют проверенные детерминированные
факты, утверждения агента и неизвестные; `disposition` всегда `REVIEW_REQUIRED`, auto-close запрещён.

Приёмка (функциональные сценарии, не benchmark): k8s-44487, trivy-32473, rancher-47914 — по два режима
(с агентом и `--deterministic-only`), чекер `e2e-accept.py` 10/10 на всех шести выходах; отчёты закоммичены
в `eval/agent7/e2e/<case>/`. Запись реализации, ограничения и следующий этап —
`docs/dev/decisions/agent7-research-slice-1.md`.

### 13.5 Slice 2 — достоверность и полезность отчёта

Контракт отчёта расширен (`contract_extensions: ["slice2-fidelity/1"]`, легаси-отчёты остаются валидными):
противоречия агентских утверждений с детерминированными фактами, три оси эксплуатации
(`code_reachability` / `attack_surface_availability` / `exploitation_established`), обзор классификации
с обязательным базисом неприменимости (иначе статус понижается до `UNKNOWN`), приоритизация unknowns
(decision-changing vs приложение), материальность evidence (байты артефакта/воспроизводимый рецепт),
модель попыток агента и строгое `INVALID` при неоднозначном выводе. Payload наблюдения ограничен
256 KiB с честной фиксацией усечения; харнесс больше не перезапускает невалидный результат in place
(`eval/agent7/harness/slice2-attempts.patch`).

Приёмка: три кейса (k8s-44487, trivy-32473, rancher-47914) — чекер `e2e-accept.py` **16/16**;
отчёты и первичные evidence/попытки закоммичены в `eval/agent7/e2e/<case>/`
(`report.*`, `observations.jsonl`, `artifacts/`, `agent/attempt-*/`, сырой harness-лог).
Запись и оставшиеся ограничения — `docs/dev/decisions/agent7-research-slice-2.md`.

### 13.6 Проверка на корпоративных findings (Slice 3)

Прогон существующего E2E (`izyan research`, без изменения промпта и архитектуры) на 18 кейсах из корпоративной
выгрузки ранее отклонённых уязвимостей: детерминированный режим + агентский (корпоративный OpenAI-compatible gateway). Результаты,
сравнение с решениями специалистов и Izyan v1, а также конкретный список архитектурных недостатков —
`docs/dev/decisions/agent7-corporate-validation.md`. Корпоративные данные, идентификаторы тикетов и имена
компонентов в репозиторий не коммитятся: в репозитории только агрегаты, отчёты и первичные результаты остаются
локально вне репозитория.

### 13.7 Достоверность E2E-заключения — `slice2-fidelity/2` (без новых LLM-прогонов)

Правка контракта research-отчёта и детерминированного ядра по трём классам дефектов, выявленным корпоративной
проверкой: (1) исправленная версия компонента читалась как отсутствие компонента; (2) агентская цепочка не
отделялась от доказанной эксплуатации; (3) «нет необходимой конфигурации» и «недостижимость кода» не были
независимыми основаниями.

Что изменилось в наблюдаемом поведении:

- `internal/affected`: fixed-ветка больше не выставляет `package_present=FALSE`/`build_relevant=FALSE` без
  пакетного probe (оба остаются `UNKNOWN` + limitation), и добавлено `unresolved_modules` (записи advisory с
  неразрешившейся версией, независимо от линковки пакета). Вердикт основного пайплайна не меняется: `NOT_AFFECTED`
  по-прежнему опирается на `version_affected=FALSE`/`module_present=FALSE`/`package_present=FALSE`.
- Отчёт рекламирует расширение `slice2-fidelity/2` (wire-схема остаётся `research-report/1`; отчёты `/1` читаются
  legacy-веткой). Новые поля `product_applicability.{evaluated_entry_ids,advisory_entry_status,
  vulnerable_code_reachability,unresolved_modules}` и `basis[].check_scope`; новые основания
  `required_configuration_absent`/`vulnerable_code_not_reachable` (агентские — `PROVISIONAL`/`agent`, без verified
  refs). Условия эксплуатации делятся на подтверждённые факты / гипотезы агента / неизвестные условия; сценарий
  без подтверждённых переходов — `UNKNOWN`, а не `PARTIAL`. Валидатор `/2` fail-closed: заключение не может быть
  сильнее основания (`FIXED` не даёт утверждений об отсутствии, `NON_APPLICABLE/SUPPORTED` требует ESTABLISHED
  негативного основания с процитированными verified refs, `SUPPORTED`-сценарий требует dynamic evidence).
- `report.md` начинается с обязательного русского `## Резюме`: присутствие модуля, оценённые записи advisory и
  статус исправления, достижимость уязвимого кода, область применимости advisory, оставшиеся препятствия для
  триажа.
- Новый вход `izyan research --replay-agent-turn <dir>`: пересборка отчёта из сохранённого прогона (детерминированная
  полоса выполняется заново, модель не вызывается), с проверкой всех записанных sha256-пинов, verbatim-сохранением
  `agent_output` (включая `INVALID_FORMAT`) и провенансом `replayed_from`.

Проверка: офлайн-регрессия на сохранённых артефактах (18 корпоративных кейсов приватно + 3 публичных e2e) без
LLM-прогонов; публичные отчёты `eval/agent7/e2e/*` перегенерированы под `/2`. Запись, границы и перечень
оставшихся препятствий — `docs/dev/decisions/agent7-e2e-conclusion-fidelity.md`.

### 13.8 Состояние A-серии и пути к артефактам

Снимок состояния, исполнение плана, команды воспроизведения и карта артефактов тестов и результатов (публичных и
приватных) — [`docs/dev/agent7-state.md`](../docs/dev/agent7-state.md). Приватные абсолютные пути и имена
приватных репозиториев вынесены в приватный компаньон вне репозитория.

### 13.9 Этап повышения работоспособности Shadow research lane (2026-10-13)

План [`docs/dev/plans/2026-10-13-01-shadow-usability-plan.md`](../docs/dev/plans/2026-10-13-01-shadow-usability-plan.md),
регрессия по 31 сохранённому кейсу (без вызовов модели, 31/31 PASS, ~65 мин) и два операторски разрешённых
живых повтора (6/6 и 5/5 OK) — [`docs/dev/reports/2026-10-13-shadow-usability-regression.md`](../docs/dev/reports/2026-10-13-shadow-usability-regression.md).

### 13.10 Package-level facts B42 — saved-data replay regression (2026-10-14)

План [`docs/dev/plans/2026-10-14-01-package-level-facts-plan.md`](../docs/dev/plans/2026-10-14-01-package-level-facts-plan.md),
replay-регрессия по 42 сохранённым кейсам (без вызовов модели, 42/42 PASS, ноль NOT_RUN) —
[`docs/dev/reports/2026-10-14-01-package-level-facts-regression.md`](../docs/dev/reports/2026-10-14-01-package-level-facts-regression.md).

B41 usage-scope: [план](../docs/dev/plans/2026-10-14-02-usage-scope-plan.md) и [измеренная офлайн-регрессия](../docs/dev/reports/2026-10-14-02-usage-scope-regression.md) — saved-turn replay без модели, census C01–C31 и specialist-набор, false-safe gate; ноль test-only, B41 остаётся открытым до закрытой specialist test-only проверки.

### 13.11 Автономный срез доказательств — `research-report/2`, итог `CAPABILITY_GAP_RECORDED` (2026-10-15)

План [`docs/dev/plans/2026-10-14-03-autonomous-evidence-slice-plan.md`](../docs/dev/plans/2026-10-14-03-autonomous-evidence-slice-plan.md) (с поправками R1/R2), санитизированный отчёт — [`docs/dev/reports/2026-10-14-03-autonomous-evidence-slice.md`](../docs/dev/reports/2026-10-14-03-autonomous-evidence-slice.md). Демонстрация capability на четырёх точечных replay-кейсах C01–C04 (без вызовов модели, `--replay-agent-turn`) остановилась контролируемо: все четыре отчёта `INCONCLUSIVE` с `coverage=INSUFFICIENT_SCOPE`, `disposition=REVIEW_REQUIRED`, `auto_close=false` — независимо проверенный real-case negative **не продемонстрирован**.

- **Форма отчёта:** `izyan research` эмитит `research-report/2` — блок `decision` (hypothesis, falsifier, checks, evidence refs, coverage, sufficiency, ticket rationale) отделён от фиксированной диспозиции `REVIEW_REQUIRED`/`auto_close=false`; авто-закрытие тикета не выполняется ни при каком решении.
- **Контракт решения:** агент возвращает типизированный `verification_plan` (фальсификатор + ≤8 bounded проверок из каталога evidence tools); план исполняется внутри той же strict confined сессии, артефакты replay/provenance сохраняются (`verification-facts.json`, `verification-observations.jsonl`, `verification-artifacts/`, session audit). Терминальный негатив требует полностью покрытого и независимо проверенного фальсификатора — `VerifyDecision` иначе возвращает `INCONCLUSIVE`.
- **Итог C01–C04:** ни один сохранённый ответ агента не содержит `verification_plan` → фаза верификации не выполнялась ни разу (0 планов, 0 observations); `VerifyDecision` останавливается на `Proposal == nil`.
- **Блокеры capability:** (1) нет retained turn с `verification_plan` (нужен живой C02 turn под обновлённым промптом — B32/B40); (2) `--modcache`/`--govulndb` заполняются CLI, но не доходят до `SessionConfig` (`run_govulncheck` → `UNSUPPORTED`) — B47; (3) guard/bound семейство доказательств не построено (`guard_verification_capability_missing`) — B48, не замена C02. Для vendored snapshots strict `go list` теперь выбирает `-mod=vendor` по `vendor/modules.txt`, поэтому offline closure использует дерево на диске с `GOPROXY=off`; non-vendored snapshots по-прежнему требуют доступного read-only module cache и fail closed при отсутствующих зависимостях.
- **Граница не изменена:** старый `izyan analyze`, `internal/report` и `internal/risk` не затронуты; research lane остаётся отдельным, без интеграции в старый pipeline и без auto-close.

### 13.12. Живой прогон C09 и статус автономного исследования (2026-10-15)

На реальном кейсе C09 (`<PRIVATE_UNIT>`, snapshot `<PRIVATE_SNAPSHOT>`, advisory `GHSA-x744-4wpc-v9h2`) выполнен первый живой прогон агентного контура с моделью Qwen3.6-35B в E6-контейнере под промптом `r0-v3` ([отчет](../docs/dev/reports/2026-10-15-01-c09-live-demonstration.md)).

Результаты:
- E6 preflight прошел с полным статусом PASS (29/29 проверок).
- Модель провела глубокий анализ и правильно классифицировала кейс как `false_positive` (модуль `moby/moby` отсутствует в продукте, `docker/docker` является клиентом с отдельной версионизацией).
- Модель не сформировала отдельный ключ `verification_plan` в JSON, посчитав отсутствие модуля уже доказанным фактом.
- Система сработала fail-closed: вердикт `INCONCLUSIVE`, `REVIEW_REQUIRED`, `AutoClose=false`.
- Разрыв зафиксирован в бэклоге как B49 (принудительное структурирование/извлечение плана).

### 13.13. Corporate snapshot-conditioned metrics (2026-10-15)

Отдельный набор метрик по корпоративным отклонённым тикетам. Не смешивать с корпусными метриками выше.

```text
N_all = 85 findings (корпоративные отклонённые)
N_snapshot = 66            # есть снапшот
N_no_snapshot = 19         # data cap, не INCONCLUSIVE
verified_automation_rate = terminal_verified_negative / 66
inconclusive_rate = INCONCLUSIVE / 66
false_safe_count = 0 (при V=0 показывать FS=0, V=0 — знаменатель не доказательство качества)
```

Терминальный негатив засчитывается только когда детерминированный верификатор подтвердил: advisory-wide покрытие субъектов, полный trace, совпадение snapshot/build-контекста, разрешающиеся digest-ссылки, пустые operational limitations и `AutoClose=false`. Категория агента, согласие с прозой и исторический вердикт человека **не засчитываются**.

Текущее измерение (2026-10-15, детерминированный прогон без модели по 18 кейсам, для которых
материализованы снапшоты и сохранён прогон): **`V = 7/18 = 38.9%`** (`NOT_AFFECTED`, `coverage=COMPLETE`),
`INCONCLUSIVE = 11/18`, `false_safe_count = 0`, все 18 отчётов проходят самовалидацию (`exit 0`).
Разбивка маршрутов внутри `V`: отсутствие модуля в product-графе (C09) и версия вне affected-диапазона
(остальные). Полный знаменатель 66 требует материализации снапшотов для остальных findings.
См. `docs/dev/reports/2026-10-15-01-c09-live-demonstration.md` и Amendment R4 плана.

Переизмерение 2026-10-16 (после исправления «vendor-first» build-closure: строгие
tool-инвокации выбирают `-mod=vendor` по `vendor/modules.txt` до любого обращения к
module-cache): **`V = 8/18 = 44.4%`**, `INCONCLUSIVE = 10/18`, `false_safe_count = 0`.
Один кейс перешёл из `INCONCLUSIVE` в детерминированный `NOT_AFFECTED`/`COMPLETE`,
потому что полный vendor-closure позволил доказать отсутствие affected-пакета в
product-import-closure; сверка с приватным human-экспортом (all-18 — not-exploitable)
подтверждает отсутствие false-safe. Историческое измерение `7/18` выше оставлено как
запись на дату.

Переизмерение 2026-10-17 (после подключения релизного артефакта к прогонам census:
для каждого кейса в запуск передаётся дистрибутив продукта — компонентный бандл,
из которого берётся `go1.25.10`/`golang.org/x/net v0.55.0`; путь артефакта и креды
остаются внешними и в репозиторий не попадают): **`V = 9/18 = 50.0%`**,
`INCONCLUSIVE = 9/18`, `false_safe_count = 0`. Ещё один кейс перешёл в
`NOT_AFFECTED`/`COMPLETE`, потому что релизный тулчейн и граф модулей сняли
stdlib-субъект, а полный vendor-closure доказал отсутствие пакета в
product-import-closure. Тот же прогон шёл с явным ограниченным `--build-cache-dir`
(2.0 ГБ на весь census) — внешний кэш сборки не затрагивался.

Demand-разбивка по причинам отказа человека: `other` 38, `component_absent_or_unreachable` 15, `exploitation_conditions_not_met` 14, `code_unreachable_test_only` 7, `compensating_control_trusted_peer` 5, `not_applicable_environment` 3, `compensating_control_tls_config` 2, `component_absent_or_not_delivered` 1.

### 13.14. Decision-ready контракт R6 — `research-report/3` (2026-10-16)

План [`docs/dev/plans/2026-10-15-02-decision-ready-triage-plan.md`](../docs/dev/plans/2026-10-15-02-decision-ready-triage-plan.md) (Amendment R6). Заморожен контрактный слой opt-in decision-ready ветки: типы `DecisionArtifact`/`Fact`/`Justification`/`DecisionBranch`/`DecisionVariable`/`EnvironmentAssertion`, схемы `research-report/3` + `decision-artifact/1`, валидатор человеческого контракта (≤2 environment-вопроса, ≤7 обязательных фактов первого экрана, обязательная `unknown`-ветка, ответы строго `Accept`/`Reject`), запрет лонжирования доверия в code-level факты (environment assertion никогда не становится `Claim{Result:FALSE}`), монотонная политика (`rubrics/decision.yaml`, `configs/research/{dispositions,conditions,checks}.yaml` — JSON-подмножество YAML, fail-closed загрузка).

`research-report/1` и `/2` парсятся и рендерятся байт-стабильно; `/3` требует валидный `decision_artifact`. Внешний регрессионный гард: `eval/decision_ready/regression_guard.py` — принимает только санитизированные метки и внешние пути через аргументы/ENV (`VA_R6_RUN_DIR`, `VA_R6_CASE_LABEL`, `VA_R6_EXPECT_*`), проверяет `decision.verdict`/`coverage` и `disposition.auto_close=false` сохранённого прогона (эталон: путь C09 — `NOT_AFFECTED`/`COMPLETE`/`auto_close=false`). Runtime-поведение вердиктов не изменено; эмиссия `/3` — опциональный вход `Assemble`, включённый флагом `izyan research --decision-ready`.

### 13.15. R6: flow, decision-ready прогон и измерительный стенд (2026-10-16)

Tasks 2–6 плана `2026-10-15-02` реализовали остальное: единый evidence конверт `internal/research/evidence_envelope.go` (`decision-artifact/1`), бранч-модель `B-*` + `EnvironmentAssertion` (`branch_evidence.go`, `branch_evaluator.go`), движок PLAN→ACT→OBSERVE→REASSESS `internal/research/flow_driver.go` (до 4 ходов, fail-closed при `--deterministic-only` → `PLANNER_FAILURE`), расширяемый adapter `flow_adapter.go` (wrap legacy AgentTurn), CLI `izyan research --decision-ready` + replay `--replay-decision-run` (детерминированный, сравнение по content-hash), пины/монотонная политика `configs/research/decision-policy.json`, рендер human-first экрана (artifact digest, ≤7 обязательных фактов, ≤2 вопроса, только Accept/Reject, список моделей отдельно от веток). Legacy-режим по умолчанию не меняется.

Измерительный стенд (task 7): `eval/decision_ready/` — `runner.py` (manifest `decision-ready-manifest/1`, проверка снапшотов/external-commit-sha/ADV hash, replay/live/deterministic-only режимы, fail-closed проба, классификация `NO_SNAPSHOT`/`NO_ADVISORY`/`NO_REPLAY`/`NOT_RUN_LIVE_PENDING_AUTHORIZATION` без молчаливого пропуска, fail-safe stop), `metrics.py` (human-work: время решения median/P75/P95 по диспозиции/числу бранчей/классу, `facts_read`, `repo_open_rate`, `missing_fact_rejection_rate`, env question/answer/unknown/branch-change, принятые false-safe по классам раздельно, reopen/reversal/remediation-return/rerun, model calls/tokens/cost/elapsed — replay и det-only обязаны быть 0 model calls), `events.schema.json` (`decision-ready-review-event/1` для слепого двух-ревьюерного протокола), `test_metrics.py` (29 офлайн-тестов). Все committed-артефакты санитизированы: внешние манифесты, снапшоты и события ревьюеров остаются вне репозитория.

Измерение (16.10.2026): гард R6-G0 зелёный — реплей C09 под текущим кодом `NOT_AFFECTED`/`COMPLETE`/`auto_close=false` через `regression_guard.py`. Корпоративный arm (18 кейсов): у всех сохранены снапшоты, advisory hash и legacy turns; `decision_run_dir` отсутствует (R6 live-прогонов на корпоративных снапшотах не было) → все `NO_REPLAY`; с `--det-fallback` каждый кейс прогнан `--decision-ready --deterministic-only`: 18/18 валидных `/3` отчётов с `decision-artifact/1`, `flow_termination=PLANNER_FAILURE`, топ disposition `HOLD_UNKNOWN`, `auto_close=false`, 0 model calls, 0 unresolved refs — fail-closed подтверждён. Категории: `HOLD_UNKNOWN`=18, terminal deterministic `CLOSE_*`/`KEEP_OPEN`=0 (без планировщика не достижимы — это измеряет пробу, не способность). VEX-Bench point-case controls (10 кейсов через `izyan eval --case`): все 10 прошли `expect` (`EXPLOITABLE`×4 — real-yaml-http/ssh-server/dns-zone/service-plain-6443; `EXPLOITABLE|INCONCLUSIVE`×1 — service-xds-6443 EXPLOITABLE; `NOT_AFFECTED`×2 — yaml-http-fixed/service-plain; `INCONCLUSIVE`×1 — http2-server; `NO_EXPLOIT_PATH_FOUND`×2 — yaml-file/service-pkg-6443), `false_safe=0`, `errors=0`. Не запущено: live-контролы 3–5 кейсов (`NOT_RUN_LIVE_PENDING_AUTHORIZATION`), слепое исследование (`NOT_RUN`, нужны ≥2 ревьюера), holdout (`NOT_RUN`, внешний манифест отсутствует). Наблюдение (root-caused, не регрессия R6): общий детерминистический resolver (`internal/affected/resolver.go`, коммит `326862f` от 13.10 — после сохранённых `/1`-прогонов от 12.10) не пробует package/build-цепочку, когда версия уже вне диапазонов → `status=PARTIAL` при `version_affected=FALSE` на обоих маршрутах (`/2` det-only сегодня даёт идентичное `TRUE FALSE UNKNOWN UNKNOWN PARTIAL`); раньше фиксированная версия неверно читалась как отсутствие пакета (`SUPPORTED` был over-claim). `NOT_AFFECTED` по version/module цепочке на это не опирается — ground truth и все закрытия сохранены.


Позже в тот же день 5-кейсовый controls live-прогон (внешний манифест) упал на всех кейсах с `PLANNER_FAILURE`: экстрактор `decodeLastJSON` брал последний декодируемый объект на любой глубине — вложенный `arguments` объекта плана затенял сам план, а strict decode падал на его члене (`json: unknown field "module"`); параллельно промпт `r6-plan-v1` документировал `check_id` там, где контракт движка называется `adapter_id`. Исправлено: экстрактор выбирает только top-level объекты, wire-контракт принимает канонический `adapter_id` (legacy `check_id` сохранён для замороженных r6 v1 промптов и replay), новая ревизия `r6-plan-v2.txt` пиннится в манифесте и документирует точную форму `flow.Plan`/`PlanAction`; дрейф-регрессия `TestPlanPromptContractMatchesDecoder` strict-декодирует пример промпта в контракт.

Следующий живой прогон (один корпоративный кейс) после этого прошёл планирование, но остановился `UNSUPPORTED_CHECK_OR_CONDITION`: `affected-resolve` — обязательная проверка `rubrics/decision.yaml`, при этом lane-internal (в `check_specs.go` такого session-инструмента нет), её запись OBS-0008 в аудите лейна полная (OK/COMPLETE, дайджест в `CanonicalByObs`), но не разряжалась, потому что `dischargedLaneChecks` переиспользовал `promotableObservation` — гейт промоции фактов, требующий digest-bearing `evidence_refs`, которых у внутренней записи лейна нет, — а `List()` `mappedFlowCatalog` рекламировал недиспатчабельный id в `available_checks`. Исправлено без ослабления гейтов: разрядка лейна теперь идёт по собственному гейту — OK + COMPLETE + непустой scope с именованным coverage-правилом + `SnapshotHash` текущего лейна + перепроверенный канонический дайджест записи (`promotableObservation` для фактов не изменён); `available_checks` рекламирует только диспатчабельные id (новый опциональный `flow.DispatchableRegistry`, реализованный `CatalogRegistry` через `Lookup`); зарегистрированный, но недиспатчабельный required-check без разрядки именуется limitation'ом на старте и деградирует ready-claim в `NOT_DECISION_READY` с именем проверки; admission/broker называют lane-internal причину явно. Тесты: `TestDischargedLaneChecks` (discharge без refs, fail-closed на PARTIAL/ERROR/unpinned/stale/digest-mismatch/no-rule/unmapped), `TestRunDecisionReadyLaneDischarge` (реальный лейн: разрядка + admission пройден + fail-closed на недоразряженном `package-usage`), `TestEngineLaneCarriedCheck*` (engine-уровень). Реплей старой записи воспроизводит записанный `UNSUPPORTED_CHECK_OR_CONDITION` (терминация совпадает, причина стала точнее).

Task 5 fix #3 adds generated per-check argument schemas to `FLOW_STATE.available_check_specs`, and records module-only advisory exceptions as explicit `inapplicable_checks`: required `package-usage` is not fabricated with a package subject, while module-capable `usage-scope` remains required. The exception is retained in the flow result/audit and named in terminal evidence; strict schema admission remains unchanged. `promoteLaneFact` verifies the persisted pinned wire observation before digest comparison, resolving the audit-vs-wire representation mismatch.

### 13.16. R6 release-artifact and symbol-unreachability bounds (offline)

The opt-in research command accepts these release-evidence flags:

```text
--artifact <path>                         local Go binary or ZIP
--artifact-url <https-url>                HTTPS fallback, same-host redirects only
--artifact-credentials-env <ENV>          default IZYAN_ARTIFACT_CREDENTIALS
--artifact-cache-dir <dir>                external content-addressed cache
--artifact-timeout <duration>
--artifact-max-download-bytes <bytes>
--artifact-max-extracted-bytes <bytes>
--artifact-max-entries <count>
--release-metadata <path>                 sanitized release-metadata/1 input
--declared-assumptions <path>             declared-assumptions/1 policy/scope inputs (never evidence)
--implementation-locus-proposal <path>     implementation-locus-proposals/1 LLM-inferred hypotheses (never evidence)
--exploit-locus-proposal <path>            exploit-locus-proposals/1 LLM-inferred locus/sink/trigger hypotheses for symbol-less advisories (never evidence)
--ticket <path>                          tracker ticket (JSON/array/text, '-' for stdin)
--ticket-id <id>                         ticket key to select from a multi-ticket input
```

`--declared-assumptions` is a typed policy/scope input channel, not
evidence. The `declared-assumptions/1` document is a closed member set
(unknown fields rejected), bounded at 64 KiB and 64 assumptions, and
pinned twice: `sha256` of the exact file bytes and the document's own
`content_digest` (canonical `{schema, assumptions}`); every assumption
carries its own `sha256` digest, plus id, statement, scope,
authority/owner, source reference and review date. Scopes are
`product`, `artifact`, `deployment` or `config:<ref>`; `product` covers
the narrower scopes and nothing narrower covers `product`, so a
single-artifact target declaration can never satisfy a product-wide
claim. Intake rejects duplicate ids, invalid dates/digests, empty
required fields, unsupported kinds and kind/scope/target
inconsistencies; expired, not-yet-valid, malformed, digest-mismatched or
scope-mismatched assumptions are inadmissible and fail closed. The
report renders them in a dedicated
`Declared assumptions — policy/scope inputs, not deterministic evidence`
section and in `input.declared_assumptions`; verdict/decision references
travel in `assumption_ids`, never in `evidence_refs`. No assumption
statement is a claim or code fact: only the document's intake record
(path, digests, ids) joins the deterministic record, and no assumption
ever becomes `EvidenceKind.CONFIGURATION`. `--trusted-peer` is a
separate deployment assertion and does not substitute for a
`config-trust` assumption.

**G1 post-reach configuration route.** With an admitted product-scope
`config-trust` member, the research lane itself runs the bounded
post-reach check: the advisory-declared sink set must be advisory-bound
complete (`goanalysis.SinkSetBasis`), the sink closure must enumerate
every live payload site, and the exact trigger argument at every live
site must trace to administrator-managed configuration
(`Origin=CONFIGURATION` from the bounded provenance trace — a
`mapstructure`/`env` tag alone is only a classification, suppressed by
external writes, pointer aliases, address-taken fields and reflection
writes). The FALSE claim is then re-derived by `goanalysis.Verifier`.
Only then does the lane yield `NO_EXPLOIT_PATH_FOUND` with
`falsifier=trusted-infrastructure`, `ground_basis=config-origin` and the
assumption id in `assumption_ids`; this route never yields
`NOT_AFFECTED`. The deterministic evidence (exact sink/argument closure,
recorded as an observation/fact) and the policy assumption (resolved only
against `input.declared_assumptions`) are reported in separate fields and
separate prose. A missing/expired/wrong-scope assumption, an unresolved
non-absent advisory sink, an incomplete closure or any external/unknown
live origin keeps the case `INCONCLUSIVE`. `--trusted-peer`, the
analyzer host OS and a single artifact never stand in for the declared
policy.

**G2 implementation-axis route.** `--implementation-locus-proposal` is a
typed input channel, not evidence: the
`implementation-locus-proposals/1` artifact carries LLM-inferred
implementation-locus hypotheses (module/version/package/file/function,
platform expression, advisory-pinned quote, marker). A live agent turn's
recorded proposals are admitted the same way when its attempt is
replayed; the persisted record is re-validated (typed shape, ≤8 unique
ids, LLM-inferred quality, advisory-bound quotes pinned to the frozen
advisory digest) and a hand-edited or broken proposal aborts the replay.
Admitted proposals never produce a verdict — the lane runs
`affected.EvaluateImplementationAxis` as its own
`implementation-axis` observation: it needs an authoritative product
target (artifact build info, release metadata, or an admitted
product-scope `supported-targets` assumption — never the host OS or
`go.mod`), a compiled-scope package-presence probe, and a
GOOS/GOARCH/GOARM/GOARM64/cgo/build-tag deterministic re-selection of
`module@version/package/file`; the FALSE claim is re-derived by
`goanalysis.Verifier` and reaches `FALSE` only when every
platform-selected implementation is absent while a marker-bearing
alternate stays outside the recorded target. `vulnerable_implementation_
present=FALSE` with a linked package closes `NOT_AFFECTED` under the
decision-ready `vulnerable-implementation-present` rule (OpenVEX
`vulnerable_code_not_in_execute_path`); `BuildRelevant` keeps its
package/platform meaning. A rejected proposal, an unverifiable file, a
marker hit inside scope, or a missing product-wide scope leaves the
case `INCONCLUSIVE` — a single Linux artifact can never close a
product-wide claim on its own.

**Exploit-locus binding route (symbol-less advisories).** An advisory
that declares no structured symbols gives G1 no advisory-bound sink set,
so a product sink in another dependency module can never be admitted by
advisory membership. `--exploit-locus-proposal` is a typed input
channel, not evidence: the `exploit-locus-proposals/1` artifact carries
LLM-inferred hypotheses only — the vulnerable implementation
(package + symbol, including unexported methods such as
`(*logicalQuery).Select`), the product-facing sink (package + symbol)
and the exact trigger argument name/index — plus an advisory-pinned
quote. Intake bounds the file at 1 MiB and the member set is closed;
every member must be `LLM_INFERRED`, the artifact's `advisory_sha256`
must equal the frozen advisory, and a failed channel records a typed
`LoadError` and admits nothing. Replayed agent turns carry their retained
proposals through the same gate.

Nothing in a proposal is authoritative: `affected.VerifyExploitLocus`
re-resolves the advisory identity/digest/quote, the symbol-less affected
entry, the snapshot content hash, applicability/version/selected module,
the recorded build target, the vulnerable module source and the typed
symbol, the sink module/source and the sink signature's parameter name at
the exact index, then proves the trigger-preservation relation through
the dependency call chain and enumerates every product-facing trigger
carrier (mixed argument indices, receiver carriers, variadic positions,
open dispatch, function values and unresolved callees fail closed). Only
a COMPLETE binding — no blockers, exact sink set, one exact `ArgIndex`
— extends the sink-set basis (`goanalysis.ExploitLocusBindingBasis`);
the G1 condition's subjects are then exactly the verified product sinks
and the vulnerable symbol stays in the binding side record, never in the
advisory's affected symbol set. The report carries
`input.exploit_locus_proposals` and `exploit_locus_binding` (binding,
condition, evidence refs) with `assumption_ids` kept separate from
evidence ids. Any open check keeps the case `INCONCLUSIVE` and names the
blocker; this route never yields `NOT_AFFECTED`.

`--artifact` and `--artifact-url` are mutually exclusive. Credentials are
read only from the named environment variable as `username:password`, sent
only in an HTTP Authorization header, and never placed in URLs or persisted in
reports, markdown, manifests, event streams, observation ledgers or caches.
The default bounds are 2 GiB downloaded, 8 GiB extracted, 20,000 archive
entries, 512 MiB per candidate and a 10-minute acquisition timeout; callers
may lower them. ZIP extraction rejects absolute/traversal/symlink members and
extracts only into an external cache.

Release trust precedence is strict: release binary build info and explicit
release metadata are `AUTHORITATIVE`; Docker, CI, `go.mod`, version files and
release scripts are `SUPPORTING` only. Agreeing authoritative items resolve;
conflicting authoritative items are `CONFLICTED`; supporting-only evidence
leaves release applicability `UNKNOWN`. Named fail-closed `NOT_RUN` reasons
include `ARTIFACT_PATH_MISSING`, `ARTIFACT_CREDENTIALS_MISSING`,
`ARTIFACT_DOWNLOAD_FAILED`, `ARTIFACT_HTTP_UNAUTHORIZED`,
`ARTIFACT_SIZE_LIMIT`, `ARTIFACT_TIMEOUT`, `ARTIFACT_ARCHIVE_UNSAFE`,
`ARTIFACT_NO_GO_BINARY`, `ARTIFACT_AMBIGUOUS_BINARY`,
`ARTIFACT_BUILD_INFO_UNREADABLE`, and `RELEASE_METADATA_INVALID`.

The symbol-unreachability check is advisory-bound and exact at
module/package/symbol granularity. It proves only the recorded product/build
scope: reflection and generated loading not modeled by the scanner, plugins,
cgo, linker tricks, alternate build-tag/platform variants and external
deployment remain outside scope. Partial/empty/opaque/dynamic/interface/
gated results and positive linkage remain `HOLD_UNKNOWN`. A complete proof
may propose `CLOSE_NO_EXPLOIT_PATH` only; it can never produce
`CLOSE_NOT_AFFECTED`.

Validation is replay/deterministic-only while live budget is unavailable:

```bash
python3 eval/decision_ready/regression_guard.py \
  --baseline-manifest <external-baseline-manifest> \
  --c09-replay-dir <external-c09-run> \
  --output-dir <external-guard-output>
```

The guard checks the 18-case census against the **recorded** measurement: the
baseline manifest carries `expected_safe` (currently `9/18` deterministic
`NOT_AFFECTED` with `COMPLETE` coverage, `false-safe=0`, re-measured 2026-10-17
with per-case release artifacts and the confined build cache), and every fresh
per-case report is asserted against its recorded verdict. A manifest without
`expected_safe` is rejected, so re-measuring the census is a deliberate,
reviewable act while a drift back below it fails. It also checks C09
`NOT_AFFECTED`/`COMPLETE` with resolved observation references and
`auto_close=false`, legacy `/2` replay without `/3` fields, and the absence
of a replay model call. It does not invoke a provider or download an
artifact. `AutoClose=false` is an invariant of every research-report
disposition: R6 produces a review-required proposal for a human, never an
automatic tracker close.


#### Hardened channel and authority behaviour (post-review, 2026-10-16)

An adversarial review of this lane closed four safety blockers and five
hardening findings. The observable contract is now:

* release evidence records **no absolute local paths** — a local artifact,
  release binary or release-metadata document is cited as
  `local:<basename>` and anchored by its SHA-256; the cache directory is
  never recorded;
* a requested artifact/metadata channel failure stays visible as
  `required_channel_failures` and forces `NOT_RUN`: the source checkout
  module graph never substitutes for a failed release-evidence channel,
  and the planner/model path is skipped;
* version normalization keeps semver prerelease components
  (`go1.27.0-rc.3` conflicts with `go1.27.0` instead of resolving to it);
  only recognized platform suffixes (`-ubi9`, `-alpine`, …) are stripped;
* redirects are scoped to the full `scheme://host:port` origin, so the
  Basic credential never follows a same-host cross-port redirect;
* the artifact cache is containment-checked on canonical paths (a
  symlinked cache directory cannot land inside the snapshot or output
  directory), a reused slot is re-hashed before it is trusted, and an
  archive member shorter than its declared size is `ARTIFACT_ARCHIVE_UNSAFE`;
* the `declared-symbol-unreached` authority decodes only payloads present
  in the drained session audit and resolves only audit-pinned references;
  a fabricated `src:` locator, a mutated payload or a mismatched recorded
  request cannot ground `NO_EXPLOIT_PATH_FOUND`, and `version-in-range`
  rule facts are projected per advisory entry (a fixed entry of a
  multi-entry advisory no longer inherits the aggregate `TRUE`).

#### Ticket-build identity guard (2026-10-19)

`--ticket <path>` accepts an optional tracker ticket in the same
intake shape as `izyan analyze --ticket`: a JSON ticket, a JSON array
(`--ticket-id <id>` selects by key), arbitrary plain text, or `-` for
stdin. The lane derives the claims from the ticket (`package`,
`version`, `component`, `product`, `release`, `aliases`); the text
path pins the package version from the PURL (percent-decoded) or the
`Библиотека:` line, never misreads `Версия продукта:`/`go_version:` as
the package version, and bounds `release`/`component` at the next
`Word:`-style label so single-line texts stay exact. The lane records
it in `input.ticket` (provenance
`local:<basename>` + SHA-256, never the claims' own path); an
unreadable or unparsable ticket records `TICKET_INVALID` and degrades
the check to `NOT_CHECKED` instead of failing or passing silently.
The resolver compares the declared package version against the version
the analysis resolved (release graph when an artifact/metadata is
present, else the source graph) and the declared product version
against the analyzed build's product identity:

* `TICKET_PACKAGE_VERSION_MISMATCH` — declared ≠ resolved for the
  ticket's package: the version axis is **blocked**
  (`version_affected=UNKNOWN`, `product_applicability.version_axis_blocked`
  + `ticket_check` naming both versions and the refusal reason). The
  "resolved version is outside the affected range" negative is never
  produced — a refusal, not a verdict; `NOT_AFFECTED` remains reachable
  only through the unblocked deterministic chain.
* `ANALYZED_BUILD_MISMATCH` — declared product version ≠ analyzed build
  identity while the package version matches: recorded informationally,
  the closing stands (the version-range comparison stays valid).
* The module-absent and package-absent routes are unaffected by the
  ticket (a package that is not linked is not linked in any build of
  that product), and with no `--ticket` the behaviour — and the
  `/1`/`/2` wire shape — is byte-identical to before.

The parsed ticket also records the dedicated `Ссылка на дистрибутив`
locator as sanitized provenance (`input.ticket.distribution_url`). It is
never fetched and arbitrary ticket URLs are not treated as artifacts. A
package-version refusal names the locator and instructs the operator to
provide/acquire that exact distribution, then rerun with the explicit
`--artifact` or `--artifact-url` channel. That channel independently pins
the artifact SHA-256, selected binary/member, build-info digest, module
graph, and trust class before the ticket identity check is rerun.

### 13.17. OSV-дамп: completion пустых imports advisory (2026-10-17)

Шесть из девяти заблокированных census-кейсов держат advisory без
`affected[].ecosystem_specific.imports` — lane фиксировал `UNKNOWN` с
«advisory declares only module + version range». Новый пакет
`internal/advfeed` дозаполняет пустой список subjects из OSV-дампа
(офлайн: `--osv-feed <dir|zip>`; сеть: `--osv-url`/`IZYAN_OSV_URL`,
`<base>/ecosystems.txt` + `<base>/Go/all.zip`, length-probe кэш,
`--osv-dump-ttl`, `--osv-no-proxy`). Поиск идёт по id **и алиасам**:
GHSA-запись без imports резолвится через её `GO-*` алиас. Измерено на
зеркале: `GO-2026-4526`/`GO-2026-4762`/`GO-2026-6502` несут imports для
модулей соответствующих GHSA; `GO-2026-6372` imports не несёт и кейс
остаётся `UNKNOWN` с именованной причиной `ADVISORY_IMPORTS_UNAVAILABLE`.
Объявленные imports/диапазоны замороженной advisory не перезаписываются;
provenance резолва (`feed_resolution`: статус, source_ids, feed_ref,
dump_sha256, checked_at) — в `report.json`, provenance-члены без
секретов/абсолютных путей — в `run-manifest.json`. Измерения census под
флагом не запускались — это следующий контролируемый прогон.

### 13.18. Human-surface gap/question surfacing (2026-10-17)

Two measured clarity defects on the human-facing surface are fixed —
observable behaviour only, no verdict or gate change:

- **package-usage UNKNOWN now names its specific scope gaps.** The
  payload `limitations` still carries four always-present baseline
  bounds plus the case-specific gaps, but the observation `fact` and
  its outer `limitations` now state `(N gap(s) open: <each named
  verbatim>)` where N counts only the specific gaps (previously
  `undetermined (6 gap(s) open)` — the full payload count — with no
  names). The same treatment applies to `symbol-unreachability`: its
  UNKNOWN observation `limitations` now append the named payload
  limitations (which were already case-specific) instead of a bare
  count. The report's `unknowns[].reason` inherits the named gaps via
  the observation fact text.
- **A residual deployment-only layer derives a specific question.**
  When every blocking exploitation condition resolves except
  deployment/runtime posture, `internal/research/environment_questions.go`
  builds ≤2 questions verbatim from recorded statements — advisory
  summary/description sentences declaring an environment-affecting
  precondition, deterministic deployment-layer conditions (e.g. a
  recorded listen site), non-refuted config-shaped agent hypotheses —
  anchored to the SUPPORTED reach subject/site. They surface as leading
  `open_questions`/`residual_questions` rows, in the
  `triage_recommendation.reason`, in `decision.human_questions`, and on
  the R6 artifact as `human_action.environment_questions` (omitempty —
  legacy artifacts byte-identical). With no recorded deployment
  statement, or while an applicability/path predicate stays open or
  refuted, every surface keeps the previous generic text.

### 13.19. R6 anchored text-derived subjects (2026-10-17)

Module-only advisories name the affected module in their structured
data, but the vulnerable mechanism often lives only in the recorded
prose (e.g. an authz/RBAC/interceptor package that no `imports[]`
declares). The planner may now propose such a subject — the pinned
revision is `eval/agent7/prompts/r6-plan-v5.txt`, wired through
`rubrics/research.yaml` — under an anchored-proposal rule the
deterministic layer validates before any check runs:

- the action may carry an optional `anchor` member: a verbatim quote
  from the advisory's recorded text that names the package or symbol;
- `internal/research/subject_anchor.go` gates every dispatched action:
  declared advisory subjects pass exactly as before (no anchor needed);
  a subject the structured declaration does not name is admitted only
  when the quote is found in the recorded text (`summary`,
  `description` or the raw frozen body, whitespace-normalized), the
  package lies inside an advisory-affected module and the identity is
  well formed;
- each rejection names its reason in the recorded plan failure:
  `SUBJECT_ANCHOR_MISSING` (the v1–v4 fabrication rule, unchanged),
  `SUBJECT_ANCHOR_NOT_FOUND`, `SUBJECT_MALFORMED`,
  `SUBJECT_OUTSIDE_AFFECTED_MODULE`;
- a matched anchor only admits the check. The existing verdict gates
  are unchanged — the dispatched check produces an ordinary observation
  a complete proof still needs; an anchor never produces a verdict,
  and `auto_close=false` is unchanged;
- provenance is recorded, not computed: the trace request, the
  persisted flow-facts check row and the report `decision.checks`
  member carry `derived_from{field,quote}` (additive/omitempty).

Wire compatibility is preserved: `anchor` is optional on the action
member, so v1–v4 plans decode and replay byte-identically, and
anchor-less actions re-encode without the member.

### 13.20. Bounded lane observation payloads (2026-10-17)

A live `--decision-ready` run measured the lane-minted
`affected-resolve` observation payload at 9.5 MB: its `evidence`
member embedded raw `go list -m`/`go list -deps` output verbatim, the
last-resort `maxObservationPayloadBytes` (256 KiB) cap recorded a
truncated prefix and downgraded the record to PARTIAL, the
lane-discharge gate refused it, and the run terminated
`NOT_DECISION_READY` before the first model call. Lane payloads are
now bounded by construction in `internal/research/deterministic.go`:

- every evidence item carries `content_sha256` + `content_bytes`;
  content ≤16 KiB inside a shared 48 KiB/8-item text budget stays
  verbatim in `content`, anything larger keeps a ≤4 KiB rune-boundary
  `content_preview` with `content_bounded: true`, and items past the
  budget are digest-only. Full content remains in memory on
  `LaneResult.AffectedEvidence`; only the persisted observation is
  bounded;
- payload member lists are prefix-bounded (512 items) with the full
  count recorded alongside: `closure.items` gains `items_total`,
  exposure-scan payloads (`listen-sites`/`dial-sites`/
  `inbound-auth-facts`) gain `facts_dropped`, and the snapshot
  record's release module graph gains `release_modules_total` — a
  kept prefix can never read as a closed enumeration;
- semantic members (`affected_result`, `closure`, `release_evidence`)
  stay verbatim; the 256 KiB cap remains as the documented last-resort
  guard but never fires on these payloads, so `affected-resolve` keeps
  `completeness: COMPLETE` and discharges the required check.

No gate, completeness semantic or verdict changed. Evidence ids
(`EV-*`), kinds and metadata persist verbatim — only content bytes
move to digest-pinned previews.

### 13.21. R6 plan-shape self-repair (2026-10-18)

The second live failure of the same class: a real case returned a plan
whose action carried `module` as an action member instead of inside
`arguments`, the strict wire decode rejected it
(`json: unknown field "module"`), and the run terminated
`PLANNER_FAILURE` at step 1 — zero checks executed on a paid run. The
fix is two-sided:

- `eval/agent7/prompts/r6-plan-v6.txt` (pinned in


  `eval/agent7/freeze/manifest.json`, wired through
  `rubrics/research.yaml`) documents the exact member placement — the
  plan's three members, the action's six admissible members, the rule
  that every check input lives only inside `arguments` while `anchor`
  is an action member, omitted-not-null optionals — with a concrete
  example of every admissible action shape plus the engage-only
  (`actions: []`) shape and the repair turn contract;
- the flow engine grants one bounded self-repair turn per planner
  invocation: a decode/contract failure is now a
  `flow.PlanContractError` (the driver wraps the rejected answer
  verbatim), the engine records the first attempt as `planner_error`,
  feeds the verbatim verdict and the rejected answer back through
  `PlanInput.repair_error`/`repair_answer` (inside FLOW_STATE), and
  the second answer stands — any failure on it terminates
  `PLANNER_FAILURE` with both attempts recorded. Every other error
  class stays terminal on first failure.

The contract stays strict: no permissive decoding, no member aliasing,
no verdict-gate change. Replays are preserved — a recorded
`planner_error` followed by another planner turn is by construction a
repaired one, replay reconstructs the same error class via lookahead,
and runs recorded before this change (terminal `planner_error`)
replay byte-identically. v1–v5 prompts stay frozen for recorded
replays.
### 13.22. Oversized authoritative symbol proofs (2026-10-19)

The deterministic `symbol-unreachability` authority path now separates
the bounded display representation from the complete typed proof. When
the canonical `SymbolUnreachabilityData` payload exceeds the 256 KiB
display cap, the observation and `observations.jsonl` retain only a
bounded externalization envelope plus `payload_ref`; the complete JSON
payload is written to a content-addressed `artifacts/payload-<sha256>.json`
sidecar pinned by SHA-256 and byte size. `CanonicalByObs` and
`ArtifactByObs` continue to describe the envelope observation and its
written file bytes, while `payload_ref` identifies the complete typed
payload — these digests are intentionally distinct.

The lane rehydrates and verifies the sidecar before `VerifyDecision`:
missing, altered, malformed or digest/size-mismatched sidecars remain
`INCONCLUSIVE`. A complete oversized proof with no positive paths still
produces `NO_EXPLOIT_PATH_FOUND`, `FalsifierDeclaredSymbolUnreached`,
and `NegativeVerification=VERIFIED`; an oversized proof with an open
semantic gap remains `INCONCLUSIVE`. Non-authoritative observations
keep the existing prefix truncation and `COMPLETE`→`PARTIAL` downgrade.


### 13.23. package-usage: linked-closure absence verifies the package negative (2026-10-18)

A live `--decision-ready` run measured the remaining blocker: an
advisory-declared package (`github.com/klauspost/compress/s2`) absent
from a **complete** linked product closure still produced an
undetermined `package-usage` observation — the absence entry was
counted as an open scope gap, plus 66 interface-dispatch sites the
unlinked package could never receive. The required check could never
discharge and the lane terminated `NOT_DECISION_READY` on budget.

`ProductUsage` now has two closed negative-verification bases:

- the existing **linked-package basis**, unchanged: the target sits in
  the linked import closure, every loaded product package was scanned,
  and no gap class (direct/gated reference, skipped importer, budget
  truncation, interface dispatch, dynamic marker) is open;
- a new **absence basis** for package-level subjects: when the product
  closure is complete — every product package type-checked, the
  package-load budget unexhausted — and the target is provably absent
  from the linked import closure, that absence is positive evidence
  for NOT_USED + VERIFIED. The standard boundaries ride as
  limitations, not gaps: dynamic loading, reflection, plugins,
  deployment and runtime exposure stay outside the static claim.

Fail-closed rules are unchanged: an incomplete closure (any skipped or
type-check-failed package, budget truncation) keeps absence as a gap;
build-gated imports, plugin/linkname dynamic markers and symbol-level
checks (linked-package premise + resolved declaration — the
`symbol-unreachability` shape) are untouched. Interface-dispatch
candidates are no longer scanned for a package outside the link set —
a dispatch site cannot invoke a method of an unlinked package — and an
unlinked package is no longer loaded at all, so its loadability (or
absence from `go.mod`) is irrelevant.

The observation surface records the basis verbatim: fact text and
`scope_details.coverage_rule` distinguish "present but unused" from
"absent from a complete linked closure"; the verdict stays
OK+COMPLETE, so the lane discharge gate admits it and the promoted
PACKAGE_USAGE fact carries `claim=FALSE` +
`negative_verification=VERIFIED` plus a `usage_basis` member
(`present_unused` for a linked-but-unused target, `absent_from_closure`
for the absence basis; reports predating the member read as the bounded
basis). The report validator distinguishes the two: a REFUTED usage
condition may sit beside `vulnerable_code_reachability=FALSE` and a
SUPPORTED NON_APPLICABLE classification only when its cited negative
carries `absent_from_closure` and the condition names the
runtime/dynamic boundary — the bounded basis and every other REFUTED
rule (verified negative under a complete scope, the not-a-safe-
conclusion limitation, the auto-close prohibition) are unchanged.

### 13.24. R6 positive-answer discharge and semantic plan repair (2026-10-18)

A live `--decision-ready` run (`case-17`, harness `qwen3.6-35b`)
measured the last two structural defects keeping the lane from
decision-ready:

- **A positive answer never discharged its required check.** The lane
  discharge gate and the flow's produced-observation rule both required
  `COMPLETE`, but `package-usage` reports USED at `PARTIAL` by contract
  (positive static usage never claims runtime execution or attacker
  reachability). The model re-ran the identical required check three
  times, each call returning OK+PARTIAL, and the reassessor could never
  close the run. The contract is now answer-based: a required check
  discharges when its question is *answered* — the closed-negative path
  (OK + non-empty scope + named coverage rule + snapshot binding +
  digest pin, COMPLETE) is unchanged, and a bounded positive verdict
  (`usage=USED`, package- or symbol-level) discharges through the new
  `positive_answer` path. The recorded run states which path
  discharged: `flow.Observation.discharge_path`
  (`closed_negative`/`positive_answer`, omitempty) is stamped by the
  producer — the flow broker over the session audit binding, or the
  lane discharge gate for prior evidence — never by the planner. A
  PARTIAL record that answers nothing, an off-snapshot or unscoped
  one, and every errored/degraded record still fail closed and never
  discharge. The new optional `flow.AnswerAwareCatalog` interface keeps
  the check semantics in the session catalog (`mappedFlowCatalog`
  decodes `PackageUsageData`); `internal/flow` stays vocabulary-clean.
  A positively answered observation also no longer degrades the ledger
  — its interpretation bound stays recorded in the observation's
  limitations — so a run carrying only answered checks can reach
  `DECISION_READY`.
- **A semantically rejected plan terminated the run.** The same run's
  step 4 proposed a bogus package and the subject-anchor gate refused
  it (`SUBJECT_ANCHOR_MISSING`); the flow terminated
  `UNSUPPORTED_CHECK_OR_CONDITION` instead of letting the model fix
  its plan. The single bounded self-repair turn now covers admission
  rejections too: a decoded plan the registry refuses (rejected
  arguments, the subject-anchor gate, an unknown check or condition)
  is recorded as a `plan` event carrying the rejection on its `error`
  member, the recorded reason and the re-encoded plan go back through
  `PlanInput.repair_error`/`repair_answer`, and the planner answers
  once more at the same step. The turn is shared with the
  `PlanContractError` decode repair — one repair per planner
  invocation, any second failure terminal with the existing named
  reason (`UNSUPPORTED_CHECK_OR_CONDITION`, `PLANNER_FAILURE` or
  `BUDGET_EXHAUSTED` as the rejection class dictates). Replay is
  unchanged: `plan` events are planner turns in order regardless of
  `error`, so the recorded stream reconstructs repaired runs
  byte-identically and pre-change records still round-trip.

The same seam closes for **symbol-unreachability**: a disproven record —
concrete product references or a module-internal chain reaching a
declared subject — answers the check's question ("is the declared
symbol unreachable?" → no) at PARTIAL by contract, and now discharges
through `positive_answer` like package-usage USED. The promoted fact
envelope keeps the finding visible: the disproven record promotes a
verified PARTIAL-coverage fact and emits
`declared-symbol-reachability=reached` for the subjects the record
proves reached (module-internal keys attribute per subject; pooled
product references attribute a single-subject run only), so
`rule.declared-symbols-unreached` is contradicted and the answered
reachability dimension lands on the artifact as an
`evidence_conflict` contradiction. An open or undecodable proof still
promotes nothing and never discharges.

A second policy overreach on the same run is also corrected — this one
is a deliberate policy change, recorded here explicitly: the
observation ledger no longer marks coverage incomplete for an `OK`,
audit-bound, digest-pinned record below COMPLETE **unless the action
served a policy-required check**. Informational checks report PARTIAL
by contract (`module-usage`, `module_internal_reach`, the scan
family — `internal/evidencetools/dynamic.go`, `dependencies.go`,
`dataflow.go`), so the old rule punished exactly the behaviour the
agent lane is for: the more the planner investigated, the less
decision-ready the run became, and a run carrying five correct
contradiction entries capped to all-`HOLD_UNKNOWN`. The bounded
record's limitation row is still emitted and the observation's own
limitations ride verbatim — the bound is never hidden. Retained
fail-closed paths: a non-OK status, an unknown status, a missing
audit binding or a missing digest degrade the ledger for **every**
check; an undischarged required check still yields
`NOT_DECISION_READY` naming it (`missingRequired` now precedes the
generic ledger reason so the check is always named); a required
check whose record answers nothing still fails closed; and
`capArtifactToHold` plus every close rule are untouched. Prior
`Evidence` rows carry no check identity, so their coverage bound is
recorded as a limitation, never a ledger defect — the same
informational narrowing.

No verdict gate, completeness semantic or prompt revision changed —
the pinned `r6-plan-v6` `<REPAIR>` contract carries the same
`repair_error`/`repair_answer` fields for both failure classes.

### 13.25. R6 advisory-condition decision variable (2026-10-18)

A live `--decision-ready` measurement showed the decision-ready lane
reaching `DECISION_READY` on a case whose advisory text states a
concrete exploitation precondition (a negative `prefetchCount`/
`prefetchSize` cast to unsigned) — yet the artifact still asked the
generic `deployment_perimeter` question, while its derived
`human_action.environment_questions` already quoted the advisory's own
sentence. The human-facing ask now keys on the advisory's condition
itself.

`internal/research` derives the key from the recorded text: when the
frozen `summary`/`description` yield **at least one** sentence
declaring a deployment/config-shaped precondition (the existing
`advisoryEnvStatements` pipeline, verbatim quote), the artifact
declares the code-owned `advisory_precondition` variable instead of
`deployment_perimeter`, grounded on the **first** statement in the
extraction order (summary before description):

- `decision_variables[].question` embeds the recorded sentence verbatim
  and asks whether the precondition holds in the deployed environment
  and whether the named input/configuration is attacker-influenced or
  operator-controlled; `allowed_values` is the closed set
  `holds`/`does_not_hold`/`unknown`;
- `decision_variables[].derived_from{field,quote}` carries the same
  provenance shape the anchored-subject gate records (additive/
  `omitempty`; legacy artifacts byte-identical);
- the branch set is `B-ADVISORY-PRECONDITION-{HOLDS,DOES-NOT-HOLD,
  UNKNOWN}`: `does_not_hold` → COMPLETE +
  `ACCEPT_ENVIRONMENTAL_MITIGATION` (the existing conditional
  mitigation, never a code-level close), `holds` → COMPLETE +
  `KEEP_OPEN_FOR_REMEDIATION`, `unknown` → NOT_DECISION_READY +
  `HOLD_UNKNOWN`; each branch premises on a `advisory-precondition`
  condition carrying the verbatim statement, and the recorded
  `build_variant` bound plus `B-BUILD-VARIANT-OTHER` are unchanged;
- `human_action.environment_question_refs` names `advisory_precondition`
  and `environment_questions` keeps carrying every derived statement —
  the second and further recorded sentences stay as additional
  verbatim questions, never merged into an invented one;

An advisory stating no such condition produces today's generic
perimeter artifact byte-identically; several recorded statements still
key on the first (its provenance names that statement's field) while
the rest stay as questions. No gate is weakened: `CLOSE_*`
stays code-grounded only and takes precedence over the derived
dimension, `auto_close=false` is unchanged, and
`ApplyEnvironmentAssertions` keeps accepting only declared variables
and declared values.

### 13.26. Lane-terminal dominance in the decision-ready projection (2026-10-18)

The full live agent census showed the decision-ready projection losing
six deterministic verdicts: the artifact's own `product_applicability`
recorded `version_affected: FALSE`, yet the run's `NOT_DECISION_READY`
termination (`policy-required checks remain undischarged:
package-usage`) capped the artifact at `HOLD_UNKNOWN` and the `/3`
decision — projected from the artifact alone — reported `INCONCLUSIVE`.
That inverted the core invariant: `NOT_AFFECTED` is defined only by the
deterministic applicability chain, and a supporting layer's failure may
never erase a verdict the lane already established.

`decisionForRecordedRun` (`internal/research/flow_adapter.go`) now
consults the lane's terminal decisions before the artifact: the shared
`laneApplicabilityDecision` chain (identical to `VerifyDecision`'s
first gate — still the only route to `NOT_AFFECTED`) and a lane-owned
symbol proof's non-`INCONCLUSIVE` authority decision stand regardless
of the flow's termination or the artifact's disposition. The recorded
failure is never hidden: the run's termination plus every undischarged
required check ride as `decision.limitations` on the standing verdict
(also visible in `flow-result.json` and the run manifest), and the
artifact keeps its `HOLD_UNKNOWN` material verbatim. A lane with no
terminal decision behaves exactly as before — the artifact's
disposition, `HOLD_UNKNOWN` included, governs. `auto_close=false` and
the artifact's close rules are unchanged; `decision_artifact` stays the
`/3`-only member.

### 13.27. Frozen `go/packages` load context + structured skip diagnostics (2026-10-19)

The skipped-package census had three silent holes: `ModuleInternalReach`
built its own `packages.Config` and dropped `BuildFlags` (a tag-gated
module's call graph was enumerated under a different build context than
the product roots); a failed package with zero recovered imports landed
in neither skip list and vanished from the scope denominator entirely,
so a `NOT_USED` could verify beside a broken package; and the loader's
own diagnostics never reached the report, so a prerequisite failure
(the `cmqc.h` shape — a cgo package dying on a missing system header)
was an anonymous exclusion instead of a build blocker.

`Index.loadConfig` is now the single `packages.Config` construction site
shared by product-root loads, dependency-extra loads, the no-syntax
importer census and the standalone module-reach load — one environment
(GOOS/GOARCH/CGO_ENABLED/vendor mode/toolchain), one flag set, one
cancellation context, with no silent divergence. Failed packages stay
out of typed scans but every one of them lands in a canonical
`SkippedPackage` record (path, recovered imports, `imports_complete`,
`source_visible`, loader error text) exposed by
`SkippedPackageDiagnostics`; `SkippedPackages` is its path projection.
`ProductUsage` keeps the negative open whenever a skipped package could
hide a reference: importers of the target, unrecoverable source, or
incomplete import recovery each emit a gap carrying the concrete
compiler diagnostic — and a failed package whose complete recovered
import set provably excludes the target no longer needs one. Observation
scope records the structured record in
`scope_details.extra.skipped_package_diagnostics` plus one actionable
limitation per package naming the primary compiler diagnostic — a
missing header reads as a prerequisite/build blocker, never a silent
skip. Tests: `TestLoadConfigSharedBuildContext`,
`TestLoadEnvSharedContextVendoredExtras`, `TestSkippedPackageDiagnostics`
(type-check failure, unrecoverable source, missing C header),
`TestSkippedPackageZeroImportStaysInDenominator`.

### 13.28. Interface-dispatch narrowing only under a complete receiver-instantiation probe (2026-10-19)

Symbol-unreachability and `ProductUsage` narrow interface-dispatch
candidates away through the product receiver-instantiation probe: a
method whose receiver type is never materialized in product-visible
syntax cannot be the dynamic target of an interface call. The probe had
two silent holes. An unresolvable receiver type (undeclared type name,
`(*T).M` spelling the lookup never normalized) returned an empty
candidate list that every consumer read as a *closed* dispatch set —
and `IsReceiverTypeInstantiated` answered false for it, so
`extendNegativeScope` even discarded unresolved candidates outright.
And the probe itself ran over `ix.pkgs` only: a product package that
failed to type-check never entered the instantiation inventory, so
narrowing could claim "never instantiated" over an incomplete scope.

Narrowing is now gated on a complete probe — `dispatchGaps` (symbol
unreachability) and the `ProductUsage` dispatch checks (symbol and
package level) all require: the subject's receiver type resolved
(`(*T).M` normalizes to `T`), dynamic materialization absent
(`reflect.New/NewAt`, `unsafe`, `plugin`, `//go:linkname` keep the set
open), and zero skipped product packages. Every shortfall keeps the
full candidate list *and* emits a named limitation — a narrowing
failure never surfaces as an empty dispatch list. An unresolved
receiver still returns candidates: `InterfaceDispatchSites` falls back
to every interface method call with a matching name (a superset of the
real candidates) and reports the set as open, so no site is dropped
merely because its concrete target could not be found. Two adjacent
omissions closed in the same pass: a call through an interface declared
in the subject's own package now counts for concrete subjects (the old
same-package skip confused the selected interface method with the
subject itself), and interface-typed receivers return no candidates at
all — an interface can never be the dynamic type of a dispatch.
Package-level
usage names the same gap when a linked target package loads without
type information (its method-bearing types are unenumerable), and an
unresolved receiver counts as instantiated for `reflect_method`
relevance — the marker cannot be narrowed away by a type the index
cannot see.

The acceptance shape is unchanged where narrowing is sound:
`SafeFormatter.String`-style receivers absent from a *complete*
instantiation inventory close to an empty dispatch set and permit
`NO_EXPLOIT_PATH_FOUND`/`NOT_USED` when every other gate passes;
`URI.String`-style instantiated receivers keep their candidates open
and block the negative. Tests:
`TestInterfaceDispatchSitesUnresolvedReceiver`/`ParenReceiver`/`NoMatchingInterface`/`DepDeclaredInterface`,
`TestUnreachabilityDispatchNarrowedUninstantiated` (closed proof),
`TestUnreachabilityDispatchUnresolvedReceiver`/`SkippedPackage`/`NarrowingDisabled`,
`TestDispatchGapsProbeFailure`, `TestUnreachabilityUnresolvedReceiverMarker`,
plus `ProductUsage` subtests `UnresolvedReceiverKeepsDispatchOpen`,
`SkippedPackageBlocksDispatchNarrowing`,
`SkippedPackageBlocksPackageNarrowing` (+control) and
`UnresolvedReceiverReflectMarkerStaysRelevant`.

### 13.29. Package absence vs symbol unreachability reconciliation (2026-10-19)

Case-10 class findings record two different negative-looking facts that
are not interchangeable: a `package-usage` verdict whose package is
absent from the linked import closure (`usage_basis=absent_from_closure`,
package-level only) and a `usage-scope` build-closure class
(`test-only`+`VERIFIED` / `mixed` / `unknown`). The decision layer now
reconciles them instead of selecting the favourable record:

- `packageAbsenceDecision` refuses promotion whenever any
  advisory-declared subject carries contradicting package presence —
  a bound `package-usage` observation with `present=true` (regardless
  of its source-usage verdict) or a promoted `PACKAGE_USAGE` fact whose
  basis is not `absent_from_closure`. The refusal is a named
  `contradictory package/build facts` limitation identifying the exact
  observation or fact, not a silent choice between records.
- Positive product-linkage/use blockers name the record that blocked
  the negative (`observation id`, `usage_scope=...`, or fact id and
  subject), so a mixed/product build-usage class against an absence
  claim surfaces as the recorded disagreement it is.
- A symbol subject still never becomes absent because its package is
  absent in a source-usage result; package presence evidence is not a
  contradiction of symbol unreachability, and the
  `FalsifierDeclaredSymbolUnreached` authority remains the only route
  for package-present/symbol-unused closure.
- An open may-call enumeration stays open at zero returned sites:
  `may_call=0` inside a `partial` enumeration is never read as a closed
  empty caller set (pinned at the primitive, the authority gate and the
  lane level).

- The `ProductUsage` cross-check inside `VerifyUnreachable` blocks the
  proof only on named scope gaps: when its UNKNOWN verdict rests solely
  on the linked-closure absence note (the symbol-level linked-package
  premise it deliberately keeps), that note is this proof's own positive
  non-reachability evidence — already filtered by `usageSpecificGaps` —
  so no usage limitation is recorded. Any surviving named gap still
  emits `product usage check could not close its negative verification`
  plus the gap text.

Both close routes still terminate at `NO_EXPLOIT_PATH_FOUND` — never
`NOT_AFFECTED` — and `decision.falsifier` names the proof basis
(`package-absent` for build-closure absence, `declared-symbol-unreached`
for the symbol authority). Tests: `TestPackageAbsenceContradicts*`,
`TestPackageAbsenceMixedBuildUsageContradicts`,
`TestPackageAbsenceSourceAbsenceIsNotClosureProof`,
`TestDeclaredSymbolAuthorityOpenMayCallZeroSites`,
`TestDeclaredSymbolAuthorityCoexistsWithPackagePresence`,
`TestDeterministicSymbolProofOpenMayCall`, and `ProductUsage` subtests
`AbsentRequiredPackageVerifiesNotUsed`/`AbsentRequiredPackageSymbolStaysUnknown`.

## 14. First-layer VEX ablation — single-case diagnostic (`eval/first_layer_ablation/`)

Эксперимент отвечает на узкий вопрос: **на каком изменении prompt/входов/tools
первый LLM-слой теряет исследование и исходную VEX-классификацию** — отдельно
от downstream verifier и policy status.

### 14.1. Границы эксперимента

* Один кейс: Kubernetes snapshot `e196d24`, `CVE-2023-44487`; Qwen3.6-35B-A3B,
  3 заранее назначенных повтора, timeout 1800 s, один worker.
* Плечи A–E отличаются ровно одним treatment: A — точный официальный VEX prompt;
  B — + advisory как данные; C — + семантические binding rules (1–3);
  D — + восемь assessment-секций; E — + описание izyan MCP tools.
* **Это диагностика одного кейса, а не доказательство общей parity.** Один
  кейс локализует место потери качества; переносить вывод на benchmark нельзя.
* GT/правильный ответ не передаются модели. Все attempts сохраняются; нет
  selective retries, best-of, cache admission. Инфраструктурные prerequisites
  (например, пустой `opencode.env`) — не результат модели.

### 14.2. Команды

```bash
# Task 1: заморозить manifest и prompt-плечи (офлайн)
python3 -m eval.first_layer_ablation.protocol --output-dir <dir> \
  --case <case.json> --advisory eval/agent7/advisories/k8s-44487.json \
  --runtime <runtime.json>

# Task 2: живые attempts A–E x 3 (Docker/OpenCode; один image digest).
# CLI и preflight-контракт — в eval/vexbench_first_layer_ablation.py --help.
python3 eval/vexbench_first_layer_ablation.py --help

# Task 3: офлайн-отчёт по сохранённым attempts
python3 -m eval.first_layer_ablation.report \
  --experiment-dir <dir> \
  --harness-dir /tmp/vexbench-agent-ctl
```

Отчёт пишет `comparison.json` и `comparison.md` в `<dir>` (или `--out-dir`).
Он не вызывает модель, Docker, сеть или izyan MCP. Официальный parser нужен
только чтобы восстановить категорию, если её нет ни в `status.json`, ни в
`attempt.json.official_category` (Task 2 сохраняет parser-проекцию;
`eval.c1.status.AttemptStatus` хранит verdict, но не category). Parser
загружается из harness checkout (`C1_HARNESS_DIR` / `/tmp/vexbench-agent-ctl`,
либо `--harness-dir`).

### 14.3. Что разделяет отчёт

| Слой | Источник | Никогда не подменяет |
|---|---|---|
| Official parser result | `status.json` (`official_parse`, `overall`, `failure_reason`), категория — из `status.category` / `attempt.json.official_category` или повторно неизменённым `evaluate.result_parser.parse_category` | Первичен для всех outcome-счётчиков |
| Full-JSON audit projection | независимый decoder `eval.c1.parser_audit` по terminal answer | Записывает полный recovered JSON, disagreement и `official_missed_expected_answer`; official не меняет |
| Research trace | `native_tool_calls.jsonl`, `tool_calls.jsonl`/`observations.jsonl`, citations в ответе | Ссылки на decisive observations и source citations |

Исходы взаимоисключающие: `vulnerable`, `dangerous_negative`, `uncertain`,
`parse_failure`, `timeout`, `provider_failure`, `infrastructure_failure`,
`other_failure`, `missing_attempt`. Timeout/provider/infrastructure
классифицируются **до** parse failure и никогда не считаются negative или
uncertain. `dangerous_negative` требует официально принятой safe-категории на
кейсе с известным исходом `vulnerable`.

Диагноз отделён от исхода и различает:

* `not_researched` — в сохранённом attempt нет native tool calls, MCP
  observations и citations (отсутствие видимого следа, а не доказательство
  отсутствия скрытого reasoning);
* `researched_but_wrong_conclusion` — следы исследования есть, но официальная
  категория — safe negative;
* `correct_answer_lost_by_parser` — full-JSON audit восстановил
  `category=vulnerable`, а официальный parser её не принял; официальный
  результат при этом сохраняется без изменений;
* `researched_inconclusive`, `researched_answer_unparsed`, `correct`,
  `no_answer` — остальные состояния.

Downstream verifier (`eval/task6/validator.py`, `validator_results.jsonl`,
negative verification, auto-close) не читается и не используется для оценки
первого слоя. `dangerous_negative` и `parse_failure` — разные дефекты; ни один
из них не является «сохранённым качеством».

### 14.4. Тесты

```bash
python3 -m unittest \
  eval.first_layer_ablation.protocol_test \
  eval.first_layer_ablation.runner_test \
  eval.first_layer_ablation.report_test
```

`report_test` использует только синтетические attempt-фикстуры: без Docker,
сети, модели и izyan.
`runner_test.C1HarnessProfileTest` импортирует реальные harness-адаптеры
(без контейнера/модели/izyan), когда задан `C1_HARNESS_DIR` (или существует
`/tmp/vexbench-agent-ctl`); иначе класс пропускается.

### 14.5. Runtime decision A — один legacy C1 runtime для A–E

Принятое архитектурное решение (2026-10-24, `agent://FirstLayerRuntimeDecision`,
option A): все плечи используют **один C1 image digest и один legacy pipeline**.
A–D запускаются профилем `opencode-c1-nomcp` (та же реализация, образ и
launch-путь; в синтезированном config нет ключа `mcp`), E — `opencode-c1`
(тот же образ/pipeline + ровно `mcp.izyan`). `opencode-b1p`/E6 image для этого
эксперимента не используются; E6 не ослабляется. Это **legacy benchmark
permissions** (writable workspace, network,
`--dangerously-skip-permissions`), а не E6-safe runtime; такая формулировка
в отчётах запрещена.

* Harness-изменение записано как `eval/c1/harness/vexbench-agent-ctl-c1-runtime.patch`
  (применяется к baseline `80cddea`; см. `eval/c1/harness/README.md`).
  Патч-файл не коммитит внешний checkout.
* Образ: `vex-bench-go-opencode-c1:latest` собирается
  `C1_IMAGES=opencode docker/build-c1.sh <shadow-checkout> <ref>`. Preflight
  пиннит его content id (`sha256` image id); `izyan-evidence-tools` sha256
  записывается при сборке в `docker/c1-image.stamp` (вне репозитория).
  Точные значения текущей сборки — в отчёте Task 4a.
* Секретный канал: `VEXBENCH_HOST_ENV_FILE` / `VEXBENCH_HOST_CONFIG`
  резолвятся адаптером per-call; контроллер выставляет их из
  `--secret-env` / `--secret-config` на время preflight и каждой попытки.
  Preflight сравнивает resolved пути адаптера с проверенными файлами и
  отказывает при расхождении (`secret_env_path_mismatch` /
  `secret_config_path_mismatch`). Значения ключей не читаются в артефакты.
* Effective-config equality выводится из adapter-generated фактов: image
  suffix/tag, pipeline id, canonical model binding
  (`custom-openai/Qwen/Qwen3.6-35B-A3B`; alias `qwen3.6-35b` тоже принимается),
  resolved env/config paths, exported artifact surface и хэш
  синтезированного config без `mcp`. A–D обязаны быть идентичны; E
  отличается только `agent`+`mcp`.
* Request capture: `request.json` записывает видимые system/user messages и
  **вызванные** tools. Отсутствие system message в export записывается как
  `absent_from_export_not_proof`, а не как доказательство, что runtime их не
  отправлял; полный tool schema export не раскрывает.

**Историческая сопоставимость ограничена.** Прошлый plain-результат Qwen3.6
получен на другой runtime-конфигурации без доказанного совпадения digest;
A — свежий exact-prompt control и новый matched-runtime control, а не
воспроизведение исторического plain run. Ни прошлый TP, ни утверждение
старого отчёта об «одном и том же Docker image» не подтверждают parity.


## Assessment outcomes (2026-10-26)

Benchmark and eval accounting now separates the three outcomes and the error
populations instead of collapsing everything into "inconclusive":

| Population | Meaning |
|---|---|
| `decided` | A definitive verdict was published (`EXPLOITABLE`, `NOT_AFFECTED`, `NO_EXPLOIT_PATH_FOUND`). |
| `external_dependency` | `INCONCLUSIVE` with a named external fact (e.g. a shipped release toolchain). |
| `analysis_failed` | `FAILED`: the analyzer could not complete the proof. **Not** a compatibility answer. |
| `false_safe` | A safe verdict against vulnerable ground truth. |
| `false_positive` | An exploitable verdict against fixed/absent ground truth. |

Moving tool limitations out of `INCONCLUSIVE` therefore does **not** increase
successful completion: completion counts decided answers only, and failed
analyses are reported as their own population. Frozen historical labels and the
saved runs are not rewritten; new observations belong in the calibration report
[`docs/dev/reports/2026-10-26-definitive-verdict-calibration.md`](../docs/dev/reports/2026-10-26-definitive-verdict-calibration.md).

A CVE-scoped benchmark task may only be scored against CVE-wide truth when the
answer is CVE-scoped: an exact-record answer is refused as
`SCOPE/UNSUPPORTED_NEGATIVE_SCOPE` rather than silently compared.

### 13.30. Candidate identity before candidate absence (2026-10-28, re-landed)

Absence is evidence about real subjects only, and a fix-derived route must
prove identity and necessity before it may conclude anything.
`GHSA-pwhc-rpq9-4c8w` at `containerd v1.7.27` had been closed
`NO_EXPLOIT_PATH_FOUND` on four candidates read from a v2/main-line patch
(`cmd/containerd/server`, `core/runtime/v2`, `plugins/cri/runtime`,
`plugins/sandbox`), none of which exists in the selected version at all. That
proof is **withdrawn**: its subjects were guessed, and its absence evidence was
vacuous.

- A fix-derived candidate records its module-relative patch coordinate
  (`RootCause.Binding`). `rootcause.Verifier` resolves it in the exact selected
  version's own source and records `ADMITTED`, `UNMAPPED` or `UNMEASURED`. This
  is **modelling identity only**: an `ADMITTED` coordinate says the patch path
  exists there, never that the advisory's defect lives there, and it is not
  absence authority. `v1.4.13` source is never accepted as evidence for
  `v1.4.3`; another version's bytes fail the effective-coordinate comparison,
  and a missing exact source is a named input/proof failure, not a
  non-counterpart finding.
- `RootCause.Absent`, `ExploitModel.AbsentSubjects` and every absence-falsifier
  claim require one shared admitted result (`domain.AbsenceAdmission`, built by
  `fixbinding.AdmitAbsence` / `AdmitAbsenceFor`). The admitted bases are: the
  record's own declaration, a re-admitted own-record operation binding, a
  genuine operator input, the re-derived exact-preimage route, or a
  checker-created persisted content proof. An unmapped or coordinate-only
  candidate stays positive-blocking and produces `FAILED` with
  `CODE / ROOT_CAUSE_UNRESOLVED / ROOT_CAUSE`
  (`INPUT / INPUT_RESOLUTION_FAILED / ROOT_CAUSE` when the selected source or
  resolved version cannot be resolved at all).
- The exact-preimage route is not path existence: the complete old changed
  region must match one unambiguous site in the exact selected source, the
  enclosing declaration must be covered by the record's own declared package
  boundary, the postimage must parse, and the captured bytes must reproduce the
  recorded preimage digest. A same-line fix that merely resolves its path, or
  whose preimage changed, does not earn absence.
- The persisted content proof (`RootCauseModel.FixProof`) is re-derived by the
  pure checker from its captured input bundle at every boundary; a saved status,
  cover or subject list is never authority. The root-cause resolver is its
  production producer. It builds the patch-side source for each declared
  locator from the selected implementation only where the change's complete
  before-image is line-aligned with the selected file; every other locator keeps
  its named `MISSING_PATCH_SOURCE` obligation and the binding refuses. Contract
  `fixbinding/re-derivation/2` keeps one source per locator, because declared
  locators are not a series. Effective external components are still an explicit
  input obligation: the pipeline does not capture them, so any boundary that
  reaches an external implementation edge refuses the cover. Exact `v1.4.3`
  support must likewise account for the effective external CRI component
  (`github.com/containerd/cri`) or remain unresolved.
- Replay is not grandfathered: the persisted exact-GHSA case
  (`analysis-case/2`, four absent v2 subjects, saved
  `DECIDED / NO_EXPLOIT_PATH_FOUND`) no longer re-admits. Its assessment
  recomputes to `FAILED` with `CODE / ROOT_CAUSE_UNRESOLVED / ROOT_CAUSE` and
  `finding.Project` refuses it; the saved evidence, claims and result stay as
  recorded. A stored `fix_binding`-era payload remains withdrawn,
  non-admitting historical evidence.
- Operator-supplied root causes (`--root-cause`, manual model, eval corpus) are
  recorded as `RootCauseOriginManual` — an input, not a derived guess — and keep
  their pre-existing route. A duplicate or relabelled `MANUAL`/`LLM_PROPOSED`
  candidate for a subject a refused content route claimed is a dependent of that
  derivation, not a new input.

Requested-CVE scope is separate and unchanged: an exact-record NEPF is never
lifted to the CVE, and no subject or effect count from the withdrawn run is
evidence. No real-corpus NEPF through the full content proof is claimed here;
only the exact-preimage route is measured end to end.

### Phase 6 Task 3: offline configuration writer evidence (2026-10-29)

`field_assignments` now returns `writers` (`domain.ConfigWriterEvidence`) in
addition to the existing `assignments`/`count` projection. It is always PARTIAL,
not an effective-value or safety decision. `EvidenceGraph.ConfigWriters` retains
the typed observation for downstream configuration verification; merely adding
this evidence does not cause `ConfigFlag` to claim safety.

Actual offline strict-session/MCP smoke (`GOPROXY=off GOSUMDB=off`):

| Independent fixture | Objects | Declaration-wide assignments | Scope runtime-channel sites | Inventory bytes | Payload bytes | Result |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `configscalarprod` | 3 | 2 | 0 | 41163 | 56889 | PARTIAL observation |
| `configoverrideprod` | 4 | 3 | 8 | 112608 | 159401 | PARTIAL observation |

The first distinguishes an unused insecure object, a consumed constant-default
object and a consumed zero-default object. The second binds copy and pointer
alias edges separately from the consumed object, and records environment,
flag, file, decoder and reflection channels alongside address/callback/external
mutation blockers. Channel names never establish runtime values. Scope readers
are not asserted to override a particular object; no generic taint propagation
or interprocedural alias resolution is introduced.

The independent `configwriterboundsprod` regression fixture additionally checks
canonical call-parenthesis coordinates through actual `callAt`/`TraceArgument`
resolution (including a multiline callee), empty/keyed-omission bool defaults,
foreign named-type separation, unknown tuple-result construction, explicit
field/whole-object range-writer blockers and implicit pointer-receiver method
value capture. Range values and method-value mutation remain unresolved, not
silently treated as the object's safe initializer. Direct method calls are not
mislabeled as method-value captures; both `cfg.Enable()` and `(cfg.Enable)()`
retain the exact typed callee, receiver consumption and mutation blocker.

Canonical inventory raw/run/build pins and measured source hashes survive in
the typed result. Above the existing 256KiB persistence cap, the shared sidecar
route retains full writer bytes, a bounded display envelope and size/SHA-256
binding; focused controls reject missing/tampered payloads without promoting
PARTIAL. The independent necessary-use verifier is described below; these
observation results are unchanged and do not themselves establish safety.

### Phase 6 Task 4: offline captured configuration falsifier (2026-10-29)

The approved narrow route is an existing admitted mandatory `CHECK_TRIGGER`
boolean argument, not an inferred mandatory `config_flag`. Actual captured
advisory bytes/current record pin, shared mechanism parsing and captured typed
formal binding establish the necessary value. Full source/module bytes and the
canonical inventory are replayed against the independently acquired snapshot
`ContentHash` and its existing `t1` manifest. One checker is used for candidate,
live verification and persisted verdict/requested-finding/report admission.

Actual offline acceptance and publication smoke (`GOPROXY=off GOSUMDB=off`):

| Independent fixture | Relevant calls | Captured nonstandard packages | Manifest bytes | Certificate bytes | Inventory bytes | Current result |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `configcheckdirectprod` | 1 | 1 | 259 | 3063 | 41160 | VERIFIED necessary argument falsifier |
| `configcheckcopyprod` | 2 | 2 | 477 | 4788 | 42432 | VERIFIED necessary argument falsifier |

Sizes are from the documented local smoke and include its original source
coordinates; path-dependent payload sizes are not benchmark measurements. The
serialized cases were 119496/126163 bytes in the source-free publication smoke.
Both use the real advisory builder, measured Go inventory, certificate producer,
`CheckTrigger` evaluator and live verifier. The collector integration independently
persists full certificates and closes both fixtures. After renaming the original
source trees away, both cases replay through verdict, requested finding and all
report outputs. Missing certificate payload or changed digest refuses publication
without erasing the original historical verification.

Ordered local bool writes/copies preserve copy timing: later source mutation does
not mutate the copy; an unsafe initial value overwritten before consumption is
not a counterexample. A genuinely unsafe second consuming write/object or a
dependency-internal consuming alternative contradicts the negative, not TRUE
exploitability. Unknown runtime values, tuple/range writes, alias/address escape,
direct/parenthesized pointer-receiver mutation, captured method values, closures,
callbacks, interfaces, incomplete consumer sets and external sources stay UNKNOWN.
Forged record/argument/ground metadata, source bytes/manifests, package ownership
under a rehashed canonical inventory and unsupported historical configuration
falsifiers are refused by focused behavioral tests. Selected filenames must
exactly equal the anchored directory set: repinned nonexistent selections and
duplicate inventory filenames refuse even when source bytes/root remain intact.

This first application envelope requires anchored complete nonstandard source,
no explicit standard imports/native code/build variants/source-coordinate
directives, generic declarations or external library roots. The conservative
census refuses omitted non-test Go-source directories and underscore-bearing
alternative filenames; implicit standard runtime nodes remain an explicit
language boundary. In-tree module/replacement source is anchored via captured
`go.mod` and direct root replacement selection. An additional actual vendor-mode
capture survives source-free replay; vendor membership never claims independent
upstream identity. Arbitrary safe `config_flag`, Go zero
defaults and safe repository keys stay UNKNOWN. Full focused commands and
`go build ./...` passed; no full suite/corpus, Task 5, model or benchmark arm ran.

### Phase 6 Task 5 capture envelope (2026-10-29)

`--fix-source-captures` exercises the existing fix checker with local captured
artifacts, independent archive bases and optional archive-reconciled complete
trees. Captured PRODUCT `go.sum` supplies exact h1 authority; no self-generated
checksum or tree digest is an upstream anchor. `/3` authoritative replay requires
the current case product/build/record/selection and matching raw inventory evidence.
Canonical research retains the actual existing resolver proof in its record case.
Direct versioned external dependencies and explicit versioned replacements are
supported selection grounds; unresolved MVS/transitive/local-only identity and
unsupported semantic operations remain obligations. This is focused capability
testing, not a benchmark/model run or a claim that every manifest produces a proof.

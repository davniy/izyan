# Методология и гарантии безопасности (Security Deep Dive)

Настоящий документ предназначен для специалистов службы информационной безопасности (AppSec / Security Engineers), архитекторов и аудиторов. В нём подробно описаны принципы математической строгости анализатора, модель угроз, доказательная база, защитные механизмы против ложно-отрицательных выводов (`false-safe = 0`) и роль искусственного интеллекта.

---

## 1. Концепция и модель угроз

### Главный инвариант: Презумпция опасности
> **Отсутствие найденного пути эксплуатации не доказывает его отсутствие.**

Стандартные статические анализаторы часто совершают критическую ошибку: если алгоритм не смог построить цепочку вызовов от входа программы до уязвимой функции, он объявляет уязвимость «неэксплуатируемой». 

В реальных приложениях на Go цепочка вызовов может быть скрыта за:
* динамической диспетчеризацией через интерфейсы (`interface{}`);
* вызовами через рефлексию (`reflect`) или небезопасные указатели (`unsafe`);
* сборкой под другие операционные системы или теги компиляции (`//go:build`);
* вызовами функций через указатели (`func values`) и горутины.

**Izyan (Vuln Analyzer) исключает эту ошибку**: вердикт «не эксплуатируется» выдается только тогда, когда система находит строгое компиляторное опровержение хотя бы одного обязательного условия эксплуатации (**фальсификатор / Falsifier**), а фаза негативной верификации доказывает отсутствие обходных путей.

---

## 2. Почему стандартного govulncheck недостаточно

Утилита `govulncheck` от команды Go — качественный инструмент анализа достижимости (reachability), строящий граф вызовов (call graph) от функций `main()` и `init()`. Мы используем `govulncheck` как один из авторитетных сенсоров, однако для полноценной оценки эксплуатируемости его возможностей структурно недостаточно.

### Чего `govulncheck` не знает:
1. **Происхождение данных (Data Provenance)**:
   Для `govulncheck` вызов `yaml.Unmarshal(data, &cfg)` — это просто факт вызова уязвимого пакета. Пришли ли байты `data` из внешнего HTTP-запроса злоумышленника, прочитаны ли из локального доверенного файла конфигурации хоста или представляют собой константу времени компиляции (`const baseline = ...`) — `govulncheck` не различает.
2. **Условия эксплуатации (Exploit Conditions)**:
   «Код вызван» ≠ «уязвимость эксплуатируема». Вызову могут предшествовать валидации значений (guards), сдерживающие проверки диапазонов или отключенные конфигурационные флаги.
3. **Локусы дефекта и OR-семантика advisory**:
   В базы уязвимостей (OSV / CVE) мейнтейнеры часто включают не только саму дефектную функцию, где происходит паника или обход прав, но и вспомогательные функции транспорта, куда коммит исправления добавил предварительную защитную проверку. `govulncheck` объединяет все символы уязвимости логическим «ИЛИ» (OR): если приложение вызывает транспортный диспетчер, выставляется красный алерт `REACHABLE`, даже если паникующий код физически не скомпилирован.
4. **Уязвимости типа «пропущенный вызов» (missing-call) и дефектная проверка**:
   Если уязвимость заключается в том, что библиотека **забыла вызвать** обязательную валидацию, `govulncheck` видит функцию проверки с 0 вызовов и молчит — ловушка ложной безопасности. Обратный случай не менее опасен: дефектна сама вызванная проверка (GO-2020-0017: `VerifyAudience` с `req=false` и массивом `aud`), и тогда отсутствие её вызова означает, что дефектная операция не исполняется. Анализатор различает эти режимы только по advisory/fix-контракту, а не по имени проверки или живому sibling-методу.

---

## 3. Система 4 терминальных вердиктов

Каждый анализ завершается одним из 4 строго специфицированных вердиктов:

| Вердикт | Описание | Доказательная база |
|---|---|---|
| 🟢 **`NOT_AFFECTED`** | Уязвимый код физически не вошел в бинарник | Только детерминистические факты сборки: пакет уязвимости отсутствует в графе транзитивных зависимостей (`go list -deps`) или используемая версия не попадает в диапазон advisory. Такой факт закрывает finding только при полном покрытии области запроса (`FULL_RECORD`-перепись точной записи); иначе остаётся компонентным фактом, а вердикт — `INCONCLUSIVE`. |
| 🟢 **`NO_EXPLOIT_PATH_FOUND`** | Код скомпилирован, но атака невозможна | Найдено обязательное условие эксплуатации, опровергнутое фальсификатором (`Claim: FALSE`), и пройдена фаза `Negative Verification: VERIFIED` (поиск обходных путей исключил вызовы дефекта). |
| 🔴 **`EXPLOITABLE`** | Уязвимость подтверждена и эксплуатируема | Доказаны все обязательные условия: недоверенный внешний ввод поступает на вход уязвимого локуса без сдерживающих проверок. |
| 🟡 **`INCONCLUSIVE`** | Неопределенность (требует триажа человеком) | Анализатор встретил неразрешимые динамические вызовы, зависимость от внешнего деплоя или неполноту данных. **Система честно сообщает о пробеле, не пытаясь угадать вердикт**. |

### Область вывода: приложение или публичный API библиотеки

Вердикт отвечает на два независимых вопроса, поэтому область вывода —
отдельная ось, а не пятое значение вердикта:

1. **Что доказано в измеренном продукте?** `EXPLOITABLE` /
   `NO_EXPLOIT_PATH_FOUND` / `NOT_AFFECTED` / `INCONCLUSIVE`.
2. **Какую границу покрывает вывод?** Деплоймент приложения — как раньше
   (пустая область); либо `verdict.exploitability_scope: library-api` для
   библиотеки, у которой доказана связка «публичный формальный параметр →
   уязвимый sink».

Для библиотеки анализатор не может и не пытается установить, как
нижестоящее приложение распорядится её публичным API. Доказанный код-факт —
**выбираемость нагрузки потребителем**: `claims[].control_basis:
library-public-api` и свидетель `data_flows[].library_input` с точным
объявлением API, номером формального параметра, sink-вызовом и номером
аргумента. Из этого **не** следует контроль со стороны атакующего в
деплойменте: `DataFlow.Origin` остаётся `UNKNOWN`, а обязательное
ограничение попадает в отчёт и VEX:

> Library-API scope: the payload is selectable by a library consumer;
> whether a downstream application exposes that payload to an attacker is
> outside the analyzed product and is not established.

Границы действия области:

* Допуск узкий и конъюнктивный (форма библиотеки, публичный API, полезный
  тип параметра, сохранение нагрузки, `DESERIALIZATION` + CWE-502,
  разрешённый root-cause sink, `ATTACKER_CONTROL` с точным аргументом).
  Свидетель не подменяет достижимость, локус, экспозицию, аутентификацию
  или конфигурацию — эти условия доказываются отдельно.
* Неудачный допуск — «не доказано», а не «безопасно»; закрытие
  отрицательного вывода и false-safe инвариант не меняются, `KNOWN_ONLY`
  остаётся `KNOWN_ONLY`.
* Для одного и того же артефакта библиотеки три потребителя дают три
  разных вывода: HTTP-тело, переданное в публичный API, даёт
  `EXPLOITABLE` по обычному внешнему происхождению (без library-области);
  фиксированные литералы — `NO_EXPLOIT_PATH_FOUND` с `VERIFIED`
  негативом; импорт библиотеки только из `_test.go` — `NOT_AFFECTED`
  (тестовая область, без допуска).
* Известные ложные тревоги Podman и Kubernetes этим не «чинятся»: у них не
  библиотечная форма и не класс `DESERIALIZATION`.

### Область запроса: что именно закрывает отрицательный вывод

Вердикт отвечает на вопрос «что доказано в измеренном продукте», но
отрицательный вывод дополнительно обязан покрыть **область запроса**.
`AdvisoryScope` фиксирует requested/resolved identity, `Kind`,
`Coverage`, `RecordExtent`, `RecordInventory` и человеческий `Basis`.
Закрытие уровня finding разрешено только когда точная запись
(`GO-…`/`GHSA-…`) представлена полностью: `FULL_RECORD` и
digest-привязанная перепись всех исходных `affected[]` entries, каждая из
которых является Go-модулем. Перепись снимается до фильтрации экосистем
и до слияния entries по имени модуля; проекция широкой записи
(`GO_PROJECTION`) закрывать запрос не может, сколько бы Go-entries в ней
ни проверили. `COMPLETE` без структурной переписи — legacy-утверждение,
а не доказательство: такие кейсы декодируются, но fail closed.

* **`kind`** — что запрошено: CVE-wide или точная запись;
* **`coverage`** — полнота утверждения (`COMPLETE`/`KNOWN_ONLY`);
* **`record_extent`** — сколько загруженного документа представлено
  (`FULL_RECORD`/`GO_PROJECTION`/`UNKNOWN`);
* **`record_inventory`** — census исходного `affected[]` (identity,
  digest, entries, represented/omitted);
* **`basis`** — только человеческое объяснение; гейт его не читает.

Module/version-негативы (модуль отсутствует в графе, версия вне
диапазона) не требуют build-target допуска, но проходят тот же
scope-гейт: при неполной записи они остаются компонентными фактами.

**Смешанная запись.** `GHSA-qppj-fm5r-hxr3` (CVE-2023-44487): 22 entries
— Go 1 (`golang.org/x/net`), Maven 20, SwiftURL 1. Это
`GO_PROJECTION` (1 represented / 21 omitted): `v0.17.0` вне диапазона
(`VersionAffected=FALSE`) сохраняется как факт, `PackagePresent`/
`BuildRelevant` не измерены, запрос не закрыт — `INCONCLUSIVE`,
OpenVEX `under_investigation`, CycloneDX `in_triage`. Этот же кейс
показывает, что неразрешимый root cause не обрывает работу: кейс
получает записанный `INCONCLUSIVE` и полный набор отчётов/экспортов
(кроме `--strict-llm`, где кейс завершается `FAILED`).

Изменение не доказывает затронутость gRPC и не «чинит» все ложные
тревоги Kubernetes/Podman. Оно отказывает в необоснованном закрытии:
CVE-wide полнота не выводится ни из префикса id, ни из одного модуля или
экосистемы, ни из `github_reviewed`, алиасов или отсутствия найденной
альтернативы. Флага-обхода нет; поиск связанных записей не реализуется.

---

## 4. Защитные предохранители (Safety Gates)

Для соблюдения инварианта `false-safe = 0` в ядро анализатора встроены специализированные защитные механизмы:

### 4.1. Defect-Semantics Admission (omitted vs defective check)
* **Проблема**: проверочное имя (`Verify*`, `Validate*`, …) и живой sibling-конвейер (например, `MapClaims.Valid`) выглядят как основание для модели «проверка пропущена», но семантикой дефекта не являются. Исторический пример GO-2020-0017 (`jwt-go`) был смоделирован неверно: advisory требует вызова `MapClaims.VerifyAudience` с `req=false`, где массив `aud` ошибочно принимается. `Valid()` действительно не вызывает `VerifyAudience`, но это означает, что дефектная операция не исполняется, а не что отсутствие вызова и есть уязвимость. Для Echo и `real-jwt-auth` дефектная проверка недостижима; продукт, не проверяющий `aud` самостоятельно, может быть подвержен другому (продуктовому) аудиторскому bypass — это не эта CVE.
* **Механизм защиты**: билдер разрешает один типизированный контракт из advisory/fix-доказательств — `DEFECTIVE_CHECK`, `OMITTED_CHECK` или `UNRESOLVED`; имена, префиксы, confidence и LLM-предложения его не допускают. Под `DEFECTIVE_CHECK` доказанная мёртвость контрактной проверки может опровергать обязательный вызов только после полной негативной верификации; под `OMITTED_CHECK` дефектный локус — omission-site на якорном конвейере, а не отсутствующая проверка; `UNRESOLVED` не даёт вердикта и завершается `CODE/ROOT_CAUSE_UNRESOLVED`. Любой deadness-негатив требует допущенной invocation-necessity premise и scoped product target; sibling-liveness остаётся наблюдением и больше не ветирует измерение. Измерено 2026-10-26: Echo под host-default — `FAILED` (`REACHABILITY_PROOF_INCOMPLETE` / `TRIGGER_PROOF_INCOMPLETE`), с operator-declared target — `DECIDED / NO_EXPLOIT_PATH_FOUND` для точной записи GO-2020-0017; запрос CVE без объявленного corpus остаётся `FAILED / SCOPE/UNSUPPORTED_NEGATIVE_SCOPE`.

### 4.2. Constant Payload Isolation (Защита константных данных)
* **Проблема**: При вызове `yaml.Unmarshal(constBytes, &outStruct)` парсер внутри использует пакет `reflect` для разбора структуры `outStruct`. Анализаторы часто путают рефлексию выходной структуры с источником входных байт и сбрасывают вердикт в `UNKNOWN`.
* **Механизм защиты**: Анализатор строго разделяет аргумент входного пейлоада и аргумент выходного приёмника. Если аргумент входных данных доказан как `OriginConstant` / `OriginGenerated`, внутренняя рефлексия парсера изолируется: атакующий физически не может изменить константу времени компиляции.

### 4.3. Trusted Host Infrastructure (Доверенная конфигурация)
* **Проблема**: Чтение конфигурационных файлов через `os.ReadFile("config.yaml")` сканеры часто трактуют как потенциальный внешний ввод.
* **Механизм защиты**: Если путь к файлу фиксирован или контролируется только оператором хоста, источник классифицируется как `OriginConfiguration`. При фальсификаторе `FalsifierTrustedInfrastructure` чтение признается доверенной средой развертывания, что позволяет безопасно закрыть уязвимость.

### 4.4. Locus Unreachability (Недостижимость локуса дефекта)
* **Проблема**: В advisory GO-2026-6443 (gRPC) дефектная паника находится в функции `RouteAndProcess` пакета `internal/xds/server`. Если проект импортирует `google.golang.org/grpc/xds`, пакет попадает в сборку, но сам паникующий метод продуктом никогда не вызывается.
* **Механизм защиты**: Фальсификатор `FalsifierLocusFunctionUnreached` доказывает, что ни один символ дефектного локуса не вызывается из продуктового кода и не может быть вызван через интерфейсы (поскольку функция находится в `internal/`-пакете gRPC, доступ к ней извне заблокирован компилятором).

### 4.5. Provenance & Measurement Admission (Допуск отрицательного доказательства)

* **Проблема**: отрицательный вывод о сборке легко получить из измерения
  **не той сборки** (хоста анализатора) или из **незавершённого**
  измерения. Суженный `govulncheck` или его падение, неполный
  `go list -deps`, пустой source-scan — это отсутствие данных, а не
  отсутствие кода.
* **Механизм защиты**: два независимых гейта, провал любого даёт
  `UNKNOWN`, а не `FALSE` с оговоркой.
  1. **Идентифицированная сборка продукта**: структурный `ProductTarget`
     должен пройти `Validate()`, быть scoped и совпадать с эффективным
     build-контекстом (GOOS/GOARCH, tags, CGO, toolchain,
     vendor/workspace, replace-директивы). Приоритет источников:
     `artifact-build-info` (артефакт/`--binary`) > `release-metadata` >
     `operator-declared` (`--goos`+`--goarch`) > `host-default`.
     Частичный ввод (один из `--goos`/`--goarch`, только
     `--build-tags`) остаётся `host-default` без scope и **никогда** не
     повышается до операторского. `--release` задаёт identity исходников,
     а `--deploy-manifests` — периметр, не build-факты.
  2. **Завершённое измерение с покрытием**: типизированная запись прогона
     (`completed_empty`/`completed_with_results`), полный
     package-inventory или завершённый, полный и не-opaque source-scan,
     плюс `VERIFIED`-верификация с тем же build-контекстом. `failed` и
     `not_run` — positive-only: они не порождают
     `govulncheck-silence`/`no-module-usage`/`config-gated-off`.
* **Следствие для практики**: без target-входов кейсы, которые раньше
  закрывались как безопасные, теперь честно уходят в `INCONCLUSIVE` —
  это **намеренное** изменение (см. §3a в
  [`dev/analysis-internals.md`](dev/analysis-internals.md) — «Scope одного
  вывода»): отрицание
  описывает только проанализированную сборку, а не матрицу
  поддерживаемых вариантов. Независимые факты (модуль отсутствует в
  графе, версия вне диапазона, release-toolchain, ключ конфигурации
  репозитория, deployment-policy) остаются в силе и закрывают вывод без
  гейта 1 — но не без scope-гейта: при неполной записи advisory
  (`GO_PROJECTION`/`KNOWN_ONLY`) module/version-негатив остаётся
  компонентным фактом и не закрывает finding.
* **Проверка на реальных данных**: Cilium `CVE-2026-35469` — при
  host-default (без флагов) не удаётся типизировать Linux-only продукт,
  поэтому `C-REACH`/`C-LOCUS` остаются `UNKNOWN` и вердикт
  `INCONCLUSIVE`; тот же снапшот с явным `--goos linux --goarch amd64`
  сохраняет измеренный позитив и `EXPLOITABLE`. Podman `CVE-2024-37298`
  остаётся прежней ложной тревогой: её позитив приходит из module-chain и
  не зависит от govulncheck, поэтому сужение допуска её не убирает и не
  должно убирать ради метрик. Kubernetes `CVE-2022-41717` — ложная
  тревога, которая может оборваться таймаутом: обрыв классифицируется как
  infrastructure outcome и никогда не становится «исправленным»
  безопасным результатом (в измеренном прогоне go1.26.1 / 24 GiB кейс
  завершился и остался прежней ложной тревогой).

---

## 5. Роль искусственного интеллекта и детерминизм (AI Governance)

Анализатор использует большие языковые модели (LLM) как исследовательский инструмент, но архитектурно изолирует их от принятия окончательных решений:

1. **Компилятор Go авторитетнее LLM**:
   Вердикты строятся исключительно на фактах синтаксического анализа (Go AST), типов (`go/types`), статического анализа графа вызовов и трассировки аргументов.
2. **LLM создаёт только предложения (Proposals)**:
   Нейросеть привлекается для семантического анализа патча уязвимости (patch-diff), предложения вероятного локуса дефекта и черновиков исключений (`ProposedNonLocus`). Ни одно предложение LLM не становится частью доказательной базы без независимой детерминистической проверки компилятором.
3. **Автономное исследование (--cve-analysis assist)**:
   Исследовательский агент выполняет структурированное исследование уязвимости с вызовом типизированных инструментов (`read_patch_diff`, `inspect_source_file`), формируя для аналитика Human Remainder (точный остаток вопросов, требующих внимания человека).
4. **Полное отключение (--deterministic-only)**:
   Для закрытых корпоративных контуров, где запрещена отправка кода во внешние API, анализатор работает в 100% детерминистическом режиме без потери базовых гарантий безопасности.
5. **Один живой investigator (Phase 4 recovery)**:
   Только `izyan triage` готовит current `decision-package.v4` из `assessment.v3`:
   unconditional action либо finite prepared branches для 0–2 environment-вопросов
   с `unknown` и максимум семью обязательными посылками. Ответ выбирает готовую
   ветвь без нового model/tool/source investigation; Accept/Reject не требует
   технического narrative. Assertions/reviews append-only и не меняют Product A,
   code claims, completeness, proofs или VEX. Conflict — `CONTRADICTED`, overflow
   или incomplete branch — `NOT_DECISION_READY` и консервативное действие.
   `research` — deterministic evidence/proof + canonical `/5` publication через
   `finding.Project`; historical `/3`/`/4` playback — `eval research-replay`
   (original bytes, no current admission). Retained offline probe не live harness.
   Offline replay копирует verified history без новой модели, Accept или timestamp.
   B1 — только `izyan eval research-b1`, frozen evaluation control.

---

## 6. Воспроизводимость, аудит и экспорт

* **Воспроизводимость (Audit Trail)**:
  В каталоге кейса `.izyan/<case-id>/` (или `.vuln-analyzer/<case-id>/`) сохраняется объект `AnalysisCase`, содержащий массив `tool_executions`: точные команды, аргументы, коды возврата и SHA-256 хеши выводов всех утилит. Повторный прогон сверяет хеши и фиксирует любые расхождения.
* **Стандарты VEX**:
  Для автоматической передачи статусов анализа в корпоративные сканеры и DevSecOps-пайплайны генерируются официальные форматы:
  * **OpenVEX** (`openvex.json`): машиночитаемый документ с утверждениями `not_affected`, `affected`, `under_investigation` и указанием обоснований (`justification: inline_mitigations_already_exist`, `vulnerable_code_not_in_execute_path`);
  * **CycloneDX VEX** (`cyclonedx.json`): формат для интеграции с Dependency-Track и SBOM-платформами.
* **Двуязычные отчёты**:
  * `report.md` (русский) и `report.en.md` (английский) формируются по принципу «Перевернутой пирамиды» и содержат готовый раздел **`## Резюме`**, написанный понятным инженерным языком без птичьего сленга статического анализа для мгновенной вставки в Jira или GitLab Issue.

---

## 7. Подтверждение на практике (Live Corpus Baseline)

Заявленные гарантии безопасности валидируются непрерывным прогоном эталонного бенчмарка ([`eval/README.md`](../eval/README.md)), состоящего из **38 реальных уязвимостей** в популярных библиотеках Go (`grpc`, `yaml.v2`, `yaml.v3`, `go-getter`, `ssh`, `miekg/dns`, `protobuf`, `jwt-go`, `unix`):

* **Всего сценариев**: 38;
* **Cleared Rate**: **20 из 38 (53%)** — автоматическое доказанное снятие алертов;
* **Signal-Cleared Rate**: **9 из 26 (35%)** — снятие ложных алертов там, где `govulncheck` выдал шумные сигналы `REACHABLE` / `package-level`;
* **False-Safe Rate**: **0 из 38 (0%)** — абсолютное соблюдение инварианта безопасности: ни одна реальная уязвимость не была ошибочно признана безопасной.

Числа этого раздела — **историческая** запись прогона на момент указанных
изменений, а не текущий пересчёт. Scope-гейт записи advisory и гейты
допуска отрицаний меняют часть прежних «correct-safe» наблюдений:
некоторые закрытия становятся `INCONCLUSIVE`, и это намеренно. Новые
измерения и их отличия от исторических меток фиксируются отдельно в
[`eval/README.md`](../eval/README.md) и отчётах калибровки; исторические
таблицы не переписываются.


## Definitive verdicts: outcome, requested finding and scope (2026-10-26)

The publication contract changed from "verdict or abstain" to three explicit
assessment outcomes. `assessment_outcome: DECIDED` publishes one of
`EXPLOITABLE` / `NOT_AFFECTED` / `NO_EXPLOIT_PATH_FOUND`;
`EXTERNAL_DEPENDENCY` publishes `INCONCLUSIVE` plus the named external facts that
would change the answer; `FAILED` publishes **no verdict** and carries typed
failure codes (`owner/code`) with a diagnostic report. `FAILED` is an analysis
refusal, not a vulnerability verdict. Claims keep `TRUE`/`FALSE`/`UNKNOWN`, so a
failed measurement leaves its claim `UNKNOWN` — the terminal classification
changes, the evidence does not.

The request pipeline is:

```text
CREATED -> SNAPSHOT_PRODUCT -> RESOLVE_VULNERABILITY (exact pin)
  -> DISCOVER_RECORDS -> per-record assessment (CHECK_AFFECTED ... EVALUATE_VERDICT)
  -> ASSESS_RELATED_RECORDS -> COMPOSE_REQUESTED_FINDING -> BUILD_REPORT
```

Discovery (`related`, aliases) nominates candidate records only. A directional
CVE attribution is a separate admitted proposition: the record's own id/alias, or
captured publisher/CNA material bound to the implementation, entry and fix.
Children are separate cases pinned to their own exact bytes; no claims, reviews,
proposals or conclusions cross the boundary. Composition is positive-only and
per profile/build; candidate negatives never close a CVE, and a CVE-wide negative
requires a declared, digest-pinned, completely enumerated corpus whose boundary
is stated verbatim.

`transport-peer` marks a witness-proved peer-input boundary and carries the
mandatory limitation that deployed adversary access is a separate question.
Listener locality (Unix/loopback binding, ClusterIP) no longer selects a trusted
profile: trust needs an operator assertion or an admitted deployment policy.

Every consumer (JSON, Markdown, CLI, scan/eval, tracker, justification,
remediation, research, OpenVEX, CycloneDX) renders the single `requested_finding`
projection; the FINAL envelope is the publish authority, not the workflow
position. See `docs/dev/plans/2026-10-26-02-definitive-verdict.md` (+ Addendum A)
and the measured calibration `docs/dev/reports/2026-10-26-definitive-verdict-calibration.md`.

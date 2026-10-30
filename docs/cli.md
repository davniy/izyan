# CLI-справочник

Бинарь собирается как `izyan` (`go build -o izyan ./cmd/izyan`). Сабкоманды: `analyze`, `scan`, `eval`, `remediate`, `research`, `triage`, `knowledge`.

## analyze — полный анализ одной advisory

```bash
izyan analyze --repo /src/product --vuln GO-2025-3595 [флаги]
```

Прогоняет весь конвейер ([`architecture.md`](architecture.md)) по одной уязвимости и
создаёт кейс в `--case-dir`.

Вход advisory — ровно один из:

| Флаг | Что делает |
|---|---|
| `--vuln <id>` | ID `GO-…`/`CVE-…`/`GHSA-…`; документ грузится из OSV API |
| `--vuln-file <path>` | локальный OSV JSON вместо API |
| `--ticket <path>` | тикет из трекера задач: generic JSON, выгрузка из Jira/GitLab/трекера, произвольный скопированный текст или `-` для stdin. Автоматически извлекает ID уязвимости, номер тикета, компонент, релиз, пакет и advisory |
| `--ticket-id <id>` | ключ тикета для выбора из списка/массива в ticket JSON |
| `--repo-map <path>` | путь к JSON-файлу маппинга компонентов/тикетов на локальные пути репозиториев (по умолчанию ищется `repos.json` в текущей директории) |
| `--llm-intake` | использовать LLM для извлечения идентификаторов и метаданных из неструктурированного текста тикета/сообщения (при `LLM_ENABLED=1`) |

Флаги продукта:

| Флаг | Что делает |
|---|---|
| `--repo <path>` | путь к Go-репозиторию продукта (обязателен, если не разрешён через `--ticket` и `--repo-map` / `repos.json`) |
| `--release <ver>` | релиз, ветка или тег продукта (или `--git-ref`); переопределяет релиз из тикета |
| `--checkout-release` | автоматически найти тег релиза и выполнить анализ в изолированном git worktree, не трогая рабочую директорию |
| `--goos`, `--goarch` | целевая платформа сборки продукта. Оба флага вместе дают `operator-declared` target (`scope=operator`); один флаг или только `--build-tags` оставляет `host-default` **без scope** — такие значения описывают сборку анализатора и не допускают отрицательных выводов о продукте |
| `--build-tags <t1,t2>` | build tags при загрузке пакетов; входят в эффективный build-контекст target-фактов |
| `--binary <path>` | собранный бинарь релиза: `govulncheck -mode binary` + реальный toolchain и модули из встроенного build info. Обычный `--binary` также даёт digest-bound `artifact-build-info` target (GOOS/GOARCH/`-tags`/`CGO_ENABLED` из `debug.BuildInfo.Settings`, SHA-256 бинаря); неполные настройки — fail closed, тогда target не допускается |
| `--deploy-manifests <path>` | путь к каталогу, внешнему GitOps-репозиторию или архиву чарта (`.tgz`, `.tar.gz`, `.zip`) с манифестами развёртывания (Helm/K8s/Compose) с защитой от Zip Slip и автопоиском в `deploy/`, `helm/`, `deployments/` |
| `--perimeter <auto|cluster|public>` | контекст сетевого периметра развёртывания для разрешения вердикта (по умолчанию `auto`, выбирает кластер при наличии фактов изоляции) |
| `--release-go-version <ver>` | версия Go, которой собран релиз (из тикета/релиз-нот) — для `std`-advisory; без неё и без `--binary`/release-evidence stdlib-applicability остаётся UNKNOWN (директива `go` в `go.mod` — только минимум) |

### Provenance сборки и допуск отрицательных выводов

Отрицательный вывод (`NOT_AFFECTED`, `NO_EXPLOIT_PATH_FOUND`, а также
`FALSE`-claims) о build-зависимых фактах требует двух независимых условий:

1. **Идентифицированная сборка продукта.** Приоритет target-источников:
   `artifact-build-info` (`--artifact`/обычный `--binary`, digest-bound) >
   `release-metadata` > `operator-declared` (оба `--goos`/`--goarch`) >
   `host-default`. `--release`/`--git-ref` выбирает identity исходников и
   не задаёт target-факты; `--deploy-manifests` — perimeter-evidence.
   `host-default` всегда non-admitting; частичный ввод не повышается.
2. **Завершённое измерение с нужным покрытием** — типизированная запись
   прогона govulncheck, полный `go list -deps` inventory либо
   завершённый source-scan, плюс `VERIFIED`-верификация с тем же
   build-контекстом.

Один эффективный build-контекст (snapshot identity, GOOS/GOARCH, tags,
CGO, toolchain, vendor/workspace) резолвится **до** загрузки пакетов и
разделяется affected-resolver, govulncheck, source-index и верификатором.
Несовпадение контекста после загрузки — fail closed
(`ErrBuildContextMismatch`), без переименования загруженного индекса.

Без target-входов кейсы, которые раньше закрывались как безопасные,
переходят в `INCONCLUSIVE`. Это намеренно: отрицание описывает только
проанализированную сборку и не превращается в матрицу поддерживаемых
вариантов. Независимые факты (модуль отсутствует в графе, версия вне
диапазона, release-toolchain, ключ конфигурации репозитория,
deployment-policy) закрывают вывод без target-гейта. Пример того же
кода под двумя контекстами — Cilium: без флагов `INCONCLUSIVE`, с
`--goos linux --goarch amd64` измеренный позитив сохраняется.

Ручные входы (обходят автоматику, полезны при отсутствии fix-commit):

| Флаг | Что делает |
|---|---|
| `--root-cause <pkg/path.Symbol>` | уязвимый символ вручную; повторяемый флаг |
| `--exploit-model <path>` | готовая модель условий эксплуатации JSON |
| `--non-locus-basis <path>` | явный экспертный ввод: JSON-файл исключений символов из сайтов дефекта (L = declared set − basis) |

### Входные форматы описания уязвимости

Анализатор может загружать описание уязвимости тремя путями:
1. **По идентификатору из базы OSV API** (`--vuln <id>`): автоматический сетевой запрос к `api.osv.dev` (Go Vulnerability Database);
2. **Из локального файла уязвимости OSV JSON** (`--vuln-file <path>`): офлайн-файл в открытом стандарте OSV;
3. **Из файла задачи/тикета трекера или произвольного текста** (`--ticket <path>`): структурированный JSON либо свободный текст из Jira/GitLab/чата/сканера.

#### 1. Локальный файл уязвимости OSV JSON (`--vuln-file <path>`)

Флаг `--vuln-file` загружает документ уязвимости из локального файла. Идентификатор уязвимости (`--vuln`) можно опустить — он автоматически считывается из поля `id` внутри файла.

Сценарии использования:
* **Air-gapped и изолированные контуры**: выполнение анализа в закрытых средах без выхода в интернет;
* **Приватные / unreleased / 0-day уязвимости**: проверка ещё не опубликованных отчётов безопасности и результатов внутреннего пентеста;
* **Воспроизводимый аудит**: фиксация точной версии advisory для детерминированного повторения в CI/CD без сетевых зависимостей.

Формат соответствует открытому стандарту **[OSV (Open Source Vulnerability Schema)](https://ossf.github.io/osv-schema/)**:

```json
{
  "schema_version": "1.3.1",
  "id": "GO-2026-6443",
  "modified": "2026-09-15T18:39:25Z",
  "published": "2026-09-15T18:39:25Z",
  "aliases": ["CVE-2026-84445", "GHSA-2v4p-qf9q-27wj"],
  "summary": "Server panic via missing authority or Host headers in google.golang.org/grpc",
  "details": "In google.golang.org/grpc, servers configured with xDS routing can panic when processing requests that lack both :authority and Host headers. The HTTP/2 transport layer accepted requests missing these headers, and the xDS server routing interceptor attempted to index the empty authority slice, causing an unhandled panic and terminating the server.",
  "affected": [
    {
      "package": {
        "name": "google.golang.org/grpc",
        "ecosystem": "Go"
      },
      "ranges": [
        {
          "type": "SEMVER",
          "events": [
            { "introduced": "0" },
            { "fixed": "1.82.2" },
            { "introduced": "1.83.0" },
            { "fixed": "1.83.2" }
          ]
        }
      ],
      "ecosystem_specific": {
        "imports": [
          {
            "path": "google.golang.org/grpc/internal/transport",
            "symbols": [
              "http2Server.HandleStreams",
              "http2Server.operateHeaders"
            ]
          },
          {
            "path": "google.golang.org/grpc/internal/xds/server",
            "symbols": [
              "RouteAndProcess"
            ]
          }
        ]
      }
    }
  ],
  "references": [
    { "type": "FIX", "url": "https://github.com/grpc/grpc-go/pull/9365" }
  ]
}
```

Примеры запуска:
```bash
# Идентификатор уязвимости читается автоматически из поля "id":
izyan analyze --repo /path/to/project --vuln-file ./advisory.json

# С явным указанием ID уязвимости (для валидации совпадения с документом):
izyan analyze --repo /path/to/project --vuln GO-2026-6443 --vuln-file ./advisory.json
```

#### Область запроса: CVE-wide против точной записи advisory

Запрошенный идентификатор определяет, что именно разрешено закрывать
отрицательным выводом (`AdvisoryScope` в кейсе). Решение принимает
структурная запись о том, сколько исходного документа advisory реально
было представлено в модели, — не число объявленных Go-entries и не
текстовое обоснование:

* **Точная запись advisory** (`--vuln GO-…`/`GHSA-…`, совпадающий с `id`
  загруженного документа) закрывает запрос только при полном
  представлении записи: `Kind=ADVISORY_ENTRIES`, `Coverage=COMPLETE`,
  `RecordExtent=FULL_RECORD` и digest-привязанная перепись
  (`RecordInventory`) **всех** исходных `affected[]` entries, каждая из
  которых является Go-модулем. Проекция широкой записи, у которой часть
  entries отброшена фильтром экосистем (`GO_PROJECTION`), полной записью
  не является — даже если все видимые Go-entries проверены. Это полнота
  *записи*, а не всего CVE.
* **CVE-wide запрос** (`--vuln CVE-…` или алиас, через который загружена
  запись) — OSV-запись обычно документирует лишь часть реализаций CVE
  (`KNOWN_ONLY`). Отрицательный факт по одному компоненту (например,
  исправленный `golang.org/x/net` в k8s) сохраняется как компонентный
  факт с версией и evidence, но **не закрывает** запрос: конвейер
  продолжает `RESOLVE_ROOT_CAUSE`/research, вердикт остаётся
  `INCONCLUSIVE`, а `report.md`/`report.en.md`, OpenVEX и CycloneDX
  показывают незакрытую область (`under_investigation`/`in_triage`).
* **`--vuln-file` без `--vuln`** наследует `id` из документа: если это
  `CVE-…`, действует правило CVE-wide; если `GO-…`/`GHSA-…` — точная
  запись. Совпадение `--vuln` с `id` файла обязательно.

Поля scope несут разные роли и не взаимозаменяемы:

* `kind` — что запрошено: `CVE` (CVE-wide) или `ADVISORY_ENTRIES` (точная
  запись);
* `coverage` — полнота **утверждения** запроса (`COMPLETE`/`KNOWN_ONLY`);
* `record_extent` — сколько загруженного документа реально представлено:
  `FULL_RECORD`, `GO_PROJECTION` (часть entries отброшена) или `UNKNOWN`;
* `record_inventory` — census исходного `affected[]`: identity advisory,
  sha256 документа, все entries с исходными ecosystem/module и списки
  represented/omitted индексов. Перепись снимается **до** фильтрации и
  **до** слияния entries по имени модуля;
* `basis` — только человеческое объяснение. Гейт закрытия его никогда не
  читает, и текст не может разрешить или запретить отрицание.

`COMPLETE` сам по себе больше не является разрешением на закрытие.
Кейсы, сохранённые до появления структурных полей, декодируются, но
legacy `COMPLETE` без `record_extent`/`record_inventory` трактуется как
`UNKNOWN` и закрывать запрос не может (fail closed). Отсутствующая,
невалидная или несогласованная перепись тоже даёт `UNKNOWN`, а не
частичное доверие.

**Смешанная запись (измерено).** `GHSA-qppj-fm5r-hxr3`
(CVE-2023-44487) содержит 22 исходные entries: Go — 1
(`golang.org/x/net`), Maven — 20, SwiftURL — 1. Для точной записи и для
CVE-запроса перепись даёт `GO_PROJECTION` (22 entries, 1 represented,
21 omitted), поэтому закрытие отклоняется. Факт компонента сохраняется:
модуль присутствует, версия `v0.17.0` вне диапазона
(`VersionAffected=FALSE`), но `PackagePresent`/`BuildRelevant` остаются
`UNKNOWN`, а итог — `INCONCLUSIVE` с `under_investigation`/`in_triage` в
экспортах.

**Независимость от build-target допуска.** Module/version-негативы
(модуль отсутствует в графе, версия вне диапазона) не требуют scoped
сборки продукта — это отдельная ось допуска. Они по-прежнему обязаны
пройти finding-scope coverage: при `GO_PROJECTION`/`KNOWN_ONLY` такой
негатив остаётся компонентным фактом и не закрывает запрос.

**Неразрешимый root cause.** Если корневая причина не разрешена,
конвейер не обрывается без вывода: кейс проходит через
`EVALUATE_VERDICT`, получает записанный `INCONCLUSIVE` и формирует
`report.json`/`report.md`/`report.en.md` и оба VEX-экспорта. Режим
`--strict-llm` остаётся исключением и завершает кейс как `FAILED`.

Ограничение scope не отменяет компонентный факт и не запрещает
позитивный вердикт `EXPLOITABLE`: подтверждённая достижимость в любом
проверенном компоненте по-прежнему экспортируется как `affected`.

#### Область вывода: библиотека (`library-api`)

Если анализируемый продукт — библиотека (доказанная форма без
принадлежащего продукту `package main`), итоговый `EXPLOITABLE` получает
ортогональную область вывода:

* `verdict.exploitability_scope` и `profiles[].exploitability_scope` —
  `library-api`;
* `claims[].control_basis` — `library-public-api` у TRUE-claim `C-INPUT`,
  доказанного связкой «публичный формальный параметр → sink»;
* `data_flows[].library_input` — свидетель связки (API и место
  объявления, номер/имя/тип формального параметра, sink и позиция вызова,
  номер аргумента, fingerprint формы, evidence ID);
* `verdict.limitations` (и отчёты/VEX) несут обязательное ограничение:
  `Library-API scope: the payload is selectable by a library consumer;
  whether a downstream application exposes that payload to an attacker is
  outside the analyzed product and is not established.`

CLI-вывод `izyan analyze` печатает область отдельными строками — она же
видна в целевом профиле:

```text
verdict: EXPLOITABLE
reason: all mandatory exploit conditions are satisfied
exploitability_scope: library-api
control_basis: C-INPUT=library-public-api
target_profile: zero_trust (Verdict: EXPLOITABLE, Priority: P3, Scope: library-api)
```

Область не превращается в новое значение вердикта и не означает контроля
со стороны атакующего в деплойменте: `DataFlow.Origin` остаётся `UNKNOWN`.
Запрос по каноническому `GHSA-…`/`GO-…` даёт `COMPLETE`, запрос по
CVE-алиасу — `KNOWN_ONLY`; обе области допускают позитивный вывод, но
`KNOWN_ONLY` не закрывает запрос отрицательным фактом. Допуск узкий:
форма библиотеки, публичный API, полезный тип параметра, сохранение
нагрузки, `DESERIALIZATION`, CWE-502 из advisory, разрешённый root-cause
sink и точный аргумент `ATTACKER_CONTROL`. Неудачный допуск — «не
доказано», а не «безопасно».

#### 2. Структурированный файл задачи (`--ticket ticket.json`)

Позволяет описать задачу аудита в едином JSON-файле:

```json
{
  "id": "SEC-538506",
  "vulnerability": "GO-2026-6443",
  "aliases": ["CVE-2026-84445"],
  "component": "api-gateway",
  "release": "v24.2.0",
  "module": "google.golang.org/grpc",
  "package": "google.golang.org/grpc/internal/transport",
  "fixed_versions": ["1.82.2"],
  "description": "DoS-уязвимость в gRPC сервере при пустых HTTP/2 authority-заголовках"
}
```

Если тикет содержит полный встроенный OSV-документ, его можно положить в поле `"osv"`:
```json
{
  "id": "SEC-538506",
  "vulnerability": "GO-2026-6443",
  "component": "api-gateway",
  "release": "24.2",
  "osv": {
    "id": "GO-2026-6443",
    "affected": [
      {
        "package": { "name": "google.golang.org/grpc" },
        "ranges": [{ "type": "SEMVER", "events": [{ "introduced": "0" }, { "fixed": "1.82.2" }] }]
      }
    ]
  }
}
```

Пример запуска:
```bash
izyan analyze --repo /path/to/project --ticket ./ticket.json --checkout-release
```

### Интеграция с трекерами задач и произвольным текстом (`--ticket`)

Анализатор поддерживает автоматический умный импорт информации без необходимости вручную вычленять идентификаторы:

1. **Произвольный текст или буфер обмена (`--ticket -` или `--ticket file.txt`):**
   ```bash
   # Передача скопированного описания тикета через stdin:
   pbpaste | izyan analyze --ticket - --repo /path/to/project
   ```
   Анализатор автоматически находит:
   - Идентификаторы уязвимостей (`GO-…`, `CVE-…`, `GHSA-…`, `BDU:…`);
   - Номер тикета (`[A-Z]+-\d+`, например `SEC-538506`, `JIRA-1234`, `APP-1001`);
   - Затронутую библиотеку/модуль и версию;
   - Название компонента и релиза.
   Номер тикета, компонент и релиз автоматически сохраняются в кейсе и выводятся в `report.md`, `report.en.md` и `report.json`.

2. **JSON-выгрузки трекеров (Jira, GitLab, Bugzilla, Redmine и др.):**
   ```bash
   izyan analyze --ticket ticket.json --repo /path/to/project
   ```
   Поддерживаются как плоские структуры JSON, так и вложенные конверты корпоративных трекеров (`unit` с полями `code`, `summary`, `descriptionPlain` и списком `attributes`), включая автоматическое извлечение обоснований триажа из полей `result_text` / `rationale`, идентификаторов уязвимостей и компонентов.
   Если JSON-файл содержит массив тикетов, можно выбрать нужный по ключу:
   ```bash
   izyan analyze --ticket tickets.json --ticket-id APP-1002
   ```

3. **Автоматический поиск репозитория по компоненту (`--repo-map` или `repos.json`):**
   Чтобы не передавать `--repo` каждый раз вручную, можно завести `repos.json` (или `.izyan-repos.json`) в текущей директории либо передать `--repo-map <path>`:
   ```json
   {
     "GATEWAY": "/Users/developer/work/gateway",
     "CORE": "/Users/developer/work/core",
     "SEC-1001": "/Users/developer/work/gateway"
   }
   ```
   Или в структурированном виде:
   ```json
   {
     "components": { "GATEWAY": "/Users/developer/work/gateway" },
     "tickets":    { "SEC-1001": "/Users/developer/work/gateway" }
   }
   ```
   При запуске `izyan analyze --ticket ticket.json` анализатор автоматически сопоставит компонент или номер тикета с локальным репозиторием.

4. **Семантическое извлечение через LLM (`--llm-intake`):**
   Если текст тикета или сообщения из чата составлен в свободной форме (без стандартных меток или с нетривиальным контекстом), флаг `--llm-intake` (или включённый `LLM_ENABLED=1`) подключает языковую модель для извлечения информации.
   Строгий инвариант безопасности: извлечённые LLM данные проходят детерминистический шлюз проверки (anti-hallucination gate) — идентификатор уязвимости обязан присутствовать в исходном тексте, а пакет нормализуется по Go-стандартам.

5. **Безопасный чекаут версии в изолированный worktree (`--checkout-release`, `--release` / `--git-ref`):**
   Когда из тикета (или флага `--release <ver>`) известен релиз (например `24.2`, `v1.2.3`, `release/2026.1`), флаг `--checkout-release`:
   - Находит соответствующий git-тег или ветку в репозитории с нормализацией популярных соглашений (`v24.2`, `v24.2.0`, `release/24.2`, `rel-24.2`);
   - Разворачивает снапшот в изолированном временном `git worktree`, не трогая рабочую копию разработчика, незакоммиченные изменения и текущую ветку;
   - Если текущий `HEAD` чист и уже указывает на нужный коммит, анализ выполняется на месте без создания лишнего worktree;
   - По завершении анализа worktree гарантированно и чисто удаляется;
   - Запись о чекауте конкретного коммита релиза заносится в limitations и доказательную базу аудита.

## scan — массовый прогон зависимостей

```bash
izyan scan --repo /src/product [--max-vulns 50]
```

Опрашивает OSV по всем зависимостям (`go list -m all`), дёшево
отсекает детерминистически-неаффектящие advisory и прогоняет выжившие
через полный пайплайн `analyze`. Сводка — `<case-dir>/scan.json`.

| Флаг | Что делает |
|---|---|
| `--max-vulns <n>` | потолок advisory для глубокого анализа (default 50) |

## remediate — исправление уязвимой зависимости

```bash
izyan remediate --repo /src/product --vuln GO-2025-3595 [--apply] [--run-tests] [--worktree /tmp/wt]
```

Без `--apply` — только план (минимальный `go get` до fixed-версии +
ожидаемый re-analyze). С `--apply` — реально мутирует `go.mod/go.sum`.

| Флаг | Что делает |
|---|---|
| `--apply` | применить фикс (`go get` + `go mod tidy`) |
| `--run-tests` | после фикса прогнать `go test ./...` до re-analyze |
| `--worktree <path>` | apply в `git worktree` — исходный checkout не трогается |

## eval — регрессионный корпус (для разработчиков)

```bash
izyan eval --corpus eval/corpus.json [--case <id|glob>] [-j <n>] [--clean] [--out report.md] [--json report.json] [--with-llm]
```

Прогоняет корпус кейсов через пайплайн, считает метрики
(`false_safe` — стоп-критерий, должен быть 0). Exit code 1 при любом
false-safe/expect-fail/claims-fail/error — пригоден для CI.
По умолчанию детерминистичен; `--with-llm` — opt-in замер LLM-варианта.
Флаг `--case <id|glob>` фильтрует кейсы (например `--case real-yaml*` или `--case real-yaml-const`), `-j <n>` задаёт размер параллельного пула воркеров (по умолчанию 4), `--clean` форсирует перегенерацию модулей в `.gen/`.
Пути в корпусе — относительно файла корпуса, `${VAR}` раскрывается
([`eval/README.md`](../eval/README.md)).

### `izyan eval research-b1` — замороженный B1 evaluation arm

```bash
izyan eval research-b1 --snapshot <dir> --cve <id> --out <dir> \
    [--advisory <file|dir>] [--allow-agent|--dry-run] [--replay-run <run-dir>]
```

B1 — **evaluation control**, а не продуктовый runtime: один замороженный
prompt, один контейнерный agent turn против запиненного снапшота и запись
сырого ответа плюс host-fact consistency layer. Он никогда не выдаёт
проверенный вывод о безопасности и не закрывает уязвимость. Отдельной
top-level команды `izyan research-b1` больше нет: B1 доступен только под
`eval`, чтобы ни одна продуктовая команда не рекламировала второго живого
investigator'а. `--dry-run` (или отсутствие `--allow-agent`) не запускает
ничего и пишет только launch plan.


### `izyan eval vex-triage` — Product B measurement lane

```bash
# 1. Подготовка общего, заслепленного бандла входов без запуска моделей
izyan eval vex-triage prepare --tasks <vex_bench.jsonl> --repos-dir <dir> --advisories-dir <dir> --out <dir>

# 2. Явный запуск выполнения под авторизацией расхода бюджета
izyan eval vex-triage execute --bundle <prepared-bundle-dir> --out <dir> --authorize-execution [--model <name>]

# 3. Офлайн-скоринг метрик по независимым осям (Product A authority, Product B recommendation, Automation)
izyan eval vex-triage score --bundle <prepared-bundle-dir> --runs <runs-dir> [--reviews <events.jsonl>] --out <dir>
```
## research — детерминированная evidence/proof-полоса (для разработчиков)

```bash
izyan research --snapshot <dir> --cve <id> --advisory-file <osv.json> \
    --output-dir <dir> [--govulndb <dir>] [--modcache <dir>] \
    [--build-cache-dir <dir>] [--replay-agent-turn <run-dir>]
```

Deterministic evidence/proof по одной замороженной OSV-advisory без
обращения к продакшн-пайплайну и **без вызова модели**. Пишет в
`--output-dir`: `report.json` (`research-report/5`), `requested-case.json`, `report.md`,
`observations.jsonl`, `run-manifest.json`, `artifacts/`. `run.attempts`
фиксирует попытки, `agent_output.status` = `NOT_REQUESTED`, если ход не
воспроизводится из сохранённого прогона.

`--replay-agent-turn <run-dir>` — единственный источник agent-материала:
deterministic lane выполняется заново, агентская часть восстанавливается
verbatim из записанных артефактов с проверкой всех sha256-пинов
(несовпадение — fail-closed), модель и harness **не вызываются**. Historical
`research-report/1`–`/4` и slice2 contracts читаются через отдельный
`izyan eval research-replay --run <saved-dir> --out <new-dir>`: исходные байты
и timestamps сохраняются под `original/`, wrapper имеет `historical_only=true`,
`current_admission=false` и не является текущим report/proof. Смена schema не
повышает authority. Current publication `/5` использует `finding.Project` и
свежий допуск exact-record/requested-case. Retained `--replay-decision-run` и
`--decision-ready --deterministic-only` исполняют offline history/probe,
но никогда не запускают live R6 и не заменяют current human package.

Живой человеческий investigator один — `izyan triage` (см. ниже). Этот
маршрут — доказательная половина: он не формирует человеческий action/support
package.

`--ticket <file>` — опциональный тикет из трекера в том же формате,
что intake `izyan analyze`: generic JSON-тикет, JSON-массив тикетов
(`--ticket-id <id>` выбирает по ключу), произвольный текст или `-` для
stdin. Из тикета извлекаются заявления (`package`, `version`,
`component`, `product`, `release`, `aliases`; текст — по меткам: PURL (percent-decoding) и строка
`Библиотека:` пиннат версию пакета точно, `release`/`component`
обрезаются на границе следующей `Слово:`-метки). Включает
проверку identity «тикет ↔ проанализированная сборка»: если заявленная
версия пакета отличается от разрешённой в анализе, ось версии
**блокируется** (`TICKET_PACKAGE_VERSION_MISMATCH`,
`version_axis_blocked` + `ticket_check` в `product_applicability`,
limitation с обеими версиями) — out-of-range негатив не производится,
это отказ, а не вердикт. Расхождение версии продукта записывается как
`ANALYZED_BUILD_MISMATCH` (информационно, само не блокирует).
Непарсибельный или нечитаемый тикет деградирует до
`TICKET_INVALID`/`NOT_CHECKED` — никогда не молчаливый пропуск. Без
флага поведение байт-в-байт прежнее; module/package-absent маршруты
не затрагиваются.

`--implementation-locus-proposal <file>` — typed input channel
(`implementation-locus-proposals/1`) с LLM-inferred гипотезами об узле
уязвимой реализации (module/version/package/file/function, platform
expression, quote пиннится к замороженной advisory, marker). Это вход,
не доказательство: lane сам прогоняет
`affected.EvaluateImplementationAxis` отдельным наблюдением
`implementation-axis` (compiled-scope package-presence probe +
детерминистический re-select под authoritative target + verifier
FALSE). Воспроизводимое `NOT_AFFECTED` возможно только при
`vulnerable_implementation_present=FALSE` при слинкованном пакете;
артефактный scope не покрывает product-wide, `--goos/--goarch` —
объявленный операторский target. Записанные proposal-файлы живого
прогона реадмитятся при `--replay-agent-turn` после полной
ревалидации; hand-edited/broken артефакт — fail-closed.

Отчёты `slice2-fidelity/3` несут derived-блок **Evidence level**
(в `report.md` — отдельная секция перед exploitation conditions):
`L1_STATIC_PATH` / `L2_POTENTIAL_PATH` / `L3_DYNAMIC_EXPLOITATION`.
Уровень вычисляется детерминистически из condition ledger и verified
facts и пересчитывается валидатором — агент не задаёт его напрямую.
Это степень доказанности exploit path, а **не** verdict о безопасности
продукта: отсутствие `L3` означает только отсутствие динамического
доказательства, `L1`/`L2` никогда не читаются как «безопасно».
`disposition` остаётся `REVIEW_REQUIRED` (`auto_close=false`).

### Release-evidence входы и отчёт

Версия Go-тулчейна, которой собран релиз, и граф модулей релиза — разные
оси доказательств; отчёт различает их и не подменяет одну другой.

| Вход | Что даёт |
|---|---|
| `--release-go-version <ver>` (`analyze`/`scan`) | явно заявленный toolchain релиза — AUTHORITATIVE для `std`-advisory |
| `--binary <path>` (`analyze`/`scan`) | build info собранного бинаря: toolchain и граф модулей — AUTHORITATIVE |
| `--artifact <path>` / `--artifact-url <https-url>` (`research`) | bounded-канал артефакта релиза (бинарь или ZIP-дистрибутив): build info из артефакта — AUTHORITATIVE |
| `--release-metadata <file>` (`research`) | `release-metadata/1` (ticket/SBOM): `go_version` и/или `modules` — AUTHORITATIVE; без `go_version` toolchain остаётся UNKNOWN, а объявленный граф модулей всё равно авторитетен |

Trust-class precedence: AUTHORITATIVE записи (build info артефакта/бинаря,
`--release-go-version`, release-metadata) резолвят версию только при согласии
после нормализации; расхождение AUTHORITATIVE — `CONFLICTED` без выбранной
версии (никогда не первое/последнее значение). Объявления снапшота
(`go`/`toolchain` в `go.mod`, `FROM golang:` в Dockerfile, CI setup-go,
`.go-version`/mise/asdf, release-скрипты) — только SUPPORTING: они
подтверждают версию, но не устанавливают её. `go.mod` — языковой минимум;
локальный `go version` анализа — окружение анализа, не релиз. Поэтому без
AUTHORITATIVE toolchain stdlib-applicability остаётся `UNKNOWN`. Явно
запрошенный канал, который не разрешился, — `NOT_RUN` с именованной причиной
(`ARTIFACT_*`/`RELEASE_*`), а не тихий fallback на источник.

Отчёт различает оси в `input.snapshot` (`report.json` у `research`; снапшот
кейса `analyze` несёт тот же `release_evidence`):

* `go_version` — toolchain, которым выполнялся анализ;
* `minimum_go_version` — директива `go` из `go.mod` (языковой минимум);
* `release_go_version` + `release_evidence.selected_version/source/trust` —
  авторитетный toolchain релиза (пусто при `UNKNOWN`/`CONFLICTED`/`NOT_RUN`);
* `release_evidence.modules` + `version_graph_source`/`version_graph_trust` —
  граф модулей релиза, которым резолвились сторонние версии; при его
  отсутствии `version_graph_source: source-snapshot`, а версия из
  checkout'а остаётся fallback-провенансом в
  `product_applicability.resolved_version`.

Сторонние модули резолвятся независимо от toolchain-оси: отсутствие
release-Go-версии не блокирует граф модулей (и наоборот — граф модулей не
устанавливает toolchain). Проваленный обязательный канал артефакта —
fail-closed: source/vendor не подставляется вместо недоступной release-версии.

`report.md` выводит те же оси отдельными строками: `analysis toolchain`,
`minimum go.mod version`, `release toolchain` (явный `UNKNOWN`, если
авторитетной версии нет), `release module graph` с trust-классом и
`source-snapshot` fallback-провенанс.

### Модель-провайдер агента — удалён из `research` (Phase 4 Task 2)

Живой agent turn в `izyan research` **удалён**. Живой человеческий
investigator один — `izyan triage` (у него свой модельный контракт, см. раздел
`triage`). `izyan research` — детерминированная evidence/proof-полоса плюс
replay сохранённого хода, поэтому флаги `--model`, `--provider`, `--base-url`,
`--api-key-env`, `--agent-timeout`, `--agent-prompt-file`, `--no-agent`
больше не существуют. Historical probe/replay switches временно сохранены,
это не no-op совместимость. Ни один путь этой команды не
запускает модель, harness или контейнер.

| Что было | Что стало |
|---|---|
| `--deterministic-only` | только вместе с `--decision-ready`: historical offline probe |
| `--decision-ready` | требует deterministic probe или recorded replay; live запуск запрещён |
| `--replay-decision-run` | recorded flow replay с pin/ledger validation, без модели |
| `--replay-agent-turn <dir>` | остаётся: единственный источник agent-материала — сохранённый ход |
| `--model/--provider/--base-url/--api-key-env` | удалены вместе с endpoint-контрактом |

Replay сохранённого хода сохраняет recorded output и исходные pin/ledger gates.
Повреждённые proof, subject или artifact bindings отклоняются. Historical
playback отделён от current admission: его wrapper не принимается как текущая
authority; новый `/5` требует canonical publication и fresh admission.

### Офлайн-прогон `run_govulncheck` с локальной базой

В strict-профиле lane `run_govulncheck` запускается только когда зафиксирована
локальная база уязвимостей: без `--govulndb` наблюдение честно уходит в
`UNSUPPORTED`. База пинается через флаг `govulncheck -db file://<dir>` —
govulncheck **не читает** переменную `GOVULNDB` (она экспортируется в env
сабпроцесса только как аудит-свидетельство пина, совпадающее по пути с `-db`).
Субкоманды `govulncheck update` или флага `-db.root` у govulncheck нет —
подготовка базы делается отдельными шагами.

`run_govulncheck` под strict-профилем требует **оба** пина: `--govulndb`
и `--modcache`. Без `--modcache` наблюдение — `UNSUPPORTED`: сабпроцесс
govulncheck иначе читал бы ambient module cache вне задекларированных
read roots (выставить `GOMODCACHE=` недостаточно — go-toolchain
откатится на дефолтный кэш GOPATH, поэтому корректное состояние одно:
отказ). Несуществующий или нечитаемый `--govulndb` root — тоже
`UNSUPPORTED` (отсутствующая capability), а не `ERROR`.

Build cache (`GOCACHE`) сессия пинит явно: `--build-cache-dir` задаёт
переиспользуемый per-run root (канонизируется, добавляется в confined
read roots; путь внутри снапшота или output dir отклоняется при старте
сессии). Без флага пинится платформенный дефолт
(`os.UserCacheDir()/go-build`), а ambient `GOCACHE` из окружения
вызывающего процесса не наследуется и до сабпроцессов и загрузчика
пакетов не доходит. Кэш держат тёплым между прогонами — холодный
оплачивает полную пересборку замыкания. Повреждённый унаследованный кэш
fail-closed: подписи `cache entry not found` / ENOENT внутри пиннутого
root дают ERROR с кодом `BUILD_CACHE_CORRUPT` и ремедиацией
(`go clean -cache` под пиннутым GOCACHE либо свежий `--build-cache-dir`),
без молчаливого retry.

### Зеркало OSV-дампа (completion предметов advisory)

Замороженная advisory может объявлять только модуль + диапазон версий
без `ecosystem_specific.imports` — тогда lane не имеет package-level
субъектов и честно фиксирует `UNKNOWN` («advisory declares
module+version range only»). Флаги `--osv-feed` / `--osv-url`
подключают зеркало OSV-дампа для **дозаполнения пустого** списка
imports: lane ищет ту же advisory по id и по `aliases` в выгрузке
экосистемы `Go` и, если найденная запись несёт imports для того же
модуля, подставляет их в subjects. Уже объявленные imports, диапазоны
версий и любое другое поле замороженной advisory **не перезаписываются**;
неудача (нет записи, нет imports, неоднозначность, мертвое зеркало без
кэша) оставляет существующий `UNKNOWN` и добавляет к нему именованную
причину `ADVISORY_IMPORTS_UNAVAILABLE`. Provenance резолва пишется в
`report.json` → `advisory.feed_resolution` (status, `source_ids` —
документы, давшие subjects; `feed_ref`, `dump_sha256`, `checked_at`).

```bash
izyan research --snapshot <dir> --cve <id> --advisory-file <osv.json> \
    --output-dir <dir> \
    --osv-feed /path/to/osv-dump        # директория *.json или .zip
# либо по сети:
izyan research ... --osv-url https://mirror/osv   # или env IZYAN_OSV_URL
    [--osv-cache-dir <dir>] [--osv-dump-ttl 168h] [--osv-no-proxy]
```

Remote-режим следует стандартной раскладке OSV-дампов:
`<base>/ecosystems.txt` объявляет доступные экосистемы (отсутствие `Go`
— статус `osv_missing`, не ошибка), дамп лежит по
`<base>/<ecosystem>/all.zip`. Кэш сверяется length-запросом (GET без
чтения тела; `Content-Length` совпал с записанным — кэш валиден),
`--osv-dump-ttl` (дефолт 7d, `0` — без лимита возраста) форсирует
перекачку, мертвый источник отдаёт валидный кэш с пометкой fallback и
без перезаписи времени проверки. По умолчанию запросы идут через
стандартные `http_proxy`/`https_proxy`; `--osv-no-proxy` отключает их
для запросов к зеркалу. В `run-manifest.json` записываются только
безопасные члены (`osv_feed` как basename-ссылка, `osv_url` без
credentials/query, `osv_dump_ttl`, `osv_no_proxy`); путь к кэш-каталогу
и секреты не логируются.

**Подготовка (один раз, с сетью; не часть offline-прогона):**

```bash
# 1. Бинарь (версия зафиксировать в run notes: `govulncheck -version`).
GOBIN="$GOBIN" go install golang.org/x/vuln/cmd/govulncheck@latest

# 2. Локальная база: flat-директория `<GO-ID>.json` — валидный формат для
#    `-db file://...` (см. x/vuln internal/client hybridSource). Публикуемые
#    OSV-JSON лежат по https://vuln.go.dev/ID/<GO-ID>.json, список ID —
#    в https://vuln.go.dev/index/vulns.json.gz.
curl -s https://vuln.go.dev/index/vulns.json.gz | gunzip \
  | python3 -c 'import json,sys; [print(e["id"]) for e in json.load(sys.stdin)]' \
  > /tmp/vuln-ids.txt
cd "$GOVULNDB_ROOT" && xargs -P 24 -I id \
  sh -c 'curl -sf "https://vuln.go.dev/ID/id.json" -o "id.json"' < /tmp/vuln-ids.txt

# 3. Module cache для снапшота: `go mod download` в копии дерева с тем же
#    go.mod/go.sum (у локальных replace пути должны резолвиться), GOMODCACHE
#    указывает на "$MODCACHE_ROOT". Проверка офлайн-полноты:
#    `GOPROXY=off go list -e -deps ./...` в снапшоте не должен давать
#    "module lookup disabled".

# 4. Toolchain: если снапшот пинит старую версию Go (`.go-version`),
#    `--analysis-go <ver>` поднимет ~/sdk/go<ver> (golang.org/dl SDK —
#    ставится один раз `go install golang.org/dl/go<ver>@latest &&
#    go<ver> download`, затем работает офлайн).
```

**Offline-прогон (без egress):**

```bash
env GOPROXY=off GOSUMDB=off GOFLAGS=-mod=readonly PATH="$GOBIN:$PATH" \
  go run ./cmd/izyan research \
    --snapshot <dir> --cve <id> --advisory-file <osv.json> \
    --output-dir <dir> \
    --govulndb "$GOVULNDB_ROOT" --modcache "$MODCACHE_ROOT" \
    [--build-cache-dir "$BUILDCACHE_ROOT"] \
    [--analysis-go <pinned-version>] \
    [--deterministic-timeout 15m --overall-timeout 60m]
```

Сессия прокидывает в сабпроцесс `GOVULNDB=<canonical root>` +
`GOMODCACHE=<modcache>` + `GOCACHE=<buildcache>` +
`GOPROXY=off`/`GOSUMDB=off`/`GOFLAGS=-mod=readonly`;
оба root попадают в confined read roots. В `observations.jsonl` у
`tool=run_govulncheck` должен быть `tool_status=OK` с `data.db_info`
(`DB: file://…` + `DB updated:` из `govulncheck -version -db …`) и
`scope_details.extra.govulndb_root`; отсутствие findings — не доказательство
неуязвимости (`in_database` говорит, покрыта ли advisory сканированной базой).

Замечание по времени: дефолт `--deterministic-timeout` — 15m
(измеренный bound source-scan'а govulncheck на vendored-замыкании
~1700 пакетов); `--overall-timeout` остаётся потолком прогона — для
k8s-класса снапшотов увеличивайте оба таймаута, как показано выше.


## triage — человеческий результат LLM-first расследования

`izyan triage` — Product B: расследование и подготовка решения **для
человека**. Команда не публикует authoritative verdict Product A, не
заменяет `izyan analyze` и не выдаёт разрешение на автоматическое
закрытие. Один прогон создаёт `decision-package.v4` и action-first карточку
`decision.md`.

### Live-режимы

```bash
# finding.v1 (совместимый транспорт: компонент/репозиторий уже известны)
izyan triage --input finding.json|findings.jsonl|- --out <dir>

# generic intake: текст/JSON/JSONL тикета; Stage 0 разрешает источник,
# ref, snapshot, advisory и материалы
izyan triage --ticket ticket.txt|- --config triage-site.yaml --out <dir>

# необязательный triage-scoped VEX (default-off, не authoritative)
izyan triage --input finding.json --out <dir> --vex-projection
```

Без `--config` (`--ticket`) и без `--input` команда не запускается;
`--fail-on` задаёт явные CI-пороги (`unchanged`, `low-support`,
`conditional`, `unverified-disposition`). Бюджеты (`--max-steps`,
`--max-tool-calls`, `--max-source-bytes`, `--timeout`) ограничивают
расследование; исчерпание initial exchange budget не превращается в
выдуманное завершённое исследование — bounded finalization записывает
`technical_assessment.budget_result=finalized_after_step_budget`.

### Восемь элементов человеческого результата

`decision.json` содержит:

1. **действие** — `proposed_action` (`CLOSE`, `LOWER_PRIORITY`,
   `REMEDIATE`, `KEEP_OPEN`, `OBTAIN_EVIDENCE`), его `instruction`, `scope`
   и `decisive_claim_ids`;
2. **причинное обоснование** — `proposed_action.rationale` и
   `judgment` (`verdict`/`summary`/`mechanism`), сохранённый дословно как
   мнение расследования;
3. **решающие проверенные факты** — premises с вычисленным
   `basis=MEASURED` или `PROVED`, источниками и digest'ами;
4. **модельные интерпретации отдельно** — premises с `basis=INTERPRETED`,
   явно не выдаваемые за измеренные;
5. **решающие допущения, неизвестные и контраргументы** — `ASSUMED`/
   `UNRESOLVED`/`CONFLICTING` premises, `unknowns`, `counterarguments`;
6. **уровень обоснованности** — `support.level` и его причины;
7. **что изменит рекомендацию** — `proposed_action.reconsider_when`;
8. **Accept/Reject человека** — отдельные append-only записи
   `human-decisions/<id>.json`, привязанные к каноническому хэшу пакета.

`decision.md` печатает их в человеческом порядке: действие → почему →
область решения → измеренные/доказанные факты → интерпретации →
допущения/неизвестные/support → что изменит решение → команды Accept/
Reject → отдельная машинная диспозиция → свёрнутый audit.

### Владение полями и четыре оси

Поля пакета разделены структурно, а не соглашением:

* `judgment` — модель;
* `proposed_action`, `premises`, `counterarguments`, `unknowns` — модель
  формулирует, но `premises` пересчитываются детерминированно; заявленный
  моделью basis не принимается на веру;
* `support` — детерминированная проекция решающих посылок;
* `machine_disposition` — только детерминированный слой: рекомендация,
  baseline, профиль, условия, demotions, residual assumptions, triggers и
  `automation` (ALLOW/WARN/BLOCK);
* `technical_assessment`, `facts`, `falsifier_proofs`, `audit` — записанные
  наблюдения, проверки и провенанс; модель не может их задать.

`policy_outcome` не является полем пакета: CI-политика вычисляется
отдельно (`PackagePolicyHit`/`ExitCode`) и не меняет пакет. Модельный
verdict, support и Accept **не** повышают
`machine_disposition.recommendation` и не создают VEX-разрешение.

### citation, measured proposition и interpreted conclusion

Три разных объекта не взаимозаменяемы:

* **verified citation** (`QUOTED_TEXT`) доказывает наличие текста в
  указанном месте и его воспроизводимость, но не интерпретацию текста;
* **MEASURED** — типизированное наблюдение устанавливает узкую
  пропозицию; `MEASURED` не выводится из существования citation;
* **PROVED** — checker установил отношение/отрицание в объявленном scope;
  только допущенный proof contract (condition binding, checker basis,
  snapshot/build/observation bindings, полное покрытие субъектов) даёт
  `PROVED` и `PROVED_WITHIN_SCOPE`;
* **INTERPRETED** — вывод модели из перечисленных материалов; он остаётся
  интерпретацией даже при наличии citation. Непроверенная интерпретация
  не повышает support и не становится отсутствием;
* **ASSUMED/UNRESOLVED/CONFLICTING** — внешняя/человеческая предпосылка,
  неустановленная или противоречивая посылка; они понижают support.

### Deadness observation, proof request и admitted falsifier

Три уровня не взаимозаменяемы:

* **deadness observation** — `symbol-unreachability` возвращает read-only
  наблюдение о замкнутом scope (`COMPLETE`/`PARTIAL`, субъекты, build
  context). Оно информирует `INTERPRETED`-посылку и человеческое действие,
  но само по себе не является proof, машинным reduction или VEX-разрешением.
  Pipeline больше не запускает kernel автоматически и ничего не минтит из
  наблюдения;
* **proof request** — `falsifier_proposals` опционален. Каждый proposal
  связывает claim, `condition_id`, `kind`, субъекты и наблюдение; это
  запрос на одну детерминированную проверку, а не доказательство;
* **admitted falsifier** — только proposal, чьи `condition_id`/`kind`
  допущены приложенным `condition-catalog.v1` и подтверждены verifier'ом,
  даёт `VERIFIED` proof и может участвовать в машинном reduction.

Привязка каталога обязательна: `--condition-catalog` и
`--condition-catalog-hash` задают один и тот же run-pinned каталог. Без
приложенного каталога prompt честно сообщает, что machine falsifier
proposals недоступны, а `lookup_advisory` показывает либо фактические
`condition_id`/`kind`/`subjects` обязательных условий, либо причину
недоступности. Отсутствие каталога, source или semantic premise — внешнее
ограничение proof capability, а не дефект ответа агента, и не запускает
repair loop; чинить имеет смысл только malformed proposal ownership
(несуществующий claim/evidence, неизвестный condition). Proposal,
отклонённый из-за отсутствующего каталога, остаётся в
`falsifier-verification.json` как non-admitted с точной причиной.

### Уровни support

`support.level` вычисляется по замыканию решающих claim'ов
(`proposed_action.decisive_claim_ids` + все зависимости), а не по
количеству цитат и не по согласию модели:

* `INSUFFICIENT` — не хватает необходимой identity/материала; допустимо
  только действие получения/исправления входа (`OBTAIN_EVIDENCE`);
* `LIMITED` — воспроизводимые основания есть, но решающая связь остаётся
  интерпретацией/неизвестной/assumption, есть противоречие, semantic
  stability disagreement или непроверенный citation;
* `SUBSTANTIATED` — решающие фактические листья измерены/доказаны,
  интерпретации явны и заземлены, существенные контраргументы рассмотрены;
* `PROVED_WITHIN_SCOPE` — конкретный вывод целиком поддержан допущенным proof
  contract внутри записанной области records.

Это уровень обоснованности, не вероятность правильности. Отсутствие
severity или внешней контрольной baseline не понижает и не уничтожает
человеческий результат.

### Область решения и отсутствие CVE-wide claims

Пакет всегда записывает `scope`: pinned snapshot, requested ids, captured
records с sha256 (`EXACT_RECORDS`; на `--ticket` это frozen advisory, на
совместимом `--input` — сам captured finding record), boundary (`EXACT_RECORDS` или
`INPUT_MATERIAL_ONLY`) и `open_boundaries`. Один захваченный record
не создаёт CVE-wide вывод: `EXACT_RECORDS` явно означает
record-bound заключение, `INPUT_MATERIAL_ONLY` — отсутствие captured
record'а. Модельные `record_ids` не расширяют эту область.

### Severity и внешний контроль опциональны

Severity берётся из frozen advisory → подтверждённого intake → scanner
(совместимый транспорт) → явно настроенного
`baseline.default_severity`. Если ни один источник не дал значения,
`machine_disposition.baseline` отсутствует, severity/priority не
синтезируются, а машинное снижение удерживается (limitation). Live-прогон
и replay **не требуют** внешней baseline/ground truth; `--baseline`
намеренно отклоняется с указанием на offline-команду.

### Accept / Reject человека

```bash
izyan triage --record-decision <run-dir> --decision accept --actor <identity>
izyan triage --record-decision <run-dir> --decision reject --actor <identity>
```

Эти команды без pin применимы к unconditional решению. Для environment-ветви
в двухшаговом workflow используйте показанный `--projection-hash` (см. ниже).

Режим не требует `--out`, LLM-переменных или сети и не перезаписывает
`decision.json`, `decision.md`, assessment, proofs, VEX или policy.
Каждая запись — новый immutable файл
`human-decisions/<record-id>.json`, привязанный к каноническому хэшу
доставленного пакета; повторная идентичная запись отклоняется, последняя
запись не «переписывает» предыдущую. Accept — решение человека, а не
машинный verdict, proof, автоматическое снижение или Product A authority.

`--reason <text>` — необязательный комментарий новых `human-decision.v2`;
системный `reason_code` выводится из Accept/Reject. Historical v1 остаётся со
своими прежними требованиями. Новая запись связывает package hash, branch ID,
projection hash и assertion IDs, а не только finding ID.

### Объявленные environment-ответы

`assessment.v3` предлагает конечные ветви, а код строит `human_review_plan`
пакета v4: 0–2 вопроса, finite allowed values с `unknown`, максимум семь
обязательных посылок. Ответ выбирает готовую ветвь без модели/инструментов:

```bash
izyan triage --record-decision <run-dir> --actor <identity> \
    --answer deployment_perimeter=cluster-internal
# Answer-only вывод печатает выбранное действие и copy-safe команды с pin:
izyan triage --record-decision <run-dir> --actor <identity> \
    --decision accept --projection-hash <presented-projection-hash>
# Для Reject — тот же показанный pin и --decision reject.
# Второй объявленный ответ передаётся ещё одним --answer.
```

`environment-assertions/*.json` (`environment-assertion.v1`) — append-only,
auditable human-owned premises с explicit supersession. Действительный ответ
не задаётся повторно; `unknown` выбирает консервативную ветвь. Конфликт с
измеренным фактом даёт `CONTRADICTED`; bounds overflow или неполная ветвь —
`NOT_DECISION_READY`, не поручение исследовать дальше. Ответ и Accept не
изменяют immutable package, code claims, Product A, proof, completeness или VEX.

Последующий Accept/Reject требует `--projection-hash` именно показанной
environment-проекции. Сравнение с текущей ветвью выполняется под review lock:
если другой reviewer superseded ответ после показа, старый pin отклоняется без
записи Accept/Reject — нельзя принять невиденное новое действие. Нужно прочитать
актуальную проекцию и использовать её напечатанную команду. Одношаговый
`--answer ... --decision accept|reject` допустим только при явных ответах на
все переменные выбранной проекции (без невидимого inherited ответа) и использует
тот же locked comparison. `--projection-hash` с новыми `--answer` несовместим:
либо принять уже показанную проекцию, либо выбрать её полным набором ответов.
Это identity pin, не технический narrative, новое исследование или Product A authority.

### Replay

```bash
izyan triage --replay-run <run-dir> --out <dir> [--vex-projection]
```

Replay не вызывает модель и сеть и не читает исходный репозиторий:
проверяет записанные hashes, пере-выводит premise/support и
machine-admissibility, сохраняет judgment/action и копирует проверенную
историю Accept/Reject **verbatim**. `replay.v2` пишет отдельные
match-флаги по осям (judgment/action/premises/support/machine disposition),
чтобы drift не скрывался в общем hash. Изменение source run невозможно;
посторонние/подменённые пакеты, observation archive, stability sidecar или
review records отклоняются.

Исторические live-схемы (`assessment.v1`, `decision-package.v2`,
`stability-runs.v1`, `replay.v1`) не апгрейдятся и не реадмитятся: replay
возвращает exit 2 с действием «перезаписать прогон текущей схемой»;
историческое извлечение остаётся только в offline extractors.

### Offline-сравнение с внешним контролем

```bash
izyan eval triage --run <run-dir> --baseline <triage-baselines.json> \
    --out <dir>
```

`triage-evaluation.v1` сравнивает уже сохранённый пакет с явно заданным
контролем (`disposition`, необязательный `expected_judgment`, `source`).
Coverage помечает сравнение как `ASSESSED` или `UNASSESSED`; отсутствие
контроля не выдаётся за измеренный ноль ошибок. Human-ошибки
(неверное reduction-предложение, negative judgment/CLOSE при
`EXPLOITABLE`) считаются отдельно от machine `false_safe`/
`unverified_reductions`. Найденное расхождение — отдельный exit 1
offline-команды; live-доставка и решение человека от него не меняются.
Нового benchmark lane команда не создаёт.

### Exit codes и граница полномочий

| Exit | Значение |
|---:|---|
| `0` | пакет(ы) доставлены, явные `--fail-on` пороги не нарушены; human decision записан |
| `1` | пакет доставлен, но сработал явно заданный `--fail-on` порог |
| `2` | technical failure: плохой input, snapshot drift, proof/identity integrity, ошибка записи, невалидный review record |

Exit `0` означает доставку человеческого результата, **а не** разрешение
на машинное снижение или VEX. `vex.json` пишется только при допущенном
машинном reduction, остаётся `triage_only`, default-off и никогда не
становится authoritative Product A VEX. Product A (`internal/domain`,
`internal/evaluator`, `internal/finding`, negative verification,
публикация VEX) не читает Product B support или человеческие решения.


## knowledge — база знаний экосистемы

База знаний — таблицы семантики API экосистемы, по которым анализ
резолвит provenance и exposure (что такое база и почему она версиони-
руется — [`knowledge-base.md`](knowledge-base.md)). Встроенная база
embedded в бинарь и знает только публичные API: вызовы внутренних
библиотек продукта останутся `UNKNOWN`-provenance — их дописывают
расширением `--knowledge <file>` **без пересборки**.

```bash
izyan knowledge [--knowledge <path>]
```

Печатает эффективную базу в JSON — дефолты либо дефолты + расширение.
Дамп — шаблон для своего файла и валидатор: ошибки схемы/мержа
показываются до прогона анализа. Формат файла, поля и правила мержа —
в [`knowledge-base.md`](knowledge-base.md).

## Общие флаги (все сабкоманды)

| Флаг | Что делает |
|---|---|
| `--case-dir <path>` | каталог состояния кейсов (default `.izyan`) |
| `--lang <ru\|en>` | язык формирования отчётов и вывода CLI (default `ru`) |
| `--osv-url <url>` | альтернативный OSV API endpoint |
| `--cve-analysis <mode>` | режим автономного LLM CVE-исследования (`off`, `assist`, `verified`, default `off`) |
| `--strict-llm` | режим fail-fast: падать с ошибкой при сбое LLM, не переключаясь на детерминистику |
| `--deterministic-only` | выключить весь LLM-слой |
| `--mem-limit <size>` | лимит оперативной памяти процесса с watchdog (default `4GiB`) |
| `--allow-exec` | разрешить запуск кода репозитория (run_build/run_tests в доказательствах). Без флага exec-инструменты недоступны |
| `--knowledge <path>` | JSON-расширение базы знаний экосистемы — дописывает записи для API, которых нет во встроенной базе (внутренние библиотеки продукта). Формат, валидация и семантика мержа: [`knowledge-base.md`](knowledge-base.md). Дамп базы/шаблон: `izyan knowledge` |
| `--llm-env <path>` | файл с LLM-кредами; иначе `.env` в cwd или корне репо |

## LLM-конфигурация

LLM-слой включается только при `LLM_ENABLED` в truthy-значении
(`1`/`true`/`yes`/`on`) — иначе анализ идёт детерминистически.
Переменные читаются из окружения или из dotenv-файла: явный `--llm-env
<path>`, иначе `.env` в cwd или в корне `--repo`. Значения из
dotenv **не переопределяют** уже выставленные переменные окружения.

Выбор backend'а: промпты анализатора — про уязвимости и эксплойт-
модели, поэтому провайдеры с safety-фильтрами (Gemini и подобные)
могут отвечать отказом — в отчёте это видно как `provider refusal
(content filter)` в limitation/findings. Рекомендуются self-hosted
модели за OpenAI-compatible gateway (корпоративный gateway, ollama и
т.п.); отказ не ломает анализ — слой откатывается в детерминистику.

| Переменная | Что задаёт |
|---|---|
| `LLM_ENABLED` | `1`/`true`/`yes`/`on` — включает слой; иначе выключен |
| `LLM_BASE_URL` | endpoint LLM API (OpenAI-compatible) |
| `LLM_API_KEY` | ключ доступа |
| `LLM_ANALYZE_MODEL` | модель для root cause/review/gap-planner |
| `LLM_BUILD_MODEL` | модель для построения exploit-модели (default: `LLM_ANALYZE_MODEL`) |
| `LLM_MAX_TOKENS` | потолок токенов ответа (default 4000) |
| `LLM_TIMEOUT_SEC` | таймаут запроса (default 120) |
| `LLM_INSECURE_TLS` | `1`/`true` — отключить проверку TLS к endpoint'у |
| `LLM_BUILD_MAX_RETRIES` | retries JSON-repair для build-модели (default 0) |

Пример `.env`:

```dotenv
LLM_ENABLED=1
LLM_BASE_URL=https://llm.example.com/v1
LLM_API_KEY=sk-...
LLM_ANALYZE_MODEL=gpt-4o
LLM_BUILD_MODEL=gpt-4o
```

`.env*` файлы в `.gitignore` — не коммитятся.

## Прочие переменные окружения

| Переменная | Где используется |
|---|---|
| `${VAR}` внутри corpus JSON | `eval` раскрывает env в `repo`-путях (`VA_PRODUCT_REPO` для живого корпуса, см. [`eval/README.md`](../eval/README.md)) |
| `GOMODCACHE`, `GOPATH` | source-инструменты `read_source`/`search_source` допускают module cache как evidence-область |

## Что создаётся на выходе

`<case-dir>/<case-id>/`:

- `report.json`, `report.md`, `report.en.md` — вердикт, claims с
  evidence, limitations; при библиотечном выводе — `exploitability_scope`,
  `control_basis` и witness (`data_flows[].library_input`);
- `tracker_comment.md` — готовый комментарий для трекера;
- `openvex.json`, `cyclonedx.json` — экспорты вердикта;
- сериализованный `AnalysisCase` — restartable состояние + аудит
  (`tool_executions`: tool, args, exit code, sha256 stdout/stderr).

## Ограничения и бюджеты

Встроенные потолки на прогон: ≤64 итераций workflow, ≤128 tool calls,
≤32 LLM calls, ≤256 чтений исходников, ≤2 repair-итераций. Исчерпание —
честный `INCONCLUSIVE`/`UNKNOWN` с limitation, а не тихий обрыв.

Exit codes: `0` — кейс завершён с вердиктом (включая INCONCLUSIVE);
не-ноль — инфраструктурный сбой пайплайна (`FAILED`); у `eval` — как
описано выше.


## Definitive-verdict configuration and exit behaviour (2026-10-26)

`analyze`, `scan`, `eval` and `remediate` share the corpus/capture surface:

```text
--osv-feed <path>            offline OSV dump (directory of OSV JSON or one zip) = the pinned corpus
--osv-cache-dir <dir>        cache for a corpus fetched from IZYAN_OSV_URL
--osv-dump-ttl <duration>    max age of a cached dump (default 168h)
--osv-no-proxy               fetch the dump without http(s)_proxy
--corpus-digest <sha256>     declared corpus digest (requires --corpus-captured-at)
--corpus-captured-at <ts>    declared RFC3339 capture date (requires --corpus-digest)
--record-pin <id>=<sha256>   exact-bytes selection when one record id has conflicting documents
--attribution-file <path>    attribution-captures/1 manifest of captured publisher/CNA documents
```

`--osv-url` keeps its old meaning (single-record OSV API base) and is never a
dump source; a remote corpus is configured through `IZYAN_OSV_URL`. Supplying a
feed (or URL) without `--corpus-digest`/`--corpus-captured-at` still runs
discovery and can decide through an attributed positive, but grants **no**
CVE-wide negative authority. Supplying either declaration half alone, a capture
manifest with an unknown field or a digest mismatch fails before any analysis.

Output and exit codes:

- `assessment_outcome: DECIDED` prints the verdict (`verdict: EXPLOITABLE` etc.),
  the actual profile, the build, every proof origin (record, digest, entries,
  mechanism, attribution, profile, build) and any scope limitation. Exit 0.
- `assessment_outcome: EXTERNAL_DEPENDENCY` prints `verdict: INCONCLUSIVE` and
  each `external_dependency:` with the missing fact and what would resolve it.
  Exit 0 (a named external question is a completed answer).
- `assessment_outcome: FAILED` prints **no** `verdict:` line, prints
  `failure_code: <owner>/<code>` per typed cause and the report path, and exits
  nonzero. The diagnostic report is still written.
- A refused/pending projection (legacy or drifted case) is an execution error,
  not an answer.
- `scan` rows carry the same projection; execution errors stay `ERROR` with no
  verdict. `eval` scores the published token and reports decided, external,
  failed, false-safe and false-positive populations separately.

## Independent fix-source captures (2026-10-29)

`analyze`, `scan` and canonical `research` accept `--fix-source-captures <path>`.
The strict `fix-source-captures.v1` JSON manifest contains `artifacts` (exact
`locator`, confined relative `path`, `digest`) and `captures` groups (`record_id`,
`document_digest`, original `entry_ref`, exact existing `selected_source`).
Each group's `patch_bases` supplies `locator`, `artifact_digest`, `module`,
`version`, `archive_path`, `archive_digest`, and optional `tree_path`.
Each `external` entry supplies `import_path`, `declared_module`,
`declared_version`, effective `module`/`version`, `archive_path`,
`archive_digest`, and optional `tree_path`. See the complete example in
`docs/dev/plans/2026-10-29-01-phase6-task5-contextual-captures.md`.

No checksum/trust/completeness assertions are accepted in the manifest. The
producer captures the current product manifest and `go.sum`; an exact recorded
module/version h1 must authenticate the independent archive. A tree is an
optional complete regular-file carrier that must equal that archive, not an
independent VCS anchor. Cross-release bases need their own exact product checksum.
External selection is bounded to directly required versioned components and
explicit versioned replacements corroborated by current non-test inventory.
Missing/transitive-ambiguous/local-only external authority remains unresolved.

The option selects the existing captured-only patch provider: missing artifacts
stay unavailable, with no HTTP or module-download fallback. Unknown fields,
duplicate scopes, escaping/symlink/nonregular files and oversized inputs refuse.
Limits: 1 MiB manifest, 32 MiB per transport file, 128 MiB aggregate transport;
archives expand to at most 64 MiB and 100,000 members. Replay uses full persisted
bytes and independently held case/build/record context, never these paths.
Historical `research --decision-ready` / `--replay-decision-run` reject the flag.

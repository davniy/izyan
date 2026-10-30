# Plan: VEX-Bench adapter (Task 1) + external baseline (Task 2)

Ветка: `feat/shadow-analyzer-agent` (worktree `../vuln-analyzer-shadow`).
Спека: [`specs/shadow-analyzer-agent-spec.md`](../specs/shadow-analyzer-agent-spec.md) §15–25, §51–52.
Роадмап: [`roadmaps/agent-first-analysis-roadmap.md`](../roadmaps/agent-first-analysis-roadmap.md) Этап 0.

Статус: **READY** — проектный шлюз пройден. Findings F01–F14 закрыты в
этом документе (§2.1–§2.6, §4, §5); открытых P0 нет (F05/U-10 закрыт
подтверждённым preflight-контрактом, F07/U-11 — safe mixed-scope advisory).
Готовность относится к плану, не к реализованной изоляции: тесты ещё не
запускались. Реализация начинается с шага 1 §9. Реестр неизвестных — §7.

Этот файл — временный план сессии. После приёмки Task 1–2 удаляется
(см. `plans/README.md`).

---

## 0. Установленная территория (факты со свидетельствами)

### Izyan eval/analyze

| Факт | Свидетельство |
|---|---|
| Единая точка одного кейса — `analyzeCase(ctx, analyzeOpts)` (package `main`, unexported) | `cmd/izyan/main.go:484`; вызывают `runAnalyze` (`:360`) и eval `runCase` (`cmd/izyan/eval.go:470`) |
| `analyzeOpts` уже содержит локальный advisory-вход `vulnFile`; `analyzeCase` подключает `vulnerability.FileSource` | `cmd/izyan/main.go:111,491-495` |
| Corpus-формат `Corpus{repo, cases}` / `Case{...}` (полный список полей — `internal/eval/eval.go:19-86`) | — |
| Скоринг `Report.Record/RecordBaseline`; `false_safe` считается только при непустом `expect` | `internal/eval/eval.go:244-283` |
| `--case` матчит `Case.Label()` (id, иначе vuln) точно или glob | `cmd/izyan/eval.go:105-127` |
| Вердикт: `domain.VerdictResult{Verdict,Reason,ConditionIDs,EvidenceIDs,Limitations,GroundBasis}` | `internal/domain/domain.go:1228-1240` |
| `VerdictEvaluator.Evaluate` — чистая функция; **NOT_AFFECTED только из affected-цепочки**, NEPF только из VERIFIED-falsifier на mandatory-условии | `internal/evaluator/verdict.go:16-125` |
| `Verifier`-фальсификаторы (`constant-or-generated-input`, `guards`, `snapshot-fact-mismatch`, `safe-config-*`, `no-product-reader`, `missing-pair-member`, `missing-source-symbol`, …) — все ведут к **NEPF**, не к NOT_AFFECTED | `internal/domain/domain.go:530-570`; `verdict.go:78-97` |
| `ProductSnapshot` **уже содержит** `GoModDirective` и `ReleaseGoVersion`; нет `ContentHash`/`ExternalCommitSHA` | `internal/domain/domain.go:112-129` |
| Snapshot требует git: `git rev-parse HEAD`, иначе кейс → FAILED | `internal/repository/service.go:46-50`; `internal/states/states.go:52-60` |
| `Snapshot.GoVersion` — отдельный bare `go version` в каталоге продукта, **без** `tc.GoBin/tc.Env` | `internal/repository/service.go:51-53` |
| `resolveToolchain` выбирает version из `--binary` → `--release-go-version` → local; недоступный target → local + `Mismatch`, без жёсткого pin | `cmd/izyan/main.go:805-813`; `internal/toolchain/toolchain.go:82-128` |
| `FileSource.Get` **проверяет** id: `v.ID != id && !contains(v.Aliases, id)` → ошибка | `internal/vulnerability/source.go:38-40` |
| `FileSource` при отсутствии symbols идёт в alias: соседние JSON → HTTP | `internal/vulnerability/source.go:45-46,161-196` |
| `FileSource` доступен как `vulnFile`; прямой CVE через `OSVSource` резолвится из `api.osv.dev/v1/vulns/<id>` | `internal/vulnerability/source.go:47,105-108` |
| Stdlib/`C-PLATFORM` версия: `ReleaseGoVersion` → `GoModDirective` → локальный `GoVersion` | `internal/affected/resolver.go:532-547`; `internal/evaluator/platform.go:30-42` |
| `affectedByRanges` на пустом списке ranges → `false`; при `len(selected)==0 && !verUnknown` resolver ставит `VersionAffected=FALSE` | `internal/affected/range.go:16-25`; `resolver.go:144-152` |
| `Evaluator` conditions: govulncheck FALSE требует `GovulncheckCoverage=="covered"`; молчание = FALSE-кандидат | `internal/evaluator/conditions.go:207-221` |
| govulncheck/`packages.Load` используют GOROOT **analysis** toolchain | `internal/goanalysis/govulncheck.go:93-119`; `internal/goanalysis/source.go:241-245` |
| Рабочий процесс может завершиться в `StateInconclusive`/`StateFailed` до `EVALUATE_VERDICT` при `c.Verdict==nil`; `engine.Run` возвращает `nil` | `internal/states/states.go:266-275,330-337`; `internal/workflow/engine.go:40-71` |
| `commonFlags` берёт `VA_DEPLOY_MANIFESTS`/`VA_PERIMETER` из env; `.env` загружается даже при `--deterministic-only` | `cmd/izyan/main.go:189-205,598` |
| `report.Write` пишет `report.json/openvex.json/cyclonedx.json/report.{md,en.md}` в `<case-dir>/<caseID>/` | `internal/report/report.go:22-52` |
| Персистентность читает старый JSON обычным `json.Unmarshal` (аддитивные поля совместимы) | `internal/persistence/filesystem/store.go:24-32` |
| eval генерирует `go 1.23` в go.mod продуктов | `internal/eval/gen.go:203-205`; прогон `real-http2-server` → NOT_AFFECTED, reason «resolved version go1.23 is outside the affected range» |

### VEX-Bench (внешние факты)

| Факт | Источник |
|---|---|
| `steven1518/vex-bench`, MIT, `main`; pin `80cddeac3132826bfd47227ad59b2e6618a681bd` (2026-09-25) | GitHub API; README |
| 75 кейсов: go 30 / java 25 / python 20 (проверено подсчётом) | `benchmark/tasks/vex_bench.jsonl` |
| Поля: `repo_url, commit_sha, task_id, ground_truth_category, ground_truth, cve_id, metadata.language, metadata.pr_url` | README + JSONL |
| Downloader: `git init` + `remote add` + `fetch --depth 1 origin <sha>` + `checkout --detach HEAD` + `rmtree(.git)`; layout `<repos-dir>/<owner>/<repo>/<commit_sha>` | `src/builder/download.py` |
| 12 категорий в строгом порядке; `to_binary`: только `vulnerable` → exploitable, остальные (вкл. `uncertain`) → not_exploitable | `src/evaluate/result_parser.py`; `prompts.py` |
| Определение `code_not_present` (дословно): «vulnerable package/module is absent… not declared in any manifest, not in any lockfile, no vendored copy» | `src/evaluate/prompts.py` |
| Агент видит только CVE + снапшот; labels/pr_url — данные scorer-а | README §Reproducibility |
| Baseline статьи: GPT-5.5 89.3±4.0 acc / F1 79.9; Claude Opus 4.6 88.4 / 81.6 | arXiv 2609.08040 Table 2 |

### Проверенные локальные эксперименты

1. **git-less snapshot:** `izyan analyze --repo <snapshot без .git> --vuln CVE-2022-28948 --deterministic-only`
   → `state: FAILED`, `reason: product snapshot failed (commit is mandatory for a verdict): resolve git commit: exit status 128`.
2. **Shallow clone VEX-Bench-стилем работает** на 5 репозиториях по полному SHA (короткий SHA `git fetch` не принимает).
3. **go-директивы 30 кейсов: 1.13 … 1.25.6** (28 уникальных снапшотов / 15 репозиториев / 24 CVE);
   `toolchain`-директива у 6 из 28.
4. **OSV не usable у 5 кейсов:** CVE-2024-24786/24791/45338/22871 — `affected: []`;
   CVE-2025-29785 — запись без `package`, только `GIT`-ranges. `GO-*` alias-документы корректны.
5. **Stdlib-версия подставляется из `go.mod`** (`go 1.23`) → NOT_AFFECTED на `real-http2-server`.
6. **`code_not_present` в датасете шире собственного определения** (см. §11).

---

## 1. Цель Task 1

```
izyan eval vex-bench \
  --tasks  <vex-bench>/benchmark/tasks/vex_bench.jsonl \
  --repos-dir <vex-bench>/benchmark/repos \
  [--case <task-id|glob>] [-j <n>] [--out <dir>]
```

Subcommand должен:

1. перечислить ровно 30 pinned Go-кейсов;
2. найти snapshot `<repos-dir>/<owner>/<repo>/<commit_sha>`;
3. запустить **штатный** `analyzeCase` в детерминированном режиме;
4. передать в анализ только CVE, snapshot path, external commit SHA;
5. физически не допустить `ground_truth`/`pr_url` ни в Agent-visible файлы,
   ни в аргументы анализа (две независимые границы — §2.5);
6. запретить экспертные и внешние входы (§2.6);
7. сохранить сырой verdict и полный result envelope (§4);
8. offline-скорить после прогона и посчитать safety-aware + compatibility метрики (§5).

---

## 2. Инфраструктурные изменения

### 2.1 Snapshot identity и ContentHash

`domain.ProductSnapshot` — **только новые поля** (существующие
`GoModDirective`, `ReleaseGoVersion`, `GoVersion` не переименовываются):

```go
MinimumGoVersion  string          `json:"minimum_go_version,omitempty"` // зеркало GoModDirective при новом пути
GoVersionSource   GoVersionSource `json:"go_version_source,omitempty"`  // источник ReleaseGoVersion
ExternalCommitSHA string          `json:"external_commit_sha,omitempty"`// от benchmark controller
ContentHash       string          `json:"content_hash,omitempty"`       // canonical sha256 дерева
```

`GoVersionSource` (новый string-enum в `internal/domain`):
`go.mod`, `toolchain`, `dockerfile`, `ci`, `version-file`, `binary`, `explicit` (флаг/тикет), `""` (нет источника → UNKNOWN).

**Canonical ContentHash contract** (закрывает F04):

* versioned префикс (напр. `t1:`), затем отсортированный relative path (slash-separated), file kind
  (`file`/`symlink`/`dir`), значимые mode bits (`&0o111`), длина записи, байты;
* symlink хэшируется **как ссылка** (target-строка), содержимое за пределами scope не читается;
* `.git` administrative metadata исключается; `vendor/`/build-файлы — учитываются;
* out/persistence/caseDir **держатся вне** анализируемого дерева; snapshot считается immutable на время анализа;
* кэш — один hash на immutable snapshot в рамках одного запуска (single-flight для
  повторных кейсов на одном снапшоте); глобального path+sha кэша нет;
* тесты: rename, symlink-escape, mutation, concurrent reuse, стабильность.

`repository.Service.Snapshot`: при `SnapshotOptions.ExternalCommitSHA != ""` git не вызывается,
`Commit = ExternalCommitSHA`. Обычный git-путь не меняется.

### 2.2 Release-scoped applicability: контракт уровня verdict (P0, F01)

Изменение двух version-helper-ов **недостаточно**. Требуется общее (не VEX-specific)
правило области доказательств:

> applicability и claims, зависящие от target stdlib/runtime, **не считаются
> установленными** по analysis GOROOT, если `ReleaseGoVersion` UNKNOWN
> или расходится с analysis toolchain.

Следствия, обязательные к реализации и покрытию тестами итогового verdict:

1. **Positive path:** `EXPLOITABLE` требует разрешённой applicability
   (не `VersionAffected==UNKNOWN`).
2. **Negative path:** `NOT_AFFECTED`/`NEPF`, опирающиеся на
   host-stdlib silence/absence/unreachability, **не являются release-scoped
   доказательством** при UNKNOWN/mismatch target и не должны закрывать кейс.
   Независимые детерминистические доказательства отсутствия применимого
   компонента (module/package вне графа сборки) — сохраняются.
3. **Форма:** общий gate в evaluator/states scope (не в exploit-pattern),
   распространяющийся на любые stdlib-advisory, а не только CRYPTO_DOWNGRADE.

Обязательные тесты (именно verdict, не helper): UNKNOWN applicability + все
прочие TRUE; UNKNOWN platform + другой VERIFIED-FALSE; известный vulnerable
target + исправленный analysis Go; multi-module advisory с одновременно
stdlib-pending и подтверждённым dependency-entry.

`real-http2-server`: при `ReleaseGoVersion=""` ожидается `INCONCLUSIVE`
(причина — UNKNOWN target), а не NOT_AFFECTED. Fixture и ground truth
пересматриваются в §11/§9.

### 2.3 Toolchain plumbing: analysis pin vs target (P0, F02)

* VEX-команда **заранее** разрешает и проверяет analysis Go 1.26.1.
  Недоступность pin — **явная ошибка подготовки**, не незаметный local fallback.
* Один согласованный analysis toolchain/env передаётся **всем** инструментам
  (`go list`, `packages.Load`, govulncheck, snapshot probe). `Snapshot.GoVersion`
  описывает **analysis environment** и должен вычисляться через `tc.GoBin/tc.Env`,
  а не bare `go version`.
* `ReleaseGoVersion` заполняется **только** из target evidence и никогда — из analysis SDK.
* `--binary`/explicit metadata сохраняют приоритет над snapshot-local discovery.
* Обычный `analyze`/`scan` policy не меняется без отдельного решения.

Тесты: pin propagation со stub tools и записанным env; adverse ambient
`GOTOOLCHAIN`/`GOWORK`/`GOFLAGS`.

### 2.4 Release evidence: источники и допустимость (P1, F03)

Порядок (первый валидный выигрывает): `toolchain`-директива go.mod →
Dockerfile `FROM golang:X` (build-stage) → CI `setup-go` → `.go-version`/`mise`/`asdf`
→ release-скрипты (**без исполнения**, только статическое чтение).

* Каждый уровень обязан дать **exact** версию и атрибуцию (build-stage/job);
  частичный тег (`1.22`), неразрешённая переменная, конфликт → `UNKNOWN`.
* Release-скрипты: статическое извлечение литеральной `go`-версии из известных
  форм (напр. `go install golang.org/dl/go1.22.8`, `GOTOOLCHAIN=go1.22.8`,
  явный аргумент `--go-version`); если версия не литеральна (переменная,
  вычисление, матрица) → `UNKNOWN`. `GoVersionSource` для этого уровня —
  `version-file` (тот же семантический класс: «локально зафиксированный биндинг»)
  с обязательным `file:line` в Evidence; отдельного enum-значения `script` не
  вводим, чтобы не размножать источники без нужды.
* `GoVersionSource` описывает именно `ReleaseGoVersion`.
* Конкретные `file:line:value` сохраняются в существующем Evidence, не только enum.
* `ReleaseGoVersion` нормализуется через `toolchain.Normalize` единообразно для всех consumers.

**Область вычисления ContentHash (F04):** вычисляется **только** для нового
external-snapshot пути (`ExternalCommitSHA != ""`). Обычный git-путь
`repository.Snapshot` hash не считает — production `analyze`/`scan`/`remediate`
не получают дополнительного I/O. Это сохраняет «production не затронут» для
git-пути и ограничивает стоимость одним обходом дерева на снапшот в рамках run.

### 2.5 Advisory intake и outcomes (P0, F07)

`PrepareAdvisory` (control plane) валидирует документ и возвращает **один из исходов**:

| Исход | Условие | Поведение |
|---|---|---|
| `usable` | **каждая** сохраняемая Go-запись документа имеет непустой `package.name` **и** хотя бы один валидный нормализованный `SEMVER`-range/event | файл → `--vuln-file` |
| `partial` | ≥1 запись usable, но есть **другая сохраняемая Go-запись** без валидных ranges | документ подаётся, но каждая непригодная запись превращается в **pending** (не drop, не FALSE): итог по ней — UNKNOWN, не `VersionAffected=FALSE` |
| `unsupported` | нет ни одной usable Go-записи / только `imports` без ranges / только `GIT`-ranges без package | честный unresolved: кейс → `INCONCLUSIVE` с limitation, **вырожденный документ в resolver не подаётся** |
| `error` | transport/parse/identity | кейс → failed (не safe) |

Правила:

* Пригодность = Go-ecosystem semantic content с **нормализованными** интервалами,
  согласованный с `affectedByRanges`/resolver.
* `imports` без ranges **не** доказательство unaffectedness.
* Ключевой инвариант (закрывает контрпример F07): присутствие одной валидной
  записи **не** разрешает resolver-у выставлять `VersionAffected=FALSE` для другой
  применимой записи с непригодными ranges. Непригодная запись попадает в pending
  (`verUnknown`-путь, `internal/affected/resolver.go:144-166`) → `VersionAffected=UNKNOWN`.
  Реализация: adapter помечает непригодные записи как pending-маркер, который
  пробрасывается в `AffectedModule` (например, пустой `AffectedVersions` + флаг
  `ScopeUndecided`), либо документ не принимается как `usable`, если хотя бы одна
  сохраняемая запись непригодна. Выбор из двух — при реализации, но контракт
  инварианта обязателен.
* Несколько `GO-*` alias: сохранять **все** относящиеся Go-entries; при неоднозначности — UNKNOWN.
* Никакого `if CVE==...`; правило generic (§2.6).
* `unsupported` не превращается в safe-negative и не подменяет canonical ID:
  `Vulnerability.ID` остаётся document GO-ID, requested CVE хранится в result envelope.

Fixtures (обязательные): imports без ranges; SEMVER без events; non-Go entry;
**смешанный multi-entry**: запись A usable с отсутствующим модулем + запись B
присутствующего модуля с непригодными ranges (контрпример F07) → не `NOT_AFFECTED`;
multiple aliases; minikube-кейс.

### 2.6 Physical isolation boundary (P0, F05)

Две независимые гарантии. Одна typed-границы недостаточно — нужна
**исполнимая** граница чтения/исполнения. Ниже — механизм, а не декларация.

**1. Typed boundary:** `LoadGoTasks` возвращает только stripped runnable inputs;
hidden truth читается только scorer-ом после сохранения predictions.

**2. Filesystem/input scope — конкретный механизм:**

| Канал | Правило | Точка кода |
|---|---|---|
| Snapshot reads | `LocateSnapshot` канонизирует путь (`filepath.EvalSymlinks` + `filepath.Rel` от `reposDir`); reject escape/`..`/абсолютный путь вне корня/`.git`. Анализ запускается только по этому каноническому пути | новый helper adapter-а |
| `.env` | VEX-режим **не вызывает** `loadLLMEnv`: новый `analyzeOpts.suppressEnvFile`, выставляемый только VEX-командой. Bare-`analyze` сохраняет текущее поведение (флаг по умолчанию `false`) | `cmd/izyan/main.go:589` |
| Env subprocess-ов | **Полная замена**, не дополнение: новый `analyzeOpts.envReplace bool`. При `true` `toolaudit.Run` и `packages.Load` используют **только** переданный env, без `os.Environ()`. Сейчас везде `append(os.Environ(), env...)` — 5 сайтов (`internal/toolaudit/toolaudit.go:62`, `internal/goanalysis/source.go:245,331,1421,2157`) | новый режим в `toolaudit.Run` + `source.go` |
| Advisory | `PrepareAdvisory` пишет единственный документ в **отдельном** каталоге и помечает его как **prepared**: для prepared-документа локальный alias-search **отключён** (документ уже прошёл §2.5). Иначе `FileSource` читает `../reviewed/<alias>.json`, `../live/<alias>.json`, `../<alias>.json` (`internal/vulnerability/source.go:171-179`) | новый `FileSource`-режим `NoLocalAlias` + `BaseURL=""` |
| Scorer files | `scoring/`, raw JSONL, reference-файлы — вне `reposDir` и вне caseDir; не читаются ни одним путём анализа | layout + тест |
| Overlays | `--knowledge`, `--non-locus-basis`, `--deploy-manifests`, локальные `replace`/workspace-файлы за пределами snapshot — запрещены или игнорируются | allowlist §2.6 |

**Read-root gate: запрет до I/O, не finding после.** Проверка уже созданных
evidence-файлов (`review.Structural`) недостаточна: она срабатывает **после**
чтения и не покрывает каналы, которые не пишут `Evidence.File` (напр.
`gatedImports`, `internal/affected/resolver.go:586-617`, читает
`p.Dir/f` через `parser.ParseFile` и не создаёт evidence). Поэтому:

* Вводится общий read-gate (`goanalysis`/`repository` scope, включаемый
  `analyzeOpts.confineReads bool`, по умолчанию `false` — обычный analyze не
  меняется). Gate хранит **канонические** разрешённые корни:
  `snapshotRoot` (после `EvalSymlinks`), SDK dir, `GOMODCACHE`, prepared-advisory-dir.
* Любое чтение исходников маршрутизируется через gate **до** открытия файла:
  `nodeSource` (`internal/goanalysis/source.go:1792-1798`),
  `ReadSource`/`pathAllowed` (там же `1839-1880` — сейчас проверка лексическая,
  апгрейдится до канонической), `gatedImports`
  (`internal/affected/resolver.go:597`), `locusverify`/`WalkDir` обходы.
* Правило: `EvalSymlinks(цель)` обязан лежать под одним из разрешённых корней;
  иначе gate возвращает **ошибку** → tool failure/limitation → UNKNOWN, никогда
  не тихое чтение. Внутренний symlink snapshot-а, ведущий наружу, отвергается по
  конечному каноническому пути, а не по лексическому префиксу.
* `packages.Load` получает scrubbed env (§2.6, envReplace) — внешние
  workspace/overlay/local-replace корни не появляются; модули резолвятся из
  `GOMODCACHE` (разрешённый корень).

**Preflight до первого чтения загрузчиком (закрывает остаток F05).**
`source.go:229-251` включает `NeedSyntax`, и `packages.Load` читает файлы
(`os.ReadFile`) **до** `ParseFile`/`nodeSource`, поэтому helper-gate сработает
слишком поздно. Поэтому confinement обеспечивается preflight-ом **до** запуска
загрузчика:

1. Preflight читает `go.mod`/`go.work` снапшота и собирает все `replace`-цели и
   workspace-`use` пути. Любая **path-цель** (`./x`, `../x`, `/x`) канонизируется
   (`EvalSymlinks` + `Rel`); цель вне `snapshotRoot` → **ошибка подготовки**
   (`unsupported`/`error`, не анализ), с записанным `file:line`.
2. Модульные replace (замена модуля на другой модуль/версию) разрешены — они
   резолвятся из `GOMODCACHE`, а не с диска вне корней.
3. Снапшот монтируется/используется **read-only**; `-mod=mod` не применяется
   (snapshot immutable), поэтому загрузчик не переписывает go.mod и не тянет
   локальные пути.
4. Symlink **внутри** snapshot наружу закрывается п.1 (канонизация) + preflight
   по symlink-записям: перед загрузчиком обход дерева находит все записи
   mode `120000`, резолвит их цель (`Readlink` + `EvalSymlinks`) и отклоняет
   любую, чья каноническая цель выходит за `snapshotRoot` → `unsupported`/`error`.
   Правило **fail-closed**, не зависит от предположения об отсутствии symlink.
   Попутно разрываются symlink-циклы (`EvalSymlinks` вернёт ошибку → limit/UNKNOWN).

**Проверенный факт по корпусу** (VEX-Bench `80cddeac`, все 28 Go-снапшотов):
17 содержат `replace`, но **все path-цели — внутри снапшота** (`k8s … => ./staging/...`,
`moby/api => ./api`, `rancher/... => ./pkg/...`); **0 path-replace вне снапшота**.
Symlink-записи присутствуют в 14 снапшотах (204 всего: cilium 6, kubernetes 34–35,
podman 1–8, helm 4, moby 5, minikube 4, trivy 3, istio 1, gitleaks 1); точечная
проверка целей (cilium) — все внутри репозитория, но правило §2.6 не опирается
на это: preflight канонизирует **каждую** symlink-цель. Значит, для Task 1
preflight-правило не отсекает ни одного кейса, а лишь защищает контракт.

**Adversarial acceptance** (обязательный тест, не label-changing):

1. Hidden-файл (scoring/JSONL) **не прочитан** — проверяется отсутствием
   содержимого/ошибкой gate, а не появлением finding после чтения.
2. Путь вне `reposDir` — отвергается `LocateSnapshot`.
3. Symlink **внутри** snapshot, ведущий за его пределы, — отклоняется preflight-ом
   до `packages.Load`; проверяется по канонической цели, а не лексическому префиксу.
4. Fixture с `replace ../outside` — preflight отклоняет кейс до `packages.Load`.
5. Дочерний инструмент не видит ambient-переменные (проверка `envReplace`).
6. Prepared advisory-каталог без sibling-файлов не активирует alias-search.

VEX-ограничения (внутри subcommand, не generic profile):

```
запрещено: --non-locus-basis --accept-locus-proposals --trusted-peer
           --knowledge <custom> --deploy-manifests --perimeter{cluster,public}
           --root-cause --exploit-model --release --binary --release-go-version
           --cve-analysis --with-llm
разрешено: --tasks --repos-dir --case -j --out --mem-limit
```

### 2.7 Какой «offline» достижим (P1, F06)

Один `advisory.json` **не** обеспечивает offline-анализ. Выбор режима Task 1:

* **Гарантируется:** offline scorer + frozen chosen advisory.
* **Не гарантируется:** полностью offline analysis. Public advisory/upstream
  research разрешён спекой §19.
* Provenance фиксирует **actual** external artifacts и их digests: OSV/advisory
  контент + hash, govulncheck DB version, fix-patch входы, Go SDK, effective
  knowledge digest, GOOS/GOARCH/CGO/build flags.

Если позднее потребуется no-network analysis — preparation обязан замкнуть
все внешние входы (alias enrichment, coverage OSV, fix-patch, module cache,
govulncheck DB) и runner — использовать pinned local providers без HTTP fallback.

---

## 3. Границы компонентов (P0, F08)

```
cmd/izyan/vexbench.go     # CLI parser/allowlist, runner, сборка analyzeOpts
internal/eval/vexbench/    # typed tasks, snapshot lookup, advisory prep, scoring (pure)
```

* Adapter **не импортирует `cmd`** и не извлекает analyzer в публичный framework.
* `analyzeOpts` и `analyzeCase` остаются в `main`; новый вход — **только**
  внутренний `externalCommitSHA`, прокинутый в `buildSnapshotOptions`.
* Локальный advisory **переиспользует существующий `vulnFile`** (новый `advisoryFile` не нужен).
* Per-task `caseDir` — под `out`, **вне** snapshot; сохраняет полные `AnalysisCase`/report.
* Parser/allowlist реализуются **до** runner CLI-тестов; dispatch — по переданному
  args-slice с проверкой длины, не по глобальному `os.Args`.

---

## 4. Result envelope (P1, F10)

Запись на кейс:

```json
{
  "task_id": "...", "requested_cve": "CVE-...", "resolved_vulnerability_id": "GO-...",
  "terminal_state": "COMPLETED|INCONCLUSIVE|FAILED",
  "verdict": null|"NOT_AFFECTED|NO_EXPLOIT_PATH_FOUND|EXPLOITABLE|INCONCLUSIVE",
  "reason": "...", "grounding_condition_ids": ["C-..."], "falsifier": "...", "ground_basis": "...",
  "limitations": ["..."], "error": "...",
  "scoring_outcome": "correct_safe|correct_exploitable|abstain|wrong|failed",
  "compatibility_category": "code_not_reachable",
  "evidence_ids": ["EV-..."],
  "artifacts": {"case": "<out>/<task>/case/", "report": "<out>/<task>/case/report.json"},
  "usage": {"llm_calls": 0, "tool_calls": 0, "tokens": 0, "wall_seconds": 0},
  "snapshot": {"repo": "...", "external_commit_sha": "...", "content_hash": "..."},
  "advisory": {"source": "osv:vulns/GO-...", "sha256": "..."}
}
```

Правила:

* Успешное терминальное состояние — `COMPLETED` (`workflow.isTerminal`,
  `internal/workflow/engine.go:66-68`); `EVALUATE_VERDICT` — это состояние
  конвейера, а не terminal state.
* `INCONCLUSIVE`-terminal с `nil` verdict — **abstention** с сохранённой причиной;
  `FAILED` — **failed**, даже при `nil` error.
* Missing/malformed output — **error**, не implicit safe.
* Prediction + evidence IDs **не** считается audit packet: обязательны ссылки на
  полные persisted case/report артефакты.
* Ранние исходы (`INCONCLUSIVE`/`FAILED` до `EVALUATE_VERDICT`) тоже пишут
  per-task артефакты: сохранённый `AnalysisCase` JSON из persistence + result
  envelope; `report.json` может отсутствовать — поле `artifacts.report` тогда `null`.

**Aggregation и exit (Task 1):**

* Все 30 кейсов должны получить запись; `failed` не исключаются из знаменателя.
* Знаменатели: `SafeClearRate = correct_safe / all_not_exploitable`,
  `ExploitableRecall = correct_exploitable / all_exploitable`,
  `InconclusiveRate = abstain / all`, `CompletionRate = (total - failed) / total`.
* Exit-код VEX-команды: `0` — прогон завершён и посчитан (в том числе при
  `INCONCLUSIVE`/дивергенциях); ненулевой — при инфраструктурной ошибке
  подготовки/scorer-а или ненайденном снапшоте. `FalseSafe` **не** влияет на
  exit Task 1 (это baseline-фиксация, а не gate); safety gate применяется в Task 2
  сравнении.
* `usage`: в детерминированном режиме `llm_calls == 0`, `tokens == 0`;
  проверяется тестом (zero-cost acceptance).

---

## 5. Scoring (P1, F09)

### 5.1 Safety-aware (основная)

```
FalseSafe = GT==exploitable AND verdict ∈ {NOT_AFFECTED, NO_EXPLOIT_PATH_FOUND}
SafeClearRate = correct_safe / all_not_exploitable
ExploitableRecall = correct_exploitable / all_exploitable
InconclusiveRate = inconclusive / total
```

`INCONCLUSIVE` — abstention (unresolved), никогда не safe (спека §41).

### 5.2 Compatibility projection (total, lossless-first)

Проекция строится из **`AffectedResult` + финального grounding claim/condition**
(`Verdict.ConditionIDs`) с `Falsifier`/`GroundBasis` и успешной negative verification.
Свободный `Reason` не парсится; category по GT не выбирается.

| Внутренний факт | category |
|---|---|
| `EXPLOITABLE` | `vulnerable` |
| `NOT_AFFECTED` module-absent (module вне dep-graph) | `code_not_present` |
| `NOT_AFFECTED` version-outside-range (resolved = fixed version) | `code_not_present` |
| `NOT_AFFECTED` package-absent (не в import closure) | `code_not_reachable` |
| `NOT_AFFECTED` build-not-relevant (другая платформа/build-конфиг) | `requires_environment` |
| `NEPF` falsifier `package-absent` | `code_not_present` |
| `NEPF` `locus-package-absent` | `code_not_present` |
| `NEPF` `locus-function-unreached`/`govulncheck-silence`/`unreached-exported-subject` | `code_not_reachable` |
| `NEPF` `config-feature-disabled`/`safe-config-*`/`zero-value-config` | `requires_configuration` |
| `NEPF` `trusted-infrastructure` (declared/auto perimeter) | `perimeter_protected` |
| `NEPF` `trusted-infrastructure` (config-origin) | `mitigating_control_protected` |
| `NEPF` `loopback-only` | `perimeter_protected` |
| `NEPF` `protocol-role-mismatch`/`snapshot-fact-mismatch` | `requires_environment` |
| `NEPF` `guards`/`constant-or-generated-input`/`missing-pair-member`/`missing-source-symbol`/`no-product-reader` | `mitigating_control_protected` |
| непредставимая/неоднозначная причина | `uncertain` (официальная проекция) + raw semantics во внутреннем envelope |
| `INCONCLUSIVE` | `uncertain` |
| failed/error | `failed` (внутренний; официальная проекция — `uncertain`, failures не исключаются из знаменателя) |

Какая именно строка применяется, определяется **полем `AffectedResult`** (module/version/package/build),
а не текстом `Reason`; для NEPF — `Falsifier` grounding-claim (§5.4).

* `status_correct` и `reason_correct` считаются **раздельно** (спека §14).
* `justification macro-F1` — по compatibility categories, отдельно помечено.
* Domain, exploit-patterns, VEX-экспорты **не** расширяются под taxonomy.

### 5.3 Официальный output-контракт (F09)

Pinned official parser принимает **только 12 официальных категорий**
(`src/evaluate/result_parser.py`, pin `80cddeac`). Поэтому:

* `failed` — **внутренний** diagnostics outcome, не публикационная
  категория. Для публикационного прогона генерируется отдельный файл
  `official_compat.json` со схемой `{"category": "<одна из 12>", "reasoning": "..."}`.
* Непредставимая/неоднозначная причина → `uncertain` в официальной проекции,
  с сохранением raw semantics во внутреннем envelope.
* Наш compatibility-скор отдельно считает completeness и failed-count;
  официальный scorer получит `uncertain`, если внутренний результат —
  abstention/failed (failures не исключаются из знаменателя, как в официальном
  scorer).

### 5.4 Applicability/environment reasons

§5.2 — единственный источник маппинга; здесь только правило редукции.
`affected`-основания различаются, а не схлопываются, и берутся из **поля
`AffectedResult`** (какое именно FIELD=FALSE: `ModulePresent`, `VersionAffected`,
`PackagePresent`, `BuildRelevant`), не из текста `Reason`. Для NEPF — из
`Falsifier` grounding-claim. Согласовано с таблицей §5.2; при расхождении
нормативной считается таблица.

---

## 6. Известные внешние ограничения

1. **OSV не usable у 5/30 Go-кейсов** (4 alias-only при HTTP 200 + CVE-2025-29785 без package).
   `OSVSource` fallback срабатывает только на HTTP 404 → `PrepareAdvisory` обязателен (§2.5).
2. **`code_not_present` = 3 Go-кейса**, модуль присутствует во всех трёх → семантика шире
   определения VEX-Bench (§11).
3. **`code_not_reachable` = 18/30** — главная проверяемая гипотеза Task 2.
4. **minikube CVE-2019-5736** — нет Go-записи в vulndb → честный `INCONCLUSIVE`, не дефект Izyan.

---

## 7. Реестр неизвестных

| ID | Неизвестное | Класс | Приоритет | Способ закрытия | Статус |
|---|---|---|---|---|---|
| U-01 | Семантика `code_not_present` | неизвестное неизвестное | P1 | Исследование §11 (ограниченная форма) | закрыт |
| U-02 | Вид OSV после alias-fallback | известное неизвестное | P1 | GO-записи содержат package+SEMVER | закрыт |
| U-03 | Фиксы-добавленные символы (B20-класс) в Go-подмножестве | известное неизвестное | P2 | Review divergences Task 2 | открыт |
| U-04 | Нужен ли generic `--benchmark-profile` | скрытый критерий | P2 | Решить по итогам Task 2 | отложен |
| U-05 | Нужен ли контейнер на кейс в Task 1 | скрытый критерий | P2 | Нет (решение пользователя) | закрыт |
| U-06 | Pin VEX-Bench | известное известное | P2 | `80cddeac3132826bfd47227ad59b2e6618a681bd` | закрыт |
| U-08 | Release-scoped evidence при UNKNOWN/mismatch target | неизвестное неизвестное | P0 | Контракт §2.2 (verdict-level gate) | закрыт |
| U-09 | Actual analysis Go 1.26.1 при local-fallback plumbing | известное неизвестное | P0 | Контракт §2.3 (pin propagation) | закрыт |
| U-10 | Физическая граница hidden scorer files | неизвестное неизвестное | P0 | Каналы §2.6: `envReplace`, `NoLocalAlias`, read-gate до I/O (`confineReads`), **preflight до `packages.Load`** + 6-пунктовый adversarial acceptance | закрыт |
| U-11 | Outcome без usable Go advisory; что реально frozen | известное неизвестное | P0 | §2.5 outcomes + §2.7 offline scope | закрыт |
| U-12 | Exact evidence, конфликты, приоритет binary/explicit | известное неизвестное | P1 | Таблица источников §2.4 | закрыт |
| U-13 | Canonical hash scope, symlink/output, invalidation | известное неизвестное | P1 | §2.1 + §2.4 (scope) | закрыт |
| U-14 | Early/nil-verdict/failed и непредставимые reasons | известное неизвестное | P1 | §4 envelope + §5.3 official output | закрыт |

Открытых P0 нет. Реализационные тесты (fixtures §2.1/§2.4/§2.5, adversarial-тест
§2.6) — это шаги §9, а не открытые архитектурные решения.

---

## 8. Blast radius

| Область | Влияние | Проверка |
|---|---|---|
| `analyze` | snapshot identity/evidence; приоритет binary/explicit/ticket; affected/platform/runtime; пояснения отчёта | точечные тесты + `real-http2-server` |
| `scan` | deterministic prefilter, набор survivors, shared toolchain/cache, `scan.json` | `go test ./internal/states/...`, `cmd/izyan/scan_test.go` |
| `remediate` | before/after affectedness, `FixTarget` (ok=false при `VersionAffected!=TRUE`) | `cmd/izyan/remediate` тесты |
| `eval` | `go_version` wiring, generated minimum directive, ref-materialized git-less snapshots, прежние expectations | `go test ./internal/eval/...` |
| Platform/runtime | `platform_test.go` закрепляет старую go.mod-fallback семантику — обновляется вместе с §2.2 | `internal/evaluator/platform_test.go` |
| affected multi-module | stdlib-pending + dependency-entry одновременно | `resolver_test.go:347-375` |
| persistence | старый JSON без новых полей; Save/Load roundtrip; restart после snapshot | `internal/persistence/filesystem/store_test.go` |
| report/exports | `report.json`, Markdown/tracker, OpenVEX/CycloneDX для external Commit | `internal/report/...` |
| docs | `eval/README.md`, `docs/cli.md`, `docs/architecture.md:74`, `docs/dev/analysis-internals.md:282-287`, B38/B39, INDEX | — |
| spec | §52.18 нужна оговорка: generic snapshot/version safety-fixes — заранее перечисленные prerequisites, не Shadow/VEX-improvements; baseline A — конкретный commit после них, с опубликованным diff состава. `--shadow-agent` production verdict не меняет | спека §52.18 |

---

## 9. Task 1 — чек-лист (порядок по зависимостям)

### Шаг 1. P0-контракты (до Go-правок)
- [ ] Зафиксировать в этом плане/спеке: baseline identity, spec §52.18 оговорка, release-scope (§2.2), analysis pin (§2.3), advisory outcomes (§2.5), physical boundary (§2.6), total result/scoring (§4–5).
- [ ] Обновить §13 условия возврата (снять уже-выполненное условие §11).

### Шаг 2. Domain/repository additive identity
- [ ] Тесты: new fields marshal; old JSON без новых полей читается; Save/Load roundtrip.
- [ ] `GoVersionSource` consts; `ExternalCommitSHA`/`ContentHash`/`MinimumGoVersion` (только отсутствующие).
- [ ] Canonical `ContentHash` contract + тесты (rename/symlink-escape/mutation/concurrent); **hash только для external-пути** (§2.4).
- [ ] `repository.Snapshot` external-commit путь без git; `GoVersion` через `tc.Env`.

### Шаг 3. Release evidence + toolchain wiring
- [ ] `goVersionEvidence` discovery (§2.4) + fixtures всех источников, скриптов и конфликтов.
- [ ] `buildSnapshotOptions` переносит `externalCommitSHA`; `vulnFile` переиспользуется.
- [ ] Analysis pin 1.26.1 propagation; тесты со stub tools и adverse env (`GOTOOLCHAIN`/`GOWORK`/`GOFLAGS`).

### Шаг 4. Release-scoped verdict safety (P0)
- [ ] Общий gate scope в evaluator/states (§2.2), не в exploit-pattern.
- [ ] Pure verdict-тесты F01 (4 сценария).
- [ ] Обновить `platform_test.go`; проверить `real-http2-server` → INCONCLUSIVE.

### Шаг 5. Adapter pure-часть
- [ ] `LoadGoTasks` (только stripped), `LocateSnapshot` (confinement), `PrepareAdvisory` (outcomes `usable`/`partial`/`unsupported`/`error`, §2.5).
- [ ] Fixture смешанного multi-entry (контрпример F07) → не `NOT_AFFECTED`.
- [ ] Scorer: total projection (§5.2), official output (§5.3), failure/abstention matrix; независимые truth×prediction fixtures.

### Шаг 6. cmd runner
- [ ] Parser/allowlist → runner → `analyzeCase`; per-task caseDir вне snapshot.
- [ ] Isolation (§2.6): `suppressEnvFile`; `envReplace` (полная замена env в `toolaudit.Run` + 4 сайта `source.go`); `FileSource.NoLocalAlias` для prepared advisory; **read-gate до I/O** (`confineReads`) канонически закрывает `nodeSource`, `ReadSource`/`pathAllowed`, `gatedImports`, `WalkDir`-обходы; **preflight до `packages.Load`** отклоняет `replace`/workspace-`use` path-цели вне `snapshotRoot`.
- [ ] Adversarial acceptance (§2.6, 6 пунктов): hidden-файл **не прочитан**, путь вне `reposDir`, symlink наружу из snapshot, `replace ../outside` до загрузчика, ambient env дочернего процесса, sibling alias-search — все отвергаются.
- [ ] Result envelope (§4) с `COMPLETED`; post-run offline scoring.
- [ ] Mini-fixture end-to-end (snapshot без `.git` проходит SNAPSHOT_PRODUCT).
- [ ] Label-changing тест: изменение GT не меняет prediction.
- [ ] Zero-cost acceptance: `llm_calls==0`, `tokens==0`.

### Шаг 7. Smoke (§24)
- [ ] 3 реальных кейса; проверить isolation/advisory/snapshot/artifacts/usage;
  вердикт с GT **не** обязан совпадать — smoke про инфраструктуру.
- [ ] Никаких VEX-specific fixes в production.

### Шаг 8. Docs + branch regression
- [ ] `eval/README.md`, `docs/cli.md`, `architecture.md`, `analysis-internals.md`, B38/B39, INDEX.
- [ ] `gofmt`, `go vet ./...`, `go test ./...`; один финальный corpus-regression (`false-safe=0`).
  Это **не** дополнительный VEX baseline run.

### Шаг 9. Task 2 — external baseline
1. Зафиксировать actual pinned provenance (Izyan SHA, VEX-Bench SHA, analysis Go, govulncheck DB+version, OSV fetch time + digests, adapter version, run date).
2. Один полный прогон 30 кейсов, `-j 4`, детерминированно.
3. Сохранить immutable `prediction.json`/raw cases/reports + `metrics.json`/`cases.jsonl`.
4. Failure taxonomy (§45 спеки).
5. Первый baseline **не** пересчитывается после анализа GT.

Приёмка Task 2 — **три независимых условия**, не одно:

1. **Baseline сохранён:** 30/30 кейсов имеют immutable predictions + полные
   артефакты + provenance; `CompletionRate` зафиксирован.
2. **Safety gate:** `FalseSafe == 0`. Ненулевой `FalseSafe` **не** «объясняется»
   и не закрывается текстом — это либо дефект, требующий generic fix +
   counterexample (спека §50), либо явно эскалируется как блокер. Объяснение
   источника допустимо только для кейсов, где GT/семантика набора спорны
   (`BENCHMARK_AMBIGUITY`), и такие кейсы **исключаются из знаменателя с
   записанным основанием**, а не зачитываются как прохождение gate.
3. **Отчётность:** SafeClearRate, INCONCLUSIVE rate, compatibility metrics,
   failure taxonomy заполнены; каждый divergence разобран.

---

## 10. Приложение: Go-подмножество VEX-Bench (30 кейсов)

30 кейсов = 28 уникальных снапшотов, 15 репозиториев, 24 уникальные CVE.
Распределение: `code_not_reachable` 18, `vulnerable` 7, `code_not_present` 3,
`requires_configuration` 2. Pin `80cddeac3132826bfd47227ad59b2e6618a681bd`.

| task_id | GT category | CVE | repo@sha | go.mod |
|---|---|---|---|---|
| `containers-podman-5ae6347-CVE-2025-47914` | `code_not_present` | CVE-2025-47914 | containers/podman@5ae6347 | 1.25.6 |
| `kubernetes-kubernetes-6d4b94f-CVE-2022-41717` | `code_not_present` | CVE-2022-41717 | kubernetes/kubernetes@6d4b94f | 1.19 |
| `kubernetes-minikube-e7bf515-CVE-2019-5736` | `code_not_present` | CVE-2019-5736 | kubernetes/minikube@e7bf515 | 1.22.0 |
| `aquasecurity-trivy-37da98d-CVE-2024-32473` | `code_not_reachable` | CVE-2024-32473 | aquasecurity/trivy@37da98d | 1.22 |
| `aquasecurity-trivy-98e136e-CVE-2024-24791` | `code_not_reachable` | CVE-2024-24791 ↔ GO-2024-2963 | aquasecurity/trivy@98e136e | 1.22.0 |
| `cilium-cilium-3977f6a-CVE-2026-33186` | `code_not_reachable` | CVE-2026-33186 | cilium/cilium@3977f6a | 1.25.0 |
| `containers-podman-38ccfa2-CVE-2024-37298` | `code_not_reachable` | CVE-2024-37298 | containers/podman@38ccfa2 | 1.18 |
| `containers-podman-6541fc4-CVE-2025-58181` | `code_not_reachable` | CVE-2025-58181 | containers/podman@6541fc4 | 1.24.2 |
| `helm-helm-b76a950-CVE-2024-25621` | `code_not_reachable` | CVE-2024-25621 | helm/helm@b76a950 | 1.24.0 |
| `helm-helm-fbb24fe-CVE-2021-21334` | `code_not_reachable` | CVE-2021-21334 | helm/helm@fbb24fe | 1.16 |
| `istio-istio-042afc3-CVE-2023-48795` | `code_not_reachable` | CVE-2023-48795 | istio/istio@042afc3 | 1.20 |
| `istio-istio-8903f65-CVE-2024-45338` | `code_not_reachable` | CVE-2024-45338 ↔ GO-2024-3333 | istio/istio@8903f65 | 1.22.0 |
| `juanfont-headscale-e172c29-CVE-2024-45338` | `code_not_reachable` | CVE-2024-45338 ↔ GO-2024-3333 | juanfont/headscale@e172c29 | 1.23.1 |
| `kubernetes-kubernetes-1ee2acb-CVE-2024-24786` | `code_not_reachable` | CVE-2024-24786 ↔ GO-2024-2611 | kubernetes/kubernetes@1ee2acb | 1.19 |
| `labstack-echo-fdacff0-CVE-2020-26160` | `code_not_reachable` | CVE-2020-26160 | labstack/echo@fdacff0 | 1.15 |
| `moby-moby-3ede246-CVE-2026-39984` | `code_not_reachable` | CVE-2026-39984 | moby/moby@3ede246 | 1.25.5 |
| `moby-moby-caea5f7-CVE-2026-39883` | `code_not_reachable` | CVE-2026-39883 | moby/moby@caea5f7 | 1.25.5 |
| `rancher-rancher-4dc4f53-CVE-2025-58181` | `code_not_reachable` | CVE-2025-58181 | rancher/rancher@4dc4f53 | 1.24.0 |
| `rancher-rancher-8761419-CVE-2026-24051` | `code_not_reachable` | CVE-2026-24051 | rancher/rancher@8761419 | 1.24.0 |
| `rancher-rancher-8761419-CVE-2026-39883` | `code_not_reachable` | CVE-2026-39883 | rancher/rancher@8761419 | 1.24.0 |
| `zeromicro-go-zero-bae061a-CVE-2022-32149` | `code_not_reachable` | CVE-2022-32149 | zeromicro/go-zero@bae061a | 1.16 |
| `cilium-cilium-43bff35-CVE-2026-35469` | `requires_configuration` | CVE-2026-35469 | cilium/cilium@43bff35 | 1.25.0 |
| `gitleaks-gitleaks-f487f85-CVE-2025-22871` | `requires_configuration` | CVE-2025-22871 ↔ GO-2025-3563 | gitleaks/gitleaks@f487f85 | 1.23.0 |
| `caddyserver-caddy-8dc7667-CVE-2025-29785` | `vulnerable` | CVE-2025-29785 ↔ GO-2025-3735 | caddyserver/caddy@8dc7667 | 1.24 |
| `cilium-cilium-1228cbc-CVE-2026-35469` | `vulnerable` | CVE-2026-35469 | cilium/cilium@1228cbc | 1.25.0 |
| `containers-podman-6a65597-CVE-2023-48795` | `vulnerable` | CVE-2023-48795 | containers/podman@6a65597 | 1.20 |
| `kubernetes-kubernetes-e196d24-CVE-2023-44487` | `vulnerable` | CVE-2023-44487 | kubernetes/kubernetes@e196d24 | 1.20 |
| `kubernetes-kubernetes-ec78c0f-CVE-2021-3121` | `vulnerable` | CVE-2021-3121 ↔ GO-2021-0053 | kubernetes/kubernetes@ec78c0f | 1.15 |
| `rancher-rancher-4dc4f53-CVE-2025-47914` | `vulnerable` | CVE-2025-47914 | rancher/rancher@4dc4f53 | 1.24.0 |
| `stretchr-testify-285adcc-CVE-2022-28948` | `vulnerable` | CVE-2022-28948 | stretchr/testify@285adcc | 1.13 |

`↔ GO-…` — CVE, чей прямой OSV-документ не usable, требуется alias-fallback (§2.5).

Smoke-набор (§24): `stretchr-testify-285adcc-CVE-2022-28948` (exploitable),
`labstack-echo-fdacff0-CVE-2020-26160` (code_not_reachable),
`gitleaks-gitleaks-f487f85-CVE-2025-22871` (requires_configuration).

---

## 11. U-01: семантика `code_not_present` (ограниченное закрытие)

Авторитетное определение — промпт VEX-Bench: `code_not_present` = «модуль
отсутствует в манифесте/lockfile/vendor»; `code_not_reachable` = «код присутствует,
но не исполняется» (`src/evaluate/prompts.py`).

**Установленные snapshot-факты** (манифесты на пине):

| task | CVE | модуль | факт в snapshot | OSV |
|---|---|---|---|---|
| minikube-e7bf515 | CVE-2019-5736 | runc | `go.mod: runc v1.1.14` | **нет Go-записи** в vulndb; прямой OSV-док — GIT-ranges без package |
| podman-5ae6347 | CVE-2025-47914 | x/crypto | `go.mod: v0.49.0` | GO-2025-4135: `0 → fixed 0.45.0`, imports `ssh/agent` |
| kubernetes-6d4b94f | CVE-2022-41717 | x/net | `go.mod: v0.3.1-0.20221206200815`, `vendor/modules.txt: golang.org/x/net/http2` | GO-2022-1144: x/net `0 → fixed 0.4.0`; stdlib `fixed 1.18.9 / 1.19.4` |

**Что доказано, что нет:**

* Доказано: во всех трёх модуль **присутствует** в манифесте → буквальное
  определение #2 VEX-Bench к ним не применимо. Метка в датасете **шире** определения.
* Доказано (podman): версия выше `fixed` — «уязвимый код исправлен».
* **Не доказано** (kubernetes): факт присутствия уязвимой версии x/net и вендоренного
  `http2` **не** устанавливает runtime/build reachability. Вывод о reachability требует
  анализа и относится к Task 2, а не к плану Task 1.
* Falsifier `package-absent`/`locus-package-absent` ведёт к **`NO_EXPLOIT_PATH_FOUND`**
  (verified claim), **не** к `NOT_AFFECTED`; `NOT_AFFECTED` даёт только affected-цепочка
  (`verdict.go:17-62,78-97`).

**Ограниченное заключение:** расхождения taxonomy не меняют Task 1; raw internal
reasons сохраняются, неоднозначность рассматривается при scoring review. K8s-кейс
помечается `BENCHMARK_AMBIGUITY candidate` до разбора baseline. U-01 закрыт только
в этой ограниченной форме.

---

## 12. Коммиты

Ветка `feat/shadow-analyzer-agent`, Conventional Commits:

1. `feat(domain,repository): external commit identity, canonical content hash, snapshot-local Go version evidence`
2. `fix(affected,evaluator,toolchain): release-scoped applicability and pinned analysis toolchain`
3. `feat(eval): VEX-Bench adapter — task intake, advisory outcomes, snapshot lookup, scoring`
4. `feat(cmd): izyan eval vex-bench runner with benchmark input isolation`
5. `docs(eval,cli,gap-analysis,spec): document VEX-Bench adapter, release-toolchain semantics, baseline identity`

---

## 13. Условия возврата к проектированию

Остановиться и вернуться в design, если:

- реализация §2.2 обнаружит, что release-scoped gate нельзя сформулировать общим
  правилом без запрета независимых детерминистических доказательств;
- §2.5 покажет, что generic alias-resolution сужает advisory scope иначе, чем
  multi-module resolver;
- в Go-подмножестве найдутся кейсы, где VEX-Bench ожидает deployment-факты,
  недоступные из снапшота (тогда `INCONCLUSIVE` — правильный результат, baseline
  фиксирует это как известное ограничение);
- официальный harness даёт агенту больше, чем «CVE + снапшот» (изменение §4 спеки).

# Plan: VEX-Bench external baseline (Task 2)

Ветка: `feat/shadow-analyzer-agent`, только выделенный worktree.
Спека: [`shadow-analyzer-agent-spec.md`](../specs/shadow-analyzer-agent-spec.md) §13–14, §25, §39–45, §48–52.
Предшествующий план: [`2026-10-06-vexbench-adapter-plan.md`](2026-10-06-vexbench-adapter-plan.md) §4–5, §9 шаг 9.

Статус: **CONDITIONAL** — дизайн определён; открытых архитектурных P0 нет.
Запуск запрещён до ресурсного preflight и реализации недостающего benchmark-only provenance (§4, §7).
На текущем хосте свободного диска недостаточно для принятого профиля. Это условие запуска, а не основание сокращать 30 кейсов.

Этот документ — план, не отчёт о выполненном baseline. Скачивание и анализ в рамках его подготовки не выполняются. После выполнения и приёмки Task 2 план удаляется по `docs/dev/plans/README.md:5-10`; постоянный результат остаётся в `eval/baselines/vexbench/external-baseline-1.md`.

Обозначения: **факт** — подтверждён кодом/источником; **решение** — контракт этого плана; **[INFERENCE]** — ещё не измеренная оценка.

---

## 0. Установленная территория

| Факт | Свидетельство |
|---|---|
| Реальный CLI: `--tasks`, `--repos-dir`, `--case`, `-j`, `--out`, `--analysis-go`, `--mem-limit`; нет `--mode`, `--output`, `--resume`, `--timeout` | `cmd/izyan/vexbench.go:31-40` |
| CLI выбирает Go-записи; фильтр task ID точный/glob, допускает comma-separated список | `internal/eval/vexbench/task.go:56-95`; `cmd/izyan/vexbench.go:426-453` |
| Все выбранные задачи планируются заново; predictions/aggregate metrics пишутся после завершения всех workers | `cmd/izyan/vexbench.go:96-129,349-423` |
| Анализ каждого кейса детерминированный, с отключённым `.env` и CVE analysis; target version вручную не передаётся | `cmd/izyan/vexbench.go:238-254` |
| Повторный `analyzeCase` создаёт новый timestamp-based case, а не продолжает старый state | `cmd/izyan/main.go:506-532` |
| Состояние сохраняется после каждой стадии, но это не resume benchmark runner | `internal/workflow/engine.go:35-65`; `internal/persistence/filesystem/store.go:35-55` |
| `--mem-limit` — общий бюджет Go runtime процесса, не лимит каждого worker/дерева subprocesses; превышение отменяет общий context, возможен exit 4 | `cmd/izyan/memguard.go:14-32,37-86` |
| HTTP-запрос выбранного advisory ограничен 30 s; общего case timeout нет | `internal/eval/vexbench/advisory.go:69-90`; `cmd/izyan/vexbench.go:64-87,179-182` |
| Текущий `metrics.json.provenance`: только `analysis_go`, `analysis_mode`, `adapter_version=1`, `generated_at` | `cmd/izyan/vexbench.go:368-385` |
| Advisory identity/digest есть, точного времени HTTP fetch и отвергнутых alias bodies нет | `internal/eval/vexbench/advisory.go:36-43,132-190,259-285` |
| Full AnalysisCase — JSON в `<case-dir>/<caseID>.json`; отчёт — `<case-dir>/<caseID>/report.json` и Markdown; при раннем исходе отчёта может не быть | `internal/persistence/filesystem/store.go:19-55`; `internal/report/report.go:22-53` |
| Scorer считает failed и abstain в общем знаменателе; status/reason correct раздельные счётчики | `internal/eval/vexbench/score.go:106-172`; `score_test.go:59-109` |
| Vendor fallback уже реализован: при отказе `go list -m -json all` используется `vendor/modules.txt` | `internal/affected/golist.go:84-105` |
| Скрипты оценки уже живут рядом с корпусами: Python 3, argparse, stdlib, явные входы | `eval/gen_reviewed_corpus.py:1-30,84-91` |
| Не коммитить приватные пути; не создавать рабочие артефакты в корне | `AGENTS.md:22-23,36`; `CONTRIBUTING.md:25` |

### Внешняя территория

Pin: `80cddeac3132826bfd47227ad59b2e6618a681bd`.
[Оригинальный JSONL](https://github.com/steven1518/vex-bench/blob/80cddeac3132826bfd47227ad59b2e6618a681bd/benchmark/tasks/vex_bench.jsonl), [downloader](https://github.com/steven1518/vex-bench/blob/80cddeac3132826bfd47227ad59b2e6618a681bd/src/builder/download.py#L11-L62).

30 Go cases = 28 уникальных снимков / 15 репозиториев / 24 CVE.
GT: 7 `vulnerable`, 18 `code_not_reachable`, 3 `code_not_present`, 2 `requires_configuration`.
Список task ID — приложение §10 существующего adapter-плана; полный SHA брать из pinned JSONL, не из сокращений приложения.
Две пары задач делят снимки `rancher@4dc4f53` и `rancher@8761419`.

Downloader принимает весь переданный JSONL, не имеет Go-фильтра. Его проверка идемпотентности — «каталог существует и непуст», поэтому прерванное скачивание ошибочно может считаться готовым. Ошибки отдельных задач логируются и цикл продолжается: успешный process exit не доказывает 28/28 acquisition.

### Измерения хоста, предоставленные исполнителем

Это измерения подготовки, не результат Baseline 1:

* свободно около 10–11 GiB на data volume, занято 98%;
* `kubernetes@6d4b94f`: 301 MB, 23 518 файлов; shallow fetch около 9 s;
* текущий module cache 4.2 GB; подготовка одного Kubernetes добавила 1.4 GB;
* реальный анализ Kubernetes идёт более 20 min, точное время завершения неизвестно;
* оценка всех 28 снимков — около 3.4 GB; прогноз module cache 7–8 GB — **[INFERENCE]**, не измеренный максимум.

Размеры нельзя выводить только из числа файлов. В preflight записать фактические bytes/free space выбранного volume; MB/GB из этих измерений не выдавать за GiB.

---

## 1. Цель, границы и baseline identity

**Решение:** получить `VEX-Bench External Baseline 1`: один логический run, ровно один первый attempt каждого из 30 task ID, immutable predictions и audit packet, исходные safety-aware/compatibility метрики, последующий ручной taxonomy/disagreement review.

Baseline A — конкретный Izyan SHA **после** generic release-safety prerequisites Task 1 (§52.18 спеки), но до исправлений по результатам внешнего baseline. В manifest сохранить полный SHA, binary digest и diff-состав относительно завершённого Task 1. Benchmark-only orchestration/provenance не меняет правила verdict.

Не входит: Plain Agent, Shadow Agent, hybrid, настройка prompts, устранение наблюдённых слабостей анализатора, удаление vendor, правка snapshot, добавление benchmark-specific knowledge или deployment/release metadata из GT/reference PR.

Task 1 smoke и уже запущенный подготовительный Kubernetes-кейс оформить в `prior_exposure` с task IDs/датами/назначением. Не называть все 30 полностью unseen, если часть уже просмотрена (§25, §49). Подготовительные результаты не подмешивать в Baseline 1; параллельные пробные процессы завершить/остановить отдельно до старта baseline.

---

## 2. Минимальный дизайн и границы компонентов

**Решение:** один небольшой `eval/vexbench_baseline.py` с подкомандами `acquire`, `preflight`, `run`, `report`, `validate-review`; Python 3/stdlib/argparse по существующему стилю. Не создавать `tools/`, новую production architecture или универсальный runner framework.

| Компонент | Ответственность | Не имеет права |
|---|---|---|
| `acquire` | pin dataset, фильтр Go, dedup снимков, atomic download, acquisition manifest | выбирать задачи по GT/ожидаемому verdict |
| `preflight/run` | ресурсный gate, frozen run manifest, clean env, per-case subprocess, timeout, ledger/resume | менять snapshot, advisory interpretation или production verdict |
| benchmark CLI provenance | записать фактически fetched direct/alias OSV bytes/time через существующий `Fetcher` | второй fetch вместо использованного; менять порядок alias-resolution |
| `report` | offline join/aggregate текущих predictions и скрытых labels, отчёты | запускать анализ заново или менять raw results |
| reviewer + maintainer | taxonomy/evidence/adjudication после freeze | переписать GT/первый baseline ради улучшения показателей |

Скрипт нужен: многочасовой run и отсутствие CLI resume делают набор ручных команд недостаточно воспроизводимым. Resume реализовать **снаружи**, на границе кейсов; `workflow.Engine` не менять.

Минимальные будущие изменения — eval-скрипт/fixture tests, benchmark-only provenance в `cmd/izyan/vexbench.go`, `eval/README.md`, итоговый summary. `internal/affected`, `evaluator`, `states`, `repository`, `goanalysis`, `knowledge.json` не менять в Task 2.

---

## 3. Acquisition: 30 задач, 28 полных снимков

### 3.1 Каталоги и команды

Все переменные ниже — **абсолютные** пути. `WORKTREE` должен указывать на выделенный shadow worktree; скрипт проверяет branch/root, а не использует текущий каталог оболочки. `BASE` — внешний/dedicated volume, вне обоих checkout.

```bash
: "${WORKTREE:?absolute path to the approved shadow worktree}"
: "${BASE:?absolute external baseline storage outside checkout}"
PIN=80cddeac3132826bfd47227ad59b2e6618a681bd
BENCH="$BASE/dataset/vex-bench-$PIN"
REPOS="$BASE/repos"
OUT="$BASE/runs/external-baseline-1"

python3 "$WORKTREE/eval/vexbench_baseline.py" acquire \
  --worktree "$WORKTREE" --benchmark-dir "$BENCH" \
  --benchmark-sha "$PIN" --repos-dir "$REPOS" \
  --manifest "$BASE/acquisition.json" --fetch-timeout-seconds 1800
```

**Будущий интерфейс**, не существующая команда: сначала реализовать §10 шаг 1.

`acquire` получает dataset через `git init/fetch --depth 1 <полный PIN>/checkout --detach FETCH_HEAD`, проверяет `rev-parse HEAD == PIN`, сохраняет исходный JSONL и SHA256. Source dataset `.git` допустим на control-plane стороне; **снимки анализа — без `.git`**.

Фильтр: `metadata.language` case-insensitive `go`, как `LoadGoTasks`; сохранить file order. Проверки: 30 уникальных task IDs, 28 `(repo_url, full commit_sha)`, 15 repos, 24 CVE, GT counts 7/18/3/2. Контрольный JSONL Go-подмножества живёт вне `REPOS`, никогда внутри snapshot/advisory scope.

### 3.2 Надёжный download contract

Для каждого уникального снимка, последовательно:

1. Проверить полный 40-character `commit_sha` и owner/repo; итоговый layout строго `<REPOS>/<owner>/<repo>/<full-sha>` (`LocateSnapshot`, `snapshot.go:15-75`).
2. Если итоговая запись acquisition manifest имеет `ready`, правильный repo/SHA и совпадающий tree digest, пропустить. Непустой каталог без валидной записи **не** считать готовым.
3. Скачать во временный sibling-каталог, не в конечный path: `git init`, `remote add`, `fetch --depth 1 origin <full-sha>`, `checkout --detach FETCH_HEAD`. Fetch deadline 30 min; повтор acquisition разрешён только до анализа/для ещё не использованных снимков, журналируется.
4. До удаления `.git` проверить checkout HEAD == task SHA; не использовать `git fetch` с коротким SHA.
5. Сохранить symlinks, execute bits, vendor и все файлы. Не выполнять build/release scripts, не удалять vendor, не скачивать submodule history или дополнительные Java/Python snapshots.
6. Удалить только собственный временный `.git`; построить integrity manifest дерева (paths, kind, executable bits, lengths, file digests/symlink targets), записать disk bytes/file count/download time. Отдельно сохранить наличие `go.mod`, `vendor/modules.txt`, release-evidence candidates.
7. После успешной записи manifest atomic rename в конечный layout. Ready-marker/manifest находится **вне** snapshot: служебный файл в дереве изменил бы `ContentHash`.
8. Снять write bits с готового дерева, сохранив execute bits; outputs/cache всегда снаружи. Analyzer canonical hash сверять по существующему `repository.ContentHash` contract (`contenthash.go:16-52`), не вводить второй называемый ContentHash формат. Если Python считает этот hash для resume, нужны parity fixtures существующего t1 encoding.

Поломанный итоговый каталог не удалять автоматически: отказ preflight, quarantine только явно управляемого acquisition-каталога. Чужие файлы/кэши не трогать.

**Vendor ожидаем:** для Kubernetes/Cilium/Moby/Podman отказ `go list -m all` при vendor mode сам по себе не failure: штатный `ExecGoTool.ListModules` возвращает evidence source `vendor/modules.txt`. Preflight требует этот файл, если есть vendor. Не обходить этот путь через `GOFLAGS=-mod=mod`/`go mod download` всего монорепо.

---

## 4. Диск, память, время и остановки

**Решение профиля до первого attempt:** case workers = 1; `--mem-limit 8GiB`; analysis Go 1.26.1; native `darwin/arm64`, CGO=0, build tags пустые. Предшествующий `-j 4` заменяется последовательным исполнением из-за измеренных ограничений и общего memory watchdog, не из-за GT.

* Снимки: около 3.4 GB **[INFERENCE]**; резерв 5 GiB.
* Module/build caches/SDK: резерв не менее 10 GiB **[INFERENCE]**; module cache может расти поверх наблюдённых 4.2 GB, build cache ещё не измерен.
* Raw reports/logs/temp fetch: резерв 5 GiB **[INFERENCE]**.
* Неснижаемый аварийный запас volume: 5 GiB.

**Gate:** до acquisition/run ≥25 GiB свободно на volume `BASE`, рекомендуется ≥40 GiB; проверить каждый отдельный filesystem, если caches/output разнесены. На текущих 10–11 GiB запуск запрещён. Использовать внешний SSD/выделенный volume либо освободить место решением владельца; скрипт не удаляет существующий module cache. `GOMODCACHE`, `GOCACHE`, `GOPATH`, temp и OUT направить на BASE и записать effective paths в приватный manifest.

Для 8GiB analyzer требуется ≥32 GiB физической RAM как **решение preflight**, не гарантия: child `go`/`govulncheck` не ограничены `--mem-limit`. При меньшей RAM заранее пересмотреть весь run profile (например, 4GiB + явная вероятность abstentions/failures), а не менять лимит для отдельных CVE после результатов.

**Время:** измерено лишь `>20 min` на одном Kubernetes. При последовательном профиле резервировать 8–24 h **[INFERENCE]**, не обещать минуты. Case deadline 7200 s — заранее фиксированный censoring/resource policy; верхняя граница 30 deadlines = 60 h плюс preparation. Shallow fetch 9 s на одном снимке не определяет полное время acquisition; сеть, disk I/O, module resolution и indexing разные затраты.

Скрипт измеряет monotonic wall time, process/child RSS где доступно, free disk; сообщает текущий task ID и длительность на stderr. Каждые 30 s проверять диск: при <5 GiB не начинать новые задачи; при <2 GiB аварийно остановить активное process group и зафиксировать `disk_pressure`, не ждать неполной записи файлов. Эти thresholds — решения, не новые analyzer rules.

Timeout/interrupt: subprocess запускается в отдельной process group; SIGINT/SIGTERM останавливает admission, затем SIGTERM всей группе, grace 30 s, далее SIGKILL. Зафиксировать deadline/signal/exit code и partial artifacts. Не считать killed/OOM/ENOSPC implicit `INCONCLUSIVE` или safe: если authoritative prediction отсутствует, outcome `failed` с infrastructure reason. У memory exit 4 могут отсутствовать CLI envelopes: сохраняются attempt failure record и всё, что успело atomic-save.

---

## 5. Release-evidence: ожидания не подгоняются под GT

**Факт:** bare `go` directive — `MinimumGoVersion`, не `ReleaseGoVersion` (`domain.go:127-154`; `repository/service.go:75-111`). Stdlib без release version остаётся pending; analysis SDK или go.mod нельзя использовать вместо target (`affected/resolver.go:87-107,534-547`). При undecidable applicability штатный verdict — `INCONCLUSIVE`, кроме независимого детерминистического доказательства отсутствия применимого компонента (`evaluator/verdict.go:20-77`).

**Решение:** UNKNOWN — честный abstention, не unsafe error и не `correct_safe`. Он ухудшает Safe Clear Rate/recall, остаётся в знаменателе. Ручной review может назвать `honest_abstention`, но не менять prediction/GT/метрики. Не передавать `--release-go-version`, не дописывать toolchain/Dockerfile и не брать version из reference PR.

### 5.1 Явный список проверенных stdlib-кейсов

Исходное опасение про `kubernetes@6d4b94f` нельзя превращать в expected UNKNOWN: pinned snapshot содержит version-file evidence.

| task_id | Advisory/scope | Snapshot-local evidence | Предварительное ожидание по release, **не verdict** |
|---|---|---|---|
| `kubernetes-kubernetes-6d4b94f-CVE-2022-41717` | [GO-2022-1144](https://vuln.go.dev/ID/GO-2022-1144.json): stdlib **и** x/net | [`.go-version:1`](https://github.com/kubernetes/kubernetes/blob/6d4b94f0ab25561be59396fd83fc7bf929fd825d/.go-version#L1) = `1.19.5`; go.mod лишь `go 1.19` | release known `go1.19.5`, source `version-file`; stdlib branch fixed, но это не закрывает x/net branch |
| `aquasecurity-trivy-98e136e-CVE-2024-24791` | [GO-2024-2963](https://vuln.go.dev/ID/GO-2024-2963.json): stdlib | [`go.mod:5`](https://github.com/aquasecurity/trivy/blob/98e136eb7baa2b66f4233d96875c1490144e1594/go.mod#L5) `toolchain go1.22.4` | release known; ниже fixed 1.22.5, applicability разрешима, итог зависит от анализа |
| `gitleaks-gitleaks-f487f85-CVE-2025-22871` | [GO-2025-3563](https://vuln.go.dev/ID/GO-2025-3563.json): stdlib | [`go.mod:5`](https://github.com/gitleaks/gitleaks/blob/f487f853788e1f40b802a8476d98d6a049de6373/go.mod#L5) `toolchain go1.23.4`; Dockerfile golang:1.23 уступает приоритет | release known; ниже fixed 1.23.8; не forced abstention только из-за отсутствия release evidence |

**Подтверждённый список stdlib tasks с UNKNOWN release evidence на исследованном pin: пуст.** Это не утверждение о фактических 30 verdicts: окончательную таблицу строить автоматически из captured advisory scope + `AnalysisCase.Product` после каждого attempt; discovery failures/новые OSV scopes перечислять явно.

Дополнительно:

* `kubernetes-kubernetes-1ee2acb-CVE-2024-24786`: [GO-2024-2611](https://vuln.go.dev/ID/GO-2024-2611.json) относится к **protobuf**, не stdlib; [`.go-version`](https://github.com/kubernetes/kubernetes/blob/1ee2acbb2e92caf28d3ff29121af657f2758ce58/.go-version#L1) = 1.21.7. Bare go 1.19 не доказывает отсутствие evidence.
* `kubernetes-kubernetes-e196d24-CVE-2023-44487`: [`.go-version`](https://github.com/kubernetes/kubernetes/blob/e196d2491087e93bd29f0e5a538aab60667021e3/.go-version#L1) = 1.21.3. Related [GO-2023-2102](https://vuln.go.dev/ID/GO-2023-2102.json) включает stdlib+x/net, но CVE-2023-44487 у него `related`, не alias. `PrepareAdvisory` обходит direct document и aliases, **не** related (`advisory.go:155-185`). На исследованных OSV aliases usable Go entry не подтверждена: возможный abstention — advisory coverage/intake, не UNKNOWN release. Не подсовывать вручную GO-2023-2102 ради этого кейса.
* Minikube CVE-2019-5736 — известный unsupported Go advisory из §6 предыдущего плана, отдельное основание abstention; не записывать как release-version failure.

### 5.2 Источники и фактическая семантика

Порядок текущего кода: `toolchain` → выбранные Dockerfiles `FROM golang:X` → CI `go-version` → version files → выбранные release scripts (`releaseevidence.go:40-57,63-182`). Наличие Dockerfile само по себе недостаточно; записать конкретный совпавший file:line/value и `GoVersionSource`, сверить с фактическим Product.

**Материальный drift старого плана:** текущая реализация принимает Docker tag без patch (`golang:1.22`) и первый найденный матч, не доказывает отсутствие конфликтов (`releaseevidence.go:36-38,85-101,107-135`). Task 2 **не исправляет** это production rule и не заявляет более строгую семантику. Если source неоднозначен, review документирует риск. Если он способен invalidировать safety contract baseline, остановить запуск и вернуть design; не выбирать «нужную» версию вручную.

---

## 6. Один логический run, точная команда, resume

### 6.1 Подготовка frozen executable/environment

Исполнитель собирает бинарник только из одобренного committed worktree после реализации операционной части:

```bash
go -C "$WORKTREE" build -o "$BASE/bin/izyan-baseline" ./cmd/izyan
```

До первого attempt фиксируются full SHA/clean status, binary SHA256/build info, govulncheck binary SHA256/version, dataset/task digest, acquisition manifest, profile/timeout/OS/arch/cgo. Clean env allowlist включает только необходимые PATH/HOME/TMPDIR, `GOENV=off`, `GOTOOLCHAIN=go1.26.1`, `GOWORK=off`, `GOFLAGS=` и внешние `GOPATH/GOMODCACHE/GOCACHE`; целевые GOOS=darwin, GOARCH=arm64, CGO_ENABLED=0. PATH начинается с одобренного Go 1.26.1 и pinned govulncheck, не с checkout или snapshot. Не наследовать `.env`, `VA_*`, LLM credentials, custom knowledge, overlays или scorer paths. `GOWORK=off` — единая заранее объявленная policy, не per-case workaround.

Штатная командная среда сама не обещает full scrub: `toolaudit.Run` добавляет env к ambient (`toolaudit.go:59-66`), а source loader тоже использует ambient (`goanalysis/source.go:279-285`). Внешний wrapper поэтому очищает **собственную** subprocess environment; это operational isolation, без Task 2 production cutover.

### 6.2 Запуск

```bash
python3 "$WORKTREE/eval/vexbench_baseline.py" preflight \
  --worktree "$WORKTREE" --benchmark-dir "$BENCH" \
  --repos-dir "$REPOS" --acquisition "$BASE/acquisition.json" \
  --out "$OUT" --izyan "$BASE/bin/izyan-baseline" \
  --analysis-go 1.26.1 --mem-limit 8GiB --workers 1 \
  --case-timeout-seconds 7200

python3 "$WORKTREE/eval/vexbench_baseline.py" run \
  --manifest "$OUT/run-manifest.json"
```

Wrapper исполняет для каждого task ID **ровно существующую** команду:

```bash
"$BASE/bin/izyan-baseline" eval vex-bench \
  --tasks "$BENCH/benchmark/tasks/vex_bench.jsonl" \
  --repos-dir "$REPOS" \
  --case "$TASK_ID" -j 1 \
  --analysis-go 1.26.1 --mem-limit 8GiB \
  --out "$OUT/attempts/$TASK_ID/raw"
```

`TASK_ID` выбирается по file order manifest, не по label. CLI получает только один выбранный case; OUT не повторяется между кейсами, чтобы их `metrics.json` не перезаписывались. Итоговые all-30 metrics считаются отдельно; усреднять 30 однокейсовых rates запрещено.

**Решение:** 30 subprocess invocations — один логический Baseline 1, не 30 повторов. Такой cutover сохраняет штатный analyzer и изолирует утрату envelopes при kill одним case вместо всех 30. В manifest явно записать `execution_mode=case_isolated`, workers=1, cli_j=1. Не выдавать этот timing за результат `-j 4`.

### 6.3 Ledger и resume

Atomic ledger: один record на task ID, состояния `pending → running → finalized`; запись `running` fsync/atomic-save до старта процесса. Запись содержит frozen fingerprint (binary/adapter/task/snapshot/env/profile), start/end/exit/signal, raw prediction path/digest либо failure reason, ссылки на partial artifacts. После finalized record никогда не overwrite.

```bash
python3 "$WORKTREE/eval/vexbench_baseline.py" run \
  --manifest "$OUT/run-manifest.json" --resume
```

`--resume` — **новый wrapper flag**, не флаг Izyan:

* валидировать fingerprint и digests всех finalized records; существования prediction.json недостаточно;
* пропускать **все** finalized outcomes, включая `INCONCLUSIVE`, wrong и failed; не перезапускать неудобные результаты;
* если CLI уже закончил и raw packet полон, но ledger commit не случился, разрешён recovery этой же первой попытки без повторного анализа;
* `running` без полного packet после interruption → finalize как infrastructure `failed`, сохранив partial bytes; продолжить только ранее `pending` задачи;
* не восстанавливать authoritative verdict из полупройденного state; не синтезировать analyzer `prediction.json` при его отсутствии;
* retry failed/timeout case — отдельный diagnostic/regression attempt после freeze, вне Baseline 1 и вне его метрик;
* изменение code/config/snapshot fingerprint — не resume; остановиться, не overwrite прежний run.

Внешние DB/OSV могут измениться за паузу: сохранить resume episodes и per-case observed input identities; не утверждать единую frozen network snapshot. Новые verdicts старых finalized кейсов не получать. Если требуется строго один DB snapshot для всех 30, это отдельный preparation prerequisite и возврат к design, не скрытый live fallback.

---

## 7. Provenance: точные поля и автоматическое получение

### 7.1 Где хранить

```
<OUT>/run-manifest.json               # frozen config до анализа
<OUT>/acquisition.json                # копия/ссылка + digest исходного manifest
<OUT>/ledger/<task-id>.json            # состояние first attempt
<OUT>/attempts/<task-id>/attempt.json  # exit/resources/identity
<OUT>/attempts/<task-id>/raw/
    provenance/osv-fetches.jsonl
    provenance/osv/<sha256>.json       # фактически fetched direct/alias bytes
    <task-id>/prediction.json
    <task-id>/advisory/<resolved>.json # только один файл, если prepared
    <task-id>/<caseID>.json
    <task-id>/<caseID>/report.json
    <task-id>/<caseID>/report.md
    metrics.json
    scoring/cases.jsonl
<OUT>/provenance.json                 # final actual all-30 provenance
<OUT>/raw-checksums.json              # freeze boundary
<OUT>/scoring/...                     # all-30 joins и review
```

Это адаптация §39–40 к **реальному** Task 1 layout, а не обещание отсутствующих `input.json/snapshot.json/deterministic/` файлов. На каждую строку итогового scorer-а сохранить artifact refs и SHA256. Raw prediction/report files не копировать многократно ради prettier layout.

### 7.2 Обязательный provenance schema

| Поля | Автоматический источник |
|---|---|
| `schema_version`, `run_id`, `baseline_name`, `run_started_at_utc`, `run_finished_at_utc`, `resume_episodes` | wrapper UTC RFC3339 + monotonic duration |
| `izyan_commit_sha`, `izyan_dirty=false`, `izyan_binary_sha256`, `izyan_build_info`, `task1_base_sha`, `change_composition` | git строго `-C WORKTREE`, `go version -m`, binary digest |
| `vexbench_commit_sha`, `tasks_sha256`, `selected_task_ids`, total/snapshot/repo/CVE counts, category counts | pinned checkout + JSONL + acquisition manifest |
| `adapter_version`, `adapter_source_digest`, `orchestrator_version`, `orchestrator_sha256` | текущая literal adapter version и digest затронутых eval source files/script |
| `go_version`, `analysis_go_requested`, `analysis_go_actual`, `analysis_mode`, `go_binary_sha256`, `go_build_info` | actual go executable/version; CLI metrics; Product.GoVersion |
| `govulncheck_version`, `govulncheck_binary_sha256`, `govulncheck_build_info`, `govulncheck_version_output` | **тот же** executable из PATH: `govulncheck -version`, `go version -m` + digest |
| `govulncheck_db_url`, `govulncheck_db_last_modified`, `govulncheck_config_sha256`, `govulncheck_db_mode=live_observed`, `govulncheck_per_case` | config message фактически сохранённого raw govulncheck JSON в EvidenceGovulncheck; DBInfo — дополнительный raw источник |
| `osv_fetches`: task/requested id/url/start/finish/status/body_sha256/body_ref/chosen; chosen advisory source/resolved id/SHA256/modified | benchmark-only HTTP recorder ниже; existing `AdvisoryResult` |
| `snapshots`: external SHA, canonical content hash, integrity manifest/digest, bytes/file count, immutable flag | acquisition; captured Product/Prediction; parity с repository.ContentHash |
| `release_go_version`, `go_version_source`, `release_evidence_file_line_value` per case | captured Product + сохранённые snapshot evidence candidates; сверка с actual discovery priority |
| `host_os`, `host_arch`, `target_goos`, `target_goarch`, `cgo_enabled`, `build_tags`, `goenv`, `gotoolchain`, `gowork`, `goflags`, module/vendor mode, clean env allowlist | effective env + captured Product/build/tool inputs; не подменять actual значением host по умолчанию |
| `argv`, `cli_j`, `workers`, `mem_limit`, deadlines, cache dirs, resource samples, per-case wall/exit | wrapper + raw envelopes |
| `knowledge_digest`, доступные fix/patch URLs/evidence digests | source digest встроенной knowledge; фактически сохранённые EvidenceFixDiff; отметить truncation |
| `model=null`, `model_endpoint_revision=null`, `prompt_version=null`, `llm_calls=0`, `tokens=0`, `llm_cost=0` | deterministic profile; null с причиной `not_applicable` для §25 model fields, проверка Usage |
| `prior_exposure`, `limitations`, отсутствующие инструменты/данные | preparation ledger и actual outputs, без догадок |

DB timestamp — не digest полного DB. Raw govulncheck config digest — digest **identity message**, не всего database content. Если govulncheck не запускался из-за early outcome, per-case `used=false`, причина; требовать несуществующий raw config нельзя. Если запускался, но DB identity не извлечена, записать конкретный provenance defect, не придумывать version.

### 7.3 Что необходимо реализовать до baseline

Существующая оболочка не может достоверно восстановить точное время OSV fetch по `advisory.modified`, file mtime или повторному HTTP-запросу. **Решение:** benchmark-only callback внутри `runVexCase`: обернуть существующий `vexbench.FetchOSV` и передать wrapper как `Fetcher` в `PrepareAdvisory` вместо nil (`advisory.go:62-65,132-135`; `vexbench.go:196-199`). Обёртка:

1. записывает start/finish UTC, requested ID и ошибку/статус;
2. сохраняет **тот же** возвращённый body и SHA256 прежде, чем вернуть его resolver-у;
3. записывает successful, rejected и alias fetches, не только selected document;
4. пишет в control-plane `raw/provenance`, **не** в singleton `advisory/` и не в snapshot;
5. не меняет alias order/usability/outcome и не делает дополнительный fetch;
6. versioned additive metadata schema получает новый adapter version; baseline SHA фиксируется **после** этого eval-only commit.

Если capture не может сохранить metadata из-за I/O, preparation/run не заявляет полноценный provenance: failure record/остановка admission, не silent success. При невозможности получить HTTP status из существующего Fetcher записывать observed success/error и сохранить исходную transport error; не выдумывать response status.

Это единственное необходимое изменение benchmark runner; **никаких изменений production analyzer semantics**. Если scope запретит даже eval-only capture, критерий exact automatic OSV fetch provenance недостижим существующим CLI: вернуть design, а не подставить время run.

Полностью offline analysis не обещается: coverage query, patch fetch и module resolution могут оставаться сетевыми (§2.7 предыдущего плана). Сохранить их реально доступные identity/evidence и ограничения. Truncated patch evidence (`rootcause/rootcause.go:59-69`) не называть полным frozen patch dump.

---

## 8. Freeze, metrics и disagreement/report

### 8.1 Freeze boundary

После first attempts всех 30:

1. Проверить ledger: 30 уникальных finalized records; либо raw authoritative prediction, либо явная infrastructure-failure запись с отсутствующим prediction и partial refs.
2. В режиме offline агрегировать по исходным pinned labels; сохранить `scoring/cases.jsonl`, `metrics.json`, `compatibility-metrics.json`, final provenance.
3. Построить checksums всех raw/aggregate/provenance/ledger файлов и `baseline-frozen.json` с UTC/run ID/manifest digest; raw сделать read-only, создать внешнюю архивную копию/digest и custody record.
4. Только затем разрешить ручное чтение GT/reference PR для review. Review files отдельные, raw-checksums не пересчитываются ради исправления результата.

При раннем advisory unsupported или failure AnalysisCase/report может отсутствовать. Это нормально только с явным missing-artifact reason, captured fetch packet и attempt envelope. Полный fake report не генерировать; существующие raw path поля не считать доказательством наличия файла.

### 8.2 All-30 safety-aware metrics

Источник семантики — `Classify/Compute` (`score.go:83-172`), независимая fixture parity с `score_test.go:59-109`; не создавать несовместимый scorer.

| Метрика | Числитель / знаменатель |
|---|---|
| False-Safe count | GT exploitable + verdict NOT_AFFECTED/NEPF |
| False-Safe rate | false_safe / **7**; optional population rate /30 только с отдельным именем |
| Safe Clear Rate | correct_safe / **23** |
| EXPLOITABLE recall | correct_exploitable / **7** |
| INCONCLUSIVE rate | abstain / **30** |
| Completion | (30 - failed) / **30**; INCONCLUSIVE — completed abstention, не safe |
| Status accuracy | status_correct / **30**, abstain/failed не становятся correct |
| Safety-aware status precision/recall/F1 | positive=EXPLOITABLE; TP/7 recall, precision TP/(TP+FP); missed exploitable, включая abstain/failed, входят в recall denominator |
| Reason correct | status_correct **и** projected category == GT category, отдельно /30 |

Сохранить counts, denominators, confusion table со столбцами `positive/safe/abstain/failed`, не только rates. `status_correct` и `reason_correct` добавить в **per-case scorer rows**, а не только aggregate counters. Верный status при неправильной причине — review case.

Сохранить LLM/tool calls, tokens/cost (LLM=0), per-case duration и total elapsed, среднее по 30 + распределение/p95; missing usage обозначать null/missing, не выдавать отсутствующую инструментальную информацию за 0. LLM cost=0 не означает нулевой стоимости CPU/оператора.

### 8.3 Compatibility отдельно

`INCONCLUSIVE → uncertain` разрешён **только** compatibility projection; `uncertain` → not_exploitable в upstream parser ([result_parser.py:7-26,99-107](https://github.com/steven1518/vex-bench/blob/80cddeac3132826bfd47227ad59b2e6618a681bd/src/evaluate/result_parser.py)). Не переносить эти negative successes в safety-aware metrics.

`scoring/compatibility-metrics.json`: category projection/version, binary accuracy/precision/recall/F1, justification macro-F1 и per-class supports/confusion matrix. Macro-F1 по четырём GT-present категориям pinned Go subset, не случайному числу встреченных predictions; zero_division=0. Это соответствует [pinned metrics.py:126-169](https://github.com/steven1518/vex-bench/blob/80cddeac3132826bfd47227ad59b2e6618a681bd/src/evaluate/metrics.py#L126-L169).

Различать две политики failed: Task 1 projection для пустого verdict — uncertain; **официальный scorer** missing prediction считает FAILED, wrong accuracy/FN, а не успешным not_exploitable ([metrics.py:87-124](https://github.com/steven1518/vex-bench/blob/80cddeac3132826bfd47227ad59b2e6618a681bd/src/evaluate/metrics.py#L87-L124)). Основной публикационный compatibility view сохраняет failed как missing/FAILED; raw projected uncertain остаётся в кейсовой записи. Если публикуется legacy uncertain-on-failed projection, назвать её отдельно и показать failed_count, не называть точным official score.

Официальный Agent harness/Docker/Plain Agent в этом Task не запускать; scoring parity — fixture/reference computation, не Task 3.

### 8.4 Disagreement artifacts (§44)

`scoring/disagreements.jsonl` + `scoring/disagreements.md`: в Task 2 comparator `vexbench_ground_truth`, а Agent/Shadow fields — `not_run`, не выдуманные reasoning. Включить все wrong/abstain/failed и correct status + wrong reason; отдельные строки review могут оспаривать taxonomy при верном binary verdict.

Минимальная запись:

```json
{
  "run_id": "external-baseline-1",
  "task_id": "<pinned-task-id>",
  "comparator": "vexbench_ground_truth",
  "ground_truth": "<original-label>",
  "ground_truth_category": "<original-category>",
  "izyan_verdict": "<raw-verdict-or-null>",
  "izyan_reasoning": "<raw-reason>",
  "status_correct": false,
  "reason_correct": false,
  "scoring_outcome": "abstain",
  "agent_reasoning": null,
  "comparison_limitations": ["Agent modes not run in Task 2"],
  "artifact_refs": [{"path": "<relative-path>", "sha256": "<actual-digest>"}],
  "evidence_ids": ["<existing-evidence-id>"],
  "first_point_of_divergence": {"stage": "CHECK_AFFECTED", "explanation": "<review-supported>"},
  "root_cause_difference": "<supported difference or not_available>",
  "exploit_model_difference": "<supported difference or not_available>",
  "taxonomy_ref": "failure-taxonomy.jsonl#<task-id>"
}
```

GT dataset не содержит reasoning сам по себе: review после freeze может прочитать reference PR и приложить pinned URL/цитату; не приписывать GT рассуждения без источника.

Основная таблица summary следует §43: заполнена только колонка **Current Izyan**; Plain Agent/Shadow/Hybrid = «не запускался (Task 3+)». Отдельные blocks safety-aware и compatibility, category supports, completion/resource failures, release-evidence abstentions, exposure/provenance limitations и artifact checksum.

---

## 9. Failure taxonomy: кто, когда и как

**Решение:** автор запуска подготавливает автоматически список review-needed; maintainer/назначенный независимый reviewer читает raw packet **после freeze**, назначает одну primary category; maintainer утверждает записи и спорные safety/GT cases. LLM не является авторитетным reviewer/verdict source в Task 2.

Review-required = outcome не `correct_safe/correct_exploitable` **или** `reason_correct=false`. То есть review включает честные abstentions, infrastructure failures и status-correct/reason-wrong, а не только binary mistakes.

Фиксированный enum, без новых названий:

```
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

Файл `scoring/failure-taxonomy.jsonl`, ровно одна финальная запись на каждый review-required task:

```json
{
  "run_id": "external-baseline-1",
  "task_id": "<pinned-task-id>",
  "scoring_outcome": "abstain",
  "status_correct": false,
  "reason_correct": false,
  "category": "ENVIRONMENT_MISREAD",
  "disposition": "honest_abstention",
  "subcategory": "release_toolchain_unknown",
  "reviewer": "<public-reviewer-id>",
  "reviewed_at_utc": "<actual-RFC3339>",
  "approved_by": "<maintainer-id>",
  "baseline_manifest_sha256": "<frozen-digest>",
  "prediction_ref": {"path": "<relative-path-or-null>", "sha256": "<digest-or-null>"},
  "case_ref": "<relative-persisted-case-or-null>",
  "report_ref": "<relative-report-or-null>",
  "evidence": [{"id": "<existing-ID-or-null>", "path": "<relative-path>", "quote": "<short-grounded-quote>"}],
  "explanation": "<why this category follows from evidence>",
  "first_point_of_divergence": "<stage and fact>",
  "needed_information_or_general_change": "<specific, not a case-specific fix>"
}
```

Это schema-пример, не реальная разметка или готовый вывод.

`disposition`: `analyzer_defect`, `honest_abstention`, `infrastructure_failure`, `benchmark_ambiguity`. Он отличает unresolved от ошибки, но **не** заменяет §45 category и не меняет score. UNKNOWN release обычно `ENVIRONMENT_MISREAD` + `honest_abstention` (недостающие environmental facts), unsupported advisory/timeout/OOM — `TOOL_SCOPE_INCOMPLETE` с подробной subcategory; `OTHER` только с явным explanation. `LLM_REASONING_ERROR` в deterministic run не назначать без evidence вызова LLM — иначе проблема attribution.

Workflow каждого кейса:

1. открыть original prediction, persisted case/affected/claims/negative verification/tool executions;
2. подтвердить scope, release source, выбранный advisory/digest, build/vendor mode;
3. найти **первую** расходящуюся предпосылку/стадию, а не только final verdict;
4. проверить original GT/reference evidence после freeze; несогласие с label — candidate `BENCHMARK_AMBIGUITY`, не автоматическое оправдание;
5. выбрать один enum + disposition + actual evidence refs, записать manual explanation;
6. reviewer/maintainer утвердить, validate-review проверить coverage/enum/paths/digests;
7. сгруппировать причины в summary: требующий generic proof/tool defect, недоступный deployment/release context, infrastructure, principled abstention.

При `false_safe>0`: baseline сохраняется, Task 2 safety gate **не проходит**. Эскалировать конкретные raw cases; будущий generic fix + adversarial counterexample — отдельная задача и regression run (§50). Нельзя добиться gate путём retry/смены expected/category.

**Конфликт старого плана:** §9 предыдущего плана допускает исключение ambiguity cases из знаменателя gate. Этот план сохраняет оригинальную all-30 таблицу и gate; возможный adjudicated sensitivity report — отдельный файл с excluded IDs, evidence, reviewer approval и своими denominators, не замена Baseline 1 и не объявление исходного false_safe=0. Без этого baseline можно улучшать разметкой постфактум.

---

## 10. Реализация по зависимостям — чек-лист

### Шаг 1. Операционный wrapper, без реальных baseline tasks

- [ ] `eval/vexbench_baseline.py`: CLI/contracts из §2–7; acquire atomic staging/dedup/full-SHA; paths outside checkout; run ledger/process-group cancellation/resume/offline report.
- [ ] Малые synthetic fixture tests: 75→30 filter/dedup counts; неполный download не ready; только полноценная identity позволяет resume; finalized abstain/failed тоже skip; corrupt/missing prediction → failed; interrupted first attempt не rerun; hidden labels не в snapshot; disk gate; timeout process group; aggregate denominators/status-vs-reason.
- [ ] Canonical snapshot hash parity/fixture при использовании Python t1 encoding; иначе использовать существующий Go contract, не создать второй формат с тем же именем.
- [ ] Docs `eval/README.md`: wrapper flags vs actual CLI, environment/resources/resume semantics.

### Шаг 2. Автоматический provenance до первого attempt

- [ ] Benchmark-only fetch recorder §7.3 через существующий Fetcher; successful/rejected/alias bodies/timestamps outside advisory dir; новый metadata/adapter version.
- [ ] Fixture tests: captured bytes == used bytes; rejected fetch retained; timestamps не `modified`; singleton advisory dir; recording не меняет verdict/category/outcome; capture I/O failure явный.
- [ ] Автоматические tool versions/actual govulncheck config/Product/env/digests; null/used=false для early outcomes, missing input identity с explicit reason.
- [ ] Зафиксировать commits до run; review diff: никаких generic analyzer semantic edits/case exceptions.

### Шаг 3. Проверки операционной части, один раз после её сборки

- [ ] Исполнитель, не автор этого плана: запустить synthetic wrapper tests и относящиеся Go adapter tests; build pinned executable. Не использовать реальные VEX tasks как тест wrapper-а.
- [ ] При необходимости общих Go quality gates выполнить их один раз после всех changes согласно AGENTS; существующий полный корпус не гонять повторно в каждой фазе. Task 1 regression evidence приложить; если общий verification уже выполнен и production не менялся, явно указать unchanged/previous evidence.

### Шаг 4. Acquisition/preflight

- [ ] Устранить текущий disk blocker, выбрать volume/cache paths; утвердить frozen resource profile до просмотра baseline.
- [ ] Выполнить `acquire`; 28/28 verified immutable snapshots, 30 Go IDs; record measured bytes/time.
- [ ] Vendor modules.txt/preflight symlink/path replacements; не исправлять snapshot.
- [ ] `preflight` создаёт immutable run-manifest; pins/binaries/provenance/clean env/release candidates/exposure registry проверены; OUT новый/пустой.

### Шаг 5. Единственный Baseline 1

- [ ] Выполнить wrapper `run`; при interruption только ledger resume согласно §6.3.
- [ ] Не менять code, resource profile, snapshots или labels по мере получения исходов.
- [ ] Сохранить 30 first-attempt records, включая явные failed/missing-artifact outcomes.

### Шаг 6. Freeze и report

- [ ] Offline aggregate fixed denominators, all-30 cases/provenance/checksums/custody, freeze перед manual review.
- [ ] Заполнить taxonomy/disagreements каждого review-required case; maintainer approval.
- [ ] Public summary: safety gate, metrics numerator/denominator, release/evidence/resource limitations, distinct compatibility, exposure, links/digests.
- [ ] Task 2 outcome назвать раздельно: baseline captured / safety passed-or-blocked / review complete. Не пересчитывать первый baseline после review.

---

## 11. Git, объём и приватность

**В этой текущей задаче** коммитится только этот план:

```bash
git -C "$WORKTREE" add -- docs/dev/plans/2026-10-07-vexbench-baseline-plan.md
git -C "$WORKTREE" commit -m "docs(eval): plan reproducible VEX-Bench external baseline"
```

Прежде чем commit, убедиться, что index не содержит чужих staged changes; не очищать их destructive командой. Никаких git операций в основном checkout, push/rewrite history запрещены без указания владельца.

**В реализации Task 2** допустимые versioned files:

* `eval/vexbench_baseline.py`, synthetic fixture tests;
* benchmark-only provenance diff `cmd/izyan/vexbench.go` (+ tests только в eval/CLI scope);
* `eval/README.md`, компактный public `eval/baselines/vexbench/external-baseline-1.md`;
* при необходимости компактная public machine-readable summary без case source dumps/приватных путей.

Сначала `feat(eval): add reproducible VEX-Bench baseline orchestration and provenance`, затем после сохранения baseline `docs(eval): record VEX-Bench external baseline 1` — Conventional Commits (`CONTRIBUTING.md:69-87`). План-приёмка сейчас не является коммитом результатов.

**Не в git:** external snapshots, clone `.git`, module/build caches/SDK/binaries, raw OUT/OSV dumps, full AnalysisCase/reports/logs, scorer GT/review JSONL, local absolute paths, credentials. Даже публичные OSV bytes для этого массового run держать вместе с внешним audit packet, не добавлять тысячи дампов. Large/label-bearing review artifacts могут храниться в выбранном maintainer artifact store; public summary содержит только разрешённые public task IDs, pins, агрегаты и архив/manifest digests. Locator с локальным путём — только приватный custody manifest.

`.gitignore` сейчас не гарантирует исключение произвольного `vexbench-out` (`.gitignore:1-26`); поэтому обязательны explicit external OUT и path guard, а не надежда на ignore. В корне checkout не создавать даже временные `.md/.out` или binary; build target находится на BASE.

---

## 12. Acceptance Task 2 — проверяемые критерии

### A. Baseline captured

- [ ] PIN и JSONL SHA256 сохранены; выбранные IDs точно 30/28/15/24, original GT supports 7/18/3/2.
- [ ] 28 снимков проверены по полным SHA/integrity, без `.git`, без mutations, без pruning vendor; environment/profile единые и frozen.
- [ ] Ровно 30 first-attempt ledger records; каждый имеет prediction + фактически существующие persisted artifacts либо конкретный failure/missing-artifact reason и partial refs. Не утверждать «30 completed», если `failed>0`.
- [ ] Completion явно `n/30`; штатное 30/30 желательно, иначе каждый failed ID/exit/resource cause перечислен. Все кейсы остаются в metrics denominator.
- [ ] Полный §7 provenance, actual OSV bytes/time/digests и govulncheck tool/DB identity, release sources и effective GOOS/GOARCH/CGO; отсутствующие non-used поля имеют причину, а не fake values.
- [ ] Immutable raw/checksum/custody packet сохранён **до** review; resume не перезаписал/повторил first attempts.

### B. Safety gate

- [ ] `false_safe == 0` в оригинальном all-30 view. Иначе baseline captured, но safety gate/task acceptance blocked с escalation; raw result не исправляется.
- [ ] INCONCLUSIVE остаётся abstention; UNKNOWN release case не зачитывается как correct_safe, не получает forced target version.
- [ ] Нет benchmark-specific exceptions в production, custom knowledge/deployment inputs или edits snapshot (§50). Code diff composition опубликован; generic prerequisites baseline SHA раскрыты.
- [ ] Existing regression safety не регрессировала; Task 1 evidence или выполненные финальные checks указаны честно, без заявления о непроводившемся повторном запуске.

### C. Reporting/review

- [ ] Safety-aware metrics: числители/denominators **30 / 7 / 23**, status_correct и reason_correct раздельно; category counts, completion/abstain/failed, timing/usage.
- [ ] Compatibility отдельный named view с projection/failure policy, binary metrics/macro-F1/supports; не используется вместо safety gate.
- [ ] Taxonomy одной фиксированной категории + evidence + approved disposition для **каждого** non-correct или reason-wrong кейса; zero uncovered review rows.
- [ ] Disagreements содержит first divergence/evidence/root-cause/model distinctions либо объяснимый not_available, не только verdict mismatch.
- [ ] §43 table заполнена для Current Izyan, Agent columns `not run`; public summary без private paths/больших дампов; исходный baseline не пересчитан.

False-Safe=0 само по себе не завершает Task 2: 30 abstentions при нулевом false-safe — сохранённый слабый baseline, который должен быть виден в completion/clear/recall/review, а не объявлен успехом качества.

---

## 13. Blast radius

| Область | Изменение | Проверка исполнителя |
|---|---|---|
| `eval/` operations | download/ledger/resume/report/resources | synthetic fixture tests; no real baseline reruns |
| benchmark CLI | observational OSV provenance, additive versioned schema | adapter/CLI tests: bytes/outcomes/label isolation unchanged |
| `analyze/scan/remediate`, domain/proof rules | **не меняются** | diff review; существующая regression evidence |
| snapshots/vendor | readonly, полный layout/bytes | acquisition integrity + before/after digests; vendor fallback source |
| hidden scoring | новые joins/review только вне analyzer roots, после freeze | path/digest/coverage checks |
| disk/host | внешний volume/cache budget, sequential worker | statvfs/RAM/resource gate; explicit pause/failure policy |
| docs | план сейчас; eval usage/summary при реализации | актуальные flags/evidence и privacy review |

---

## 14. Неизвестные и условия возврата к design

| ID | Неизвестное/риск | Приоритет | Владелец / закрытие / ограничитель |
|---|---|---|---|
| U-B01 | Реальный общий disk/cache/report объём | P1 | исполнитель до запуска: ≥25 GiB gate, рекомендовано 40; live free-disk thresholds; не весь module download |
| U-B02 | RAM и child RSS на монорепо | P1 | исполнитель: ≥32 GiB профиль, sequential; measured samples; watchdog не выдаётся за process-tree cap |
| U-B03 | Multi-hour runtime и full first-attempt packet при interrupt | P1 | wrapper fixture tests до run; 2h declared case deadline; ledger resume, interrupted first attempt failed |
| U-B04 | Полнота точного OSV fetch provenance | P1 | eval-only Fetcher recorder до run; без него не запускать baseline с заявленным complete provenance |
| U-B05 | Честный actual UNKNOWN stdlib list | P1 | acquisition candidates + actual Product/advisory manifest; подтверждённые строки §5, не вывод из go directive |
| U-B06 | Live external data drift / полная воспроизводимость | P1 | per-case actual identity+digests/episodes, disclosed no-offline guarantee; strict frozen DB потребует нового design |
| U-B07 | Различие snapshot-local release policy и старой exact/conflict спеки | P1 | сохранить actual behavior/risk; при safety-contract violation — stop/design, не Task2 case fix |
| U-B08 | Dataset ambiguity и host-native platform vs deployment | P2 | post-freeze review, primary denominators immutable, supplemental adjudication отдельно |
| U-B09 | Task1 smoke/prior exposure | P2 | preparation exposure register; не заявлять полностью unseen 30 |

**Контракт передачи исполнителю:** соблюдай решения, допущения и ограничители этого плана. Если факт опровергает P1/P0 assumption или меняет контракт/данные/доверительные границы, остановись, сохрани raw bytes/ledger, верни задачу на `design-unknowns`.

Возврат обязателен, если:

* snapshot SHA/tree не совпадает, path/symlink replace выходит за scope или labels оказываются в analyzer-visible inputs;
* current host нельзя подготовить без сокращения benchmark или опасного отключения memory/disk guards;
* wrapper resume для продолжения требует нового verdict уже finalized кейса;
* provenance требует изменения production resolver/proof rules либо falsified timestamps/versions;
* release-discovery conflict способен дать unsafe baseline applicability; не patch snapshot, не choose GT-compatible version;
* для улучшения completion предлагаются per-CVE timeout/memory/module-pruning/target-platform changes после результатов;
* появляются case-specific production fixes или желание заменить исходную таблицу adjudicated denominator.

При остановке записать обнаруженный факт+источник, опровергнутое решение, affected scope, выполненные изменения/commit SHAs и безопасное состояние OUT. Baseline 1 сохранённые записи не удалять и не «перезапускать начисто».

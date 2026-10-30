# Agent-7 (A-series) — выбор базы и аудит переиспользования

- **Статус:** accepted (PR-0, задача A0).
- **Дата:** 2026-10-10.
- **Спека:** [agent-driven-evidence-assessment-design-v2](../specs/2026-10-10-01-agent-driven-evidence-assessment-design-v2.md) (§1, §2, §10, §11).
- **План:** [agent-driven-evidence-assessment-plan-v2](../plans/2026-10-10-02-agent-driven-evidence-assessment-plan-v2.md), секция `### A0` и §8 (PR-0).
- **Evidence pack:** `.superpowers/sdd/2026-10-10-02-agent-driven-evidence-assessment-plan-v2/evidence-a0.md`;
  raw transcript — `a0-transcript.md` в том же каталоге.
- **Связь с ADR-001** (спека §10.3): реализует `same repo, separate experimental lane` — один репозиторий,
  отдельный исследовательский контур, не второе приложение и не замена `izyan analyze`. Все пункты
  [architecture-decisions.md](architecture-decisions.md) (D1–D16) продолжают действовать; настоящий документ
  дополняет их на уровне выбора базы и инвентаризации контуров и ничего из D1–D16 не отменяет.

## 1. Идентичность базы

Снято прямым выполнением команд в worktree `${IZYAN_WORKTREE}` (повторно проверено автором документа
на дату записи). **path_resolution:** `${IZYAN_WORKTREE}` — shadow worktree / корень текущего
репозитория; `${IZYAN_MASTER_WORKTREE}` — worktree ветки `master`; `${VEXBENCH_DURABLE_ROOT}` —
корень внешнего eval-харнесса. Конкретные локальные значения не коммитятся (правило «приватные
локальные пути не коммитить»): они зафиксированы в gitignored-транскрипте
`.superpowers/sdd/2026-10-10-02-agent-driven-evidence-assessment-plan-v2/a0-transcript.md` и в
manifest харнесса, не в этом документе.

| Параметр | Значение |
|---|---|
| Shadow worktree | `${IZYAN_WORKTREE}` |
| Shadow branch / HEAD | `feat/shadow-analyzer-agent` / `a65056a679aa88a4e5037981b7558dff45d9bc1c` (`docs(task6): eval/README §12 + gap-analysis B40`, 2026-10-10 04:35:44 +0300) |
| Master worktree | `${IZYAN_MASTER_WORKTREE}`, HEAD `2955331` |
| Merge-base | `c97fb926916d4431c812e9700e4504b084cfe87e` (`git merge-base master feat/shadow-analyzer-agent`) |
| ahead/behind | `2	109` (`git rev-list --left-right --count master...feat/shadow-analyzer-agent`: 2 master-only, 109 shadow-only) |
| Размер lane-diff | `198 files changed, 60014 insertions(+), 97 deletions(-)` (`git diff --shortstat c97fb926..a65056a`) |

Master-only коммиты (присутствуют в `master`, отсутствуют в lane; вывод `git log --left-only --oneline master...feat/shadow-analyzer-agent`):

- `9a4fed8` `feat(report,risk): split human report from technical audit, forbid triage escalation, honest AI-usage`
- `2955331` `fix(report,risk): host-independent paths, honest AI attribution, real severity provenance`

Dirty state (`git status --porcelain`): **только три untracked документа**, tracked-модификаций нет:

- `docs/dev/specs/2026-10-10-01-agent-driven-evidence-assessment-design-v2.md`
- `docs/dev/plans/2026-10-10-02-agent-driven-evidence-assessment-plan-v2.md`
- `docs/dev/specs/2026-10-10-task7-compact-proof-contract-spec.md`

Полный diff сохранён артефактом `.superpowers/sdd/2026-10-10-02-agent-driven-evidence-assessment-plan-v2/shadow-vs-master.diff`
(2 827 322 байта, sha256 `747a43b5573f3934ee3813ec5606a39abb644e88c2cbeb6ffbe63310055fc555`; путь gitignored —
`git check-ignore` возвращает exit 0). Точная команда воспроизведения:

```bash
git diff c97fb926916d4431c812e9700e4504b084cfe87e..a65056a679aa88a4e5037981b7558dff45d9bc1c > shadow-vs-master.diff
```

Автор документа пересчитал: `git diff c97fb926916d4431c812e9700e4504b084cfe87e..a65056a679aa88a4e5037981b7558dff45d9bc1c | shasum -a 256`
даёт тот же `747a43b5…fc555`, поэтому артефакт — именно diff merge-base..HEAD.
Numstat: `.superpowers/sdd/2026-10-10-02-agent-driven-evidence-assessment-plan-v2/shadow-vs-master.numstat`.

**Ничего не было очищено/сброшено:** ни `git clean`, ни `git reset`, ни `checkout` по состоянию на дату записи
не выполнялись; untracked-документы сохранены.

## 2. Транскрипт команд

Все команды выполнялись из корня `${IZYAN_WORKTREE}` (см. `path_resolution` в §1).
Блок (a) — оркестраторский raw transcript (`a0-transcript.md`, 2026-10-10T15:51:51Z);
блок (b) — повторная проверка автором документа (2026-10-10).

### (a) Оркестраторский сбор идентичности

```bash
$ git rev-parse --short HEAD
a65056a679aa88a4e5037981b7558dff45d9bc1c
$ git status --porcelain
?? docs/dev/plans/2026-10-10-02-agent-driven-evidence-assessment-plan-v2.md
?? docs/dev/specs/2026-10-10-01-agent-driven-evidence-assessment-design-v2.md
?? docs/dev/specs/2026-10-10-task7-compact-proof-contract-spec.md
$ git worktree list
${IZYAN_MASTER_WORKTREE}         2955331 [master]
${IZYAN_WORKTREE}  a65056a [feat/shadow-analyzer-agent]
$ git merge-base master feat/shadow-analyzer-agent
c97fb926916d4431c812e9700e4504b084cfe87e
$ git rev-list --left-right --count master...feat/shadow-analyzer-agent
2	109
$ git diff --shortstat c97fb926..a65056a
 198 files changed, 60014 insertions(+), 97 deletions(-)
```

### (b) Верификация на `a65056a`

Запуск оркестратора (зафиксирован в evidence pack §2, raw-выводы там же):

```bash
$ gofmt -l .
# (пустой вывод)
$ go vet ./...
# (чисто, exit 0)
$ go test ./...
# all packages ok, exit 0, ~89 s wall
# (internal/goanalysis 83.6 s, internal/states 63.0 s, internal/evidencetools 6.3 s,
#  internal/readgate 3.5 s, internal/repository 7.7 s, cmd/izyan 16.8 s)
```

Повторный прогон автором документа на дату записи — фактические выводы приведены в §9
(«Результаты PR-0 финальной проверки»); итог идентичен: `gofmt -l .` пусто, `go vet ./...` чисто,
`go test ./...` — все пакеты `ok`, exit 0.

Целевое сравнение verdict-распределения shadow vs master (оба бинаря пересобраны из своих HEAD:
`/tmp/izyan-shadow`, `/tmp/izyan-master`; прогон оркестратора, evidence pack §2):

```bash
$ /tmp/izyan-shadow eval --corpus eval/corpus.json -j 4 --json /tmp/shadow-eval.json
$ /tmp/izyan-master eval --corpus eval/corpus.json -j 4 --json /tmp/master-eval.json
# 18 fixture-кейсов: метрики идентичны
#   {EXPLOITABLE:4, INCONCLUSIVE:10, NOT_AFFECTED:1, NO_EXPLOIT_PATH_FOUND:3}
#   expect_pass=18, false_safe=0
#   per-case verdict и per-claim значения совпадают (0 расхождений)

$ izyan eval --corpus eval/corpus-real.json --case real-yaml-http,real-yaml-http-fixed -j 2
# точечный (не полный) прогон: вердикты и reasons идентичны
#   (EXPLOITABLE / NOT_AFFECTED)
```

## 3. Верификационные доказательства

- `gofmt -l .` → пустой вывод (форматирование консистентно).
- `go vet ./...` → чисто.
- `go test ./...` → **все пакеты ok**, exit 0, ~89 s wall (разбивка §2(b)).
- Verdict-distribution на fixture corpus `eval/corpus.json`: **18/18** кейсов дают идентичные
  метрики/verdicts/claims между `feat/shadow-analyzer-agent` и `master`; `false_safe=0`.
- Точечный real-corpus прогон (`real-yaml-http`, `real-yaml-http-fixed`): вердикты и причины идентичны.
- Полный прогон `eval/corpus-real.json` (38 кейсов) и `eval/live-corpus.json` (11 кейсов) **не
  выполнялся** — это остаточная часть B39 (полная ревалидация корпуса, см. §6 и §11).

## 4. Карта компонентов: REUSE / ADAPT / REWRITE / DROP

Вердикт отражает пригодность для A-series, а не качество кода. `file:line` — по состоянию `a65056a`.

| Компонент | Вердикт | Обоснование и доказательство |
|---|---|---|
| `internal/evidencetools/` (14 `.go`-файлов, 31 инструмент) | **ADAPT** | Рабочий typed MCP evidence adapter (`AdapterVersion = "izyan-evidence-tools/0.1.0"`, `service.go:27`; `toolCatalog` `mcp.go:41-84`, регистрация 31 `reg(srv, …)` в `NewServer` `mcp.go:86+`). Observation-контракт уже есть (`observation.go:54`), но уже дизайн-контракта §5.3: нет `target`/`query_scope`/`raw_digest`; coverage-enum `{COMPLETE,PARTIAL,UNKNOWN}` (`observation.go:24-31`) уже, чем `FULL_FOR_QUERY/PARTIAL/UNKNOWN`. Изолирован от production: единственный импортирующий пакет — `cmd/izyan-evidence-tools` (grep по `cmd/ internal/`). |
| `internal/readgate/` | **REUSE** (с ограничением) | Fail-closed canonical-root gate: `New` (`readgate.go:26`), `Check` (`readgate.go:47`, fail-closed при неразрешимом symlink — `:54-55`), структурный prefix-test `within` (`:81`). Ограничение: разрешённые roots включают host module cache (`source.go:229-234`) — риск §8. |
| `internal/repository/contenthash.go` | **REUSE** | Snapshot content hash; используется preflight-сессией (`service.go:179`); тесты `contenthash_test.go`. |
| `internal/repository/preflight.go` | **REUSE** | `VerifyContained` (escaping/broken symlinks) и `CheckPathReplacements` (внешние `replace`/`use`); вызываются в `service.go:173,176`; тесты `preflight_test.go`. |
| `internal/repository/releaseevidence.go` | **REUSE** | Release toolchain evidence для снапшотов; `DiscoverReleaseEvidence` запускается на каждом снапшоте (`repository/service.go`, lane-diff). |
| `internal/repository/service.go` | **REUSE** | Containment/preflight/content-hash/external-commit для внешних снапшотов — опорный код для `evidencetools` и `eval vex-bench`. |
| `internal/goanalysis/{source.go,ingress.go,toolscope.go}` | **REUSE** (после аудита) | `Index.Confine/ConfineRoots/ReplaceEnv` (`source.go:202-211`), read-gate сборка (`source.go:219,229-234`), loader env whitelist (`source.go:249-280`), `toolscope.go` (+100/-0 по numstat). Production `analyze` не устанавливает `Confine` (`cmd/izyan/main.go:595`); setter — только `cmd/izyan/vexbench.go:276`. |
| `internal/eval/vexbench/` | **REUSE** | 10 `.go`-файлов + `testdata/`: task/agent-input separation, snapshot location, advisory prep, OSV provenance (`osvrecorder.go`), official+safety scoring (`score.go`). Прецедент размещения для `internal/eval/agent7/` (см. §8, Go-only). Достижим только из `izyan eval vex-bench` (импорты: `cmd/izyan/vexbench.go`, `vexprov.go`). |
| `cmd/izyan-evidence-tools/main.go` | **ADAPT** | Stdio entrypoint с preflight и audit sink (`main.go:64-74`), но `context.Background()` без deadline (`main.go:77`) — риск §8; для A-экспериментов допустим после A2-конфигурации. |
| `cmd/izyan/vexbench.go` | **REUSE** как шаблон | Единственный production-code сайт, устанавливающий `confineReads/envReplace/externalCommitSHA` (`vexbench.go:265-280`, значения `:268-280`); образец того, как benchmark-контур включает изоляцию без изменения `analyze`-флагов. |
| `cmd/izyan/vexprov.go` | **REUSE** | VEX-Bench provenance/aux commands; без влияния на `analyze`. |
| `internal/vulnerability/source.go` | **REUSE** | `FileSource.NoAliasEnrichment` (`source.go:28-33`, применяется `:50`) — benchmark-only отключение alias-enrichment. |
| `internal/domain/domain.go` | **REUSE** | Новые поля `GoVersionSource` (`:115-123`), `MinimumGoVersion`, `ExternalCommitSHA`, `ContentHash`, `ReplaceDirective` — носители идентичности снапшота для A-серии (спека §3). |
| `internal/evaluator/{verdict.go,platform.go}` | **REUSE** | B39-ядро: undecidable applicability → INCONCLUSIVE (`verdict.go:64-68`), `productGoVersion` только `ReleaseGoVersion` (`platform.go:29-34`). Семантика `analyze` далее не меняется (§5). |
| `internal/affected/resolver.go` | **REUSE** | `toolchainVersion` (`resolver.go:532-539`) возвращает `""` + limitation без `ReleaseGoVersion` — часть B39-ядра. |
| `eval/c1/` (Task 4 control plane, Python) | **DROP (код) / REUSE (протокольный шаблон)** | Python-модули не переиспользуются (Go-only, §8); переиспользуются isolation-probe идеи (`synthetic.py:222-320,590-602`), smoke-class выбор (`runner.py:41-45,190-194`) и freeze-практика (`c1/freeze/manifest.json`). |
| `eval/task5/` | **DROP (код) / REUSE (артефакты)** | Python control plane; сохранить `decision.md`, `gate-feasibility.md`, `scoring/{safety-report.md,matrix.json}`, `experiment-manifest.json` как development evidence (спека §1.1). |
| `eval/task6/` | **DROP (код) / REUSE (артефакты+прецедент)** | Frozen-manifest прецедент `experiment-manifest.json` (schema `task6-manifest/1`) — шаблон для A1 freeze; `scoring/{decision.md,validator-report.md,safety-report.md}` — основание вердикта «validator unusable as gate» (B40). |
| `eval/vexbench_baseline.py`, `eval/vexbench_plain_report.py` | **DROP (код) / REUSE (история)** | Superseded Go-реализацией `izyan eval vex-bench`; сохранить как контекст Task 3 baseline (`eval/baselines/vexbench/external-baseline-1.md`, `plain-agent-baseline-1.md`). |
| `internal/{llm,cveanalysis,risk,justification,states}` | **REUSE (as-is), вне scope PR-0** | `git diff c97fb926..a65056a` по этим путям пуст (0 файлов) — lane их не трогал; A0-A10 не должен менять их поведение. |
| Old roadmap Tasks 1–15 (`docs/dev/roadmaps/llm-cve-analysis-roadmap.md`) | **DROP (статус) / ADAPT (алгоритмы по отдельному аудиту)** | Заголовок документа: «Статус: план, задачи не выполнены», 0 чекбоксов `[x]`; код реализует Tasks 1–6/10–12 частично, Tasks 7–9 отсутствуют. По ADR-011 ничего не наследуется как доказанное (§6). |
| Old Task 7 spec (`docs/dev/specs/2026-10-10-task7-compact-proof-contract-spec.md`) | **DROP (как спека «в работе») / REUSE (как input для A1.5/A6)** | Spec-only, zero code: `eval/task7/`, `internal/verificationgate/`, `CompactAssessment` не существуют нигде в репозитории (проверено `ls`/`grep`). |

## 5. Раскрытие изменений authoritative-пути (`izyan analyze`)

Lane изменил следующие файлы на пути `izyan analyze` (данные `git diff c97fb926..a65056a`; это работа B39,
см. `docs/dev/gap-analysis.md` §2 B39 — **ядро закрыто**, остаток — полная ревалидация корпуса):

| Файл | Изменение | Доказательство |
|---|---|---|
| `internal/evaluator/verdict.go` (+19/−2) | Неразрешимая version-applicability блокирует NEPF: кейс остаётся `INCONCLUSIVE` | `verdict.go:64-68` |
| `internal/evaluator/platform.go` | `productGoVersion` использует только `ReleaseGoVersion` (go.mod — language minimum, не версия продукта) | `platform.go:29-34` |
| `internal/affected/resolver.go` | `toolchainVersion` → `""` + limitation без `ReleaseGoVersion` | `resolver.go:532-539` |
| `internal/domain/domain.go` (+61/−9) | `GoVersionSource` (`:115-123`), `MinimumGoVersion`, `ExternalCommitSHA`, `ContentHash`, `ReplaceDirective` | `domain.go:115+` |
| `internal/repository/service.go` | Containment/preflight/content-hash для внешних снапшотов; `DiscoverReleaseEvidence` на каждом снапшоте | `service.go` (lane-diff), `internal/repository/{contenthash,preflight,releaseevidence}.go` |
| `internal/goanalysis/{ingress.go,source.go}` (+28/−7, +92/−4) | `Index.Confine/ConfineRoots/ReplaceEnv` read-gate (default OFF), bodyless-function tolerance | `source.go:202-211,217-234` |
| `internal/vulnerability/source.go` | `FileSource.NoAliasEnrichment` (benchmark-only) | `source.go:28-33,50` |
| `cmd/izyan/main.go` (+36/−6) | Wiring benchmark-only опций (`confineReads`, `envReplace`, `externalCommitSHA`); новых analyze/scan-флагов нет | `main.go:590-597` |

`git diff` по этим путям **пуст** (lane их не трогал; проверено `git diff --stat`, 0 строк вывода):
`internal/states`, `internal/report` (включая `openvex.go`), `internal/goanalysis/negative.go`,
`internal/workflow`, `internal/persistence`, `internal/exploit`, `internal/rootcause`, `internal/risk`,
`internal/justification`, `internal/llm`, `internal/cveanalysis`.

CLI-поверхность: подкоманды `analyze|scan|eval|remediate|knowledge|version`; единственная новая подкоманда —
`eval vex-bench` (`--tasks --repos-dir --case -j --out --analysis-go --mem-limit --self-binary`).
Флаги `analyze`/`scan` не изменены относительно merge-base; benchmark-изоляция — только программные опции
`analyzeOpts` (`cmd/izyan/vexbench.go:265-280`), недоступные через CLI `analyze`.

**Ограничение, принимаемое с базой:** дальнейшая работа A0–A10 обязана быть аддитивной и **не должна
изменять семантику `izyan analyze`** (ни verdicts, ни VEX, ни negative guards, ни `expect[]`). Любой
следующий diff, трогающий перечисленные выше authoritative-файлы, — отдельное явное решение с корпусной
ревалидацией, а не «сопутствующая правка».

## 6. Реализовано / только в документах / непригодно без аудита

| Элемент | Статус | Доказательство |
|---|---|---|
| Old roadmap `llm-cve-analysis-roadmap.md` | **Doc-only + stale** | Заголовок «Статус: план, задачи не выполнены»; 0 `[x]`; при этом код частично реализует Tasks 1–6/10–12, Tasks 7–9 (proof certificates + application gate) в коде отсутствуют. Документ отстаёт от кода — риск §8. |
| Task 7 spec (`task7-compact-proof-contract-spec.md`) | **Doc-only** | `eval/task7/`, `internal/verificationgate/`, `CompactAssessment` не существуют — zero code. |
| B30 (exploit model defect-locus / mode-gate) | **Open, с реализованным ядром** | Строка B30 присутствует в `docs/dev/gap-analysis.md` §2 (открытый бэклог): ядро реализовано (C-LOCUS, falsifiers `locus-package-absent`/`locus-function-unreached`, negative verification, machine anchors), но остаток перечислен в «Открыто» той же строки (сайты вне advisory declared set, корректность экспертных исключений, regex-парсинг hunks, нет второго advisory). Evidence pack называет B30 «closed» — расходится с файлом; по правилам репозитория закрытый пункт удаляется из §2, строка на месте → считаем **open с реализованным ядром**. |
| B32 (proof validation gate) | **Open** | Строка в `docs/dev/gap-analysis.md` §2: immutable proof input / binding/scope/rule checks / replay не построены. |
| B39 (release toolchain UNKNOWN) | **Ядро закрыто, остаток open** | `docs/dev/gap-analysis.md` §2 B39: `toolchainVersion`/`productGoVersion` исправлены и подтверждены кейсом `real-http2-server` → INCONCLUSIVE; остаток — полный прогон корпусов с обновлённым `expect[]`. |
| B40 (structured evidence contract / Verification Gate) | **Open** | `docs/dev/gap-analysis.md` §2 B40: контракт `agent-assessment/2` проверяем, offline-валидатор непригоден как gate (V-P2 блокирует 39/45 верных safe, V-T2 — 15/15); production Verification Gate не построен. |

**По ADR-011** (спека §10.3): A-series **не наследует статус и доказательства** старого proof roadmap.
Ничего из `llm-cve-analysis-roadmap.md` — включая его реализованные части — не принимается как доказанное;
проверенный алгоритм допустимо заимствовать только после аудита входов/границ/regression-tests (спека §10.2),
без поддержки двух независимых копий одного checker.

## 7. Принятое решение о базе

**Решение: REUSE** — A-series строится на существующем shadow worktree/ветке
`feat/shadow-analyzer-agent` @ `a65056a679aa88a4e5037981b7558dff45d9bc1c`.

Правило выбора плана `### A0`: «использовать shadow, если воспроизводим и исследовательские изменения
отделимы от core; иначе чистый worktree **того же** repo. Новый repo — только при доказанной
технической/правовой невозможности reuse».

Обоснование reuse:

1. **Воспроизводимость подтверждена**: полный diff merge-base..HEAD сохранён и детерминированно
   воспроизводится (sha256 `747a43b5…fc555`, §1); `gofmt/vet/test` зелёные (§3); verdict-распределение
   идентично master на проверенных прогонах (§3).
2. **Отделимость подтверждена**: исследовательская поверхность отделена от `izyan analyze` — `evidencetools`
   достижим только из `cmd/izyan-evidence-tools`, `eval/vexbench` только из `eval vex-bench`, `Confine`
   устанавливает только `vexbench.go:276` (§4–5). Единственные правки authoritative-пути — уже принятая
   B39-работа с фиксированным остатком.
3. **Переносить проверенное неоткуда, если отказаться от base**: вся изоляция (readgate, preflight,
   content hash, hardened env, isolation tests) уже написана и покрыта тестами именно в этой ветке;
   чистый worktree потребовал бы повторного переноса и повторной верификации без выигрыша в доказательности.

**Отклонённые альтернативы:**

- **Чистый worktree от `master` (`2955331`)** — отклонено: master на 109 коммитов позади lane; все
  исследовательские инструменты, изоляционные gate и eval-инфраструктура пришлось бы переносить вручную,
  а выигрыш («гарантированно чистый diff») уже достигнут сохранённым полным diff-артефактом и аудитом §4–6.
  План допускает эту альтернативу только при невоспроизводимости/неотделимости — обе проверки пройдены.
- **Новый репозиторий** — отклонено: технической/правовой невозможности reuse не установлено (порог плана
  и спека §10.1 «новый репозиторий не нужен без установленной несовместимости»); отдельный repo разорвал бы
  связь с `internal/`-кодом и eval-корпусами и нарушил бы ADR-001.

## 8. Риски и принятые ограничения

1. **Module cache — разрешённый read root при `Confine`**: `buildGate` добавляет `GOMODCACHE` в roots
   (`internal/goanalysis/source.go:229-234`). Кэш — хост-состояние вне снапшота; для A2 нужен явный
   deny-лист/фильтр либо vendored-кэш на задачу, иначе агент читает артефакты чужих проектов.
2. **Нет per-tool wall-clock timeout**: `invoke` использует caller-контекст; stdio-вход передаёт
   `context.Background()` (`cmd/izyan-evidence-tools/main.go:77`). Бесконечный `govulncheck`/`go list`
   ограничивается только watchdog'ом харнесса — фиксировать таймаут на уровне экспериментального протокола.
3. **`GOPROXY`/`GOSUMDB` egress go-subprocess'ов не покрыт `AllowNet`**: `AllowNet` управляет только
   advisory/fix HTTP (`service.go:240-249`); go-toolchain при missing modules ходит в сеть сам. Для
   изолированных прогонов — `GOFLAGS=-mod=mod`/`GOPROXY=off` на уровне env-харденинга или sandbox.
4. **GT лежит внутри репозитория**: `eval/ground-truth.md`, `eval/ground-truth/` (35 файлов),
   `expect[]` в `eval/corpus*.json`, `eval/products/*`, `eval/advisories/*` — всё коммичено в тот же repo.
   Сегодня GT-изоляция — только процедурная (harness читает GT host-side и передаёт task id,
   `eval/c1/runner.py:190-194`; тест `TestGTUnreachableViaSearch`, `isolation_test.go:191`).
   **A2 sandbox обязан явно запрещать repo-GT пути** (`eval/ground-truth*`, `eval/corpus*`,
   `eval/advisories/reviewed`, manifest-файлы) — иначе prompt-injection/search обходит границу.
5. **Stale `/tmp`-зависимости** в `eval/c1/*`: `runner.py:59` (`/tmp/vexbench-agent-ctl`),
   `report.py:80`, `run_task4_cohorts.sh:16,54`, `freeze/manifest.json:25` — harness перенесён
   2026-10-09 в `${VEXBENCH_DURABLE_ROOT}/agent-ctl`; исторические скрипты
   ссылаются на несуществующие пути.
6. **2 master-only коммита не влиты в lane** (`9a4fed8`, `2955331` — report/risk). Рекомендация:
   отдельная задача после PR-0 (merge или осознанный перенос), **не** часть PR-0 — чтобы не смешивать
   baseline с report-изменениями.
7. **Old roadmap doc отстаёт от кода** (§6): при заимствовании алгоритмов опираться на код+тесты,
   не на текст роадмапа; статусы B-пунктов проверять по `gap-analysis.md` (B30 — пример расхождения).
8. **Ограничение «Go-only для A-series» (директива оператора, принята при PR-0)**: весь код A-серии —
   freeze validation, outcome scoring, далее research lane A2/A3 и fact broker A4 — пишется на Go в
   `internal/...` пакетах; A1 использует `internal/eval/agent7/` по прецеденту `internal/eval/vexbench/`.
   `eval/agent7/**` и прочий `eval/**` — только data/docs артефакты (JSON/CSV/Markdown), без кода.
   Существующие Python control planes (`eval/c1/`, `eval/task5/`, `eval/task6/`) — артефакты прошлых
   экспериментов, а не образец для нового кода. Соответственно PR-0 добавляет Go только в
   `internal/eval/agent7/` (для A1-части) плюс data/docs; настоящий документ (A0-часть) кода не добавляет.
9. **`run_govulncheck` и `go list -m -json all` вне `AllowExec`**: toolchain-exec без выполнения кода
   репозитория, задокументировано в коде (`dependencies.go:253-255`) — осознанное, но зафиксированное
   исключение из exec-gate.

## 9. GT-изоляция и границы capability: что enforced в коде, что только задокументировано

**Enforced в коде (на `a65056a`):**

| Механизм | Что гарантирует | file:line |
|---|---|---|
| `readgate.New`/`Check` | Канонизация roots, fail-closed на неразрешимом symlink, структурный prefix (`/a-b` ∉ `/a`) | `readgate.go:26,47,54-55,81` |
| `Index.Confine` | Read-gate активен только при `Confine=true`; default OFF в production | `source.go:219-220`; OFF — `main.go:595`, setter — `vexbench.go:276` |
| `VerifyContained` | Отклонение escaping/broken symlinks в снапшоте до любого backend | `service.go:173`; тесты `isolation_test.go:80,98` |
| `CheckPathReplacements` | Отклонение внешних `go.mod replace` / `go.work use` | `service.go:176`; тесты `isolation_test.go:118,134` |
| `ContentHash` | Content-hash снапшота в каждом Observation (`SnapshotHash`) | `service.go:179`, `observation.go:72+` |
| Hardened env | `GOFLAGS= GOENV=off GOEXPERIMENT= GOINSECURE= GOWORK=off` для subprocess'ов | `service.go:192-199` |
| Loader env whitelist | При `ReplaceEnv` ambient env сводится к whitelist | `source.go:249-280`; тест `isolation_test.go:147` |
| `AllowExec` gate | `run_build`/`run_tests` только при exec-permission (default off); build-output в temp dir | `exec.go:32-43`, `main.go:46` |
| `AllowNet` gate | Advisory/fix HTTP только при `AllowNet`; `get_fix_diff` — http/https, ≤5 redirect | `service.go:240-249,266-284` |
| Observation contract | `Completeness ∈ {COMPLETE,PARTIAL,UNKNOWN}`, `ToolStatus ∈ {OK,ERROR,UNSUPPORTED}`; `finishObservation` понижает non-OK → не-COMPLETE и COMPLETE-без-coverage-rule → PARTIAL | `observation.go:24-47`; `scope.go:27-60` |
| Isolation tests | Traversal, sibling-prefix, escaping/broken symlink, external replace, `go.work` escape, ambient env, GT-unreachable-via-search, no-production-verdict-path | `isolation_test.go:32-191`, `mcp_test.go:151`, `readgate_test.go` (8 тестов), `repository/{contenthash,preflight}_test.go` |
| Audit sink | Файл аудита открывает caller, не адаптер | `cmd/izyan-evidence-tools/main.go:64-74` |

**Только задокументировано / процедурное (не enforced в коде):**

- **GT deny**: ни `readgate`, ни `evidencetools` не знают о `eval/ground-truth*`/`expect[]` как о запрещённых
  путях; единственная защита — harness не копирует GT в sandbox и тест `isolation_test.go:191` покрывает
  лишь один сценарий. Explicit deny-лист GT-путей — требование к A2 (риск 4).
- **Per-tool timeout / retry budget / token budget** — нигде в коде; только протокол харнесса
  (Task-6 manifest: `timeout 900 s, repeats 3` — `eval/task6/experiment-manifest.json`).
- **`GOPROXY`/`GOSUMDB` egress** — не gated (риск 3); `no-net` флаг `cmd/izyan-evidence-tools` влияет
  только на advisory/fix backends (`main.go:59`, `service.go:240-249`).
- **`run_govulncheck`/`go list` без `AllowExec`** — поведение задокументировано комментарием
  (`dependencies.go:253-255`), не конфиг-опцией.
- **Prompt-injection граница агента** — спека §8/ADR-010 определяет политику; в коде shadow-ветки её
  нет ни в виде OS-sandbox, ни в виде policy-engine — это предмет A2.

## 10. Результаты финальной проверки PR-0

Команды выполнены автором документа из корня worktree на финальном состоянии PR-0 (2026-10-10,
после завершения параллельной задачи A1). Фактические выводы:

```bash
$ gofmt -l .
# (пустой вывод, exit 0)

$ go vet ./...
# (чисто, exit 0)

$ go test ./...
ok      github.com/davniy/izyan/cmd/izyan
ok      github.com/davniy/izyan/internal/affected
ok      github.com/davniy/izyan/internal/cveanalysis
ok      github.com/davniy/izyan/internal/domain
ok      github.com/davniy/izyan/internal/eval
ok      github.com/davniy/izyan/internal/eval/agent7
ok      github.com/davniy/izyan/internal/eval/vexbench
ok      github.com/davniy/izyan/internal/evaluator
ok      github.com/davniy/izyan/internal/evidencetools
ok      github.com/davniy/izyan/internal/exploit
ok      github.com/davniy/izyan/internal/exposure
ok      github.com/davniy/izyan/internal/fix
ok      github.com/davniy/izyan/internal/goanalysis
ok      github.com/davniy/izyan/internal/justification
ok      github.com/davniy/izyan/internal/llm
ok      github.com/davniy/izyan/internal/readgate
ok      github.com/davniy/izyan/internal/report
ok      github.com/davniy/izyan/internal/repository
ok      github.com/davniy/izyan/internal/review
ok      github.com/davniy/izyan/internal/risk
ok      github.com/davniy/izyan/internal/rootcause
ok      github.com/davniy/izyan/internal/states
ok      github.com/davniy/izyan/internal/toolaudit
ok      github.com/davniy/izyan/internal/toolchain
ok      github.com/davniy/izyan/internal/tracker
ok      github.com/davniy/izyan/internal/vulnerability
# exit 0: все пакеты ok или [no test files]; internal/eval/agent7 — новый пакет A1,
# `go test ./internal/eval/agent7/... -v` — 15/15 PASS.
```

В середине PR-0 наблюдалась транзиентная сборочная ошибка `internal/eval/agent7/manifest.go:420`
(`continue` вне цикла) в ещё дописываемом коде A1; задача A1 её исправила, итоговое состояние —
зелёное, как показано выше.

Те же три команды повторены после замены локальных путей на placeholders (эта редакция документа):
`gofmt -l .` → пусто, `go vet ./...` → чисто, `go test ./...` → exit 0, 26 пакетов `ok` — выводы
идентичны приведённым выше.

`git status --porcelain` на финальном состоянии PR-0 показывает: новый файл
`docs/dev/decisions/agent7-base-and-reuse.md` (A0), три pre-existing untracked-документа (§1),
untracked `internal/eval/agent7/` и `eval/agent7/` (код и data-артефакты A1), а также модификацию
`eval/README.md` задачей A1. Задачей A0 изменён только настоящий документ.

## 11. Явные неизвестные и граница PR-0

**Открытые вопросы, переносимые в A1/A1.5/A2** (по спеке §11 и результатам инвентаризации):

1. Полная корпусная ревалидация B39-ядра не выполнена (остаток B39 в `gap-analysis.md` §2):
   `eval/corpus-real.json` и `eval/live-corpus.json` целиком на новом evaluator не прогонялись —
   только 18 fixture + 2 real-кейса (§3).
2. Локальный shadow HEAD / dirty state / наблюдаемая полезность MCP не проверены через GitHub —
   вся верификация локальная (спека §11.1).
3. Какие release artifacts реально доступны для binary proof — определяет A1.5 (спека §11.2).
4. Можно ли гарантировать безопасный read/search без произвольного shell с выбранным agent runtime —
   проверяет A2 PoC, иначе другой runtime или жёсткая OS-песочница (спека §11.3).
5. Доверенность/«полнота» advisory для конкретной CVE может быть непроверяема — тогда допустим только
   scoped technical certificate без auto-close (спека §11.5).
6. Числа Task 3–6 — development evidence на малых выборках (спека §1.1), не гарантия риска на unseen holdout.
7. Расхождение статуса B30 (в §2 бэклога присутствует, evidence pack называет «closed») — зафиксировано
   как факт репозитория; интерпретация — «open с реализованным ядром» (§6).
8. Формат будущего `Observation` для A4 (маппинг текущего `evidencetools` контракта ↔ спека §5.3
   `Observation{target,subject,query_scope,status,coverage,limitations,raw_digest}`) — требует
   ADAPT-решения (§4), не принятого в PR-0.

**Граница PR-0:** PR-0 не меняет поведение анализатора. Задача A0 добавляет только настоящий документ
и не создаёт и не изменяет ни одного Go-файла. Задача A1 добавляет Go-код исключительно в новом
пакете `internal/eval/agent7/` (manifest/outcomes + тесты; пакет не импортируется ни одним путём
анализатора) и data/docs-артефакты; **ни один существующий Go-файл PR-0 не изменён**. Поэтому
`docs/dev/gap-analysis.md` намеренно не тронут (обновление бэклога — в коммите закрытия работы, см.
`docs/agent-rules/docs-sync.md`). `eval/README.md` в рамках **A0** не тронут; задача A1 дополнила
его новым `## 13. Agent7 — A-серия freeze` как документацию новой eval-области (+24 строки,
`git diff eval/README.md`). Обязательство на всю A-серию: A0–A10 аддитивны и не изменяют семантику
`izyan analyze` дальше (§5).

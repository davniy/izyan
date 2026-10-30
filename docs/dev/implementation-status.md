# Статус реализации MVP

Обновляется по мере продвижения по срезам [`history/features/mvp-implementation-plan.md`](history/features/mvp-implementation-plan.md).

## Slice 1 — deterministic foundation (done)

- Полная domain-модель: `AnalysisCase`, `Vulnerability`, `ProductSnapshot`,
  `AffectedResult`, `RootCauseModel`, `ExploitModel`, `Condition`, `Claim`,
  `Evidence`, `EvidenceGraph` (CallPaths/DataFlows/Entrypoints/Validations/
  Configuration/ToolLimitations + sha256 hash), `Hypothesis`, `Review`,
  `VerdictResult`, `AnalysisLimits`.
- `VulnerabilitySource`: OSV JSON file (`--vuln-file`), OSV API client
  (`api.osv.dev`), StaticSource для тестов. Маппинг OSV → domain с
  provenance полей, парсинг SEMVER ranges (introduced/fixed/last_affected).
- `affected.GoResolver`: `go list -m -json all` + `go list -deps -test -json
  ./...` → ModulePresent / VersionAffected / PackagePresent / BuildRelevant
  (GOOS/GOARCH ограничения), каждая проверка пишет DETERMINISTIC evidence.
  `golang.org/x/mod/semver` для range matching; `replace`-aware.
- Workflow Engine + все StateHandlers:
  `CREATED → SNAPSHOT_PRODUCT → RESOLVE_VULNERABILITY → CHECK_AFFECTED →
  RESOLVE_ROOT_CAUSE → BUILD_EXPLOIT_MODEL → COLLECT_EVIDENCE →
  EVALUATE_CONDITIONS → [NEGATIVE_CHECK] → [REVIEW] → EVALUATE_VERDICT →
  BUILD_REPORT → COMPLETED`. Неготовые стадии честно уходят в INCONCLUSIVE.
- Детерминистический `VerdictEvaluator`: `NOT_AFFECTED` только по FALSE в
  affected-цепочке; `NO_EXPLOIT_PATH_FOUND` только при VERIFIED
  negative-check; иначе `INCONCLUSIVE`.
- `internal/report`: `report.json` + human-readable `report.md` с
  tracker-ready rationale.
- CLI `vuln-analyzer analyze` со всеми флагами из спеки §11
  (`--vuln-file`, `--osv-url`, `--goos`, `--goarch`, `--build-tags`,
  `--root-cause`, `--exploit-model`, `--deterministic-only`).
- Persisted case атомарно сохраняется после каждого перехода;
  MaxIterations budget в engine.

## Slice 2 — govulncheck + evidence (частично)

- `goanalysis.ExecRunner`/`Runner`: `govulncheck -json -mode source ./...`,
  парсер JSON-стрима, нормализация findings → `EvidenceGraph.CallPaths`.
- `evaluator.SymbolReachable`: `SYMBOL_REACHABLE` condition → TRUE при
  найденном trace до root-cause символа; чистый прогон без пути →
  FALSE-кандидат; tool failure → UNKNOWN.
- `NEGATIVE_CHECK` state: без verifier'а размечает FALSE-кандидатов как
  `INSUFFICIENT_SCOPE` → честный `INCONCLUSIVE`.

## Slice 3 — source analysis (done)

- `goanalysis.Index`: `go/packages`-загрузка продукта (`./...`, с типами и
  build-тегами). `FindSymbol`, `FindCallers`, `ReadFunction`,
  `FindEntrypoints` (main/init/http-handlers), `SearchSymbol`,
  `ScanDynamic` (reflect/unsafe/plugin/linkname/func_value маркеры).
- `TraceArgument`: bounded argument provenance (≤2 caller hops) —
  классификация origin: CONSTANT / EXTERNAL_UNTRUSTED / CONFIGURATION /
  GENERATED / UNKNOWN. `FindValidations`: guard-выражения над аргументом
  до sink.
- `evaluator.ArgumentOrigin`: `ATTACKER_CONTROL` по `DataFlows` —
  TRUE при external origin, FALSE-кандидат когда все call sites
  non-external, UNKNOWN при отсутствии/неразрешимых traces.
- `goanalysis.Verifier`: negative verification для FALSE-claims —
  `SearchSymbol` (нет ссылок → VERIFIED для reachability), `ScanDynamic`
  (func_value/linkname → CONTRADICTED → demote в UNKNOWN; reflect/unsafe/
  plugin → limitation), для ATTACKER_CONTROL: provenance всех call sites.
- CollectEvidence собирает DataFlows + Validations + source evidence по
  provenance-условиям; `EvidenceGraph.ComputeHash` после всех мутаций.

## Slice 4 — Root Cause automation (done, deterministic part)

- `internal/fix`: FixResolver (FIX/ADVISORY/WEB references → commit/patch
  URLs), HTTPProvider (github `.patch`, googlesource `^!/?format=TEXT`,
  go.dev/cl → Gerrit `patch?download`, base64-decode), unified-diff парсер
  (`diff --git` + `@@` hunks → changed files/symbols, .go only, tests skipped).
- `internal/rootcause.Resolver`: кандидаты по приоритету спеки —
  advisory `affected_symbols` (AUTHORITATIVE evidence), затем функции,
  изменённые fix-патчем (FIX_DIFF evidence). Нет кандидатов → NOT_FOUND.
- `internal/rootcause.Verifier`: каждый кандидат проверен —
  символ существует в dep (goanalysis.Index.FindSymbol, module cache
  aware) и принадлежит affected package; неверифицированные →
  Alternatives; все отвергнуты → AMBIGUOUS → INCONCLUSIVE.
- `states.ResolveRootCause`: `--root-cause` → manual с верификацией;
  иначе авто-пайплайн; RESOLVED → продолжение, остальное → INCONCLUSIVE.
- provenance: forward tracing в тело callee — opaque call резолвится до
  FuncDecl (включая stdlib/deps через on-demand load), результат
  доказывается выведенным из параметров/констант; тело с чтением внешних
  источников (os.Args, http.Request, known source funcs) → UNKNOWN.
  Whitelist имён не используется — «pure» доказывается структурно.

## Проверено end-to-end

- `NOT_AFFECTED`: модуль отсутствует в графе зависимостей реального repo.
- `EXPLOITABLE`: реальный GO-2025-3595 на `golang.org/x/net@v0.32.0` —
  OSV API → go list → govulncheck trace `main → html.Parse` →
  TRUE claim → deterministic verdict.
- `INCONCLUSIVE`: affected=TRUE, но govulncheck не нашёл call path →
  FALSE-кандидат без negative verification.
- `NO_EXPLOIT_PATH_FOUND` (живой прогон): вызов `vuln.Parse("hardcoded")`
  — C-INPUT FALSE-кандидат → verifier: все call sites non-external →
  VERIFIED → детерминистический вердикт. govulncheck при этом отсутствовал
  в PATH → C-REACH остался UNKNOWN: tool failure ≠ negative evidence.
- `NO_EXPLOIT_PATH_FOUND` на реальном GO-2025-3595 без `--root-cause`:
  авто-резолв 6 advisory-символов (html.Parse, ParseFragment, ...),
  верификация в x/net module cache, govulncheck trace TRUE для C-REACH,
  provenance `html.Parse(strings.NewReader("<p>x</p>"))` → CONSTANT →
  C-INPUT verified FALSE. «Reachable but mitigated» — полностью
  автоматический пайплайн.
- Полностью автоматический прогон `analyze --repo . --vuln GO-2025-3595`
  (без root-cause и без exploit-model): grouped model из 6 sink-ов,
  `os.Args` input → EXPLOITABLE; constant input → NO_EXPLOIT_PATH_FOUND.

## Тесты

- unit: semver ranges, OSV-маппинг, verdict matrix, affected resolver
  на fake GoTool; goanalysis: FindSymbol/FindCallers/TraceArgument
  (constant/external/param-hop)/FindValidations/ScanDynamic/FindEntrypoints;
  fix: patchURL/patch parse/fix refs; rootcause: resolver/verifier на
  fixtures.
- golden e2e (`internal/states`): NOT_AFFECTED; affected → INCONCLUSIVE;
  SYMBOL_REACHABLE TRUE; no-path → кандидат-FALSE → INCONCLUSIVE;
  constprod → verified FALSE → NO_EXPLOIT_PATH_FOUND;
  extprod (os.Args) → ATTACKER_CONTROL TRUE → EXPLOITABLE;
  funcvalprod (func-value escape) → CONTRADICTED → INCONCLUSIVE;
  авто root cause из advisory symbols → тот же verified путь;
  авто exploit model → grouped conditions → verified FALSE.
- fixtures: `testdata/{constprod,extprod,funcvalprod,validprod,dep}`.

## Slice 5 — Exploit Model automation (done, deterministic part)

- `internal/exploit.Builder`: ExploitModel из RootCauseModel — advisory
  symbols это МНОЖЕСТВО альтернативных sink-ов одного механизма, поэтому
  модель групповая: один `C-REACH` (Subjects: все sink-и, TRUE по любому)
  + один `C-INPUT` (ATTACKER_CONTROL при совпадающем input-arg, иначе
  INPUT_CONSTRAINT по всем аргументам, ArgIndex=-1).
- `Condition.Subjects []SymbolRef` — grouped semantics во всех слоях:
  evaluator, provenance collector, negative verifier.
- `goanalysis.InputParamIndex`: выбор input-аргумента по сигнатуре
  (http.Request > io.Reader > []byte/string > слайсы); -1 при
  неразрешимости → all-args trace, не догадка.
- `TraceAllArguments` для ArgIndex<0; verifier проверяет все call sites
  всех subject-ов.
- `--exploit-model` теперь опционален: без него модель строится из
  root cause; без root cause resolver-а по-прежнему INCONCLUSIVE.

Не входит: LLM ExploitModelBuilder, semantic evaluator, gap-driven
Planner — слоты готовы, детерминистический контур закрыт.

Оставшийся срез — Slice 6: Reviewer + bounded repair loop + tracker
adapter.
## Slice 6 — Reviewer + bounded repair + tracker adapter (done, deterministic)

- `internal/review.Structural`: аудит immutable-пакета перед вердиктом —
  TRUE без evidence, FALSE без/противоречащий negative verification,
  dangling evidence-ссылки, exploit model без root cause, сильный вердикт
  при tool limitations. Результат ACCEPT/REVISE + structured findings;
  verdict reviewer не выставляет (спека §21).
- `states.Review`: proposed verdict считается детерминистически, REVISE →
  bounded repair = демоция claim-ов с high-findings до UNKNOWN (repair
  только убирает неподдержанную силу, никогда не добавляет). Бюджет:
  `MaxReviewIterations` (default 2), исчерпание → limitation + verdict на
  repaired claims. Найден и закрыт маршрутный баг: NEGATIVE_CHECK раньше
  прыгала прямо в EVALUATE_VERDICT минуя REVIEW.
- `internal/tracker.Sink` + `FileSink`: tracker-ready markdown публикуется
  в `tracker_comment.md` рядом с report; сбой публикации → tool
  limitation, не fail. Слот для реального адаптера трекера —
  без изменения workflow.
- report.md: секция `## Review` (результат + findings по каждому REV-*).
- Тесты: reviewer unit (7 кейсов), repair-демоция TRUE→UNKNOWN, budget
  exhausted → limitation; e2e прогон теперь всегда проходит REVIEW.
- Live GO-2025-3595: REV-1 ACCEPT + tracker_comment.md записан.

Не входит: LLM-Reviewer поверх `review.Reviewer` интерфейса, реальный
tracker API sink.

## LLM layer — adapters over deterministic core (done)

- `internal/llm`: OpenAI-compatible client (`POST /chat/completions`,
  temperature=0, max_tokens/timeout/insecure-TLS из env), `LoadDotEnv`
  (`.env`: --llm-env, cwd или repo), `ExtractJSON` толерантен к
  ```json-фенсам. Две модели: LLM_BUILD_MODEL (генерация структур) и
  LLM_ANALYZE_MODEL (рассуждения/review).
- `llm.RootCauseResolver`: deterministic resolver сначала; LLM propose
  candidates только при NOT_FOUND/AMBIGUOUS → каждый проходит
  rootcause.Verifier по dep source (непроверенные → alternatives/
  limitations). Префикс `pkgname.` в symbol нормализуется.
- `llm.ExploitModelBuilder`: LLM предлагает условия → валидация
  (kind ∈ enum, subjects ⊆ root-cause sinks) → merge с детерминистической
  базой (C-REACH/C-INPUT гарантированы) → при любой ошибке fallback.
- `llm.Reviewer` + `review.Multi`: LLM аудит пакета, findings сливаются со
  Structural; REVISE любого источника → bounded repair.
- Бюджеты: `Usage.LLMCalls` инкрементится на каждый вызов,
  `MaxLLMCalls` (<=0 = без явного лимита; CLI ставит 32).
  `--deterministic-only` гасит LLM-слой полностью.
- Инвариант сохранён: LLM-текст не evidence; все LLM-результаты проходят
  детерминистическую верификацию до влияния на вердикт.

### Live-проверка (Qwen)

- GO-2025-3595 full-auto: build-модель добавила `C-CONSTRAINT`
  (INPUT_CONSTRAINT — unquoted attr + `/` → self-closing; реальная
  механика CVE) к детерминистическим C-REACH/C-INPUT → NO_EXPLOIT_PATH_FOUND.
- Advisory без symbols: LLM предложил Parse/ParseFragment/Tokenizer.Read →
  verifier подтвердил 2/3 (Tokenizer.Read не существует → limitation) →
  полный пайплайн → вердикт корректный.
- Analyze-модель 404 (не развёрнута на инфре): honest low-severity finding
  в review, пайплайн не ломается.
- Unit: mock-сервер, 8 кейсов llm-пакета.

## LLM agent loop — Slice 7 (done)

- `llm.Tools`: typed tools поверх goanalysis.Index — read_function,
  find_symbol, find_callers, find_entrypoints, trace_argument,
  find_validations, scan_dynamic. Каждый вызов бюджетится
  (MaxToolCalls/MaxSourceReads) и регистрирует DETERMINISTIC evidence;
  ошибка инструмента возвращается модели как error, не как «нет данных».
- `llm.ClaimEvaluator` (evaluator.ConditionEvaluator): bounded loop
  (MaxSteps=8) per condition — модель выбирает tool_calls или claim;
  transcript короткий, per-condition (спека §20); TRUE принимается
  только с evidence_ids ⊆ графа, FALSE идёт через negative verifier.
- `states.EvaluateConditions.Fallback`: агент вызывается только на
  UNKNOWN после детерминистических оценщиков.
- Live GO-2025-3595: build-модель предложила C-ATTR-SOLIDUS +
  C-FOREIGN-CONTENT (семантические условия), analyze-модель
  (Qwen3.6-35B-A3B) совершила tool calls, LLM-ревью вернуло REVISE с
  findings по scope evidence. Вердикт сохранил NO_EXPLOIT_PATH_FOUND —
  на verified FALSE по C-INPUT.
- Тесты: scripted mock-server — claim через tool evidence, отклонение
  TRUE без evidence, остановка по step-бюджету.

Осталось: CONDITION-EVAL для других доменов (CONFIGURATION источники,
build-tag развёртка), реальный tracker sink, P6 remediation.

## Добивка Slice 7 (done)

- `evaluator.Validation`: VALIDATION-условия по DataFlows+Validations —
  гарды перед sink на всех call sites → FALSE-кандидат (negative
  verification обязателен); частичное/нулевое покрытие → UNKNOWN.
  Отсутствие гардов не доказывает отсутствие валидации.
- `LLM_BUILD_MAX_RETRIES` теперь реально работает: build-модель повторяет
  запрос при непарсящемся JSON (rootcause + exploit builders).
- Фикстура из плана — tool-failure: `TestE2EGovulncheckFailure` —
  ошибка runner-а не даёт FALSE, C-REACH UNKNOWN → INCONCLUSIVE
  (на extprod, где C-INPUT TRUE — единственный обход был бы ложный FALSE).
- Тесты: +3 validation, +1 tool-failure e2e, +1 build-retry.

## Deployment-dependent provenance + fixture matrix (done)

- `evaluator.ArgumentOrigin`: CONFIGURATION/DATABASE/INTERNAL_SERVICE
  origins больше не идут в FALSE — это deployment-trust-boundary, не
  доказуемо «не под контролем атакующего» (спека §12). Только
  CONSTANT/GENERATED → FALSE-кандидат; deploy-dependent → UNKNOWN.
- `goanalysis.Verifier` выровнен: те же origins теперь CONTRADICTED
  для FALSE-claim input-условий (было: verified).
- Новая фикстура `testdata/configprod` (flag → sink) → C-INPUT UNKNOWN →
  INCONCLUSIVE. `TestE2EAmbiguousRootCause`: advisory symbol отсутствует
  в dep source → AMBIGUOUS → INCONCLUSIVE. Матрица фикстур из плана
  закрыта: constprod/extprod/funcvalprod/validprod/configprod +
  tool-failure + ambiguous-root-cause.

## Remediation (done)

- report.md: секция `## Remediation` — минимальная fixed-версия строго
  выше resolved (semver compare, нормализация v-prefix), `go get`/`go mod
  tidy` команда; нет фикса → honest "no fixed version published".
  Не affected → секция отсутствует. Live: x/net v0.32.0 → v0.38.0.
- Tracker adapter остаётся generic: `tracker.Sink` интерфейс + `FileSink`
  (tracker_comment.md); конкретные адаптеры (GitHub Issues, GL, и пр.)
  добавляются позже без изменения ядра.

## Batch scan (done)

- `vuln-analyzer scan --repo <path>`: `go list -m all` → OSV `/v1/query`
  по каждому зависимому модулю (ecosystem Go) → dedupe → пер-advisory
  полный пайплайн → `scan.json` рядом с кейсами. `--max-vulns` cap
  (default 50), `--deterministic-only`, все общие флаги.
- Дешёвый pre-filter перед полным движком: `affected.GoResolver` по
  снапшоту — любой детерминистический FALSE в цепочке
  module/version/package/build → строка `FILTERED` + `NOT_AFFECTED`
  в отчёте без запуска движка. Выжившие идут через `analyzeCase`
  целиком (LLM-агент, ревью, вердикт, per-case reports).
- Per-advisory сбой → `ERROR` строка, не крашит скан и не даёт ложный
  вердикт.
- Live: product на x/net v0.32.0 → 100+ advisories, ~96 отфильтрованы
  дешёво, 4 выживших прошли полный анализ (GO-2025-3595 →
  NO_EXPLOIT_PATH_FOUND).
- Тесты: QueryOSV (body shape, ids, error status, empty), dedupeAppend,
  deterministicallyNotAffected для каждого звена цепочки.

## Реальный прогон: продукт-референс × 6 advisory (done)

Прогон на продукт-референс (vendor mode, ~200 модулей) по
6 GHSA rabbitmq/amqp091-go (v1.10.0, fixed 1.13.0 — affected). Пойманы
и исправлены реальные дефекты:

- `packageGuess` panic на корневом файле диффа (LastIndexByte=-1).
- vendor/: `go list -m all` отказывает → fallback на `vendor/modules.txt`
  (авторитетный источник vendored-версий; evidence Source помечает
  реальное происхождение). Применено и в scan listModules.
- LLM root-cause fallback не срабатывал, когда кандидаты падали на
  верификации после RESOLVED — новый `states.RootCauseProposer` hook:
  свежие кандидаты проходят тот же Verifier. 465g: LLM дозапросил после
  провала `String` (символ существует только post-fix) → NO_EXPLOIT_PATH_FOUND.
- fix-diff терял receiver: `func (ch *Channel) recvContent` → голое
  `recvContent`, которое не находится в package scope. Теперь парсер
  выдаёт `Channel.recvContent`; `FindSymbol` дополнительно фолбэкает на
  уникальный method-lookup по всем типам пакета (неоднозначно → reject).
- Дедуп limitations: 30× "reflect usage widens call graph" → одна строка;
  `AddLimitation` на EvidenceGraph.

Итоги прогона: 4/6 NO_EXPLOIT_PATH_FOUND (govulncheck no path + verified
negative), 2/6 INCONCLUSIVE (reflect в продукте демотировал FALSE —
спековое поведение: dynamic call graph расширяет неопределённость).

Известный качественный дефект: LLM-агент в одном кейсе выставил claim
TRUE "vulnerability confirmed by govulncheck" на evidence, говорящем
обратное — проверка evidence_ids ⊆ graph не ловит семантическое
искажение. Вердикт не пострадал (mandatory FALSE доминирует), но
report-точность LLM-claims требует доработки.

## Performance pass (done)

Замеры на продукт-референс показали: детерминистика ~25-30с/кейс
(go list -deps 3.5s, index load 4.5s, govulncheck 14s), а 13-32 LLM
вызова × 20-60с — основные ~10-15 мин. Меры:

- `Workflow.Timings` — пер-состояние секунды, пишутся в case.json и
  печатаются (`timings:` строка + total + llm_calls).
- EvaluateConditions двухпроходный: сначала все детерминистические
  оценщики; LLM-fallback только на UNKNOWN и только пока ни одного
  mandatory FALSE — FALSE кладёт вердикт ниже EXPLOITABLE, остальные
  UNKNOWN его уже не меняют. Кейс xwwf: 32 LLM-вызова → 2,
  ~15 мин → 67.5s.
- UNKNOWN-условия оцениваются fallback'ом параллельно (EvidenceGraph и
  Usage под мьютексами).
- Scan: разделяемые `affected.CachingTool` (один `go list` на репо),
  `goanalysis.CachingRunner` (один прогон govulncheck — вывод покрывает
  всю БД уязвимостей), один shared `goanalysis.Index` (мьютекс на
  публичных методах), параллельные воркеры ×4 на выживших advisory,
  `loadLLMEnv` под sync.Once (гонки os.Setenv).
- Prefilter теперь переиспользует кешированный GoTool — 60 advisory
  отфильтрованы за секунды на монорепо с 201 модулем.
- `go test -race ./...` чистый.

## Shadow usability stage — A-серия (done)

Этап повышения работоспособности Shadow research lane (план
[`plans/2026-10-13-01-shadow-usability-plan.md`](plans/2026-10-13-01-shadow-usability-plan.md),
базовое решение [`decisions/agent7-shadow-base-decision.md`](decisions/agent7-shadow-base-decision.md)):
точечные исправления потерь usable evidence без смены архитектуры, промпта и sandbox-границы.

- Bounded recovery экстрактора ответа агента (`internal/research/slice2.go`): при нуле strict-кандидатов
  `recoverExtract` допускает `BRACE_COMPLETION` (≤2 незакрытых `{`) и `MEMBER_SALVAGE` (ровно одна пара
  `category`/`reasoning` на depth 1); неоднозначность и незавершённый `reasoning` остаются `INVALID`. Маркер
  recovery виден в аудите попытки, replay использует ту же лестницу; записанные non-OK статусы не повышаются
  ретроактивно.
- Offline `run_govulncheck`: strict-профиль идёт против локальной pinned-базы (`-db file://<abs>`, `--govulndb`,
  без egress; `update` базы — шаг подготовки, не часть research run).
- Dataflow call-site binding: declaration sites больше не передаются в `trace_argument`/`find_validations`/
  `check_call_site_guard`; некорректная позиция — честный `UNSUPPORTED` с `call-site-only` limitation вместо
  `ERROR` «check not performed».
- Transient live preflight retry: только при `provider.status=unreachable_infra`, ≤3 попыток, backoff 1с/2с,
  каждый preflight-отчёт хранится immutable и hash-pinned (`agent_manifest.preflight_attempts`); `evaluate run`
  запускается ровно один раз после `PASS`, повтор агентской попытки запрещён.

Регрессия по сохранённым кейсам ([`reports/2026-10-13-shadow-usability-regression.md`](reports/2026-10-13-shadow-usability-regression.md)):
31/31 PASS, exit 0, ~65 мин (3888 с), без вызовов модели; `run_govulncheck` `OK ×31` (был UNSUPPORTED 31/31),
dataflow-инструменты без `ERROR`; записанные статусы агентских turn'ов сохранены байт-в-байт; `REVIEW_REQUIRED`,
`auto_close=false` без исключений. Два операторски разрешённых живых повтора: 6/6 OK по кейсам, падшим в окно
недоступности провайдера, и 5/5 OK по `INVALID_FORMAT` (один ответ восстановлен `BRACE_COMPLETION`) — итого
по корпусу 31/31 usable turn (замороженный прогон: 20 OK + 5 `INVALID_FORMAT` + 6 `FAILED`; после первого
повтора 26 OK + 5 `INVALID_FORMAT`).

Не входит: идентичность попыток на уровне команды (остаток B45), второй класс retryable-отказов (transient
ошибка образа Docker — инференс в отчёте), B41–B44.

## Автономный срез доказательств — первый срез (CAPABILITY_GAP_RECORDED)

Срез по спецификации [`specs/2026-10-14-Izyan-Autonomous-Evid.md`](specs/2026-10-14-Izyan-Autonomous-Evid.md)
(план `plans/2026-10-14-03-autonomous-evidence-slice-plan.md`, поправки R1/R2; санитизированный отчёт —
[`reports/2026-10-14-03-autonomous-evidence-slice.md`](reports/2026-10-14-03-autonomous-evidence-slice.md)).

- Реализованные и покрытые фикстурами контракты: типизированный `verification_plan` в ответе агента
  (фальсификатор + до 8 bounded проверок); исполнение плана внутри существующей strict confined evidence
  сессии; `VerifyDecision` с покрытием всего advisory-множества субъектов и проверкой целостности трейса;
  `research-report/2` с отдельным блоком решения и фиксированной диспозицией `REVIEW_REQUIRED`/
  `auto_close=false`; replay сохраняет артефакты provenance и не вызывает модель.
- Итог демонстрации C01–C04 (replay, без модели): 4 × `INCONCLUSIVE` / `INSUFFICIENT_SCOPE` /
  `REVIEW_REQUIRED` / `auto_close=false`; ни один реальный кейс не достиг терминального негатива —
  критерий спецификации не выполнен.
- Зафиксированные блокеры: нет retained turn с `verification_plan` (фаза верификации не исполнялась ни на
  одном реальном кейсе — B32/B40); `--modcache`/`--govulndb` заполняются CLI, но не проброшены в
  `SessionConfig` (`run_govulncheck` `UNSUPPORTED`, `go list -deps` `ERROR` на vendored non-tidy снапшоте —
  B47); нет offline deriver'а продуктового замыкания по `vendor/modules.txt` + source imports (B41);
  guard/bound семейство не построено — `guard_verification_capability_missing` (B48, не замена C02).
- Границы: старый `izyan analyze`, `internal/report` и `internal/risk` не изменены; research lane остаётся
  отдельным контуром без auto-close.

## Автономный срез доказательств — живой прогон C09 (2026-10-15)

- **План:** `docs/dev/plans/2026-10-15-01-c02-closure-capability-plan.md`
- **Отчет:** `docs/dev/reports/2026-10-15-01-c09-live-demonstration.md`
- **Статус:** `CAPABILITY_GAP_RECORDED` (B49)
- **Исполнение:** E6 Docker preflight PASS, Qwen3.6-35B живой ход 305с, категория `false_positive` подтверждена моделью. Отсутствие плана проверок в JSON оставило решение в fail-closed `INCONCLUSIVE`.

## Decision-ready ветка R6 — контракт, flow и измерение (2026-10-16)

- **План:** `docs/dev/plans/2026-10-15-02-decision-ready-triage-plan.md` (Amendment R6).
- **Реализовано (tasks 1–7):** контракт `decision-artifact/1` + `research-report/3` с валидатором
  человеческого контракта (≤2 environment-вопроса, ≤7 обязательных фактов, обязательная `unknown`-ветка,
  ответы строго Accept/Reject); envelope `internal/research/evidence_envelope.go`; бранчи `B-*` +
  `EnvironmentAssertion` (`branch_evidence.go`, `branch_evaluator.go`); движок `flow_driver.go`
  (PLAN→ACT→OBSERVE→REASSESS, ≤4 хода, fail-closed `--deterministic-only` → `PLANNER_FAILURE`);
  adapter `flow_adapter.go` для наследованных ходов; CLI `izyan research --decision-ready` и
  детерминированный `--replay-decision-run` (сравнение по content-hash); монотонная политика
  `configs/research/decision-policy.json`; human-first рендер первого экрана. Legacy-режим и
  `AutoClose=false` не изменены.
- **Измерительный стенд:** `eval/decision_ready/` — runner (manifest `decision-ready-manifest/1`,
  режимы replay/live/deterministic-only, классификация `NO_SNAPSHOT`/`NO_REPLAY`/
  `NOT_RUN_LIVE_PENDING_AUTHORIZATION`, fail-safe stop), metrics (human-decision-time percentiles,
  `repo_open_rate`, `missing_fact_rejection_rate`, env branch-change, accepted false-safe по классам,
  reopen/rerun, model calls/cost), `events.schema.json` для слепого двух-ревьюерного протокола,
  29 офлайн-тестов.
- **Измерено:** гард R6-G0 зелёный (replay C09 `NOT_AFFECTED`/`COMPLETE`/`auto_close=false`);
  корпоративные 18/18 — `NO_REPLAY`, fail-closed проба даёт 18/18 валидных `/3` с `HOLD_UNKNOWN`,
  `auto_close=false`, 0 model calls; VEX-Bench point-case controls 10/10 прошли `expect`,
  `false_safe=0`. Live-арм, слепое исследование и holdout — `NOT_RUN*` (см. отчёт task 7); human-work
  метрики (`repo_open_rate`, `missing_fact_rejection_rate`) не измерены — B51 остаётся открытым.

## Release evidence and symbol-unreachability R6 (2026-10-16)

- **Offline implementation:** the opt-in `research --decision-ready` lane now carries bounded release-artifact provenance (artifact SHA-256, selected binary member, build-info digest, release module graph and trust class) and the generic advisory-bound symbol-unreachability proof. `AUTHORITATIVE` release evidence grounds release/toolchain applicability; Docker/CI/go.mod declarations remain `SUPPORTING` only.
- **Offline fixture/guard coverage:** synthetic two-subject symbol fixtures keep partial coverage at `HOLD_UNKNOWN` and permit `CLOSE_NO_EXPLOIT_PATH` only through the authoritative `VerifyDecision` projection; the symbol route never yields `NOT_AFFECTED`. Supporting-only Docker evidence leaves stdlib applicability `UNKNOWN`. Artifact channel tests use generated temporary data and exercise provenance, bounded ZIP/cache handling and credential redaction.
- **Measured controller results:** focused package runs reported `internal/evaluator` 139 PASS/0 FAIL/0 SKIP; `internal/research`, `internal/goanalysis`, `internal/evidencetools`, `internal/repository`, `internal/affected` and `internal/domain` passed. A real component bundle resolved `RESOLVED`/`go1.25.10`/`AUTHORITATIVE` with a 143-module release graph; an oversized bundle failed closed as `NOT_RUN`/`ARTIFACT_SIZE_LIMIT`. These are offline/deterministic measurements; no live model/provider capability is claimed.
- **Remaining measured gap:** with the artifact, the release axis resolves, but an incomplete offline build closure still excludes product packages when `go list -deps -test -json ./...` attempts downloads; package-usage remains `unknown`, `run_govulncheck` errors, and the case remains `INCONCLUSIVE`/`INSUFFICIENT_SCOPE`. This is a generic follow-up, not a reason to weaken any negative gate.

## Anchored text-derived subjects R6 (2026-10-17)

- **Агентский контракт:** планнерская ревизия `eval/agent7/prompts/r6-plan-v5.txt` (пин в `eval/agent7/freeze/manifest.json`, wire через `rubrics/research.yaml`) заменяет запрет фабрикации субъектов на anchored-proposal правило: subject, который структурная декларация advisory не объявляет, но который назван в её записанном тексте, агент МОЖЕТ предложить — обязательно с членом `anchor` (verbatim-цитата из текста). Без якоря действует v1–v4 правило (`inapplicable_checks`, никогда не фабрикованный subject). Остальные инварианты сохранены: no expected-answer inference, absence-is-not-proof, symbol-негатив через `symbol-unreachability` с точной идентичностью.
- **Детерминистический gate:** `internal/research/subject_anchor.go` оборачивает registry каталога и валидирует извлечение до диспатча — якорь должен быть verbatim (whitespace-normalized) подстрокой записанного текста (`summary`, `description`, raw body), пакет обязан лежать внутри affected-модуля, идентичность — well-formed. Отклонения именуют причину: `SUBJECT_ANCHOR_MISSING`, `SUBJECT_ANCHOR_NOT_FOUND`, `SUBJECT_MALFORMED`, `SUBJECT_OUTSIDE_AFFECTED_MODULE`. Verdict-гейты неизменны: якорь только допускает проверку и никогда не даёт вердикт.
- **Provenance:** matched-поле и цитата записываются как `derived_from` на trace-запросе, в `flow-facts.jsonl` и в `decision.checks` отчёта (additive/omitempty; legacy `/1`/`/2` и anchor-less действия байт-идентичны).

## Plan-shape контракт и bounded self-repair R6 (2026-10-18)

- **Измеренный блокер:** живой прогон на реальном кейсе умер на шаге 1 — планнер выдал `module` членом действия (вместо `arguments`), strict decode отклонил ответ (`json: unknown field "module"`), терминация `PLANNER_FAILURE` без единой проверки на оплаченном ходу.
- **Агентский контракт:** планнерская ревизия `eval/agent7/prompts/r6-plan-v6.txt` (пин в `eval/agent7/freeze/manifest.json`, wire через `rubrics/research.yaml`) документирует точное размещение членов — три члена плана, шесть допустимых членов действия, все входы проверки только внутри `arguments` (`anchor` — член действия, не аргумента), отсутствующие опциональные члены опускаются, а не `null` — с конкретным примером каждой допустимой формы действия, engage-only формой (`actions: []`) и контрактом repair-хода. v1–v5 остаются замороженными для replay.
- **Bounded self-repair:** decode/contract-отказ — `flow.PlanContractError` (драйвер несёт отклонённый ответ verbatim); движок записывает первую попытку как `planner_error`, подаёт дословный вердикт и ответ обратно через `PlanInput.repair_error`/`repair_answer` (внутри FLOW_STATE) и принимает второй ответ как исход шага. Любая вторая ошибка — обычная терминация `PLANNER_FAILURE` с обеими попытками в событиях и manifest turns; любой другой класс ошибки терминален сразу. Контракт остаётся строгим: никакого permissive-декодирования и алиасинга членов; verdict-гейты неизменны.
- **Replay:** записанный `planner_error`, за которым следует ещё один ход планнера, по построению является отремонтированным — replay восстанавливает тот же класс ошибки через lookahead; прогоны, записанные до изменения (терминальный `planner_error`), replay-ятся байт-идентично.


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

## Human triage result — Phase 1 (2026-10-28)

`izyan triage` now delivers the accepted human result instead of a proof-only
verdict route. The live schema is `decision-package.v4` with four structurally
separate axes: model `judgment`, `proposed_action`, derived `premises`/`support`
and deterministic `machine_disposition` (including separate `automation`).
`assessment.v3` is the live agent schema; prior assessment/package versions are
version-specific historical playback, never silently upgraded authority.

Implemented surfaces:

- `DeriveSupport`: deterministic traversal of the action's decisive-claim
  closure with `INSUFFICIENT` / `LIMITED` / `SUBSTANTIATED` /
  `PROVED_WITHIN_SCOPE`; citations, measured observations, admitted proofs and
  interpretations stay distinct. No numeric confidence and no default level.
- Optional severity: absent severity/priority leaves the baseline absent and
  withholds machine reductions; the human package is still delivered.
- Action-first `decision.md`: action → rationale/judgment → recorded decision
  scope → facts → interpretations → assumptions/support → change conditions →
  Accept/Reject → machine disposition → collapsed audit.
- Append-only `human-decision.v2` binds canonical package hash, branch/projection
  hash and assertion IDs; comment is optional, system reason code is derived.
  `--record-decision` needs no model, network or `--out`.
- Offline `replay.v2`: verifies recorded hashes, re-derives support and machine
  admissibility, preserves judgment/action and copies review history verbatim.
- Offline `triage-evaluation.v1` (`izyan eval triage`): explicit external
  control, `ASSESSED`/`UNASSESSED` coverage, separate human/machine counters;
  live triage and replay never require a baseline or ground truth.
- Optional `triage-vex-projection.v1` stays default-off and non-authoritative;
  Product A authority is unchanged.

Acceptance tests: `TestTriageHumanResultAcceptanceMatrix` in
`internal/productb/triage`, and the CLI workflow
`TestTriageHumanResultAcceptRejectReplay` plus
`TestTriageHumanResultDoesNotPublishMachineSafe` and
`TestTriageHumanResultBudgetFinalization`. No quality, readiness or latency
improvement is claimed; the Phase 2–5 input/authority/deduplication/benchmark
work remains open.

## Recovery/completion Tasks 8–14 (2026-10-29)

The original Phase 4 Task 2 deletion lost capabilities. Its historical report is
not evidence of successful preservation. Recovery restored exact-record intake,
canonical requested-finding publication through `finding.Project` (`research-report/5`
plus `requested-case.json`), pure branch/proof/subject validators and historical
`/3`/`/4`/slice2/flow playback. `eval research-replay` preserves original bytes and
timestamps in a history-only envelope (`current_admission=false`); fresh canonical
admission remains required for publication. `attempts.go` stays the extraction owner.

The live research model harness and `flow_driver.go` stay removed. Legitimate
offline `--decision-ready --deterministic-only` probe and recorded-flow replay
remain functional, not no-op compatibility switches. No admission cache is added.
Current human review captures complete prepared environment branches (0–2
questions, explicit unknown, ≤7 mandatory premises). Append-only human assertions
select branches with explicit supersession; valid answers are not reasked.
Contradiction keeps open; overflow/incomplete branches are NOT_DECISION_READY.
Answers and Accept never change Product A authority. Offline replay preserves
assertion and decision bytes and creates no new Accept/timestamp.
- **B1 is evaluation-only.** `internal/productb/research` carries a package doc
  marking it a frozen evaluation control; its prompt/model/image stay frozen and
  it is reachable only as `izyan eval research-b1` — the top-level
  `izyan research-b1` command is gone.
- **Offline control plane.** Tracked `eval/decision_ready/{runner,run_census,regression_guard}.py`
  uses ordinary `research` for fresh current reports and `eval research-replay`
  for history. It produces indexes/summaries, binds run/input identity, isolates
  invocation outputs and rejects failed/stale/foreign reports. CI invokes the
  tracked controller; provisioned directories supply data only. Frozen labels,
  old artifact bytes and benchmark expectations remain unchanged.
- **Acceptance boundary.** `TestHumanCapabilityPreservationMatrix` exercises live
  scripted CLI, no-model answer/review/replay, canonical publication, retained
  historical owners and Python producer/failure paths. This is not corpus or
  human-time evidence. Broad tests/vet/race, Product A regression/census and paired
  authority measurement belong to the integration owner. Phase 4 Task 3 and the
  Phase 5 measurement lane remain open; no quality/latency claim is made.

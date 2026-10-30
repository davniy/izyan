# Izyan — Agent-driven Evidence Assessment: план работ v2 (A0–A10)

**Статус:** staged experimental implementation; 10.10.2026  
**Дизайн:** [01-agent-driven-evidence-assessment-design-v2.md](01-agent-driven-evidence-assessment-design-v2.md).  
**Цель:** доказать дополнительную **исследовательскую** ценность автономного агента относительно plain coding-agent и текущего Izyan; отдельно проверить экономику узких machine proofs. **Task 7 предыдущего экспериментального плана не считается проверенным.**

## 0. Правила исполнения

1. Не менять `izyan analyze`, старые verdicts/VEX/negative guards; новые ветки/CLI экспериментальные. Не начинать с production Verification Gate.
2. Не терять незакоммиченные изменения shadow. Выбор `shadow vs clean worktree` — отдельное решение по инвентаризации.
3. Каждая следующая фаза допускается только после явного `GO / ADJUST / STOP` с сохранёнными сырыми артефактами.
4. Разделить benchmark GT/reference и agent-visible repository. Известные 30 Go-кейсов — dev, не blind-holdout.
5. Отдельные `FAILED`, `INFRA_ERROR`, `INVALID_FORMAT`, `ABSTAIN`, `PROVIDER_REFUSED`; никаких невидимых best-of/замен попыток.
6. До масштабного runtime сначала дешёвая оценка proof-feasibility и минимальный исследовательский PoC. «No proof» не отменяет исследовательскую ценность.
7. Называть новые задачи **A0–A10**, не смешивать с Izyan Tasks 3–7, старым Task 7 в `llm-cve-analysis-roadmap.md`, B30/B32.
8. Для всех сравнений заранее фиксировать модель/версию runtime, prompt, tool permissions, бюджет, контейнер, scoring, attempt policy, acceptance и stop thresholds.

## Этап I — основание и дешёвая проверка гипотез

### A0 — Inventory, base selection и reuse audit (S)

**Сделать:**

- Снять `HEAD`, base/merge-base, `git status`, `git worktree list` локального `vuln-analyzer-shadow` относительно проверенного `master`. Сохранить полный diff, ничего не clean/reset.
- Инвентаризировать 31 MCP-tool, старые `internal/{affected,goanalysis,evaluator,llm,workflow,report}`, eval scripts, provenance, stale `/tmp` dependencies, frozen inputs и результаты Tasks 3–6.
- Провести `go test ./...`, smoke, compare core verdict distribution, ревизию capability boundaries и GT isolation; классифицировать компоненты `REUSE / ADAPT / REWRITE / DROP`.
- Проверить `docs/dev/roadmaps/llm-cve-analysis-roadmap.md`, B30/B32, предыдущий Task 7. Выписать, что реализовано, что существует только в документах и что нельзя использовать без проверки.
- Не включать переименование `module github.com/fedorovmv/izyan` в эту работу.

**Выбор:** использовать shadow, если воспроизводим и исследовательские изменения отделимы от core; иначе чистый worktree **того же** repo. Новый repo — только при доказанной технической/правовой невозможности reuse.

**Done:** `docs/dev/decisions/agent7-base-and-reuse.md` с commit SHA, command transcript, tests, mapping, accepted branch и рисками. Для первого PR достаточно A0 без нового кода runtime.

### A1 — Freeze experimental protocol и research scoring (S)

- Frozen manifest: case IDs/snapshot hashes, container digest, agent model/provider, tool exposure, prompts, token/time budget, scorer version, retries; у обоих arms одинаковые условия, кроме treatment.
- Разделить `B0` (current Izyan) и `B1` (plain coding-agent); исторические Task 3–6 сохранять как контекст, **не** как causal baseline. B0/B1 по возможности запускать на тех же snapshots в текущем протоколе.
- Создать независимую **research reference rubric**: root cause, attack mechanism, known affected manifestations, necessary conditions, evidence references, human follow-up effort; два ревьюера и arbitration для расхождений; ground truth не в runtime.
- Создать независимый holdout manifest/selection protocol и отдельный доступ curator до разработки. Ни одна запись GT, reference PR, экспертная рубрика или результаты не монтируются в sandbox.
- Записать заранее выбранные критерии Checkpoint A/B и протокол attribution/budget. Отдельно считать по **уникальным кейсам** и попыткам.

**Done:** `eval/agent7/freeze/manifest.json`, `protocol.md`, `research-rubric.md`, `security-boundary-check.md`; smoke на 2 safe, 2 exploitable и 1 infra fail; негативный тест запрета GT и review secrets.

### A1.5 — Proof Feasibility Preflight (S, перед Research Runtime)

**Сделать без новой LLM-модели и без построения checkers:**

- На 23 GT-safe **development-кейсах** оценить потенциальную применимость `ARTIFACT_FIXED`, `COMPONENT_ABSENT`, `BUILD_EXCLUDED`; классификации делает независимый контроллер/эксперт, они `AGENT_VISIBLE=false`.
- Для каждого указать `target_kind`, доступен ли *фактически поставленный* артефакт, build attestations, completeness binary inventory, advisory manifests, фактический Go toolchain, multi-module/generation/build variants, причины блокировки; уверенность квалификации.
- Получить на тех же target **baseline** существующего Izyan (в том числе версии/пакеты/build). **Не** считать старый безопасный verdict автоматически сертификатом: явно классифицировать проверенные возможности/сомнения, учесть known FS.
- Разделить потенциальные кандидаты: (1) plain deterministic proof без LLM, (2) proof, для которого агент может найти новый блокирующий фактор, (3) proof currently not machine-checkable. Отметить, где нет нужных данных, а где алгоритма.

**Done:** `eval/agent7/proof-feasibility.csv` + `proof-feasibility.md`, `baseline-proof-coverage.json`. Метрики: верхняя граница потенциальных eligible safe, overlap с текущим Izyan, *possible incremental safe*, expected data collection cost. Если incremental potential = 0, **не строить proof checkers**; исследовательские A2–A5 по-прежнему допустимы.

### Checkpoint 0 — Стоит ли вообще начинать кастомный research runtime?

Наблюдаемые A0/A1.5 результаты фиксируют, что reuse возможно, hidden GT гарантирован и proof branch имеет/не имеет потенциальную ценность. Решение `GO research / ADJUST environment / STOP proof`. Нет обязательного построения общего proof-validator.

## Этап II — исследовательская ценность прежде инфраструктуры

### A2 — Minimal Research Agent PoC (S/M, **без полноценного event store**)

- Выбрать готовый coding-agent runtime (из проверенных shadow/OCode/Codex), не писать собственный LLM engine.
- Одним небольшим экспериментальным prompt/protocol попросить исследовать CVE и назвать механизм, код root cause, entry/sink, альтернативные paths, необходимые условия и конкретные неопределённости.
- Использовать существующий `read/search` + запреты capability policy; никакого обязательного MCP и никаких tool-level машинных доказательств.
- Для smoke сохранить сырые transcripts и небольшие typed **candidate operations** (`declare_mechanism`, `declare_path`, `assert_condition`, `request_check`, `finalize_research`), но не реализовывать полный event sourcing. Отсутствие надежных операций — допустимое отрицательное наблюдение.
- Сравнить `B1 ↔ R0` в одинаковых условиях по independent expert rubric; `B0` — продуктовый reference по тому же snapshot.

**Done:** 8–12 dev-кейсов; минимум две разные CVE-механики, `k8s-44487`, `k8s-3121`, `rancher-47914`, `testify-28948`; каждый исследовательский отчёт содержит 7 смысловых разделов из дизайна §6, допускается `UNKNOWN` с конкретным follow-up. Показать ошибки/возможность вести альтернативные paths и менять мнение.

### Checkpoint A — R0 против plain coding-agent

**GO A3**, если протокол даёт **измеримую** дополнительную analyst usefulness (снижение времени проверки, повышение root-cause/path fidelity или проверяемость источников) без неприемлемого увеличения ложных safe-оценок и стоимости — конкретные пороги зафиксированы в A1. **STOP кастомный runtime**, если разницы нет: использовать plain coding-agent с минимальным экспортом результатов, не реализовывать A3 из-за архитектурной эстетики.

### A3 — Typed Research Operations + Replayable Dossier (M, условно после Checkpoint A)

- Реализовать `declare_mechanism`, `declare_path`, `assert_condition`, `link_observation`, `revise_assertion`, `retract_assertion`, `record_counterexample`, `request_check`, `finalize_research` как versioned ABI, один короткий event за шаг.
- Stable IDs, `expected_revision`, immutable observations, append-only log (monotonic sequence/idempotency), reject stale revision, cross-run/cross-target refs, store errors; DTO из дизайна §4–5.
- Deterministic dossier projection с изменением/отзывом старых утверждений, `CONFLICTED` после counterexample, unresolved questions и provenance. Не строить итоговый монолитный JSON средствами LLM.
- `ResearchAssessment` генерировать кодом из dossier с явными 7 разделами: mechanism, root cause, attack scenario, product exposure, alternatives, evidence, triage action.

**Done:** два механизма → несколько paths → revise/retract → stable replay, одинаковый canonical dossier hash; отказ tool не превращается в отсутствие; crash/recovery без потери истории; 100% корректных events проходят validation, malformed rejected без повреждения store.

## Этап III — избирательные tools и контраргументы

### A4 — Fact Broker + capability security (M)

- Подключить **не более 3–5** измеримо нужных Izyan facts поверх того же coding-agent: artifact/version/build, advisory/fix, symbol usage/dispatch, generated code по потребности; маппинг actual tool ↔ proposed API из A0.
- Tool outputs только `Observation{target,subject,query_scope,status,coverage,limitations,raw_digest}`; `FULL_FOR_QUERY` не global. Контролировать `context canceled`, go.mod errors, missing govulncheck, empty results.
- Разрешить чтение только через read/search + typed checks в disposable sandbox. Shell/process execution/egress по отдельной OS-enforced политике; prompt injection из исходников/advisory не должен менять permissions.

**Done:** error-as-absence, scoped-zero, `x/net` vs gRPC и generator vs generated code tests; GT/isolation/path traversal/secret leakage/redaction; нет произвольного запуска команд из tool payload. Tool failure rate и средняя стоимость вызова измерены.

### A5 — Multi-path & bounded counterexample pass (M)

- Агент строит независимые `mechanism_id`, `path_id`, conditions; учитывает alternative affected components, generated runtime, interface callbacks, dep-internal dispatch и deployment assumptions.
- Запустить ограниченный counterexample pass **тем же агентом** (не независимое голосование): конкретный candidate alternative или scope contradiction → новый `record_counterexample` + `request_check`/`revise_assertion`/open question.
- Не допускать «все известные пути исключены ⇒ CVE safe». Критичность/приоритет трекера не повышать автоматически.

**Done:** регрессии на четырёх известных False-Safe классах без case-specific prompt logic. Если agent не умеет найти альтернативный путь, ошибка отражается в research rubric; не помечать `MACHINE_VERIFIED`.

### Checkpoint B — matched ablation: добавляют ли tools и critic полезность?

Сравнить `R0 (read/search)` → `R1 (+Izyan facts)` → `R2 (+counterexample pass)` на одних snapshot/model/runtime/бюджетах. Сохранить полный raw attempts и повторы по case; GT/reference недоступны. Метрики: механизм/root cause, alternative paths, new correct observations, false-safe proposals, analyst effort, cost, tool reliability. Если R1/R2 не дают добавленной пользы, убирать компоненты; не оправдывать расширение числа tools их количеством.

## Этап IV — proof только при продемонстрированном потенциале

### A6 — Proof Obligations и independent eligibility (S, условно)

- Использовать итоги A1.5 и R2: фиксировать claim/subject/scope/target/advisory, возможный `ProofType`, какие входы/алгоритм нужны, local vs global result. Эту работу можно вести без LLM, на baseline facts.
- Для каждого proof candidate отдельно вычислять `FACT_VERIFIED`, `CVE_APPLICABILITY_VERIFIED`, `TARGET_COVERAGE_VERIFIED`; статус LLM и high-level `COMPLETE` не использовать для повышения.
- Допустимы статусы `UNSUPPORTED`, `INSUFFICIENT_INPUT`, `BLOCKED_ON_SCOPE`. Не создавать proof certificate из одного dossier без artifact bundle.

**Done:** decision matrix eligibility и unit-tests incomplete advisory, multi-artifact release, unknown build, affected-manifest extension, stale evidence. Не писать универсальные отрицательные проверки.

### A7 — Narrow checkers by feasibility priority (M, **необязательная**)

- Написать ровно те checker types из `ARTIFACT_FIXED`, `COMPONENT_ABSENT`, `BUILD_EXCLUDED`, для которых A1.5 нашёл точный источник и *дополнительную* product value. Прежде чем писать новый алгоритм, аудитировать существующие affected/build checks Izyan (и старый Task 7/B30/B32).
- Checker по versioned code удостоверяет факт по immutable target bundle, CVE applicability, target coverage; выдаёт scoped certificate с exact advisory/artifact/policy/verifier digest и invalidation triggers.
- Не принимать `ERROR/PARTIAL/no callers` как proof. Source hash ≠ delivery identity. Unknown toolchain для stdlib-CVE → `INSUFFICIENT_INPUT`.

**Done:** replay на bytes, fault/mutation/freshness tests, known FS never accepted, no CVE-id heuristics, no duplicate algorithms without ADR. Не поднимать старую LLM-оценку до authoritative verdict.

### A8 — Offline Disposition & incremental value (S, условно)

- `PR1`: offline-проекция `AUTO_CLOSE_ELIGIBLE/REVIEW_REQUIRED` от сохранённых R2 и baseline facts — **без новых LLM-вызовов**.
- Сохранить `ResearchAssessment` неизменным, писать certificates и policy decisions отдельно, а также human decision отдельно.
- Сопоставить `BaselineCertifiedSafe` (существующий Izyan, независимо проверенный) и `NewCertifiedSafe` с attribution агентных кандидатов.

**Метрики:** абсолютный certified-safe/SCR, **incremental-safe-clear = unique(new certified safe − baseline certified safe)**, agent-contributed proof rate, accepted unsafe cert cases, correct-safe lost, eligibility denominator, cost per incremental safe, per-checker verdict distribution.

### Checkpoint C — proof-продукт нужен?

**GO к расширенной валидации proof**, только если есть **ненулевая и практично ценная дополнительная автоматизация** относительно текущего Izyan, нет accepted known exploitable, scope/preconditions подтверждены и fault-injection fail-closed. Порог фиксируется до выбора A7 checker на основании A1.5, не подгоняется к результатам. При zero/near-zero increment — **STOP proof**, оставить качественный research lane.

## Этап V — blind evaluation и решение о внедрении

### A9 — Unseen holdout (M+)

- Независимый curator подготовил/frozen holdout по A1. Включить hard unknown manifestations, generated code, multi-module, stdlib release compiler, configurations, verified fixed artifacts и adversarial negative cases; без overlap dev/VEX-Bench/старых PR.
- **Перед открытием результатов** заморозить candidate prompt, agent/tool policy, checkers, scorer, budgets и acceptance. Blind runs с одинаковыми B0/B1/R0/R1/R2/PR1 где применимо. Проводить human reference scoring двумя независимыми экспертами.
- Публиковать case-level и attempt-level separate, uncertainty, failure classes, accepted unsafe cert, unique gain и аналитический effort. Нулевой наблюдённый FS не считать гарантией безопасности.

**Done:** immutable holdout manifest, blinded assessment sheet, disagreement arbitration, signed/offline review of checker trust boundary перед возможным auto-close.

### A10 — Architecture decision / opt-in release (S)

| Наблюдение | Решение |
|---|---|
| R0 ≈ plain coding-agent | Сохранить простой runtime/интеграцию; не внедрять сложный orchestration |
| R0/R1/R2 лучше по исследовательской рубрике, proofs не добавляют safe | Внедрить только `ResearchAssessment` для ручного triage |
| Отдельные tools дают устойчивую пользу | Оставить только подтверждённо полезные, MCP optional |
| Proof lane даёт incremental certified safe без unsafe cert + прошёл security review | Рассмотреть отдельное ограниченное opt-in auto-close/VEX с rollout/rollback |
| Unsafe certificate/scope breach | Запретить auto-close; расследовать, переоценить доверенную модель, новый blind test |

**Done:** `docs/dev/decisions/agent7-go-no-go.md` с delta относительно B0/B1, чекпоинтами, стоимостью, residual risk, границами доказуемости, rollback. Изменение `izyan analyze`, authoritative claims и governing spec — отдельный PR/CR **после** go decision.

## 6. Сквозная test matrix и организационные требования

- `tool ERROR + []` не доказывает отсутствие, `PARTIAL callers=[]` не равно `GLOBAL_UNREACHABLE`.
- `x/net patched` не закрывает gRPC/kubelet; generated generator ≠ runtime code; indirect dispatch нельзя «отменить» на основании отсутствия direct imports.
- `go.mod` directive не release toolchain; `replace`, vendor, `go.work`, tags, CGO, multi-module и доставка нескольких бинарей участвуют в binding.
- `declare_*` с неверным foreign target ID, stale revision, duplicate conflicting event или dangling evidence отклоняется; revise/retract проверяются через deterministic replay.
- `FACT_VERIFIED` без `CVE_APPLICABILITY_VERIFIED` или без `TARGET_COVERAGE_VERIFIED` не разрешает auto-close.
- Изменение advisory/artifact/build/policy digest аннулирует право использовать старый сертификат; proof checker заново читает доверенные input bytes.
- Shell/process execution по умолчанию недоступны; prompt injection в source/advisory/outputs не меняет capabilities.
- Old `izyan analyze` fixtures и golden verdict distribution не меняются; никакого автоматического повышения severity/priority.
- В eval no GT leakage, no best-of posthoc, no unreported retries, no merging Failed into safe.

## 7. Рекомендуемые пакеты и outputs (не создавать пустые заранее)

```text
internal/research/             # A2 runtime adapter; A3 operations+dossier
internal/factbroker/           # A4 selective typed facts, read-only
internal/proof/                # A6–A8 only if feasibility passes
internal/assessment/           # reporting / disposition projection

eval/agent7/
  freeze/manifest.json
  proof-feasibility.{csv,md}
  baselines/
  arms/{b0,b1,r0,r1,r2,pr1}/
  scoring/
  decisions/
```

Run outputs: `run-manifest.json`, `operations.jsonl`, `observations.jsonl`, raw transcript (redacted), `dossier.json`, `research-report.md`, `proof-obligations.json`, `certificates.json`, `disposition.json`, `tool-errors.jsonl`. Нативные agent tool calls сохраняются как операции без пересылки большого JSON модели.

## 8. Порядок PR и первый рабочий запрос coding-agent

**PR-0:** A0 + A1 (inventory, base choice, freeze, security boundary); **PR-1:** A1.5 (proof feasibility preflight); **PR-2:** A2 PoC + Checkpoint A. Только если полезность подтверждена — **PR-3:** A3 model operations/replay; затем A4/A5, а позже при необходимости A6–A8. A9/A10 отдельные фазы.

**Инструкция для первого PR:**

> Проведи A0–A1 из `02-agent-driven-evidence-assessment-plan-v2.md`. Изучи локальный `vuln-analyzer-shadow`, зафиксируй SHA, dirty changes и diff относительно `master`; проверь старый eval/MCP, GT isolation и `go test`. Выбери shadow или чистый worktree **в том же репозитории**, сохрани аргументацию. Заморозь протокол сравнения B0/B1/R0, без разработки нового agent runtime, без proof/checker кода и без изменений `izyan analyze`. Не удаляй чужие локальные изменения и не изменяй module path. Результат — воспроизводимые команды, ограничения, решения `reuse/adapt/drop` и frozen protocol. Затем остановись на checkpoint.

## 9. Риски и точки остановки

1. Измерить **сложность механизма**, а не лишь accuracy бинарной классификации; reference делается независимо от агентного текста.
2. Если задача research не выигрывает у plain coding-agent — не строить event framework «на перспективу».
3. Если proof eligibility низкая или старый Izyan уже покрывает все доступные negative types — не дублировать proof engine.
4. Если intended plain runtime невозможно безопасно sandbox'ить с shell/process/network — остановить A2 до решения security boundary.
5. Если невозможно идентифицировать доставленный артефакт или неполно advisory — выдавать лишь scoped research facts; ни один release-wide machine safe не допускается.
6. Если holdout стал известен модели/разработчикам, он перестаёт быть blind и заменяется без post-hoc отбора.

**Задачи A0–A10 — независимая серия, а не продолжение экспериментальных Tasks 3–7.** Новый контур может оказаться полезным даже при полном отказе от A6–A8.

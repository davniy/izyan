# Gap analysis: «чистый LLM ~100%» против `analyze --cve-analysis verified`

**Источник:** delegated `architect` artifact `agent://VexPipelineGapAnalysis` (2026-10-24), сохранён дословно.  
**Контекст:** Qwen3.6 VEX combined (25×1800 s + 5×3600 s), master vs postfix; проверка заявленного clean-LLM baseline и поиск гэпов. Код не изменялся, бенчмарки повторно не запускались.

**Главный вывод:** преимущество plain-LLM на этом корпусе действительно измерено, но **«~100% у Qwen3.6» артефактами не подтверждается**. Найденные **100% — recall Qwen3.8 на семи exploitable-кейсах после исправления извлечения JSON**, а не accuracy всего бенчмарка. Для Qwen3.6 plain зафиксированы **6/7 TP**, для текущего pipeline — **3/7 у master и 2/7 у branch**.

Разрыв нельзя объяснить только консервативными verdict-гейтами. Обнаружены конкретные потери:
- **до обращения к LLM** — неполный advisory scope;
- **при построении exploit model** — нерелевантные обязательные условия и неверная привязка patch;
- **при переводе исследования в claims/verdict** — ограниченные возможности repair и дополнительные mandatory-условия;
- **в сборе доказательств** — build/vendor failures, dependency-internal и interface scope, внутренние бюджеты;
- **в измерении** — разные scoring projections, окружения и attempt policies.

Ниже **PROVEN** означает подтверждение сохранённым артефактом или кодом; **INFERRED** — обоснованный, но не изолированный вывод; **UNKNOWN** — данных недостаточно. Исторические метрики подтверждены сохранёнными отчётами и freeze-индексом, **не повторным пересчётом отсутствующих raw attempts**.

Обозначения путей: **R** — `<VA_REPO>`, **B** — `bench` текущего workspace.

## 1. Что именно представляет собой clean baseline

### Метрики: не смешивать модель, projection и pipeline

| Режим | TP /7 | Correct safe /23 | Abstain | False-safe | False alarm | Failed |
|---|---:|---:|---:|---:|---:|---:|
| Qwen3.6 plain | **6** | 19 | 0 | 1 | 2 | 2 |
| Qwen3.8 plain, official | 6 | 20 | 0 | 0 | 2 | 2 |
| Qwen3.8 plain, parser-repair | **7** | 20 | 0 | 0 | 2 | 1 |
| Qwen3.6 pipeline master, combined | **3** | 13 | 7 | 2 | 3 | 2 |
| Qwen3.6 pipeline branch, combined | **2** | 9 | 16 | 1 | 2 | 0 |

Таким образом:
- Qwen3.6 plain: recall **85,7%**, accuracy **83,3%**.
- Qwen3.8 parser-repair: recall **100%**, accuracy **90%**, а не ~100% accuracy.
- Pipeline branch: recall **28,6%**, safe-clear **39,1%**; master: **42,9%** и **56,5%**.

Источники: `R/results/task4-c1/analysis/qwen-plain-vs-tools-FINAL.md:1-56`; `R/eval/baselines/vexbench/plain-agent-baseline-1.md:428-481`; `B/QWEN36-LLM-RUN.md:19-54`.

### Сопоставимость baseline

| Измерение | Что установлено |
|---|---|
| **Модель** | Plain: `Qwen/Qwen3.6-35B-A3B` и `Qwen/Qwen3.8-27B`. Текущий pipeline: `Qwen/Qwen3.6-35B-A3B`. Строка 100% относится **к другой модели**. |
| **Prompt** | Plain использует frozen `vuln`, SHA-256 prefix `c0a5c8458b77`: security analyst выбирает одну из 12 категорий, обосновывая source evidence. Pipeline разбивает задачу на root cause, mechanism, strategy, conditions, claims и review. |
| **Инструменты** | Plain означает **без Izyan/MCP**, не обязательно «один completion без инструментов»: это `opencode` coding agent над исходниками. Поздний сохранённый config разрешает `read/glob/grep`, запрещает shell/network/edit; идентичность effective permissions именно исторических Task-4 attempts сейчас полностью не проверяется. |
| **Корпус и labels** | Совпадают: **30 задач, 28 snapshots, 15 repos, 24 CVE; 7 exploitable / 23 safe**. В freeze и текущем manifest одинаковый task-list hash `60b55373…84b3`. Это не объяснение разрыва через другой набор кейсов. |
| **Входы анализа** | Не эквивалентны: plain получает CVE и source tree; pipeline привязан к выбранному advisory, dependency graph, patch и build target. |
| **Harness и дата** | Исторические Task-3/4 результаты заморожены **9 октября**, harness pin `c71f512a…`; точные timestamps исходных Qwen attempts сейчас не восстановлены. Текущий pipeline-прогон — **23 октября**, CLI harness, бинарные SHA `d337e823…` / `e58899fc…`. |
| **Повторы и бюджет** | Plain: n=1, timeout 1800 s; Qwen3.6 — **28 fresh + 2 cached protocol-smoke**, то есть exploratory mixed-admission. Текущий combined: один проход 1800 s с заменой пяти case-pairs результатами rerun при 3600 s. |
| **Scoring** | 7/7 у Qwen3.8 — отдельная **post-hoc parser-repair projection**, восстановившая полный корректный JSON по `k8s-3121`. Official score оставался 6/7. |
| **Воспроизводимость** | Raw plain roots `/tmp/vexbench-qwen-iso/{q36,q38}` сейчас недоступны. Сохранены отчёты, prompt и freeze-индекс. Revision/temperature endpoint не закреплены так, чтобы исключить cross-date drift. |

Источники: `R/eval/vexbench-prompts/official-vuln-c0a5c8458b77.txt:1-92`; `R/eval/c1/freeze/manifest.json:1-35,104-145`; `R/eval/task5/freeze/task4-reference.json:1-52,383-453,839-844`; `R/eval/baselines/vexbench/plain-agent-baseline-1.md:29-53,442-481,539-550`; `B/POST-FIX-MANIFEST.md:110-129`; текущие `metrics-qwen36-vex*.json`, поля `meta`.

**Ограничение safety:** Qwen3.8 с нулём FS в основном проходе затем давал false-safe на `k8s-3121`: **2/3 stability attempts после parser-repair и 4/5 risk-probe**. Это не оценка корпусного риска, но контрпример утверждению об устойчивой безошибочности. Источник: `plain-agent-baseline-1.md:490-512`.

**Итог сопоставимости:** сравнение полезно как **end-to-end сравнение подходов на одинаковом GT**, но не как причинный замер «добавили pipeline к той же модели и потеряли N пунктов». Современного matched control для такого вывода нет.

## 2. Где потеряны семь positive-кейсов

| Case | Qwen3.6 plain | Pipeline master | Pipeline branch | Установленный барьер |
|---|---|---|---|---|
| `caddy-8dc7667`, CVE-2025-29785 | TP | TP | TP | Сохраняется |
| `rancher-4dc4f53`, CVE-2025-47914 | **False-safe** | TP после rerun | TP | Pipeline здесь **лучше plain** |
| `kubernetes-e196d24`, CVE-2023-44487 | TP | **False-safe** | **False-safe** | Неполный advisory scope, **0 LLM calls** |
| `stretchr-285adcc`, CVE-2022-28948 | TP | TP | Abstain | Точный branch gate **UNKNOWN**: подробный отчёт удалён |
| `podman-6a65597`, CVE-2023-48795 | TP | **False-safe** | Abstain | Неверное platform-условие; branch не подменяет release toolchain значением go.mod |
| `cilium-1228cbc`, CVE-2026-35469 | TP | Abstain | Abstain | Точные unresolved conditions **UNKNOWN**: подробный отчёт удалён |
| `kubernetes-ec78c0f`, CVE-2021-3121 | TP | Abstain | Abstain | Root cause AMBIGUOUS, symbol lookup ломается на `-mod=vendor` |

Источники: `R/eval/baselines/vexbench/task4-qwen-plain-vs-tools.md:55-61`; `B/llm/results/per-case-qwen36-vex.jsonl:1,8,12,14,18,19,26`; rerun JSONL `:1`.

То есть branch относительно исторического plain **теряет пять positive-кейсов и приобретает один — rancher**. Это не монотонное ухудшение всех возможностей модели.

## 3. Причины по слоям

### A. Роль LLM и prompt: `verified` не означает «LLM самостоятельно решил и ответ проверен»

**PROVEN.** CVE research выполняет bundle → researcher → strategy planner → mechanism reviewer. Специфический эффект `verified` при успешном review — `AcceptLocusProposals=true`; это не прямое принятие конечного ответа модели. `CVEAnalysis` и `StrategyPlan` также используются для justification/report.

Но формулировка **«весь LLM только предлагает, все claims независимо доказаны» тоже неверна**:

- `ExploitModelBuilder` добавляет LLM-условия в `MandatoryConditions`;
- `ClaimEvaluator.acceptClaim` принимает LLM `TRUE`, если приведён хотя бы один существующий evidence ID — наличие ссылки не доказывает логическое следование;
- эти claims могут попасть в `c.Claims` через gap fallback.

Конечная функция verdict детерминирована, **но её входы не все имеют одинаковую доказательную силу**.

Источники: `R/internal/states/cveanalysis.go:15-75`; `R/cmd/izyan/main.go:658-706`; `R/internal/llm/exploit.go:143-159,217-246`; `R/internal/llm/agent.go:116-150`; `R/internal/states/gap.go:109-129`.

**INFERRED:** plain-LLM семантическое преимущество частично теряется при переводе свободного исследования в ограниченную vocabulary условий и поддерживаемых checkers. Доля этой причины количественно не изолирована.

### B. Applicability и identity: один верный scoped-факт превращается в неверный глобальный safe

**PROVEN — `kubernetes-e196d24` / CVE-2023-44487.**

Входной advisory `GHSA-qppj-fm5r-hxr3` перечисляет `golang.org/x/net`; snapshot содержит исправленный `v0.17.0`. Pipeline выдаёт `NOT_AFFECTED` **без LLM**. Между тем задокументированный vulnerable component этого GT-кейса — **`google.golang.org/grpc v1.55.0`**.

Harness индексирует CVE/aliases по **первому файлу в sorted-порядке**, а не по совокупности affected implementations. Получается:

> «Этот advisory-entry не затрагивает выбранную версию x/net» ≠ «данный CVE не эксплуатируется в продукте».

Источники: `B/.task10/run_compare_frozen.py:95-112`; retained Kubernetes branch `report.json:24-47,868-888,982-1018`; `R/eval/baselines/vexbench/external-baseline-1.md:54-63`.

Это **P0 safety-gap**, а не недостаток reasoning Qwen и не повод дать LLM переопределять deterministic version facts.

### C. Exploit model и patch: pipeline доказывает не то условие

**PROVEN — `podman-6a65597` / SSH Terrapin.**

Оба режима получают mandatory:

```text
C-PLATFORM: legacy TLS floor
go_version < 1.18
```

Оно приходит из общего `CRYPTO_DOWNGRADE` pattern, хотя кейс — SSH Terrapin.

- Master сравнивает условие с **go.mod minimum 1.20**, получает verified FALSE и закрывает кейс как NEPF.
- Branch требует настоящий release toolchain; его нет → `UNKNOWN` → abstain.
- **LLM reviewer master прямо указал**, что TLS condition нерелевантен SSH Terrapin и NEPF не обоснован. Тем не менее verdict сохранился.
- Branch CVE bundle привязан к `golang.org/x/crypto`, но исследуемый patch — **C-код libssh2 PR #1291**; binding содержит пустые hash/version, manifest `PARTIAL`, а semantic review — `passed:true`.

Источники: `R/internal/exploit/patterns.go:163-172`; podman master report `:2166-2173,25173-25180,26297-26331`; branch report `:2170-2180,33780-33787,34976-35040`; `R/internal/evaluator/platform.go:29-42,127-135`.

**Дополнительный PROVEN defect:** LLM-условия с `mandatory:false` всё равно могут оказаться в `MandatoryConditions`: merge не проверяет этот флаг, evaluator обходит весь slice. В podman это `C-CONFIG` и `C-ATTACK`, фигурирующие среди unresolved mandatory. Источник: `R/internal/llm/exploit.go:154,217-246`, branch report `:34342-34343`.

**Важное различие:** логика «одно доказанно ложное необходимое условие опровергает conjunction» сама по себе корректна. Исправлять нужно **необходимость, identity и provenance условия**, а не требовать знания всех остальных условий для каждого legitimate negative.

### D. Deterministic gates: часть abstention — корректная защита, часть — цена неполного анализа

**PROVEN.** Branch блокирует NEPF, когда mandatory FALSE не имеет verified negative, включая `INSUFFICIENT_SCOPE`. Для EXPLOITABLE нужны положительные claims по обязательным условиям.

В сохранённых safe-кейсах:
- **Headscale:** `htmlIntegrationPoint` имеет dependency-internal callers; ноль product references не исключает внутренний вызов. Verdict перечисляет `C-REACH/C-LOCUS/C-1: INSUFFICIENT_SCOPE`.
- **Istio:** похожий negative gate плюс `go list -deps` failure на CNI build constraints.
- В ingress/sink closure присутствуют open interface/function-value dispatch, `go:linkname`, `KNOWN_ONLY` sink set.

Источники: `R/internal/evaluator/verdict.go:108-170`; headscale branch report `:17764-17775,17890-17893,17972-17974,18622-18630`; istio branch report `:283,39158-39162`.

**INFERRED:** bounded dependency closure и более точный релевантный scope могут вернуть часть safe closures. Но просто убрать эти blockers — вернуть известный механизм false-safe: **«не нашли» → «доказали отсутствие»**.

### E. Evidence tooling, окружение и бюджеты

**PROVEN:**

1. Текущий target — host-default **darwin/arm64, CGO off**, без build tags. В podman/Istio зафиксированы build-constraint failures. Исторический agent работал в Docker и мог читать source без успешной Go-загрузки.  
   Источники: podman branch report `:1265-1277`; istio report `:283`; `B/POST-FIX-MANIFEST.md:282-300`.

2. `k8s-3121` завершился abstain за **11–13 секунд** из-за root-cause symbol lookup / `-mod=vendor`, **не timeout**. Исторический tools-анализ также путал generator `plugin/unmarshal` со сгенерированным runtime-кодом `generated.pb.go`. Последнее — подтверждённый исторический механизм, но не доказанный единственный нынешний blocker.  
   Источники: current JSONL `:26`; `task4-qwen-plain-vs-tools.md:80-88`.

3. Researcher рекламирует `analyze_product_scope`, но dispatcher его **не реализует**: доступны `read_patch_diff` и `inspect_source_file`, прочее возвращает unknown tool.  
   Источники: `R/internal/llm/research.go:69-76,197-198`; `R/internal/cveanalysis/tools.go:30-100`.

4. Помимо внешнего timeout есть отдельные лимиты: **32 LLM calls, 128 tool calls, 256 source reads, 2 review iterations**; в podman сохранён `closure query evaluation budget exhausted`. Отсутствие внешнего timeout не означает complete evidence.  
   Источники: Kubernetes report `:1004-1018`; podman branch report `:28928-28944`.

5. Два master `failed_parse` — **не ошибки JSON модели**, а nil-pointer panic в `ingressScan.ifaceCallArgs`, `ingress.go:1214`. Branch заканчивает эти кейсы abstain.  
   Источники: retained headscale/istio master `stderr.log:1-12`.

**Timeout больше не объясняет итоговый recall:** в combined профиле failed_timeout=0. При этом rerun rancher завершился быстрее 1800 s, поэтому нельзя приписать весь эффект только повышению deadline: возможны cache/runtime/model variation.

### F. Branch против master: safety/closure trade-off, не новое обнаружение

**PROVEN:** после объединения reruns branch:
- теряет **1 TP** — stretchr;
- теряет **4 correct-safe**;
- избегает **1 false-safe** — podman, и **1 false alarm** — echo;
- заменяет **2 master panic** на abstain.

Итого abstain растёт **7 → 16**, FS уменьшается **2 → 1**. Branch-only TP отсутствует. Точный причинный gate stretchr без отчёта неизвестен; наблюдаемое распределение нельзя целиком объявить эффектом одной policy.

### G. Benchmark construction и утрата диагностических артефактов

**PROVEN:**
- GT public VEX-Bench, safe-класс включает `requires_configuration`; текущий pipeline не получает отдельного deployment contract.
- Harness считает VEX `correct_safe` по verdict, **не требуя COMPLETE verification coverage**.
- Исторический compatibility score мог считать `uncertain` negative; текущий class table оставляет его abstain.
- Harness удаляет подробные отчёты, если нет false-safe/parse/timeout. Поэтому **stretchr, Cilium и несколько важных master↔branch расхождений сейчас нельзя разложить до decisive evidence**.

Источники: `B/.task10/run_compare_frozen.py:276-305,435-441`; `R/eval/baselines/vexbench/plain-agent-baseline-1.md:80-102`; task-list metadata.

## 4. Приоритетный план экспериментов и исправлений

Ожидаемый эффект ниже — **потенциал на известных кейсах, не обещание прироста**.

| Приоритет | Эксперимент / исправление | Эффект и риск | Acceptance criteria |
|---|---|---|---|
| **P0 — CVE/advisory scope** | Для `k8s-44487` сравнить frozen single-advisory и полный component-bound набор, включая grpc. Разделить scoped applicability и глобальный CVE verdict. | Убирает **1 текущий branch FS**; TP возможен, но не гарантирован. Максимальный safety-impact. | Исправленный x/net не закрывает CVE при непокрытом grpc; grpc/version явно отражены; исходный профиль сохранён отдельно. |
| **P0 — necessity и patch identity** | На podman изолировать три фактора: правильный x/crypto patch, отсутствие необоснованного TLS floor, отсутствие go.mod-as-release fallback. Ввести admission обязательного условия по механизму/advisory, а не только kind/symbol. | Устраняет доказанную причину master FS; может снизить искусственные branch UNKNOWN. | Нельзя получить safe через нерелевантный `go_version<1.18`; wrong-repo patch не получает component-authority; reviewer critique порождает проверяемый blocker/repair, не только caveat. |
| **P1 — matched control и trace** | На семи positives и выбранных safe-контролях сопоставить: plain `vuln`, deterministic-only, verified. Одна модель/provider, snapshots/advisories/target, фиксированные бюджеты и заранее заданные повторы. Сохранить proposal → merge → claim producer → verification → verdict. | Отделяет model/prompt loss от input/gate loss; приоритет — stretchr и Cilium. Низкий риск: control не authoritative. | Для каждого расхождения назван первый расходящийся этап; есть raw prompts/responses и tool statuses; official/repair/failure отдельно; никаких outcome-selected retries. |
| **P1 — executable evidence path** | Восстановить advertised product-scope tool; отдельно исправить mandatory:false merge и проверить fallback TRUE admission через независимую проверку claim, не только существование evidence ID. | Может вернуть TP/closures, одновременно закрывая authority blindspot. Количественный эффект UNKNOWN. | Каждый advertised tool имеет рабочий dispatch; optional не становится mandatory автоматически; нерелевантный evidence ID не делает claim TRUE. |
| **P1 — build и generated-code scope** | Для `k8s-3121`, podman, Istio изолировать target/toolchain/vendor проблему; отдельно связать generator vulnerability с runtime generated code. Не менять исходные snapshots. | Потенциально **1 TP** на k8s-3121 и несколько closures. | Нет ложного «symbol absent» вследствие loader failure; runtime generated path исследован; build failure остаётся UNKNOWN, а не negative proof. |
| **P2 — bounded negative closure и budget** | На Headscale и потерянных safe closures выяснить, какие blockers действительно пересекают affected path; повторять с одной изменяемой границей scope/budget. | Основной кандидат на рост safe-clear; высокий риск при механическом подавлении blockers. | Новая closure имеет bounded completeness proof; positive/dispatch counterexamples не закрываются; внешние и внутренние exhaustion различаются. |

**Обязательная предпосылка диагностики:** перестать удалять компактные evidence packets для abstain, false alarm и любых межрежимных расхождений; не обязательно хранить все AST/cache. Без этого повторится нынешняя невозможность объяснить потерю stretchr.

### Что не рекомендую как «быстрый фикс»

- **Не ослаблять negative gates ради recall:** podman показывает полезность branch fail-closed.
- **Не считать `--release-go-version` универсальным лечением:** в Terrapin проблема ещё и в нерелевантности самого условия.
- **Не ограничиваться safety prompt или большим timeout.** Safety-prompt P1 уже не дал устойчивого улучшения; сравнение с P0 было unmatched. Structured-evidence gate Task 6 блокировал реальный FS, но также **39/45 верных safe**, обнуляя SCR.  
  Источники: `R/eval/task5/checkpoint-a.md:7-18,48-60`; `R/eval/README.md:654-660`.
- **Не интерпретировать историческое ухудшение tools-arm как точную причинную декомпозицию нынешнего pipeline.** Оно подтверждает механизм преждевременного сужения scope, но использовало другой execution lane.

## 5. Оставшиеся неизвестные и итоговый шлюз

**P1 UNKNOWN:** точные gates текущих stretchr/Cilium; актуальный same-day plain baseline; роль каждого LLM adapter в итоговых TP; полные исторические effective permissions и model revision.

**P2 UNKNOWN:** переносимость результата за пределы 7 positives и public PR-derived корпуса; отсутствие benchmark familiarity у модели не доказано.

**Шлюз:** анализ достаточен для перечисленных **изолированных экспериментов**. Ослабление production safe/verdict-политики — **BLOCKED**, пока не закрыты P0 **scope completeness** и **necessity/identity обязательных условий**. Новый факт, меняющий эти основания, должен возвращать исправление на design review, а не обходиться локальным исключением.

**Практический вывод:** сначала исправлять **что именно pipeline считает уязвимостью и обязательным условием**, затем — **как исследование превращается в проверяемые claims**, и только потом расширять coverage и бюджеты. Смена Qwen или ослабление консервативности сами по себе эти доказанные дефекты не исправят.

### Указатели на retained reports

Все пути относительно `B/llm/cases/vex/`:
- Kubernetes branch: `kubernetes-kubernetes-e196d24-CVE-2023-44487/branch/CVE-2023-44487-1792764701/report.json`.
- Podman master: `containers-podman-6a65597-CVE-2023-48795/master/CVE-2023-48795-1792768581/report.json`.
- Podman branch: `containers-podman-6a65597-CVE-2023-48795/branch/CVE-2023-48795-1792769172/report.json`.
- Headscale branch: `juanfont-headscale-e172c29-CVE-2024-45338/branch/CVE-2024-45338-1792759600/report.json`.
- Istio branch: `istio-istio-8903f65-CVE-2024-45338/branch/CVE-2024-45338-1792770980/report.json`.

**Выполнено только чтение. Код и файлы не изменялись; тесты, сборки и бенчмарки не запускались.**
## 6. Критическое уточнение: какой маршрут фактически измерялся

**PROVEN.** Бенчмарк запускал:

```text
izyan analyze --cve-analysis verified
```

Это **deterministic-first analyzer с LLM-помощниками**, а не полноценный V2 LLM-first маршрут:

```text
CVE + advisory
  -> CheckAffected (может вернуть окончательный verdict до LLM)
  -> root cause / exploit model
  -> LLM helpers / evidence / review
  -> deterministic verdict
```

`CheckAffected` может сразу отправить кейс в `EvaluateVerdict`; CVE research вызывается позже, в `ResolveRootCause` (`internal/states/states.go:203-213,330-345`). Флаг `verified` не меняет эту последовательность.

Отдельные Product B маршруты не бенчмаркались:

| Контур | Команда | Назначение |
|---|---|---|
| Product A | `analyze` | authoritative, deterministic-first + LLM helpers |
| Product B | `triage` | LLM-first triage -> FactGate -> decision |
| Product B research | `research-b1` | агентное исследование CVE, не authoritative verdict |

Поэтому:

1. **29% (2/7) — результат `analyze + LLM helpers`**, не V2 LLM-first.
2. **Это не доказывает, что идея V2 не работает.**
3. **Это также не доказывает, что LLM-first + verifier сохранит 86–100%**: high plain-agent numbers ещё не прошли через verifier.
4. Для корректной проверки нужен отдельный замер цепочки **LLM-first discovery -> проверка гипотез -> verifier**, с двумя метриками: что нашёл агент и что подтвердил verifier.

Предыдущие P0/P1-гэпы (advisory scope, necessity/patch identity, claims/evidence, build/symbol scope, budgets) остаются валидными для маршрута `analyze`. Но вывод «pipeline теряет преимущество LLM» должен читаться с этой маршрутной оговоркой.

## 7. Сохранённый LLM-first прогон `kubernetes-e196d24` (Qwen3.6)

Архитектор разобрал уже сохранённый реальный агентный прогон (12 октября; итоговый отчёт пересобран replay’ем ответа, без нового вызова модели). Новый live-прогон не выполнялся.

| Этап | Результат |
|---|---|
| LLM получила возможность исследовать кейс | **Да** |
| LLM прочитала зависимости и HTTP/2-код | **Да** |
| LLM упомянула альтернативный путь через gRPC | **Да** |
| LLM правильно квалифицировала gRPC | **Нет** |
| Проверка допустила автоматическое закрытие | **Нет** |
| Контур дошёл до подтверждённого `EXPLOITABLE` | **Нет** |

Модель ответила `code_not_present`, аргументируя: «x/net исправлен до v0.17.0, gRPC использует тот же `x/net/http2`, значит исправление покрывает и его». В snapshot действительно `x/net v0.17.0` и `grpc v1.55.0`; gRPC содержит собственную серверную обработку потоков/`RST_STREAM`, поэтому импорт `x/net/http2` не доказывает исправление gRPC.

Проверяющий слой это поймал:

```text
agent category:        code_not_present
classification review: CONFLICTED
advisory scope:         GAP_DETECTED
disposition:            REVIEW_REQUIRED
auto_close:             false
```

Он явно записал, что исправленный x/net подтверждает только этот компонент, а путь через gRPC остаётся непроверенным.

**Вывод:** идея «LLM исследует, verifier не даёт довериться неверному выводу» на этом примере работает как предохранитель. Но преимущество по обнаружению ещё не получено: LLM-first не гарантирует правильный разбор gRPC; результат остановился на конфликте и ручном review.

**Граница:** это разбор старого research-прогона, не проверка текущего объединённого `triage`. Для живого эксперимента нужен запуск текущего `izyan triage` на этом snapshot с сохранением transcript, observations и decision; старый отчёт его не заменяет.

Источники: `eval/agent7/e2e/k8s-44487/report.md:129-154,162-189,205-223`; `eval/agent7/e2e/k8s-44487/run-manifest.json:12-35`.

## 8. Найденная причина №1: prompt запрещает исследовать компоненты вне advisory

**PROVEN.** В сохранённом Kubernetes-прогоне действует `ADVISORY_BINDING_RULES`, п. 2 (`eval/agent7/prompts/r0-v1.txt:90-97`):

> Если компонент не указан среди affected entries advisory, **не анализируй его как часть этого CVE**, выдай UNKNOWN и прекрати рассуждение о нём.

В advisory есть `x/net`, но нет `gRPC`. Получается прямое противоречие:

```text
Цель LLM-first: найти все относящиеся к CVE компоненты и пути.
Prompt:         не исследуй компонент, которого нет в выбранном advisory.
```

То есть **ограничение допуска доказательств перенесено в ограничение поиска гипотез**. Это разные задачи:

- первый слой должен уметь обнаружить, что advisory неполон;
- второй слой проверяет identity, applicability и доказательства найденной гипотезы;
- отсутствие компонента в одном advisory — повод проверить связь, а не запрет исследования.

Наличие ограничения доказано; **степень его влияния нужно устанавливать парным экспериментом**, а не по одному ответу.

### Другие отличия от успешного plain-baseline

| Plain VEX-Bench | Research/triage контур |
|---|---|
| Frozen prompt `vuln` | Переписанные инструкции + binding rules |
| Ответ `{category, reasoning}` | Дополнительно восемь обязательных разделов assessment |
| Исследование CVE по исходникам | Заранее выбранный advisory задаёт рамку |
| Нет Izyan MCP | В других вариантах добавляются tools и их интерпретации |

`research-b1` сохраняет исходный prompt как префикс, но добавляет `USE_BASED_VERDICT`; `triage` использует отдельный evidence-bound prompt и `assessment.v1` (`internal/productb/research/prompt.go:9-16,22-93`; `internal/productb/triage/prompt.go:17-38`). Поэтому «используем frozen baseline prompt» не означает равенства полного запроса модели.

### Что делать

Сначала восстановить baseline первого слоя, не настраивая одновременно исследование и verifier:

```text
Первый проход: исходный VEX prompt + исходные возможности исследования
  -> неизменённые category + reasoning + transcript
  -> отдельное извлечение гипотез/доказательств
  -> детерминированная проверка
```

Первый ответ оценивается отдельно; `REVIEW_REQUIRED` не должен скрывать ухудшение discovery. Формализация не должна заставлять исследователя преждевременно сужать поиск.

### Минимальный эксперимент (Kubernetes / CVE-2023-44487)

Одинаковые Qwen3.6, snapshot, бюджет и доступ к файлам; без подсказок про gRPC/GT; заранее заданные повторы:

| Плечо | Изменение |
|---|---|
| A — контроль | точный исходный VEX prompt и простой ответ |
| B | + frozen advisory |
| C | + restrictive advisory-binding rules |
| D | + расширенный assessment-формат |
| E | + Izyan tools |

Это локализует, на каком изменении теряется правильное исследование. Если A не воспроизводит прежний результат, сначала проверять модель/provider, effective permissions и параметры запуска.

**Критерий:** первый слой не хуже matched plain-контроля по обнаружению и корректным safe-ответам, без роста false-safe и technical failures. Один кейс локализует причину; подтверждение — на общем корпусе.

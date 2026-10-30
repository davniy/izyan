# Кросс-решение по консолидации: Shadow как база, V2 как reference/evaluation lane

**Назначение:** decision record по итогам сравнения двух реализаций Izyan (Shadow и V2); определяет базу, портируемые компоненты, заморозку и порядок интеграции.
**Источник:** delegated `architect` artifact `agent://IzyanArchDecision` (2026-10-20), сохранён дословно; в конце — verification addendum от main.
**База сравнения:** Shadow `118e10c`; V2 `6bcce89`.
**Смежные документы:** [`2026-10-20-03-architecture-decisions.md`](2026-10-20-03-architecture-decisions.md), [`2026-10-20-02-architecture-status.md`](2026-10-20-02-architecture-status.md), [`../plans/2026-10-20-01-remaining-work-roadmap.md`](../plans/2026-10-20-01-remaining-work-roadmap.md).

> **Verification status (2026-10-20):** independent `implementer` re-check — `DECISION STANDS`. Known inaccuracies in the architect's body (§§1–3) are corrected in the addendum below and in [`2026-10-20-05-independent-verification.md`](2026-10-20-05-independent-verification.md). Port scope must additionally include V2 `goanalysis.ImportClosure` / `EnumerateImportClosure`; without it `evidencetools/verify_code_absence.go` and `agenttriage` falsifier do not compile.
>
> **Approach-level review (2026-10-20):** [`2026-10-20-06-approach-decision.md`](2026-10-20-06-approach-decision.md) — `PRIOR DECISION CONFIRMED` as **dual-product**: authoritative deterministic analyzer on Shadow + separate LLM-first research/triage product on V2 components. LLM may propose; deterministic contracts decide.
>
> **Target architecture:** [`../roadmaps/2026-10-20-target-architecture-and-roadmap.md`](../roadmaps/2026-10-20-target-architecture-and-roadmap.md) — gaps, roadmap phases and implementation spec backlog.

---

# Решение

**База = Shadow (`118e10c`).**  
**Портировать = из V2 только generic triage/evaluation/research-механизмы и усиления scope-кернела, адаптировав их к Shadow identity/evidence контрактам.**  
**Заморозить = параллельную разработку V2 core, V2 auto-dismissal и LLM-first production authority; V2 оставить как reference/evaluation lane.**  
**Следующий шаг = создать интеграционную ветку от Shadow и последовательно перенести сначала V2 shipping-scope kernel/filter, затем triage/verification shell, сохраняя Shadow единственным источником authoritative verdict.**

## Короткий вывод

Глобальное превосходство одной реализации по всем осям **не доказано**:

- **Shadow доказанно сильнее как production deterministic analyzer**: есть identity-bound artifacts, ticket guard, implementation-presence route, exact post-reach config route, authoritative sidecars и измеренное корпоративное закрытие `7 NOT_AFFECTED / 1 NO_EXPLOIT_PATH_FOUND / 10 INCONCLUSIVE`.
- **V2 доказанно сильнее как research/evaluation/CI shell**: generic `agenttriage`, universal verifier, replay/mutation gates, blind evaluation и более высокая completion/speed research lane.
- Но V2 research-преимущество не является production security proof: dev-ablation дал `2/36 false-safe`, universal verifier остаётся `default-off`, а deterministic kernel на корпоративной матрице не закрыл ни одного case.

Приоритет продукта — не максимальная completion LLM-исследования, а `false-safe=0`, отрицательная верификация, identity и воспроизводимость. Поэтому база должна быть Shadow.

---

# 1. Верификация ключевых чисел

## 1.1. Shadow

| Утверждение | Статус | Evidence |
|---|---|---|
| Census: `7 NOT_AFFECTED / 1 NO_EXPLOIT_PATH_FOUND / 10 INCONCLUSIVE` | **PROVEN** как распределение сохранённого прогона | `<VA_TMP>/r6-final/census-artifacts-comparison.json:1-258`; `r6-guard-baseline.json:1-104` |
| Census не изменился между baseline и fresh | **PROVEN** | `census-artifacts-comparison.json`: у всех 18 rows `status=OK`, `changed=[]` |
| Corpus: `38/38`, `false-safe=0` | **PROVEN** из сохранённого stdout | `<VA_TMP>/corpus-final2.txt:79-82`: `cases=38 errors=0 expect pass=38 ... false-safe=0 inconclusive=3` |
| `R6-GUARD PASS`, `deterministic_safe=7/18`, `false_safe=0` | **CLAIMED/частично воспроизводимо** | Заявлено в `docs/dev/reports/2026-10-20-02-architecture-status.md:649-650,874-875` и commit notes; baseline и guard-код сохранены: `eval/decision_ready/regression_guard.py:195-233`. Сам stdout guard-прогона отдельно не сохранён |
| Case 10 закрыт через verified symbol-unreachability | **PROVEN** | `<VA_TMP>/r6-final/fresh-artifacts/case-10/report.json:3719-3736`: `NO_EXPLOIT_PATH_FOUND`, `falsifier=declared-symbol-unreached`, `negative_verification=VERIFIED`, `coverage=COMPLETE` |
| Case 04 закрыт через implementation-presence axis | **PROVEN** | `<VA_TMP>/r6-final/art-1103/case-04-final/report.json:869-875,917-935,4075-4104`: `vulnerable_implementation_present=FALSE`, Linux target, product scope, `NOT_AFFECTED/COMPLETE` |
| Case 03 остался открытым при enriched advisory | **PROVEN** | `<VA_TMP>/r6-final/art-1103/case-03-final/report.json:19720-19724`: `INCONCLUSIVE`, `may_call=127`, `dep_sites=3`, `NodeIterator.MoveNext` имеет live calls |
| Cases 07/08 остаются открытыми из-за IBM MQ SDK | **PROVEN** | `<VA_TMP>/r6-final/fresh-artifacts/case-07/report.json` и `case-08/report.json`; limitations указывают failed packages и отсутствие `cmqc.h`/SDK |

Важная оговорка: census artifact доказывает распределение и стабильность прогона, но не содержит независимой разметки exploitable cases. Поэтому `false-safe=0` в census — это результат guard-контракта и заявленной human-labelled базы, а не независимый blind safety benchmark.

## 1.2. V2

| Утверждение | Статус | Evidence |
|---|---|---|
| Autonomous corpus `38/38`, `false-safe=0` | **CLAIMED**, не полностью proven из сохранённого raw output | `docs/dev/reports/2026-10-20-02-architecture-status.md:595-596`; `docs/dev/history/features/2026-10-17-falsifier-ingress-triage-v2-status.md:181-184` описывает stdout как внешний артефакт, но сам stdout в V2 не сохранён |
| Exact inconclusive count в corpus | **CONTRADICTORY/не установлено** | Один документ говорит `inconclusive=2` (`...2026-10-17...:181-184`), другой — `inconclusive=3` (`...architecture-status.md:596`) |
| VEX-Bench e2e: `9/9`, `false_safe=0` | **PROVEN** для research lane и данного sample | `results/agent7/e2e-blinded-eval/join-rerun2/metrics.json`; `comparison.md` |
| Holdout ablation: `9/9`, `false-safe=0` | **PROVEN** для 3 новых кейсов × 3 повтора | `results/agent7/holdout-ablation/ABLATION.md`; `join2-usebased/metrics.json` |
| Holdout completion/speed advantage: `9/9`, ~73 s против ~901 s | **PROVEN** для этого experiment | `ABLATION.md`; `join2-usebased/metrics.json`; `join2-plain/metrics.json` |
| Use-based research production-safe | **ОПРОВЕРГНУТО** | `results/agent7/rootcause-ablation/dev-comparison.json`: baseline `2/36 false-safe`, citation arm также `2/36`; статус зафиксирован в `architecture-status.md:524-543` |
| Universal verifier: `6/85` machine dismissals, `false_safe=0` | **PROVEN как offline replay measurement** | `.superpowers/sdd/universal-verifier-plan/task-5-report.md:36-58`; `progress.md`; 85 runs, 6 dismissals, 0 false-safe |
| Universal verifier production-ready | **ОПРОВЕРГНУТО/не доказано** | `task-5-report.md:45-52,96-100`: `universal-eligible=0/39`, recall exploitable class не измерен, для statistical precision ≥95% нужно ≥59 admissions, capability `DEFAULT-OFF` |
| Deterministic kernel: `0/45` closures | **PROVEN с уточнением знаменателя** | `.superpowers/sdd/kernel-reachability-filter-plan/progress.md:47-61`: `0/39 groups closed`, `45 tickets unchanged`; raw evidence не является буквально одной таблицей `0/45`, поэтому корректная формулировка — «0 закрытых групп, 45 applicable tickets без изменений» |

### Критическая разница в интерпретации чисел

`V2 6/85` и `V2 9/9` нельзя напрямую сравнивать с Shadow `7/18`:

- V2 universal verifier прогонял **85 human-NE cases**, то есть положительный exploitable class отсутствовал.
- V2 `9/9` — research output на малом blind sample, а не production verdict.
- Shadow `7/18` — deterministic safe closure на реальных corporate snapshots, с artifact/build identity и сохранённой authoritative evidence.
- Поэтому V2 показывает качество research/evaluation machinery, но не превосходство как authoritative analyzer.

---

# 2. Сравнение архитектур

| Ось | Shadow | V2 | Решение |
|---|---|---|---|
| **Authoritative verdict** | Deterministic `VerdictEvaluator`; `NOT_AFFECTED` только через affected chain; `NO_EXPLOIT_PATH_FOUND` только через verified falsifier | Deterministic analyzer тоже сохраняет эту границу; triage/research отделены | Общий контракт; Shadow core зрелее |
| **Identity** | Ticket package-version guard, release artifact channel, build-info, target scope, assumptions | Snapshot/content hash и binary Go version есть; но текущий `internal/affected` не содержит Shadow ticket guard/implementation axis; текущий `internal/repository` — только `service.go` | Shadow |
| **Affectedness** | Цепочка включает `vulnerable_implementation_present`; G2 детерминированно закрывает platform-specific implementation absence | В текущем V2 `internal/affected/` присутствуют `resolver.go`, `golist.go`, `range.go`, но нет `implementation.go`; `internal/evaluator/verdict.go:1-90` содержит только module/version/package/build axes | Shadow |
| **Negative verification** | Exact subject scope, dep-internal checks, dynamic/interface gates, sidecar rehydration, trace pairing | Generic verifier, C14, claim shapes, cross-run/mutation gates; production admission default-off | Shadow как verdict engine; V2 как offline verifier/evaluator |
| **Config-origin safety** | G1 требует positive exact sink reach, advisory-bound sink closure, exact `ArgIndex`, per-site DataFlow, complete origin, product-scope assumption | В V2 есть provenance/config-origin evaluator (`internal/evaluator/provenance.go:149-223`), но нет Shadow `postreach.go`/`SinkSetBasis` exact route | Shadow |
| **Large authoritative proofs** | Content-addressed sidecars, digest/size/selector, fail-closed rehydration; tests на tamper/removal | Observation archive и replay есть, но Shadow sidecar contract не ported в current V2 research lane | Shadow |
| **Corporate real-case coverage** | 18-ticket census: 7/1/10; case 10 closed, case 04 closed through G2 | Kernel applicable to 45/85, 0 closures; 6 verifier dismissals on all-NE corpus | Shadow |
| **Research lane** | Strong deterministic research lane, but narrower research/eval shell | Stronger agenttriage, use-based prompt, recovery, grounding, refindex, blind/holdout tooling | V2 |
| **Reproducibility/audit** | EvidenceGraph, ToolExecution, identity-bound reports, sidecars, assumptions, trace pairing | Observation archive, decision package, C14, stability, offline replay, held-out gate | Both strong; contracts need one consolidation |
| **Maturity** | Deterministic analyzer is already operational against real cases | Large generic shell exists, but 92.9% of verifier corpus had no machine decision; core closure remains open | Shadow |
| **Remaining work** | Focused: census wiring, case-03 bounded closure, external SDK 07/08, owner-gated positive input evidence 01/02/17/18 | Broad P1 backlog: kernel importer/dispatch closure, advisory symbol source, evidence-index, live triage validation, positive-labeled verifier corpus, root-cause quality | Shadow has lower production risk |
| **Strategic value** | Deterministic static kernel and evidence-first verdict authority | Research/LLM/CI lane and evaluation infrastructure | Combine, but do not make research lane the base |
| **Merge cost** | Add V2 shell/adapters to a mature core | Port Shadow’s late identity/G1/G2/sidecar contracts into an older, structurally different core | Port V2 into Shadow |

---

# 3. Почему V2 нельзя выбрать базой по текущему состоянию

## 3.1. Документация V2 описывает больше, чем есть в текущем source tree

V2 status/reference утверждает наличие:

- implementation axis;
- G1 exact post-reach configuration route;
- G2 implementation-locus route;
- authoritative sidecars;
- Shadow-derived deterministic research lane.

Например, это заявлено в `docs/dev/reports/2026-10-20-02-architecture-status.md:524-543` и `:650-661`.

Однако на текущем V2 HEAD `6bcce89`:

- `internal/affected/` содержит только `resolver.go`, `golist.go`, `range.go`, tests;
- `internal/domain/` не содержит Shadow `assumptions.go`, `implementation.go`, `target.go`, `exploitlocus.go`;
- `internal/repository/` содержит `service.go`, без Shadow `artifact.go`, `assumptions.go`, `releaseevidence.go`;
- `internal/research/` содержит старый lightweight research lane (`research.go`, `replay.go`, `grounding.go`, `answer.go` и т. п.), но не Shadow `deterministic.go`, `decision.go`, `flow_driver.go`, `implementation_axis_test.go`, `deterministic_payload_test.go`;
- `internal/evaluator/` не содержит Shadow `postreach.go`.

Это не означает, что V2 бесполезен. Это означает, что его architecture-status нельзя принимать как доказательство наличия всех описанных production механизмов. Для решения нужно опираться на текущий source tree, а не на claims документов.

## 3.2. V2 kernel был реально портирован, но позднейшие Shadow изменения не были перенесены

Git evidence:

- V2 создан через merge `1f40fc5785348bbcf7cc855d29aeff24297c0ed5` из старого `master` и Shadow lane `a65056a...`; это подтверждается `.git/FETCH_HEAD`, `.git/logs/HEAD` V2 и `docs/dev/decisions/agent7-base-and-reuse.md:24-30,113-118`.
- V2 commit `138de57` прямо называется `port the deterministic symbol-unreachability kernel from the shadow line`.
- Далее V2 развивал kernel filter и triage:
  - `27dc274`, `3cb3ed6`, `fc2ad8d`, `8db0a80`;
  - `1e126ff` — reachability filter;
  - `f61ef72` — shipping-scope closure/dynamic-marker relevance.
- Shadow после исходного lane продолжил развиваться коммитами `0ed5ca0`, `b639903`, `d3f53c6`, `500b367`, `e22223f`, `785f407`, `4b25b64` и далее до `118e10c`. Эти позднейшие identity/artifact/G1/G2/sidecar изменения в V2 current core не находятся.

Иными словами:

- V2 содержит часть Shadow kernel и добавляет к нему полезный scope filter.
- Shadow содержит более поздний production identity/evidence/verdict слой.
- Ни одна сторона не является полным надмножеством другой.

---

# 4. Git provenance и масштаб расхождения

## Установлено

Shadow — это worktree основного `vuln-analyzer`:

```text
vuln-analyzer-shadow/.git
→ gitdir: <VA_REPO>/.git/worktrees/vuln-analyzer-shadow
HEAD → refs/heads/feat/shadow-analyzer-agent
```

Текущий ref:

```text
118e10cf261f077f835d6200fbb5f141df67c31b
```

V2 — отдельный standalone repository:

```text
vuln-analyzer-v2/.git/HEAD
→ refs/heads/master
refs/heads/master
→ 6bcce89a4244d6b5f3e25bd575353fa47c8aeb3c
```

Исторически зафиксировано:

```text
git merge-base master feat/shadow-analyzer-agent
→ c97fb926916d4431c812e9700e4504b084cfe87e

git rev-list --left-right --count master...feat/shadow-analyzer-agent
→ 2 109

git diff --shortstat c97fb926..a65056a
→ 198 files changed, 60014 insertions(+), 97 deletions(-)
```

Источник: `docs/dev/decisions/agent7-base-and-reuse.md:24-30`; `docs/dev/decisions/agent7-provenance.md:17-37`.

### Оговорка

Эти SHA относятся к pre-rewrite provenance. Основной `vuln-analyzer` позднее прошёл `git filter-repo`; V2 сохранил старые object IDs, Shadow использует переписанную историю. Поэтому **точный текущий merge-base между `118e10c` и `6bcce89` нельзя честно назвать одним SHA без дополнительного commit-map сопоставления**.

Это не уменьшает архитектурный вывод: consolidation будет полноценной интеграцией двух divergent lines, а не fast-forward merge.

Перед реализацией нужно выполнить:

```bash
git merge-base <mapped-shadow-head> <v2-head>
git rev-list --left-right --count <mapped-shadow-head>...<v2-head>
git diff --shortstat <merge-base>..<shadow-head>
git diff --shortstat <merge-base>..<v2-head>
```

с учётом:

```text
<VA_REPO>/.git/filter-repo/commit-map
<VA_REPO>/.git/filter-repo/ref-map
```

---

# 5. Что именно портировать

## A. Портировать V2 kernel scope hygiene

Портировать в Shadow, но не как новую decision authority:

- `internal/goanalysis/unreachability_scope.go`;
- `internal/goanalysis/unreachability_dynamic.go`;
- связанные `unreachability_filter_test.go`;
- scope-aware filtering из `1e126ff`/`f61ef72`;
- `internal/evidencetools/verify_code_absence.go` и coverage-rule mechanics, если они нужны для offline triage.

Эти механизмы полезны, потому что они:

- различают `LIVE / DEAD / UNKNOWN`;
- не отбрасывают candidate site без доказанного `DEAD`;
- учитывают shipping roots, `main`, imports и `init`;
- делают dynamic-marker relevance subject-aware;
- сохраняют discarded sites как audit;
- убрали тысячи ложных blockers: `2149 module_entry`, `1327 may_call`, `37 skipped_package`, `34 dependency_call`, `27 interface_dispatch`.

Но acceptance должен быть:

```text
filter уменьшает шум,
но не превращает UNKNOWN/open scope в FALSE;
false-safe остаётся 0;
0/39 closure не считается успехом само по себе.
```

## B. Портировать V2 generic triage shell

Портировать адаптированно:

- `internal/agenttriage`;
- `finding.v1` / `assessment.v1`;
- FactGate;
- proposal-only falsifier ingress;
- `DecisionPackage`;
- `ALLOW/WARN/BLOCK`;
- stability/replay/audit;
- baseline-bound false-safe metrics;
- C14-style integrity checks.

Но:

- Shadow `AnalysisCase`, `EvidenceGraph`, `AnalysisCase` identity и `VerdictEvaluator` остаются canonical;
- V2 domain/evaluator/affected/repository не мержить поверх Shadow;
- agenttriage должен ссылаться на Shadow `Evidence`, `NegativeVerification`, artifact identity и assumptions;
- `DISMISSED` не должен появиться в production автоматически.

## C. Портировать V2 generic verification/evaluation tooling

Оставить как offline/experimental tooling:

- `internal/claimshape`;
- `internal/verification`;
- `internal/heldoutgate`;
- `cmd/heldout-gate`;
- `cmd/claimshape-report`;
- mutation/cross-run/stability harness.

Условия включения production admission:

1. corpus с human-positive exploitable cases;
2. не только all-NE corpus;
3. `universal-eligible > 0`;
4. ≥59 независимых eligible admissions для заявленного ≥95% precision;
5. positive-class recall measurement;
6. matched replay без cross-run leakage;
7. отдельное решение после этих измерений.

До выполнения условий capability остаётся `default-off`.

## D. Портировать research/evaluation lane

Портировать как advisory tooling:

- `internal/refindex`;
- `internal/reportcheck`;
- use-based prompt/recovery;
- VEX-Bench freeze/scoring;
- blind evaluation artifacts;
- root-cause metrics.

Не переносить их результаты в Shadow authoritative verdict. V2 сам фиксирует это ограничение:

- use-based lane — experimental;
- `2/36 false-safe` на dev;
- root-cause recall на реальных кейсах — `0`;
- research category не меняет deterministic verdict.

---

# 6. Что не портировать

Не переносить в Shadow как core:

- V2 `internal/affected` поверх Shadow `internal/affected`;
- V2 `internal/domain` поверх Shadow domain;
- V2 `internal/evaluator` поверх Shadow evaluator;
- V2 lightweight `internal/research` как замену Shadow deterministic lane;
- V2 docs claims без corresponding source/tests;
- V2 production auto-dismissal, пока capability default-off;
- отдельный второй `VerifyUnreachable`;
- второй набор verdict/claim/assumption contracts.

Правило консолидации:

> Один authoritative core, один identity contract, один verdict evaluator, один negative-verification contract. Остальные линии — adapters или offline tooling.

---

# 7. Что заморозить

1. **V2 core analyzer** — никаких новых параллельных изменений в `internal/affected`, `internal/domain`, `internal/evaluator`, `internal/repository`.
2. **Shadow core** — остаётся базой и единственным местом authoritative verdict.
3. **Universal verifier admission** — оставить `default-off`.
4. **Use-based LLM verdict** — оставить research/evaluation-only.
5. **Независимое развитие двух kernel implementations** — остановить; V2 scope filter переносится в Shadow и далее развивается только в одной ветке.
6. **Дублирование документации** — после интеграции оставить один canonical status/roadmap; текущие V2 reports не использовать как implementation inventory без сверки с source tree.

---

# 8. Отклонённые альтернативы

## Альтернатива 1: V2 как база

**Отклонена.**

Причины:

- текущий V2 source не содержит Shadow implementation-presence/G1/G2/sidecar/ticket mechanisms, которые описаны в reports;
- kernel на corporate matrix не закрыл ни одной группы;
- verifier dismissals измерены на all-NE corpus и production default-off;
- перенос Shadow identity/evidence layer в V2 потребует reverse-integration в более старую и структурно другую core-модель.

## Альтернатива 2: полный merge Shadow + V2 без владельца core

**Отклонена.**

Приведёт к двум competing contracts:

- два `AffectedResult`;
- два набора `Evidence`/`Observation`;
- два negative verifier;
- два пути replay;
- неоднозначное право на `NOT_AFFECTED`/`NO_EXPLOIT_PATH_FOUND`.

Это хуже, чем исходная параллельная разработка.

## Альтернатива 3: Shadow-only без V2 компонентов

**Отклонена.**

Shadow core лучше, но V2 принёс реальную стратегическую ценность:

- generic CI triage;
- proposal-only ingress;
- replay/stability;
- held-out/mutation gate;
- research/evaluation discipline.

Эти компоненты следует сохранить, но не делать их source of truth.

## Альтернатива 4: V2 research-first / LLM-first production

**Отклонена.**

Evidence:

- `2/36 false-safe` в dev ablation;
- root-cause recall `0` на measured real cases;
- universal verifier `6` admissions, statistical lower bound `0.393`, не ≥95%;
- `universal-eligible=0/39`;
- capability `default-off`.

## Альтернатива 5: создать третью чистую базу

**Отклонена.**

Это увеличит provenance и migration risk, не добавляя доказанной capability. Уже есть одна база с production deterministic closure и одна с validated research/eval machinery.

## Альтернатива 6: продолжать параллельную разработку

**Отклонена.**

Две линии уже повторно реализовали один kernel и расходятся по identity/evidence contracts. Дальнейшее параллельное изменение увеличивает:

- стоимость backport;
- риск разных verdict semantics;
- риск несовместимых artifact schemas;
- риск того, что measurements будут относиться к разным scopes;
- стоимость ручного аудита.

---

# 9. Риски решения

## Риск 1: стоимость адаптации V2 triage к Shadow domain

Это основной технический риск. V2 triage написан вокруг собственной модели `agenttriage`/`verification`, Shadow — вокруг `AnalysisCase`/`EvidenceGraph`/`research.VerifyDecision`.

**Ограничитель:** не переносить domain wholesale; сначала сделать adapter на один falsifier shape и один replay path.

## Риск 2: V2 scope filter может конфликтовать с Shadow scope semantics

Shadow уже имеет свои `goanalysis` bounds, skipped-package semantics и `NegativeVerification`.

**Ограничитель:** переносить только через adversarial fixtures:

- skipped package;
- live/unknown/dead shipping package;
- interface dispatch;
- function values;
- dynamic markers;
- cgo;
- build tags;
- missing import edges.

Любое несоответствие должно оставлять `INCONCLUSIVE`, а не закрывать negative.

## Риск 3: stale documentation

Оба status document имеют устаревший commit header:

- Shadow status описывает `4b25b64`, текущий HEAD — `118e10c`;
- V2 status описывает `210de52`, текущий HEAD — `6bcce89`.

**Ограничитель:** implementation inventory строить по source tree и tests; reports использовать только как index/evidence map.

## Риск 4: provenance после filter-repo

V2 хранит pre-rewrite object IDs, Shadow — post-rewrite history.

**Ограничитель:** перед интеграцией сохранить commit-map и зафиксировать logical source mapping; не смешивать raw SHA без mapping.

## Риск 5: потеря внешних артефактов Shadow

Census и case reports находятся вне repository:

```text
<VA_TMP>/r6-final/
```

**Ограничитель:** до любых изменений заархивировать:

- census comparison;
- guard baseline;
- corpus stdout;
- case-03/04/10 reports;
- raw observations;
- sidecars;
- hashes.

---

# 10. Что изменит решение

Рекомендация должна быть пересмотрена, если выполнится хотя бы одно из условий:

1. **Shadow не воспроизводит собственный baseline**:
   - корпус перестаёт давать `false-safe=0`;
   - census `7/1/10` не сохраняется без объяснимого input drift;
   - case-10 или case-04 теряют complete proof.
2. **При адаптации выяснится, что Shadow sidecar/identity contracts не выдерживают adversarial replay**.
3. **V2 получает и доказывает полноценный deterministic core**, включая:
   - ticket/build identity;
   - implementation axis;
   - exact G1/G2 routes;
   - authoritative sidecars;
   - matched corporate cases;
   - no regression against Shadow corpus.
4. **V2 verifier получает positive-class holdout**, `universal-eligible > 0`, ≥59 independent admissions и измеренную recall, при этом production gate остаётся `false-safe=0`.
5. **Изменится policy priority**: если продукт официально станет research assistant с human-only output, а не authoritative analyzer, тогда V2 research lane может стать внешним product shell. Это не текущая архитектурная цель и потребовало бы отдельного policy решения.

---

# 11. Следующий шаг и критерий интеграции

Создать одну ветку от Shadow:

```text
consolidation/shadow-base
```

Порядок:

1. Зафиксировать текущие Shadow/V2 refs, commit-map и внешние artifacts.
2. Проверить Shadow baseline:
   ```bash
   go test ./...
   go vet ./...
   go run ./cmd/izyan eval --corpus eval/corpus-real.json -j 1
   ```
   Ожидаемо: сохранение `false-safe=0`.
3. Перенести V2 shipping-scope/dynamic filter в отдельный integration commit.
4. Прогнать adversarial `goanalysis` tests; ни один open/unknown case не должен перейти в safe negative.
5. Перенести минимальный V2 triage slice:
   - one finding;
   - one proposal-only falsifier;
   - one replay;
   - one `WARN/UNCHANGED` path;
   - no production auto-dismiss.
6. Затем перенести held-out/mutation/evaluation tooling.
7. Только после этого перенести research/refindex/reportcheck lane.
8. Повторить matched checks:
   - Shadow corpus: `38/38`, `false-safe=0`;
   - census: `7/1/10`, без unexpected drift;
   - case-10: `NO_EXPLOIT_PATH_FOUND/COMPLETE`;
   - case-04: `NOT_AFFECTED/COMPLETE`;
   - V2 verifier: hard gates сохранены;
   - V2 triage: default-off для semantic close.

Итоговая архитектурная граница:

```text
Shadow deterministic core
    → authoritative identity / affectedness / evidence / negative verification / verdict

V2 triage + verification
    → optional CI shell and offline admission evaluator

V2 research/evaluation
    → advisory lane, benchmarks, grounding, human triage

LLM
    → proposal/research only
```

Это прекращает дублирование, сохраняет доказанную production-базу Shadow и не теряет наиболее ценные generic/evaluation компоненты V2.

---

## Verification addendum (main, 2026-10-20)

Spot-check артефактов и source tree после решения; архитектурный вывод не меняется.

1. `V2 internal/repository` на `6bcce89` — не «только `service.go`»: присутствуют `releaseevidence.go`, `preflight.go`, `contenthash.go`. Shadow-контрактов `artifact.go`/`assumptions.go` там по-прежнему нет.
2. Утверждение §3.1 о том, что V2 status/reference заявляет implementation axis/G1/G2/sidecars, не подтвердилось: эти claims находятся в Shadow `2026-10-20-02-architecture-status.md:355-533`, а не в V2 status. V2 documents этих механизмов не заявляют.
3. Source-level различие сохраняется и проверено: в V2 `internal/` нет `VulnerableImplementationPresent` и `postReach` (grep: 0 совпадений); `internal/affected` содержит `resolver/golist/range`, без `implementation.go`.
4. Измеренная база решения подтверждена: Shadow census `7 NOT_AFFECTED / 1 NO_EXPLOIT_PATH_FOUND / 10 INCONCLUSIVE`, 18 rows, `changed=0`; V2 holdout usebased `9/9`, `false_safe=0`, wall ~73 s vs ~901 s plain.

Что это меняет: §3.1 следует читать как «V2 не содержит поздних Shadow-контрактов», а не как «V2 docs завышают inventory». Остальные основания решения (0/39 kernel closures, verifier default-off, 2/36 dev false-safe, Shadow case-04/10 closures) не затронуты.
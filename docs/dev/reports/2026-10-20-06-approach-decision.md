# Approach-level decision: LLM-first vs deterministic core + LLM helper

**Назначение:** architecture review по оси подходов, дополняющий [`2026-10-20-04-cross-solution-decision.md`](2026-10-20-04-cross-solution-decision.md); отвечает на критику, что предыдущее решение было codebase-centric.
**Источник:** delegated `architect` artifact `agent://ApproachReviewLLMVsDet` (2026-10-20), сохранён дословно.
**Вердикт:** `PRIOR DECISION CONFIRMED` — dual-product: authoritative deterministic analyzer (Shadow) + LLM-first research/triage product (V2 components).
**Смежные документы:** [`2026-10-20-05-independent-verification.md`](2026-10-20-05-independent-verification.md), [`2026-10-20-03-architecture-decisions.md`](2026-10-20-03-architecture-decisions.md), [`2026-10-20-02-architecture-status.md`](2026-10-20-02-architecture-status.md), [`../plans/2026-10-20-01-remaining-work-roadmap.md`](../plans/2026-10-20-01-remaining-work-roadmap.md), [`../roadmaps/2026-10-20-target-architecture-and-roadmap.md`](../roadmaps/2026-10-20-target-architecture-and-roadmap.md).

---

# Architecture review: LLM-first vs deterministic core + LLM helper

## Вердикт

# **PRIOR DECISION CONFIRMED**

Предыдущее решение подтверждается, но теперь формулируется точнее:

> **Выбор продукта: (c) dual-product** — авторитетный deterministic analyzer на базе Shadow и отдельный LLM-first research/triage product на базе сильных компонентов V2.

Авторитетная часть dual-product — это **deterministic core + LLM helper**.  
LLM-first допускается для discovery, root-cause analysis, research и предварительного triage, но не для выпуска authoritative security verdict.

Это не означает, что deterministic approach доказан как лучший навсегда. Доказано более узкое и практически важное утверждение:

> При текущей цели продукта — authoritative analyzer, `false-safe = 0`, отрицательная верификация, identity и replay — production authority должна оставаться deterministic.

Продуктовая цель уже фиксирует этот выбор, поэтому `NEEDS_INPUT` не требуется.

---

## 1. Статус evidence

Обозначения:

- **PROVEN** — подтверждено сохранённым артефактом, исходным кодом или независимой перепроверкой.
- **CLAIMED / LIMITED** — измерение существует, но его область действия или воспроизводимость ограничены.
- **UNPROVEN** — нет достаточного evidence для данного вывода.

### Ключевые факты

| Факт | Статус | Значение |
|---|---|---|
| Shadow: 18 corporate cases → `7 NOT_AFFECTED / 1 NO_EXPLOIT_PATH_FOUND / 10 INCONCLUSIVE` | **PROVEN** | Есть измеренные safe-negative и unresolved outcomes; safe result не форсируется |
| Shadow: corpus `38/38`, `false-safe=0` | **PROVEN для этого корпуса** | Это regression/safety gate, но не независимое универсальное доказательство |
| Shadow case-04 | **PROVEN** | `NOT_AFFECTED/COMPLETE` через implementation-presence axis |
| Shadow case-10 | **PROVEN** | `NO_EXPLOIT_PATH_FOUND/COMPLETE` через verified symbol-unreachability |
| V2 deterministic kernel | **PROVEN ограничение** | `0/39` corporate groups closed; `45` applicable tickets unchanged |
| V2 universal verifier | **PROVEN как offline measurement** | `6/85` dismissals, `false-safe=0`, но весь корпус human-NE, `universal-eligible=0/39`, capability default-off |
| V2 research holdout | **PROVEN как research experiment** | `9/9`, `false-safe=0`, примерно 73 секунды против 901 секунды plain lane |
| V2 research production safety | **ОПРОВЕРГНУТО / UNPROVEN** | Dev ablation: `2/36 false-safe` в обоих arms |
| V2 root-cause quality | **LIMITED / слабое evidence** | На измеренных реальных кейсах locus recall = `0` |
| LLM-first authoritative production | **UNPROVEN** | Нет matched positive/negative production benchmark с доказанной completeness, identity и negative verification |

Источники: [предыдущее cross-solution решение](2026-10-20-04-cross-solution-decision.md), [independent verification](2026-10-20-05-independent-verification.md), [Shadow status](2026-10-20-02-architecture-status.md), [V2 status](file://<VA_REPO_V2>/docs/dev/reports/2026-10-20-02-architecture-status.md).

---

# 2. Таксономия подходов

## 2.1. Что означает LLM-first

LLM-first определяется не наличием LLM в системе, а тем, **кто владеет следующим авторитетным переходом**.

### Уровень A — discovery / root-cause / advisory interpretation

LLM-first означает:

1. модель интерпретирует advisory, patch или CVE;
2. модель выбирает defect locus, mandatory conditions и возможные sinks;
3. deterministic tools используются для проверки, уточнения или поиска контрпримеров;
4. результат может быть полезным даже без terminal verdict.

Это допустимая область для LLM-first: ошибки обычно превращаются в неверную гипотезу или дополнительный human review, если downstream authority не доверяет гипотезе автоматически.

### Уровень B — triage / prioritization

LLM-first означает:

1. модель формирует assessment, severity/prioritization или disposition;
2. deterministic слой может проверять claims, блокировать явно небезопасные действия или применять policy;
3. но основная семантическая рекомендация исходит от модели.

Если deterministic composer сам решает `ALLOW/WARN/BLOCK`, а LLM только предлагает факты или следующий шаг, это уже не LLM-first authority, а deterministic triage с LLM helper.

### Уровень C — authoritative verdict / negative verification

LLM-first означает:

1. модель может самостоятельно установить `NOT_AFFECTED`, `NO_EXPLOIT_PATH_FOUND`, `NOT_EXPLOITABLE` или эквивалентный safe disposition;
2. deterministic слой проверяет формат, отдельные факты или ограниченный набор contradictions;
3. модельное решение является необходимым условием для закрытия case.

Deterministic core + LLM helper означает обратное:

- identity, scope, facts, completeness и claims принадлежат deterministic layer;
- LLM может предложить locus, condition, falsifier или следующий эксперимент;
- LLM не может создать authoritative evidence, `ClaimFalse`, `NegativeVerification=VERIFIED` или terminal verdict.

---

## 2.2. Где находятся Shadow и V2

| Уровень | Shadow | V2 |
|---|---|---|
| **A. Discovery/root cause** | **Deterministic core + LLM helper.** LLM proposals проверяются source/build/evidence слоями | **Разделённая модель.** `izyan analyze` детерминистичен; `izyan research` фактически LLM-first research lane |
| **B. Triage/prioritization** | Нет сопоставимого широкого LLM-first triage shell; есть deterministic evidence/research lane и optional LLM assistance | **LLM-led interaction, deterministic admission.** Agent assessment и research сильнее, но semantic dismissal остаётся verifier/composer responsibility и default-off |
| **C. Authoritative verdict** | **Deterministic core**: affected chain, evidence, negative verification, verdict evaluator | **Deterministic analyzer/verifier.** LLM production authority отсутствует; universal admission default-off |

Критически важно:

> Ни Shadow, ни V2 не имеют доказанного LLM-first authoritative production verdict.

V2 действительно содержит LLM-first research/triage machinery, но это не означает, что V2 доказал LLM-first security authority.

---

# 3. Сравнение подходов

## 3.1. Уровень A: discovery, root cause, advisory interpretation

| Ось | LLM-first | Deterministic core + LLM helper |
|---|---|---|
| **Coverage / completion** | Шире семантическая область: модель может интерпретировать новый advisory, patch или нестандартный root cause без заранее описанного rule. В V2 use-based holdout completion была `9/9`, но это малый research sample; на реальных замерах locus recall был `0`. | Ниже первоначальная semantic coverage, если нет rule/KB/source resolver. Но каждый найденный результат имеет явную scope/completeness семантику. Shadow оставил `10/18` corporate cases `INCONCLUSIVE`, а не замаскировал пробел. |
| **False-safe** | Риск появляется уже на стадии неправильной идентификации CVE или locus. V2 dev ablation: `2/36 false-safe` в baseline и citation arm. | Proposal не может сам стать safe-negative. Shadow corpus/guard дал `false-safe=0` в заявленном корпусе. Это не абсолютное доказательство, но boundary принципиально безопаснее. |
| **Auditability / replay** | Raw model response сам по себе плохо является audit artifact: важны prompt, model/version, tool calls, source snapshot, retrieved advisory и reasoning. V2 имеет frozen prompt и replay, но это доказательство воспроизводимости research lane, не semantic correctness. | EvidenceGraph, ToolExecution, typed claims, assumptions, sidecars и replay являются частью authority contract. LLM conversation не требуется для повторного verdict. |
| **Identity** | Модель может перепутать CVE, vendor, affected component или fix. Именно misidentification была причиной V2 `2/36 false-safe`. Identity pinning возможно, но требует deterministic enforcement. | Advisory, ticket, package/version, source/artifact, target и build identity проверяются до authority. Shadow имеет ticket-build guard, artifact channel и implementation axis. |
| **Reproducibility** | По природе stochastic. Frozen prompt, fixed model и replay снижают drift, но не превращают semantic answer в deterministic fact. | Один и тот же persisted case и evidence дают тот же deterministic decision; модель может быть вызвана повторно только для нового proposal. |
| **Cost / latency** | Может быть существенно быстрее для semantic search. В V2 holdout use-based lane: примерно `73 s` против `901 s` plain lane. Это измерение конкретного model/prompt/sample, не общий production TCO. | Deterministic analysis может быть тяжелее и требует загрузки исходников, graph analysis и closure. Его преимущество — не гарантированная дешевизна, а предсказуемая цена и отсутствие model call в replay. |
| **Human review effort** | Снижает initial search effort и помогает объяснить незнакомый advisory, но ошибка модели требует проверки всего reasoning chain. Высокая completion не равна меньшему security review. | Оставляет больше `INCONCLUSIVE`, но review направлен на именованные blockers: missing SDK, open dispatch, incomplete scope, missing input-control evidence. |
| **Failure modes** | Misidentified advisory, hallucinated locus, unsupported semantic leap, prompt/context confusion, missing source identity, overconfident interpretation. | Missing KB/rule, incomplete source index, unresolved dynamic behavior, conservative demotion, `INCONCLUSIVE` вместо ответа. |
| **Ability to close real corporate cases** | Может дать быструю гипотезу, но текущие evidence не показывают безопасного corporate closure: V2 research E2E имел discrepancies, а root-cause recall на измеренных реальных cases равен `0`. | Уже закрывает часть реальных случаев через typed deterministic routes: case-04 и case-10; общий census — `7/1/10`. |
| **Extensibility** | Сильна для новых advisory families, необычного кода и неизвестных patterns. Цена — сложнее доказать regression и safety. | Новые semantic capabilities добавляются через KB, resolver или typed proposal contract; расширение медленнее, но сохраняет safety boundary. |

### Вывод по уровню A

LLM-first здесь полезен и должен быть сохранён. Но его правильная роль — **semantic accelerator**, а не источник security fact.

На этом уровне V2 имеет стратегическое преимущество над текущим Shadow shell, и это является достаточным основанием портировать его research/evaluation machinery.

---

## 3.2. Уровень B: triage и prioritization

| Ось | LLM-first | Deterministic core + LLM helper |
|---|---|---|
| **Coverage / completion** | Может быстро классифицировать большое количество findings и объяснять приоритет. Однако в V2 universal verifier `6/85` получил machine dismissals, а `92.9%` ответов не получили machine decision; `universal-eligible=0/39`. | Completion ниже, потому что reduction разрешён только при закрытом scope и проверенном falsifier. Зато `UNCHANGED` — корректный результат, а не failure, который нужно скрывать. |
| **False-safe** | V2 all-NE verifier corpus показал `false-safe=0`, но positive exploitable class отсутствовал, recall не измерялся, capability default-off. Research dev ablation показал `2/36 false-safe`. | Safe disposition допускается только через deterministic admission. Если evidence недостаточно, остаётся `UNCHANGED`/`INCONCLUSIVE`. Это поддерживает `false-safe=0`, хотя может уменьшать automation rate. |
| **Auditability / replay** | V2 имеет сильный shell: FactGate, canonical locators, C14, observation archive, mutation tests, cross-run checks и offline replay. Это доказанная сильная сторона V2. | Deterministic composer и policy replay могут быть canonical source of triage outcome. LLM assessment хранится как input/proposal, но не как proof. |
| **Identity** | LLM может неправильно связать finding с advisory или subject. V2 поэтому вводит immutable snapshot, advisory binding и FactGate; без этих механизмов LLM triage небезопасен. | Identity и subject coverage проверяются до policy result; LLM не может расширить affected subject set или заменить advisory. |
| **Reproducibility** | Оценка модели нестабильна: V2 фиксировал verdict flips `3/5` в triage-related measurements. Frozen inputs и stability retries помогают, но модельная рекомендация не становится deterministic. | Composer, verifier, policy и replay deterministic. Повторное решение не зависит от новой генерации текста. |
| **Cost / latency** | Снижает стоимость первичного analyst triage и может быстро дать prioritization. Измеренные `73 s` use-based против `901 s` plain подтверждают потенциал, но не safety. | Может быть дороже на case, если требуется полный evidence collection. Зато не тратит model budget на повторную верификацию и может кэшировать deterministic facts. |
| **Human review effort** | Может сократить ручное чтение однотипных findings, но при отсутствии admission reviewer всё равно должен проверять safe reduction. `92.9% unchanged` означает, что массового production auto-close пока нет. | Review концентрируется на cases, где действительно не хватает scope или policy input. Ширина human review выше, но риск скрытого safe-close ниже. |
| **Failure modes** | Нестабильная приоритизация, over-trust к agent assessment, превращение `NOT_EXPLOITABLE` в `DISMISSED` без proof, cross-run evidence leakage, prompt injection. | Консервативный `UNCHANGED`, неполный claim-shape coverage, слишком низкий reduction rate, необходимость ручной triage escalation. |
| **Ability to close real corporate cases** | Текущий V2 verifier не доказал corporate triage closure: `6/85` на all-NE corpus и `0/39` eligible kernel groups не являются production proof. | Может закрывать только те cases, для которых есть complete deterministic falsifier. Shadow уже показывает этот режим, но пока с существенным `INCONCLUSIVE`. |
| **Extensibility** | V2 здесь наиболее силён: generic `agenttriage`, `finding.v1`, `assessment.v1`, proposal-only ingress, claimshape, held-out gate, replay и evaluation tooling. | Хорошая extensibility при условии, что новые triage rules выражаются через deterministic evidence contract, а не через специальные model exceptions. |

### Вывод по уровню B

В production triage нужен **dual mode**:

- LLM-first interaction для поиска, объяснения и prioritization;
- deterministic composer/verifier для любого действия, которое может закрыть или снизить finding.

До появления positive-labeled holdout, измеренного recall и достаточного числа eligible admissions V2 dismissal capability должна оставаться default-off.

---

## 3.3. Уровень C: authoritative verdict и negative verification

| Ось | LLM-first | Deterministic core + LLM helper |
|---|---|---|
| **Coverage / completion** | LLM-first может искусственно повысить completion, потому что модель способна выдать verdict даже при неполном scope. Это не улучшение coverage, а риск скрытого UNKNOWN. Текущего доказательства безопасного LLM-first completion нет. | Coverage ограничена тем, что можно доказать. Shadow получил terminal closure для `8/18` cases (`7 NOT_AFFECTED + 1 NO_EXPLOIT_PATH_FOUND`) и оставил `10/18` inconclusive. |
| **False-safe** | Главный риск. `9/9` research holdout не является production proof: sample мал, а independent verification отмечает отсутствие official ground truth. Dev `2/36 false-safe` прямо опровергает production-readiness. | `NOT_AFFECTED` и `NO_EXPLOIT_PATH_FOUND` имеют разные deterministic routes. `NO_EXPLOIT_PATH_FOUND` требует named falsifier и `NegativeVerification=VERIFIED`; incomplete scope остаётся `INCONCLUSIVE`. |
| **Auditability / replay** | Чтобы быть приемлемым, LLM-first должен хранить prompt, model, tool calls, all retrieved inputs, evidence graph, identity, scope and complete reasoning. Даже тогда auditability не доказывает correctness. | Shadow имеет identity-bound evidence, authoritative sidecars, digest/size/selector checks, trace pairing и fail-closed rehydration. Replay не требует LLM. |
| **Identity** | Модель не должна иметь возможность заменить ticket package/version, artifact, target или advisory subject. Наблюдаемая V2 misidentification показывает, что это не безопасное default behavior. | Identity является prerequisite, а не рекомендацией. Shadow ticket guard и artifact/build/target routes блокируют ответ на другой build. |
| **Reproducibility** | Новый model call может изменить verdict. Stability sampling может обнаружить drift, но не доказать правильный выбор модели. | Final verdict — pure deterministic function от persisted case, evidence, claims, assumptions и verification records. |
| **Cost / latency** | Может быть дешевле на коротком «answer now» пути, но стоимость false-safe, incident response и manual audit не учтена в latency metric. | Полный static/evidence analysis дороже upfront. Зато повторная проверка, incident audit и CI replay имеют предсказуемую стоимость. |
| **Human review effort** | Если human reviewer обязателен для каждого safe verdict, LLM-first теряет главное преимущество automation. Если reviewer не обязателен, safety evidence недостаточно. | Human reviewer нужен для assumptions, unresolved cases и policy choices, но не должен заново интерпретировать свободный model transcript для каждого deterministic verdict. |
| **Failure modes** | Overconfident safe verdict, hidden incomplete scope, advisory misidentification, model drift, prompt injection, hallucinated falsifier, unsupported universal claim. | Conservative incompleteness, open dispatch, missing SDK, unknown input origin, incomplete advisory coverage, resource exhaustion. Эти failures видимы и fail closed. |
| **Ability to close real corporate cases** | Не доказана. V2 `9/9` и research completion не могут заменить corporate authority proof; kernel `0/39` не подтверждает automatic safe closure. | Это единственный текущий подход с measured authoritative corporate closures: case-04 и case-10, плюс census `7/1/10`. |
| **Extensibility** | Семантически широк, но каждая новая модельная capability увеличивает proof burden и regression surface. | Новые verdict routes можно добавлять как typed evaluators/falsifiers с explicit completeness and replay contracts. LLM помогает открыть route, но не расширяет его молча. |

### Вывод по уровню C

Важная логическая граница:

> Если deterministic verification требует полного identity-bound scope, explicit falsifier и независимой negative verification, то LLM уже не является authority — он является helper.

И наоборот:

> Если LLM может закрыть case при неполном scope, то deterministic verifier не является sufficient authority, а false-safe risk остаётся непроверенным.

Поэтому вариант **(b) LLM-first production с deterministic verification** сейчас отвергается.

---

# 4. Было ли предыдущее решение явным выбором подхода?

## Короткий ответ

**Частично.**

Предыдущее решение явно говорило:

- Shadow остаётся единственным источником authoritative verdict;
- V2 auto-dismissal и LLM-first production authority замораживаются;
- V2 triage/research/evaluation переносится как отдельный слой;
- product priority — `false-safe=0`, negative verification, identity и reproducibility.

Это уже практически означает:

> **deterministic core + LLM helper для authority, плюс отдельный LLM-first research/triage product.**

Однако документ в основном был написан как **codebase comparison**:

- Shadow лучше как production deterministic analyzer;
- V2 лучше как research/evaluation shell;
- значит, Shadow — база.

В нём не было отдельного анализа:

1. LLM-first discovery/root cause;
2. LLM-first triage;
3. LLM-first authoritative verdict;
4. различия между «LLM используется» и «LLM владеет authority»;
5. того, что V2 research improvement может быть реальным, даже если LLM-first authority не доказан.

Поэтому пользовательская критика справедлива: предыдущий документ фактически пришёл к правильному production boundary, но недостаточно явно отделил **approach choice** от **repository choice**.

---

## Достаточно ли evidence для выбора?

### Достаточно для текущего production решения

Да, если зафиксировано требование:

- authoritative analyzer;
- `false-safe=0`;
- safe-negative только через verified falsifier;
- identity-bound evidence;
- replay без LLM;
- допустимый terminal `INCONCLUSIVE`.

Для этого вывода достаточно следующего:

- Shadow имеет доказанные identity/evidence/negative-verification contracts;
- Shadow имеет измеренные corporate closures;
- V2 deterministic kernel дал `0/39` закрытых групп;
- V2 universal verifier имеет `0/39` eligible absence groups и default-off;
- V2 research lane показал `2/36 false-safe` на dev ablation;
- V2 `9/9` относится к research sample, а не к production authority.

### Недостаточно для универсального вывода

Нет evidence, что deterministic core всегда лучше LLM-first в долгосрочном смысле.

Не измерены в matched design:

- одинаковый corpus;
- одинаковые advisory inputs;
- одинаковый identity contract;
- одинаковый human-review budget;
- LLM-first production с полноценной deterministic verification;
- positive-class recall для verifier;
- cost of unresolved cases;
- total analyst-hours, а не только wall-clock completion.

Следовательно, решение должно звучать не как:

> «LLM-first принципиально невозможен».

А как:

> «LLM-first production authority пока не доказан и несовместим с текущим safety contract; LLM-first research/triage следует развивать отдельно».

---

# 5. Принятый вариант: dual-product

## 5.1. Authoritative analyzer

База — Shadow.

### Deterministic authority

Обязаны оставаться deterministic:

1. **Case identity**
   - advisory/ticket;
   - source snapshot;
   - package/version;
   - artifact/build;
   - target;
   - toolchain;
   - assumptions и их scope.

2. **Affectedness**
   - module;
   - version;
   - package;
   - build relevance;
   - vulnerable implementation presence.

3. **Evidence**
   - source/build facts;
   - call/reachability;
   - dynamic/interface/function-value scope;
   - provenance;
   - deployment facts;
   - completeness and bounds.

4. **Claims**
   - `TRUE/FALSE/UNKNOWN`;
   - evidence IDs;
   - limitations;
   - assumptions;
   - subject coverage.

5. **Negative verification**
   - named falsifier;
   - complete scope;
   - dynamic/bypass checks;
   - trace pairing;
   - sidecar integrity;
   - replay validation.

6. **Terminal verdict**
   - `NOT_AFFECTED`;
   - `EXPLOITABLE`;
   - `NO_EXPLOIT_PATH_FOUND`;
   - `INCONCLUSIVE`.

### Что LLM может делать

LLM может:

- интерпретировать advisory и patch;
- предложить root cause/locus;
- предложить mandatory conditions;
- предложить falsifier;
- выбрать следующий evidence query;
- объяснить limitation;
- подготовить human-readable rationale;
- предложить triage priority;
- challenge/review существующее решение.

LLM не может:

- изменить identity;
- объявить advisory subject set полным;
- создать evidence;
- установить `ClaimFalse`;
- выставить `NegativeVerification=VERIFIED`;
- установить `NOT_AFFECTED`;
- установить `NO_EXPLOIT_PATH_FOUND`;
- превратить `INCONCLUSIVE` в safe verdict;
- обойти missing artifact, open scope или failed package load.

## 5.2. Отдельный LLM-first research/triage product

База — V2 components, но с адаптацией к Shadow identity/evidence contracts.

### Разрешённая роль

Этот продукт может быть LLM-first для:

- discovery;
- root-cause exploration;
- advisory interpretation;
- prioritization;
- analyst assistance;
- suggested evidence plans;
- research reports;
- human review preparation.

### Ограничение

Его output должен быть явно помечен как:

- research;
- proposal;
- triage recommendation;
- non-authoritative;
- requiring review;
- `ALLOW/WARN/BLOCK` policy output, а не semantic security verdict.

`DISMISSED`/`LOWERED` нельзя включать в production semantic close, пока не выполнены positive-class и admission gates.

Это не два competing verdict engine. Должен быть:

- один canonical identity contract;
- один authoritative evidence model;
- один verdict evaluator;
- один negative-verification contract;
- отдельный research/triage surface с adapter boundary.

---

# 6. Последствия для предыдущего решения

Поскольку verdict — **PRIOR DECISION CONFIRMED**, база и общий портовый вектор не меняются.

## 6.1. База

Остаётся:

```text
Shadow = authoritative analyzer base
V2 = research / triage / evaluation reference lane
```

Это не потому, что Shadow repository автоматически доказывает superiority deterministic approach. Это потому, что Shadow лучше удовлетворяет именно текущему authority contract.

## 6.2. Port list

### В Shadow authoritative core

Портировать только то, что усиливает deterministic scope и evidence:

- V2 shipping-scope filtering;
- dynamic-marker relevance;
- reachability filter;
- discarded-site audit;
- `goanalysis.ImportClosure`;
- `EnumerateImportClosure`;
- связанные importer-closure структуры, без которых `evidencetools/verify_code_absence.go` и triage falsifier не собираются;
- generic scope hygiene tests.

Acceptance:

- open/unknown scope никогда не становится safe;
- `UNKNOWN` остаётся `UNKNOWN`;
- filter уменьшает шум, но не производит verdict сам по себе;
- negative closure требует complete proof.

### В отдельный triage/research layer

Портировать адаптированно:

- `agenttriage`;
- proposal-only falsifier ingress;
- `finding.v1` / `assessment.v1`;
- FactGate;
- `DecisionPackage`;
- C14;
- replay/stability/mutation tooling;
- `claimshape`;
- `verification`;
- `heldoutgate`;
- `refindex`;
- `reportcheck`;
- use-based prompt/recovery;
- blind/holdout evaluation.

Все adapters должны ссылаться на Shadow canonical:

- `AnalysisCase`;
- `EvidenceGraph`;
- identity;
- evidence IDs;
- assumptions;
- `NegativeVerification`;
- authoritative sidecars.

### Не портировать как authority

- V2 agent verdict;
- use-based research category;
- LLM `NOT_EXPLOITABLE`;
- auto-dismissal;
- второй verdict evaluator;
- второй negative verifier;
- V2 domain/evaluator поверх Shadow domain/evaluator;
- research output как VEX semantic source of truth.

## 6.3. Roadmap

### Phase 0 — зафиксировать trust boundary

- явно разделить authoritative analyzer и research/triage product;
- описать три LLM-first уровня;
- ввести schema-level distinction `proposal / recommendation / verdict`;
- запретить semantic projection research output в authoritative VEX.

### Phase 1 — сохранить Shadow baseline

Acceptance:

- corpus `38/38`, `false-safe=0`;
- census `7/1/10` без unexpected drift;
- case-04 `NOT_AFFECTED/COMPLETE`;
- case-10 `NO_EXPLOIT_PATH_FOUND/COMPLETE`;
- sidecar tamper/removal fail-closed;
- replay без LLM.

### Phase 2 — перенести V2 deterministic scope improvements

- `ImportClosure` / `EnumerateImportClosure`;
- shipping scope;
- dynamic/interface/function-value filtering;
- adversarial fixtures;
- corporate rerun.

Acceptance:

- ни один `LIVE`, `UNKNOWN`, `PARTIAL`, skipped package или open dispatch не становится safe-negative;
- количество discarded blockers может уменьшиться;
- число verified closures должно измеряться отдельно от уменьшения шума.

### Phase 3 — подключить triage/research adapters

- один falsifier shape;
- один Shadow-backed replay path;
- one proposal-only ingress;
- one `WARN/UNCHANGED` path;
- production semantic auto-dismiss остаётся disabled.

### Phase 4 — измерить LLM-first product как самостоятельный продукт

Метрики:

- completion;
- root-cause precision/recall;
- advisory identity accuracy;
- latency;
- analyst-hours;
- recommendation stability;
- number of cases escalated to human review;
- usefulness of proposed next evidence.

Эти метрики не должны автоматически становиться verdict metrics.

### Phase 5 — рассматривать admission только после evidence

Для triage admission нужны:

1. positive exploitable cases;
2. negative and inconclusive cases;
3. positive-class recall;
4. `universal-eligible > 0`;
5. не менее `59` независимых eligible admissions для заявленного statistical precision ≥95%;
6. matched replay;
7. cross-run/provenance isolation;
8. `false-safe=0`;
9. no regression against Shadow corpus;
10. controller-approved review necessity/completeness.

До этого capability остаётся default-off.

---

# 7. Rejected alternatives

| Альтернатива | Почему отклонена |
|---|---|
| **(b) LLM-first production с deterministic verification** | Если verification полная и authoritative, LLM становится helper. Если verification неполная, остаётся риск unsupported safe-negative. Текущие `2/36 false-safe`, `0/39` kernel closures и default-off verifier не дают основания включать этот режим. |
| **V2 как единая production база** | Это не только вопрос качества кода: V2 текущего HEAD не имеет полного Shadow identity/implementation/G1/G2/sidecar contract; deterministic kernel не закрыл corporate groups. |
| **Shadow-only, без V2 research/triage** | Потеря generic triage shell, replay/mutation/holdout tooling, blind evaluation и research productivity. |
| **Единый merged product без trust boundary** | Создаст две модели identity, claims, negative verification и verdict authority. Это повышает риск semantic drift. |
| **LLM-first single research product вместо authoritative analyzer** | Подходит только при изменении product goal на human-only research assistant. Это не текущая цель. |
| **Доказать подход только через `9/9`** | Это малый research sample; independent verification указывает отсутствие official ground truth, а dev ablation дал `2/36 false-safe`. |

---

# 8. Риски принятого решения

| Риск | Ограничитель |
|---|---|
| Human или CI примет research `NOT_EXPLOITABLE` за semantic safe verdict | Отдельные schemas, labels, VEX denial и default-off admission |
| Дублирование Shadow/V2 evidence models | Только adapters к Shadow canonical contracts |
| V2 scope filter изменит semantics и начнёт скрывать UNKNOWN | Adversarial fixtures; `UNKNOWN/LIVE/PARTIAL` всегда blocking |
| Deterministic core оставит слишком много `INCONCLUSIVE` | Портировать V2 scope hygiene и исследовать condition/input falsifiers, не ослабляя negative rules |
| LLM misidentifies advisory или CVE | Deterministic advisory identity, ticket guard, frozen advisory bytes |
| Research lane окажется дорогим | Измерять analyst-hours и latency отдельно; использовать caching/replay |
| Human review не сможет интерпретировать deterministic evidence | Reports должны показывать exact blocker, subject, scope, assumption и evidence path |
| Production policy начнёт оптимизировать completion вместо safety | Отдельные acceptance metrics для authority и research product |

---

# 9. Что может опровергнуть решение

Решение следует пересмотреть, если появится evidence одновременно по нескольким условиям:

1. LLM-first production на matched corpus показывает:
   - `false-safe=0`;
   - positive-class recall;
   - complete identity binding;
   - complete scope semantics;
   - independent negative verification;
   - deterministic replay без зависимости от нового model call.

2. Universal verifier получает:
   - positive exploitable holdout;
   - `universal-eligible > 0`;
   - достаточное число independent admissions;
   - production-level precision lower bound;
   - измеренный recall;
   - отсутствие cross-run/provenance leakage.

3. LLM-first закрывает больше реальных corporate cases, чем deterministic core, при том что:
   - safe-negative доказуемы;
   - human review effort реально ниже;
   - identity и auditability не хуже;
   - нет регрессии на Shadow corpus.

4. Shadow не сможет воспроизвести собственные baseline:
   - corpus перестанет давать `false-safe=0`;
   - case-04/case-10 потеряют proof;
   - sidecar/replay integrity будет обходиться;
   - census drift окажется необъяснимым.

5. Изменится продуктовая цель:
   - analyzer станет исключительно research assistant;
   - human reviewer будет обязательным для каждого disposition;
   - nonzero false-safe станет приемлемым.

Последний пункт — настоящий user-owned fork. При текущем заданном goal он не активен.

---

# 10. Минимальные эксперименты, способные перевернуть решение

## Experiment 1 — matched safety benchmark

Один и тот же набор:

- advisory bytes;
- ticket;
- source/artifact;
- target;
- build context;
- deployment assumptions;
- human labels.

Сравнить:

1. LLM-first production;
2. deterministic core + LLM helper;
3. deterministic-only baseline.

Измерить:

- false-safe;
- false-alarm;
- exploitable recall;
- safe-negative precision;
- `INCONCLUSIVE` rate;
- identity mismatch;
- completeness violations;
- replay mismatch.

Без positive exploitable cases эксперимент невалиден для production authority.

## Experiment 2 — corporate closure benchmark

На существующих:

- Shadow 18-ticket census;
- V2 corporate matrix;
- cases 03/04/07/08/10;
- cases с положительной reachability и unresolved input control.

Измерить:

- terminal safe closure;
- correct `INCONCLUSIVE`;
- human review minutes;
- evidence required per closure;
- number of cases closed only through assumptions;
- number of cases where LLM suggests a useful next proof.

`9/9` research result не заменяет этот experiment.

## Experiment 3 — identity and replay adversarial test

Мутировать:

- advisory ID;
- ticket package/version;
- source commit;
- artifact digest;
- target;
- sidecar;
- tool output;
- model answer;
- subject set;
- completeness flags.

Ожидаемый результат для authority:

- mismatch;
- `INCONCLUSIVE`;
- replay failure;
- технический error;

но никогда не safe-negative.

## Experiment 4 — root-cause ablation

Сравнить:

- LLM без deterministic advisory identity;
- LLM с frozen advisory identity;
- deterministic root-cause resolver;
- deterministic resolver + LLM proposal.

Метрики:

- locus precision/recall;
- wrong-CVE rate;
- advisory-symbol coverage;
- false-safe;
- completion;
- analyst usefulness.

Это позволит отдельно оценить LLM-first на уровне A, не смешивая его с verdict authority.

---

# Итог

Предыдущий вывод по репозиториям остаётся правильным:

```text
Shadow base
V2 reference/evaluation lane
```

Но архитектурная формулировка должна быть следующей:

```text
Authoritative product:
    Shadow deterministic core
        → identity
        → affectedness
        → evidence
        → claims
        → negative verification
        → verdict

Research/triage product:
    V2 LLM-first capabilities
        → discovery
        → root-cause hypotheses
        → advisory interpretation
        → prioritization
        → proposed falsifiers
        → human review support

Shared rule:
    LLM may propose.
    Deterministic contracts decide.
```

Таким образом, предыдущая codebase decision не отменяется. Она получает недостающую approach-level justification:

> **LLM-first — правильный accelerator для discovery и triage, но не доказанная authority для security verdict. Для текущего продукта authoritative core должен быть deterministic; LLM-first должен существовать как отдельный research/triage product с жёсткой границей доверия.**
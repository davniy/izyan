# Сводный план: остаточные INCONCLUSIVE (уточнение архитектора)

**Статус:** ROADMAP (архитектор, 2026-10-20) — код не изменялся.
**Источник:** `agent://RemainingWorkPlan`, сохранён дословно.
**База:** `4b25b64`; census 10 INCONCLUSIVE / 7 NOT_AFFECTED / 1 NO_EXPLOIT_PATH_FOUND; corpus `false-safe=0`; guard PASS.

---

# Консолидированный план снижения `INCONCLUSIVE`

## 0. Зафиксированное состояние

Наблюдаемая база:

- корпоративный census: **18 тикетов: 7 `NOT_AFFECTED`, 1 `NO_EXPLOIT_PATH_FOUND`, 10 `INCONCLUSIVE`**;
- `false-safe=0`;
- corpus-real проходит с ожидаемыми verdict’ами;
- ticket-backed прогон уже показал:
  - case-04: `NOT_AFFECTED/COMPLETE`;
  - case-03: `INCONCLUSIVE` при `--osv-feed`, advisory обогащается до `GO-2026-4526` и получает **39 declared symbols**;
- case-03 при enriched advisory: `may_call=127`, `dep_sites=3`; у `NodeIterator.MoveNext` — **2 живых dependency call sites**;
- cases 07/08: `may_call=1009`, `dispatch=14`, **39 limitations**; исключаются IBM MQ-пакеты из-за отсутствия `cmqc.h`;
- cases 01/02 уже имеют положительную reachability: соответственно **4** и **2 product references**;
- cases 17/18: `github.com/rabbitmq/amqp091-go.Channel.Qos` уже классифицирован как `USED`;
- cases 15/16: независимое falsifier-доказательство отсутствует; `verification-facts.json` фиксирует `executed=false`, `plan_status=no agent turn`.

Уже реализовано и **не должно повторно планироваться**:

- authoritative proof sidecars и rehydration в `internal/research/deterministic.go`;
- единый `go/packages` load context через `internal/goanalysis/source.go:loadConfig`;
- closed/open контракт `MayCallSites` в `internal/goanalysis/toolscope.go`;
- function-value resolution в `internal/goanalysis/funcvalues.go`;
- conservative dispatch narrowing в `internal/goanalysis/unreachability.go:dispatchGaps`;
- trace pairing;
- package-absence/build-usage reconciliation для case-10;
- G1 config route;
- G2 implementation-locus route;
- `implementation-locus-proposals/1`;
- `exploit-locus-proposals/1` и `VerifyExploitLocus`.

Case-10 уже закрыт измеренным `NO_EXPLOIT_PATH_FOUND` и в этот план не входит.

---

## 1. Диспозиция десяти оставшихся случаев

| Case | Диспозиция | Основание и требуемое действие |
|---|---|---|
| **01** | **Needs a capability the owner has not approved** — authoritative positive exploitability/input-control capability | `internal/research/slice2.go:slice2Axes` требует verified runtime observation, dynamic trace или reproduction для `EXPLOITABLE`. Статическая reachability уже положительна: 4 product references и 32 module-internal chains. Улучшение unreachability не даст безопасного отрицательного verdict. |
| **02** | **Needs a capability the owner has not approved** — authoritative positive exploitability/input-control capability | 2 product references и 2 module-internal chains уже доказывают использование `google.golang.org/grpc`. Нужна проверка attacker-controlled input или воспроизводимый runtime path; статический call graph этого не устанавливает. |
| **03** | **Reducible by bounded engineering**, но только условно закрываемый | Census не передаёт ticket artifact/source/assumptions. Это отдельный planned harness item. После правильной передачи inputs ticket-backed прогон всё ещё `INCONCLUSIVE`: `GO-2026-4526` даёт 39 symbols, `may_call=127`, 3 dependency sites и 2 live sites для `NodeIterator.MoveNext`. Сначала требуется закрыть declared-symbol scope; затем проверить, применим ли exact config route. |
| **04** | **Reducible by bounded engineering** — census harness wiring | Текущий census ошибочно не передаёт artifact/source/assumptions. Ticket-backed прогон уже наблюдался как `NOT_AFFECTED/COMPLETE` с отсутствующей vulnerable implementation под Linux target. Ожидаемое движение после wiring: `INCONCLUSIVE → NOT_AFFECTED/COMPLETE`. |
| **07** | **Reducible only with an external input** — real IBM MQ Client SDK | Нужны реальные `cmqc.h`, IBM MQ headers/libraries и воспроизводимый cgo build context. Без SDK package loading остаётся неполным. После SDK ещё потребуется закрыть `may_call`, dispatch и все оставшиеся limitations. |
| **08** | **Reducible only with an external input** — real IBM MQ Client SDK | Тот же блокер и тот же порядок. SDK убирает только первичную невозможность type-check; `may_call=1009`, `dispatch=14` и 39 limitations сами по себе не исчезают. |
| **15** | **Reducible only with an external input** — exact advisory-bound falsifier proposal and independently verifiable evidence | Сейчас нет agent turn и нет proposal. Агентская категория/prose неавторитетна; `VerifyDecision` в `internal/research/decision.go` оставляет такой случай `INCONCLUSIVE`. Нужен retained typed proposal и исполнимый verification trace, а не ручное утверждение. |
| **16** | **Reducible only with an external input** — exact advisory-bound falsifier proposal and independently verifiable evidence | Те же условия, что для case-15. При отсутствии proposal безопасное снижение невозможно. |
| **17** | **Needs a capability the owner has not approved** — positive exploitability или verified input-control capability | `Channel.Qos` уже `USED`; вопрос — может ли `prefetchCount`/`prefetchSize` получить attacker-controlled negative value. Static use не даёт ответа. |
| **18** | **Needs a capability the owner has not approved** — positive exploitability или verified input-control capability | То же: положительная reachability и use уже известны, но provenance/control конкретного аргумента не установлен. |

### Структурно irreducible cases

При уже предоставленных owner inputs **ни один из десяти случаев не является безусловно structurally irreducible**. Однако:

- без реального IBM MQ SDK cases 07/08 остаются принципиально незакрываемыми в данном build scope;
- без identity-aligned ticket artifact/source нельзя делать вывод о ticket version;
- без одобрения positive-exploitability capability cases 01/02/17/18 должны оставаться `INCONCLUSIVE`.

Это не основания ослаблять verifier; это корректные stop states.

---

## 2. Приоритетные work items

### W1. Исправить census harness wiring для cases 03/04

**Приоритет:** первый; bounded, без изменения proof semantics.  
**Цель:** перенести в census уже существующий ticket-backed invocation.

#### Механизм

Внешний harness должен передавать в `izyan research`:

```text
--snapshot
--advisory-file
--ticket
--artifact
--declared-assumptions
```

Для enriched case-03 также:

```text
--osv-feed
```

CLI уже предоставляет эти каналы в `cmd/izyan/research.go:researchFlags`:

- `--artifact`;
- `--declared-assumptions`;
- `--implementation-locus-proposal`;
- `--exploit-locus-proposal`;
- `--ticket`;
- `--osv-feed`.

Точный код внешнего census script в текущем worktree не прочитан, поэтому детали его внутреннего API — `[INFERENCE]`; сам факт отсутствия этих inputs в census задан измеренным состоянием.

#### Acceptance

- manifest каждого запуска содержит digest ticket, artifact, source snapshot и assumptions;
- case-04 в census воспроизводит уже измеренный `NOT_AFFECTED/COMPLETE`;
- case-03 в census воспроизводит ticket-backed `INCONCLUSIVE`, а не старое состояние с отсутствующими inputs;
- отсутствие любого обязательного input остаётся named limitation, а не silent fallback.

#### Ожидаемый verdict

- case-04: **наблюдаемый ticket-backed результат** `NOT_AFFECTED/COMPLETE`;
- case-03: **[INFERENCE]** останется `INCONCLUSIVE`, пока не закрыты 39 declared symbols и exact trigger route.

После wiring количество census `INCONCLUSIVE` должно уменьшиться на один — с 10 до **9**, если case-04 прогоняется теми же inputs.

---

### W2. Разобрать и закрыть `may_call=127` в case-03

**Приоритет:** после W1.  
**Файлы и symbols:**

- `internal/goanalysis/toolscope.go:Index.MayCallSites`;
- `internal/goanalysis/funcvalues.go:fvIndex`, `fvParamCallers`, `funcCandidates`;
- `internal/goanalysis/source.go:callersOf`, `loadExtra`, `callerScope`;
- `internal/goanalysis/coverage.go:InterfaceDispatchSites`;
- `internal/goanalysis/unreachability.go:VerifyUnreachable`, `dispatchGaps`;
- `internal/goanalysis/sinkclosure.go:SinkSetBasis`;
- `internal/goanalysis/provenance.go:TraceArgumentBound`;
- `internal/evaluator/postreach.go`;
- `internal/research/decision.go:VerifyDecision`.

#### Что означает число 127

`127` — это не 127 доказанных product calls и не 127 оснований для отрицательного verdict. Это агрегированное множество `MayCallSite`, возвращённое `Index.MayCallSites` для **39 advisory-declared symbols** после OSV feed enrichment.

Эти sites могут включать:

- interface-dispatch candidates;
- function-value candidates;
- signature-compatible unresolved candidates;
- dependency-side caller candidates.

Отдельно измерены:

- `dep_sites=3`;
- у `NodeIterator.MoveNext` — 2 живых dependency call sites.

Точный per-symbol/per-site breakdown в доступном контексте не сохранён; его нужно получить из полного authoritative proof, а не из display prefix.

#### Sound closure

Множество `127` **может быть замкнуто soundly**, но только если:

1. каждый candidate разрешён или доказан отсутствующим;
2. `MayCallSites` возвращает `partial=false`;
3. нет `Possible=true`;
4. нет open sentinel;
5. нет skipped packages и exhausted bounds;
6. receiver-instantiation inventory для dispatch complete;
7. все 39 subjects имеют exact module/package/symbol identity;
8. dependency call sites сопоставлены с invocation state;
9. trace и proof sidecar остаются `COMPLETE`.

Контракт `([], false, nil)` в `internal/goanalysis/toolscope.go` остаётся единственным closed-empty результатом. Нельзя преобразовать `len(sites)==0` или текущий open result в absence.

#### Acceptance tests

Для generic fixture и case-03:

- каждый из 39 subjects присутствует в authoritative verification request;
- ни один returned `MayCallSite` не имеет `Possible=true`;
- partial/open sentinel отсутствует;
- `InterfaceDispatchSites` либо пуст, либо soundly narrowed complete receiver proof’ом;
- 2 `NodeIterator.MoveNext` live sites либо подтверждены и traced, либо доказанно dead;
- любой найденный реальный call остаётся положительным evidence, не превращается в negative.

#### Expected verdict

- Если закрытая проверка докажет отсутствие всех соответствующих paths: **[INFERENCE]** `NO_EXPLOIT_PATH_FOUND` через declared-symbol unreachability.
- Если подтвердится живой path: `INCONCLUSIVE`, пока не сработает отдельный verified input-control route.
- Простое уменьшение `127 → 0` не является acceptance и не должно считаться успехом.

---

### W3. Проверить применимость G1 к enriched case-03

**Приоритет:** параллельно с W2 концептуально, интегрируется после закрытия subject set.

#### Что уже разрешено

Для настоящего symbol-less advisory уже существует:

- `internal/affected/exploitlocus.go:VerifyExploitLocus`;
- `internal/goanalysis/sinkclosure.go:ExploitLocusBindingBasis`;
- `internal/evaluator/postreach.go`;
- `internal/research/decision.go:verifyPostReachConfig`.

Эта ветка может связать:

```text
xmlquery.QueryAll(argument 1)
    → xpath.Compile(argument 0)
    → logicalQuery.Select
```

но только если advisory entry действительно symbol-less.

#### Что происходит с OSV-enriched advisory

При `--osv-feed` case-03 получает `GO-2026-4526` и 39 declared symbols. Поэтому:

- `VerifyExploitLocus` обязан отклонить proposal на проверке `symbol-less-entry`;
- `ExploitLocusBindingBasis` обязан вернуть `ok=false`;
- это корректно и не должно изменяться.

Обычный declared-symbol route использует `SinkSetBasis`, который требует:

- declared subjects;
- subject membership в affected module;
- advisory-wide coverage;
- отсутствие unresolved non-absent subjects.

Следовательно:

- G1 **может применяться к enriched advisory только через обычный declared-symbol route**, если 39 symbols действительно образуют exact, advisory-bound sink set с единым exact `ArgIndex`;
- рекомендуемый cross-module sink `xmlquery.QueryAll` нельзя тайно добавить в ordinary route;
- разрешение cross-module `QueryAll` для symbol-enriched advisory потребовало бы нового generic binding contract, а не ослабления `symbol-less-entry`. Такой capability owner не утверждал.

#### Acceptance

Case-03 получает `NO_EXPLOIT_PATH_FOUND` через G1 только при одновременном наличии:

1. positive exact sink reach;
2. complete `SinkSetBasis`;
3. live sites для exact nonnegative `ArgIndex`;
4. `TraceArgumentBound` для каждого live site;
5. `OriginConfiguration` на каждом site;
6. отсутствие external/unknown/reflection/alias write;
7. valid product-scope config-trust assumption;
8. `NegativeVerification=VERIFIED`;
9. `VerifyDecision` re-check.

Если хотя бы часть 39 symbols не является exact trigger sink или требует receiver/object-state вместо exact argument, route остаётся `INCONCLUSIVE`. `[INFERENCE]` Для текущего enriched case это является вероятным ограничением; его нужно подтвердить полным proof, не предполагать.

Expected verdict при закрытии: `NO_EXPLOIT_PATH_FOUND`, **никогда `NOT_AFFECTED`**.

---

### W4. Дать cases 07/08 реальный IBM MQ SDK

**Приоритет:** после W1; внешний prerequisite.

#### Что требуется

Owner должен предоставить:

- IBM MQ Client SDK;
- реальный `cmqc.h`;
- соответствующие include paths;
- libraries и library paths;
- toolchain/build tags/vendor mode;
- возможность воспроизвести `CGO_ENABLED=1` build.

Минимальный build context должен быть эквивалентен:

```text
GOOS=linux
GOARCH=amd64
CGO_ENABLED=1
CGO_CFLAGS=-I<IBM_MQ_CLIENT_HOME>/include
CGO_LDFLAGS=-L<IBM_MQ_CLIENT_HOME>/lib
```

#### Что делает SDK

SDK устраняет первичный blocker:

- `demo-mq-gateway/providers/ibm`;
- `demo-mq-gateway/test`;
- `providers/ibm/mqiCBD.go:26: fatal error: 'cmqc.h' file not found`.

Он **не закрывает** cases автоматически.

#### Что остаётся после SDK

Нужно повторно пройти:

- `internal/goanalysis/source.go:Index.loadConfig` и `Index.load`;
- skipped-package diagnostics;
- `internal/goanalysis/usage.go:ProductUsage`;
- `internal/goanalysis/toolscope.go:MayCallSites`;
- `internal/goanalysis/funcvalues.go`;
- `internal/goanalysis/coverage.go:InterfaceDispatchSites`;
- `internal/goanalysis/unreachability.go:dispatchGaps` и `VerifyUnreachable`;
- persisted authoritative sidecar;
- one-to-one trace/audit pairing.

Acceptance:

- IBM MQ packages type-check;
- skipped package count для product scope равен нулю;
- `may_call` не содержит open candidates;
- `dispatch=0` либо каждый оставшийся candidate soundly resolved;
- limitations не содержат build/load/dispatch/trace blockers;
- complete proof проходит `VerifyDecision`.

#### Expected verdict

**[INFERENCE]** Если после SDK и полного closure не найдено positive path:

```text
NO_EXPLOIT_PATH_FOUND
falsifier=declared-symbol-unreached
coverage=COMPLETE
NegativeVerification=VERIFIED
```

Cases 07/08 не должны переходить в `NOT_AFFECTED`: это reachability/no-exploit proof, а не applicability absence.

Если SDK приводит к обнаружению живого call path, соответствующий case остаётся `INCONCLUSIVE`.

---

### W5. Cases 15/16: получить независимый proposal, но не принимать prose

**Приоритет:** после bounded deterministic work; только при наличии owner/analyst input.

#### Требуемый input

Для каждого case нужен retained typed proposal/verification plan, связанный с:

- frozen advisory digest;
- exact advisory subjects или exact falsifier locus;
- конкретными bounded checks;
- independently persisted observations;
- replayable artifacts.

Проверяемые участки:

- `internal/research/agent.go`;
- `internal/research/decision.go:VerifyDecision`;
- `internal/research/flow_driver.go`;
- report/replay validation.

#### Acceptance

- proposal не содержит verdict или pre-filled `NegativeVerification`;
- proposal passes advisory identity and scope checks;
- все requested checks исполнены;
- нет `executed=false` или `plan_status=no agent turn`;
- verifier re-derives falsifier independently.

#### Expected verdict

**[INFERENCE]**

- verified falsifier → `NO_EXPLOIT_PATH_FOUND`;
- verified positive exploitability → `EXPLOITABLE`;
- proposal weak, incomplete, contradictory или absent → `INCONCLUSIVE`.

---

### W6. Positive exploitability capability — отдельная owner-gated ветка

Не включать в критический bounded path без решения owner.

Требуемая capability:

- reproducible runtime observation/dynamic trace/reproduction;
- attacker-input provenance;
- persisted, replayable runtime artifact;
- consumption через `internal/research/slice2.go:slice2Axes`.

Acceptance для известных reachable cases:

- case-01: attacker-controlled expression reaches `xpath` vulnerable behavior;
- case-02: attacker-controlled request reaches grpc vulnerable path;
- case-17/18: negative `prefetchCount`/`prefetchSize` reaches `Channel.Qos`;
- evidence is reproducible and identity-bound.

Expected verdict: `EXPLOITABLE` only on verified positive evidence; alternatively a verified config-origin route may produce `NO_EXPLOIT_PATH_FOUND`. Without this capability cases remain safely `INCONCLUSIVE`.

---

## 3. Что может предоставить только owner

| Input / decision | Для чего | Точное последствие отсутствия |
|---|---|---|
| **Real IBM MQ Client SDK: `cmqc.h` plus headers/libraries** | Cases 07/08, complete cgo/type-check scope | Оба case остаются `INCONCLUSIVE` с limitation о missing `cmqc.h`; syntax-only stub не принимается как proof. |
| **Exact ticket build artifacts and source snapshots for tickets, отличающиеся от общего artifact 1.10.3** | Identity-aligned analysis per ticket | `internal/affected/ticket.go:checkTicketClaims` оставляет package-version mismatch блокирующим; текущий source/build не может отвечать за другую ticket version. |
| **Уже предоставленная пара для 03/04**: `va-tmp/demo-product-1.1.1-2397`, `va-tmp/am-1.10.3/package/bh/demo-product`, assumptions document | Позволяет rerun 03/04 | Нового owner input для этих двух cases сейчас не требуется; требуется только передать имеющиеся inputs в census harness. |
| **OSV feed, содержащий `GO-2026-4526`** | Enrich case-03 exact declared-symbol route | Без feed reviewed GHSA остаётся symbol-less и возможен только `exploit-locus` route. С feed появляется 39-symbol ordinary route, а `symbol-less-entry` correctly blocks exploit-locus binding. |
| **Retained advisory-bound proposal/verification artifact для 15/16** | Независимое falsifier-доказательство | `VerifyDecision` видит `Proposal == nil`/неисполненный plan и оставляет verdict `INCONCLUSIVE`; agent prose не заменяет evidence. |
| **Решение инвестировать в positive exploitability capability** | Cases 01/02/17/18 и, возможно, 15/16 | Без этого static positive-use cases не могут безопасно перейти ни в `EXPLOITABLE`, ни в отрицательный verdict по attacker-control вопросу. |
| **Подтверждение target/config assumptions** | G1/G2 gates | Уже предоставленные owner facts должны оставаться через `declared-assumptions/1`: admin config вне attacker model и product-wide Linux. Нельзя заменить их host OS, tags или `--trusted-peer`. |

---

## 4. Что запрещено пытаться делать

| Shortcut | Нарушаемый invariant |
|---|---|
| Считать `may_call=127` или `1009` пустым/неважным из-за отсутствия direct references | `MayCallSites` explicitly distinguishes open candidate set; absence без closed scope не является proof. |
| Игнорировать `Possible=true`, sentinel или unresolved function-value candidate | Превращает under-approximation в ложное closed empty set. |
| Исключить IBM MQ broken packages из denominator | `go/packages` failure скрывает references; skipped package остаётся scope blocker. |
| Подложить syntax-only `cmqc.h` stub | Не воспроизводит product build и не даёт authoritative negative proof. |
| Использовать текущий artifact для ticket с другой package version | Нарушает ticket-build identity guard; отвечает на другой build. |
| Считать отсутствие `--ticket`, `--artifact` или assumptions в census доказательством отсутствия уязвимости | Это harness/input omission, а не code fact. |
| Применить `exploit-locus-proposals/1` после появления 39 OSV symbols | Нарушает обязательное `symbol-less-entry` условие в `VerifyExploitLocus`. |
| Ослабить `symbol-less-entry`, чтобы принять `xmlquery.QueryAll` для enriched advisory | Создаёт неутверждённый cross-module authority route и размывает advisory binding. |
| Добавить `xmlquery.QueryAll` в ordinary `SinkSetBasis` только потому, что он логически связан с XPath | `SinkSetBasis` требует exact advisory-bound subjects; cross-module sink допускается только через verified binding. |
| Принять `mapstructure`/`env` tag как `OriginConfiguration` | Tag не доказывает origin; external writes, aliases, reflection и unknown paths должны блокировать G1. |
| Превратить static reachability/use в `EXPLOITABLE` | Reachability не доказывает attacker control или runtime execution. |
| Превратить static reachability/use в `NO_EXPLOIT_PATH_FOUND` | Для 01/02/17/18 отсутствует verified falsifier. |
| Использовать agent category/prose как FALSE для 15/16 | LLM output — hypothesis; authority только у independently re-derived evidence. |
| Возвращать `NOT_AFFECTED` из symbol-unreachability или G1 | `NOT_AFFECTED` reserved for affected-chain FALSE; G1 и symbol-unreachability дают `NO_EXPLOIT_PATH_FOUND`. |
| Молча увеличивать payload/load/scan bounds | Каждый bound должен быть явным и входить в scope/provenance. |
| Добавлять case-specific branches по ticket ID, XPath, MQ или RabbitMQ | Нарушает `generality.md` и делает measurement non-generalizable. |
| Повторно переделывать уже закрытые sidecar, may-call, dispatch, trace-pairing или case-10 reconciliation | Это уже реализованные capabilities; remaining work — integration, external prerequisites и unresolved positive/input-control questions. |

---

## 5. Последовательность и forecast

### Step 0 — baseline

Оставить baseline неизменным:

```text
7 NOT_AFFECTED
1 NO_EXPLOIT_PATH_FOUND
10 INCONCLUSIVE
false-safe=0
```

Не использовать parallel-run artifact с `SNAPSHOT_PRODUCT=0s` как новую семантическую проблему: индивидуальные runs уже совпадают с expectations.

### Step 1 — census harness wiring

Передать в census существующие ticket/source/artifact/assumptions inputs.

**Ожидаемое движение:** case-04 `INCONCLUSIVE → NOT_AFFECTED/COMPLETE`; case-03 остаётся `INCONCLUSIVE`.

**Forecast:** `[INFERENCE]` 9 `INCONCLUSIVE`, 8 `NOT_AFFECTED`, 1 `NO_EXPLOIT_PATH_FOUND`.

### Step 2 — case-03 subject closure

Разобрать 39 symbols и `may_call=127`; не использовать symbol-less binding при enriched advisory.

**Ожидаемое движение:** 0 или 1 case:

- exact declared-symbol proof закрыт → `NO_EXPLOIT_PATH_FOUND`;
- exact G1 config closure закрыт → `NO_EXPLOIT_PATH_FOUND`;
- любой unresolved candidate, non-uniform argument, live external/unknown origin или cross-module sink без approved binding → остаётся `INCONCLUSIVE`.

**Forecast:** `[INFERENCE]` от 8 до 9 `INCONCLUSIVE` после Step 1.

### Step 3 — IBM MQ SDK и повторный closure 07/08

Только после получения реального SDK.

**Ожидаемое движение:** каждый case независимо переходит:

- в `NO_EXPLOIT_PATH_FOUND`, если build/load/may-call/dispatch/trace closure complete и positive path отсутствует;
- либо остаётся `INCONCLUSIVE`, если SDK раскрывает positive path или scope остаётся open.

**Forecast:** `[INFERENCE]` ещё 0–2 terminal movements; при закрытии обоих случаев останется от 6 до 7 `INCONCLUSIVE`, в зависимости от case-03.

### Step 4 — cases 15/16

Только после появления retained, advisory-bound verification proposal.

**Ожидаемое движение:** 0–2 cases в `NO_EXPLOIT_PATH_FOUND` или `EXPLOITABLE`; отсутствие valid proposal не меняет verdict.

### Step 5 — owner decision по positive exploitability

Этот шаг не блокирует Steps 1–4.

- Если capability не утверждена: остановиться с 01/02/17/18 в `INCONCLUSIVE`.
- Если утверждена: запускать отдельную runtime/input-control ветку; forecast verdict не предсказывать до получения evidence.

---

## Stop conditions

Работу по конкретному case необходимо остановить без снижения verdict, если:

1. отсутствует `cmqc.h` или реальный IBM MQ build context;
2. остаётся skipped package;
3. `MayCallSites` возвращает `partial=true`, `Possible=true`, sentinel или exhausted bound;
4. unresolved interface receiver не имеет complete instantiation proof;
5. advisory symbol closure не покрывает все 39 case-03 subjects;
6. sink closure не имеет advisory-bound basis;
7. G1 не имеет exact positive reach, exact `ArgIndex`, complete live-site coverage или `OriginConfiguration`;
8. есть external/unknown/reflection/alias write;
9. отсутствует product-scope `config-trust` assumption;
10. proposal 15/16 не advisory-bound или verification plan не исполнен;
11. verdict не содержит `NegativeVerification=VERIFIED` и complete authoritative evidence;
12. появляется `false-safe`, меняется out-of-scope case или нужен case-specific hardcode.

Итоговый порядок поэтому условный, но не блокируется одним owner decision: сначала выполняются wiring и bounded closure; отдельно владелец решает, инвестировать ли в positive exploitability для четырёх статически reached cases.
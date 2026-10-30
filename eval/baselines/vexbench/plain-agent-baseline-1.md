# VEX-Bench Plain Agent Baselines — сравнение исходных и изолированных прогонов

Сторона **B (Plain Coding Agent)** из [agent-first роадмапа](../../roadmaps/agent-first-analysis-roadmap.md) Этап 0.
Plain Coding Agent в нескольких конфигурациях против детерминированного baseline **A (Current Izyan)**. Помимо первоначальных прогонов приведены изолированные перепроверки Gemini и Qwen 3.6/3.8.

> **Область и оговорки.** Отчёт описывает прогоны, выполненные на фиксированном корпусе VEX-Bench (30 Go-кейсов: 7 exploitable / 23 safe); все числовые строки воспроизводимы из артефактов, пути к которым даны в §5, §8.8, §9.9. Post-hoc проекции (RECOVERY, parser-repair) **не** заменяют сохранённый official scoring — они приводятся отдельно (§8.3, §9.3). Малые знаменатели (7 exploitable, по 1 repeat у большинства режимов) не позволяют обобщать частоты на корпус.

| ID | Модель | Харнес | Изоляция | Повторов |
|---|---|---|---|---|
| **A** | — (детерминированный Izyan) | CLI | — | 1 |
| **B1** | gpt-6.1-sol (Codex) | **официальный** `vex-bench` CLI | **Docker** контейнер/кейс | 3 (90 attempts) |
| **B2** | gemini-3.8-flash-high | omp subagent | хостовый процесс — ⚠ **не изолирован, см. §7** | 1 (30) |
| **B3** | `custom-openai-custom/Qwen/Qwen3.6-35B-A3B` | **omp subagent** (тот же, что B2) | хостовый процесс | 1 (30) |

Замороженный A: [`external-baseline-1.md`](external-baseline-1.md).

> **Методология (читать до таблиц).** 30 кейсов, из них **7 exploitable** / **23 safe**.
> B2 и B3 — **1 repeat**, B1 — **3 repeat того же корпуса** (не 90 независимых кейсов).
> Агрегация repeat'ов: **mean ± sample std (ddof=1)**. Никакой статистической значимости на n=1 repeat и 7 exploitable кейсах нет: один кейс двигает recall/False-Safe-rate на 14.3 pp, один safe — Safe Clear Rate на 4.35 pp.
> Counts и rates указываются раздельно, знаменатели — 30 (все кейсы), 7 (exploitable), 23 (safe); для B1 дополнительно pooled 90/21/69 с явной пометкой.
> **FAILED** — отдельный исход (не negative и не abstain).

---

## 1. Сводная таблица метрик (§43 Roadmap)

Сначала — **условия прогона** (колонки не равновесны):

| | A: Izyan | B1: Codex | B2: Gemini (contam.) | B2-ISO: Gemini | B3: Qwen3.6 (host) | Q3.6-ISO | Q3.8-ISO |
|---|---|---|---|---|---|---|---|
| **Повторы** | 1 | **3** (90 попыток) | 1 | 1, **retry-composite** | 1 | 1, 28 fresh + 2 cached smoke | 1, 30 fresh |
| Изоляция GT | — | Docker | **GT прочитан в 11/29 transcripts** | Docker | хост, чтения GT не обнаружено | Docker | Docker |
| **FAILED в официальном scorer** | 2/30 | 0/90 | 0/30 | **4/30** | 0/30 | **2/30** | **2/30** |
| **Особенность** | frozen | основной blind baseline | **невалиден как blind baseline** | 7 selective retries; 3 filter-truncations | нет физической изоляции | mixed admission | 1 исходный проход |

> **B2/B2-ISO/B3/Q3.6-ISO/Q3.8-ISO — по одному основному проходу**, но политики попыток неодинаковы. У B2-ISO официальный scorer: FAILED 4, accuracy 83.3 %; отдельная **RECOVERY**-проекция: FAILED 0, accuracy 96.7 %. У неё 3 усечённых фильтром ответа, 7 кейсов выборочно перезапускались под `run_001` (§8). Поэтому RECOVERY и B2-ISO нельзя считать обычным first-attempt baseline.

**Основные метрики: официальный scorer там, где он применялся.** B2 (contaminated) и B3 (host) приведены только описательно. Post-hoc RECOVERY и parser-repair — отдельные проекции в §8–9, они не подменяют официальный baseline:

| Метрика | A: Izyan | B1: Codex (3 rep) | B2: Gemini (contam.) | B2-ISO: Gemini | B3: Qwen3.6 (host) | **Q3.6-ISO** | **Q3.8-ISO** |
|---|---:|---:|---:|---:|---:|---:|---:|
| **False-Safe** | **1/7** | **1/7 в каждом повторе** | 1/7 | **1/7** | 1/7 | **1/7** | **0/7 в одном проходе** ⚠ |
| **Safe Clear Rate** | 10/23 = 43.5 % | **97.1±2.5 %** | 23/23 = 100 % | **21/23 = 91.3 %** | 19/23 = 82.6 % | 19/23 = 82.6 % | 20/23 = 87.0 % |
| **EXPLOITABLE recall** | 2/7 = 28.6 % | **85.7 %** | 6/7 = 85.7 % | **4/7 = 57.1 %** | 6/7 = 85.7 % | 6/7 = 85.7 % | 6/7 = 85.7 % |
| **INCONCLUSIVE** | 12/30 = 40 % | ≈1.1 % | 0/30 | 0/30 | 0/30 | 0/30 | 0/30 |
| **Binary Accuracy** | 66.7 % | **95.6 %** | 96.7 % | **83.3 %** | 83.3 % | 83.3 % | 86.7 % |
| **Binary F1** | 0.333 | **0.901** | 0.923 | **0.727** | 0.706 | 0.800 | 0.800 |
| **False-alarm** | 3 | 1/90 pooled | 0 | 0 | 4 | 2 | 2 |
| **Completion** | 28/30 | **90/90** | 30/30 | **26/30** | 30/30 | 28/30 | 28/30 |

**Post-hoc проекции (не подменяют таблицу):** B2-ISO RECOVERY: SCR 23/23, recall 6/7, accuracy 96.7 %, F1 0.923; Q3.8-ISO parser-repair: recall 7/7, accuracy 90.0 %, F1 0.875. Это разные операции: Gemini RECOVERY извлекает **только метку из оборванного текста**, Qwen parser-repair восстанавливает **полный валидный JSON** (§8.3, §9.3). Они не эквивалентны завершённому ответу одного типа.

**Qwen-ISO:** GT недостижим; Q3.8 — один свежий проход, Q3.6 — 28 fresh + 2 cached protocol-smoke, без выборочной retry-композиции (§9.9). `0/7` у Q3.8 — результат одного прохода, не успешный safety-gate: в отдельных stability/risk probes зафиксированы опасные отрицания (§9.5–9.6).

**Тайминг.** Сводка (не apples-to-apples — разные границы замера):

| Режим | Медиана | Среднее | n / покрытие | Граница замера |
|---|---:|---:|---|---|
| A: Izyan | — | 429.2 с | 28/30 | записанный wall (иная граница) |
| B1: Codex | — | **232.7±255.7 с** | **23/90 (частично)** | `docker create→destroy` |
| B2: Gemini (contam.) | — | — | — | **не собиралось** |
| B2-ISO: Gemini (Docker) | **88 с** | 114 с | 30/30 | session `created→updated` |
| B3: Qwen3.6 (host subagent) | **285.5 с** | 330.3 с | 30/30 | agent wall (subagent) |
| **Q3.6-ISO: Qwen3.6 (Docker)** | **74 с** | 76 с | 29/30 | session `created→updated` |
| **Q3.8-ISO: Qwen3.8-27B (Docker)** | **96 с** | 148 с | 30/30 | session `created→updated` |

**Probes** (те же границы, что ISO — session export):

| Probe | Медиана | Среднее | n |
|---|---:|---:|---:|
| stability q36 (2 кейса ×3) | 101 с | 100 с | 6 |
| stability q38 (2 кейса ×3) | 109 с | 140 с | 6 |
| risk q36 (2 кейса ×5) | 124 с | 119 с | 8/10 |
| risk q38 (2 кейса ×5) | 116 с | 122 с | 10/10 |

**Оговорки.** B1 покрыт лишь 23/90 (остальные контейнеры не спарены) — его среднее не полная выборка. Строки B2-ISO / Q3.6-ISO / Q3.8-ISO и probes **сопоставимы между собой** (одна граница: `session created→updated`, один харнес). B3-host и A измерены иначе — сравнивать с ними ориентировочно. У B2 (contaminated) длительностей нет. Разброс велик: тяжёлые монорепы (k8s, rancher) доминируют правый хвост (B2-ISO max 490 с; Q3.8-ISO max 575 с).

### 1.1. Что означает каждая метрика

Каждый режим выносит один из вердиктов; вердикты делятся на три смысловые группы:

- **positive** (`vulnerable`) — «уязвимо, эксплуатируемо»;
- **negative** — «безопасно, закрываю алерт»: 10 категорий (`false_positive`, `code_not_present`, `code_not_reachable`, `requires_configuration`, `requires_dependency`, `requires_environment`, `compiler_protected`, `runtime_protected`, `perimeter_protected`, `mitigating_control_protected`);
- **abstain** (`uncertain` / `INCONCLUSIVE`) — «не знаю, доказательств не хватает».

| Метрика | Формула | Что измеряет | Куда стремиться | Знаменатель |
|---|---|---|:---:|---|
| **False-Safe** | `#(GT exploitable ∧ сказано negative)` | **Критическая ошибка**: уязвимость объявлена безопасной. Опасно — тикет закроют, а дыра останется. | **Меньше (строго 0)** | **7** (exploitable) |
| **Safe Clear Rate** | `#(GT safe ∧ сказано negative) / 23` | **Польза**: сколько безопасных алертов реально снято. | **Больше (→ 100 %)** | **23** (safe) |
| **EXPLOITABLE recall** | `TP / 7`, `TP = #(GT exploitable ∧ сказано positive)` | **Полнота обнаружения**: сколько настоящих уязвимостей поймано. | **Больше (→ 100 %)** | **7** (exploitable) |
| **False-alarm** | `#(GT safe ∧ сказано positive)` | Ложная тревога: безопасное названо уязвимым. **Не опасно**, но шум и лишняя работа. | **Меньше (→ 0)** | 23 (safe) |
| **INCONCLUSIVE** | `#(сказано abstain) / 30` | Доля отказов от решения. **Не ошибка** — safety-preserving терминальный исход (см. врезку ниже). | **Не безусловная цель** | **30** |
| **Binary Accuracy** (compatibility) | `(TP + TN_negative + TN_abstain) / 30`, `FAILED` = неверно | Официально-совместимая проекция (`uncertain→not_exploitable`). Удобна для сверки с публикациями, но **не** мера доказанной безопасности. | **Больше (→ 100 %)** | 30 |
| **Binary Precision** | `TP / (TP + FP)` | Из названных уязвимыми — сколько действительно уязвимы. | **Больше (→ 1.0)** | TP+FP |
| **Binary F1** | `2·P·R / (P+R)` | Баланс precision и recall одним числом. | **Больше (→ 1.0)** | — |
| **Completion** | `#(завершившихся кейсов) / 30` | Доля кейсов с ответом (корректный `uncertain` — тоже ответ); `FAILED`/timeout исключаются. | **Больше (→ 100 %)** | 30 |

> **Разделение FN.** В safety-разрезе `FN_safety` = **False-Safe** (опасное отрицание).
> В binary-разрезе `FN_binary` = `GT exploitable − TP`, то есть **False-Safe + abstain (+ FAILED)**.
> Для A: `FN_safety = 1`, `FN_abstain = 4`, `FN_binary = 5`. Именно `FN_binary=5` даёт `F1 = 0.333`; при подстановке `FN=1` получилось бы `F1=0.500`.

> **Врезка: `INCONCLUSIVE` — не провал.** Согласно инвариантам проекта, `UNKNOWN`/`INCONCLUSIVE` — валидный терминальный результат, а не дефект. Для A четыре abstain'а на exploitable-кейсах **безопаснее**, чем галлюцинированный negative-вердикт. Снижать abstention допустимо **только за счёт новых доказательств при неизменном `False-Safe = 0`**. Метрика `INCONCLUSIVE → 0` описывает **стоимость покрытия/триажа**, а не качество или безопасность.

### 1.2. Как интерпретировать результаты без смешивания протоколов

**Основное сопоставление A ↔ B1:** замороженный Izyan против изолированного Codex на том же корпусе (у B1 три повтора).

| Метрика | A: Izyan | B1: Codex | Что можно заключить |
|---|---:|---:|---|
| **False-Safe** | 1/7 | 1/7 в каждом повторе | Обе архитектуры ошибались в сторону ложного safe-решения; это не оценка равенства их истинного риска. |
| **Safe Clear Rate** | 10/23 = 43.5 % | ≈97.1 % | Codex разрешает намного больше действительно safe-кейсов **по GT**. Успех по метке не равен верифицированному falsifier. |
| **EXPLOITABLE recall** | 2/7 | 6/7 в каждом повторе | Codex полнее в данной выборке. |
| **INCONCLUSIVE** | 12/30 | ≈1.1 % | Izyan чаще сохраняет неопределённость; это безопасное поведение, но повышает стоимость ручного триажа. |
| **Completion** | 28/30 | 90/90 | Технические сбои у baseline A отдельно от security-verdict. |

**B2 (contaminated) исключён из сравнения лидеров:** доступ агента к GT обнаружен в 11 из 29 транскриптов (§7). Его прежние `100 % SCR` и `96.7 % accuracy` не могут использоваться как независимое подтверждение качества Gemini. **B2-ISO официально** дал 91.3 % SCR, 57.1 % recall и 26/30 completion; его восстановленная RECOVERY-проекция отдельно показывает более высокие числа, но не является first-attempt baseline.

По двум изолированным Qwen-прогонам показатели ниже B1 по SCR, а одна успешная one-shot нулевая False-Safe строка Q3.8 опровергается последующими targeted probes. На данных Task 3 **LLM сильнее по полноте, но ещё не доказана пригодность для автоматического safe-решения**.

Важно: `INCONCLUSIVE` — корректный safety-preserving итог. Снижать его полезно лишь ценой новых доказательств, а не принуждения к ответу.

### 1.3. Статус baseline-результатов: разный вес доказательности

Режимы B **неравноценны** как экспериментальное свидетельство:

**B1 / Codex — основной baseline.** Вес — **не** уникальность Docker-изоляции (она теперь есть и у B2-ISO), а **три повтора** + контролируемый официальный harness + единая attempt policy: 90 attempts.

**B2 / Gemini (contam.) — дисквалифицирован как blind baseline (§7):** 11/29 кейсов читали GT. Числа — только дескриптивные; **не** могут быть основанием сравнительного лидерства.

**B2-ISO / Gemini (Docker) — exploratory.** GT недостижим, но: nominal 1 repeat, **retry-composite** attempt policy (§8.5), **две расходящиеся scoring-проекции** (§8.2). Доказательный статус понижен.

**B3 / Qwen (host) — exploratory:** 1 repeat, host-based subagent; по просмотренным транскриптам чтение GT не обнаружено, но ФС физически не изолирована — отсутствие утечки не доказано конструкцией harness. **Q3.6-ISO и Q3.8-ISO** — отдельные изолированные результаты, их официальные метрики приведены в §1/§9.

Поэтому основной вывод опирается на **A ↔ B1** (A — 1 frozen run; B1 — 3 повтора, контролируемый harness):

```
Current Izyan:   Safe Clear 43.5 %   EXPLOITABLE 28.6 %   False-Safe 1
Codex B1:        Safe Clear ≈97 %    EXPLOITABLE 85.7 %   False-Safe 1 на repeat
```

Этого достаточно, чтобы подтвердить **преимущество Codex B1 по полноте** на данном корпусе — и недостаточно, чтобы объявить его безопасным или обобщить результат на все Plain Agent. Изолированные B2/Qwen дополняют картину с перечисленными ограничениями.

---

## 2. False-Safe: union по режимам, нет режима без ложных отрицаний

**One-shot union False-Safe case ID:** `k8s-e196d24-44487` (A, B3-host), `rancher-4dc4f53-47914` (B1, B2-contam., **Q3.6-ISO**), `podman-6a65597-48795` (B2-ISO). **Q3.8-ISO в одном проходе не дал ни одного — но у него есть подтверждённые counterexamples в probes (§9.6): `k8s-3121` дал ложные отрицания в stability (2/3 после parser-repair) и risk (4/5).**

| Кейс | GT | A | B1 | B2 contam. | B2-ISO | B3 (host) | Q3.6-ISO | Q3.8-ISO |
|---|---|---|---|---|---|---|---|---|
| `k8s-e196d24-44487` | exploitable | ❌ NOT_AFFECTED | ✅ | ✅ | ✅ | ❌ mitigating_control | ✅ | ✅ |
| `rancher-4dc4f53-47914` | exploitable | ✅ | ❌ requires_config | ❌ code_not_reach | ⚠ recov./FAILED | ✅ | ❌ **code_not_reachable** | ✅ |
| `podman-6a65597-48795` | exploitable | ⚪ INCONCLUSIVE | ✅ | ✅ | ❌ code_not_reachable | ✅ | ✅ | ✅ |
| `k8s-ec78c0f-3121` | exploitable | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ **4/5 ложных (§9.1)** |

⚪ — abstain (не false-safe). ⚠ — recovered категория (strict = FAILED).

**Ни одна протестированная модель не проходит safety-gate с учётом всех наблюдавшихся попыток.** У Qwen3.8 нулевой False-Safe в основном one-shot **не был вызван сокрытием отрицательного ответа**: конкретно его `k8s-3121` в основном прогоне содержал **верное `vulnerable`**, которое официальный парсер ошибочно классифицировал как `parse_fail` (§9.2–9.3). При этом **другие попытки того же кейса** дали False-Safe (2/3 в stability после parser-repair и 4/5 в risk probe). Значит нулевой результат одного прохода нельзя интерпретировать как устойчивое отсутствие опасных отрицаний. В другом stability-attempt `parse_fail` действительно скрывал отрицательную категорию — это самостоятельная проблема наблюдаемости риска.

**Модельные слепые зоны — разных типов, модели взаимно дополняют:** Qwen3.6 ломается на indirect dispatch (`rancher`, 2/5), Qwen3.8 — на различении «генератор vs сгенерированный артефакт» (`k8s-3121`, 4/5). На этих кейсах каждая чиста там, где другая ошибается. **n=5 повторов на кейс, ablation нет.**

**Наблюдение о двух B2-конфигурациях (без причинного вывода):** в B2-contaminated false-safe — `rancher-47914`, в B2-ISO — `podman-6a65597`; **counts равны 1**. Между прогонами менялись изоляция, harness, runtime и attempt policy — **вклад изоляции не отделён**. False-safe, воспроизведённый **без** локального GT, доказывает лишь возможность такой ошибки.

**Механизмы ошибок (по сверке с сырыми reasoning):**

1. **`rancher-47914`: Codex НЕ «не проследил» indirect path.** Во всех 3 repeat'ах reasoning явно описывает `pkg/controllers/dashboard/helm/repo.go` → `git.Head/Update` → `pkg/catalogv2/git/git.go` → `injectAgent` → `agent.ServeAgent:136` и прямо пишет «Therefore code_not_reachable does not apply». Ошибка — в **интерпретации configuration-gate** (недостижимый `ClientSecret`/SSH-auth конфиг).
   **Gemini (contam.)** тоже называет работающий `ServeAgent`, но отрицает, что git-клиент доходит до identity-add/`parseConstraints` — unsafe protocol/input-boundary denial.
   **Gemini (B2-ISO)**: сохранённый ответ **оборван фильтром** внутри описания CVE; видимого trace репозитория в нём **нет** — приписывать ему точный trace нельзя (восстановлена только категория).
   **Qwen** — с точным trace в reasoning.
2. **`k8s-44487`: A и B3 заякорились на advisory-компоненте** (`x/net/http2`). A вынесла `NOT_AFFECTED` (OSV покрывает только `x/net`), B3 нашла apiserver-митигацию `UnauthenticatedHTTP2DOSMitigation` и вынесла `mitigating_control_protected`. Оба пропустили реальный путь через `grpc v1.55.0` в kubelet. Codex и Gemini (оба прогона) нашли его.
3. **`podman-6a65597` (Terrapin, B2-ISO):** Gemini отрицал достижимость SSH-пути из-за отсутствия **прямого first-party импорта** уязвимого пакета (в отличие от B1/Codex, который нашёл `ssh.Dial` в `pkg/bindings/connection.go`). Установленного configuration-gate здесь нет.

4. **Ни один режим не достиг `False-Safe = 0`.** Это мотивация для §4, но не доказательство какой-либо архитектуры.

---

## 3. Профиль ошибок по моделям (в этом прогоне)

| | Codex B1 | Gemini B2 (contam.) | **Gemini B2-ISO** | Qwen B3 |
|---|---|---|---|---|
| False-Safe | 1 / repeat (3 pooled attempts одного кейса) | 1 | **1** | 1 |
| False-alarm | pooled 1 / 90 (counts [0,0,1]) | 0 / 23 | **0 / 23** | 4 / 23 |
| Наблюдаемая сильная сторона | поиск за пределами advisory | поиск за пределами advisory, 0 FA | 0 FA *(reasoning неполон: 3 усечения)* | точный trace непрямых вызовов |
| Наблюдаемая слабость | configuration-gate denial | protocol/input-boundary denial | отрицание reachability без прямого first-party импорта | смелость: 4 false-alarm |

**B2-ISO:** 3/30 ответов усечены safety-фильтром (§8.6); false-safe пришёлся на `podman-6a65597`. **Точный trace indirect path у B2-ISO приписать нельзя** — сохранённый Rancher-ответ оборван фильтром внутри описания CVE, trace в нём отсутствует; восстановлена только категория, не обоснование.

**B1 false-alarm (добавлено):** `kubernetes-kubernetes-1ee2acb-CVE-2024-24786` в `run_003` — единственный FA на 90 attempts.

**False-alarm у Qwen (4, из них 3 — недооценка гейтов достижимости, 1 — версия/фикс):**
- `cilium-43bff35` — пропустила `--port-forward` (default false) → нужно было `requires_configuration`;
- `echo-fdacff0` — неверно решила, что `MapClaims.Validate()` зовёт `VerifyAudience` (в jwt-go v3.2.0 — нет);
- `trivy-98e136e` — «stdlib-вулн ⇒ достижимо», пропустив триггер `Expect: 100-continue`;
- `k8s-6d4b94f` — **affected-version/fix-presence ошибка**: не распознала, что pseudo-version `...1e63c2f08a10` **и есть** фикс-коммит (не reachability-gate).

Причинные утверждения выше ссылаются на оригинальные output'ы агентов (`agent://Q_14_echo26160`, `agent://Q_15_trivy24791`, `agent://Q_28_k8s41717`), а не только на post-hoc аннотации в `results.jsonl`.

> Профили моделей («осторожна»/«смелая») — описание **наблюдаемых ошибок в одном прогоне**, не устойчивая таксономия. Qwen, например, единственная LLM с верным `rancher-47914`.

---

## 4. Архитектурный вывод после Task 3

**Task 3 не доказывает готовую Hybrid-архитектуру.** Он доказывает более узкие вещи.

### 4.1. Plain Agent нужен в дальнейшей архитектуре

Izyan: `Safe Clear 43.5 %`, `EXPLOITABLE recall 28.6 %`, `INCONCLUSIVE 40 %`.
Plain Agent (B1, изолированный baseline) показывает существенно более высокую способность самостоятельно разбирать реальные vulnerability-кейсы (`SCR ≈97 %`, `recall 85.7 %`).

Поэтому дальнейшее развитие только за счёт усложнения deterministic semantic analysis выглядит **неоптимальным** — по крайней мере для exploitable/safe-разрешения.

### 4.2. Plain Agent нельзя сделать authoritative самостоятельно

**Все** исследованные режимы дают завершённый отрицательный ответ на exploitable-GT: A=1, B1=1, B2=1, B2-ISO=1, B3-host=1, Q3.6-ISO=1, **Q3.8-ISO=1** (в stability/risk probes; its one-shot `0/7` — исторический single-pass, §9.6). Следовательно `Agent verdict ≠ авторитетный verdict` — прямо следует из инварианта проекта.

### 4.3. Минимум два механизма опасной ошибки

Наблюдаются **как минимум два** механизма (не исчерпывающая таксономия):

| Механизм | Кейс | Где ошибка |
|---|---|---|
| **1. Неверно определена область vulnerability / exploit model** | `k8s-44487` | Ошибка **до** negative verification: advisory-маппинг взяли за границу области, реальный affected-компонент (`grpc v1.55.0`) вне неё |
| **2. В корректной области неверно оценено обязательное условие эксплуатации** | `rancher-47914` | Plain Agent **нашёл путь**, но необоснованно объявил блокирующий configuration-gate; формальной `NegativeVerification` у него не было |

Следствие: проверка **локального** negative в **неполной** области недостаточна для глобального CVE-safe verdict — контракт должен учитывать **scope/completeness**. Это можно реализовать и внутри существующего контракта acceptance (верификатор, отвергающий global-negative как `INSUFFICIENT_SCOPE`), поэтому вывод **не** доказывает необходимость отдельного нового модуля.

### 4.4. Следующий эксперимент — режим C (предлагаемый, не доказанный оптимум)

**Предлагаем** следующий эксперимент C (согласован с roadmap): проверить, помогают ли агенту **инструменты** Izyan.

```
C: CVE + snapshot → LLM Agent исследует → при необходимости вызывает typed tools Izyan → AgentAssessment
   (dependency/version facts, govulncheck, find_callers, find_references,
    trace_argument, find_validations, build/config facts, dynamic-dispatch checks)
```

Критерий проверки C: **меняет ли Evidence Tools профиль ошибок** (false-safe / recall / SCR) при сопоставимом протоколе. `AgentAssessment` — вне production verdict.

Результатов C/D, их стоимости и сравнения альтернатив **нет**. Что порядок C→D оптимален, что Hybrid даст нужное качество — **проектная гипотеза**, не измеренный факт. Конкретный состав Kernel проектируется **после** C.

### 4.5. Что Task 3 позволяет утверждать сейчас

> **Agent-first анализ — кандидат для дальнейшего развития Izyan: Plain Agent (B1) на данном корпусе заметно превосходит текущий deterministic-first pipeline по полноте. При этом Plain Agent самостоятельно не проходит safety-gate. Следующий шаг — эксперимент C; необходимость и состав Verification Kernel определяются по его результатам.**

Чего данные **не** устанавливают:
- что Hybrid — **единственная** архитектура, способная достичь `False-Safe = 0` при `Safe Clear Rate > 90 %` (0 прогонов Hybrid; качество Kernel не измерено; альтернативы — исправление deterministic advisory intake, проверка новых falsifiers — не исключены);
- что существующий deterministic Izyan уже является подходящим Verification Kernel (у него свой False-Safe на `k8s-44487`);
- что B1 превосходит A для **класса** Plain Agent вообще — только на данном фиксированном corpus.

`False-Safe = 0` и `SCR > 90 %` — **цели будущей валидации**.

---

## 5. Артефакты

```
/tmp/vexbench-baseline/runs/external-baseline-1/     # A (frozen)
/tmp/vexbench-plain/full/                            # B1 (official harness, 90 attempts)
/tmp/vexbench-plain/b2/                              # B2 (Gemini subagent)
/tmp/vexbench-plain/b3-qwen-subagent/                # B3 (Qwen subagent)
/tmp/vexbench-plain/b3-qwen-python-harness/          # отброшенный Python-харнес (см. §6)
```

## 6. Отброшенный Python-харнес (B3-python)

Первая попытка B3 использовала самописный Python runner (`max_steps=8`, только `bash`+`read_file`, **без `web_search`**).

Числа (n=30, 1 repeat):
- **strict correct-status = 11/30 = 36.7 %** (abstain считается ошибкой);
- **official-compatible Accuracy = 22/30 = 73.3 %** (`uncertain→not_exploitable`);
- 24 строки `steps=8`; из них 15 с non-`uncertain` финальной категорией и **9** `uncertain`; ещё **6** `uncertain` завершились раньше (3,4,5,6,7,7 шагов);
- `TIMEOUT_STEPS` — **ровно 1** (`k8s-ec78c0f`); 14 из 15 `uncertain` имеют пустой `raw_content`.

**Важно:** 36.7 % — это **другая метрика**, чем Binary Accuracy основной таблицы (73.3 % при той же compatibility-политике). Ставить их рядом без пометки нельзя.

**Формулировка причины (исправлено):** результат получен **в другой, ограниченной runner-конфигурации**; вклад harness и модели **не разделён** (ablation не проводился). Утверждение «отражает harness, а не модель» данными не подтверждается. Основание для отброса — **фиксированный критерий несопоставимости** (иной toolset, отсутствие `web_search`, жёсткий step-limit), а не низкая accuracy. Post-hoc исключение прогона раскрыто здесь явно.

---

## 7. ⚠ Contamination: B2 не является слепым baseline

**P0-находка ревью.** Субагенты B2/B3 бегут **на хосте** с полным доступом к ФС. Каталог `/tmp/vexbench-baseline/` содержит `go-tasks.jsonl` и `vex_bench.jsonl` — оба с полями `ground_truth` / `ground_truth_category`.

**B2 (Gemini): 11 из 29 транскриптов содержат фактическое значение GT**, и все 11 совпали с GT по точной категории. GT прочитан **до** вердикта (например `B2_06_cilium`: строка 97 из 225; `B2_13_k8s24786`: 48/152; `B2_25_k8s3121`: 60/171).

Механизм (`B2_25_k8s3121`, строки 55–60): агент сам сделал `glob /tmp/vexbench-baseline/*`, затем `grep "CVE-2021-3121" .../vex_bench.jsonl` и получил строку с `ground_truth_category`. Аналогично `B2_13/16/17/21/26` — `grep`/`read` по `go-tasks.jsonl`.

Дополнительно `B2_08_rancher47914` (свой GT не читал) читал транскрипты **соседних** кейсов (`B2_01,02,03,04,05,07,09`) — то есть оценивал не вслепую.

**B3 (Qwen): 0 из 30** — строка `ground_truth` не встречается ни в одном транскрипте (`Q_13` сделал только листинг каталога, значение не читал).
**B1 (Codex): чист по построению** — `src/evaluate/agents/base.py:43` («workspace is never bind-mounted»): контейнер создаётся `docker create` + `docker cp` снапшота; из хостовых путей монтируется только config-файл (`codex.py:59`).

**Следствие:** наблюдаемые B2-числа (Safe Clear 100 %, False-alarm 0, F1 0.923) **нельзя публиковать как строгую слепую независимую оценку** — только как дескриптивный **неизолированный host-run**. B3 валиден по факту (0 утечек), но харнес **не изолирован** — это латентный риск, подлежащий закрытию. Для восстановления статуса blind baseline требуется **отдельный изолированный прогон** с реально недоступными GT, историями агентов и артефактами Izyan.

---

## 8. Изолированный перепрогон B2 (Gemini) — выполнен

Gemini прогнан через **официальный harness** (адаптер `opencode`) в **disposable Docker-контейнере** `vex-bench-go-opencode:latest`, как B1. Снапшот и промпт копируются `docker cp`.

**Проверка изоляции:** внутри контейнера `/tmp/vexbench-baseline` отсутствует, `find / -name go-tasks.jsonl` → ничего. Корректная формулировка: **GT, истории агентов и каталоги результатов с хоста не монтируются; монтируется только read-only config провайдера** (`opencode.py:160-186`) — не «ничего не монтируется».

| Свойство | B2 (загрязнён) | **B2-ISO** |
|---|---|---|
| Харнес | omp subagent (хостовый) | **официальный harness + Docker** |
| Доступ к GT | 11/29 кейсов читали GT | **0 — недостижим** |
| Истории агентов Izyan | доступны | недоступны |
| **Attempt policy** | 1 pass | ⚠ **retry-composite, см. §8.5** |
| Prompt / кейсы / GT | официальные | те же |

### 8.1. Три числа, которые нельзя смешивать

Ревью зафиксировало расхождение проекций. Три разных «completion»:

| Число | Значение | Что означает |
|---|---|---|
| **Официальный harness** | **26/30** | `ok=26`; `parse_fail=2`, `no_result=2` → FAILED=4 |
| Завершённые ответы текущего raw | 27/30 | один `no_result` (Moby) пересобран не-фильтровым repair (§8.4) |
| **Coverage извлечённых категорий** | **30/30** (RECOVERY) | `category` есть у всех 30 после восстановления |

### 8.2. Официальные метрики (сохранённый `metrics.json`)

| | TP | FP | TN | FN_official | FAILED | SCR | recall | F1 | accuracy |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **Официальный harness** | 4 | 0 | **21** | 1 | **4** | **21/23 = 91.3 %** | 4/7 = 57.1 % | 0.727 | 25/30 = **83.3 %** |
| **RECOVERY** (проекция) | 6 | 0 | 23 | 1 | 0 | 23/23 = 100 % | 6/7 = 85.7 % | 0.923 | 29/30 = 96.7 % |

**Важно:** правило «`filter_truncated → FAILED`» даёт TN=22/FAILED=3, что **не совпадает** с официальным (TN=21/FAILED=4). Причина — **четвёртый**, не-фильтровый repair (§8.4). Поэтому ранее использованное имя «HARNESS-STRICT» было **неточным**; официальные числа — в строке выше.

`FAILED_exploitable = 2`, `FAILED_safe = 2` (официально). Официальный `binary.totals.fn=1` считает только завершённые negative-ошибки, а не `7−TP`.

### 8.3. RECOVERY — что это такое (и чем не является)

**Определение.** RECOVERY — **вторичная post-hoc label-only проекция** опубликованных моделью `category`-токенов, **не** восстановленный полноценный verdict.

**Механизм (на реальном фрагменте `rancher-47914`):**
```
{"category": "vulnerable", "reasoning": "CVE-2025-47914 affects ... (such as inThis request was blocked by Gemini's filters...
```
1. `category` стоит в JSON раньше `reasoning` (требование официального prompt).
2. Фильтр обрывает `reasoning`, `category` **уже напечатан** и завершён.
3. Извлечение — GT-blind правило: последний assistant raw-ответ → regex `"category"\s*:\s*"([a-z_]+)"` → проверка значения по whitelist 12 категорий → иначе `FAILED`.

**Ограничения (обязательные):**
- восстанавливается **только** категория; **`reasoning` и предполагаемое продолжение не восстанавливаются**;
- оборванный reasoning **нельзя** использовать для оценки качества обоснования;
- гипотетический полный ответ **мог бы** отличаться — RECOVERY этого не доказывает;
- **не** полноценный JSON-ответ, **не** подтверждён falsifier;
- правило применяется **единообразно ко всем** категориям, GT-blind, только к последнему assistant-ответу (не к prompt/примеру/tool output);
- **30 восстановленных labels ≠ 30 полноценных завершённых ответов.**

**Что НЕ утверждается:** что одной буквальности извлечения достаточно для доказательства отсутствия подгонки; что RECOVERY эквивалентен официальному парсеру (тот требует парсибельный JSON, `result_parser.py:24-79`).

**Усечённые кейсы (3):**
| Кейс | GT | Напечатано | Official status |
|---|---|---|---|
| `k8s-minikube-e7bf515-5736` | safe | `code_not_present` | parse_fail |
| `rancher-4dc4f53-47914` | **exploitable** | `vulnerable` | parse_fail |
| `stretchr-testify-285adcc-28948` | **exploitable** | `vulnerable` | no_result |

Источник: `final/results.jsonl`, raw `…/run_001/artifacts/opencode-stdout.txt`.

### 8.4. Четвёртый repair: Moby (не-фильтровый)

`moby-moby-caea5f7-CVE-2026-39883` в официальном `parsed.jsonl` = `no_result`, но текущий raw stdout содержит **полный неусечённый** `code_not_reachable`. Поэтому переход official→RECOVERY меняет **четыре** записи: три усечённых **плюс** этот capture/result repair.

[INFERENCE] Вероятно, официальный parse снят по более раннему состоянию артефактов; точная временная причина `no_result` не установлена — это **не** доказанный дефект парсера.

### 8.5. ⚠ Attempt policy: retry-composite, не first-attempt baseline

Номинально `repeats=1`, но фактически **7 кейсов переисполнены** под тем же `run_001` (minikube, rancher-47914, k8s-1ee2acb, testify, echo, cilium-1228cbc, moby-caea5f7); остальные 23 — из cache; 2 smoke-кейса — тоже cache. **Это не 30 first-attempt ответов без ретраев.**

План `docs/dev/plans/2026-10-08-vexbench-plain-agent-plan.md` запрещает outcome-driven retries и подмешивание smoke в first-attempt baseline. **Первоначальные attempt-preserving backups не сохранены** — парной выборки initial→retry нет.

**Следствие:** B2-ISO классифицируется как **retry-composite exploratory result**, а не first-attempt baseline. Доказательный статус понижен. Для строгого baseline нужен прогон с единой attempt policy.

### 8.6. Фильтры Gemini: наблюдаемый отказ провайдерского пути

**3/30** финальных raw-ответов содержат `"This request was blocked by Gemini's filters"` после полностью напечатанного `category`. Это **число усечённых ответов в финальном наборе**, а не частота блокировок всех попыток.

**Что подтверждено:** operational refusal исследованного Gemini-provider-path существует; контур должен обрабатывать его **fail-closed**.

**Что НЕ утверждается:**
- что refusal «не лечится промптом» (raw сам предлагает rephrasing) — **не измерено**;
- что ретраи «сняли блокировки» — парной выборки нет, все три усечения сохранились после retry-волны;
- что стохастика имеет установленную вероятность/зависимость от CVE;
- что отказ автоматически означает unsafe decision (он может быть fail-closed);
- преимущество self-hosted перед внешними моделями — **не измерено**;
- `finish_reason` в export = `stop`, а не специализированный `content_filter`; внутренний механизм фильтра не реконструируется.

**Refusal ≠ `uncertain`:** это разные причины невыдачи решения. `uncertain` — содержательный отказ при нехватке доказательств; refusal — отклонение запроса. Категория до обрыва **не** доказывает достаточность доказательств: «Reasoning не завершён; полноту анализа установить нельзя». В safety-контуре обе ведут к отсутствию safe claim, но операционно различаются.

### 8.7. Покейсовое сравнение B2-contaminated vs B2-ISO (дескриптивно)

**Изменились 5 категорий** (не 6); только 2 из них меняют binary direction:

| Кейс | GT | B2-contam | B2-ISO | направление |
|---|---|---|---|---|
| `cilium-43bff35` | safe | requires_configuration | code_not_reachable | — |
| `rancher-4dc4f53-47914` | **exploitable** | code_not_reachable (FS) | vulnerable *(recovered)* | меняет |
| `podman-6a65597` | **exploitable** | vulnerable | code_not_reachable (FS) | меняет |
| `podman-5ae6347` | safe | code_not_present | false_positive | — |
| `k8s-6d4b94f` | safe | code_not_present | code_not_reachable | — |

`k8s-1ee2acb` **не** менялся (`code_not_reachable` в обоих) и **не** filter-recovery.

**Ограниченное наблюдение:** в B2-contaminated false-safe — `rancher`, в B2-ISO — `podman`; **counts равны 1**. Между прогонами менялись изоляция, harness, runtime и attempt policy — **вклад изоляции не отделён**. Тот факт, что false-safe воспроизвёлся **без** локального GT, доказывает лишь возможность такой ошибки, **не** происхождение contaminated-ошибки и **не** равенство истинного риска. Формулировку «утечка мешала», «инвариант устойчив» из отчёта убрал как недоказанную.

### 8.8. Артефакты

```
/tmp/vexbench-gemini-iso/
    smoke-results/c0a5c8458b77/opencode/gemini-3.8-flash-high/   # 30 raw + official metrics.json (FAILED=4)
    final/results.jsonl                                          # derived: category + filter_truncated
    full-run.log, retry.log, retry-tasks.jsonl                   # attempt policy
/tmp/vexbench-agent-ctl/env/opencode/opencode.json               # provider config
```

> **PublicationGate (ревью):** B2-ISO как **HARNESS-STRICT / first-attempt baseline** публиковать нельзя (расхождение official/derived scoring, скрытый 4-й repair, выборочные ретраи). Как **дескриптивное** сообщение «в изолированном наборе есть один negative на exploitable» — допустимо.

---

## 9. Изолированные прогоны Qwen (3.6 и 3.8) — выполнен

Обе модели прогнаны **официальным harness** (адаптер `opencode`) в **Docker**. Container-образ дополнен корпоративным CA (`vex-bench-go-opencode-gw`), т.к. `<corporate-provider-host>` использует внутренний CA. GT недостижим.

### 9.1. SAVED OFFICIAL (не переписывается)

| Метрика | Qwen3.6-35B-A3B | Qwen3.8-27B |
|---|---:|---:|
| TP / FP / TN / FN_official | 6 / 2 / 19 / 1 | 6 / 2 / 20 / 0 |
| FAILED (exploitable / safe) | 2 (0 / 2) | 2 (1 / 1) |
| **False-Safe** | **1/7 = 14.3 %** | **0/7 = 0 %** |
| Safe Clear Rate (из 23) | 19/23 = 82.6 % | 20/23 = 87.0 % |
| EXPLOITABLE recall (из 7) | 6/7 = 85.7 % | 6/7 = 85.7 % |
| False-alarm (из 23) | 2/23 = 8.7 % | 2/23 = 8.7 % |
| Binary Accuracy | **25/30 = 83.3 %** | **26/30 = 86.7 %** |
| Precision / F1 | 0.75 / **0.800** | 0.75 / **0.800** |
| Completion | **28/30** | **28/30** |

Тип прогона: Q3.6 — **exploratory mixed-admission one-shot** (28 fresh + 2 cached protocol-smoke, §9.9); Q3.8 — one-shot 30/30.

### 9.2. ⚠ Дефект harness-парсера (подтверждён)

Официальный extractor (`result_parser.py:53-79`) **не строго-осведомлён**: brace-counting не учитывает строковые литералы. В reasoning Qwen есть Go-код со скобками (`if skippy < 0 { ... } else { ... }`), из-за чего **полный валидный JSON теряется**.

Проверка (`main Q3.8 k8s-3121 run_001`): last assistant text содержит полный `{"category":"vulnerable",...}`; harness brace-count кандидаты падают на `Unterminated string`; `JSONDecoder.raw_decode` → **`vulnerable`**.

**Дефект двунаправленный — теряет и верные positive, и небезопасные negative:**

| Run | Underlying label | Official | Parser-repair |
|---|---|---|---|
| main Q3.8 `k8s-3121` run_001 | **vulnerable** (верно) | parse_fail | vulnerable → TP |
| stability Q3.8 `k8s-3121` run_001 | **code_not_reachable** (небезопасно) | parse_fail | negative |
| stability Q3.8 `k8s-3121` run_003 | vulnerable (верно) | parse_fail | vulnerable |

Это **не** stale-capture и **не** отсутствие JSON. `FAILED ≠ negative` и `FAILED ≠ «модель не смогла»`.

### 9.3. POST-HOC PARSER-REPAIR (отдельная проекция, не официальная)

Исправление извлечения **полного JSON** — иная операция, чем RECOVERY (§8.3, обрывок) и чем prose-extraction. Публикуется **рядом** с official:

| Проекция | TP | FP | TN | FN | FAILED | recall | accuracy | F1 | completion |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Q3.8 official | 6 | 2 | 20 | 0 | 2 | 6/7 | 86.7 % | 0.800 | 28/30 |
| **Q3.8 parser-repair** | **7** | 2 | 20 | 0 | 1 | **7/7 = 100 %** | **27/30 = 90.0 %** | **0.875** | **29/30** |
| Q3.6 official = parser-repair | 6 | 2 | 19 | 1 | 2 | 6/7 | 83.3 % | 0.800 | 28/30 |

Правка — **один** кейс (`k8s-3121`); `cilium-43bff35` остаётся prose-format failure.

**Если публикуется prose label-only проекция** (Istio/Cilium) — отдельная строка, GT-blind, симметрично: Q3.6 accuracy 86.7 %, Q3.8 accuracy 93.3 % / recall 100 %. Молчаливый prose-reparse **может поднять recall и одновременно скрыть небезопасную категорию** (пример — stability run_001).

### 9.4. Провалы: четыре класса, не «форматные»

| Кейс | Namespace | Класс |
|---|---|---|
| `istio-042afc3` | main Q3.6 | **prose-format** (`` `code_not_reachable` `` без JSON) |
| `cilium-43bff35` | main Q3.8 | **prose-format** («classification is `requires_configuration`») |
| `k8s-3121` | main Q3.8 | **parser defect** (полный верный JSON) |
| `echo-fdacff0` | main Q3.6 | **timeout** (exit 124) |

`FAILED` смешивает эти классы; **underlying label не выводится из failure-class**.

### 9.5. Probes (NOT baseline)

Отдельные каталоги; все попытки публикуются (без best-of); official не заменяются.

**stability-probe** (`repeats=3`):

| Модель | Кейс | GT | official | parser-repair |
|---|---|---|---:|---|
| Q3.6 | `echo-fdacff0` | safe | vulnerable ×3 | — |
| Q3.6 | `istio-042afc3` | safe | code_not_reachable ×3 | — |
| Q3.8 | `cilium-43bff35` | safe | requires_configuration, perimeter_protected, requires_configuration | — |
| Q3.8 | **`k8s-3121`** | **exploitable** | parse_fail, code_not_present, parse_fail → **FS 1/3** | code_not_reachable, code_not_present, vulnerable → **FS 2/3**, FAILED 0 |

**risk-probe** (`repeats=5`):

| Модель | Кейс | Вердикты (run_001..005) | False-Safe |
|---|---|---|---:|
| Q3.6 | `rancher-47914` | perimeter_protected, FAILED, vulnerable, FAILED, perimeter_protected | **2/5** |
| Q3.6 | `k8s-3121` | vulnerable, vulnerable, FAILED, vulnerable, vulnerable | 0/5 |
| Q3.8 | `rancher-47914` | vulnerable ×5 | 0/5 |
| Q3.8 | `k8s-3121` | FAILED, perimeter_protected, code_not_reachable ×3 | **4/5** |

### 9.6. Safety-gate: не проходит ни одна конфигурация

**Обоснование — наблюдённые counterexamples**, не экстраполяция. У каждой Qwen-конфигурации есть завершённый отрицательный ответ на exploitable-GT: Q3.6 — `rancher` (main+risk), Q3.8 — `k8s-3121` (stability+risk).

Достаточно **одного** контрпримера. Это **не** означает: что риск корпуса = 40 % или 80 %; что «1/7 занижает»; что следующий полный проход обязательно ненулевой. **1/7** — cross-case доля одного прохода; **2/5 и 4/5** — attempt-frequencies на двух выбранных кейсах, не корпусная доля.

### 9.7. Механизмы ошибок — разные

| Конфигурация / кейс | Механизм |
|---|---|
| Q3.6 main `rancher` | ложное **отсутствие first-party imports** |
| Q3.6 risk `rancher` (×2) | perimeter/protocol-boundary denial **при найденном** trace (`ServeAgent:136`) |
| Q3.8 risk `k8s` (×3) | **CVE/package-scope denial**: generator vs сгенерированный артефакт (+1 auth-perimeter denial) |
| Q3.8 stability `k8s` run_002 | отдельная **OpenSSH-CVE-галлюцинация** |

**«4/5 — один устойчивый механизм» не воспроизводится.** Допустимо: «повторяемая ошибка в исследованных attempts».

### 9.8. Тайминг

| Режим | n | dt_med | **end_med** | dt_mean | end_mean |
|---|---:|---:|---:|---:|---:|
| Q3.6-ISO | 29/30 | 74 | **79** | 76.2 | 82.6 |
| Q3.8-ISO | 30/30 | 96 | **106** | 148.5 | 159.6 |
| stability q36 / q38 | 6 / 6 | 101 / 109 | 108 / 120 | 99.9 / 140.5 | 107.8 / 155.4 |
| risk q36 / q38 | 8 / 10 | 124 / 116 | 129 / 125 | 118.6 / 122.1 | 124.8 / 132.2 |
| B2-ISO | 30/30 | 88 | **114** | 114.1 | 136.7 |

**⚠ Граница.** `dt = (updated − created)`, но `updated` **предшествует** финальному assistant-ответу **во всех 119 exports** (delta 2.6–90.5 с). **dt — нижняя граница** session-to-answer, не end-to-end wall и не `docker create→destroy`. `enddt = (last assistant completed − created)` — session-to-final-answer, без setup/copy/cleanup. `B1` — **`mean ± sample std` трёх частично наблюдаемых repeat means** (coverage 8/8/7), не медиана. ISO и probes — разные cohorts; timeouts цензурированы.

### 9.9. Артефакты

```
/tmp/vexbench-qwen-iso/q36/{c0a5c8458b77/opencode/qwen3.6-35b/ , final/results.jsonl}
/tmp/vexbench-qwen-iso/q38/{c0a5c8458b77/opencode/qwen3.8-27b/ , final/results.jsonl}
/tmp/vexbench-qwen-iso/flaky-probe/{PROTOCOL.md,RESULTS.md,q36-tasks.jsonl,q38-tasks.jsonl,q36/,q38/}
/tmp/vexbench-qwen-iso/risk-probe/{tasks.jsonl,RESULTS.md,q36/,q38/,q36.log,q38.log}
/tmp/review2/timing-recompute.json          # raw created/updated/completed по каждой строке
/tmp/vexbench-agent-ctl/docker/go.opencode.gw.Dockerfile   # + corporate CA
```

**Protocol-honesty:** probes — separate dirs, все attempts сохранены (result.json / error.txt), best-of в логах нет. `parsed.jsonl` probes имеет corpus-shape (90/150 rows); реальные probe-attempts фильтруются по task-manifests (stability: 6/model; risk: 10). `final/results.jsonl` **не** восстанавливает failed-категории (`null`).

> **EngineeringFollowup:** исправление extractor (строко-осведомлённый brace-count) — отдельная задача; правки внешнего harness-checkout ревью не поручает. Для честной публикации достаточно frozen official + явная post-hoc проекция. При исправлении — аудировать affected parse_fail, сохранить оригиналы; новых прогонов не требуется.


---

## 10. Решение после изолированных перепрогонов

**Task 3 закрыть как исследование Plain Agent.** Новые данные не подтверждают преимущество определённой модели и не дают основания делать LLM authoritative. Дополнительные полные перепрогоны Gemini/Qwen сейчас не являются блокером — основной blind baseline B1/Codex уже есть.

**Следующий единственный этап — Task 4 / C1: `Codex + Izyan Evidence Tools`.** Сравнивать с **B1/Codex**, а не с загрязнённым B2 или одноразовыми Qwen-результатами.

### Порядок

1. **Зафиксировать артефакты Task 3.** Сохранить все исходные outputs/official metrics/attempt IDs отдельно от post-hoc interpretations, с хешами; не переписывать `run_001` выборочными ретраями. Базу B1 оставить неизменной.
2. **C1 smoke на трёх кейсах** без hints по именам CVE и без GT: проверить корректность вызова typed tools, evidence refs, границы доступа и `AgentAssessment`.
3. **C1 полный прогон 30 Go-кейсов × 3 повтора** с той же моделью, что B1, тем же official Docker harness, теми же source snapshots, CVE research permissions и по возможности тем же бюджето-временным протоколом. Идеально — расширить toolset B1 инструментами Izyan, а не одновременно заменить старые инструменты, prompt и agent loop: иначе разница B1↔C1 не покажет эффект специализированных tools.
4. **Считать official/failure-aware metrics и покейсовые расхождения.** Сколько B1 False-Safe исправлено? Не появились ли новые? Какие именно tool-observations изменили вывод, а какие вызваны без пользы? Дополнительно отдельно анализировать failure/abstain, не смешивать их с safe.
5. **После C1 решить, что проектировать в Verification Kernel.** Не реализовывать большой новый kernel до того, как станет ясно, какие ошибки остаются при наличии typed tools.

### Критерий приёмки Task 4

- `AgentAssessment` отделён от production `Verdict`;
- ни GT, ни B1 outputs, ни готовые claims Izyan не видны агенту;
- C1 run воспроизводим с прозрачной attempt policy;
- есть сравнение B1↔C1 и ссылки на decisive observations;
- запрещены case-specific rules и обучающие подсказки по опубликованным ответам VEX-Bench;
- результат **не** интерпретируется как доказательство реального zero-risk по 7 positive-кейсам.

**Отдельный engineering follow-up:** исправить JSON extraction официального harness или вести версионированную full-JSON-repair-проекцию по заранее зафиксированному правилу. Не смешивать это с Task 4 и не корректировать только «удобные» для модели parse_fail (§9.2–9.4).

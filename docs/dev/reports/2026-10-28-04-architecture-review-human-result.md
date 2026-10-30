# DESIGN_FOR_REVIEW — архитектурное ревью объединённого Shadow/V2

## Главный вывод

**Решение 20 октября менять не нужно: LLM-first триаж — основной продукт для человека, детерминированный анализатор — отдельный источник доказательных заключений. Реализация пока не доводит это разделение до результата.**

Сейчас объединены значительные объёмы кода, но не сквозной пользовательский сценарий:

- один маршрут выдаёт строгий вердикт либо `FAILED`;
- второй — исследовательскую категорию и текст;
- третий — CI-рекомендацию, ограниченную небольшим набором детерминированных правил;
- старый decision-ready контур существует рядом со своей системой фактов, условий и ветвлений.

Человек получает последствия рассогласования этих маршрутов: отказ, арбитраж или досье, которое всё ещё надо самостоятельно превращать в решение.

**Основная архитектурная ошибка — не строгость доказательного ядра сама по себе, а распространение его требований на право LLM сформировать полезный результат триажа.** Одновременно в старом LLM-helper контуре остались обратные утечки: модель местами влияет на авторитетные claims, необходимость условий и сужение локусов.

Рекомендация: **один LLM-first маршрут расследования и подготовки решения; один общий слой наблюдений; один детерминированный контур допуска доказательных заключений.** Не новый универсальный доказатель и не очередное семейство CVE-правил.

Исследование выполнено read-only. Код, тесты и benchmark не запускались. Ниже факты отделены от прогнозов.

---

## 0. Что действительно измерено

### Текущий VEX recheck не проверяет принятый LLM-first продукт

`bench/run_vex_recheck_current.py` вызывает:

```text
izyan analyze ... --deterministic-only
```

Он не вызывает ни `triage`, ни `research-b1`. В `cmd/izyan/main.go:analyzeCase` этот флаг отключает LLM-resolver, builder, planner, claim fallback и reviewer.

Поэтому текущие:

- 4 `DECIDED / EXPLOITABLE`;
- 14 `FAILED`;
- 3 timeout;
- 1 missing advisory;
- 8 без завершённой строки harness;

— **результат Product A, а не объединённого LLM-first триажа**.

Это первостепенная ошибка проверки продукта: направление LLM-first было принято, но основной замер запускает другой маршрут. Однако это не оправдывает Product B: его собственные ограничения подтверждаются кодом.

### Product B уже перенесён, а не только запланирован

В выбранном Shadow присутствуют:

- `internal/productb/triage`;
- `internal/productb/research`;
- `verify`, `claimshape`, `heldoutgate`, `reportcheck`, `refindex`;
- CLI `triage` и `research-b1`.

`productb/triage/doc.go` устарел: composer/policy названы отложенными, хотя они существуют и вызываются из `cmd/izyan/triage.go`.

Говернинг-решение — `2026-10-20-06-approach-decision.md` и последующее уточнение target architecture. Записи R5/R6 в `gap-analysis.md` — история развития, а не основание повторно запрещать уже принятый LLM-first продукт.

### Исторические результаты LLM нельзя смешивать с текущим recheck

| Измерение | Наблюдение | Ограничение |
|---|---|---|
| V2 e2e rerun2 | 9/9 правильных направлений ответа | Три кейса × три попытки; исследовательский результат |
| V2 holdout use-based | 9/9; медиана около 73 с против 901 с plain | Три других кейса; один оценщик; ошибки/таймауты plain существенно влияют на сравнение |
| V2 dev baseline | 25/36 правильных; **2 false-safe**, 6 false alarm, 3 failed | 12 кейсов × три попытки |
| V2 dev citation | 32/36 правильных; **те же 2 false-safe** | Более подробные цитаты не устранили ошибочную идентификацию CVE |
| Universal verifier | 6/85 dismissals; 0 false-safe | Корпус human-NE; positive recall не измерен; admission default-off |
| Kernel corporate | 0/39 групп закрыто | 45 applicable tickets остались без изменения |

Источники: V2 `results/agent7/{e2e-blinded-eval,holdout-ablation,rootcause-ablation}`, `dev-comparison.json`, отчёты 20 октября.

Исторические LLM-результаты есть для **18 из этих 30 кейсов**, но получены в разных экспериментах. Для остальных 12 сохранённого LLM-прогона нет. Результаты текущего Shadow Product B на этих 30 кейсах **не измерены**.

Отдельно: правильная итоговая категория не означала готовность решения. В сохранённых e2e-метриках оценивались в среднем около 25,6 минуты до решения и 3,1 дополнительных ручных проверки. В отдельных root-cause замерах recall был нулевым; dev micro-F1 локуса — примерно 0,019, с citation — 0,006. Это существенное свидетельство против тезиса «достаточно заставить модель подробнее цитировать».

---

# 1. Инвентаризация переобучения и хардкода

**В просмотренном production-коде не найден dispatch вида `if CVE == X → answer Y`.** Основная специализация устроена иначе: словари формулировок, имён, классов механизмов и ограниченные доказательные языки.

Важно различать:

1. **нормальную доменную семантику** — Go imports, receivers, build constraints, module resolution;
2. **ограниченный специализированный доказатель** — полезен, если честно объявлена область применимости;
3. **case-shaped эвристику** — наблюдение, превращённое в общее правило после одного случая;
4. **benchmark-протокол** — допустим в evaluation, но не должен управлять production-продуктом.

### Конкретные механизмы

| Механизм и источник | Что зашито | Оценка и происхождение |
|---|---|---|
| `exploit/classify.go:cweClass` | 35 CWE-сопоставлений | Законная классификационная информация. CWE не доказывает конкретные необходимые условия эксплуатации. |
| `exploit/classify.go:keywordSignals` | 34 regex-правила классификации | Эвристическая интерпретация advisory. **[ВЫВОД]** Формулировки отражают корпус встреченных advisory; точная история добавления каждого правила не установлена. Не должна создавать авторитетную необходимость условий. |
| `exploit/classify.go:DetectProtocolRole` | 30 regex: server/client/symmetric и patch names, включая `HandleStreams` | Протокольная гипотеза по словам и именам. Опасна там, где её результат используется для FALSE о несовпадении роли. |
| `exploit/patterns.go:Registry` | 7 patterns, 19 condition templates | Семейства, а не отдельные CVE. Сохранять как предложения модели расследования; обязательность каждого условия требует собственного основания. |
| `exploit/semantics.go` | Regex для «called with … set to …», claim-полей, array/slice и «rather than a single string» | Точное совпадение с формулировками fixture GO-2020-0017. **[ВЫВОД]** Это case-shaped extractor. Типизированный контракт дефекта полезен; текстовый extractor не становится доказателем семантики из-за детерминированности. |
| `exploit/applicability.go:TLSFloorBound` | Отдельное исключение SSH и распознавание TLS floor | Защита от ранее неверно добавленного условия. Убирать особую власть исключения; TLS boundary должен следовать из конкретного доказанного основания. |
| `goanalysis/transport_proof.go:ProveServerTransport` | Один поддержанный trigger-механизм — HTTP/2 Rapid Reset; `Serve`, `ReadFrame`, quota/lifecycle формы | Реальный специализированный доказатель, связанный с Kubernetes-44487/gRPC acceptance. Не универсальный transport analyzer. Его нельзя запускать как обязательный путь для любого server peer-input случая. |
| `states.CollectEvidence.collectTransportProof` | Передаёт `MechanismHTTP2RapidReset` | Специализация просачивается в общий orchestration. Другой механизм получает нерелевантные обязательства. |
| `evaluator/transport.go:isServerTransportFrame`, `evaluateServerTransportInput` | Имена transport frames/receivers; unexported internals + module usage как основание TRUE; две role-mismatch FALSE-ветки | Слабые альтернативы уже существующим typed witnesses. Должны остаться гипотезами, не authority. |
| `evaluator/conditions.go:libraryUsageVerdict` | «Продукт использует API модуля, значит его unexported sink выполняется» | Не доказанная цепочка. Удалить TRUE-повышение; использовать конкретный путь либо UNKNOWN. |
| `evaluator/authn.go:Authentication.Evaluate` | Auth wiring по имени и соседству с listener | Код сам говорит «plausibly» и отсутствие per-route coverage, но устанавливает TRUE. Это структурная подсказка, не полный факт о пути. |
| `fixbinding/api.go:supportedOperations` | 4 class labels, 8 конкретных API-записей для файловых/permission операций | Законная ограниченная семантика API. Неверно превращать её в универсальный prerequisite отрицательного триажа. Trivy networking ей не покрывается. |
| `goanalysis/knowledge.json` | 229 записей в 17 семантических таблицах; в том числе три конкретные go-getter string transformations | Большая часть — нормальные Models-as-Data. Семантика отдельных сторонних функций требует версии, source binding и отдельного обоснования; имя пакета само по себе не зло, неподтверждённая универсальность — зло. |
| `goanalysis/provenance.go:reflectDispatchAPIs` | 13 API-моделей, включая yaml/mapstructure | Законная ecosystem-модель при точной идентичности/версии; не повод считать reflection вообще закрытой. |
| `exploit/subjects.go:pairStems`, фильтры путей | 8 пар глаголов; специальное исключение `/internal/testdata` | Парные имена годятся для поиска кандидатов. Классификацию test scope должен давать census, не похожесть пути на fixture. |
| `bench/run_vex_recheck_current.py:TARGET` | Четыре task-ID-specific build declarations | Прямой benchmark-shaped хардкод. Заменить данными о build context каждого task, не увеличивать таблицу после очередного падения. |
| V2/ported `research/prompt.go:useBasedVerdictRule` | «imported, referenced or called» объединены с «executes» | Prompt-level эвристика, не per-CVE ветка. Расширяет смысл исполнения и влияет на категории. |
| V2/ported `research/answer.go:facetKeywords`, `assumptionRx`, `unknownRx` | Пять групп ключевых слов; извлечение assumptions/unknowns из прозы | Удобство чтения, не структура доказательств. Может не извлечь важное допущение только из-за иной формулировки. |
| `productb/triage:DefaultRules`, `DefaultProfiles` | 5 правил решения, 2 профиля | Общая политика, не переобучение на CVE. Но именно эти пять правил, а не гибкое расследование LLM, определяют итоговую рекомендацию. |

### Что можно честно количественно утверждать

В семи просмотренных прямых директориях — `domain`, `evaluator`, `goanalysis`, `fixbinding`, `rootcause`, `exploit`, `cmd/izyan` — перечислены **120 production Go-файлов** и 142 test-файла. Это ограниченный read-set, не размер всего проекта.

В нём установлены перечисленные выше размеры таблиц. В дополнение сосуществуют:

- 13 condition evaluators;
- 20 falsifier kinds;
- три перекрывающиеся поверхности tools: старый analyze/LLM, research, Product B triage;
- 16 det-tools в triage;
- 3 вида triage falsifier proposals;
- 4 уровня `support_level`;
- 14 triage checks;
- 28 Product B schema declarations.

**Процент кода, написанного «ради кейсов», из этого вывести нельзя.** Ни совпадение fixture, ни количество таблиц не доказывают историю происхождения всего файла. Но доказано, что обобщение часто происходит добавлением ещё одного словаря/ветки и последующего admission-исключения.

---

# 2. Почему LLM-first не переносится в результат

## 2.1. Сегодня существуют три разных LLM-сценария

### A. Старый LLM-helper внутри `analyze`

Порядок уже задан детерминированным pipeline. Модель получает отдельное неизвестное условие и небольшой набор действий.

- `llm.RootCauseResolver` — fallback после deterministic discovery.
- `llm.Planner` — одно действие для одного уже сформированного условия.
- `llm.ClaimEvaluator` — fallback после deterministic gap loop.
- `llm.Reviewer` — проверка/изменение модели.

Это **не LLM-first расследование**. Модель не владеет постановкой вопроса и всем путём от advisory к рекомендации.

### B. V2 / ported `research-b1`

Это действительно свободное исследование, но production-контракт — `{category, reasoning}`.

Проблемы:

1. `research.Run` захватывает advisory, но вызывает `renderPrompt(o.CVE)`.
2. `buildRunPlan` монтирует snapshot, config и prompt — **не захваченный advisory**.
3. Значит, сохранённый host advisory не является обязательным исследовательским контекстом агента. Consistency сравнивает ответ с ним уже после расследования.
4. B1 намеренно отключает MCP, сохраняя benchmark-arm.
5. Вывод затем разбирается regex-группировкой; категория может быть salvaged без reasoning.
6. Нет обязательного action/confidence/decisive-assumptions контракта.

Источники: `productb/research/{research,agentrun,prompt,answer}.go`.

**[ВЫВОД]** Здесь сохранён воспроизводимый экспериментальный стенд вместо полноценного product workflow. Историческая CVE-misidentification — не только недостаток модели: входной контекст не заставляет расследовать именно захваченные записи.

### C. Product B `triage`

Здесь есть настоящий сквозной runtime: intake → snapshot → tools → agent → FactGate → falsifier verifier → composer → artifacts/replay/policy.

Но гибкость ограничена не только моделью:

- `detAllowlist` содержит 16 инструментов, исключая `trace_argument`, field assignments, dynamic scans, исследование fix/advisory;
- prompt запрещает отрицательное **мнение** при неполном детерминированном доказательстве;
- отрицательный ответ с advisory symbols требует ровно одного `code_absent` proposal;
- новый config/input механизм должен втиснуться в отсутствие кода либо стать `INCONCLUSIVE`;
- condition catalog не имеет in-repo producer;
- `runUnreachabilityKernel` передаёт `UnreachabilityRequestFor(s0, nil)`, что гарантированно отвергается;
- build session получает `runtime.GOOS/GOARCH`, CGO=false; `Finding.Target` не содержит полноценного target matrix;
- composer вычисляет рекомендацию из пяти правил, оставляя мнение LLM для арбитража;
- `HumanDecision` допускает только `"NOT_APPLICABLE (ci mode)"`;
- снижение без внешнего `AuthoritativeBaseline` превращается в runtime `ErrFalseSafe`.

Источники: `cmd/izyan/triage.go:{runUnreachabilityKernel,detToolExecutor}`, `productb/triage/{prompt,detools,conditioncatalog,composer,decision_types,metrics}.go`.

**Получается замкнутый круг:** LLM не разрешено дать содержательное отрицательное мнение без proof; proof требует отсутствующих producer’ов; composer предлагает человеку арбитраж, но schema не умеет записать его решение.

## 2.2. Где детерминированные гейты нужны, а где применены не к тому

Нужны:

- проверка snapshot/advisory identity;
- воспроизводимость цитат;
- точная семантика tool observation;
- запрет universal-negative на partial scope;
- допуск safe/VEX/автоматического снижения.

Не должны блокировать доставку человеческого результата:

- отсутствие corpus declaration;
- неподдержанный механизм;
- отсутствие готового falsifier kind;
- неизвестная severity baseline;
- отсутствие внешнего контрольного ответа;
- неполный call graph.

Они должны ограничивать **утверждение и уверенность**, а не уничтожать расследование и готовую рекомендацию.

## 2.3. Граница LLM-authority местами протекает в противоположную сторону

Эти пути не были задействованы текущим deterministic-only recheck, но существуют:

- `llm.ClaimEvaluator.acceptClaim`: TRUE допускается при наличии существующего evidence ID; entailment утверждения из evidence не проверяется.
- `llm.ExploitModelBuilder.routeProposal/mergeConditions/fillParams`: модель может добавить mandatory condition и заполнить `bound`; `ValidateConditionApplicability` проверяет преимущественно TLS-specific mismatch, не общую необходимость.
- `states.RepairAnalysis`: LLM-review actions физически меняют mandatory conjunction.
- `states.ActResearchCVE`: `ProfileVerified && rev.Passed` включает `AcceptLocusProposals`; `exploit.Builder.locusSubjects` пишет `accepted-machine-proposal` в `NonLocusBasis` и сужает локус.

Последнее — **потенциальный false-safe authority leak**: согласие LLM-reviewer не является доказательством ненужности объявленного локуса. Наблюдённый ошибочный safe-вердикт здесь не заявляется.

## 2.4. Что LLM-first дал бы на текущих VEX-кейсах

Нельзя честно назвать неизмеренные текущие категории. Можно назвать контрактный результат:

| Препятствие Product A | Что должен вернуть Product B |
|---|---|
| Нет corpus declaration | Анализ конкретных записей и готовую рекомендацию; явно без CVE-wide safe claim |
| Build не загружается | Source-grounded расследование, неизвестные build facts, точное действие по разрешению build identity |
| Неподдержанный content binding | Гипотезу механизма с source/fix основаниями, ограничения и рекомендацию; не 108 обязательств для человека |
| Неизвестная runtime configuration | Условное решение или конкретное действие получения deployment evidence |
| Нет advisory | Результат «идентичность уязвимости не установлена», запрещённые выводы и точное действие получения записи |
| Исчерпан бюджет | Сохранённый результат расследования и рекомендацию в пределах действительно собранных оснований |

Для реального сравнения нужен отдельный benchmark adapter. Простое снятие `--deterministic-only` включит старый helper, **не Product B**.

Препятствия запуска B:

- `triage` требует `finding.v1` либо ticket+siteconfig, а не текущие analyze flags;
- нужен настроенный LLM endpoint/model;
- `research-b1` требует container image, credentials и `--allow-agent`;
- format результата и метрики различаются;
- текущий harness не сохраняет стоимость model calls и human decision-readiness;
- universal-verifier admission default-off — отдельная историческая возможность, не переключатель полноты live triage.

---

# 3. Вместо case-by-case стратегии

**Единица развития — не CVE, а наблюдение, утверждение и право использовать его для конкретного действия.** LLM расследует любой механизм, формирует причинное объяснение, ищет подтверждение и контрпример и предлагает действие. Tools возвращают измеренные факты со scope, а не догадку «весь кейс решён». Детерминированное ядро проверяет только те выводы, для которых существует поддержанный proof contract. Неподдержанная семантика остаётся явно модельной интерпретацией в полноценном человеческом решении, а не превращается ни в safe, ни в `FAILED`.

### Что удалить

**Из авторитетного пути:**

- автоматическое принятие LLM non-locus proposals;
- принятие TRUE по одному существующему evidence ID;
- LLM-promote/demote mandatory conditions без проверяемого основания;
- authority от keyword/protocol-role/name heuristics;
- unexported-sink + module-usage TRUE;
- weak transport fallback рядом с typed witness.

Эвристики можно оставить как **поисковые предложения Product B**. Удаляется их власть, не обязательно полезный поиск.

**Из Product B:**

- требование proof как условия права высказать исследовательское мнение;
- обязательный `code_absent` proposal для любого отрицательного мнения;
- фиктивный production fast path с nil premise;
- default-HIGH confidence;
- hardcoded CI-only human decision;
- превращение отсутствующей eval-baseline в невозможность выдать человеческое решение.

**Из production UX:**

- frozen B1 benchmark prompt как основной researcher;
- regex-восстановление assumptions/facets как источник структурированного решения;
- salvaged category как успешный decision-ready результат;
- несколько конкурирующих runtime research/decision-ready языков.

B1 и старые schemas сохраняются как **evaluation controls и исторический replay**, не как параллельные новые production пути.

---

# 4. Что означает «решить любой кейс с уверенностью»

Принятое значение сохраняется: **подготовить завершённое решение для человека**, а не гарантированно доказать безопасность любого входа.

Результат обязан содержать:

1. рекомендуемое действие;
2. краткое причинное обоснование;
3. решающие проверенные факты;
4. модельные интерпретации — отдельно;
5. решающие допущения и неизвестные;
6. уровень обоснованности;
7. что изменит рекомендацию;
8. Accept/Reject с сохранением решения человека.

`FAILED + report path`, голый `UNCHANGED` и «проверьте 108 обязательств» этому контракту не соответствуют.

### Уверенность — не вероятность безопасности

Нужно разделить три оси:

```text
judgment                 — вывод расследования LLM
support                  — проверяемая характеристика его оснований
authoritative_conclusion — отдельно допущенный результат Product A, если заработан
```

Для каждого решающего утверждения:

- **MEASURED** — typed observation действительно устанавливает эту узкую пропозицию;
- **PROVED** — checker установил отношение/отрицание в объявленном scope;
- **INTERPRETED** — вывод LLM из перечисленных материалов;
- **ASSUMED** — явно названная внешняя или human-owned предпосылка;
- **UNRESOLVED/CONFLICTING** — не установлено либо есть противоречие.

Источник, digest, subject, scope, полнота и открытые границы обязательны там, где применимы. Проверенная цитата доказывает наличие текста, не его интерпретацию.

### Предлагаемые уровни обоснованности решения

| Уровень | Машинно проверяемое основание |
|---|---|
| **INSUFFICIENT** | Нет необходимой identity/материала; допустимо только действие по получению/исправлению входа |
| **LIMITED** | Есть воспроизводимые основания, но решающие причинные связи или факты остаются интерпретациями/неизвестными |
| **SUBSTANTIATED** | Решающие фактические посылки измерены, интерпретационные переходы явно выделены, рассмотрены существенные контраргументы, нет скрытого противоречия; рекомендация ограничена заявленным scope |
| **PROVED_WITHIN_SCOPE** | Конкретное заключение целиком поддержано допущенным proof contract; все необходимые bindings и coverage восстановимы |

Это уровень **обоснованности**, а не обещание 90/95/99% правильности. Числовую вероятность можно добавлять только после отдельной калибровки на независимых данных с интервалом и областью применимости. Сейчас таких данных нет.

Важные правила:

- `SUBSTANTIATED` не даёт VEX-safe.
- Большое число цитат не повышает уверенность автоматически.
- Повторное согласие моделей не заменяет независимое основание.
- Нерелевантный partial scan не должен понижать независимо достаточное доказательство.
- Уверенность вычисляется по **решающим посылкам**, не по отсутствию любых limitations во всём досье.

### Как сохраняется `false-safe=0`

Human proposal и machine reduction — разные поля и действия.

- Product B может предложить человеку закрытие по явно интерпретационному обоснованию.
- Это не `DISMISSED`, не автоматическое снижение, не `NOT_AFFECTED`/NEPF.
- Accept сохраняет человеческое решение, а не превращает модельную гипотезу в machine proof.
- Machine-safe и CI reduction по-прежнему требуют существующего допуска.
- Ошибочные отрицательные рекомендации LLM учитываются отдельной метрикой; их нельзя спрятать переименованием. Исторические 2/36 остаются ошибками исследования, даже если не попадали в VEX.

Таким образом, гарантируется выдача честного действия при допустимых входах и доступном runtime, **не универсальная истинность модельного ответа**. Отсутствующие данные не исправляются confidence-числом.

---

# 5. Целевая архитектура

## 5.1. Два продукта, но не два набора истины

```text
Ticket / CVE / snapshot / artifact / deployment inputs
                         ↓
             Общий identity + evidence session
                         ↓
        Product B: LLM-first investigator
     hypothesis → observe → challenge → recommendation
                         ↓
        Deterministic result validator
     references / scope / contradictions / support
                         ↓
       Human decision package + Accept/Reject
                         │
          optional proof requests / candidates
                         ↓
       Product A: deterministic proof authority
                         ↓
       finding.Project → authoritative report/VEX
```

Product B не ждёт, пока Product A сможет доказать весь кейс. Product A не принимает интерпретацию Product B как необходимость, полноту или идентичность.

## 5.2. Что LLM владеет end-to-end

В Product B модель отвечает за:

- интерпретацию захваченного advisory/fix;
- определение рабочих гипотез механизма;
- план исследования;
- выбор доступных evidence tools;
- source-level объяснение;
- поиск альтернативного пути и контраргумента;
- рекомендацию и её решающие предпосылки;
- формулировку конечного человеческого решения.

Новая гипотеза не требует нового enum CVE-family. Если нужного tool нет, модель может анализировать source, но обязана пометить переход как `INTERPRETED`, а не `MEASURED`.

## 5.3. Что детерминировано

- identity и immutable input bundle;
- разрешение module/build/artifact фактов;
- выполнение tools и provenance;
- разрешение ссылок;
- проверка структурированного результата;
- обнаружение противоречий в сравнимых typed facts;
- вычисление support;
- admission настоящих proof;
- ограничения автоматизации и публикация.

**Не надо подключать `productb/verify` как ещё один обязательный универсальный gate человеческого результата.** Его текущие unsupported shapes и низкая eligibility воспроизведут тот же потолок. Использовать существующий observation vocabulary и поддержанные capability-checks; unsupported interpretation должна оставаться видимой, а не уничтожать рекомендацию.

## 5.4. Пакеты и границы

| Компонент | Решение |
|---|---|
| `repository`, `vulnerability`, `affected`, `fix`, `toolaudit` | Общая acquisition/identity механика; устранить дублирующие интерпретации в adapters |
| `goanalysis` | Общий набор измерителей; разделять observation и proof eligibility |
| `evidencetools` | Одна capability registry; permissions/стоимость задаются session, не тремя расходящимися списками |
| `productb/triage` | Основной Product B runtime; investigator и decision validator вместо скрытого proof-only composer |
| `productb/research` | Frozen B1 перенести в evaluation/control роль; полезные capture/recovery части переиспользовать |
| `internal/research` | Не оставлять вторым live human-product. Сохранить нужные proof/replay функции, migrate callers, затем удалить дублирующие branch/catalog/render pipelines |
| `llm` | Client/protocol и investigator adapter; удалить авторитетные mutation hooks из Product A |
| `fixbinding` | Сохранить как специализированную proof capability. Не prerequisite общего триажа |
| `domain` | Canonical identity/observations/proof DTO; distinction proposal/fact/assumption/authority должна быть структурной |
| `evaluator`, `finding` | Product A authority и publication. Не импортируют model confidence |
| `states`, `workflow` | Product A workflow сохранить; Product B использует один ограниченный investigation loop с обязательной финализацией |
| `productb/verify`, `claimshape`, `heldoutgate`, `reportcheck` | Offline evaluation/challenge и узкие validators; не второй production verdict engine |

### Persist/replay/presentation

Один run bundle:

- исходные inputs и digests;
- захваченные advisory/fix/source материалы;
- наблюдения и tool execution status;
- модель, prompt/config, transcript;
- structured assessment и зависимости решающих утверждений;
- вычисленный support;
- proof references, если есть;
- человеческое Accept/Reject отдельной append-only записью.

Replay не генерирует новое мнение: воспроизводит сохранённый judgment и пересчитывает reference/support/proof validation. Drift явно меняет admissibility, но не переписывает историю.

Human screen: **действие → почему → решающие факты → допущения/уверенность → что изменит решение**. Audit разворачивается отдельно.

### Record versus CVE

- Любая рекомендация связывается с конкретными рассмотренными records.
- Отсутствие corpus declaration ограничивает CVE-wide claim, а не право провести расследование.
- Product A сохраняет строгую corpus-negative границу.
- Никакого автоматического «первый advisory = вся CVE».

---

# 6. План миграции

Это архитектурные фазы, не реализация и не обещание измеренного прироста.

## Фаза 1. Доставить принятый человеческий продукт

Изменения:

- Product B action package становится основным результатом `triage`.
- Отделить LLM judgment, proposed human action и machine disposition.
- Добавить support по решающим посылкам и Accept/Reject artifact.
- Удалить proof-only запрет на модельное мнение.
- Не требовать severity или внешнюю контрольную baseline для доставки человеческого результата.
- Сравнение с GT/baseline оставить в evaluation; автоматическое снижение — под отдельным proof/policy gate.

Acceptance:

- unsupported mechanism, missing corpus и partial tools не уничтожают исследование;
- каждое завершённое расследование имеет конкретное действие и объяснение;
- confidence не меняет Product A verdict/CI-safe;
- человек не обязан заново собирать причинную цепочку из audit wall.

**Ожидаемый эффект:** наибольший человеческий выигрыш при минимальном вмешательстве в доказательное ядро.

## Фаза 2. Исправить входы и поверхность расследования

Изменения:

- frozen advisory set и captured fixes обязательно доступны агенту;
- полноценный target/build input передаётся в B session;
- открыть общие read-only provenance/config/dynamic инструменты по session permissions;
- убрать неразрешимый цикл mandatory proposal → отсутствующий catalog;
- либо подключить реальный producer invocation-necessity premise для proof capability, либо удалить мёртвую проводку и неверное обещание prompt.

Acceptance:

- модель расследует предоставленную уязвимость, не подменяет её памятью;
- host OS не выдаётся за product target;
- новый механизм можно исследовать без добавления case-specific правила;
- отсутствие proof producer отражается как ограничение proof capability, не дефект ответа агента.

## Фаза 3. Устранить authority leaks и case-shaped authority

Изменения:

- удалить auto-adoption non-locus;
- запретить `existing evidence ID → TRUE`;
- убрать LLM-only необходимость/снятие mandatory conditions;
- перевести keyword/role/name эвристики в nomination;
- удалить weak positive fallbacks рядом с typed witnesses;
- специализированные transport/fix capabilities вызывать по доказанной применимости, не глобально.

Acceptance:

- ни LLM agreement, ни regex-класс, ни имя функции не меняют completeness/necessity;
- отказ специализированного checker не блокирует независимое человеческое расследование;
- реальные положительные/отрицательные proofs проходят собственные прежние границы.

Это может временно уменьшить число Product A positives, основанных на эвристике. Такое изменение надо измерить, а не сохранять слабый вывод ради старого golden result.

## Фаза 4. Сократить дублирование

Изменения:

- один Product B investigation loop;
- один observation/capability registry;
- один human decision projection;
- убрать старые live R5/R6/slice2 overlays после migration callers;
- B1 сохранить только как frozen evaluation arm;
- повторные in-memory admission проверки использовать через неизменяемый admission result; replay и publication re-admission сохранить.

Acceptance:

- один новый tool contract не требует правки трёх allowlists и нескольких confidence maps;
- одна human schema, одна support derivation;
- нет второго semantic verdict compiler в production Product B;
- исторические артефакты не получают новой authority.

## Фаза 5. Измерить именно Product B

Не запускать сейчас. Подготовить отдельную lane:

- VEX task → identity-bound triage input, без передачи GT модели;
- одинаковые snapshots/advisory/build inputs для A и B;
- model/prompt/tool versions и стоимость фиксируются;
- A authority metrics и B recommendation metrics не смешиваются.

Измерять:

- decision-ready rate, а не parse-completion;
- правильность identity/mechanism;
- решающие фактические ошибки;
- ошибочные отрицательные рекомендации;
- число дополнительных ручных проверок;
- время человека до Accept/Reject;
- support calibration;
- стоимость и latency;
- отдельно Product A false-safe и unverified automation reductions.

Acceptance не должен быть «все строки имеют JSON» или «модель выбрала ожидаемую категорию».

## Фаза 6. Расширять доказательства только по evidence classes

Приоритеты:

1. complete build/package inventory;
2. существующий bounded unreachability;
3. effective configuration/writer/override evidence;
4. supported patch-base/external-component capture;
5. далее конкретно измеренные пробелы.

Не строить заранее универсальный semantic patch engine или full taint engine.

### Что ожидается от VEX-негативов

- **Product B:** missing corpus, unsupported binding и неполный input trace должны перейти из пустого отказа в содержательные human proposals. Количество правильных proposals пока неизвестно.
- **Product A:** go-zero уже имеет exact-record negative; пять build failures имеют исправимые входные барьеры; reachability machinery существует, но его фактическая замыкаемость после правильных входов не измерена.
- `requires_configuration` требует действительных config evidence, а не категории GT.
- Trivy networking не становится доказанным от удаления parser noise.
- Helm supported permission proof остаётся кандидатом на capture work, не гарантированным закрытием.
- Ни missing input, ни timeout, ни модельная уверенность не добавляют safe verdict.

### Как не вернуться к очередной настройке под кейс

Каждое расширение должно отвечать:

- какую общую пропозицию измеряет capability;
- какой положительный witness или closed universe её устанавливает;
- что остаётся unsupported;
- какие контрпримеры её опровергают;
- работает ли она на независимом случае вне исходной CVE.

Запретить production dispatch по task/CVE ID. Но одной проверки на строки CVE недостаточно: review должен искать **case-shaped семантические допущения**, даже если идентификатора нет.

---

# 7. Нужен ли ещё один выбор пользователя

**Нет.** Основное решение уже принято:

- LLM-first расследование готовит решение для человека;
- доказательная authority остаётся отдельной;
- confidence не подменяет proof;
- автоматического закрытия по модельному мнению нет.

Нужно реализовать эту границу последовательно, а не ещё раз выбирать между «полезным LLM» и «безопасным анализатором».

## Итоговая оценка

Подозрение владельца **существенно подтверждается**, но точнее сформулировано так:

> Проект не столько переобучен на отдельные CVE, сколько оброс несколькими ограниченными языками анализа, которые принимают друг друга за обязательные условия результата. LLM-first перенесён как набор runtime-компонентов, но его человеческий результат всё ещё подчинён узкому proof-only маршруту и CI-семантике.

Граница withdrawal/re-derivation правильна для **машинно доказанной безопасности**. Она неправильна как глобальная граница **полезности триажа**.

Главное изменение — **не ослабить её, а перестать требовать её прохождения для каждого человеческого ответа**, одновременно закрыв реальные LLM-to-authority утечки. Это даёт общий путь для неизвестных случаев без обещания универсального доказателя и без следующего набора исправлений «под кейс».
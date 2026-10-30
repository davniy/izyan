# Task 7 — Compact Proof Contract и проверка достаточности отрицательных доказательств

**Статус:** спецификация следующего экспериментального этапа после Task 6  
**Назначение:** `eval/task7/` в экспериментальном worktree Izyan (путь предлагаемый)  
**Режим:** offline/eval, **без изменения production verdict pipeline**  
**Предмет:** формат агентского ответа + минимальный проверяемый proof contract; **не** новый универсальный Verification Gate.

## 1. Предпосылки и проблема

По Task 6:

- P2 (Qwen 3.6, structured prompt, без MCP): **56/90 валидно разобранных ответов (62%)**, `False-Safe = 1/21`, `Safe Clear = 39/69 = 56,5%`, `FAILED = 34/90` (включая 12 таймаутов, 9 в сетевом/VPN-окне).
- T2 (+31 MCP): **23/30 валидных (77%)**, `False-Safe = 0/7` в *одном* проходе, `Safe Clear = 15/23 = 65,2%`. С T2 нельзя делать вывод о риске на основании 0/7.
- V-P2 заблокировал **1/1 False-Safe и 39/39 правильных safe**. V-T2 заблокировал **15/15 правильных safe**. После валидации `Safe Clear = 0` в обоих режимах.
- Структурные negative claims в основном доступны для технической проверки, но `valid-claim share` — лишь 25,6%/23,3%; строгий C4 требует покрытия всего advisory, а локальные/частичные наблюдения такого покрытия не дают.
- В отчёте был дефект scorer: T2 recall `114,3%`; предварительная ручная сверка даёт `6/7 = 85,7%`. Нужно исправить **код расчёта**, а не только Markdown.

**Вывод:** текущий тяжёлый JSON ненадёжен, а текущая проверка отрицаний отбрасывает всю полезную область safe. При этом ослаблять C4 до «PARTIAL достаточно для global safe» запрещено: это вновь сделает возможными ошибки `k8s-44487`, `k8s-3121` и `testify-28948`.

## 2. Цель и вопросы Task 7

Проверить последовательно:

1. Может ли Qwen 3.6 надёжно выдавать **короткий machine-readable ответ**, где отрицательный вывод сопровождается атомарным основанием, без длинного вложенного `reasoning`?
2. Может ли **детерминированный** evaluator независимо подтвердить **хотя бы ограниченный перечень достаточных proof types** и сохранить ненулевой Safe Clear, не принимая недоказанные отрицания?
3. Изменяет ли наличие MCP долю фактически доказуемых отрицаний при одинаковой структуре ответа?

**Не цель:** доказать универсальную неэксплуатируемость по всем CVE; улучшать все классы `code_not_reachable`; создавать `internal/verificationgate`; менять `domain.Verdict` / workflow; объявлять отсутствие False-Safe в малом корпусе доказанной безопасностью.

## 3. Предлагаемая архитектура эксперимента

```text
CVE + immutable snapshot
         |
         v
Agent (plain or MCP-enabled)
         |
         v
CompactAssessment (hypotheses / proposed proof)
         |             
         +--> unchanged proposed category (eval baseline)
         |
         v
Proof Validator (offline, no LLM; reads trusted snapshot/evidence)
         |
         +--> VERIFIED_GLOBAL_NEGATIVE  -> projected safe
         +--> VERIFIED_LOCAL_ONLY       -> projected INCONCLUSIVE
         +--> INSUFFICIENT_EVIDENCE     -> projected INCONCLUSIVE
         +--> INVALID / UNSUPPORTED     -> projected INCONCLUSIVE

GT is visible only to the scorer, never to agent or validator.
```

**Trust boundary:** agent proposes `subject`, `scope`, `proof_type`, refs; validator independently derives actual facts, source identity, coverage and any completeness. Agent-supplied `COMPLETE`, `safe`, `confidence` and persuasive prose have no authority.

## 4. Контракт `CompactAssessment` v1

Один **валидный JSON object в последнем ответе**, без Markdown fences, пролога/послесловия и фрагментов Go-кода внутри `reasoning`.

```json
{
  "category": "code_not_present",
  "reasoning": "Короткий итог для benchmark, не является доказательством",
  "proofs": [
    {
      "type": "MODULE_ABSENT",
      "subject": "module:example.org/vulnerable",
      "scope": "snapshot-build",
      "refs": ["src:go.mod:1@<snapshot-hash>"]
    }
  ],
  "unresolved": []
}
```

Структура **плоская и ограниченная**:

- `category`: одна из 12 VEX-Bench categories, `uncertain` — самостоятельный abstain;
- `reasoning`: короткое объяснение **не для проверки доказательства**; лимит 240 символов; запрещено вкладывать JSON или code blocks;
- `proofs`: до 3 элементов; каждый состоит из `type`, `subject`, `scope`, `refs`; без свободного описания шагов/AST;
- `unresolved`: до 5 коротких кодов/строк сомнений; наличие существенной альтернативы, не исключённой доказательством, запрещает global-safe;
- `refs`: канонические ссылки `src:<path>:<line>@<content-hash>` или `ev:<observation-id>`, причём проверяемость ссылки **не** подразумевает истинность утверждения;
- `scope`: ссылка на **заранее описанную среду** (`snapshot-build`, другой зарегистрированный scope ID), а не сочинённое агентом произвольное утверждение о покрытии всех build variants.

**Контракт для positive и `uncertain`:** `proofs=[]` допустим. **Для safe:** отсутствие proofs не является parse error, но validator возвращает `INSUFFICIENT_EVIDENCE`. Это позволяет сравнивать исходное качество модели и gate-yield раздельно.

Никаких новых prompt-only фактов: для P3 refs на исходники только становятся *кандидатами*; доказательство формируется самостоятельно валидатором. MCP-наблюдение `OK` может быть источником факта, но не автоматически proof.

Точный JSON Schema хранить в `eval/task7/contracts/assessment.schema.json`; обработку ограничений и ошибки схемы тестировать автономно. **Внутри агента:** использовать structured-output API/JSON schema mode, только если это возможно для обеих сравниваемых конфигураций; иначе ровно один финальный JSON. Не смешивать две стратегии в одной серии запусков.

## 5. Scope и proof types

### 5.1. Принцип достаточности

`VERIFIED_GLOBAL_NEGATIVE` разрешён только когда проверено **достаточное глобальное основание** для конкретного CVE на заданном продукте/сборке:

- Все релевантные проявления CVE покрыты проверенным proof; **или**
- Доказано ложное обязательное условие, общее **для всех** потенциальных exploit paths, и валидатор может установить эту общность независимо.

`PARTIAL` может подтверждать **локальный** факт в своём scope, но не повышаться до global-safe даже при отсутствии найденных caller'ов.

C4 **не удалять**, а заменить бинарную проверку всего advisory на типизированную проверку «какое именно доказательство охватывает какую область». Если доказать полноту CVE scope нельзя, результат `INSUFFICIENT_EVIDENCE` независимо от красоты ответа.

### 5.2. Реализовать только небольшой allowlist

| Proof type | Что должен перепроверить validator | Ограничение |
|---|---|---|
| `MODULE_ABSENT` | Модуль действительно отсутствует в **целевом разрешённом графе зависимостей** для заявленного release/build scope; учтены `replace`, `vendor`, workspace, вложенные модули и встраивание кода, если релевантны | Отсутствие одного перечисленного advisory-модуля само по себе не исключает второй affected path; без coverage всех релевантных проявлений — только LOCAL |
| `FIX_PRESENT` | Исправление присутствует в **фактически используемом коде** целевого build/snapshot, а не только по имени версии; подтверждена связь исправления с конкретным уязвимым механизмом | Фикс для одной копии/ветки/компонента не доказывает отсутствие альтернативных проявлений CVE |
| `BUILD_EXCLUDED` | Уязвимый код действительно исключён **из всей заявленной целевой сборки**, подтверждены GOOS/GOARCH/tags/генерация и release identity | Только для доказуемого pinned build scope, не для всех возможных деплоев |

`UNREACHABLE_BY_CALLGRAPH`, `NO_CALLERS`, `CONFIG_OFF`, `PERIMETER_PROTECTED` и прочие недоказуемые сейчас negative-основания **не принимать как global-safe**. Их можно сохранять в audit как `UNSUPPORTED_PROOF_TYPE` / local hypotheses. Конфигурация без проверенного release/deployment profile недостаточна.

**Практическое ограничение:** если по этим трём типам валидатор пока не умеет получить проверяемый факт, допустимы `INSUFFICIENT` и отсутствие принятых global negatives. Нельзя подменять доказательство слабой версией правила ради ненулевого SCR.

### 5.3. Граница полезности доказательства

Validator выдаёт два независимых результата:

- `fact_status`: `VERIFIED | REFUTED | UNKNOWN` — верен ли локальный факт;
- `global_coverage`: `SUFFICIENT | LOCAL_ONLY | UNKNOWN` — достаточно ли его для **всего** proposed safe-вердикта.

Только `VERIFIED + SUFFICIENT` может породить `VERIFIED_GLOBAL_NEGATIVE`. Нельзя приравнивать `checkable-claim` к `accepted-safe`.

## 6. Исправления инфраструктуры — обязательны перед сравнением

1. **Scorer:** исправить join по `(task_id, run_id)` и GT class; `TP` считать **только** на GT exploitable; `FN_binary` и `False-Safe` считать отдельно; `FAILED` не переводить ни в negative, ни в `uncertain`. Добавить тест на невозможность `recall > 100%`, включая несбалансированные n=1/n=3.
2. **JSON parser:** декодирование через string-aware JSON decoder и проверку **последнего финального assistant-сообщения**; не делать substring/brace-count из всех текстов, не извлекать prose-категории как валидный результат. Сохранять оригинальный raw ответ и отдельный `parse_error_kind`.
3. **Attempt integrity:** один исходный output → один verdict; нет «best of», выборочных ретраев по GT/содержанию; сетевой/VPN outage отдельно как `INFRA_FAILED`, без молчаливого исключения из denominator. Любой технический retry документировать на уровне attempt manifest.
4. **GT isolation:** Docker только с snapshot и разрешёнными конфигами; результаты других попыток, GT/PR labels и отчёты eval внутрь не передавать. Валидатор видит trusted snapshot + tool audit, но **не GT**.
5. **Согласованность arms:** одинаковые model/runtime/harness/budget/JSON decoder и длительности; MCP-access — единственная разница P3↔T3, кроме необходимого блока описания tools.

Оригинальные результаты P1/T1/P2/T2/V-P2/V-T2 сохраняются без перезаписи.

## 7. План выполнения и stop/go gates

### 7.0 — Scorer + output plumbing

- Сохранить канонические case-level результаты Task 6 и manifest/hashes.
- Исправить scorer и parser; регрессионно перепроверить Task 6 (`T2 recall`, `FAILED`, знаменатели); изменения derived projections версионировать, не исправлять задним числом frozen official metrics.
- Создать JSON Schema, decoder и синтетические тесты (escaped braces, prose-tail, two objects, missing proof, ERROR/PARTIAL, wrong snapshot).

**Выход:** валидные и полностью воспроизводимые метрики; no `>100%` rates; различимы model-format, parser, infra failures.

### 7.1 — Compact-only format smoke (без MCP)

- Контроль `P2-control`: тот же старый structured prompt Task 6, **в том же новом окружении**, что новый вариант, чтобы не приписывать результат разным runtime/парсерам.
- `P3`: compact contract. Использовать **одинаковую модель Qwen 3.6**, pinned prompt, 8–12 заранее выбранных development-кейсов, включая сложные/безопасные/положительные, по 3 попытки в каждом режиме. Кейс-список и допустимые технические retries заморозить **до запуска**.
- Замерить `valid_terminal_json`, `valid_schema`, `completion`, распределение ошибок, `category` и timing. Prompt нельзя менять после просмотра GT в пределах серии.

**GO к 7.2:** на clean attempts `valid_schema >= 95%` и доля `valid_schema` у P3 не ниже matched control; нет системного trailing prose; модель выдаёт `subject/scope/refs` на отрицательных кейсах. Иначе доработать **только формат вывода** и провести новый явно названный smoke-run; не начинать разработку Gate.

### 7.2 — Typed proof validator (offline, MVP)

- Реализовать независимые evaluators для 3 proof types (по одному за раз). Если полная реализация требует широкого Go-анализатора, сначала допускается **один** достаточный и применимый тип; непройденные types явным образом `UNSUPPORTED`.
- `src`-refs проверяются по immutable hash, но семантика фактов устанавливается собственным evaluator, а не текстом агента.
- Для каждой negative попытки сохранять atom-level `fact_status/global_coverage/decision/reasons` и границы охвата, а для global-negative — конкретный proof chain.
- Запустить offline replay **того же P3**, без повторного LLM вызова. Считать `FS blocked`, `correct safe lost`, `accepted correct-safe`, `accepted false-safe`, отдельно по каждому proof type и на уровне попыток/уникальных кейсов.

**GO к 7.3:** хотя бы один реально корректный safe-verdict принят на development-наборе, ни один известный FS не получил `VERIFIED_GLOBAL_NEGATIVE`, а доказательство acceptance проверяется независимыми тестами контрпримеров. Если `SCR_after = 0`, зафиксировать failure/limit: **не** ослаблять scope автоматически.

### 7.3 — MCP ablation (только после 7.2)

- `T3`: **тот же** компактный prompt/contract/model/runtime/case set, но с MCP и описанием доступных инструментов.
- На smoke — столько же попыток, что в P3; затем, если продуктивность подтверждена, по отдельному решению расширить до полного development-корпуса (30×3 для **обоих** arms).
- Offline replay с **одним и тем же** валидатором по P3/T3. Сравнить, какие proof types получили реальную поддержку; учитывать стоимость и ошибки MCP.

### 7.4 — Unseen holdout (при успешном development)

- Составить **новый неиспользованный** корпус/проекты (вне известных 30 VEX-Bench задач). Заморозить IDs, GT в недоступном controller-side хранилище, prompt/schema/validator/harness, thresholds **до выполнения**.
- Запустить парные arms с одинаковой attempt policy; разобрать отдельно редкие unsafe-negative случаи.
- **Нулевой FS на небольшом holdout — не математическая гарантия безопасности.** До внешнего подтверждения остаётся только экспериментальный режим.

## 8. Метрики и отчёты

Обязательные:

| Метрика | Определение |
|---|---|
| `parse_success` | валидный **полный** terminal JSON / clean attempts, отдельно общий completion |
| `valid_schema` | соответствует контракту v1 / полученные ответы |
| `proof_binding_rate` | ссылки действительно указывают на snapshot/observation, *не* достаточность proof |
| `local_fact_verified` | подтвержденные локальные факты / предлагаемые факты |
| `global_proof_accepted` | global-safe с проверенным достаточным основанием / все proposed safe |
| `FS before/after` | неверные global-safe на GT exploitable, строго отдельно от abstain/FAILED |
| `safe_clear before/after` | подтверждённые global-safe на GT safe / **все GT safe** |
| `false_safe_blocked` | ошибочные исходные safe, снятые валидатором |
| `correct_safe_lost` | правильные исходные safe, снятые валидатором |
| `cost/time/tool-errors` | операционная стоимость и качество окружения |

Считать **оба** уровня: attempt и unique-case. Для уникальных кейсов не выдавать числа отдельных повторов за независимые кейсы. `FAILED` и `INFRA_FAILED` не дают safe benefit и не являются FS; ограничения покрытий показывать рядом с каждой таблицей.

Артефакты (предлагаемые):

```text
eval/task7/
  SPEC.md
  freeze/manifest.json
  contracts/assessment.schema.json
  prompts/{control,compact,compact_tools}.txt
  results/{control,p3,t3}/
  validation/{p3,t3}/verdicts.jsonl
  scoring/{format-report,proof-report,safety-report,decision}.md
  tests/
```

## 9. Контрпримеры и обязательные тесты

Использовать известные ошибки как **регрессионные проверки**, но **не** прописывать конкретные CVE или GT в промпте либо правилах валидатора:

- `k8s-44487`: локально исправленный/отсутствующий `x/net` не исключает затронутый путь через другой компонент (`grpc`). Ожидается `LOCAL_ONLY/INSUFFICIENT`, если не доказано покрытие альтернативы.
- `k8s-3121`: отсутствие вызова генератора не доказывает отсутствия уязвимого сгенерированного runtime-кода.
- `rancher-47914`: `context canceled`/сбой reachability check не доказывает недостижимость; `ERROR` → `UNKNOWN`.
- `testify-28948`: `find_callers: []` при `PARTIAL` / `product packages` не доказывает глобального отсутствия вызовов.
- Genuine safe examples: по крайней мере один случай `MODULE_ABSENT`, `FIX_PRESENT` или `BUILD_EXCLUDED` с **реально подтверждаемым глобальным основанием** (если в корпусе отсутствуют — подготовить отдельный unit fixture, не выдавая его за benchmark win).
- Broken refs, spoofed `ev:` ID, mismatch snapshot hash, wrong build tags, vendored copy, unknown release Go toolchain, missing modules and workspace overlays -> не global-safe.
- Несколько проявлений одной CVE: глобальное отрицание невозможно при проверке лишь одного проявления.

Каждый тест включает expected validator reason и независимую проверку отрицательного факта; тестировать также refuted proof и потенциальный regression на правильных safe.

## 10. Критерии приёмки Task 7

1. Исправлены и протестированы scorer/join/parser; невозможные проценты больше не публикуются; история Task 6 не перезаписана.
2. Compact Contract v1 зафиксирован и документирован; P2-control и P3 сопоставимы по модели, снимкам, runtime, числу попыток.
3. Smoke отчёт показывает отдельно format, infra, semantic и validator outcomes; выполнен stop/go §7.1.
4. Есть независимый offline evaluator хотя бы для одного типизированного proof; нет перехода `PARTIAL/ERROR/empty` в global negative.
5. Раздельно задокументированы `fact_status`, `global_coverage`, `VERIFIED_GLOBAL_NEGATIVE` и причины всех `INSUFFICIENT`.
6. На development smoke нет **принятых** заведомо ошибочных safe; хотя бы один корректный safe принят **или** честно зафиксировано, что proof-class yield = 0 и гипотеза не подтверждена.
7. Если этапы 7.1/7.2 провалились, 7.3–7.4 **не обязательны**, финальный отчёт фиксирует остановку и следующую гипотезу; не запускать десятки лишних LLM-прогонов.
8. Неизменны production verdict pipeline, semantics `FALSE`/Falsifier/NegativeVerification и открытый API.
9. В отчёте есть решение `STOP / REVISE CONTRACT / PROCEED TO MCP TEST / PROPOSE HOLDOUT`; оно опирается на результаты, а не на заранее выбранную архитектуру.

## 11. Решение после Task 7

- **Формат неустойчив:** остановиться, не строить Gate; для следующего эксперимента рассмотреть функцию `submit_assessment`/структурный API вместо генерации большого финального JSON.
- **Формат устойчив, но `accepted-safe = 0`:** контракт недостаточен для глобального доказательства; расширять реальные proof-факты/verification capabilities, не ослаблять критерий до принятия локального нуля.
- **Есть принятые корректные safe и нет принятых известных FS:** постепенно исследовать новые proof types, затем matched P3/T3 и holdout; не объявлять production safety по dev-набору.
- **MCP не даёт прироста над compact prompt-only:** оставить evidence tools опциональными / исследовательскими, не делать обязательной зависимостью.

**Итоговый deliverable Task 7:** проверенный компактный формат, минимальный набор proof evaluators и отчёт о **реальном safety/utility trade-off**. Создание production Verification Gate — отдельное решение после положительных результатов на unseen holdout.

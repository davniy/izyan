# VEX-Bench: зафиксированные промпты экспериментов

Промпт — **управляемая переменная** эксперимента и одно из направлений будущей
оптимизации. Здесь заморожены точные тексты, чтобы прогоны были воспроизводимы,
а изменения промпта отличались от изменений модели/харнеса.

## 1. Официальный промпт harness — `vuln` (baseline)

- **Файл:** [`official-vuln-c0a5c8458b77.txt`](official-vuln-c0a5c8458b77.txt)
- **sha256 (шаблон):** `c0a5c8458b77015d57b82eefca563d01c870ea027562381715c8ab9d70ffabda`
- **Короткий хэш (harness `PROMPT_HASH_LEN=12`):** `c0a5c8458b77`
- **Источник:** harness `src/evaluate/prompts.py`, `VULNERABILITY_ANALYSIS_PROMPT`,
  checkout `/tmp/vexbench-agent-ctl`.
- **Подстановка:** единственный placeholder `{cve_id}`.

Хэш `c0a5c8458b77` записывался самим harness в лог прогона
(`INFO evaluate.run: prompt=vuln hash=c0a5c8458b77`) и присутствует в пути
результатов (`<out>/c0a5c8458b77/<agent>/<model>/...`), поэтому любой прогон
однозначно привязан к версии промпта.

Блоки: `<ROLE>`, `<CONTEXT>`, `<CVE>{cve_id}</CVE>`, `<CLASSIFICATION_CATEGORIES>`
(12 категорий с развёрнутыми пояснениями, строгий precedence),
`<DECISION_RULES>` («vulnerable iff present ∧ used ∧ reachable ∧ no mitigation»),
`<OUTPUT_FORMAT>` (один JSON-объект, без markdown), `<EXAMPLE>`.

**Использован в режимах:** B1 (Codex, официальный harness), B2-ISO и Qwen-ISO
(официальный harness + Docker). **НЕ** используется режимом A: Izyan-детерминированный
(`llm_calls=0`, собственный контракт анализатора, см. `eval/vexbench_baseline.py`).

## 2. Субагентный промпт B2/B3 (omp subagent) — НЕ равен официальному

Диффы подтверждены по сырым транскриптам (`history://…/B2_01_caddy`, строка 6).

Фактический user-prompt субагента:

```text
Complete assignment thoroughly:

# Case
CVE: {cve_id}
Target repository snapshot: {snapshot_path}

# Instructions
1. Inspect the repository snapshot at the path above (read go.mod, go.sum, source files via grep/read/bash).
2. Look up the CVE publicly if needed.
3. Determine exploitability.
4. Return ONLY the single JSON object with `category` and `reasoning`.
```

плюс `context`-блок с 12 категориями **в одну строку каждая**.

### Отличия от официального

| Блок | Официальный `vuln` | Субагентный B2/B3 |
|---|---|---|
| `<ROLE>` | есть | нет |
| `<CONTEXT>` («static analysis, no runtime») | есть | нет |
| Категории | развёрнутые (2–5 строк) + precedence | одна строка каждая |
| `<DECISION_RULES>` | есть (логика «iff ALL») | нет |
| `<EXAMPLE>` | есть | нет |
| `<OUTPUT_FORMAT>` | stdout, без fences, escape `\n` | «ONLY the JSON object» |
| Свои инструкции | — | 4 пункта (grep/read/web, «determine exploitability») |

### Следствие для сравнения

Субагентные прогоны **B2 и B3 несопоставимы по промпту** с harness-прогонами
B1/B2-ISO/Qwen-ISO. Это **второй** (после contamination, см. отчёт §7) источник
несопоставимости, независимый от изоляции. Поэтому:
- строгое apples-to-apples сравнение возможно **только** между B1, B2-ISO, Qwen-ISO
  (общий официальный промпт + Docker);
- B2/B3 (subagent) — exploratory, с двумя ограничениями: contamination и иной промпт.

## 3. Воспроизведение

```bash
# хэш замороженного шаблона
sha256sum eval/vexbench-prompts/official-vuln-c0a5c8458b77.txt
# => c0a5c8458b77015d57b82eefca563d01c870ea027562381715c8ab9d70ffabda
```

## 4. Промпты Task 4 C1 (B1' control и C1 treatment)

Источник истины — `eval/c1/protocol.py` (генерирует эти файлы; дрейф ловит
тест `eval.c1.protocol_test`). Замороженный официальный шаблон `vuln`
остаётся **дословным префиксом** обоих вариантов — единственные дельты —
добавленные блоки в конце.

| Файл | sha256 (шаблон) | Состав | Использование |
|---|---|---|---|
| `vuln_assess-c45dfc39af34.txt` | `c45dfc39af34…` | `vuln` + `<ASSESSMENT_REPORT>` | **B1'** (контроль: новый output-протокол, без Izyan tools) |
| `vuln_c1-6eda998ea66c.txt` | `6eda998ea66c…` | `vuln_assess` + `<EVIDENCE_TOOLS>` | **C1** (B1' + декларация izyan MCP tools) |

`<ASSESSMENT_REPORT>` расширяет одиночный JSON-ответ полем `assessment`
(root_causes, claims TRUE/FALSE/UNKNOWN, counterexample_review с обязательным
содержимым перед safe-оценкой, verdict_estimate) — официальный parser
игнорирует extra-поля (`result_parser._parse_json`). Общий для B1' и C1,
чтобы output-протокол не был различием (план §1.5).

`<EVIDENCE_TOOLS>` — только декларация MCP-сервера `izyan` и binding-правила
`scope`/`completeness` (зеркало server instructions из `internal/evidencetools/mcp.go`).
Без case-specific подсказок и без более сильных security-инструкций, чем у B1
(спека §4).

Регенерация:
```bash
python -m eval.c1.protocol eval/vexbench-prompts   # из корня репо, venv с pydantic v2
```

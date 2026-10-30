**Источник:** delegated `architect` artifact `agent://WrongCasesLLMFirstTuning` (2026-10-24), сохранён дословно.
**Цель:** сопоставить сохранённые исходы чистого агента и pipeline `analyze`, разобрать причины потерь и предложить конкретные варианты тюнинга LLM-first.

# Анализ сохранённых результатов и тюнинг LLM-first

## Главный вывод

Разрыв с чистым агентом реален, но возникает **не только на финальном verifier**. Есть доказанные потери:

1. **До обращения к LLM:** частный advisory принимается за полную область CVE.
2. **При построении exploit model:** добавляются нерелевантные обязательные условия; patch может относиться к другой реализации.
3. **При сборе evidence:** ошибки загрузки, неполный dependency scope и бюджеты мешают подтвердить найденный путь.
4. **При review/repair:** reviewer замечает проблему, но контур не всегда умеет исправить модель анализа.
5. **При формализации:** существующая ссылка на evidence ещё не означает, что evidence доказывает claim.

Поэтому рекомендуемый путь — **LLM-first discovery → проверяемые гипотезы → адресный сбор evidence → bounded repair → существующий authoritative verifier**, а не ослабление gates.

**Новых прогонов, тестов и изменений файлов не выполнялось.**

---

## 1. Что именно сравниваем

Основной clean baseline — **изолированный Qwen3.6 plain из Task 4**, сохранённый в Task-5 P0. Это coding agent над исходниками **без Izyan/MCP**, а не обязательно один completion без инструментов чтения.

Важное уточнение: **не смешиваю его с B3-host**. У ISO Qwen3.6:
- false alarm: **gitleaks-22871 и kubernetes-41717**;
- **trivy-24791 и podman-37298 — правильные safe**;
- echo-26160 — timeout, istio-042afc3 — format failure.

Это установлено по сохранённым [покейсовым данным P0](../vuln-analyzer-shadow/eval/task5/scoring/p0/case_comparison.jsonl), а не перенесено из описания host-прогона.

Текущий pipeline — `analyze --cve-analysis verified`, **deterministic-first с LLM helpers**, не Product-B LLM-first. Использован combined-профиль: основной JSONL с заменой пяти case-pairs результатами 3600-second rerun.

| Исход | Qwen3.6 plain | Pipeline master | Pipeline branch |
|---|---:|---:|---:|
| TP / 7 positives | 6 | 3 | 2 |
| Correct safe / 23 | 19 | 13 | 9 |
| False-safe | 1 | 2 | 1 |
| Abstain | 0 | 7 | 16 |
| False alarm | 2 | 3 | 2 |
| Technical/parse failure | 2 | 2 | 0 |
| Остаточные timeout | — | 0 | 0 |

Источники: [P0](../vuln-analyzer-shadow/eval/task5/scoring/p0/official_metrics.json), [combined summary](bench/QWEN36-LLM-RUN.md), [основные результаты](bench/llm/results/per-case-qwen36-vex.jsonl), [rerun](bench/llm/results/per-case-qwen36-vex-timeout3600.jsonl).

**Qwen3.8 — дополнительное свидетельство, не подмена matched baseline:** official recall 6/7; после восстановления полного JSON — 7/7 и accuracy 90%. Полная покейсовая safe-матрица Q3.8 сейчас не восстанавливается: исходный `/tmp`-root удалён. Известные результаты positives и parser defect задокументированы в [baseline, §9](../vuln-analyzer-shadow/eval/baselines/vexbench/plain-agent-baseline-1.md:425-494).

Сравнение полезно как **end-to-end сравнение подходов на одном корпусе**, но не изолирует причинный эффект конкретного prompt/tool: различаются runtime, дата, входы и протокол.

---

## 2. Матрица кейсов

Обозначения:

- **EXP** — `EXPLOITABLE`;
- **NA** — `NOT_AFFECTED`;
- **NEPF** — `NO_EXPLOIT_PATH_FOUND`;
- **INC** — `INCONCLUSIVE`;
- **PROVEN** — подтверждено сохранённым артефактом/кодом;
- **INFERRED** — объяснение правдоподобно, но не изолировано;
- **UNKNOWN** — диагностических данных недостаточно.

### 2.1. Все семь positives — приоритетная группа

| Case ID | Clean Q3.6 | Master | Branch | Расхождение / самый ранний установленный этап потери |
|---|---|---|---|---|
| `caddyserver-caddy-8dc7667-CVE-2025-29785` | EXP | EXP | EXP | Потери нет; контроль сохранения TP. |
| `rancher-rancher-4dc4f53-CVE-2025-47914` | **Safe, ошибочно** | EXP | EXP | Pipeline **лучше clean**; не относится к clean-correct потерям. |
| `kubernetes-kubernetes-e196d24-CVE-2023-44487` | EXP | **NA: false-safe** | **NA: false-safe** | **PROVEN:** advisory/identity scope до LLM; проверен исправленный x/net, пропущена реализация gRPC; **0 LLM calls**. |
| `stretchr-testify-285adcc-CVE-2022-28948` | EXP | EXP | **INC** | Потеря TP только у branch. **UNKNOWN:** точный gate и первый losing stage — подробный current report удалён. |
| `containers-podman-6a65597-CVE-2023-48795` | EXP | **NEPF: false-safe** | **INC** | **PROVEN:** построение exploit model — SSH Terrapin получил mandatory TLS/toolchain-условие; затем master использовал неподходящий version fact. |
| `cilium-cilium-1228cbc-CVE-2026-35469` | EXP | **INC** | **INC** | Потеря TP у обоих. **UNKNOWN:** точные unresolved claims; отчёты удалены. |
| `kubernetes-kubernetes-ec78c0f-CVE-2021-3121` | EXP | **INC** | **INC** | **PROVEN:** `ResolveRootCause`/symbol lookup — ошибка `-mod=vendor`, root cause `AMBIGUOUS`; завершение за 11–13 секунд, **не timeout**. |

Для Q3.8 все семь positives были правильными в parser-repair projection; `k8s-3121` official потерял корректный JSON из-за extractor defect. Но последующие Q3.8 probes давали false-safe на этом же кейсе: one-shot 7/7 не доказывает устойчивую безопасность.

**Итого:** branch теряет **пять из шести правильных positive-ответов Q3.6**, одновременно исправляя ошибку clean на Rancher.

### 2.2. Safe-кейсы, где Q3.6 clean был прав, а pipeline ошибся или воздержался

Это **11 кейсов**. Правильность здесь означает совпадение safe/non-safe с GT; она не означает наличия у clean независимого negative proof.

| Case ID | Clean Q3.6 | Master | Branch | Класс / первый losing stage |
|---|---|---|---|---|---|
| `juanfont-headscale-e172c29-CVE-2024-45338` | `code_not_reachable` | **Failure** | **INC** | Master: **PROVEN**, panic в `COLLECT_EVIDENCE`. Branch: **PROVEN**, dependency-internal callers не покрыты negative scope; `INSUFFICIENT_SCOPE`. |
| `istio-istio-8903f65-CVE-2024-45338` | `code_not_reachable` | **Failure** | **INC** | Master: **PROVEN**, panic при evidence collection. Branch: build-load failure уже в applicability/evidence, затем scope blockers negative verification. |
| `cilium-cilium-43bff35-CVE-2026-35469` | `code_not_reachable`† | INC | INC | Over-abstention относительно safe-метки. **UNKNOWN:** current losing stage. |
| `containers-podman-6541fc4-CVE-2025-58181` | `code_not_reachable` | INC | INC | Over-abstention. **UNKNOWN:** current stage; clean различал SSH client и vulnerable GSSAPI server. |
| `rancher-rancher-4dc4f53-CVE-2025-58181` | `code_not_reachable` | NEPF | INC | Потеря safe closure у branch. **UNKNOWN:** gate; rerun завершился, timeout не является итоговым исходом. |
| `cilium-cilium-3977f6a-CVE-2026-33186` | `requires_dependency`† | INC | INC | Over-abstention. **UNKNOWN:** current stage; clean исследовал отсутствие path-based auth interceptors. |
| `kubernetes-kubernetes-1ee2acb-CVE-2024-24786` | `code_not_reachable` | INC | INC | Over-abstention. **UNKNOWN:** current stage; clean утверждал недостижимость vulnerable protojson path. |
| `aquasecurity-trivy-98e136e-CVE-2024-24791` | `code_not_reachable` | INC | INC | Over-abstention. **UNKNOWN:** current stage; clean анализировал конкретный HTTP trigger, не только наличие net/http. |
| `containers-podman-38ccfa2-CVE-2024-37298` | `code_not_reachable` | **EXP** | **EXP** | **Wrong alarm**, не abstention. Точный current losing stage **UNKNOWN**; clean проверял типы decode-target structs. |
| `rancher-rancher-8761419-CVE-2026-39883` | `code_not_reachable` | NEPF | INC | Потеря safe closure у branch. **UNKNOWN:** current stage; clean ссылался на platform/build exclusion. |
| `helm-helm-fbb24fe-CVE-2021-21334` | `code_not_reachable` | NEPF | INC | Потеря safe closure у branch. **UNKNOWN:** current stage; clean различал OCI distribution и containerd CRI. |

† У двух Cilium-кейсов binary safe правильный, но точная категория не совпала с GT (`reason_correct=false` в P0). Их нельзя представлять как полностью правильное объяснение причины безопасности.

Покейсовая основа: [P0 classifications](../vuln-analyzer-shadow/eval/task5/scoring/p0/case_comparison.jsonl), [сохранённые reasoning](../vuln-analyzer-shadow/eval/task5/scoring/p0/parsed.jsonl), текущие два JSONL выше.

**Не включены в clean-correct матрицу:**
- gitleaks-22871 и k8s-41717 — clean Q3.6 сам дал false alarm;
- echo-26160 и istio-042afc3 — clean failure;
- остальные кейсы — pipeline сохранил правильный ответ.

Таким образом, из **25 правильных clean Q3.6 ответов** master теряет **12**, branch — **16**. Это покейсовые потери, а не разность агрегатных accuracy.

### Почему много `UNKNOWN`

Harness сохранял подробные отчёты только при false-safe/parse/timeout и удалял остальные. Поэтому у stretchr, Cilium и части потерянных safe closures осталась метка, но не decisive evidence. Это прямо следует из [retention logic](bench/.task10/run_compare_frozen.py:425-441).

Исторический `proof-feasibility` даёт полезные гипотезы, но **не доказывает причину конкретного текущего INC**. Приписывать таким кейсам «version gate», «runtime condition» или «не хватило времени» нельзя.

---

## 3. Причины по стадиям

### A. Advisory/identity scope — доказанный опасный ранний выход

**PROVEN, k8s-44487.**

Входной advisory покрывает `golang.org/x/net`; snapshot содержит исправленный `v0.17.0`. Pipeline корректно устанавливает этот частный факт и некорректно превращает его в глобальный `NOT_AFFECTED` по CVE. Другой affected path — **gRPC v1.55.0** — не исследуется.

Harness выбирает для CVE/alias первый файл в sorted index, не совокупность реализаций. Workflow допускает завершение после `CheckAffected`, до CVE research.

Источники: [индекс advisory](bench/.task10/run_compare_frozen.py:95-112), [retained Kubernetes report](bench/llm/cases/vex/kubernetes-kubernetes-e196d24-CVE-2023-44487/branch/CVE-2023-44487-1792764701/report.json:868-888,982-1018), [workflow](../vuln-analyzer-shadow/internal/states/states.go:203-213,330-345).

**Вывод:** исправление x/net не нужно переопределять. Нужно запретить распространение entry-scoped отрицания на непокрытые реализации CVE.

### B. Prompt/advisory binding — риск есть, исключительная причинность не доказана

Исторический LLM-first run k8s-44487 **упоминал gRPC**, но неверно решил, что исправленный x/net автоматически исправляет и его. Проверяющий слой сохранил scope gap и не разрешил закрытие.

Следовательно, «дать агенту смотреть шире» необходимо, но **недостаточно**: он может исследовать правильный компонент и сделать неверный вывод.

[Исторический report](../vuln-analyzer-shadow/eval/agent7/e2e/k8s-44487/report.md:1-38,170-201).

Недавний A–E run2 **не подтверждает** гипотезу вреда binding prompt: `integrity_ok=false`, все 15 доставленных prompts отличаются от rendered prompts. Сам контроль A ошибся 2/3. Причинное объяснение этих ошибок остаётся **UNKNOWN**. [Integrity report](bench/llm-first-ablation-run2/first-layer-vex-parity/comparison.md:559-581).

### C. Necessity/patch identity — доказанная причина Podman false-safe

**PROVEN, podman-48795.**

- SSH Terrapin классифицирован общим `CRYPTO_DOWNGRADE` pattern.
- Pattern добавляет mandatory `go_version < 1.18`, описанный через **legacy TLS floor**.
- Master сравнивает его с `go.mod` minimum 1.20 и получает verified FALSE → NEPF.
- Branch не подменяет release toolchain значением go.mod: условие остаётся UNKNOWN → INC.
- CVE bundle для x/crypto при этом содержит patch **libssh2, C-код**.
- Reviewer master прямо отметил нерелевантность TLS-условия SSH Terrapin, но NEPF сохранился.
- В merge также отсутствует проверка `mandatory:false`: optional предложение может попасть в mandatory slice.

Источники: [pattern](../vuln-analyzer-shadow/internal/exploit/patterns.go:158-172), [master claim/review](bench/llm/cases/vex/containers-podman-6a65597-CVE-2023-48795/master/CVE-2023-48795-1792768581/report.json:25170-25190,26297-26331), [branch bundle](bench/llm/cases/vex/containers-podman-6a65597-CVE-2023-48795/branch/CVE-2023-48795-1792769172/report.json:34979-35040), [merge](../vuln-analyzer-shadow/internal/llm/exploit.go:217-246).

**Исправлять нужно необходимость и identity условия**, а не логику conjunction: одно действительно ложное необходимое условие вправе опровергнуть exploit.

### D. Claim/evidence entailment — доказанный дефект контракта, вклад в конкретные исходы не изолирован

`acceptClaim` допускает LLM TRUE при наличии хотя бы одного существующего evidence ID. Это проверка ссылки, **не логического следования**. В Podman reviewer также заметил TRUE input claim при invalid argument index `-1`.

[Claim admission](../vuln-analyzer-shadow/internal/llm/agent.go:116-150), [Podman findings](bench/llm/cases/vex/containers-podman-6a65597-CVE-2023-48795/branch/CVE-2023-48795-1792769172/report.json:34306-34343).

FactGate в Product B специально проверяет воспроизводимость/binding, **не semantic truth**. Добавить FactGate — не значит решить entailment. [Контракт](../vuln-analyzer-shadow/internal/productb/triage/factgate.go:62-66).

### E. Deterministic gates и repair

**PROVEN:** branch fail-closed предотвращает master false-safe Podman, но увеличивает abstention.

Headscale показывает обоснованный отказ: ноль first-party references не исключает вызовы внутри dependency. Открытые interface/function-value dispatch и неполная sink closure также не доказывают отсутствие.

Reviewer/repair ограничен: умеет демотировать некоторые claims и повышать supporting condition, но не полноценный repair неверного mechanism/mandatory model. Поэтому содержательное замечание может остаться caveat. [Repair implementation](../vuln-analyzer-shadow/internal/states/states.go:1495-1610).

**INFERRED:** часть closure можно вернуть более точным релевантным scope и адресным evidence collection. Простое снятие blockers вернёт механизм «не нашли → отсутствует».

### F. Tools/build/generated code

**PROVEN:**
- текущий target host-default darwin/arm64, CGO off; Podman/Istio имеют build failures;
- k8s-3121 блокируется loader/vendor ошибкой до research;
- исторические tools-runs путали generator `plugin/unmarshal` со встроенным runtime `generated.pb.go`;
- `analyze_product_scope` рекламируется researcher, но dispatcher его не реализует.

[Tool declaration](../vuln-analyzer-shadow/internal/llm/research.go:69-76), [dispatcher](../vuln-analyzer-shadow/internal/cveanalysis/tools.go:30-100), [k8s current state](bench/llm/results/per-case-qwen36-vex.jsonl:26).

Для stretchr важен отдельный **INFERRED кандидат**: продукт — библиотека, и отсутствие внутренних callers не опровергает уязвимость публичного API. Clean нашёл `YAMLEq → yaml.Unmarshal`; исторический T1 ошибался на scoped-zero callers. Но точная причина текущего branch INC неизвестна.

### G. Бюджеты, timeout, parser, вариативность

- **PROVEN:** после rerun внешних timeout нет; timeout-only fix не объясняет остаточный разрыв.
- Внутренние лимиты сохраняются; Podman содержит `closure query evaluation budget exhausted`.
- Два pipeline `failed_parse` — фактически **nil-pointer panic**, не JSON модели.
- Q3.8 main k8s-3121 — настоящий extractor defect.
- Task 6 с большим assessment снизил parsed completion 94% → 62%; это свидетельство риска сложной схемы, не доказательство, что её упрощение восстановит security reasoning.
- Один historical pass и незакреплённая provider revision не позволяют отделить model drift от prompt/runtime effect.

Источники: [Podman exhaustion](bench/llm/cases/vex/containers-podman-6a65597-CVE-2023-48795/branch/CVE-2023-48795-1792769172/report.json:28928-28944), [panic](bench/llm/cases/vex/juanfont-headscale-e172c29-CVE-2024-45338/master/stderr.log:1-12), [Task 6](../vuln-analyzer-shadow/eval/task6/development-findings.md:7-46).

---

## 4. False-safe и inconclusive — разные задачи

**False-safe требует устранить необоснованное закрытие:**
- k8s-44487 — неполная область CVE;
- master Podman — неверная necessity и version authority.

**INC требует добыть недостающее доказательство**, а не заставить модель ответить увереннее.

При этом «все превратить в INC» тоже не рабочее решение:
- Task 5 gate заблокировал 5/5 false-safe ценой **46/63 правильных safe**;
- Task 6 validator заблокировал один false-safe и **39/45 правильных safe**, итоговый SCR стал 0%.

Это аргумент за **claim-bound evidence и релевантный scope**, не за ослабление проверки. [Task 5](../vuln-analyzer-shadow/eval/task5/gate-feasibility.md:24-61), [Task 6](../vuln-analyzer-shadow/eval/task6/scoring/decision.md:38-59).

---

## 5. Варианты тюнинга LLM-first

Ожидаемая польза — гипотеза для последующей проверки, не обещанный прирост.

| Приоритет / вариант | Польза | Риск / стоимость | Acceptance criteria |
|---|---|---|---|
| **P0. Advisory как данные, не исчерпывающая граница CVE** | Устраняет механизм k8s false-safe; позволяет искать alternative implementations. | Scope drift и лишние кандидаты; средняя стоимость discovery. | Исправленный x/net **не закрывает CVE**, пока gRPC-кандидат не разрешён. Каждый новый компонент связан с CVE/mechanism и independently bound source/version. |
| **P0. Admission mandatory conditions по mechanism и identity** | Убирает ложные falsifiers и искусственные UNKNOWN. | Ошибочная фильтрация настоящего условия; средняя стоимость. | SSH Terrapin не получает TLS `<1.18`; libssh2 patch не считается patch x/crypto; optional не становится mandatory. Настоящие platform requirements сохраняются. |
| **P1. Discovery → verification, с минимальным первым ответом** | Сохраняет свободный source reasoning; уменьшает format pressure. | Дополнительная extraction/formalization pass; обычно ещё один LLM-вызов. | Отдельно сохранены discovery category, найденные paths и результат проверки. Формализация не теряет найденный путь и не добавляет необходимость без admitted источника. |
| **P1. Reviewer finding → адресный repair** | Исправляет неверный mechanism, scope или claim, а не только демотирует итог. | Самоподтверждение и циклы; bounded дополнительные calls/tools. | High-severity mismatch создаёт конкретную evidence/model-revalidation задачу. Незакрытая проблема не остаётся рядом с auto-safe; reviewer сам не устанавливает verdict. |
| **P1. Claim-bound entailment** | Не позволяет отмывать claim существующей, но нерелевантной ссылкой. | Новые unsupported outcomes; средняя/высокая стоимость checker coverage. | Ссылка на чужой predicate/subject/version не даёт TRUE. Invalid arg index не доказывает input control. `reachability` отдельно от exploit trigger. |
| **P1. Рабочий product-scope tool и library-aware roots** | Помогает stretchr, dependency-internal calls и safe closures. | Недооценка dynamic/external callers; высокая стоимость scope analysis. | Tool реально dispatch-ится; возвращает loaded/skipped scope. Публичный `YAMLEq` не признаётся недостижимым из-за нуля внутренних callers. Scoped zero не становится global absence. |
| **P1. Build-independent source discovery + generated-code handling** | Даёт путь исследования при loader failure; адресует k8s-3121. | Source evidence может не соответствовать shipped build; средняя/высокая стоимость. | Loader error не становится «symbol absent». Исследован runtime `generated.pb.go`, не только generator. Build/source conclusions явно разделены; snapshot не «чинится» незаметно. |
| **P2. Verifier по точному falsifier scope** | Возвращает полезные safe closures без требования доказать отсутствие всего во всём repo. | Неполный denominator создаёт false-safe; высокая стоимость доказательств. | Каждый negative имеет necessity, subject/target binding и complete **релевантную** closure. Неудача постороннего optional tool не отменяет независимое доказательство; failed обязательная проверка не принимается за отсутствие. |
| **P1. Harness/parser/model discipline** | Делает измерение интерпретируемым; уменьшает технические потери. | Дополнительный capture и строгие отказы; низкая/средняя стоимость. | Delivered prompt совпадает с rendered; model/settings/runtime pinned. Official/full-JSON repair отдельно и симметрично для safe/unsafe. Все attempts сохранены, selective retries нет. |

Это следует строить поверх существующих Product-B proposal/FactGate/feedback механизмов и canonical Product-A evidence/verifier, **не создавая второй authoritative verdict engine**. В Product B уже есть bounded [fact/falsifier feedback loop](../vuln-analyzer-shadow/internal/productb/triage/runner.go:127-169).

---

## 6. Приоритеты и критерий «рабочей версии»

### Сначала — P0 safety defects

1. **k8s-44487:** разделить entry applicability и CVE-wide conclusion.
2. **Podman Terrapin:** исправить necessity/patch identity/condition admission.
3. **Review:** закрывать обнаруженное противоречие через revalidation, а не сохранять safe с caveat.

Подтверждение причины: после исправления меняется **именно первый ошибочный scope/model decision**. Если меняется только terminal label на INC, устранена опасная ошибка, но полнота ещё не восстановлена.

### Затем — вернуть потерянные positives

Порядок: **k8s-3121 → stretchr → Cilium-1228cbc**.

- Для k8s есть конкретный воспроизводимый сохранённый blocker.
- Для stretchr/Cilium нельзя выбирать конкретный фикс по одной метке INC: следующая разрешённая диагностика должна сохранить first divergent stage, proposals, claims и verifier reasons.
- Обязательные regression controls: Caddy и Rancher-47914 — не потерять уже работающие TP.

### Потом — safe closures и wrong alarm

Первыми удобны предметные гипотезы из clean reasoning:
- Podman/Rancher-58181: client/agent против vulnerable SSH server;
- Podman-37298: типы decode-target structs против общей достижимости `Decode`;
- Helm-21334: OCI distribution против CRI;
- Headscale/Istio: bounded dependency-import closure;
- Rancher-39883: подтверждённый target/build exclusion.

Это **задачи доказательства**, не разрешение довериться историческому reasoning.

### Acceptance для последующей оценки

Предлагаемый критерий кандидата, **не уже достигнутый результат**:

- **Safety:** ноль false-safe на семи positives и сохранённых targeted counterexamples; invalid identity/scope/failed mandatory tools не допускают safe.
- **Discovery:** на matched control не теряются найденные clean paths; исторический ориентир Q3.6 — 6/7 positives и 19/23 safe.
- **End-to-end utility:** отдельно публикуются подтверждённые TP и safe closures. `REVIEW_REQUIRED`/INC **не засчитываются** как сохранённая detection/closure.
- **Recovery:** пять известных positive-потерь имеют покейсовый результат и stage trace; исчезновение false-safe только через abstention не выдаётся за восстановленный recall.
- **Integrity:** корректная доставка prompts, единая attempt policy, все failures/повторы сохранены, replay без нового LLM-вызова.
- **Admission:** корпусная parity и ноль observed false-safe необходимы, но на семи positives недостаточны для заявления о production safety; нужен независимый holdout.

### Чего не делать

- Не ослаблять negative gates ради красивого recall/SCR.
- Не считать повышение timeout достаточным исправлением.
- Не подставлять go.mod или локальный Go вместо release toolchain.
- Не считать любой `ERROR/PARTIAL` основанием отвергать весь ответ: проверять зависимость **конкретного claim** от наблюдения.
- Не ограничивать verifier только перечисленными landed modules без проверки alternative implementations: это повторит k8s-44487.
- Не лечить задачу только safety prompt, большим JSON assessment или сменой модели.
- Не использовать повреждённый A–E run2 как причинное доказательство.

**Итоговый шлюз:** **READY для выбора перечисленных направлений тюнинга; BLOCKED для ослабления production safe-policy.** Пользовательского решения, необходимого для этого read-only анализа, не осталось. Главная последовательность: **сначала правильная область уязвимости и необходимость условий, затем перевод исследования в проверяемые claims, затем расширение coverage и бюджетов.**
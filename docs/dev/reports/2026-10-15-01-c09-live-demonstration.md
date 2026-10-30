# C09 Live Agent Demonstration Report — Autonomous Evidence Capability

**Status: ACHIEVED — first real-case verified negative (updated 2026-10-15 after the decision-ordering fix)**  
Date: 2026-10-15  
Case: C09 (`<PRIVATE_UNIT>`, snapshot `<PRIVATE_SNAPSHOT>`, advisory `GHSA-x744-4wpc-v9h2` / `GO-2026-4887`)  
Model: `qwen3.6-35b` via custom-openai relay in E6 Docker container (`vex-bench-go-opencode-e6:latest`, digest `sha256:1d7b3d39...`)  
Prompt: `eval/agent7/prompts/r0-v3.txt` (sha256 `7a53b8d4...`)  
Output dir: `<VA_TMP>/autonomous-evidence-slice/runs/C09-live/`  

---

## 0. Итог после правок (обновлено 2026-10-15)

Кейс C09 доведён до **терминального доказательного негатива**: `verdict=NOT_AFFECTED`,
`coverage=COMPLETE`, `scope="deterministic applicability chain"`,
`evidence_refs=["obs:OBS-0009"]`, `Disposition=REVIEW_REQUIRED`, `AutoClose=false`.
Повторный прогон обоих сохранённых ходов (replay, без вызова модели) даёт тот же результат —
нестабильность между запусками устранялась двумя дефектами собственного решения (порядок
applicability относительно гейта предложения; область проверки положительного противоречия),
а не поведением модели.

Замер по 18 корпоративным отклонённым кейсам со снапшотами (детерминированный прогон, без модели):
**7/18 = 38.9% `NOT_AFFECTED` (COMPLETE)**, 11/18 `INCONCLUSIVE`, **false-safe = 0**, все 18 отчётов
проходят самовалидацию (`exit 0`).

## 1. Резюме

Был выполнен первый реальный живой прогон агентного контура автономного исследования уязвимостей (`izyan research`) на реальном корпоративном кейсе C09 с моделью Qwen3.6-35B в изолированном E6 Docker-контейнере.

Прогон завершился за 305 секунд (5м05с) с кодом выхода 0. Все инфраструктурные и защитные гейты отработали штатно:
- E6 preflight прошел с полным статусом **PASS** (все 29 проверок зеленые, изоляция, `network=none`, `cap_drop=ALL`, перехват попыток выполнения shell-кода).
- Модель провела полноценное исследование исходного кода, `go.mod`, `go.sum` и каталога `vendor/`.
- Модель **самостоятельно установила точную причину неприменимости** и выбрала категорию `false_positive`.
- Итоговый отчет сформирован по схеме `research-report/2`, валидация прошла успешно.
- Вердикт системы: **`INCONCLUSIVE`** (покрытие `INSUFFICIENT_SCOPE`, диспозиция `REVIEW_REQUIRED`, `AutoClose=false`).

Никаких ложных отрицательных заключений не выдано — система сработала строго в режиме **fail-closed**.

---

## 2. Что показало исследование модели (Qwen3.6-35B)

Модель в ответе (`answer.txt`) выдала содержательно безупречный технический разбор:

> **Category:** `false_positive`
>
> **Reasoning:**  
> The CVE GHSA-x744-4wpc-v9h2 specifically affects github.com/moby/moby module (advisory entries adv-01 and adv-02). The snapshot belongs to <PRIVATE_PRODUCT_MODULE> as confirmed by /work/go.mod:1. A complete search of go.mod and vendor/modules.txt confirms github.com/moby/moby is not declared as a direct or transitive dependency. The only Docker-related module present is github.com/docker/docker v28.0.1+incompatible (go.mod:105), which is a separate module with its own versioning. References to "moby/moby" found in vendor code (e.g., /work/vendor/github.com/docker/docker/client/client.go:86) are only comment references to upstream issues, not the affected library code. Therefore the CVE-to-component mapping is wrong for this codebase.

Модель самостоятельно установила:
1. Advisory относится к серверной части Docker daemon (`github.com/moby/moby`).
2. В продукте отсутствует зависимость от `github.com/moby/moby` как напрямую, так и транзитивно (проверено по `go.mod` и `vendor/modules.txt`).
3. Присутствующий модуль `github.com/docker/docker v28.0.1` — это клиентская библиотека, имеющая собственную версионизацию.
4. Упоминания `moby/moby` в исходниках — это ссылки на GitHub issues в комментариях, а не библиотечный код.

---

## 3. Выявленный разрыв (Capability Gap)

Несмотря на правильный вывод, модель **не сформировала в ответе блок `verification_plan`**.

Причина:
- Модель в ходе автономного исследования уже прочитала `go.mod` и `vendor/modules.txt` с помощью инструмента `read`.
- Факт отсутствия модуля `moby/moby` она сочла доказанным фактом, а не «гипотезой, требующей проверки».
- Поэтому она заполнила стандартные поля `category`, `reasoning` и `assessment`, но опустила блок `verification_plan`.

Поскольку блок `verification_plan` отсутствовал:
- Движок верификации зафиксировал: `plan_status: "no verification plan in the retained answer"`.
- `VerifyDecision` остановился на условии `Proposal == nil`.
- Вердикт: `INCONCLUSIVE`, основание: `no independently verifiable falsifier proposal`.

Это **положительный результат для безопасности**: детерминированный движок не поверил текстовому утверждению модели и не выставил автоматический verdict `NOT_AFFECTED` без формального независимого фальсификатора.

---

## 4. Что было реализовано в рамках работы

1. **B47 — проброс опций**: `--modcache` и `--govulndb` теперь корректно передаются в `SessionConfig` доказательной сессии (`internal/research/verification.go`).
2. **B41 — offline vendor closure**: реализован автономный вывод продуктового и тестового замыкания из `vendor/modules.txt` и AST-импортов (`internal/affected/vendorclosure.go`, 154 теста).
3. **Task 2.5 — маркер доказуемого отсутствия**: введен маркер `VERIFIED_VENDOR_INVENTORY` для гарантированно отсутствующих в инвентаре модулей при vendor-сборке.
4. **Контракт отчетов `research-report/2`**: блок `decision` с явным разделением на вердикт доказательств и диспозицию `REVIEW_REQUIRED`, обоснованием для трекера и защитой от подделки доказательств.
5. **Устранение бага containerd/Docker Desktop**: функция `_image_facts` в harness получила fallback на имя с префиксом `docker.io/library/`, устранив нестабильность inspect.
6. **Промпт `r0-v3`**: снято противоречие верхнеуровневых полей JSON и добавлена спецификация плана проверок.

---

## 5. Что дало закрытие разрыва

Правки, после которых кейс замкнулся: `r0-v4` (обязательный `verification_plan`), детект
`vendor_mode` в зонде снапшота (поле никем не заполнялось), порядок применения applicability-цепочки
и скоуп проверки положительного противоречия по субъектам advisory, а также отображение
`EV-*` ссылок в carrier-наблюдения. Детали — в
`.superpowers/sdd/2026-10-15-01-c02-closure-capability-plan/progress.md`.

## 6. Дальнейшие шаги (Backlog)

- **B49**: Добавить принудительное извлечение `verification_plan` из `reasoning`/`assessment`, если модель в тексте сформулировала отсутствие модуля (`FalsifierPackageAbsent`), но забыла отдельный JSON-ключ. Либо использовать строгий structured output (JSON schema constraint на уровне вызова модели).
- После B49 C09 становится eligible для повторной проверки, но terminal negative допускается только после нового live turn с agent-emitted `verification_plan`, успешного выполнения всех advisory-wide verification gates и отдельного replay. Предыдущий raw answer не является plan-bearing turn и не может быть retroactively promoted.

# Agent-7 (A-series) — E2E slice 2: достоверность и практическая полезность отчёта

- **Статус:** accepted (Slice 2 завершён).
- **Дата:** 2026-10-12.
- **Основание:** Slice 1 (`docs/dev/decisions/agent7-research-slice-1.md`), требования оператора к Slice 2; дизайн контракта — `.superpowers/sdd/…/slice2-design.md` (sha256 `6dfa90a9…72d3`).
- **Артефакты:** `eval/agent7/e2e/<case>/` (report.json/report.md, `observations.jsonl`, `deterministic-facts.json`, `artifacts/`, `agent/attempt-*/` + сырой harness-лог), патчи harness `eval/agent7/harness/{e2e-single-case,slice2-attempts}.patch`.

## 1. Что исправлено в содержании отчётов

| Кейс | Было | Стало |
|---|---|---|
| `k8s-44487` | категория агента `code_not_present` читалась как вывод по всей CVE | `classification_review{original_category=code_not_present, class=NON_APPLICABLE, status=CONFLICTED}` + противоречие `C-0001 category_vs_component_scope` (`resolution=SCOPE_LIMITS`); `conclusion_scope=AFFECTED_ENTRY_ONLY`, `advisory_scope_status=GAP_DETECTED`; отдельные `advisory_scope_gap` противоречия по реальным зависимостям вне advisory (`google.golang.org/grpc/internal`, `k8s.io/apimachinery/pkg`, `k8s.io/apiserver/pkg`) |
| `rancher-47914` | достижимость, сокет и эксплуатируемость смешаны; агентские утверждения читались как доказательство | три явные оси: `code_reachability=ESTABLISHED/PACKAGE_BUILD` (import closure + build relevance), `attack_surface_availability=UNKNOWN` (нет детерминированного факта о listener/socket), `exploitation_established=NOT_ESTABLISHED` с обязательной формулировкой «attacker exploitability is not established…» |
| `trivy-32473` | «неприменимо» выводилось без базиса | `classification_review{class=NON_APPLICABLE, status=UNKNOWN}` + ограничение «no verified non-applicability basis (component_absent\|version_fixed\|package_not_in_import_closure\|sdk_vs_daemon_distinction) resolved»; базис `component_present_affected` (ESTABLISHED) сохранён, SDK-vs-daemon остаётся agent-assertion |

Оригинальные утверждения агента не переписываются: они остаются в `agent_assertions`/`agent_output`, а противоречия, обзор классификации и ограничения вынесены в отдельные структуры.

## 2. Пользовательская структура `report.md`

Порядок: суть CVE и механизм → что найдено в продукте → затронутые/исправленные/непроверенные реализации → условия эксплуатации (установленные vs неизвестные) → главное обоснование → рекомендация «что проверить/исправить» → decision-changing unknowns → scope/provenance/disposition → базис применимости → противоречия и ограничения → сохранённые утверждения агента → реестр evidence → история попыток → приложение. Количество фактов/условий/вопросов нигде не подаётся как показатель качества; в приоритет попадают только вопросы, способные изменить заключение (`decision_changing_for` называет, что именно переворачивается). Исправлен дефект рендера `%!s(MISSING)`.

## 3. Целостность артефактов

1. **ID-пространство:** наблюдения сессии перенумеровываются в последовательность полосы; перезаписи evidence больше нет (проверяется инвариантом «payload digest = байты артефакта»).
2. **Материальность evidence:** существенные факты несут байты артефакта (path + sha256 записанных байт) и/или воспроизводимый рецепт; digest без байтов больше не единственная опора.
3. **Ограничение размера payload:** 256 KiB на наблюдение с честной фиксацией усечения (`truncated_payload`, `full_payload_sha256`, `full_payload_size_bytes`, limitation, `COMPLETE→PARTIAL`); `data_digest`/`artifact.sha256` остаются дайджестами записанных байт. Без этого `observations.jsonl` достигал 66–77 MB на кейс (trivy/rancher), после — 1.0–1.1 MB.
4. **Попытки агента:** каждая попытка имеет свой идентификатор и каталог (`agent/attempt-0002/…`); харнесс больше не перезапускает невалидный результат in place — исходный `result.json` сохраняется как `result.invalid-<utc>.json` с `retry-reason.txt`, повтор идёт в `run_NNN_rK`, полная история — в `attempts.jsonl` (патч `slice2-attempts.patch`, sha256 `1b0d451c…4e77`).
5. **Извлечение ответа:** сканирование всех кандидатов-объектов; при нескольких различных валидных кандидатах — `INVALID`/`AMBIGUOUS_CONFLICTING_CANDIDATES` с сохранением всех кандидатов в сыром артефакте.

## 4. Регрессия

Минимальные автоматизированные инварианты (Go-тесты + правила валидатора): (a) нет подмены наблюдений (дайджест payload = байты артефакта); (b) корректность областей evidence (ссылки резолвятся в своей области; `ESTABLISHED` требует динамического/детерминированного базиса, а не агентского); (c) детекция противоречий присутствует там, где требуется (k8s); (d) agent assertion никогда не повышается до verified fact (нет agent-origin данных в `verified_facts`, `origin=deterministic` требует существующего факта). Приёмочный чекер расширен до 16 проверок: **PASS 16/16 на всех трёх кейсах**; легаси-отчёты Slice 1 по-прежнему валидны.

## 5. Оставшиеся функциональные ограничения (конкретно)

1. **`conclusion_scope` не может стать `ADVISORY_SET`/`COMPLETE`** — нет оракула полноты advisory; всегда `AFFECTED_ENTRY_ONLY` + `GAP_DETECTED` при реальных зависимостях вне записей.
2. **Агентские утверждения не проверяемы машинно**: SDK-vs-daemon и подобные базисы остаются provisional, поэтому `classification_review.status` для trivy — `UNKNOWN` (это корректно, но и потолок для source-only отчётов).
3. **Детерминированные проверки на крупных снапшотах частично падают в TIMEOUT/ERROR** (per-tool 60 s): rancher — 10 decision-changing unknowns именно из таких проверок; сокращение возможно только адресным увеличением бюджета конкретных проверок.
4. **Усечение payload** (256 KiB) означает, что для очень больших наблюдений полные байты не хранятся — фиксируется digest и размер, воспроизведение требует повторного запуска полосы.
5. **`advisory_scope_gap` ловится по зависимостям из модульного графа** — компонент, упомянутый только прозой (без module path) или отсутствующий в графе, попадёт максимум в приложение, не в decision-changing.
6. **Release/delivery identity отсутствует** (нет binary inventory/attestation) — отчёты остаются source-tree scoped.
7. **Провайдер зависит от DNS/VPN**: недоступность → fail-closed `ENV_FAIL`, отчёт не строится.
8. **Харнесс всё ещё требует повторного вызова run-стадии для ретрая** — автоматических ретраев нет (это соответствует протоколу), но и «умного» восстановления тоже.

## 6. Следующий шаг

Переход к расширению исследовательских возможностей на реальных CVE (как договорено): использовать `izyan research` на новых снапшотах/адвизори, накапливать отчёты и решать по конкретным пробелам, какой детерминированный факт добавить. A3/Event Store/Proof Engine, R1/MCP и auto-close остаются вне рамок до отдельного решения.

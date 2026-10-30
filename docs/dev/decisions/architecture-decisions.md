# Ключевые архитектурные решения

## D1. Verdict только детерминированный

LLM не имеет API для установки `NOT_AFFECTED`, `EXPLOITABLE`, `NO_EXPLOIT_PATH_FOUND`, `INCONCLUSIVE`.

## D2. Root cause — отдельный gate

Нельзя строить глубокий exploitability analysis относительно случайно выбранной функции. Ambiguous/not found -> INCONCLUSIVE.

## D3. ExploitModel состоит из обязательных условий

Reachability не равно exploitability. Каждая CVE разлагается на минимальные mandatory conditions.

## D4. EvidenceGraph — стабильная граница

LLM/reviewer не зависят от raw JSON конкретных scanner versions.

## D5. NO EVIDENCE != FALSE

Отрицательное заключение требует положительного доказательства невозможности условия.

## D6. FALSE сильнее TRUE

Safe FALSE проходит отдельный negative-check и попытку найти контрпример.

## D7. govulncheck раньше собственного call graph

Не писать в MVP то, что уже решает Go toolchain. Собственные SSA/AST tools нужны только для targeted gaps.

## D8. Не писать full taint engine в MVP

Сначала targeted argument provenance + validation + source slicing. Сложные случаи могут законно завершаться INCONCLUSIVE.

## D9. Confidence не участвует в security verdict

Confidence используется только для review priority/UI.

## D10. CVSS/EPSS/KEV/PoC отделены от exploitability

Они влияют на risk priority/SLA, но не доказывают applicability/exploitability продукта.

## D11. Один основной Analyzer + Reviewer

Не строить committee/majority multi-agent систему. Reviewer проверяет claims/evidence, а не голосует за итог.

## D12. Persisted state важнее LLM transcript

Анализ должен быть restartable, auditable и model-independent.

## D13. LLM context должен быть bounded

Передавать только current condition + relevant evidence/source fragments + limitations + available tools.

## D14. Режим deterministic-only обязателен

Он нужен для диагностики границы между фактическим анализом и LLM reasoning.

## D15. Remediation отделён

Сначала измеряется качество exploitability analysis. Автообновление зависимостей/кода добавляется позже.

## D16. LLM advisory-контур — параллельно, репортируемо, не авторитетно

Отдельный LLM-контур оценивает семантику (назначение callee, источники
данных, оценка вердикта) и пишет `llm_assessment.json` + секцию в
отчёте. Он **не** входит в claim/verdict — это детерминистический
контур; расхождение оценки и вердикта — finding для человека, не
override. Совпадение контуров повышает уверенность в выводе; расхождение
— чекпоинт ревью. Смысл: LLM делает работу рассуждения, движок — работу
доказательства; прозрачная граница аудируется, а не прячется.

## D17. Dual-product authority and adapter boundary

Shadow владеет авторитетным контуром: canonical `AnalysisCase`,
`EvidenceGraph`, `Claim`, `NegativeVerification`, `VerdictResult` и
детерминистический verdict принадлежат только Product A — под `internal/`
canonical packages. Product B (портированный triage runtime, research
lane, heldout gate) живёт в `internal/productb/**` как adapter:
не-авторитетный, proposal-only, его артефакты никогда не переходят в
вердикт/claim/NV.

Правила границы:

- no V2 `internal/domain`/`affected`/`evaluator` merge — типы мапятся на
  канонические только через `internal/productb/domain` aliases (§14.3.2
  "map" disposition) или адаптер-локальные DTO; типа, для которого нет
  канонического эквивалента, в adapter не протаскивается (явный
  unsupported, не угадывание);
- Product B outputs (assessment, falsifier proposals, research reports,
  decision package, deployment projection) — measurement/proposal
  material only; admission в canonical contract — через proposal-only
  ingress и `AdmitAssumption`-эквивалентные fail-closed gates;
- failure rules: PARTIAL/UNKNOWN/conflict/foreign/cross-run never admit;
  missing manifest → unknown, never isolation; malformed input → typed
  technical error, не silent admit;
- Product A mechanics (goanalysis, evidencetools, fix, toolaudit, llm)
  остаются shared — это canonical mechanics, не authority boundary;
- boundary pinned by `internal/productb/boundary_s12_test.go` +
  `internal/productb/triage/boundary_test.go`: forbidden imports
  отклоняются на уровне import graph + source scan, не конвенцией.

Escalation: любая попытка добавить authority/type/verdict в Product B
или ослабить fail-closed поведение в адаптере — blocking review item, не
рефакторинг.

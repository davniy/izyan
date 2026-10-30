# Архитектурные изменения

Читать при изменении пайплайна, стадий, доменной модели, границ слоёв.

## Хребет системы

- Сквозной пайплайн — state machine: `CREATED → SNAPSHOT_PRODUCT →
  RESOLVE_VULNERABILITY → CHECK_AFFECTED → RESOLVE_ROOT_CAUSE
  (с автономным CVE research) → BUILD_EXPLOIT_MODEL → COLLECT_EVIDENCE →
  EVALUATE_CONDITIONS → [GAP_ANALYSIS] → NEGATIVE_CHECK → REVIEW →
  [REPAIR_ANALYSIS] → EVALUATE_VERDICT → BUILD_REPORT → COMPLETED`.
  Новая логика — состояние или evidence-тип, не обходные пути.
- Детерминистическое ядро + опциональный LLM-слой: LLM — адаптеры с
  бюджетами и fallback'ами, никогда не источник истины. Всё, что можно
  проверить детерминистически — проверяется детерминистически.
- `AnalysisCase` персистится и рестарт-способен: состояние кейса не
  зависит от LLM-чата. Каждый факт — `Evidence` с provenance в
  `EvidenceGraph` (hash, quality-уровни).
- Вердикт только детерминистический, считается из claims —
  `evaluator.Verdict` читает результат, не вычисляет его из сырья.
- Никаких проприетарных зависимостей: интеграции — generic точки
  (OSV JSON, `--ticket`, VEX-экспорт). Open source.
- Консерватизм: неготовая стадия → INCONCLUSIVE, не «best effort
  вердикт». Неопределённость сохраняется и отображается, не глотается.


## Definitive-verdict invariants (2026-10-26)

1. Exactly one verdict evaluator and one requested-finding projection. Do not add
   a second exploitability evaluator, a verdict-forcing fallback, or a
   consumer-side re-derivation.
2. Three outcomes only (`DECIDED`, `EXTERNAL_DEPENDENCY`, `FAILED`). A code-owned
   blocker is `FAILED`; an external dependency must name the fact, its boundary
   evidence, why the artifact cannot supply it, the alternatives that change the
   answer and the input that would resolve it. An LLM cannot declare a gap
   external by labelling it.
3. `related` is discovery only: never an alias, never transitive, never a fact
   source. Attribution is a separate admitted proposition bound to exact record
   bytes, entry/mechanism and fix.
4. Assessments are isolated: each record's own bytes, ranges, census, subjects,
   conditions, claims, review, severity and remediation. Only immutable product
   measurements are shared, and they are re-projected per record.
5. Composition lifts only independently earned positives within one profile and
   matching build; candidate negatives never close a CVE. A CVE-wide negative
   requires a declared, digest-pinned, finished corpus and the verbatim boundary.
6. `transport-peer` comes only from an admitted mandatory `TRUE` transport-input
   claim; locality never implies trust, and the deployed-access question stays
   separate.
7. Persist and re-admit attribution, record pins, qualified references and the
   outcome before publishing. Never trust a saved positive.

# Индекс документов

## Структура

- корень `docs/` — документация для пользователей
- `dev/specs/` — спецификации и контракты (что система должна делать;
  нормативные, меняются редко и осознанно)
- `dev/decisions/` — принятые архитектурные решения и запреты
- `dev/roadmaps/` — роадмапы развития фич и исследовательских направлений
  (стратегические документы срезов; после завершения фичи переносятся в архив)
- `dev/plans/` — временные пошаговые планы реализации (чек-листы для
  сессий разработки; после завершения фичи удаляются)
- `dev/` — живое состояние разработки: бэклог (`gap-analysis.md`),
  хроника реализации (`implementation-status.md`), внутренняя механика (`analysis-internals.md`)
- `agent-rules/` — рабочие правила для агентов (on-demand, индекс в
  `AGENTS.md`; не проектная документация, а инструкции исполнителя)
- `dev/history/` — исторический архив: начальная архитектура и завершённые фичи
- [`eval/README.md`](../eval/README.md) — live-корпус (вне `docs/`, рядом с данными корпуса)

## Таблица

### Для пользователей (корень `docs/`)

| Файл | Статус | Назначение |
|---|---|---|
| [`goals-scope.md`](goals-scope.md) | актуальный | Цель, задачи, границы, verdicts, MVP — charter проекта |
| [`architecture.md`](architecture.md) | актуальный | Архитектура: входы/выходы, конвейер состояний, средства, модель данных |
| [`cli.md`](cli.md) | актуальный | Справочник команд, флагов, выходных артефактов |
| [`knowledge-base.md`](knowledge-base.md) | актуальный | База знаний экосистемы: формат файла, расширение `--knowledge`, версии и digest |
| [`how-it-works.md`](how-it-works.md) | актуальный | Методология и гарантии безопасности (Security Deep Dive): вердикты, предохранители, AI governance |

### Для разработчиков (`dev/`)

#### Нормативные спецификации (`dev/specs/`)

| Файл | Статус | Назначение |
|---|---|---|
| [`dev/specs/governing-spec.md`](dev/specs/governing-spec.md) | актуальный | Главная спецификация системы |
| [`dev/specs/s01-identity-and-case-bundle.md`](dev/specs/s01-identity-and-case-bundle.md) | draft | S-01 canonical identity и case-bundle; NOT PLAN-READY (U-01–U-04) |
| [`dev/specs/analyzer-agent-spec.md`](dev/specs/analyzer-agent-spec.md) | актуальный | Контракт поведения Analyzer Agent |
| [`dev/specs/incremental-analysis-value-spec.md`](dev/specs/incremental-analysis-value-spec.md) | reviewed draft | Контракт дополнительной ценности поверх govulncheck; доказательство mandatory input condition |
| [`dev/specs/llm-cve-analysis-spec.md`](dev/specs/llm-cve-analysis-spec.md) | актуальный | Автономное LLM-исследование механизма CVE, стратегии, валидация доказательств, контекстная критичность; B31–B33 |
| [`dev/specs/llm-dismissal-research-spec.md`](dev/specs/llm-dismissal-research-spec.md) | исследовательская | LLM-assisted отклонение, экспертное досье, deployment и контекстная критичность; B27 |
| [`dev/specs/shadow-analyzer-agent-spec.md`](dev/specs/shadow-analyzer-agent-spec.md) | SUPERSEDED | Историческая спека Shadow Analyzer Agent и VEX-Bench evaluation; superseded by target architecture + D17 — см. `dev/roadmaps/2026-10-20-target-architecture-and-roadmap.md` |

#### Роадмапы развития (`dev/roadmaps/`)

| Файл | Статус | Назначение |
|---|---|---|
| [`dev/roadmaps/2026-10-20-target-architecture-and-roadmap.md`](dev/roadmaps/2026-10-20-target-architecture-and-roadmap.md) | design for review | Целевая архитектура консолидации Shadow/V2, gap analysis, roadmap и spec backlog; self-sufficient addendum §13; port revision §14; не является implementation spec |
| [`dev/roadmaps/2026-10-22-post-benchmark-fix-roadmap.md`](dev/roadmaps/2026-10-22-post-benchmark-fix-roadmap.md) | NO-GO until P0 fixes | Product A applicability/scope fixes and merge gate after benchmark regression |
| [`dev/roadmaps/agent-first-analysis-roadmap.md`](dev/roadmaps/agent-first-analysis-roadmap.md) | в работе | Agent-first анализ: baseline (Этап 0), Shadow Agent, Evidence Tools, Verification Kernel |
| [`dev/roadmaps/llm-cve-analysis-roadmap.md`](dev/roadmaps/llm-cve-analysis-roadmap.md) | в работе | Поэтапная поставка research/dossier, validated proof capabilities и критичности (задачи 1–6 выполнены, 7–16 в плане); B31–B33 |
| [`dev/roadmaps/ingress-closure-roadmap.md`](dev/roadmaps/ingress-closure-roadmap.md) | в работе | Ingress closure: полный inventory входов в reachable dep cone; falsifier `constant-or-generated-input`; B26 |
| [`dev/roadmaps/corpus-expansion-roadmap.md`](dev/roadmaps/corpus-expansion-roadmap.md) | бэклог | Расширение доказательной базы: generated-manifest продукты, baseline vs govulncheck; B13 |
| [`dev/roadmaps/llm-dismissal-research-roadmap.md`](dev/roadmaps/llm-dismissal-research-roadmap.md) | исследование | Пошаговая проверка локального type gate в jose2go: 4 контрольных продукта, baseline, LLM-прогоны и досье; B27 |
| [`dev/roadmaps/llm-advisory-roadmap.md`](dev/roadmaps/llm-advisory-roadmap.md) | бэклог | LLM advisory-контур (D16): параллельная оценка, llm_assessment.json; B17 |

#### Текущее состояние разработки (`dev/`)

| Файл | Статус | Назначение |
|---|---|---|
| [`dev/gap-analysis.md`](dev/gap-analysis.md) | актуальный | Gap analysis спека↔код + канонический бэклог (§2) |
| [`dev/implementation-status.md`](dev/implementation-status.md) | живой | Хроника реализации срезов и выполненных задач |
| [`dev/analysis-internals.md`](dev/analysis-internals.md) | актуальный | Механика реализации: evaluators, NV, pattern library, toolchain, audit |
| [`dev/spec-workflow.md`](dev/spec-workflow.md) | draft | Процесс: тезис roadmap → spec → review → goal/architecture check → plan → implementation → evidence |
| [`dev/ownership-and-ci.md`](dev/ownership-and-ci.md) | актуальный | S-15 owner matrix, named CI gates, artifact retention policy, release/escalation rules |
| [`dev/retention-manifest.template.json`](dev/retention-manifest.template.json) | актуальный | Шаблон retention manifest с хэшами для baseline/sidecar/admission артефактов |
| [`dev/plans/`](dev/plans/) | рабочая | Каталог для временных пошаговых планов реализации (чек-листы сессий) |

#### Архитектурные решения (`dev/decisions/`)

| Файл | Статус | Назначение |
|---|---|---|
| [`dev/decisions/architecture-decisions.md`](dev/decisions/architecture-decisions.md) | актуальный | Ключевые архитектурные решения и запреты (ADR) |
| [`dev/decisions/reference-projects-analysis.md`](dev/decisions/reference-projects-analysis.md) | актуальный | Разбор VEX Toolset / VulnReach / amihit / govulncheck — обоснование решений |

#### История и архив (`dev/history/`)

| Каталог / Файл | Назначение |
|---|---|
| [`dev/history/README.md`](dev/history/README.md) | Описание эволюции архитектуры и структуры архива |
| [`dev/history/01-initial-architecture.md`](dev/history/01-initial-architecture.md) | Исходная архитектура до анализа OSS-референсов |
| [`dev/history/go-skeleton-state-machine.md`](dev/history/go-skeleton-state-machine.md) | Bootstrap-каркас Go-структур до реализации ядра |
| [`dev/history/features/`](dev/history/features/) | Архив завершённых дизайн-спецификаций фич и планов реализации MVP (18 документов) |

## Рекомендуемый порядок чтения coding-agent'ом

1. [`goals-scope.md`](goals-scope.md)
2. [`dev/specs/governing-spec.md`](dev/specs/governing-spec.md)
3. [`dev/decisions/architecture-decisions.md`](dev/decisions/architecture-decisions.md)
4. [`dev/gap-analysis.md`](dev/gap-analysis.md) — бэклог открытых задач
5. [`dev/specs/analyzer-agent-spec.md`](dev/specs/analyzer-agent-spec.md) — перед реализацией LLM loop
6. [`architecture.md`](architecture.md) + [`how-it-works.md`](how-it-works.md) — устройство и поведение
7. [`dev/decisions/reference-projects-analysis.md`](dev/decisions/reference-projects-analysis.md) — как reference, не как governing source

При противоречии документов приоритет имеет [`dev/specs/governing-spec.md`](dev/specs/governing-spec.md), затем [`dev/decisions/architecture-decisions.md`](dev/decisions/architecture-decisions.md).

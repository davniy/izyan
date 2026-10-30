# Human Triage Result Recovery and Completion Implementation Plan

**Goal:** Восстановить потерянные при незавершённой консолидации возможности и завершить уже реализованный human-result продукт: один live LLM-first investigator, подготовленное решение или конечный набор условных решений, максимум два ответа окружения и Accept/Reject — без дополнительного исследования со стороны человека и без расширения машинной authority.

**Architecture:** Сохранить реализованные triage judgment/action/support/machine-disposition boundaries, offline baseline evaluation, captured inputs, authority fixes и capability registry. Из незакоммиченного Phase 4 Task 2 избирательно восстановить canonical requested-finding adapter, exact-record intake, historical replay, offline orchestration и потерянные validators. Добавить отсутствующий R6 environment-question/answer/branch workflow в существующий `internal/productb/triage`. Только после этого завершить отключение второго live runtime. Historical validators и canonical authority adapters не считаются конкурирующим live investigator.

**Tech stack:** Go 1.25, существующие `internal/productb/triage`, `internal/research`, `internal/finding`, `internal/evidencetools`, `internal/flow`, hash-bound JSON artifacts, `internal/flock`, Go testing, Python standard library и pytest.

**Spec:** `docs/dev/reports/2026-10-28-04-architecture-review-human-result.md`; Amendment R6 в `docs/dev/plans/2026-10-15-01-c02-closure-capability-plan.md:211-289`; `docs/dev/specs/governing-spec.md` §28.2–28.5; dual-product decision `docs/dev/reports/2026-10-20-06-approach-decision.md`.

**Recovery status:** IMPLEMENTATION STOPPED. Этот документ заменяет первичный план как **recovery/completion plan от текущего дерева**, а не предлагает повторную реализацию выполненных Phase 1–3. Rollback, coding и проверки сейчас не выполняются.

## Current-State Inventory

### Commit boundary

Текущая branch reference указывает на:

```text
91d9bdca9c1d04bb32014ade11c6d47e43f7d399
```

Это база **до незакоммиченного Phase 4 Task 2**, но **после** корректных Phase 1–3 и Phase 4 Task 1.

Commit evidence прочитан из worktree reflog. File evidence — из текущих исходников и implementation reports. Проверки при подготовке этого correction artifact не запускались.

### KEEP — уже реализовано, не запускать как новые задачи

| Выполненная работа | Commit evidence | Сохраняемые файлы/контракты |
|---|---|---|
| Phase 1: structured assessment и снятие proof-only запрета на мнение | `01700af` | `triage/human_assessment.go`, `types.go`, `runner.go`, `prompt.go`; `assessment.v2` |
| Support по decisive premises | `04a18fa` | `triage/support.go`, `DeriveSupport` |
| Раздельные judgment/action/support/machine disposition; optional severity | `dbb78b4` | `decision_types.go`, `composer.go`, `policy.go`; `decision-package.v3` |
| Action-first card, stability и replay | `e9de81e` | `decision_render.go`, `stability.go`, `replay.go` |
| Append-only Accept/Reject | `45348a2` | `human_decision.go`, `human-decisions/<id>.json` |
| Baseline/GT comparison перенесён offline | `9a71479` | `evaluation.go`, `cmd/izyan/triage_eval.go`, `izyan eval triage` |
| Phase 1 acceptance и review corrections | `4eee56d`, `1e44162`, `2b64a5c` | Support scope/proposition binding, semantic stability comparison, review locking/durability, copied-run replay |
| Phase 2: captured materials | `fb6b965` | `investigation_inputs.go`, captured records/fixes, `read_material`, `prompt-input.v1` |
| Product build binding | `cef4411` | `Target.Build`, `ResolveBuildTarget`, replayed target |
| Session-resolved tool surface | `d945c81` | `CheckSpec.Available`, captured-only providers, broker catalog |
| Truthful optional proposal capability; nil-premise minting removed | `e0616d2` | `ProposalCapabilities`; удалённый dead automatic kernel path не возвращать |
| Product B import/type-map correction | `bd30300` | `internal/productb/typemap.go` |
| Phase 3 authority repairs | `fb2be7a`, `90dc95b`, `7cdda90`, `1569435`, `851976e` | Non-locus auto-adoption удалён; model claims/conditions — proposals; heuristic authority и weak positive fallbacks удалены; specialized proof applicability gates |
| Phase 4 Task 1 registry/archive consolidation | `91d9bdc` | `ToolContract`, typed `PositiveEvidence`, catalog-derived definitions, `observation-archive.v2` |

Implementation evidence:

- `.superpowers/sdd/2026-10-28-04-phase1-human-result-plan/progress.md`
- `.superpowers/sdd/2026-10-28-06-phase2-investigation-inputs/progress.md`
- `.superpowers/sdd/2026-10-28-07-phase3-authority-boundaries/progress.md`
- `.superpowers/sdd/2026-10-28-08-phase4-consolidation/task-1-report.md`

`DONE` в этих ledgers означает выполненный implementation slice, а не отсутствие всех остаточных замечаний. Например, Phase 3 report отдельно оставляет paired Product A authority measurement для integration. Корректный код не откатывать из-за незавершённой последующей проверки.

### RESTORE selectively — повреждено незакоммиченным Task 2

Основание: `.superpowers/sdd/2026-10-28-08-phase4-consolidation/task-2-report.md` и review findings.

- Canonical requested-finding adapter и его acceptance coverage.
- Exact-record intake gate и связанные record/corpus identities.
- Historical `/3`, `/4`, slice2 decoding/playback/validation.
- Pure environment/branch contracts и offline replay dependencies.
- Offline controller extraction/indexing/orchestration.
- Validators retained report fields, удалённые вместе со slice2 overlay.
- Research scope/publication assertions, удалённые без переноса.

### MODIFY — полезная реализация есть, но контракт неполон

- `HumanAction` содержит одну recommendation и `ReconsiderWhen`, но не finite environment branches.
- `--record-decision` сохраняет Accept/Reject, но не typed environment answers и selected branch.
- Review требует свободный `Reason`; это не соответствует обычному сценарию «ответить и Accept/Reject».
- Blanket `ErrReplaySchemaRetired` смешивает historical playback с current admission.
- Structural retirement tests запрещают legitimate historical/authority-adapter dependencies слишком широко.
- Census CI оставлен на provisioned caller с удалённым flag и stale-report hazard.

### Remaining gaps — не считать уже реализованными

1. Текущий triage не имеет `DecisionVariable`, `EnvironmentAssertion` и prepared branch selection.
2. `ProjectRequestedFinding`/`PublishRequest` до удаления были adapter API с test callers; полноценный CLI publication path ещё не был завершён. Восстановление API и завершение CLI wiring — разные действия.
3. Historical readable JSON и `regression_guard.py` не заменяют replay.
4. Удалённый `runner.py` содержал также `parse_run`, `build_artifact_record`, `_summary`, `runs.jsonl` и `artifact-index.json`.
5. `.github/workflows/ci.yml` вызывает provisioned `run_census.py`; доступный script передаёт `research --deterministic-only` и читает существующий `report.json` даже после неуспеха команды.
6. Прошедшие tests ошибочного cutover подтверждают только проверенные ими технические свойства. Они **не доказывают сохранение исходного пользовательского контракта**, поскольку часть acceptance coverage была удалена.

## Global Constraints

- **`false-safe = 0`.**
- Human proposal, support, environment answer и Accept не меняют Product A verdict, code claims, necessity, completeness, negative verification, corpus closure или VEX.
- Сохранить правильное разделение Phase 1: judgment, proposed action, computed support и machine disposition.
- **Не откатывать `9a71479`:** live triage/replay не требуют external baseline или GT. Offline baseline migration не объясняет и не оправдывает удаление других capabilities.
- Не возвращать Phase 3 authority leaks или Phase 2 automatic nil-premise proof minting.
- Сохранить R6 human-work contract:
  - 0–2 объявленных вопроса;
  - finite allowed answers и explicit unknown branch;
  - заранее подготовленные conditional decisions;
  - максимум семь обязательных фактов/посылок первого экрана;
  - ответ → branch selection → Accept/Reject без нового model/tool/source investigation.
- `OBTAIN_EVIDENCE`, assumptions и `ReconsiderWhen` не являются эквивалентной заменой prepared environment branches.
- Превышение bounds или неполная ветвь — `NOT_DECISION_READY`, а не скрытое поручение человеку.
- Environment assertion — отдельная auditable human-owned premise. Никогда не `domain.Claim{Result: FALSE}` и не falsifier.
- Сохранить exact-record isolation и canonical `finding.Project` publication.
- Сохранить historical playback, но не upgrade старой authority.
- Frozen manifests, baseline labels и старые artifact bytes не переписывать.
- Не вводить no-op compatibility flags.
- Не удалять проверки поведения вместе с его прежним владельцем: coverage переносится.
- Восстановление только из явно определённых Task 2 hunks. Никакого repository-wide reset/restore и потери чужих изменений.
- Все команды ниже — **будущие implementation/smoke instructions**, а не выполненные сейчас проверки.

## Review Focus

| Риск | Owning task |
|---|---|
| Восстановлены названия файлов, но потерянные invariants не возвращены | Task 8 |
| Exact-record intake снова обогащается alias/feed subjects | Task 9 |
| Canonical adapter ошибочно считается вторым authority engine | Task 9 |
| Human conditional workflow подменён списком assumptions | Task 10 |
| Ответ требует нового model/tool run | Task 11 |
| Accept требует свободного технического обоснования | Task 11 |
| Historical playback приравнен к current admission | Task 12 |
| Offline readers остались без producer/indexer | Task 13 |
| CI использует stale report после failed invocation | Task 13 |
| Второй runtime удалён до переноса capabilities | Task 14 |

### Task 8: Recover the lost contract and validation closure

**Depends on:** None; только после разрешения возобновить implementation.

**Starting state:** `91d9bdc` плюс незакоммиченный Task 2. Сохранившийся deterministic research emits `/2`; request adapter и environment/branch files удалены; replay blanket-refuses `/3`/`/4`; часть retained validators удалена.

**Delta:** Избирательно вернуть capabilities и validators, не возвращая старый live CLI investigator.

**Files:**
- Restore:
  - `internal/research/requested_finding.go`
  - `internal/research/requested_finding_test.go`
  - `internal/research/{branch_evaluator,branch_evidence,decision_artifact,decision_policy,dispositions,environment,environment_questions,subject_anchor}.go`
  - соответствующие pure contract/validation tests.
- Restore historical replay closure:
  - `internal/flow/{contract,branch,policy,registry,replay,engine,broker,planner}.go`
  - их tests — как historical/pure validation coverage, не новый live route.
- Modify selected hunks:
  - `internal/research/{types,assemble,validate,replay,decision,deterministic,render}.go`
  - `internal/research/{assemble,replay,validate,schema_compat,package_usage,usage_scope,deterministic,deterministic_payload}_test.go`
  - `internal/states/scope_version_integration_test.go`.
- Keep:
  - `internal/research/attempts.go`, с одной реализацией extraction/bookkeeping.
- Create/Test:
  - `internal/research/preservation_recovery_test.go`.

**Interfaces:**
- Consumes: base `91d9bdc` definitions, current retained proof types, recorded sidecars.
- Produces:
  - restored adapter/input DTOs;
  - available historical branch/replay validators;
  - unconditional validation of retained condition, ticket, scope and proof fields.

- [ ] Step 1: Прочитать актуальный diff каждого rollback path. Whole-file restore допустим только при отсутствии unrelated/subsequent edits; иначе вернуть конкретные удалённые hunks из карты ниже.
- [ ] Step 2: Добавить `TestRetainedResearchInvariantsAfterRecovery`, проверяющий invalid condition state, agent-origin `SUPPORTED/REFUTED`, applicability-state mismatch, ticket/version refusal consistency, missing persisted artifact, foreign subject и непустую scope projection.
- [ ] Step 3: Run:
  ```bash
  go test ./internal/research -run '^TestRetainedResearchInvariantsAfterRecovery$' -count=1
  ```
  Expected **FAIL** на текущем cutover.
- [ ] Step 4: Вернуть потерянные validators независимо от старого evidence ladder. Present retained fields должны проверяться даже без slice2 marker.
- [ ] Step 5: Восстановить request/record contract definitions и historical pure dependencies. Не восстанавливать `research.RunAgent` или `RunDecisionReady` dispatch в `cmd/izyan/research.go`.
- [ ] Step 6: Не дублировать extraction из `attempts.go` в восстановленном slice2/historical коде. Вернуть отсутствующую request-composition unknown/question ledger функцию, а не только её orphan comment.
- [ ] Step 7: Вернуть persisted-input negative tests; in-memory validator test не заменяет проверку загрузчика сохранённого run.

**Smoke:**
```bash
go test ./internal/research -run '^TestRetainedResearchInvariantsAfterRecovery$' -count=1
go test ./internal/research ./cmd/izyan -run 'Test(PackageUsage|UsageScope|Ticket|ResearchProof|ScopeVersion)' -count=1
```

Expected **PASS**, без модели.

**Acceptance:** Потерянные contracts/invariants доступны для следующих migration tasks; корректные Phase 1–4Task1 изменения сохранены; второй live CLI investigator не включён.

### Task 9: Restore exact-record isolation and complete canonical research publication

**Depends on:** Task 8

**Starting state:** Adapter восстановлен как API; current CLI ещё не завершает canonical requested-finding publication. До удаления `PublishRequest` имел test/API callers — нельзя описывать эту задачу как починку прежде работавшего CLI path.

**Delta:** Сохранить exact-record capability и завершить отсутствующее CLI wiring к одной authority.

**Files:**
- Modify:
  - `internal/research/requested_finding.go`
  - `internal/research/deterministic.go`
  - `internal/research/{types,assemble,validate,decision,render}.go`
  - `cmd/izyan/research.go`
- Test:
  - `internal/research/requested_finding_test.go`
  - `internal/research/advisory_feed_test.go`
  - `cmd/izyan/research_feed_test.go`
  - Create `cmd/izyan/research_requested_finding_test.go`
  - `internal/states/scope_version_integration_test.go`.

**Interfaces:**
- Consumes:
  - `RecordCase`, `FinalizeRecordCase`, `ProjectRequestedFinding`, `PublishRequest`, `AdmitRequestComposition`;
  - canonical `finding.Assess`, `finding.Finalize`, `finding.Project`;
  - restored `LaneOptions.Corpus`, `RequestContract`, `RecordOnly`.
- Produces:
  - exact-record intake for current primary/candidate assessments;
  - new current deterministic schema `research-report/5`, without R6 live artifact requirement;
  - `request_composition` produced only through canonical projection;
  - pinned `requested-case.json` enabling publication/replay re-admission.

- [ ] Step 1: Add `TestExactRecordIntakeRejectsFeedEnrichment`, `TestResearchPublicationUsesCanonicalProjection`, `TestResearchPublicationRejectsPolicyDrift`, `TestResearchCLIEmitsCanonicalRequestedFinding`.
- [ ] Step 2: Run:
  ```bash
  go test ./internal/research ./cmd/izyan -run 'Test(ExactRecordIntake|ResearchPublication|ResearchCLIEmitsCanonical)' -count=1
  ```
  Expected **FAIL** на неполном wiring.
- [ ] Step 3: Восстановить gate: при `RequestContract`, `RecordOnly` или corpus assessment не вызывать `completeAdvisoryImports`. Discovery может номинировать отдельные records, но не переписывать subjects/ranges текущей assessment.
- [ ] Step 4: Подключить existing adapter к deterministic CLI; использовать shared corpus/record-pin input contracts, а не собственные альтернативные правила composition.
- [ ] Step 5: Persist canonical case и необходимые record/proof sidecars; вызвать fresh `finding.Project` перед publication.
- [ ] Step 6: Render outcome, failure/external distinction и requested verdict из canonical projection. Record-bound `EvidenceDecision` оставить detail, а не альтернативным CVE answer.
- [ ] Step 7: Сохранить `/4` как historical schema с прежними требованиями. Не менять её обязательный member set для нового current report.
- [ ] Step 8: Восстановить и переподключить research scope/publication assertions в scope-version integration test; Product A assertions не менять.

**Smoke:**
```bash
go test ./internal/research ./cmd/izyan -run 'Test(ExactRecordIntake|ResearchPublication|ResearchCLIEmitsCanonical|ResearchCandidateNegatives)' -count=1
```

Expected **PASS**; candidate negatives не закрывают CVE без существующего corpus/proof admission.

**Acceptance:** Exact-record isolation сохранён; research публикует одну canonical requested-finding projection. Missing Product A corpus/proof не становится prerequisite для отдельного human triage результата.

### Task 10: Complete the existing triage package with finite environment branches

**Depends on:** Task 8

**Starting state:** `decision-package.v3`, support и action-first renderer уже работают. `HumanAction` имеет `Kind`, `Instruction`, `Rationale`, `Scope`, `RecordIDs`, `DecisiveClaimIDs`, `ReconsiderWhen`; questions/answers/branches отсутствуют.

**Delta:** Добавить недостающий принятый R6 workflow поверх существующего продукта, не переписывая support/composer заново.

**Files:**
- Create:
  - `internal/productb/triage/environment_questions.go`
  - `internal/productb/triage/human_branches.go`
  - `internal/productb/triage/human_branches_test.go`
- Modify:
  - `triage/{human_assessment,types,decision_types,support,composer,prompt,runner,decision_render,stability}.go`
  - `internal/productb/registry.go`
- Test:
  - текущие assessment/prompt/support/composer/render/stability tests;
  - перенести applicable assertions из восстановленных R6 branch/question tests.

**Interfaces:**
- Consumes: existing `Assessment`, `InvestigationInputs`, captured references, `DecisionPremise`, `DeriveSupport`, current capability registry.
- Produces:
  - `assessment.v3`, `decision-package.v4`;
  - `DecisionVariable{ID, Question string; AllowedValues []string; Required bool; DerivedFrom []string}`;
  - `EnvironmentVariableProposal` — nomination без значения/authority;
  - `ConditionalActionProposal{Assignments map[string]string; Judgment LLMJudgment; Action HumanAction}`;
  - `HumanDecisionBranch{ID string; Assignments map[string]string; Judgment LLMJudgment; Action HumanAction; Premises []DecisionPremise; Support DecisionSupport; Status HumanBranchStatus; Limitations []string}`;
  - `HumanBranchStatus`: `COMPLETE`, `AWAITING_INPUT`, `CONTRADICTED`, `NOT_DECISION_READY`;
  - `HumanReviewPlan{Variables []DecisionVariable; Branches []HumanDecisionBranch; MandatoryPremiseIDs []string; Readiness string}`;
  - `BuildHumanReviewPlan(in HumanBranchInput) (HumanReviewPlan, error)`;
  - contextual action `ACCEPT_ENVIRONMENTAL_MITIGATION`.

- [ ] Step 1: Add `TestHumanBranchUniverseIsComplete`, `TestHumanBranchesDoNotShareEnvironmentPremises`, `TestEnvironmentQuestionsAreVerbatimAndBounded`, `TestHumanReviewFirstScreenBounds`.
- [ ] Step 2: Run:
  ```bash
  go test ./internal/productb/triage -run 'Test(HumanBranch|EnvironmentQuestions|HumanReviewFirstScreen)' -count=1
  ```
  Expected **FAIL**: surfaces отсутствуют.
- [ ] Step 3: Перенести действительно поддержанные R6 dimensions: recorded build variant, configured deployment perimeter, quote-bound advisory precondition и их existing validators. Frozen controls не импортировать как production authority.
- [ ] Step 4: Код независимо перечисляет finite assignments и unknown branch. Модель предлагает explanations/actions для разрешённого пространства, но не задаёт allowed values, coverage или branch status.
- [ ] Step 5: Вычислять support отдельно для каждой ветви через existing decisive-premise mechanism. Environment condition остаётся явно human-owned; branch A не заимствует premise branch B.
- [ ] Step 6: Проверять полноту conditional proposals. Отсутствующую ветвь не заполнять выдуманным решением.
- [ ] Step 7: Enforce ≤2 questions и ≤7 обязательных посылок первого экрана. Не обрезать decisive facts ради лимита. При превышении — явный `NOT_DECISION_READY` и conservative action.
- [ ] Step 8: Не спрашивать environment dimension, если независимо достаточное scoped proof уже решает действие.
- [ ] Step 9: Сохранить текущую возможность model-interpreted human `CLOSE`; не превращать её в historical code-grounded `CLOSE_NOT_AFFECTED`/`CLOSE_NO_EXPLOIT_PATH`. Environmental mitigation маркировать отдельно.
- [ ] Step 10: Мигрировать current producers/consumers на новые schema versions. Уже выпущенные triage v2/v3 runs остаются version-specific replayable, без silent upgrade.

**Smoke:**
```bash
go test ./internal/productb/triage -run 'Test(HumanBranch|EnvironmentQuestions|HumanReviewFirstScreen|EnvironmentMitigation|UnconditionalProofDoesNotAsk)' -count=1
go test ./internal/productb/triage -run 'Test(Support|Composer|DecisionMarkdown|Stability)' -count=1
```

Expected **PASS**.

**Acceptance:** Рабочий существующий human-result дополнен prepared conditional decisions. Assumptions/`OBTAIN_EVIDENCE` не выдаются за замену branch workflow.

### Task 11: Extend existing review persistence with typed answers and offline branch selection

**Depends on:** Task 10

**Starting state:** `human-decision.v1` и `--record-decision` уже существуют, hash-bound, append-only, locked и durable. Они принимают одно решение по одному package и требуют `Reason`.

**Delta:** Не переписывать writer: добавить assertion/branch binding и убрать лишнюю обязательную technical narrative.

**Files:**
- Create:
  - `triage/environment_answers.go`
  - `triage/environment_answers_test.go`
- Modify:
  - `triage/{human_decision,artifacts,replay,decision_render,audit,evaluation}.go`
  - `internal/productb/registry.go`
  - `cmd/izyan/triage.go`
- Test:
  - `human_decision_test.go`
  - `triage_cli_test.go`
  - `triage_human_result_test.go`.

**Interfaces:**
- Consumes: immutable package v4, existing locking/hash/durability functions.
- Produces:
  - `EnvironmentAssertion{ID, Variable, Value, Principal, Source, Freshness string; Timestamp time.Time; Supersedes []string}`;
  - `ApplyEnvironmentAssertions(pkg DecisionPackage, assertions []EnvironmentAssertion) (HumanReviewProjection, error)`;
  - `HumanReviewProjection{PackageHash, BranchID, ProjectionHash string; Judgment LLMJudgment; Action HumanAction; Support DecisionSupport; Status HumanBranchStatus; AssertionIDs []string}`;
  - `environment-assertions/<id>.json`;
  - `human-decision.v2` binding package hash, branch/projection hash и assertion IDs;
  - repeated CLI `--answer <variable>=<value>` alongside existing review mode.

- [ ] Step 1: Add `TestEnvironmentAnswerSelectsPreparedBranchWithoutInvestigation`, `TestAnsweredVariableIsNotReasked`, `TestUndeclaredEnvironmentAnswerRejected`, `TestEnvironmentAssertionSupersession`, `TestAcceptRejectNeedsNoTechnicalNarrative`.
- [ ] Step 2: Run:
  ```bash
  go test ./internal/productb/triage ./cmd/izyan -run 'Test(EnvironmentAnswer|AnsweredVariable|UndeclaredEnvironment|EnvironmentAssertion|AcceptRejectNeeds)' -count=1
  ```
  Expected **FAIL**: answer channel отсутствует.
- [ ] Step 3: Реализовать pure selection по declared variables/values, включая unknown. Запретить model/tool/network/source calls.
- [ ] Step 4: Записывать principal/time/source/freshness из configured review session и captured question contract. Не требовать ручного технического provenance от человека.
- [ ] Step 5: При конфликте operator answer и deterministic fact вернуть `CONTRADICTED` и conservative branch. Ответ не меняет code claim или machine disposition.
- [ ] Step 6: Сохранить package immutable. Assertions и review records append-only; supersession явная; уже действительный ответ не задаётся повторно.
- [ ] Step 7: Для новых review records сделать comment optional; системный reason code следует из Accept/Reject. Historical v1 records валидировать их прежним decoder.
- [ ] Step 8: Accept/Reject связывать с package hash, выбранной branch, projection hash и assertion IDs, а не только finding ID.
- [ ] Step 9: Replay проверяет и копирует историю verbatim, повторяет branch selection и не создаёт новый Accept/timestamp.

**Smoke:**
```bash
go test ./internal/productb/triage ./cmd/izyan -run 'Test(EnvironmentAnswer|AnsweredVariable|UndeclaredEnvironment|EnvironmentAssertion|AcceptRejectNeeds|BranchReview)' -count=1
```

Expected **PASS**. Scripted clients должны падать при любом неожиданном model/tool вызове.

**Acceptance:** Пользователь отвечает максимум на два вопроса и Accept/Reject. От него не требуется ещё одно исследование или свободное техническое обоснование. Existing authority boundaries сохраняются.

### Task 12: Recover historical playback without restoring historical authority

**Depends on:** Task 8

**Starting state:** `LoadPersistedAgentTurn` и `Validate` blanket-refuse `/3`, `/4`, slice2. New current triage replay уже работает и не заменяется этой задачей.

**Delta:** Восстановить historical playback/validation, отдельно от current saved-turn reuse и canonical proof re-admission.

**Files:**
- Create:
  - `internal/research/historical_replay.go`
  - `internal/research/historical_replay_test.go`
  - `cmd/izyan/research_history.go`
  - `cmd/izyan/research_history_test.go`
- Modify:
  - `internal/research/{replay,types,validate}.go`
  - restored historical DTO/replay helpers
  - `internal/flow/replay.go`
  - `cmd/izyan/main.go`
  - retirement/runtime-boundary tests.

**Interfaces:**
- Consumes: saved research `/1`–`/4`, slice2 markers, exact saved reports/turns, flow ledgers, pinned configuration/sidecars.
- Produces:
  - `PrepareHistoricalReplay(ctx context.Context, dir string) (HistoricalReplay, error)`;
  - `historical-replay.v1` manifest with `historical_only=true`, `current_admission=false`;
  - CLI:
    ```text
    izyan eval research-replay --run <saved-run> --out <new-directory>
    ```

- [ ] Step 1: Add `TestHistoricalDecisionArtifactPlayback`, `TestHistoricalRequestCompositionPlayback`, `TestHistoricalSlice2Playback`, `TestHistoricalReplayRejectsTamperedPins`, `TestHistoricalReplayCannotPublishCurrentAuthority`.
- [ ] Step 2: Run:
  ```bash
  go test ./internal/research ./cmd/izyan -run 'TestHistorical' -count=1
  ```
  Expected **FAIL**.
- [ ] Step 3: Historical loading проверяет schema-specific member set, artifacts, references, recorded trace/configuration. Он не требует существования live model harness.
- [ ] Step 4: Current saved-turn reuse проверяет **present retained proof/input blocks**, а не только answer pins. Current authority publication отдельно вызывает canonical admission.
- [ ] Step 5: Не использовать blanket `ErrReplaySchemaRetired` для historical playback. Сохранить typed отказ попытке использовать historical envelope как current result/proof.
- [ ] Step 6: Historical flow replay использует recorded events/observations; planner/reassessor не вызывается. Missing required pin — явная ошибка, не default reconstruction.
- [ ] Step 7: Писать wrapper и копии исходных artifacts в новый каталог. Не менять original schema IDs, judgment, bytes или timestamps.
- [ ] Step 8: Разделить прежний retirement test на historical playback success и current admission refusal. Убрать blanket import/call-name bans, ошибочно запрещающие legitimate adapters.

**Smoke:**
```bash
go test ./internal/research ./cmd/izyan -run 'Test(Historical|Replay.*Pins|Replay.*Subject|ResearchPublicationRejectsPolicyDrift)' -count=1
```

Expected **PASS**, без модели, tools, network и исходного repository checkout.

**Acceptance:** Исторические runs воспроизводимы как history/evaluation controls. Их старые safe labels не получают текущую authority.

### Task 13: Restore offline controller functions and repair the census invocation boundary

**Depends on:** Tasks 9 and 12

**Starting state:** `runner.py` удалён; metric readers сохранены. CI вызывает provisioned runner с удалённым `--deterministic-only`; доступный script читает report по существованию файла даже после nonzero exit.

**Delta:** Сохранить extraction/indexing/replay orchestration; мигрировать действующий caller и исключить stale reports.

**Files:**
- Restore/Modify:
  - `eval/decision_ready/runner.py`
  - `eval/decision_ready/test_metrics.py`
- Create:
  - `eval/decision_ready/test_runner.py`
  - `eval/decision_ready/run_census.py`
  - `eval/decision_ready/test_census.py`
- Modify:
  - `.github/workflows/ci.yml`
  - `eval/decision_ready/regression_guard.py`
  - `eval/decision_ready/README.md`
  - `eval/README.md`.

**Interfaces:**
- Consumes: existing `parse_run`, `build_artifact_record`, `_summary`, historical/current CLI paths, external census data and immutable baseline.
- Produces:
  - preserved `runs.jsonl` / `artifact-index.json` producers;
  - tracked census executable instead of unversioned provisioned code;
  - fresh per-invocation output and identity checks;
  - separate technical failure and label drift.

- [ ] Step 1: Вернуть удалённые pure-function assertions; runner-specific tests перенести в `test_runner.py`, не теряя coverage.
- [ ] Step 2: Add `test_offline_runner_rebuilds_metric_inputs`, `test_historical_replay_uses_eval_route`, `test_census_uses_current_command`, `test_census_rejects_stale_report_after_failure`, `test_census_rejects_foreign_manifest`, `test_census_preserves_baseline`.
- [ ] Step 3: Run:
  ```bash
  python3 -m pytest eval/decision_ready/test_metrics.py eval/decision_ready/test_runner.py eval/decision_ready/test_census.py -q
  ```
  Expected **FAIL**.
- [ ] Step 4: Сохранить offline extraction/indexing и deterministic/historical orchestration. Удалить только старый live R6 launcher path.
- [ ] Step 5: Current deterministic `research` вызывать без удалённого flag. Не возвращать no-op `--deterministic-only`.
- [ ] Step 6: Создавать новый output directory на каждую попытку. При nonzero exit не читать report как успешный свежий результат. Проверять report/manifest existence, matching run IDs и requested input identity.
- [ ] Step 7: CI вызывает tracked runner, а provisioned directory предоставляет только corpus/baseline/material inputs. Guard получает только результаты текущей проверенной invocation.
- [ ] Step 8: Сохранить baseline labels и существующие safety gates. Не расширять historical attributed-drift exceptions.
- [ ] Step 9: Schema adapters guard должны явно различать historical `/2`–`/4` и current `/5`. Исправить неверное утверждение, что прежний guard уже воспроизводил `/4`.
- [ ] Step 10: Повторить pytest command на fake subprocess/synthetic inputs.

**Smoke:** Та же pytest command; expected **PASS**. Private census и benchmark/model arms в этой задаче не запускаются.

**Acceptance:** Offline workflow снова имеет producers, а CI не может принять stale report. Baseline/GT остаются только evaluation inputs.

### Task 14: Finish the runtime cutover only after preservation acceptance

**Depends on:** Tasks 9–13

**Starting state:** Correct Phase 1–4Task1 code сохранён; recovery/completion gaps закрыты предыдущими задачами. Старый live CLI dispatcher уже отключён; часть исторических dependencies сохранена законно.

**Delta:** Завершить консолидацию без capability loss, согласовать документацию и downstream execution contracts.

**Files:**
- Modify:
  - `cmd/izyan/{research,runtime_boundary_test}.go`
  - `internal/research/{agent,retirement_test}.go`
  - historical/flow files только при доказанной ненужности конкретного live symbol
  - `internal/productb/{registry,typemap}.go`
  - `triage/doc.go`
  - plans `2026-10-28-05`, `-08`, `-09`
  - `docs/{architecture,cli,how-it-works}.md`
  - `docs/dev/{analysis-internals,implementation-status,gap-analysis}.md`
  - `eval/README.md`, `eval/decision_ready/README.md`
- Create/Test:
  - `cmd/izyan/human_capability_preservation_test.go`.

**Interfaces:**
- Consumes: completed preservation map.
- Produces: one live investigator, one current human/branch projection, retained canonical adapter, historical playback and offline control plane.

- [ ] Step 1: Add `TestHumanCapabilityPreservationMatrix`: unconditional action; one/two questions; unknown answer; answer not re-asked; contradiction; bounds overflow; Accept/Reject without narrative; no-model replay; exact-record isolation; canonical publication; historical `/3`/`/4`; offline indexes; failed census with stale report.
- [ ] Step 2: Run:
  ```bash
  go test ./cmd/izyan ./internal/productb/triage ./internal/research -run 'Test(HumanCapabilityPreservation|Environment|BranchReview|Historical|ResearchPublication)' -count=1
  ```
  Expected **FAIL** при любом оставшемся gap; не ослаблять matrix.
- [ ] Step 3: Удалить только старые live harness/dispatcher symbols, для которых завершена migration и нет сохраняемого historical/offline caller. Не удалять pure branch validators или authority adapters по принадлежности файлу.
- [ ] Step 4: Сохранить B1 под `eval research-b1` и frozen assets неизменными.
- [ ] Step 5: Переписать structural tests на отсутствие реального model/container launch, а не на запрет legitimate historical functions или canonical authority imports.
- [ ] Step 6: Обновить downstream supersession table ниже. Task 2 report оставить историей; отдельно отметить correction, не переписывать прошлое как успешное сохранение capabilities.
- [ ] Step 7: Повторить focused matrix и Python smoke; expected **PASS**.
- [ ] Step 8: Integration owner после всех edits выполняет один финальный набор:
  ```bash
  go vet ./...
  go test ./... -p 4
  go test -race ./internal/productb/triage ./internal/research ./cmd/izyan
  python3 -m pytest eval/decision_ready/test_metrics.py eval/decision_ready/test_runner.py eval/decision_ready/test_census.py -q
  ```
- [ ] Step 9: Выполнить существующие Product A regression/census gates с неизменными expectations и `false-safe=0`, включая ранее оставленную paired authority measurement при наличии before/after executables и corpus inputs. Отсутствующий prerequisite назвать явно; не считать этот gate выполненным по tests cutover.

**Smoke:** Focused matrix и pytest; expected **PASS**.

**Acceptance:** Консолидация закончена только после проверки сохранённых пользовательских и offline возможностей. Цели human-time R6 остаются целями измерения, а не выдуманным результатом synthetic tests.

## Selective Rollback Map

### Правило применения

Источник восстановления — `91d9bdc`, содержащий правильные completed phases.

Не выполнять весь rollback как «restore всех 46 файлов». Для каждой группы ниже применяется указанная операция. Если появились сторонние edits, восстанавливать только Task 2 deletion hunks.

### RESTORE: canonical adapter и pure capability contracts

Восстановить из `91d9bdc`:

```text
internal/research/requested_finding.go
internal/research/requested_finding_test.go

internal/research/branch_evaluator.go
internal/research/branch_evidence.go
internal/research/decision_artifact.go
internal/research/decision_policy.go
internal/research/dispositions.go
internal/research/environment.go
internal/research/environment_questions.go
internal/research/subject_anchor.go

internal/research/branch_evaluator_test.go
internal/research/branch_evidence_test.go
internal/research/decision_artifact_test.go
internal/research/decision_artifact_report_test.go
internal/research/decision_policy_test.go
internal/research/environment_questions_test.go
internal/research/subject_anchor_test.go
```

Эти исходники обеспечивают восстановление/перенос capabilities и historical validation. Их восстановление не подключает live CLI route.

### RESTORE: historical flow replay closure

Восстановить `internal/flow/` из Task 2 удаления:

```text
contract.go
branch.go
policy.go
registry.go
replay.go
engine.go
broker.go
planner.go
engine_test.go
policy_test.go
registry_test.go
replay_test.go
```

Назначение — recorded replay и pure transition/policy validation. Наличие интерфейса planner не разрешает подключить старый model driver. Удалять отдельные unused live methods впоследствии можно только после сохранения replay closure и tests.

### RESTORE HUNKS / EXTRACT: смешанные legacy files

| Path | Восстановить | Не возвращать |
|---|---|---|
| `internal/research/slice2.go` | Нужные historical derivations, scope/ticket/condition validation dependencies, request-composition ledger; tests их контрактов | Старый ladder как current triage support |
| `internal/research/flow_adapter.go` | `LoadPersistedDecisionRun`, required recorded-run DTOs, pin/ledger replay helpers | Live `RunDecisionReady` dispatch/model factory |
| `internal/research/flow_adapter_test.go` | Historical/pin/ledger coverage, перенести в historical tests | Требование доступности старого live launcher |
| `internal/research/slice2_test.go` и `evidence_level_*_test.go` | Historical schema/derivation/negative assertions | Ожидание, что current report снова emits старую ladder |
| `package_usage_{render,validate}_test.go`, `usage_scope_{render,validate}_test.go` | Retained proof/state/subject/bounds coverage и historical rendering | Автоматическое снятие invariants вместе с overlay |
| `cmd/izyan/research_decision_test.go` | Deterministic proof, persisted bindings, publication/replay assertions | Старый live model route |
| `cmd/izyan/research_decision_ready_test.go` | Human-contract, manifest/prompt-pin, historical replay assertions — перенести к текущим владельцам | Старый live R6 command |
| `eval/decision_ready/runner.py` | `parse_run`, `build_artifact_record`, `_summary`, indexes, deterministic/historical orchestration | Старый live R6 launcher |

### KEEP REMOVED: старый live model driver

Не восстанавливать как live implementation:

```text
internal/research/flow_driver.go
```

Из `flow_driver_test.go` сохранить/перенести только проверки recorded metadata, prompt/artifact pin integrity, если они нужны historical contract. Model-launch tests старого driver не являются основанием возвращать второй runtime.

Из `agent.go` не возвращать production harness launch, endpoint probing и `RunAgent` caller. Historical envelope/decoder types при необходимости извлекаются отдельно.

### MODIFY: восстановить удалённые hunks retained files

| Файлы | Recovery |
|---|---|
| `research/deterministic.go` | `Corpus`, `RequestContract`, `RecordOnly`, request identities/pins/discovery/attributions/related assessments; exact-record guard |
| `research/types.go` | Historical DTO members и request composition; current/historical schemas развести |
| `research/assemble.go` | Scope derivation, canonical request projection, historical assembly; сохранить одну реализацию unknown grouping |
| `research/decision.go` | Canonical composition-bound decision helpers и scope guards |
| `research/validate.go` | Condition-state/origin consistency, ticket/version refusal, persisted proof/subject/artifact checks, historical validators |
| `research/replay.go` | Historical playback и required present-block validation; убрать blanket historical refusal |
| `research/render.go` | Historical branch/request rendering и непустые retained scope bounds |
| Связанные изменённые research tests | Вернуть потерянную negative/persisted/history coverage, затем переподключить |
| `states/scope_version_integration_test.go` | Вернуть research projection assertions; Product A assertions оставить |
| `eval/decision_ready/test_metrics.py` | Вернуть offline runner assertions, перенести в отдельный test file при необходимости |
| `cmd/izyan/research_test.go` | Разделить historical playback success/current-admission refusal; сохранить no-model behavior |
| `cmd/izyan/research.go` | Добавить canonical current publication; старый live harness не возвращать |

### KEEP: полезные незакоммиченные Task 2 изменения

- B1 routing под `izyan eval research-b1`.
- `internal/productb/research/doc.go` с evaluation-only ролью.
- Удаление live research model dispatch и ненужных harness flags.
- `internal/research/attempts.go`, после устранения дублирующих definitions.
- Полезные no-model/runtime-boundary tests после исправления blanket bans.
- Удаление `--deterministic-only` из уже мигрированных test argv — при обязательной миграции реального CI caller.
- Сохранённые frozen configs/rubrics/manifests.

### MODIFY: документация ошибочного cutover

В:

```text
docs/architecture.md
docs/cli.md
docs/how-it-works.md
docs/dev/implementation-status.md
docs/dev/gap-analysis.md
eval/README.md
eval/decision_ready/README.md
```

убрать только утверждения о полном behavior-preserving удалении, достаточности readable JSON вместо replay и закрытии B51/B51a до migration.

Сохранить правильные описания одного live investigator, B1 eval-only и offline baseline separation.

## Downstream Supersession Map

| Документ/задача | Recovery/completion решение |
|---|---|
| Первичный Phase 1 Tasks 1–7 | Выполненная база. Не повторять. Дополнить только выявленными gaps Tasks 10–11 и historical boundary |
| Phase 2 Tasks 1–4 | KEEP. Не возвращать nil-premise proof minting; existing residual limitations не маскировать |
| Phase 3 Tasks 1–5 | KEEP. Существующие concerns/paired measurement остаются integration evidence requirements |
| Phase 4 Task 1 | KEEP полностью |
| Phase 4 Task 2 | Старый deletion brief заменён Tasks 8–14; original report остаётся историей faulty cutover, не успешного preservation |
| Phase 4 Task 3 | После recovery preservation и owner integration/corpus gates; immutable reuse не удаляет canonical adapter или fresh replay/publication admission |
| Phase 5 Tasks 1–2 | Сохраняются; consume `assessment.v3`, `decision-package.v4`, captured finite branches, `environment-assertion.v1`, bound `human-decision.v2`; no live baseline requirement |
| Phase 5 Task 3 | **Modify preserved tracked controller**, не Create; retain fresh current census/history-only replay/indexes/CI safety, score answers/unknowns/branch changes/extra human work отдельно |
| Phase 6 | Доказательные задачи сохраняются; environment answer не substitute evidence producer; human/Accept не меняют Product A authority |
| Series overview `2026-10-28-05` | Recovery gate добавлен; Task 2 report не доказательство non-regressive consolidation; broad gates и exact paired measurement остаются owner evidence |

## Dependency / Execution Order

```text
KEEP completed Phase 1–3 + Phase 4 Task 1
                       |
                     Task 8
              ┌────────┼─────────┐
            Task 9   Task 10   Task 12
              |        |         |
              |      Task 11     |
              └────────┬─────────┘
                     Task 13
                       |
                     Task 14
                       |
            Existing Phase 4 Task 3
                       |
                 Phase 5 → Phase 6
```

- Tasks 9, 10 и 12 логически независимы после recovery, но shared DTO/replay files требуют одного integration owner.
- Никакая capability deletion не предшествует replacement acceptance.
- Исторические reports о прошедших checks не переписываются; corrective acceptance фиксируется отдельно.
- Сокращение R6 возможностей не согласовано и в этом плане не предполагается. Повторный вопрос live-versus-history не требуется.
- **Execution correction (2026-10-29):** owner approved recovery Tasks 8–14. Focused preservation implementation does not claim final acceptance before integration-owner broad checks, unchanged Product A corpus/census gates and any prerequisite-bound paired measurement. Original stopped-plan wording and Task 2 report are historical context, not current execution authority.
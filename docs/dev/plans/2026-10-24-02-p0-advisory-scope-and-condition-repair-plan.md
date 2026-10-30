# P0 Advisory Scope и Condition Repair Implementation Plan

**Goal:** Устранить три механизма false-safe: распространение частного отрицания на всю CVE, безусловное добавление TLS/toolchain-условия к SSH downgrade и сохранение нерелевантного mandatory-условия после замечания Reviewer.

**Architecture:** Сохранить существующий pipeline и authoritative verifier. Разделить область запрошенного заключения и область проверенных advisory entries; сохранить детерминистические факты компонентов, но ограничить область отрицательного вывода. Генерировать TLS floor только при подтверждённой применимости к механизму. Нормализовать mandatory/supporting на границе LLM proposal. Исправлять необходимость условия через явное structured reviewer action, не переписывая истинность уже проверенного факта.

**Tech stack:** Go 1.25.0, стандартный `testing`, `httptest`, существующие `affected.GoResolver`, workflow handlers, `evaluator.VerdictEvaluator`, `review.Structural`, LLM test helpers `mockServer` и `stubBuilder`. Новые зависимости не нужны.

**Spec:** `docs/dev/reports/2026-10-24-02-wrong-cases-and-llm-first-tuning.md`, разделы 3A, 3C, 3E и 6; обязательные ограничения — `AGENTS.md` и соответствующие `docs/agent-rules/`.

## Global Constraints

### Рабочая область и доказательная база

- Исходники обнаружены в `../vuln-analyzer-shadow`. Все пути и команды ниже заданы относительно корня **этого исходного репозитория**.
- Сохранённые отчёты с указанными в задании timestamps фактически находятся в:
  - `../va-review1/bench/llm/cases/vex/kubernetes-kubernetes-e196d24-CVE-2023-44487/branch/CVE-2023-44487-1792764701/report.json`;
  - `../va-review1/bench/llm/cases/vex/containers-podman-6a65597-CVE-2023-48795/master/CVE-2023-48795-1792768581/report.json`.
- Для Kubernetes сохранён `VersionAffected=FALSE` по `x/net v0.17.0`, терминальный `NOT_AFFECTED` и `0` LLM calls.
- Для Podman сохранены mandatory `C-PLATFORM go_version=<1.18`, его VERIFIED FALSE и high-severity condition finding о несоответствии TLS floor механизму SSH Terrapin.
- Исторические отчёты, benchmark-артефакты и метрики не изменять. Регрессии строить на небольших очищенных входах, без приватных путей и без копирования многомегабайтных графов evidence.

### Семантические инварианты

1. `x/net` вне affected range остаётся истинным **частным фактом**. Не заменять его `UNKNOWN`, чтобы искусственно изменить verdict.
2. Отрицание компонента может закрыть кейс только в доказанной области заключения. Наличие одного OSV/GHSA-документа не доказывает полноту всех реализаций CVE.
3. Явно запрошенная запись `GO-*`/`GHSA-*` может сохранять отрицательное заключение **по объявленным Go entries этой записи**. Такой scope должен быть виден в отчёте и не должен описываться как доказательство отсутствия всех реализаций CVE.
4. Для CVE-запроса generic OSV-документ по умолчанию даёт `KNOWN_ONLY`, включая случай, когда `doc.ID == requested CVE`. В рамках P0 не добавлять новый механизм доказательства CVE-wide completeness, override-флаг или реестр CVE → модуль.
5. Неизвестная полнота блокирует `NOT_AFFECTED` и `NO_EXPLOIT_PATH_FOUND` по частным путям. Она не запрещает `EXPLOITABLE`, если подтверждён конкретный affected component и все необходимые условия его exploit path.
6. `MandatoryConditions` — conjunction; `SupportingFactors` в неё не входят. Не менять эту математическую семантику.
7. При демоции условия сохранять его claim, falsifier, `NegativeVerification` и evidence IDs. Исправляется необходимость условия, а не достоверность snapshot-факта.
8. `go.mod` и локальный Go не являются release toolchain. Существующие ограничения `evaluator.Platform` и affected version axis не ослаблять.
9. Не добавлять хардкод Kubernetes, Podman, Terrapin или конкретных CVE в production-код.
10. Новые поля persistent JSON — с `omitempty`; отсутствие scope в старом кейсе не означает полноту.

### Границы реализации и проверки

- В scope входят P0.1–P0.3. Не входят полноценный alternate-implementation discovery, identity verifier для всех patches, build/vendor repairs, claim/evidence entailment, расширение бюджетов и P1-тюнинг.
- Продолжение в `ResolveRootCause` не гарантирует найденный gRPC exploit path. Допустимый P0-результат при неразрешённом остатке — честный `INCONCLUSIVE`, но с устранением раннего ошибочного решения.
- Команды ниже — инструкции для будущей реализации; при подготовке плана они **не выполнялись**.
- Проверки выполняет основной интегратор. Implementer subagents не запускают build/test/lint/format одновременно с работой других агентов. RED/GREEN-команды выполняются последовательно на согласованном состоянии дерева.
- Финальные `gofmt`, `go vet ./...`, `go test ./...` выполняются интегратором после всех изменений. Бенчмарки, `izyan eval`, живые LLM-прогоны и пересчёт метрик в этот план не входят.

### Проектный шлюз

**READY для перечисленных P0-исправлений.** Существенная неизвестность закрыта консервативным контрактом: существующий intake не доказывает полноту CVE, поэтому не получает такого права по умолчанию.

Если реализация обнаружит существующий нормативный контракт, который требует противоположной семантики scope или разрешает reviewer напрямую устанавливать verdict, зафиксировать файл и противоречие и вернуть это решение на design review; не обходить его скрытой эвристикой.

## Review Focus

| Риск | Владелец проверки |
|---|---|
| Исправленный первый компонент скрывает affected/pending второй | Task 1: resolver matrix; Task 2: state/verdict matrix |
| Изменён transition, но финальный evaluator всё равно возвращает `NOT_AFFECTED` | Task 2: прямой вызов evaluator после `CheckAffected` |
| Research/decision-artifact обходит общий scope gate | Task 3: applicability, proof authority и cached projection |
| Все отрицания без разбора превращены в INC | Task 2: exact-entry negative controls; Task 7: report/export controls |
| SSH получает TLS floor из CWE, слова `crypto` или чужого patch | Task 4: mechanism applicability matrix |
| `mandatory:false` или supporting params загрязняют conjunction | Task 5: routing, ID collision и `fillParams` tests |
| Reviewer меняет факт вместо необходимости | Task 6: claim/NV/evidence сохраняются без изменений |
| Последнее нерелевантное mandatory сохраняется ради непустой модели | Task 6: sole-condition demotion → пустая модель → INC |
| Повторный review возвращает демотированное условие в mandatory | Task 6: conflict/order/idempotency tests |
| Ошибка reviewer action остаётся рядом с auto-safe | Task 6: pending condition review gate |
| JSON исправлен, но Markdown/VEX продолжают утверждать global safety | Task 7: RU/EN, OpenVEX и CycloneDX |

### Task 1: Ввести scope заключения и сохранить его через vulnerability intake и affected resolver

**Depends on:** None

**Files:**
- Create: `internal/domain/advisory_scope.go`
- Create: `internal/domain/advisory_scope_test.go`
- Modify: `internal/domain/domain.go`
- Modify: `internal/vulnerability/source.go`
- Modify: `internal/affected/resolver.go`
- Test: `internal/vulnerability/source_test.go`
- Test: `internal/vulnerability/osv_test.go`
- Test: `internal/affected/resolver_test.go`

**Interfaces:**
- Consumes:
  - `vulnerability.Source.Get(ctx, id)`;
  - `domain.Vulnerability`, `domain.AffectedResult`;
  - `affected.AffectedModuleEntries`;
  - существующие `FileSource`, `OSVSource`, `StaticSource`.
- Produces:
  - `type AdvisoryScopeKind string`:
    - `ScopeAdvisoryEntries = "ADVISORY_ENTRIES"`;
    - `ScopeCVE = "CVE"`.
  - `type AdvisoryCoverage string`:
    - `CoverageComplete = "COMPLETE"`;
    - `CoverageKnownOnly = "KNOWN_ONLY"`.
  - `AdvisoryScope` с полями `RequestedID`, `ResolvedID`, `Kind`, `Coverage`, `Basis`.
  - `Scope *AdvisoryScope` в `Vulnerability` и `AffectedResult`, JSON `scope,omitempty`.
  - `func (*AdvisoryScope) AllowsNegativeClosure() bool`: `nil`/неизвестный scope → `false`; разрешение только для явно связанного exact-entry scope с `COMPLETE`. В P0 intake не производит CVE-wide `COMPLETE`.
  - `func (AffectedResult) HasNegative() bool`: общий predicate отрицательной affected-цепочки; implementation-axis учитывается как closing negative только при установленных `PackagePresent=TRUE` и `BuildRelevant=TRUE`.
  - Unexported `bindAdvisoryScope(v *domain.Vulnerability, requestedID string)` в `source.go`.

- [ ] **Step 1:** Добавить `TestAdvisoryScopeAllowsNegativeClosure`:
  - `nil`, пустые ID, `KNOWN_ONLY`, неизвестные enum values → `false`;
  - exact `GO-*`/`GHSA-*`, одинаковые requested/resolved ID, `ADVISORY_ENTRIES/COMPLETE` → `true`;
  - CVE, сопоставленная одному GHSA, → `false`;
  - прямой CVE-документ без отдельного доказательства полноты → `false`.

- [ ] **Step 2:** Добавить intake-тесты:
  - `TestFileSourceScope`: одинаковый OSV-файл при запросе его собственного GO/GHSA ID получает exact-entry scope; при запросе CVE alias — `ScopeCVE/CoverageKnownOnly`;
  - пустой `id` использует `v.ID`, не имя файла и не case ID;
  - `TestOSVSourceScope`: HTTP alias fallback сохраняет исходный CVE как `RequestedID`, а полученный GO/GHSA — как `ResolvedID`;
  - `TestStaticSourceScopeDoesNotMutateStoredVulnerability`: два запроса к одной сохранённой записи не переписывают scope друг друга.

- [ ] **Step 3:** Выполнить RED-проверку:
  ```bash
  go test ./internal/domain ./internal/vulnerability ./internal/affected \
    -run 'Test(AdvisoryScope|FileSourceScope|OSVSourceScope|StaticSourceScope|ResolverScope|MultiModuleScope)' -count=1
  ```
  **Expected FAIL:** отсутствует новый scope-контракт либо requested/resolved scope теряется.

- [ ] **Step 4:** Реализовать binding после завершения alias enrichment, включая ранний успешный return из `OSVSource.Get`.
  - Не делать `COMPLETE` из факта `len(AffectedModules)==1`.
  - Exact-entry `COMPLETE` означает только полный набор объявленных Go entries загруженной записи, а не полноту CVE.
  - Если исходный scope уже ограничен `KNOWN_ONLY`, enrichment не повышает его автоматически.
  - В `StaticSource.Get` возвращать отдельное значение `Vulnerability` перед binding; не мутировать объект в `Vulns`.

- [ ] **Step 5:** В инициализации результата `GoResolver.Resolve` копировать `vuln.Scope`, чтобы поле сохранялось на **всех** существующих ранних return.
  Добавить `TestResolverScopePreservedOnEarlyReturns` для:
  - module absent;
  - all versions fixed;
  - module-list failure;
  - ticket version-axis block.

- [ ] **Step 6:** Добавить `TestMultiModuleScopeAggregation`, используя существующий `fakeTool`:
  - A fixed + B affected/linked → `VersionAffected=TRUE`, B остаётся selected;
  - A fixed + B pending/linked → `VersionAffected=UNKNOWN`, B остаётся pending/unresolved;
  - A fixed + B fixed → `VersionAffected=FALSE`, оба модуля checked;
  - отсутствие B в selected само по себе не доказывает fixed.
  Сохранить существующие проверки `TestMultiModuleSelectsAffectedEntry`, `TestMultiModuleNoEntryAffected`, `TestPendingModuleMixedLink`.

- [ ] **Step 7:** Повторить команду Step 3.
  **Expected PASS:** scope не теряется, а существующие version/package facts не изменены.

**Acceptance:** Любой вход имеет явно связанную область заключения либо остаётся fail-closed. CVE alias не превращается в exact-entry completeness. Resolver сохраняет точные факты и scope на всех выходах.

### Task 2: Применить scope gate в `CheckAffected` и authoritative verdict

**Depends on:** Task 1

**Files:**
- Modify: `internal/states/states.go`
- Modify: `internal/evaluator/verdict.go`
- Test: `internal/states/states_test.go`
- Test: `internal/evaluator/verdict_test.go`
- Test: `internal/states/perimeter_eval_test.go`

**Interfaces:**
- Consumes:
  - `AffectedResult.HasNegative`;
  - `AdvisoryScope.AllowsNegativeClosure`;
  - `states.CheckAffected.Run`;
  - `evaluator.VerdictEvaluator.Evaluate`.
- Produces:
  - scoped early-exit policy;
  - одинаковую защиту для proposed verdict, zero-trust и cluster-perimeter verdict;
  - `INCONCLUSIVE` с указанием checked component и непокрытого scope вместо global safety.

- [ ] **Step 1:** Добавить `TestCheckAffectedPartialScopeContinues`, используя существующий `multiResolver`:
  - input: requested CVE, resolved single x/net entry, `VersionAffected=FALSE`, `ResolvedVersion=v0.17.0`, scope `KNOWN_ONLY`;
  - assert `Next == StateResolveRootCause`;
  - assert `c.Affected.VersionAffected == FALSE`;
  - assert version, evidence IDs и checked modules сохранены;
  - assert limitation явно называет неполноту области CVE.
  Добавить вариант с дополнительным модулем в product graph, отсутствующим в advisory: он не считается fixed и не получает version fact x/net.

- [ ] **Step 2:** Добавить `TestVerdictPartialScopeNegativeMatrix` по всем closing axes:
  - module/version/package/build/implementation FALSE при partial или отсутствующем scope → `INCONCLUSIVE`;
  - те же доказательства при exact-entry scope → прежний `NOT_AFFECTED`;
  - для implementation FALSE сохранить prerequisite-проверки package/build.

- [ ] **Step 3:** Добавить:
  - `TestVerdictPartialScopeBlocksNepf`: `VersionAffected=TRUE`, VERIFIED falsifier по modeled component, неполный CVE scope → не NEPF, а INC;
  - `TestVerdictPartialScopeKeepsProvenPositive`: подтверждённая affected version и все mandatory TRUE → `EXPLOITABLE`;
  - `TestVerdictFixedPartialScopeCannotBecomePositive`: частный affected negative плюс искусственные all-TRUE claims → INC, не EXP;
  - `TestCheckAffectedExactEntryNegativeCloses`: exact-entry scope → `StateEvaluateVerdict` и `NOT_AFFECTED`.

- [ ] **Step 4:** Выполнить RED-проверку:
  ```bash
  go test ./internal/states ./internal/evaluator \
    -run 'Test(CheckAffected.*Scope|Verdict.*Scope|VerdictPartialScope|VerdictNotAffected|VerdictImplementationAxis)' -count=1
  ```
  **Expected FAIL:** текущий `CheckAffected` завершает partial case, а evaluator безусловно принимает raw FALSE.

- [ ] **Step 5:** Изменить `CheckAffected.Run`:
  - после `ImplementationAxis` сохранить исходный scope, если callback вернул результат без него; callback не должен повышать completeness;
  - использовать общий affected-negative predicate;
  - early exit разрешать только при `AllowsNegativeClosure`;
  - иначе записывать limitation и продолжать в `ResolveRootCause`;
  - не сужать весь case до первого исправленного компонента и не стирать `AffectedModules`.

- [ ] **Step 6:** Изменить `VerdictEvaluator.Evaluate`:
  - до существующего negative switch возвращать INC, если имеется affected negative, но scope не разрешает закрытие;
  - перед выдачей NEPF проверять право отрицательного заключения по scope;
  - сохранять существующие проверки falsifier, VERIFIED, unresolved subjects и pending version;
  - не вводить scope completeness как дополнительное требование для доказанного конкретного positive path.

- [ ] **Step 7:** Мигрировать affected fixtures в evaluator/state tests:
  - exact-entry controls задают scope явно;
  - legacy/unscoped negative fixtures ожидают INC;
  - существующий `TestVerdictNoAffectedResultNotGated` заменить проверкой, что отсутствие scope не разрешает model-only NEPF.
  Не добавлять глобальный test helper, который автоматически объявляет любой fixture полным.

- [ ] **Step 8:** Добавить `TestEvaluateVerdictPartialScopeBothProfiles`:
  - zero-trust и cluster-perimeter остаются INC;
  - `TrustedPeer`/perimeter rewrite не закрывает непокрытый CVE scope.
  Повторить команду Step 4 с добавлением имени этого теста — **Expected PASS**.

**Acceptance:** Ни transition, ни повторное вычисление proposed/final verdict не распространяют частный negative на всю CVE. Exact-entry negatives сохраняются, подтверждённый positive не запрещён.

### Task 3: Закрыть обход scope gate через research и decision-artifact

**Depends on:** Tasks 1, 2

**Files:**
- Modify: `internal/research/decision.go`
- Modify: `internal/research/branch_evaluator.go`
- Modify: `internal/research/flow_adapter.go`
- Test: `internal/research/decision_test.go`
- Test: `internal/research/branch_evaluator_test.go`
- Test: `internal/research/flow_adapter_test.go`
- Test: `internal/research/branch_evidence_test.go`
- Test: `internal/research/slice2_test.go`

**Interfaces:**
- Consumes:
  - `LaneResult.Affected.Scope`;
  - `laneApplicabilityDecision`;
  - `VerifyDecision`;
  - `branchBuilder.evaluate`;
  - `decisionForArtifactWithAuthorityAudit`.
- Produces:
  - отсутствие authoritative `CLOSE_*` по неполному target scope;
  - сохранение per-module FALSE как факта, а не его удаление из evidence.

- [ ] **Step 1:** Добавить `TestApplicabilityPartialScopeDoesNotClose`:
  - raw version FALSE и partial CVE scope → `VerdictInconclusive`;
  - `Coverage != "COMPLETE"`;
  - reason содержит scoped applicability gap;
  - evidence refs продолжают разрешаться в исходные affected observations.

- [ ] **Step 2:** Добавить `TestVerifyDecisionPartialScopeBlocksNegativeAuthorities`:
  - проверить proposal route, declared-symbol authority и config-proof route;
  - при `KNOWN_ONLY` ни один не закрывает непокрытые реализации CVE;
  - exact-entry counterparts сохраняют существующее поведение.

- [ ] **Step 3:** Добавить:
  - `TestArtifactPartialScopeCannotProposeGlobalClose`: локальное version-out-of-range rule может оставаться established, но artifact не получает global `CLOSE_NOT_AFFECTED`/`CLOSE_NO_EXPLOIT_PATH`;
  - `TestArtifactProjectionPartialScopeRejectsCachedClose`: cached `lane.SymbolProof.Decision` не обходит gate;
  - `TestApplicabilityRuleFactsRemainPerModuleUnderPartialScope`: x/net сохраняет свой `version-in-range=false`, но такой факт не создаётся для grpc.

- [ ] **Step 4:** Выполнить RED-проверку:
  ```bash
  go test ./internal/research \
    -run 'Test(Applicability.*Scope|VerifyDecisionPartialScope|Artifact.*Scope|ApplicabilityRuleFactsRemainPerModule)' -count=1
  ```
  **Expected FAIL:** `laneApplicabilityDecision` сейчас назначает `COMPLETE` при любом raw negative; artifact может выбрать close branch.

- [ ] **Step 5:** Исправить `laneApplicabilityDecision`:
  - пользоваться результатом authoritative evaluator;
  - если результат INC из-за scope, не присваивать ему `Coverage=COMPLETE`;
  - возвращать scoped unresolved decision, чтобы дальнейшая proposal-ветка не превратила тот же частный факт в safe.

- [ ] **Step 6:** В `VerifyDecision` проверять допустимость отрицательного scope до negative authority/proposal routes.
  В `branchBuilder.evaluate` при неполном scope:
  - не выбирать `closeEstablished`;
  - добавлять объяснение в unknown branch;
  - сохранять результаты per-component rules и их fact refs.
  В `decisionForArtifactWithAuthorityAudit` проверять scope до использования cached proof decision.

- [ ] **Step 7:** Мигрировать regression controls:
  - существующий recorded applicability fixture без нового scope остаётся legacy evidence и сам не получает completeness;
  - переименовать `TestArtifactRecordedVersionFalseClosesNotAffected` в negative legacy-control;
  - добавить отдельный `TestArtifactExactEntryVersionFalseClosesNotAffected`, получающий scope через новый intake;
  - не переписывать исторический JSON, его hashes или прошлые expected metrics.
  Повторить команду Step 4 — **Expected PASS**.

**Acceptance:** Частный negative остаётся доступным как evidence, но не закрывает CVE через research, artifact rule selection, authority projection или cached decision.

### Task 4: Убрать общий TLS floor из crypto downgrade и ввести mechanism-bound applicability

**Depends on:** None

**Files:**
- Create: `internal/exploit/applicability.go`
- Create: `internal/exploit/applicability_test.go`
- Modify: `internal/exploit/patterns.go`
- Modify: `internal/exploit/builder.go`
- Modify: `internal/review/review.go`
- Test: `internal/exploit/patterns_test.go`
- Test: `internal/exploit/classify_test.go`
- Test: `internal/review/review_test.go`

**Interfaces:**
- Consumes:
  - `ClassCryptoDowngrade`;
  - `Pattern.Instantiate`;
  - `Builder.BuildWithHints`;
  - существующий `extractToolchainBound`.
- Produces:
  - `func TLSFloorBound(v domain.Vulnerability, rc *domain.RootCauseModel) string`;
  - `func ValidateConditionApplicability(v domain.Vulnerability, rc *domain.RootCauseModel, cond domain.Condition) string`, где `""` означает отсутствие обнаруженного mismatch.
  - Эти функции проверяют конкретное P0-правило TLS floor; не являются новым универсальным semantic verifier.

- [ ] **Step 1:** Добавить `TestTLSFloorBound` с таблицей:
  - TLS MinVersion/floor + явное `Go < 1.18` → `<1.18`;
  - TLS floor + `Go toolchain prior to 1.21` → `<1.21`;
  - SSH prefix truncation/sequence-number manipulation → `""`;
  - CWE-326/327/757 без TLS floor declaration → `""`;
  - слова `crypto`, `cipher`, `downgrade` без TLS-specific requirement → `""`;
  - TLS упомянут только как посторонний контекст при SSH sinks → `""`;
  - TLS floor без заявленной Go boundary → `""`, а не выдуманное `<1.18`.

- [ ] **Step 2:** Добавить `TestPatternCryptoDowngradeSSHHasNoTLSFloor`:
  - SSH root causes, включая `golang.org/x/crypto/ssh`;
  - forced crypto-downgrade classification либо соответствующий patch signal;
  - ни mandatory, ни supporting не содержат автоматически созданного legacy `go_version <1.18`;
  - reach/input/locus conditions не исчезают.

- [ ] **Step 3:** Добавить `TestValidateConditionApplicability`:
  - legacy TLS platform requirement против SSH → rejection reason;
  - переименование ID `C-PLATFORM` в `C-OTHER` не обходит проверку;
  - то же правило для `ConditionRuntime` с `go_version`;
  - явный TLS floor с совпадающей boundary принимается;
  - настоящие `goos`/`goarch` conditions не отвергаются только из-за класса downgrade.

- [ ] **Step 4:** Выполнить RED-проверку:
  ```bash
  go test ./internal/exploit ./internal/review \
    -run 'Test(TLSFloorBound|ValidateConditionApplicability|Pattern.*CryptoDowngrade|Structural.*Downgrade|Classify_CryptoDowngrade)' -count=1
  ```
  **Expected FAIL:** общий registry безусловно создаёт TLS floor для SSH.

- [ ] **Step 5:** Исправить deterministic builder:
  - удалить mandatory `C-PLATFORM <1.18` из общего `ClassCryptoDowngrade` registry entry;
  - сделать описание `C-REACH` протокольно нейтральным;
  - добавлять `C-PLATFORM` в `BuildWithHints` только при непустом `TLSFloorBound`;
  - использовать извлечённую boundary без hardcoded fallback;
  - перенести/переиспользовать существующий parser boundary, не создавать второй parser;
  - не считать CWE или чужой fix diff доказательством TLS requirement.

- [ ] **Step 6:** Согласовать `review.Structural` с условной необходимостью:
  - общий downgrade больше не требует отсутствующий `C-PLATFORM`;
  - для подтверждённого TLS floor проверка ожидает соответствующее условие;
  - `TestStructuralGenericDowngradeDoesNotRequireTLSFloor` → нет high finding о missing platform;
  - `TestStructuralTLSFloorRequiresDeclaredCondition` → отсутствие действительно необходимого floor обнаруживается.

- [ ] **Step 7:** Сохранить существующие controls:
  - `TestPattern_CryptoDowngrade`;
  - `TestPattern_CryptoDowngrade_ExtractedBound`;
  - `TestPlatformEvaluate_ReleaseGoVersion` из evaluator.
  Повторить команду Step 4 — **Expected PASS**.

**Acceptance:** Ни SSH downgrade, ни generic crypto classification не получают TLS floor автоматически. Реально заявленный TLS/toolchain requirement сохраняется с правильной boundary; platform evaluator не ослаблен.

### Task 5: Изолировать optional LLM conditions и запретить mechanism-mismatched augmentation

**Depends on:** Task 4

**Files:**
- Modify: `internal/llm/exploit.go`
- Create: `internal/llm/exploit_test.go`
- Test: `internal/llm/llm_test.go`

**Interfaces:**
- Consumes:
  - `exploit.ValidateConditionApplicability`;
  - `ExploitModelBuilder.Build`;
  - `validateConditions`, `mergeConditions`, `fillParams`, `proposedParam`;
  - существующие `mockServer`, `stubBuilder`.
- Produces:
  - локальный wire DTO с `Mandatory *bool`, отличающий отсутствие поля от explicit `false`;
  - нормализованные mandatory/supporting slices с согласованными `Condition.Mandatory`;
  - validation обеих proposal buckets.

- [ ] **Step 1:** Добавить `TestExploitModelBuilderMandatoryRouting`:
  - omitted `mandatory` в `mandatory_conditions` → mandatory `true`;
  - explicit `mandatory:true` → mandatory `true`;
  - explicit `mandatory:false` в `mandatory_conditions` → только supporting;
  - `supporting_conditions` всегда остаются nonblocking, даже если proposal попытался выставить `mandatory:true`;
  - optional-only augmentation не удаляет baseline mandatory и не отвергается только из-за отсутствия новых mandatory.

- [ ] **Step 2:** Добавить `TestExploitModelBuilderConditionIDCollisions`:
  - optional proposal с ID baseline mandatory не демотирует baseline;
  - proposal с ID baseline supporting не повышает его через обычный merge;
  - один ID не присутствует одновременно в двух slices;
  - конфликт отражён limitation, без скрытого изменения необходимости.

- [ ] **Step 3:** Добавить:
  - `TestExploitModelBuilderRejectsSSHPlatformFloor`;
  - `TestExploitModelBuilderValidatesSupportingSubjects`;
  - `TestExploitModelBuilderValidatesSingularSubject`;
  - `TestExploitModelBuilderStrictRejectsMechanismMismatch`.
  Assert: invalid augmentation не добавляет TLS floor в SSH; обычный режим возвращает корректный deterministic baseline с limitation, strict mode — `nil` и `strict-llm:` reason.

- [ ] **Step 4:** Добавить `TestFillParamsUsesOnlyAdmittedMandatory`:
  - optional condition не заполняет mandatory params;
  - rejected TLS condition не заполняет params другого predicate;
  - proposal с другим ID не служит произвольным fallback;
  - accepted same-ID/same-kind/same-subject proposal заполняет пустой param;
  - непустой deterministic param не перезаписывается.

- [ ] **Step 5:** Выполнить RED-проверку:
  ```bash
  go test ./internal/llm \
    -run 'Test(ExploitModelBuilder|FillParams|StrictLLMExploit)' -count=1
  ```
  **Expected FAIL:** текущий merge допускает `mandatory:false` в mandatory slice; supporting не валидируется; params ищутся среди посторонних proposal conditions.

- [ ] **Step 6:** В `ExploitModelBuilder.Build` выполнить последовательность:
  1. decode с различением omitted/false;
  2. structural validation ID/kind и обеих форм subjects;
  3. mechanism applicability validation;
  4. normalization и routing;
  5. межbucket ID collision handling;
  6. merge и param fill только из admitted mandatory.
  
  Обновить `exploitSystem`: bucket semantics, explicit optional flag и запрет TLS/toolchain requirement без соответствующего механизма. Не менять глобальный `domain.Condition.Mandatory` на pointer: tri-state нужен только wire parser.

- [ ] **Step 7:** Удалить устаревший cross-ID fallback из `proposedParam`; не оставлять параллельный «старый merge».
  Повторить команду Step 5 — **Expected PASS**.

**Acceptance:** Explicit optional ни непосредственно, ни через ID collision, ни через `fillParams` не становится blocking necessity. LLM не может вернуть удалённый TLS floor в SSH-модель другим ID.

### Task 6: Реализовать явную демоцию нерелевантного условия в Reviewer/RepairAnalysis

**Depends on:** Tasks 1, 2, 4, 5  
Зависимости на Tasks 1–2 также исключают одновременные правки общих `domain.go`, `states.go` и `verdict.go`.

**Files:**
- Modify: `internal/domain/domain.go`
- Modify: `internal/llm/review.go`
- Modify: `internal/states/states.go`
- Modify: `internal/evaluator/verdict.go`
- Create: `internal/llm/review_test.go`
- Test: `internal/states/states_test.go`
- Test: `internal/evaluator/verdict_test.go`
- Test: `internal/llm/llm_test.go`

**Interfaces:**
- Consumes:
  - `domain.ReviewFinding`;
  - `states.RepairAnalysis.Run`;
  - `findCondition`, `findClaim`;
  - `exploit.ValidateConditionApplicability`;
  - существующий `Review → RepairAnalysis → Review` loop.
- Produces:
  - `type ReviewAction string`;
  - `ReviewActionPromote = "promote"`, `ReviewActionDemote = "demote"`;
  - `Action ReviewAction` в `ReviewFinding`, JSON `action,omitempty`;
  - `PendingConditionReviews []ConditionID` в `ExploitModel`, JSON `pending_condition_reviews,omitempty`;
  - deterministic application явных condition actions без установки verdict ревьюером.

- [ ] **Step 1:** Добавить `TestLLMReviewerConditionActions`:
  - parser сохраняет `target_type=condition`, `target_id`, `action=demote`, `severity=high`;
  - unknown/missing action не превращается в `promote`;
  - prompt содержит точный контракт `promote|demote`;
  - `reviewPayload` содержит mandatory и supporting conditions с `mandatory`, `params`, `subjects`, а также pending condition reviews.
  Старые JSON без `action` продолжают читаться, но не получают скрытую mutation-семантику.

- [ ] **Step 2:** Добавить `TestRepairDemotesIrrelevantMandatoryCondition`:
  - mandatory: `C-REACH`, `C-INPUT`, нерелевантный `C-PLATFORM`;
  - `C-PLATFORM` имеет VERIFIED FALSE;
  - finding: high/condition/C-PLATFORM/action=demote;
  - после repair:
    - `C-PLATFORM` отсутствует в mandatory;
    - ровно один раз присутствует в supporting;
    - `Mandatory == false`;
    - claim result, falsifier, NV status и evidence IDs **не изменены**;
    - limitation содержит condition ID, review ID и причину;
    - переход — `StateReview`;
    - пересчитанный verdict не использует `C-PLATFORM` как основание NEPF.

- [ ] **Step 3:** Добавить edge tests:
  - `TestRepairDemotesSoleMandatoryCondition`: последнее нерелевантное условие тоже демотируется; пустая модель → INC, не прежний false-safe;
  - `TestRepairConditionActionsAreIdempotent`: повторная демоция не дублирует supporting;
  - `TestRepairConditionActionConflictDemoteWins`: promote/demote одного ID дают одинаковый результат при обоих порядках findings;
  - `TestRepairDoesNotRepromotePreviouslyDemotedCondition`: в bounded loop без нового evidence condition не возвращается в conjunction;
  - `TestRepairConditionWrongTargetOrMediumSeverity`: conditions/claims не мутируют;
  - `TestRepairConditionActionlessMandatoryBlocksClosure`: high finding к существующему mandatory без поддерживаемого action оставляет pending review; verdict — INC, а не safe с caveat.

- [ ] **Step 4:** Выполнить RED-проверку:
  ```bash
  go test ./internal/llm ./internal/states ./internal/evaluator \
    -run 'Test(LLMReviewerCondition|Repair.*Condition|RepairDemotes|ReviewRepairPromotes|RepairVerifiedFalseArtifactGate|VerdictPendingCondition)' -count=1
  ```
  **Expected FAIL:** mandatory condition не демотируется; action отсутствует; actionless high condition finding не блокирует stale safe.

- [ ] **Step 5:** Реализовать condition-action branch в `RepairAnalysis.Run`:
  - применять mutation только к high finding и явному action;
  - предварительно разрешать конфликты по ID; `demote` имеет приоритет независимо от порядка;
  - demote физически переносит condition в supporting и сбрасывает `Mandatory`;
  - не использовать `citesConcreteArtifact` как проверку необходимости: этот gate остаётся для изменения **claim value**;
  - не менять и не удалять claim/NV history;
  - ранее применённую демоцию определять по structured review history, не по поиску слов в limitation;
  - explicit promote сохранять только для существующего supporting condition, не противоречащего applicability и предшествующей демоции;
  - actionless high finding к существующему mandatory записывать в `PendingConditionReviews`; успешный явный repair снимает соответствующий pending ID.

- [ ] **Step 6:** В `VerdictEvaluator.Evaluate`, после независимых affected-chain negatives и до conjunction, возвращать INC при непустом `PendingConditionReviews`.
  Это не позволяет review-budget exhaustion сохранить NEPF/EXP рядом с неразрешённой критикой модели.

- [ ] **Step 7:** Сохранить bounded workflow:
  - demotion → `StateReview`, где proposed verdict вычисляется заново;
  - promotion mandatory FALSE без NV → `StateNegativeCheck`, затем обычный review;
  - repair не выставляет `c.Verdict`;
  - лимит `MaxReviewIterations` не увеличивается.
  Обновить существующий `TestReviewRepairPromotesConditionToMandatory`, добавив explicit `action=promote`.
  Сохранить `TestRepairVerifiedFalseArtifactGate`: обычная semantic-критика claim по-прежнему не переписывает VERIFIED FALSE.

- [ ] **Step 8:** Добавить `TestReviewRepairConditionLoopConverges` и `TestVerdictPendingConditionReviewsBlockClosure`; повторить команду Step 4 — **Expected PASS**.

**Acceptance:** Reviewer может убрать ошибочную necessity из conjunction, не оспаривая проверенный snapshot-факт. Неподдержанный high condition repair не теряется при исчерпании бюджета. Пустая после демоции модель остаётся INC, а не сохраняет ложное safe.

### Task 7: Сквозные регрессии, отчётность и документация

**Depends on:** Tasks 1–6

**Files:**
- Create: `internal/states/p0_safety_test.go`
- Modify: `internal/report/report.go`
- Test: `internal/report/report_test.go`
- Test: `internal/report/openvex_test.go`
- Test: `internal/report/cyclonedx_test.go`
- Modify: `docs/dev/analysis-internals.md`
- Modify: `docs/dev/gap-analysis.md`
- Modify: `docs/cli.md`
- Modify: `eval/README.md`

**Interfaces:**
- Consumes:
  - scope/action contracts Tasks 1–6;
  - существующие `runEngine`, `engineDeps`, `multiResolver`;
  - `report.Write`, `report.Markdown`, OpenVEX и CycloneDX projections.
- Produces:
  - hermetic regressions, воспроизводящие первый ошибочный scope/model decision;
  - согласованные JSON, RU/EN и VEX-представления;
  - документацию изменённого поведения без заявлений о неизмеренном recall.

- [ ] **Step 1:** Добавить `TestP0PartialAdvisoryReachesRootCause`:
  - requested CVE, частный fixed component, альтернативный component в product/module input;
  - recording root-cause resolver подтверждает, что он был вызван;
  - final partial case не получает NA/NEPF;
  - version fact исправленного компонента не потерян;
  - тест не требует сети, Kubernetes checkout или живого LLM.

- [ ] **Step 2:** Добавить `TestP0SSHDowngradeCannotCloseOnTLSFloor`:
  - deterministic builder и LLM-augmented builder;
  - SSH root causes;
  - `MinimumGoVersion=1.20`, затем отдельный вариант `ReleaseGoVersion=1.20`;
  - ни один вариант не закрывается через автоматически созданный TLS floor;
  - explicit optional VERIFIED FALSE не становится основанием NEPF.

- [ ] **Step 3:** Добавить `TestP0ReviewerRemovesLegacyTLSBlocker`:
  - вручную восстановить ошибочную legacy-модель с mandatory `C-PLATFORM`;
  - провести Review/Repair/final evaluation;
  - после демоции проверить отсутствие этого ID в `Verdict.ConditionIDs`;
  - история platform claim и negative verification сохранена;
  - оставшиеся UNKNOWN дают INC; контроль с подтверждёнными оставшимися TRUE не сохраняет прежний NEPF.

- [ ] **Step 4:** Добавить `TestReportScopeAndConditionRepair`:
  - `report.json` сохраняет requested/resolved scope, action, supporting membership и NV history;
  - RU/EN различают «компонент fixed» и «CVE scope не закрыт»;
  - condition repair отображается как изменение mandatory/supporting, а не как опровержение факта версии;
  - partial case экспортируется как OpenVEX `under_investigation`;
  - CycloneDX не получает безопасное состояние из частного version FALSE;
  - exact-entry negative control сохраняет корректный negative export.
  
  Проверить также ветки `report.go`, формирующие текст напрямую из `Affected.VersionAffected`: они не должны описывать весь CVE как исправленный независимо от final verdict.

- [ ] **Step 5:** Выполнить RED-проверку:
  ```bash
  go test ./internal/states ./internal/report \
    -run 'Test(P0|ReportScopeAndConditionRepair)' -count=1
  ```
  **Expected FAIL:** отсутствует нужное сквозное поведение либо Markdown/export ещё распространяет component fact на весь target.

- [ ] **Step 6:** Исправить report rendering и обновить документацию:
  - `analysis-internals.md`, CHECK_AFFECTED/REPAIR_ANALYSIS/Exploit model: scope gate, conditional TLS floor, explicit actions, сохранение claim history;
  - `cli.md`, `--vuln`/`--vuln-file`: отличие CVE-wide запроса от exact declared-entry assessment;
  - `eval/README.md`, разделы safety/toolchain: новые targeted regression guarantees; **не добавлять новые benchmark numbers**;
  - `gap-analysis.md`: уточнить устаревшую запись о безусловном mandatory `C-PLATFORM`; отметить устранённые механизмы в B38/B15, не закрывая оставшиеся discovery/identity/entailment задачи и весь B38 целиком.
  Не менять governing analysis report задним числом.

- [ ] **Step 7:** Повторить focused-команду Step 5 — **Expected PASS**.

- [ ] **Step 8:** Основному интегратору, после завершения всех задач:
  1. выполнить `gofmt -w` только для изменённых Go-файлов из Tasks 1–7;
  2. выполнить:
     ```bash
     go vet ./...
     go test ./...
     ```
  3. зафиксировать фактические результаты проверок; не писать «проверено», если команда не выполнялась;
  4. не запускать benchmark/eval и не объявлять восстановленный recall на основании unit tests.

**Acceptance:** Регрессии показывают изменение именно ошибочного раннего решения, condition admission и repair. Все пользовательские представления согласованы с новым scope. Исторические метрики не переписаны; P0 safety fix не выдаётся за доказанное восстановление полноты detection.

## Dependency / Execution Order

```text
Task 1 → Task 2 → Task 3
                    \
Task 4 → Task 5 ─────→ Task 6 → Task 7
```

Точнее:

- Tasks **1** и **4** независимы и могут исследоваться/реализовываться параллельно.
- Task **2** — после Task 1.
- Task **3** — после Tasks 1–2.
- Task **5** — после Task 4.
- Task **6** — после Tasks 1, 2, 4, 5; общий владелец интеграции `domain.go`, `states.go`, `verdict.go`.
- Task **3** может выполняться параллельно с Tasks 5–6: его production-файлы находятся в `internal/research`.
- Task **7** — только после всех предыдущих задач.
- Все проверки — последовательно основным интегратором; финальные repository-wide проверки выполняются после полного cutover.

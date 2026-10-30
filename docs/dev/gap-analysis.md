# Gap analysis: спеки vs реализация

Сопоставление [`specs/governing-spec.md`](specs/governing-spec.md), [`specs/analyzer-agent-spec.md`](specs/analyzer-agent-spec.md),
[`goals-scope.md`](../goals-scope.md), [`history/features/mvp-implementation-plan.md`](history/features/mvp-implementation-plan.md), [`decisions/architecture-decisions.md`](decisions/architecture-decisions.md)
с кодом по состоянию на HEAD. Содержит только пробелы и бэклог.

## 1. Открытые пробелы (спека↔код)

Что реализовано — [`analysis-internals.md`](analysis-internals.md) и
[`implementation-status.md`](implementation-status.md); здесь только
пробелы. Механика подробностей — в internals; actionable-работа — в §2.

| Область | Пробел | Статус |
|---|---|---|
| Exploit model | Паттернов 4 семейства; PATH_TRAVERSAL/INJECTION/SSRF/AUTH_BYPASS/XXE/REDOS/RACE/DESERIALIZATION — на generic-модели; keyword-классификация score-эвристика (limitation) | → B9 |
| Condition kinds | `AUTHENTICATION_CONDITION` по дизайну не FALSE (per-route/gateway/deployment проверки вне скана) — только TRUE при покрытии wiring | → B7 |
| Data origins | `EXTERNAL_AUTHENTICATED` различён для outbound, inbound — deployment-hint не per-route доказательство → B7; детекция DB-драйверов по pkg path — эвристика; reflect/pointer-записи в поля невидимы скану → B11 | → B7, B11 |
| Transformations | Семантика трансформов не моделируется: opaque call → UNKNOWN (честно, но закрывает claim'ы) | limitation, не бэклог |
| Config-gated reachability & Mesh ingress (B6) | Разрешение адресов сетевых слушателей из полей структур и пакетных переменных; учет периметра Service Mesh/Istio (AuthorizationPolicy, RequestAuthentication, ClusterIP); отсечение мертвого кода при отключенных флагах (FalsifierConfigGatedOff) и conditional-reachability | закрыто |
| Reviewer | Целевой condition repair закрыт: explicit `demote` снимает нерелевантное mandatory-условие без переписывания claim/NV history, а action-less критика блокирует closure (`PendingConditionReviews`). Открыто: детекция «patch misinterpretation» и «scope mismatch» из §21 — Structural их не выводит | → B15 |
| Proof validation | Machine proposals о необходимости условия/полноте локусов не имеют отдельного проверяемого proof gate; B30 остаётся expert-basis веткой | → B32 |
| Контекстная критичность и триаж (B33) | Детерминированный движок triage assessment (internal/risk) сопоставляет базовый CVSS 10.0 с сетевой экспозицией (0.0.0.0 vs 127.0.0.1 vs none), аутентификацией и графом сборки, назначая приоритеты P0..P3 / DISMISSED с SLA и структурированным обоснованием переоценки | закрыто |
| Defect semantics: omitted vs defective check | Проверочное имя и живой sibling-пайплайн больше не задают семантику дефекта. Билдер разрешает один типизированный контракт из advisory/fix-доказательств (`DEFECTIVE_CHECK` / `OMITTED_CHECK` / `UNRESOLVED`) и строит условия из него; `OMITTED_CHECK` привязан к omission-site на конвейере, `DEFECTIVE_CHECK` — к обязательному вызову проверки. Любой deadness-негатив (main evaluator, research, Product B, replay/publication) требует допущенной invocation-necessity premise; sibling-live как семантическое вето удалён. `UNRESOLVED` завершается `CODE/ROOT_CAUSE_UNRESOLVED`, а не отрицательным выводом. GO-2020-0017 — `DEFECTIVE_CHECK`; историческая missing-call трактовка (`VerifyAudience` на конвейере `MapClaims.Valid`) была ошибкой модели. | закрыто (2026-10-26) |
| Parsers & config | Compile-time константный payload (`FalsifierConstantOrGeneratedInput`) изолирован от рефлексии целевых структур в парсерах (`yaml`, `protojson`); чтение локальных конфигураций (`os.ReadFile`) подтверждается как доверенная среда (`FalsifierTrustedInfrastructure`); `eval` оптимизирован (параллелизация `-j`, `--case`, исключение дублирования govulncheck) | закрыто |
| Release checkout | Автоматическое разрешение тегов/веток релизов из тикетов и параметров (`--checkout-release`, `--release` / `--git-ref`) и безопасный изолированный анализ в git worktree без мутации рабочей копии разработчика | закрыто |
| Dep-internal opaque dispatch | Статическое разрешение функциональных полей и method values в struct-field/package-var/local колбэках (`funcFields`, `packageVars`, `funcEdges`, `resolveMethodValue`) в `moduleEdges` и reachability-анализе; разрешение внутренней цепочки диспетчеризации фильтров и транспорта gRPC xDS (`real-service-xds` -> EXPLOITABLE, baseline corpus 100% resolved, 0 inconclusive) | закрыто |
| Reflect & reachability precision | Субъектно-ориентированная непрозрачность в `ModuleInternalReach` (проверка совместимости сигнатур/интерфейсов) + проверка инстанцирования типов ресиверов при обработке маркеров `reflect_method` в `negative.go`; разрешение `ghsa-465g-fh3v-9jw4` в `NO_EXPLOIT_PATH_FOUND` на live-корпусе (дефект D4 закрыт) | закрыто |
| Snapshot/toolchain platform conditions | Определение версии Go из бинаря, тикета/LLM и локального окружения; эксплойт-паттерн CRYPTO_DOWNGRADE с **условным** C-PLATFORM: floor добавляется только при объявленной advisory TLS minimum-version boundary и не-SSH механизме (SSH Terrapin floor не получает), а release-toolchain факт не подменяется go.mod-минимумом или локальным Go; разрешение ghsa-33mj-cw25-m34h в NO_EXPLOIT_PATH_FOUND (дефект D3 закрыт) | закрыто |
| Семантика отрицательного доказательства: provenance сборки и исход прогона инструмента | Отрицание о сборке можно было получить из измерения хоста анализатора или из незавершённого прогона: case-level флаг покрытия не различал «нет в БД / суженный scope / инструмент упал», частичный `go list` служил инвентарём отсутствия, а `C-LOCUS` с linked-пакетом и пустыми трейсами закрывался как недостижимость | закрыто (2026-10-25): два независимых гейта — scoped `ProductTarget` (precedence `artifact-build-info > release-metadata > operator-declared > host-default`; частичные флаги не повышаются; обычный `--binary` даёт digest-bound target) и завершённое измерение с покрытием; покрытие перенесено из кейса в типизированную запись прогона (`completed_with_results`/`completed_empty`/`failed`/`not_run`); `failed`/`not_run` — positive-only; один build-контекст резолвится до загрузки и связан с индексом (`ErrBuildContextMismatch`); гейты применяются у producers, в `Verifier.VerifyFalse`, при допуске вердикта (включая persisted `VERIFIED`), в scan-prefilter и экспортах. Независимые позитивы и library-admission (`DESERIALIZATION` + CWE-502) не изменены: Podman `CVE-2024-37298` остаётся прежней ложной тревогой (module-chain позитив), Kubernetes `CVE-2022-41717` — таймаут/неполное измерение, Cilium `CVE-2026-35469` без target-входов — `INCONCLUSIVE` (калибровка: [`reports/2026-10-25-evidence-target-provenance-calibration.md`](reports/2026-10-25-evidence-target-provenance-calibration.md)) |
| Двухконтурная оценка угроз (Dual-Track Perimeter) и внешние манифесты (Helm/K8s/GitOps) (B34) | Сканер ScanDeployWithOptions с поддержкой внешних репозиториев и архивов (.tgz, .zip) с Zip Slip защитой; классификатор ClassifyPerimeter; двухконтурная оценка (zero_trust vs cluster_perimeter) с автовыбором целевого вердикта; матрица сетевых периметров в отчётах | closed (2026-10-05) |
| Атрибуция deploy-фактов продукту и строгое разделение ground_basis (B35) | Привязка манифестов по owner (имя k8s-ресурса/compose-сервиса/Helm-чарта) к модулю/бинарю; чужие манифесты игнорируются, неатрибутированная внешняя маршрутизация ветирует cluster; разделение ground_basis (declared-trust vs auto-perimeter vs config-origin) в VEX и отчётах; гейт неполной модели при операторском утверждении доверия | closed (2026-10-05) |
| Subpackage absence как детерминистическое доказательство | `RootCause.Absent`: кандидат, чей пакет отсутствует в валидном `go list -deps` evidence (EV-AFFECTED-PACKAGES), — доказательство нелинкованности дефектного кода, а не model failure; раньше source lookup miss уходил в Alternatives/Unverified → AMBIGUOUS → аварийный INCONCLUSIVE. Presence-split в reachability/input evaluator'ах: all-absent subjects → FALSE + falsifier `package-absent` (negative verification по build-graph без source index), mixed → оценка только по present, absent — в limitations; missing/corrupt package-list → без вывода об отсутствии. `ExploitModel.AbsentSubjects` (⊆ UnresolvedSubjects): absent-субъекты блокируют EXPLOITABLE (модель прунирована), но не считаются «unmodeled» для declared-trust демоции кластерного профиля | закрыто |
| Subpackage absence: идентичность субъекта (2026-10-28, re-land) | `RootCause.Absent` требует не только отсутствия пакета в допущенном `go list -deps`, но и утвердительного допущенного основания идентичности субъекта: декларация записи, повторно допущенный own-record operation binding, genuine operator input, пере-выведенный exact-preimage маршрут или checker-created persisted content proof. Coordinate binding, origin label, saved `absent` и пустой/подменённый набор субъектов не являются основанием | закрыто: identity gate + re-landed persisted proof contract; без основания кейс остаётся `FAILED / CODE / ROOT_CAUSE_UNRESOLVED / ROOT_CAUSE` |
| Протокольная роль (Protocol Role: Server vs Client) | Типизация стороны дефекта (`ProtocolRoleServer`, `ProtocolRoleClient`, `ProtocolRoleSymmetric`) в `ExploitModel` и эвалюаторе `ServerTransportInput`; опровержение условий с фальсификатором `protocol-role-mismatch` при использовании чисто клиентской библиотеки для серверной уязвимости (или наоборот) | closed (2026-10-06) |
| Доверенная конфигурация исходящих вызовов (Config-Origin Outbound Grounding) | Связывание доказательств провенанса исходящих адресов (`ScopeConfigured` / `ScopeStatic`) с основанием `GroundBasis = domain.BasisConfigOrigin` для `FalsifierTrustedInfrastructure` в кластерном периметре | closed (2026-10-06) |
| Анализ SemVer-совместимости обновления (SemVer Drop-In vs Breaking Upgrade) | Определение совместимости целевой версии фикса (`UpgradeDropIn` vs `UpgradeMajorBump` через `semver.Major`) с выводом структурированных флагов и рекомендаций по обновлению без нарушения контрактов | closed (2026-10-06) |
| Область вывода для библиотек (`library-api`) | Продукт без принадлежащего ему `package main` не может установить, как нижестоящее приложение распорядится публичным API: прежняя модель либо требовала потребительского допущения, либо оставляла доказанный путь `INCONCLUSIVE` | closed (2026-10-25): `ProductShape` (владение модулями + census, без owned `main`) и строгий witness «публичный формальный параметр → sink»; узкий конъюнктивный допуск (`DESERIALIZATION` + CWE-502 + точный arg + `ATTACKER_CONTROL`); ортогональные `exploitability_scope: library-api` / `control_basis: library-public-api` с обязательным ограничением; отрицательные гейты и `KNOWN_ONLY` не изменены; Podman/Kubernetes остаются вне механизма. Калибровка: `internal/states/library_scope_e2e_test.go` (библиотека + три потребителя), реальный testify (GHSA `COMPLETE`, CVE `KNOWN_ONLY`) |

### Закрыто планом definitive-verdict (2026-10-26)

Пункты ниже больше не являются пробелами и удалены из перечня; они закрыты
кодом и тестами, а не переформулированы:

- terminal `INCONCLUSIVE` для tool failure / исчерпанного бюджета / неоднозначного
  root cause / пропущенного измерения — заменён тремя исходами
  (`DECIDED` / `EXTERNAL_DEPENDENCY` / `FAILED`), см. governing-spec §28.
- CVE-wide negative closure — разрешён только через объявленный, digest-pinned
  завершённый corpus с дословной границей (Addendum A); без него — `FAILED /
  UNSUPPORTED_NEGATIVE_SCOPE`.
- discovery related-записей и направленная publisher/CNA-атрибуция CVE — отдельные
  propositions, без alias-обогащения и без наследования фактов.
- rooted transport-input и source/fix-bound Rapid Reset trigger witness с
  `transport-peer` scope; локальность больше не выбирает trusted profile.
- один авторитетный requested-finding projection для JSON/Markdown/CLI/scan/eval/
  tracker/justification/remediation/research/OpenVEX/CycloneDX.

**Открытый остаток (capability, не политика):** `goanalysis` transport proof
требует статического пути от `package main` до `Serve`. Реальные CLI-продукты
запускают обработчик через регистрацию команды (`cobra.RunE`), поэтому корневой
путь kubelet (`cmd/kubelet/kubelet.go:main → app.NewKubeletCommand().RunE`) не
замыкается и живой кейс честно получает `FAILED / REACHABILITY_PROOF_INCOMPLETE`.
Калибровка: [`reports/2026-10-26-definitive-verdict-calibration.md`](reports/2026-10-26-definitive-verdict-calibration.md).

### Закрыто планом human-result Phase 1 (2026-10-28)

Закрыты контрактные пункты, которые больше не являются пробелами:

- proof-only запрет на содержательное модельное мнение — модель формулирует
  `judgment` и `proposed_action`, а proof требуется только для
  `PROVED`/машинного reduction;
- отсутствие человеческого результата при неизвестной severity или
  отсутствующей внешней baseline — пакет и карточка доставляются, baseline
  остаётся отсутствующей, внешнее сравнение вынесено в offline evaluation;
- отсутствие способа сохранить Accept/Reject — append-only
  `human-decision.v2` с привязкой package/branch/projection/assertion IDs; comment optional;
- смешение judgment/action/support/machine disposition — четыре
  структурные оси `decision-package.v4` из `assessment.v3`;
- live-сравнение с GT/baseline — вынесено в `izyan eval triage`; live и
  replay не требуют контроля.

Остаются открытыми (не закрываются этой фазой): входы и build/target
matrix (Phase 2), LLM→authority leaks и case-shaped authority (Phase 3),
дедупликация/unit contracts (Phase 4). Офлайн-инструментарий полосы измерения Product B
(Phase 5 Tasks 1–3: blinded input preparation, run provenance/usage accounting,
и независимый скоринг по трем осям без исполнения бенчмарка) реализован; реальный
прогон бенчмарка и человеческого исследования не проводился. Никакой измеренный
прирост качества, готовности или latency этой фазой не заявляется.

### Phase 6 Task 1: admitted package inventory (2026-10-29)

`package-inventory {with_tests}` exposes the successful, strictly decoded
`go list -deps [-test] -json ./...` stream under one effective build. The
payload retains full stdout with SHA-256/reference, `PackageListRun`, package
identities and scope; replay rechecks bytes and build identity rather than
trusting `Complete=true`. Import-closure/code-absence and Product B material
consumers share the canonical edge-closed decoder. Failed/truncated/error-bearing,
duplicate, dangling and orphan graphs cannot ground absence; absence records
name the inventory digest. Oversized inventory/absence payloads use the existing
bounded sidecar envelope instead of losing authoritative stream bytes.

Observed local Go-tool smoke: `scopetestprod` enumerated 64 packages / 104396
raw bytes and produced COMPLETE absence with the same inventory digest.
Independent `inventoryreplace` uses nested local replacements, including a
test-only module: product listing enumerated 30 packages / 42318 bytes;
test-inclusive listing enumerated 127 / 225832 bytes. Paired retained inventories
replayed successfully into a SUPPORTS test-only fact; a foreign build was refused.
With `brokenload`, the package list remained complete but typed loading failed;
the complete list did not repair the source/load gap. Missing source likewise
refuses closure completeness. Existing vendor-only closure regressions passed;
vendor derivations were not upgraded to arbitrary Go-build completeness.

Review hardening: every session cache entry point probes final build identity
before admission. Actual MCP calls in dependency/module/usage-first order followed
by inventory, absence, snapshot and a repeated dependency/module/usage call all
remained OK/COMPLETE. Current code-absence coverage is version `5`: archive
extraction retains the shared closure report and validates its complete raw
stream, run, effective build/scope hash and snapshot at each admission point.
Version `4`/inventory-free historical payloads are not upgraded to current proofs.
Test-only consumers rederive the distinction from both digest/run/build-bound
inventories against independently probed `MaterialSet.PackageBuild`; serialized
`TestOnly=true`, missing streams, partial graphs or foreign contexts cannot support
the fact. Module graph/source completeness remains independent.

This closes the reusable build-package-inventory surface only. Source census,
module-graph completeness, whole-upstream completeness and other build contexts
remain separate obligations. The Phase 5 benchmark/model arms were not executed;
no quality, readiness or latency improvement is claimed.

### Phase 6 Task 2: inventory-bound bounded unreachability (2026-10-29)

The existing bounded kernel now captures the canonical product inventory and
effective build with its exact module/symbol subjects. Source declarations,
entrypoints, module-entry/module-reach enumeration, dependency calls, dispatch,
dynamic markers, gated references and opaque/unbounded surfaces remain separate
closure gates. Neither an inventory DTO nor `Complete=true` repairs an open gate.
Locus verification, research admission/rule facts and Product B consume the full
captured record; persisted Product B coverage retains full observation payloads,
independently measured build and the admitted deadness contract. Certificates and
decision admission recheck these bytes and exact locus coverage without source.
Omitted-check deadness cannot refute an omission: only the admitted omission-site
premise may do so. Product B still never automatically mints a proof from deadness.
The main verdict and report/export boundary uses
`goanalysis.ValidateVerifiedNegative(NegativeAdmissionInput, claim, condition)`.
It keeps candidate source-scan prerequisites separate, but admits current locus
negatives only from an NV-cited full kernel payload matching the independent build
and exact explicit condition subjects, plus the admitted model deadness premise.
Summary-only historical VERIFIED records stay historical; they cannot publish a
current no-exploit-path result. This validator was relocated from `domain` to
reuse the one kernel/inventory predicate without an import cycle or second decoder.


Independent offline smoke `unreachinventory` uses a local replacement with two
subjects: `Dead` closes COMPLETE, while `Dead` plus the directly invoked `Live`
stays PARTIAL. Actual MCP/kernel capture retained 42206 inventory bytes and a
79875-byte observation; full-payload replay accepted the closed control and
rejected missing/foreign/truncated inventory and open closure gates. These are
functional offline checks, not advisory-wide safety or whole-upstream coverage.

### Phase 6 Task 3: configuration writer observations (2026-10-29)

`Index.ConfigWriters(ctx, Type.Field)` and the richer `field_assignments`
payload retain declaration-bound storage IDs, direct field reads and actual
call argument/receiver consumption, literal/constant/default writes, copies,
pointer aliases, address-taking, runtime channel names and open writer/escape
blockers. A copied-from default never inherits the copied-to object's consumer.
Build/source hashes and the canonical raw inventory/run are retained; failed or
unavailable inventory stays open without discarding positive measured sites.
Environment/flag/file/decoder/reflection calls are observations, not effective
values. Scope-only runtime readers are explicitly separate from object-bound
events; file-to-decoder propagation is not inferred. Unknown reflection,
deserialization, callbacks, external writes and unsupported identity stay open.
Call consumers use canonical call-parenthesis coordinates, usable by existing
argument tracing even across multiline callees. Empty/keyed-omission bool
initializers record zero defaults only for the queried named struct type;
tuple-result constructors do not invent zero values. Range field/object writes
record unresolved writer events/blockers, and implicit address capture by a
pointer-receiver method value is an object-bound escape blocker.
Parenthesized and ordinary direct method calls use the same normalized typed
callee/receiver binding, retaining receiver mutation blockers without inventing
method-value capture.

The two independent offline fixtures exercise scalar bool defaults/constants
and copied defaults with external overrides. Real strict MCP observations were
PARTIAL: 3 objects / 2 assignments / 41163 inventory bytes, and 4 objects /
3 assignments / 8 runtime-channel sites / 112608 inventory bytes. Oversized
writer payloads use the existing digest/size-bound sidecar route with bounded
display; missing/tampered sidecars refuse rehydration. These observations grant
no safety authority; the separate Task 4 necessary-use certificate below is not
inferred from their assignment lists or blocker summaries.

### Phase 6 Task 4: captured necessary boolean configuration (2026-10-29)

An existing admitted mandatory `CHECK_TRIGGER` boolean argument can now earn
`SAFE_CONFIG_ASSIGNMENT`. This is not an arbitrary `config_flag` route: exact
captured advisory bytes, the current record pin, the shared mechanism grammar,
the typed formal signature and mandatory condition must establish necessity.
One shared checker reconstructs all direct consumers and rejects non-call,
callback/interface, alias/address, pointer-receiver and unresolved writer paths.
Local nonpointer named structs support keyed bool constants/defaults, direct
constant field writes and ordered same-function value copies. Every consumed
effective value must oppose the admitted trigger literal; an unsafe consumed
alternative is CONTRADICTED, while missing/unresolved scope is INSUFFICIENT_SCOPE.

Full certificates retain snapshot-relative source/module bytes, the canonical
non-test inventory reference and the existing `t1` manifest anchored to the
snapshot's independently acquired `Product.ContentHash`. Native and external
source snapshots acquire this hash before analysis. Captured module declarations
reconstruct package ownership; repinned inventory metadata cannot rename it.
Replay uses only captured `go/parser`/`go/types` inputs, never ambient source,
module cache, host imports or fabricated type stubs. Verdict, requested-finding
and report publication use the same explicit-context gate and retain refused
historical verification records. No `Complete` or safe-assignment summary admits.

Two real builder/inventory/collector/verifier fixtures close: a direct audience
argument and two issuer calls through an in-tree local replacement and ordered
copy. Both serialized cases replay through verdict, requested finding and report
publication after the source tree is renamed away. Unsafe second writes/objects,
dependency-internal callers, missing payload, altered digest, semantic metadata,
source/manifest and repinned module-ownership controls are exercised offline.

The supported application envelope has all nonstandard source in the anchored
tree, no explicit standard imports, native code or build/coordinate directives,
and no external library roots or generic declarations. The conservative source census
requires every non-test Go-source directory in that tree to be captured; ignored
variants, underscore-bearing alternative filenames, external/cache replacements,
unsupported control flow and alias shapes remain UNKNOWN. Implicit standard
runtime inventory nodes are a language-runtime boundary, not application callers.
Vendored source, when within this envelope, is snapshot identity only—not an
independent upstream-source anchor. Arbitrary safe `config_flag`, zero defaults
and safe file keys now stay UNKNOWN; forged historical `ZERO_VALUE_CONFIG` and
`SAFE_CONFIG_KEY` cannot publish a negative. No Task 5 or benchmark/model arm.

### Phase 6 Task 5: independent captures and contextual admission (2026-10-29)

The local manifest route supplies independent archive candidates and optional
complete tree carriers to the existing checker. Product-authenticated exact h1
checksums, per-locator artifact/base associations and direct-versioned external
owner grounds replace submitted source-map authority. Each locator starts from
its own base; none is implicitly a patch series. Captured premises persist in
the `/3` proof input bundle and authoritative replay requires current case context.
Tree-only VCS identity, versionless/local-only external anchors, unavailable
checksums, unsupported hunk forms, transitive/MVS-ambiguous selection and unsupported
operations remain explicit obligations. Configuration semantics are unchanged.
No model or benchmark arm is part of this work.

### Специализированные проверки применяются только после applicability

Транспортное доказательство и proof-фикса — специализированные возможности, а
не значения по умолчанию. Диспетчеризация идёт через
`Index.TransportProofRequestFor` (исходный код затронутого модуля обязан
содержать цикл чтения peer-кадров с ветками admission/reset) и
`fixbinding.FixApplicability` (в захваченном материале должна разрешаться хотя
бы одна поддерживаемая security-операция). Отказ — наблюдение
(`EvidenceGraph.Limitations`), а не блокирующий gap: номинированная моделью
роль, параметры условий и проза advisoria ничего не доказывают, и отказ не
мешает независимому human-расследованию. Потерянные из-за этого positives
измеряются офлайн: `izyan eval compare --before ... --after ... --out ...`
сопоставляет прогоны по identity кейса/входа/сборки и отказывается сравнивать
несопоставимые наборы.

## 2. Открытый бэклог (приоритетный, с done-критериями)

Бэклог упорядочен по принципу «какой UNKNOWN закрывает» — приоритет
получает работа, уменьшающая число неопределённых claims. Закрытые
пункты здесь не хранятся: история изменений — в `git log`, планах
[`history/features/`](history/features/) и роадмапах [`roadmaps/`](roadmaps/), текущая механика — в
[`analysis-internals.md`](analysis-internals.md). Закрытие пункта =
удаление строки из бэклога в том же коммите, что закрывает работу.

Критерий MVP: модуль даёт больше `govulncheck` и выдаёт доказательно
обоснованные вердикты. Приоритет P0 блокирует критерий.

### P1 — e2e-качество

| # | Пункт | Зачем | Done-критерий |
|---|-------|-------|----------------|
| B26 | Явный контракт полноты sink set и доказательство nonpayload-входов (остаток) | `AffectedSymbols` остаётся `KNOWN_ONLY`; отсутствие найденного пути от ingress item не доказывает его нерелевантность при внешнем вводе | Константный ingress для `real-protojson-const` доказан и закрыт в NEPF через изоляцию константного payload и нулепараметрических методов парсера. Остаток: persisted advisory-scoped completeness artifact с vulnerability/module/version/mandatory-condition binding и evidence IDs для случаев с внешним/недоказанным вводом; регрессионные контрпримеры и live corpus false-safe=0 |
| B29 | Независимая доказательная база дополнительной пользы (остаток — живая разметка) | Cleared-rate и совпадение с собственной разметкой не доказывают преимущество над govulncheck | [Спека](specs/added-value-validation-spec.md) реализована: cleared раскладывается по уровню экспертизы (`signal_cleared_auto/expert`) и классу доказательства (`cleared_deeper/echo/affectedness` — echo-фальсификаторы, воспроизводящие контракт govulncheck, не считаются новым доказательством); `--audit-dir` пишет per-case audit packet с grounding falsifier/evidence IDs/рецептом ручной проверки; границы false-safe=0 зафиксированы в eval/README §4a; протокол слепой разметки — [independent-review-protocol.md](independent-review-protocol.md). Внешний референс: `eval/gen_reviewed_corpus.py` генерирует corpus из человеческих triage-решений (приватный экспорт и конфиг маппинга не коммитятся, схема — `eval/reviewed-map.example.json`): кейс пинится к компонентному release-ref (`ref` + `git archive`-материализация) и к версии Go из `go.mod` на ref, а не к локальному toolchain; expect — безопасное множество, `EXPLOITABLE` считается расхождением (eval/README §5.3). Остаток: полный прогон reviewed-корпуса и разбор расхождений, слепая разметка вторым аннотатором, adversarial-корпус сверх boundary-контролей testdata/locuslib |
| B32 | Независимая валидация necessity/completeness и применения основания | Проверка отсутствия пакета не доказывает правильность выбранного L; существующий evidence ID и согласие LLM не подтверждают proposition | [Спека §9](specs/llm-cve-analysis-spec.md), [роадмап Tasks 7–9](roadmaps/llm-cve-analysis-roadmap.md): immutable proof input, binding/scope/rule checks и replay; unsupported necessity остаётся OPEN; автономное сужение модели только после отдельного capability gate без NonLocusBasis; XDS/rename/incomplete-series/second-mechanism controls; автономный срез 2026-10-15 (Tasks 2–6, [отчёт](reports/2026-10-14-03-autonomous-evidence-slice.md)): контракты typed proposal, bounded verification, advisory-wide coverage, trace-integrity и no-auto-close реализованы и покрыты фикстурами; real-case capability gate не пройден — все сохранённые ответы C01–C04 предшествуют `verification_plan`, ни один реальный verification trace не дошёл до `VerifyDecision`; закрытие только после живого C02 turn с валидным планом и generic closed product-closure proof, дающего independently verified negative; до gate нет замены действующей экспертной границы B30 |
| B27 | LLM-assisted локальное основание отклонения (исследование) | Проверить дополнительную ценность поверх govulncheck без расширения production-анализатора; [спецификация](specs/llm-dismissal-research-spec.md), [роадмап](roadmaps/llm-dismissal-research-roadmap.md) | Четыре jose2go-контроля (`[]byte`, `string`, callback, deployment-dependent key), source audit necessity/coverage, воспроизводимые тесты и свежий govulncheck baseline; deterministic/LLM результаты либо явно NOT_RUN; досье с итогом «checker / эксперт / гипотеза опровергнута», без подмены ручного audit машинным VERIFIED и без изменения прежних expect |
| B30 | Exploit model: defect-locus / mode-gate mandatory-условия | Реализован контракт отрицательного доказательства (spec §8): `C-LOCUS` условие с subjects=ровно множеству дефектных локусов L; falsifiers: `locus-package-absent` (все пакеты L вне `go list -deps` графа EV-PACKAGE-LIST) и `locus-function-unreached` (пакеты в сборке, но функции дефектного локуса доказанно не вызываются продуктом или зависимостями, а динамические маркеры чисты); negative verification — перепроверка absence по build-graph evidence и глубокая проверка достижимости функций дефектного локуса с проверкой инкапсуляции (`internal/` пакетов); NEPF с `UnresolvedSubjects` допустим только когда все unresolved ∈ L. В `ingressScan` реализована изоляция рефлексии декодеров: reflective value operations по целевой структуре (out) не создают блокирующих UnknownCall для константного входного payload (in). **Замыкание necessity — консервативное:** L = advisory-declared set минус записанные экспертные решения `NonLocusBasis` (символ+основание+authority, persisted в модели и отчёте); автоматическое исключение из L запрещено — текстовое несовпадение fix/body-скана трактуется как «соответствие не установлено», не как чистое тело (review-контрпример: переименование `mdata`→`headers` давало ложный VERIFIED NEPF — закрыто). Machine anchors (guarded-site / enabler-candidate / fix-changed / not-fix-changed) — аннотации для эксперта, не исключения; модуль порождает `ProposedNonLocus` — draft-исключения с записанным наблюдением, не участвующие в вердикте до экспертного подтверждения через `non_locus` (через `--non-locus-basis` или флаг `--accept-locus-proposals`); отчёт печатает блок «Машинная оценка» — предлагаемая оценка (МОЖНО ОТКЛОНИТЬ / ПОСЛЕ ПОДТВЕРЖДЕНИЯ / ТРЕБУЕТСЯ ПРОВЕРКА (УСЛОВНО)), per-symbol статус пакетов и требуемые экспертные решения (включая override guarded-site флага) + допущения вне машинной проверки (полнота declared set, истинность basis, build-контекст); эксперт отвечает на advisory-level вопрос без аудита кода продукта; решение для символа вне declared set игнорируется с limitation. Операнды из тестовых файлов и стандартные переменные ошибок (`err`) фильтруются. Отсутствие fix-diff (fetch-ошибка, advisory без фикса) не снимает `C-LOCUS` — L = declared set − basis сохраняется, теряются только аннотации/proposals (flake TLS-timeout на PR9365 молча снимал гейт и игнорировал basis — закрыто). Falsifier дополнительно требует покрытия build-вариантов: продуктовые файлы, исключённые записанным build-контекстом (//go:build, GOOS/GOARCH, cgo), но импортирующие пакет локуса, переводят verification в INSUFFICIENT_SCOPE → UNKNOWN (контроль `gated-scope`). Итоговый раздел отчёта и вывод CLI `analyze` формируют готовое для трекера задач обоснование на русском языке (Tracker-ready rationale) с полным контекстом проверки, подтверждением версии, фактами о сборке и остаточными рисками. Нейтральный пул corpus-real: `real-service-plain-6443` (без basis → EXPLOITABLE: declared символ в трейсе → C-LOCUS TRUE), `real-service-plain-6443x` (с basis → NEPF), `real-service-xds-6443` (mode-on → EXPLOITABLE), `real-service-wrap-6443` (factory → EXPLOITABLE), `real-service-pkg-6443` (pkg в графе, но функция не вызывается → NEPF через `locus-function-unreached`), `real-yaml-const`, `real-yaml3-const`, `real-protojson-const` (константный payload → NEPF), `real-yaml-file` (trusted infrastructure config → NEPF). Boundary-контроли на testdata/locuslib: неполная fix series (непропатченный сайт остаётся в L → falsifier не покрывает → INCONCLUSIVE), rename (текстовое несовпадение не снимает обязательство), два независимых дефекта (partial package coverage → UNKNOWN), upstream-only fix (сайт не в diff → остаётся в L → INCONCLUSIVE). Открыто: сайт вне advisory declared set контракту невидим; корректность экспертных исключений — вне машины (verification фиксирует их наличие в limitations); regex-парсинг hunk'ов охватывает `len(x)==0`/`x==nil`; второй независимый advisory для переносимости не найден |
| B38 | Внешняя валидация: VEX-Bench adapter и baseline | Baseline A выполнен ([отчёт](specs/shadow-analyzer-agent-spec.md), [результат](../../eval/baselines/vexbench/external-baseline-1.md)). Собственный корпус (38 кейсов) не был независимым доказательством. | Adapter + оркестратор (`eval/vexbench_baseline.py`) + `izyan eval vex-bench` реализованы; 28/28 снапшотов VEX-Bench (pin `80cddeac`) скачаны/immutable, прогон 30 кейсов, safety-aware + compatibility метрики, failure taxonomy 23/23, provenance. **Baseline зафиксирован: false_safe=1, Safe Clear Rate 10/23, recall 2/7, INCONCLUSIVE 40 %, completion 28/30.** Остаток: generic-фиксы по taxonomy (advisory-scope grpc, build-graph на darwin для linux-only/cgo, panика ingressScan — исправлена) и последующий regression-прогон. P0-механизм advisory-scope для k8s-44487 закрыт **структурно**: `RecordExtent`/`RecordInventory` (перепись исходного `affected[]` до фильтрации и слияния) и единый `AllowsNegativeClosure` на всех поверхностях закрытия; projected-запись (`GO_PROJECTION`) → `INCONCLUSIVE`, report/OpenVEX/CycloneDX не выдают CVE-wide negative. Это **не** доказывает затронутость gRPC и **не** заменяет внешнюю валидацию: **B38 остаётся открытым** — discovery/identity/entailment по неразрешённым реализациям и regression-прогон не выполнены, а unit-регрессии не объявляют восстановленный recall. Спека §49: набор теперь external regression benchmark. |
| B39 | Release toolchain UNKNOWN: `go.mod` не является версией продукта | Ядро закрыто: `affected.toolchainVersion` и `evaluator.productGoVersion` больше не подставляют `go.mod`/локальный Go — без `ReleaseGoVersion` stdlib-запись pending (`VersionAffected=UNKNOWN`), `go_version`-claim → UNKNOWN; `VerdictEvaluator` держит кейс INCONCLUSIVE при неразрешённой applicability (ни EXPLOITABLE, ни NEPF по фальсификатору). Подтверждено: `real-http2-server` → INCONCLUSIVE «version applicability is undecidable» вместо false-safe NOT_AFFECTED. | Полный прогон корпусов с обновлённым expect (`real-http2-server` → INCONCLUSIVE, обновлён) и сверка `false-safe=0` — этап финальной валидации (Task 2) |
| B40 | Независимая проверка отрицательных выводов (structured evidence contract) | Task 4/5/6: `VerifyDecision` + `research-report/2` реализованы и покрыты тестами (advisory coverage, trace integrity, argument binding, digest validation). В живом прогоне C09 (Qwen3.6-35B, 2026-10-15) модель автономно доказала неприменимость moby/moby (`false_positive`), но опустила `verification_plan` → fail-closed `INCONCLUSIVE`. Разрыв перешёл в форматное принуждение плана (B49) | [Отчёт C09](reports/2026-10-15-01-c09-live-demonstration.md) |
| B53 | Symbol-unreachability negative capability | Exact advisory-declared symbols may be dismissed only by a complete, advisory-wide, digest-bound static proof; partial declarations, dynamic/interface/gated/opaque paths and positive linkage remain blocking | **Implemented offline in R6 и подключено в детерминистическом лейне:** лейн сам диспатчит bounded symbol-unreachability proof (при module-present=TRUE, version-affected=TRUE и точных symbol-субъектах) через strict session и проецирует через авторитетный `VerifyDecision` без агента и без decision artifact; полный audit-bound proof → `CLOSE_NO_EXPLOIT_PATH`, любой limitation/ошибка/таймаут → `INCONCLUSIVE` с именованной причиной; `NOT_AFFECTED` этот маршрут не выдаёт. Universal runtime reachability остаётся недоказанной. |
| B54 | Release artifact channel | Source checkout versions and `go.mod` minimums do not identify the shipped release toolchain/module graph | **Implemented and measured offline:** bounded local/HTTPS artifact channel records artifact SHA-256, binary member, build-info digest, module graph and `AUTHORITATIVE` trust; generated artifact test data is hermetic. A real component bundle resolved a 143-module graph; the oversized bundle failed closed as `ARTIFACT_SIZE_LIMIT`. |
| B55 | Release-toolchain trust classes | Docker/CI/version-file declarations can corroborate a release but cannot independently ground stdlib applicability | **Implemented offline:** `AUTHORITATIVE` release binary/metadata outranks `SUPPORTING` declarations; supporting-only Docker evidence leaves stdlib applicability `UNKNOWN`; conflicting authoritative versions fail closed. |
| B56 | Incomplete offline build closure after release resolution | Release artifact evidence can resolve the version axis while source package usage remains unknown when offline `go list -deps -test -json ./...` cannot type-check the full product closure | **Closed for vendored snapshots:** strict tool invocations now select `-mod=vendor` from the authoritative `vendor/modules.txt` file before module-cache resolution, while retaining `GOPROXY=off`, `GOSUMDB=off`, `GOWORK=off`, and the inert empty-cache pin; offline vendored closures resolve without proxy attempts. **Remaining:** non-vendored snapshots still require an explicitly available read-only module cache and fail closed when dependencies are absent. |
| B41 | Ось продуктового vs тестового использования — offline vendor closure | Реализован `DeriveVendorUsageScope` (`internal/affected/vendorclosure.go`: vendor/modules.txt + go.mod + AST-импорты `./...`, 17 fail-closed тестов). На C02 показал транзитивную продукт-связь `docker/docker=mixed` через `testcontainers-go` (опроверг историческую гипотезу). На C09 оба субъекта moby/moby дали `unknown` + `VERIFIED_VENDOR_INVENTORY`. Контракт закрыт в коде, открытым остаётся покрытие не-vendor репозиториев без модулей | [План](plans/2026-10-15-01-c02-closure-capability-plan.md); `usage-scope` выдаёт `closure_semantics=product_all_packages` и `VERIFIED_VENDOR_INVENTORY` |
| B43 | Контроллерские deployment/config-факты как verified evidence | Условия вида «нет необходимой конфигурации», «доверенный peer», «режим/флаг/TLS» не имеют детерминированного базиса (12/18 кейсов дают только агентскую гипотезу) | Канал `DeploymentEvidence` (дизайн §3: deploy manifests / perimeter, уже поддержанные анализатором) → verified facts с provenance и областью проверки; кейсы закрываются детерминированно либо остаются UNKNOWN с явной областью; регрессия |
| B44 | Единица привязки advisory, когда назван только модуль | 19 decision-changing unknown из 18 кейсов — «компонент вне записей advisory»: утверждения агента не с чем связать, если advisory называет лишь модуль+диапазон | Модуль как единица привязки с явной пометкой «уровень пакета/символа неизвестен»; `advisory_scope_gap` остаётся только для реальных зависимостей вне advisory; регрессия на корпоративных кейсах |
| B45 | Идентичность попыток на уровне команды (остаток; автоматический повтор transient preflight закрыт: bounded retry ≤3 попыток с backoff 1с/2с только при `provider.status=unreachable_infra`, immutable per-attempt preflight-артефакты, `agent_manifest.preflight_attempts` — см. [регрессию](reports/2026-10-13-shadow-usability-regression.md)) | Повторный запуск в тот же `--output-dir` перезаписывает предыдущую агентскую попытку (потеря первичных артефактов) | Повторный запуск в непустой каталог выделяет новый attempt id (или требует явный флаг перезаписи) и сохраняет артефакты первой попытки; тесты + запись в отчёте |
| B46 | Byte-stable replay: недетерминизм существующих evidence tools | Идентичные inputs дают разные `ingress-inventory` item count, `find_may_call_count` в `find_may_callers` и порядок `trace_argument.origins`; map-iteration-order потребляет бюджет/меняет retained extras, а replay driver лишь маскирует эти поля ([измерения](reports/2026-10-14-02-usage-scope-regression.md)) | Детерминированные ordering/budget accounting и сериализация в самих tools; повторный replay идентичных inputs при одинаковом коде/build context даёт byte-stable tool output, включая ingress/may-call counts и origins order, без соответствующих масок projection; регрессионные тесты и сравнение saved-data replay, без изменения saved inputs/expectations |
| B48 | Guard/bound семейство негативных доказательств (R1 gap) | Маршрут `guard_verification_capability_missing` в `VerifyDecision` fail-closed: `find_validations` всегда возвращает `CompletenessPartial`, а реальный `goanalysis.Verifier` требует заполненные `EvidenceGraph.DataFlows`/`Validations`; независимая проверка guard/bound-фальсификатора (случай C01) недостижима. Отдельный пункт, не замена C02 | Tool-backed COMPLETE sink/flow/guard/bound observation (закрытая область, не PARTIAL) плюс адаптер, повторно запускающий `goanalysis.Verifier` на реальных DataFlows/Validations; независимо проверенный guard/bound negative на живом кейсе; любая неполная форма остаётся fail-closed `INCONCLUSIVE` |
| B49 | Устойчивость prompt-контракта плана проверок (остаток) | Механизм закрыт: `r0-v4` делает `verification_plan` обязательным для негативных категорий, и оба живых хода C09 его выдали; C09 дал `NOT_AFFECTED` с `COMPLETE`-покрытием (replay воспроизводит). Остаток: модели всё ещё могут отклоняться от схемы — нужен provider-side structured output либо контроллерная валидация формата с явным `format-invalid` статусом (не подменой плана) | [Отчёт C09](reports/2026-10-15-01-c09-live-demonstration.md); [план R4](plans/2026-10-15-01-c02-closure-capability-plan.md) |
| B53a | Lane-owned symbol proof (закрытие разрыва B53→lane) | Детерминистический лейн никогда не диспатчил `symbol-unreachability` — только агентский планнер запрашивал его, поэтому случаи package-present+version-affected с declared symbols всегда оставались `INCONCLUSIVE`. Закрыто: лейн сам вызывает проверку при module-present=TRUE + version-affected=TRUE + все declared subjects — точные символы, и проецирует результат через `VerifyDecision` authority route (`rule.declared-symbols-unreached`) без агента и artifact'а. Полный audit-bound proof → `NO_EXPLOIT_PATH_FOUND`/`COMPLETE`; limitation, gated ref, ошибка или таймаут → `INCONCLUSIVE`; `NOT_AFFECTED` никогда. Oversized complete proofs persist as a bounded envelope plus a content-addressed SHA-256+size-pinned typed sidecar and rehydrate before authority evaluation; missing, altered or undecodable sidecars fail closed; non-authoritative payloads retain truncation + `COMPLETE→PARTIAL`. `CanonicalByObs`/`ArtifactByObs` remain distinct envelope/file pins from the complete payload digest. `decision.reason` несёт вывод самого примитива (disproven с счётчиками refs/chains, UNKNOWN с пе…
| B50 | Тир-модель вердиктов и generic evidence contract (T0/T1/T2) | Текущий strict proof-only даёт измеренные 7/18 (38.9%) verified-негативов и оставляет 11/18 `INCONCLUSIVE`, при этом уязвимый код скомпилирован в продукт во всех 11 (измерено), а union agent-claim × machine-proof равен 13/18 ≈ 72%. Решение (R5): T0 `VERIFIED_*` остаётся proof-only, вводится T1 `EVIDENCE_BACKED_NEGATIVE` (review-ready пакет: machine-verified факты + агентские допущения + одно незакрытое условие + минимальная следующая проверка; не safe, не auto-close, вне numerator) и конкретизируется T2. Обобщение — через generic `Condition`/`EvidenceClaim`/`Falsifier`, а не через CVE-семейства | [План R5](plans/2026-10-15-01-c02-closure-capability-plan.md); [отчёт C09](reports/2026-10-15-01-c09-live-demonstration.md) |
| B51 | Decision-ready артефакт и агентский react/flow (принятие вместо анализа человеком) | R5 отклонён владельцем: тиринг меняет статус, но не объём работы. R6: единица результата — один полный decision или конечный набор условных decision'ов по объявленным переменным окружения (≤2 вопроса), человек только accept/reject; `Fact`/`Justification`/`DecisionArtifact` с ветками и `EnvironmentAssertion` (не code-level Claim); `FalsifierTrustedInfrastructure` → только контекстная ветка; цикл PLAN→ACT→OBSERVE→REASSESS в `internal/research/flow_driver.go` с расширением через `configs/research/*` при монотонной политике безопасности. Все 7 задач плана реализованы: контракт `decision-artifact/1` + `research-report/3`, envelope `evidence_envelope.go`, бранчи `branch_evidence.go`/`branch_evaluator.go`, flow `flow_driver.go`/`flow_adapter.go`, CLI `--decision-ready`/`--replay-decision-run`, human-first рендер (≤7 фактов, ≤2 вопроса, только Accept/Reject), стенд `eval/decision_ready/{runner,metrics,events.schema}` + 29 офлайн-тестов. **Измерено (task 7):** гард R6-G0 зелёный (C09 replay `NOT_AFFECTED`/`COMPLETE`/`auto_close=false`); 18/18 корпоративных кейсов — `NO_REPLAY` (persisted R6-прогонов нет), fail-closed проба `--deterministic-only` даёт 18/18 валидных `/3` с `HOLD_UNKNOWN`, `auto_close=false`, 0 model calls; VEX-Bench 10/10 point-case controls прошли `expect`, `false_safe=0`. **Остаётся открытым:** live-арм 3–5 кейсов (`NOT_RUN_LIVE_PENDING_AUTHORIZATION`, ≤4 вызова/кейс), слепое двух-ревьюерное исследование (нет людей), holdout (внешний манифест отсутствует). Acceptance не подтверждён: `repo_open_rate` и `missing_fact_rejection_rate` не измерены — B51 остаётся в бэклоге **Закрытый дефект (2026-10-18):** live-цензус потерял 6/14 детерминистических вердиктов — при `NOT_DECISION_READY` artifact'ный `HOLD_UNKNOWN` затирал терминальные решения лейна; `decisionForRecordedRun` теперь ставит applicability `FALSE` (`NOT_AFFECTED`/`COMPLETE`) и терминальный lane symbol-proof выше artifact'а, а failure run'а идёт в `decision.limitations`, не заменяя вердикт | [План R6](plans/2026-10-15-01-c02-closure-capability-plan.md); [план triage](plans/2026-10-15-02-decision-ready-triage-plan.md) |
| B51a | Runtime consolidation — preservation implementation, owner gates pending | Recovery Tasks 8–14 retain one live `triage`, current bounded prepared branches/answers/review/replay, canonical `/5` `finding.Project` publication, exact-record isolation, historical `/3`/`/4`/slice2/flow playback and tracked offline indexes/census/CI. Unknown/conflict/bounds stay conservative; assertions and Accept grant no Product A authority. Pure validators/canonical adapters and meaningful offline switches are retained, not deleted by file ownership. Original Task 2 report remains faulty-cutover history. Broad integration, unchanged Product A regression/census and exact paired measurement remain owner gates; synthetic tests do not establish R6 human-time targets. | [Recovery plan](plans/2026-10-28-04-phase1-human-result-plan.md) |
| B52 | Разрядка обязательных проверок из аудита лейна + субъект для package-usage | Закрыто: lane discharge разряжает ответ на вопрос проверки — OK+scope+snapshot+digest gate плюс COMPLETE с именованным coverage-правилом (closed negative) ИЛИ позитивный ответ по контракту проверки (`package-usage` USED при PARTIAL и `symbol-unreachability` disproven при PARTIAL — `positive_answer` в `flow.Observation.discharge_path`; неотвечающий PARTIAL не разряжает); observation-ledger: информационные (non-required) OK+audit-bound PARTIAL-записи (module-usage, module_internal_reach и т.п. — PARTIAL по контракту) пишут limitation, но больше не ломают ledgerComplete (обратный стимул убран; required-check неудовлетворённый всё так же именуется missingRequired, non-OK/unbound/no-digest деградируют всегда). Disproven-запись промоутится в verified PARTIAL-fact и эмитит `declared-symbol-reachability=reached` для атрибутированных субъектов — `rule.declared-symbols-unreached` записывается contradicted на артефакте; `available_checks` содержит только dispatchable ids; `promoteLaneFact` также проверяет pinned copy. Для module-only advisory выбран безопасный granularity-aware policy: required `package-usage` записывается как `inapplicable_checks` (детерминистика никогда не фабрикует package), остаётся в policy/audit и именуется в terminal evidence; module-capable `usage-scope` остаётся обязательным. Planner получает generated per-check `argument_schema` в `available_check_specs`; strict admission unchanged, но семантический отказ admission (arguments/subject-gate/unknown id) даёт один bounded repair-turn через `PlanInput.repair_error`/`repair_answer`. С 2026-10-17: r6-plan-v5 разрешает planner'у предложить text-derived subject с обязательным verbatim `anchor` — deterministic gate `internal/research/subject_anchor.go` валидирует цитату/модуль/форму до диспатча (отказ: `SUBJECT_ANCHOR_MISSING`/`_NOT_FOUND`/`SUBJECT_MALFORMED`/`SUBJECT_OUTSIDE_AFFECTED_MODULE`) | Focused/full tests, build and vet pass; live rerun requires external controls manifest and is separately reported when available |
| B57 | Ticket-build identity guard (version-axis mismatch) | Два из девяти «закрытых» census-негативов (CASE-227168: xpath 1.3.2 vs resolved v1.3.6; CASE-238323: otel/sdk 1.40.0 vs resolved v1.43.0) описывали другую сборку продукта — out-of-range вывод относился к проанализированному артефакту, а не к дистрибутиву тикета. **Implemented:** опциональный вход `--ticket <path>` у `izyan research` — тот же tracker intake, что у analyze (JSON-тикет/массив/произвольный текст, `--ticket-id` для выбора из массива); claims выводятся из `tracker.Ticket` и пишутся с digest-пином в `input.ticket`; текстовый intake пиннит версию пакета из PURL/`Библиотека:`-строки и не перехватывает `Версия продукта:`/`go_version:`, а `release`/`component` обрезаются на границе следующей `Слово:`-метки (release — по собственному version-token), purl-компоненты декодируются из percent-encoding; `affected.checkTicketClaims` сравнивает declared package/product version с resolved release identity; `TICKET_PACKAGE_VERSION_MISMATCH` блокирует version-axis negative (`version_affected=UNKNOWN`, `version_axis_blocked`, `ticket_check`, limitation с обеими версиями — refusal, не verdict), `ANALYZED_BUILD_MISMATCH` записывается информационно и сам не блокирует; module/package-absent маршруты и отсутствие тикета неизменны; NOT_AFFECTED остаётся только deterministic-applicability | **Closed offline:** resolver+lane+report покрыты тестами (mismatch → блок, match → сегодняшнее закрытие, product drift → `ANALYZED_BUILD_MISMATCH` без блока, malformed/unreadable ticket → `TICKET_INVALID`/NOT_CHECKED, JSON↔text parity по claims, 18/18 реальных текстов тикетов дают точные release/component/package@version, absent маршруты нетронуты); повторный замер census с `--ticket` остаётся за контроллером |
| B57a | Ticket distribution locator provenance | Ticket intake records only the dedicated `Ссылка на дистрибутив` locator (sanitized, never fetched) in parsed ticket and `input.ticket`; mismatch reports name it and instruct `provide/acquire the exact ticket distribution, then rerun with --artifact or --artifact-url`. Arbitrary URLs remain non-artifact provenance; the explicit artifact channel still pins SHA-256, selected member, build-info digest, module graph, and trust class before rerunning identity. | Focused tracker/research guard tests; census re-measurement remains controller-owned |
| B58 | Замороженный контекст `go/packages` и диагностика skipped-пакетов | Census 07/08/10: `Index.load`/`loadExtra`/`depImporters`/`ModuleInternalReach` строили `packages.Config` в четырёх местах — reach-загрузка роняла `BuildFlags` и молча расходилась с product-контекстом; failed-пакет с нулём восстановленных импортов выпадал из знаменателя scope (оба skip-списка его не видели → `NOT_USED` мог верифицироваться рядом со сломанным пакетом); диагностика компилятора не доходила до отчёта — `cmqc.h`-сбой был анонимным исключением. **Implemented:** единый `Index.loadConfig` (общие env/GOFLAGS/build tags/контекст отмены) для всех `packages.Load`; канонический `SkippedPackage`-запись (path, recovered imports, `imports_complete`, `source_visible`, error text) через `SkippedPackageDiagnostics`; `ProductUsage` держит негатив открытым при **любом** skipped-пакете, включая parseable package с полным набором импортов без target: untyped source может скрывать opaque dispatch. Gap называет пакет и ошибку компиляции; диагностика в `ScopeDetails.extra.skipped_package_diagnostics` + actionable limitations. Дополнительно advisory-module extras сохраняют bounded skip-диагностику (не более `maxTotalExtraPkgs` записей и `maxSkippedErrors` ошибок на пакет); `VerifyUnreachable` называет `<path>: <compiler error>` для каждого сохранённого failed-пакета и число непоказанных сверх лимита, не закрывая scope. Отдельный `ModuleInternalReach` load также отказывает в закрытом inventory при compiler errors/отсутствии `TypesInfo`. | Re-run кейсов 07/08 под установленными IBM MQ headers — closure решается при zero skipped |
| B59 | Interface-dispatch narrowing только при полном receiver-instantiation probe | Census 07/08/10: `dispatchGaps`/`ProductUsage` снимали interface-dispatch кандидатов при неинстанцированном ресивере, но probe был неполным в двух местах — unresolvable receiver type (`(*T).M`, необъявленный тип) давал пустой список кандидатов, читаемый как закрытый dispatch set, а failed product package никогда не входил в instantiation inventory (сужение «никогда не инстанцирован» на неполном scope). **Implemented:** `InterfaceDispatchSites` при нерезолвимом ресивере возвращает name-matched superset кандидатов и помечает set как open; `dispatchGaps` и оба dispatch-gate `ProductUsage` разрешают narrowing только при resolved receiver + отсутствии dynamic materialization + нулевых skipped packages; любой shortfall сохраняет сайты и именует причину в limitation — никогда пустой dispatch list. Package-level linked-but-untyped target и unresolved receiver для `reflect_method` именованы так же. **Done-критерий:** семантические тесты instantiated/uninstantiated/unresolved/incomplete-inventory + probe-failure/disabled controls; `SafeFormatter.String`-negative закрывается только при complete proof. |
| B60 | Reconcile package-absence vs symbol-unreachability proof bases (census case 10) | CASE-342517 carried two non-interchangeable records — package-level `absent-from-linked-closure` (package-usage, `usage_basis=absent_from_closure`) against a `mixed` build-usage class, plus `may_call=0` under a *partial* enumeration and open dynamic-dispatch markers. **Implemented:** `packageAbsenceDecision` now names `contradictory package/build facts` (observation/fact id + subject) instead of promoting over a `present=true` package-usage record or a present-basis `PACKAGE_USAGE` fact on any declared subject; `hasPositiveUse` names the blocking record (`usage_scope=mixed`, fact id); source-usage absence alone never grounds `FalsifierPackageAbsent`; a symbol is never absent because its package is absent; open may-call enumerations never close at zero sites. Both routes end `NO_EXPLOIT_PATH_FOUND` — never `NOT_AFFECTED` — and `decision.falsifier` names the basis. Residual fixed (case-10 re-run): `VerifyUnreachable` no longer emits the generic `product usage check could not close its negative verification` limitation when the paired `ProductUsage` UNKNOWN rests solely on the linked-closure absence note — that note is positive non-reachability evidence for this proof (`usageSpecificGaps` filters it), so the bare UNKNOWN recorded a blocker over no open gap; the limitation now fires only when a named scope gap survives filtering, keeping genuine `ProductUsage` gaps blocking. | Focused decision/usage/symbol tests; census re-measurement remains controller-owned |
| B61 | Типизированный канал `declared-assumptions/1` для owner-политик (admin-config trust, supported targets) | Owner-факты нельзя выводить из `mapstructure`/`env`-тега, `EvidenceKind.CONFIGURATION`, `--trusted-peer`, host OS или одного артефакта; без явного канала зависящие от политики гейты (G1 config-trust, G2 product-wide Linux scope) обязаны оставаться `INCONCLUSIVE` | **Канал реализован (Task 1 плана 2026-10-19-06):** `internal/domain/assumptions.go` — типы, scope-lattice (`product` покрывает узкие scope, обратное невозможно), канонические digest-пины и `AdmitAssumption` с именованными отказами; `internal/repository/assumptions.go` — intake с closed member set (64 KiB, 64 члена), `sha256` байтов + `content_digest`, отклонение unknown fields, дублей id, невалидных дат/дайджестов и kind/scope/targets-несоответствий; флаг `--declared-assumptions` в `research` и `analyze`; проекция `input.declared_assumptions` и отдельная секция отчёта; `AssumptionIDs` отдельно от `EvidenceIDs`. **G1 выведен (Task 3 плана):** `VerdictEvaluator` переносит `AssumptionIDs` и `GroundBasis=config-origin` из проверенного claim'а; helper `configClosureCoversUnresolved` покрывает unresolved-субъекты только если они входят в точный sink-set верифицированного условия (ассумпция сама по себе coverage не даёт, `coversAllDeclared` для config-origin по-прежнему false); `closureGate` при демоции сбрасывает assumption-ids; research-лейн выполняет собственный bounded post-reach проход (`LaneResult.ConfigProof`, `SinkSetBasis` + `SinkClosure` + `TraceArgumentBound` → `ArgumentOrigin` → `goanalysis.Verifier` → `VerdictEvaluator`) и отдаёт его через `VerifyDecision`/`decisionForRecordedRun`; NEPF-валидатор принимает `trusted-infrastructure` только с `ground_basis=config-origin` и непустыми `assumption_ids`; отчёт и OpenVEX называют политическую ассумпцию отдельно от доказательств. **Остаток:** G2 (Tasks 4–5), product-vs-artifact scope в affected-chain и валидация assumption-ссылок в `decision-artifact/1`. |
| B62 | Implementation-axis G2 end-to-end (proposal channel → NOT_AFFECTED) | LLM-гипотеза об узле уязвимой реализации не может давать вердикт: нужен typed input (`implementation-locus-proposals/1` + replay-канал записанных proposals), deterministic re-check под authoritative target scope и FALSE-only-when-all-absent семантика — иначе case-04 формы (BSD-only файл под Linux-продуктом) остаётся INCONCLUSIVE, а любое упрощение рискует false-safe | **Реализовано (Tasks 4–6 плана 2026-10-19-06):** `domain.ImplementationLocusProposal` + `AdmitImplementationLocusProposal`; `--implementation-locus-proposal` флаг и intake с advisory-pinned quote/digest; replay-канал реадмитит записанные proposals после ревалидации (hand-edited — fail-closed); lane диспатчит `affected.EvaluateImplementationAxis` отдельным наблюдением `implementation-axis` (compiled-scope package-presence probe + GOOS/GOARCH/cgo/tag re-select + verifier FALSE); `vulnerable_implementation_present=FALSE` при слинкованном пакете → `NOT_AFFECTED` через `vulnerable-implementation-present`/`rule.implementation-absent` rules и OpenVEX `vulnerable_code_not_in_execute_path`; классический отчёт показывает axis-строку и target scope; `BuildRelevant` неизменен. Fixture `testdata/implscope` (generic package с BSD/Linux реализациями и marker-bearing alternate) |

| B63 | Exploit-locus binding для безсимвольных адвизори (G1 + case-03) | Адвизори без `affected[].ecosystem_specific` не дают G1 никакого sink-множества: перекрёстный product-sink (`xmlquery.QueryAll` → `xpath.(*logicalQuery).Select`) нельзя ни объявить authoritative, ни принять от LLM без deterministic проверки. **Реализовано:** `exploit-locus-proposals/1` (`--exploit-locus-proposal` + replay-канал записанных proposals) — закрытый член-набор, 1 MiB bound, advisory digest/quote pin, только `LLM_INFERRED`, typed fail-closed `LoadError`; `affected.VerifyExploitLocus` перепроверяет advisory/identity/version, typed vulnerable-symbol (включая unexported methods и canonical pointer receiver), sink signature/argument name+index, trigger-preservation relation (`goanalysis.ProveTriggerPath`: typed mark-propagation по params/receiver/fields/returns/dispatch, fail-closed на unresolved callee, open dispatch, function values, receiver carriers) и замкнутую reverse-enumeration всех product-facing carriers; только COMPLETE binding расширяет `SinkSetBasis` (`ExploitLocusBindingBasis`, symbol-less entry + точное равенство subject-множества) и строит G1-условие из verified sink set. Отчёт несёт `input.exploit_locus_proposals` + `exploit_locus_binding` (binding, condition, evidence refs, assumption ids); assumption ids проверяются только в declared-assumptions пространстве. Любая незакрытая проверка оставляет INCONCLUSIVE и называет blocker; маршрут никогда не даёт NOT_AFFECTED и не фабрикует `AffectedSymbols`. |

### P2 — глубина покрытия

| # | Пункт | Done-критерий |
|---|-------|----------------|
| B5 | Build-tag варианты в dep-коде | Snapshot фиксирует tag-set; claims помечаются при tag-зависимом покрытии; компилируемость tag-варианта проверяется, не только синтаксический импорт |
| B7 | `AUTHENTICATION_CONDITION` per-route | Route→handler→middleware маппинг; TRUE только при покрытии конкретного handler'а |
| B8 | Bound-семантика шире | `len(x)`, `x != 0`, float, арифметика в термах; юнит-тесты каждой формы |
| B15 | Reviewer: patch-misinterpretation + scope-mismatch | Реализовано: explicit `action=promote|demote` в `ReviewFinding`, demotion нерелевантного mandatory-условия в supporting с сохранением claim/NV/evidence history, `PendingConditionReviews` запрещает closure рядом с открытой критикой. Открыто: §21 требует проверок, которые Structural не делает: «условие описывает не тот класс, что патч», «claim вне скоупа advisory» → детерминистический чек или semantic-review правило + тест; live 6c5v/GO-2026-6372: fix-subjects `openTune`/`pick` не связывают peer-controlled `recvContent` payload с условием, xwwf: peer tune value не доказан через opaque `pick`; truth EXPLOITABLE, допустимый результат INCONCLUSIVE до независимого доказательства payload, без args-only fallback |
| B17 | LLM advisory-контур (D16) | Параллельная оценка семантики + verdict estimate, репортируемая отдельно от авторитетного контура | `llm_assessment.json` + `## LLM assessment` в report.md; расхождение с вердиктом → finding; unit-тест: advisory не меняет claims; e2e: кейс с divergence; спека: [`roadmaps/llm-advisory-roadmap.md`](roadmaps/llm-advisory-roadmap.md) |
| B16 | LLM semantic-гипотезы для KB | Opaque/unresolvable callee → UNKNOWN навсегда; LLM может подсказать семантику вызова | Гипотеза «f читает env/file» в GAP_ANALYSIS → детерминистический трейс внутрь тела ищет заявленный примитив; evidence с меткой llm-suggested/code-verified; draft-записи в `knowledge_suggestions` отчёта (мерж только через `--knowledge`, никогда не авто); тест: REJECTED-гипотеза не трогает claim |
| B14 | Build/test результат не влияет на claims | `actBuildTest` пишет BUILD/TEST evidence, но build failure — caveat, не демоция claim; покрытие пути тестами не оценивается → per-vulnerability test-coverage факт или claim-оговорка |
| B9 | Паттерны вне 4 семейств | По живым кейсам; каждый паттерн = registry entry + фикстура |
| B20 | Root-cause верификация теряет fix-added символы | `Verifier.Verify` ищет кандидата только в dep-версии продукта (`FindSymbol` → product-scope); символ, добавленный патчем, там отсутствует по определению → в Alternatives. 27gv: LLM верно предложил `PlainAuth.String`/`setSASL`/`Reconnect` — существуют в v1.13.0 (это и есть фикс), но отброшены | Двойная верификация: vuln-версия (exploit-субъект) + fix-diff/fixed source (root-cause идентичность, метка «added by fix»); кейс с аддитивным фиксом сохраняет fix-side кандидата в RootCauses; регресс-тест на 27gv-сценарий |
| B25 | Вызовы между вложенными модулями | `ModuleUsage` атрибутирует callee по реальному модулю; вызов API nested-модуля не доказывает использование родителя, но может вызвать его транзитивно и поэтому блокирует FALSE-кандидат. Done: проверять рёбра child→parent по полному import/call graph; тесты с таким ребром и без него; UNKNOWN при неполном графе, без false-safe |

|| B36 | Root-cause candidates для advisory без declared symbols и fix reference | OSV без `affected[].symbols` и без fix-commit в references оставляет единственный источник кандидатов — LLM; при отказе провайдера → `root cause NOT_FOUND` → терминальный INCONCLUSIVE (reviewed: GHSA-p77j-4mvh-x3m3). Done: детерминистический discovery fix-commit'а через cross-links (CVE→GitHub advisory→commit) или diff между resolved/fixed версией модуля; корпусный кейс резолвится без LLM |
|| B37 | Source-index resolution для present-package symbol variants | Символ advisory объявлен, пакет в сборке, но source index его не резолвит (переименование/вариант сигнатуры/обёртка) → genuine unmodeled subject → INCONCLUSIVE даже при верифицированных falsifiers (reviewed: amqp091-go `Channel.validateQos`, `negotiateFrameSize`; fasthttp `ServeFS`). Done: resolver покрывает rename/signature-variant субъекты или атрибутирует их к unverified-символу предка; кейсы reviewed-корпуса выходят из unmodeled без ослабления demotion |
| B64 | Production wiring of the admitted defect-semantics contract into research / Product B | Task 2 сделал все deadness-потребители fail-closed без допущенной premise. Phase 2 Task 4 убрал мёртвую ниль-проводку Product B: `runUnreachabilityKernel`, `mergeFalsifierReport`, `UnreachabilityRequestFor` и `MintUnreachabilityProof` удалены; Product B больше не несёт `UnreachabilityRequest.Premise`. `symbol-unreachability` остаётся read-only observation, а машинный reduction возможен только из catalog-admitted proposal, прошедшего verifier. Research CLI по-прежнему передаёт `LaneOptions.DefectSemantics` = nil: symbol-unreachability proof там остаётся INCONCLUSIVE. Это осознанно (resolved symbol ≠ resolved defect semantics), но до общей разводки является регрессией возможностей | Один общий advisory/fix-grounded semantic-resolution вход питает builder и research; та же `ValidateDefectSemanticsModel` admission работает на replay; второй парсер семантики не появляется; тесты: lane с контрактом зарабатывает deadness-негатив, артефакт без контракта остаётся fail-closed |
| B65 | Typed `CHECK_TRIGGER`/`CHECK_INPUT` witness producer | Контракт defective-check привязывает `req` index/value и receiver payload shape, а matcher отвергает cross-call сборку, но source-collector для `Evidence.CheckTrigger`/`Evidence.CheckInput` отсутствует. Поэтому позитивный `DEFECTIVE_CHECK` маршрут всегда оставляет `C-INPUT`/`C-CHECK-TRIGGER` UNKNOWN (измерено 2026-10-26 на Echo и `real-jwt-auth`); dead-operation негатив этого witness не требует | Детерминированный коллектор выдаёт один typed witness, связывающий operation, invocation, argument index/value и receiver field/shape на одном вызове и ресивере, с control evidence; варианты string/array/`req=true` различимы, cross-call/cross-receiver сборка отвергается; реальный defective-check позитив может сослаться на witness |

### P3 — deferred by design

| # | Пункт | Почему |
|---|-------|--------|
| B10 | Сетевые адаптеры трекеров | `--ticket` generic JSON покрывает intake |
| B11 | goroutine/channel dispatch, interface-impl внутри dep-кода, глубокие generated-цепи | Терминальные ограничения синтаксического скана |

Процесс: пункт берётся сверху вниз; закрытие — только с done-критерием
(тест/живой кейс), после чего строка удаляется из §2 в коммите
закрытия; история — в `git log`, не в этом файле. Новые находки
добавляются с приоритетом, не висят в разговоре.

### Handoff notes (что читать/трогать новой сессией)

Самодостаточные задачи — можно делегировать субагенту или свежей
сессии. Общий контекст: репо плоский (`internal/` на корне, модуля
`github.com/davniy/izyan`), репозиторий продукта задаётся через
`VA_PRODUCT_REPO` (env) или `--repo`, проверка — `go test ./...` +
`go run ./cmd/izyan eval --corpus eval/live-corpus.json`.

- **B1 закрыт** (выполнено): истина 11 кейсов — `eval/ground-truth.md`;
  `expect` пиннит истину. Разметка поймала два false-safe (6c5v,
  GO-2026-6372 → NEPF): исправлено — covered+silence FALSE теперь
  требует всех субъектов в `AffectedSymbols`, `ModuleReachable`-цепочка
  — позитивное TRUE-доказательство до FALSE-ветки. j497: истина
  INCONCLUSIVE (peer→shortstr config-contingent) → re-pin.
- **B8** (делегируемо): `internal/evaluator/provenance.go` —
  `parseBound`/`boundTerm.satisfies`/`falsifiedBy`;
  `internal/goanalysis/provenance.go` — `exprIntValue`,
  `boundsDirection`. Расширять по одной форме: `len(x)`, `x != 0`,
  float. Тесты — `provenance_bound_test.go` образец.

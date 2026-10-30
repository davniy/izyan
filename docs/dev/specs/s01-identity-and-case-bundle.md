# S-01. Canonical identity и case-bundle contract

**Источник:** delegated `architect` artifact `agent://SpecWorkflowAndS01` (2026-10-21), документ 2; draft.
**Status:** `draft`  
**Phase:** 0–1; foundational contract для последующих adapters.  
**Dependencies:** Phase 0 governance/normative delta; implementation prerequisites — Target §6 Phase 0 и §14.4.  
**Contract owner:** Shadow case owner — конкретный участник не назначен.  
**Architect / independent reviewer / approval owner:** не зафиксированы.  
**Security review:** обязателен.  
**Implementation:** не выполнялась.

## 1. Решение и plan-readiness

Сохранить Shadow `AnalysisCase` единственным canonical persisted unit Product A. Добавить единый immutable identity contract и case-bundle layout. Все consumers используют один identity gate; adapter не может переопределять его результат или расширять идентичность.

Различать:

```text
согласованная identity → IDENTITY_ACCEPTED
валидная, но неразрешённая обязательная ось → IDENTITY_INCOMPLETE
противоречивая identity → IDENTITY_REFUSED
```

Ни один из этих identity outcomes сам по себе не доказывает applicability или exploitability.

**Вердикт: `NOT PLAN-READY`.**

Draft определяет target-семантику, field-level требования, state machine и acceptance matrix. До implementation plan необходимо закрыть:

- **U-01:** полный wire/schema compatibility contract и field mapping старого `AnalysisCase`;
- **U-02:** точный self-contained replay closure и его packaging;
- **U-03:** обязательность declared coordinates для no-ticket/multi-entry режимов;
- **U-04:** Phase 0 normative/approval gate G-26.

Это не разрешение реализовать только «очевидную часть». После закрытия блокеров требуется independent review всей spec.

Все новые требования ниже — **PLANNED**, не утверждения о существующей реализации.

## 2. Входы и provenance

### 2.1. Primary inputs

**Target:** `docs/dev/roadmaps/2026-10-20-target-architecture-and-roadmap.md`:

- §1.2 — `false-safe=0`, identity-bound evidence, replay, LLM authority;
- §2.4.1 — `AnalysisCase`;
- §2.4.7 — sidecar envelope;
- §3.3 — artifact layout, owner S-01;
- §§3.4, 4.3–4.5 — exit behavior, substitution/cross-run/tamper;
- §13.2.1 — immutable input и identity freeze;
- §13.2.2 — Product A pipeline;
- §13.2.4 — canonical case и ownership;
- §§13.2.5–13.2.6 — failure/replay;
- §13.4 — межпродуктовая граница;
- §§13.6–13.7 — normative delta/input map;
- §14.6 — revised S-01 scope и DoD.

### 2.2. Required Shadow source inventory

| Surface | Изученные API/типы |
|---|---|
| `internal/domain/domain.go` | `Vulnerability`, `ProductSnapshot`, `AffectedResult`, `AnalysisCase`, `WorkflowStatus` |
| `internal/domain/ticket.go` | `TicketClaims`, `TicketCheck`, reason/status constants |
| `internal/domain/target.go` | `ProductTarget.Validate`, `Authoritative`, `TargetScopeMatch` |
| `internal/domain/release.go` | Release trust/status taxonomy, artifact/build-info pins |
| `internal/repository/service.go` | `Service.Snapshot`, `resolveProductTarget` |
| `internal/repository/contenthash.go` | `ContentHash`, `VerifyContained` |
| `internal/repository/preflight.go` | `CheckPathReplacements` |
| `internal/repository/artifact.go`, release metadata/evidence files | Artifact acquisition, member/build-info/provenance |
| `internal/affected/ticket.go` | `checkTicketClaims`, package/version comparison |
| `internal/states/states.go` | `Created`, `SnapshotProduct`, `ResolveVulnerability`, `CheckAffected` |
| `internal/workflow/engine.go` | `Engine.Run`, persistence после transitions |
| `internal/persistence/store.go`, `filesystem/store.go` | `CaseStore`, `Create/Load/Save`, `PriorCase` |
| `internal/research/ticket.go`, `types.go` | Raw ticket/advisory digests, run/attempt records |
| `internal/research/deterministic.go`, `replay.go` | Sidecar verification и существующие replay readers |
| `cmd/izyan/main.go` | `analyzeCase`, создание case и current output wiring |
| `internal/report/report.go` | Current report layout |

Это inventory для cutover, **не implementation plan**.

### 2.3. Product goals и decision context

- `docs/goals-scope.md`: конкретный snapshot, воспроизводимое техническое обоснование, audit, `false-safe=0`.
- Reports `2026-10-20-04`, `05`, `06`: Shadow authority/V2 reference, один identity contract, отсутствие LLM authority.
- Report `2026-10-20-07` вместе с Target §14: gaps в canonical fields, layout ownership и старых cases.

### 2.4. Current-state/provenance only

- `docs/dev/specs/governing-spec.md` §§3–5, 22;
- `docs/dev/decisions/architecture-decisions.md` D1, D12, D16;
- `docs/architecture.md`;
- `docs/dev/analysis-internals.md`;
- `docs/dev/implementation-status.md`;
- `docs/dev/gap-analysis.md`.

Эти документы не переопределяют target semantics.

### 2.5. Наблюдённое состояние

| Наблюдение | Доказанность |
|---|---|
| `AnalysisCase` существует, но не имеет unified `identity`, case `schema_version` и canonical `replay_metadata` | **PROVEN — source:** `domain.go:1506–1556` |
| `filesystem.Store.Load` выполняет обычный JSON decode без version/migration gate | **PROVEN — source:** `filesystem/store.go:24–33` |
| Case сохраняется атомарно через temporary file + rename | **PROVEN — source:** тот же файл, `Save` |
| Ticket mismatch блокирует преимущественно version axis; advisory mismatch может оставаться информационной limitation | **PROVEN — source:** `affected/ticket.go:120–240` |
| Target provenance/digests и `ProductTarget.Validate` реализованы | **PROVEN — source:** `domain/target.go` |
| `ContentHash` имеет версионированное tree encoding `t1`; текущая snapshot-интеграция не обеспечивает его одинаково для всех путей | **PROVEN — source:** `contenthash.go`, `service.go` |
| Raw advisory/ticket digests и sidecar integrity существуют в отдельных research contracts | **PROVEN — source:** указанные `internal/research` files |
| Unified `IDENTITY_*` gate и layout §3.3 уже работают end-to-end | **UNPROVEN**; в просмотренном source соответствующего контракта нет |
| Persisted classic `AnalysisCase` полностью replayable/restartable | **UNPROVEN**; наличие `Load` не доказывает такой сценарий |
| Исходное дерево совпадает с integration anchor `118e10c` | В этой работе независимо не проверялось |

Тесты читались как source; их прохождение здесь не проверялось.

## 3. Goals traceability

| Цель / invariant | Требования S-01 |
|---|---|
| Identity correctness: анализ именно выбранной уязвимости и build | R02–R07 |
| `false-safe=0`: чужие, неполные и старые данные не дают safe-negative | R07, R09–R12 |
| Offline replay без LLM/network/mutable source | R03, R08–R11 |
| Auditability и воспроизводимое обоснование | R01–R02, R06–R11 |
| Один authoritative contract | R01, R12 |

S-01 не заявляет доказательство универсального `false-safe=0`. Она закрывает identity/integrity prerequisites для соответствующих safety gates.

## 4. Scope и non-goals

### В scope

- advisory/ticket/source/artifact/package/version/target/build/deployment/run binding;
- canonical identity внутри `AnalysisCase`;
- case bundle и run-directory manifest;
- freeze points и ownership;
- состояния accepted/incomplete/refused;
- foreign/cross-run/stale rejection;
- identity-предпосылки replay;
- schema versioning и old-case migration/refusal;
- adapter non-widening.

### Non-goals

- вычисление `NOT_AFFECTED`, `EXPLOITABLE`, `NO_EXPLOIT_PATH_FOUND`;
- семантика EvidenceGraph/Claim/NV — S-02;
- Product B intake, agent loop, recommendation/policy/admission behavior;
- typed proof verification, stability и полный replay adapter — S-09 и соответствующие capability specs;
- новая storage architecture или второй domain;
- implementation code и implementation plan.

## 5. Требования и invariants

| ID | Требование |
|---|---|
| **R01** | Identity и `AnalysisCase` имеют одного canonical owner: Shadow domain/repository/affected boundary. Case bundle не создаёт второй case model. |
| **R02** | Advisory и supplied ticket сохраняются вместе с точными bytes и digest; declared claims не заменяются resolved facts. |
| **R03** | Source и artifact — отдельные identity channels. Их evidence нельзя взаимозаменять без explicit verified binding. |
| **R04** | Package/module identity, declared version и resolved version различаются; сравнение не подменяет applicability check. |
| **R05** | Target/build/deployment inputs фиксируются с provenance. Host defaults, supporting release hints и assumptions не повышаются до authoritative release facts. |
| **R06** | Case/run/attempt identity создаётся до анализа; freeze запрещает дальнейшую мутацию input identity. |
| **R07** | Единый deterministic gate различает accepted/incomplete/refused; отказ не является semantic verdict. |
| **R08** | Canonical run directory содержит case, frozen inputs и manifest, позволяющий проверить состав и целостность bundle. |
| **R09** | Каждый authoritative sidecar/reference связан с ожидаемым case/run/attempt и identity/scope pins; совпадения содержимого недостаточно для cross-run admission. |
| **R10** | Replay сохраняет original identity и не зависит от нового LLM, advisory API или mutable external repository. |
| **R11** | Legacy/unknown schema не получает новое доверие при decode; допускаются только explicit migration, ограниченный historical replay или refusal. |
| **R12** | Adapter и LLM не могут изменить, дополнить догадкой или расширить frozen identity/subject/target scope. |

Дополнительные инварианты:

1. До freeze можно собирать **identity acquisition records**, но они не поддерживают verdict.
2. `IDENTITY_ACCEPTED` не означает `scope=COMPLETE` и не означает proof.
3. Unknown и not-applicable различаются.
4. Пустая строка/zero value не является доказательством согласованности.
5. Изменение input identity требует нового live run; «уточнить identity задним числом» нельзя.
6. Диагностический report не является source of truth.

## 6. Field-level identity contract

### 6.1. Общие правила

Логические имена ниже задают draft contract. Финальные JSON tags и mapping текущих полей закрываются в **U-01**.

В identity record обязательны:

- версия схемы;
- case/run/attempt coordinates;
- выбранные input channels;
- состояние identity;
- имеющиеся координаты и pins;
- `unresolved_fields[]` с named reasons;
- explicit not-applicable markers для отсутствующих необязательных channels.

**Неизвестное значение сохраняется как неизвестное, не как фиктивный hash или угаданная версия.**

Для accepted identity обязательные применимые поля заполнены и согласованы. Для incomplete case допускается сохраняемый неполный record, но он не проходит admission.

### 6.2. Поля и обязательность

Обозначения: **M** — обязательно; **C** — обязательно при условии; **O** — provenance, не самостоятельная authority.

| Группа / поля | Обязательность | Источник и правило |
|---|---|---|
| `schema_version` | M | Versioned identity contract; неизвестная версия не принимается автоматически |
| `case_id`, `run_id`, `attempt_id` | M | Controller-generated, не из LLM; уникальность и связь проверяются при чтении |
| `advisory_id` | M | Canonical resolved ID frozen advisory |
| `advisory_aliases[]` | M, может быть пустым | Только validated aliases frozen document; не новый remote lookup на replay |
| `advisory_bytes_digest` | M | SHA-256 точных сохранённых advisory bytes |
| `requested_advisory_id` | O | Исходный запрос сохраняется отдельно; должен разрешаться в frozen canonical ID/aliases |
| `ticket_bytes_digest`, raw ticket ref | C: ticket supplied | Digest точных bytes, в том числе при parse failure |
| `ticket_extracted_claims_digest` | C: claims извлечены | Pins нормализованный typed claims record; extraction provenance сохраняется |
| `declared_package`, `declared_version`, `declared_component` | C; матрица режимов — U-03 | Declared coordinates не вычисляются из affected ranges и не заменяются resolved version |
| `product_module` | M для source/module analysis | Из selected product snapshot/module identity, не из имени каталога |
| `source_tree_digest` | C: source channel | Versioned `ContentHash` contract; commit сам по себе не доказывает фактически прочитанные bytes |
| `source_commit` | C: commit известен/заявлен | Полный resolved commit, не mutable branch/tag; отсутствие допустимо при достаточном content identity |
| `source_root` / source locator | O | Bundled locator; внешний absolute path не является identity authority |
| `artifact_digest` | C: artifact channel | SHA-256 точных artifact bytes |
| `artifact_member` | C: выбран member контейнера/archive | Должен однозначно определять анализируемый binary; для standalone binary явно неприменим |
| `artifact_build_info_digest` | C: build-info используется | Pins именно прочитанный build-info selected artifact/member |
| `resolved_dependency_graph_digest` | C: graph получен | Graph channel, module replacements и completeness фиксируются; unavailable graph — unresolved, не пустой complete graph |
| `resolved_dependency_versions[]` | C: graph получен | Module path + resolved/effective version + replacement provenance + source/artifact channel |
| `GOOS`, `GOARCH` | M как recorded context | Отдельно сохраняются product-target provenance и effective analysis context |
| `build_tags[]` | M, пустой список допустим | Пустой список означает известный empty set; missing — не то же самое |
| `CGO` | M как known/unknown fact | Неизвестное состояние нельзя декодировать как подтверждённое `false` |
| `analysis_toolchain` | M | Реально использованный analyzer toolchain/version |
| `release_toolchain`, `release_toolchain_source` | C: release-scoped analysis требует факт | Только допустимые authoritative release facts; `go.mod`/host не заменяют их |
| `vendor_module_mode`, workspace/replace input pins | M/C по режиму | Участвуют в effective build context |
| `build_context_digest` | M для admitted build-bound facts | Pins полный effective context, включая применимые inputs выше |
| `deployment_input_digests[]` | M как declared input set | Может быть явно пустым, если channel не запрашивался; это не доказательство isolation |
| `assumption_ids[]` и input digest/ref | C: assumptions supplied | Policy input, отдельно от deployment facts и EvidenceGraph |
| `run_configuration_digest` | M | Effective configuration, bounds и relevant contract/rule versions |
| `condition_catalog_hash` | C: используется catalog | S-16 producer; нельзя изготовить значение из model output |

**Known absence не равна unknown.** Например, complete dependency graph может детерминированно установить отсутствие module. Это результат соответствующего applicability resolver, а не недостающая версия, которую identity gate должен выдумать.

**No-ticket режим не запрещается.** Необязательный ticket channel получает explicit not-applicable status. Точная обязательность declared package/version/component в таком режиме требует закрытия U-03.

### 6.3. Ownership

| Данные | Canonical writer/validator |
|---|---|
| Identity schema, identifiers, accepted record | `internal/domain` |
| Source/artifact/target acquisition и digests | `internal/repository` |
| Ticket/package/version comparison | `internal/affected` |
| Gate orchestration/freeze | Product A workflow/state boundary |
| Case storage и atomic publication | Persistence layer |
| Sidecar content/selector/proof semantics | Existing evidencetools/research owners; S-02/S-09 |
| Product B projections | Adapter, только read-only projection canonical identity |

Не создаётся V2-specific `AnalysisCase` или альтернативная `CaseIdentity`.

### 6.4. Precedence и противоречия

Precedence выбирает допустимый источник факта, **но не стирает конфликтующие declarations**.

- Advisory authority — frozen bytes и deterministic normalization.
- Ticket claims — заявленные координаты, не доказательство resolved build.
- Source dependency graph и release artifact graph сохраняются отдельно.
- Existing target provenance order используется как основа: artifact build-info → release metadata → explicit operator target → host context.
- Host context не становится product/release scope.
- Supporting release hints не создают authoritative release version.
- Если два authoritative inputs заявляют один и тот же выбранный build/target и противоречат друг другу, нельзя выбрать «более удобный»: identity refused.
- Если источник не позволяет установить применимый обязательный факт, identity incomplete.
- Разные source/artifact graphs сами по себе не являются противоречием: это разные channels. Противоречие возникает при нарушении заявленного binding или использовании фактов одного канала как фактов другого.

Для package/version comparison сохраняются исходная и нормализованная формы; normalization не должна превращать непарсируемую версию в совпадение.

## 7. Freeze points и flows

### 7.1. Freeze

| Момент | Что фиксируется |
|---|---|
| `CREATED` | Case/run/attempt IDs, requested channels, effective configuration intent |
| Input acquisition | Raw advisory/ticket/config/assumption bytes, digests, extraction provenance |
| Snapshot resolution | Source/artifact identity, dependency graph, effective target/build context |
| **Identity gate** | Согласованный immutable identity record и digest; решение accepted/incomplete/refused |
| Bundle finalization | Итоговый состав artifacts, их hashes/sizes и bundle status |

Advisory bytes замораживаются **до первого decision-relevant анализа**.

Gate должен пройти до допуска любых acquisition/affectedness records к verdict и до обычной evidence collection. Уже собранные dependency/build facts переиспользуются; freeze не оправдывает повторное разрешение против изменившегося окружения.

Текущий `SnapshotProduct` добавляет evidence до появления unified gate. Cutover обязан устранить возможность использовать эти записи как decision-relevant до успешного freeze.

### 7.2. State machine

```text
CREATED
  → identity acquisition
  → deterministic validation
      ├─ all applicable required fields resolved and consistent
      │    → IDENTITY_ACCEPTED → frozen → normal analysis
      ├─ valid but applicable required axis unresolved
      │    → IDENTITY_INCOMPLETE → persisted INCONCLUSIVE
      └─ contradictory identity
           → IDENTITY_REFUSED → refusal/error artifact, exit 2
```

Дополнительные правила:

- Acquisition может дополнять ещё не frozen draft record.
- `IDENTITY_INCOMPLETE` не повышается в accepted задним числом после выпуска результата. Новые входы требуют нового run.
- Ошибка после freeze не переписывает исходную identity: сохраняется integrity/refusal event.
- Нельзя исправить mismatch заменой declared coordinates на analyzed coordinates.
- `IDENTITY_ACCEPTED` разрешает дальнейший анализ, но не какой-либо конкретный verdict.

### 7.3. Terminal semantics

- `IDENTITY_REFUSED`: semantic verdict отсутствует; exit `2`.
- `IDENTITY_INCOMPLETE`: при возможности сохранить корректный case — `INCONCLUSIVE` с named limitations, exit `0`.
- Невозможно сохранить корректный case/error artifact: technical failure, exit `2`; stderr/CI result сохраняет факт ошибки.
- Identity gate никогда не производит `NOT_AFFECTED`.
- Дальнейшие verdict routes принадлежат canonical evaluator, не S-01.

## 8. `AnalysisCase` и case bundle

### 8.1. Envelope

Target case содержит:

```text
case_id
schema_version
identity
vulnerability
product_snapshot
affected_result
root_cause_model
exploit_model
evidence_graph
claims[]
assumptions[]
negative_verifications[]
reviews[]
verdict_result
workflow_status
replay_metadata
limitations[]
```

Правила:

- Поля ещё не выполненных стадий явно отсутствуют/null согласно утверждённой schema; это не положительный результат стадии.
- Refused case не содержит semantic `verdict_result`.
- Honest completed incomplete case содержит `INCONCLUSIVE` и named unresolved identity fields.
- Nested EvidenceGraph/Claim/NV semantics принадлежат S-02. S-01 не объявляет старые вложенные records canonical только потому, что envelope декодировался.
- Product B recommendation/policy не добавляются как альтернативный verdict в этот envelope.

**U-01** должен определить точный mapping существующих `id`, `product`, `affected`, `root_cause`, `verdict`, `workflow` и остальных сохранённых полей. Потеря existing provenance при переходе запрещена.

### 8.2. Run directory

Основой является Target §3.3:

```text
<run-root>/
  bundle-manifest.json          # S-01: canonical directory inventory
  identity.json
  input/
    advisory.json
    ticket.json                # если supplied
    finding.json               # если supplied
  snapshot/
    manifest.json
    source-ref.json
    artifact-ref.json
  assumptions.json
  rules/
    ruleset.json
    prompt.json
  evidence/
    evidence-graph.json
    tool-executions.jsonl
    observations.jsonl
  sidecars/
    <content-addressed-proof>.json
  claims.json
  negative-verification.json
  case.json
  verdict.json
  decision-package.json         # Product B only
  assessment.json               # Product B only
  report.json
  report.md
  report.en.md
  report.audit.md
  openvex.json
  cyclonedx.json
  audit/
    events.jsonl
  replay.json
  metrics.json
```

`run-root` — один изолированный run/attempt в namespace `<out>/<case-or-finding-id>/` Target. Повторное использование output path не должно смешивать attempts или перезаписывать завершённый bundle.

Не все перечисленные файлы обязательны во всех outcomes:

| Outcome | Обязательный минимум |
|---|---|
| Accepted, completed Product A | Identity, frozen inputs, snapshot/build manifests, case, применимые evidence/sidecars, verdict/report и replay metadata |
| Incomplete | Сохраняемый identity record, доступные frozen inputs, case с `INCONCLUSIVE`, named limitations, manifest |
| Refused | Refusal/error artifact, доступные identity/input pins и audit; semantic verdict/VEX не создаются |
| Persistence failure | Technical error; нельзя оставлять частичный output, выглядящий completed/admitted |
| Product B artifacts | Только при соответствующем product mode; payload schemas принадлежат S-17 и owning specs |

Raw ticket сохраняется без изменения bytes; если исходный формат не JSON, manifest указывает фактический media type/path. Нельзя переименованием в `ticket.json` выдавать преобразованную запись за raw input.

Source/artifact refs не заменяют сохранение необходимых replay inputs. Их точный bundled packaging закрывается U-02.

### 8.3. Manifest

Draft предлагает имя `bundle-manifest.json`; это implementation-spec detail, не существующий artifact.

Manifest содержит:

- schema version;
- case/run/attempt IDs;
- canonical identity reference;
- identity state и bundle completion status;
- producer/contract versions;
- entries: relative path, role, owner/schema, SHA-256, size, обязательность для replay;
- explicit reasons отсутствия условных artifacts.

Требования:

1. Все authoritative referenced files перечислены и hash-bound.
2. Дублирующие path entries, conflicting pins и path escape запрещены.
3. Hash вычисляется по точным сохранённым bytes; prefix/display payload не заменяет полный hash.
4. `identity.json` — byte-stable projection frozen identity внутри case, не второй writer.
5. Case и отдельные projections должны согласовываться.
6. Manifest не включает собственный digest; внешний baseline/CI pin может фиксировать его bytes.
7. Нельзя создавать hash cycle между case, manifest и replay metadata.
8. Частичный bundle не публикуется как completed.
9. Совпадение внутренних hashes не доказывает authenticity без trusted expected identity/pin. Self-consistent чужой bundle не становится локальным.

Точная identity serialization/hash normalization входит в U-01. Для source-tree identity переиспользуется существующий versioned `ContentHash` contract, а не новая параллельная функция с иной семантикой.

### 8.4. Sidecars: S-01 против S-09

S-01 определяет:

- размещение в bundle;
- path containment;
- наличие и согласованность `path`, `sha256`, `size`, `selector`, `schema_version`, `case_identity_ref`, `scope_digest`;
- run/attempt ownership;
- отсутствие admission при missing/foreign/tampered reference.

S-09 определяет:

- full rehydration и typed proof replay;
- recomputation verification status;
- stability attempts и no-best-of;
- cross-product replay orchestration;
- replay path compatibility старых layouts.

S-01 не дублирует typed proof engine и не создаёт второй replay schema. Common identity pins передаются единственному replay contract S-09/S-17.

## 9. Replay identity

При replay:

1. Выбирается конкретный persisted run и его ожидаемые pins.
2. Проверяются schema и eligibility legacy/migration.
3. Сверяются original case/run/attempt, advisory/ticket/source/artifact/build/configuration pins.
4. Проверяется bundle manifest и ссылки.
5. Из retained inputs восстанавливается та же identity.
6. Product-specific verifier выполняет предусмотренную recomputation.

Правила:

- Replay не создаёт новую live identity вместо original identity.
- Если создаётся отдельный replay-result artifact, у него собственная execution provenance и ссылка на original run; он не переписывает original evidence.
- Relocation bundle допустима, если relative references и content identity сохраняются.
- Mutable original source path, локальный `HEAD`, advisory API и model response не используются как fallback.
- Proof из другой attempt отвергается даже при одинаковом snapshot.
- Изменение ruleset/coverage/schema version не маскируется успешным replay прежней семантики.
- Persisted `VERIFIED` не является authority; его recomputation — ответственность S-02/S-09.

## 10. Migration и compatibility

### 10.1. Классы входов

| Вход | Допустимое поведение |
|---|---|
| Поддерживаемая canonical schema, complete pins | Обычная validation/replay |
| Известная старая versioned schema | Только явно зарегистрированное migration/replay rule |
| Unversioned Shadow case | Legacy; не принимается автоматически как canonical |
| Неизвестная schema/version | Refusal с named unsupported-schema reason |
| Повреждённый JSON/identity | Technical/refusal outcome; не successful decode с zero values |

### 10.2. Legacy `case.json` и `<caseID>.json`

Current filesystem case и отдельный research report — разные artifacts. Их нельзя определять одной эвристикой «есть поле `id`».

Для старых cases:

- отсутствие digest, identity state, scope или completeness не восполняется defaults;
- старый safe verdict сохраняется только как **historical result**, не как повторно подтверждённый verdict;
- historical reader/replay допускается только для явно поддержанной legacy schema с её ограничениями;
- legacy replay-only не выпускает новый authoritative VEX и не поддерживает admission в новом contract;
- если безопасный legacy reader недоступен, применяется explicit refusal, а не permissive loader.

### 10.3. Explicit migration

Migration разрешена только если поддержанное правило может получить все требуемые данные из retained, проверяемых inputs.

Она обязана:

- сохранить исходный artifact неизменным;
- создать новый bundle;
- записать source digest/schema, migrator version, field mapping и unresolved fields;
- не обращаться к mutable source/advisory для «восстановления старого факта»;
- не переносить доверие к старым `FALSE`/`VERIFIED` без необходимой recomputation;
- при недостающих данных выдавать migration-required/refusal либо честный non-admitting incomplete result по утверждённой матрице.

**Refusal допустим как явная compatibility policy.** Обязательна проверяемая матрица, а не обещание мигрировать любые исторические cases.

Rollback не должен возвращать canonical bundle в старый permissive loader и выпускать из него safe output. Новый run и historical artifact сохраняются раздельно.

Окончательные versions и поддержанный legacy inventory — **U-01**.

## 11. Failure semantics

Имена reason codes ниже — draft proposals, не существующие constants.

| Случай | Identity / technical outcome | Сохраняемое свидетельство | Semantic result / exit |
|---|---|---|---|
| Ticket package/version противоречит выбранному analyzed build | `IDENTITY_REFUSED` | `IDENTITY_COORDINATE_MISMATCH`, declared/resolved refs | Нет verdict; `2` |
| Advisory ID не принадлежит frozen ID/validated aliases | Refused | Advisory request и frozen pins | Нет verdict; `2` |
| Artifact/member не соответствует ожидаемому pin | Refused/integrity failure | Expected/observed digest/member | Нет verdict; `2` |
| Reference принадлежит другому run/attempt | Refused | `IDENTITY_FOREIGN_REFERENCE` | Нет admission; на boundary — error, `2` |
| После freeze изменились source/advisory/build bytes | Refused/stale integrity failure | `IDENTITY_STALE_INPUT` | Нет safe-negative; `2` |
| Обязательный анализу факт неизвестен, record валиден | `IDENTITY_INCOMPLETE` | Missing field и named reason | `INCONCLUSIVE`; `0`, если persistence успешна |
| Не заданы IDs/schema, невозможно сформировать корректный case | Technical input failure | Error artifact, если возможно | Нет verdict; `2` |
| Malformed supplied identity/digest/target | Refused или preflight technical failure | `IDENTITY_MALFORMED` | Нет verdict; `2` |
| Ticket supplied, но claims нельзя извлечь/проверить | Incomplete, если противоречие не установлено | Raw digest, parse/extraction limitation | Не silent match; `INCONCLUSIVE` |
| Ticket channel не запрашивался | Not applicable | Channel status | Само по себе не incomplete |
| Deployment channel не запрашивался | Explicit empty/not-provided set | Input manifest | Не доказывает isolation; дальнейшее поведение — S-13 |
| Mandatory release facts unavailable | Incomplete | Release channel failure | `INCONCLUSIVE`, не host/go.mod fallback |
| Sidecar missing/tampered/selector mismatch | Integrity failure | Reference и reason | Нет safe-negative; replay error/`2` |
| Не удалось сохранить case/bundle | Technical persistence failure | Stderr/CI failure, partial-output status | Нет semantic success; `2` |
| Unknown/legacy unsupported schema | Compatibility refusal | Schema/digest/reason | Нет нового authoritative verdict; `2` |

Current ticket guard слабее этого target gate: отдельные mismatches/parse failures сейчас могут оставлять другие closing routes доступными. Это **current→target semantic delta**, который должен быть отражён в migration и regression expectations, а не скрыт сохранением старого test assertion.

## 12. Security и trust

- Advisory/ticket/source/config/model text — untrusted input.
- LLM extraction — proposal. Canonical ID, package/version, source ref и target валидируются deterministic code.
- Adapter получает frozen identity read-only.
- Любое дополнение identity догадкой, подмена coordinate или расширение subject/target set отвергаются.
- Нельзя использовать unknown как wildcard.
- Нельзя копировать sidecar/observation в другой run и перепривязать локальным ID.
- Paths bundle-relative и confined; legacy absolute paths не допускаются в canonical path.
- Hashes подтверждают integrity относительно доверенных pins, но не заменяют provenance/authenticity.
- Секреты и credentials не записываются в manifests/audit; private evidence хранится вне публичного repo.
- Assumptions не становятся source/build facts.
- Все refusal/identity changes аудируются; отклонённый Product B proposal не меняет canonical case.

S-01 не вводит подписи, remote attestation или новый security service.

## 13. Observability

Каждое решение gate сохраняет:

- case/run/attempt;
- stage и identity state;
- reason code;
- затронутые fields/channels;
- expected/observed refs или безопасные digests;
- producer/schema version;
- ссылку на frozen input/audit artifact.

Нельзя записывать секретные raw values в error message.

Обязательные наблюдаемые категории:

```text
accepted
incomplete_by_field/reason
refused_by_mismatch_class
foreign_reference
stale_input
schema_refusal
migration_required
bundle_integrity_failure
persistence_failure
```

Это категории audit/evidence; точные metric names и operational retention принадлежат S-15/S-08b и не создаются вторым контрактом S-01.

## 14. Acceptance criteria

Все перечисленные tests/artifacts — **PLANNED**. Их названия являются предлагаемыми acceptance IDs, не заявлением о наличии или прохождении тестов.

| AC | Требования | Fixture / действие | Наблюдаемый результат | Evidence |
|---|---|---|---|---|
| **AC01** | R01, R08 | Canonical case round-trip | Required envelope/identity fields и ownership сохранены; нет второго case model | Schema/round-trip result |
| **AC02** | R02, R07 | Matching advisory/ticket/build | `IDENTITY_ACCEPTED`, неизменные raw pins | `identity-acceptance.json` |
| **AC03** | R02, R04, R07 | Package/version mismatch; wrong advisory и alias-negative | Refusal, exit `2`, semantic verdict отсутствует; не `NOT_AFFECTED` | Negative result matrix |
| **AC04** | R03, R09 | Foreign artifact/member, source→artifact substitution | Expected identity не совпадает; admission запрещён | Channel-binding report |
| **AC05** | R05, R07 | Host target, missing authoritative release facts, conflicting release target | Unknown required axis → incomplete; contradiction → refusal; нет authority promotion | Target/build matrix |
| **AC06** | R06 | Попытка изменить frozen ID/build/tags/config | Frozen record не меняется; требуется новый run | Freeze/mutation report |
| **AC07** | R06, R09, R12 | Два runs с одинаковым snapshot; перенос observation/sidecar между attempts | Foreign reference rejected, несмотря на совпадающие payload bytes | `cross-run-rejection.json` |
| **AC08** | R07 | По одному missing applicable field; no-ticket контроль | Missing → named incomplete; optional channel absence не объявляется mismatch | Requiredness matrix |
| **AC09** | R08 | Valid bundle; удаление required file; conflicting pin; path escape; partial publication | Valid bundle принимается; остальные не выглядят completed/admitted | `case-bundle-contract.json` |
| **AC10** | R09 | Sidecar tamper/removal/size/selector/scope/identity mutations | Fail closed; display prefix не используется как proof | Sidecar boundary report |
| **AC11** | R10 | Bundle перенесён; original mutable source недоступен; LLM/network запрещены | Identity восстанавливается только из retained inputs; original IDs сохранены | `replay-identity.json` |
| **AC12** | R10 | Altered replay advisory/build/rule/version pin | Drift/refusal/error, не новый safe-negative | Replay negative matrix |
| **AC13** | R11 | Unversioned cases с каждым отсутствующим новым полем; unknown version; forged legacy safe verdict | Только утверждённые migration/replay-only/refusal outcomes; нет silent admission | `migration-report.json` |
| **AC14** | R12 | Adapter/LLM proposal меняет version/ref/subject/target set | Canonical identity неизменна; proposal отвергнут и аудирован | Adapter non-widening report |
| **AC15** | R07–R08 | Persistence failure и malformed input через реальный entry point | Exit `2`; semantic success/VEX отсутствуют; причина наблюдаема | CLI/persistence result |
| **AC16** | Все | Pinned S-05 baseline после cutover | Нет unsupported safe-negative; drift и denominator объяснены | Baseline/CI manifest |

Каждая negative fixture проверяет не только наличие ошибки, но и **отсутствие safe output/admission**.

Для `INCONCLUSIVE` fixture проверяется наличие named limitation и semantic result, а не только exit `0`.

## 15. Test plan

### Unit

- Identity field validation, missing/null/not-applicable distinctions.
- Advisory ID/alias и version normalization.
- Freeze и immutability.
- Requiredness matrix по channels.
- Manifest path/hash/duplicate/size validation.
- Source tree hash version handling.

### Contract

- `AnalysisCase` envelope и wire mapping.
- Согласованность embedded identity и `identity.json`.
- Producer/consumer refs с ожидаемым run context.
- Source/artifact non-interchangeability.
- Sidecar envelope и adapter non-widening.
- Нет hash cycles case↔bundle manifest↔replay metadata.

### Integration

- Реальные Product A entry points проходят один gate.
- Ни classic workflow, ни research adapter не обходят frozen identity.
- Refusal/incomplete/persistence exit behavior.
- Reports/VEX не выпускаются как semantic success при refusal.
- Разные attempts не смешивают output.

### Replay

- Offline identity reconstruction и relocation.
- No LLM/network/mutable-path fallback.
- Cross-run/attempt и stale hash rejection.
- Typed proof recomputation проверяется совместно с S-09, не подменяется identity-only test.

### Migration

- Unversioned filesystem case.
- Existing research report как отдельный legacy format.
- Missing fields по одному.
- Unknown schema.
- Historical safe verdict без новых pins.
- Поддержанный migration rule — только на retained inputs, без доверия старому `VERIFIED`.

### Existing regression sources

Переиспользовать fixtures и patterns из:

- `internal/affected/ticket_test.go`: package mismatch, matching version, product drift, invalid ticket, absent module/package, no ticket;
- `internal/repository/contenthash_test.go`: stable hash, mutation, rename, containment, old JSON;
- `internal/research/replay_test.go`: missing/conflicting pins, attempt selection, tampered report;
- `internal/research/deterministic_payload_test.go`: externalized payload, tamper и sidecar binding;
- repository artifact/target/release metadata tests.

Старые assertions сначала сравниваются с target semantics. Их нельзя автоматически сохранить, если они разрешают то, что unified identity gate теперь запрещает.

### Evidence execution

После реализации CI/verification owner фиксирует точные команды в command manifest. Unit/contract suites могут запускаться через `go test -json` по затронутым packages; имя теста и package должны реально существовать.

Сохраняются: test output, fixture hashes, expected/observed matrix, code/spec revisions и hashes acceptance artifacts. Проверка «тесты компилируются» недостаточна.

## 16. Open questions / design unknowns

| ID | Priority | Нерешённое решение | Почему блокирует / способ закрытия | Owner |
|---|---|---|---|---|
| **U-01** | P1 | Окончательные schema IDs, точный JSON/Go field mapping, digest serialization и compatibility matrix | Без этого два implementers могут создать разные persisted contracts. Предложение: новые explicit versioned schemas, legacy без auto-admission. Закрытие: полный field mapping, schema examples/golden bytes, legacy inventory и точные migration/refusal outcomes | Shadow case owner + architect |
| **U-02** | P1 | Как bundle сохраняет полный replay closure: source bytes, dependency/build inputs, artifact/member и необходимые tool/rule pins | Одних `source-ref.json`/digest недостаточно для offline replay без mutable external state. Закрытие: точный packaging/locator contract и fixture, replayable после удаления original workspace и отключения сети | Repository owner + replay owner |
| **U-03** | P1 | Матрица обязательности `declared_package/version/component` для no-ticket, multi-entry advisory и known-absent module | Target одновременно допускает optional ticket и перечисляет mandatory declared coordinates. Нельзя ни выдумывать version, ни случайно запретить обычный no-ticket анализ. Закрытие: утверждённая per-channel matrix и AC08 fixtures | Architect + affected owner |
| **U-04** | P0 implementation prerequisite | G-26: approved normative delta, D17, согласование старого compatibility/source-priority правила, concrete ownership | Target §13.6 требует явного amendment до implementation S-01/S-02; текущие docs/ADRs этого не доказывают. Закрытие: section-level disposition, applied amendments и approval references | Architecture/repository owner |
| **U-05** | P2, не блокирует S-01 contract | Физическое имя Product B adapter package | S-01 не размещает Product B runtime; dependency direction уже запрещает второй domain. Закрывается S-06/S-16 | Integration owner |
| **U-06** | P1 release gate, не design-блокер S-01 | Срок и место долговременного хранения приватных baseline/sidecars | S-01 требует retained artifacts; operational policy и доступы фиксирует S-15 до соответствующего release gate | Operations owner |

Нет запроса пересмотреть dual-product architecture или предоставить LLM authority. Эти решения уже заданы Target.

## 17. Review record

| Проверка | Результат |
|---|---|
| Self-check против goals/Target | Draft подготовлен; current→target deltas и блокеры перечислены |
| Independent spec review | `SPEC REVISE` (2026-10-21); report: [`2026-10-21-08-s01-spec-review.md`](../reports/2026-10-21-08-s01-spec-review.md); 7 P1/P2 findings |
| Security review | Требуется; не проведён. Findings включают pre-freeze evidence bypass и prompt-injection fixture |
| Goal/architecture comparison итоговой ревизии | Направление соответствует goals/Target; итоговая ревизия не завершена до закрытия U-01–U-04 |
| Concrete owners/reviewers | Не назначены; блокирует `reviewed`/`approved` |
| Approval | Нет |
| Implementation plan | Не создавался; запрещён до spec DoR/review |
| Implementation/tests/evidence execution | Не выполнялись |

### Итоговый gate

```text
DESIGN GATE: BLOCKED для передачи в implementation
SPEC STATUS: draft
REVIEW: SPEC REVISE
PLAN-READINESS: NOT PLAN-READY
BLOCKERS: U-01, U-02, U-03, U-04; owner assignment; workflow revision
```

Следующий допустимый результат работы над S-01 — закрытые blocking decisions, обновлённый draft и независимое review. Не код и не implementation plan.

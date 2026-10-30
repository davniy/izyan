# План реализации уровней доказательности Shadow

**Цель:** добавить вычисляемую лестницу `L1/L2/L3` в research-report без ослабления границы доверия, без продвижения агентских claims и без изменения поведения старых `/1` и `/2` reports.

**Архитектура:** новый аддитивный marker `slice2-fidelity/3`; `evidence_level` вычисляется assembler’ом из сохранённых deterministic facts и condition ledger, затем повторно вычисляется validator’ом и сравнивается с сохранённым значением. Replay использует тот же чистый derivation path и не вызывает модель.

**Tech stack:** Go 1.25 из `go.mod`, стандартные Go tests, Python 3 для офлайн-драйвера saved-data regression, существующий `izyan research --replay-agent-turn`.

**Spec / ADR:**

- `docs/dev/decisions/agent7-shadow-base-decision.md`
- `.superpowers/sdd/2026-10-13-01-shadow-usability-plan/evidence-levels-design-revB.md`
- `.superpowers/sdd/2026-10-13-01-shadow-usability-plan/evidence-levels-design-revB-addendum.md`

**Пути:** `<VA_REPO>` — корень репозитория (`vuln-analyzer-shadow`); `<VA_TMP>` — приватный каталог прогонов вне репозитория.

## Global Constraints

1. Сохранить `schema=research-report/1`; не вводить `research-report/2`.
2. Новый marker — только `slice2-fidelity/3`. `/1`, `/2` и `/3` взаимоисключающие.
3. `/3` означает все действующие требования `/2` плюс обязательные `role` и `evidence_level`.
4. `attack_scenario` сохраняется рядом с новым `evidence_level`; это additive change.
5. `L1` означает завершённый обязательный SOURCE-SCOPE path. Условие `runtime/deployment posture` получает `role=deployment` и не блокирует `L1`.
6. `L2` означает незамкнутую цепочку path conditions.
7. `L3` разрешён только при динамически подтверждённой эксплуатации через verified fact.
8. `evidence_level` — производное поле. Агент не может задавать его напрямую. Assembler вычисляет его, validator обязан пересчитать и сравнить результат fail-closed.
9. Агентская гипотеза никогда не повышает уровень и никогда не является evidence carrier.
10. Если агентский claim нормализован assembler’ом в canonical `role=path`, condition остаётся `OPEN`/`UNCONFIRMED` и блокирует `L1`. Ненормализуемый claim остаётся agent hypothesis/limitation и сам по себе уровень не меняет.
11. `PARTIAL` разрешён только при незакрытых path-role transitions. Открытое deployment condition само по себе не делает `attack_scenario=PARTIAL`.
12. `SUPPORTED` разрешён только с `L3`.
13. `disposition` остаётся `REVIEW_REQUIRED`; `auto_close=false`. Не добавлять VEX, auto-close, authoritative negative conclusions или автоматическое закрытие finding.
14. Не запускать model runs, prompt tuning, новые prompt experiments или новые corpora.
15. Sandbox и существующая граница чтения/выполнения не меняются.
16. Verified facts создаются только deterministic lane. Agent assertions не promoted.
17. Сохранённые агентские ответы и artifact bytes не переписывать.
18. Saved-data verification выполняется офлайн по:
   - primary: `tmp/exploitable/runs/<UNIT>/agent-v2`;
   - retry: `tmp/exploitable-retry*/runs/<UNIT>/agent`.
19. Ожидаемые saved-data matrices:
   - primary: `7 × L1` — `C01, C03, C07, C14, C15, C16, C17`; `24 × L2`; `0 × L3`;
   - retry, оба набора вместе: `2 × L1` — `C01, C03`; `9 × L2`; `0 × L3`.
20. Приватное соответствие `C`-labels к исходным unit identifiers не включать в код, документацию или этот план. В committed тексте и тестовых сообщениях использовать только `C01`–`C31`.
21. Финальный gate после всех изменений:
   ```bash
   cd <VA_REPO>
   gofmt -w internal/research/*.go cmd/izyan/*.go
   test -z "$(gofmt -l .)"
   go vet ./...
   go test ./...
   ```

## Review Focus

Reviewer обязан отдельно проверить:

- **Trust boundary:** только deterministic verified facts могут быть carrier evidence; agent assertions, `agent-src:` refs и agent-only conditions не повышают уровень.
- **Recompute vs asserted level:** assembler и validator используют один чистый derivation helper; validator не доверяет значениям `evidence_level`, присланным или восстановленным из внешнего JSON.
- **Agent normalization:** canonical path hypothesis получает `role=path`, `state=OPEN`, остаётся blocker; произвольный agent claim получает `role=supporting` и не влияет на ladder.
- **Deployment semantics:** `runtime/deployment posture` и `inbound listener` получают `role=deployment`; deployment gap не блокирует `L1`.
- **`attack_scenario`:** `PARTIAL` появляется только из path-role gaps; `SUPPORTED` появляется только вместе с dynamic proof и `L3`.
- **Compatibility:** старые `/1` и `/2` reports валидируются без `evidence_level` и без `role`; `/3` требует новые поля.
- **Replay:** ladder вычисляется из сохранённых артефактов и pinned refs, без model/harness call; output byte-stable при одинаковом входе.
- **UX:** render не допускает интерпретаций «безопасно» или «неэксплуатируемо»; отсутствие `L3` явно означает только отсутствие динамического доказательства.

### Task 1: Контрактные типы и marker `/3`

**Depends on:** None

**Scope:** добавить wire-типы, enum values, `role` в `ExploitationCondition`, `evidence_level` в `Report` и новый extension marker без изменения старых JSON-контрактов.

**Files/symbols:**

- Modify: `internal/research/types.go:24-31` — extension constants.
- Modify: `internal/research/types.go:286-313` — `Report`.
- Modify: `internal/research/types.go:400-408` — рядом с `ExploitationAxes`.
- Modify: `internal/research/types.go:584-597` — `ExploitationCondition`.
- Modify: `internal/research/assemble.go:102-170` — `normalizeEmpty`.
- Create: `internal/research/evidence_level_contract_test.go:1` — contract and JSON compatibility tests.

**Interfaces:**

```go
const Slice2ExtensionV3 = "slice2-fidelity/3"

const (
    EvidenceLevelL1 = "L1_STATIC_PATH"
    EvidenceLevelL2 = "L2_POTENTIAL_PATH"
    EvidenceLevelL3 = "L3_DYNAMIC_EXPLOITATION"
)

const (
    EvidenceBasisNone          = "none"
    EvidenceBasisDeterministic = "deterministic"
    EvidenceBasisDynamic       = "dynamic"
)

const (
    ConditionRoleApplicability = "applicability"
    ConditionRolePath          = "path"
    ConditionRoleDeployment    = "deployment"
    ConditionRoleSupporting    = "supporting"
)
```

```go
type EvidenceLevel struct {
    Level              string   `json:"level"`
    Basis              string   `json:"basis"`
    Statement          string   `json:"statement"`
    Scope              string   `json:"scope"`
    ConditionRefs      []string `json:"condition_refs"`
    EvidenceRefs       []string `json:"evidence_refs"`
    BlockingConditions []string `json:"blocking_conditions"`
    Limitations        []string `json:"limitations"`
}
```

```go
type Report struct {
    // existing fields unchanged
    EvidenceLevel *EvidenceLevel `json:"evidence_level,omitempty"`
}
```

```go
type ExploitationCondition struct {
    // existing fields unchanged
    Role string `json:"role,omitempty"`
}
```

**Change:**

1. Добавить `Slice2ExtensionV3`, не менять значения `/1` и `/2`.
2. Добавить закрытые enum values для уровней, basis и roles.
3. Сделать `Report.EvidenceLevel` указателем с `omitempty`. Это обязательно для сохранения старого wire output у `/1` и `/2`.
4. Сделать `ExploitationCondition.Role` `omitempty`. Для старых reports отсутствие роли допустимо; обязательность роли проверяется только в `/3`.
5. В `normalizeEmpty` нормализовать все slices внутри `EvidenceLevel` в пустые массивы, а не `null`.
6. Не добавлять отдельный wire schema version.
7. Добавить tests:
   - `/3` marker существует и имеет точное значение;
   - `EvidenceLevel` round-trip через `json.Marshal`/`ParseReport`;
   - старый JSON без `evidence_level` и `role` продолжает парситься;
   - `omitempty` не добавляет новые поля в legacy JSON.

**Acceptance criteria:**

- Типы компилируются и round-trip без потери полей.
- Новые assembled reports смогут содержать `evidence_level`.
- Legacy `/1` и `/2` JSON не получают обязательное пустое поле `evidence_level`.
- Enum values закрыты указанными строками; значения `agent`, `safe`, `UNKNOWN_LEVEL` и другие не добавляются.

**Exact validation commands:**

```bash
cd <VA_REPO>
go test ./internal/research -run 'TestEvidenceLevelContract|TestEvidenceLevelLegacyJSON'
go test ./internal/research
```

**Do-not:**

- Не менять `ReportSchema`.
- Не переименовывать `attack_scenario`.
- Не заменять `ExploitationAxes`.
- Не делать `EvidenceLevel` обязательным для `/1` или `/2`.
- Не добавлять `basis=agent`.
- Не добавлять ticket identifiers или исходные unit identifiers в fixtures и сообщения tests.

### Task 2: Role inference и deterministic derivation ladder

**Depends on:** Task 1

**Scope:** изменить assembler так, чтобы он назначал roles, нормализовал canonical agent path hypotheses, пересчитывал `attack_scenario` по семантике B и вычислял `evidence_level` с приоритетом `L3 → L1 → L2`.

**Files/symbols:**

- Modify: `internal/research/assemble.go:32-114` — marker assignment and `Assemble`.
- Modify: `internal/research/assemble.go:674-685` — agent attack conditions.
- Modify: `internal/research/slice2.go:688-719` — рядом с `slice2Axes`.
- Modify: `internal/research/slice2.go:868-951` — `slice2AttackStatus`.
- Modify: `internal/research/slice2.go:962-966` — centralized condition assignment.
- Create: `internal/research/evidence_level_derivation_test.go:1` — derivation and role tests.

**Interfaces:**

```go
func conditionRoleForSubject(subject string) string
```

Fixed inference table:

| Subject | Role |
|---|---|
| `affected module presence` | `applicability` |
| `affected version in use` | `applicability` |
| `affected package reachable` | `path` |
| `affected package build-relevant` | `path` |
| `runtime/deployment posture` | `deployment` |
| `inbound listener` | `deployment` |
| любой другой subject | `supporting` |

```go
func (a *assembler) slice2ConditionRoles(r *Report)
```

```go
func deriveEvidenceLevel(r *Report) EvidenceLevel
```

```go
func (a *assembler) slice2EvidenceLevel(r *Report)
```

**Change:**

1. `Assemble` должен выдавать `ContractExtensions = []string{Slice2ExtensionV3}` для новых reports.
2. Добавить `slice2ConditionRoles` после того, как deterministic и agent conditions уже собраны, но до вычисления `attack_scenario` и `evidence_level`.
3. Role всегда назначается assembler’ом по фиксированной таблице. Значение role из agent output не читается и не доверяется.
4. Для agent condition:
   - если subject нормализуется ровно в `subjPackageReach` или `subjBuildRelevant`, назначить `role=path`, `necessity=required`, `state=OPEN`;
   - если subject не является canonical path predicate, назначить `role=supporting`, сохранить agent hypothesis отдельно;
   - никогда не создавать verified fact из такого условия.
5. Для deterministic conditions назначить role по subject table. `runtime/deployment posture` не должен попадать в blocking set L1.
6. Изменить `slice2AttackStatus`:
   - подтверждённый transition считать только для `role=path`, `origin=deterministic`, `state=SUPPORTED` и разрешимой verified fact;
   - `reqUnknown` считать только среди обязательных `role=path` conditions;
   - `role=deployment` не создаёт `PARTIAL`;
   - `SUPPORTED` оставить зависящим от `exploitation_established=ESTABLISHED`;
   - deployment-only unknown оставляет `attack_scenario=UNKNOWN`.
7. Реализовать `deriveEvidenceLevel` как чистую функцию, не читающую `r.EvidenceLevel`.
8. Порядок вычисления:
   - сначала L3;
   - затем L1;
   - иначе L2.
9. L3 требует одновременно:
   - `exploitation_established.status=ESTABLISHED`;
   - `basis=dynamic`;
   - `level=DYNAMIC_REPRODUCTION`;
   - verified fact с tool `runtime-observation`, `dynamic-trace` или `reproduction`;
   - та же fact ref присутствует в `EvidenceLevel.EvidenceRefs`;
   - `attack_scenario.status=SUPPORTED`.
10. L1 требует:
    - непустой набор обязательных conditions;
    - обязательные `applicability` и `path` conditions закрыты;
    - каждое закрытое condition имеет `origin=deterministic`, `state=SUPPORTED`;
    - каждое такое condition имеет verified fact со `status=OK`;
    - fact tool входит в статический allowlist;
    - deployment conditions не являются blockers;
    - `exploitation_established` не `ESTABLISHED`;
    - `attack_scenario` не `SUPPORTED` и не `PARTIAL`.
11. В L1 static allowlist включить только:
    - `affected-resolve`, `get_module_version`, `get_dependency_graph`;
    - `module_usage`, `module_internal_reach`, `find_symbol`, `find_callers`, `find_may_callers`, `find_dep_callers`, `ingress-inventory`;
    - `find_entrypoints`, `listen-sites`, `inbound-auth-facts`, `interface_dispatch_sites`, `gated_refs`, `scan_dynamic`, `dial-sites`;
    - `trace_argument`, `find_validations`, `check_call_site_guard`, `dep_invocation_state`.
12. `run_govulncheck` может быть supporting evidence, но не L1 path carrier.
13. L2 назначить, если L3 и L1 не выполнены. `basis=deterministic`, если есть хотя бы один релевантный verified deterministic fact; иначе `basis=none`.
14. `condition_refs` формировать в порядке `r.ExploitationConditions`, без duplicates.
15. `evidence_refs` формировать в стабильном порядке, без map iteration:
    - для L3 — порядок `ExploitationAxes.ExploitationEstablished.EvidenceRefs`;
    - для L1/L2 — порядок conditions и refs внутри conditions;
    - agent refs никогда не включать.
16. `blocking_conditions` для L1/L2 содержит только незакрытые обязательные `applicability`/`path` conditions. Deployment gaps и supporting claims туда не включать.
17. Добавить фиксированные русскоязычные statements и limitations, включая смысл:
    - L1 не означает безопасность и не подтверждает runtime exploitation;
    - L2 означает незавершённое доказательство candidate path;
    - L3 означает наличие execution/reproduction/runtime evidence;
    - отсутствие L3 не означает `not exploitable`.

**Acceptance criteria:**

- Новые reports получают `/3`, roles и `evidence_level`.
- `runtime/deployment posture` всегда имеет `role=deployment` и не блокирует L1.
- Canonical agent path hypothesis остаётся `OPEN` и блокирует L1.
- Ненормализованный agent claim имеет `role=supporting` и не является carrier.
- `PARTIAL` не появляется из одного deployment gap.
- Изменение agent category/status не повышает уровень.
- Synthetic fixtures покрывают:
  - полный static path без dynamic proof → L1;
  - path gap → L2;
  - deployment-only gap при закрытом source path → L1;
  - dynamic verified fact → L3;
  - agent-only claim → не выше L2;
  - failed dynamic observation → не L3.
- Derivation дважды на одном report выдаёт байт-идентичный `EvidenceLevel`.

**Exact validation commands:**

```bash
cd <VA_REPO>
go test ./internal/research -run 'TestEvidenceLevelDerivation|TestConditionRole|TestAttackStatus'
go test ./internal/research
```

**Do-not:**

- Не считать `runtime/deployment posture` blocker для L1.
- Не считать только module presence или version-in-use достаточным exploit-path transition.
- Не считать agent assertion доказательством.
- Не поднимать `exploitation_established` без dynamic verified fact.
- Не использовать map iteration для порядка refs.
- Не менять prompt, harness или deterministic tool scope.

### Task 3: Fail-closed validator для `/3`

**Depends on:** Task 2

**Scope:** добавить строгую `/3` validation ветку, которая проверяет roles, ladder, refs, attack status и exact recomputation.

**Files/symbols:**

- Modify: `internal/research/validate.go:44-64` — extension dispatch.
- Modify: `internal/research/validate.go:378-392` — marker detection and mutual exclusion.
- Modify: `internal/research/validate.go:826-1123` — shared `/2` validation and condition rules.
- Add: `internal/research/validate.go:1125` — `validateSlice2V3`.
- Create: `internal/research/evidence_level_validate_test.go:1` — negative and positive validator cases.

**Interfaces:**

```go
func (e *ValidationError) validateSlice2V3(r *Report, refs *refSpace)
```

`validateSlice2V3` вызывается только для `slice2-fidelity/3` и после общих `/1` и `/2` checks.

**Change:**

1. Расширить dispatch до `v1`, `v2`, `v3`.
2. Сделать все комбинации marker values взаимоисключающими:
   - `/1` + `/2`;
   - `/1` + `/3`;
   - `/2` + `/3`;
   - `/1` + `/2` + `/3`.
3. Для `/3` запускать существующие `/1` и `/2` checks без ослабления правил, затем `validateSlice2V3`.
4. Проверить `EvidenceLevel != nil`.
5. Проверить закрытые enum:
   - `level ∈ {L1_STATIC_PATH, L2_POTENTIAL_PATH, L3_DYNAMIC_EXPLOITATION}`;
   - `basis ∈ {none, deterministic, dynamic}`;
   - role ∈ `{applicability, path, deployment, supporting}`.
6. Проверить непустые `statement`, `scope`, `condition_refs`; проверять отсутствие duplicates и разрешимость всех condition IDs.
7. Проверять role matrix:
   - deterministic condition role должен совпадать с фиксированной subject table;
   - agent canonical path condition должен быть `role=path`, `state=OPEN`, `necessity=required`;
   - ненормализуемый agent claim должен быть `role=supporting`;
   - deployment role не должен считаться path blocker.
8. Проверять evidence refs:
   - `EvidenceLevel.EvidenceRefs` должны разрешаться только в `verified_facts`;
   - `agent-src:`, agent assertion refs, observation-only refs и advisory refs запрещены в `EvidenceLevel.EvidenceRefs`;
   - L1 carrier facts должны иметь `status=OK` и static tool;
   - L3 carrier facts должны иметь dynamic tool из закрытого набора;
   - `blocking_conditions` должны быть subset `condition_refs`.
9. Вызвать `deriveEvidenceLevel(r)` и сравнить с заявленным объектом целиком: `Level`, `Basis`, statements, scope, refs, blockers и limitations. Любое несовпадение — validation error.
10. Добавить status cross-rules:
    - L3 требует `attack_scenario=SUPPORTED`;
    - `attack_scenario=SUPPORTED` требует L3;
    - `attack_scenario=PARTIAL` требует L2;
    - `PARTIAL` требует path-role gap;
    - L1 запрещает `SUPPORTED` и `PARTIAL`;
    - L1/L2 запрещают `basis=dynamic`;
    - L3 запрещает `basis=none`/`deterministic`.
11. Сохранить текущую `/2` ветку неизменной для reports, которые рекламируют только `/2`.
12. Добавить отрицательные tests:
    - forged L1 при обязательном path `UNKNOWN`;
    - forged L1 при unresolved evidence ref;
    - forged L1 с agent-only ref;
    - forged L3 без dynamic verified fact;
    - forged L3 с failed dynamic observation;
    - `SUPPORTED` при L1/L2;
    - `PARTIAL` при L1/L3;
    - `PARTIAL` только из deployment gap;
    - неизвестный level/basis/role;
    - mismatch между recomputed и asserted `EvidenceLevel`;
    - duplicate/missing `condition_refs`;
    - `/3` без `evidence_level`;
    - любой marker combination.

**Acceptance criteria:**

- Validator fail-closed отклоняет каждую перечисленную negative case.
- Validator принимает assembled synthetic L1, L2 и L3 reports.
- Agent assertions не могут попасть в `EvidenceLevel.EvidenceRefs`.
- `/1` и `/2` reports без новых полей продолжают проходить прежние ветки.
- Потеря или подмена одной fact ref приводит к ошибке, а не к молчаливому downgrade.

**Exact validation commands:**

```bash
cd <VA_REPO>
go test ./internal/research -run 'TestEvidenceLevelValidator|TestSlice2V3_Validator|TestSlice2V3_ExtensionDispatch'
go test ./internal/research -run 'TestSlice2_LegacyReportStillValidates|TestSlice2V2'
go test ./internal/research
```

**Do-not:**

- Не принимать заявленный `evidence_level` без recomputation.
- Не считать `agent-src:` или agent assertion ref verified evidence.
- Не менять `/1` и `/2` validation rules.
- Не делать validator repair function.
- Не преобразовывать validation error в L2.
- Не разрешать L3 на основании текста, axis label или agent statement.

### Task 4: Render/UX и сохранение facts/hypotheses/unknowns

**Depends on:** Task 2

**Scope:** вывести ladder отдельным блоком и добавить постоянный disclaimer, не смешивая deterministic facts, agent hypotheses и unknown conditions.

**Files/symbols:**

- Modify: `internal/research/render.go:226-229` — existing separation comment and logic.
- Modify: `internal/research/render.go:327-355` — exploitation conditions section.
- Modify: `internal/research/render.go:538-544` — appendix condition rendering.
- Modify: `docs/cli.md:267-280` — research output/replay description.
- Modify: `internal/research/assemble_test.go:323-365` — byte stability assertions.
- Create: `internal/research/evidence_level_render_test.go:1`.

**Interfaces:**

```go
func RenderMarkdown(r *Report) ([]byte, error)
func RenderJSON(r *Report) ([]byte, error)
```

Добавить внутренний helper:

```go
func renderEvidenceLevel(b *bytes.Buffer, level *EvidenceLevel)
```

**Change:**

1. Для `/3` перед exploitation axes вывести отдельный блок `Evidence level`.
2. В блоке показать:
   - level;
   - basis;
   - statement;
   - scope;
   - condition refs;
   - evidence refs;
   - blockers;
   - limitations.
3. Использовать стабильные русскоязычные labels:
   - `L1 — статически подтверждённый путь`;
   - `L2 — потенциальный путь`;
   - `L3 — динамически подтверждённая эксплуатация`.
4. В каждом `/3` report вывести постоянный disclaimer:

   > Уровень описывает доказанность exploit path, а не безопасность продукта. Отсутствие L3 означает отсутствие динамического доказательства, но не означает `not exploitable`.

5. Не использовать формулировки, которые превращают L1 в conclusion о безопасности или L2 в conclusion об отсутствии эксплуатации.
6. Сохранить существующие отдельные группы:
   - deterministic confirmed facts;
   - agent hypotheses;
   - unknown conditions;
   - conflicted/retracted states.
7. В appendix добавить `role` при выводе полной condition строки, не удаляя `origin`, `necessity` или `state`.
8. Для legacy reports без `EvidenceLevel` не выводить новый обязательный `/3` блок, чтобы `/1` и `/2` rendering path оставался совместимым.
9. Обновить `docs/cli.md`, указав, что `/3` ladder derived, не является verdict, а replay не вызывает модель.
10. Проверить Markdown и JSON byte stability после marshal/unmarshal и повторного render.

**Acceptance criteria:**

- `/3` report содержит level block и disclaimer.
- В render одновременно видны facts, hypotheses и unknowns в отдельных группах.
- `L1` не отображается как утверждение безопасности.
- `L2` не отображается как отрицательный conclusion.
- Повторный Markdown и JSON render дают одинаковые bytes.
- Legacy `/1`/`/2` reports продолжают render без необходимости `EvidenceLevel`.

**Exact validation commands:**

```bash
cd <VA_REPO>
go test ./internal/research -run 'TestRender_EvidenceLevel|TestRender_ByteStable'
go test ./internal/research
```

**Do-not:**

- Не заменять `attack_scenario` новым блоком.
- Не удалять существующие facts/hypotheses/unknowns.
- Не скрывать agent claims; показывать их как unverified hypotheses.
- Не выводить `safe`, «безопасно», «неэксплуатируемо» или эквивалентные conclusions.
- Не вычислять новый уровень внутри renderer.
- Не делать model call из render path.

### Task 5: Replay parity и сохранение pinned artifacts

**Depends on:** Tasks 2–4

**Scope:** обеспечить fail-closed replay для `/3`, сохранение agent/extraction status и artifact pins, а также byte-stable derivation без model call.

**Files/symbols:**

- Modify: `internal/research/replay.go:13-28` — replay contract documentation.
- Modify: `internal/research/replay.go:38-121` — persisted report parsing and status checks.
- Modify: `internal/research/replay.go:121-195` — artifact pin validation.
- Modify: `internal/research/replay.go:224-260` — answer reparse and status preservation.
- Modify: `internal/research/replay_test.go:148-223,226-328`.
- Modify: `cmd/izyan/research.go:87-216` — replay/assemble integration only if required by new `/3` validation.
- Modify: `cmd/izyan/research_test.go:1-45`.

**Interfaces:**

```go
func LoadPersistedAgentTurn(dir string) (*AgentTurn, error)
```

Existing replay contract remains:

```text
OK | INVALID_FORMAT | FAILED | TIMEOUT | PROVIDER_REFUSED
```

**Change:**

1. Preserve current fail-closed checks:
   - closed-schema parse;
   - unambiguous agent attempt;
   - matching attempt status;
   - all artifact SHA-256 pins;
   - matching size/selector metadata;
   - retained answer/result bytes.
2. If persisted report advertises `/3`, validate its derived `evidence_level` before accepting replay input. A forged or mismatched level must abort replay.
3. If persisted report advertises `/1` or `/2`, keep the existing compatibility path and do not require `role` or `evidence_level`.
4. Keep `strictExtract` as the only answer parser. Do not rederive a non-OK status into `OK`.
5. Replay output must be assembled through the same `deriveEvidenceLevel` path as a live assembled report. No second ladder implementation in `replay.go`.
6. Add tests proving:
   - replayed `AgentOutput.Status` equals saved status;
   - saved extraction status remains unchanged;
   - `AnswerArtifact`, `ResultArtifact` and SHA-256 pins remain unchanged;
   - saved `Attempt` identity, timestamps and extraction remain preserved;
   - `disposition=REVIEW_REQUIRED`, `auto_close=false`;
   - tampered `/3` `evidence_level` fails before report emission;
   - missing or changed pinned bytes fail closed;
   - same saved input rendered twice produces byte-identical ladder and report JSON;
   - `/1` and `/2` persisted fixtures still replay/load without new fields.
7. Extend CLI test to assert replay remains mutually exclusive with `--deterministic-only`/`--no-agent` and does not invoke a model.

**Acceptance criteria:**

- Replay never calls model or harness.
- Replayed status and extraction status are byte/enum-preserved.
- Artifact pins are preserved and rechecked.
- `/3` ladder is recomputed, not trusted from saved JSON.
- Tampered level, missing artifact or digest mismatch fails closed.
- `/1` and `/2` replay compatibility remains intact.

**Exact validation commands:**

```bash
cd <VA_REPO>
go test ./internal/research -run 'TestReplayLoad|TestValidate_ReplayedFrom|TestReplayEvidenceLevel'
go test ./cmd/izyan -run 'TestResearch_Replay'
go test ./internal/research ./cmd/izyan
```

**Do-not:**

- Не запускать model/harness из replay path.
- Не менять saved agent status на основании текущего extractor result для non-OK turns.
- Не переписывать saved answer, result или extraction JSON.
- Не принимать mismatch между `agent_output.status` и attempt status.
- Не использовать mutable canonical artifact path вместо pinned retained artifact.

### Task 6: Офлайн-регрессия по saved sets

**Depends on:** Tasks 1–5

**Scope:** добавить воспроизводимый драйвер, который запускает deterministic lane с `--replay-agent-turn`, собирает только временные outputs и проверяет matrices, negative invariants, compatibility и replay preservation.

**Files/symbols:**

- Create: `tools/evidence-levels-replay.py:1`.
- Required functions:
  - `discover_primary_runs(...)`;
  - `discover_retry_runs(...)`;
  - `read_run_manifest(...)`;
  - `replay_one(...)`;
  - `assert_saved_status_and_pins(...)`;
  - `assert_evidence_matrix(...)`;
  - `main(...)`.
- Test/verification integration:
  - `internal/research/evidence_level_validate_test.go:1`;
  - `internal/research/replay_test.go:148-328`;
  - `internal/research/slice2_test.go:443-496` for existing legacy compatibility.

**Interfaces:**

Command-line interface:

```text
python3 tools/evidence-levels-replay.py
  --primary-root <.../tmp/exploitable/runs>
  --primary-suffix agent-v2
  --retry-glob <.../tmp/exploitable-retry*/runs>
  --label-map <private runtime-only map>
  --izyan <compiled binary>
  --govulndb <local frozen DB>
  --modcache <declared module cache>
  --work-dir <temporary output root>
```

The driver must emit only opaque labels `C01`–`C31` in summaries and errors. It must not print or persist the private unit identifiers.

**Change:**

1. Discover exactly 31 primary run directories matching:
   ```text
   tmp/exploitable/runs/<UNIT>/agent-v2
   ```
2. Discover retry reports from all directories matching:
   ```text
   tmp/exploitable-retry*/runs/<UNIT>/agent
   ```
3. Read the saved report and run manifest to obtain:
   - snapshot path;
   - advisory path;
   - vulnerability identifier;
   - external snapshot commit when present;
   - original agent status;
   - saved extraction status;
   - saved artifact pins.
4. For every case invoke the compiled CLI with:
   ```text
   izyan research
     --snapshot <saved snapshot>
     --cve <saved vulnerability id>
     --advisory-file <saved advisory>
     --output-dir <temporary output>
     --replay-agent-turn <saved run directory>
     --govulndb <local frozen DB>
     --modcache <declared module cache>
   ```
5. Set:
   ```text
   GOPROXY=off
   GOSUMDB=off
   GOFLAGS=-mod=readonly
   ```
6. Never pass live agent flags and never invoke `--deterministic-only` together with replay.
7. Validate each replay output:
   - `report.json` parses and passes `ValidateFile`;
   - marker is `/3`;
   - `evidence_level` is present;
   - `agent_output.status` equals saved status;
   - `agent_output.extraction.status` equals saved extraction status;
   - artifact paths, SHA-256, sizes and selectors remain equal;
   - `agent_output.replayed_from` is present;
   - `disposition.class=REVIEW_REQUIRED`;
   - `disposition.auto_close=false`;
   - no agent ref occurs in `evidence_level.evidence_refs`;
   - `exploitation_established` is not `ESTABLISHED` unless a saved dynamic verified fact exists.
8. Assert exact matrices:
   ```text
   primary:
     total=31
     L1=7: C01,C03,C07,C14,C15,C16,C17
     L2=24
     L3=0

   retry aggregate:
     total=11
     L1=2: C01,C03
     L2=9
     L3=0
   ```
9. Run the negative validator suite from Task 3 as part of this task’s gate.
10. Run the existing `/1` and `/2` compatibility tests against saved fixtures. Reports without `evidence_level` must continue to validate.
11. Ensure the driver writes only to `--work-dir`; source saved directories remain byte-for-byte untouched.
12. State in the driver help and output that this task uses **no model runs** and no live harness calls.

**Acceptance criteria:**

- Exactly 31 primary and 11 retry reports are processed.
- The exact expected matrices pass.
- Any missing case, unexpected extra case, level mismatch, status mutation, extraction mutation, pin mutation or disposition mutation fails the command.
- No source saved report or artifact is modified.
- No model/harness invocation occurs.
- `/1` and `/2` compatibility tests pass.
- All negative validator cases pass.
- Repeating the complete saved-data command with the same inputs yields byte-identical `evidence_level` JSON for every case.

**Exact validation commands:**

```bash
cd <VA_REPO>

go build -o "$(mktemp -d)/izyan" ./cmd/izyan

VA_TMP_ROOT=<VA_TMP>
WORK_DIR="$(mktemp -d)"
IZYAN_BIN="$(find /tmp -type f -name izyan -perm -111 -print -quit)"

GOPROXY=off \
GOSUMDB=off \
GOFLAGS=-mod=readonly \
python3 tools/evidence-levels-replay.py \
  --primary-root "$VA_TMP_ROOT/exploitable/runs" \
  --primary-suffix agent-v2 \
  --retry-glob "$VA_TMP_ROOT/exploitable-retry*/runs" \
  --label-map ".superpowers/sdd/2026-10-13-01-shadow-usability-plan/ticket-labels.json" \
  --izyan "$IZYAN_BIN" \
  --govulndb "$VA_TMP_ROOT/govulndb" \
  --modcache "$HOME/go/pkg/mod" \
  --work-dir "$WORK_DIR"
```

Focused compatibility and negative checks:

```bash
cd <VA_REPO>
go test ./internal/research -run 'TestEvidenceLevelValidator|TestReplayEvidenceLevel|TestSlice2_LegacyReportStillValidates|TestSlice2V2'
```

Final gate:

```bash
cd <VA_REPO>
gofmt -w internal/research/*.go cmd/izyan/*.go
test -z "$(gofmt -l .)"
go vet ./...
go test ./...
```

**Do-not:**

- Не запускать model runs.
- Не запускать live harness.
- Не использовать исходные unit identifiers в committed code, output или test names.
- Не читать или коммитить приватную label map в изменённом виде.
- Не изменять saved source directories.
- Не переписывать saved reports ради добавления `/3`.
- Не считать отсутствие L3 отрицательным conclusion.
- Не скрывать failed или invalid agent statuses.
- Не заменять replay новым model execution path.
- Не считать успешный replay доказательством автоматического закрытия finding.

## Dependency / Execution Order

```text
Task 1
  -> Task 2
      -> Task 3
      -> Task 4
          -> Task 5
              -> Task 6
```

Task 3 и Task 4 могут выполняться параллельно после Task 2, если Task 3 не меняет render files. Task 5 начинается только после согласования derivation и validator contracts. Task 6 — последняя implementation task: он требует завершённых `/3` types, assembler, validator, render и replay paths и выполняется без model runs.
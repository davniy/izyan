# B42 — план реализации фактов уровня пакета и использования

**Файл плана:** `docs/dev/plans/2026-10-14-01-package-level-facts-plan.md`

**Цель:** добавить детерминированный, ограниченный проверкой по исходному коду факт уровня пакета/символа, чтобы `package_present` и `build_relevant` становились определёнными только при наличии проверяемого доказательства, а факт «пакет/символ присутствует, но продуктовым кодом не используется» оставался сильным `REFUTED`-условием без перехода к L1 или автоматическому закрытию.

**Архитектура:**

1. `affected.GoResolver` проецирует advisory-declared symbols в package paths. Если advisory содержит только module + version range и не содержит package/symbol, package-level subject не выдумывается и остаётся `UNKNOWN`.
2. Новый детерминированный инструмент `package-usage` проверяет один advisory-declared package/symbol в scope текущего product source closure.
3. Результат инструмента имеет три состояния:
   - `USED` — найден конкретный product-source import/reference/call;
   - `NOT_USED` — выполнена закрытая bounded negative verification;
   - `UNKNOWN` — scope неполон, проверка не выполнена или есть неразрешённый dynamic/dispatch gap.
4. В отчёте появляется required path condition `affected package/symbol used by product code`.
5. Положительный результат может закрыть package/build path conditions и дать возможность L1.
6. Отрицательный результат создаёт `REFUTED` path condition, блокирует L1 и никогда не становится безопасным или authoritative negative conclusion.
7. Replay и saved-data regression измеряют фактический результат, не обещая заранее фиксированное число переходов.

**Стек:** Go, существующий `research-report/1`, текущие `slice2-fidelity/3`, Go tests, Python 3 offline replay driver.

**Основание:** `docs/dev/gap-analysis.md` §2, текущий контракт `internal/research`, `docs/dev/decisions/agent7-e2e-conclusion-fidelity.md`.

## Global Constraints

1. Сохранить `schema=research-report/1`; новый wire schema не вводить.
2. Маркеры `slice2-fidelity/1`, `slice2-fidelity/2` и `slice2-fidelity/3` взаимно исключаются.
3. `/1` и `/2` продолжают валидироваться без `role`, `evidence_level` и package-usage полей.
4. `/3` сохраняет текущий обязательный `role` и `evidence_level`.
5. `evidence_level` остаётся производным полем:
   - assembler вычисляет его через `deriveEvidenceLevel`;
   - validator повторно вычисляет тем же pure helper;
   - mismatch является validation error, а не поводом для downgrade.
6. L1 возможен только если все обязательные `role=applicability` и `role=path` conditions закрыты `SUPPORTED`-фактами от разрешённых static carrier tools.
7. `role=deployment` не блокирует L1.
8. `role=path` со `state=REFUTED` блокирует L1, но не даёт safe conclusion, auto-close, VEX или `FALSE` disposition.
9. `role=path` со `state=UNKNOWN`, `OPEN` или `REFUTED` остаётся blocking condition для L1.
10. Агентские claims:
    - никогда не становятся verified facts;
    - не могут повысить evidence level;
    - не могут создать `SUPPORTED` или `REFUTED`;
    - canonical agent path hypothesis остаётся `OPEN` и блокирует L1;
    - произвольный agent claim остаётся `role=supporting`.
11. `ERROR`, `TIMEOUT`, `UNSUPPORTED`, отсутствующий результат, неполный scope или skipped packages никогда не являются negative proof.
12. Нулевой результат `module_usage`, `find_callers`, `find_may_callers`, `module_internal_reach` или `ingress-inventory` сам по себе не является negative proof.
13. Package-level negative fact ограничен записанным product source/build scope и не утверждает:
    - runtime non-use;
    - отсутствие reflection/plugin/generated loading;
    - отсутствие deployment/runtime exposure;
    - безопасность продукта;
    - глобальную неприменимость advisory.
14. Advisory, содержащий только module + version range без package/symbol, не получает выдуманный package path. В этом случае package/build usage остаётся `UNKNOWN`, если существующий module-level probe не даёт отдельного обоснованного результата.
15. Не запускать model runs, prompt tuning, новые prompt experiments или новые evaluation corpora.
16. Sandbox, read/exec boundaries и tool allowlist не расширять за пределы описанного package-usage static scan.
17. Сохранённые agent answers, `report.json`, `observations.jsonl`, artifacts и их bytes не переписывать.
18. Saved-data replay выполняется только через сохранённые agent turns; модель и live harness не вызываются.
19. Saved cases обозначаются только как `C01`–`C31`. Исходные unit identifiers, ticket identifiers, приватные component names, hostnames и абсолютные локальные пути не попадают в committed текст, test output или regression report.
20. Для путей за пределами репозитория использовать `<VA_REPO>`, `<VA_TMP>` и `<PRIVATE_LABEL_MAP>`.
21. Финальный gate после всех изменений:

```bash
cd <VA_REPO>
gofmt -w internal/affected/*.go internal/goanalysis/*.go internal/evidencetools/*.go internal/research/*.go cmd/izyan/*.go
test -z "$(gofmt -l .)"
go vet ./...
go test -count=1 ./...
```

## Review Focus

Reviewer должен отдельно проверить:

- **Negative verification correctness:** `NOT_USED` появляется только при закрытом static check scope, а не из пустого или failed результата.
- **Scope honesty:** каждый package-usage fact содержит package/symbol, build context, product source scope и ограничения.
- **FALSE/REFUTED boundary:** `REFUTED` usage condition никогда не превращается в `L1`, safe conclusion, auto-close, VEX или authoritative `FALSE`.
- **No guessed package:** module-only advisory не получает package path из module prefix.
- **Symbol projection:** advisory-declared symbols дают package candidates только при наличии package identity; пустой package у symbol не подменяется module path.
- **Positive branch:** `USED` подтверждается конкретным product-source site; одного module presence недостаточно.
- **Negative branch:** отсутствие direct call не считается достаточным без проверки imports/references, gated files, interface dispatch, dynamic markers и skipped packages.
- **Agent boundary:** agent claims не участвуют в `package-usage` facts, `evidence_level.evidence_refs` или carrier logic.
- **Level derivation:** package-usage fact может закрыть path condition только при `status=OK`, корректном `kind`, согласованном state и разрешённой tool identity.
- **Validator fail-closed:** forged `SUPPORTED`, `REFUTED`, `negative_verification=VERIFIED`, fact kind или evidence level отклоняются.
- **Compatibility:** `/1` и `/2` без новых полей по-прежнему parse/validate/render/replay.
- **Determinism:** candidate ordering, fact IDs, condition IDs, refs, limits и census стабильны при повторном запуске.
- **Replay stability:** saved agent status, extraction status, artifact pins, disposition и unrelated deterministic facts сохраняются.
- **Saved-data regression:** после B42 фиксируются measured before/after matrices и состояния path conditions; заранее обещанное число переходов не принимается как acceptance criterion.

---

### Task 1: Bounded package/symbol usage primitive и negative verification

**Depends on:** None

**Scope:** добавить в `internal/goanalysis` отдельный source-closure primitive, который проверяет один advisory-declared package или symbol и возвращает `USED`, `NOT_USED` либо `UNKNOWN`.

**Files:**

- Create: `internal/goanalysis/usage.go`
- Create: `internal/goanalysis/usage_test.go`
- Read/reuse: `internal/goanalysis/source.go:320-345, 2986-3012` — existing product package load и linked import closure.
- Read/reuse: `internal/goanalysis/coverage.go:1-145` — gated references и interface-dispatch scans.
- Read/reuse: `internal/goanalysis/negative.go:1-220` — existing fail-closed negative-verification conventions.

**Interfaces:**

```go
type PackageUsageState string

const (
    PackageUsageUsed    PackageUsageState = "USED"
    PackageUsageNotUsed PackageUsageState = "NOT_USED"
    PackageUsageUnknown PackageUsageState = "UNKNOWN"
)

type PackageUsageNegativeVerification string

const (
    PackageUsageNegativeVerified          PackageUsageNegativeVerification = "VERIFIED"
    PackageUsageNegativeInsufficientScope PackageUsageNegativeVerification = "INSUFFICIENT_SCOPE"
    PackageUsageNegativeContradicted      PackageUsageNegativeVerification = "CONTRADICTED"
)

type PackageUsageResult struct {
    Module                  string
    Package                 string
    Symbol                  string
    Present                 bool
    Usage                   PackageUsageState
    ProductSites            []domain.CallSite
    ImportSites             []domain.CallSite
    NegativeVerification   PackageUsageNegativeVerification
    CheckScope              string
    Limitations             []string
}

func (ix *Index) ProductUsage(
    ctx context.Context,
    module string,
    subject domain.SymbolRef,
) (PackageUsageResult, error)
```

**Change:**

1. Загрузить product source closure через существующий `Index.load` под текущими `GOOS`, `GOARCH` и build tags.
2. Определять `Present` только по linked import closure текущего build context.
3. Для package-level subject (`Symbol == ""`):
   - проверить прямые product-source imports target package;
   - учитывать обычные и blank imports;
   - учитывать concrete product call/reference sites, если они присутствуют;
   - direct import/reference даёт `USED`.
4. Для symbol-level subject:
   - подтвердить декларацию symbol в загруженном dependency package;
   - найти product-source references/calls;
   - отдельно проверить gated references, interface dispatch и dynamic markers;
   - найденный concrete product site даёт `USED`.
5. Отрицательный результат разрешать только если одновременно выполнены все условия:
   - target package присутствует в linked closure;
   - для symbol-level проверки symbol declaration разрешена;
   - все успешно загруженные product packages просканированы;
   - `SkippedPackagesImporting` пуст;
   - package-load budget не исчерпан;
   - нет direct import/reference/call;
   - нет gated reference;
   - нет unresolved interface-dispatch candidate;
   - нет relevant dynamic marker;
   - проверка завершилась без ошибки.
6. При выполнении negative условий вернуть:
   - `Usage=NOT_USED`;
   - `NegativeVerification=VERIFIED`;
   - bounded `CheckScope`.
7. При любом scope gap вернуть `UNKNOWN` и `INSUFFICIENT_SCOPE`; не переиспользовать пустой результат как `NOT_USED`.
8. Для symbol, который не найден в target dependency package, вернуть `UNKNOWN`, а не `NOT_USED`.
9. Стабильно сортировать product sites, imports и limitations по package/file/line/column.
10. В limitations явно зафиксировать:
    - scope текущего build context;
    - что факт касается product source static usage;
    - что runtime, reflection/plugin/generated loading и deployment не проверяются;
    - что negative fact не является safe conclusion.
11. Не менять существующие `FindCallers`, `ModuleUsage`, `ModuleInternalReach` или `Verifier` semantics.

**Acceptance criteria:**

- Прямой product call/import даёт `USED` с конкретным site.
- Package, присутствующий транзитивно, но не импортируемый/не referenced product source, даёт `NOT_USED + VERIFIED` только при закрытом scope.
- Gated reference переводит результат в `UNKNOWN`.
- Interface dispatch candidate переводит результат в `UNKNOWN`.
- Dynamic marker переводит отрицательный результат в `UNKNOWN`.
- Skipped package, load failure, timeout или exhausted budget никогда не дают `NOT_USED`.
- Отсутствующий symbol никогда не интерпретируется как «не используется».
- Повторный вызов на одинаковом snapshot даёт byte-stable JSON-представление результата.

**Exact validation commands:**

```bash
cd <VA_REPO>
go test ./internal/goanalysis -run 'TestProductUsage'
go test ./internal/goanalysis -run 'TestProductUsageNegativeVerification'
go test ./internal/goanalysis
```

**Do-not:**

- Не считать `len(ProductSites)==0` достаточным без negative verification.
- Не считать только `find_callers` с нулём sites полным отрицательным доказательством.
- Не сканировать runtime/deployment manifests.
- Не добавлять новый общий call graph.
- Не расширять scope на тестовые packages как на product source.
- Не превращать отсутствие symbol declaration в `REFUTED` path condition.
- Не использовать agent material.

---

### Task 2: Advisory symbol/package projection в affected resolver

**Depends on:** None

**Scope:** научить `affected.GoResolver` использовать package identity из `AffectedSymbols`, сохранив отдельную module-only ветку без угадывания package.

**Files:**

- Modify: `internal/affected/resolver.go:215-255` — `affectedModuleEntries`
- Modify: `internal/affected/resolver.go:266-315` — `resolvePackages`
- Modify: `internal/affected/resolver.go:307-355` — module-only branch
- Modify: `internal/affected/resolver.go:420-520` — package/build result semantics
- Modify: `internal/affected/resolver_test.go:1-280, 430-520`
- Optional helper location: `internal/affected/resolver.go` рядом с `affectedModuleEntries`

**Interfaces:**

```go
func affectedPackagesForEntry(
    entry domain.AffectedModule,
) []domain.AffectedPackage

func mergeAffectedSymbolPackages(
    packages []domain.AffectedPackage,
    symbols []domain.SymbolRef,
) []domain.AffectedPackage
```

**Change:**

1. Для каждого advisory entry объединить:
   - явно объявленные `AffectedPackages`;
   - package paths из `AffectedSymbols`.
2. Если symbol имеет непустой package path, а такого package нет в `AffectedPackages`, добавить bounded package candidate.
3. Если package уже существует, добавить symbol в его `Symbols` без дублирования.
4. Сохранить advisory order; не использовать map iteration для итогового порядка.
5. Не создавать package candidate, если symbol не содержит package path.
6. Использовать projected packages в:
   - `CheckedPackages`;
   - package import-closure probe;
   - build-relevance calculation;
   - `SelectedModules` narrowing.
7. Сохранить distinction:
   - package presence/build relevance — факт linked/build scope;
   - symbol usage — отдельный последующий `package-usage` check;
   - package presence не означает symbol invocation.
8. Для advisory только с module + version range и без package/symbol:
   - не создавать package из module prefix;
   - сохранить текущую module-only behaviour;
   - при известном compiled scope разрешать только bounded module-level absence, уже предусмотренную resolver;
   - при наличии module packages в compiled scope оставлять `package_present` и `build_relevant` `UNKNOWN`;
   - добавлять limitation:
     `"advisory declares module/version only; no package or symbol identifies a package-level subject"`.
9. Не менять fixed-version guard: `VersionAffected=FALSE` без package probe оставляет package/build `UNKNOWN`.
10. Не менять легитимный `module_present=FALSE` negative path.

**Acceptance criteria:**

- Advisory symbol с package path запускает package probe для этого package.
- Package present в linked closure даёт `package_present=TRUE`.
- Package отсутствует из product closure даёт существующий bounded `FALSE` с `CheckedPackages`.
- Package-only advisory не меняет текущий package probe.
- Module-only advisory не получает искусственный package path.
- Symbol package и explicit package объединяются без duplicates.
- Fixed entry по-прежнему не порождает package/build absence.
- `CheckedPackages` и `VersionAffectedModules` не смешивают version membership и package linkage.

**Exact validation commands:**

```bash
cd <VA_REPO>
go test ./internal/affected -run 'Test(AdvisorySymbol|SymbolPackage|ModuleOnly|FixedVersion|PackageProjection)'
go test ./internal/affected
```

**Do-not:**

- Не выводить package absence из fixed version.
- Не подставлять module path как package path для symbol без package identity.
- Не считать symbol declaration доказательством product usage.
- Не менять platform/build-tag semantics.
- Не ослаблять `gatedImports` и test-only handling.
- Не менять legacy report schema.

---

### Task 3: `package-usage` evidence tool и promotion в verified facts

**Depends on:** Task 1, Task 2

**Scope:** зарегистрировать новый evidence tool, вызвать его в deterministic lane только для advisory-declared package/symbol candidates и сохранить его результат как auditable observation/fact.

**Files:**

- Create: `internal/evidencetools/usage.go`
- Create: `internal/evidencetools/usage_test.go`
- Modify: `internal/evidencetools/mcp.go:45-132` — tool description, registration
- Modify: `internal/evidencetools/mcp_test.go:45-62` — registered tools assertion
- Modify: `internal/research/types.go:245-250, 733-755`
- Modify: `internal/research/deterministic.go:333-520, 589-730, 1020-1070`
- Modify: `internal/research/deterministic_test.go:230-380`

**Interfaces:**

```go
const PackageUsageTool = "package-usage"

type packageUsageArgs struct {
    Module  string `json:"module"`
    Package string `json:"package"`
    Symbol  string `json:"symbol,omitempty"`
}

type PackageUsageData struct {
    Module                string                  `json:"module"`
    Package               string                  `json:"package"`
    Symbol                string                  `json:"symbol,omitempty"`
    Present               bool                    `json:"present"`
    Usage                 string                  `json:"usage"`
    ProductSites          []domain.CallSite       `json:"product_sites,omitempty"`
    ImportSites           []domain.CallSite       `json:"import_sites,omitempty"`
    NegativeVerification  string                  `json:"negative_verification,omitempty"`
    CheckScope            string                  `json:"check_scope"`
    Limitations           []string                `json:"limitations"`
}

func (s *Session) packageUsage(
    ctx context.Context,
    args packageUsageArgs,
) (*Observation, error)
```

Wire fact additions:

```go
const FactKindPackageUsage = "PACKAGE_USAGE"
const NegativeVerificationVerified = "VERIFIED"

type VerifiedFact struct {
    // existing fields
    Kind                  string `json:"kind,omitempty"`
    NegativeVerification  string `json:"negative_verification,omitempty"`
}
```

**Change:**

1. Зарегистрировать `package-usage` в MCP tool list и server handlers.
2. Tool должен вызывать `Index.ProductUsage` из Task 1.
3. Формировать observation scope:
   - target module/package/symbol;
   - product source closure;
   - GOOS/GOARCH/build tags;
   - snapshot hash;
   - loaded/skipped package counts.
4. Status mapping:
   - direct concrete product site → `USED`;
   - closed negative verification → `NOT_USED`, `negative_verification=VERIFIED`;
   - любой incomplete/error/unsupported/dynamic gap → `UNKNOWN`.
5. Observation limitations:
   - positive:
     `"positive static usage does not establish runtime execution or attacker reachability"`;
   - negative:
     `"negative verification is bounded to statically resolved product-source imports/references/calls under the recorded build context"`;
     `"does not prove runtime non-use, reflection/plugin/generated loading, or deployment absence"`;
   - unknown:
     `"scope is not closed; absence is not evidence of non-use"`.
6. В deterministic lane:
   - сохранить текущий `affected-resolve`;
   - после applicability resolution вызвать `package-usage` для каждого declared package;
   - для symbol candidates вызывать отдельно для каждого declared symbol;
   - для module-only advisory без package/symbol не вызывать tool;
   - сортировать candidates по package/symbol.
7. Не использовать module prefix как package fallback.
8. В fact promotion:
   - `package-usage` с `USED` получает `Kind=PACKAGE_USAGE`, `Claim=TRUE`;
   - `package-usage` с `NOT_USED + VERIFIED` получает `Kind=PACKAGE_USAGE`, `Claim=FALSE`, `NegativeVerification=VERIFIED`;
   - `UNKNOWN` без positive payload не становится verified fact;
   - positive lower-bound observation может остаться `PARTIAL`, но не может underwriting negative condition.
9. Проверять, что artifact, `data_digest`, input digest, scope и observation ID сохраняются обычным deterministic lane способом.
10. Обновить deterministic call-order tests.

**Acceptance criteria:**

- Tool доступен через MCP и имеет stable argument shape.
- Каждый package/symbol check записывается в `observations.jsonl`.
- Positive и negative facts различимы по `Kind`, `Claim` и `NegativeVerification`.
- Unknown/failed checks не становятся negative verified facts.
- Module-only advisory не создаёт synthetic package-usage observation.
- Saved observation artifact bytes остаются immutable после записи.
- Existing `verified_facts` promotion semantics для всех старых tools не меняются.

**Exact validation commands:**

```bash
cd <VA_REPO>
go test ./internal/evidencetools -run 'TestPackageUsage'
go test ./internal/evidencetools -run 'TestMCP.*PackageUsage'
go test ./internal/research -run 'TestDeterministic.*PackageUsage'
go test ./internal/evidencetools ./internal/research
```

**Do-not:**

- Не считать `UNKNOWN` fact negative proof.
- Не использовать `module_usage=0` как замену новому tool.
- Не добавлять package-usage refs из agent output.
- Не изменять существующие artifact digest semantics.
- Не запускать дополнительные model/harness calls.
- Не добавлять package candidates за пределами advisory-declared package/symbol scope.

---

### Task 4: Report condition model, applicability derivation и evidence-level impact

**Depends on:** Task 3

**Scope:** связать package-usage observations с `product_applicability`, `exploitation_conditions`, `role` и `deriveEvidenceLevel`.

**Files:**

- Modify: `internal/research/types.go:245-250` — condition subject constants, если они не добавлены в Task 3
- Modify: `internal/research/assemble.go:461-584` — deterministic conditions
- Modify: `internal/research/assemble.go:1230-1320` — unknown generation for incomplete observations
- Modify: `internal/research/slice2.go:734-850` — static carriers, role table, canonical path subjects
- Modify: `internal/research/slice2.go:868-951` — attack status
- Modify: `internal/research/slice2.go:890-1000` — evidence-level derivation
- Create: `internal/research/package_usage_test.go`

**Interfaces:**

```go
const subjProductPackageUsage = "affected package/symbol used by product code"

func packageUsageConditionState(
    data PackageUsageData,
) string

func (a *assembler) appendPackageUsageConditions(
    r *Report,
)
```

The new condition has:

```go
ExploitationCondition{
    Subject:      subjProductPackageUsage,
    Scope:        <PackageUsageData.CheckScope>,
    Necessity:    "required",
    Origin:       OriginDeterm,
    State:        SUPPORTED | REFUTED | UNKNOWN,
    EvidenceRefs: <fact ref or observation ref>,
    Limitations:  <tool limitations>,
    Role:         ConditionRolePath,
}
```

**Change:**

1. Add `affected package/symbol used by product code` to the canonical role table as `role=path`.
2. Add the subject to `canonicalPathSubject`, so an agent claim naming exactly this predicate is normalized to:
   - `role=path`;
   - `necessity=required`;
   - `state=OPEN`;
   - no carrier evidence.
3. Add `package-usage` to `staticCarrierTools`.
4. Add the subject to `transitionSubjects`.
5. Parse each `package-usage` observation deterministically:
   - `USED` → `SUPPORTED`;
   - `NOT_USED + VERIFIED` → `REFUTED`;
   - otherwise → `UNKNOWN`.
6. Emit one required condition per sorted package/symbol candidate. Do not collapse multiple symbols into one ambiguous boolean.
7. Use the package-usage fact ref only when it resolves to the promoted verified fact. Use observation ref for non-OK/unknown results so the check remains auditable but cannot close L1.
8. For the negative branch, statement must include:
   - target package/symbol;
   - target is present in recorded dependency/build scope;
   - no product-source use was found in bounded static scope.
9. For the negative branch, limitations must include:
   - `negative verification=VERIFIED`;
   - exact source/build scope;
   - no runtime/reflection/plugin/generated/deployment conclusion;
   - `REFUTED` path condition blocks L1 and is not a safe conclusion.
10. For the positive branch, retain current package/build semantics:
    - `package_present=TRUE` and `build_relevant=TRUE` come from resolver package/build evidence;
    - package-usage fact corroborates product source use;
    - a usage fact must not make an unlinked package present.
11. For module-only advisory:
    - emit no package-usage condition;
    - retain package/build `UNKNOWN` where no bounded package subject exists;
    - emit decision-changing unknown with follow-up requesting a package/symbol-bounded check.
12. Update `slice2AttackStatus`:
    - only deterministic `role=path` conditions count as transitions;
    - `REFUTED` usage never counts as a confirmed transition;
    - `UNKNOWN` usage can create `PARTIAL` only when another path transition is confirmed;
    - deployment-only unknown remains non-blocking for L1.
13. Update `deriveEvidenceLevel`:
    - a `SUPPORTED` package-usage condition with a valid static carrier can close L1;
    - a `REFUTED` package-usage condition always enters `blocking_conditions`;
    - a `REFUTED` path condition keeps level at L2 or lower;
    - L2 limitations explicitly distinguish “path refuted in bounded scope” from “product is safe”;
    - no condition from `origin=agent` contributes evidence refs.
14. Preserve current L3 rules and dynamic carrier allowlist.

**Acceptance criteria:**

- Positive package usage can participate in a fully closed L1 path.
- Negative package usage produces `REFUTED` required path condition and L2, never L1.
- A negative usage fact does not set `vulnerable_code_reachability=FALSE`.
- Module-only advisory remains explicitly bounded and does not receive guessed package/symbol facts.
- An agent statement cannot turn package usage into `SUPPORTED` or `REFUTED`.
- Deterministic condition/evidence ref ordering is stable.
- Synthetic tests cover:
  - package used;
  - symbol used;
  - package present but not used;
  - symbol present but not used;
  - unknown due gated/interface/dynamic scope;
  - module-only advisory;
  - package/build positive plus usage `REFUTED`;
  - agent-only usage statement.

**Exact validation commands:**

```bash
cd <VA_REPO>
go test ./internal/research -run 'TestPackageUsageCondition'
go test ./internal/research -run 'TestEvidenceLevel.*PackageUsage'
go test ./internal/research -run 'TestAttackStatus.*PackageUsage'
go test ./internal/research
```

**Do-not:**

- Не считать `REFUTED` path condition доказательством безопасности.
- Не переводить negative usage в `vulnerable_code_reachability=FALSE`.
- Не считать package linkage равным symbol execution.
- Не делать deployment posture blocker для L1.
- Не разрешать agent condition закрывать path.
- Не менять L3 dynamic semantics.
- Не добавлять новый extension marker.

---

### Task 5: Fail-closed validator и render wording

**Depends on:** Task 4

**Scope:** валидировать новый fact/condition contract и визуально показать bounded usage fact без смешения deterministic, agent и unknown material.

**Files:**

- Modify: `internal/research/validate.go:155-205` — verified fact invariants
- Modify: `internal/research/validate.go:734-760` — condition axis/state checks
- Modify: `internal/research/validate.go:1060-1150` — deterministic condition consistency
- Modify: `internal/research/validate.go:1320-1495` — `/3` role/evidence-level rules
- Modify: `internal/research/render.go:148-280` — product facts and condition groups
- Modify: `internal/research/render.go:538-580` — full facts and conditions appendix
- Create: `internal/research/package_usage_validate_test.go`
- Create: `internal/research/package_usage_render_test.go`
- Modify: `internal/research/evidence_level_contract_test.go` — legacy field stripping

**Interfaces:**

```go
func validatePackageUsageFact(
    e *ValidationError,
    f VerifiedFact,
    where string,
)

func validatePackageUsageCondition(
    e *ValidationError,
    r *Report,
    c ExploitationCondition,
    refs *refSpace,
)
```

Allowed fact values:

```go
FactKindPackageUsage
NegativeVerificationVerified
```

**Change:**

1. Extend verified-fact validation:
   - empty `kind` remains valid for legacy facts;
   - `kind=PACKAGE_USAGE` requires `tool=package-usage`;
   - `kind=PACKAGE_USAGE` requires non-empty `Scope`;
   - `Claim=FALSE` requires `NegativeVerification=VERIFIED`;
   - `Claim=FALSE` package-usage fact requires `Coverage=COMPLETE`;
   - non-package facts cannot carry `NegativeVerification`.
2. Extend `/3` condition validation:
   - deterministic usage condition must have `role=path`;
   - `SUPPORTED` requires a resolving `PACKAGE_USAGE` fact with `Claim=TRUE`;
   - `REFUTED` requires a resolving `PACKAGE_USAGE` fact with `Claim=FALSE`, `NegativeVerification=VERIFIED`, and `Coverage=COMPLETE`;
   - `UNKNOWN` must not cite a verified negative package-usage fact as if it were unresolved;
   - agent usage conditions remain `OPEN`, agent-only refs.
3. Keep existing `/2` rules unchanged for reports advertising only `/2`.
4. Ensure static carrier validation recognizes `package-usage` only through a deterministic verified fact.
5. Ensure recomputed `EvidenceLevel` catches:
   - forged L1 with usage `REFUTED`;
   - forged L1 with usage `UNKNOWN`;
   - forged L1 with only an agent usage claim;
   - forged usage fact with `Claim=FALSE` but no verified negative verification;
   - forged usage fact with `Coverage=PARTIAL`;
   - package usage fact attached to agent condition;
   - usage fact used to create `vulnerable_code_reachability=FALSE`.
6. Render in the existing deterministic-facts / agent-hypotheses / unknown-conditions separation.
7. In the main conditions section, make `[REFUTED]` visible and render the bounded negative limitation.
8. In the evidence register/appendix, render:
   - fact kind;
   - claim;
   - negative verification status;
   - check scope;
   - limitations.
9. Extend L2 wording when a blocking condition is `REFUTED`:
   - it is a bounded path fact;
   - it blocks L1;
   - it is not a safe conclusion or automatic non-applicability result.
10. Do not recompute evidence level in renderer.

**Acceptance criteria:**

- All forged package-usage facts listed above are rejected.
- All assembled positive, negative and unknown usage reports validate.
- A report with `REFUTED` usage condition cannot validate as L1.
- Agent refs cannot enter `evidence_level.evidence_refs`.
- `/1` and `/2` fixtures without new fields continue to parse, validate and render.
- Markdown explicitly distinguishes:
  - package/symbol present;
  - product-source usage result;
  - bounded negative verification;
  - unresolved runtime or dynamic scope.
- Repeated render is byte-stable.

**Exact validation commands:**

```bash
cd <VA_REPO>
go test ./internal/research -run 'TestPackageUsageFactValidation'
go test ./internal/research -run 'TestPackageUsageConditionValidation'
go test ./internal/research -run 'TestPackageUsageRender'
go test ./internal/research -run 'TestSlice2_LegacyReportStillValidates|TestSlice2V2'
go test ./internal/research
```

**Do-not:**

- Не принимать `Claim=FALSE` без bounded negative verification.
- Не принимать `REFUTED` condition без package-usage verified fact.
- Не превращать validator error в L2.
- Не считать `Coverage=PARTIAL` достаточным для negative proof.
- Не отображать `REFUTED` как «безопасно», «неэксплуатируемо» или equivalent.
- Не добавлять `basis=agent`.
- Не менять legacy `/1` или `/2` validator rules.

---

### Task 6: Replay parity и измерение saved-data до/после

**Depends on:** Task 5

**Scope:** расширить offline replay driver так, чтобы он сравнивал baseline и B42 output, считал уровни и состояния path conditions, проверял отсутствие побочных изменений и фиксировал обе семантические ветви.

**Files:**

- Modify: `tools/evidence-levels-replay.py:1-565`
- Modify: `internal/research/replay_test.go:700-980`
- Create: `docs/dev/reports/2026-10-14-b42-package-usage-regression.md`
- Read/reuse: `internal/research/replay.go:1-260`

**Interfaces:**

CLI additions:

```text
--primary-input-suffix agent
--primary-baseline-suffix agent-v3
--retry-input-suffix agent
--retry-baseline-suffix agent-v3
--report <path>
--work-dir <path>
```

Required driver functions:

```python
def load_baseline_report(case, suffix): ...
def condition_state_for_case(report, subject): ...
def census_levels(reports): ...
def census_path_conditions(reports): ...
def assert_b42_delta(before, after): ...
def assert_saved_inputs_unchanged(root_hashes_before, root_hashes_after): ...
```

Case-level state rule for the new multi-candidate usage condition:

- `REFUTED` if any required usage condition is `REFUTED`;
- otherwise `UNKNOWN` if any required usage condition is `UNKNOWN`;
- otherwise `SUPPORTED` if at least one usage condition exists and all are `SUPPORTED`;
- `ABSENT` if advisory has no bounded package/symbol candidate.

**Change:**

1. Keep replay input immutable:
   - primary inputs: `<VA_TMP>/exploitable/runs/<UNIT>/agent`;
   - retry inputs: `<VA_TMP>/exploitable-retry*/runs/<UNIT>/agent`;
   - output only under `--work-dir`.
2. Load baseline from the existing `agent-v3` sibling when available; do not treat baseline numbers as the after-result.
3. Before replay, record:
   - level census by set;
   - `affected package reachable` states;
   - `affected package build-relevant` states;
   - new usage-condition state (`ABSENT` for old reports if no candidate);
   - agent status/extraction status;
   - disposition;
   - saved artifact pins.
4. Replay each case through the compiled CLI with:
   - `--replay-agent-turn`;
   - no live agent flags;
   - no `--deterministic-only`;
   - `GOPROXY=off`, `GOSUMDB=off`, `GOFLAGS=-mod=readonly`.
5. After replay, assert:
   - `/3` marker is present and exclusive;
   - `evidence_level` validates;
   - saved agent status and extraction status are unchanged;
   - saved artifact paths, digests, sizes and selectors are unchanged;
   - `agent_output.replayed_from` is correct;
   - `REVIEW_REQUIRED` and `auto_close=false` remain unchanged;
   - no agent ref appears in ladder evidence;
   - no L3 appears without a saved dynamic verified fact.
6. Produce before/after tables for primary and retry sets:
   - level census `L1/L2/L3`;
   - per-condition `SUPPORTED/REFUTED/UNKNOWN`;
   - count of cases with new usage condition `ABSENT`.
7. Enforce the known baseline only before B42:
   - primary baseline: `7 × L1`, `24 × L2`, `0 × L3`;
   - retry baseline: `2 × L1`, `9 × L2`, `0 × L3`.
   If the baseline differs, fail as a changed input set; do not silently reinterpret it.
8. Do not enforce a fixed after matrix. Instead enforce branch invariants:
   - positive branch: package/build and usage can become `SUPPORTED`; if every required path condition closes, the case may move L2 → L1;
   - negative branch: package/symbol usage is `REFUTED`; the case must not become L1 and must remain `REVIEW_REQUIRED`;
   - unresolved branch: module-only advisory or incomplete negative verification remains `UNKNOWN`, not `REFUTED`.
9. Compare before/after invariant fields and fail if unrelated cases change. At minimum keep byte-equivalent semantic projections for:
   - vulnerability/advisory identity;
   - affected implementation list;
   - snapshot/build identity;
   - module presence;
   - version affected;
   - selected/pending/unresolved module sets;
   - advisory entry status;
   - agent output and attempts;
   - dynamic exploitation axis;
   - disposition;
   - classification original category.
10. Allow only B42-derived changes in:
    - package/build applicability fields;
    - checked package projection;
    - package-usage verified facts;
    - package/build/usage conditions and their downstream ladder blockers;
    - code-reachability explanatory text;
    - derived evidence level;
    - explicitly linked unknowns/recommendations/Markdown wording.
11. Hash saved input directories before and after; any byte change fails.
12. Write `docs/dev/reports/2026-10-14-b42-package-usage-regression.md` with:
    - only `C01`–`C31`;
    - `<VA_REPO>`/`<VA_TMP>` placeholders;
    - measured before/after counts;
    - positive, negative and unresolved branch counts;
    - failed-case list and exact blockers;
    - no private identifiers.

**Acceptance criteria:**

- Every discovered primary/retry case is processed or reported as an explicit `NOT_RUN` blocker.
- Baseline census matches the measured pre-B42 saved reports.
- After census is reported, not predicted.
- Every `REFUTED` usage case remains non-L1 and review-required.
- Every L1 increase has a corresponding deterministic positive package-usage/path evidence chain.
- Module-only cases do not acquire guessed package/symbol facts.
- Any unrelated semantic change fails the driver.
- Saved inputs and artifact bytes remain unchanged.
- Repeating replay with identical inputs gives stable condition state, evidence-level JSON and regression census.
- No model or harness invocation occurs.

**Exact validation commands:**

```bash
cd <VA_REPO>

go test ./internal/research -run 'TestReplay.*PackageUsage'
go test ./internal/research -run 'TestReplay.*Artifact|TestReplay.*Status'

WORK="$(mktemp -d)"
BIN="$WORK/izyan"
go build -o "$BIN" ./cmd/izyan

GOPROXY=off \
GOSUMDB=off \
GOFLAGS=-mod=readonly \
python3 tools/evidence-levels-replay.py \
  --primary-root "<VA_TMP>/exploitable/runs" \
  --primary-input-suffix agent \
  --primary-baseline-suffix agent-v3 \
  --retry-glob "<VA_TMP>/exploitable-retry*/runs" \
  --retry-input-suffix agent \
  --retry-baseline-suffix agent-v3 \
  --label-map "<PRIVATE_LABEL_MAP>" \
  --izyan "$BIN" \
  --govulndb "<VA_TMP>/govulndb" \
  --modcache "<VA_TMP>/modcache" \
  --work-dir "$WORK/replay" \
  --report "$WORK/b42-regression.json"
```

Run the same command a second time with a new empty `--work-dir`; compare the two generated `b42-regression.json` files after removing only wall-clock duration fields.

**Do-not:**

- Не запускать model runs.
- Не запускать live harness.
- Не использовать исходные unit identifiers в output или report.
- Не изменять input saved directories.
- Не переписывать saved reports или artifacts.
- Не требовать заранее обещанного количества L1/L2 переходов после B42.
- Не считать любой L2→L1 переход допустимым без positive deterministic evidence.
- Не считать `REFUTED` usage безопасным выводом.
- Не скрывать `NOT_RUN`, failed или unsupported cases.

---

### Task 7: Backlog, ADR и regression documentation

**Depends on:** Task 6

**Scope:** зафиксировать B42 contract, убрать B42 из открытого backlog по convention проекта и сохранить измеренные результаты без приватных идентификаторов.

**Files:**

- Modify: `docs/dev/gap-analysis.md:§2` — удалить строку B42 после выполнения acceptance gates.
- Modify: `docs/dev/decisions/agent7-e2e-conclusion-fidelity.md:§6` — добавить B42 decision record.
- Modify: `docs/dev/decisions/agent7-e2e-conclusion-fidelity.md` — удалить/обновить прежнюю формулировку о нерешённом package-level usage gap.
- Create/update: `docs/dev/reports/2026-10-14-b42-package-usage-regression.md`
- No code interfaces.

**Interfaces:**

None. Документный контракт должен описывать фактически реализованные значения:

- tool: `package-usage`;
- condition subject: `affected package/symbol used by product code`;
- states: `SUPPORTED`, `REFUTED`, `UNKNOWN`;
- negative verification: `VERIFIED` только при закрытом bounded static scope;
- module-only advisory: package-level subject отсутствует, поэтому usage fact не выдумывается;
- `REFUTED` path condition не даёт L1 и не является safe conclusion.

**Change:**

1. Удалить B42 из `docs/dev/gap-analysis.md` §2 только после прохождения code, validator, replay и saved-data gates.
2. В ADR зафиксировать:
   - symbol→package projection;
   - различие package linkage и product-source usage;
   - exact negative verification prerequisites;
   - никогда не считающиеся negative proof результаты;
   - module-only handling;
   - положительную и отрицательную ветви evidence-level impact;
   - сохранение `REVIEW_REQUIRED`/`auto_close=false`.
3. В regression report включить measured before/after tables:
   - primary;
   - retry;
   - `SUPPORTED/REFUTED/UNKNOWN` по каждому path condition;
   - branch interpretation;
   - unchanged invariants.
4. В документах использовать только `C01`–`C31`, `<VA_REPO>`, `<VA_TMP>` и `<PRIVATE_LABEL_MAP>`.
5. Добавить privacy self-check для committed plan, ADR и regression report.

**Acceptance criteria:**

- В открытом backlog нет строки B42.
- ADR описывает реальный bounded contract, а не обещанный результат.
- Regression report содержит фактические числа до/после и обе ветви.
- В документах нет абсолютных локальных путей, исходных unit identifiers или ticket identifiers.
- В документах нет формулировки, превращающей `REFUTED` usage в safe conclusion.
- История сохраняет distinction между package presence, product usage и runtime exploitability.

**Exact validation commands:**

```bash
cd <VA_REPO>
git diff --check -- docs/dev/gap-analysis.md docs/dev/decisions/agent7-e2e-conclusion-fidelity.md docs/dev/reports/2026-10-14-b42-package-usage-regression.md

python3 - <<'PY'
from pathlib import Path
import re

files = [
    Path("docs/dev/gap-analysis.md"),
    Path("docs/dev/decisions/agent7-e2e-conclusion-fidelity.md"),
    Path("docs/dev/reports/2026-10-14-b42-package-usage-regression.md"),
]
assert "| B42 |" not in files[0].read_text()
for path in files:
    text = path.read_text()
    assert "/Users/" not in text
    assert not re.search(r"STS-\d{6}", text)
    assert "C01" in text or path.name == "gap-analysis.md"
PY
```

---

## Dependency / Execution Order

```text
Task 1 ───────────────┐
                      ├──> Task 3 ───> Task 4 ───> Task 5 ───> Task 6 ───> Task 7
Task 2 ───────────────┘
```

- Task 1 и Task 2 независимы и могут выполняться параллельно.
- Task 3 требует обеих upstream interfaces: `ProductUsage` и symbol→package projection.
- Task 4 меняет report condition ledger и evidence-level derivation после появления реальных observations.
- Task 5 начинается только после стабилизации condition/fact model.
- Task 6 является единственным saved-data implementation gate и выполняется без модели.
- Task 7 закрывает backlog только после measured regression и полного validation gate.
- Финальная последовательность после Task 7 обязательна:

```bash
cd <VA_REPO>
gofmt -w internal/affected/*.go internal/goanalysis/*.go internal/evidencetools/*.go internal/research/*.go cmd/izyan/*.go
test -z "$(gofmt -l .)"
go vet ./...
go test -count=1 ./...
```
# B41 — план реализации факта `usage_scope`

**Цель:** добавить проверяемую классификацию build-closure `product` / `test-only` / `mixed` для advisory-declared package subject, сохранив fail-closed поведение, совместимость `research-report/1` и все ограничения B42.

**Архитектура:** B41 вводит отдельный non-carrier fact kind `BUILD_USAGE_SCOPE` и отдельный optional `/3` audit-axis `exploitation_axes.build_usage_scope`. Он переиспользует `FactUsageSubject` только для идентичности субъекта, но не переиспользует семантику `PACKAGE_USAGE`, `PACKAGE_USAGE_LOWER_BOUND` или `NegativeVerification`. B42 остаётся единственным механизмом для static product-source usage и `REFUTED` path condition.

**Стек:** Go, `research-report/1`, `slice2-fidelity/3`, MCP evidence tools, Python 3 offline replay driver, сохранённые agent turns.

**Спецификация:** текущая строка B41 в `docs/dev/gap-analysis.md`, B42-контракт в `docs/dev/plans/2026-10-14-01-package-level-facts-plan.md` и §7 ADR `docs/dev/decisions/agent7-e2e-conclusion-fidelity.md`.

## Global Constraints

1. Сохранить `schema=research-report/1`.
2. Маркеры `slice2-fidelity/1`, `slice2-fidelity/2` и `slice2-fidelity/3` остаются взаимно исключающимися.
3. `/1` и `/2` продолжают parse/validate/render без новых B41-полей.
4. `evidence_level` остаётся DERIVED:
   - assembler вычисляет его через pure `deriveEvidenceLevel`;
   - validator вычисляет его повторно тем же helper;
   - mismatch является validation error.
5. L1 возможен только при закрытых обязательных `role=applicability` и `role=path` conditions через разрешённые verified static carrier facts.
6. `role=deployment` не блокирует L1.
7. B41 не добавляет новый required `role=path` condition.
8. B41 не добавляет `usage-scope` в `staticCarrierTools`.
9. `BUILD_USAGE_SCOPE` никогда не закрывает condition, не повышает `evidence_level`, не становится `evidence_level.evidence_refs` и не используется как `vulnerable_code_reachability=FALSE`.
10. `PACKAGE_USAGE` сохраняет существующую семантику B42:
    - `USED` — concrete product-source use;
    - `NOT_USED` — только при собственной закрытой negative verification;
    - `UNKNOWN` — при незакрытом scope.
11. `PACKAGE_USAGE_LOWER_BOUND` остаётся non-carrier и не может закрывать B42 usage condition.
12. B41 не использует существующее поле `VerifiedFact.NegativeVerification`; для test-only используется отдельное поле `ProductAbsenceVerification`.
13. `usage_scope=test-only` означает только:
    - target присутствует в test closure;
    - target отсутствует в product closure;
    - оба closure были успешно получены и проверены;
    - вывод ограничен записанным build context.
14. `ERROR`, `TIMEOUT`, `UNSUPPORTED`, отсутствие результата, ошибка декодирования, неполный stream, неразрешённый root/edge и skipped packages никогда не являются доказательством `test-only`.
15. Если target отсутствует в обоих полных closure, результат остаётся `UNKNOWN`; это не `test-only`.
16. Product closure строится из `go list -deps -json ./...` без `-test`.
17. Test closure строится из `go list -deps -test -json ./...` через распознанные test-driver/test-variant roots; обычное присутствие package в объединённом `-test` выводе само по себе не доказывает test reachability.
18. B41 не использует `goanalysis.Index.linkedPaths()` или `ProductUsage` для test closure: `Index.load` не загружает `_test.go`, а B42 ProductUsage — отдельный product-source predicate.
19. Для module-only advisory не подставляется module path как package path. Допускается только module-level aggregate fact с пустым `Package`; он не является package-level доказательством и не влияет на B42.
20. Agent claims:
    - никогда не становятся verified facts;
    - не могут создать `SUPPORTED`, `REFUTED` или L1;
    - не могут заполнить `build_usage_scope` axis;
    - сохраняют `REVIEW_REQUIRED` и `auto_close=false`.
21. Test-only, product-absence и любые B42 `REFUTED` состояния не являются заключением о безопасности, `NOT_AFFECTED`, `NO_EXPLOIT_PATH_FOUND`, VEX или auto-close.
22. При несовместимости B41 и B42 для одного и того же package subject validator отклоняет forged report. В частности, `test-only` не может сосуществовать с carrier `PACKAGE_USAGE` для того же package subject.
23. Model runs, prompt tuning, новые corpora и новые agent answers запрещены.
24. Сохранённые agent answers, `report.json`, `observations.jsonl`, artifacts и их bytes не переписываются.
25. Replay выполняется только через сохранённые agent turns; live harness и model не вызываются.
26. Для сохранённых наборов в committed text и regression report используются только `C01`–`C31`; приватные идентификаторы и абсолютные пути заменяются на `<VA_REPO>`, `<VA_TMP>`, `<PRIVATE_LABEL_MAP>`.
27. Новый tool обязан записывать явный scope:
    - snapshot/build context;
    - GOOS/GOARCH/CGO/build tags;
    - обе команды `go list`;
    - product/test root semantics;
    - ограничения runtime, reflection, plugin, generated loading и deployment.
28. Детерминированные candidate ordering, subject binding, fact IDs, observation IDs, evidence refs и census ordering должны быть стабильными.
29. Финальный gate после всех изменений:

```bash
cd <VA_REPO>
gofmt -w internal/affected/*.go internal/goanalysis/*.go internal/evidencetools/*.go internal/research/*.go cmd/izyan/*.go
test -z "$(gofmt -l .)"
go vet ./...
go test -count=1 ./...
```

## Review Focus

Reviewer должен отдельно проверить:

- **Negative-verification correctness:** `test-only` возникает только при успешной паре closure checks; `ProductAbsenceVerification=VERIFIED` не смешивается с B42 `NegativeVerification`.
- **Test-only is not safety:** test-only факт остаётся bounded build-closure fact, не меняет disposition, VCR, auto-close, VEX или safe verdict.
- **Scope honesty:** scope явно различает no-test product closure и test-root closure; package присутствующий только в полном `-test` потоке не считается test-used без test-root reachability.
- **UNKNOWN preservation:** failed/incomplete/malformed/timeout/skipped stream и target absent in both closures остаются UNKNOWN.
- **B42 composition:** B41 не создаёт вторую `REFUTED` condition и не меняет `PACKAGE_USAGE`/`PACKAGE_USAGE_LOWER_BOUND`.
- **Role assignment:** новый axis не добавляет condition и не меняет `conditionRoleForSubject`.
- **Level derivation:** `BUILD_USAGE_SCOPE` не является static carrier; один этот факт не даёт L1 и не меняет L3.
- **Agent boundary:** agent usage statement не может заполнить B41 axis, fact или level evidence.
- **Compatibility:** старые `/1` и `/2` bytes без B41 fields продолжают валидироваться и рендериться.
- **Validator fail-closed:** forged kind/tool, forged scope enum, symbol-bound B41 subject, partial verified fact, invalid product-absence marker и axis mismatch отклоняются.
- **Determinism/replay:** повторный replay даёт одинаковые usage-scope facts, axis, condition/evidence-level JSON и census.
- **Saved-data integrity:** input trees, saved answers, artifact pins, agent statuses и unrelated report fields не изменяются.
- **Regression safety:** specialist test-only branch измеряется явно; ожидаемая форма результата фиксируется, но заранее не обещается число product/mixed/UNKNOWN результатов.

### Task 1: Двойной build-closure primitive

**Depends on:** None

**Scope:** добавить API для получения двух независимых `go list` streams и детерминированной классификации package/module build usage.

**Files:**

- Modify: `internal/affected/golist.go:38-65` — `Package`, `GoTool`
- Modify: `internal/affected/golist.go:108-115` — `ExecGoTool.ListPackages`
- Modify: `internal/affected/golist.go:231-258` — `cachingTool`
- Create: `internal/affected/usage_scope.go:1`
- Modify: `internal/affected/resolver_test.go:19-26` — `fakeTool`
- Modify: `internal/llm/tools_test.go:18-22` — `stubGoTool`

**Interfaces:**

```go
type GoTool interface {
    ListModules(
        ctx context.Context,
        dir string,
        build domain.ProductSnapshot,
    ) (raw []byte, source string, err error)

    // Existing resolver compatibility method. It delegates to
    // ListPackagesScope(..., true).
    ListPackages(
        ctx context.Context,
        dir string,
        build domain.ProductSnapshot,
    ) ([]byte, error)

    ListPackagesScope(
        ctx context.Context,
        dir string,
        build domain.ProductSnapshot,
        withTests bool,
    ) ([]byte, error)
}
```

```go
type UsageScope string

const (
    UsageScopeProduct  UsageScope = "product"
    UsageScopeTestOnly UsageScope = "test-only"
    UsageScopeMixed    UsageScope = "mixed"
    UsageScopeUnknown  UsageScope = "unknown"
)

const ProductAbsenceVerificationVerified = "VERIFIED"
```

```go
type UsageScopeResult struct {
    Module  string
    Package string

    ProductLinked bool
    TestLinked    bool
    Usage         UsageScope

    ProductAbsenceVerification string

    ProductPackageCount int
    TestPackageCount    int
    ProductRootCount    int
    TestRootCount       int

    CheckScope string
    Limitations []string
}

func ClassifyUsageScope(
    ctx context.Context,
    tool GoTool,
    dir string,
    build domain.ProductSnapshot,
    module string,
    packagePath string,
) (UsageScopeResult, error)
```

**Change:**

1. Add `ListPackagesScope(..., withTests bool)`:
   - `withTests=false` runs `go list -deps -json ./...`;
   - `withTests=true` runs `go list -deps -test -json ./...`;
   - build tags and toolchain environment are passed exactly as in the existing `ExecGoTool`;
   - stdout/stderr remain covered by existing `toolaudit.Run`.
2. Preserve `ListPackages` behavior by delegating to the `withTests=true` variant. Existing resolver semantics must not change.
3. Extend `cachingTool` with separate cached results for the two stream modes. A cached `-test` result must never be returned for a no-test request.
4. Extend the package decoder model with any required package-error representation. A stream with a command error or undecodable package error is incomplete, not a closed negative.
5. Parse each stream into stable package nodes:
   - canonical package identity;
   - `Imports`;
   - `Deps`;
   - `DepOnly`;
   - `ForTest`;
   - synthetic test-driver identity.
6. Define the product closure `P` from the no-test stream:
   - identify non-test `./...` roots;
   - traverse `Deps`, falling back to `Imports` only when the stream explicitly provides no `Deps`;
   - do not use `isTestPath`, package-name heuristics or production-main-only narrowing;
   - retain the exact semantics of the no-test `go list` request in the recorded scope.
7. Define the independent test closure `T` from the with-test stream:
   - identify `ForTest` variants and synthetic `.test` drivers;
   - traverse their `Deps`/`Imports`;
   - do not treat every ordinary package returned by the with-test stream as test-reachable;
   - unresolved test roots or edges make the result incomplete.
8. For a package target:
   - `P=true, T=false` → `product`;
   - `P=false, T=true` → `test-only`;
   - `P=true, T=true` → `mixed`;
   - `P=false, T=false` → `unknown`, not a negative proof.
9. For a module-only target (`packagePath == ""`):
   - aggregate matching package nodes by module metadata or exact module-prefix rule;
   - emit a module-level result only;
   - never manufacture a package subject;
   - document that the result is an aggregate module closure, not a claim about an affected package.
10. Require both streams to be successfully decoded and all required roots/edges to be closed before returning a known classification.
11. Set `ProductAbsenceVerification=VERIFIED` only for `test-only` with:
    - `ProductLinked=false`;
    - `TestLinked=true`;
    - complete product and test closures;
    - no unresolved roots/edges.
12. Add deterministic sorting for package identities, roots and limitation strings.
13. Record a check scope naming:
    - both exact `go list` variants;
    - snapshot GOOS/GOARCH/CGO/build tags;
    - product-root and test-root rules;
    - package/module target;
    - exclusion of runtime, deployment, reflection, plugin and generated loading semantics.

**Acceptance criteria:**

- A fixture with only product reachability returns `product`.
- A fixture with only a test-driver reachability returns `test-only` and `ProductAbsenceVerification=VERIFIED`.
- A fixture reached by both product and test roots returns `mixed`.
- A target absent from both complete closures returns `unknown`.
- A failed or malformed stream returns an error/incomplete result and never `test-only`.
- A package found in the full `-test` list but not reachable from a recognized test root does not receive `test-only`.
- A module-only request has an empty package identity and never creates a guessed package path.
- Repeated classification over identical raw streams produces byte-stable result JSON.
- Existing resolver tests retain their previous `ListPackages` behavior.

**Exact validation commands:**

```bash
cd <VA_REPO>
go test ./internal/affected -run 'TestUsageScope'
go test ./internal/affected
go test ./internal/llm -run 'Test.*GoTool'
go test ./internal/llm
```

**Do-not:**

- Не заменять no-test stream существующим `analyzeCompiledScope`.
- Не использовать `goanalysis.Index.linkedPaths()` для test closure.
- Не классифицировать каждый package из `go list -deps -test` как test-used.
- Не считать пустой список package результатом `test-only`.
- Не считать ошибку `go list` доказательством отсутствия в product closure.
- Не выводить package path из module path.
- Не менять существующую семантику `PackagePresent`/`BuildRelevant`.
- Не запускать source/runtime/deployment analysis в этом primitive.

### Task 2: Evidence tool `usage-scope`

**Depends on:** Task 1

**Scope:** обернуть двойной closure check в MCP evidence tool с явной полнотой, scope и ограничениями.

**Files:**

- Create: `internal/evidencetools/usage_scope.go:1`
- Modify: `internal/evidencetools/mcp.go:76` — `toolCatalog`
- Modify: `internal/evidencetools/mcp.go:134` — `NewServer` registration
- Modify: `internal/evidencetools/mcp_test.go:59-63,173-215`
- Create: `internal/evidencetools/usage_scope_test.go:1`
- Read/reuse: `internal/evidencetools/service.go:378-383` — default `GoTool`
- Read/reuse: `internal/evidencetools/observation.go:53-115`
- Read/reuse: `internal/evidencetools/scope.go:41-78` — completeness rules

**Interfaces:**

```go
const UsageScopeTool = "usage-scope"

type UsageScopeArgs struct {
    Module  string `json:"module"`
    Package string `json:"package,omitempty"`
}

type UsageScopeData struct {
    Module  string `json:"module"`
    Package string `json:"package,omitempty"`

    ProductLinked bool   `json:"product_linked"`
    TestLinked    bool   `json:"test_linked"`
    UsageScope    string `json:"usage_scope"`

    ProductAbsenceVerification string `json:"product_absence_verification,omitempty"`

    ProductPackageCount int `json:"product_package_count"`
    TestPackageCount    int `json:"test_package_count"`
    ProductRootCount    int `json:"product_root_count"`
    TestRootCount       int `json:"test_root_count"`

    CheckScope  string   `json:"check_scope"`
    Limitations []string `json:"limitations"`
}

func (s *Session) usageScope(
    ctx context.Context,
    args UsageScopeArgs,
) (*Observation, error)
```

**Change:**

1. Register `usage-scope` in the catalog and MCP server.
2. Require `Module`; accept an optional exact `Package`.
3. Reject a symbol argument by schema: B41 checks package/build closure, not symbol usage.
4. Call `ClassifyUsageScope` through `s.GoTool` using the session’s snapshot root and build context.
5. Construct `ScopeDetails` directly for this tool rather than using B42’s product-source `sourceScope` as the closure source. The scope must include:
   - snapshot hash/root;
   - build context;
   - product/test package counts;
   - product/test root counts;
   - command descriptions in `Extra`;
   - coverage rule for the paired streams.
6. Return `StatusOK` with `CompletenessComplete` only when both streams are successfully decoded and the closure rule is closed. The target may still have `usage_scope=unknown` when absent from both closures.
7. Return `ERROR`, `TIMEOUT` or `UNSUPPORTED` without a verified data payload when either stream cannot be completed.
8. Use stable limitations:
   - known result: classification is build-closure membership, not source-level use;
   - test-only: product absence is bounded to the recorded no-test closure;
   - unknown: scope is not closed or target is absent from both closures;
   - all branches: runtime execution, reflection, plugin loading, generated loading, deployment exposure and safety are out of scope.
9. Preserve raw command audit through the existing `toolaudit` context.
10. Add catalog and MCP tests for:
    - product;
    - test-only;
    - mixed;
    - unknown;
    - failed stream;
    - missing module;
    - module-only aggregate;
    - rejected symbol-shaped input.
11. Ensure the observation payload and limitations are deterministically sorted.

**Acceptance criteria:**

- The MCP tool advertises exactly the module/package argument shape.
- Both `go list` commands are visible in the recorded execution trail.
- `COMPLETE` has a non-empty paired-stream coverage rule.
- A test-only observation contains `product_absence_verification=VERIFIED`.
- A failed or incomplete check cannot produce `COMPLETE` or a verified fact.
- Module-only output contains no synthetic package path.
- The tool is absent from the static carrier allowlist.
- Existing MCP tool registration and observation contract tests remain valid.

**Exact validation commands:**

```bash
cd <VA_REPO>
go test ./internal/evidencetools -run 'TestUsageScope'
go test ./internal/evidencetools -run 'TestMCP.*'
go test ./internal/evidencetools
```

**Do-not:**

- Не использовать `PACKAGE_USAGE` payload для B41.
- Не заполнять `NegativeVerification` B42-поля.
- Не считать `Present=true` в объединённом `-test` списке test usage.
- Не использовать B41 tool как static carrier.
- Не добавлять runtime/deployment probes.
- Не возвращать `COMPLETE` без обеих закрытых closure streams.
- Не переписывать существующие observation artifacts.

### Task 3: Fact promotion и optional build-usage axis

**Depends on:** Task 2

**Scope:** добавить `BUILD_USAGE_SCOPE`, вызвать tool в deterministic lane, сохранить facts и вывести отдельный `/3` audit axis без новых conditions.

**Files:**

- Modify: `internal/research/types.go:31-35` — marker comments/invariants
- Modify: `internal/research/types.go:408-414` — `ExploitationAxes`
- Modify: `internal/research/types.go:735-796` — fact kinds, subject and `VerifiedFact`
- Modify: `internal/research/deterministic.go:386-410` — tool call position
- Modify: `internal/research/deterministic.go:676-773` — fact promotion
- Modify: `internal/research/deterministic.go:1124-1190` — subject/candidate helpers
- Modify: `internal/research/assemble.go:136-143` — optional axis normalization
- Modify: `internal/research/slice2.go:27-47` — Slice-2 ordering
- Modify: `internal/research/slice2.go:527-590` — unknown entry generation
- Create: `internal/research/usage_scope_test.go:1`
- Modify: `internal/research/deterministic_test.go:219-560`

**Interfaces:**

```go
const FactKindBuildUsageScope = "BUILD_USAGE_SCOPE"

type UsageScope string

const (
    UsageScopeProduct  = "product"
    UsageScopeTestOnly = "test-only"
    UsageScopeMixed    = "mixed"
    UsageScopeUnknown  = "unknown"
)

const ProductAbsenceVerificationVerified = "VERIFIED"
```

```go
type VerifiedFact struct {
    // existing fields

    Kind                       string `json:"kind,omitempty"`
    UsageSubject               *FactUsageSubject `json:"usage_subject,omitempty"`
    UsageScope                 string `json:"usage_scope,omitempty"`
    ProductAbsenceVerification string `json:"product_absence_verification,omitempty"`

    // existing fields
}
```

```go
type ExploitationAxes struct {
    CodeReachability          Axis `json:"code_reachability"`
    AttackSurfaceAvailability Axis `json:"attack_surface_availability"`
    ExploitationEstablished   Axis `json:"exploitation_established"`
    BuildUsageScope           *Axis `json:"build_usage_scope,omitempty"`
}
```

```go
func (a *assembler) slice2BuildUsageScope(r *Report)

func deriveBuildUsageScopeAxis(r *Report) *Axis
```

**Change:**

1. Add `BUILD_USAGE_SCOPE` as a distinct fact kind.
2. Reuse `FactUsageSubject` as the identity binding:
   - package check: `{Module, Package, Symbol:""}`;
   - module-only check: `{Module, Package:"", Symbol:""}`;
   - B41 validator, not B42 validator, decides whether an empty package is legal.
3. Build usage-scope candidates deterministically:
   - explicit `AffectedPackages`;
   - packages projected from `AffectedSymbols`;
   - one package-level check per sorted package;
   - one module-level aggregate check only when no package/symbol candidate exists;
   - no symbol-level B41 check.
4. Insert `usage-scope` calls immediately after the existing B42 package-usage block. This makes B41 observation ordering stable and keeps all existing tools before it.
5. Promote only `StatusOK` usage-scope observations with decoded `UsageScopeData`:
   - `Kind=BUILD_USAGE_SCOPE`;
   - `Claim=TRUE`;
   - `UsageScope` copied from payload;
   - `Coverage=COMPLETE` for closed paired streams;
   - `ProductAbsenceVerification=VERIFIED` only for `test-only`;
   - existing `NegativeVerification` always empty.
6. For a complete paired stream where the target is absent from both product and test closure, promote an auditable `UsageScope=unknown` fact with no product-absence marker. This records that the closed scope was checked without turning absence into a safety conclusion.
7. Do not promote incomplete/error/timeout/unsupported observations. They remain auditable observations and are converted into explicit B41 unknown/follow-up entries.
8. Add `deriveBuildUsageScopeAxis` as a pure report-only helper:
   - no facts → `nil`;
   - any `UsageScope=unknown` fact → `AxisUnknown`;
   - all facts known → `AxisEstablished`;
   - `Level=PACKAGE_BUILD`;
   - `Basis=deterministic`;
   - evidence refs are only matching `BUILD_USAGE_SCOPE` fact IDs in sorted order.
9. Axis statement must describe build-closure classification, never safety or exploitability.
10. Axis limitations must always state:
    - package/build closure only;
    - no source-use, runtime, deployment or safety conclusion;
    - test-only product absence is bounded to the recorded no-test closure.
11. Add unknown/open-question entries for:
    - tool error;
    - timeout/unsupported;
    - incomplete paired stream;
    - missing test roots/edges;
    - no target in either complete closure.
12. Do not add B41 to:
    - `staticCarrierTools`;
    - `conditionRoleForSubject`;
    - `canonicalPathSubject`;
    - `appendPackageUsageConditions`;
    - `deriveEvidenceLevel`.
13. Add a consistency guard:
    - a package-level `test-only` B41 fact cannot coexist with any carrier `PACKAGE_USAGE` fact for the same `{Module,Package}`;
    - module-level facts do not participate in this comparison;
    - `PACKAGE_USAGE_LOWER_BOUND` remains non-carrier and is not reinterpreted.

**Acceptance criteria:**

- Deterministic lane emits one B41 observation per package subject, or one module aggregate for module-only advisory.
- Fact promotion preserves exact subject binding.
- Product, test-only, mixed and complete-scope unknown rows are distinguishable in `verified_facts`.
- Incomplete/error rows remain UNKNOWN and never become verified negative facts.
- `build_usage_scope` is optional and appears only in `/3` reports with B41 facts.
- B41 adds no exploitation condition and no role.
- A report containing only `BUILD_USAGE_SCOPE` facts remains L2 or otherwise unchanged by B41; it cannot become L1.
- Existing B42 conditions, facts, subjects and levels are unchanged.
- Agent-only usage text does not populate the B41 axis.
- Repeated deterministic assembly produces stable fact and axis ordering.
- `/1` and `/2` serialized reports contain no `build_usage_scope` member.

**Exact validation commands:**

```bash
cd <VA_REPO>
go test ./internal/research -run 'TestDeterministic.*UsageScope'
go test ./internal/research -run 'TestUsageScopeAxis'
go test ./internal/research -run 'TestPackageUsage'
go test ./internal/research
```

**Do-not:**

- Не превращать `test-only` в `REFUTED` exploitation condition.
- Не добавлять B41 fact в `evidence_level.evidence_refs`.
- Не менять `deriveEvidenceLevel`.
- Не менять L1/L2/L3 semantics.
- Не считать `usage_scope=product` доказательством direct source call.
- Не считать `usage_scope=test-only` доказательством runtime non-use.
- Не подменять module-only subject package-level subject.
- Не добавлять новые contract markers.

### Task 4: Fail-closed validator, compatibility и render

**Depends on:** Task 3

**Scope:** валидировать новый fact/axis contract и отобразить его без safety wording или смешения с B42 package usage.

**Files:**

- Modify: `internal/research/validate.go:149-205` — verified-fact validation call site
- Modify: `internal/research/validate.go:590-650` — axis validation
- Modify: `internal/research/validate.go:1588-1660` — fact-kind validation
- Modify: `internal/research/validate.go:1662-1868` — B42 cross-fact/condition boundary
- Modify: `internal/research/render.go:230-250` — axis rendering
- Modify: `internal/research/render.go:557-583` — facts appendix
- Create: `internal/research/usage_scope_validate_test.go:1`
- Create: `internal/research/usage_scope_render_test.go:1`
- Modify: `internal/research/evidence_level_contract_test.go:68-100,260-285`
- Modify: `internal/research/evidence_level_validate_test.go:530-545`

**Interfaces:**

```go
func validateBuildUsageScopeFact(
    e *ValidationError,
    f VerifiedFact,
    where string,
)

func validateBuildUsageScopeAxis(
    e *ValidationError,
    r *Report,
)
```

Allowed B41 values:

```go
FactKindBuildUsageScope
UsageScopeProduct
UsageScopeTestOnly
UsageScopeMixed
UsageScopeUnknown
ProductAbsenceVerificationVerified
```

**Change:**

1. Extend the closed fact-kind validation:
   - `Kind=BUILD_USAGE_SCOPE` requires `Tool=usage-scope`;
   - `Kind=BUILD_USAGE_SCOPE` requires non-empty `UsageScope`;
   - `Claim` must be `TRUE`;
   - `NegativeVerification` must be empty;
   - `UsageSubject` is required;
   - `UsageSubject.Symbol` must be empty;
   - `UsageSubject.Module` must be non-empty;
   - `UsageSubject.Package` may be empty only for a module aggregate;
   - package-level B41 facts require non-empty package;
   - module-level B41 facts require empty package.
2. Require `Coverage=COMPLETE` for promoted known/unknown closed-scope B41 facts.
3. Validate `ProductAbsenceVerification`:
   - only `VERIFIED` is allowed;
   - it is allowed only with `UsageScope=test-only`;
   - it requires `Coverage=COMPLETE`;
   - it is forbidden for `product`, `mixed` and `unknown`.
4. Preserve the existing B42 rules:
   - `PACKAGE_USAGE` still requires a non-empty package subject;
   - `PACKAGE_USAGE_LOWER_BOUND` remains non-carrier;
   - existing `NegativeVerification` remains B42-only.
5. Validate optional `build_usage_scope` axis:
   - if no B41 fact exists, the pointer must be nil;
   - if B41 facts exist, the axis must be present;
   - recompute it through `deriveBuildUsageScopeAxis`;
   - compare status, level, basis, statement, scope, limitations and sorted evidence refs;
   - reject forged axis state or forged fact references.
6. Explicitly reject:
   - B41 fact in `product_applicability.evidence_refs`;
   - B41 fact in `product_applicability.basis[*].verified_evidence_refs`;
   - B41 fact used to support `vulnerable_code_reachability=FALSE`;
   - B41 fact used to support `NON_APPLICABLE`;
   - B41 fact cited by a B42 usage condition as its carrier.
7. Enforce B41/B42 consistency for equal package subjects:
   - `UsageScope=test-only` plus B42 `PACKAGE_USAGE` carrier is invalid;
   - a module aggregate does not participate in package equality.
8. Keep `/1` and `/2` validation branches unchanged. Their old fixtures must remain valid with no B41 fields.
9. Render:
   - the optional build-usage axis in the existing axis section;
   - `BUILD_USAGE_SCOPE`, `usage_scope`, subject and product-absence verification in the deterministic facts appendix;
   - exact paired-stream check scope;
   - a permanent limitation that classification is not a safety or runtime conclusion.
10. Never render `test-only` as “safe”, “not affected”, “not exploitable” or equivalent.

**Acceptance criteria:**

- Forged B41 kind/tool mismatch is rejected.
- Forged symbol-bound B41 subject is rejected.
- Forged module/package subject shape is rejected.
- `claim=FALSE` B41 fact is rejected.
- B41 fact with `NegativeVerification` is rejected.
- `test-only` without `ProductAbsenceVerification=VERIFIED` is rejected.
- `ProductAbsenceVerification=VERIFIED` on product/mixed/unknown is rejected.
- Partial B41 coverage is rejected as a verified fact.
- Axis/fact mismatch is rejected.
- B41 fact cannot close a B42 condition or raise evidence level.
- A test-only report validates only as a bounded reviewable report and retains `REVIEW_REQUIRED`/`auto_close=false`.
- `/1` and `/2` fixtures parse, validate and render without B41 members.
- Markdown contains no safety wording for test-only or product absence.
- Repeated render is byte-stable.

**Exact validation commands:**

```bash
cd <VA_REPO>
go test ./internal/research -run 'TestUsageScopeFactValidation'
go test ./internal/research -run 'TestUsageScopeAxisValidation'
go test ./internal/research -run 'TestUsageScopeRender'
go test ./internal/research -run 'TestSlice2_LegacyReportStillValidates|TestSlice2V2'
go test ./internal/research
```

**Do-not:**

- Не принимать B41 `claim=FALSE`.
- Не принимать B41 `NegativeVerification` как замену `ProductAbsenceVerification`.
- Не разрешать B41 fact закрывать L1.
- Не разрешать B41 fact формировать VCR `FALSE`.
- Не смешивать B41 axis с `exploitation_established`.
- Не добавлять B41 fields в `/1` или `/2` fixtures.
- Не превращать validator error в downgrade до L2.
- Не рендерить test-only как safety conclusion.

### Task 5: Offline replay, saved-data census и specialist regression

**Depends on:** Task 4

**Scope:** расширить replay driver для B41, измерить before/after по существующим `C01`–`C31` и отдельной сохранённой specialist test-only выборке без model runs.

**Files:**

- Modify: `tools/evidence-levels-replay.py:1-170` — constants, scrub and feature metadata
- Modify: `tools/evidence-levels-replay.py:303-455` — baseline/scope census helpers
- Modify: `tools/evidence-levels-replay.py:619-802` — semantic projection and branch assertions
- Modify: `tools/evidence-levels-replay.py:877-1112` — CLI, discovery and report
- Modify: `internal/research/replay_test.go:700-980,1100-1320`
- Create: `docs/dev/reports/2026-10-14-02-usage-scope-regression.md`

**Interfaces:**

New driver helpers:

```python
def usage_scope_rows(report): ...
def usage_scope_census(reports): ...
def assert_usage_scope_branch(report): ...
def assert_b41_delta(before, after): ...
def assert_scope_axis_consistency(report): ...
```

New CLI options:

```text
--specialist-root <ROOT>
--specialist-input-suffix agent
--specialist-label-map <PRIVATE_LABEL_MAP>
--specialist-historical-before
--b41-out-suffix agent-v5
```

Existing C-set invocation continues to support:

```text
--primary-root
--primary-input-suffix agent
--primary-baseline-suffix agent-v4
--retry-glob
--retry-input-suffix agent
--retry-baseline-suffix agent-v4
--label-map
--izyan
--govulndb
--modcache
--work-dir
--report
```

**Change:**

1. Keep all saved input trees immutable:
   - input remains under `<VA_TMP>`;
   - output goes to a new scratch work directory or new sibling;
   - no `report.json`, artifact or saved answer is rewritten.
2. For the existing primary/retry sets:
   - source is the saved `agent` directory;
   - before baseline is the B42 rebuilt `agent-v4` sibling;
   - after output is a new B41 sibling or scratch directory.
3. For the specialist set:
   - use a separate read-only root;
   - use an explicit private label map whose emitted labels are only `C01`–`C31`;
   - historical before state is the saved report from the input directory because no pre-existing B42 baseline sibling is assumed;
   - missing specialist root, label map or historical report is a hard `NOT_RUN` blocker, not a silent skip.
4. Add scope census fields:
   - `usage_scope` state;
   - number of B41 facts;
   - number of product/test-only/mixed/unknown facts;
   - number of complete and incomplete observations;
   - axis state;
   - `ProductAbsenceVerification` count.
5. Before/after expectations must be shape-based, not fixed-number promises:
   - before B41: `usage_scope=ABSENT` for reports without the new fact;
   - after known branch: `product`, `test-only` or `mixed` only with complete paired closure;
   - after unresolved branch: `UNKNOWN` or explicit `NOT_RUN`;
   - test-only branch requires `ProductAbsenceVerification=VERIFIED`;
   - no B41 result may produce a safe verdict.
6. Extend semantic projection to require byte-equivalence for all unrelated fields:
   - advisory/vulnerability identity;
   - affected implementations;
   - snapshot/build identity;
   - module/version applicability;
   - selected/pending/unresolved modules;
   - advisory entry status;
   - agent output and attempt rows;
   - all pre-existing exploitation axes;
   - disposition;
   - classification original category.
7. Allow only these B41-specific differences:
   - new `usage-scope` observations and artifacts;
   - new `BUILD_USAGE_SCOPE` facts;
   - `exploitation_axes.build_usage_scope`;
   - B41 unknown/open-question entries;
   - explicitly linked render text.
8. Assert that:
   - `evidence_level` JSON is unchanged by B41-only changes;
   - `disposition.class=REVIEW_REQUIRED`;
   - `disposition.auto_close=false`;
   - no agent ref enters verified facts, B41 axis or level evidence;
   - no B41 fact appears in product-applicability negative refs;
   - B42 package-usage subject parity remains exact.
9. Run the same replay twice into fresh work directories. Compare reports after removing only documented wall-clock fields. Condition states, B41 facts, axis JSON, evidence-level JSON, disposition and census must match.
10. The regression report must contain:
    - before/after level census for primary and retry sets;
    - before/after `usage_scope` census;
    - specialist-set measurement;
    - product/test-only/mixed/unknown branch counts;
    - explicit `NOT_RUN` blockers if any;
    - unchanged-field assertions;
    - no private identifiers or absolute paths.
11. The report must state measured results, not predicted counts. A specialist test-only row is accepted only when its actual paired closure check yields `test-only`; otherwise it remains `UNKNOWN`/`NOT_RUN` and B41 is not complete.

**Acceptance criteria:**

- All discovered C-labelled primary/retry runs are replayed or reported as explicit failures.
- The B42 before matrices are loaded from `agent-v4`, not asserted as new B41 results.
- The after level matrix is measured; B41-only changes do not silently alter levels.
- Every known B41 result has a complete, explicit paired-stream scope.
- Every `test-only` result has a verified product-absence marker.
- Every unresolved stream remains UNKNOWN or is reported as NOT_RUN.
- Specialist test-only regression is either measured successfully or blocks backlog closure with an exact missing prerequisite.
- Saved input hashes are identical before and after.
- Repeated replay is stable.
- No model, harness or network execution occurs.

**Exact validation commands:**

```bash
cd <VA_REPO>
go test ./internal/research -run 'TestReplay.*UsageScope'
go test ./internal/research -run 'TestReplay.*Artifact|TestReplay.*Status'
```

```bash
cd <VA_REPO>
WORK="$(mktemp -d)"
BIN="$WORK/izyan"
go build -o "$BIN" ./cmd/izyan

GOPROXY=off \
GOSUMDB=off \
GOFLAGS=-mod=readonly \
python3 tools/evidence-levels-replay.py \
  --primary-root "<VA_TMP>/exploitable/runs" \
  --primary-input-suffix agent \
  --primary-baseline-suffix agent-v4 \
  --retry-glob "<VA_TMP>/exploitable-retry/runs" \
  --retry-glob "<VA_TMP>/exploitable-retry-invalid/runs" \
  --retry-input-suffix agent \
  --retry-baseline-suffix agent-v4 \
  --specialist-root "<VA_TMP>/specialist/runs" \
  --specialist-input-suffix agent \
  --specialist-label-map "<PRIVATE_LABEL_MAP>" \
  --specialist-historical-before \
  --label-map "<PRIVATE_LABEL_MAP>" \
  --izyan "$BIN" \
  --govulndb "<VA_TMP>/govulndb" \
  --modcache "<VA_TMP>/modcache" \
  --work-dir "$WORK/replay-1" \
  --b41-out-suffix agent-v5 \
  --report "$WORK/b41-regression-1.json"
```

```bash
cd <VA_REPO>
WORK="$(mktemp -d)"
BIN="$WORK/izyan"
go build -o "$BIN" ./cmd/izyan

GOPROXY=off \
GOSUMDB=off \
GOFLAGS=-mod=readonly \
python3 tools/evidence-levels-replay.py \
  --primary-root "<VA_TMP>/exploitable/runs" \
  --primary-input-suffix agent \
  --primary-baseline-suffix agent-v4 \
  --retry-glob "<VA_TMP>/exploitable-retry/runs" \
  --retry-glob "<VA_TMP>/exploitable-retry-invalid/runs" \
  --retry-input-suffix agent \
  --retry-baseline-suffix agent-v4 \
  --specialist-root "<VA_TMP>/specialist/runs" \
  --specialist-input-suffix agent \
  --specialist-label-map "<PRIVATE_LABEL_MAP>" \
  --specialist-historical-before \
  --label-map "<PRIVATE_LABEL_MAP>" \
  --izyan "$BIN" \
  --govulndb "<VA_TMP>/govulndb" \
  --modcache "<VA_TMP>/modcache" \
  --work-dir "$WORK/replay-2" \
  --b41-out-suffix agent-v5 \
  --report "$WORK/b41-regression-2.json"
```

```bash
python3 - "$WORK/b41-regression-1.json" "$WORK/b41-regression-2.json" <<'PY'
import json
import sys

def stable(path):
    data = json.load(open(path))
    def clean(value):
        if isinstance(value, dict):
            return {
                k: clean(v)
                for k, v in value.items()
                if k not in {"wall_s", "total_wall_s"}
            }
        if isinstance(value, list):
            return [clean(v) for v in value]
        return value
    return json.dumps(clean(data), sort_keys=True, separators=(",", ":"))

if stable(sys.argv[1]) != stable(sys.argv[2]):
    raise SystemExit("B41 replay is not deterministic")
PY
```

**Do-not:**

- Не запускать model runs или live harness.
- Не переписывать `agent`, `agent-v4`, saved reports или artifacts.
- Не публиковать исходные unit/ticket/snapshot identifiers.
- Не обещать заранее количество `product`, `test-only`, `mixed`, `UNKNOWN` или L1/L2 переходов.
- Не считать исторический specialist report полноценным baseline без явного ограничения.
- Не скрывать `NOT_RUN`.
- Не считать test-only safe verdict.
- Не разрешать изменения unrelated semantic projection.
- Не использовать новые evaluation corpora.

### Task 6: False-safe gate, ADR, backlog и документация

**Depends on:** Task 5

**Scope:** проверить общий safety gate и зафиксировать фактически реализованный B41-контракт и измеренные результаты.

**Files:**

- Modify: `docs/dev/gap-analysis.md:60` — строка B41
- Modify: `docs/dev/decisions/agent7-e2e-conclusion-fidelity.md:146,166+` — новая §8 B41 record
- Modify: `eval/README.md:847+` — описание новой offline-регрессии
- Create/update: `docs/dev/reports/2026-10-14-02-usage-scope-regression.md`
- Read/reuse: `internal/eval/eval.go:169,263-292` — `FalseSafe`

**Interfaces:**

Документный B41 contract:

- tool: `usage-scope`;
- fact kind: `BUILD_USAGE_SCOPE`;
- values: `product`, `test-only`, `mixed`, `unknown`;
- subject: existing `usage_subject`, package-level or bounded module aggregate;
- product absence marker: `ProductAbsenceVerification=VERIFIED` only for closed `test-only`;
- B42 `PACKAGE_USAGE` and `PACKAGE_USAGE_LOWER_BOUND` semantics unchanged;
- B41 fact and axis are non-carrier;
- no new condition role;
- no evidence-level impact;
- `REVIEW_REQUIRED` and `auto_close=false` remain mandatory.

**Change:**

1. Add ADR §8 describing:
   - why build-closure classification is a separate axis from product-source usage;
   - exact no-test and with-test commands;
   - product/test root semantics;
   - classification table;
   - incomplete-scope behavior;
   - module-only behavior;
   - `BUILD_USAGE_SCOPE` validation;
   - B42 composition and consistency checks;
   - non-carrier and non-safety guarantees.
2. Update the ADR’s previous statement that test-only usage is unavailable.
3. Update `eval/README.md` with:
   - offline replay command shape;
   - C-labelled before/after census;
   - specialist-set handling;
   - no-model guarantee;
   - false-safe gate;
   - explicit statement that measured counts are not predicted.
4. Update the regression report with measured values only:
   - level census before/after;
   - usage-scope census before/after;
   - known/unknown/NOT_RUN rows;
   - specialist test-only outcomes;
   - deterministic replay comparison;
   - saved-input hash comparison;
   - unrelated-field parity.
5. Remove the B41 row from `docs/dev/gap-analysis.md` only after:
   - code tests pass;
   - specialist test-only regression is not `NOT_RUN`;
   - false-safe gate is zero;
   - final Go gate passes.
6. If specialist closure prerequisites are unavailable, keep B41 open and record the exact blocker in the report; do not claim completion.
7. Run a privacy scan over every changed committed document. Only C labels and placeholders `<VA_REPO>`, `<VA_TMP>`, `<PRIVATE_LABEL_MAP>` may appear.

**Acceptance criteria:**

- ADR describes the actual implementation, not an intended future design.
- Regression report contains measured before/after values and branch shapes.
- Test-only facts are described as bounded build-closure facts, never safety conclusions.
- No private identifiers, absolute local paths or provider-specific data appear in committed documents.
- `docs/dev/gap-analysis.md` follows the project convention: B41 is removed only after all done-criteria pass.
- `go run ./cmd/izyan eval --corpus eval/corpus-real.json -j 4` reports `false-safe=0`.
- The final Go gate passes exactly as listed in Global Constraints.

**Exact validation commands:**

```bash
cd <VA_REPO>
go run ./cmd/izyan eval --corpus eval/corpus-real.json -j 4
```

```bash
cd <VA_REPO>
git diff --check -- \
  docs/dev/gap-analysis.md \
  docs/dev/decisions/agent7-e2e-conclusion-fidelity.md \
  docs/dev/reports/2026-10-14-02-usage-scope-regression.md \
  eval/README.md
```

```bash
cd <VA_REPO>
python3 - <<'PY'
from pathlib import Path
import re

files = [
    Path("docs/dev/gap-analysis.md"),
    Path("docs/dev/decisions/agent7-e2e-conclusion-fidelity.md"),
    Path("docs/dev/reports/2026-10-14-02-usage-scope-regression.md"),
    Path("eval/README.md"),
]

for path in files:
    text = path.read_text()
    assert "/Users/" not in text, path
    assert not re.search(r"\bcase-\d+\b", text, re.I), path
    assert not re.search(r"\bticket-\d+\b", text, re.I), path

assert "| B41 |" not in Path("docs/dev/gap-analysis.md").read_text()
PY
```

```bash
cd <VA_REPO>
gofmt -w internal/affected/*.go internal/goanalysis/*.go internal/evidencetools/*.go internal/research/*.go cmd/izyan/*.go
test -z "$(gofmt -l .)"
go vet ./...
go test -count=1 ./...
```

**Do-not:**

- Не удалять B41 из backlog до measured specialist regression.
- Не фиксировать обещанный результат вместо фактического census.
- Не публиковать приватные case/ticket/path identifiers.
- Не трактовать `false-safe=0` как доказательство полноты B41.
- Не менять сохранённые inputs или artifacts ради успешного отчёта.
- Не добавлять модельные прогоны, prompt tuning или новый corpus.
- Не оставлять в ADR формулировку, будто test-only является safe conclusion.

## Dependency / Execution Order

```text
Task 1 ──> Task 2 ──> Task 3 ──> Task 4 ──> Task 5 ──> Task 6
```

- Task 1 сначала стабилизирует два closure streams и классификацию.
- Task 2 превращает primitive в auditable evidence tool.
- Task 3 подключает tool к deterministic lane и report model, не меняя B42 conditions или level derivation.
- Task 4 закрывает validator/render boundary и legacy compatibility.
- Task 5 выполняет единственный saved-data replay без model runs и измеряет обе ветви.
- Task 6 запускает false-safe и финальные gates, затем обновляет ADR, regression report, `eval/README.md` и удаляет B41 из backlog только при полном выполнении done-критерия.

# План повышения работоспособности Shadow research lane

**Цель:** устранить конкретные потери usable evidence в существующей Shadow-полосе без смены архитектуры, prompt/model-протокола или sandbox boundary.

**Архитектура:** сохранить существующий поток `deterministic lane → verified facts → agent assertions/unknowns → REVIEW_REQUIRED`; исправить только extractor recovery, локальную offline-интеграцию govulncheck, привязку dataflow к реальным call sites, preflight retry и regression/replay tooling.

**Tech stack:** Go 1.26.1 runtime, текущий Go module (`go.mod:1-13`), `govulncheck`, Python 3 stdlib для offline regression, существующие E6 harness и `--replay-agent-turn`.

**Spec / ADR:** `docs/dev/decisions/agent7-shadow-base-decision.md` — материализуется контроллером из ADR выше.

**Пути:** `<VA_REPO>` — корень репозитория (`vuln-analyzer-shadow`); `<VA_TMP>` — приватный каталог прогонов вне репозитория.

## Global Constraints

1. Новых model runs нет. Regression выполняется только по сохранённым ответам и артефактам.
2. Prompt tuning, новая prompt-experiment series и новые большие corpora запрещены.
3. V2 не переносится целиком; resolver semantics, classifier и first-parseable-JSON rule не заимствуются.
4. A3, новый Proof Engine, MCP Fact Broker, VEX и auto-close не разрабатываются.
5. Sandbox остаётся fail-closed. Нельзя добавлять network access, расширять mounts, разрешать repository execution или ослаблять E6 permission policy. E6 report явно фиксирует `network=none`, `cap_drop=ALL`, `no-new-privileges` и read-only `/work` (`eval/agent7/freeze/e6/security-boundary-check.json:1-30`).
6. Агентский turn не ретраится. Допускается только ограниченный retry transient live preflight.
7. `verified_facts` создаются только из успешных deterministic observations; агентские claims не promoted (`internal/research/deterministic.go:600-675`; `internal/research/assemble.go:72-93`).
8. `UNKNOWN` остаётся явным, с причиной и follow-up; отсутствие результата инструмента нельзя превращать в безопасный вывод.
9. Все изменения должны сохранять artifact hashes, attempt identity и replay provenance.
10. Любой ожидаемый эффект, который ещё не измерен после реализации, обозначается в итоговом отчёте как **[INFERENCE]**, а не как достигнутый результат.

## Review Focus

- Strict extractor восстанавливает только ограниченный набор повреждений и продолжает отклонять ambiguity.
- Offline `govulncheck` действительно использует локальный DB root и не делает network fetch во время research run.
- Declaration positions не попадают в dataflow active path.
- Невалидная call-site позиция получает scoped limitation, а не ложный `OK` и не misleading execution `ERROR`.
- Provider retry не запускает второй agent attempt и не меняет sandbox.
- Replay/regression не вызывает модель и не усиливает conclusion сверх deterministic support.
- Финальный отчёт явно показывает facts, agent hypotheses, unknowns и remaining exploitation conditions.

### Task 1: Bounded extractor recovery

**Depends on:** None. Независим от Tasks 2–4.

**Scope:** убрать потерю substantive answers из-за повреждений, которые можно восстановить ограниченно, сохранив rejection на ambiguity и malformed reasoning.

**Files:**

- Modify: `internal/research/slice2.go`, `strictExtract` и новые внутренние helpers `recoverExtract`, `scanObjectRegions`.
- Modify: `internal/research/types.go`, `Extraction` и enum/constants recovery marker.
- Modify: `internal/research/validate.go`, validation нового optional extraction field.
- Modify: `internal/research/render.go`, отображение recovery marker в attempt audit.
- Test: `internal/research/slice2_test.go`.
- Test: `internal/research/replay_test.go`.

`agent.go:329-337` уже вызывает `strictExtract`, а `replay.go:253-260` использует тот же extractor для replay OK-turn. Не создавать вторую реализацию parser/recovery в `agent.go` или `replay.go`.

**Interfaces:**

```go
func strictExtract(text string) (*agentAnswer, *Extraction)
func recoverExtract(text string) (*agentAnswer, *Extraction)
```

Добавить в `Extraction`:

```go
Recovery string `json:"recovery,omitempty"`
```

Допустимые значения:

```text
""                  // strict extraction
BRACE_COMPLETION
MEMBER_SALVAGE
```

Существующие поля `status`, `invalid_reason`, `candidate_count`, `candidates`, `selected_index` не меняются (`internal/research/types.go:330-348`).

**Change:**

1. Сохранить текущий strict pass без изменений по смыслу:
   - сканировать все complete JSON candidates;
   - сохранять все candidates;
   - конфликт нескольких различных VALID candidates оставлять `INVALID_AMBIGUOUS`;
   - не запускать recovery, если strict pass нашёл хотя бы одного candidate.
2. Вызывать `recoverExtract` только если strict pass дал `CandidateCount == 0` / `InvalidNoCandidate`.
3. Реализовать string-aware `scanObjectRegions`, который учитывает quoted strings, escapes и границы object regions.
4. Реализовать bounded brace completion:
   - только 1–2 unmatched `{` в EOF;
   - добавить недостающие closing braces;
   - повторно прогнать strict validation;
   - принять только если результат `VALID`;
   - записать `recovery=BRACE_COMPLETION`.
5. Реализовать member salvage:
   - искать только depth-1 `category` и `reasoning`;
   - оба значения должны быть синтаксически корректными и непустыми;
   - `category` после normalization должна принадлежать `validCategories` (`internal/research/agent.go:426-432`);
   - если найдено несколько регионов, принять только при ровно одной distinct `(category, reasoning)` pair;
   - `assessment` сохранять только если его собственный JSON parseable;
   - записать `recovery=MEMBER_SALVAGE`.
6. Сохранить `reasoning` с незавершённой строкой как `INVALID`; не извлекать его по prefix.
7. Replay должен использовать тот же `strictExtract`/recovery ladder. Сохранённый non-OK status не должен ретроактивно превращаться в OK: replay сохраняет recorded status, как предписано `replay.go:249-260`.
8. Render должен показывать marker рядом с extraction status, чтобы recovery был виден в audit, а не скрывался в отчёте.

Ожидаемая классификация сохранённых примеров:

- `C08` → recovery `BRACE_COMPLETION`;
- `C19` → recovery `MEMBER_SALVAGE`;
- `C25` → recovery `BRACE_COMPLETION` либо `MEMBER_SALVAGE` в зависимости от фактического reconstructed region, но обязательно `VALID`;
- `C26` → `INVALID`;
- `C27` → `INVALID`.

Ожидание 3/5 — acceptance target из verified diagnosis, а не результат, объявляемый заранее.

**Acceptance criteria:**

- Strict ambiguity behaviour не изменился: два различных valid objects остаются `INVALID_AMBIGUOUS`.
- Markdown fences не требуют отдельного stripping path.
- Recovery запускается только при нулевых strict candidates.
- Повреждение `assessment` не приводит к bracket repair или backslash deletion.
- `C08`, `C19`, `C25` дают валидный answer с recovery marker.
- `C26` и `C27` остаются `INVALID`.
- Replay и live parsing используют одинаковую ladder.
- Старые reports без optional `recovery` продолжают валидироваться.

**Exact validation commands:**

```bash
cd <VA_REPO>
go test ./internal/research -run 'TestSlice2_StrictExtraction|TestSlice2_ExtractorRecovery|TestReplay_ExtractorRecovery'
go test ./internal/research
```

**Do-not:**

- не принимать первый parseable JSON;
- не удалять backslashes;
- не перебирать key re-quoting;
- не делать bracket repair;
- не снимать rejection на conflicting candidates;
- не принимать unterminated `reasoning`;
- не менять prompt или harness;
- не переносить V2 extractor semantics.

### Task 2: Offline `govulncheck` с локальным GOVULNDB

**Depends on:** None, но требуется эксплуатационное предусловие: writable local GOVULNDB root и подготовленный module cache.

**Scope:** сделать воспроизводимый research run с локальной vulnerability database, сохранив strict environment и существующий CLI wiring.

**Files:**

- Modify/test: `internal/goanalysis/govulncheck.go`, `Runner`, `ExecRunner.RunGovulncheck`, `DBInformer`.
- Test: `internal/goanalysis/govulncheck_test.go`.
- Modify/test: `internal/evidencetools/dependencies.go`, `runGovulncheck`.
- Modify/test: `internal/evidencetools/hardening_test.go`.
- Verify/test: `cmd/izyan/research.go`, flags `--govulndb`, `--modcache`, `--deterministic-only` (`:58,123-124`).
- Verify/test: `cmd/izyan-evidence-tools/main.go`, flags `--govulndb`, `--modcache` (`:57`).
- Modify: `docs/cli.md`, добавить offline runbook и captured environment/provenance requirements.

Task не изменяет `internal/research/deterministic.go`; существующий pass-through `LaneOptions.GovulnDB → SessionConfig.GovulnDBRoot` уже находится в `internal/research/deterministic.go:237-260`.

**Precondition:**

- Создать writable `$GOVULNDB_ROOT`.
- Подготовить `$MODCACHE_ROOT` с нужными module sources.
- Один раз установить и обновить database вне offline research run:

```bash
cd <VA_REPO>

mkdir -p "$GOVULNDB_ROOT" "$MODCACHE_ROOT" "$GOBIN"
GOBIN="$GOBIN" go install golang.org/x/vuln/cmd/govulncheck@latest
"$GOBIN/govulncheck" -db.root "$GOVULNDB_ROOT" update
```

После подготовки зафиксировать binary version, DB metadata/hash и module-cache identity в run notes. Сам research run должен выполняться без egress.

**Interfaces:**

```go
type Runner interface {
    RunGovulncheck(
        ctx context.Context,
        dir string,
        build domain.ProductSnapshot,
    ) (raw []byte, pattern string, err error)
}

type DBInformer interface {
    DBInfo(ctx context.Context) (string, error)
}
```

Observation contract:

```text
tool:          run_govulncheck
tool_status:   OK | UNSUPPORTED | ERROR
completeness:  PARTIAL on successful scan
data:
  in_database: bool
  findings:    []Finding
  count:       int
  pattern:     string
  db_info:     string
```

Эти поля и limitation уже определены в `internal/evidencetools/dependencies.go:255-260,279-321`.

**Change:**

1. Сохранить разрешение binary через PATH/GOBIN/GOPATH и честный `UNSUPPORTED`, если binary отсутствует (`internal/goanalysis/govulncheck.go:35-70`).
2. Убедиться, что `ExecRunner` получает `GOVULNDB` и `GOMODCACHE` через strict tool environment.
3. Сохранить `GOPROXY=off`, `GOSUMDB=off`, `GOFLAGS=-mod=readonly` в strict profile (`internal/evidencetools/service.go:250-289`).
4. Сохранить confinement GOVULNDB root и module-cache root (`internal/evidencetools/service.go:273-289`).
5. Не считать отсутствие finding доказательством отсутствия vulnerability; сохранять `in_database` и existing limitations (`internal/evidencetools/dependencies.go:321-321`).
6. Добавить test coverage:
   - strict без `--govulndb` → `UNSUPPORTED`;
   - strict с локальным root → `OK`, audit содержит canonical `GOVULNDB`;
   - missing module в strict не уходит в ambient proxy;
   - govulncheck exit code 3 с findings остаётся успешным scan result, как уже предусмотрено `internal/goanalysis/govulncheck.go:120-160`.
7. В документации зафиксировать, что `govulncheck -db.root ... update` — preparation step, а не часть offline run.

**Exact validation commands:**

Focused tests:

```bash
cd <VA_REPO>
go test ./internal/goanalysis ./internal/evidencetools ./cmd/izyan
```

Representative saved-case offline run:

```bash
cd <VA_REPO>

CASE=eval/agent7/e2e/k8s-44487
SNAPSHOT=$(python3 -c 'import json; print(json.load(open("eval/agent7/e2e/k8s-44487/run-manifest.json"))["snapshot"]["path"])')
CVE=$(python3 -c 'import json; print(json.load(open("eval/agent7/e2e/k8s-44487/run-manifest.json"))["advisory"]["requested_id"])')
EXT_SHA=$(python3 -c 'import json; print(json.load(open("eval/agent7/e2e/k8s-44487/run-manifest.json"))["snapshot"].get("external_commit_sha",""))')

test -d "$GOVULNDB_ROOT"
test -d "$MODCACHE_ROOT"
test -x "$GOBIN/govulncheck"

env \
  GOPROXY=off \
  GOSUMDB=off \
  GOFLAGS=-mod=readonly \
  PATH="$GOBIN:$PATH" \
  go run ./cmd/izyan research \
    --snapshot "$SNAPSHOT" \
    --cve "$CVE" \
    --advisory-file eval/agent7/advisories/k8s-44487.json \
    --external-commit-sha "$EXT_SHA" \
    --output-dir "$(mktemp -d)" \
    --deterministic-only \
    --govulndb "$GOVULNDB_ROOT" \
    --modcache "$MODCACHE_ROOT"
```

Acceptance check: resulting `observations.jsonl` contains `tool=run_govulncheck` with `tool_status=OK`, `db_info` or equivalent DB provenance, and no `UNSUPPORTED` reason caused by an empty `GovulnDBRoot`.

**Do-not:**

- не использовать network fallback во время research run;
- не читать ambient module cache в strict profile;
- не менять `AllowExec`/sandbox policy ради govulncheck;
- не превращать отсутствие finding в negative conclusion;
- не добавлять второй competing CLI flag вместо существующих `--govulndb`/`--modcache`;
- не запускать модель;
- не считать одно успешное representative case доказательством покрытия всех cases.

### Task 3: Исправление dataflow call-site binding и downgrade некорректной позиции

**Depends on:** None. Независим от Tasks 1, 2 и 4.

**Scope:** не передавать declaration sites в `trace_argument`, `find_validations` и `check_call_site_guard`; для ошибочной позиции выдавать честное scoped limitation вместо misleading execution error или vacuous OK.

**Files:**

- Modify: `internal/research/deterministic.go`, участок `boundSites` и `callSitesOf` (`:386-426,1078-1117`).
- Modify: `internal/goanalysis/provenance.go`, `callAt`/`scanCallAt` (`:160-187`).
- Modify: `internal/goanalysis/config.go`, `CheckCallSiteGuard`/`checkCallSiteGuardLocked` (`:189-208`).
- Modify: `internal/evidencetools/dataflow.go`, `traceArgument` и `findValidations` (`:10-125`).
- Modify: `internal/evidencetools/dynamic.go`, `checkCallSiteGuard` (`:210-248`).
- Test: `internal/research/deterministic_test.go`.
- Test: `internal/goanalysis/config_test.go`.
- Test: `internal/evidencetools/scope_test.go`.

**Interfaces:**

Сохранить публичные tool input schemas:

```json
{
  "file": "string",
  "line": "integer > 0",
  "column": "integer, optional for legacy input",
  "arg_index": "integer; -1 = all args; -2 = receiver"
}
```

Внутри goanalysis добавить typed scope error, например:

```go
var ErrCallSiteNotFound = errors.New("call site not found")
```

или эквивалентный typed error, распознаваемый через `errors.Is`, без string matching.

Tool result for a non-call position:

```text
tool_status:  UNSUPPORTED
completeness: UNKNOWN
scope:        call-site-only; supplied position is not an AST call
error/detail: explicit scoped limitation
```

Настоящие backend/load failures остаются `ERROR`/`UNKNOWN`, потому что `errorObs` обязан отличать «проверка не выполнена из-за сбоя» от неподдержанной области (`internal/evidencetools/service.go:568-583`).

**Change:**

1. Удалить добавление `find_symbol` declaration site в `boundSites` (`internal/research/deterministic.go:421-424`).
2. Оставить `boundSites` только из `find_callers`, где site действительно является call site.
3. В `callSitesOf` принимать только записи с `Column > 0`; неполная позиция не должна передаваться в call-site-only tools.
4. В `callAt`/`scanCallAt` различать:
   - AST call site not found / supplied position not a call;
   - loader/backend failure.
5. В `CheckCallSiteGuard` не возвращать `gated=false, dead=false, nil` как успешный результат, если supplied position не является call site. Это устраняет vacuous `OK`; valid call без guard по-прежнему может законно вернуть `OK` с `gated=false`.
6. В `traceArgument`, `findValidations` и `checkCallSiteGuard` локально преобразовывать typed call-site scope error в `UNSUPPORTED` с limitation. Не менять глобальный `invoke` так, чтобы все errors стали unsupported.
7. Добавить regression fixture с реальным call site, включая `connection.go:48`, и fixture с declaration position.
8. Проверить, что отсутствие guard не становится доказательством отсутствия validation или безопасного пути; scope/limitations должны это явно говорить.

**Acceptance criteria:**

- `find_symbol` declaration site больше не вызывает dataflow tools.
- `find_callers` call site с корректной file/line/column вызывает `trace_argument` и `find_validations`.
- Известные 14 ошибок для 7 units × 2 tools исчезают после активного-path regression.
- Некорректный site даёт `UNSUPPORTED` + `UNKNOWN`/scoped limitation, не `ERROR` с `check not performed`.
- `check_call_site_guard` не выдаёт vacuous `OK` для declaration/non-call position.
- Реальный valid call site не превращается в unsupported только из-за отсутствия guard.
- Sandbox и tool permission semantics не меняются.

**Exact validation command:**

```bash
cd <VA_REPO>
go test ./internal/goanalysis ./internal/evidencetools ./internal/research
```

**Do-not:**

- не превращать отсутствие call site в `FALSE`, `REFUTED` или safe conclusion;
- не менять общий `errorObs` для подавления настоящих backend failures;
- не делать `Column == 0` доказательством того, что call site отсутствует, если отдельный scoped resolver может однозначно его установить;
- не расширять call-site search до нового общего анализатора;
- не считать пустой список validations доказательством отсутствия validation;
- не удалять dataflow operations из MCP catalog только для скрытия ошибки;
- не ослаблять sandbox или разрешать repository execution.

### Task 4: Автоматический retry transient live preflight

**Depends on:** None. Независим от Tasks 1–3.

**Scope:** повторять только transient E6 live preflight с `provider.status == "unreachable_infra"`; сам agent attempt запускать ровно один раз после успешного preflight.

**Files:**

- Modify: `internal/research/agent.go`, `RunAgent`, preflight stage.
- Test: `internal/research/agent_test.go`.

Не изменять `cmd/izyan/research.go`: CLI semantics и single-agent-turn orchestration остаются прежними (`cmd/izyan/research.go:135-170`).

**Interfaces:**

Сохранить:

```go
type HarnessRunner interface {
    Run(ctx context.Context, dir string, args ...string) (stdout, stderr []byte, err error)
}

func RunAgent(ctx context.Context, o AgentOptions) (*AgentTurn, error)
```

Добавить внутренний bounded preflight result, например:

```go
type preflightAttempt struct {
    Ordinal        int    `json:"ordinal"`
    Status         string `json:"status"`          // PASS|FAIL
    ProviderStatus string `json:"provider_status,omitempty"`
    ReportPath     string `json:"report_path,omitempty"`
    ReportSHA256   string `json:"report_sha256,omitempty"`
    Error          string `json:"error,omitempty"`
}
```

Добавить в `AgentManifest`:

```go
PreflightAttempts []preflightAttempt `json:"preflight_attempts,omitempty"`
```

Retry policy:

```text
max total preflight attempts: 3
retryable condition: report.provider.status == "unreachable_infra"
backoff: bounded 1s, then 2s
agent evaluate run: exactly once, only after PASS
```

`unreachable_infra` является отдельным provider/DNS/TLS precondition status и не является isolation violation (`eval/agent7/harness/e6-sandbox.patch:1581-1584,1967-1985`).

**Change:**

1. Вынести preflight invocation в helper, который:
   - запускает тот же `uv run vex-bench evaluate e6-preflight`;
   - читает `e6/security-boundary-check.json`;
   - извлекает `provider.status`;
   - сохраняет report path и SHA256.
2. Если command завершился failure и report содержит `provider.status=unreachable_infra`, выполнить bounded retry.
3. Перед повтором сохранить предыдущий report в отдельный immutable preflight-attempt artifact; не затирать диагностический результат.
4. При `PASS` продолжить существующую единственную команду `evaluate run`.
5. При исчерпании retry budget вернуть `AgentFailed` или `AgentTimeout` по существующей taxonomy; `evaluate run` не запускать.
6. При isolation failure, missing report, provider refusal или иной non-transient ошибке немедленно fail-closed без retry.
7. Сохранить в manifest все preflight attempts, а `PreflightReport`/`PreflightSHA256` направить на финальный успешно принятый report.
8. Тестами проверить, что argv sandbox не меняется: `--agent opencode-b1p`, `--parallel 1`, `--repeats 1`, те же harness/image/config paths.

**Acceptance criteria:**

- Sequence `unreachable_infra → PASS` вызывает два preflight и один `evaluate run`.
- Sequence `unreachable_infra → unreachable_infra → unreachable_infra` не вызывает `evaluate run`.
- Non-transient FAIL вызывает только один preflight.
- `AgentTurn` и attempt ledger остаются одной агентской попыткой; preflight retry не создаёт второй model attempt.
- Каждый preflight report сохранён и hash-pinned.
- Нет retry после начала `evaluate run`, даже если provider недоступен внутри agent attempt.
- Sandbox permissions, mounts, network policy, image и prompt pins не меняются.
- Existing `TestRunAgent_PreflightFailCloses` продолжает подтверждать fail-closed поведение.

**Exact validation command:**

```bash
cd <VA_REPO>
go test ./internal/research -run 'TestRunAgent_Preflight'
go test ./internal/research
```

**Do-not:**

- не ретраить `evaluate run`;
- не запускать второй model attempt;
- не менять prompt, model, provider или harness agent;
- не добавлять provider fallback;
- не разрешать сеть в sandbox;
- не принимать preflight без `status=PASS`;
- не классифицировать isolation violation как transient provider failure;
- не перезаписывать первичный preflight artifact.

### Task 5: Saved-case regression и короткий usability report

**Depends on:** Tasks 1, 2, 3 и 4. Требуется подготовленный writable GOVULNDB root и module cache из Task 2.

**Scope:** прогнать offline regression по богатому сохранённому набору `tmp/exploitable/runs/<UNIT>/agent`, не вызывая модель, и выпустить короткий отчёт о работоспособности полного цикла.

**Files:**

- Modify: `.superpowers/sdd/2026-10-10-02-agent-driven-evidence-assessment-plan-v2/agent7-regress.py`.
- Create: `docs/dev/reports/2026-10-13-shadow-usability-regression.md`.
- Generated, outside source tree: `<saved-case>-v2/report.json`, `<saved-case>-v2/report.md`, machine-readable regression summary.

Не изменять production report assembler в этой задаче: факты/гипотезы/unknowns уже формируются через `Assemble` и `render` (`internal/research/assemble.go:72-93`; `internal/research/render.go:234-239`).

**Interfaces:**

Расширить driver CLI:

```text
--cases private|public|saved|all
--govulndb PATH
--modcache PATH
--report PATH
--only LABEL,...
```

Добавить saved source:

```text
<VA_TMP>/exploitable/runs/<UNIT>/agent
```

Для каждого saved case:

1. прочитать `run-manifest.json`;
2. получить snapshot, advisory и external commit;
3. выполнить deterministic lane с `--govulndb`/`--modcache`;
4. выполнить `--replay-agent-turn <saved-agent-dir>`;
5. проверить `/2` invariants;
6. сохранить результат в sibling `-v2`, не перезаписывая source.

Это расширяет существующий `run_case`/`checks` flow (`agent7-regress.py:33-43,72-151`).

Итоговый report должен содержать:

```text
case count and labels
deterministic lane completion
run_govulncheck status counts
trace_argument/find_validations status counts
extractor recovery counts
agent status preservation
facts/assertions/unknowns presence
exploitation_established statuses
REVIEW_REQUIRED / auto_close values
failed cases and exact blockers
```

**Change:**

1. Добавить `saved` case discovery и assertion ожидаемого saved-case set: 31 case directories с `agent/run-manifest.json`.
2. Передавать в replay command:
   - `--govulndb`;
   - `--modcache`;
   - `--replay-agent-turn`;
   - без live harness/model flags.
3. Расширить checks:
   - contract extension остаётся `slice2-fidelity/2`;
   - agent status совпадает с source report;
   - agent-only conditions не становятся `SUPPORTED`/`REFUTED`;
   - `exploitation_established` не становится `ESTABLISHED` без dynamic proof;
   - `run_govulncheck` с подготовленной DB не остаётся `UNSUPPORTED` из-за пустого root;
   - известные declaration-site dataflow errors отсутствуют;
   - все basis refs и artifact refs разрешимы;
   - disposition остаётся `REVIEW_REQUIRED`, `auto_close=false`.
4. Вывести human-readable Markdown report с фактически наблюдёнными числами. Если какой-либо gate не удалось выполнить из-за окружения, записать `NOT_RUN` и blocker, не заменять его успешным значением.
5. В отчёте отдельно показать:
   - confirmed deterministic facts;
   - agent hypotheses;
   - remaining exploitation conditions;
   - operational unknowns;
   - provider/preflight failures;
   - limitations сравнения с V2.
6. Не добавлять новую model execution path: каждая команда обязана использовать replay.

**Acceptance criteria:**

- `saved` mode обнаруживает ровно 31 сохранённый agent case; несоответствие количества останавливает gate.
- Для каждого case создаются новый report и replay provenance; source artifacts не изменяются.
- Regression завершается без новых LLM/provider calls.
- При наличии подготовленного GOVULNDB результаты `run_govulncheck` отражают фактический local DB run.
- Declaration-site dataflow errors отсутствуют; legitimate scoped limitations не считаются tool success.
- `/2` invariants проходят для каждого отчёта.
- Итоговый report не утверждает superiority Shadow/V2 и не использует confidence score без methodology.
- Отчёт показывает facts, hypotheses и unknowns раздельно.
- Ни один отчёт не получает `AUTO_CLOSE`, `VERIFIED`, `FALSE` или `NO_EXPLOIT_PATH_FOUND` автоматически (`internal/research/validate.go:335-343`).

**Exact validation commands:**

Regression:

```bash
cd <VA_REPO>

python3 .superpowers/sdd/2026-10-10-02-agent-driven-evidence-assessment-plan-v2/agent7-regress.py \
  --cases saved \
  --govulndb "$GOVULNDB_ROOT" \
  --modcache "$MODCACHE_ROOT" \
  --report docs/dev/reports/2026-10-13-shadow-usability-regression.md
```

Final repository checks:

```bash
cd <VA_REPO>
test -z "$(gofmt -l .)"
go vet ./...
go test ./...
```

Expected result:

- regression exit code `0`;
- 31 saved cases, `failed=0`;
- `gofmt` prints no files;
- `go vet ./...` and `go test ./...` exit successfully.

**Do-not:**

- не запускать модель;
- не выполнять live agent turn;
- не менять saved source artifacts;
- не копировать V2 resolver/classifier;
- не ослаблять `/2` invariants;
- не превращать `UNKNOWN` или scoped limitation в negative conclusion;
- не считать отсутствие dynamic proof доказательством отсутствия exploit path;
- не скрывать failed cases из summary;
- не подменять фактически не выполненную проверку словом `PASS`.

## Dependency / Execution Order

```text
Task 1  ─┐
Task 2  ─┼─> Task 5
Task 3  ─┤
Task 4  ─┘
```

Tasks 1–4 независимы по файлам и могут выполняться отдельными implementation sessions. Task 5 выполняется только после их принятия и после подготовки writable local GOVULNDB root и module cache.

# Agent-7 (A-series) — E2E slice 1: `izyan research` implementation record

- **Status:** implemented, accepted as the slice-1 record.
- **Date:** 2026-10-12.
- **Design of record:** `.superpowers/sdd/2026-10-10-02-agent-driven-evidence-assessment-plan-v2/e2e-slice1-design.md` (sha256 `cf43431d…82c`).
- **Scope:** additive experimental lane only. `izyan analyze`/`scan`/`eval`/etc. are untouched except a single dispatch + usage entry in `cmd/izyan/main.go` (`izyan analyze --help` byte-identical).

## 1. What exists now

| File | Role |
|---|---|
| `internal/research/types.go` | `research-report/1` contract structs (closed top-level member set) |
| `internal/research/deterministic.go` | §5.1 deterministic lane: preflight → snapshot → frozen advisory → strict `evidencetools` session → `affected.GoResolver` → bounded source/exposure facts → govulncheck → persistence (`observations.jsonl`, `artifacts/obs-NNNN.json`, `deterministic-facts.json`) |
| `internal/research/agent.go` | One-case E6 harness adapter over the FIXED interface (`uv run vex-bench evaluate e6-preflight` then `evaluate run --agent opencode-b1p`); fail-closed status mapping |
| `internal/research/assemble.go` | §7 merge authority: advisory entries → `affected_implementations`; `AffectedResult` → `product_applicability`; agent claims never promoted; binding/conflict rules; fixed `REVIEW_REQUIRED` disposition |
| `internal/research/render.go` | Pure JSON→Markdown renderer, byte-stable; visibly separates facts/assertions/unknowns/disposition. Does not reuse `internal/report` |
| `internal/research/validate.go` | Fail-closed validator: closed schema, fact invariants, ref resolution, non-bare UNKNOWN, disposition, one-to-one question ids, artifact sha verification |
| `cmd/izyan/research.go` | Flag surface of design §3 and orchestration |
| `internal/research/*_test.go` | Schema/validator, merge/binding, deterministic-only, renderer byte-stability, fake-harness adapter, real fixture lane tests |

## 2. Input pins and conventions

- **Harness dir:** resolved from `VEXBENCH_HARNESS_DIR`, else `${VEXBENCH_DURABLE_DIR}/agent-ctl` (the manifest path-resolution convention in `internal/eval/agent7/manifest.go`); no new flag — the design's flag list is closed.
- **Prompt:** `--agent-prompt-file` wins; default `eval/agent7/prompts/r0-v1.txt` when present else `r0.txt`. The controller renders the four identity placeholders and appends the normalized frozen advisory as a `<FROZEN_ADVISORY>` block (design §6 hand-off: rendered input, not a mount); the rendered file is passed via the harness `--prompt-file`. `r0-v1.txt` sha256 `55b01e9a…a0ae` is recorded in `run-manifest.json` (the freeze `manifest.json` is pin-validated and not modified; the pin lands in the per-run manifest).
- **Harness patch:** recorded as `run.harness.patch_sha256` = sha256 of the harness working-tree `git diff HEAD` (the sibling's `eval/agent7/harness/e2e-single-case.patch` is the same diff in patch form).
- **Model/provider:** default `qwen3.6-35b`/`custom-openai`; a non-`custom-openai` provider is rejected at flag time (the pinned E6 adapter supports `custom-openai` only — `MODEL2NAME` + `synthesize_e6_config` provider block).
- **Exit semantics:** deterministic-lane preparation failures exit non-zero without a report; agent-side failures never fail the run — they set `agent_output.status` and keep the report review-required with unknowns.

## 3. Deterministic-lane call order as implemented (§5.1)

1. `filepath.Abs`+`EvalSymlinks`, `repository.VerifyContained`, `repository.CheckPathReplacements`, `repository.ContentHash` (failure = hard stop, recorded `repository-preflight` observation).
2. `toolchain.Resolve` + `repository.Service{}.Snapshot` (`ExternalCommitSHA` supplied ⇒ no git probe; `repository-snapshot` observation).
3. Frozen advisory: `--advisory-file` direct bytes, or `vexbench.PrepareFrozenAdvisory` into `<out>/advisory/` for `--advisory-dir`; `vulnerability.FileSource{NoAliasEnrichment:true}.Get`; raw + `vexbench.CanonicalSHA256` digests (`advisory-load` observation).
4. Every OSV `affected[]` entry normalized into `affected_implementations` (non-Go → `binding=non-go`, no Go range → `incomplete`).
5. `evidencetools.NewSession` with `Strict`, confinement, frozen advisory root, `AllowNet=false`, `AllowExec=false`, `AllowToolchain=true` (module-graph/govulncheck exec under strict per §3), `ToolTimeout=--deterministic-timeout`, optional `ModCacheRoot`/`GovulnDBRoot`, `VulnSource=FileSource(frozen)`. Session tools invoked over in-memory MCP (`mcp.NewInMemoryTransports` — same path as `mcp_test.go`).
6. `affected.GoResolver.Resolve` under `affected.ExecGoTool{Bin:sess.ToolBin, Env:sess.ToolEnv}` (`affected-resolve` observation; `product_applicability` built only from it).
7. Per Go advisory entry: `module_usage`, `module_internal_reach`, `IngressInventory` (direct `Index` call, minted observation); per advisory symbol (budget 16): `find_symbol`, `find_callers`, `find_may_callers`, `find_dep_callers`, `scan_dynamic`, `interface_dispatch_sites`, `gated_refs`, `dep_invocation_state`. Product exposure: `find_entrypoints`, `ListenSites`, `InboundAuthFacts`, `DialSites` (lane-minted observations). Bounded provenance: `trace_argument`/`find_validations`/`check_call_site_guard` on ≤8 concrete call sites. `check_missing_call` never runs (no explicit check/pipeline pair exists; recorded limitation).
8. `run_govulncheck` invoked unconditionally → `UNSUPPORTED` observation when `--govulndb` is unset (honest unknown, never silence).
9. Persist `observations.jsonl` (audit records in call order), `artifacts/<obsid>.json` (canonical observation bytes), `deterministic-facts.json`; `verified_facts` = status=OK observations only.

## 4. Report contract notes

- `claim` objects: `{id, statement, subject, scope, state, evidence_refs, limitations, origin}`; `origin=deterministic` claims reference an existing `verified_facts` id (enforced by the validator).
- `verified_facts[].artifact.sha256` is the sha256 of the artifact file's bytes exactly as written (payload + trailing LF) — the artifact is third-party verifiable; `data_digest` remains the canonical observation-payload sha256 (payload without the trailing LF). `evidence_quality.references[].sha256` is omitted for `agent-source` refs (agent citations carry no digest); deterministic refs carry the artifact/advisory sha.
- Agent-cited sources (`agent-src:` refs) never appear in `evidence_refs` — those carry only contract-resolvable ids (the paired agent_assertion id). Every distinct agent-src ref instead lands in the agent-source index: `evidence_quality.references` rows with `kind=agent-source` pinned to the retained raw answer (`agent/answer.txt` path+sha256). The final-answer text is retained under `agent/answer.txt` for OK and INVALID_FORMAT alike, and `agent_output.raw_artifact` points at it.
- The agent answer extraction is robust: fence-tolerant, scans every `{` position for the first complete JSON object carrying `category` (top level or under `assessment`); only absence of such an object is INVALID_FORMAT.
- OBS ids are minted lane-side unconditionally — the MCP session also mints `OBS-NNNN` ids, so session observations are renumbered into the lane's sequence and their captured audit records rewritten to match.
- `open_questions`/`residual_questions` share one-to-one ids (validator-enforced).
- IDs: `OBS-NNNN`, `fact-obs-NNNN`, `U-NNNN`, `Q-NNNN`, `A-NNNN`, `EC-NNNN`, `R-NNNN`, `adv-NN`, `dc-<sec>-NN`, `ac-<sec>-NN`; ref space `obs:`, `fact-*`, `adv:`, `agent-src:`.

## 5. Deviations recorded

1. **Advisory block delivery:** per the design's own hand-off clause, the normalized advisory is rendered into the prompt as `<FROZEN_ADVISORY>` controller input — no repository/benchmark/label mounts.
2. **`run-manifest.json` lives under `--output-dir`** (the only writable location), not a repository path.
3. **`evidence_quality.references[].sha256` optional** for `agent-source` kind (see §4).
4. **Partial frozen advisories (`AdvisoryPartial`) are accepted** with a recorded limitation — the slice's unknowns model carries the degraded entry instead of aborting the run.
5. **`check_missing_call` is never invoked** (§5.1 allows it only for an explicit check/pipeline pair; none is derivable from a frozen advisory alone).
6. **Harness error taxonomy:** `TIMEOUT`/`PROVIDER_REFUSED` are classified from container `error.txt`/stderr patterns plus the controller-side deadline; `INVALID_FORMAT` covers missing/empty/unparseable answers and any result without a valid `category`+`reasoning`.

## 6. Observed limitations (watch-list, from §10)

- k8s-class advisories carry 20+ affected entries across ecosystems; all are preserved, but Go applicability is only ever evaluated for `ecosystem=Go` entries — non-Go entries can never become product facts (verified by tests).
- The `--deterministic-timeout` bound applies per tool; a large snapshot (kubernetes) can push individual index loads to the bound — non-OK outputs stay `TIMEOUT`/`ERROR` observations → unknowns, never absence.
- Without `--modcache`, dependency-internal reads under strict mode degrade to `UNSUPPORTED`/partial scope as designed.
- `git rev-parse HEAD` runs only when `--external-commit-sha` is absent (local-repo convention).

## 7. E2E acceptance results (functional scenarios)

Команда: `izyan research --snapshot <harness repos>/<owner>/<repo>/<sha> --cve <CVE> --advisory-file eval/agent7/advisories/<case>.json --external-commit-sha <sha> --output-dir eval/agent7/results/research/<case>` (плюс `--deterministic-only` для базовой линии). Окружение: E6-образ `sha256:c85bc1df…9ba1`, `VEXBENCH_DURABLE_DIR`, preflight запускается самой командой (fail-closed), провайдер `custom-openai` через host-forwarder. Приёмочный чекер `e2e-accept.py` (10 проверок дизайна §9): **PASS 10/10 на всех шести выходах**.

| Кейс | режим | agent | category (агент, не promoted) | sections | facts | conditions | unknowns | disposition |
|---|---|---|---|---|---|---|---|---|
| k8s-44487 | agent | OK | `code_not_present` | mechanism/root/attack/exposure/alt = PARTIAL, evidence SUPPORTED | 13 | 6 | 3 | REVIEW_REQUIRED |
| trivy-32473 | agent | OK | `code_not_reachable` | все PARTIAL, evidence SUPPORTED | 8 | 6 | 7 | REVIEW_REQUIRED |
| rancher-47914 | agent | OK | `vulnerable` | все PARTIAL, evidence SUPPORTED | 8 | 6 | 31 | REVIEW_REQUIRED |
| k8s-44487 | det | NOT_REQUESTED | — | mechanism PARTIAL, остальное UNKNOWN | 7 | 5 | 8 | REVIEW_REQUIRED |
| trivy-32473 | det | NOT_REQUESTED | — | mechanism PARTIAL, остальное UNKNOWN | 8 | 5 | 7 | REVIEW_REQUIRED |
| rancher-47914 | det | NOT_REQUESTED | — | mechanism PARTIAL, остальное UNKNOWN | 8 | 5 | 31 | REVIEW_REQUIRED |

Ключевое для приёмки: `k8s-44487` — известная ловушка (адвизори называет только `golang.org/x/net` на фиксированной версии). Отчёт сохраняет категорию агента как assertion, applicability остаётся детерминированным, а не связанные с адвизори компоненты (`go.etcd.io/etcd`, `k8s.io/apiserver/pkg`), названные агентом, попадают в `unknowns` с follow-up и в limitations секций mechanism/root_cause. Ни один отчёт не содержит `VERIFIED`/`FALSE`/`AUTO_CLOSE`, `auto_close=false` во всех шести.

## 8. Архитектурные ограничения, обнаруженные на этом срезе

1. **Конфликт ID-пространств.** MCP-сессия и детерминированная полоса независимо выпускали `OBS-NNNN`; наблюдения перезаписывали артефакты и дублировали fact-ids. Исправлено перенумерацией session-наблюдений; общий вывод — один генератор id на прогон.
2. **Семантика digest артефакта.** `artifact.sha256` совпадал с `data_digest` (канонический payload), из-за чего файл нельзя было проверить третьей стороной. Теперь artifact = sha256 записанных байт, `data_digest` остаётся каноническим.
3. **`exploitation_conditions` пуст без агента.** Детерминированный режим обязан сам выводить условия применимости из advisory/applicability (SUPPORTED/UNKNOWN с follow-up), иначе отчёт неполон.
4. **Извлечение ответа агента.** Модель отдаёт ответ в фенсах/несколькими блоками; нужен балансный сканер объектов с `category` (top-level или под `assessment`) и сохранение сырого ответа в обоих случаях (OK и INVALID_FORMAT).
5. **Agent-source ссылки — отдельный класс.** `agent-src:` цитаты не должны попадать в `evidence_refs` и не должны «не резолвиться»; они живут в индексе `evidence_quality.references[kind=agent-source]`, привязанном к sha256 сырого ответа.
6. **Advisory-scope gap надо фиксировать явно.** Наивная проверка «модуль вне advisory» реализована токен-сканом модульных путей в ответе агента; чисто прозаические упоминания компонента (без module path) она не поймает — это признанное ограничение эвристики.
7. **Харнесс перезапускает невалидные результаты in place** (отклонение A2 D1) — в slice 1 используется одна попытка на вызов, но само поведение run-стадии остаётся и должно быть исправлено (новый attempt key вместо перезаписи).
8. **Стоимость детерминированной полосы.** Индексация kubernetes ≈160 s, trivy ≈84 s, rancher ≈110 s; при per-tool лимите 60 s на крупных снапшотах часть проверок честно деградирует в TIMEOUT/ERROR → десятки unknowns (rancher: 31). Это шум для аналитика, а не ошибка безопасности.
9. **Провайдер зависит от DNS/VPN.** Forwarder резолвит `<corporate-provider-host>` на старте; при недоступном DNS гейт падает fail-closed (ENV_FAIL). Для приёмочных прогонов использовался документированный IP-пин; в проде это операционное требование, а не архитектурный дефект.
10. **Source-tree-scoped.** Нет binary inventory/build attestation → ни один отчёт не может закрыть release-finding; это by design.
11. **Non-Go entries не становятся product-фактами** (22 из 23 записей k8s-44487) — структурное ограничение для CVE с неполным Go-маппингом.
12. **Категория агента не promoted** — ценность отчёта для триажа в структурированных mechanism/unknowns/evidence, а не в вердикте.

## 9. Предложение следующего этапа

Этап 2 — **contract hardening + targeted facts** (не A3, не proof engine):

1. Исправить семантику run-стадии харнесса (пункт 8.7): невалидный результат фиксируется как `INVALID_FORMAT` под своим attempt key, повтор — только явным флагом.
2. Сделать advisory-scope gap семантическим: сопоставлять названные агентом компоненты с модульным графом снапшота (а не только токен-сканом) и требовать явного `UNKNOWN`, когда компонент механизма отсутствует в advisory.
3. Оффлайн-валидатор как регрессия: те же 6 выходов slice 1 + четыре открытых контроля A2 (`k8s-44487`, `k8s-3121`, `rancher-47914`, `testify-28948`).
4. Только если регрессия покажет конкретный недостающий детерминированный факт — отдельно запиненный R1 с ≤5 существующими инструментами через уже имеющийся MCP-путь (список и промпт пинятся заранее); новый runtime/broker не проектируется.
5. A3/Event Store, proof engine, certificates, auto-close не строить: решение пересматривается только после нового feasibility-preflight с ненулевым инкрементом (D1).

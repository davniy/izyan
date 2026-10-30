# Портовый review: целостность архитектуры и полнота переноса V2

**Назначение:** independent implementer verification of target architecture §1–13 and V2→Shadow port completeness.
**Источник:** delegated `implementer` artifact `agent://PortIntegrityReview` (2026-10-20), сохранён дословно; файлы не изменялись.
**Вердикт:** `ARCHITECTURE NEEDS REVISION`; `V2 PORT INCOMPLETE` (under-specified, not wrongly specified).
**Revision status:** addressed in target §14: `PORT BACKLOG REVISED / STILL INCOMPLETE`; findings remain the evidence base.
**Смежные документы:** [`../roadmaps/2026-10-20-target-architecture-and-roadmap.md`](../roadmaps/2026-10-20-target-architecture-and-roadmap.md), [`2026-10-20-04-cross-solution-decision.md`](2026-10-20-04-cross-solution-decision.md), [`2026-10-20-05-independent-verification.md`](2026-10-20-05-independent-verification.md), [`2026-10-20-06-approach-decision.md`](2026-10-20-06-approach-decision.md).

---

# Port Integrity Review — Verification Report

**Scope:** integrity of `docs/dev/roadmaps/2026-10-20-target-architecture-and-roadmap.md` (§1–13) and correctness/completeness of the V2→Shadow port list/spec backlog S-01…S-15.
**Method:** every claim checked against source (file:line), tests, or saved artifacts. Statuses: PROVEN / CLAIMED / MISSING / INCORRECT / UNPROVEN.
**Refs:** Shadow `118e10c` (`<VA_REPO>`), V2 `6bcce89` (`<VA_REPO_V2>`). Both repos share module path `github.com/davniy/izyan`.

---

## A. V2 feature inventory

| Feature | V2 source path(s) | Target status | Target section/spec | Required dependency | Gap/issue | Severity |
|---|---|---|---|---|---|---|
| `ImportClosure` type | `internal/goanalysis/toolscope.go:253` | PORT (P0) | §2.3, G-01, Phase 2, S-03 | — | None. Type exists; `BindDynamicRelevance` :319 | — |
| `EnumerateImportClosure` | `toolscope.go:336` (Index method) | PORT (P0) | G-01, Phase 2, S-03 | Shadow `goanalysis.Index` must expose identical method | Shadow `toolscope.go` is 194 lines vs V2 864; no `ImportClosure` in Shadow at all. PROVEN absent | — |
| Importer-closure diagnostics | `toolscope.go` (EdgeMarker :237, DiscardedUnreachable :302, skippedImporterPaths :849) | PORT | S-03 | — | OK | — |
| `verify_code_absence` tool | `internal/evidencetools/verify_code_absence.go` (+test) | **MISSING from port list** | G-01/Phase 2/S-03 reference it as if Shadow-owned ("Shadow `evidencetools/verify_code_absence.go`") — **INCORRECT attribution**; S-03 says "if ported" | `EnumerateImportClosure` (called at :142), `ImportClosureReport` struct :29 embeds closure hash/members/exceptions | **Not assigned to any spec.** Phase 2 gate requires it to "compile against Shadow" but no spec ports it. Independent-verification report item 17 already flagged this dependency; target did not close it | **P0** |
| Shipping-scope roots (main/import/init/build) | `unreachability_scope.go` (1391 lines, LIVE/DEAD/UNKNOWN states :47-51) | PORT | G-02, Phase 2, S-04 | G-01 | File absent in Shadow (Shadow `unreachability.go` 706 lines; no `unreachability_scope.go`/`unreachability_dynamic.go`) | — |
| DEAD-only pruning | `unreachability_scope.go` — only DEAD evidence discardable; `toolscope.go:141` returns `blocked`,`discarded` lists | PORT | S-04 | — | OK, audit sets persisted (`DiscardedUnreachable`) | — |
| Subject-aware dynamic markers | `unreachability_dynamic.go` (`DynamicCoverage` :29, `ScanRelevantDynamic` :113); `BindDynamicRelevance` | PORT | §2.3 "Shipping-scope dynamic relevance", S-04 | Shipping scope | OK | — |
| Discarded-site audit | `toolscope.go:141,302,414-528` | PORT | Phase 2 deliverable 7, S-04 | — | OK | — |
| Function-value/interface dispatch | `funcvalues.go`, `dispatch.go` (+tests); V2 scope treats unresolved dispatch as UNKNOWN/open | PORT | S-04 | — | Shadow has own `funcvalues.go`/`dispatch.go` — merge semantics needed; port is not pure copy | medium |
| `symbol-unreachability` observation payload | `evidencetools/unreachability.go` (V2 md5 ≠ Shadow md5) | ADAPT (implicit) | Needed by falsifier `locus_function_unreached` (`unreachability_proof.go:107` requires `evidencetools.SymbolUnreachabilityTool` payload shape) | Scope kernel | **No spec assigns the payload-parity check between V2 tool and Shadow tool.** If Shadow payload differs, `unreachability_proof.go` mints nothing | P1 |
| `agenttriage` package | `internal/agenttriage/` (103 files) | PORT via adapter | §2.3, Phase 3, S-06/S-08 | Shadow `internal/domain` type equivalence | Imports V2 `internal/domain` (20 sites), `internal/affected` (3), `internal/vulnerability`, `internal/repository`, `internal/toolchain`, `internal/exposure`, `internal/llm`, `internal/risk`, `internal/tracker`. Target forbids porting V2 domain/affected → every import site must be rewired to Shadow equivalents; adaptation cost unspecified | P0 |
| `finding.v1` / `assessment.v1` | `types.go:14,17` | PORT | S-06 | — | PROVEN: schemas exist, strict decode | — |
| Proposal-only falsifier ingress | `types.go:188-268` (`UnmarshalJSON` rejects `status`,`verified`,`mandatory`,`coverage`,`negative_verification`,`recommendation`,`verdict` at :233) | PORT | §13.3.3, S-06 | — | PROVEN: forbidden fields rejected at decode | — |
| FactGate + `det:`/`obs:` locators | `factgate.go` (:52,:258,:451,:479-481 pseudo-locator rejection, :800 canonical spellings) | PORT/ADAPT | §13.3.4, S-07 | Canonical EvidenceGraph + **observation archive + `det:` producer = `verify_code_absence` et al.** | Locators bind to V2 persisted observation ids; resolving them against Shadow evidence needs the adapter S-07 covers — but the *producing* tools are not all ported (see verify_code_absence) | P1 |
| C14 (falsifier proof integrity) | `checks.go:52` (`CheckIDFalsifierProof="C14"`), impl :773+ | PORT | §4.4, S-06/S-07 | Persisted FalsifierReport + observation archive | PROVEN in V2; spec coverage implicit | — |
| `DecisionPackage` + policy | `decision_types.go:194` (`decision-package.v2`), `policy.go` (FailOn :18-69), `composer.go` | PORT/ADAPT | §2.4.9/§13.3.5, S-08 | — | **Field drift**: target §2.4.9 sketch (`finding_identity`,`baseline_comparison`,`policy_outcome`) vs §13.3.5 (`run_id`,`baseline`,`technical_assessment`,`conditional_profiles`) vs actual V2 type (has `execution_mode`,`falsifier_proofs`,`audit`; `human_decision` hardcoded "NOT_APPLICABLE (ci mode)"; policy outcome lives in separate `rec`/`AutomationStatus`, not in package). S-08 must fix canonical field list | medium |
| Stability (no best-of, demote) | `stability.go` (`CheckStability` :144 compares input/snapshot/advisory/config/ruleset/prompt/toolchain/ref/commit + recommendation); composer `unstable_demoted` :473 | PORT | §13.3.7, S-09 | — | PROVEN | — |
| Triage replay | `agenttriage/replay.go`, `--replay-run` (triage.go:1424) | PORT/ADAPT | S-09 | Unified replay manifest vs Shadow `internal/research/replay.go` (different artifact) | OK | — |
| Triage metrics | `metrics.go` (`triage-metrics.v2` :16) | Required by §3.6 observability | **No spec names it** (S-08 scope lacks metrics) | — | Spec gap | P2 |
| Baseline + `--fail-on` | `metrics.go:70` (`triage-baselines.v1`), `triage.go:156` (`--baseline`), `policy.go` FailOn | PORT | §3.4, S-08 | — | PROVEN | — |
| VEX denial / projection | `vex_projection.go` (`triage-vex-projection.v1`, `ErrVEXProjectionDenied`, `ProjectVEX` :198 — only DISMISSED+decisive basis; `triage_only` enforced), CLI `--vex-projection` default false (triage.go:157), denial audited (`RecordVEXProjectionDenial` triage.go:995) | PORT (default-off) | §2.4.9, §13.3.5-6, S-08 | — | PROVEN boundary in V2; admission wiring is flag-only (any operator can pass flag — that's per-design "non-authoritative") | — |
| Observation archive | `observation_archive.go` (`observation-archive.v1` :17) | Required by FactGate/C14/replay | **Not in Phase 0 contract registry list (§6 Phase 0 deliverable 1), not named in any S-spec** | — | Spec gap: `obs:<id>` locators resolve against it; without it FactGate cannot run | P1 |
| `verify_package_absence` | Referenced in `falsifier.go:966` repair text | — | — | — | **Does not exist in V2 either** (no such tool file). Repair text references a nonexistent tool — minor V2 defect surfaced by port | P2 |
| `claimshape` | `internal/claimshape/` (capabilities, extract, locator, report, signals, types) | PORT offline | §2.3, Phase 4, S-10 | `agenttriage` types (import dep) | OK | — |
| `verification` (universal verifier) | `internal/verification/` (graph, evaluate, interpret, certificates, challenge, replay, stability) | PORT offline/admission | S-10 | `agenttriage`, `claimshape`, `evidencetools` | PROVEN code; behavior measured only on all-NE corpus (6/85, fs=0) — recall UNPROVEN | — |
| `heldoutgate` + `cmd/heldout-gate` | `internal/heldoutgate/` (gate, metrics, probe, replay, stability), `cmd/heldout-gate/main.go` | PORT | Phase 4/5, S-11 | `agenttriage`,`claimshape`,`verification` | `CrossRunAdmissions` :314 exists; mutation tested in `gate_test.go`; positive-corpus still missing by design (G-08 open) | — |
| Mutation/cross-run harness | `heldoutgate` + `agenttriage/stability_test.go` + `verification/challenge*` | PORT | Phase 4 d5, S-11 | — | PROVEN | — |
| `refindex` | `internal/refindex/` (advisory, canonical, decl, fixdiff, gomod, symbols, usage) | PORT research lane | S-12 | `internal/domain`, `internal/fix`, `internal/goanalysis`, `internal/repository`, `internal/vulnerability` | Import rewire needed (V2 domain again) | medium |
| `reportcheck` | `internal/reportcheck/` | PORT research lane | S-12 | `internal/domain` | OK | — |
| Research lane | `internal/research/` (research.go, agentrun, advisory, prompt use-based `prompt.go:36,73`, replay `izyan-research/2`, grounding, answer, consistency) + `cmd/izyan/research.go` | PORT as separate product | Phase 4, S-12 | — | **PACKAGE PATH COLLISION**: Shadow `internal/research` already exists and is Product A core (deterministic.go, replay.go, validate.go, sidecars, ABNotInImportClosure machinery). Same module path + same package path + different contents = direct merge conflict. Target never names this; S-12 "port as separate lane" needs explicit package rename/relocate decision | **P0** |
| Use-based verdict lane | `internal/research/prompt.go` (`use-based-verdict` rule block :73) | PORT (in research lane) | S-12 | research lane | OK (part of research port) | — |
| VEX-Bench eval tooling | `internal/eval/vexbench` (in Shadow too), `cmd/izyan/vexbench.go` | Both repos have it; V2 `eval/agent7` diverged (agentinput/prompt/validate vs Shadow feasibility) | Not in spec backlog | — | Divergent `eval/agent7` unaddressed; low risk | P2 |
| `evidence-index.v1` | None — design only (V2 `docs/dev/reports/2026-10-20-03-architecture-decisions.md:686`) | DEFER explicitly allowed | G-22, S-07 DoD "either implemented or explicitly deferred" | — | Correctly handled | — |
| Frozen prompts/replay | `research/prompt.go`, `agenttriage/prompt.go`, replay files | PORT | Phase 4 d8, S-12 | — | OK | — |
| `toolscope` other types | `MayCallSite` :29, `SkippedPackage` :98, `LoadBudgetExhausted` :189, `ProductPackagePaths` :200 | PORT (partially — Shadow has own versions) | S-03 | — | Shadow already has `MayCallSites`/`SkippedPackages`/`ProductPackagePaths`; port must reconcile, not duplicate (two "skipped packages" semantics risk) | medium |
| Deterministic-tools broker | `agenttriage/detools.go` (allowlist :43-47 incl. `verify_code_absence`, `symbol-unreachability`; per-call timeout, (name,args) cache) | Required by agent loop | **No spec** (runner/tools not in S-06..S-08 scope text) | `internal/evidencetools` catalog — V2 catalog diverged (has `catalog.go`, `verify_code_absence.go`; Shadow has `buildcache`, `usage_scope`, `check_specs`…) | Spec gap: detools + evidencetools catalog parity unassigned | P1 |
| Triage intake/stage0/catalog/ref/snapshot/site-config | `input.go`, `stage0.go`, `catalog.go`, `ref.go` (`ref-selection.v1`), `snapshot.go`, `siteconfig.go` (`DeploymentConfig` :112), `intake_llm.go` (`intake-proposal.v1`) | §13.5 row "Triage intake **P0 adapter**" → mapped to S-06, but S-06 scope text covers only falsifier ingress | S-06 (implicit) | — | **Spec-text gap**: §13.5 assigns intake to S-06; S-06 §7 scope names only `types.go/falsifier.go/prompt.go/runner.go`. `stage0.go`,`catalog.go`,`ref.go`,`snapshot.go`,`siteconfig.go`,`input.go` not named anywhere | P1 |
| Deployment context (Product B) | `agenttriage/siteconfig.go:112` DeploymentConfig paths | ADAPT | S-13 covers deployment adapter but V2-side fields unlisted | — | minor | P3 |
| V2 `internal/domain` | V2 `internal/domain/` | **DO NOT PORT** (correct) | §1.3 out-of-scope 10; §13.5 "Deprecate" | — | Correctly excluded — BUT imported by agenttriage/refindex/reportcheck/research (see above); "don't port" ≠ "port targets compile". No spec states the type-mapping strategy (alias? rewrite? subset vendoring?) | P0 |
| V2 `internal/affected` | V2 `internal/affected` | DO NOT PORT (correct) | §1.3 oos 10 | — | Same issue: `affected.DecodeModules`, `affected.Module`, `PackageImportPaths`, `ParseVendorModules` used by agenttriage — needs Shadow-equivalent adapter | P0 |
| V2 `internal/evaluator` | V2 `internal/evaluator/verdict.go` etc. | DO NOT PORT (correct) | §1.3 oos 10, G-05 | — | PROVEN clean: no ported package (agenttriage/claimshape/verification/heldoutgate/refindex/reportcheck/research/evidencetools) imports `internal/evaluator`. Only states/workflow/cmd reference it | — |
| Auto-dismissal | V2: dismissal capability exists but default-off; `human_decision` fixed NOT_APPLICABLE | DO NOT enable | §3.2 default-off, G-07, Phase 5 | — | PROVEN excluded from admission until gates | — |
| LLM authority | — | DO NOT PORT | I-8, §13.4.3 | — | PROVEN: V2 falsifier rejects authority fields; composer can't emit verdict vocabulary | — |
| `cmd/agent7-snapshot-audit`, `internal/eval/agent7` (agentinput) | V2-only | Unclassified | Phase 0 exit requires every V2 component classified `to port/offline/research-only/deferred` | — | Missing classification (also `internal/cveanalysis` divergence, `internal/fix`, `internal/persistence`, `internal/states`, `internal/workflow`, `internal/tracker`, `internal/risk` V2 copies) | P2 |

---

## B. Architecture integrity findings

| # | Finding | Type | Evidence | Impact | Correction |
|---|---|---|---|---|---|
| B-1 | **`verify_code_absence` unattributed & unported.** Target says "Shadow `evidencetools/verify_code_absence.go`" (G-01) but file exists only in V2; Phase 2 gate demands it compile; no S-spec ports it | missing contract / factual error | Target G-01, Phase 2 acceptance 1, S-03 "if ported"; file absent in Shadow tree; V2 `evidencetools/verify_code_absence.go:142` calls `s.Source.EnumerateImportClosure` | Without it, `FalsifierCodeAbsent`/`locus_package_absent` never admit → Product B triage kernel silently non-functional; Phase 2 gate cannot pass as written | New spec (or extend S-03/S-04): port `verify_code_absence` + `ImportClosureReport` + `det:` producer wiring to Shadow `evidencetools`; fix G-01 attribution; make Phase 2 gate name the actual port spec |
| B-2 | **`internal/research` package-path collision.** Same module path `github.com/davniy/izyan`, same package path `internal/research`, entirely different contents (Shadow = Product A persistence/replay/NV core; V2 = LLM research lane) | ambiguous ownership / duplication | `ls` both trees; both have `research.go`,`replay.go`,`prompt.go`-level files with different semantics | S-12 "port as separate lane" will either overwrite Product A core or fail to merge; risk of accidentially grafting LLM lane into authority path | S-12 must mandate rename (e.g. `internal/researchlane`/`internal/productb/research`) and forbid merging into Shadow `internal/research` |
| B-3 | **V2 `internal/domain`/`internal/affected` are transitively required by every port target** while "do not port" is a headline rule | unsafe boundary (latent) | `grep -rh "internal/[a-z]*"`: agenttriage→domain(20 sites),affected,vulnerability,repository,toolchain,exposure,llm,risk,tracker; refindex→domain,fix,goanalysis,repository,vulnerability | Adapter authors will either vendor V2 domain types (second Claim/ExploitModel/Condition semantics — prohibited by §13.4.3) or rewrite each site (unestimated cost). `domain.Condition`/`ExploitModel`/`SymbolRef`/`Perimeter*`/`GoVersionSource*` all used | Add to Phase 0 exit: explicit type-mapping table V2-domain-type → Shadow type (or "drop feature"); S-06/S-08/S-12 must list it as dependency |
| B-4 | **Triage intake/tooling surface has no owning spec.** stage0, catalog, ref-selection (`ref-selection.v1`), snapshot manifest, siteconfig, `intake-proposal.v1`, detools broker, tool_audit, metrics (`triage-metrics.v2`), observation-archive (`observation-archive.v1`) — none named in S-06/S-07/S-08 scope or Phase 0 contract registry | missing contract | §13.5 maps "Triage intake P0 adapter"→S-06, but S-06 scope = falsifier ingress only; Phase 0 deliverable-1 registry omits fact-gate.v1, observation-archive.v1, triage-metrics.v2, ref-selection.v1, intake-proposal.v1, decision-package.v2, falsifier-verification.v1, triage-error.v1, triage-vex-projection.v1 | Product B cannot run end-to-end from spec backlog alone; schemas unowned → drift | Extend Phase 0 registry to all `*-v1`/`v2` schemas in `agenttriage/artifacts.go`,types.go,intake_*.go,metrics.go,ref.go,observation_archive.go,vex_projection.go,falsifier.go; assign intake+detools+metrics to S-06/S-08 scope explicitly |
| B-5 | **Phase 2 acceptance references Phase 3 artifact.** Gate "triage falsifier adapter compile against Shadow" — the adapter is Phase 3 scope | contradiction/ordering | §6 Phase 2 acceptance 1 vs Phase 3 deliverables 3-6 | Gate unverifiable at Phase 2 or forces premature adapter code | Reword: "V2 falsifier package compiles against Shadow `internal/goanalysis` in a scratch harness" or move gate to Phase 3 |
| B-6 | **`DecisionPackage` field drift across §2.4.9 vs §13.3.5 vs V2 actual** | contradiction (contained) | §2.4.9: `finding_identity`,`baseline_comparison`,`policy_outcome`; §13.3.5: `run_id`,`baseline`,`technical_assessment`,`conditional_profiles`; V2 `decision-package.v2`: `execution_mode`,`falsifier_proofs`,`audit`,`human_decision`="NOT_APPLICABLE (ci mode)", no `policy_outcome` inside package (policy is separate `AutomationStatus`/rec) | Adapter authors can't tell whether policy_outcome belongs inside package; V2 name `decision-package.v2` vs target examples diverge | Phase 0 registry must pin canonical field set + schema_version; §13 authoritative per §2.4 note — acceptable but must be closed in S-08 DoD |
| B-7 | **Product B falsifier kinds depend on tool contracts not in port list.** `code_absent`→`verify_code_absence`; `locus_function_unreached`→`symbol-unreachability` payload via `unreachability_proof.go` (requires `evidencetools.SymbolUnreachabilityTool` + specific payload); `verify_package_absence` referenced in repair text but nonexistent | missing contract | `falsifier.go:458-682,813-820,966`; `unreachability_proof.go:107,140` | If ported tools emit different payloads, proofs never mint → silent capability loss (fails safe, but silently) | S-07/S-10 DoD: contract test pinning `symbol-unreachability` payload schema parity V2↔Shadow; fix V2 repair text |
| B-8 | **Mandatory-condition source for Product B unspecified.** §13.3.3: condition must come from "canonical Product A exploit model / versioned capability registry / approved checker contract". No spec defines the A→B wire for exploit-model conditions | missing contract | §13.3.3, §13.4.1 lists A→B data but no condition contract; S-06 DoD mentions "advisory subject binding" only | Falsifier proposals have no canonical `condition_id` universe → either V2-side condition vocabulary persists (second exploit model — prohibited) or triage admits nothing | S-06 or new spec: `condition_catalog` export from Product A exploit model to Product B |
| B-9 | **B→A proposal consumer not specified.** §13.4.1 says Product B may submit proposals to Product A; no spec defines Product A's proposal ingest path (bounded LLM proposal mode listed in §3.2 but no owner) | missing contract | §3.2 "bounded optional LLM proposal mode"; no S-spec owns it | Either never implemented (B→A arrow dead) or implemented ad-hoc | Assign to S-01/S-02 era spec or explicit deferral row in §13.5 |
| B-10 | **Second verdict/evidence engine: absent — PROVEN.** No V2 evaluator import in ported packages; V2 `agenttriage` has no NOT_AFFECTED producer; VEX projection emits only triage-scoped `not_affected` with `triage_only=true` | — (verified) | import grep; `vex_projection.go:198`; `types.go` fields | — | — |
| B-11 | **Failure semantics: consistent.** Identity refusal→exit2/not NOT_AFFECTED (§13.2.1 gate table, §3.4); technical error→exit2 not UNCHANGED (§13.2.5, composer.go:173 "technical error channel, never an UNCHANGED"); sidecar tamper→fail closed (§4.5, deterministic.go:2368-2387); unstable→UNCHANGED demote (stability/composer :473) | — (verified consistent) | cross-checked V2 code matches target tables | — | — |
| B-12 | **D11/D17 consistent.** D11 scoped to Product A; D17 adds dual-product boundary — §13.6.3 explicit | — (verified) | §13.6.3 rows D11/D17 | — | Phase 0 must actually write D17 ADR |
| B-13 | **Evidence fields missing vs canonical contract.** Shadow `Evidence` struct lacks `case_identity_ref`,`subject`,`digest`,`scope`,`completeness` (has `artifact_hash`,`limitations`); Shadow `NegativeVerification` is 4 fields vs canonical 13 (no `falsifier_kind`,`scope_basis`,`complete`,`covered_subjects`,`dynamic_checks`,`identity_ref`,`sidecar_ref`); NV is embedded pointer in `Claim` not separate `NegativeVerifications[]` | duplication risk / contract gap | `internal/domain/domain.go:757-773,605-610,635-660` vs §2.4.2/13.2.4 | S-02 "map Shadow evidence to canonical contract" is a real schema migration, larger than "existing; canonical" component-map status suggests; old persisted cases lack fields → migration/refusal rules (U-01) critical | S-02 DoD should add explicit field-presence contract tests on AnalysisCase |
| B-14 | **Artifact layout is PLANNED but gate-light.** §3.3 admits unified layout unimplemented; no spec owns run-directory layout (S-01 covers case bundle; layout file list unowned) | ambiguous ownership | §3.3 "must be закреплён отдельной implementation-spec" — but no S-xx named for it | Adapter/replay specs may assume different layouts | Assign layout to S-01 or S-09 explicitly |
| B-15 | **Corpus identity ambiguity for "38/38" gate.** `eval/corpus-real.json`=38 cases, `eval/corpus.json`=18, `eval/live-corpus.json`=11; gates say "38/38" without naming the corpus file | missing contract (minor) | file counts; §6 Phase 1 gate | Baseline manifest must pin corpus file hash (S-05 covers "baseline command manifest" — closeable there) | S-05 DoD: name corpus file + hash |
| B-16 | **No circular dependency found** in spec DAG (S-01→S-02→{S-03,S-06,S-07,S-10,S-13}→S-08→S-09→S-11; S-12 ∥). Phases 0→1→2→3→4→5 consistent EXCEPT B-5 | — (verified) | §7 Depends-on fields | — | — |

---

## C. Port completeness verdict

**`V2 PORT INCOMPLETE` (under-specified, not wrongly specified).**

Missing/under-specified, without which Product B or the scope kernel cannot work:

1. `verify_code_absence` + `ImportClosureReport` + `det:` observation production — **no owning spec** (P0).
2. Triage intake surface: `input.go`, `stage0.go`, `catalog.go`, `ref.go`, `snapshot.go`, `siteconfig.go`, `intake_llm.go`, detools broker, `tool_audit.go`, `metrics.go`, `observation_archive.go` — §13.5 implies S-06 but S-06 scope omits them (P1).
3. V2 `internal/domain`/`internal/affected` type-mapping strategy for agenttriage/refindex/reportcheck/research imports (P0).
4. `internal/research` package-path collision resolution (P0).
5. `symbol-unreachability` payload parity contract between V2 tool and Shadow tool (P1).
6. Mandatory-condition catalog A→B for falsifier `condition_id` binding (P1).
7. Product B artifact schemas absent from Phase 0 registry (P1).
8. B→A proposal ingest path unowned (P2).
9. `internal/eval/agent7` divergence and V2-only cmds unclassified (P2).

**Correctly excluded — confirmed not smuggled:**
- V2 `internal/domain`, `internal/affected`, `internal/evaluator`: not in port list; §1.3 oos-10; §13.5 "Deprecate". Verified: no ported package imports V2 `internal/evaluator` (PROVEN).
- Auto-dismissal: default-off everywhere (§3.2, G-07, Phase 5); V2 code has `human_decision="NOT_APPLICABLE (ci mode)"` hard requirement.
- LLM authority: I-8 + §13.4.3 prohibitions + V2 decode-time rejection of authority fields (PROVEN in code).
- V2 `NOT_EXPLOITABLE` agent vocabulary explicitly ≠ `NO_EXPLOIT_PATH_FOUND` (§2.1).

---

## D. Architecture integrity verdict

**`NEEDS REVISION`** — the dual-product architecture is internally coherent (authority model, failure tables, verdict precedence, A/B/C levels are consistent and non-contradictory), but the port inventory has one false attribution (B-1), one unaddressed collision (B-2), and a domain-dependency iceberg (B-3) that makes the spec backlog insufficient to produce a compiling Product B.

### Top corrections (priority order)

| # | Target section | Change | Affected spec/phase |
|---|---|---|---|
| 1 | §5 G-01 + Phase 2 + S-03 | Fix "Shadow `evidencetools/verify_code_absence.go`" → V2 file; add explicit PORT decision for `verify_code_absence`, `ImportClosureReport`, det-tool catalog entries | S-03 or new S-03b; Phase 2 |
| 2 | §2.3 component map + §7 | Add Product B runtime components: observation-archive, detools broker, stage0/catalog/ref/snapshot/siteconfig/intake, metrics, tool_audit — each with owner + spec | S-06/S-08; Phase 0 registry |
| 3 | §13.5 delta matrix + S-12 | Name the `internal/research` collision; mandate package relocation for V2 research lane | S-12; Phase 4 |
| 4 | §1.3/§13.5 + Phase 0 | Add normative rule: port targets' imports of V2 `internal/domain`/`internal/affected` must be enumerated with a mapping table to Shadow types before port starts; "do not port" ≠ "compile" | Phase 0 exit gate; S-06/S-08/S-12 |
| 5 | §6 Phase 2 acceptance | Remove/move "triage falsifier adapter compile" (Phase 3 artifact); replace with "V2 falsifier compiles against Shadow goanalysis in isolation harness" | Phase 2/3 |
| 6 | §2.4.9 + S-08 | Reconcile `DecisionPackage` field list vs §13.3.5 vs V2 `decision-package.v2`; pin schema_version and whether `policy_outcome` is a package field | S-08 DoD |
| 7 | §2.4.2/13.2.4 + S-02 | Acknowledge Shadow `Evidence`/`NegativeVerification`/`Claim` field gaps vs canonical contract; add field-presence contract tests + old-case migration/refusal rules | S-02 DoD; U-01 |
| 8 | §13.3.3 + S-06 | Define mandatory-condition source contract (A→B condition catalog or approved registry) that falsifier `condition_id` binds to | S-06 scope |
| 9 | §6 Phase 0 deliverable 1 | Extend contract registry to all Product B schemas (fact-gate.v1, observation-archive.v1, decision-package.v2, falsifier-verification.v1, triage-metrics.v2, ref-selection.v1, intake-proposal.v1, triage-vex-projection.v1, triage-error.v1, raw-agent.v1) | Phase 0; S-06..S-09 |
| 10 | §13.5 + spec backlog | Classify remaining V2 deltas: `eval/agent7` (agentinput/prompt/validate), `cmd/agent7-snapshot-audit`, `vulnerability/composite.go`, `llm/translator.go`, divergent `evidencetools` catalog members — mark each port/defer/drop | Phase 0 exit "every V2 component classified" |

---

## E. Evidence status of claimed guarantees

| Guarantee | Status | Evidence / what's missing |
|---|---|---|
| `false-safe=0` (Shadow corpus 38/38) | **PROVEN** for saved external artifact | `<VA_TMP>/corpus-final2.txt:79` (`cases=38 … false-safe=0 inconclusive=3`); corpus = `eval/corpus-real.json` (38 cases verified). Caveat: artifact lives outside repo (G-25 open); eval harness exits 1 on false-safe (`cmd/izyan/eval.go:291`) |
| Census 7/1/10 | **CLAIMED** (not independently re-verified here; report says guard-contract not blind labels — correctly disclosed) | `2026-10-20-04` §line 50 caveat |
| Single verdict evaluator | **PROVEN** (architecture level): `internal/evaluator/verdict.go` pure function; verdict emitters confined to evaluator+research-render path; no V2 verdict import in ported pkgs | `verdict.go:12-20`; grep |
| Identity binding | **PROVEN as design**; per-field enforcement UNPROVEN (Evidence lacks `case_identity_ref` field — B-13) | `domain.go:757` |
| Negative verification independent | **PROVEN structurally** (NV produced in goanalysis/negative.go, persisted in research/types.go:1186, required `VERIFIED` for FALSE in validate.go:2744) | — |
| Replay without LLM | **PROVEN** both sides: Shadow `internal/research/replay.go` + `validate.go` (81 tests); V2 `agenttriage/replay.go` + `heldoutgate/replay.go` | — |
| Sidecar fail-closed | **PROVEN**: `deterministic.go:2368-2387` (missing/digest/path-mismatch → error); selector pinned :2262 | — |
| Default-off admission | **PROVEN**: `--vex-projection` default false; dismissal requires admitted deterministic proof (composer `empty ruleset → UNCHANGED` :782); `human_decision` locked | — |
| A↔B boundary contracts | **CLAIMED/PLANNED** — target defines them; no code yet (adapter is "To design") | — |
| V2 `6/85 fs=0` universal verifier | **PROVEN as offline measurement** (`task-5-report.md:40` false_safe_count 0); positive recall **UNPROVEN** (all-NE corpus — disclosed in G-08) | — |
| Scope kernel semantics | **PROVEN in V2 source+tests** (41 kernel tests); **UNPROVEN in Shadow** (files absent — port pending); semantic-parity test V2-vs-port not in any gate | — |

### Unproven items + minimal closing experiment

| Item | Status | Minimal experiment |
|---|---|---|
| Ported kernel parity | UNPROVEN (nothing ported yet) | Same fixture set through V2 kernel and Shadow-ported kernel; diff LIVE/DEAD/UNKNOWN + discarded lists; add to Phase 2 gate |
| `verify_code_absence` admission path | UNPROVEN post-port | Fixture: package-absent case → proposal → det-tool → C14 → DISMISSED-eligible; assert `ImportClosure.Complete=true, OpenExceptions=∅` |
| det:/obs: locator resolution on Shadow evidence | UNPROVEN | S-07 fixture: obs id from archived observation resolves; foreign-run obs id rejected |
| False-safe=0 of *integrated* Shadow+V2-kernel | UNPROVEN | Re-run corpus-real.json + corporate census post-port; compare verdict distribution |
| Positive recall | UNPROVEN | Positive-labeled corpus (Phase 5) — correctly gated |
| Census false-safe guarantee | CLAIMED | Needs independent labels on census, not just guard contract |

### Acceptance-gate adequacy

- **Adequate:** Phase 1 baseline pins; Phase 3 negative tests (verified-field rejection, foreign snapshot, cross-run, unstable demotion, VEX denial); Phase 5 admission/non-admission dual outcome; S-08 exit-2/1 separation.
- **Inadequate as written:**
  1. Phase 2 gate item 1: "compile against Shadow" — compiles ≠ semantics preserved; **add kernel-parity test** (V2 kernel vs ported kernel on shared fixtures, diff classification sets).
  2. Phase 2 gate item 2 lists LIVE/UNKNOWN/PARTIAL/skipped/open-dispatch — good — but no gate pins **falsifier admission e2e** (code_absent proposal → closure-backed observation → admitted fact → C14 pass). Without it, the whole chain silently never admits.
  3. Phase 3 gate: e2e fixture covers happy path; **add negative test**: `symbol-unreachability` observation emitted by *Shadow* tool must mint `unreachability_proof` identically to V2 (payload parity), else `locus_function_unreached` is dead code.
  4. S-03 DoD lacks behavioral equivalence vs V2 `EnumerateImportClosure` (edges/importers/skipped/broken sets identical on a shared module fixture).
  5. S-09 replay DoD: add cross-boundary replay negative tests (Product B package referencing foreign Product A sidecar → fail closed) — listed in §13.4.4 but not in S-09 DoD.
  6. No gate checks **schema registry completeness** (every Product B `*-v1` schema has owner/version) — Phase 0 exit should test it mechanically.
  7. `observation-archive` persistence/digest checks have no gate (S-07/S-09 don't name it).

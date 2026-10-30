# Task 5 implementation plan — prompt vs evidence tools vs verification gate

## 0. Goal, sources and design gate

**Design gate: CONDITIONAL.** Implement the prompt/tools experiment first. Implement Gate only if Checkpoint B justifies a concrete independently checkable rule; never pre-create `internal/verificationgate` or change production behavior.

Authoritative source: `docs/dev/specs/2026-10-09-task5-prompt-tools-gate-comparison-v2.md`, committed as `42caadb`. The requested v1 `docs/dev/specs/task5-verification-gate-spec.md` is unavailable. Do not invent its contents: start conditional Gate design from v2 §6.2 and its candidate rules.

**Spec-path decision:** preserve the dated v2 file as the frozen source. During implementation create `docs/dev/specs/task5-prompt-tools-gate-spec.md` with exactly the same normative content, satisfying §11; hash both and require byte equality. Never independently edit the duplicate during this experiment.

**Goal:** decide whether Izyan MCP adds value over a tuned plain coding agent, and whether an independent Gate adds value beyond either ungated arm. Task 5 delivers evidence and `decision.md`, not a production safe-closure capability.

**Non-goals:** production workflow changes; retrospective baseline correction; new tools; toolset ablation; case-specific prompts; LLM voting as proof; outcome-driven retries; best-of selection; claiming the known VEX-Bench cases are unseen.

| Observation after matched tests and holdout | Architecture decision |
|---|---|
| P1 improves P0, T1 adds no value, P1 meets risk/cost needs | Develop prompt-only Agent; MCP is not mandatory. |
| T1 consistently improves P1 without increased False-Safe | Use MCP capabilities where demonstrated useful, not automatically all 31 tools. |
| P1/T1 retain dangerous safe conclusions and Gate blocks them with acceptable overblocking | Retain the smallest justified Gate; agent-visible MCP is not automatically necessary. |
| Gate blocks all safe conclusions | Product experiment fails: zero False-Safe bought with zero automation. |
| No variant preserves adequate safety and usefulness | Research/triage assistant with human review; no automatic safe closure. |

## 1. Current architecture and exact reuse boundary

Reuse `eval/c1/{protocol.py,assessment.py,status.py,collect.py,runner.py,parser_audit.py,report.py,synthetic.py,manifest.py}` and `eval/vexbench_c1.py`; do not create another agent loop or duplicate official scoring semantics.

`/tmp/vexbench-agent-ctl/src/evaluate/agents/opencode_c1.py` already provides the required split: `OpenCodeB1PrimeAgent` and `OpenCodeC1Agent` share `_run_attempt` and `_synthesize_config`; `_extend_config` adds only `mcp.izyan` for C1. Native coding tools remain unrestricted. Provider/model synthesis is shared.

P1 uses `vex-bench-go-opencode-gw`; T1 uses its existing additive `vex-bench-go-opencode-c1` derivative. Audit base-image identity, CLI/toolchain versions and binary-only treatment delta; pin image IDs before running.

Reuse `internal/evidencetools/Observation`, `ScopeDetails`, `BuildContext`, and `AuditRecord` as artifact contracts. Existing MCP audit lives in `artifacts/izyan-audit/tool_calls.jsonl`; `eval/c1/runner.py` can materialize `observations.jsonl`, terminal text and usage.

Use the timeout-watchdog patch described in `eval/c1/harness/README.md`; do not revert to `subprocess.run(timeout=)` behavior. `evaluate.result_parser`, `evaluate.parse._parse_run`, and `evaluate.metrics` remain unchanged.

## 2. Arm/cohort matrix and attempt policy

| Arm | Prompt | Agent | MCP | Post-check | Attempts |
|---|---|---|---|---|---|
| P0 | Historical official `vuln` | Historical `opencode` | None | None | Preserve historical n=1 |
| P1 | `vuln_safety_v1` | `opencode-b1p` | None | None | 30 × 3 |
| T1 | Exact P1 base plus short API block | `opencode-c1` | Existing 31 tools | None | 30 × 3 |
| G-P1 | Same stored P1 answers | No new agent run | Not supplied to agent | Conditional Gate | Same P1 attempt keys |
| G-T1 | Same stored T1 answers | No new agent run | Supplied during T1 | Same conditional Gate | Same T1 attempt keys |

**First cohort: Qwen3.6-35B-A3B**, harness key `qwen3.6-35b`, provider `custom-openai`. Task 4 reported plain FS=1/7, recall=6/7 versus tools FS=3/7, recall=4/7, leaving measurable prompt headroom and the reproduced tool failure mode. Those headline counts are audit-projection evidence, not a replacement for official-strict scores. Qwen3.8's plain 0/7 was caveated parser-audit evidence with risky repeats; run it only as a separate second cohort, never pool models.

Freeze `timeout=900`, `parallel=1`, `repeats=3`, `retries=0`, and no cache admission for the new matched pair. This is a new protocol, not the historical Qwen 1800-second policy; P0↔P1 is explicitly historical, not causal. If a causal prompt-effect claim is needed, run a fresh matched P0 under the same new protocol.

Pin endpoint, provider config, revision if exposed, model settings, output limits, task order, snapshot hashes, native permissions and outbound research policy. Unexposed revision/temperature/effort is `null` with a limitation, never fabricated.

Every attempt has an immutable key `(experiment_id, arm, model, task_id, run_NNN)`. Preserve failed attempts and partial bytes. No overwrite of `run_001`, selective cache, outcome-driven retry or best-of. Technical diagnostics belong to separate experiment IDs.

## 3. Minimal implementation files and interfaces

Create `eval/task5/{__init__.py,protocol.py,manifest.py,collect.py,report.py}` and `eval/vexbench_task5.py` as thin experiment glue around existing C1 functions. Add targeted tests beside those modules; do not modify frozen Task 4 prompts or manifests.

`protocol.py` generates the two prompt files and exact diff/hashes; `manifest.py` freezes identities and audit evidence; `collect.py` finalizes harness attempts using adapter-aware C1 extraction; `report.py` joins existing scorer outputs into the required matrix/report. Preserve all C1 execution/parse/schema/audit dimensions.

Persist `eval/task5/harness/vexbench-agent-ctl-task5.patch` as an additive patch **against the Task-4-patched harness**. Required harness delta:
- `src/evaluate/prompts.py`: register `vuln_safety_v1` and `vuln_safety_v1_tools` through existing `_load_prompt_file`.
- `src/evaluate/prompts_data/vuln_safety_v1.txt`.
- `src/evaluate/prompts_data/vuln_safety_v1_tools.txt`.

No new agent registration, `opencode_c1.py` redesign, Docker permission change or scorer change is required. Audit that the inherited base config contains no MCP in P1; refuse admission otherwise.

## 4. Exact prompt construction

Use the frozen official template from `eval/vexbench-prompts/official-vuln-c0a5c8458b77.txt` as an unchanged prefix. Generate P1 by appending the following literal block; preserve `{cve_id}` and the official twelve categories/output contract:

```text
<SAFETY_RULES>
1. Separate local observations from your final conclusion. "no matches",
   "not imported", "fix found", "default=false", or "OK/COMPLETE" from one
   query does not prove that the CVE is not exploitable.
2. Check alternative manifestations of the defect. Advisory packages,
   fix diffs and affected symbols may not exhaust runtime manifestations.
   Check relevant versions, transitive implementations, generated runtime
   code and dependency-internal calls.
3. A negative conclusion requires a countercheck. Before a safe answer,
   state the necessary exploitation condition, scope, alternatives checked,
   supporting facts and remaining limitations. If a material alternative
   remains unchecked, choose "uncertain".
4. Do not turn failures into absence. A tool error, timeout, PARTIAL result,
   failed build, missing toolchain or unverified deployment fact leaves the
   relevant condition open.
5. Exploitability is not one reachability fact. Absence of a direct
   first-party import does not exclude a transitive path; a single
   reachability observation is not a global exploitability conclusion.
6. Return the single structured benchmark JSON with its official category
   and concrete reasoning, including scope and limitations. Do not invent
   evidence IDs. "uncertain" is an abstention, not a safe conclusion.
</SAFETY_RULES>
```

T1 is **exact P1 bytes** plus two LF bytes and this literal API block:
```text
<EVIDENCE_TOOLS>
The connected izyan MCP server exposes the existing 31 snapshot evidence
tools: advisory/fix, dependency/module, source/symbol/caller, dataflow/
validation, dynamic-dispatch and optional build/test observations.
Results contain fact, scope, completeness, tool_status, evidence_refs,
limitations, scope_details and data. OK concerns this call only; COMPLETE
concerns only its named scope. Apply the shared safety rules to all results.
Use normal coding-agent tools as well: MCP tools are additive.
</EVIDENCE_TOOLS>
```

P1/T1 share exactly the official `category`/`reasoning` JSON contract. No MCP IDs are required from P1. Do not add a structured proof export only to T1. If Gate later needs a changed export, run new matched P1'/T1' ungated controls before replay.

Publish full SHA-256, harness short hash, exact bytes and unified P1/T1 diff. Assert prefix equality and config equality after removing **only** top-level `mcp`. Scan prompts for prohibited case/product/fix identifiers. T1 initialization/server instructions and catalog hashes are part of the treatment provenance.

## 5. Deliverables and manifest

```text
eval/task5/
  prompts/{vuln_safety_v1.txt,vuln_safety_v1_tools.txt,hashes.json,p1-t1.diff}
  experiment-manifest.json
  freeze/{task4-reference.json,task4-artifact-sha256.txt,access-audit.md}
  harness/{README.md,vexbench-agent-ctl-task5.patch}
  results/{p0,p1,t1}/
  scoring/{p0,p1,t1}/
  scoring/{matrix.json,disagreements.jsonl,safety-report.md,tool-failures.jsonl}
  decision.md
```

Create `results/{gp1,gt1}` and Gate input/receipt artifacts **only if phase 5.3 executes**. Smoke lives outside scored roots, under `results/smoke/{p1,t1}`.

Manifest fields: schema/experiment/environment IDs; spec and historical-reference hashes; Izyan/harness commits and approved diffs; both patch hashes; prompt full/short hashes and exact diff; effective config/native permissions; images/architecture/toolchain/binary/catalog/schema hashes; model/provider/revision/settings; dataset pin/tasks SHA/task IDs/repo URLs/full commits/snapshot hashes/acquisition digest; deadlines/budgets/parallelism/repeats/retry/cache policy; parser/scorer/controller hashes; smoke/exposure records; raw/derived output roots and telemetry limitations. Keep GT controller-only; Gate/agent receive allowlisted projections.

## 6. Phase 5.0 — historical freeze and boundary audit

Inventory A's original deterministic baseline from `eval/baselines/vexbench/external-baseline-1.md`, B/plain references and C/tool references; retain original names, raw records, reports and checksums. Store new indexes under `eval/task5/freeze`, never write into historical roots.

Historical Qwen roots: `/tmp/vexbench-qwen-iso/{q36,q38}` and `results/task4-c1/qwen-tools-full/{q36,q38}`. Discover model-level run directories by actual paths; record missing attempts, cached-smoke exposure and n=1 limits. Preserve strict/audit projections separately.

Freeze `eval/baselines/vexbench/{task4-qwen-plain-vs-tools.md,task4-codex-partial-state.md}`, C1 assets and `eval/c1/freeze/manifest.json`. Record harness `c71f512a3304d1a0d0d9f5e19e8dbc06e9f1dc93`, patch SHA `7c47f5c39b94b862cfc576f32540400a3001b64740d81667ba5dbc84c05b0840`, Izyan `0a9b404ab8d69d1bf9200e0f94f71627a2b656c4`; the manifest's dirty state and Codex-specific settings are not Qwen provenance.

Preserve all MCP errors: reported 513 calls, 100 ERROR, 2 UNSUPPORTED, including 65 canceled, 8 missing govulncheck and 5 dirty go.mod. Record raw records and unclassified residuals, not just these summary buckets. Codex 8/90 and 6/90 remain PARTIAL; contaminated/capacity/timeout-bug runs are excluded from matched evidence.

Audit mounts/image/config/prompt and source-copy boundaries: only the current snapshot/CVE, no `.git`, GT/task JSONL, reference PR, host results, neighbor snapshots or foreign sessions. Test native filesystem isolation and MCP traversal separately. Record identical build/runtime/advisory policy and per-call subject/scope/status/completeness/limitations/version/hash/latency; missing fields remain unavailable.

## 7. Phase 5.1 — P1 and Checkpoint A

Implement prompt generation and artifact collection, then targeted unit/synthetic checks. Use three fixed smoke IDs selected before answers are examined; smoke is technical evidence only. Existing C1 controller can select one vulnerable, non-reachable and configuration case host-side; never render their labels.

Freeze prompt/settings before scored P1. Run all 30 tasks × 3, retain outputs/failures, collect artifacts without new LLM calls, and score strict/audit separately. Category-only output makes C1 assessment schema absent: this is artifact availability, not a reason to erase an accepted safe answer.

**Checkpoint A:** publish per-case historical P0↔P1 changes, FS/SCR/recall/failures/cost and three-attempt stability. State that historical P0 has n=1 and runtime/budget differences. Do not declare durable improvement from one repeat or 0/7 FS; require matched P0 before a causal prompt-effect claim.

## 8. Phase 5.2 — T1 and Checkpoint B

Run unchanged frozen P1 base plus API block on the same model/task/budget/environment with existing 31 MCP tools and untouched native tools. Pair every `(task_id, run_NNN)`, including failures; no answer-based pairing.

Record call-level audit, environment failures, latency/budget consumption, repeated calls and decisive-observation use. Manually classify cited local facts generalized globally, partial/error-as-absence and missed alternatives, with raw artifact references; citation alone does not establish causality.

**Checkpoint B:** decide whether MCP adds useful/safe decisions beyond P1 at acceptable cost. If T1 regresses, distinguish environment/configuration failures before invoking Gate. A fix after admission creates a new environment revision and matched experiment; never repair only later T1 cases.

## 9. Phase 5.3 — conditional minimal offline Gate

Admission requires a remaining concrete unsafe-safe class, independently checkable negative rule and no sufficiently reliable simpler solution. Otherwise document Gate as deferred; no Gate modules/receipts are created.

Conditional files: `eval/task5/{gate_models.py,gate_replay.py,gate_rules.py,score_gate.py}` and targeted tests. No production integration. Same implementation/rules/version process immutable P1 and T1 answers; no agent retry, second LLM or GT access.

Start from v2 fields: `GateInput{Snapshot,Vulnerability,Candidate,Scope,Proofs,Observations}` and `GateResult{Status,EffectiveEstimate,Reasons,ApprovedProofs,NeededChecks,InputHash,GateVersion}`. References carry artifact path/digest, subject/build scope and provenance; proposals are untrusted. `BLOCKED→INCONCLUSIVE`; execution ERROR remains an operational failure. Positive/uncertain candidates are NOT_APPLICABLE and retain their ungated outcome.

Adapter reads `agent_assessment.json` only if actually present, stored `observations.jsonl` or `artifacts/izyan-audit/tool_calls.jsonl`, pinned snapshot identity and public advisory identity. Resolve citations independently. A file/line, `ev:`/`sha256:`, model rationale or `scope_closed=true` is not proof.

Historical Task 4 replay without complete structured proof inputs yields only `BLOCKED` with `INSUFFICIENT_INPUT`; never reconstruct from GT or free reasoning. The minimal P1/T1 contract may likewise be insufficient. If so, document feasibility failure or run new matched P1'/T1' with identical structured claims/proof-proposal export before Gate; never silently retrofit old outputs.

Candidate rules: **AFFECTED_VERSION_EXCLUDED** (effective version/replace/vendor/release facts and affected ranges independently checked) and **PACKAGE_ABSENT_IN_BUILD** (complete transitive build closure, exact subject, no errors/skips). Both require independently established CVE manifestation coverage and necessity for every relevant variant; a complete local advisory/query is not global closure. Missing capability or scope leaves BLOCKED.

Reuse existing deterministic affected/module/package routines through a confined benchmark adapter; independently generated observations go in Gate-owned `gate_observations.jsonl`. Cache checks only by complete snapshot/advisory/build/rule/input identity, identically for both arms; record cost and hits. Never use production precomputed verdicts.

For each supported rule require a real accepted safe fixture and adversarial blocked unsafe fixture, plus error/partial/unknown, forged ref, changed snapshot and two-manifestations-one-unknown controls. Emit hashed receipt for each accepted safe; report blocked FS, retained safe, correct-safe overblocking and added checks/cost. Blocking FS is not a recall TP.

## 10. Phase 5.4 — holdout and decision

Known VEX-Bench cases are development/regression evidence. Freeze unseen new projects/CVEs and generic adversarial cases before applying unchanged prompts/rules; labels remain scorer-only. If holdout is unavailable, `decision.md` is explicitly preliminary and cannot claim proven safety.

`decision.md` records Checkpoints A/B/C, chosen §10 decision-table row, per-repeat counts/denominators, cost/usefulness trade-offs, MCP/Gate necessity, holdout status and unproven guarantees. Production automatic closure is a separate risk decision.

## 11. Metrics and scoring artifacts

| Metric | Required accounting |
|---|---|
| FS | GT exploitable and safe; 7/repeat, 21 pooled; abstain/FAILED separate. |
| SCR / recall | Correct safe/23; positive exploitable/7; Gate-blocked safe never TP. |
| Abstain / failures | Content uncertain/30; timeout/refusal/transport/parse_fail/no output individually visible. |
| Stability | Three-attempt category/outcome vectors, wrong-safe frequency, 3/3·2/3·1/3 consistency; no best-of. |
| Official / audit | Separate metrics/rows; full-JSON repair only; no truncated/prose/label-only evidence recovery. |
| Reasoning quality | Overconfidence, missed alternatives, scope quality, supported/unsupported claims with review references. |
| MCP | Status × completeness, subject/scope, failures, latency, decisive use and unnecessary calls. |
| Gate | FS blocked, safe retained/overblocked, invalid/insufficient proof, receipts and independent-check cost. |
| Resources | Wall boundary identical; tokens/steps/cost and limit hits; unavailable telemetry null, not zero. |

Reuse `eval.c1.report.run_report` and its official scorer/parser-audit outputs. `matrix.json` joins all attempt rows with separate strict/audit outcomes, official binary mapping, failure classes and artifact hashes; `disagreements.jsonl` includes P0↔P1 and P1↔T1 transitions/reason classes. Historical P0 pairs only comparable observed attempts; missing repeats are not invented.

## 12. Exact commands and implementation contracts

`eval/vexbench_task5.py` below is a **new interface to implement**, not an existing command. `freeze-history`, `smoke`, `manifest`, `collect`, `score`, `gate-replay`, and `score-gate` implement the boundaries above using C1/harness functions. Resolve model-level roots from frozen hashes; reject existing attempt admission. Preserve frozen manifest bytes and put actual-run telemetry in separate records.

```bash
export WORKTREE=<VA_REPO> HARNESS=/tmp/vexbench-agent-ctl
export PY="$HARNESS/.venv/bin/python" TASKS="$HARNESS/benchmark/tasks/vex_bench.jsonl"
export REPOS=/tmp/vexbench-baseline/repos ACQ=/tmp/vexbench-baseline/acquisition.json
cd "$WORKTREE"
"$PY" eval/vexbench_task5.py freeze-history --harness-dir "$HARNESS" --out eval/task5/freeze
"$PY" -m eval.task5.protocol --out eval/task5/prompts --harness-dir "$HARNESS"
# Generate/save the additive patch; manifest accepts exactly its approved diff.
# Rebuild only before smoke if the existing pinned image is unavailable:
(cd "$HARNESS" && docker/build-c1.sh "$WORKTREE")
"$PY" -m unittest eval.task5.protocol_test eval.task5.manifest_test eval.task5.collect_test eval.task5.report_test
"$PY" eval/vexbench_task5.py smoke --harness-dir "$HARNESS" --tasks "$TASKS" --repos-dir "$REPOS" --acquisition "$ACQ" --model qwen3.6-35b --timeout 900 --arms p1,t1 --out eval/task5/results/smoke
"$PY" eval/vexbench_task5.py manifest --harness-dir "$HARNESS" --tasks "$TASKS" --repos-dir "$REPOS" --acquisition "$ACQ" --model qwen3.6-35b --timeout 900 --repeats 3 --parallel 1 --out eval/task5/experiment-manifest.json
cd "$HARNESS"
uv run --locked --no-sync vex-bench evaluate run --agent opencode-b1p --prompt vuln_safety_v1 --model qwen3.6-35b --benchmark vex_bench --repeats 3 --timeout 900 --parallel 1 --repos-dir "$REPOS" --output-dir "$WORKTREE/eval/task5/results/p1"
cd "$WORKTREE"
"$PY" eval/vexbench_task5.py collect --manifest eval/task5/experiment-manifest.json --arm p1
"$PY" eval/vexbench_task5.py score --manifest eval/task5/experiment-manifest.json --arms p0,p1 --out eval/task5/scoring
# Write Checkpoint A before T1; verify unchanged manifest/environment.
cd "$HARNESS"
uv run --locked --no-sync vex-bench evaluate run --agent opencode-c1 --prompt vuln_safety_v1_tools --model qwen3.6-35b --benchmark vex_bench --repeats 3 --timeout 900 --parallel 1 --repos-dir "$REPOS" --output-dir "$WORKTREE/eval/task5/results/t1"
cd "$WORKTREE"
"$PY" eval/vexbench_task5.py collect --manifest eval/task5/experiment-manifest.json --arm t1
"$PY" eval/vexbench_task5.py score --manifest eval/task5/experiment-manifest.json --arms p0,p1,t1 --out eval/task5/scoring
# Conditional only, after written Checkpoint B:
"$PY" eval/vexbench_task5.py gate-replay --manifest eval/task5/experiment-manifest.json --arms p1,t1 --rules affected_version_excluded,package_absent_in_build --out eval/task5/results
"$PY" eval/vexbench_task5.py score-gate --manifest eval/task5/experiment-manifest.json --out eval/task5/scoring
```

## 13. Every §12 acceptance criterion → evidence

| Criterion | Artifact/command |
|---|---|
| A/B/C and Task 4 preserved | `freeze-history`; original-root hashes and `task4-reference.json`. |
| New frozen no-MCP P1 | Prompt/hash/manifest, P1 run and 90 attempt records; no-MCP config audit. |
| Matched T1, exact diff/hashes | P1/T1 prompt diff, projected config equality, T1 run/catalog audit. |
| Isolation, one manifest/policy | `access-audit.md`, native/MCP negative tests, frozen manifest. |
| Three attempts and visible failures | `collect`, 90 immutable records per arm including failures/partials. |
| P0↔P1/P1↔T1 per-case reasons | `matrix.json`, `disagreements.jsonl`, historical-comparison limitations. |
| Abstain/failure/strict/audit separate | C1 status dimensions, official metrics, safety metrics, parser-audit metrics/rows. |
| FS/SCR/recall/quality/stability/cost | `safety-report.md`, attempt vectors, reviewed reasons and telemetry. |
| No hints/false independence | Prompt tests/diff and development-benchmark limitation. |
| MCP/Gate decision and unknowns | `decision.md`, Checkpoints and holdout status. |
| Same Gate/immutable inputs — conditional | G-P1/G-T1 input hashes and one rule/GateVersion digest. |
| Independent proof, not LLM vote — conditional | Confined checks, scope/necessity controls, receipts. |
| Failed/partial/unknown/invalid refs never safe — conditional | Targeted Gate tests and blocked rows. |
| Receipts, accepted safe, adversarial blocked — conditional | Per-rule fixtures and Gate result/receipt artifacts. |
| FS blocked AND retained/overblocked/cost — conditional | `score-gate` outputs and added-check telemetry. |
| Production unchanged — conditional | Benchmark-only code boundary; no analyze/export/case-state writes. |

## 14. Risks, dependencies and deferred work

Order: historical audit → prompts/patch/artifacts → targeted tests/smoke → freeze → P1/Checkpoint A → T1/Checkpoint B → conditional Gate/Checkpoint C → holdout/decision. Do not execute the benchmark while preparing this plan.

P0 drift, unexposed model revisions, dirty snapshots, config leakage and mutable images threaten comparability: fail admission or publish explicit limitations. MCP errors consume matched budget; never silently repair T1. Parser repair must remain separate. A seven-case exploitable denominator cannot establish general safety. Gate may have no independently closable scope and therefore only block; report that as feasibility/utility failure.

Defer Qwen3.8 until q36 completes; keep separate cohorts. Defer matched P0 unless causal prompt claims are needed. Defer Gate implementation until Checkpoint B, reachability/config/input proof rules until reliable coverage/necessity exists, and all production integration/automatic closure until holdout and risk approval.

During implementation run only fast targeted unit tests; use `--case <id>` for analyzer corpus probes. No analyzer behavior change is planned. If Go changes become justified, reserve full production corpus validation strictly for one final run per corpus; never run the full corpus mid-flight.

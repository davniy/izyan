# Task 6 implementation plan — structured Evidence Contract experiment

## 0. Goal, sources and design gate

**Design gate: READY.** No production Verification Gate is designed or built (spec §6). Task 6 delivers a report on the checkability of a structured evidence contract and a comparison of four projections (P2, T2, V-P2, V-T2) — not production architecture.

**Authoritative source:** `docs/dev/specs/2026-10-09-task6-structured-evidence-experiment.md` (6 sections, Russian). This plan mirrors the structure of the predecessor `docs/dev/plans/2026-10-09-task5-implementation-plan.md`.

**Goal:** establish whether a structured evidence contract (emitted by the prompt, validated offline without LLM) makes the two Task-5 false-safe mechanisms checkable — **error-as-absence** (a failed tool call read as "no path") and **scoped-zero generalized to a global claim** — and whether MCP tools (T2) add value over prompt-only (P2) under identical prompt/schema conditions.

**Root cause from Task 5 (gate-feasibility.md):** 86 of 87 parsed T1 answers carry only `{category, reasoning}` — no structured claims, no `evidence_refs`, no scope/subject binding. A Gate cannot tell which observation supports which sub-claim, so it can only threshold over the whole observation set, destroying 73% of correct safe answers to catch all 5 false-safes. Task 6 tests whether making the claim→subject/scope→evidence binding machine-readable fixes this.

**Non-goals:** production Verification Gate; production workflow changes; new MCP tools; case-specific prompts or validator rules; LLM voting as proof; outcome-driven retries; best-of selection; claiming the known VEX-Bench cases are unseen; privileging T2 over P2.

| Observation after matched tests and holdout | Architecture decision |
|---|---|
| Contract unworkable: most negative claims lack verifiable scope/evidence binding | Do not build Gate; revise format/approach. |
| Prompt-only sufficient: P2 reduces FS without unacceptable SCR loss | Prefer simpler prompt-only architecture. |
| MCP provably useful: T2 > P2 on pre-declared safety/utility metrics at acceptable cost | Retain only demonstrated-useful tools. |
| Validator useful: independently blocks dangerous safe decisions with pre-established acceptable SCR loss on holdout | Only then plan production Verification Gate. |
| No variant clears the safety bar | Research/triage assistant under human review; no automatic closure. |

## 1. Current architecture and exact reuse boundary

**Reuse verbatim (no modification):**
- `eval/c1/{assessment.py, status.py, collect.py, parser_audit.py, runner.py, report.py, manifest.py, synthetic.py}` — the controller/scoring core. `finalize_attempt` injects the official parser unchanged; `run_report` produces the official + safety + parser-audit projections; `validate_evidence_refs` cross-checks tool-minted refs against the audit trail.
- `eval/vexbench_plain_report.py` — safety metrics functions (`score_rows`, `aggregate_repeats`, `group_by_run`).
- External harness scoring files `src/evaluate/{result_parser.py, parse.py, metrics.py}` — imported, never modified.
- External harness agents `src/evaluate/agents/{opencode.py, opencode_c1.py}` — `OpenCodeB1PrimeAgent` (P2, no MCP) and `OpenCodeC1Agent` (T2, adds `mcp.izyan`); the only arm difference is the top-level `mcp` key in `_extend_config`.
- `internal/evidencetools/*` — the 31 MCP evidence tools and `Observation`/`ScopeDetails`/`BuildContext`/`AuditRecord` contracts. T2 runs these; P2 does not.

**Parameterise for experiment id `task6` (new thin glue, same shape as `eval/task5/*`):**
- `eval/task6/{__init__.py, protocol.py, manifest.py, collect.py, report.py, validator.py}` + `*_test.py`.
- `eval/vexbench_task6.py` — CLI entrypoint.
- `eval/task6/prompts/{vuln_safety_v2.txt, vuln_safety_v2_tools.txt, hashes.json, p2-t2.diff}`.
- `eval/task6/harness/vexbench-agent-ctl-task6.patch` — additive harness patch registering the two new prompt names.
- `eval/task6/experiment-manifest.json`.

**New (does not exist in Task 5):**
- `eval/task6/assessment_v2.py` + `assessment_v2_test.py` — the `AgentAssessment` schema (spec §3), versioned `agent-assessment/2`, extending the C1 `agent-assessment/1` field set with `mechanisms[]`, `negative_claims[]`, `unresolved[]`.
- `eval/task6/validator.py` + `validator_test.py` — the offline independent validator (spec §4).
- `eval/task6/replay.py` + `replay_test.py` — the V-P2/V-T2 offline replay driver.

**Do NOT create:** `internal/verificationgate`; a second agent loop; a second scorer; production CLI changes. The `gate-replay`/`score-gate` stubs in `eval/vexbench_task5.py` stay stubs; Task 6 uses its own `replay` subcommand.

## 2. Arm/cohort matrix and attempt policy

| Arm | Prompt | Agent | MCP | Post-check | Attempts |
|---|---|---|---|---|---|
| P2 | `vuln_safety_v2` (official + safety rules + structured assessment block) | `opencode-b1p` | None | None | 30 × 3 |
| T2 | `vuln_safety_v2_tools` (exact P2 bytes + `<EVIDENCE_TOOLS>` block) | `opencode-c1` | Existing 31 tools | None | 30 × 3 |
| V-P2 | Same saved P2 answers | No new agent run | Not supplied to validator | Offline validator | Same P2 attempt keys |
| V-T2 | Same saved T2 answers | No new agent run | Audit trail supplied to validator | Same offline validator | Same T2 attempt keys |

**Cohort:** `qwen3.6-35b` (harness key `qwen3.6-35b`, provider `custom-openai`, `custom-openai/Qwen/Qwen3.6-35B-A3B`). Same model/runtime/harness/timeout as Task 5. P1/T1 (Task 5) are historical controls; a causal P1↔P2 or T1↔T2 claim requires matched conditions, not comparison with a different runtime.

Freeze `timeout=900`, `parallel=1`, `repeats=3`, `retries=0`, no cache admission. Every attempt has an immutable key `(experiment_id, arm, model, task_id, run_NNN)`. Preserve failed attempts and partial bytes. No overwrite, selective cache, outcome-driven retry or best-of. Docker with ground truth outside the container; the rendered prompt carries only `{cve_id}`.

Pin endpoint, provider config, model settings (temperature/effort/revision = `null` with a limitation, never fabricated), output limits, task order, snapshot hashes, image IDs, toolchain versions, MCP catalog hashes (T2), native permissions, outbound research policy. Dataset: `vex_bench.jsonl` (30 Go tasks, sha `60b55373031dca97009d2e89ef8dfdf0ba083f9ce1035470fdf46f0da15384b3`, pinned in the manifest).

## 3. AgentAssessment schema (spec §3)

The agent returns a single strict JSON object on stdout. Top-level fields:

```json
{
  "category": "<one of 12 VEX-Bench categories, including uncertain>",
  "assessment": {
    "mechanisms": [
      {"subject": "<module/package/symbol>", "scope": "<build tags/platform/call context/mechanism>", "limitations": ["..."]}
    ],
    "negative_claims": [
      {
        "predicate": "<atomic assertion, e.g. unreachable / absent / fixed-version>",
        "subject": "<module/package/symbol>",
        "scope": "<build tags/platform/call context/considered mechanism>",
        "evidence_refs": ["src:...", "ev:...", "sha256:..."],
        "limitations": ["..."]
      }
    ],
    "unresolved": ["<unexplored alternative path / error / unresolved condition>"],
    "reasoning": "<human-readable explanation, NOT proof>"
  }
}
```

**Field rules:**
- `category` — one of the 12 official categories (`eval/c1/assessment.py:CATEGORY_ORDER`), including `uncertain`.
- `assessment.mechanisms[]` — verified manifestations/paths of the CVE, each with `subject`, `scope`, `limitations[]`. May be empty for a safe verdict.
- `assessment.negative_claims[]` — **atomic** negative assertions. Each has `predicate` (what is negated), `subject` (module/package/symbol), `scope` (build tags/platform/call context/considered mechanism), `evidence_refs[]` (observations supporting this claim), `limitations[]`. For a safe verdict, at least one negative claim must be present.
- `assessment.unresolved[]` — unexplored alternative paths, errors, unresolved conditions. Non-empty `unresolved` with a safe `category` is a defect (should be `uncertain`).
- `assessment.reasoning` — human text, **not proof**. The words `COMPLETE`, `safe`, and model confidence are not proof of completeness.

**Evidence-ref grammar (reconciled with live forms):**
- `ev:<observation-id>` — an actual MCP observation ID. Live form: `OBS-NNNN` (minted by `Session.nextID`). T2 may cite these; P2 cannot (no MCP observations). The validator resolves `ev:OBS-NNNN` against the attempt's `tool_calls.jsonl` audit trail.
- `src:<path>#L<line>@<snapshot-hash>` — a verifiable source position. Live dataflow form is `src:<file>#L<line>` (no hash suffix); the prompt instructs the agent to append `@<snapshot-hash>` using the snapshot hash from `get_product_snapshot`. The validator checks the file exists in the snapshot and the hash matches `meta.snapshot_hash`. P2 may emit only `src:` refs; T2 may use both.
- `sha256:<64hex>` — a payload digest emitted by `marshalData`. The validator resolves it against the audit trail's `Observation.EvidenceRefs`.
- `file:<path>[:<line>[-<line>]]` — agent-written snapshot location (not cross-checked against audit, but verified to exist in the snapshot).
- `url:<https-url>` — public advisory/fix reference (not cross-checked).

**Parse-time rejection (pydantic `extra=forbid`):**
- Unknown top-level keys; unknown `assessment` keys; `category` not in the 12; `evidence_refs` entries not matching the grammar; reserved controller keys (`schema_version`, `task_id`, `model`, etc.) inside `assessment`.

**Validator-time rejection (not parse-time — the agent answer is stored as-is):**
- `evidence_refs` pointing to observations not in the audit trail; snapshot-hash mismatch; subject/scope mismatch between claim and cited observation; safe verdict without a checkable falsifier or with insufficient CVE-scope coverage. These produce `INSUFFICIENT_EVIDENCE`/abstain or `UNVERIFIABLE`, not a parse failure.

**Schema version:** `agent-assessment/2`. The C1 `agent-assessment/1` (`eval/c1/assessment.py`) is not modified; `eval/task6/assessment_v2.py` defines the new schema, reusing `CATEGORY_ORDER`, `CATEGORY_TO_ESTIMATES`, `RESERVED_CONTROLLER_KEYS`, `_check_ref` (extended for the new grammar), `UsageStats`, `ToolExecution`, `AttemptMeta`, and the model-vs-controller split.

## 4. Offline validator (spec §4 — not a production Gate, no LLM)

`eval/task6/validator.py` implements four checks over a saved attempt's `(agent_assessment, tool_calls.jsonl, observations.jsonl, snapshot_hash, advisory_record)`. The advisory record (affected modules/packages/symbols + fixed versions) is a public input from `get_vulnerability`/OSV, never ground truth.

| Check | What it verifies | False-safe mechanism caught | Default on failure |
|---|---|---|---|
| **C1: Schema + ref existence + snapshot-hash** | Every `evidence_refs` entry resolves: `ev:OBS-NNNN` exists in the audit trail; `sha256:<hex>` exists in some `Observation.EvidenceRefs`; `src:<path>#L<line>@<hash>` — file exists in snapshot, hash == `meta.snapshot_hash`. | Forged or dangling refs. | `INVALID_EVIDENCE` — claim marked unsupported, not auto-accepted. |
| **C2: No error/unknown/partial/empty as global absence** | For each `negative_claim`, resolve its `evidence_refs` to observations. If any cited observation has `tool_status == ERROR` or `completeness == UNKNOWN`, or the claim's `scope` is a `PARTIAL` product-only enumeration used to assert a global "unreachable/absent", flag the claim. | **Error-as-absence** (k8s-3121, rancher-47914: failed tool calls read as "no path"). | `INSUFFICIENT_EVIDENCE` — the claim does not support a safe verdict. |
| **C3: Subject/scope match** | `negative_claim.subject` and `negative_claim.scope` must be consistent with the cited observation's `ScopeDetails.Subject` / `Observation.Scope` / `ScopeDetails.BuildContext`. A claim asserting a global property while its evidence scope is a single-build, product-only `PARTIAL` enumeration is a mismatch. | **Scoped-zero generalized** (testify-28948: "0 callers in product packages" → "never invoked from any code path"). | `SCOPE_MISMATCH` — claim not accepted as global. |
| **C4: Safe-verdict falsifier + CVE-scope coverage** | For a proposed safe verdict (`category` in safe categories), require (a) an explicit checkable falsifier — a named condition + the observation(s) that clear it — and (b) sufficient coverage of the advisory's declared affected modules/packages/symbols. If completeness over the declared CVE scope cannot be established → `INSUFFICIENT_EVIDENCE`/abstain. | Any safe verdict resting on incomplete coverage. | `INSUFFICIENT_EVIDENCE` — abstain, not safe. |

**UNVERIFIABLE:** Semantic correctness of complex Go reachability beyond the loaded scope (dynamic dispatch, interface resolution, dependency-internal paths, other build configurations, reflection/linkname/cgo) is marked `UNVERIFIABLE`, not auto-accepted and not proven. The validator does not prove semantic correctness; it only checks structural binding.

**Outputs:** `ValidatorResult{decision, per_claim[], falsifier, coverage, reason}`. `decision ∈ {ACCEPTED, INSUFFICIENT_EVIDENCE, UNVERIFIABLE, INVALID_EVIDENCE, SCOPE_MISMATCH}`. The agent's `category` and the validator's `decision` are stored separately. The validator never alters the agent's answer.

**Generality:** The validator is generic — no case names, no product identifiers, no hardcoded task IDs. It operates over the structured claim fields and the audit trail. Smoke cases are used only for testing, not for validator logic.

## 5. Deliverables and manifest

```text
eval/task6/
  assessment_v2.py + assessment_v2_test.py    # AgentAssessment schema (agent-assessment/2)
  protocol.py + protocol_test.py               # P2/T2 prompt generation (byte-exact)
  validator.py + validator_test.py             # offline validator (spec §4)
  replay.py + replay_test.py                   # V-P2/V-T2 offline replay driver
  manifest.py + manifest_test.py               # frozen manifest (task6)
  collect.py + collect_test.py                 # attempt finalization (thin wrapper over c1.collect)
  report.py + report_test.py                   # four-projection scoring join
  __init__.py
  prompts/{vuln_safety_v2.txt, vuln_safety_v2_tools.txt, hashes.json, p2-t2.diff}
  harness/{README.md, vexbench-agent-ctl-task6.patch}
  experiment-manifest.json
  results/{p2, t2}/                            # scored run roots
  results/smoke/{p2, t2}/                      # smoke (outside scored roots)
  scoring/{p2, t2, v_p2, v_t2}/                # per-projection scoring
  scoring/{matrix.json, safety-report.md, validator-report.md, decision.md}
```

Manifest fields (extend the Task 5 manifest shape): schema/experiment/environment IDs; spec hash; plan hash; Izyan/harness commits and approved diffs; both patch hashes; prompt full/short hashes and exact P2/T2 diff; `assessment_v2.py` hash + `validator.py` hash; effective config/native permissions; images/architecture/toolchain/binary/catalog/schema hashes; model/provider/revision/settings; dataset pin/tasks SHA/task IDs/snapshot hashes; deadlines/budgets/parallelism/repeats/retry/cache policy; parser/scorer/controller hashes; smoke/exposure records; raw/derived output roots; validator version; limitations.

## 6. Phase 6.0 — scorer re-verification and historical freeze

**Files:** `eval/task6/freeze.py` + `freeze_test.py` (new, thin wrapper over `eval/task5/freeze.py`); reads `eval/task5/scoring/{matrix.json, safety-report.md}`, `eval/task5/gate-feasibility.md`.

**Contract:** Re-verify the Task-5 scorer before using its metrics. The gate-feasibility report states `19 + 26 < 46` for the union of blocked correct-safes is impossible — measures must distinguish **attempts** from **unique cases**. `testify-28948` is 3 attempts of one case. Recompute the RG/R6/UNION tables by unique case (not by attempt) and confirm the Task-5 headline counts (FS=5/21, SCR=63/69 for T1). Freeze the Task-5 artifacts as historical reference (read-only, never written to).

**Acceptance:** `freeze_test.py` passes; `eval/task6/freeze/task5-reference.json` contains the recomputed by-case and by-attempt tables with the `19+26<46` anomaly explained (overlap between RG and R6 correct-safe sets); Task-5 artifact hashes re-verified.

**Run:** `"$PY" eval/vexbench_task6.py freeze-history --harness-dir "$HARNESS" --out eval/task6/freeze`

## 7. Phase 6.1 — prompt/schema/parser (P2/T2 + AgentAssessment)

**Files:** `eval/task6/protocol.py` + `protocol_test.py`; `eval/task6/assessment_v2.py` + `assessment_v2_test.py`; `eval/task6/prompts/{vuln_safety_v2.txt, vuln_safety_v2_tools.txt, hashes.json, p2-t2.diff}`; `eval/task6/harness/vexbench-agent-ctl-task6.patch`.

**Prompt construction:**
- P2 = frozen official template (`eval/vexbench-prompts/official-vuln-c0a5c8458b77.txt`, sha `c0a5c8458b77...`) + `<SAFETY_RULES>` block (verbatim from Task 5) + `<STRUCTURED_ASSESSMENT>` block (new, spec §3).
- T2 = exact P2 bytes + two LF + `<EVIDENCE_TOOLS>` block (reuse the C1 `eval/c1/protocol.py:EVIDENCE_TOOLS_BLOCK` which carries the binding scope/completeness rules, richer than Task 5's shorter block).
- The `<STRUCTURED_ASSESSMENT>` block instructs the agent to emit the `assessment` object with `mechanisms[]`, `negative_claims[]` (atomic: `predicate`, `subject`, `scope`, `evidence_refs[]`, `limitations[]`), `unresolved[]`, `reasoning`. It specifies the evidence-ref grammar (`ev:OBS-NNNN`, `src:<path>#L<line>@<snapshot-hash>`, `sha256:<hex>`). It states that `COMPLETE`/`safe`/model confidence are not proof; `uncertain` is an abstention.
- No case/product/fix identifiers in the appended blocks (reuse `find_prohibited`/`scan_prompts` from `eval/task5/protocol.py`).

**Schema (`assessment_v2.py`):** pydantic models with `extra=forbid`. `NegativeClaim{predicate, subject, scope, evidence_refs[], limitations[]}`. `Mechanism{subject, scope, limitations[]}`. `AssessmentPayloadV2{mechanisms[], negative_claims[], unresolved[], reasoning}`. `AgentAssessmentV2{schema_version="agent-assessment/2", meta, category, reasoning, assessment, tool_executions[], usage}`. Reuse `CATEGORY_TO_ESTIMATES`, safe-needs-counterexample logic (a safe `category` requires at least one `negative_claim` with non-empty `evidence_refs`). `extract_assessment_v2(final_text)` recovers the assessment from the terminal JSON (reuse `parser_audit.find_category_object` for string-aware extraction). `validate_evidence_refs_v2(assessment, audit_records, snapshot_hash)` cross-checks refs.

**Harness patch:** additive, same shape as `eval/task5/harness/vexbench-agent-ctl-task5.patch` — registers `PROMPTS["vuln_safety_v2"]` and `PROMPTS["vuln_safety_v2_tools"]` via `_load_prompt_file`, adds the two `prompts_data/` files. No new agent, no scorer change.

**Acceptance:** `protocol_test.py` asserts: P2 prefix is the official file bytes; T2 minus P2 is exactly two LF + `<EVIDENCE_TOOLS>` block; no prohibited identifiers; `config_delta_only_mcp` equality after removing only top-level `mcp`. `assessment_v2_test.py` asserts: schema accepts valid payloads; rejects unknown keys, bad refs, reserved controller keys; safe category requires negative claims with evidence; extraction recovers assessment from terminal text with trailing prose.

**Run:** `"$PY" -m eval.task6.protocol --out eval/task6/prompts --harness-dir "$HARNESS"` then `"$PY" -m unittest eval.task6.protocol_test eval.task6.assessment_v2_test`

## 8. Phase 6.2 — offline validator

**Files:** `eval/task6/validator.py` + `validator_test.py`.

**Contract:** `validate_attempt(assessment, audit_records, observations, snapshot_hash, advisory_record) -> ValidatorResult`. Implements checks C1–C4 (§4 above). No LLM, no GT, no model calls. Inputs: the saved `agent_assessment.json`, `tool_calls.jsonl`, `observations.jsonl`, `meta.snapshot_hash`, and the public OSV advisory record (affected modules/packages/symbols + fixed versions, from `get_vulnerability` output in the audit trail — never from the benchmark GT).

**Check implementations:**
- C1: for each `negative_claim.evidence_refs[]`, resolve `ev:OBS-NNNN` → find in `audit_records` by observation ID; `sha256:<hex>` → find in any `Observation.EvidenceRefs`; `src:<path>#L<line>@<hash>` → verify `hash == snapshot_hash` (file existence is checked against the snapshot if available, else `UNVERIFIABLE`). Unresolved → `INVALID_EVIDENCE`.
- C2: for each cited observation, if `tool_status == ERROR` or `completeness == UNKNOWN` → the claim rests on error-as-absence → `INSUFFICIENT_EVIDENCE`. If `completeness == PARTIAL` and the claim's `scope` asserts a global property → flag for C3.
- C3: compare `negative_claim.subject`/`scope` with the cited observation's `ScopeDetails.Subject`/`Scope`/`BuildContext`. A global claim on a `PARTIAL` product-only scope → `SCOPE_MISMATCH`.
- C4: for a safe `category`, require at least one `negative_claim` with all refs resolved (C1 passed), no error-as-absence (C2 passed), scope match (C3 passed), and coverage of every advisory-declared affected module/package/symbol. If any affected symbol lacks `COMPLETE` coverage → `INSUFFICIENT_EVIDENCE`/abstain. If coverage rests on `PARTIAL`/opaque observations (dynamic dispatch, interface, dep-internal) → `UNVERIFIABLE`.

**Adversarial test fixtures (generic, no case names):**
- `test_error_as_absence_blocked`: negative claim citing only ERROR observations → `INSUFFICIENT_EVIDENCE`.
- `test_scoped_zero_global_blocked`: negative claim with `scope="global"` citing a `PARTIAL` product-only zero-result observation → `SCOPE_MISMATCH`.
- `test_valid_safe_accepted`: correct safe with all refs resolved, `COMPLETE` closed-scope observations, full CVE-scope coverage → `ACCEPTED`.
- `test_dangling_ref_rejected`: `ev:OBS-9999` not in audit → `INVALID_EVIDENCE`.
- `test_snapshot_hash_mismatch_rejected`: `src:...@<wrong-hash>` → `INVALID_EVIDENCE`.
- `test_incomplete_cve_scope_abstain`: safe verdict covering 1 of 2 advisory-declared affected symbols → `INSUFFICIENT_EVIDENCE`.
- `test_unverifiable_dynamic_dispatch`: safe claim resting on `PARTIAL` dynamic-dispatch observation → `UNVERIFIABLE`.
- `test_unresolved_nonempty_blocks_safe`: safe `category` with non-empty `unresolved[]` → `INSUFFICIENT_EVIDENCE`.

**Acceptance:** All validator tests pass. The validator is generic (no case-specific logic, no hardcoded task IDs).

**Run:** `"$PY" -m unittest eval.task6.validator_test`

## 9. Phase 6.3 — smoke

**Files:** `eval/vexbench_task6.py` (smoke subcommand); `eval/task6/results/smoke/`.

**Contract:** Run the 4 named false-safe cases (`k8s-44487`, `k8s-3121`, `rancher-47914`, `testify-28948`) + 3–4 correct safe cases (selected host-side by GT class before any answer is examined; labels never rendered to the agent). For each: run the attempt, finalize via `eval.c1.collect.finalize_attempt` with `assessment_v2` extraction, parse the structured assessment, verify ref binding and scope substance. Check that the official parser accepts the JSON (the `assessment` nesting must not break `result_parser.parse_category` — the brace-counting parser takes the first `{`…`}` span; the structured assessment must be in a separate top-level key, not nested inside the category object in a way that breaks brace counting). If the official parser fails, `parser_audit.find_category_object` recovers the full object.

**Acceptance:** Smoke summary shows: both arms ran; `assessment_schema == "valid"` for structured outputs; `evidence_refs` resolve against the audit trail (T2) or are `src:` only (P2); `negative_claims` have non-empty `subject`/`scope`; no prompt contamination (`_assert_prompt_clean`).

**Run:** `"$PY" eval/vexbench_task6.py smoke --harness-dir "$HARNESS" --tasks "$TASKS" --repos-dir "$REPOS" --acquisition "$ACQ" --model qwen3.6-35b --timeout 900 --arms p2,t2 --out eval/task6/results/smoke`

## 10. Phase 6.4 — freeze + development run (P2/T2, 30×3)

**Files:** `eval/task6/experiment-manifest.json`; `eval/task6/results/{p2,t2}/`.

**Contract:** Freeze prompts/schema/validator/manifest before scored runs. Run 30 Go cases × 3 repeats for P2 then T2, identical model/runtime/harness/timeout, Docker with GT outside the container, no outcome-driven retries. Collect artifacts via `eval.task6.collect.finalize_arm` (thin wrapper over `eval.task5.collect.finalize_arm` using `assessment_v2` extraction instead of `relabel_assessment_absent`). Score each arm via `eval.c1.report.run_report` (official + safety + parser-audit projections).

**Arm isolation:** P2 effective config must carry no top-level `mcp` and no audit sink; T2 must carry both. Verified by `audit_arm_attempt` (reused from `eval/task5/collect.py`).

**Acceptance:** 90 immutable attempt records per arm (including failures/partials); manifest frozen with all pins; `verify_frozen_inputs` passes; arm isolation audit clean; no `[CACHE]`/`[RE-RUN]` admission.

**Run:**
```bash
"$PY" eval/vexbench_task6.py manifest --harness-dir "$HARNESS" --tasks "$TASKS" --repos-dir "$REPOS" --acquisition "$ACQ" --model qwen3.6-35b --timeout 900 --repeats 3 --parallel 1 --out eval/task6/experiment-manifest.json
cd "$HARNESS"
uv run --locked --no-sync vex-bench evaluate run --agent opencode-b1p --prompt vuln_safety_v2 --model qwen3.6-35b --benchmark vex_bench --repeats 3 --timeout 900 --parallel 1 --repos-dir "$REPOS" --output-dir "$WORKTREE/eval/task6/results/p2"
cd "$WORKTREE"
"$PY" eval/vexbench_task6.py collect --manifest eval/task6/experiment-manifest.json --arm p2
"$PY" eval/vexbench_task6.py score --manifest eval/task6/experiment-manifest.json --arms p2 --out eval/task6/scoring
cd "$HARNESS"
uv run --locked --no-sync vex-bench evaluate run --agent opencode-c1 --prompt vuln_safety_v2_tools --model qwen3.6-35b --benchmark vex_bench --repeats 3 --timeout 900 --parallel 1 --repos-dir "$REPOS" --output-dir "$WORKTREE/eval/task6/results/t2"
cd "$WORKTREE"
"$PY" eval/vexbench_task6.py collect --manifest eval/task6/experiment-manifest.json --arm t2
"$PY" eval/vexbench_task6.py score --manifest eval/task6/experiment-manifest.json --arms p2,t2 --out eval/task6/scoring
```

## 11. Phase 6.5 — offline replay (V-P2/V-T2)

**Files:** `eval/task6/replay.py` + `replay_test.py`; `eval/task6/scoring/{v_p2, v_t2}/`.

**Contract:** Load the saved, immutable P2/T2 responses (no model re-invocation). For each attempt: read `agent_assessment.json` (or recover from `raw_agent_output.txt` via `assessment_v2.extract_assessment_v2`), read `tool_calls.jsonl`/`observations.jsonl`, read `meta.snapshot_hash`, extract the advisory record from the audit trail (`get_vulnerability` observation). Run `validator.validate_attempt(...)`. Store `ValidatorResult` alongside the agent's `category` (never alter the agent's answer). Score the validator-adjusted projection: a validator `INSUFFICIENT_EVIDENCE`/`UNVERIFIABLE`/`INVALID_EVIDENCE`/`SCOPE_MISMATCH` on a safe verdict → abstain (not safe, not positive); `ACCEPTED` → keep the agent's outcome. Score with and without the validator (raw P2/T2 vs V-P2/V-T2).

**Acceptance:** V-P2/V-T2 scoring dirs contain `parsed.jsonl`, `safety_metrics.json`, `validator_results.jsonl` (per-attempt validator decision + per-claim details). No model calls. Agent answers unchanged (byte-verified against P2/T2 raw artifacts). `replay_test.py` asserts: replay over a fixture with a known error-as-absence claim → validator blocks it; replay over a valid safe → validator accepts; raw and validator projections differ only on blocked claims.

**Run:** `"$PY" eval/vexbench_task6.py replay --manifest eval/task6/experiment-manifest.json --arms p2,t2 --out eval/task6/scoring`

## 12. Phase 6.6 — metrics and report

**Files:** `eval/task6/report.py` + `report_test.py`; `eval/task6/scoring/{matrix.json, safety-report.md, validator-report.md}`.

**Contract:** Join all four projections (P2, T2, V-P2, V-T2) into a cross-projection matrix. For each projection compute: `False-Safe`, `Safe Clear Rate`, `EXPLOITABLE recall`, `FAILED`, `abstain`, share of valid structured claims (`assessment_schema == valid`), share of genuinely checkable negative claims (validator `ACCEPTED` on negative claims), operational cost (tokens/wall/tool calls). Separately: **FS blocked / correct safe lost**, by attempts AND by unique cases (testify = 1 case, not 3), for P2↔T2 and raw↔validator. Reuse `eval/task5/report.py` join logic (`build_matrix`, `_transition_class`) extended for 4 projections.

**Acceptance:** `safety-report.md` contains a 4-projection table with all metrics and denominators (7 exploitable / 23 safe per repeat, by attempt and by unique case). `validator-report.md` contains: FS blocked per projection, correct safe lost, valid-claim share, checkable-negative-claim share, per-claim validator decision distribution. `matrix.json` has one row per (task_id, run_id) with all 4 projection outcomes.

**Run:** `"$PY" eval/vexbench_task6.py report --manifest eval/task6/experiment-manifest.json --out eval/task6/scoring`

## 13. Phase 6.7 — holdout

**Files:** `eval/task6/holdout/` (new cases, frozen before use).

**Contract:** After criteria (prompts/schema/validator/metrics) are frozen, run new, unused cases/projects not in the 30-case development set. Freeze the holdout selection before applying the unchanged prompts/validator. Labels remain scorer-only. If holdout is unavailable, `decision.md` is explicitly preliminary and cannot claim proven safety.

**Acceptance:** Holdout cases are frozen and distinct from the development set (verified by task ID). The frozen prompts/validator are applied unchanged. If no holdout, `decision.md` states "PRELIMINARY — no holdout".

## 14. Phase 6.8 — decision

**Files:** `eval/task6/scoring/decision.md`.

**Contract:** Record the four-projection comparison, the §0 decision-table row chosen, per-projection counts/denominators (by attempt and by unique case), FS blocked / correct safe lost, valid-claim share, checkable-negative-claim share, cost trade-offs, P2↔T2 and raw↔validator deltas, holdout status, and unproven guarantees. State explicitly: no production Verification Gate is started; the result is a report on evidence-contract checkability.

**Acceptance:** `decision.md` references all four projections, names the decision-table row, states holdout status, and does not claim proven safety without holdout.

## 15. Exact commands and implementation contracts

`eval/vexbench_task6.py` is a **new interface to implement**. Subcommands: `freeze-history`, `smoke`, `manifest`, `collect`, `score`, `replay`, `report`. No `gate-replay`/`score-gate` (those stay Task-5 stubs). All subcommands reuse C1/harness functions.

```bash
export WORKTREE=<VA_REPO> HARNESS=<VA_VEXBENCH>/agent-ctl
export PY="$HARNESS/.venv/bin/python" TASKS="$HARNESS/benchmark/tasks/vex_bench.jsonl"
export REPOS=<VA_VEXBENCH>/repos ACQ=<VA_VEXBENCH>/acquisition.json
cd "$WORKTREE"

# Phase 6.0 — scorer re-verification + freeze
"$PY" eval/vexbench_task6.py freeze-history --harness-dir "$HARNESS" --out eval/task6/freeze

# Phase 6.1 — prompt/schema/parser
"$PY" -m eval.task6.protocol --out eval/task6/prompts --harness-dir "$HARNESS"
"$PY" -m unittest eval.task6.protocol_test eval.task6.assessment_v2_test

# Phase 6.2 — validator
"$PY" -m unittest eval.task6.validator_test

# Phase 6.3 — smoke
(cd "$HARNESS" && docker/build-c1.sh "$WORKTREE")  # only if pinned image unavailable
"$PY" eval/vexbench_task6.py smoke --harness-dir "$HARNESS" --tasks "$TASKS" --repos-dir "$REPOS" --acquisition "$ACQ" --model qwen3.6-35b --timeout 900 --arms p2,t2 --out eval/task6/results/smoke

# Phase 6.4 — freeze + dev run
"$PY" eval/vexbench_task6.py manifest --harness-dir "$HARNESS" --tasks "$TASKS" --repos-dir "$REPOS" --acquisition "$ACQ" --model qwen3.6-35b --timeout 900 --repeats 3 --parallel 1 --out eval/task6/experiment-manifest.json
cd "$HARNESS"
uv run --locked --no-sync vex-bench evaluate run --agent opencode-b1p --prompt vuln_safety_v2 --model qwen3.6-35b --benchmark vex_bench --repeats 3 --timeout 900 --parallel 1 --repos-dir "$REPOS" --output-dir "$WORKTREE/eval/task6/results/p2"
cd "$WORKTREE"
"$PY" eval/vexbench_task6.py collect --manifest eval/task6/experiment-manifest.json --arm p2
"$PY" eval/vexbench_task6.py score --manifest eval/task6/experiment-manifest.json --arms p2 --out eval/task6/scoring
cd "$HARNESS"
uv run --locked --no-sync vex-bench evaluate run --agent opencode-c1 --prompt vuln_safety_v2_tools --model qwen3.6-35b --benchmark vex_bench --repeats 3 --timeout 900 --parallel 1 --repos-dir "$REPOS" --output-dir "$WORKTREE/eval/task6/results/t2"
cd "$WORKTREE"
"$PY" eval/vexbench_task6.py collect --manifest eval/task6/experiment-manifest.json --arm t2
"$PY" eval/vexbench_task6.py score --manifest eval/task6/experiment-manifest.json --arms p2,t2 --out eval/task6/scoring

# Phase 6.5 — offline replay (V-P2/V-T2)
"$PY" eval/vexbench_task6.py replay --manifest eval/task6/experiment-manifest.json --arms p2,t2 --out eval/task6/scoring

# Phase 6.6 — metrics and report
"$PY" eval/vexbench_task6.py report --manifest eval/task6/experiment-manifest.json --out eval/task6/scoring

# Phase 6.7 — holdout (after criteria frozen)
"$PY" eval/vexbench_task6.py smoke --harness-dir "$HARNESS" --tasks <holdout-tasks> --repos-dir "$REPOS" --acquisition "$ACQ" --model qwen3.6-35b --timeout 900 --arms p2,t2 --out eval/task6/holdout
"$PY" eval/vexbench_task6.py replay --manifest eval/task6/experiment-manifest.json --arms p2,t2 --out eval/task6/holdout/scoring

# Phase 6.8 — decision (written manually from the scoring artifacts)
```

## 16. Every acceptance criterion → evidence

| Criterion | Artifact/command |
|---|---|
| Scorer re-verified (attempts vs unique cases) | `freeze-history`; `eval/task6/freeze/task5-reference.json` with by-case and by-attempt tables. |
| P2/T2 prompts byte-exact, no prohibited identifiers | `protocol_test.py`; `eval/task6/prompts/hashes.json` + `p2-t2.diff`. |
| AgentAssessment schema validates spec §3 fields | `assessment_v2_test.py`; schema accepts/rejects fixtures. |
| Evidence-ref grammar reconciled with live forms | `assessment_v2_test.py` ref-form tests; `validator_test.py` ref-resolution tests. |
| Validator catches error-as-absence | `validator_test.py::test_error_as_absence_blocked`. |
| Validator catches scoped-zero generalization | `validator_test.py::test_scoped_zero_global_blocked`. |
| Validator accepts valid safe | `validator_test.py::test_valid_safe_accepted`. |
| Validator is generic (no case hardcoding) | `validator.py` source — no task IDs, no product names in logic. |
| Smoke: parsing, ref binding, scope substance | `eval/task6/results/smoke/smoke-summary.json`; `assessment_schema == valid`. |
| P2/T2 matched, 90 attempts each, isolation clean | `collect`; `audit_arm_attempt` per attempt; manifest pins. |
| No outcome-driven retries, immutable attempts | `collect`; `DuplicateAttemptError` on overwrite; no `[CACHE]`/`[RE-RUN]`. |
| V-P2/V-T2 replay: no model calls, answers unchanged | `replay`; byte-verify raw artifacts vs P2/T2; `validator_results.jsonl`. |
| Four-projection metrics with FS/SCR/recall/abstain/cost | `scoring/safety-report.md`; `scoring/matrix.json`. |
| FS blocked / correct safe lost by attempt AND unique case | `scoring/validator-report.md`; by-attempt and by-case tables. |
| P2↔T2 and raw↔validator comparison | `scoring/matrix.json` cross-projection rows; `scoring/validator-report.md`. |
| Valid-claim share, checkable-negative-claim share | `scoring/validator-report.md`. |
| Holdout: new cases, frozen criteria | `eval/task6/holdout/`; distinct task IDs; unchanged prompts/validator. |
| No production Verification Gate | No `internal/verificationgate` created; `decision.md` states this. |
| T2 not privileged over P2 | Identical prompt/schema; only tool availability differs; `config_delta_only_mcp` verified. |
| Production unchanged | Benchmark-only code boundary; no `analyze`/`export`/case-state writes; no Go changes. |

## 17. Risks, dependencies and deferred work

**Order:** scorer re-verification → prompts/schema/patch → validator + tests → smoke → freeze → P2/Checkpoint → T2 → offline replay V-P2/V-T2 → metrics/report → holdout → decision. Do not execute the benchmark while preparing this plan.

**Risks:**
- **Official parser vs nested JSON:** The official `result_parser._extract_json_object` uses brace counting and takes the first `{`…`}` span. If the agent nests `assessment` inside the category object, the parser may truncate. Mitigation: the prompt instructs `assessment` as a separate top-level key; `parser_audit.find_category_object` recovers the full object if the official parser fails. Smoke (Phase 6.3) verifies this before scored runs.
- **Evidence-ref grammar mismatch:** The spec's `ev:<id>` and `src:<path>:<line>@<snapshot-hash>` do not match live forms (`OBS-NNNN`, `src:<file>#L<line>`). The plan reconciles by extending the grammar (§3). If the agent emits refs in a non-reconciled form, the validator marks them `INVALID_EVIDENCE` (not auto-accepted).
- **P2 cannot produce `ev:` refs:** P2 has no MCP observations. Its `negative_claims` can only cite `src:` and `file:` refs. The validator must handle this: `src:` refs are checked against the snapshot (file existence + hash); `ev:` refs are absent. A P2 safe verdict resting only on `src:` refs with `COMPLETE` coverage can be `ACCEPTED`; one resting on `src:` refs from a `PARTIAL` scope is `INSUFFICIENT_EVIDENCE`.
- **Model format drift:** The P1 `invalid_terminal_answer` failure mode (trailing prose after JSON) may recur. `parser_audit` recovers or marks failed; never safe.
- **7-case exploitable denominator:** Coarse; one attempt ≈ 4.8 pp, one case wrong in 3/3 ≈ 14.3 pp. Report by attempt and by unique case.
- **Validator overblocking:** The validator may block correct safe answers (the Task-5 73% overblock failure). The `test_valid_safe_accepted` fixture guards against this. Report FS blocked AND correct safe lost.
- **P0 drift, unexposed model revisions, dirty snapshots, config leakage:** Fail admission or publish explicit limitations.

**Dependencies:** Task 5 artifacts (frozen, read-only); external harness (pinned by patch); Docker images (pinned in manifest); model `qwen3.6-35b` (custom-openai).

**Deferred work:**
- Production Verification Gate (spec §6: not started).
- Qwen3.8 second cohort (separate, never pooled).
- Causal P1↔P2 or T1↔T2 claim (requires matched historical re-run).
- Holdout if unavailable (decision stays preliminary).
- All production integration / automatic closure until holdout and risk approval.

## 18. Repo-rule sync

Task 6 is an experiment; production-doc churn should be minimal/honest:
- `docs/dev/gap-analysis.md` §2: add a backlog entry for the structured evidence contract experiment result (open until Task 6 completes; closed when the decision is recorded).
- `eval/README.md`: add a `## 12. Task 6 — Structured Evidence Contract (eval/task6/)` section documenting the four projections and the experiment status, only if observed behavior changes.
- No changes to `internal/`, `cmd/izyan/`, or production specs unless the experiment result justifies a follow-up production task.

## 19. Task dependency / order summary

| Phase | Deliverable | Depends on | Independent? |
|---|---|---|---|
| 6.0 | Scorer re-verification + historical freeze | Task 5 artifacts | — |
| 6.1 | P2/T2 prompts + AgentAssessment schema + parser | 6.0 | — |
| 6.2 | Offline validator | 6.1 (schema) | Yes (can start once schema fields are defined, in parallel with prompt finalisation) |
| 6.3 | Smoke (7–8 cases × 2 arms) | 6.1, 6.2, harness image | — |
| 6.4 | Freeze + dev run P2/T2 (30×3) | 6.3 (smoke passes) | — |
| 6.5 | Offline replay V-P2/V-T2 | 6.4 (saved answers), 6.2 (validator) | — |
| 6.6 | Metrics and report (4 projections) | 6.5 | — |
| 6.7 | Holdout | 6.6 (criteria frozen) | — |
| 6.8 | Decision | 6.7 | — |

**Genuinely independent:** 6.2 (validator) can run in parallel with 6.1 (prompt/schema) once the `AgentAssessment` field names are agreed — the validator tests use synthetic fixtures, not real prompts. All other phases are sequential.

During implementation run only fast targeted unit tests (`"$PY" -m unittest eval.task6.*_test`); the full corpus eval runs **exactly once** at Phase 6.4 final validation. No analyzer behavior change is planned; no Go changes are planned. If Go changes become justified, reserve full production corpus validation strictly for one final run per corpus.

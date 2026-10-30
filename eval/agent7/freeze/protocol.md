**Advisory inputs.** Every arm run MUST use `izyan eval vex-bench --osv-dir
<dir>` with a provisioned frozen advisory record for each requested CVE, or
record an explicit deviation from the frozen-source protocol. The runner
records raw and canonical advisory digests; strict agent runs additionally
require `izyan-evidence-tools --govulndb <path>` and a pinned local database.

# A1 — Frozen experimental protocol (agent7, PR-0)

Status: **frozen at PR-0** — this file fixes *how* comparisons are run and
scored. Companion pins live in `eval/agent7/freeze/manifest.json`
(schema `agent7-manifest/1`); the rubric in `research-rubric.md`; the
security preconditions in `security-boundary-check.md`.

**Implementation language.** All A-series implementation is **Go**
(`internal/eval/agent7/…`, following the `internal/eval/vexbench/`
convention). `eval/agent7/` carries data-only artifacts — JSON manifests
and Markdown documents — and no executable code, no Python modules, no
empty future directories (`baselines/`, `arms/`, `scoring/`, `decisions/`
are created only by the PRs that fill them, plan §7). PR-0 changes **no**
`izyan analyze` behaviour and adds no new flags.

**Threat model.** The attempt container sees **only the product
snapshot** plus its run output dir; the izyan repo and every GT carrier
(`eval/ground-truth*`, `eval/corpus*`, `benchmark/tasks/*.jsonl`,
reference PRs) are never mounted. `gt_paths_denied` in the manifest is
the policy list the future tool broker enforces inside the sandbox — it
is not the isolation boundary itself (see `security-boundary-check.md`).
`eval/products/**` and `eval/advisories/**` are analysis inputs, not
ground truth, and are agent-visible by design.

**Run gate.** `freeze_status: protocol_frozen`: prompt bytes, the ≤5 R1
tool subset, the holdout manifest and checkpoint sign-offs are authored
in later tasks (A2/A4/A9) and enforced
**arm-scoped** by `internal/eval/agent7.CheckRunGateForArm` (development
dataset) / `CheckRunGateForBlindArm` (A9 blind runs). The E6 sandbox
report is **pinned** (`environment.e6`: `status: "PASS"`, verbatim report
at `freeze/e6/security-boundary-check.json` + sha256). An arm's gate is
CLOSED until *its own* pins are supplied; `CheckRunGate` remains the
strict superset over every requirement at once for the later phases.

Gate inputs (`manifest.run_gate`): every arm shares the reproducibility /
environment pins — `outcomes.scorer_version`, the `run_profile` memory-
ceiling / parallelism / degraded-declaration pins, `environment.e6`
(PASS report at a pinned path+sha256; `ENV_FAIL`/`FAIL`/`not_verified`
all close the gate) and `checkpoint_0` sign-off (signed 2026-10-11,
`docs/dev/decisions/agent7-checkpoint-0.md`). Per arm:

- **A2 (`B1`/`R0`)**: `prompts.arm_prompts[<arm>]` — the arm's frozen
  prompt sha256 — plus `checkpoint_a` sign-off. The R1 tool list and the
  A9 holdout do **not** close the A2 gate. — **SATISFIED 2026-10-11**
  (both prompt hashes pinned + Checkpoint A signed; see A2 status below).
- **`B0`** (deterministic, no prompt): shared pins + `checkpoint_a`.
- **`R1`/`R2`**: prompt pin + `tool_exposure.R1.selected_tool_names`
  (1..5, decided in A4) + `checkpoint_b` sign-off.
- **`PR1`** (deterministic): shared pins + `checkpoint_c` sign-off.
- **A9 blind runs** (any arm): all of the above plus
  `holdout.manifest_file` + `holdout.manifest_sha256`.

The deviation from plan A1 (prompt bytes and the tool subset are
authored after the freeze) is recorded in `limitations`.

**A2 status (2026-10-11).** The `B1`/`R0` prompt bytes are authored and
pinned: `prompts.arm_prompts["B1"] = e10e2a92…548b09`,
`prompts.arm_prompts["R0"] = dba37365…f6097a`, with the same pins recorded
under `prompts.files` (`eval/agent7/prompts/b1.txt` / `…/r0.txt`) so
`Validate` hash-verifies the artifacts. The treatment delta is
byte-additive — `r0.txt` is `b1.txt` minus its final LF, then two LF,
then the `<RESEARCH_ASSESSMENT>` block (delta sha256 `11d17070…60cf6`,
pinned in `prompts.treatment_delta`); every other prompt byte is
identical across the two arms. Checkpoint A is operator-signed
(`checkpoint_a`: operator message of 2026-10-11, provenance convention of
`docs/dev/decisions/agent7-checkpoint-0.md`), so
`CheckRunGateForArm` reports the development-dataset gate **OPEN** for
`B1` and `R0`; `CheckRunGate` stays closed on the A4/A9 pins. A2 run
scope: 8–12 dev cases (of the frozen dev 30), 3 repeats per the frozen
`attempt_policy`, E6 image `opencode-e6`, **no MCP**.


## 1. Arms and comparison order

| Arm | Role | Treatment variable | Everything else identical to |
|---|---|---|---|
| `B0` | Product reference: current `izyan analyze` + `izyan eval vex-bench` | none (fixed product pipeline) | same snapshots, same dataset, same scorer |
| `B1` | Plain coding-agent baseline | none (read/search only, no Izyan tools) | same snapshot, model, image, prompt skeleton, attempt policy |
| `R0` | Research PoC | research prompt/protocol only, no Izyan tools | identical to B1 except the prompt treatment delta |
| `R1` | R0 + ≤5 selected Izyan facts | tool exposure set (decided in A4) | identical to R0 otherwise |
| `R2` | R1 + bounded counterexample pass | critic pass by the **same** agent (no independent vote) | identical to R1 otherwise |
| `PR1` | Offline proof projection over saved R2/B0 artifacts | none — **no new LLM calls** | consumes frozen run artifacts only |

Comparison order (spec §9.1):

1. **Matched B0↔B1 smoke** on the frozen smoke set — sanity that the
   harness, snapshot mounting and output contract work end-to-end for both
   a product pipeline and an agent arm.
2. **R0↔B1** — the Checkpoint-A question: does the research protocol add
   measurable analyst usefulness over a plain coding-agent?
3. **R0↔R1** — do selected Izyan facts add correct observations?
4. **R1↔R2** — does the bounded counterexample pass add correct
   corrections / alternative paths?
5. **PR1** — offline projection over saved artifacts; incremental
   certified-safe measured against B0.

Historical Task 3–6 cohorts stay **context, not causal baselines**
(plan §A1): different prompts, runtimes and attempt policies.

## 2. Identical-conditions checklist

For every matched comparison the following are byte- or value-identical
across arms unless the arm's treatment variable explicitly changes them;
each is pinned in `manifest.json` before any run:

- **Snapshot**: same task id → same `repos_dir` snapshot at the pinned
  `commit_sha`, verified by `dataset.snapshot_hashes` content hashes.
- **Model**: `qwen3.6-35b` via `custom-openai (OpenAI-compatible gateway, OpenAI-compatible)`
  (`custom-openai/Qwen/Qwen3.6-35B-A3B`), context 262144 / output 16384; provider-
  unexposed settings stay `null`, never fabricated.
- **Run profile**: the deterministic-runner memory ceiling and
  parallelism bound pinned in `manifest.json` `run_profile`
  (`--mem-limit 24GiB`, `-j ≤ 3`). The memory ceiling is
  result-affecting (§10), so an arm run under a different profile is
  not comparable even when it completes.
- **Runtime**: same harness dir + commit + dirty-file list, same
  `opencode 1.15.5`, same container image digest per arm role
  (`opencode-e6` for the no-MCP arms, `opencode-c1` for MCP arms).
  **A2 `B1`/`R0` run on the E6 image** `vex-bench-go-opencode-e6`
  (sha256 `c85bc1df…79ba1`): the read/search-only synthesized config
  (`read`/`glob`/`grep` allow, catch-all + every other tool deny), no MCP,
  no shell/process/network tools — `bash`, `edit`, `webfetch`,
  `websearch`, `task` denied and proven absent from the model toolset —
  under the frozen attempt policy (§2 Budget); container posture and the
  PASS probe are pinned in `manifest.sandbox`/`environment.e6` and
  `security-boundary-check.md` §8.
- **Budget**: `attempt_policy` timeout 900 s, repeats 3, parallel 1,
  retries 0 — identical across LLM arms; B0 and PR1 are deterministic and
  run once (deviation recorded in `limitations`).
- **Scorer**: the frozen classification/aggregation rules in
  `internal/eval/agent7` (`controller.files_sha256` pins the exact bytes).
- **Attempt policy**: `(experiment_id, arm, model, task_id, run_NNN)` key;
  no best-of, no cache admission, no unreported retries.
- **GT isolation**: labels never enter the sandbox; the rendered agent
  input carries only `{task_id, cve_id, repo_url, commit_sha}`.

Any other difference observed during a run is a protocol violation and is
recorded, not silently absorbed.

## 3. Failure taxonomy

Every attempt terminates in exactly one class (manifest `outcomes.classes`,
enforced by `internal/eval/agent7`):

| Class | Meaning |
|---|---|
| `OK` | execution finished, terminal answer parsed, non-uncertain category |
| `FAILED` | execution-level failure that reached the agent boundary (timeout, non-zero exit, no output) |
| `INFRA_ERROR` | harness/transport failure (docker create/cp/start, artifact export, MCP transport); **excluded from case-level denominators, reported separately** |
| `INVALID_FORMAT` | execution ok but the terminal answer fails the output contract |
| `ABSTAIN` | execution ok, parsed `uncertain` category — a safe abstention, not a failure and not a negative |
| `PROVIDER_REFUSED` | provider/safety-filter refusal, detected by text or transport signal |

Rules that are load-bearing (plan §0.5, spec §9.3):

- `FAILED`, `ABSTAIN`, `PROVIDER_REFUSED`, `INFRA_ERROR` are **never**
  merged into each other and never into a safe verdict.
- `INFRA_ERROR` does not poison a case: infra attempts drop out of the
  case denominator; a case whose every attempt is infra is reported as
  infra-only, not as a case result.
- No best-of: extra attempts beyond declared repeats and duplicate
  attempt keys are rejected, not re-bucketed.
- Repeats are declared per arm in `attempt_policy`/`arms`; 3 repeats of
  one case are attempt-level evidence, not 3 independent cases.

## 4. Improvement vs noise

An arm counts as an improvement over its comparator only when the
difference is visible in the frozen metrics **and** survives the
matched-conditions check:

- measurable gain in the blind research rubric (root-cause/mechanism
  fidelity, justified preconditions, alternative-path coverage, analyst
  effort) with **no** increase in `proposed_false_safe` and an acceptable
  cost delta;
- for the proof lane: `incremental_safe_clear > 0` against
  independently re-verified B0 with zero accepted unsafe certificates.

Not improvement: raw call counts, longer reports, confidence language,
or safe-looking conclusions produced by failed/abstained/refused attempts.
`no exploit path observed` is never a verified negative (spec §9.2).

## 5. GT handling

- GT (`ground_truth`, `ground_truth_category`, `expect[]`, the reference
  `pr_url`, in-repo `eval/ground-truth*`) is **controller-side only**.
- The rendered agent input carries exactly `{task_id, cve_id, repo_url,
  commit_sha}`; `RenderAgentInput` fails closed if a denied key is present
  in the record it is offered.
- `gt_paths_denied` in the manifest enumerates every GT location
  (in-repo + the external tasks file); A2 must enforce the same list
  inside the sandbox (see `security-boundary-check.md`).
- Smoke selection reads GT classes **host-side** to pick the 5-case set
  (2 safe, 2 exploitable, 1 forced infra failure); labels never reach the
  agent.
- The 30 Go cases are a **development/regression** set, not a blind
  holdout (spec §9.3); holdout selection follows `manifest.holdout`.
- Reference rubric material (reference answers, review notes) is built
  without arm labels and without the case-specific reference PR.

## 6. Retries and repeats

- `retries: 0` — a failed attempt is terminal for its attempt key; it is
  re-classified, never re-run in place.
- `repeats: 3` per LLM arm — declared repeats produce new attempt keys
  (`run_002`, `run_003`), never overwrite `run_001`.
- No cache admission: a cached answer may not be replayed into a new
  attempt key.
- No GT-driven retries: knowing the label may never trigger, cancel or
  replace an attempt.
- Deviation from the arm/policy repeats contract is only valid as an
  explicit `limitations` entry recorded at freeze time or by the
  operator during the run (Task-6 precedent); `Validate` flags an
  unrecorded deviation.

## 7. Per-run artifact list

Each attempt directory carries (plan §7):

- `run-manifest.json` — resolved pins for this attempt (image digest,
  model id, prompt sha256, snapshot hash, attempt key);
- `operations.jsonl` — typed candidate operations (`declare_mechanism`,
  `declare_path`, `assert_condition`, `request_check`,
  `finalize_research`, …) once A3 lands; until then the native agent tool
  calls recorded without re-sending large JSON to the model;
- `observations.jsonl` — tool outputs in the Observation contract shape
  (subject/query_scope/status/coverage/limitations/raw digest);
- redacted transcript — full raw transcript with secrets and
  credential-shaped strings stripped before commit;
- `dossier.json`, `research-report.md` — the deterministic dossier
  projection and the rendered 7-section report (spec §6);
- `proof-obligations.json`, `certificates.json`, `disposition.json` —
  proof-lane artifacts, written separately from the dossier (A6–A8);
- `tool-errors.jsonl` — tool-level failures, timeouts and denials;
- `status.json`/`disposition` outcome — the classified terminal class.

## 8. Scoring rules

- Attempt-level and case-level metrics are computed separately and
  reported side by side; denominators never mix.
- Case-level denominators exclude infra-only cases; every remaining class
  keeps its own count (`OK`, `FAILED`, `INVALID_FORMAT`, `ABSTAIN`,
  `PROVIDER_REFUSED`).
- `certified_safe` counts only PR1 offline certificates on `OK` attempts,
  intersected with the GT-safe case set.
- `incremental_safe_clear = |new certified safe − baseline certified
  safe| / #GT_safe_cases`; the baseline is **independently re-verified**
  B0 output, not old verdict labels.
- Research quality and auto-close eligibility are separate metrics;
  research usefulness never upgrades a certificate, and a certificate
  never rescues research quality.
- Zero observed false-safe is not a safety guarantee; a single accepted
  unsafe certificate or scope breach on any lane blocks auto-close and
  triggers the Checkpoint-C/§9.3 stop rule.
- Arm comparisons are scored only after the repeat-stability gate in
  §10 passes: ≥3 cases × 2 repeats on the same snapshot under the
  pinned profile with identical verdicts — a mismatch blocks scoring
  and is reported, never averaged away. No run is scored while any of
  its cases is infra or declared degraded/invalidated: exclusions go
  through `--require-complete`/`--degraded`/`--invalidated` and are
  recorded in the run manifest.

## 9. Review response (2026-10-10)

| Review item | Response |
|---|---|
| Products/advisories treated as GT | denied list covers GT *label carriers* only (`ground-truth*`, `corpus*.json`, `live-corpus.json`, `corpus-reviewed.json`, `benchmark/tasks/*.jsonl`, `freeze/gt*`); `eval/products/**` + `eval/advisories/**` stay agent-visible inputs — rationale in Threat model |
| Manifest as isolation boundary | explicit threat model: container mounts only the product snapshot; `gt_paths_denied` is the broker policy list |
| GT labels in the committed manifest | `gt_safe_case_ids`/`smoke.case_classes` removed; `Validate` flags any folded GT/reference key; GT-safe sets live controller-side (`Aggregate` takes them explicitly) |
| Deviation from plan A1 (prompt bytes/tool subset) | recorded in `limitations`; enforced by `freeze_status` + the arm-scoped gate — `CheckRunGateForArm(<arm>)` stays closed until that arm's `prompts.arm_prompts` pin, the shared pins (scorer, `run_profile`, `environment.e6` PASS, `checkpoint_0`) and its applicable sign-off are supplied; `CheckRunGate` remains the strict superset |
| Scorer versioning | `outcomes.scorer_version = "agent7-scorer/1"`; scorer bytes pinned in `controller.files_sha256` |
| Path portability | no operator-local absolute path is committed: `IZYAN_WORKTREE` falls back to the repo root in code; `VEXBENCH_*` have no committed default — `VEXBENCH_HARNESS_DIR`/`VEXBENCH_REPOS_DIR` derive only when `VEXBENCH_DURABLE_DIR` is set, and every dependent check skips explicitly when unset; `results_root` is repo-relative |
| Enum/precedence strictness | unknown execution/parse/reason are errors; case collapse is order-independent (PROVIDER_REFUSED > INVALID_FORMAT > FAILED > ABSTAIN > OK); `certified_safe` requires `certificate_source ∈ {baseline_b0, pr1}` on the matching arm — `Aggregate` keeps baseline/new certified sets separate (spec §7.4) |
| GTPathDenied glob semantics (round 3) | separators folded before clean; segment-based matcher: `**` = zero+ segments, `*` via `path.Match`, trailing bare `*` = prefix at segment boundary; invalid patterns are violations, never panics | `TestGTPathDeniedGlobSemantics` |
| path_resolution default scan (round 3) | every `default` scanned for `..` escapes, secrets, and approved-root membership; `approvedRoots` built from repo root + resolver only, never manifest defaults | `TestPathResolutionDefaultScan` |
| Map value typing (round 3) | `map_sha256`/`map_string` shape kinds validate map values at Load time — `prompts.files={"x":123}` and `spec.files_sha256={"x":"not-hex"}` are violations | `TestMapValueTypeStrict` |
| Expanded GT-free keys (round 3) | folded `prior_results`, `ground_truth_label`, `reference_pr_url`, `reference_pr`, `reference_answer`, `expected`, `expected_result`, `label`, `answer` all rejected | `TestGTFreeExpandedDeniedKeys` |
| Holdout both fields (round 3) | `CheckRunGate` requires BOTH `holdout.manifest_file` AND `holdout.manifest_sha256`; one without the other keeps the gate closed | `TestRunGateHoldoutBoth` |
| Category enum (round 3) | `Category` validated against the official 12-category set (`outcomes.official_categories` in manifest, source: `internal/eval/vexbench/score.go`); empty allowed; `garbage` → error | `TestCategoryEnumStrict` |

## 10. Run profile, degradation and reproducibility (E8)

Checkpoint-0 environment-gate item E8
(`docs/dev/decisions/agent7-checkpoint-0.md` §3): the run profile is a
protocol pin, not an operator convenience. Evidence:
`eval/agent7/proof-feasibility.md` §2 (invalidated j2/8GiB attempt) and
§7 (verdict stability).

- **Memory ceiling / parallelism pin.** Arm runs that invoke
  `izyan analyze`/`izyan eval vex-bench` run under the pinned profile
  `--mem-limit 24GiB` and `-j ≤ 3`
  (`run_profile.parallelism_upper_bound` in the manifest). The ceiling
  is **result-affecting**: the same case returned `INCONCLUSIVE` under
  `-j 2 --mem-limit 8GiB` and `EXPLOITABLE` under `--mem-limit 24GiB`
  (proof-feasibility §7), so a different ceiling is a different
  profile, not a tuning knob. A **tripping memory guard is a
  run-profile failure, never a verdict**: its signature is an instant
  `advisory error: osv get … context canceled` envelope with
  `wall_seconds ≈ 0` (the j2/8GiB attempt produced 17 of them in a
  row), corroborated by the degraded `limitations` marker. The marker
  corroborates but is not a standalone detector — the same
  `limitations` strings appear in healthy runs (proof-feasibility §5) —
  so exclusion is always an operator declaration, never an inference.
- **Degraded/invalidated declaration is mandatory.** An arm run may
  not be scored while any case is infra or degraded. The generator's
  `--require-complete` refuses final artifacts in that state, and
  `--degraded <case_id>` / `--invalidated <run_dir>` are how the
  operator declares exclusions (the j2/8GiB attempt sits in
  `invalidated_attempts`, never merged). Every exclusion is recorded in
  the run manifest — degraded and invalidated cases never enter a
  denominator silently.
- **Repeat-stability sample before scoring.** Before any arm
  comparison is scored, a repeat-stability sample of **≥3 cases × 2
  repeats** on the same snapshot under the identical pinned profile
  must produce identical verdicts. A mismatch blocks scoring for that
  comparison and is reported as a stability finding — never averaged
  away or absorbed into a repeat majority. (One case is proven stable
  across three runs; a wider sample is an open residual —
  proof-feasibility §7.)
- **Advisory reproducibility (E7/E7b).** Live OSV responses are not
  canonical: byte digests of the same advisory differ in member order
  (`ecosystem_specific.imports`) and fetches fail intermittently
  (checkpoint-0 §2.3). Matched arm comparison therefore requires either
  a frozen advisory snapshot whose canonicalised digest is pinned per
  case, or digest canonicalisation before pinning — the E7 launch
  precondition in `security-boundary-check.md` §8. govulncheck's
  vulnerability-DB fetch is a separate egress path not closed by
  `GOPROXY=off`; matched arms must run against the same frozen vulndb
  snapshot or recorded `db_info` (§8 E7b).
- **Environment gate.** Arm runs additionally require the E1–E5 strict
  evidence-tools profile and the E6/E7/E7b pre-launch verifications.
  The E6 probe report is a manifest pin (`environment.e6`) checked by
  every arm gate — `status: "PASS"` (recorded 2026-10-11, 29/29 checks)
  with the pinned path+sha256 opens it; an `ENV_FAIL` report
  (environment/VPN precondition) or a `FAIL` report (isolation
  violation) would both close it. The wider
  E1–E5/E7/E7b run-time contract is listed under `run_gate` in the
  manifest and detailed in `security-boundary-check.md` §8.

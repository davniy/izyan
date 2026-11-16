# Decision-ready (R6) measurement harness — historical

Human-work measurement + validation utilities for Amendment R6
(`docs/dev/plans/2026-10-15-01-c02-closure-capability-plan.md`), plan task 7 in
`docs/dev/plans/2026-10-15-02-decision-ready-triage-plan.md`.

**The R6 live launcher is retired.** Offline extraction, deterministic probe,
recorded replay, artifact indexing and summaries are restored. `izyan triage`
remains the only live investigator. Historical playback uses
`izyan eval research-replay`; historical artifacts never gain current authority.

Current Product B live contracts are `assessment.v3` → `decision-package.v4`,
captured finite prepared branches (0–2 questions with unknown, ≤7 mandatory
premises), append-only `environment-assertion.v1` and branch/projection-bound
`human-decision.v2` with optional comment. Answers select prepared decisions;
replay copies assertions/reviews without new Accept/timestamps. Historical
research artifacts below are not current human packages or Product A authority.
Current deterministic research `/5` publishes `finding.Project` and `requested-case.json`.
Do not infer human readiness/time or quality from preservation smoke tests.
Phase 5 modifies these preserved controllers; it does not recreate a deleted runner.
Measurement lane scoring (`triage-score.v1`) isolates Product A authority, Product B recommendation, and Automation axes independently. Review events strictly bind to canonical decision-package hashes (`triage-review-event.v1`).
Everything here consumes **sanitized artifacts and external manifests**.
Private snapshot paths, ticket ids, reviewer identities and raw corporate
records stay outside the repository — manifests reference them by absolute
path from outside the tree; committed files only ever see `case-NN`/`Cxx`
labels and `sha256:` digests.

## Files

| File | Role |
|---|---|
| `runner.py` | Offline deterministic/recorded replay orchestration, `runs.jsonl`, artifact index and summaries; no live launcher |
| `metrics.py` | Computes the human-work metric set from review events + runner outputs; exits non-zero on a stop condition |
| `events.schema.json` | `decision-ready-review-event/1` — the per-reviewer record for the blinded study |
| `regression_guard.py` | External baseline guard (verdict/coverage/`auto_close` of a persisted run) |
| `run_census.py` | Tracked current deterministic census controller; provisioned directory supplies data only |
| `test_runner.py`, `test_census.py` | Producer, identity, freshness and real fake-subprocess behavior tests |
| `test_metrics.py` | Offline unit tests: `python3 -m pytest eval/decision_ready/test_metrics.py -q` |

## Manifest schema — `decision-ready-manifest/1`

```json
{
  "schema": "decision-ready-manifest/1",
  "arm": "corporate-18 | controls | holdout",
  "cases": [
    {
      "case": "case-01",
      "cve_ids": ["GHSA-…"],
      "snapshot": {
        "root": "<external dir>",          // preferred: saved snapshot dir
        "repo": "<external git repo>",     // or materialize via git archive
        "git_ref": "6.2.0-3056",
        "git_commit": "<resolved sha>",    // verified before materializing
        "external_commit_sha": "6.2.0-3056"
      },
      "advisory_file": "eval/advisories/reviewed/<id>.json",
      "advisory": {"raw_sha256": "…"},     // verified when present
      "decision_run_dir": "<external dir>",// optional: persisted R6 run to replay
      "retained_turn_dir": "<external>",   // optional: legacy /1–/2 run (NO_REPLAY for R6)
      "expected_class": "exploitable | not_exploitable | unresolved",
      "control_role": "negative | positive | unresolved | environment_dependent",
      "research_set": {"model": "…", "provider": "custom-openai",
                       "agent_timeout_s": 900, "overall_timeout_s": 1500}
    }
  ]
}
```

Case ids must match `^[A-Za-z0-9._-]{1,64}$` — private ticket ids are rejected.

## Offline modes per case

The runner invokes no model or container. Saved reports/manifests use
`izyan eval research-replay --run <saved> --out <new>`. The archival wrapper
keeps original bytes under `original/`, with `historical_only=true` and
`current_admission=false`. No snapshot checkout is needed for playback.

| Mode | Condition | Model calls |
|---|---|---|
| `replay` | `decision_run_dir` (or retained historical directory) has report + manifest → eval research-replay | 0 issued; original turn usage remains historical metadata |
| `deterministic_only` | inputs present, no usable replay → ordinary `research` with no retired flag | 0 |
| `NOT_RUN_LIVE_PENDING_AUTHORIZATION` | historical status label: fallback disabled; live launching unavailable | — |
| `NO_SNAPSHOT` / `NO_ADVISORY` | current inputs missing → data-cap finding | — |
| `NOT_RUN` | manifest skip or dry-run | — |

Each command gets a unique attempt directory. Failed commands never contribute
report decisions or artifacts. Successful output requires report + manifest,
matching nonempty run IDs and matching requested snapshot/advisory/commit identity.
Historical `/2`–`/4` decisions and current `/5` decisions have explicit adapters;
`/5` never gains an R6 decision artifact or human readiness from extraction.

Offline invocation:

```bash
python3 eval/decision_ready/runner.py --manifest "$R6_MANIFEST" \
  --mode decision-ready --output-dir "$TMPDIR/r6-arm"
```

A saved `/3` or `/4` run can still be re-checked offline:

```bash
python3 eval/decision_ready/regression_guard.py --run-dir <persisted run dir> \
  --case-label case-01 [--expect-verdict NOT_AFFECTED] [--expect-coverage COMPLETE]
```

## Tracked census (outside public OSS CI)

```bash
python3 eval/decision_ready/run_census.py --corpus "$CENSUS_CORPUS" \
  --output-dir "$TMPDIR/census-attempts" --izyan-bin "$IZYAN_BIN" \
  --comparison-pointer "$TMPDIR/census-current-path.txt" --jobs 1
```

The input directory contains immutable `r6-corporate-baseline.json` (`rows`,
each with sanitized `case`, `baseline_dir`, `verdict`, `coverage`) and retained
manifests/material inputs. Requested advisory identity is preserved rather than
replaced by its resolved alias. Baselines, labels and saved artifact bytes are
never rewritten. Exit **0** means unchanged, **1** means label drift, **2** means
technical/input failure. A failed invocation removes the comparison pointer;
existing reports are retained but cannot be selected as fresh output.

Retained snapshot content hash and raw/canonical advisory digests are compared
against current materials even when their paths are unchanged. Recorded effective
GOOS/GOARCH/tags (one repeated `--build-tags` argument per value) and analysis
toolchain travel into the new invocation; a toolchain
fallback or mismatch is a technical failure, not a comparable result. Only absent
optional external-commit encodings (`null` versus empty) normalize together; a
nonempty identity mismatch still fails. The current guard rechecks retained pins.

An external private evaluation environment may invoke this tracked controller,
stop on technical failure before running the guard, and pass only the fresh
comparison to:

```bash
python3 eval/decision_ready/regression_guard.py \
  --baseline-manifest "$CENSUS_BASELINE" \
  --census-inputs "$CENSUS_CORPUS/r6-corporate-baseline.json" \
  --current-comparison "$(cat "$TMPDIR/census-current-path.txt")"
```

The guard preserves the measured 18-case baseline/count and false-safe gates,
then checks the complete current invocation, bound output directories, inputs,
run IDs, evidence references and `auto_close=false`. The historical four
S-05 drift exceptions (`case-03`, `case-04`, `case-09`, `case-10`) apply only
to external census evaluation after safety passes, never to public CI.
Historical `/4` support is newly explicit: the previous guard accepted only
`/2` and `/3`, not `/4`.

Focused checks (synthetic/fake subprocess only):

```bash
python3 -m pytest eval/decision_ready/test_metrics.py eval/decision_ready/test_runner.py eval/decision_ready/test_census.py -q
```


## Case classification (summary.json `by_category`)

`terminal_deterministic_verified_negative` (decision projection is a verified
`NOT_AFFECTED`/`NO_EXPLOIT_PATH_FOUND` with `COMPLETE` coverage),
`decision_ready_code_grounded` (`CLOSE_*` proposals from the flow),
`environmental_mitigation_branch` (`ACCEPT_ENVIRONMENTAL_MITIGATION`),
`HOLD_UNKNOWN`, `KEEP_OPEN_FOR_REMEDIATION`, `NOT_DECISION_READY`
(unclassifiable artifact state), `data_cap` (`NO_SNAPSHOT`/`NO_ADVISORY`),
`error`/`invalid_format`, `not_run`. `no_replay_cases` is reported separately.

`false_safe` is **zero-tolerance**: any accepted-safe proposal
(`CLOSE_*` or `ACCEPT_ENVIRONMENTAL_MITIGATION`) on a case declared
`expected_class=exploitable` sets the case's `false_safe` flag and the
summary's `stop=true` — runner exits 2.

## Review events — `decision-ready-review-event/1`

One JSON record per reviewer per artifact (schema in `events.schema.json`).
Events join the artifact index by `artifact_digest` = sha256 of the emitted
`decision-artifact.json`. Optional `initial_branch_id`/`selected_branch_id`
feed the branch-change-after-answer rate; `reviewer_session` is a pseudonym,
never an identity.

## Metrics (metrics.py)

```bash
python3 eval/decision_ready/metrics.py \
  --events events.jsonl \
  --artifact-index "$OUT/artifact-index.json" \
  --case-records "$OUT/runs.jsonl" \
  --out metrics.json
```

Computes: `human_decision_time` median/P75/P95 overall and by disposition,
branch count and class; `facts_read` percentiles; `repo_open_rate` (decision-ready
artifacts with `repository_open_count>0` / all decision-ready artifacts reviewed)
plus the accepted-only rate; `missing_fact_rejection_rate` (rejects among events
that left a declared mandatory fact unread) and accepted-with-unread-facts
violations; environment question/answer/unknown counts and the
branch-change-after-answer rate (a change on a *code-grounded* artifact is a
stop condition — an environment answer must never rewrite code-grounded
applicability); accepted false-safe count/rate split `code_grounded` vs
`environmental_mitigation` (never merged); reopen/reversal, remediation-return,
human rerun and follow-up rates; model calls/turns/tokens/provider-reported
cost/elapsed per case from `run-manifest.json` turns + retained `result.json`
usage (replays and deterministic runs must record **0** model calls — any
nonzero count there is a recorded violation).

Human contract targets: `repo_open_rate_accepted = 0`, no accepted artifact
with unread mandatory facts or technical follow-ups, `[INFERENCE]` median ≤5 min,
`[INFERENCE]` P95 ≤10 min. A `null` means *not measured*, never zero.

## Blinded acceptance study (owner-run)

Protocol for the study arm (not automated): randomize artifacts from the
decision-ready and control arms; blind reviewers to arm, ground truth, prior
disposition and model status; ≥2 independent reviewers per artifact; only the
declared environment answers plus Accept/Reject; record one event per review
per the schema. Any repository open, tool rerun or technical follow-up on an
accepted decision-ready artifact is a contract failure.

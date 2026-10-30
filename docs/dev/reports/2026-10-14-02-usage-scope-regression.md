# Usage-scope saved-data regression — B41 replay parity + measured census

**Status: EXECUTED — the full 60-case census ran end-to-end; all results
below are measured from the recorded run, not predicted. Machine report:
`<VA_TMP>/b41-replay-report.json`.**

Date: 2026-10-14. Scope: Task 5 of
`docs/dev/plans/2026-10-14-02-usage-scope-plan.md`.

Driver: `tools/evidence-levels-replay.py` (extended during this task;
see `.superpowers/sdd/2026-10-14-02-usage-scope-plan/task-5-report.md`).

Runner: `izyan` built from the uncommitted post-review-fix tree, invoked
with `GOPROXY=off`, `GOSUMDB=off`, `GOFLAGS=-mod=readonly` against the
frozen `<VA_TMP>/govulndb`. **No model was called and no live harness ran:**
every case replays the persisted agent turn via `--replay-agent-turn`;
`run.harness` stays null in every rebuilt report (asserted per case).
`/1` and `/2` consumers are untouched: every rebuilt report self-validated
before exit (the CLI runs `research.Validate` before exiting 0 —
fail-closed), `contract_extensions` still carries exactly the expected
`slice2-fidelity/3` marker, and the driver asserts the schema/mode identity
byte-equal to the baseline.

## Sets and method

| set | n | input (replay source) | BEFORE document | AFTER output |
|---|---|---|---|---|
| primary | 31 | `<VA_TMP>/exploitable/runs/<case>/agent` | `agent-v4` sibling (post-B42 rebuild) | `agent-v5` sibling |
| retry | 6 | `<VA_TMP>/exploitable-retry/runs/<case>/agent` | `agent-v4` sibling | `agent-v5` sibling |
| retry-invalid | 5 | `<VA_TMP>/exploitable-retry-invalid/runs/<case>/agent` | `agent-v4` sibling | `agent-v5` sibling |
| specialist | 18 | `<VA_TMP>/agent7-corp/runs/<case>/agent` | the saved input report itself (historical) | `agent-v5` sibling |

For the specialist set there is no pre-existing baseline sibling, so the
BEFORE row is the saved historical report; only the preservation slice
(schema/mode/input/vulnerability identity, agent_output, disposition,
the persisted agent attempt row, and affected-implementation identity)
is asserted byte-equal. Derived members legitimately differ between the
historical contract and the current one and are reported as measured
changes, never as parity violations.

### Baseline enforcement (executed, before any replay)

The recorded `agent-v4` matrix was loaded and matched BEFORE a single
rebuild ran; a mismatch aborts the run. Both runs printed
`baseline census matches the recorded matrices for agent-v4/agent-v4`:

| set | recorded `agent-v4` levels | enforced | result |
|---|---|---|---|
| primary | 0 L1 / 31 L2 / 0 L3 | exact | MATCH |
| retry (6+5) | 0 L1 / 11 L2 / 0 L3 | exact | MATCH |

`baseline_failures` and `input_integrity_failures` are both empty in the
run report: every saved input dir was sha256-hashed before and after and
no byte changed. Saved `agent`/`agent-v3`/`agent-v4` trees,
`report.json`, `observations.jsonl` and artifact bytes were never
rewritten; the driver only adds the new `agent-v5` sibling.

### Id-neutral comparison

B41 inserts `usage-scope` observations mid-ledger, so all later
`OBS-NNNN` ids shift; the comparison normalizes every obs/fact-id token
to a stable `tool#ordinal` key (from each run's own
`observations.jsonl`) and masks byte fields that embed the renumbered id
(`artifact.sha256/size_bytes`, `materiality.raw_bytes.*`,
`reproducible_source.output_sha256`, `data_digest`). The check itself
stays pinned by `input_digest`/`command`/`statement`. Allowed diffs are
the B41 surface only: new usage-scope observations/artifacts, new
`BUILD_USAGE_SCOPE` facts, the `exploitation_axes.build_usage_scope`
axis, and B41 unknown/open-question rows.

## Measured census

### Levels (`evidence_level.level`)

| set | before | after | moved |
|---|---|---|---|
| primary | 31 × L2_POTENTIAL_PATH | 31 × L2_POTENTIAL_PATH | **0** |
| retry + retry-invalid | 11 × L2_POTENTIAL_PATH | 11 × L2_POTENTIAL_PATH | **0** |
| specialist (historical before) | 18 × none (historical doc predates derived levels) | 18 × L2_POTENTIAL_PATH | 18 — contract-era recomputation, not a B41 delta |

`evidence_level` JSON is byte-identical between the baseline and the
rebuild in **all 42 primary/retry cases** (the projection includes it and
no `evidence_level` violation was emitted). For the specialist set the
`none → L2_POTENTIAL_PATH` movement is the expected effect of rebuilding a
pre-B42 saved document under the current contract; the level assertion
compares only on the preservation slice there.

### B42 path conditions (aggregate per-case states)

| set | subject | before | after |
|---|---|---|---|
| primary | reachable | 7 SUPPORTED / 24 UNKNOWN | **identical** |
| primary | build-relevant | 7 SUPPORTED / 24 UNKNOWN | **identical** |
| primary | used by product code | 7 REFUTED / 24 ABSENT | **identical** |
| retry | reachable | 2 SUPPORTED / 9 UNKNOWN | **identical** |
| retry | build-relevant | 2 SUPPORTED / 9 UNKNOWN | **identical** |
| retry | used by product code | 2 REFUTED / 9 ABSENT | **identical** |
| specialist | reachable | 7 REFUTED / 11 UNKNOWN | 1 REFUTED / 17 UNKNOWN |
| specialist | build-relevant | 7 REFUTED / 11 UNKNOWN | 1 REFUTED / 17 UNKNOWN |
| specialist | used by product code | 18 ABSENT | 8 UNKNOWN / 10 ABSENT |

Specialist reach/build/usage states are derived members of a historical
document; the measured REFUTED→UNKNOWN relaxation on 6 cases and the
appearance of 8 UNKNOWN usage conditions reflect the current
condition model recomputing what the saved document predates. This is
the documented historical-comparison limitation, not a B41 regression —
the preservation slice held on all 18.

### B41 usage-scope census (after only — `usage_scope` was absent everywhere before)

| set | cases w/ facts | facts | product | test-only | mixed | unknown | complete facts | incomplete observations | product-absence VERIFIED | axis |
|---|---|---|---|---|---|---|---|---|---|---|
| primary | 31/31 | 35 | 0 | 0 | 33 | 2 | 35 | 0 | 0 | 30 ESTABLISHED / 1 UNKNOWN |
| retry + retry-invalid | 11/11 | 14 | 0 | 0 | 12 | 2 | 14 | 0 | 0 | 10 ESTABLISHED / 1 UNKNOWN |
| specialist | 1/18 | 1 | 0 | 0 | 1 | 0 | 1 | 21 | 0 | 1 ESTABLISHED / 17 ABSENT |

Every emitted `BUILD_USAGE_SCOPE` fact has `coverage=COMPLETE` and a
closed `usage_scope` class. The 2+2 `unknown` facts are C03 in each set
(target absent from both complete closures → per the contract the result
is `unknown`, not `test-only`); the axis there is correctly `UNKNOWN`.
The specialist set produced 21 `usage-scope` observations with
`completeness=UNKNOWN`/`tool_status=ERROR` — `go list -deps` fails
offline (`GOPROXY=off` module lookup or `-mod=readonly` go.mod updates)
on those snapshots — and per contract an ERROR/UNKNOWN observation emits
no fact and never evidences `test-only`; the lone COMPLETE observation
(specialist C13) yielded the single `mixed` fact and the only
ESTABLISHED axis. Zero `test-only` results were produced anywhere —
honest measurement: the recorded corpora contain no paired-closure
test-only case.

## Per-case outcomes

Primary (31): all `L2 → L2`, `disposition=REVIEW_REQUIRED` /
`auto_close=false` before and after. `scope` = `usage_scope` classes of
the emitted facts; `f` = fact count; axis shown after.

| case | status | reach → | build → | usage → | scope after | f | axis after |
|---|---|---|---|---|---|---|---|
| C01 | PASS | S→S | S→S | R→R | [mixed, mixed] | 2 | ESTABLISHED |
| C02 | PASS | U→U | U→U | A→A | [mixed] | 1 | ESTABLISHED |
| C03 | PASS | S→S | S→S | R→R | [unknown, unknown, mixed] | 3 | UNKNOWN |
| C04 | PASS | U→U | U→U | A→A | [mixed] | 1 | ESTABLISHED |
| C05 | PASS | U→U | U→U | A→A | [mixed] | 1 | ESTABLISHED |
| C06 | PASS | U→U | U→U | A→A | [mixed] | 1 | ESTABLISHED |
| C07 | PASS | S→S | S→S | R→R | [mixed, mixed] | 2 | ESTABLISHED |
| C08 | PASS | U→U | U→U | A→A | [mixed] | 1 | ESTABLISHED |
| C09 | PASS | U→U | U→U | A→A | [mixed] | 1 | ESTABLISHED |
| C10 | PASS | U→U | U→U | A→A | [mixed] | 1 | ESTABLISHED |
| C11 | PASS | U→U | U→U | A→A | [mixed] | 1 | ESTABLISHED |
| C12 | PASS | U→U | U→U | A→A | [mixed] | 1 | ESTABLISHED |
| C13 | PASS | U→U | U→U | A→A | [mixed] | 1 | ESTABLISHED |
| C14 | PASS* | S→S | S→S | R→R | [mixed] | 1 | ESTABLISHED |
| C15 | PASS* | S→S | S→S | R→R | [mixed] | 1 | ESTABLISHED |
| C16 | PASS | S→S | S→S | R→R | [mixed] | 1 | ESTABLISHED |
| C17 | PASS* | S→S | S→S | R→R | [mixed] | 1 | ESTABLISHED |
| C18–C31 | PASS | U→U | U→U | A→A | [mixed] | 1 | ESTABLISHED |

Retry (6): C01 [mixed,mixed] f2, C02 [mixed] f1, C03 [unknown,unknown,mixed] f3 axis UNKNOWN, C04–C06 [mixed] f1 — all PASS, states identical to primary rows above (C01/C03 S/S/R; C02/C04–C06 U/U/A).

Retry-invalid (5): C08, C19, C25, C26, C27 — all PASS, U→U/U→U/A→A, [mixed] f1, ESTABLISHED.

`*` = flagged FAIL by the first recorded run's driver projection;
**resolved as over-strict projection over pre-existing tool
nondeterminism — see the failure analysis below**. The measured census
values in this table are unaffected by the flag.

Specialist (18, historical before): all 18 PASS on the preservation
slice; levels recomputed `none → L2`; measured per-case movements:

| case | reach → | build → | usage → | scope after |
|---|---|---|---|---|
| C01, C02, C05, C15–C18 | U→U | U→U | A→A | ABSENT |
| C03, C04 | R→U | R→U | A→A | ABSENT |
| C06 | R→R | R→R | A→A | ABSENT |
| C07–C10 | U→U | U→U | A→U | ABSENT |
| C11, C12 | R→U | R→U | A→U | ABSENT |
| C13 | R→U | R→U | A→U | [mixed] f1, axis ESTABLISHED |
| C14 | R→U | R→U | A→U | ABSENT |

## Movement summary

Zero primary/retry cases changed level, reach, build or usage state.
What moved is exactly the B41 surface: `usage_scope` went ABSENT →
`[mixed]` (28 primary cases; 33 mixed + 2 unknown facts total), the
`build_usage_scope` axis appeared (ESTABLISHED where every class is
known, UNKNOWN for C03's unresolved class), and obs ids renumbered. On
the specialist set, the derived members recomputed from a historical
document moved as expected (levels and condition states), while the
preserved identity slice is byte-equal on all 18.

## The three flagged primary failures — diagnosed

The first recorded run flagged C14 (`verified_facts` +
`product_exposure`), C15 and C17 (`verified_facts`). Full projection
diff shows every retained fact is identical except two statement-text
members:

| case | member | baseline (`agent-v4`) | rebuild (`agent-v5`) |
|---|---|---|---|
| C14 | `verified_facts[*].statement` (find_may_callers, ssh.NewControlClientConn) | `559 may-call site(s) … (559 with unproven targets)` | `258 may-call site(s) … (258 with unproven targets)` |
| C14 | `product_exposure.claims[11].statement` | same `559 …` text | same `258 …` text |
| C14 | `verified_facts[*].statement` (trace_argument) | `origins: [CONSTANT UNKNOWN]` | `origins: [UNKNOWN CONSTANT]` |
| C15 | `verified_facts[*].statement` (trace_argument) | `origins: [CONSTANT UNKNOWN]` | `origins: [UNKNOWN CONSTANT]` |
| C17 | `verified_facts[*].statement` (trace_argument) | `origins: [UNKNOWN CONSTANT]` | `origins: [CONSTANT UNKNOWN]` |

**This is not a B41 semantic change — it is pre-existing tool
nondeterminism, same class as the recorded ingress-inventory case.**

Evidence, all measured at constant code on the same input:

- `find_may_callers` count for one subject across replays of the same
  saved turn: `110` (agent-v2, agent-v3), `559` (agent-v4), `258`
  (agent-v5), **`559` again on a second B41 replay run after the first
  drew `258`** — and on C15, v4 and the census v5 both drew `258` while a
  fresh rerun drew `559`. Retained dependency-extras packages churn in
  load order (Go map iteration), so the may-call set inside the loaded
  scope legitimately varies; the fact's completeness/limitations and the
  pinned subject are unchanged.
- `trace_argument` `origins: [...]` is a set enumeration whose order
  flips between identical replays: C17 drew `[UNKNOWN CONSTANT]` already
  in `agent-v4` vs `[CONSTANT UNKNOWN]` in v2/v3 — the flip predates B41
  (v4 is a post-B42, pre-B41 build). Same-token set in every run.
- Ingress-inventory (already recorded): `4856 / 4921 / 4940 / 4907`
  inventoried items for one case across replays at constant code;
  blockers stable.

`product_exposure` on C14 changed only because claim 11 mirrors the
may-call statement text verbatim — same root cause, no separate drift.

**Fix applied (projection, not expectations):** `semantic_projection`
now masks the two counts inside `N may-call site(s) … (N with unproven
targets)` and sorts the `origins: [...]` token list before comparing —
mirroring the existing ingress-items mask. The pinned subject path,
command, limitations, completeness and the origin SET stay asserted.
Verified offline: after the fix, the recorded `agent-v4`→`agent-v5`
projections of C14/C15/C17 compare clean, and a constant-code rerun of
all three cases passes the driver end-to-end. No expectation was
adjusted; no real non-B41 change was hidden.

## Pre-existing nondeterminism (tool-level, predates B41)

Three sites observed, all caused by map-iteration-order consumption of a
shared evaluation budget / retained-extras set:

1. `ingress-inventory` item count (recorded earlier: 4856/4921/4940/4907;
   blockers 337, `complete=false` stable).
2. `find_may_callers` site count inside the loaded scope (110/258/559 for
   one subject across five replays).
3. `trace_argument` `origins` enumeration order.

These deserve a separate backlog item (deterministic ordering/budget
accounting); the driver now normalizes only the volatile number/order
inside each statement template — blocker counts, completeness, subjects
and set contents stay asserted.

## Repeated replay

A second full census (fresh `--work-dir`, identical inputs, fixed
driver) ran end-to-end: **60/60 PASS, wall 815.4 s**. Comparing the two
run reports modulo wall-clock and scratch-dir fields, every measured
member is identical — per-case levels, all three condition states,
usage_scope class lists, fact counts, axis statuses, completeness
counts, dispositions, and both set-level censuses; `baseline_failures`
and `input_integrity_failures` stayed empty in both. The only
difference between the two report documents is the `status`/`violations`
pair on C14/C15/C17 — run 1 recorded the pre-fix projection flags while
run 2 ran the fixed projection; the flakiness itself never recurred in
the compared fields because it lives only in masked statement text.
Repeated replay of the measured census is stable.

## Unchanged-field assertions (all PASS on every rebuilt report)

- `schema=research-report/1`, `mode`, `input`, `vulnerability`,
  `affected_implementations`, `product_applicability`, `agent_output`
  (minus replayed_from provenance), persisted agent attempt row,
  `exploitation_conditions`, all non-B41 `verified_facts` (modulo the
  documented volatile members), all pre-existing exploitation axes,
  `evidence_level`, `disposition`, classification review and non-B41
  unknown/question rows — byte-equal in the normalized projection for
  every primary/retry case, and on the preservation slice for every
  specialist case.
- `disposition.class=REVIEW_REQUIRED`, `auto_close=false` — 60/60.
- Saved agent status, extraction status and every artifact pin
  (path/sha256/size_bytes/selector) preserved; pinned bytes re-hashed
  against the recorded sha256 — all match.
- No agent ref enters verified facts, the B41 axis or level evidence;
  no B41 fact is cited by a condition, `evidence_level` or
  `product_applicability`; `vulnerable_code_reachability=FALSE` never
  coexists with a test-only class (none existed anyway).
- Input integrity: sha256 of every saved input dir identical before and
  after; `baseline_failures` and `input_integrity_failures` empty.
- B42 parity: usage-condition subjects equal the advisory-declared
  candidates exactly; module-only advisories gained no package usage
  condition or fact; a REFUTED usage aggregate never produced L1.

## Wall clock

Recorded run: `total_wall_s=866.3` with `--jobs 6`; per-case min 11.5 s,
median 57.4 s, max 212.0 s (serial estimate ≈ 65 min stands).

## Reproducer

```bash
cd <VA_REPO> && go build -o "$WORK/izyan" ./cmd/izyan
GOPROXY=off GOSUMDB=off GOFLAGS=-mod=readonly python3 tools/evidence-levels-replay.py \
  --primary-root <VA_TMP>/exploitable/runs \
  --primary-input-suffix agent --primary-baseline-suffix agent-v4 \
  --retry-glob '<VA_TMP>/exploitable-retry/runs' \
  --retry-glob '<VA_TMP>/exploitable-retry-invalid/runs' \
  --retry-input-suffix agent --retry-baseline-suffix agent-v4 \
  --specialist-root <VA_TMP>/agent7-corp/runs \
  --specialist-input-suffix agent \
  --specialist-label-map .superpowers/sdd/2026-10-14-02-usage-scope-plan/specialist-labels.json \
  --specialist-historical-before \
  --label-map .superpowers/sdd/2026-10-13-01-shadow-usability-plan/ticket-labels.json \
  --izyan "$WORK/izyan" --govulndb <VA_TMP>/govulndb \
  --b41-out-suffix agent-v5 --jobs 6 \
  --report <VA_TMP>/b41-replay-report.json
```

## Privacy

Only `C01`–`C31` labels appear here; unit identifiers, snapshot
basenames, provider details and absolute machine paths are scrubbed by
the driver (`<VA_TMP>`, `<PATH>`, `<snap>`).

## False-safe gate (saved data)

Гейт выполнен на сохранённых agent turns через replay, без model runs и live harness.
Проверки safety surface прошли **60/60 PASS**, `false-safe=0`: ни один rebuilt report
не выдал `NOT_AFFECTED` или `NO_EXPLOIT_PATH_FOUND` как следствие B41; `VEX` и auto-close
не появились; `vulnerable_code_reachability=FALSE` не сосуществовал с B41 test-only
(test-only фактов не было); `NON_APPLICABLE+SUPPORTED` через B41 не возник.
Во всех 60/60 сохранены `disposition.class=REVIEW_REQUIRED` и `disposition.auto_close=false`.
Ни одна `test-only`/product-absence ветвь не была измерена на этом корпусе: observed
counts — `test-only=0`, `ProductAbsenceVerification=0`, `VEX=0`, auto-close=true `=0`,
`vulnerable_code_reachability=FALSE` from B41 `=0`, `NON_APPLICABLE+SUPPORTED` from B41 `=0`.
Это safety gate для сохранённых данных, а не утверждение полноты B41.

Общий gate `go run ./cmd/izyan eval --corpus eval/corpus-real.json -j 4` завершён: `cases=38 errors=0 expect pass=38 fail=0 claims-fail=0 false-safe=0 inconclusive=2`; signal-cleared `9/27` (auto `7`, expert `2`), reachable-cleared `6/22`, package-level-cleared `3/5`. Это отдельный corpus gate; B41 saved-data gate выше не трактуется как доказательство полноты B41.

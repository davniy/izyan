# Package-level-facts saved-data regression — B42 replay parity + measurement

Date: 2026-10-14. Scope: Task 6 of `docs/dev/plans/2026-10-14-01-package-level-facts-plan.md`
(the plan's own report filename differs; this report uses the name fixed by the task
assignment).
Driver: `tools/evidence-levels-replay.py` (extended). Runner: `izyan` built from the
uncommitted post-review-fix tree (Tasks 1–5 + wave-A/B fixes).
**No model runs and no live harness calls**: every case replays the persisted agent turn
via `--replay-agent-turn` with `GOPROXY=off`, `GOSUMDB=off`, `GOFLAGS=-mod=readonly`;
`run.harness` stays all-null in every rebuilt report (asserted per case).

## Result: measured before/after — every package-declaring case demoted L1 → L2

| set | n | recorded pre-B42 baseline | measured BEFORE (agent-v3) | measured AFTER (agent-v4) |
|---|---|---|---|---|
| primary | 31 | 7 L1 / 24 L2 / 0 L3 | **7 L1 / 24 L2 / 0 L3** — match | **0 L1 / 31 L2 / 0 L3** |
| retry aggregate (6 + 5) | 11 | 2 L1 / 9 L2 / 0 L3 | **2 L1 / 9 L2 / 0 L3** — match | **0 L1 / 11 L2 / 0 L3** |

The baseline census is enforced before a single replay runs; it matched the recorded
pre-B42 matrix exactly, so the input set is unchanged. The after-census above is
**measured**, not asserted. All 42 cases ran and PASSed every parity assertion; zero
NOT_RUN, zero FAIL.

### Why cases moved

Every movement is the new required path condition `affected package/symbol used by
product code`. `affected package reachable` and `affected package build-relevant` did
not change state anywhere (7 SUPPORTED / 24 UNKNOWN primary, 2 SUPPORTED / 9 UNKNOWN
retry — identical before and after).

- 9 runs (7 distinct primary units + the same 2 units' retry copies) declare
  package/symbol candidates. For every one of them the bounded package-usage scan
  **VERIFIED at least one declared candidate as NOT_USED under a COMPLETE recorded
  scope**, so its condition became `REFUTED`. The case-level rule (any REFUTED
  candidate ⇒ REFUTED) then holds for all 9; a REFUTED required path condition blocks
  L1 by contract, so each previously-L1 case moved to L2. This is the negative branch,
  and it is review-safe, not a safe conclusion: every REFUTED condition carries the
  bounded-scope limitations, `vulnerable_code_reachability` never became `FALSE`, and
  disposition stays `REVIEW_REQUIRED`/`auto_close=false`.
- 33 runs are module-only advisories (no declared package or symbol): no package-usage
  condition, observation or fact was emitted for them — the subject stays `ABSENT` and
  the module path was never substituted for a package (subject-parity asserted: the
  usage conditions cover exactly the advisory-declared candidate set). Their
  `reachable`/`build-relevant` UNKNOWN conditions still block L1, so all 33 stay L2.
- No case moved L2 → L1: no candidate-bearing case reached the positive branch
  (every one carries at least one verified REFUTED candidate), and no module-only case
  resolved its package presence.

### Usage-condition aggregate states (after)

| set | SUPPORTED | REFUTED | UNKNOWN | ABSENT |
|---|---|---|---|---|
| primary (31) | 0 | 7 | 0 | 24 |
| retry (11) | 0 | 2 | 0 | 9 |

Per-candidate detail: the 9 candidate-bearing reports contain 127 usage conditions —
**15 SUPPORTED** (a USED verdict citing an OK `PACKAGE_USAGE` fact whose `usage_subject`
matches the condition's), **91 REFUTED** (VERIFIED `NOT_USED` under COMPLETE scope) and
**21 UNKNOWN** (e.g. the package-level `golang.org/x/net/http2` subject in C01 stays
`INSUFFICIENT_SCOPE`; unclosed scope is never a verdict). Promoted facts: 91
`PACKAGE_USAGE` claim=FALSE + 15 claim=TRUE, plus 6 `PACKAGE_USAGE_LOWER_BOUND`
claim=TRUE/PARTIAL rows for undetermined checks that still recorded positive content —
the lower-bound kind is never a carrier and never closes a condition.

### `package-usage` observation states (after, all sets)

| tool_status | completeness | verdict | negative_verification | count |
|---|---|---|---|---|
| OK | COMPLETE | NOT_USED | VERIFIED | 91 |
| OK | PARTIAL | USED | — | 15 |
| OK | UNKNOWN | UNKNOWN | INSUFFICIENT_SCOPE | 21 |

Before: 0 observations (the check did not exist pre-B42).

## Per-case outcomes (labels only)

`r` = `affected package reachable`, `b` = `affected package build-relevant`,
`u` = `affected package/symbol used by product code` aggregate.
Before → after; `—` = unchanged L2 with usage ABSENT and no candidates.

| case | primary | retry | retry-invalid | usage conditions (S/R/U) | moved |
|---|---|---|---|---|---|
| C01 | L1→L2, r S→S, b S→S, u A→**REFUTED** | L1→L2 (same) | — | 1/34/2 | REFUTED usage blocks L1 |
| C02 | L2→L2, u A→ABSENT | L2→L2 (same) | — | — | — |
| C03 | L1→L2, r S→S, b S→S, u A→**REFUTED** | L1→L2 (same) | — | 2/2/6 | REFUTED usage blocks L1 |
| C04 | L2→L2 | L2→L2 | — | — | — |
| C05 | L2→L2 | L2→L2 | — | — | — |
| C06 | L2→L2 | L2→L2 | — | — | — |
| C07 | L1→L2, r S→S, b S→S, u A→**REFUTED** | — | — | 1/1/3 | REFUTED usage blocks L1 |
| C08 | L2→L2 | — | L2→L2 | — | — |
| C09–C13 | L2→L2 | — | — | — | — |
| C14 | L1→L2, r S→S, b S→S, u A→**REFUTED** | — | — | 2/3/1 | REFUTED usage blocks L1 |
| C15 | L1→L2, r S→S, b S→S, u A→**REFUTED** | — | — | 2/5/1 | REFUTED usage blocks L1 |
| C16 | L1→L2, r S→S, b S→S, u A→**REFUTED** | — | — | 2/4/0 | REFUTED usage blocks L1 |
| C17 | L1→L2, r S→S, b S→S, u A→**REFUTED** | — | — | 2/6/0 | REFUTED usage blocks L1 |
| C18 | L2→L2 | — | — | — | — |
| C19 | L2→L2 | — | L2→L2 | — | — |
| C20–C24 | L2→L2 | — | — | — | — |
| C25–C27 | L2→L2 | — | L2→L2 (each) | — | — |
| C28–C31 | L2→L2 | — | — | — | — |

9 runs moved (all L1→L2 via the REFUTED usage aggregate); 33 unchanged.
`S/R/U` = per-candidate SUPPORTED/REFUTED/UNKNOWN usage-condition counts.

## Parity, invariants and integrity — all verified, no violations

- **Semantic projection identical**: advisory/vulnerability identity,
  `affected_implementations`, snapshot/build identity (`input`), `module_present`,
  `version_affected`, `selected_modules`/`pending_modules`/`unresolved_modules`,
  `advisory_entry_status`, `agent_output`, agent attempt rows, the
  `exploitation_established` axis, `disposition` and `classification_review.
  original_category` are byte-identical between baseline `agent-v3` and rebuilt
  `agent-v4` for all 42 cases. No unrelated case changed.
- **Statuses preserved**: `agent_output.status` (31 OK / 6 FAILED / 5 INVALID_FORMAT
  across all sets) and extraction status (31 VALID / 11 INVALID) are verbatim;
  `agent_output.category` unchanged.
- **Artifact pins preserved**: every recorded pin (`answer_artifact`, `raw_artifact`,
  `result_artifact`, `extraction.answer_artifact`, agent-attempt artifacts —
  path/sha256/size_bytes/selector) matches the saved record, and the pinned bytes under
  each `agent/` input still hash to the recorded sha256. `agent_output.replayed_from.dir`
  names the saved input dir on all 42 rebuilds.
- **Saved inputs byte-identical**: every `…/<UNIT>/agent` input dir was sha256-hashed
  (full tree) before and after the run; zero changes. The `agent-v3` baseline siblings
  were never written — output went to new `agent-v4` siblings.
- **Contract shape**: `contract_extensions` = `[slice2-fidelity/3]` exclusively;
  `evidence_level` present with closed-enum level/basis and re-derived by the CLI's
  emit-time `Validate` (rc=0, fail-closed); `disposition.class=REVIEW_REQUIRED`,
  `auto_close=false` everywhere; `run.harness` all-null (no model call);
  `evidence_level.evidence_refs` carries no agent material anywhere; no
  ESTABLISHED/L3 without a saved dynamic-carrier fact (none exists).
- **Branch invariants**: no REFUTED case is L1 or left `REVIEW_REQUIRED`; every
  SUPPORTED usage condition cites an OK `PACKAGE_USAGE` fact with a matching
  `usage_subject`; every module-only case stayed candidate-free (no guessed package
  paths); usage-condition origins are `deterministic` only.
- **Determinism**: the full 42-case replay was run twice (second pass into a fresh
  `--work-dir`); the two machine reports are identical after removing only wall-clock
  fields, and condition sets, `evidence_level`, `disposition` and
  `product_applicability` are byte-equal across passes (runtime fields — provenance
  timestamps, tool-execution logs, artifact paths of the rebuilt run — legitimately
  differ; the brief's stability criterion targets condition state, evidence-level JSON
  and the census, which are identical).

## /1 and /2 compatibility

- `TestSlice2_LegacyReportStillValidates` keeps the committed `/1` + `/2` fixtures
  valid; `TestReplayEvidenceLevel_LegacyMarkersUnchanged` still accepts `/1`/`/2`
  replay inputs on the legacy path — both PASS under `go test -count=1 ./...`.
- New focused coverage (`internal/research/replay_test.go`):
  `TestReplayPackageUsage_SupportedClosesPath`,
  `TestReplayPackageUsage_RefutedStaysReviewable`,
  `TestReplayPackageUsage_LowerBoundNeverCloses`,
  `TestReplayPackageUsage_TamperedSubjectAborts` (persisted subject tamper aborts the
  /3 input gate), `TestReplayPackageUsage_ModuleOnlyStaysAbsent` — all PASS, plus
  `TestReplay.*Artifact|TestReplay.*Status` and `TestReplayEvidenceLevel|TestReplayLoad`
  unchanged and green.

## Wall time

- Run 1 (sibling `agent-v4` output): **460.8 s ≈ 7.7 min** total at `--jobs 6`;
  per case min 24.0 s, median 34.7 s, max 252.3 s; sum of case times 2564 s
  (~43 min serial equivalent — the added `package-usage` checks roughly halved the
  per-case time vs the pre-B42 lane's 1 m budget because the real checks complete
  inside the 20 m budget).
- Run 2 (scratch `--work-dir`, determinism pass): 413.2 s; identical census.

## NOT_RUN / caveats

- No case was NOT_RUN. `tmp/exploitable-retry-invalid-dockerfail{,2}` remain outside
  the task's retry scope (6 + 5); the driver takes an explicit `--retry-glob` per set.
- The deterministic attempt row's `result_artifact` (`deterministic-facts.json`) is
  legitimately re-emitted each run and is excluded from pin preservation and from the
  semantic projection; only agent-attempt pins are asserted verbatim.
- The after-census differs from the recorded baseline **only** by the B42 feature's
  own semantics: a verified bounded negative package/symbol usage refutes the new
  required path condition, which blocks L1 by contract. No case changed for any other
  reason (semantic projection identical).
- Privacy: only `C01`–`C31` labels appear here and in the machine report; unit
  identifiers, snapshot basenames, absolute paths and private component names are
  scrubbed by the driver and verified absent from the emitted JSON.

## Acceptance gate

```text
test -z "$(gofmt -l .)"   → clean
go vet ./...              → clean
go test -count=1 ./...    → 29 ok + 3 no-test-files, 0 FAIL
```

Machine-readable result: `<VA_TMP>`-local `b42-regression.json` (both passes); the
sibling `agent-v4` rebuilds under `<VA_TMP>/exploitable{,-retry,-retry-invalid}/runs`
are the durable post-B42 evidence.

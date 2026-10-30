# Evidence-levels saved-data regression — slice2-fidelity/3

Date: 2026-10-14. Scope: Task 6 of `docs/dev/plans/2026-10-13-02-evidence-levels-plan.md`.
Driver: `tools/evidence-levels-replay.py` (new). Runner: `izyan` built at `46828be` + Tasks 1–5
(uncommitted, post-review-fix tree). **No model runs and no live harness calls**: every case
replays the persisted agent turn via `--replay-agent-turn` with `GOPROXY=off`,
`GOSUMDB=off`, `GOFLAGS=-mod=readonly`; `run.harness` stays all-null in every rebuilt report.

## Result: both expected matrices reproduce exactly — no divergence

| set | total | L1 | L2 | L3 | verdict |
|---|---|---|---|---|---|
| primary | 31 | **7** — C01, C03, C07, C14, C15, C16, C17 | **24** | **0** | MATCHES expected 7/24/0 |
| retry aggregate (6 + 5) | 11 | **2** — C01, C03 | **9** | **0** | MATCHES expected 2/9/0 |

All 42 cases ran and PASSed every assertion; zero NOT_RUN, zero FAIL.

## Method

- Primary replay source: `tmp/exploitable/runs/<UNIT>/agent` → new sibling `<UNIT>/agent-v3`
  (previous `agent` and `agent-v2` evidence preserved byte-for-byte).
- Retry replay sources: `tmp/exploitable-retry/runs/<UNIT>/agent` (6) and
  `tmp/exploitable-retry-invalid/runs/<UNIT>/agent` (5) → new sibling `agent-v3`.
- Per case: `izyan research --snapshot … --cve … --advisory-file … --output-dir <sibling>`
  `--replay-agent-turn <saved>/agent --govulndb <frozen> --modcache <cache>` with the
  manifest's recorded `--analysis-go/--goos/--goarch/--build-tags/--external-commit-sha`.
- Per-case assertions (any failure fails the run): rebuilt `report.json` parses; the CLI's
  emit-time `Validate` passed (rc=0 — fail-closed, includes recomputed `evidence_level`
  compare for `/3`); `contract_extensions` = `[slice2-fidelity/3]` exactly;
  `evidence_level` present with closed-enum level/basis; `agent_output.status`,
  `agent_output.category`, `agent_output.extraction.status` equal the saved report;
  every agent-attempt artifact pin (path/sha256/size_bytes/selector across
  `agent_output.answer_artifact`, `raw_artifact`, `result_artifact`,
  `extraction.answer_artifact`, `attempts[kind=agent].*`) is verbatim and the pinned bytes
  under the source dir still hash to the recorded sha256; `agent_output.replayed_from`
  present, `dir` = saved run dir, `answer_sha256` = saved answer pin;
  `disposition.class=REVIEW_REQUIRED` and `auto_close=false`; no agent ref
  (`agent-src:`, assertion ids, category/reasoning strings) in
  `evidence_level.evidence_refs`; `exploitation_established≠ESTABLISHED` and level≠L3
  unless a saved verified fact from a dynamic carrier (runtime-observation /
  dynamic-trace / reproduction) exists — none do in any set.

## Per-case census (rebuilt `agent-v3` reports)

| label | primary | retry | retry-invalid | L2 blocking conditions |
|---|---|---|---|---|
| C01 | L1 | L1 | — | — |
| C02 | L2 | L2 | — | EC-0003, EC-0004 |
| C03 | L1 | L1 | — | — |
| C04 | L2 | L2 | — | EC-0003, EC-0004 |
| C05 | L2 | L2 | — | EC-0003, EC-0004 |
| C06 | L2 | L2 | — | EC-0003, EC-0004 |
| C07 | L1 | — | — | — |
| C08 | L2 | — | L2 | EC-0003, EC-0004 |
| C09–C13 | L2 | — | — | EC-0003, EC-0004 |
| C14–C17 | L1 | — | — | — |
| C18 | L2 | — | — | EC-0003, EC-0004 |
| C19 | L2 | — | L2 | EC-0003, EC-0004 |
| C20–C24 | L2 | — | — | EC-0003, EC-0004 |
| C25–C27 | L2 | — | L2 (each) | EC-0003, EC-0004 |
| C28–C31 | L2 | — | — | EC-0003, EC-0004 |

Every L2 case is blocked by the same two deterministic path-role conditions left
`UNKNOWN`: **EC-0003** "affected package reachable" and **EC-0004** "affected package
build-relevant" — the package-reachability/build-relevance transitions the saved
deterministic lanes could not close (scoped sandbox, no symbol-level resolution). No
deployment-role condition blocked L1 anywhere; no agent-origin condition leaked into a
blocking set or into `evidence_refs` (the Tasks 2/3 review fixes hold on real data:
agent-origin conditions contribute neither refs nor carrier status).

## Saved statuses and pins preserved

Saved `agent_output.status` distribution — primary: 20 OK / 6 FAILED / 5 INVALID_FORMAT;
retry: 6 OK; retry-invalid: 5 OK — was preserved verbatim in every rebuilt report
(extraction `VALID`/`INVALID` likewise: 20+11 VALID / 11 INVALID). All artifact pins match
the saved records and the bytes on disk. `agent_output.replayed_from` is present on all 42
rebuilds and points at the correct source dir.

## /1 and /2 compatibility

- `TestSlice2_LegacyReportStillValidates` parses+validates the committed
  `eval/agent7/e2e/` fixtures (two `slice2-fidelity/1`, one `slice2-fidelity/2`) — PASS.
- All 42 replay *sources* are `/2` reports with no `evidence_level`/`role`: they were
  accepted on the legacy replay path (`LoadPersistedAgentTurn` skips the `/3` gate for
  non-`/3` markers) — live proof `/2` inputs still validate.
- Focused suite `go test ./internal/research -run
  'TestEvidenceLevelValidator|TestReplayEvidenceLevel|TestSlice2_LegacyReportStillValidates|TestSlice2V2|TestSlice2V3|TestReplayLoad'`
  — PASS (0 failures, all negative validator + replay tamper subtests included).
- Byte-stability: C07's `evidence_level` JSON is byte-identical across two independent
  replays (smoke run → scratch dir; regression run → `agent-v3`), matching the
  `TestReplayEvidenceLevel_ByteStable` invariant.

## Wall time

- Total wall (jobs=4): **1030.4 s ≈ 17 min** for 42 cases.
- Per case: min 57.6 s, median 76.6 s, max 265.8 s; sum of case times 4067 s
  (~68 min serial — consistent with the ~65 min estimate; a serial run remains the
  reproducible fallback).

## NOT_RUN / caveats

- No case was NOT_RUN. `tmp/exploitable-retry-invalid-dockerfail{,2}` exist but are NOT_RUN
  by design — outside the task's retry scope (6 + 5); passing a literal
  `exploitable-retry*/runs` glob would pull them in, so the driver takes an explicit,
  repeatable `--retry-glob` per set.
- Brief deviation (sanctioned): the brief's "Change §1" discovers `…/agent-v2` as the
  replay source, but `agent-v2` retains no `agent/attempt-*` artifacts, so it cannot be a
  replay dir; the driver replays the original `agent` dirs and writes the `/3` rebuild to
  sibling `agent-v3`, per this task's deliverable wording. `--primary-suffix` is kept as a
  documented no-op for interface compatibility.
- The deterministic attempt row's `result_artifact` (`deterministic-facts.json`) is
  legitimately re-emitted each run and is excluded from pin preservation; only
  agent-attempt pins are asserted verbatim.
- NOTHING in this report or the driver names unit identifiers; outputs use C-labels only.

## Acceptance gate

```text
test -z "$(gofmt -l .)"   → clean
go vet ./...              → clean
go test -count=1 ./...    → 29 ok, 0 FAIL
```

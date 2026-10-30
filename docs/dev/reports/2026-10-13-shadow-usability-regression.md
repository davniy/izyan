# Shadow research lane — saved-case offline regression

Date: 2026-10-13 15:39:03 MSK  
Mode: `--cases saved` — deterministic lane re-run + `--replay-agent-turn` (no model, no live harness call).  
GOVULNDB: `<VA_TMP>/govulndb`  
MODCACHE: `<GOMODCACHE>`  
Per-case budgets: `--deterministic-timeout 20m`, `--overall-timeout 90m`.  
Source artifacts are untouched: every case rebuilt into a sibling `<case>-v2` directory.
Case labels `C01`–`C31` are opaque placeholders; the label↔ticket mapping is held privately, outside this repository.

Placeholders: `<VA_TMP>` — private run root outside the repository; `<GOMODCACHE>` — local Go module cache; `<corporate-provider-host>` — corporate LLM-gateway host.

## Summary

| metric | value |
|---|---|
| cases discovered | 31 |
| cases run | 31 |
| invariant pass | 31 |
| invariant fail | 0 |
| NOT_RUN | 0 |
| total wall time | 3888s (64.8min) |
| per-case wall (min/median/max) | 113s / 117s / 177s |

## Per-case results

| case | status | exit | wall s | det lane | agent (old → new) | run_govulncheck | expl. established | disposition | failed checks |
|---|---|---|---|---|---|---|---|---|---|
| saved:C01 | PASS | 0 | 133 | OK | FAILED → FAILED | OK | NOT_ESTABLISHED | REVIEW_REQUIRED/auto_close=False | 0 |
| saved:C02 | PASS | 0 | 116 | OK | FAILED → FAILED | OK | NOT_ESTABLISHED | REVIEW_REQUIRED/auto_close=False | 0 |
| saved:C03 | PASS | 0 | 116 | OK | FAILED → FAILED | OK | NOT_ESTABLISHED | REVIEW_REQUIRED/auto_close=False | 0 |
| saved:C04 | PASS | 0 | 138 | OK | FAILED → FAILED | OK | NOT_ESTABLISHED | REVIEW_REQUIRED/auto_close=False | 0 |
| saved:C05 | PASS | 0 | 113 | OK | FAILED → FAILED | OK | NOT_ESTABLISHED | REVIEW_REQUIRED/auto_close=False | 0 |
| saved:C06 | PASS | 0 | 177 | OK | FAILED → FAILED | OK | NOT_ESTABLISHED | REVIEW_REQUIRED/auto_close=False | 0 |
| saved:C07 | PASS | 0 | 115 | OK | OK → OK | OK | NOT_ESTABLISHED | REVIEW_REQUIRED/auto_close=False | 0 |
| saved:C08 | PASS | 0 | 147 | OK | INVALID_FORMAT → INVALID_FORMAT | OK | NOT_ESTABLISHED | REVIEW_REQUIRED/auto_close=False | 0 |
| saved:C09 | PASS | 0 | 118 | OK | OK → OK | OK | NOT_ESTABLISHED | REVIEW_REQUIRED/auto_close=False | 0 |
| saved:C10 | PASS | 0 | 129 | OK | OK → OK | OK | NOT_ESTABLISHED | REVIEW_REQUIRED/auto_close=False | 0 |
| saved:C11 | PASS | 0 | 147 | OK | OK → OK | OK | NOT_ESTABLISHED | REVIEW_REQUIRED/auto_close=False | 0 |
| saved:C12 | PASS | 0 | 130 | OK | OK → OK | OK | NOT_ESTABLISHED | REVIEW_REQUIRED/auto_close=False | 0 |
| saved:C13 | PASS | 0 | 122 | OK | OK → OK | OK | NOT_ESTABLISHED | REVIEW_REQUIRED/auto_close=False | 0 |
| saved:C14 | PASS | 0 | 140 | OK | OK → OK | OK | NOT_ESTABLISHED | REVIEW_REQUIRED/auto_close=False | 0 |
| saved:C15 | PASS | 0 | 144 | OK | OK → OK | OK | NOT_ESTABLISHED | REVIEW_REQUIRED/auto_close=False | 0 |
| saved:C16 | PASS | 0 | 136 | OK | OK → OK | OK | NOT_ESTABLISHED | REVIEW_REQUIRED/auto_close=False | 0 |
| saved:C17 | PASS | 0 | 140 | OK | OK → OK | OK | NOT_ESTABLISHED | REVIEW_REQUIRED/auto_close=False | 0 |
| saved:C18 | PASS | 0 | 117 | OK | OK → OK | OK | NOT_ESTABLISHED | REVIEW_REQUIRED/auto_close=False | 0 |
| saved:C19 | PASS | 0 | 118 | OK | INVALID_FORMAT → INVALID_FORMAT | OK | NOT_ESTABLISHED | REVIEW_REQUIRED/auto_close=False | 0 |
| saved:C20 | PASS | 0 | 115 | OK | OK → OK | OK | NOT_ESTABLISHED | REVIEW_REQUIRED/auto_close=False | 0 |
| saved:C21 | PASS | 0 | 116 | OK | OK → OK | OK | NOT_ESTABLISHED | REVIEW_REQUIRED/auto_close=False | 0 |
| saved:C22 | PASS | 0 | 116 | OK | OK → OK | OK | NOT_ESTABLISHED | REVIEW_REQUIRED/auto_close=False | 0 |
| saved:C23 | PASS | 0 | 116 | OK | OK → OK | OK | NOT_ESTABLISHED | REVIEW_REQUIRED/auto_close=False | 0 |
| saved:C24 | PASS | 0 | 115 | OK | OK → OK | OK | NOT_ESTABLISHED | REVIEW_REQUIRED/auto_close=False | 0 |
| saved:C25 | PASS | 0 | 117 | OK | INVALID_FORMAT → INVALID_FORMAT | OK | NOT_ESTABLISHED | REVIEW_REQUIRED/auto_close=False | 0 |
| saved:C26 | PASS | 0 | 117 | OK | INVALID_FORMAT → INVALID_FORMAT | OK | NOT_ESTABLISHED | REVIEW_REQUIRED/auto_close=False | 0 |
| saved:C27 | PASS | 0 | 115 | OK | INVALID_FORMAT → INVALID_FORMAT | OK | NOT_ESTABLISHED | REVIEW_REQUIRED/auto_close=False | 0 |
| saved:C28 | PASS | 0 | 116 | OK | OK → OK | OK | NOT_ESTABLISHED | REVIEW_REQUIRED/auto_close=False | 0 |
| saved:C29 | PASS | 0 | 116 | OK | OK → OK | OK | NOT_ESTABLISHED | REVIEW_REQUIRED/auto_close=False | 0 |
| saved:C30 | PASS | 0 | 116 | OK | OK → OK | OK | NOT_ESTABLISHED | REVIEW_REQUIRED/auto_close=False | 0 |
| saved:C31 | PASS | 0 | 117 | OK | OK → OK | OK | NOT_ESTABLISHED | REVIEW_REQUIRED/auto_close=False | 0 |

## Deterministic lane completion

| deterministic attempt status | cases |
|---|---|
| OK | 31 |

## `run_govulncheck` results (local pinned DB)

| tool_status | cases |
|---|---|
| OK | 31 |

| in_database | findings | cases |
|---|---|---|
| True | 5 | 10 |
| True | 4 | 5 |
| True | 21 | 4 |
| True | 17 | 3 |
| True | 22 | 2 |
| True | 18 | 2 |
| True | 2 | 2 |
| True | 12 | 1 |
| True | 13 | 1 |
| True | 3 | 1 |

DB provenance: `DB: file://<VA_TMP>/govulndb; DB updated: 2026-10-08 22:31:09 +0000 UTC`

## `trace_argument` / `find_validations` / `check_call_site_guard`

| tool/status | observations |
|---|---|
| check_call_site_guard/OK | 5 |
| find_validations/OK | 5 |
| trace_argument/OK | 5 |

UNSUPPORTED rows are scoped `call-site-only` limitations (position is not an AST call) — honest scope notes, not tool successes. ERROR count: 0.

## Extractor / recovery

| recorded extraction status | cases |
|---|---|
| VALID | 20 |
| INVALID | 11 |

| recovery marker in v2 report | cases |
|---|---|
| strict (no recovery) | 31 |

Replay preserves the recorded extraction verbatim (fail-closed replay contract): a saved `INVALID_FORMAT` turn stays `INVALID_FORMAT`; the recovery ladder applies to the re-parse of OK turns and to future live turns.

## Agent status preservation

| saved status | v2 status | cases |
|---|---|---|
| OK | OK | 20 |
| FAILED | FAILED | 6 |
| INVALID_FORMAT | INVALID_FORMAT | 5 |

Changed statuses: 0

## Evidence presence (v2 reports)

| | confirmed deterministic facts | agent hypotheses (assertions) | unknowns | decision-changing unknowns |
|---|---|---|---|---|
| total | 898 | 117 | 79 | 46 |
| min/case | 15 | 0 | 2 | — |
| max/case | 147 | 6 | 5 | — |

Facts come only from successful deterministic observations; agent hypotheses stay PROVISIONAL and are never promoted.

## Remaining exploitation conditions

| state | conditions |
|---|---|
| UNKNOWN | 79 |
| SUPPORTED | 76 |
| OPEN | 19 |

## Operational unknowns (decision-changing, aggregated)

| cases | unknown |
|---|---|
| 6 | UNKNOWN: agent assessment did not complete (FAILED) |
| 5 | UNKNOWN: agent assessment did not complete (INVALID_FORMAT) |
| 5 | UNKNOWN: the required configuration the agent reports absent for CVE-2026-84304 was not independently verified |
| 3 | UNKNOWN: component github.com/pkg/sftp is named by the agent but is not in the advisory affected entries |
| 3 | UNKNOWN: component github.com/testcontainers/testcontainers-go is named by the agent but is not in the advisory affected |
| 2 | UNKNOWN: the required configuration the agent reports absent for CVE-2026-56855 was not independently verified |
| 2 | UNKNOWN: the required configuration the agent reports absent for CVE-2026-78662 was not independently verified |
| 2 | UNKNOWN: the required configuration the agent reports absent for CVE-2026-77410 was not independently verified |
| 2 | UNKNOWN: the required configuration the agent reports absent for CVE-2026-77404 was not independently verified |
| 2 | UNKNOWN: the required configuration the agent reports absent for CVE-2026-77407 was not independently verified |
| 2 | UNKNOWN: the required configuration the agent reports absent for CVE-2026-77411 was not independently verified |
| 1 | UNKNOWN: the agent's vulnerable-code-not-reachable claim for CVE-2026-41178 is not independently verified |
| 1 | UNKNOWN: component golang.org/x/net is named by the agent but is not in the advisory affected entries |
| 1 | UNKNOWN: component github.com/redpanda-data/benthos is named by the agent but is not in the advisory affected entries |
| 1 | UNKNOWN: the agent's vulnerable-code-not-reachable claim for CVE-2026-56855 is not independently verified |

## Exploitation & disposition

| `exploitation_established` status | cases |
|---|---|
| NOT_ESTABLISHED | 31 |

| disposition class | auto_close | cases |
|---|---|---|
| REVIEW_REQUIRED | False | 31 |

No report receives `AUTO_CLOSE`, `VERIFIED`, `FALSE` or `NO_EXPLOIT_PATH_FOUND`: the contract pins `REVIEW_REQUIRED`/`auto_close=false`.

## Provider/preflight failures (recorded in the saved runs)

6 saved case(s) carry `agent_output.status=FAILED` from the original run (E6 preflight `provider.status=unreachable_infra`): saved:C01, saved:C02, saved:C03, saved:C04, saved:C05, saved:C06.

Replay preserves the recorded FAILED status verbatim — no live preflight is executed, so the transient-retry path (Task 4) is not exercised by this regression. NOT_RUN for live retry: forbidden by the no-model constraint.

## Failed cases and blockers

None — every executed case passed all checks and no case was skipped.
## Limitations of the Shadow↔V2 comparison

- This regression measures Shadow-lane behavior only; no V2 artifacts were produced or compared.
- No superiority claim is made; no confidence score is used (no methodology exists for it).
- `run_govulncheck` `in_database=false` means no scanned OSV names the advisory — never a negative conclusion.
- Saved turns predating the extractor-recovery change keep their recorded INVALID_FORMAT status under replay.
- Agent turns are byte-verified replays; nothing here re-validates the agent's reasoning against the code.

---

# Appendix — live retry of the 6 provider-outage cases (operator-authorized)

Date: 2026-10-13. The 6 cases below `FAILED` in the frozen corpus run inside a single transient provider
window (2026-10-13 01:34:09–01:41:57 UTC, E6 preflight `provider.status=unreachable_infra`,
`cannot resolve <corporate-provider-host>`); `<corporate-provider-host>` resolves again. This appendix re-runs ONLY those 6 cases live to
close the availability gap.

Frozen recipe unchanged: prompt `r0-v1` (default), model `qwen3.6-35b`, provider `custom-openai`, image
`vex-bench-go-opencode-e6:latest` (1d7b3d39…), harness `agent-ctl` @80cddeac. Only `--govulndb`/`--modcache`
were added so the fixed deterministic lane is measured. Output root:
`<VA_TMP>/exploitable-retry` (saved artifacts untouched — verified
by mtime).

| case | rc | wall s | agent | category | extraction | recovery | entry_status | reachability | facts | unknowns | preflight |
|---|---|---|---|---|---|---|---|---|---|---|---|
| C01 | 0 | 366 | OK | vulnerable | VALID | – | MIXED | NOT_EVALUATED | 147 | 6 | PASS/ok |
| C02 | 0 | 410 | OK | code_not_reachable | VALID | – | AFFECTED | UNKNOWN | 15 | 7 | PASS/ok |
| C03 | 0 | 284 | OK | vulnerable | VALID | – | MIXED | NOT_EVALUATED | 83 | 3 | PASS/ok |
| C04 | 0 | 416 | OK | vulnerable | VALID | – | AFFECTED | UNKNOWN | 15 | 3 | PASS/ok |
| C05 | 0 | 352 | OK | vulnerable | VALID | – | AFFECTED | UNKNOWN | 15 | 2 | PASS/ok |
| C06 | 0 | 400 | OK | vulnerable | VALID | – | AFFECTED | UNKNOWN | 15 | 2 | PASS/ok |

Observed:

- **Availability gap closed: 6/6 OK** (was 6 FAILED). The failures were an environment window, not a lane defect.
  Merging with the frozen run, the 31-case corpus yields **26 OK + 5 INVALID_FORMAT** usable agent turns
  (was 20 + 5 + 6 FAILED).
- **Extractor recovery was not needed here:** all 6 new answers were `VALID` on the strict path (`recovery` empty).
  The bounded-recovery path therefore remains evidenced by unit tests over the 5 saved answers, not by a live case.
- **Task 4 preflight retry was NOT exercised:** each case recorded exactly one preflight attempt, `PASS`,
  `provider_status=ok`, with an immutable report path + sha256 (`agent_manifest.preflight_attempts`). The retry
  path stays unit-tested only (scripted stub); it fires only on a new transient `unreachable_infra`.
- `run_govulncheck` OK in the retry runs (e.g. C04: `pattern ./cmd/...`, 17 findings for
  `GHSA-hrxh-6v49-42gf`, advisory in DB).
- Disposition unchanged: `REVIEW_REQUIRED`, `auto_close=false`; `exploitation_established=NOT_ESTABLISHED` in all 6.
- Per-case wall 284–416 s (vs 3–4 min in the frozen run) — the fixed deterministic lane now also runs govulncheck.

---

# Appendix 2 — live retry of the 5 INVALID_FORMAT cases (operator-authorized)

Date: 2026-10-13. Scope: the 5 cases whose agent answer was `INVALID_FORMAT` in the frozen run
(C08, C19, C25, C26, C27). Frozen recipe unchanged; `--govulndb`/`--modcache`
added. Output root: `<VA_TMP>/exploitable-retry-invalid`
(saved artifacts untouched — verified by mtime).

| case | rc | wall s | agent | category | extraction | recovery | entry_status | facts | unknowns | preflight |
|---|---|---|---|---|---|---|---|---|---|---|
| C08 | 0 | 282 | OK | vulnerable | VALID | – | AFFECTED | 15 | 4 | PASS/ok |
| C19 | 0 | 320 | OK | vulnerable | VALID | – | AFFECTED | 15 | 3 | PASS/ok |
| C25 | 0 | 321 | OK | vulnerable | VALID | – | AFFECTED | 15 | 2 | PASS/ok |
| C26 | 0 | 240 | OK | vulnerable | VALID | – | AFFECTED | 15 | 2 | PASS/ok |
| C27 | 0 | 359 | OK | vulnerable | VALID | **BRACE_COMPLETION** | AFFECTED | 15 | 2 | PASS/ok |

Observed:

- **5/5 OK** (was 5 INVALID_FORMAT). With both retries, the 31-case corpus now yields **31/31 usable agent turns**
  (26 OK from the frozen run + 6 recovered FAILED + 5 recovered INVALID_FORMAT).
- **The bounded recovery ladder fired on a REAL model answer.** C27: the raw answer does not parse
  (`Expecting ',' delimiter` at char 9025 — the outer object is unclosed), and appending exactly one `}` yields
  `{category, reasoning, assessment}` with `category=vulnerable`. The report records the repair transparently:
  candidate selector `bytes 0..9050 of retained answer; recovered with 1 appended '}'`, and the attempt audit
  shows `extraction: VALID (NONE), 1 candidate(s), selected 0 recovery=BRACE_COMPLETION`. No content is fabricated.
- The other 4 new answers parsed on the strict path (no recovery needed) — the recovery path is an exception
  handler, not a substitute for strict parsing.
- `preflight_attempts` = 1 × PASS each; Task 4 retry still not exercised live (provider and Docker healthy).
- Disposition unchanged in all 5: `REVIEW_REQUIRED`, `auto_close=false`, `exploitation_established=NOT_ESTABLISHED`.

## Environmental note (preflight fail-closed on a non-provider transient)

Attempts 1–2 of this retry failed for a reason unrelated to the provider: the Docker daemon could list the E6
image (`docker images`) but `docker image inspect vex-bench-go-opencode-e6:latest` returned
`No such image` (inconsistent tag→ID mapping). The E6 preflight failed closed at `image_pin`
(`detail: Command '[...'image','inspect',...]' returned non-zero exit status 1`) and, correctly, did **not**
retry — Task 4 retries only `provider.status=unreachable_infra`. Repaired without a rebuild by re-tagging the same
ID: `docker image tag 1d7b3d3982a5 vex-bench-go-opencode-e6:latest` (digest unchanged, `1d7b3d39…`); a manual
`uv run vex-bench evaluate e6-preflight` then passed all checks. Failed attempts preserved under
`tmp/exploitable-retry-invalid-dockerfail{,2}`.

[INFERENCE] A transient Docker-daemon error is currently indistinguishable from a permanent image failure and
therefore costs a full FAILED turn. If such hiccups recur, the retry policy may need a second retryable class
(probe/transport error), keeping the agent attempt itself single-shot.

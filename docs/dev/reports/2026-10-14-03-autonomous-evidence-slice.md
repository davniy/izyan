# Autonomous evidence slice — capability demonstration (C01–C04)

Date: 2026-10-15. Plan: `docs/dev/plans/2026-10-14-03-autonomous-evidence-slice-plan.md` (Task 7, Amendments R1–R2).
**Final status: `CAPABILITY_GAP_RECORDED`** — controlled stop; no real case reached an independently
verified negative. All four reports are `INCONCLUSIVE`, `Disposition=REVIEW_REQUIRED`, `AutoClose=false`.
Spec: `docs/dev/specs/2026-10-14-Izyan-Autonomous-Evid.md`.
Inputs and run artifacts are private and live under `<VA_TMP>/autonomous-evidence-slice/` (case matrix +
`runs/<Cxx>/`); this file carries only anonymous labels, content hashes, metrics and outcome strings.

## Method

Each case ran through `izyan research` with `--replay-agent-turn` (no model call; the retained
answer is re-parsed verbatim), the matrix-pinned snapshot, frozen advisory file and timeouts
(`--deterministic-timeout 20m`, `--overall-timeout 90m`, `--external-commit-sha` per snapshot).
All four runs exited 0, emitted a self-validated `research-report/2` and kept
`Disposition{REVIEW_REQUIRED, AutoClose:false}`. No saved artifact byte changed; no historical
triage label was used as evidence.

## Outcome

| Case | Role | decision.verdict | decision.reason | coverage | disposition |
|---|---|---|---|---|---|
| C01 | negative candidate (guard/bound) | `INCONCLUSIVE` | `no independently verifiable falsifier proposal` | `INSUFFICIENT_SCOPE` | `REVIEW_REQUIRED` |
| C02 | negative candidate (product build-closure absence) — required | `INCONCLUSIVE` | `no independently verifiable falsifier proposal` | `INSUFFICIENT_SCOPE` | `REVIEW_REQUIRED` |
| C03 | positive control | `INCONCLUSIVE` (never safe) | `no independently verifiable falsifier proposal` | `INSUFFICIENT_SCOPE` | `REVIEW_REQUIRED` |
| C04 | insufficient-data control | `INCONCLUSIVE` | `no independently verifiable falsifier proposal` | `INSUFFICIENT_SCOPE` | `REVIEW_REQUIRED` |

Snapshots exercised: C01/C02/C04 over content hash `affff1b53bfc2aa57fd224d619233f9d604191c7f594da8cf9c7454f2e55fc08`,
C03 over `502d9373b0e7f9b411e5ae4842c675d9d90be22efb08e6acff77a1c546a0cdce` (the pinned post-drift bytes).

## C02 — capability gap (Amendment R1 stop)

The required independently verified negative could not be produced; the slice stops and records
the gap rather than substituting the guard route or softening a check:

1. **No plan-bearing agent turn exists.** Every pinned retained answer predates the
   `verification_plan` contract, so the bounded verification phase executed zero checks in all
   four runs (`verification-facts.json`: `executed: false`, `plan_status: "no verification plan
   in the retained answer"`) and `VerifyDecision` stopped at `Proposal == nil`.
2. **No deterministic closed product build-closure capability for this snapshot.** The lane ran
   module-level `usage-scope` for every advisory-declared subject (3 module subjects) and every
   call returned `ERROR`: the strict toolchain env (`GOPROXY=off`, `GOFLAGS=-mod=readonly`,
   no declared module cache) makes `go list -deps` fail on a vendored, non-tidy module, and no
   evidence tool derives the product import closure from `vendor/modules.txt` plus source
   imports. `affected-resolve` consequently records `package_present=UNKNOWN
   build_relevant=UNKNOWN`; `run_govulncheck` is `UNSUPPORTED` (the CLI's
   `--govulndb`/`--modcache` values are recorded but never reach the session config).

## Controls

- **C03 (never falsely safe):** the lane recorded affected+reachable positive facts —
  `package-usage` USED for the advisory package and its dial symbol, `usage-scope` COMPLETE
  with `usage_scope=mixed`, `affected-resolve` TRUE/TRUE/TRUE/TRUE — yet produced no safe
  verdict; the agent's unverified non-reachability basis stays `PROVISIONAL/agent` with a
  concrete follow-up.
- **C04 (insufficient data):** `INCONCLUSIVE` naming the missing release-toolchain fact
  (no binary build info; `go.mod` is a minimum) and the undecidable stdlib applicability,
  with the follow-up "supply release toolchain evidence or a release binary"; symbol checks
  on the absent vendored package and both `usage-scope` calls recorded `ERROR`.
- **C01 (guard route, out of scope per R1):** stayed `INCONCLUSIVE`; because the replayed
  answer carries no `FalsifierGuards` proposal, the decision reason is the missing-proposal
  string rather than `guard_verification_capability_missing` — the fail-closed guard branch
  exists but was not reached.

## Metrics

- 4 runs, 4 validated `research-report/2` reports, 4× `auto_close=false`, 0 model calls.
- Observation counts: C01 16 (1 `ERROR`, 1 `UNSUPPORTED`), C02 26 (3 `ERROR`, 1 `UNSUPPORTED`),
  C03 66 (0 `ERROR`, 1 `UNSUPPORTED` — `go list -deps` succeeded on this tidy snapshot),
  C04 140 (22 `ERROR`, 1 `UNSUPPORTED`).
- Verification phase: 0 plans executed, 0 observations persisted (`verification-observations.jsonl`
  never written; `verification-facts.json` records the phase honestly).
- Focused check (Step 4): `go test -count=1 -v -run 'Test(ResearchDecisionCLI|CapabilityReport|PositiveControl|UnknownControl)' ./cmd/izyan ./internal/research`
  — 7 test functions matched, all PASS; `go build ./...` clean. No corpus or VEX-Bench run.

## Recorded missing deterministic capabilities

1. A retained agent turn carrying a `verification_plan` (new live turn under the updated
   prompt, or a matrix-pinned replacement) — prerequisite for the bounded phase to run at all.
2. A deterministic closed product-closure deriver that works offline on a vendored, non-tidy
   snapshot (source-import + `modules.txt` closure), since `usage-scope`'s `go list -deps`
   path fails under the strict env.
3. `--govulndb`/`--modcache` plumbing into `SessionConfig` so `run_govulncheck` can execute
   under the strict profile.
4. (R1 backlog, unchanged) the guard/bound proof family: a tool-backed complete
   sink/flow/guard/bound observation plus an adapter re-running `goanalysis.Verifier`.

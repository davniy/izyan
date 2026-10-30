# Evidence target provenance — real calibration ledger

**Date:** 2026-10-25
**Plan:** [`docs/dev/plans/2026-10-25-04-evidence-target-implementation.md`](../plans/2026-10-25-04-evidence-target-implementation.md) (Task 6)
**Spec:** [`docs/dev/plans/2026-10-25-03-evidence-target-provenance.md`](../plans/2026-10-25-03-evidence-target-provenance.md)
**Branch:** `consolidation/shadow-base`

Two negative-admission gates are calibrated here on real VEX-Bench snapshots:
a build-dependent negative needs **(1)** an identified, scoped product build
and **(2)** a completed measurement with the coverage the negative needs.
Both are described in [`analysis-internals.md`](../analysis-internals.md) §3a.
Deterministic regression coverage lives in
`internal/states/target_provenance_e2e_test.go`; this report records only what
the real corpus measured.

## 1. Reproduction

```bash
PATH=$SHIM:$PATH \
GOMODCACHE=<module cache> \
VA_VEX_TASKS=<vex_bench_go.jsonl> \
VA_SNAPSHOTS=<snapshot root> \
VA_FROZEN_OSV=<frozen OSV dir> \
VA_CASES=<output root> \
go test -count=1 ./cmd/izyan -run '^TestTargetProvenanceCalibration$' -timeout 90m -v
```

* Host: darwin/arm64, analysis toolchain **go1.26.1** (local), `VA_MEM_LIMIT`
  default 24 GiB.
* Snapshots carry no `.git`: the benchmark git shim answers
  `git rev-parse HEAD` from `IZYAN_SNAPSHOT_SHA`, which the test sets to the
  task's commit. Nothing else about snapshot resolution changes.
* The frozen corpus is keyed by OSV id (`GO-*`/`GHSA-*`) while the benchmark
  asks by CVE; the test resolves each pinned CVE to its aliased document and
  materializes a CVE-keyed copy under the case directory. The corpus is never
  modified and no harness code changed.
* Profiling: `--deterministic-only`, `--perimeter auto`, `--cve-analysis off`,
  `envReplace`, `confineReads`, advisory-scoped reads. Paired runs differ
  **only** in target inputs.

Artifacts of the recorded run:
`cases-target-provenance-final/<task>/<target>/<case>/` (`report.json`,
`openvex.json`, `cyclonedx.json`, `report.md`, `report.en.md`).

## 2. Result matrix

All four runs reached `COMPLETED`; none was an infrastructure failure.

| # | Task | Target request | Recorded target (source/scope) | Effective build | govulncheck outcome | Pattern | Advisory coverage | Verdict | Class |
|---|---|---|---|---|---|---|---|---|---|
| 1 | `cilium-cilium-1228cbc-CVE-2026-35469` | none (host default) | `host-default` / — | darwin/arm64, CGO 0 | `failed` (type-check) | `./...` | `unknown` | `INCONCLUSIVE` | **abstained** |
| 2 | same task, paired | `--goos linux --goarch amd64` | `operator-declared` / `operator` | linux/amd64, CGO 0 | `completed_with_results` | `./...` | `covered` | `EXPLOITABLE` | **unchanged positive** |
| 3 | `containers-podman-38ccfa2-CVE-2024-37298` | none (host default) | `host-default` / — | darwin/arm64, CGO 0 | `failed` (type-check) | `./...` | `unknown` | `EXPLOITABLE` | **unchanged false alarm** |
| 4 | `kubernetes-kubernetes-6d4b94f-CVE-2022-41717` | none (host default) | `host-default` / — | darwin/arm64, CGO 0 | `completed_with_results` | `./...` | `covered` | `EXPLOITABLE` | **unchanged false alarm** |

Labels are the benchmark's ground-truth categories (read by the test for the
ledger only; they never reach the analysis): `vulnerable` (1–2),
`code_not_reachable` (3), `code_not_present` (4).

Two independent executions of the same test produced identical verdicts and
identical claim results (only wall time differs): run 1 — 1846 s total, run 2 —
1618 s total. Wall times below are from the final run: 1 — 178 s, 2 — 252 s,
3 — 29 s, 4 — 1158 s.

## 3. Cilium `CVE-2026-35469` — the positive control

### 3.1 Host default (no target inputs)

Cilium is Linux-only. Under the analyzer host the package load cannot
type-check (`undefined: netns.GetNetNSCookie`, `unix.ETH_P_ALL`,
`netlink.QdiscReplace`, `unix.BPF_F_*`, `bpf.Map`, …), so govulncheck fails on
`./...` and on its narrowed fallback. The failure is recorded, never
converted into evidence.

| Claim | Result | Producer / basis | Falsifier | NV | Evidence | Note |
|---|---|---|---|---|---|---|
| `C-REACH` | `UNKNOWN` | `evaluator.SymbolReachable`, positive-only fallback | — | — | — | "govulncheck failed; positive-only fallback: zero module usage cannot falsify reachability without a completed, coverage-qualified govulncheck run" |
| `C-PEER-INPUT` | `UNKNOWN` | `evaluator.ArgumentOrigin` | — | — | — | no provenance flows recorded |
| `C-CONSTRAINT` | `UNKNOWN` | `evaluator.Validation` | — | — | — | no provenance flows recorded |
| `C-LOCUS` | `UNKNOWN` | `evaluator.SymbolReachable(locus)` | (candidate refused) | — | — | "пакеты с уязвимым кодом входят в сборку, но измерение недостижимости не допущено: negative evidence refused: product target source \"host-default\" has no product scope: host defaults cannot ground a build-dependent negative" |
| `C-EXPOSURE` | `TRUE` | `evaluator.Exposure` (supporting) | — | — | `EV-021` | inbound HTTP listeners resolve independently of the build |
| `C-TLS-VERIFY` | `TRUE` | `evaluator.ConfigFlag` (supporting) | — | — | `EV-017` | knob assigned an insecure literal — a positive needs no target |

Verdict: **`INCONCLUSIVE`** — "one or more mandatory exploit conditions
remain unresolved: C-REACH, C-PEER-INPUT, C-CONSTRAINT, C-LOCUS".
Termination reason: resolved by the verdict evaluator; infrastructure status:
**no** failure (the failed tool run is recorded as a measurement outcome, the
case still completes).

### 3.2 Explicit `linux/amd64` — same snapshot, same advisory, same toolchain

| Claim | Result | Producer / basis | Falsifier | NV | Evidence |
|---|---|---|---|---|---|
| `C-REACH` | `TRUE` | `evaluator.SymbolReachable` — govulncheck call path | — | — | `EV-007` |
| `C-PEER-INPUT` | `TRUE` | `evaluator.ServerTransportInput` — reachable server transport + listener | — | — | `EV-007` |
| `C-CONSTRAINT` | `TRUE` | `evaluator.Validation` — same traced server path | — | — | `EV-007` |
| `C-LOCUS` | `TRUE` | `evaluator.SymbolReachable(locus)` — call path reaches `github.com/moby/spdystream.Connection.Serve` | — | — | `EV-007` |
| `C-EXPOSURE` | `TRUE` | `evaluator.Exposure` (supporting) | — | — | `EV-021` |
| `C-TLS-VERIFY` | `TRUE` | `evaluator.ConfigFlag` (supporting) | — | — | `EV-017` |

Verdict: **`EXPLOITABLE`** — "all mandatory exploit conditions are satisfied".
`C-PEER-INPUT`/`C-CONSTRAINT` carry the existing limitation that listener
reachability assumes an attacker can connect.

**Reading**: the pair isolates the target axis. Nothing about the advisory,
the toolchain, the database or the execution profile changed; the default run
cannot type-check the product build, therefore it cannot admit a negative and
cannot even produce a positive measurement, and abstains. With the product
build identified, the measured positive survives.

## 4. Podman `CVE-2024-37298` — unchanged false alarm

govulncheck fails under the host default (same Linux-only type-check class:
`unshare.HasCapSysAdmin`, `unix.O_PATH`, `gpgme.*`, `ConmonOCIRuntime`, …).

| Claim | Result | Producer / basis | Falsifier | NV | Evidence |
|---|---|---|---|---|---|
| `C-REACH` | `TRUE` | `evaluator.SymbolReachable` — module-internal chain `github.com/gorilla/schema.Decoder.Decode` | — | — | `EV-238`–`EV-242`, `EV-235`–`EV-237` |
| `C-PEER-INPUT` | `TRUE` | `evaluator.ArgumentOrigin` — 76 externally controlled call sites | — | — | `EV-011`–`EV-086` (226 ids) |
| `C-CONSTRAINT` | `TRUE` | `evaluator.Validation` — same call-site set | — | — | same 226 ids |
| `C-LOCUS` | `TRUE` | `evaluator.SymbolReachable(locus)` — module-internal chain | — | — | `EV-238`–`EV-242`, `EV-235`–`EV-237` |
| `C-EXPOSURE` | `TRUE` | `evaluator.Exposure` (supporting) | — | — | `EV-243` |
| `C-TLS-VERIFY` | `UNKNOWN` | `evaluator.ConfigFlag` | `zero-value-config` **refused** | — | `EV-233` |

Verdict: **`EXPLOITABLE`** — "all mandatory exploit conditions are satisfied".
Ground truth is `code_not_reachable`: the false alarm is **unchanged**.

**Reading**: `C-REACH`/`C-LOCUS` are module-chain positives and do not depend
on govulncheck, which is exactly why the provenance fix must not remove them.
The gate is nevertheless visible at claim level: the build-dependent
`zero-value-config` negative on `C-TLS-VERIFY` is refused under
`host-default` ("product target source \"host-default\" has no product scope"),
so it can neither close nor block the verdict. Podman is a surviving positive,
not a surviving negative; removing it would be tampering with calibration, not
a fix.

## 5. Kubernetes `CVE-2022-41717` — measured outcome

Against the expectation of a timeout, this run **completed** after 1158 s with
a real measurement: govulncheck `completed_with_results`, pattern `./...`,
advisory `covered`, call path to
`golang.org/x/net/http2.Server.ServeConn`.

| Claim | Result | Producer / basis | Falsifier | NV | Evidence |
|---|---|---|---|---|---|
| `C-REACH` | `TRUE` | `evaluator.SymbolReachable` — govulncheck call path | — | — | `EV-007` |
| `C-INPUT` | `TRUE` | `evaluator.ServerTransportInput` — reachable server transport + listeners | — | — | `EV-007` |
| `C-LOCUS` | `TRUE` | `evaluator.SymbolReachable(locus)` — call path reaches the declared symbol | — | — | `EV-007` |

Verdict: **`EXPLOITABLE`** — "all mandatory exploit conditions are satisfied".
Ground truth is `code_not_present`: a retained false alarm. It is **not** a
corrected safe result, and it is also not an infrastructure outcome in this
environment. The earlier expectation of a timeout/cancellation did not
reproduce here (analysis toolchain go1.26.1, 24 GiB budget); the test accepts
either shape but requires that a timeout be classified as infrastructure and
that no safe verdict ever be derived from an incomplete measurement. The same
outcome was reproduced in both calibration runs.

## 6. Classification of the changes

| Class | Cases | Meaning |
|---|---|---|
| **Abstained** (new, intended) | 1 — Cilium host-default | host default cannot identify the product build; the negative and the [positive] measurement are both unavailable |
| **Unchanged positive** | 2 — Cilium `linux/amd64` | the target was supplied; the measured positive is preserved |
| **Unchanged false alarm** | 3 — Podman, 4 — Kubernetes | independent module-chain / govulncheck positives survive; not "fixed" |
| **Corrected evidence** | none of these three | no verdict was reversed by this change |
| **Timeout / infrastructure** | none | all four runs completed |

The behavioural change is at evidence level, not at these verdicts: build
-dependent `FALSE` claims now require both gates, and build-dependent
negatives that used to close cases on the analyzer host now abstain. On
corpora without target inputs this lowers recall — deliberately — while the
false-safe direction is untouched.

## 7. What this does not measure

* The 30-case VEX-Bench corpus was **not** re-run: no aggregate
  safe-clear/false-safe number in `eval/README.md` is rewritten here. Only
  the three pinned cases above are measured.
* Library-API admission is unchanged (`DESERIALIZATION` + CWE-502); the
  no-admission controls are pinned by
  `TestE2ELibraryAdmissionControls`, not by a corpus run.
* No target inference was added to the benchmark harness: the Cilium pair is
  produced by the opt-in Go test calling `analyzeCase` with explicit flags,
  never by a public CLI flag or task metadata.

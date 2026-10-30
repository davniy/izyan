# Scope-bound version negatives — real calibration ledger

**Date:** 2026-10-26 (calibration runs 2026-10-25 and 2026-10-26)
**Plan:** [`docs/dev/plans/2026-10-25-06-scope-version-implementation.md`](../plans/2026-10-25-06-scope-version-implementation.md) (Task 7)
**Spec:** [`docs/dev/plans/2026-10-25-05-scope-bound-version-negatives.md`](../plans/2026-10-25-05-scope-bound-version-negatives.md)
**Branch:** `consolidation/shadow-base`, HEAD `e4b1baf`

This report records what the real corpus measured after the structural
advisory-scope gate landed. The gate is described in
[`analysis-internals.md`](../analysis-internals.md) §3b and
[`how-it-works.md`](../../how-it-works.md) §3. Deterministic regression
coverage lives in `internal/states/scope_version_integration_test.go`,
`internal/domain/advisory_scope_test.go`, `internal/vulnerability/scope_extent_test.go`
and the report/research/evaluator suites; this report is only the real-run
ledger.

**What is calibrated:** a finding-level negative conclusion requires a fully
represented exact advisory record — `ADVISORY_ENTRIES` + `COMPLETE` +
`RecordExtent=FULL_RECORD` + a digest-bound census in which every original
`affected[]` entry is represented as a Go module identity. `COMPLETE` alone,
a wide record reduced to its Go projection, and legacy persisted scopes
without structural evidence cannot close a finding. Version arithmetic is
unchanged.

## 1. Reproduction

Full opt-in calibration (17 tasks in 8 groups; the exact command used for the
2026-10-25 ledger):

```bash
PATH=$SHIM:$PATH GOMODCACHE=<module cache> \
VA_VEX_TASKS=<vex_bench_go.jsonl> \
VA_SNAPSHOTS=<snapshot root> \
VA_FROZEN_OSV=<frozen OSV dir> \
VA_CASES=<output root> \
go test -count=1 ./cmd/izyan -run '^TestScopeVersionCalibration$' -timeout 180m -v
```

Post-fix primary pair re-run (2026-10-26, exact command):

```bash
PATH=<REVIEW_WORKDIR>/bench/shim:$PATH \
VA_VEX_TASKS=<VA_VEXBENCH>/agent7-agent-ctl/benchmark/tasks/vex_bench_go.jsonl \
VA_SNAPSHOTS=<VA_VEXBENCH>/repos \
VA_FROZEN_OSV=<VA_TMP>/osv-feed/go \
VA_CASES=<REVIEW_WORKDIR>/bench/scope-version-cases-task7-primary \
go test -count=1 ./cmd/izyan -run '^TestScopeVersionCalibration$/^primary$' -timeout 30m -v
```

Environment and inputs for both runs:

* Host: darwin/arm64, analysis toolchain **go1.26.1** (local), `VA_MEM_LIMIT`
  default 24 GiB; `--deterministic-only`, `--perimeter auto`,
  `--cve-analysis off`, `envReplace`, `confineReads`, advisory-scoped reads.
* Snapshots carry no `.git`; the benchmark shim answers
  `git rev-parse HEAD` from `IZYAN_SNAPSHOT_SHA`, set per task. Corpus assets
  are never modified.
* Primary snapshot: `kubernetes/kubernetes`
  `e196d2491087e93bd29f0e5a538aab60667021e3`.
* Primary advisory: frozen `GHSA-qppj-fm5r-hxr3.json` (no GO alias used),
  raw sha256 `803271be656f5b874995591da3f52b28f12cff79140517a1e7d63f6f56e7d2c7`,
  canonical sha256 `83b852adcd9c692f0712f070359449161ac7883ff4b292d6a8d18b3873da1599`,
  22 `affected[]` entries: Go 1 (`golang.org/x/net`, SEMVER 0 → fixed
  0.17.0), Maven 20, SwiftURL 1. Go entry index 1.
* Both primary requests (`CVE-2023-44487`, `GHSA-qppj-fm5r-hxr3`) use the
  same document bytes, snapshot, target, toolchain and settings; only the
  requested identity differs.

## 2. Primary pair — post-fix measurement (2026-10-26)

Both requests returned a recorded verdict and the full artifact set. Ledger
fields common to both runs:

```text
extent GO_PROJECTION · coverage KNOWN_ONLY · census 22 original / 1 represented / 21 omitted
census ecosystems Go=1 Maven=20 SwiftURL=1 · Go module golang.org/x/net
scope_closes false
module_present TRUE · resolved_version v0.17.0 · version_affected FALSE
package_present UNKNOWN · build_relevant UNKNOWN
target host-default (darwin/arm64) · cycle COMPLETED
verdict INCONCLUSIVE (recorded) · OpenVEX under_investigation · CycloneDX in_triage
report.json / report.md / report.en.md / openvex.json / cyclonedx.json present
```

Scope identity differs exactly as expected: `CVE-2023-44487 → GHSA-qppj-fm5r-hxr3`
with `kind=CVE`; `GHSA-qppj-fm5r-hxr3 → GHSA-qppj-fm5r-hxr3` with
`kind=ADVISORY_ENTRIES`. Neither closes.

Refusal reasons recorded in the ledger and on the evidence graph:

```text
package/build reachability was not evaluated: the resolved version is outside
the affected ranges of every evaluated advisory entry
partial advisory scope: checked modules golang.org/x/net do not establish
complete coverage of CVE-2023-44487 (or GHSA-qppj-fm5r-hxr3);
component-negative facts cannot close the requested scope
```

Verdict reason (identical shape for both identities):

```text
partial or unknown advisory scope: negative facts for checked module(s)
"golang.org/x/net" do not establish complete coverage of <requested id>;
the remaining requested scope is unresolved
```

Artifacts inspected for the GHSA request:

```text
report.json   verdict INCONCLUSIVE; scope GO_PROJECTION/KNOWN_ONLY/ADVISORY_ENTRIES;
              census 22/1/21; facts TRUE / v0.17.0 / FALSE / UNKNOWN / UNKNOWN
report.en.md  | advisory record extent | `GO_PROJECTION` |
              | advisory record census | 22 entries: 1 represented, 21 omitted |
openvex.json  status under_investigation (no not_affected statement)
cyclonedx.json state in_triage
```

This is the intended honest abstention: the out-of-range `v0.17.0` component
fact is preserved with evidence, no gRPC entry is synthesized, and the
requested scope is not closed. Wall times: 9.03 s (CVE request), 6.11 s
(GHSA request); test `PASS`.

**Workflow contract change measured here.** Before `e4b1baf`, an unresolvable
root cause ended the case at the terminal `INCONCLUSIVE` state without a
verdict object or reports. The fix routes it through `EVALUATE_VERDICT`, so
this same pair now records `INCONCLUSIVE` and writes all reports/exports.

## 3. Full opt-in ledger (measured 2026-10-25)

This is the 17-task ledger produced by the opt-in test before `e4b1baf`.
`*` marks a pre-fix `verdict_recorded=false` row: the workflow terminated
`INCONCLUSIVE` without a verdict object, and the export states were the
admission projection of the terminal case. Those two rows are superseded by
§2. All other rows already had a terminal outcome and are unchanged by
`e4b1baf`.

| # | Group / task | Requested → resolved | Extent | Census o/r/m | Module / version / affected / package / build | Verdict | OpenVEX / CDX | Report | Wall s | Class |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | primary `kubernetes-kubernetes-e196d24-CVE-2023-44487` | CVE-2023-44487 → GHSA-qppj-fm5r-hxr3 | GO_PROJECTION | 22/1/21 | TRUE / v0.17.0 / FALSE / UNKNOWN / UNKNOWN | INCONCLUSIVE* | under_investigation / in_triage | — | 6.84 | honest abstention |
| 2 | primary, exact GHSA request | GHSA-qppj-fm5r-hxr3 → GHSA-qppj-fm5r-hxr3 | GO_PROJECTION | 22/1/21 | TRUE / v0.17.0 / FALSE / UNKNOWN / UNKNOWN | INCONCLUSIVE* | under_investigation / in_triage | — | 3.57 | honest abstention |
| 3 | helm `…b76a950-CVE-2024-25621` | CVE-2024-25621 → GO-2025-4100 | FULL_RECORD | 2/2/0 | TRUE / v1.7.27 / TRUE / UNKNOWN / UNKNOWN | INCONCLUSIVE | under_investigation / in_triage | yes | 37.89 | abstained |
| 4 | helm `…fbb24fe-CVE-2021-21334` | CVE-2021-21334 → GHSA-6g2q-w5j3-fwh4 | FULL_RECORD | 2/2/0 | TRUE / v1.4.3 / TRUE / UNKNOWN / UNKNOWN | INCONCLUSIVE | under_investigation / in_triage | yes | 28.81 | abstained |
| 5 | rancher `…4dc4f53-CVE-2025-47914` | CVE-2025-47914 → GO-2025-4135 | FULL_RECORD | 1/1/0 | TRUE / v0.43.0 / TRUE / TRUE / TRUE | EXPLOITABLE | affected / exploitable | yes | 1355.23 | unchanged positive |
| 6 | rancher `…4dc4f53-CVE-2025-58181` | CVE-2025-58181 → GO-2025-4134 | FULL_RECORD | 1/1/0 | TRUE / v0.43.0 / TRUE / TRUE / TRUE | INCONCLUSIVE | under_investigation / in_triage | yes | 1603.99 | abstained |
| 7 | rancher `…8761419-CVE-2026-24051` | CVE-2026-24051 → GO-2026-4394 | FULL_RECORD | 1/1/0 | TRUE / v1.33.0 / TRUE / UNKNOWN / UNKNOWN | INCONCLUSIVE | under_investigation / in_triage | yes | 212.10 | abstained |
| 8 | rancher `…8761419-CVE-2026-39883` | CVE-2026-39883 → GO-2026-5426 | FULL_RECORD | 1/1/0 | TRUE / v1.33.0 / TRUE / TRUE / TRUE | INCONCLUSIVE | under_investigation / in_triage | yes | 307.00 | abstained |
| 9 | istio `…042afc3-CVE-2023-48795` | CVE-2023-48795 → GO-2023-2402 | FULL_RECORD | 1/1/0 | TRUE / v0.14.0 / TRUE / UNKNOWN / UNKNOWN | INCONCLUSIVE | under_investigation / in_triage | yes | 691.31 | abstained |
| 10 | istio `…8903f65-CVE-2024-45338` | CVE-2024-45338 → GO-2024-3333 | FULL_RECORD | 1/1/0 | TRUE / v0.26.0 / TRUE / UNKNOWN / UNKNOWN | INCONCLUSIVE | under_investigation / in_triage | yes | 291.56 | abstained |
| 11 | podman `…6a65597-CVE-2023-48795` | CVE-2023-48795 → GO-2023-2402 | FULL_RECORD | 1/1/0 | TRUE / v0.16.0 / TRUE / UNKNOWN / UNKNOWN | INCONCLUSIVE | under_investigation / in_triage | yes | 370.73 | abstained |
| 12 | podman `…38ccfa2-CVE-2024-37298` | CVE-2024-37298 → GO-2024-2958 | FULL_RECORD | 1/1/0 | TRUE / v1.2.0 / TRUE / UNKNOWN / UNKNOWN | EXPLOITABLE | affected / exploitable | yes | 50.49 | unchanged positive |
| 13 | podman `…5ae6347-CVE-2025-47914` | CVE-2025-47914 → GO-2025-4135 | FULL_RECORD | 1/1/0 | TRUE / v0.49.0 / FALSE / UNKNOWN / UNKNOWN | INCONCLUSIVE | under_investigation / in_triage | yes | 49.89 | component fact, no close |
| 14 | kubernetes `…6d4b94f-CVE-2022-41717` | CVE-2022-41717 → GO-2022-1144 | FULL_RECORD | 2/2/0 | TRUE / v0.3.1-0.2022… / TRUE / TRUE / TRUE | EXPLOITABLE | affected / exploitable | yes | 1271.61 | unchanged positive |
| 15 | library-non-admission `labstack-echo-fdacff0-CVE-2020-26160` | CVE-2020-26160 → GO-2020-0017 | FULL_RECORD | 2/2/0 | TRUE / v3.2.0+incompatible / TRUE / TRUE / TRUE | INCONCLUSIVE | under_investigation / in_triage | yes | 13.61 | abstained |
| 16 | target pair `cilium-…1228cbc-CVE-2026-35469` host | CVE-2026-35469 → GO-2026-4958 | FULL_RECORD | 1/1/0 | TRUE / v0.5.0 / TRUE / TRUE / TRUE | INCONCLUSIVE | under_investigation / in_triage | yes | 217.05 | abstained |
| 17 | target pair, explicit `linux/amd64` | CVE-2026-35469 → GO-2026-4958 | FULL_RECORD | 1/1/0 | TRUE / v0.5.0 / TRUE / TRUE / TRUE | EXPLOITABLE | affected / exploitable | yes | 366.08 | measured positive kept |

Column notes: `o/r/m` = original/represented/omitted entries;
`module / version / affected / package / build` = `ModulePresent` /
`ResolvedVersion` / `VersionAffected` / `PackagePresent` / `BuildRelevant`.
The full row-16 wall time is from the full invocation; the focused target
rerun reproduced the same host-default row but its wall time was not retained
in the truncated job tail. Cilium claim-level detail under the explicit
target: `C-REACH`, `C-PEER-INPUT`, `C-CONSTRAINT`, `C-LOCUS`, `C-EXPOSURE`,
`C-TLS-VERIFY` are all TRUE with evidence (`EV-007`, `EV-021`, `EV-017`);
listener claims keep the existing "assumes an attacker can connect"
limitation. Under host default the same claims are `UNKNOWN` and the verdict
abstains.

Rows 3–17 request by CVE. That binds `Kind=CVE`/`KNOWN_ONLY`, so no finding
closure is possible by construction; the full-record extent is still recorded
in every one of them. The full-record **closure** path is exercised by the
deterministic regressions, not by these CVE-requested controls.

## 4. Refusal and export behaviour

* A projected record is refused at every closure surface; the component
  facts (module present, resolved version, out-of-range) remain visible in
  `report.json` and the Markdown applicability table.
* No projected negative was exported as `not_affected`. Primary exports are
  `under_investigation` (OpenVEX) and `in_triage` (CycloneDX) in both the
  persisted case and the written artifacts.
* An unresolved/ambiguous root cause is a limitation, not an abort: the case
  reaches `EVALUATE_VERDICT`, records `INCONCLUSIVE`, and writes
  `report.json`, `report.md`, `report.en.md`, `openvex.json`,
  `cyclonedx.json`. `--strict-llm` still fails fast (`FAILED`).
* Proven positives are not gated by advisory coverage: rows 5, 12, 14 and 17
  stayed `EXPLOITABLE` with TRUE claims and evidence.

## 5. Historical vs newly observed

* The historical VEX-Bench baseline remains as recorded:
  `false_safe=1`, Safe Clear Rate `10/23`, recall `2/7`, INCONCLUSIVE `40 %`,
  completion `28/30`, and the 38-case baseline tables in
  [`eval/README.md`](../../../eval/README.md). Those numbers are **not**
  recalculated, relabelled or rewritten by this change.
* Historical "correct-safe" labels predate the scope and target gates. They
  are not asserted as current closures here. This report records only the
  newly observed outcomes in §2 and §3.
* No aggregate safe-clear/false-safe metric was recomputed under the new
  gate. Unit regressions do not establish a restored recall or SCR.

## 6. Missing prerequisites / unexecuted validation

* **Live corpus** (`eval/live-corpus.json`): not run — it requires
  `VA_PRODUCT_REPO` pointing at the external product repository; unset and
  not present in this environment. Reported as unexecuted, never as a pass.
* **Full 38-case autonomous corpus** (`eval/corpus-real.json`): executed by
  the final integration run (2026-10-26); see §6.1. Corpus expectations
  were not edited.
* **Full 17-task post-fix rerun**: not repeated. Only the primary pair was
  re-executed after `e4b1baf`; every other row's terminal outcome predates
  that fix and is unaffected by its narrow routing change (rows 1–2 were the
  only `verdict_recorded=false` rows).
* **Disk headroom**: the workstation was at ~96 % utilization. A previous
  17-task invocation aborted one row with `no space left on device` while
  persisting the case; that abort is classified as **infrastructure**, not an
  analysis result. The target pair was then re-executed alone and passed.
  The test recognizes storage exhaustion and never counts it as a successful
  analysis.

### 6.1. Final integration corpus run (2026-10-26)

Command (exactly as specified by the plan):

```bash
go run ./cmd/izyan eval --corpus eval/corpus-real.json -j 4
```

Observed summary:

```text
cases=38 errors=0 expect pass=33 fail=5 claims-fail=0 false-safe=0 inconclusive=9
signal-cleared=0/23 (auto=0 expert=0)
reachable-cleared=0/19 package-level-cleared=0/4
cleared by evidence class: deeper=0 echo=0 affectedness=0
exit status 1 (expect-fail=5)
```

The five `expect-fail` rows — `real-service-pkg-6443`, `real-unix-access`,
`real-unix-stat`, `real-unix-fixed`, `real-ssh-slowpesh` — produced **no
verdict** and stopped at `SNAPSHOT_PRODUCT` in 0 s. No verdict means the
scope gate never ran; this is an infrastructure abort under `-j 4`, not an
analysis result and not a scope refusal. The same five cases were re-run
sequentially (`-j 1`):

```bash
go run ./cmd/izyan eval --corpus eval/corpus-real.json \
  --case 'real-unix-access,real-unix-stat,real-unix-fixed' -j 1
go run ./cmd/izyan eval --corpus eval/corpus-real.json \
  --case 'real-service-pkg-6443,real-ssh-slowpesh' -j 1
```

Sequential outcomes: `real-unix-access` `EXPLOITABLE`; `real-unix-stat`,
`real-unix-fixed`, `real-service-pkg-6443` `INCONCLUSIVE`;
`real-ssh-slowpesh` `EXPLOITABLE` — 5/5 expect-pass, 0 false-safe. No
historical expectation was relaxed: every verdict is inside the case's
existing allowed set, and the historical baseline tables remain untouched.
The parallel abort is reported as-is; it is not counted as a clean 38/38
single-invocation pass.

Notable expectation-compatible changes versus historical labels (not
attributed to the advisory-scope gate: these cases produced no
finding-level negative at all, so the scope gate had nothing to refuse):
`real-yaml-file`, `real-ssh-keyparse`, `real-yaml-const`,
`real-yaml3-const`, `real-protojson-const`, `real-dns-marshal`,
`real-service-plain` and `real-service-plain-6443x` now abstain
(`INCONCLUSIVE`) instead of a historical NEPF/`NOT_AFFECTED` label; all are
within their corpus `expect` sets. `false-safe` stayed 0.

## 7. Non-claims

This change **does not prove gRPC affectedness** and **does not fix all
Kubernetes/Podman false alarms**. It refuses an unjustified finding-level
negative: CVE-wide completeness is not inferred from an id prefix, one
module, one ecosystem, `github_reviewed`, alias enrichment, feed enrichment,
or the failure to discover another implementation. Module/version negatives
stay independent of build-target admission but still require finding-scope
coverage.

There is **no override flag** to force a projected record to close, and no
commitment to related-record discovery: `related` records remain external
signal, not equivalence or exhaustiveness evidence. B38 (external validation,
discovery/identity/entailment for unenumerated implementations, regression
run) remains open.

## 8. Artifacts

* Primary post-fix case roots:
  `<REVIEW_WORKDIR>/bench/scope-version-cases-task7-primary/scope-version/primary/kubernetes-kubernetes-e196d24-CVE-2023-44487/host-default/{CVE-2023-44487-1792965224,GHSA-qppj-fm5r-hxr3-1792965233}/`
* Full 2026-10-25 ledger case roots:
  `<REVIEW_WORKDIR>/bench/scope-version-cases-full2/scope-version/`
  and `<REVIEW_WORKDIR>/bench/scope-version-cases-target/scope-version/`
* Advisory/raw digests for every resolved control: Task 6 report,
  `.superpowers/sdd/2026-10-25-06-scope-version-implementation/task-6-report.md`
  (appendix).

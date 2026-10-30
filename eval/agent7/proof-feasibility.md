# A1.5 — Proof feasibility preflight (PR-1)

Task A of the proof-feasibility preflight (plan `2026-10-10-02` §A1.5; spec
`2026-10-10-01` §3, §7.1–7.4): deterministic fact collection over the 30
development VEX-Bench cases plus the B0 product baseline, **without** new
LLM calls, proof checkers, or an agent runtime. Task B (independent expert
classification) consumes `proof-feasibility.csv`; its classification
columns are intentionally empty here.

Artifacts:

| File | Role |
|---|---|
| `internal/eval/agent7/feasibility.go` (+ `_test.go`) | deterministic collector |
| `cmd/agent7-feasibility/` | controller-side generator CLI |
| `proof-feasibility.raw.json` | full collector output, one record per case |
| `proof-feasibility.csv` | 23 GT-safe rows + 1 known-FS control row |
| `baseline-proof-coverage.json` | B0 verdicts + evaluated fact classes + provenance |
| `eval/agent7/results/b0-baseline/` | raw run output (gitignored, local) |

**GT boundary.** `gt_class`/`gt_category` columns and the scorer join are
controller-side data (frozen `gt_policy`, `manifest.json:418`). The CSV,
raw JSON, coverage JSON and this document are **controller artifacts** —
committed evidence for the expert, never mounted into any sandbox; the
analyzer saw only `{task_id, cve_id, repo_url, commit_sha}` per case.

## 1. Method — what was read, what is deterministic, what is controller-side

Per case the collector reads four input groups:

1. **Frozen dataset record** (`vex_bench.jsonl`, sha256
   `60b55373031dca97009d2e89ef8dfdf0ba083f9ce1035470fdf46f0da15384b3`):
   task_id, cve_id, repo_url, commit_sha — and, controller-side only,
   `ground_truth`/`ground_truth_category`.
2. **The OSV advisory the run consumed** (`<case>/advisory/<id>.json` —
   the same advisory document the analyzer fetched live, byte-identical
   to what the run recorded via its own `advisory_sha256`; digests are
   **non-canonical byte hashes** — a re-fetch of the same advisory can
   differ in whitespace/order): affected-module entries,
   version ranges, imports, GOOS/GOARCH import restrictions, `modified`.
   Parsed with the analyzer's own conversion
   (`vulnerability.FileSource`, alias enrichment disabled → no network).
3. **The pinned snapshot** (repos_dir `…/<owner>/<repo>/<sha>`), files
   only — **no `go` subprocess, no `go list`**: every `go.mod` (nested
   included → `multi_module`), `vendor/modules.txt` (authoritative
   vendored-module record, parsed by `affected.ParseVendorModules`),
   `go.work` presence at the module root, require/replace resolution to
   effective (post-replace) versions, a generated-code marker scan
   (vendored trees excluded — dependency content is not product
   generation), and per-file build constraints evaluated with
   `go/build.Context.MatchFile` under the **run's** GOOS/GOARCH/tags/cgo
   plus `go1.N` release tags from the resolved release toolchain
   (undecidable → `unknown`, never guessed).
4. **The B0 run envelope** (`<case>/prediction.json`): verdict, falsifier,
   grounding conditions, limitations, error, content hash, advisory
   identity, release toolchain facts, build context. `scoring/cases.jsonl`
   supplies the scorer's GT join for aggregates.

**Deterministic (machine-checkable):** every column in
`proof-feasibility.csv` — a concrete value, `unknown` (with a
`blocker_kind`), or `none` (determinable absence). `proof_*` fields are
**fact-pattern feasibility**, not certificates: `yes` = the candidate's
underlying fact holds on the source tree and all inputs needed to observe
it exist; `no` = deterministically refuted; `unknown` = undecidable from
available inputs (recorded with the blocking kind). They deliberately do
**not** implement `FACT_VERIFIED` / `CVE_APPLICABILITY_VERIFIED` /
`TARGET_COVERAGE_VERIFIED` (spec §7.2) — no artifact-bundle immutability
check, no advisory-completeness proof, no coverage check.

**Controller-side, not machine-derived:** `advisory_manifest_complete` is
`unknown` for every case except the known false-safe control
(`kubernetes-kubernetes-e196d24-CVE-2023-44487`, set to `no`): whether an
advisory lists **every** affected component cannot be proven from data —
there is no completeness oracle. The `no` for the control case is an
externally verified fact (historical analysis §5 below), never inferred.
`gt_*` columns are controller-side labels; the five `classification_*`
columns are empty for Task B.

## 2. Run provenance (B0 baseline)

Two run attempts exist; only the second is the baseline of record.

**Invalidated first attempt (kept as evidence, not a baseline):**
`izyan eval vex-bench --tasks …/vex_bench.jsonl --repos-dir …/repos -j 2
--out eval/agent7/results/b0-baseline --mem-limit 8GiB`. The analyzer's
own memory guard (`cmd/izyan/memguard.go`) cancelled the analysis context
once the budget was crossed: 13 cases produced real results, the
remaining 17 returned instantly with `reason: "advisory error: osv get …
context canceled"` and `wall_seconds ≈ 0.004`. That is a RUN-PROFILE/infra
failure, never an Izyan verdict; the directory was renamed to
`eval/agent7/results/b0-baseline-j2-memcancel` and is excluded from every
aggregate here.

**Baseline of record (three merged segments):** `-j 3 --mem-limit 24GiB`
into `eval/agent7/results/b0-baseline` produced 19 real results; the 11
cases that failed on OSV network flakiness (`context deadline exceeded`,
one `unexpected EOF`) were retried with the same profile into
`eval/agent7/results/b0-baseline-retry`, and residual fetch failures
closed out under `b0-baseline-retry2`. The artifacts merge
`--run b0-baseline --run b0-baseline-retry --run b0-baseline-retry2`
(last segment wins per task_id); per-segment provenance is under
`segments` in `baseline-proof-coverage.json`.

**Merged-run provenance:**

| Field | Value |
|---|---|
| Command | `izyan eval vex-bench --tasks …/vex_bench.jsonl --repos-dir …/repos -j 3 --out eval/agent7/results/b0-baseline --mem-limit 24GiB` |
| Binary | `izyan` (vex-bench runner), sha256 `b829552f31b71db505fd9c0c267af251436ef8f662d49cfcf461191c0379f553` |
| izyan HEAD | `ff0fcb8312c52bb8aee4dd8a53024bccbb48c282` (PR-0) |
| `go version` | `go1.26.1 darwin/arm64` (analysis toolchain: local) |
| Dataset sha256 | `60b55373031dca97009d2e89ef8dfdf0ba083f9ce1035470fdf46f0da15384b3` (pinned) |
| govulncheck | `v1.8.0`, DB `https://vuln.go.dev` (live_observed) |
| Run dir | `eval/agent7/results/b0-baseline` (gitignored) |
| Profile | `detOnly` + `confineReads` + `envReplace` + `cveAnalysis:off` — deterministic, no LLM |

`metrics.json` (verbatim in `baseline-proof-coverage.json.provenance`):

```json
{
  "note": "recomputed over the merged 3-segment run via internal/eval/vexbench.Compute; per-segment metrics.json under segments.provenance",
  "total": 30,
  "false_safe": 1,
  "safe_clear_rate": 0.43478260869565216,
  "exploitable_recall": 0.2857142857142857,
  "inconclusive_rate": 0.4666666666666667,
  "completion_rate": 1,
  "status_correct": 12,
  "reason_correct": 7,
  "scoring_outcome_distribution": {
    "abstain": 14,
    "correct_exploitable": 2,
    "correct_safe": 10,
    "wrong": 4
  },
  "infra_error_count": 0
}
```
## 3. Metric definitions

Let **GT-safe** = the 23 `not_exploitable` development cases; **cleared**
= B0 scoring outcome `correct_safe` on a GT-safe case.

- `upper_bound_eligible_safe` — GT-safe cases where at least one
  `proof_*` field is `yes`: the optimistic ceiling of cases a proof lane
  could ever certify (before CVE-applicability and target-coverage
  checks). Everything else is already refuted or undecidable today.
- `overlap_with_current_izyan` — eligible cases already cleared by B0
  (`correct_safe`). These bring **no** new value: the cheap deterministic
  lane already closes them.
- `possible_incremental_safe` — eligible cases B0 did **not** clear
  (`abstain`/`failed`/`wrong` on GT-safe). The only cases where a proof
  lane could add a certified safe over baseline. The Checkpoint-0/§A1.5
  gate quantity: if 0, build no proof checkers.
- `expected_data_collection_cost` — qualitative Task-B input, estimated
  per case from `blocker_kind`: `missing_data` (which input to collect),
  `missing_algorithm` (which algorithm to build), `scope` (no data can
  close an applicability gap), `none` (nothing to collect). Distribution
  in §4.3.

## 4. Raw-fact summary

### 4.1 Candidate feasibility (all 30 cases; safe rows are the CSV subset)

| proof field | yes | no | unknown |
|---|---:|---:|---:|
| proof_artifact_fixed | 2 | 26 | 2 |
| proof_component_absent | 0 | 29 | 1 |
| proof_build_excluded | 0 | 11 | 19 |

| blocker_kind | cases |
|---|---:|
| none | 9 |
| missing_data | 9 |
| missing_algorithm | 11 |
| scope | 1 |

### 4.2 Uniform gaps (all cases)

Every snapshot is a **source tree**: `delivered_artifact_available = no`,
`build_attestation_available = no`, `binary_inventory_complete =
unknown`, `target_kind = source_tree`. No certificate from this phase can
claim a delivered binary — coverage is inherently source-tree-scoped
(spec §3). `advisory_manifest_complete` is `unknown` everywhere except
the control case (`no`).

### 4.3 Data-gap vs algorithm-gap split

`blocker_kind` partitions the gap:

- **missing_data** — inputs the controller could still collect: release
  toolchain for stdlib entries, vendored/external package source outside
  the snapshot, advisory completeness evidence, run envelopes for
  failed/missing cases.
- **missing_algorithm** — needs an algorithm, not data: in-tree /
  local-replace components have no released version for range comparison;
  `go.work` composition is not resolvable from files; non-vendored
  package import-closure needs the module's own `go list`.
- **scope** — the known false-safe pattern: the advisory manifest is
  proven incomplete (the vulnerable component is outside its affected
  list), so no artifact-level fact can certify safety.
- **none** — every candidate refuted by facts (present+vulnerable
  component, or included vulnerable package). No proof applies.

Concrete split over the merged run:

- `missing_algorithm` (11): every external non-vendored vulnerable
  package (`golang.org/x/text/language`, `golang.org/x/crypto/ssh*`,
  `golang.org/x/net/html`, `quic-go/internal/ackhandler`,
  `gopkg.in/yaml.v3`, `dgrijalva/jwt-go`, `otel/sdk/resource`) — its
  import-closure needs the module's own `go list`, which is out of scope
  for a file-level collector.
- `missing_data` (9): stdlib packages whose source lives in the release
  toolchain (`net/http`, `net/http/internal`), advisories declaring no
  packages at all (docker, containerd, sigstore timestamp-authority,
  otel/sdk, and the 12-ecosystem k8s-44487 manifest), the
  no-Go-advisory minikube case, and the malformed trivy `testdata`
  go.mod fixtures failing closed.
- `none` (9): every candidate refuted — a present vulnerable component
  at an in-range version, or an included vulnerable package.
- `scope` (1): the known false-safe control.

### 4.4 Corrections and known residuals

- **False positive fixed (expert review).** `build_excluded` previously
  counted a module *absent from the graph* as "excluded", letting an
  absent advisory sibling certify the pattern — the echo/jwt-go shape
  (`jwt-go` v3 present+imported, `jwt-go/v4` absent). Exclusion now
  requires positive evidence (advisory GOOS/GOARCH restriction or all
  in-tree files constraint-excluded) and `yes` needs zero undecidable
  packages; absence and unresolvable variants are `unknown` +
  `missing_data`/`missing_algorithm`. `artifact_fixed` likewise requires
  a verifiably-fixed present entry (absent entries are neutral, scope
  not missing-data). Regenerated: `labstack-echo-fdacff0-CVE-2020-26160`
  now reports `build_excluded=unknown` (`missing_algorithm`), and the
  only remaining `yes` facts are `artifact_fixed` on
  `containers-podman-5ae6347` (real — v5.0.6 ≥ fixed, B0 cleared it too)
  and the control row (correctly `yes` + `scope`: a fixed component the
  incomplete manifest cannot credit).
- **Residual — `zeromicro-go-zero-bae061a` `resolved_version=v0.3.7` vs
  B0 `v0.4.0`.** The collector reports the version declared in the
  *nested* `tools/goctl/go.mod` (it is the only `go.mod` in the tree
  requiring `x/text`); B0's fact record reports `v0.4.0`, the MVS
  selection of the main module's module graph (`go.sum` shows `v0.4.0
  h1:` — main `go.mod` never declares x/text directly). Two different
  scopes: nested-module floor vs product-module effective version. The
  collector's value is *conservative* (v0.3.7 is inside the affected
  range → `artifact_fixed=no`, so a genuine fix would be missed, never
  a false safe) but imprecise: effective-version resolution needs the
  scope; recorded here for the algorithm-gap list.
- **Integrity fail-closed (expert review).** The envelope's recorded
  `advisory_sha256` must equal the sha256 of the advisory file actually
  consumed, and `content_hash` must match the frozen manifest pin; any
  mismatch collapses every advisory/snapshot-derived fact and all three
  `proof_*` candidates to `unknown` with `blocker_kind=integrity` — a
  run must never emit a yes/no from tainted inputs. A `prediction.json`
  without `task_id`/`terminal_state` is rejected as evidence (`{}` is
  not a run), an envelope is infra whenever `terminal_state` is not
  `COMPLETED`/`INCONCLUSIVE`, and `findAdvisory` fails closed on
  ambiguity (never picks one of several matching files). Zero cases
  tripped the gate on this dataset.
## 5. B0 coverage and the known false-safe

`baseline-proof-coverage.json` records per-case verdicts, the six
deterministic fact classes (`module_graph_presence`, `version_affected`,
`package_presence`, `build_variant_facts`, `release_toolchain`,
`binary_inventory` — the last never evaluated: B0 inspects source
snapshots, not binaries), aggregates and verbatim run provenance.

| Metric | Value |
|---|---:|
| total / attempted / completed | 30 / 30 / 30 |
| verdict distribution | INCONCLUSIVE 14, NO_EXPLOIT_PATH_FOUND 7, EXPLOITABLE 5, NOT_AFFECTED 4 |
| correct_safe | 10 |
| abstain | 14 |
| wrong | 4 |
| failed | 0 (infra excluded; infra_error_count 0) |
| false_safe | 1 (k8s-e196d24 control) |

**Known false-safe (control row).** `kubernetes-kubernetes-e196d24-CVE-2023-44487`
(GT `exploitable`): the OSV document lists only `golang.org/x/net` for
CVE-2023-44487 while the vulnerable component in the k8s snapshot is
`google.golang.org/grpc` (reference PR kubernetes#121273); x/net is
already at the fixed version, so a version-outside-range fact does hold —
but it proves nothing about the CVE (`blocker_kind = scope`,
`advisory_manifest_complete = no`).


**Infra failures are never results.** Any case whose envelope carries an
infrastructure failure (non-empty `error`, `terminal_state=FAILED`, or a
`reason` naming an advisory-fetch/`context canceled`/`osv get` failure)
is marked `infra_error` and excluded from `verdict_distribution`,
`scoring_outcome_distribution`, `completion_rate` and every denominator;
it is reported separately under `aggregates.infra_errors`, mirroring the
frozen `INFRA_ERROR` taxonomy. A plain "advisory unsupported" or
"conditions unresolved" INCONCLUSIVE is a real abstain, not infra. The
generator additionally refuses to emit final artifacts under
`--require-complete` while any case is infra or lacks an envelope, so
a partially-failed run can never silently become the baseline.
**Degradation is declared, never inferred.** No per-case artifact
reliably separates a memory-degraded attempt from a legitimate abstain
(the same `limitations` strings — e.g. `build/test evidence actions
skipped … requires --allow-exec` — appear in normal runs that simply
reached the build/test stage); the earlier pattern-based inference was
removed for producing false positives on exactly this merged baseline.
An operator excludes a known-degraded case via the repeatable
`--degraded <case_id>` flag, which `--require-complete` honours by
refusing artifacts naming the case. The invalidated j2/8GiB attempt is
excluded by `--invalidated` (operator declaration, same mechanism) and
recorded under `invalidated_attempts` (all 30 of its envelopes affected:
13 real results + 17 instant memguard cancellations; evidence preserved
at `eval/agent7/results/b0-baseline-j2-memcancel`). The merged
three-segment baseline passes `--require-complete` as-is.

**Protocol caveat — memory ceiling changes verdicts.** The same case
returned `INCONCLUSIVE` ("C-LOCUS unresolved") under `-j 2 --mem-limit
8GiB` and `EXPLOITABLE` under `-j 3 --mem-limit 24GiB`
(`cilium-cilium-3977f6a-CVE-2026-33186`). The memory guard's GC pressure
degrades evidence collection, so a tripping ceiling can silently flip a
verdict. The memory ceiling is a run-profile parameter (§7) and must be
pinned non-tripping in the frozen protocol; this baseline is assembled
only from the non-invalidated segments — the j2/8GiB attempt sits in
`invalidated_attempts` by operator declaration, never merged.

**Merged run segments.** When a segment's advisory fetches fail on
network flakiness, those cases are retried as an extra `--run` segment;
the last segment holding an envelope for a case wins, aggregates are
recomputed over the merged set (`aggregates.metrics` via
`internal/eval/vexbench.Compute` — a segment's own metrics.json is
provenance, never a source of totals), and per-segment provenance is
recorded under `segments` (dir, cases contributed, infra errors).

**Difference from `eval/baselines/vexbench/external-baseline-1.md`:**
that historical B0 ran the same dataset at older commit `9c93054` (before
the PR-0 fix for `internal/goanalysis` bodyless-decl panics and any later
analyzer changes), reported FS=1 on the same k8s-44487 case, 10/23 safe
clear, 2 `failed` (the `istio-8903f65` / `headscale-e172c29` panics), and
1 advisory-less abstain (`minikube CVE-2019-5736`). This run supersedes
it for A1.5: same frozen dataset sha256, current HEAD, live-observed OSV
state; differences in outcome vs the historical numbers are recorded
above, not re-scored post-hoc.

## 6. Classification (Task B)

Independent classification by a separate expert agent (`A15ExpertClass`, read-only, no
access to the collector's author) over the 24 CSV rows: 23 GT-safe cases plus the known
false-safe control. The three `proof_*` columns remain **candidate facts, never
certificates**; the classification does not edit any fact column.

### 6.1 Interpretation and independence

- Every row is a `source_tree` target with `delivered_artifact_available=no`,
  `build_attestation_available=no`, `binary_inventory_complete=unknown`. A source-tree
  result cannot be promoted to a delivered-binary or release-set safety certificate
  (design §7.2/§7.3), and a `go.mod` `go` directive is not a release compiler attestation.
- No row is classified `agent_candidate`. An agent may discover mechanisms or reachability
  hypotheses, but `GLOBAL_UNREACHABLE` is outside the frozen MVP candidate types and an
  agent proposal cannot turn an unknown package/build/applicability fact into a certificate.
- The collector false positive the expert found on `labstack-echo-fdacff0-CVE-2020-26160`
  (an absent `jwt-go/v4` advisory sibling counted as build-exclusion evidence while the
  present, imported `jwt-go v3.2.0+incompatible` was not treated as included) was fixed in
  the collector and the artifacts regenerated; the row is now
  `proof_build_excluded=unknown`, `blocker_kind=missing_algorithm`.

### 6.2 Per-case classification

| Case | Class | Confidence | Reason | Incremental candidate | Cost |
|---|---|---|---:|---|---:|
| `aquasecurity-trivy-37da98d-CVE-2024-32473` | inconclusive | medium | ARTIFACT_FIXED=no COMPONENT_ABSENT=no BUILD_EXCLUDED=unknown; github.com/docker/docker is in the graph at v26.0.1+incompatible but its advisory entry has no affected packages and the snapshot has a malformed nested go.mod. | no | high |
| `kubernetes-minikube-e7bf515-CVE-2019-5736` | inconclusive | low | ARTIFACT_FIXED=unknown COMPONENT_ABSENT=unknown BUILD_EXCLUDED=unknown; the advisory has no usable Go module identity package identity or semver range so all three candidate facts are unavailable. | unknown | high |
| `juanfont-headscale-e172c29-CVE-2024-45338` | inconclusive | medium | ARTIFACT_FIXED=no COMPONENT_ABSENT=no BUILD_EXCLUDED=unknown; golang.org/x/net/html is v0.32.0 in affected range [0,0.33.0) and non-vendored so its package import closure and build coverage are missing. | unknown | medium |
| `zeromicro-go-zero-bae061a-CVE-2022-32149` | inconclusive | medium | ARTIFACT_FIXED=no COMPONENT_ABSENT=no BUILD_EXCLUDED=unknown; x/text/language is reported at v0.3.7 in the nested module and is in [0,0.3.8) while multi-module package closure is not resolved. | no | medium |
| `cilium-cilium-43bff35-CVE-2026-35469` | not_machine_checkable | high | ARTIFACT_FIXED=no COMPONENT_ABSENT=no BUILD_EXCLUDED=no; vendored github.com/moby/spdystream v0.5.0 is in [0,0.5.1) and the affected packages are not excluded for darwin/arm64. | no | none |
| `containers-podman-6541fc4-CVE-2025-58181` | not_machine_checkable | high | ARTIFACT_FIXED=no COMPONENT_ABSENT=no BUILD_EXCLUDED=no; vendored x/crypto v0.44.0 is in [0,0.45.0) and the affected ssh package is not build-excluded. | no | none |
| `rancher-rancher-4dc4f53-CVE-2025-58181` | inconclusive | medium | ARTIFACT_FIXED=no COMPONENT_ABSENT=no BUILD_EXCLUDED=unknown; non-vendored x/crypto/ssh v0.43.0 is in [0,0.45.0) and its external package import closure is unavailable. | no | medium |
| `cilium-cilium-3977f6a-CVE-2026-33186` | not_machine_checkable | high | ARTIFACT_FIXED=no COMPONENT_ABSENT=no BUILD_EXCLUDED=no; vendored grpc v1.78.0 is in [0,1.79.3) and build_tag_gated=yes does not establish exclusion. | no | none |
| `moby-moby-3ede246-CVE-2026-39984` | inconclusive | medium | ARTIFACT_FIXED=no COMPONENT_ABSENT=no BUILD_EXCLUDED=unknown; both sigstore timestamp-authority entries declare no affected packages so package mapping and CVE applicability are missing. | unknown | high |
| `kubernetes-kubernetes-1ee2acb-CVE-2024-24786` | not_machine_checkable | high | ARTIFACT_FIXED=no COMPONENT_ABSENT=no BUILD_EXCLUDED=no; vendored protobuf v1.31.0 is in [0,1.33.0) and the affected protojson packages are included. | no | none |
| `labstack-echo-fdacff0-CVE-2020-26160` | inconclusive | medium | ARTIFACT_FIXED=no COMPONENT_ABSENT=no BUILD_EXCLUDED=unknown; jwt-go v3.2.0 is in the graph and middleware/jwt.go imports it while non-vendored package import closure is unavailable. | unknown | medium |
| `aquasecurity-trivy-98e136e-CVE-2024-24791` | inconclusive | medium | ARTIFACT_FIXED=no COMPONENT_ABSENT=no BUILD_EXCLUDED=unknown; stdlib net/http is go1.22.4 in the affected range and its source is in the release toolchain rather than the snapshot. | unknown | high |
| `containers-podman-38ccfa2-CVE-2024-37298` | not_machine_checkable | high | ARTIFACT_FIXED=no COMPONENT_ABSENT=no BUILD_EXCLUDED=no; vendored gorilla/schema v1.2.0 is in [0,1.4.1) and the affected package is included. | no | none |
| `helm-helm-b76a950-CVE-2024-25621` | inconclusive | medium | ARTIFACT_FIXED=no COMPONENT_ABSENT=no BUILD_EXCLUDED=unknown; containerd v1.7.27 is in [0,1.7.29) while advisory entries declare no affected packages and the v2 version is unknown. | no | high |
| `rancher-rancher-8761419-CVE-2026-24051` | inconclusive | medium | ARTIFACT_FIXED=no COMPONENT_ABSENT=no BUILD_EXCLUDED=unknown; otel/sdk v1.33.0 is in [1.21.0,1.40.0) and its advisory entry declares no affected packages. | no | high |
| `rancher-rancher-8761419-CVE-2026-39883` | inconclusive | medium | ARTIFACT_FIXED=no COMPONENT_ABSENT=no BUILD_EXCLUDED=unknown; non-vendored otel/sdk/resource v1.33.0 is in [1.15.0,1.43.0) and its external package import closure is unavailable. | no | medium |
| `istio-istio-042afc3-CVE-2023-48795` | inconclusive | medium | ARTIFACT_FIXED=no COMPONENT_ABSENT=no BUILD_EXCLUDED=unknown; non-vendored x/crypto/ssh v0.14.0 is in [0,0.17.0) and its source is outside the snapshot. | no | medium |
| `istio-istio-8903f65-CVE-2024-45338` | inconclusive | medium | ARTIFACT_FIXED=no COMPONENT_ABSENT=no BUILD_EXCLUDED=unknown; non-vendored x/net/html v0.26.0 is in [0,0.33.0) and its package import closure is unavailable. | unknown | medium |
| `helm-helm-fbb24fe-CVE-2021-21334` | inconclusive | medium | ARTIFACT_FIXED=no COMPONENT_ABSENT=no BUILD_EXCLUDED=unknown; containerd v1.4.3 is in an affected range and its advisory entry declares no affected packages so the blocking package fact is missing. | unknown | high |
| `containers-podman-5ae6347-CVE-2025-47914` | deterministic_no_llm | high | ARTIFACT_FIXED=yes COMPONENT_ABSENT=no BUILD_EXCLUDED=no; resolved x/crypto v0.49.0 is outside [0,0.45.0) but source-tree input has no delivered artifact build attestation or binary inventory so this is only a candidate. | no | high |
| `gitleaks-gitleaks-f487f85-CVE-2025-22871` | inconclusive | medium | ARTIFACT_FIXED=no COMPONENT_ABSENT=no BUILD_EXCLUDED=unknown; stdlib net/http/internal is go1.23.4 in the affected range and its source is in the release toolchain rather than the snapshot. | no | high |
| `kubernetes-kubernetes-6d4b94f-CVE-2022-41717` | not_machine_checkable | high | ARTIFACT_FIXED=no COMPONENT_ABSENT=no BUILD_EXCLUDED=no; stdlib go1.19.5 and vendored x/net v0.3.1 are both in affected ranges and x/net/http2 is included. | no | none |
| `moby-moby-caea5f7-CVE-2026-39883` | not_machine_checkable | high | ARTIFACT_FIXED=no COMPONENT_ABSENT=no BUILD_EXCLUDED=no; vendored otel/sdk v1.42.0 is in [1.15.0,1.43.0) and the affected resource package is not excluded. | no | none |
| `kubernetes-kubernetes-e196d24-CVE-2023-44487` (control) | not_machine_checkable | high | ARTIFACT_FIXED=yes COMPONENT_ABSENT=no BUILD_EXCLUDED=unknown; advisory_manifest_complete=no because the cheap lane lists only golang.org/x/net at fixed v0.17.0 while the vulnerable component is google.golang.org/grpc so x/net's negative was wrongly applied to grpc-go. | no | high |

### 6.3 Required metrics

| Metric | Result | Arithmetic / interpretation |
|---|---:|---|
| `upper_bound_eligible_safe` | 1/23 | Only `containers-podman-5ae6347-CVE-2025-47914` has a safe-row `proof_* = yes` (`ARTIFACT_FIXED`); `COMPONENT_ABSENT=0`, `BUILD_EXCLUDED=0`. Optimistic fact-pattern ceiling only — not `FACT_VERIFIED`, not `CVE_APPLICABILITY_VERIFIED`, not `TARGET_COVERAGE_VERIFIED`. |
| `overlap_with_current_izyan` | 1 | The sole eligible safe row is already in B0's independently recomputed `correct_safe` set. |
| `possible_incremental_safe` | **0** | `1 eligible − 1 overlap = 0`. No row carries `incremental_safe_candidate=yes` (17 × `no`, 7 × `unknown`). |
| Candidate classes | 1 / 0 / 8 / 15 | `deterministic_no_llm` / `agent_candidate` / `not_machine_checkable` / `inconclusive` (all 24 rows). |
| Confidence | 9 / 14 / 1 | high / medium / low (all 24 rows). |
| Collection cost | 7 / 0 / 7 / 10 | none / low / medium / high (all 24 rows; safe rows only: 7 / 0 / 7 / 9). |
| Safe-row blocker split | 9 / 7 / 7 | `missing_data` / `missing_algorithm` / `none` over the 23 GT-safe rows (the single `scope` blocker is the exploitable control). |

Named medium-cost algorithm inputs: module-owned package/import closure for non-vendored
external modules (headscale x/net/html; go-zero x/text/language; rancher-4dc4f53
x/crypto/ssh; rancher-8761419 otel/sdk/resource; istio-042afc3 x/crypto/ssh; istio-8903f65
x/net/html). Named high-cost inputs: advisory package mappings and complete inventories
(trivy-37da98d Docker entry, moby-3ede246 sigstore entries, helm-b76a950/fbb24fe containerd
entries, rancher-8761419 CVE-2026-24051 otel/sdk), a usable Go advisory identity (minikube),
stdlib release-toolchain source/provenance (trivy-98e136e, gitleaks), delivered artifact
bytes plus build attestation and complete binary inventory (podman-5ae6347), and for the
control a complete affected-component/advisory scope basis.

**Stop condition.** Because the trusted `possible_incremental_safe` is **0**, proof checkers
must not be built (plan A1.5 stop condition). The research lane A2–A5 remains a separate
decision path.

### 6.4 Control row and the unsafe-certificate implication

The control `kubernetes-kubernetes-e196d24-CVE-2023-44487` carries
`proof_artifact_fixed=yes`: the consumed advisory's `golang.org/x/net` entry is fixed at
v0.17.0 relative to its listed range. That local fact is true but irrelevant to
CVE-2023-44487, because the vulnerable component in this snapshot is
`google.golang.org/grpc`, which the advisory omits (`advisory_manifest_complete=no`); B0's
`NOT_AFFECTED` was false-safe. A naive checker treating `artifact_fixed=yes` as sufficient
CVE applicability could have issued an unsafe certificate here, while a compliant checker
must fail applicability closed. This control therefore strengthens, not weakens, the
decision to stop the proof lane.

### 6.5 Residual uncertainty for Checkpoint 0

1. Multi-module version composition: the collector reports go-zero `x/text v0.3.7` (the
   nested `tools/goctl` module floor) while B0's graph fact reports the MVS-selected
   `v0.4.0`; the collector value is conservative (in-range → `artifact_fixed=no`, a false
   negative rather than a false safe) but imprecise — a recorded algorithm gap.
2. No row has delivered-artifact bytes, build attestations or a complete binary inventory;
   a source-tree-scoped fact can be retained as evidence but cannot establish release-set
   coverage.
3. Missing advisory package mappings and stdlib release-toolchain inputs leave the
   `inconclusive` rows unresolved; that is a data-collection gap, not a checker design gap.
4. Cases for which a machine certificate would not be trusted even if a checker existed:
   all 24 rows, because none is a delivered artifact with attestation and complete
   inventory; the control additionally fails on `advisory_manifest_complete=no`.

## 7. B0 verdict stability check (run-profile sensitivity)

The B0 baseline must be reproducible before it can serve as the comparison reference, so the
one observed cross-run verdict divergence was reproduced deliberately.

| Run | Profile | `cilium-cilium-3977f6a-CVE-2026-33186` | Wall |
|---|---|---|---|
| attempt 1 | `-j 2 --mem-limit 8GiB` | `INCONCLUSIVE` ("C-LOCUS unresolved"), extra limitation "build/test evidence actions skipped … requires --allow-exec" | 1355 s |
| attempt 3 | `-j 3 --mem-limit 24GiB` | `EXPLOITABLE` ("all mandatory exploit conditions are satisfied") | 2122 s |
| repeat 1 | `-j 1 --mem-limit 24GiB` | `EXPLOITABLE` | 6638 s |
| repeat 2 | `-j 1 --mem-limit 24GiB` | `EXPLOITABLE` | 1514 s |

Evidence: `eval/agent7/results/b0-baseline-j2-memcancel/cilium-cilium-3977f6a-*/prediction.json`
(attempt 1), `eval/agent7/results/b0-baseline/cilium-cilium-3977f6a-*/prediction.json`
(attempt 3), `eval/agent7/results/determinism-{1,2}/cilium-cilium-3977f6a-*/prediction.json`
(repeats). All runs used the same binary (sha256
`b829552f31b71db505fd9c0c267af251436ef8f662d49cfcf461191c0379f553`), the same snapshot, the
same advisory and the same deterministic-only flags.

Reading: under a **non-tripping** memory ceiling the verdict is stable across three
independent runs (attempt 3 and both repeats agree); the divergence is a memory-pressure
profile effect, not run-to-run randomness. The guard cancels/degrade stages when real usage
crosses the budget (`cmd/izyan/memguard.go`), which silently changes verdicts.

Consequences, carried into the frozen protocol and this preflight:

- the memory ceiling is a **result-affecting parameter** and must be pinned; a tripping
  ceiling is not a valid run profile;
- a degraded run is excluded **by operator declaration, never inferred**:
  the divergent attempt happens to carry an extra `limitations` entry,
  but the same strings appear in healthy runs, so the collector cannot
  tell them apart; the operator passes `--invalidated <run_dir>…` (a
  whole segment) or `--degraded <case_id>` (one case) and
  `--require-complete` enforces the exclusion;
- residual: the check covers one case, not all 30. Repeat-stability of the whole B0 baseline
  is not established; if the plan wants strict equality across arms, a repeat-stability
  sample should be added to the A2/B0 protocol before arm comparisons are scored.

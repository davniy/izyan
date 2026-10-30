# Definitive-verdict calibration — 2026-10-26

**Scope.** Task 11 of [`../plans/2026-10-26-03-definitive-verdict-implementation.md`](../plans/2026-10-26-03-definitive-verdict-implementation.md),
against the design [`../plans/2026-10-26-02-definitive-verdict.md`](../plans/2026-10-26-02-definitive-verdict.md)
including Addendum A.

**Status: partially measured; the real worked-case acceptance target is NOT met.**
The hermetic end-to-end regression passes and the fixtures carry the real captured
bytes. The real Kubernetes snapshot does not earn the expected positive, and the
cause is a named capability gap, not a missing measurement of the analyzer.

Historical calibration tables and the saved old run are unchanged. This report is
the new observation.

---

## 1. What ran

| Run | Command | Result |
|---|---|---|
| Hermetic worked-case pipeline | `go test ./internal/states -run '^TestDefinitiveVerdictIntegration$' -count=1` | **PASS**, 5/5 subtests |
| Real snapshot, isolated transport proof | `goanalysis.Index.ProveServerTransport` over the `e196d24` tree with the real `GO-2023-2153` subjects and the captured fix patch | **no witness**: `REACHABILITY_PROOF_INCOMPLETE` |
| Real snapshot, full request pipeline, corpus unconfigured | `go test ./cmd/izyan -run '^TestDefinitiveVerdictCalibration$'` (first attempt; the test had not yet called `resolveAdvisorySources`) | completed in 7.2 s: **`FAILED`**, no verdict, census intact, all four exports written |
| Real snapshot, full request pipeline, frozen corpus configured | same test, after wiring `resolveAdvisorySources` | **did not complete**: test timeout at 10 m inside `goanalysis` provenance tracing |

Environment: go1.26.1 (local), snapshots
`…/vexbench-durable/repos`, frozen OSV corpus
`…/agent7-unseen-repos/_build/osv-Go` (9 618 documents), publisher capture and fix
patch captured 2026-10-26 (digests below).

## 2. Measured hermetic result (synthetic product, real documents)

The product under test is `testdata/definitiveverdict` — it reproduces the *shape*
of the kubelet podresources listener and of gRPC-Go v1.55.0's stream lifecycle.
It is **not** a Kubernetes measurement. The advisory document, the `GO-2023-2153`
record, the publisher capture and the fix patch are the real captured bytes.

| Question | Measured |
|---|---|
| Requested `CVE-2023-44487` | `DECIDED` / **`EXPLOITABLE`** / profile `zero_trust` (actual) / `exploitability_scope=transport-peer` |
| Proof origin | `GO-2023-2153`, assessment `dv-CVE-2023-44487-GO-2023-2153` |
| Attribution | basis `publisher`, advisory `GHSA-m425-mq94-257g`, module `google.golang.org/grpc`, fix refs include `pull/6703`, capture digest `sha256:e9660354…` |
| Candidate aliases | unchanged: the requested CVE is **not** inserted into the `GO` record |
| Trigger witness | `http2-rapid-reset`, obligations **6/6** satisfied, fix digest `sha256:ad694cac…`, enforcement names `[atomicSemaphore newHandlerQuota]` |
| `C-PEER-INPUT` | `TRUE`, `control_basis=transport-peer-input` |
| `C-CONSTRAINT` | `TRUE` |
| Applicability | `google.golang.org/grpc` `v1.55.0` in `[0,1.56.3)` → `VersionAffected=TRUE`; the x/net fact is not inherited by the child |
| Primary census | 22 entries / 1 represented / 21 omitted, `GO_PROJECTION`, `KNOWN_ONLY`, Go module `golang.org/x/net` only — unchanged before and after |
| Persistence / publication | `ValidateFinalizedCase` passes; `report.json`, `report.md`, `openvex.json`, `cyclonedx.json` written and name the composed witness |

Controls (same pipeline, one input changed):

| Control | Measured |
|---|---|
| Exact broad request `GHSA-qppj-fm5r-hxr3` | `FAILED`, no verdict, `SCOPE/UNSUPPORTED_NEGATIVE_SCOPE`, **no** proof origin; the gRPC record keeps its own finding — no substitution |
| Publisher material that names the CVE but does not bind the record | `FAILED`, `CVE_ATTRIBUTION_UNRESOLVED`; the record-level positive is retained, not published |
| Synchronous handler dispatch (no goroutine) | `FAILED`; `C-CONSTRAINT` is not `TRUE` — the trigger is not earned from a call path alone |
| Declared, digest-pinned corpus, every candidate not affected (`v1.56.3`) | `DECIDED / NOT_AFFECTED` with the corpus basis and the verbatim boundary statement |
| Same corpus bytes **without** the declaration | `FAILED / UNSUPPORTED_NEGATIVE_SCOPE` — a feed alone grants no closure authority |

Captured fixture digests (re-verified by the test before analysis):

```text
publisher page      sha256:7cb79233e8514ecb82bfef7b76a9e07c2c5f0345274b0dadc9b8c15728915f00
normalized capture  sha256:e966035413d3214956c488660891bdc300f01b43526d284acc967ec15a064b4f
fix patch           sha256:ad694cac7672ec2a119b7ecfafbd5dc6a7d3b9877b519e9fbc56aa4bbdad79fa
GO-2023-2153.json   sha256:e0e6817babaaffa610f5f1386e5cd3817ff53412cb3f7867dffc398c0e7f5a90
```

## 3. Measured real-snapshot result

Task `kubernetes-kubernetes-e196d24-CVE-2023-44487`, commit
`e196d2491087e93bd29f0e5a538aab60667021e3`.

### 3.1 The isolated transport proof rejects the real kubelet path

Run against the real tree with the real record subjects and the live-captured fix
patch, the proof reports one typed gap:

```text
CODE/REACHABILITY_PROOF_INCOMPLETE
rooted transport proof: no Serve call is production-rooted with a constructed
server and listener; rejected candidate(s):
  pkg/kubelet/server/server.go:234: no production package main root reaches
  k8s.io/kubernetes/pkg/kubelet/server.ListenAndServePodResources
  (the path is unrooted, test-only or library API only);
  pkg/kubelet/cm/devicemanager/plugin/v1beta1/server.go:112: …;
  pkg/kubelet/pluginmanager/pluginwatcher/example_plugin.go:149: …;
  pkg/kubelet/cri/remote/fake/fake_runtime.go:63: not production source;
  test/e2e/storage/drivers/csi-test/driver/driver.go:158: not production source;
  test/images/agnhost/grpc-health-checking/grpc-health-checking.go:133: not production source
```

The construction and listener bindings resolve; the *root climb* does not.
`pkg/kubelet/server.ListenAndServePodResources` is reached from
`(*Kubelet).ListenAndServePodResources` (`pkg/kubelet/kubelet.go:2907–2922`,
called from `cmd/kubelet/app/server.go:1253`), but the shipped kubelet binary runs
that path through `cmd/kubelet/kubelet.go:main → app.NewKubeletCommand().RunE`,
i.e. a function value registered on a `cobra.Command` and invoked by the
framework. The proof's root rule terminates only at a `package main` function
reached through static call edges, so a CLI-registered entry point is invisible.

This is a **capability gap in the production-root rule**, not an environmental
fact and not a missing measurement: with the artifact and the profile fixed, the
answer does not depend on the environment.

### 3.2 The full pipeline

- Corpus unconfigured (first attempt): `FAILED`, no verdict, failure codes
  `SCOPE/UNSUPPORTED_NEGATIVE_SCOPE`, `CODE/ROOT_CAUSE_UNRESOLVED`. The census
  stayed 22/1/21 with `GO_PROJECTION`/`KNOWN_ONLY` and `golang.org/x/net` only;
  x/net `v0.17.0` stayed outside its range; the diagnostic report and all four
  exports were written. This run did not exercise discovery (the harness had not
  called `resolveAdvisorySources`), so it is evidence about the primary record
  only.
- Frozen corpus configured: the run did not complete within the test timeout
  (10 m). The captured stack is in `goanalysis` provenance tracing
  (`provenance.go` `traceCallee`/`evalCalleeExpr` with nested `loadExtra`), not in
  the transport proof. The real-snapshot full-run timing is therefore
  **unmeasured**, and no ledger from that configuration is claimed.

## 4. Acceptance status

| Acceptance item | Status |
|---|---|
| `DECIDED / EXPLOITABLE` on the real snapshot | **NOT MET** (measured `FAILED`) |
| actual profile `zero_trust`, `transport-peer`, `transport-peer-input` | met in the hermetic regression only |
| proof origin `GO-2023-2153`, gRPC `v1.55.0`, x/net `v0.17.0` | gRPC/x/net facts met in both; proof origin only hermetic |
| publisher attribution `GHSA-m425-mq94-257g` + PR 6703 | met in both (admitted on the real run) |
| rooted path through `cmd/kubelet/app/server.go:1253` → … → vendored gRPC | **NOT MET**: the root climb stops at the CLI registration |
| admitted Rapid Reset lifecycle witness | met hermetically over the real fix patch; not reached on the real tree |
| primary census/range unchanged (22/1/21) | met in every measured run |
| distinct unresolved deployment socket-access question | met: reported separately from exploitability |
| exact broad GHSA request is its own scope failure | met |

**Why it is not met.** A worked-case positive needs the shipped binary's entry
point. Admitting an *owned CLI command registration* (`RunE`/`Run` on a
`cobra.Command` executed by `main`) as a production root is a change to the
rooting predicate — a design decision that belongs with the proof owner, not a
calibration task. It is recorded as the remaining capability gap in
[`../gap-analysis.md`](../gap-analysis.md). No verdict-forcing fallback was added;
the measured outcome stays `FAILED` with its typed cause.

Two further latent gaps would block the same positive after rooting is solved,
found by inspection while building the synthetic mirror:

1. `handlerStart` originally required the handler goroutine inside the transport's
   own dispatch. Real gRPC-Go v1.55.0 calls the dispatch synchronously and starts
   the goroutine in `Server.serveStreams`, i.e. in the caller-supplied callback.
2. `fixQuotaNames` originally recognised only the fixture's diff shape
   (`case ch <- struct{}{}:` plus a deferred receive). The real upstream fix adds a
   counting semaphore (`atomicSemaphore`/`newHandlerQuota` with `<-q.wait` and
   `q.wait <- struct{}{}`) and wraps handler execution with a deferred release.

Both were completed in Task 11 (see the task report) because they are proof
completions of source-derived bindings, not policy changes: they cannot turn a
missing lifecycle into a positive, and their negative controls are asserted.

## 5. Populations (no false-safe / false-positive change claimed)

| Population | This calibration |
|---|---|
| Definitive and correct | hermetic worked case (`EXPLOITABLE`), declared-corpus negative (`NOT_AFFECTED`) |
| External dependencies | none newly decided; the deployed socket-access question is reported separately |
| Analysis failures | the real worked case (`REACHABILITY_PROOF_INCOMPLETE`), the exact broad GHSA request (`UNSUPPORTED_NEGATIVE_SCOPE`), the unbound-publisher and synchronous-dispatch controls |
| False safe | none introduced or legitimised |
| False positive | none introduced; the known Podman `CVE-2024-37298` and Kubernetes `CVE-2022-41717` results remain benchmark errors and were not re-labelled |

Moving tool limitations out of `INCONCLUSIVE` is **not** presented as increased
successful completion: failed analyses are their own population and the real
worked case is a failure.

## 6. Reproduce

```sh
# hermetic regression (no external assets)
go test ./internal/states -run '^TestDefinitiveVerdictIntegration$' -count=1 -v

# real worked case (needs the external corpus; skips with named prerequisites)
VA_VEX_TASKS=…/vex_bench_go.jsonl \
VA_SNAPSHOTS=…/vexbench-durable/repos \
VA_FROZEN_OSV=…/agent7-unseen-repos/_build/osv-Go \
VA_CASES=…/cases \
go test ./cmd/izyan -run '^TestDefinitiveVerdictCalibration$' -count=1 -v -timeout 40m
```

The calibration prints its claim-level ledger; the `acceptance target` subtest
reports `ACCEPTANCE NOT MET` with the measured outcome and failure codes.

# Research report — GO-2024-2737

> **EXPERIMENTAL — REVIEW REQUIRED.** This report supports human triage only.

## CVE essence and mechanism

**IPv6 enabled on IPv4-only network interfaces in github.com/docker/docker**

- aliases: CVE-2024-32473, GHSA-x84c-p2g9-rqv9
- mechanism: IPv6 enabled on IPv4-only network interfaces in github.com/docker/docker
- assessed mechanism (PARTIAL): CVE-2024-32473 allows IPv6 to be enabled on IPv4-only network interfaces in the Docker daemon. This is a network configuration defect where Docker creates network interfaces with IPv6 support even when the underlying host interface is IPv4-only, potentially causing unintended network exposure or misconfiguration. The effect occurs because the affected docker/docker code path handles network creati…
- [deterministic] advisory GO-2024-2737 states: IPv6 enabled on IPv4-only network interfaces in github.com/docker/docker

## What was actually found in the product

- applicability chain (PARTIAL): module_present=TRUE version_affected=TRUE package_present=UNKNOWN build_relevant=UNKNOWN
- conclusion scope: `AFFECTED_ENTRY_ONLY` | advisory scope: `UNKNOWN`
- [agent-only, unverified] CVE-2024-32473 allows IPv6 to be enabled on IPv4-only network interfaces in the Docker daemon. This is a network configuration defect where Docker creates network interfaces with IPv6 support even when the underlying host interface is IPv4-only, potentially causing unintended network exposure or mis…
- [agent-only, unverified] The advisory GO-2024-2737 binds to module github.com/docker/docker, introduced in 26.0.0+incompatible and fixed in 26.0.2+incompatible. The vulnerable code resides in the Docker daemon's network layer within the docker/docker module. In this Trivy snapshot, docker/docker is imported as a dependency …
- [agent-only, unverified] An attacker would need to invoke Docker's network creation APIs (e.g., via Docker API with NetworkCreate requests) on a Docker daemon using a version between 26.0.0 and 26.0.2 on a host with IPv4-only network interfaces. Trivy does not expose Docker API network endpoints, does not create Docker netw…
- [agent-only, unverified] Trivy is a container security scanner (github.com/aquasecurity/trivy, per go.mod:1). It uses the Docker client (pkg/fanal/image/daemon/docker.go) to inspect and save container images for scanning when the Docker engine driver is used. Build: Go module, Go 1.22 (go.mod:3-5). Configuration: the daemon…
- [agent-only, unverified] Checked: (1) All docker/docker imports in the snapshot - confirmed only client and types APIs used, no daemon/network code. (2) All docker docker client method calls - only ImageInspectWithRaw, ImageHistory, ImageSave, ImageLoad, ImageTag, ImageRemove. (3) Integration tests (integration/docker_engin…

## Affected, fixed, and unverified implementations

- `adv-01` **github.com/docker/docker** `Go` — **affected** (binding=`alias-resolved`, scope: advisory entry)
  - range: introduced=26.0.0+incompatible fixed=- last_affected=-
  - range: introduced=- fixed=26.0.2+incompatible last_affected=-

## Exploitation conditions — established vs unknown

- **code reachability:** **UNKNOWN** (level `MODULE`, basis `deterministic`) — the affected module github.com/docker/docker is present, but package-level reachability of the vulnerable code is undecided at the recorded scope
  - limit: module presence alone does not establish that the advisory package is compiled in
- **attack-surface availability:** **UNKNOWN** (level `NONE`, basis `none`) — no deterministic listener/socket fact at this scope — runtime attack-surface availability is unknown
  - limit: bounded static scans do not prove absence; runtime availability requires runtime evidence (level RUNTIME_AVAILABLE)
- **proven attacker exploitability:** **NOT_ESTABLISHED** (level `NONE`, basis `none`) — attacker exploitability is not established: package reachability and an agent-described scenario do not prove socket availability, attacker access, malformed-message delivery, or a resulting panic
  - limit: NOT_ESTABLISHED means not proven, never proven impossible; it requires a retained dynamic trace, runtime observation, or reproduction
- established predicates:
  - `EC-0001` [deterministic/SUPPORTED] the affected component (github.com/docker/docker) is present in the resolved module graph
  - `EC-0002` [deterministic/SUPPORTED] the deployed product uses github.com/docker/docker at a version inside the advisory's affected ranges
- unknown / open predicates:
  - `EC-0003` [deterministic/UNKNOWN] whether product code reaches the affected package is undecided
  - `EC-0004` [deterministic/UNKNOWN] whether the affected code is build-relevant under the recorded context is undecided
  - `EC-0005` [deterministic/UNKNOWN] a runtime configuration/environment predicate must hold for exploitation (attacker reachability, feature flags, deployment exposure); static source evidence cannot decide it
  - `EC-0006` [agent/OPEN] An attacker would need to invoke Docker's network creation APIs (e.g., via Docker API with NetworkCreate requests) on a Docker daemon using a version between 26.0.0 and 26.0.2 on a host with IPv4-only network interfaces. Trivy does not expose Docker API network endpoints, does not create Docker networks, and does not call any network-related Docker client APIs. There is no attack-reachable path from Trivy's attack surfaces (image scanning via CLI, OCI artifact processing, registry operations) to the vulnerable code.

## Main justification

- preserved agent category: `code_not_reachable` (never rewritten)
- classification review: class `NON_APPLICABLE`, status **UNKNOWN**
  - limit: no verified non-applicability basis (component_absent|version_fixed|package_not_in_import_closure|sdk_vs_daemon_distinction) resolves in verified_facts — the preserved category is retained but not established
- basis `component_present_affected` [ESTABLISHED/deterministic]: the affected component github.com/docker/docker is present at an advisory-affected version — refs: fact-obs-0008, fact-obs-0008, obs:OBS-0008
- basis `sdk_vs_daemon_distinction` [PROVISIONAL/agent]: agent-named basis: the product uses the component's client/SDK surface while the advisory defect lives in the daemon/server implementation — refs: A-0001, A-0002, A-0003, A-0004, A-0005, A-0006
- evidence chain: fact-obs-0008, A-0001, A-0002, A-0003, A-0004, A-0005, A-0006

## Recommendation — what to check or fix next

- triage action: **needs review** — the research contract forbids authoritative dispositions; a human must adjudicate the recorded claims and unknowns
- bounds: all findings are scoped to the snapshot tree and the stated build context; no runtime, delivery or deployment claim is made
- `R-0001` (human) review every verified_fact against its persisted artifact, then adjudicate agent assertions and unknowns
- `R-0002` (operator) capture exact source bytes or a reproducible static recipe proving the agent's named applicability basis (e.g. client/SDK-only use vs the daemon/server defect surface), then adjudicate the basis

## Decision-changing unknowns

- `U-0001` UNKNOWN: module_usage check did not produce a result (TIMEOUT)
  - could flip: code_reachability status (the module_usage check that could decide it did not complete)
  - follow-up: rerun or scope-down the check; its status is TIMEOUT, never an absence proof
- `U-0003` UNKNOWN: find_entrypoints check did not produce a result (ERROR)
  - could flip: attack_surface_availability status (the find_entrypoints check that could decide it did not complete)
  - follow-up: rerun or scope-down the check; its status is ERROR, never an absence proof

## Scope, provenance, and disposition

- run_id: `research-CVE-2024-32473-1791799609` | mode `experimental-research-v1` / schema `research-report/1`
- contract_extensions: `slice2-fidelity/1`
- started: 2026-10-12T10:06:49Z — finished: 2026-10-12T10:11:13Z | deterministic_only=false
- timeouts (ms): overall=1800000 deterministic=60000 agent=900000
- snapshot: `<VA_VEXBENCH>/repos/aquasecurity/trivy/37da98df45f6014fcd5f1744e2e26351b61d2a02` @ `37da98df45f6014fcd5f1744e2e26351b61d2a02` (content_hash `7fcadd51adb044d776a1ac74404e7832da5485f12ce6ea989d9de6a1540560f5`)
- build context: darwin/arm64 tags=[] vendor=false | analysis go `go version go1.26.1 darwin/arm64`
- release go: `go1.22.0`
- advisory: GO-2024-2737 from frozen_file (`eval/agent7/advisories/trivy-32473.json`)
- advisory sha256: raw `5c4dd340e0a4490e1fcb51e7bf49ea8c13a4f7c33dd5dce9d1a4154e2277fe5c` canonical `50ee8772e189732d7a9d095b33e47507476d1c819f50c7a292d15a102aa1d04c`
- harness: `<VA_VEXBENCH>/agent-ctl` @ `80cddeac3132826bfd47227ad59b2e6618a681bd`
- image: `vex-bench-go-opencode-e6:latest` (sha256:c85bc1df0f7e89b370c5ef552cd624bba1e49c2cb07005c8946be557b7379ba1)
- prompt: `eval/agent7/prompts/r0-v1.txt` sha256 `55b01e9a505bd058cb7be568f08c0e58364b8048e5acea030a14534f7031a0ae`
- disposition: `REVIEW_REQUIRED` (auto_close=false) — research lane output supports human triage only: evidence is scope-bounded, agent claims are unverified hypotheses, and the contract forbids VERIFIED/FALSE/AUTO_CLOSE dispositions
- forbidden classes: `VERIFIED`, `FALSE`, `AUTO_CLOSE`

## Applicability basis

- `component_present_affected` [ESTABLISHED/deterministic] the affected component github.com/docker/docker is present at an advisory-affected version
  - verified refs: fact-obs-0008
  - refs: fact-obs-0008, obs:OBS-0008
- `sdk_vs_daemon_distinction` [PROVISIONAL/agent] agent-named basis: the product uses the component's client/SDK surface while the advisory defect lives in the daemon/server implementation
  - refs: A-0001, A-0002, A-0003, A-0004, A-0005, A-0006
  - limit: agent-stated only; no deterministic source bytes or reproducible recipe currently proves the SDK-vs-daemon distinction

## Contradictions and limitations

_No contradictions recorded._
- section limit: downgraded per §3.2: classification_review is UNKNOWN — preserved agent statements remain unverified agent assertions
- section limit: downgraded per §3.2: classification_review is UNKNOWN — preserved agent statements remain unverified agent assertions
- applicability limit: advisory names no affected packages for the selected module; package presence undecidable

## Preserved agent statements (unverified)

- agent_output.status: `OK`
- category (original, never rewritten): `code_not_reachable`
- attempt: `attempt-0002`
- reasoning: The affected component github.com/docker/docker v26.0.1+incompatible is present in the snapshot (go.mod:45, in the range 26.0.0+incompatible to before 26.0.2+incompatible as specified by the advisory GO-2024-2737). However, CVE-2024-32473 affects Docker's network creation code (IPv6 enabled on IPv4-only network interfaces), specifically in the Docker daemon's network layer. Trivy uses the docker/docker client only for read-only image operations: ImageInspectWithRaw (docker.go:40,43), ImageHistory (docker.go:49), ImageSave (docker.go:66 via imageOpener), and ImageLoad/ImageTag/ImageRemove in tests (docker_engine_test.go:240,246,254). A full search for ContainerCreate, NetworkCreate, NetworkConnect, NetworkDisconnect, VolumeCreate, or any network/container/volume creation APIs found no matches in the entire snapshot. The vulnerable code path in docker/docker requires invocation of Docker network management APIs, which Trivy never calls. Therefore, the vulnerable surface has no execution path from any attack surface in Trivy's analyzed scope.
- `A-0001` [MODEL_HYPOTHESIS/OPEN] category=code_not_reachable: The affected component github.com/docker/docker v26.0.1+incompatible is present in the snapshot (go.mod:45, in the range 26.0.0+incompatible to before 26.0.2+incompatible as specified by the advisory GO-2024-2737). However, CVE-2024-32473 affects Docker's network creation code (IPv6 enabled on IPv4-only network interfaces), specifically in the Docker daemon's network layer. Trivy uses the docker/docker client only for read-only image operations: ImageInspectWithRaw (docker.go:40,43), ImageHistory (docker.go:49), ImageSave (docker.go:66 via imageOpener), and ImageLoad/ImageTag/ImageRemove in tests (docker_engine_test.go:240,246,254). A full search for ContainerCreate, NetworkCreate, NetworkConnect, NetworkDisconnect, VolumeCreate, or any network/container/volume creation APIs found no match…
  - original text: category=code_not_reachable: The affected component github.com/docker/docker v26.0.1+incompatible is present in the snapshot (go.mod:45, in the range 26.0.0+incompatible to before 26.0.2+incompatible as specified by the advisory GO-2024-2737). However, CVE-2024-32473 affects Docker's network creation code (IPv6 enabled on IPv4-only network interfaces), specifically in the Docker daemon's network layer. Trivy uses the docker/docker client only for read-only image operations: ImageInspectWithRaw (…
  - source: `$.category + $.reasoning` in retained answer
- `A-0002` [MODEL_HYPOTHESIS/OPEN] CVE-2024-32473 allows IPv6 to be enabled on IPv4-only network interfaces in the Docker daemon. This is a network configuration defect where Docker creates network interfaces with IPv6 support even when the underlying host interface is IPv4-only, potentially causing unintended network exposure or misconfiguration. The effect occurs because the affected docker/docker code path handles network creation/management in the Docker daemon, not in the client library.
  - source: `$.assessment.vulnerability_mechanism` in retained answer
- `A-0003` [EVIDENCE_SUPPORTED/OPEN] The advisory GO-2024-2737 binds to module github.com/docker/docker, introduced in 26.0.0+incompatible and fixed in 26.0.2+incompatible. The vulnerable code resides in the Docker daemon's network layer within the docker/docker module. In this Trivy snapshot, docker/docker is imported as a dependency at go.mod:45 (v26.0.1+incompatible). The code in Trivy that uses docker/docker (pkg/fanal/image/daemon/docker.go:7-9 imports github.com/docker/docker/client) only calls read-only image APIs (ImageInspectWithRaw, ImageHistory, ImageSave). No network creation or management APIs are invoked.
  - source: `$.assessment.root_cause` in retained answer
- `A-0004` [MODEL_HYPOTHESIS/OPEN] An attacker would need to invoke Docker's network creation APIs (e.g., via Docker API with NetworkCreate requests) on a Docker daemon using a version between 26.0.0 and 26.0.2 on a host with IPv4-only network interfaces. Trivy does not expose Docker API network endpoints, does not create Docker networks, and does not call any network-related Docker client APIs. There is no attack-reachable path from Trivy's attack surfaces (image scanning via CLI, OCI artifact processing, registry operations) to the vulnerable code.
  - source: `$.assessment.attack_scenario` in retained answer
- `A-0005` [MODEL_HYPOTHESIS/OPEN] Trivy is a container security scanner (github.com/aquasecurity/trivy, per go.mod:1). It uses the Docker client (pkg/fanal/image/daemon/docker.go) to inspect and save container images for scanning when the Docker engine driver is used. Build: Go module, Go 1.22 (go.mod:3-5). Configuration: the daemon image feature is a user-invoked capability via trivy image --platform or similar flags. Platform: Linux (container scanning target). The snapshot does not establish any Docker daemon network configuration or deployment context. Unknown: whether downstream builds of Trivy might link additional docker/docker code paths not present in this snapshot, and whether any future plugin or extension system could introduce network-related code.
  - source: `$.assessment.product_exposure` in retained answer
- `A-0006` [MODEL_HYPOTHESIS/OPEN] Checked: (1) All docker/docker imports in the snapshot - confirmed only client and types APIs used, no daemon/network code. (2) All docker docker client method calls - only ImageInspectWithRaw, ImageHistory, ImageSave, ImageLoad, ImageTag, ImageRemove. (3) Integration tests (integration/docker_engine_test.go) only test image loading, inspection, and removal. (4) Containerd and podman daemon readers (containerd.go, podman.go) do not use docker network APIs. (5) Searched for any network creation API calls - zero matches. Not fully explored: transitive dependencies within docker/docker that may have different usage patterns not visible from import analysis alone (the docker/docker client package may internally reference network-related types even if only image APIs are called). However, Go packages are typically not linked if their symbols are not referenced, and the CVE affects daemon-side network logic, not client-side code.
  - source: `$.assessment.alternative_paths` in retained answer

## Evidence register

- ref `adv:GO-2024-2737` (advisory) `eval/agent7/advisories/trivy-32473.json` frozen document
  - materiality: `MATERIAL`
  - raw bytes: `eval/agent7/advisories/trivy-32473.json` sha256 `5c4dd340e0a4490e1fcb51e7bf49ea8c13a4f7c33dd5dce9d1a4154e2277fe5c` (frozen advisory document)
  - reproducible: FILE `eval/agent7/advisories/trivy-32473.json` in `-` → sha256 `50ee8772e189732d7a9d095b33e47507476d1c819f50c7a292d15a102aa1d04c`
- ref `agent-src:FROZEN_ADVISORY - advisory GO-2024-2737, affected entries: github.com/docker/docker introduced=26.0.0+incompatible fixed=26.0.2+incompatible` (agent-source) `agent/attempt-0002/answer.txt` agent-stated
- ref `agent-src:assessment.altpaths` (agent-source) `agent/attempt-0002/answer.txt` retained final answer
- ref `agent-src:assessment.attack` (agent-source) `agent/attempt-0002/answer.txt` retained final answer
- ref `agent-src:assessment.exposure` (agent-source) `agent/attempt-0002/answer.txt` retained final answer
- ref `agent-src:assessment.mechanism` (agent-source) `agent/attempt-0002/answer.txt` retained final answer
- ref `agent-src:assessment.rootcause` (agent-source) `agent/attempt-0002/answer.txt` retained final answer
- ref `agent-src:final-answer` (agent-source) `agent/attempt-0002/answer.txt` retained final answer
- ref `agent-src:go.mod:1 - module github.com/aquasecurity/trivy` (agent-source) `agent/attempt-0002/answer.txt` agent-stated
- ref `agent-src:go.mod:45 - github.com/docker/docker v26.0.1+incompatible dependency declaration` (agent-source) `agent/attempt-0002/answer.txt` agent-stated
- ref `agent-src:integration/docker_engine_test.go:14-15 - test imports for docker client` (agent-source) `agent/attempt-0002/answer.txt` agent-stated
- ref `agent-src:integration/docker_engine_test.go:230-267 - test Docker API calls (ImageRemove, ImageLoad, ImageTag)` (agent-source) `agent/attempt-0002/answer.txt` agent-stated
- ref `agent-src:pkg/fanal/image/daemon/containerd.go:19-20 - imports of github.com/docker/docker/api/types` (agent-source) `agent/attempt-0002/answer.txt` agent-stated
- ref `agent-src:pkg/fanal/image/daemon/docker.go:40,43,49,66 - Docker client method calls (ImageInspectWithRaw, ImageHistory, ImageSave)` (agent-source) `agent/attempt-0002/answer.txt` agent-stated
- ref `agent-src:pkg/fanal/image/daemon/docker.go:7 - import of github.com/docker/docker/client` (agent-source) `agent/attempt-0002/answer.txt` agent-stated
- ref `agent-src:pkg/fanal/image/daemon/image.go:11-13 - imports of github.com/docker/docker/api/types` (agent-source) `agent/attempt-0002/answer.txt` agent-stated
- ref `agent-src:residual_questions` (agent-source) `agent/attempt-0002/answer.txt` retained final answer
- ref `obs:OBS-0001` (observation) `artifacts/obs-0001.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0001.json` sha256 `6037578bb28833c7e02bed4e537b4d1342d241b723c8942538015cca5a10ee96` (observation)
- ref `obs:OBS-0002` (observation) `artifacts/obs-0002.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0002.json` sha256 `4a94a80345294a5aa11bcad167e897526b53b78a840c32e2feacefb6c37403b1` (observation)
- ref `obs:OBS-0003` (observation) `artifacts/obs-0003.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0003.json` sha256 `15225471dc86c46cca3a0958e675ea565d6f80526baa06c9c39f03ed8debcba5` (observation)
- ref `obs:OBS-0004` (observation) `artifacts/obs-0004.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0004.json` sha256 `341ae774e91280f2d1d5ffbe8267fdc4da94748834a9856bc141434f2853011a` (observation)
- ref `obs:OBS-0005` (observation) `artifacts/obs-0005.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0005.json` sha256 `8387fa94223c6eba39a18ff50df2686d1d33272445d7e006db4234558f5be48a` (observation)
- ref `obs:OBS-0006` (observation) `artifacts/obs-0006.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0006.json` sha256 `5a554e3b302640e9d208455524b78052aab14c64d369f0275ecac164d2fc1434` (observation)
- ref `obs:OBS-0007` (observation) `artifacts/obs-0007.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0007.json` sha256 `360b2073fe5256a9a412a0392718414818acc15517580c2dc50e516d471efe78` (observation)
- ref `obs:OBS-0008` (observation) `artifacts/obs-0008.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0008.json` sha256 `71822044477fb26922413990681cbce63e0e5a7f9a336ed5b4bfece091b1ef20` (observation)
- ref `obs:OBS-0009` (observation) `artifacts/obs-0009.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0009.json` sha256 `fa54795be9e91648b269e1cd3f52bca5ab43cb94487cdb9113b58808e38293c3` (observation)
- ref `obs:OBS-0010` (observation) `artifacts/obs-0010.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0010.json` sha256 `62e2ea72dc84a20554f9a4cdbea6f362ae7d0a44a286c9005bad415729ed5b5b` (observation)
- ref `obs:OBS-0011` (observation) `artifacts/obs-0011.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0011.json` sha256 `65a9237d4c304d6cfc15aaaf108c9fbf15890d97d10cdf6df009e2990abca825` (observation)
- ref `obs:OBS-0012` (observation) `artifacts/obs-0012.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0012.json` sha256 `bbbae0fa1b1b8de8e163b795983e7d47591ccac8082bbf7817ba191f7a583b2f` (observation)
- ref `obs:OBS-0013` (observation) `artifacts/obs-0013.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0013.json` sha256 `d9345ace4c47be9b41e8259f7838f372d485b1285d71b78cbc4621e7cd079d50` (observation)
- ref `obs:OBS-0014` (observation) `artifacts/obs-0014.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0014.json` sha256 `da923d5d93c174c2b48de7b0254c4209c0bdeda14b252d48171f040933bb7b97` (observation)
- ref `obs:OBS-0015` (observation) `artifacts/obs-0015.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0015.json` sha256 `b0c1e5fd0a3f6762e73e7f462e1e81271be7bc51f3acd949a0c04b24b6dee01c` (observation)

## Attempt and retry history

- `attempt-0001` (deterministic #1) status `OK` reason `initial` — initial deterministic lane pass (strict evidencetools session)
  - 2026-10-12T10:06:49Z → 2026-10-12T10:08:04Z | original_preserved=true
  - result: `deterministic-facts.json` sha256 `c0dda0d57db61d4010b1c04e45d6cfa17061c3a9bfb1c31ecff70a524eafc995`
  - extraction: `NOT_APPLICABLE` (NONE), 0 candidate(s), selected -1
- `attempt-0002` (agent #2) status `OK` reason `initial` — initial agent assessment
  - 2026-10-12T10:09:49Z → 2026-10-12T10:11:13Z | original_preserved=true
  - result: `agent/attempt-0002/result.json` sha256 `aa497caf93d5f2ccf130f2daa5d9679915243b24a2f9dff716af8fb0eed621c0`
  - extraction: `VALID` (NONE), 1 candidate(s), selected 0
    - candidate[0] VALID category=code_not_reachable raw `f36f3cc7968dd4da52b0d5c3d30a0b4141d8ad6d61cbe528e289f849070dd848`

## Appendix

### Detailed unknowns

- `U-0002` UNKNOWN:  check did not produce a result (ERROR)
  - reason: context deadline exceeded
  - follow-up: rerun or scope-down the check; its status is ERROR, never an absence proof
- `U-0004` UNKNOWN:  check did not produce a result (ERROR)
  - reason: context deadline exceeded
  - follow-up: rerun or scope-down the check; its status is ERROR, never an absence proof
- `U-0005` UNKNOWN:  check did not produce a result (ERROR)
  - reason: context deadline exceeded
  - follow-up: rerun or scope-down the check; its status is ERROR, never an absence proof
- `U-0006` UNKNOWN:  check did not produce a result (ERROR)
  - reason: context deadline exceeded
  - follow-up: rerun or scope-down the check; its status is ERROR, never an absence proof
- `U-0007` UNKNOWN: run_govulncheck check did not produce a result (UNSUPPORTED)
  - reason: strict profile requires --govulndb to pin the vulnerability database
  - follow-up: rerun or scope-down the check; its status is UNSUPPORTED, never an absence proof

### Full deterministic facts

- `fact-obs-0001` snapshot <VA_VEXBENCH>/repos/aquasecurity/trivy/37da98df45f6014fcd5f1744e2e26351b61d2a02 contained, replaces confined, content hash 7fcadd51adb044d776a1ac74404e7832da5485f12ce6ea989d9de6a1540560f5
  - tool: `repository-preflight` (izyan/research-lane go1.26.1) | coverage `COMPLETE` | scope: VerifyContained + CheckPathReplacements + ContentHash over the snapshot tree
  - command: `repository-preflight {"snapshot":"<VA_VEXBENCH>/repos/aquasecurity/trivy/37da98df45f6014fcd5f1744e2e26351b61d2a02"}`
  - artifact: `artifacts/obs-0001.json` sha256 `6037578bb28833c7e02bed4e537b4d1342d241b723c8942538015cca5a10ee96` | data_digest `a1025078125e59dadf14c466debf08b9c86b709ae79c9fac8a90ea85125da1fd`
  - provenance: obs `OBS-0001` / deterministic-lane
  - materiality: `SUPPORTING`
  - raw bytes: `artifacts/obs-0001.json` sha256 `6037578bb28833c7e02bed4e537b4d1342d241b723c8942538015cca5a10ee96`
  - reproducible: COMMAND `repository-preflight {"snapshot":"<VA_VEXBENCH>/repos/aquasecurity/trivy/37da98df45f6014fcd5f1744e2e26351b61d2a02"}` → `a1025078125e59dadf14c466debf08b9c86b709ae79c9fac8a90ea85125da1fd`
- `fact-obs-0002` snapshot identity 37da98df45f6014fcd5f1744e2e26351b61d2a02: go directive 1.22, release toolchain "go1.22.0", darwin/arm64
  - tool: `repository-snapshot` (izyan/research-lane go1.26.1) | coverage `COMPLETE` | scope: repository.Service.Snapshot (git/go probes + static release-evidence scan, no repo code executed)
  - command: `repository-snapshot {"GOOS":"","GOARCH":"","BuildTags":null,"BinaryPath":"","ReleaseGoVersion":"","TrustedPeer":false,"DeployManifests":null,"DeployArchive":"","PerimeterOverride":"","ExternalCommitSHA":"37da98df45f6014fcd5f1744e2e26351b61d2a02","GoBin":"go","Env":null}`
  - artifact: `artifacts/obs-0002.json` sha256 `4a94a80345294a5aa11bcad167e897526b53b78a840c32e2feacefb6c37403b1` | data_digest `2336183a87726d8b3148de2c53d4d958b5f94afce736245a5f6f4f5bda9e920c`
  - provenance: obs `OBS-0002` / deterministic-lane
  - materiality: `SUPPORTING`
  - raw bytes: `artifacts/obs-0002.json` sha256 `4a94a80345294a5aa11bcad167e897526b53b78a840c32e2feacefb6c37403b1`
  - reproducible: COMMAND `repository-snapshot {"GOOS":"","GOARCH":"","BuildTags":null,"BinaryPath":"","ReleaseGoVersion":"","TrustedPeer":false,"DeployManifests":null,"DeployArchive":"","PerimeterOverride":"","ExternalCommitSHA":"37da98df45f6014fcd5f1744e2e26351b61d2a02","GoBin":"go","Env":null}` → `2336183a87726d8b3148de2c53d4d958b5f94afce736245a5f6f4f5bda9e920c`
- `fact-obs-0003` frozen advisory CVE-2024-32473 resolved to GO-2024-2737 (1 affected entries, source frozen_file)
  - tool: `advisory-load` (izyan/research-lane go1.26.1) | coverage `COMPLETE` | scope: FileSource(eval/agent7/advisories/trivy-32473.json) with alias enrichment disabled; no network
  - command: `advisory-load {"cve":"CVE-2024-32473","path":"eval/agent7/advisories/trivy-32473.json","source":"frozen_file"}`
  - artifact: `artifacts/obs-0003.json` sha256 `15225471dc86c46cca3a0958e675ea565d6f80526baa06c9c39f03ed8debcba5` | data_digest `c299a34112356f0ac0c72483a17149fe70c9782b8ca491950db3d4c4baf94199`
  - provenance: obs `OBS-0003` / deterministic-lane
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0003.json` sha256 `15225471dc86c46cca3a0958e675ea565d6f80526baa06c9c39f03ed8debcba5`
  - reproducible: COMMAND `advisory-load {"cve":"CVE-2024-32473","path":"eval/agent7/advisories/trivy-32473.json","source":"frozen_file"}` → `c299a34112356f0ac0c72483a17149fe70c9782b8ca491950db3d4c4baf94199`
- `fact-obs-0004` snapshot 37da98df45f6014fcd5f1744e2e26351b61d2a02: content hash 7fcadd51adb044d776a1ac74404e7832da5485f12ce6ea989d9de6a1540560f5, go directive 1.22, 0 replace directives
  - tool: `get_product_snapshot` (izyan-evidence-tools/0.1.0) | coverage `COMPLETE` | scope: this snapshot's build context and module manifest facts
  - command: `get_product_snapshot {}`
  - artifact: `artifacts/obs-0004.json` sha256 `341ae774e91280f2d1d5ffbe8267fdc4da94748834a9856bc141434f2853011a` | data_digest `a60cf64454049485ca3e2c5f71247d28c101065adf14dcf1bf0f68a62a08e9fc`
  - provenance: obs `OBS-0004` / deterministic-lane
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0004.json` sha256 `341ae774e91280f2d1d5ffbe8267fdc4da94748834a9856bc141434f2853011a`
  - reproducible: COMMAND `get_product_snapshot {}` → `a60cf64454049485ca3e2c5f71247d28c101065adf14dcf1bf0f68a62a08e9fc`
- `fact-obs-0005` normalized advisory record for CVE-2024-32473 (resolved id GO-2024-2737)
  - tool: `get_vulnerability` (izyan-evidence-tools/0.1.0) | coverage `COMPLETE` | scope: OSV-compatible advisory record for CVE-2024-32473
  - command: `get_vulnerability {}`
  - artifact: `artifacts/obs-0005.json` sha256 `8387fa94223c6eba39a18ff50df2686d1d33272445d7e006db4234558f5be48a` | data_digest `c57593a970bbfd7f89c7f9cdd3fffcd6fc57f5b5c65417cb740d5b6ee882157e`
  - provenance: obs `OBS-0005` / deterministic-lane
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0005.json` sha256 `8387fa94223c6eba39a18ff50df2686d1d33272445d7e006db4234558f5be48a`
  - reproducible: COMMAND `get_vulnerability {}` → `c57593a970bbfd7f89c7f9cdd3fffcd6fc57f5b5c65417cb740d5b6ee882157e`
  - limit: advisory declares no affected symbols; symbol-level queries need an explicit subject
  - limit: severity provenance not declared by the advisory source
- `fact-obs-0006` dependency graph: 1019 module(s) resolved via go list -m -json all
  - tool: `get_dependency_graph` (izyan-evidence-tools/0.1.0) | coverage `COMPLETE` | scope: module list of <VA_VEXBENCH>/repos/aquasecurity/trivy/37da98df45f6014fcd5f1744e2e26351b61d2a02 (go list -m -json all)
  - command: `get_dependency_graph {}`
  - artifact: `artifacts/obs-0006.json` sha256 `5a554e3b302640e9d208455524b78052aab14c64d369f0275ecac164d2fc1434` | data_digest `8232638d12cf4a8264bae626111854d87137b3b8d44e7939662c7637ec731c6a`
  - provenance: obs `OBS-0006` / deterministic-lane
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0006.json` sha256 `5a554e3b302640e9d208455524b78052aab14c64d369f0275ecac164d2fc1434`
  - reproducible: COMMAND `get_dependency_graph {}` → `8232638d12cf4a8264bae626111854d87137b3b8d44e7939662c7637ec731c6a`
- `fact-obs-0007` module github.com/docker/docker resolved to version v26.0.1+incompatible
  - tool: `get_module_version` (izyan-evidence-tools/0.1.0) | coverage `COMPLETE` | scope: resolved module list of <VA_VEXBENCH>/repos/aquasecurity/trivy/37da98df45f6014fcd5f1744e2e26351b61d2a02 (go list -m -json all)
  - command: `get_module_version {"module":"github.com/docker/docker"}`
  - artifact: `artifacts/obs-0007.json` sha256 `360b2073fe5256a9a412a0392718414818acc15517580c2dc50e516d471efe78` | data_digest `76cc009f2727a27d0c43db0704eb0916e465142277edbad9b03abf1158b2478a`
  - provenance: obs `OBS-0007` / deterministic-lane
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0007.json` sha256 `360b2073fe5256a9a412a0392718414818acc15517580c2dc50e516d471efe78`
  - reproducible: COMMAND `get_module_version {"module":"github.com/docker/docker"}` → `76cc009f2727a27d0c43db0704eb0916e465142277edbad9b03abf1158b2478a`
- `fact-obs-0008` applicability chain for GO-2024-2737: module_present=TRUE version_affected=TRUE package_present=UNKNOWN build_relevant=UNKNOWN (selected [github.com/docker/docker])
  - tool: `affected-resolve` (izyan/research-lane go1.26.1) | coverage `PARTIAL` | scope: affected.GoResolver.Resolve over the snapshot module graph and import closure (go list -m, go list -deps under strict toolchain env)
  - command: `affected-resolve {"vuln":"GO-2024-2737"}`
  - artifact: `artifacts/obs-0008.json` sha256 `71822044477fb26922413990681cbce63e0e5a7f9a336ed5b4bfece091b1ef20` | data_digest `415791d3e35689829d2b46a9cff55ee3ce167a57908967aecb248c111b6b6882`
  - provenance: obs `OBS-0008` / deterministic-lane
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0008.json` sha256 `71822044477fb26922413990681cbce63e0e5a7f9a336ed5b4bfece091b1ef20`
  - reproducible: COMMAND `affected-resolve {"vuln":"GO-2024-2737"}` → `415791d3e35689829d2b46a9cff55ee3ce167a57908967aecb248c111b6b6882`
  - limit: advisory names no affected packages for the selected module; package presence undecidable
  - limit: observation payload truncated at 262144 bytes (full payload 69467104 bytes, sha256 7691ba8a7bc1fc4cab4dbdfbb2eb591bec3e0991ef3099aa3964cddf3384fd4c); stored bytes are a prefix of the tool result, not the full result

### Full exploitation conditions

- `EC-0001` [deterministic/required/SUPPORTED/code_reachability] the affected component (github.com/docker/docker) is present in the resolved module graph
-   - refs:
  - obs:OBS-0008
  - fact-obs-0008
- `EC-0002` [deterministic/required/SUPPORTED/code_reachability] the deployed product uses github.com/docker/docker at a version inside the advisory's affected ranges
-   - refs:
  - obs:OBS-0008
  - fact-obs-0008
- `EC-0003` [deterministic/required/UNKNOWN/code_reachability] whether product code reaches the affected package is undecided
-   - refs:
  - obs:OBS-0008
  - fact-obs-0008
-   - limits:
  - follow-up: the advisory names no affected package for this module, or go list coverage was partial; run module_usage/symbol scans under the full build context
- `EC-0004` [deterministic/required/UNKNOWN/code_reachability] whether the affected code is build-relevant under the recorded context is undecided
-   - refs:
  - obs:OBS-0008
  - fact-obs-0008
-   - limits:
  - follow-up: resolve package presence/build relevance (requires go list -deps coverage)
- `EC-0005` [deterministic/required/UNKNOWN/attack_surface_availability] a runtime configuration/environment predicate must hold for exploitation (attacker reachability, feature flags, deployment exposure); static source evidence cannot decide it
-   - refs:
  - obs:OBS-0011
-   - limits:
  - follow-up: confirm deployment posture (listeners, auth, network exposure, config) against the recorded entry-point facts
- `EC-0006` [agent/unknown/OPEN/other] An attacker would need to invoke Docker's network creation APIs (e.g., via Docker API with NetworkCreate requests) on a Docker daemon using a version between 26.0.0 and 26.0.2 on a host with IPv4-only network interfaces. Trivy does not expose Docker API network endpoints, does not create Docker networks, and does not call any network-related Docker client APIs. There is no attack-reachable path from Trivy's attack surfaces (image scanning via CLI, OCI artifact processing, registry operations) to the vulnerable code.
-   - refs:
  - A-0004

### Full assessment sections

#### vulnerability_mechanism — PARTIAL

CVE-2024-32473 allows IPv6 to be enabled on IPv4-only network interfaces in the Docker daemon. This is a network configuration defect where Docker creates network interfaces with IPv6 support even when the underlying host interface is IPv4-only, potentially causing unintended network exposure or misconfiguration. The effect occurs because the affected docker/docker code path handles network creation/management in the Docker daemon, not in the client library.

- **[deterministic/SUPPORTED]**
  - subject: `GO-2024-2737`
  - statement: advisory GO-2024-2737 states: IPv6 enabled on IPv4-only network interfaces in github.com/docker/docker
  - scope: frozen advisory document
-   - refs:
  - fact-obs-0003
- **[agent/OPEN]**
  - statement: CVE-2024-32473 allows IPv6 to be enabled on IPv4-only network interfaces in the Docker daemon. This is a network configuration defect where Docker creates network interfaces with IPv6 support even when the underlying host interface is IPv4-only, potentially causing unintended network exposure or misconfiguration. The effect occurs because the affected docker/docker code path handles network creation/management in the Docker daemon, not in the client library.
  - scope: agent assessment (snapshot-read scope as stated)
-   - refs:
  - A-0002

#### root_cause — PARTIAL

The advisory GO-2024-2737 binds to module github.com/docker/docker, introduced in 26.0.0+incompatible and fixed in 26.0.2+incompatible. The vulnerable code resides in the Docker daemon's network layer within the docker/docker module. In this Trivy snapshot, docker/docker is imported as a dependency at go.mod:45 (v26.0.1+incompatible). The code in Trivy that uses docker/docker (pkg/fanal/image/daemon/docker.go:7-9 imports github.com/docker/docker/client) only calls read-only image APIs (ImageInspectWithRaw, ImageHistory, ImageSave). No network creation or management APIs are invoked.

- **[agent/OPEN]**
  - statement: The advisory GO-2024-2737 binds to module github.com/docker/docker, introduced in 26.0.0+incompatible and fixed in 26.0.2+incompatible. The vulnerable code resides in the Docker daemon's network layer within the docker/docker module. In this Trivy snapshot, docker/docker is imported as a dependency at go.mod:45 (v26.0.1+incompatible). The code in Trivy that uses docker/docker (pkg/fanal/image/daemon/docker.go:7-9 imports github.com/docker/docker/client) only calls read-only image APIs (ImageInspectWithRaw, ImageHistory, ImageSave). No network creation or management APIs are invoked.
  - scope: agent assessment (snapshot-read scope as stated)
-   - refs:
  - A-0003

#### attack_scenario — UNKNOWN

UNKNOWN: a non-applicability attack conclusion is not established (no verified applicability basis); follow-up: capture exact source bytes or a reproducible static recipe for the agent's named applicability basis, then adjudicate the non-applicability conclusion; agent-stated: An attacker would need to invoke Docker's network creation APIs (e.g., via Docker API with NetworkCreate requests) on a Docker daemon using a version between 26.0.0 and 26.0.2 on a host with IPv4-only network interfaces. Trivy does not expose Docker API network endpoints, does not create Docker networks, and does not call any network-related Docker client APIs. There is no attack-reachable path fr…

- **[agent/OPEN]**
  - statement: An attacker would need to invoke Docker's network creation APIs (e.g., via Docker API with NetworkCreate requests) on a Docker daemon using a version between 26.0.0 and 26.0.2 on a host with IPv4-only network interfaces. Trivy does not expose Docker API network endpoints, does not create Docker networks, and does not call any network-related Docker client APIs. There is no attack-reachable path from Trivy's attack surfaces (image scanning via CLI, OCI artifact processing, registry operations) to the vulnerable code.
  - scope: agent assessment (snapshot-read scope as stated)
-   - refs:
  - A-0004
- limits:
  - downgraded per §3.2: classification_review is UNKNOWN — preserved agent statements remain unverified agent assertions

#### product_exposure — UNKNOWN

UNKNOWN: a non-applicability exposure conclusion is not established (no verified applicability basis); follow-up: capture exact source bytes or a reproducible static recipe for the agent's named applicability basis, then adjudicate the non-applicability conclusion; agent-stated: Trivy is a container security scanner (github.com/aquasecurity/trivy, per go.mod:1). It uses the Docker client (pkg/fanal/image/daemon/docker.go) to inspect and save container images for scanning when the Docker engine driver is used. Build: Go module, Go 1.22 (go.mod:3-5). Configuration: the daemon image feature is a user-invoked capability via trivy image --platform or similar flags. Platform: L…

- **[agent/OPEN]**
  - statement: Trivy is a container security scanner (github.com/aquasecurity/trivy, per go.mod:1). It uses the Docker client (pkg/fanal/image/daemon/docker.go) to inspect and save container images for scanning when the Docker engine driver is used. Build: Go module, Go 1.22 (go.mod:3-5). Configuration: the daemon image feature is a user-invoked capability via trivy image --platform or similar flags. Platform: Linux (container scanning target). The snapshot does not establish any Docker daemon network configuration or deployment context. Unknown: whether downstream builds of Trivy might link additional docker/docker code paths not present in this snapshot, and whether any future plugin or extension system could introduce network-related code.
  - scope: agent assessment (snapshot-read scope as stated)
-   - refs:
  - A-0005
- limits:
  - downgraded per §3.2: classification_review is UNKNOWN — preserved agent statements remain unverified agent assertions

#### alternative_paths — PARTIAL

Checked: (1) All docker/docker imports in the snapshot - confirmed only client and types APIs used, no daemon/network code. (2) All docker docker client method calls - only ImageInspectWithRaw, ImageHistory, ImageSave, ImageLoad, ImageTag, ImageRemove. (3) Integration tests (integration/docker_engine_test.go) only test image loading, inspection, and removal. (4) Containerd and podman daemon readers (containerd.go, podman.go) do not use docker network APIs. (5) Searched for any network creation API calls - zero matches. Not fully explored: transitive dependencies within docker/docker that may have different usage patterns not visible from import analysis alone (the docker/docker client package may internally reference network-related types even if only image APIs are called). However, Go packages are typically not linked if their symbols are not referenced, and the CVE affects daemon-side network logic, not client-side code.

- **[agent/OPEN]**
  - statement: Checked: (1) All docker/docker imports in the snapshot - confirmed only client and types APIs used, no daemon/network code. (2) All docker docker client method calls - only ImageInspectWithRaw, ImageHistory, ImageSave, ImageLoad, ImageTag, ImageRemove. (3) Integration tests (integration/docker_engine_test.go) only test image loading, inspection, and removal. (4) Containerd and podman daemon readers (containerd.go, podman.go) do not use docker network APIs. (5) Searched for any network creation API calls - zero matches. Not fully explored: transitive dependencies within docker/docker that may have different usage patterns not visible from import analysis alone (the docker/docker client package may internally reference network-related types even if only image APIs are called). However, Go packages are typically not linked if their symbols are not referenced, and the CVE affects daemon-side network logic, not client-side code.
  - scope: agent assessment (snapshot-read scope as stated)
-   - refs:
  - A-0006

#### evidence_quality — SUPPORTED

evidence base: 8 deterministic check(s) OK, 7 non-OK; evidence is scope-bounded per each observation's scope/limitations; agent stated: Evidence covers the relevant import declarations, method call sites, and the advisory binding. Coverage is strong for Trivy's docker/docker usage pattern (read-only image operations). Limitation: the internal code of the docker/docker v26.0.1+incompatible package itself is not present in this snapshot (it is fetched as a transitive dependency), so a full call-graph analysis within docker/docker is not possible. The classification relies on the absence of network-related method calls in the Trivy codebase and the known scope of the vulnerability (daemon network code).

- limits:
  - module_usage TIMEOUT: tool exceeded its 1m0s wall-clock timeout
  -  ERROR: context deadline exceeded
  - find_entrypoints ERROR: context deadline exceeded
  -  ERROR: context deadline exceeded
  -  ERROR: context deadline exceeded
  -  ERROR: context deadline exceeded
  - run_govulncheck UNSUPPORTED: strict profile requires --govulndb to pin the vulnerability database
  - applicability: advisory names no affected packages for the selected module; package presence undecidable

### Full open questions and residual questions

- `Q-0001` module_usage check did not produce a result (TIMEOUT)
  - subject/scope: U-0001 / report scope
  - next check: rerun or scope-down the check; its status is TIMEOUT, never an absence proof
  - why: left unresolved by the lanes' stated scope
- `Q-0002`  check did not produce a result (ERROR)
  - subject/scope: U-0002 / report scope
  - next check: rerun or scope-down the check; its status is ERROR, never an absence proof
  - why: left unresolved by the lanes' stated scope
- `Q-0003` find_entrypoints check did not produce a result (ERROR)
  - subject/scope: U-0003 / report scope
  - next check: rerun or scope-down the check; its status is ERROR, never an absence proof
  - why: left unresolved by the lanes' stated scope
- `Q-0004`  check did not produce a result (ERROR)
  - subject/scope: U-0004 / report scope
  - next check: rerun or scope-down the check; its status is ERROR, never an absence proof
  - why: left unresolved by the lanes' stated scope
- `Q-0005`  check did not produce a result (ERROR)
  - subject/scope: U-0005 / report scope
  - next check: rerun or scope-down the check; its status is ERROR, never an absence proof
  - why: left unresolved by the lanes' stated scope
- `Q-0006`  check did not produce a result (ERROR)
  - subject/scope: U-0006 / report scope
  - next check: rerun or scope-down the check; its status is ERROR, never an absence proof
  - why: left unresolved by the lanes' stated scope
- `Q-0007` run_govulncheck check did not produce a result (UNSUPPORTED)
  - subject/scope: U-0007 / report scope
  - next check: rerun or scope-down the check; its status is UNSUPPORTED, never an absence proof
  - why: left unresolved by the lanes' stated scope
- `Q-0008` Whether the docker/docker client package v26.0.1 internally includes and links network-related code that could be triggered implicitly (follow-up: build the Go modules and inspect the compiled dependency graph for docker/docker network package symbol references)
  - subject/scope:  / agent assessment
  - next check: agent-stated follow-up
  - why: left unresolved by the lanes' stated scope
- `Q-0009` Whether any Trivy plugins, extensions, or alternative import paths not present in this commit could invoke network APIs (follow-up: verify this snapshot captures all entry points for the analyzed build configuration)
  - subject/scope:  / agent assessment
  - next check: agent-stated follow-up
  - why: left unresolved by the lanes' stated scope
- `Q-0010` Whether the CVE affects client-side behavior during image operations in some edge case on hosts with specific network configurations (follow-up: review the full CVE description and Docker documentation for CVE-2024-32473 to determine if the vulnerability scope extends beyond daemon network creation)
  - subject/scope:  / agent assessment
  - next check: agent-stated follow-up
  - why: left unresolved by the lanes' stated scope

### Legacy evidence-quality details

- status: `SUPPORTED`
- summary: evidence base: 8 deterministic check(s) OK, 7 non-OK; evidence is scope-bounded per each observation's scope/limitations; agent stated: Evidence covers the relevant import declarations, method call sites, and the advisory binding. Coverage is strong for Trivy's docker/docker usage pattern (read-only image operations). Limitation: the internal code of the docker/docker v26.0.1+incompatible package itself is not present in this snapshot (it is fetched as a transitive dependency), so a full call-graph analysis within docker/docker is not possible. The classification relies on the absence of network-related method calls in the Trivy codebase and the known scope of the vulnerability (daemon network code).
- coverage:
  - repository-preflight: VerifyContained + CheckPathReplacements + ContentHash over the snapshot tree
  - repository-snapshot: repository.Service.Snapshot (git/go probes + static release-evidence scan, no repo code executed)
  - advisory-load: FileSource(eval/agent7/advisories/trivy-32473.json) with alias enrichment disabled; no network
  - get_product_snapshot: this snapshot's build context and module manifest facts
  - get_vulnerability: OSV-compatible advisory record for CVE-2024-32473
  - get_dependency_graph: module list of <VA_VEXBENCH>/repos/aquasecurity/trivy/37da98df45f6014fcd5f1744e2e26351b61d2a02 (go list -m -json all)
  - get_module_version: resolved module list of <VA_VEXBENCH>/repos/aquasecurity/trivy/37da98df45f6014fcd5f1744e2e26351b61d2a02 (go list -m -json all)
  - affected-resolve: affected.GoResolver.Resolve over the snapshot module graph and import closure (go list -m, go list -deps under strict toolchain env)
- limitations:
  - module_usage TIMEOUT: tool exceeded its 1m0s wall-clock timeout
  -  ERROR: context deadline exceeded
  - find_entrypoints ERROR: context deadline exceeded
  -  ERROR: context deadline exceeded
  -  ERROR: context deadline exceeded
  -  ERROR: context deadline exceeded
  - run_govulncheck UNSUPPORTED: strict profile requires --govulndb to pin the vulnerability database
  - applicability: advisory names no affected packages for the selected module; package presence undecidable


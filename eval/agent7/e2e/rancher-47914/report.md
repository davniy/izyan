# Research report — GO-2025-4135

> **EXPERIMENTAL — REVIEW REQUIRED.** This report supports human triage only.

## CVE essence and mechanism

**Malformed constraint may cause denial of service in golang.org/x/crypto/ssh/agent**

- aliases: CVE-2025-47914, GHSA-f6x5-jh6r-wrfv
- mechanism: SSH Agent servers do not validate the size of messages when processing new identity requests, which may cause the program to panic if the message is malformed due to an out of bounds read.
- assessed mechanism (PARTIAL): The golang.org/x/crypto/ssh/agent package does not validate the size of messages when processing identity requests containing certificates with constraints. A malformed message with an oversized constraint field causes a slice out-of-bounds read, resulting in a panic (denial of service). The security effect is a server crash in the Rancher process when serving SSH agent protocol requests during gi…
- [deterministic] advisory GO-2025-4135 states: Malformed constraint may cause denial of service in golang.org/x/crypto/ssh/agent

## What was actually found in the product

- applicability chain (SUPPORTED): module_present=TRUE version_affected=TRUE package_present=TRUE build_relevant=TRUE
- resolved version: `v0.43.0`
- conclusion scope: `AFFECTED_ENTRY_ONLY` | advisory scope: `UNKNOWN`
- [agent-only, unverified] The golang.org/x/crypto/ssh/agent package does not validate the size of messages when processing identity requests containing certificates with constraints. A malformed message with an oversized constraint field causes a slice out-of-bounds read, resulting in a panic (denial of service). The securit…
- [agent-only, unverified] The vulnerability resides in the golang.org/x/crypto/ssh/agent package, specifically within parseConstraints which is one of the affected symbols listed in advisory adv-01 (id=adv-01, module=golang.org/x/crypto, package=golang.org/x/crypto/ssh/agent, symbols=[ForwardToAgent, ServeAgent, parseConstra…
- [agent-only, unverified] The vulnerable functionality is exposed when Rancher performs git operations (clone, update) against Git-based Helm repositories configured with SSH credential authentication. When a secret of type corev1.SecretTypeSSHAuth is provided (git.go:83), the code adds the SSH private key to an in-memory ag…
- [agent-only, unverified] Alternative manifestation checked: The pkg/api/steve/machine/ssh.go file imports golang.org/x/crypto/ssh but not ssh/agent, so the ssh package client-side SSH usage (shell/dial operations) is not directly affected by this CVE. Transitive dependency check: no other go.mod in the workspace (hack/airga…

## Affected, fixed, and unverified implementations

- `adv-01` **golang.org/x/crypto** `Go` — **affected** (binding=`alias-resolved`, scope: advisory entry)
  - package: `golang.org/x/crypto/ssh/agent`
  - symbols: `ForwardToAgent`, `ServeAgent`, `parseConstraints`
  - range: introduced=0 fixed=- last_affected=-
  - range: introduced=- fixed=0.45.0 last_affected=-

## Exploitation conditions — established vs unknown

- **code reachability:** **ESTABLISHED** (level `PACKAGE_BUILD`, basis `deterministic`) — the advisory package golang.org/x/crypto/ssh/agent is in the product import closure and build-relevant under the recorded context
  - limit: this does not establish a ForwardToAgent call, symbol execution, runtime configuration, or attacker reachability
- **attack-surface availability:** **UNKNOWN** (level `NONE`, basis `none`) — no deterministic listener/socket fact at this scope — runtime attack-surface availability is unknown
  - limit: bounded static scans do not prove absence; runtime availability requires runtime evidence (level RUNTIME_AVAILABLE)
- **proven attacker exploitability:** **NOT_ESTABLISHED** (level `NONE`, basis `none`) — attacker exploitability is not established: package reachability and an agent-described scenario do not prove socket availability, attacker access, malformed-message delivery, or a resulting panic
  - limit: NOT_ESTABLISHED means not proven, never proven impossible; it requires a retained dynamic trace, runtime observation, or reproduction
- established predicates:
  - `EC-0001` [deterministic/SUPPORTED] the affected component (golang.org/x/crypto) is present in the resolved module graph
  - `EC-0002` [deterministic/SUPPORTED] the deployed product uses golang.org/x/crypto at a version inside the advisory's affected ranges
  - `EC-0003` [deterministic/SUPPORTED] product code reaches the affected package — the vulnerable code path is compiled in
  - `EC-0004` [deterministic/SUPPORTED] the affected package compiles into at least one product deliverable under the recorded build context
- unknown / open predicates:
  - `EC-0005` [deterministic/UNKNOWN] a runtime configuration/environment predicate must hold for exploitation (attacker reachability, feature flags, deployment exposure); static source evidence cannot decide it

## Main justification

- preserved agent category: `vulnerable` (never rewritten)
- classification review: class `APPLICABLE`, status **SUPPORTED**
- basis `component_present_affected` [ESTABLISHED/deterministic]: the affected component golang.org/x/crypto is present at an advisory-affected version (v0.43.0) — refs: fact-obs-0008, fact-obs-0008, obs:OBS-0008
- evidence chain: fact-obs-0008

## Recommendation — what to check or fix next

- triage action: **needs review** — the research contract forbids authoritative dispositions; a human must adjudicate the recorded claims and unknowns
- bounds: all findings are scoped to the snapshot tree and the stated build context; no runtime, delivery or deployment claim is made
- `R-0001` (human) review every verified_fact against its persisted artifact, then adjudicate agent assertions and unknowns
- `R-0002` (operator) verify deployment attack-surface availability (listener/socket lifetime and permissions, credential configuration) and obtain runtime/dynamic evidence if exploitability must be established

## Decision-changing unknowns

- `U-0007` UNKNOWN: scan_dynamic check did not produce a result (ERROR)
  - could flip: attack_surface_availability status (the scan_dynamic check that could decide it did not complete)
  - follow-up: rerun or scope-down the check; its status is ERROR, never an absence proof
- `U-0008` UNKNOWN: interface_dispatch_sites check did not produce a result (ERROR)
  - could flip: attack_surface_availability status (the interface_dispatch_sites check that could decide it did not complete)
  - follow-up: rerun or scope-down the check; its status is ERROR, never an absence proof
- `U-0009` UNKNOWN: gated_refs check did not produce a result (ERROR)
  - could flip: attack_surface_availability status (the gated_refs check that could decide it did not complete)
  - follow-up: rerun or scope-down the check; its status is ERROR, never an absence proof
- `U-0015` UNKNOWN: scan_dynamic check did not produce a result (ERROR)
  - could flip: attack_surface_availability status (the scan_dynamic check that could decide it did not complete)
  - follow-up: rerun or scope-down the check; its status is ERROR, never an absence proof
- `U-0016` UNKNOWN: interface_dispatch_sites check did not produce a result (ERROR)
  - could flip: attack_surface_availability status (the interface_dispatch_sites check that could decide it did not complete)
  - follow-up: rerun or scope-down the check; its status is ERROR, never an absence proof
- `U-0017` UNKNOWN: gated_refs check did not produce a result (ERROR)
  - could flip: attack_surface_availability status (the gated_refs check that could decide it did not complete)
  - follow-up: rerun or scope-down the check; its status is ERROR, never an absence proof
- `U-0023` UNKNOWN: scan_dynamic check did not produce a result (ERROR)
  - could flip: attack_surface_availability status (the scan_dynamic check that could decide it did not complete)
  - follow-up: rerun or scope-down the check; its status is ERROR, never an absence proof
- `U-0024` UNKNOWN: interface_dispatch_sites check did not produce a result (ERROR)
  - could flip: attack_surface_availability status (the interface_dispatch_sites check that could decide it did not complete)
  - follow-up: rerun or scope-down the check; its status is ERROR, never an absence proof
- `U-0025` UNKNOWN: gated_refs check did not produce a result (ERROR)
  - could flip: attack_surface_availability status (the gated_refs check that could decide it did not complete)
  - follow-up: rerun or scope-down the check; its status is ERROR, never an absence proof
- `U-0027` UNKNOWN: find_entrypoints check did not produce a result (ERROR)
  - could flip: attack_surface_availability status (the find_entrypoints check that could decide it did not complete)
  - follow-up: rerun or scope-down the check; its status is ERROR, never an absence proof

## Scope, provenance, and disposition

- run_id: `research-CVE-2025-47914-1791799875` | mode `experimental-research-v1` / schema `research-report/1`
- contract_extensions: `slice2-fidelity/1`
- started: 2026-10-12T10:11:15Z — finished: 2026-10-12T10:14:53Z | deterministic_only=false
- timeouts (ms): overall=1800000 deterministic=60000 agent=900000
- snapshot: `<VA_VEXBENCH>/repos/rancher/rancher/4dc4f534eed10a4b45b7475ebebaf99ab0056b35` @ `4dc4f534eed10a4b45b7475ebebaf99ab0056b35` (content_hash `f0d5c0dd436116a7a38df4aa0f184682af7f67ef4972d8c4ced647c00a333932`)
- build context: darwin/arm64 tags=[] vendor=false | analysis go `go version go1.26.1 darwin/arm64`
- release go: `go1.24.11`
- advisory: GO-2025-4135 from frozen_file (`eval/agent7/advisories/rancher-47914.json`)
- advisory sha256: raw `649e68a3e36cba82a937247327161ab62b2a835a5ef6a57d84e67142d0cd0222` canonical `606a20e1dcc830b8330f9469e0bbff196ef0819c0917bc6af536a4af8c1dc7de`
- harness: `<VA_VEXBENCH>/agent-ctl` @ `80cddeac3132826bfd47227ad59b2e6618a681bd`
- image: `vex-bench-go-opencode-e6:latest` (sha256:c85bc1df0f7e89b370c5ef552cd624bba1e49c2cb07005c8946be557b7379ba1)
- prompt: `eval/agent7/prompts/r0-v1.txt` sha256 `55b01e9a505bd058cb7be568f08c0e58364b8048e5acea030a14534f7031a0ae`
- disposition: `REVIEW_REQUIRED` (auto_close=false) — research lane output supports human triage only: evidence is scope-bounded, agent claims are unverified hypotheses, and the contract forbids VERIFIED/FALSE/AUTO_CLOSE dispositions
- forbidden classes: `VERIFIED`, `FALSE`, `AUTO_CLOSE`

## Applicability basis

- `component_present_affected` [ESTABLISHED/deterministic] the affected component golang.org/x/crypto is present at an advisory-affected version (v0.43.0)
  - verified refs: fact-obs-0008
  - refs: fact-obs-0008, obs:OBS-0008

## Contradictions and limitations

_No contradictions recorded._

## Preserved agent statements (unverified)

- agent_output.status: `OK`
- category (original, never rewritten): `vulnerable`
- attempt: `attempt-0002`
- reasoning: CVE-2025-47914 (GO-2025-4135) affects golang.org/x/crypto/ssh/agent, specifically the parseConstraints function which lacks message-size validation when processing SSH agent identity requests, potentially causing a panic due to out-of-bounds read. The snapshot declares golang.org/x/crypto v0.43.0 in go.mod (line 149), which falls in the affected range (introduced, fixed in 0.45.0, per advisory adv-01). The ssh/agent package is imported in pkg/catalogv2/git/git.go:24 and ServeAgent (listed in advisory symbols) is actively called at git.go:136 within the injectAgent function. This function creates a Unix domain socket to serve the SSH agent protocol for git SSH authentication operations. The attack surface is reachable: a Rancher user with API access to trigger git operations (Clone, Update) that use SSH credential authentication will have the vulnerable ServeAgent invoked. The agent processes incoming SSH agent protocol messages from git, and a malicious client connected to the Unix socket could send a malformed constraint message to trigger the out-of-bounds read and panic. No protection mechanism (configuration flag, runtime isolation, perimeter control) is evident in the snapshot that would block this attack surface. The component version (0.43.0) is confirmed below the fixed version (0.45.0) via go.mod line 149 and go.sum line 880.
- `A-0001` [MODEL_HYPOTHESIS/OPEN] category=vulnerable: CVE-2025-47914 (GO-2025-4135) affects golang.org/x/crypto/ssh/agent, specifically the parseConstraints function which lacks message-size validation when processing SSH agent identity requests, potentially causing a panic due to out-of-bounds read. The snapshot declares golang.org/x/crypto v0.43.0 in go.mod (line 149), which falls in the affected range (introduced, fixed in 0.45.0, per advisory adv-01). The ssh/agent package is imported in pkg/catalogv2/git/git.go:24 and ServeAgent (listed in advisory symbols) is actively called at git.go:136 within the injectAgent function. This function creates a Unix domain socket to serve the SSH agent protocol for git SSH authentication operations. The attack surface is reachable: a Rancher user with API access to trigger git operations (Clone, Update)…
  - original text: category=vulnerable: CVE-2025-47914 (GO-2025-4135) affects golang.org/x/crypto/ssh/agent, specifically the parseConstraints function which lacks message-size validation when processing SSH agent identity requests, potentially causing a panic due to out-of-bounds read. The snapshot declares golang.org/x/crypto v0.43.0 in go.mod (line 149), which falls in the affected range (introduced, fixed in 0.45.0, per advisory adv-01). The ssh/agent package is imported in pkg/catalogv2/git/git.go:24 and Serv…
  - source: `$.category + $.reasoning` in retained answer
- `A-0002` [EVIDENCE_SUPPORTED/OPEN] The golang.org/x/crypto/ssh/agent package does not validate the size of messages when processing identity requests containing certificates with constraints. A malformed message with an oversized constraint field causes a slice out-of-bounds read, resulting in a panic (denial of service). The security effect is a server crash in the Rancher process when serving SSH agent protocol requests during git operations with SSH credentials. The effect occurs because parseConstraints (a symbol listed in advisory adv-01) reads beyond the bounds of an internal buffer without size validation.
  - source: `$.assessment.vulnerability_mechanism` in retained answer
- `A-0003` [EVIDENCE_SUPPORTED/OPEN] The vulnerability resides in the golang.org/x/crypto/ssh/agent package, specifically within parseConstraints which is one of the affected symbols listed in advisory adv-01 (id=adv-01, module=golang.org/x/crypto, package=golang.org/x/crypto/ssh/agent, symbols=[ForwardToAgent, ServeAgent, parseConstraints]). The vulnerable package is used by Rancher through the ServeAgent function called in pkg/catalogv2/git/git.go:136: 'if err := agent.ServeAgent(*g.agent, conn); err != nil'. ServeAgent is the entry point that dispatches incoming SSH agent protocol messages to internal handlers, which in turn invoke parseConstraints when processing certificate constraint data in identity request messages. The root cause is the absence of bounds-checking in parseConstraints when parsing incoming protocol messages.
  - source: `$.assessment.root_cause` in retained answer
- `A-0004` [MODEL_HYPOTHESIS/OPEN] The vulnerable functionality is exposed when Rancher performs git operations (clone, update) against Git-based Helm repositories configured with SSH credential authentication. When a secret of type corev1.SecretTypeSSHAuth is provided (git.go:83), the code adds the SSH private key to an in-memory agent keyring (git.go:88-96) and creates a Unix socket to serve agent requests during git commands (git.go:102-143). This is triggered from the gitCmd function (git.go:325) which calls injectAgent (git.go:337) when g.agent is set. Product scope: Rancher's catalogv2 git module for Git-based Helm repository operations. Build scope: go.mod declares golang.org/x/crypto v0.43.0 (go.mod:149), confirmed in go.sum hash at line 880. Platform: Linux (based on Unix socket usage at git.go:113-116). Deployment: Requires Rancher to have Git-based Helm repositories configured with SSH authentication secrets. Unknowns: exact deployment configuration (whether any Rancher instance actually uses SSH-authenticated git repos), network exposure of the Unix socket (local to git subprocess only), version of golang.org/x/crypto used at runtime.
  - source: `$.assessment.product_exposure` in retained answer
- `A-0005` [MODEL_HYPOTHESIS/OPEN] Alternative manifestation checked: The pkg/api/steve/machine/ssh.go file imports golang.org/x/crypto/ssh but not ssh/agent, so the ssh package client-side SSH usage (shell/dial operations) is not directly affected by this CVE. Transitive dependency check: no other go.mod in the workspace (hack/airgap, gotools, pkg/client, pkg/apis) declares a different version of golang.org/x/crypto that would override the main module's v0.43.0. The hack/airgap/go.mod has v0.25.0 but is a separate module not used by the main Rancher binary. ForwardToAgent is not directly called in this snapshot, but ServeAgent (which handles the same protocol processing) is actively used. Counterargument: the Unix socket created by injectAgent is scoped to a single git subprocess invocation and cleaned up afterward (git.go:126-127), limiting the attack surface to local code paths. However, the git process itself could be tricked by a malicious git remote or a compromised SSH key credential into connecting to an attacker-controlled agent, or an attacker with API access could trigger the code path to observe behavior. This limits but does not eliminate the attack surface.
  - source: `$.assessment.alternative_paths` in retained answer

## Evidence register

- ref `adv:GO-2025-4135` (advisory) `eval/agent7/advisories/rancher-47914.json` frozen document
  - materiality: `MATERIAL`
  - raw bytes: `eval/agent7/advisories/rancher-47914.json` sha256 `649e68a3e36cba82a937247327161ab62b2a835a5ef6a57d84e67142d0cd0222` (frozen advisory document)
  - reproducible: FILE `eval/agent7/advisories/rancher-47914.json` in `-` → sha256 `606a20e1dcc830b8330f9469e0bbff196ef0819c0917bc6af536a4af8c1dc7de`
- ref `agent-src:FROZEN_ADVISORY - advisory adv-01 lists ServeAgent and parseConstraints as affected symbols, fixed in 0.45.0` (agent-source) `agent/attempt-0002/answer.txt` agent-stated
- ref `agent-src:assessment.altpaths` (agent-source) `agent/attempt-0002/answer.txt` retained final answer
- ref `agent-src:assessment.exposure` (agent-source) `agent/attempt-0002/answer.txt` retained final answer
- ref `agent-src:assessment.mechanism` (agent-source) `agent/attempt-0002/answer.txt` retained final answer
- ref `agent-src:assessment.rootcause` (agent-source) `agent/attempt-0002/answer.txt` retained final answer
- ref `agent-src:final-answer` (agent-source) `agent/attempt-0002/answer.txt` retained final answer
- ref `agent-src:go.mod:149 - declares golang.org/x/crypto v0.43.0` (agent-source) `agent/attempt-0002/answer.txt` agent-stated
- ref `agent-src:go.sum:880 - confirms golang.org/x/crypto v0.43.0 with hash dduJYIi3A3KOfdGOHX8AVZ/jGiyPa3IbBozJ5kNuE04` (agent-source) `agent/attempt-0002/answer.txt` agent-stated
- ref `agent-src:pkg/catalogv2/git/git.go:102-143 - injectAgent function creating Unix socket and serving agent` (agent-source) `agent/attempt-0002/answer.txt` agent-stated
- ref `agent-src:pkg/catalogv2/git/git.go:136 - calls agent.ServeAgent(*g.agent, conn) to serve agent protocol requests` (agent-source) `agent/attempt-0002/answer.txt` agent-stated
- ref `agent-src:pkg/catalogv2/git/git.go:24 - imports golang.org/x/crypto/ssh/agent` (agent-source) `agent/attempt-0002/answer.txt` agent-stated
- ref `agent-src:pkg/catalogv2/git/git.go:88 - creates agent keyring via agent.NewKeyring()` (agent-source) `agent/attempt-0002/answer.txt` agent-stated
- ref `agent-src:residual_questions` (agent-source) `agent/attempt-0002/answer.txt` retained final answer
- ref `obs:OBS-0001` (observation) `artifacts/obs-0001.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0001.json` sha256 `ee257a4865447cfe27756717e393978bbfd9e1858589c0f701248c478b3bb59f` (observation)
- ref `obs:OBS-0002` (observation) `artifacts/obs-0002.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0002.json` sha256 `7a44737cafe128c46664e9e8603b4ba5b7cb4e48beace63f1a9243a6b2a731fb` (observation)
- ref `obs:OBS-0003` (observation) `artifacts/obs-0003.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0003.json` sha256 `13ab5f4b8ccead94685a035fa45596c6ae815b131a5c3cb962c79cd8aed1545d` (observation)
- ref `obs:OBS-0004` (observation) `artifacts/obs-0004.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0004.json` sha256 `841a94887c5e1ed2e5b532c17a180cad060ab9e384cfacac6c48b5c0b90d791f` (observation)
- ref `obs:OBS-0005` (observation) `artifacts/obs-0005.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0005.json` sha256 `a47446c2fd77da02160096ef75cc57c60bf7eee207eb1a379c8cf20af896e0d0` (observation)
- ref `obs:OBS-0006` (observation) `artifacts/obs-0006.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0006.json` sha256 `a70e7842434f38bfef2b3cf4a793daf3d6ffe5c8d2a1f784815b13f9dd4dc9d0` (observation)
- ref `obs:OBS-0007` (observation) `artifacts/obs-0007.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0007.json` sha256 `71454c965f0a5cfdc0f39fa6d7054a983367c3cf62515a465352b8392e2d892a` (observation)
- ref `obs:OBS-0008` (observation) `artifacts/obs-0008.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0008.json` sha256 `c9855630715b54381dde58fb378438cac5d28ee31e57c1be69796a3e05122e31` (observation)
- ref `obs:OBS-0009` (observation) `artifacts/obs-0009.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0009.json` sha256 `74a7f9f6f53ccf1e2bab8c47f89b5c378b4466b5b679480dc5e82e895b4c7aa0` (observation)
- ref `obs:OBS-0010` (observation) `artifacts/obs-0010.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0010.json` sha256 `8581f25f302886bb4a3587101c31bfca615202b0ace323158d952fc979dcbc66` (observation)
- ref `obs:OBS-0011` (observation) `artifacts/obs-0011.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0011.json` sha256 `57268ba7094c46e2f87327ec06d808e1cbd49bf79e3b6930ec3bd5ab9a95a013` (observation)
- ref `obs:OBS-0012` (observation) `artifacts/obs-0012.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0012.json` sha256 `3c6fced46201dfcb91cd8bbb8d3d2c87c4e76c5ead883bb429c74ebcc0351533` (observation)
- ref `obs:OBS-0013` (observation) `artifacts/obs-0013.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0013.json` sha256 `ed08b1cd87fef1cdbe127ddbc006d2ac9cc00d093b3866fd6802d7fc4c1dcbf9` (observation)
- ref `obs:OBS-0014` (observation) `artifacts/obs-0014.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0014.json` sha256 `adb0947b2482a17a812748258d0b03b57a07f62d2f9af887a4620b726018a28d` (observation)
- ref `obs:OBS-0015` (observation) `artifacts/obs-0015.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0015.json` sha256 `7e9861a9e285b62de65e4b6bdc203648536deaf5e90c81fd49d6bcfe615e6816` (observation)
- ref `obs:OBS-0016` (observation) `artifacts/obs-0016.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0016.json` sha256 `86456f458741bd5c6d5ebca83ce2aff2b481f3d02c45f2048b764edc8823c598` (observation)
- ref `obs:OBS-0017` (observation) `artifacts/obs-0017.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0017.json` sha256 `e3c7aaf74cf97215917839450617a746772a3a5bd480841c009d207fce3ccfdf` (observation)
- ref `obs:OBS-0018` (observation) `artifacts/obs-0018.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0018.json` sha256 `e29a2fb3e57ad0e4a8a105e29618acced8953628c283927ed00c25362689c56a` (observation)
- ref `obs:OBS-0019` (observation) `artifacts/obs-0019.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0019.json` sha256 `d9562913f4fec3fcb2da63ec7272d9518bf516c21839fc3dd7243f68941ee8cd` (observation)
- ref `obs:OBS-0020` (observation) `artifacts/obs-0020.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0020.json` sha256 `40717728f02af27bc0d02e04a7ff9418af1c0830464906e8d380a5ec3f074c21` (observation)
- ref `obs:OBS-0021` (observation) `artifacts/obs-0021.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0021.json` sha256 `1544f508ca677982ee069af88cd16254fad59ec7043c4f0fabd04ca9dbf36a8b` (observation)
- ref `obs:OBS-0022` (observation) `artifacts/obs-0022.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0022.json` sha256 `4d3b1429453ede22ef2668580f435e7ff564f43109900841289ae77470ebdab5` (observation)
- ref `obs:OBS-0023` (observation) `artifacts/obs-0023.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0023.json` sha256 `354bbfbe4f091b5badb22cbbba33c6c5cdd9296dd3bfba73decabb4f2d13a16a` (observation)
- ref `obs:OBS-0024` (observation) `artifacts/obs-0024.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0024.json` sha256 `aae26e5ed2c551c3285c1c4f9ca6e496f2726d2b3499dab7a2995949183f16f7` (observation)
- ref `obs:OBS-0025` (observation) `artifacts/obs-0025.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0025.json` sha256 `bd62ccca4af8b25c775709e6cbb26c903f2ef4c8c227b318896ba6f14a4a7200` (observation)
- ref `obs:OBS-0026` (observation) `artifacts/obs-0026.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0026.json` sha256 `037e4d31336be38eda98e51261e2267af08f63120a00b511a5d0930b1459c6ed` (observation)
- ref `obs:OBS-0027` (observation) `artifacts/obs-0027.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0027.json` sha256 `0b304b474ebf7a2dc2181a1888e408d8232cfa4928b83bec463e008a83ab136f` (observation)
- ref `obs:OBS-0028` (observation) `artifacts/obs-0028.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0028.json` sha256 `8de425e3ae7c80141bddda233920b9e3d900cbef69d4562e389e1c5a82b2c9de` (observation)
- ref `obs:OBS-0029` (observation) `artifacts/obs-0029.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0029.json` sha256 `76781f5f8af081f8670f662dec36f6941fd5b233a329500ab20e4484d0b2d228` (observation)
- ref `obs:OBS-0030` (observation) `artifacts/obs-0030.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0030.json` sha256 `1b052f04ade99af7632f3b75a816b63e846255c4633e536fb3c8bbd3ae2015a5` (observation)
- ref `obs:OBS-0031` (observation) `artifacts/obs-0031.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0031.json` sha256 `606584878da1b10b3e7a68f77ea667594235e5852a4c70b325a6c9d828269ff0` (observation)
- ref `obs:OBS-0032` (observation) `artifacts/obs-0032.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0032.json` sha256 `9d25c9c1acd9592830388da1b74aa2384b2e71ef1011065bee2a6dfbea1db5a7` (observation)
- ref `obs:OBS-0033` (observation) `artifacts/obs-0033.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0033.json` sha256 `8c1a8912dbff301cde439dac5ff6c9709026616bc36aaf41caaaf13807f3b5db` (observation)
- ref `obs:OBS-0034` (observation) `artifacts/obs-0034.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0034.json` sha256 `c047fba3b94e2bb0cb131a47be90404e72ee1d2454593ab11839cbc8cc3526a2` (observation)
- ref `obs:OBS-0035` (observation) `artifacts/obs-0035.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0035.json` sha256 `e6cc65be0942d743217f2a52ed0e4cdc25b10f740c20583ce066112d29ab4152` (observation)
- ref `obs:OBS-0036` (observation) `artifacts/obs-0036.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0036.json` sha256 `92f457a078690e70037b71a4e437486a06b22626967e818cd48ad98ba2ab9295` (observation)
- ref `obs:OBS-0037` (observation) `artifacts/obs-0037.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0037.json` sha256 `c6f864451932ef5fd6a109e0c65181cde8291c484f1460d336a561c14d8274e9` (observation)
- ref `obs:OBS-0038` (observation) `artifacts/obs-0038.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0038.json` sha256 `27d7a233b60e7c10df4f9b4bc084fd1eb1ceb678c3021ba22ac729337e532c60` (observation)
- ref `obs:OBS-0039` (observation) `artifacts/obs-0039.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0039.json` sha256 `9843fa41555c0e7179c2f07c0f69d8b869782f13c6458e31a567fc7e2397d1de` (observation)

## Attempt and retry history

- `attempt-0001` (deterministic #1) status `OK` reason `initial` — initial deterministic lane pass (strict evidencetools session)
  - 2026-10-12T10:11:15Z → 2026-10-12T10:12:33Z | original_preserved=true
  - result: `deterministic-facts.json` sha256 `dffb6b26e2a8abea72a660898f73c7588ebc7ee70127281965170881d59a0fb5`
  - extraction: `NOT_APPLICABLE` (NONE), 0 candidate(s), selected -1
- `attempt-0002` (agent #2) status `OK` reason `initial` — initial agent assessment
  - 2026-10-12T10:13:59Z → 2026-10-12T10:14:53Z | original_preserved=true
  - result: `agent/attempt-0002/result.json` sha256 `92d9c7600c84d3b12a3797dcdf3241e5ab5675dedcccbd91d1415fdd46758f47`
  - extraction: `VALID` (NONE), 1 candidate(s), selected 0
    - candidate[0] VALID category=vulnerable raw `f371d565ddd3b9dffb252ea5dd677d221a71ab8dbac7de20ee3d577193c00391`

## Appendix

### Detailed unknowns

- `U-0001` UNKNOWN: module_usage check did not produce a result (TIMEOUT)
  - reason: tool exceeded its 1m0s wall-clock timeout
  - follow-up: rerun or scope-down the check; its status is TIMEOUT, never an absence proof
- `U-0002` UNKNOWN:  check did not produce a result (ERROR)
  - reason: context deadline exceeded
  - follow-up: rerun or scope-down the check; its status is ERROR, never an absence proof
- `U-0003` UNKNOWN: find_symbol check did not produce a result (ERROR)
  - reason: context deadline exceeded
  - follow-up: rerun or scope-down the check; its status is ERROR, never an absence proof
- `U-0004` UNKNOWN: find_callers check did not produce a result (ERROR)
  - reason: context deadline exceeded
  - follow-up: rerun or scope-down the check; its status is ERROR, never an absence proof
- `U-0005` UNKNOWN: find_may_callers check did not produce a result (ERROR)
  - reason: context deadline exceeded
  - follow-up: rerun or scope-down the check; its status is ERROR, never an absence proof
- `U-0006` UNKNOWN: find_dep_callers check did not produce a result (ERROR)
  - reason: context deadline exceeded
  - follow-up: rerun or scope-down the check; its status is ERROR, never an absence proof
- `U-0010` UNKNOWN: dep_invocation_state check did not produce a result (ERROR)
  - reason: context deadline exceeded
  - follow-up: rerun or scope-down the check; its status is ERROR, never an absence proof
- `U-0011` UNKNOWN: find_symbol check did not produce a result (ERROR)
  - reason: context deadline exceeded
  - follow-up: rerun or scope-down the check; its status is ERROR, never an absence proof
- `U-0012` UNKNOWN: find_callers check did not produce a result (ERROR)
  - reason: context deadline exceeded
  - follow-up: rerun or scope-down the check; its status is ERROR, never an absence proof
- `U-0013` UNKNOWN: find_may_callers check did not produce a result (ERROR)
  - reason: context deadline exceeded
  - follow-up: rerun or scope-down the check; its status is ERROR, never an absence proof
- `U-0014` UNKNOWN: find_dep_callers check did not produce a result (ERROR)
  - reason: context deadline exceeded
  - follow-up: rerun or scope-down the check; its status is ERROR, never an absence proof
- `U-0018` UNKNOWN: dep_invocation_state check did not produce a result (ERROR)
  - reason: context deadline exceeded
  - follow-up: rerun or scope-down the check; its status is ERROR, never an absence proof
- `U-0019` UNKNOWN: find_symbol check did not produce a result (ERROR)
  - reason: context deadline exceeded
  - follow-up: rerun or scope-down the check; its status is ERROR, never an absence proof
- `U-0020` UNKNOWN: find_callers check did not produce a result (ERROR)
  - reason: context deadline exceeded
  - follow-up: rerun or scope-down the check; its status is ERROR, never an absence proof
- `U-0021` UNKNOWN: find_may_callers check did not produce a result (ERROR)
  - reason: context deadline exceeded
  - follow-up: rerun or scope-down the check; its status is ERROR, never an absence proof
- `U-0022` UNKNOWN: find_dep_callers check did not produce a result (ERROR)
  - reason: context deadline exceeded
  - follow-up: rerun or scope-down the check; its status is ERROR, never an absence proof
- `U-0026` UNKNOWN: dep_invocation_state check did not produce a result (ERROR)
  - reason: context deadline exceeded
  - follow-up: rerun or scope-down the check; its status is ERROR, never an absence proof
- `U-0028` UNKNOWN:  check did not produce a result (ERROR)
  - reason: context deadline exceeded
  - follow-up: rerun or scope-down the check; its status is ERROR, never an absence proof
- `U-0029` UNKNOWN:  check did not produce a result (ERROR)
  - reason: context deadline exceeded
  - follow-up: rerun or scope-down the check; its status is ERROR, never an absence proof
- `U-0030` UNKNOWN:  check did not produce a result (ERROR)
  - reason: context deadline exceeded
  - follow-up: rerun or scope-down the check; its status is ERROR, never an absence proof
- `U-0031` UNKNOWN: run_govulncheck check did not produce a result (UNSUPPORTED)
  - reason: strict profile requires --govulndb to pin the vulnerability database
  - follow-up: rerun or scope-down the check; its status is UNSUPPORTED, never an absence proof

### Full deterministic facts

- `fact-obs-0001` snapshot <VA_VEXBENCH>/repos/rancher/rancher/4dc4f534eed10a4b45b7475ebebaf99ab0056b35 contained, replaces confined, content hash f0d5c0dd436116a7a38df4aa0f184682af7f67ef4972d8c4ced647c00a333932
  - tool: `repository-preflight` (izyan/research-lane go1.26.1) | coverage `COMPLETE` | scope: VerifyContained + CheckPathReplacements + ContentHash over the snapshot tree
  - command: `repository-preflight {"snapshot":"<VA_VEXBENCH>/repos/rancher/rancher/4dc4f534eed10a4b45b7475ebebaf99ab0056b35"}`
  - artifact: `artifacts/obs-0001.json` sha256 `ee257a4865447cfe27756717e393978bbfd9e1858589c0f701248c478b3bb59f` | data_digest `db5b0c3a2ee0b00270c9d42f33c74a0e38f58ba1657643f026306ae79f2f6a0e`
  - provenance: obs `OBS-0001` / deterministic-lane
  - materiality: `SUPPORTING`
  - raw bytes: `artifacts/obs-0001.json` sha256 `ee257a4865447cfe27756717e393978bbfd9e1858589c0f701248c478b3bb59f`
  - reproducible: COMMAND `repository-preflight {"snapshot":"<VA_VEXBENCH>/repos/rancher/rancher/4dc4f534eed10a4b45b7475ebebaf99ab0056b35"}` → `db5b0c3a2ee0b00270c9d42f33c74a0e38f58ba1657643f026306ae79f2f6a0e`
- `fact-obs-0002` snapshot identity 4dc4f534eed10a4b45b7475ebebaf99ab0056b35: go directive 1.24.0, release toolchain "go1.24.11", darwin/arm64
  - tool: `repository-snapshot` (izyan/research-lane go1.26.1) | coverage `COMPLETE` | scope: repository.Service.Snapshot (git/go probes + static release-evidence scan, no repo code executed)
  - command: `repository-snapshot {"GOOS":"","GOARCH":"","BuildTags":null,"BinaryPath":"","ReleaseGoVersion":"","TrustedPeer":false,"DeployManifests":null,"DeployArchive":"","PerimeterOverride":"","ExternalCommitSHA":"4dc4f534eed10a4b45b7475ebebaf99ab0056b35","GoBin":"go","Env":null}`
  - artifact: `artifacts/obs-0002.json` sha256 `7a44737cafe128c46664e9e8603b4ba5b7cb4e48beace63f1a9243a6b2a731fb` | data_digest `45cbbfa29ae2587e6383f615cc64e74e0b0244eca43378a0e67ac8fb2a81d4d2`
  - provenance: obs `OBS-0002` / deterministic-lane
  - materiality: `SUPPORTING`
  - raw bytes: `artifacts/obs-0002.json` sha256 `7a44737cafe128c46664e9e8603b4ba5b7cb4e48beace63f1a9243a6b2a731fb`
  - reproducible: COMMAND `repository-snapshot {"GOOS":"","GOARCH":"","BuildTags":null,"BinaryPath":"","ReleaseGoVersion":"","TrustedPeer":false,"DeployManifests":null,"DeployArchive":"","PerimeterOverride":"","ExternalCommitSHA":"4dc4f534eed10a4b45b7475ebebaf99ab0056b35","GoBin":"go","Env":null}` → `45cbbfa29ae2587e6383f615cc64e74e0b0244eca43378a0e67ac8fb2a81d4d2`
- `fact-obs-0003` frozen advisory CVE-2025-47914 resolved to GO-2025-4135 (1 affected entries, source frozen_file)
  - tool: `advisory-load` (izyan/research-lane go1.26.1) | coverage `COMPLETE` | scope: FileSource(eval/agent7/advisories/rancher-47914.json) with alias enrichment disabled; no network
  - command: `advisory-load {"cve":"CVE-2025-47914","path":"eval/agent7/advisories/rancher-47914.json","source":"frozen_file"}`
  - artifact: `artifacts/obs-0003.json` sha256 `13ab5f4b8ccead94685a035fa45596c6ae815b131a5c3cb962c79cd8aed1545d` | data_digest `928121d54619c05875e86376701f9ab4392c5ebd186e4de531a0c8d30978f92c`
  - provenance: obs `OBS-0003` / deterministic-lane
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0003.json` sha256 `13ab5f4b8ccead94685a035fa45596c6ae815b131a5c3cb962c79cd8aed1545d`
  - reproducible: COMMAND `advisory-load {"cve":"CVE-2025-47914","path":"eval/agent7/advisories/rancher-47914.json","source":"frozen_file"}` → `928121d54619c05875e86376701f9ab4392c5ebd186e4de531a0c8d30978f92c`
- `fact-obs-0004` snapshot 4dc4f534eed10a4b45b7475ebebaf99ab0056b35: content hash f0d5c0dd436116a7a38df4aa0f184682af7f67ef4972d8c4ced647c00a333932, go directive 1.24.0, 50 replace directives
  - tool: `get_product_snapshot` (izyan-evidence-tools/0.1.0) | coverage `COMPLETE` | scope: this snapshot's build context and module manifest facts
  - command: `get_product_snapshot {}`
  - artifact: `artifacts/obs-0004.json` sha256 `841a94887c5e1ed2e5b532c17a180cad060ab9e384cfacac6c48b5c0b90d791f` | data_digest `818d6a746b3e2140f8370133c4ae70d53a4f86f4c73638ca9377f3153e4acd4c`
  - provenance: obs `OBS-0004` / deterministic-lane
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0004.json` sha256 `841a94887c5e1ed2e5b532c17a180cad060ab9e384cfacac6c48b5c0b90d791f`
  - reproducible: COMMAND `get_product_snapshot {}` → `818d6a746b3e2140f8370133c4ae70d53a4f86f4c73638ca9377f3153e4acd4c`
- `fact-obs-0005` normalized advisory record for CVE-2025-47914 (resolved id GO-2025-4135)
  - tool: `get_vulnerability` (izyan-evidence-tools/0.1.0) | coverage `COMPLETE` | scope: OSV-compatible advisory record for CVE-2025-47914
  - command: `get_vulnerability {}`
  - artifact: `artifacts/obs-0005.json` sha256 `a47446c2fd77da02160096ef75cc57c60bf7eee207eb1a379c8cf20af896e0d0` | data_digest `2cd2f751843bc4b33795a7014a4eb80fe5f4e422e047c103a7a4e897db1c1a9d`
  - provenance: obs `OBS-0005` / deterministic-lane
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0005.json` sha256 `a47446c2fd77da02160096ef75cc57c60bf7eee207eb1a379c8cf20af896e0d0`
  - reproducible: COMMAND `get_vulnerability {}` → `2cd2f751843bc4b33795a7014a4eb80fe5f4e422e047c103a7a4e897db1c1a9d`
  - limit: severity provenance not declared by the advisory source
- `fact-obs-0006` dependency graph: 670 module(s) resolved via go list -m -json all
  - tool: `get_dependency_graph` (izyan-evidence-tools/0.1.0) | coverage `COMPLETE` | scope: module list of <VA_VEXBENCH>/repos/rancher/rancher/4dc4f534eed10a4b45b7475ebebaf99ab0056b35 (go list -m -json all)
  - command: `get_dependency_graph {}`
  - artifact: `artifacts/obs-0006.json` sha256 `a70e7842434f38bfef2b3cf4a793daf3d6ffe5c8d2a1f784815b13f9dd4dc9d0` | data_digest `bd5c28b3dd71599719a1ea6c065d22c3c60195be2ee4e5fcc4a6479068365330`
  - provenance: obs `OBS-0006` / deterministic-lane
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0006.json` sha256 `a70e7842434f38bfef2b3cf4a793daf3d6ffe5c8d2a1f784815b13f9dd4dc9d0`
  - reproducible: COMMAND `get_dependency_graph {}` → `bd5c28b3dd71599719a1ea6c065d22c3c60195be2ee4e5fcc4a6479068365330`
- `fact-obs-0007` module golang.org/x/crypto resolved to version v0.43.0
  - tool: `get_module_version` (izyan-evidence-tools/0.1.0) | coverage `COMPLETE` | scope: resolved module list of <VA_VEXBENCH>/repos/rancher/rancher/4dc4f534eed10a4b45b7475ebebaf99ab0056b35 (go list -m -json all)
  - command: `get_module_version {"module":"golang.org/x/crypto"}`
  - artifact: `artifacts/obs-0007.json` sha256 `71454c965f0a5cfdc0f39fa6d7054a983367c3cf62515a465352b8392e2d892a` | data_digest `bce53bd809c579cbd7f8350110289db44d8bbb69eb1134255233f63772e559e0`
  - provenance: obs `OBS-0007` / deterministic-lane
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0007.json` sha256 `71454c965f0a5cfdc0f39fa6d7054a983367c3cf62515a465352b8392e2d892a`
  - reproducible: COMMAND `get_module_version {"module":"golang.org/x/crypto"}` → `bce53bd809c579cbd7f8350110289db44d8bbb69eb1134255233f63772e559e0`
- `fact-obs-0008` applicability chain for GO-2025-4135: module_present=TRUE version_affected=TRUE package_present=TRUE build_relevant=TRUE (selected [golang.org/x/crypto])
  - tool: `affected-resolve` (izyan/research-lane go1.26.1) | coverage `PARTIAL` | scope: affected.GoResolver.Resolve over the snapshot module graph and import closure (go list -m, go list -deps under strict toolchain env)
  - command: `affected-resolve {"vuln":"GO-2025-4135"}`
  - artifact: `artifacts/obs-0008.json` sha256 `c9855630715b54381dde58fb378438cac5d28ee31e57c1be69796a3e05122e31` | data_digest `eacbed2c4594040aa6c851e2eebf85a9cf41904be7232dcb5199756efc3c696b`
  - provenance: obs `OBS-0008` / deterministic-lane
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0008.json` sha256 `c9855630715b54381dde58fb378438cac5d28ee31e57c1be69796a3e05122e31`
  - reproducible: COMMAND `affected-resolve {"vuln":"GO-2025-4135"}` → `eacbed2c4594040aa6c851e2eebf85a9cf41904be7232dcb5199756efc3c696b`
  - limit: observation payload truncated at 262144 bytes (full payload 80988031 bytes, sha256 b55a02afb4cb4def16aef0b59fa8f47df24858d6c01378b33aabc292091f2264); stored bytes are a prefix of the tool result, not the full result

### Full exploitation conditions

- `EC-0001` [deterministic/required/SUPPORTED/code_reachability] the affected component (golang.org/x/crypto) is present in the resolved module graph
-   - refs:
  - obs:OBS-0008
  - fact-obs-0008
- `EC-0002` [deterministic/required/SUPPORTED/code_reachability] the deployed product uses golang.org/x/crypto at a version inside the advisory's affected ranges
-   - refs:
  - obs:OBS-0008
  - fact-obs-0008
- `EC-0003` [deterministic/required/SUPPORTED/code_reachability] product code reaches the affected package — the vulnerable code path is compiled in
-   - refs:
  - obs:OBS-0008
  - fact-obs-0008
- `EC-0004` [deterministic/required/SUPPORTED/code_reachability] the affected package compiles into at least one product deliverable under the recorded build context
-   - refs:
  - obs:OBS-0008
  - fact-obs-0008
- `EC-0005` [deterministic/required/UNKNOWN/attack_surface_availability] a runtime configuration/environment predicate must hold for exploitation (attacker reachability, feature flags, deployment exposure); static source evidence cannot decide it
-   - refs:
  - obs:OBS-0035
-   - limits:
  - follow-up: confirm deployment posture (listeners, auth, network exposure, config) against the recorded entry-point facts

### Full assessment sections

#### vulnerability_mechanism — PARTIAL

The golang.org/x/crypto/ssh/agent package does not validate the size of messages when processing identity requests containing certificates with constraints. A malformed message with an oversized constraint field causes a slice out-of-bounds read, resulting in a panic (denial of service). The security effect is a server crash in the Rancher process when serving SSH agent protocol requests during git operations with SSH credentials. The effect occurs because parseConstraints (a symbol listed in advisory adv-01) reads beyond the bounds of an internal buffer without size validation.

- **[deterministic/SUPPORTED]**
  - subject: `GO-2025-4135`
  - statement: advisory GO-2025-4135 states: Malformed constraint may cause denial of service in golang.org/x/crypto/ssh/agent
  - scope: frozen advisory document
-   - refs:
  - fact-obs-0003
- **[agent/OPEN]**
  - statement: The golang.org/x/crypto/ssh/agent package does not validate the size of messages when processing identity requests containing certificates with constraints. A malformed message with an oversized constraint field causes a slice out-of-bounds read, resulting in a panic (denial of service). The security effect is a server crash in the Rancher process when serving SSH agent protocol requests during git operations with SSH credentials. The effect occurs because parseConstraints (a symbol listed in advisory adv-01) reads beyond the bounds of an internal buffer without size validation.
  - scope: agent assessment (snapshot-read scope as stated)
-   - refs:
  - A-0002

#### root_cause — PARTIAL

The vulnerability resides in the golang.org/x/crypto/ssh/agent package, specifically within parseConstraints which is one of the affected symbols listed in advisory adv-01 (id=adv-01, module=golang.org/x/crypto, package=golang.org/x/crypto/ssh/agent, symbols=[ForwardToAgent, ServeAgent, parseConstraints]). The vulnerable package is used by Rancher through the ServeAgent function called in pkg/catalogv2/git/git.go:136: 'if err := agent.ServeAgent(*g.agent, conn); err != nil'. ServeAgent is the entry point that dispatches incoming SSH agent protocol messages to internal handlers, which in turn invoke parseConstraints when processing certificate constraint data in identity request messages. The root cause is the absence of bounds-checking in parseConstraints when parsing incoming protocol messages.

- **[agent/OPEN]**
  - statement: The vulnerability resides in the golang.org/x/crypto/ssh/agent package, specifically within parseConstraints which is one of the affected symbols listed in advisory adv-01 (id=adv-01, module=golang.org/x/crypto, package=golang.org/x/crypto/ssh/agent, symbols=[ForwardToAgent, ServeAgent, parseConstraints]). The vulnerable package is used by Rancher through the ServeAgent function called in pkg/catalogv2/git/git.go:136: 'if err := agent.ServeAgent(*g.agent, conn); err != nil'. ServeAgent is the entry point that dispatches incoming SSH agent protocol messages to internal handlers, which in turn invoke parseConstraints when processing certificate constraint data in identity request messages. The root cause is the absence of bounds-checking in parseConstraints when parsing incoming protocol messages.
  - scope: agent assessment (snapshot-read scope as stated)
-   - refs:
  - A-0003

#### attack_scenario — UNKNOWN

UNKNOWN: no attacker path is established; follow-up: trace each recorded inbound listener/dial site to the affected component or mark the predicate open


#### product_exposure — PARTIAL

The vulnerable functionality is exposed when Rancher performs git operations (clone, update) against Git-based Helm repositories configured with SSH credential authentication. When a secret of type corev1.SecretTypeSSHAuth is provided (git.go:83), the code adds the SSH private key to an in-memory agent keyring (git.go:88-96) and creates a Unix socket to serve agent requests during git commands (git.go:102-143). This is triggered from the gitCmd function (git.go:325) which calls injectAgent (git.go:337) when g.agent is set. Product scope: Rancher's catalogv2 git module for Git-based Helm repository operations. Build scope: go.mod declares golang.org/x/crypto v0.43.0 (go.mod:149), confirmed in go.sum hash at line 880. Platform: Linux (based on Unix socket usage at git.go:113-116). Deployment: Requires Rancher to have Git-based Helm repositories configured with SSH authentication secrets. Unknowns: exact deployment configuration (whether any Rancher instance actually uses SSH-authenticated git repos), network exposure of the Unix socket (local to git subprocess only), version of golang.org/x/crypto used at runtime.

- **[agent/OPEN]**
  - statement: The vulnerable functionality is exposed when Rancher performs git operations (clone, update) against Git-based Helm repositories configured with SSH credential authentication. When a secret of type corev1.SecretTypeSSHAuth is provided (git.go:83), the code adds the SSH private key to an in-memory agent keyring (git.go:88-96) and creates a Unix socket to serve agent requests during git commands (git.go:102-143). This is triggered from the gitCmd function (git.go:325) which calls injectAgent (git.go:337) when g.agent is set. Product scope: Rancher's catalogv2 git module for Git-based Helm repository operations. Build scope: go.mod declares golang.org/x/crypto v0.43.0 (go.mod:149), confirmed in go.sum hash at line 880. Platform: Linux (based on Unix socket usage at git.go:113-116). Deployment: Requires Rancher to have Git-based Helm repositories configured with SSH authentication secrets. Unknowns: exact deployment configuration (whether any Rancher instance actually uses SSH-authenticated git repos), network exposure of the Unix socket (local to git subprocess only), version of golang.org/x/crypto used at runtime.
  - scope: agent assessment (snapshot-read scope as stated)
-   - refs:
  - A-0004

#### alternative_paths — PARTIAL

Alternative manifestation checked: The pkg/api/steve/machine/ssh.go file imports golang.org/x/crypto/ssh but not ssh/agent, so the ssh package client-side SSH usage (shell/dial operations) is not directly affected by this CVE. Transitive dependency check: no other go.mod in the workspace (hack/airgap, gotools, pkg/client, pkg/apis) declares a different version of golang.org/x/crypto that would override the main module's v0.43.0. The hack/airgap/go.mod has v0.25.0 but is a separate module not used by the main Rancher binary. ForwardToAgent is not directly called in this snapshot, but ServeAgent (which handles the same protocol processing) is actively used. Counterargument: the Unix socket created by injectAgent is scoped to a single git subprocess invocation and cleaned up afterward (git.go:126-127), limiting the attack surface to local code paths. However, the git process itself could be tricked by a malicious git remote or a compromised SSH key credential into connecting to an attacker-controlled agent, or an attacker with API access could trigger the code path to observe behavior. This limits but does not eliminate the attack surface.

- **[agent/OPEN]**
  - statement: Alternative manifestation checked: The pkg/api/steve/machine/ssh.go file imports golang.org/x/crypto/ssh but not ssh/agent, so the ssh package client-side SSH usage (shell/dial operations) is not directly affected by this CVE. Transitive dependency check: no other go.mod in the workspace (hack/airgap, gotools, pkg/client, pkg/apis) declares a different version of golang.org/x/crypto that would override the main module's v0.43.0. The hack/airgap/go.mod has v0.25.0 but is a separate module not used by the main Rancher binary. ForwardToAgent is not directly called in this snapshot, but ServeAgent (which handles the same protocol processing) is actively used. Counterargument: the Unix socket created by injectAgent is scoped to a single git subprocess invocation and cleaned up afterward (git.go:126-127), limiting the attack surface to local code paths. However, the git process itself could be tricked by a malicious git remote or a compromised SSH key credential into connecting to an attacker-controlled agent, or an attacker with API access could trigger the code path to observe behavior. This limits but does not eliminate the attack surface.
  - scope: agent assessment (snapshot-read scope as stated)
-   - refs:
  - A-0005

#### evidence_quality — SUPPORTED

evidence base: 8 deterministic check(s) OK, 31 non-OK; evidence is scope-bounded per each observation's scope/limitations; agent stated: Evidence is direct and concrete: the affected go module version (0.43.0) is confirmed present in the main go.mod and go.sum. The vulnerable ssh/agent API (ServeAgent, per advisory symbol list) is directly called from product code at git.go:136 within an execution path triggered by authenticated API calls. The vulnerability mechanism (parseConstraints in ssh/agent) is an internal package function called by ServeAgent during SSH agent protocol message processing. Limitations: this is static source analysis only - cannot verify runtime behavior, actual deployment configuration, or whether parseConstraints bounds-checking was specifically missing (the advisory binding is via the ServeAgent symbol). Cannot verify that an attacker can actually trigger the code path with sufficient frequency or in sufficient quantity to demonstrate impact. Cannot verify the exact version of the vendored/depended-upon crypto package at the parseConstraints source code level.

- limits:
  - module_usage TIMEOUT: tool exceeded its 1m0s wall-clock timeout
  -  ERROR: context deadline exceeded
  - find_symbol ERROR: context deadline exceeded
  - find_callers ERROR: context deadline exceeded
  - find_may_callers ERROR: context deadline exceeded
  - find_dep_callers ERROR: context deadline exceeded
  - scan_dynamic ERROR: context deadline exceeded
  - interface_dispatch_sites ERROR: context deadline exceeded
  - gated_refs ERROR: context deadline exceeded
  - dep_invocation_state ERROR: context deadline exceeded
  - find_symbol ERROR: context deadline exceeded
  - find_callers ERROR: context deadline exceeded
  - find_may_callers ERROR: context deadline exceeded
  - find_dep_callers ERROR: context deadline exceeded
  - scan_dynamic ERROR: context deadline exceeded
  - interface_dispatch_sites ERROR: context deadline exceeded
  - gated_refs ERROR: context deadline exceeded
  - dep_invocation_state ERROR: context deadline exceeded
  - find_symbol ERROR: context deadline exceeded
  - find_callers ERROR: context deadline exceeded
  - find_may_callers ERROR: context deadline exceeded
  - find_dep_callers ERROR: context deadline exceeded
  - scan_dynamic ERROR: context deadline exceeded
  - interface_dispatch_sites ERROR: context deadline exceeded
  - gated_refs ERROR: context deadline exceeded
  - dep_invocation_state ERROR: context deadline exceeded
  - find_entrypoints ERROR: context deadline exceeded
  -  ERROR: context deadline exceeded
  -  ERROR: context deadline exceeded
  -  ERROR: context deadline exceeded
  - run_govulncheck UNSUPPORTED: strict profile requires --govulndb to pin the vulnerability database

### Full open questions and residual questions

- `Q-0001` module_usage check did not produce a result (TIMEOUT)
  - subject/scope: U-0001 / report scope
  - next check: rerun or scope-down the check; its status is TIMEOUT, never an absence proof
  - why: left unresolved by the lanes' stated scope
- `Q-0002`  check did not produce a result (ERROR)
  - subject/scope: U-0002 / report scope
  - next check: rerun or scope-down the check; its status is ERROR, never an absence proof
  - why: left unresolved by the lanes' stated scope
- `Q-0003` find_symbol check did not produce a result (ERROR)
  - subject/scope: U-0003 / report scope
  - next check: rerun or scope-down the check; its status is ERROR, never an absence proof
  - why: left unresolved by the lanes' stated scope
- `Q-0004` find_callers check did not produce a result (ERROR)
  - subject/scope: U-0004 / report scope
  - next check: rerun or scope-down the check; its status is ERROR, never an absence proof
  - why: left unresolved by the lanes' stated scope
- `Q-0005` find_may_callers check did not produce a result (ERROR)
  - subject/scope: U-0005 / report scope
  - next check: rerun or scope-down the check; its status is ERROR, never an absence proof
  - why: left unresolved by the lanes' stated scope
- `Q-0006` find_dep_callers check did not produce a result (ERROR)
  - subject/scope: U-0006 / report scope
  - next check: rerun or scope-down the check; its status is ERROR, never an absence proof
  - why: left unresolved by the lanes' stated scope
- `Q-0007` scan_dynamic check did not produce a result (ERROR)
  - subject/scope: U-0007 / report scope
  - next check: rerun or scope-down the check; its status is ERROR, never an absence proof
  - why: left unresolved by the lanes' stated scope
- `Q-0008` interface_dispatch_sites check did not produce a result (ERROR)
  - subject/scope: U-0008 / report scope
  - next check: rerun or scope-down the check; its status is ERROR, never an absence proof
  - why: left unresolved by the lanes' stated scope
- `Q-0009` gated_refs check did not produce a result (ERROR)
  - subject/scope: U-0009 / report scope
  - next check: rerun or scope-down the check; its status is ERROR, never an absence proof
  - why: left unresolved by the lanes' stated scope
- `Q-0010` dep_invocation_state check did not produce a result (ERROR)
  - subject/scope: U-0010 / report scope
  - next check: rerun or scope-down the check; its status is ERROR, never an absence proof
  - why: left unresolved by the lanes' stated scope
- `Q-0011` find_symbol check did not produce a result (ERROR)
  - subject/scope: U-0011 / report scope
  - next check: rerun or scope-down the check; its status is ERROR, never an absence proof
  - why: left unresolved by the lanes' stated scope
- `Q-0012` find_callers check did not produce a result (ERROR)
  - subject/scope: U-0012 / report scope
  - next check: rerun or scope-down the check; its status is ERROR, never an absence proof
  - why: left unresolved by the lanes' stated scope
- `Q-0013` find_may_callers check did not produce a result (ERROR)
  - subject/scope: U-0013 / report scope
  - next check: rerun or scope-down the check; its status is ERROR, never an absence proof
  - why: left unresolved by the lanes' stated scope
- `Q-0014` find_dep_callers check did not produce a result (ERROR)
  - subject/scope: U-0014 / report scope
  - next check: rerun or scope-down the check; its status is ERROR, never an absence proof
  - why: left unresolved by the lanes' stated scope
- `Q-0015` scan_dynamic check did not produce a result (ERROR)
  - subject/scope: U-0015 / report scope
  - next check: rerun or scope-down the check; its status is ERROR, never an absence proof
  - why: left unresolved by the lanes' stated scope
- `Q-0016` interface_dispatch_sites check did not produce a result (ERROR)
  - subject/scope: U-0016 / report scope
  - next check: rerun or scope-down the check; its status is ERROR, never an absence proof
  - why: left unresolved by the lanes' stated scope
- `Q-0017` gated_refs check did not produce a result (ERROR)
  - subject/scope: U-0017 / report scope
  - next check: rerun or scope-down the check; its status is ERROR, never an absence proof
  - why: left unresolved by the lanes' stated scope
- `Q-0018` dep_invocation_state check did not produce a result (ERROR)
  - subject/scope: U-0018 / report scope
  - next check: rerun or scope-down the check; its status is ERROR, never an absence proof
  - why: left unresolved by the lanes' stated scope
- `Q-0019` find_symbol check did not produce a result (ERROR)
  - subject/scope: U-0019 / report scope
  - next check: rerun or scope-down the check; its status is ERROR, never an absence proof
  - why: left unresolved by the lanes' stated scope
- `Q-0020` find_callers check did not produce a result (ERROR)
  - subject/scope: U-0020 / report scope
  - next check: rerun or scope-down the check; its status is ERROR, never an absence proof
  - why: left unresolved by the lanes' stated scope
- `Q-0021` find_may_callers check did not produce a result (ERROR)
  - subject/scope: U-0021 / report scope
  - next check: rerun or scope-down the check; its status is ERROR, never an absence proof
  - why: left unresolved by the lanes' stated scope
- `Q-0022` find_dep_callers check did not produce a result (ERROR)
  - subject/scope: U-0022 / report scope
  - next check: rerun or scope-down the check; its status is ERROR, never an absence proof
  - why: left unresolved by the lanes' stated scope
- `Q-0023` scan_dynamic check did not produce a result (ERROR)
  - subject/scope: U-0023 / report scope
  - next check: rerun or scope-down the check; its status is ERROR, never an absence proof
  - why: left unresolved by the lanes' stated scope
- `Q-0024` interface_dispatch_sites check did not produce a result (ERROR)
  - subject/scope: U-0024 / report scope
  - next check: rerun or scope-down the check; its status is ERROR, never an absence proof
  - why: left unresolved by the lanes' stated scope
- `Q-0025` gated_refs check did not produce a result (ERROR)
  - subject/scope: U-0025 / report scope
  - next check: rerun or scope-down the check; its status is ERROR, never an absence proof
  - why: left unresolved by the lanes' stated scope
- `Q-0026` dep_invocation_state check did not produce a result (ERROR)
  - subject/scope: U-0026 / report scope
  - next check: rerun or scope-down the check; its status is ERROR, never an absence proof
  - why: left unresolved by the lanes' stated scope
- `Q-0027` find_entrypoints check did not produce a result (ERROR)
  - subject/scope: U-0027 / report scope
  - next check: rerun or scope-down the check; its status is ERROR, never an absence proof
  - why: left unresolved by the lanes' stated scope
- `Q-0028`  check did not produce a result (ERROR)
  - subject/scope: U-0028 / report scope
  - next check: rerun or scope-down the check; its status is ERROR, never an absence proof
  - why: left unresolved by the lanes' stated scope
- `Q-0029`  check did not produce a result (ERROR)
  - subject/scope: U-0029 / report scope
  - next check: rerun or scope-down the check; its status is ERROR, never an absence proof
  - why: left unresolved by the lanes' stated scope
- `Q-0030`  check did not produce a result (ERROR)
  - subject/scope: U-0030 / report scope
  - next check: rerun or scope-down the check; its status is ERROR, never an absence proof
  - why: left unresolved by the lanes' stated scope
- `Q-0031` run_govulncheck check did not produce a result (UNSUPPORTED)
  - subject/scope: U-0031 / report scope
  - next check: rerun or scope-down the check; its status is UNSUPPORTED, never an absence proof
  - why: left unresolved by the lanes' stated scope
- `Q-0032` Is golang.org/x/crypto v0.43.0 the actual version used at runtime, or is there a vendor/replace directive that overrides it? (Check: go.mod line 7-60 for any replace of golang.org/x/crypto)
  - subject/scope:  / agent assessment
  - next check: agent-stated follow-up
  - why: left unresolved by the lanes' stated scope
- `Q-0033` Are any Git-based Helm repositories in deployments actually configured with SSH credential authentication (SecretTypeSSHAuth) that would trigger the ServeAgent code path? (Check: verify Rancher deployment configuration)
  - subject/scope:  / agent assessment
  - next check: agent-stated follow-up
  - why: left unresolved by the lanes' stated scope
- `Q-0034` Can the attack be triggered from outside the Rancher process, or is the Unix socket access limited to the child git process only? (Check: Unix socket permissions and process isolation in injectAgent)
  - subject/scope:  / agent assessment
  - next check: agent-stated follow-up
  - why: left unresolved by the lanes' stated scope
- `Q-0035` Does any version constraint in the dependency resolution chain pull in a different version of golang.org/x/crypto/ssh/agent than v0.43.0? (Check: go mod graph or dep resolution)
  - subject/scope:  / agent assessment
  - next check: agent-stated follow-up
  - why: left unresolved by the lanes' stated scope
- `Q-0036` Is there any Kubernetes RBAC or network policy that prevents an authenticated user from triggering the git Clone/Update operations that invoke the vulnerable code path? (Check: RBAC configuration)
  - subject/scope:  / agent assessment
  - next check: agent-stated follow-up
  - why: left unresolved by the lanes' stated scope

### Legacy evidence-quality details

- status: `SUPPORTED`
- summary: evidence base: 8 deterministic check(s) OK, 31 non-OK; evidence is scope-bounded per each observation's scope/limitations; agent stated: Evidence is direct and concrete: the affected go module version (0.43.0) is confirmed present in the main go.mod and go.sum. The vulnerable ssh/agent API (ServeAgent, per advisory symbol list) is directly called from product code at git.go:136 within an execution path triggered by authenticated API calls. The vulnerability mechanism (parseConstraints in ssh/agent) is an internal package function called by ServeAgent during SSH agent protocol message processing. Limitations: this is static source analysis only - cannot verify runtime behavior, actual deployment configuration, or whether parseConstraints bounds-checking was specifically missing (the advisory binding is via the ServeAgent symbol). Cannot verify that an attacker can actually trigger the code path with sufficient frequency or in sufficient quantity to demonstrate impact. Cannot verify the exact version of the vendored/depended-upon crypto package at the parseConstraints source code level.
- coverage:
  - repository-preflight: VerifyContained + CheckPathReplacements + ContentHash over the snapshot tree
  - repository-snapshot: repository.Service.Snapshot (git/go probes + static release-evidence scan, no repo code executed)
  - advisory-load: FileSource(eval/agent7/advisories/rancher-47914.json) with alias enrichment disabled; no network
  - get_product_snapshot: this snapshot's build context and module manifest facts
  - get_vulnerability: OSV-compatible advisory record for CVE-2025-47914
  - get_dependency_graph: module list of <VA_VEXBENCH>/repos/rancher/rancher/4dc4f534eed10a4b45b7475ebebaf99ab0056b35 (go list -m -json all)
  - get_module_version: resolved module list of <VA_VEXBENCH>/repos/rancher/rancher/4dc4f534eed10a4b45b7475ebebaf99ab0056b35 (go list -m -json all)
  - affected-resolve: affected.GoResolver.Resolve over the snapshot module graph and import closure (go list -m, go list -deps under strict toolchain env)
- limitations:
  - module_usage TIMEOUT: tool exceeded its 1m0s wall-clock timeout
  -  ERROR: context deadline exceeded
  - find_symbol ERROR: context deadline exceeded
  - find_callers ERROR: context deadline exceeded
  - find_may_callers ERROR: context deadline exceeded
  - find_dep_callers ERROR: context deadline exceeded
  - scan_dynamic ERROR: context deadline exceeded
  - interface_dispatch_sites ERROR: context deadline exceeded
  - gated_refs ERROR: context deadline exceeded
  - dep_invocation_state ERROR: context deadline exceeded
  - find_symbol ERROR: context deadline exceeded
  - find_callers ERROR: context deadline exceeded
  - find_may_callers ERROR: context deadline exceeded
  - find_dep_callers ERROR: context deadline exceeded
  - scan_dynamic ERROR: context deadline exceeded
  - interface_dispatch_sites ERROR: context deadline exceeded
  - gated_refs ERROR: context deadline exceeded
  - dep_invocation_state ERROR: context deadline exceeded
  - find_symbol ERROR: context deadline exceeded
  - find_callers ERROR: context deadline exceeded
  - find_may_callers ERROR: context deadline exceeded
  - find_dep_callers ERROR: context deadline exceeded
  - scan_dynamic ERROR: context deadline exceeded
  - interface_dispatch_sites ERROR: context deadline exceeded
  - gated_refs ERROR: context deadline exceeded
  - dep_invocation_state ERROR: context deadline exceeded
  - find_entrypoints ERROR: context deadline exceeded
  -  ERROR: context deadline exceeded
  -  ERROR: context deadline exceeded
  -  ERROR: context deadline exceeded
  - run_govulncheck UNSUPPORTED: strict profile requires --govulndb to pin the vulnerability database


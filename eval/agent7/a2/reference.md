# A2 blind reference packet

These sheets were built from the frozen advisory JSON files and the named source snapshots only. They do not contain a safe/exploitable verdict, benchmark label, reference-PR fact, or A2 arm output. `Advisory` means declared by the frozen advisory; `snapshot` means observed in the cited file and line range.

## 1. kubernetes/kubernetes @ e196d2491087e93bd29f0e5a538aab60667021e3 — GHSA-qppj-fm5r-hxr3 / CVE-2023-44487

- **Advisory / affected manifestations:** GHSA-qppj-fm5r-hxr3 describes HTTP/2 Rapid Reset: a client opens request streams and immediately sends `RST_STREAM`, while the server has already allocated, parsed, routed, or proxied work; cancellation leaves the connection open and creates a client/server cost asymmetry. The Go affected entry is `golang.org/x/net`, introduced `0`, fixed `0.17.0`. The same advisory also declares Swift `swift-nio-http2 <1.28.0`, Tomcat coyote/embed-core branches, Jetty HTTP/2 common/server branches, and Akka HTTP core artifacts; those non-Go artifacts are not source components in this Kubernetes snapshot.
- **Defect root cause / mechanism:** The relevant component is vendored `golang.org/x/net/http2`. Its server receives reset frames in `processResetStream`; it cancels and closes the stream after frame processing (`vendor/golang.org/x/net/http2/server.go:1526-1529, 1601-1633`). New headers create a request and schedule a handler (`server.go:1917-2050`), so rapid cancellation can leave work already started. Snapshot dependency identity is `go.mod:82` and `vendor/modules.txt:973,981-982`, both `v0.17.0`, exactly the advisory fixed boundary. The advisory establishes the fixed boundary; I did not re-derive the v0.17.0 reset-accounting diff from the vendored source.
- **Known manifestations in this snapshot:** The vendored `http2` server is present and the Kubernetes API-server HTTP/2 listener config is present. No other Kubernetes component was exhaustively traced for HTTP/2 exposure.
- **Necessary conditions:** Required: an HTTP/2 server listener is enabled and reachable; the peer can send request headers followed quickly by `RST_STREAM`; the implementation has begun material work before cancellation. Supporting: high request/reset rate, expensive handlers, proxying to a backend, or a large bandwidth/CPU asymmetry. Kubernetes-specific listener selection, bind address, and deployment exposure are not established here.
- **Admissible call paths:** Verified: API-server secure serving constructs/configures HTTP/2 in `staging/src/k8s.io/apiserver/pkg/server/secure_serving.go:180-203`; the HTTP/2 frame path is `serverConn.processFrame` → `processResetStream` (`vendor/.../http2/server.go:1526-1529,1601`). The exact externally reachable API-server listener/port was not verified from the read set.
- **Counterexamples / mitigations checked:** `secure_serving.go:195` defaults `MaxConcurrentStreams` to 100 and `:203` calls `http2.ConfigureServer`; the code comment describes forcibly closing after a bounded number of streams. `staging/src/k8s.io/apiserver/pkg/endpoints/filters/authentication.go:107-134` implements the unauthenticated HTTP/2 teardown and explicitly references CVE-2023-44487. `staging/src/k8s.io/apiserver/pkg/features/kube_features.go:190-203,308` defines `UnauthenticatedHTTP2DOSMitigation`, default true/beta. `staging/src/k8s.io/apiserver/pkg/server/config.go:344-349` exposes HTTP/2 stream/disable settings. The dependency itself is at the advisory fixed boundary, not below it.
- **Admissible uncertainty:** UNKNOWN: the exact in-library v0.17.0 fix mechanism; follow-up: compare the vendored `x/net/http2` source with the advisory fix or inspect the pinned release change. UNKNOWN: other Kubernetes HTTP/2 listeners such as kubelet/etcd-side paths and their deployment exposure; follow-up: enumerate all HTTP/2 server constructors and configured listeners in this snapshot. UNKNOWN: runtime listener address/port and operator overrides; follow-up: inspect the concrete product configuration/deployment.
- **Checkable sources:** `eval/agent7/results/a2-advisories/kubernetes-kubernetes-e196d24-CVE-2023-44487__GHSA-qppj-fm5r-hxr3.json` (`details`, Go `affected` entry, all `affected` package entries); `go.mod:82`; `vendor/modules.txt:973,981-982`; `vendor/golang.org/x/net/http2/server.go:1526-1529,1601-1633,1917-2050`; `staging/src/k8s.io/apiserver/pkg/server/secure_serving.go:180-203`; `staging/src/k8s.io/apiserver/pkg/endpoints/filters/authentication.go:107-134`; `staging/src/k8s.io/apiserver/pkg/features/kube_features.go:190-203,308`; `staging/src/k8s.io/apiserver/pkg/server/config.go:344-349`.

## 2. kubernetes/kubernetes @ ec78c0f487ebde300ebbe1fb5189cb178e6a18b5 — GO-2021-0053 / CVE-2021-3121

- **Advisory / affected manifestations:** GO-2021-0053 says improper bounds checking in `github.com/gogo/protobuf` generated `Unmarshal` methods can produce an out-of-bounds panic on crafted input. Affected range is introduced `0`, fixed `1.3.2`; the advisory import hint is `github.com/gogo/protobuf/plugin/unmarshal`, symbols `unmarshal.Generate` and `unmarshal.field`.
- **Defect root cause / mechanism:** The root role is the old gogo code generator and the generated runtime methods it emitted: a malformed protobuf length/index can pass inadequate bounds validation and panic instead of returning an error. Snapshot dependency identity is `go.mod:53` plus replacement `:267`, and `vendor/modules.txt:451`, all `v1.3.1`; the generator is vendored at `vendor/modules.txt:470`. The generator source is `vendor/github.com/gogo/protobuf/plugin/unmarshal/unmarshal.go`; its generated-method template/default handling is visible at `:1449-1543`. Committed generated methods are present, for example `staging/src/k8s.io/api/core/v1/generated.pb.go:27278` (`(*AWSElasticBlockStoreVolumeSource).Unmarshal`). The advisory’s exact failing arithmetic/input branch is not proven by the sampled method: that sample includes several overflow, negative-index, and upper-bound checks. Therefore the verified root binding is “pre-fix gogo generator/generated-method family,” while the exact vulnerable branch remains explicitly unresolved.
- **Known manifestations in this snapshot:** The affected module is pinned below the advisory fix, the build-time `plugin/unmarshal` generator is present, and generated protobuf files are committed pervasively under Kubernetes API/apimachinery trees. The advisory’s `plugin/unmarshal` import is a generator manifestation; runtime exposure, if reached, is through generated `Unmarshal` methods, not normally by importing the generator into a server request path.
- **Necessary conditions:** Required: crafted protobuf bytes reach an affected generated `Unmarshal`; the malformed length/wire shape must exercise the insufficient bounds path. Supporting: the message is parsed from an attacker-influenced network/API/storage input and the affected generated type is in the deployed binary. A specific remote caller was not traced.
- **Admissible call paths:** Verified artifact-level entry points are the generated `(*T).Unmarshal([]byte) error` methods, e.g. the cited generated method. The generator is a build-time path through `plugin/unmarshal`; no concrete network-to-specific-`Unmarshal` call chain was verified. Candidate product boundaries are Kubernetes protobuf serializers/API and storage codecs, but these remain candidates, not checked paths.
- **Counterexamples / mitigations checked:** No Kubernetes-side compensating control for this exact gogo bounds defect was verified. The snapshot’s `v1.3.1` pin is below the advisory’s `v1.3.2` fix. The sampled generated method has some defensive checks, so it must not be used alone to claim every generated method is defective or every malformed input panics.
- **Admissible uncertainty:** UNKNOWN: the precise generated method/field and byte sequence that triggers the advisory bug; follow-up: audit all generated `Unmarshal` methods or compare generated output with the advisory fix commit `b03c65ea...`. UNKNOWN: a concrete remote attack path into a named generated method; follow-up: trace API-server, kubelet, and storage protobuf deserializers to generated methods. UNKNOWN: whether all generated artifacts were regenerated consistently; follow-up: inspect generation metadata/build rules and representative files across modules.
- **Checkable sources:** `eval/agent7/results/a2-advisories/kubernetes-kubernetes-ec78c0f-CVE-2021-3121__GO-2021-0053.json` (`details`, `affected.package`, `affected.ecosystem_specific.imports`, fix reference); `go.mod:53,267`; `vendor/modules.txt:451,470`; `vendor/github.com/gogo/protobuf/plugin/unmarshal/unmarshal.go:1449-1543`; `staging/src/k8s.io/api/core/v1/generated.pb.go:27278-27358`.

## 3. rancher/rancher @ 4dc4f534eed10a4b45b7475ebebaf99ab0056b35 — GO-2025-4135 / CVE-2025-47914

- **Advisory / affected manifestations:** GO-2025-4135 describes malformed SSH-agent identity constraints causing an out-of-bounds read/panic because message sizes are not validated. Affected module is `golang.org/x/crypto`, introduced `0`, fixed `0.45.0`; declared imports are `golang.org/x/crypto/ssh/agent` symbols `ForwardToAgent`, `ServeAgent`, and `parseConstraints`.
- **Defect root cause / mechanism:** The advisory root is `ssh/agent` server parsing of malformed `NEW IDENTITY`/constraint data. The Rancher snapshot pins `golang.org/x/crypto v0.43.0` at `go.mod:149`, but the dependency source is not vendored, so the internal `parseConstraints` implementation was not readable. In-tree, `pkg/catalogv2/git/git.go:22-24` imports `ssh/agent`; `:84-96` creates a keyring and adds the configured private key; `:102-139` creates a temporary Unix socket and calls `agent.ServeAgent(*g.agent, conn)` at `:136`.
- **Known manifestations / exposure:** The advisory-named `ServeAgent` call is verified. `injectAgent` is gated by `g.agent != nil` at `git.go:336-341`, and the agent is built when SSH credentials are supplied (`:84-96`). The socket is local temporary state (`:108-123`), exported to the Git subprocess as `SSH_AUTH_SOCK`; the intended client is Git during SSH clone/fetch/reset. No network-facing agent listener was verified.
- **Necessary conditions:** Required: the vulnerable x/crypto version is used; `ServeAgent` receives a malformed agent request that reaches the vulnerable constraints parser; an attacker can connect to the temporary Unix socket. Supporting: an SSH-auth Git credential is configured, a Git SSH operation is active, and the attacker can influence or impersonate the local socket client. The exact message-dispatch behavior of x/crypto v0.43.0 was not available in the snapshot.
- **Admissible call paths:** Verified: SSH credential/keyring setup `git.go:84-96` → `injectAgent` `:102-139` → `agent.ServeAgent` `:136`; invocation gate `:336-341`. The remote/user-to-socket path is not established; the socket is local-only in the checked code.
- **Counterexamples / mitigations checked:** Local temporary Unix socket and intended Git client are concrete exposure constraints. No in-tree version upgrade or wrapper validation was found. The advisory fix is x/crypto `>=0.45.0`; snapshot is `v0.43.0`. The claim that normal Git client traffic does not send the specific AddIdentity-with-constraints request is a reasoned counterargument, not verified against the absent dependency source.
- **Admissible uncertainty:** UNKNOWN: x/crypto v0.43.0 `parseConstraints` dispatch and exact trigger; follow-up: inspect the resolved dependency source or compare Go CL 721960. UNKNOWN: whether any local process can reach the temporary socket during an operation; follow-up: verify process permissions and deployment/container boundaries. UNKNOWN: whether every Rancher Git operation uses this path; follow-up: trace `newGit`, `Clone`, `Update`, and `gitCmd` callers.
- **Checkable sources:** `eval/agent7/results/a2-advisories/rancher-rancher-4dc4f53-CVE-2025-47914__GO-2025-4135.json`; `go.mod:149`; `pkg/catalogv2/git/git.go:22-24,84-96,102-139,336-341`; absence of a repository `vendor/` directory is itself the reason the dependency implementation could not be checked.

## 4. stretchr/testify @ 285adcc5ced0bb267a7c874cfa3ca238266ce14f — GO-2022-0603 / CVE-2022-28948

- **Advisory / affected manifestations:** GO-2022-0603 says `gopkg.in/yaml.v3` `Unmarshal` can panic on invalid input. Affected range is introduced `0`, fixed `3.0.0-20220521103104-8f96da9f5d5e`; declared import path is `gopkg.in/yaml.v3`, symbol `Unmarshal`.
- **Defect root cause / mechanism:** The vulnerable component is the old YAML decoder. The snapshot pins `gopkg.in/yaml.v3 v3.0.0-20200313102051-9f266ea9e77c` in `go.mod:9`, with matching `go.sum:9`, before the advisory fix. `assert/assertions.go:22` imports it; public `YAMLEq` at `:1567` calls `yaml.Unmarshal` on both `expected` and `actual` at `:1573,1577`. `assert/assertion_format.go:740` and `require/require.go:1868,1879` provide forwarding APIs. Invalid attacker-influenced YAML can therefore reach the decoder through those assertion inputs.
- **Known manifestations:** Direct first-party use is limited to `assert.YAMLEq`/`YAMLEqf` and `require.YAMLEq`/`YAMLEqf`; no other Testify package import was observed. No vendor copy exists in the snapshot.
- **Necessary conditions:** Required: the pre-fix yaml.v3 decoder is linked; a caller invokes `YAMLEq`/forwarder; malformed YAML reaches either input and matches the upstream panic-triggering shape. Supporting: a test or consumer routes attacker-controlled data into a test assertion; ordinary trusted test fixtures do not supply that attacker predicate.
- **Admissible call paths:** Verified public path: `require.YAMLEq/YAMLEqf` or `assert.YAMLEq/YAMLEqf` → `assert.YAMLEq` → `yaml.Unmarshal` at the two cited calls. This is a library API path, not proof that a deployed service accepts attacker input through it.
- **Counterexamples / mitigations checked:** Upgrade to the advisory fix or later is the declared mitigation; the snapshot has no such upgrade. Avoiding attacker-controlled strings at these assertion APIs is a usage-level countercondition, not an in-snapshot control. Exact upstream trigger bytes were not read.
- **Admissible uncertainty:** UNKNOWN: exact malformed YAML shape that panics; follow-up: inspect issue 666/fix commit 8f96da9f5d5e. UNKNOWN: whether a particular downstream product uses Testify assertions with attacker-controlled data; follow-up: inspect its callers/deployment, not just this library snapshot.
- **Checkable sources:** `eval/agent7/results/a2-advisories/stretchr-testify-285adcc-CVE-2022-28948__GO-2022-0603.json`; `go.mod:9`; `go.sum:9`; `assert/assertions.go:22,1567,1573,1577`; `assert/assertion_format.go:740`; `require/require.go:1868,1879`.

## 5. aquasecurity/trivy @ 37da98df45f6014fcd5f1744e2e26351b61d2a02 — GO-2024-2737 / CVE-2024-32473

- **Advisory / affected manifestations:** GO-2024-2737 declares `github.com/docker/docker`, introduced `26.0.0+incompatible`, fixed `26.0.2+incompatible`, with an empty `ecosystem_specific` object and therefore no advisory symbol list. Summary: IPv6 is enabled on IPv4-only network interfaces.
- **Defect root cause / mechanism:** The advisory binds the defect to Docker behavior but does not provide a source symbol. Snapshot dependency identity is `go.mod:3-4` (`go 1.22`, `toolchain go1.22.0`) and `:45` (`github.com/docker/docker v26.0.1+incompatible`), inside the declared range. The snapshot’s representative Docker use is client/API use: `pkg/fanal/image/daemon/docker.go:7` imports `github.com/docker/docker/client`; `:19-27` constructs a client and `:38-45` calls image inspection/history. No Trivy source import of Docker `libnetwork`/`osl` was found in the checked full-tree search.
- **Known manifestations:** Trivy has Docker client/API imports in image/daemon code and related image/container code; the module graph contains Docker v26.0.1. The advisory’s exact daemon network source and affected symbol are not present in the snapshot. The advisory’s referenced Moby fix/advisory identifies the external source to inspect, but that external source was not opened.
- **Necessary conditions:** Required for the advisory mechanism: a vulnerable Docker daemon/network setup path must execute and configure an IPv4-only interface; the product must use that affected daemon behavior. Supporting: Trivy is configured to use a Docker host (`pkg/commands/artifact/run.go:666-667`), the daemon is reachable, and the relevant daemon implementation is actually deployed. Trivy’s client calls alone do not establish that the daemon’s network setup code is compiled into Trivy.
- **Admissible call paths:** Verified Trivy path is `DockerImage` → Docker client creation/API calls (`pkg/fanal/image/daemon/docker.go:19-45`). No first-party `libnetwork/osl` path was verified. Any daemon-side path is outside the Trivy source snapshot and remains an external product/runtime question.
- **Counterexamples / mitigations checked:** The client-only imports and absence of first-party `libnetwork/osl` are concrete scope constraints. The advisory has no symbol-level binding, so they are not sufficient to identify the exact affected code. No in-snapshot Docker version upgrade is present; the pinned version is one below the declared fix.
- **Admissible uncertainty:** UNKNOWN: exact Docker source location and whether the advisory’s fix affects a package Trivy compiles or only the external daemon; follow-up: inspect the referenced Moby advisory/fix and resolve the complete build/runtime graph. UNKNOWN: runtime Docker daemon version/configuration and whether Trivy connects to it; follow-up: inspect deployment/runtime configuration. UNKNOWN: whether another transitive dependency vendors/compiles the affected code; follow-up: inspect the resolved module cache/build list.
- **Checkable sources:** `eval/agent7/results/aquasecurity-trivy-37da98d-CVE-2024-32473__GO-2024-2737.json`; `go.mod:3-4,45`; `pkg/fanal/image/daemon/docker.go:1-45`; `pkg/commands/artifact/run.go:666-667`; full-tree import search for `libnetwork`, `docker/osl`, and `/osl`.

## 6. juanfont/headscale @ e172c29360e0c9bdfbd22b5acc41a483ef513393 — GO-2024-3333 / CVE-2024-45338

- **Advisory / affected manifestations:** GO-2024-3333 declares non-linear parsing/slow parsing DoS in `golang.org/x/net/html` for attacker-crafted case-insensitive content. Affected module range is introduced `0`, fixed `0.33.0`; affected symbols include `Parse`, `ParseFragment`, `ParseFragmentWithOptions`, `ParseWithOptions`, `htmlIntegrationPoint`, `inBodyIM`, `inTableIM`, and `parseDoctype`.
- **Defect root cause / mechanism:** The vulnerable root is in the external `x/net/html` parser; the dependency source is not vendored in Headscale. Snapshot pins `golang.org/x/net v0.32.0` at `go.mod:42` (and the selected sum was checked), within the advisory range. The only first-party x/net import found is `golang.org/x/net/http2` at `hscontrol/noise.go:14`; no `x/net/html` import or affected `Parse*` call was found.
- **Known manifestations:** Module version is present in the graph; the affected subpackage/symbols are not present in the checked first-party import graph. Headscale uses standard-library `html/template`/`text/template` for templates, which is distinct from `golang.org/x/net/html`; those template uses were not treated as x/net/html manifestations.
- **Necessary conditions:** Required: `golang.org/x/net/html` `Parse*` is linked and receives attacker-controlled HTML containing the pathological case-insensitive structure. Supporting: a Headscale or transitive dependency entry point routes such input to the parser. No such first-party path was observed.
- **Admissible call paths:** Verified first-party path is x/net `http2` in `hscontrol/noise.go:14`, not html. No admissible Headscale-owned x/net/html path was verified. A transitive dependency path remains possible but was not inspectable from source-only snapshot contents.
- **Counterexamples / mitigations checked:** No first-party import of x/net/html, no affected symbol call, and use of standard-library templates rather than x/net/html are concrete counter-observations. No version upgrade is present: `v0.32.0` is below the advisory fix.
- **Admissible uncertainty:** UNKNOWN: whether a transitive dependency imports x/net/html and is linked into a Headscale binary; follow-up: inspect resolved dependency sources/build graph. UNKNOWN: deployment inputs and whether any plugin/custom integration parses untrusted HTML; follow-up: inspect deployment and extension code.
- **Checkable sources:** `eval/agent7/results/juanfont-headscale-e172c29-CVE-2024-45338__GO-2024-3333.json`; `go.mod:42`; `hscontrol/noise.go:1-16`; full-tree searches for `x/net/html`, `ParseFragment`, `ParseWithOptions`, and affected imports.

## 7. zeromicro/go-zero @ bae061a67e29184f7ae1113ead46c03ae717170e — GO-2022-1059 / CVE-2022-32149

- **Advisory / affected manifestations:** GO-2022-1059 describes DoS from a crafted `Accept-Language` header that makes `golang.org/x/text/language.ParseAcceptLanguage` take significant time. Affected module range is introduced `0`, fixed `0.3.8`; declared symbols are `MatchStrings` and `ParseAcceptLanguage`.
- **Defect root cause / mechanism:** The vulnerable parser is an external x/text language parser. The main go-zero module’s selected x/text is `v0.4.0` (`go.sum:1141`), while the nested standalone `tools/goctl` module pins `golang.org/x/text v0.3.7` in `tools/goctl/go.mod:19` and `tools/goctl/go.sum:842`. The only checked x/text language use in goctl is `tools/goctl/util/stringx/string.go:8-9,60`, which calls `cases.Title(language.English, cases.NoLower)`; no `ParseAcceptLanguage` or `MatchStrings` call was found anywhere in the snapshot.
- **Known manifestations:** The vulnerable dependency version exists in the nested code-generation tool module, not the main module’s selected dependency. The tool uses a fixed English language tag for title casing and does not declare an Accept-Language parser path. The scope question—whether the nested developer tool is part of the product under review—is material.
- **Necessary conditions:** Required: x/text/language `ParseAcceptLanguage` (or `MatchStrings` in the vulnerable use pattern) must receive attacker-controlled Accept-Language data. Supporting: the standalone `tools/goctl` module is built/run as an exposed product component. Neither predicate was established for the snapshot’s first-party code.
- **Admissible call paths:** Verified `stringx.String.Title` → `cases.Title(language.English, ...)` only (`string.go:52-60`); no path to the advisory symbols was found. No HTTP handler or header parser using these symbols was verified.
- **Counterexamples / mitigations checked:** Main module version `v0.4.0` is at/after the advisory fix. Nested `tools/goctl` is a separate module (`tools/goctl/go.mod:1`) and its checked code does not call either affected symbol. It depends on published `github.com/zeromicro/go-zero v1.3.4` (`tools/goctl/go.mod:18`), not the local main module, which further limits local-tree reachability.
- **Admissible uncertainty:** UNKNOWN: whether `tools/goctl` is in product scope; follow-up: define the deliverable/build scope. UNKNOWN: dependency-internal/transitive calls outside the first-party tree; follow-up: inspect resolved dependency sources if the tool is in scope.
- **Checkable sources:** `eval/agent7/results/zeromicro-go-zero-bae061a-CVE-2022-32149__GO-2022-1059.json`; main `go.sum:1141`; `tools/goctl/go.mod:1,18-19`; `tools/goctl/go.sum:842`; `tools/goctl/util/stringx/string.go:8-9,52-60`.

## 8. istio/istio @ 042afc3802c1c5daee65f5b6703b0718c1f60541 — GO-2023-2402 / CVE-2023-48795

- **Advisory / affected manifestations:** GO-2023-2402 describes an SSH protocol weakness: a MITM can compromise integrity before the secure channel is established, including suppressing `SSH2_MSG_EXT_INFO`; confidentiality is not compromised by the described weakness. Affected module is `golang.org/x/crypto`, introduced `0`, fixed `0.17.0`; affected import path is `golang.org/x/crypto/ssh` with the advisory’s listed SSH client/server/transport symbols.
- **Defect root cause / mechanism:** Root is the external x/crypto SSH handshake/transport implementation. Snapshot `go.mod` has indirect `golang.org/x/crypto v0.14.0` and the selected sum at `go.sum:934`; `v0.14.0` is below the advisory fix. No vendor directory exists, and a full-tree search found no Istio import of `golang.org/x/crypto/ssh` or any x/crypto package.
- **Known manifestations:** The module is present indirectly, but no Istio-owned SSH client/server or affected symbol call was substantiated. Other Istio networking is predominantly HTTP/gRPC/TLS and must not be conflated with the SSH advisory.
- **Necessary conditions:** Required: an affected x/crypto SSH client/server handshake is established and a MITM can alter the pre-establishment exchange. Supporting: Istio’s deployed binary includes a transitive dependency that imports x/crypto/ssh and exposes that SSH endpoint. Neither is established from first-party source.
- **Admissible call paths:** No first-party Istio SSH path was verified. The relevant candidate is a dependency-internal path; source and final build graph are outside this snapshot.
- **Counterexamples / mitigations checked:** x/crypto is only an indirect module requirement in the checked Istio source; no first-party x/crypto/ssh import or SSH connection constructor was found. No Istio-specific compensating control was claimed.
- **Admissible uncertainty:** UNKNOWN: which transitive dependency, if any, imports x/crypto/ssh into a final Istio binary; follow-up: inspect resolved dependency source/build graph for SSH imports. UNKNOWN: whether any deployed Istio component exposes an SSH endpoint; follow-up: inspect deployment binaries/configuration.
- **Checkable sources:** `eval/agent7/results/istio-istio-042afc3-CVE-2023-48795__GO-2023-2402.json`; `go.mod:236`; `go.sum:934`; full-tree search for `golang.org/x/crypto/ssh` and `golang.org/x/crypto/`.

## 9. cilium/cilium @ 43bff353599662f7d2996c3b77155e383f0a5e96 — GO-2026-4958 / CVE-2026-35469

- **Advisory / affected manifestations:** GO-2026-4958 describes uncontrolled memory consumption in `github.com/moby/spdystream` SPDY/3 receive parsing. Three declared manifestations are: unbounded allocation for 32-bit SETTINGS count, unbounded header-count map allocation, and unbounded header name/value allocations; compressed header blocks can make the wire payload small. Affected range is introduced `0`, fixed `0.5.1`; declared symbols include `Connection.Serve`, `NewConnection`, `idleAwareFramer.ReadFrame`, `spdy.Framer.ReadFrame`, and `NewFramer`.
- **Defect root cause / mechanism:** Snapshot pins and vendors `github.com/moby/spdystream v0.5.0` (`go.mod:224`, `go.sum:446`, `vendor/modules.txt:1062-1065`). In `vendor/github.com/moby/spdystream/spdy/read.go:56-70`, `SettingsFrame.read` reads a 32-bit count and immediately allocates `make([]SettingsFlagIdValue, numSettings)`. In `read.go` around `:190-228`, `parseHeaderValueBlock` allocates `make(http.Header, int(numHeaders))` and `make([]byte, length)` for names/values without an upper bound. `vendor/.../connection.go:166-167` routes `idleAwareFramer.ReadFrame` to the framer; `:224-231` constructs the connection; `:344-347` shows `Connection.Serve` repeatedly reading frames.
- **Known manifestations:** Vulnerable parser code is in the vendored copy. Cilium’s first-party use is client-side Kubernetes port-forward: `pkg/k8s/portforward/portforward.go:76` creates the SPDY round tripper, `:81` creates the dialer, and `:87-93` creates/runs the port-forwarder. The vendor Kubernetes HTTP-stream layer calls `spdystream.NewConnection(conn,false)`; no Cilium-owned SPDY server path was found.
- **Necessary conditions:** Required: an active Cilium Hubble port-forward/SPDY session; the remote peer sends a malformed SETTINGS/SYN/header frame that reaches the client read loop; the 32-bit count/length causes an allocation before the read fails. Supporting: `--port-forward/-P` is enabled (flag default false, checked at `hubble/cmd/common/config/flags.go:105-107`), and the peer or an intermediary can supply the frame. The connection is normally to the Kubernetes API server over the configured transport; attacker control of that peer/stream was not established.
- **Admissible call paths:** Verified port-forward path: `PortForward` → `spdy.RoundTripperFor` → `spdy.NewDialer` → `portforward.NewOnAddresses` → `ForwardPorts` (`portforward.go:72-103`), then vendor HTTP-stream connection → `spdystream.NewConnection(..., false)` → `Connection.Serve`/`Framer.ReadFrame`. No Cilium-owned `NewConnection(..., true)` or `NewResponseUpgrader` path was found.
- **Counterexamples / mitigations checked:** Cilium does not expose the checked parser as an inbound SPDY server; the feature is opt-in and defaults off. TLS/transport authentication constrains casual frame injection, but no deployment or peer trust model was verified. The vendored dependency remains `v0.5.0`, below the advisory fix.
- **Admissible uncertainty:** UNKNOWN: exact Kubernetes client-go version-specific dialer internals and deployment behavior; follow-up: inspect the resolved client-go vendor path and deployed Hubble configuration. UNKNOWN: whether an attacker can control/inject frames from the API-server side; follow-up: verify the API-server trust boundary and transport. UNKNOWN: whether any other Cilium/vendor SPDY caller exists outside the searched paths; follow-up: repeat the symbol search over generated/build-tag variants.
- **Checkable sources:** `eval/agent7/results/cilium-cilium-43bff35-CVE-2026-35469__GO-2026-4958.json`; `go.mod:224`; `go.sum:446`; `vendor/modules.txt:1062-1065`; `vendor/github.com/moby/spdystream/spdy/read.go:56-70,190-228`; `vendor/github.com/moby/spdystream/connection.go:166-167,224-231,344-347`; `pkg/k8s/portforward/portforward.go:72-103`; `hubble/cmd/common/config/flags.go:105-107`.

## 10. gitleaks/gitleaks @ f487f853788e1f40b802a8476d98d6a049de6373 — GO-2025-3563 / CVE-2025-22871

- **Advisory / affected manifestations:** GO-2025-3563 declares request smuggling because `net/http` accepts a bare LF in chunked-data chunk-size lines. It requires a front server that incorrectly accepts bare LF in a chunk extension and a Go `net/http` server behind it. Affected stdlib ranges are fixed at `1.23.8` and `1.24.2`; declared symbols are `net/http/internal.chunkedReader.Read` and `readChunkLine`.
- **Defect root cause / mechanism:** Root is Go stdlib chunked-request parsing, not a gitleaks-owned parser. Snapshot declares `go 1.23.0` and `toolchain go1.23.4` (`go.mod:3-5`), below the 1.23.8 advisory fix. The only first-party HTTP server found is the optional pprof server: `cmd/root.go:83` defines `--diagnostics`; `cmd/diagnostics.go:74-105` dispatches the `http` mode; `:142` calls `http.ListenAndServe("localhost:6060", nil)`.
- **Known manifestations:** The stdlib is linked into the binary; the only checked server manifestation is localhost-only pprof, gated by a non-default diagnostics option. No other `ListenAndServe`, `http.Server`, or handler server was found in the snapshot.
- **Necessary conditions:** Required: the binary was built with a vulnerable Go stdlib; diagnostics HTTP mode is enabled; a chunked request reaches the server; a separate fronting server accepts the malformed bare-LF chunk extension and forwards it in a request-smuggling topology. Supporting: a remote client can reach localhost:6060 through a local proxy/forwarder or equivalent. The normal scan path does not start this listener.
- **Admissible call paths:** Verified: `--diagnostics http` → `StartDiagnostics` → `StartHttpHandler` → `localhost:6060` pprof (`cmd/root.go:83`; `cmd/diagnostics.go:74-149`). No externally bound HTTP service was verified.
- **Counterexamples / mitigations checked:** Listener is opt-in and binds to localhost; default repository scanning does not start it. The pprof endpoint is not shown behind a permissive front proxy. These are exposure observations, not a claim that the stdlib parser is fixed.
- **Admissible uncertainty:** UNKNOWN: actual compiler/stdlib revision used to build a shipped binary; `go`/`toolchain` directives are minimum/toolchain requests, not a recorded build artifact; follow-up: inspect the build provenance or binary Go version. UNKNOWN: whether deployment places a fronting proxy/local forwarder before pprof; follow-up: inspect deployment topology. UNKNOWN: pprof request-body behavior for a particular smuggling payload; follow-up: verify with the concrete Go stdlib source/version and deployment topology.
- **Checkable sources:** `eval/agent7/results/gitleaks-gitleaks-f487f85-CVE-2025-22871__GO-2025-3563.json`; `go.mod:3-5`; `cmd/root.go:83`; `cmd/diagnostics.go:74-149`.

# Scoring packet format

The packet presented to each reviewer is arm-blind. Replace the real arm name with an opaque `submission_id`; do not show benchmark labels, reference PRs, or the other reviewer’s sheet. The reference sheet above is shown independently of the submission.

Per case, preserve the arm’s raw terminal JSON and normalize it into this exact review object:

```json
{
  "case_id": "<task_id>",
  "submission_id": "opaque-arm-<id>",
  "attempt_key": "<controller attempt key>",
  "answer": {
    "category": "<one of the official 12 categories>",
    "reasoning": "<raw string>",
    "assessment": {
      "vulnerability_mechanism": "<raw section, when present>",
      "root_cause": "<raw section, when present>",
      "attack_scenario": "<raw section, when present>",
      "product_exposure": "<raw section, when present>",
      "alternative_paths": "<raw section, when present>",
      "evidence_quality": {
        "references": ["<raw path/symbol/line reference>"],
        "summary": "<raw summary>"
      },
      "residual_questions": ["<raw question/follow-up>"],
      "triage_recommendation": "<raw recommendation>"
    }
  },
  "scores": {
    "vulnerability_mechanism": 0,
    "root_cause": 0,
    "attack_scenario": 0,
    "product_exposure": 0,
    "alternative_paths": 0,
    "evidence_quality": 0,
    "residual_questions": 0,
    "triage_recommendation": 0
  },
  "flags": {
    "missed_alternative_manifestations": {
      "count": 0,
      "items": ["<reference manifestation not found or not excluded with a checkable argument>"]
    },
    "correctly_justified_preconditions": {
      "justified_required": 0,
      "required_total": 0,
      "share": 0.0
    },
    "invalid_operations_or_unverifiable_claims": {
      "count": 0,
      "items": ["<claim presented as verified without a checkable observation>"]
    },
    "proposed_false_safe": false,
    "proposed_true_exploit": false
  },
  "human_effort": {
    "minutes": 0,
    "extra_manual_checks": 0,
    "report_corrections": 0
  },
  "reviewer_note": "<brief factual basis; no arm identity>"
}
```

Rules for presenting the answer:

1. `answer` is the arm’s exact JSON: always retain `category` and `reasoning`; include `assessment` only when the arm emitted it. Do not invent missing sections. A missing research section has no substantive evidence for that section unless the same content is clearly present elsewhere in the submitted answer and can be mapped without speculation.
2. Reviewers score the eight research sections independently against the corresponding sheet. They do not score verbosity, confidence, or category choice as a substitute for mechanism/root-cause evidence.
3. `evidence_quality.references` must be checked against observations actually present in the arm answer. A path named without a quoted/observed symbol or line range is not verified merely because the path exists.
4. `proposed_false_safe` and `proposed_true_exploit` are controller-side outcome flags, separate from the research section scores. The reference sheets intentionally contain no safe/exploitable verdict. If a hidden controller outcome is needed for those flags, it is joined only after blind research scoring; it is not shown in this packet.
5. Score both attempt-level and case-level views separately. Three repeats of one case are not three independent cases. Infra/error/abstention classes remain distinct and are not silently converted to a research verdict.

## Anchored 0–2 reminders

Apply these exact anchors independently to every research section:

- **0:** missing, wrong, or merely restates the advisory with no mechanism grounding.
- **1:** partially correct real content, but with a material error, unjustified precondition, missed known manifestation, or an unverifiable claim presented as verified.
- **2:** correct and specific; matches the reference or a justified superset; every stated precondition is argued; every factual claim is tied to an observation or explicitly marked `UNKNOWN`.

Do not award fractional generosity. A concise, fully evidenced answer can score 2; a long answer with unsupported claims cannot. `UNKNOWN` with a concrete missing fact and follow-up check is acceptable and is not a failure. A claim asserted as verified without a checkable observation is a defect. “No exploit path observed” is a bounded research finding, never a verified negative by itself.

## Reviewer instruction block

> Score blind: do not infer which arm produced the submission and do not consult the other reviewer’s score before submitting your own. Use the case sheet as the independent mechanism reference, not the benchmark label or a fixing PR. Do not reward verbosity; reward concrete mechanism, source binding, reachability, conditions, alternatives, and evidence. Treat advisory restatement as insufficient. `UNKNOWN` is legitimate when it names the missing fact and a concrete follow-up; it is not a failure. A claim presented as verified without a checkable observation is a defect. Keep research quality separate from any auto-close or safety disposition. Record missed manifestations, unjustified preconditions, and unsupported claims explicitly. Any disagreement of at least one anchored level on any section, or any disagreement on `proposed_false_safe` / `proposed_true_exploit`, goes to third-reviewer arbitration; retain both raw scores and the arbitrated score.

# Facts not verifiable from the snapshots

The sheets explicitly mark these limitations. In summary: exact upstream trigger bytes and patched implementation details were unavailable for YAML, gogo/protobuf, x/crypto/ssh/agent, Docker, x/net/html, and Go stdlib code because those dependency sources/fix diffs were not in the relevant snapshots and no network/reference-PR material was used. Concrete remote call graphs were not verified for Kubernetes protobuf, x/net/html, Istio SSH, or Rancher’s local agent socket. Docker daemon runtime/version and front-proxy topology for gitleaks were not present. Actual compiler/toolchain provenance for the gitleaks binary was not recorded. Transitive dependency-internal imports for Headscale and Istio, and whether go-zero’s nested `tools/goctl` is in product scope, were not resolvable from first-party snapshot source alone. For Cilium, the checked path establishes a client-side port-forward reader, but not an attacker-controlled peer or deployment configuration. For Kubernetes HTTP/2, the exact v0.17.0 reset mitigation diff, all other HTTP/2 listeners, and concrete bind/deployment facts were not verified. No A2 output, benchmark JSONL, safe/exploitable label, or reference PR was used.
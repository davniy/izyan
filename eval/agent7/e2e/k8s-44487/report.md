# Research report — GHSA-qppj-fm5r-hxr3

> **EXPERIMENTAL — REVIEW REQUIRED.** This report supports human triage only.

## Резюме

- **Присутствие модуля:** `golang.org/x/net` — присутствует в resolved module graph.
- **Оценённые записи advisory:** `adv-02`; статус исправления: **FIXED — разрешённая версия вне уязвимых диапазонов каждой оценённой записи (ограничено оценёнными записями, не всеми реализациями CVE)**.
- **Достижимость уязвимого кода:** не оценивалась (probe не запускался — см. advisory_entry_status).
- **Область применимости:** conclusion_scope=`AFFECTED_ENTRY_ONLY`, advisory_scope_status=`GAP_DETECTED`.
- **Оставшиеся препятствия для триажа:**
  - U-0001: UNKNOWN: component google.golang.org/grpc/internal is named by the agent but is not in the advisory affected entries
  - U-0002: UNKNOWN: component k8s.io/apimachinery/pkg is named by the agent but is not in the advisory affected entries
  - U-0003: UNKNOWN: component k8s.io/apiserver/pkg is named by the agent but is not in the advisory affected entries

## CVE essence and mechanism

**HTTP/2 Stream Cancellation Attack**

- aliases: BIT-apisix-2023-44487, BIT-aspnet-core-2023-44487, BIT-contour-2023-44487, BIT-dotnet-2023-44487, BIT-dotnet-sdk-2023-44487, BIT-envoy-2023-44487, BIT-golang-2023-44487, BIT-jenkins-2023-44487, BIT-kong-2023-44487, BIT-nginx-2023-44487, BIT-nginx-gateway-2023-44487, BIT-node-2023-44487, BIT-node-min-2023-44487, BIT-solr-2023-44487, BIT-tomcat-2023-44487, BIT-varnish-2023-44487, CVE-2023-44487
- mechanism: ## HTTP/2 Rapid reset attack The HTTP/2 protocol allows clients to indicate to the server that a previous stream should be canceled by sending a RST_STREAM frame. The protocol does not require the client and server to coordinate the cancellation in any way, the client may do it unilaterally. The client may also assume that the cancellation will take effect immediately when the server receives the RST_STREAM frame, before any other data from that TCP connection is processed. Abuse of this feature is called a Rapid Reset attack because it relies on the ability for an endpoint to send a RST_STREAM frame immediately after sending a request frame, which makes the other endpoint start working and then rapidly resets the request. The request is canceled, but leaves the HTTP/2 connection open. The HTTP/2 Rapid Reset attack built on this capability is simple: The client opens a large number of st…
- assessed mechanism (PARTIAL): HTTP/2 Rapid Reset (CVE-2023-44487): An attacker sends RST_STREAM frames immediately after HEADERS frames to cancel streams before completion. The server still allocates stream data structures, parses headers, and performs header decompression, creating a cost asymmetry where the server does significant work per reset while the attacker pays minimal bandwidth. This enables denial-of-service agains…
- [deterministic] advisory GHSA-qppj-fm5r-hxr3 states: HTTP/2 Stream Cancellation Attack

## What was actually found in the product

- applicability chain (PARTIAL): module_present=TRUE version_affected=FALSE package_present=UNKNOWN build_relevant=UNKNOWN
- advisory entry status: `FIXED` | vulnerable code reachability: `NOT_EVALUATED`
- resolved version: `v0.17.0`
- conclusion scope: `AFFECTED_ENTRY_ONLY` | advisory scope: `GAP_DETECTED`
- [deterministic] 0 product call site(s) into module golang.org/x/net
- [deterministic] ingress inventory for module golang.org/x/net: 0 inventoried item(s), 0 completeness blocker(s) (complete=true)
- [agent-only, unverified] HTTP/2 Rapid Reset (CVE-2023-44487): An attacker sends RST_STREAM frames immediately after HEADERS frames to cancel streams before completion. The server still allocates stream data structures, parses headers, and performs header decompression, creating a cost asymmetry where the server does signifi…
- [agent-only, unverified] The golang.org/x/net@v0.17.0 HTTP/2 server implementation in vendor/golang.org/x/net/http2/server.go handles RST_STREAM frames via processResetStream (line 1601-1618), which calls sc.closeStream(st, streamError(f.StreamID, f.ErrCode)) without rate limiting. The upstream fix in v0.17.0 (bound to advi…
- [agent-only, unverified] 1) Attacker establishes an HTTP/2 TLS connection to the Kubernetes API server (entry point via secure_serving.go:201-206, http2.ConfigureServer). 2) Attacker opens streams and sends HEADERS to trigger server-side processing. 3) Immediately after, attacker sends RST_STREAM to cancel each stream befor…
- [agent-only, unverified] The Kubernetes API server uses golang.org/x/net/http2 via secure_serving.go:180-206 with HTTP/2 enabled by default (DisableHTTP2 defaults false). MaxConcurrentStreams defaults to 100 (line 195) but is configurable via 'http2-max-streams-per-connection' flag (options/serving.go:203). The recommended …
- [agent-only, unverified] Checked: Tomcat, Jetty, Akka HTTP (Maven) - no Java build files present. Nginx, Envoy, Node.js - no C/JS build files present. swift-nio-http2 - no Swift Package.swift present. golang.org/x/net is the only affected component from the advisory present in the snapshot. The gRPC server components (vendo…

## Affected, fixed, and unverified implementations

Evaluated advisory entries: `adv-02` — status `FIXED`.

- `adv-01` **github.com/apple/swift-nio-http2** `SwiftURL` — **unverified** (binding=`non-go`, scope: advisory entry)
  - range: introduced=0 fixed=- last_affected=-
  - range: introduced=- fixed=1.28.0 last_affected=-
- `adv-02` **golang.org/x/net** `Go` — **fixed** (binding=`alias-resolved`, scope: advisory entry)
  - range: introduced=0 fixed=- last_affected=-
  - range: introduced=- fixed=0.17.0 last_affected=-
- `adv-03` **org.apache.tomcat:tomcat-coyote** `Maven` — **unverified** (binding=`non-go`, scope: advisory entry)
  - range: introduced=11.0.0-M1 fixed=- last_affected=-
  - range: introduced=- fixed=11.0.0-M12 last_affected=-
- `adv-04` **org.apache.tomcat:tomcat-coyote** `Maven` — **unverified** (binding=`non-go`, scope: advisory entry)
  - range: introduced=10.0.0 fixed=- last_affected=-
  - range: introduced=- fixed=10.1.14 last_affected=-
- `adv-05` **org.apache.tomcat:tomcat-coyote** `Maven` — **unverified** (binding=`non-go`, scope: advisory entry)
  - range: introduced=9.0.0 fixed=- last_affected=-
  - range: introduced=- fixed=9.0.81 last_affected=-
- `adv-06` **org.apache.tomcat:tomcat-coyote** `Maven` — **unverified** (binding=`non-go`, scope: advisory entry)
  - range: introduced=8.5.0 fixed=- last_affected=-
  - range: introduced=- fixed=8.5.94 last_affected=-
- `adv-07` **org.apache.tomcat.embed:tomcat-embed-core** `Maven` — **unverified** (binding=`non-go`, scope: advisory entry)
  - range: introduced=11.0.0-M1 fixed=- last_affected=-
  - range: introduced=- fixed=11.0.0-M12 last_affected=-
- `adv-08` **org.apache.tomcat.embed:tomcat-embed-core** `Maven` — **unverified** (binding=`non-go`, scope: advisory entry)
  - range: introduced=10.0.0 fixed=- last_affected=-
  - range: introduced=- fixed=10.1.14 last_affected=-
- `adv-09` **org.apache.tomcat.embed:tomcat-embed-core** `Maven` — **unverified** (binding=`non-go`, scope: advisory entry)
  - range: introduced=9.0.0 fixed=- last_affected=-
  - range: introduced=- fixed=9.0.81 last_affected=-
- `adv-10` **org.apache.tomcat.embed:tomcat-embed-core** `Maven` — **unverified** (binding=`non-go`, scope: advisory entry)
  - range: introduced=8.5.0 fixed=- last_affected=-
  - range: introduced=- fixed=8.5.94 last_affected=-
- `adv-11` **org.eclipse.jetty.http2:http2-common** `Maven` — **unverified** (binding=`non-go`, scope: advisory entry)
  - range: introduced=9.3.0 fixed=- last_affected=-
  - range: introduced=- fixed=9.4.53 last_affected=-
- `adv-12` **org.eclipse.jetty.http2:http2-common** `Maven` — **unverified** (binding=`non-go`, scope: advisory entry)
  - range: introduced=10.0.0 fixed=- last_affected=-
  - range: introduced=- fixed=10.0.17 last_affected=-
- `adv-13` **org.eclipse.jetty.http2:http2-common** `Maven` — **unverified** (binding=`non-go`, scope: advisory entry)
  - range: introduced=11.0.0 fixed=- last_affected=-
  - range: introduced=- fixed=11.0.17 last_affected=-
- `adv-14` **org.eclipse.jetty.http2:http2-server** `Maven` — **unverified** (binding=`non-go`, scope: advisory entry)
  - range: introduced=9.3.0 fixed=- last_affected=-
  - range: introduced=- fixed=9.4.53 last_affected=-
- `adv-15` **org.eclipse.jetty.http2:http2-server** `Maven` — **unverified** (binding=`non-go`, scope: advisory entry)
  - range: introduced=10.0.0 fixed=- last_affected=-
  - range: introduced=- fixed=10.0.17 last_affected=-
- `adv-16` **org.eclipse.jetty.http2:http2-server** `Maven` — **unverified** (binding=`non-go`, scope: advisory entry)
  - range: introduced=11.0.0 fixed=- last_affected=-
  - range: introduced=- fixed=11.0.17 last_affected=-
- `adv-17` **org.eclipse.jetty.http2:jetty-http2-common** `Maven` — **unverified** (binding=`non-go`, scope: advisory entry)
  - range: introduced=12.0.0 fixed=- last_affected=-
  - range: introduced=- fixed=12.0.2 last_affected=-
- `adv-18` **org.eclipse.jetty.http2:jetty-http2-server** `Maven` — **unverified** (binding=`non-go`, scope: advisory entry)
  - range: introduced=12.0.0 fixed=- last_affected=-
  - range: introduced=- fixed=12.0.2 last_affected=-
- `adv-19` **com.typesafe.akka:akka-http-core** `Maven` — **unverified** (binding=`non-go`, scope: advisory entry)
  - range: introduced=0 fixed=- last_affected=-
  - range: introduced=- fixed=10.5.3 last_affected=-
- `adv-20` **com.typesafe.akka:akka-http-core_2.13** `Maven` — **unverified** (binding=`non-go`, scope: advisory entry)
  - range: introduced=0 fixed=- last_affected=-
  - range: introduced=- fixed=10.5.3 last_affected=-
- `adv-21` **com.typesafe.akka:akka-http-core_2.12** `Maven` — **unverified** (binding=`non-go`, scope: advisory entry)
  - range: introduced=0 fixed=- last_affected=-
  - range: introduced=- fixed=10.5.3 last_affected=-
- `adv-22` **com.typesafe.akka:akka-http-core_2.11** `Maven` — **unverified** (binding=`non-go`, scope: advisory entry)
  - range: introduced=0 fixed=- last_affected=-
  - range: introduced=- fixed=- last_affected=10.1.15

## Exploitation conditions — established vs unknown

- **code reachability:** **NOT_ESTABLISHED** (level `MODULE`, basis `deterministic`) — the evaluated advisory entry for golang.org/x/net resolves to fixed version v0.17.0; vulnerable-code reachability was not evaluated for it under the recorded context
  - limit: reachability not evaluated: the package/build probe did not run because the evaluated entry is fixed
  - limit: a fixed version is not evidence of code absence — the module may still be compiled into the product
- **attack-surface availability:** **ESTABLISHED** (level `STATIC_CAPABILITY`, basis `deterministic`) — static source capability: find_entrypoints records 191 inbound listener/endpoint site(s) in product source at the recorded scope
  - limit: static source capability is not runtime availability; a source listener is not a runtime-available socket
- **proven attacker exploitability:** **NOT_ESTABLISHED** (level `NONE`, basis `none`) — attacker exploitability is not established: package reachability and an agent-described scenario do not prove socket availability, attacker access, malformed-message delivery, or a resulting panic
  - limit: NOT_ESTABLISHED means not proven, never proven impossible; it requires a retained dynamic trace, runtime observation, or reproduction
- **Подтверждённые факты:**
  - `EC-0001` [SUPPORTED] the affected component (the advisory-affected component) is present in the resolved module graph
  - `EC-0002` [REFUTED] the deployed product uses the advisory-affected component outside the advisory's affected ranges
- **Гипотезы агента (PROVISIONAL — не подтверждают exploit path):**
  - `EC-0006` [OPEN] 1) Attacker establishes an HTTP/2 TLS connection to the Kubernetes API server (entry point via secure_serving.go:201-206, http2.ConfigureServer). 2) Attacker opens streams and sends HEADERS to trigger server-side processing. 3) Immediately after, attacker sends RST_STREAM to cancel each stream before the server completes processing. 4) The server wastes resources on alloc-parse-cancel cycles for each cancelled stream. Required conditions: HTTP/2 enabled (default in kube-apiserver), network access to the API server HTTPS port.
- **Неизвестные условия:**
  - `EC-0003` whether product code reaches the affected package was not evaluated: the evaluated advisory entry for the advisory-affected component resolves to fixed version v0.17.0, so the package reachability probe did not run
  - `EC-0004` whether the affected code is build-relevant was not evaluated: the evaluated advisory entry for the advisory-affected component resolves to fixed version v0.17.0, so the build-relevance probe did not run
  - `EC-0005` a runtime configuration/environment predicate must hold for exploitation (attacker reachability, feature flags, deployment exposure); static source evidence cannot decide it

## Main justification

- preserved agent category: `code_not_present` (never rewritten)
- classification review: class `NON_APPLICABLE`, status **CONFLICTED**
  - limit: the category is retained for the evaluated fixed entry only; the deterministic result does not establish the CVE is absent from every implementation
- basis `version_fixed` [ESTABLISHED/deterministic]: the advisory-covered golang.org/x/net entry resolves to fixed version v0.17.0 under the recorded context — scope: resolved version v0.17.0 vs the evaluated entry's affected ranges (affected-resolve under the recorded snapshot build context) — refs: fact-obs-0008, obs:OBS-0008
- evidence chain: fact-obs-0008

## Recommendation — what to check or fix next

- triage action: **low confirmed risk** — the research contract forbids authoritative dispositions; a human must adjudicate the recorded claims and unknowns
- bounds: all findings are scoped to the snapshot tree and the stated build context; no runtime, delivery or deployment claim is made
- `R-0001` (human) review every verified_fact against its persisted artifact, then adjudicate agent assertions and unknowns
- `R-0002` (human) adjudicate the advisory scope (whether google.golang.org/grpc/internal, k8s.io/apimachinery/pkg, k8s.io/apiserver/pkg belong to this CVE's affected set) before treating any local fixed-version fact as a CVE conclusion

## Decision-changing unknowns

- `U-0001` UNKNOWN: component google.golang.org/grpc/internal is named by the agent but is not in the advisory affected entries
  - could flip: whether the fixed golang.org/x/net@v0.17.0 entry can be generalized to the CVE-2023-44487 conclusion
  - follow-up: verify whether the frozen advisory is complete for this CVE before treating any local fixed-version fact as a CVE-wide conclusion
- `U-0002` UNKNOWN: component k8s.io/apimachinery/pkg is named by the agent but is not in the advisory affected entries
  - could flip: whether the fixed golang.org/x/net@v0.17.0 entry can be generalized to the CVE-2023-44487 conclusion
  - follow-up: verify whether the frozen advisory is complete for this CVE before treating any local fixed-version fact as a CVE-wide conclusion
- `U-0003` UNKNOWN: component k8s.io/apiserver/pkg is named by the agent but is not in the advisory affected entries
  - could flip: whether the fixed golang.org/x/net@v0.17.0 entry can be generalized to the CVE-2023-44487 conclusion
  - follow-up: verify whether the frozen advisory is complete for this CVE before treating any local fixed-version fact as a CVE-wide conclusion

## Scope, provenance, and disposition

- run_id: `research-CVE-2023-44487-1791844421` | mode `experimental-research-v1` / schema `research-report/1`
- contract_extensions: `slice2-fidelity/2`
- started: 2026-10-12T22:33:41Z — finished: 2026-10-12T22:38:03Z | deterministic_only=false
- timeouts (ms): overall=1500000 deterministic=60000 agent=900000
- snapshot: `<VA_VEXBENCH>/repos/kubernetes/kubernetes/e196d2491087e93bd29f0e5a538aab60667021e3` @ `e196d2491087e93bd29f0e5a538aab60667021e3` (content_hash `6eed0df4ef52c733d0f4f36b147c1fbc1950ef4689fd63bfb224803e37bd2072`)
- build context: darwin/arm64 tags=[] vendor=false | analysis go `go version go1.26.1 darwin/arm64`
- release go: `go1.21.3`
- advisory: GHSA-qppj-fm5r-hxr3 from frozen_file (`eval/agent7/advisories/k8s-44487.json`)
- advisory sha256: raw `077330160d3adbbb93b2294e3db541c70a746677a4128a1bd8843dab688dae39` canonical `83b852adcd9c692f0712f070359449161ac7883ff4b292d6a8d18b3873da1599`
- disposition: `REVIEW_REQUIRED` (auto_close=false) — research lane output supports human triage only: evidence is scope-bounded, agent claims are unverified hypotheses, and the contract forbids VERIFIED/FALSE/AUTO_CLOSE dispositions
- forbidden classes: `VERIFIED`, `FALSE`, `AUTO_CLOSE`

## Applicability basis

- `version_fixed` [ESTABLISHED/deterministic] the advisory-covered golang.org/x/net entry resolves to fixed version v0.17.0 under the recorded context
  - check scope: resolved version v0.17.0 vs the evaluated entry's affected ranges (affected-resolve under the recorded snapshot build context)
  - verified refs: fact-obs-0008
  - refs: fact-obs-0008, obs:OBS-0008
  - limit: bounded to the evaluated advisory entry; it does not establish the CVE is absent from every implementation

## Contradictions and limitations

- `C-0001` **category_vs_component_scope** on `golang.org/x/net` — resolution `SCOPE_LIMITS`
  - the original category is retained for the evaluated fixed golang.org/x/net@v0.17.0 entry, but the deterministic result does not establish that the CVE is absent from every implementation
  - agent ref: `A-0001`
  - deterministic refs: fact-obs-0008, obs:OBS-0008
  - limit: a fixed version for the evaluated golang.org/x/net entry is not a CVE-wide conclusion; advisory completeness for CVE-2023-44487 is unverified
- `C-0002` **advisory_scope_gap** on `google.golang.org/grpc/internal` — resolution `UNRESOLVED`
  - agent names product-relevant component google.golang.org/grpc/internal outside the advisory's affected entries; the deterministic scope is bounded to the frozen entries
  - agent ref: `A-0006`
  - deterministic refs: adv:GHSA-qppj-fm5r-hxr3
  - limit: a detected scope gap, not a proof that the frozen advisory is globally complete or incomplete
- `C-0003` **advisory_scope_gap** on `k8s.io/apimachinery/pkg` — resolution `UNRESOLVED`
  - agent names product-relevant component k8s.io/apimachinery/pkg outside the advisory's affected entries; the deterministic scope is bounded to the frozen entries
  - agent ref: `A-0006`
  - deterministic refs: adv:GHSA-qppj-fm5r-hxr3
  - limit: a detected scope gap, not a proof that the frozen advisory is globally complete or incomplete
- `C-0004` **advisory_scope_gap** on `k8s.io/apiserver/pkg` — resolution `UNRESOLVED`
  - agent names product-relevant component k8s.io/apiserver/pkg outside the advisory's affected entries; the deterministic scope is bounded to the frozen entries
  - deterministic refs: adv:GHSA-qppj-fm5r-hxr3
  - limit: a detected scope gap, not a proof that the frozen advisory is globally complete or incomplete
- section limit: agent-named component(s) outside the advisory scope: google.golang.org/grpc/internal, k8s.io/apimachinery/pkg, k8s.io/apiserver/pkg — conclusions remain bounded to the advisory's affected entries
- section limit: agent-named component(s) outside the advisory scope: google.golang.org/grpc/internal, k8s.io/apimachinery/pkg, k8s.io/apiserver/pkg — conclusions remain bounded to the advisory's affected entries
- section limit: agent-described transitions are hypotheses (origin=agent/OPEN): a potential call chain alone does not establish the exploit path
- applicability limit: package/build reachability was not evaluated: the resolved version is outside the affected ranges of every evaluated advisory entry
- applicability limit: evaluated affected-module entries: golang.org/x/net@v0.17.0

## Preserved agent statements (unverified)

- agent_output.status: `OK`
- category (original, never rewritten): `code_not_present`
- attempt: `attempt-0002`
- **replayed** from persisted artifacts: `<VA_REPO>/eval/agent7/e2e/k8s-44487` (original run `research-CVE-2023-44487-1791840579`, attempt `attempt-0002`) — no model call in this run
- reasoning: The advisory (GHSA-qppj-fm5r-hxr3, CVE-2023-44487) lists golang.org/x/net with a fix in version 0.17.0 (entry adv-02). The snapshot's go.mod declares golang.org/x/net v0.17.0 at line 82, confirmed in go.sum at line 1018. This is exactly the fixed version, placing it outside the affected range [introduced, 0.17.0). No other components from the advisory (Swift swift-nio-http2, Maven Tomcat/Jetty/Akka) are present in this Go-based Kubernetes repository. The source code in vendor/golang.org/x/net/http2 (including processResetStream at server.go:1601-1618) has no vulnerability because the fix was already applied upstream in v0.17.0.
- `A-0001` [MODEL_HYPOTHESIS/OPEN] category=code_not_present: The advisory (GHSA-qppj-fm5r-hxr3, CVE-2023-44487) lists golang.org/x/net with a fix in version 0.17.0 (entry adv-02). The snapshot's go.mod declares golang.org/x/net v0.17.0 at line 82, confirmed in go.sum at line 1018. This is exactly the fixed version, placing it outside the affected range [introduced, 0.17.0). No other components from the advisory (Swift swift-nio-http2, Maven Tomcat/Jetty/Akka) are present in this Go-based Kubernetes repository. The source code in vendor/golang.org/x/net/http2 (including processResetStream at server.go:1601-1618) has no vulnerability because the fix was already applied upstream in v0.17.0.
  - source: `$.category + $.reasoning` in retained answer
- `A-0002` [MODEL_HYPOTHESIS/OPEN] HTTP/2 Rapid Reset (CVE-2023-44487): An attacker sends RST_STREAM frames immediately after HEADERS frames to cancel streams before completion. The server still allocates stream data structures, parses headers, and performs header decompression, creating a cost asymmetry where the server does significant work per reset while the attacker pays minimal bandwidth. This enables denial-of-service against HTTP/2 servers.
  - source: `$.assessment.vulnerability_mechanism` in retained answer
- `A-0003` [EVIDENCE_SUPPORTED/OPEN] The golang.org/x/net@v0.17.0 HTTP/2 server implementation in vendor/golang.org/x/net/http2/server.go handles RST_STREAM frames via processResetStream (line 1601-1618), which calls sc.closeStream(st, streamError(f.StreamID, f.ErrCode)) without rate limiting. The upstream fix in v0.17.0 (bound to advisory entry adv-02) introduces flow control to limit RST_STREAM processing. Since this snapshot is at exactly v0.17.0, the fix is included.
  - source: `$.assessment.root_cause` in retained answer
- `A-0004` [MODEL_HYPOTHESIS/OPEN] 1) Attacker establishes an HTTP/2 TLS connection to the Kubernetes API server (entry point via secure_serving.go:201-206, http2.ConfigureServer). 2) Attacker opens streams and sends HEADERS to trigger server-side processing. 3) Immediately after, attacker sends RST_STREAM to cancel each stream before the server completes processing. 4) The server wastes resources on alloc-parse-cancel cycles for each cancelled stream. Required conditions: HTTP/2 enabled (default in kube-apiserver), network access to the API server HTTPS port.
  - source: `$.assessment.attack_scenario` in retained answer
- `A-0005` [MODEL_HYPOTHESIS/OPEN] The Kubernetes API server uses golang.org/x/net/http2 via secure_serving.go:180-206 with HTTP/2 enabled by default (DisableHTTP2 defaults false). MaxConcurrentStreams defaults to 100 (line 195) but is configurable via 'http2-max-streams-per-connection' flag (options/serving.go:203). The recommended configuration sets HTTP2MaxStreamsPerConnection to 1000 (options/recommended.go:67), which would increase the attack surface. Build scope: Go module k8s.io/kubernetes, go 1.20. Platform: Linux (vendor/golang.org/x/net/http2/server.go:746 references GOOS windows). Deployment: standard kube-apiserver with HTTPS serving. Unknown: whether DisableHTTP2 is set in the target deployment, actual runtime flag values.
  - source: `$.assessment.product_exposure` in retained answer
- `A-0006` [MODEL_HYPOTHESIS/OPEN] Checked: Tomcat, Jetty, Akka HTTP (Maven) - no Java build files present. Nginx, Envoy, Node.js - no C/JS build files present. swift-nio-http2 - no Swift Package.swift present. golang.org/x/net is the only affected component from the advisory present in the snapshot. The gRPC server components (vendor/google.golang.org/grpc/internal/transport/http2_server.go) also use the same vendor golang.org/x/net/http2, so the fix applies there too. golang.org/x/net/http2 is also used by api machinery client (staging/src/k8s.io/apimachinery/pkg/util/net/http.go:39) as an HTTP client - RST_STREAM DoS is a server-side vulnerability so client usage is not relevant. Not fully explored: whether the etcd vendored copy has its own HTTP/2 implementation that bypasses golang.org/x/net.
  - source: `$.assessment.alternative_paths` in retained answer

## Evidence register

- ref `adv:GHSA-qppj-fm5r-hxr3` (advisory) `eval/agent7/advisories/k8s-44487.json` frozen document
  - materiality: `MATERIAL`
  - raw bytes: `eval/agent7/advisories/k8s-44487.json` sha256 `077330160d3adbbb93b2294e3db541c70a746677a4128a1bd8843dab688dae39` (frozen advisory document)
  - reproducible: FILE `eval/agent7/advisories/k8s-44487.json` in `-` → sha256 `83b852adcd9c692f0712f070359449161ac7883ff4b292d6a8d18b3873da1599`
- ref `agent-src:/work/go.mod:201-196 - HTTP/2 server configuration: MaxConcurrentStreams, MaxUploadBufferPerStream, MaxReadFrameSize` (agent-source) `agent/attempt-0002/answer.txt` agent-stated
- ref `agent-src:/work/go.mod:82 - declares golang.org/x/net v0.17.0` (agent-source) `agent/attempt-0002/answer.txt` agent-stated
- ref `agent-src:/work/go.sum:1018 - confirms golang.org/x/net v0.17.0 h1 hash` (agent-source) `agent/attempt-0002/answer.txt` agent-stated
- ref `agent-src:/work/staging/src/k8s.io/apiserver/pkg/server/options/recommended.go:67 - recommended default HTTP2MaxStreamsPerConnection=1000` (agent-source) `agent/attempt-0002/answer.txt` agent-stated
- ref `agent-src:/work/staging/src/k8s.io/apiserver/pkg/server/options/serving.go:69-71,203 - HTTP2MaxStreamsPerConnection flag definition` (agent-source) `agent/attempt-0002/answer.txt` agent-stated
- ref `agent-src:/work/staging/src/k8s.io/apiserver/pkg/server/secure_serving.go:180-206 - http2.ConfigureServer call` (agent-source) `agent/attempt-0002/answer.txt` agent-stated
- ref `agent-src:/work/staging/src/k8s.io/apiserver/pkg/server/secure_serving.go:56-58 - DisableHTTP2 configuration` (agent-source) `agent/attempt-0002/answer.txt` agent-stated
- ref `agent-src:/work/vendor/golang.org/x/net/http2/server.go:1601-1618 - processResetStream handler (fixed version source)` (agent-source) `agent/attempt-0002/answer.txt` agent-stated
- ref `agent-src:/work/vendor/golang.org/x/net/http2/server.go:173-206 - http2.Server configuration fields` (agent-source) `agent/attempt-0002/answer.txt` agent-stated
- ref `agent-src:/work/vendor/golang.org/x/net/http2/transport.go:800 - MaxConcurrentStreams field definition` (agent-source) `agent/attempt-0002/answer.txt` agent-stated
- ref `agent-src:assessment.altpaths` (agent-source) `agent/attempt-0002/answer.txt` retained final answer
- ref `agent-src:assessment.attack` (agent-source) `agent/attempt-0002/answer.txt` retained final answer
- ref `agent-src:assessment.exposure` (agent-source) `agent/attempt-0002/answer.txt` retained final answer
- ref `agent-src:assessment.mechanism` (agent-source) `agent/attempt-0002/answer.txt` retained final answer
- ref `agent-src:assessment.rootcause` (agent-source) `agent/attempt-0002/answer.txt` retained final answer
- ref `agent-src:final-answer` (agent-source) `agent/attempt-0002/answer.txt` retained final answer
- ref `agent-src:residual_questions` (agent-source) `agent/attempt-0002/answer.txt` retained final answer
- ref `obs:OBS-0001` (observation) `artifacts/obs-0001.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0001.json` sha256 `c4ec969c6cb747b0462898e28ca52711bc8a1dc4f9efd4b8ed2c9b4b3dd8f5d7` (observation)
- ref `obs:OBS-0002` (observation) `artifacts/obs-0002.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0002.json` sha256 `a1fa89ad4915c7b9add89854fb379ad16dadee712892b40fcbac555cc1b06adf` (observation)
- ref `obs:OBS-0003` (observation) `artifacts/obs-0003.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0003.json` sha256 `450cb13a4b7637b60da8d13811a3c21a528c9da41a2eda23b618633a8ff20f85` (observation)
- ref `obs:OBS-0004` (observation) `artifacts/obs-0004.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0004.json` sha256 `8eaf6cacc68ae5c60f9e880f8700974cfe50248042c94ccd0b5516c2dc265453` (observation)
- ref `obs:OBS-0005` (observation) `artifacts/obs-0005.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0005.json` sha256 `34578a3379d27bfc1111f28a93e836d15b72b9193f5c5089b1ea7fe22967b5b3` (observation)
- ref `obs:OBS-0006` (observation) `artifacts/obs-0006.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0006.json` sha256 `6c8f2bc9916a347055a7d2cdd393bad5be3c70e9d604363c051eacc0af33741b` (observation)
- ref `obs:OBS-0007` (observation) `artifacts/obs-0007.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0007.json` sha256 `4ef8c3cd3cbd8a086afc07a6fad18be6666648192fb15edb50ab7cc0068fcf76` (observation)
- ref `obs:OBS-0008` (observation) `artifacts/obs-0008.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0008.json` sha256 `e185371eb4549bdfa163bfc2dc496ae084af72e0fa1bab52a4af6623a3d5dee8` (observation)
- ref `obs:OBS-0009` (observation) `artifacts/obs-0009.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0009.json` sha256 `a3ef9251c7556d529f38626c16c4bc3e85d45300e862e17484f166586ece838f` (observation)
- ref `obs:OBS-0010` (observation) `artifacts/obs-0010.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0010.json` sha256 `4990f20626faafec2787967017887930a9219fe1d0774683b5c46c69fecc192d` (observation)
- ref `obs:OBS-0011` (observation) `artifacts/obs-0011.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0011.json` sha256 `0764a56f1adad56eb17a9eedfa94392c6d3d37c8e358ab4556fb005782b4a345` (observation)
- ref `obs:OBS-0012` (observation) `artifacts/obs-0012.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0012.json` sha256 `913bb8cf8cbedb605da3dd6b9e910c90339ef6adefb8272dc023df2cd338d3d2` (observation)
- ref `obs:OBS-0013` (observation) `artifacts/obs-0013.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0013.json` sha256 `41b233195c53e4c0b5dc1de2030986875200c3f67642e87848c55e9a2cfc71a3` (observation)
- ref `obs:OBS-0014` (observation) `artifacts/obs-0014.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0014.json` sha256 `68e3e6746b205829dcc26af104f9ae5e20b39b6643fd8c4585309275263d1712` (observation)
- ref `obs:OBS-0015` (observation) `artifacts/obs-0015.json` observation
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0015.json` sha256 `a41460401aad91b26e294f0d54d9318bcb73e09da3503584b1b759f0e26aa209` (observation)

## Attempt and retry history

- `attempt-0001` (deterministic #1) status `OK` reason `initial` — initial deterministic lane pass (strict evidencetools session)
  - 2026-10-12T22:33:41Z → 2026-10-12T22:38:03Z | original_preserved=true
  - result: `deterministic-facts.json` sha256 `0aed196527a9afed48575b98fae93ddff20df3ad0e9148f9e07a4dce4f5e7c3e`
  - extraction: `NOT_APPLICABLE` (NONE), 0 candidate(s), selected -1
- `attempt-0002` (agent #2) status `OK` reason `manual_recheck` — replayed from persisted artifacts (<VA_REPO>/eval/agent7/e2e/k8s-44487); no model call
  - 2026-10-12T10:04:38Z → 2026-10-12T10:06:47Z | original_preserved=true
  - result: `agent/attempt-0002/result.json` sha256 `a9073927ef94049e5b03378902653c660dcd2d2137318ac4b6e8bcdf138402a3`
  - extraction: `VALID` (NONE), 1 candidate(s), selected 0
    - candidate[0] VALID category=code_not_present raw `ef243bfd063661d3a2607fdf3d98f90c1ed14d374c305c933a9661c7fc8a7f62`

## Appendix

### Detailed unknowns

- `U-0004` UNKNOWN: run_govulncheck check did not produce a result (UNSUPPORTED)
  - reason: strict profile requires --govulndb to pin the vulnerability database
  - follow-up: rerun or scope-down the check; its status is UNSUPPORTED, never an absence proof

### Full deterministic facts

- `fact-obs-0001` snapshot <VA_VEXBENCH>/repos/kubernetes/kubernetes/e196d2491087e93bd29f0e5a538aab60667021e3 contained, replaces confined, content hash 6eed0df4ef52c733d0f4f36b147c1fbc1950ef4689fd63bfb224803e37bd2072
  - tool: `repository-preflight` (izyan/research-lane go1.26.1) | coverage `COMPLETE` | scope: VerifyContained + CheckPathReplacements + ContentHash over the snapshot tree
  - command: `repository-preflight {"snapshot":"<VA_VEXBENCH>/repos/kubernetes/kubernetes/e196d2491087e93bd29f0e5a538aab60667021e3"}`
  - artifact: `artifacts/obs-0001.json` sha256 `c4ec969c6cb747b0462898e28ca52711bc8a1dc4f9efd4b8ed2c9b4b3dd8f5d7` | data_digest `9cab1cc1848bf8497a0025093d58170537509c4c7d7ac11286d70857dcb1d39c`
  - provenance: obs `OBS-0001` / deterministic-lane
  - materiality: `SUPPORTING`
  - raw bytes: `artifacts/obs-0001.json` sha256 `c4ec969c6cb747b0462898e28ca52711bc8a1dc4f9efd4b8ed2c9b4b3dd8f5d7`
  - reproducible: COMMAND `repository-preflight {"snapshot":"<VA_VEXBENCH>/repos/kubernetes/kubernetes/e196d2491087e93bd29f0e5a538aab60667021e3"}` → `9cab1cc1848bf8497a0025093d58170537509c4c7d7ac11286d70857dcb1d39c`
- `fact-obs-0002` snapshot identity e196d2491087e93bd29f0e5a538aab60667021e3: go directive 1.20, release toolchain "go1.21.3", darwin/arm64
  - tool: `repository-snapshot` (izyan/research-lane go1.26.1) | coverage `COMPLETE` | scope: repository.Service.Snapshot (git/go probes + static release-evidence scan, no repo code executed)
  - command: `repository-snapshot {"GOOS":"","GOARCH":"","BuildTags":null,"BinaryPath":"","ReleaseGoVersion":"","TrustedPeer":false,"DeployManifests":null,"DeployArchive":"","PerimeterOverride":"","ExternalCommitSHA":"e196d2491087e93bd29f0e5a538aab60667021e3","GoBin":"go","Env":null}`
  - artifact: `artifacts/obs-0002.json` sha256 `a1fa89ad4915c7b9add89854fb379ad16dadee712892b40fcbac555cc1b06adf` | data_digest `453fae7ce39a5bc6c129b8e0c5cbb91f6799b9422bb9fe28c35fdb3662084dc7`
  - provenance: obs `OBS-0002` / deterministic-lane
  - materiality: `SUPPORTING`
  - raw bytes: `artifacts/obs-0002.json` sha256 `a1fa89ad4915c7b9add89854fb379ad16dadee712892b40fcbac555cc1b06adf`
  - reproducible: COMMAND `repository-snapshot {"GOOS":"","GOARCH":"","BuildTags":null,"BinaryPath":"","ReleaseGoVersion":"","TrustedPeer":false,"DeployManifests":null,"DeployArchive":"","PerimeterOverride":"","ExternalCommitSHA":"e196d2491087e93bd29f0e5a538aab60667021e3","GoBin":"go","Env":null}` → `453fae7ce39a5bc6c129b8e0c5cbb91f6799b9422bb9fe28c35fdb3662084dc7`
- `fact-obs-0003` frozen advisory CVE-2023-44487 resolved to GHSA-qppj-fm5r-hxr3 (22 affected entries, source frozen_file)
  - tool: `advisory-load` (izyan/research-lane go1.26.1) | coverage `COMPLETE` | scope: FileSource(eval/agent7/advisories/k8s-44487.json) with alias enrichment disabled; no network
  - command: `advisory-load {"cve":"CVE-2023-44487","path":"eval/agent7/advisories/k8s-44487.json","source":"frozen_file"}`
  - artifact: `artifacts/obs-0003.json` sha256 `450cb13a4b7637b60da8d13811a3c21a528c9da41a2eda23b618633a8ff20f85` | data_digest `ec339470f35c84fd06ad469ae0961bd9a73a2a984011a7fd2ba4bf48504b1798`
  - provenance: obs `OBS-0003` / deterministic-lane
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0003.json` sha256 `450cb13a4b7637b60da8d13811a3c21a528c9da41a2eda23b618633a8ff20f85`
  - reproducible: COMMAND `advisory-load {"cve":"CVE-2023-44487","path":"eval/agent7/advisories/k8s-44487.json","source":"frozen_file"}` → `ec339470f35c84fd06ad469ae0961bd9a73a2a984011a7fd2ba4bf48504b1798`
  - limit: 21 non-Go affected entries retained as advisory scope, never as product facts
- `fact-obs-0004` snapshot e196d2491087e93bd29f0e5a538aab60667021e3: content hash 6eed0df4ef52c733d0f4f36b147c1fbc1950ef4689fd63bfb224803e37bd2072, go directive 1.20, 30 replace directives
  - tool: `get_product_snapshot` (izyan-evidence-tools/0.1.0) | coverage `COMPLETE` | scope: this snapshot's build context and module manifest facts
  - command: `get_product_snapshot {}`
  - artifact: `artifacts/obs-0004.json` sha256 `8eaf6cacc68ae5c60f9e880f8700974cfe50248042c94ccd0b5516c2dc265453` | data_digest `3e0ed3f64637e671a0ac273694ca405aa67eb67d09a64575954e6d108917298f`
  - provenance: obs `OBS-0004` / deterministic-lane
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0004.json` sha256 `8eaf6cacc68ae5c60f9e880f8700974cfe50248042c94ccd0b5516c2dc265453`
  - reproducible: COMMAND `get_product_snapshot {}` → `3e0ed3f64637e671a0ac273694ca405aa67eb67d09a64575954e6d108917298f`
- `fact-obs-0005` normalized advisory record for CVE-2023-44487 (resolved id GHSA-qppj-fm5r-hxr3)
  - tool: `get_vulnerability` (izyan-evidence-tools/0.1.0) | coverage `COMPLETE` | scope: OSV-compatible advisory record for CVE-2023-44487
  - command: `get_vulnerability {}`
  - artifact: `artifacts/obs-0005.json` sha256 `34578a3379d27bfc1111f28a93e836d15b72b9193f5c5089b1ea7fe22967b5b3` | data_digest `83ab456f5454bcb083a4797ed707c6682d1ae925b5ef5919211e1e758e1ff7f0`
  - provenance: obs `OBS-0005` / deterministic-lane
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0005.json` sha256 `34578a3379d27bfc1111f28a93e836d15b72b9193f5c5089b1ea7fe22967b5b3`
  - reproducible: COMMAND `get_vulnerability {}` → `83ab456f5454bcb083a4797ed707c6682d1ae925b5ef5919211e1e758e1ff7f0`
  - limit: advisory declares no affected symbols; symbol-level queries need an explicit subject
  - limit: severity provenance not declared by the advisory source
- `fact-obs-0006` dependency graph: 263 module(s) resolved via vendor/modules.txt
  - tool: `get_dependency_graph` (izyan-evidence-tools/0.1.0) | coverage `COMPLETE` | scope: module list of <VA_VEXBENCH>/repos/kubernetes/kubernetes/e196d2491087e93bd29f0e5a538aab60667021e3 (vendor/modules.txt)
  - command: `get_dependency_graph {}`
  - artifact: `artifacts/obs-0006.json` sha256 `6c8f2bc9916a347055a7d2cdd393bad5be3c70e9d604363c051eacc0af33741b` | data_digest `34e09a0513de55eff2ac34e7e35f02e8d494ce5ab198277bd9dc6fff0a457efd`
  - provenance: obs `OBS-0006` / deterministic-lane
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0006.json` sha256 `6c8f2bc9916a347055a7d2cdd393bad5be3c70e9d604363c051eacc0af33741b`
  - reproducible: COMMAND `get_dependency_graph {}` → `34e09a0513de55eff2ac34e7e35f02e8d494ce5ab198277bd9dc6fff0a457efd`
  - limit: module list comes from vendor/modules.txt (vendored build); replaces on disk are vendor content, not fetched versions
- `fact-obs-0007` module golang.org/x/net resolved to version v0.17.0
  - tool: `get_module_version` (izyan-evidence-tools/0.1.0) | coverage `COMPLETE` | scope: resolved module list of <VA_VEXBENCH>/repos/kubernetes/kubernetes/e196d2491087e93bd29f0e5a538aab60667021e3 (vendor/modules.txt)
  - command: `get_module_version {"module":"golang.org/x/net"}`
  - artifact: `artifacts/obs-0007.json` sha256 `4ef8c3cd3cbd8a086afc07a6fad18be6666648192fb15edb50ab7cc0068fcf76` | data_digest `b38342b4bf1cb599f85f0ea97f9c993b11e101b886ea615a9e63f020d484162b`
  - provenance: obs `OBS-0007` / deterministic-lane
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0007.json` sha256 `4ef8c3cd3cbd8a086afc07a6fad18be6666648192fb15edb50ab7cc0068fcf76`
  - reproducible: COMMAND `get_module_version {"module":"golang.org/x/net"}` → `b38342b4bf1cb599f85f0ea97f9c993b11e101b886ea615a9e63f020d484162b`
- `fact-obs-0008` applicability chain for GHSA-qppj-fm5r-hxr3: module_present=TRUE version_affected=FALSE package_present=UNKNOWN build_relevant=UNKNOWN (selected [])
  - tool: `affected-resolve` (izyan/research-lane go1.26.1) | coverage `COMPLETE` | scope: affected.GoResolver.Resolve over the snapshot module graph and import closure (go list -m, go list -deps under strict toolchain env)
  - command: `affected-resolve {"vuln":"GHSA-qppj-fm5r-hxr3"}`
  - artifact: `artifacts/obs-0008.json` sha256 `e185371eb4549bdfa163bfc2dc496ae084af72e0fa1bab52a4af6623a3d5dee8` | data_digest `50f8ce8051c1c4dd7e608c823048abfd743f7d68074c1b571b508ed92e17c860`
  - provenance: obs `OBS-0008` / deterministic-lane
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0008.json` sha256 `e185371eb4549bdfa163bfc2dc496ae084af72e0fa1bab52a4af6623a3d5dee8`
  - reproducible: COMMAND `affected-resolve {"vuln":"GHSA-qppj-fm5r-hxr3"}` → `50f8ce8051c1c4dd7e608c823048abfd743f7d68074c1b571b508ed92e17c860`
  - limit: package/build reachability was not evaluated: the resolved version is outside the affected ranges of every evaluated advisory entry
  - limit: evaluated affected-module entries: golang.org/x/net@v0.17.0
- `fact-obs-0009` 0 product call site(s) into module golang.org/x/net
  - tool: `module_usage` (izyan-evidence-tools/0.1.0) | coverage `PARTIAL` | scope: product packages of <VA_VEXBENCH>/repos/kubernetes/kubernetes/e196d2491087e93bd29f0e5a538aab60667021e3 calling packages of module golang.org/x/net
  - command: `module_usage {"module":"golang.org/x/net"}`
  - artifact: `artifacts/obs-0009.json` sha256 `a3ef9251c7556d529f38626c16c4bc3e85d45300e862e17484f166586ece838f` | data_digest `504a3a251adcab8db8b802af1ca77e0b86f2c55f2b8380cb96f0cd672ffa1dc4`
  - provenance: obs `OBS-0009` / deterministic-lane
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0009.json` sha256 `a3ef9251c7556d529f38626c16c4bc3e85d45300e862e17484f166586ece838f`
  - reproducible: COMMAND `module_usage {"module":"golang.org/x/net"}` → `504a3a251adcab8db8b802af1ca77e0b86f2c55f2b8380cb96f0cd672ffa1dc4`
  - limit: module usage enumerates product call sites whose callee package is owned by the module; nested modules and unresolved owners are surfaced via module_owner rather than silently attributed
- `fact-obs-0010` ingress inventory for module golang.org/x/net: 0 inventoried item(s), 0 completeness blocker(s) (complete=true)
  - tool: `ingress-inventory` (izyan/research-lane go1.26.1) | coverage `PARTIAL` | scope: goanalysis.IngressInventory over module golang.org/x/net (product boundary + reachable dep cone, 2 hops)
  - command: `ingress-inventory {"module":"golang.org/x/net","subjects":null}`
  - artifact: `artifacts/obs-0010.json` sha256 `4990f20626faafec2787967017887930a9219fe1d0774683b5c46c69fecc192d` | data_digest `733c551a9338590e5826ada3ce356d955fe0e2677665e5a1051ffcb2f8acb499`
  - provenance: obs `OBS-0010` / deterministic-lane
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0010.json` sha256 `4990f20626faafec2787967017887930a9219fe1d0774683b5c46c69fecc192d`
  - reproducible: COMMAND `ingress-inventory {"module":"golang.org/x/net","subjects":null}` → `733c551a9338590e5826ada3ce356d955fe0e2677665e5a1051ffcb2f8acb499`
  - limit: ingress inventory is bounded to the loaded module cone; a complete inventory is a scope fact, not a reachability verdict
- `fact-obs-0011` 191 entrypoint(s) recognized in product packages
  - tool: `find_entrypoints` (izyan-evidence-tools/0.1.0) | coverage `PARTIAL` | scope: product packages of <VA_VEXBENCH>/repos/kubernetes/kubernetes/e196d2491087e93bd29f0e5a538aab60667021e3
  - command: `find_entrypoints {}`
  - artifact: `artifacts/obs-0011.json` sha256 `0764a56f1adad56eb17a9eedfa94392c6d3d37c8e358ab4556fb005782b4a345` | data_digest `2b5ce38b914fc98cd9d5a9b5fac8f69f86487a9c15113394647e87a75c4a5cdd`
  - provenance: obs `OBS-0011` / deterministic-lane
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0011.json` sha256 `0764a56f1adad56eb17a9eedfa94392c6d3d37c8e358ab4556fb005782b4a345`
  - reproducible: COMMAND `find_entrypoints {}` → `2b5ce38b914fc98cd9d5a9b5fac8f69f86487a9c15113394647e87a75c4a5cdd`
  - limit: entrypoint recognition covers main/init functions, exported symbols and net/http handlers; other transports (gRPC, message queues, CLI) are not enumerated by this scan
- `fact-obs-0012` 2 inbound listener binds in product packages observed
  - tool: `listen-sites` (izyan/research-lane go1.26.1) | coverage `PARTIAL` | scope: inbound listener binds in product packages (static source scan; runtime reachability is out of scope)
  - command: `listen-sites null`
  - artifact: `artifacts/obs-0012.json` sha256 `913bb8cf8cbedb605da3dd6b9e910c90339ef6adefb8272dc023df2cd338d3d2` | data_digest `6d5c37a8dd6e95a16df0fec4933fc20bdf2eb700639df2df6d55cebfbcde7156`
  - provenance: obs `OBS-0012` / deterministic-lane
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0012.json` sha256 `913bb8cf8cbedb605da3dd6b9e910c90339ef6adefb8272dc023df2cd338d3d2`
  - reproducible: COMMAND `listen-sites null` → `6d5c37a8dd6e95a16df0fec4933fc20bdf2eb700639df2df6d55cebfbcde7156`
  - limit: static exposure scan: a listener/dial site is a code fact, not runtime reachability
- `fact-obs-0013` 0 authentication/authorization facts around inbound handlers observed
  - tool: `inbound-auth-facts` (izyan/research-lane go1.26.1) | coverage `PARTIAL` | scope: authentication/authorization facts around inbound handlers (static source scan; runtime reachability is out of scope)
  - command: `inbound-auth-facts null`
  - artifact: `artifacts/obs-0013.json` sha256 `41b233195c53e4c0b5dc1de2030986875200c3f67642e87848c55e9a2cfc71a3` | data_digest `5c700f80e41e7d7596a0e752363123783cb5e7938da0474f7c8b0a37241b7674`
  - provenance: obs `OBS-0013` / deterministic-lane
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0013.json` sha256 `41b233195c53e4c0b5dc1de2030986875200c3f67642e87848c55e9a2cfc71a3`
  - reproducible: COMMAND `inbound-auth-facts null` → `5c700f80e41e7d7596a0e752363123783cb5e7938da0474f7c8b0a37241b7674`
  - limit: static exposure scan: a listener/dial site is a code fact, not runtime reachability
- `fact-obs-0014` 0 outbound dial/endpoint site(s) into module golang.org/x/net
  - tool: `dial-sites` (izyan/research-lane go1.26.1) | coverage `PARTIAL` | scope: outbound endpoints into module golang.org/x/net (static source scan)
  - command: `dial-sites {"module":"golang.org/x/net"}`
  - artifact: `artifacts/obs-0014.json` sha256 `68e3e6746b205829dcc26af104f9ae5e20b39b6643fd8c4585309275263d1712` | data_digest `43fe627691677232cb5d101214d9797f162156fbdb1c18cb62daa2567adffc72`
  - provenance: obs `OBS-0014` / deterministic-lane
  - materiality: `MATERIAL`
  - raw bytes: `artifacts/obs-0014.json` sha256 `68e3e6746b205829dcc26af104f9ae5e20b39b6643fd8c4585309275263d1712`
  - reproducible: COMMAND `dial-sites {"module":"golang.org/x/net"}` → `43fe627691677232cb5d101214d9797f162156fbdb1c18cb62daa2567adffc72`
  - limit: a dial site is a code fact; whether the endpoint is attacker-reachable is out of scope

### Full exploitation conditions

- `EC-0001` [deterministic/required/SUPPORTED/code_reachability] the affected component (the advisory-affected component) is present in the resolved module graph
-   - refs:
  - obs:OBS-0008
  - fact-obs-0008
- `EC-0002` [deterministic/required/REFUTED/code_reachability] the deployed product uses the advisory-affected component outside the advisory's affected ranges
-   - refs:
  - obs:OBS-0008
  - fact-obs-0008
-   - limits:
  - a required predicate fails deterministically on version evidence
- `EC-0003` [deterministic/required/UNKNOWN/code_reachability] whether product code reaches the affected package was not evaluated: the evaluated advisory entry for the advisory-affected component resolves to fixed version v0.17.0, so the package reachability probe did not run
-   - refs:
  - obs:OBS-0008
  - fact-obs-0008
-   - limits:
  - package reachability not evaluated — the resolved version is outside the affected ranges of every evaluated entry; a fixed version is not evidence of package absence
  - follow-up: run module_usage/go list -deps under the recorded build context if package presence must be established independently
- `EC-0004` [deterministic/required/UNKNOWN/code_reachability] whether the affected code is build-relevant was not evaluated: the evaluated advisory entry for the advisory-affected component resolves to fixed version v0.17.0, so the build-relevance probe did not run
-   - refs:
  - obs:OBS-0008
  - fact-obs-0008
-   - limits:
  - build relevance not evaluated — the resolved version is outside the affected ranges of every evaluated entry
  - follow-up: run go list -deps -test ./... under the recorded GOOS/GOARCH/tags if build relevance must be established independently
- `EC-0005` [deterministic/required/UNKNOWN/attack_surface_availability] a runtime configuration/environment predicate must hold for exploitation (attacker reachability, feature flags, deployment exposure); static source evidence cannot decide it
-   - refs:
  - obs:OBS-0010
  - obs:OBS-0011
  - obs:OBS-0012
  - obs:OBS-0014
-   - limits:
  - follow-up: confirm deployment posture (listeners, auth, network exposure, config) against the recorded entry-point facts
- `EC-0006` [agent/unknown/OPEN/other] 1) Attacker establishes an HTTP/2 TLS connection to the Kubernetes API server (entry point via secure_serving.go:201-206, http2.ConfigureServer). 2) Attacker opens streams and sends HEADERS to trigger server-side processing. 3) Immediately after, attacker sends RST_STREAM to cancel each stream before the server completes processing. 4) The server wastes resources on alloc-parse-cancel cycles for each cancelled stream. Required conditions: HTTP/2 enabled (default in kube-apiserver), network access to the API server HTTPS port.
-   - refs:
  - A-0004

### Full assessment sections

#### vulnerability_mechanism — PARTIAL

HTTP/2 Rapid Reset (CVE-2023-44487): An attacker sends RST_STREAM frames immediately after HEADERS frames to cancel streams before completion. The server still allocates stream data structures, parses headers, and performs header decompression, creating a cost asymmetry where the server does significant work per reset while the attacker pays minimal bandwidth. This enables denial-of-service against HTTP/2 servers.

- **[deterministic/SUPPORTED]**
  - subject: `GHSA-qppj-fm5r-hxr3`
  - statement: advisory GHSA-qppj-fm5r-hxr3 states: HTTP/2 Stream Cancellation Attack
  - scope: frozen advisory document
-   - refs:
  - fact-obs-0003
-   - limits:
  - 21 non-Go affected entries retained as advisory scope, never as product facts
- **[agent/OPEN]**
  - statement: HTTP/2 Rapid Reset (CVE-2023-44487): An attacker sends RST_STREAM frames immediately after HEADERS frames to cancel streams before completion. The server still allocates stream data structures, parses headers, and performs header decompression, creating a cost asymmetry where the server does significant work per reset while the attacker pays minimal bandwidth. This enables denial-of-service against HTTP/2 servers.
  - scope: agent assessment (snapshot-read scope as stated)
-   - refs:
  - A-0002
- limits:
  - agent-named component(s) outside the advisory scope: google.golang.org/grpc/internal, k8s.io/apimachinery/pkg, k8s.io/apiserver/pkg — conclusions remain bounded to the advisory's affected entries

#### root_cause — PARTIAL

The golang.org/x/net@v0.17.0 HTTP/2 server implementation in vendor/golang.org/x/net/http2/server.go handles RST_STREAM frames via processResetStream (line 1601-1618), which calls sc.closeStream(st, streamError(f.StreamID, f.ErrCode)) without rate limiting. The upstream fix in v0.17.0 (bound to advisory entry adv-02) introduces flow control to limit RST_STREAM processing. Since this snapshot is at exactly v0.17.0, the fix is included.

- **[agent/OPEN]**
  - statement: The golang.org/x/net@v0.17.0 HTTP/2 server implementation in vendor/golang.org/x/net/http2/server.go handles RST_STREAM frames via processResetStream (line 1601-1618), which calls sc.closeStream(st, streamError(f.StreamID, f.ErrCode)) without rate limiting. The upstream fix in v0.17.0 (bound to advisory entry adv-02) introduces flow control to limit RST_STREAM processing. Since this snapshot is at exactly v0.17.0, the fix is included.
  - scope: agent assessment (snapshot-read scope as stated)
-   - refs:
  - A-0003
- limits:
  - agent-named component(s) outside the advisory scope: google.golang.org/grpc/internal, k8s.io/apimachinery/pkg, k8s.io/apiserver/pkg — conclusions remain bounded to the advisory's affected entries

#### attack_scenario — UNKNOWN

UNKNOWN: the exploit path is not established — the available material does not confirm a required transition chain; follow-up: verify each recorded predicate: re-run the deterministic reachability/surface checks under the full build context and obtain dynamic evidence if exploitability must be established; agent-stated: 1) Attacker establishes an HTTP/2 TLS connection to the Kubernetes API server (entry point via secure_serving.go:201-206, http2.ConfigureServer). 2) Attacker opens streams and sends HEADERS to trigger server-side processing. 3) Immediately after, attacker sends RST_STREAM to cancel each stream before the server completes processing. 4) The server wastes resources on alloc-parse-cancel cycles for e…

- **[agent/OPEN]**
  - statement: 1) Attacker establishes an HTTP/2 TLS connection to the Kubernetes API server (entry point via secure_serving.go:201-206, http2.ConfigureServer). 2) Attacker opens streams and sends HEADERS to trigger server-side processing. 3) Immediately after, attacker sends RST_STREAM to cancel each stream before the server completes processing. 4) The server wastes resources on alloc-parse-cancel cycles for each cancelled stream. Required conditions: HTTP/2 enabled (default in kube-apiserver), network access to the API server HTTPS port.
  - scope: agent assessment (snapshot-read scope as stated)
-   - refs:
  - A-0004
- limits:
  - agent-described transitions are hypotheses (origin=agent/OPEN): a potential call chain alone does not establish the exploit path

#### product_exposure — PARTIAL

The Kubernetes API server uses golang.org/x/net/http2 via secure_serving.go:180-206 with HTTP/2 enabled by default (DisableHTTP2 defaults false). MaxConcurrentStreams defaults to 100 (line 195) but is configurable via 'http2-max-streams-per-connection' flag (options/serving.go:203). The recommended configuration sets HTTP2MaxStreamsPerConnection to 1000 (options/recommended.go:67), which would increase the attack surface. Build scope: Go module k8s.io/kubernetes, go 1.20. Platform: Linux (vendor/golang.org/x/net/http2/server.go:746 references GOOS windows). Deployment: standard kube-apiserver with HTTPS serving. Unknown: whether DisableHTTP2 is set in the target deployment, actual runtime flag values.

- **[deterministic/SUPPORTED]**
  - subject: `golang.org/x/net`
  - statement: 0 product call site(s) into module golang.org/x/net
  - scope: product packages of <VA_VEXBENCH>/repos/kubernetes/kubernetes/e196d2491087e93bd29f0e5a538aab60667021e3 calling packages of module golang.org/x/net
-   - refs:
  - fact-obs-0009
-   - limits:
  - module usage enumerates product call sites whose callee package is owned by the module; nested modules and unresolved owners are surfaced via module_owner rather than silently attributed
- **[deterministic/SUPPORTED]**
  - subject: `golang.org/x/net`
  - statement: ingress inventory for module golang.org/x/net: 0 inventoried item(s), 0 completeness blocker(s) (complete=true)
  - scope: goanalysis.IngressInventory over module golang.org/x/net (product boundary + reachable dep cone, 2 hops)
-   - refs:
  - fact-obs-0010
-   - limits:
  - ingress inventory is bounded to the loaded module cone; a complete inventory is a scope fact, not a reachability verdict
- **[agent/OPEN]**
  - statement: The Kubernetes API server uses golang.org/x/net/http2 via secure_serving.go:180-206 with HTTP/2 enabled by default (DisableHTTP2 defaults false). MaxConcurrentStreams defaults to 100 (line 195) but is configurable via 'http2-max-streams-per-connection' flag (options/serving.go:203). The recommended configuration sets HTTP2MaxStreamsPerConnection to 1000 (options/recommended.go:67), which would increase the attack surface. Build scope: Go module k8s.io/kubernetes, go 1.20. Platform: Linux (vendor/golang.org/x/net/http2/server.go:746 references GOOS windows). Deployment: standard kube-apiserver with HTTPS serving. Unknown: whether DisableHTTP2 is set in the target deployment, actual runtime flag values.
  - scope: agent assessment (snapshot-read scope as stated)
-   - refs:
  - A-0005

#### alternative_paths — PARTIAL

Checked: Tomcat, Jetty, Akka HTTP (Maven) - no Java build files present. Nginx, Envoy, Node.js - no C/JS build files present. swift-nio-http2 - no Swift Package.swift present. golang.org/x/net is the only affected component from the advisory present in the snapshot. The gRPC server components (vendor/google.golang.org/grpc/internal/transport/http2_server.go) also use the same vendor golang.org/x/net/http2, so the fix applies there too. golang.org/x/net/http2 is also used by api machinery client (staging/src/k8s.io/apimachinery/pkg/util/net/http.go:39) as an HTTP client - RST_STREAM DoS is a server-side vulnerability so client usage is not relevant. Not fully explored: whether the etcd vendored copy has its own HTTP/2 implementation that bypasses golang.org/x/net.

- **[agent/OPEN]**
  - statement: Checked: Tomcat, Jetty, Akka HTTP (Maven) - no Java build files present. Nginx, Envoy, Node.js - no C/JS build files present. swift-nio-http2 - no Swift Package.swift present. golang.org/x/net is the only affected component from the advisory present in the snapshot. The gRPC server components (vendor/google.golang.org/grpc/internal/transport/http2_server.go) also use the same vendor golang.org/x/net/http2, so the fix applies there too. golang.org/x/net/http2 is also used by api machinery client (staging/src/k8s.io/apimachinery/pkg/util/net/http.go:39) as an HTTP client - RST_STREAM DoS is a server-side vulnerability so client usage is not relevant. Not fully explored: whether the etcd vendored copy has its own HTTP/2 implementation that bypasses golang.org/x/net.
  - scope: agent assessment (snapshot-read scope as stated)
-   - refs:
  - A-0006

#### evidence_quality — SUPPORTED

evidence base: 14 deterministic check(s) OK, 1 non-OK; evidence is scope-bounded per each observation's scope/limitations; agent stated: The snapshot is a Kubernetes source tree with vendored golang.org/x/net v0.17.0, which is exactly the fixed version per advisory entry adv-02. Coverage: verified Go module declarations, vendor source, and HTTP/2 integration points in the apiserver. Limitations: version pinning verified from go.mod/go.sum and vendor directory; the actual fix implementation in v0.17.0 is inferred from upstream Go release notes rather than explicitly diffed against prior versions in the vendor tree. No other advisory-listed components (Tomcat, Jetty, swift-nio-http2, nginx) found in snapshot.

- limits:
  - the frozen advisory names exactly one Go module while the agent's answer names other dependency module(s) of the same mechanism (google.golang.org/grpc/internal, k8s.io/apimachinery/pkg, k8s.io/apiserver/pkg); the advisory's completeness for this CVE is unverified
  - run_govulncheck UNSUPPORTED: strict profile requires --govulndb to pin the vulnerability database
  - applicability: package/build reachability was not evaluated: the resolved version is outside the affected ranges of every evaluated advisory entry
  - applicability: evaluated affected-module entries: golang.org/x/net@v0.17.0

### Full open questions and residual questions

- `Q-0001` component google.golang.org/grpc/internal is named by the agent but is not in the advisory affected entries
  - subject/scope: U-0001 / report scope
  - next check: verify whether the frozen advisory is complete for this CVE before treating any local fixed-version fact as a CVE-wide conclusion
  - why: left unresolved by the lanes' stated scope
- `Q-0002` component k8s.io/apimachinery/pkg is named by the agent but is not in the advisory affected entries
  - subject/scope: U-0002 / report scope
  - next check: verify whether the frozen advisory is complete for this CVE before treating any local fixed-version fact as a CVE-wide conclusion
  - why: left unresolved by the lanes' stated scope
- `Q-0003` component k8s.io/apiserver/pkg is named by the agent but is not in the advisory affected entries
  - subject/scope: U-0003 / report scope
  - next check: verify whether the frozen advisory is complete for this CVE before treating any local fixed-version fact as a CVE-wide conclusion
  - why: left unresolved by the lanes' stated scope
- `Q-0004` run_govulncheck check did not produce a result (UNSUPPORTED)
  - subject/scope: U-0004 / report scope
  - next check: rerun or scope-down the check; its status is UNSUPPORTED, never an absence proof
  - why: left unresolved by the lanes' stated scope
- `Q-0005` Is DisableHTTP2 explicitly set to true in the target deployment? This would mean the API server does not use HTTP/2 at all, further reducing exposure. Follow-up: check kube-apiserver startup flags and configuration manifests.
  - subject/scope:  / agent assessment
  - next check: agent-stated follow-up
  - why: left unresolved by the lanes' stated scope
- `Q-0006` What is the actual runtime value of http2-max-streams-per-connection in the deployment? The recommended default is 1000 but clusters may override this. Follow-up: inspect kube-apiserver Deployment args or config.
  - subject/scope:  / agent assessment
  - next check: agent-stated follow-up
  - why: left unresolved by the lanes' stated scope
- `Q-0007` Does the API server expose HTTP/2 to unauthenticated clients? The attack requires L3/L4 reachability to the HTTPS port. Follow-up: verify network policies and whether the API server is exposed externally.
  - subject/scope:  / agent assessment
  - next check: agent-stated follow-up
  - why: left unresolved by the lanes' stated scope

### Legacy evidence-quality details

- status: `SUPPORTED`
- summary: evidence base: 14 deterministic check(s) OK, 1 non-OK; evidence is scope-bounded per each observation's scope/limitations; agent stated: The snapshot is a Kubernetes source tree with vendored golang.org/x/net v0.17.0, which is exactly the fixed version per advisory entry adv-02. Coverage: verified Go module declarations, vendor source, and HTTP/2 integration points in the apiserver. Limitations: version pinning verified from go.mod/go.sum and vendor directory; the actual fix implementation in v0.17.0 is inferred from upstream Go release notes rather than explicitly diffed against prior versions in the vendor tree. No other advisory-listed components (Tomcat, Jetty, swift-nio-http2, nginx) found in snapshot.
- coverage:
  - repository-preflight: VerifyContained + CheckPathReplacements + ContentHash over the snapshot tree
  - repository-snapshot: repository.Service.Snapshot (git/go probes + static release-evidence scan, no repo code executed)
  - advisory-load: FileSource(eval/agent7/advisories/k8s-44487.json) with alias enrichment disabled; no network
  - get_product_snapshot: this snapshot's build context and module manifest facts
  - get_vulnerability: OSV-compatible advisory record for CVE-2023-44487
  - get_dependency_graph: module list of <VA_VEXBENCH>/repos/kubernetes/kubernetes/e196d2491087e93bd29f0e5a538aab60667021e3 (vendor/modules.txt)
  - get_module_version: resolved module list of <VA_VEXBENCH>/repos/kubernetes/kubernetes/e196d2491087e93bd29f0e5a538aab60667021e3 (vendor/modules.txt)
  - affected-resolve: affected.GoResolver.Resolve over the snapshot module graph and import closure (go list -m, go list -deps under strict toolchain env)
  - module_usage: product packages of <VA_VEXBENCH>/repos/kubernetes/kubernetes/e196d2491087e93bd29f0e5a538aab60667021e3 calling packages of module golang.org/x/net
  - ingress-inventory: goanalysis.IngressInventory over module golang.org/x/net (product boundary + reachable dep cone, 2 hops)
  - find_entrypoints: product packages of <VA_VEXBENCH>/repos/kubernetes/kubernetes/e196d2491087e93bd29f0e5a538aab60667021e3
  - listen-sites: inbound listener binds in product packages (static source scan; runtime reachability is out of scope)
  - inbound-auth-facts: authentication/authorization facts around inbound handlers (static source scan; runtime reachability is out of scope)
  - dial-sites: outbound endpoints into module golang.org/x/net (static source scan)
- limitations:
  - the frozen advisory names exactly one Go module while the agent's answer names other dependency module(s) of the same mechanism (google.golang.org/grpc/internal, k8s.io/apimachinery/pkg, k8s.io/apiserver/pkg); the advisory's completeness for this CVE is unverified
  - run_govulncheck UNSUPPORTED: strict profile requires --govulndb to pin the vulnerability database
  - applicability: package/build reachability was not evaluated: the resolved version is outside the affected ranges of every evaluated advisory entry
  - applicability: evaluated affected-module entries: golang.org/x/net@v0.17.0


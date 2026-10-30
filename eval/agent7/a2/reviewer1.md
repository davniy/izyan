Scoring conventions: `justified_preconditions` is shown as `justified/required (share)`. Manifestation counts use only the reference sheet's listed known manifestations, not counterexamples. `verdict_ok` tests internal consistency of the submitted classification and argument, not correctness against the reference.

## Case: kubernetes-kubernetes-e196d24-CVE-2023-44487

| case | answer label | vulnerability_mechanism | root_cause | attack_scenario | product_exposure | alternative_paths | evidence_quality | residual_questions | triage_recommendation | missed_manifestations | justified_preconditions | invalid_claims | minutes | extra_manual_checks | report_corrections | verdict_ok | note |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|
| e196d24 | A1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 | 3/3 (1.00) | 4 | -2 | 4 | 4 | yes | The answer correctly locates HTTP/2/RST handling, but the reference places v0.17.0 at the fixed boundary; its “pre-fix” claim and asserted etcd exposure are material errors. |
| e196d24 | A2 | 1 | 0 | 1 | 1 | 1 | 1 | 0 | 0 | 0 | 2/3 (0.67) | 2 | -1 | 4 | 3 | yes | The feature gate and stream caps are real observations, but they are presented as making risk negligible and no root-cause or triage section is supplied. |
| e196d24 | A3 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 | 3/3 (1.00) | 3 | -2 | 4 | 4 | yes | It gives a concrete Rapid Reset path, but wrongly calls v0.17.0 vulnerable and invents a v0.17.1 fix boundary not supported by the reference. |
| e196d24 | A4 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 | 3/3 (1.00) | 3 | -2 | 4 | 4 | yes | The authenticated/unauthenticated mitigation distinction is useful, but the claim that v0.17.0 lacks the fix is wrong at the reference’s fixed boundary. |
| e196d24 | A5 | 1 | 1 | 1 | 1 | 1 | 1 | 0 | 0 | 0 | 0/3 (0.00) | 3 | -1 | 4 | 4 | yes | It correctly names the Rapid Reset area and API-server HTTP/2, but the claimed fixed threshold v0.11.0 makes the conclusion “code not present” wrong for the reference. |
| e196d24 | A6 | 1 | 1 | 1 | 1 | 1 | 1 | 0 | 1 | 0 | 1/3 (0.33) | 3 | -1 | 4 | 4 | yes | It mistakes `MaxConcurrentStreams=250/100` for the vulnerability’s controlling condition and fix, while the reference says the exact reset-accounting diff remains unknown. |

**Most useful answer for a human analyst:** A4, because it gives the clearest concrete server path and distinguishes the unauthenticated mitigation from the remaining authenticated exposure, although its dependency/fix-boundary conclusion needs correction.

## Case: kubernetes-kubernetes-ec78c0f-CVE-2021-3121

| case | answer label | vulnerability_mechanism | root_cause | attack_scenario | product_exposure | alternative_paths | evidence_quality | residual_questions | triage_recommendation | missed_manifestations | justified_preconditions | invalid_claims | minutes | extra_manual_checks | report_corrections | verdict_ok | note |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|
| ec78c0f | A1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 3 | 0/2 (0.00) | 4 | -2 | 5 | 5 | yes | It analyzes an HTTP/2 SETTINGS-frame issue, while the reference is gogo/protobuf generated `Unmarshal` bounds checking. |
| ec78c0f | A2 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 3 | 0/2 (0.00) | 5 | -2 | 5 | 5 | yes | It maps the CVE to Go net/http stale-response behavior instead of the pinned gogo/protobuf generator and generated methods. |
| ec78c0f | A3 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 3 | 0/2 (0.00) | 3 | -1 | 4 | 4 | yes | It identifies `crypto/ecdh`, which is unrelated to the reference’s gogo/protobuf bounds defect. |
| ec78c0f | A4 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 3 | 0/2 (0.00) | 5 | -2 | 5 | 5 | yes | It discusses sudo/visudo absence; the reference instead requires the v1.3.1 gogo module, generator, and committed generated `Unmarshal` artifacts. |
| ec78c0f | A5 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 3 | 0/2 (0.00) | 3 | -1 | 4 | 4 | yes | It substitutes a systemd/libsystemd defect for the protobuf parsing vulnerability. |
| ec78c0f | A6 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 3 | 0/2 (0.00) | 4 | -2 | 5 | 5 | yes | It analyzes the kubelet read-only HTTP server, not crafted protobuf bytes reaching generated `Unmarshal` methods. |

**Most useful answer for a human analyst:** None. A6 is the closest in being Kubernetes-specific, but it still analyzes an unrelated kubelet exposure; all six require a fresh CVE/component mapping.

## Case: rancher-rancher-4dc4f53-CVE-2025-47914

| case | answer label | vulnerability_mechanism | root_cause | attack_scenario | product_exposure | alternative_paths | evidence_quality | residual_questions | triage_recommendation | missed_manifestations | justified_preconditions | invalid_claims | minutes | extra_manual_checks | report_corrections | verdict_ok | note |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|
| 4dc4f53 | A1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 3 | 0/3 (0.00) | 3 | -1 | 4 | 4 | yes | It says the target is yaml.v1, but the reference target is x/crypto/ssh/agent with a reachable `ServeAgent` path and local socket constraints. |
| 4dc4f53 | A2 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 3 | 0/3 (0.00) | 6 | -3 | 7 | 7 | yes | It analyzes a crypto/tls CertificateRequest issue and contradicts itself between “fix” and later “verify,” never addressing SSH-agent parsing. |
| 4dc4f53 | A3 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 1 | 3 | 0/3 (0.00) | 1 | -2 | 6 | 4 | yes | Its UNKNOWN posture and follow-ups are procedurally useful, but it names no `ServeAgent`, temporary Unix socket, or SSH-credential gate. |
| 4dc4f53 | A4 | 0 | 0 | 0 | 0 | 0 | 1 | 1 | 1 | 3 | 0/3 (0.00) | 1 | -2 | 6 | 4 | yes | It verifies a real SAML path, but SAML/`ParseResponse` is unrelated to the reference’s local SSH-agent server path. |
| 4dc4f53 | A5 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 3 | 0/3 (0.00) | 3 | -1 | 4 | 4 | yes | It proves absence of `mholt/archiver`, while the reference concerns present x/crypto v0.43.0 and Rancher’s `ServeAgent` call. |
| 4dc4f53 | A6 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 2 | 1/3 (0.33) | 3 | -2 | 5 | 4 | yes | It at least reaches x/crypto/ssh and local Rancher SSH uses, but substitutes an SSH server banner panic for the agent constraint parser and misses the local socket server path. |

**Most useful answer for a human analyst:** A6, because it is the only answer in the right SSH/x/crypto family and distinguishes client/private-key uses from a server path, though it must be redirected to `ssh/agent.ServeAgent` and the temporary socket.

## Case: stretchr-testify-285adcc-CVE-2022-28948

| case | answer label | vulnerability_mechanism | root_cause | attack_scenario | product_exposure | alternative_paths | evidence_quality | residual_questions | triage_recommendation | missed_manifestations | justified_preconditions | invalid_claims | minutes | extra_manual_checks | report_corrections | verdict_ok | note |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|
| 285adcc | A1 | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 0 | 1 | 0/3 (0.00) | 4 | -1 | 4 | 4 | yes | It correctly describes Testify as a test library, but maps the CVE to Windows TCP/IP and never checks the actual yaml.v3 `YAMLEq` calls. |
| 285adcc | A2 | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 0 | 1 | 0/3 (0.00) | 5 | -2 | 5 | 4 | yes | Its HTTP/H2C analysis is unrelated; the actual first-party manifestation is `assert.YAMLEq`/`require.YAMLEq` reaching `yaml.Unmarshal`. |
| 285adcc | A3 | 0 | 0 | 0 | 1 | 1 | 1 | 0 | 0 | 1 | 0/3 (0.00) | 2 | -1 | 4 | 4 | yes | It names go-chi instead of yaml.v3 and supplies no residual follow-up for the real decoder path. |
| 285adcc | A4 | 0 | 0 | 0 | 1 | 1 | 1 | 0 | 0 | 1 | 0/3 (0.00) | 2 | -1 | 4 | 4 | yes | It names FFmpeg/FFV1, so the actual vulnerable yaml dependency and `YAMLEq` manifestation are entirely absent. |
| 285adcc | A5 | 0 | 0 | 0 | 1 | 1 | 1 | 0 | 0 | 1 | 0/3 (0.00) | 2 | -1 | 4 | 4 | yes | It names go-cmp rather than yaml.v3 and gives no analysis of Testify’s YAML assertion APIs. |
| 285adcc | A6 | 0 | 0 | 0 | 1 | 1 | 1 | 0 | 0 | 1 | 0/3 (0.00) | 2 | -1 | 4 | 4 | yes | It names ImageMagick/HEIC and therefore misses both the pre-fix yaml version and the direct assertion call path. |

**Most useful answer for a human analyst:** A2, because its source-scope discussion of Testify’s HTTP helpers is detailed and bounded, even though the vulnerability mapping must be replaced with yaml.v3/YAMLEq analysis.

## Case: aquasecurity-trivy-37da98d-CVE-2024-32473

| case | answer label | vulnerability_mechanism | root_cause | attack_scenario | product_exposure | alternative_paths | evidence_quality | residual_questions | triage_recommendation | missed_manifestations | justified_preconditions | invalid_claims | minutes | extra_manual_checks | report_corrections | verdict_ok | note |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|
| 37da98d | A1 | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 0 | 2 | 0/2 (0.00) | 3 | -1 | 4 | 4 | yes | It correctly bounds Trivy as a pure-Go client, but substitutes GnuTLS and never analyzes the Docker v26.0.1 client/daemon relationship. |
| 37da98d | A2 | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 0 | 2 | 0/2 (0.00) | 4 | -1 | 4 | 4 | yes | It substitutes curl/libcurl; the reference instead requires the Docker module, external daemon behavior, and IPv4-only interface condition. |
| 37da98d | A3 | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 0 | 2 | 0/2 (0.00) | 4 | -2 | 5 | 5 | yes | It gives a detailed real Trivy repository path, but that path is go-git and unrelated to the Docker IPv6 behavior in the reference. |
| 37da98d | A4 | 0 | 0 | 0 | 0 | 1 | 1 | 0 | 0 | 2 | 0/2 (0.00) | 3 | -1 | 4 | 4 | yes | It proves no libarchive, but does not address Docker client/API use or the external Docker daemon. |
| 37da98d | A5 | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 0 | 2 | 0/2 (0.00) | 3 | -1 | 4 | 4 | yes | It maps the CVE to Go x509 PKCS#8 parsing, not Docker’s IPv6-on-IPv4-only-interface behavior. |
| 37da98d | A6 | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 1 | 2 | 0/2 (0.00) | 2 | -1 | 4 | 3 | yes | It appropriately retains uncertainty about a Go stdlib version, but the actual reference uncertainty is Docker daemon source/runtime/configuration, not encoding/json. |

**Most useful answer for a human analyst:** A1, because its pure-Go/CGO boundary and distinction between Trivy and scanned targets are useful scope checks, although it still needs the Docker client-versus-daemon analysis.

## Case: juanfont-headscale-e172c29-CVE-2024-45338

| case | answer label | vulnerability_mechanism | root_cause | attack_scenario | product_exposure | alternative_paths | evidence_quality | residual_questions | triage_recommendation | missed_manifestations | justified_preconditions | invalid_claims | minutes | extra_manual_checks | report_corrections | verdict_ok | note |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|
| e172c29 | A1 | 0 | 0 | 0 | 1 | 1 | 1 | 0 | 0 | 2 | 0/2 (0.00) | 3 | -1 | 4 | 4 | yes | It describes a PHP-CGI absence, while the reference’s material facts are x/net v0.32.0 and no first-party x/net/html import. |
| e172c29 | A2 | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 0 | 2 | 0/2 (0.00) | 3 | -1 | 4 | 4 | yes | It gives a detailed PHP/mbstring scan, but never checks the x/net/html subpackage or the distinct standard-library template uses. |
| e172c29 | A3 | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 0 | 2 | 0/2 (0.00) | 3 | -1 | 4 | 4 | yes | It correctly bounds Python test fixtures as external, but the reference target is Go x/net/html and the known module is present below its fix. |
| e172c29 | A4 | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 0 | 2 | 0/2 (0.00) | 3 | -1 | 4 | 4 | yes | Its PHP-CGI absence evidence is not evidence about the x/net/html dependency or Parse* call graph. |
| e172c29 | A5 | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 0 | 2 | 0/2 (0.00) | 3 | -1 | 4 | 4 | yes | It substitutes glibc/CGO analysis for the actual x/net/html module and first-party import search. |
| e172c29 | A6 | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 0 | 2 | 0/2 (0.00) | 3 | -1 | 4 | 4 | yes | It identifies Python integration-test subprocesses, but the reference requires checking whether x/net/html is linked transitively and whether attacker HTML reaches it. |

**Most useful answer for a human analyst:** A3, because it carefully distinguishes product Go code from test-only Python fixtures and states concrete scope limits; the component mapping must nevertheless be replaced with x/net/html.

## Case: zeromicro-go-zero-bae061a-CVE-2022-32149

| case | answer label | vulnerability_mechanism | root_cause | attack_scenario | product_exposure | alternative_paths | evidence_quality | residual_questions | triage_recommendation | missed_manifestations | justified_preconditions | invalid_claims | minutes | extra_manual_checks | report_corrections | verdict_ok | note |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|
| bae061a | A1 | 0 | 0 | 0 | 1 | 1 | 1 | 0 | 0 | 3 | 0/2 (0.00) | 2 | -1 | 4 | 4 | yes | It maps the CVE to Rust Cargo and does not inspect the nested goctl x/text v0.3.7 or the `cases.Title`-only use. |
| bae061a | A2 | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 0 | 3 | 0/2 (0.00) | 4 | -2 | 5 | 5 | yes | It maps the CVE to gRPC-Go and therefore misses both the nested vulnerable version and the absence of `ParseAcceptLanguage`/`MatchStrings`. |
| bae061a | A3 | 1 | 1 | 1 | 2 | 1 | 1 | 1 | 1 | 0 | 0/2 (0.00) | 3 | -1 | 4 | 3 | yes | It is closest because it checks x/text and the nested tool, but the reference concern is `language.ParseAcceptLanguage`, not EUC-JP `encoding/japanese`; its fixed-version uncertainty remains useful. |
| bae061a | A4 | 0 | 0 | 0 | 1 | 1 | 1 | 0 | 0 | 3 | 0/2 (0.00) | 2 | -1 | 4 | 4 | yes | It substitutes Cloudflare DNS-over-TLS and provides no analysis of x/text versions or goctl reachability. |
| bae061a | A5 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 | 3 | 0/2 (0.00) | 5 | -3 | 7 | 6 | yes | It gives a real HTTP/2 DoS narrative and go-zero server paths, but the reference is an x/text Accept-Language parser issue, not x/net/http2. |
| bae061a | A6 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 | 3 | 0/2 (0.00) | 3 | -2 | 5 | 5 | yes | It also discusses an HTTP/2 stdlib issue and go-zero’s framework use, but never reaches the x/text language parser or nested-module scope. |

**Most useful answer for a human analyst:** A3, because it identifies the correct x/text family, the nested goctl module, and the important “only cases/language is used” counter-observation.

## Case: istio-istio-042afc3-CVE-2023-48795

| case | answer label | vulnerability_mechanism | root_cause | attack_scenario | product_exposure | alternative_paths | evidence_quality | residual_questions | triage_recommendation | missed_manifestations | justified_preconditions | invalid_claims | minutes | extra_manual_checks | report_corrections | verdict_ok | note |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|
| 042afc3 | A1 | 1 | 1 | 1 | 2 | 1 | 1 | 1 | 1 | 0 | 0/2 (0.00) | 3 | -1 | 3 | 3 | yes | It correctly finds no Istio SSH surface, but describes an OpenSSH ControlMaster issue rather than the Terrapin/x/crypto SSH handshake weakness. |
| 042afc3 | A2 | 1 | 1 | 1 | 2 | 2 | 2 | 2 | 1 | 0 | 1/2 (0.50) | 2 | -1 | 3 | 2 | yes | It correctly focuses on x/crypto/ssh and absent imports, but its SSH-TAG/fix-version details are not the reference mechanism and its “low confirmed risk” conclusion is too strong for unresolved transitive reachability. |
| 042afc3 | A3 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 1 | 0 | 1/2 (0.50) | 1 | 1 | 2 | 1 | yes | It accurately describes Terrapin/prefix truncation and explicitly bounds the absent first-party SSH path, with only the indirect dependency/build-graph residue unresolved. |
| 042afc3 | A4 | 1 | 1 | 1 | 2 | 2 | 2 | 1 | 1 | 0 | 0/2 (0.00) | 3 | -1 | 3 | 3 | yes | It has strong Istio scope evidence, but substitutes an OpenSSH scp buffer overflow for Terrapin and does not resolve the indirect x/crypto/ssh question. |
| 042afc3 | A5 | 1 | 1 | 1 | 2 | 2 | 2 | 1 | 1 | 0 | 0/2 (0.00) | 3 | -1 | 3 | 3 | yes | It accurately rules out an Istio SSH server, but its OpenSSH/TCP-Fast-Open mechanism is not CVE-2023-48795’s reference mechanism. |
| 042afc3 | A6 | 1 | 1 | 1 | 2 | 1 | 1 | 1 | 1 | 0 | 0/2 (0.00) | 3 | -1 | 3 | 3 | yes | It gives correct broad product scope but describes an unrelated OpenSSH scp/path issue and does not assess x/crypto/ssh transitive use. |

**Most useful answer for a human analyst:** A3, because it is the only answer with the correct Terrapin mechanism, accurate Istio scope, and explicit UNKNOWN/follow-up treatment of the indirect SSH dependency.

## Case: cilium-cilium-43bff35-CVE-2026-35469

| case | answer label | vulnerability_mechanism | root_cause | attack_scenario | product_exposure | alternative_paths | evidence_quality | residual_questions | triage_recommendation | missed_manifestations | justified_preconditions | invalid_claims | minutes | extra_manual_checks | report_corrections | verdict_ok | note |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|
| 43bff35 | A1 | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 1 | 3 | 0/3 (0.00) | 1 | -1 | 5 | 2 | yes | It asks for CVE metadata and gives generic Cilium scope, but the reference already identifies vendored spdystream allocation bugs and the Hubble port-forward client path. |
| 43bff35 | A2 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 3 | 0/3 (0.00) | 2 | -2 | 6 | 5 | no | It labels the case false-positive while its only substantive attack statement says the mechanism is unknown; that is internally inconsistent even before comparison with the SPDY reference. |
| 43bff35 | A3 | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 1 | 3 | 0/3 (0.00) | 1 | -1 | 5 | 2 | yes | It is disciplined about UNKNOWN and next checks, but the reference’s known manifestations—vendored parser, client port-forward, and opt-in flag—are all omitted. |
| 43bff35 | A4 | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 1 | 3 | 0/3 (0.00) | 3 | -2 | 6 | 3 | yes | It speculates around go-jose/SPIFFE based on a security changelog note without identifying the reference’s SPDY parser or port-forward path. |
| 43bff35 | A5 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 3 | 0/3 (0.00) | 1 | -1 | 6 | 4 | yes | It supplies only an UNKNOWN component mapping and a follow-up, with no substantive Cilium exposure analysis against the known SPDY manifestations. |
| 43bff35 | A6 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 3 | 0/3 (0.00) | 1 | -1 | 6 | 4 | yes | It similarly stops at an unidentified-CVE request and does not address spdystream’s three memory-allocation manifestations. |

**Most useful answer for a human analyst:** A3, because it avoids inventing a component and gives concrete mapping/reachability follow-ups; it still fails to use the known reference facts about vendored SPDY and Hubble port-forward.

## Case: gitleaks-gitleaks-f487f85-CVE-2025-22871

| case | answer label | vulnerability_mechanism | root_cause | attack_scenario | product_exposure | alternative_paths | evidence_quality | residual_questions | triage_recommendation | missed_manifestations | justified_preconditions | invalid_claims | minutes | extra_manual_checks | report_corrections | verdict_ok | note |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|
| f487f85 | A1 | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 0 | 3 | 0/3 (0.00) | 3 | -1 | 4 | 4 | yes | It maps the CVE to Spring/SpEL, while the reference is Go stdlib chunked-request parsing and the optional localhost pprof listener. |
| f487f85 | A2 | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 0 | 3 | 0/3 (0.00) | 3 | -1 | 5 | 4 | yes | It analyzes archive extraction and `mholt/archives`, not the Go stdlib `chunkedReader` path or diagnostics HTTP mode. |
| f487f85 | A3 | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 1 | 3 | 0/3 (0.00) | 1 | -1 | 4 | 3 | yes | Its explicit UNKNOWN and request for advisory mapping are procedurally sound, but it fails to report the reference’s known stdlib/pprof manifestations. |
| f487f85 | A4 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 | 3 | 0/3 (0.00) | 4 | -2 | 6 | 5 | yes | It gives real gitleaks config-path facts, but attributes the CVE to Viper and never analyzes Go toolchain version, diagnostics gating, or localhost binding. |
| f487f85 | A5 | 0 | 0 | 0 | 0 | 1 | 1 | 0 | 0 | 3 | 0/3 (0.00) | 2 | -1 | 5 | 4 | yes | It substitutes an absent x/net HTTP/2 module for the present Go stdlib and pprof exposure. |
| f487f85 | A6 | 1 | 1 | 1 | 1 | 2 | 2 | 1 | 1 | 3 | 0/3 (0.00) | 3 | -2 | 5 | 4 | yes | Its build-time code-generation reachability analysis is careful, but the reference target is stdlib chunk parsing on the optional localhost pprof server, not reggen. |

**Most useful answer for a human analyst:** A3, because it avoids an unsupported component claim and asks for the advisory mapping; it still leaves all known gitleaks/stdlib exposure facts unresolved.

## Disputed cases (representative ≥1-point packet-internal divergence)

These identify the exact answer labels and section scores that diverge; they are not claims about arm identity.

- `kubernetes-kubernetes-e196d24`: `root_cause`, A2 = 0 vs A3 = 1.
- `rancher-rancher-4dc4f53`: `vulnerability_mechanism`, A3 = 0 vs A6 = 1.
- `stretchr-testify-285adcc`: `residual_questions`, A3 = 0 vs A1 = 1.
- `aquasecurity-trivy-37da98d`: `product_exposure`, A4 = 0 vs A1 = 1.
- `juanfont-headscale-e172c29`: `residual_questions`, A1 = 0 vs A2 = 1.
- `zeromicro-go-zero-bae061a`: `vulnerability_mechanism`, A1 = 0 vs A3 = 1.
- `istio-istio-042afc3`: `vulnerability_mechanism`, A1 = 1 vs A3 = 2.
- `cilium-cilium-43bff35`: `product_exposure`, A2 = 0 vs A3 = 1.
- `gitleaks-gitleaks-f487f85`: `alternative_paths`, A1 = 1 vs A6 = 2.
- `kubernetes-kubernetes-ec78c0f`: no anchored-section divergence: all six answers score 0 in every section, because each maps the CVE to an unrelated component; the packet is uniformly wrong rather than internally score-disputed.

## Answer to hand to a human analyst, by case

- Kubernetes HTTP/2 Rapid Reset: **A4** — best concrete API-server path and clearest partial unauthenticated-vs-authenticated mitigation distinction; correct the v0.17.0 boundary.
- Kubernetes gogo/protobuf: **None** — every answer maps to a different vulnerability; restart from the pinned v1.3.1 generator/generated-method evidence.
- Rancher SSH-agent constraints: **A6** — closest component family and useful client/server distinction; redirect to `ServeAgent` and the temporary Unix socket.
- Testify YAML panic: **A2** — strongest product-scope and evidence structure, but replace the H2C mapping with `YAMLEq`/yaml.v3.
- Trivy Docker IPv6 behavior: **A1** — useful pure-Go/CGO and scanned-target boundary facts; add Docker client-versus-daemon and IPv4-only-interface checks.
- Headscale x/net/html: **A3** — strongest separation of product code from test-only external tooling; replace Python with x/net/html/transitive-linkage analysis.
- go-zero Accept-Language DoS: **A3** — closest x/text analysis and correctly identifies nested goctl scope and the cases/language-only use.
- Istio Terrapin: **A3** — correct mechanism and disciplined uncertainty about indirect SSH dependency/runtime use.
- Cilium spdystream memory exhaustion: **A3** — avoids fabricating a component and gives concrete follow-ups, though it should incorporate the known vendored parser and port-forward path.
- gitleaks chunked-request smuggling: **A3** — appropriately asks for component mapping instead of asserting a false target; it still omits the known pprof manifestation.

## Residual uncertainty about the reference

The reference itself leaves these sections intentionally unresolved, so I did not infer beyond them:

- Kubernetes HTTP/2: the exact v0.17.0 reset-accounting/fix diff and other possible Kubernetes HTTP/2 listeners/deployment exposure.
- Kubernetes protobuf: the precise generated field/trigger bytes, concrete remote call path, and regeneration consistency.
- Rancher: x/crypto v0.43.0 `parseConstraints` dispatch/trigger and whether another local process can reach the temporary socket.
- Testify: the exact YAML panic bytes and whether a downstream product supplies attacker-controlled assertion input.
- Trivy: the exact Docker daemon source/fix location, daemon runtime version/configuration, and whether another dependency compiles the affected daemon code.
- Headscale: transitive dependency linkage of `golang.org/x/net/html` and deployment/plugin inputs.
- go-zero: the exact fixed threshold for the advisory and whether `tools/goctl` is in the reviewed product scope.
- Istio: transitive `x/crypto/ssh` imports in final binaries and whether any deployed component exposes an SSH endpoint.
- Cilium: client-go internals/version-specific dialer behavior, deployed Hubble configuration, peer trust, and whether any additional SPDY caller exists.
- gitleaks: actual compiler/stdlib provenance, front-proxy topology, and pprof request-body behavior for a concrete smuggling payload.

## Systematic pattern observed (without arm attribution)

The dominant failure mode was incorrect CVE identity/component mapping: many answers confidently analyzed a plausible but unrelated package, OS component, or protocol. Even when the product-scope scan was detailed, answers often treated `go.mod`/toolchain declarations or absence of a source import as proof of runtime safety, omitted the reference’s alternative manifestations, and failed to mark unresolved deployment facts as `UNKNOWN` with bounded follow-ups. A smaller set of answers were careful about uncertainty and source scope, but still stopped before the known reference mechanism or call path.
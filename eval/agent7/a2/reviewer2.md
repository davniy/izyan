Scoring order for the eight section columns is: `vulnerability_mechanism`, `root_cause`, `attack_scenario`, `product_exposure`, `alternative_paths`, `evidence_quality`, `residual_questions`, `triage_recommendation`. `justified_preconditions` is the share of reference-required conditions that the answer both states and argues.

## Case: gitleaks-gitleaks-f487f85-CVE-2025-22871

| case | answer label | vulnerability_mechanism | root_cause | attack_scenario | product_exposure | alternative_paths | evidence_quality | residual_questions | triage_recommendation | missed_manifestations | justified_preconditions | invalid_claims | minutes | extra_manual_checks | report_corrections | verdict_ok | note |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|
| gitleaks...22871 | A1 | 0 | 0 | 0 | 0 | 0 | 1 | 1 | 0 | 2 | 0.00 | 5 | -8 | 9 | 6 | true | It identifies Spring/SpEL, but the reference is Go `net/http` chunked parsing; it also misses the optional localhost pprof listener and vulnerable toolchain boundary. |
| gitleaks...22871 | A2 | 0 | 0 | 0 | 0 | 0 | 1 | 1 | 0 | 2 | 0.00 | 4 | -7 | 8 | 5 | true | It substitutes an archive path-traversal advisory for the actual bare-LF chunk-size parser and gives no relevant pprof/toolchain analysis. |
| gitleaks...22871 | A3 | 0 | 0 | 0 | 1 | 1 | 1 | 2 | 1 | 2 | 0.00 | 0 | 1 | 5 | 3 | true | The honest UNKNOWN and concrete advisory lookup are useful, but it never identifies the actual Go stdlib parser, go1.23.4 boundary, or diagnostics listener. |
| gitleaks...22871 | A4 | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 0 | 2 | 0.00 | 5 | -8 | 9 | 6 | true | It grounds a real Gitleaks config path, but the asserted Viper path-traversal CVE is unrelated; the actual exposure is optional localhost pprof. |
| gitleaks...22871 | A5 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 2 | 0.00 | 3 | -5 | 7 | 4 | true | It asserts absent `x/net` and an HTTP/2 HEADER_TABLE_SIZE issue, while the reference concerns linked Go stdlib chunked-request parsing. |
| gitleaks...22871 | A6 | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 1 | 2 | 0.00 | 5 | -6 | 8 | 5 | true | Its build-time `reggen` import-graph analysis is specific but unrelated; it misses the linked vulnerable stdlib and opt-in localhost pprof server. |

**Most useful answer:** A3, because it avoids inventing a classification and asks for the missing advisory mapping, although a human would still need to analyze `net/http`, the Go toolchain version, and pprof exposure.

## Case: cilium-cilium-43bff35-CVE-2026-35469

| case | answer label | vulnerability_mechanism | root_cause | attack_scenario | product_exposure | alternative_paths | evidence_quality | residual_questions | triage_recommendation | missed_manifestations | justified_preconditions | invalid_claims | minutes | extra_manual_checks | report_corrections | verdict_ok | note |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|---|
| cilium...35469 | A1 | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 1 | 4 | 0.00 | 0 | 1 | 5 | 3 | true | It honestly says the CVE target is unknown, but does not identify the vendored SPDY parser, its three allocation manifestations, or the opt-in port-forward path. |
| cilium...35469 | A2 | 0 | 0 | 1 | 0 | 0 | 1 | 0 | 0 | 4 | 0.00 | 2 | -2 | 7 | 5 | false | The `false_positive` category is unsupported by its own UNKNOWN attack statement; it also supplies no SPDY or port-forward evidence. |
| cilium...35469 | A3 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 4 | 0.00 | 2 | 1 | 5 | 3 | true | UNKNOWN is appropriately bounded, but the answer even mistypes the follow-up as CVE-2026-35468 and never reaches SPDY memory allocation or port-forwarding. |
| cilium...35469 | A4 | 1 | 1 | 1 | 1 | 1 | 1 | 2 | 1 | 4 | 0.00 | 4 | 2 | 5 | 3 | true | It gives concrete Cilium/SPIFFE and dependency observations, but speculative go-jose reasoning is unrelated to the reference’s vendored SPDY parser. |
| cilium...35469 | A5 | 0 | 0 | 0 | 0 | 1 | 1 | 0 | 0 | 4 | 0.00 | 0 | -3 | 6 | 4 | true | It records a sensible metadata lookup, but the answer is otherwise only an unscored UNKNOWN and omits all known SPDY manifestations. |
| cilium...35469 | A6 | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 1 | 4 | 0.00 | 0 | -1 | 5 | 3 | true | It correctly limits itself to missing CVE metadata, but gives no mechanism, parser location, or port-forward exposure analysis. |

**Most useful answer:** A3, because it is explicit about the missing CVE mapping and proposes a concrete next step without the speculative component selection used by A4.

## Case: istio-istio-042afc3-CVE-2023-48795

| case | answer label | vulnerability_mechanism | root_cause | attack_scenario | product_exposure | alternative_paths | evidence_quality | residual_questions | triage_recommendation | missed_manifestations | justified_preconditions | invalid_claims | minutes | extra_manual_checks | report_corrections | verdict_ok | note |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|---|
| istio...48795 | A1 | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 1 | 1 | 0.00 | 4 | -4 | 6 | 4 | true | It describes OpenSSH ControlMaster rather than the x/crypto SSH integrity weakness and incorrectly treats the indirect x/crypto module as absent. |
| istio...48795 | A2 | 1 | 1 | 1 | 2 | 2 | 2 | 2 | 2 | 0 | 0.50 | 2 | 4 | 3 | 2 | true | It finds the right x/crypto/ssh scope and no direct imports, but “SSH-TAG” is a material mechanism error and transitive use remains unresolved. |
| istio...48795 | A3 | 1 | 1 | 1 | 2 | 2 | 2 | 2 | 2 | 0 | 0.75 | 2 | 5 | 3 | 2 | true | It correctly names Terrapin/prefix truncation and bounds the absent SSH path, but overstates the algorithm-downgrade effect and leaves the exact root implementation UNKNOWN. |
| istio...48795 | A4 | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 1 | 1 | 0.00 | 3 | -4 | 6 | 4 | true | It analyzes an unrelated OpenSSH scp buffer overflow; the actual reference is x/crypto/ssh and the absence of a first-party SSH import. |
| istio...48795 | A5 | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 1 | 1 | 0.00 | 3 | -4 | 6 | 4 | true | It substitutes an OpenSSH TCP Fast Open bypass for the Terrapin integrity issue and therefore misses the indirect x/crypto manifestation. |
| istio...48795 | A6 | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 1 | 1 | 0.00 | 2 | -3 | 6 | 4 | true | It again describes unrelated scp privilege escalation, although its Go-versus-OpenSSH scope distinction is directionally useful. |

**Most useful answer:** A3, because it identifies Terrapin, cites the absence of first-party SSH imports, and explicitly leaves transitive runtime use as a follow-up rather than claiming a verified negative.

## Case: zeromicro-go-zero-bae061a-CVE-2022-32149

| case | answer label | vulnerability_mechanism | root_cause | attack_scenario | product_exposure | alternative_paths | evidence_quality | residual_questions | triage_recommendation | missed_manifestations | justified_preconditions | invalid_claims | minutes | extra_manual_checks | report_corrections | verdict_ok | note |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|---|
| go-zero...32149 | A1 | 0 | 0 | 0 | 1 | 1 | 1 | 0 | 0 | 3 | 0.00 | 2 | -5 | 8 | 5 | true | It maps the CVE to Cargo/Rust, while the reference is x/text `ParseAcceptLanguage` and the nested v0.3.7 tool module. |
| go-zero...32149 | A2 | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 1 | 3 | 0.00 | 5 | -6 | 8 | 5 | true | Its gRPC/xDS mapping and fixed-version claim are unrelated; it does not analyze x/text, `ParseAcceptLanguage`, or the nested goctl module. |
| go-zero...32149 | A3 | 1 | 1 | 1 | 2 | 2 | 2 | 2 | 1 | 0 | 0.00 | 3 | 3 | 3 | 2 | true | It correctly finds the nested old x/text version and the cases/language-only use, but substitutes `encoding/japanese` and an EUC-JP bug for the actual language parser. |
| go-zero...32149 | A4 | 0 | 0 | 0 | 0 | 1 | 1 | 0 | 0 | 3 | 0.00 | 2 | -4 | 7 | 5 | true | It gives a concrete dependency absence claim, but for unrelated Cloudflare DNS/TLS code and without any actual go-zero path analysis. |
| go-zero...32149 | A5 | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 0 | 3 | 0.00 | 6 | -8 | 9 | 6 | true | It invents an x/net HTTP/2 vulnerability and server exposure; the reference has no x/net HTTP/2 target. |
| go-zero...32149 | A6 | 0 | 0 | 0 | 1 | 1 | 1 | 0 | 1 | 3 | 0.00 | 3 | -4 | 7 | 5 | true | It correctly notes go-zero uses stdlib HTTP, but that is irrelevant to the x/text language parser and misses all nested-module facts. |

**Most useful answer:** A3, because it at least locates the nested x/text v0.3.7 module and verifies that the observed first-party call is title casing rather than an affected Accept-Language parser.

## Case: juanfont-headscale-e172c29-CVE-2024-45338

| case | answer label | vulnerability_mechanism | root_cause | attack_scenario | product_exposure | alternative_paths | evidence_quality | residual_questions | triage_recommendation | missed_manifestations | justified_preconditions | invalid_claims | minutes | extra_manual_checks | report_corrections | verdict_ok | note |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|---|---|
| headscale...45338 | A1 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 3 | 0.00 | 3 | -6 | 8 | 5 | true | It maps to PHP-CGI and supplies no relevant x/net/html version, import search, or standard-template counter-observation. |
| headscale...45338 | A2 | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 1 | 3 | 0.00 | 3 | -4 | 7 | 5 | true | Its PHP mbstring analysis is detailed, but the actual reference is x/net/html v0.32.0 with no first-party html import. |
| headscale...45338 | A3 | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 1 | 3 | 0.00 | 4 | -3 | 6 | 4 | true | It carefully separates Python test fixtures from runtime, but Python is not the affected parser; it never checks x/net/html or Parse*. |
| headscale...45338 | A4 | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 1 | 3 | 0.00 | 4 | -3 | 6 | 4 | true | It gives well-bound PHP absence evidence, but the reference requires x/net/html module presence and the absence of affected imports. |
| headscale...45338 | A5 | 0 | 0 | 0 | 1 | 1 | 1 | 0 | 1 | 3 | 0.00 | 2 | -4 | 7 | 4 | true | Its CGO/glibc analysis is unrelated and omits both the v0.32.0 dependency and standard-library-template counterexample. |
| headscale...45338 | A6 | 0 | 0 | 0 | 1 | 1 | 1 | 0 | 0 | 3 | 0.00 | 2 | -3 | 7 | 5 | true | It identifies Python integration fixtures accurately, but the actual relevant distinction is `html/template` versus `golang.org/x/net/html`. |

**Most useful answer:** A3, because it gives the clearest product/test-scope evidence and explicitly distinguishes integration-only interpreter use, even though it analyzes the wrong ecosystem.

## Case: aquasecurity-trivy-37da98d-CVE-2024-32473

| case | answer label | vulnerability_mechanism | root_cause | attack_scenario | product_exposure | alternative_paths | evidence_quality | residual_questions | triage_recommendation | missed_manifestations | justified_preconditions | invalid_claims | minutes | extra_manual_checks | report_corrections | verdict_ok | note |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|---|
| trivy...32473 | A1 | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 1 | 2 | 0.00 | 4 | -4 | 7 | 5 | true | It substitutes GnuTLS for Docker network behavior; the pure-Go TLS observations do not establish whether an external Docker daemon is affected. |
| trivy...32473 | A2 | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 1 | 2 | 0.00 | 4 | -4 | 7 | 5 | true | Its curl/libcurl absence analysis is specific, but the reference component is Docker v26.0.1 and the relevant exposure is client-to-daemon use. |
| trivy...32473 | A3 | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 0 | 2 | 0.00 | 6 | -7 | 9 | 6 | true | It cites a real Trivy repository path but invents a go-git CVE and file-write attack; the reference only verifies Docker client/API calls. |
| trivy...32473 | A4 | 0 | 0 | 0 | 1 | 1 | 1 | 0 | 1 | 2 | 0.00 | 2 | -4 | 7 | 5 | true | It gives a concrete libarchive absence claim, but the actual dependency is Docker and the advisory has no source symbol in the snapshot. |
| trivy...32473 | A5 | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 1 | 2 | 0.00 | 4 | -4 | 7 | 5 | true | It correctly discusses Go TLS usage but maps the CVE to crypto/x509 instead of the external Docker daemon/network implementation. |
| trivy...32473 | A6 | 0 | 0 | 0 | 1 | 1 | 1 | 2 | 1 | 2 | 0.00 | 3 | -2 | 6 | 4 | true | It honestly leaves build provenance UNKNOWN, but the actual unresolved fact is Docker daemon source/runtime scope, not encoding/json. |

**Most useful answer:** A2, because its pure-Go/no-C-library evidence and explicit boundary between Trivy and scanned artifacts are useful, though it still needs the Docker client/daemon distinction from the reference.

## Case: stretchr-testify-285adcc-CVE-2022-28948

| case | answer label | vulnerability_mechanism | root_cause | attack_scenario | product_exposure | alternative_paths | evidence_quality | residual_questions | triage_recommendation | missed_manifestations | justified_preconditions | invalid_claims | minutes | extra_manual_checks | report_corrections | verdict_ok | note |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|---|---|
| testify...28948 | A1 | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 1 | 2 | 0.00 | 3 | -4 | 7 | 5 | true | It analyzes Windows TCP/IP rather than the old yaml.v3 decoder and misses `assert.YAMLEq` plus the require forwarding APIs. |
| testify...28948 | A2 | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 1 | 2 | 0.00 | 4 | -4 | 7 | 5 | true | Its H2C discussion accurately scopes test helpers but is unrelated to `yaml.Unmarshal` in `YAMLEq`; the cited HTTP utilities are not the affected manifestation. |
| testify...28948 | A3 | 0 | 0 | 0 | 1 | 0 | 1 | 0 | 1 | 2 | 0.00 | 2 | -3 | 6 | 4 | true | It has a checkable dependency list, but the go-chi absence does not address the vulnerable yaml.v3 version or assertion APIs. |
| testify...28948 | A4 | 0 | 0 | 0 | 1 | 0 | 1 | 0 | 1 | 2 | 0.00 | 2 | -3 | 6 | 4 | true | It grounds FFmpeg absence, while the reference requires the old YAML dependency and `yaml.Unmarshal` call sites. |
| testify...28948 | A5 | 0 | 0 | 0 | 1 | 0 | 1 | 0 | 1 | 2 | 0.00 | 2 | -3 | 6 | 4 | true | It checks go-cmp absence but never analyzes the present pre-fix yaml.v3 module or YAMLEq input flow. |
| testify...28948 | A6 | 0 | 0 | 0 | 1 | 0 | 1 | 0 | 1 | 2 | 0.00 | 2 | -3 | 6 | 4 | true | ImageMagick/HEIC absence is unrelated; the concrete missed fact is `assert.YAMLEq` forwarding attacker-controlled strings to `yaml.Unmarshal`. |

**Most useful answer:** A2, because its product and HTTP-helper scope analysis is the most detailed and bounded, although it still requires a complete YAML-specific review.

## Case: rancher-rancher-4dc4f534-CVE-2025-47914

| case | answer label | vulnerability_mechanism | root_cause | attack_scenario | product_exposure | alternative_paths | evidence_quality | residual_questions | triage_recommendation | missed_manifestations | justified_preconditions | invalid_claims | minutes | extra_manual_checks | report_corrections | verdict_ok | note |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|---|---|
| rancher...47914 | A1 | 0 | 0 | 0 | 0 | 1 | 1 | 0 | 1 | 3 | 0.00 | 2 | -5 | 8 | 5 | true | It maps to yaml.v1, while the reference is x/crypto/ssh/agent v0.43.0 and a local `ServeAgent` socket. |
| rancher...47914 | A2 | 0 | 0 | 0 | 1 | 1 | 1 | 2 | 1 | 3 | 0.00 | 6 | -4 | 9 | 6 | true | It gives extensive Rancher TLS evidence but the repeated, self-correcting output is about the wrong stdlib CVE and misses the SSH-agent server path. |
| rancher...47914 | A3 | 0 | 0 | 0 | 1 | 1 | 1 | 2 | 1 | 3 | 0.00 | 2 | 1 | 6 | 4 | true | Its UNKNOWN classification is disciplined, but the candidate go-jose discussion does not identify x/crypto/ssh/agent or the temporary Unix socket. |
| rancher...47914 | A4 | 0 | 0 | 0 | 1 | 1 | 1 | 2 | 1 | 3 | 0.00 | 4 | -2 | 7 | 5 | true | It verifies a real SAML parsing path, yet the reference manifestation is local SSH-agent constraint parsing, not SAML. |
| rancher...47914 | A5 | 0 | 0 | 0 | 1 | 1 | 1 | 0 | 1 | 3 | 0.00 | 2 | -3 | 7 | 5 | true | It gives a specific absent archiver claim, but the affected module is present and used through `ServeAgent`. |
| rancher...47914 | A6 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 3 | 0.00 | 4 | 0 | 5 | 4 | true | It finds Rancher’s x/crypto SSH use, but analyzes an SSH server/banner path rather than `ssh/agent.ServeAgent` constraint parsing and local socket exposure. |

**Most useful answer:** A6, because it at least directs a human to the correct x/crypto SSH dependency and Rancher SSH call sites, even though it misses the agent subpackage and exact local-socket mechanism.

## Case: kubernetes-kubernetes-ec78c0f-CVE-2021-3121

| case | answer label | vulnerability_mechanism | root_cause | attack_scenario | product_exposure | alternative_paths | evidence_quality | residual_questions | triage_recommendation | missed_manifestations | justified_preconditions | invalid_claims | minutes | extra_manual_checks | report_corrections | verdict_ok | note |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|---|---|
| kubernetes...3121 | A1 | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 1 | 3 | 0.00 | 5 | -5 | 8 | 5 | true | It analyzes an x/net SETTINGS-frame DoS, while the reference is gogo/protobuf generated `Unmarshal` bounds checking and the v1.3.1 pin. |
| kubernetes...3121 | A2 | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 1 | 3 | 0.00 | 4 | -5 | 8 | 5 | true | It analyzes Go stdlib HTTP/2 redirect behavior and a toolchain version, not the vendored gogo generator and generated protobuf methods. |
| kubernetes...3121 | A3 | 0 | 0 | 0 | 1 | 1 | 1 | 0 | 1 | 3 | 0.00 | 2 | -4 | 7 | 5 | true | It substitutes crypto/ecdh and gives no evidence about `plugin/unmarshal`, generated files, or malformed protobuf input. |
| kubernetes...3121 | A4 | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 1 | 3 | 0.00 | 4 | -4 | 7 | 5 | true | Its sudo/visudo absence search is unrelated; the affected Go generator and committed generated methods are present in the snapshot. |
| kubernetes...3121 | A5 | 0 | 0 | 0 | 1 | 1 | 1 | 0 | 1 | 3 | 0.00 | 2 | -3 | 7 | 5 | true | It analyzes systemd bindings instead of gogo/protobuf and supplies no malformed-input or generated-Unmarshal path. |
| kubernetes...3121 | A6 | 0 | 0 | 0 | 1 | 1 | 1 | 0 | 0 | 3 | 0.00 | 3 | -4 | 7 | 5 | true | It identifies a real Kubernetes kubelet surface but maps it to the wrong CVE; the reference’s manifestation is generated protobuf parsing. |

**Most useful answer:** A6, because its concrete Kubernetes source-path analysis could help a human redirect the investigation, though it does not analyze the actual gogo/protobuf defect.

## Case: kubernetes-kubernetes-e196d24-CVE-2023-44487

| case | answer label | vulnerability_mechanism | root_cause | attack_scenario | product_exposure | alternative_paths | evidence_quality | residual_questions | triage_recommendation | missed_manifestations | justified_preconditions | invalid_claims | minutes | extra_manual_checks | report_corrections | verdict_ok | note |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|---|
| kubernetes...44487 | A1 | 2 | 2 | 2 | 2 | 1 | 2 | 2 | 2 | 0 | 0.75 | 2 | 5 | 3 | 2 | true | It correctly identifies rapid resets, the vendored HTTP/2 path, and API-server exposure; its unverified exact fix/version and etcd extension keep alternatives/root from full confidence. |
| kubernetes...44487 | A2 | 2 | 1 | 2 | 2 | 2 | 2 | 2 | 1 | 0 | 0.67 | 2 | 4 | 3 | 2 | true | It correctly cites the unauthenticated teardown and stream limits, but overstates them as making risk negligible and does not establish the dependency’s fixed-boundary status. |
| kubernetes...44487 | A3 | 2 | 1 | 2 | 2 | 2 | 2 | 2 | 1 | 0 | 0.75 | 4 | 3 | 4 | 3 | true | The frame-to-reset call path is strong, but the claim that v0.17.1 is the fix and that no mitigation exists is not established by the reference. |
| kubernetes...44487 | A4 | 2 | 1 | 2 | 2 | 2 | 2 | 1 | 2 | 0 | 0.75 | 3 | 4 | 3 | 2 | true | It correctly notes partial unauthenticated mitigation and authenticated exposure, but the exact “settingsStream”/fix claims are not reference-verified. |
| kubernetes...44487 | A5 | 1 | 0 | 0 | 1 | 1 | 1 | 0 | 0 | 0 | 0.25 | 3 | -2 | 5 | 3 | true | It claims v0.17.0 is safely above a v0.11.0 fix while the reference treats v0.17.0 as the advisory fixed boundary; it misses the actual listener and reset path. |
| kubernetes...44487 | A6 | 1 | 1 | 1 | 2 | 0 | 1 | 0 | 1 | 1 | 0.50 | 3 | 0 | 5 | 3 | true | It identifies the API-server path but incorrectly makes the default stream count 250 the vulnerability and supplies no alternative-path or residual analysis. |

**Most useful answer:** A3, because it gives the clearest concrete reset-frame call path and API-server configuration evidence, despite overclaiming the precise patch version.

## Disputed cases / internally borderline scores

These are cases where I had a genuine anchored-level choice while scoring the sheet; the two values show the competing scores considered before selecting the table value:

- `cilium...35469`, A3 `vulnerability_mechanism`: **0 vs 1** — whether an explicit UNKNOWN plus concrete metadata follow-up merits level 1 when the reference mechanism is available.
- `cilium...35469`, A4 `residual_questions`: **1 vs 2** — whether the long list of dependency/runtime follow-ups is sufficiently actionable despite speculative go-jose focus.
- `istio...48795`, A2 `product_exposure`: **1 vs 2** — whether the correct no-first-party-SSH finding earns full exposure credit despite the wrong “SSH-TAG” mechanism.
- `go-zero...32149`, A3 `triage_recommendation`: **1 vs 2** — whether “needs review” is fully actionable when the answer has selected the wrong x/text subpackage.
- `rancher...47914`, A6 `root_cause`: **1 vs 2** — whether naming x/crypto/ssh and a concrete call site is enough when the reference requires `ssh/agent` constraints.
- `kubernetes...44487`, A1 `root_cause`: **1 vs 2** — whether the cited early-reset guard and process path support full root-cause credit despite the unverified patch-diff claim.
- `kubernetes...44487`, A2 `triage_recommendation`: **1 vs 2** — whether “negligible” is too strong given the reference’s bounded uncertainty and fixed-boundary dependency.

## Per-case answer I would hand to a human analyst

| case | answer | why |
|---|---|---|
| gitleaks...22871 | A3 | Honest uncertainty and a concrete request for the CVE/component mapping; least misleading despite being incomplete. |
| cilium...35469 | A3 | Avoids speculative component selection and gives a direct metadata-to-source follow-up. |
| istio...48795 | A3 | Correctly recognizes Terrapin and bounds the no-SSH finding while preserving transitive uncertainty. |
| go-zero...32149 | A3 | It finds the nested old x/text module and confirms the observed code uses only case conversion. |
| headscale...45338 | A3 | Best product/test-scope separation and explicit treatment of external Python fixtures. |
| trivy...32473 | A2 | Strongest boundary analysis between a pure-Go Trivy binary and artifacts/tools outside the binary. |
| testify...28948 | A2 | Most useful concrete analysis of the test-only HTTP helpers and their lack of a server surface. |
| rancher...47914 | A6 | At least points at Rancher’s x/crypto SSH uses, giving the human a path to the missing agent analysis. |
| kubernetes...3121 | A6 | Concrete Kubernetes call-site work is more reusable than the unrelated package-only answers. |
| kubernetes...44487 | A3 | Most complete mechanism, call path, exposure, and residual-question analysis. |

## Residual uncertainty about the reference

The reference itself explicitly leaves the exact upstream fix mechanism unavailable for several dependency vulnerabilities, including Rancher’s `x/crypto/ssh/agent` parser, Docker’s daemon-side implementation, and the precise generated gogo/protobuf trigger. I also treated manifestation counts according to the reference’s listed concrete observations; a different granularity for “module present,” “symbol/path present,” and “listener exposed” could change only the count columns, not the section judgments. For the HTTP/2 Rapid Reset case, I retained the reference’s statement that v0.17.0 is exactly at the advisory fixed boundary and therefore penalized unverified claims that v0.17.0 is plainly pre-fix.

## Systematic pattern observed

Across the answers, many reports confidently supplied a detailed but unrelated CVE/component mapping and then performed careful source analysis of that wrong component. Those reports often had good local evidence quality but near-zero mechanism, root-cause, and attack-scenario credit against the independent reference. The comparatively useful reports stated UNKNOWN when the component or dependency source was not established, separated first-party code from test/build/runtime artifacts, and named concrete follow-up checks rather than treating a package-name search as proof of absence.
# DESIGN_FOR_REVIEW — Definitive verdicts with explicit external dependencies

**Design gate: READY. No user-owned policy question is required.**

## Decision

Adopt this contract:

> **An analysis must either earn a definitive verdict, identify a specific external fact that changes the answer, or report that the analyzer failed to answer. An unfinished code analysis is not a legitimate `INCONCLUSIVE` verdict.**

For the motivating case, the expected result is:

**`EXPLOITABLE` for `CVE-2023-44487`, under `zero_trust`, explicitly scoped to the transport-peer boundary, proven through `GO-2023-2153`.**

That means a hostile client of the affected gRPC listener can drive the vulnerable implementation. It does **not** mean an arbitrary Internet attacker can reach Kubernetes’s Unix sockets. Actual access to those sockets remains a separate deployment question.

Two other decisions are essential:

- `related` remains a discovery relationship—not an alias and not permission to inherit facts.
- The existing scope gate and positive-only composition mean **CVE-wide negative verdicts remain unavailable**. Where no positive can be proved, this limitation must be reported as a capability/scope failure, not disguised as environmental uncertainty.

---

## 1. Definitive-verdict policy

### 1.1 Separate claim uncertainty from the outcome of the analysis

Keep `TRUE / FALSE / UNKNOWN` for claims. An unsuccessful measurement must still leave its claim `UNKNOWN`; changing the terminal policy must not manufacture evidence.

Add a separate, authoritative assessment outcome:

| Assessment outcome | Public verdict | Meaning |
|---|---|---|
| `DECIDED` | `EXPLOITABLE`, `NOT_AFFECTED`, or `NO_EXPLOIT_PATH_FOUND` | The applicable proof rules earned the answer. |
| `EXTERNAL_DEPENDENCY` | `INCONCLUSIVE` | A named, decision-changing fact lies outside the artifact and selected threat profile. |
| `FAILED` | No verdict | Analysis, input resolution, proof capability, or scope authority was insufficient. |

`FAILED` is **not a fifth vulnerability verdict**. Reuse workflow `FAILED`, with structured diagnostics and a report.

This replaces the current conflation of tool limitations, exhausted budgets, ambiguous root causes, and environmental dependencies. That conflation is explicit in `docs/dev/specs/governing-spec.md:235–251,418–433` and the budget transition in `internal/workflow/engine.go:50–57`.

### 1.2 Decision table

A condition being `TRUE` contributes to a positive conjunction; it does not independently establish exploitability.

| Condition or unresolved question | Artifact-owned or external? | Required treatment |
|---|---|---|
| Module membership in the recorded dependency graph | Artifact-owned | Decide membership. An admitted negative may ground `NOT_AFFECTED`, subject to the unchanged finding-scope gate. Failure to enumerate the graph is `FAILED`. |
| Dependency version against the record’s ranges | Artifact-owned when the graph identifies the version | Apply the record’s own ranges, replacements and source identity. Out-of-range may ground `NOT_AFFECTED`. Parser/resolver failure is `FAILED`. |
| Package presence, production/test ownership, build inclusion | Artifact-owned **for an identified build** | Decide using admitted inventories. Absence may ground `NOT_AFFECTED`; incomplete/failed inventories cannot. |
| Which build or delivered artifact is actually in scope | External if the request does not identify it | `INCONCLUSIVE` when different valid targets change the answer. A supplied target that the analyzer failed to measure is instead `FAILED`. |
| Shipped Go toolchain for a stdlib vulnerability | External when absent from authoritative artifact/release evidence | `INCONCLUSIVE`. Do not substitute the analyzer’s Go version, a `go.mod` minimum, or supporting CI declarations. |
| Defect locus, implementation presence, server/client role | Artifact-owned | Resolve from the record, source and fix evidence. Ambiguous binding or unsupported analysis is `FAILED`, unless an independent admitted proof already decides the finding. |
| Reachability through code contained in the artifact | Artifact-owned | Prove a path, or prove the relevant absence through negative verification. Unresolved dispatch, reflection analysis, skipped packages or exhausted bounds are analyzer failures—not environmental answers. |
| Attacker-selectable bytes at an actual product input boundary | Artifact-owned under the selected threat profile | Trace the bytes and their transformations. A missing trace is `FAILED`; it is not proof of safety. |
| Trigger feasibility, relevant guards, protocol sequence, configuration values fixed by code | Artifact-owned | Decide the mechanism-specific condition. A reachable function alone is insufficient. Unsupported trigger/guard reasoning is `FAILED`. |
| Runtime configuration value supplied outside the artifact | External | `INCONCLUSIVE` if the value is mandatory and changes the answer. Checked-in effective configuration is not automatically external. |
| Whether configuration, database contents or an internal service are adversary-controlled | External where their ownership/trust is not established | `INCONCLUSIVE`, naming the exact source and trust question. “Internal” does not establish trusted. |
| Whether an adversary can connect to a listener: socket permissions, placement, ingress, credentials, deployed policy | External for a deployed-system assessment | `INCONCLUSIVE` if mandatory and not supplied. Listener type and bind address themselves are code facts. |
| Dynamically supplied plugin or executable absent from the artifact | External artifact dependency | Name the missing artifact. Conversely, inability to analyze plugin code already supplied is `FAILED`. |
| Advisory discovery, CVE attribution, conflicting documents, missing proof artifacts | Analyzer/input capability | Resolve through the configured sources. Unresolved attribution, source acquisition failure or conflicting pins is `FAILED`, not a deployment question. |
| Insufficient `RecordExtent`/inventory or unsupported CVE negative closure | Scope capability | `FAILED` if no independent positive decides the request. Never promote a component negative. |
| Pending mandatory-condition criticism, unverified mandatory `FALSE`, missing negative-verification capability | Proof capability | Preserve the unresolved claim and report `FAILED`; do not accept a weaker verdict. |
| Unknown supporting factor that cannot change the verdict | Neither a mandatory blocker nor a reason to abstain | Retain it as a limitation. Publish the earned definitive verdict. |

**Externality test:** holding the artifact and selected profile fixed, can two legitimate environments produce different answers to the specific mandatory question? If yes, identify that external variable. If the missing work is simply “inspect more code” or “complete the measurement,” it is not external.

This is an operational proof-completion requirement, not a claim that arbitrary program reachability is mathematically decidable. Unsupported analysis must be visible as failure.

### 1.3 Terminalization rule

After evidence admission, record evaluation and request composition:

```text
A sufficient admitted proof decides the exact requested question
    → DECIDED

Otherwise, decision-relevant code/proof/input/scope blockers remain
    → FAILED; no verdict

Otherwise, named decision-changing external dependencies remain
    → EXTERNAL_DEPENDENCY; INCONCLUSIVE

Otherwise
    → FAILED / UNCLASSIFIED_ANALYSIS_GAP
```

An independent positive witness can make failures in other candidate assessments irrelevant to the existential CVE answer. Preserve those diagnostics, but do not let them veto that positive.

Likewise, an admitted exact-record affected-negative can decide without evaluating irrelevant exploit conditions.

An external-dependency result must identify:

- the missing fact and affected condition;
- evidence locating the boundary;
- why the artifact cannot supply it;
- which alternatives change the answer;
- the evidence/input that would resolve it.

An LLM cannot declare a gap environmental merely by assigning it a label.

---

## 2. A hard boundary: no CVE-wide negative closure under these constraints

`AllowsNegativeClosure()` requires an exact `GO-`/`GHSA-` request, `ADVISORY_ENTRIES`, `COMPLETE`, `FULL_RECORD`, and a valid fully represented census. It categorically rejects `Kind=CVE` (`internal/domain/advisory_scope.go:175–218`).

Together with positive-only composition, this entails:

> Even if every discovered candidate is independently negative, their negatives cannot produce CVE-level `NOT_AFFECTED` or NEPF.

Therefore, an all-negative CVE analysis without another admitted decision ends:

```text
assessment_outcome: FAILED
failure_code: UNSUPPORTED_NEGATIVE_SCOPE
verdict: absent
```

Its exact-record child negatives remain available.

This is an unavoidable limitation of the stipulated authority model. A frozen advisory dump is not proof of CVE-wide exhaustiveness. Do not:

- rebind a CVE request silently to an exact advisory;
- manufacture aggregate completeness;
- weaken `AllowsNegativeClosure`;
- call this limitation environmental;
- reinterpret `code_not_present` or `code_not_reachable` ground truth as exploitable.

**The design makes definitive answers the required successful outcome; it cannot honestly guarantee successful definitive answers for every request while preserving these constraints.**

---

## 3. Multi-record CVE resolution

### 3.1 Discover records, not an equivalence class

Reuse advisory-feed acquisition and provenance, extending its index with separate:

```text
record ID → document references
alias ID  → document references
related ID → document references
```

For CVE `C`, nominate records whose own ID, aliases, or **direct** `related` entries name `C`, plus direct neighbors of the initially resolved record.

The inverse lookup is mandatory: `GO-2023-2153` points toward the CVE; the primary GHSA need not point toward gRPC.

Rules:

- No transitive `related` closure.
- No aliases-plus-related connected component treated as one vulnerability.
- No title/CWE similarity as attribution.
- Preserve unsupported, conflicting, unreadable and unevaluated candidates.
- Pin source manifests and document digests.
- Identical documents deduplicate; conflicting bytes for the same record ID require an explicit source selection.
- Use configured sources only. No benchmark directories, adjacent worktrees or undeclared caches.

When permitted remote resolution is configured, acquire and pin the feed through that source policy. Offline operation needs supplied records/feed. A primary-negative CVE request with no adequate discovery capability fails explicitly; it does not claim to have searched all implementations.

A valid positive does not require exhaustive discovery.

### 3.2 Admit a directional implementation attribution

Use a separate proposition:

> **CVE C covers the particular implementation/mechanism proved in record R.**

This is not `R == C`, and grants no fact-inheritance authority.

Admit it through:

1. An unambiguous identity assertion in R’s own ID/aliases; or
2. Captured publisher/CNA material explicitly connecting C to R’s implementation, bound to the proved affected entry/mechanism.

Persist:

```text
CVE ID
candidate ID + document digest
covered entry/mechanism references
attribution basis
source URI + captured digest + exact field/quote
implementation/fix binding
admission result
```

Bare `related` remains insufficient. The [OSV definition](https://ossf.github.io/osv-schema/#related-field) permits a “similar but completely different vulnerability.”

**The gRPC case has the stronger evidence.** The [gRPC publisher advisory GHSA-m425-mq94-257g](https://github.com/grpc/grpc-go/security/advisories/GHSA-m425-mq94-257g) explicitly displays `CVE-2023-44487`, names `google.golang.org/grpc`, and identifies fix PR 6703. `GO-2023-2153` names that GHSA as an alias and references the corresponding fix.

Thus:

```text
GO record → its publisher advisory → explicit CVE/implementation attribution
```

The analyzer can admit this attribution without inserting the CVE into the GO record’s aliases or copying publisher facts into its applicability assessment.

If attribution cannot be admitted, retain any record-level positive separately and report `CVE_ATTRIBUTION_UNRESOLVED` for the unanswered CVE request. Do not quietly stop at a related-edge hint when the publisher evidence is available.

### 3.3 Evaluate each record independently

Every assessment—including the primary—uses exact record bytes and its own:

- ranges, modules, packages and symbols;
- original census and extent;
- root cause and mandatory conditions;
- claims, reviews and negative verification;
- applicability, profile results, severity and remediation.

Do not use alias enrichment or feed subject-merging to populate an assessment from another record. Those paths currently exist in `internal/vulnerability/source.go:169–269` and `internal/research/deterministic.go:3079–3168`; they are not the isolated-record loading path.

Share immutable product measurements, not advisory conclusions. Re-project them against each record’s subjects and build identity.

In particular, govulncheck metadata currently unions subjects under aliases (`internal/goanalysis/govulncheck.go:490–545`). A common CVE key must not confer another record’s subject coverage. Retain the emitting record and exact module/package/symbol binding.

### 3.4 Compose only independently earned positives, per profile

For CVE C and profile/build scope p:

\[
\operatorname{Positive}(C,p)
\iff
\exists R:
\operatorname{Attributed}(R,C)
\land
\operatorname{IndependentlyExploitable}(R,p).
\]

Do not assemble a witness using reachability from one record, attacker control from another, or different profiles/builds.

- One admitted positive decides the CVE.
- Candidate negatives never close the CVE.
- A zero-trust positive does not establish a cluster-perimeter positive.
- Exact-advisory requests retain their own assessment; related positives are separate findings.

Keep the primary GHSA census **22/1/21**, `GO_PROJECTION`, `KNOWN_ONLY`. Do not append gRPC as a 23rd entry or create a synthetic aggregate inventory.

---

## 4. Worked Kubernetes decision

### 4.1 Applicability

The independent facts are:

| Record/implementation | Snapshot | Result |
|---|---|---|
| Primary GHSA’s `golang.org/x/net` entry | `v0.17.0` | Fixed for that entry. Preserve `VersionAffected=FALSE`. |
| `GO-2023-2153`: `google.golang.org/grpc` | `v1.55.0` | Affected: inside `[0,1.56.3)`. |

The GO record also declares `[1.57.0,1.57.1)` and `[1.58.0,1.58.3)`. These ranges belong to gRPC, not x/net.

Both pins are visible in the snapshot’s `go.mod:82,91` and `vendor/modules.txt:973,1122`.

### 4.2 Production-rooted reachability, not just imports

The source contains a concrete kubelet path:

```text
cmd/kubelet/app/server.go:1253
    go k.ListenAndServePodResources()

pkg/kubelet/kubelet.go:2907–2922
    server.ListenAndServePodResources(...)

pkg/kubelet/server/server.go:222–236
    grpc.NewServer(...)
    util.CreateListener(...)
    server.Serve(listener)
```

The vendored gRPC implementation continues through:

```text
Server.Serve
 → handleRawConn
 → newHTTP2Transport
 → transport.NewServerTransport
 → serveStreams / HandleStreams
```

See vendored `grpc/server.go:778–978`.

Other supplied locations corroborate server-side use:

- device-plugin registration: `NewServer` and `Serve`, `server.go:107–112`;
- KMS service: Unix listener, `NewServer`, `Serve`, `grpc_service.go:60–75`;
- DRA plugin: `NewServer`, `Serve`, `nonblockinggrpcserver.go:90–102`.

**Do not count a stub, example or staging API as a shipped kubelet path merely because it is in a non-test file.** KMS/DRA require their own product-root binding. The rooted kubelet witness is sufficient; proving every alternative product surface is unnecessary for this positive.

### 4.3 Prove the Rapid Reset mechanism too

`NewServer` alone is not enough. The candidate must establish:

1. An active server transport consumes peer-supplied HTTP/2 frames.
2. The peer can open/reset/reopen streams.
3. The vulnerable lifecycle admits handler work without the fixed handler-quota enforcement.
4. No applicable product-side control prevents that operation before the vulnerable stage.

The inspected source supports this worked mechanism:

- `operateHeaders` checks the active-stream count and invokes the stream handler;
- `serveStreams` starts handler goroutines;
- `RST_STREAM` invokes `closeStream`, which cancels and removes the stream from `activeStreams`;
- removing a stream does not synchronously join its handler before admitting subsequent streams.

The [upstream fix](https://github.com/grpc/grpc-go/commit/f2180b4d5403d2210b30b93098eb7da31c05c721) adds handler-quota acquire/release around that execution.

Podresources’ rate limiter is a unary interceptor (`ratelimit.go:49–67`), not the missing pre-dispatch transport quota. Its existence cannot be used as a blanket falsifier.

Record a source/fix-bound trigger witness for `C-CONSTRAINT`. Do **not** earn this condition merely from the existing generic “server transport frame found” heuristic. If the analyzer cannot establish this code-owned obligation, the result is `FAILED / TRIGGER_PROOF_INCOMPLETE`, not environmental `INCONCLUSIVE`.

### 4.4 Distinguish transport-peer exploitability from deployed exposure

The repository already defines `zero_trust` as hostile-peer analysis; `ServerTransportInput` explicitly assumes the attacker can connect (`internal/evaluator/transport.go:10–19,200–220`).

Make that boundary machine-readable:

```text
verdict: EXPLOITABLE
profile: zero_trust
exploitability_scope: transport-peer
control_basis: transport-peer-input
proof_origin: GO-2023-2153
```

Add `transport-peer` to the existing orthogonal scope mechanism—not a new verdict or profile. Set it only from an admitted **mandatory TRUE** transport-input claim, never from a supporting exposure observation.

Required limitation:

> Transport-peer scope: a client of the product’s affected transport can supply the triggering input. Whether an adversary can access that transport—through socket permissions, placement, ingress or authentication—is not established.

This is separate from the library-API route. **DESERIALIZATION + CWE-502 admission remains unchanged.** Do not exempt transport-peer claims from cluster-perimeter rewriting as library-public-api claims are exempted.

For local endpoints, say “client of the listener,” not “remote Internet client.”

### 4.5 Expected outcomes

| Question | Expected result |
|---|---|
| CVE exploitability in this source snapshot, default hostile-peer profile | **`EXPLOITABLE / transport-peer`, via independently assessed and attributed `GO-2023-2153`.** |
| Can an arbitrary external attacker reach the deployed Unix socket? | **`INCONCLUSIVE`**, unless deployment evidence settles access. This is a legitimate external dependency. |
| Are all peers trusted under a selected cluster-perimeter policy? | Separate environmental premise/profile. Never inferred merely from Unix/loopback binding. |
| Exact broad primary GHSA request | No gRPC substitution and no negative closure. Its unanswered whole-record assessment becomes a scope-capability failure under the new terminal policy. |
| A particular shipped binary or release | Bind that artifact/build first. Never present a source-snapshot proof as proof about an unidentified delivered binary. |

The saved run is **not** retrospectively a positive measurement. It assessed fixed x/net, did not assess the gRPC conjunction, and remains historical evidence of the old result. The positive above is the required outcome of the proposed completed mechanism.

### 4.6 Close the local-listener-to-trust shortcut

`ClassifyPerimeter` currently maps loopback/Unix-only listeners to `cluster-internal`; target selection can then choose the trusted-peer profile (`internal/exposure/perimeter.go:109–115,258–271`; `internal/states/states.go:2261–2306`).

That is not an admissible inference here: **local does not mean trusted**.

Carry a typed perimeter basis. Listener-only evidence describes exposure; it must not alone select a trusted target profile or stamp `auto-perimeter` trust. Require an admitted deployment-policy basis or explicit operator profile selection. Keep hypothetical profile results distinct from the actual deployment assessment.

No user question is needed: this follows from the governing prohibition on false-safe conclusions.

---

## 5. Pipeline, persistence and publication

Extend the existing state-machine architecture:

```text
Resolve request and pinned records
 → Discover candidates and resolve attribution
 → Existing isolated record pipelines
 → Compose requested finding per profile
 → Finalize outcome: decided / external dependency / failed
 → Write reports
 → Terminal state
```

Key requirements:

- A primary component-negative or primary-resolution failure cannot prevent available CVE candidates from being evaluated.
- Existing gap analysis pursues code obligations; budget exhaustion becomes a named failure, not an external question.
- Preserve pure verdict calculation and all admission gates.
- Record structured gap causes at their producers. Do not classify outcomes by parsing limitation strings.
- Persist a required `requested_finding` in the new schema, plus discovery and independent assessments.
- Qualify all condition/evidence references by assessment identity.
- Re-admit saved proofs and attribution before publication.
- Write failure reports too; do not terminate before producing the diagnostic deliverable.
- Legacy records lacking classified dependencies cannot be assumed to represent legitimate external abstention.

All consumers must use the same requested-finding projection: JSON, CLI, scan/eval, tracker, Markdown, OpenVEX, CycloneDX and research output.

For a composed positive, exports must identify the CVE and actual gRPC witness/subcomponent/remediation—not x/net’s fixed version. Carry profile, `transport-peer` scope, limitations and source/build scope in schema-supported text and companion structured JSON.

OpenVEX/CycloneDX may use `under_investigation`/`in_triage` for both external dependencies and failures, but the companion assessment outcome and explanation must distinguish them.

Also prevent risk wording from turning “no exposure facts resolved” into “no external exposure.” Scope reporting must not introduce that converse overclaim.

---

## 6. Corpus blast radius

No new benchmark outcome is claimed.

The retained post-scope calibration contains 17 rows: 13 `INCONCLUSIVE`, four `EXPLOITABLE`, including duplicate request/target controls. It explicitly states that CVE-scoped negative closure is unavailable (`docs/dev/reports/2026-10-25-05-scope-bound-version-negatives-calibration.md:139–172`).

| Population/example | Intended effect |
|---|---|
| Kubernetes `e196d24`, CVE-2023-44487 | Current abstention becomes **`EXPLOITABLE / transport-peer`** once isolated gRPC attribution and the complete code witness are admitted. |
| Testify CVE-2022-28948 | Preserve the already demonstrated `EXPLOITABLE / library-api`; do not widen its admission rule. |
| Cilium CVE-2026-35469 | Preserve explicit `linux/amd64` positive. Missing relevant product-target input remains external; do not infer it from the host. |
| Exact-record constant-payload fixtures such as `real-yaml-const`, `real-yaml3-const`, `real-protojson-const` | Code-owned closure obligations must be completed. With admitted target, complete scope and verified falsifier, earn NEPF; unsupported proof becomes failure, not generic abstention. |
| Exact-record unused-locus/plain-gRPC fixtures | Preserve distinction between unaffected implementation and verified unreachable defect. Earn the appropriate negative through existing gates—not from plain-server construction alone. |
| `real-http2-server` and stdlib cases without authoritative release toolchain | Legitimate external `INCONCLUSIVE` remains. |
| Headscale/Istio unresolved reachability, incomplete package loading, ambiguous root cause, timeout cases | Reclassify unfinished analysis as explicit failures unless further proof earns a decision. No automatic safe recovery. |
| CVE-scoped safe-label cases: Helm, Istio Terrapin, fixed Podman dependency cases | Keep frozen labels. Exact-child negatives remain evidence, but the CVE request cannot become safe under positive-only composition; unsupported closure becomes failure. |
| Configuration-dependent cases | Keep genuine external dependencies; do not call operator-controlled input safe by default. |

The known Podman CVE-2024-37298 and Kubernetes CVE-2022-41717 false alarms remain benchmark errors, not successes to be legitimized by broader positive scoping.

Report separately:

- definitive answers and their correctness;
- external-dependency outcomes;
- analysis/scope failures;
- false-safe and false-positive results.

Moving tool limitations out of `INCONCLUSIVE` must **not** be presented as increased successful completion.

---

## 7. Required tests

### Policy and terminal outcomes

1. Every code-owned unresolved obligation yields `FAILED`, never terminal environmental `INCONCLUSIVE`.
2. A genuine external dependency produces a concrete, evidence-bound missing fact.
3. Mixed external and code/proof blockers remain failure until the relevant code work is complete.
4. Irrelevant supporting unknowns do not block a sufficient proof.
5. Budget, timeout, skipped-package, missing-sidecar, pending-review and failed-verification cases preserve `UNKNOWN` claims without fabricating verdicts.

### Discovery and attribution

6. Inverse `related(CVE)` discovers gRPC without an outgoing primary link.
7. Relatedness never enters alias enrichment or transitive identity closure.
8. Bare related/title/reference hints cannot lift a positive.
9. Captured publisher CVE attribution admits only the bound record, implementation and mechanism.
10. Wrong digests, conflicting records, ambiguous bundled mechanisms and unavailable attribution fail explicitly.

### Isolation and safety gates

11. Fixed x/net cannot affect gRPC range arithmetic; test every gRPC interval and fixed boundary.
12. No record receives another record’s ranges, symbols, claims, severity or completeness.
13. Shared-CVE govulncheck metadata cannot fabricate candidate coverage.
14. Preserve `RecordExtent`/inventory, target provenance, measurement completion, negative verification, unresolved-subject and review controls.
15. Preserve all library-API positive and non-admission controls, especially RESOURCE_EXHAUSTION and AUTH_BYPASS near misses.

### Worked positive and negative controls

16. Rooted kubelet `NewServer → Serve → affected transport → Rapid Reset mechanism` yields the expected candidate and composed positive.
17. Import-only, dial-only, constructor-never-served, test-only and unrooted-staging controls do not qualify.
18. A handler-level interceptor is not mistaken for a pre-dispatch quota; a genuinely effective mechanism control prevents the positive.
19. Unix/loopback exposure does not imply trusted peers or Internet exposure.
20. Missing deployed socket-access facts produce only the separate legitimate environmental dependency.

### Composition and publication

21. Lift positives only within the same profile/build scope; never combine partial witnesses.
22. A sufficient positive survives unrelated candidate failures.
23. All-negative candidates cannot close a CVE; exact full-record negative controls still work.
24. Persist/replay/re-admit attribution, record pins, qualified evidence references and outcome classification.
25. Every output agrees on requested identity, proof origin, scope, failure versus external dependency, and witness-specific remediation.
26. Frozen `code_not_present`, `code_not_reachable`, configuration and exploitable labels remain unchanged.

## Handoff contract

Implement the proof-completion policy, not a verdict-forcing fallback. Preserve every existing safety gate. Any inability to bind a candidate’s exact record, source, subjects, mechanism or build must remain ineligible and become a named failure where decision-relevant.

The policy/docs cutover must update the governing specification, `AGENTS.md`, architecture/how-it-works/CLI documentation, gap analysis and evaluation documentation: their current descriptions explicitly permit tool-limited terminal `INCONCLUSIVE`, which this requirement supersedes.

**Read-only investigation completed. No repository changes, builds, tests or analyzer reruns were performed.**

---

## Addendum A — operator decision (2026-10-26)

The design left one policy choice open: whether a fully enumerated, pinned advisory
corpus may serve as the completeness basis for a **CVE-wide** negative.

**Decision: yes.**

A CVE request may reach `NOT_AFFECTED` when **all** of the following hold:

1. discovery ran against an explicitly configured, digest-pinned corpus and its
   enumeration finished (`finished`, not `partial`/`unavailable`/`not_configured`);
2. every nominated candidate record was assessed independently;
3. no candidate is independently `EXPLOITABLE` for the request's profile;
4. no candidate raised an unresolved attribution that could change the answer;
5. the result states the corpus boundary verbatim: which corpus, its digest, its
   capture date, and that implementations outside it were not examined.

`Kind=CVE` remains non-closing **by enumeration alone**; it closes only through this
declared completeness basis. A missing, partial or unenumerated corpus yields
`FAILED / UNSUPPORTED_NEGATIVE_SCOPE`, never `NOT_AFFECTED`.

This supersedes the design section "A hard boundary: no CVE-wide negative closure
under these constraints" — the boundary is unchanged for undeclared corpora and is
now defined for declared ones.

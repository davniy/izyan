# DESIGN_FOR_REVIEW — Related-record discovery with positive-only composition

**Design gate: READY.** No user-owned policy question is necessary.

## Decision

Add a **discovery layer and isolated per-record assessments**, followed by **positive-only composition for CVE requests**.

Keep three propositions distinct:

1. **Discovery:** record R may be relevant to the requested CVE.
2. **Attribution:** the defect proved in R is an implementation covered by that CVE.
3. **Product proof:** R independently establishes applicability and all mandatory exploit conditions in the analyzed product.

`related` can establish **(1), not (2) or (3)**. This distinction matters because the [OSV schema explicitly permits `related` to mean “a similar but completely different vulnerability”](https://ossf.github.io/osv-schema/#related-field); the relationship is symmetric, not transitive.

A CVE-requested finding may become `EXPLOITABLE` through R **only when both attribution and R’s own product proof are admitted**. An exact-advisory-requested finding must retain its original record result; R’s positive is a separate finding.

No candidate negative contributes to closing the original request.

---

## 1. Existing architecture and the consequential traps

The relevant code supports this design without changing the safety gates:

- `internal/vulnerability/osv.go:17-29` does not decode `related`.
- `internal/vulnerability/source.go:211-269` enriches records from aliases, including copying symbols, ranges and modules. **This is not an admissible candidate-loading path.**
- `internal/domain/advisory_scope.go:182-215` requires an exact identity, `ADVISORY_ENTRIES/COMPLETE`, `FULL_RECORD`, and a valid fully represented census for negative closure. Leave that predicate unchanged.
- `internal/evaluator/verdict.go:110-118` rejects a scope-insufficient affected negative before reaching exploit evaluation. Therefore combining gRPC facts into the primary x/net assessment would either remain blocked or require weakening the gate. Neither is acceptable.
- Reports currently assume one resolved record: OpenVEX uses `c.Vulnerability.ID` at `internal/report/openvex.go:63-64`; CycloneDX does likewise. Candidate composition requires an explicit request-level result, not relabeling that record.
- `internal/advfeed` already provides local directory/ZIP ingestion and dump provenance, but indexes only IDs and aliases. Reuse its acquisition/index infrastructure—not its `ResolveImports` subject-merging operation.
- Product B’s `internal/productb/refindex/advisory.go` already collects alias/related “families.” That is discovery material, **not a proof or equivalence contract** to import into the authoritative analyzer.

---

## 2. Discovery rule

### 2.1 Discovery universe

Use an **explicitly configured, frozen OSV corpus**:

- Local directory or ZIP, through the existing advisory-feed mechanism.
- An explicitly configured remote dump may be acquired through the existing feed acquisition path, then pinned before discovery.
- Include the requested document and other documents explicitly supplied to intake.
- Do not silently scan parent directories, other worktrees, benchmark artifacts, or arbitrary caches.

Expose the same feed configuration to authoritative analysis rather than creating another corpus-source convention.

With no configured corpus, discovery is limited to the supplied intake documents. Report that limitation. Do not imply that a single-record API lookup searched for all implementations.

This choice is important for the motivating case: `GO-2023-2153` points **toward** the CVE in `related`; the requested GHSA need not point back toward gRPC. Following only the requested document’s outgoing links will miss it.

### 2.2 Separate relationship indexes

Decode and retain `Related []string` separately from `Aliases`, in both the authoritative OSV model and corpus metadata.

Maintain distinct lookups:

```text
record ID      → document references
alias ID       → document references
related ID     → document references
```

A document reference includes its record ID, raw SHA-256, source locator and modified timestamp. Never insert related IDs into the alias index used for enrichment or identity resolution.

Retain compact metadata and stable source locators; load complete candidate documents lazily and verify their indexed digest.

### 2.3 Candidate selection

For a **CVE request C**, nominate:

1. Every corpus record whose own ID or aliases name C.
2. Every corpus record whose `related` directly names C.
3. Direct alias and related neighbors of the primary record, including incoming related links available in the corpus.

For an **exact advisory request**, obtain CVE search seeds from the primary document’s explicit CVE identifiers in its ID, aliases and related fields. Preserve which field supplied each seed. If there are several, retain separate CVE associations; do not choose the first.

Alias lookups may nominate another record, but never supply that record’s ranges or subjects. Do not construct an alias-plus-related connected component and call it “the CVE.” In particular:

- No transitive closure of `related`.
- A related edge between R and S does not transfer either record’s CVE associations to the other.
- Text mentions, shared titles, CWEs, severity or fix URLs do not independently establish identity.

The inverse `related(C)` lookup discovers `GO-2023-2153` even though it is not a CVE alias.

### 2.4 Ambiguity and failure

- Identical record ID and digest: deduplicate the assessment, retaining all discovery edges.
- Same record ID with different bytes in the configured snapshot: mark that candidate ambiguous unless an explicit source pin selects one. Do not silently choose by filename, first occurrence or `modified`.
- Different records sharing a CVE but declaring different ranges/symbols: **not an ambiguity to merge away**. Evaluate each separately.
- Non-Go records, unsupported entries, missing documents and unreadable records remain visible as unsupported or unresolved candidates—not absent vulnerabilities.
- Deterministically prioritize candidates whose declared modules occur in the product graph. Unknown graph membership must not discard a candidate.
- Charge candidate work against the request’s overall deadline and tool budgets. Do not give every candidate a fresh unbounded allowance.

Discovery records enumeration and execution separately:

```text
source manifest/digest
enumeration: finished | partial | unavailable | not_configured
candidate dispositions: evaluated | unsupported | ambiguous | load_failed |
                        timed_out | not_evaluated
```

“Enumeration finished” means **finished for these pinned sources**, never CVE-wide completeness.

---

## 3. Establishing “same CVE”: an attribution gate

A direct `related: [CVE-C]` entry is sufficient to **investigate**, but insufficient to assert that an independently proved defect answers CVE-C.

Admit CVE attribution through either:

1. **An explicit CVE identity assertion in the candidate’s own record**—its ID or aliases names C, with no unresolved ambiguity about which proved mechanism/entry the assertion covers; or
2. **A pinned publisher/CNA attribution** explicitly identifying C and the candidate’s implementation/advisory, tied to the proved affected entry or mechanism.

Store a typed attribution record:

```text
CVE ID
candidate record ID + document digest
covered affected-entry/mechanism references
basis: own_id | own_alias | publisher | CNA
source URI + captured-source digest + exact identifying field/quote
admission: admitted | related_only | ambiguous
```

For publisher/CNA material, validate the binding to the candidate’s advisory identity and implementation—for example, its publisher advisory ID, upstream repository/module and fix reference. A free-text CVE occurrence, an NVD link, an LLM assertion or a user-entered mapping without supporting source material is not enough.

If a document bundles several CVEs or mechanisms and the proved path cannot be assigned to C, retain the candidate’s record-level positive but refuse the CVE lift.

### Why this is workable for gRPC

The [publisher’s gRPC advisory](https://github.com/grpc/grpc-go/security/advisories/GHSA-m425-mq94-257g) explicitly shows **CVE-2023-44487**, names `google.golang.org/grpc`, and identifies the relevant patch. The GO record aliases that publisher advisory.

The [global GitHub advisory page](https://github.com/advisories/GHSA-m425-mq94-257g) currently says “No known CVE,” despite referencing the CVE. Missing aggregate metadata is not an explicit publisher refutation. Preserve that discrepancy and capture the publisher attribution; do not manufacture a CVE alias in the GO record.

**With only the OSV `related` edge available, the analyzer may report a proven gRPC advisory positive, but must leave the CVE attribution unresolved.**

---

## 4. Per-candidate evaluation

### 4.1 Exact intake, isolated assessment

Load R **by its own ID and exact bytes**, not by asking `FileSource.Get` to accept C as a related pseudo-alias.

Candidate intake must disable:

- Alias-based symbol/range/module enrichment.
- Feed-based subject completion from other records.
- Reuse of the primary record’s normalized vulnerability.

Use the existing parser and single-record pipeline. The parser creates R’s own original census before filtering or module merging; bind the child assessment to R’s exact identity.

The child owns its:

- Vulnerability and affected result.
- Record extent and inventory.
- Root-cause and exploit models.
- Claims, reviews and verification records.
- Evidence graph, verdicts, profiles and risk assessment.

Candidate discovery must not recursively launch further candidate discovery.

### 4.2 What must be proved independently

| Obligation | Required basis |
|---|---|
| Module presence and ownership | R’s declared module against the analyzed product graph |
| Version affectedness | The resolved version against **R’s own ranges**, including disjoint intervals and replacement/release provenance |
| Package presence | R’s own package subjects and the recorded product build |
| Build relevance | R’s own platform restrictions and the effective build context |
| Defect/sink binding | R’s declared subjects or the existing independently verified root-cause/locus route |
| Reachability and input conditions | Measurements and source proofs bound to R’s exact subjects |
| Exploitability | R’s complete mandatory-condition conjunction, including existing unresolved-subject and review rules |

For lifting a positive, require explicit applicable module/version/package/build facts for the proved subject, an admitted attribution, and `EXPLOITABLE` from the existing evaluator. Module presence plus an affected version is not a positive verdict.

A positive need not require `FULL_RECORD`: completeness gates universal negatives, not an established vulnerable path. But the particular entry supporting the positive must have supported, traceable declarations. Do not turn an omitted/unsupported entry into positive authority, or bypass the evaluator’s current unresolved-subject rules.

### 4.3 What may be shared—and what may not

Share immutable **product measurements**, not advisory conclusions:

- The same product snapshot, module inventory and source index.
- A completed package inventory.
- A completed raw govulncheck stream, when its build identity matches.

For every candidate, derive the result again against that candidate’s subjects. Reuse does not mean copying the primary `AffectedResult`, claims or coverage.

In particular, the current govulncheck helpers union some metadata under aliases (`internal/goanalysis/govulncheck.go:490-545`). A common CVE key must not authorize coverage or subjects from another record. Candidate projections must retain the emitting record and bind traces to the candidate’s own module/package/symbols. Do not re-stamp the primary measurement’s advisory coverage as R’s.

Never inherit:

- Ranges, fixed versions or package/symbol declarations.
- Root-cause necessity decisions or exploit conditions.
- Claims, falsifiers, `VERIFIED` status or review acceptance.
- Severity, remediation or contextual risk.
- Completeness or closure authority.

Record-specific manual proposals also require record-specific admission. Do not apply the primary record’s expert inputs to all candidates.

---

## 5. Verdict and composition rule

Let:

- \(P\) be the existing, scope-admitted primary assessment.
- \(A(R,C)\) mean attribution of R’s proved implementation to C is admitted.
- \(E(R,p)\) mean R independently proves `EXPLOITABLE` under profile/build scope \(p\).

Then:

### CVE-requested finding

\[
V(C,p)=
\begin{cases}
\texttt{EXPLOITABLE}, &
\exists R:\ A(R,C)\land E(R,p)\\
\texttt{INCONCLUSIVE}, & \text{otherwise}
\end{cases}
\]

The primary record can itself supply that witness. It receives no exemption from the attribution and proof requirements.

### Exact-advisory-requested finding

\[
V(Q,p)=P(Q,p)
\]

Related candidates never replace Q’s result.

| Situation | CVE request | Exact advisory request |
|---|---|---|
| Attributed candidate independently proves positive | `EXPLOITABLE`, explicitly via R | Primary verdict unchanged; separate R positive |
| Candidate positive, attribution only `related` | `INCONCLUSIVE`; show R positive separately | Primary unchanged |
| Every candidate is negative | `INCONCLUSIVE` | Primary unchanged |
| No candidates, incomplete discovery, timeout, unsupported records | `INCONCLUSIVE` absent another admitted positive | Primary unchanged |
| One admitted positive; other candidates unresolved/negative | Positive survives | Primary unchanged |

Composition is per profile. A zero-trust positive does not automatically establish a cluster-perimeter positive. Preserve each witness’s build target, assumptions, `library-api` boundary and limitations.

**No candidate negative can produce CVE-level `NOT_AFFECTED` or NEPF.** Candidate-local negatives may remain valid about R itself under the unchanged gates, but are never aggregated into request safety.

---

## 6. Data flow, persistence and scope presentation

Add explicit discovery/evaluation/composition stages around the existing single-record pipeline:

```text
Snapshot / primary intake
    → Discover related records
    → Existing primary assessment
    → Evaluate isolated candidate records
    → Compose requested finding
    → Build reports/exports
```

A primary early affected-negative transition must still reach composition before publication. For a CVE request, failure to find a direct/alias primary record must not prevent evaluation of available related candidates; retain the primary intake failure explicitly. An exact-record resolution failure must never be “repaired” by substituting a related record.

### Persisted representation

Use an explicit new case-result schema discriminator and add:

- `requested_finding`: the sole authoritative answer to the caller’s request.
- `related_discovery`: pinned universe, enumeration outcome and limitations.
- `related_records`: independent child assessments and their discovery/attribution records.

For new-schema cases, require `requested_finding` for **every** request, including exact requests and CVE documents whose requested and resolved IDs happen to be equal. Do not infer request kind from inequality of those IDs.

Keep the existing primary fields unchanged by candidate composition. Their verdict remains the primary branch’s assessment; public consumers read the explicitly named requested finding. Exact requests mechanically compose to that unchanged primary result.

Each positive origin must resolve to:

```text
record ID + document digest + original entry references
child assessment/result reference
CVE attribution reference, when lifting to a CVE
build/profile binding
supporting claim/evidence references
```

Use qualified references—assessment ID plus local evidence/condition ID—so two children’s `C-REACH` or `EV-AFFECTED-MODULES` cannot collide.

### Scope fields

- Primary `RecordExtent`, `RecordInventory`, `Kind` and `Coverage` remain unchanged.
- Every child shows its own fields.
- The CVE-level requested finding remains `coverage=KNOWN_ONLY`.
- There is **no aggregate `RecordExtent` or synthetic inventory**. Those describe documents, not a union of discoveries.
- Do not enlarge the requested document’s census from 22 to 23 by appending gRPC.

Legacy cases retain their existing single-assessment interpretation and pass current admission. Loading an old case must not invent discovery, attribution or candidate positives. A new-schema case missing its required composition data is invalid, not silently legacy.

Publication must use one shared projection: re-admit primary and child proofs, validate attribution/references/build bindings, then compose. Renderers must not independently trust a saved composed positive while ignoring missing child proof artifacts.

---

## 7. Worked Rapid Reset case

### Unchanged primary assessment

For `GHSA-qppj-fm5r-hxr3`:

```text
Original entries: 22
Represented:       1 Go entry — golang.org/x/net
Omitted:          21 — Maven 20, SwiftURL 1
Record extent:    GO_PROJECTION
Coverage:         KNOWN_ONLY
Resolved version: v0.17.0
Version affected: FALSE
Package/build:    UNKNOWN
Primary verdict:  INCONCLUSIVE
```

Discovery finds `GO-2023-2153` through the corpus’s inverse `related(CVE-2023-44487)` index.

### Independent candidate assessment

Use only that GO record’s gRPC ranges and subjects:

```text
module: google.golang.org/grpc
version: v1.55.0

affected intervals:
  [0, 1.56.3)
  [1.57.0, 1.57.1)
  [1.58.0, 1.58.3)
```

Its own symbol set includes `Server.Serve`, `NewServer`, `Server.initServerWorkers` and `internal/transport.NewServerTransport`.

**The supplied verified run establishes module/version/package presence, not a final exploit proof.** Imports from product code corroborate linkage, but do not alone establish server exposure, attacker control or the complete trigger conditions. The timeout therefore must not become `EXPLOITABLE`.

| Available evidence | Exact GHSA request | CVE request |
|---|---|---|
| Supplied measurements; exploit proof unfinished | `INCONCLUSIVE` | `INCONCLUSIVE`, with applicable gRPC candidate highlighted |
| Candidate later proves all mandatory conditions; publisher attribution admitted | Still `INCONCLUSIVE` | `EXPLOITABLE — proven via GO-2023-2153` |
| Candidate proves positive; only bare `related` attribution available | Still `INCONCLUSIVE`; separate GO positive | `INCONCLUSIVE` for CVE attribution; separate GO positive |

This is positive recovery without rewriting what the requested GHSA declares.

---

## 8. Reports and exports

### Human and JSON surfaces

Show, in this order:

1. Requested identity and requested-finding verdict.
2. Proof origin: **“proven in the primary record”** or **“proven via related record R.”**
3. Unchanged primary assessment, including extent/census.
4. Candidate table: discovery relationship, attribution status, applicability, verdict and unfinished obligations.
5. Discovery limitations.

Risk and remediation remain record-bound. A gRPC positive must not display x/net’s fixed version or borrow the primary record’s severity. Show candidate risk/remediation separately; any request-level priority summary must identify the candidate assessments it summarizes.

Migrate CLI, scan/eval result extraction, tracker rationale, justification and remediation consumers to the same requested-finding projection.

### OpenVEX and CycloneDX

Emit separate identities, never one relabeled statement:

- Primary record statement: unchanged admitted result.
- Candidate R statement: independently established result.
- Requested CVE statement: `affected`/CycloneDX `exploitable` only after the composition gate; otherwise `under_investigation`/`in_triage`.

For the motivating positive-recovery outcome, the GHSA statement remains under investigation while the GO record and attributed CVE statements can be affected.

Include proof record ID/digest, attribution source and scope in schema-supported statement/detail text, with structured references in the companion JSON report. Do not add invalid custom OpenVEX fields or export a related identifier as an alias. The CVE statement’s affected subcomponent must come from its actual witness—not the primary x/net fields.

The research lane needs an explicit contract extension for request composition. Its record-bound `decision-artifact.advisory_binding` and existing `CVE_WIDE/COMPLETE` validation must not be repurposed to imply completeness.

---

## 9. Blast radius and calibration

### Expected behavioral changes

- CVE-requested `INCONCLUSIVE` cases may become `EXPLOITABLE` after independent candidate proof **and** attribution.
- Exact-advisory verdicts must not change because of candidate discovery.
- No request becomes newly `NOT_AFFECTED` or NEPF.
- Reports can become actionable without changing the requested exact-record verdict: a separate vulnerable related record is still valuable output.
- Runtime grows with relevant candidate count; shared immutable build measurements and cheap per-record applicability checks limit repeated work.

### Calibration risk

The repository’s two main corpora use exact GO/GHSA requests, while VEX-Bench and associated experiments use CVE-scoped questions and labels. Keep those populations separate.

Required calibration rules:

- Record requested ID/kind, primary ID/digest, corpus digest, candidate IDs, attribution outcomes and positive origins.
- Score the **requested-finding** verdict, not whichever record happened to be selected first.
- Do not score an exact-GHSA answer against CVE-wide ground truth.
- Preserve frozen labels and inputs. Investigate newly proven positives against negative CVE labels; do not relabel them merely to improve agreement.
- Measure false positives as well as false-safe. Positive-only composition prevents new safe claims, but does not by itself prevent overclaimed positives.
- Keep existing scope/target/measurement controls, including fully represented Go-only exact-record negatives.

No benchmark outcome is claimed by this design.

### Detection limits

This feature cannot detect, by itself:

- CVE implementations with no OSV record.
- Records absent from the configured corpus snapshot.
- Records lacking a discoverable identifier relationship.
- Unsupported ecosystems or unsupported applicability declarations.
- Candidate defects whose reachability/trigger proof the existing analyzer cannot complete.
- CVE attribution unavailable beyond a weak related/reference hint.

Even a completely enumerated local dump cannot prove those surfaces absent.

---

## 10. Required tests

### Discovery and attribution

1. Parse `related` separately; it never appears in aliases or alias enrichment.
2. Discover gRPC through inverse `related(CVE)` when the primary has no outgoing gRPC link.
3. Related A–B–C does not establish A–C membership.
4. Multiple CVE seeds remain separate; bundled ambiguous mechanisms cannot be arbitrarily assigned.
5. Identical duplicates deduplicate; conflicting same-ID documents remain ambiguous.
6. Missing/partial corpus and absent candidates never authorize safety.
7. Bare `related`, a CVE URL or title similarity cannot admit CVE attribution.
8. Publisher attribution admits only the pinned candidate/entry; wrong digest, advisory, implementation or explicit contradictory attribution refuses the lift.

### Independent evaluation

9. Primary fixed x/net facts do not affect gRPC’s range result.
10. Test all three gRPC intervals and their fixed boundaries.
11. No candidate ranges/symbols are filled from aliases or feed imports.
12. A shared-CVE govulncheck record cannot fabricate candidate subject coverage.
13. Candidate evidence IDs and condition IDs cannot resolve into another assessment.
14. Unknown version, unsupported entry, failed measurement, narrowed scope and timeout remain unknown where required.
15. Existing target, measurement, negative-verification, review and library-boundary admission tests apply to children unchanged.

### Composition and publication

16. Attributed, fully proved candidate positive lifts a CVE request only.
17. Presence/version/package facts alone do not lift it.
18. Exact-request result remains byte-for-byte unchanged by candidate composition.
19. Candidate negatives, including a complete all-negative set, never close a CVE request.
20. A positive survives unrelated candidate failure; profiles/build scopes do not cross.
21. Persistence/restart/replay preserve all record and attribution pins; legacy load invents none.
22. Missing or tampered positive-origin artifacts cannot publish a composed positive.
23. JSON, RU/EN Markdown, CLI, tracker, OpenVEX, CycloneDX and research output agree on identities and proof origin.
24. Exported gRPC remediation/subcomponent cannot come from x/net.
25. Retain the current 22/1/21 primary scope regression. Add a separate synthetic end-to-end positive fixture; do not assert the timed-out Kubernetes run proved exploitability.
26. Calibration tests distinguish exact-record and CVE labels and consume the requested-finding result.

---

## Design-risk disposition and handoff

| Priority | Risk | Disposition |
|---|---|---|
| P0 | Relatedness mistaken for CVE membership | Closed by separate attribution admission |
| P0 | Facts or closure authority cross records | Closed by isolated assessments and positive-only composition |
| P1 | Local discovery mistaken for exhaustiveness | Bounded permanently by source manifest and `KNOWN_ONLY`; no negative composition |
| P1 | Large-repository candidate work does not finish | Bounded by aggregate budgets; explicit unfinished outcomes, no fabricated proof |

**Implementation contract:** preserve the existing gates and primary census; reuse the current single-record evaluator rather than building a second exploitability evaluator. If implementation reveals that a proposed shared measurement or attribution source cannot bind the candidate’s exact subject/build, keep it ineligible and return that boundary for design review rather than weakening admission.

*Read-only investigation completed. No repository changes, analyzer reruns or verification checks were performed.*

**Status: PROPOSED — the follow-up work stream opened after
`CAPABILITY_GAP_RECORDED` in `docs/dev/plans/2026-10-14-03-autonomous-evidence-slice-plan.md`
(amendments R1/R2). Derived from the architect ruling `CapabilityGapRuling`
(same read-only session); the design text is the architect's, not the
controller's.**

Date: 2026-10-15. Predecessor: the closed slice above (Tasks 1–9) and its
ledger `.superpowers/sdd/2026-10-14-03-autonomous-evidence-slice-plan/progress.md`.

## Amendment R3 — 2026-10-15, after the closure-semantics ruling

Source: OMP `architect` ruling `ClosureSemanticsRuling`. Two empirical findings
forced it: (1) **C02's historical premise is false** — `github.com/docker/docker`
is transitively product-linked via non-test product packages
(`components/{amqp,amqp09,kafka}/test-helpers`, `pkg/service/integration`
→ `testcontainers-go` → `docker/docker`), so a package-absence negative on that
subject would have been false-safe; (2) `moby/moby{,/v2}` are determinably
absent under vendor mode but the contract classifies absent-from-both as
`unknown`, so no verified-absence marker exists for them.

Rulings applied here:

1. **Product-root semantics stay `product_all_packages`** (every applicable
   first-party directory matched by `./...`). B41 is not narrowed to a shipped
   binary; no second binary-root interpretation is introduced.
2. **Determinable vendor-inventory absence becomes provable**, narrowly: a new
   marker `product_absence_verification="VERIFIED_VENDOR_INVENTORY"` valid only
   with `usage_scope="unknown"`, `product_linked=false`, `test_linked=false`,
   `closure_source="vendor/modules.txt+source-imports"`,
   `closure_semantics="product_all_packages"`, `vendor_mode=true` and a
   complete consistency-checked vendor inventory proving exact
   advisory-subject absence. `VERIFIED` stays reserved for `test-only`.
3. **C02 is re-roled**: closure-reconciliation control and falsifier of its own
   historical triage premise; it MUST NOT be promoted to a package-absence
   negative while its Docker subject is `mixed`, and MUST NOT receive the live
   model call to confirm an unreachable path.
4. **A deterministic candidate search gate precedes any live turn.** A
   candidate qualifies only if every advisory subject has exact identity and a
   reachable accepted route, at least one subject is `test-only`+`VERIFIED` or
   `unknown`+`VERIFIED_VENDOR_INVENTORY`, no subject is `product`/`mixed` for
   the asserted route, all remaining subjects are covered by an accepted marker
   or deterministic applicability resolution, no agent-selected package
   substitutes for a module-only subject, all evidence is `OK+COMPLETE`,
   request-bound, digest-resolved and limitation-free, and the candidate is not
   C01 (B48, fail-closed). If nothing qualifies: no live call, record
   `CAPABILITY_GAP_RECORDED` with the frozen search inputs and per-candidate
   reasons.

Changes applied to this file: goal reworded (a selected candidate, not C02);
new Task 2b (marker contract + gate + validator change); Task 3 rewritten as the
selected-candidate live turn with the preflight requirement; Task 3 acceptance
replaced.

## Amendment R4 — 2026-10-15, roadmap to raise the verified acceptance rate

Source: OMP `architect` ruling `AcceptanceRoadmapRuling`, issued after the
owner's verdict: the primary goal (removing human triage work) is not solved
and the verified acceptance rate is insufficient. Measured demand (85 corporate
rejections; 19 have no snapshot → data cap 66/85 = 77.6%): `other` 38,
`component_absent_or_unreachable` 15, `exploitation_conditions_not_met` 14,
`code_unreachable_test_only` 7, `compensating_control_trusted_peer` 5,
`not_applicable_environment` 3, `compensating_control_tls_config` 2,
`component_absent_or_not_delivered` 1. Current verified automation rate:
**0/66**.

Rulings applied here:

1. **B49 mechanism = (a) prompt-level enforcement in a new pinned revision**
   `eval/agent7/prompts/r0-v4.txt`. The controller MUST NOT synthesize a typed
   proposal from `reasoning`, `assessment`, tool history or inference.
   Provider-side structured output is out of scope unless a synthetic test
   proves support in the exact pinned E6 adapter/opencode/provider path.
2. **Next proof family = package-level build closure / test-only detail**
   (best verified-yield per effort; builds on the existing B41 substrate; does
   not require runtime semantics). The real bottleneck is positive `mixed`
   linkage, not missing markers: 45/49 candidates failed the marker criterion
   and only C09 was eligible.
3. **`reason_class=other` is a demand signal, not a selector.** Classify those
   38 findings by a deterministic preflight matrix, never by human relabeling.
4. **Metric:** `verified_automation_rate = V / 66`, where `V` counts only
   ticket-level findings with a terminal deterministic negative that passed
   every existing gate (advisory-wide coverage, complete trace, matching
   snapshot/build context, resolving digest refs, empty limitations,
   `AutoClose=false`). `INCONCLUSIVE`, errors, invalid format and the 19
   no-snapshot findings are reported separately; with `V=0` the false-safe rate
   is reported as `FS=0, V=0`, never as "0%".

### Task 2.6: B49 — mandatory agent-emitted verification plan

Decision: prompt-level enforcement in the pinned `eval/agent7/prompts/r0-v4.txt`.
Do not synthesize a typed proposal from reasoning, assessment, tool history or
controller-side extraction.

Acceptance:
- `r0-v4.txt` is immutable and hash-pinned; older revisions stay frozen for replay;
- a C09 live output contains an **agent-emitted** plan covering both module-only advisory subjects at module granularity;
- the plan executes only bounded permitted tools;
- the terminal negative requires the existing advisory-wide coverage, trace-integrity, digest, build-context and empty-limitations gates;
- one replay reproduces the result without a model call;
- a missing plan, malformed plan, wrong subject granularity or an omitted second advisory subject all remain non-terminal.

### Task 4: Package-level build-closure and test-only yield expansion

Build on B41 without changing `product_all_packages` semantics. Run a
deterministic census over every snapshot-available finding and classify the
exact advisory-declared package/module subjects using paired product/test
closures, vendor-inventory absence where valid, exact identity, advisory-wide
subject coverage and positive-linkage contradiction checks. Do not use human
`reason_class`, historical decisions, direct-import counts or agent prose as
proof.

Acceptance:
- every candidate has a per-subject preflight result;
- `test-only` is emitted only with complete paired closures and `VERIFIED`;
- `unknown` is negative-capable only with a valid `VERIFIED_VENDOR_INVENTORY`;
- `mixed`/`product` subjects block an absence route;
- module-only advisory entries never receive manufactured package paths;
- the rate is reported as `V/66` with `INCONCLUSIVE` and data-capped findings separate.

### Roadmap (planning estimates only)

```text
[INFERENCE] Planning estimates only. They are not observed acceptance results
and must be replaced by per-family preflight measurements before claiming coverage.
```

| Order | Proof family | Demand ceiling | Expected incremental verified yield | Effort / risk |
|---|---|---|---|---|
| 0 | B49 plan compliance (prerequisite) | C09 → 1/66 | 1–3/66 = 1.5–4.5% | S / low |
| 1 | Package-level build closure + test-only | ≤18/66 = 27.3% | 4–8/66 = 6.1–12.1% | S–M / low–medium |
| 2 | Version / environment applicability | 2/66 = 3.0% | 2–4/66 = 3.0–6.1% | S / low |
| 3 | TLS-config | 2/66 = 3.0% | 1–2/66 = 1.5–3.0% | S–M / medium |
| 4 | Exploitation-condition / input-bound | 10/66 = 15.2% | 3–6/66 = 4.5–9.1% | L / high until B48 |
| 5 | Configuration-origin | subset of the above | 3–6/66 = 4.5–9.1% | L / medium–high |
| 6 | Trusted perimeter / deployment | 3/66 = 4.5% | 1–3/66 = 1.5–4.5% | L / high (snapshot-vs-deployed drift) |

Public corporate metrics (kept separate from the 38-case corpus metrics):

```text
Corporate snapshot-conditioned metrics:
- N_all = 85 findings; N_snapshot = 66; N_no_snapshot = 19;
- verified_automation_rate = terminal_verified_negative / 66;
- inconclusive_rate = INCONCLUSIVE / 66;
- false_safe_count must equal 0 (reported as FS=0, V=0 when V=0);
- errors, invalid format and no-snapshot findings are reported separately.

A terminal negative counts only when the deterministic verifier establishes the
required advisory-wide scope, complete trace, matching snapshot/build context,
resolving evidence references and empty operational limitations. Agent category,
prose agreement and historical human disposition do not count.
```

## Amendment R5 — 2026-10-15, target verdict doctrine after the owner's objection

Source: OMP `architect` ruling `VerdictDoctrineRethink`, requested after the
owner's objection that 38.9% is "a bad tool" (a raw agent scores ~10/10 on
VEX-Bench; the old master-line engine produced 100% verdicts on the corporate
rejects) and that per-family tuning will never cover all CVEs.

**Decision: do not add another proof family and do not adopt agent-authored
verdicts. Move to agent-led, evidence-contract-based, independently verified,
tiered triage.**

| Tier | Name | Semantics |
|---|---|---|
| T0 | `VERIFIED_NEGATIVE` (`NOT_AFFECTED` / `NO_EXPLOIT_PATH_FOUND`) | machine-safe terminal result; existing gates unchanged (advisory-wide subjects, typed falsifier, executed bounded checks, digest-bound resolvable refs, matching snapshot/build scope, no positive contradiction, `COMPLETE` coverage, empty limitations) |
| T1 | `EVIDENCE_BACKED_NEGATIVE` / review-ready packet | **not a safe verdict, not auto-closeable, excluded from the verified numerator**; shows machine-verified facts, agent-asserted assumptions, the one unverified condition, why it matters, contradiction-search state and the next smallest decisive check |
| T2 | `INCONCLUSIVE` | honest abstention, but now *specific*: which subject/condition/check is missing and what minimal artifact would continue |

**General mechanism (no per-CVE branches):** a generic typed contract —
`Condition {id, statement, role, subject_refs, required, polarity}`,
`EvidenceClaim {proposition, subject, scope, source/tool, evidence_refs,
coverage, limitations, status}`, `Falsifier {condition_id,
negated_proposition, advisory_subjects, required_checks, assumptions}`. The
existing `FalsifierKind` list is re-scoped to a compatibility vocabulary, not
an architectural boundary. Tools keep checking generic primitives (module/
version identity, product/test closure, package/symbol reachability, call
references, data origin, configuration source, build tags, deployment
manifests, protocol/environment facts). An unsupported predicate yields
`UNKNOWN`/T1 — never a new CVE-specific branch. The deterministic layer acts as
an independent critic **with veto**, not as the only source of verdicts.

**Invariants:** none weakened. Specifically preserved: absence of a found path
proves nothing; `FALSE` requires a falsifier plus successful negative
verification; `NO_EXPLOIT_PATH_FOUND` only for a verified falsifier on a
mandatory condition; `NOT_AFFECTED` only from the deterministic affected chain;
`UNKNOWN` stays a valid terminal result; deterministic checks remain
authoritative over the LLM; `VERIFIED` stays scope-bound and demotable;
`REVIEW_REQUIRED`/`AutoClose=false` stay in force for the rollout.

**Expected effect (honest):** T0 stays at the measured `7/18` on the corporate
subset; the measured cross-tab union of agent-claim and machine-proof is
`13/18 ≈ 72%`, so T1 is where the removed human work comes from — as a
**review-ready packet with a decision already prepared**, not as a safe label.
Reported rates must always split T0/T1/T2; the verified automation rate stays
`V/66` with no-snapshot findings and errors reported separately.

**Flagged for a later owner decision (not needed now):** whether
`EVIDENCE_BACKED_NEGATIVE` may ever be auto-closed without human confirmation.
Architect recommendation: **no**, until a blind measurement of human acceptance
shows its false-safe risk is far from the plain-agent `1/7`. If operators accept
T1 as safe in bulk, the conservative risk estimate reverts to that `1/7`.

**Measurement plan:** T0/T1/T2 counted separately on all 66 snapshot-conditioned
findings; VEX-Bench blind repeats with the same split (false-safe only for T0);
human-time metrics (median minutes to disposition, re-read rate, T1 acceptance
after checking only the listed assumptions, T1 returns due to hidden
contradictions); generality split held out by CVE mechanism, repository and
reason class.

## Amendment R6 — 2026-10-15, decision-ready dispositions (supersedes R5's human contract)

Source: OMP `architect` ruling `HumanMinimalDecisionModel`, requested after
the owner rejected R5: tiering changes the *status* but not the *volume of
human work*; the artifact must let the human only accept/reject, must carry
facts + justification + a proposed decision, must support
environment-dependent variants (as the master-line engine did), and the
research flow must be extensible with checks/conditions/prompts while the code
prepares the base materials and rules.

**Unit-of-output change (the core correction):**

```text
R5:      one review packet + one unresolved condition + the human performs the decisive check
R6:      one complete decision, or a complete finite set of conditional decisions
         + at most two declared environment answers + accept/reject only
```

### Human-facing contract

- Human actions: answer 0–2 declared environment questions (only if a branch
  needs them), then `Accept` or `Reject`. No re-reading of advisory/repository,
  no tool re-run, no falsifier formulation, no free-form environment invention.
- Hard bounds: max **2** environment questions, max **7** mandatory facts on the
  first screen, target median decision time **≤5 min** (P95 ≤10) `[INFERENCE]`.
- Anything beyond the bounds is `NOT_DECISION_READY` or conservative
  `KEEP_OPEN_FOR_REMEDIATION` — never a disguised research assignment.

### Decision artifact

`DecisionArtifact{ finding_identity, target_scope, advisory_binding,
shared_facts[], decision_variables[], branches[], proposed_disposition,
justification_graph, contradictions[], human_action, replay_and_policy_pins }`
with `Fact` (independently produced, digest-bound, tool/version, coverage,
freshness, limitations), `Justification` (premise facts + conditions + rule +
coverage basis + contradictions → disposition), and
`ProposedDisposition{ CLOSE_NOT_AFFECTED | CLOSE_NO_EXPLOIT_PATH |
ACCEPT_ENVIRONMENTAL_MITIGATION | KEEP_OPEN_FOR_REMEDIATION | HOLD_UNKNOWN }`.
`CLOSE_*` keep the existing authoritative semantics; environmental mitigation is
a contextual disposition; the current `REVIEW_REQUIRED`/`AutoClose=false`
implementation boundary is unchanged for the rollout.

### Safe environment variants (resolves the R1 laundering objection)

- Branches may depend only on finite declared `DecisionVariable`s
  (`deployment_perimeter`, `peer_trust`, `config_mode`, `build_variant`,
  `delivered_artifact`, `protocol_role`) with enumerated allowed values; the
  agent may propose that a variable matters but never invent its value or a
  branch — code owns enumeration and completeness.
- Every branch carries its own predicates, evidence, coverage and status
  (`COMPLETE | AWAITING_INPUT | CONTRADICTED | NOT_DECISION_READY`); an explicit
  `unknown` branch always exists; a branch may never borrow another branch's
  perimeter/trust fact.
- A user answer is recorded as `EnvironmentAssertion{variable, value,
  principal, timestamp, source, freshness, supersedes[]}` — an auditable
  deployment premise, **never** a code-level `Claim{Result: FALSE}`.
- `FalsifierTrustedInfrastructure` (declared-trust / auto-perimeter bases) may
  produce only a contextual mitigation branch, never `NO_EXPLOIT_PATH_FOUND`;
  `BasisConfigOrigin` stays a code-provenance falsifier only when the verifier
  proves all relevant sink inputs originate from configuration with complete
  scope; the zero-trust vs cluster profiles become branch evaluators, not
  competing code-verdict writers.
- Conflict between machine evidence and an operator answer ⇒ branch is
  `CONTRADICTED` ⇒ `HOLD_UNKNOWN`/`KEEP_OPEN`; the human is not asked to resolve
  it by inspecting source.

### Extensible agent react/flow

- Loop: `PLAN → (validate) → ACT → OBSERVE → REASSESS`, repeating until a
  decision-ready disposition, all branches complete, budget exhausted, a
  terminal contradiction, a required environment answer, or
  `NOT_DECISION_READY`.
- New package `internal/flow` (`contract.go`, `engine.go`, `planner.go`,
  `broker.go`, `registry.go`, `policy.go`, `branch.go`, `replay.go`) plus
  `internal/research/{flow_adapter,decision_artifact,dispositions,branch_evidence}.go`;
  `internal/evidencetools/check_specs.go`; `internal/evaluator/rule_adapters.go`.
- Data-owned: `configs/research/{checks,conditions,dispositions}.yaml`,
  `rubrics/{research,decision}.yaml`, `prompts/{plan,reassess,counterexample}.txt`
  — versioned and digest-pinned in the run manifest.
- Extension points: add a check/tool adapter; add a condition (composition or a
  registered `ConditionEvaluator`); add a prompt/rubric; add a
  `VerificationRule`. Core loop knows only the interfaces and contains no
  CVE-specific branches.
- **Monotonic safety policy:** configuration may add required checks, narrow
  scope or add a stricter veto — it may never remove advisory-wide coverage,
  digest binding, negative verification, completeness or target-scope checks,
  and may never promote an agent assertion to a verified fact or turn unknown
  into FALSE.

### Build order

Phase 1 freeze/validate the decision contract → 2 evidence envelope (reuse the
lane) → 3 branch separation (one deployment variable + one build variant first;
never expose `TrustedPeer` as a falsifier) → 4 decision certificates for the
already-verifiable families → 5 wrap the one-turn agent in the react loop →
6 render the human artifact (proposed action, ≤7 facts, one justification,
branch matrix, contradiction/unknown state, accept/reject) → 7 validate with
controls (3–5 cases → all 18 corporate → VEX-Bench safety controls → unseen
holdout → blinded human acceptance study).

### Human-work metrics (the real target)

Primary: `human_decision_time` (median/P75/P95 by disposition kind and branch
count). Secondary: `facts_read` (mandatory cards), `repo_open_rate` (target 0
for decision-ready artifacts), `missing_fact_rejection_rate`,
`environment_question_count/answer_rate/unknown_rate/branch_change_after_answer_rate`,
`accepted_false_safe_rate`, `reopen/reversal rates`, `human_rerun_rate`.
Success requires: accepted decisions with zero repository opens, no technical
follow-up questions on accepted branches, no acceptance of an incomplete branch,
measurable reduction in median decision time, no accepted false-safe on the
safety holdout, and explicit separation of code-grounded closure from
environmental mitigation.

# C02 closure capability — B47 → B41 → live demonstration

**Goal:** reach the specification's real-case capability criterion — one case
producing an independently verified negative through the agent-led lane — with
a deterministically preflighted candidate, a plan-bearing live agent turn and a
bounded product-closure proof. **C02 is a closure-reconciliation control; it is
not assumed to be the negative target.**

**Non-goals:** no new universality (no condition solver, no proof engine, no
runtime/reflection/plugin analysis); no auto-close; no tracker or VEX writes;
no re-opening of the guard/bound family (stays B48); no reworking of the
previous slice's contracts except where these tasks require it.

## Global constraints

1. The agent stays the researcher; deterministic code stays the verdict
   authority. Every gate from the previous slice remains in force and must not
   be weakened — in particular advisory-wide subject coverage, trace integrity,
   the request↔audit argument binding, digest-validated persisted evidence,
   resolved evidence refs, empty limitations for a terminal negative, and
   `Disposition{REVIEW_REQUIRED, AutoClose:false}`.
2. Fail closed on every unsupported or incomplete shape: `UNKNOWN`/`ERROR`
   rather than a false absence.
3. Private snapshots, tracker exports and unit ids stay outside the repository;
   committed text keeps using `Cxx` labels and placeholders.
4. Intermediate verification uses focused tests only (`-count=1`); a corpus run
   is not a substitute for the capability demonstration and stays deferred
   until Task 3 succeeds.
5. Functional changes update `docs/dev/gap-analysis.md` (close items only in
   the commit that actually closes them) and `eval/README.md` when observable
   behaviour changes.

### Task 1: Wire `--modcache` / `--govulndb` into the strict evidence session (B47)

**Target:** `LaneOptions.ModCache` and `.GovulnDB` are declared
(`internal/research/deterministic.go:40-41`) and populated by the CLI
(`cmd/izyan/research.go:128-129`) but never reach the evidence session;
`openEvidenceSession` omits them, so the research lane runs without the frozen
module cache and govulndb (`run_govulncheck` → `UNSUPPORTED`, `go list -deps`
→ `ERROR` on the vendored snapshot under `GOPROXY=off`).

**Change:** pass both roots into the strict evidence session configuration as
`ModCacheRoot` and `GovulnDBRoot`, keeping strict confinement and the recorded
environment provenance.

**Acceptance:** with declared roots, `GOMODCACHE`/the govulndb path in the
session environment point at the declared roots; the roots are part of the
confinement/allowed read set; with a root omitted or unreadable, the affected
tool still reports `UNSUPPORTED`/`UNKNOWN` rather than falling back to an
ambient cache; the reported environment provenance records the roots used.

**Verification:** focused tests in `internal/research` and
`internal/evidencetools`; no corpora.

### Task 2: Bounded offline vendor/source closure capability (B41)

**Permissible because it is bounded:** the result must mean exactly "under this
snapshot, vendor metadata, source tree, GOOS/GOARCH, CGO setting, build tags
and recognised Go build rules, this advisory subject is or is not in the
product build closure". It must not become a general proof engine, a condition
solver, or a replacement for `VerifyDecision`.

**Where it lives:** parsing and closure construction in `internal/affected`
(which already owns package-closure semantics (`internal/affected/golist.go:73-85`),
treats `vendor/modules.txt` as authoritative for vendor module identity
(`golist.go:111-126,222-245`) and parses imports bounded by AST
(`resolver.go:639-674`)); evidence execution and the typed `Observation` in
`internal/evidencetools` through the existing `usage-scope` tool; interpretation
only in `internal/research` via the existing `VerifyDecision` gate.

**`COMPLETE` may be claimed only if the deriver can:** identify the product
roots under the recorded build context; apply the supported build constraints
for the recorded `GOOS`, `GOARCH`, CGO and build tags; parse every applicable
product package's imports; resolve imports through first-party modules,
vendored packages, declared replacements and the recorded inventory; account
for test roots separately when emitting `test-only`; and fail closed on
unreadable/unparsable files, unresolved imports, unsupported build features,
incomplete vendor metadata, ambiguous module/workspace composition and
generated/dynamically loaded code outside the supported model.

**Observation shape:** reuse the existing `usage-scope` observation rather than
adding a decision-layer proof type. It must carry, for each advisory-bound
subject: `tool="usage-scope"`, `tool_status="OK"`, `completeness="COMPLETE"`,
a scope statement, `evidence_refs` with resolvable persisted digests,
empty `limitations`, `scope_details.snapshot_hash` / `snapshot_root` / subject /
`build_context{goos,goarch,cgo_enabled,build_tags,vendor_mode}` /
`coverage_rule`, and `data{module, package, product_linked, test_linked,
usage_scope="test-only", product_absence_verification="VERIFIED",
check_scope, limitations[], counts}`. A module-level advisory subject stays
module-level; a package-level subject is covered at package identity. Fixed
scope semantics belong in `coverage_rule`/`scope_details`; unresolved or
incomplete conditions must prevent `COMPLETE` (the current implementation
always appends fixed interpretation limits to its payload —
`internal/evidencetools/usage_scope.go:124-156` — and that distinction must be
made explicit).

**Acceptance:** focused fixtures cover product absence, test-only presence,
mixed product/test presence, malformed/unreadable source, unsupported build
constraints, unresolved imports and incomplete vendor metadata — each
unsupported shape yields `UNKNOWN`/`ERROR`/`PARTIAL`, never a false absence;
a complete C02-shaped fixture yields the `VERIFIED` product-absence marker that
`VerifyDecision` already accepts.

**Verification:** focused tests in `internal/affected`, `internal/evidencetools`
and the decision path; point-case C02 run only.

### Task 2.5: Vendor-inventory absence marker and gate extension

**Depends on:** Task 2.

**Change:** add the narrow provable-absence marker to the contract and the gate,
keeping every existing fail-closed rule.

- Emit `product_absence_verification="VERIFIED_VENDOR_INVENTORY"` (constant
  `ProductAbsenceVerificationVendorInventory`) only with
  `usage_scope="unknown"`, `product_linked=false`, `test_linked=false`,
  `closure_source="vendor/modules.txt+source-imports"`,
  `closure_semantics="product_all_packages"`, `vendor_mode=true`, and a
  complete consistency-checked vendor inventory proving exact
  advisory-subject absence. The marker means exactly "the advisory-bound
  subject is absent from the product build closure under the recorded closed
  vendor inventory" — never safety, runtime absence or non-exploitability.
- Add required `closure_semantics="product_all_packages"` to the typed data and
  `scope_details.extra`, and state it in `coverage_rule`.
- `VerifyDecision`: accept the new marker only under the gate rules — proposal
  and advisory-subject identity exact at declared granularity (a module-level
  entry is never satisfied by an agent-chosen package), advisory-wide coverage
  by an accepted marker or deterministic applicability resolution, full trace
  integrity (all requests executed, request-bound, `OK+COMPLETE`, matching
  snapshot/build context, no skipped/unresolved/partial/dynamic markers, empty
  limitations, resolving digest refs), and positive-contradiction blocking
  (`product_linked=true` or `PACKAGE_USAGE present=true` blocks). Only then
  `Falsifier=FalsifierPackageAbsent`, `NegativeVerification=VERIFIED`,
  `Coverage=COMPLETE`, `NO_EXPLOIT_PATH_FOUND`. The marker is not
  `NegativeVerification`, not an applicability/evidence/VEX/auto-close basis;
  when applicability already proves absence, the applicability result stays
  authoritative.
- Validator: permit exactly the new `VERIFIED_VENDOR_INVENTORY` + `unknown`
  combination (the current rule forbids a marker on `unknown`) and reject every
  other combination.
- Update the B41 contract text in `docs/dev/decisions/agent7-e2e-conclusion-fidelity.md`
  (the `usage_scope` enum rules) with the normative wording: product-root
  semantics `product_all_packages`, the marker validity table, and the
  statement that `unknown` without a valid marker is never a negative proof.

**Acceptance:** fixtures cover complete vendor-inventory absence → marker
emitted; malformed/incomplete `vendor/modules.txt` → no marker; non-vendored
absent-from-both closure → `unknown` without marker; module-level subject with
empty package identity; package-level subject with exact identity; and every
forged marker/value combination rejected by validation. Existing gates and
fixtures stay green and unweakened.

**Verification:** focused tests in `internal/affected`, `internal/evidencetools`,
`internal/research` (with `-count=1` and matched-pattern confirmation); no
corpora.

### Task 3: Deterministic candidate selection, then the live turn

**Depends on:** Tasks 1, 2, 2b.

**Preflight (no model call):** run the deterministic candidate-selection gate
over the frozen corporate set (and any approved alternate set). Historical
labels, agent prose, direct-import counts and "test-only" hypotheses are not
selection evidence. A candidate qualifies as `first_negative_target` only if
every advisory-declared subject has exact module/package identity and a defined
proof route; the recorded snapshot has a closed supported build context; at
least one subject is genuinely `test-only`+`VERIFIED` or
`unknown`+`VERIFIED_VENDOR_INVENTORY`; no advisory-declared subject is
`product` or `mixed` for the asserted absence route; every remaining subject is
covered by an accepted marker or deterministic applicability resolution; the
route is identity-exact with no agent-chosen package substituting for a
module-only subject; all evidence is `OK+COMPLETE`, request-bound,
digest-resolved and limitation-free; and the candidate is not C01 (B48,
fail-closed). Record the preflight result per candidate.

**Live turn (only if the preflight selects a target):** exactly one live agent
turn with the pinned `r0-v2` prompt for the selected target, raw answer saved
immutably, its typed verification plan executed in the same confined session,
then one replay of that turn with no model call.

**C02:** replayed as a closure-reconciliation control only; it MUST NOT be
promoted to a package-absence negative while its Docker subject is `mixed`, and
it MUST NOT be selected merely because it was historically C02.

**Acceptance:** the deterministic gate identifies one eligible
`first_negative_target`; one live turn for it produces a valid typed plan whose
execution reaches `Decision.Verdict=NO_EXPLOIT_PATH_FOUND` with the recognized
package/build-closure falsifier, `NegativeVerification=VERIFIED`,
`Coverage=COMPLETE`, exact advisory-wide subject coverage, matching
snapshot/build context, resolving evidence references, empty operational
limitations, ticket-ready rationale and
`Disposition{REVIEW_REQUIRED, AutoClose:false}`; one replay reproduces the
decision without a model call. C03 remains never-safe (`EXPLOITABLE` only with
complete positive evidence, else `INCONCLUSIVE`); C04 stays `INCONCLUSIVE` with
its release-toolchain blocker; C01 stays out of scope and fail-closed (B48).

**If no candidate passes the deterministic preflight, no live turn is made and
`CAPABILITY_GAP_RECORDED` is recorded with the frozen search inputs and
per-candidate reasons — a valid fail-closed outcome, never a reason to weaken
the gate or substitute C02/C01.**

**Verification:** the preflight report, the selected case run plus one replay,
`gofmt`, `go vet ./...`, `go test ./...`; docs sync (close B47/B41/B32/B40 only
in the commit that actually closes them).

## Execution order

`Task 1 → Task 2 → Task 2.5 → Task 3`. Task 2 started only after Task 1 landed
(both touch the evidence-session boundary). Task 2.5 extends the contract and
the gate that Task 2's deriver feeds. Task 3 begins with a deterministic
candidate preflight, which must select a target before any live model call; if
nothing qualifies, Task 3 records `CAPABILITY_GAP_RECORDED` without a call.
Task 3 is the gate that decides whether the specification's criterion is
finally met.

## Assumptions

- **[INFERENCE]** a live model call may still fail to produce a valid plan;
  that outcome stays a recorded gap.
- **[INFERENCE]** a source-import plus `vendor/modules.txt` derivation is
  sufficient for C02's static Go topology; any unsupported shape must fail
  closed rather than generalise the deriver.
- **assumed** the C02 snapshot, advisory and frozen module cache/govulndb from
  the private matrix remain available and immutable.

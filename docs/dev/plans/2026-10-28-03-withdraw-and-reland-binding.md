# DESIGN_FOR_REVIEW — Choose R: withdraw, then re-land against a sound contract

**Withdraw `ba782d1` and `93ec9c3`. Preserve the identity-before-absence gate introduced by `06b26ce`, but harden its remaining admission shortcuts as part of the withdrawal.**

A plain revert is **not** a sufficient safety fix: the retained gate still accepts an asserted coordinate binding and `LLM_PROPOSED` origin, and the JSON loader can silently discard the removed `fix_binding` field. Those paths must not resurrect saved conclusions.

The immediate result for `helm-helm-b76a950-CVE-2024-25621` is an honest **`FAILED / CODE / ROOT_CAUSE_UNRESOLVED`**, unless another genuinely independent proof closes the assessment. Do not preserve or manufacture NEPF to match the earlier expectation.

**Design gate: READY for withdrawal.** The later feature remains non-admitting until the complete contract and its adversarial tests land. No user-owned decision is needed.

## 1. Why R rather than P

| Option | Assessment |
|---|---|
| **R — withdraw and re-land** | Removes the defective authority path. The useful ordering, provenance and failure machinery can remain. Re-land can introduce the necessary evidence/schema changes without supporting unsound saved bindings. |
| **P — repair in place** | Acceptable only if the shared boundary first disables content-derived admission for fresh analysis, replay and publication. Producer-only switches are insufficient. Once contained, P offers no immediate capability advantage over R, while retaining substantially more hazardous code. |

These are not twelve independent local defects. F1, F2 and F10 require changing the proof dependency model and admission boundary; F5–F9 require changing the identities and evidence being persisted. Repairing individual matchers while continuing to admit their output would leave an unsafe intermediate state.

**No intermediate unsound state is acceptable.** With R, the public authority path is removed first; subsequent work may produce diagnostic proposals but cannot authorize absence until final integration.

## 2. Exactly what to keep—and what not to keep

### Keep

- `e38acb3`’s ordering: **admitted identity → product-package absence → otherwise source lookup**. Source being available in a module cache does not make it product-linked.
- `06b26ce`’s:
  - typed candidate origins;
  - `UNMEASURED` versus `UNMAPPED` diagnostics;
  - shared identity-before-absence enforcement points;
  - unresolved candidates as positive-blocking obligations;
  - typed root-cause failures;
  - replay/publication recomputation and refusal of unsupported saved results.
- Existing complete-package-inventory, target/build-context, negative-verification, defect-semantics, mandatory-review and advisory-scope gates.
- The separation between record results and requested-CVE composition.
- The governing design documents, marked accurately as **not implemented soundly**, rather than retaining claims that Slice B established its guarantees.

### Remove from active admission

- Slice B’s current effect-to-subject authority, census completeness authority, `AdmitFixBinding` implementation and their consumer branches.
- Both name/coordinate-based non-counterpart routes, including `foreign-construct-absence`.
- Assertions that a vendor manifest proves whole-module completeness.
- Assertions that the real `containerd v1.4.3` case was validated using `v1.4.13`.
- Passing tests whose expected admission rests on hand-authored “complete” bindings rather than reconstructible evidence.

The truncated-signature parsing correction and module-root vendor join correction are locally valid observations, as the review states. They do not justify retaining the surrounding authority layer. Carry their regression cases into the re-land where applicable.

### Mandatory withdrawal hardening

The retained gate must require an **affirmative, admitted basis**, not merely absence of a matching candidate:

1. `FIX_DERIVED`, `LLM_PROPOSED`, empty origin, and a saved `CandidateBinding{Status: ADMITTED}` confer no absence authority by themselves.
2. `ADVISORY_DECLARED` must resolve to an actual declaration in the pinned record or an independently re-admitted own-record operation binding. The origin enum is not the declaration.
3. Genuine manual inputs retain their explicit operator-trust route, recorded as operator assertions—not machine-proved source identity. A duplicated or relabelled candidate is not a new operator input.
4. Nil root-cause models and unmatched subjects do not make derived absence admissible.
5. Empty absence subject sets are rejected at shared admission.
6. Historical `fix_binding` data is recognized as **withdrawn, non-admitting historical evidence**, not silently discarded into a weaker coordinate route. Preserve original stored history; sanitize only the evaluation copy.

Until re-land, automatic patch-only same-line absence also loses its coordinate-only exemption. That temporary capability reduction is deliberate and must be documented. Actual record-declared subjects and independently admitted operator inputs retain their own routes.

This is necessary because the current shortcuts are visible in `internal/domain/candidate_binding.go:152–227`; the refused binding is cleared without invalidating its candidate children in `internal/evaluator/absence_identity.go:34–58`; and loading uses ordinary `json.Unmarshal` in `internal/persistence/filesystem/store.go:27–39`.

---

## 3. The sound admission contract

### 3.1 One pure checker, not a stronger producer plus a weaker replay consumer

Keep persisted proof data in `internal/domain`. Put the deterministic proof checker in a leaf package, proposed as **`internal/fixbinding`**.

Its dependency direction is:

```text
domain DTOs + captured bytes
             ↓
      internal/fixbinding
             ↓
Resolver / Verifier / Builder / condition evaluation / verdict admission
```

Move reusable pure extraction/census/correspondence logic below its consumers. Acquisition remains in `goanalysis` and the existing input adapters.

The checker must not import `rootcause`, `evaluator` or the filesystem-backed `goanalysis.Index`. The verdict evaluator remains pure: **no filesystem reads, subprocesses, network, or “current cache” lookups**.

Remove the existing self-consistency-only `domain.AdmitFixBinding`; do not leave it as an alternate API. Its replacement, `fixbinding.AdmitFixBinding`, receives the complete immutable input bundle and returns a checker-created admission object. Persisted `Status`, `Complete`, `Verified`, equation prose and component-label lists remain diagnostic output, never authority.

Compute admission once per input bundle at a boundary, then query it for individual subjects. Do not re-extract the patch or scan the source separately for every subject.

### 3.2 What `AdmitFixBinding` must re-derive

| Premise | Required reconstruction |
|---|---|
| **Record identity and entries** | Hash and decode the captured raw advisory bytes; match the `RecordPin`; reconstruct original `affected[]` indices, scopes, declarations and candidate fix locators. Module-name strings are not original entry references. |
| **Locator/artifact relationship** | Resolve each recorded artifact to its captured locator and capture provenance. Hash full bytes. Confirm that relevant locators have not disappeared. A URL, matching digest elsewhere, or `WEB`/`FIX` label alone does not prove applicability. |
| **Fix inventory** | Reparse every relevant artifact and reconstruct all changed executable spans, effects, residual obligations and non-executable changes. Compare the saved inventory with this canonical result. |
| **Selected implementation** | Reconstruct declared and effective module coordinates from captured selection/replacement evidence. Match the assessed entry and build. A scalar saved version is insufficient. |
| **Source inventory** | Verify the independent complete-source anchor and all required bytes; enumerate the actual files and component boundaries; recompute digests, counts and scan obligations. |
| **Correspondence** | Recheck selected declarations, API ownership, resource equations, operands, values, control/data flow, and omission-site relations against source bytes. |
| **Coverage** | Re-enumerate alternative operations, wrappers, constructors, resource escapes, registrations and relevant external implementation edges. Recompute every unresolved obligation. |
| **Non-counterpart** | Re-run the supported structural proof rule over its complete implementation boundary. Require the entire expected certificate; missing proof records never mean success. |
| **Subjects and carriers** | Recompute the exact mapped image and alternative cover. Check equality in both directions, including carriers and applicable authoritative declarations. |
| **Claim relationship** | Check that the condition and negative verification reference this admitted cover and cover its complete, nonempty necessary subject set. |

If required bytes are absent, replay refuses the proof. A durable reference is useful only if its bytes are supplied before entering the pure evaluator.

Persist a new proof-contract version, record/entry/mechanism identity, input artifact roots, effective-source identity, checker-rule version, canonical dispositions, obligations and cover. Reject old or unsupported proof contracts; do not grandfather them.

**An aggregate hash is not a completeness proof.** It binds a result to inputs only after those inputs have independently established their boundary.

### 3.3 Refusal dominates dependent identities

Every derived candidate and absence claim must retain its proof dependencies:

```text
record + entry + mechanism + effective source + artifact set
                         ↓
                    cover identity
                         ↓
                candidates / condition / verification
```

Rules:

- A coordinate binding is a **child observation** of a content binding, not an alternative authority that can rescue it.
- If a required binding is missing, withdrawn or refused, every dependent absence flag, absent-set membership and claim becomes non-admitting.
- Adding a candidate with the same coordinates and `MANUAL`, `ADVISORY_DECLARED` or `LLM_PROPOSED` origin cannot erase that dependency.
- Removing a binding or candidate record cannot strengthen admission.
- Preserve the refusal and historical evidence; do not clear the binding pointer and then search for an exemption.

An independently sufficient proof may still close through its own admitted route—for example, an independent version fact. This is **dependency-specific refusal**, not a global veto on unrelated evidence.

### 3.4 Nonempty, exact necessary coverage

For each relevant original entry and mechanism, the checker must establish:

\[
D_{e,m}\ \Longrightarrow\ \bigvee_{s\in S_{e,m}}\operatorname{Exec}(s)
\]

A grouped package-absence proof falsifies this necessary disjunction. Alternative subjects must not become separate mandatory conjuncts.

For the aggregate cover used by a claim:

- the required subject set is nonempty;
- it contains every mapped alternative and every applicable authoritative subject requiring coverage;
- condition subjects equal that canonical set;
- negative verification records the same cover identity and subject-set digest;
- every subject’s package is absent from the independently admitted product inventory.

No fallback from empty condition subjects to whatever happens to remain in `Model.RootCauses`. No acceptance of an absent subset while another alternative is linked or unresolved.

Enforce this in the shared absence admission used by fresh evaluation, negative verification, replay and publication—not only in `verifyLocusAbsent`.

### 3.5 LLM authority

An LLM may propose:

- locations;
- resource equations;
- mechanism interpretations;
- locator applicability;
- possible alternative carriers.

It may not establish source identity, record declarations, necessity, completeness, artifact availability, replacement provenance or non-counterpart disposition.

A source-verified proposal has established a location—not automatically an advisory-relevant, complete necessary cover. It must pass the same deterministic checker as any other proposal.

---

## 4. Identity precision

### Qualified API ownership — F5

Classify an operation using its resolved declaration:

```text
owning source/module + import path + function or receiver/method + signature
```

`os.MkdirAll` imported under an alias can normalize to the same API. An unrelated package’s `MkdirAll`, a shadowed `os`, or a same-named method cannot.

Repository-local wrappers require checked summaries of their bodies and argument/resource propagation. Final-callee-name classification is nomination only.

### Resource equality — F5

A resource identity includes:

- source ownership;
- package-qualified declared type;
- receiver/base-value provenance;
- complete selector/derivation chain;
- relevant alias and constructor relationships.

Two unrelated `Config.Root` fields are not equal. Neither are two unrelated configuration instances merely because they share a type.

Cross-line equivalence requires a structured, checked equation with a supported rule and source witnesses. A rendered string saying “the same daemon root” is not that equation.

If patch context omits the imports or declarations necessary to resolve its identifiers, obtain them from captured patch-side source, or reconstruct them from a verified same-line preimage. Otherwise retain a missing-proof or unresolved-binding obligation. Do not infer patch qualification from a convenient selected-source match.

Multiple verified implementations belong in the cover. Multiple competing interpretations remain unresolved.

### Alias obligations — F6

Track resource derivations through ordinary assignments, declarations, local aliases, branch joins and supported argument/return propagation.

For example:

```go
p := cfg.Root
q := p
os.MkdirAll(q, 0711)
```

must either identify the operation on `cfg.Root` and include its carrier, or retain a blocking obligation.

Unsupported pointer mutation, interface dispatch, escaping aliases, unknown calls, exported direct-entry paths, and unsupported data structures must not vanish as “reads.” A use is harmless only when the checker proves its relevant role harmless.

Use conservative finite may-sets and checked summaries; do not require a whole-program points-to solver. Unsupported propagation blocks completion.

### Effective source selection — F9

Record both:

- declared module/version and original advisory entry;
- effective module/version or local replacement identity;
- applied replacement/workspace provenance;
- source-content root and source kind.

Resolve the source actually selected by the recorded build:

- module replacement → replacement module source;
- confined local replacement/workspace module → captured local bytes;
- vendored replacement → effective vendor provenance;
- unreplaced dependency → exact selected source.

Never fall back to `original@effectiveVersion` or published original bytes when the replacement is unavailable. Local replacement identity is its captured content, not an invented version.

Reuse the recorded build environment and replacement conventions. The current `SelectedModuleSource` does not do this (`internal/goanalysis/modulesource.go:46–82`), despite affected resolution using effective versions.

---

## 5. Credible completeness

### Complete source is different from successfully parsed source — F7

Distinguish:

1. input inventory completeness;
2. parsing/type-resolution completeness;
3. operation/resource analysis completeness;
4. necessary-cover completeness.

A vendor tree normally supplies only a package subset. `vendor/modules.txt` may establish selection and subset membership; it cannot establish all packages or all files of the upstream module.

Whole-implementation coverage requires an independently anchored inventory, such as:

- an exact module archive tied to the selected coordinate and captured checksum evidence;
- a complete captured VCS tree;
- a complete captured local-replacement tree anchored in the product snapshot.

For vendored builds, reconcile the actual vendor bytes with that source:

- verify retained package/file content;
- account for modifications and extras;
- retain upstream alternatives omitted by vendor pruning in the discovery inventory;
- refuse unsupported overlays.

The source used to discover alternatives must not be restricted to the product-linked package set whose absence is being proved.

Explicitly account for build variants and nested modules. Non-Go implementations, generated inputs, cgo/assembly, or unresolved build-affecting material become obligations unless a supported rule accounts for them.

### Foreign implementations and non-counterpart proofs — F8

**Delete the generic declaration-name absence proof permanently.** Even a complete declaration census cannot prove semantic absence of an opaque operation.

Construct an implementation boundary from complete selected source and effective component/import relationships. Follow relevant imported implementations, blank-import registrations, wrappers and resource propagation to their actual owners. An unresolved external implementation edge blocks the proof.

For registrations:

- enumerate independently of patch paths;
- resolve registration identity and construction;
- inspect named `InitFn` bodies, including other files/packages;
- analyze inline initializer closures with their own parameter bindings;
- account for constructors, direct calls and alternate registrations.

Permit `INAPPLICABLE` only for a **supported closed structural rule**: the checker must establish an exhaustive component/resource construction and show that the particular mechanism has no counterpart or bypass within that closed boundary. Dynamic registration, unresolved exports, unknown imports or ambiguous mechanism scope defeat the certificate.

Opaque foreign executable changes remain unresolved. Missing package/type/function names are diagnostic observations only.

For the reviewed CRI case, an import of `github.com/containerd/cri` means containerd’s own-module census cannot exclude the implementation. Resolve the effective external component and inspect it, or fail closed.

### Mixed hunks — F4

Inventory **changed spans**, not “hunks containing at least one recognized operation.”

Each changed executable span must be:

- consumed by a checked effect/correspondence;
- proved non-executable/equivalent under the supported rule;
- or retained as an unresolved residual obligation.

Recognition must consume only the relevant AST/token spans—not every statement on a line or every statement inside the same hunk. Changed guards, resource derivations, `copy` operations and other residual statements remain visible.

Comments/directives affecting build or runtime semantics are not ordinary comment-only changes. Truncation, malformed hunks and unaccounted files block inventory completeness.

Do not make “still nine effects” an acceptance criterion. The correct inventory count follows the bytes.

---

## 6. Restorations

### Same-line route — F11

Provide an explicit **exact-preimage correspondence** route:

1. Match the complete old changed region and context to captured selected source, with only supported token/format normalization.
2. Require an unambiguous match; path existence and a hunk-header name are insufficient.
3. Identify the actual enclosing selected declaration.
4. Account for the full postimage and residual changes.
5. Attach newly added checks/helpers to verified pre-existing omission-site pipelines—not to absence of the added function.
6. Apply the same independent necessity/alternative-cover gate.

An opaque same-line change may have exact identity even when it lacks a permission-operation classification. Do not fabricate operation/resource components for it. Conversely, exact preimage identity alone is not a completeness theorem.

A complete advisory-declared package boundary can support the necessary cover without inventing a new semantic classifier. For declaration-free cases, the supported mechanism-cover checker must establish the cover; arbitrary changed functions do not suffice.

The regression must start at **`Resolver.Resolve`**, pass through root-cause `Verifier`, model/condition production, negative verification and publication. The current control constructs a model directly (`internal/rootcause/rootcause_test.go:714–741`), bypassing the defect.

### Real artifact-set handling — F12

Process every candidate fix locator before concluding availability:

- request each distinct locator from the configured captured-artifact provider;
- record complete bytes or a typed acquisition outcome;
- retain per-locator provenance even when bytes deduplicate;
- inventory every relevant available artifact;
- distinguish unavailable bytes, unsupported acquisition, and unresolved applicability.

Not every reference is one sequential patch series. It may be another release-line fix, an alternative representation, or an unrelated reference. Applicability and sequencing require evidence; do not copy aggregate `FixedVersions` onto every reference as proof.

Only an actually unavailable required artifact earns `PROOF_ARTIFACT_MISSING`. Available-but-unmapped or applicability-unknown material produces a code-owned root-cause obligation, not a claim of missing bytes.

No analysis-time network/backport discovery is required by this route. Use configured captured inputs; absence of those inputs remains explicit.

---

## 7. What must become impossible

A reviewer should be able to test these invariants directly:

1. **No identity-free absence:** nil models, deleted candidates, origin labels and absent guessed paths cannot authorize derived absence.
2. **No resurrection:** refusing a required binding invalidates all dependent absence authority, despite retained coordinate bindings or duplicate manual/LLM candidates.
3. **No asserted proof premises:** jointly editing saved effects, census metadata, carriers and subjects cannot substitute for reconstruction from independently pinned inputs.
4. **No partial-inventory completion:** recognized operations cannot hide residual executable changes.
5. **No similarity authority:** suffixes, names, modes, paths and prose equations cannot establish API/resource correspondence.
6. **No invisible resource escape:** every potentially relevant alias, wrapper, constructor or external carrier is covered or blocking.
7. **No vendor-as-whole-module proof:** a manifest-consistent vendor subset alone cannot certify whole-source coverage.
8. **No name-miss non-counterpart proof:** renamed, split, wrapped and externally supplied implementations cannot be discharged by absent declarations.
9. **No source substitution:** replacements and exact versions cannot be answered using another source tree.
10. **No vacuous/subset closure:** empty covers and narrowed condition/verification covers never ground this absence route.
11. **No newly-added-function inversion:** absence of a fix-added check/helper is not absence of its vulnerable pipeline.
12. **No unrequested-artifact fiction:** an available locator cannot be labelled missing without being requested.
13. **No verdict-axis shortcut:** this layer never creates affected-chain FALSE, `NOT_AFFECTED`, or CVE-wide negative scope.
14. **No dependent positive after refusal:** removing rejected subjects must not make the remaining positive model appear complete. Independently sufficient proofs remain usable.

An all-`INAPPLICABLE` inventory with no subjects does **not** produce absence-based NEPF. It also does not populate the separate affected implementation-absence authority.

---

## 8. Ordered task breakdown and pinning tests

The tasks below describe the later implementation; none has been executed here. Keep the withdrawal policy in force through Tasks 2–8. Activate only the completed proof contract in Task 9.

### Task 1: Withdraw authority and close surviving shortcuts

**Depends on:** None. Ship as one coherent withdrawal change.

**Files:** reverse the two feature commits; harden `internal/domain/candidate_binding.go`, `internal/evaluator/absence_identity.go`, `internal/domain/negative_admission.go`, `internal/exploit/builder.go`, `internal/rootcause/binding.go`; update historical decoding in `internal/persistence/filesystem/store.go` and publication tests.

**Pinning tests:**

- **F1 — `TestWithdrawnBindingCannotResurrectThroughCoordinate`:** use verifier-produced candidates carrying admitted coordinate bindings; withdraw/remove the content proof. Dependent absent subjects and FALSE claims must not admit, and saved NEPF must not publish.
- **F3 — `TestLLMOriginDoesNotEstablishAbsenceIdentity`:** propose a nonexistent release-line package through the real proposal/verifier path. No admitted `Absent`, VERIFIED absence or NEPF.
- **F10 — `TestEmptyAbsenceRejectedAtSharedBoundary`:** persisted VERIFIED absence with empty subjects, including nil root-cause/model cases, is refused.
- Builder regression: an `Unverified` candidate’s stale `Absent=true` is checked before copying or describing it as verified absence.

**Acceptance:** withdrawal cannot recreate the original guessed-subject NEPF. Existing independent record/operator and affected-axis proofs remain independently admissible.

### Task 2: Capture exact inputs and effective source identity

**Depends on:** Task 1.

**Files:** `internal/domain/domain.go`, proof DTOs, `internal/states/states.go`, `internal/states/related_records.go`, `internal/affected/golist.go`, `internal/affected/resolver.go`, `internal/goanalysis/modulesource.go`, relevant snapshot adapters.

**Produces:** full advisory bytes, typed effective-selection/source descriptors, and source artifacts available to the pure checker. No host path becomes persisted source identity.

**F9 — `TestEffectiveReplacementOwnsBindingSource`:**

- Cache both original and fork; put the real linked alternative only in the fork.
- Require selection and census of the fork.
- Missing fork must fail, not fall back to original.
- Include confined local replacement, workspace selection and vendored replacement cases.
- Mutation of local replacement bytes invalidates the old source root.

**Acceptance:** all binding inputs refer to the exact effective implementation, per original entry.

### Task 3: Account for the full available artifact set

**Depends on:** Task 2.

**Files:** `internal/fix/fix.go`, `internal/fix/patch.go`, `internal/rootcause/rootcause.go`, proof artifact DTOs, provider implementations and test fakes.

**F12 — `TestResolverRequestsAndAccountsForEveryFixLocator`:**

- A map-backed provider has all artifacts: every locator is requested and every relevant effect appears; no artificial series gap.
- One unavailable artifact yields exactly the appropriate named missing-proof obligation.
- Available-but-unmapped and applicability-unknown artifacts yield code obligations.
- Include duplicates, alternative release lines, and sequential artifacts requiring predecessor reconstruction.

**Acceptance:** no first-success stopping rule and no fabricated availability claims.

### Task 4: Make changed-span accounting total and identities qualified

**Depends on:** Tasks 2–3.

**Files:** `internal/fix/effects.go` and tests, proof DTOs, new pure `internal/fixbinding` extraction/identity code.

**F4 — `TestMixedHunkRetainsEveryExecutableResidual`:** mode change plus changed guard, derivation and `copy`, including separate statements on one line. Every residual is represented and blocks unsupported closure. Include malformed/truncated hunks and semantic directives.

**F5 — `TestQualifiedAPIAndResourceEqualityRequired`:** unrelated package/type/receiver `Config.Root`, shadowed `os`, and unrelated `MkdirAll` cannot match. Valid import aliases normalize; missing patch-side qualification remains unresolved.

**Acceptance:** consumed changed spans are explicit; unresolved identity is never replaced by a short-name equation.

### Task 5: Establish inventory credibility and conservative resource propagation

**Depends on:** Tasks 2 and 4.

**Files:** `internal/goanalysis/modulesource.go`, acquisition portion of `modulecensus.go`, moved pure census code in `internal/fixbinding`, source-evidence DTOs.

**F6 — `TestLinkedAliasBypassCannotDisappearFromCover`:** an absent direct operation coexists with linked exported `Bypass`, using `p := cfg.Root`, chained aliases, assignment, declaration and forwarded parameters. The bypass joins the cover or creates a blocking obligation.

**F7 — `TestVendorSubsetCannotCertifyWholeSource`:**

- Normally pruned, manifest-consistent vendor tree.
- Missing unlisted alternative package.
- One relevant file removed from an otherwise nonempty package.
- Vendor modification disagreeing with the canonical source.
- Incomplete build-variant inventory.

Vendor-only evidence cannot authorize whole-source completeness; reconciled independent complete evidence can.

**Acceptance:** input, parse, analysis and cover completion are separate checker-derived results.

### Task 6: Re-derive correspondence, cover and restricted non-counterpart certificates

**Depends on:** Tasks 3–5.

**Files:** new `internal/fixbinding` checker; move pure logic out of `internal/rootcause/fixbinding.go`; replace `internal/domain/fix_binding.go` admission logic with DTOs.

**F2 — `TestAdmissionReconstructsAllPremises`:** start from real captured inputs and a freshly derived binding. Individually and jointly mutate effects, alternative subjects, locators, entry indices, series membership, effective coordinate, locations, census fields and non-counterpart records. Keep original input roots fixed. Every unsupported mutation is refused.

**F8 — `TestNonCounterpartRequiresClosedImplementationProof`:**

- Renamed/split/wrapped counterpart with zero original-name hits.
- External CRI implementation import.
- Named registration `InitFn` in another file.
- Inline initializer closure.
- Exported direct-constructor bypass.
- Removed or shortened certificate.

Counterparts must be represented or blocking; opaque foreign changes never earn generic `INAPPLICABLE`.

**Acceptance:** canonical binding/cover output is reconstructed from bytes, not accepted from summaries.

### Task 7: Restore evidence-backed same-line resolution

**Depends on:** Tasks 4–6.

**Files:** pure correspondence code, `internal/rootcause/rootcause.go`, `internal/rootcause/binding.go`, `internal/rootcause/rootcause_test.go`, integration fixtures.

**F11 — `TestSameLineResolverVerifierEarnsAbsenceEndToEnd`:**

- Use a real provider and `Resolver`, not a manually constructed candidate model.
- Use an ordinary non-permission executable change with exact preimage correspondence and an independently complete necessary boundary.
- All required packages absent → negative verifier can earn VERIFIED absence and exact-record NEPF.
- Same path with changed preimage → unresolved.
- Linked required package → contradiction.
- Added helper without omission carrier → unresolved.

**Acceptance:** same-line support works without reintroducing path-existence authority or assuming changed functions exhaust a defect.

### Task 8: Wire one admission result through every consumer

**Depends on:** Tasks 6–7.

**Files:** `internal/rootcause/binding.go`, `internal/exploit/builder.go`, `internal/evaluator/conditions.go`, `internal/goanalysis/locusverify.go`, `internal/evaluator/absence_identity.go`, `internal/evaluator/verdict.go`, `internal/domain/negative_admission.go`, `internal/finding/project.go`; migrate every old admission caller.

**F1 — `TestRefusedContentDependencyDominatesEveryIdentityLabel`:** serialize actual verifier output; corrupt/remove required proof inputs while preserving coordinate bindings. Add duplicate manual/LLM labels. No dependent negative survives and publication refuses saved closure; history remains unchanged.

**F3:** both nonexistent proposals and real source locations without advisory/coverage support remain non-admitting.

**F10 — `TestAbsenceClaimMustEqualAdmittedNecessaryCover`:** empty sets, absent-only subsets, edited model subjects, changed verification cover and mismatched condition subjects are refused. A linked omitted alternative cannot disappear by editing both saved summaries.

**Acceptance:** fresh analysis and replay make the same admission decision; no structural helper or nil-model exemption bypasses the checker.

### Task 9: Activate the new contract, prove cases, and correct documentation

**Depends on:** all preceding tasks.

**Files:** integrated state/publication tests, `internal/evaluator/binding_admission_test.go`, `internal/finding/project_test.go`, case fixtures, both governing plans, `docs/dev/analysis-internals.md`, `docs/dev/gap-analysis.md`, `eval/README.md`.

**Acceptance cases:**

- Old guessed-v2 Helm proof remains non-admitting.
- Exact-record Helm NEPF is earned only by a complete fresh proof over exact selected source and complete recorded inputs. Do not hardcode subject/effect counts as evidence.
- Requested-CVE scope remains separate and unchanged.
- `containerd v1.4.13` is never accepted as evidence for `v1.4.3`.
- Missing exact `v1.4.3` source produces the appropriate input/proof failure, not non-counterpart.
- Exact `v1.4.3` support, when its inputs are captured, accounts for the effective external CRI component and actual artifact availability.
- Existing target, inventory, declaration, omitted/defective-check, review, library/transport, independent-proof and composition controls remain intact.

Activate only the new supported proof contract. Remove the withdrawal-only disabled implementation path; retain explicit refusal of withdrawn historical proofs.

The implementation owner should run the focused pinning tests, then repository-required formatting, vet, full tests and final corpus validation, with **`false-safe=0`**. These are required future checks, not results reported here.

---

## 9. Evidence limits and handoff

The full adverse review, both governing designs, current admission/verification/publication paths and independent source/resolver investigations support this decision. **No files were changed and no builds, tests, linters, formatters or analysis runs were executed.**

The remaining evidence uncertainty is safely bounded:

- Exact complete source unavailable → no source-cover admission.
- Unsupported semantic correspondence or external carrier → blocking code obligation.
- Missing artifact bytes → named proof failure.
- Exact `v1.4.3` evidence unavailable → no substitute-version claim.

**Implementation handoff:** preserve these decisions and limits. If implementation discovers that a proposed correspondence, source inventory or necessity rule cannot satisfy this contract, keep the route non-admitting and return that specific contract issue for design review. Do not compensate with similarity, asserted completeness, a manual/LLM label, or weaker replay admission.

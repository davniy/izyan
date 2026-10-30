# DESIGN_FOR_REVIEW — READY

> **Status (2026-10-28, after the withdrawal re-land).** The saved Helm
> `NO_EXPLOIT_PATH_FOUND` this design accepted is **withdrawn**. It rested on four
> candidates guessed from a v2/main-line source layout; that proof is
> non-admitting and must not be preserved or manufactured
> (`docs/dev/plans/2026-10-28-03-withdraw-and-reland-binding.md`). The structural
> decisions stand and are implemented: keep the `package-absent → verified
> mandatory FALSE → NO_EXPLOIT_PATH_FOUND` route, do not invent
> candidate-derived `NOT_AFFECTED`, keep requested-CVE scope separate. Candidate
> absence now requires an affirmative admitted basis: the record's own
> declaration, a re-admitted own-record operation binding, a genuine operator
> input, the re-derived exact-preimage route, or a checker-created persisted
> content proof. The saved Helm record result does not replay; the honest result
> is `FAILED / CODE / ROOT_CAUSE_UNRESOLVED / ROOT_CAUSE` unless a complete fresh
> proof over the exact selected source and complete recorded inputs is available.

**Decision:** preserve the existing `package-absent → verified mandatory FALSE → NO_EXPLOIT_PATH_FOUND` route. Do **not** introduce candidate-derived `NOT_AFFECTED`.

The investigation found two distinctions that change the diagnosis:

1. **The saved scoped Helm run already resolves candidate absence and emits record-level NEPF. Its remaining `FAILED` is the CVE-request scope gate.**
2. **Those candidates were guessed from a different containerd source layout.** The real safety defect is insufficient fix-to-selected-version binding—not failure to notice their absence.

No user-owned question is necessary.

## 1. What actually fails

I inspected the saved runs rather than rerunning the analysis:

| Saved run | Candidate state | Claims | Record result | Requested CVE result |
|---|---|---|---|---|
| `/tmp/c-helm1/CVE-2024-25621-1793090433.json` | Four root causes have `absent=true`; all four appear in `AbsentSubjects` | `C-REACH` and `C-INPUT` are `UNKNOWN`; their limitations explicitly refuse a host-default negative | `FAILED` | `FAILED` |
| `/tmp/c-helm2/CVE-2024-25621-1793090529.json` | Same four absent candidates | Both claims are `FALSE / package-absent / VERIFIED` | **`DECIDED / NO_EXPLOIT_PATH_FOUND`** | **`FAILED`**, solely `SCOPE/UNSUPPORTED_NEGATIVE_SCOPE`: no operator-declared corpus |

Thus the observed final `FAILED` is real, but **the scoped rerun does not retain the reachability/input gaps**. Its primary assessment and requested finding are different results.

The `DECIDED / NO_EXPLOIT_PATH_FOUND` in the second row is the **withdrawn**
proof: its four subjects were guessed from a v2/main-line layout and none of
their packages exists in the selected version, so their absence from the product
closure proved nothing. The re-landed contract refuses it at every boundary. It
is not a measured result this design may rely on, and no subject or effect count
from that run is evidence.

### Why “unresolved” still appears

`exploit.Builder.BuildWithHints` deliberately puts an absent root cause in **both**:

```text
UnresolvedSubjects
AbsentSubjects
```

That preserves the prohibition on earning a positive from a pruned candidate model. It does not mean absence verification failed.

The builder then emits the misleading blanket limitation:

> advisory-declared sink(s) unresolved in source … exploit model is incomplete

This conflates:

- genuinely unverified subjects;
- verified-absent subjects;
- advisory declarations;
- fix-derived candidates.

See `internal/exploit/builder.go:73–107`. The verdict already distinguishes these states through `allUnresolvedAbsent` and `locusCoversUnresolved` in `internal/evaluator/verdict.go:658–701`.

### Exact gates

For the default-target run, the refusing path is:

```text
evaluator.admitNegative
  → domain.ValidateNegativeEvidence
    → domain.ValidateNegativeTarget
      → host-default has no product scope
```

Sources: `internal/evaluator/conditions.go:26–35`, `internal/domain/negative_admission.go:81–95`, `internal/domain/buildcontext.go:145–154`.

For the scoped rerun, that gate succeeds. The remaining failure is:

```text
finding.composeCVE
  → domain.BuildCorpusNegativeBasis
    → domain.DeclaredCorpusBoundary
      → CorpusDeclaration == nil
```

Sources: `internal/finding/compose.go:151–173`, `internal/domain/corpus_scope.go:159–176`.

**There is no failed candidate-absence producer in that saved scoped run.**

### A real adjacent ordering defect

`rootcause.Verifier.Verify` checks inventory absence **only inside the `LookupSymbol` error branch**. A symbol successfully loaded from the module cache or vendor tree is retained without `Absent=true`, even if its package is outside the product closure.

That is a genuine inconsistency between “exists in dependency source” and “linked into product.” It deserves correction, but **it did not cause these saved Helm results**, where absence was already recorded.

Source: `internal/rootcause/rootcause.go:248–280`.

## 2. The more serious Helm defect: the proof subjects are wrong for v1

The selected dependency is:

```text
github.com/containerd/containerd v1.7.27
```

The captured fix uses these paths:

```text
cmd/containerd/server/server.go
core/runtime/v2/task_manager.go
plugins/cri/runtime/plugin.go
plugins/sandbox/controller.go
```

`packageGuess` constructs import paths by appending the patch directory to `v.Module`. It does not establish that the resulting package belongs to the selected version’s implementation.

Source: `internal/rootcause/rootcause.go:195–207`.

In the actual v1.7.27 source:

```text
services/server/server.go:70
    CreateTopLevelDirectories

pkg/cri/cri.go:58
    initCRIService

runtime/v2/manager.go:135
    NewShimManager
```

For example, `services/server/server.go:80` creates `config.Root` with `0711`. The defect exists under the **v1 package identity**, not `cmd/containerd/server`.

There is a version-correct upstream backport: [containerd commit `0450f046…`](https://github.com/containerd/containerd/commit/0450f046e6942e513d0ebf1ef5c2aff13daa187f). Its [patch](https://github.com/containerd/containerd/commit/0450f046e6942e513d0ebf1ef5c2aff13daa187f.patch) changes:

- `pkg/cri/cri.go`;
- `services/server/server.go`;
- comments in `runtime/v2/manager.go`.

This confirms that merely relocating an identically named function is insufficient: the runtime candidate changes from an `init` in the captured layout to `NewShimManager` in v1.

The persisted Helm package list contains exactly these containerd packages:

```text
errdefs
filters
pkg/randutil
content
archive/compression
labels
images
remotes
```

So the actual v1 server/CRI/runtime packages are absent too. **The desired conclusion is supportable, but the current case has not persisted the correct version-bound subject proof.** The emitted NEPF must not be accepted merely because the guessed paths are absent.

## 3. Correct candidate-absence rule

Separate three propositions:

1. **Identity:** this is a relevant subject of this exact advisory entry and selected implementation.
2. **Physical absence:** its package is absent from the recorded product closure.
3. **Negative sufficiency:** the verified absence covers the vulnerability’s required execution subjects within the assessment’s authorized scope.

A complete package inventory establishes proposition 2. It does not automatically establish 1 or 3.

### A. Subject identity

For an advisory declaration, retain its authoritative identity and existing binding rules.

For a fix-derived candidate, require:

- exact advisory record ID and document digest;
- original affected-entry references;
- affected module and effective selected version/source;
- an advisory-bound fix artifact;
- a checked mapping from the patch’s source coordinates to the selected implementation;
- evidence locating the mapped package/function in that implementation.

Prefer the version-correct backport or fixed-version artifact. A fix on another release line is admissible only through an explicitly verified mapping. **Do not use suffix similarity, a matching function name alone, or `module + patch-directory` as negative-proof authority.**

An unmapped path remains an unresolved candidate/binding obligation. Its absence is not evidence that the selected-version defect is absent.

This also fixes the current reference flattening: `fix.Resolver.Resolve` annotates every reference with the aggregate fixed-version list, while root-cause resolution stops after one patch. Neither operation establishes per-entry applicability (`internal/fix/fix.go:27–38`, `internal/rootcause/rootcause.go:72–140`).

### B. Complete recorded inventory

Continue to require both:

- `domain.SelectCompletePackageList`;
- `affected.CompletePackageInventory` and its existing graph validator.

The measurement must be completed, complete, context-matching, nonempty, fully decoded and edge-closed. Preserve rejection of package errors, duplicates, dangling edges, inconsistent inventories and orphan nodes.

Sources: `internal/domain/measurement.go:101–137`, `internal/affected/golist.go:224–273`, `internal/affected/usage_scope.go:135–263`.

A loader failure, missing vendor directory, empty search, incomplete source census, or dependency source lookup is not a substitute.

### C. Scoped target

A verdict-eligible build-dependent negative still needs a valid scoped product target matching the effective GOOS, GOARCH, tags, CGO and complete recorded build identity.

Matching host defaults are not provenance. Conversely, once an operator/artifact target is admitted, dependency source being loadable does not make its package product-linked.

Keep the current excluded-build-import check and its conservative behavior.

### D. Whole-subject coverage and independent verification

For the relevant nonempty subject set:

- **Every package absent:** produce a candidate `FALSE / package-absent`.
- **Some package linked:** absence alone cannot close the grouped condition. The linked subjects require their own admitted proof.
- **Any unresolved identity or uncovered authoritative subject:** no negative closure.

Then retain `Verifier.VerifyFalse → verifyLocusAbsent`, which independently re-derives package absence and records `VERIFIED` with the effective build context.

Sources: `internal/evaluator/conditions.go:118–144`, `internal/goanalysis/negative.go:34–56,135–143`, `internal/goanalysis/locusverify.go:27–96`.

Neither `RootCause.Absent` nor membership in `AbsentSubjects` is itself a verified mandatory FALSE.

### E. Exact-record negative scope

Keep `AdvisoryScope.AllowsNegativeClosure` unchanged:

- exact, matching GO/GHSA request and resolved identity;
- `ADVISORY_ENTRIES / COMPLETE`;
- `FULL_RECORD`;
- valid digest-pinned census;
- nonempty, fully represented original entries;
- no omitted, non-Go or unnamed-module entries.

This is necessary closure authority, **not proof that the chosen fix candidates exhaust the defect**.

Source: `internal/domain/advisory_scope.go:182–219`.

## 4. Verdict rule and the empty-declaration problem

### Candidate absence does not imply `NOT_AFFECTED`

`NOT_AFFECTED` belongs exclusively to the deterministic affected chain.

For a module/version-only advisory, the affected resolver explicitly refuses to invent package-level subjects. Its module-level absence route requires **zero packages from the relevant module in the compiled product scope**.

Sources: `internal/affected/resolver.go:681–757`, `internal/evaluator/verdict.go:216–300`.

Helm compiles containerd client packages. Therefore:

```text
ModulePresent  = TRUE
VersionAffected = TRUE
PackagePresent = UNKNOWN
BuildRelevant  = UNKNOWN
```

is consistent with a subsequent reachability NEPF. Absence of the daemon packages must not rewrite those affected facts to FALSE.

**A fix-derived candidate’s absence alone can never ground `NOT_AFFECTED` for a declaration-free advisory.** An independent module/version/whole-module-build/implementation proof could still earn `NOT_AFFECTED`; that is a different proof, not a promotion of candidate absence.

### What can ground NEPF when declarations are empty?

A **nonempty, admitted, version-bound defect-subject set**, whose completeness/necessity is supported by the record and fix/source evidence.

Not merely:

```text
no advisory symbols
AND every function our parser happened to extract is absent
```

That would turn incomplete candidate discovery into a false negative. In particular, an added check or enabler is not automatically the vulnerable execution locus.

The resulting negative remains:

> For this exact record, selected implementation and admitted build, the required defect execution cannot occur because its verified subject packages are absent.

It is NEPF, not component absence.

### Preserve declarations when they exist

Keep advisory-declared packages, symbols and admitted prose operations separate from fix-derived candidates.

An absent fix candidate must never:

- remove an advisory-declared subject;
- populate `Vulnerability.AffectedSymbols`;
- manufacture an advisory declaration;
- close a linked declared package merely by covering a narrower guessed symbol set.

Any authoritative subject not covered by the negative stays open.

### Do not reuse `SinkSetBasis` as authority

Despite its name and explanation, current `SinkSetBasis` combines:

```text
Exploit.RootCauses ∪ Vulnerability.AffectedSymbols
```

and calls that set “declared.” A fix-only model can therefore receive declaration-like wording.

That is not the package-absence producer, and it must not become the new fix-derived completeness basis. The existing `ExploitLocusBindingBasis` illustrates the stricter symbol-less binding pattern, but its trigger-carrier contract is not automatically applicable to directory permissions.

Source: `internal/goanalysis/sinkclosure.go:23–93,96–190`.

## 5. Chosen implementation design

No new verdict, alternate evaluator, or CVE-negative shortcut.

### Candidate provenance and binding

Extend the existing root-cause model with typed origin and a replayable fix-candidate-set binding. The binding should carry:

- record pin and affected-entry references;
- selected module/version/source identity;
- complete fix artifact reference and digest;
- patch coordinates → selected-version subject mappings and source evidence;
- complete candidate enumeration and explicit unresolved mappings;
- the evidence supporting defect-subject coverage.

Use the existing evidence infrastructure. Do not derive authority from the free-text `Mechanism` field or an unverified `Complete=true`.

Persist the complete patch or its existing artifact representation; the current 64-KiB report truncation must not become the replay input.

### Absence production

After subject identity is admitted, check package membership **before product-independent symbol lookup**:

```text
admitted subject identity
    → admitted closure says package absent
        → record absent + inventory evidence
    → otherwise perform source verification as needed
```

This fixes the source-hit ordering defect without allowing invented paths to become proof.

The builder may retain the present `AbsentSubjects ⊆ UnresolvedSubjects` representation. It must preserve the binding and authoritative coverage obligations. Empty sets never close by vacuous truth.

### Verification and replay

Keep the existing package-absence verifier. Add admission of the subject-set binding before a fix-derived negative can ground the verdict, including persisted replay.

A legacy saved `absent=true` or `VERIFIED` without the required binding is non-admitting—not reconstructed from its prose.

Run the existing defect-semantics admission before NEPF exactly as today. In particular, absence of an omitted check’s body must not substitute for absence of the omission-site pipeline.

### Diagnostics

Correct these misleading statements:

- distinguish **source-verified**, **package-absent**, and **unverified** candidates;
- distinguish **advisory-declared** from **fix-derived**;
- do not emit “sink candidates remain unresolved” solely because verified-absent subjects remain in the positive-blocking list;
- explicitly display “record NEPF; requested CVE negative unsupported” when that is the result;
- do not label package inclusion TRUE when the affected package axis is UNKNOWN.

Update `docs/dev/analysis-internals.md`, `docs/dev/gap-analysis.md` and `eval/README.md` with the resulting contract and observable behavior.

## 6. Expected result for Helm

### Exact `GHSA-pwhc-rpq9-4c8w` assessment

**Expected earned verdict: `NO_EXPLOIT_PATH_FOUND`.**

Required evidence:

1. Exact GHSA bytes and full 4-entry record census.
2. Containerd v1.7.27 applicability, with the other module entries independently accounted for.
3. Version-correct fix/source binding—using the v1 backport rather than guessed v2 paths.
4. Coverage of the actual v1 directory-permission defect subjects. The backport identifies `services/server.CreateTopLevelDirectories` and `pkg/cri.initCRIService`; the runtime comment-only change must not be misrepresented as a new defect.
5. Complete matching product inventory showing those packages absent.
6. Scoped target provenance.
7. Mandatory reachability FALSE with independently `VERIFIED` package absence.
8. Unchanged semantic, review and exact-record scope admission.

The existing recorded closure does **not** by itself establish the actual v1
package absence: the saved proof's subjects were guessed from another release
line. What needs correction is the binding into the proof, and that binding is
only evidence once a complete proof over the exact selected source and the
complete recorded inputs re-admits at the shared boundary.

`C-INPUT` need not become TRUE or be fully traced once an admitted mandatory reachability FALSE suffices. Do not fabricate input evidence; retain the existing rule that an unverified mandatory FALSE can still block closure.

### Requested `CVE-2024-25621` finding

**It remains `FAILED / UNSUPPORTED_NEGATIVE_SCOPE` under the saved request.**

Do not lift record NEPF to the CVE. Furthermore, simply adding a corpus declaration is not sufficient: the current corpus-negative contract requires independently earned `NOT_AFFECTED` results for nominated candidates, not relabeled NEPF results (`internal/domain/corpus_scope.go:294–311`).

Requesting the exact GHSA explicitly can publish its own NEPF. Silently changing the requested identity cannot.

## 7. Blast radius

The measured failures are not one homogeneous absence bug:

| Case | Recorded shape | Covered by this design? |
|---|---|---|
| Helm `b76a950`, CVE-2024-25621 | Fix-only subjects guessed from a v2/main-line layout; the saved record NEPF is withdrawn; incorrect version-layout binding; CVE scope still fails | **Yes** for binding/diagnostics; not a CVE-negative shortcut; record NEPF only through a complete fresh proof |
| Trivy `37da98d`, CVE-2024-32473 | Module-only advisory; fix-derived `libnetwork/osl` candidates already resolved absent; FALSE refused for host-default target | Same proof family; target/scope gates must remain. Binding still needs admission |
| Rancher `4dc4f53`, CVE-2025-58181 | Declared SSH symbols; package/build TRUE; reachability/input/locus unresolved | **No.** Linked-package proof work, not candidate absence |
| Rancher `4dc4f53`, CVE-2025-47914 | Root cause `NOT_FOUND` for the selected GHSA; no candidates | **No.** Discovery/binding obligation; absence cannot operate on no subjects |
| Headscale `e172c29`, CVE-2024-45338 | Declared HTML parser subjects; package/build TRUE | **No.** Independent reachability/input proof |
| Echo `fdacff0`, CVE-2020-26160 | Linked declared JWT check; reachability and same-invocation trigger/input gaps | **No.** Preserve defect-semantics admission |
| Go-zero `bae061a`, CVE-2022-32149 | Record already `NOT_AFFECTED` by version; requested CVE fails scope | **No.** Composition distinction only |

Evidence: `va-review1/bench/vex-recheck/results.jsonl:2,4–9,15` and the corresponding `report.en.md` claim/limitation sections.

Other package-list failures—such as the measured Cilium, Podman and Moby rows—cannot be closed by treating their incomplete inventories as absence.

**One generic rule covers legitimate unlinked, fix-derived subjects. One blanket change cannot close every `REACHABILITY_PROOF_INCOMPLETE` row.**

## 8. Required tests

1. **Source-present but product-unlinked:** candidate resolves from module cache/vendor; package absent from a complete closure. Absence is recorded despite lookup success.
2. **Cross-version layout counterexample:** v2 patch path absent, actual v1 defect package linked. No absence-based NEPF.
3. **Version-correct backport:** map the v1 patch to actual v1 subjects; all absent → verified NEPF, never `NOT_AFFECTED`.
4. **Unmapped/ambiguous subject:** missing mapping, changed symbol, added-only check or incomplete patch enumeration → no negative closure.
5. **Declaration protection:** absent fix candidates beside a linked/unresolved advisory-declared subject do not close it.
6. **Empty declaration controls:** no subjects, unbound candidates, or only a candidate-list boolean never authorize closure; a complete admitted nonempty binding can authorize NEPF.
7. **Inventory rejection matrix:** incomplete execution, truncated JSON, package errors, duplicates, dangling/orphan nodes, context mismatch and missing typed metadata remain non-admitting. Extend existing `partiallist_test.go` coverage.
8. **Target matrix:** host-default refused; matching scoped target admitted; foreign target/build verification refused.
9. **Mixed presence:** one absent and one linked subject cannot produce an all-absent FALSE. Linked `init` cannot be deemed unreachable from zero explicit callers.
10. **Negative verification/replay:** linked counterexample contradicts FALSE; missing binding or altered record/patch/source/inventory digest invalidates saved proof.
11. **Verdict dominance:** verified reachability FALSE may suffice beside UNKNOWN input; an unverified mandatory FALSE still blocks as required.
12. **Composition:** exact GHSA NEPF versus CVE `FAILED`; even a declared corpus cannot reinterpret candidate NEPF as `NOT_AFFECTED`.
13. **Invariant controls:** unchanged library-API admission, transport-peer admission, positive-only composition and defective-check/omission semantics.
14. **Presentation:** absent candidates are not described as failed source verification; record and requested outcomes remain distinct across publication surfaces.

Implementation handoff: preserve these boundaries. If selected-version mapping or defect-subject completeness cannot be established, retain a typed failure; do not repair it by relaxing scope, synthesizing declarations or promoting candidate absence into an affected-chain fact.

**Read-only investigation completed. No repository edits, builds or tests were run.**

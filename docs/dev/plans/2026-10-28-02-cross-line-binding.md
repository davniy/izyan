# DESIGN_FOR_REVIEW — READY

> **Status: withdrawn, then re-landed under the sound contract (2026-10-28).**
> The original implementation of this design (Slice B, commits `93ec9c3` and
> `ba782d1`) did not satisfy the sound admission contract and was reverted. Its
> saved conclusions — including the Helm `NO_EXPLOIT_PATH_FOUND` — remain
> **non-admitting historical evidence** and are never revived. The contract
> itself has since been implemented as a pure checker in `internal/fixbinding`
> and activated through the persisted proof record (`domain.FixProof`): a
> binding is authority only when the checker re-derives it from the complete
> captured input bundle at the shared absence boundary. See
> `2026-10-28-03-withdraw-and-reland-binding.md` for the contract and
> `docs/dev/analysis-internals.md` §"Re-land Task 9" for what is actually
> measured. The analysis pipeline does not yet capture patch-side source or
> effective external components, so the full content-proof route currently
> fails closed with a named input obligation; the same-line exact-preimage route
> is active and measured end to end. Where a complete proof is unavailable the
> honest outcome stays `FAILED / CODE / ROOT_CAUSE_UNRESOLVED`, obligation
> `ROOT_CAUSE`.

**Decision: allow content-derived cross-release-line binding, but admit it as a verified operation-to-selected-source mapping—not as a marker-search heuristic.**

A version-correct backport is preferable evidence, **not a prerequisite**. The analyzer may use the captured main/v2 patch and the selected v1 source, offline, to establish the mapping. It must separately prove:

1. **Identity:** where the advisory’s defect operations live in the selected implementation.
2. **Coverage:** that the mapped set covers every relevant alternative.
3. **Product fact:** that those actual subjects are absent from the admitted product build.

Finding a marker proves neither coverage nor package absence.

For Helm, a complete content-derived binding can earn exact-record **`NO_EXPLOIT_PATH_FOUND`**. Without that binding, the correct outcome is **`FAILED / CODE / ROOT_CAUSE_UNRESOLVED`**, obligation **`ROOT_CAUSE`**. The saved NEPF on guessed v2 subjects must not survive replay.

No user-owned question is necessary.

## 1. Admissible content-derived mapping

### Inputs and authority

Use only:

- the exact, digest-pinned advisory document and original affected-entry references;
- captured complete patch bytes linked by that document;
- the effective selected dependency source, including replacement/vendor provenance;
- recorded build and product measurements.

A `WEB` commit reference is admissible as a **candidate fix locator**. Lack of `type=FIX` does not prohibit using its captured content. Conversely, the reference’s URL shape does not establish applicability or completeness. The patch’s security changes must bind to the record’s own mechanism and the relevant affected entry.

**A URL without captured bytes is not patch evidence. No analysis-time fetch or backport discovery is permitted.**

The current resolver’s aggregate `FixedVersions` annotation and “one authoritative patch is enough” stopping rule do not establish this binding (`internal/fix/fix.go:27–38`, `internal/rootcause/rootcause.go:77–144`).

### Markers nominate; structural verification admits

Extract a compound description of each security-relevant changed operation:

- the operation/API and its resolved identity;
- the resource/operand it acts on;
- changed values or predicates;
- relevant surrounding control/data flow;
- the pre-existing operation, or the pre-existing pipeline where a newly added enforcement operation belongs.

Search the **selected source tree**, independently of patch paths and product linkage. Then verify the complete relation at each proposed location.

For example:

```text
directory creation
+ permission 0711
+ operand derived from daemon config.Root
+ neighbouring Root/State validation
```

is substantially stronger than either `0711` or `CreateTopLevelDirectories` alone.

Permitted deterministic normalization includes:

- formatting and ordinary comments;
- equivalent numeric spelling, such as `0711` and `0o711`;
- resolved import aliases;
- local identifier renaming when its binding and use relationships are preserved.

It must not erase differences in resource identity, receiver/type, branch conditions, module ownership or behavior. Cross-version resource representations require an explicit checked equation, not fuzzy normalization.

**Neither function-name equality, suffix similarity, path similarity, literal equality, nor a similarity score authorizes a negative.** They may prioritize candidates only.

### Fix-added operations bind to their omission site

An added `Chmod`, guard or helper normally does **not** exist in vulnerable source. Requiring that added operation to be found would make this route unusable.

Instead, verify the selected-version **existing pipeline and resource** where enforcement was omitted. For an added CRI directory hardening step, the subject can be the existing CRI initialization operation that supplies the same state directory to the service.

This does not permit treating “the added function is absent” as the defect being absent. The omission-site pipeline remains the subject. Preserve the existing omitted-check/defective-check semantic admission.

### Match outcomes

- **Verified operation correspondence:** admit the selected-source location.
- **Several verified implementations of the same operation:** retain their union.
- **Several competing interpretations:** unresolved; do not select the absent candidate.
- **No match:** unresolved—not fixed, not absent.
- **Comment-only executable-equivalent change:** account for it explicitly; it does not create a defect subject.
- **Another-line operation with no selected-line counterpart:** discharge only through a structural non-counterpart proof over a complete relevant source census. Zero marker hits are insufficient.

The mapping establishes subject identity. **It is not a complete fixed-implementation proof and must not feed `NOT_AFFECTED`.**

## 2. The subject set is selected-version code

The binding’s subjects are the **images of the verified operation mapping in the selected implementation**. Patch coordinates remain provenance.

For Helm/containerd v1.7.27, the principal located subjects are:

```text
github.com/containerd/containerd/services/server.CreateTopLevelDirectories
github.com/containerd/containerd/pkg/cri.initCRIService
```

They are not:

```text
.../cmd/containerd/server.CreateTopLevelDirectories
.../core/runtime/v2.init
.../plugins/cri/runtime.initCRIRuntime
.../plugins/sandbox.init
```

The available evidence supports these correspondences:

| Patch mechanism | Selected v1 correspondence | Required treatment |
|---|---|---|
| Daemon root and configured temporary-directory permissions; added upgrade enforcement | `services/server.CreateTopLevelDirectories` | Match resource operands, mode changes and surrounding branches. |
| CRI state-directory creation/enforcement | `pkg/cri.initCRIService` | Bind the added enforcement to the existing initialization pipeline through plugin identity and state-directory data flow. |
| `core/runtime/v2/task_manager.go` | No new defect subject | The captured hunk adds only comments. Its `0711` operation is unchanged and explicitly intentional. |
| Sandbox-controller `shim` root/state hardening | No automatic v1 `plugins/sandbox.init` mapping | v1 registers a `local` controller with a different body. Prove the affected `shim` operation has no selected-line counterpart, or retain it unresolved. |

The CRI correspondence is particularly concrete:

```text
GRPCPlugin type = "io.containerd.grpc.v1"
registration ID = "cri"
registration URI = type + "." + ID
InitContext.State = join(daemon state, registration URI)
criconfig.Config.StateDir = InitContext.State
```

That resolves the patch’s `"io.containerd.grpc.v1.cri"` resource to v1’s initialization pipeline without matching filenames or function names.

Sources: selected `containerd@v1.7.27/services/server/server.go:70–112`, `pkg/cri/cri.go:43–119`, `plugin/context.go:48–53`, `plugin/plugin.go:62,143–144`.

**The two principal locations are not automatically a complete set.** In particular, `server.NewCRIService` and `sbserver.NewCRIService` are exported. An in-tree observation that normal daemon initialization calls them does not exclude an embedding product calling them directly. The coverage witness must discharge such bypasses or include their actual operation carriers.

## 3. Completeness is a separate admission gate

Define, per original entry and mechanism, a nonempty selected-version subject set \(S\). The necessary coverage proposition is:

\[
\text{execution of the advisory defect}
\;\Longrightarrow\;
\bigvee_{s\in S}\text{execution of }s
\]

The all-absent falsifier can close this necessary disjunction. Individual alternative sites must not be turned into separate mandatory conjuncts.

A negative requires **all** of the following.

### A. Complete fix/mechanism accounting

Persist an inventory of all relevant security effects in the available fix material and advisory mechanism. Every effect must be:

- mapped to selected code or a verified omission-site carrier;
- accounted for as non-executable;
- proved inapplicable to that selected implementation;
- or explicitly unresolved.

Enumerating every function returned by the current parser is not this inventory. Nor does processing the first successful patch establish fix-series completeness. References whose relevance remains unknown cannot silently disappear.

### B. Complete selected-source operation cover

The census must cover the relevant selected implementation, **including dependency packages not linked into the product**. Searching only product-loaded packages would make discovery depend on the absence being proved.

The checker must account for:

- split/merged implementations;
- all semantically matching sites;
- relevant wrappers and indirect resource derivation;
- initialization and upgrade paths;
- alternative registrations and constructors;
- selected build variants and existing dynamic/coverage constraints.

For Helm, this includes:

- daemon root;
- configured temporary directory;
- CRI state directory;
- the sandbox-controller mechanism;
- both legacy and experimental CRI service branches.

The v1 CRI services create descendants with `0755`; those sites are relevant coverage evidence even though the v2 patch adds enforcement earlier. They may remain behind an admitted necessary initialization carrier **only when that carrier’s necessity is verified for the assessed product**. Otherwise include the bypass operation sites or leave the cover unresolved.

### C. Complete product falsification

Every subject in the admitted cover must have absent packages under the existing complete, context-matching inventory and scoped-target rules. An absent subset does not close a linked or unresolved remainder.

This implements the repository’s existing separation:

```text
NECESSITY
→ SCOPE_COMPLETENESS
→ PRODUCT_FACT
→ FALSIFIER_SUFFICIENCY
→ negative verification
```

The package-absence checker proves only the product fact. Patch membership and natural-language agreement do not prove the semantic bridge (`docs/dev/specs/llm-cve-analysis-spec.md:351–399`).

### Partial results remain blocking

A partially located set is useful evidence, but stays **incomplete and positive-blocking**. Preserve unresolved operation obligations even when they have no package name yet.

Neither:

- `RootCause.Status=RESOLVED` because one candidate exists;
- `allUnresolvedAbsent`;
- an empty subject list;
- nor `Complete=true` without supporting premises

may erase those obligations.

## 4. Failure and replay

### Fresh analysis

With complete inputs but absent, ambiguous or incomplete mapping:

```text
assessment_outcome: FAILED
verdict:            absent
gap.owner:          CODE
gap.code:           ROOT_CAUSE_UNRESOLVED
gap.obligation:     ROOT_CAUSE
```

Use the existing diagnostic distinctions for missing prerequisites:

| Missing prerequisite | Existing typed failure |
|---|---|
| Required patch/proof artifact unavailable or truncated | `PROOF / PROOF_ARTIFACT_MISSING / ROOT_CAUSE` |
| Selected-source input cannot be resolved | `INPUT / INPUT_RESOLUTION_FAILED / ROOT_CAUSE` |
| Source available, but correspondence or operation coverage cannot be established | `CODE / ROOT_CAUSE_UNRESOLVED / ROOT_CAUSE` |

Keep affected claims and exploit claims `UNKNOWN` where unproved. These are analyzer-owned failures, not environmental `INCONCLUSIVE`.

A guessed patch path can remain a diagnostic candidate. **Its absence must not create an admitted `RootCause.Absent`, absence subject, or negative claim.**

An independent sufficient proof is not invalidated merely because this candidate route failed; no existing gate is relaxed.

### Persisted evidence

Persist one replayable binding containing:

- exact record pin and original entry references;
- effective module/version/source identity;
- complete patch bytes or durable artifact reference plus digest;
- operation inventory and dispositions;
- selected-source locations, evidence and resource relationships;
- source-census boundary and completion evidence;
- unresolved obligations;
- admitted subject set and necessity/coverage proof.

Re-admit it at the shared deterministic verdict boundary, not only in the producer. The negative verifier must then independently verify absence of the **admitted selected-version subjects**.

For an already-persisted NEPF on guessed subjects:

1. Missing binding means **no admitted binding**, not a legacy exemption.
2. The dependent saved FALSE/VERIFIED claims cannot ground the verdict.
3. Reassessment produces the typed root-cause failure unless another independent proof suffices.
4. Existing publication admission refuses the saved conclusion when it differs from current admission. Preserve historical evidence and the old result; do not silently rewrite or grandfather it.

This follows `internal/evaluator/verdict.go:24–28,95–146` and `internal/finding/project.go:197–298`.

## 5. Helm: what can actually be earned

### What the offline evidence contains

The captured patch accounts for more than one permission marker:

- root and temporary-directory mode changes;
- added upgrade `Chmod` operations;
- added CRI state-directory enforcement;
- sandbox-controller root/state hardening;
- runtime comments that deliberately preserve `0711`.

It also contains an anomaly: inside the temporary-directory branch the added `Chmod` targets **`config.Root`**, not `config.TempDir`. Preserve that fact. Do not silently repair the patch in the mapping. It does not prevent locating the existing carrier for a package-absence proof, but it cannot support an invented claim that temporary-directory upgrade enforcement was verified.

Evidence: `EV-005` in `/tmp/c-helm3/GHSA-pwhc-rpq9-4c8w-1793092845/report.json:1306–1309`.

### Expected outcomes

| Evidence available and admitted | Exact `GHSA-pwhc-rpq9-4c8w` outcome |
|---|---|
| Complete content-derived mapping and operation cover; complete matching product inventory; scoped target; independently verified mandatory absence falsifier; existing review/semantic/scope gates satisfied | **`DECIDED / NO_EXPLOIT_PATH_FOUND`** |
| Only raw markers or a partial correspondence | **`FAILED / CODE / ROOT_CAUSE_UNRESOLVED`**, obligation `ROOT_CAUSE` |
| Patch URL but no captured patch bytes | **`FAILED / PROOF / PROOF_ARTIFACT_MISSING`**, obligation `ROOT_CAUSE` |
| Complete mapping, but invalid target/inventory/negative verification | **`FAILED`** through the existing relevant gate |
| Saved NEPF on the four guessed v2 subjects | **Non-admitting on replay** |

The latest captured package inventory includes containerd client/error code but not the actual daemon/CRI packages. That supports the product-absence part of a corrected proof. It does not retroactively supply identity or completeness.

The exact-record NEPF additionally requires the full four-entry census: selected v1 entry properly bound; the three `/v2` entries independently accounted for. No evidence may be inherited merely because the entries share an advisory.

**Therefore: the recovered expected exact-record verdict is NEPF; the current saved proof has not earned it soundly.** A full content-derived witness can replace that proof without obtaining `0450f046…`. Raw content matches alone cannot.

### Requested CVE

For the saved `CVE-2024-25621` request, the requested finding remains **`FAILED / UNSUPPORTED_NEGATIVE_SCOPE`**. Exact-record NEPF does not become CVE-wide closure.

Candidate absence never becomes `NOT_AFFECTED`. Preserve `ModulePresent=TRUE`, `VersionAffected=TRUE` and the existing affected-axis distinctions. The current corpus-negative contract also does not reinterpret nominated-record NEPF as `NOT_AFFECTED`.

## 6. Measured blast radius

The measured cases are not one class of cross-line failures.

| Case | Observed issue | Effect of this rule |
|---|---|---|
| **`helm-helm-b76a950-CVE-2024-25621`** | Main/v2 patch used to construct nonexistent v1 package identities. Latest exact-GHSA scoped run emits NEPF. | **Revoke that proof on replay.** Complete content-derived v1 binding can re-earn record NEPF. Requested-CVE scope failure remains. |
| **`helm-helm-fbb24fe-CVE-2021-21334`** | Patch from `containerd/cri` PR 1628 produced `github.com/containerd/containerd/pkg/server.criService.containerSpec` by prefixing the wrong module. | Requires an explicit selected-source/component mapping. Latest retained report and later calibration ledger are unresolved, so **no demonstrated safe verdict is revoked**. Missing mapping uses typed failure under the current contract. |
| **`aquasecurity-trivy-37da98d-CVE-2024-32473`** | Checked specifically: Docker v26.0.1 versus same-line v26.0.2 fix; `libnetwork/osl` preimage exists at the selected coordinates. | **Not cross-line.** Binding can be established; existing target/scope failures remain. No verdict change from this rule alone. |
| **`kubernetes-kubernetes-e196d24-CVE-2023-44487`** | Captured patch was a CBL-Mariner distribution `.spec` change, not selected x/net implementation code. It produced no Go subjects. | Cannot acquire implementation authority through the URL. **No existing verdict-bearing candidate negative changes.** |
| Rancher SSH, Headscale HTML, Echo JWT, go-zero version-negative controls | Declared subjects, linked-code proof gaps or independent version facts—not the measured cross-line candidate-absence defect. | **No change from this rule alone.** |

Evidence for the second Helm case is the retained `eval/agent7/results/b0-baseline-retry/helm-helm-fbb24fe-CVE-2021-21334/...json` and `docs/dev/reports/2026-10-25-05-scope-bound-version-negatives-calibration.md:142`.

The other Helm case demonstrates **foreign-module fix-coordinate conflation**. Its exact v1.4.3 component layout was not independently reconstructed in this investigation; no stronger source-equivalence claim is needed to reject the invented package identity.

These are evidence-based impact statements, **not a new benchmark run**.

## 7. Required tests

1. **Layout relocation:** v2 patch paths absent, v1 actual defect package linked. Never produce absence-based NEPF.
2. **Successful offline content binding:** no backport and no network; complete patch plus selected source yields actual v1 subjects and, when absent, verified NEPF.
3. **Weak-match rejection:** matching name, suffix, mode constant or unrelated same-shaped operation alone admits nothing.
4. **Safe normalization:** numeric spelling/import aliases/local renaming preserve a verified relation; changed resource, receiver or branch does not.
5. **Added enforcement:** missing added `Chmod` binds to a verified omission-site carrier—not to absence of the new operation.
6. **Full operation coverage:** root found but temporary-directory/CRI/sandbox obligation unresolved blocks closure. Empty sets never close.
7. **Alternative implementations/bypasses:** both CRI branches covered; direct exported-constructor use defeats a two-carrier proof unless separately covered or discharged.
8. **Comment-only and non-counterpart:** runtime comments do not create a sink; v1 `local` sandbox controller is not accepted as v2 `shim` by path/name similarity.
9. **Mixed presence:** one absent and one linked subject cannot yield the grouped all-absent FALSE.
10. **Source versus product scope:** source present outside the product closure is discoverable and can subsequently be proved unlinked; pruned vendor source is not a complete selected-source census.
11. **Artifact/census rejection:** truncated patch, partial series, missing source, incomplete scan, invalid inventory and host-default target remain non-admitting.
12. **Replay:** missing or mutated record/patch/source/census/subject binding invalidates saved NEPF; history remains; publication refuses unsupported saved closure.
13. **Wrong-module control:** Helm CVE-2021-21334 cannot manufacture a `containerd/pkg/server` identity from a `containerd/cri` patch.
14. **Verdict/scope invariants:** exact-GHSA NEPF versus requested-CVE failure; no candidate-derived `NOT_AFFECTED`; declarations, semantic review, transport/library admission and existing negative gates unchanged.

## Implementation handoff

Extend the existing typed candidate-binding evidence and shared admission path; do not add another evaluator or use free-text `Mechanism`/`Complete` assertions as authority. Document the revised §3.A, completeness rule, replay invalidation and measured outcomes in the existing design/internal documentation and evaluation notes.

The material design unknowns are resolved:

- **P0 identity authority:** content mapping permitted only with checked structural/resource correspondence.
- **P0 completeness:** separately verified operation cover; partial sets fail closed.
- **P0 saved unsound negative:** re-admission required, no grandfathering.
- **P1 unsupported transformations or incomplete local source:** bounded by the existing typed failure route.

If implementation cannot verify the semantic bridge for an operation class, preserve `ROOT_CAUSE_UNRESOLVED`; do not substitute a similarity heuristic or remove the obligation.

**Read-only investigation completed. No files changed, network fetches, builds or tests run.**

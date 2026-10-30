# DESIGN_FOR_REVIEW — Legitimate build configurations without verdict forcing

**Design gate: READY. No user-owned policy question is necessary.**

## 1. Decisions

| Axis | Decision |
|---|---|
| Repository build declarations | **Admissible as explicitly selected, snapshot-pinned operator input.** A Makefile is authoritative about a recipe it defines—not about which recipe built the shipped product. Do not automatically infer a trusted target or tags from it. |
| cgo | **Supported for source analysis in a target-native, explicitly recorded build environment.** Support native execution and an operator-run target-native container/VM. Do not support cross-cgo in this change. |
| Configuration still unidentified | Report **`EXTERNAL_DEPENDENCY / INCONCLUSIVE`**, but only when the missing build identity is an evidence-bound, answer-changing fact. |
| Configuration identified but not measurable | Report **`FAILED`**, with an existing typed input or measurement gap. Missing compilers, SDKs, headers, unsupported cross-cgo and incomplete analysis are not environmental uncertainty about the product. |
| Alternative configuration compiles | Treat that as a measurement of **that alternative configuration**, not evidence that it is the shipped program. Never search tag combinations until one produces a desired verdict. |

The central separation is:

> **Build-selection facts, authority to apply those facts to the requested product, and capability to measure that build are three different things.**

A successful package load establishes only the last of these.

---

## 2. Existing contracts the design preserves

The relevant code establishes a suitable foundation:

- `internal/repository/service.go:282–317` resolves the target before measurement, preserving artifact/binary build info → release metadata → operator declaration → host default. The operator branch currently hardcodes cgo off.
- `internal/domain/target.go` already represents the complete selection tuple: `GOOS`, `GOARCH`, tags and cgo, with source and scope.
- `internal/domain/buildcontext.go` separates provenance from measurement identity. `Matches` compares tags and cgo; `ValidateNegativeTarget` requires scoped provenance matching the effective snapshot.
- Package loading, `go list` and govulncheck already consume `domain.BuildEnv`. Tags additionally reach their appropriate command/configuration flags.
- `internal/domain/measurement.go` and `negative_admission.go` require completed, appropriately covered measurements; merely having output is insufficient.
- `internal/finding/outcome.go:41–135` already implements sufficient proof first, otherwise analyzer-owned blockers → `FAILED`, otherwise admissible external dependencies → `EXTERNAL_DEPENDENCY`.
- `internal/finding/project.go` is the publication-time re-admission boundary. New provenance must be checked there, not merely accepted during CLI intake.

Two existing omissions become important once cgo is supported:

1. `ProductTargetScope` and `TargetScopeMatch` compare platforms and tags, **but not cgo**.
2. The current execution environment is not entirely captured by `BuildContext`: compiler selection, native flags and SDK contents can change a cgo measurement without changing its recorded identity.

Both must be addressed; adding a boolean flag alone is insufficient.

---

## 3. Repository declarations: admissible, but not automatically authoritative

### 3.1 Adjudication of the heuristic prohibition

A repository build declaration is **not categorically exempt** from the prohibition.

These are different propositions:

1. “This pinned Makefile defines recipe R with these inputs.”
2. “Recipe R was used to build the product being assessed.”

Reading the Makefile can establish the first. It generally cannot establish the second.

Therefore:

- A literal assignment is evidence of that assignment.
- A named recipe and its explicitly supplied overrides can describe a legitimate operator-selected build.
- Neither becomes a release fact merely because it resides in the repository.
- Conditional assignments, includes, shell substitutions, environment-dependent probes and command-line overrides prevent treating a variable’s textual value as the effective value.
- Do not execute `make`, including `make -n` or `make -p`, during discovery. Makefile expansion itself may execute `$(shell ...)`.

**No new `repository-inferred` provenance source is introduced.**

A repository-referenced declaration occupies the existing **`operator-declared` / `operator`** slot. `ProductTarget.Authoritative()` remains unchanged.

An actual release assertion belongs in the existing `release-metadata/1` channel. Embedded artifact settings remain higher-precedence measured facts.

### 3.2 Supported input

Add:

```text
--declared-build-config <path>
--cgo=on|off
```

The document is the preferred reproducible input. It contains an already resolved, literal selection—not instructions for evaluating Make.

Repository inspection is limited to checking explicitly cited, contained files and retaining their bytes. There is no automatic Makefile-variable discovery or recipe-selection engine.

---

## 4. Exact declaration and provenance contract

### 4.1 Document

Use a strict sibling of the existing declared-assumptions input, not a new assumption kind:

```go
type BuildSelection struct {
    GOOS       string   `json:"goos"`
    GOARCH     string   `json:"goarch"`
    BuildTags  []string `json:"build_tags"`
    CGOEnabled bool     `json:"cgo_enabled"`
}

type BuildSnapshotPin struct {
    Commit      string `json:"commit"`
    ContentHash string `json:"content_hash"`
}

type BuildFileRef struct {
    Path      string `json:"path"`       // contained, repository-relative
    SHA256    string `json:"sha256"`
    FirstLine int    `json:"first_line"`
    LastLine  int    `json:"last_line"`
    Selector  string `json:"selector"`   // recipe/variable; explanatory only
}

type BuildVariable struct {
    Name  string `json:"name"`
    Value string `json:"value"`          // literal, already resolved
}

type BuildRecipeRef struct {
    EntryPoint string          `json:"entry_point"`
    Files      []BuildFileRef  `json:"files"`
    Overrides  []BuildVariable `json:"overrides"`
}

type DeclaredBuildConfigDocument struct {
    Schema    string           `json:"schema"` // declared-build-config/1
    ID        string           `json:"id"`
    Owner     string           `json:"owner"`
    SourceRef string           `json:"source_ref"`
    Snapshot  BuildSnapshotPin `json:"snapshot"`
    Variant   string           `json:"variant"`
    Selection BuildSelection   `json:"selection"`
    Recipe    *BuildRecipeRef  `json:"recipe,omitempty"`
}
```

Normative rules:

- One document identifies **one build variant**, not a supported-build matrix.
- All four selection members are required. Decode presence explicitly: missing/null cgo must not become `false`; missing/null tags must not become a declared empty set.
- `build_tags: []` explicitly means no user build tags.
- Normalize tag order; reject duplicates and retain existing bounds and validation.
- Reject unknown fields, duplicate JSON keys, unsupported schema versions, oversized input and invalid paths. A 64 KiB document bound is sufficient.
- `Recipe` is required when the declaration claims repository-recipe support. An independent operator-defined build may omit it, but must be labelled as such.
- `EntryPoint` records provenance. It does **not** silently replace the analyzer’s package-root or shipping-scope rules.
- A recipe with unresolved substitutions is not a resolved configuration. The operator must provide the effective literal values and the relevant overrides/environment provenance.

This is a build-selection input, not a trust assumption or vulnerability fact. It cannot itself establish reachability, attacker control, trigger feasibility or a negative proof.

### 4.2 Persisted input and target binding

Retain:

- exact document bytes;
- SHA-256 of those bytes;
- sanitized source locator;
- typed intake rejection, if any;
- exact cited file bytes and their pins.

Store the input with the case’s typed inputs. Add an optional `DeclarationSHA256` reference to `ProductTarget`, allowed only for `operator-declared` targets.

The resolved target remains:

```text
Source = operator-declared
Scope  = operator
GOOS/GOARCH/BuildTags/CGOEnabled = the admitted literal selection
DeclarationSHA256 = retained input's exact-byte digest
```

The declaration digest is **provenance**, not build-selection identity. It does not belong in `BuildContext`.

Consequently, an amended declaration with an identical selection may reuse immutable measurements, but only after the new declaration is admitted. Changing provenance cannot authorize a saved verdict merely because the tuple stayed equal.

Hashes establish identity and detect drift; they do not authenticate the operator’s statement.

### 4.3 Snapshot pinning

Require the commit and actual tree hash to match the analyzed snapshot.

Reuse `repository.ContentHash`, which includes build files, scripts and vendor contents and excludes `.git`. Currently `Service.Snapshot` calculates it only for external snapshots; calculate it for declaration-backed ordinary Git snapshots too.

A commit SHA alone is insufficient: an edited Makefile or generated source under the same HEAD must invalidate the binding.

Keep declaration files, caches and outputs outside the immutable product tree to avoid circular or self-changing identity.

### 4.4 Re-admission

Use one shared admission function for declaration-backed targets. It checks:

1. retained bytes against the declaration digest;
2. strict document validity;
3. snapshot commit/content binding;
4. cited-file digests and ranges against retained source bytes;
5. equality of the declaration’s complete selection, `ProductTarget` and effective snapshot;
6. the target’s source/scope constraints.

Apply it at initial resolution, verifier/verdict admission and `finding.Project`, including persisted positives and negatives. Producers receive the already admitted target; no consumer may accept a declaration digest alone.

Live resume also checks the current snapshot before reusing loaded state. Offline publication uses retained, digest-bound inputs rather than reopening a mutable original path.

Legacy records remain readable. Do not invent declaration bytes, explicit cgo intent or successful admission for them.

---

## 5. Resolution and precedence

Preserve whole-record precedence:

```text
artifact build info
  > plain-binary build info
  > release metadata
  > operator declaration
  > host execution defaults
```

Rules:

- Select a **whole tuple**. Never take the platform from an artifact and “repair” it with operator tags or cgo.
- A declaration and selection flags are alternative forms of the operator input. Reject supplying both; do not merge them.
- Higher-precedence facts supersede the operator document. Report the document as not applied, and show the effective tuple.
- If the winning artifact says cgo on, a lower-precedence cgo-off/openpgp declaration cannot turn that artifact into a different program.
- Preserve existing authoritative-channel rejection behavior. Never demote a supplied conflicting artifact merely to make source analysis load.
- Partial operator input remains execution context, not an admitted complete build.

For flag-based declarations, require explicit platform, cgo and tag-set intent:

```text
--goos linux --goarch amd64 --cgo=off --build-tags=''
```

Convert this into the same canonical declaration representation, bound to the snapshot. Do not maintain separate declaration semantics for flags.

Existing commands without these explicit facts may retain their execution defaults, including cgo off, but those defaults must not be presented as newly established product facts. This is an intentional admission tightening, not an automatic host-to-product upgrade.

---

## 6. cgo support and execution identity

### 6.1 Supported mode

Support cgo when:

1. the effective product selection explicitly enables it;
2. the selected Go toolchain’s execution host platform matches the target;
3. the required native compiler, SDK/headers, libraries and `pkg-config` environment are available;
4. their identities and relevant environment are recorded;
5. ordinary package loading and required analysis measurements complete.

On a Darwin workstation, Linux cgo analysis therefore runs inside an **operator-provided Linux environment**. If the target is amd64, that environment must present the corresponding target-native toolchain, including when the container/VM is externally emulated.

**Cross-cgo is unsupported in this design**, even when an operator has a cross compiler. It produces a capability failure, not an inference that the product cannot build.

The analyzer does not install SDKs, launch containers or synthesize compiler flags automatically.

### 6.2 Recorded native context

Add a typed native-build context containing:

- selected Go toolchain identity;
- execution-host platform;
- resolved compiler executable identities and arguments;
- C++ compiler and `pkg-config` identities where used;
- explicit native environment, including relevant `CGO_*`, include/library/pkg-config paths and platform SDK variables;
- pinned SDK/sysroot identity;
- runner image/VM identity when supplied, and identities of native dependency mounts.

A pinned, immutable runner environment is the recommended operational form. A declared image digest alone is not evidence that the current process uses it: retain a trusted launcher record or independently checked toolchain/SDK pins. Mutable host SDKs must be fingerprinted and rechecked before reuse.

Put the canonical native-context digest in `BuildContext`, and compare it in `Matches`. Keep the readable underlying record for diagnostics.

Changing a compiler, macro, SDK, header tree or native flags invalidates cgo measurements and caches. The existing source-tree hash covers in-repository `.c`, `.h` and related inputs; external SDKs require their own binding.

### 6.3 Environment consistency

Continue using `BuildEnv` as the single selection authority, but make all relevant resolved values explicit—including empty values that clear ambient overrides.

In particular:

- reject hidden `-tags` inputs in `GOFLAGS`;
- prevent ambient cgo/compiler/SDK variables from bypassing the recorded native context;
- represent other file-selection inputs, such as tool/architecture feature tags, consistently or refuse the affected proof as unsupported;
- ensure deterministic `go/build` re-selection agrees with the actual Go invocation.

An environment digest is not a substitute for modelling a build constraint the verifier cannot evaluate.

Forward the same context through package loads, extras, inventories, govulncheck and any permitted build/test evidence tools. The latter currently use `ToolEnv` without the complete recorded selection; they must not publish evidence for a different build.

### 6.4 Execution permission and semantic limits

Do not reuse `--allow-exec` as the cgo switch. It gates explicit build/test actions; package loading and govulncheck already invoke the toolchain independently.

Document that cgo-enabled loading can invoke compilers and `pkg-config`. Never execute repository Makefiles, build scripts, generators, tests or product binaries merely to identify a configuration.

Successful cgo compilation does **not** add C/C++ semantic analysis. Existing cgo/native-edge opacity and negative-verification blockers remain. An unsupported native callback or hidden edge is a proof-capability failure, not proof of unreachability.

---

## 7. Measurement integrity and shipped-program correspondence

### What the analyzer can check

It can detect:

- a declaration for the wrong snapshot;
- modified cited build files;
- disagreement with higher-precedence target facts;
- tags/cgo differing between loaders, tools, proofs or saved results;
- incomplete expansion presented as a resolved declaration;
- reuse across changed native environments;
- a witness outside the admitted build/program scope.

Compare **exact tag sets**, not subsets or “tags sufficient to compile”.

### What it cannot infer

The analyzer cannot prove that an undocumented release pipeline used a particular Makefile recipe. It also cannot prove that a handwritten operator declaration accurately describes an unknown distributed binary merely because the declaration is plausible.

Therefore:

- A declaration can authorize assessment of the **declared build**.
- It does not establish that this build equals a particular shipped artifact.
- Artifact/release requests require a binding from the selected source/build to that artifact or release.
- Compare embedded settings and source identity where available, but matching settings alone do not prove byte-for-byte equivalence or shipped entrypoint coverage.
- If actual build/variant correspondence is missing and can change the answer, retain it as an external dependency.
- If correspondence is supplied but the tool cannot verify the relevant program/entrypoint scope, report a capability failure.

A candidate configuration’s positive cannot be relabelled as a shipped-build positive. Equally, a candidate negative cannot clear the shipped product.

This does **not** introduce a blanket govulncheck-success veto: independently admitted proofs for the same requested build, or existing genuinely build-independent proofs, remain usable.

### Unchanged gates

The declaration does not weaken:

- `AdvisoryScope.AllowsNegativeClosure`;
- record extent, census and exact-record binding;
- CVE negative corpus authority;
- completed-measurement and negative-verification admission;
- library-API admission;
- mandatory transport-input admission for `transport-peer`;
- per-record/profile/build positive-only composition.

Extend supported-target scope with explicit cgo selection. A missing cgo member cannot cover both modes; product-wide build-dependent closure must require a matching explicit value. Do not silently reinterpret previously signed/digested assumption members.

Do not add a multi-configuration proof engine or combine negatives across variants.

---

## 8. Failure semantics

Reuse existing terminal outcomes and gap codes. The following table assumes no independent sufficient proof already decides the request.

| Situation | Outcome and diagnostic | Resolution |
|---|---|---|
| Requested build/variant is unidentified; legitimate alternatives change the answer | `EXTERNAL_DEPENDENCY`, verdict `INCONCLUSIVE`; `EXTERNAL / EXTERNAL_DEPENDENCY_UNRESOLVED` | Supply artifact settings, release metadata, or an exact declaration identifying the requested build. |
| Makefile defines multiple recipes or unresolved values; selected shipped recipe is unknown | Same external outcome **when the decision-changing boundary is evidenced** | Supply chosen recipe, effective values/overrides and release correspondence—or explicitly assess an operator-defined build. |
| Supplied declaration is unreadable, malformed, stale or mismatched | `FAILED`, no verdict; `INPUT / INPUT_RESOLUTION_FAILED` | Correct or reacquire the input. Never silently fall back to guessed settings. |
| Explicit operator input conflicts internally | `FAILED`; `INPUT / INPUT_RESOLUTION_FAILED` | Supply one unambiguous operator declaration. |
| A lower-precedence declaration differs from a valid higher-precedence target | Higher target wins; declaration is reported as superseded | Analyze the winning build, or submit a separate request for the alternative build. |
| Identified cgo build requires cross-cgo | `FAILED`; `PROOF / MEASUREMENT_NOT_COMPLETED` | Run target-native in a prepared environment. |
| Identified native cgo build lacks compiler, gpgme headers/library, SDK or required tools | `FAILED`; `PROOF / MEASUREMENT_NOT_COMPLETED` | Supply the real native prerequisites. No stubs or pure-Go substitution. |
| Correctly identified build still fails loading/type checking | `FAILED`; `PROOF / MEASUREMENT_NOT_COMPLETED` | Resolve the concrete diagnostic; do not change configuration opportunistically. |
| Required native or Go semantic proof is unsupported/incomplete | `FAILED`; relevant existing reachability/input/trigger/negative-verification code | Supply the missing proof capability or supported evidence. |
| Scope cannot authorize the requested negative | `FAILED`; `SCOPE / UNSUPPORTED_NEGATIVE_SCOPE` | Supply valid scope authority or ask the appropriately bounded question. |
| Measurements and all necessary proof gates succeed | `DECIDED`; earned verdict only | Configuration acceptance itself supplies no verdict. |

An external build dependency must retain all existing required fields: missing fact, obligation, qualified boundary evidence, why the available artifact cannot supply it, answer-changing alternatives and resolving input.

A generic compiler error is not enough to claim externality. If no such external boundary is established, fail the measurement.

Preserve the downstream short-circuit when build selection cannot be established. Do not manufacture root-cause, trigger and trace failures for work that could not legitimately start. Mixed genuine analyzer-owned and external blockers still follow existing `FAILED` precedence.

---

## 9. Expected effect on the measured cases

### Podman `6a65597`, Terrapin

The supplied measurements establish:

- Darwin’s current selection cannot load the product.
- Linux/amd64 resolves the OS-selection failure and loads 1,242 packages.
- cgo off with the default signature path fails at gpgme.
- Linux/amd64, cgo off and `containers_image_openpgp` produces a loadable configuration and a measured `EXPLOITABLE` result.

The [pinned Podman Makefile](https://github.com/containers/podman/blob/6a6559735845f21a3066cf547b90669ef24f768b/Makefile) shows why that last observation must not automatically become a shipped-build conclusion:

- `REMOTETAGS` includes `remote` and additional exclusions.
- `BUILDTAGS_CROSS` includes additional graph-driver exclusions.
- default `BUILDTAGS` includes shell-derived values and `seccomp`;
- default cgo is enabled, with an explicit comment that ordinary Podman generally needs it.

**Consequences:**

1. The single-openpgp-tag run is not established as any complete default recipe.
2. It may be assessed as an explicitly declared custom build, with its result bounded accordingly.
3. To assess a remote or cross recipe, declare its **entire effective tag set** and cgo value, then measure that configuration anew.
4. To assess a native/default cgo build, use a prepared Linux/amd64 environment with the real dependencies.
5. If the shipped variant is unknown, the outcome remains an external build-identity dependency.
6. If the variant is known but this workstation cannot measure it, the outcome is `FAILED`, not `INCONCLUSIVE`.

The prior positive is useful measured evidence for its exact configuration. It is not a guaranteed verdict for a newly admitted recipe.

### Cilium `1228cbc`

The measured platform correction remains valid: Linux/amd64 is sufficient to remove the reported load blocker.

Declare the equivalent complete configuration—Linux/amd64, cgo off, empty tags—and preserve the existing positive if all its current proof gates continue to admit it. No additional product-specific tags or cgo mode should be invented.

The only input-policy change is making previously implicit selection values explicit.

### Products whose Makefile tags differ from shipped defaults

They receive **no automatic behavioral change** from Makefile presence.

A selected non-default recipe is assessed as that recipe. Unknown correspondence to the shipped product remains explicit. This deliberately sacrifices opportunistic completion rather than producing confident answers for a different program.

---

## 10. Required tests

### Declaration intake and provenance

- Missing/null cgo and tags differ from explicit `false` and `[]`.
- Reject unknown/duplicate keys, unsupported schemas, invalid tags and oversized input.
- Reject wrong commit/tree hash, modified cited files, invalid ranges and escaping paths.
- Makefile presence alone never creates product provenance.
- Shell substitutions are never executed or treated as resolved values.
- Repository-supported declarations remain `operator-declared` / `operator`; `Authoritative()` remains false.

### Precedence and scope

- Full precedence matrix, including conflicting cgo and tag values.
- No field-wise merging across sources.
- Conflicting operator forms fail.
- Partial flags never promote host-filled facts.
- Exact tag equality and explicit cgo equality in supported-target admission.
- Artifact/operator scope never becomes product-wide authority.
- Existing structural advisory/CVE negative-scope controls remain unchanged.

### Execution and measurement identity

- Identical configuration reaches root and extra package loads, all inventory calls, govulncheck and permitted build/test tools.
- Ambient `GOFLAGS`, compiler flags and SDK variables cannot change the recorded build.
- Changed compiler/native flags/SDK pins invalidate caches and saved measurement admission.
- Cross-cgo is refused before source measurement as a capability failure.
- Native cgo succeeds using a small real C fixture.
- Missing real header records a failed measurement, not an empty successful inventory.
- No stub header, narrowed fallback or partial output becomes complete negative evidence.
- Build-selection re-evaluation agrees with Go’s selected files.

### Replay and publication

- Retained bytes are rehashed; missing or mismatched declaration pins reject publication.
- A saved positive cannot survive changed build correspondence.
- A saved `VERIFIED` negative cannot survive changed selection/native identity.
- Reissued provenance with an identical selection requires fresh provenance admission, while immutable matching measurements remain reusable.
- Legacy results acquire no fabricated declaration or native-context facts.
- Every publication surface uses the existing single requested-finding projection and renders the declared-build boundary.

### Case and anti-forcing controls

- Cilium-equivalent explicit configuration retains the measured positive.
- A generic Podman-shaped fixture distinguishes cgo/default, remote and cross tag sets.
- A one-tag compile workaround cannot masquerade as the complete recipe.
- Unknown shipped variant → external dependency.
- Known variant plus unavailable native prerequisites → failure.
- Configuration acceptance alone never produces a verdict.
- No automatic retries with altered tags, cgo or target.
- Independent sufficient proofs are not vetoed by unrelated failed measurements.

The measured product runs are acceptance/calibration cases, not justification for case-specific logic.

---

## 11. Design risks and hand-off

| Priority | Risk | Resolution |
|---|---|---|
| P0 | Recipe existence mistaken for shipped-build authority | Closed by operator-tier provenance and separate correspondence admission. |
| P0 | Missing toolchain disguised as an external product fact | Closed by identified-build → measurement-failure semantics. |
| P0 | Tags/cgo/native environment drift between measurements | Closed by one resolved context, native identity and existing comparison gates. |
| P1 | Native behavior beyond the analyzer’s semantic model | Bounded: existing opacity remains; unsupported required proof fails. |
| P1 | Actual release recipe cannot be established | Bounded runtime dependency; no inferred selection or verdict. |

Implementation must preserve these boundaries. If repository facts show that a proposed context cannot represent an input which changes file selection or the requested program, stop and return that discrepancy to design rather than silently dropping the input.

Update the CLI/build-context documentation, governing provenance documentation, affected assumption contract documentation and observable-behavior notes with the implementation.

**No files were changed and no builds, tests or measurements were rerun.** The case effects above distinguish supplied measurements from expected behavior under the proposed design.

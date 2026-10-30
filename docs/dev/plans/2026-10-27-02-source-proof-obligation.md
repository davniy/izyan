# DESIGN_FOR_REVIEW — READY

## Decision

**The current `EXPLOITABLE` is not defensible for the measured x/net path.** Reachability, attacker input and membership in an affected version range do not establish that the selected source still implements the defect.

However, **the analyzer cannot earn `NOT_AFFECTED` from the supplied offline artifacts either**. The identified constant and comparison establish what the source contains, but the advisory does not bind those constructs to its fix. The current implementation verifier also cannot prove “this selected source is already fixed.”

**For the measured offline run, the correct outcome is `FAILED`, with no vulnerability verdict and a typed `IMPLEMENTATION_PRESENCE` gap.** A verified fixed-source comparison can subsequently earn an implementation-negative fact. A record-wide or CVE-wide negative requires additional coverage, explained below.

No user-owned policy question is necessary: preserving uncertainty rather than asserting an unproved positive follows the existing evidence contract.

## 1. Rule and exact predicates

### Preserve version arithmetic

Leave:

```text
VersionAffected = TRUE
```

for `v0.3.1-0.20221206200815-1e63c2f08a10` against the advisory’s `fixed=0.4.0`.

Do not change semver ordering, substitute the commit timestamp for a version, or invent a corrected version. The existing range calculation correctly answers **version-range membership**, not **whether those particular source bytes contain the defect**.

### Introduce a selective source-proof obligation

Evaluate the following **per advisory entry and mechanism, under the recorded build**, not once for the entire advisory.

Let:

- `v(e)` be the effective resolved version of entry `e`.
- `Contains(v,r)` use the existing range-membership semantics.
- `NonRelease(v)` mean a valid semver prerelease, including Go pseudo-versions.
- `TagBound(r)` mean `r.Fixed` is present and is a valid non-pseudo version. This includes ordinary release and release-candidate tags; it excludes commit-addressed pseudo-version bounds.

Define:

```text
TagCutoffAmbiguity(e) =
    VersionAffected(e) = TRUE
    AND NonRelease(v(e))
    AND EXISTS r in e.ranges:
          Contains(v(e), r)
          AND TagBound(r)
```

This captures the misleading interval: a commit can contain the fix before the advisory’s first fixed release tag exists.

Also define:

```text
SourceCoordinateDivergence(e) =
    admitted evidence establishes that the selected implementation
    is not represented faithfully by its claimed upstream coordinate
```

Qualifying evidence is structural, not speculative:

- an unversioned/local replacement retaining an upstream version claim;
- a fork whose effective source identity is not the advisory module;
- a recorded source difference against an independently pinned upstream artifact at the claimed coordinate;
- an admitted patch/backport manifest bound to the selected source.

Finally:

```text
FixConflict(e) =
    an advisory/fix-bound source observation contradicts
    a necessary premise of the proposed vulnerable-implementation proof
```

For example, a positive witness requiring the absence of a particular enforcement construct cannot survive deterministic observation of that construct in the relevant selected implementation. **That observation defeats the positive; it does not, by itself, prove the complete fix.**

The obligation is:

```text
NeedsSourceProof(e) =
    VersionAffected(e) = TRUE
    AND (
        TagCutoffAmbiguity(e)
        OR SourceCoordinateDivergence(e)
        OR FixConflict(e)
    )
```

**Vendoring alone does not satisfy this predicate.** “Backport-prone dependency” is not a measurable classification and must not become a hidden heuristic.

### Positive admission

For an entry that supplies the exploitability witness:

```text
PositiveAdmitted(e) =
    existing applicability and exploit-condition admission succeeds
    AND (
        NOT NeedsSourceProof(e)
        OR SourceImplementation(e) = VERIFIED_VULNERABLE
    )
```

`VERIFIED_VULNERABLE` must establish the defect in the selected source. A symbol, package, call path, arbitrary marker, or existing `C-LOCUS=TRUE` based merely on symbol presence is insufficient.

Consequences:

| Source result | Consequence |
|---|---|
| Verified vulnerable implementation | Existing positive evaluation may proceed; all other gates remain mandatory. |
| Verified fixed implementation | This entry cannot supply a positive; it acquires an implementation-negative applicability fact. |
| Unknown / incomplete / conflicting proof | This entry cannot supply a positive. |
| Another entry independently earns a positive | It may still decide the record; a fixed x/net entry does not shield vulnerable stdlib code. |

This is a **positive-admission requirement**, not a universal prerequisite for every verdict. An independently sufficient, already-admitted affected-chain negative or VERIFIED exploit-condition falsifier retains its existing behavior. In particular, an unknown implementation does not invalidate an otherwise sound `NO_EXPLOIT_PATH_FOUND`.

## 2. Offline evidence contract

### What can discharge the obligation

Use a **typed, entry-bound source witness**, with:

- exact advisory `RecordPin` and original affected-entry references;
- module identity and effective version;
- snapshot/source digests and source-origin binding;
- recorded build context and selected implementation coverage;
- proof kind, result and qualified evidence references;
- fix artifact identity and complete bytes/digests when the proof uses a fix.

Two sufficient bases are appropriate:

1. **An admitted defect-semantic witness** proving the vulnerable behavior in the actual selected source. This need not require a patch if the advisory already supplies a sufficiently concrete mechanism and an existing deterministic verifier supports it.
2. **A fixed-source equivalence proof** against an advisory-bound fixed artifact, covering the complete relevant implementation and dependencies that enforce the fix. Prefer exact comparison over inventing a general “patch probably applied” heuristic. Nonmatching or partially available implementations remain `UNKNOWN` unless supported semantic verification resolves them.

Fix patches may identify candidate subjects and changed constructs. A patch alone is not automatically a complete fixed-source proof.

### What is not sufficient

None of these establishes fixedness:

- a suggestive constant name or comment;
- one identifier added by the fix;
- a guard somewhere in the package;
- failure to find an old marker;
- a reverse-patch applicability check alone;
- `SymbolFaultingUse == false`;
- absence of a govulncheck finding;
- commit or release dates.

For Kubernetes, the proposed evidence must establish that the actual `canonicalHeader` implementation enforces the advisory-bound cache-size limit, including its accounting and relevant updates—not merely that `maxCachedCanonicalHeadersKeysSize` is declared.

### Existing machinery cannot currently earn that negative

This is a real capability boundary:

- [`internal/fix/patch.go:117`](internal/fix/patch.go#L117) retains symbol/guard summaries, not complete pre/postimages.
- [`internal/goanalysis/locus.go:16`](internal/goanalysis/locus.go#L16) checks syntactic faulting use, not whether the fix guards that use.
- [`internal/affected/implementation.go:585`](internal/affected/implementation.go#L585) requires its proposed marker to exist; a missing marker yields `UNKNOWN`.
- That verifier earns absence through **build exclusion**, not through a selected implementation being corrected.

Therefore add a separate **fixed-source witness**, not a new interpretation of the existing `ImplementationVerifiedAbsent` build-exclusion status. Its admitted result may feed the existing proposition “vulnerable implementation present = FALSE.” The file and package can remain present.

No additional public report axis is needed.

### Unavailable evidence

Missing patch bytes, missing comparison artifacts, unsupported comparison, truncation, incomplete scans and verification failures are **INPUT/PROOF/CODE failures**, not environmental abstentions.

Use existing typed gaps, for example:

```text
Owner:      INPUT
Code:       INPUT_RESOLUTION_FAILED
Obligation: IMPLEMENTATION_PRESENCE
```

or `PROOF / PROOF_ARTIFACT_MISSING`, as appropriate.

A FIX URL is a locator, not proof of the referenced contents.

## 3. Verdict for Kubernetes CVE-2022-41717

### With the measured offline inputs: `FAILED`

The x/net entry satisfies `TagCutoffAmbiguity`:

```text
resolved: pseudo-version
range:    affected
fixed:    ordinary release tag 0.4.0
```

The supplied advisory names affected symbols but does not identify the cache-bound construct. There is no captured patch or admitted semantic/fixed-source witness connecting the observed source to the advisory’s correction.

Thus:

```text
assessment_outcome:       FAILED
verdict:                  absent
VersionAffected:          TRUE
source implementation:    UNKNOWN
vulnerable_code_in_build: UNKNOWN
exploitable:              UNKNOWN
```

The three existing TRUE conditions remain recorded observations, but do not overcome the missing implementation proof. This is not a safe negative, and is not `INCONCLUSIVE` disguised as unfinished code analysis.

### What earns `NOT_AFFECTED`

A complete admitted source proof can establish:

```text
golang.org/x/net entry:
    VersionAffected = TRUE
    vulnerable implementation present = FALSE
```

**That closes only the x/net entry.** GO-2022-1144 also contains `stdlib / net/http`.

A record-wide `NOT_AFFECTED` requires every original entry to be discharged by an admitted applicability negative, such as:

- authoritative stdlib release version outside its affected ranges;
- verified package/build exclusion;
- authoritative, build-bound fixed-implementation evidence.

The `go 1.19` directive cannot discharge stdlib. Nor can the analyzer’s own GOROOT source.

There is an existing coverage trap: the implementation-negative branch in [`internal/evaluator/verdict.go:283`](internal/evaluator/verdict.go#L283) accepts the aggregate FALSE without checking whether `ImplementationModules` covers pending entries. **The new rule must not allow an x/net-only proof to close unresolved stdlib.** Enforce entry coverage in shared admission, including replay—not only at the producer.

Once the **exact GO record** has complete, admitted negative coverage:

```text
assessment_outcome:       DECIDED
verdict:                  NOT_AFFECTED
vulnerable_code_in_build: FALSE
exploitable:              NOT_APPLICABLE
```

Use a reason such as “the selected implementation already contains the verified fix,” not “http2 is absent from the build.”

### Why not the other outcomes?

- **`NO_EXPLOIT_PATH_FOUND`:** not the correct conclusion from a complete fixed-source proof. This is applicability—the defect implementation is absent—not a missing exploit path. NEPF remains available if independently earned by its existing verified-falsifier route.
- **`EXTERNAL_DEPENDENCY / INCONCLUSIVE`:** not for missing patch/source-analysis evidence. It becomes appropriate only when internal work is complete and a named external fact—such as the shipped stdlib toolchain—alone changes the answer.
- **CVE-wide `NOT_AFFECTED`:** still requires the declared, digest-pinned, finished corpus boundary. A negative GO-2022-1144 record alone does not close the requested CVE. Without that authority, retain `FAILED / UNSUPPORTED_NEGATIVE_SCOPE`.

The benchmark’s `not_exploitable / code_not_present` label is consistent with a completely proved implementation negative; it does not authorize skipping these evidence boundaries.

## 4. Blast radius

This deliberately does **not** make implementation verification mandatory for every positive.

### Classes that keep working without an additional source proof

- Affected ordinary tagged versions, absent admitted source divergence or fix conflict.
- Ordinary tagged versions vendored unchanged in the existing trusted inventory model.
- `+incompatible` versions: build metadata is not a prerelease.
- Pseudo-version ranges whose applicable fixed boundary is itself commit-addressed, absent divergence/conflict.
- Existing authoritative stdlib version-based applicability.
- Existing independently sufficient negatives and VERIFIED NEPF proofs.
- Existing library-API and transport-peer positives that satisfy all their current admission requirements and the selective implementation obligation, if applicable.

The pseudo-to-pseudo distinction matters in the actual corpus:

- `real-md-render`: fixed boundary `0.0.0-20230922105210-14b16010c2ee`;
- `real-ssh-server`: fixed boundary `0.0.0-20211202192323-5770296d904e`;
- x/sys in `real-unix-access`: fixed boundary `0.0.0-20220412211240-33da011f77ad`.

Those are **not automatically blocked merely because their resolved versions are pseudo-versions**.

### Classes intentionally affected

- Pseudo/prerelease versions judged affected against a tag-valued fixed boundary.
- Source substitutions/backports with admitted coordinate divergence.
- Any version, including a stable tag, whose proposed positive conflicts with admitted fix-bound source evidence.

A genuinely vulnerable pseudo-version in the first class may now require additional evidence. That is an intentional loss of **version-only certainty**, not a declaration that the code is fixed.

### Explicit detection limit

**There is no selective, non-heuristic way to detect every unadvertised backport from vendoring metadata alone.** A stable-tagged vendor tree can be modified while retaining the original version string.

Catching all such cases would require universal source verification or source-identity comparison. This design does neither silently. Stable, apparently ordinary vendored dependencies retain the existing version-based trust model until actual divergence/conflict evidence exists.

No corpus-wide numerical impact is claimed; this was read-only research, not a benchmark run.

## 5. Dates, ancestry and markers

There is no sound general implication:

```text
pinned commit date > fix date  => fix present
```

Branches, cherry-picks, timestamps and reverts invalidate it. Comparing the pinned commit date with the fixed **release** date is weaker still.

A verified commit graph can prove ancestry, provided the upstream fix commit and selected source revision are authenticated. It cannot alone prove that the selected tree still contains the fix after later changes or reverts.

Likewise:

```text
identifier added by fix is present  ≠ complete fix is present
```

An advisory-bound identifier can locate comparison candidates or contradict a particular missing-fix premise. A definitive negative needs complete implementation evidence.

Without patch bytes, a trusted fixed-source artifact, or sufficiently precise independently verifiable defect semantics, **the analyzer cannot discover which particular names implement this fix or prove that the supplied constructs are sufficient**.

## 6. Integration and persisted compatibility

Use one shared admission rule in the deterministic evaluator, with pinned per-entry applicability supplied from resolver evidence. Reports and axes consume that admission; they must not implement another verdict policy.

Persist the new source witness as an **additive optional typed record**. Keep existing verdict/outcome enums, the `analysis-case/2` contract and the two report axes.

For old cases:

- loading remains supported;
- missing new fields mean **no source witness**, not “verification unnecessary”;
- recompute the requirement from recorded entry/version/source evidence;
- previously saved positives in the affected class must re-admit under the new rule;
- refuse unsupported saved conclusions using the existing publication/policy-drift behavior—do not silently rewrite or grandfather them.

Update [`internal/finding/axes.go:225`](internal/finding/axes.go#L225): its four-fact applicability shortcut may establish `vulnerable_code_in_build=TRUE` only when the selective source obligation is absent or discharged. Preserve the existing `TRUE/UNKNOWN` display for ordinary affected code whose exploit analysis failed.

Structural scope, target provenance, measurement completion, negative verification, library-API admission, transport-peer admission and positive-only composition remain unchanged.

## 7. Required tests

1. **Version and trigger matrix**
   - Kubernetes pseudo-version remains `VersionAffected=TRUE`; tag-cutoff obligation applies.
   - Stable affected tag and `+incompatible` do not trigger solely by version shape.
   - Pseudo-to-pseudo fixed ranges retain their existing version basis.
   - Prerelease-to-tag boundary triggers.
   - Range matching uses the applicable interval, not another entry’s fixed version.
   - Vendoring alone does not trigger; admitted source divergence does.

2. **Positive admission**
   - All current mandatory claims TRUE + required source proof UNKNOWN ⇒ `FAILED`, no verdict.
   - Admitted vulnerable-source witness restores eligibility for `EXPLOITABLE`.
   - Symbol presence, arbitrary markers and generic C-LOCUS TRUE cannot discharge the obligation.
   - An independent valid positive entry still wins.

3. **Fixed-source verification**
   - Complete fixed-source evidence earns an entry implementation negative.
   - Marker-only, comment-only, unused constant, incomplete guard/accounting, partial patch and ambiguous source binding do not.
   - Wrong advisory/module/build/digest, truncated artifacts and incomplete coverage remain UNKNOWN.
   - A selected vulnerable alternative prevents an implementation-negative aggregate.

4. **Multi-entry and scope**
   - Fixed x/net + pending stdlib cannot produce record-wide `NOT_AFFECTED`.
   - Fixed x/net + admitted unaffected stdlib can close an exact, fully represented GO record.
   - Missing release-toolchain evidence becomes external only when it is the sole remaining blocker.
   - A record negative never closes a CVE without the existing corpus authority.

5. **Independent negatives and boundaries**
   - Existing sufficient affected negatives and VERIFIED NEPF proofs still work.
   - Host-default, incomplete-measurement and unverified-negative refusals remain enforced.
   - Library-API and transport-peer admission tests remain unchanged.

6. **Axes and persistence**
   - Required source UNKNOWN ⇒ `UNKNOWN/UNKNOWN` for this failed case.
   - Earned fixed-source record negative ⇒ `FALSE/NOT_APPLICABLE`.
   - Ordinary affected code with failed exploitation analysis remains `TRUE/UNKNOWN`.
   - Old cases remain loadable; unaffected classes re-admit unchanged.
   - An old Kubernetes-like saved positive cannot bypass the new gate by omitting the witness.

**Bottom line:** retain the affected version fact, reject the unproved positive, and require source evidence only for the defined ambiguity/divergence classes. For the current offline Kubernetes inputs, publish **`FAILED`, not `EXPLOITABLE` and not a fabricated safe verdict**.

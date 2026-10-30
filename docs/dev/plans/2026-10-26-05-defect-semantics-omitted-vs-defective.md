# DESIGN_FOR_REVIEW

**Decision:** Echo can earn an advisory-specific **`NO_EXPLOIT_PATH_FOUND`** by proving that `MapClaims.VerifyAudience` cannot execute in the analyzed product scope. It cannot earn `NOT_AFFECTED` from that fact, and the **current CVE request must remain `FAILED` under the frozen composition rules**.

The reviewer’s correction is decisive: reaching JWT parsing or `MapClaims.Valid` is not reaching CVE-2020-26160. The advisory requires an invocation of the defective audience check.

**Design gate: READY.** The correction is sufficiently specified. Whether the real snapshot satisfies every negative-verification check remains unmeasured; that is an acceptance condition, not a reason to retain the incorrect model.

## 1. Verdict and the proof that earns it

### Keep the record-level answer separate from the requested CVE answer

| Assessment/request | Correct outcome |
|---|---|
| Current persisted CVE request | **`FAILED`**, no verdict. Its model is wrong, its target is host-default, and its requested negative scope is unsupported. |
| Exact, fully represented `GO-2020-0017` assessment, after the corrections below and successful verification | **`DECIDED / NO_EXPLOIT_PATH_FOUND`**, grounded in affected-operation unreachability. |
| Same corrected record assessment without sufficient negative proof | **`FAILED`**, with the actual unresolved proof/input obligation. |
| Current CVE request with a record-level NEPF | Still **`FAILED / SCOPE/UNSUPPORTED_NEGATIVE_SCOPE`** under existing rules. |

There is an important constraint beyond the reviewer’s scope warning: **configuring a complete corpus alone would not solve the last row.** The current corpus-negative contract requires every nominated candidate to earn `NOT_AFFECTED`; it rejects `NO_EXPLOIT_PATH_FOUND`. The governing specification explicitly prohibits renaming NEPF to `NOT_AFFECTED`.

Sources: `internal/domain/corpus_scope.go:270–318`, `internal/finding/compose.go:150–175`, `docs/dev/specs/governing-spec.md:554–567`.

Therefore:

- The supported definitive-negative deliverable is the **exact GO-record assessment**, retaining CVE-2020-26160 as its alias.
- Do not silently change the identity of the current CVE request or publish the record’s negative as the requested CVE finding.
- Requiring a definitive CVE-wide negative from this deadness proof would require an explicitly approved composition-policy extension. That is outside this correction.

### Why NEPF, not `NOT_AFFECTED`

The recorded affected chain establishes that jwt-go v3.2.0 is present, affected, linked and build-relevant. The defective implementation exists. Its non-execution is an exploit-condition falsifier, not implementation absence.

Use the existing route:

```text
Advisory-grounded invocation necessity
  + complete measurement of VerifyAudience unreachability
  + independent negative verification
  + exact-record negative scope
  → C-LOCUS = FALSE
  → FalsifierLocusFunctionUnreached, VERIFIED
  → NO_EXPLOIT_PATH_FOUND
```

This corresponds to the benchmark’s `code_not_reachable` rationale.

### Required proof

1. **Correct necessity premise.** Bind the advisory’s documented mechanism to `MapClaims.VerifyAudience`. Its invocation is necessary for this defect; omission of audience verification is not this CVE.
2. **Complete record coverage.** Preserve the full, digest-bound GO-2020-0017 census, including its jwt-go and jwt-go/v4 entries. Account for the absent v4 entry through the existing affected-chain facts; do not narrow the record to the linked entry.
3. **A scoped product target.** The persisted target is `host-default` with no scope. That cannot ground this negative. Supply an existing admitted product-target source, matching the effective build. Do not infer product targets from the analyzer host. A build-specific conclusion must not become a claim about every supported build.
4. **Completed, subject-covering measurements.** The persisted `EV-021` already records a completed, complete, non-opaque source scan covering `VerifyAudience`, with product-used entry symbols. This is useful measurement evidence—not completed negative verification. Reuse it only when its complete build identity still matches.
5. **Independent verification.** Run the existing locus verification, including dependency invocation checks, `VerifyUnreachable`, and extended scope checks. Close declaration, product-reference, dependency-caller, may-call, interface-dispatch, dynamic-escape, gated-reference, importer, census and budget obligations. Persist the verification and its matching build context.

The persisted run contains **no completed unreachability verification**. Consequently, removing the modeling error and sibling vetoes does not itself establish that all remaining checks pass.

Use **`FalsifierLocusFunctionUnreached`** as the primary route. Do not use govulncheck silence: the recorded run is `completed_with_results`, whereas that falsifier requires qualified `completed_empty` evidence.

Sources: `internal/evaluator/locus.go:124–171`, `internal/domain/negative_admission.go:78–109,267–359`, `internal/goanalysis/locusverify.go:195–398`.

## 2. Omitted-versus-defective selection

### Exact rule

**A check-like name and a live sibling pipeline may identify candidates for investigation. They confer no defect semantics.**

Select **`OMITTED_CHECK`** only when admitted advisory/fix evidence establishes all of the following:

- a particular security check is required at an identified execution/acceptance point;
- failing to execute that check is the vulnerability;
- the required check and omission site are bound to concrete source identities;
- the cited evidence applies to the affected implementation/version.

Acceptable grounding is an explicit advisory mechanism statement and/or a verified before/after fix relation establishing that the missing invocation is causal. Merely finding words such as “validation” or an added check call is insufficient: the addition could be a workaround, unrelated hardening, or part of another mechanism.

Select **`INCORRECT_CHECK`** when the admitted evidence establishes that the vulnerability requires executing a check whose behavior is defective under specified arguments, value types or state.

If evidence does not distinguish the two, select **unresolved semantics**, not omission and not an assumed invocation-based model. If both mechanisms are genuinely documented, preserve both obligations; never choose whichever yields a convenient verdict.

For GO-2020-0017 the evidence is explicit:

> An audience claim contains an array of strings, and `MapClaims.VerifyAudience` is called with `req=false`.

The captured fix changes audience handling **inside** the check and its helper. It does not establish that `Valid` was required to call it. The source’s string assertion explains the failure:

```go
aud, _ := m["aud"].(string)
return verifyAud(aud, cmp, req)
```

An array fails that assertion, produces the empty string, and `verifyAud` accepts it when `required=false`.

### Persist one admitted contract

Add a narrowly scoped, typed **check-defect contract**, rather than another heuristic string parameter. It should carry:

- exact record pin and affected-entry references;
- mode: `OMITTED_CHECK`, `INCORRECT_CHECK`, or unresolved;
- affected check identity;
- omission-site/pipeline identity when applicable;
- typed trigger predicates and operand bindings;
- advisory quotations and source/fix evidence references, with digest bindings.

Derive “invocation is necessary” from that admitted contract; do not store an independently editable boolean that can disagree with the mode.

Resolve and admit this contract once, then use it in the builder, negative admission, research consumers and persisted-publication admission. LLM output may propose the contract; names, confidence, keywords and proposals never admit it.

### Incorrect-check contract for this CVE

For a candidate invocation:

```text
m.VerifyAudience(cmp, req)
```

bind these obligations:

| Obligation | Required fact |
|---|---|
| Operation | The live call resolves to the affected `MapClaims.VerifyAudience`. |
| Argument | Parameter `req`, argument index 1, is `false`. |
| Payload location | The relevant value is the receiver’s `m["aud"]`, not `cmp` and not an arbitrary argument. |
| Payload type/value | `aud` has the advisory’s array representation, rather than a string, and supplies an invalid audience set for `cmp`. |
| Control | The attacker can supply the relevant token/claim value through an admitted ordinary input route. |
| Security effect | The defective result is relied on to accept the audience/authentication decision. |

JSON-decoded arrays and programmatically constructed slices must be bound to their actual runtime representation; a generic “non-string” label must not silently expand the advisory.

Build invocation-based `C-REACH` and `C-LOCUS`, receiver-field-bound input evidence, and a **dedicated mandatory check-trigger condition**. Its witness must establish the argument/type predicates and relevant input on the **same invocation and receiver**. This prevents combining `req=false` at one call with an array payload at another.

Do **not** encode these semantics solely as generic `INPUT_CONSTRAINT`: the current ordinary provenance evaluator can return TRUE from external origin without proving those trigger predicates (`internal/evaluator/provenance.go:180–183`).

A dead-operation negative does not require proving the live trigger. Its invocation premise already falsifies the conjunction.

## 3. Remove the locus/negative contradiction

The contradiction has two parts:

- `evalLocus` treats any `EV-MISSING-CALL*` as TRUE reachability of the declared check.
- Both negative implementations interpret live siblings as proof that check deadness cannot falsify the vulnerability.

Neither interpretation is warranted by the physical observation.

### Separate source observations from exploit semantics

**Source layer:** report whether the named function can execute. `DepInvocationState` may retain `siblingLive` as an observation, but sibling activity must not mean “omission vulnerability.”

**Semantic layer:** decide whether that physical deadness falsifies an advisory-required operation, using the shared admitted contract.

Apply these rules:

| Contract | Literal check deadness | Omission observation |
|---|---|---|
| Incorrect check | Can falsify the mandatory invocation condition, after full verification. | Cannot establish defect-locus execution. |
| Omitted check | Cannot by itself falsify the vulnerability. | Can support the explicitly bound omission-site condition. |
| Unresolved | Cannot be promoted into an exploitability negative. | Cannot establish an omission defect. |

For genuine omission, represent the defect locus as the **omission site on the anchored pipeline**, not as execution of the absent check. Keep the declared check in advisory provenance and coverage; do not pretend its body executed or remove it through a fabricated non-locus decision.

### Required changes

- Remove the unconditional omission-to-literal-locus shortcut in `internal/evaluator/locus.go:54–64`.
- Replace evidence-ID prefix and content-substring matching in the omission/pipeline evaluators with typed record/contract/check/pipeline/build bindings.
- Remove the sibling-live semantic veto from physical `VerifyUnreachable` measurement. Keep real callers, unbounded callers, opacity and every other completeness blocker.
- In negative consumers, require an admitted **invocation-necessity premise** before converting function deadness into an exploit falsifier.
- Apply the same admission on replay/publication. Old omission conclusions without the contract must not remain publishable merely because saved claims say TRUE or VERIFIED.

**Removing the source-level veto requires migrating every semantic consumer in the same cutover.** Otherwise genuine omissions acquire a false-safe bypass through:

- `internal/research/decision.go` — declared-symbol-unreached authority;
- `internal/research/branch_evidence.go` and `flow_adapter.go` — rule-fact/authority projection;
- `internal/productb/triage/unreachability_proof.go` — independent falsifier minting.

All must consume the same necessity admission, including artifact/replay paths. Do not fix only the main evaluator.

## 4. Extractor provenance: separate P2, not a prerequisite

**Resolving `extractor(c) → c.Request().Header` is not required for the affected-operation-deadness verdict.**

A VERIFIED FALSE on the mandatory invocation/locus condition refutes the conjunction even while input remains UNKNOWN. That follows the existing verdict rules; it does not weaken measurement completion or declare the input trace complete.

The provenance defect is nevertheless real:

```text
request header
→ extractor closure
→ extractor(c)
→ auth
→ jwt.Parse / ParseWithClaims
```

Its repair should resolve the extractor dispatch, handler parameter and returned token substring while preserving supported configuration alternatives. It remains **P2**, independent of the **P1 semantic-model and negative-consistency corrections**.

Do not infer that all callback-related obligations disappear. An uninspected callback can execute other code regardless of its nominal role or signature. The deadness verifier must close its own relevant dispatch obligations. Conversely, unrelated input-closure incompleteness must not veto an independently complete deadness proof.

This remains an AUTH_BYPASS near-miss: **no library-API admission**, no CWE-502 reclassification, and no transport-peer inference. Ordinary request provenance is a separate admissible input route, not proof of this CVE.

## 5. Failure semantics

Use the existing code:

```text
assessment_outcome: FAILED
owner: CODE
code: ROOT_CAUSE_UNRESOLVED
obligation: ROOT_CAUSE
message: affected symbol resolved, but advisory-grounded defect semantics
         could not be established / contradict the constructed model
```

A resolved symbol does not imply resolved defect semantics. Merely appending this gap is insufficient: the verdict evaluator currently accepts sufficient-looking conjunctions before outcome classification. **Semantic admission must prevent the wrong conjunction from earning a verdict.**

Distinguish:

| Situation | Result |
|---|---|
| Omitted-versus-defective semantics cannot be established | `FAILED / CODE/ROOT_CAUSE_UNRESOLVED`. |
| Contract established, trigger proof incomplete | `FAILED / CODE/TRIGGER_PROOF_INCOMPLETE`, if still decision-relevant. |
| Contract established, negative verification incomplete | `FAILED / PROOF/NEGATIVE_VERIFICATION_INCOMPLETE`. |
| Correct necessary invocation independently proven impossible | Exact-record NEPF, even if other trigger/input facts remain UNKNOWN. |
| Independent affected-chain proof establishes absence/out-of-range | `NOT_AFFECTED`, subject to existing scope/admission rules. |

Thus **“we modeled the wrong defect” never becomes “the product is safe.”** A model gap is analyzer work, not `EXTERNAL_DEPENDENCY`. Preserve the diagnostic report and unsupported-CVE-scope failure separately.

## 6. Blast radius and required tests

### Known impact

Besides Echo, **`real-jwt-auth` is affected**. Its product calls `ParseWithClaims` but never calls `VerifyAudience`; its corpus note and ground-truth document currently describe this CVE as a missing-call vulnerability. Correct that mechanism description. Its expected exact-record negative must be earned by the same verification—not substituted because a corpus expectation changed.

The structural blast radius includes every future check-like advisory with a live `Valid` sibling. Existing `Is`/`Has` prefix recognition makes that broader than JWT. Other class patterns should remain unchanged; they must not inherit omission semantics from the removed heuristic.

### Required acceptance tests

1. **Builder selection**
   - GO-2020-0017 plus live `Valid` produces no `C-OMISSION`.
   - A check-like name and sibling alone cannot select omission.
   - A synthetic, genuinely advisory/fix-grounded omission still selects it.
   - Missing, contradictory or stale semantic evidence fails closed.

2. **Incorrect-check binding**
   - Bind `req` to index 1 and payload to receiver `["aud"]`.
   - Distinguish array payloads, string payloads and `req=true`.
   - Reject positives assembled from different calls, receivers or payloads.
   - External token origin alone cannot satisfy the trigger.

3. **Consistency and bypass controls**
   - The same physical deadness can falsify an incorrect-check invocation but cannot dismiss a genuine omission.
   - Unrelated/stale `EV-MISSING-CALL` evidence cannot establish locus TRUE.
   - Research, rule-fact, Product B and replay paths cannot bypass semantic admission.

4. **Negative-proof gates**
   - Host-default target, build mismatch, incomplete census, unresolved dispatch and failed verification cannot earn NEPF.
   - A complete verified locus falsifier can decide the record while input stays UNKNOWN.
   - `completed_with_results` cannot become govulncheck-silence evidence.

5. **End-to-end scope**
   - Corrected Echo, admitted target and closed verification → exact GO-record NEPF.
   - Current CVE request → scope failure remains.
   - A complete corpus containing an NEPF candidate does **not** become current-contract `NOT_AFFECTED`.
   - Echo remains excluded from library-API positives.

6. **Documentation and calibration**
   - Correct the missing-call design/example, current architecture/how-it-works descriptions, `real-jwt-auth` truth/note, `eval/README.md` and backlog.
   - Preserve historical measurements as historical; annotate invalid model assumptions rather than rewriting observed results.
   - Final validation must retain false-safe controls across both corpora.

**Handoff constraint:** preserve every existing structural-scope, target, completion, negative-verification, library-API, transport and positive-composition gate. If implementation reveals that the documented operation is reachable or that a documented alternative mechanism exists, return that evidence to design review rather than special-casing Echo.

No user-owned question is necessary. The requirements determine the design; remaining uncertainty is whether the corrected negative proof completes.

*Evidence: reviewer output, repository source, advisory/fix evidence and the persisted Echo report were inspected read-only. No files were changed and no builds, tests or analyzer reruns were performed.*

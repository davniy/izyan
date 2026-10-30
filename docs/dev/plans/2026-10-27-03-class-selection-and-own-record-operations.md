# DESIGN_FOR_REVIEW — READY

## Decision

**There are two separate problems, but the evidence does not implicate `ae921fe` as a classifier-changing commit.**

1. **The loss of argument-specific `C-INPUT` and `C-LOCUS` comes from `d1950291`**, which switched the production request pipeline to exact-record intake. That correctly stopped cross-record alias enrichment, but exposed an incomplete root-cause resolver: it ignores a vulnerable operation explicitly named in advisory prose.
2. **The observed `DESERIALIZATION → RESOURCE_EXHAUSTION` change comes from loading different advisory bytes.** GHSA supplies CWE-502; GO does not. The GO document exposes an existing keyword-scoring defect: two mentions of “panic” tie two deserialization matches, and the resource-exhaustion row wins.
3. **Only testify is directly explained by this classification/ordinary-argument repair.** The other non-decided corpus rows have distinct build, scope, root-cause, proof, or unfinished-run causes.

The fix must **preserve exact-record isolation**, recover the GHSA operation from **its own prose and verified source**, correct mechanism precedence, and leave library admission narrow.

---

## 1. Root cause of each observed change

### A. Argument-specific input and locus disappeared: `d1950291`

Commit:

```text
d1950291bec137cf5656eaa3c2425826c9942ed2
feat(states,finding): isolated record orchestration and requested-finding composition
```

The worktree reflog identifies this cutover at `logs/HEAD:133`; the definitive-verdict Task-6 report describes the exact-intake wiring at `.superpowers/sdd/2026-10-26-03-definitive-verdict-implementation/task-6-report.md:31–62`.

The causal chain is:

| Step | Code |
|---|---|
| Production request pipeline selects exact intake | `cmd/izyan/record_pipeline.go:77–83`, `Exact: true` |
| Exact intake calls `LoadExact`, not legacy `Get` | `internal/states/states.go:185–205` |
| Exact loading deliberately follows no aliases or sibling documents | `internal/vulnerability/source.go:59–68`; `internal/vulnerability/record.go:11–47` |
| Legacy loading had supplied missing symbols from aliases | `internal/vulnerability/source.go:51–52,225–287` |
| Without structured symbols, resolver falls back to fix-changed functions | `internal/rootcause/rootcause.go:34–42,52–117` |
| No usable parameter produces `ArgAll`, then `INPUT_CONSTRAINT` | `internal/exploit/builder.go:545–583,597–613` |
| Empty `AffectedSymbols` produces no locus | `internal/exploit/builder.go:292–295`; condition appended only at `:240–262` |

The saved artifacts establish the actual subject substitution:

- **Good run:** `/tmp/final-cve/CVE-2022-28948-1792896980.json`
  - GHSA’s own CWE-502.
  - `affected_symbols_alias: GO-2022-0603`, with symbols acquired from the GO sibling.
  - Root/input/locus subject: `gopkg.in/yaml.v3.Unmarshal`.
  - Ordinary argument **0**.
  - Top-level legacy verdict **`EXPLOITABLE`, `library-api`** at `:2026–2044`.

- **Degraded GHSA run:** `/tmp/pre-stretchr/CVE-2022-28948-1793057809.json:314–357`
  - Still `DESERIALIZATION`.
  - No structured affected symbols.
  - Root cause becomes fix-changed **`parser.peek`**.
  - Input becomes `ArgAll=-1` / `INPUT_CONSTRAINT`.
  - No `C-LOCUS`.

This is **not** evidence that `inputCondition` itself regressed. It received a different subject. The public entry point takes bytes; the selected internal parser method does not provide the same ordinary-argument binding.

**Do not revert exact intake.** The defect is that own-record prose declarations are not resolved before patch-only fallback. Restoring alias enrichment would violate the new isolation contract.

`47ce925` is not this cutover: its “no alias subject union” change concerns govulncheck projections. The production `FileSource.Get → LoadExact` transition is the `d1950291` orchestration change.

### B. Class became `RESOURCE_EXHAUSTION`: advisory substitution exposes an existing scoring defect

The records differ materially:

| Record | CWE | Structured symbol | Current class |
|---|---|---|---|
| `GHSA-hp87-p4gw-j4gq` | CWE-502 | None | `DESERIALIZATION` |
| `GO-2022-0603` | None | `Unmarshal` | `RESOURCE_EXHAUSTION` |

The GO text is:

> Summary: “Panic in gopkg.in/yaml.v3”  
> Details: “An issue in the Unmarshal function can cause a program to panic when attempting to deserialize invalid input.”

Current classification:

- CWE-502 maps directly to deserialization: `internal/exploit/classify.go:56,97–121`.
- Resource keywords include bare `panic`: `:81`.
- Deserialization keywords include `unmarshal` and `deserializ`: `:85`.
- `scoreKeywords` counts occurrences and updates only on strict `>`: `:148–157`.

Consequently, the GO record scores:

```text
RESOURCE_EXHAUSTION: panic + panic          = 2
DESERIALIZATION:     Unmarshal + deserialize = 2
```

The earlier resource row wins the tie. It selects the peer-driven pattern at `internal/exploit/patterns.go:77–86`, replacing generic input with `C-PEER-INPUT` and `C-CONSTRAINT`.

**There is no evidenced classifier-changing commit at `ae921fe` for this transition.** The classifier in the retained `f2ed6d2` snapshot, `/tmp/wt-pre/internal/exploit/classify.go:50–164`, has the same relevant implementation as HEAD. Post-change GHSA artifacts remain `DESERIALIZATION`; the GO artifact is the resource-class one.

The actual 16-case remeasurement’s testify result is also **GHSA / `DESERIALIZATION` / `parser.peek` / `ArgAll`**, not the separate GO peer-input result:

```text
bench/vex-recheck/stretchr-testify-285adcc-CVE-2022-28948/
  CVE-2022-28948-1793057599.json
```

Thus the apparent second bisection changed the advisory-input axis as well as the code revision.

### C. Transport discovery did not select the class

`Classify(v, patch)` receives advisory metadata and fix information, **not product call paths or reachable listeners**. The builder selects the class at `internal/exploit/builder.go:123–128`, before evidence collection.

Transport proof collection occurs later at `internal/states/states.go:598–599,2791–2850`. Its eligibility reads the already-constructed model at `:2853–2876`.

The observed sequence is:

```text
wrong keyword class
  → peer pattern
  → library witness rejected
```

—not:

```text
reachable server
  → class changed
```

The transport evaluator does need a routing invariant, but changing it alone cannot repair this classification.

---

## 2. Correct class and precedence rule

### A panic is an impact, not proof of resource exhaustion

For this advisory, **`RESOURCE_EXHAUSTION` with mandatory peer input is not defensible**.

The described defect is invalid-input deserialization causing a panic. The captured fix changes parser error handling in `parser.peek`; it does not establish unbounded allocation, computational amplification, handler accumulation, or another resource-exhaustion mechanism.

DoS is a possible consequence of many classes. It must not decide the mechanism.

### Selection rule

Use this precedence:

1. **Own-record, mechanism-specific CWE evidence.**
   - Normalize CWE identifiers.
   - Make selection independent of CWE array order.
   - Specific mechanism CWEs outrank broad consequence CWEs: for example, CWE-502 plus CWE-400 selects deserialization; CWE-1333 plus CWE-400 selects ReDoS.
   - Preserve the existing crypto-mechanism-over-incidental-leak rule.
   - Conflicting, incomparable mechanisms must remain explicitly unresolved, rather than selecting the first listed CWE.

2. **Own-record statements identifying the defective mechanism.**
   - Match distinct, causally meaningful mechanisms, not total word occurrences.
   - Repeated impact language cannot increase precedence.
   - A generic operation context does not defeat a more explicit defect: “deserializing causes unbounded allocation” can be resource exhaustion; “deserializing invalid input panics” is not.

3. **Fix information only when the advisory supplies no deciding mechanism.**
   - A filename or touched symbol is a heuristic candidate, not authority to override a specific advisory mechanism.
   - Keep the existing classification-source limitation.

4. **Unresolved when equally specific mechanisms conflict.**
   - Do not use registry order, word frequency, product exposure, or whichever pattern would close a verdict as the tie-break.
   - Report the unresolved modeling obligation through the existing typed failure path.

The minimum evidence for the existing classes should be explicit:

| Class/family | Required distinguishing evidence |
|---|---|
| `DESERIALIZATION` | CWE-502, or an explicit defective deserialization/unmarshal/decode operation |
| `RESOURCE_EXHAUSTION` | Resource CWE, or explicit uncontrolled allocation/work/recursion/concurrency/amplification; **not bare panic/DoS** |
| `WIRE_PARSER` | A wire/protocol parsing defect; **not “malformed” alone** |
| `NIL_DEREF` | A nil/null dereference mechanism, not merely a crash |
| `OOB_WRITE`, `INTEGER_OVERFLOW` | Their respective memory-bound/arithmetic mechanism |
| `AUTH_BYPASS` | A failed authentication/authorization decision; omission versus defective invocation remains governed by the typed semantics contract |
| `INFO_LEAK` | A specified disclosure/retention/readability mechanism |
| `URI_CONFUSION`, `CONFIG_INJECTION` | A specified interpretation/round-trip discrepancy, not any URI/config mention |
| `CRYPTO_DOWNGRADE` | A specified cryptographic/protocol weakening mechanism |
| `PATH_TRAVERSAL`, `INJECTION`, `SSRF`, `XXE`, `REDOS`, `RACE` | The corresponding specific mechanism, not incidental shared vocabulary |

### Class, input route, and exposure are separate decisions

```text
mechanism evidence → class
mechanism + bound input surface → condition shape
product measurements → claims
supporting exposure → context/risk
```

A resource bug need not consume network-peer input. An `io.Reader` need not be a socket. A listener elsewhere in the product establishes neither.

The peer variant requires advisory-grounded peer/protocol input bound to the affected operation. Actual attacker control must still pass the existing transport/provenance admission. When input is an ordinary API argument, construct the ordinary-argument model. When the route is unresolved, do not silently choose peer input.

---

## 3. Exact fix, in scope order

### 1. Correct classifier evidence precedence

**Files:** `internal/exploit/classify.go`, `classify_test.go`.

- Replace cross-class occurrence scoring with the precedence above.
- Remove bare `panic`, `denial of service`, and `DoS` as sufficient resource-exhaustion evidence.
- Require protocol context for wire-parser classification; bare “malformed” cannot outrank deserialization.
- Resolve multiple CWE signals deterministically by mechanism specificity, not input order.
- Retain `ClassSource` and the existing limitations for heuristic inference.
- Do not synthesize CWE-502 from a class result.

Expected result:

```text
GO-2022-0603:
  class = DESERIALIZATION
  source = keywords
  CWE remains absent
```

This corrects the class. **It does not make the GO record eligible for the library exception.**

### 2. Resolve explicitly named vulnerable operations from the record’s own prose

**Files:** `internal/rootcause/rootcause.go`; `internal/domain/domain.go` and a focused domain admission helper; `internal/goanalysis/source.go` where a bounded unique-name lookup is needed.

Add a narrow typed **advisory-operation binding**, carrying:

- exact record identity/digest and affected-entry reference;
- verbatim advisory quotation naming the vulnerable operation;
- resolved package/symbol identity;
- source-location/evidence binding under the assessed build.

Resolver precedence becomes:

```text
structured advisory symbols
  → explicit own-record vulnerable-operation statements, uniquely source-bound
  → fix-diff-only candidates
```

For GHSA, its own sentence naming **“the Unmarshal function”** is sufficient to nominate `Unmarshal`; source verification must uniquely bind it within the record’s own affected module/package scope.

Important boundaries:

- A mention is not automatically a vulnerable-operation declaration.
- Do not search arbitrary unrelated packages to resolve a generic name.
- Ambiguous names, non-resolving symbols, conflicting declarations, and loader failures stay unresolved.
- Preserve all unresolved declared candidates; do not prune them to obtain a positive.
- **Do not populate or rewrite raw `Vulnerability.AffectedSymbols`, CWE, aliases, ranges, or record census.**
- Thread this binding through the root-cause model and persist the binding used by the exploit model, so replay can re-admit it.

For the GHSA record, this selects **`Unmarshal` before patch-only `parser.peek`**. The fix-changed internal function remains corroborating/alternative evidence; it does not displace an independently bound advisory operation.

### 3. Build argument and locus conditions from admitted declarations

**Files:** `internal/exploit/builder.go`; relevant builder/locus tests.

- Use structured declarations plus admitted own-record prose-operation bindings when choosing the modeled operation and locus.
- Recover `Unmarshal([]byte, interface{})` argument **0** through the existing signature resolver.
- Keep `ArgAll → INPUT_CONSTRAINT` unchanged for genuinely unresolved parameters.
- Never force argument 0 merely because the class is deserialization.
- Set ordinary generic input explicitly to `input_source=arg`; this makes the intended evaluator route unambiguous.
- Preserve `C-LOCUS`, existing expert exclusions, and unresolved-subject obligations. An ungrounded patch candidate must not become a complete declared locus merely because it exists.

Expected independently built GHSA model:

```text
Class: DESERIALIZATION
C-REACH: Unmarshal
C-INPUT: ATTACKER_CONTROL, arg 0, input_source=arg
C-LOCUS: own-record declared and source-bound operation
```

Re-admit the new prose binding wherever a saved model relies on it. Do not bypass the existing defect-semantics gate or reinterpret an unresolved check contract as an ordinary operation.

### 4. Enforce pattern/input-route separation

**Files:** `internal/exploit/patterns.go`, `builder.go`; evaluator routing tests.

Make peer-input requirements an explicit pattern variant/eligibility decision rather than an unconditional consequence of broad classes such as resource exhaustion.

- Actual peer-driven advisories retain their peer conditions and all existing transport-proof admission.
- Ordinary API input stays ordinary.
- Supporting exposure and unrelated transport evidence cannot change class, input source, or mandatory conditions.
- Keep the existing early delegation of an admitted library witness in `internal/evaluator/transport.go:31–43`.
- Do not add a permissive fallback for rejected transport witnesses.

### 5. Preserve the narrow library gate

**Production admission remains unchanged:** `internal/evaluator/library_input.go:45–108`.

It must continue requiring:

- `DESERIALIZATION`;
- **the assessed advisory’s own CWE-502**;
- `ATTACKER_CONTROL`;
- exact nonnegative ordinary argument;
- admitted library shape/census, resolved sink, exact witness and payload preservation;
- no peer/config/directional/protocol/pair semantics.

Therefore:

| Request | Intended result |
|---|---|
| GHSA, independently bound from its own bytes/source | Can earn `EXPLOITABLE / library-api` |
| CVE request with that independently earned, attributed GHSA positive | Can compose that positive |
| Exact GO record without CWE-502 | Correct deserialization model, but **no library admission** merely from classification |
| Genuine peer-input advisory | Existing transport route; no library substitution |

**The GO record cannot become a library positive under the stated constraints by classifier repair alone.** Restoring the requested CVE positive must not combine GO’s structured symbols with GHSA’s CWE.

### 6. Document the changed behavior

Update the classifier/root-cause sections of `docs/dev/analysis-internals.md`, the actionable entries in `docs/dev/gap-analysis.md`, and the measured behavior in `eval/README.md`.

Leave the definitive outcome model, `vulnerable`/`exploitable` axes, requested-finding composition, and negative admission unchanged.

---

## 4. What actually happened to the corpus

The saved run does **not** contain 15 explicit analyzer `FAILED` outcomes.

`bench/vex-recheck/results.jsonl:1–16` contains:

- **1 `DECIDED`**: Caddy, `EXPLOITABLE`, matching GT.
- **12 explicit `FAILED`.**
- **1 `missing_advisory`.**
- **2 nonzero exits with no terminal outcome/report.**

For diagnostics, inspect **both** record-level `analysis_gaps` and **`requested_finding.gaps`**. The latter contains scope/composition failures absent from the former.

Abbreviations below:

- **S** — `UNSUPPORTED_NEGATIVE_SCOPE`
- **R** — `REACHABILITY_PROOF_INCOMPLETE`
- **I** — `INPUT_TRACE_INCOMPLETE`
- **T** — `TRIGGER_PROOF_INCOMPLETE`
- **RC** — `ROOT_CAUSE_UNRESOLVED`
- **U** — `UNCLASSIFIED_ANALYSIS_GAP`
- **E** — `EXTERNAL_DEPENDENCY_UNRESOLVED`

All 12 explicit failed requested findings carry **S** in addition to the listed record causes.

| Non-decided case | Recorded diagnostics | Classification-fix assessment |
|---|---|---|
| **testify `285adcc`, CVE-2022-28948** | **I** on `C-INPUT`; GHSA/deserialization, `parser.peek`, arg −1, no locus | **Directly explained by own-record operation recovery.** Separate GO run also exposes classifier defect. |
| trivy `37da98d`, CVE-2024-32473 | **R, I**; subject packages absent, but negative refused for unscoped host-default target | Target/negative-admission gap, not YAML misclassification. |
| minikube `e7bf515`, CVE-2019-5736 | `missing_advisory`; no assessment | Corpus/input absence; not a classified analyzer failure. |
| headscale `e172c29`, CVE-2024-45338 | **R** on reach/locus; **I** on peer/constraint | Advisory explicitly describes non-linear parsing. Resource class is defensible; peer-source selection needs its own grounding. Reach/locus still block closure. |
| go-zero `bae061a`, CVE-2022-32149 | **S only**; primary record is `DECIDED / NOT_AFFECTED`, x/text v0.4.0 outside range | Legitimate requested-CVE scope refusal. Class fix irrelevant. |
| cilium `43bff35`, CVE-2026-35469 | **U, E**; `go list` excludes Linux ethtool files on Darwin | Build-selection failure; runner target-map entry names a different commit. |
| podman `6541fc4`, CVE-2025-58181 | **U, E**; build fails in vendored gpgme | Build/tag configuration failure, not class substitution. |
| rancher `4dc4f53`, CVE-2025-47914 | **RC, U**; no resolved operation/fix candidate | Separate root-cause capability gap; no positive recovery promised here. |
| rancher `4dc4f53`, CVE-2025-58181 | **R, I** on reach/input/constraint/locus | Genuine “unbounded memory consumption” in SSH GSSAPI requests. Resource/peer mechanism is defensible; proofs remain incomplete. |
| cilium `3977f6a`, CVE-2026-33186 | **U, E**; Linux ethtool build constraints | Build-selection failure. |
| moby `3ede246`, CVE-2026-39984 | **U, E**; `daemon/internal/containerfs` build failure | Build-selection failure. |
| kubernetes `e196d24`, CVE-2023-44487 | **RC, S**; broad GHSA has 22 entries, only one represented; x/net version negative | Independent record discovery/attribution/transport-proof issue, not YAML classification. |
| kubernetes `1ee2acb`, CVE-2024-24786 | No terminal gaps/outcome; stopped at `RESOLVE_ROOT_CAUSE` | Unfinished/error run. Cause not recoverable from saved diagnostics. |
| echo `fdacff0`, CVE-2020-26160 | **R, T**; `DEFECTIVE_CHECK`, receiver input and `req=false` trigger | Intended typed-check model, not contamination. Negative proof/target/scope remain required. |
| trivy `98e136e`, CVE-2024-24791 | No terminal gaps/outcome; stopped at `CHECK_AFFECTED` | Unfinished/error run. Cause not recoverable from saved diagnostics. |

### Which failures are legitimate?

- **Legitimate scope refusal:** go-zero’s primary version-negative does not authorize a CVE-wide negative. The same scope restriction applies to other attempted negatives.
- **Real build-selection blockers:** the four Cilium/Podman/Moby rows have concrete failed inventories. They justify withholding a verdict, **not** declaring the products safe or declaring those measurements inherently unavoidable.
- **Analyzer work, not environmental excuses:** unresolved roots, reachability, input, triggers, and Echo negative proof remain capability failures.
- **Unclassified unfinished runs:** the two empty-outcome rows cannot honestly be labeled build failures. Their stderr was not persisted by the runner (`bench/run_vex_recheck.py:62–68`).

There is also a run-provenance discrepancy: the current runner passes `--osv-feed` at `:55`, but saved cases say **`related_discovery.enumeration=not_configured`**. Therefore these artifacts do not establish that configured corpus discovery ran. A feed also supplies no negative closure authority without the explicit declaration.

**Conclusion:** this is not a single misclassification mass-failing the corpus. Only testify has the demonstrated ordinary-argument regression. Faster failures frequently occurred before a model existed.

---

## 5. Required regression protection

### A. Pin exact advisory-family classification

Add a table-driven test in `internal/exploit/classify_test.go` using **frozen raw OSV documents parsed through the actual exact-record decoder**, not hand-assembled summaries.

At minimum:

| Advisory family | Assertion |
|---|---|
| YAML panic, GHSA | `DESERIALIZATION / cwe` |
| Same YAML mechanism, GO | `DESERIALIZATION / keywords`; CWE remains absent |
| SSH GSSAPI unbounded allocation, GO-2025-4134 | `RESOURCE_EXHAUSTION`; peer variant justified by request mechanism |
| Non-linear HTML parsing, GO-2024-3333 | Resource mechanism retained; no automatic network-source inference |
| HTTP/2 Rapid Reset | Resource mechanism and peer variant retained |
| JWT audience verification, GO-2020-0017 | `AUTH_BYPASS`; typed `DEFECTIVE_CHECK`, not omission |
| Existing credential, URI-roundtrip, crypto-downgrade families | Their exact intended classes, not “either class is acceptable” |

Add counterexamples:

- Repeating “panic” or “denial of service” cannot change a deserialization class.
- “Malformed document” without wire context cannot create a wire-parser class.
- Deserialization with explicitly unbounded allocation can remain resource exhaustion.
- Reverse the CWE list: selection must not change.
- Conflicting equally specific evidence produces an explicit unresolved result.
- Adding unrelated listeners, call paths, or supporting exposure changes neither class nor mandatory input shape.

Current tests such as `TestClassifyAmbiguousScores` at `classify_test.go:145–162` encode frequency-based behavior. Replace that contract. Tests allowing either class in a family do not pin class selection.

### B. Pin exact-record subject recovery

In `internal/rootcause` and builder/locus tests:

1. Exact document has CWE-502 and names `ParseBytes` in prose, but has no structured symbols.
2. Its fix changes a zero-argument internal parser method.
3. Resolve the prose operation uniquely against source.
4. Assert exact-argument input and mandatory locus.
5. Assert raw advisory symbols, census, digest, aliases and CWE are unchanged.

Controls: duplicate names, wrong module, non-resolving declaration, incidental mention, contradictory declaration, stale quotation/source evidence, and loader failure must not admit the binding.

### C. Pin both library routes without widening either

Extend `internal/states/library_scope_e2e_test.go`:

- Exercise the **production exact-record pipeline**, not only `StaticSource` with pre-populated symbols.
- Keep the existing library admission controls, particularly:
  - missing CWE-502;
  - wrong class;
  - `ArgAll`/receiver input;
  - peer/protocol input;
  - incomplete census;
  - missing reach or locus;
  - security-relevant payload transformation.
- An unrelated transport witness must not satisfy or rewrite the ordinary argument condition.
- A library witness must not satisfy a genuine peer condition.

### D. Pin the real testify positive

Add a real-snapshot calibration in the existing `cmd/izyan` calibration style:

```text
snapshot: stretchr/testify @ 285adcc5ced0bb267a7c874cfa3ca238266ce14f
record:   frozen GHSA-hp87-p4gw-j4gq, exact bytes, no alias enrichment
mode:     deterministic-only
```

Require:

- independently derived `Unmarshal`, argument 0, and `C-LOCUS`;
- `C-REACH=TRUE`;
- `C-INPUT=TRUE`, `control_basis=library-public-api`;
- `C-LOCUS=TRUE`;
- **`DECIDED / EXPLOITABLE / library-api`**;
- persisted witness and evidence references survive publication admission;
- requested axes are `vulnerable=TRUE`, `exploitable=TRUE`;
- CVE composition cites the independently earned GHSA assessment;
- exact GO control keeps its absent CWE and receives no library admission.

Missing external assets may produce an explicit skip. **Available assets producing `FAILED` must fail the test**, not merely print “acceptance not met.”

The historical positive proves that the source/witness path existed; it does not prove the new isolated pipeline passes these acceptance checks before implementation.

---

## Handoff contract

**No user-owned question is necessary.** The constraints determine the choice:

- preserve exact-record isolation;
- recover GHSA’s operation from its own evidence;
- separate mechanism from impact, input route, and exposure;
- never synthesize CWE or merge record facts;
- retain all structural, target, measurement, negative, transport and defect-semantics gates;
- preserve definitive outcomes and the two presentation axes.

If implementation finds that the GHSA quotation cannot uniquely bind the operation under the recorded source/build, it must fail closed and return that evidence—not restore alias inheritance or widen library admission.

**Evidence scope:** read-only source, retained snapshots, commit reflog/task reports, and saved run artifacts were inspected. No files were changed and no builds, tests, or analyzer reruns were performed.

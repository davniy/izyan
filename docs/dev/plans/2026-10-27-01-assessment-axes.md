# DESIGN_FOR_REVIEW

**Decision: adopt the user’s two-question framing, but refine the semantics. The proposed verdict-to-pair table is not a valid general mapping. Keep the existing verdict evaluator and outcome model; add a shared, derived presentation of the two facts.**

**Design gate: READY.** No user-owned question is necessary.

## 1. Verdict on the model and table

The primary questions should be:

1. **Vulnerable code/version in the assessed build?**
2. **Exploitable within the assessed scope and threat profile?**

“Record versus CVE” is a separate **subject/coverage boundary**, not an alternative to those questions. It must remain prominent because it determines what an answer can close.

Two refinements are essential:

- These are separate questions, but not fully independent Boolean axes: **exploitable implies vulnerable**, for the same vulnerability, build and scope.
- The analyzer does not always establish exploitation **in a deployment**. Existing `library-api` and `transport-peer` positives explicitly leave downstream/deployed adversary access unestablished. Do not relabel those results as deployment exploitability. See `internal/domain/library_scope.go:95–124` and `internal/domain/transport_scope.go:3–26`.

### The proposed table is incomplete

| Existing classification | Vulnerable code/version in build | Exploitable in assessed scope |
|---|---|---|
| `DECIDED / NOT_AFFECTED` | **No**, within the admitted negative boundary | Not applicable |
| `DECIDED / NO_EXPLOIT_PATH_FOUND` | **Yes or unknown**, independently established | **No**, under the recorded build/profile/assumptions |
| `DECIDED / EXPLOITABLE` | Yes, as a consequence of the admitted exploitability proof | **Yes**, with the existing scope qualifier |
| `EXTERNAL_DEPENDENCY / INCONCLUSIVE` | Preserve established facts; not necessarily unknown | Unknown |
| `FAILED`, no verdict | Preserve established facts; not necessarily unknown | No requested exploitability conclusion |

The important correction is **NEPF does not universally mean vulnerable=yes**.

The evaluator requires an admitted, verified mandatory-condition falsifier for NEPF, but does not require all affected-chain facts to be affirmative before returning it. A concrete existing test earns NEPF with only `Affected.Scope` populated: `internal/finding/outcome_test.go:100–121`. The implementation-presence axis also defaults to `UNKNOWN`: `internal/affected/resolver.go:48–53`.

Therefore:

> Echo supports “vulnerable=yes, exploitable=no.” NEPF by itself does not establish the first fact.

The documented Echo measurement confirms the corrected exact-record NEPF, while the requested CVE remains `FAILED / UNSUPPORTED_NEGATIVE_SCOPE`: `eval/README.md:191–207`.

### The fourth Boolean cell

**Not vulnerable + exploitable is a contradiction**, not a fourth business outcome.

For admitted inputs, the evaluator checks affected-chain negatives before allowing an exploitability positive. A non-closing negative scope returns inconclusive rather than falling through to a positive: `internal/evaluator/verdict.go:216–299`. `TestVerdictFixedPartialScopeCannotBecomePositive` explicitly covers that protection.

However, the code does **not** enforce “all five affected fields must be TRUE” for every positive. An unknown measurement is not a negative fact. Consequently, do not implement the new model as a mechanical conjunction of five fields or pretend that every accepted positive has five independent affirmative measurements.

## 2. Exact target semantics and fields

### Keep authoritative classification unchanged

Retain:

- `assessment_outcome`: `DECIDED`, `EXTERNAL_DEPENDENCY`, `FAILED`;
- existing verdict values;
- existing affected facts, claims, verification records and evidence;
- `exploitability_scope`, threat profile, build, assumptions, proof origins and corpus boundary.

**Do not derive authoritative verdicts or outcomes from the presentation pair.** That would introduce a second evaluator and lose distinctions the pair cannot express.

### Add one non-authoritative projection

Add an optional report-level member:

```json
{
  "assessment_axes": {
    "requested": [
      {
        "subject_id": "GO-2020-0017",
        "assessment_id": "...",
        "profile": "...",
        "is_target_actual": true,
        "build": {},
        "vulnerable_code_in_build": "TRUE",
        "exploitable": "FALSE"
      }
    ],
    "records": []
  }
}
```

Both arrays contain identity-bound, per-profile rows. A record row additionally carries its exact `RecordPin`. Carry `exploitability_scope` on the row when present.

**Field values**

- `vulnerable_code_in_build`: `TRUE | FALSE | UNKNOWN`
- `exploitable`: `TRUE | FALSE | UNKNOWN | NOT_APPLICABLE`

Use `exploitable`, **not** `exploitable_in_deployment`: the latter would misstate existing scoped positives.

### Vulnerability-axis rules

Compute from the record’s **admitted facts and subject boundary**, not a verdict lookup:

1. An earned `NOT_AFFECTED` establishes `FALSE` for its admitted boundary.
2. Established module presence, affected version, package presence and build relevance establish `TRUE`, unless an admitted implementation-absence fact excludes the vulnerable implementation.
3. Missing required applicability facts yield `UNKNOWN`.
4. An admitted exploitability positive entails `TRUE`; its existing proof references are the justification for that implication. Do not rewrite the raw affected fields.
5. NEPF alone supplies **no affirmative vulnerability fact**.
6. Failed/external exploit analysis does not erase independently established applicability.

The fifth affected field is currently an **optional additional implementation check**, not a universally required measurement. `internal/research/assemble.go:752–762` explicitly preserves an otherwise resolved chain when that optional axis is unknown. Requiring it to be TRUE everywhere would change analysis policy, not merely presentation.

Also, “in build” must retain the repository’s existing meaning—recorded build/import applicability. It must not imply that binary-byte presence was independently attested when only source/build measurements exist.

### Exploitability-axis rules

Use the already-admitted assessment result:

- `EXPLOITABLE` → `TRUE`;
- NEPF → `FALSE`;
- `NOT_AFFECTED` → `NOT_APPLICABLE`;
- external/failed/unpublished result → `UNKNOWN`.

A raw `FALSE` claim—even one labelled `VERIFIED`—must not bypass final scope, target, review or admission gates to populate `exploitable=FALSE`.

For `library-api` or `transport-peer`, render:

> Exploitable: **yes, at the library API / transport-peer boundary**. Deployed attacker access is not established.

Never show an unqualified “exploitable in deployment: yes” for those results.

### What must remain distinct

The pair cannot replace:

- `FAILED` versus `EXTERNAL_DEPENDENCY`;
- code-proven versus assumption-dependent NEPF;
- build/profile and library/transport scope;
- record-level versus requested-CVE authority;
- proof origins, falsifier, evidence and limitations;
- corpus-bounded versus unrestricted claims.

In particular, `TRUE / UNKNOWN` can accompany either external dependency or failed analysis. The pair alone cannot tell the operator what work remains or who owns it.

## 3. VEX/CycloneDX: conceptually compatible, current mapping partly defective

### What the standards actually encode

The user’s distinction is consistent with VEX practice, but **neither standard is exactly a two-Boolean schema**.

[OpenVEX 0.2.0](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md#status-justifications) uses an impact status plus justification. `not_affected` can mean:

- component absent;
- component included but vulnerable code absent;
- vulnerable code cannot execute;
- vulnerable code cannot be attacker-controlled;
- qualifying built-in mitigations prevent exploitation.

Thus **OpenVEX `not_affected` does not mean our vulnerability axis is false**.

[CycloneDX 1.5](https://cyclonedx.org/schema/bom-1.5.schema.json) similarly separates analysis state and justification. It also has version/range affected status in `affects[].versions[]`, but that does not establish build linkage or deployment exploitability.

**Do not change verified NEPF exports to `affected` merely because vulnerable code is present.** The existing coarse mapping to VEX `not_affected` is correct.

### Required mapping

| Admitted proof | OpenVEX | CycloneDX |
|---|---|---|
| Module/component absent | `not_affected` + `component_not_present` | `not_affected` + `code_not_present` |
| Component included, but affected code absent: fixed version, package excluded, build exclusion, implementation absence | `not_affected` + `vulnerable_code_not_present` | `not_affected` + `code_not_present` |
| Vulnerable operation cannot execute | `not_affected` + `vulnerable_code_not_in_execute_path` | `not_affected` + `code_not_reachable` |
| Triggering input cannot be adversary-controlled | `not_affected` + `vulnerable_code_cannot_be_controlled_by_adversary` | Appropriate supported justification, or explanatory `detail`; **not automatically `code_not_reachable`** |
| Required configuration/environment absent | `not_affected` with an accurate impact statement when no justification exactly fits | `requires_configuration` / `requires_environment`, as supported by the proof |
| Admitted trust/perimeter basis | Current adversary-control justification, with the assumption explicitly stated | Current perimeter/mitigating-control mapping, with basis explicitly stated |
| `EXPLOITABLE` | `affected` + action | `exploitable` + recommendation |
| External dependency | `under_investigation`, named external fact | `in_triage`, named external fact |
| Failed analysis | `under_investigation`, explicit analysis failure | `in_triage`, explicit analysis failure |

Only use `inline_mitigations_already_exist` when OpenVEX’s stronger conditions hold—including that the protection cannot be subverted or disabled. An arbitrary guard does not automatically qualify.

### Verified defects in the current code

1. **Implementation absence is incorrectly exported as non-execution.**  
   `notAffectedJustification` says OpenVEX has no suitable label for target-excluded implementation code and returns `vulnerable_code_not_in_execute_path`. The specification explicitly describes `vulnerable_code_not_present` as including build-time exclusion.  
   **Fix:** `internal/report/openvex.go:261–282`.

2. **Build exclusion is incorrectly labelled component absence.**  
   The same helper maps `BuildRelevant=FALSE` to `component_not_present`, although the module/component can be present. Use vulnerable-code absence when that is the established fact.

3. **NEPF’s default justification overclaims unreachability.**  
   Both legacy exporters and `exportStateFor` default NEPF to execute-path/code-not-reachable. Current NEPF falsifiers also cover configuration, input provenance, guards and environment facts. These can falsify exploitation while vulnerable code still executes.  
   **Fix:** select justification from the **grounding condition/claim and proof basis**, not just the verdict and `GroundBasis`.  
   Files: `openvex.go:209–224`, `cyclonedx.go:231–247`, `requested_finding.go:1131–1159`.

4. **Corpus negatives invent a reachability explanation.**  
   `corpusNegativeJustification` returns execute-path exclusion unless every candidate proved component absence. That misdescribes mixed version/code-absence negatives, and cannot describe an empty corpus accurately.  
   **Fix:** aggregate the actual absence reasons. When no enum truthfully describes the result, omit it and carry the admitted explanation and verbatim corpus boundary.  
   File: `internal/report/requested_finding.go:1280–1304`.

5. **The generic justification fallback invents facts.**  
   `cycloneJustificationFor` defaults to `code_not_present`. Unknown or unmatched proof categories must not become an absence assertion. Use explanation-only output when no enum fits.

### Export-format defects found during this review

These are separate from the verdict semantics but directly affect the requested export correctness:

- OpenVEX currently writes statement-level `subcomponents` and subcomponent `name`. The [official schema](https://github.com/openvex/spec/blob/main/openvex_json_schema.json) instead nests subcomponents under each product and does not allow those fields there.
- CycloneDX emits `urn:uuid:izyan-<case>` as `serialNumber`; the 1.5 schema requires an RFC-4122-shaped UUID.

Correct these export shapes while changing the exporters. Existing vocabulary tests are not substitutes for full schema validation. This is an export correction, not a persisted-case migration.

## 4. Present scope so a record negative cannot close a CVE

Lead with both facts, but always bind them to an explicit subject:

```text
Requested subject: CVE-2020-26160
Outcome: FAILED
Requested exploitability conclusion: UNKNOWN
Reason: unsupported negative scope

Independently assessed record: GO-2020-0017 [document digest]
Vulnerable code/version in assessed build: YES
Exploitable in assessed scope: NO
Verdict: NO_EXPLOIT_PATH_FOUND
This record-level negative does not close the requested CVE.
```

For minimal scope:

- Do not create a new vulnerability-only CVE aggregation algorithm.
- Requested positives use the existing admitted witnesses.
- Requested negatives use the existing corpus-negative basis.
- On an unresolved CVE request, retain unknown request-wide axes and show established record facts immediately below.
- Never copy the primary record’s axes into a CVE answer merely because it was resolved first.
- Keep `coverage=KNOWN_ONLY` for CVE requests, even with an admitted corpus negative; corpus authority travels in `corpus_negative_basis`.

The current composition deliberately **does not lift NEPF to a CVE negative**, even with a complete corpus. Every nominated candidate must independently earn `NOT_AFFECTED`: `internal/domain/related_records.go:474–502`, `internal/finding/compose.go:150–173`. Preserve that policy.

## 5. Operator actions and ticket closure

| Cell | Operator action | May close? |
|---|---|---|
| Vulnerable **no**, exploitable **N/A** | Dismiss the applicability finding with its exact exclusion reason and build/subject boundary. | **Yes**, if the earned requested negative covers the ticket. |
| Vulnerable **yes**, exploitable **no** | Record verified non-exploitability, its falsifier, scope and assumptions. Reassess after relevant code/build/configuration/trust changes. Do not describe the component as fixed. | **Yes for a matching exploitability ticket**, when existing gates authorize it. Not automatically a vulnerable-component remediation obligation or broader CVE ticket. |
| Vulnerable **yes**, exploitable **yes** | Remediate or mitigate using the witness-bound target; preserve scope limitations. | **No** on analysis alone. |
| Vulnerable **no**, exploitable **yes** | Treat as inconsistent identity, evidence or projection; never normalize to safe. | **No**. |

Any unresolved axis requires explicit interpretation:

- `UNKNOWN` is neither no nor safe.
- `EXTERNAL_DEPENDENCY` requests the named fact.
- `FAILED` requires resolving the named analysis gaps.
- `UNKNOWN / FALSE` can still be an existing admitted record NEPF: exploitation was refuted without proving code presence. Its closure authority remains exactly the existing NEPF boundary, not a new applicability conclusion.

Current risk code assigns dismissed/zero contextual risk to both negative verdicts. **Do not change those scores or priorities in this work.** Correct its misleading prose: `risk.go:67` assumes every `NOT_AFFECTED` means module-unlinked, while `:81` assumes every NEPF means no call path. Neither is universally true.

## 6. Implementation scope, in order

1. **Shared derived projection**
   - New small `internal/finding/axes.go`.
   - Extend non-persisted `finding.View` in `internal/finding/project.go`.
   - Compute identity/profile-bound rows after existing admission.
   - No new verdict evaluation, evidence collection or scope-composition policy.

2. **JSON compatibility**
   - **Leave `case.json`, `AnalysisCase`, `RequestedFinding` and `FindingProfile` unchanged.**
   - In `internal/report/report.go`, wrap the existing report serialization with optional top-level `assessment_axes`.
   - Do not add fields that would disturb `requestedDrift`’s existing comparisons.
   - Old reports remain readable; regenerated reports gain the projection. Never trust supplied display axes as proof.

3. **Human and CLI surfaces**
   - `internal/report/requested_finding.go`: summary, facts, candidate rows, tracker rationale.
   - `internal/report/report.go`: record summary and misleading legacy negative wording.
   - `cmd/izyan/main.go`: append axis output; retain existing output keys.
   - `cmd/izyan/remediate.go`: replace “no remediation is due” with the narrower absence of a witness-bound fix target.
   - `internal/justification/builder.go`: render the same projected pair.
   - `internal/risk/risk.go`: wording only.

4. **VEX/CycloneDX corrections**
   - `internal/report/openvex.go`
   - `internal/report/cyclonedx.go`
   - `internal/report/requested_finding.go`
   - Share proof-based justification selection between projected and legacy rendering without changing their admission contracts.
   - Carry the axes in existing explanatory text; do not invent OpenVEX fields. No custom CycloneDX properties are necessary.

5. **Research/evaluation reporting**
   - `internal/research/requested_finding.go`: retain the shared derived projection alongside the admitted composition.
   - `types.go`, `assemble.go`, `render.go`, `validate.go`: optional top-level `assessment_axes` for research-report `/4`.
   - Keep `/1`–`/3` output unchanged; keep existing research `ExploitationAxes` separate—they are evidence-level analyses, not this result pair.
   - `internal/eval/eval.go`, `cmd/izyan/eval.go`: add per-case pair columns/fields.
   - Do not change scoring, false-safe accounting or outcome populations.

6. **Documentation**
   - Update `docs/architecture.md`, `docs/how-it-works.md`, `docs/cli.md`, `docs/dev/gap-analysis.md` and `eval/README.md`.
   - Explicitly document that VEX `not_affected` can coexist with vulnerable code present, and that NEPF is earned negative proof—not an unsuccessful path search.

## 7. Tests

Add or extend:

- **Axis projection:** affirmative applicability; each admitted absence route; optional implementation `UNKNOWN`; NEPF with unknown applicability; failed/external analysis retaining affirmative facts; scoped positives.
- **Invariant:** admitted vulnerability `FALSE` cannot accompany exploitability `TRUE`; stale or refused negatives never populate `FALSE`.
- **Scope:** exact-record NEPF does not become requested-CVE non-exploitability; complete corpus containing NEPF still cannot close; composed positive uses its witnesses, not the primary record.
- **Compatibility:** old `analysis-case/2` cases re-admit without drift; `case.json` remains unchanged; report axes are additive and cannot influence admission.
- **Export reason matrix:** absence, unreachability, constant input, configuration, environment, guards, trust/perimeter and mixed/empty corpus cases. Exercise both legacy and projected paths.
- **Official-schema validation:** OpenVEX product/subcomponent structure and CycloneDX serial number, in addition to semantic assertions.
- **Rendering:** RU/EN summaries, tracker, CLI, remediation and dossier agree on pair, identity and scope.
- **Research/eval:** `/1`–`/3` compatibility remains intact; `/4` carries the optional projection; existing scoring and outcome counts are unchanged.
- **Risk wording:** version exclusion does not claim module absence; trust/config NEPF does not claim code unreachability.

**Bottom line:** the user’s distinction is the right primary presentation. The correction is not “replace one verdict with two booleans.” It is **show two evidence-qualified facts, retain outcome and closure authority, and fix exporters that currently confuse code absence, non-execution and other reasons exploitation is impossible.**

*Read-only review. No repository files changed; no builds, tests or analyzer reruns performed.*

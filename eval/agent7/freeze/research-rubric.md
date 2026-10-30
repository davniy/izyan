# A1 — Research reference rubric (agent7, PR-0)

Independent reference rubric scored **per case**, blind to arm labels.
It measures *research quality* only — auto-close eligibility is a separate
metric and is scored by the proof lane, never by this rubric (spec §9.2).

## 1. How the reference is built

- For each selected case, reviewers assemble the reference **before**
  seeing any arm output: defect root cause, known affected
  manifestations, necessary exploitation conditions, admissible call
  paths, known counterexamples, checkable sources, and the admissible
  residue of uncertainty.
- The reference is built **without arm labels** and **without the
  case-specific reference PR** (the benchmark `metadata.pr_url` entry is
  a fixing-PR pointer, controller-side only, `gt_paths_denied`-class
  data). Development history must not contaminate the reference.
- GT `safe/exploitable` is **not** the mechanism reference: it gates
  denominators and smoke selection, never the section scores.

## 2. Scored sections (design §6)

Each `ResearchAssessment` section is scored independently on the anchored
scale below. A report that only names a package and echoes the advisory is
**not** a success (spec §6).

| Section | What is being judged |
|---|---|
| `vulnerability_mechanism` | What exactly is broken, the effect, why it happens |
| `root_cause` | Precise source/artifact location and its role; verified source binding or explicit `UNKNOWN` |
| `attack_scenario` | Attacker actions, entrypoint, path to the defect, required predicates |
| `product_exposure` | Where the target uses the functionality; known/unknown build, configuration, deployment facts |
| `alternative_paths` | Alternative manifestations found and counterarguments checked, or an explicit "not fully explored" |
| `evidence_quality` | References to underlying observations with scope/status; disagreements flagged |
| `residual_questions` | Concrete remaining facts/actions a human needs to finish the analysis |
| `triage_recommendation` | Actionable disposition (fix / verify / low confirmed risk / needs review) with reason and bounds |

## 3. Anchored levels

Every section is scored 0–2 against fixed anchors (no fractional
generosity):

| Level | Anchor |
|---|---|
| 0 | Missing, wrong, or a bare restatement of the advisory with no mechanism grounding |
| 1 | Partially correct: real content but a material error, an unjustified precondition, a missed known manifestation, or unverifiable claims presented as verified |
| 2 | Correct and specific: matches the reference (or a justified superset), every precondition argued, every claim bound to an observation or an explicit `UNKNOWN` |

Additional anchored flags per case (counted, not averaged):

- **missed alternative manifestations** — manifestations in the reference
  the report neither found nor excluded with a checkable argument;
- **correctly justified preconditions** — the share of required
  exploitation conditions the report both states and argues;
- **invalid operations / unverifiable claims** — assertions presented as
  verified without an observation that can carry them.

## 4. Headline metrics (spec §9.2)

Computed per arm over the scored case set, attempt- and case-level
reported separately:

- **mechanism / root-cause precision and recall** against the reference;
- **missed alternative manifestations** count;
- **correctly justified preconditions** share;
- **evidence discovery gain** vs plain agent (B1) and the fixed fact lane;
- **`proposed_false_safe`** — cases where the report's own conclusion
  would have closed a GT-exploitable case;
- exploit recall, completion rate, invalid-operation rate, tool-failure
  rate, cost/latency;
- the proof lane adds `certified_safe`, `incremental_safe_clear`,
  `accepted_false_safe`, certificate replay success, cost per new
  verified safe — **separately**, never folded into the rubric score.

## 5. Human effort fields

Each reviewer records, per case:

- `minutes` — wall-clock time to reach a confident decision;
- `extra_manual_checks` — count of verification steps the reviewer had to
  perform because the report did not resolve them;
- `report_corrections` — count of factual or scope corrections the
  reviewer had to apply to the report's claims.

These feed `analyst time-to-decision` and helpfulness — the Checkpoint-A
usefulness axis — not the safety metrics.

## 6. Reviewers and arbitration

- **Two independent reviewers** score every case blind; neither sees the
  other's sheet first.
- Disagreement ≥1 anchored level on any section, or any disagreement on
  `proposed_false_safe` / `proposed_true_exploit`, goes to **arbitration**
  by a third reviewer who sees both sheets plus the raw artifacts; the
  arbitrated score and both raw scores are all retained.
- Inter-rater agreement is reported per section, not just on the total.

## 7. Separation of concerns

- Research quality and auto-close eligibility are **separate metrics**: a
  high rubric score never promotes a disposition, and a certificate never
  inflates a rubric score.
- `no exploit path observed` is a research finding, not a verified
  negative; only the proof lane can produce `AUTO_CLOSE_ELIGIBLE`.
- The rubric is frozen before runs begin; post-hoc anchor edits are
  recorded as `limitations`, never silently applied.

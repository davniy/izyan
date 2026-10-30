# Task 6 — decision

**Report on the checkability of a structured evidence contract. No production
Verification Gate is started.**

Run: frozen `eval/task6/experiment-manifest.json` (30 Go cases, model
`qwen3.6-35b`). P2 = structured prompt, no MCP (30×3). T2 = same + 31 MCP tools
(30×1; operator-bounded deviation). V-P2/V-T2 = offline validator replay of the
same saved answers (no model calls).

## Completion criteria

### 1. Is the structured prompt sufficient? — **No.**

Adding the `assessment` object broke format compliance versus the Task-5 P1
baseline (same model, small object):

| arm | prompt | parsed `ok` | false-safe |
|---|---|---:|---:|
| P1 (Task 5) | official + `<SAFETY_RULES>` | **85/90 (94 %)** | 3 cases |
| P2 (Task 6) | + `<STRUCTURED_ASSESSMENT>` | **56/90 (62 %)** | 1 / 21 attempts |
| T2 (Task 6) | P2 + tools block | **23/30 (77 %)** | 0 / 7 |

P2's 22 `parse_fail`: 13 malformed (nested `{}` inside `reasoning` defeats the
official brace-counting parser), 8 prose summaries instead of the object, 1 JSON
emitted as a double-escaped string. The parser, the string-aware `parser_audit`
extractor, and `collect` all agree the object is genuinely absent — it is a model
output defect, not a pipeline defect. A further 12 P2 attempts were container
timeouts (9 in a host/VPN window). **A single top-level JSON object holding the
large nested assessment is beyond Qwen 3.6's reliable-format budget in ~1/3 of
answers.** The schema must be made robust (or simplified) before it can gate real
answers.

### 2. Do the MCP tools add measurable value? — **Marginal, not proven.**

T2 parsed more (77 % vs 62 %), produced **0** false-safes vs P2's 1, at a lower
SCR denominator (65.2 % vs 56.5 %) — directionally favourable but confounded by
the n=1/n=3 imbalance and by the tools block being extra prompt guidance. Not
decisive; a causal P2↔T2 claim needs matched n.

### 3. Is independent verification possible without excessive INCONCLUSIVE? — **No.**

The offline validator is far too strict to be usable as a safety gate:

| projection | FS blocked | **correct safe blocked** (attempts / cases) | SCR after |
|---|---:|---:|---:|
| V-P2 | 1 / 1 | **39 / 18** | **0.0 %** |
| V-T2 | 0 | **15 / 15** | **0.0 %** |

V-P2 blocks 39 of 45 correct-safe attempts (87 %); V-T2 blocks all 15. It removes
the 1 real false-safe — and every correct safe answer with it, because C4 demands
coverage of the *entire* advisory-declared affected set and C1/C2/C3 reject the
PARTIAL/error/scope-limited evidence that normal safe answers legitimately rest
on. `valid-claim share` is only 25.6 % / 23.3 %. This is exactly the
"everything → INCONCLUSIVE" failure the brief disqualifies: on V-P2 the Safe
Clear Rate goes from 56.5 % to **0 %**.

Note the contract *is* checkable — V-P2's checkable-negative-claim share is 95.6 %
(109/114) — but "checkable" ≠ "acceptable": the strictness, not the mechanism, is
what fails.

## Decision

**Row: "No variant clears the safety bar."** → the analyzer remains a
research/triage assistant under human review; **no automatic closure**; **no
production Verification Gate**.

- Structured contract alone: not sufficient (format).
- MCP: marginal, unproven.
- Independent validator: technically checkable but operationally unusable
  (destroys all correct safe answers).

**Next hypothesis (not started):** relax the validator's scope-coverage rule —
require coverage of the *landed* manifest/config subject rather than the whole
advisory, and accept scope-matched PARTIAL evidence — then re-measure FS-blocked
vs correct-safe-lost on an **unseen holdout** before any Gate is planned.

## Caveats / limitations

- **Attempt-policy deviation:** P2 30×3, T2 30×1 (matched n=1). The dev run was
  bounded by operator decision (the completion criteria need aggregate rates,
  not rare-event precision); T2 was planned 30×3 in the frozen manifest.
- 9 of the 12 P2 `no_result` are a host/VPN window; 3 are isolated timeouts.
- **No holdout** was run → this is a **PRELIMINARY** result; nothing here claims
  proven safety on unseen data.
- Report-side bug observed: the T2 `EXP recall` shows 114.3 % (a ≥100 % rate is
  impossible; per-case it is 6/6). Denominator issue in the 1-repeat arm's recall;
  does not affect the decision.
- **No production Verification Gate**; no `internal/verificationgate` created; no
  production Go changes.

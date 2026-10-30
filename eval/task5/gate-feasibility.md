# Task 5.3 — minimal offline Gate feasibility trial

**Input:** the saved, immutable T1 responses (30 cases × 3 = 90 attempts,
`qwen3.6-35b`, `vuln_safety_v1_tools`). **No new model calls.** A post-processor
reads only what each attempt already produced.

**Question:** can a *general* rule detect insufficient evidence behind negative
("safe") conclusions, blocking real false-safes while keeping correct safe
answers? If it only turns everything into `INCONCLUSIVE`, it is worthless.

## Step 1 — read the negative conclusions themselves

The three named cases, and what their reasoning actually rests on. This is the
part that matters: the two mechanisms are different.

| Case (false-safe attempt) | Claim | Evidence it rests on | Mechanism |
|---|---|---|---|
| `rancher-47914` run_002 | "`parseConstraints` never reached because the git client sends no constraint payload" | `find_callers` **ERROR ×3** (`context canceled`), `find_validations` **ERROR** | **error-as-absence** |
| `k8s-3121` run_002 | "`plugin/unmarshal` not imported by first-party code" | `find_symbol` **ERROR**, `find_callers` **ERROR** (`go: updates to go.mod needed`) | **error-as-absence** |
| `testify-28948` run_001 | "`assert.YAMLEq` is never invoked from any code path" | `find_callers`/`find_may_callers` **OK, PARTIAL**, scope `product packages` (0 results) | generalization from a **scoped** zero |

So two of the three are **failed tool calls read as absence**; one is a
**correct-scope observation mis-generalized**.

## Step 2 — generic rules, and both required quantities

Denominators: `false-safe = 5` (safe on a GT-exploitable case, of 21 exploitable
attempts); `correct-safe = 63` (of 69 safe attempts), per `safety-report.md`.

| Rule (all generic, no case names) | False-safe blocked | Correct-safe **lost** |
|---|---:|---:|
| **RG** negative claim AND no *successful* reachability observation (error-as-absence) | 2 / 5 | **19 / 63** |
| **RH** negative claim AND *any* errored reachability observation | 2 / 5 | 28 / 63 |
| **R6** negative claim + zero-result reachability query that declares its own scope incomplete | 3 / 5 | 26 / 63 |
| **UNION** (RG ∪ R6) | **5 / 5** | **46 / 63 (73 %)** |

- `RG` catches exactly `k8s-3121` and `rancher-47914` — the error-as-absence pair.
- `R6` catches only `testify-28948`.
- The union catches **all** false-safes — and destroys **73 % of correct safe
  decisions**. This is precisely the "everything → `INCONCLUSIVE`" failure the
  brief disqualifies.

There is **no operating point with acceptable overblocking**: 2–3 of 5 false-safes
cost 30–44 % of correct safe answers; 5 of 5 costs 73 %.

## Step 3 — why it cannot be sharpened with this data

**86 of 87 parsed answers carry only `{category, reasoning}`.** There are no
structured claims, no `evidence_refs`, no scope or subject binding. Consequences:

- The Gate cannot tell *which* observation supports *which* sub-claim, so it can
  only threshold over the whole observation set — and in a monorepo reachability
  is `PARTIAL` almost always, so ~half of the correct-safe answers share the
  signature that flags the false-safes.
- The check the spec actually wants — **claim-vs-scope** ("0 callers within the
  loaded scope" being used to assert global unreachability) — needs the claim and
  its evidence scope to be machine-readable. They are not present.

This is the case spec §6.2 anticipated: an offline replay over Task 4/5 artifacts
**can yield only `INSUFFICIENT_INPUT`** for a real verification, because the
evidence contract was deliberately not required of P1/T1 (requiring it only of T1
would have privileged that arm).

## Conclusion

**Negative, and now for a specific, actionable reason.** A cheap general gate
does exist for the *error-as-absence* defect (`RG`: 2/5 caught, but 19/63 correct
safes lost) and for the *scoped-zero* defect (`R6`: 1/5 caught, 26/63 lost) — but
neither is viable standalone, and the union is disqualified.

The experiment therefore yields a sharper negative than "no rule helps":

1. **Two distinct defect classes are confirmed** in the saved answers — error
   turned into absence, and scoped observation generalized to a global claim.
2. **Neither is cleanly separable from correct behaviour** using only
   `completeness`/`tool_status`/`limitations`, because correct answers rely on the
   same incomplete-by-nature observations.
3. **A productive Gate needs a richer evidence contract** (structured claim with
   claimed subject/scope + bound evidence refs) — which the current prompts do not
   emit. Testing that requires a **new matched run** with an identical structured
   export in both arms, then an **unseen holdout**.

## Decision impact

Consistent with `decision.md`: **no Gate is built.** The §5.3 admission test fails
in the strongest form — not "no rule found", but "no rule is *checkable* on the
current evidence contract." `internal/verificationgate` stays uncreated; the
`gate-replay`/`score-gate` stubs stay stubs. The next Gate hypothesis is a
claim-vs-scope contract on a new matched run, evaluated on a frozen unseen
corpus — not more thresholding on this one.

## Reproduce

Throwaway offline scripts: `/tmp/neg_claims.py`, `/tmp/obs3.py`,
`/tmp/gate_err.py`, `/tmp/gate_union.py` (and the earlier
`/tmp/gate_matrix*.py`), run with
`~/work/personal/vexbench-durable/agent-ctl/.venv/bin/python`.

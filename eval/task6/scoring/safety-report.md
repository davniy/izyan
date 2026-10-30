# Task 6 safety report — task6

Generated 2026-10-10T01:31:09Z — offline join of four projections (no model calls).

| Projection | Rows | FS | FS rate | SCR | EXP recall | abstain | FAILED | valid-claim | checkable-claim | tokens | cost |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| p2 | 90 | 1 / 21 | 4.8% | 56.5% | 76.2% | 0 | 34 | 25.6% | n/a | 0 | $0.000 |
| t2 | 30 | 0 / 7 | 0.0% | 65.2% | 114.3% | 0 | 7 | 23.3% | n/a | 0 | $0.000 |
| v_p2 | 90 | 0 / 21 | 0.0% | 0.0% | 76.2% | 40 | 34 | 25.6% | 95.6% | 0 | $0.000 |
| v_t2 | 30 | 0 / 7 | 0.0% | 0.0% | 114.3% | 15 | 7 | 23.3% | 68.9% | 0 | $0.000 |

Denominators: 7 exploitable / 23 safe per repeat (30 total); FS counts only GT-exploitable rows scored safe; abstain and FAILED are never false-safe. V- projections replay the same saved answers through the offline validator — a non-ACCEPTED decision on a safe verdict projects to abstain.

## Unique-case view (repeats of one case count once)

| Projection | cases | FS cases | CS cases | any-abstain |
|---|---:|---:|---:|---:|
| p2 | 30 | 1 | 18 | 0 |
| t2 | 30 | 0 | 15 | 0 |
| v_p2 | 30 | 0 | 0 | 19 |
| v_t2 | 30 | 0 | 0 | 15 |

## Transition classes (paired observed attempts only)

- p2->t2 false_alarm_appeared: 2
- p2->t2 false_alarm_cleared: 1
- p2->t2 positive_gained_from_failed: 3
- p2->t2 safe_gained_from_failed: 5
- p2->t2 safe_lost_to_failed: 5
- p2->t2 stable_failed: 1
- p2->t2 stable_positive: 3
- p2->t2 stable_safe: 10
- p2->v_p2 safe_lost_to_abstain: 39
- p2->v_p2 safe_wobble: 1
- p2->v_p2 stable_failed: 34
- p2->v_p2 stable_positive: 16
- t2->v_t2 safe_lost_to_abstain: 15
- t2->v_t2 stable_failed: 7
- t2->v_t2 stable_positive: 8

## Limitations

- attempt-policy deviation: P2 30x3, T2 30x1 (matched n=1 comparison); T2 was planned 30x3 in this frozen manifest. Justified by completion criteria (contract sufficiency / MCP value / validator viability) needing aggregate rates, not rare-event precision.

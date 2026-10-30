# Task 5 safety report — task5

Generated 2026-10-09T12:47:20Z — offline scoring join, no model calls.

| Arm | Rows | Repeats | Acc (official) | FS strict | FS audit | SCR strict | Recall strict | INCONCLUSIVE | FAILED |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| p1 | 30 | 3 | 80.0% | 5 | 5 | 84.1% | 61.9% | 1 | 5 |
| t1 | 30 | 3 | 84.4% | 5 | 5 | 91.3% | 61.9% | 0 | 3 |

Denominators: 7 exploitable / 23 safe per repeat (30 total); FS counts only GT-exploitable rows scored safe; abstain and FAILED are never false-safe. Strict = official-parse rows; audit = parser-audit projection (separate, never merged).

## Transition classes (paired observed attempts only)

- p1->t1 false_alarm_appeared: 5
- p1->t1 false_alarm_cleared: 7
- p1->t1 false_safe_appeared: 4
- p1->t1 false_safe_cleared: 4
- p1->t1 positive_gained_from_failed: 2
- p1->t1 positive_lost_to_failed: 2
- p1->t1 safe_gained_from_abstain: 1
- p1->t1 safe_gained_from_failed: 2
- p1->t1 stable_failed: 1
- p1->t1 stable_positive: 8
- p1->t1 stable_safe: 54

## Limitations


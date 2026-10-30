# Remaining Architecture Migration: Execution Plan Series

Use **five separate plans**, in the order below. These changes cross distinct authority, runtime, evaluation and proof boundaries; combining them would make review and rollback unnecessarily difficult.

| Plan | Prerequisites | Independence |
|---|---|---|
| Phase 2 — Investigation inputs and tools | Completed Phase 1 | Functionally independent of Phase 3; separate worktrees are possible, but merge Phase 2 first |
| Phase 3 — Authority-boundary repair | Completed Phase 1 | Does not depend on Phase 2’s new inputs |
| Phase 4 — Runtime and admission consolidation | Phases 2 and 3 plus recovery Tasks 8–14 preservation/integration gate | Task 1 kept; original Task 2 deletion superseded; Task 3 admission reuse remains downstream |
| Phase 5 — Product B measurement tooling | Phase 4 | Can be developed independently of Phase 6 after Phase 4 |
| Phase 6 — Evidence-class proof extensions | Phases 2–4 | Recommended after Phase 5 tooling lands; **does not require executing that lane** |

**Current execution correction (2026-10-29):** Phase 1–3 and Phase 4 Task 1
repairs are retained. The original Phase 4 Task 2 deletion lost capabilities;
its report remains history and is not non-regressive consolidation evidence.
[`2026-10-28-04-phase1-human-result-plan.md`](2026-10-28-04-phase1-human-result-plan.md)
Tasks 8–14 supersede that deletion and restore/migrate capabilities before cutover.

- One live investigator: `izyan triage`, `assessment.v3` → `decision-package.v4`.
- Complete finite prepared decisions: 0–2 questions, explicit unknown, ≤7 mandatory
  premises; append-only assertions and v2 reviews bind selected branch/projection.
- Canonical research `/5` publication and exact-record adapters retained; pure
  validators and historical `/3`/`/4`/slice2/flow survive without authority upgrade.
- Tracked offline controllers/indexes/CI are preserved; no R6 live launcher.
- Phase 4 Task 3 reuses immutable admission only after preservation and owner gates;
  fresh replay/publication admission is not cacheable away. Phase 5 modifies the
  existing controller and consumes current answer/review contracts. Phase 6 proof
  work remains: human environment answers are never evidence-producer substitutes.
- Broad integration, unchanged Product A regression/census and exact paired
  authority measurement remain owner evidence, not inferred from focused tests.
- `internal/evdomain` is absent. Use the existing `internal/domain` contracts and the permitted data aliases in `internal/productb/domain/dto.go`.

**Execution convention for every plan:** Commands below are implementation instructions, not recorded results. This planning assignment performs no writes, builds, tests, model calls or corpus runs. Implementers use focused tests during tasks; the integration owner performs the final repository checks after all relevant changes land.

**Series-wide invariants:**

1. `false-safe = 0`.
2. Product B judgments, support and human Accept/Reject never authorize Product A conclusions or machine reductions.
3. No production dispatch by CVE, benchmark task, GT category or fixture identity.
4. A citation establishes its referenced material, not arbitrary semantic entailment.
5. Replay uses captured inputs and observations only: no model, network or live-tree reconstruction.
6. Unsupported proof capability limits machine authority, not the delivery of a human recommendation.
7. Historical artifacts retain their original meaning. Retired schemas are never silently upgraded into current authority.
8. Update `docs/dev/gap-analysis.md` when functionality closes a gap, and `eval/README.md` when observable analyzer behavior changes. Do not rewrite historical measurements or frozen experiment manifests.

---

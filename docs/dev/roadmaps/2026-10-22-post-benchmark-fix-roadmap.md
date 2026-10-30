# Post-Benchmark Fix Roadmap: Product A applicability, scope and merge gate

**Источник:** delegated `architect` artifact `agent://PostBenchArchReview` (2026-10-22), документ 1; сохранён.
**Status:** NO-GO до P0 fixes  
**Branch:** `consolidation/shadow-base`  
**Benchmarked branch:** `c73151f`  
**Master comparator:** `e351e0f`  
**Architecture base:** Shadow Product A + V2 Product B  
**Evidence:** `va-review1/bench/STATUS.md`, `REPORT.md`, `LLM-ANALYSIS.md`, S-05 baseline, target architecture §14

## Goal

Исправить регрессии третьей итерации, сохранить safety improvements и получить branch, который можно merge без снижения detection/closure относительно master.

## Decision

Полный rollback не нужен.

Сохранить:

- исправление master nil-pointer panic;
- fail-closed semantics;
- снижение false-safe;
- Shadow authoritative identity/evidence/verdict core;
- Product B triage/research/evaluation как отдельный non-authoritative продукт;
- sidecar/replay/tamper protections;
- открытый scope для `UNKNOWN`, `PARTIAL`, skipped packages, unresolved dispatch и timeout.

Исправить до merge:

- multi-entry advisory/version resolver;
- per-entry applicability ownership;
- release-evidence input contract;
- tail-latency and timeout regression;
- benchmark lane separation.

Не делать:

- не ослаблять `VersionAffected=UNKNOWN → INCONCLUSIVE`;
- не использовать `go.mod` или analysis toolchain как release truth;
- не превращать LLM proposal в authoritative verdict;
- не откатывать case-10 fail-closed semantics только ради одной safe closure;
- не создавать второй `AffectedResult`, `Claim`, `NegativeVerification` или verdict engine;
- не засчитывать `izyan triage`/`research-b1` как улучшение `izyan analyze` без отдельного измерения.

## Evidence summary

### Proven

- Branch deterministic result: `-7.5 case-equivalents` versus master.
- Corporate confirmed: master `6/35 EXPLOITABLE`, branch `0/35`.
- Corporate rejected safe closure: master `16/18`, branch `12/18`.
- Branch corporate false-safe: `0`; master: `2`.
- Branch has 3 corporate confirmed timeouts; master has none.
- VEX TP: `1/7` for both.
- VEX false-safe: branch `1/7`, master `2/7`.
- Branch removes three master panics.
- Branch reports exact module versions in evidence but still emits `VersionAffected=UNKNOWN` for lost TP cases.
- Product B code is present and tested, but its value was not measured by the deterministic `analyze` comparison.
- LLM in `analyze --cve-analysis verified` proposes; deterministic evaluator still decides.

### Inference supported by source and reports

The primary TP regression is caused by an empty/malformed advisory entry interacting with:

- `isStdlibModule("")`;
- strict release-toolchain gating;
- merged package subjects;
- `pathOwner` assignment;
- global `VersionAffected=UNKNOWN` evaluator gate.

The performance regression is caused by the expanded V2 scope/closure work entering the critical Product A path without a completed parity and performance gate.

## Target topology

```text
Product A — Shadow authority
  identity
  affectedness
  implementation axis
  deterministic evidence
  negative verification
  terminal verdict
  authoritative VEX

Product B — V2-derived non-authoritative lane
  triage
  research
  proposals
  DecisionPackage
  policy
  heldout/evaluation
  replay

LLM
  proposal/research only
```

## Phase 0 — Freeze contracts and evidence

**Priority:** P0  
**Owner:** repository maintainer + benchmark owner

### Deliverables

- This roadmap.
- Implementation plan.
- Pinned master/branch commits and binary hashes.
- Existing benchmark artifacts retained unchanged.
- S-05 baseline retained unchanged.
- A short input contract for:
  - advisory identity;
  - source snapshot;
  - module graph;
  - release toolchain;
  - target/build context;
  - timeout/memory/workers.

### Exit gate

No implementation starts until the following are recorded:

- master `e351e0f`;
- branch `c73151f`;
- corpus/report/metrics paths;
- S-05 baseline path;
- known expected branch changes;
- no benchmark artifact is overwritten.

## Phase 1 — P0 applicability fix

**Priority:** P0  
**Owner:** `internal/affected` + `internal/vulnerability`

### Objectives

- Preserve applicability independently for every advisory entry.
- Never classify an empty module name as stdlib.
- Do not let an unknown unlinked entry poison a linked entry with an exact version.
- Preserve safety when a malformed entry has a unique linked subject.

### Required changes

- Normalize OSV affected entries.
- Deduplicate/merge duplicate subjects by valid module owner.
- Preserve malformed entries as explicit unresolved data when they have unique subjects.
- Make stdlib classification exact.
- Keep package ownership per entry.
- Preserve `UNKNOWN` only for the affected linked entry.

### Exit gate

Focused tests prove:

- named third-party module version resolves without release toolchain evidence;
- empty duplicate entry does not poison named module;
- empty unique linked subject remains `UNKNOWN`;
- empty unique unlinked subject does not poison another linked module;
- linked stdlib entry without authoritative release evidence remains `UNKNOWN`;
- two valid linked modules retain independent ownership.

## Phase 2 — Release-evidence contract

**Priority:** P0  
**Owner:** CLI/evaluation owner

### Objectives

- Make release toolchain evidence explicit for stdlib applicability.
- Keep the source/vendor module graph, authoritative release module graph and release toolchain axes distinct.
- Ensure benchmark manifests do not silently omit required release facts.

### Rules

- `--binary` or authoritative release metadata may establish release toolchain.
- `--release-go-version` may establish release toolchain.
- `go.mod` is only a language minimum.
- Local analysis `go version` is not release evidence.
- Missing release evidence produces `UNKNOWN` only for the affected stdlib entry.
- Third-party presence/version prefers the authoritative release module graph when present; source/vendor is the fallback.
- Missing release **Go toolchain** evidence alone does not block third-party resolution.
- A failed required release-artifact channel remains fail-closed: source/vendor must not substitute for the unavailable release version.

### Exit gate

Every stdlib benchmark case declares one of:

- authoritative release artifact;
- explicit release Go version;
- intentional unresolved release evidence.

The report names the source and trust class.

## Phase 3 — P0 performance and timeout fix

**Priority:** P0  
**Owner:** `internal/goanalysis` + Product A workflow owner

### Objectives

- Remove branch-specific tail latency.
- Reuse closure/index work within one analysis.
- Preserve fail-closed semantics when a budget is exhausted.
- Do not solve the problem only by increasing timeout.

### Required changes

- Reuse `BuildShippingScope` and importer closure within one verification session.
- Avoid repeated full module/symbol closure for identical subjects.
- Ensure all expensive operations observe the caller context.
- Keep incomplete/timeout results non-admitting.
- Record stage and tool budget exhaustion explicitly.
- If the heavy V2 scope path cannot satisfy Product A budget, gate it behind an explicit non-default capability rather than weakening verdict semantics.

### Exit gate

On the matched benchmark:

- no master-completing case becomes a branch timeout;
- no new panic;
- no timeout becomes a safe-negative;
- Product A completion is not below master;
- state timings identify remaining heavy stages.

## Phase 4 — Product B separation and measurement

**Priority:** P1  
**Owner:** Product B owner

### Objectives

- Stop treating `analyze --cve-analysis verified` as the V2 research benchmark.
- Measure Product B independently.
- Keep semantic dismissal default-off.

### Required measurements

Separate arms:

1. deterministic `analyze`;
2. `analyze --cve-analysis verified`;
3. `izyan triage`;
4. `izyan research-b1`;
5. plain-agent research, only if compared with V2 research claims.

Measure:

- completion;
- TP/false-safe where labels exist;
- `INCONCLUSIVE`/`UNCHANGED`;
- verified proof count;
- LLM calls;
- stability;
- replay;
- policy output;
- manual review workload.

Run rejected LLM lane before claiming triage closure benefit.

## Phase 5 — S-01 identity and S-14 product gaps

**Priority:** P1/P2

### S-01

Keep as a prerequisite for all adapters.

Must cover:

- advisory/ticket identity;
- source/artifact/build identity;
- target/toolchain;
- release evidence;
- migration/refusal;
- foreign/cross-run artifacts.

### S-14

Keep case-specific. Do not turn it into “reduce INCONCLUSIVE”.

| Cases | Required result |
|---|---|
| 03 | verified declared-symbol closure or durable `INCONCLUSIVE` |
| 07/08 | real IBM MQ SDK or durable `INCONCLUSIVE` |
| 01/02/17/18 | positive attacker-input/control capability or durable `INCONCLUSIVE` |
| 15/16 | retained proposal plus independently verified falsifier or durable `INCONCLUSIVE` |

## Merge gate

### Product A

GO only if:

- `false-safe=0` on the pinned safety corpus;
- corporate confirmed TP is at least master: `>=6/35`;
- corporate rejected safe closure is at least master: `>=16/18`, or every difference is explicitly approved as durable `INCONCLUSIVE`;
- VEX TP is not below `1/7`;
- VEX safe-clear is not below `10/23`;
- completion is not below master;
- no master-completing case becomes branch timeout;
- no new panic;
- unknown applicability remains non-admitting and entry-local.

### Product B

GO only if:

- no second authority contract exists;
- proposal authority fields are rejected;
- foreign/tampered/cross-run artifacts fail closed;
- replay works offline;
- semantic dismissal remains default-off;
- positive holdout and recall are measured before any admission.

### Final status

Until all gates pass:

```text
CONDITIONAL / NO-GO
```

# Task 6 — phase 6.3 smoke notes

Three smoke runs on the pinned env (Docker images `vex-bench-go-opencode-gw:latest`
for P2 / `vex-bench-go-opencode-c1:latest` for T2, model `qwen3.6-35b`, timeout 900).
Smoke = controller-only 3-class pick (one case per GT class: exploitable,
non_reachable, configuration) × 2 arms, run in the `task6-smoke` namespace
(outside scored roots). Raw smoke dirs are gitignored.

## Run 1 — pre-hardening
Envelope non-compliance dominated: model emitted prose/markdown tables instead
of a JSON object (t2/exploitable), one malformed JSON object (p2/non_reachable),
one 900 s timeout (p2/configuration), and a `file:` ref carrying free text
(`file:go.sum:github.com/docker/docker v26.0.1+incompatible entries`). The
official parser and the v2 extractor both correctly rejected these — i.e. the
*ceiling* here is model formatting, not pipeline.

## Action — output-envelope hardening (shared P2 text)
Added an explicit single-JSON-object rule (first char `{`, last `}`, no tables/
headings/prose), a `file:` BAD/GOOD example, and an end-of-block reminder. The
safety semantics are untouched; T2 remains P2 bytes + `\n\n` + the task6-local
`<EVIDENCE_TOOLS>` block.

## Run 2 — post-hardening
Parse failures fell (1/6), no timeout. Remaining `schema invalid` causes were
**model field omissions**, not pipeline bugs: a `negative_claim` missing the
required `scope`, and an `assessment` missing the required `reasoning`. The
official `category` is still parsed and scored (`overall=valid`), so a schema
defect does not lose the safety signal — schema-valid share is itself a metric.

## Run 3 — post review fixes (validator strictness F1–F5; v2-aligned T2 block F6)
Pipeline validated end-to-end:
- T2 attempts drive real MCP tools (5–8 `tool_calls`); P2 attempts have 0 and no
  audit sink — arm isolation clean.
- A valid T2 attempt cites `file:` refs that bind to the snapshot, with per-claim
  `subject`/`scope` populated.
- Residual model non-compliance: 1 parse-fail; 1 `safe` + non-empty `unresolved[]`
  correctly flagged as a contract defect.
- Two `transport_failure` (p2) are a **host infrastructure race**, not a code
  defect: `docker cp ... mkdir /host_mnt/.../: no such file or directory`
  (Docker Desktop bind-grace under rapid re-runs). Scored runs create attempt
  dirs before the container starts and are unaffected; `parallel=1`.

## Verdict
Smoke acceptance met: both arms run, structured schema produced, refs bind
(T2 audit / P2 src-file), negative claims carry subject/scope, no prompt
contamination, arm isolation clean. Cleared for the phase-6.4 frozen dev run.

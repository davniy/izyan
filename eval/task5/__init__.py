"""Task 5 experiment control plane (Prompt vs Evidence Tools vs Gate).

Controller-side glue over the Task 4 C1 machinery
(``eval.c1.{status,collect,runner,parser_audit,report}``):

- ``protocol.py``   — the two frozen prompt variants: ``vuln_safety_v1``
  (P1, plain arm) and ``vuln_safety_v1_tools`` (T1, MCP arm), generated
  byte-exactly per the plan (P1 = frozen official template + the literal
  ``<SAFETY_RULES>`` block; T1 = exact P1 bytes + two LF + the literal
  ``<EVIDENCE_TOOLS>`` block) plus hash/diff/prohibited-identifier
  assertions.
- ``manifest.py``   — frozen experiment manifest (identities, patches,
  prompts, dataset pins, attempt policy).
- ``collect.py``    — post-hoc attempt finalization over harness-run
  cohorts and controller-run smoke dirs (immutable attempt keys).
- ``report.py``     — joins per-arm C1 scorer outputs into the Task 5
  matrix / disagreements / safety report artifacts.
- ``freeze.py``     — phase 5.0: read-only index of the frozen Task 3/4
  evidence (baselines A/B/C, Qwen plain/tools roots, Codex partial
  cohorts, harness/izyan provenance, MCP error accounting).

The executable entrypoint is ``eval/vexbench_task5.py``. Nothing here
touches production ``AnalysisCase``/``Verdict``/``Claims``, the official
VEX-Bench parser/scorer, or frozen Task 4 prompts/manifests/artifacts.
"""

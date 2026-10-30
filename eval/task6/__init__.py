"""Task 6 experiment control plane (structured Evidence Contract).

Controller-side glue over the Task 4 C1 machinery
(``eval.c1.{status,collect,parser_audit,report}``) and the Task 5 thin
glue (``eval.task5.*``), same shape as ``eval/task5/``:

- ``freeze.py``       — phase 6.0: read-only re-verification of the
  Task-5 scorer (RG/R6/UNION blocked/correct-safe tables recomputed by
  attempt AND by unique case, the ``19 + 26 < 46`` union anomaly
  explained, Task-5 artifact hashes re-verified) — frozen as
  ``freeze/task5-reference.json``.
- ``protocol.py``     — the two frozen prompt variants:
  ``vuln_safety_v2`` (P2: official + <SAFETY_RULES> +
  <STRUCTURED_ASSESSMENT>) and ``vuln_safety_v2_tools`` (T2: exact P2
  bytes + two LF + the task6-local ``<EVIDENCE_TOOLS>`` contract block
  — the C1 binding-rules text with evidence-ref field names aligned
  to ``agent-assessment/2``), with hash/diff/prohibited-identifier
  assertions.
- ``assessment_v2.py`` — the ``agent-assessment/2`` schema: the strict
  structured assessment the prompt requires (mechanisms /
  negative_claims / unresolved / reasoning + evidence_refs grammar).
- ``validator.py``     — phase 6.2: the offline Evidence-Contract
  validator (spec §4): C1 ref-existence/snapshot-hash, C2
  error-as-absence, C3 subject/scope match, C4 falsifier + declared
  CVE-scope coverage → ACCEPTED / INSUFFICIENT_EVIDENCE /
  UNVERIFIABLE / INVALID_EVIDENCE / SCOPE_MISMATCH.
- ``manifest.py``     — frozen experiment manifest (identities,
  contract file hashes, arm bindings, dataset pin, attempt policy).
- ``collect.py``      — post-hoc attempt finalization over
  harness-run dirs: same status classification as C1 plus the
  ``agent-assessment/2`` extraction pipeline (a missing
  ``assessment`` object is schema-INVALID under the Task-6 contract,
  never "absent"); ``agent_assessment.json`` per attempt.
- ``replay.py``       — the V-P2 / V-T2 projections: offline
  validator replay over the saved, immutable P2/T2 answers (no model
  calls) — a non-ACCEPTED decision on a safe verdict projects to
  abstain, never safe, never rewritten.
- ``report.py``       — the four-projection scoring join:
  ``matrix.json`` / ``disagreements.jsonl`` / ``safety-report.md`` /
  ``validator-report.md``, attempt-based AND unique-case
  denominators.

The executable entrypoint is ``eval/vexbench_task6.py``. Nothing here
touches production ``AnalysisCase``/``Verdict``/``Claims``, the official
VEX-Bench parser/scorer, or frozen Task 4/5 artifacts (all read-only).
"""

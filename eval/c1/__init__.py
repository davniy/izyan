"""Task 4 C1 experiment control plane (Shadow Agent + Evidence Tools).

Controller-side only: assessment schema/validation (assessment.py), prompt
blocks for the shared B1'/C1 output protocol (protocol.py), per-attempt
status model and artifact assembly (status.py, collect.py), attempt
orchestration (runner.py), synthetic integration/isolation battery
(synthetic.py), manifest freezing (manifest.py), the parser-audit decoder
(parser_audit.py) and the offline scoring/audit reporter (report.py);
the executable entrypoint is ``eval/vexbench_c1.py``.
Nothing here touches production ``AnalysisCase``/``Verdict``/``Claims`` or
the official VEX-Bench parser/scorer.
"""

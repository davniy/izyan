"""Unit tests for eval/c1/collect.py — attempt finalization rules.

Run: /tmp/vexbench-agent-ctl/.venv/bin/python -m unittest eval.c1.collect_test -v
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from eval.c1 import assessment as A  # noqa: E402
from eval.c1 import collect as C  # noqa: E402
from eval.c1.assessment_test import META, VALID_PAYLOAD  # noqa: E402


def official_parser(text):
    """Stand-in for harness result_parser.parse_category (same contract)."""
    obj = C.extract_json_object(text)
    if not obj:
        return None, None
    cat = obj.get("category")
    return (cat.lower() if isinstance(cat, str) else None), obj.get("reasoning")


def make_ndjson(final_text):
    events = [
        {"type": "item.completed", "item": {"type": "agent_message", "text": "working..."}},
        {"type": "item.completed", "item": {"type": "agent_message", "text": final_text}},
        {"type": "turn.completed", "usage": {"input_tokens": 100}},
    ]
    return "\n".join(json.dumps(e) for e in events)


def valid_final_json(category="code_not_reachable", estimate="NO_EXPLOIT_PATH_FOUND"):
    p = json.loads(json.dumps(VALID_PAYLOAD))
    p["verdict_estimate"] = estimate
    if estimate == "EXPLOITABLE":
        p["counterexample_review"] = {"checked": ["x"], "still_unknown": []}
    return json.dumps(
        {"category": category, "reasoning": "grounded reasoning", "assessment": p}
    )


def meta():
    return A.AttemptMeta(**META)


class FinalizeSuccessTest(unittest.TestCase):
    def test_valid_attempt_writes_both_artifacts(self):
        with tempfile.TemporaryDirectory() as td:
            rd = Path(td)
            (rd / "result.jsonl").write_text(make_ndjson(valid_final_json()))
            status, asm = C.finalize_attempt(
                rd, meta=meta(), official_parser=official_parser
            )
            self.assertEqual(status.overall, "valid")
            self.assertEqual(status.official_parse, "accepted")
            self.assertEqual(status.assessment_schema, "valid")
            self.assertIsNotNone(asm)
            self.assertTrue((rd / "agent_assessment.json").exists())
            self.assertTrue((rd / "status.json").exists())

    def test_duplicate_attempt_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            rd = Path(td)
            (rd / "result.jsonl").write_text(make_ndjson(valid_final_json()))
            C.finalize_attempt(rd, meta=meta(), official_parser=official_parser)
            with self.assertRaises(A.DuplicateAttemptError):
                C.finalize_attempt(rd, meta=meta(), official_parser=official_parser)

    def test_officially_valid_but_bad_assessment_stays_valid(self):
        # Plan §3: malformed assessment is an artifact defect; the accepted
        # official category must not be erased from status.
        with tempfile.TemporaryDirectory() as td:
            rd = Path(td)
            bad = json.dumps(
                {"category": "code_not_reachable", "reasoning": "r",
                 "assessment": {"bogus": True}}
            )
            (rd / "result.jsonl").write_text(make_ndjson(bad))
            status, asm = C.finalize_attempt(
                rd, meta=meta(), official_parser=official_parser
            )
            self.assertEqual(status.overall, "valid")
            self.assertEqual(status.official_parse, "accepted")
            self.assertEqual(status.assessment_schema, "invalid")
            self.assertIsNone(asm)
            self.assertFalse((rd / "agent_assessment.json").exists())
            self.assertTrue((rd / "status.json").exists())

    def test_custom_result_file_and_extractor(self):
        # opencode-c1 writes result.json (session export); its adapter
        # supplies the terminal-text rule via agent.extract_text.
        with tempfile.TemporaryDirectory() as td:
            rd = Path(td)
            export = {
                "messages": [
                    {"info": {"role": "assistant"}, "parts": [{"type": "text", "text": "first"}]},
                    {"info": {"role": "assistant"}, "parts": [{"type": "text", "text": valid_final_json()}]},
                ]
            }
            (rd / "result.json").write_text(json.dumps(export))

            def extract_last_part(raw: str) -> str:
                for msg in reversed(json.loads(raw)["messages"]):
                    if msg.get("info", {}).get("role") != "assistant":
                        continue
                    for part in reversed(msg.get("parts", [])):
                        if part.get("type") == "text" and part.get("text"):
                            return part["text"]
                return ""

            status, asm = C.finalize_attempt(
                rd,
                meta=meta(),
                official_parser=official_parser,
                result_filename="result.json",
                final_text_extractor=extract_last_part,
            )
            self.assertEqual(status.overall, "valid")
            self.assertEqual(status.official_parse, "accepted")
            self.assertIsNotNone(asm)


class FinalizeFailureTest(unittest.TestCase):
    def test_timeout_from_error_txt(self):
        with tempfile.TemporaryDirectory() as td:
            rd = Path(td)
            (rd / "error.txt").write_text(
                "container timed out after 600s (tail: ...)"
            )
            status, asm = C.finalize_attempt(
                rd, meta=meta(), official_parser=official_parser
            )
            self.assertEqual(status.overall, "failed")
            self.assertEqual(status.execution, "timeout")
            self.assertEqual(status.failure_reason, "timeout")
            self.assertIsNone(asm)

    def test_nonzero_exit(self):
        with tempfile.TemporaryDirectory() as td:
            rd = Path(td)
            (rd / "error.txt").write_text("container exited 2: codex exploded")
            status, _ = C.finalize_attempt(
                rd, meta=meta(), official_parser=official_parser
            )
            self.assertEqual(status.execution, "nonzero_exit")
            self.assertEqual(status.overall, "failed")

    def test_no_result_no_error(self):
        with tempfile.TemporaryDirectory() as td:
            status, _ = C.finalize_attempt(
                Path(td), meta=meta(), official_parser=official_parser
            )
            self.assertEqual(status.execution, "no_output")
            self.assertEqual(status.failure_reason, "no_result")
            self.assertEqual(status.overall, "failed")

    def test_prose_only_terminal_answer(self):
        with tempfile.TemporaryDirectory() as td:
            rd = Path(td)
            (rd / "result.jsonl").write_text(
                make_ndjson("The classification is `requires_configuration`.")
            )
            status, asm = C.finalize_attempt(
                rd, meta=meta(), official_parser=official_parser
            )
            self.assertEqual(status.overall, "failed")
            self.assertEqual(status.official_parse, "parse_fail")
            self.assertEqual(status.parser_audit, "no_object")
            self.assertIsNone(asm)

    def test_official_miss_but_audit_recovers_full_json(self):
        # Parser-audit projection: full valid JSON that the official
        # extractor would lose is recorded, assessment still stamps the
        # model's own category, official_parse stays parse_fail.
        with tempfile.TemporaryDirectory() as td:
            rd = Path(td)
            obj = json.loads(valid_final_json(category="vulnerable",
                                              estimate="EXPLOITABLE"))
            obj["reasoning"] = "code: if x { f() } else { g() }"
            text = json.dumps(obj)
            # Simulate official parser that misses it (returns None):
            blind = lambda t: (None, None)  # noqa: E731
            (rd / "result.jsonl").write_text(make_ndjson(text))
            status, asm = C.finalize_attempt(
                rd, meta=meta(), official_parser=blind
            )
            self.assertEqual(status.official_parse, "parse_fail")
            self.assertEqual(status.parser_audit, "recovered")
            self.assertEqual(status.overall, "failed")  # official-strict
            self.assertIsNotNone(asm)  # model said something valid
            self.assertEqual(asm.category, "vulnerable")

    def test_audit_file_drives_tool_executions(self):
        with tempfile.TemporaryDirectory() as td:
            rd = Path(td)
            audit_dir = rd / "artifacts" / "izyan-audit"
            audit_dir.mkdir(parents=True)
            (audit_dir / "tool_calls.jsonl").write_text(
                json.dumps(
                    {
                        "tool": "find_callers",
                        "args": {"symbol": "f"},
                        "duration_ms": 5,
                        "observation": {"id": "o1", "tool_status": "OK",
                                        "completeness": "PARTIAL",
                                        "evidence_refs": []},
                    }
                )
                + "\n"
            )
            (rd / "result.jsonl").write_text(make_ndjson(valid_final_json()))
            status, asm = C.finalize_attempt(
                rd, meta=meta(), official_parser=official_parser
            )
            self.assertIsNotNone(asm)
            self.assertEqual(len(asm.tool_executions), 1)
            self.assertEqual(asm.tool_executions[0].tool, "find_callers")
            self.assertEqual(asm.usage.tool_calls, 1)


if __name__ == "__main__":
    unittest.main()

"""Unit tests for eval/c1/status.py — separated status dimensions.

Run: /tmp/vexbench-agent-ctl/.venv/bin/python -m unittest eval.c1.status_test -v
"""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from eval.c1 import status as S  # noqa: E402
from eval.c1.assessment import DuplicateAttemptError  # noqa: E402

IDS = dict(task_id="t-1", attempt_id="run_001", experiment_id="exp")


class ClassifyTest(unittest.TestCase):
    def test_valid_requires_ok_and_accepted(self):
        st = S.AttemptStatus.classify(
            **IDS, execution="ok", official_parse="accepted",
            assessment_schema="valid",
        )
        self.assertEqual(st.overall, "valid")
        self.assertIsNone(st.failure_reason)

    def test_timeout_is_failed_with_reason(self):
        st = S.AttemptStatus.classify(
            **IDS, execution="timeout", official_parse="no_result",
            assessment_schema="absent",
        )
        self.assertEqual(st.overall, "failed")
        self.assertEqual(st.failure_reason, "timeout")

    def test_parse_fail_is_not_uncertain(self):
        st = S.AttemptStatus.classify(
            **IDS, execution="invalid_terminal_answer",
            official_parse="parse_fail", assessment_schema="absent",
        )
        self.assertEqual(st.overall, "failed")
        self.assertEqual(st.failure_reason, "invalid_terminal_answer")

    def test_accepted_category_but_bad_assessment_is_valid_with_defect(self):
        # Plan §3: malformed assessment must NOT erase the official category.
        st = S.AttemptStatus.classify(
            **IDS, execution="ok", official_parse="accepted",
            assessment_schema="invalid", detail="assessment schema invalid: x",
        )
        self.assertEqual(st.overall, "valid")

    def test_uncertain_maps_to_inconclusive_not_failed(self):
        st = S.AttemptStatus.classify(
            **IDS, execution="ok", official_parse="accepted",
            assessment_schema="valid", category="uncertain",
        )
        self.assertEqual(st.overall, "inconclusive")
        self.assertIsNone(st.failure_reason)

    def test_non_uncertain_category_is_valid(self):
        st = S.AttemptStatus.classify(
            **IDS, execution="ok", official_parse="accepted",
            assessment_schema="valid", category="vulnerable",
        )
        self.assertEqual(st.overall, "valid")

    def test_unknown_reason_rejected(self):
        with self.assertRaises(ValueError):
            S.AttemptStatus.classify(
                **IDS, execution="no_output", official_parse="no_result",
                assessment_schema="absent", failure_reason="it was sad",
            )

    def test_provider_refusal_distinct_from_parse(self):
        st = S.AttemptStatus.classify(
            **IDS, execution="provider_refusal", official_parse="parse_fail",
            assessment_schema="absent",
        )
        self.assertEqual(st.overall, "failed")
        self.assertEqual(st.failure_reason, "provider_refusal")


class RuntimeErrorClassificationTest(unittest.TestCase):
    def test_timeout(self):
        ex, reason = S.classify_runtime_error(
            "container timed out after 600s (tail ...)"
        )
        self.assertEqual((ex, reason), ("timeout", "timeout"))

    def test_nonzero_exit(self):
        ex, reason = S.classify_runtime_error("container exited 1: boom")
        self.assertEqual((ex, reason), ("nonzero_exit", "container_nonzero_exit"))

    def test_docker_create(self):
        ex, reason = S.classify_runtime_error("docker create failed: no image")
        self.assertEqual((ex, reason), ("transport_failure", "docker_create_failed"))

    def test_docker_cp(self):
        ex, reason = S.classify_runtime_error("docker cp failed: x")
        self.assertEqual((ex, reason), ("transport_failure", "docker_cp_failed"))

    def test_refusal_inside_nonzero(self):
        ex, reason = S.classify_runtime_error(
            "container exited 1: request was refused by content_filter"
        )
        self.assertEqual((ex, reason), ("provider_refusal", "provider_refusal"))

    def test_unknown_falls_back_to_transport(self):
        ex, reason = S.classify_runtime_error("something odd happened")
        self.assertEqual((ex, reason), ("transport_failure", "docker_start_failed"))

    def test_refusal_text_detection(self):
        self.assertTrue(S.detect_provider_refusal("I'm sorry, I can't do that"))
        self.assertFalse(S.detect_provider_refusal('{"category":"vulnerable"}'))
        # Observed B2-ISO shape: Gemini filter truncation lands mid-reasoning,
        # not at refusal-page start — the hint must still fire.
        self.assertTrue(S.detect_provider_refusal(
            '{"category":"vulnerable","reasoning":"...GO-This request was '
            'blocked by Gemini\'s filters.'))


class StatusWriteTest(unittest.TestCase):
    def test_write_then_duplicate_rejected(self):
        st = S.AttemptStatus.classify(
            **IDS, execution="ok", official_parse="accepted",
            assessment_schema="valid",
        )
        with tempfile.TemporaryDirectory() as td:
            S.write_status_artifact(Path(td), st)
            with self.assertRaises(DuplicateAttemptError):
                S.write_status_artifact(Path(td), st)

    def test_roundtrip_fields(self):
        st = S.AttemptStatus.classify(
            **IDS, execution="ok", official_parse="accepted",
            assessment_schema="valid", parser_audit="matched",
        )
        with tempfile.TemporaryDirectory() as td:
            p = S.write_status_artifact(Path(td), st)
            import json

            data = json.loads(p.read_text())
            self.assertEqual(data["execution"], "ok")
            self.assertEqual(data["official_parse"], "accepted")
            self.assertEqual(data["assessment_schema"], "valid")
            self.assertEqual(data["parser_audit"], "matched")
            self.assertEqual(data["overall"], "valid")


if __name__ == "__main__":
    unittest.main()

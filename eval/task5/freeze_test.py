"""Unit tests for eval/task5/freeze.py — inventory shapes (synthetic
roots only; the real freeze-history runs against /tmp roots).

Run: /tmp/vexbench-agent-ctl/.venv/bin/python -m unittest eval.task5.freeze_test -v
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from eval.task5 import freeze as F  # noqa: E402


class AttemptInventoryTest(unittest.TestCase):
    def test_counts_and_missing(self):
        with tempfile.TemporaryDirectory() as t:
            ml = Path(t) / "level"
            for tid, kind in (("a", "result"), ("b", "error"),
                              ("c", "empty")):
                rd = ml / tid / "run_001"
                rd.mkdir(parents=True)
                if kind == "result":
                    (rd / "result.json").write_text("{}")
                    (rd / "status.json").write_text("{}")
                elif kind == "error":
                    (rd / "error.txt").write_text("x")
            inv = F._attempt_inventory(ml, ["a", "b", "c", "d"])
            self.assertEqual(inv["attempts"], 3)
            self.assertEqual(inv["with_result"], 1)
            self.assertEqual(inv["with_error"], 1)
            self.assertEqual(inv["finalized"], 1)
            self.assertEqual(inv["missing_task_ids"], ["d"])
            self.assertEqual(inv["unexpected_task_ids"], [])

    def test_missing_root_marks_all_missing(self):
        inv = F._attempt_inventory(Path("/nonexistent-xyz"),
                                   ["a", "b"])
        self.assertFalse(inv["exists"])
        self.assertEqual(inv["missing_task_ids"], ["a", "b"])


class CohortSpecTest(unittest.TestCase):
    def test_p0_cohort_points_at_frozen_q36(self):
        p0 = next(c for c in F.COHORTS if c["id"] == "q36_plain")
        self.assertIn("q36", p0["model_level"])
        self.assertFalse(p0["mcp"])
        self.assertEqual(p0["admission"], "matched_evidence")

    def test_partial_and_contaminated_marked(self):
        adm = {c["id"]: c["admission"] for c in F.COHORTS}
        self.assertEqual(adm["codex_c1_partial"], "partial_excluded")
        self.assertEqual(adm["codex_b1p_partial"], "partial_excluded")
        self.assertEqual(adm["codex_c1_timeout_bug"],
                         "excluded_harness_defect")
        self.assertEqual(adm["codex_c1_capacity"],
                         "excluded_provider_capacity")
        self.assertEqual(adm["B2_gemini_host"], "excluded_contaminated")
        # every cohort carries an explicit admission class
        for c in F.COHORTS:
            self.assertIn("admission", c)

    def test_reported_mcp_totals_match_task4_doc(self):
        # the frozen report's claims — pinned verbatim
        self.assertEqual(F.REPORTED_MCP["total_calls"], 513)
        self.assertEqual(F.REPORTED_MCP["error"], 100)
        self.assertEqual(F.REPORTED_MCP["unsupported"], 2)
        self.assertEqual(F.REPORTED_MCP["context_canceled"], 65)


if __name__ == "__main__":
    unittest.main()

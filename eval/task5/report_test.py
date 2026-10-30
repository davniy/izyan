"""Unit tests for eval/task5/report.py — matrix/disagreement join shape.

Run: /tmp/vexbench-agent-ctl/.venv/bin/python -m unittest eval.task5.report_test -v
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from eval.task5 import report as R  # noqa: E402

T1 = "o-r-aaa1111-CVE-2020-00001"   # GT exploitable
T2 = "o-r-bbb2222-CVE-2020-00002"   # GT safe


def _row(task_id, run_id, category, *, status="ok"):
    return {
        "task_id": task_id, "run_id": run_id,
        "cve_id": "CVE-2020-0000" + task_id[-1],
        "ground_truth": "exploitable" if task_id == T1
        else "not_exploitable",
        "ground_truth_category": "vulnerable" if task_id == T1
        else "code_not_reachable",
        "predicted": ("exploitable" if category == "vulnerable"
                      else "not_exploitable" if category else None),
        "predicted_category": category,
        "reasoning": "because",
        "status": status,
        "completed": status == "ok", "steps": 4,
        "input_tokens": 10, "cached_input_tokens": 0,
        "output_tokens": 5, "reasoning_tokens": 1,
        "total_tokens": 15, "cost_usd": 0.001,
    }


def _scored_dir(root: Path, rows: list[dict], audit_rows=None) -> Path:
    root.mkdir(parents=True)
    (root / "parsed.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in rows))
    (root / "parsed.parser_audit.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in (audit_rows or rows)))
    per_repeat = {"run_001": {
        "rows": len(rows), "gt_exploitable": 1, "gt_non_exploitable": 1,
        "outcomes": {"positive": 0, "safe": 0, "abstain": 0, "failed": 0},
        "false_safe_count": 0, "false_safe_ids": [],
        "safe_clear_rate": 0.0, "exploitable_recall": 0.0,
        "inconclusive_rate": 0.0, "completion_rate": 1.0,
    }}
    for r in rows:
        o = ("positive" if r["predicted_category"] == "vulnerable"
             else "safe" if r["predicted_category"] and r["status"] == "ok"
             else "failed")
        per_repeat["run_001"]["outcomes"][o] += 1
        if o == "safe" and r["ground_truth"] == "exploitable":
            per_repeat["run_001"]["false_safe_count"] += 1
            per_repeat["run_001"]["false_safe_ids"].append(r["task_id"])
    safety = {
        "inputs": {"n_tasks": len(rows)},
        "n_repeats": 1,
        "aggregate": {
            "n_repeats": 1,
            "false_safe": {
                "total_count":
                    per_repeat["run_001"]["false_safe_count"],
                "unique_case_ids":
                    per_repeat["run_001"]["false_safe_ids"],
                "mean": per_repeat["run_001"]["false_safe_count"],
            },
            "safe_clear_rate": {"mean": 0.5},
            "exploitable_recall": {"mean": 0.5},
        },
        "per_repeat": per_repeat,
        "pooled": {"outcomes": per_repeat["run_001"]["outcomes"]},
        "failure_classes": {"pooled": {}},
        "assessment_schema": {"pooled": {"absent": len(rows)}},
        "telemetry_coverage": {"mcp_audit": {"state": "partial"}},
    }
    (root / "safety_metrics.json").write_text(json.dumps(safety))
    (root / "parser_audit_metrics.json").write_text(json.dumps({
        "metrics": {"safety_projection": {
            "aggregate": safety["aggregate"],
            "pooled": safety["pooled"]}},
    }))
    (root / "official_metrics.json").write_text(json.dumps({
        "binary": {"accuracy": {"mean": 0.5, "std": 0.0},
                   "f1": {"mean": 0.4, "std": 0.0}},
        "n_runs": 1,
    }))
    return root


def _manifest(tmp: Path) -> dict:
    return {
        "experiment_id": "task5-test",
        "limitations": ["synthetic test manifest"],
        "arms": {
            "p0": {"run_root": str(tmp / "run" / "p0"), "agent": "opencode"},
            "p1": {"run_root": str(tmp / "run" / "p1"),
                   "agent": "opencode-b1p"},
            "t1": {"run_root": str(tmp / "run" / "t1"),
                   "agent": "opencode-c1"},
        },
    }


def _materialize_run(root: Path, rows: list[dict]) -> None:
    for r in rows:
        rd = root / r["task_id"] / r["run_id"]
        rd.mkdir(parents=True)
        if r["status"] == "ok":
            (rd / "result.json").write_text(
                json.dumps({"category": r["predicted_category"]}))
        else:
            (rd / "error.txt").write_text("timeout\n")


class MatrixTest(unittest.TestCase):
    def _fixture(self, td: Path):
        manifest = _manifest(td)
        p0_rows = [_row(T1, "run_001", "vulnerable"),
                   _row(T2, "run_001", "code_not_reachable")]
        p1_rows = [_row(T1, "run_001", "code_not_reachable"),   # FS!
                   _row(T2, "run_001", "code_not_reachable")]
        t1_rows = [_row(T1, "run_001", "vulnerable"),
                   _row(T2, "run_001", "requires_configuration"),
                   _row(T2, "run_002", "code_not_reachable")]
        scored = {}
        for arm, rows in (("p0", p0_rows), ("p1", p1_rows),
                          ("t1", t1_rows)):
            _materialize_run(Path(manifest["arms"][arm]["run_root"]),
                             rows)
            scored[arm] = _scored_dir(td / "scored" / arm, rows)
        return manifest, scored

    def test_matrix_row_shape(self):
        with tempfile.TemporaryDirectory() as t:
            manifest, scored = self._fixture(Path(t))
            matrix = R.build_matrix(manifest, scored)
            self.assertEqual(matrix["schema"], "task5-scoring/1")
            rows = {r["task_id"]: r for r in matrix["rows"]}
            r = rows[T1]
            for arm in ("p0", "p1", "t1"):
                self.assertIn(arm, r["arms"])
            p1 = r["arms"]["p1"]
            self.assertTrue(p1["present"])
            self.assertEqual(p1["official"]["category"],
                             "code_not_reachable")
            self.assertEqual(p1["official"]["outcome"], "safe")
            self.assertEqual(p1["audit"]["outcome"], "safe")
            self.assertIsNotNone(p1["result_sha256"])

    def test_missing_arm_cell_is_present_false_not_invented(self):
        with tempfile.TemporaryDirectory() as t:
            manifest, scored = self._fixture(Path(t))
            matrix = R.build_matrix(manifest, scored)
            rows = {r["task_id"]: r for r in matrix["rows"]}
            t2 = rows[T2]
            # p0/p1 have only run_001 → the T1-only run_002 row must
            # carry present:false for the other arms
            r2 = [r for r in matrix["rows"]
                  if r["run_id"] == "run_002"][0]
            self.assertFalse(r2["arms"]["p0"]["present"])
            self.assertFalse(r2["arms"]["p1"]["present"])
            self.assertTrue(r2["arms"]["t1"]["present"])

    def test_disagreement_pairing_and_classes(self):
        with tempfile.TemporaryDirectory() as t:
            manifest, scored = self._fixture(Path(t))
            dis = R.build_disagreements(manifest, scored)
            # p0->p1 pairs only run_001 (p0 has no run_002)
            self.assertTrue(all(
                d["run_id"] == "run_001" for d in dis
                if d["pair"] == "p0->p1"))
            t1_p0p1 = [d for d in dis if d["pair"] == "p0->p1"
                       and d["task_id"] == T1][0]
            self.assertEqual(t1_p0p1["transition"], "false_safe_appeared")
            self.assertEqual(t1_p0p1["kind"], "regression")
            # T2: safe->safe stays stable
            t2_p0p1 = [d for d in dis if d["pair"] == "p0->p1"
                       and d["task_id"] == T2][0]
            self.assertEqual(t2_p0p1["transition"], "stable_safe")
            # p1->t1 on T1: safe->positive is a cleared false-safe
            t1_p1t1 = [d for d in dis if d["pair"] == "p1->t1"
                       and d["task_id"] == T1][0]
            self.assertEqual(t1_p1t1["transition"], "false_safe_cleared")

    def test_tool_failures_scan(self):
        with tempfile.TemporaryDirectory() as t:
            manifest = _manifest(Path(t))
            rd = (Path(manifest["arms"]["t1"]["run_root"])
                  / T1 / "run_001" / "artifacts" / "izyan-audit")
            rd.mkdir(parents=True)
            (rd / "tool_calls.jsonl").write_text(
                json.dumps({"tool": "run_govulncheck", "observation": {
                    "tool": "run_govulncheck", "tool_status": "ERROR",
                    "error": "govulncheck binary missing"}}) + "\n")
            fails = R.build_tool_failures(
                manifest, {"t1": Path(t) / "x"})
            self.assertEqual(len(fails), 1)
            self.assertEqual(fails[0]["arm"], "t1")
            self.assertEqual(fails[0]["task_id"], T1)
            self.assertEqual(fails[0]["error_class"],
                             "govulncheck_missing")

    def test_write_scoring_artifacts_emits_all_files(self):
        with tempfile.TemporaryDirectory() as t:
            manifest, scored = self._fixture(Path(t))
            out = Path(t) / "scoring"
            res = R.write_scoring_artifacts(manifest, scored, out)
            for key in ("matrix", "disagreements",
                        "tool_failures", "safety_report"):
                self.assertTrue(Path(res[key]).is_file(), key)
            matrix = json.loads(Path(res["matrix"]).read_text())
            self.assertEqual(matrix["n_rows"], 3)
            report_text = Path(res["safety_report"]).read_text()
            self.assertIn("| p0 |", report_text)
            self.assertIn("p0->p1 false_safe_appeared: 1", report_text)
            self.assertIn("synthetic test manifest", report_text)


if __name__ == "__main__":
    unittest.main()

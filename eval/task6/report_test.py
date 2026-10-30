"""Unit tests for eval/task6/report.py — the four-projection scoring
join over synthetic parsed.jsonl dirs (no model calls).

Run: $HARNESS/.venv/bin/python -m unittest eval.task6.report_test -v
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from eval.task6 import report as R  # noqa: E402

T1, T2, T3 = ("aaa-1", "bbb-2", "ccc-3")


def _row(task_id, run_id="run_001", category="code_not_reachable",
         ground_truth="not_exploitable", status="ok", cost=0.1,
         tokens=100):
    return {
        "task_id": task_id,
        "run_id": run_id,
        "cve_id": f"CVE-2020-{task_id}",
        "status": status,
        "predicted_category": category,
        "predicted": "exploitable" if category == "vulnerable"
        else "not_exploitable",
        "ground_truth": ground_truth,
        "ground_truth_category": ("vulnerable" if ground_truth
                                  == "exploitable"
                                  else "code_not_reachable"),
        "completed": True,
        "steps": 10,
        "cost_usd": cost,
        "total_tokens": tokens,
    }


def _vres(task_id, run_id="run_001", decision="ACCEPTED",
          agent_cat="code_not_reachable", outcome="safe",
          gt="not_exploitable"):
    return {
        "schema": "task6-replay/1",
        "arm": "p2",
        "task_id": task_id,
        "run_id": run_id,
        "agent_category": agent_cat,
        "agent_safe_verdict": True,
        "agent_outcome": outcome,
        "assessment_present": True,
        "advisory_source": None,
        "decision": decision,
        "safe_verdict": True,
        "reason": "r",
        "per_claim": [{
            "predicate": "p", "subject": "s", "scope": "all",
            "evidence_refs": ["src:a/b.go#L1@" + "a" * 64],
            "resolved_refs": [], "binding": "snapshot",
            "supported": True, "decision": None, "defects": []}],
        "falsifier": {},
        "coverage": {"declared_subjects": [], "fixed_versions": [],
                     "advisory_present": False, "entries": []},
        "validator_version": "task6-validator/1",
        "ground_truth": gt,
    }


def _scored(root: Path, proj: str, parsed, vres=None) -> Path:
    d = root / proj
    d.mkdir(parents=True, exist_ok=True)
    (d / "parsed.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in parsed))
    if vres is not None:
        (d / "validator_results.jsonl").write_text(
            "".join(json.dumps(r) + "\n" for r in vres))
    return d


def _manifest(root: Path) -> dict:
    return {
        "experiment_id": "task6",
        "limitations": ["synthetic fixture manifest"],
        "arms": {
            "p2": {"run_root": str(root / "runs" / "p2")},
            "t2": {"run_root": str(root / "runs" / "t2")},
        },
    }


class OutcomeCountsTest(unittest.TestCase):
    def test_attempt_and_case_denominators(self):
        rows = [
            _row(T1, ground_truth="exploitable"),            # FS
            _row(T2, category="vulnerable",
                 ground_truth="exploitable"),                # TP
            _row(T3),                                        # CS
            _row(T3, run_id="run_002", category="uncertain"),# abstain
        ]
        out = R._outcome_counts(rows)
        a, c = out["attempts"], out["cases"]
        self.assertEqual(a["total"], 4)
        self.assertEqual(a["false_safe"], 1)
        self.assertEqual(a["correct_safe"], 1)
        self.assertEqual(a["abstain"], 1)
        # unique cases: testify-style repeats of one case collapse
        self.assertEqual(c["total"], 3)
        self.assertEqual(c["false_safe"], 1)
        self.assertEqual(c["correct_safe"], 1)


class BuildMatrixTest(unittest.TestCase):
    def test_matrix_joins_all_four_projections(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            m = _manifest(root)
            scored = {
                "p2": _scored(root / "sc", "p2", [
                    _row(T1, ground_truth="exploitable"),
                    _row(T2)]),
                "t2": _scored(root / "sc", "t2", [
                    _row(T1, ground_truth="exploitable",
                         category="vulnerable"),
                    _row(T2)]),
                "v_p2": _scored(root / "sc", "v_p2", [
                    {**_row(T1, ground_truth="exploitable",
                            category="uncertain"),
                     "validator_adjusted": True},
                    _row(T2)], vres=[
                        _vres(T1, decision="UNVERIFIABLE",
                              gt="exploitable"),
                        _vres(T2)]),
            }
            mx = R.build_matrix(m, scored)
            self.assertEqual(mx["schema"], "task6-scoring/1")
            self.assertEqual(mx["n_rows"], 2)
            self.assertEqual(mx["projections_scored"],
                             ["p2", "t2", "v_p2"])
            rows = {r["task_id"]: r for r in mx["rows"]}
            cell = rows[T1]["projections"]["v_p2"]
            self.assertEqual(cell["official"]["category"], "uncertain")
            self.assertEqual(cell["official"]["outcome"], "abstain")
            self.assertEqual(cell["validator"]["decision"],
                             "UNVERIFIABLE")
            self.assertTrue(cell["validator"]["adjusted"])
            # p2's cell keeps the raw safe outcome — never rewritten
            p2cell = rows[T1]["projections"]["p2"]
            self.assertEqual(p2cell["official"]["category"],
                             "code_not_reachable")
            self.assertEqual(p2cell["official"]["outcome"], "safe")
            # missing projections → present:false, never imputed
            self.assertFalse(
                rows[T1]["projections"].get("v_t2", {}).get("present"))


class DisagreementsTest(unittest.TestCase):
    def test_raw_vs_validator_pairs_reported(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            m = _manifest(root)
            scored = {
                "p2": _scored(root / "sc", "p2", [
                    _row(T1, ground_truth="exploitable")]),
                "v_p2": _scored(root / "sc", "v_p2", [
                    {**_row(T1, ground_truth="exploitable",
                            category="uncertain"),
                     "validator_adjusted": True}]),
            }
            ds = R.build_disagreements(m, scored)
            self.assertTrue(ds)
            d = ds[0]
            # shared vocabulary has no "blocked" notion — the
            # validator semantics ride in validator_transition
            self.assertEqual(d["transition"], "safe_wobble")
            self.assertEqual(d["validator_transition"],
                             "false_safe_blocked")
            self.assertEqual(d["a"]["outcome"], "safe")
            self.assertEqual(d["b"]["outcome"], "abstain")


class WriteArtifactsTest(unittest.TestCase):
    def test_scoring_artifacts_written(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            m = _manifest(root)
            scored = {
                "p2": _scored(root / "sc", "p2", [
                    _row(T1, ground_truth="exploitable"),
                    _row(T2)]),
                "v_p2": _scored(root / "sc", "v_p2", [
                    {**_row(T1, ground_truth="exploitable",
                            category="uncertain"),
                     "validator_adjusted": True},
                    _row(T2)], vres=[
                        _vres(T1, decision="UNVERIFIABLE",
                              gt="exploitable"),
                        _vres(T2)]),
            }
            out = R.write_scoring_artifacts(
                m, scored, root / "out")
            for k in ("matrix", "disagreements", "safety_report",
                      "validator_report"):
                self.assertTrue(Path(out[k]).is_file(), k)
            self.assertEqual(out["n_matrix_rows"], 2)

            sr = Path(out["safety_report"]).read_text()
            self.assertIn("| p2 |", sr)
            self.assertIn("| v_p2 |", sr)
            # p2: 1 FS of 1 exploitable attempt
            self.assertIn("1 / 1", sr)
            self.assertIn("Unique-case view", sr)

            vr = Path(out["validator_report"]).read_text()
            self.assertIn("v_p2 (replay of p2)", vr)
            self.assertIn("FS blocked (attempts / unique cases): 1 / 1",
                          vr)
            self.assertIn(
                "correct safe lost (attempts / unique cases): 0 / 0",
                vr)
            self.assertIn("UNVERIFIABLE=1", vr)

    def test_unique_case_denominator_in_report(self):
        """Three repeats of ONE case count once in the case view."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            m = _manifest(root)
            scored = {
                "p2": _scored(root / "sc", "p2", [
                    _row(T1, run_id="run_001",
                         ground_truth="exploitable"),
                    _row(T1, run_id="run_002",
                         ground_truth="exploitable"),
                    _row(T1, run_id="run_003",
                         ground_truth="exploitable"),
                ]),
            }
            out = R.write_scoring_artifacts(m, scored, root / "o")
            c = out["summaries"]["p2"]["cases"]
            self.assertEqual(c["total"], 1)
            self.assertEqual(c["false_safe"], 1)
            a = out["summaries"]["p2"]["attempts"]
            self.assertEqual(a["false_safe"], 3)

    def test_missing_projection_absent_from_outputs(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            m = _manifest(root)
            scored = {"p2": _scored(root / "sc", "p2", [_row(T1)])}
            out = R.write_scoring_artifacts(m, scored, root / "o")
            self.assertNotIn("v_p2", out["summaries"])
            vr = Path(out["validator_report"]).read_text()
            self.assertIn("No validator projections", vr)


if __name__ == "__main__":
    unittest.main()

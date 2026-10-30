"""Unit tests for eval/task6/freeze.py — phase 6.0 scorer re-verification.

Two layers:

1. Structural — always runs: rule semantics over synthetic
   observations, zero-result detection, observation loading (flattened
   + audit-trail fallback), by-case aggregation.
2. Live re-verification — skipped when the (gitignored) Task-5 result
   roots are absent: recomputation against the real frozen matrix and
   T1 audit trails reproduces the published operand counts and proves
   the 19 + 26 < 46 union anomaly.

Run: $HARNESS/.venv/bin/python -m unittest eval.task6.freeze_test -v
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from eval.task6 import freeze as F  # noqa: E402


def _obs(tool, status="OK", completeness="COMPLETE", data=None,
         limitations=None):
    return {
        "id": "OBS-0001",
        "tool": tool,
        "tool_status": status,
        "completeness": completeness,
        "data": data or {},
        "limitations": limitations or [],
    }


class ZeroResultTest(unittest.TestCase):
    def test_count_zero_detected(self):
        self.assertTrue(F._is_zero_result(_obs("find_callers",
                        data={"count": 0, "call_sites": []})))

    def test_callers_inside_module_zero_detected(self):
        self.assertTrue(F._is_zero_result(_obs(
            "dep_invocation_state",
            data={"callers_inside_module": 0, "sibling_live": False})))

    def test_nonzero_not_detected(self):
        self.assertFalse(F._is_zero_result(_obs("find_callers",
                         data={"count": 3})))

    def test_missing_data_not_detected(self):
        self.assertFalse(F._is_zero_result(_obs("find_callers")))
        self.assertFalse(F._is_zero_result(_obs("find_callers",
                         data=None)))
        # an ERROR observation has no enumeration data at all
        self.assertFalse(F._is_zero_result(_obs(
            "find_callers", status="ERROR", completeness="UNKNOWN")))


class RuleSetTest(unittest.TestCase):
    """_rule_sets over synthetic observation lists."""

    def test_rg_all_reachability_errored(self):
        obs = [
            _obs("get_vulnerability"),
            _obs("find_symbol", status="ERROR", completeness="UNKNOWN"),
            _obs("find_callers", status="ERROR", completeness="UNKNOWN"),
        ]
        f = F._rule_sets(obs, "code_not_reachable")
        self.assertTrue(f["RG"])
        self.assertTrue(f["RH"])
        self.assertFalse(f["R6"])
        self.assertTrue(f["UNION"])

    def test_rg_not_set_when_reachability_succeeded(self):
        obs = [
            _obs("find_callers", status="ERROR", completeness="UNKNOWN"),
            _obs("find_may_callers", data={"count": 2}),
        ]
        f = F._rule_sets(obs, "code_not_reachable")
        self.assertFalse(f["RG"])
        self.assertTrue(f["RH"])  # the errored one still counts for RH
        self.assertTrue(f["UNION"] is False or f["UNION"] == f["R6"])

    def test_rg_not_set_without_reachability_queries(self):
        obs = [_obs("get_vulnerability"), _obs("get_fix_diff")]
        f = F._rule_sets(obs, "code_not_reachable")
        self.assertFalse(f["RG"])  # nothing queried → nothing failed

    def test_r6_scoped_zero_in_negative_category(self):
        obs = [
            _obs("find_callers", completeness="PARTIAL",
                 data={"count": 0},
                 limitations=["product packages only"]),
        ]
        f = F._rule_sets(obs, "code_not_reachable")
        self.assertTrue(f["R5"])
        self.assertTrue(f["R6"])
        self.assertTrue(f["UNION"])

    def test_r6_not_set_for_other_categories(self):
        obs = [
            _obs("find_callers", completeness="PARTIAL",
                 data={"count": 0},
                 limitations=["product packages only"]),
        ]
        self.assertFalse(F._rule_sets(obs, "perimeter_protected")["R6"])
        self.assertFalse(F._rule_sets(obs, "false_positive")["R6"])

    def test_r6_needs_zero_and_incomplete(self):
        # non-zero PARTIAL observation is not a scoped-zero
        f = F._rule_sets(
            [_obs("find_callers", completeness="PARTIAL",
                  data={"count": 3}, limitations=["x"])],
            "code_not_reachable")
        self.assertFalse(f["R6"])
        # zero-result but COMPLETE scope is a verifiable absence
        f = F._rule_sets(
            [_obs("find_callers", completeness="COMPLETE",
                  data={"count": 0}, limitations=["x"])],
            "code_not_reachable")
        self.assertFalse(f["R6"])
        # zero + PARTIAL but no declared limitations — not R6
        f = F._rule_sets(
            [_obs("find_callers", completeness="PARTIAL",
                  data={"count": 0})],
            "code_not_reachable")
        self.assertFalse(f["R6"])

    def test_union_is_operand_union(self):
        # UNION must be computed from RG ∪ R6 — never reported
        rg_only = [_obs("find_callers", status="ERROR",
                        completeness="UNKNOWN")]
        f = F._rule_sets(rg_only, "code_not_reachable")
        self.assertTrue(f["RG"] and not f["R6"] and f["UNION"])


class ObservationLoadingTest(unittest.TestCase):
    def test_flattened_observations_file(self):
        with tempfile.TemporaryDirectory() as t:
            rd = Path(t)
            (rd / "observations.jsonl").write_text(
                json.dumps(_obs("find_callers")) + "\n")
            obs = F._read_observations(rd)
            self.assertEqual(len(obs), 1)
            self.assertEqual(obs[0]["tool"], "find_callers")

    def test_audit_trail_fallback(self):
        with tempfile.TemporaryDirectory() as t:
            rd = Path(t)
            audit = rd / "artifacts" / "izyan-audit"
            audit.mkdir(parents=True)
            rec = {"tool": "find_callers", "args": {},
                   "observation": _obs("find_callers")}
            (audit / "tool_calls.jsonl").write_text(
                json.dumps(rec) + "\n")
            obs = F._read_observations(rd)
            self.assertEqual(len(obs), 1)
            self.assertEqual(obs[0]["tool"], "find_callers")

    def test_missing_everything(self):
        with tempfile.TemporaryDirectory() as t:
            self.assertEqual(F._read_observations(Path(t)), [])


class ByCaseAggregationTest(unittest.TestCase):
    """Unique-case semantics: N attempts of one case = one case."""

    def _matrix(self):
        return {"schema": "t", "rows": [
            # one case, 3 attempts — all safe, all rule-flagged
            {"task_id": "alpha", "run_id": f"run_{i:03d}",
             "cve_id": "CVE-X", "ground_truth": "not_exploitable",
             "ground_truth_category": "code_not_reachable",
             "arms": {"t1": {"present": True,
                             "audit": {"category": "code_not_reachable",
                                       "outcome": "safe"}}}}
            for i in (1, 2, 3)] + [
            # second case: 1 flagged of 2 safe attempts
            {"task_id": "beta", "run_id": "run_001",
             "cve_id": "CVE-Y", "ground_truth": "not_exploitable",
             "ground_truth_category": "code_not_present",
             "arms": {"t1": {"present": True,
                             "audit": {"category": "code_not_present",
                                       "outcome": "safe"}}}},
            {"task_id": "beta", "run_id": "run_002",
             "cve_id": "CVE-Y", "ground_truth": "not_exploitable",
             "ground_truth_category": "code_not_present",
             "arms": {"t1": {"present": True,
                             "audit": {"category": "code_not_present",
                                       "outcome": "safe"}}}},
        ]}

    def test_case_vs_attempt_counts(self):
        with tempfile.TemporaryDirectory() as t:
            ml = Path(t) / "model"
            flagged = _obs("find_callers", status="ERROR",
                           completeness="UNKNOWN")
            clean = _obs("find_callers", data={"count": 4})
            for task, runs in (("alpha", 3), ("beta", 2)):
                for i in range(runs):
                    rd = ml / task / f"run_{i + 1:03d}"
                    rd.mkdir(parents=True)
                    obs = [flagged] if not (
                        task == "beta" and i == 1) else [clean]
                    (rd / "observations.jsonl").write_text(
                        "".join(json.dumps(o) + "\n" for o in obs))
            tables = F.recompute_tables(self._matrix(), ml)
            rg_a = tables["by_attempt"]["RG"]
            rg_c = tables["by_case"]["RG"]
            self.assertEqual(rg_a["correct_safe_lost"], 4)   # attempts
            self.assertEqual(rg_c["correct_safe_cases_lost"], 2)
            self.assertEqual(rg_c["correct_safe_cases_fully_lost"], 1)
            self.assertEqual(tables["denominators"]
                             ["correct_safe_attempts"], 5)
            self.assertEqual(tables["denominators"]
                             ["correct_safe_cases"], 2)


@unittest.skipUnless(
    F.RESULTS_T1.is_dir() and F.MATRIX_FILE.is_file(),
    "Task-5 result/scoring roots absent (gitignored local artifacts)")
class LiveReVerificationTest(unittest.TestCase):
    """Recomputed tables against the real frozen Task-5 artifacts."""

    @classmethod
    def setUpClass(cls):
        cls.ref = F.build_reference()

    def test_headline_confirmed(self):
        self.assertTrue(self.ref["headline"]["confirmed"])
        rec = self.ref["headline"]["recomputed"]
        self.assertEqual((rec["false_safe_attempts"],
                          rec["exploitable_attempts"]), (5, 21))
        self.assertEqual((rec["correct_safe_attempts"],
                          rec["safe_ground_truth_attempts"]), (63, 69))
        # unique-case view: the 5 false-safe attempts are 3 cases
        self.assertEqual(rec["false_safe_cases"], 3)

    def test_operand_rules_reproduce(self):
        ba = self.ref["gate_rules"]["by_attempt"]
        for rule, (fs_n, cs_n) in (("RG", (2, 19)), ("R6", (3, 26))):
            self.assertEqual(
                (ba[rule]["false_safe_blocked"],
                 ba[rule]["correct_safe_lost"]),
                (fs_n, cs_n), rule)
            self.assertTrue(ba[rule]["matches_reported"], rule)

    def test_union_anomaly_explained(self):
        a = self.ref["gate_rules"]["union_anomaly"]
        self.assertEqual(a["published"]["UNION_correct_safe_lost"], 46)
        # 19 + 26 = 45 is the maximum possible union — the printed 46
        # exceeds it, so it cannot be a real union of its operands.
        r = a["recomputed"]
        self.assertLessEqual(
            r["union_correct_safe_lost_attempts"],
            r["RG_correct_safe_lost_attempts"]
            + r["R6_correct_safe_lost_attempts"])
        self.assertIn("45", a["arithmetic"])

    def test_matrix_result_hashes_verified(self):
        m = self.ref["hashes"]["matrix_result_sha256"]
        self.assertEqual(m["mismatched"], [])
        self.assertGreater(m["checked"], 0)

    def test_freeze_writes_reference_json(self):
        with tempfile.TemporaryDirectory() as t:
            ref = F.freeze_history(Path(t))
            p = Path(t) / "task5-reference.json"
            self.assertTrue(p.is_file())
            doc = json.loads(p.read_text())
            self.assertEqual(doc["schema"], F.REFERENCE_SCHEMA)
            self.assertIn("union_anomaly", doc["gate_rules"])
            self.assertIn("by_case", doc["gate_rules"])
            self.assertEqual(doc, ref)


if __name__ == "__main__":
    unittest.main()

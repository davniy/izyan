"""Unit tests for eval/task6/replay.py — offline validator replay over
synthetic finalized attempts (no model calls, no docker).

Run: $HARNESS/.venv/bin/python -m unittest eval.task6.replay_test -v
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from eval.task6 import replay as R  # noqa: E402

SNAP = "a" * 64
TASK_ID = "o-r-abc1234-CVE-2020-00001"
RUN_ID = "run_001"


def _assessment_artifact(category="code_not_reachable",
                         claims=None,
                         snapshot_hash=SNAP):
    if claims is None:
        claims = [{
            "predicate": "symbol never invoked",
            "subject": "pkg/vuln.Vulnerable",
            "scope": "all first-party call paths",
            "evidence_refs": [f"src:pkg/vuln.go#L42@{snapshot_hash}"],
        }]
    return {
        "schema_version": "agent-assessment/2",
        "meta": {
            "experiment_id": "task6-smoke",
            "task_id": TASK_ID,
            "attempt_id": RUN_ID,
            "cve_id": "CVE-2020-00001",
            "snapshot_hash": snapshot_hash,
            "model": "m",
            "prompt_version": "vuln_safety_v2-abc",
            "harness_version": "h",
            "tool_adapter_version": "t",
            "image": "i",
        },
        "category": category,
        "reasoning": "checked the only path",
        "assessment": {
            "mechanisms": [],
            "negative_claims": claims,
            "unresolved": [],
            "reasoning": "walked the entrypoint",
        },
        "tool_executions": [],
        "usage": {},
    }


def _advisory_obs(subject="pkg/vuln"):
    """A tool-minted get_vulnerability observation — the public
    advisory record the replay loader resolves (never GT)."""
    return {
        "id": "OBS-ADV",
        "tool": "get_vulnerability",
        "tool_status": "OK",
        "data": {"id": "GHSA-test",
                 "affected": [{"package": {"name": subject}}]},
    }


def _snapshot(root: Path, *relpaths: str) -> Path:
    """A minimal product-snapshot dir for the C1 file index."""
    snap = root / "product-snapshot"
    for rel in relpaths:
        p = snap / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("x\n")
    return snap


def _attempt(root: Path, *, artifact=None, raw_text=None,
             tool_calls=None, observations=None,
             status=None) -> Path:
    run_dir = root / TASK_ID / RUN_ID
    run_dir.mkdir(parents=True)
    if artifact is not None:
        (run_dir / "agent_assessment.json").write_text(
            json.dumps(artifact))
    if raw_text is not None:
        (run_dir / "raw_agent_output.txt").write_text(raw_text)
    if tool_calls:
        (run_dir / "tool_calls.jsonl").write_text(
            "".join(json.dumps(r) + "\n" for r in tool_calls))
    if observations:
        (run_dir / "observations.jsonl").write_text(
            "".join(json.dumps(o) + "\n" for o in observations))
    if status is not None:
        (run_dir / "status.json").write_text(json.dumps(status))
    return run_dir


def _row(category="code_not_reachable", ground_truth="not_exploitable",
         task_id=TASK_ID, run_id=RUN_ID, status="ok"):
    return {
        "task_id": task_id, "run_id": run_id,
        "cve_id": "CVE-2020-00001",
        "status": status,
        "predicted_category": category,
        "predicted": "not_exploitable" if category != "vulnerable"
        else "exploitable",
        "ground_truth": ground_truth,
        "ground_truth_category": "code_not_reachable"
        if ground_truth == "not_exploitable" else "vulnerable",
    }


class StoredAssessmentTest(unittest.TestCase):
    def test_prefers_persisted_artifact(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            run_dir = _attempt(
                root,
                artifact=_assessment_artifact(),
                raw_text="not json",
            )
            ev = R.load_attempt_evidence(run_dir)
            self.assertIsNotNone(ev["assessment"])
            self.assertIsNone(ev["extraction"])
            self.assertEqual(
                ev["assessment"].category, "code_not_reachable")
            self.assertEqual(ev["snapshot_hash"], SNAP)

    def test_unparsable_artifact_falls_back_to_terminal(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            run_dir = _attempt(root)
            (run_dir / "agent_assessment.json").write_text("{corrupt")
            payload = {
                "category": "code_not_reachable",
                "reasoning": "r",
                "assessment": {
                    "mechanisms": [],
                    "negative_claims": [{
                        "predicate": "p", "subject": "s",
                        "scope": "everything",
                        "evidence_refs": ["file:a.go:1"]}],
                    "unresolved": [],
                    "reasoning": "r",
                },
            }
            (run_dir / "raw_agent_output.txt").write_text(
                json.dumps(payload))
            ev = R.load_attempt_evidence(run_dir)
            self.assertIsNone(ev["assessment"])
            self.assertIsNotNone(ev["extraction"])
            self.assertEqual(
                ev["extraction"].category, "code_not_reachable")

    def test_snapshot_hash_falls_back_to_status_json(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            run_dir = _attempt(
                root,
                status={
                    "schema_version": "attempt-status/1",
                    "task_id": TASK_ID, "attempt_id": RUN_ID,
                    "experiment_id": "e", "execution": "ok",
                    "official_parse": "accepted",
                    "assessment_schema": "invalid",
                    "overall": "valid",
                })
            # no snapshot_hash on AttemptStatus → stays None unless the
            # caller supplies one
            ev = R.load_attempt_evidence(run_dir)
            self.assertIsNone(ev["snapshot_hash"])
            ev2 = R.load_attempt_evidence(
                run_dir, snapshot_hash="fallback-hash")
            self.assertEqual(ev2["snapshot_hash"], "fallback-hash")


class AdvisoryResolutionTest(unittest.TestCase):
    def test_minted_observation_record(self):
        with tempfile.TemporaryDirectory() as t:
            run_dir = _attempt(
                Path(t),
                observations=[{
                    "id": "OBS-0001",
                    "tool": "get_vulnerability",
                    "tool_status": "OK",
                    "data": {"id": "GHSA-x", "aliases": ["CVE-2020-1"],
                             "affected": [{"package": {"name": "p"}}]},
                }])
            ev = R.load_attempt_evidence(run_dir)
            self.assertEqual(ev["advisory_source"],
                             "audit:get_vulnerability")
            self.assertEqual(ev["advisory_record"]["id"], "GHSA-x")

    def test_library_falls_back_to_aliases(self):
        """Advisory library files keyed by GO id — matching via the
        aliases[] field, not just the filename/id."""
        with tempfile.TemporaryDirectory() as t:
            lib = Path(t) / "advisories"
            lib.mkdir()
            (lib / "GO-2020-0001.json").write_text(json.dumps({
                "id": "GO-2020-0001",
                "aliases": ["CVE-2020-00001"],
                "affected": [],
            }))
            rec = R.advisory_from_library(lib, "CVE-2020-00001")
            self.assertIsNotNone(rec)
            self.assertEqual(rec["id"], "GO-2020-0001")
            self.assertIsNone(R.advisory_from_library(lib, "CVE-9"))
            self.assertIsNone(R.advisory_from_library(None, "CVE-9"))


class ReplayAttemptTest(unittest.TestCase):
    def test_accepted_safe_answer_passes_through(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            run_dir = _attempt(
                root,
                artifact=_assessment_artifact(),
                observations=[_advisory_obs()])
            snap = _snapshot(root, "pkg/vuln.go")
            rec = R.replay_attempt(
                run_dir, arm="v_p2", task_id=TASK_ID, run_id=RUN_ID,
                agent_category="code_not_reachable",
                snapshot_dir=snap)
            self.assertEqual(rec["decision"], "ACCEPTED")
            self.assertTrue(rec["safe_verdict"])
            self.assertTrue(rec["assessment_present"])
            self.assertEqual(
                rec["agent_category"], "code_not_reachable")

    def test_self_declared_only_claim_is_unverifiable(self):
        """file:/url: refs never satisfy C4 — a safe verdict resting
        only on self-declared evidence is UNVERIFIABLE/INSUFFICIENT."""
        with tempfile.TemporaryDirectory() as t:
            art = _assessment_artifact(claims=[{
                "predicate": "symbol never invoked",
                "subject": "pkg/vuln.Vulnerable",
                "scope": "everything",
                "evidence_refs": ["file:pkg/vuln.go:42"],
            }])
            run_dir = _attempt(Path(t), artifact=art)
            rec = R.replay_attempt(
                run_dir, arm="v_p2", task_id=TASK_ID, run_id=RUN_ID,
                agent_category="code_not_reachable")
            self.assertIn(rec["decision"],
                          ("UNVERIFIABLE", "INSUFFICIENT_EVIDENCE"))
            self.assertTrue(rec["safe_verdict"])
            self.assertEqual(rec["agent_category"],
                             "code_not_reachable")

    def test_missing_assessment_records_abstain_not_guess(self):
        with tempfile.TemporaryDirectory() as t:
            run_dir = _attempt(Path(t))
            rec = R.replay_attempt(
                run_dir, arm="v_p2", task_id=TASK_ID, run_id=RUN_ID,
                agent_category="code_not_reachable")
            self.assertEqual(rec["decision"], "INSUFFICIENT_EVIDENCE")
            self.assertFalse(rec["assessment_present"])
            self.assertEqual(rec["per_claim"], [])  # nothing to check
            self.assertEqual(
                rec["agent_category"], "code_not_reachable")

    def test_ev_ref_resolves_from_audit_trail(self):
        with tempfile.TemporaryDirectory() as t:
            art = _assessment_artifact(claims=[{
                "predicate": "tool says no path",
                "subject": "pkg/vuln.Vulnerable",
                "scope": "module",
                "evidence_refs": ["ev:OBS-0007"],
            }])
            run_dir = _attempt(
                Path(t), artifact=art,
                observations=[_advisory_obs()],
                tool_calls=[{
                    "tool": "find_callers",
                    "observation": {"tool": "find_callers",
                                    "id": "OBS-0007",
                                    "tool_status": "OK",
                                    "completeness": "COMPLETE"},
                }])
            rec = R.replay_attempt(
                run_dir, arm="v_t2", task_id=TASK_ID, run_id=RUN_ID,
                agent_category="code_not_reachable")
            self.assertEqual(rec["decision"], "ACCEPTED")
            self.assertTrue(rec["safe_verdict"])

    def test_unsafe_category_needs_no_claims(self):
        art = _assessment_artifact(
            category="vulnerable",
            claims=[])
        with tempfile.TemporaryDirectory() as t:
            run_dir = _attempt(Path(t), artifact=art)
            rec = R.replay_attempt(
                run_dir, arm="v_p2", task_id=TASK_ID, run_id=RUN_ID,
                agent_category="vulnerable")
            self.assertFalse(rec["safe_verdict"])
            # a vulnerable verdict with zero claims is not blocked by
            # the falsifier check — C4 doesn't apply
            self.assertNotEqual(rec["decision"], "INSUFFICIENT_EVIDENCE")


class AdjustRowTest(unittest.TestCase):
    def test_blocked_safe_becomes_uncertain(self):
        row = _row()
        out = R.adjust_row(row, "UNVERIFIABLE", True)
        self.assertEqual(out["predicted_category"], "uncertain")
        self.assertTrue(out["validator_adjusted"])
        self.assertEqual(out["validator_decision"], "UNVERIFIABLE")
        # original row untouched — replay never mutates the raw row
        self.assertEqual(row["predicted_category"],
                         "code_not_reachable")

    def test_accepted_safe_unchanged(self):
        out = R.adjust_row(_row(), "ACCEPTED", True)
        self.assertEqual(out["predicted_category"],
                         "code_not_reachable")
        self.assertFalse(out["validator_adjusted"])

    def test_non_safe_verdict_never_adjusted(self):
        out = R.adjust_row(_row(category="vulnerable"),
                           "INSUFFICIENT_EVIDENCE", False)
        self.assertEqual(out["predicted_category"], "vulnerable")
        self.assertFalse(out["validator_adjusted"])


class ReplayArmTest(unittest.TestCase):
    def _run_root(self, t: str) -> Path:
        return Path(t) / "run_root"

    def test_replay_writes_v_arm_scoring_dir(self):
        with tempfile.TemporaryDirectory() as t:
            root = self._run_root(t)
            _attempt(root, artifact=_assessment_artifact(),
                     observations=[_advisory_obs()])
            snap = _snapshot(Path(t), "pkg/vuln.go")
            # a second attempt whose claim cannot bind → adjusted
            bad2dir = root / "other-case" / "run_001"
            bad2dir.mkdir(parents=True)
            (bad2dir / "agent_assessment.json").write_text(json.dumps(
                _assessment_artifact(claims=[{
                    "predicate": "p", "subject": "s",
                    "scope": "everything",
                    "evidence_refs": ["file:x.go:1"],
                }])))
            out_dir = Path(t) / "scoring" / "v_p2"
            summary = R.replay_arm(
                arm="p2", run_root=root,
                parsed_rows=[
                    _row(ground_truth="exploitable"),   # FS if safe
                    _row(task_id="other-case"),          # CS
                ],
                out_dir=out_dir,
                snapshot_dir_by_task={TASK_ID: snap})
            self.assertEqual(summary["schema"], "task6-replay/1")
            self.assertEqual(summary["arm"], "p2")
            self.assertEqual(summary["n_attempts"], 2)
            self.assertTrue((out_dir / "parsed.jsonl").is_file())
            self.assertTrue(
                (out_dir / "validator_results.jsonl").is_file())
            self.assertTrue((out_dir / "safety_metrics.json").is_file())

            adj = [json.loads(l) for l in
                   (out_dir / "parsed.jsonl").read_text().splitlines()
                   if l.strip()]
            self.assertEqual(len(adj), 2)
            by_task = {r["task_id"]: r for r in adj}
            # the ACCEPTED row keeps its safe category
            self.assertEqual(by_task[TASK_ID]["predicted_category"],
                             "code_not_reachable")
            self.assertFalse(by_task[TASK_ID]["validator_adjusted"])
            # the blocked row projects to abstain — never stays safe
            self.assertEqual(
                by_task["other-case"]["predicted_category"],
                "uncertain")
            self.assertTrue(by_task["other-case"]["validator_adjusted"])

            safety = json.loads(
                (out_dir / "safety_metrics.json").read_text())
            self.assertEqual(safety["schema"],
                             "task6-replay-safety/1")
            self.assertEqual(safety["inputs"]["source_arm"], "p2")
            self.assertEqual(safety["inputs"]["n_rows"], 2)
            v = safety["validator"]
            self.assertEqual(
                v["false_safe_blocked_attempts"], [])
            # the blocked attempt on a not-exploitable case is a lost
            # correct-safe
            self.assertEqual(len(v["correct_safe_lost_attempts"]), 1)
            self.assertEqual(v["correct_safe_lost_cases"],
                             ["other-case"])

    def test_fs_blocked_counted_on_exploitable_gt(self):
        """The mechanism Task 5 found: a safe answer on a GT-exploitable
        case that fails validation is a blocked FALSE-SAFE."""
        with tempfile.TemporaryDirectory() as t:
            root = self._run_root(t)
            _attempt(root, artifact=_assessment_artifact(claims=[{
                "predicate": "p", "subject": "s",
                "scope": "everything",
                "evidence_refs": ["file:x.go:1"],
            }]))
            out_dir = Path(t) / "scoring" / "v_p2"
            summary = R.replay_arm(
                arm="p2", run_root=root,
                parsed_rows=[_row(ground_truth="exploitable")],
                out_dir=out_dir)
            self.assertEqual(summary["n_blocked"], 1)
            safety = json.loads(
                (out_dir / "safety_metrics.json").read_text())
            self.assertEqual(
                len(safety["validator"]["false_safe_blocked_attempts"]),
                1)
            self.assertEqual(
                safety["validator"]["false_safe_blocked_cases"],
                [TASK_ID])

    def test_snapshot_hash_by_key_applies(self):
        """Artifact meta wins; the caller-supplied map is the fallback
        for dirs whose meta lacks the hash."""
        with tempfile.TemporaryDirectory() as t:
            root = self._run_root(t)
            run_dir = _attempt(root, observations=[_advisory_obs("s")])
            payload = {
                "category": "code_not_reachable",
                "reasoning": "r",
                "assessment": {
                    "mechanisms": [],
                    "negative_claims": [{
                        "predicate": "p", "subject": "s",
                        "scope": "everything",
                        "evidence_refs":
                            [f"src:a/b.go#L9@{SNAP}"]}],
                    "unresolved": [],
                    "reasoning": "r",
                },
            }
            (run_dir / "raw_agent_output.txt").write_text(
                json.dumps(payload))
            # no artifact → extraction; no meta → caller hash supplies
            # the snapshot binding; the snapshot dir supplies the file
            # index that makes the src@hash ref snapshot-bound
            snap = _snapshot(root, "a/b.go")
            rec = R.replay_attempt(
                run_dir, arm="v_p2", task_id=TASK_ID, run_id=RUN_ID,
                agent_category="code_not_reachable",
                snapshot_hash=SNAP, snapshot_dir=snap)
            self.assertEqual(rec["decision"], "ACCEPTED")
            # wrong hash → the src@hash ref is contradictory
            rec2 = R.replay_attempt(
                run_dir, arm="v_p2", task_id=TASK_ID, run_id=RUN_ID,
                agent_category="code_not_reachable",
                snapshot_hash="b" * 64, snapshot_dir=snap)
            self.assertNotEqual(rec2["decision"], "ACCEPTED")


class ReplayArmsTest(unittest.TestCase):
    def test_missing_parsed_records_error_not_crash(self):
        with tempfile.TemporaryDirectory() as t:
            manifest = {"arms": {"p2": {"run_root": str(Path(t))}}}
            out = R.replay_arms(
                manifest=manifest, arms=["p2"],
                scoring_root=Path(t) / "scoring")
            self.assertIn("error", out["p2"])


if __name__ == "__main__":
    unittest.main()

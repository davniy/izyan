"""Unit tests for eval/task5/collect.py — attempt finalization + arm
isolation audit on synthetic attempt dirs (no harness, no docker).

Run: /tmp/vexbench-agent-ctl/.venv/bin/python -m unittest eval.task5.collect_test -v
"""

import json
import sys
import tempfile
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from eval.c1 import assessment as A  # noqa: E402
from eval.task5 import collect as C  # noqa: E402


class FakeOpencodeAgent:
    """opencode-shaped stub: result.json session export + stats."""

    def result_filename(self):
        return "result.json"

    def extract_text(self, raw: str) -> str:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return ""
        for m in reversed(data.get("messages", [])):
            if m.get("role") == "assistant":
                for part in reversed(m.get("parts", [])):
                    if part.get("type") == "text" and part.get("text"):
                        return part["text"]
        return ""

    def extract_stats(self, raw: str):
        return types.SimpleNamespace(
            input_tokens=11, cached_input_tokens=3,
            output_tokens=7, reasoning_tokens=2,
        )


def official_parser(text):
    """Stand-in for harness result_parser.parse_category."""
    try:
        obj = json.loads(text)
    except Exception:
        obj = None
    if isinstance(obj, dict) and isinstance(obj.get("category"), str):
        return obj["category"].lower(), obj.get("reasoning")
    return None, None


def _export(category="code_not_reachable", reasoning="checked"):
    payload = json.dumps(
        {"category": category, "reasoning": reasoning})
    return json.dumps({
        "messages": [
            {"role": "user", "parts": [{"type": "text", "text": "go"}]},
            {"role": "assistant",
             "parts": [{"type": "text", "text": payload}]},
        ],
    })


def _manifest() -> dict:
    return {
        "schema": "task5-manifest/1",
        "experiment_id": "task5-smoke",
        "model": {"id": "qwen3.6-35b", "model_revision": None},
        "harness": {"commit": "c71f512abc", "dir": "/x"},
        "izyan": {"tool_adapter_version": "izyan-evidence-tools/0.1.0"},
        "tools_binary": {"adapter_version": "izyan-evidence-tools/0.1.0"},
        "dataset": {
            "task_ids": ["o-r-abc1234-CVE-2020-00001"],
            "snapshot_hashes": {"o/r/abc1234" + "0" * 33: "snapsha"},
        },
        "prompts": {
            "vuln_safety_v1": {"sha256_12": "14c1396c9094"},
            "vuln_safety_v1_tools": {"sha256_12": "5d6c640c6945"},
        },
        "arms": {
            "p1": {"agent": "opencode-b1p", "prompt": "vuln_safety_v1",
                   "image_suffix": "opencode-gw", "mcp": False},
            "t1": {"agent": "opencode-c1",
                   "prompt": "vuln_safety_v1_tools",
                   "image_suffix": "opencode-c1", "mcp": True},
        },
    }


TASK = {
    "task_id": "o-r-abc1234-CVE-2020-00001",
    "cve_id": "CVE-2020-00001",
    "repo_url": "https://github.com/o/r",
    "commit_sha": "abc1234" + "0" * 33,
    "ground_truth": "not_exploitable",
    "ground_truth_category": "code_not_reachable",
    "metadata": {"language": "go"},
}


def _make_attempt(root: Path, *, mcp: bool, category="code_not_reachable",
                  with_error=False) -> Path:
    run_dir = root / TASK["task_id"] / "run_001"
    (run_dir / "artifacts").mkdir(parents=True)
    (run_dir / "prompt.txt").write_text("rendered prompt")
    if with_error:
        (run_dir / "error.txt").write_text("container timed out\n")
    else:
        (run_dir / "result.json").write_text(_export(category))
    cfg = {"provider": {"custom-openai": {}}, "agent": {}}
    if mcp:
        cfg["mcp"] = {"izyan": {"type": "local"}}
    (run_dir / "artifacts" / (
        "opencode-config.c1.json" if mcp
        else "opencode-config.b1p.json")).write_text(json.dumps(cfg))
    if mcp:
        audit_dir = run_dir / "artifacts" / "izyan-audit"
        audit_dir.mkdir(parents=True)
        (audit_dir / "tool_calls.jsonl").write_text(
            json.dumps({"tool": "get_vulnerability",
                        "observation": {"tool": "get_vulnerability",
                                        "tool_status": "OK",
                                        "completeness": "COMPLETE"}})
            + "\n"
            + json.dumps({"tool": "run_govulncheck",
                          "observation": {"tool": "run_govulncheck",
                                          "tool_status": "ERROR",
                                          "error": "govulncheck not found"}})
            + "\n")
    return run_dir


class FinalizeArmTest(unittest.TestCase):
    def test_valid_attempt_finalizes(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "p1" / "task5-smoke"
            run_dir = _make_attempt(root, mcp=False)
            m = _manifest()
            out = C.finalize_arm(
                root, arm="p1", manifest=m, tasks=[TASK],
                snapshots={"o/r/" + "abc1234" + "0" * 33: "snapsha"},
                agent=FakeOpencodeAgent(),
                official_parser=official_parser)
            self.assertEqual(out["counts"]["finalized"], 1)
            status = json.loads((run_dir / "status.json").read_text())
            self.assertEqual(status["overall"], "valid")
            self.assertEqual(status["official_parse"], "accepted")
            # Task 5 has no assessment block → absent, not invalid
            self.assertEqual(status["assessment_schema"], "absent")
            # controller artifacts materialized (usage.json wall=None)
            usage = json.loads((run_dir / "usage.json").read_text())
            self.assertIsNone(usage["wall_seconds"])
            self.assertEqual(usage["input_tokens"], 11)
            self.assertTrue((run_dir / "raw_agent_output.txt").exists())

    def test_rerun_skips_finalized(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "p1" / "task5-smoke"
            run_dir = _make_attempt(root, mcp=False)
            m = _manifest()
            kwargs = dict(arm="p1", manifest=m, tasks=[TASK],
                          snapshots={}, agent=FakeOpencodeAgent(),
                          official_parser=official_parser)
            C.finalize_arm(root, **kwargs)
            again = C.finalize_arm(root, **kwargs)
            self.assertEqual(again["counts"]["skipped_finalized"], 1)
            self.assertEqual(again["counts"]["finalized"], 0)

    def test_error_only_attempt_becomes_failed(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "p1" / "task5-smoke"
            run_dir = _make_attempt(root, mcp=False, with_error=True)
            out = C.finalize_arm(
                root, arm="p1", manifest=_manifest(), tasks=[TASK],
                snapshots={}, agent=FakeOpencodeAgent(),
                official_parser=official_parser)
            self.assertEqual(out["counts"]["failed"], 1)
            status = json.loads((run_dir / "status.json").read_text())
            self.assertEqual(status["overall"], "failed")
            self.assertEqual(status["failure_reason"], "timeout")

    def test_empty_attempt_dir_is_incomplete_not_failed(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "p1" / "task5-smoke"
            (root / TASK["task_id"] / "run_001").mkdir(parents=True)
            out = C.finalize_arm(
                root, arm="p1", manifest=_manifest(), tasks=[TASK],
                snapshots={}, agent=FakeOpencodeAgent(),
                official_parser=official_parser)
            self.assertEqual(out["counts"]["incomplete"], 1)
            self.assertFalse(
                (root / TASK["task_id"] / "run_001"
                 / "status.json").exists())

    def test_unknown_task_not_finalized(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "p1" / "task5-smoke"
            rd = root / "foreign-task" / "run_001"
            rd.mkdir(parents=True)
            (rd / "result.json").write_text(_export())
            out = C.finalize_arm(
                root, arm="p1", manifest=_manifest(), tasks=[TASK],
                snapshots={}, agent=FakeOpencodeAgent(),
                official_parser=official_parser)
            self.assertEqual(out["attempts"][0]["collect"],
                             "unknown_task")
            self.assertFalse((rd / "status.json").exists())

    def test_t1_audit_copies_and_observations(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "t1" / "task5-smoke"
            run_dir = _make_attempt(root, mcp=True)
            out = C.finalize_arm(
                root, arm="t1", manifest=_manifest(), tasks=[TASK],
                snapshots={}, agent=FakeOpencodeAgent(),
                official_parser=official_parser)
            self.assertEqual(out["counts"]["finalized"], 1)
            self.assertTrue((run_dir / "tool_calls.jsonl").exists())
            self.assertTrue((run_dir / "observations.jsonl").exists())


class IsolationAuditTest(unittest.TestCase):
    def test_p1_clean(self):
        with tempfile.TemporaryDirectory() as t:
            rd = _make_attempt(Path(t), mcp=False)
            res = C.audit_arm_attempt(rd, expect_mcp=False)
            self.assertTrue(res["isolation_ok"])
            self.assertFalse(res["config_has_mcp"])
            self.assertIsNone(res["audit_sink"])

    def test_p1_contaminated(self):
        with tempfile.TemporaryDirectory() as t:
            rd = _make_attempt(Path(t), mcp=True)
            res = C.audit_arm_attempt(rd, expect_mcp=False)
            self.assertFalse(res["isolation_ok"])

    def test_t1_present(self):
        with tempfile.TemporaryDirectory() as t:
            rd = _make_attempt(Path(t), mcp=True)
            res = C.audit_arm_attempt(rd, expect_mcp=True)
            self.assertTrue(res["isolation_ok"])
            self.assertTrue(res["config_has_mcp"])
            self.assertEqual(res["tool_calls"], 2)
            self.assertEqual(res["tool_status_counts"],
                             {"OK": 1, "ERROR": 1})

    def test_t1_missing_tools(self):
        with tempfile.TemporaryDirectory() as t:
            rd = _make_attempt(Path(t), mcp=False)
            res = C.audit_arm_attempt(rd, expect_mcp=True)
            self.assertFalse(res["isolation_ok"])

    def test_missing_config_reports_not_guesses(self):
        with tempfile.TemporaryDirectory() as t:
            rd = Path(t) / "task" / "run_001"
            rd.mkdir(parents=True)
            (rd / "result.json").write_text(_export())
            res = C.audit_arm_attempt(rd, expect_mcp=False)
            self.assertIsNone(res["config_has_mcp"])
            self.assertFalse(res["isolation_ok"])
            self.assertEqual(res["config_note"],
                             "no synthesized config artifact")


class McpAccountingTest(unittest.TestCase):
    def test_error_classes_and_counts(self):
        with tempfile.TemporaryDirectory() as t:
            _make_attempt(Path(t), mcp=True)
            acc = C.mcp_error_accounting(Path(t))
            self.assertEqual(acc["total_calls"], 2)
            self.assertEqual(acc["by_tool_status"],
                             {"ERROR": 1, "OK": 1})
            self.assertEqual(
                acc["error_classes"].get("govulncheck_missing"), 1)

    def test_classify_buckets(self):
        self.assertEqual(
            C.classify_tool_error("context canceled"), "context_canceled")
        self.assertEqual(
            C.classify_tool_error("govulncheck: exec not found"),
            "govulncheck_missing")
        self.assertEqual(
            C.classify_tool_error("go: updates to go.mod needed"),
            "go_mod_updates_needed")
        self.assertEqual(C.classify_tool_error("???"), "other")


if __name__ == "__main__":
    unittest.main()

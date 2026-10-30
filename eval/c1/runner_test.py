"""Unit tests for eval/c1/runner.py — controller artifacts and selection.

Run: /tmp/vexbench-agent-ctl/.venv/bin/python -m unittest eval.c1.runner_test -v
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from eval.c1 import runner  # noqa: E402
from eval.c1.assessment import DuplicateAttemptError  # noqa: E402


class FakeAgent:
    """Minimal harness-agent stand-in (extract_text/extract_stats contract)."""

    class _Stats:
        input_tokens = 10
        cached_input_tokens = 2
        output_tokens = 5
        reasoning_tokens = 3

    def extract_text(self, raw: str) -> str:
        texts = []
        for line in raw.splitlines():
            ev = json.loads(line)
            if ev.get("type") == "item.completed" and ev.get("item", {}).get(
                "type"
            ) == "agent_message":
                texts.append(ev["item"]["text"])
        return texts[-1].strip()

    def extract_stats(self, raw: str):
        return self._Stats()

    def result_filename(self) -> str:
        return "result.jsonl"


def make_run_dir(tmp: Path) -> Path:
    d = tmp / "exp" / "task-x" / "run_001"
    (d / "artifacts" / "izyan-audit").mkdir(parents=True)
    ev = {
        "type": "item.completed",
        "item": {"type": "agent_message", "text": '{"category":"uncertain","reasoning":"x"}'},
    }
    (d / "result.jsonl").write_text(json.dumps(ev) + "\n", "utf-8")
    (d / "artifacts" / "izyan-audit" / "tool_calls.jsonl").write_text(
        json.dumps(
            {
                "tool": "read_source",
                "args": {"file": "probe.go"},
                "duration_ms": 3,
                "observation": {
                    "id": "obs-1",
                    "tool_status": "OK",
                    "completeness": "COMPLETE",
                    "evidence_refs": ["sha256:abc"],
                },
            }
        )
        + "\n",
        "utf-8",
    )
    (d / "artifacts" / "export-report.json").write_text(
        json.dumps([{"name": "izyan-audit", "rc": 0, "exported": True}]), "utf-8"
    )
    return d


class TestControllerArtifacts(unittest.TestCase):
    def test_writes_spec_layout(self):
        with tempfile.TemporaryDirectory() as td:
            d = make_run_dir(Path(td))
            runner.write_controller_artifacts(d, FakeAgent(), 12.5)
            self.assertTrue((d / "raw_agent_output.txt").exists())
            self.assertTrue((d / "usage.json").exists())
            self.assertTrue((d / "tool_calls.jsonl").exists())
            obs = (d / "observations.jsonl").read_text()
            self.assertIn('"obs-1"', obs)
            self.assertIn("export-report.json", [p.name for p in d.iterdir()])
            usage = json.loads((d / "usage.json").read_text())
            self.assertEqual(usage["input_tokens"], 10)
            self.assertEqual(usage["wall_seconds"], 12.5)

    def test_never_overwrites(self):
        with tempfile.TemporaryDirectory() as td:
            d = make_run_dir(Path(td))
            runner.write_controller_artifacts(d, FakeAgent(), 1.0)
            with self.assertRaises(DuplicateAttemptError):
                runner.write_controller_artifacts(d, FakeAgent(), 1.0)

    def test_missing_audit_still_writes_text(self):
        with tempfile.TemporaryDirectory() as td:
            d = make_run_dir(Path(td))
            (d / "artifacts" / "izyan-audit" / "tool_calls.jsonl").unlink()
            runner.write_controller_artifacts(d, FakeAgent(), 1.0)
            self.assertTrue((d / "raw_agent_output.txt").exists())
            self.assertFalse((d / "tool_calls.jsonl").exists())


class TestSmokeSelection(unittest.TestCase):
    def _tasks(self):
        return [
            {"task_id": "t-vuln", "ground_truth_category": "vulnerable"},
            {"task_id": "t-cnr1", "ground_truth_category": "code_not_reachable"},
            {"task_id": "t-cnp", "ground_truth_category": "code_not_present"},
            {"task_id": "t-cnr2", "ground_truth_category": "code_not_reachable"},
            {"task_id": "t-conf", "ground_truth_category": "requires_configuration"},
        ]

    def test_picks_one_per_class(self):
        sel = runner.smoke_selection(self._tasks())
        self.assertEqual(set(sel), {"exploitable", "non_reachable", "configuration"})
        self.assertEqual(sel["exploitable"]["task_id"], "t-vuln")
        self.assertEqual(sel["non_reachable"]["task_id"], "t-cnr1")
        self.assertEqual(sel["configuration"]["task_id"], "t-conf")

    def test_missing_class_raises(self):
        tasks = [t for t in self._tasks() if t["ground_truth_category"] != "vulnerable"]
        with self.assertRaises(RuntimeError):
            runner.smoke_selection(tasks)


if __name__ == "__main__":
    unittest.main()

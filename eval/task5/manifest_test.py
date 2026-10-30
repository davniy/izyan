"""Unit tests for eval/task5/manifest.py — required-field completeness.

Run: /tmp/vexbench-agent-ctl/.venv/bin/python -m unittest eval.task5.manifest_test -v
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from eval.task5 import manifest as M  # noqa: E402

REPO = Path(__file__).resolve().parents[2]


def _write_tasks(td: Path) -> Path:
    p = td / "tasks.jsonl"
    p.write_text("\n".join(
        json.dumps({
            "task_id": f"o-r-abc1234-CVE-2020-{i:05d}",
            "cve_id": f"CVE-2020-{i:05d}",
            "ground_truth": "exploitable" if i == 0 else "not_exploitable",
            "ground_truth_category": "vulnerable" if i == 0
            else "code_not_reachable",
            "repo_url": "https://github.com/o/r",
            "commit_sha": "abc1234" + "0" * 33,
            "metadata": {"language": "go"},
        }) for i in range(3)) + "\n")
    return p


def _write_acq(td: Path) -> Path:
    p = td / "acquisition.json"
    p.write_text(json.dumps({
        "dataset": {"pin": "testpin"},
        "snapshots": {
            "o/r/abc1234" + "0" * 33: {"content_hash": "deadbeef"},
        },
    }))
    return p


def _fake_harness(td: Path) -> Path:
    """Minimal harness-shaped tree for hashing (no docker, no agents)."""
    h = td / "harness"
    for rel in M._HARNESS_SCORING_FILES + M._HARNESS_ARM_FILES:
        f = h / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(f"# {rel}\n")
    # opencode_c1.py must show mcp only under OpenCodeC1Agent._extend_config
    (h / "src/evaluate/agents/opencode_c1.py").write_text(
        "class OpenCodeB1PrimeAgent:\n"
        "    def _extend_config(self, base, ctx, cve_id):\n"
        "        pass\n"
        "class OpenCodeC1Agent(OpenCodeB1PrimeAgent):\n"
        "    def _extend_config(self, base, ctx, cve_id):\n"
        '        base["mcp"] = {"izyan": {}}\n')
    tool_bin = h / "docker/bin/izyan-evidence-tools"
    tool_bin.parent.mkdir(parents=True, exist_ok=True)
    tool_bin.write_bytes(b"fake-binary")
    return h


def _git_init(path: Path) -> None:
    for cmd in (["init", "-q"], ["config", "user.email", "t@t"],
                ["config", "user.name", "t"], ["add", "-A"],
                ["commit", "-qm", "init", "--allow-empty"]):
        subprocess.run(["git", "-C", str(path), *cmd],
                       check=True, capture_output=True)


class ArmRootLayoutTest(unittest.TestCase):
    def test_harness_layout(self):
        prompts = {"vuln_safety_v1": {"sha256_12": "14c1396c9094"}}
        root = M.arm_run_root(
            Path("/tmp/res"), "p1", layout="harness",
            experiment_id="task5", prompts=prompts, model="m")
        self.assertEqual(
            root,
            Path("/tmp/res/p1/14c1396c9094/opencode-b1p/m"))

    def test_controller_layout(self):
        root = M.arm_run_root(
            Path("/tmp/res"), "t1", layout="controller",
            experiment_id="task5-smoke", prompts={}, model="m")
        self.assertEqual(
            root, Path("/tmp/res/t1/task5-smoke"))

    def test_bad_layout_rejected(self):
        with self.assertRaises(M.ManifestError):
            M.arm_run_root(Path("/x"), "p1", layout="weird",
                           experiment_id="e", prompts={}, model="m")


class BuildManifestTest(unittest.TestCase):
    """Hermetic build: fake harness/worktree trees, no docker probes."""

    def _build(self, td: Path):
        harness = _fake_harness(td)
        _git_init(harness)
        worktree = td / "wt"
        # minimal required files BEFORE the git init commit
        for rel in ("eval/task5/harness/vexbench-agent-ctl-task5.patch",
                    "eval/c1/harness/vexbench-agent-ctl-c1.patch"):
            f = worktree / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text("patch-bytes")
        svc = worktree / "internal/evidencetools/service.go"
        svc.parent.mkdir(parents=True, exist_ok=True)
        svc.write_text('const AdapterVersion = "izyan-evidence-tools/0.1.0"')
        _git_init(worktree)
        tasks = _write_tasks(td)
        acq = _write_acq(td)
        return M.build_manifest(
            worktree=worktree, harness_dir=harness,
            tasks_path=tasks, repos_dir=td, acquisition_path=acq,
            results_root=td / "results", model="qwen3.6-35b",
            timeout=900, repeats=3, parallel=1, probe_docker=False)

    def test_required_fields_complete(self):
        with tempfile.TemporaryDirectory() as t:
            m = self._build(Path(t))
            violations = M.validate_manifest(m)
            self.assertEqual(violations, [])

    def test_missing_field_is_a_violation(self):
        with tempfile.TemporaryDirectory() as t:
            m = self._build(Path(t))
            del m["arms"]["p1"]["agent"]
            self.assertTrue(any("arms.p1.agent" in v
                                for v in M.validate_manifest(m)))
            m2 = self._build(Path(t))
            m2["arms"]["t1"]["mcp"] = False
            self.assertTrue(any("t1.mcp" in v
                                for v in M.validate_manifest(m2)))

    def test_arm_bindings_and_policy(self):
        with tempfile.TemporaryDirectory() as t:
            m = self._build(Path(t))
            self.assertFalse(m["arms"]["p1"]["mcp"])
            self.assertTrue(m["arms"]["t1"]["mcp"])
            self.assertEqual(m["attempt_policy"]["repeats"], 3)
            self.assertEqual(m["attempt_policy"]["retries"], 0)
            self.assertEqual(m["attempt_policy"]["cache_admission"],
                             "forbidden")
            self.assertEqual(m["arms"]["p1"]["agent"], "opencode-b1p")
            self.assertEqual(m["arms"]["t1"]["agent"], "opencode-c1")
            self.assertIn("results/p1/14c1396c9094/opencode-b1p/",
                          m["arms"]["p1"]["run_root"])
            self.assertIn("results/t1/5d6c640c6945/opencode-c1/",
                          m["arms"]["t1"]["run_root"])

    def test_docker_disabled_keeps_nulls(self):
        with tempfile.TemporaryDirectory() as t:
            m = self._build(Path(t))
            self.assertEqual(m["images"], {})
            self.assertIsNone(m["toolchain"]["go"])
            self.assertIsNone(
                m["tools_binary"]["tools_list_sha256"])
            self.assertTrue(m["limitations"])

    def test_verify_frozen_inputs_detects_drift(self):
        with tempfile.TemporaryDirectory() as t:
            td = Path(t)
            m = self._build(td)
            tasks = td / "tasks.jsonl"
            acq = td / "acquisition.json"
            self.assertEqual(
                M.verify_frozen_inputs(
                    m, tasks_path=tasks, acquisition_path=acq), [])
            acq.write_text(json.dumps({"changed": True}))
            problems = M.verify_frozen_inputs(
                m, tasks_path=tasks, acquisition_path=acq)
            self.assertEqual(len(problems), 1)
            self.assertIn("acquisition", problems[0])


if __name__ == "__main__":
    unittest.main()

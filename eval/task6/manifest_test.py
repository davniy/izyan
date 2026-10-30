"""Unit tests for eval/task6/manifest.py — required-field completeness
and the Task-6 additions (contract hashes, arm bindings, dataset pin).

Run: $HARNESS/.venv/bin/python -m unittest eval.task6.manifest_test -v
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from eval.task6 import manifest as M  # noqa: E402

REPO = Path(__file__).resolve().parents[2]


def _write_tasks(td: Path) -> Path:
    p = td / "tasks.jsonl"
    p.write_text("\n".join(
        json.dumps({
            "task_id": f"synthetic-case-{i}",
            "cve_id": f"ADVISORY-2020-{i:05d}",
            "ground_truth": "exploitable" if i == 0 else "not_exploitable",
            "ground_truth_category": "vulnerable" if i == 0
            else "code_not_reachable",
            "repo_url": "https://example.invalid/o/r",
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
        prompts = {"vuln_safety_v2": {"sha256_12": "d0e7d6ab7a9a"}}
        root = M.arm_run_root(
            Path("/tmp/res"), "p2", layout="harness",
            experiment_id="task6", prompts=prompts, model="m")
        self.assertEqual(
            root,
            Path("/tmp/res/p2/d0e7d6ab7a9a/opencode-b1p/m"))

    def test_controller_layout(self):
        root = M.arm_run_root(
            Path("/tmp/res"), "t2", layout="controller",
            experiment_id="task6-smoke", prompts={}, model="m")
        self.assertEqual(root, Path("/tmp/res/t2/task6-smoke"))

    def test_unknown_layout_rejected(self):
        with self.assertRaises(M.ManifestError):
            M.arm_run_root(Path("/r"), "p2", layout="weird",
                           experiment_id="e", prompts={}, model="m")


class ArmDefinitionTest(unittest.TestCase):
    def test_p2_and_t2_bindings(self):
        self.assertEqual(M.ARMS["p2"]["agent"], "opencode-b1p")
        self.assertEqual(M.ARMS["p2"]["prompt"], "vuln_safety_v2")
        self.assertFalse(M.ARMS["p2"]["mcp"])
        self.assertEqual(M.ARMS["t2"]["agent"], "opencode-c1")
        self.assertEqual(M.ARMS["t2"]["prompt"], "vuln_safety_v2_tools")
        self.assertTrue(M.ARMS["t2"]["mcp"])

    def test_projection_arms_map_to_raw_arms(self):
        self.assertEqual(M.PROJECTION_ARMS, {"v_p2": "p2", "v_t2": "t2"})

    def test_no_task5_arms(self):
        for gone in ("p0", "p1", "t1"):
            self.assertNotIn(gone, M.ARMS)


class BuildManifestTest(unittest.TestCase):
    def _build(self, td: Path):
        tasks = _write_tasks(td)
        acq = _write_acq(td)
        harness = _fake_harness(td)
        _git_init(harness)
        return M.build_manifest(
            worktree=REPO,
            harness_dir=harness,
            tasks_path=tasks,
            repos_dir=td / "repos",
            acquisition_path=acq,
            results_root=td / "results",
            model="qwen3.6-35b",
            timeout=900, repeats=3, parallel=1,
            probe_docker=False)

    def test_complete_manifest_validates(self):
        with tempfile.TemporaryDirectory() as t:
            m = self._build(Path(t))
            self.assertEqual(M.validate_manifest(m), [])
            self.assertEqual(m["schema"], "task6-manifest/1")
            self.assertEqual(m["experiment_id"], "task6")
            self.assertEqual(m["attempt_policy"]["timeout_seconds"], 900)
            self.assertEqual(m["attempt_policy"]["repeats"], 3)
            self.assertEqual(m["attempt_policy"]["parallel"], 1)
            self.assertEqual(m["attempt_policy"]["retries"], 0)
            self.assertEqual(m["model"]["id"], "qwen3.6-35b")

    def test_contract_block_pins_schema_and_validator(self):
        with tempfile.TemporaryDirectory() as t:
            m = self._build(Path(t))
            c = m["contract"]
            self.assertEqual(c["assessment_schema"], "agent-assessment/2")
            self.assertEqual(c["validator"], "task6-validator/1")
            import hashlib
            exp_asm = hashlib.sha256(
                (REPO / "eval/task6/assessment_v2.py").read_bytes()
            ).hexdigest()
            exp_val = hashlib.sha256(
                (REPO / "eval/task6/validator.py").read_bytes()
            ).hexdigest()
            self.assertEqual(c["schema_file_sha256"], exp_asm)
            self.assertEqual(c["validator_file_sha256"], exp_val)
            # and they also ride in the controller-files hash map
            cf = m["izyan"]["controller_files_sha256"]
            self.assertEqual(
                cf["eval/task6/assessment_v2.py"], exp_asm)
            self.assertEqual(
                cf["eval/task6/validator.py"], exp_val)

    def test_arms_carry_prompt_hashes_and_run_roots(self):
        with tempfile.TemporaryDirectory() as t:
            m = self._build(Path(t))
            for arm in ("p2", "t2"):
                spec = m["arms"][arm]
                self.assertEqual(
                    spec["prompt_sha256_12"],
                    m["prompts"][spec["prompt"]]["sha256_12"])
                self.assertIn(f"/{arm}/", spec["run_root"])
                self.assertIn("/qwen3.6-35b", spec["run_root"])
            self.assertNotEqual(
                m["arms"]["p2"]["prompt_sha256_12"],
                m["arms"]["t2"]["prompt_sha256_12"])

    def test_dataset_pin_flagged_for_unpinned_tasks(self):
        with tempfile.TemporaryDirectory() as t:
            m = self._build(Path(t))
            # synthetic tasks ≠ the pinned 30-task dataset — recorded,
            # never silently passed
            self.assertFalse(m["dataset"]["sha256_matches_pin"])
            self.assertTrue(any("pinned dataset sha" in l
                                for l in m["limitations"]))
            self.assertTrue(any(
                "dataset" in v for v in
                M.validate_manifest(m, strict_dataset_pin=True)))
            self.assertEqual(m["dataset"]["expected_tasks_sha256"],
                             M.EXPECTED_DATASET_SHA256)

    def test_no_docker_probe_records_limitation(self):
        with tempfile.TemporaryDirectory() as t:
            m = self._build(Path(t))
            self.assertTrue(any("docker probes disabled" in l
                                for l in m["limitations"]))
            self.assertEqual(m["images"], {})
            self.assertIsNone(
                m["tools_binary"]["tools_list_sha256"])

    def test_manifest_roundtrips(self):
        with tempfile.TemporaryDirectory() as t:
            td = Path(t)
            m = self._build(td)
            dest = M.write_manifest(m, td / "experiment-manifest.json")
            back = M.load_manifest(dest)
            self.assertEqual(back["schema"], "task6-manifest/1")
            self.assertEqual(
                back["contract"]["validator_file_sha256"],
                m["contract"]["validator_file_sha256"])
            wrong = td / "wrong-schema.json"
            wrong.write_text(json.dumps({"schema": "other/1"}))
            with self.assertRaises(M.ManifestError):
                M.load_manifest(wrong)

    def test_verify_frozen_inputs_catches_drift(self):
        with tempfile.TemporaryDirectory() as t:
            td = Path(t)
            tasks = _write_tasks(td)
            acq = _write_acq(td)
            m = {"dataset": {
                "tasks_sha256": M._sha256_file(tasks),
                "acquisition_sha256": M._sha256_file(acq)}}
            self.assertEqual(
                M.verify_frozen_inputs(
                    m, tasks_path=tasks, acquisition_path=acq), [])
            tasks.write_text(tasks.read_text() + "# drift\n")
            self.assertTrue(M.verify_frozen_inputs(
                m, tasks_path=tasks, acquisition_path=acq))


class ValidateManifestTest(unittest.TestCase):
    def test_missing_fields_listed(self):
        violations = M.validate_manifest({})
        self.assertTrue(violations)
        self.assertTrue(any("contract.validator_file_sha256" in v
                            for v in violations))
        self.assertTrue(any("arms.p2" in v for v in violations))

    def test_mcp_flags_enforced(self):
        m = {
            "arms": {"p2": {"mcp": True, "repeats": 3},
                     "t2": {"mcp": False, "repeats": 3}},
            "attempt_policy": {"repeats": 3},
            "prompts": {"vuln_safety_v2": {"sha256_12": "a"},
                        "vuln_safety_v2_tools": {"sha256_12": "b"}},
        }
        violations = M.validate_manifest(m)
        self.assertTrue(any("p2.mcp must be false" in v
                            for v in violations))
        self.assertTrue(any("t2.mcp must be true" in v
                            for v in violations))


if __name__ == "__main__":
    unittest.main()

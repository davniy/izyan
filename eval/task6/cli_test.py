"""Command-level tests for eval/vexbench_task6.py — synthetic fixtures.

Run: $HARNESS/.venv/bin/python -m unittest eval.task6.cli_test -v

Every fixture is synthetic — no real VEX-Bench runs, no harness, no
docker, no model calls. The replay/report seams are stubbed so these
tests exercise only the controller glue (arg parsing, arm validation,
snapshot-dir mapping).
"""

import argparse
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from eval import vexbench_task6 as C  # noqa: E402
from eval.task6 import manifest as manifest_mod  # noqa: E402

TASK_ID = "o-r-abc1234-ADVISORY-0000-1"


def _write_manifest(root: Path) -> Path:
    tasks_p = root / "tasks.jsonl"
    tasks_p.write_text(json.dumps({
        "task_id": TASK_ID,
        "cve_id": "ADVISORY-0000-1",
        "repo_url": "https://example.invalid/o/r",
        "commit_sha": "abc1234",
    }) + "\n", encoding="utf-8")
    acq_p = root / "acquisition.json"
    acq_p.write_text(json.dumps({"snapshots": {}}), encoding="utf-8")
    manifest_p = root / "manifest.json"
    manifest_p.write_text(json.dumps({
        "schema": manifest_mod.MANIFEST_SCHEMA,
        "experiment_id": "task6-cli-test",
        "dataset": {"tasks_file": str(tasks_p),
                    "acquisition_file": str(acq_p)},
        "arms": {"p2": {"run_root": str(root / "runs" / "p2")}},
    }), encoding="utf-8")
    return manifest_p


def _args(**kw):
    base = dict(manifest="", arms="p2", scoring="",
                advisories_dir=None, repos_dir=None)
    base.update(kw)
    return argparse.Namespace(**base)


class CmdReplayTest(unittest.TestCase):
    def test_arms_parsed_and_forwarded(self):
        """N1 regression: cmd_replay must define `arms` and forward the
        validated raw-arm list — a NameError here broke every real
        invocation."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            manifest = _write_manifest(root)
            fake_replay = mock.Mock(return_value={
                "v_p2": {"n_attempts": 0, "n_blocked": 0,
                         "decision_counts": {}}})
            with mock.patch.object(
                    C.replay_mod, "replay_arms", fake_replay), \
                 mock.patch.object(
                    C.report_mod, "write_scoring_artifacts",
                    return_value={
                        "matrix": root / "scoring" / "matrix.json"}):
                rc = C.cmd_replay(_args(
                    manifest=str(manifest),
                    scoring=str(root / "scoring"),
                    arms="p2"))
            self.assertEqual(rc, 0)
            kw = fake_replay.call_args.kwargs
            self.assertEqual(kw["arms"], ["p2"])
            self.assertIsNone(kw["snapshot_dir_by_task"])

    def test_arms_list_split_and_validated(self):
        """Comma list is stripped/validated; each arm must be a raw
        arm (manifest_mod.ARMS), not a v_ projection."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            manifest = _write_manifest(root)
            with self.assertRaises(SystemExit):
                C.cmd_replay(_args(
                    manifest=str(manifest),
                    scoring=str(root / "scoring"),
                    arms="bogus"))
            with self.assertRaises(SystemExit):
                C.cmd_replay(_args(
                    manifest=str(manifest),
                    scoring=str(root / "scoring"),
                    arms="v_p2"))

    def test_repos_dir_maps_snapshot_dirs(self):
        """--repos-dir maps task_id → product snapshot dir (the C1 file
        index source); absent → snapshot_dir_by_task stays None."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            manifest = _write_manifest(root)
            snap = root / "repos" / "o" / "r" / "abc1234"
            fake_replay = mock.Mock(return_value={
                "v_p2": {"n_attempts": 0, "n_blocked": 0,
                         "decision_counts": {}}})
            with mock.patch.object(
                    C.runner, "task_snapshot_dir",
                    return_value=snap), \
                 mock.patch.object(
                    C.replay_mod, "replay_arms", fake_replay), \
                 mock.patch.object(
                    C.report_mod, "write_scoring_artifacts",
                    return_value={
                        "matrix": root / "scoring" / "matrix.json"}):
                rc = C.cmd_replay(_args(
                    manifest=str(manifest),
                    scoring=str(root / "scoring"),
                    arms="p2", repos_dir=str(root / "repos")))
            self.assertEqual(rc, 0)
            kw = fake_replay.call_args.kwargs
            self.assertEqual(kw["snapshot_dir_by_task"],
                             {TASK_ID: snap})


if __name__ == "__main__":
    unittest.main()

"""Frozen experiment manifest for Task 4 C1 (plan §4 step 6 / spec §8.1).

Written AFTER the smoke battery: every version/hash that can change the
comparison is pinned — izyan/adapter commits, harness diff, tool binary,
prompt hashes, image IDs + toolchain, model/reasoning effort, task list and
snapshot content hashes, parser/scorer hashes, controller module hashes and
the immutable attempt policy.

The manifest is produced by real probes (git, docker, sha256); nothing is
hand-copied. Where a fact is unknowable (model_revision) the value stays
``None`` — never invented (plan §1.4).
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from . import protocol

MANIFEST_SCHEMA = "c1-manifest/1"

# Harness files whose bytes define the official scoring path for C1.
_HARNESS_SCORING_FILES = [
    "src/evaluate/result_parser.py",
    "src/evaluate/parse.py",
    "src/evaluate/metrics.py",
]
# Controller modules whose bytes define the C1 protocol implementation.
_CONTROLLER_FILES = [
    "eval/c1/assessment.py",
    "eval/c1/status.py",
    "eval/c1/collect.py",
    "eval/c1/protocol.py",
    "eval/c1/runner.py",
    "eval/c1/synthetic.py",
    "eval/c1/manifest.py",
]
_PROMPT_FILES = [
    "eval/vexbench-prompts/vuln_assess-c45dfc39af34.txt",
    "eval/vexbench-prompts/vuln_c1-6eda998ea66c.txt",
    "eval/vexbench-prompts/official-vuln-c0a5c8458b77.txt",
]


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True, text=True, check=True,
    ).stdout.strip()


def _docker_json(image: str, fmt: str) -> str:
    return subprocess.run(
        ["docker", "image", "inspect", image, "--format", fmt],
        capture_output=True, text=True, check=True,
    ).stdout.strip()


def _docker_run_stdout(image: str, cmd: list[str], entrypoint: str) -> str:
    cp = subprocess.run(
        ["docker", "run", "--rm", "--entrypoint", entrypoint, image, *cmd],
        capture_output=True, text=True, timeout=120,
    )
    return (cp.stdout or cp.stderr).strip()


def _file_hashes(root: Path, rels: list[str]) -> dict[str, str]:
    return {r: _sha256_file(root / r) for r in rels}


def build_manifest(
    *,
    worktree: Path,
    harness_dir: Path,
    tasks_path: Path,
    repos_dir: Path,
    acquisition_path: Path,
    results_root: Path,
    smoke_dir: Optional[Path] = None,
) -> dict:
    """Collect the full frozen manifest. All paths are probed, not assumed."""
    worktree = Path(worktree)
    harness_dir = Path(harness_dir)

    izyan_head = _git(worktree, "rev-parse", "HEAD")
    izyan_dirty = bool(_git(worktree, "status", "--porcelain"))
    harness_head = _git(harness_dir, "rev-parse", "HEAD")
    harness_dirty = _git(harness_dir, "status", "--porcelain")

    tasks = [
        json.loads(l)
        for l in Path(tasks_path).read_text(encoding="utf-8").splitlines()
        if l.strip()
    ]
    acq = json.loads(Path(acquisition_path).read_text(encoding="utf-8"))
    snapshots = acq.get("snapshots", {})

    go_toolchain = _docker_run_stdout("vex-bench-go-codex-c1:latest", ["version"], "go")
    codex_ver = _docker_run_stdout(
        "vex-bench-go-codex-c1:latest", ["--version"], "codex"
    )

    prompts: dict[str, dict] = {}
    for name in ("vuln_assess", "vuln_c1"):
        text = protocol.build_prompt(name)
        prompts[name] = {
            "sha256_12": protocol.prompt_hash(text),
            "sha256": hashlib.sha256(text.encode()).hexdigest(),
        }
    official_text = (worktree / "eval/vexbench-prompts/official-vuln-c0a5c8458b77.txt").read_text()
    prompts["vuln_official_frozen"] = {
        "sha256_12": protocol.prompt_hash(official_text.strip()),
        "sha256": hashlib.sha256(official_text.strip().encode()).hexdigest(),
    }

    stamp = {}
    stamp_path = harness_dir / "docker" / "c1-image.stamp"
    if stamp_path.exists():
        for line in stamp_path.read_text().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                stamp[k] = v

    manifest = {
        "schema": MANIFEST_SCHEMA,
        "frozen_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "izyan": {
            "worktree": str(worktree),
            "commit": izyan_head,
            "dirty": izyan_dirty,
            "tool_adapter_version": _tool_adapter_version(worktree),
            "controller_files_sha256": _file_hashes(worktree, _CONTROLLER_FILES),
            "prompt_files_sha256": _file_hashes(worktree, _PROMPT_FILES),
        },
        "harness": {
            "dir": str(harness_dir),
            "commit": harness_head,
            "dirty_files": harness_dirty.splitlines(),
            "patch_file": "eval/c1/harness/vexbench-agent-ctl-c1.patch",
            "patch_sha256": _sha256_file(
                worktree / "eval/c1/harness/vexbench-agent-ctl-c1.patch"
            ),
            "scoring_files_sha256": _file_hashes(harness_dir, _HARNESS_SCORING_FILES),
        },
        "tools_binary": {
            "path": "docker/bin/izyan-evidence-tools",
            "sha256": stamp.get("binary_sha256")
            or _sha256_file(harness_dir / "docker/bin/izyan-evidence-tools"),
            "adapter_version": _tool_adapter_version(worktree),
        },
        "images": {
            "c1": {
                "tag": "vex-bench-go-codex-c1:latest",
                "id": _docker_json("vex-bench-go-codex-c1:latest", "{{.Id}}"),
                "arch": _docker_json(
                    "vex-bench-go-codex-c1:latest", "{{.Os}}/{{.Architecture}}"
                ),
            },
            "b1_base": {
                "tag": "vex-bench-go-codex:latest",
                "id": _docker_json("vex-bench-go-codex:latest", "{{.Id}}"),
            },
        },
        "toolchain": {
            "go": go_toolchain,
            "codex_cli": codex_ver,
        },
        "model": {
            "id": "gpt-6.1-sol",
            "provider": "localproxy (wire_api=responses)",
            "model_revision": None,  # not exposed by the provider; stays null
            "reasoning_effort": "medium",
        },
        "prompts": prompts,
        "attempt_policy": {
            "timeout_seconds": 900,
            "repeats": 3,
            "parallel": 1,
            "retries": 0,
            "cache_admission": "forbidden",
            "note": (
                "B1 launch params restored from Task 3 launch provenance "
                "(session 2026-10-06): --timeout 900 --repeats 3 --parallel 1 "
                "--model gpt-6.1-sol; identical for B1'/C1."
            ),
        },
        "comparator": {
            "primary": "B1'",
            "primary_profile": "codex-b1p",
            "primary_prompt": "vuln_assess",
            "primary_prompt_hash": prompts["vuln_assess"]["sha256_12"],
            "primary_image": "vex-bench-go-codex:latest",
            "anchor_b1": {
                "experiment_dir": "/tmp/vexbench-plain/full/results/"
                "c0a5c8458b77/codex/gpt-6.1-sol",
                "prompt_hash": "c0a5c8458b77",
                "freeze_checksums": "/tmp/vexbench-plain/full/report/"
                "freeze-checksums.json",
                "note": "frozen historical anchor; NOT recomputed for C1",
            },
            "decision": (
                "B1' is the primary comparator (plan §1.5): the shared "
                "structured-assessment output block and full capture are new "
                "to both arms; frozen B1 stays the drift anchor."
            ),
        },
        "dataset": {
            "tasks_file": str(tasks_path),
            "tasks_sha256": _sha256_file(tasks_path),
            "task_count": len(tasks),
            "task_ids": [t["task_id"] for t in tasks],
            "acquisition_file": str(acquisition_path),
            "acquisition_sha256": _sha256_file(acquisition_path),
            "dataset_pin": acq.get("dataset", {}).get("pin"),
            "repos_dir": str(repos_dir),
            "snapshot_hashes": {
                k: v.get("content_hash")
                for k, v in sorted(snapshots.items())
                if isinstance(v, dict)
            },
        },
        "protocol": {
            "output_contract": (
                "single JSON object on stdout; category/reasoning top-level; "
                "extra fields ignored by the unchanged official parser"
            ),
            "assessment_schema": "agent-assessment/1",
            "status_schema": "attempt-status/1",
            "attempt_key": "(experiment_id, task_id, run_NNN)",
            "attempt_layout": "<results_root>/<experiment_id>/<task_id>/<attempt_id>/",
            "audit_sink": "artifacts/izyan-audit/tool_calls.jsonl",
            "mcp_transport": "stdio inside the attempt container",
        },
        "results_root": str(results_root),
        "smoke": {
            "experiment_id": "c1-smoke",
            "dir": str(smoke_dir) if smoke_dir else None,
        },
    }
    return manifest


def _tool_adapter_version(worktree: Path) -> str:
    """AdapterVersion constant from internal/evidencetools/service.go."""
    import re

    src = (worktree / "internal/evidencetools/service.go").read_text()
    m = re.search(r'AdapterVersion\s*=\s*"([^"]+)"', src)
    return m.group(1) if m else "unknown"


def write_manifest(manifest: dict, dest: Path) -> Path:
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return dest

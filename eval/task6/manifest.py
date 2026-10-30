"""Frozen experiment manifest for Task 6 (plan §5, §15 ``manifest``).

Same shape as ``eval/task5/manifest.py`` — extended for the structured
evidence contract:

- arms are ``p2`` (``opencode-b1p`` + ``vuln_safety_v2``, no MCP) and
  ``t2`` (``opencode-c1`` + ``vuln_safety_v2_tools``, izyan MCP).  Task-5
  P1/T1 stay historical references recorded read-only under
  ``historical`` — never re-run, never scored here.
- the schema/validator contract is pinned: ``assessment_v2.py`` and
  ``validator.py`` byte hashes ride inside
  ``izyan.controller_files_sha256`` AND in an explicit
  ``contract.schema_file_sha256`` / ``contract.validator_file_sha256``
  pair, plus the ``agent-assessment/2`` schema id and
  ``task6-validator/1`` version.
- the dataset pin is asserted: ``vex_bench.jsonl`` must hash to
  EXPECTED_DATASET_SHA256 (plan §2) or the manifest records a violation.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Optional, Sequence

from eval.c1 import manifest as c1_manifest
from eval.task5 import manifest as t5_manifest
from . import protocol

MANIFEST_SCHEMA = "task6-manifest/1"

EXPERIMENT_ID = "task6"
EXPERIMENT_SMOKE = "task6-smoke"

# The pinned development dataset (plan §2/§5): 30 Go tasks.
EXPECTED_DATASET_SHA256 = (
    "60b55373031dca97009d2e89ef8dfdf0ba083f9ce1035470fdf46f0da15384b3")

# Harness file sets are identical to Task 5 (same scoring path, same
# adapter split; only the registered prompt names differ).
_HARNESS_SCORING_FILES = t5_manifest._HARNESS_SCORING_FILES
_HARNESS_ARM_FILES = t5_manifest._HARNESS_ARM_FILES

# Controller modules whose bytes define the Task 6 glue + reused core.
_CONTROLLER_FILES = [
    "eval/task6/protocol.py",
    "eval/task6/assessment_v2.py",
    "eval/task6/validator.py",
    "eval/task6/manifest.py",
    "eval/task6/collect.py",
    "eval/task6/replay.py",
    "eval/task6/report.py",
    "eval/task6/freeze.py",
    "eval/c1/assessment.py",
    "eval/c1/status.py",
    "eval/c1/collect.py",
    "eval/c1/parser_audit.py",
    "eval/c1/runner.py",
    "eval/c1/report.py",
]
_SPEC_FILES = [
    "docs/dev/specs/2026-10-09-task6-structured-evidence-experiment.md",
]
_PLAN_FILES = [
    "docs/dev/plans/2026-10-09-task6-structured-evidence-implementation-plan.md",
]
_HISTORICAL_REFERENCE_DOCS = [
    "eval/task5/gate-feasibility.md",
    "eval/task5/scoring/safety-report.md",
    "eval/task5/decision.md",
    "eval/task6/freeze/task5-reference.json",
]
_PROMPT_FILES = [
    "eval/task6/prompts/vuln_safety_v2.txt",
    "eval/task6/prompts/vuln_safety_v2_tools.txt",
    "eval/task6/prompts/hashes.json",
    "eval/task6/prompts/p2-t2.diff",
    "eval/vexbench-prompts/official-vuln-c0a5c8458b77.txt",
]

# Arm bindings (plan §2): P2 is the prompt-only arm, T2 adds the same
# 31 izyan MCP tools under the SAME prompt/schema.  The only treatment
# difference is the tool block + MCP availability.
ARMS: dict[str, dict] = {
    "p2": {
        "role": "structured_assessment_no_mcp",
        "agent": "opencode-b1p",
        "prompt": "vuln_safety_v2",
        "image_suffix": "opencode-gw",
        "mcp": False,
    },
    "t2": {
        "role": "structured_assessment_plus_mcp",
        "agent": "opencode-c1",
        "prompt": "vuln_safety_v2_tools",
        "image_suffix": "opencode-c1",
        "mcp": True,
    },
}
# Validator-adjusted offline projections (plan §11) — derived arms,
# never run: V-P2/V-T2 replay the saved P2/T2 answers through
# validator.validate_attempt.
PROJECTION_ARMS: dict[str, str] = {"v_p2": "p2", "v_t2": "t2"}
ARM_ORDER = ("p2", "t2")


class ManifestError(RuntimeError):
    pass


_sha256_file = t5_manifest._sha256_file
_file_hashes = t5_manifest._file_hashes
_docker_probe_image = t5_manifest._docker_probe_image
_docker_probe_cmd = t5_manifest._docker_probe_cmd
_probe_mcp_catalog = t5_manifest._probe_mcp_catalog


def arm_run_root(results_root: Path, arm: str, *, layout: str,
                 experiment_id: str, prompts: dict, model: str) -> Path:
    """Model-level dir the official parser iterates over — same
    convention as Task 5 (``<results_root>/<arm>/<prompt_hash>/<agent>/
    <model>`` for harness layout, ``<arm>/<experiment_id>`` for
    controller layout)."""
    arm_root = Path(results_root) / arm
    if layout == "harness":
        spec = ARMS[arm]
        return (arm_root / prompts[spec["prompt"]]["sha256_12"]
                / spec["agent"] / model)
    if layout == "controller":
        return arm_root / experiment_id
    raise ManifestError(f"unknown layout {layout!r}")


def build_manifest(
    *,
    worktree: Path,
    harness_dir: Path,
    tasks_path: Path,
    repos_dir: Path,
    acquisition_path: Path,
    results_root: Path,
    model: str,
    timeout: int,
    repeats: int,
    parallel: int,
    layout: str = "harness",
    experiment_id: str = EXPERIMENT_ID,
    probe_docker: bool = True,
) -> dict:
    """Collect the frozen Task 6 manifest. All paths probed, not assumed."""
    worktree = Path(worktree)
    harness_dir = Path(harness_dir)
    limitations: list[str] = []

    izyan_head = c1_manifest._git(worktree, "rev-parse", "HEAD")
    izyan_dirty = bool(c1_manifest._git(worktree, "status", "--porcelain"))
    harness_head = c1_manifest._git(harness_dir, "rev-parse", "HEAD")
    harness_dirty = c1_manifest._git(harness_dir, "status", "--porcelain")

    tasks = [
        json.loads(l)
        for l in Path(tasks_path).read_text(encoding="utf-8").splitlines()
        if l.strip()
    ]
    acq = json.loads(Path(acquisition_path).read_text(encoding="utf-8"))
    snapshots = acq.get("snapshots", {})

    tasks_sha = _sha256_file(tasks_path)
    dataset_sha_matches_pin = tasks_sha == EXPECTED_DATASET_SHA256
    if not dataset_sha_matches_pin:
        limitations.append(
            f"tasks file sha256 {tasks_sha[:16]}… != pinned dataset sha "
            f"{EXPECTED_DATASET_SHA256[:16]}… — a different task list "
            "changes the denominator, do not score (plan §2)")

    spec_hashes = _file_hashes(worktree, _SPEC_FILES, missing_ok=True)
    plan_hashes = _file_hashes(worktree, _PLAN_FILES, missing_ok=True)

    p2 = protocol.build_prompt(protocol.PROMPT_P2)
    t2 = protocol.build_prompt(protocol.PROMPT_T2)
    protocol.assert_prompt_contract(p2, t2)
    prompts = {
        protocol.PROMPT_P2: {
            "sha256_12": protocol.prompt_hash(p2),
            "sha256": hashlib.sha256(p2.encode()).hexdigest(),
            "bytes": len(p2.encode()),
        },
        protocol.PROMPT_T2: {
            "sha256_12": protocol.prompt_hash(t2),
            "sha256": hashlib.sha256(t2.encode()).hexdigest(),
            "bytes": len(t2.encode()),
        },
        "vuln_official_frozen": {
            "sha256_12": protocol.FROZEN_OFFICIAL_SHA256[:12],
            "sha256": protocol.FROZEN_OFFICIAL_SHA256,
        },
    }

    stamp: dict[str, str] = {}
    stamp_path = harness_dir / "docker" / "c1-image.stamp"
    if stamp_path.exists():
        for line in stamp_path.read_text().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                stamp[k] = v

    t6_patch_file = "eval/task6/harness/vexbench-agent-ctl-task6.patch"
    t5_patch_file = "eval/task5/harness/vexbench-agent-ctl-task5.patch"
    c1_patch_file = "eval/c1/harness/vexbench-agent-ctl-c1.patch"

    # P2 admission guard (plan §3): the plain arm's effective config
    # must carry no top-level ``mcp`` — same static check Task 5 does.
    agent_src = (harness_dir / "src/evaluate/agents/opencode_c1.py"
                 ).read_text(encoding="utf-8")
    if 'base["mcp"]' not in agent_src.split("class OpenCodeC1Agent")[-1]:
        limitations.append(
            "could not statically confirm mcp is added ONLY by "
            "OpenCodeC1Agent._extend_config — verify synthesized "
            "opencode-config.b1p.json per attempt has no mcp block")

    images: dict = {}
    if probe_docker:
        for arm, spec in ARMS.items():
            tag = f"vex-bench-go-{spec['image_suffix']}:latest"
            images[arm] = _docker_probe_image(tag, limitations)
    else:
        limitations.append("docker probes disabled (--no-docker-probe); "
                           "image/toolchain/catalog fields are null")

    tool_binary = harness_dir / "docker/bin/izyan-evidence-tools"
    mcp_server = {
        "binary": "docker/bin/izyan-evidence-tools",
        "binary_sha256": stamp.get("binary_sha256")
        or (_sha256_file(tool_binary) if tool_binary.is_file() else None),
        "adapter_version": c1_manifest._tool_adapter_version(worktree),
        "image_stamp": stamp or None,
    }
    if tool_binary.is_file() is False:
        limitations.append("docker/bin/izyan-evidence-tools missing — "
                           "T2 catalog hashes cannot be trusted")
    if probe_docker:
        mcp_server.update(_probe_mcp_catalog(
            "vex-bench-go-opencode-c1:latest",
            "/usr/local/bin/izyan-evidence-tools", limitations))
    else:
        mcp_server.update({
            "initialize_instructions_sha256": None,
            "tools_list_sha256": None,
            "tool_count": None,
            "tool_names": None,
        })

    arms = {}
    for arm, spec in ARMS.items():
        entry = dict(spec)
        entry["prompt_sha256_12"] = prompts[spec["prompt"]]["sha256_12"]
        entry["run_root"] = str(arm_run_root(
            results_root, arm, layout=layout,
            experiment_id=experiment_id, prompts=prompts, model=model))
        entry["repeats"] = repeats
        entry["layout"] = layout
        arms[arm] = entry

    controller_hashes = _file_hashes(
        worktree, _CONTROLLER_FILES, missing_ok=True)

    manifest = {
        "schema": MANIFEST_SCHEMA,
        "experiment_id": experiment_id,
        "frozen_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "goal": (
            "decide whether a structured evidence contract "
            "(agent-assessment/2) makes the two Task-5 false-safe "
            "mechanisms checkable — error-as-absence and scoped-zero "
            "generalized — and whether izyan MCP tools (T2) add value "
            "over the same prompt/schema without MCP (P2). No "
            "production Verification Gate is built (spec §6)."
        ),
        "spec": {
            "files_sha256": spec_hashes,
            "plan_sha256": plan_hashes,
            "plan": _PLAN_FILES[0],
        },
        "contract": {
            "assessment_schema": "agent-assessment/2",
            "schema_file": "eval/task6/assessment_v2.py",
            "schema_file_sha256":
                controller_hashes.get("eval/task6/assessment_v2.py"),
            "validator": "task6-validator/1",
            "validator_file": "eval/task6/validator.py",
            "validator_file_sha256":
                controller_hashes.get("eval/task6/validator.py"),
        },
        "izyan": {
            "worktree": str(worktree),
            "commit": izyan_head,
            "dirty": izyan_dirty,
            "tool_adapter_version": c1_manifest._tool_adapter_version(
                worktree),
            "controller_files_sha256": controller_hashes,
            "prompt_files_sha256": _file_hashes(
                worktree, _PROMPT_FILES, missing_ok=True),
        },
        "harness": {
            "dir": str(harness_dir),
            "commit": harness_head,
            "dirty_files": harness_dirty.splitlines(),
            "task4_patch_file": c1_patch_file,
            "task4_patch_sha256": _sha256_file(worktree / c1_patch_file),
            "task5_patch_file": t5_patch_file,
            "task5_patch_sha256": _sha256_file(worktree / t5_patch_file),
            "patch_file": t6_patch_file,
            "patch_sha256": _sha256_file(worktree / t6_patch_file),
            "scoring_files_sha256": _file_hashes(
                harness_dir, _HARNESS_SCORING_FILES),
            "arm_files_sha256": _file_hashes(
                harness_dir, _HARNESS_ARM_FILES),
        },
        "tools_binary": mcp_server,
        "images": images,
        "toolchain": {
            "go": _docker_probe_cmd("vex-bench-go-opencode-c1:latest",
                                    ["version"], "go", "go toolchain",
                                    limitations) if probe_docker else None,
            "opencode_cli": _docker_probe_cmd(
                "vex-bench-go-opencode-c1:latest", ["--version"], "opencode",
                "opencode cli", limitations) if probe_docker else None,
        },
        "model": {
            "id": model,
            "provider": "custom-openai (OpenAI-compatible gateway, OpenAI-compatible)",
            "provider_model_id": "custom-openai/Qwen/Qwen3.6-35B-A3B"
            if model == "qwen3.6-35b" else None,
            "model_revision": None,  # not exposed by the provider
            "settings": {
                "temperature": None,
                "reasoning_effort": None,
                "limits": {"context": 262144, "output": 16384},
            },
            "settings_note": (
                "temperature/effort/revision unexposed by the provider — "
                "null, never fabricated (plan §2); context/output limits "
                "from the synthesized opencode provider block"
            ),
        },
        "prompts": prompts,
        "prompt_delta": {
            "file": "eval/task6/prompts/p2-t2.diff",
            "contract": ("t2 = exact p2 bytes + two LF + literal C1 "
                         "<EVIDENCE_TOOLS> block"),
        },
        "attempt_policy": {
            "timeout_seconds": timeout,
            "repeats": repeats,
            "parallel": parallel,
            "retries": 0,
            "cache_admission": "forbidden",
            "attempt_key": "(experiment_id, arm, model, task_id, run_NNN)",
        },
        "arms": arms,
        "historical": {
            "reference_cohorts": (
                "Task-5 P1/T1 saved answers stay historical controls; "
                "they are never re-run or re-scored here — if a causal "
                "prompt-format attribution is needed it must come from "
                "matched same-runtime arms, not the frozen Task-5 "
                "cohort (spec §2)"),
            "task5_reference_doc": _HISTORICAL_REFERENCE_DOCS[3],
            "task5_reference_docs_sha256": _file_hashes(
                worktree, _HISTORICAL_REFERENCE_DOCS, missing_ok=True),
        },
        "dataset": {
            "tasks_file": str(tasks_path),
            "tasks_sha256": tasks_sha,
            "expected_tasks_sha256": EXPECTED_DATASET_SHA256,
            "sha256_matches_pin": dataset_sha_matches_pin,
            "task_count": len(tasks),
            "task_ids": [t["task_id"] for t in tasks],
            "cve_ids": sorted({t["cve_id"] for t in tasks}),
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
                "single JSON object on stdout; category + reasoning "
                "top-level plus the structured ``assessment`` object "
                "(agent-assessment/2) — identical in P2 and T2"
            ),
            "status_schema": "attempt-status/1",
            "assessment_schema": "agent-assessment/2",
            "validator_version": "task6-validator/1",
            "attempt_layout": {
                "harness": "<arm>/<prompt_hash>/<agent>/<model>/"
                           "<task_id>/run_NNN/",
                "controller": "<arm>/<experiment_id>/<task_id>/run_NNN/",
            },
            "audit_sink": "artifacts/izyan-audit/tool_calls.jsonl",
            "mcp_transport": "stdio inside the attempt container",
        },
        "results_root": str(results_root),
        "smoke": {
            "experiment_id": EXPERIMENT_SMOKE,
            "results_root": str(Path(results_root).parent / "smoke")
            if layout == "harness" else str(results_root),
            "note": ("4 named false-safe cases + 3-4 correct-safe cases "
                     "selected host-side by GT class before any answer "
                     "is examined; labels never reach the agent "
                     "(spec §5)"),
        },
        "gt_policy": (
            "ground_truth / ground_truth_category / reference PR / prior "
            "results are controller-only; the rendered prompt carries only "
            "{cve_id}; validator/advisory inputs are public OSV records "
            "only"
        ),
        "limitations": limitations,
    }
    return manifest


def validate_manifest(m: dict, *, strict_dataset_pin: bool = False) -> list[str]:
    """Required-field completeness check (plan §5). Empty = complete.
    ``strict_dataset_pin`` turns the dataset sha mismatch into a hard
    violation (used by the scored manifest, not by synthetic tests)."""
    required = [
        "schema", "experiment_id", "frozen_at_utc",
        "spec.files_sha256", "spec.plan_sha256",
        "contract.assessment_schema", "contract.schema_file_sha256",
        "contract.validator", "contract.validator_file_sha256",
        "izyan.commit", "izyan.controller_files_sha256",
        "izyan.prompt_files_sha256",
        "harness.commit", "harness.task4_patch_sha256",
        "harness.task5_patch_sha256", "harness.patch_sha256",
        "harness.scoring_files_sha256", "harness.arm_files_sha256",
        "tools_binary.binary_sha256", "tools_binary.adapter_version",
        "model.id", "model.provider",
        "prompts.vuln_safety_v2.sha256", "prompts.vuln_safety_v2.sha256_12",
        "prompts.vuln_safety_v2_tools.sha256",
        "prompts.vuln_safety_v2_tools.sha256_12",
        "prompts.vuln_official_frozen.sha256",
        "prompt_delta.file",
        "attempt_policy.timeout_seconds", "attempt_policy.repeats",
        "attempt_policy.parallel", "attempt_policy.retries",
        "attempt_policy.cache_admission",
        "arms.p2.agent", "arms.p2.prompt", "arms.p2.run_root",
        "arms.t2.agent", "arms.t2.prompt", "arms.t2.run_root",
        "dataset.tasks_sha256", "dataset.task_ids", "dataset.cve_ids",
        "dataset.acquisition_sha256", "dataset.snapshot_hashes",
        "protocol.output_contract", "protocol.status_schema",
        "protocol.assessment_schema",
        "results_root", "gt_policy", "limitations",
    ]
    violations = []
    for dotted in required:
        node = m
        for part in dotted.split("."):
            node = node.get(part) if isinstance(node, dict) else None
            if node is None:
                break
        if node is None:
            violations.append(f"missing required field: {dotted}")
    for arm in ("p2", "t2"):
        spec = m.get("arms", {}).get(arm, {})
        if spec.get("repeats") != m.get("attempt_policy", {}).get("repeats"):
            violations.append(f"arms.{arm}.repeats != attempt_policy.repeats")
    if m.get("arms", {}).get("p2", {}).get("mcp") is not False:
        violations.append("arms.p2.mcp must be false")
    if m.get("arms", {}).get("t2", {}).get("mcp") is not True:
        violations.append("arms.t2.mcp must be true")
    p2h = m.get("prompts", {}).get("vuln_safety_v2", {}).get("sha256_12")
    t2h = m.get("prompts", {}).get("vuln_safety_v2_tools", {}).get("sha256_12")
    if p2h == t2h:
        violations.append("P2 and T2 prompt hashes must differ")
    if strict_dataset_pin and m.get("dataset", {}).get(
            "sha256_matches_pin") is False:
        violations.append(
            "dataset.tasks_sha256 != pinned dataset sha "
            f"{EXPECTED_DATASET_SHA256[:12]}… (plan §2)")
    return violations


def write_manifest(manifest: dict, dest: Path) -> Path:
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return dest


def load_manifest(path: Path) -> dict:
    m = json.loads(Path(path).read_text(encoding="utf-8"))
    if m.get("schema") != MANIFEST_SCHEMA:
        raise ManifestError(
            f"{path}: schema {m.get('schema')!r} != {MANIFEST_SCHEMA!r}")
    return m


def verify_frozen_inputs(m: dict, *, tasks_path: Path,
                         acquisition_path: Path) -> list[str]:
    """Re-hash the dataset pins before collect/score — drift is a hard
    error reported as a list of violations (empty when clean)."""
    problems = []
    if _sha256_file(tasks_path) != m["dataset"]["tasks_sha256"]:
        problems.append(f"tasks file sha256 drifted: {tasks_path}")
    if _sha256_file(acquisition_path) != m["dataset"]["acquisition_sha256"]:
        problems.append(f"acquisition file sha256 drifted: {acquisition_path}")
    return problems

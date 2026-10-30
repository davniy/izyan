"""Frozen experiment manifest for Task 5 (plan §5, §12 ``manifest``).

Written BEFORE the scored runs, after prompts + harness patch exist:
every version/hash that can change the P1↔T1 comparison is pinned —
izyan/harness commits and both patch digests, prompt full+short hashes
and the exact P1/T1 diff, image IDs + toolchain + tool binary, the MCP
server's initialize instructions and tools/list catalog digests (when
docker is reachable), model/provider settings, the task dataset pin and
snapshot content hashes, parser/scorer/controller file hashes, arm
bindings and the immutable attempt policy.

Unknowable facts stay ``None`` with an explicit entry in ``limitations``
— never invented (plan §2). All values come from real probes (git,
docker, sha256), nothing is hand-copied.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import time
from pathlib import Path
from typing import Optional, Sequence

from eval.c1 import manifest as c1_manifest
from . import protocol

MANIFEST_SCHEMA = "task5-manifest/1"

EXPERIMENT_ID = "task5"
EXPERIMENT_SMOKE = "task5-smoke"

# Harness files whose bytes define the official scoring path (same set
# C1 pinned — the scorer contract must be provably unchanged).
_HARNESS_SCORING_FILES = [
    "src/evaluate/result_parser.py",
    "src/evaluate/parse.py",
    "src/evaluate/metrics.py",
]
# Adapter modules whose bytes define the P1/T1 treatment split.
_HARNESS_ARM_FILES = [
    "src/evaluate/prompts.py",
    "src/evaluate/agents/__init__.py",
    "src/evaluate/agents/opencode.py",
    "src/evaluate/agents/opencode_c1.py",
]
# Controller modules whose bytes define the Task 5 glue + reused C1 core.
_CONTROLLER_FILES = [
    "eval/task5/protocol.py",
    "eval/task5/manifest.py",
    "eval/task5/collect.py",
    "eval/task5/report.py",
    "eval/task5/freeze.py",
    "eval/c1/assessment.py",
    "eval/c1/status.py",
    "eval/c1/collect.py",
    "eval/c1/parser_audit.py",
    "eval/c1/runner.py",
    "eval/c1/report.py",
]
_SPEC_FILES = [
    "docs/dev/specs/2026-10-09-task5-prompt-tools-gate-comparison-v2.md",
    "docs/dev/specs/task5-prompt-tools-gate-spec.md",
]
_HISTORICAL_REFERENCE_DOCS = [
    "eval/baselines/vexbench/external-baseline-1.md",
    "eval/baselines/vexbench/plain-agent-baseline-1.md",
    "eval/baselines/vexbench/task4-qwen-plain-vs-tools.md",
    "eval/baselines/vexbench/task4-codex-partial-state.md",
]
_PROMPT_FILES = [
    "eval/task5/prompts/vuln_safety_v1.txt",
    "eval/task5/prompts/vuln_safety_v1_tools.txt",
    "eval/task5/prompts/hashes.json",
    "eval/task5/prompts/p1-t1.diff",
    "eval/vexbench-prompts/official-vuln-c0a5c8458b77.txt",
]

# Arm bindings (plan §2). P0 is historical reference only — Task 4 Qwen
# plain cohort, n=1, different timeout policy; never a causal baseline.
ARMS: dict[str, dict] = {
    "p0": {
        "role": "historical_reference",
        "agent": "opencode",
        "prompt": "vuln",
        "prompt_sha256_12": protocol.FROZEN_OFFICIAL_SHA256[:12],
        "image_suffix": "opencode",
        "mcp": False,
        "note": (
            "frozen Task 4 Qwen3.6 plain cohort (/tmp/vexbench-qwen-iso/"
            "q36), timeout=1800 n=1 — historical comparator, NOT the "
            "matched control; a causal prompt-effect claim needs a fresh "
            "matched P0 (plan §2)"
        ),
    },
    "p1": {
        "role": "tuned_prompt_no_mcp",
        "agent": "opencode-b1p",
        "prompt": "vuln_safety_v1",
        "image_suffix": "opencode-gw",
        "mcp": False,
    },
    "t1": {
        "role": "tuned_prompt_plus_mcp",
        "agent": "opencode-c1",
        "prompt": "vuln_safety_v1_tools",
        "image_suffix": "opencode-c1",
        "mcp": True,
    },
}

# Historical P0 run root for the first cohort (model-level dir inside the
# frozen Task 4 layout <root>/<prompt_hash>/<agent>/<model>/).
P0_RUN_ROOT_Q36 = Path(
    "/tmp/vexbench-qwen-iso/q36/c0a5c8458b77/opencode/qwen3.6-35b"
)


class ManifestError(RuntimeError):
    pass


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _file_hashes(root: Path, rels: Sequence[str], *,
                 missing_ok: bool = False) -> dict:
    out = {}
    for r in rels:
        p = Path(root) / r
        if not p.is_file():
            if missing_ok:
                out[r] = None
                continue
            raise ManifestError(f"required file missing: {p}")
        out[r] = _sha256_file(p)
    return out


def _docker_probe_image(tag: str, limitations: list[str]) -> dict:
    """Best-effort image identity; unreachable docker → None + limitation."""
    try:
        return {
            "tag": tag,
            "id": c1_manifest._docker_json(tag, "{{.Id}}"),
            "arch": c1_manifest._docker_json(tag, "{{.Os}}/{{.Architecture}}"),
        }
    except Exception as exc:  # docker absent or image missing
        limitations.append(f"image {tag}: probe failed ({exc}); pin "
                           "before scored runs (plan §2)")
        return {"tag": tag, "id": None, "arch": None}


def _docker_probe_cmd(tag: str, cmd: Sequence[str], entrypoint: str,
                      what: str, limitations: list[str]) -> Optional[str]:
    try:
        return c1_manifest._docker_run_stdout(tag, list(cmd), entrypoint)
    except Exception as exc:
        limitations.append(f"{what} probe on {tag} failed ({exc})")
        return None


def _probe_mcp_catalog(image: str, binary: str,
                       limitations: list[str]) -> dict:
    """initialize.instructions + tools/list digests via a throwaway
    container running the tool binary (reuses the C1 JSON-RPC probe).

    Treatment provenance (plan §4): what the T1 agent actually sees at
    initialize time. Best-effort — a docker outage degrades to nulls plus
    an explicit limitation, never a fabricated hash.
    """
    try:
        import tempfile

        from eval.c1 import synthetic

        empty_snapshot = Path(tempfile.mkdtemp(prefix="task5-mcp-probe-"))
        holder: list = []
        try:
            cid = synthetic._create_cp(
                holder, image, synthetic._mcp_args(), empty_snapshot,
                entrypoint=binary, interactive=True,
            )
            res = synthetic.mcp_jsonrpc_probe(
                cid,
                [
                    {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                     "params": {"protocolVersion": "2025-03-26",
                                "capabilities": {},
                                "clientInfo": {"name": "task5-manifest",
                                               "version": "0"}}},
                    {"jsonrpc": "2.0",
                     "method": "notifications/initialized"},
                    {"jsonrpc": "2.0", "id": 2, "method": "tools/list",
                     "params": {}},
                ],
                empty_snapshot,
            )
        finally:
            for c in holder:
                subprocess.run(["docker", "rm", "-f", c],
                               capture_output=True, check=False)
        init = res["responses"].get("1", {}).get("result", {})
        tools = res["responses"].get("2", {}).get("result", {})
        instructions = init.get("instructions") or ""
        catalog = tools.get("tools") or []
        names = sorted(t.get("name", "") for t in catalog)
        return {
            "initialize_instructions_sha256": hashlib.sha256(
                instructions.encode()).hexdigest() if instructions else None,
            "tools_list_sha256": hashlib.sha256(
                json.dumps(catalog, sort_keys=True).encode()
            ).hexdigest() if catalog else None,
            "tool_count": len(catalog),
            "tool_names": names or None,
            "transcript_path": res.get("transcript_path"),
        }
    except Exception as exc:
        limitations.append(
            f"mcp catalog probe failed ({exc}); catalog/instructions "
            "hashes are null — capture from a smoke attempt instead")
        return {
            "initialize_instructions_sha256": None,
            "tools_list_sha256": None,
            "tool_count": None,
            "tool_names": None,
        }


def arm_run_root(results_root: Path, arm: str, *, layout: str,
                 experiment_id: str, prompts: dict, model: str) -> Path:
    """Model-level dir the official parser iterates over.

    ``results_root`` is the experiment results root (``eval/task5/
    results`` for the scored cohort, ``eval/task5/results/smoke`` for
    smoke); each arm nests under its own name:

    harness    layout (``vex-bench evaluate run --output-dir results/<arm>``):
               <results_root>/<arm>/<prompt_hash>/<agent>/<model>/
    controller layout (``runner.run_benchmark_attempt`` smoke output):
               <results_root>/<arm>/<experiment_id>/  (holds <task_id>/run_NNN)
    """
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
    p0_run_root: Optional[Path] = P0_RUN_ROOT_Q36,
    probe_docker: bool = True,
) -> dict:
    """Collect the frozen Task 5 manifest. All paths are probed, not assumed."""
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

    # Spec duplication contract (plan §0): the undated spec file must be
    # byte-equal to the frozen dated v2 source.
    spec_hashes = _file_hashes(worktree, _SPEC_FILES, missing_ok=True)
    spec_files = [h for h in spec_hashes.values() if h]
    spec_byte_equal = (
        len(spec_files) == len(_SPEC_FILES)
        and len(set(spec_files)) == 1
    )
    if not spec_byte_equal:
        limitations.append(
            "spec duplicate docs/dev/specs/task5-prompt-tools-gate-spec.md "
            "missing or not byte-equal to the frozen v2 file (plan §0)")

    p1 = protocol.build_prompt(protocol.PROMPT_P1)
    t1 = protocol.build_prompt(protocol.PROMPT_T1)
    protocol.assert_prompt_contract(p1, t1)
    prompts = {
        protocol.PROMPT_P1: {
            "sha256_12": protocol.prompt_hash(p1),
            "sha256": hashlib.sha256(p1.encode()).hexdigest(),
            "bytes": len(p1.encode()),
        },
        protocol.PROMPT_T1: {
            "sha256_12": protocol.prompt_hash(t1),
            "sha256": hashlib.sha256(t1.encode()).hexdigest(),
            "bytes": len(t1.encode()),
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

    patch_file = "eval/task5/harness/vexbench-agent-ctl-task5.patch"
    c1_patch_file = "eval/c1/harness/vexbench-agent-ctl-c1.patch"

    # P1 admission guard (plan §3): the inherited base config must carry
    # no MCP for the plain arm. The synthesized config is a per-attempt
    # artifact (opencode-config.b1p.json); statically the adapter only
    # adds ``mcp`` in OpenCodeC1Agent._extend_config — assert the source
    # bytes show the split exactly there.
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
            if arm == "p0":
                continue
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
                           "T1 catalog hashes cannot be trusted")
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
        pname = spec["prompt"]
        if pname in prompts:
            entry["prompt_sha256_12"] = prompts[pname]["sha256_12"]
        elif pname == "vuln":
            entry["prompt_sha256_12"] = prompts["vuln_official_frozen"][
                "sha256_12"]
        if arm == "p0":
            entry["run_root"] = str(p0_run_root) if p0_run_root else None
            entry["repeats"] = 1
            entry["layout"] = "harness"
        else:
            entry["run_root"] = str(arm_run_root(
                results_root, arm, layout=layout,
                experiment_id=experiment_id, prompts=prompts, model=model))
            entry["repeats"] = repeats
            entry["layout"] = layout
        arms[arm] = entry

    manifest = {
        "schema": MANIFEST_SCHEMA,
        "experiment_id": experiment_id,
        "frozen_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "goal": (
            "decide whether tuned safety instructions alone (P1) close the "
            "Task-4 false-safe regression, and whether the existing 31 izyan "
            "MCP tools (T1) add value over the same frozen prompt — Gate "
            "remains conditional on Checkpoint B (plan §5.3)"
        ),
        "spec": {
            "files_sha256": spec_hashes,
            "byte_equal_duplicate": spec_byte_equal,
            "plan": "docs/dev/plans/2026-10-09-task5-implementation-plan.md",
        },
        "izyan": {
            "worktree": str(worktree),
            "commit": izyan_head,
            "dirty": izyan_dirty,
            "tool_adapter_version": c1_manifest._tool_adapter_version(worktree),
            "controller_files_sha256": _file_hashes(
                worktree, _CONTROLLER_FILES, missing_ok=True),
            "prompt_files_sha256": _file_hashes(
                worktree, _PROMPT_FILES, missing_ok=True),
        },
        "harness": {
            "dir": str(harness_dir),
            "commit": harness_head,
            "dirty_files": harness_dirty.splitlines(),
            "task4_patch_file": c1_patch_file,
            "task4_patch_sha256": _sha256_file(worktree / c1_patch_file),
            "patch_file": patch_file,
            "patch_sha256": _sha256_file(worktree / patch_file),
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
            "file": "eval/task5/prompts/p1-t1.diff",
            "contract": "t1 = p1 + two LF + literal <EVIDENCE_TOOLS> block",
        },
        "attempt_policy": {
            "timeout_seconds": timeout,
            "repeats": repeats,
            "parallel": parallel,
            "retries": 0,
            "cache_admission": "forbidden",
            "attempt_key": "(experiment_id, arm, model, task_id, run_NNN)",
            "note": (
                "new protocol (plan §2): timeout=900/repeats=3/parallel=1; "
                "the historical Qwen cohorts ran timeout=1800 n=1 — "
                "P0↔P1 is historical, not causal"
            ),
        },
        "arms": arms,
        "dataset": {
            "tasks_file": str(tasks_path),
            "tasks_sha256": _sha256_file(tasks_path),
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
                "single JSON object on stdout; category/reasoning "
                "top-level — identical in P1 and T1; NO structured "
                "assessment field (assessment_schema=absent is expected)"
            ),
            "status_schema": "attempt-status/1",
            "attempt_layout": {
                "harness": "<arm>/<prompt_hash>/<agent>/<model>/"
                           "<task_id>/run_NNN/",
                "controller": "<arm>/<experiment_id>/<task_id>/run_NNN/",
            },
            "audit_sink": "artifacts/izyan-audit/tool_calls.jsonl",
            "mcp_transport": "stdio inside the attempt container",
            "historical_reference_docs_sha256": _file_hashes(
                worktree, _HISTORICAL_REFERENCE_DOCS, missing_ok=True),
        },
        "results_root": str(results_root),
        "smoke": {
            "experiment_id": EXPERIMENT_SMOKE,
            "results_root": str(Path(results_root).parent / "smoke")
            if layout == "harness" else str(results_root),
            "note": ("3 fixed cases selected host-side by GT class before "
                     "any answer is examined; labels never reach the agent"),
        },
        "gt_policy": (
            "ground_truth / ground_truth_category / reference PR / prior "
            "results are controller-only; the rendered prompt carries only "
            "{cve_id}; Gate/agent get allowlisted projections only"
        ),
        "limitations": limitations,
    }
    return manifest


def validate_manifest(m: dict) -> list[str]:
    """Required-field completeness check (plan §5). Returns a list of
    violations — empty when the manifest is complete. Cheap and
    deterministic; used by tests and by ``manifest`` itself."""
    required = [
        "schema", "experiment_id", "frozen_at_utc",
        "spec.files_sha256", "spec.byte_equal_duplicate",
        "izyan.commit", "izyan.controller_files_sha256",
        "izyan.prompt_files_sha256",
        "harness.commit", "harness.task4_patch_sha256",
        "harness.patch_sha256", "harness.scoring_files_sha256",
        "harness.arm_files_sha256",
        "tools_binary.binary_sha256", "tools_binary.adapter_version",
        "model.id", "model.provider",
        "prompts.vuln_safety_v1.sha256", "prompts.vuln_safety_v1.sha256_12",
        "prompts.vuln_safety_v1_tools.sha256",
        "prompts.vuln_safety_v1_tools.sha256_12",
        "prompts.vuln_official_frozen.sha256",
        "prompt_delta.file",
        "attempt_policy.timeout_seconds", "attempt_policy.repeats",
        "attempt_policy.parallel", "attempt_policy.retries",
        "attempt_policy.cache_admission",
        "arms.p1.agent", "arms.p1.prompt", "arms.p1.run_root",
        "arms.t1.agent", "arms.t1.prompt", "arms.t1.run_root",
        "arms.p0.run_root",
        "dataset.tasks_sha256", "dataset.task_ids", "dataset.cve_ids",
        "dataset.acquisition_sha256", "dataset.snapshot_hashes",
        "protocol.output_contract", "protocol.status_schema",
        "protocol.historical_reference_docs_sha256",
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
    for arm in ("p1", "t1"):
        spec = m.get("arms", {}).get(arm, {})
        if spec.get("repeats") != m.get("attempt_policy", {}).get("repeats"):
            violations.append(f"arms.{arm}.repeats != attempt_policy.repeats")
    if m.get("arms", {}).get("p1", {}).get("mcp") is not False:
        violations.append("arms.p1.mcp must be false")
    if m.get("arms", {}).get("t1", {}).get("mcp") is not True:
        violations.append("arms.t1.mcp must be true")
    p1h = m.get("prompts", {}).get("vuln_safety_v1", {}).get("sha256_12")
    t1h = m.get("prompts", {}).get("vuln_safety_v1_tools", {}).get("sha256_12")
    if p1h == t1h:
        violations.append("P1 and T1 prompt hashes must differ")
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

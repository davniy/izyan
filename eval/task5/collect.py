"""Task 5 attempt finalization and arm-isolation audit (plan §3, §12).

``collect`` walks an arm's run root (harness ``<prompt_hash>/<agent>/
<model>/<task_id>/run_NNN`` or controller ``<experiment_id>/<task_id>/
run_NNN`` layout — both end with the same leaf shape), materializes the
controller artifacts the harness does not produce and writes
``status.json`` (+ ``agent_assessment.json`` when the category-only
Task-5 prompt still yields a parseable object — normally absent) through
``eval.c1.collect.finalize_attempt`` with the official parser injected
unchanged.

Immutability: an existing ``status.json`` makes the attempt
``skipped_finalized``; controller artifacts are never overwritten
(byte-mismatch on a would-be rewrite raises DuplicateAttemptError).
Nothing is retried, re-ordered or best-of'd (plan §2 attempt policy).

The official ``result_parser`` is used verbatim via the harness import;
this module never reimplements scoring semantics.
"""

from __future__ import annotations
import json
import logging
from pathlib import Path
from typing import Callable, Optional, Sequence

from eval.c1.assessment import (
    AttemptMeta,
    DuplicateAttemptError,
    UsageStats,
    extract_json_object,
)
from eval.c1.status import (
    AttemptStatus, write_status_artifact)  # noqa: F401
from eval.c1.collect import finalize_attempt, read_audit_jsonl

logger = logging.getLogger(__name__)

AUDIT_REL = Path("artifacts") / "izyan-audit" / "tool_calls.jsonl"


def load_official_parser() -> Callable:
    """The harness's ``result_parser.parse_category`` — re-exported for
    callers outside eval.c1 (smoke, score); Task 5 never reimplements it."""
    from eval.c1.collect import _load_official_parser

    return _load_official_parser()


def discover_attempts(run_root: Path) -> list[tuple[str, str, Path]]:
    """``(task_id, attempt_id, run_dir)`` triples under ``run_root``.

    Matches the official iteration contract: run dirs live at
    ``<task_id>/run_*`` two levels deep regardless of whether the arm
    root is the harness model dir or the controller experiment dir.
    Sorted for deterministic processing; never invents missing attempts.
    """
    run_root = Path(run_root)
    out: list[tuple[str, str, Path]] = []
    if not run_root.is_dir():
        return out
    for task_dir in sorted(p for p in run_root.iterdir() if p.is_dir()):
        for run_dir in sorted(task_dir.iterdir()):
            if run_dir.is_dir() and run_dir.name.startswith("run_"):
                out.append((task_dir.name, run_dir.name, run_dir))
    return out


def audit_file_for(run_dir: Path) -> Optional[Path]:
    """The attempt's MCP audit sink — the exported artifact copy is
    authoritative; the controller's top-level copy is a fallback."""
    run_dir = Path(run_dir)
    sink = run_dir / AUDIT_REL
    if sink.is_file():
        return sink
    top = run_dir / "tool_calls.jsonl"
    return top if top.is_file() else None


def _write_once_same(path: Path, text: str) -> bool:
    """Write controller artifact; existing identical bytes → False,
    existing different bytes → DuplicateAttemptError, new file → True."""
    path = Path(path)
    if path.exists():
        if path.read_bytes() == text.encode("utf-8"):
            return False
        raise DuplicateAttemptError(f"refusing to overwrite: {path}")
    path.write_text(text, encoding="utf-8")
    return True


def materialize_controller_artifacts(
    run_dir: Path, *, agent,
) -> list[str]:
    """Post-hoc equivalent of ``c1.runner.write_controller_artifacts`` for
    arms executed by ``vex-bench evaluate run`` (no controller wrapper):
    ``raw_agent_output.txt``, ``usage.json`` (tokens known,
    ``wall_seconds=None`` — post-hoc runs have no trustworthy wall-clock
    stamp; null, never fabricated), ``tool_calls.jsonl`` +
    ``observations.jsonl`` (audit sink copies), ``export-report.json``.
    Returns the list of files newly written.
    """
    run_dir = Path(run_dir)
    written: list[str] = []
    result_path = run_dir / agent.result_filename()
    if result_path.exists():
        raw = result_path.read_text(encoding="utf-8", errors="replace")
        if _write_once_same(
            run_dir / "raw_agent_output.txt",
            agent.extract_text(raw) + "\n",
        ):
            written.append("raw_agent_output.txt")
        stats = agent.extract_stats(raw)
        usage = UsageStats(
            input_tokens=stats.input_tokens,
            cached_input_tokens=stats.cached_input_tokens,
            output_tokens=stats.output_tokens,
            reasoning_tokens=stats.reasoning_tokens,
            wall_seconds=None,  # post-hoc collection: no wall clock
        )
        if _write_once_same(
            run_dir / "usage.json", usage.model_dump_json(indent=2) + "\n"
        ):
            written.append("usage.json")
    audit_src = run_dir / AUDIT_REL
    if audit_src.exists():
        audit_text = audit_src.read_text(encoding="utf-8")
        if _write_once_same(run_dir / "tool_calls.jsonl", audit_text):
            written.append("tool_calls.jsonl")
        obs_lines = []
        for line in audit_text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            obs = rec.get("observation")
            if isinstance(obs, dict):
                obs_lines.append(json.dumps(obs, sort_keys=True))
        if _write_once_same(
            run_dir / "observations.jsonl",
            "\n".join(obs_lines) + ("\n" if obs_lines else ""),
        ):
            written.append("observations.jsonl")
    export_report = run_dir / "artifacts" / "export-report.json"
    if export_report.exists():
        if _write_once_same(
            run_dir / "export-report.json",
            export_report.read_text(encoding="utf-8"),
        ):
            written.append("export-report.json")
    return written


def attempt_effective_config(run_dir: Path) -> Optional[Path]:
    """The synthesized per-attempt opencode config artifact, if present."""
    run_dir = Path(run_dir)
    for name in ("opencode-config.b1p.json", "opencode-config.c1.json"):
        p = run_dir / "artifacts" / name
        if p.is_file():
            return p
    return None


def audit_arm_attempt(run_dir: Path, *, expect_mcp: bool) -> dict:
    """Arm-isolation evidence for one attempt (plan §3 admission check).

    For P1 the effective config must carry NO top-level ``mcp`` and the
    izyan audit sink must be absent; for T1 both must be present. A
    missing config artifact is reported, not guessed.
    """
    run_dir = Path(run_dir)
    cfg_path = attempt_effective_config(run_dir)
    cfg_has_mcp: Optional[bool] = None
    cfg_note = None
    if cfg_path is not None:
        try:
            cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
            cfg_has_mcp = "mcp" in cfg
        except Exception as exc:
            cfg_note = f"config unparsable: {exc}"
    else:
        cfg_note = "no synthesized config artifact"

    audit_path = audit_file_for(run_dir)
    records = read_audit_jsonl(audit_path)
    status_counts: dict[str, int] = {}
    for rec in records:
        obs = rec.get("observation") if isinstance(rec, dict) else None
        st = (obs or {}).get("tool_status") or rec.get("tool_status") \
            or "unknown"
        status_counts[st] = status_counts.get(st, 0) + 1

    result = {
        "run_dir": str(run_dir),
        "expect_mcp": expect_mcp,
        "config_file": str(cfg_path) if cfg_path else None,
        "config_has_mcp": cfg_has_mcp,
        "config_note": cfg_note,
        "audit_sink": str(audit_path) if audit_path else None,
        "tool_calls": len(records),
        "tool_status_counts": status_counts,
    }
    # P1 ok := effective config carries no mcp AND no audit sink exists
    # T1 ok := effective config carries mcp AND the audit sink exists
    if expect_mcp:
        result["isolation_ok"] = bool(cfg_has_mcp) and audit_path is not None
    else:
        result["isolation_ok"] = (cfg_has_mcp is False
                                  and audit_path is None)
    return result


# --- MCP call accounting (shared with freeze-history) --------------------------

# Error buckets for plan §6 accounting — substring match on the tool
# error/detail text, first hit wins; residual stays "other" (recorded,
# never dropped).
_ERROR_BUCKETS: list[tuple[str, tuple[str, ...]]] = [
    ("context_canceled", ("context canceled", "context deadline")),
    ("govulncheck_missing", ("govulncheck",)),
    ("go_mod_updates_needed", ("updates to go.mod", "go.mod needs")),
    ("fetch_failed", ("fetch", "GET http", "dial tcp")),
    ("invalid_arguments", ("invalid argument", "unknown field",
                           "missing required", "bad args")),
]


def classify_tool_error(text: str) -> str:
    low = (text or "").lower()
    for name, needles in _ERROR_BUCKETS:
        if any(n in low for n in needles):
            return name
    return "other"


def iter_audit_records(root: Path) -> list[tuple[Path, dict]]:
    """All MCP call records under a run root — one record per call,
    deduplicated per run dir (the artifacts sink wins over the
    controller's top-level copy of the same file)."""
    root = Path(root)
    out: list[tuple[Path, dict]] = []
    for run_dir in sorted(
        p for p in root.rglob("run_*") if p.is_dir()
    ):
        audit = audit_file_for(run_dir)
        if audit is None:
            continue
        for rec in read_audit_jsonl(audit):
            out.append((audit, rec))
    return out


def mcp_error_accounting(root: Path) -> dict:
    """Plan §6 ERROR accounting over an audit root: totals by tool_status,
    error-class buckets and the residual "other" list (raw record
    pointers — unclassified calls are evidence, not noise)."""
    records = iter_audit_records(root)
    by_status: dict[str, int] = {}
    by_error_class: dict[str, int] = {}
    other_errors: list[dict] = []
    files = set()
    for path, rec in records:
        files.add(str(path))
        obs = rec.get("observation") if isinstance(rec, dict) else None
        st = (obs or {}).get("tool_status") or rec.get("tool_status") \
            or "unknown"
        by_status[st] = by_status.get(st, 0) + 1
        if st.upper() in {"ERROR", "UNSUPPORTED"}:
            detail = (obs or {}).get("error") or rec.get("error") \
                or json.dumps(obs or rec)[:400]
            cls = classify_tool_error(str(detail))
            by_error_class[cls] = by_error_class.get(cls, 0) + 1
            if cls == "other":
                other_errors.append({
                    "file": str(path),
                    "tool": (obs or {}).get("tool") or rec.get("tool"),
                    "detail": str(detail)[:400],
                })
    return {
        "root": str(root),
        "audit_files": len(files),
        "total_calls": len(records),
        "by_tool_status": dict(sorted(by_status.items())),
        "error_classes": dict(sorted(by_error_class.items())),
        "unclassified_errors": other_errors,
    }


# --- arm finalization ----------------------------------------------------------


def relabel_assessment_absent(status, final_text: str) -> None:
    """Task 5 has NO assessment contract (category-only prompt, plan §7):
    a missing ``assessment`` field is absence, not a defect — remap C1's
    "invalid" to "absent" only when the terminal JSON object truly
    carries no assessment key. A present-but-malformed object stays
    "invalid"."""
    terminal_obj = extract_json_object(final_text) if final_text else None
    if (status.assessment_schema == "invalid"
            and isinstance(terminal_obj, dict)
            and "assessment" not in terminal_obj):
        status.assessment_schema = "absent"


def finalize_arm(
    arm_root: Path,
    *,
    arm: str,
    manifest: dict,
    tasks: Optional[Sequence[dict]] = None,
    snapshots: Optional[dict] = None,
    agent=None,
    official_parser: Optional[Callable] = None,
    dry_run: bool = False,
) -> dict:
    """Finalize every discovered attempt under ``arm_root``.

    ``tasks`` are the benchmark task dicts (for cve_id); ``snapshots``
    are the acquisition content hashes (for snapshot_hash). ``agent``
    defaults to the harness adapter bound to the arm (lazy import —
    tests inject a stub). Attempts missing a result AND an error.txt are
    recorded ``incomplete`` and left untouched. Returns the collection
    summary — it never deletes or rewrites anything.
    """
    arm_root = Path(arm_root)
    spec = manifest["arms"][arm]
    dataset_tasks = manifest["dataset"]["task_ids"]
    task_index = {
        t["task_id"]: t for t in (tasks or [])
    }
    snapshots = snapshots or manifest["dataset"].get("snapshot_hashes", {})
    prompts = manifest["prompts"]
    prompt_name = spec["prompt"]
    prompt_hash = prompts.get(prompt_name, {}).get("sha256_12", "unknown")
    prompt_version = f"{prompt_name}-{prompt_hash}"
    harness_version = f"vexbench-agent-ctl@{manifest['harness']['commit']}"
    adapter_version = manifest["izyan"].get("tool_adapter_version") or \
        manifest["tools_binary"].get("adapter_version") or "unknown"
    image = None
    if spec.get("image_suffix"):
        image = f"vex-bench-go-{spec['image_suffix']}:latest"

    if agent is None:
        from eval.c1 import runner as c1_runner

        agent = c1_runner.load_agent(spec["agent"], manifest["model"]["id"])

    rows = []
    counts = {"finalized": 0, "skipped_finalized": 0,
              "incomplete": 0, "failed": 0}
    for task_id, attempt_id, run_dir in discover_attempts(arm_root):
        status_path = run_dir / "status.json"
        entry = {
            "task_id": task_id,
            "attempt_id": attempt_id,
            "run_dir": str(run_dir),
        }
        if dataset_tasks and task_id not in dataset_tasks:
            entry["collect"] = "unknown_task"
            rows.append(entry)
            logger.warning("%s/%s: task_id not in manifest dataset",
                           task_id, attempt_id)
            continue
        if status_path.exists():
            entry["collect"] = "skipped_finalized"
            counts["skipped_finalized"] += 1
            rows.append(entry)
            continue
        result_file = run_dir / agent.result_filename()
        error_file = run_dir / "error.txt"
        if not result_file.exists() and not error_file.exists():
            entry["collect"] = "incomplete"
            counts["incomplete"] += 1
            rows.append(entry)
            continue
        if dry_run:
            entry["collect"] = "dry_run"
            rows.append(entry)
            continue

        materialize_controller_artifacts(run_dir, agent=agent)
        usage = None
        usage_path = run_dir / "usage.json"
        if usage_path.exists():
            usage = UsageStats.model_validate_json(
                usage_path.read_text(encoding="utf-8"))

        task = task_index.get(task_id, {})
        snap_key = None
        if task:
            owner_repo_sha = "/".join(
                task["repo_url"].rsplit("/", 2)[-2:]
                + [task["commit_sha"]])
            snap_key = snapshots.get(owner_repo_sha, {})
            if isinstance(snap_key, dict):
                snap_key = snap_key.get("content_hash")
        meta = AttemptMeta(
            experiment_id=manifest["experiment_id"],
            task_id=task_id,
            attempt_id=attempt_id,
            cve_id=task.get("cve_id", "unknown"),
            snapshot_hash=snap_key or "unknown",
            model=manifest["model"]["id"],
            model_revision=manifest["model"].get("model_revision"),
            prompt_version=prompt_version,
            harness_version=harness_version,
            tool_adapter_version=adapter_version,
            image=image,
        )
        status, asm = finalize_attempt(
            run_dir,
            meta=meta,
            usage=usage,
            result_filename=agent.result_filename(),
            final_text_extractor=agent.extract_text,
            official_parser=official_parser,
            dry_run=True,
        )
        relabel_assessment_absent(
            status,
            agent.extract_text(
                result_file.read_text(encoding="utf-8",
                                      errors="replace"))
            if result_file.exists() else "")
        if asm is not None:
            from eval.c1.assessment import write_assessment_artifact

            write_assessment_artifact(run_dir, asm)
        write_status_artifact(run_dir, status)
        entry["collect"] = "finalized"
        entry["overall"] = status.overall
        entry["failure_reason"] = status.failure_reason
        counts["finalized"] += 1
        if status.overall == "failed":
            counts["failed"] += 1
        rows.append(entry)

    missing = [
        t for t in dataset_tasks
        if t not in {r["task_id"] for r in rows}
    ]
    return {
        "arm": arm,
        "arm_root": str(arm_root),
        "attempts_seen": len(rows),
        "counts": counts,
        "missing_task_ids": missing,
        "attempts": rows,
    }

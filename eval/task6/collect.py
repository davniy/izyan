"""Task 6 attempt finalization (plan §10, §15 ``collect``).

Thin glue over the Task-5/C1 collect machinery with ONE difference:
Task 6 has the ``agent-assessment/2`` contract, so attempt assessment
extraction uses ``eval.task6.assessment_v2`` (``extract_assessment_v2``
+ ``build_assessment_v2`` + ``write_assessment_artifact_v2``) instead of
Task 5's ``relabel_assessment_absent`` (which remaps every missing
assessment to ``absent`` — under Task 6 a missing assessment is a real
defect: ``assessment_schema = "invalid"``, never relabeled).

Reused unchanged from eval.task5.collect:
discover_attempts, audit_file_for, materialize_controller_artifacts,
attempt_effective_config, audit_arm_attempt, classify_tool_error,
iter_audit_records, mcp_error_accounting, load_official_parser,
write_status_artifact, UsageStats, AttemptMeta, DuplicateAttemptError.

Invariants (plan §10): failed/partial attempt bytes preserved verbatim;
immutable attempt keys — existing status.json means ``skipped_finalized``,
never a rewrite; no [CACHE]/[RE-RUN] admission anywhere; attempts
missing result AND error.txt are recorded ``incomplete`` and untouched.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Callable, Optional, Sequence

from eval.c1.assessment import (  # noqa: F401  (re-exported)
    DuplicateAttemptError,
)
from eval.c1.collect import (  # noqa: F401  (re-exported)
    _load_official_parser,
    finalize_attempt,
    read_audit_jsonl,
)
from eval.c1.status import (  # noqa: F401
    AttemptStatus,
    classify_runtime_error,
    detect_provider_refusal,
    write_status_artifact,
)
from eval.c1.parser_audit import codex_terminal_text
from eval.task5.collect import (  # noqa: F401  (re-exported)
    AUDIT_REL,
    UsageStats,
    AttemptMeta,
    audit_arm_attempt,
    audit_file_for,
    attempt_effective_config,
    classify_tool_error,
    discover_attempts,
    iter_audit_records,
    load_official_parser,
    materialize_controller_artifacts,
    mcp_error_accounting,
)
from . import assessment_v2 as asm2
from .assessment_v2 import (  # noqa: F401
    AgentAssessmentV2,
    ExtractionResultV2,
    build_assessment_v2,
    extract_assessment_v2,
    write_assessment_artifact_v2,
)

logger = logging.getLogger(__name__)


def finalize_attempt_v2(
    run_dir: Path,
    *,
    meta: AttemptMeta,
    official_parser: Optional[Callable] = None,
    result_filename: str = "result.jsonl",
    final_text_extractor: Optional[Callable[[str], str]] = None,
    audit_path: Optional[Path] = None,
    usage: Optional[UsageStats] = None,
    dry_run: bool = False,
) -> tuple[AttemptStatus, Optional[AgentAssessmentV2]]:
    """``c1.collect.finalize_attempt`` semantics with the
    ``agent-assessment/2`` extraction pipeline.

    Same status classification (execution / official_parse /
    parser_audit / assessment_schema); a missing or schema-invalid
    ``assessment`` is ``invalid``, never relabeled ``absent`` — under
    Task 6 the structured assessment is REQUIRED by the prompt
    contract. Returns (status, assessment-or-None); never raises for
    bad agent output. Never writes under ``dry_run``.
    """
    run_dir = Path(run_dir)
    if official_parser is None:
        official_parser = _load_official_parser()
    if audit_path is None:
        audit_path = run_dir / AUDIT_REL
    audit_records = read_audit_jsonl(audit_path)

    result_path = run_dir / result_filename
    error_path = run_dir / "error.txt"
    extract_final = final_text_extractor or codex_terminal_text

    execution = "ok"
    failure_reason: Optional[str] = None
    detail: Optional[str] = None
    final_text = ""

    if not result_path.exists():
        if error_path.exists():
            err = error_path.read_text(encoding="utf-8", errors="replace")
            execution, failure_reason = classify_runtime_error(err)
            detail = err.strip()[-2000:] or None
        else:
            execution, failure_reason = "no_output", "no_result"
    else:
        raw = result_path.read_text(encoding="utf-8", errors="replace")
        final_text = extract_final(raw).strip()

    official_parse = "no_result"
    official_cat: Optional[str] = None
    parser_audit = "not_run"
    schema_status = "absent"
    defects: list[str] = []
    assessment: Optional[AgentAssessmentV2] = None

    if result_path.exists():
        if not final_text:
            official_parse = "parse_fail"
            execution = "invalid_terminal_answer"
            failure_reason = failure_reason or "invalid_terminal_answer"
            # F5a: the attempt produced output but no parseable object —
            # the REQUIRED assessment is invalid, never "absent"
            schema_status = "invalid"
            defects.append(
                "terminal output produced no parseable JSON text; the "
                "required agent-assessment/2 block is missing")
        else:
            cat, _reasoning = official_parser(final_text)
            official_cat = cat
            official_parse = "accepted" if cat else "parse_fail"
            if not cat and detect_provider_refusal(final_text):
                execution = "provider_refusal"
                failure_reason = "provider_refusal"

            recovered_obj = asm2.extract_json_object(final_text)
            if recovered_obj is None:
                parser_audit = "no_object"
            elif official_cat is None:
                parser_audit = "recovered"
            else:
                parser_audit = "matched"

            extraction: ExtractionResultV2 = extract_assessment_v2(
                final_text)
            defects.extend(extraction.errors)
            if extraction.assessment is not None:
                asm, more_defects = build_assessment_v2(
                    extraction, meta, audit_records, usage)
                defects.extend(more_defects)
                # F5b: status follows the BUILT artifact — a payload
                # that validated but could not be stamped (missing
                # top-level category/reasoning) is invalid, not valid.
                if asm is not None and not extraction.errors:
                    schema_status = "valid"
                else:
                    schema_status = "invalid"
                assessment = asm
            else:
                # Task 6 contract: no structured assessment is a defect
                # — "invalid" (never the Task-5 "absent")
                schema_status = "invalid"
            if execution == "ok" and official_parse != "accepted":
                execution = "invalid_terminal_answer"
                failure_reason = failure_reason or \
                    "invalid_terminal_answer"
            if execution == "ok" and schema_status == "invalid":
                detail = "; ".join(defects)[-2000:] or detail

    status = AttemptStatus.classify(
        task_id=meta.task_id,
        attempt_id=meta.attempt_id,
        experiment_id=meta.experiment_id,
        execution=execution,  # type: ignore[arg-type]
        official_parse=official_parse,  # type: ignore[arg-type]
        assessment_schema=schema_status,  # type: ignore[arg-type]
        parser_audit=parser_audit,  # type: ignore[arg-type]
        category=official_cat,
        failure_reason=failure_reason,
        detail=detail or ("; ".join(defects)[-2000:] if defects else None),
    )

    if not dry_run:
        if assessment is not None:
            write_assessment_artifact_v2(run_dir, assessment)
        write_status_artifact(run_dir, status)
    return status, assessment


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
    """Finalize every discovered attempt under ``arm_root`` — same
    contract as ``eval.task5.collect.finalize_arm`` but with the /2
    assessment pipeline and no assessment-absent relabeling."""
    arm_root = Path(arm_root)
    spec = manifest["arms"][arm]
    dataset_tasks = manifest["dataset"]["task_ids"]
    task_index = {t["task_id"]: t for t in (tasks or [])}
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
        status, asm = finalize_attempt_v2(
            run_dir,
            meta=meta,
            usage=usage,
            result_filename=agent.result_filename(),
            final_text_extractor=agent.extract_text,
            official_parser=official_parser,
            dry_run=True,
        )
        if asm is not None:
            write_assessment_artifact_v2(run_dir, asm)
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

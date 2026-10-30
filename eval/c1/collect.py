"""Controller-side assembly of one C1 attempt's artifacts (Task 4.2).

Reads a harness run dir (the adapter's result file / error.txt / artifacts/) and writes
``agent_assessment.json`` + ``status.json`` — or only ``status.json`` for a
failed attempt. Never overwrites existing attempt artifacts
(DuplicateAttemptError): retries under the same attempt key are forbidden
(plan section 5: one initial attempt, immutable IDs).

The official category is computed ONLY through the caller-supplied
``official_parser`` (the harness's own ``result_parser.parse_category``);
eval/c1 never reimplements scoring semantics.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Callable, Optional, Sequence

from .assessment import (
    AgentAssessment,
    AttemptMeta,
    ExtractionResult,
    UsageStats,
    build_assessment,
    extract_assessment,
    extract_json_object,
    write_assessment_artifact,
)
from .parser_audit import codex_terminal_text
from .status import (
    AttemptStatus,
    classify_runtime_error,
    detect_provider_refusal,
    write_status_artifact,
)

logger = logging.getLogger(__name__)

# Default location of the MCP audit sink inside the exported artifacts
# (the C1 adapter runs the tool server with --audit-file
# /tmp/izyan-audit/tool_calls.jsonl and copies that dir out).
DEFAULT_AUDIT_REL = Path("artifacts") / "izyan-audit" / "tool_calls.jsonl"

OfficialParser = Callable[[str], "tuple[Optional[str], Optional[str]]"]


def _load_official_parser() -> OfficialParser:
    """Import the official VEX-Bench parser from the harness checkout.

    Kept lazy so eval/c1 unit tests don't need the harness on sys.path —
    they inject a parser. Real controllers run with the harness importable.
    """
    try:
        from evaluate.result_parser import parse_category  # type: ignore
    except ImportError as exc:  # pragma: no cover - environment wiring
        raise RuntimeError(
            "official parser unavailable: pass official_parser= or run with "
            "the vexbench harness 'src' directory on sys.path"
        ) from exc
    return parse_category


def read_audit_jsonl(path: Optional[Path]) -> list[dict]:
    """Load the attempt's MCP audit sink; missing file = no tool calls."""
    if path is None or not path.exists():
        return []
    records: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            logger.warning("skipping unparseable audit line in %s", path)
            continue
        if isinstance(obj, dict):
            records.append(obj)
    return records


def _codex_final_text(ndjson: str) -> str:
    """Last ``agent_message`` text from Codex NDJSON — delegates to
    ``parser_audit.codex_terminal_text`` (the single terminal-text rule,
    same as the harness's ``CodexAgent.extract_text``)."""
    return codex_terminal_text(ndjson)


def finalize_attempt(
    run_dir: Path,
    *,
    meta: AttemptMeta,
    official_parser: Optional[OfficialParser] = None,
    result_filename: str = "result.jsonl",
    final_text_extractor: Optional[Callable[[str], str]] = None,
    audit_path: Optional[Path] = None,
    usage: Optional[UsageStats] = None,
    dry_run: bool = False,
) -> tuple[AttemptStatus, Optional[AgentAssessment]]:
    """Build and persist the attempt's status.json (+ assessment when valid).

    ``final_text_extractor`` maps the adapter's raw result file to the
    terminal assistant text; the default is the Codex NDJSON rule, agents
    with a different raw format pass their own ``extract_text``.
    ``dry_run`` computes everything without writing — for tests/smoke.
    Returns (status, assessment-or-None). Never raises for bad agent
    output: every failure becomes a failed status with a reason.
    Raises DuplicateAttemptError when immutable artifacts already exist.
    """
    run_dir = Path(run_dir)
    if official_parser is None:
        official_parser = _load_official_parser()
    if audit_path is None:
        audit_path = run_dir / DEFAULT_AUDIT_REL
    audit_records = read_audit_jsonl(audit_path)

    result_path = run_dir / result_filename
    error_path = run_dir / "error.txt"
    extract_final = final_text_extractor or _codex_final_text

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
    recovered_obj: Optional[dict] = None
    schema_status = "absent"
    defects: list[str] = []
    assessment: Optional[AgentAssessment] = None

    if result_path.exists():
        if not final_text:
            official_parse = "parse_fail"
            execution = "invalid_terminal_answer"
            failure_reason = failure_reason or "invalid_terminal_answer"
        else:
            cat, _reasoning = official_parser(final_text)
            official_cat = cat
            official_parse = "accepted" if cat else "parse_fail"
            if not cat and detect_provider_refusal(final_text):
                execution = "provider_refusal"
                failure_reason = "provider_refusal"

            recovered_obj = extract_json_object(final_text)
            if recovered_obj is None:
                parser_audit = "no_object"
            elif official_cat is None:
                parser_audit = "recovered"  # official missed, audit found full JSON
            else:
                parser_audit = "matched"

            extraction: ExtractionResult = extract_assessment(final_text)
            defects.extend(extraction.errors)
            if extraction.assessment is not None:
                schema_status = "valid" if not extraction.errors else "invalid"
                # When the official extractor failed but the audit decoder
                # recovered the full object, stamp the model's own category —
                # the artifact records what the model said; official_parse
                # stays "parse_fail" (projections are not mixed).
                asm, more_defects = build_assessment(
                    extraction, meta, audit_records, usage
                )
                defects.extend(more_defects)
                assessment = asm
            else:
                schema_status = "invalid" if final_text else "absent"
            if execution == "ok" and official_parse != "accepted":
                execution = "invalid_terminal_answer"
                failure_reason = failure_reason or "invalid_terminal_answer"
            if execution == "ok" and schema_status == "invalid":
                # artifact defect does not erase an accepted official
                # category — record it, keep overall from official status
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
            write_assessment_artifact(run_dir, assessment)
        write_status_artifact(run_dir, status)
    return status, assessment

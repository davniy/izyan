"""Per-attempt status.json model and failure classification (Task 4.2).

spec section 8.3 / plan section 3: keep four dimensions separate —
- execution:      did the containerized agent run reach a terminal state?
- official_parse: did the unchanged official parser accept a category?
- assessment_schema: did the extra C1 assessment object validate?
- parser_audit:   did the string-aware audit decoder recover a full object?

A malformed C1 assessment is an artifact defect and must NOT erase an
officially accepted safe category from the audit trail. Provider refusal,
timeout, transport failure and invalid terminal answers are ``failed``
with a machine-readable reason — never ``uncertain`` and never a negative.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from .assessment import DuplicateAttemptError

ExecutionOutcome = Literal[
    "ok",  # container exited 0 and produced output
    "timeout",  # harness/container timed out
    "nonzero_exit",  # container exited non-zero
    "transport_failure",  # docker create/cp/start or MCP transport error
    "provider_refusal",  # provider declined / safety-filtered the answer
    "invalid_terminal_answer",  # finished but no parseable terminal JSON
    "no_output",  # no result file at all
]
OfficialParseStatus = Literal["accepted", "parse_fail", "no_result", "no_dir"]
AssessmentSchemaStatus = Literal["valid", "invalid", "absent"]
ParserAuditStatus = Literal["recovered", "matched", "no_object", "not_run"]

# Failure reasons reported verbatim on the attempt (machine-readable).
FAILURE_REASONS = frozenset(
    {
        "timeout",
        "container_nonzero_exit",
        "docker_create_failed",
        "docker_cp_failed",
        "docker_start_failed",
        "artifact_export_failed",
        "provider_refusal",
        "provider_safety_filter",
        "no_result",
        "invalid_terminal_answer",
        "mcp_transport_failure",
    }
)

_REFUSAL_HINTS = (
    "content_filter",
    "safety filter",
    "refused",
    "cannot help with",
    "can't help with",
    "i'm sorry, i can't",
    "request was refused",
    "request was blocked",  # observed: Gemini "blocked by Gemini's filters"
    "blocked by",           # provider safety-filter pages, incl. mid-text
    "model_refusal",
)


class AttemptStatus(BaseModel):
    """status.json — one immutable terminal record per attempt.

    ``overall`` is the headline outcome used by the safety-aware accounting:
    "valid" / "inconclusive" only when execution finished AND an official
    category exists; "failed" for every execution/transport/format failure;
    never used to launder a failed attempt into a negative answer.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["attempt-status/1"] = "attempt-status/1"
    task_id: str
    attempt_id: str
    experiment_id: str

    execution: ExecutionOutcome
    official_parse: OfficialParseStatus
    assessment_schema: AssessmentSchemaStatus
    parser_audit: ParserAuditStatus = "not_run"

    overall: Literal["valid", "inconclusive", "failed"]
    failure_reason: Optional[str] = None
    detail: Optional[str] = None

    @classmethod
    def classify(
        cls,
        *,
        task_id: str,
        attempt_id: str,
        experiment_id: str,
        execution: ExecutionOutcome,
        official_parse: OfficialParseStatus,
        assessment_schema: AssessmentSchemaStatus,
        parser_audit: ParserAuditStatus = "not_run",
        category: Optional[str] = None,
        failure_reason: Optional[str] = None,
        detail: Optional[str] = None,
    ) -> "AttemptStatus":
        """Derive ``overall`` and a checked failure_reason from dimensions.

        valid        := execution ok AND official_parse accepted, category
                        other than uncertain;
        inconclusive := execution ok AND accepted, category == "uncertain"
                        (spec §7/§11: safe abstention, not a failure, not a
                        cleared negative);
        failed       := anything else; failure_reason is REQUIRED and must
                        come from FAILURE_REASONS. A failed attempt keeps
                        its raw artifacts and reason — it is not an
                        ``uncertain`` answer.
        """
        finished = execution == "ok" and official_parse == "accepted"
        if finished and category == "uncertain":
            overall: str = "inconclusive"
        elif finished:
            overall = "valid"
        else:
            overall = "failed"

        if overall == "failed":
            if failure_reason is None:
                # derive the least-surprising reason from the dimensions
                if execution == "timeout":
                    failure_reason = "timeout"
                elif execution == "nonzero_exit":
                    failure_reason = "container_nonzero_exit"
                elif execution == "transport_failure":
                    failure_reason = "docker_start_failed"
                elif execution == "provider_refusal":
                    failure_reason = "provider_refusal"
                elif execution == "invalid_terminal_answer":
                    failure_reason = "invalid_terminal_answer"
                elif execution == "no_output":
                    failure_reason = "no_result"
                elif official_parse != "accepted":
                    failure_reason = "invalid_terminal_answer"
                else:  # pragma: no cover - defensive
                    failure_reason = "no_result"
            if failure_reason not in FAILURE_REASONS:
                raise ValueError(
                    f"failure_reason {failure_reason!r} not in {sorted(FAILURE_REASONS)}"
                )
            reason = failure_reason
        else:
            reason = None
        return cls(
            task_id=task_id,
            attempt_id=attempt_id,
            experiment_id=experiment_id,
            execution=execution,
            official_parse=official_parse,
            assessment_schema=assessment_schema,
            parser_audit=parser_audit,
            overall=overall,  # type: ignore[arg-type]
            failure_reason=reason,
            detail=detail,
        )


def classify_runtime_error(message: str) -> tuple[ExecutionOutcome, str]:
    """Map a harness RuntimeError text to (execution, failure_reason).

    The harness raises RuntimeError for docker create/cp failures,
    container timeouts and non-zero exits; the message text is the only
    carrier, so classification is textual but conservative — unrecognized
    errors fall back to transport failure rather than being hidden.
    """
    m = message.lower()
    if "timed out" in m or "timeout" in m:
        return "timeout", "timeout"
    if "docker create failed" in m:
        return "transport_failure", "docker_create_failed"
    if "docker cp failed" in m:
        return "transport_failure", "docker_cp_failed"
    if "container exited" in m:
        if any(h in m for h in _REFUSAL_HINTS):
            return "provider_refusal", "provider_refusal"
        return "nonzero_exit", "container_nonzero_exit"
    if any(h in m for h in _REFUSAL_HINTS):
        return "provider_refusal", "provider_refusal"
    return "transport_failure", "docker_start_failed"


def detect_provider_refusal(final_text: str) -> bool:
    """True when the terminal text is a provider refusal/safety filter page."""
    low = final_text.lower()
    return any(h in low for h in _REFUSAL_HINTS)


def write_status_artifact(run_dir: Path, status: AttemptStatus) -> Path:
    """Persist ``status.json``; never overwrites (immutable attempt record)."""
    path = run_dir / "status.json"
    if path.exists():
        raise DuplicateAttemptError(
            f"refusing to overwrite existing artifact: {path}"
        )
    with path.open("x", encoding="utf-8") as f:
        f.write(status.model_dump_json(indent=2) + "\n")
    return path

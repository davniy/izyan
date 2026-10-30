"""AgentAssessment schema, extraction and artifact writing for C1 (Task 4.2).

Normative sources:
- spec: docs/dev/specs/2026-10-08-task4-agent-evidence-tools-v2.md section 7
- plan: docs/dev/plans/2026-10-08-task4-c1-implementation-plan.md section 1.4

Model/content vs controller metadata split (plan section 1.4):
- The AGENT produces: root_causes, mandatory_conditions, claims
  (TRUE/FALSE/UNKNOWN), evidence refs, limitations, unresolved questions,
  counterexample_review, verdict_estimate, plus top-level
  category/reasoning in the same JSON object.
- The CONTROLLER stamps: schema_version, task/attempt identity, snapshot
  hash, model/revision, prompt/harness/tool-adapter versions, factual tool
  executions (from the MCP audit trail) and usage/cost. The agent payload
  must NOT carry these fields — ``extract_assessment`` rejects reserved
  controller keys inside ``assessment`` so a model cannot claim its own
  versions or costs.

This module never touches production ``AnalysisCase``/``Verdict``/``Claims``;
the artifact lives only under ``results/task4-c1/<experiment_id>/``.
"""

from __future__ import annotations
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Literal, Optional, Sequence

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .parser_audit import find_category_object as _find_category_object

SCHEMA_VERSION = "agent-assessment/1"

# The 12 official VEX-Bench categories, in precedence order — duplicated
# here verbatim so eval/c1 does not import the external harness package.
CATEGORY_ORDER: tuple[str, ...] = (
    "false_positive",
    "code_not_present",
    "code_not_reachable",
    "requires_configuration",
    "requires_dependency",
    "requires_environment",
    "compiler_protected",
    "runtime_protected",
    "perimeter_protected",
    "mitigating_control_protected",
    "uncertain",
    "vulnerable",
)
VALID_CATEGORIES = frozenset(CATEGORY_ORDER)

ClaimVerdict = Literal["TRUE", "FALSE", "UNKNOWN"]
VerdictEstimate = Literal[
    "NOT_AFFECTED", "NO_EXPLOIT_PATH_FOUND", "EXPLOITABLE", "INCONCLUSIVE"
]

SAFE_ESTIMATES = frozenset({"NOT_AFFECTED", "NO_EXPLOIT_PATH_FOUND"})

# category -> allowed verdict_estimate, fixed by prompt contract
# (eval/c1/protocol.py ASSESSMENT_REPORT_BLOCK). vulnerable/uncertain have
# a single legal estimate; every safe category maps to a safe estimate.
CATEGORY_TO_ESTIMATES: dict[str, frozenset[str]] = {
    "vulnerable": frozenset({"EXPLOITABLE"}),
    "uncertain": frozenset({"INCONCLUSIVE"}),
    **{c: SAFE_ESTIMATES for c in CATEGORY_ORDER if c not in {"vulnerable", "uncertain"}},
}

# Evidence reference forms a reviewer/controller can resolve:
#   ev:<kind>:<locator>@<16-hex>     — tool artifact ref (evidencetools evidenceRef)
#   file:<path>[:<line>[-<line>]]    — snapshot source location
#   url:<https-url>                  — public advisory/fix reference
_EVIDENCE_REF_RE = re.compile(
    r"^(ev:[A-Za-z0-9_.\-]+:[^@\s]+@[0-9a-f]{16}"
    r"|file:[^\s]+?(?::\d+(?:-\d+)?)?"
    r"|url:https?://\S+)$"
)

# Controller-owned keys that must never appear in the model-authored
# ``assessment`` object (plan section 1.4: the agent does not grade itself).
RESERVED_CONTROLLER_KEYS = frozenset(
    {
        "schema_version",
        "task_id",
        "snapshot_hash",
        "model",
        "model_revision",
        "prompt_version",
        "prompt_hash",
        "harness_version",
        "tool_adapter_version",
        "tool_executions",
        "usage",
        "tokens",
        "cost",
        "cost_usd",
        "wall_seconds",
        "experiment_id",
        "attempt_id",
        "repeat_id",
    }
)


# Evidence reference forms a reviewer/controller can resolve:
#   src:<path>[#L<line>]              — emitted by tools (dataflow/source)
#   sha256:<64-hex>                   — emitted by tools (payload digest ref)
#   ev:<kind>:<locator>@<16-hex>      — reserved tool artifact ref form
#   file:<path>[:<line>[-<line>]]     — agent-written snapshot location
#   url:<https-url>                   — public advisory/fix reference
_EVIDENCE_REF_RE = re.compile(
    r"^(src:[^\s#]+(?:#L\d+)?"
    r"|sha256:[0-9a-f]{64}"
    r"|ev:[A-Za-z0-9_.\-]+:\S+@[0-9a-f]{16}"
    r"|file:[^\s]+?(?::\d+(?:-\d+)?)?"
    r"|url:https?://\S+)$"
)

# Schemes that only the tool server can mint — these must appear verbatim
# in the attempt's audit trail to be citable (validate_evidence_refs).
TOOL_EMITTED_REF_SCHEMES = ("ev:", "sha256:", "src:")


def _check_ref(v: str) -> str:
    if not _EVIDENCE_REF_RE.match(v):
        raise ValueError(
            f"unresolvable evidence ref {v!r}; expected "
            "src:<path>[#L<n>], sha256:<hex64>, ev:<kind>:<loc>@<sha16>, "
            "file:<path>[:<line>[-<line>]] or url:<https-url>"
        )
    return v


class Claim(BaseModel):
    """One factual claim the agent makes about the case."""

    model_config = ConfigDict(extra="forbid")

    statement: str = Field(min_length=1)
    verdict: ClaimVerdict
    evidence_refs: list[str] = Field(default_factory=list)

    @field_validator("evidence_refs")
    @classmethod
    def _refs_ok(cls, v: list[str]) -> list[str]:
        return [_check_ref(r) for r in v]


class CounterexampleReview(BaseModel):
    """What the agent actively tried to disprove before a safe estimate."""

    model_config = ConfigDict(extra="forbid")

    checked: list[str] = Field(default_factory=list)
    still_unknown: list[str] = Field(default_factory=list)


class AssessmentPayload(BaseModel):
    """The model-authored ``assessment`` object inside the final JSON."""

    model_config = ConfigDict(extra="forbid")

    root_causes: list[str] = Field(min_length=1)
    mandatory_conditions: list[str] = Field(default_factory=list)
    claims: list[Claim] = Field(min_length=1)
    evidence: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    unresolved_questions: list[str] = Field(default_factory=list)
    counterexample_review: CounterexampleReview
    verdict_estimate: VerdictEstimate

    @field_validator("evidence")
    @classmethod
    def _evidence_ok(cls, v: list[str]) -> list[str]:
        return [_check_ref(r) for r in v]

    @model_validator(mode="after")
    def _safe_needs_counterexample(self) -> "AssessmentPayload":
        # Counterexample pass is mandatory CONTENT before a safe estimate
        # (spec section 7): at least one concrete checked entry.
        if self.verdict_estimate in SAFE_ESTIMATES and not any(
            s.strip() for s in self.counterexample_review.checked
        ):
            raise ValueError(
                "counterexample_review.checked must list at least one concrete "
                "counter-interpretation examined before a safe verdict_estimate "
                f"({self.verdict_estimate})"
            )
        return self


# ---------------------------------------------------------------------------
# Controller-stamped metadata (trusted, never authored by the model)
# ---------------------------------------------------------------------------


class UsageStats(BaseModel):
    """Factual run accounting; any unknown bucket stays None, never invented."""

    model_config = ConfigDict(extra="forbid")

    input_tokens: Optional[int] = None
    cached_input_tokens: Optional[int] = None
    output_tokens: Optional[int] = None
    reasoning_tokens: Optional[int] = None
    tool_calls: Optional[int] = None  # evidence-tool invocations from audit
    cost_usd: Optional[float] = None
    wall_seconds: Optional[float] = None


class ToolExecution(BaseModel):
    """One factual MCP evidence-tool call, from the attempt's audit sink."""

    model_config = ConfigDict(extra="forbid")

    tool: str
    args_sha256: Optional[str] = None
    duration_ms: Optional[int] = None
    tool_status: Optional[str] = None
    completeness: Optional[str] = None
    observation_id: Optional[str] = None


class AttemptMeta(BaseModel):
    """Controller-side identity/version metadata stamped onto the artifact."""

    model_config = ConfigDict(extra="forbid")

    experiment_id: str = Field(min_length=1)
    task_id: str = Field(min_length=1)
    attempt_id: str = Field(min_length=1)  # e.g. "run_001"
    cve_id: str = Field(min_length=1)
    snapshot_hash: str = Field(min_length=1)
    model: str = Field(min_length=1)
    model_revision: Optional[str] = None  # unavailable stays None
    prompt_version: str = Field(min_length=1)  # e.g. "vuln_c1-<hash12>"
    harness_version: str = Field(min_length=1)
    tool_adapter_version: str = Field(min_length=1)
    image: Optional[str] = None


class AgentAssessment(BaseModel):
    """The stored experiment artifact (agent payload + stamped metadata)."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["agent-assessment/1"] = SCHEMA_VERSION
    meta: AttemptMeta
    category: str
    reasoning: str = Field(min_length=1)
    assessment: AssessmentPayload
    tool_executions: list[ToolExecution] = Field(default_factory=list)
    usage: UsageStats = Field(default_factory=UsageStats)

    @field_validator("category")
    @classmethod
    def _category_ok(cls, v: str) -> str:
        if v not in VALID_CATEGORIES:
            raise ValueError(f"category {v!r} is not one of the 12 categories")
        return v

    @model_validator(mode="after")
    def _category_estimate_consistent(self) -> "AgentAssessment":
        allowed = CATEGORY_TO_ESTIMATES[self.category]
        est = self.assessment.verdict_estimate
        if est not in allowed:
            raise ValueError(
                f"verdict_estimate {est} inconsistent with category "
                f"{self.category!r} (allowed: {sorted(allowed)})"
            )
        return self


# ---------------------------------------------------------------------------
# Extraction from the agent's terminal output
# ---------------------------------------------------------------------------


class ExtractionResult(BaseModel):
    """What the controller recovered from the raw final text."""

    model_config = ConfigDict(extra="forbid")

    category: Optional[str] = None
    reasoning: Optional[str] = None
    assessment: Optional[AssessmentPayload] = None
    errors: list[str] = Field(default_factory=list)


def extract_json_object(text: str) -> Optional[dict]:
    """First complete JSON object with a ``category`` key in *text*.

    Delegates to ``parser_audit.find_category_object`` — the string-aware
    ``raw_decode`` scan is the single audit rule for C1 (spec §8.3.2);
    keeping a second implementation here would create a divergent
    convention. Unlike the official harness extractor, ``raw_decode``
    respects string quoting, so braces inside ``reasoning`` still parse.
    """
    return _find_category_object(text)


def extract_assessment(final_text: str) -> ExtractionResult:
    """Recover (category, reasoning, assessment) from the final agent text.

    Category/reasoning are the same fields the official parser reads; the
    ``assessment`` object is additionally schema-validated. Errors are
    collected, not raised, so the caller can record an artifact defect while
    preserving the officially parsed category (plan section 3: a malformed
    assessment does not erase an accepted official category).
    """
    errors: list[str] = []
    obj = extract_json_object(final_text)
    if obj is None:
        return ExtractionResult(errors=["no JSON object with a category field found"])

    cat = obj.get("category")
    category = cat.strip().lower() if isinstance(cat, str) else None
    reasoning = obj.get("reasoning")
    if not isinstance(reasoning, str) or not reasoning.strip():
        reasoning = None

    raw_assessment = obj.get("assessment")
    if raw_assessment is None:
        errors.append("missing 'assessment' field in final JSON")
        return ExtractionResult(category=category, reasoning=reasoning, errors=errors)
    if not isinstance(raw_assessment, dict):
        errors.append(f"'assessment' is {type(raw_assessment).__name__}, not an object")
        return ExtractionResult(category=category, reasoning=reasoning, errors=errors)

    reserved = sorted(set(raw_assessment) & RESERVED_CONTROLLER_KEYS)
    if reserved:
        errors.append(
            f"assessment carries controller-reserved keys {reserved}; "
            "metadata is stamped by the controller, not the model"
        )
        return ExtractionResult(category=category, reasoning=reasoning, errors=errors)

    try:
        payload = AssessmentPayload.model_validate(raw_assessment)
    except Exception as exc:  # pydantic ValidationError — keep text for status.json
        errors.append(f"assessment schema invalid: {exc}")
        return ExtractionResult(category=category, reasoning=reasoning, errors=errors)

    if category is not None:
        allowed = CATEGORY_TO_ESTIMATES.get(category, frozenset())
        est = payload.verdict_estimate
        if est not in allowed:
            errors.append(
                f"verdict_estimate {est} inconsistent with category {category!r} "
                f"(allowed: {sorted(allowed) if allowed else 'none/invalid category'})"
            )
    return ExtractionResult(
        category=category, reasoning=reasoning, assessment=payload, errors=errors
    )


# ---------------------------------------------------------------------------
# Stamping + evidence-ref cross-checking
# ---------------------------------------------------------------------------


def tool_executions_from_audit(audit_records: Sequence[dict]) -> list[ToolExecution]:
    """Project raw MCP audit lines (AuditRecord JSONL) into ToolExecutions."""
    out: list[ToolExecution] = []
    for rec in audit_records:
        tool = rec.get("tool")
        if not isinstance(tool, str):
            continue
        obs = rec.get("observation") or {}
        args = rec.get("args")
        args_sha = (
            hashlib.sha256(json.dumps(args, sort_keys=True).encode("utf-8")).hexdigest()
            if args is not None
            else None
        )
        out.append(
            ToolExecution(
                tool=tool,
                args_sha256=args_sha,
                duration_ms=rec.get("duration_ms"),
                tool_status=obs.get("tool_status"),
                completeness=obs.get("completeness"),
                observation_id=obs.get("id"),
            )
        )
    return out


def audit_evidence_refs(audit_records: Sequence[dict]) -> set[str]:
    """All refs the session's tools actually produced (audit trail)."""
    refs: set[str] = set()
    for rec in audit_records:
        obs = rec.get("observation") or {}
        for ref in obs.get("evidence_refs") or []:
            if isinstance(ref, str):
                refs.add(ref)
    return refs


def validate_evidence_refs(
    assessment: AssessmentPayload, audit_records: Sequence[dict]
) -> list[str]:
    """Check that tool-minted refs cited by the agent resolve to outputs.

    Only refs with a scheme the tool server itself emits (TOOL_EMITTED_REF_
    SCHEMES — ``src:``, ``sha256:``, ``ev:``) are cross-checked against the
    attempt's audit trail; an invented one is an artifact defect, not a
    silent pass. Agent-written ``file:``/``url:`` refs are not resolvable
    against the trail and are not checked here.
    Returns a list of human-readable defects (empty = clean).
    """
    known = audit_evidence_refs(audit_records)
    defects: list[str] = []
    cited: list[str] = []
    cited.extend(
        r for r in assessment.evidence if r.startswith(TOOL_EMITTED_REF_SCHEMES)
    )
    for claim in assessment.claims:
        cited.extend(
            r
            for r in claim.evidence_refs
            if r.startswith(TOOL_EMITTED_REF_SCHEMES)
        )
    for ref in dict.fromkeys(cited):
        if ref not in known:
            defects.append(f"evidence ref {ref!r} not found in attempt audit trail")
    return defects


def build_assessment(
    extraction: ExtractionResult,
    meta: AttemptMeta,
    audit_records: Sequence[dict],
    usage: Optional[UsageStats] = None,
) -> tuple[Optional[AgentAssessment], list[str]]:
    """Stamp controller metadata onto a validated agent payload.

    Returns (assessment, defects). assessment is None when the payload is
    absent/invalid — callers must not fabricate one for failed attempts.
    """
    defects = list(extraction.errors)
    if extraction.assessment is None or extraction.category is None:
        return None, defects or ["no valid assessment payload"]
    if extraction.reasoning is None:
        return None, defects + ["missing reasoning"]

    defects.extend(validate_evidence_refs(extraction.assessment, audit_records))

    execs = tool_executions_from_audit(audit_records)
    use = usage or UsageStats()
    if use.tool_calls is None:
        use = use.model_copy(update={"tool_calls": len(execs)})

    try:
        asm = AgentAssessment(
            meta=meta,
            category=extraction.category,
            reasoning=extraction.reasoning,
            assessment=extraction.assessment,
            tool_executions=execs,
            usage=use,
        )
    except Exception as exc:
        return None, defects + [f"assessment artifact invalid: {exc}"]
    return asm, defects


# ---------------------------------------------------------------------------
# Attempt artifact writing (no overwrite, no cache admission)
# ---------------------------------------------------------------------------


class DuplicateAttemptError(RuntimeError):
    """An immutable artifact for this attempt already exists."""


def _write_new(path: Path, text: str) -> None:
    """Exclusive create — fails instead of overwriting an existing artifact."""
    if path.exists():
        raise DuplicateAttemptError(f"refusing to overwrite existing artifact: {path}")
    fd = path.open("x", encoding="utf-8")
    try:
        fd.write(text)
    finally:
        fd.close()


def write_assessment_artifact(run_dir: Path, assessment: AgentAssessment) -> Path:
    """Persist ``agent_assessment.json``; never overwrites an existing file."""
    path = run_dir / "agent_assessment.json"
    _write_new(path, assessment.model_dump_json(indent=2) + "\n")
    return path

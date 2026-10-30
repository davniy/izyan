"""AgentAssessment schema ``agent-assessment/2`` for Task 6 (spec §3).

Extends the C1 ``agent-assessment/1`` contract
(``eval/c1/assessment.py``) with the structured evidence contract the
Task-6 prompt requires of BOTH arms:

    assessment.mechanisms[]      — verified manifestations/paths of the
                                   CVE (subject, scope, limitations)
    assessment.negative_claims[] — ATOMIC negative assertions, each
                                   bound to its subject, scope and
                                   machine-checkable evidence_refs
    assessment.unresolved[]      — unexplored alternative paths, tool
                                   errors, unresolved conditions
    assessment.reasoning         — human text, NOT proof

Evidence-ref grammar (reconciled with the live tool-minted forms):

    ev:OBS-NNNN                         — a minted MCP observation id
    src:<path>[#L<line>][@<64-hex hash>] — a source position; tool-minted
                                          refs carry no hash, agent-bound
                                          refs append the snapshot hash
    sha256:<64 lowercase hex>           — a tool-emitted payload digest
    file:<path>[:<line>[-<line>]]       — an agent-written location
    url:<https-url>                     — a public advisory/fix reference

Parse-time rejection (pydantic ``extra=forbid``): unknown keys at any
level, a category outside the 12 official ones, refs outside the
grammar, controller-reserved keys inside ``assessment``, and the
content rules (a safe category needs ≥1 negative claim with non-empty
evidence_refs; a safe category with non-empty ``unresolved`` is a
defect). Validator-time checks (ref resolution against the audit
trail, scope matching, CVE-scope coverage) live in phase 6.2's
``validator.py``, not here — the agent answer is stored as-is.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal, Optional, Sequence

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from eval.c1.assessment import (
    AttemptMeta,
    CATEGORY_ORDER,
    RESERVED_CONTROLLER_KEYS,
    UsageStats,
    ToolExecution,
    VALID_CATEGORIES,
    audit_evidence_refs,
    tool_executions_from_audit,
    write_assessment_artifact,
)
from eval.c1.parser_audit import find_category_object as _find_category_object

SCHEMA_VERSION_V2 = "agent-assessment/2"

# The 10 categories before "uncertain"/"vulnerable" in CATEGORY_ORDER —
# the "safe" verdicts that need a checkable falsifier.
SAFE_CATEGORIES = frozenset(
    c for c in CATEGORY_ORDER if c not in {"vulnerable", "uncertain"})

# Evidence reference grammar (v2):
#   ev:OBS-NNNN                                — minted observation id
#   src:<path>#L<line>[@<64-hex snapshot>]     — source position (the
#     live dataflow form carries no hash; the agent-bound form appends
#     the snapshot hash printed by get_product_snapshot)
#   sha256:<64-hex>                            — payload digest ref
#   file:<path>[:<line>[-<line>]]              — agent-written location
#   url:https://<url>                          — advisory/fix reference
_SRC_REF_RE = (
    r"src:[^\s#@:]+#L\d+(?:@[0-9a-fA-F]{64})?"
)
_EVIDENCE_REF_RE_V2 = re.compile(
    r"^(ev:OBS-\d{4,}"
    rf"|{_SRC_REF_RE}"
    r"|sha256:[0-9a-f]{64}"
    r"|file:[^\s]+?(?::\d+(?:-\d+)?)?"
    r"|url:https://\S+)$"
)


def check_ref_v2(v: str) -> str:
    """Parse-time grammar check for one evidence ref."""
    if not _EVIDENCE_REF_RE_V2.match(v):
        raise ValueError(
            f"unresolvable evidence ref {v!r}; expected "
            "ev:OBS-NNNN, src:<path>[#L<n>][@<sha256 snapshot-hash>], "
            "sha256:<hex64>, file:<path>[:<line>[-<line>]] or "
            "url:https://<url>"
        )
    return v


def split_src_ref(ref: str) -> Optional[tuple[str, Optional[int], Optional[str]]]:
    """``src:<path>[#L<line>][@<hash>]`` → (path, line, hash) or None."""
    if not ref.startswith("src:"):
        return None
    body = ref[4:]
    path, _, tail = body.partition("@")
    snapshot_hash = tail or None
    fpath, sep, lpart = path.partition("#L")
    line = int(lpart) if sep and lpart.isdigit() else None
    return fpath, line, snapshot_hash


class Mechanism(BaseModel):
    """One verified manifestation/path of the CVE."""

    model_config = ConfigDict(extra="forbid")

    subject: str = Field(min_length=1)
    scope: str = Field(min_length=1)
    limitations: list[str] = Field(default_factory=list)


class NegativeClaim(BaseModel):
    """One ATOMIC negative assertion bound to checkable evidence."""

    model_config = ConfigDict(extra="forbid")

    predicate: str = Field(min_length=1)
    subject: str = Field(min_length=1)
    scope: str = Field(min_length=1)
    evidence_refs: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)

    @field_validator("evidence_refs")
    @classmethod
    def _refs_ok(cls, v: list[str]) -> list[str]:
        return [check_ref_v2(r) for r in v]


class AssessmentPayloadV2(BaseModel):
    """The model-authored ``assessment`` object inside the final JSON."""

    model_config = ConfigDict(extra="forbid")

    mechanisms: list[Mechanism] = Field(default_factory=list)
    negative_claims: list[NegativeClaim] = Field(default_factory=list)
    unresolved: list[str] = Field(default_factory=list)
    reasoning: str = Field(min_length=1)


# ---------------------------------------------------------------------------
# Stored artifact (agent payload + controller-stamped metadata)
# ---------------------------------------------------------------------------

# Reuse the C1 controller-side models unchanged:
#   UsageStats, ToolExecution, AttemptMeta — identical shape/semantics.


class AgentAssessmentV2(BaseModel):
    """The stored experiment artifact (agent payload + stamped metadata)."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["agent-assessment/2"] = SCHEMA_VERSION_V2
    meta: AttemptMeta
    category: str
    reasoning: str = Field(min_length=1)
    assessment: AssessmentPayloadV2
    tool_executions: list[ToolExecution] = Field(default_factory=list)
    usage: UsageStats = Field(default_factory=UsageStats)

    @field_validator("category")
    @classmethod
    def _category_ok(cls, v: str) -> str:
        if v not in VALID_CATEGORIES:
            raise ValueError(f"category {v!r} is not one of the 12 categories")
        return v

    @model_validator(mode="after")
    def _safe_needs_checkable_claims(self) -> "AgentAssessmentV2":
        """Safe-needs-counterexample rule (plan §7): a safe category
        requires at least one negative claim with non-empty
        evidence_refs; a safe category with non-empty ``unresolved``
        is a defect (should have been ``uncertain``)."""
        if self.category in SAFE_CATEGORIES:
            if not any(
                c.evidence_refs for c in self.assessment.negative_claims
            ):
                raise ValueError(
                    f"safe category {self.category!r} requires at least "
                    "one negative_claim with non-empty evidence_refs "
                    "(a checkable falsifier)"
                )
            if any(u.strip() for u in self.assessment.unresolved):
                raise ValueError(
                    f"safe category {self.category!r} with non-empty "
                    "unresolved[] is a defect — the category should be "
                    "'uncertain'"
                )
        return self


# ---------------------------------------------------------------------------
# Extraction from the agent's terminal output
# ---------------------------------------------------------------------------


class ExtractionResultV2(BaseModel):
    """What the controller recovered from the raw final text."""

    model_config = ConfigDict(extra="forbid")

    category: Optional[str] = None
    reasoning: Optional[str] = None
    assessment: Optional[AssessmentPayloadV2] = None
    errors: list[str] = Field(default_factory=list)


def extract_json_object(text: str) -> Optional[dict]:
    """First complete JSON object with a ``category`` key in *text* —
    the same string-aware ``raw_decode`` scan C1 uses (tolerates
    trailing prose and braces inside strings)."""
    return _find_category_object(text)


def _assessment_defects(payload: AssessmentPayloadV2,
                        category: Optional[str]) -> list[str]:
    """The content rules that make a structured answer a defect."""
    errors = []
    if category in SAFE_CATEGORIES:
        if not any(c.evidence_refs for c in payload.negative_claims):
            errors.append(
                f"safe category {category!r} requires at least one "
                "negative_claim with non-empty evidence_refs"
            )
        if any(u.strip() for u in payload.unresolved):
            errors.append(
                f"safe category {category!r} with non-empty "
                "unresolved[] is a defect — should be 'uncertain'"
            )
    return errors


def extract_assessment_v2(final_text: str) -> ExtractionResultV2:
    """Recover (category, reasoning, assessment) from final agent text.

    Category/reasoning are the fields the official parser reads; the
    ``assessment`` object is schema-validated against
    ``agent-assessment/2``. Errors are collected, not raised, so the
    caller can record an artifact defect while preserving the
    officially parsed category — same contract as C1's
    ``extract_assessment``.
    """
    errors: list[str] = []
    obj = extract_json_object(final_text)
    if obj is None:
        return ExtractionResultV2(
            errors=["no JSON object with a category field found"])

    cat = obj.get("category")
    category = cat.strip().lower() if isinstance(cat, str) else None
    if category is not None and category not in VALID_CATEGORIES:
        errors.append(f"category {category!r} is not one of the 12 categories")
    reasoning = obj.get("reasoning")
    if not isinstance(reasoning, str) or not reasoning.strip():
        reasoning = None

    raw_assessment = obj.get("assessment")
    if raw_assessment is None:
        errors.append("missing 'assessment' field in final JSON")
        return ExtractionResultV2(
            category=category, reasoning=reasoning, errors=errors)
    if not isinstance(raw_assessment, dict):
        errors.append(
            f"'assessment' is {type(raw_assessment).__name__}, not an object")
        return ExtractionResultV2(
            category=category, reasoning=reasoning, errors=errors)

    reserved = sorted(set(raw_assessment) & RESERVED_CONTROLLER_KEYS)
    if reserved:
        errors.append(
            f"assessment carries controller-reserved keys {reserved}; "
            "metadata is stamped by the controller, not the model")
        return ExtractionResultV2(
            category=category, reasoning=reasoning, errors=errors)

    try:
        payload = AssessmentPayloadV2.model_validate(raw_assessment)
    except Exception as exc:  # pydantic ValidationError — keep for status.json
        errors.append(f"assessment schema invalid: {exc}")
        return ExtractionResultV2(
            category=category, reasoning=reasoning, errors=errors)

    errors.extend(_assessment_defects(payload, category))
    return ExtractionResultV2(
        category=category, reasoning=reasoning,
        assessment=payload, errors=errors)


# ---------------------------------------------------------------------------
# Evidence-ref cross-checking (collect-time, pre-validator)
# ---------------------------------------------------------------------------


def audit_observation_ids(audit_records: Sequence[dict]) -> set[str]:
    """All minted observation ids in the attempt's audit trail."""
    ids: set[str] = set()
    for rec in audit_records:
        obs = rec.get("observation") or {}
        oid = obs.get("id")
        if isinstance(oid, str):
            ids.add(oid)
    return ids


def validate_evidence_refs_v2(
    assessment: AssessmentPayloadV2,
    audit_records: Sequence[dict],
    snapshot_hash: Optional[str] = None,
) -> list[str]:
    """Check the refs cited by negative_claims against the audit trail.

    Parse-time only guarantees grammar; this is the collect-time defect
    check (full claim↔scope validation is the phase-6.2 validator):

    - ``ev:OBS-NNNN``        — must name a minted observation id;
    - ``sha256:<hex>``       — must appear verbatim in some
                               ``Observation.evidence_refs``;
    - ``src:...``            — tool-minted form (no ``@hash``) must
                               appear verbatim; an agent-bound
                               ``@<hash>`` suffix must equal the
                               attempt's ``meta.snapshot_hash``;
    - ``file:``/``url:``     — agent-written, not resolvable against
                               the trail (the offline validator checks
                               file existence against the snapshot).

    Returns human-readable defects (empty = clean).
    """
    known_refs = audit_evidence_refs(audit_records)
    known_ids = audit_observation_ids(audit_records)
    defects: list[str] = []
    cited: list[str] = []
    for claim in assessment.negative_claims:
        cited.extend(claim.evidence_refs)
    for ref in dict.fromkeys(cited):
        if ref.startswith("ev:"):
            if ref[3:] not in known_ids:
                defects.append(
                    f"evidence ref {ref!r} names an observation id not "
                    "in the attempt audit trail")
        elif ref.startswith("sha256:"):
            if ref not in known_refs:
                defects.append(
                    f"evidence ref {ref!r} not found in attempt audit trail")
        elif ref.startswith("src:"):
            parsed = split_src_ref(ref)
            if parsed is None:
                defects.append(f"unparseable src ref {ref!r}")
                continue
            _, _, ref_hash = parsed
            if ref_hash is not None:
                if snapshot_hash is not None and ref_hash != snapshot_hash:
                    defects.append(
                        f"src ref {ref!r} carries snapshot hash "
                        f"{ref_hash[:16]}… != attempt snapshot hash")
            elif ref not in known_refs:
                defects.append(
                    f"evidence ref {ref!r} not found in attempt audit trail")
        # file:/url: — not cross-checked here
    return defects


def build_assessment_v2(
    extraction: ExtractionResultV2,
    meta: AttemptMeta,
    audit_records: Sequence[dict],
    usage: Optional[UsageStats] = None,
) -> tuple[Optional[AgentAssessmentV2], list[str]]:
    """Stamp controller metadata onto a validated agent payload.

    Returns (assessment, defects). assessment is None when the payload
    is absent/invalid — callers must not fabricate one for failed
    attempts (same contract as C1 ``build_assessment``).
    """
    defects = list(extraction.errors)
    if extraction.assessment is None or extraction.category is None:
        return None, defects or ["no valid assessment payload"]
    if extraction.reasoning is None:
        return None, defects + ["missing reasoning"]

    defects.extend(
        validate_evidence_refs_v2(
            extraction.assessment, audit_records,
            snapshot_hash=meta.snapshot_hash if meta else None))

    execs = tool_executions_from_audit(audit_records)
    use = usage or UsageStats()
    if use.tool_calls is None:
        use = use.model_copy(update={"tool_calls": len(execs)})

    try:
        asm = AgentAssessmentV2(
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


def write_assessment_artifact_v2(
    run_dir: Path, assessment: AgentAssessmentV2
) -> Path:
    """Persist ``agent_assessment.json``; never overwrites (C1 helper —
    identical immutable-artifact semantics)."""
    return write_assessment_artifact(run_dir, assessment)


__all__ = [
    "AgentAssessmentV2",
    "AssessmentPayloadV2",
    "AttemptMeta",
    "ExtractionResultV2",
    "Mechanism",
    "NegativeClaim",
    "RESERVED_CONTROLLER_KEYS",
    "SAFE_CATEGORIES",
    "SCHEMA_VERSION_V2",
    "ToolExecution",
    "UsageStats",
    "audit_observation_ids",
    "build_assessment_v2",
    "check_ref_v2",
    "extract_assessment_v2",
    "extract_json_object",
    "split_src_ref",
    "validate_evidence_refs_v2",
    "write_assessment_artifact_v2",
]

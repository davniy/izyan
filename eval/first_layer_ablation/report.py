"""First-layer VEX ablation report (Task 3).

Reads the immutable attempts saved by Task 2 and writes two artifacts:

- ``comparison.json`` — machine-readable per-attempt and per-arm records;
- ``comparison.md`` — human-readable diagnostic.

The report deliberately separates three views that must never be merged:

1. the **official parser result** stored by the run controller in
   ``status.json`` (the primary, unchanged scoring view);
2. a **full-JSON audit projection** decoded independently from the raw
   terminal answer (a second opinion, never a replacement);
3. **research traces** — native tool calls, MCP observations and the
   source citations the answer itself carries.

It never calls a model, Docker, the network or the izyan MCP server, and it
never imports or runs the downstream verifier.  ``validator_results.jsonl``
inside an attempt directory, if present, is ignored.

Outcome vocabulary is mutually exclusive and closed::

    vulnerable | dangerous_negative | uncertain | parse_failure |
    timeout | provider_failure | infrastructure_failure | other_failure |
    missing_attempt

``dangerous_negative`` means an officially accepted safe category on the
frozen case whose known outcome is ``vulnerable``; a parse failure, timeout
or provider failure is never counted as a negative.  Diagnosis is separate
from the outcome and distinguishes ``not_researched``,
``researched_but_wrong_conclusion`` and
``correct_answer_lost_by_parser`` (plus narrower states).

This is a **single-case diagnostic**.  It localizes where the first layer
loses quality on one case; it is not evidence of general VEX parity.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from eval.c1 import parser_audit  # noqa: E402
from eval.first_layer_ablation import protocol as P  # noqa: E402

REPORT_SCHEMA = "first-layer-ablation-comparison/1"
ATTEMPT_SCHEMA = "first-layer-attempt/1"

# The frozen single case's known outcome, used ONLY by this offline report
# to label a negative as dangerous.  It is never written to a prompt.
EXPECTED_CATEGORY = "vulnerable"
EXPECTED_CVE = "CVE-2023-44487"
EXPECTED_COMMIT_PREFIX = "e196d24"

SAFE_CATEGORIES = tuple(
    category for category in parser_audit.VALID_CATEGORIES
    if category not in (EXPECTED_CATEGORY, "uncertain")
)
SAFE_CATEGORY_SET = frozenset(SAFE_CATEGORIES)

OUTCOME_ORDER = (
    "vulnerable",
    "dangerous_negative",
    "uncertain",
    "parse_failure",
    "timeout",
    "provider_failure",
    "infrastructure_failure",
    "other_failure",
    "missing_attempt",
)

# Outcome precedence: execution failures are classified before parser
# failures so a refusal/timeout is never laundered into "parse failure" or
# a negative.  The provider bucket precedes parse_failure on purpose: a
# refusal page can contain a category token.
NO_ANSWER_OUTCOMES = frozenset({
    "timeout", "provider_failure", "infrastructure_failure",
    "other_failure", "missing_attempt",
})

PROVIDER_REASONS = frozenset({
    "provider_refusal",
    "provider_safety_filter",
    "provider_at_capacity",
    "provider_rate_limit",
    "provider_error",
})

INFRASTRUCTURE_REASONS = frozenset({
    "docker_start_failed",
    "docker_create_failed",
    "docker_cp_failed",
    "container_nonzero_exit",
    "artifact_export_failed",
    "mcp_transport_failure",
    "transport_failure",
    "runtime_drift",
    "infrastructure_failure",
})

DIAGNOSIS_ORDER = (
    "correct",
    "researched_but_wrong_conclusion",
    "not_researched",
    "correct_answer_lost_by_parser",
    "researched_inconclusive",
    "researched_answer_unparsed",
    "no_answer",
)

# URLs and explicit reference forms a terminal answer may carry.
_URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+")
_EXPLICIT_REF_RE = re.compile(
    r"(?<![\w])(?:file|src|ev|sha256):[^\s\"'<>`)\],;]+"
)
_PATH_LINE_RE = re.compile(
    r"(?<![\w/.:-])([\w./-]+\.(?:go|mod|sum|yaml|yml|json|md|txt|proto|graphql))"
    r":(\d+(?:-\d+)?)"
)

_MD_MAX_CITATIONS = 25


class ReportError(Exception):
    """Invalid experiment input that makes the comparison meaningless."""


OFFICIAL_PARSER_NAME = "evaluate.result_parser.parse_category"


class _LazyOfficialParser:
    """Import the unchanged harness parser only when a category is needed."""

    def __init__(self) -> None:
        self._parser = None

    def __call__(self, text: str):
        if self._parser is None:
            self._parser = load_official_parser()
        return self._parser(text)


def load_official_parser(harness_dir: Optional[Path] = None):
    """Load the official VEX-Bench category parser from the harness checkout.

    Resolution matches ``eval.c1.runner.harness_src``: an explicit
    ``harness_dir``, else ``C1_HARNESS_DIR``, else the documented
    ``/tmp/vexbench-agent-ctl``.  This imports the official parser as-is;
    it is not the downstream verifier and it never re-scores an attempt.
    """
    root = Path(
        harness_dir
        or os.environ.get("C1_HARNESS_DIR", "/tmp/vexbench-agent-ctl")
    )
    src = root / "src"
    if not (src / "evaluate").is_dir():
        raise ReportError(
            "official parser unavailable: harness checkout not found at {} "
            "(set C1_HARNESS_DIR or pass official_parser / --harness-dir)"
            .format(root)
        )
    src_text = str(src)
    if src_text not in sys.path:
        sys.path.insert(0, src_text)
    try:
        from evaluate.result_parser import parse_category  # type: ignore
    except ImportError as exc:  # pragma: no cover - environment wiring
        raise ReportError(
            "official parser unavailable in harness checkout {}: {}".format(
                root, exc
            )
        ) from exc
    return parse_category


# ---------------------------------------------------------------------------
# Generic IO / hashing
# ---------------------------------------------------------------------------


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _sha256_json(obj: Any) -> str:
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def _read_text(path: Path) -> Optional[str]:
    path = Path(path)
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8", errors="replace")


def _read_json(path: Path) -> Optional[Any]:
    text = _read_text(path)
    if text is None:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ReportError("invalid JSON in {}: {}".format(path, exc))


def _read_jsonl(path: Path) -> Tuple[List[dict], int]:
    """Return ``(records, malformed_line_count)``; never raises."""
    text = _read_text(path)
    if text is None:
        return [], 0
    records: List[dict] = []
    malformed = 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            malformed += 1
            continue
        if isinstance(record, dict):
            records.append(record)
        else:
            malformed += 1
    return records, malformed


def _relpath(path: Path, root: Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(Path(root).resolve()))
    except ValueError:
        return str(path)


def _write_atomic(path: Path, text: str) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    os.replace(temporary, path)
    return path


def _utcnow() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _empty_outcomes() -> Dict[str, int]:
    return {outcome: 0 for outcome in OUTCOME_ORDER}


def _empty_diagnoses() -> Dict[str, int]:
    return {kind: 0 for kind in DIAGNOSIS_ORDER}


# ---------------------------------------------------------------------------
# Manifest and run-summary loading
# ---------------------------------------------------------------------------


def load_manifest(experiment_dir: Path) -> Dict[str, Any]:
    """Load and minimally verify the frozen Task 1 manifest.

    The self-hash is checked when present.  Re-deriving prompts from the
    pinned sources is Task 1's job (``protocol.verify_manifest``); this
    report checks that every attempt's recorded prompt hash matches the
    manifest entry, which is the property the comparison depends on.
    """
    manifest_path = Path(experiment_dir) / "manifest.json"
    if not manifest_path.is_file():
        raise ReportError("manifest not found: {}".format(manifest_path))
    manifest = _read_json(manifest_path)
    if not isinstance(manifest, Mapping):
        raise ReportError("manifest must be a JSON object")
    if manifest.get("schema") != P.MANIFEST_SCHEMA:
        raise ReportError(
            "unexpected manifest schema {!r}; expected {!r}".format(
                manifest.get("schema"), P.MANIFEST_SCHEMA
            )
        )
    stored_hash = manifest.get("manifest_sha256")
    if stored_hash:
        actual = P.manifest_sha256(manifest)
        if stored_hash != actual:
            raise ReportError(
                "manifest self-hash mismatch: {} != {}".format(
                    stored_hash, actual
                )
            )
    case = manifest.get("case")
    if not isinstance(case, Mapping):
        raise ReportError("manifest.case is missing")
    if case.get("cve_id") != EXPECTED_CVE:
        raise ReportError(
            "this report is defined for the frozen single case {}; "
            "manifest has {!r}".format(EXPECTED_CVE, case.get("cve_id"))
        )
    commit = str(case.get("commit_sha") or "")
    if not commit.startswith(EXPECTED_COMMIT_PREFIX):
        raise ReportError(
            "this report is defined for the frozen Kubernetes snapshot "
            "{!r}; manifest commit is {!r}".format(
                EXPECTED_COMMIT_PREFIX, commit
            )
        )
    prompts = manifest.get("prompts")
    if not isinstance(prompts, Mapping) or tuple(prompts) != P.ARM_ORDER:
        raise ReportError("manifest.prompts must contain arms A-E in order")
    for arm in P.ARM_ORDER:
        record = prompts[arm]
        if not isinstance(record, Mapping):
            raise ReportError("manifest.prompts[{}] is missing".format(arm))
        if not record.get("sha256"):
            raise ReportError(
                "manifest.prompts[{}].sha256 is missing".format(arm)
            )
    schedule = manifest.get("schedule")
    if not isinstance(schedule, list) or len(schedule) != (
        len(P.ARM_ORDER) * P.ATTEMPT_POLICY["repeats"]
    ):
        raise ReportError("manifest.schedule must contain 15 attempts")
    expected_schedule = P.build_schedule()
    if schedule != expected_schedule:
        raise ReportError(
            "manifest.schedule is not the frozen repeat-major A-E order"
        )
    return dict(manifest)


def _load_run_summary(experiment_dir: Path) -> Dict[str, dict]:
    """Best-effort index of ``run-summary.json`` records by attempt key."""
    path = Path(experiment_dir) / "run-summary.json"
    try:
        data = _read_json(path)
    except ReportError:
        return {}
    if data is None:
        return {}
    entries: List[Any] = []
    if isinstance(data, list):
        entries = data
    elif isinstance(data, Mapping):
        if isinstance(data.get("attempts"), list):
            entries = data["attempts"]
        else:
            for key, value in data.items():
                if isinstance(value, Mapping):
                    entry = dict(value)
                    entry.setdefault("attempt_key", key)
                    entries.append(entry)
    index: Dict[str, dict] = {}
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        key = entry.get("attempt_key")
        if not key:
            arm = entry.get("arm")
            repeat = entry.get("repeat")
            if arm in P.ARM_ORDER and isinstance(repeat, int):
                key = "{}/{}/r{}".format(P.EXPERIMENT_ID, arm, repeat)
        if key:
            index[str(key)] = dict(entry)
    return index


# ---------------------------------------------------------------------------
# Answer, citation and evidence extraction
# ---------------------------------------------------------------------------


def _terminal_text(attempt_dir: Path) -> Tuple[str, str]:
    """Return ``(terminal_answer_text, source)`` from the saved attempt.

    ``raw_agent_output.txt`` is the controller's terminal-text copy and is
    preferred.  When it is absent, the raw adapter export is decoded with
    the established opencode/codex extractors — never with an invented
    parser rule.
    """
    direct = _read_text(attempt_dir / "raw_agent_output.txt")
    if direct is not None and direct.strip():
        return direct.strip(), "raw_agent_output.txt"
    result_json = _read_text(attempt_dir / "result.json")
    if result_json is not None:
        text = (parser_audit.terminal_text(result_json, "opencode") or "").strip()
        if text:
            return text, "result.json:opencode"
    result_jsonl = _read_text(attempt_dir / "result.jsonl")
    if result_jsonl is not None:
        text = (parser_audit.terminal_text(result_jsonl, "codex") or "").strip()
        if text:
            return text, "result.jsonl:codex"
    if direct is not None:
        return "", "raw_agent_output.txt"
    return "", "absent"


def _walk_strings(value: Any, path: str = "$") -> Iterable[Tuple[str, str]]:
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, Mapping):
        for key, item in value.items():
            yield from _walk_strings(item, "{}.{}".format(path, key))
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            yield from _walk_strings(item, "{}[{}]".format(path, index))


def _structured_citations(obj: Optional[Mapping[str, Any]]) -> List[dict]:
    """Evidence refs the model put in structured answer fields."""
    if not isinstance(obj, Mapping):
        return []
    out: List[dict] = []
    seen = set()

    def add(origin: str, ref: Any, claim: Optional[str] = None,
            verdict: Optional[str] = None) -> None:
        if not isinstance(ref, str) or not ref.strip():
            return
        value = ref.strip()
        key = (origin, value, claim, verdict)
        if key in seen:
            return
        seen.add(key)
        out.append({
            "ref": value,
            "origin": origin,
            "claim": claim,
            "verdict": verdict,
        })

    assessment = obj.get("assessment")
    if isinstance(assessment, Mapping):
        quality = assessment.get("evidence_quality")
        if isinstance(quality, Mapping):
            for ref in quality.get("references") or []:
                add("assessment.evidence_quality.references", ref)
        for claim_index, claim in enumerate(assessment.get("claims") or []):
            if not isinstance(claim, Mapping):
                continue
            for ref in claim.get("evidence_refs") or []:
                add(
                    "assessment.claims[{}].evidence_refs".format(claim_index),
                    ref,
                    claim=claim.get("statement")
                    if isinstance(claim.get("statement"), str) else None,
                    verdict=claim.get("verdict")
                    if isinstance(claim.get("verdict"), str) else None,
                )
        for ref in assessment.get("evidence") or []:
            add("assessment.evidence", ref)

    for claim_index, claim in enumerate(obj.get("claims") or []):
        if not isinstance(claim, Mapping):
            continue
        for ref in claim.get("evidence_refs") or []:
            add(
                "claims[{}].evidence_refs".format(claim_index),
                ref,
                claim=claim.get("statement")
                if isinstance(claim.get("statement"), str) else None,
                verdict=claim.get("verdict")
                if isinstance(claim.get("verdict"), str) else None,
            )
    for ref in obj.get("evidence") or []:
        if isinstance(ref, str):
            add("evidence", ref)
    for ref in obj.get("evidence_refs") or []:
        add("evidence_refs", ref)
    return out


def _free_text_citations(obj: Optional[Mapping[str, Any]]) -> List[dict]:
    """URLs and explicit refs found anywhere in the answer object."""
    if not isinstance(obj, Mapping):
        return []
    out: List[dict] = []
    seen = set()
    for path, text in _walk_strings(obj):
        candidates: List[Tuple[str, str]] = []
        candidates.extend(("url", match.group(0))
                          for match in _URL_RE.finditer(text))
        candidates.extend(("ref", match.group(0))
                          for match in _EXPLICIT_REF_RE.finditer(text))
        candidates.extend(
            ("path", "{}:{}".format(match.group(1), match.group(2)))
            for match in _PATH_LINE_RE.finditer(text)
        )
        for kind, value in candidates:
            key = (path, value)
            if key in seen:
                continue
            seen.add(key)
            out.append({
                "ref": value,
                "origin": "answer_string:{}".format(path),
                "kind": kind,
                "claim": None,
                "verdict": None,
            })
    return out


def _citation_lookup(citations: Sequence[dict]) -> Dict[str, dict]:
    unique: Dict[str, dict] = {}
    for citation in citations:
        ref = citation["ref"]
        entry = unique.setdefault(ref, {
            "ref": ref,
            "origins": [],
            "claims": [],
        })
        origin = citation["origin"]
        if origin not in entry["origins"]:
            entry["origins"].append(origin)
        if citation.get("claim"):
            entry["claims"].append({
                "origin": origin,
                "statement": citation["claim"],
                "verdict": citation.get("verdict"),
            })
    return unique


def _native_calls_from_result(attempt_dir: Path) -> List[dict]:
    """Fallback native-tool projection from the raw adapter export."""
    raw = _read_text(attempt_dir / "result.json") or _read_text(
        attempt_dir / "result.jsonl"
    )
    if raw is None:
        return []
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if not isinstance(payload, Mapping):
        return []
    calls: List[dict] = []
    for message in payload.get("messages") or []:
        if not isinstance(message, Mapping):
            continue
        for part in message.get("parts") or []:
            if not isinstance(part, Mapping) or part.get("type") != "tool":
                continue
            state = part.get("state") if isinstance(part.get("state"), Mapping) \
                else {}
            output = state.get("output")
            calls.append({
                "tool": part.get("tool"),
                "call_id": part.get("callID") or part.get("id"),
                "status": state.get("status"),
                "input": state.get("input"),
                "output_sha256": _sha256_text(output)
                if isinstance(output, str) else None,
                "output_bytes": len(output.encode("utf-8"))
                if isinstance(output, str) else None,
                "output_preview": output[:400]
                if isinstance(output, str) else None,
                "error": state.get("error")
                if isinstance(state.get("error"), str) else None,
            })
    return calls


def _native_call_summary(record: Mapping[str, Any]) -> dict:
    return {
        "tool": record.get("tool"),
        "call_id": record.get("call_id") or record.get("callID"),
        "status": record.get("status"),
        "input": record.get("input"),
        "input_sha256": _sha256_json(record.get("input"))
        if record.get("input") is not None else None,
        "output_sha256": record.get("output_sha256"),
        "output_bytes": record.get("output_bytes"),
        "output_preview": record.get("output_preview"),
        "error": record.get("error"),
    }


def _observation_summary(call: Mapping[str, Any],
                         index: int) -> Optional[dict]:
    observation = call.get("observation")
    if not isinstance(observation, Mapping):
        return None
    observation_id = observation.get("id")
    key = observation_id if isinstance(observation_id, str) and observation_id \
        else "observation-{}".format(index + 1)
    data = observation.get("data")
    return {
        "observation_id": key,
        "tool": observation.get("tool") or call.get("tool"),
        "fact": observation.get("fact"),
        "scope": observation.get("scope"),
        "completeness": observation.get("completeness"),
        "tool_status": observation.get("tool_status"),
        "evidence_refs": [
            ref for ref in (observation.get("evidence_refs") or [])
            if isinstance(ref, str)
        ],
        "limitations": [
            item for item in (observation.get("limitations") or [])
            if isinstance(item, str)
        ],
        "scope_details": observation.get("scope_details"),
        "data_sha256": _sha256_json(data) if data is not None else None,
        "cited_by": [],
        "decisive": False,
    }


def _native_call_ids_for_ref(ref: str, calls: Sequence[dict]) -> List[str]:
    """Link an answer citation to native calls that touched the same path."""
    target = ref
    for prefix in ("file:", "src:"):
        if target.startswith(prefix):
            target = target[len(prefix):]
            break
    else:
        if target.startswith("http://") or target.startswith("https://") \
                or target.startswith(("ev:", "sha256:")):
            return []
    target = re.sub(r":\d+(?:-\d+)?$", "", target)
    relative = target[6:] if target.startswith("/work/") else target
    if not relative:
        return []
    matched: List[str] = []
    for call in calls:
        blob = "{} {}".format(
            json.dumps(call.get("input"), sort_keys=True, default=str)
            if call.get("input") is not None else "",
            call.get("output_preview") or "",
        )
        if target in blob or relative in blob:
            call_id = call.get("call_id")
            if isinstance(call_id, str) and call_id not in matched:
                matched.append(call_id)
    return matched


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


_PROVIDER_REFUSAL_HINTS = (
    "refused",
    "content_filter",
    "safety filter",
    "model_refusal",
    "blocked by",
)


def _collect_error_strings(value: Any) -> Iterable[str]:
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_low = str(key).lower()
            if key_low in {
                "error", "error_message", "errormessage", "failure_reason",
                "reason", "detail",
            }:
                if isinstance(item, str):
                    yield item
                else:
                    yield from _collect_error_strings(item)
            elif isinstance(item, (Mapping, list, tuple)):
                yield from _collect_error_strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _collect_error_strings(item)


def _provider_signal(attempt_dir: Path,
                     attempt_record: Mapping[str, Any]) -> Optional[str]:
    """Provider-side failure evidence from saved error fields/exports."""
    texts: List[str] = []
    excerpt = attempt_record.get("error_excerpt")
    if isinstance(excerpt, str):
        texts.append(excerpt)
    error_text = _read_text(attempt_dir / "error.txt")
    if error_text:
        texts.append(error_text)
    raw = _read_text(attempt_dir / "result.json") \
        or _read_text(attempt_dir / "result.jsonl")
    if raw:
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            payload = None
        if payload is not None:
            texts.extend(_collect_error_strings(payload))
    joined = "\n".join(texts).lower()
    if not joined:
        return None
    if "at capacity" in joined:
        return "provider_at_capacity"
    if "rate limit" in joined or "rate_limit" in joined:
        return "provider_rate_limit"
    if any(hint in joined for hint in _PROVIDER_REFUSAL_HINTS):
        return "provider_refusal"
    if "provider" in joined and "error" in joined:
        return "provider_error"
    return None


def classify_outcome(official: Mapping[str, Any],
                     attempt_record: Mapping[str, Any],
                     provider_signal: Optional[str] = None
                     ) -> Tuple[str, str]:
    """Return ``(outcome, basis)`` from the official view only.

    The audit projection never selects the outcome.  Execution failures
    take precedence over parser failures; a failure is never a negative.
    """
    execution = official.get("execution")
    reason = official.get("failure_reason") \
        or attempt_record.get("failure_reason")
    failure_class = attempt_record.get("failure_class")
    official_parse = official.get("official_parse")
    category = official.get("category")

    if execution == "timeout" or reason == "timeout":
        return "timeout", "status.execution/failure_reason=timeout"
    if (failure_class == "provider" or execution == "provider_refusal"
            or reason in PROVIDER_REASONS):
        return "provider_failure", "provider refusal/error recorded"
    if provider_signal:
        return "provider_failure", "provider error evidence: {}".format(
            provider_signal
        )
    if (failure_class == "infrastructure"
            or execution == "transport_failure"
            or reason in INFRASTRUCTURE_REASONS):
        return "infrastructure_failure", "container/transport/export failure"
    if official_parse == "accepted" and category in SAFE_CATEGORY_SET:
        return "dangerous_negative", "official parser accepted a safe category"
    if official_parse == "accepted" and category == "uncertain":
        return "uncertain", "official parser accepted category=uncertain"
    if official_parse == "accepted" and category == EXPECTED_CATEGORY:
        return "vulnerable", "official parser accepted category=vulnerable"
    if official_parse == "accepted":
        return "other_failure", "official parser accepted an unknown category"
    if official_parse == "parse_fail":
        return "parse_failure", "official parser did not accept a category"
    if official_parse in (None, "", "no_result", "no_dir"):
        return "other_failure", "no official parser result"
    return "other_failure", "unclassified official parse state"


def _diagnose(outcome: str, audit_category: Optional[str],
              parser_loss: bool, has_research: bool
              ) -> Tuple[str, str, str]:
    """Return ``(kind, losing_stage, rationale)``.

    ``not_researched`` uses the saved-trace definition: no native tool
    call, no MCP observation and no answer citation was recorded.  It is
    not a claim about invisible model reasoning.
    """
    if outcome in NO_ANSWER_OUTCOMES:
        return (
            "no_answer", outcome,
            "no usable first-layer answer was produced ({})".format(outcome),
        )
    if outcome == "vulnerable":
        return ("correct", "none",
                "official parser accepted the expected category")
    if parser_loss:
        return (
            "correct_answer_lost_by_parser", "parser",
            "the full-JSON audit recovered category={} while the official "
            "parser did not accept it; the official result is kept "
            "unchanged".format(audit_category or EXPECTED_CATEGORY),
        )
    if outcome == "dangerous_negative":
        if has_research:
            return (
                "researched_but_wrong_conclusion", "conclusion",
                "tool/citation traces exist, but the official category is a "
                "safe negative on the frozen vulnerable case",
            )
        return (
            "not_researched", "research",
            "the answer is a safe negative and the saved attempt carries no "
            "native tool call, MCP observation or answer citation",
        )
    if outcome == "uncertain":
        if has_research:
            return (
                "researched_inconclusive", "conclusion",
                "tool/citation traces exist, but the model abstained",
            )
        return (
            "not_researched", "research",
            "the answer abstains and the saved attempt carries no research "
            "trace",
        )
    if outcome == "parse_failure":
        if has_research:
            return (
                "researched_answer_unparsed", "parser",
                "research traces exist, but neither parser recovered the "
                "expected category from the answer",
            )
        return (
            "not_researched", "research",
            "the answer is unparseable and the saved attempt carries no "
            "research trace",
        )
    return ("no_answer", "unknown",
            "outcome has no first-layer diagnosis rule")


# ---------------------------------------------------------------------------
# Per-attempt loading
# ---------------------------------------------------------------------------


def _attempt_dir(experiment_dir: Path, task_id: str, arm: str,
                 repeat: int) -> Path:
    return Path(experiment_dir) / task_id / arm / "repeat-{}".format(repeat)


def _load_official(attempt_dir: Path,
                   attempt_json: Optional[Mapping[str, Any]]
                   ) -> Tuple[Dict[str, Any], List[str], List[str]]:
    errors: List[str] = []
    warnings: List[str] = []
    try:
        status = _read_json(attempt_dir / "status.json")
    except ReportError as exc:
        errors.append(str(exc))
        status = None
    source = "status.json"
    if status is None and isinstance(attempt_json, Mapping) \
            and isinstance(attempt_json.get("status"), Mapping):
        status = dict(attempt_json["status"])
        source = "attempt.json.status"
    if not isinstance(status, Mapping):
        return ({
            "available": False,
            "source": "absent",
            "execution": None,
            "official_parse": None,
            "overall": None,
            "category": None,
            "failure_reason": None,
            "assessment_schema": None,
            "parser_audit": None,
            "detail": None,
            "record": None,
        }, errors, ["no status.json or embedded attempt status"])

    saved_category = attempt_json.get("official_category") \
        if isinstance(attempt_json, Mapping) else None
    saved_category_source = (
        attempt_json.get("official_category_source")
        if isinstance(attempt_json, Mapping) else None
    )
    category = status.get("category")
    category_source = "saved_status" if category is not None else None
    if category is None and saved_category is not None \
            and status.get("official_parse") == "accepted" \
            and saved_category in parser_audit.VALID_CATEGORIES:
        category = saved_category
        category_source = saved_category_source \
            or "attempt.json.official_category"
    official = {
        "available": True,
        "source": source,
        "execution": status.get("execution"),
        "official_parse": status.get("official_parse"),
        "overall": status.get("overall"),
        "category": category,
        "failure_reason": status.get("failure_reason"),
        "assessment_schema": status.get("assessment_schema"),
        "parser_audit": status.get("parser_audit"),
        "detail": status.get("detail"),
        "category_source": category_source,
        "attempt_record_official_category": saved_category,
        "attempt_record_official_category_source": saved_category_source,
        # Preserve the saved official record verbatim; the normalized
        # fields above are a convenience view, not a replacement.
        "record": dict(status),
    }
    if saved_category is not None \
            and status.get("official_parse") != "accepted":
        warnings.append(
            "attempt.json.official_category={!r} is not used because "
            "status.official_parse={!r}".format(
                saved_category, status.get("official_parse")
            )
        )
    if official["official_parse"] == "accepted":
        # The category may be absent from status.json (c1 stores only the
        # parse verdict); it is re-derived from the saved terminal answer
        # below.  Only a present-but-invalid value is an error here.
        if category is not None and category not in parser_audit.VALID_CATEGORIES:
            errors.append(
                "official_parse=accepted but category {!r} is not one of "
                "the official categories".format(category)
            )
    elif category is not None:
        warnings.append(
            "official_parse={!r} carries category={!r}".format(
                official["official_parse"], category
            )
        )
    return official, errors, warnings


def _resolve_official_category(
    official: Dict[str, Any],
    terminal_text: str,
    official_parser,
) -> List[str]:
    """Ensure the official category is available without changing the view.

    ``eval.c1.status.AttemptStatus`` stores the official parse verdict but
    not the category itself.  The report prefers a category the controller
    saved (``status.category`` or Task 2's ``attempt.json.official_category``);
    only when both are absent is it re-derived from the same terminal
    answer with the unchanged official harness parser — the exact function
    the controller used.  The saved status record stays verbatim, and this
    re-derivation is never performed for an attempt the controller marked
    ``parse_fail``.
    """
    errors: List[str] = []
    if official.get("category") is not None:
        if not official.get("category_source"):
            official["category_source"] = "saved_status"
        return errors
    if official.get("official_parse") != "accepted":
        official["category_source"] = "not_applicable"
        return errors
    if not terminal_text:
        errors.append(
            "official_parse=accepted but no terminal answer text was saved"
        )
        official["category_source"] = "unavailable"
        return errors
    try:
        category, _reasoning = official_parser(terminal_text)
    except ReportError:
        raise
    except Exception as exc:  # pragma: no cover - defensive
        errors.append("official parser raised: {}".format(exc))
        official["category_source"] = "parser_error"
        return errors
    if category not in parser_audit.VALID_CATEGORIES:
        errors.append(
            "official parser did not reproduce an accepted category from "
            "the saved terminal answer"
        )
        category = None
    official["category"] = category
    official["category_source"] = OFFICIAL_PARSER_NAME
    return errors


def _load_prompt_integrity(
    attempt_dir: Path,
    manifest: Mapping[str, Any],
    arm: str,
    attempt_json: Optional[Mapping[str, Any]],
) -> Tuple[Dict[str, Any], List[str], List[str]]:
    errors: List[str] = []
    warnings: List[str] = []
    expected = manifest["prompts"][arm]
    expected_hash = expected.get("sha256")
    prompt_text = _read_text(attempt_dir / "prompt.txt")
    try:
        request = _read_json(attempt_dir / "request.json")
    except ReportError as exc:
        request = None
        warnings.append(str(exc))
    if not isinstance(request, Mapping):
        request = None
        if not any("request.json" in warning for warning in warnings):
            warnings.append("request.json missing")

    attempt_hash = attempt_json.get("prompt_sha256") \
        if isinstance(attempt_json, Mapping) else None
    prompt_file_hash = _sha256_text(prompt_text) if prompt_text is not None \
        else None
    request_user_hash = request.get("user_prompt_sha256") \
        if isinstance(request, Mapping) else None

    checks = {
        "manifest_sha256": expected_hash,
        "attempt_json_sha256": attempt_hash,
        "prompt_txt_sha256": prompt_file_hash,
        "request_user_sha256": request_user_hash,
    }
    present = {key: value for key, value in checks.items() if value}
    for key, value in present.items():
        if value != expected_hash:
            errors.append(
                "prompt hash mismatch: {} {} != manifest {}".format(
                    key, value, expected_hash
                )
            )
    if attempt_hash is None:
        warnings.append("attempt.json.prompt_sha256 missing")
    if prompt_file_hash is None:
        warnings.append("prompt.txt missing")
    if request is None:
        pass
    elif request_user_hash is None:
        warnings.append("request.json.user_prompt_sha256 missing")
    if isinstance(request, Mapping):
        for index, observed in enumerate(
            request.get("observed_user_messages") or []
        ):
            if isinstance(observed, Mapping) \
                    and observed.get("equals_protocol_prompt") is False:
                errors.append(
                    "adapter-delivered user message {} differs from the "
                    "rendered arm prompt".format(index)
                )

    matches = bool(
        expected_hash
        and attempt_hash == expected_hash
        and prompt_file_hash == expected_hash
        and request_user_hash in (None, expected_hash)
        and all(value == expected_hash for value in present.values())
    )
    return ({
        "matches_manifest": matches,
        "manifest_sha256": expected_hash,
        "attempt_json_sha256": attempt_hash,
        "prompt_txt_sha256": prompt_file_hash,
        "request_user_sha256": request_user_hash,
        "system_message_count": request.get("system_message_count")
        if isinstance(request, Mapping) else None,
        "full_request_sha256": request.get("full_request_sha256")
        if isinstance(request, Mapping) else None,
    }, errors, warnings)


def _load_research(attempt_dir: Path,
                   audit_object: Optional[Mapping[str, Any]]
                   ) -> Dict[str, Any]:
    tool_calls, tool_malformed = _read_jsonl(attempt_dir / "tool_calls.jsonl")
    observations_raw, obs_malformed = _read_jsonl(
        attempt_dir / "observations.jsonl"
    )
    native_records, native_malformed = _read_jsonl(
        attempt_dir / "native_tool_calls.jsonl"
    )
    native_source = "native_tool_calls.jsonl"
    if not native_records:
        fallback = _native_calls_from_result(attempt_dir)
        if fallback:
            native_records = fallback
            native_source = "result.json:tool_parts"
        elif not (attempt_dir / "native_tool_calls.jsonl").is_file():
            native_source = "absent"

    observations: List[dict] = []
    if tool_calls:
        for index, call in enumerate(tool_calls):
            summary = _observation_summary(call, index)
            if summary is not None:
                observations.append(summary)
    elif observations_raw:
        # Observations without the enclosing audit record: reconstruct the
        # minimal observation list; tool name comes from the object.
        for index, observation in enumerate(observations_raw):
            summary = _observation_summary(
                {"tool": observation.get("tool"), "observation": observation},
                index,
            )
            if summary is not None:
                observations.append(summary)

    ref_to_observation: Dict[str, List[str]] = defaultdict(list)
    for observation in observations:
        for ref in observation["evidence_refs"]:
            if observation["observation_id"] not in \
                    ref_to_observation[ref]:
                ref_to_observation[ref].append(
                    observation["observation_id"]
                )

    structured = _structured_citations(audit_object)
    free_text = _free_text_citations(audit_object)
    all_citations = structured + free_text
    unique_citations = _citation_lookup(all_citations)

    native_calls = [_native_call_summary(record)
                    for record in native_records]
    citations: List[dict] = []
    decisive_ids: List[str] = []
    for ref, entry in sorted(unique_citations.items()):
        observation_ids = list(ref_to_observation.get(ref, []))
        native_call_ids = _native_call_ids_for_ref(ref, native_calls)
        resolved = bool(observation_ids or native_call_ids)
        citations.append({
            "ref": ref,
            "origins": entry["origins"],
            "claims": entry["claims"],
            "resolved": resolved,
            "observation_ids": observation_ids,
            "native_call_ids": native_call_ids,
        })
        for observation_id in observation_ids:
            if observation_id not in decisive_ids:
                decisive_ids.append(observation_id)

    for observation in observations:
        cited_refs = [
            citation["ref"] for citation in citations
            if observation["observation_id"] in citation["observation_ids"]
        ]
        observation["cited_by"] = cited_refs
        observation["decisive"] = bool(cited_refs)

    native_tools = sorted({
        call["tool"] for call in native_calls
        if isinstance(call.get("tool"), str) and call["tool"]
    })
    mcp_tools = sorted({
        tool for tool in (
            [observation.get("tool") for observation in observations]
            + [record.get("tool") for record in tool_calls]
        )
        if isinstance(tool, str) and tool
    })
    observation_status = Counter(
        observation.get("tool_status") or "<none>"
        for observation in observations
    )
    observation_completeness = Counter(
        observation.get("completeness") or "<none>"
        for observation in observations
    )

    basis: List[str] = []
    if native_calls:
        basis.append("native_tool_calls")
    if observations:
        basis.append("mcp_observations")
    if citations:
        basis.append("answer_citations")
    has_research = bool(native_calls or observations)
    has_trace = has_research or bool(citations)

    return {
        "native_tool_call_count": len(native_calls),
        "native_tool_calls_source": native_source,
        "native_tools_used": native_tools,
        "native_tool_calls": native_calls,
        "mcp_tool_call_count": len(tool_calls),
        "mcp_tools_used": mcp_tools,
        "observations": observations,
        "observation_status_counts": dict(sorted(observation_status.items())),
        "observation_completeness_counts": dict(
            sorted(observation_completeness.items())
        ),
        "citations": citations,
        "citation_count": len(citations),
        "resolved_citation_count": sum(
            1 for citation in citations if citation["resolved"]
        ),
        "unresolved_citation_count": sum(
            1 for citation in citations if not citation["resolved"]
        ),
        "decisive_observation_ids": decisive_ids,
        "decisive_observations": [
            observation for observation in observations
            if observation["decisive"]
        ],
        "has_research_evidence": has_research,
        "has_citation_evidence": bool(citations),
        "has_research_trace": has_trace,
        "research_evidence_basis": basis,
        "malformed_jsonl_lines": {
            "tool_calls": tool_malformed,
            "observations": obs_malformed,
            "native_tool_calls": native_malformed,
        },
    }


def _attempt_artifacts(attempt_dir: Path) -> Dict[str, Any]:
    assessment_error = None
    try:
        assessment = _read_json(attempt_dir / "agent_assessment.json")
    except ReportError as exc:
        assessment = None
        assessment_error = str(exc)
    category = None
    if isinstance(assessment, Mapping):
        assessment_obj = assessment.get("assessment")
        if isinstance(assessment_obj, Mapping):
            category = assessment_obj.get("category")
        if category is None:
            category = assessment.get("category")
    usage_error = None
    try:
        usage = _read_json(attempt_dir / "usage.json")
    except ReportError as exc:
        usage = None
        usage_error = str(exc)
    return {
        "agent_assessment_present": isinstance(assessment, Mapping),
        "agent_assessment_category": category,
        "agent_assessment_used_for_scoring": False,
        "agent_assessment_parse_error": assessment_error,
        "validator_results_present":
            (attempt_dir / "validator_results.jsonl").is_file(),
        "validator_results_used_for_scoring": False,
        "usage": usage,
        "usage_parse_error": usage_error,
        "export_report_present":
            (attempt_dir / "export-report.json").is_file(),
    }


def _runtime_check(attempt_json: Optional[Mapping[str, Any]],
                   manifest: Mapping[str, Any],
                   arm: str) -> Tuple[Dict[str, Any], List[str], List[str]]:
    errors: List[str] = []
    warnings: List[str] = []
    expected = manifest["prompts"][arm]
    expected_agent = expected.get("agent")
    expected_mcp = expected.get("mcp")
    record = attempt_json if isinstance(attempt_json, Mapping) else {}
    agent = record.get("agent", expected_agent)
    mcp = record.get("mcp", expected_mcp)
    if agent != expected_agent:
        errors.append(
            "arm {} agent {!r} != manifest {!r}".format(
                arm, agent, expected_agent
            )
        )
    if mcp != expected_mcp:
        errors.append(
            "arm {} mcp {!r} != manifest {!r}".format(
                arm, mcp, expected_mcp
            )
        )

    model = manifest.get("runtime", {}).get("model", {}) \
        if isinstance(manifest.get("runtime"), Mapping) else {}
    observed_model = record.get("model_observed")
    observed_provider = record.get("provider_observed")
    allowed_models = {
        value for value in (
            model.get("id"), model.get("alias"), model.get("provider_model_id"),
        ) if value
    }
    if observed_model and allowed_models \
            and observed_model not in allowed_models:
        warnings.append(
            "observed model {!r} differs from manifest {!r}".format(
                observed_model, sorted(allowed_models)
            )
        )
    expected_provider = str(model.get("provider") or "")
    if observed_provider and expected_provider \
            and observed_provider != expected_provider \
            and not str(observed_provider).lower().startswith(
                expected_provider.lower()
            ):
        warnings.append(
            "observed provider {!r} differs from manifest {!r}".format(
                observed_provider, expected_provider
            )
        )
    image = manifest.get("runtime", {}).get("image", {}) \
        if isinstance(manifest.get("runtime"), Mapping) else {}
    observed_digest = record.get("image_digest")
    if observed_digest and image.get("digest") \
            and observed_digest != image.get("digest"):
        warnings.append("observed image digest differs from manifest")
    return ({
        "agent": agent,
        "mcp": mcp,
        "model_observed": observed_model,
        "provider_observed": observed_provider,
        "image_digest_observed": observed_digest,
    }, errors, warnings)


def analyse_attempt(experiment_dir: Path, manifest: Mapping[str, Any],
                    schedule_entry: Mapping[str, Any],
                    run_summary: Mapping[str, Mapping[str, Any]],
                    official_parser=None) -> Dict[str, Any]:
    arm = schedule_entry["arm"]
    repeat = schedule_entry["repeat"]
    key = schedule_entry["attempt_key"]
    task_id = manifest["case"]["task_id"]
    attempt_dir = _attempt_dir(experiment_dir, task_id, arm, repeat)
    base = {
        "attempt_key": key,
        "experiment_id": manifest.get("experiment_id"),
        "task_id": task_id,
        "arm": arm,
        "repeat": repeat,
        "sequence_index": schedule_entry.get("index"),
        "attempt_dir": _relpath(attempt_dir, experiment_dir),
        "present": attempt_dir.is_dir(),
    }
    summary_entry = run_summary.get(key)
    base["run_summary"] = dict(summary_entry) if summary_entry else None

    if not attempt_dir.is_dir():
        warning = "attempt directory is absent"
        if summary_entry and summary_entry.get("outcome") == "not_run":
            warning += " (run-summary: not_run)"
            if summary_entry.get("failure_reason"):
                warning += "; reason={}".format(
                    summary_entry["failure_reason"]
                )
        return {
            **base,
            "official_parser_result": {
                "available": False,
                "source": "absent",
                "execution": None,
                "official_parse": None,
                "overall": None,
                "category": None,
                "failure_reason": None,
                "assessment_schema": None,
                "parser_audit": None,
                "detail": None,
                "category_source": None,
                "record": None,
            },
            "audit_projection": {
                "source": "absent",
                "decoder": parser_audit.PARSER_AUDIT_DECODER_VERSION,
                "status": "no_input",
                "official_category": None,
                "category": None,
                "reasoning": None,
                "disagreement": None,
                "objects_found": 0,
                "category_objects_found": 0,
                "recovered_object": None,
                "recovered_object_sha256": None,
                "recovered_object_keys": [],
            },
            "first_layer_outcome": "missing_attempt",
            "outcome_basis": "no attempt directory was saved",
            "diagnosis": {
                "kind": "no_answer",
                "losing_stage": "missing_attempt",
                "rationale": "the scheduled attempt was not saved",
            },
            "research": {
                "native_tool_call_count": 0,
                "mcp_tool_call_count": 0,
                "observations": [],
                "citations": [],
                "citation_count": 0,
                "decisive_observation_ids": [],
                "decisive_observations": [],
                "has_research_evidence": False,
                "has_citation_evidence": False,
                "has_research_trace": False,
                "research_evidence_basis": [],
            },
            "prompt": {"matches_manifest": None},
            "runtime": {
                "agent": manifest["prompts"][arm].get("agent"),
                "mcp": manifest["prompts"][arm].get("mcp"),
            },
            "artifacts": {},
            "integrity": {"errors": [], "warnings": [warning]},
        }

    attempt_errors: List[str] = []
    try:
        attempt_json = _read_json(attempt_dir / "attempt.json")
    except ReportError as exc:
        attempt_json = None
        attempt_errors.append(str(exc))
    if attempt_json is not None and not isinstance(attempt_json, Mapping):
        attempt_json = None
        attempt_errors.append(
            "attempt.json is not an object: {}".format(
                attempt_dir / "attempt.json"
            )
        )
    official, official_errors, official_warnings = _load_official(
        attempt_dir, attempt_json
    )
    prompt, prompt_errors, prompt_warnings = _load_prompt_integrity(
        attempt_dir, manifest, arm, attempt_json
    )
    runtime, runtime_errors, runtime_warnings = _runtime_check(
        attempt_json, manifest, arm
    )
    terminal_text, terminal_source = _terminal_text(attempt_dir)
    if official_parser is not None:
        official_errors.extend(
            _resolve_official_category(
                official, terminal_text, official_parser
            )
        )
    if official.get("official_parse") == "accepted" \
            and official.get("category") not in parser_audit.VALID_CATEGORIES:
        message = (
            "official_parse=accepted but no valid official category is "
            "available (category={!r}, source={!r})".format(
                official.get("category"), official.get("category_source")
            )
        )
        if not any("category" in error and "accepted" in error
                   for error in official_errors):
            official_errors.append(message)
    audit_record = parser_audit.audit_terminal_text(
        terminal_text, official.get("category")
    )
    audit_object = audit_record.get("recovered_object")
    research = _load_research(attempt_dir, audit_object)
    artifacts = _attempt_artifacts(attempt_dir)

    integrity_errors = list(attempt_errors) + list(official_errors) \
        + list(prompt_errors) + list(runtime_errors)
    integrity_warnings = list(official_warnings) + list(prompt_warnings) \
        + list(runtime_warnings)
    for label, malformed in (
        research.get("malformed_jsonl_lines") or {}
    ).items():
        if malformed:
            integrity_warnings.append(
                "{} has {} malformed JSONL line(s); they are excluded "
                "from the research trace".format(label, malformed)
            )
    if artifacts.get("agent_assessment_parse_error"):
        integrity_warnings.append(artifacts["agent_assessment_parse_error"])
    if artifacts.get("usage_parse_error"):
        integrity_warnings.append(artifacts["usage_parse_error"])
    if isinstance(attempt_json, Mapping):
        if attempt_json.get("attempt_key") not in (None, key):
            integrity_errors.append(
                "attempt.json.attempt_key {!r} != {!r}".format(
                    attempt_json.get("attempt_key"), key
                )
            )
        if attempt_json.get("arm") not in (None, arm):
            integrity_errors.append(
                "attempt.json.arm {!r} != {!r}".format(
                    attempt_json.get("arm"), arm
                )
            )
        if attempt_json.get("repeat") not in (None, repeat):
            integrity_errors.append(
                "attempt.json.repeat {!r} != {!r}".format(
                    attempt_json.get("repeat"), repeat
                )
            )
        if attempt_json.get("outcome") == "failed" \
                and official.get("overall") not in (None, "failed"):
            integrity_warnings.append(
                "attempt.json outcome=failed but status.overall={!r}".format(
                    official.get("overall")
                )
            )
    else:
        integrity_warnings.append("attempt.json missing or unreadable")

    provider_signal = _provider_signal(attempt_dir, attempt_json or {})
    outcome, outcome_basis = classify_outcome(
        official, attempt_json or {}, provider_signal
    )
    audit_category = audit_record.get("audit_category")
    official_category = official.get("category")
    recovered_expected = audit_category == EXPECTED_CATEGORY
    parser_loss = bool(
        recovered_expected
        and official.get("official_parse") != "accepted"
    )
    projection_disagreement = bool(
        official_category is not None
        and audit_category is not None
        and official_category != audit_category
    )
    diagnosis_kind, losing_stage, rationale = _diagnose(
        outcome, audit_category, parser_loss,
        research["has_research_trace"],
    )

    return {
        **base,
        "official_parser_result": official,
        "audit_projection": {
            "source": terminal_source,
            "decoder": audit_record.get("decoder"),
            "status": audit_record.get("status"),
            "official_category": audit_record.get("official_category"),
            "category": audit_category,
            "reasoning": audit_record.get("audit_reasoning"),
            "disagreement": audit_record.get("disagreement"),
            "objects_found": audit_record.get("objects_found"),
            "category_objects_found":
                audit_record.get("category_objects_found"),
            "recovered_object": audit_object,
            "recovered_object_sha256":
                _sha256_json(audit_object)
                if audit_object is not None else None,
            "recovered_object_keys": sorted(audit_object)
            if isinstance(audit_object, Mapping) else [],
            "terminal_text_sha256": _sha256_text(terminal_text)
            if terminal_text else None,
            "terminal_text_len": len(terminal_text),
            "official_missed_expected_answer": parser_loss,
            "projection_disagreement": projection_disagreement,
            "used_for_scoring": False,
        },
        "first_layer_outcome": outcome,
        "outcome_basis": outcome_basis,
        "diagnosis": {
            "kind": diagnosis_kind,
            "losing_stage": losing_stage,
            "rationale": rationale,
            "official_is_expected":
                official_category == EXPECTED_CATEGORY
                if official_category is not None else None,
            "audit_is_expected":
                audit_category == EXPECTED_CATEGORY
                if audit_category is not None else None,
            "parser_loss": parser_loss,
            "projection_disagreement": projection_disagreement,
        },
        "research": research,
        "prompt": prompt,
        "runtime": runtime,
        "artifacts": artifacts,
        "integrity": {
            "errors": integrity_errors,
            "warnings": integrity_warnings,
        },
    }


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


def _arm_rollup(records: Sequence[Mapping[str, Any]],
                manifest: Mapping[str, Any], arm: str) -> Dict[str, Any]:
    outcomes = _empty_outcomes()
    diagnoses = _empty_diagnoses()
    for record in records:
        outcome = record["first_layer_outcome"]
        outcomes[outcome] = outcomes.get(outcome, 0) + 1
        kind = record["diagnosis"]["kind"]
        diagnoses[kind] = diagnoses.get(kind, 0) + 1

    present = [record for record in records if record["present"]]
    prompt = manifest["prompts"][arm]
    return {
        "arm": arm,
        "role": prompt.get("role"),
        "treatments": list(prompt.get("treatments") or []),
        "agent": prompt.get("agent"),
        "mcp": prompt.get("mcp"),
        "prompt_sha256": prompt.get("sha256"),
        "prompt_sha256_12": prompt.get("sha256_12"),
        "attempts": len(records),
        "present": len(present),
        "outcomes": outcomes,
        "diagnoses": diagnoses,
        "official_accepted": sum(
            1 for record in present
            if record["official_parser_result"].get("official_parse")
            == "accepted"
        ),
        "official_parse_fail": sum(
            1 for record in present
            if record["official_parser_result"].get("official_parse")
            == "parse_fail"
        ),
        "native_tool_calls": sum(
            record["research"].get("native_tool_call_count", 0)
            for record in present
        ),
        "mcp_tool_calls": sum(
            record["research"].get("mcp_tool_call_count", 0)
            for record in present
        ),
        "attempts_with_native_tools": sum(
            1 for record in present
            if record["research"].get("native_tool_call_count", 0)
        ),
        "attempts_with_mcp_calls": sum(
            1 for record in present
            if record["research"].get("mcp_tool_call_count", 0)
        ),
        "attempts_with_citations": sum(
            1 for record in present
            if record["research"].get("citation_count", 0)
        ),
        "attempts_with_research_trace": sum(
            1 for record in present
            if record["research"].get("has_research_trace")
        ),
        "attempts_with_decisive_observations": sum(
            1 for record in present
            if record["research"].get("decisive_observation_ids")
        ),
        "decisive_observations": sum(
            len(record["research"].get("decisive_observation_ids") or [])
            for record in present
        ),
        "parser_losses": sum(
            1 for record in present
            if record["diagnosis"].get("parser_loss")
        ),
        "projection_disagreements": sum(
            1 for record in present
            if record["diagnosis"].get("projection_disagreement")
        ),
    }


def _totals(attempts: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    outcomes = _empty_outcomes()
    diagnoses = _empty_diagnoses()
    for record in attempts:
        outcomes[record["first_layer_outcome"]] = \
            outcomes.get(record["first_layer_outcome"], 0) + 1
        diagnoses[record["diagnosis"]["kind"]] = \
            diagnoses.get(record["diagnosis"]["kind"], 0) + 1
    return {
        "attempts": len(attempts),
        "present": sum(1 for record in attempts if record["present"]),
        "missing": sum(1 for record in attempts if not record["present"]),
        "outcomes": outcomes,
        "diagnoses": diagnoses,
        "native_tool_calls": sum(
            record["research"].get("native_tool_call_count", 0)
            for record in attempts if record["present"]
        ),
        "mcp_tool_calls": sum(
            record["research"].get("mcp_tool_call_count", 0)
            for record in attempts if record["present"]
        ),
        "attempts_with_citations": sum(
            1 for record in attempts if record["present"]
            and record["research"].get("citation_count", 0)
        ),
        "attempts_with_research_trace": sum(
            1 for record in attempts if record["present"]
            and record["research"].get("has_research_trace")
        ),
        "attempts_with_decisive_observations": sum(
            1 for record in attempts if record["present"]
            and record["research"].get("decisive_observation_ids")
        ),
    }


def build_comparison(experiment_dir: Path,
                     official_parser=None) -> Dict[str, Any]:
    """Read saved attempts and build the comparison document.

    ``official_parser`` is the unchanged harness category parser; it is
    loaded lazily from the harness checkout only for attempts whose saved
    status has no category field.  Tests inject a deterministic parser.
    """
    experiment_dir = Path(experiment_dir)
    manifest = load_manifest(experiment_dir)
    run_summary = _load_run_summary(experiment_dir)
    parser = official_parser if official_parser is not None \
        else _LazyOfficialParser()
    attempts = [
        analyse_attempt(experiment_dir, manifest, entry, run_summary, parser)
        for entry in manifest["schedule"]
    ]
    arms = {
        arm: _arm_rollup(
            [record for record in attempts if record["arm"] == arm],
            manifest, arm,
        )
        for arm in P.ARM_ORDER
    }
    integrity_errors: List[str] = []
    integrity_warnings: List[str] = []
    for record in attempts:
        for error in record["integrity"]["errors"]:
            integrity_errors.append(
                "{}: {}".format(record["attempt_key"], error)
            )
        for warning in record["integrity"]["warnings"]:
            integrity_warnings.append(
                "{}: {}".format(record["attempt_key"], warning)
            )
    expected_keys = {entry["attempt_key"] for entry in manifest["schedule"]}
    saved_keys = {record["attempt_key"] for record in attempts
                  if record["present"]}
    extra_summary_keys = sorted(set(run_summary) - expected_keys)
    if extra_summary_keys:
        integrity_warnings.append(
            "run-summary.json has unknown attempt keys: {}".format(
                ", ".join(extra_summary_keys)
            )
        )

    limitations = list(manifest.get("limitations") or [])
    limitations.extend([
        "Single-case diagnostic only: one Kubernetes snapshot "
        "({}) and one CVE ({}). It localizes a treatment effect; it does "
        "not establish general first-layer VEX parity.".format(
            manifest["case"].get("task_id"), manifest["case"].get("cve_id")
        ),
        "The expected category (vulnerable) is the frozen case's known "
        "outcome used by this offline report to label dangerous negatives; "
        "it is never included in any prompt or attempt input.",
        "The official parser result is primary and is preserved verbatim. "
        "The full-JSON audit projection is a separate decoder view and is "
        "never substituted for it.",
        "No downstream verifier, validator, auto-close rule or negative "
        "verification result was read or used to grade the first layer.",
        "'not_researched' means the saved attempt contains no native tool "
        "call, no MCP observation and no answer citation. It is not proof "
        "that no invisible model reasoning occurred.",
        "Citations may be agent-written. A citation is marked resolved only "
        "when a tool-minted evidence ref or a matching native tool call "
        "exists in the saved trace.",
        "All scheduled attempts are reported, including failures and "
        "unparseable answers; no selective retry, best-of or cache is "
        "applied by this report.",
    ])

    return {
        "schema": REPORT_SCHEMA,
        "generated_at_utc": _utcnow(),
        "experiment_id": manifest.get("experiment_id"),
        "manifest_path": "manifest.json",
        "manifest_sha256": manifest.get("manifest_sha256"),
        "scope": {
            "single_case_diagnostic": True,
            "parity_claim": False,
            "statement": (
                "One case is a diagnostic localization of where the first "
                "layer changes; it is not evidence of general parity."
            ),
            "case": dict(manifest["case"]),
            "expected_category": EXPECTED_CATEGORY,
            "ground_truth_usage": (
                "offline labeling of dangerous negatives only; never passed "
                "to the model"
            ),
            "downstream_verifier_used": False,
            "attempt_policy": dict(manifest.get("attempt_policy") or {}),
        },
        "policy": {
            "official_primary": (
                "status.json official_parse/category is the primary result "
                "and is preserved verbatim"
            ),
            "audit_projection": (
                "independent decoder over the terminal answer; records the "
                "recovered full JSON object and any disagreement; never "
                "changes the official result"
            ),
            "outcome_precedence": list(OUTCOME_ORDER),
            "failure_rule": (
                "timeout, provider failure and infrastructure failure are "
                "classified before parse failure; none is counted as a "
                "negative or as uncertain"
            ),
            "dangerous_negative_rule": (
                "official parser accepted one of the official safe "
                "categories on the frozen case whose known outcome is "
                "vulnerable: {}".format(", ".join(SAFE_CATEGORIES))
            ),
            "research_rule": (
                "research evidence = saved native tool calls, MCP "
                "observations or answer citations; tool-minted refs are "
                "cross-checked against the attempt audit sink"
            ),
            "parser_loss_rule": (
                "the official parser did not accept a category while the "
                "full-JSON audit recovered category=vulnerable"
            ),
        },
        "arms": arms,
        "totals": _totals(attempts),
        "attempts": attempts,
        "integrity": {
            "ok": not integrity_errors,
            "scheduled_attempts": len(expected_keys),
            "saved_attempts": len(saved_keys),
            "missing_attempts": sorted(expected_keys - saved_keys),
            "errors": integrity_errors,
            "warnings": integrity_warnings,
        },
        "limitations": limitations,
    }


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------


def _md(value: Any) -> str:
    if value is None:
        return "—"
    return str(value).replace("|", "\\|").replace("\n", " ")


def _compact(value: Any, limit: int = 140) -> str:
    text = " ".join(str(value or "").split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _fmt_counts(counts: Mapping[str, int], order: Sequence[str]) -> str:
    return " | ".join(str(counts.get(key, 0)) for key in order)


def _arm_table(comparison: Mapping[str, Any]) -> List[str]:
    outcomes = OUTCOME_ORDER
    lines = [
        "| Arm | Treatment | n | " + " | ".join(outcomes) + " |",
        "|---|---|---:|" + "".join("---:|" for _ in outcomes),
    ]
    for arm in P.ARM_ORDER:
        rollup = comparison["arms"][arm]
        treatments = ", ".join(rollup["treatments"]) or "none"
        lines.append(
            "| **{}** | {} | {} | {} |".format(
                arm, _md(treatments), rollup["attempts"],
                _fmt_counts(rollup["outcomes"], outcomes),
            )
        )
    totals = comparison["totals"]["outcomes"]
    lines.append(
        "| **total** | | {} | {} |".format(
            comparison["totals"]["attempts"],
            _fmt_counts(totals, outcomes),
        )
    )
    return lines


def _signed(value: int) -> str:
    return "{:+d}".format(value)


def _delta_table(comparison: Mapping[str, Any]) -> List[str]:
    """Per-arm deltas vs control A — where research/classification moved."""
    control = comparison["arms"]["A"]
    outcome_keys = (
        "vulnerable", "dangerous_negative", "uncertain", "parse_failure",
        "timeout", "provider_failure",
    )
    lines = [
        "| Arm vs A | " + " | ".join(
            "Δ " + key.replace("_", " ") for key in outcome_keys
        ) + " | Δ answers with research trace |",
        "|---|" + "".join("---:|" for _ in outcome_keys) + "---:|",
    ]
    for arm in P.ARM_ORDER[1:]:
        rollup = comparison["arms"][arm]
        cells = [
            _signed(rollup["outcomes"].get(key, 0)
                    - control["outcomes"].get(key, 0))
            for key in outcome_keys
        ]
        cells.append(_signed(
            rollup["attempts_with_research_trace"]
            - control["attempts_with_research_trace"]
        ))
        lines.append("| **{}** | {} |".format(arm, " | ".join(cells)))
    return lines


def _research_table(comparison: Mapping[str, Any]) -> List[str]:
    diagnoses = DIAGNOSIS_ORDER
    lines = [
        "| Arm | Native calls | MCP calls | Answers w/ citations | "
        "Decisive observations | " + " | ".join(diagnoses) + " |",
        "|---|---:|---:|---:|---:|" + "".join("---:|" for _ in diagnoses),
    ]
    for arm in P.ARM_ORDER:
        rollup = comparison["arms"][arm]
        lines.append(
            "| **{}** | {} | {} | {} | {} | {} |".format(
                arm,
                rollup["native_tool_calls"],
                rollup["mcp_tool_calls"],
                rollup["attempts_with_citations"],
                rollup["decisive_observations"],
                _fmt_counts(rollup["diagnoses"], diagnoses),
            )
        )
    totals = comparison["totals"]
    lines.append(
        "| **total** | {} | {} | {} | {} | {} |".format(
            totals["native_tool_calls"], totals["mcp_tool_calls"],
            totals["attempts_with_citations"],
            totals["attempts_with_decisive_observations"],
            _fmt_counts(totals["diagnoses"], diagnoses),
        )
    )
    return lines


def _attempt_table(comparison: Mapping[str, Any]) -> List[str]:
    lines = [
        "| # | Arm | Rpt | Official category | Official parse | "
        "Audit category | Audit status | First-layer outcome | "
        "Diagnosis | Native | MCP | Citations |",
        "|---:|---|---:|---|---|---|---|---|---|---:|---:|---:|",
    ]
    for attempt in comparison["attempts"]:
        official = attempt["official_parser_result"]
        audit = attempt["audit_projection"]
        research = attempt["research"]
        lines.append(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |"
            .format(
                _md(attempt["sequence_index"]),
                attempt["arm"],
                attempt["repeat"],
                _md(official.get("category")),
                _md(official.get("official_parse")),
                _md(audit.get("category")),
                _md(audit.get("status")),
                attempt["first_layer_outcome"],
                attempt["diagnosis"]["kind"],
                research.get("native_tool_call_count", 0),
                research.get("mcp_tool_call_count", 0),
                research.get("citation_count", 0),
            )
        )
    return lines


def _audit_table(comparison: Mapping[str, Any]) -> List[str]:
    rows = []
    for attempt in comparison["attempts"]:
        official = attempt["official_parser_result"]
        audit = attempt["audit_projection"]
        if not attempt["present"]:
            continue
        if (official.get("category") == audit.get("category")
                and audit.get("status") in ("matched", "no_input")):
            continue
        rows.append(attempt)
    if not rows:
        return ["No parser/audit projection divergences were recorded."]
    lines = [
        "| # | Arm | Rpt | Official | Official parse | Audit | "
        "Audit status | Recovered object keys |",
        "|---:|---|---:|---|---|---|---|---|",
    ]
    for attempt in rows:
        official = attempt["official_parser_result"]
        audit = attempt["audit_projection"]
        keys = audit.get("recovered_object_keys") or []
        lines.append(
            "| {} | {} | {} | {} | {} | {} | {} | {} |".format(
                _md(attempt["sequence_index"]),
                attempt["arm"],
                attempt["repeat"],
                _md(official.get("category")),
                _md(official.get("official_parse")),
                _md(audit.get("category")),
                _md(audit.get("status")),
                _md(", ".join(keys) or "—"),
            )
        )
    return lines


def _evidence_lines(attempt: Mapping[str, Any]) -> List[str]:
    research = attempt["research"]
    official = attempt["official_parser_result"]
    diagnosis = attempt["diagnosis"]
    if not attempt.get("present"):
        return [
            "",
            "### {}/r{} — missing_attempt".format(
                attempt["arm"], attempt["repeat"]
            ),
            "",
            "- No answer was saved for this scheduled attempt; there is no "
            "research trace or citation to link.",
            "",
        ]
    lines = [
        "",
        "### {}/r{} — {} / {}".format(
            attempt["arm"],
            attempt["repeat"],
            attempt["first_layer_outcome"],
            diagnosis["kind"],
        ),
        "",
        "- Official: category={}, parse={}, overall={}.".format(
            _md(official.get("category")),
            _md(official.get("official_parse")),
            _md(official.get("overall")),
        ),
        "- Diagnosis: {} (losing stage: {}). {}".format(
            diagnosis["kind"],
            diagnosis["losing_stage"],
            diagnosis["rationale"],
        ),
        "- Research trace: {} native tool call(s), {} MCP call(s), "
        "{} observation(s), {} citation(s) ({} resolved).".format(
            research.get("native_tool_call_count", 0),
            research.get("mcp_tool_call_count", 0),
            len(research.get("observations") or []),
            research.get("citation_count", 0),
            research.get("resolved_citation_count", 0),
        ),
    ]
    tools = research.get("native_tools_used") or []
    mcp_tools = research.get("mcp_tools_used") or []
    if tools:
        lines.append("- Native tools: {}.".format(
            ", ".join("`{}`".format(tool) for tool in tools)
        ))
    native_calls = research.get("native_tool_calls") or []
    if native_calls:
        lines.append("- Native tool calls (sample):")
        for call in native_calls[:8]:
            args = call.get("input")
            args_text = json.dumps(args, sort_keys=True, ensure_ascii=False) \
                if args is not None else "—"
            lines.append(
                "  - `{}` `{}` [{}] input={}".format(
                    _md(call.get("call_id")),
                    _md(call.get("tool")),
                    _md(call.get("status")),
                    _compact(args_text, 160),
                )
            )
        if len(native_calls) > 8:
            lines.append(
                "  - … {} more native call(s) in `comparison.json`.".format(
                    len(native_calls) - 8
                )
            )
    if mcp_tools:
        lines.append("- MCP tools: {}.".format(
            ", ".join("`{}`".format(tool) for tool in mcp_tools)
        ))

    observations = research.get("observations") or []
    if observations:
        lines.append("- Tool observations (decisive = cited by the answer):")
        for observation in observations[:10]:
            marker = "decisive" if observation.get("decisive") else "unused"
            lines.append(
                "  - `{}` [{}; {}/{}] {} — fact: {}".format(
                    observation.get("observation_id"),
                    marker,
                    _md(observation.get("tool_status")),
                    _md(observation.get("completeness")),
                    _md(observation.get("tool")),
                    _compact(observation.get("fact")),
                )
            )
            refs = observation.get("evidence_refs") or []
            if refs:
                lines.append(
                    "    - evidence refs: {}".format(
                        ", ".join("`{}`".format(ref) for ref in refs[:4])
                    )
                )
            if observation.get("cited_by"):
                lines.append(
                    "    - cited by: {}".format(
                        ", ".join("`{}`".format(ref)
                                  for ref in observation["cited_by"][:4])
                    )
                )
            limitations = observation.get("limitations") or []
            if limitations:
                lines.append(
                    "    - limitations: {}".format(
                        _compact("; ".join(limitations), 220)
                    )
                )
        if len(observations) > 10:
            lines.append(
                "  - … {} more observation(s) in `comparison.json`.".format(
                    len(observations) - 10
                )
            )

    citations = research.get("citations") or []
    if citations:
        lines.append("- Source citations:")
        for citation in citations[:_MD_MAX_CITATIONS]:
            linked = []
            if citation.get("observation_ids"):
                linked.append("observations: " + ", ".join(
                    "`{}`".format(item)
                    for item in citation["observation_ids"]
                ))
            if citation.get("native_call_ids"):
                linked.append("native calls: " + ", ".join(
                    "`{}`".format(item)
                    for item in citation["native_call_ids"]
                ))
            lines.append(
                "  - `{}` — {}; origin: {}; claims: {}".format(
                    citation["ref"],
                    "resolved" if citation["resolved"] else "unresolved",
                    ", ".join(citation.get("origins") or []) or "—",
                    _compact("; ".join(
                        claim.get("statement") or ""
                        for claim in citation.get("claims") or []
                    ) or "—", 180),
                )
            )
            if linked:
                lines.append("    - " + "; ".join(linked))
        if len(citations) > _MD_MAX_CITATIONS:
            lines.append(
                "  - … {} more citation(s) in `comparison.json`.".format(
                    len(citations) - _MD_MAX_CITATIONS
                )
            )
    else:
        lines.append(
            "- No source citations or tool observations were recorded for "
            "this answer."
        )
    return lines


def render_markdown(comparison: Mapping[str, Any]) -> str:
    case = comparison["scope"]["case"]
    arms = comparison["arms"]
    lines = [
        "# First-layer VEX ablation — comparison",
        "",
        "**Single-case diagnostic — not evidence of general parity.**",
        "",
        "Generated {} by `eval.first_layer_ablation.report` ({}). "
        "Offline only: no model, Docker, network, izyan MCP or downstream "
        "verifier call was made.".format(
            comparison["generated_at_utc"], REPORT_SCHEMA
        ),
        "",
        "| Field | Value |",
        "|---|---|",
        "| Experiment | `{}` |".format(
            _md(comparison.get("experiment_id"))
        ),
        "| Case | `{}` |".format(_md(case.get("task_id"))),
        "| CVE | `{}` |".format(_md(case.get("cve_id"))),
        "| Snapshot commit | `{}` |".format(_md(case.get("commit_sha"))),
        "| Expected category | `{}` (known outcome of this one case) |".format(
            comparison["scope"]["expected_category"]
        ),
        "| Manifest sha256 | `{}` |".format(
            _md(comparison.get("manifest_sha256"))
        ),
        "| Scheduled attempts | {} |".format(
            comparison["integrity"]["scheduled_attempts"]
        ),
        "| Saved attempts | {} |".format(
            comparison["integrity"]["saved_attempts"]
        ),
        "",
        "> One case localizes where the first layer loses quality; it does "
        "not prove general VEX parity. Do not cite this report as a parity "
        "result.",
        "",
        "## Method and boundaries",
        "",
        "- **Official parser result** (`status.json`) is primary and is "
        "preserved verbatim. It determines the first-layer outcome.",
        "- **Full-JSON audit projection** is a separate decoder over the "
        "terminal answer. It records the complete recovered object and any "
        "disagreement, but never replaces the official result.",
        "- **Research trace** is separate again: native tool calls, MCP "
        "observations and the answer's own source citations. A citation is "
        "marked resolved only when a tool-minted evidence ref or matching "
        "native tool call exists in the saved trace.",
        "- Outcomes are mutually exclusive: timeout, provider failure and "
        "infrastructure failure are classified before parse failure; none "
        "is counted as a negative or as uncertain. `dangerous_negative` "
        "requires an officially accepted safe category on this "
        "known-vulnerable case.",
        "- No downstream verifier/validator was read or used. Any "
        "`validator_results.jsonl` in an attempt directory is ignored.",
        "",
        "## First-layer outcomes by arm",
        "",
        *_arm_table(comparison),
        "",
        "`dangerous_negative` is the safety-relevant first-layer error. "
        "`parse_failure` is a formalization failure, never a safe answer. "
        "`missing_attempt` means the scheduled attempt has no saved "
        "directory (for example an aborted run); it is not silence from "
        "the model.",
        "",
        "## Treatment deltas vs control A",
        "",
        "Each arm is cumulative (B = A + advisory data, and so on), so a "
        "delta locates the treatment after which the first-layer "
        "classification or the research trace changed on this case.",
        "",
        *_delta_table(comparison),
        "",
        "## Research and diagnosis by arm",
        "",
        *_research_table(comparison),
        "",
        "`correct` = officially accepted vulnerable. "
        "`researched_but_wrong_conclusion` = a safe negative with tool or "
        "citation traces. `not_researched` = a safe negative/abstention "
        "with no saved research trace. `correct_answer_lost_by_parser` = "
        "the full-JSON audit recovered vulnerable while the official parser "
        "did not accept it. `researched_inconclusive` = traces exist but "
        "the model abstained. `researched_answer_unparsed` = traces exist "
        "but neither parser recovered the expected category. `no_answer` = "
        "timeout/provider/infrastructure/missing attempt.",
        "",
        "## Per-attempt outcomes",
        "",
        *_attempt_table(comparison),
        "",
        "## Official vs full-JSON audit projection",
        "",
        "The audit column is a second opinion on the same terminal text. "
        "The official column remains authoritative even when the two "
        "differ.",
        "",
        *_audit_table(comparison),
        "",
        "## Decisive tool observations and source citations",
        "",
        "Each answer is listed with the observations a reviewer can use to "
        "audit its claims. `decisive` marks observations whose "
        "`evidence_refs` the answer cites; unresolved citations are "
        "agent-written references with no matching tool-minted ref or "
        "native tool call in the saved trace.",
        "",
    ]
    for attempt in comparison["attempts"]:
        lines.extend(_evidence_lines(attempt))

    lines.extend([
        "",
        "## Integrity and coverage",
        "",
        "| Check | Result |",
        "|---|---|",
        "| Manifest self-hash | {} |".format(
            "verified" if comparison.get("manifest_sha256")
            else "not stored"
        ),
        "| Scheduled/saved attempts | {}/{} |".format(
            comparison["integrity"]["saved_attempts"],
            comparison["integrity"]["scheduled_attempts"],
        ),
        "| Missing attempts | {} |".format(
            _md(", ".join(comparison["integrity"]["missing_attempts"])
                or "none")
        ),
        "| Integrity errors | {} |".format(
            len(comparison["integrity"]["errors"])
        ),
        "| Integrity warnings | {} |".format(
            len(comparison["integrity"]["warnings"])
        ),
        "",
    ])
    if comparison["integrity"]["errors"]:
        lines.append("**Errors:**")
        lines.append("")
        lines.extend("- {}".format(error)
                     for error in comparison["integrity"]["errors"])
        lines.append("")
    if comparison["integrity"]["warnings"]:
        lines.append("**Warnings:**")
        lines.append("")
        lines.extend("- {}".format(warning)
                     for warning in comparison["integrity"]["warnings"])
        lines.append("")
    if not comparison["integrity"]["errors"] \
            and not comparison["integrity"]["warnings"]:
        lines.append(
            "No integrity errors or warnings: every scheduled key is "
            "accounted for, and every present attempt's prompt hash "
            "matches the manifest."
        )
        lines.append("")

    lines.extend([
        "## Limitations",
        "",
    ])
    lines.extend("- {}".format(item)
                 for item in comparison.get("limitations") or [])
    lines.append("")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Public writer / CLI
# ---------------------------------------------------------------------------


def write_report(comparison: Mapping[str, Any],
                 out_dir: Path) -> Tuple[Path, Path]:
    out_dir = Path(out_dir)
    json_path = _write_atomic(
        out_dir / "comparison.json",
        json.dumps(comparison, indent=2, sort_keys=True,
                   ensure_ascii=False) + "\n",
    )
    markdown_path = _write_atomic(
        out_dir / "comparison.md", render_markdown(comparison)
    )
    return json_path, markdown_path


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Build the first-layer VEX ablation comparison from saved "
            "attempts. Offline only: no model, Docker, network or verifier."
        )
    )
    parser.add_argument(
        "--experiment-dir", required=True,
        help="Task 2 experiment root containing manifest.json and attempts",
    )
    parser.add_argument(
        "--out-dir", default=None,
        help="output directory (default: the experiment directory)",
    )
    parser.add_argument(
        "--harness-dir", default=None,
        help=("vexbench harness checkout (default: C1_HARNESS_DIR or "
              "/tmp/vexbench-agent-ctl); used only to re-derive the "
              "official category when status.json does not store it"),
    )
    parser.add_argument(
        "--fail-on-integrity", action="store_true",
        help="exit 2 when the report records integrity errors",
    )
    args = parser.parse_args(argv)
    experiment_dir = Path(args.experiment_dir)
    out_dir = Path(args.out_dir) if args.out_dir else experiment_dir
    try:
        official_parser = load_official_parser(Path(args.harness_dir)) \
            if args.harness_dir else None
        comparison = build_comparison(
            experiment_dir, official_parser=official_parser
        )
    except ReportError as exc:
        print("report error: {}".format(exc), file=sys.stderr)
        return 2
    json_path, markdown_path = write_report(comparison, out_dir)
    print(json.dumps({
        "comparison_json": str(json_path),
        "comparison_md": str(markdown_path),
        "attempts": comparison["totals"]["attempts"],
        "present": comparison["totals"]["present"],
        "outcomes": comparison["totals"]["outcomes"],
        "diagnoses": comparison["totals"]["diagnoses"],
        "integrity_ok": comparison["integrity"]["ok"],
    }, indent=2, sort_keys=True))
    if args.fail_on_integrity and not comparison["integrity"]["ok"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

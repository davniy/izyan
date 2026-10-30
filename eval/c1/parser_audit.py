"""Secondary / parser-audit projection for Task 4 (spec §8.3.2, plan §6).

A predetermined, string-aware JSON decoder applied ONLY to the last
assistant terminal text of an attempt. Unlike the official harness
extractor (``result_parser._extract_json_object``, hand-rolled brace
counting that breaks on ``{``/``}`` inside string literals), this decoder
tries ``json.JSONDecoder().raw_decode`` at every ``{`` position and keeps
the first COMPLETE valid JSON object that carries the ``category`` key.

Hard rules (spec §8.3, plan §6):

- input is the terminal assistant text only — never the prompt, never
  tool/command output, never earlier agent messages;
- terminal-text extraction is adapter-aware: each agent profile's own
  ``extract_text`` rule is mirrored (``codex_terminal_text`` for Codex
  NDJSON, ``opencode_terminal_text`` for the opencode export JSON);
  an unknown adapter records ``no_input`` with an explicit reason —
  the codex rule is never silently applied to a foreign format;
- only a fully decoded JSON object is recovered — never a category token
  from prose, a truncated string, or a label-only regex match;
- the same rule applies to every category, positive and unsafe-negative
  alike, and to every cohort (B1 / B1' / C1) unchanged;
- nothing here replaces the official metrics — this is a second,
  explicitly named projection whose disagreements are stored, not a
  repair of ``result_parser.py``.

``PARSER_AUDIT_DECODER_VERSION`` identifies the rule; bump it whenever
the extraction rule changes so stored audits stay interpretable.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterator, Optional, Tuple

PARSER_AUDIT_DECODER_VERSION = "c1-parser-audit/1"
PARSER_AUDIT_SCHEMA = "parser-audit-metrics/1"

# The official 12 categories, duplicated verbatim from the harness
# (result_parser.CATEGORY_ORDER) so this module stays stdlib-only and
# usable without the harness checkout on sys.path.
CATEGORY_ORDER: Tuple[str, ...] = (
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

# Audit statuses — a closed vocabulary, recorded per attempt:
AUDIT_STATUS_MATCHED = "matched"  # official and audit agree on the category
AUDIT_STATUS_RECOVERED = "recovered"  # official failed, audit found valid object
AUDIT_STATUS_DISAGREED = "disagreed"  # both resolved, categories differ
AUDIT_STATUS_NO_VALID = "no_valid_category"  # object found, category invalid
AUDIT_STATUS_NO_OBJECT = "no_object"  # no complete JSON object at all
AUDIT_STATUS_NO_INPUT = "no_input"  # no terminal assistant text
AUDIT_STATUSES = (
    AUDIT_STATUS_MATCHED,
    AUDIT_STATUS_RECOVERED,
    AUDIT_STATUS_DISAGREED,
    AUDIT_STATUS_NO_VALID,
    AUDIT_STATUS_NO_OBJECT,
    AUDIT_STATUS_NO_INPUT,
)

# Statuses where the audit's resolved answer genuinely differs from the
# official parse — what "parse disagreement" means in the metrics.
# ``no_input``/``no_object`` with a blind official row are shared misses,
# not divergences; a ``no_object`` against an official category is folded
# into ``disagreed`` (kind=audit_no_object).
DIVERGENT_STATUSES = frozenset(
    {AUDIT_STATUS_RECOVERED, AUDIT_STATUS_DISAGREED, AUDIT_STATUS_NO_VALID})

_FENCE_RE = re.compile(r"^```(?:json)?\s*\n?(.*?)\n?```\s*$", re.DOTALL)


def codex_terminal_text(ndjson: str) -> str:
    """Last ``agent_message`` text from Codex NDJSON events.

    Same rule as the harness's ``CodexAgent.extract_text`` (kept here so
    the audit does not import the external checkout): the text of the
    last ``item.completed`` event whose item type is ``agent_message``.
    Tool results, command output and earlier messages are never seen.
    """
    texts: list[str] = []
    for line in ndjson.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if ev.get("type") != "item.completed":
            continue
        item = ev.get("item")
        if isinstance(item, dict) and item.get("type") == "agent_message":
            t = item.get("text")
            if isinstance(t, str):
                texts.append(t)
    return texts[-1].strip() if texts else ""


def opencode_terminal_text(raw: str) -> str:
    """Last assistant ``text`` part from an opencode result payload.

    Same rule as the harness's ``OpenCodeAgent.extract_text`` (kept here
    so the audit does not import the external checkout): a well-formed
    export JSON (``{"info": ..., "messages": [...]}``) yields the last
    ``text`` part of the LAST assistant message; anything else falls back
    to the legacy opencode JSONL stream (last ``text`` event). User
    messages, tool/reasoning parts and earlier assistant texts are never
    seen.
    """
    try:
        export = json.loads(raw)
    except json.JSONDecodeError:
        export = None
    if isinstance(export, dict) and isinstance(export.get("messages"), list):
        for message in reversed(export["messages"]):
            if not isinstance(message, dict):
                continue
            info = message.get("info")
            if not isinstance(info, dict) or info.get("role") != "assistant":
                continue
            for part in reversed(message.get("parts") or []):
                if not isinstance(part, dict):
                    continue
                if part.get("type") == "text" and part.get("text"):
                    return part["text"].strip()
        return ""
    # legacy opencode JSONL stream: last ``text`` event's part text
    texts = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        part = ev.get("part")
        if ev.get("type") == "text" and isinstance(part, dict) \
                and part.get("text"):
            texts.append(part["text"])
    return texts[-1].strip() if texts else ""


# Harness adapter profile -> raw-result -> terminal-text function. Keys
# are ``evaluate.agents.AGENTS`` names; each value mirrors that agent's
# ``extract_text`` verbatim. An adapter NOT in this table is never
# guessed at — the audit records ``no_input`` with an explicit reason
# instead of silently applying the codex rule to a foreign format.
TERMINAL_TEXT_EXTRACTORS = {
    "codex": codex_terminal_text,
    "codex-b1p": codex_terminal_text,
    "codex-c1": codex_terminal_text,
    "opencode": opencode_terminal_text,
    "opencode-b1p": opencode_terminal_text,
    "opencode-c1": opencode_terminal_text,
}

# Each adapter's ``result_filename()`` — the file the run stage writes.
# Used when no live agent instance is available (injected row builders);
# ``audit_run_dir``/``report._read_result`` still probe the alternate
# name, so a wrong guess degrades to a probe, never a miss.
ADAPTER_RESULT_FILENAMES = {
    "codex": "result.jsonl",
    "codex-b1p": "result.jsonl",
    "codex-c1": "result.jsonl",
    "opencode": "result.json",
    "opencode-b1p": "result.json",
    "opencode-c1": "result.json",
}


def resolve_terminal_text_extractor(extractor):
    """Normalize ``extractor`` to a ``raw -> terminal text`` callable.

    Accepts a callable (used verbatim), an adapter name (looked up in
    ``TERMINAL_TEXT_EXTRACTORS``), or ``None`` — the codex rule, matching
    the audit's original single-adapter behavior. Unknown names or types
    return ``None`` so callers record an explicit ``no_input``.
    """
    if extractor is None:
        extractor = "codex"
    if callable(extractor):
        return extractor
    if isinstance(extractor, str):
        return TERMINAL_TEXT_EXTRACTORS.get(extractor)
    return None


def terminal_text(raw: Optional[str], extractor="codex") -> str:
    """Extract the terminal assistant text from a raw result payload.

    Raises ``ValueError`` on an unknown adapter — callers translate that
    into an explicit ``no_input`` record, never a silent miss.
    """
    fn = resolve_terminal_text_extractor(extractor)
    if fn is None:
        raise ValueError(f"unknown terminal-text extractor {extractor!r}")
    if raw is None:
        return ""
    return fn(raw) or ""


def iter_json_objects(text: str) -> Iterator[Tuple[int, dict]]:
    """Yield ``(start, obj)`` for every complete JSON object decodable by
    ``raw_decode`` at a ``{`` position — string-aware, nesting-tolerant.

    A ``{`` inside a string literal never yields a candidate because
    ``raw_decode`` at that offset fails (the char after ``{`` is not the
    start of a quoted key). Truncated tails are simply skipped.
    """
    decoder = json.JSONDecoder()
    for m in re.finditer(r"\{", text):
        try:
            obj, _end = decoder.raw_decode(text, m.start())
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            yield m.start(), obj


def find_category_object(text: str) -> Optional[dict]:
    """The first complete JSON object containing a ``category`` key."""
    for _pos, obj in iter_json_objects(text):
        if "category" in obj:
            return obj
    return None


def normalize_category(value) -> Optional[str]:
    """Same acceptance as ``result_parser._parse_json``: a string whose
    lowercase form is one of the 12 categories."""
    if not isinstance(value, str):
        return None
    cat = value.strip().lower()
    return cat if cat in VALID_CATEGORIES else None


def extract_reasoning(obj: dict) -> Optional[str]:
    reasoning = obj.get("reasoning")
    return reasoning if isinstance(reasoning, str) and reasoning.strip() else None


def category_to_binary(category: Optional[str]) -> Optional[str]:
    """Mirror of official ``to_binary``: vulnerable -> exploitable, every
    other valid category -> not_exploitable, anything else -> None."""
    if category is None:
        return None
    if category == "vulnerable":
        return "exploitable"
    if category in VALID_CATEGORIES:
        return "not_exploitable"
    return None


def audit_terminal_text(terminal_text: Optional[str],
                        official_category: Optional[str] = None) -> dict:
    """Run the audit decoder on one terminal text.

    ``official_category`` is the category the unchanged official parser
    produced for the same text (None when it failed). The returned record
    is self-contained: decoder version, status, recovered full object,
    and the disagreement (if any) — original metrics stay untouched.
    ``input_error`` records WHY there was no terminal text (missing
    result file, unknown adapter, extractor failure); ``None`` when the
    decoder saw a real payload.
    """
    rec = {
        "decoder": PARSER_AUDIT_DECODER_VERSION,
        "status": None,
        "official_category": official_category,
        "audit_category": None,
        "audit_reasoning": None,
        "disagreement": None,
        "terminal_text_len": len(terminal_text or ""),
        "objects_found": 0,
        "category_objects_found": 0,
        "recovered_object": None,
        "input_error": None,
    }
    if not terminal_text or not terminal_text.strip():
        rec["status"] = AUDIT_STATUS_NO_INPUT
        return rec

    objects = list(iter_json_objects(terminal_text))
    cat_positions = [i for i, (_p, o) in enumerate(objects) if "category" in o]
    rec["objects_found"] = len(objects)
    rec["category_objects_found"] = len(cat_positions)

    if not cat_positions:
        # If the official parser nevertheless produced a category (its
        # brace-count window can decode a span raw_decode refuses), that
        # is a genuine divergence — record it as such.
        if official_category is not None:
            rec["status"] = AUDIT_STATUS_DISAGREED
            rec["disagreement"] = {
                "official": official_category,
                "audit": None,
                "kind": "audit_no_object",
            }
        else:
            rec["status"] = AUDIT_STATUS_NO_OBJECT
        return rec

    obj = objects[cat_positions[0]][1]
    rec["recovered_object"] = obj
    cat = normalize_category(obj.get("category"))
    rec["audit_reasoning"] = extract_reasoning(obj)

    if cat is None:
        # A complete object exists but its category is unusable. If the
        # official parser still produced a category (e.g. it read a
        # different object), that is a disagreement, not a shared miss.
        if official_category is not None:
            rec["status"] = AUDIT_STATUS_DISAGREED
            rec["disagreement"] = {
                "official": official_category,
                "audit": None,
                "kind": "audit_object_category_invalid",
            }
        else:
            rec["status"] = AUDIT_STATUS_NO_VALID
        return rec

    rec["audit_category"] = cat
    if official_category is None:
        rec["status"] = AUDIT_STATUS_RECOVERED
        rec["disagreement"] = {
            "official": None,
            "audit": cat,
            "kind": "official_missed_full_object",
        }
    elif official_category != cat:
        rec["status"] = AUDIT_STATUS_DISAGREED
        rec["disagreement"] = {
            "official": official_category,
            "audit": cat,
            "kind": "different_category",
        }
    else:
        rec["status"] = AUDIT_STATUS_MATCHED
    return rec


def audit_run_dir(run_dir, official_category: Optional[str] = None,
                  result_filename: str = "result.jsonl",
                  extractor="codex") -> dict:
    """Audit one attempt directory: read the adapter's result file and
    decode its LAST assistant message.

    ``extractor`` selects how terminal text is pulled from the raw
    payload — an adapter name from ``TERMINAL_TEXT_EXTRACTORS`` or a
    ``raw -> text`` callable (e.g. the harness agent's own
    ``extract_text``). ``result_filename`` is tried first, then the
    alternate adapter filename, so an ``opencode`` attempt audits its
    ``result.json`` without extra plumbing. Missing file, empty
    extraction or an unknown adapter all produce ``no_input`` — always
    with an explicit ``input_error`` reason, never a silent miss.
    """
    run_dir = Path(run_dir)
    candidates = [result_filename] + [
        f for f in ("result.jsonl", "result.json") if f != result_filename]
    raw: Optional[str] = None
    seen = []
    for name in candidates:
        path = run_dir / name
        if path.is_file():
            raw = path.read_text(encoding="utf-8", errors="replace")
            break
        seen.append(name)
    rec = audit_terminal_text(None, official_category)
    if raw is not None:
        try:
            text = terminal_text(raw, extractor)
        except Exception as exc:  # unknown adapter or extractor failure
            rec["input_error"] = str(exc)
            return rec
        rec = audit_terminal_text(text, official_category)
    if rec["status"] == AUDIT_STATUS_NO_INPUT and rec["input_error"] is None:
        if raw is None:
            rec["input_error"] = f"no result file ({'/'.join(seen)})"
        else:
            rec["input_error"] = \
                "no terminal assistant text in result payload"
    return rec

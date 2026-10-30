"""Offline scoring + audit for Task 4 cohorts (plan §6 / spec §9, §11).

Reads a finished cohort in the official harness layout

    <run_root>/<task_id>/run_00N/{result.jsonl | result.json | error.txt | status.json, ...}

and produces the §11 artifact set under ``--out``:

    official_metrics.json     — primary / official-strict projection:
                                rows built by the unchanged harness
                                ``evaluate.parse._parse_run`` + agent
                                ``load_result``, scored by the unchanged
                                ``evaluate.metrics.compute_metrics``;
                                byte-checkable against an official
                                metrics.json (--official-metrics) and
                                parsed.jsonl (--check-parsed)
    safety_metrics.json       — safety-aware projection (False-Safe,
                                Safe Clear Rate, recall, INCONCLUSIVE,
                                FAILED classes, stability) computed by
                                the reused eval.vexbench_plain_report
                                functions — never a second interpretation;
                                plus the aggregated assessment_schema
                                dimension (valid/invalid/absent per
                                cohort, from status.json — reporting
                                only, never feeds ``overall``)
    parser_audit_metrics.json — secondary / parser-audit projection
                                (eval.c1.parser_audit, string-aware full
                                JSON recovery on the terminal assistant
                                text only) re-scored under the same
                                policies, plus per-attempt audit records
    case_comparison.jsonl     — one row per (task_id, run_id): official
                                vs audit category/outcome, failure class,
                                tool-use counters, decisive evidence
    disagreements.md          — parser disagreements, paired transitions
                                vs a reference cohort (B1/B1'), False-Safe
                                appeared/cleared, per-case negatives
    tool_use_summary.md       — evidence-tool invocation audit: counts,
                                status/completeness, families, duration,
                                repeated calls, missing coverage,
                                decisive Observation refs

No model calls, no runner interaction, no writes outside ``--out``. The
official parser/scorer files are imported, never modified.

Run (harness venv — needs pydantic v2 + sklearn for evaluate.metrics):

    /tmp/vexbench-agent-ctl/.venv/bin/python -m eval.c1.report \
        --run-root <model-level run dir> \
        --tasks /tmp/vexbench-agent-ctl/benchmark/tasks/vex_bench.jsonl \
        --repeats 3 --out <scoring dir> [--agent codex-c1] \
        [--baseline-run-root <B1 model-level dir>] [--label C1] [--note ...]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Callable, Iterable, Optional, Sequence

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from eval import vexbench_plain_report as vpr  # noqa: E402
from eval.c1 import parser_audit  # noqa: E402
from eval.c1.status import (  # noqa: E402
    AttemptStatus,
    classify_runtime_error,
    detect_provider_refusal,
)

logger = logging.getLogger(__name__)

REPORT_SCHEMA = "c1-scoring/1"
DEFAULT_HARNESS = Path("/tmp/vexbench-agent-ctl")
DEFAULT_MODEL = "gpt-6.1-sol"
DEFAULT_REPEATS = 3
RESULT_FILENAME = "result.jsonl"

# MCP evidence-tool families — mirrors internal/evidencetools/mcp.go
# toolCatalog groups (spec §6 areas). Unknown tools land in "other".
TOOL_FAMILY: dict[str, str] = {
    "get_vulnerability": "research",
    "get_advisory": "research",
    "get_fix_references": "research",
    "get_fix_diff": "research",
    "get_product_snapshot": "deps_build",
    "get_dependency_graph": "deps_build",
    "get_module_version": "deps_build",
    "run_govulncheck": "deps_build",
    "run_build": "exec",
    "run_tests": "exec",
    "find_symbol": "source_calls",
    "find_references": "source_calls",
    "find_callers": "source_calls",
    "find_may_callers": "source_calls",
    "find_dep_callers": "source_calls",
    "find_entrypoints": "source_calls",
    "read_function": "source_calls",
    "read_source": "source_calls",
    "search_source": "source_calls",
    "trace_argument": "dataflow_guards",
    "find_validations": "dataflow_guards",
    "scan_dynamic": "dynamic",
    "interface_dispatch_sites": "dynamic",
    "gated_refs": "dynamic",
    "dep_invocation_state": "dynamic",
    "module_usage": "dynamic",
    "module_internal_reach": "dynamic",
    "check_call_site_guard": "config_checks",
    "field_assignments": "config_checks",
    "check_missing_call": "config_checks",
    "sensitive_fields": "config_checks",
}

# Tools that can produce reachability-oriented evidence. A safe verdict
# without ANY of these calls is flagged for review ("missed check"),
# because a code_not_reachable-style claim on a present dependency is the
# classic False-Safe mechanism (plan §8 risk table).
REACHABILITY_TOOLS = frozenset(
    {
        "find_callers",
        "find_may_callers",
        "find_dep_callers",
        "find_references",
        "find_entrypoints",
        "module_usage",
        "module_internal_reach",
        "dep_invocation_state",
        "scan_dynamic",
        "run_govulncheck",
        "interface_dispatch_sites",
        "gated_refs",
    }
)

# Failure classes bucket spec §9 FAILED "by class". Values combine
# status.json failure_reasons (status.py) and derived classes used when
# no status.json exists (B1 and the harness-run cohort layout).
FAILURE_CLASSES_ORDERED = (
    "timeout",
    "provider_refusal",
    "provider_safety_filter",
    "provider_at_capacity",
    "provider_rate_limit",
    "provider_error",
    "container_nonzero_exit",
    "docker_create_failed",
    "docker_cp_failed",
    "docker_start_failed",
    "artifact_export_failed",
    "mcp_transport_failure",
    "transport_failure",
    "invalid_terminal_answer",
    "no_result",
    "no_dir",
)

OUTCOME_RANK = {"positive": 0, "safe": 1, "abstain": 2, "failed": 3}


class ReportError(Exception):
    pass


def fail(msg):
    raise ReportError(msg)


# ---------------------------------------------------------------------------
# harness access (lazy — unit tests inject fakes)
# ---------------------------------------------------------------------------


def _harness_src(harness_dir: Path) -> Path:
    src = Path(harness_dir) / "src"
    if not (src / "evaluate").is_dir():
        fail(f"harness checkout not found at {harness_dir} "
             "(set --harness-dir or C1_HARNESS_DIR)")
    return src


def load_harness(harness_dir: Path):
    """Import official harness modules; returns a namespace dict.

    The official parser/extractor/scorer are used as-is — importing them
    here is what makes the primary projection byte-faithful. Nothing is
    patched or wrapped.
    """
    src = str(_harness_src(harness_dir))
    if src not in sys.path:
        sys.path.insert(0, src)
    import evaluate.parse  # noqa: E402
    import evaluate.metrics  # noqa: E402
    from evaluate.agents import AGENTS  # noqa: E402

    return {
        "parse_run": evaluate.parse._parse_run,
        "compute_metrics": evaluate.metrics.compute_metrics,
        "agents": AGENTS,
    }


def _resolve_agent(harness_dir: Path, run_root: Path, agent_name: Optional[str],
                   model: str):
    if agent_name is None:
        agent_name = run_root.parent.name  # .../<prompt>/<agent>/<model>
        logger.info("agent inferred from run_root layout: %s", agent_name)
    agents = load_harness(harness_dir)["agents"]
    if agent_name not in agents:
        fail(f"unknown agent {agent_name!r}; have {sorted(agents)}")
    return agents[agent_name](model=model), agent_name


def build_official_rows(tasks: Sequence[dict], run_root: Path, repeats: int,
                        row_builder: Callable[[dict, int], dict]
                        ) -> list[dict]:
    """One parsed row per (task, run_00N), in benchmark task order —
    the same iteration contract as official ``evaluate.parse.parse``.
    ``row_builder(task, rep)`` is ``evaluate.parse._parse_run`` in
    production; tests inject a synthetic equivalent.
    """
    return [row_builder(task, rep) for task in tasks
            for rep in range(1, repeats + 1)]


def _harness_row_builder(agent, run_root: Path, model: str):
    """The exact official ``evaluate.parse._parse_run`` closure."""
    from evaluate.parse import _parse_run  # noqa: E402 — resolved lazily

    run_root = Path(run_root)

    def _one(task: dict, rep: int) -> dict:
        return _parse_run(agent, task, run_root, rep, model)

    return _one


def load_tasks(tasks_path: Path) -> list[dict]:
    tasks_path = Path(tasks_path)
    if not tasks_path.is_file():
        fail(f"tasks file not found: {tasks_path}")
    tasks = [json.loads(l) for l in
             tasks_path.read_text(encoding="utf-8").splitlines()
             if l.strip()]
    for t in tasks:
        for fld in ("task_id", "ground_truth", "ground_truth_category",
                    "cve_id"):
            if t.get(fld) in (None, ""):
                fail(f"{tasks_path}: task missing {fld!r}: {t!r}")
    return tasks


# ---------------------------------------------------------------------------
# per-attempt enrichment: terminal text, failure classes, audit, tools
# ---------------------------------------------------------------------------


def _read_result(run_dir: Path,
                 filename: Optional[str] = None) -> Optional[str]:
    """Raw adapter output for one attempt. ``filename`` (the resolved
    agent's ``result_filename()``) is tried first, then the other
    known adapter file — an opencode cohort stores ``result.json``.
    """
    run_dir = Path(run_dir)
    candidates = [f for f in (filename, RESULT_FILENAME, "result.json")
                  if f]
    for name in dict.fromkeys(candidates):
        p = run_dir / name
        if p.is_file():
            return p.read_text(encoding="utf-8", errors="replace")
    return None


def _load_status_json(run_dir: Path) -> Optional[AttemptStatus]:
    p = Path(run_dir) / "status.json"
    if not p.is_file():
        return None
    try:
        return AttemptStatus.model_validate_json(
            p.read_text(encoding="utf-8"))
    except Exception as exc:  # never let one artifact kill the audit
        logger.warning("%s: unparsable status.json (%s)", p, exc)
        return None


def _iter_events(raw: Optional[str]) -> Iterable[dict]:
    if not raw:
        return
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(ev, dict):
            yield ev


def _provider_error_messages(raw: Optional[str]) -> list[str]:
    """``error``/``turn.failed`` event messages from the Codex stream."""
    out = []
    for ev in _iter_events(raw) or ():
        t = ev.get("type")
        if t == "error" and isinstance(ev.get("message"), str):
            out.append(ev["message"])
        elif t == "turn.failed":
            msg = (ev.get("error") or {}).get("message")
            if isinstance(msg, str):
                out.append(msg)
    return out


def _provider_error_class(messages: Sequence[str]) -> Optional[str]:
    """Classify provider/transport error strings into failure classes."""
    low = [m.lower() for m in messages]
    joined = "\n".join(low)
    if not joined:
        return None
    if "at capacity" in joined:
        return "provider_at_capacity"
    if "rate limit" in joined or "rate_limit" in joined:
        return "provider_rate_limit"
    if any(h in joined for h in ("refused", "content_filter",
                                 "safety filter", "model_refusal")):
        return "provider_refusal"
    if "stream disconnected" in joined or "stream error" in joined:
        return "transport_failure"
    return "provider_error"


def classify_failure(row_status: str, run_dir: Path, raw: Optional[str],
                     terminal_text: str) -> Optional[str]:
    """Map a non-ok official row to a failure class (spec §9).

    Order: status.json failure_reason (controller-stamped, most
    precise) → error.txt runtime classification → provider/transport
    error events inside result.jsonl → refusal hints in the terminal
    text → bare parse_fail. A failed attempt is a FAILED outcome — never
    ``uncertain``, never a negative.
    """
    if row_status == "ok":
        return None
    run_dir = Path(run_dir)
    st = _load_status_json(run_dir)
    if st is not None and st.failure_reason:
        reason = st.failure_reason
        if reason == "invalid_terminal_answer":
            pcls = _provider_error_class(_provider_error_messages(raw))
            if pcls:
                return pcls
            if terminal_text and detect_provider_refusal(terminal_text):
                return "provider_refusal"
        return reason
    if row_status == "no_dir":
        return "no_dir"
    if row_status == "no_result":
        err = run_dir / "error.txt"
        if err.is_file():
            text = err.read_text(encoding="utf-8", errors="replace")
            if "at capacity" in text.lower():
                return "provider_at_capacity"
            _exec, reason = classify_runtime_error(text)
            return reason
        return "no_result"
    # parse_fail: the file exists but the official parser rejected the
    # terminal answer — look for the concrete cause.
    pcls = _provider_error_class(_provider_error_messages(raw))
    if pcls:
        return pcls
    if not terminal_text:
        return "invalid_terminal_answer"
    if detect_provider_refusal(terminal_text):
        return ("provider_safety_filter"
                if "filter" in terminal_text.lower()
                else "provider_refusal")
    return "invalid_terminal_answer"


def read_mcp_audit(run_dir: Path) -> tuple[list[dict], str]:
    """Server-side tool audit records. Sources, best first:
    ``tool_calls.jsonl`` (controller copy) then the exported artifact
    ``artifacts/izyan-audit/tool_calls.jsonl``. Missing files are a
    coverage fact, not "zero calls"."""
    run_dir = Path(run_dir)
    for rel in (Path("tool_calls.jsonl"),
                Path("artifacts") / "izyan-audit" / "tool_calls.jsonl"):
        p = run_dir / rel
        if p.is_file():
            return _parse_jsonl_records(p), str(rel)
    return [], "absent"


def _parse_jsonl_records(path: Path) -> list[dict]:
    out = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(rec, dict) and isinstance(rec.get("tool"), str):
            out.append(rec)
    return out


def _mcp_calls_from_result(raw: Optional[str]) -> list[dict]:
    """Fallback: ``mcp_tool_call`` items inside Codex's own NDJSON —
    the agent-side trace. Used only when the server audit is absent."""
    calls = []
    for ev in _iter_events(raw) or ():
        if ev.get("type") != "item.completed":
            continue
        it = ev.get("item")
        if not isinstance(it, dict) or it.get("type") != "mcp_tool_call":
            continue
        obs = None
        res = it.get("result")
        if isinstance(res, dict):
            for part in res.get("content") or []:
                if isinstance(part, dict) and part.get("type") == "text":
                    try:
                        cand = json.loads(part.get("text") or "")
                    except json.JSONDecodeError:
                        continue
                    if isinstance(cand, dict) and "completeness" in cand:
                        obs = cand
                        break
        calls.append({
            "tool": it.get("tool"),
            "args": it.get("arguments"),
            "observation": obs,
            "source": "result.jsonl:mcp_tool_call",
        })
    return calls


def _mcp_call_projection(rec: dict) -> dict:
    obs = rec.get("observation") or {}
    return {
        "tool": rec.get("tool"),
        "family": TOOL_FAMILY.get(rec.get("tool"), "other"),
        "tool_status": obs.get("tool_status"),
        "completeness": obs.get("completeness"),
        "observation_id": obs.get("id"),
        "duration_ms": rec.get("duration_ms"),
        "args_sha256": rec.get("args_sha256") or (
            parser_audit_json_sha(rec.get("args"))),
        "evidence_refs": [r for r in (obs.get("evidence_refs") or [])
                          if isinstance(r, str)],
    }


def audit_row(row: dict, audit: dict, refused: bool) -> dict:
    """Re-score one official row under the parser-audit projection.

    Only a COMPLETE recovered object with a valid category can produce an
    ``ok`` audit row — and never when the terminal text is a provider
    refusal page (spec §8.3: a printed category token must not launder a
    refusal into a valid attempt). When the audit finds no usable label,
    transport-level statuses (``no_dir``/``no_result``, missing output)
    stay verbatim; everything else becomes ``parse_fail`` — a categorical
    statement about this projection, not about the official row.
    """
    out = dict(row)
    cat = audit.get("audit_category")
    if cat is not None and not refused:
        out["status"] = "ok"
        out["predicted_category"] = cat
        out["predicted"] = parser_audit.category_to_binary(cat)
        out["reasoning"] = (audit.get("audit_reasoning")
                            or row.get("reasoning"))
    elif cat is None and row.get("status") not in ("no_dir", "no_result"):
        out["status"] = "parse_fail"
        out["predicted"] = None
        out["predicted_category"] = None
        out["reasoning"] = None
    # refused: never recover — the official outcome stands verbatim
    return out


def parser_audit_json_sha(obj) -> Optional[str]:
    if obj is None:
        return None
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True).encode("utf-8")).hexdigest()


def _assessment_claim_citations(run_dir: Path) -> list[dict]:
    """Tool-minted evidence refs cited inside agent_assessment.json.

    ``ev:``/``sha256:``/``src:`` refs can only come from the tool server —
    every citation is cross-referenced against the attempt audit trail
    (the same rule ``validate_evidence_refs`` applies at collect time).
    """
    p = Path(run_dir) / "agent_assessment.json"
    if not p.is_file():
        return []
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    asm = doc.get("assessment") or {}
    cited = []
    for ref in asm.get("evidence") or []:
        if isinstance(ref, str) and ref.startswith(("ev:", "sha256:", "src:")):
            cited.append({"where": "assessment.evidence", "verdict": None,
                          "claim": None, "ref": ref})
    for claim in asm.get("claims") or []:
        if not isinstance(claim, dict):
            continue
        for ref in claim.get("evidence_refs") or []:
            if isinstance(ref, str) and ref.startswith(
                    ("ev:", "sha256:", "src:")):
                cited.append({
                    "where": "claim",
                    "verdict": claim.get("verdict"),
                    "claim": (claim.get("statement") or "")[:200],
                    "ref": ref,
                })
    return cited


def enrich_attempt(run_dir: Path, row: dict, audit: dict,
                   raw: Optional[str], terminal: str) -> dict:
    """Per-attempt controller data: parser audit record, failure class,
    tool calls, decisive-evidence citations. ``raw``/``terminal`` are
    already-read inputs (no double read)."""
    run_dir = Path(run_dir)

    status_json = _load_status_json(run_dir)
    failure_class = classify_failure(row.get("status") or "ok",
                                     run_dir, raw, terminal)

    audit_records, audit_source = read_mcp_audit(run_dir)
    fallback_calls = _mcp_calls_from_result(raw) if not audit_records else []
    if audit_records:
        calls = [_mcp_call_projection(r) for r in audit_records]
        call_source = audit_source
    else:
        calls = [_mcp_call_projection(r) for r in fallback_calls]
        call_source = ("result.jsonl:mcp_tool_call" if calls else "absent")

    # decisive evidence: tool-minted ref -> audit observations that minted it
    ref_to_obs: dict[str, list[dict]] = defaultdict(list)
    for proj in calls:
        for ref in proj["evidence_refs"]:
            ref_to_obs[ref].append({
                "observation_id": proj["observation_id"],
                "tool": proj["tool"],
                "completeness": proj["completeness"],
                "tool_status": proj["tool_status"],
            })
    citations = []
    for c in _assessment_claim_citations(run_dir):
        obs = ref_to_obs.get(c["ref"], [])
        citations.append({**c, "resolved": bool(obs),
                          "observations": obs[:3]})

    tools_used = {c["tool"] for c in calls if c["tool"]}
    tools_ok = {c["tool"] for c in calls
                if c["tool"] and c["tool_status"] in (None, "OK")}
    missed_reachability = (
        row.get("safety_outcome") == "safe"
        and not (tools_used & REACHABILITY_TOOLS)
    )
    dup = Counter(c["args_sha256"] for c in calls
                  if c["tool"] and c["args_sha256"])
    repeated = [k for k, v in dup.items() if v > 1]

    return {
        "run_dir": str(run_dir),
        "terminal_text_len": len(terminal),
        "status_json": (status_json.model_dump(mode="json")
                        if status_json is not None else None),
        "failure_class": failure_class,
        "audit": audit,
        "mcp_calls": calls,
        "mcp_calls_source": call_source,
        "mcp_audit_present": audit_source != "absent",
        "tools_used": sorted(tools_used),
        "tools_ok": sorted(tools_ok),
        "repeated_calls": len(repeated),
        "citations": citations,
        "missed_reachability_check": missed_reachability,
        "turn_completed": bool(
            row.get("completed")) if "completed" in row else None,
    }


# ---------------------------------------------------------------------------
# row derivation shared with vpr.load_parsed_cases (same field semantics)
# ---------------------------------------------------------------------------


def derive_case(row: dict) -> dict:
    """exactly ``vpr.load_parsed_cases``'s per-row derivation, without the
    file reading — same fields, same outcome/compat rules."""
    status = row.get("status")
    cat = row.get("predicted_category")
    outcome = vpr.safety_outcome(status, cat)
    gt = vpr.normalize_ground_truth(row["ground_truth"])
    gt_pos = gt == "exploitable"
    status_correct = ((outcome == "positive" and gt_pos) or
                      (outcome == "safe" and not gt_pos))
    reason_correct = bool(
        status_correct and cat == row["ground_truth_category"])
    return {
        "task_id": row["task_id"],
        "run_id": row["run_id"],
        "cve_id": row.get("cve_id"),
        "ground_truth": gt,
        "ground_truth_category": row["ground_truth_category"],
        "status": status,
        "predicted": row.get("predicted"),
        "predicted_category": cat,
        "safety_outcome": outcome,
        "compat_prediction": vpr.compat_prediction(status, cat),
        "status_correct": status_correct,
        "reason_correct": reason_correct,
        "completed": row.get("completed"),
        "steps": row.get("steps"),
        "tokens": {f: row.get(f) for f in vpr.TOKEN_FIELDS},
        "cost_usd": row.get("cost_usd"),
        "reasoning": row.get("reasoning"),
        "_gt_pos": gt_pos,
    }


def audit_row(row: dict, audit: dict, refused: bool) -> dict:
    """Re-score one official row under the parser-audit projection.

    Only a COMPLETE recovered object with a valid category can produce an
    ``ok`` audit row — and never when the terminal text is a provider
    refusal page (spec §8.3: a printed category token must not launder a
    refusal into a valid attempt).
    """
    out = dict(row)
    cat = audit.get("audit_category")
    has_result = (row.get("status") == "ok") or bool(
        audit.get("terminal_text_len"))
    if cat is not None and not refused and has_result:
        out["status"] = "ok"
        out["predicted_category"] = cat
        out["predicted"] = parser_audit.category_to_binary(cat)
        out["reasoning"] = audit.get("audit_reasoning") or row.get("reasoning")
    else:
        out["status"] = "ok" if refused is False and cat is not None \
            else row.get("status")
        if cat is None:
            out["status"] = "parse_fail" if row.get("status") in (
                "ok", "parse_fail") else row.get("status")
            out["predicted"] = None
            out["predicted_category"] = None
            out["reasoning"] = None
    return out


# ---------------------------------------------------------------------------
# metric blocks
# ---------------------------------------------------------------------------


def safety_block(cases: list[dict]) -> dict:
    by_run = vpr.group_by_run(cases)
    per_repeat = {r: vpr.score_rows(cs) for r, cs in by_run.items()}
    agg = vpr.aggregate_repeats(per_repeat)
    pooled = dict(vpr.score_rows(cases))
    pooled["note"] = ("secondary pooled view over all rows — NOT the "
                      "repeat-mean; pooled F1/majority vote are not an "
                      "official aggregate")
    return {"by_run": by_run, "per_repeat": per_repeat,
            "aggregate": agg, "pooled": pooled}


def failure_class_block(cases: list[dict], enrich: dict) -> dict:
    """FAILED counts by class — explicit denominators, per repeat + pooled."""
    per_run: dict[str, Counter] = {}
    per_run_ids: dict[str, dict] = {}
    for c in cases:
        key = (c["task_id"], c["run_id"])
        cls = enrich.get(key, {}).get("failure_class") \
            if c["safety_outcome"] == "failed" else None
        if c["safety_outcome"] != "failed":
            continue
        cls = cls or "unclassified"
        per_run.setdefault(c["run_id"], Counter())[cls] += 1
        per_run_ids.setdefault(c["run_id"], {}).setdefault(
            cls, []).append(c["task_id"])
    pooled: Counter = Counter()
    for rc in per_run.values():
        pooled.update(rc)
    order = {c: i for i, c in enumerate(FAILURE_CLASSES_ORDERED)}
    return {
        "policy": "FAILED = execution/format failure, never uncertain and "
                  "never a negative; classes: status.json failure_reason "
                  "when present, else derived from error.txt / stream "
                  "error events / terminal refusal",
        "per_repeat": {r: dict(sorted(v.items(),
                                      key=lambda kv: order.get(kv[0], 99)))
                       for r, v in sorted(per_run.items())},
        "per_repeat_ids": {r: per_run_ids[r] for r in sorted(per_run_ids)},
        "pooled": dict(sorted(pooled.items(),
                              key=lambda kv: order.get(kv[0], 99))),
        "total_failed": sum(pooled.values()),
    }


ASSESSMENT_SCHEMA_ORDERED = ("valid", "invalid", "absent")


def assessment_schema_block(cases: list[dict], enrich: dict) -> dict:
    """Aggregated ``assessment_schema`` dimension per cohort (spec §9.1):
    did the C1 assessment artifact validate? Counts over status.json's
    ``assessment_schema`` (valid/invalid/absent); ``no_status_json``
    counts attempts whose run dir carries no controller status at all,
    so denominators stay explicit. This block is reporting only — it
    never feeds ``overall`` and never re-scores a row."""
    order = {s: i for i, s in enumerate(ASSESSMENT_SCHEMA_ORDERED)}

    def _sorted(c: Counter) -> dict:
        return dict(sorted(c.items(), key=lambda kv: order.get(kv[0], 99)))

    per_run: dict[str, Counter] = {}
    pooled: Counter = Counter()
    no_status = 0
    invalid_ids: list[str] = []
    for c in cases:
        key = (c["task_id"], c["run_id"])
        st = (enrich.get(key, {}).get("status_json") or {})
        val = st.get("assessment_schema")
        if val is None:
            no_status += 1
            continue
        per_run.setdefault(c["run_id"], Counter())[val] += 1
        pooled[val] += 1
        if val == "invalid":
            invalid_ids.append(f"{key[0]}/{key[1]}")
    return {
        "policy": "artifact dimension only: valid/invalid/absent from "
                  "status.json assessment_schema; invalid means the "
                  "assessment artifact failed validation (schema or "
                  "evidence refs) — it never erases an accepted "
                  "official category and never changes overall",
        "attempts": len(cases),
        "per_repeat": {r: _sorted(v) for r, v in sorted(per_run.items())},
        "pooled": _sorted(pooled),
        "no_status_json": no_status,
        "invalid_attempts": sorted(invalid_ids),
    }


def stability_block(cases: list[dict], n_expected: int) -> dict:
    """Per-case stability across repeats: dominant outcome k of n,
    safe-outcome counts (the False-Safe-relevant axis), per §9."""
    by_task: dict[str, list[dict]] = defaultdict(list)
    for c in cases:
        by_task[c["task_id"]].append(c)
    rows = []
    dist = Counter()
    for task_id in sorted(by_task):
        cs = sorted(by_task[task_id], key=lambda c: c["run_id"])
        outcomes = [c["safety_outcome"] for c in cs]
        cats = [c["predicted_category"] for c in cs]
        counts = Counter(outcomes)
        dominant, dom_n = counts.most_common(1)[0]
        safe_n = counts.get("safe", 0)
        stab = f"{dom_n}/{len(cs)}"
        dist[stab] += 1
        runs = {c["run_id"]: c["safety_outcome"] for c in cs}
        rows.append({
            "task_id": task_id,
            "ground_truth": cs[0]["ground_truth"],
            "ground_truth_category": cs[0]["ground_truth_category"],
            "n_attempts": len(cs),
            "n_expected": n_expected,
            "missing_runs": sorted(
                {f"run_{i:03d}" for i in range(1, n_expected + 1)}
                - set(runs)),
            "outcomes": runs,
            "dominant_outcome": dominant,
            "stability": stab,
            "safe_count": safe_n,
            "safe_stable": safe_n == n_expected,
            "categories": dict(zip((c["run_id"] for c in cs), cats)),
            "category_set": sorted({c for c in cats if c}),
        })
    return {
        "denominator_note": "stability is dominant-outcome-count/n_attempts "
                            "per task; missing repeats listed explicitly",
        "n_tasks": len(rows),
        "stability_distribution": dict(sorted(dist.items(), reverse=True)),
        "safe_stable_tasks": [r["task_id"] for r in rows if r["safe_stable"]],
        "tasks": rows,
    }


def tool_use_block(cases: list[dict], enrich: dict) -> dict:
    """Evidence-tool invocation audit (spec §9.1 / plan §6)."""
    per_attempt = {}
    total_calls = 0
    by_tool = Counter()
    by_family = Counter()
    by_status = Counter()
    by_completeness = Counter()
    attempts_with_calls = 0
    audit_absent = []
    repeated_total = 0
    missed = []
    decisive = []
    for c in cases:
        key = (c["task_id"], c["run_id"])
        e = enrich.get(key, {})
        calls = e.get("mcp_calls") or []
        rec = {
            "n_calls": len(calls),
            "source": e.get("mcp_calls_source"),
            "tools": sorted({k["tool"] for k in calls if k["tool"]}),
            "by_status": dict(Counter(k["tool_status"] or "<none>"
                                      for k in calls)),
            "by_completeness": dict(Counter(
                k["completeness"] or "<none>" for k in calls)),
            "duration_ms_total": sum(k["duration_ms"] for k in calls
                                     if isinstance(k["duration_ms"], (int, float)))
                if any(isinstance(k["duration_ms"], (int, float))
                       for k in calls) else None,
            "repeated_calls": e.get("repeated_calls", 0),
            "missed_reachability_check":
                e.get("missed_reachability_check", False),
        }
        per_attempt[f"{key[0]}/{key[1]}"] = rec
        total_calls += len(calls)
        if calls:
            attempts_with_calls += 1
        if not e.get("mcp_audit_present") and e.get("mcp_calls_source") \
                == "absent":
            audit_absent.append(f"{key[0]}/{key[1]}")
        repeated_total += rec["repeated_calls"]
        if rec["missed_reachability_check"]:
            missed.append(f"{key[0]}/{key[1]}")
        for k in calls:
            if k["tool"]:
                by_tool[k["tool"]] += 1
                by_family[k["family"]] += 1
                by_status[k["tool_status"] or "<none>"] += 1
                by_completeness[k["completeness"] or "<none>"] += 1
        for cite in e.get("citations") or []:
            decisive.append({
                "task_id": c["task_id"], "run_id": c["run_id"],
                "outcome": c["safety_outcome"],
                "verdict": cite["verdict"], "claim": cite["claim"],
                "ref": cite["ref"], "resolved": cite["resolved"],
                "observations": cite["observations"],
            })
    n = len(cases)
    return {
        "policy": "one evidence-tool invocation = one audit record "
                  "(server-side) or one mcp_tool_call item in result.jsonl "
                  "(fallback); missing audit is a coverage fact, not zero",
        "coverage": {
            "attempts": n,
            "attempts_with_tool_calls": attempts_with_calls,
            "audit_source_absent": sorted(audit_absent),
        },
        "totals": {
            "mcp_calls": total_calls,
            "calls_per_attempt_mean":
                (total_calls / n) if n else None,
            "by_tool": dict(sorted(by_tool.items())),
            "by_family": dict(sorted(by_family.items())),
            "by_tool_status": dict(sorted(by_status.items())),
            "by_completeness": dict(sorted(by_completeness.items())),
            "repeated_useless_calls": repeated_total,
        },
        "missed_reachability_check": sorted(missed),
        "decisive_evidence": decisive,
        "per_attempt": per_attempt,
        "causality_note": "invocation counts and decisive-evidence "
                          "citations are observational; tool-caused "
                          "improvement requires raw-trace review / ablation",
    }


def compare_cohorts(cohort_cases: list[dict], cohort_name: str,
                    base_cases: list[dict], base_name: str) -> dict:
    """Pairwise (task_id, run_id) transitions base -> cohort (spec §9.1)."""
    base_map = {(c["task_id"], c["run_id"]): c for c in base_cases}
    coh_map = {(c["task_id"], c["run_id"]): c for c in cohort_cases}
    keys = sorted(set(base_map) | set(coh_map))
    pairs = []
    tally = Counter()
    for key in keys:
        b = base_map.get(key)
        c = coh_map.get(key)
        rec = {"task_id": key[0], "run_id": key[1],
               "base": _pair_side(b), "cohort": _pair_side(c)}
        flags = rec["flags"] = []
        if b is None:
            flags.append("only_in_cohort")
        elif c is None:
            flags.append("missing_in_cohort")
        else:
            b_fs = b["safety_outcome"] == "safe" and b["_gt_pos"]
            c_fs = c["safety_outcome"] == "safe" and c["_gt_pos"]
            if not b["status_correct"] and c["status_correct"]:
                flags.append("correction")
                tally["correction"] += 1
            if b["status_correct"] and not c["status_correct"]:
                flags.append("regression")
                tally["regression"] += 1
            if b["safety_outcome"] in ("abstain", "failed") and \
                    c["safety_outcome"] in ("positive", "safe"):
                flags.append(f"from_{b['safety_outcome']}_to_decisive")
                tally[f"from_{b['safety_outcome']}_to_decisive"] += 1
            if b["safety_outcome"] in ("positive", "safe") and \
                    c["safety_outcome"] in ("abstain", "failed"):
                flags.append(f"from_decisive_to_{c['safety_outcome']}")
                tally[f"from_decisive_to_{c['safety_outcome']}"] += 1
            if b_fs and not c_fs:
                flags.append("false_safe_cleared")
                tally["false_safe_cleared"] += 1
            if c_fs and not b_fs:
                flags.append("false_safe_new")
                tally["false_safe_new"] += 1
            if b["status_correct"] and c["status_correct"] \
                    and b["safety_outcome"] == c["safety_outcome"]:
                if not b["reason_correct"] and c["reason_correct"]:
                    flags.append("reason_improved")
                    tally["reason_improved"] += 1
                if b["reason_correct"] and not c["reason_correct"]:
                    flags.append("reason_regressed")
                    tally["reason_regressed"] += 1
            if b["safety_outcome"] != c["safety_outcome"]:
                flags.append(
                    f"outcome:{b['safety_outcome']}->{c['safety_outcome']}")
        pairs.append(rec)
    trans = Counter()
    for p in pairs:
        if p["base"] and p["cohort"]:
            trans[f"{p['base']['outcome']}->{p['cohort']['outcome']}"] += 1
    return {
        "base": base_name,
        "cohort": cohort_name,
        "pair_key": "(task_id, run_id) — same task and repeat index",
        "causality_note": "Tool Correction Rate / transitions are the "
                          "OBSERVED paired delta, not proof of tool "
                          "causality (spec §9.1) — causality needs raw "
                          "trace review or ablation",
        "tally": dict(tally),
        "tool_correction_rate": {
            "corrections": tally.get("correction", 0),
            "regressions": tally.get("regression", 0),
            "pairs": sum(1 for p in pairs
                         if p["base"] and p["cohort"]),
        },
        "outcome_transitions": dict(sorted(trans.items())),
        "pairs": pairs,
    }


def _pair_side(c: Optional[dict]) -> Optional[dict]:
    if c is None:
        return None
    return {
        "status": c["status"],
        "category": c["predicted_category"],
        "outcome": c["safety_outcome"],
        "status_correct": c["status_correct"],
        "reason_correct": c["reason_correct"],
        "false_safe": c["safety_outcome"] == "safe" and c["_gt_pos"],
    }


# ---------------------------------------------------------------------------
# markdown writers
# ---------------------------------------------------------------------------


def _fmt_ms(ms, digits=3):
    return vpr._fmt_ms(ms, digits)


def _fmt_pct(x, digits=1):
    return vpr._fmt_pct(x, digits)


def write_disagreements(path: Path, *, label: str, note: Optional[str],
                        cohort: dict, audits: dict, comparison: Optional[dict],
                        stability: dict, failure_classes: dict) -> None:
    lines = [f"# Disagreements and transitions — {label}", ""]
    lines.append(f"Generated {vpr.utcnow()} by `eval.c1.report` "
                 f"({REPORT_SCHEMA}); offline only, no model calls.")
    if note:
        lines.append("")
        lines.append(f"> **Cohort note:** {note}")
    lines.append("")

    # 1. official vs parser-audit disagreements
    lines.append("## Official vs parser-audit disagreements")
    lines.append("")
    lines.append("| task_id | run_id | official | audit | audit status |")
    lines.append("|---|---|---|---|---|")
    n_dis = 0
    for key, a in sorted(audits.items()):
        if a["status"] not in parser_audit.DIVERGENT_STATUSES:
            continue
        n_dis += 1
        lines.append(
            f"| `{key[0]}` | {key[1]} | {a['official_category']} "
            f"| {a['audit_category']} | {a['status']} |")
    if not n_dis:
        lines.append("| — | — | — | — | none |")
    lines.append("")
    lines.append("`recovered` = official extractor failed but the audit "
                 "decoder found a complete valid JSON object (the known "
                 "brace-in-string defect); `disagreed` = both extracted a "
                 "category and they differ — the official category remains "
                 "the primary one in every metric.")
    lines.append("")

    # 2. failure classes
    lines.append("## FAILED by class (never uncertain, never negative)")
    lines.append("")
    lines.append("| class | pooled | per repeat |")
    lines.append("|---|---:|---|")
    fc = failure_classes
    all_classes = sorted(
        set(fc["pooled"]),
        key=lambda c: FAILURE_CLASSES_ORDERED.index(c)
        if c in FAILURE_CLASSES_ORDERED else 99)
    for cls in all_classes:
        per = " ".join(f"{r}={v.get(cls, 0)}"
                       for r, v in fc["per_repeat"].items())
        lines.append(f"| {cls} | {fc['pooled'][cls]} | {per} |")
    if not all_classes:
        lines.append("| — | 0 | none |")
    lines.append("")

    # 3. case-level disagreement & negative stability
    lines.append("## Per-case stability and non-stable negatives")
    lines.append("")
    lines.append("| task_id | GT | stability | outcomes | safe |")
    lines.append("|---|---|---|---|---:|")
    for t in stability["tasks"]:
        if t["stability"] != f"{t['n_attempts']}/{t['n_attempts']}" \
                or t["safe_count"] or t["n_attempts"] != t["n_expected"]:
            lines.append(
                f"| `{t['task_id']}` | {t['ground_truth_category']} "
                f"| {t['stability']} "
                f"| {t['outcomes']} | {t['safe_count']} |")
    lines.append("")
    lines.append("`stability` = dominant-outcome count / attempts. "
                 "A `safe` count on GT-exploitable rows is the False-Safe "
                 "surface — every such attempt is a safety defect, not "
                 "a cleared alert.")
    lines.append("")

    # 4. cohort vs reference transitions
    if comparison is not None:
        lines.append(f"## Paired transitions {comparison['base']} → "
                     f"{comparison['cohort']}")
        lines.append("")
        t = comparison["tally"]
        tcr = comparison["tool_correction_rate"]
        lines.append("| transition | count |")
        lines.append("|---|---:|")
        for k in ("correction", "regression",
                  "from_abstain_to_decisive", "from_failed_to_decisive",
                  "from_decisive_to_abstain", "from_decisive_to_failed",
                  "false_safe_cleared", "false_safe_new",
                  "reason_improved", "reason_regressed"):
            lines.append(f"| {k} | {t.get(k, 0)} |")
        lines.append("")
        lines.append(f"Tool Correction Rate (observed pair delta): "
                     f"{tcr['corrections']} corrections / "
                     f"{tcr['regressions']} regressions over "
                     f"{tcr['pairs']} paired attempts. "
                     f"{comparison['causality_note']}.")
        lines.append("")
        lines.append("| task_id | run_id | base | cohort | flags |")
        lines.append("|---|---|---|---|---|")
        for p in comparison["pairs"]:
            if not p["flags"] or p["flags"] == ["outcome:safe->safe"]:
                continue
            b = p["base"]["category"] if p["base"] else "—"
            c = p["cohort"]["category"] if p["cohort"] else "—"
            bo = p["base"]["outcome"] if p["base"] else "—"
            co = p["cohort"]["outcome"] if p["cohort"] else "—"
            flags = ", ".join(f for f in p["flags"]
                              if not f.startswith("outcome:"))
            if not flags and not p["flags"]:
                continue
            lines.append(f"| `{p['task_id']}` | {p['run_id']} "
                         f"| {b} ({bo}) | {c} ({co}) | {flags or '—'} |")
        lines.append("")

    vpr.atomic_write_text(str(path), "\n".join(lines) + "\n")


def write_tool_summary(path: Path, *, label: str, note: Optional[str],
                       tools: dict, n_cases: int) -> None:
    lines = [f"# Evidence-tool usage — {label}", ""]
    lines.append(f"Generated {vpr.utcnow()} by `eval.c1.report` "
                 f"({REPORT_SCHEMA}); offline audit, no model calls.")
    if note:
        lines.append("")
        lines.append(f"> **Cohort note:** {note}")
    lines.append("")
    cov = tools["coverage"]
    lines.append(f"Coverage: {cov['attempts_with_tool_calls']}/"
                 f"{cov['attempts']} attempts invoked ≥1 evidence tool; "
                 f"audit sink absent for "
                 f"{len(cov['audit_source_absent'])} attempts "
                 f"(listed in parser_audit/tool_use JSON — absent audit "
                 f"is a coverage gap, not 'zero calls').")
    lines.append("")
    tot = tools["totals"]
    lines.append(f"Total invocations: **{tot['mcp_calls']}** "
                 f"(mean {tot['calls_per_attempt_mean'] or 0:.2f}/attempt "
                 f"over {n_cases} cases); repeated same-tool+args calls: "
                 f"{tot['repeated_useless_calls']}.")
    lines.append("")
    lines.append("## By tool / family / status / completeness")
    lines.append("")
    for title, block in (("tool", "by_tool"), ("family", "by_family"),
                         ("tool_status", "by_tool_status"),
                         ("completeness", "by_completeness")):
        lines.append(f"### {title}")
        lines.append("")
        lines.append("| value | calls |")
        lines.append("|---|---:|")
        for k, v in sorted(tot[block].items()):
            lines.append(f"| {k} | {v} |")
        lines.append("")
    lines.append("## Missed checks")
    lines.append("")
    if tools["missed_reachability_check"]:
        lines.append("Attempts that returned a safe outcome without ANY "
                     "reachability-class tool call (find_callers, "
                     "module_usage, run_govulncheck, ...). Each is a "
                     "candidate 'empty evidence' safe — review, not an "
                     "automatic defect:")
        lines.append("")
        for k in tools["missed_reachability_check"]:
            lines.append(f"- `{k}`")
    else:
        lines.append("None observed.")
    lines.append("")
    lines.append("## Decisive evidence (tool-minted refs cited in "
                 "assessments)")
    lines.append("")
    de = tools["decisive_evidence"]
    if not de:
        lines.append("No agent_assessment.json artifacts or no "
                     "tool-minted citations — decisive evidence is "
                     "unavailable, not zero.")
    else:
        lines.append("| task_id | run_id | claim verdict | ref | resolves "
                     "to | outcome |")
        lines.append("|---|---|---|---|---|---|")
        for d in de:
            obs = ", ".join(
                f"{o['observation_id']}({o['tool']})"
                for o in d["observations"]) or "UNRESOLVED"
            lines.append(f"| `{d['task_id']}` | {d['run_id']} "
                         f"| {d['verdict'] or '—'} | `{d['ref']}` "
                         f"| {obs} | {d['outcome']} |")
    lines.append("")
    lines.append("Citation of a tool artifact is observed evidence use; "
                 "it does not by itself prove the tool caused the "
                 "outcome (spec §9.1).")
    vpr.atomic_write_text(str(path), "\n".join(lines) + "\n")


# ---------------------------------------------------------------------------
# pipeline
# ---------------------------------------------------------------------------


def _infer_defaults(run_root: Path):
    """(prompt_hash, agent, model) from .../<prompt>/<agent>/<model>."""
    p = Path(run_root).resolve()
    model = p.name
    agent = p.parent.name
    prompt_hash = p.parent.parent.name if p.parent.parent.name else None
    return prompt_hash, agent, model

def _infer_label(run_root: Path) -> str:
    """Best-effort cohort label: walk up past the model name looking for an
    experiment directory, else fall back to the run-root name itself."""
    parts = run_root.resolve().parts
    for name in reversed(parts[:-1]):
        if name not in {"results", "task4-c1"} and "/" not in name:
            return name
    return run_root.name or "cohort"

def _write_jsonl(path: Path, rows: Iterable[dict]) -> None:
    txt = "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows)
    vpr.atomic_write_text(str(path), txt)


def _check_against(path: Optional[Path], obj, name: str) -> dict:
    """Compare a computed artifact with a reference file on disk.

    ``obj`` may be a dict (metrics.json) or a list of row dicts
    (parsed.jsonl); JSONL is compared row-wise after a json round-trip
    so Python-level non-JSON types cannot produce false mismatches.
    """
    if path is None:
        return {"provided": False, "match": None, "name": name}
    path = Path(path)
    if not path.is_file():
        return {"provided": True, "path": str(path), "name": name,
                "match": None, "error": "file not found"}
    if isinstance(obj, list):
        ref = [json.loads(l) for l in
               path.read_text(encoding="utf-8").splitlines() if l.strip()]
        match = ref == [json.loads(json.dumps(o)) for o in obj]
    else:
        ref = json.loads(path.read_text(encoding="utf-8"))
        match = ref == json.loads(json.dumps(obj))
    return {"provided": True, "path": str(path), "name": name,
            "match": match, "sha256": vpr.sha256_file(str(path))}


def run_report(*, run_root: Path, tasks: Sequence[dict], out_dir: Path,
               label: str, harness_dir: Optional[Path], agent_name: str,
               model: str, prompt_hash: Optional[str], benchmark: str,
               repeats: int, note: Optional[str],
               baseline_rows: Optional[list[dict]], baseline_name: str,
               check_parsed: Optional[Path],
               official_metrics_path: Optional[Path],
               row_builder: Optional[Callable[[dict, int], dict]] = None,
               compute_metrics: Optional[Callable] = None,
               ) -> dict:
    """Full scoring pipeline; returns the checks dict (match results)."""
    run_root = Path(run_root)
    out_dir = Path(out_dir)
    if not run_root.is_dir():
        fail(f"run_root not found: {run_root}")

    agent = None
    if row_builder is None or compute_metrics is None:
        harness = load_harness(harness_dir or DEFAULT_HARNESS)
        if row_builder is None:
            agent, agent_name = _resolve_agent(
                harness_dir or DEFAULT_HARNESS, run_root, agent_name, model)
            row_builder = _harness_row_builder(agent, run_root, model)
        if compute_metrics is None:
            compute_metrics = harness["compute_metrics"]

    # Terminal-text extraction is adapter-aware: prefer the resolved
    # agent's own ``extract_text`` (the official rule verbatim); when the
    # row builder was injected (tests), fall back to the mirrored
    # extractor registered for ``agent_name``. An unknown profile
    # records ``no_input`` with an explicit reason — never a silent codex
    # read of a foreign format.
    extract = agent.extract_text if agent is not None else None
    if extract is None:
        extract = parser_audit.resolve_terminal_text_extractor(agent_name)
    result_filename = (
        agent.result_filename() if agent is not None
        else parser_audit.ADAPTER_RESULT_FILENAMES.get(
            agent_name, RESULT_FILENAME))
    extract_label = agent_name or "codex"

    # --- primary / official-strict projection -------------------------------
    rows = build_official_rows(tasks, run_root, repeats, row_builder)
    official_doc = {
        "config": {
            "benchmark": benchmark,
            "agent": agent_name,
            "model": model,
            "prompt_hash": prompt_hash,
            "repeats": repeats,
        },
        **compute_metrics(rows),
    }

    cases = [derive_case(r) for r in rows]
    by_run = vpr.group_by_run(cases)
    per_repeat = {r: vpr.score_rows(cs) for r, cs in by_run.items()}
    agg = vpr.aggregate_repeats(per_repeat)
    pooled = dict(vpr.score_rows(cases))
    pooled["note"] = ("secondary pooled view over all rows — NOT the "
                      "repeat-mean; pooled F1/majority vote are not an "
                      "official aggregate")

    # per-attempt enrichment (terminal text, audit, tools, failures)
    enrich: dict = {}
    audits: dict = {}
    for row, case in zip(rows, cases):
        rd = run_root / row["task_id"] / row["run_id"]
        key = (row["task_id"], row["run_id"])
        raw = _read_result(rd, result_filename)
        if raw is None:
            terminal, input_error = "", f"no result file ({result_filename})"
        else:
            try:
                terminal = parser_audit.terminal_text(
                    raw, extract or agent_name)
                input_error = None
            except Exception as exc:
                # unknown adapter or a broken extractor — an explicit
                # no_input reason, never a silent empty payload
                logger.warning("%s: terminal-text extraction failed (%s)",
                               rd, exc)
                terminal, input_error = "", str(exc)
        audit = parser_audit.audit_terminal_text(
            terminal, row.get("predicted_category"))
        audit["input_error"] = input_error
        audit["provider_refusal_hint"] = (
            bool(terminal) and detect_provider_refusal(terminal))
        audits[key] = audit
        enrich[key] = enrich_attempt(rd, case, audit, raw, terminal)

    # --- secondary / parser-audit projection --------------------------------
    audit_rows = [
        audit_row(row, audits[(row["task_id"], row["run_id"])],
                  audits[(row["task_id"], row["run_id"])]
                  .get("provider_refusal_hint", False))
        for row in rows]
    audit_cases = [derive_case(r) for r in audit_rows]
    audit_by_run = vpr.group_by_run(audit_cases)
    audit_per_repeat = {r: vpr.score_rows(cs)
                        for r, cs in audit_by_run.items()}
    audit_agg = vpr.aggregate_repeats(audit_per_repeat)
    audit_pooled = dict(vpr.score_rows(audit_cases))
    audit_metrics = compute_metrics(audit_rows) if compute_metrics else None
    audit_status_counts = dict(
        Counter(a["status"] for a in audits.values()))

    # --- metrics blocks -----------------------------------------------------
    failure_classes = failure_class_block(cases, enrich)
    stability = stability_block(cases, repeats)
    tools = tool_use_block(cases, enrich)
    tokens = vpr.build_token_telemetry(by_run)
    compat = vpr.compat_projection(
        by_run,
        (json.loads(Path(official_metrics_path).read_text(encoding="utf-8"))
         if official_metrics_path else official_doc))

    # --- baseline comparison -------------------------------------------------
    comparison = None
    if baseline_rows is not None:
        base_cases = [derive_case(r) for r in baseline_rows]
        comparison = compare_cohorts(cases, label, base_cases, baseline_name)

    # --- checks ---------------------------------------------------------------
    checks = {
        "check_parsed": _check_against(check_parsed, rows, "parsed.jsonl"),
        "official_metrics": _check_against(
            official_metrics_path, official_doc, "metrics.json"),
    }

    # --- write §11 artifacts --------------------------------------------------
    out_dir.mkdir(parents=True, exist_ok=True)
    inputs = {
        "run_root": str(run_root),
        "run_root_sha256_note": "input cohort is read-only; per-attempt "
                                "files hashed in case_comparison, not "
                                "re-stamped",
        "label": label,
        "note": note,
        "repeats": repeats,
        "n_tasks": len(tasks),
    }

    vpr.atomic_write_json(str(out_dir / "official_metrics.json"),
                          official_doc)
    _write_jsonl(out_dir / "parsed.jsonl", rows)

    safety_doc = {
        "schema": "vexbench-plain-safety/1",
        "projection": "primary/official-strict",
        "generated_at_utc": vpr.utcnow(),
        "inputs": inputs,
        "checks": checks,
        "denominators": {
            "policy": "fixed per-repeat GT denominators",
            "expected_full_dataset": vpr.EXPECTED_DENOMINATORS,
            "observed_per_repeat": {
                r: {"total": m["rows"],
                    "gt_exploitable": m["gt_exploitable"],
                    "gt_non_exploitable": m["gt_non_exploitable"]}
                for r, m in per_repeat.items()},
        },
        "n_repeats": agg["n_repeats"],
        "per_repeat": per_repeat,
        "aggregate": agg,
        "pooled": pooled,
        "failure_classes": failure_classes,
        "assessment_schema": assessment_schema_block(cases, enrich),
        "stability": stability,
        "uncertain_policy": vpr.uncertain_policy_block(by_run),
        "compatibility": compat,
        "scoring_policy": {
            "name": "safety-aware-projection/1",
            "uncertain": "abstain (INCONCLUSIVE); never a safe claim and "
                         "never a completion failure; official "
                         "compatibility maps the same rows to "
                         "not_exploitable",
            "false_safe": "GT exploitable AND outcome=safe only; abstain "
                          "and failed are never false-safe",
            "failed": "execution/format failure — never uncertain, never "
                      "a negative; failure_classes carries the reason",
            "aggregation": "per-repeat vectors, then mean ± sample std "
                           "(ddof=1) across repeats; pooled 90-row "
                           "ratios are secondary",
            "not_official": "supplements and never replaces official "
                            "metrics.json",
        },
        "telemetry_coverage": {
            "tokens": tokens["coverage"]["state"],
            "mcp_audit": tools["coverage"],
        },
    }
    vpr.atomic_write_json(str(out_dir / "safety_metrics.json"), safety_doc)

    audit_doc = {
        "schema": parser_audit.PARSER_AUDIT_SCHEMA,
        "projection": "secondary/parser-audit",
        "decoder": parser_audit.PARSER_AUDIT_DECODER_VERSION,
        "terminal_text_extractor": extract_label,
        "result_filename": result_filename,
        "generated_at_utc": vpr.utcnow(),
        "inputs": inputs,
        "rule": "string-aware json.JSONDecoder.raw_decode at each '{' on "
                "the LAST assistant terminal text only; terminal text is "
                "extracted by the cohort adapter's own rule "
                "(extract_text) resolved from the agent profile; first "
                "complete object carrying 'category' wins; category must "
                "be one of the 12 official values; identical rule for "
                "every category and cohort; provider-refusal terminal "
                "text never recovers to ok",
        "audit_status_counts": audit_status_counts,
        "disagreements": [
            {"task_id": k[0], "run_id": k[1],
             "status": a["status"],
             "official_category": a["official_category"],
             "audit_category": a["audit_category"],
             "disagreement": a["disagreement"],
             "provider_refusal_hint": a.get("provider_refusal_hint")}
            for k, a in sorted(audits.items())
            if a["status"] in parser_audit.DIVERGENT_STATUSES],
        "per_attempt_audit": {
            f"{k[0]}/{k[1]}": a for k, a in sorted(audits.items())},
        "metrics": {
            "official_scorer_on_audit_rows": audit_metrics,
            "safety_projection": {
                "per_repeat": audit_per_repeat,
                "aggregate": audit_agg,
                "pooled": audit_pooled,
            },
        },
        "note": "secondary audit projection — never replaces "
                "official_metrics.json; recovered labels are published "
                "separately so a parse defect can be seen to hide a "
                "positive or a False-Safe alike",
    }
    vpr.atomic_write_json(str(out_dir / "parser_audit_metrics.json"),
                          audit_doc)
    _write_jsonl(out_dir / "parsed.parser_audit.jsonl", audit_rows)

    # case_comparison.jsonl — per-attempt join
    comp_lines = []
    for case in cases:
        key = (case["task_id"], case["run_id"])
        e = enrich[key]
        a = audits[key]
        rec = {
            "task_id": case["task_id"],
            "run_id": case["run_id"],
            "cve_id": case["cve_id"],
            "ground_truth": case["ground_truth"],
            "ground_truth_category": case["ground_truth_category"],
            "official": {
                "status": case["status"],
                "category": case["predicted_category"],
                "outcome": case["safety_outcome"],
                "status_correct": case["status_correct"],
                "reason_correct": case["reason_correct"],
            },
            "audit": {
                "status": a["status"],
                "category": a["audit_category"],
                "disagreement": a["disagreement"],
                "provider_refusal_hint": a.get("provider_refusal_hint"),
                "input_error": a.get("input_error"),
            },
            "failure_class": e["failure_class"],
            "status_json": (e["status_json"] or {}).get("overall")
                if e["status_json"] else None,
            "assessment_schema": (e["status_json"] or {}).get(
                "assessment_schema") if e["status_json"] else None,
            "tools": {
                "n_calls": len(e["mcp_calls"]),
                "source": e["mcp_calls_source"],
                "used": e["tools_used"],
                "missed_reachability_check":
                    e["missed_reachability_check"],
                "repeated_calls": e["repeated_calls"],
            },
            "decisive_evidence": e["citations"],
            "steps": case["steps"],
            "completed": case["completed"],
            "tokens": case["tokens"],
            "cost_usd": case["cost_usd"],
        }
        comp_lines.append(rec)
    _write_jsonl(out_dir / "case_comparison.jsonl", comp_lines)

    write_disagreements(out_dir / "disagreements.md",
                        label=label, note=note, cohort=cases,
                        audits=audits, comparison=comparison,
                        stability=stability,
                        failure_classes=failure_classes)
    write_tool_summary(out_dir / "tool_use_summary.md",
                       label=label, note=note, tools=tools,
                       n_cases=len(cases))
    vpr.atomic_write_json(str(out_dir / "tool_use_summary.json"), tools)

    n_ok = sum(1 for c in cases if c["status"] == "ok")
    fs = agg["false_safe"]
    print(f"[{label}] {len(cases)} rows ({n_ok} ok) over "
          f"{agg['n_repeats']} repeat(s); false-safe "
          f"{list(fs['per_repeat_counts'].values())} "
          f"unique {fs['unique_case_ids']}; "
          f"audit disagreements "
          f"{audit_status_counts.get('recovered', 0)} recovered / "
          f"{audit_status_counts.get('disagreed', 0)} disagreed; "
          f"out={out_dir}", file=sys.stderr)
    return {"checks": checks, "out_dir": str(out_dir)}




def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="eval.c1.report",
        description=__doc__.split("\n")[0])
    ap.add_argument("--run-root", required=True,
                    help="model-level run dir: <...>/<prompt>/<agent>/"
                         "<model> containing <task_id>/run_NNN/")
    ap.add_argument("--tasks", required=True,
                    help="benchmark tasks JSONL (frozen GT/labels)")
    ap.add_argument("--repeats", type=int, default=DEFAULT_REPEATS)
    ap.add_argument("--benchmark", default="vex_bench")
    ap.add_argument("--agent", default=None,
                    help="harness agent profile (default: inferred from "
                         "run-root layout)")
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--prompt-hash", default=None,
                    help="prompt fingerprint for the config block "
                         "(default: inferred from run-root layout)")
    ap.add_argument("--harness-dir", default=str(DEFAULT_HARNESS))
    ap.add_argument("--label", default=None, help="cohort label (default: "
                    "basename of the experiment root)")
    ap.add_argument("--note", default=None,
                    help="free-text cohort note stamped into every output")
    ap.add_argument("--baseline-run-root", default=None,
                    help="reference cohort run root (e.g. frozen B1) for "
                         "paired transitions")
    ap.add_argument("--baseline-parsed", default=None,
                    help="reference cohort's existing parsed.jsonl "
                         "(overrides --baseline-run-root)")
    ap.add_argument("--baseline-agent", default=None,
                    help="agent profile for --baseline-run-root parsing")
    ap.add_argument("--baseline-label", default="B1")
    ap.add_argument("--check-parsed", default=None,
                    help="existing official parsed.jsonl to compare "
                         "computed rows against (reproduction check)")
    ap.add_argument("--official-metrics", default=None,
                    help="existing official metrics.json to compare "
                         "computed metrics against (reproduction check)")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)

    run_root = Path(args.run_root)
    prompt_hash = args.prompt_hash
    agent_name = args.agent
    model = args.model
    if prompt_hash is None or agent_name is None:
        ih, ia, im = _infer_defaults(run_root)
        prompt_hash = prompt_hash or ih
        agent_name = agent_name or ia
        if args.model == DEFAULT_MODEL:
            model = im
    label = args.label or _infer_label(run_root)

    try:
        baseline_rows = None
        baseline_name = args.baseline_label
        if args.baseline_parsed:
            baseline_rows = [json.loads(l) for l in
                             Path(args.baseline_parsed)
                             .read_text(encoding="utf-8").splitlines()
                             if l.strip()]
        elif args.baseline_run_root:
            harness_dir = Path(args.harness_dir)
            tasks = load_tasks(Path(args.tasks))
            harness = load_harness(harness_dir)
            b_agent = args.baseline_agent or \
                Path(args.baseline_run_root).parent.name
            if b_agent not in harness["agents"]:
                fail(f"baseline agent {b_agent!r} not in registry")
            agent = harness["agents"][b_agent](model=model)
            builder = _harness_row_builder(
                agent, Path(args.baseline_run_root), model)
            baseline_rows = build_official_rows(
                tasks, Path(args.baseline_run_root), args.repeats, builder)
        result = run_report(
            run_root=run_root,
            tasks=load_tasks(Path(args.tasks)),
            out_dir=Path(args.out),
            label=label,
            harness_dir=Path(args.harness_dir),
            agent_name=agent_name,
            model=model,
            prompt_hash=prompt_hash,
            benchmark=args.benchmark,
            repeats=args.repeats,
            note=args.note,
            baseline_rows=baseline_rows,
            baseline_name=baseline_name,
            check_parsed=Path(args.check_parsed) if args.check_parsed
            else None,
            official_metrics_path=Path(args.official_metrics)
            if args.official_metrics else None)
    except ReportError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    checks = result["checks"]
    bad = [k for k, v in checks.items()
           if v.get("provided") and v.get("match") is False]
    if bad:
        print(f"REPRODUCTION CHECK FAILED for {bad}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

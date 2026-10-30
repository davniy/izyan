"""Task 5 scoring join (plan §11): cross-arm matrix and disagreements.

Reads the per-arm artifact sets produced by ``eval.c1.report.run_report``
(``parsed.jsonl``, ``parsed.parser_audit.jsonl``, ``safety_metrics.json``,
``parser_audit_metrics.json`` under ``scoring/<arm>/``) plus the immutable
attempt dirs, and emits the plan §5 scoring artifacts:

- ``matrix.json``          — one row per (task_id, run_id) with separate
  strict/audit outcomes per arm, official binary mapping, failure class
  and result-artifact hash;
- ``disagreements.jsonl``  — paired P0↔P1 and P1↔T1 transitions with
  reason classes; only attempts present in BOTH arms are paired
  (missing repeats are never invented — plan §11);
- ``safety-report.md``     — counts/denominators per arm and projection,
  side by side, with the manifest's limitations repeated;
- ``tool-failures.jsonl``  — every MCP call with tool_status ERROR or
  UNSUPPORTED (subject/scope/error-class; the §6 error accounting input).

Pure file joins — no model calls, no harness interaction, no writes
outside ``--out``.
"""

from __future__ import annotations

import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Optional, Sequence

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from eval.c1 import parser_audit  # noqa: E402
from eval.c1.report import derive_case  # noqa: E402
from eval.c1.status import AttemptStatus  # noqa: E402

from . import collect as collect_mod  # noqa: E402
from . import manifest as manifest_mod  # noqa: E402

SCORING_SCHEMA = "task5-scoring/1"
ARM_ORDER = ("p0", "p1", "t1")


def _read_jsonl(path: Path) -> list[dict]:
    path = Path(path)
    if not path.is_file():
        return []
    return [json.loads(l) for l in
            path.read_text(encoding="utf-8").splitlines() if l.strip()]


def _result_sha256(run_dir: Path) -> Optional[str]:
    """Hash of the attempt's raw result artifact (either adapter name)."""
    for name in ("result.jsonl", "result.json"):
        p = Path(run_dir) / name
        if p.is_file():
            return hashlib.sha256(p.read_bytes()).hexdigest()
    return None


def _status_overall(run_dir: Path) -> tuple[Optional[str], Optional[str]]:
    """(overall, failure_reason) from the controller status.json."""
    p = Path(run_dir) / "status.json"
    if not p.is_file():
        return None, None
    try:
        st = AttemptStatus.model_validate_json(
            p.read_text(encoding="utf-8"))
        return st.overall, st.failure_reason
    except Exception:
        return "unparsable", None


def _arm_rows(scored_dir: Path) -> tuple[dict, dict]:
    """(official, audit) row maps keyed by (task_id, run_id)."""
    scored_dir = Path(scored_dir)
    official = {
        (r["task_id"], r["run_id"]): r
        for r in _read_jsonl(scored_dir / "parsed.jsonl")
    }
    audit = {
        (r["task_id"], r["run_id"]): r
        for r in _read_jsonl(scored_dir / "parsed.parser_audit.jsonl")
    }
    return official, audit


def build_matrix(
    manifest: dict,
    scored: dict[str, Path],
) -> dict:
    """Join all attempt rows across arms.

    ``scored`` maps arm -> scoring dir that already contains the C1
    artifacts. Cells for arms without a row are ``present: false`` —
    absence is data, never imputed.
    """
    per_arm: dict[str, tuple[dict, dict]] = {}
    keys: set[tuple[str, str]] = set()
    for arm in ARM_ORDER:
        if arm not in scored:
            continue
        per_arm[arm] = _arm_rows(scored[arm])
        keys.update(per_arm[arm][0])

    rows = []
    for task_id, run_id in sorted(keys):
        arms_cell: dict[str, dict] = {}
        meta_src: Optional[dict] = None
        for arm in ARM_ORDER:
            if arm not in per_arm:
                continue
            official, audit = per_arm[arm]
            row = official.get((task_id, run_id))
            arow = audit.get((task_id, run_id))
            cell: dict = {"present": row is not None}
            if row is not None:
                meta_src = meta_src or row
                case = derive_case(row)
                run_dir = (Path(manifest["arms"][arm]["run_root"])
                           / task_id / run_id)
                overall, reason = _status_overall(run_dir)
                acase = derive_case(arow) if arow else None
                cell.update({
                    "official": {
                        "status": row.get("status"),
                        "category": row.get("predicted_category"),
                        "binary": row.get("predicted"),
                        "outcome": case["safety_outcome"],
                    },
                    "audit": {
                        "category": arow.get("predicted_category")
                        if arow else None,
                        "outcome": acase["safety_outcome"] if acase else None,
                    },
                    "status_overall": overall,
                    "failure_reason": reason,
                    "result_sha256": _result_sha256(run_dir),
                    "completed": row.get("completed"),
                    "steps": row.get("steps"),
                    "cost_usd": row.get("cost_usd"),
                })
            arms_cell[arm] = cell
        rows.append({
            "task_id": task_id,
            "run_id": run_id,
            "cve_id": (meta_src or {}).get("cve_id"),
            "ground_truth": (meta_src or {}).get("ground_truth"),
            "ground_truth_category":
                (meta_src or {}).get("ground_truth_category"),
            "arms": arms_cell,
        })
    return {
        "schema": SCORING_SCHEMA,
        "experiment_id": manifest.get("experiment_id"),
        "arms_scored": sorted(scored),
        "n_rows": len(rows),
        "rows": rows,
    }


def _transition_class(a_out: Optional[str], b_out: Optional[str],
                      gt_pos: bool) -> tuple[str, str]:
    """(class, kind) for one paired attempt transition a -> b.

    Classes are named by the safety meaning, not the raw labels:
    ``false_safe_appeared`` only fires on GT-exploitable rows, etc.
    """
    if a_out is None or b_out is None:
        return "unpaired", "missing"
    if a_out == b_out:
        return f"stable_{a_out}", "neutral"
    pair = (a_out, b_out)
    if gt_pos:
        if pair == ("positive", "safe"):
            return "false_safe_appeared", "regression"
        if pair == ("safe", "positive"):
            return "false_safe_cleared", "improvement"
        if a_out == "positive":
            return "positive_lost_to_" + b_out, "regression"
        if b_out == "positive":
            return "positive_gained_from_" + a_out, "improvement"
        if a_out == "safe" or b_out == "safe":
            return "safe_wobble", "neutral"
        return "failure_wobble", "neutral"
    # GT safe side: any positive is a false alarm.
    if a_out != "positive" and b_out == "positive":
        return "false_alarm_appeared", "regression"
    if a_out == "positive" and b_out != "positive":
        return "false_alarm_cleared", "improvement"
    if b_out == "safe" and a_out in ("abstain", "failed"):
        return "safe_gained_from_" + a_out, "improvement"
    if a_out == "safe" and b_out in ("abstain", "failed"):
        return "safe_lost_to_" + b_out, "regression"
    return "wobble", "neutral"


def build_disagreements(
    manifest: dict,
    scored: dict[str, Path],
    pairs: Sequence[tuple[str, str]] = (("p0", "p1"), ("p1", "t1")),
) -> list[dict]:
    """Paired transition rows for the requested arm comparisons.

    Only (task_id, run_id) observed in BOTH arms enter a pair — P0's
    n=1 history pairs run_001 only; missing repeats are never invented.
    """
    per_arm: dict[str, dict] = {}
    for arm in ARM_ORDER:
        if arm in scored:
            per_arm[arm] = _arm_rows(scored[arm])[0]

    out: list[dict] = []
    for a_arm, b_arm in pairs:
        if a_arm not in per_arm or b_arm not in per_arm:
            continue
        keys = sorted(set(per_arm[a_arm]) & set(per_arm[b_arm]))
        for task_id, run_id in keys:
            ra, rb = per_arm[a_arm][(task_id, run_id)], \
                per_arm[b_arm][(task_id, run_id)]
            ca, cb = derive_case(ra), derive_case(rb)
            cls, kind = _transition_class(
                ca["safety_outcome"], cb["safety_outcome"],
                ca["_gt_pos"])
            out.append({
                "pair": f"{a_arm}->{b_arm}",
                "task_id": task_id,
                "run_id": run_id,
                "cve_id": ca.get("cve_id"),
                "ground_truth": ca["ground_truth"],
                "ground_truth_category": ca["ground_truth_category"],
                "a": {"arm": a_arm, "category": ca["predicted_category"],
                      "outcome": ca["safety_outcome"],
                      "status": ra.get("status")},
                "b": {"arm": b_arm, "category": cb["predicted_category"],
                      "outcome": cb["safety_outcome"],
                      "status": rb.get("status")},
                "transition": cls,
                "kind": kind,
                "reason_note": None,  # filled by manual review (plan §8)
            })
    return out


def build_tool_failures(
    manifest: dict,
    scored: dict[str, Path],
) -> list[dict]:
    """ERROR/UNSUPPORTED MCP calls with error class — plan §5/§8 input.

    Scans the attempt dirs of the arms actually scored (the audit sinks
    live there, not in the scoring dirs)."""
    rows = []
    for arm in ARM_ORDER:
        if arm not in scored:
            continue
        run_root = Path(manifest["arms"][arm]["run_root"])
        for path, rec in collect_mod.iter_audit_records(run_root):
            obs = rec.get("observation") if isinstance(rec, dict) else None
            st = (obs or {}).get("tool_status") or rec.get("tool_status")
            if str(st).upper() not in {"ERROR", "UNSUPPORTED"}:
                continue
            detail = (obs or {}).get("error") or rec.get("error") or ""
            run_dir = path
            while run_dir.name and not run_dir.name.startswith("run_"):
                run_dir = run_dir.parent
            task_id = run_dir.parent.name if run_dir.name else None
            rows.append({
                "arm": arm,
                "task_id": task_id,
                "run_id": run_dir.name or None,
                "tool": (obs or {}).get("tool") or rec.get("tool"),
                "tool_status": st,
                "completeness": (obs or {}).get("completeness"),
                "error_class": collect_mod.classify_tool_error(
                    str(detail)),
                "detail": str(detail)[:400],
            })
    return rows


def _arm_summary(scored_dir: Path) -> dict:
    """Pull the headline per-arm numbers out of the C1 artifacts."""
    scored_dir = Path(scored_dir)
    safety = json.loads(
        (scored_dir / "safety_metrics.json").read_text(encoding="utf-8"))
    audit = json.loads(
        (scored_dir / "parser_audit_metrics.json").read_text(
            encoding="utf-8"))
    official = json.loads(
        (scored_dir / "official_metrics.json").read_text(encoding="utf-8"))
    agg = safety["aggregate"]
    pooled = safety["pooled"]
    aproj = audit.get("metrics", {}).get("safety_projection", {})
    aagg = aproj.get("aggregate", {})
    apooled = aproj.get("pooled", {})
    binary = official.get("binary", {})

    def _agg_rate(block: dict, key: str):
        v = block.get(key)
        if isinstance(v, dict):
            return v.get("mean")
        return v

    return {
        "rows": safety.get("inputs", {}).get("n_tasks"),
        "n_repeats": safety.get("n_repeats"),
        "official": {
            "binary_accuracy": (binary.get("accuracy") or {}).get("mean"),
            "binary_f1": (binary.get("f1") or {}).get("mean"),
        },
        "strict": {
            "false_safe": agg.get("false_safe", {}).get("total_count"),
            "false_safe_unique_cases":
                agg.get("false_safe", {}).get("unique_case_ids"),
            "safe_clear_rate": _agg_rate(agg, "safe_clear_rate"),
            "recall": _agg_rate(agg, "exploitable_recall"),
            "inconclusive": pooled.get("outcomes", {}).get("abstain"),
            "failed": pooled.get("outcomes", {}).get("failed"),
        },
        "audit": {
            "false_safe": aagg.get("false_safe", {}).get("total_count"),
            "safe_clear_rate": _agg_rate(aagg, "safe_clear_rate"),
            "recall": _agg_rate(aagg, "exploitable_recall"),
            "inconclusive": apooled.get("outcomes", {}).get("abstain"),
            "failed": apooled.get("outcomes", {}).get("failed"),
        },
        "failure_classes": safety.get("failure_classes", {}).get("pooled"),
        "assessment_schema": (safety.get("assessment_schema", {})
                              .get("pooled")),
        "tool_use": (safety.get("telemetry_coverage", {})
                     .get("mcp_audit")),
    }


def write_scoring_artifacts(
    manifest: dict,
    scored: dict[str, Path],
    out_dir: Path,
) -> dict:
    """Emit matrix.json + disagreements.jsonl + tool-failures.jsonl +
    safety-report.md; returns the written paths."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    matrix = build_matrix(manifest, scored)
    (out_dir / "matrix.json").write_text(
        json.dumps(matrix, indent=2) + "\n", encoding="utf-8")

    disagreements = build_disagreements(manifest, scored)
    (out_dir / "disagreements.jsonl").write_text(
        "".join(json.dumps(r, ensure_ascii=False) + "\n"
                for r in disagreements),
        encoding="utf-8")

    tool_failures = build_tool_failures(manifest, scored)
    (out_dir / "tool-failures.jsonl").write_text(
        "".join(json.dumps(r, ensure_ascii=False) + "\n"
                for r in tool_failures),
        encoding="utf-8")

    lines = [
        f"# Task 5 safety report — {manifest.get('experiment_id')}",
        "",
        f"Generated {time_utc()} — offline scoring join, no model calls.",
        "",
        "| Arm | Rows | Repeats | Acc (official) | FS strict | FS audit | "
        "SCR strict | Recall strict | INCONCLUSIVE | FAILED |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    summaries = {}
    for arm in ARM_ORDER:
        if arm not in scored:
            continue
        s = _arm_summary(scored[arm])
        summaries[arm] = s
        lines.append(
            f"| {arm} | {s['rows']} | {s['n_repeats']} | "
            f"{_pct(s['official']['binary_accuracy'])} | "
            f"{s['strict']['false_safe']} | {s['audit']['false_safe']} | "
            f"{_pct(s['strict']['safe_clear_rate'])} | "
            f"{_pct(s['strict']['recall'])} | "
            f"{s['strict']['inconclusive']} | {s['strict']['failed']} |")
    lines += [
        "",
        "Denominators: 7 exploitable / 23 safe per repeat (30 total); "
        "FS counts only GT-exploitable rows scored safe; abstain and "
        "FAILED are never false-safe. Strict = official-parse rows; "
        "audit = parser-audit projection (separate, never merged).",
        "",
        "## Transition classes (paired observed attempts only)",
        "",
    ]
    counts = Counter((d["pair"], d["transition"]) for d in disagreements)
    for (pair, cls), n in sorted(counts.items()):
        lines.append(f"- {pair} {cls}: {n}")
    if not disagreements:
        lines.append("- none (no paired attempts yet)")
    lines += ["", "## Limitations", ""]
    for lim in manifest.get("limitations", []):
        lines.append(f"- {lim}")
    lines.append("")
    (out_dir / "safety-report.md").write_text(
        "\n".join(lines), encoding="utf-8")

    return {
        "matrix": str(out_dir / "matrix.json"),
        "disagreements": str(out_dir / "disagreements.jsonl"),
        "tool_failures": str(out_dir / "tool-failures.jsonl"),
        "safety_report": str(out_dir / "safety-report.md"),
        "n_matrix_rows": matrix["n_rows"],
        "n_disagreements": len(disagreements),
        "n_tool_failures": len(tool_failures),
    }


def time_utc() -> str:
    import time

    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _pct(x) -> str:
    return f"{x * 100:.1f}%" if isinstance(x, (int, float)) else "n/a"

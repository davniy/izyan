"""Task 6 scoring join (plan §12): the four projections.

Joins the scored artifacts of all four projections — P2, T2 (raw agent
answers) and V-P2, V-T2 (validator-adjusted replays of the same saved
answers) — into:

    matrix.json           — one row per (task_id, run_id) with all four
                            projection outcomes side by side
    safety-report.md      — the 4-projection table: False-Safe, Safe
                            Clear Rate, EXPLOITABLE recall, FAILED,
                            abstain, valid-claim share, checkable-
                            negative-claim share, cost — by attempt
                            AND by unique case (testify-style repeats
                            of one case count ONCE)
    validator-report.md   — FS blocked / correct-safe lost per v-proj
                            (attempts + unique cases), per-claim
                            validator-decision distribution, claim
                            checkability

Reuses the Task-5 join shape; per-attempt outcomes are derived
uniformly from parsed.jsonl rows via the official safety_outcome so
raw and validator projections are scored by the same rule. Missing
projection dirs are data, never imputed.
"""


import json
import time
from collections import Counter
from pathlib import Path
from typing import Optional, Sequence

from eval import vexbench_plain_report as vpr
from eval.c1.report import derive_case
from eval.c1.status import AttemptStatus
from eval.task5.report import (
    _read_jsonl,
    _result_sha256,
    _status_overall,
    _transition_class,
)

from .manifest import ARM_ORDER, PROJECTION_ARMS

SCORING_SCHEMA = "task6-scoring/1"
PROJECTION_ORDER = ("p2", "t2", "v_p2", "v_t2")
# Paired transitions reported in validator-report (plan §12):
# arm-vs-arm and raw-vs-validator.
TRANSITION_PAIRS = (("p2", "t2"), ("p2", "v_p2"), ("t2", "v_t2"))


def _run_dir_for(manifest: dict, proj: str, task_id: str,
                 run_id: str) -> Path:
    """Attempt dir backing a projection row — v-arms inherit the
    source arm's immutable run root."""
    source = PROJECTION_ARMS.get(proj, proj)
    return Path(manifest["arms"][source]["run_root"]) / task_id / run_id


def _validator_results(scored_dir: Path) -> dict:
    """(task_id, run_id) → validator_results.jsonl record, if the v-arm
    wrote one."""
    return {
        (r["task_id"], r["run_id"]): r
        for r in _read_jsonl(Path(scored_dir) / "validator_results.jsonl")
    }


def _arm_run_root(manifest: dict, proj: str) -> Path:
    """The run root backing a projection — v-arms inherit the source
    arm's immutable run root."""
    return Path(manifest["arms"][PROJECTION_ARMS.get(proj, proj)]
                ["run_root"])


def build_matrix(
    manifest: dict,
    scored: dict[str, Path],
) -> dict:
    """Join all attempt rows across the four projections.

    Cells for projections without a row are ``present: false`` —
    absence is data. V-projection cells additionally carry the
    validator decision and the raw (unadjusted) category.
    """
    per_proj: dict[str, tuple[dict, dict, dict]] = {}
    keys: set[tuple[str, str]] = set()
    for proj in PROJECTION_ORDER:
        if proj not in scored:
            continue
        official = {
            (r["task_id"], r["run_id"]): r
            for r in _read_jsonl(Path(scored[proj]) / "parsed.jsonl")}
        audit = {
            (r["task_id"], r["run_id"]): r
            for r in _read_jsonl(
                Path(scored[proj]) / "parsed.parser_audit.jsonl")}
        vres = _validator_results(scored[proj])
        per_proj[proj] = (official, audit, vres)
        keys.update(official)

    rows = []
    for task_id, run_id in sorted(keys):
        cells: dict[str, dict] = {}
        meta_src: Optional[dict] = None
        for proj in PROJECTION_ORDER:
            if proj not in per_proj:
                continue
            official, audit, vres = per_proj[proj]
            row = official.get((task_id, run_id))
            arow = audit.get((task_id, run_id))
            cell: dict = {"present": row is not None}
            if row is not None:
                meta_src = meta_src or row
                case = derive_case(row)
                run_dir = _run_dir_for(manifest, proj, task_id, run_id)
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
                        "outcome": acase["safety_outcome"]
                        if acase else None,
                    },
                    "status_overall": overall,
                    "failure_reason": reason,
                    "result_sha256": _result_sha256(run_dir),
                    "completed": row.get("completed"),
                    "steps": row.get("steps"),
                    "cost_usd": row.get("cost_usd"),
                })
                v = vres.get((task_id, run_id))
                if v is not None:
                    cell["validator"] = {
                        "decision": v.get("decision"),
                        "agent_category": v.get("agent_category"),
                        "agent_outcome": v.get("agent_outcome"),
                        "adjusted": row.get("validator_adjusted"),
                        "reason": v.get("reason"),
                    }
            cells[proj] = cell
        rows.append({
            "task_id": task_id,
            "run_id": run_id,
            "cve_id": (meta_src or {}).get("cve_id"),
            "ground_truth": (meta_src or {}).get("ground_truth"),
            "ground_truth_category":
                (meta_src or {}).get("ground_truth_category"),
            "projections": cells,
        })
    return {
        "schema": SCORING_SCHEMA,
        "experiment_id": manifest.get("experiment_id"),
        "projections_scored": sorted(scored),
        "n_rows": len(rows),
        "rows": rows,
    }


# ---------------------------------------------------------------------------
# Per-projection summary (uniform: parsed rows → official outcomes)
# ---------------------------------------------------------------------------


def _outcome_counts(rows: Sequence[dict]) -> dict:
    """Attempt-level and case-level outcome buckets for one projection.

    GT mapping is the official binary: exploitable vs not_exploitable.
    safe outcome on GT-exploitable = false-safe; safe on GT-safe =
    correct-safe. Abstain/failed are neither.
    """
    attempts = {"total": 0, "gt_exploitable": 0, "gt_safe": 0,
                "safe": 0, "positive": 0, "abstain": 0, "failed": 0,
                "false_safe": 0, "correct_safe": 0,
                "cost_usd": 0.0, "total_tokens": 0, "steps": 0}
    by_case: dict[str, dict] = {}
    for row in rows:
        outcome = vpr.safety_outcome(row.get("status"),
                                     row.get("predicted_category"))
        gt_expl = row.get("ground_truth") == "exploitable"
        attempts["total"] += 1
        attempts["gt_exploitable" if gt_expl else "gt_safe"] += 1
        attempts[outcome] += 1
        if isinstance(row.get("cost_usd"), (int, float)):
            attempts["cost_usd"] += row["cost_usd"]
        if isinstance(row.get("total_tokens"), (int, float)):
            attempts["total_tokens"] += row["total_tokens"]
        if isinstance(row.get("steps"), (int, float)):
            attempts["steps"] += row["steps"]
        case = by_case.setdefault(row["task_id"], {
            "gt_exploitable": gt_expl, "outcomes": set()})
        case["outcomes"].add(outcome)
        if outcome == "safe" and gt_expl:
            attempts["false_safe"] += 1
        if outcome == "safe" and not gt_expl:
            attempts["correct_safe"] += 1

    cases = {"total": len(by_case),
             "gt_exploitable": sum(1 for c in by_case.values()
                                   if c["gt_exploitable"]),
             "gt_safe": sum(1 for c in by_case.values()
                            if not c["gt_exploitable"]),
             "false_safe": sum(
                 1 for c in by_case.values()
                 if c["gt_exploitable"] and "safe" in c["outcomes"]),
             "correct_safe": sum(
                 1 for c in by_case.values()
                 if not c["gt_exploitable"] and "safe" in c["outcomes"]),
             "any_abstain": sum(
                 1 for c in by_case.values()
                 if "abstain" in c["outcomes"])}
    return {"attempts": attempts, "cases": cases}


def _claim_stats(results: Sequence[dict]) -> dict:
    """Per-claim checkability from validator_results records."""
    n_claims = 0
    supported = 0
    decisions: Counter = Counter()
    for rec in results:
        for c in rec.get("per_claim", []):
            n_claims += 1
            decisions[c.get("decision") or "clean"] += 1
            if c.get("supported"):
                supported += 1
    return {
        "n_negative_claims": n_claims,
        "n_checkable_claims": supported,
        "checkable_claim_share": (supported / n_claims
                                  if n_claims else None),
        "per_claim_decisions": dict(decisions),
    }


def _assessment_stats(scored_dir: Path, run_root: Path,
                      rows: Sequence[dict]) -> dict:
    """Valid-claim share: status.json assessment_schema per attempt —
    read from the attempt dirs (controller truth); falls back to the
    v-arm's assessment_present flag."""
    vres = _validator_results(scored_dir)
    counts: Counter = Counter()
    for row in rows:
        st_p = Path(run_root) / row["task_id"] / row["run_id"] / \
            "status.json"
        val = None
        if st_p.is_file():
            try:
                st = AttemptStatus.model_validate_json(
                    st_p.read_text(encoding="utf-8"))
                val = st.assessment_schema
            except Exception:
                val = "unparsable_status"
        if val is None:
            rec = vres.get((row["task_id"], row["run_id"]))
            if rec is not None:
                val = ("present" if rec.get("assessment_present")
                       else "missing")
        counts[val or "unknown"] += 1
    total = sum(counts.values())
    valid = counts.get("valid", 0)
    return {
        "assessment_schema_counts": dict(counts),
        "valid_claim_share": valid / total if total else None,
    }


def projection_summary(manifest: dict, proj: str,
                       scored_dir: Path) -> dict:
    """One row of the cross-projection table for *proj*."""
    scored_dir = Path(scored_dir)
    rows = _read_jsonl(scored_dir / "parsed.jsonl")
    counts = _outcome_counts(rows)
    results = list(_validator_results(scored_dir).values())
    run_root = _arm_run_root(manifest, proj)
    asm = _assessment_stats(scored_dir, run_root, rows)
    att, cs = counts["attempts"], counts["cases"]
    return {
        "projection": proj,
        "n_rows": len(rows),
        "attempts": att,
        "cases": cs,
        "false_safe_rate": (att["false_safe"] / att["gt_exploitable"]
                            if att["gt_exploitable"] else None),
        "safe_clear_rate": (att["correct_safe"] / att["gt_safe"]
                            if att["gt_safe"] else None),
        "exploitable_recall": (
            att["positive"] / att["gt_exploitable"]
            if att["gt_exploitable"] else None),
        "abstain_rate": att["abstain"] / att["total"] if att["total"]
        else None,
        **asm,
        **_claim_stats(results),
    }


def build_disagreements(
    manifest: dict,
    scored: dict[str, Path],
    pairs: Sequence[tuple[str, str]] = TRANSITION_PAIRS,
) -> list[dict]:
    """Paired transition rows — task5 semantics, extended to raw↔
    validator pairs. Only (task_id, run_id) in BOTH projections pair.

    ``transition``/``kind`` keep the shared Task-5 vocabulary
    (safe→abstain on an exploitable row is ``safe_wobble/neutral``
    there — the raw comparison has no concept of blocking). For
    validator pairs (``b`` starts with ``v_``) the row additionally
    carries ``validator_transition`` which names the safety meaning
    under the validator rule: a safe verdict that became abstain on
    an exploitable case is ``false_safe_blocked`` (improvement); the
    same on a safe case is ``correct_safe_lost`` (regression)."""
    per_proj: dict[str, dict] = {}
    for proj in PROJECTION_ORDER:
        if proj in scored:
            per_proj[proj] = {
                (r["task_id"], r["run_id"]): r
                for r in _read_jsonl(
                    Path(scored[proj]) / "parsed.jsonl")}

    out: list[dict] = []
    for a_proj, b_proj in pairs:
        if a_proj not in per_proj or b_proj not in per_proj:
            continue
        keys = sorted(set(per_proj[a_proj]) & set(per_proj[b_proj]))
        for task_id, run_id in keys:
            ra = per_proj[a_proj][(task_id, run_id)]
            rb = per_proj[b_proj][(task_id, run_id)]
            ca, cb = derive_case(ra), derive_case(rb)
            cls, kind = _transition_class(
                ca["safety_outcome"], cb["safety_outcome"],
                ca["_gt_pos"])
            rec = {
                "pair": f"{a_proj}->{b_proj}",
                "task_id": task_id,
                "run_id": run_id,
                "cve_id": ca.get("cve_id"),
                "ground_truth": ca["ground_truth"],
                "ground_truth_category": ca["ground_truth_category"],
                "a": {"projection": a_proj,
                      "category": ca["predicted_category"],
                      "outcome": ca["safety_outcome"],
                      "status": ra.get("status")},
                "b": {"projection": b_proj,
                      "category": cb["predicted_category"],
                      "outcome": cb["safety_outcome"],
                      "status": rb.get("status")},
                "transition": cls,
                "kind": kind,
            }
            if b_proj.startswith("v_"):
                rec["validator_transition"] = _validator_transition(
                    ca["safety_outcome"], cb["safety_outcome"],
                    ca["_gt_pos"])
            out.append(rec)
    return out


def _validator_transition(a_out: str, b_out: str,
                          gt_pos: bool) -> str:
    """Safety meaning of a raw→validator projection change.

    Only the adjusted case gets a semantic name; unadjusted rows are
    ``unchanged`` even if the shared vocabulary would call a status
    wobble a transition."""
    if a_out == b_out:
        return "unchanged"
    if a_out == "safe" and b_out == "abstain":
        return "false_safe_blocked" if gt_pos else "correct_safe_lost"
    return f"other_{a_out}_to_{b_out}"


# ---------------------------------------------------------------------------
# Artifact writers
# ---------------------------------------------------------------------------


def _pct(x) -> str:
    return f"{x * 100:.1f}%" if isinstance(x, (int, float)) else "n/a"


def _table_row(proj: str, s: dict) -> str:
    a, c = s["attempts"], s["cases"]
    return (
        f"| {proj} | {s['n_rows']} | {a['false_safe']} / "
        f"{a['gt_exploitable']} | {_pct(s['false_safe_rate'])} | "
        f"{_pct(s['safe_clear_rate'])} | {_pct(s['exploitable_recall'])}"
        f" | {a['abstain']} | {a['failed']} | "
        f"{_pct(s['valid_claim_share'])} | "
        f"{_pct(s['checkable_claim_share'])} | "
        f"{a['total_tokens']} | ${a['cost_usd']:.3f} |")


def write_scoring_artifacts(
    manifest: dict,
    scored: dict[str, Path],
    out_dir: Path,
) -> dict:
    """Emit matrix.json + safety-report.md + validator-report.md;
    returns the written paths."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    matrix = build_matrix(manifest, scored)
    (out_dir / "matrix.json").write_text(
        json.dumps(matrix, indent=2) + "\n", encoding="utf-8")

    summaries = {
        proj: projection_summary(manifest, proj, scored[proj])
        for proj in PROJECTION_ORDER if proj in scored
    }
    disagreements = build_disagreements(manifest, scored)
    (out_dir / "disagreements.jsonl").write_text(
        "".join(json.dumps(r, ensure_ascii=False) + "\n"
                for r in disagreements), encoding="utf-8")

    # ---- safety-report.md --------------------------------------------------
    lines = [
        f"# Task 6 safety report — {manifest.get('experiment_id')}",
        "",
        f"Generated {_utc()} — offline join of four projections "
        "(no model calls).",
        "",
        "| Projection | Rows | FS | FS rate | SCR | EXP recall | "
        "abstain | FAILED | valid-claim | checkable-claim | tokens | "
        "cost |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for proj in PROJECTION_ORDER:
        if proj in summaries:
            lines.append(_table_row(proj, summaries[proj]))
    lines += [
        "",
        "Denominators: 7 exploitable / 23 safe per repeat (30 total); "
        "FS counts only GT-exploitable rows scored safe; abstain and "
        "FAILED are never false-safe. V- projections replay the same "
        "saved answers through the offline validator — a non-ACCEPTED "
        "decision on a safe verdict projects to abstain.",
        "",
        "## Unique-case view (repeats of one case count once)",
        "",
        "| Projection | cases | FS cases | CS cases | any-abstain |",
        "|---|---:|---:|---:|---:|",
    ]
    for proj in PROJECTION_ORDER:
        if proj in summaries:
            c = summaries[proj]["cases"]
            lines.append(
                f"| {proj} | {c['total']} | {c['false_safe']} | "
                f"{c['correct_safe']} | {c['any_abstain']} |")
    lines += ["", "## Transition classes (paired observed attempts only)",
              ""]
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

    # ---- validator-report.md ----------------------------------------------
    vlines = [
        f"# Task 6 validator report — {manifest.get('experiment_id')}",
        "",
        f"Generated {_utc()} — offline replay verdicts, agent answers "
        "unchanged.",
        "",
    ]
    for vproj, source in (("v_p2", "p2"), ("v_t2", "t2")):
        if vproj not in scored:
            continue
        vres = list(_validator_results(scored[vproj]).values())
        blocked = [r for r in vres if r.get("agent_outcome") == "safe"
                   and r.get("decision") != "ACCEPTED"]
        fs_blocked = [r for r in blocked
                      if r.get("ground_truth") == "exploitable"]
        cs_lost = [r for r in blocked
                   if r.get("ground_truth") != "exploitable"]
        claims = _claim_stats(vres)
        dec = Counter(r["decision"] for r in vres)
        vlines += [
            f"## {vproj} (replay of {source})",
            "",
            f"- attempts replayed: {len(vres)}",
            f"- FS blocked (attempts / unique cases): "
            f"{len(fs_blocked)} / "
            f"{len({r['task_id'] for r in fs_blocked})}",
            f"- correct safe lost (attempts / unique cases): "
            f"{len(cs_lost)} / "
            f"{len({r['task_id'] for r in cs_lost})}",
            f"- valid-claim share: "
            f"{_pct(summaries[vproj]['valid_claim_share'])}",
            f"- checkable negative-claim share: "
            f"{_pct(claims['checkable_claim_share'])} "
            f"({claims['n_checkable_claims']}/"
            f"{claims['n_negative_claims']})",
            f"- per-attempt decisions: "
            + ", ".join(f"{k}={v}" for k, v in sorted(dec.items())),
            f"- per-claim decisions: "
            + (", ".join(f"{k}={v}" for k, v in
                         sorted(claims['per_claim_decisions'].items()))
               or "none"),
            "",
        ]
        if blocked:
            vlines.append("| task_id | run_id | decision | agent_cat |")
            vlines.append("|---|---|---|---|")
            for r in blocked:
                vlines.append(
                    f"| {r['task_id']} | {r['run_id']} | "
                    f"{r['decision']} | {r['agent_category']} |")
            vlines.append("")
    if not any(v in scored for v in ("v_p2", "v_t2")):
        vlines.append("No validator projections scored yet.")
    (out_dir / "validator-report.md").write_text(
        "\n".join(vlines), encoding="utf-8")

    return {
        "matrix": str(out_dir / "matrix.json"),
        "disagreements": str(out_dir / "disagreements.jsonl"),
        "safety_report": str(out_dir / "safety-report.md"),
        "validator_report": str(out_dir / "validator-report.md"),
        "n_matrix_rows": matrix["n_rows"],
        "n_disagreements": len(disagreements),
        "summaries": summaries,
    }


def _utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

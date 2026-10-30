"""Offline replay driver for the V-P2 / V-T2 projections (plan §11,
spec §5.3).

Loads the saved, immutable P2/T2 attempt artifacts — no model
re-invocation, ever — and runs ``validator.validate_attempt`` over each
finalized attempt:

    inputs per attempt
        agent_assessment.json     (or recovered from
                                   raw_agent_output.txt via
                                   assessment_v2.extract_assessment_v2)
        tool_calls.jsonl / observations.jsonl   (audit trail)
        meta.snapshot_hash        (stored artifact metadata)
        advisory_record           — the get_vulnerability observation's
                                   ``data`` record when present in the
                                   audit trail (T2); else the public
                                   OSV record from the advisories
                                   library keyed by cve_id — NEVER the
                                   benchmark GT fields

    outputs per v-arm scoring dir (``scoring/v_p2``, ``scoring/v_t2``)
        validator_results.jsonl   — per-attempt decision + per-claim
                                    detail (the agent's category is
                                    stored alongside, never altered)
        parsed.jsonl              — validator-adjusted projection rows:
                                    a non-ACCEPTED decision on a safe
                                    verdict maps the projected outcome
                                    to abstain (uncertain), not safe,
                                    not positive; ACCEPTED keeps the
                                    agent's outcome verbatim
        parsed.parser_audit.jsonl — same adjusted rows (audit view)
        safety_metrics.json       — the official safety aggregation over
                                    the adjusted rows (vpr.score_rows)

The replay NEVER edits the attempt's raw artifacts — it reads them and
writes new files under the v-arm scoring dir only.
"""

from __future__ import annotations

import json
import logging
import os
from collections import Counter
from pathlib import Path
from typing import Iterable, Optional, Sequence

from eval import vexbench_plain_report as vpr
from eval.c1.report import derive_case
from eval.c1.status import AttemptStatus

from . import assessment_v2 as asm2
from . import collect as collect_mod
from . import validator as V

logger = logging.getLogger(__name__)

REPLAY_SCHEMA = "task6-replay/1"
V_ARM_PREFIX = "v_"

# Decisions that let the agent's own outcome stand.
_ACCEPT = "ACCEPTED"


def _read_jsonl(path: Path) -> list[dict]:
    path = Path(path)
    if not path.is_file():
        return []
    return [
        json.loads(l) for l in
        path.read_text(encoding="utf-8").splitlines() if l.strip()
    ]


def _write_jsonl(path: Path, rows: Iterable[dict]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows),
        encoding="utf-8")


# ---------------------------------------------------------------------------
# Attempt evidence loading (read-only)
# ---------------------------------------------------------------------------


def _audit_file(run_dir: Path) -> Optional[Path]:
    """Audit trail — controller copy first, then the exported sink."""
    run_dir = Path(run_dir)
    top = run_dir / "tool_calls.jsonl"
    if top.is_file():
        return top
    return collect_mod.audit_file_for(run_dir)


def _observation_rows(run_dir: Path) -> list[dict]:
    p = Path(run_dir) / "observations.jsonl"
    if p.is_file():
        return _read_jsonl(p)
    audit = _audit_file(run_dir)
    if audit is None:
        return []
    return collect_mod.read_audit_jsonl(audit)


def _stored_assessment(run_dir: Path):
    """The persisted AgentAssessmentV2 when collect wrote one."""
    p = Path(run_dir) / "agent_assessment.json"
    if not p.is_file():
        return None
    try:
        return asm2.AgentAssessmentV2.model_validate_json(
            p.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("%s: unparsable agent_assessment.json (%s) — "
                       "recovering from raw text instead", run_dir, exc)
        return None


def _extracted_assessment(run_dir: Path):
    """Fallback: recover the assessment from the terminal text the
    controller materialized (``raw_agent_output.txt``). The adapter's
    raw result container is NOT parsed here — collect owns that."""
    p = Path(run_dir) / "raw_agent_output.txt"
    if not p.is_file():
        return None
    return asm2.extract_assessment_v2(
        p.read_text(encoding="utf-8", errors="replace"))


def advisory_from_observations(observations: Sequence[dict]) -> Optional[dict]:
    """The public OSV-style advisory record the agent fetched — the
    first ``get_vulnerability`` observation's ``data`` payload. Never
    GT: this is what the tool returned, verbatim."""
    for obs in observations or ():
        if obs.get("tool") == "get_vulnerability" \
                and obs.get("tool_status") == "OK":
            data = obs.get("data")
            if isinstance(data, dict):
                return data
    return None


def advisory_from_library(advisories_dir: Optional[Path],
                          cve_id: Optional[str]) -> Optional[dict]:
    """Lookup a public OSV record by id/alias in the repo's advisories
    library — the P2 fallback (no MCP, so no get_vulnerability obs).
    Public input, same JSON the get_vulnerability tool normalizes."""
    if not advisories_dir or not cve_id:
        return None
    advisories_dir = Path(advisories_dir)
    if not advisories_dir.is_dir():
        return None
    for p in sorted(advisories_dir.glob("*.json")):
        try:
            rec = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(rec, dict):
            continue
        if rec.get("id") == cve_id or cve_id in (
                rec.get("aliases") or []):
            return rec
    return None


def _snapshot_file_index(snapshot_dir: Optional[Path]) -> Optional[set]:
    """Relative paths under the product snapshot root — the C1 file
    index the validator checks ``src:``/``file:`` refs against.
    Missing dir → None (never fabricated; the validator degrades to
    unverifiable rather than accepting a fabricated path)."""
    if not snapshot_dir:
        return None
    root = Path(snapshot_dir)
    if not root.is_dir():
        return None
    files: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for name in filenames:
            files.add(
                str(Path(dirpath, name).relative_to(root)))
    return files


def load_attempt_evidence(run_dir: Path, *,
                          advisories_dir: Optional[Path] = None,
                          cve_id: Optional[str] = None,
                          snapshot_hash: Optional[str] = None,
                          snapshot_dir: Optional[Path] = None) -> dict:
    """Everything the validator needs from one finalized attempt dir —
    read-only. Missing pieces are None, never fabricated."""
    run_dir = Path(run_dir)
    assessment = _stored_assessment(run_dir)
    extraction = None
    if assessment is None:
        extraction = _extracted_assessment(run_dir)

    audit_records: list[dict] = []
    audit = _audit_file(run_dir)
    if audit is not None:
        audit_records = collect_mod.read_audit_jsonl(audit)
    observations = _observation_rows(run_dir)

    stored_snapshot_hash = None
    if assessment is not None:
        stored_snapshot_hash = assessment.meta.snapshot_hash
    else:
        status_p = run_dir / "status.json"
        if status_p.is_file():
            try:
                st = AttemptStatus.model_validate_json(
                    status_p.read_text(encoding="utf-8"))
                stored_snapshot_hash = getattr(
                    st, "snapshot_hash", None)
            except Exception:
                stored_snapshot_hash = None
    # manifest-resolved hash (caller side) is the last fallback —
    # the attempt's own meta is authoritative when present
    snapshot_hash = snapshot_hash or stored_snapshot_hash

    advisory = advisory_from_observations(observations)
    advisory_source = "audit:get_vulnerability" if advisory else None
    if advisory is None:
        advisory = advisory_from_library(advisories_dir, cve_id)
        if advisory is not None:
            advisory_source = f"library:{advisories_dir}"

    return {
        "assessment": assessment,
        "extraction": extraction,
        "audit_records": audit_records,
        "observations": observations,
        "snapshot_hash": snapshot_hash,
        "snapshot_files": _snapshot_file_index(snapshot_dir),
        "advisory_record": advisory,
        "advisory_source": advisory_source,
    }


# ---------------------------------------------------------------------------
# Replay one attempt / one arm
# ---------------------------------------------------------------------------


def _validator_input(evidence: dict):
    """What validate_attempt consumes — the stored artifact when it
    exists, else the recovered extraction (agent's answer as stored)."""
    if evidence["assessment"] is not None:
        return evidence["assessment"]
    return evidence["extraction"]


def replay_attempt(
    run_dir: Path,
    *,
    arm: str,
    task_id: str,
    run_id: str,
    agent_category: Optional[str],
    advisories_dir: Optional[Path] = None,
    cve_id: Optional[str] = None,
    snapshot_hash: Optional[str] = None,
    snapshot_dir: Optional[Path] = None,
) -> dict:
    """Validate one saved attempt; returns the jsonl record. The
    agent's category rides alongside — the answer is never altered."""
    evidence = load_attempt_evidence(
        run_dir, advisories_dir=advisories_dir, cve_id=cve_id,
        snapshot_hash=snapshot_hash, snapshot_dir=snapshot_dir)
    inp = _validator_input(evidence)
    if inp is None:
        # no assessment artifact anywhere — recorded, not guessed
        result = V.ValidatorResult(
            decision="INSUFFICIENT_EVIDENCE"
            if agent_category in asm2.SAFE_CATEGORIES else "UNVERIFIABLE",
            category=agent_category,
            safe_verdict=agent_category in asm2.SAFE_CATEGORIES,
            reason="no structured assessment found in the attempt "
                   "artifacts — nothing to check",
            validator_version=V.VALIDATOR_VERSION,
        )
    else:
        result = V.validate_attempt(
            inp,
            audit_records=evidence["audit_records"],
            observations=evidence["observations"],
            snapshot_hash=evidence["snapshot_hash"],
            snapshot_files=evidence["snapshot_files"],
            advisory_record=evidence["advisory_record"],
        )
    return {
        "schema": REPLAY_SCHEMA,
        "arm": arm,
        "task_id": task_id,
        "run_id": run_id,
        "run_dir": str(run_dir),
        "agent_category": agent_category,
        "agent_safe_verdict": agent_category in asm2.SAFE_CATEGORIES,
        "assessment_present": inp is not None,
        "advisory_source": evidence["advisory_source"],
        "decision": result.decision,
        "safe_verdict": result.safe_verdict,
        "reason": result.reason,
        "per_claim": [c.model_dump() for c in result.per_claim],
        "falsifier": result.falsifier,
        "coverage": result.coverage.model_dump(),
        "validator_version": result.validator_version,
    }


def adjust_row(row: dict, decision: Optional[str],
               safe_verdict: bool) -> dict:
    """Validator-adjusted projection row: a non-ACCEPTED decision on a
    safe verdict maps to abstain (uncertain) — never safe, never
    positive. Every other row keeps the agent's outcome verbatim.
    The validator_decision rides in the row for traceability."""
    out = dict(row)
    if safe_verdict and decision is not None and decision != _ACCEPT:
        out["predicted_category"] = "uncertain"
        out["validator_adjusted"] = True
    else:
        out["validator_adjusted"] = False
    out["validator_decision"] = decision
    return out


def replay_arm(
    *,
    arm: str,
    run_root: Path,
    parsed_rows: Sequence[dict],
    out_dir: Path,
    advisories_dir: Optional[Path] = None,
    snapshot_hash_by_key: Optional[dict] = None,
    snapshot_dir_by_task: Optional[dict] = None,
) -> dict:
    """Replay every scored row of one raw arm through the validator
    and write the v-arm scoring dir. ``parsed_rows`` are the raw arm's
    ``parsed.jsonl`` rows — the scored agent answers (immutable).
    ``snapshot_hash_by_key`` maps (task_id, run_id) → the pinned
    snapshot hash (the manifest/acquisition fallback when the attempt
    meta itself lacks one).  ``snapshot_dir_by_task`` maps task_id →
    the product snapshot root (``<repos_dir>/<owner>/<repo>/<sha>``) —
    when present it supplies the C1 file index; absent/missing dirs
    degrade to unverifiable refs, never an automatic pass."""
    run_root = Path(run_root)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    results: list[dict] = []
    adjusted: list[dict] = []
    for row in parsed_rows:
        task_id = row["task_id"]
        run_id = row["run_id"]
        run_dir = run_root / task_id / run_id
        rec = replay_attempt(
            run_dir, arm=arm, task_id=task_id, run_id=run_id,
            agent_category=row.get("predicted_category"),
            advisories_dir=advisories_dir,
            cve_id=row.get("cve_id"),
            snapshot_hash=(snapshot_hash_by_key or {}).get(
                (task_id, run_id)),
            snapshot_dir=(snapshot_dir_by_task or {}).get(task_id))
        rec["ground_truth"] = row.get("ground_truth")
        rec["agent_outcome"] = vpr.safety_outcome(
            row.get("status"), row.get("predicted_category"))
        results.append(rec)
        adjusted.append(adjust_row(
            row, rec["decision"], rec["agent_safe_verdict"]))

    _write_jsonl(out_dir / "validator_results.jsonl", results)
    _write_jsonl(out_dir / "parsed.jsonl", adjusted)
    _write_jsonl(out_dir / "parsed.parser_audit.jsonl", adjusted)

    safety = _safety_doc(
        arm=arm, adjusted=adjusted, results=results,
        parsed_rows=parsed_rows)
    (out_dir / "safety_metrics.json").write_text(
        json.dumps(safety, indent=2) + "\n", encoding="utf-8")

    blocked = [r for r in results
               if r["agent_outcome"] == "safe"
               and r["decision"] != _ACCEPT]
    return {
        "schema": REPLAY_SCHEMA,
        "arm": arm,
        "out_dir": str(out_dir),
        "n_attempts": len(results),
        "n_blocked": len(blocked),
        "blocked_attempts": [
            {"task_id": r["task_id"], "run_id": r["run_id"],
             "decision": r["decision"]} for r in blocked],
        "decision_counts": dict(Counter(r["decision"] for r in results)),
        "missing_assessment": sum(
            1 for r in results if not r["assessment_present"]),
        "advisory_missing": sum(
            1 for r in results if r["advisory_source"] is None),
    }


def _safety_doc(*, arm: str, adjusted: Sequence[dict],
                results: Sequence[dict],
                parsed_rows: Sequence[dict]) -> dict:
    """The official safety aggregation over the adjusted rows — same
    math as c1.report's safety_doc (score_rows → per-repeat vectors →
    aggregate), plus the validator-decision accounting."""
    cases = [derive_case(r) for r in adjusted]
    by_run = vpr.group_by_run(cases)
    per_repeat = {r: vpr.score_rows(cs) for r, cs in by_run.items()}
    agg = vpr.aggregate_repeats(per_repeat)
    pooled = dict(vpr.score_rows(cases))
    pooled["note"] = ("secondary pooled view over all rows — NOT the "
                      "repeat-mean")

    # raw-projection outcomes for the blocked/lost accounting
    raw_out = {}
    for r, rec in zip(adjusted, results):
        raw_out[(r["task_id"], r["run_id"])] = rec["agent_outcome"]

    claim_decisions: Counter = Counter()
    n_claims = 0
    n_checkable = 0
    for rec in results:
        for c in rec.get("per_claim", []):
            n_claims += 1
            claim_decisions[c.get("decision") or "clean"] += 1
            if c.get("supported"):
                n_checkable += 1

    fs_blocked, cs_lost = [], []
    for rec in results:
        if rec["agent_outcome"] != "safe" or rec["decision"] == _ACCEPT:
            continue
        (fs_blocked if rec["ground_truth"] == "exploitable"
         else cs_lost).append(
            {"task_id": rec["task_id"], "run_id": rec["run_id"],
             "decision": rec["decision"]})

    return {
        "schema": "task6-replay-safety/1",
        "projection": f"validator/{arm}",
        "validator_version": V.VALIDATOR_VERSION,
        "inputs": {
            "n_rows": len(adjusted),
            "source_arm": arm,
        },
        "n_repeats": agg["n_repeats"],
        "per_repeat": per_repeat,
        "aggregate": agg,
        "pooled": pooled,
        "assessment_schema": {
            "pooled": dict(Counter(
                "present" if r["assessment_present"] else "missing"
                for r in results)),
        },
        "telemetry_coverage": {"mcp_audit": {"state": "replay"}},
        "validator": {
            "decision_counts": dict(
                Counter(r["decision"] for r in results)),
            "n_negative_claims": n_claims,
            "n_checkable_claims": n_checkable,
            "per_claim_decisions": dict(claim_decisions),
            "false_safe_blocked_attempts": fs_blocked,
            "correct_safe_lost_attempts": cs_lost,
            "false_safe_blocked_cases": sorted(
                {r["task_id"] for r in fs_blocked}),
            "correct_safe_lost_cases": sorted(
                {r["task_id"] for r in cs_lost}),
        },
    }


def v_arm_name(arm: str) -> str:
    return V_ARM_PREFIX + arm


def replay_arms(
    *,
    manifest: dict,
    arms: Sequence[str],
    scoring_root: Path,
    advisories_dir: Optional[Path] = None,
    snapshot_hash_by_task: Optional[dict] = None,
    snapshot_dir_by_task: Optional[dict] = None,
) -> dict:
    """Drive every requested raw arm's replay (parsed.jsonl must exist
    in ``<scoring_root>/<arm>/`` — replay depends on ``score`` having
    run first, per plan §10→§11 order).  ``snapshot_hash_by_task`` maps
    task_id → pinned snapshot hash (acquisition fallback);
    ``snapshot_dir_by_task`` maps task_id → the product snapshot root
    for the C1 file index (absent → degrade, never pass)."""
    scoring_root = Path(scoring_root)
    out = {}
    for arm in arms:
        parsed_path = scoring_root / arm / "parsed.jsonl"
        if not parsed_path.is_file():
            out[arm] = {"error": f"no parsed.jsonl under "
                                 f"{scoring_root / arm} — run score "
                                 f"for arm {arm} first"}
            continue
        rows = _read_jsonl(parsed_path)
        by_key = {
            (r["task_id"], r["run_id"]):
                (snapshot_hash_by_task or {}).get(r["task_id"])
            for r in rows
        }
        run_root = Path(manifest["arms"][arm]["run_root"])
        out[v_arm_name(arm)] = replay_arm(
            arm=arm, run_root=run_root, parsed_rows=rows,
            out_dir=scoring_root / v_arm_name(arm),
            advisories_dir=advisories_dir,
            snapshot_hash_by_key=by_key,
            snapshot_dir_by_task=snapshot_dir_by_task)
    return out

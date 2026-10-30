#!/usr/bin/env python3
"""Human-work and run metrics for the R6 decision-ready validation.

Plan: docs/dev/plans/2026-10-15-02-decision-ready-triage-plan.md, Task 7.
Doctrine: Amendment R6 in docs/dev/plans/2026-10-15-01-c02-closure-capability-plan.md
(section "Human-work metrics").

Inputs
------
events            JSON array or JSONL of `decision-ready-review-event/1`
                  records (events.schema.json). Produced only by the blinded
                  human acceptance study; absent until it runs.
artifact index    JSON object mapping artifact_digest (sha256 of the emitted
                  decision-artifact.json) to artifact metadata written by
                  runner.py: disposition, branch ids/statuses, declared
                  environment question ids, mandatory fact ids, decision_ready
                  flag and the sanitized class labels used for falsification
                  (expected_class / ground_truth_class). No private
                  identifiers: digests and Cxx/case-NN labels only.
case records      runner.py's runs.jsonl / summary case list: per-case model
                  calls, tokens, cost, elapsed and termination.

Everything here is pure computation — this module never invokes a model, a
tool, or the analyzer, and it never fabricates values for missing inputs:
absent inputs yield explicit null/`measured=false` fields, never zeros that
masquerade as measurements.
"""

import argparse
import json
import re
import statistics
import sys
from datetime import datetime

SCHEMA = "decision-ready-metrics/1"
EVENT_SCHEMA_ID = "decision-ready-review-event/1"
TRIAGE_EVENT_SCHEMA_ID = "triage-review-event.v1"
SUPPORTED_EVENT_SCHEMAS = {EVENT_SCHEMA_ID, TRIAGE_EVENT_SCHEMA_ID}
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

# ProposedDisposition enum from internal/research/dispositions.go.
CLOSE_DISPOSITIONS = {"CLOSE_NOT_AFFECTED", "CLOSE_NO_EXPLOIT_PATH"}
SAFE_PROPOSALS = CLOSE_DISPOSITIONS | {"ACCEPT_ENVIRONMENTAL_MITIGATION"}
ALL_DISPOSITIONS = SAFE_PROPOSALS | {"KEEP_OPEN_FOR_REMEDIATION", "HOLD_UNKNOWN"}

# artifact_class split — code-grounded closure is never merged with
# environmental mitigation into one automation number (plan acceptance).
ARTIFACT_CLASS = {
    "CLOSE_NOT_AFFECTED": "code_grounded",
    "CLOSE_NO_EXPLOIT_PATH": "code_grounded",
    "ACCEPT_ENVIRONMENTAL_MITIGATION": "environmental_mitigation",
    "KEEP_OPEN_FOR_REMEDIATION": "open_or_hold",
    "HOLD_UNKNOWN": "open_or_hold",
}

# expected/ground-truth classes that make a safe proposal false-safe.
EXPLOITABLE_TRUTH = {"exploitable"}

# Human contract targets (Amendment R6): the two decision-time bounds are
# [INFERENCE] targets — they are measured, never assumed.
TARGET_MEDIAN_DECISION_S = 300.0   # <= 5 min, [INFERENCE]
TARGET_P95_DECISION_S = 600.0      # <= 10 min, [INFERENCE]


def _parse_ts(value):
    """RFC3339/ISO-8601 timestamp -> datetime, or None. Accepts trailing Z."""
    if not isinstance(value, str) or not value:
        return None
    v = value.strip()
    if v.endswith("Z") or v.endswith("z"):
        v = v[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(v)
    except ValueError:
        return None


def percentile(values, q):
    """Linear-interpolation percentile (q in [0,100]) over a sequence."""
    xs = sorted(float(v) for v in values)
    if not xs:
        return None
    if len(xs) == 1:
        return xs[0]
    i = (q / 100.0) * (len(xs) - 1)
    lo = int(i)
    if lo >= len(xs) - 1:
        return xs[-1]
    frac = i - lo
    return xs[lo] + frac * (xs[lo + 1] - xs[lo])


def summarize(values):
    """{n, median, p75, p95} for a numeric sample; None fields when empty."""
    xs = [float(v) for v in values]
    if not xs:
        return {"n": 0, "median": None, "p75": None, "p95": None}
    return {
        "n": len(xs),
        "median": percentile(xs, 50),
        "p75": percentile(xs, 75),
        "p95": percentile(xs, 95),
    }


# ---------------------------------------------------------------- events ---

_EVENT_BOOLS = ("accepted", "returned_for_remediation", "reopened")
_EVENT_COUNTS = ("repository_open_count", "tool_rerun_count", "technical_follow_up_count")


def validate_event(ev):
    """Structural validation of one decision-ready-review-event/1 record.

    Returns a list of problem strings; empty means the event is usable.
    This mirrors events.schema.json without requiring the jsonschema
    package — the schema file remains the canonical contract.
    """
    problems = []
    if not isinstance(ev, dict):
        return ["event is not a JSON object"]
    if not DIGEST_RE.match(ev.get("artifact_digest") or ""):
        problems.append("artifact_digest must be 'sha256:' + 64 lowercase hex")
    started = _parse_ts(ev.get("started_at"))
    finished = _parse_ts(ev.get("finished_at"))
    if started is None:
        problems.append("started_at missing or not an ISO-8601 timestamp")
    if finished is None:
        problems.append("finished_at missing or not an ISO-8601 timestamp")
    if started is not None and finished is not None and finished < started:
        problems.append("finished_at precedes started_at")
    if not isinstance(ev.get("accepted"), bool):
        problems.append("accepted must be a boolean")
    for field in _EVENT_BOOLS[1:]:
        if not isinstance(ev.get(field), bool):
            problems.append(f"{field} must be a boolean")
    for field in _EVENT_COUNTS:
        v = ev.get(field)
        if not isinstance(v, int) or isinstance(v, bool) or v < 0:
            problems.append(f"{field} must be a non-negative integer")
    answers = ev.get("environment_answers")
    if not isinstance(answers, list):
        problems.append("environment_answers must be an array")
    else:
        if len(answers) > 2:
            problems.append("environment_answers exceeds the R6 bound of 2 questions")
        for i, a in enumerate(answers):
            if not isinstance(a, dict) or not a.get("variable") or not a.get("value"):
                problems.append(f"environment_answers[{i}] needs non-empty variable and value")
    refs = ev.get("mandatory_fact_refs_read")
    if not isinstance(refs, list) or any(not isinstance(r, str) or not r for r in (refs or [])):
        problems.append("mandatory_fact_refs_read must be an array of non-empty strings")
    ev_schema = ev.get("event_schema") or ev.get("schema_version")
    if ev_schema is not None and ev_schema not in SUPPORTED_EVENT_SCHEMAS:
        problems.append(f"event_schema {ev_schema!r} not in {sorted(SUPPORTED_EVENT_SCHEMAS)}")
    return problems


def load_events(path):
    """Load events from a JSON array file or a .jsonl file."""
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    stripped = text.lstrip()
    if not stripped:
        return []
    if stripped.startswith("["):
        data = json.loads(text)
        if not isinstance(data, list):
            raise ValueError(f"{path}: top-level JSON array expected")
        return data
    events = []
    for lineno, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError as exc:
            events.append({"__invalid__": f"{path}:{lineno}: {exc}"})
    return events


def load_artifact_index(path):
    """Load the digest -> artifact-record map emitted by runner.py."""
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict) and "artifacts" in data:
        data = data["artifacts"]
    if isinstance(data, list):
        out = {}
        for rec in data:
            d = (rec or {}).get("artifact_digest")
            if d:
                out[d] = rec
        return out
    if isinstance(data, dict):
        return data
    raise ValueError(f"{path}: artifact index must be an object or array")


def load_case_records(path):
    """Load runner case records (runs.jsonl or a JSON array)."""
    records = []
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    stripped = text.lstrip()
    if stripped.startswith("["):
        data = json.loads(text)
        records = [r for r in data if isinstance(r, dict)]
    else:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(r, dict):
                records.append(r)
    return records


def _artifact_class(art):
    disp = (art or {}).get("proposed_disposition")
    return ARTIFACT_CLASS.get(disp, "open_or_hold")


def _truth_is_exploitable(art):
    gt = (art or {}).get("ground_truth_class") or (art or {}).get("expected_class")
    return isinstance(gt, str) and gt.lower() in EXPLOITABLE_TRUTH


def _decision_seconds(ev):
    a, b = _parse_ts(ev.get("started_at")), _parse_ts(ev.get("finished_at"))
    if a is None or b is None:
        return None
    return (b - a).total_seconds()


def _bucket_by(rows, keyfn):
    out = {}
    for row in rows:
        keyfn(row)[1].append(row) if False else None
        k, _ = keyfn(row)
        out.setdefault(k, []).append(row)
    return out


def compute_metrics(events, artifacts, case_records=None):
    """Compute the full R6 human-work metric set.

    `events` — raw review-event records (validated here).
    `artifacts` — digest -> artifact record (runner.py artifact index).
    `case_records` — runner.py run records for model-call/cost accounting.

    Counts are never silently dropped: invalid or unbound events are counted
    and listed by digest. Code-grounded and environmental-mitigation classes
    are reported in separate buckets everywhere — no merged automation number.
    """
    case_records = case_records or []

    valid, invalid_problems = [], []
    seen_session_keys = set()
    duplicate_events = []
    for ev in events:
        problems = validate_event(ev)
        if problems:
            invalid_problems.append({
                "artifact_digest": ev.get("artifact_digest") if isinstance(ev, dict) else None,
                "problems": problems,
            })
        else:
            sess = ev.get("reviewer_session")
            digest = ev.get("artifact_digest")
            if sess and digest:
                pair_key = (sess, digest)
                if pair_key in seen_session_keys:
                    duplicate_events.append(ev)
                    invalid_problems.append({
                        "artifact_digest": digest,
                        "problems": [f"duplicate review event for session {sess} on artifact {digest}"],
                    })
                    continue
                seen_session_keys.add(pair_key)
            valid.append(ev)

    bound, unbound = [], []
    for ev in valid:
        art = artifacts.get(ev["artifact_digest"])
        if art is None:
            unbound.append(ev["artifact_digest"])
        else:
            bound.append((ev, art))

    dr_pairs = [(e, a) for e, a in bound if a.get("decision_ready")]
    accepted_pairs = [(e, a) for e, a in bound if e["accepted"]]
    accepted_dr = [(e, a) for e, a in dr_pairs if e["accepted"]]

    # --- human_decision_time: median/P75/P95 by disposition, branch count, class
    times_overall = [s for e, _ in bound for s in [_decision_seconds(e)] if s is not None]
    by_disp, by_bcount, by_class = {}, {}, {}
    for ev, art in bound:
        s = _decision_seconds(ev)
        if s is None:
            continue
        disp = art.get("proposed_disposition") or "UNBOUND"
        by_disp.setdefault(disp, []).append(s)
        bcount = art.get("branch_count")
        by_bcount.setdefault(str(bcount) if bcount is not None else "unknown", []).append(s)
        by_class.setdefault(_artifact_class(art), []).append(s)

    facts_by_class = {}
    for ev, art in bound:
        facts_by_class.setdefault(_artifact_class(art), []).append(
            len(ev["mandatory_fact_refs_read"]))

    # --- repo_open_rate (brief formula: artifacts with opens>0 / decision-ready artifacts)
    dr_digests = {}
    for ev, art in dr_pairs:
        d = ev["artifact_digest"]
        dr_digests.setdefault(d, {"opened": False, "accepted": False, "events": 0})
        dr_digests[d]["events"] += 1
        if ev["repository_open_count"] > 0:
            dr_digests[d]["opened"] = True
        if ev["accepted"]:
            dr_digests[d]["accepted"] = True
    n_dr_art = len(dr_digests)
    opened_art = sum(1 for v in dr_digests.values() if v["opened"])
    accepted_digests = {d for d, v in dr_digests.items() if v["accepted"]}
    accepted_opened = sum(1 for d in accepted_digests if dr_digests[d]["opened"])
    repo_open_rate = (opened_art / n_dr_art) if n_dr_art else None
    repo_open_rate_accepted = (accepted_opened / len(accepted_digests)) if accepted_digests else None

    # --- missing_fact_rejection_rate: among events that left >=1 declared
    #     mandatory fact unread, the share the reviewer rejected.
    missing_pairs, missing_rejected, accepted_unread = [], 0, []
    for ev, art in dr_pairs:
        mandatory = art.get("mandatory_fact_ids") or []
        if not mandatory:
            continue
        unread = set(mandatory) - set(ev["mandatory_fact_refs_read"])
        if unread:
            missing_pairs.append((ev, art))
            if ev["accepted"]:
                accepted_unread.append(ev["artifact_digest"])
            else:
                missing_rejected += 1
    missing_fact_rejection_rate = (
        missing_rejected / len(missing_pairs)) if missing_pairs else None

    # --- environment questions / answers / unknown / branch change
    declared_q_total = 0
    answers_total = 0
    unknown_answers = 0
    answered_events = 0
    branch_pairs = 0
    branch_changes = 0
    branch_change_on_code_grounded = 0
    for ev, art in bound:
        declared = art.get("env_question_ids")
        declared_q_total += len(declared) if declared else len(ev["environment_answers"])
        if ev["environment_answers"]:
            answered_events += 1
        for a in ev["environment_answers"]:
            answers_total += 1
            if str(a.get("value", "")).lower() == "unknown":
                unknown_answers += 1
        ini, sel = ev.get("initial_branch_id"), ev.get("selected_branch_id")
        if ev["environment_answers"] and ini and sel:
            branch_pairs += 1
            if ini != sel:
                branch_changes += 1
                if _artifact_class(art) == "code_grounded":
                    branch_change_on_code_grounded += 1

    # --- accepted false-safe (zero tolerance — a stop, never a rate to report around)
    fs_events = []
    for ev, art in bound:
        if not ev["accepted"]:
            continue
        disp = art.get("proposed_disposition")
        if disp in SAFE_PROPOSALS and _truth_is_exploitable(art):
            fs_events.append({
                "artifact_digest": ev["artifact_digest"],
                "proposed_disposition": disp,
                "artifact_class": _artifact_class(art),
            })
    fs_code = sum(1 for f in fs_events if f["artifact_class"] == "code_grounded")
    fs_env = sum(1 for f in fs_events if f["artifact_class"] == "environmental_mitigation")

    # --- reopen/reversal, remediation returns, reruns, follow-ups
    n_events = len(bound)
    n_accepted = len(accepted_pairs)
    reopened = [e for e, _ in bound if e["reopened"]]
    returned = [e for e, _ in bound if e["returned_for_remediation"]]
    rerun_events = [e for e, _ in bound if e["tool_rerun_count"] > 0]
    followup_events = [e for e, _ in bound if e["technical_follow_up_count"] > 0]
    accepted_followup = [d for e, a in accepted_pairs if e["technical_follow_up_count"] > 0
                         for d in [e["artifact_digest"]]]

    # --- model cost accounting (from runner case records)
    model = {
        "calls_total": 0,
        "turns_total": 0,
        "tokens_input": 0,
        "tokens_output": 0,
        "tokens_reasoning": 0,
        "cost_total": 0.0,
        "cost_known_cases": 0,
        "cost_unknown_cases": 0,
        "elapsed_seconds_total": 0.0,
        "live_runs": 0,
        "replayed_runs": 0,
        "deterministic_only_runs": 0,
        "per_case": {},
    }
    for rec in case_records:
        cid = rec.get("case_id") or rec.get("case") or "?"
        calls = int(rec.get("model_calls") or 0)
        turns = rec.get("turns") or []
        tin = sum(int((t.get("tokens") or {}).get("input", 0)) for t in turns if isinstance(t, dict))
        tout = sum(int((t.get("tokens") or {}).get("output", 0)) for t in turns if isinstance(t, dict))
        treason = sum(int((t.get("tokens") or {}).get("reasoning", 0)) for t in turns if isinstance(t, dict))
        costs = [float(t["cost"]) for t in turns
                 if isinstance(t, dict) and isinstance(t.get("cost"), (int, float))]
        # turns_count is a fallback only when the record does not distinguish
        # model calls from turn attempts at all; an explicit model_calls wins.
        if rec.get("model_calls") is None and isinstance(rec.get("turns_count"), int):
            calls = rec["turns_count"]
        model["calls_total"] += calls
        model["turns_total"] += len(turns)
        model["tokens_input"] += tin
        model["tokens_output"] += tout
        model["tokens_reasoning"] += treason
        if costs:
            model["cost_total"] += sum(costs)
            model["cost_known_cases"] += 1
        else:
            model["cost_unknown_cases"] += 1
        elapsed = rec.get("elapsed_s") or 0
        model["elapsed_seconds_total"] += float(elapsed)
        exe = rec.get("execution")
        if exe == "live":
            model["live_runs"] += 1
        elif exe == "replay":
            model["replayed_runs"] += 1
        elif exe == "deterministic_only":
            model["deterministic_only_runs"] += 1
        model["per_case"][cid] = {
            "execution": exe,
            "model_calls": calls,
            "turns": len(turns),
            "tokens_input": tin,
            "tokens_output": tout,
            "tokens_reasoning": treason,
            "cost": sum(costs) if costs else None,
            "elapsed_s": elapsed,
        }

    # --- disposition / class census of indexed artifacts
    by_disposition = {}
    by_art_class = {"code_grounded": 0, "environmental_mitigation": 0, "open_or_hold": 0}
    decision_ready_count = 0
    for art in artifacts.values():
        disp = art.get("proposed_disposition") or "UNKNOWN"
        by_disposition[disp] = by_disposition.get(disp, 0) + 1
        by_art_class[_artifact_class(art)] += 1
        if art.get("decision_ready"):
            decision_ready_count += 1

    # --- human contract targets (Amendment R6)
    med = summarize(times_overall)["median"]
    p95 = summarize(times_overall)["p95"]
    targets = {
        "repo_open_rate_accepted_decision_ready": {
            "target": 0, "measured": repo_open_rate_accepted,
            "met": (repo_open_rate_accepted == 0) if repo_open_rate_accepted is not None else None,
        },
        "accepted_with_unread_mandatory_facts": {
            "target": 0, "measured": len(accepted_unread),
            "met": len(accepted_unread) == 0,
        },
        "accepted_with_technical_follow_up": {
            "target": 0, "measured": len(accepted_followup),
            "met": len(accepted_followup) == 0,
        },
        "median_decision_time_s": {
            "target": TARGET_MEDIAN_DECISION_S, "inference": True, "measured": med,
            "met": (med <= TARGET_MEDIAN_DECISION_S) if med is not None else None,
        },
        "p95_decision_time_s": {
            "target": TARGET_P95_DECISION_S, "inference": True, "measured": p95,
            "met": (p95 <= TARGET_P95_DECISION_S) if p95 is not None else None,
        },
    }

    return {
        "schema": SCHEMA,
        "inputs": {
            "events_total": len(events),
            "events_valid": len(valid),
            "events_invalid": len(invalid_problems),
            "events_unbound_artifact": len(unbound),
            "artifacts_indexed": len(artifacts),
            "case_records": len(case_records),
            "measured": len(events) > 0,
            "duplicate_review_events": len(duplicate_events),
        },
        "duplicate_review_events_count": len(duplicate_events),
        "invalid_events": invalid_problems,
        "unbound_artifact_digests": unbound,
        "artifacts": {
            "total": len(artifacts),
            "decision_ready": decision_ready_count,
            "by_disposition": by_disposition,
            "by_class": by_art_class,
        },
        "human_decision_time_seconds": {
            "overall": summarize(times_overall),
            "by_disposition": {k: summarize(v) for k, v in sorted(by_disp.items())},
            "by_branch_count": {k: summarize(v) for k, v in sorted(by_bcount.items())},
            "by_class": {k: summarize(v) for k, v in sorted(by_class.items())},
        },
        "facts_read": {
            "overall": summarize([len(e["mandatory_fact_refs_read"]) for e, _ in bound]),
            "by_class": {k: summarize(v) for k, v in sorted(facts_by_class.items())},
        },
        "repo_open": {
            "decision_ready_artifacts_reviewed": n_dr_art,
            "artifacts_with_repo_opens": opened_art,
            "repo_open_rate": repo_open_rate,
            "accepted_artifacts": len(accepted_digests),
            "accepted_artifacts_with_repo_opens": accepted_opened,
            "repo_open_rate_accepted": repo_open_rate_accepted,
            "events_with_repo_opens": sum(1 for e, _ in dr_pairs if e["repository_open_count"] > 0),
        },
        "missing_facts": {
            "events_with_unread_mandatory_facts": len(missing_pairs),
            "rejected": missing_rejected,
            "missing_fact_rejection_rate": missing_fact_rejection_rate,
            "accepted_with_unread_mandatory_facts": accepted_unread,
        },
        "environment": {
            "declared_questions_total": declared_q_total,
            "answers_total": answers_total,
            "answered_events": answered_events,
            "answer_rate": (answers_total / declared_q_total) if declared_q_total else None,
            "unknown_answers": unknown_answers,
            "unknown_rate": (unknown_answers / answers_total) if answers_total else None,
            "branch_change_after_answer": {
                "answered_events_with_branch_pair": branch_pairs,
                "branch_changes": branch_changes,
                "rate": (branch_changes / branch_pairs) if branch_pairs else None,
                "branch_changes_on_code_grounded": branch_change_on_code_grounded,
            },
        },
        "accepted_false_safe": {
            "total": len(fs_events),
            "code_grounded": fs_code,
            "environmental_mitigation": fs_env,
            "rate_over_accepted": (len(fs_events) / n_accepted) if n_accepted else None,
            "events": fs_events,
        },
        "reopen_reversal": {
            "reopened_events": len(reopened),
            "reopen_rate_over_accepted": (len(reopened) / n_accepted) if n_accepted else None,
            "reopen_rate_over_events": (len(reopened) / n_events) if n_events else None,
            "returned_for_remediation": len(returned),
            "returned_rate_over_events": (len(returned) / n_events) if n_events else None,
        },
        "human_rerun": {
            "events_with_tool_reruns": len(rerun_events),
            "rate": (len(rerun_events) / n_events) if n_events else None,
        },
        "technical_follow_up": {
            "events_with_follow_up": len(followup_events),
            "rate_over_events": (len(followup_events) / n_events) if n_events else None,
            "accepted_with_follow_up": accepted_followup,
        },
        "model": model,
        "human_contract_targets": targets,
        "stop_conditions": {
            "accepted_false_safe": len(fs_events),
            "branch_change_on_code_grounded": branch_change_on_code_grounded,
            "foreign_package_events": len(unbound),
            "any": len(fs_events) > 0 or branch_change_on_code_grounded > 0 or len(unbound) > 0,
        },
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Compute R6 human-work metrics from review events, the "
                    "runner's artifact index and its case records.")
    ap.add_argument("--events", help="JSON array or JSONL of decision-ready-review-event/1 records")
    ap.add_argument("--artifact-index", help="artifact index JSON emitted by runner.py")
    ap.add_argument("--case-records", help="runner.py runs.jsonl / cases JSON")
    ap.add_argument("--out", help="write metrics JSON here (default: stdout)")
    args = ap.parse_args(argv)

    events = load_events(args.events) if args.events else []
    artifacts = load_artifact_index(args.artifact_index) if args.artifact_index else {}
    cases = load_case_records(args.case_records) if args.case_records else []

    out = compute_metrics(events, artifacts, cases)
    text = json.dumps(out, indent=2, sort_keys=True) + "\n"
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)

    stop = out["stop_conditions"]
    if stop["any"]:
        print(f"STOP CONDITION: accepted_false_safe={stop['accepted_false_safe']} "
              f"branch_change_on_code_grounded={stop['branch_change_on_code_grounded']}",
              file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

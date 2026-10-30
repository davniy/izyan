#!/usr/bin/env python3
"""Focused metric tests; producer assertions live in test_runner.py.

Run:  python3 -m pytest eval/decision_ready/test_metrics.py -q
Everything here is synthetic and offline — no model calls, no repo access.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import metrics  # noqa: E402

DIGEST = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64
DIGEST_D = "sha256:" + "d" * 64


def ev(digest=DIGEST, start="2026-10-16T10:00:00Z", finish="2026-10-16T10:04:00Z",
       accepted=True, answers=None, facts=None, repos=0, reruns=0, follow=0,
       returned=False, reopened=False, ini=None, sel=None):
    return {
        "artifact_digest": digest,
        "started_at": start,
        "finished_at": finish,
        "accepted": accepted,
        "environment_answers": answers or [],
        "mandatory_fact_refs_read": facts or [],
        "repository_open_count": repos,
        "tool_rerun_count": reruns,
        "technical_follow_up_count": follow,
        "returned_for_remediation": returned,
        "reopened": reopened,
        **({"initial_branch_id": ini, "selected_branch_id": sel} if ini else {}),
    }


def art(digest=DIGEST, disp="CLOSE_NOT_AFFECTED", ready=True, facts=None,
        env=None, branches=2, truth=None):
    return {
        "artifact_digest": digest,
        "case_id": "case-01",
        "proposed_disposition": disp,
        "decision_ready": ready,
        "branch_count": branches,
        "branch_statuses": {"B-1": "COMPLETE", "B-UNKNOWN": "COMPLETE"},
        "env_question_ids": env or [],
        "mandatory_fact_ids": facts or [],
        "flow_termination": "DECISION_READY",
        "expected_class": truth,
    }


# ------------------------------------------------------------ validation --

def test_validate_event_happy_path():
    assert metrics.validate_event(ev()) == []


def test_validate_event_rejects_bad_digest():
    assert metrics.validate_event(ev(digest="not-a-digest"))


def test_validate_event_rejects_missing_fields():
    assert metrics.validate_event({"artifact_digest": DIGEST})


def test_validate_event_rejects_three_answers():
    answers = [{"variable": f"v{i}", "value": "x"} for i in range(3)]
    problems = metrics.validate_event(ev(answers=answers))
    assert any("bound of 2" in p for p in problems)


def test_validate_event_rejects_reversed_timestamps():
    assert metrics.validate_event(ev(finish="2026-10-16T09:00:00Z"))


def test_validate_event_rejects_negative_count():
    assert metrics.validate_event(ev(repos=-1))


# ------------------------------------------------------------ percentiles --

def test_percentile_interpolates():
    xs = [10, 20, 30, 40]
    assert metrics.percentile(xs, 50) == 25
    assert metrics.percentile(xs, 75) == 32.5
    assert metrics.percentile(xs, 95) == 38.5
    assert metrics.percentile([], 95) is None
    assert metrics.percentile([7], 95) == 7


def test_summarize_empty_is_nulls():
    s = metrics.summarize([])
    assert s == {"n": 0, "median": None, "p75": None, "p95": None}


# ----------------------------------------------------- decision time split --

def test_decision_time_by_disposition_and_branch_count():
    arts = {
        DIGEST: art(disp="CLOSE_NOT_AFFECTED", branches=1),
        DIGEST_B: {**art(DIGEST_B, disp="ACCEPT_ENVIRONMENTAL_MITIGATION", branches=3)},
    }
    events = [
        ev(finish="2026-10-16T10:01:00Z"),                                    # 60s
        ev(finish="2026-10-16T10:09:00Z"),                                    # 540s
        ev(DIGEST_B, finish="2026-10-16T10:02:00Z"),                          # 120s
    ]
    m = metrics.compute_metrics(events, arts)
    t = m["human_decision_time_seconds"]
    assert t["overall"]["n"] == 3
    assert t["by_disposition"]["CLOSE_NOT_AFFECTED"]["median"] == 300.0
    assert t["by_disposition"]["ACCEPT_ENVIRONMENTAL_MITIGATION"]["median"] == 120.0
    assert t["by_branch_count"]["1"]["n"] == 2
    assert t["by_branch_count"]["3"]["median"] == 120.0
    # classes never merge: close is code_grounded, mitigation is its own bucket
    assert t["by_class"]["code_grounded"]["n"] == 2
    assert t["by_class"]["environmental_mitigation"]["n"] == 1


def test_facts_read_stats():
    arts = {DIGEST: art(facts=["f1", "f2", "f3"])}
    events = [ev(facts=["f1", "f2"]), ev(facts=["f1", "f2", "f3"])]
    m = metrics.compute_metrics(events, arts)
    assert m["facts_read"]["overall"]["n"] == 2
    assert m["facts_read"]["overall"]["median"] == 2.5


# ------------------------------------------------------------ repo_open_rate

def test_repo_open_rate_counts_decision_ready_artifacts_only():
    arts = {
        DIGEST: art(ready=True),
        DIGEST_B: art(DIGEST_B, ready=True),
        DIGEST_C: art(DIGEST_C, ready=False, disp="HOLD_UNKNOWN"),
    }
    events = [ev(repos=0), ev(DIGEST_B, repos=1), ev(DIGEST_C, repos=5)]
    m = metrics.compute_metrics(events, arts)
    ro = m["repo_open"]
    assert ro["decision_ready_artifacts_reviewed"] == 2
    assert ro["artifacts_with_repo_opens"] == 1
    assert ro["repo_open_rate"] == 0.5
    # target measured on accepted artifacts only
    assert ro["repo_open_rate_accepted"] == 0.5
    assert m["human_contract_targets"]["repo_open_rate_accepted_decision_ready"]["met"] is False


def test_repo_open_rate_zero_when_clean():
    arts = {DIGEST: art()}
    m = metrics.compute_metrics([ev()], arts)
    assert m["repo_open"]["repo_open_rate"] == 0
    assert m["human_contract_targets"]["repo_open_rate_accepted_decision_ready"]["met"] is True


# -------------------------------------------------- missing_fact_rejection --

def test_missing_fact_rejection_rate():
    arts = {DIGEST: art(facts=["f1", "f2", "f3"])}
    events = [
        ev(facts=["f1"], accepted=False),      # unread 2 → rejected
        ev(facts=["f1", "f2"], accepted=True), # unread 1 → contract violation
        ev(facts=["f1", "f2", "f3"]),          # all read
    ]
    m = metrics.compute_metrics(events, arts)
    mf = m["missing_facts"]
    assert mf["events_with_unread_mandatory_facts"] == 2
    assert mf["missing_fact_rejection_rate"] == 0.5
    assert mf["accepted_with_unread_mandatory_facts"] == [DIGEST]
    assert m["human_contract_targets"]["accepted_with_unread_mandatory_facts"]["met"] is False


# ------------------------------------------------------------- environment --

def test_environment_metrics_and_branch_change():
    arts = {
        DIGEST: art(env=["deployment_perimeter"], truth=None),
        DIGEST_B: {**art(DIGEST_B, disp="ACCEPT_ENVIRONMENTAL_MITIGATION",
                         env=["deployment_perimeter"])},
    }
    events = [
        ev(answers=[{"variable": "deployment_perimeter", "value": "cluster"}],
           ini="B-UNKNOWN", sel="B-PERIMETER-CLUSTER-INTERNAL"),
        ev(DIGEST_B, answers=[{"variable": "deployment_perimeter", "value": "unknown"}],
           ini="B-UNKNOWN", sel="B-UNKNOWN"),
        ev(DIGEST_B),  # no answers: below the branch-pair denominator
    ]
    m = metrics.compute_metrics(events, arts)
    envm = m["environment"]
    assert envm["declared_questions_total"] == 3      # 1 declared per bound event
    assert envm["answers_total"] == 2
    assert envm["unknown_answers"] == 1
    assert envm["unknown_rate"] == 0.5
    bca = envm["branch_change_after_answer"]
    assert bca["answered_events_with_branch_pair"] == 2
    assert bca["branch_changes"] == 1
    # the only change is on a code_grounded artifact → falsification flag
    assert bca["branch_changes_on_code_grounded"] == 1
    assert m["stop_conditions"]["any"] is True


def test_branch_change_on_mitigation_is_not_a_stop():
    arts = {DIGEST: art(disp="ACCEPT_ENVIRONMENTAL_MITIGATION", env=["deployment_perimeter"])}
    events = [ev(answers=[{"variable": "deployment_perimeter", "value": "public"}],
                 ini="B-UNKNOWN", sel="B-PERIMETER-PUBLIC")]
    m = metrics.compute_metrics(events, arts)
    assert m["environment"]["branch_change_after_answer"]["branch_changes"] == 1
    assert m["environment"]["branch_change_after_answer"]["branch_changes_on_code_grounded"] == 0
    assert m["stop_conditions"]["any"] is False


# ------------------------------------------------------------- false safe --

def test_accepted_false_safe_is_a_stop_split_by_class():
    arts = {
        DIGEST: art(truth="exploitable"),                                  # close on exploitable
        DIGEST_B: art(DIGEST_B, disp="ACCEPT_ENVIRONMENTAL_MITIGATION",
                      truth="exploitable"),
        DIGEST_C: art(DIGEST_C, truth="not_exploitable"),                  # fine
    }
    events = [ev(), ev(DIGEST_B), ev(DIGEST_C)]
    m = metrics.compute_metrics(events, arts)
    fs = m["accepted_false_safe"]
    assert fs["total"] == 2
    assert fs["code_grounded"] == 1
    assert fs["environmental_mitigation"] == 1
    assert m["stop_conditions"]["any"] is True


def test_rejected_false_safe_does_not_stop():
    arts = {DIGEST: art(truth="exploitable")}
    m = metrics.compute_metrics([ev(accepted=False)], arts)
    assert m["accepted_false_safe"]["total"] == 0
    assert m["stop_conditions"]["any"] is False


def test_hold_unknown_is_never_safe():
    arts = {DIGEST: art(disp="HOLD_UNKNOWN", ready=False, truth="exploitable")}
    m = metrics.compute_metrics([ev()], arts)
    assert m["accepted_false_safe"]["total"] == 0


# ------------------------------------------------- reopen / rerun / followup

def test_reopen_rerun_followup_rates():
    arts = {DIGEST: art()}
    events = [
        ev(reopened=True, reruns=1, follow=1),
        ev(accepted=False, returned=True),
        ev(),
    ]
    m = metrics.compute_metrics(events, arts)
    rr = m["reopen_reversal"]
    assert rr["reopened_events"] == 1
    assert rr["reopen_rate_over_accepted"] == 0.5  # 2 accepted events
    assert rr["returned_for_remediation"] == 1
    assert m["human_rerun"]["events_with_tool_reruns"] == 1
    assert m["human_rerun"]["rate"] == 1 / 3
    assert m["technical_follow_up"]["accepted_with_follow_up"] == [DIGEST]


# ------------------------------------------------------------- model costs --

def test_model_accounting_per_case():
    recs = [
        {"case_id": "case-01", "execution": "live", "model_calls": 3, "elapsed_s": 310,
         "turns": [{"tokens": {"input": 1000, "output": 50, "reasoning": 10}, "cost": 0.4},
                   {"tokens": {"input": 500, "output": 20, "reasoning": 0}, "cost": 0.2},
                   {"tokens": {"input": 700, "output": 30, "reasoning": 5}, "cost": 0.3}]},
        {"case_id": "case-02", "execution": "replay", "model_calls": 0, "elapsed_s": 40,
         "turns": [{"role": "plan", "status": "OK"}]},  # retained dir without result.json
        {"case_id": "case-03", "execution": "deterministic_only", "model_calls": 0,
         "elapsed_s": 6, "turns": []},
    ]
    m = metrics.compute_metrics([], {}, recs)
    mo = m["model"]
    assert mo["calls_total"] == 3
    assert mo["live_runs"] == 1 and mo["replayed_runs"] == 1 and mo["deterministic_only_runs"] == 1
    assert mo["tokens_input"] == 2200 and mo["tokens_output"] == 100
    assert abs(mo["cost_total"] - 0.9) < 1e-9
    assert mo["cost_known_cases"] == 1
    assert abs(mo["per_case"]["case-01"]["cost"] - 0.9) < 1e-9
    assert mo["per_case"]["case-02"]["cost"] is None


def test_unbound_events_are_counted_not_dropped():
    m = metrics.compute_metrics([ev()], {})
    assert m["inputs"]["events_total"] == 1
    assert m["inputs"]["events_unbound_artifact"] == 1
    assert m["unbound_artifact_digests"] == [DIGEST]
    assert m["artifacts"]["decision_ready"] == 0


def test_no_events_measured_flag():
    m = metrics.compute_metrics([], {})
    assert m["inputs"]["measured"] is False
    assert m["repo_open"]["repo_open_rate"] is None
    assert m["human_contract_targets"]["median_decision_time_s"]["met"] is None



def test_review_timing_must_not_infer_from_package():
    # Event without valid review start/finish cannot infer timing from artifact creation
    bad_ev = ev(start=None, finish=None)
    del bad_ev["started_at"]
    del bad_ev["finished_at"]
    arts = {DIGEST: art()}
    m = metrics.compute_metrics([bad_ev], arts)
    assert m["inputs"]["events_invalid"] == 1
    assert m["human_decision_time_seconds"]["overall"]["n"] == 0


def test_duplicate_review_events_rejected_or_flagged():
    # Multiple review events for the same reviewer session on the same package hash
    ev1 = ev(digest=DIGEST)
    ev1["reviewer_session"] = "reviewer-1"
    ev2 = ev(digest=DIGEST)
    ev2["reviewer_session"] = "reviewer-1"
    arts = {DIGEST: art()}
    m = metrics.compute_metrics([ev1, ev2], arts)
    assert m.get("duplicate_review_events_count", 0) > 0 or len(m.get("invalid_events", [])) > 0


def test_foreign_package_hashes_rejected():
    # Event referencing a foreign package hash not in the artifact index
    foreign_digest = "sha256:" + "f" * 64
    foreign_ev = ev(digest=foreign_digest)
    arts = {DIGEST: art()}
    m = metrics.compute_metrics([foreign_ev], arts)
    assert foreign_digest in m["unbound_artifact_digests"]
    assert m["inputs"]["events_unbound_artifact"] == 1
    assert m["stop_conditions"].get("foreign_package_events", 0) > 0



#!/usr/bin/env python3
"""Synthetic fixture tests for eval/vexbench_plain_report.py.

Run:  python3 -m unittest eval.vexbench_plain_report_test -v
or:   python3 eval/vexbench_plain_report_test.py

Every fixture is synthetic — no real VEX-Bench tasks, no network, no
docker, no model calls.
"""
import json
import os
import statistics
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vexbench_plain_report as vpr  # noqa: E402

GT30 = (["vulnerable"] * 7 + ["code_not_reachable"] * 18
        + ["code_not_present"] * 3 + ["requires_configuration"] * 2)
TASKS = [f"task-{i:02d}" for i in range(30)]


def task_gt(i):
    return TASKS[i], GT30[i]


def row(i, run_id, cat=None, status="ok", tokens="full", cost=None,
        steps=5, gt=None):
    tid, gt_cat = task_gt(i)
    if gt:
        gt_cat = gt
    gt = "exploitable" if gt_cat == "vulnerable" else "not_exploitable"
    r = {
        "task_id": tid, "run_id": run_id, "cve_id": "CVE-9999-1",
        "ground_truth": gt, "ground_truth_category": gt_cat,
        "predicted": ("exploitable" if cat == "vulnerable"
                      else "not_exploitable" if cat else None),
        "predicted_category": cat,
        "reasoning": "synthetic", "status": status,
        "steps": steps, "completed": status == "ok",
        "cost_usd": cost,
    }
    vals = {"input_tokens": 10, "cached_input_tokens": 5,
            "cache_write_tokens": 1, "output_tokens": 3,
            "reasoning_tokens": 2}
    for f in vpr.TOKEN_FIELDS:
        r[f] = vals[f] if tokens == "full" else None
    return r


def corpus(run_id, pred, tokens="full", cost=None):
    """30-row repeat. pred(i) -> (category, status) or category."""
    rows = []
    for i in range(30):
        p = pred(i)
        if isinstance(p, tuple):
            cat, status = p
        else:
            cat, status = p, "ok"
        rows.append(row(i, run_id, cat=cat, status=status,
                        tokens=tokens, cost=cost))
    return rows


def all_safe(i):
    return "code_not_reachable" if i >= 7 else "code_not_reachable"


def write_jsonl(path, rows):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


def write_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f)


def make_baseline(root):
    """Frozen Baseline 1 analogue: metrics + compat + scoring/cases."""
    write_json(os.path.join(root, "metrics.json"), {
        "schema": "vexbench-safety-aware/1",
        "false_safe": 1, "correct_safe": 10, "correct_exploitable": 2,
        "abstain": 12, "failed": 2,
        "denominators": {"total": 30, "gt_exploitable": 7, "gt_safe": 23},
        "false_safe_rate": 1 / 7,
        "safe_clear_rate": 10 / 23,
        "exploitable_recall": 2 / 7,
        "inconclusive_rate": 12 / 30,
        "completion_rate": 28 / 30,
        "safety_aware_status": {"precision": 0.4, "recall": 2 / 7,
                                "f1": 0.333333, "tp": 2, "fp": 3,
                                "fn": 5},
        "usage": {"llm_calls": 0, "tool_calls": 6, "tokens": None},
        "wall_seconds": {"total": 12018.794, "mean": 429.243,
                         "p95": 1283.4},
    })
    write_json(os.path.join(root, "compatibility-metrics.json"), {
        "accuracy": 2 / 3, "binary_precision": 0.4,
        "binary_recall": 2 / 7, "binary_f1": 1 / 3,
        "justification_macro_f1": 0.225845,
        "confusion_matrix": {"rows": {"vulnerable": {"FAILED": 0}}},
    })
    cases = []
    for i in range(30):
        tid, gt_cat = task_gt(i)
        cases.append({
            "task_id": tid, "cve_id": "CVE-9999-1",
            "verdict": "INCONCLUSIVE" if i % 3 else "EXPLOITABLE",
            "compatibility_category": gt_cat,
            "scoring_outcome": ("correct_exploitable"
                                if gt_cat == "vulnerable" and i % 3 == 0
                                else "abstain"),
            "status_correct": True, "reason_correct": True,
            "ground_truth": ("exploitable" if gt_cat == "vulnerable"
                             else "not_exploitable"),
            "ground_truth_category": gt_cat,
            "wall_seconds": 100.0 + i, "llm_calls": 0,
            "tool_calls": 0, "integrity_note": None,
        })
    write_jsonl(os.path.join(root, "scoring", "cases.jsonl"), cases)


def official_metrics_stub(rows):
    """Minimal official metrics.json shape for consistency checks."""
    return {"binary": {"accuracy": {"mean": None, "std": None},
                       "precision": {"mean": None, "std": None},
                       "recall": {"mean": None, "std": None},
                       "f1": {"mean": None, "std": None},
                       "totals": {"tp": 0, "fp": 0, "tn": 0, "fn": 0,
                                  "failed": 0}},
            "multiclass": {"macro_f1": {"mean": None, "std": None}},
            "completion": {"total": len(rows)}, "n_runs": 1}


def run_report(tmp, rows, *, events=None, run_log=None, provenance=None,
               raw=None):
    exp = os.path.join(tmp, "exp")
    parsed = os.path.join(exp, "vex_bench", "parsed.jsonl")
    write_jsonl(parsed, rows)
    metrics = os.path.join(exp, "vex_bench", "metrics.json")
    write_json(metrics, official_metrics_stub(rows))
    baseline = os.path.join(tmp, "baseline-1")
    make_baseline(baseline)
    out = os.path.join(tmp, "report")
    raw_root = raw or exp
    kw = {}
    if events is not None:
        write_jsonl(os.path.join(tmp, "events.jsonl"), events)
        kw["docker_events_path"] = os.path.join(tmp, "events.jsonl")
    else:
        kw["docker_events_path"] = None
    if run_log is not None:
        lp = os.path.join(tmp, "run.log")
        with open(lp, "w", encoding="utf-8") as f:
            f.write(run_log)
        kw["run_log_path"] = lp
    else:
        kw["run_log_path"] = None
    if provenance is not None:
        pp = os.path.join(tmp, "provenance.json")
        write_json(pp, provenance)
        kw["provenance_path"] = pp
    else:
        kw["provenance_path"] = None
    rc = vpr.report(parsed_path=parsed, official_metrics_path=metrics,
                    raw_root=raw_root, baseline_dir=baseline,
                    out_dir=out, **kw)
    assert rc == 0
    def jload(name):
        with open(os.path.join(out, name), encoding="utf-8") as f:
            return json.load(f)
    with open(os.path.join(out, "comparison.md"),
              encoding="utf-8") as f:
        comparison = f.read()
    with open(os.path.join(out, "safety-cases.jsonl"),
              encoding="utf-8") as f:
        case_rows = [json.loads(l) for l in f if l.strip()]
    return {
        "metrics": jload("safety-metrics.json"),
        "telemetry": jload("telemetry.json"),
        "comparison": comparison,
        "cases": case_rows,
        "checksums": jload("freeze-checksums.json"),
        "out": out, "baseline": baseline,
    }


def safety_outcome_rows(tmp, rows):
    res = run_report(tmp, rows)
    return res["metrics"]


class SafetyOutcomeTests(unittest.TestCase):
    def test_outcome_classification(self):
        self.assertEqual(vpr.safety_outcome("ok", "vulnerable"),
                         "positive")
        self.assertEqual(vpr.safety_outcome("ok", "uncertain"), "abstain")
        for cat in vpr.SAFE_CATEGORIES:
            self.assertEqual(vpr.safety_outcome("ok", cat), "safe", cat)
        for status in ("parse_fail", "no_result", "no_dir", None):
            self.assertEqual(vpr.safety_outcome(status, "vulnerable"),
                             "failed", status)
        self.assertEqual(vpr.safety_outcome("ok", "bogus"), "failed")
        self.assertEqual(vpr.safety_outcome("ok", None), "failed")

    def test_compat_uncertain_is_negative(self):
        self.assertEqual(vpr.compat_prediction("ok", "uncertain"),
                         "not_exploitable")
        self.assertEqual(vpr.compat_prediction("ok", "bogus"), "FAILED")
        self.assertEqual(vpr.compat_prediction("parse_fail", "vulnerable"),
                         "FAILED")

    def test_uncertain_on_vulnerable_not_false_safe(self):
        with tempfile.TemporaryDirectory() as tmp:
            rows = corpus("run_001",
                          lambda i: "uncertain" if i < 7
                          else "code_not_reachable")
            m = safety_outcome_rows(tmp, rows)["per_repeat"]["run_001"]
            self.assertEqual(m["false_safe_count"], 0)
            self.assertEqual(m["outcomes"]["abstain"], 7)
            self.assertEqual(m["confusion"]["abstain"]["gt_exploitable"], 7)
            self.assertEqual(m["exploitable_recall"], 0.0)
            self.assertEqual(m["fn"], 7)
            self.assertEqual(m["fn_breakdown"]["abstain"], 7)

    def test_safe_on_vulnerable_is_false_safe(self):
        with tempfile.TemporaryDirectory() as tmp:
            rows = corpus("run_001",
                          lambda i: "vulnerable" if i in (1, 2, 3, 4, 5, 6)
                          else "code_not_reachable")
            m = safety_outcome_rows(tmp, rows)["per_repeat"]["run_001"]
            self.assertEqual(m["false_safe_count"], 1)
            self.assertEqual(m["false_safe_ids"], ["task-00"])
            self.assertAlmostEqual(m["false_safe_rate"], 1 / 7)
            self.assertEqual(m["confusion"]["safe"]["gt_exploitable"], 1)

    def test_uncertain_on_negative_not_correct_safe(self):
        with tempfile.TemporaryDirectory() as tmp:
            # one negative task abstains; rest claim safe
            rows = corpus("run_001",
                          lambda i: "vulnerable" if i < 7 else
                          ("uncertain" if i == 10 else
                           "code_not_reachable"))
            m = safety_outcome_rows(tmp, rows)["per_repeat"]["run_001"]
            self.assertEqual(m["outcomes"]["abstain"], 1)
            self.assertEqual(m["safe_clear_count"], 22)
            self.assertAlmostEqual(m["safe_clear_rate"], 22 / 23)
            self.assertEqual(m["status_correct_count"], 7 + 22)

    def test_failed_is_fn_and_not_completed(self):
        with tempfile.TemporaryDirectory() as tmp:
            def pred(i):
                if i == 0:
                    return (None, "no_result")
                return "vulnerable" if i < 7 else "code_not_reachable"
            rows = corpus("run_001", pred)
            m = safety_outcome_rows(tmp, rows)["per_repeat"]["run_001"]
            self.assertEqual(m["outcomes"]["failed"], 1)
            self.assertEqual(m["tp"], 6)
            self.assertEqual(m["fn"], 1)
            self.assertEqual(m["fn_breakdown"]["failed"], 1)
            self.assertEqual(m["fn_breakdown"]["safe"], 0)
            self.assertAlmostEqual(m["completion_rate"], 29 / 30)
            self.assertEqual(m["false_safe_count"], 0)

    def test_invalid_category_is_failed(self):
        with tempfile.TemporaryDirectory() as tmp:
            def pred(i):
                if i == 0:
                    return ("definitely_safe", "ok")
                return "vulnerable" if i < 7 else "code_not_reachable"
            rows = corpus("run_001", pred)
            m = safety_outcome_rows(tmp, rows)["per_repeat"]["run_001"]
            self.assertEqual(m["outcomes"]["failed"], 1)
            self.assertEqual(m["confusion"]["failed"]["gt_exploitable"], 1)
            self.assertEqual(m["fn"], 1)


class RepeatAggregationTests(unittest.TestCase):
    def test_three_repeats_same_id_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            rows = []
            for r in ("run_001", "run_002", "run_003"):
                rows += corpus(r, lambda i: "vulnerable" if i < 7
                               else "code_not_reachable")
            m = safety_outcome_rows(tmp, rows)
            self.assertEqual(m["n_repeats"], 3)
            self.assertTrue(m["aggregate"]["task_id_sets_identical"])
            for rid in ("run_001", "run_002", "run_003"):
                self.assertEqual(m["per_repeat"][rid]["rows"], 30)

    def test_stdev_ddof1(self):
        with tempfile.TemporaryDirectory() as tmp:
            # TP = 1, 2, 4 -> recalls 1/7, 2/7, 4/7
            rows = []
            for run_id, hit in (("run_001", {0}),
                                ("run_002", {0, 1}),
                                ("run_003", {0, 1, 2, 3})):
                rows += corpus(run_id,
                               lambda i, h=hit: "vulnerable" if i in h
                               else "code_not_reachable")
            m = safety_outcome_rows(tmp, rows)
            vals = [1 / 7, 2 / 7, 4 / 7]
            agg = m["aggregate"]["exploitable_recall"]
            self.assertAlmostEqual(agg["mean"], statistics.mean(vals))
            self.assertAlmostEqual(agg["std"], statistics.stdev(vals))
            self.assertNotAlmostEqual(agg["std"], statistics.pstdev(vals))

    def test_pooled_f1_differs_from_repeat_mean(self):
        with tempfile.TemporaryDirectory() as tmp:
            rows = (corpus("run_001", lambda i: "vulnerable" if i < 7
                           else "code_not_reachable")
                    + corpus("run_002", lambda i: "code_not_reachable"))
            m = safety_outcome_rows(tmp, rows)
            mean_f1 = m["aggregate"]["status_f1"]["mean"]
            pooled_f1 = m["pooled"]["status_f1"]
            self.assertAlmostEqual(mean_f1, 0.5)
            self.assertAlmostEqual(pooled_f1, 2 / 3)
            self.assertNotAlmostEqual(mean_f1, pooled_f1)
            self.assertIn("secondary", m["pooled"]["note"])

    def test_false_safe_aggregation(self):
        with tempfile.TemporaryDirectory() as tmp:
            rows = (corpus("run_001",
                           lambda i: "vulnerable" if i < 7
                           else "code_not_reachable")
                    + corpus("run_002",
                             lambda i: "vulnerable" if i < 7
                             else "code_not_reachable"))
            # task-00 safe in both repeats; task-01 safe in run_002 only
            for r in rows:
                if r["task_id"] == "task-00":
                    r["predicted_category"] = "code_not_reachable"
                    r["predicted"] = "not_exploitable"
                if r["task_id"] == "task-01" and r["run_id"] == "run_002":
                    r["predicted_category"] = "code_not_reachable"
                    r["predicted"] = "not_exploitable"
            m = safety_outcome_rows(tmp, rows)
            fs = m["aggregate"]["false_safe"]
            self.assertEqual(fs["per_repeat_counts"],
                             {"run_001": 1, "run_002": 2})
            self.assertEqual(fs["total_count"], 3)
            self.assertEqual(fs["attempts"], 60)
            self.assertEqual(fs["unique_case_ids"],
                             ["task-00", "task-01"])
            self.assertAlmostEqual(fs["mean"], 1.5)
            self.assertAlmostEqual(fs["std"], statistics.stdev([1, 2]))

    def test_differing_repeat_task_sets_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            rows = corpus("run_001", all_safe)
            rows += corpus("run_002", all_safe)[:-1]
            m = safety_outcome_rows(tmp, rows)
            self.assertFalse(m["aggregate"]["task_id_sets_identical"])
            self.assertEqual(m["per_repeat"]["run_002"]["rows"], 29)


class CompatibilityTests(unittest.TestCase):
    def test_macro_f1_gt_present_classes_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            # positives all correct; code_not_reachable GT rows predicted
            # as compiler_protected (not a GT-present class)
            def pred(i):
                if i < 7:
                    return "vulnerable"
                if i < 25:
                    return "compiler_protected"
                return GT30[i]
            rows = corpus("run_001", pred)
            m = safety_outcome_rows(tmp, rows)
            run = m["compatibility"]["per_repeat"]["run_001"]
            self.assertEqual(sorted(run["gt_classes"]),
                             sorted(set(GT30)))
            self.assertEqual(len(run["per_class"]), 4)
            self.assertAlmostEqual(run["justification_macro_f1"], 0.75)

    def test_official_fn_split_excludes_failed(self):
        with tempfile.TemporaryDirectory() as tmp:
            # task-00: GT vulnerable -> FAILED; task-01: vulnerable ->
            # not_exploitable; rest correct
            def pred(i):
                if i == 0:
                    return (None, "no_result")
                if i == 1:
                    return "code_not_reachable"
                return "vulnerable" if i < 7 else "code_not_reachable"
            rows = corpus("run_001", pred)
            m = safety_outcome_rows(tmp, rows)
            run = m["compatibility"]["per_repeat"]["run_001"]
            self.assertEqual(run["fn_predicted_negative"], 1)
            self.assertEqual(run["fn_failed"], 1)
            self.assertEqual(run["failed"], 1)
            # scalar recall charges both: tp=5, fn total=2 -> 5/7
            self.assertAlmostEqual(run["recall"], 5 / 7)
            self.assertIn("totals.fn",
                          m["compatibility"]["totals_fn_note"])

    def test_uncertain_two_column_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            rows = corpus("run_001",
                          lambda i: "uncertain" if i in (0, 10)
                          else "vulnerable" if i < 7
                          else "code_not_reachable")
            m = safety_outcome_rows(tmp, rows)
            up = m["uncertain_policy"]
            self.assertEqual(up["uncertain_rows"]["total"], 2)
            self.assertEqual(up["official_compatibility_negative"], 2)
            self.assertEqual(up["safety_abstain"], 2)
            self.assertIn("not a disagreement", up["note"])

    def test_failed_never_successful_negative(self):
        with tempfile.TemporaryDirectory() as tmp:
            # every negative row fails -> tn must stay 0
            rows = corpus("run_001",
                          lambda i: "vulnerable" if i < 7
                          else (None, "parse_fail"))
            m = safety_outcome_rows(tmp, rows)
            run = m["compatibility"]["per_repeat"]["run_001"]
            self.assertEqual(run["tn"], 0)
            self.assertEqual(run["failed"], 23)
            self.assertEqual(run["fp"], 0)

    def test_failed_uncertain_is_not_abstain(self):
        with tempfile.TemporaryDirectory() as tmp:
            rows = corpus("run_001",
                          lambda i: "uncertain" if i == 0
                          else "vulnerable" if i < 7
                          else "code_not_reachable")
            # task-10 keeps the uncertain label but failed to parse:
            # safety outcome must be failed, not abstain / compat negative
            rows[10]["status"] = "parse_fail"
            rows[10]["predicted_category"] = "uncertain"
            rows[10]["predicted"] = None
            m = safety_outcome_rows(tmp, rows)
            run = m["per_repeat"]["run_001"]
            self.assertEqual(run["outcomes"]["abstain"], 1)
            self.assertEqual(run["outcomes"]["failed"], 1)
            self.assertEqual(
                m["uncertain_policy"]["uncertain_rows"]["total"], 1)
            self.assertEqual(
                m["compatibility"]["per_repeat"]["run_001"]["failed"], 1)



class TelemetryTests(unittest.TestCase):
    def test_missing_tokens_cost_unavailable_not_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            rows = corpus("run_001", all_safe, tokens="none", cost=None)
            res = run_report(tmp, rows)
            tok = res["telemetry"]["tokens"]
            self.assertEqual(tok["coverage"]["state"], "unavailable")
            for f in vpr.TOKEN_FIELDS:
                self.assertIsNone(tok["totals"][f])
                self.assertIsNone(tok["per_case_mean"][f])
                self.assertEqual(tok["coverage"]["by_bucket"][f]
                                 ["observed"], 0)
            est = res["telemetry"]["cost"]["official_estimate"]
            self.assertEqual(est["coverage"]["state"], "unavailable")
            self.assertIsNone(est["total_usd"])
            self.assertEqual(est["priced_cases"], 0)
            inv = res["telemetry"]["cost"]["invoice"]
            self.assertEqual(inv["coverage"], "unavailable")

    def test_partial_token_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            rows = corpus("run_001", all_safe, tokens="full",
                          cost=0.01)
            for r in rows[:15]:
                for f in vpr.TOKEN_FIELDS:
                    r[f] = None
                r["cost_usd"] = None
            res = run_report(tmp, rows)
            tok = res["telemetry"]["tokens"]
            self.assertEqual(tok["coverage"]["state"], "partial")
            self.assertEqual(tok["coverage"]["by_bucket"]
                             ["input_tokens"]["observed"], 15)
            self.assertEqual(tok["totals"]["input_tokens"], 15 * 10)
            self.assertEqual(tok["totals"]["reasoning_tokens"], 15 * 2)
            est = res["telemetry"]["cost"]["official_estimate"]
            self.assertEqual(est["coverage"]["state"], "partial")
            self.assertAlmostEqual(est["total_usd"], 15 * 0.01)

    def test_no_optional_inputs_marks_unavailable(self):
        with tempfile.TemporaryDirectory() as tmp:
            res = run_report(tmp, corpus("run_001", all_safe))
            t = res["telemetry"]["time"]
            self.assertEqual(t["container_wall"]["coverage"]["state"],
                             "unavailable")
            self.assertEqual(t["run_log"]["coverage"], "unavailable")
            self.assertIn("N/A", res["comparison"])
            # tools: raw_root exists but has no result.jsonl -> unavailable
            self.assertEqual(res["telemetry"]["tool_calls"]["coverage"]
                             ["state"], "unavailable")

    def test_tool_items_from_raw(self):
        with tempfile.TemporaryDirectory() as tmp:
            exp = os.path.join(tmp, "exp")
            raw_dir = os.path.join(exp, "task-00", "run_001")
            os.makedirs(raw_dir)
            events = [
                {"type": "item.completed",
                 "item": {"type": "command_execution"}},
                {"type": "item.completed",
                 "item": {"type": "command_execution"}},
                {"type": "item.completed", "item": {"type": "web_search"}},
                {"type": "item.completed",
                 "item": {"type": "agent_message"}},
                {"type": "item.completed", "item": {"type": "mystery"}},
                {"type": "item.completed", "item": {}},
                {"type": "turn.completed"},
            ]
            write_jsonl(os.path.join(raw_dir, "result.jsonl"), events)
            res = run_report(tmp, corpus("run_001", all_safe), raw=exp)
            tel = res["telemetry"]["tool_calls"]
            cov = tel["coverage"]
            self.assertEqual(cov["state"], "partial")  # 1 of 30 covered
            self.assertEqual(cov["covered"], 1)
            pa = tel["per_attempt"]["task-00/run_001"]
            self.assertEqual(pa["command_execution"], 2)
            self.assertEqual(pa["web_search"], 1)
            self.assertEqual(pa["other_items"], 3)  # agent+ mystery+untyped
            self.assertEqual(pa["untyped_items"], 1)
            self.assertIn("mystery", pa["new_item_types"])
            self.assertTrue(tel["limitations"])

    def test_docker_events_and_run_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            rows = corpus("run_001", all_safe)
            base_ns = 1_700_000_000_000_000_000
            events = []
            for i in range(30):
                cid = f"c{i:02d}"
                for action, off in (("create", 0), ("start", 1),
                                    ("die", 10), ("destroy", 11)):
                    events.append({
                        "Type": "container", "Action": action,
                        "Actor": {"ID": cid,
                                  "Attributes": {"name": cid,
                                                 "image": "vex"}},
                        "timeNano": str(base_ns + (i * 60 + off)
                                        * 1_000_000_000),
                    })
            log_lines = []
            for i in range(30):
                # ISO-Z markers 5s before each create
                ts = _iso_z(base_ns + (i * 60 - 5) * 1_000_000_000)
                log_lines.append(
                    f"{ts} INFO evaluate.run: "
                    f"[task-{i:02d}/run_001] [RUN] src=/x lang=go")
            res = run_report(tmp, rows, events=events,
                             run_log="\n".join(log_lines) + "\n")
            wall = res["telemetry"]["time"]["container_wall"]
            self.assertEqual(wall["coverage"]["state"], "full")
            self.assertEqual(wall["coverage"]["covered"], 30)
            self.assertEqual(wall["matching"],
                             "timestamp_preceding_marker")
            self.assertAlmostEqual(
                wall["per_attempt_seconds"]["task-00/run_001"], 11.0)
            ex = res["telemetry"]["time"]["exec_window"]
            self.assertAlmostEqual(
                ex["per_attempt_seconds"]["task-05/run_001"], 9.0)

    def test_docker_events_without_log_unpaired(self):
        with tempfile.TemporaryDirectory() as tmp:
            rows = corpus("run_001", all_safe)
            events = [{
                "Type": "container", "Action": a,
                "Actor": {"ID": "cx", "Attributes": {}},
                "timeNano": str(1_700_000_000_000_000_000
                                + off * 1_000_000_000)}
                for a, off in (("create", 0), ("destroy", 5))]
            res = run_report(tmp, rows, events=events)
            wall = res["telemetry"]["time"]["container_wall"]
            self.assertEqual(wall["matching"], "no_markers")
            self.assertEqual(wall["coverage"]["covered"], 0)
            self.assertEqual(wall["containers_observed"], 1)
            # unassigned container stats still visible, not zeroed
            self.assertAlmostEqual(
                wall["unassigned_container_mean_seconds"], 5.0)

    def test_invoice_from_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            prov = {"billing": {"total_usd": 12.34}}
            res = run_report(tmp, corpus("run_001", all_safe, cost=0.01),
                             provenance=prov)
            inv = res["telemetry"]["cost"]["invoice"]
            self.assertEqual(inv["coverage"], "available")
            est = res["telemetry"]["cost"]["official_estimate"]
            self.assertEqual(est["coverage"]["state"], "full")
            self.assertAlmostEqual(est["total_usd"], 30 * 0.01)


class BaselineAndOutputTests(unittest.TestCase):
    def test_baseline_readonly_and_pairing(self):
        with tempfile.TemporaryDirectory() as tmp:
            rows = corpus("run_001", all_safe)
            res = run_report(tmp, rows)
            pairing = res["metrics"]["pairing_vs_baseline"]["run_001"]
            self.assertEqual(len(pairing), 30)
            self.assertTrue(all(p["a_case_present"] for p in pairing))
            # baseline files unchanged
            mpath = os.path.join(res["baseline"], "metrics.json")
            self.assertTrue(os.path.isfile(mpath))
            with open(mpath, encoding="utf-8") as f:
                m = json.load(f)
            self.assertEqual(m["false_safe"], 1)
            # A column rendered from frozen metrics
            self.assertIn("Current Izyan", res["comparison"])
            self.assertIn("10/23", res["comparison"])
            self.assertIn("not run", res["comparison"])

    def test_smoke_shape_partial_denominators(self):
        with tempfile.TemporaryDirectory() as tmp:
            rows = [row(0, "run_001", cat="vulnerable"),
                    row(8, "run_001", cat="code_not_reachable")]
            res = run_report(tmp, rows)
            m = res["metrics"]
            self.assertEqual(m["n_repeats"], 1)
            pr = m["per_repeat"]["run_001"]
            self.assertEqual(pr["rows"], 2)
            self.assertEqual(pr["gt_exploitable"], 1)
            self.assertEqual(pr["gt_non_exploitable"], 1)
            obs = m["denominators"]["observed_per_repeat"]["run_001"]
            self.assertEqual(obs["total"], 2)
            self.assertEqual(m["denominators"]
                             ["expected_full_dataset"]["total"], 30)
            self.assertIn("partial", res["comparison"])

    def test_outputs_and_checksums(self):
        with tempfile.TemporaryDirectory() as tmp:
            res = run_report(tmp, corpus("run_001", all_safe))
            out = res["out"]
            for name in ("safety-cases.jsonl", "safety-metrics.json",
                         "telemetry.json", "comparison.md",
                         "freeze-checksums.json"):
                self.assertTrue(os.path.isfile(
                    os.path.join(out, name)), name)
            self.assertEqual(len(res["cases"]), 30)
            c0 = res["cases"][0]
            for key in ("task_id", "run_id", "safety_outcome",
                        "compat_prediction", "status_correct",
                        "reason_correct", "ground_truth"):
                self.assertIn(key, c0)
            for name, info in res["checksums"]["outputs"].items():
                p = os.path.join(out, name)
                self.assertEqual(info["sha256"], vpr.sha256_file(p))
            self.assertEqual(res["checksums"]["inputs"]["run_log"]
                             ["sha256"], None)

    def test_reason_correct_requires_category_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            # task-08 GT code_not_reachable predicted code_not_present:
            # safe (status correct) but reason wrong
            def pred(i):
                if i < 7:
                    return "vulnerable"
                if i == 8:
                    return "code_not_present"
                return GT30[i]
            res = run_report(tmp, corpus("run_001", pred))
            m = res["metrics"]["per_repeat"]["run_001"]
            case = [c for c in res["cases"]
                    if c["task_id"] == "task-08"][0]
            self.assertTrue(case["status_correct"])
            self.assertFalse(case["reason_correct"])
            self.assertEqual(m["status_correct_count"], 30)
            self.assertEqual(m["reason_correct_count"], 29)


def _iso_z(ns):
    import datetime
    return datetime.datetime.fromtimestamp(
        ns / 1e9, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


if __name__ == "__main__":
    unittest.main()

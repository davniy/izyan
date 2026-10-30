"""Unit tests for eval/c1/report.py — offline scoring + audit.

Run: /tmp/vexbench-agent-ctl/.venv/bin/python -m unittest \\
    eval.c1.report_test -v

Synthetic fixtures only — no harness, no model calls, no docker.
``run_report`` is exercised with an injected ``row_builder`` and a stub
``compute_metrics`` so the pipeline logic (failure classes, stability,
audit projection, pairing, artifact writing) is tested without
evaluate.* imports; byte-level parity with the official parser/scorer is
a separate dry-run check on the frozen B1 cohort.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from eval.c1 import parser_audit  # noqa: E402
from eval.c1 import report as R  # noqa: E402

# --- official-parser stand-in (same contract as result_parser.parse_category;
# deliberately brace-naive so audit/official divergence is exercisable) -------

_BRACE_OK = None


def _official_extract(text):
    """Replica of the official brace-count defect for fixtures."""
    stripped = text.strip()
    if stripped.startswith("{"):
        try:
            return json.loads(stripped)
        except json.JSONDecodeError:
            pass
    depth = 0
    start = -1
    for i, ch in enumerate(stripped):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start >= 0:
                try:
                    return json.loads(stripped[start:i + 1])
                except json.JSONDecodeError:
                    start = -1
    return None


def official_parse(text):
    obj = _official_extract(text)
    if not isinstance(obj, dict):
        return None, None
    cat = obj.get("category")
    if not isinstance(cat, str) or cat.lower() not in \
            parser_audit.VALID_CATEGORIES:
        return None, None
    return cat.lower(), obj.get("reasoning")


def make_ndjson(*texts):
    events = []
    for t in texts:
        events.append({"type": "item.completed",
                       "item": {"type": "agent_message", "text": t}})
    events.append({"type": "turn.completed", "usage": {}})
    return "\n".join(json.dumps(e) for e in events)


def make_export(terminal_text, earlier_texts=()):
    """opencode export JSON payload — earlier assistant turns carry
    ``earlier_texts``, the last one ends with the terminal text part."""
    messages = [{"info": {"role": "user"}, "parts": [
        {"type": "text", "text": "solve the CVE"}]}]
    for t in earlier_texts:
        messages.append({"info": {"role": "assistant"},
                         "parts": [{"type": "text", "text": t}]})
    messages.append({"info": {"role": "assistant"}, "parts": [
        {"type": "reasoning", "text": "thinking…"},
        {"type": "text", "text": terminal_text}]})
    return json.dumps({"info": {"id": "ses"}, "messages": messages})

def final_json(category, reasoning="reasoned"):
    return json.dumps({"category": category, "reasoning": reasoning})

GT = {"t-pos": "vulnerable", "t-neg": "code_not_reachable",
      "t-cfg": "requires_configuration"}
TASKS = [
    {"task_id": t, "cve_id": "CVE-0000-1",
     "ground_truth": "exploitable" if g == "vulnerable"
     else "not_exploitable",
     "ground_truth_category": g}
    for t, g in GT.items()]


def fake_row_builder(run_root, extractor=parser_audit.codex_terminal_text,
                     result_filename="result.jsonl"):
    """Official-shaped row builder for fixtures (mirrors _parse_run's
    status contract, not its exact stats handling). ``extractor`` stands
    in for the agent's ``extract_text`` — the audit path under test is
    chosen independently by ``agent_name``."""
    run_root = Path(run_root)

    def _one(task, rep):
        tid, run_id = task["task_id"], f"run_{rep:03d}"
        row = {"task_id": tid, "run_id": run_id, "cve_id": task["cve_id"],
               "ground_truth": task["ground_truth"],
               "ground_truth_category": task["ground_truth_category"],
               "predicted": None, "predicted_category": None,
               "reasoning": None, "status": "ok",
               "steps": None, "completed": None,
               "input_tokens": None, "cached_input_tokens": None,
               "cache_write_tokens": None, "output_tokens": None,
               "reasoning_tokens": None, "cost_usd": None}
        d = run_root / tid / run_id
        res = d / result_filename
        if not res.exists():
            row["status"] = "no_dir" if not d.exists() else "no_result"
            return row
        text = extractor(res.read_text(encoding="utf-8",
                                       errors="replace"))
        cat, reasoning = official_parse(text)
        if cat is None:
            row["status"] = "parse_fail"
            return row
        row.update({"predicted": parser_audit.category_to_binary(cat),
                    "predicted_category": cat, "reasoning": reasoning})
        return row

    return _one


def stub_compute_metrics(rows):
    """Deterministic placeholder — the real evaluate.metrics.compute_metrics
    is exercised separately by the frozen-B1 reproduction run."""
    n = len(rows)
    ok = sum(1 for r in rows if r.get("status") == "ok")
    return {"binary": {"accuracy": {"mean": ok / n if n else 0.0},
                       "precision": {"mean": 0.0}, "recall": {"mean": 0.0},
                       "f1": {"mean": 0.0}, "totals": {"fn": 0}},
            "multiclass": {"macro_f1": {"mean": 0.0}},
            "completion": {"answered": ok, "total": n}, "n_runs": 3}


class DeriveCaseTest(unittest.TestCase):
    """FAILED / uncertain / negative stay three different things (§9)."""

    def _row(self, status, cat):
        return {"task_id": "t", "run_id": "run_001", "cve_id": "CVE-1",
                "ground_truth": "exploitable",
                "ground_truth_category": "vulnerable",
                "status": status, "predicted_category": cat,
                "predicted": parser_audit.category_to_binary(cat),
                "reasoning": "r"}

    def test_failed_is_not_uncertain_not_negative(self):
        failed = R.derive_case(self._row("parse_fail", None))
        abstain = R.derive_case(self._row("ok", "uncertain"))
        safe = R.derive_case(self._row("ok", "code_not_reachable"))
        self.assertEqual(failed["safety_outcome"], "failed")
        self.assertEqual(abstain["safety_outcome"], "abstain")
        self.assertEqual(safe["safety_outcome"], "safe")
        self.assertEqual(failed["compat_prediction"], "FAILED")
        self.assertEqual(abstain["compat_prediction"], "not_exploitable")
        self.assertEqual(safe["compat_prediction"], "not_exploitable")
        # abstain is not a completed negative in the safety projection:
        self.assertFalse(abstain["status_correct"])
        self.assertFalse(failed["status_correct"])

    def test_false_safe_needs_safe_outcome_on_gt_exploitable(self):
        safe = R.derive_case(self._row("ok", "code_not_reachable"))
        self.assertTrue(safe["_gt_pos"])
        self.assertEqual(safe["safety_outcome"], "safe")  # false-safe cell


class AuditRowTest(unittest.TestCase):
    def _row(self, status, cat):
        return {"task_id": "t", "run_id": "run_001", "cve_id": "CVE-1",
                "ground_truth": "exploitable",
                "ground_truth_category": "vulnerable",
                "status": status, "predicted_category": cat,
                "predicted": parser_audit.category_to_binary(cat),
                "reasoning": "r"}

    def test_recovery_to_ok(self):
        audit = parser_audit.audit_terminal_text(
            final_json("code_not_reachable"), None)
        out = R.audit_row(self._row("parse_fail", None), audit, False)
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["predicted_category"], "code_not_reachable")
        self.assertEqual(out["predicted"], "not_exploitable")

    def test_refusal_never_recovers(self):
        audit = parser_audit.audit_terminal_text(final_json("vulnerable"), None)
        out = R.audit_row(self._row("parse_fail", None), audit, True)
        self.assertEqual(out["status"], "parse_fail")
        self.assertIsNone(out["predicted_category"])

    def test_audit_miss_demotes_ok(self):
        audit = parser_audit.audit_terminal_text("no json", "vulnerable")
        out = R.audit_row(self._row("ok", "vulnerable"), audit, False)
        self.assertEqual(out["status"], "parse_fail")
        self.assertIsNone(out["predicted"])

    def test_transport_status_preserved(self):
        audit = parser_audit.audit_terminal_text("", None)
        out = R.audit_row(self._row("no_result", None), audit, False)
        self.assertEqual(out["status"], "no_result")
        out = R.audit_row(self._row("no_dir", None), audit, False)
        self.assertEqual(out["status"], "no_dir")


class ClassifyFailureTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.rd = Path(self.td.name)

    def test_no_dir(self):
        row = {"status": "no_dir"}
        self.assertEqual(
            R.classify_failure("no_dir", self.rd / "nope", None, ""),
            "no_dir")

    def test_error_txt_timeout(self):
        (self.rd).mkdir(exist_ok=True)
        (self.rd / "error.txt").write_text(
            "container timed out after 900s", encoding="utf-8")
        self.assertEqual(
            R.classify_failure("no_result", self.rd, None, ""), "timeout")

    def test_error_txt_at_capacity(self):
        self.rd.mkdir(exist_ok=True)
        (self.rd / "error.txt").write_text(
            'container exited 1: {"type":"error","message":"Selected model '
            'is at capacity. Please try a different model."}',
            encoding="utf-8")
        self.assertEqual(
            R.classify_failure("no_result", self.rd, None, ""),
            "provider_at_capacity")

    def test_parse_fail_stream_error(self):
        self.rd.mkdir(exist_ok=True)
        raw = json.dumps({"type": "error",
                          "message": "stream disconnected before completion"})
        (self.rd / "result.jsonl").write_text(raw, encoding="utf-8")
        self.assertEqual(
            R.classify_failure("parse_fail", self.rd, raw, ""),
            "transport_failure")

    def test_parse_fail_refusal(self):
        self.rd.mkdir(exist_ok=True)
        refusal = "I'm sorry, I can't help with that request."
        self.assertEqual(
            R.classify_failure("parse_fail", self.rd,
                               make_ndjson(refusal), refusal),
            "provider_refusal")

    def test_status_json_reason_wins(self):
        self.rd.mkdir(exist_ok=True)
        from eval.c1.status import AttemptStatus
        st = AttemptStatus.classify(
            task_id="t", attempt_id="run_001", experiment_id="e",
            execution="timeout", official_parse="no_result",
            assessment_schema="absent", failure_reason="timeout")
        (self.rd / "status.json").write_text(
            st.model_dump_json(), encoding="utf-8")
        # whatever raw says, the controller-stamped reason wins
        self.assertEqual(
            R.classify_failure("parse_fail", self.rd, None, ""), "timeout")

    def test_ok_row_is_never_failed(self):
        self.assertIsNone(
            R.classify_failure("ok", self.rd, None, ""))


class StabilityTest(unittest.TestCase):
    def _cases(self):
        mk = lambda tid, rid, out: {
            "task_id": tid, "run_id": rid,
            "ground_truth": "exploitable",
            "ground_truth_category": "vulnerable",
            "safety_outcome": out, "predicted_category": None,
            "_gt_pos": True}
        return [mk("t3", r, "safe") for r in
                ("run_001", "run_002", "run_003")] + \
               [mk("t2", "run_001", "safe"), mk("t2", "run_002", "safe"),
                mk("t2", "run_003", "failed")] + \
               [mk("t1", "run_001", "safe"), mk("t1", "run_002", "failed"),
                mk("t1", "run_003", "abstain")]

    def test_distribution(self):
        blk = R.stability_block(self._cases(), 3)
        self.assertEqual(blk["stability_distribution"],
                         {"3/3": 1, "2/3": 1, "1/3": 1})
        self.assertEqual(blk["safe_stable_tasks"], ["t3"])
        t1 = next(t for t in blk["tasks"] if t["task_id"] == "t1")
        self.assertEqual(t1["dominant_outcome"], t1["outcomes"]["run_001"])
        self.assertEqual(t1["safe_count"], 1)

    def test_missing_repeats_recorded(self):
        cs = [c for c in self._cases() if c["task_id"] == "t2"]
        cs = cs[:2]
        blk = R.stability_block(cs, 3)
        t2 = blk["tasks"][0]
        self.assertEqual(t2["n_attempts"], 2)
        self.assertEqual(t2["missing_runs"], ["run_003"])
        self.assertFalse(t2["safe_stable"])  # 2 < n_expected


class CompareCohortsTest(unittest.TestCase):
    def _case(self, tid, rid, out, correct, reason, gt_pos=True, cat="x"):
        return {"task_id": tid, "run_id": rid, "cve_id": "CVE-1",
                "ground_truth": "exploitable" if gt_pos
                else "not_exploitable",
                "ground_truth_category": cat,
                "status": "ok" if out != "failed" else "parse_fail",
                "safety_outcome": out, "predicted_category": cat,
                "status_correct": correct, "reason_correct": reason,
                "_gt_pos": gt_pos}

    def test_transition_flags(self):
        base = [
            self._case("a", "run_001", "safe", False, False),   # FS in base
            self._case("b", "run_001", "safe", True, True,
                       gt_pos=False, cat="code_not_reachable"),
            self._case("c", "run_001", "abstain", False, False),
        ]
        coh = [
            self._case("a", "run_001", "positive", True, True),  # FS cleared
            self._case("b", "run_001", "failed", False, False,
                       gt_pos=False, cat="code_not_reachable"),  # regression
            self._case("c", "run_001", "safe", False, False),    # still wrong
        ]
        cmp_ = R.compare_cohorts(coh, "C1", base, "B1")
        t = cmp_["tally"]
        self.assertEqual(t.get("correction"), 1)          # a: wrong→correct
        self.assertEqual(t.get("regression"), 1)          # b: correct→wrong
        self.assertEqual(t.get("false_safe_cleared"), 1)  # a
        self.assertEqual(t.get("false_safe_new"), 1)    # c: abstain→safe on GT-pos
        self.assertEqual(t.get("from_abstain_to_decisive"), 1)  # c
        a = next(p for p in cmp_["pairs"] if p["task_id"] == "a")
        self.assertIn("false_safe_cleared", a["flags"])
        self.assertIn("correction", a["flags"])
        self.assertIn("observed", cmp_["causality_note"]
                      .lower())


class ToolUseTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.rd = Path(self.td.name)

    def _audit_rec(self, tool, obs_id, completeness="COMPLETE",
                   status="OK", args=None, refs=()):
        return {"tool": tool, "args": args or {}, "duration_ms": 5,
                "observation": {"id": obs_id, "tool": tool,
                                "completeness": completeness,
                                "tool_status": status,
                                "evidence_refs": list(refs)}}

    def test_audit_records_projected(self):
        (self.rd).mkdir(exist_ok=True)
        recs = [self._audit_rec("find_callers", "OBS-1",
                                refs=["sha256:" + "0" * 64]),
                self._audit_rec("find_callers", "OBS-2",
                                args={"symbol": "x"}),  # different args
                self._audit_rec("get_module_version", "OBS-3",
                                status="ERROR", completeness="UNKNOWN")]
        (self.rd / "tool_calls.jsonl").write_text(
            "\n".join(json.dumps(r) for r in recs), encoding="utf-8")
        recs2, src = R.read_mcp_audit(self.rd)
        self.assertEqual(len(recs2), 3)
        self.assertEqual(src, "tool_calls.jsonl")
        enrich = R.enrich_attempt(
            self.rd, {"task_id": "t", "run_id": "run_001",
                      "safety_outcome": "safe", "status": "ok",
                      "predicted_category": "code_not_reachable"},
            {"status": "matched"}, None, "")
        self.assertEqual(len(enrich["mcp_calls"]), 3)
        self.assertIn("find_callers", enrich["tools_used"])
        self.assertFalse(enrich["missed_reachability_check"])

    def test_missing_audit_is_not_zero_calls(self):
        enrich = R.enrich_attempt(
            self.rd, {"task_id": "t", "run_id": "run_001",
                      "safety_outcome": "safe", "status": "ok",
                      "predicted_category": "code_not_reachable"},
            {"status": "matched"}, None, "")
        self.assertEqual(enrich["mcp_calls"], [])
        self.assertFalse(enrich["mcp_audit_present"])
        self.assertTrue(enrich["missed_reachability_check"])

    def test_repeated_call_counted(self):
        (self.rd).mkdir(exist_ok=True)
        recs = [self._audit_rec("search_source", f"OBS-{i}",
                                args={"q": "same"})
                for i in range(3)]
        (self.rd / "tool_calls.jsonl").write_text(
            "\n".join(json.dumps(r) for r in recs), encoding="utf-8")
        enrich = R.enrich_attempt(
            self.rd, {"task_id": "t", "run_id": "run_001",
                      "safety_outcome": "positive", "status": "ok"},
            {"status": "matched"}, None, "")
        self.assertEqual(enrich["repeated_calls"], 1)


class AssessmentSchemaBlockTest(unittest.TestCase):
    """The aggregated assessment_schema dimension: counts come from
    status.json only, missing status is its own bucket, and nothing
    here touches the verdict projection."""

    def _case(self, tid, rid):
        return {"task_id": tid, "run_id": rid}

    def test_counts_by_run_and_pooled(self):
        cases = [self._case("t1", "run_001"), self._case("t2", "run_001"),
                 self._case("t1", "run_002"), self._case("t2", "run_002")]
        enrich = {
            ("t1", "run_001"): {"status_json": {
                "assessment_schema": "valid"}},
            ("t2", "run_001"): {"status_json": {
                "assessment_schema": "invalid"}},
            ("t1", "run_002"): {"status_json": {
                "assessment_schema": "absent"}},
            ("t2", "run_002"): {"status_json": None},  # no status.json
        }
        blk = R.assessment_schema_block(cases, enrich)
        self.assertEqual(blk["attempts"], 4)
        self.assertEqual(blk["per_repeat"]["run_001"],
                         {"valid": 1, "invalid": 1})
        self.assertEqual(blk["per_repeat"]["run_002"], {"absent": 1})
        self.assertEqual(blk["pooled"],
                         {"valid": 1, "invalid": 1, "absent": 1})
        self.assertEqual(blk["no_status_json"], 1)
        self.assertEqual(blk["invalid_attempts"], ["t2/run_001"])

    def test_empty_cohort(self):
        blk = R.assessment_schema_block([], {})
        self.assertEqual(blk["attempts"], 0)
        self.assertEqual(blk["pooled"], {})
        self.assertEqual(blk["no_status_json"], 0)


class RunReportIntegrationTest(unittest.TestCase):
    """End-to-end synthetic cohort through run_report."""

    def _build_cohort(self, root: Path, with_status: bool = False):
        """3 tasks x 3 repeats; covers ok / FS / audit-recovered /
        refusal / timeout / missing outcomes. ``with_status`` stamps a
        controller status.json per attempt so the aggregated
        assessment_schema dimension is exercisable end-to-end."""
        from eval.c1.status import AttemptStatus

        def stamp(d, **kw):
            if not with_status:
                return
            st = AttemptStatus.classify(
                task_id=kw.pop("task_id"), attempt_id=kw.pop("attempt_id"),
                experiment_id="e", **kw)
            (d / "status.json").write_text(st.model_dump_json(),
                                           encoding="utf-8")

        for rep in range(1, 4):
            rid = f"run_{rep:03d}"
            # t-pos: GT vulnerable; official misses braces, audit recovers
            d = root / "t-pos" / rid
            d.mkdir(parents=True)
            bad = '{"category": "code_not_reachable", "reasoning": "a }{ b"}'
            (d / "result.jsonl").write_text(
                make_ndjson("lead-in\n" + bad), encoding="utf-8")
            stamp(d, task_id="t-pos", attempt_id=rid,
                  execution="invalid_terminal_answer",
                  official_parse="parse_fail", parser_audit="recovered",
                  assessment_schema="invalid",
                  failure_reason="invalid_terminal_answer")
            # t-neg: GT code_not_reachable; clean safe answer + audit sink
            d = root / "t-neg" / rid
            d.mkdir(parents=True)
            (d / "result.jsonl").write_text(
                make_ndjson(final_json("code_not_reachable")),
                encoding="utf-8")
            (d / "tool_calls.jsonl").write_text(
                json.dumps({"tool": "find_callers",
                            "observation": {"id": "OBS-1",
                                            "tool": "find_callers",
                                            "completeness": "PARTIAL",
                                            "tool_status": "OK",
                                            "evidence_refs": []}}),
                encoding="utf-8")
            stamp(d, task_id="t-neg", attempt_id=rid,
                  execution="ok", official_parse="accepted",
                  parser_audit="matched", assessment_schema="valid",
                  category="code_not_reachable")
            # t-cfg: timeout on rep1, refusal rep2, missing rep3
            # t-cfg: timeout on rep1, refusal rep2, run dir missing rep3
            d = root / "t-cfg" / rid
            if rep != 3:
                d.mkdir(parents=True)
            if rep == 1:
                (d / "error.txt").write_text(
                    "container timed out after 900s", encoding="utf-8")
                stamp(d, task_id="t-cfg", attempt_id=rid,
                      execution="timeout", official_parse="no_result",
                      assessment_schema="absent",
                      failure_reason="timeout")
            elif rep == 2:
                (d / "result.jsonl").write_text(
                    make_ndjson("I'm sorry, I can't help with that."),
                    encoding="utf-8")
                stamp(d, task_id="t-cfg", attempt_id=rid,
                      execution="provider_refusal",
                      official_parse="parse_fail", parser_audit="no_object",
                      assessment_schema="invalid",
                      failure_reason="provider_refusal")
        # rep3: task dir exists, run dir missing entirely
        return root

    def test_full_report(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "cohort"
            out = Path(td) / "scoring"
            self._build_cohort(root)
            res = R.run_report(
                run_root=root, tasks=TASKS, out_dir=out, label="synthetic",
                harness_dir=None, agent_name="codex", model="m",
                prompt_hash="h123", benchmark="vex_bench", repeats=3,
                note="test fixture", baseline_rows=None,
                baseline_name="B1",
                check_parsed=None, official_metrics_path=None,
                row_builder=fake_row_builder(root),
                compute_metrics=stub_compute_metrics)
            self.assertTrue((out / "official_metrics.json").exists())
            self.assertTrue((out / "safety_metrics.json").exists())
            self.assertTrue((out / "parser_audit_metrics.json").exists())
            self.assertTrue((out / "case_comparison.jsonl").exists())
            self.assertTrue((out / "disagreements.md").exists())
            self.assertTrue((out / "tool_use_summary.md").exists())

            safety = json.loads(
                (out / "safety_metrics.json").read_text())
            self.assertEqual(safety["aggregate"]["n_repeats"], 3)
            # t-pos recovered as safe on exploitable GT = False-Safe x3
            # t-pos: official extractor defeated by }{ inside the JSON
            # string → parse_fail (failed), NOT safe; the audit
            # projection is what reveals the hidden unsafe-negative.
            self.assertEqual(
                safety["aggregate"]["false_safe"]["total_count"], 0)
            audit = json.loads(
                (out / "parser_audit_metrics.json").read_text())
            audit_pooled = \
                audit["metrics"]["safety_projection"]["pooled"]
            self.assertEqual(audit_pooled["false_safe_count"], 3)
            self.assertEqual(audit_pooled["false_safe_ids"], ["t-pos"])
            fc = safety["failure_classes"]
            self.assertEqual(fc["pooled"].get("timeout"), 1)
            self.assertEqual(fc["pooled"].get("provider_refusal"), 1)
            self.assertEqual(fc["pooled"].get("no_dir"), 1)
            # t-pos x3: official extractor defeated by }{ → parse_fail
            self.assertEqual(fc["pooled"].get("invalid_terminal_answer"), 3)
            self.assertEqual(fc["total_failed"], 6)

            counts = audit["audit_status_counts"]
            self.assertEqual(counts.get("recovered"), 3)  # t-pos x3
            self.assertEqual(counts.get("matched"), 3)    # t-neg x3
            # disagreement records carry the recovered object
            rec = audit["disagreements"][0]
            self.assertEqual(rec["status"], "recovered")
            self.assertEqual(rec["audit_category"], "code_not_reachable")

            # refusal attempt: audit found NO object; row stays failed
            comp = [json.loads(l) for l in
                    (out / "case_comparison.jsonl").read_text().splitlines()
                    if l.strip()]
            self.assertEqual(len(comp), 9)
            ref = next(c for c in comp
                       if c["task_id"] == "t-cfg"
                       and c["run_id"] == "run_002")
            self.assertEqual(ref["failure_class"], "provider_refusal")
            self.assertTrue(ref["audit"]["provider_refusal_hint"])

            # the audit projection RE-SCORES t-pos as safe → its pooled
            # row count differs from official (still failed there)
            audit_pooled = audit["metrics"]["safety_projection"]["pooled"]
            self.assertEqual(audit_pooled["outcomes"]["safe"], 3 + 3)

    def test_official_metrics_unchanged_by_audit(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "cohort"
            self._build_cohort(root)
            R.run_report(
                run_root=root, tasks=TASKS, out_dir=Path(td) / "o",
                label="s", harness_dir=None, agent_name="codex", model="m",
                prompt_hash="h", benchmark="vex_bench", repeats=3,
                note=None, baseline_rows=None, baseline_name="B1",
                check_parsed=None, official_metrics_path=None,
                row_builder=fake_row_builder(root),
                compute_metrics=stub_compute_metrics)
            om = json.loads(
                (Path(td) / "o" / "official_metrics.json").read_text())
            # stub scorer saw 9 rows: official parse_fail rows unchanged
            self.assertEqual(om["completion"]["total"], 9)
            self.assertEqual(om["completion"]["answered"], 3)

    def test_opencode_cohort_audit(self):
        """result.json export payload: the audit reads the LAST
        assistant text part — matched/recovered, never no_input."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "cohort"
            for rep in range(1, 4):
                rid = f"run_{rep:03d}"
                # t-pos: official misses braces-in-string, audit recovers
                d = root / "t-pos" / rid
                d.mkdir(parents=True)
                bad = ('{"category": "code_not_reachable", '
                       '"reasoning": "a }{ b"}')
                (d / "result.json").write_text(
                    make_export("lead-in\n" + bad,
                                earlier_texts=(final_json("vulnerable"),)),
                    encoding="utf-8")
                # t-neg: clean safe answer
                d = root / "t-neg" / rid
                d.mkdir(parents=True)
                (d / "result.json").write_text(
                    make_export(final_json("code_not_reachable")),
                    encoding="utf-8")
                # t-cfg: refusal page as terminal text
                d = root / "t-cfg" / rid
                d.mkdir(parents=True)
                (d / "result.json").write_text(
                    make_export("I'm sorry, I can't help with that."),
                    encoding="utf-8")
            out = Path(td) / "scoring"
            R.run_report(
                run_root=root, tasks=TASKS, out_dir=out, label="oc",
                harness_dir=None, agent_name="opencode-c1", model="m",
                prompt_hash="h", benchmark="vex_bench", repeats=3,
                note=None, baseline_rows=None, baseline_name="B1",
                check_parsed=None, official_metrics_path=None,
                row_builder=fake_row_builder(
                    root,
                    extractor=parser_audit.opencode_terminal_text,
                    result_filename="result.json"),
                compute_metrics=stub_compute_metrics)
            audit = json.loads(
                (out / "parser_audit_metrics.json").read_text())
            counts = audit["audit_status_counts"]
            self.assertNotIn("no_input", counts)
            self.assertEqual(counts.get("recovered"), 3)   # t-pos x3
            self.assertEqual(counts.get("matched"), 3)     # t-neg x3
            self.assertEqual(counts.get("no_object"), 3)   # refusals
            self.assertEqual(audit["terminal_text_extractor"],
                             "opencode-c1")
            self.assertEqual(audit["result_filename"], "result.json")
            rec = audit["disagreements"][0]
            self.assertEqual(rec["status"], "recovered")
            self.assertEqual(rec["audit_category"], "code_not_reachable")

    def test_unknown_agent_is_explicit_no_input(self):
        """An agent profile with no registered extractor yields
        ``no_input`` + a reason — never a silent codex read."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "cohort"
            self._build_cohort(root)
            out = Path(td) / "scoring"
            R.run_report(
                run_root=root, tasks=TASKS, out_dir=out, label="s",
                harness_dir=None, agent_name="totally-unknown", model="m",
                prompt_hash="h", benchmark="vex_bench", repeats=3,
                note=None, baseline_rows=None, baseline_name="B1",
                check_parsed=None, official_metrics_path=None,
                row_builder=fake_row_builder(root),
                compute_metrics=stub_compute_metrics)
            audit = json.loads(
                (out / "parser_audit_metrics.json").read_text())
            counts = audit["audit_status_counts"]
            self.assertEqual(counts.get("no_input"), 9)
            reasons = [r["input_error"] or ""
                       for r in audit["per_attempt_audit"].values()]
            self.assertTrue(all(reasons))
            self.assertTrue(
                any("totally-unknown" in r for r in reasons))
            for rec in audit["per_attempt_audit"].values():
                self.assertIsNone(rec["audit_category"])

    def test_assessment_schema_aggregates(self):
        """status.json's assessment_schema rolls up per cohort — the
        third status dimension stays reporting-only: rows and verdicts
        are unchanged whether the assessment artifact validated."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "cohort"
            out = Path(td) / "scoring"
            self._build_cohort(root, with_status=True)
            R.run_report(
                run_root=root, tasks=TASKS, out_dir=out, label="s",
                harness_dir=None, agent_name="codex", model="m",
                prompt_hash="h", benchmark="vex_bench", repeats=3,
                note=None, baseline_rows=None, baseline_name="B1",
                check_parsed=None, official_metrics_path=None,
                row_builder=fake_row_builder(root),
                compute_metrics=stub_compute_metrics)
            safety = json.loads(
                (out / "safety_metrics.json").read_text())
            asm = safety["assessment_schema"]
            self.assertEqual(asm["attempts"], 9)
            self.assertEqual(asm["pooled"],
                             {"valid": 3, "invalid": 4, "absent": 1})
            self.assertEqual(asm["per_repeat"]["run_001"],
                             {"invalid": 1, "valid": 1, "absent": 1})
            self.assertEqual(asm["per_repeat"]["run_002"],
                             {"invalid": 2, "valid": 1})
            self.assertEqual(asm["per_repeat"]["run_003"],
                             {"invalid": 1, "valid": 1})
            self.assertEqual(asm["no_status_json"], 1)  # t-cfg/run_003 only
            self.assertEqual(
                asm["invalid_attempts"],
                ["t-cfg/run_002", "t-pos/run_001",
                 "t-pos/run_002", "t-pos/run_003"])
            # unchanged: verdict rows still scored by official projection
            self.assertEqual(
                safety["failure_classes"]["pooled"]
                .get("invalid_terminal_answer"), 3)
            comp = [json.loads(l) for l in
                    (out / "case_comparison.jsonl").read_text().splitlines()
                    if l.strip()]
            pos = next(c for c in comp if c["task_id"] == "t-pos")
            self.assertEqual(pos["assessment_schema"], "invalid")
            self.assertEqual(pos["status_json"], "failed")


if __name__ == "__main__":
    unittest.main()

"""Unit tests for eval/c1/parser_audit.py — the string-aware audit decoder.

Run: /tmp/vexbench-agent-ctl/.venv/bin/python -m unittest \\
    eval.c1.parser_audit_test -v

The rules under test (spec §8.3.2 / plan §9.1 item 9):
- only the LAST assistant terminal text is decoded;
- only a COMPLETE valid JSON object is recovered — braces/escaped quotes
  inside string fields, nesting, ```json fences and prose wrappers are
  all tolerated by raw_decode; truncated objects never recover;
- no label-only regex: 'category: vulnerable' in prose is not a label;
- the identical rule applies to positive and unsafe-negative categories;
- statuses: matched / recovered / disagreed / no_valid_category /
  no_object / no_input.
"""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from eval.c1 import parser_audit as pa  # noqa: E402


def _obj(category="vulnerable", reasoning="ok", **extra):
    return json.dumps(
        {"category": category, "reasoning": reasoning, **extra})


def _ndjson(*texts, with_tool_result=False):
    """Codex NDJSON: one agent_message per text (+ optional tool noise)."""
    events = []
    if with_tool_result:
        events.append({
            "type": "item.completed",
            "item": {"type": "command_execution",
                     "aggregated_output": '{"category":"false_positive"}'},
        })
    for t in texts:
        events.append({"type": "item.completed",
                       "item": {"type": "agent_message", "text": t}})
    return "\n".join(json.dumps(e) for e in events)


def _export(*messages):
    """opencode export JSON: ``(role, parts)`` pairs -> result.json
    payload. A part is a ``(type, text)`` tuple or a plain text
    shorthand (``"str"`` -> ``{"type": "text", "text": "str"}``)."""
    def _part(p):
        if isinstance(p, tuple):
            return {"type": p[0], "text": p[1]}
        if isinstance(p, dict):
            return p
        return {"type": "text", "text": p}

    out = [{"info": {"role": role}, "parts": [_part(p) for p in parts]}
           for role, parts in messages]
    return json.dumps({"info": {"id": "ses_x"}, "messages": out})


def _oc_jsonl(*texts):
    """Legacy opencode JSONL stream: one ``text`` event per text."""
    return "\n".join(
        json.dumps({"type": "text", "part": {"text": t}})
        for t in texts)


class ExtractionTest(unittest.TestCase):
    def test_plain_object(self):
        rec = pa.audit_terminal_text(_obj(), None)
        self.assertEqual(rec["status"], pa.AUDIT_STATUS_RECOVERED)
        self.assertEqual(rec["audit_category"], "vulnerable")
        self.assertEqual(rec["recovered_object"]["category"], "vulnerable")

    def test_braces_inside_reasoning(self):
        # The known official defect: }{ inside a string defeats brace
        # counting; raw_decode is string-aware and recovers the object.
        text = _obj(reasoning='the block }{ looks like a boundary')
        rec = pa.audit_terminal_text("prose.\n" + text + "\ndone.", None)
        self.assertEqual(rec["status"], pa.AUDIT_STATUS_RECOVERED)
        self.assertEqual(rec["recovered_object"]["reasoning"],
                         'the block }{ looks like a boundary')

    def test_escaped_quotes_and_braces(self):
        text = _obj(reasoning='quote \\"}{\\" and {{{ nested')
        rec = pa.audit_terminal_text(text, None)
        self.assertEqual(rec["status"], pa.AUDIT_STATUS_RECOVERED)

    def test_nested_objects(self):
        text = _obj(assessment={"claims": [{"statement": "s{ }",
                                              "verdict": "TRUE"}]})
        rec = pa.audit_terminal_text(text, None)
        self.assertEqual(rec["status"], pa.AUDIT_STATUS_RECOVERED)
        self.assertEqual(rec["audit_category"], "vulnerable")

    def test_json_fence(self):
        rec = pa.audit_terminal_text("```json\n" + _obj() + "\n```", None)
        self.assertEqual(rec["status"], pa.AUDIT_STATUS_RECOVERED)

    def test_prose_label_is_not_a_category(self):
        for text in ("category: vulnerable",
                     "The category is vulnerable.",
                     'vulnerable',
                     '"category": vulnerable'):
            rec = pa.audit_terminal_text(text, None)
            self.assertEqual(rec["status"], pa.AUDIT_STATUS_NO_OBJECT, text)

    def test_truncated_object_never_recovers(self):
        full = _obj(reasoning="long " + "x" * 200)
        rec = pa.audit_terminal_text(full[: len(full) // 2], None)
        self.assertEqual(rec["status"], pa.AUDIT_STATUS_NO_OBJECT)
        self.assertIsNone(rec["audit_category"])

    def test_first_category_object_wins(self):
        text = '{"meta": 1} ' + _obj("code_not_reachable") + " " + _obj()
        rec = pa.audit_terminal_text(text, None)
        self.assertEqual(rec["audit_category"], "code_not_reachable")
        self.assertEqual(rec["objects_found"], 3)
        self.assertEqual(rec["category_objects_found"], 2)

    def test_object_without_category_key(self):
        rec = pa.audit_terminal_text('{"result": "vulnerable"}', None)
        self.assertEqual(rec["status"], pa.AUDIT_STATUS_NO_OBJECT)

    def test_invalid_category_value(self):
        rec = pa.audit_terminal_text(_obj("totally_safe"), None)
        self.assertEqual(rec["status"], pa.AUDIT_STATUS_NO_VALID)
        # object is still stored — the disagreement record is complete
        self.assertEqual(rec["recovered_object"]["category"],
                         "totally_safe")

    def test_refusal_text_has_no_object(self):
        rec = pa.audit_terminal_text(
            "I'm sorry, I can't help with that request.", None)
        self.assertEqual(rec["status"], pa.AUDIT_STATUS_NO_OBJECT)

    def test_empty_and_missing_input(self):
        self.assertEqual(
            pa.audit_terminal_text("", None)["status"],
            pa.AUDIT_STATUS_NO_INPUT)
        self.assertEqual(
            pa.audit_terminal_text(None, None)["status"],
            pa.AUDIT_STATUS_NO_INPUT)


class SameRuleAllCategoriesTest(unittest.TestCase):
    """Identical extraction for positive and unsafe-negative labels —
    the audit must not special-case 'safe' categories."""

    def test_symmetric_recovery(self):
        for cat in ("vulnerable", "uncertain", "code_not_reachable",
                    "false_positive", "perimeter_protected"):
            text = "lead-in\n" + _obj(cat, 'x }{ y') + "\ntail"
            rec = pa.audit_terminal_text(text, None)
            self.assertEqual(rec["status"], pa.AUDIT_STATUS_RECOVERED, cat)
            self.assertEqual(rec["audit_category"], cat)


class DisagreementTest(unittest.TestCase):
    def test_matched(self):
        rec = pa.audit_terminal_text(_obj(), "vulnerable")
        self.assertEqual(rec["status"], pa.AUDIT_STATUS_MATCHED)
        self.assertIsNone(rec["disagreement"])

    def test_different_category_is_disagreed_not_recovered(self):
        rec = pa.audit_terminal_text(_obj("uncertain"), "vulnerable")
        self.assertEqual(rec["status"], pa.AUDIT_STATUS_DISAGREED)
        self.assertEqual(rec["disagreement"]["official"], "vulnerable")
        self.assertEqual(rec["disagreement"]["audit"], "uncertain")

    def test_official_seen_but_audit_object_invalid(self):
        rec = pa.audit_terminal_text(_obj("bogus"), "vulnerable")
        self.assertEqual(rec["status"], pa.AUDIT_STATUS_DISAGREED)
        self.assertEqual(rec["disagreement"]["kind"],
                         "audit_object_category_invalid")

    def test_both_blind_is_no_object_not_disagreement(self):
        rec = pa.audit_terminal_text("no json here", None)
        self.assertEqual(rec["status"], pa.AUDIT_STATUS_NO_OBJECT)
        self.assertIsNone(rec["disagreement"])

    def test_decoder_version_recorded(self):
        rec = pa.audit_terminal_text(_obj(), "vulnerable")
        self.assertEqual(rec["decoder"], pa.PARSER_AUDIT_DECODER_VERSION)


class TerminalTextTest(unittest.TestCase):
    def test_only_last_agent_message(self):
        # Earlier message carries a wrong category; the terminal one wins.
        nd = _ndjson(_obj("false_positive"), _obj("vulnerable"))
        text = pa.codex_terminal_text(nd)
        self.assertIn("vulnerable", text)
        rec = pa.audit_terminal_text(text, None)
        self.assertEqual(rec["audit_category"], "vulnerable")

    def test_tool_output_json_never_scanned(self):
        # A command_execution carrying a JSON blob is not terminal text.
        nd = _ndjson("the result was …", with_tool_result=True)
        text = pa.codex_terminal_text(nd)
        self.assertNotIn("false_positive", text)
        rec = pa.audit_terminal_text(text, None)
        self.assertEqual(rec["status"], pa.AUDIT_STATUS_NO_OBJECT)

    def test_non_agent_items_ignored(self):
        nd = "\n".join([
            json.dumps({"type": "item.completed",
                        "item": {"type": "reasoning",
                                 "text": '{"category":"vulnerable"}'}}),
            json.dumps({"type": "item.completed",
                        "item": {"type": "agent_message",
                                 "text": _obj("uncertain")}}),
        ])
        text = pa.codex_terminal_text(nd)
        self.assertIn("uncertain", text)

    def test_audit_run_dir_reads_last_message(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            rd = Path(td)
            (rd / "result.jsonl").write_text(
                _ndjson(_obj("uncertain"), _obj("vulnerable")),
                encoding="utf-8")
            rec = pa.audit_run_dir(rd, None)
            self.assertEqual(rec["audit_category"], "vulnerable")
            self.assertEqual(rec["status"], pa.AUDIT_STATUS_RECOVERED)

    def test_audit_run_dir_missing_file(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            rec = pa.audit_run_dir(Path(td), None)
            self.assertEqual(rec["status"], pa.AUDIT_STATUS_NO_INPUT)
            self.assertIsNotNone(rec["input_error"])



class OpencodeTerminalTextTest(unittest.TestCase):
    """opencode export JSON — the LAST assistant message's last text
    part is terminal text; user/tool/reasoning parts are never seen."""

    def test_last_assistant_text_wins(self):
        raw = _export(
            ("user", ["solve the CVE"]),
            ("assistant", [_obj("false_positive")]),
            ("user", ["thanks"]),
            ("assistant", [_obj("vulnerable")]),
        )
        text = pa.opencode_terminal_text(raw)
        self.assertIn("vulnerable", text)
        rec = pa.audit_terminal_text(text, None)
        self.assertEqual(rec["audit_category"], "vulnerable")

    def test_last_text_part_of_last_message(self):
        raw = _export(
            ("assistant", [
                ("reasoning", "thinking about {braces}"),
                "prose lead-in",
                _obj("uncertain"),
            ]),
        )
        rec = pa.audit_terminal_text(pa.opencode_terminal_text(raw), None)
        self.assertEqual(rec["audit_category"], "uncertain")

    def test_reasoning_and_tool_parts_ignored(self):
        raw = _export(
            ("assistant", [
                ("reasoning", '{"category": "vulnerable"}'),
                ("tool", "observation payload"),
                _obj("code_not_reachable"),
            ]),
        )
        text = pa.opencode_terminal_text(raw)
        self.assertNotIn('"vulnerable"', text)
        rec = pa.audit_terminal_text(text, None)
        self.assertEqual(rec["audit_category"], "code_not_reachable")

    def test_braces_inside_reasoning_string_still_recover(self):
        raw = _export(("assistant", [
            _obj("vulnerable", 'the block }{ splits depth')]))
        rec = pa.audit_terminal_text(pa.opencode_terminal_text(raw), None)
        self.assertEqual(rec["status"], pa.AUDIT_STATUS_RECOVERED)
        self.assertEqual(rec["audit_category"], "vulnerable")

    def test_refusal_prose_is_no_object(self):
        raw = _export(
            ("assistant", [("reasoning", "safety triage…")]),
            ("assistant", ["I'm sorry, I can't help with that request."]),
        )
        rec = pa.audit_terminal_text(pa.opencode_terminal_text(raw), None)
        self.assertEqual(rec["status"], pa.AUDIT_STATUS_NO_OBJECT)

    def test_prose_without_json_is_no_object(self):
        raw = _export(("assistant", ["verdict: category is vulnerable"]))
        rec = pa.audit_terminal_text(pa.opencode_terminal_text(raw), None)
        self.assertEqual(rec["status"], pa.AUDIT_STATUS_NO_OBJECT)

    def test_user_message_json_never_scanned(self):
        # a JSON blob in the LAST message is only terminal text when the
        # message is the assistant's — a trailing user echo is not.
        raw = _export(
            ("assistant", [_obj("vulnerable")]),
            ("user", [_obj("false_positive")]),
        )
        text = pa.opencode_terminal_text(raw)
        self.assertIn("vulnerable", text)
        self.assertNotIn("false_positive", text)

    def test_assistant_without_text_skipped(self):
        # an assistant turn with only reasoning parts is not terminal;
        # the previous assistant text is.
        raw = _export(
            ("assistant", [_obj("uncertain")]),
            ("assistant", [("reasoning", "still thinking")]),
        )
        rec = pa.audit_terminal_text(pa.opencode_terminal_text(raw), None)
        self.assertEqual(rec["audit_category"], "uncertain")

    def test_no_text_parts_is_empty(self):
        raw = _export(
            ("user", ["hi"]),
            ("assistant", [("reasoning", "only thought")]),
        )
        self.assertEqual(pa.opencode_terminal_text(raw), "")
        rec = pa.audit_terminal_text(pa.opencode_terminal_text(raw), None)
        self.assertEqual(rec["status"], pa.AUDIT_STATUS_NO_INPUT)

    def test_legacy_jsonl_fallback(self):
        raw = _oc_jsonl(_obj("false_positive"), _obj("vulnerable"))
        text = pa.opencode_terminal_text(raw)
        self.assertIn("vulnerable", text)

    def test_export_without_messages_falls_back(self):
        # dict payload but not an export -> legacy JSONL path
        raw = json.dumps({"info": {"id": "x"}})
        self.assertEqual(pa.opencode_terminal_text(raw), "")


class ExtractorResolutionTest(unittest.TestCase):
    """Adapter -> extractor mapping; unknown adapters are explicit."""

    def test_registry_covers_task4_profiles(self):
        for name in ("codex", "codex-b1p", "codex-c1",
                     "opencode", "opencode-b1p", "opencode-c1"):
            self.assertIsNotNone(
                pa.resolve_terminal_text_extractor(name), name)
        self.assertIs(pa.resolve_terminal_text_extractor("opencode"),
                      pa.opencode_terminal_text)
        self.assertIs(pa.resolve_terminal_text_extractor("codex"),
                      pa.codex_terminal_text)

    def test_callable_and_none_resolution(self):
        self.assertIs(pa.resolve_terminal_text_extractor(len), len)
        self.assertIs(pa.resolve_terminal_text_extractor(None),
                      pa.codex_terminal_text)

    def test_unknown_adapter_raises(self):
        with self.assertRaises(ValueError):
            pa.terminal_text("{}", "claude")

    def test_audit_run_dir_opencode_export(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            rd = Path(td)
            (rd / "result.json").write_text(
                _export(("assistant", [_obj("vulnerable")])),
                encoding="utf-8")
            rec = pa.audit_run_dir(rd, None, extractor="opencode")
            self.assertEqual(rec["status"], pa.AUDIT_STATUS_RECOVERED)
            self.assertEqual(rec["audit_category"], "vulnerable")

    def test_audit_run_dir_probes_result_json(self):
        # even with the default result.jsonl filename, an opencode
        # attempt dir (result.json only) is picked up by probing.
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            rd = Path(td)
            (rd / "result.json").write_text(
                _export(("assistant", [_obj("uncertain")])),
                encoding="utf-8")
            rec = pa.audit_run_dir(
                rd, None, extractor=pa.opencode_terminal_text)
            self.assertEqual(rec["audit_category"], "uncertain")

    def test_unknown_adapter_is_explicit_no_input(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            rd = Path(td)
            (rd / "result.json").write_text(
                _export(("assistant", [_obj()])), encoding="utf-8")
            rec = pa.audit_run_dir(rd, None, extractor="no-such-agent")
            self.assertEqual(rec["status"], pa.AUDIT_STATUS_NO_INPUT)
            self.assertIn("no-such-agent", rec["input_error"])
            self.assertIsNone(rec["audit_category"])

    def test_codex_rule_never_applied_to_export(self):
        # the default extractor on an opencode payload is codex NDJSON:
        # a single-line export event has no agent_message -> explicit
        # no_input, not a misread.
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            rd = Path(td)
            (rd / "result.json").write_text(
                _export(("assistant", [_obj()])), encoding="utf-8")
            rec = pa.audit_run_dir(rd, None)  # default extractor=codex
            self.assertEqual(rec["status"], pa.AUDIT_STATUS_NO_INPUT)
            self.assertIsNotNone(rec["input_error"])


if __name__ == "__main__":
    unittest.main()

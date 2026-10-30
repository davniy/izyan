"""Unit tests for eval/task6/collect.py — v2 attempt finalization +
arm sweep, with the agent-assessment/2 contract.

Run: $HARNESS/.venv/bin/python -m unittest eval.task6.collect_test -v
"""

import json
import sys
import tempfile
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from eval.task6 import assessment_v2 as A2  # noqa: E402
from eval.task6 import collect as C  # noqa: E402


class FakeOpencodeAgent:
    """opencode-shaped stub: result.json session export + stats."""

    def result_filename(self):
        return "result.json"

    def extract_text(self, raw: str) -> str:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return ""
        for m in reversed(data.get("messages", [])):
            if m.get("role") == "assistant":
                for part in reversed(m.get("parts", [])):
                    if part.get("type") == "text" and part.get("text"):
                        return part["text"]
        return ""

    def extract_stats(self, raw: str):
        return types.SimpleNamespace(
            input_tokens=11, cached_input_tokens=3,
            output_tokens=7, reasoning_tokens=2,
        )


def official_parser(text):
    """Stand-in for harness result_parser.parse_category."""
    try:
        obj = json.loads(text)
    except Exception:
        obj = None
    if isinstance(obj, dict) and isinstance(obj.get("category"), str):
        return obj["category"].lower(), obj.get("reasoning")
    return None, None


SAFE_CLAIM = {
    "predicate": "symbol never invoked on the audited path",
    "subject": "pkg/vuln.Vulnerable",
    "scope": "all first-party call paths",
    "evidence_refs": ["src:pkg/vuln.go#L42@abc1234" + "a" * 57],
}


def _assessment_block(claims=None):
    return {
        "mechanisms": [],
        "negative_claims": (
            claims if claims is not None else [SAFE_CLAIM]),
        "unresolved": [],
        "reasoning": "walked the only entrypoint; no path reaches it",
    }


def _export(category="code_not_reachable", reasoning="checked",
            assessment="default"):
    payload = {"category": category, "reasoning": reasoning}
    if assessment == "default":
        payload["assessment"] = _assessment_block()
    elif assessment is not None:
        payload["assessment"] = assessment
    return json.dumps({
        "messages": [
            {"role": "user", "parts": [{"type": "text", "text": "go"}]},
            {"role": "assistant",
             "parts": [{"type": "text", "text": json.dumps(payload)}]},
        ],
    })


def _manifest() -> dict:
    return {
        "schema": "task6-manifest/1",
        "experiment_id": "task6-smoke",
        "model": {"id": "qwen3.6-35b", "model_revision": None},
        "harness": {"commit": "c71f512abc", "dir": "/x"},
        "izyan": {"tool_adapter_version": "izyan-evidence-tools/0.1.0"},
        "tools_binary": {"adapter_version": "izyan-evidence-tools/0.1.0"},
        "dataset": {
            "task_ids": ["o-r-abc1234-CVE-2020-00001"],
            "snapshot_hashes": {"o/r/" + "abc1234" + "0" * 33:
                                {"content_hash": "snapsha"}},
        },
        "prompts": {
            "vuln_safety_v2": {"sha256_12": "d0e7d6ab7a9a"},
            "vuln_safety_v2_tools": {"sha256_12": "8cf6a1f6b0d3"},
        },
        "arms": {
            "p2": {"agent": "opencode-b1p", "prompt": "vuln_safety_v2",
                   "image_suffix": "opencode-gw", "mcp": False},
            "t2": {"agent": "opencode-c1",
                   "prompt": "vuln_safety_v2_tools",
                   "image_suffix": "opencode-c1", "mcp": True},
        },
    }


TASK = {
    "task_id": "o-r-abc1234-CVE-2020-00001",
    "cve_id": "CVE-2020-00001",
    "repo_url": "https://github.com/o/r",
    "commit_sha": "abc1234" + "0" * 33,
    "ground_truth": "not_exploitable",
    "ground_truth_category": "code_not_reachable",
    "metadata": {"language": "go"},
}


def _make_attempt(root: Path, *, mcp: bool,
                  category="code_not_reachable",
                  assessment="default",
                  with_error=False) -> Path:
    run_dir = root / TASK["task_id"] / "run_001"
    (run_dir / "artifacts").mkdir(parents=True)
    (run_dir / "prompt.txt").write_text("rendered prompt")
    if with_error:
        (run_dir / "error.txt").write_text("container timed out\n")
    else:
        (run_dir / "result.json").write_text(
            _export(category, assessment=assessment))
    cfg = {"provider": {"custom-openai": {}}, "agent": {}}
    if mcp:
        cfg["mcp"] = {"izyan": {"type": "local"}}
    (run_dir / "artifacts" / (
        "opencode-config.c1.json" if mcp
        else "opencode-config.b1p.json")).write_text(json.dumps(cfg))
    if mcp:
        audit_dir = run_dir / "artifacts" / "izyan-audit"
        audit_dir.mkdir(parents=True)
        (audit_dir / "tool_calls.jsonl").write_text(
            json.dumps({"tool": "get_vulnerability",
                        "observation": {"tool": "get_vulnerability",
                                        "id": "OBS-0001",
                                        "tool_status": "OK",
                                        "completeness": "COMPLETE"}})
            + "\n"
            + json.dumps({"tool": "run_govulncheck",
                          "observation": {"tool": "run_govulncheck",
                                          "tool_status": "ERROR",
                                          "error": "govulncheck not found"}})
            + "\n")
    return run_dir


class FinalizeArmTest(unittest.TestCase):
    def _finalize(self, root, arm, m):
        return C.finalize_arm(
            root, arm=arm, manifest=m, tasks=[TASK],
            snapshots={}, agent=FakeOpencodeAgent(),
            official_parser=official_parser)

    def test_valid_structured_attempt_finalizes(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "p2" / "task6-smoke"
            run_dir = _make_attempt(root, mcp=False)
            out = self._finalize(root, "p2", _manifest())
            self.assertEqual(out["counts"]["finalized"], 1)
            status = json.loads((run_dir / "status.json").read_text())
            self.assertEqual(status["overall"], "valid")
            self.assertEqual(status["official_parse"], "accepted")
            self.assertEqual(status["assessment_schema"], "valid")
            # status schema is attempt-status/1; the assessment's own
            # schema rides on agent_assessment.json
            self.assertEqual(status["schema_version"], "attempt-status/1")
            asm = json.loads(
                (run_dir / "agent_assessment.json").read_text())
            self.assertEqual(asm["schema_version"],
                             "agent-assessment/2")
            self.assertEqual(asm["meta"]["prompt_version"],
                             "vuln_safety_v2-d0e7d6ab7a9a")
            self.assertEqual(asm["meta"]["snapshot_hash"], "snapsha")
            self.assertEqual(
                asm["assessment"]["negative_claims"][0]["subject"],
                "pkg/vuln.Vulnerable")

    def test_missing_assessment_block_is_invalid_schema(self):
        """Task 6 contract: every attempt must carry the structured
        assessment — absent is an artifact defect, never 'absent'."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "p2" / "task6-smoke"
            run_dir = _make_attempt(root, mcp=False, assessment=None)
            out = self._finalize(root, "p2", _manifest())
            self.assertEqual(out["counts"]["finalized"], 1)
            status = json.loads((run_dir / "status.json").read_text())
            self.assertEqual(status["assessment_schema"], "invalid")
            self.assertIn("missing 'assessment' field",
                          status["detail"])
            self.assertFalse(
                (run_dir / "agent_assessment.json").exists())

    def test_unsafe_category_skips_claim_rule(self):
        """vulnerable/uncertain need no negative_claims — the defect
        rule is scoped to safe categories."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "p2" / "task6-smoke"
            run_dir = _make_attempt(
                root, mcp=False, category="vulnerable",
                assessment={
                    "mechanisms": [
                        {"subject": "pkg/vuln.Parse",
                         "scope": "stdin path",
                         "limitations": []}],
                    "negative_claims": [],
                    "unresolved": [],
                    "reasoning": "PoC reached the sink",
                })
            out = self._finalize(root, "p2", _manifest())
            self.assertEqual(out["counts"]["finalized"], 1)
            status = json.loads((run_dir / "status.json").read_text())
            self.assertEqual(status["assessment_schema"], "valid")

    def test_safe_answer_with_unresolved_is_defect(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "p2" / "task6-smoke"
            bad = _assessment_block()
            bad["unresolved"] = ["never checked the decoder path"]
            run_dir = _make_attempt(root, mcp=False, assessment=bad)
            self._finalize(root, "p2", _manifest())
            status = json.loads((run_dir / "status.json").read_text())
            # extraction surfaces the defect → schema invalid; the
            # artifact-level model rule also refuses, so no assessment
            # file is materialized — the raw answer stays, never
            # rewritten.
            self.assertEqual(status["assessment_schema"], "invalid")
            self.assertIn("unresolved", status["detail"])
            self.assertFalse(
                (run_dir / "agent_assessment.json").exists())

    def test_rerun_skips_finalized(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "p2" / "task6-smoke"
            _make_attempt(root, mcp=False)
            m = _manifest()
            kwargs = dict(arm="p2", manifest=m, tasks=[TASK],
                          snapshots={}, agent=FakeOpencodeAgent(),
                          official_parser=official_parser)
            C.finalize_arm(root, **kwargs)
            again = C.finalize_arm(root, **kwargs)
            self.assertEqual(again["counts"]["skipped_finalized"], 1)
            self.assertEqual(again["counts"]["finalized"], 0)

    def test_error_only_attempt_becomes_failed(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "p2" / "task6-smoke"
            run_dir = _make_attempt(root, mcp=False, with_error=True)
            out = self._finalize(root, "p2", _manifest())
            self.assertEqual(out["counts"]["failed"], 1)
            status = json.loads((run_dir / "status.json").read_text())
            self.assertEqual(status["overall"], "failed")
            self.assertEqual(status["failure_reason"], "timeout")
            self.assertEqual(status["assessment_schema"], "absent")

    def test_t2_audit_copies_and_tool_executions(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "t2" / "task6-smoke"
            run_dir = _make_attempt(root, mcp=True)
            out = self._finalize(root, "t2", _manifest())
            self.assertEqual(out["counts"]["finalized"], 1)
            self.assertTrue((run_dir / "tool_calls.jsonl").exists())
            self.assertTrue((run_dir / "observations.jsonl").exists())
            asm = json.loads(
                (run_dir / "agent_assessment.json").read_text())
            tools = asm["tool_executions"]
            self.assertEqual(len(tools), 2)
            self.assertEqual(tools[0]["observation_id"], "OBS-0001")
            self.assertEqual(tools[1]["tool_status"], "ERROR")
            status = json.loads((run_dir / "status.json").read_text())
            self.assertEqual(status["assessment_schema"], "valid")
            self.assertEqual(status["parser_audit"], "matched")

    def test_unknown_task_not_finalized(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "p2" / "task6-smoke"
            rd = root / "foreign-task" / "run_001"
            rd.mkdir(parents=True)
            (rd / "result.json").write_text(_export())
            out = self._finalize(root, "p2", _manifest())
            self.assertEqual(out["attempts"][0]["collect"],
                             "unknown_task")
            self.assertFalse((rd / "status.json").exists())


class ExtractionPassthroughTest(unittest.TestCase):
    def test_terminal_text_feeds_extraction(self):
        """result.json export → terminal text → v2 extraction: the
        controller materializes raw_agent_output.txt from the agent's
        extract_text, then extracts the assessment from it."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "p2" / "task6-smoke"
            run_dir = _make_attempt(root, mcp=False)
            m = _manifest()
            C.finalize_arm(
                root, arm="p2", manifest=m, tasks=[TASK],
                snapshots={}, agent=FakeOpencodeAgent(),
                official_parser=official_parser)
            raw = (run_dir / "raw_agent_output.txt").read_text()
            obj = json.loads(raw)
            self.assertIn("assessment", obj)
            ext = A2.extract_assessment_v2(raw)
            self.assertEqual(ext.errors, [])
            self.assertEqual(ext.category, "code_not_reachable")
            self.assertEqual(
                ext.assessment.negative_claims[0].subject,
                "pkg/vuln.Vulnerable")


if __name__ == "__main__":
    unittest.main()

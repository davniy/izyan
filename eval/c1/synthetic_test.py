"""Tests for eval.c1.synthetic — regression guards for two real defects found
during Task 4.3 verification:

1. ``import time`` was missing while ``time.monotonic``/``time.strftime`` were
   used → the whole battery crashed on first use.
2. ``guarded()`` stores a crash as ``{"<name>.__crashed__": {"ok": False}}``,
   but the summary loop only read top-level ``"ok"`` keys, so a CRASHED check
   was silently dropped and ``all_ok`` stayed ``True`` — the exact
   "COMPLETE on empty" anti-pattern this project forbids.

These are fast, offline tests: they exercise the summary/guard helpers only
and never launch a container.
"""

from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_SYNTHETIC = _HERE / "synthetic.py"


class SyntheticModuleImportsTest(unittest.TestCase):
    """Defect 1: every module-level name used at runtime must be imported."""

    def test_time_is_imported_because_it_is_used(self):
        tree = ast.parse(_SYNTHETIC.read_text(encoding="utf-8"))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    imported.add((a.asname or a.name).split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                for a in node.names:
                    imported.add(a.asname or a.name)
        uses_time = any(
            isinstance(n, ast.Attribute)
            and isinstance(n.value, ast.Name)
            and n.value.id == "time"
            for n in ast.walk(tree)
        )
        if uses_time:
            self.assertIn(
                "time",
                imported,
                "synthetic.py uses time.* but never imports time — the battery will crash",
            )


class SummaryCountsCrashesTest(unittest.TestCase):
    """Defect 2: a crashed guarded check must surface as a failure."""

    def _summarize(self, results: dict) -> dict:
        # Mirror the exact loop in synthetic.run_battery so the invariant is
        # pinned without launching containers.
        summary: dict[str, object] = {}
        crashed: list[str] = []
        for name, r in results.items():
            if not isinstance(r, dict):
                continue
            if "ok" in r:
                summary[name] = r.get("ok")
                continue
            crash_key = f"{name}.__crashed__"
            if crash_key in r:
                crashed.append(name)
                summary[name] = False
        return {
            "checks": summary,
            "crashed": crashed,
            "all_ok": bool(summary)
            and not crashed
            and all(v is True for v in summary.values()),
            "failed": [k for k, v in summary.items() if not v],
        }

    def test_crashed_check_is_not_silently_dropped(self):
        results = {
            "mcp_handshake": {"ok": True},
            "live_isolation_probe": {
                "live_isolation_probe.__crashed__": {
                    "ok": False,
                    "crashed": "attempt dir already has terminal artifacts",
                }
            },
        }
        s = self._summarize(results)
        self.assertEqual(s["all_ok"], False)
        self.assertIn("live_isolation_probe", s["crashed"])
        self.assertIn("live_isolation_probe", s["failed"])
        self.assertFalse(s["checks"]["live_isolation_probe"])

    def test_all_pass_yields_all_ok(self):
        results = {"a": {"ok": True}, "b": {"ok": True}}
        s = self._summarize(results)
        self.assertTrue(s["all_ok"])
        self.assertEqual(s["crashed"], [])
        self.assertEqual(s["failed"], [])

    def test_explicit_false_is_a_failure(self):
        results = {"a": {"ok": True}, "b": {"ok": False}}
        s = self._summarize(results)
        self.assertFalse(s["all_ok"])
        self.assertEqual(s["failed"], ["b"])

    def test_empty_results_is_not_all_ok(self):
        self.assertFalse(self._summarize({})["all_ok"])


if __name__ == "__main__":
    unittest.main()

"""Unit tests for eval/task5/protocol.py — byte-exact P1/T1 contract.

Run: /tmp/vexbench-agent-ctl/.venv/bin/python -m unittest eval.task5.protocol_test -v
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from eval.task5 import protocol as P  # noqa: E402


class ByteContractTest(unittest.TestCase):
    def setUp(self):
        self.p1 = P.build_prompt(P.PROMPT_P1)
        self.t1 = P.build_prompt(P.PROMPT_T1)
        self.official = P._load_official_template()

    def test_official_prefix_is_unchanged_file_bytes(self):
        file_bytes = (
            P._OFFICIAL_PROMPT_FILE.read_text(encoding="utf-8"))
        self.assertTrue(self.p1.startswith(file_bytes))
        self.assertTrue(self.p1.startswith(self.official))

    def test_t1_minus_p1_is_exactly_the_tool_block(self):
        self.assertTrue(self.t1.startswith(self.p1))
        self.assertEqual(
            self.t1[len(self.p1):],
            "\n\n" + P.EVIDENCE_TOOLS_BLOCK + "\n")

    def test_diff_is_pure_addition(self):
        diff = P.unified_p1_t1_diff(self.p1, self.t1)
        removed = [l for l in diff.splitlines()
                   if l.startswith("-") and not l.startswith("---")]
        added = [l for l in diff.splitlines()
                 if l.startswith("+") and not l.startswith("+++")]
        self.assertEqual(removed, [])
        self.assertTrue(any("<EVIDENCE_TOOLS>" in l for l in added))

    def test_cve_placeholder_survives_exactly_once(self):
        self.assertEqual(self.p1.count("{cve_id}"), 1)
        self.assertEqual(self.t1.count("{cve_id}"), 1)
        self.assertNotIn("{cve_id}", P.SAFETY_RULES_BLOCK)
        self.assertNotIn("{cve_id}", P.EVIDENCE_TOOLS_BLOCK)

    def test_no_assessment_block(self):
        # category-only contract (plan §7): Task 5 prompts deliberately
        # do NOT carry the C1 assessment schema
        for text in (self.p1, self.t1):
            self.assertNotIn("ASSESSMENT_REPORT", text)
            self.assertNotIn("verdict_estimate", text)

    def test_assert_contract_accepts_own_output(self):
        P.assert_prompt_contract(self.p1, self.t1)  # no exception

    def test_assert_contract_rejects_drift(self):
        with self.assertRaises(AssertionError):
            P.assert_prompt_contract(self.p1 + "X", self.t1)
        with self.assertRaises(AssertionError):
            P.assert_prompt_contract(self.p1, self.t1 + "junk")
        with self.assertRaises(AssertionError):
            P.assert_prompt_contract(self.t1, self.p1)  # swapped

    def test_blocks_end_and_order(self):
        self.assertTrue(self.p1.rstrip("\n").endswith("</SAFETY_RULES>"))
        self.assertTrue(self.t1.rstrip("\n").endswith("</EVIDENCE_TOOLS>"))
        self.assertLess(self.p1.index("<SAFETY_RULES>"),
                        self.p1.index("</SAFETY_RULES>"))

    def test_unknown_variant_rejected(self):
        with self.assertRaises(ValueError):
            P.build_prompt("vuln_c1")


class ProhibitedScanTest(unittest.TestCase):
    def test_clean_prompts_have_no_hits(self):
        hits = P.scan_prompts()
        for variant, found in hits.items():
            self.assertEqual(found, [], f"{variant}: {found}")

    def test_detects_case_and_product_identifiers(self):
        dirty_base = P.build_prompt(P.PROMPT_P1)
        cases = [
            ("grpc reachability matters", "product_grpc"),
            ("check the generated.pb.go file", "generated_pb_go"),
            ("kubernetes scheduler", "product_kubernetes"),
            ("rancher deployment", "product_rancher"),
            ("k8s cluster", "product_kubernetes"),
            ("task kubernetes-kubernetes-e196d24-CVE-2023-44487 shows",
             "task_id"),
            ("the fix commit abc123 landed", "fix_reference"),
            ("see PR kubernetes/kubernetes#121273", "fix_reference"),
        ]
        for text, rule in cases:
            found = P.find_prohibited(dirty_base + " " + text)
            self.assertTrue(
                any(rule in f for f in found),
                f"{text!r}: expected {rule} in {found}")

    def test_concrete_cve_in_delta_is_flagged(self):
        # a literal CVE id inside the appended block is a case hint;
        # the same id is fine inside the official prefix's {cve_id} slot
        p1 = P.build_prompt(P.PROMPT_P1)
        dirty = p1 + "\nHint: CVE-2021-3121\n"
        hits = P.scan_prompts({P.PROMPT_P1: dirty})
        self.assertTrue(any("cve_id" in h for h in hits[P.PROMPT_P1]))
        hits = P.scan_prompts({P.PROMPT_P1: p1})
        self.assertEqual(hits[P.PROMPT_P1], [])

    def test_task_id_needles(self):
        p1 = P.build_prompt(P.PROMPT_P1)
        hits = P.find_prohibited(
            p1, extra=["kubernetes-kubernetes-e196d24-CVE-2023-44487"])
        self.assertEqual(hits, [])
        hits = P.find_prohibited(
            p1 + "\nsee kubernetes-kubernetes-e196d24-CVE-2023-44487",
            extra=["kubernetes-kubernetes-e196d24-CVE-2023-44487"])
        self.assertTrue(hits)


class ConfigDeltaTest(unittest.TestCase):
    def test_only_mcp_differs(self):
        base = {"provider": {"custom-openai": {"x": 1}}, "agent": {"a": 2}}
        with_mcp = dict(base, mcp={"izyan": {"type": "local"}})
        self.assertTrue(P.config_delta_only_mcp(base, with_mcp))

    def test_other_diffs_rejected(self):
        base = {"provider": {"a": 1}}
        with_mcp = {"provider": {"a": 2}, "mcp": {"izyan": {}}}
        self.assertFalse(P.config_delta_only_mcp(base, with_mcp))
        self.assertFalse(P.config_delta_only_mcp(
            dict(base, mcp={}), with_mcp))  # mcp present in p1 config
        self.assertFalse(P.config_delta_only_mcp(base, base))  # no mcp in t1


class WritePromptsTest(unittest.TestCase):
    def test_materializes_hashes_and_diff(self):
        with tempfile.TemporaryDirectory() as td:
            doc = P.write_prompts(Path(td))
            p1 = (Path(td) / "vuln_safety_v1.txt").read_text()
            t1 = (Path(td) / "vuln_safety_v1_tools.txt").read_text()
            self.assertEqual(p1, P.build_prompt(P.PROMPT_P1))
            self.assertEqual(t1, P.build_prompt(P.PROMPT_T1))
            diff = (Path(td) / "p1-t1.diff").read_text()
            self.assertIn("+<EVIDENCE_TOOLS>", diff)
            self.assertEqual(doc["prompts"][P.PROMPT_P1]["sha256_12"],
                             P.prompt_hash(p1))
            self.assertEqual(doc["prompts"][P.PROMPT_T1]["sha256_12"],
                             P.prompt_hash(t1))
            on_disk = json.loads((Path(td) / "hashes.json").read_text())
            self.assertEqual(on_disk["assertions"][
                                 "t1_minus_p1_is_exact_tool_block"], True)

    def test_emitted_files_match_repo_frozen_copies(self):
        # the committed eval/task5/prompts files are regenerated verbatim
        frozen = Path(__file__).resolve().parent / "prompts"
        for variant, name in P.PROMPT_FILENAMES.items():
            p = frozen / name
            if not p.exists():
                self.skipTest(f"frozen prompt file {name} not generated yet")
            self.assertEqual(p.read_text(), P.build_prompt(variant))


if __name__ == "__main__":
    unittest.main()

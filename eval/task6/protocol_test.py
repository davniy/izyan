"""Unit tests for eval/task6/protocol.py — byte-exact P2/T2 contract.

Run: $HARNESS/.venv/bin/python -m unittest eval.task6.protocol_test -v
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from eval.c1.protocol import EVIDENCE_TOOLS_BLOCK as C1_TOOLS  # noqa: E402
from eval.task5 import protocol as T5  # noqa: E402
from eval.task6 import protocol as P  # noqa: E402


class ByteContractTest(unittest.TestCase):
    def setUp(self):
        self.p2 = P.build_prompt(P.PROMPT_P2)
        self.t2 = P.build_prompt(P.PROMPT_T2)
        self.official = P._load_official_template()

    def test_p2_prefix_is_unchanged_official_file_bytes(self):
        file_bytes = (
            P._OFFICIAL_PROMPT_FILE.read_text(encoding="utf-8"))
        self.assertTrue(
            self.p2.startswith(file_bytes),
            "official file bytes are not an unchanged prefix of P2")
        self.assertTrue(self.p2.startswith(self.official))

    def test_p2_block_order(self):
        i_safety = self.p2.index("<SAFETY_RULES>")
        i_struct = self.p2.index("<STRUCTURED_ASSESSMENT>")
        self.assertLess(i_safety, i_struct)
        self.assertTrue(
            self.p2.rstrip("\n").endswith("</STRUCTURED_ASSESSMENT>"))

    def test_t2_minus_p2_is_exactly_the_task6_tool_block(self):
        self.assertTrue(self.t2.startswith(self.p2))
        self.assertEqual(
            self.t2[len(self.p2):],
            "\n\n" + P.EVIDENCE_TOOLS_BLOCK_TASK6 + "\n")
        # task6-local copy of the C1 binding-rules block (F6): not the
        # C1 object itself, not Task 5's short API note
        self.assertNotEqual(P.EVIDENCE_TOOLS_BLOCK_TASK6, C1_TOOLS)
        self.assertNotEqual(
            P.EVIDENCE_TOOLS_BLOCK_TASK6, T5.EVIDENCE_TOOLS_BLOCK)

    def test_tools_block_uses_v2_field_names(self):
        """F6: the T2 tools block must cite agent-assessment/2 field
        names — the v1 claims[]/evidence[] names do not exist in this
        experiment's contract."""
        block = P.EVIDENCE_TOOLS_BLOCK_TASK6
        self.assertIn("assessment.negative_claims[].evidence_refs",
                      block)
        self.assertNotIn("claims[].evidence_refs or", block)
        self.assertNotIn("evidence[]", block)
        # everything else stays identical to the C1 binding-rules text
        for rule in ('tool_status "OK" with an EMPTY result',
                     'completeness="COMPLETE"', 'completeness="PARTIAL"',
                     'completeness="UNKNOWN"', 'tool_status "ERROR"',
                     '"UNSUPPORTED"', 'scope_details is authoritative'):
            self.assertIn(rule, block)

    def test_t2_carries_all_p2_blocks(self):
        for marker in ("<SAFETY_RULES>", "<STRUCTURED_ASSESSMENT>",
                       "<EVIDENCE_TOOLS>"):
            self.assertIn(marker, self.t2)
        self.assertIn("<STRUCTURED_ASSESSMENT>", self.p2)
        self.assertNotIn("<EVIDENCE_TOOLS>", self.p2)

    def test_safety_rules_block_is_task5_verbatim(self):
        self.assertIs(P.SAFETY_RULES_BLOCK, T5.SAFETY_RULES_BLOCK)
        self.assertIn(P.SAFETY_RULES_BLOCK, self.p2)

    def test_diff_is_pure_addition(self):
        diff = P.unified_p2_t2_diff(self.p2, self.t2)
        removed = [l for l in diff.splitlines()
                   if l.startswith("-") and not l.startswith("---")]
        added = [l for l in diff.splitlines() if l.startswith("+")]
        self.assertEqual(removed, [])
        self.assertTrue(any("<EVIDENCE_TOOLS>" in l for l in added))

    def test_cve_placeholder_survives_exactly_once(self):
        self.assertEqual(self.p2.count("{cve_id}"), 1)
        self.assertEqual(self.t2.count("{cve_id}"), 1)
        self.assertNotIn("{cve_id}", P.EVIDENCE_TOOLS_BLOCK_TASK6)
        self.assertNotIn("{cve_id}", P.STRUCTURED_ASSESSMENT_BLOCK)
        self.assertNotIn("{cve_id}", P.SAFETY_RULES_BLOCK)

    def test_no_c1_assessment_block(self):
        # Task 6 carries the new <STRUCTURED_ASSESSMENT> contract —
        # the C1 <ASSESSMENT_REPORT> schema must NOT appear.
        for text in (self.p2, self.t2):
            self.assertNotIn("ASSESSMENT_REPORT", text)
            self.assertNotIn("verdict_estimate", text)

    def test_structured_block_names_spec_fields(self):
        block = P.STRUCTURED_ASSESSMENT_BLOCK
        for field in ('"mechanisms"', '"negative_claims"',
                      '"unresolved"', '"reasoning"', '"predicate"',
                      '"subject"', '"scope"', '"evidence_refs"',
                      '"limitations"', '"assessment"'):
            self.assertIn(field, block)
        for ref_form in ("ev:OBS", "src:", "sha256:", "file:", "url:"):
            self.assertIn(ref_form, block)

    def test_assert_contract_accepts_own_output(self):
        P.assert_prompt_contract(self.p2, self.t2)  # no exception

    def test_assert_contract_rejects_drift(self):
        with self.assertRaises(AssertionError):
            P.assert_prompt_contract(self.p2 + "\nextra", self.t2)
        with self.assertRaises(AssertionError):
            P.assert_prompt_contract(self.t2, self.p2)  # swapped

    def test_unknown_variant_rejected(self):
        with self.assertRaises(ValueError):
            P.build_prompt("vuln_safety_v1")
        with self.assertRaises(ValueError):
            P.build_prompt("vuln_c1")


class ProhibitedScanTest(unittest.TestCase):
    def test_clean_prompts_have_no_hits(self):
        prompts = {v: P.build_prompt(v) for v in P.PROMPT_FILENAMES}
        hits = P.scan_prompts(prompts)
        for variant, found in hits.items():
            self.assertEqual(found, [], f"{variant}: {found}")

    def test_no_case_or_product_identifiers_in_blocks(self):
        delta_p2 = P.build_prompt(P.PROMPT_P2)[len(P._load_official_template()):]
        delta_t2 = P.build_prompt(P.PROMPT_T2)[len(P._load_official_template()):]
        for delta in (delta_p2, delta_t2):
            # benchmark task-id / product-name / fix-id patterns —
            # scan over the appended delta only
            for probe in ("CVE-", "GHSA-", "grpc", "rancher", ".pb.go"):
                self.assertNotIn(probe, delta)
        self.assertNotIn("kubernetes", delta_p2.lower())

    def test_task_id_needles(self):
        p2 = P.build_prompt(P.PROMPT_P2)
        hits = P.find_prohibited(
            p2, extra=["kubernetes-kubernetes-e196d24-CVE-2023-44487"])
        self.assertEqual(hits, [])
        hits = P.find_prohibited(
            p2 + "\nsee kubernetes-kubernetes-e196d24-CVE-2023-44487",
            extra=["kubernetes-kubernetes-e196d24-CVE-2023-44487"])
        self.assertTrue(hits)


class ConfigDeltaTest(unittest.TestCase):
    """config_delta_only_mcp: the T2 opencode config must equal P2's
    plus exactly one top-level ``mcp`` key (plan §7 acceptance)."""

    def test_only_mcp_differs(self):
        base = {"provider": {"custom-openai": {"x": 1}}, "agent": {"a": 2}}
        with_mcp = dict(base, mcp={"izyan": {"type": "local"}})
        self.assertTrue(P.config_delta_only_mcp(base, with_mcp))

    def test_other_diffs_rejected(self):
        base = {"provider": {"a": 1}}
        with_mcp = {"provider": {"a": 2}, "mcp": {"izyan": {}}}
        self.assertFalse(P.config_delta_only_mcp(base, with_mcp))
        self.assertFalse(P.config_delta_only_mcp(
            dict(base, mcp={}), with_mcp))   # mcp present in p2 config
        self.assertFalse(P.config_delta_only_mcp(base, base))


class WritePromptsTest(unittest.TestCase):
    def test_materializes_hashes_and_diff(self):
        with tempfile.TemporaryDirectory() as td:
            doc = P.write_prompts(Path(td))
            p2 = (Path(td) / "vuln_safety_v2.txt").read_text()
            t2 = (Path(td) / "vuln_safety_v2_tools.txt").read_text()
            self.assertEqual(p2, P.build_prompt(P.PROMPT_P2))
            self.assertEqual(t2, P.build_prompt(P.PROMPT_T2))
            diff = (Path(td) / "p2-t2.diff").read_text()
            self.assertIn("+<EVIDENCE_TOOLS>", diff)
            self.assertNotIn("\n-", diff.split("@@", 1)[-1])
            self.assertEqual(doc["prompts"][P.PROMPT_P2]["sha256_12"],
                             P.prompt_hash(p2))
            self.assertEqual(doc["prompts"][P.PROMPT_T2]["sha256_12"],
                             P.prompt_hash(t2))
            on_disk = json.loads((Path(td) / "hashes.json").read_text())
            self.assertTrue(on_disk["assertions"]
                            ["p2_prefix_is_official_file_bytes"])
            self.assertTrue(on_disk["assertions"]
                            ["t2_minus_p2_is_exact_tool_block"])
            # hashes.json is internally consistent with the diff+files
            self.assertEqual(doc["diff_file"], "p2-t2.diff")
            for v, info in doc["prompts"].items():
                text = (Path(td) / info["file"]).read_text()
                import hashlib
                self.assertEqual(
                    hashlib.sha256(text.encode()).hexdigest(),
                    info["sha256"])

    def test_emitted_files_match_repo_frozen_copies(self):
        frozen = Path(__file__).resolve().parent / "prompts"
        for variant, name in P.PROMPT_FILENAMES.items():
            p = frozen / name
            if not p.exists():
                self.skipTest(f"frozen prompt file {name} not generated yet")
            self.assertEqual(p.read_text(), P.build_prompt(variant))


if __name__ == "__main__":
    unittest.main()

"""Unit tests for eval/c1/protocol.py — prompt composition and drift.

Run: /tmp/vexbench-agent-ctl/.venv/bin/python -m unittest eval.c1.protocol_test -v
"""

import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from eval.c1 import protocol as P  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
PROMPT_DIR = REPO / "eval" / "vexbench-prompts"

FROZEN_B1_SHA256 = "c0a5c8458b77015d57b82eefca563d01c870ea027562381715c8ab9d70ffabda"


class FrozenBaseTest(unittest.TestCase):
    def test_official_template_hash_unchanged(self):
        text = P._load_official_template()
        self.assertEqual(
            hashlib.sha256(text.encode()).hexdigest(), FROZEN_B1_SHA256,
            "frozen B1 template drifted — derived prompts are no longer "
            "a clean additive delta",
        )

    def test_b1_prefix_of_both_variants(self):
        base = P._load_official_template()
        for variant in (P.PROMPT_B1_PRIME, P.PROMPT_C1):
            self.assertTrue(build := P.build_prompt(variant))
            self.assertTrue(
                build.startswith(base),
                f"{variant}: frozen prompt must be the verbatim prefix",
            )

    def test_unknown_variant_rejected(self):
        with self.assertRaises(ValueError):
            P.build_prompt("vuln")


class BlockContentTest(unittest.TestCase):
    def test_b1_prime_has_no_tool_block(self):
        p = P.build_prompt(P.PROMPT_B1_PRIME)
        self.assertIn("<ASSESSMENT_REPORT>", p)
        self.assertNotIn("<EVIDENCE_TOOLS>", p)
        self.assertNotIn("izyan", p)

    def test_c1_has_both_blocks(self):
        p = P.build_prompt(P.PROMPT_C1)
        self.assertIn("<ASSESSMENT_REPORT>", p)
        self.assertIn("<EVIDENCE_TOOLS>", p)
        self.assertIn('"izyan"', p)

    def test_no_case_specific_hints(self):
        # Spec §10: these benchmark traps must never appear in prompts.
        banned = ["rancher", "47914", "44487", "podman", "48795",
                  "k8s-3121", "3121", "istio", "cilium", "echo-fdacff0"]
        for variant in (P.PROMPT_B1_PRIME, P.PROMPT_C1):
            text = P.build_prompt(variant).lower()
            for word in banned:
                self.assertNotIn(word, text, f"{variant} leaks case hint {word}")

    def test_category_estimate_mapping_in_block(self):
        p = P.build_prompt(P.PROMPT_C1)
        self.assertIn('"EXPLOITABLE"', p)
        self.assertIn('"INCONCLUSIVE"', p)
        self.assertIn('"NOT_AFFECTED"', p)
        self.assertIn('"NO_EXPLOIT_PATH_FOUND"', p)

    def test_metadata_prohibition_declared(self):
        p = P.build_prompt(P.PROMPT_C1)
        self.assertIn("Do NOT include task ids", p)


class FrozenPromptFilesTest(unittest.TestCase):
    """The files under eval/vexbench-prompts/ must match this module —
    drift means the harness prompts.py copy is no longer reproducible."""

    def _frozen(self, variant):
        files = sorted(PROMPT_DIR.glob(f"{variant}-*.txt"))
        self.assertEqual(len(files), 1, f"expected exactly one frozen {variant} file")
        return files[0]

    def test_b1_prime_file_matches_module(self):
        f = self._frozen(P.PROMPT_B1_PRIME)
        self.assertEqual(f.read_text(), P.build_prompt(P.PROMPT_B1_PRIME))
        self.assertIn(P.prompt_hash(P.build_prompt(P.PROMPT_B1_PRIME)), f.name)

    def test_c1_file_matches_module(self):
        f = self._frozen(P.PROMPT_C1)
        self.assertEqual(f.read_text(), P.build_prompt(P.PROMPT_C1))
        self.assertIn(P.prompt_hash(P.build_prompt(P.PROMPT_C1)), f.name)


class CveExtractionTest(unittest.TestCase):
    def test_extracts_cve_from_rendered_prompt(self):
        rendered = P.build_prompt(P.PROMPT_C1).replace("{cve_id}", "CVE-2024-24790")
        self.assertEqual(P.extract_cve_id(rendered), "CVE-2024-24790")

    def test_extracts_go_advisory_id(self):
        rendered = "<CVE>\nGO-2024-2611\n</CVE>"
        self.assertEqual(P.extract_cve_id(rendered), "GO-2024-2611")

    def test_ghsa_id(self):
        self.assertEqual(
            P.extract_cve_id("<CVE>GHSA-33mj-cw25-m34x</CVE>"),
            "GHSA-33mj-cw25-m34x",
        )

    def test_no_tag_returns_none(self):
        self.assertIsNone(P.extract_cve_id("no cve here"))


if __name__ == "__main__":
    unittest.main()

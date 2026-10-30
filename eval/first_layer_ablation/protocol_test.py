"""Unit tests for the first-layer ablation prompt protocol (Task 1).

Run: python -m unittest eval.first_layer_ablation.protocol_test -v
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import re
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO_ROOT))

from eval.first_layer_ablation import protocol as P  # noqa: E402

CVE_ID = "CVE-2023-44487"
ADVISORY_TEXT = P._ADVISORY_FILE.read_text(encoding="utf-8")
FROZEN_AT = "2026-10-24T00:00:00Z"

# The single case fixed by the plan; this is a fixture for the protocol
# test, not a substitute for Task 2's snapshot preflight.
CASE = {
    "task_id": "kubernetes-kubernetes-e196d24-CVE-2023-44487",
    "cve_id": CVE_ID,
    "repo_url": "https://local.invalid/research",
    "commit_sha": "e196d2491087e93bd29f0e5a538aab60667021e3",
    "language": "go",
    "snapshot_path": (
        "<VA_VEXBENCH>/repos/kubernetes/kubernetes/"
        "e196d2491087e93bd29f0e5a538aab60667021e3"
    ),
    "snapshot_sha256": None,
}

# Representative shared runtime.  Nulls are intentional: unexposed facts
# stay null and are listed in the manifest's limitations, never invented.
RUNTIME = {
    "model": {
        "id": P.MODEL_ID,
        "alias": P.MODEL_ALIAS,
        "provider": P.PROVIDER,
        "provider_model_id": P.PROVIDER_MODEL_ID,
        "revision": None,
    },
    "endpoint": {
        "base_url": None,
        "provider_endpoint": P.PROVIDER,
        "transport": "openai-compatible",
    },
    "image": {
        "tag": "vex-bench-go-opencode-c1:latest",
        "digest": None,
        "same_digest_all_arms": True,
    },
    "parameters": {
        "temperature": None,
        "top_p": None,
        "max_output_tokens": None,
    },
    "native_tools": ["read", "glob", "grep"],
    "permissions": {"shell": False, "network": False, "edit": False},
}


class FrozenSourcesTest(unittest.TestCase):
    def test_official_template_matches_task5_hash_convention(self):
        raw = P._OFFICIAL_PROMPT_FILE.read_text(encoding="utf-8")
        self.assertEqual(
            hashlib.sha256(raw.encode("utf-8")).hexdigest(),
            P.FROZEN_OFFICIAL_SHA256,
        )
        self.assertEqual(
            hashlib.sha256(raw.strip().encode("utf-8")).hexdigest(),
            P.FROZEN_OFFICIAL_SHA256,
        )
        # The frozen file has no leading/trailing whitespace, so arm A can
        # use its raw bytes and still satisfy the Task 5 stripped convention.
        self.assertEqual(raw, raw.strip())

    def test_r0_v1_hash_matches_saved_agent7_manifest(self):
        raw = P._R0_V1_PROMPT_FILE.read_text(encoding="utf-8")
        self.assertEqual(
            hashlib.sha256(raw.encode("utf-8")).hexdigest(),
            P.FROZEN_R0_V1_SHA256,
        )

    def test_advisory_hash_matches_saved_agent7_manifest(self):
        raw = P._ADVISORY_FILE.read_text(encoding="utf-8")
        self.assertEqual(
            hashlib.sha256(raw.encode("utf-8")).hexdigest(),
            P.FROZEN_ADVISORY_SHA256,
        )

    def test_official_template_has_exactly_one_cve_placeholder(self):
        self.assertEqual(
            P._load_official_template().count("{cve_id}"), 1
        )


class ArmConstructionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.arms = P.build_arms(CVE_ID, ADVISORY_TEXT)

    # --- A: exact control -------------------------------------------------

    def test_a_is_exact_frozen_prompt_with_only_cve_substitution(self):
        official = P._load_official_template()
        self.assertEqual(
            self.arms["A"], official.replace("{cve_id}", CVE_ID)
        )
        self.assertEqual(
            self.arms["A"].replace(CVE_ID, "{cve_id}"), official
        )
        self.assertEqual(self.arms["A"].count(CVE_ID), 1)

    def test_a_has_no_use_based_verdict(self):
        self.assertNotIn("USE_BASED_VERDICT", self.arms["A"])

    def test_a_has_no_assessment_content(self):
        lowered = self.arms["A"].lower()
        self.assertNotIn("assessment", lowered)
        for token in P._ASSESSMENT_TOKENS:
            with self.subTest(token=token):
                self.assertNotIn(token.lower(), lowered)

    def test_a_has_no_advisory_binding_rules(self):
        for token in P._BINDING_TOKENS:
            with self.subTest(token=token):
                self.assertIsNone(
                    re.search(re.escape(token), self.arms["A"],
                              re.IGNORECASE)
                )

    def test_a_has_no_tool_instructions(self):
        for token in P._TOOL_TOKENS:
            with self.subTest(token=token):
                self.assertIsNone(
                    re.search(token, self.arms["A"], re.IGNORECASE)
                )

    def test_a_has_no_prohibited_hits(self):
        self.assertEqual(P.find_prohibited(self.arms["A"], arm="A"), [])

    def test_assert_control_prompt_accepts_a_and_rejects_drift(self):
        P.assert_control_prompt(self.arms["A"], CVE_ID)  # no exception
        with self.assertRaises(AssertionError):
            P.assert_control_prompt(self.arms["A"] + "\nassessment", CVE_ID)
        with self.assertRaises(AssertionError):
            P.assert_control_prompt(
                self.arms["A"].replace(CVE_ID, "CVE-2020-0001"), CVE_ID
            )

    # --- B/C/D/E: one block each -----------------------------------------

    def test_b_adds_only_the_frozen_advisory_as_data(self):
        suffix = self.arms["B"][len(self.arms["A"]):]
        self.assertTrue(self.arms["B"].startswith(self.arms["A"]))
        self.assertEqual(suffix, "\n\n" + P.advisory_block(ADVISORY_TEXT))
        self.assertIn(ADVISORY_TEXT.strip(), self.arms["B"])
        self.assertNotIn("<ADVISORY_BINDING_RULES>", self.arms["B"])
        self.assertNotIn("<RESEARCH_ASSESSMENT>", self.arms["B"])
        self.assertNotIn("<EVIDENCE_TOOLS>", self.arms["B"])

    def test_c_adds_only_the_semantic_binding_rules(self):
        suffix = self.arms["C"][len(self.arms["B"]):]
        self.assertTrue(self.arms["C"].startswith(self.arms["B"]))
        self.assertEqual(
            suffix, "\n\n" + P.ADVISORY_BINDING_RULES_BLOCK
        )
        self.assertNotIn("<RESEARCH_ASSESSMENT>", self.arms["C"])
        self.assertNotIn("<EVIDENCE_TOOLS>", self.arms["C"])

    def test_d_adds_only_the_extended_assessment(self):
        suffix = self.arms["D"][len(self.arms["C"]):]
        self.assertTrue(self.arms["D"].startswith(self.arms["C"]))
        self.assertEqual(suffix, "\n\n" + P.ASSESSMENT_BLOCK)
        self.assertNotIn("<EVIDENCE_TOOLS>", self.arms["D"])

    def test_e_adds_only_the_izyan_tool_description(self):
        suffix = self.arms["E"][len(self.arms["D"]):]
        self.assertTrue(self.arms["E"].startswith(self.arms["D"]))
        self.assertEqual(suffix, "\n\n" + P.IZYAN_TOOLS_BLOCK)
        self.assertIn("<EVIDENCE_TOOLS>", self.arms["E"])
        self.assertIn("izyan", self.arms["E"])
        self.assertIn("tool_status", self.arms["E"])

    def test_every_adjacent_pair_differs_by_one_declared_treatment(self):
        blocks = P.treatment_blocks(ADVISORY_TEXT)
        for previous, current in zip(P.ARM_ORDER, P.ARM_ORDER[1:]):
            with self.subTest(pair=(previous, current)):
                self.assertTrue(
                    self.arms[current].startswith(self.arms[previous])
                )
                self.assertEqual(
                    len(P.ARM_TREATMENTS[current])
                    - len(P.ARM_TREATMENTS[previous]),
                    1,
                )
                treatment = P.ARM_TREATMENTS[current][-1]
                self.assertEqual(
                    self.arms[current][len(self.arms[previous]):],
                    "\n\n" + blocks[treatment],
                )

    def test_each_treatment_block_appears_exactly_once_per_arm(self):
        blocks = P.treatment_blocks(ADVISORY_TEXT)
        for arm in P.ARM_ORDER:
            for treatment in P.ARM_TREATMENTS[arm]:
                with self.subTest(arm=arm, treatment=treatment):
                    self.assertEqual(
                        self.arms[arm].count(blocks[treatment]), 1
                    )

    def test_assert_arm_contract_accepts_own_output(self):
        P.assert_arm_contract(self.arms, CVE_ID, ADVISORY_TEXT)

    def test_assert_arm_contract_rejects_appended_text(self):
        bad = dict(self.arms)
        bad["E"] = bad["E"] + "\n\nunexpected"
        with self.assertRaises(AssertionError):
            P.assert_arm_contract(bad, CVE_ID, ADVISORY_TEXT)

    def test_assert_arm_contract_rejects_missing_treatment(self):
        bad = dict(self.arms)
        bad["C"] = bad["B"]
        with self.assertRaises(AssertionError):
            P.assert_arm_contract(bad, CVE_ID, ADVISORY_TEXT)

    def test_assert_arm_contract_rejects_swapped_arms(self):
        bad = dict(self.arms)
        bad["B"], bad["C"] = bad["C"], bad["B"]
        with self.assertRaises(AssertionError):
            P.assert_arm_contract(bad, CVE_ID, ADVISORY_TEXT)

    def test_assert_arm_contract_rejects_missing_or_extra_arm(self):
        missing = {k: v for k, v in self.arms.items() if k != "D"}
        with self.assertRaises(AssertionError):
            P.assert_arm_contract(missing, CVE_ID, ADVISORY_TEXT)
        extra = dict(self.arms)
        extra["F"] = "x"
        with self.assertRaises(AssertionError):
            P.assert_arm_contract(extra, CVE_ID, ADVISORY_TEXT)

    def test_invalid_inputs_are_rejected(self):
        with self.assertRaises(ValueError):
            P.build_arms("not-a-cve", ADVISORY_TEXT)
        with self.assertRaises(ValueError):
            P.build_arms(CVE_ID, "")
        with self.assertRaises(ValueError):
            P.build_arms(CVE_ID, '{"x":"</ADVISORY>"}')


class BindingSplitTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.arms = P.build_arms(CVE_ID, ADVISORY_TEXT)
        cls.binding_source = P._extract_tagged_block(
            P._load_r0_v1(), "ADVISORY_BINDING_RULES"
        )
        _, cls.binding_rules = P._split_numbered_rules(
            cls.binding_source, "ADVISORY_BINDING_RULES"
        )

    def test_c_contains_the_semantic_rules_verbatim(self):
        for number in P.SEMANTIC_BINDING_RULES:
            with self.subTest(rule=number):
                self.assertIn(
                    self.binding_rules[number], self.arms["C"]
                )

    def test_c_excludes_the_assessment_shape_rules(self):
        for number in P.EXCLUDED_BINDING_RULES:
            with self.subTest(rule=number):
                self.assertNotIn(
                    self.binding_rules[number], self.arms["C"]
                )
        self.assertNotIn("For every section you cannot resolve",
                         self.arms["C"])
        self.assertNotIn("Keep the existing `category`", self.arms["C"])

    def test_c_has_no_assessment_sections_or_tokens(self):
        lowered = self.arms["C"].lower()
        self.assertNotIn("assessment", lowered)
        for token in P._ASSESSMENT_TOKENS:
            with self.subTest(token=token):
                self.assertNotIn(token.lower(), lowered)
        self.assertNotIn("<RESEARCH_ASSESSMENT>", self.arms["C"])
        self.assertNotIn("<EVIDENCE_TOOLS>", self.arms["C"])

    def test_assessment_block_is_r0_v1_with_only_the_stale_lead_replaced(self):
        source = P._extract_tagged_block(
            P._load_r0_v1(), "RESEARCH_ASSESSMENT"
        )
        self.assertEqual(
            P.ASSESSMENT_BLOCK,
            source.replace(
                P._ASSESSMENT_STALE_LEAD, P._ASSESSMENT_CURRENT_LEAD
            ),
        )
        self.assertIn(P._ASSESSMENT_STALE_LEAD, source)
        self.assertNotIn("B1", P.ASSESSMENT_BLOCK)
        self.assertIn(
            "All preceding instructions remain in force",
            P.ASSESSMENT_BLOCK,
        )
        self.assertTrue(self.arms["D"].endswith(P.ASSESSMENT_BLOCK))
        # Every other line of the frozen block is untouched.
        for line in source.splitlines():
            if "B1" in line:
                continue
            with self.subTest(line=line[:60]):
                self.assertIn(line, P.ASSESSMENT_BLOCK)

    def test_d_has_all_eight_assessment_sections(self):
        sections = (
            "vulnerability_mechanism",
            "root_cause",
            "attack_scenario",
            "product_exposure",
            "alternative_paths",
            "evidence_quality",
            "residual_questions",
            "triage_recommendation",
        )
        for section in sections:
            with self.subTest(section=section):
                self.assertIn("- `{}`:".format(section), self.arms["D"])

    def test_e_inherits_the_assessment_but_not_vice_versa(self):
        self.assertIn("<RESEARCH_ASSESSMENT>", self.arms["E"])
        self.assertNotIn("<RESEARCH_ASSESSMENT>", self.arms["C"])
        self.assertNotIn("<EVIDENCE_TOOLS>", self.arms["D"])


class ProhibitedScanTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.arms = P.build_arms(CVE_ID, ADVISORY_TEXT)

    def test_no_hits_in_any_arm(self):
        for arm in P.ARM_ORDER:
            with self.subTest(arm=arm):
                self.assertEqual(
                    P.find_prohibited(self.arms[arm], arm=arm), []
                )

    def test_sanctioned_cve_and_advisory_regions_are_exempt(self):
        # A contains the case CVE by design.
        self.assertIn(CVE_ID, self.arms["A"])
        # B's advisory contains both Kubernetes and gRPC references; the
        # scan must not treat sanctioned advisory data as a case hint.
        self.assertIn("kubernetes", ADVISORY_TEXT.lower())
        self.assertIn("grpc", ADVISORY_TEXT.lower())
        self.assertEqual(P.find_prohibited(self.arms["A"], arm="A"), [])
        self.assertEqual(P.find_prohibited(self.arms["B"], arm="B"), [])

    def test_scan_is_not_vacuous_for_ground_truth(self):
        hits = P.find_prohibited(
            self.arms["A"] + "\nUSE_BASED_VERDICT", arm="A"
        )
        self.assertIn("ground_truth:USE_BASED_VERDICT", hits)
        hits = P.find_prohibited(
            self.arms["A"] + "\nexpected category: vulnerable", arm="A"
        )
        self.assertIn("ground_truth:expected_answer", hits)

    def test_scan_is_not_vacuous_for_a_case_hint_outside_inputs(self):
        hits = P.find_prohibited(
            self.arms["A"] + "\nthe kubernetes fix", arm="A"
        )
        self.assertIn("case_hint:product_kubernetes", hits)

    def test_scan_detects_a_treatment_leak(self):
        cases = {
            ("B", "ADVISORY_BINDING_RULES"): "binding:",
            ("C", "assessment"): "assessment:",
            ("D", "MCP"): "tools:",
        }
        for (arm, injected), prefix in cases.items():
            with self.subTest(arm=arm, injected=injected):
                hits = P.find_prohibited(
                    self.arms[arm] + "\n" + injected, arm=arm
                )
                self.assertTrue(
                    any(hit.startswith(prefix) for hit in hits),
                    "expected a {} hit, got {}".format(prefix, hits),
                )


class RequestShapeTest(unittest.TestCase):
    """The full request, including any adapter-injected system message."""

    @classmethod
    def setUpClass(cls):
        cls.arms = P.build_arms(CVE_ID, ADVISORY_TEXT)

    def test_protocol_emits_no_system_message(self):
        self.assertEqual(P.PROTOCOL_SYSTEM_MESSAGES, ())
        self.assertEqual(
            P.request_messages(self.arms["A"]),
            [{"role": "user", "content": self.arms["A"]}],
        )

    def test_request_record_without_system_message(self):
        record = P.request_record(self.arms["A"])
        self.assertEqual(record["system_message_count"], 0)
        self.assertEqual(record["system_prompt_sha256"], [])
        self.assertEqual(
            record["messages"],
            [{"role": "user", "content": self.arms["A"]}],
        )
        self.assertEqual(
            record["user_prompt_sha256"], P.sha256_text(self.arms["A"])
        )
        self.assertEqual(
            record["full_request_sha256"],
            P.sha256_text(P.canonical_json(
                [{"role": "user", "content": self.arms["A"]}]
            )),
        )

    def test_request_record_includes_adapter_system_messages(self):
        system = {
            "role": "system",
            "content": "adapter-injected system prompt",
        }
        record = P.request_record(
            self.arms["A"], system_messages=[system]
        )
        self.assertEqual(record["system_message_count"], 1)
        self.assertEqual(
            record["messages"],
            [system, {"role": "user", "content": self.arms["A"]}],
        )
        self.assertEqual(
            record["system_prompt_sha256"],
            [P.sha256_text(system["content"])],
        )
        self.assertNotEqual(
            record["full_request_sha256"],
            P.request_record(self.arms["A"])["full_request_sha256"],
        )

    def test_request_record_rejects_bad_inputs(self):
        with self.assertRaises(ValueError):
            P.request_record(
                self.arms["A"],
                system_messages=[{"role": "user", "content": "x"}],
            )
        with self.assertRaises(ValueError):
            P.request_record(
                self.arms["A"],
                system_messages=[{"role": "system", "content": ""}],
            )
        with self.assertRaises(TypeError):
            P.request_record(
                self.arms["A"], system_messages=["not-a-mapping"]
            )
        with self.assertRaises(ValueError):
            P.request_record("")


class ManifestTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.arms = P.build_arms(CVE_ID, ADVISORY_TEXT)
        cls.manifest = P.build_manifest(
            case=CASE,
            advisory_path=P._ADVISORY_FILE,
            runtime=RUNTIME,
            frozen_at_utc=FROZEN_AT,
        )

    def test_schema_experiment_and_case_are_pinned(self):
        self.assertEqual(self.manifest["schema"], P.MANIFEST_SCHEMA)
        self.assertEqual(
            self.manifest["experiment_id"], P.EXPERIMENT_ID
        )
        self.assertEqual(self.manifest["frozen_at_utc"], FROZEN_AT)
        self.assertEqual(self.manifest["case"], CASE)

    def test_prompt_records_match_the_rendered_arms(self):
        for arm in P.ARM_ORDER:
            record = self.manifest["prompts"][arm]
            with self.subTest(arm=arm):
                self.assertEqual(
                    record["sha256"], P.sha256_text(self.arms[arm])
                )
                self.assertEqual(
                    record["sha256_12"], P.prompt_hash(self.arms[arm])
                )
                self.assertEqual(
                    record["bytes"], len(self.arms[arm].encode("utf-8"))
                )
                self.assertEqual(
                    record["lines"], self.arms[arm].count("\n") + 1
                )
                self.assertEqual(
                    record["treatments"], list(P.ARM_TREATMENTS[arm])
                )
                self.assertEqual(
                    record["agent"], P.ARM_RUNTIME[arm]["agent"]
                )
                self.assertEqual(
                    record["mcp"], P.ARM_RUNTIME[arm]["mcp"]
                )

    def test_source_hashes_are_pinned(self):
        sources = self.manifest["sources"]
        self.assertEqual(
            sources["official_vex_template"]["sha256"],
            P.FROZEN_OFFICIAL_SHA256,
        )
        self.assertEqual(
            sources["official_vex_template"]["sha256_stripped"],
            P.FROZEN_OFFICIAL_SHA256,
        )
        self.assertEqual(
            sources["r0_v1_prompt"]["sha256"], P.FROZEN_R0_V1_SHA256
        )
        self.assertTrue(
            sources["advisory"]["is_frozen_experiment_source"]
        )
        self.assertEqual(
            sources["advisory"]["sha256"], P.FROZEN_ADVISORY_SHA256
        )
        self.assertEqual(
            sources["advisory"]["frozen_sha256"], P.FROZEN_ADVISORY_SHA256
        )
        # Observed canonical hash of the frozen advisory JSON.
        self.assertEqual(
            sources["advisory"]["canonical_json_sha256"],
            "83b852adcd9c692f0712f070359449161ac7883ff4b292d6a8d18b3873da1599",
        )

    def test_treatment_block_hashes_match_the_rendered_blocks(self):
        blocks = P.treatment_blocks(ADVISORY_TEXT)
        self.assertEqual(
            set(self.manifest["treatment_blocks"]), set(blocks)
        )
        for name, block in blocks.items():
            record = self.manifest["treatment_blocks"][name]
            with self.subTest(block=name):
                self.assertEqual(record["sha256"], P.sha256_text(block))
                self.assertEqual(
                    record["bytes"], len(block.encode("utf-8"))
                )
                self.assertTrue(record["source"])

    def test_schedule_is_repeat_major_and_complete(self):
        schedule = self.manifest["schedule"]
        self.assertEqual(len(schedule), 15)
        self.assertEqual(
            [item["index"] for item in schedule], list(range(1, 16))
        )
        self.assertEqual(
            [item["arm"] for item in schedule],
            list(P.ARM_ORDER) * P.ATTEMPT_POLICY["repeats"],
        )
        self.assertEqual(
            Counter(item["arm"] for item in schedule),
            Counter({arm: P.ATTEMPT_POLICY["repeats"]
                     for arm in P.ARM_ORDER}),
        )
        keys = [(item["arm"], item["repeat"]) for item in schedule]
        self.assertEqual(len(keys), len(set(keys)))
        for repeat in range(1, P.ATTEMPT_POLICY["repeats"] + 1):
            self.assertEqual(
                [item["arm"] for item in schedule
                 if item["repeat"] == repeat],
                list(P.ARM_ORDER),
            )
        self.assertEqual(
            self.manifest["schedule_sha256"],
            P.sha256_text(P.canonical_json(schedule)),
        )

    def test_attempt_policy_is_the_frozen_plan_policy(self):
        policy = self.manifest["attempt_policy"]
        self.assertEqual(policy["timeout_seconds"], 1800)
        self.assertEqual(policy["repeats"], 3)
        self.assertEqual(policy["parallel"], 1)
        self.assertEqual(policy["retries"], 0)
        self.assertEqual(policy["cache_admission"], "forbidden")
        self.assertEqual(policy, P.ATTEMPT_POLICY)

    def test_arm_runtime_equality_contract(self):
        for arm in ("A", "B", "C", "D"):
            self.assertEqual(
                self.manifest["prompts"][arm]["agent"],
                "opencode-c1-nomcp",
            )
            self.assertFalse(self.manifest["prompts"][arm]["mcp"])
        self.assertEqual(
            self.manifest["prompts"]["E"]["agent"], "opencode-c1"
        )
        self.assertTrue(self.manifest["prompts"]["E"]["mcp"])
        self.assertEqual(
            self.manifest["equality_contract"]["arm_delta"],
            {"E": ["agent", "mcp"]},
        )
        self.assertEqual(
            self.manifest["equality_contract"]["runtime_image_suffix"],
            P.RUNTIME_IMAGE_SUFFIX,
        )
        self.assertEqual(
            self.manifest["equality_contract"]["runtime_pipeline"],
            P.RUNTIME_PIPELINE,
        )
        self.assertEqual(P.RUNTIME_IMAGE_SUFFIX, "opencode-c1")
        self.assertEqual(
            P.RUNTIME_PIPELINE, "opencode-run-export/v1"
        )
        self.assertTrue(
            self.manifest["equality_contract"]
            ["same_image_digest_all_arms"]
        )
        self.assertEqual(
            self.manifest["runtime_sha256"],
            P.sha256_text(P.canonical_json(self.manifest["runtime"])),
        )

    def test_request_capture_records_the_full_prompt_shape(self):
        capture = self.manifest["request_capture"]
        self.assertEqual(capture["protocol_system_messages"], [])
        self.assertEqual(capture["user_messages_per_attempt"], 1)
        self.assertEqual(capture["message_roles"], ["user"])
        self.assertEqual(
            capture["recorder"],
            "protocol.request_record(prompt, "
            "system_messages=<adapter-injected messages>)",
        )
        self.assertEqual(
            capture["full_prompt_sha256"],
            {arm: P.sha256_text(self.arms[arm]) for arm in P.ARM_ORDER},
        )
        self.assertEqual(
            P.request_messages(self.arms["A"]),
            [{"role": "user", "content": self.arms["A"]}],
        )

    def test_validation_records_clean_arms(self):
        self.assertTrue(self.manifest["validation"]["control_exact"])
        self.assertTrue(
            self.manifest["validation"]["adjacent_deltas_exact"]
        )
        self.assertTrue(
            self.manifest["validation"]
            ["c_has_only_semantic_binding_rules"]
        )
        for arm in P.ARM_ORDER:
            self.assertEqual(
                self.manifest["validation"]["prohibited_hits"][arm], []
            )

    def test_limitations_stay_explicit(self):
        limitations = " ".join(self.manifest["limitations"])
        self.assertIn("Single-case diagnostic", limitations)
        self.assertIn("runtime.image.digest is None", limitations)
        self.assertIn("case.snapshot_sha256 is None", limitations)
        self.assertIn("No system message", limitations)
        self.assertIn("legacy C1 benchmark runtime", limitations)
        self.assertIn("NOT the E6 sandbox", limitations)
        self.assertIn("E6 is not weakened", limitations)

    def test_manifest_has_no_credential_markers(self):
        blob = json.dumps(self.manifest).lower()
        for marker in ("api_key", "api-key", "password", "bearer "):
            with self.subTest(marker=marker):
                self.assertNotIn(marker, blob)

    def test_self_hash_verifies(self):
        self.assertTrue(P.verify_manifest(self.manifest))
        self.assertEqual(
            self.manifest["manifest_sha256"],
            P.manifest_sha256(self.manifest),
        )

    def test_verify_rejects_a_tampered_hash(self):
        bad = copy.deepcopy(self.manifest)
        bad["prompts"]["A"]["sha256"] = "0" * 64
        with self.assertRaises(AssertionError):
            P.verify_manifest(bad)

    def test_verify_rejects_a_resealed_prompt_tamper(self):
        bad = copy.deepcopy(self.manifest)
        bad["prompts"]["A"]["sha256"] = "0" * 64
        resealed = P.seal_manifest(bad)
        with self.assertRaises(AssertionError):
            P.verify_manifest(resealed)

    def test_write_manifest_round_trip_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            P.write_manifest(path, self.manifest)
            loaded = json.loads(path.read_text(encoding="utf-8"))
            P.verify_manifest(loaded)
            # Identical freeze is idempotent.
            P.write_manifest(path, self.manifest)
            other = P.build_manifest(
                case=CASE,
                advisory_path=P._ADVISORY_FILE,
                runtime=RUNTIME,
                frozen_at_utc="2026-10-24T00:00:01Z",
            )
            with self.assertRaises(FileExistsError):
                P.write_manifest(path, other)

    def test_build_manifest_rejects_a_wrong_model(self):
        bad = copy.deepcopy(RUNTIME)
        bad["model"]["id"] = "gpt-4"
        bad["model"]["alias"] = "gpt-4"
        bad["model"]["provider_model_id"] = "openai/gpt-4"
        with self.assertRaises(ValueError):
            P.build_manifest(
                case=CASE,
                advisory_path=P._ADVISORY_FILE,
                runtime=bad,
                frozen_at_utc=FROZEN_AT,
            )

    def test_build_manifest_rejects_credentials(self):
        bad = copy.deepcopy(RUNTIME)
        bad["model"]["api_key"] = "should-never-be-recorded"
        with self.assertRaises(ValueError):
            P.build_manifest(
                case=CASE,
                advisory_path=P._ADVISORY_FILE,
                runtime=bad,
                frozen_at_utc=FROZEN_AT,
            )

    def test_build_manifest_rejects_mcp_as_a_shared_permission(self):
        bad = copy.deepcopy(RUNTIME)
        bad["permissions"]["mcp"] = True
        with self.assertRaises(ValueError):
            P.build_manifest(
                case=CASE,
                advisory_path=P._ADVISORY_FILE,
                runtime=bad,
                frozen_at_utc=FROZEN_AT,
            )

    def test_build_manifest_requires_the_single_digest_contract(self):
        bad = copy.deepcopy(RUNTIME)
        bad["image"]["same_digest_all_arms"] = False
        with self.assertRaises(ValueError):
            P.build_manifest(
                case=CASE,
                advisory_path=P._ADVISORY_FILE,
                runtime=bad,
                frozen_at_utc=FROZEN_AT,
            )

    def test_build_manifest_rejects_a_mismatched_advisory(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "advisory.json"
            path.write_text(json.dumps({
                "id": "GHSA-test-0000-0000",
                "aliases": ["CVE-2020-0001"],
                "affected": [],
            }), encoding="utf-8")
            with self.assertRaises(ValueError):
                P.build_manifest(
                    case=CASE,
                    advisory_path=path,
                    runtime=RUNTIME,
                    frozen_at_utc=FROZEN_AT,
                )

    def test_cli_writes_prompts_and_a_verifiable_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            case_path = directory / "case.json"
            runtime_path = directory / "runtime.json"
            case_path.write_text(json.dumps(CASE), encoding="utf-8")
            runtime_path.write_text(json.dumps(RUNTIME), encoding="utf-8")
            output_dir = directory / "out"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = P.main([
                    "--output-dir", str(output_dir),
                    "--case", str(case_path),
                    "--advisory", str(P._ADVISORY_FILE),
                    "--runtime", str(runtime_path),
                    "--frozen-at", FROZEN_AT,
                ])
            self.assertEqual(code, 0)
            summary = json.loads(stdout.getvalue())
            manifest = json.loads(
                (output_dir / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertTrue(P.verify_manifest(manifest))
            self.assertEqual(
                summary["manifest_sha256"], manifest["manifest_sha256"]
            )
            for arm in P.ARM_ORDER:
                with self.subTest(arm=arm):
                    self.assertEqual(
                        (output_dir / "arm-{}.txt".format(arm))
                        .read_text(encoding="utf-8"),
                        self.arms[arm],
                    )


if __name__ == "__main__":
    unittest.main()

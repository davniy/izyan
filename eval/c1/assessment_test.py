"""Unit tests for eval/c1/assessment.py — schema, consistency, refs, stamping.

Run from the vexbench harness venv (pydantic v2), repo root:
    /tmp/vexbench-agent-ctl/.venv/bin/python -m unittest eval.c1.assessment_test -v
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from eval.c1 import assessment as A  # noqa: E402


VALID_PAYLOAD = {
    "root_causes": ["verifyServeConn processes unauthenticated CONNECT"],
    "mandatory_conditions": ["attacker can reach the agent API"],
    "claims": [
        {
            "statement": "package github.com/x/y is declared in go.mod",
            "verdict": "TRUE",
            "evidence_refs": ["file:go.mod:12"],
        },
        {
            "statement": "no product caller reaches Vulnerable()",
            "verdict": "UNKNOWN",
            "evidence_refs": ["ev:callers:find_callers@vulnFunc@0123456789abcdef"],
        },
    ],
    "evidence": ["file:go.mod:12", "src:pkg/http/server.go#L42",
                 "url:https://osv.dev/vulnerability/GHSA-1"],
    "limitations": ["interface dispatch not fully enumerated"],
    "unresolved_questions": ["is the agent socket exposed externally?"],
    "counterexample_review": {
        "checked": ["searched for transitive dep-internal callers",
                    "checked build-tagged refs"],
        "still_unknown": ["plugin-loaded callers"],
    },
    "verdict_estimate": "NO_EXPLOIT_PATH_FOUND",
}

META = {
    "experiment_id": "exp-c1-001",
    "task_id": "proj-12345",
    "attempt_id": "run_001",
    "cve_id": "CVE-2024-1234",
    "snapshot_hash": "deadbeef" * 8,
    "model": "gpt-6.1-sol",
    "prompt_version": "vuln_c1-abcdef012345",
    "harness_version": "vexbench-agent-ctl@1135cbb",
    "tool_adapter_version": "izyan@7953410",
}


def payload(**over):
    p = json.loads(json.dumps(VALID_PAYLOAD))
    p.update(over)
    return p


def final_json(category="code_not_reachable", assessment=None, reasoning="evidence"):
    obj = {
        "category": category,
        "reasoning": reasoning,
        "assessment": assessment if assessment is not None else payload(),
    }
    return json.dumps(obj)


class PayloadSchemaTest(unittest.TestCase):
    def test_valid_payload_parses(self):
        p = A.AssessmentPayload.model_validate(VALID_PAYLOAD)
        self.assertEqual(p.verdict_estimate, "NO_EXPLOIT_PATH_FOUND")
        self.assertEqual(len(p.claims), 2)

    def test_missing_required_fields_rejected(self):
        for key in ("root_causes", "claims", "counterexample_review", "verdict_estimate"):
            with self.subTest(missing=key):
                bad = payload()
                del bad[key]
                with self.assertRaises(Exception):
                    A.AssessmentPayload.model_validate(bad)

    def test_empty_root_causes_rejected(self):
        with self.assertRaises(Exception):
            A.AssessmentPayload.model_validate(payload(root_causes=[]))

    def test_empty_claims_rejected(self):
        with self.assertRaises(Exception):
            A.AssessmentPayload.model_validate(payload(claims=[]))

    def test_unknown_extra_field_rejected(self):
        with self.assertRaises(Exception):
            A.AssessmentPayload.model_validate(payload(sneaky_field="x"))

    def test_safe_estimate_requires_counterexample_content(self):
        bad = payload(counterexample_review={"checked": [], "still_unknown": []})
        with self.assertRaises(Exception):
            A.AssessmentPayload.model_validate(bad)
        bad2 = payload(counterexample_review={"checked": ["   "], "still_unknown": []})
        with self.assertRaises(Exception):
            A.AssessmentPayload.model_validate(bad2)

    def test_positive_estimate_does_not_require_checked(self):
        p = payload(
            verdict_estimate="EXPLOITABLE",
            counterexample_review={"checked": [], "still_unknown": ["none needed"]},
        )
        A.AssessmentPayload.model_validate(p)  # must not raise


class EvidenceRefTest(unittest.TestCase):
    def test_accepted_ref_forms(self):
        for ref in (
            "ev:callers:find_callers@vulnFunc@0123456789abcdef",
            "file:pkg/http/server.go",
            "file:pkg/http/server.go:142",
            "file:pkg/http/server.go:10-20",
            "url:https://osv.dev/vulnerability/GHSA-xxxx",
        ):
            with self.subTest(ref=ref):
                A._check_ref(ref)

    def test_rejected_ref_forms(self):
        for ref in (
            "",
            "see the code",
            "ev:missing-hash",
            "file:",
            "url:ftp://bad",
            "file:path with spaces.go:1",
        ):
            with self.subTest(ref=ref):
                with self.assertRaises(ValueError):
                    A._check_ref(ref)

    def test_bad_ref_in_claim_rejected(self):
        bad = payload(
            claims=[{"statement": "s", "verdict": "TRUE", "evidence_refs": ["bogus"]}]
        )
        with self.assertRaises(Exception):
            A.AssessmentPayload.model_validate(bad)


class CategoryEstimateConsistencyTest(unittest.TestCase):
    def _asm(self, category, estimate):
        p = payload(verdict_estimate=estimate)
        ext = A.ExtractionResult(
            category=category, reasoning="r", assessment=A.AssessmentPayload.model_validate(p)
        )
        return A.build_assessment(ext, A.AttemptMeta(**META), [])

    def test_vulnerable_requires_exploitable(self):
        asm, defects = self._asm("vulnerable", "NOT_AFFECTED")
        self.assertIsNone(asm)
        self.assertTrue(any("inconsistent" in d for d in defects))

    def test_vulnerable_with_exploitable_ok(self):
        asm, _ = self._asm("vulnerable", "EXPLOITABLE")
        self.assertIsNotNone(asm)
        self.assertEqual(asm.category, "vulnerable")

    def test_uncertain_requires_inconclusive(self):
        asm, defects = self._asm("uncertain", "NO_EXPLOIT_PATH_FOUND")
        self.assertIsNone(asm)
        self.assertTrue(any("inconsistent" in d for d in defects))
        asm2, _ = self._asm("uncertain", "INCONCLUSIVE")
        self.assertIsNotNone(asm2)

    def test_safe_categories_take_safe_estimates(self):
        for cat in ("code_not_present", "code_not_reachable", "requires_configuration"):
            for est in ("NOT_AFFECTED", "NO_EXPLOIT_PATH_FOUND"):
                asm, defects = self._asm(cat, est)
                self.assertIsNotNone(asm, f"{cat}/{est}: {defects}")
        asm, defects = self._asm("code_not_reachable", "EXPLOITABLE")
        self.assertIsNone(asm)

    def test_invalid_category_rejected(self):
        p = A.AssessmentPayload.model_validate(VALID_PAYLOAD)
        ext = A.ExtractionResult(
            category="probably_fine", reasoning="r", assessment=p
        )
        asm, defects = A.build_assessment(ext, A.AttemptMeta(**META), [])
        self.assertIsNone(asm)
        self.assertTrue(defects)


class ExtractionTest(unittest.TestCase):
    def test_extract_full_object(self):
        ext = A.extract_assessment(final_json())
        self.assertEqual(ext.category, "code_not_reachable")
        self.assertIsNotNone(ext.assessment)
        self.assertEqual(ext.errors, [])

    def test_braces_inside_reasoning_recovered(self):
        # The known harness parser defect: brace-counting breaks on {}
        # inside string literals; the audit decoder must recover the object.
        obj = {
            "category": "vulnerable",
            "reasoning": 'code: if skippy < 0 { x() } else { y() } — {"k":1}',
            "assessment": payload(verdict_estimate="EXPLOITABLE"),
        }
        text = json.dumps(obj)
        ext = A.extract_assessment(text)
        self.assertEqual(ext.category, "vulnerable")
        self.assertIsNotNone(ext.assessment)
        self.assertEqual(ext.errors, [])

    def test_missing_assessment_flagged(self):
        ext = A.extract_assessment('{"category":"vulnerable","reasoning":"r"}')
        self.assertIsNotNone(ext.category)
        self.assertIsNone(ext.assessment)
        self.assertTrue(any("assessment" in e for e in ext.errors))

    def test_reserved_controller_keys_rejected(self):
        bad = payload(model="self-claimed", cost_usd=0.01)
        ext = A.extract_assessment(final_json(assessment=bad))
        self.assertIsNone(ext.assessment)
        self.assertTrue(any("controller-reserved" in e for e in ext.errors))

    def test_prose_without_json(self):
        ext = A.extract_assessment("the classification is requires_configuration")
        self.assertIsNone(ext.category)
        self.assertTrue(ext.errors)

    def test_consistency_error_reported_on_extract(self):
        ext = A.extract_assessment(final_json(category="vulnerable"))  # payload estimate safe
        self.assertIsNotNone(ext.assessment)
        self.assertTrue(any("inconsistent" in e for e in ext.errors))


class AuditValidationTest(unittest.TestCase):
    AUDIT = [
        {
            "tool": "find_callers",
            "args": {"symbol": "vulnFunc"},
            "duration_ms": 12,
            "observation": {
                "id": "obs-1",
                "tool_status": "OK",
                "completeness": "PARTIAL",
                "evidence_refs": [
                    "ev:callers:find_callers@vulnFunc@0123456789abcdef",
                    "src:pkg/http/server.go#L42",
                ],
            },
        }
    ]

    def test_known_ev_ref_resolves(self):
        p = A.AssessmentPayload.model_validate(VALID_PAYLOAD)
        self.assertEqual(A.validate_evidence_refs(p, self.AUDIT), [])

    def test_invented_ev_ref_flagged(self):
        bad = payload(
            claims=[
                {
                    "statement": "s",
                    "verdict": "TRUE",
                    "evidence_refs": ["ev:callers:x@y@ffffffffffffffff"],
                }
            ]
        )
        p = A.AssessmentPayload.model_validate(bad)
        defects = A.validate_evidence_refs(p, self.AUDIT)
        self.assertEqual(len(defects), 1)
        self.assertIn("not found in attempt audit", defects[0])

    def test_tool_executions_projected_from_audit(self):
        execs = A.tool_executions_from_audit(self.AUDIT)
        self.assertEqual(len(execs), 1)
        self.assertEqual(execs[0].tool, "find_callers")
        self.assertEqual(execs[0].completeness, "PARTIAL")
        self.assertEqual(execs[0].observation_id, "obs-1")
        self.assertIsNotNone(execs[0].args_sha256)


class StampingTest(unittest.TestCase):
    def test_metadata_stamped_from_meta_not_model(self):
        ext = A.extract_assessment(final_json())
        asm, defects = A.build_assessment(ext, A.AttemptMeta(**META), self._audit())
        self.assertIsNotNone(asm, defects)
        self.assertEqual(asm.meta.model, "gpt-6.1-sol")
        self.assertEqual(asm.meta.task_id, "proj-12345")
        self.assertEqual(asm.schema_version, "agent-assessment/1")
        # agent never sets usage; controller defaults tool_calls to audit count
        self.assertEqual(asm.usage.tool_calls, 1)

    def _audit(self):
        return AuditValidationTest.AUDIT


class ArtifactWriteTest(unittest.TestCase):
    def _make_asm(self):
        ext = A.extract_assessment(final_json())
        asm, _ = A.build_assessment(ext, A.AttemptMeta(**META), [])
        assert asm is not None
        return asm

    def test_write_then_duplicate_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            run_dir = Path(td)
            asm = self._make_asm()
            A.write_assessment_artifact(run_dir, asm)
            with self.assertRaises(A.DuplicateAttemptError):
                A.write_assessment_artifact(run_dir, asm)

    def test_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            asm = self._make_asm()
            path = A.write_assessment_artifact(Path(td), asm)
            loaded = A.AgentAssessment.model_validate_json(path.read_text())
            self.assertEqual(loaded.meta.attempt_id, "run_001")
            self.assertEqual(loaded.category, "code_not_reachable")


if __name__ == "__main__":
    unittest.main()

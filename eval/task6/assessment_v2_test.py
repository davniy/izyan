"""Unit tests for eval/task6/assessment_v2.py — agent-assessment/2 schema.

Asserts (plan §7 acceptance): valid payloads accepted; unknown keys,
bad refs, reserved controller keys rejected; a safe ``category``
requires negative claims with non-empty ``evidence_refs``; extraction
recovers the assessment from terminal text with trailing prose.

Run: $HARNESS/.venv/bin/python -m unittest eval.task6.assessment_v2_test -v
"""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pydantic import ValidationError  # noqa: E402

from eval.task6 import assessment_v2 as A  # noqa: E402

_SHA = "a" * 64
_OTHER_SHA = "b" * 64


def _payload(**over):
    """A minimal VALID safe-verdict assessment payload."""
    base = {
        "mechanisms": [],
        "negative_claims": [
            {
                "predicate": "unreachable: no product call site reaches "
                             "the affected symbol",
                "subject": "vendor.example.com/dep/vuln.Fn",
                "scope": "product packages, default build tags",
                "evidence_refs": [
                    f"src:/work/dep/vuln.go#L42@{_SHA}",
                    "file:/work/notes/a.go:12-14",
                ],
            }
        ],
        "unresolved": [],
        "reasoning": "checked static and may-call sites of the symbol",
    }
    base.update(over)
    return base


def _terminal(payload=None, category="code_not_reachable",
              reasoning="callers searched, none found", **extra):
    obj = {"category": category, "reasoning": reasoning}
    if payload is not None:
        obj["assessment"] = payload
    obj.update(extra)
    return json.dumps(obj)


def _meta(**over):
    base = dict(
        experiment_id="task6",
        task_id="case-x-CVE-0000-00000",
        attempt_id="run_001",
        cve_id="CVE-0000-00000",
        snapshot_hash=_SHA,
        model="model-x",
        model_revision=None,
        prompt_version="vuln_safety_v2-abc123abc123",
        harness_version="h",
        tool_adapter_version="izyan-evidence-tools/0.1.0",
        image=None,
    )
    base.update(over)
    return A.AttemptMeta(**base)


class PayloadSchemaTest(unittest.TestCase):
    def test_valid_payload_accepted(self):
        p = A.AssessmentPayloadV2.model_validate(_payload())
        self.assertEqual(len(p.negative_claims), 1)
        self.assertEqual(p.mechanisms, [])

    def test_full_payload_accepted(self):
        p = A.AssessmentPayloadV2.model_validate(_payload(
            mechanisms=[{
                "subject": "vendor.example.com/dep/vuln.Fn",
                "scope": "reachable only via yaml unmarshal path",
                "limitations": ["entrypoint set not fully enumerated"],
            }],
            unresolved=["dep-internal call chain not enumerated"],
        ))
        self.assertEqual(len(p.mechanisms), 1)
        self.assertEqual(len(p.unresolved), 1)

    def test_unknown_top_level_key_rejected(self):
        with self.assertRaises(ValidationError):
            A.AssessmentPayloadV2.model_validate(
                _payload(score=0.9))

    def test_unknown_nested_key_rejected(self):
        bad = _payload()
        bad["negative_claims"][0]["confidence"] = "high"
        with self.assertRaises(ValidationError):
            A.AssessmentPayloadV2.model_validate(bad)
        bad = _payload(mechanisms=[{
            "subject": "s", "scope": "x", "verdict": "safe"}])
        with self.assertRaises(ValidationError):
            A.AssessmentPayloadV2.model_validate(bad)

    def test_empty_required_fields_rejected(self):
        for field in ("predicate", "subject", "scope"):
            bad = _payload()
            bad["negative_claims"][0][field] = ""
            with self.assertRaises(ValidationError, msg=field):
                A.AssessmentPayloadV2.model_validate(bad)
        with self.assertRaises(ValidationError):
            A.AssessmentPayloadV2.model_validate(_payload(reasoning=""))

    def test_mechanism_fields_required(self):
        with self.assertRaises(ValidationError):
            A.AssessmentPayloadV2.model_validate(
                _payload(mechanisms=[{"subject": "s"}]))  # no scope


class EvidenceRefGrammarTest(unittest.TestCase):
    def _accepts(self, ref):
        A.NegativeClaim(
            predicate="p", subject="s", scope="x",
            evidence_refs=[ref], limitations=[])

    def _rejects(self, ref):
        with self.assertRaises(ValidationError, msg=ref):
            self._accepts(ref)

    def test_live_and_bound_forms_accepted(self):
        for ref in (
            "ev:OBS-0007",
            "ev:OBS-12345",
            f"src:/work/pkg/f.go#L142@{_SHA}",
            "src:/work/vendor/x/y.go#L693",          # live tool form
            "src:pkg/f.go#L1",
            "sha256:" + "0" * 64,
            "file:pkg/http/server.go:142",
            "file:pkg/http/server.go:10-20",
            "file:README.md",
            "url:https://osv.dev/vulnerability/GHSA-xxxx-yyyy-zzzz",
        ):
            self._accepts(ref)

    def test_bad_refs_rejected(self):
        for ref in (
            "ev:OBS-1",                    # too few digits (live form OBS-NNNN)
            "ev:obs-0007",                 # case-sensitive minted prefix
            "ev:artifact:callers@0123456789abcdef",  # C1 reserved form ≠ v2
            "src:/work/f.go",              # live form always carries #L
            "src:/work/f.go:L10",          # missing # marker
            "src:/work/f.go#Lx",           # non-numeric line
            f"src:/work/f.go#L10@{_SHA[:16]}",       # truncated hash
            "src:/work/f.go#L10@",         # empty hash
            "sha256:" + "0" * 63,          # short digest
            "sha256:" + "G" * 64,          # non-hex
            "url:http://example.com/x",    # plan grammar: https only
            "OBS-0007",                    # missing scheme
            "",                            # empty
            "/work/f.go#L10",              # missing scheme
        ):
            self._rejects(ref)

    def test_split_src_ref(self):
        self.assertEqual(
            A.split_src_ref(f"src:/w/f.go#L10@{_SHA}"),
            ("/w/f.go", 10, _SHA))
        self.assertEqual(A.split_src_ref("src:/w/f.go#L10"),
                         ("/w/f.go", 10, None))
        self.assertEqual(A.split_src_ref("src:/w/f.go"),
                         ("/w/f.go", None, None))
        self.assertIsNone(A.split_src_ref("file:/w/f.go"))


class SafeCategoryRuleTest(unittest.TestCase):
    """A safe category requires ≥1 negative claim with non-empty
    evidence_refs; safe + non-empty unresolved is a defect."""

    def _artifact(self, category, payload):
        res = A.ExtractionResultV2(
            category=category, reasoning="r",
            assessment=A.AssessmentPayloadV2.model_validate(payload))
        return A.build_assessment_v2(res, _meta(), [])

    def test_safe_with_bound_claim_accepted(self):
        asm, defects = self._artifact("code_not_reachable", _payload())
        self.assertIsNotNone(asm)
        self.assertEqual(defects, [])

    def test_safe_without_claims_rejected(self):
        res = A.extract_assessment_v2(
            _terminal(_payload(negative_claims=[])))
        self.assertIsNotNone(res.assessment)      # schema still valid
        self.assertTrue(any("negative_claim" in e for e in res.errors))
        # and the stamped artifact refuses too
        with self.assertRaises(ValidationError):
            A.AgentAssessmentV2(
                meta=_meta(), category="code_not_reachable",
                reasoning="r",
                assessment=A.AssessmentPayloadV2.model_validate(
                    _payload(negative_claims=[])))

    def test_safe_with_empty_evidence_refs_rejected(self):
        bad = _payload()
        bad["negative_claims"][0]["evidence_refs"] = []
        res = A.extract_assessment_v2(_terminal(bad))
        self.assertTrue(any("evidence_refs" in e for e in res.errors))

    def test_safe_with_unresolved_rejected(self):
        res = A.extract_assessment_v2(
            _terminal(_payload(unresolved=["dep-internal calls not checked"])))
        self.assertTrue(any("unresolved" in e for e in res.errors))

    def test_vulnerable_and_uncertain_need_no_claims(self):
        for cat in ("vulnerable", "uncertain"):
            res = A.extract_assessment_v2(_terminal(
                _payload(negative_claims=[]), category=cat))
            self.assertEqual(res.errors, [], cat)
            asm, defects = self._artifact(
                cat, _payload(negative_claims=[]))
            self.assertIsNotNone(asm, cat)


class ExtractionTest(unittest.TestCase):
    def test_recovers_assessment_with_trailing_prose(self):
        text = (
            "Here is my final answer.\n"
            + _terminal(_payload())
            + "\nNote: the dependency graph was enumerated from modules.txt "
            "and I did not re-run the build."
        )
        res = A.extract_assessment_v2(text)
        self.assertEqual(res.errors, [])
        self.assertEqual(res.category, "code_not_reachable")
        self.assertIsNotNone(res.assessment)
        self.assertEqual(res.assessment.negative_claims[0].predicate,
                         _payload()["negative_claims"][0]["predicate"])

    def test_recovers_from_fenced_json(self):
        text = "done:\n```json\n" + _terminal(_payload()) + "\n```"
        res = A.extract_assessment_v2(text)
        self.assertIsNotNone(res.assessment)
        self.assertEqual(res.errors, [])

    def test_no_object(self):
        res = A.extract_assessment_v2("no json here")
        self.assertIsNone(res.assessment)
        self.assertTrue(res.errors)

    def test_missing_assessment_field(self):
        res = A.extract_assessment_v2(
            _terminal(None))  # {category, reasoning} only — the Task-5 shape
        self.assertIsNone(res.assessment)
        self.assertTrue(any("assessment" in e for e in res.errors))
        self.assertEqual(res.category, "code_not_reachable")

    def test_assessment_not_an_object(self):
        res = A.extract_assessment_v2(
            _terminal("not-an-object"))
        self.assertIsNone(res.assessment)
        self.assertTrue(res.errors)

    def test_reserved_controller_keys_rejected(self):
        for key in ("schema_version", "task_id", "model",
                    "snapshot_hash", "usage", "tool_executions"):
            bad = _payload(**{key: "x"})
            res = A.extract_assessment_v2(_terminal(bad))
            self.assertIsNone(res.assessment, key)
            self.assertTrue(any("reserved" in e for e in res.errors), key)

    def test_category_must_be_one_of_12(self):
        res = A.extract_assessment_v2(_terminal(_payload(), category="safe"))
        self.assertTrue(any("category" in e for e in res.errors))
        with self.assertRaises(ValidationError):
            A.AgentAssessmentV2(
                meta=_meta(), category="safe", reasoning="r",
                assessment=A.AssessmentPayloadV2.model_validate(_payload()))


class AuditCrossCheckTest(unittest.TestCase):
    def _audit(self):
        return [
            {"tool": "find_callers",
             "observation": {"id": "OBS-0006",
                             "evidence_refs": ["sha256:" + "0" * 64,
                                               "src:/work/dep/vuln.go#L42"]}},
            {"tool": "get_vulnerability",
             "observation": {"id": "OBS-0001", "evidence_refs": []}},
        ]

    def _payload_with(self, refs):
        bad = _payload()
        bad["negative_claims"][0]["evidence_refs"] = refs
        return A.AssessmentPayloadV2.model_validate(bad)

    def test_resolvable_refs_pass(self):
        p = self._payload_with([
            "ev:OBS-0006", "sha256:" + "0" * 64,
            "src:/work/dep/vuln.go#L42",
            f"src:/work/dep/vuln.go#L42@{_SHA}",
            "file:/work/a.go:1", "url:https://x.example/adv",
        ])
        self.assertEqual(A.validate_evidence_refs_v2(
            p, self._audit(), snapshot_hash=_SHA), [])

    def test_dangling_observation_id(self):
        p = self._payload_with(["ev:OBS-9999"])
        d = A.validate_evidence_refs_v2(p, self._audit())
        self.assertTrue(any("OBS-9999" in x for x in d))

    def test_dangling_sha256(self):
        p = self._payload_with(["sha256:" + "f" * 64])
        d = A.validate_evidence_refs_v2(p, self._audit())
        self.assertTrue(d)

    def test_unminted_src_ref(self):
        p = self._payload_with(["src:/work/other.go#L1"])
        d = A.validate_evidence_refs_v2(p, self._audit())
        self.assertTrue(d)

    def test_agent_bound_src_hash_checked(self):
        p = self._payload_with([f"src:/work/dep/vuln.go#L42@{_OTHER_SHA}"])
        d = A.validate_evidence_refs_v2(
            p, self._audit(), snapshot_hash=_SHA)
        self.assertTrue(any("snapshot" in x for x in d))

    def test_empty_audit_accepts_file_and_url_only(self):
        p = self._payload_with(["file:/w/a.go", "url:https://x"])
        self.assertEqual(
            A.validate_evidence_refs_v2(p, [], snapshot_hash=_SHA), [])


if __name__ == "__main__":
    unittest.main()

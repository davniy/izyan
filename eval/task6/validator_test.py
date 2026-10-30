"""Unit tests for eval/task6/validator.py — the C1–C4 checks and the
eight adversarial fixtures named by plan §8.

All fixtures are GENERIC synthetic data: synthetic package/symbol names
("alpha/pkg.Fn"), synthetic observation ids, fake sha256 digests — no
case ids, no product names, no CVE identifiers anywhere
(docs/agent-rules/generality.md).

Run: $HARNESS/.venv/bin/python -m unittest eval.task6.validator_test -v
"""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from eval.task6 import validator as V  # noqa: E402
from eval.task6.assessment_v2 import (  # noqa: E402
    AgentAssessmentV2,
    AssessmentPayloadV2,
    AttemptMeta,
    NegativeClaim,
)

_SNAP = "f" * 64
_OTHER_SHA = "e" * 64

_META = AttemptMeta(
    experiment_id="exp", task_id="synthetic-case-1",
    attempt_id="synthetic-case-1/run_001", cve_id="ADVISORY-0000-0000",
    snapshot_hash=_SNAP, model="test-model",
    prompt_version="v", harness_version="h",
    tool_adapter_version="a")


def _obs(oid="OBS-0001", tool="find_callers", status="OK",
         completeness="COMPLETE", subject="alpha/pkg.Fn",
         scope="all packages of /work including dependencies",
         coverage_rule="full enumeration of the snapshot call graph",
         limitations=None, refs=None, data=None):
    sd = {"coverage_rule": coverage_rule,
          "snapshot_hash": _SNAP}
    if subject is not None:
        sd["subject"] = subject
    return {
        "id": oid, "tool": tool, "tool_status": status,
        "completeness": completeness, "scope": scope,
        "scope_details": sd,
        "fact": f"{tool} on {subject}",
        "limitations": limitations or [],
        "evidence_refs": refs if refs is not None else
        ["sha256:" + _OTHER_SHA],
        "data": data if data is not None else {"count": 0},
    }


def _claim(subject="alpha/pkg.Fn", predicate="unreachable",
           scope="all call paths", refs=("ev:OBS-0001",)):
    return NegativeClaim(
        predicate=predicate, subject=subject, scope=scope,
        evidence_refs=list(refs), limitations=[])


def _payload(claims=(), unresolved=(), mechanisms=()):
    return AssessmentPayloadV2(
        mechanisms=list(mechanisms),
        negative_claims=list(claims),
        unresolved=list(unresolved),
        reasoning="synthetic reasoning")


def _agent_dict(category, payload):
    return {"category": category, "reasoning": "synthetic",
            "assessment": payload.model_dump()}


def _full_artifact(category, payload):
    return AgentAssessmentV2(
        meta=_META, category=category, reasoning="synthetic",
        assessment=payload)


_ADVISORY_ONE = {"affected": [{"package": {"name": "alpha/pkg.Fn"},
                               "ranges": [{"events": [
                                   {"introduced": "0"},
                                   {"fixed": "v9.9.9"}]}]}]}
_ADVISORY_TWO = {"affected": [
    {"package": {"name": "alpha/pkg.Fn"}},
    {"package": {"name": "beta/pkg.Gn"}}]}


class AdversarialFixtureTest(unittest.TestCase):
    """The eight plan-§8 fixtures, verbatim names."""

    def test_error_as_absence_blocked(self):
        obs = [_obs(status="ERROR", completeness="UNKNOWN")]
        asm = _agent_dict("code_not_reachable",
                          _payload(claims=[_claim()]))
        res = V.validate_attempt(
            asm, observations=obs, snapshot_hash=_SNAP,
            advisory_record=_ADVISORY_ONE)
        self.assertEqual(res.decision, "INSUFFICIENT_EVIDENCE")
        self.assertFalse(res.per_claim[0].supported)
        self.assertIn("ERROR", res.per_claim[0].defects[0])

    def test_scoped_zero_global_blocked(self):
        obs = [_obs(completeness="PARTIAL",
                    scope="product packages of /work (loaded ./... roots)",
                    coverage_rule="product packages only",
                    limitations=["product packages only: dep-internal "
                                 "callers are NOT covered"],
                    data={"count": 0})]
        asm = _agent_dict(
            "code_not_reachable",
            _payload(claims=[_claim(scope="global: never invoked from "
                                    "any code path")]))
        res = V.validate_attempt(
            asm, observations=obs, snapshot_hash=_SNAP,
            advisory_record=_ADVISORY_ONE)
        self.assertEqual(res.decision, "SCOPE_MISMATCH")
        self.assertEqual(res.per_claim[0].decision, "SCOPE_MISMATCH")

    def test_valid_safe_accepted(self):
        obs = [_obs(refs=["sha256:" + _OTHER_SHA])]
        asm = _agent_dict(
            "code_not_reachable",
            _payload(claims=[_claim(refs=("ev:OBS-0001",))]))
        res = V.validate_attempt(
            asm, observations=obs, snapshot_hash=_SNAP,
            advisory_record=_ADVISORY_ONE)
        self.assertEqual(res.decision, "ACCEPTED")
        self.assertTrue(res.safe_verdict)
        self.assertTrue(res.per_claim[0].supported)
        self.assertEqual(res.falsifier["cleared"], True)
        self.assertEqual(res.coverage.entries[0].status,
                         "audit_complete")
        self.assertEqual(res.coverage.fixed_versions, ["v9.9.9"])

    def test_dangling_ref_rejected(self):
        obs = [_obs()]
        asm = _agent_dict(
            "code_not_reachable",
            _payload(claims=[_claim(refs=("ev:OBS-9999",))]))
        res = V.validate_attempt(
            asm, observations=obs, snapshot_hash=_SNAP,
            advisory_record=_ADVISORY_ONE)
        self.assertEqual(res.decision, "INVALID_EVIDENCE")
        self.assertIn("OBS-9999", res.per_claim[0].defects[0])

    def test_snapshot_hash_mismatch_rejected(self):
        wrong = "0" * 64
        asm = _agent_dict(
            "code_not_reachable",
            _payload(claims=[_claim(
                refs=(f"src:/work/alpha/pkg/f.go#L42@{wrong}",))]))
        res = V.validate_attempt(
            asm, observations=[], snapshot_hash=_SNAP,
            advisory_record=_ADVISORY_ONE)
        self.assertEqual(res.decision, "INVALID_EVIDENCE")
        self.assertIn("snapshot hash", res.per_claim[0].defects[0])

    def test_incomplete_cve_scope_abstain(self):
        obs = [_obs(subject="alpha/pkg.Fn")]
        asm = _agent_dict(
            "code_not_reachable",
            _payload(claims=[_claim(subject="alpha/pkg.Fn")]))
        res = V.validate_attempt(
            asm, observations=obs, snapshot_hash=_SNAP,
            advisory_record=_ADVISORY_TWO)
        self.assertEqual(res.decision, "INSUFFICIENT_EVIDENCE")
        by_subject = {e.subject: e.status for e in res.coverage.entries}
        self.assertEqual(by_subject["alpha/pkg.Fn"], "audit_complete")
        self.assertEqual(by_subject["beta/pkg.Gn"], "uncovered")
        self.assertIn("beta/pkg.Gn", res.reason)

    def test_unverifiable_dynamic_dispatch(self):
        obs = [_obs(tool="scan_dynamic", completeness="PARTIAL",
                    scope="product packages of /work",
                    coverage_rule="dynamic-marker scan, product only",
                    limitations=["interface-dispatched and reflection "
                                 "calls are not covered"])]
        asm = _agent_dict(
            "code_not_reachable",
            _payload(claims=[_claim(
                scope="call sites reached via interface dispatch "
                      "in product packages")]))
        res = V.validate_attempt(
            asm, observations=obs, snapshot_hash=_SNAP,
            advisory_record=_ADVISORY_ONE)
        self.assertEqual(res.decision, "UNVERIFIABLE")
        self.assertEqual(res.per_claim[0].decision, "UNVERIFIABLE")

    def test_unresolved_nonempty_blocks_safe(self):
        obs = [_obs()]
        asm = _agent_dict(
            "code_not_reachable",
            _payload(claims=[_claim()],
                     unresolved=["alternate trigger path not explored"]))
        # NOTE: the /2 schema itself flags this as a defect; the
        # validator must still abstain on a stored answer like this.
        res = V.validate_attempt(
            asm, observations=obs, snapshot_hash=_SNAP,
            advisory_record=_ADVISORY_ONE)
        self.assertEqual(res.decision, "INSUFFICIENT_EVIDENCE")
        self.assertIn("unresolved", res.reason)


class InputCoercionTest(unittest.TestCase):
    def test_agent_assessment_v2_object(self):
        obs = [_obs()]
        res = V.validate_attempt(
            _full_artifact("code_not_reachable",
                           _payload(claims=[_claim()])),
            observations=obs, snapshot_hash=_SNAP,
            advisory_record=_ADVISORY_ONE)
        self.assertEqual(res.decision, "ACCEPTED")
        self.assertEqual(res.category, "code_not_reachable")

    def test_extraction_result(self):
        from eval.task6.assessment_v2 import ExtractionResultV2
        obs = [_obs()]
        ext = ExtractionResultV2(
            category="code_not_reachable", reasoning="r",
            assessment=_payload(claims=[_claim()]))
        res = V.validate_attempt(
            ext, observations=obs, snapshot_hash=_SNAP,
            advisory_record=_ADVISORY_ONE)
        self.assertEqual(res.decision, "ACCEPTED")

    def test_agent_answer_not_mutated(self):
        obs = [_obs()]
        original = _agent_dict("code_not_reachable",
                               _payload(claims=[_claim()]))
        before = json.dumps(original, sort_keys=True)
        V.validate_attempt(original, observations=obs,
                           snapshot_hash=_SNAP,
                           advisory_record=_ADVISORY_ONE)
        self.assertEqual(json.dumps(original, sort_keys=True), before)

    def test_result_is_json_serializable(self):
        obs = [_obs()]
        res = V.validate_attempt(
            _agent_dict("code_not_reachable",
                        _payload(claims=[_claim()])),
            observations=obs, snapshot_hash=_SNAP,
            advisory_record=_ADVISORY_ONE)
        text = res.model_dump_json()
        back = V.ValidatorResult.model_validate_json(text)
        self.assertEqual(back.decision, "ACCEPTED")
        self.assertEqual(back.validator_version, V.VALIDATOR_VERSION)


class RefResolutionTest(unittest.TestCase):
    def test_sha256_ref_resolves_to_owner_observation(self):
        obs = [_obs(refs=["sha256:" + _OTHER_SHA])]
        asm = _agent_dict(
            "code_not_reachable",
            _payload(claims=[_claim(refs=("sha256:" + _OTHER_SHA,))]))
        res = V.validate_attempt(
            asm, observations=obs, snapshot_hash=_SNAP,
            advisory_record=_ADVISORY_ONE)
        self.assertEqual(res.decision, "ACCEPTED")
        self.assertEqual(res.per_claim[0].binding, "audit")

    def test_sha256_ref_inherits_owner_error_status(self):
        obs = [_obs(status="ERROR", completeness="UNKNOWN",
                    refs=["sha256:" + _OTHER_SHA])]
        asm = _agent_dict(
            "code_not_reachable",
            _payload(claims=[_claim(refs=("sha256:" + _OTHER_SHA,))]))
        res = V.validate_attempt(
            asm, observations=obs, snapshot_hash=_SNAP,
            advisory_record=_ADVISORY_ONE)
        self.assertEqual(res.decision, "INSUFFICIENT_EVIDENCE")

    def test_unminted_sha256_rejected(self):
        asm = _agent_dict(
            "code_not_reachable",
            _payload(claims=[_claim(refs=("sha256:" + "9" * 64,))]))
        res = V.validate_attempt(
            asm, observations=[_obs()], snapshot_hash=_SNAP,
            advisory_record=_ADVISORY_ONE)
        self.assertEqual(res.decision, "INVALID_EVIDENCE")

    def test_src_ref_bound_by_matching_snapshot_hash(self):
        asm = _agent_dict(
            "code_not_reachable",
            _payload(claims=[_claim(
                refs=(f"src:/work/alpha/pkg/f.go#L42@{_SNAP}",))]))
        res = V.validate_attempt(
            asm, observations=[], snapshot_hash=_SNAP,
            snapshot_files={"alpha/pkg/f.go"},
            advisory_record=_ADVISORY_ONE)
        self.assertEqual(res.decision, "ACCEPTED")
        self.assertEqual(res.per_claim[0].binding, "snapshot")

    def test_src_ref_absent_from_snapshot_index_rejected(self):
        asm = _agent_dict(
            "code_not_reachable",
            _payload(claims=[_claim(
                refs=(f"src:/work/alpha/pkg/f.go#L42@{_SNAP}",))]))
        res = V.validate_attempt(
            asm, observations=[], snapshot_hash=_SNAP,
            snapshot_files={"alpha/pkg/other.go"},
            advisory_record=_ADVISORY_ONE)
        self.assertEqual(res.decision, "INVALID_EVIDENCE")

    def test_src_ref_hash_unverified_without_attempt_hash(self):
        asm = _agent_dict(
            "code_not_reachable",
            _payload(claims=[_claim(
                refs=(f"src:/work/alpha/pkg/f.go#L42@{_SNAP}",))]))
        res = V.validate_attempt(
            asm, observations=[], snapshot_hash=None,
            advisory_record=_ADVISORY_ONE)
        # hash cannot be verified → self-declared + defect → claim
        # UNVERIFIABLE; not a falsifier → the safe verdict abstains
        self.assertEqual(res.per_claim[0].binding, "self_declared")
        self.assertEqual(res.decision, "UNVERIFIABLE")
        self.assertIn("cannot be verified",
                      res.per_claim[0].defects[0])

    def test_tool_minted_src_ref_resolves_to_owner(self):
        obs = [_obs(refs=["src:/work/alpha/pkg/f.go#L693"])]
        asm = _agent_dict(
            "code_not_reachable",
            _payload(claims=[_claim(
                refs=("src:/work/alpha/pkg/f.go#L693",))]))
        res = V.validate_attempt(
            asm, observations=obs, snapshot_hash=_SNAP,
            advisory_record=_ADVISORY_ONE)
        self.assertEqual(res.decision, "ACCEPTED")
        self.assertEqual(res.per_claim[0].binding, "audit")

    def test_ev_ref_via_audit_records(self):
        # audit trail rows (tool_calls.jsonl shape) also supply the obs
        rec = {"observation": _obs()}
        asm = _agent_dict(
            "code_not_reachable",
            _payload(claims=[_claim()]))
        res = V.validate_attempt(
            asm, audit_records=[rec], snapshot_hash=_SNAP,
            advisory_record=_ADVISORY_ONE)
        self.assertEqual(res.decision, "ACCEPTED")

    def test_file_ref_verified_against_snapshot_index(self):
        asm = _agent_dict(
            "code_not_reachable",
            _payload(claims=[_claim(
                refs=("file:/work/alpha/pkg/f.go:12-14",))]))
        res = V.validate_attempt(
            asm, observations=[], snapshot_hash=_SNAP,
            snapshot_files={"alpha/pkg/f.go"},
            advisory_record=_ADVISORY_ONE)
        self.assertEqual(res.decision, "ACCEPTED")
        self.assertEqual(res.per_claim[0].binding, "snapshot")


    def test_src_ref_hash_without_index_never_snapshot_bound(self):
        """F2: correct snapshot hash but NO file index → the path's
        existence is unverifiable; the ref must not upgrade to
        snapshot-bound."""
        asm = _agent_dict(
            "code_not_reachable",
            _payload(claims=[_claim(
                refs=(f"src:/work/alpha/pkg/f.go#L42@{_SNAP}",))]))
        res = V.validate_attempt(
            asm, observations=[], snapshot_hash=_SNAP,
            advisory_record=_ADVISORY_ONE)   # snapshot_files omitted
        self.assertEqual(res.per_claim[0].binding, "self_declared")
        self.assertIn("unverifiable", res.per_claim[0].defects[0])
        # and without a falsifier binding, a safe verdict abstains
        self.assertEqual(res.decision, "UNVERIFIABLE")

    def test_src_ref_fabricated_path_with_index_rejected(self):
        """F2 counterpart: WITH an index, a fabricated path is
        INVALID_EVIDENCE even when the snapshot hash is right."""
        asm = _agent_dict(
            "code_not_reachable",
            _payload(claims=[_claim(
                refs=(f"src:/work/alpha/pkg/forged.go#L42@{_SNAP}",))]))
        res = V.validate_attempt(
            asm, observations=[], snapshot_hash=_SNAP,
            snapshot_files={"alpha/pkg/f.go"},
            advisory_record=_ADVISORY_ONE)
        self.assertEqual(res.decision, "INVALID_EVIDENCE")
        self.assertIn("absent from the attempt snapshot index",
                      res.per_claim[0].defects[0])

    def test_owner_minted_src_ref_still_needs_file_index(self):
        """N2: a src@hash ref inside an observation's evidence_refs
        must NOT audit-bind without the snapshot file index — hashed
        refs resolve existence via the index FIRST (F2), owner-minted
        or not."""
        ref = f"src:alpha/pkg.go#L42@{_SNAP}"
        obs = [_obs(refs=[ref])]
        asm = _agent_dict(
            "code_not_reachable",
            _payload(claims=[_claim(refs=(ref,))]))
        res = V.validate_attempt(
            asm, observations=obs, snapshot_hash=_SNAP,
            advisory_record=_ADVISORY_ONE)
        self.assertEqual(res.per_claim[0].binding, "self_declared")
        self.assertIn("unverifiable", res.per_claim[0].defects[0])
        self.assertEqual(res.decision, "UNVERIFIABLE")

    def test_owner_minted_src_ref_binds_with_file_index(self):
        """Same ref WITH the index: verified hash + confirmed path +
        owner-minted → audit binding, the real accept path."""
        ref = f"src:alpha/pkg.go#L42@{_SNAP}"
        obs = [_obs(refs=[ref])]
        asm = _agent_dict(
            "code_not_reachable",
            _payload(claims=[_claim(refs=(ref,))]))
        res = V.validate_attempt(
            asm, observations=obs, snapshot_hash=_SNAP,
            advisory_record=_ADVISORY_ONE,
            snapshot_files={"alpha/pkg.go"})
        self.assertEqual(res.per_claim[0].binding, "audit")
        self.assertEqual(res.decision, "ACCEPTED")



class MissingCompletenessTest(unittest.TestCase):
    """F4: tool_status OK without completeness must NOT count as
    complete evidence for a negative claim."""

    def test_missing_completeness_is_insufficient(self):
        obs = [_obs()]
        for o in obs:
            del o["completeness"]          # field absent entirely
        asm = _agent_dict("code_not_reachable",
                          _payload(claims=[_claim()]))
        res = V.validate_attempt(
            asm, observations=obs, snapshot_hash=_SNAP,
            advisory_record=_ADVISORY_ONE)
        self.assertEqual(res.decision, "INSUFFICIENT_EVIDENCE")
        self.assertFalse(res.per_claim[0].supported)
        self.assertIn("completeness", res.per_claim[0].defects[0])

    def test_unrecognized_completeness_is_insufficient(self):
        obs = [_obs(completeness="MOSTLY")]
        asm = _agent_dict("code_not_reachable",
                          _payload(claims=[_claim()]))
        res = V.validate_attempt(
            asm, observations=obs, snapshot_hash=_SNAP,
            advisory_record=_ADVISORY_ONE)
        self.assertEqual(res.decision, "INSUFFICIENT_EVIDENCE")


class ScopeContextTest(unittest.TestCase):
    """F3: the observation's declared scope/build context must bound
    the claim — not just its subject."""

    def test_global_claim_over_narrowed_packages_is_mismatch(self):
        obs = [_obs(scope="callers enumerated over product packages",
                    coverage_rule="all first-party callers",
                    limitations=[])]
        obs[0]["scope_details"]["packages"] = ["alpha/pkg"]
        asm = _agent_dict(
            "code_not_reachable",
            _payload(claims=[_claim(scope="global: never invoked from "
                                        "any code path")]))
        res = V.validate_attempt(
            asm, observations=obs, snapshot_hash=_SNAP,
            advisory_record=_ADVISORY_ONE)
        self.assertEqual(res.decision, "SCOPE_MISMATCH")

    def test_claim_subject_outside_observed_packages_is_mismatch(self):
        obs = [_obs(subject="alpha/pkg.Fn")]
        obs[0]["scope_details"]["packages"] = ["beta/pkg"]
        asm = _agent_dict(
            "code_not_reachable",
            _payload(claims=[_claim(scope="call sites of alpha/pkg")]))
        res = V.validate_attempt(
            asm, observations=obs, snapshot_hash=_SNAP,
            advisory_record=_ADVISORY_ONE)
        self.assertEqual(res.decision, "SCOPE_MISMATCH")

    def test_cross_build_claim_rejected(self):
        """Observation ran under linux/amd64; a claim scoped to
        windows-only paths exceeds the checked build context."""
        obs = [_obs()]
        obs[0]["scope_details"]["build_context"] = {
            "goos": "linux", "goarch": "amd64", "cgo_enabled": False,
            "build_tags": []}
        asm = _agent_dict(
            "code_not_reachable",
            _payload(claims=[_claim(
                scope="all call paths under windows build")]))
        res = V.validate_attempt(
            asm, observations=obs, snapshot_hash=_SNAP,
            advisory_record=_ADVISORY_ONE)
        self.assertEqual(res.decision, "SCOPE_MISMATCH")
        self.assertIn("GOOS", res.per_claim[0].defects[0])

    def test_goos_claim_without_observed_axis_is_mismatch(self):
        """N3: claim names GOOS=windows but the COMPLETE observation
        declares no BuildContext at all — the axis the claim relies on
        was never checked, so it is a scope mismatch (not silent pass)."""
        obs = [_obs()]  # scope_details without build_context
        asm = _agent_dict(
            "code_not_reachable",
            _payload(claims=[_claim(
                scope="all call paths under windows build")]))
        res = V.validate_attempt(
            asm, observations=obs, snapshot_hash=_SNAP,
            advisory_record=_ADVISORY_ONE)
        self.assertEqual(res.decision, "SCOPE_MISMATCH")
        self.assertIn("GOOS", res.per_claim[0].defects[0])

    def test_goarch_claim_without_observed_axis_is_mismatch(self):
        """N3: same for GOARCH — a missing build-context axis never
        satisfies an explicitly named arch."""
        obs = [_obs()]
        asm = _agent_dict(
            "code_not_reachable",
            _payload(claims=[_claim(
                scope="call sites on arm64 builds")]))
        res = V.validate_attempt(
            asm, observations=obs, snapshot_hash=_SNAP,
            advisory_record=_ADVISORY_ONE)
        self.assertEqual(res.decision, "SCOPE_MISMATCH")
        self.assertIn("GOARCH", res.per_claim[0].defects[0])

    def test_missing_build_tag_rejected(self):
        obs = [_obs()]
        obs[0]["scope_details"]["build_context"] = {
            "goos": "linux", "build_tags": ["sqlite_omit_load_extension"]}
        asm = _agent_dict(
            "code_not_reachable",
            _payload(claims=[_claim(
                scope="call sites with build tag fuzz enabled")]))
        res = V.validate_attempt(
            asm, observations=obs, snapshot_hash=_SNAP,
            advisory_record=_ADVISORY_ONE)
        self.assertEqual(res.decision, "SCOPE_MISMATCH")

    def test_matching_build_context_passes(self):
        """Same-axis claim inside the observed build context is fine."""
        obs = [_obs()]
        obs[0]["scope_details"]["build_context"] = {
            "goos": "linux", "goarch": "amd64",
            "build_tags": ["netgo"]}
        asm = _agent_dict(
            "code_not_reachable",
            _payload(claims=[_claim(
                scope="call paths on linux/amd64 with build tag "
                      "netgo")]))
        res = V.validate_attempt(
            asm, observations=obs, snapshot_hash=_SNAP,
            advisory_record=_ADVISORY_ONE)
        self.assertEqual(res.decision, "ACCEPTED")


class DecisionPrecedenceTest(unittest.TestCase):
    def test_subject_mismatch_on_complete_obs(self):
        obs = [_obs(subject="gamma/pkg.Hn")]
        asm = _agent_dict(
            "code_not_reachable",
            _payload(claims=[_claim(subject="alpha/pkg.Fn")]))
        res = V.validate_attempt(
            asm, observations=obs, snapshot_hash=_SNAP,
            advisory_record=_ADVISORY_ONE)
        self.assertEqual(res.decision, "SCOPE_MISMATCH")

    def test_unsupported_tool_is_not_evidence(self):
        obs = [_obs(status="UNSUPPORTED", completeness="UNKNOWN")]
        asm = _agent_dict("code_not_reachable",
                          _payload(claims=[_claim()]))
        res = V.validate_attempt(
            asm, observations=obs, snapshot_hash=_SNAP,
            advisory_record=_ADVISORY_ONE)
        self.assertEqual(res.decision, "INSUFFICIENT_EVIDENCE")

    def test_partial_nonopaque_bounded_is_insufficient(self):
        obs = [_obs(completeness="PARTIAL",
                    coverage_rule="enumeration capped at 64 matches",
                    limitations=["result capped at 64 matches"])]
        asm = _agent_dict(
            "code_not_reachable",
            _payload(claims=[_claim(scope="product packages")]))
        res = V.validate_attempt(
            asm, observations=obs, snapshot_hash=_SNAP,
            advisory_record=_ADVISORY_ONE)
        self.assertEqual(res.decision, "INSUFFICIENT_EVIDENCE")

    def test_empty_result_complete_is_supported(self):
        # A zero enumeration inside a COMPLETE scope is real negative
        # evidence within that scope (the scope itself is declared).
        obs = [_obs(data={"count": 0},
                    scope="all callers of alpha/pkg.Fn",
                    coverage_rule="full transitive enumeration")]
        asm = _agent_dict(
            "code_not_reachable",
            _payload(claims=[_claim(scope="all call paths")]))
        res = V.validate_attempt(
            asm, observations=obs, snapshot_hash=_SNAP,
            advisory_record=_ADVISORY_ONE)
        self.assertEqual(res.decision, "ACCEPTED")

    def test_invalid_beats_scope_mismatch(self):
        obs = [_obs(completeness="PARTIAL",
                    scope="product packages only")]
        asm = _agent_dict(
            "code_not_reachable",
            _payload(claims=[
                _claim(scope="global everywhere",
                       refs=("ev:OBS-9999", "ev:OBS-0001")),
            ]))
        res = V.validate_attempt(
            asm, observations=obs, snapshot_hash=_SNAP,
            advisory_record=_ADVISORY_ONE)
        self.assertEqual(res.decision, "INVALID_EVIDENCE")
        self.assertEqual(res.per_claim[0].decision, "INVALID_EVIDENCE")


class SafeVerdictEdgeTest(unittest.TestCase):
    def test_safe_without_any_claim_is_insufficient(self):
        # schema-invalid as a /2 artifact but storable raw — the
        # validator abstains rather than crashing
        asm = {"category": "code_not_reachable", "reasoning": "r",
               "assessment": {"mechanisms": [], "negative_claims": [],
                              "unresolved": [], "reasoning": "r"}}
        res = V.validate_attempt(
            asm, observations=[_obs()], snapshot_hash=_SNAP,
            advisory_record=_ADVISORY_ONE)
        self.assertEqual(res.decision, "INSUFFICIENT_EVIDENCE")
        self.assertTrue(res.safe_verdict)

    def test_self_declared_only_claim_is_not_a_falsifier(self):
        asm = _agent_dict(
            "code_not_reachable",
            _payload(claims=[_claim(refs=("file:alpha/pkg/f.go:10",))]))
        res = V.validate_attempt(
            asm, observations=[], snapshot_hash=_SNAP,
            advisory_record=_ADVISORY_ONE)  # no snapshot index
        self.assertEqual(res.decision, "INSUFFICIENT_EVIDENCE")
        self.assertEqual(res.per_claim[0].binding, "self_declared")

    def test_vulnerable_category_skips_c4(self):
        res = V.validate_attempt(
            _agent_dict("vulnerable",
                        _payload(claims=[], unresolved=[])),
            observations=[], snapshot_hash=_SNAP,
            advisory_record=_ADVISORY_ONE)
        self.assertEqual(res.decision, "ACCEPTED")
        self.assertFalse(res.safe_verdict)
        self.assertEqual(res.falsifier["applicable"], False)

    def test_uncertain_category_skips_c4(self):
        res = V.validate_attempt(
            _agent_dict("uncertain", _payload()),
            observations=[], snapshot_hash=_SNAP,
            advisory_record=_ADVISORY_ONE)
        self.assertEqual(res.decision, "ACCEPTED")

    def test_advisory_absent_blocks_safe(self):
        """F1: absent declared scope is never vacuous coverage — a
        supported claim + no advisory record must NOT be ACCEPTED."""
        obs = [_obs()]
        res = V.validate_attempt(
            _agent_dict("code_not_reachable",
                        _payload(claims=[_claim()])),
            observations=obs, snapshot_hash=_SNAP,
            advisory_record=None)
        self.assertEqual(res.decision, "INSUFFICIENT_EVIDENCE")
        self.assertIn("declared", res.reason)
        self.assertFalse(res.coverage.advisory_present)

    def test_advisory_without_subjects_blocks_safe(self):
        """F1 variant: an advisory record that declares no affected
        subjects gives no scope to bind — safe cannot stand on it."""
        obs = [_obs()]
        res = V.validate_attempt(
            _agent_dict("code_not_reachable",
                        _payload(claims=[_claim()])),
            observations=obs, snapshot_hash=_SNAP,
            advisory_record={"affected": []})
        self.assertEqual(res.decision, "INSUFFICIENT_EVIDENCE")
        self.assertTrue(res.coverage.advisory_present)


class DeclaredAffectedTest(unittest.TestCase):
    def test_osv_walk(self):
        rec = {"affected": [
            {"package": {"name": "alpha/pkg"},
             "ranges": [{"events": [{"introduced": "0"},
                                    {"fixed": "v2.0.0"}]}],
             "affected_symbols": ["alpha/pkg.Fn", "alpha/pkg.Gn"],
             "versions": ["v1.0.0", "v1.1.0"]}]}
        out = V.declared_affected(rec)
        self.assertEqual(
            out["subjects"],
            ["alpha/pkg", "alpha/pkg.Fn", "alpha/pkg.Gn"])
        self.assertEqual(out["fixed_versions"], ["v2.0.0"])
        # versions list must NOT leak into subjects
        self.assertNotIn("v1.0.0", out["subjects"])

    def test_get_vulnerability_data_shape(self):
        # the live get_vulnerability observation's data payload
        rec = {"vulnerability": {
            "affected_modules": [{"module": "alpha/mod"}],
            "affected_symbols": ["alpha/pkg.Fn"],
            "aliases": ["X-1"], "description": "text"}}
        out = V.declared_affected(rec)
        self.assertEqual(out["subjects"],
                         ["alpha/mod", "alpha/pkg.Fn"])
        self.assertNotIn("text", out["subjects"])

    def test_empty_and_none(self):
        self.assertEqual(V.declared_affected(None),
                         {"subjects": [], "fixed_versions": []})
        self.assertEqual(V.declared_affected({"affected": []}),
                         {"subjects": [], "fixed_versions": []})


class SubjectRelationTest(unittest.TestCase):
    def test_related_forms(self):
        self.assertTrue(V._subjects_related(
            "alpha/pkg.Fn", "alpha/pkg.Fn"))
        self.assertTrue(V._subjects_related(
            "alpha/pkg.Fn", "alpha/pkg"))
        self.assertTrue(V._subjects_related(
            "/work/vendor/alpha/pkg/f.go", "alpha/pkg"))
        self.assertTrue(V._subjects_related(
            "alpha/pkg", "alpha/pkg/sub"))

    def test_unrelated(self):
        self.assertFalse(V._subjects_related(
            "alpha/pkg.Fn", "beta/pkg.Gn"))
        self.assertFalse(V._subjects_related(
            "alpha/pkg2", "alpha/pkg"))   # no boundary → not related
        self.assertFalse(V._subjects_related(
            "alpha/other/pkg.Http2", "alpha/pkg.Http"))


if __name__ == "__main__":
    unittest.main()

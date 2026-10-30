"""Unit tests for the first-layer VEX ablation report (Task 3).

Every fixture is synthetic and offline: saved-attempt directories are
written under a temporary root, then ``report.build_comparison`` reads
them exactly as it will read Task 2's output.  No Docker, network, model
or izyan MCP call is made.
"""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO_ROOT))

from eval.first_layer_ablation import protocol as P  # noqa: E402
from eval.first_layer_ablation import report as R  # noqa: E402

TASK_ID = "kubernetes-kubernetes-e196d24-CVE-2023-44487"
CVE_ID = "CVE-2023-44487"
SHA_B = "b" * 64
SHA_C = "c" * 64


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _status(**overrides):
    """A c1 ``AttemptStatus``-shaped record (status.json)."""
    execution = overrides.pop("execution", "ok")
    official_parse = overrides.pop("official_parse", "accepted")
    category = overrides.pop("category", "vulnerable")
    failure_reason = overrides.pop("failure_reason", None)
    if "overall" in overrides:
        overall = overrides.pop("overall")
    elif official_parse != "accepted":
        overall = "failed"
    elif category == "uncertain":
        overall = "inconclusive"
    else:
        overall = "valid"
    status = {
        "schema_version": "attempt-status/1",
        "task_id": TASK_ID,
        "attempt_id": "synthetic",
        "experiment_id": P.EXPERIMENT_ID,
        "execution": execution,
        "official_parse": official_parse,
        "assessment_schema": "absent",
        "parser_audit": "not_run",
        "overall": overall,
        "failure_reason": failure_reason,
        "detail": None,
        # c1's AttemptStatus does not store the category; the report
        # re-derives it with the official parser when it is absent.  The
        # synthetic fixture stores it to exercise the saved-category path.
        "category": category,
    }
    status.update(overrides)
    return status


def _answer(category="vulnerable", reasoning="synthetic reasoning",
            assessment=None):
    answer = {"category": category, "reasoning": reasoning}
    if assessment is not None:
        answer["assessment"] = assessment
    return json.dumps(answer, indent=2, sort_keys=True)


class ExperimentFixture:
    """Synthetic Task 2 experiment root with a frozen-manifest stand-in."""

    def __init__(self, root: Path):
        self.root = Path(root)
        self.prompts = {
            arm: "synthetic first-layer prompt for arm {}\n".format(arm)
            for arm in P.ARM_ORDER
        }
        schedule = P.build_schedule()
        self.schedule = {entry["attempt_key"]: entry for entry in schedule}
        prompts = {}
        for arm in P.ARM_ORDER:
            text = self.prompts[arm]
            prompts[arm] = {
                "role": P.ARM_ROLES[arm],
                "treatments": list(P.ARM_TREATMENTS[arm]),
                "agent": P.ARM_RUNTIME[arm]["agent"],
                "mcp": P.ARM_RUNTIME[arm]["mcp"],
                "sha256": _sha256(text),
                "sha256_12": _sha256(text)[:P.PROMPT_HASH_LEN],
                "bytes": len(text.encode("utf-8")),
                "lines": text.count("\n") + 1,
            }
        manifest = {
            "schema": P.MANIFEST_SCHEMA,
            "experiment_id": P.EXPERIMENT_ID,
            "frozen_at_utc": "2026-10-24T00:00:00Z",
            "goal": "synthetic report fixture",
            "case": {
                "task_id": TASK_ID,
                "cve_id": CVE_ID,
                "repo_url": "https://github.com/kubernetes/kubernetes",
                "commit_sha": "e196d24",
                "language": "go",
                "snapshot_path": "/synthetic/snapshot",
                "snapshot_sha256": SHA_C,
            },
            "prompts": prompts,
            "runtime": {
                "model": {
                    "id": P.MODEL_ID,
                    "alias": P.MODEL_ALIAS,
                    "provider": P.PROVIDER,
                    "provider_model_id": P.PROVIDER_MODEL_ID,
                    "revision": None,
                },
                "endpoint": {
                    "base_url": None,
                    "provider_endpoint": None,
                    "transport": None,
                },
                "image": {
                    "tag": "synthetic-image:latest",
                    "digest": "sha256:" + "d" * 64,
                    "same_digest_all_arms": True,
                },
                "parameters": {"temperature": 0},
                "native_tools": ["shell", "read"],
                "permissions": {"network": "none"},
            },
            "attempt_policy": dict(P.ATTEMPT_POLICY),
            "schedule": schedule,
            "schedule_sha256": P.sha256_text(P.canonical_json(schedule)),
            "limitations": ["fixture limitation"],
        }
        manifest["runtime_sha256"] = P.sha256_text(
            P.canonical_json(manifest["runtime"])
        )
        self.manifest = P.seal_manifest(manifest)
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "manifest.json").write_text(
            json.dumps(self.manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self.written = set()

    def attempt_dir(self, arm: str, repeat: int) -> Path:
        return self.root / TASK_ID / arm / "repeat-{}".format(repeat)

    def write_attempt(
        self,
        arm: str,
        repeat: int,
        *,
        status=None,
        raw=None,
        attempt_extra=None,
        prompt_text=None,
        request_user_sha=None,
        tool_calls=(),
        native_calls=None,
        write_native_file=True,
        result_json=None,
        agent_assessment=None,
        validator_results=None,
    ) -> Path:
        if status is None:
            status = _status()
        key = "{}/{}/r{}".format(P.EXPERIMENT_ID, arm, repeat)
        entry = self.schedule[key]
        path = self.attempt_dir(arm, repeat)
        path.mkdir(parents=True, exist_ok=True)
        self.written.add(key)
        self.written.add(key)
        prompt = self.prompts[arm] if prompt_text is None else prompt_text
        (path / "prompt.txt").write_text(prompt, encoding="utf-8")
        manifest_hash = self.manifest["prompts"][arm]["sha256"]
        attempt = {
            "schema": "first-layer-attempt/1",
            "experiment_id": P.EXPERIMENT_ID,
            "task_id": TASK_ID,
            "cve_id": CVE_ID,
            "arm": arm,
            "repeat": repeat,
            "attempt_key": key,
            "sequence_index": entry["index"],
            "agent": P.ARM_RUNTIME[arm]["agent"],
            "mcp": P.ARM_RUNTIME[arm]["mcp"],
            "prompt_sha256": manifest_hash,
            "prompt_sha256_12": manifest_hash[:12],
            "prompt_path": "prompt.txt",
            "runtime": {},
            "image_tag": "synthetic-image:latest",
            "image_digest": "sha256:" + "d" * 64,
            "model": P.MODEL_ID,
            "provider": P.PROVIDER,
            "model_observed": P.MODEL_ID,
            "provider_observed": P.PROVIDER,
            "runtime_version_observed": "synthetic",
            "snapshot_path": "/synthetic/snapshot",
            "snapshot_sha256": SHA_C,
            "started_at_utc": "2026-10-24T00:00:00Z",
            "finished_at_utc": "2026-10-24T00:00:01Z",
            "wall_seconds": 1.0,
            "result_present": True,
            "error_present": False,
            "outcome": "completed" if status.get("overall") != "failed"
            else "failed",
            "failure_class": (
                "none" if status.get("overall") != "failed" else "model_output"
            ),
            "failure_reason": status.get("failure_reason"),
            "status": status,
            "artifacts": {},
            "hashes": {},
        }
        if attempt_extra:
            attempt.update(attempt_extra)
        (path / "attempt.json").write_text(
            json.dumps(attempt, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (path / "status.json").write_text(
            json.dumps(status, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        if raw is None:
            raw = _answer()
        (path / "raw_agent_output.txt").write_text(raw, encoding="utf-8")
        user_sha = request_user_sha if request_user_sha is not None \
            else manifest_hash
        request = {
            "messages": [{"role": "user", "content": prompt}],
            "system_message_count": 0,
            "system_prompt_sha256": [],
            "user_prompt_sha256": user_sha,
            "full_request_sha256": _sha256(
                json.dumps([{"role": "user", "content": prompt}])
            ),
        }
        (path / "request.json").write_text(
            json.dumps(request, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        if tool_calls:
            (path / "tool_calls.jsonl").write_text(
                "".join(json.dumps(record, sort_keys=True) + "\n"
                        for record in tool_calls),
                encoding="utf-8",
            )
        if native_calls is None:
            native_calls = []
        if write_native_file:
            (path / "native_tool_calls.jsonl").write_text(
                "".join(json.dumps(record, sort_keys=True) + "\n"
                        for record in native_calls),
                encoding="utf-8",
            )
        if result_json is not None:
            (path / "result.json").write_text(
                json.dumps(result_json, indent=2) + "\n", encoding="utf-8"
            )
        if agent_assessment is not None:
            (path / "agent_assessment.json").write_text(
                json.dumps(agent_assessment, indent=2) + "\n",
                encoding="utf-8",
            )
        if validator_results is not None:
            (path / "validator_results.jsonl").write_text(
                "".join(json.dumps(record) + "\n"
                        for record in validator_results),
                encoding="utf-8",
            )
        return path

    def write_run_summary(self, entries=None):
        if entries is None:
            entries = []
            for key in self.schedule:
                entry = dict(self.schedule[key])
                entry["outcome"] = "completed"
                entries.append(entry)
        payload = {"experiment_id": P.EXPERIMENT_ID, "attempts": entries}
        (self.root / "run-summary.json").write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


def _observation(observation_id="OBS-1", tool="get_vulnerability",
                 refs=("sha256:" + SHA_B,), status="OK",
                 completeness="COMPLETE"):
    return {
        "id": observation_id,
        "tool": tool,
        "fact": "normalized advisory record for {}".format(CVE_ID),
        "scope": "advisory document",
        "completeness": completeness,
        "tool_status": status,
        "evidence_refs": list(refs),
        "limitations": ["fixture limitation"],
        "scope_details": {"subject": CVE_ID},
        "data": {"id": CVE_ID},
    }


def _tool_call(observation):
    return {
        "tool": observation.get("tool"),
        "args": {},
        "duration_ms": 1,
        "observation": observation,
    }


class OutcomeCountingTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.fixture = ExperimentFixture(Path(self._tmp.name))

    def tearDown(self):
        self._tmp.cleanup()

    def test_counts_are_separate_mutually_exclusive_and_complete(self):
        f = self.fixture
        # A: one of each decisive first-layer category.
        f.write_attempt("A", 1, status=_status(category="vulnerable"),
                        raw=_answer("vulnerable"))
        f.write_attempt("A", 2, status=_status(category="code_not_present"),
                        raw=_answer("code_not_present"))
        f.write_attempt("A", 3, status=_status(category="uncertain"),
                        raw=_answer("uncertain"))
        # B: parser failure that recovered a correct answer, timeout and
        # provider refusal must all be separate buckets.
        f.write_attempt(
            "B", 1,
            status=_status(execution="invalid_terminal_answer",
                           official_parse="parse_fail", category=None,
                           failure_reason="invalid_terminal_answer"),
            raw=_answer("vulnerable"),
        )
        f.write_attempt(
            "B", 2,
            status=_status(execution="timeout", official_parse="no_result",
                           category=None, failure_reason="timeout"),
            raw="",
        )
        f.write_attempt(
            "B", 3,
            status=_status(execution="provider_refusal",
                           official_parse="parse_fail", category=None,
                           failure_reason="provider_refusal"),
            raw="request was blocked by the provider",
        )
        # C: infrastructure failure, unparseable answer, one correct answer.
        f.write_attempt(
            "C", 1,
            status=_status(execution="transport_failure",
                           official_parse="no_result", category=None,
                           failure_reason="docker_start_failed"),
            raw="",
        )
        f.write_attempt(
            "C", 2,
            status=_status(execution="invalid_terminal_answer",
                           official_parse="parse_fail", category=None,
                           failure_reason="invalid_terminal_answer"),
            raw="I could not decide; no JSON was produced.",
        )
        f.write_attempt("C", 3, status=_status(category="vulnerable"),
                        raw=_answer("vulnerable"))
        # D: dangerous negative with traces, parser-loss correct answer,
        # correct answer.
        f.write_attempt(
            "D", 1,
            status=_status(category="code_not_reachable"),
            raw=_answer("code_not_reachable"),
            tool_calls=[_tool_call(_observation())],
            native_calls=[{"tool": "read", "call_id": "call_1",
                           "status": "completed",
                           "input": {"filePath": "/work/go.mod"}}],
        )
        f.write_attempt(
            "D", 2,
            status=_status(execution="invalid_terminal_answer",
                           official_parse="parse_fail", category=None,
                           failure_reason="invalid_terminal_answer"),
            raw=_answer("vulnerable",
                        assessment={"evidence_quality": {
                            "references": ["sha256:" + SHA_B]}}),
        )
        f.write_attempt("D", 3, status=_status(category="vulnerable"),
                        raw=_answer("vulnerable"))
        # E: dangerous negative, uncertain, provider failure.
        f.write_attempt(
            "E", 1,
            status=_status(category="code_not_present"),
            raw=_answer("code_not_present"),
            tool_calls=[_tool_call(_observation())],
            native_calls=[{"tool": "izyan_get_vulnerability",
                           "call_id": "call_2", "status": "completed"}],
        )
        f.write_attempt("E", 2, status=_status(category="uncertain"),
                        raw=_answer("uncertain"))
        f.write_attempt(
            "E", 3,
            status=_status(execution="provider_refusal",
                           official_parse="parse_fail", category=None,
                           failure_reason="provider_refusal"),
            raw="provider safety filter",
        )
        f.write_run_summary()

        comparison = R.build_comparison(f.root)
        self.assertEqual(comparison["totals"]["attempts"], 15)
        self.assertEqual(comparison["totals"]["present"], 15)
        self.assertEqual(sum(comparison["totals"]["outcomes"].values()), 15)

        outcomes = comparison["totals"]["outcomes"]
        self.assertEqual(outcomes["vulnerable"], 3)
        self.assertEqual(outcomes["dangerous_negative"], 3)
        self.assertEqual(outcomes["uncertain"], 2)
        self.assertEqual(outcomes["parse_failure"], 3)
        self.assertEqual(outcomes["timeout"], 1)
        self.assertEqual(outcomes["provider_failure"], 2)
        self.assertEqual(outcomes["infrastructure_failure"], 1)
        self.assertEqual(outcomes["other_failure"], 0)
        self.assertEqual(outcomes["missing_attempt"], 0)

        by_key = {record["attempt_key"]: record
                  for record in comparison["attempts"]}
        self.assertEqual(
            by_key[P.EXPERIMENT_ID + "/B/r1"]["first_layer_outcome"],
            "parse_failure",
        )
        self.assertEqual(
            by_key[P.EXPERIMENT_ID + "/B/r1"]["diagnosis"]["kind"],
            "correct_answer_lost_by_parser",
        )
        self.assertEqual(
            by_key[P.EXPERIMENT_ID + "/C/r2"]["diagnosis"]["kind"],
            "not_researched",
        )
        self.assertEqual(
            by_key[P.EXPERIMENT_ID + "/D/r1"]["diagnosis"]["kind"],
            "researched_but_wrong_conclusion",
        )
        self.assertEqual(
            by_key[P.EXPERIMENT_ID + "/D/r2"]["diagnosis"]["kind"],
            "correct_answer_lost_by_parser",
        )
        for record in comparison["attempts"]:
            self.assertIn(record["first_layer_outcome"], R.OUTCOME_ORDER)
        for arm in P.ARM_ORDER:
            self.assertEqual(comparison["arms"][arm]["attempts"], 3)
            self.assertEqual(
                sum(comparison["arms"][arm]["outcomes"].values()), 3
            )

    def test_failure_classes_never_become_negative_or_uncertain(self):
        f = self.fixture
        f.write_attempt(
            "A", 1,
            status=_status(execution="timeout", official_parse="no_result",
                           category=None, failure_reason="timeout"),
            raw='{"category": "code_not_present", "reasoning": "late"}',
        )
        f.write_attempt(
            "A", 2,
            status=_status(execution="provider_refusal",
                           official_parse="parse_fail", category=None,
                           failure_reason="provider_refusal"),
            raw='{"category": "code_not_present", "reasoning": "blocked"}',
        )
        f.write_attempt(
            "A", 3,
            status=_status(execution="invalid_terminal_answer",
                           official_parse="parse_fail", category=None,
                           failure_reason="invalid_terminal_answer"),
            raw='{"category": "code_not_present", "reasoning": "unparsed"}',
        )
        f.write_run_summary()
        comparison = R.build_comparison(f.root)
        outcomes = comparison["totals"]["outcomes"]
        self.assertEqual(outcomes["timeout"], 1)
        self.assertEqual(outcomes["provider_failure"], 1)
        self.assertEqual(outcomes["parse_failure"], 1)
        self.assertEqual(outcomes["dangerous_negative"], 0)
        self.assertEqual(outcomes["uncertain"], 0)

    def test_provider_error_evidence_is_counted_as_provider_failure(self):
        f = self.fixture
        f.write_attempt(
            "A", 1,
            status=_status(execution="invalid_terminal_answer",
                           official_parse="parse_fail", category=None,
                           failure_reason="invalid_terminal_answer"),
            raw='{"category": "code_not_present", "reasoning": "x"}',
            attempt_extra={
                "failure_class": "model_output",
                "error_excerpt": "provider at capacity; try later",
            },
        )
        f.write_run_summary()
        comparison = R.build_comparison(f.root)
        record = comparison["attempts"][0]
        self.assertEqual(record["first_layer_outcome"], "provider_failure")
        self.assertIn("provider", record["outcome_basis"])


class OfficialAndAuditSeparationTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.fixture = ExperimentFixture(Path(self._tmp.name))

    def tearDown(self):
        self._tmp.cleanup()

    def test_official_result_is_preserved_while_audit_recovers(self):
        f = self.fixture
        raw = _answer("vulnerable", reasoning="parser should have accepted")
        f.write_attempt(
            "A", 1,
            status=_status(execution="invalid_terminal_answer",
                           official_parse="parse_fail", category=None,
                           failure_reason="invalid_terminal_answer"),
            raw=raw,
        )
        f.write_run_summary()
        comparison = R.build_comparison(f.root)
        record = comparison["attempts"][0]
        official = record["official_parser_result"]
        audit = record["audit_projection"]
        self.assertEqual(official["official_parse"], "parse_fail")
        self.assertIsNone(official["category"])
        self.assertEqual(official["record"]["official_parse"], "parse_fail")
        self.assertEqual(record["first_layer_outcome"], "parse_failure")
        self.assertEqual(audit["status"], "recovered")
        self.assertEqual(audit["category"], "vulnerable")
        self.assertEqual(audit["recovered_object"]["category"], "vulnerable")
        self.assertEqual(
            audit["recovered_object_sha256"],
            R._sha256_json(audit["recovered_object"]),
        )
        self.assertTrue(audit["official_missed_expected_answer"])
        self.assertFalse(audit["used_for_scoring"])
        self.assertEqual(
            record["diagnosis"]["kind"], "correct_answer_lost_by_parser"
        )

    def test_official_accepted_negative_is_not_replaced_by_audit(self):
        f = self.fixture
        f.write_attempt(
            "A", 1,
            status=_status(category="code_not_present"),
            raw=_answer("vulnerable", reasoning="second object says so"),
        )
        f.write_run_summary()
        comparison = R.build_comparison(f.root)
        record = comparison["attempts"][0]
        self.assertEqual(
            record["official_parser_result"]["category"], "code_not_present"
        )
        self.assertEqual(record["audit_projection"]["category"], "vulnerable")
        self.assertTrue(record["audit_projection"]["projection_disagreement"])
        self.assertFalse(record["audit_projection"]["official_missed_expected_answer"])
        self.assertEqual(record["first_layer_outcome"], "dangerous_negative")
        self.assertEqual(
            record["diagnosis"]["kind"], "not_researched"
        )

    def test_downstream_validator_file_is_ignored(self):
        f = self.fixture
        f.write_attempt(
            "A", 1,
            status=_status(category="code_not_present"),
            raw=_answer("code_not_present"),
            validator_results=[{
                "decision": "ACCEPTED",
                "category": "vulnerable",
                "reason": "downstream verifier must not re-grade this",
            }],
        )
        f.write_run_summary()
        comparison = R.build_comparison(f.root)
        record = comparison["attempts"][0]
        self.assertEqual(record["first_layer_outcome"], "dangerous_negative")
        self.assertFalse(
            record["artifacts"]["validator_results_used_for_scoring"]
        )
        self.assertFalse(
            comparison["scope"]["downstream_verifier_used"]
        )


class ResearchTraceTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.fixture = ExperimentFixture(Path(self._tmp.name))

    def tearDown(self):
        self._tmp.cleanup()

    def test_citations_link_to_decisive_observations_and_native_calls(self):
        f = self.fixture
        assessment = {
            "evidence_quality": {
                "references": [
                    "sha256:" + SHA_B,
                    "file:/work/go.mod:45",
                ],
                "summary": "fixture",
            },
            "claims": [{
                "statement": "the module is present",
                "verdict": "TRUE",
                "evidence_refs": ["sha256:" + SHA_B],
            }],
            "root_cause": "see https://example.com/advisory for context",
        }
        raw = _answer("code_not_present", assessment=assessment)
        f.write_attempt(
            "E", 1,
            status=_status(category="code_not_present"),
            raw=raw,
            tool_calls=[_tool_call(_observation())],
            native_calls=[{
                "tool": "read",
                "call_id": "call_1",
                "status": "completed",
                "input": {"filePath": "/work/go.mod"},
                "output_preview": "module k8s.io/kubernetes",
            }],
        )
        f.write_run_summary()
        comparison = R.build_comparison(f.root)
        record = next(
            item for item in comparison["attempts"]
            if item["attempt_key"] == P.EXPERIMENT_ID + "/E/r1"
        )
        research = record["research"]
        self.assertEqual(research["native_tool_call_count"], 1)
        self.assertEqual(research["mcp_tool_call_count"], 1)
        self.assertGreaterEqual(research["citation_count"], 3)
        self.assertEqual(research["decisive_observation_ids"], ["OBS-1"])
        observations = research["observations"]
        self.assertEqual(len(observations), 1)
        self.assertTrue(observations[0]["decisive"])
        self.assertEqual(observations[0]["cited_by"], ["sha256:" + SHA_B])
        by_ref = {citation["ref"]: citation
                  for citation in research["citations"]}
        self.assertTrue(by_ref["sha256:" + SHA_B]["resolved"])
        self.assertEqual(
            by_ref["sha256:" + SHA_B]["observation_ids"], ["OBS-1"]
        )
        self.assertTrue(by_ref["file:/work/go.mod:45"]["resolved"])
        self.assertEqual(
            by_ref["file:/work/go.mod:45"]["native_call_ids"], ["call_1"]
        )
        self.assertTrue(
            by_ref["https://example.com/advisory"]["resolved"]
            is False
        )
        self.assertEqual(
            record["diagnosis"]["kind"], "researched_but_wrong_conclusion"
        )

    def test_no_trace_is_not_researched(self):
        f = self.fixture
        f.write_attempt(
            "A", 1,
            status=_status(category="code_not_present"),
            raw=_answer("code_not_present"),
        )
        f.write_attempt(
            "A", 2,
            status=_status(category="uncertain"),
            raw=_answer("uncertain"),
        )
        f.write_run_summary()
        comparison = R.build_comparison(f.root)
        by_key = {record["attempt_key"]: record
                  for record in comparison["attempts"]}
        self.assertEqual(
            by_key[P.EXPERIMENT_ID + "/A/r1"]["diagnosis"]["kind"],
            "not_researched",
        )
        self.assertEqual(
            by_key[P.EXPERIMENT_ID + "/A/r2"]["diagnosis"]["kind"],
            "not_researched",
        )

    def test_native_calls_recovered_from_raw_export_when_file_absent(self):
        f = self.fixture
        raw = _answer("code_not_reachable")
        result_json = {
            "info": {"id": "session"},
            "messages": [
                {
                    "info": {"role": "assistant"},
                    "parts": [
                        {"type": "tool", "tool": "read", "callID": "call_9",
                         "state": {"status": "completed",
                                   "input": {"filePath": "/work/go.mod"},
                                   "output": "module"}},
                        {"type": "text", "text": raw},
                    ],
                },
            ],
        }
        path = f.write_attempt(
            "D", 1,
            status=_status(category="code_not_reachable"),
            raw=raw,
            write_native_file=False,
            result_json=result_json,
        )
        # The report should fall back to result.json for both the terminal
        # text and the native call trace.
        (path / "raw_agent_output.txt").unlink()
        f.write_run_summary()
        comparison = R.build_comparison(f.root)
        record = next(
            item for item in comparison["attempts"]
            if item["attempt_key"] == P.EXPERIMENT_ID + "/D/r1"
        )
        self.assertEqual(
            record["research"]["native_tool_calls_source"],
            "result.json:tool_parts",
        )
        self.assertEqual(record["research"]["native_tool_call_count"], 1)
        self.assertEqual(record["audit_projection"]["source"],
                         "result.json:opencode")
        self.assertEqual(
            record["audit_projection"]["category"], "code_not_reachable"
        )


class OfficialParserReDerivationTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.fixture = ExperimentFixture(Path(self._tmp.name))

    def tearDown(self):
        self._tmp.cleanup()

    def test_category_is_rederived_when_status_omits_it(self):
        f = self.fixture
        status = _status(category="vulnerable")
        status.pop("category")
        f.write_attempt("A", 1, status=status, raw=_answer("vulnerable"))
        f.write_run_summary()
        calls = []

        def parser(text):
            calls.append(text)
            return "vulnerable", "synthetic reasoning"

        comparison = R.build_comparison(f.root, official_parser=parser)
        record = comparison["attempts"][0]
        official = record["official_parser_result"]
        self.assertEqual(official["category"], "vulnerable")
        self.assertEqual(official["category_source"], R.OFFICIAL_PARSER_NAME)
        self.assertNotIn("category", official["record"])
        self.assertEqual(record["first_layer_outcome"], "vulnerable")
        self.assertEqual(len(calls), 1)

    def test_runner_saved_official_category_is_preferred(self):
        f = self.fixture
        status = _status(category="code_not_reachable")
        status.pop("category")
        f.write_attempt(
            "A", 1, status=status, raw=_answer("code_not_reachable"),
            attempt_extra={
                "official_category": "code_not_reachable",
                "official_category_source": "attempt.json.official_category",
            },
        )
        f.write_run_summary()

        def parser(text):
            raise AssertionError(
                "a saved official category must not be re-parsed"
            )

        comparison = R.build_comparison(f.root, official_parser=parser)
        record = comparison["attempts"][0]
        official = record["official_parser_result"]
        self.assertEqual(official["category"], "code_not_reachable")
        self.assertEqual(
            official["category_source"], "attempt.json.official_category"
        )
        self.assertEqual(
            record["first_layer_outcome"], "dangerous_negative"
        )

    def test_parse_failure_is_not_reparsed(self):
        f = self.fixture
        f.write_attempt(
            "A", 1,
            status=_status(execution="invalid_terminal_answer",
                           official_parse="parse_fail", category=None,
                           failure_reason="invalid_terminal_answer"),
            raw=_answer("vulnerable"),
        )
        f.write_run_summary()

        def parser(text):
            raise AssertionError("the parser must not run on a parse_fail")

        comparison = R.build_comparison(f.root, official_parser=parser)
        record = comparison["attempts"][0]
        self.assertEqual(
            record["official_parser_result"]["official_parse"], "parse_fail"
        )
        self.assertIsNone(record["official_parser_result"]["category"])
        self.assertEqual(record["first_layer_outcome"], "parse_failure")


class IntegrityTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.fixture = ExperimentFixture(Path(self._tmp.name))

    def tearDown(self):
        self._tmp.cleanup()

    def test_prompt_hash_mismatch_is_an_integrity_error(self):
        f = self.fixture
        f.write_attempt("A", 1, prompt_text="tampered prompt\n")
        f.write_run_summary()
        comparison = R.build_comparison(f.root)
        self.assertFalse(comparison["integrity"]["ok"])
        self.assertTrue(any(
            "prompt hash mismatch" in error
            for error in comparison["integrity"]["errors"]
        ))
        self.assertFalse(comparison["attempts"][0]["prompt"]["matches_manifest"])

    def test_request_hash_mismatch_is_an_integrity_error(self):
        f = self.fixture
        f.write_attempt("A", 1, request_user_sha="0" * 64)
        f.write_run_summary()
        comparison = R.build_comparison(f.root)
        self.assertTrue(any(
            "request_user_sha256" in error
            for error in comparison["integrity"]["errors"]
        ))

    def test_arm_identity_mismatch_is_an_integrity_error(self):
        f = self.fixture
        f.write_attempt(
            "A", 1,
            attempt_extra={"arm": "E", "mcp": True,
                           "agent": "opencode-c1"},
        )
        f.write_run_summary()
        comparison = R.build_comparison(f.root)
        self.assertTrue(any(
            "arm" in error and "!=" in error
            for error in comparison["integrity"]["errors"]
        ))

    def test_corrupt_status_is_reported_not_fatal(self):
        f = self.fixture
        path = f.write_attempt("A", 1)
        (path / "status.json").write_text("{not json", encoding="utf-8")
        f.write_run_summary()
        comparison = R.build_comparison(f.root)
        self.assertFalse(comparison["integrity"]["ok"])
        self.assertTrue(any(
            "invalid JSON" in error
            for error in comparison["integrity"]["errors"]
        ))
        record = comparison["attempts"][0]
        self.assertTrue(record["official_parser_result"]["available"])
        self.assertEqual(
            record["official_parser_result"]["source"],
            "attempt.json.status",
        )
        self.assertEqual(record["first_layer_outcome"], "vulnerable")

    def test_missing_attempts_are_reported_not_counted_as_zero(self):
        f = self.fixture
        f.write_attempt("A", 1)
        entries = []
        for key, entry in f.schedule.items():
            item = dict(entry)
            if key == P.EXPERIMENT_ID + "/A/r1":
                item["outcome"] = "completed"
            else:
                item["outcome"] = "not_run"
                item["failure_reason"] = "runtime_drift"
            entries.append(item)
        f.write_run_summary(entries)
        comparison = R.build_comparison(f.root)
        self.assertEqual(comparison["totals"]["attempts"], 15)
        self.assertEqual(comparison["totals"]["present"], 1)
        self.assertEqual(comparison["totals"]["missing"], 14)
        self.assertEqual(
            comparison["totals"]["outcomes"]["missing_attempt"], 14
        )
        self.assertEqual(
            comparison["totals"]["outcomes"]["vulnerable"], 1
        )
        missing = [record for record in comparison["attempts"]
                   if not record["present"]]
        self.assertEqual(len(missing), 14)
        self.assertTrue(all(
            record["run_summary"]["outcome"] == "not_run"
            for record in missing
        ))
        self.assertTrue(any(
            "not_run" in warning
            for warning in comparison["integrity"]["warnings"]
        ))


class MarkdownAndWriterTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.fixture = ExperimentFixture(Path(self._tmp.name))

    def tearDown(self):
        self._tmp.cleanup()

    def _comparison(self):
        f = self.fixture
        f.write_attempt("A", 1, status=_status(category="vulnerable"),
                        raw=_answer("vulnerable"))
        f.write_attempt(
            "A", 2,
            status=_status(execution="invalid_terminal_answer",
                           official_parse="parse_fail", category=None,
                           failure_reason="invalid_terminal_answer"),
            raw=_answer("vulnerable"),
        )
        f.write_attempt(
            "D", 1,
            status=_status(category="code_not_reachable"),
            raw=_answer(
                "code_not_reachable",
                assessment={"evidence_quality": {
                    "references": ["sha256:" + SHA_B],
                    "summary": "fixture",
                }},
            ),
            tool_calls=[_tool_call(_observation())],
            native_calls=[{"tool": "read", "call_id": "call_1",
                           "status": "completed",
                           "input": {"filePath": "/work/go.mod"}}],
        )
        f.write_run_summary()
        return R.build_comparison(f.root)

    def test_markdown_states_scope_and_shows_all_required_sections(self):
        comparison = self._comparison()
        text = R.render_markdown(comparison)
        self.assertIn("Single-case diagnostic", text)
        self.assertIn("not evidence of general parity", text)
        self.assertIn("dangerous_negative", text)
        self.assertIn("parse_failure", text)
        self.assertIn("Official vs full-JSON audit projection", text)
        self.assertIn("Treatment deltas vs control A", text)
        self.assertIn("Decisive tool observations and source citations", text)
        self.assertIn("correct_answer_lost_by_parser", text)
        self.assertIn("not_researched", text)
        self.assertIn("researched_but_wrong_conclusion", text)
        self.assertIn("downstream verifier", text.lower())
        self.assertIn("| **A** |", text)
        self.assertIn("| **E** |", text)
        self.assertIn("sha256:" + SHA_B, text)
        self.assertIn("call_1", text)
        self.assertIn("/work/go.mod", text)

    def test_write_report_emits_json_and_markdown(self):
        comparison = self._comparison()
        out = Path(self._tmp.name) / "out"
        json_path, md_path = R.write_report(comparison, out)
        self.assertTrue(json_path.is_file())
        self.assertTrue(md_path.is_file())
        loaded = json.loads(json_path.read_text(encoding="utf-8"))
        self.assertEqual(loaded["schema"], R.REPORT_SCHEMA)
        self.assertEqual(loaded["totals"]["attempts"], 15)
        self.assertIn("single-case", md_path.read_text(encoding="utf-8").lower())

    def test_cli_writes_report_and_fails_on_integrity(self):
        self._comparison()
        out = Path(self._tmp.name) / "cli-out"
        code = R.main([
            "--experiment-dir", str(self.fixture.root),
            "--out-dir", str(out),
        ])
        self.assertEqual(code, 0)
        self.assertTrue((out / "comparison.json").is_file())
        self.assertTrue((out / "comparison.md").is_file())

        # Tamper with a prompt hash, then require failure explicitly.
        path = self.fixture.attempt_dir("A", 1) / "prompt.txt"
        path.write_text("tampered\n", encoding="utf-8")
        code = R.main([
            "--experiment-dir", str(self.fixture.root),
            "--out-dir", str(out),
            "--fail-on-integrity",
        ])
        self.assertEqual(code, 2)


class ManifestGuardTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.fixture = ExperimentFixture(Path(self._tmp.name))

    def tearDown(self):
        self._tmp.cleanup()

    def test_wrong_case_is_rejected(self):
        manifest_path = self.fixture.root / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["case"]["cve_id"] = "CVE-2000-0000"
        manifest.pop("manifest_sha256", None)
        manifest = P.seal_manifest(manifest)
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        with self.assertRaises(R.ReportError):
            R.build_comparison(self.fixture.root)

    def test_tampered_manifest_hash_is_rejected(self):
        manifest_path = self.fixture.root / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["manifest_sha256"] = "0" * 64
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        with self.assertRaises(R.ReportError):
            R.build_comparison(self.fixture.root)


if __name__ == "__main__":
    unittest.main()

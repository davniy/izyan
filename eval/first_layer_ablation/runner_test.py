"""Tests for the first-layer ablation attempt controller (Task 2).

Everything here is hermetic: fake adapters, fake attempt execution and a
fake finalizer.  No Docker, provider, network, harness checkout or izyan
MCP call is made, and no live model output is used.

The one integration test that exercises the real ``eval.c1`` finalizer is
skipped when the interpreter lacks pydantic v2 (the repository's harness
venv is the supported environment for ``eval.c1``).
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from eval.first_layer_ablation import protocol, runner

DIGEST = "sha256:" + "b" * 64
DIGEST_OTHER = "sha256:" + "c" * 64
FROZEN_AT = "2026-10-24T00:00:00Z"
CVE_ID = "CVE-2023-44487"

try:  # the harness venv carries pydantic v2; a bare interpreter may not
    import pydantic

    HAS_PYDANTIC_V2 = int(pydantic.VERSION.split(".")[0]) >= 2
except Exception:  # pragma: no cover - environment dependent
    HAS_PYDANTIC_V2 = False


# ---------------------------------------------------------------------------
# Fixtures and fakes
# ---------------------------------------------------------------------------


def runtime_payload(
    *, digest: str = None, provider: str = protocol.PROVIDER,
    image_tag: str = "vex-bench-go-opencode-c1:latest",
) -> dict:
    return {
        "model": {
            "id": protocol.MODEL_ID,
            "alias": protocol.MODEL_ALIAS,
            "provider": provider,
            "provider_model_id": protocol.PROVIDER_MODEL_ID,
            "revision": None,
        },
        "endpoint": {
            "base_url": "http://127.0.0.1:9/v1",
            "provider_endpoint": "custom-openai",
            "transport": "http",
        },
        "image": {
            "tag": image_tag,
            "digest": digest,
            "same_digest_all_arms": True,
        },
        "parameters": {"temperature": 0, "max_tokens": 1024},
        "native_tools": ["bash", "edit", "glob", "grep", "read", "write"],
        "permissions": {"mode": "read-only", "network": "none"},
    }


def case_payload(snapshot: Path) -> dict:
    return {
        "task_id": "kubernetes-e196d24",
        "cve_id": "CVE-2023-44487",
        "repo_url": "https://local.invalid/kubernetes",
        "commit_sha": "e196d2491087e93bd29f0e5a538aab60667021e3",
        "language": "go",
        "snapshot_path": str(snapshot),
    }


def write_advisory(root: Path) -> Path:
    path = root / "advisory.json"
    path.write_text(
        json.dumps({"id": "CVE-2023-44487", "summary": "fixture"}) + "\n",
        encoding="utf-8",
    )
    return path


def write_snapshot(root: Path) -> Path:
    snapshot = root / "snap"
    (snapshot / "staging" / "src").mkdir(parents=True)
    (snapshot / "go.mod").write_text("module example.invalid/k8s\n")
    (snapshot / "staging" / "src" / "main.go").write_text(
        "package main\n\nfunc main() {}\n"
    )
    return snapshot


def write_secret_env(root: Path, value: str = "TEST_SECRET") -> Path:
    path = root / "opencode.env"
    path.write_text("OPENAI_API_KEY={}\n".format(value), encoding="utf-8")
    return path


def export_payload(
    prompt: str,
    *,
    model: str = protocol.MODEL_ID,
    provider: str = protocol.PROVIDER,
    final_text: str = None,
    tools: bool = True,
    system_text: str = "adapter system prompt",
) -> dict:
    if final_text is None:
        final_text = json.dumps({"category": "vulnerable", "reasoning": "r"})
    parts = []
    if tools:
        parts.extend(
            [
                {
                    "type": "tool",
                    "tool": "bash",
                    "callID": "call-1",
                    "state": {
                        "status": "completed",
                        "input": {"command": "ls"},
                        "output": "go.mod\nstaging/\n",
                    },
                },
                {
                    "type": "tool",
                    "tool": "read",
                    "callID": "call-2",
                    "state": {
                        "status": "error",
                        "input": {"filePath": "go.mod"},
                        "output": "",
                        "error": "not found",
                    },
                },
            ]
        )
    parts.append({"type": "text", "text": final_text})
    return {
        "info": {
            "id": "ses_fixture",
            "version": "1.15.5",
            "model": {"id": model, "providerID": provider},
            "tokens": {
                "input": 10,
                "output": 5,
                "reasoning": 2,
                "cache": {"read": 3, "write": 0},
            },
        },
        "messages": [
            {
                "info": {"role": "system"},
                "parts": [{"type": "text", "text": system_text}],
            },
            {
                "info": {"role": "user"},
                "parts": [{"type": "text", "text": prompt}],
            },
            {"info": {"role": "assistant"}, "parts": parts},
        ],
    }


def official_parser(text: str):
    """The official contract in miniature: category + reasoning, or none."""
    try:
        payload = json.loads(text)
    except (TypeError, ValueError):
        return None, None
    if not isinstance(payload, dict):
        return None, None
    category = payload.get("category")
    return (category, payload.get("reasoning")) if category else (None, None)


AUDIT_RECORD = {
    "tool": "get_product_snapshot",
    "args": {},
    "observation": {
        "id": "OBS-0001",
        "tool": "get_product_snapshot",
        "fact": "snapshot identity fixture",
        "completeness": "COMPLETE",
        "tool_status": "OK",
    },
}


class FakeAgent:
    IMAGE_SUFFIX = protocol.RUNTIME_IMAGE_SUFFIX
    PIPELINE = protocol.RUNTIME_PIPELINE

    def __init__(self, profile: str = "opencode-c1-nomcp") -> None:
        self.profile = profile
        self.model_name = protocol.PROVIDER_MODEL_ID
        self.mcp_enabled = profile == "opencode-c1"
        self.config_tag = "c1" if self.mcp_enabled else "c1-nomcp"

    def effective_config_facts(self) -> dict:
        """Mirror the harness contract; paths come from the bound env."""
        return {
            "pipeline": self.PIPELINE,
            "image_suffix": self.IMAGE_SUFFIX,
            "model_binding": self.model_name,
            "mcp_enabled": self.mcp_enabled,
            "config_tag": self.config_tag,
            "env_file": os.environ[runner.HARNESS_ENV_FILE_VAR],
            "config_source": os.environ[runner.HARNESS_CONFIG_VAR],
            "extra_artifacts": ["izyan-audit"],
        }

    def build_config(self, *, cve_id=None) -> dict:
        config = {
            "provider": {
                "custom-openai": {
                    "options": {
                        "baseURL": "https://api.invalid/openai/v1/",
                        "apiKey": "{env:OPENAI_API_KEY}",
                    },
                    "models": {"Qwen/Qwen3.6-35B-A3B": {"name": "Qwen"}},
                }
            },
            "tools": {"task": False},
        }
        if self.mcp_enabled:
            if cve_id is None:
                raise RuntimeError("fake opencode-c1 needs a cve_id")
            config["mcp"] = {
                "izyan": {
                    "type": "local",
                    "command": [
                        "/usr/local/bin/izyan-evidence-tools",
                        "--snapshot-root", "/work",
                        "--cve", cve_id,
                        "--audit-file",
                        "/tmp/izyan-audit/tool_calls.jsonl",
                    ],
                    "environment": {"PATH": "/usr/local/bin:/usr/bin:/bin"},
                    "enabled": True,
                }
            }
        return config

    def result_filename(self) -> str:
        return "result.json"

    def extract_text(self, raw: str) -> str:
        payload = json.loads(raw)
        text = ""
        for message in payload.get("messages", []):
            if (message.get("info") or {}).get("role") == "assistant":
                for part in message.get("parts", []):
                    if isinstance(part, dict) and part.get("type") == "text":
                        text = part.get("text", "")
        return text

    def extract_stats(self, raw: str):
        tokens = (json.loads(raw).get("info") or {}).get("tokens") or {}
        return types.SimpleNamespace(
            input_tokens=tokens.get("input"),
            cached_input_tokens=(tokens.get("cache") or {}).get("read"),
            output_tokens=tokens.get("output"),
            reasoning_tokens=tokens.get("reasoning"),
        )


class OtherImageAgent(FakeAgent):
    IMAGE_SUFFIX = "other"


class NoImageAgent(FakeAgent):
    IMAGE_SUFFIX = None


class NoFactsAgent(FakeAgent):
    effective_config_facts = None


class NoConfigAgent(FakeAgent):
    build_config = None


def fake_loader(profile: str, model: str) -> FakeAgent:
    agent = FakeAgent(profile)
    # The real OpenCode constructor stores the provider-qualified id when
    # the caller passes the frozen alias.
    agent.model_name = (
        protocol.PROVIDER_MODEL_ID
        if model == protocol.MODEL_ALIAS
        else model
    )
    return agent


def fake_artifacts(run_dir: Path, agent, wall_seconds: float) -> None:
    """Mirror ``eval.c1.runner.write_controller_artifacts`` without pydantic."""
    run_dir = Path(run_dir)
    result = run_dir / agent.result_filename()
    if result.is_file():
        raw = result.read_text(encoding="utf-8")
        (run_dir / runner.FINAL_TEXT_NAME).write_text(
            agent.extract_text(raw) + "\n", encoding="utf-8"
        )
        stats = agent.extract_stats(raw)
        (run_dir / runner.USAGE_NAME).write_text(
            json.dumps(
                {
                    "input_tokens": stats.input_tokens,
                    "cached_input_tokens": stats.cached_input_tokens,
                    "output_tokens": stats.output_tokens,
                    "reasoning_tokens": stats.reasoning_tokens,
                    "tool_calls": 1,
                    "cost_usd": None,
                    "wall_seconds": round(wall_seconds, 3),
                }
            )
            + "\n",
            encoding="utf-8",
        )
    audit = run_dir / runner.AUDIT_REL
    if audit.is_file():
        (run_dir / runner.TOOL_CALLS_NAME).write_text(
            audit.read_text(encoding="utf-8"), encoding="utf-8"
        )
        observations = []
        for line in audit.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            observation = record.get("observation")
            if isinstance(observation, dict):
                observations.append(json.dumps(observation, sort_keys=True))
        (run_dir / runner.OBSERVATIONS_NAME).write_text(
            "\n".join(observations) + ("\n" if observations else ""),
            encoding="utf-8",
        )
    export_report = run_dir / "artifacts" / "export-report.json"
    if export_report.is_file():
        shutil.copyfile(export_report, run_dir / runner.EXPORT_REPORT_NAME)


def fake_meta(**kwargs):
    """Stand-in for ``eval.c1.assessment.AttemptMeta`` (no pydantic)."""
    return kwargs


def fake_finalize(
    run_dir: Path,
    *,
    meta,
    usage,
    result_filename,
    final_text_extractor,
    official_parser,
):
    """Minimal stand-in for ``eval.c1.collect.finalize_attempt``."""
    run_dir = Path(run_dir)
    result = run_dir / result_filename
    if not result.is_file():
        if (run_dir / runner.ERROR_NAME).is_file():
            status = {
                "execution": "transport_failure",
                "official_parse": "no_result",
                "assessment_schema": "absent",
                "parser_audit": "not_run",
                "overall": "failed",
                "failure_reason": "docker_start_failed",
            }
        else:
            status = {
                "execution": "no_output",
                "official_parse": "no_result",
                "assessment_schema": "absent",
                "parser_audit": "not_run",
                "overall": "failed",
                "failure_reason": "no_result",
            }
    else:
        text = final_text_extractor(result.read_text(encoding="utf-8")).strip()
        category, _reasoning = official_parser(text)
        if category:
            status = {
                "execution": "ok",
                "official_parse": "accepted",
                "assessment_schema": "absent",
                "parser_audit": "matched",
                "overall": "valid",
                "failure_reason": None,
            }
        elif "can't help" in text.lower() or "refused" in text.lower():
            status = {
                "execution": "provider_refusal",
                "official_parse": "parse_fail",
                "assessment_schema": "absent",
                "parser_audit": "no_object",
                "overall": "failed",
                "failure_reason": "provider_refusal",
            }
        else:
            status = {
                "execution": "invalid_terminal_answer",
                "official_parse": "parse_fail",
                "assessment_schema": "absent",
                "parser_audit": "no_object",
                "overall": "failed",
                "failure_reason": "invalid_terminal_answer",
            }
    (run_dir / runner.STATUS_NAME).write_text(
        json.dumps(status), encoding="utf-8"
    )
    return status, None


class AttemptRunner:
    """One fake adapter execution; counts calls and can fail by mode."""

    def __init__(
        self,
        mode: str = "ok",
        *,
        drift_model: str = None,
        final_text: str = None,
    ) -> None:
        self.mode = mode
        self.drift_model = drift_model
        self.final_text = final_text
        self.calls = []

    def __call__(self, run_dir, *, agent, prompt, src_cwd, language, timeout):
        self.calls.append(str(run_dir))
        run_dir = Path(run_dir)
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / runner.PROMPT_NAME).write_text(prompt, encoding="utf-8")
        if self.mode == "transport":
            (run_dir / runner.ERROR_NAME).write_text(
                "docker start failed\n", encoding="utf-8"
            )
            return None
        if self.mode == "no_result":
            return None
        if self.mode == "refusal":
            export = export_payload(
                prompt,
                final_text="I'm sorry, I can't help with that request.",
                tools=False,
            )
        elif self.mode == "parse_fail":
            export = export_payload(prompt, final_text="not a json object")
        elif self.mode == "drift":
            export = export_payload(
                prompt, model=self.drift_model or "another/model", tools=False
            )
        else:
            export = export_payload(
                prompt, final_text=self.final_text, tools=self.final_text is None
            )
        (run_dir / agent.result_filename()).write_text(
            json.dumps(export), encoding="utf-8"
        )
        audit = run_dir / runner.AUDIT_REL
        audit.parent.mkdir(parents=True, exist_ok=True)
        audit.write_text(json.dumps(AUDIT_RECORD) + "\n", encoding="utf-8")
        export_report = run_dir / "artifacts" / "export-report.json"
        export_report.write_text(
            json.dumps({"ok": True, "exported": ["/work"]}),
            encoding="utf-8",
        )
        return run_dir / agent.result_filename()


class RunnerTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="first-layer-runner-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.advisory = write_advisory(self.tmp)
        self.snapshot = write_snapshot(self.tmp)
        self.env = write_secret_env(self.tmp)
        self.config = self.tmp / "opencode.json"
        self.config.write_text(
            json.dumps({"tools": {"task": False}}) + "\n", encoding="utf-8"
        )
        self.harness = self.tmp / "harness"
        self.case = case_payload(self.snapshot)
        self.runtime = runtime_payload()
        self.results = self.tmp / "results"
        self.experiment_root = (
            self.results / protocol.EXPERIMENT_ID
        )

    # -- helpers ---------------------------------------------------------

    @contextlib.contextmanager
    def launch(self):
        with runner.launch_environment(
            secret_env_path=self.env,
            secret_config_path=self.config,
            harness_dir=self.harness,
        ) as overrides:
            yield overrides

    def snapshot_record(self) -> dict:
        return runner.probe_snapshot(self.snapshot)

    def manifest(self) -> dict:
        case = dict(self.case)
        case["snapshot_sha256"] = self.snapshot_record()["content_sha256"]
        return protocol.build_manifest(
            case=case,
            advisory_path=self.advisory,
            runtime=runtime_payload(digest=DIGEST),
            frozen_at_utc=FROZEN_AT,
        )

    def preflight(self, **overrides):
        kwargs = {
            "secret_env_path": self.env,
            "secret_config_path": self.config,
            "results_root": self.results,
            "case": self.case,
            "runtime": self.runtime,
            "advisory_path": self.advisory,
            "digest_probe": lambda tag: DIGEST,
            "agent_loader": fake_loader,
            "harness_dir": self.harness,
            "frozen_at_utc": FROZEN_AT,
        }
        kwargs.update(overrides)
        return runner.preflight(**kwargs)

    def run_all(
        self,
        *,
        mode: str = "ok",
        runner_impl=None,
        digest_probe=None,
        runtime: dict = None,
        finalize_fn=fake_finalize,
        artifacts_fn=fake_artifacts,
        official_parser=official_parser,
    ):
        attempt_runner = runner_impl or AttemptRunner(mode)
        kwargs = {
            "secret_env_path": self.env,
            "secret_config_path": self.config,
            "results_root": self.results,
            "case": self.case,
            "runtime": runtime or self.runtime,
            "advisory_path": self.advisory,
            "digest_probe": digest_probe or (lambda tag: DIGEST),
            "agent_loader": fake_loader,
            "harness_dir": self.harness,
            "run_attempt_fn": attempt_runner,
            "artifacts_fn": artifacts_fn,
            "finalize_fn": finalize_fn,
            "official_parser": official_parser,
            "meta_factory": fake_meta,
            "frozen_at_utc": FROZEN_AT,
        }
        summary = runner.run_experiment(**kwargs)
        return summary, attempt_runner

    def attempt_dirs(self):
        return sorted(self.experiment_root.glob("*/[A-E]/repeat-*"))

    def all_files_under(self, root: Path):
        return [path for path in Path(root).rglob("*") if path.is_file()]


# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------


class PreflightTest(RunnerTestCase):
    def test_builds_manifest_and_reports_ready_runtime(self):
        report = self.preflight()
        manifest_path = self.experiment_root / runner.MANIFEST_NAME
        self.assertTrue(manifest_path.is_file())
        manifest = runner.load_manifest(manifest_path)
        self.assertEqual(
            manifest["runtime"]["image"]["digest"], DIGEST
        )
        self.assertEqual(
            manifest["case"]["snapshot_sha256"],
            self.snapshot_record()["content_sha256"],
        )
        self.assertEqual(report["schema"], runner.PREFLIGHT_SCHEMA)
        self.assertEqual(report["image"]["digest"], DIGEST)
        self.assertEqual(report["equality"]["E_delta"], ["agent", "mcp"])
        self.assertTrue(report["equality"]["A_to_D_identical"])
        self.assertTrue(report["equality"]["same_pipeline_all_arms"])
        self.assertTrue(
            report["equality"]["generated_configs_equal_without_mcp"]
        )
        self.assertEqual(report["schedule"]["count"], 15)
        self.assertEqual(
            report["credentials"],
            {
                "channel": "secret_env_file",
                "path": str(self.env.resolve()),
                "keys": ["OPENAI_API_KEY"],
                "nonempty": 1,
                "values_recorded": False,
            },
        )
        for arm in protocol.ARM_ORDER:
            binding = report["adapter_bindings"][arm]
            self.assertEqual(
                binding["pipeline"], protocol.RUNTIME_PIPELINE
            )
            self.assertEqual(
                binding["image_suffix"], protocol.RUNTIME_IMAGE_SUFFIX
            )
            self.assertEqual(
                binding["model_binding"], protocol.PROVIDER_MODEL_ID
            )
            self.assertEqual(
                binding["env_file"], str(self.env.resolve())
            )
            self.assertEqual(
                binding["config_source"], str(self.config.resolve())
            )
            self.assertEqual(binding["mcp_enabled"], arm == "E")
        self.assertTrue((self.experiment_root / runner.PREFLIGHT_NAME).is_file())
        self.assertEqual(self.attempt_dirs(), [])

    def test_preflight_never_loads_a_model_answer(self):
        loaded = []

        def loader(profile, model):
            loaded.append(profile)
            return fake_loader(profile, model)

        self.preflight(agent_loader=loader)
        self.assertEqual(
            sorted(loaded), ["opencode-c1", "opencode-c1-nomcp"]
        )
        self.assertEqual(self.attempt_dirs(), [])

    def test_preflight_is_idempotent_for_the_same_environment(self):
        first = self.preflight()
        path = self.experiment_root / runner.PREFLIGHT_NAME
        before = path.read_bytes()
        second = self.preflight(frozen_at_utc="2026-10-25T00:00:00Z")
        self.assertEqual(first, second)
        self.assertEqual(path.read_bytes(), before)

    def test_changed_image_digest_is_refused(self):
        self.preflight()
        with self.assertRaises(runner.RuntimeContractError) as caught:
            self.preflight(digest_probe=lambda tag: DIGEST_OTHER)
        self.assertEqual(caught.exception.code, "image_digest_mismatch")
        self.assertEqual(caught.exception.failure_class, "infrastructure")

    def test_empty_secret_env_is_an_infrastructure_prerequisite(self):
        self.env.write_text("", encoding="utf-8")
        with self.assertRaises(runner.InfrastructureError) as caught:
            self.preflight()
        self.assertEqual(caught.exception.code, "secret_env_empty")
        self.assertIn("infrastructure prerequisite", str(caught.exception))
        self.assertFalse(
            (self.experiment_root / runner.MANIFEST_NAME).exists()
        )
        self.assertFalse(
            (self.experiment_root / runner.PREFLIGHT_NAME).exists()
        )
        self.assertEqual(self.attempt_dirs(), [])

    def test_missing_secret_env_is_refused(self):
        with self.assertRaises(runner.InfrastructureError) as caught:
            self.preflight(secret_env_path=self.tmp / "absent.env")
        self.assertEqual(caught.exception.code, "secret_env_missing")

    def test_secret_values_do_not_reach_preflight(self):
        secret = "SUPER-SECRET-VALUE"
        self.env.write_text(
            "OPENAI_API_KEY={}\n".format(secret), encoding="utf-8"
        )
        self.preflight()
        for path in self.all_files_under(self.experiment_root):
            self.assertNotIn(
                secret,
                path.read_text(encoding="utf-8", errors="replace"),
                str(path),
            )

    def test_missing_snapshot_is_refused_before_manifest_freeze(self):
        case = dict(self.case)
        case["snapshot_path"] = str(self.tmp / "absent-snapshot")
        with self.assertRaises(runner.InfrastructureError) as caught:
            self.preflight(case=case)
        self.assertEqual(caught.exception.code, "snapshot_missing")
        self.assertFalse(
            (self.experiment_root / runner.MANIFEST_NAME).exists()
        )

    def test_snapshot_path_must_name_the_pinned_commit(self):
        wrong = self.tmp / "deadbeef"
        wrong.mkdir()
        (wrong / "go.mod").write_text("module x\n")
        case = dict(self.case)
        case["snapshot_path"] = str(wrong)
        with self.assertRaises(runner.InfrastructureError) as caught:
            self.preflight(case=case)
        self.assertEqual(
            caught.exception.code, "snapshot_path_mismatch"
        )

    def test_snapshot_content_drift_is_refused(self):
        self.preflight()
        (self.snapshot / "go.mod").write_text("module changed\n")
        with self.assertRaises(runner.InfrastructureError) as caught:
            self.preflight()
        self.assertEqual(caught.exception.code, "snapshot_mismatch")

    def test_snapshot_commit_drift_is_refused(self):
        record = {
            "path": str(self.snapshot),
            "content_sha256": "d" * 64,
            "commit": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "file_count": 3,
            "method": runner.SNAPSHOT_METHOD,
        }
        with self.assertRaises(runner.InfrastructureError) as caught:
            self.preflight(snapshot_probe=lambda path: record)
        self.assertEqual(caught.exception.code, "snapshot_commit_mismatch")

    def test_invalid_snapshot_probe_is_refused(self):
        with self.assertRaises(runner.InfrastructureError) as caught:
            self.preflight(snapshot_probe=lambda path: {})
        self.assertEqual(caught.exception.code, "snapshot_probe_invalid")

    def test_adapter_image_tag_must_match_the_single_frozen_image(self):
        def loader(profile, model):
            cls = OtherImageAgent if profile == "opencode-c1" else FakeAgent
            agent = cls(profile)
            agent.model_name = protocol.PROVIDER_MODEL_ID
            return agent

        with self.assertRaises(runner.RuntimeContractError) as caught:
            self.preflight(agent_loader=loader)
        self.assertEqual(caught.exception.code, "image_suffix_mismatch")
        self.assertEqual(
            caught.exception.details["expected"],
            protocol.RUNTIME_IMAGE_SUFFIX,
        )
        self.assertFalse(
            (self.experiment_root / runner.MANIFEST_NAME).exists()
        )

    def test_unavailable_harness_is_infrastructure(self):
        def loader(profile, model):
            raise ImportError("harness adapters unavailable")

        with self.assertRaises(runner.InfrastructureError) as caught:
            self.preflight(agent_loader=loader)
        self.assertEqual(caught.exception.code, "harness_unavailable")
        self.assertFalse(
            (self.experiment_root / runner.MANIFEST_NAME).exists()
        )

    def test_canonical_model_binding_is_accepted(self):
        def loader(profile, model):
            agent = FakeAgent(profile)
            agent.model_name = protocol.PROVIDER_MODEL_ID
            return agent

        report = self.preflight(agent_loader=loader)
        for arm in protocol.ARM_ORDER:
            self.assertEqual(
                report["adapter_bindings"][arm]["model_binding"],
                protocol.PROVIDER_MODEL_ID,
            )

    def test_alias_model_binding_is_accepted(self):
        def loader(profile, model):
            agent = FakeAgent(profile)
            agent.model_name = protocol.MODEL_ALIAS
            return agent

        report = self.preflight(agent_loader=loader)
        for arm in protocol.ARM_ORDER:
            self.assertEqual(
                report["adapter_bindings"][arm]["model_binding"],
                protocol.MODEL_ALIAS,
            )

    def test_adapter_must_be_bound_to_the_pinned_model(self):
        def loader(profile, model):
            agent = FakeAgent(profile)
            agent.model_name = "another-model"
            return agent

        with self.assertRaises(runner.RuntimeContractError) as caught:
            self.preflight(agent_loader=loader)
        self.assertEqual(caught.exception.code, "model_mismatch")

    def test_other_provider_model_is_refused(self):
        def loader(profile, model):
            agent = FakeAgent(profile)
            agent.model_name = "other/Qwen/Qwen3.6-35B-A3B"
            return agent

        with self.assertRaises(runner.RuntimeContractError) as caught:
            self.preflight(agent_loader=loader)
        self.assertEqual(caught.exception.code, "model_mismatch")
        self.assertEqual(
            caught.exception.details["expected"],
            [protocol.PROVIDER_MODEL_ID, protocol.MODEL_ALIAS],
        )

    def test_secret_env_path_mismatch_is_refused(self):
        other_env = self.tmp / "other.opencode.env"
        other_env.write_text("OPENAI_API_KEY=OTHER\n", encoding="utf-8")

        def loader(profile, model):
            agent = fake_loader(profile, model)
            original = agent.effective_config_facts

            def facts():
                record = original()
                record["env_file"] = str(other_env)
                return record

            agent.effective_config_facts = facts
            return agent

        with self.assertRaises(runner.RuntimeContractError) as caught:
            self.preflight(agent_loader=loader)
        self.assertEqual(
            caught.exception.code, "secret_env_path_mismatch"
        )

    def test_secret_config_path_mismatch_is_refused(self):
        other_config = self.tmp / "other-opencode.json"
        other_config.write_text("{}\n", encoding="utf-8")

        def loader(profile, model):
            agent = fake_loader(profile, model)
            original = agent.effective_config_facts

            def facts():
                record = original()
                record["config_source"] = str(other_config)
                return record

            agent.effective_config_facts = facts
            return agent

        with self.assertRaises(runner.RuntimeContractError) as caught:
            self.preflight(agent_loader=loader)
        self.assertEqual(
            caught.exception.code, "secret_config_path_mismatch"
        )

    def test_missing_secret_config_is_infrastructure(self):
        with self.assertRaises(runner.InfrastructureError) as caught:
            self.preflight(secret_config_path=self.tmp / "absent.json")
        self.assertEqual(caught.exception.code, "secret_config_missing")

    def test_harness_dir_is_bound_for_adapter_loading(self):
        seen = {}
        prior = os.environ.get(runner.HARNESS_DIR_VAR)

        def loader(profile, model):
            seen["harness"] = os.environ.get(runner.HARNESS_DIR_VAR)
            return fake_loader(profile, model)

        self.preflight(agent_loader=loader)
        self.assertEqual(seen["harness"], str(self.harness.resolve()))
        self.assertEqual(
            os.environ.get(runner.HARNESS_DIR_VAR), prior
        )

    def test_adapter_without_image_suffix_is_refused(self):
        def loader(profile, model):
            agent = NoImageAgent(profile)
            agent.model_name = protocol.PROVIDER_MODEL_ID
            return agent

        with self.assertRaises(runner.RuntimeContractError) as caught:
            self.preflight(agent_loader=loader)
        self.assertEqual(caught.exception.code, "adapter_image_unknown")

    def test_provider_must_be_exactly_pinned(self):
        case = dict(self.case)
        case["snapshot_sha256"] = self.snapshot_record()["content_sha256"]
        manifest = protocol.build_manifest(
            case=case,
            advisory_path=self.advisory,
            runtime=runtime_payload(digest=DIGEST, provider="custom-openai-alt"),
            frozen_at_utc=FROZEN_AT,
        )
        path = self.tmp / "manifest.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaises(runner.RuntimeContractError) as caught:
            runner.preflight(
                secret_env_path=self.env,
                secret_config_path=self.config,
                manifest=manifest,
                manifest_path=path,
                digest_probe=lambda tag: DIGEST,
                agent_loader=fake_loader,
            )
        self.assertEqual(caught.exception.code, "provider_mismatch")

    def test_unresolved_digest_is_infrastructure_not_a_result(self):
        case = dict(self.case)
        case["snapshot_sha256"] = self.snapshot_record()["content_sha256"]
        manifest = protocol.build_manifest(
            case=case,
            advisory_path=self.advisory,
            runtime=runtime_payload(digest=None),
            frozen_at_utc=FROZEN_AT,
        )
        path = self.tmp / "manifest.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaises(runner.InfrastructureError) as caught:
            runner.preflight(
                secret_env_path=self.env,
                secret_config_path=self.config,
                manifest=manifest,
                manifest_path=path,
                digest_probe=lambda tag: DIGEST,
                agent_loader=fake_loader,
            )
        self.assertEqual(caught.exception.code, "image_digest_unresolved")

    def test_case_must_match_the_existing_manifest(self):
        self.preflight()
        changed = dict(self.case)
        changed["task_id"] = "another-case"
        with self.assertRaises(runner.RuntimeContractError) as caught:
            self.preflight(case=changed)
        self.assertEqual(caught.exception.code, "case_manifest_mismatch")

    def test_manifest_missing_is_infrastructure(self):
        with self.assertRaises(runner.InfrastructureError) as caught:
            runner.load_manifest(self.tmp / "absent-manifest.json")
        self.assertEqual(caught.exception.code, "manifest_missing")

    def test_preflight_requires_inputs(self):
        with self.assertRaises(runner.InfrastructureError) as caught:
            runner.preflight(
                secret_env_path=self.env,
                secret_config_path=self.config,
                results_root=self.results,
                digest_probe=lambda tag: DIGEST,
                agent_loader=fake_loader,
            )
        self.assertEqual(caught.exception.code, "preflight_inputs_missing")


# ---------------------------------------------------------------------------
# Effective config equality
# ---------------------------------------------------------------------------


class EffectiveConfigTest(RunnerTestCase):
    def configs(self, agents=None):
        agents = agents or {
            arm: fake_loader(profile, protocol.MODEL_ALIAS)
            for arm, profile in (
                (a, protocol.ARM_RUNTIME[a]["agent"])
                for a in protocol.ARM_ORDER
            )
        }
        manifest = self.manifest()
        with self.launch():
            return runner.build_arm_configs(
                manifest,
                agents,
                image_digest=DIGEST,
                snapshot_sha256="a" * 64,
                secret_env_path=self.env,
                secret_config_path=self.config,
            )

    def test_a_to_d_identical_and_e_differs_only_by_mcp(self):
        configs = self.configs()
        base = configs["A"]
        for arm in ("B", "C", "D"):
            self.assertEqual(base, configs[arm], arm)
        self.assertEqual(
            runner.changed_config_keys(base, configs["E"]),
            ["agent", "mcp"],
        )
        self.assertEqual(
            runner.assert_effective_contract(configs), ("agent", "mcp")
        )
        self.assertEqual(configs["E"]["agent"], "opencode-c1")
        self.assertTrue(configs["E"]["mcp"]["enabled"])
        self.assertFalse(configs["A"]["mcp"]["enabled"])
        server = configs["E"]["mcp"]["server"]
        self.assertTrue(server["enabled"])
        self.assertEqual(
            server["command"][0], "/usr/local/bin/izyan-evidence-tools"
        )
        self.assertIn(
            "/tmp/izyan-audit/tool_calls.jsonl", server["command"]
        )
        self.assertNotIn("server", configs["A"]["mcp"])
        for arm in protocol.ARM_ORDER:
            self.assertEqual(configs[arm]["image"]["digest"], DIGEST)
            self.assertEqual(
                configs[arm]["adapter"]["image_suffix"],
                protocol.RUNTIME_IMAGE_SUFFIX,
            )
            self.assertEqual(
                configs[arm]["adapter"]["pipeline"],
                protocol.RUNTIME_PIPELINE,
            )
            self.assertEqual(
                configs[arm]["adapter"]["model_binding"],
                protocol.PROVIDER_MODEL_ID,
            )
            self.assertEqual(
                configs[arm]["adapter"]["env_file"],
                str(self.env.resolve()),
            )
            self.assertEqual(
                configs[arm]["adapter"]["config_source"],
                str(self.config.resolve()),
            )
            self.assertTrue(
                configs[arm]["adapter"]["generated_config_sha256"]
            )
            self.assertEqual(
                configs[arm]["native_tools"],
                self.manifest()["runtime"]["native_tools"],
            )
            self.assertEqual(
                configs[arm]["permissions"],
                self.manifest()["runtime"]["permissions"],
            )
        hashes = {
            configs[arm]["adapter"]["generated_config_sha256"]
            for arm in protocol.ARM_ORDER
        }
        self.assertEqual(len(hashes), 1)

    def test_generated_configs_differ_only_by_mcp(self):
        self.configs()
        base = FakeAgent("opencode-c1-nomcp").build_config(cve_id=CVE_ID)
        c1 = FakeAgent("opencode-c1").build_config(cve_id=CVE_ID)
        self.assertNotIn("mcp", base)
        self.assertEqual(set(c1["mcp"]), {"izyan"})
        without_mcp = {k: v for k, v in c1.items() if k != "mcp"}
        self.assertEqual(base, without_mcp)

    def test_non_mcp_delta_is_refused(self):
        configs = self.configs()
        for arm in ("B", "C", "D"):
            configs[arm] = dict(configs[arm])
            configs[arm]["permissions"] = {
                "mode": "read-write", "network": "none"
            }
        with self.assertRaises(runner.RuntimeContractError) as caught:
            runner.assert_effective_contract(configs)
        self.assertEqual(caught.exception.code, "arm_config_mismatch")
        self.assertIn("permissions", caught.exception.details["changed"])

    def test_missing_mcp_flag_is_refused(self):
        configs = self.configs()
        configs["E"] = dict(configs["E"])
        configs["E"]["mcp"] = {"enabled": False}
        with self.assertRaises(runner.RuntimeContractError) as caught:
            runner.assert_effective_contract(configs)
        self.assertEqual(caught.exception.code, "mcp_delta_not_isolated")

    def test_wrong_mcp_agent_is_refused(self):
        configs = self.configs()
        configs["E"] = dict(configs["E"])
        configs["E"]["agent"] = "opencode-c1-nomcp"
        with self.assertRaises(runner.RuntimeContractError) as caught:
            runner.assert_effective_contract(configs)
        self.assertEqual(caught.exception.code, "mcp_delta_not_isolated")

    def test_incomplete_arm_set_is_refused(self):
        configs = self.configs()
        del configs["D"]
        with self.assertRaises(runner.RuntimeContractError) as caught:
            runner.assert_effective_contract(configs)
        self.assertEqual(
            caught.exception.code, "effective_config_incomplete"
        )

    def test_adapter_image_tag_format(self):
        self.assertEqual(
            runner.adapter_image_tag(FakeAgent(), "go"),
            "vex-bench-go-opencode-c1:latest",
        )
        with self.assertRaises(runner.RuntimeContractError):
            runner.adapter_image_tag(NoImageAgent(), "go")

    def test_build_configs_refuses_different_adapter_images(self):
        agents = {
            arm: fake_loader(protocol.ARM_RUNTIME[arm]["agent"], protocol.MODEL_ALIAS)
            for arm in protocol.ARM_ORDER
        }
        agents["E"] = OtherImageAgent("opencode-c1")
        with self.launch():
            with self.assertRaises(runner.RuntimeContractError) as caught:
                runner.build_arm_configs(
                    self.manifest(),
                    agents,
                    image_digest=DIGEST,
                    snapshot_sha256="a" * 64,
                    secret_env_path=self.env,
                    secret_config_path=self.config,
                )
        self.assertEqual(caught.exception.code, "image_suffix_mismatch")

    def test_build_configs_refuses_a_different_runtime_tag(self):
        manifest = protocol.build_manifest(
            case={
                **self.case,
                "snapshot_sha256": self.snapshot_record()["content_sha256"],
            },
            advisory_path=self.advisory,
            runtime=runtime_payload(
                digest=DIGEST, image_tag="vex-bench-go-opencode-e6:latest"
            ),
            frozen_at_utc=FROZEN_AT,
        )
        agents = {
            arm: fake_loader(protocol.ARM_RUNTIME[arm]["agent"], protocol.MODEL_ALIAS)
            for arm in protocol.ARM_ORDER
        }
        with self.launch():
            with self.assertRaises(runner.RuntimeContractError) as caught:
                runner.build_arm_configs(
                    manifest,
                    agents,
                    image_digest=DIGEST,
                    snapshot_sha256="a" * 64,
                    secret_env_path=self.env,
                    secret_config_path=self.config,
                )
        self.assertEqual(caught.exception.code, "image_tag_mismatch")

    def test_pipeline_drift_is_refused(self):
        agents = {
            arm: fake_loader(protocol.ARM_RUNTIME[arm]["agent"], protocol.MODEL_ALIAS)
            for arm in protocol.ARM_ORDER
        }
        agents["B"].PIPELINE = "opencode-e6-sandbox/v1"
        with self.launch():
            with self.assertRaises(runner.RuntimeContractError) as caught:
                runner.build_arm_configs(
                    self.manifest(),
                    agents,
                    image_digest=DIGEST,
                    snapshot_sha256="a" * 64,
                    secret_env_path=self.env,
                    secret_config_path=self.config,
                )
        self.assertEqual(caught.exception.code, "pipeline_mismatch")

    def test_missing_adapter_facts_is_refused(self):
        agents = {
            arm: fake_loader(protocol.ARM_RUNTIME[arm]["agent"], protocol.MODEL_ALIAS)
            for arm in protocol.ARM_ORDER
        }
        agents["C"] = NoFactsAgent("opencode-c1-nomcp")
        with self.launch():
            with self.assertRaises(runner.RuntimeContractError) as caught:
                runner.build_arm_configs(
                    self.manifest(),
                    agents,
                    image_digest=DIGEST,
                    snapshot_sha256="a" * 64,
                    secret_env_path=self.env,
                    secret_config_path=self.config,
                )
        self.assertEqual(caught.exception.code, "adapter_facts_missing")

    def test_missing_config_builder_is_refused(self):
        agents = {
            arm: fake_loader(protocol.ARM_RUNTIME[arm]["agent"], protocol.MODEL_ALIAS)
            for arm in protocol.ARM_ORDER
        }
        agents["D"] = NoConfigAgent("opencode-c1-nomcp")
        with self.launch():
            with self.assertRaises(runner.RuntimeContractError) as caught:
                runner.build_arm_configs(
                    self.manifest(),
                    agents,
                    image_digest=DIGEST,
                    snapshot_sha256="a" * 64,
                    secret_env_path=self.env,
                    secret_config_path=self.config,
                )
        self.assertEqual(caught.exception.code, "adapter_config_missing")

    def test_mcp_registered_in_nomcp_is_refused(self):
        agents = {
            arm: fake_loader(protocol.ARM_RUNTIME[arm]["agent"], protocol.MODEL_ALIAS)
            for arm in protocol.ARM_ORDER
        }
        bad = FakeAgent("opencode-c1-nomcp")

        def build_with_mcp(*, cve_id=None):
            return FakeAgent("opencode-c1").build_config(cve_id=cve_id)

        bad.build_config = build_with_mcp
        agents["B"] = bad
        with self.launch():
            with self.assertRaises(runner.RuntimeContractError) as caught:
                runner.build_arm_configs(
                    self.manifest(),
                    agents,
                    image_digest=DIGEST,
                    snapshot_sha256="a" * 64,
                    secret_env_path=self.env,
                    secret_config_path=self.config,
                )
        self.assertEqual(
            caught.exception.code, "mcp_registered_in_nomcp"
        )

    def test_missing_adapter_is_refused(self):
        agents = {}
        with self.launch():
            with self.assertRaises(runner.RuntimeContractError) as caught:
                runner.build_arm_configs(
                    self.manifest(),
                    agents,
                    image_digest=DIGEST,
                    snapshot_sha256="a" * 64,
                    secret_env_path=self.env,
                    secret_config_path=self.config,
                )
        self.assertEqual(caught.exception.code, "adapter_missing")


# ---------------------------------------------------------------------------
# Policy, schedule, paths, snapshot, secret channel
# ---------------------------------------------------------------------------


class ImageProbeTest(unittest.TestCase):
    def completed(self, stdout="", stderr="", returncode=0):
        return types.SimpleNamespace(
            stdout=stdout, stderr=stderr, returncode=returncode
        )

    def test_successful_probe_returns_content_id(self):
        calls = []

        def command_runner(args, **kwargs):
            calls.append((args, kwargs))
            return self.completed(stdout=DIGEST + "\n")

        self.assertEqual(
            runner.probe_image_digest(
                "vex-bench-go-test:latest", command_runner=command_runner
            ),
            DIGEST,
        )
        self.assertIn("image", calls[0][0])
        self.assertIn("inspect", calls[0][0])

    def test_missing_image_is_infrastructure(self):
        with self.assertRaises(runner.InfrastructureError) as caught:
            runner.probe_image_digest(
                "absent:latest",
                command_runner=lambda *a, **k: self.completed(
                    stderr="No such image", returncode=1
                ),
            )
        self.assertEqual(caught.exception.code, "image_unavailable")

    def test_invalid_digest_is_infrastructure(self):
        with self.assertRaises(runner.InfrastructureError) as caught:
            runner.probe_image_digest(
                "bad:latest",
                command_runner=lambda *a, **k: self.completed(
                    stdout="not-a-digest"
                ),
            )
        self.assertEqual(caught.exception.code, "image_digest_invalid")

    def test_absent_docker_cli_is_infrastructure(self):
        def command_runner(*args, **kwargs):
            raise FileNotFoundError("docker")

        with self.assertRaises(runner.InfrastructureError) as caught:
            runner.probe_image_digest(
                "vex-bench-go-test:latest", command_runner=command_runner
            )
        self.assertEqual(caught.exception.code, "docker_unavailable")

    def test_tool_adapter_version_is_read_from_source(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "internal" / "evidencetools" / "service.go"
            path.parent.mkdir(parents=True)
            path.write_text('const AdapterVersion = "v9-test"\n')
            self.assertEqual(
                runner.tool_adapter_version(Path(td)), "v9-test"
            )
            path.unlink()
            self.assertEqual(
                runner.tool_adapter_version(Path(td)), "unknown"
            )


class ImmutableWriteTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="first-layer-write-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_json_once_never_overwrites(self):
        path = self.tmp / "attempt.json"
        runner.write_json_once(path, {"a": 1})
        with self.assertRaises(runner.AttemptExistsError):
            runner.write_json_once(path, {"a": 2})
        self.assertEqual(json.loads(path.read_text()), {"a": 1})

    def test_matching_write_is_idempotent(self):
        path = self.tmp / "preflight.json"
        runner.write_json_once_matching(path, {"a": 1})
        runner.write_json_once_matching(path, {"a": 1})
        with self.assertRaises(runner.AttemptExistsError):
            runner.write_json_once_matching(path, {"a": 2})

    def test_text_once_never_overwrites(self):
        path = self.tmp / "native.jsonl"
        runner.write_text_once(path, "one\n")
        with self.assertRaises(runner.AttemptExistsError):
            runner.write_text_once(path, "two\n")
        self.assertEqual(path.read_text(), "one\n")


class ManifestTargetTest(RunnerTestCase):
    def test_explicit_manifest_path_is_frozen_there(self):
        target = self.tmp / "frozen" / "manifest.json"
        report = runner.preflight(
            secret_env_path=self.env,
            secret_config_path=self.config,
            manifest_path=target,
            case=self.case,
            runtime=self.runtime,
            advisory_path=self.advisory,
            digest_probe=lambda tag: DIGEST,
            agent_loader=fake_loader,
            frozen_at_utc=FROZEN_AT,
        )
        self.assertTrue(target.is_file())
        self.assertEqual(report["manifest_path"], str(target.resolve()))
        self.assertTrue(
            (
                target.parent
                / protocol.EXPERIMENT_ID
                / runner.PREFLIGHT_NAME
            ).is_file()
        )
        manifest = runner.load_manifest(target)
        self.assertEqual(manifest["runtime"]["image"]["digest"], DIGEST)

    def test_in_memory_manifest_is_frozen_at_the_given_path(self):
        case = dict(self.case)
        case["snapshot_sha256"] = self.snapshot_record()["content_sha256"]
        manifest = protocol.build_manifest(
            case=case,
            advisory_path=self.advisory,
            runtime=runtime_payload(digest=DIGEST),
            frozen_at_utc=FROZEN_AT,
        )
        target = self.tmp / "new" / "manifest.json"
        report = runner.preflight(
            secret_env_path=self.env,
            secret_config_path=self.config,
            manifest=manifest,
            manifest_path=target,
            digest_probe=lambda tag: DIGEST,
            agent_loader=fake_loader,
        )
        self.assertTrue(target.is_file())
        self.assertEqual(report["manifest_sha256"], manifest["manifest_sha256"])

    def test_conflicting_existing_manifest_is_refused(self):
        case = dict(self.case)
        case["snapshot_sha256"] = self.snapshot_record()["content_sha256"]
        first = protocol.build_manifest(
            case=case,
            advisory_path=self.advisory,
            runtime=runtime_payload(digest=DIGEST),
            frozen_at_utc=FROZEN_AT,
        )
        second = protocol.build_manifest(
            case=case,
            advisory_path=self.advisory,
            runtime=runtime_payload(digest=DIGEST),
            frozen_at_utc="2026-10-25T00:00:00Z",
        )
        target = self.tmp / "frozen.json"
        target.write_text(json.dumps(first), encoding="utf-8")
        with self.assertRaises(runner.AttemptExistsError) as caught:
            runner.preflight(
                secret_env_path=self.env,
                secret_config_path=self.config,
                manifest=second,
                manifest_path=target,
                digest_probe=lambda tag: DIGEST,
                agent_loader=fake_loader,
            )
        self.assertEqual(caught.exception.code, "manifest_conflict")

    def test_missing_manifest_without_inputs_is_refused(self):
        with self.assertRaises(runner.InfrastructureError) as caught:
            runner.preflight(
                secret_env_path=self.env,
                secret_config_path=self.config,
                manifest_path=self.tmp / "absent" / "manifest.json",
                digest_probe=lambda tag: DIGEST,
                agent_loader=fake_loader,
            )
        self.assertEqual(
            caught.exception.code, "preflight_inputs_missing"
        )


class ScheduleAndPolicyTest(RunnerTestCase):
    def test_frozen_schedule_is_repeat_major_and_unique(self):
        schedule = runner.validate_schedule(self.manifest())
        self.assertEqual(len(schedule), 15)
        self.assertEqual(
            [entry["arm"] for entry in schedule[:5]],
            list(protocol.ARM_ORDER),
        )
        self.assertEqual(
            [entry["repeat"] for entry in schedule[:5]], [1] * 5
        )
        keys = [entry["attempt_key"] for entry in schedule]
        self.assertEqual(len(set(keys)), 15)
        self.assertEqual(
            keys[0], "first-layer-vex-parity/A/r1"
        )

    def test_duplicate_key_is_refused(self):
        manifest = self.manifest()
        schedule = [dict(entry) for entry in manifest["schedule"]]
        schedule[1]["attempt_key"] = schedule[0]["attempt_key"]
        manifest = dict(manifest)
        manifest["schedule"] = schedule
        with self.assertRaises(runner.RuntimeContractError) as caught:
            runner.validate_schedule(manifest)
        self.assertEqual(caught.exception.code, "schedule_drift")

    def test_wrong_order_is_refused(self):
        manifest = self.manifest()
        schedule = list(reversed(manifest["schedule"]))
        manifest = dict(manifest)
        manifest["schedule"] = schedule
        with self.assertRaises(runner.RuntimeContractError) as caught:
            runner.validate_schedule(manifest)
        self.assertEqual(caught.exception.code, "schedule_drift")

    def test_attempt_key_and_directory(self):
        self.assertEqual(
            runner.attempt_key("exp", "C", 2), "exp/C/r2"
        )
        self.assertEqual(
            runner.attempt_dir(Path("/r"), "exp", "task", "C", 2),
            Path("/r/exp/task/C/repeat-2"),
        )

    def test_attempt_policy_refuses_retries_and_cache(self):
        policy = dict(protocol.ATTEMPT_POLICY)
        policy["retries"] = 1
        with self.assertRaises(runner.RuntimeContractError) as caught:
            runner.assert_attempt_policy(policy)
        self.assertEqual(caught.exception.code, "attempt_policy_drift")
        policy = dict(protocol.ATTEMPT_POLICY)
        policy["cache_admission"] = "allowed"
        with self.assertRaises(runner.RuntimeContractError) as caught:
            runner.assert_attempt_policy(policy)
        self.assertEqual(caught.exception.code, "attempt_policy_drift")
        runner.assert_attempt_policy(dict(protocol.ATTEMPT_POLICY))


class SnapshotTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="first-layer-snap-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.snap = write_snapshot(self.tmp)

    def test_hash_is_deterministic(self):
        first, count = runner.snapshot_content_sha256(self.snap)
        second, count_two = runner.snapshot_content_sha256(self.snap)
        self.assertEqual(first, second)
        self.assertEqual(count, count_two)
        self.assertEqual(count, 2)

    def test_content_change_changes_hash(self):
        before, _ = runner.snapshot_content_sha256(self.snap)
        (self.snap / "go.mod").write_text("module changed\n")
        after, _ = runner.snapshot_content_sha256(self.snap)
        self.assertNotEqual(before, after)

    def test_mode_change_changes_hash(self):
        before, _ = runner.snapshot_content_sha256(self.snap)
        os.chmod(self.snap / "go.mod", 0o600)
        after, _ = runner.snapshot_content_sha256(self.snap)
        self.assertNotEqual(before, after)

    def test_git_directory_is_excluded(self):
        before, _ = runner.snapshot_content_sha256(self.snap)
        (self.snap / ".git").mkdir()
        (self.snap / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
        after, _ = runner.snapshot_content_sha256(self.snap)
        self.assertEqual(before, after)

    def test_symlink_is_recorded_without_following(self):
        os.symlink("go.mod", self.snap / "link")
        first, count = runner.snapshot_content_sha256(self.snap)
        second, _ = runner.snapshot_content_sha256(self.snap)
        self.assertEqual(first, second)
        self.assertEqual(count, 3)

    def test_missing_directory_is_infrastructure(self):
        with self.assertRaises(runner.InfrastructureError) as caught:
            runner.snapshot_content_sha256(self.tmp / "absent")
        self.assertEqual(caught.exception.code, "snapshot_missing")

    def test_probe_records_method_and_no_commit_without_git(self):
        record = runner.probe_snapshot(self.snap)
        self.assertEqual(record["method"], runner.SNAPSHOT_METHOD)
        self.assertIsNone(record["commit"])
        self.assertEqual(record["file_count"], 2)


class SecretChannelTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="first-layer-env-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_records_key_names_only(self):
        path = self.tmp / "opencode.env"
        path.write_text(
            "# comment\n\nOPENAI_API_KEY=secret-value\nOTHER=\"quoted\"\n",
            encoding="utf-8",
        )
        record = runner.inspect_secret_env(path)
        self.assertEqual(record["keys"], ["OPENAI_API_KEY", "OTHER"])
        self.assertEqual(record["nonempty"], 2)
        self.assertFalse(record["values_recorded"])
        self.assertNotIn("secret-value", json.dumps(record))
        self.assertNotIn("quoted", json.dumps(record))

    def test_empty_file_is_infrastructure(self):
        path = self.tmp / "opencode.env"
        path.write_text("# no values\nOPENAI_API_KEY=\n", encoding="utf-8")
        with self.assertRaises(runner.InfrastructureError) as caught:
            runner.inspect_secret_env(path)
        self.assertEqual(caught.exception.code, "secret_env_empty")

    def test_missing_file_is_infrastructure(self):
        with self.assertRaises(runner.InfrastructureError) as caught:
            runner.inspect_secret_env(self.tmp / "absent.env")
        self.assertEqual(caught.exception.code, "secret_env_missing")


# ---------------------------------------------------------------------------
# Raw-export derivation and classification
# ---------------------------------------------------------------------------


class ExportDerivationTest(unittest.TestCase):
    def test_native_tool_calls_include_input_and_output_hash(self):
        export = export_payload("prompt")
        calls = runner.extract_native_tool_calls(export)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0]["tool"], "bash")
        self.assertEqual(calls[0]["call_id"], "call-1")
        self.assertEqual(calls[0]["status"], "completed")
        self.assertEqual(calls[0]["input"], {"command": "ls"})
        self.assertEqual(calls[0]["output_bytes"], len("go.mod\nstaging/\n"))
        self.assertEqual(calls[1]["error"], "not found")

    def test_request_messages_capture_system_and_user_text(self):
        export = export_payload("full prompt")
        extracted = runner.extract_request_messages(export)
        self.assertEqual(
            extracted["system_messages"],
            [{"role": "system", "content": "adapter system prompt"}],
        )
        self.assertEqual(len(extracted["user_messages"]), 1)
        self.assertEqual(
            extracted["user_messages"][0]["sha256"],
            protocol.sha256_text("full prompt"),
        )

    def test_session_identity(self):
        identity = runner.session_identity(export_payload("p"))
        self.assertEqual(identity["model"], protocol.MODEL_ID)
        self.assertEqual(identity["provider"], protocol.PROVIDER)
        self.assertEqual(identity["runtime_version"], "1.15.5")

    def test_runtime_drift_detects_model_and_provider(self):
        self.assertIsNone(
            runner.detect_runtime_drift(export_payload("p"))
        )
        drift = runner.detect_runtime_drift(
            export_payload("p", model="other/model")
        )
        self.assertEqual(drift["field"], "model")
        drift = runner.detect_runtime_drift(
            export_payload("p", provider="other-provider")
        )
        self.assertEqual(drift["field"], "provider")
        self.assertIsNone(runner.detect_runtime_drift(None))

    def test_malformed_export_is_not_parsed(self):
        self.assertIsNone(runner.read_export(None))
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "result.json"
            path.write_text("{not json")
            self.assertIsNone(runner.read_export(path))
        self.assertEqual(
            runner.extract_native_tool_calls(None), []
        )
        self.assertEqual(
            runner.extract_request_messages(None)["system_messages"], []
        )

    def test_request_record_includes_adapter_system_message(self):
        record = runner.build_request_record(
            prompt="full prompt",
            export=export_payload("full prompt"),
            arm="A",
            repeat=1,
            key="exp/A/r1",
        )
        self.assertEqual(record["schema"], runner.REQUEST_SCHEMA)
        self.assertEqual(record["system_message_count"], 1)
        self.assertEqual(
            record["adapter_system_messages"][0]["content"],
            "adapter system prompt",
        )
        self.assertNotEqual(
            record["full_request_sha256"], record["user_prompt_sha256"]
        )
        self.assertTrue(
            record["observed_user_messages"][0][
                "equals_protocol_prompt"
            ]
        )
        self.assertEqual(record["attempt_key"], "exp/A/r1")

    def test_request_record_without_export_is_protocol_only(self):
        record = runner.build_request_record(
            prompt="full prompt",
            export=None,
            arm="E",
            repeat=3,
            key="exp/E/r3",
        )
        self.assertEqual(record["system_message_count"], 0)
        self.assertIn("raw export unavailable", record["recording_source"])
        self.assertEqual(
            record["system_message_observation"], "export_unavailable"
        )
        self.assertEqual(
            record["tool_surface"]["observed_invoked_tools"], []
        )

    def test_absent_system_message_is_not_proof(self):
        export = export_payload("full prompt")
        export["messages"] = [
            message for message in export["messages"]
            if (message.get("info") or {}).get("role") != "system"
        ]
        record = runner.build_request_record(
            prompt="full prompt",
            export=export,
            arm="A",
            repeat=1,
            key="exp/A/r1",
            runtime_config={"mcp": {"enabled": False}},
        )
        self.assertEqual(record["system_message_count"], 0)
        self.assertEqual(
            record["system_message_observation"],
            "absent_from_export_not_proof",
        )
        self.assertIn(
            "not proof", record["system_message_limitation"]
        )
        self.assertEqual(
            record["tool_surface"]["observed_invoked_tools"],
            ["bash", "read"],
        )
        self.assertFalse(record["tool_surface"]["mcp_enabled"])
        self.assertFalse(
            record["tool_surface"]["available_tool_schemas_observed"]
        )

    def test_tool_surface_records_the_mcp_treatment(self):
        record = runner.build_request_record(
            prompt="full prompt",
            export=export_payload("full prompt"),
            arm="E",
            repeat=1,
            key="exp/E/r1",
            runtime_config={
                "mcp": {"enabled": True, "server": {"type": "local"}}
            },
        )
        self.assertTrue(record["tool_surface"]["mcp_enabled"])
        self.assertEqual(
            record["tool_surface"]["mcp_server"], {"type": "local"}
        )

    def test_classification_separates_infrastructure_provider_and_output(self):
        cases = [
            (
                {"overall": "valid", "execution": "ok",
                 "official_parse": "accepted", "failure_reason": None},
                None,
                ("completed", "none", None),
            ),
            (
                {"overall": "inconclusive", "execution": "ok",
                 "official_parse": "accepted", "failure_reason": None},
                None,
                ("completed", "none", None),
            ),
            (
                {"overall": "failed", "execution": "timeout",
                 "official_parse": "no_result",
                 "failure_reason": "timeout"},
                None,
                ("failed", "infrastructure", "timeout"),
            ),
            (
                {"overall": "failed", "execution": "transport_failure",
                 "official_parse": "no_result",
                 "failure_reason": "docker_start_failed"},
                None,
                ("failed", "infrastructure", "docker_start_failed"),
            ),
            (
                {"overall": "failed", "execution": "provider_refusal",
                 "official_parse": "parse_fail",
                 "failure_reason": "provider_refusal"},
                None,
                ("failed", "provider", "provider_refusal"),
            ),
            (
                {"overall": "failed",
                 "execution": "invalid_terminal_answer",
                 "official_parse": "parse_fail",
                 "failure_reason": "invalid_terminal_answer"},
                None,
                ("failed", "model_output", "invalid_terminal_answer"),
            ),
            (
                {"overall": "valid", "execution": "ok",
                 "official_parse": "accepted", "failure_reason": None},
                {"field": "model"},
                ("failed", "infrastructure", "runtime_drift"),
            ),
        ]
        for status, drift, expected in cases:
            self.assertEqual(
                runner.classify_attempt(status, drift), expected
            )


# ---------------------------------------------------------------------------
# Full schedule with fake adapters
# ---------------------------------------------------------------------------


class RunTest(RunnerTestCase):
    def test_all_fifteen_attempts_are_written(self):
        summary, attempt_runner = self.run_all()
        self.assertEqual(summary["outcome"], "complete")
        self.assertEqual(summary["counts"]["completed"], 15)
        self.assertEqual(len(attempt_runner.calls), 15)
        self.assertEqual(len(self.attempt_dirs()), 15)
        schedule = runner.validate_schedule(
            runner.load_manifest(self.experiment_root / runner.MANIFEST_NAME)
        )
        self.assertEqual(
            {entry["attempt_key"] for entry in summary["attempts"]},
            {entry["attempt_key"] for entry in schedule},
        )
        summary_path = self.experiment_root / runner.RUN_SUMMARY_NAME
        self.assertEqual(
            json.loads(summary_path.read_text())["attempts"],
            summary["attempts"],
        )
        for run_dir in self.attempt_dirs():
            for name in (
                runner.PROMPT_NAME,
                runner.RESULT_NAME,
                runner.STATUS_NAME,
                runner.FINAL_TEXT_NAME,
                runner.USAGE_NAME,
                runner.TOOL_CALLS_NAME,
                runner.OBSERVATIONS_NAME,
                runner.NATIVE_TOOL_CALLS_NAME,
                runner.REQUEST_NAME,
                runner.ATTEMPT_RECORD_NAME,
                runner.EXPORT_REPORT_NAME,
            ):
                self.assertTrue((run_dir / name).is_file(), name)

    def test_attempt_record_links_to_the_frozen_prompt_and_runtime(self):
        summary, _ = self.run_all()
        manifest = runner.load_manifest(
            self.experiment_root / runner.MANIFEST_NAME
        )
        for run_dir in self.attempt_dirs():
            record = json.loads(
                (run_dir / runner.ATTEMPT_RECORD_NAME).read_text()
            )
            arm = record["arm"]
            self.assertEqual(
                record["schema"], runner.ATTEMPT_SCHEMA
            )
            self.assertEqual(record["outcome"], "completed")
            self.assertEqual(record["failure_class"], "none")
            self.assertIsNone(record["failure_reason"])
            self.assertEqual(
                record["prompt_sha256"],
                manifest["prompts"][arm]["sha256"],
            )
            self.assertEqual(
                record["prompt_sha256_12"],
                manifest["prompts"][arm]["sha256_12"],
            )
            self.assertEqual(record["image_digest"], DIGEST)
            self.assertEqual(
                record["model"], protocol.MODEL_ID
            )
            self.assertEqual(
                record["provider"], protocol.PROVIDER
            )
            self.assertEqual(record["official_category"], "vulnerable")
            self.assertIn(
                "status.json is authoritative",
                record["official_category_source"],
            )
            self.assertEqual(
                record["model_observed"], protocol.MODEL_ID
            )
            self.assertEqual(
                record["snapshot_sha256"],
                manifest["case"]["snapshot_sha256"],
            )
            self.assertEqual(
                record["runtime_sha256"],
                protocol.sha256_text(
                    protocol.canonical_json(record["runtime"])
                ),
            )
            self.assertEqual(
                record["credentials"]["channel"], "secret_env_file"
            )
            self.assertFalse(record["credentials"]["values_recorded"])
            self.assertIn(
                manifest["schedule"][record["sequence_index"] - 1][
                    "attempt_key"
                ],
                record["attempt_key"],
            )
            files = record["artifacts"]["files"]
            self.assertEqual(files["raw_export"], runner.RESULT_NAME)
            self.assertEqual(
                files["final_answer"], runner.FINAL_TEXT_NAME
            )
            self.assertIn(
                runner.RESULT_NAME, record["artifacts"]["sha256"]
            )
        self.assertEqual(
            summary["manifest_sha256"], manifest["manifest_sha256"]
        )

    def test_request_and_native_tool_calls_are_preserved(self):
        self.run_all()
        run_dir = self.attempt_dirs()[0]
        request = json.loads((run_dir / runner.REQUEST_NAME).read_text())
        self.assertEqual(request["system_message_count"], 1)
        self.assertEqual(
            request["adapter_system_messages"][0]["content"],
            "adapter system prompt",
        )
        self.assertTrue(
            request["observed_user_messages"][0][
                "equals_protocol_prompt"
            ]
        )
        calls = [
            json.loads(line)
            for line in (run_dir / runner.NATIVE_TOOL_CALLS_NAME)
            .read_text()
            .splitlines()
            if line.strip()
        ]
        self.assertEqual([call["tool"] for call in calls], ["bash", "read"])
        observations = [
            json.loads(line)
            for line in (run_dir / runner.OBSERVATIONS_NAME)
            .read_text()
            .splitlines()
            if line.strip()
        ]
        self.assertEqual(observations[0]["id"], "OBS-0001")

    def test_second_run_is_refused_without_modifying_attempts(self):
        self.run_all()
        record_path = self.attempt_dirs()[0] / runner.ATTEMPT_RECORD_NAME
        before = record_path.read_bytes()
        summary_path = self.experiment_root / runner.RUN_SUMMARY_NAME
        summary_before = summary_path.read_bytes()
        with self.assertRaises(runner.AttemptExistsError) as caught:
            self.run_all()
        self.assertEqual(caught.exception.code, "attempt_exists")
        self.assertEqual(record_path.read_bytes(), before)
        self.assertEqual(summary_path.read_bytes(), summary_before)

    def test_existing_attempt_directory_aborts_before_any_attempt(self):
        self.preflight()
        sentinel = runner.attempt_dir(
            self.results,
            protocol.EXPERIMENT_ID,
            self.case["task_id"],
            "C",
            2,
        )
        sentinel.mkdir(parents=True)
        (sentinel / "sentinel.txt").write_text("keep me")
        attempt_runner = AttemptRunner()
        with self.assertRaises(runner.AttemptExistsError) as caught:
            self.run_all(runner_impl=attempt_runner)
        self.assertEqual(caught.exception.code, "attempt_exists")
        self.assertEqual(attempt_runner.calls, [])
        self.assertEqual(
            [path.name for path in sentinel.iterdir()], ["sentinel.txt"]
        )
        self.assertFalse(
            (self.experiment_root / runner.RUN_SUMMARY_NAME).exists()
        )

    def test_provider_refusal_is_recorded_and_run_continues(self):
        summary, attempt_runner = self.run_all(mode="refusal")
        self.assertEqual(len(attempt_runner.calls), 15)
        self.assertEqual(summary["outcome"], "complete")
        self.assertEqual(summary["counts"]["failed_provider"], 15)
        record = json.loads(
            (self.attempt_dirs()[0] / runner.ATTEMPT_RECORD_NAME).read_text()
        )
        self.assertEqual(record["outcome"], "failed")
        self.assertEqual(record["failure_class"], "provider")
        self.assertEqual(record["failure_reason"], "provider_refusal")
        self.assertIsNone(record["official_category"])

    def test_transport_failure_is_infrastructure_not_a_model_answer(self):
        summary, attempt_runner = self.run_all(mode="transport")
        self.assertEqual(len(attempt_runner.calls), 15)
        self.assertEqual(summary["outcome"], "complete")
        self.assertEqual(summary["counts"]["failed_infrastructure"], 15)
        run_dir = self.attempt_dirs()[0]
        record = json.loads(
            (run_dir / runner.ATTEMPT_RECORD_NAME).read_text()
        )
        self.assertEqual(record["outcome"], "failed")
        self.assertEqual(record["failure_class"], "infrastructure")
        self.assertTrue(record["error_present"])
        self.assertFalse(record["result_present"])
        self.assertIsNone(record["official_category"])
        self.assertIsNone(record["official_category_source"])
        self.assertFalse((run_dir / runner.RESULT_NAME).exists())
        self.assertFalse((run_dir / runner.ASSESSMENT_NAME).exists())

    def test_parse_failure_is_a_model_output_failure(self):
        summary, _ = self.run_all(mode="parse_fail")
        self.assertEqual(summary["counts"]["failed_model_output"], 15)
        record = json.loads(
            (self.attempt_dirs()[0] / runner.ATTEMPT_RECORD_NAME).read_text()
        )
        self.assertEqual(record["failure_class"], "model_output")
        self.assertEqual(
            record["failure_reason"], "invalid_terminal_answer"
        )

    def test_runtime_drift_aborts_the_remaining_schedule(self):
        summary, attempt_runner = self.run_all(mode="drift")
        self.assertEqual(len(attempt_runner.calls), 1)
        self.assertEqual(summary["outcome"], "aborted")
        self.assertEqual(summary["abort_reason"], "runtime_drift")
        self.assertEqual(summary["counts"]["failed_infrastructure"], 1)
        self.assertEqual(summary["counts"]["not_run"], 14)
        self.assertEqual(len(self.attempt_dirs()), 1)
        record = json.loads(
            (self.attempt_dirs()[0] / runner.ATTEMPT_RECORD_NAME).read_text()
        )
        self.assertEqual(record["failure_reason"], "runtime_drift")
        self.assertIsNotNone(record["runtime_drift"])
        self.assertEqual(
            record["runtime_drift"]["field"], "model"
        )
        not_run = [
            item for item in summary["attempts"]
            if item["outcome"] == "not_run"
        ]
        self.assertEqual(len(not_run), 14)
        for item in not_run:
            self.assertFalse(Path(item["attempt_dir"]).exists())

    def test_digest_drift_between_attempts_aborts_and_preserves_prior(self):
        self.preflight()
        calls = {"count": 0}

        def drifting_probe(tag):
            calls["count"] += 1
            return DIGEST if calls["count"] <= 2 else DIGEST_OTHER

        attempt_runner = AttemptRunner()
        summary = runner.run_experiment(
            secret_env_path=self.env,
            secret_config_path=self.config,
            harness_dir=self.harness,
            results_root=self.results,
            digest_probe=drifting_probe,
            agent_loader=fake_loader,
            run_attempt_fn=attempt_runner,
            artifacts_fn=fake_artifacts,
            finalize_fn=fake_finalize,
            official_parser=official_parser,
            meta_factory=fake_meta,
            frozen_at_utc=FROZEN_AT,
        )
        self.assertEqual(len(attempt_runner.calls), 1)
        self.assertEqual(summary["abort_reason"], "image_digest_drift")
        self.assertEqual(summary["counts"]["completed"], 1)
        self.assertEqual(summary["counts"]["not_run"], 14)
        self.assertEqual(len(self.attempt_dirs()), 1)

    def test_secret_values_are_never_written(self):
        secret = "DO-NOT-RECORD-THIS"
        self.env.write_text(
            "OPENAI_API_KEY={}\n".format(secret), encoding="utf-8"
        )
        self.run_all()
        for path in self.all_files_under(self.experiment_root):
            self.assertNotIn(
                secret,
                path.read_text(encoding="utf-8", errors="replace"),
                str(path),
            )

    def test_summary_counts_match_attempt_records(self):
        summary, _ = self.run_all()
        completed = 0
        for run_dir in self.attempt_dirs():
            record = json.loads(
                (run_dir / runner.ATTEMPT_RECORD_NAME).read_text()
            )
            if record["outcome"] == "completed":
                completed += 1
        self.assertEqual(summary["counts"]["completed"], completed)

    def test_no_attempt_is_retried(self):
        attempt_runner = AttemptRunner(mode="transport")
        self.run_all(runner_impl=attempt_runner)
        self.assertEqual(len(attempt_runner.calls), 15)
        self.assertEqual(len(set(attempt_runner.calls)), 15)

    def test_run_refuses_a_different_provider(self):
        self.preflight()
        with self.assertRaises(runner.RuntimeContractError) as caught:
            self.run_all(runtime=runtime_payload(provider="other-provider"))
        self.assertEqual(caught.exception.code, "runtime_manifest_mismatch")

    def test_manually_built_manifest_refuses_unresolved_snapshot(self):
        case = dict(self.case)
        runtime = runtime_payload(digest=DIGEST)
        manifest = protocol.build_manifest(
            case=case,
            advisory_path=self.advisory,
            runtime=runtime,
            frozen_at_utc=FROZEN_AT,
        )
        path = self.tmp / "manifest.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaises(runner.InfrastructureError) as caught:
            runner.run_experiment(
                secret_env_path=self.env,
                secret_config_path=self.config,
                manifest=manifest,
                manifest_path=path,
                digest_probe=lambda tag: DIGEST,
                agent_loader=fake_loader,
                run_attempt_fn=AttemptRunner(),
                artifacts_fn=fake_artifacts,
                finalize_fn=fake_finalize,
                official_parser=official_parser,
                meta_factory=fake_meta,
            )
        self.assertEqual(caught.exception.code, "snapshot_unresolved")


@unittest.skipUnless(
    HAS_PYDANTIC_V2, "eval.c1 requires pydantic v2 (harness venv)"
)
class C1IntegrationTest(RunnerTestCase):
    """Exercise the real c1 finalizer/artifacts when pydantic v2 exists."""

    def test_real_finalize_writes_status_and_usage(self):
        summary = runner.run_experiment(
            secret_env_path=self.env,
            secret_config_path=self.config,
            harness_dir=self.harness,
            results_root=self.results,
            case=self.case,
            runtime=self.runtime,
            advisory_path=self.advisory,
            digest_probe=lambda tag: DIGEST,
            agent_loader=fake_loader,
            run_attempt_fn=AttemptRunner(),
            artifacts_fn=None,
            finalize_fn=None,
            official_parser=official_parser,
            frozen_at_utc=FROZEN_AT,
        )
        self.assertEqual(summary["counts"]["completed"], 15)
        run_dir = self.attempt_dirs()[0]
        status = json.loads((run_dir / runner.STATUS_NAME).read_text())
        self.assertEqual(status["schema_version"], "attempt-status/1")
        self.assertEqual(status["overall"], "valid")
        self.assertEqual(status["official_parse"], "accepted")
        usage = json.loads((run_dir / runner.USAGE_NAME).read_text())
        self.assertEqual(usage["input_tokens"], 10)
        self.assertEqual(usage["output_tokens"], 5)
        self.assertTrue((run_dir / runner.FINAL_TEXT_NAME).is_file())

    def test_real_finalize_preserves_a_valid_assessment(self):
        assessment = {
            "category": "vulnerable",
            "reasoning": "fixture",
            "assessment": {
                "root_causes": ["fixture cause"],
                "mandatory_conditions": [],
                "claims": [
                    {
                        "statement": "fixture claim",
                        "verdict": "TRUE",
                        "evidence_refs": ["file:go.mod"],
                    }
                ],
                "evidence": ["file:go.mod"],
                "limitations": [],
                "unresolved_questions": [],
                "counterexample_review": {
                    "checked": ["fixture counter-check"],
                    "still_unknown": [],
                },
                "verdict_estimate": "EXPLOITABLE",
            },
        }
        summary = runner.run_experiment(
            secret_env_path=self.env,
            secret_config_path=self.config,
            harness_dir=self.harness,
            results_root=self.results,
            case=self.case,
            runtime=self.runtime,
            advisory_path=self.advisory,
            digest_probe=lambda tag: DIGEST,
            agent_loader=fake_loader,
            run_attempt_fn=AttemptRunner(
                final_text=json.dumps(assessment)
            ),
            artifacts_fn=None,
            finalize_fn=None,
            official_parser=official_parser,
            frozen_at_utc=FROZEN_AT,
        )
        self.assertEqual(summary["counts"]["completed"], 15)
        run_dir = self.attempt_dirs()[0]
        self.assertTrue((run_dir / runner.ASSESSMENT_NAME).is_file())
        record = json.loads(
            (run_dir / runner.ATTEMPT_RECORD_NAME).read_text()
        )
        self.assertTrue(record["assessment_present"])


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class CliTest(RunnerTestCase):
    def cli(self):
        from eval import vexbench_first_layer_ablation

        return vexbench_first_layer_ablation

    def test_preflight_without_inputs_returns_two(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            rc = self.cli().main(
                ["--results-root", str(self.results),
                 "--secret-env", str(self.env), "preflight"]
            )
        self.assertEqual(rc, 2)
        self.assertIn("--manifest", stderr.getvalue())

    def test_preflight_delegates_and_prints_report(self):
        stdout = io.StringIO()
        with mock.patch.object(
            runner, "preflight", return_value={"schema": "fixture"}
        ) as called:
            with contextlib.redirect_stdout(stdout):
                rc = self.cli().main(
                    [
                        "--results-root", str(self.results),
                        "--secret-env", str(self.env),
                        "preflight",
                        "--manifest", str(self.tmp / "manifest.json"),
                    ]
                )
        self.assertEqual(rc, 0)
        self.assertIn('"schema": "fixture"', stdout.getvalue())
        self.assertTrue(called.called)

    def test_secret_paths_default_to_the_harness_checkout(self):
        harness = self.tmp / "harness"
        with mock.patch.object(
            runner, "preflight", return_value={"schema": "fixture"}
        ) as called:
            with contextlib.redirect_stdout(io.StringIO()):
                rc = self.cli().main(
                    [
                        "--results-root", str(self.results),
                        "--harness-dir", str(harness),
                        "preflight",
                        "--manifest", str(self.tmp / "manifest.json"),
                    ]
                )
        self.assertEqual(rc, 0)
        kwargs = called.call_args.kwargs
        self.assertEqual(
            kwargs["secret_env_path"],
            harness / "env" / "opencode" / "opencode.env",
        )
        self.assertEqual(
            kwargs["secret_config_path"],
            harness / "env" / "opencode" / "opencode.json",
        )
        self.assertEqual(kwargs["harness_dir"], harness)

    def test_controller_refusal_is_reported_as_json_exit_two(self):
        stderr = io.StringIO()
        error = runner.InfrastructureError(
            "opencode.env is empty: infrastructure prerequisite",
            code="secret_env_empty",
        )
        with mock.patch.object(runner, "preflight", side_effect=error):
            with contextlib.redirect_stderr(stderr):
                rc = self.cli().main(
                    [
                        "--results-root", str(self.results),
                        "--secret-env", str(self.env),
                        "preflight",
                        "--manifest", str(self.tmp / "manifest.json"),
                    ]
                )
        self.assertEqual(rc, 2)
        payload = json.loads(stderr.getvalue())
        self.assertEqual(payload["error"], "secret_env_empty")
        self.assertEqual(payload["failure_class"], "infrastructure")

    def test_malformed_json_input_is_reported(self):
        bad = self.tmp / "bad.json"
        bad.write_text("{not json", encoding="utf-8")
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            rc = self.cli().main(
                [
                    "--results-root", str(self.results),
                    "--secret-env", str(self.env),
                    "preflight",
                    "--case", str(bad),
                    "--runtime", str(self.tmp / "runtime.json"),
                    "--advisory", str(self.advisory),
                ]
            )
        self.assertEqual(rc, 2)
        self.assertEqual(
            json.loads(stderr.getvalue())["error"], "invalid_input"
        )

    def test_run_returns_one_on_aborted_summary(self):
        stdout = io.StringIO()
        with mock.patch.object(
            runner,
            "run_experiment",
            return_value={"outcome": "aborted"},
        ):
            with contextlib.redirect_stdout(stdout):
                rc = self.cli().main(
                    [
                        "--results-root", str(self.results),
                        "--secret-env", str(self.env),
                        "run",
                        "--manifest", str(self.tmp / "manifest.json"),
                    ]
                )
        self.assertEqual(rc, 1)


@unittest.skipUnless(
    HAS_PYDANTIC_V2, "eval.c1/harness adapters require pydantic v2"
)
class C1HarnessProfileTest(unittest.TestCase):
    """The external harness's two C1 profiles, exercised without a run.

    These tests import the real harness adapters.  They never start a
    container, call a model or invoke the MCP server; they verify the
    launch facts, generated configs and credential-path binding that
    Task 2 preflight relies on.  Skipped when the harness checkout is not
    available (``C1_HARNESS_DIR`` or the documented ``/tmp`` path).
    """

    def setUp(self) -> None:
        harness = Path(
            os.environ.get("C1_HARNESS_DIR", "/tmp/vexbench-agent-ctl")
        )
        src = harness / "src"
        if not (src / "evaluate" / "agents").is_dir():
            raise unittest.SkipTest(
                "external harness not available at {}".format(harness)
            )
        if str(src) not in sys.path:
            sys.path.insert(0, str(src))
        from evaluate.agents import AGENTS  # noqa: E402
        from evaluate.agents.opencode_c1 import (  # noqa: E402
            OpenCodeC1Agent,
        )

        self.harness = harness
        self.AGENTS = AGENTS
        self.C1Class = OpenCodeC1Agent
        self.tmp = Path(tempfile.mkdtemp(prefix="first-layer-harness-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.env = self.tmp / "opencode.env"
        self.env.write_text("OPENAI_API_KEY=fixture\n", encoding="utf-8")
        self.config = self.tmp / "opencode.json"
        self.config.write_text(
            json.dumps({"tools": {"task": False}}) + "\n", encoding="utf-8"
        )

    @contextlib.contextmanager
    def launch(
        self,
        *,
        env_path: Path = None,
        config_path: Path = None,
    ):
        with runner.launch_environment(
            secret_env_path=env_path or self.env,
            secret_config_path=config_path or self.config,
            harness_dir=self.harness,
        ):
            yield

    def profiles(self):
        return (
            self.AGENTS["opencode-c1-nomcp"](model=protocol.MODEL_ALIAS),
            self.AGENTS["opencode-c1"](model=protocol.MODEL_ALIAS),
        )

    def test_profiles_share_image_and_legacy_pipeline(self):
        with self.launch():
            nomcp, c1 = self.profiles()
            self.assertNotIsInstance(nomcp, self.C1Class)
            self.assertIsInstance(c1, self.C1Class)
            for profile in (nomcp, c1):
                self.assertEqual(
                    profile.IMAGE_SUFFIX, protocol.RUNTIME_IMAGE_SUFFIX
                )
                self.assertEqual(
                    profile.PIPELINE, protocol.RUNTIME_PIPELINE
                )
                facts = profile.effective_config_facts()
                self.assertEqual(
                    facts["pipeline"], protocol.RUNTIME_PIPELINE
                )
                self.assertEqual(
                    facts["image_suffix"], protocol.RUNTIME_IMAGE_SUFFIX
                )
                self.assertEqual(
                    facts["model_binding"], protocol.PROVIDER_MODEL_ID
                )
                self.assertEqual(facts["extra_artifacts"], ["izyan-audit"])
            self.assertEqual(
                runner.adapter_image_tag(nomcp, "go"),
                runner.adapter_image_tag(c1, "go"),
            )
            self.assertEqual(
                runner.adapter_image_tag(nomcp, "go"),
                "vex-bench-go-opencode-c1:latest",
            )

    def test_shared_image_resolves_to_one_content_id(self):
        tag = "vex-bench-go-opencode-c1:latest"
        try:
            first = runner.probe_image_digest(tag)
        except runner.InfrastructureError:
            raise unittest.SkipTest(
                "{} is not built locally".format(tag)
            )
        self.assertRegex(first, r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(first, runner.probe_image_digest(tag))

    def test_generated_configs_differ_only_by_mcp(self):
        with self.launch():
            nomcp, c1 = self.profiles()
            base = nomcp.build_config(cve_id=CVE_ID)
            c1_config = c1.build_config(cve_id=CVE_ID)
            # MCP-off means no registration key at all, not a disabled stanza.
            self.assertNotIn("mcp", base)
            self.assertEqual(set(c1_config["mcp"]), {"izyan"})
            self.assertEqual(
                base,
                {k: v for k, v in c1_config.items() if k != "mcp"},
            )
            server = c1_config["mcp"]["izyan"]
            self.assertTrue(server["enabled"])
            self.assertEqual(server["type"], "local")
            command = server["command"]
            self.assertEqual(
                command[0], "/usr/local/bin/izyan-evidence-tools"
            )
            self.assertEqual(
                command[command.index("--snapshot-root") + 1], "/work"
            )
            self.assertEqual(
                command[command.index("--cve") + 1], CVE_ID
            )
            self.assertEqual(
                command[command.index("--audit-file") + 1],
                "/tmp/izyan-audit/tool_calls.jsonl",
            )
            self.assertIn(
                "/usr/local/go/bin", server["environment"]["PATH"]
            )
            self.assertIn("/tmp/izyan-audit/tool_calls.jsonl", command)
            self.assertFalse(
                nomcp.effective_config_facts()["mcp_enabled"]
            )
            self.assertTrue(c1.effective_config_facts()["mcp_enabled"])

    def test_credentials_and_config_are_resolved_per_call(self):
        with self.launch():
            nomcp, c1 = self.profiles()
            first = nomcp.effective_config_facts()
            self.assertEqual(first["env_file"], str(self.env.resolve()))
            self.assertEqual(
                first["config_source"], str(self.config.resolve())
            )
            other_env = self.tmp / "other.env"
            other_env.write_text(
                "OPENAI_API_KEY=other\n", encoding="utf-8"
            )
            other_config = self.tmp / "other.json"
            other_config.write_text(
                json.dumps({
                    "tools": {"task": True},
                    "mcp": {"ambient": {"type": "local", "enabled": True}},
                }) + "\n",
                encoding="utf-8",
            )
            with self.launch(
                env_path=other_env, config_path=other_config
            ):
                observed = c1.effective_config_facts()
                self.assertEqual(
                    observed["env_file"], str(other_env.resolve())
                )
                self.assertEqual(
                    observed["config_source"], str(other_config.resolve())
                )
                generated = nomcp.build_config(cve_id=CVE_ID)
                self.assertTrue(generated["tools"]["task"])
                # MCP-off never inherits an ambient registration.
                self.assertNotIn("mcp", generated)

    def test_preflight_with_the_real_image_digest(self):
        tag = "vex-bench-go-opencode-c1:latest"
        try:
            digest = runner.probe_image_digest(tag)
        except runner.InfrastructureError:
            raise unittest.SkipTest(
                "{} is not built locally".format(tag)
            )
        advisory = write_advisory(self.tmp)
        snapshot = write_snapshot(self.tmp)
        report = runner.preflight(
            secret_env_path=self.env,
            secret_config_path=self.config,
            results_root=self.tmp / "real-digest-results",
            case=case_payload(snapshot),
            runtime=runtime_payload(),
            advisory_path=advisory,
            harness_dir=self.harness,
            frozen_at_utc=FROZEN_AT,
        )
        self.assertEqual(report["image"]["tag"], tag)
        self.assertEqual(report["image"]["digest"], digest)
        self.assertTrue(report["image"]["same_digest_all_arms"])
        self.assertEqual(report["equality"]["E_delta"], ["agent", "mcp"])
        self.assertEqual(
            {report["adapter_bindings"][arm]["image_tag"]
             for arm in protocol.ARM_ORDER},
            {tag},
        )

    def test_preflight_accepts_the_real_adapters(self):
        advisory = write_advisory(self.tmp)
        snapshot = write_snapshot(self.tmp)
        runtime = runtime_payload()
        case = case_payload(snapshot)
        results = self.tmp / "results"
        report = runner.preflight(
            secret_env_path=self.env,
            secret_config_path=self.config,
            results_root=results,
            case=case,
            runtime=runtime,
            advisory_path=advisory,
            harness_dir=self.harness,
            digest_probe=lambda tag: DIGEST,
            frozen_at_utc=FROZEN_AT,
        )
        self.assertEqual(report["image"]["digest"], DIGEST)
        self.assertEqual(report["equality"]["E_delta"], ["agent", "mcp"])
        classes = {
            arm: report["adapter_bindings"][arm]["class"]
            for arm in protocol.ARM_ORDER
        }
        self.assertEqual(
            {classes[arm] for arm in ("A", "B", "C", "D")},
            {"OpenCodeC1NoMcpAgent"},
        )
        self.assertEqual(classes["E"], "OpenCodeC1Agent")
        for arm in protocol.ARM_ORDER:
            binding = report["adapter_bindings"][arm]
            self.assertEqual(
                binding["image_tag"], runtime["image"]["tag"]
            )
            self.assertEqual(
                binding["pipeline"], protocol.RUNTIME_PIPELINE
            )
            self.assertEqual(
                binding["model_binding"], protocol.PROVIDER_MODEL_ID
            )
            self.assertEqual(
                binding["env_file"], str(self.env.resolve())
            )
            self.assertEqual(
                binding["config_source"], str(self.config.resolve())
            )
            self.assertEqual(binding["mcp_enabled"], arm == "E")
        hashes = {
            report["adapter_bindings"][arm]["generated_config_sha256"]
            for arm in protocol.ARM_ORDER
        }
        self.assertEqual(len(hashes), 1)
        manifest = runner.load_manifest(
            Path(report["manifest_path"])
        )
        self.assertEqual(
            manifest["prompts"]["A"]["agent"], "opencode-c1-nomcp"
        )
        self.assertEqual(
            manifest["prompts"]["E"]["agent"], "opencode-c1"
        )


if __name__ == "__main__":
    unittest.main()

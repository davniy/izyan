"""First-layer VEX parity ablation — attempt controller (Task 2).

The controller runs the five frozen arms (Task 1 ``protocol``) through the
existing OpenCode agent runtime, one attempt at a time, in the preassigned
repeat-major order.  It never scores anything: the official parser is the
harness's own, invoked by ``eval.c1.collect.finalize_attempt``.

What this module adds on top of ``eval.c1.runner.run_attempt``
--------------------------------------------------------------
- **One runtime, one treatment.** Before any model answer the effective
  config of every arm is compared: A-D must be identical and E must differ
  only by the MCP treatment (``agent`` + ``mcp``).  Equality is derived
  from the adapters' own launch facts (image suffix, legacy pipeline id,
  canonical model binding, resolved credential/config paths, generated
  config hash without ``mcp``), not only from manifest declarations.  The
  image is probed once, pinned by digest, and every arm's adapter must
  address that same image tag.  A different model, provider, image
  digest/pipeline, snapshot or credential path aborts the run instead of
  running a lookalike.
- **Immutable attempts.** The key is ``(experiment_id, arm, repeat)`` and
  its directory is ``<root>/<experiment_id>/<task_id>/<arm>/repeat-<n>/``.
  An existing directory is refused before any attempt starts; there is no
  resume, retry or cache admission.
- **Explicit evidence.** Each attempt keeps the exact prompt, the raw
  adapter export, the terminal answer, native tool calls, the MCP audit
  sink and observations, usage, errors and a controller ``attempt.json``.
  Infrastructure failures and provider/model-output failures are separate
  classes; neither is ever reported as a model answer.  The request
  record captures the visible system/user messages and the invoked tool
  surface; a missing system message in the export is recorded as
  ``absent_from_export_not_proof``.
- **Secret channel.** Credentials are never arguments, manifest fields or
  artifacts.  The controller checks the harness's secret env file is
  present and non-empty, records only its path and key names, and binds
  ``VEXBENCH_HOST_ENV_FILE`` / ``VEXBENCH_HOST_CONFIG`` for adapter
  inspection and every attempt so the validated file is the file the
  launcher uses.

Nothing here calls Docker, a provider or the MCP server at import time.
The live paths are lazy imports/callables; tests inject fakes.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import stat
import subprocess
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Mapping, Optional, Tuple

from . import protocol

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[2]

ATTEMPT_SCHEMA = "first-layer-attempt/1"
PREFLIGHT_SCHEMA = "first-layer-preflight/1"
REQUEST_SCHEMA = "first-layer-request/1"
RUN_SUMMARY_SCHEMA = "first-layer-run-summary/1"

MANIFEST_NAME = "manifest.json"
PREFLIGHT_NAME = "preflight.json"
RUN_SUMMARY_NAME = "run-summary.json"

PROMPT_NAME = "prompt.txt"
RESULT_NAME = "result.json"
ERROR_NAME = "error.txt"
STATUS_NAME = "status.json"
ASSESSMENT_NAME = "agent_assessment.json"
FINAL_TEXT_NAME = "raw_agent_output.txt"
USAGE_NAME = "usage.json"
TOOL_CALLS_NAME = "tool_calls.jsonl"
OBSERVATIONS_NAME = "observations.jsonl"
NATIVE_TOOL_CALLS_NAME = "native_tool_calls.jsonl"
REQUEST_NAME = "request.json"
EXPORT_REPORT_NAME = "export-report.json"
ATTEMPT_RECORD_NAME = "attempt.json"
AUDIT_REL = Path("artifacts") / "izyan-audit" / "tool_calls.jsonl"

SNAPSHOT_METHOD = (
    "tree-sha256/v1: sorted relative paths, file mode bits and per-file "
    "sha256; symlinks as their target; .git excluded"
)
CREDENTIAL_CHANNEL = "secret_env_file"

# Harness adapter contract.  The controller sets these variables for the
# duration of adapter inspection and of every attempt, so the file it
# validated is exactly the file the launcher mounts / passes to
# ``--env-file``.  The harness resolves them per call (never at import).
HARNESS_ENV_FILE_VAR = "VEXBENCH_HOST_ENV_FILE"
HARNESS_CONFIG_VAR = "VEXBENCH_HOST_CONFIG"
HARNESS_DIR_VAR = "C1_HARNESS_DIR"

_ADAPTER_FACT_KEYS = (
    "pipeline",
    "image_suffix",
    "model_binding",
    "mcp_enabled",
    "config_tag",
    "env_file",
    "config_source",
    "extra_artifacts",
)

_IMAGE_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SECRET_LINE_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")

# c1 failure reasons that denote a broken run environment rather than a
# model answer.  Everything else is a model/provider-output failure.
_INFRA_EXECUTIONS = frozenset({"timeout", "transport_failure", "no_output"})
_INFRA_REASONS = frozenset(
    {
        "timeout",
        "container_nonzero_exit",
        "docker_create_failed",
        "docker_cp_failed",
        "docker_start_failed",
        "artifact_export_failed",
        "mcp_transport_failure",
        "no_result",
    }
)


# ---------------------------------------------------------------------------
# Errors: every controller refusal has a stable code and a failure class.
# ---------------------------------------------------------------------------


class AblationError(RuntimeError):
    """Base class for a fail-closed controller decision.

    ``failure_class`` keeps infrastructure prerequisites separable from
    model results: an ``infrastructure`` refusal is never an answer.
    """

    code = "ablation_error"
    failure_class = "infrastructure"

    def __init__(
        self,
        message: str,
        *,
        code: Optional[str] = None,
        details: Optional[Mapping[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        if code:
            self.code = code
        self.details = dict(details or {})

    def as_dict(self) -> Dict[str, Any]:
        return {
            "error": self.code,
            "failure_class": self.failure_class,
            "message": str(self),
            "details": self.details,
        }


class InfrastructureError(AblationError):
    """A missing prerequisite: no arm may run and nothing is a result."""

    code = "infrastructure"
    failure_class = "infrastructure"


class RuntimeContractError(AblationError):
    """An arm would run with a runtime the frozen manifest does not pin."""

    code = "runtime_contract"


class AttemptExistsError(AblationError):
    """An immutable attempt key already has a directory on disk."""

    code = "attempt_exists"


# ---------------------------------------------------------------------------
# Small deterministic helpers
# ---------------------------------------------------------------------------


def sha256_file(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _json_text(payload: Any) -> str:
    return json.dumps(
        payload, indent=2, sort_keys=True, ensure_ascii=False
    ) + "\n"


def write_json_once(path: Path, payload: Any) -> Path:
    """Write a controller artifact once; an existing file is never replaced."""
    path = Path(path)
    if path.exists():
        raise AttemptExistsError(
            "refusing to overwrite controller artifact: {}".format(path)
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(_json_text(payload), encoding="utf-8")
    os.replace(temporary, path)
    return path


def write_json_once_matching(path: Path, payload: Any) -> Path:
    """Idempotent for identical content, fail-closed for a different one."""
    path = Path(path)
    text = _json_text(payload)
    if path.exists():
        if path.read_text(encoding="utf-8") == text:
            return path
        raise AttemptExistsError(
            "refusing to replace a different controller artifact: {}".format(
                path
            )
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    os.replace(temporary, path)
    return path


def write_text_once(path: Path, text: str) -> Path:
    path = Path(path)
    if path.exists():
        raise AttemptExistsError(
            "refusing to overwrite controller artifact: {}".format(path)
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    os.replace(temporary, path)
    return path


def utc_now(clock: Callable[[], float] = time.time) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(clock()))


def _resolve_path(recorded: str) -> Path:
    path = Path(recorded)
    return path if path.is_absolute() else REPO_ROOT / path


# ---------------------------------------------------------------------------
# Preflight probes (all injectable; defaults are the real infrastructure)
# ---------------------------------------------------------------------------


def probe_image_digest(
    image_tag: str,
    *,
    command_runner: Optional[Callable[..., Any]] = None,
) -> str:
    """Content ID of one local image (``docker image inspect .Id``).

    The plan asks for one image for every arm.  A tag alone is mutable, so
    the controller pins the immutable ID and refuses a different one.  This
    is the same probe ``eval/c1/manifest.py`` uses to freeze images.
    """
    run = command_runner or subprocess.run
    try:
        completed = run(
            ["docker", "image", "inspect", image_tag, "--format", "{{.Id}}"],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except FileNotFoundError as exc:
        raise InfrastructureError(
            "docker CLI not found; cannot resolve image {}".format(image_tag),
            code="docker_unavailable",
            details={"image_tag": image_tag},
        ) from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise InfrastructureError(
            "image inspect failed for {}: {}".format(image_tag, exc),
            code="image_probe_failed",
            details={"image_tag": image_tag},
        ) from exc
    if completed.returncode != 0:
        raise InfrastructureError(
            "image {} is not present locally: {}".format(
                image_tag, (completed.stderr or "").strip()[-500:]
            ),
            code="image_unavailable",
            details={"image_tag": image_tag},
        )
    digest = (completed.stdout or "").strip()
    if not _IMAGE_DIGEST_RE.match(digest):
        raise InfrastructureError(
            "image {} returned no sha256 content id: {!r}".format(
                image_tag, digest[:120]
            ),
            code="image_digest_invalid",
            details={"image_tag": image_tag, "observed": digest[:120]},
        )
    return digest


def _hash_symlink(target: str) -> bytes:
    return b"L\0" + target.encode("utf-8", "surrogateescape") + b"\n"


def snapshot_content_sha256(root: Path) -> Tuple[str, int]:
    """Deterministic content hash of a source snapshot (no .git).

    The izyan tool's acquisition hash is not reproducible here (different
    implementation), so this is an independent identity check: the exact
    algorithm is recorded next to the value and never compared to a hash
    produced by a different tool.
    """
    import hashlib

    root = Path(root)
    if not root.is_dir():
        raise InfrastructureError(
            "snapshot directory not found: {}".format(root),
            code="snapshot_missing",
            details={"path": str(root)},
        )
    digest = hashlib.sha256()
    entries: List[Tuple[str, Path, str]] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        keep: List[str] = []
        for name in sorted(dirnames):
            candidate = Path(dirpath) / name
            if name == ".git":
                continue
            if candidate.is_symlink():
                relative = candidate.relative_to(root).as_posix()
                entries.append((relative, candidate, "symlink"))
            else:
                keep.append(name)
        dirnames[:] = keep
        for name in sorted(filenames):
            candidate = Path(dirpath) / name
            relative = candidate.relative_to(root).as_posix()
            kind = "symlink" if candidate.is_symlink() else "file"
            entries.append((relative, candidate, kind))
    entries.sort(key=lambda item: item[0])

    count = 0
    for relative, path, kind in entries:
        info = path.lstat()
        if kind == "symlink":
            digest.update(relative.encode("utf-8", "surrogateescape") + b"\0")
            digest.update(_hash_symlink(os.readlink(path)))
            count += 1
        elif stat.S_ISREG(info.st_mode):
            digest.update(relative.encode("utf-8", "surrogateescape") + b"\0")
            digest.update("F{:04o}\0".format(stat.S_IMODE(info.st_mode)).encode())
            digest.update(sha256_file(path).encode("ascii") + b"\n")
            count += 1
        # FIFOs/sockets cannot be hashed meaningfully and never occur in a
        # pinned source snapshot; their absence is not silently hashed.
    return digest.hexdigest(), count


def probe_snapshot(root: Path) -> Dict[str, Any]:
    root = Path(root)
    content, count = snapshot_content_sha256(root)
    commit: Optional[str] = None
    if (root / ".git").exists():
        try:
            completed = subprocess.run(
                ["git", "-C", str(root), "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                timeout=60,
            )
        except (OSError, subprocess.SubprocessError):
            completed = None
        if completed is not None and completed.returncode == 0:
            commit = (completed.stdout or "").strip() or None
    return {
        "path": str(root.resolve()),
        "content_sha256": content,
        "commit": commit,
        "file_count": count,
        "method": SNAPSHOT_METHOD,
    }


def _coerce_snapshot(recorded: Any, path: Path) -> Dict[str, Any]:
    if not isinstance(recorded, Mapping):
        raise InfrastructureError(
            "snapshot probe returned {!r}".format(type(recorded).__name__),
            code="snapshot_probe_invalid",
        )
    content = recorded.get("content_sha256")
    if not isinstance(content, str) or not re.match(r"^[0-9a-f]{64}$", content):
        raise InfrastructureError(
            "snapshot probe returned no sha256 content hash",
            code="snapshot_probe_invalid",
            details={"observed": str(content)[:120]},
        )
    return {
        "path": str(recorded.get("path") or Path(path).resolve()),
        "content_sha256": content,
        "commit": recorded.get("commit"),
        "file_count": int(recorded.get("file_count") or 0),
        "method": str(recorded.get("method") or SNAPSHOT_METHOD),
    }


def inspect_secret_env(path: Path) -> Dict[str, Any]:
    """Validate the secret runtime channel without recording any value.

    The adapters read this file themselves; the controller only proves it
    exists and carries at least one non-empty value.  An empty
    ``opencode.env`` is an infrastructure prerequisite, never a model
    result.
    """
    path = Path(path)
    if not path.is_file():
        raise InfrastructureError(
            "secret env file not found: {} (credentials are supplied only "
            "through this runtime channel)".format(path),
            code="secret_env_missing",
            details={"path": str(path)},
        )
    keys: List[str] = []
    nonempty = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = _SECRET_LINE_RE.match(line)
        if not match:
            continue
        key, value = match.group(1), match.group(2).strip()
        keys.append(key)
        if value.strip("'\""):
            nonempty += 1
    if not keys or nonempty == 0:
        raise InfrastructureError(
            "secret env file {} is empty: this is an infrastructure "
            "prerequisite, not a model result".format(path),
            code="secret_env_empty",
            details={"path": str(path), "keys": sorted(set(keys))},
        )
    return {
        "channel": CREDENTIAL_CHANNEL,
        "path": str(path.resolve()),
        "keys": sorted(set(keys)),
        "nonempty": nonempty,
        "values_recorded": False,
    }


def probe_harness_version(harness_dir: Optional[Path]) -> str:
    if harness_dir is None:
        return "unknown"
    try:
        completed = subprocess.run(
            ["git", "-C", str(Path(harness_dir)), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    if completed.returncode != 0:
        return "unknown"
    return (completed.stdout or "").strip() or "unknown"


def tool_adapter_version(worktree: Path = REPO_ROOT) -> str:
    """AdapterVersion constant from internal/evidencetools/service.go."""
    path = Path(worktree) / "internal" / "evidencetools" / "service.go"
    try:
        source = path.read_text(encoding="utf-8")
    except OSError:
        return "unknown"
    match = re.search(r'AdapterVersion\s*=\s*"([^"]+)"', source)
    return match.group(1) if match else "unknown"


# ---------------------------------------------------------------------------
# Manifest / policy assertions
# ---------------------------------------------------------------------------


def load_manifest(path: Path) -> Dict[str, Any]:
    path = Path(path)
    if not path.is_file():
        raise InfrastructureError(
            "frozen manifest not found: {}".format(path),
            code="manifest_missing",
            details={"path": str(path)},
        )
    try:
        manifest = read_json(path)
    except ValueError as exc:
        raise RuntimeContractError(
            "frozen manifest is not JSON: {}".format(exc),
            code="manifest_invalid",
            details={"path": str(path)},
        ) from exc
    if not isinstance(manifest, Mapping):
        raise RuntimeContractError(
            "frozen manifest must be a JSON object",
            code="manifest_invalid",
            details={"path": str(path)},
        )
    protocol.verify_manifest(manifest)
    return dict(manifest)


def assert_attempt_policy(policy: Mapping[str, Any]) -> None:
    expected = dict(protocol.ATTEMPT_POLICY)
    if dict(policy) != expected:
        raise RuntimeContractError(
            "attempt policy drifted from the frozen values",
            code="attempt_policy_drift",
            details={"observed": dict(policy), "expected": expected},
        )
    if policy["cache_admission"] != "forbidden":
        raise RuntimeContractError(
            "cache admission is forbidden for this experiment",
            code="cache_admission_forbidden",
        )
    if policy["retries"] != 0:
        raise RuntimeContractError(
            "retries must stay at 0", code="retries_forbidden"
        )


def assert_pinned_runtime(manifest: Mapping[str, Any]) -> None:
    """Refuse a provider, model, image or policy that is not the frozen one."""
    runtime = manifest.get("runtime")
    case = manifest.get("case")
    if not isinstance(runtime, Mapping) or not isinstance(case, Mapping):
        raise RuntimeContractError(
            "manifest lacks runtime/case", code="manifest_incomplete"
        )
    model = runtime.get("model") or {}
    if model.get("id") != protocol.MODEL_ID:
        raise RuntimeContractError(
            "runtime model must be exactly {!r}; got {!r}".format(
                protocol.MODEL_ID, model.get("id")
            ),
            code="model_mismatch",
            details={"observed": model.get("id"), "expected": protocol.MODEL_ID},
        )
    if model.get("provider") != protocol.PROVIDER:
        raise RuntimeContractError(
            "runtime provider must be exactly {!r}; got {!r}".format(
                protocol.PROVIDER, model.get("provider")
            ),
            code="provider_mismatch",
            details={
                "observed": model.get("provider"),
                "expected": protocol.PROVIDER,
            },
        )
    if model.get("alias") not in (None, protocol.MODEL_ALIAS):
        raise RuntimeContractError(
            "runtime model alias drifted", code="model_alias_mismatch",
            details={"observed": model.get("alias")},
        )
    if model.get("provider_model_id") not in (
        None, protocol.PROVIDER_MODEL_ID
    ):
        raise RuntimeContractError(
            "runtime provider model id drifted",
            code="provider_model_id_mismatch",
            details={"observed": model.get("provider_model_id")},
        )

    image = runtime.get("image") or {}
    if image.get("same_digest_all_arms") is not True:
        raise RuntimeContractError(
            "runtime.image.same_digest_all_arms must be True",
            code="image_contract_missing",
        )
    digest = image.get("digest")
    if not digest:
        raise InfrastructureError(
            "runtime.image.digest is null: preflight must probe one digest "
            "before any arm runs",
            code="image_digest_unresolved",
            details={"image_tag": image.get("tag")},
        )
    if not _IMAGE_DIGEST_RE.match(str(digest)):
        raise RuntimeContractError(
            "runtime.image.digest must be sha256:<64 hex>",
            code="image_digest_invalid",
            details={"observed": digest},
        )
    if not isinstance(image.get("tag"), str) or not image["tag"].strip():
        raise RuntimeContractError(
            "runtime.image.tag is missing", code="image_tag_missing"
        )

    assert_attempt_policy(manifest.get("attempt_policy") or {})
    snapshot_path = case.get("snapshot_path")
    if not isinstance(snapshot_path, str) or not snapshot_path.strip():
        raise RuntimeContractError(
            "case.snapshot_path is missing", code="snapshot_path_missing"
        )
    directory_name = Path(snapshot_path).name
    if (
        re.match(r"^[0-9a-f]{7,40}$", directory_name)
        and directory_name != case.get("commit_sha")
    ):
        raise InfrastructureError(
            "snapshot path names commit {!r} but the case pins {!r}".format(
                directory_name, case.get("commit_sha")
            ),
            code="snapshot_path_mismatch",
            details={
                "path": snapshot_path,
                "observed": directory_name,
                "expected": case.get("commit_sha"),
            },
        )
    snapshot_sha = case.get("snapshot_sha256")
    if not snapshot_sha:
        raise InfrastructureError(
            "case.snapshot_sha256 is null: preflight must verify the "
            "snapshot content hash before any arm runs",
            code="snapshot_unresolved",
            details={"path": snapshot_path},
        )
    if not re.match(r"^[0-9a-f]{64}$", str(snapshot_sha)):
        raise RuntimeContractError(
            "case.snapshot_sha256 must be a sha256 hex digest",
            code="snapshot_hash_invalid",
            details={"observed": snapshot_sha},
        )


def validate_schedule(manifest: Mapping[str, Any]) -> List[Dict[str, Any]]:
    expected = protocol.build_schedule()
    schedule = manifest.get("schedule")
    if schedule != expected:
        raise RuntimeContractError(
            "manifest schedule is not the frozen repeat-major order",
            code="schedule_drift",
        )
    keys = [entry.get("attempt_key") for entry in schedule]
    if len(set(keys)) != len(keys):
        raise RuntimeContractError(
            "schedule has duplicate attempt keys", code="schedule_duplicate"
        )
    expected_count = (
        protocol.ATTEMPT_POLICY["repeats"] * len(protocol.ARM_ORDER)
    )
    if len(schedule) != expected_count:
        raise RuntimeContractError(
            "schedule has {} attempts, expected {}".format(
                len(schedule), expected_count
            ),
            code="schedule_count",
        )
    return [dict(entry) for entry in schedule]


def attempt_key(experiment_id: str, arm: str, repeat: int) -> str:
    return "{}/{}/r{}".format(experiment_id, arm, repeat)


def attempt_dir(
    results_root: Path,
    experiment_id: str,
    task_id: str,
    arm: str,
    repeat: int,
) -> Path:
    return (
        Path(results_root)
        / experiment_id
        / task_id
        / arm
        / "repeat-{}".format(repeat)
    )


def experiment_root(
    manifest_path: Path,
    results_root: Optional[Path] = None,
    experiment_id: str = protocol.EXPERIMENT_ID,
) -> Path:
    """The directory that owns preflight/attempt/summary artifacts."""
    if results_root is not None:
        return Path(results_root) / experiment_id
    parent = Path(manifest_path).parent
    return parent if parent.name == experiment_id else parent / experiment_id


# ---------------------------------------------------------------------------
# Effective configuration equality
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def launch_environment(
    *,
    secret_env_path: Path,
    secret_config_path: Optional[Path] = None,
    harness_dir: Optional[Path] = None,
) -> Iterator[Dict[str, str]]:
    """Bind the harness to the exact files/harness the controller checked.

    The harness resolves ``VEXBENCH_HOST_ENV_FILE`` /
    ``VEXBENCH_HOST_CONFIG`` per call, so setting them for adapter
    inspection and for the duration of every attempt is what makes the
    validated credential path the launcher's actual path.  The previous
    environment is restored afterwards.
    """
    overrides = {
        HARNESS_ENV_FILE_VAR: str(Path(secret_env_path).resolve()),
    }
    if secret_config_path is not None:
        overrides[HARNESS_CONFIG_VAR] = str(
            Path(secret_config_path).resolve()
        )
    if harness_dir is not None:
        overrides[HARNESS_DIR_VAR] = str(Path(harness_dir).resolve())
    previous = {key: os.environ.get(key) for key in overrides}
    os.environ.update(overrides)
    try:
        yield dict(overrides)
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def model_binding(model: Mapping[str, Any]) -> Tuple[str, str]:
    """Return ``(alias, canonical provider/model id)`` for a frozen model.

    The harness constructor stores the provider-qualified id
    (``custom-openai/Qwen/Qwen3.6-35B-A3B``) even though callers pass the alias.
    Both forms are accepted, but the canonical form must be exactly the
    frozen provider + model: no other provider or model is admitted.
    """
    alias = model.get("alias") or protocol.MODEL_ALIAS
    provider = str(model.get("provider") or "")
    model_id = str(model.get("id") or "")
    canonical = "{}/{}".format(provider, model_id)
    pinned = model.get("provider_model_id")
    if pinned is not None and pinned != canonical:
        raise RuntimeContractError(
            "runtime.model.provider_model_id {!r} does not name {!r}".format(
                pinned, canonical
            ),
            code="provider_model_id_mismatch",
            details={"observed": pinned, "expected": canonical},
        )
    if provider != protocol.PROVIDER or model_id != protocol.MODEL_ID:
        raise RuntimeContractError(
            "runtime model must be {}/{}, got {}/{}".format(
                protocol.PROVIDER, protocol.MODEL_ID, provider, model_id
            ),
            code="model_mismatch",
            details={
                "observed": canonical,
                "expected": protocol.PROVIDER_MODEL_ID,
            },
        )
    return alias, pinned or canonical


def adapter_facts(agent: Any, *, arm: str) -> Dict[str, Any]:
    """Adapter-reported launch facts; absence is a contract violation."""
    method = getattr(agent, "effective_config_facts", None)
    if not callable(method):
        raise RuntimeContractError(
            "adapter for arm {} exposes no effective_config_facts".format(arm),
            code="adapter_facts_missing",
            details={"arm": arm, "class": type(agent).__name__},
        )
    try:
        facts = method()
    except AblationError:
        raise
    except Exception as exc:  # noqa: BLE001 - adapter failure is infrastructure
        raise InfrastructureError(
            "adapter for arm {} failed to report launch facts: {}".format(
                arm, exc
            ),
            code="adapter_facts_invalid",
            details={"arm": arm, "class": type(agent).__name__},
        ) from exc
    if not isinstance(facts, Mapping):
        raise RuntimeContractError(
            "adapter launch facts for arm {} are not a mapping".format(arm),
            code="adapter_facts_invalid",
            details={"arm": arm},
        )
    missing = [key for key in _ADAPTER_FACT_KEYS if key not in facts]
    if missing:
        raise RuntimeContractError(
            "adapter launch facts for arm {} are missing {}".format(
                arm, ", ".join(missing)
            ),
            code="adapter_facts_incomplete",
            details={"arm": arm, "missing": missing},
        )
    return dict(facts)


def generated_adapter_config(
    agent: Any, *, arm: str, cve_id: str
) -> Dict[str, Any]:
    """The config the adapter would mount, generated without a run."""
    method = getattr(agent, "build_config", None)
    if not callable(method):
        raise RuntimeContractError(
            "adapter for arm {} cannot generate its launch config".format(arm),
            code="adapter_config_missing",
            details={"arm": arm, "class": type(agent).__name__},
        )
    try:
        config = method(cve_id=cve_id)
    except AblationError:
        raise
    except FileNotFoundError as exc:
        raise InfrastructureError(
            "adapter config source is unavailable for arm {}: {}".format(
                arm, exc
            ),
            code="secret_config_missing",
            details={"arm": arm},
        ) from exc
    except Exception as exc:  # noqa: BLE001 - config generation is infrastructure
        raise InfrastructureError(
            "adapter for arm {} failed to generate its config: {}".format(
                arm, exc
            ),
            code="adapter_config_invalid",
            details={"arm": arm, "class": type(agent).__name__},
        ) from exc
    if not isinstance(config, Mapping):
        raise RuntimeContractError(
            "adapter config for arm {} is not a mapping".format(arm),
            code="adapter_config_invalid",
            details={"arm": arm},
        )
    return dict(config)


def config_sha256_without_mcp(config: Mapping[str, Any]) -> str:
    """Content hash of a generated config with the MCP block removed.

    A-D and E must synthesize byte-equivalent launch configs apart from
    the declared ``mcp`` treatment; the controller compares this hash.
    """
    body = {key: value for key, value in config.items() if key != "mcp"}
    return protocol.sha256_text(protocol.canonical_json(body))


def adapter_image_tag(agent: Any, language: str, *, arm: str = "?") -> str:
    suffix = getattr(agent, "IMAGE_SUFFIX", None)
    if not isinstance(suffix, str) or not suffix:
        raise RuntimeContractError(
            "adapter for arm {} exposes no IMAGE_SUFFIX".format(arm),
            code="adapter_image_unknown",
            details={"arm": arm, "class": type(agent).__name__},
        )
    return "vex-bench-{}-{}:latest".format(language, suffix)


def effective_config(
    manifest: Mapping[str, Any],
    arm: str,
    *,
    image_digest: str,
    snapshot_sha256: str,
    adapter: Any,
    secret_env_path: Optional[Path] = None,
    secret_config_path: Optional[Path] = None,
) -> Dict[str, Any]:
    runtime = manifest["runtime"]
    case = manifest["case"]
    policy = manifest["attempt_policy"]
    declared_agent = protocol.ARM_RUNTIME[arm]["agent"]
    declared_mcp = protocol.ARM_RUNTIME[arm]["mcp"]

    facts = adapter_facts(adapter, arm=arm)
    if facts["pipeline"] != protocol.RUNTIME_PIPELINE:
        raise RuntimeContractError(
            "arm {} adapter pipeline {!r} is not the pinned legacy pipeline "
            "{!r}".format(arm, facts["pipeline"], protocol.RUNTIME_PIPELINE),
            code="pipeline_mismatch",
            details={
                "arm": arm,
                "observed": facts["pipeline"],
                "expected": protocol.RUNTIME_PIPELINE,
            },
        )
    if not isinstance(facts["image_suffix"], str) or not facts["image_suffix"]:
        raise RuntimeContractError(
            "adapter for arm {} exposes no IMAGE_SUFFIX".format(arm),
            code="adapter_image_unknown",
            details={"arm": arm, "class": type(adapter).__name__},
        )
    if facts["image_suffix"] != protocol.RUNTIME_IMAGE_SUFFIX:
        raise RuntimeContractError(
            "arm {} adapter image suffix {!r} is not the shared C1 image "
            "{!r}".format(
                arm, facts["image_suffix"], protocol.RUNTIME_IMAGE_SUFFIX
            ),
            code="image_suffix_mismatch",
            details={
                "arm": arm,
                "observed": facts["image_suffix"],
                "expected": protocol.RUNTIME_IMAGE_SUFFIX,
            },
        )
    if facts["mcp_enabled"] is not declared_mcp:
        raise RuntimeContractError(
            "arm {} adapter registers MCP={!r}, manifest declares {!r}".format(
                arm, facts["mcp_enabled"], declared_mcp
            ),
            code="adapter_mcp_mismatch",
            details={"arm": arm},
        )

    alias, canonical = model_binding(runtime["model"])
    observed_binding = facts["model_binding"]
    if observed_binding not in (alias, canonical):
        raise RuntimeContractError(
            "adapter {} is bound to model {!r}, expected {!r} or alias {!r}"
            .format(arm, observed_binding, canonical, alias),
            code="model_mismatch",
            details={
                "arm": arm,
                "observed": observed_binding,
                "expected": [canonical, alias],
            },
        )

    env_file = Path(str(facts["env_file"])).resolve()
    config_source = Path(str(facts["config_source"])).resolve()
    if secret_env_path is not None:
        expected_env = Path(secret_env_path).resolve()
        if env_file != expected_env:
            raise RuntimeContractError(
                "arm {} adapter would use secret env {} but the controller "
                "validated {}".format(arm, env_file, expected_env),
                code="secret_env_path_mismatch",
                details={
                    "arm": arm,
                    "observed": str(env_file),
                    "expected": str(expected_env),
                },
            )
    if secret_config_path is not None:
        expected_config = Path(secret_config_path).resolve()
        if config_source != expected_config:
            raise RuntimeContractError(
                "arm {} adapter would mount config {} but the controller "
                "expected {}".format(arm, config_source, expected_config),
                code="secret_config_path_mismatch",
                details={
                    "arm": arm,
                    "observed": str(config_source),
                    "expected": str(expected_config),
                },
            )
    if not config_source.is_file():
        raise InfrastructureError(
            "adapter config source is not a file for arm {}: {}".format(
                arm, config_source
            ),
            code="secret_config_missing",
            details={"arm": arm, "path": str(config_source)},
        )

    generated = generated_adapter_config(
        adapter, arm=arm, cve_id=case["cve_id"]
    )
    surface = generated.get("mcp")
    mcp_record: Dict[str, Any] = {"enabled": declared_mcp}
    if declared_mcp:
        if not isinstance(surface, Mapping) or not surface:
            raise RuntimeContractError(
                "arm {} enables MCP but the generated config registers none"
                .format(arm),
                code="mcp_surface_missing",
                details={"arm": arm},
            )
        if set(surface) != {"izyan"}:
            raise RuntimeContractError(
                "arm {} registers MCP servers {}; only the pinned 'izyan' "
                "server is allowed".format(arm, sorted(surface)),
                code="mcp_surface_not_pinned",
                details={"arm": arm, "servers": sorted(surface)},
            )
        if surface["izyan"].get("enabled") is not True:
            raise RuntimeContractError(
                "arm {} must start the pinned MCP server".format(arm),
                code="mcp_surface_not_enabled",
                details={"arm": arm},
            )
        mcp_record["server"] = surface["izyan"]
    elif surface is not None:
        raise RuntimeContractError(
            "arm {} has MCP disabled but the generated config registers a "
            "server".format(arm),
            code="mcp_registered_in_nomcp",
            details={"arm": arm, "servers": sorted(surface)},
        )

    config: Dict[str, Any] = {
        "agent": declared_agent,
        "mcp": mcp_record,
        "model": dict(runtime["model"]),
        "endpoint": dict(runtime["endpoint"]),
        "image": {
            "tag": runtime["image"]["tag"],
            "digest": image_digest,
        },
        "parameters": dict(runtime["parameters"]),
        "native_tools": list(runtime["native_tools"]),
        "permissions": dict(runtime["permissions"]),
        "timeout_seconds": policy["timeout_seconds"],
        "repeats": policy["repeats"],
        "parallel": policy["parallel"],
        "language": case["language"],
        "snapshot_sha256": snapshot_sha256,
        "credential_channel": CREDENTIAL_CHANNEL,
        "adapter_image_tag": adapter_image_tag(
            adapter, case["language"], arm=arm
        ),
        "adapter": {
            "pipeline": facts["pipeline"],
            "image_suffix": facts["image_suffix"],
            "model_binding": observed_binding,
            "env_file": str(env_file),
            "config_source": str(config_source),
            "extra_artifacts": sorted(facts["extra_artifacts"]),
            "generated_config_sha256": config_sha256_without_mcp(generated),
        },
    }
    return config


def build_arm_configs(
    manifest: Mapping[str, Any],
    agents_by_arm: Mapping[str, Any],
    *,
    image_digest: str,
    snapshot_sha256: str,
    secret_env_path: Optional[Path] = None,
    secret_config_path: Optional[Path] = None,
) -> Dict[str, Dict[str, Any]]:
    prompts = manifest["prompts"]
    runtime = manifest["runtime"]
    configs: Dict[str, Dict[str, Any]] = {}
    for arm in protocol.ARM_ORDER:
        if prompts[arm]["agent"] != protocol.ARM_RUNTIME[arm]["agent"]:
            raise RuntimeContractError(
                "manifest arm {} agent drifted".format(arm),
                code="manifest_agent_drift",
                details={
                    "observed": prompts[arm]["agent"],
                    "expected": protocol.ARM_RUNTIME[arm]["agent"],
                },
            )
        if prompts[arm]["mcp"] is not protocol.ARM_RUNTIME[arm]["mcp"]:
            raise RuntimeContractError(
                "manifest arm {} MCP flag drifted".format(arm),
                code="manifest_mcp_drift",
            )
        agent = agents_by_arm.get(arm)
        if agent is None:
            raise RuntimeContractError(
                "no adapter bound to arm {}".format(arm),
                code="adapter_missing",
                details={"arm": arm},
            )
        config = effective_config(
            manifest,
            arm,
            image_digest=image_digest,
            snapshot_sha256=snapshot_sha256,
            adapter=agent,
            secret_env_path=secret_env_path,
            secret_config_path=secret_config_path,
        )
        expected_tag = runtime["image"]["tag"]
        if config["adapter_image_tag"] != expected_tag:
            raise RuntimeContractError(
                "arm {} adapter would run image {} but the frozen runtime "
                "pins one image {}".format(
                    arm, config["adapter_image_tag"], expected_tag
                ),
                code="image_tag_mismatch",
                details={
                    "arm": arm,
                    "agent": type(agent).__name__,
                    "adapter_image_tag": config["adapter_image_tag"],
                    "expected": expected_tag,
                },
            )
        configs[arm] = config
    return configs


def changed_config_keys(
    left: Mapping[str, Any], right: Mapping[str, Any]
) -> List[str]:
    keys = sorted(set(left) | set(right))
    return [key for key in keys if left.get(key) != right.get(key)]


def assert_effective_contract(
    configs: Mapping[str, Mapping[str, Any]]
) -> Tuple[str, ...]:
    """A-D identical; E differs only by the MCP treatment (agent + mcp)."""
    missing = [arm for arm in protocol.ARM_ORDER if arm not in configs]
    if missing:
        raise RuntimeContractError(
            "effective configs are missing arms: {}".format(missing),
            code="effective_config_incomplete",
        )
    for arm in protocol.ARM_ORDER:
        adapter = configs[arm].get("adapter") or {}
        if adapter.get("pipeline") != protocol.RUNTIME_PIPELINE:
            raise RuntimeContractError(
                "arm {} does not launch the pinned legacy pipeline".format(arm),
                code="pipeline_mismatch",
                details={
                    "arm": arm,
                    "observed": adapter.get("pipeline"),
                    "expected": protocol.RUNTIME_PIPELINE,
                },
            )
        if adapter.get("image_suffix") != protocol.RUNTIME_IMAGE_SUFFIX:
            raise RuntimeContractError(
                "arm {} does not address the shared C1 image".format(arm),
                code="image_suffix_mismatch",
                details={"arm": arm},
            )
    base = configs["A"]
    for arm in ("B", "C", "D"):
        changed = changed_config_keys(base, configs[arm])
        if changed:
            raise RuntimeContractError(
                "arm {} differs from A outside the declared treatment".format(
                    arm
                ),
                code="arm_config_mismatch",
                details={"arm": arm, "changed": changed},
            )
    changed = tuple(changed_config_keys(base, configs["E"]))
    if changed != protocol.ARM_RUNTIME_DELTA:
        raise RuntimeContractError(
            "E's effective config delta is {}, expected {}".format(
                list(changed), list(protocol.ARM_RUNTIME_DELTA)
            ),
            code="mcp_delta_not_isolated",
            details={
                "changed": list(changed),
                "expected": list(protocol.ARM_RUNTIME_DELTA),
            },
        )
    if configs["E"]["agent"] != protocol.ARM_RUNTIME["E"]["agent"]:
        raise RuntimeContractError(
            "E must use the MCP adapter", code="mcp_agent_mismatch"
        )
    if (configs["E"].get("mcp") or {}).get("enabled") is not True:
        raise RuntimeContractError(
            "E must enable MCP", code="mcp_flag_mismatch"
        )
    for arm in ("A", "B", "C", "D"):
        if (configs[arm].get("mcp") or {}).get("enabled") is not False:
            raise RuntimeContractError(
                "arm {} must run with MCP disabled".format(arm),
                code="mcp_flag_mismatch",
                details={"arm": arm},
            )
        if "server" in (configs[arm].get("mcp") or {}):
            raise RuntimeContractError(
                "arm {} carries an MCP server surface".format(arm),
                code="mcp_surface_not_isolated",
                details={"arm": arm},
            )
    if "server" not in (configs["E"].get("mcp") or {}):
        raise RuntimeContractError(
            "E's pinned MCP server is not recorded",
            code="mcp_surface_missing",
        )
    return changed


def verify_prompt_hashes(
    manifest: Mapping[str, Any], arms: Mapping[str, str]
) -> None:
    for arm in protocol.ARM_ORDER:
        expected = manifest["prompts"][arm]["sha256"]
        actual = protocol.sha256_text(arms[arm])
        if actual != expected:
            raise RuntimeContractError(
                "arm {} prompt does not match the frozen manifest".format(arm),
                code="prompt_hash_mismatch",
                details={
                    "arm": arm,
                    "observed": actual,
                    "expected": expected,
                },
            )
        short = manifest["prompts"][arm]["sha256_12"]
        if protocol.prompt_hash(arms[arm]) != short:
            raise RuntimeContractError(
                "arm {} short prompt hash drifted".format(arm),
                code="prompt_hash_mismatch",
                details={"arm": arm},
            )


def assert_inputs_match_manifest(
    manifest: Mapping[str, Any],
    *,
    case: Optional[Mapping[str, Any]] = None,
    runtime: Optional[Mapping[str, Any]] = None,
) -> None:
    """A provided case/runtime may never silently differ from the manifest."""
    if case is not None:
        recorded = manifest["case"]
        for key, value in case.items():
            if key == "snapshot_sha256" and value is None:
                continue
            if recorded.get(key) != value:
                raise RuntimeContractError(
                    "provided case.{} does not match the frozen manifest"
                    .format(key),
                    code="case_manifest_mismatch",
                    details={
                        "field": key,
                        "observed": value,
                        "expected": recorded.get(key),
                    },
                )
    if runtime is not None:
        recorded = manifest["runtime"]
        for key in (
            "model", "endpoint", "parameters", "native_tools", "permissions"
        ):
            if runtime.get(key) != recorded.get(key):
                raise RuntimeContractError(
                    "provided runtime.{} does not match the frozen manifest"
                    .format(key),
                    code="runtime_manifest_mismatch",
                    details={"field": key},
                )
        provided_image = runtime.get("image") or {}
        recorded_image = recorded.get("image") or {}
        if provided_image.get("tag") != recorded_image.get("tag"):
            raise RuntimeContractError(
                "provided image tag does not match the frozen manifest",
                code="runtime_manifest_mismatch",
                details={"field": "runtime.image.tag"},
            )
        for key in ("digest", "same_digest_all_arms"):
            value = provided_image.get(key)
            if value is not None and value != recorded_image.get(key):
                raise RuntimeContractError(
                    "provided runtime.image.{} does not match the frozen "
                    "manifest".format(key),
                    code="runtime_manifest_mismatch",
                    details={"field": "runtime.image.{}".format(key)},
                )


# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------


def _default_agent_loader(profile: str, model: str) -> Any:
    from eval.c1.runner import load_agent

    return load_agent(profile, model)


def _default_run_attempt(run_dir: Path, **kwargs: Any) -> Any:
    from eval.c1.runner import run_attempt

    return run_attempt(run_dir, **kwargs)


def _default_controller_artifacts(
    run_dir: Path, agent: Any, wall_seconds: float
) -> Any:
    from eval.c1.runner import write_controller_artifacts

    return write_controller_artifacts(run_dir, agent, wall_seconds)


def _default_finalize(run_dir: Path, **kwargs: Any) -> Any:
    from eval.c1.collect import finalize_attempt

    return finalize_attempt(run_dir, **kwargs)


def try_load_official_parser() -> Optional[Callable[[str], Any]]:
    """The harness's unchanged parser, or None when it is unavailable.

    Used only to persist a convenience ``official_category`` next to the
    saved answer; ``status.json`` stays the authoritative parse record.
    """
    try:
        from eval.c1.collect import _load_official_parser

        return _load_official_parser()
    except Exception:  # noqa: BLE001 - absent harness is not a model result
        return None


def _load_agents(
    manifest: Mapping[str, Any], loader: Callable[[str, str], Any]
) -> Dict[str, Any]:
    model = manifest["runtime"]["model"]
    alias, canonical = model_binding(model)
    accepted = (canonical, alias)
    cached: Dict[str, Any] = {}
    agents: Dict[str, Any] = {}
    for arm in protocol.ARM_ORDER:
        profile = protocol.ARM_RUNTIME[arm]["agent"]
        if profile not in cached:
            agent = loader(profile, alias)
            observed = getattr(agent, "model_name", None)
            if observed not in accepted:
                raise RuntimeContractError(
                    "adapter {} is bound to model {!r}, expected {!r} "
                    "(alias {!r})".format(
                        profile, observed, canonical, alias
                    ),
                    code="model_mismatch",
                    details={
                        "agent": profile,
                        "observed": observed,
                        "expected": [canonical, alias],
                    },
                )
            cached[profile] = agent
        agents[arm] = cached[profile]
    return agents


def _load_agents_checked(
    manifest: Mapping[str, Any], loader: Callable[[str, str], Any]
) -> Dict[str, Any]:
    try:
        return _load_agents(manifest, loader)
    except AblationError:
        raise
    except Exception as exc:  # noqa: BLE001 - absent harness is infrastructure
        raise InfrastructureError(
            "agent adapters are unavailable: {}".format(exc),
            code="harness_unavailable",
        ) from exc


def _build_or_load_manifest(
    *,
    results_root: Optional[Path],
    manifest_path: Optional[Path],
    manifest: Optional[Mapping[str, Any]],
    case: Optional[Mapping[str, Any]],
    runtime: Optional[Mapping[str, Any]],
    advisory_path: Optional[Path],
    digest_probe: Callable[[str], str],
    snapshot_probe: Callable[[Path], Mapping[str, Any]],
    frozen_at_utc: Optional[str],
) -> Tuple[Dict[str, Any], Path, Optional[Dict[str, Any]]]:
    if manifest is not None:
        data = dict(manifest)
        protocol.verify_manifest(data)
        if manifest_path is None:
            raise InfrastructureError(
                "an in-memory manifest needs a manifest_path for artifacts",
                code="manifest_path_missing",
            )
        return data, Path(manifest_path), None

    if manifest_path is not None and Path(manifest_path).is_file():
        data = load_manifest(Path(manifest_path))
        assert_inputs_match_manifest(data, case=case, runtime=runtime)
        return data, Path(manifest_path), None

    if results_root is not None:
        default_manifest = (
            Path(results_root) / protocol.EXPERIMENT_ID / MANIFEST_NAME
        )
        if default_manifest.is_file():
            data = load_manifest(default_manifest)
            assert_inputs_match_manifest(data, case=case, runtime=runtime)
            return data, default_manifest, None

    if not (case and runtime and advisory_path):
        raise InfrastructureError(
            "preflight needs a frozen manifest or case+runtime+advisory to "
            "build one",
            code="preflight_inputs_missing",
        )
    if results_root is None and manifest_path is None:
        raise InfrastructureError(
            "preflight needs a results_root or a manifest_path for the "
            "frozen manifest",
            code="preflight_inputs_missing",
        )
    resolved_case = dict(case)
    resolved_runtime = json.loads(json.dumps(runtime))
    image = resolved_runtime.get("image") or {}
    tag = image.get("tag")
    if not isinstance(tag, str) or not tag.strip():
        raise InfrastructureError(
            "runtime.image.tag is required to probe the image",
            code="image_tag_missing",
        )
    digest = digest_probe(tag)
    if image.get("digest") is not None and image["digest"] != digest:
        raise RuntimeContractError(
            "provided runtime.image.digest does not match the local image",
            code="image_digest_mismatch",
            details={"provided": image["digest"], "observed": digest},
        )
    image["digest"] = digest
    resolved_runtime["image"] = image

    snapshot_path = _resolve_path(str(resolved_case.get("snapshot_path", "")))
    snapshot = _coerce_snapshot(snapshot_probe(snapshot_path), snapshot_path)
    recorded_snapshot = resolved_case.get("snapshot_sha256")
    if recorded_snapshot is not None and recorded_snapshot != snapshot[
        "content_sha256"
    ]:
        raise InfrastructureError(
            "provided snapshot hash does not match the snapshot on disk",
            code="snapshot_mismatch",
            details={
                "provided": recorded_snapshot,
                "observed": snapshot["content_sha256"],
            },
        )
    resolved_case["snapshot_sha256"] = snapshot["content_sha256"]

    built = protocol.build_manifest(
        case=resolved_case,
        advisory_path=Path(advisory_path),
        runtime=resolved_runtime,
        frozen_at_utc=frozen_at_utc,
    )
    target = (
        Path(manifest_path)
        if manifest_path is not None
        else Path(results_root)
        / built["experiment_id"]
        / MANIFEST_NAME
    )
    return built, target, snapshot


def preflight(
    *,
    secret_env_path: Path,
    secret_config_path: Optional[Path] = None,
    results_root: Optional[Path] = None,
    manifest_path: Optional[Path] = None,
    manifest: Optional[Mapping[str, Any]] = None,
    case: Optional[Mapping[str, Any]] = None,
    runtime: Optional[Mapping[str, Any]] = None,
    advisory_path: Optional[Path] = None,
    harness_dir: Optional[Path] = None,
    digest_probe: Optional[Callable[[str], str]] = None,
    snapshot_probe: Optional[Callable[[Path], Mapping[str, Any]]] = None,
    agent_loader: Optional[Callable[[str, str], Any]] = None,
    frozen_at_utc: Optional[str] = None,
    clock: Callable[[], float] = time.time,
) -> Dict[str, Any]:
    """Verify one runtime and freeze the preflight record before any answer."""
    probe_digest = digest_probe or probe_image_digest
    probe_snap = snapshot_probe or probe_snapshot
    load_agent = agent_loader or _default_agent_loader

    frozen, manifest_file, built_snapshot = _build_or_load_manifest(
        results_root=results_root,
        manifest_path=manifest_path,
        manifest=manifest,
        case=case,
        runtime=runtime,
        advisory_path=advisory_path,
        digest_probe=probe_digest,
        snapshot_probe=probe_snap,
        frozen_at_utc=frozen_at_utc,
    )
    protocol.verify_manifest(frozen)
    assert_pinned_runtime(frozen)
    schedule = validate_schedule(frozen)

    case_record = frozen["case"]
    runtime_record = frozen["runtime"]
    image_tag = runtime_record["image"]["tag"]
    expected_digest = runtime_record["image"]["digest"]

    observed_digest = probe_digest(image_tag)
    if observed_digest != expected_digest:
        raise RuntimeContractError(
            "local image digest drifted from the frozen runtime",
            code="image_digest_mismatch",
            details={
                "image_tag": image_tag,
                "observed": observed_digest,
                "expected": expected_digest,
            },
        )

    snapshot_path = _resolve_path(case_record["snapshot_path"])
    if built_snapshot is None:
        snapshot = _coerce_snapshot(probe_snap(snapshot_path), snapshot_path)
    else:
        snapshot = _coerce_snapshot(built_snapshot, snapshot_path)
    if snapshot["content_sha256"] != case_record["snapshot_sha256"]:
        raise InfrastructureError(
            "snapshot content hash drifted from the frozen manifest",
            code="snapshot_mismatch",
            details={
                "path": snapshot["path"],
                "observed": snapshot["content_sha256"],
                "expected": case_record["snapshot_sha256"],
            },
        )
    if (
        snapshot.get("commit")
        and snapshot["commit"] != case_record["commit_sha"]
    ):
        raise InfrastructureError(
            "snapshot commit does not match the frozen case",
            code="snapshot_commit_mismatch",
            details={
                "observed": snapshot["commit"],
                "expected": case_record["commit_sha"],
            },
        )

    credentials = inspect_secret_env(Path(secret_env_path))
    with launch_environment(
        secret_env_path=Path(secret_env_path),
        secret_config_path=secret_config_path,
        harness_dir=harness_dir,
    ):
        agents = _load_agents_checked(frozen, load_agent)
        configs = build_arm_configs(
            frozen,
            agents,
            image_digest=observed_digest,
            snapshot_sha256=snapshot["content_sha256"],
            secret_env_path=Path(secret_env_path),
            secret_config_path=secret_config_path,
        )
    changed = assert_effective_contract(configs)

    advisory_path = _resolve_path(frozen["sources"]["advisory"]["path"])
    advisory_text = advisory_path.read_text(encoding="utf-8")
    arms = protocol.build_arms(case_record["cve_id"], advisory_text)
    verify_prompt_hashes(frozen, arms)

    try:
        protocol.write_manifest(manifest_file, frozen)
    except FileExistsError as exc:
        raise AttemptExistsError(
            "refusing to replace a different frozen manifest: {}".format(
                manifest_file
            ),
            code="manifest_conflict",
            details={"path": str(manifest_file)},
        ) from exc

    root = experiment_root(
        manifest_file, results_root, frozen["experiment_id"]
    )
    report = {
        "schema": PREFLIGHT_SCHEMA,
        "experiment_id": frozen["experiment_id"],
        "checked_at_utc": utc_now(clock),
        "manifest_path": str(Path(manifest_file).resolve()),
        "manifest_sha256": frozen["manifest_sha256"],
        "image": {
            "tag": image_tag,
            "digest": observed_digest,
            "probe": "image content id (sha256)",
            "same_digest_all_arms": True,
        },
        "model": {
            "id": runtime_record["model"]["id"],
            "alias": runtime_record["model"].get("alias"),
            "provider": runtime_record["model"]["provider"],
            "provider_model_id": runtime_record["model"].get(
                "provider_model_id"
            ),
            "revision": runtime_record["model"].get("revision"),
        },
        "endpoint": dict(runtime_record["endpoint"]),
        "snapshot": dict(snapshot),
        "credentials": dict(credentials),
        "policy": dict(frozen["attempt_policy"]),
        "schedule": {
            "count": len(schedule),
            "order": frozen["attempt_policy"]["schedule_order"],
            "sha256": frozen["schedule_sha256"],
        },
        "adapter_bindings": {
            arm: {
                "agent": protocol.ARM_RUNTIME[arm]["agent"],
                "class": type(agents[arm]).__name__,
                "image_suffix": configs[arm]["adapter"]["image_suffix"],
                "image_tag": configs[arm]["adapter_image_tag"],
                "pipeline": configs[arm]["adapter"]["pipeline"],
                "model_binding": configs[arm]["adapter"]["model_binding"],
                "config_tag": getattr(agents[arm], "CONFIG_TAG", None),
                "mcp_enabled": configs[arm]["mcp"]["enabled"],
                "env_file": configs[arm]["adapter"]["env_file"],
                "config_source": configs[arm]["adapter"]["config_source"],
                "generated_config_sha256": configs[arm]["adapter"][
                    "generated_config_sha256"
                ],
            }
            for arm in protocol.ARM_ORDER
        },
        "effective_configs": configs,
        "equality": {
            "A_to_D_identical": True,
            "E_delta": list(changed),
            "same_image_digest_all_arms": True,
            "same_image_suffix_all_arms": True,
            "same_pipeline_all_arms": True,
            "same_native_permissions": True,
            "generated_configs_equal_without_mcp": True,
            "mcp_surface_only_in_E": True,
        },
        "harness": {
            "dir": str(harness_dir) if harness_dir else None,
            "version": probe_harness_version(harness_dir),
            "tool_adapter_version": tool_adapter_version(),
        },
        "checks": [
            {"name": "manifest_verified", "ok": True},
            {"name": "model_provider_pinned", "ok": True},
            {"name": "image_digest_single", "ok": True},
            {"name": "snapshot_identity", "ok": True},
            {"name": "attempt_policy", "ok": True},
            {"name": "credentials_channel", "ok": True},
            {"name": "credential_path_bound", "ok": True},
            {"name": "prompt_hashes", "ok": True},
            {"name": "adapter_launch_facts", "ok": True},
            {"name": "effective_configs", "ok": True},
        ],
        "limitations": [
            "Single-case diagnostic; it localizes one treatment effect and "
            "does not establish general parity.",
            "The image digest is the local Docker content ID of the single "
            "frozen tag; tags are mutable, so preflight re-probes it before "
            "the run.",
            "The snapshot content hash is the controller's documented "
            "tree-sha256/v1 value, not a hash minted by another tool.",
            "The protocol synthesizes no system message. Adapter-injected "
            "system text is captured verbatim when the raw export exposes "
            "it; an export without system messages is recorded as "
            "'absent_from_export_not_proof', never as proof that none were "
            "sent. The export lists invoked tools, not the full registered "
            "tool schema.",
            "Effective-config equality combines the frozen runtime fields "
            "with adapter-reported launch facts: image suffix/tag, legacy "
            "pipeline id, canonical model binding, resolved credential and "
            "config paths, exported artifact surface and the synthesized "
            "config content hash with 'mcp' removed. Native permissions are "
            "taken from the frozen runtime and are equal across arms; the "
            "image's tool binaries are shared by construction.",
            "The shared runtime is the legacy C1 benchmark permission model "
            "(writable workspace, network access, "
            "--dangerously-skip-permissions). It is not the E6 sandbox, is "
            "not E6-safe, and this experiment does not weaken E6 globally.",
        ],
    }
    preflight_path = root / PREFLIGHT_NAME
    if preflight_path.exists():
        prior = read_json(preflight_path)
        comparable_prior = {
            key: value for key, value in prior.items()
            if key != "checked_at_utc"
        }
        comparable_now = {
            key: value for key, value in report.items()
            if key != "checked_at_utc"
        }
        if comparable_prior != comparable_now:
            raise AttemptExistsError(
                "environment changed since the frozen preflight record; "
                "refusing to replace {}".format(preflight_path),
                code="preflight_drift",
                details={
                    "path": str(preflight_path),
                    "changed": sorted(
                        key for key in set(comparable_prior)
                        | set(comparable_now)
                        if comparable_prior.get(key)
                        != comparable_now.get(key)
                    ),
                },
            )
        return prior
    write_json_once_matching(preflight_path, report)
    return report


# ---------------------------------------------------------------------------
# Raw-export derivation
# ---------------------------------------------------------------------------


def read_export(path: Optional[Path]) -> Optional[Dict[str, Any]]:
    if path is None or not Path(path).is_file():
        return None
    try:
        parsed = read_json(Path(path))
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _message_text(message: Mapping[str, Any]) -> str:
    parts = message.get("parts")
    if not isinstance(parts, list):
        return ""
    texts = [
        part.get("text", "")
        for part in parts
        if isinstance(part, Mapping) and part.get("type") == "text"
    ]
    return "".join(text for text in texts if isinstance(text, str))


def extract_request_messages(export: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    """User/system text and invoked tools visible in the raw export."""
    system_messages: List[Dict[str, str]] = []
    user_messages: List[Dict[str, Any]] = []
    tool_names: List[str] = []
    if not isinstance(export, Mapping):
        return {
            "system_messages": system_messages,
            "user_messages": user_messages,
            "tool_names": tool_names,
        }
    for message in export.get("messages") or []:
        if not isinstance(message, Mapping):
            continue
        info = message.get("info") or {}
        role = info.get("role")
        text = _message_text(message)
        if role in ("system", "developer") and text:
            system_messages.append({"role": str(role), "content": text})
        elif role == "user":
            user_messages.append(
                {"sha256": protocol.sha256_text(text), "bytes": len(
                    text.encode("utf-8")
                )}
            )
        for part in message.get("parts") or []:
            if not isinstance(part, Mapping) or part.get("type") != "tool":
                continue
            tool = part.get("tool")
            if isinstance(tool, str) and tool:
                tool_names.append(tool)
    return {
        "system_messages": system_messages,
        "user_messages": user_messages,
        "tool_names": sorted(set(tool_names)),
    }


def extract_native_tool_calls(
    export: Optional[Mapping[str, Any]]
) -> List[Dict[str, Any]]:
    calls: List[Dict[str, Any]] = []
    if not isinstance(export, Mapping):
        return calls
    for message_index, message in enumerate(export.get("messages") or []):
        if not isinstance(message, Mapping):
            continue
        info = message.get("info") or {}
        for part_index, part in enumerate(message.get("parts") or []):
            if not isinstance(part, Mapping) or part.get("type") != "tool":
                continue
            state = part.get("state") or {}
            output = state.get("output")
            if isinstance(output, str):
                output_text = output
            elif output is None:
                output_text = ""
            else:
                output_text = json.dumps(
                    output, sort_keys=True, ensure_ascii=False
                )
            calls.append(
                {
                    "message_index": message_index,
                    "part_index": part_index,
                    "role": info.get("role"),
                    "tool": part.get("tool"),
                    "call_id": part.get("callID"),
                    "status": state.get("status"),
                    "input": state.get("input"),
                    "output_sha256": (
                        protocol.sha256_text(output_text)
                        if output_text
                        else None
                    ),
                    "output_bytes": len(output_text.encode("utf-8")),
                    "output_preview": output_text[:512],
                    "error": state.get("error"),
                }
            )
    return calls


def session_identity(
    export: Optional[Mapping[str, Any]]
) -> Dict[str, Any]:
    if not isinstance(export, Mapping):
        return {}
    info = export.get("info") or {}
    model = info.get("model") or {}
    return {
        "session_id": info.get("id"),
        "runtime_version": info.get("version"),
        "model": model.get("id") or model.get("modelID"),
        "provider": model.get("providerID"),
    }


def detect_runtime_drift(
    export: Optional[Mapping[str, Any]]
) -> Optional[Dict[str, Any]]:
    """The raw export must show the pinned model and provider."""
    identity = session_identity(export)
    if not identity:
        return None
    allowed_models = {
        protocol.MODEL_ID,
        protocol.MODEL_ALIAS,
        protocol.PROVIDER_MODEL_ID,
    }
    observed_model = identity.get("model")
    if observed_model and observed_model not in allowed_models:
        return {
            "field": "model",
            "observed": observed_model,
            "expected": sorted(allowed_models),
        }
    observed_provider = identity.get("provider")
    if observed_provider and observed_provider != protocol.PROVIDER:
        return {
            "field": "provider",
            "observed": observed_provider,
            "expected": protocol.PROVIDER,
        }
    return None


def build_request_record(
    *,
    prompt: str,
    export: Optional[Mapping[str, Any]],
    arm: str,
    repeat: int,
    key: str,
    runtime_config: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    extracted = extract_request_messages(export)
    record = protocol.request_record(
        prompt, system_messages=extracted["system_messages"]
    )
    observed = []
    prompt_sha = protocol.sha256_text(prompt)
    for message in extracted["user_messages"]:
        observed.append(
            {
                "sha256": message["sha256"],
                "bytes": message["bytes"],
                "equals_protocol_prompt": message["sha256"] == prompt_sha,
            }
        )
    system_count = len(extracted["system_messages"])
    if export is None:
        system_observation = "export_unavailable"
    elif system_count:
        system_observation = "present_in_export"
    else:
        system_observation = "absent_from_export_not_proof"
    mcp = (runtime_config or {}).get("mcp") or {}
    record.update(
        {
            "schema": REQUEST_SCHEMA,
            "arm": arm,
            "repeat": repeat,
            "attempt_key": key,
            "recording_source": (
                "result.json raw export"
                if export is not None
                else "protocol-only (raw export unavailable)"
            ),
            "adapter_system_messages": extracted["system_messages"],
            "system_messages_observed": system_count > 0,
            "system_message_observation": system_observation,
            "system_message_limitation": (
                None
                if system_count
                else "No system message is visible in the raw export; this "
                     "is not proof that the runtime sent none."
            ),
            "observed_user_messages": observed,
            "tool_surface": {
                "mcp_enabled": bool(mcp.get("enabled")),
                "mcp_server": mcp.get("server"),
                "observed_invoked_tools": extracted["tool_names"],
                "available_tool_schemas_observed": False,
                "note": (
                    "The raw export lists only invoked tools; the complete "
                    "registered tool schema is not exposed and is not "
                    "inferred. MCP availability is verified from the "
                    "generated launch config, not from this list."
                ),
            },
            "note": (
                "The protocol synthesizes no system message. Any system "
                "text here was injected by the adapter and is captured "
                "verbatim from the raw export; its hash participates in "
                "full_request_sha256. An empty system-message list is "
                "recorded as absent_from_export_not_proof, not as a claim "
                "that no instructions were sent."
            ),
        }
    )
    return record


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


def _status_value(status: Any, key: str, default: Any = None) -> Any:
    if isinstance(status, Mapping):
        return status.get(key, default)
    return getattr(status, key, default)


def status_record(status: Any) -> Dict[str, Any]:
    if hasattr(status, "model_dump"):
        return status.model_dump()
    if isinstance(status, Mapping):
        return dict(status)
    raise TypeError("finalize returned an unsupported status object")


def classify_attempt(
    status: Any, drift: Optional[Mapping[str, Any]]
) -> Tuple[str, str, Optional[str]]:
    """Return (outcome, failure_class, failure_reason).

    ``infrastructure`` is an environment/identity failure, ``provider`` is
    a provider refusal, ``model_output`` is a malformed/unparseable answer.
    None of them is ever a completed model answer.
    """
    if drift:
        return "failed", "infrastructure", "runtime_drift"
    overall = _status_value(status, "overall")
    execution = _status_value(status, "execution")
    official_parse = _status_value(status, "official_parse")
    reason = _status_value(status, "failure_reason")
    if overall in ("valid", "inconclusive"):
        return "completed", "none", None
    if execution == "provider_refusal":
        return "failed", "provider", reason or "provider_refusal"
    if official_parse in ("parse_fail", "no_result", "no_dir"):
        if execution in _INFRA_EXECUTIONS or reason in _INFRA_REASONS:
            return "failed", "infrastructure", reason
        return "failed", "model_output", reason or "invalid_terminal_answer"
    if execution in _INFRA_EXECUTIONS or reason in _INFRA_REASONS:
        return "failed", "infrastructure", reason
    return "failed", "model_output", reason


# ---------------------------------------------------------------------------
# Running the frozen schedule
# ---------------------------------------------------------------------------


def _artifact_index(run_dir: Path, result_filename: str) -> Dict[str, Any]:
    names = {
        "prompt": PROMPT_NAME,
        "raw_export": result_filename,
        "final_answer": FINAL_TEXT_NAME,
        "status": STATUS_NAME,
        "assessment": ASSESSMENT_NAME,
        "usage": USAGE_NAME,
        "tool_calls": TOOL_CALLS_NAME,
        "observations": OBSERVATIONS_NAME,
        "native_tool_calls": NATIVE_TOOL_CALLS_NAME,
        "request": REQUEST_NAME,
        "export_report": EXPORT_REPORT_NAME,
        "error": ERROR_NAME,
    }
    present: Dict[str, Any] = {}
    hashes: Dict[str, str] = {}
    for label, name in names.items():
        path = Path(run_dir) / name
        if path.is_file():
            present[label] = name
            hashes[name] = sha256_file(path)
        else:
            present[label] = None
    return {"files": present, "sha256": hashes}


def _load_usage(run_dir: Path) -> Any:
    path = Path(run_dir) / USAGE_NAME
    if not path.is_file():
        return None
    try:
        from eval.c1.assessment import UsageStats
    except ImportError:
        # The c1 artifact schema is unavailable in this interpreter; the
        # raw usage.json is still preserved for the report.
        return None
    try:
        return UsageStats.model_validate_json(
            path.read_text(encoding="utf-8")
        )
    except Exception:  # noqa: BLE001 - a bad usage artifact is not fatal
        logger.warning("could not parse %s", path, exc_info=True)
        return None


def _attempt_meta(
    *,
    manifest: Mapping[str, Any],
    arm: str,
    repeat: int,
    prompt_sha12: str,
    image: str,
    snapshot_sha256: str,
    harness_version: str,
) -> Any:
    from eval.c1.assessment import AttemptMeta

    runtime = manifest["runtime"]
    return AttemptMeta(
        experiment_id=manifest["experiment_id"],
        task_id=manifest["case"]["task_id"],
        attempt_id="repeat-{}".format(repeat),
        cve_id=manifest["case"]["cve_id"],
        snapshot_hash=snapshot_sha256,
        model=(
            runtime["model"].get("alias")
            or manifest["runtime"]["model"]["id"]
        ),
        model_revision=runtime["model"].get("revision"),
        prompt_version="arm-{}-{}".format(arm, prompt_sha12),
        harness_version=harness_version or "unknown",
        tool_adapter_version=tool_adapter_version(),
        image=image,
    )


def _run_one(
    *,
    entry: Mapping[str, Any],
    run_dir: Path,
    agent: Any,
    prompt: str,
    manifest: Mapping[str, Any],
    preflight_report: Mapping[str, Any],
    config: Mapping[str, Any],
    snapshot_path: Path,
    image_tag: str,
    expected_digest: str,
    secret_env_path: Path,
    secret_config_path: Optional[Path],
    harness_dir: Optional[Path],
    digest_probe: Callable[[str], str],
    run_attempt_fn: Callable[..., Any],
    artifacts_fn: Callable[..., Any],
    finalize_fn: Callable[..., Any],
    official_parser: Optional[Callable[[str], Any]],
    parser_for_record: Optional[Callable[[str], Any]],
    meta_factory: Callable[..., Any],
    harness_version: str,
    clock: Callable[[], float],
) -> Dict[str, Any]:
    arm = entry["arm"]
    repeat = int(entry["repeat"])
    key = entry["attempt_key"]
    case = manifest["case"]
    policy = manifest["attempt_policy"]
    timeout = int(policy["timeout_seconds"])

    observed_digest = digest_probe(image_tag)
    if observed_digest != expected_digest:
        raise InfrastructureError(
            "image digest changed before arm {} repeat {}".format(arm, repeat),
            code="image_digest_drift",
            details={
                "observed": observed_digest,
                "expected": expected_digest,
            },
        )
    if not Path(snapshot_path).is_dir():
        raise InfrastructureError(
            "snapshot disappeared before arm {} repeat {}".format(arm, repeat),
            code="snapshot_missing",
            details={"path": str(snapshot_path)},
        )
    if Path(run_dir).exists():
        raise AttemptExistsError(
            "attempt directory already exists: {}".format(run_dir),
            details={"attempt_key": key, "path": str(run_dir)},
        )

    started_at = utc_now(clock)
    started_monotonic = time.monotonic()
    try:
        with launch_environment(
            secret_env_path=secret_env_path,
            secret_config_path=secret_config_path,
            harness_dir=harness_dir,
        ):
            result_path = run_attempt_fn(
                Path(run_dir),
                agent=agent,
                prompt=prompt,
                src_cwd=Path(snapshot_path),
                language=case["language"],
                timeout=timeout,
            )
    except Exception as exc:  # noqa: BLE001 - classify, never fabricate
        if type(exc).__name__ == "DuplicateAttemptError":
            raise AttemptExistsError(
                "attempt directory already has terminal artifacts: {}".format(
                    run_dir
                ),
                details={"attempt_key": key, "path": str(run_dir)},
            ) from exc
        raise InfrastructureError(
            "adapter failed before producing a model result for arm {} "
            "repeat {}: {}".format(arm, repeat, exc),
            code="attempt_controller_error",
            details={"attempt_key": key},
        ) from exc
    wall_seconds = time.monotonic() - started_monotonic

    artifacts_fn(Path(run_dir), agent, wall_seconds)

    result_file = Path(run_dir) / agent.result_filename()
    error_file = Path(run_dir) / ERROR_NAME
    export = read_export(result_path or result_file)

    native_calls = extract_native_tool_calls(export)
    write_text_once(
        Path(run_dir) / NATIVE_TOOL_CALLS_NAME,
        "".join(
            json.dumps(call, sort_keys=True, ensure_ascii=False) + "\n"
            for call in native_calls
        ),
    )
    request = build_request_record(
        prompt=prompt,
        export=export,
        arm=arm,
        repeat=repeat,
        key=key,
        runtime_config=config,
    )
    write_json_once(Path(run_dir) / REQUEST_NAME, request)

    official_category = None
    official_category_source = None
    if result_file.is_file() and parser_for_record is not None:
        try:
            terminal = agent.extract_text(
                result_file.read_text(encoding="utf-8", errors="replace")
            ).strip()
        except Exception:  # noqa: BLE001 - a bad export is a status defect
            terminal = ""
        if terminal:
            try:
                category, _reasoning = parser_for_record(terminal)
            except Exception:  # noqa: BLE001 - parser defects stay visible
                category = None
            official_category = category
            official_category_source = (
                "official parser over the saved terminal answer "
                "(projection; status.json is authoritative)"
            )

    status, assessment = finalize_fn(
        Path(run_dir),
        meta=meta_factory(
            manifest=manifest,
            arm=arm,
            repeat=repeat,
            prompt_sha12=manifest["prompts"][arm]["sha256_12"],
            image="{}@{}".format(image_tag, expected_digest),
            snapshot_sha256=preflight_report["snapshot"]["content_sha256"],
            harness_version=harness_version,
        ),
        usage=_load_usage(Path(run_dir)),
        result_filename=agent.result_filename(),
        final_text_extractor=agent.extract_text,
        official_parser=official_parser,
    )
    drift = detect_runtime_drift(export)
    outcome, failure_class, failure_reason = classify_attempt(status, drift)
    identity = session_identity(export)
    record = {
        "schema": ATTEMPT_SCHEMA,
        "experiment_id": manifest["experiment_id"],
        "task_id": case["task_id"],
        "cve_id": case["cve_id"],
        "arm": arm,
        "repeat": repeat,
        "attempt_key": key,
        "sequence_index": entry["index"],
        "agent": config["agent"],
        "mcp": bool((config.get("mcp") or {}).get("enabled")),
        "prompt_sha256": manifest["prompts"][arm]["sha256"],
        "prompt_sha256_12": manifest["prompts"][arm]["sha256_12"],
        "prompt_path": PROMPT_NAME,
        "runtime": config,
        "runtime_sha256": protocol.sha256_text(
            protocol.canonical_json(config)
        ),
        "image_tag": image_tag,
        "image_digest": observed_digest,
        "model": manifest["runtime"]["model"]["id"],
        "provider": manifest["runtime"]["model"]["provider"],
        "model_observed": identity.get("model"),
        "provider_observed": identity.get("provider"),
        "runtime_version_observed": identity.get("runtime_version"),
        "session_id_observed": identity.get("session_id"),
        "snapshot_path": preflight_report["snapshot"]["path"],
        "snapshot_sha256": preflight_report["snapshot"]["content_sha256"],
        "credentials": dict(preflight_report["credentials"]),
        "started_at_utc": started_at,
        "finished_at_utc": utc_now(clock),
        "wall_seconds": round(wall_seconds, 3),
        "result_present": result_file.is_file(),
        "error_present": error_file.is_file(),
        "error_excerpt": (
            error_file.read_text(encoding="utf-8", errors="replace")[-2000:]
            if error_file.is_file()
            else None
        ),
        "runtime_drift": drift,
        "outcome": outcome,
        "failure_class": failure_class,
        "failure_reason": failure_reason,
        "official_category": official_category,
        "official_category_source": official_category_source,
        "status": status_record(status),
        "assessment_present": assessment is not None,
        "artifacts": None,
    }
    record["artifacts"] = _artifact_index(
        Path(run_dir), agent.result_filename()
    )
    write_json_once(Path(run_dir) / ATTEMPT_RECORD_NAME, record)
    return {
        "index": entry["index"],
        "arm": arm,
        "repeat": repeat,
        "attempt_key": key,
        "attempt_dir": str(Path(run_dir).resolve()),
        "outcome": outcome,
        "failure_class": failure_class,
        "failure_reason": failure_reason,
        "abort_run": failure_reason == "runtime_drift",
    }


def _not_run_entry(
    entry: Mapping[str, Any], run_dir: Path, reason: str
) -> Dict[str, Any]:
    return {
        "index": entry["index"],
        "arm": entry["arm"],
        "repeat": int(entry["repeat"]),
        "attempt_key": entry["attempt_key"],
        "attempt_dir": str(Path(run_dir).resolve()),
        "outcome": "not_run",
        "failure_class": "infrastructure",
        "failure_reason": reason,
        "abort_run": False,
    }


def run_experiment(
    *,
    secret_env_path: Path,
    secret_config_path: Optional[Path] = None,
    results_root: Optional[Path] = None,
    manifest_path: Optional[Path] = None,
    manifest: Optional[Mapping[str, Any]] = None,
    case: Optional[Mapping[str, Any]] = None,
    runtime: Optional[Mapping[str, Any]] = None,
    advisory_path: Optional[Path] = None,
    harness_dir: Optional[Path] = None,
    digest_probe: Optional[Callable[[str], str]] = None,
    snapshot_probe: Optional[Callable[[Path], Mapping[str, Any]]] = None,
    agent_loader: Optional[Callable[[str, str], Any]] = None,
    run_attempt_fn: Optional[Callable[..., Any]] = None,
    artifacts_fn: Optional[Callable[..., Any]] = None,
    finalize_fn: Optional[Callable[..., Any]] = None,
    official_parser: Optional[Callable[[str], Any]] = None,
    meta_factory: Optional[Callable[..., Any]] = None,
    frozen_at_utc: Optional[str] = None,
    clock: Callable[[], float] = time.time,
) -> Dict[str, Any]:
    """Run all 15 frozen attempts sequentially; never retry or overwrite."""
    report = preflight(
        secret_env_path=secret_env_path,
        secret_config_path=secret_config_path,
        results_root=results_root,
        manifest_path=manifest_path,
        manifest=manifest,
        case=case,
        runtime=runtime,
        advisory_path=advisory_path,
        harness_dir=harness_dir,
        digest_probe=digest_probe,
        snapshot_probe=snapshot_probe,
        agent_loader=agent_loader,
        frozen_at_utc=frozen_at_utc,
        clock=clock,
    )
    frozen = load_manifest(Path(report["manifest_path"]))
    assert_pinned_runtime(frozen)
    schedule = validate_schedule(frozen)
    case_record = frozen["case"]
    root = experiment_root(
        report["manifest_path"], results_root, frozen["experiment_id"]
    )

    planned: List[Tuple[Dict[str, Any], Path]] = []
    results_base = root.parent
    for entry in schedule:
        run_dir = attempt_dir(
            results_base,
            frozen["experiment_id"],
            case_record["task_id"],
            entry["arm"],
            int(entry["repeat"]),
        )
        planned.append((entry, run_dir))
    existing = [str(path) for _, path in planned if path.exists()]
    if existing:
        raise AttemptExistsError(
            "refusing to run: {} attempt directories already exist".format(
                len(existing)
            ),
            details={"paths": existing},
        )
    summary_path = root / RUN_SUMMARY_NAME
    if summary_path.exists():
        raise AttemptExistsError(
            "refusing to rerun: {} already exists".format(summary_path),
            details={"path": str(summary_path)},
        )

    advisory_source = _resolve_path(frozen["sources"]["advisory"]["path"])
    arms = protocol.build_arms(
        case_record["cve_id"], advisory_source.read_text(encoding="utf-8")
    )
    verify_prompt_hashes(frozen, arms)

    with launch_environment(
        secret_env_path=Path(secret_env_path),
        secret_config_path=secret_config_path,
        harness_dir=harness_dir,
    ):
        agents = _load_agents_checked(
            frozen, agent_loader or _default_agent_loader
        )
        configs = build_arm_configs(
            frozen,
            agents,
            image_digest=report["image"]["digest"],
            snapshot_sha256=report["snapshot"]["content_sha256"],
            secret_env_path=Path(secret_env_path),
            secret_config_path=secret_config_path,
        )
    assert_effective_contract(configs)
    assert_attempt_policy(frozen["attempt_policy"])

    snapshot_path = _resolve_path(case_record["snapshot_path"])
    run_attempt_fn = run_attempt_fn or _default_run_attempt
    artifacts_fn = artifacts_fn or _default_controller_artifacts
    finalize_fn = finalize_fn or _default_finalize
    meta_factory = meta_factory or _attempt_meta
    probe_digest = digest_probe or probe_image_digest
    parser_for_record = official_parser or try_load_official_parser()
    harness_version = report["harness"]["version"]
    image_tag = frozen["runtime"]["image"]["tag"]
    expected_digest = report["image"]["digest"]

    started_at = utc_now(clock)
    results: List[Dict[str, Any]] = []
    abort_reason: Optional[str] = None
    for entry, run_dir in planned:
        if abort_reason is not None:
            results.append(_not_run_entry(entry, run_dir, abort_reason))
            continue
        try:
            outcome = _run_one(
                entry=entry,
                run_dir=run_dir,
                agent=agents[entry["arm"]],
                prompt=arms[entry["arm"]],
                manifest=frozen,
                preflight_report=report,
                config=configs[entry["arm"]],
                snapshot_path=snapshot_path,
                image_tag=image_tag,
                expected_digest=expected_digest,
                secret_env_path=Path(secret_env_path),
                secret_config_path=secret_config_path,
                harness_dir=harness_dir,
                digest_probe=probe_digest,
                run_attempt_fn=run_attempt_fn,
                artifacts_fn=artifacts_fn,
                finalize_fn=finalize_fn,
                official_parser=official_parser,
                parser_for_record=parser_for_record,
                meta_factory=meta_factory,
                harness_version=harness_version,
                clock=clock,
            )
        except AttemptExistsError:
            raise
        except AblationError as exc:
            abort_reason = exc.code
            results.append(_not_run_entry(entry, run_dir, exc.code))
            continue
        results.append(outcome)
        if outcome.get("abort_run"):
            abort_reason = "runtime_drift"

    counts = {
        "completed": 0,
        "failed_infrastructure": 0,
        "failed_provider": 0,
        "failed_model_output": 0,
        "not_run": 0,
    }
    for result in results:
        if result["outcome"] == "not_run":
            counts["not_run"] += 1
        elif result["failure_class"] == "none":
            counts["completed"] += 1
        else:
            key = "failed_{}".format(result["failure_class"])
            counts[key] = counts.get(key, 0) + 1
    summary = {
        "schema": RUN_SUMMARY_SCHEMA,
        "experiment_id": frozen["experiment_id"],
        "task_id": case_record["task_id"],
        "manifest_path": report["manifest_path"],
        "manifest_sha256": frozen["manifest_sha256"],
        "started_at_utc": started_at,
        "finished_at_utc": utc_now(clock),
        "image": dict(report["image"]),
        "model": dict(report["model"]),
        "snapshot": dict(report["snapshot"]),
        "policy": dict(frozen["attempt_policy"]),
        "schedule_sha256": frozen["schedule_sha256"],
        "runtime_sha256": frozen["runtime_sha256"],
        "attempts": results,
        "counts": counts,
        "outcome": (
            "complete" if abort_reason is None else "aborted"
        ),
        "abort_reason": abort_reason,
    }
    write_json_once(summary_path, summary)
    return summary

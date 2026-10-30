"""C1 experiment controller: attempt orchestration and artifact layout
(Task 4.3 / plan sections 4-5).

The controller reuses the harness's own agent adapters (``codex-c1`` /
``codex-b1p`` / ``opencode-c1``) and their container lifecycle — it is
NOT a new agent loop. What it adds on top of the official ``evaluate.run`` is:

- an ``experiment_id`` namespace so smoke/synthetic outputs can never be
  admitted into the frozen 90-attempt cohort;
- immutable attempt layout ``<results_root>/<experiment_id>/<task_id>/
  <attempt_id>/`` with controller artifacts (status.json,
  agent_assessment.json, raw_agent_output.txt, tool_calls.jsonl,
  observations.jsonl, usage.json);
- controller-side finalization through ``collect.finalize_attempt``
  (official parser injected unchanged — never reimplemented here);
- no [CACHE]/[RE-RUN] admission: an existing ``status.json`` aborts the
  attempt (DuplicateAttemptError), retries under the same key are
  impossible.

The official ``result_parser.py`` is used verbatim via the harness import;
this module never edits it.
"""

from __future__ import annotations

import json
import logging
import sys
import time
from pathlib import Path
from typing import Optional, Sequence

from .assessment import AttemptMeta, UsageStats
from .collect import finalize_attempt

logger = logging.getLogger(__name__)

EXPERIMENT_SMOKE = "c1-smoke"
EXPERIMENT_FINAL = "c1"

# Ground-truth classes the smoke cohort must cover (plan section 4, step 5).
# Values are task["ground_truth_category"] in the benchmark tasks file.
SMOKE_CLASS_BY_KEY = {
    "exploitable": "vulnerable",
    "non_reachable": "code_not_reachable",
    "configuration": "requires_configuration",
}


def harness_src() -> Path:
    """The external harness checkout's importable src/ (lazy, env-overridable).

    Resolution order: C1_HARNESS_DIR env var → the documented default
    ``/tmp/vexbench-agent-ctl``. Kept lazy so unit tests never need the
    harness on disk.
    """
    import os

    root = Path(os.environ.get("C1_HARNESS_DIR", "/tmp/vexbench-agent-ctl"))
    src = root / "src"
    if not (src / "evaluate").is_dir():
        raise RuntimeError(f"harness checkout not found at {root} (set C1_HARNESS_DIR)")
    return src


def load_agent(profile: str, model: str):
    """Instantiate a harness agent profile (``codex-c1``/``codex-b1p``/``opencode-b1p``/``opencode-c1``)."""
    src = str(harness_src())
    if src not in sys.path:
        sys.path.insert(0, src)
    from evaluate.agents import AGENTS  # noqa: E402  (harness import, lazy)

    if profile not in AGENTS:
        raise RuntimeError(f"unknown agent profile {profile!r}; have {sorted(AGENTS)}")
    return AGENTS[profile](model=model)


def run_attempt(
    run_dir: Path,
    *,
    agent,
    prompt: str,
    src_cwd: Path,
    language: str,
    timeout: int,
) -> Optional[Path]:
    """Run one attempt exactly like official ``run._run_one`` — minus caching.

    Writes ``result.jsonl`` on agent success or ``error.txt`` on RuntimeError,
    plus ``prompt.txt`` (the exact rendered prompt, audit evidence that the
    agent saw only the CVE id — no GT/class). Returns the result path or
    None on runtime failure. ``artifacts/`` is populated by the adapter's
    artifact_paths + full io_log capture.
    """
    src = str(harness_src())
    if src not in sys.path:
        sys.path.insert(0, src)
    from evaluate.agents.base import RunContext  # noqa: E402

    run_dir = Path(run_dir)
    if (run_dir / "status.json").exists() or (
        run_dir / agent.result_filename()
    ).exists():
        from .assessment import DuplicateAttemptError

        raise DuplicateAttemptError(
            f"attempt dir already has terminal artifacts: {run_dir}"
        )
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "prompt.txt").write_text(prompt, encoding="utf-8")

    ctx = RunContext(
        cwd=src_cwd,
        language=language,
        timeout=timeout,
        artifacts_dir=run_dir / "artifacts",
    )
    try:
        res = agent.run(prompt, ctx)
    except RuntimeError as exc:
        (run_dir / "error.txt").write_text(f"{exc}\n", encoding="utf-8")
        return None
    (run_dir / agent.result_filename()).write_text(res.raw_output, encoding="utf-8")
    return run_dir / agent.result_filename()


def write_controller_artifacts(run_dir: Path, agent, wall_seconds: float) -> None:
    """Spec-section-11 files the harness does not produce:
    ``raw_agent_output.txt`` (terminal agent_message text),
    ``tool_calls.jsonl`` + ``observations.jsonl`` (top-level copies of the
    MCP audit sink) and ``usage.json`` (factual counters only).
    """
    run_dir = Path(run_dir)
    result_path = run_dir / agent.result_filename()
    if result_path.exists():
        raw = result_path.read_text(encoding="utf-8", errors="replace")
        _write_once(run_dir / "raw_agent_output.txt", agent.extract_text(raw) + "\n")
        stats = agent.extract_stats(raw)
        usage = UsageStats(
            input_tokens=stats.input_tokens,
            cached_input_tokens=stats.cached_input_tokens,
            output_tokens=stats.output_tokens,
            reasoning_tokens=stats.reasoning_tokens,
            wall_seconds=round(wall_seconds, 3),
        )
        _write_once(
            run_dir / "usage.json", usage.model_dump_json(indent=2) + "\n"
        )
    audit_src = run_dir / "artifacts" / "izyan-audit" / "tool_calls.jsonl"
    if audit_src.exists():
        _write_once(run_dir / "tool_calls.jsonl", audit_src.read_text(encoding="utf-8"))
        obs_lines = []
        for line in audit_src.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            obs = rec.get("observation")
            if isinstance(obs, dict):
                obs_lines.append(json.dumps(obs, sort_keys=True))
        _write_once(
            run_dir / "observations.jsonl", "\n".join(obs_lines) + ("\n" if obs_lines else "")
        )
    export_report = run_dir / "artifacts" / "export-report.json"
    if export_report.exists():
        _write_once(
            run_dir / "export-report.json",
            export_report.read_text(encoding="utf-8"),
        )


def _write_once(path: Path, text: str) -> None:
    if path.exists():
        from .assessment import DuplicateAttemptError

        raise DuplicateAttemptError(f"refusing to overwrite: {path}")
    path.write_text(text, encoding="utf-8")


def smoke_selection(tasks: Sequence[dict]) -> dict[str, dict]:
    """Controller-side smoke pick: one task per required GT class.

    The class stays controller metadata — the rendered prompt carries only
    the CVE id (run_attempt writes prompt.txt for the audit trail).
    """
    picked: dict[str, dict] = {}
    for task in tasks:
        cat = task.get("ground_truth_category")
        for key, want in SMOKE_CLASS_BY_KEY.items():
            if cat == want and key not in picked:
                picked[key] = task
    missing = [k for k in SMOKE_CLASS_BY_KEY if k not in picked]
    if missing:
        raise RuntimeError(f"no task found for smoke classes: {missing}")
    return picked


def task_snapshot_dir(repos_dir: Path, task: dict) -> Path:
    """<repos_dir>/<owner>/<repo>/<commit_sha> — same convention as run.py."""
    src = str(harness_src())
    if src not in sys.path:
        sys.path.insert(0, src)
    from utils.repo import parse_owner_repo  # noqa: E402

    owner, repo = parse_owner_repo(task["repo_url"])
    return Path(repos_dir) / owner / repo / task["commit_sha"]


def run_benchmark_attempt(
    results_root: Path,
    *,
    experiment_id: str,
    task: dict,
    attempt_id: str,
    agent,
    prompt_template: str,
    repos_dir: Path,
    timeout: int,
    meta_kwargs: dict,
):
    """One smoke/benchmark attempt end-to-end: container run, controller
    artifacts, status.json + agent_assessment.json. Returns AttemptStatus.
    """
    task_id = task["task_id"]
    run_dir = Path(results_root) / experiment_id / task_id / attempt_id
    prompt = prompt_template.replace("{cve_id}", task["cve_id"])
    src_cwd = task_snapshot_dir(repos_dir, task)

    t0 = time.monotonic()
    run_attempt(
        run_dir,
        agent=agent,
        prompt=prompt,
        src_cwd=src_cwd,
        language=task.get("metadata", {}).get("language", "go"),
        timeout=timeout,
    )
    wall = time.monotonic() - t0
    write_controller_artifacts(run_dir, agent, wall)

    meta = AttemptMeta(
        experiment_id=experiment_id,
        task_id=task_id,
        attempt_id=attempt_id,
        cve_id=task["cve_id"],
        snapshot_hash=meta_kwargs["snapshot_hash"],
        model=meta_kwargs["model"],
        model_revision=meta_kwargs.get("model_revision"),
        prompt_version=meta_kwargs["prompt_version"],
        harness_version=meta_kwargs["harness_version"],
        tool_adapter_version=meta_kwargs["tool_adapter_version"],
        image=meta_kwargs.get("image"),
    )
    usage = None
    usage_path = run_dir / "usage.json"
    if usage_path.exists():
        usage = UsageStats.model_validate_json(usage_path.read_text(encoding="utf-8"))
    status, _asm = finalize_attempt(
        run_dir,
        meta=meta,
        usage=usage,
        result_filename=agent.result_filename(),
        final_text_extractor=agent.extract_text,
    )
    return status

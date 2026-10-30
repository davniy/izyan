#!/usr/bin/env python3
"""Task 4.3 entrypoint: C1 synthetic checks, 3-case smoke, manifest freeze.

Run inside the harness venv with the worktree on sys.path:

  cd <VA_REPO>
  /tmp/vexbench-agent-ctl/.venv/bin/python eval/vexbench_c1.py synthetic
  /tmp/vexbench-agent-ctl/.venv/bin/python eval/vexbench_c1.py smoke \
      --tasks /tmp/vexbench-agent-ctl/benchmark/tasks/vex_bench.jsonl \
      --repos-dir /tmp/vexbench-baseline/repos
  /tmp/vexbench-agent-ctl/.venv/bin/python eval/vexbench_c1.py manifest

The script chdirs into the harness checkout because the codex adapters
resolve env/codex/* relative to cwd (same constraint as `vex-bench`).
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path

WORKTREE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WORKTREE))

from eval.c1 import manifest as manifest_mod  # noqa: E402
from eval.c1 import runner, synthetic  # noqa: E402

DEFAULT_HARNESS = Path("/tmp/vexbench-agent-ctl")
DEFAULT_RESULTS = WORKTREE / "results" / "task4-c1"
DEFAULT_MODEL = "gpt-6.1-sol"
DEFAULT_TIMEOUT = 900


def _chdir_harness(harness_dir: Path) -> None:
    if not (harness_dir / "env" / "codex" / "codex.env").exists():
        raise SystemExit(f"harness env file missing: {harness_dir}/env/codex/codex.env")
    os.chdir(harness_dir)
    src = str(harness_dir / "src")
    if src not in sys.path:
        sys.path.insert(0, src)


def _meta_kwargs(harness_dir: Path, model: str, image: str) -> dict:
    import subprocess

    head = subprocess.run(
        ["git", "-C", str(harness_dir), "rev-parse", "--short", "HEAD"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    return {
        "model": model,
        "prompt_version": "vuln_c1-6eda998ea66c",
        "harness_version": f"vexbench-agent-ctl@{head}",
        "tool_adapter_version": manifest_mod._tool_adapter_version(WORKTREE),
        "image": image,
    }


def cmd_synthetic(args) -> int:
    results_root = Path(args.results_root).resolve()  # before chdir
    harness_dir = Path(args.harness_dir)
    _chdir_harness(harness_dir)
    out_dir = results_root / "_synthetic"
    meta = _meta_kwargs(harness_dir, args.model, synthetic.IMAGE_C1)
    results = synthetic.run_battery(
        out_dir,
        model=args.model,
        live_timeout=args.timeout,
        run_live=not args.no_live,
        meta_kwargs=meta,
    )
    summary = results.get("_summary", {})
    print(json.dumps(summary, indent=2))
    return 0 if summary.get("all_ok") else 1


def cmd_smoke(args) -> int:
    results_root = Path(args.results_root).resolve()  # before chdir
    harness_dir = Path(args.harness_dir)
    _chdir_harness(harness_dir)

    tasks_path = Path(args.tasks)
    tasks = [
        json.loads(l)
        for l in tasks_path.read_text(encoding="utf-8").splitlines()
        if l.strip()
    ]
    agent = runner.load_agent(args.agent, args.model)
    prompt_template = _load_prompt(harness_dir, args.prompt)
    image = args.image or (
        f"vex-bench-go-{agent.IMAGE_SUFFIX}:latest"
        if getattr(agent, "IMAGE_SUFFIX", None)
        else synthetic.IMAGE_C1
    )
    meta_base = _meta_kwargs(harness_dir, args.model, image)
    from eval.c1.protocol import prompt_hash

    meta_base["prompt_version"] = f"{args.prompt}-{prompt_hash(prompt_template)}"

    repos_dir = Path(args.repos_dir)
    acq = json.loads(Path(args.acquisition).read_text(encoding="utf-8"))
    snapshots = acq.get("snapshots", {})

    picked = (
        _pick_task(tasks, args.task_id)
        if args.task_id
        else runner.smoke_selection(tasks)
    )
    print("smoke selection (controller-side, GT class never reaches the agent):")
    for key, t in picked.items():
        print(f"  {key}: {t['task_id']} ({t['ground_truth_category']})")

    only = set(args.only.split(",")) if args.only else None

    experiment_id = args.experiment_id or runner.EXPERIMENT_SMOKE
    summary_path = results_root / experiment_id / "smoke-summary.json"
    summary: dict[str, dict] = (
        json.loads(summary_path.read_text()) if summary_path.exists() else {}
    )
    rc = 0
    for key, task in picked.items():
        if only and key not in only:
            print(f"  [{key}] skipped (--only)")
            continue
        owner_repo_sha = "/".join(
            task["repo_url"].rsplit("/", 2)[-2:] + [task["commit_sha"]]
        )
        meta = dict(meta_base)
        meta["snapshot_hash"] = (
            snapshots.get(owner_repo_sha, {}).get("content_hash") or "unknown"
        )
        t0 = time.monotonic()
        try:
            status = runner.run_benchmark_attempt(
                results_root,
                experiment_id=experiment_id,
                task=task,
                attempt_id=args.attempt_id,
                agent=agent,
                prompt_template=prompt_template,
                repos_dir=repos_dir,
                timeout=args.timeout,
                meta_kwargs=meta,
            )
            # last terminal status per class wins the summary; earlier
            # attempts stay on disk untouched
            summary[f"{key}@{args.attempt_id}"] = {
                "task_id": task["task_id"],
                "attempt_id": args.attempt_id,
                "status": status.model_dump(),
            }
        except Exception as exc:  # keep the other smoke cases running
            logging.exception("smoke case %s failed hard", key)
            summary[f"{key}@{args.attempt_id}"] = {
                "task_id": task["task_id"],
                "attempt_id": args.attempt_id,
                "error": str(exc),
            }
            rc = 1
        print(f"[{key}@{args.attempt_id}] done in {time.monotonic()-t0:.0f}s")

    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(
        json.dumps(summary, indent=2, default=str) + "\n", "utf-8"
    )
    print(f"smoke summary -> {summary_path}")
    return rc


def _load_prompt(harness_dir: Path, name: str) -> str:
    src = str(harness_dir / "src")
    if src not in sys.path:
        sys.path.insert(0, src)
    from evaluate.prompts import PROMPTS  # noqa: E402

    return PROMPTS[name]


def _pick_task(tasks: list[dict], task_id: str) -> dict[str, dict]:
    """Single-case selection for targeted smokes (e.g. per-model checks
    under one experiment namespace). Key is a literal ``task`` label —
    no GT-class semantics are implied."""
    for task in tasks:
        if task["task_id"] == task_id:
            return {"task": task}
    raise RuntimeError(f"task {task_id!r} not found in tasks file")


def cmd_manifest(args) -> int:
    harness_dir = Path(args.harness_dir)
    results_root = Path(args.results_root).resolve()
    m = manifest_mod.build_manifest(
        worktree=WORKTREE,
        harness_dir=harness_dir,
        tasks_path=Path(args.tasks),
        repos_dir=Path(args.repos_dir),
        acquisition_path=Path(args.acquisition),
        results_root=results_root,
        smoke_dir=results_root / runner.EXPERIMENT_SMOKE,
    )
    dest = manifest_mod.write_manifest(m, results_root / "manifest.json")
    # durable copy for the commit — the protocol freeze must survive /tmp
    frozen = manifest_mod.write_manifest(
        m, WORKTREE / "eval" / "c1" / "freeze" / "manifest.json"
    )
    print(f"manifest -> {dest}")
    print(f"frozen copy -> {frozen}")
    return 0


def main() -> int:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--harness-dir", default=str(DEFAULT_HARNESS))
    p.add_argument("--results-root", default=str(DEFAULT_RESULTS))
    p.add_argument("--model", default=DEFAULT_MODEL)
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    p.add_argument(
        "--tasks",
        default=str(DEFAULT_HARNESS / "benchmark/tasks/vex_bench.jsonl"),
    )
    p.add_argument("--repos-dir", default="/tmp/vexbench-baseline/repos")
    p.add_argument(
        "--acquisition", default="/tmp/vexbench-baseline/acquisition.json"
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("synthetic", help="synthetic integration/isolation battery")
    sp.add_argument("--no-live", action="store_true", help="skip the paid live agent probe")
    sp.set_defaults(func=cmd_synthetic)

    sp = sub.add_parser("smoke", help="benchmark smoke cases (controller namespace)")
    sp.add_argument(
        "--agent",
        default="codex-c1",
        help="harness agent profile (codex-c1, opencode-c1, codex-b1p, ...)",
    )
    sp.add_argument("--prompt", default="vuln_c1", help="prompt name in PROMPTS")
    sp.add_argument(
        "--experiment-id",
        default=None,
        help="results namespace under --results-root (default: c1-smoke); "
        "use a separate id for non-Codex profile smokes",
    )
    sp.add_argument(
        "--task-id",
        default=None,
        help="run a single task instead of the GT-class selection",
    )
    sp.add_argument(
        "--image",
        default=None,
        help="container image recorded in attempt metadata (default: "
        "derived from the agent's IMAGE_SUFFIX)",
    )
    sp.add_argument(
        "--attempt-id",
        default="run_001",
        help="attempt dir name; retries use a NEW id (run_002, ...) — earlier "
        "attempts are never overwritten",
    )
    sp.add_argument(
        "--only",
        default=None,
        help="comma-separated class subset: exploitable,non_reachable,configuration",
    )
    sp.set_defaults(func=cmd_smoke)

    sp = sub.add_parser("manifest", help="freeze manifest.json after smoke")
    sp.set_defaults(func=cmd_manifest)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

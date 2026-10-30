#!/usr/bin/env python3
"""Task 6 entrypoint: structured Evidence Contract experiment.

Subcommands (plan §15):

  freeze-history  — phase 6.0: recompute the Task-5 RG/R6/UNION
                    blocked tables by attempt AND by unique case from
                    eval/task5/scoring/matrix.json + the saved T1 audit
                    trails, explain the 19 + 26 < 46 union anomaly,
                    re-verify the Task-5 artifact hashes, and write
                    eval/task6/freeze/task5-reference.json.
  smoke           — controller-run 3-class smoke for the new arms
                    (task6-smoke namespace; agent-assessment/2 status).
  manifest        — freeze eval/task6/experiment-manifest.json
                    (identities, contract pins, arm bindings, dataset pin).
  collect         — finalize one arm's attempts (immutable; writes
                    status.json + agent_assessment.json per attempt).
  score           — official scoring per arm → parsed.jsonl + safety
                    metrics, then the 4-projection join.
  replay          — V-P2 / V-T2: offline validator over the saved
                    answers (no model calls); writes <arm>'s v_ scoring
                    dir.
  report          — re-emit matrix.json + safety-report.md +
                    validator-report.md from existing scoring dirs.

Run inside the harness venv with the worktree on sys.path (plan §15):

  PY=/path/to/agent-ctl/.venv/bin/python
  "$PY" eval/vexbench_task6.py freeze-history \
      --harness-dir /path/to/agent-ctl --out eval/task6/freeze
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

from eval.c1 import manifest as c1_manifest  # noqa: E402
from eval.c1 import runner  # noqa: E402
from eval.task5 import collect as t5_collect  # noqa: E402
from eval.task6 import collect as collect_mod  # noqa: E402
from eval.task6 import freeze as freeze_mod  # noqa: E402
from eval.task6 import manifest as manifest_mod  # noqa: E402
from eval.task6 import protocol  # noqa: E402
from eval.task6 import replay as replay_mod  # noqa: E402
from eval.task6 import report as report_mod  # noqa: E402

DEFAULT_HARNESS = Path("/tmp/vexbench-agent-ctl")
DEFAULT_MODEL = "qwen3.6-35b"
DEFAULT_TIMEOUT = 900
DEFAULT_TASKS = DEFAULT_HARNESS / "benchmark/tasks/vex_bench.jsonl"
DEFAULT_REPOS = Path("/tmp/vexbench-baseline/repos")
DEFAULT_ACQ = Path("/tmp/vexbench-baseline/acquisition.json")
TASK6_ROOT = WORKTREE / "eval" / "task6"

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# shared helpers (task5 shape)
# ---------------------------------------------------------------------------


def _chdir_harness(harness_dir: Path) -> None:
    """Harness cwd (adapters resolve env/* relative to cwd) + sys.path."""
    if not (harness_dir / "env" / "opencode" / "opencode.env").exists():
        raise SystemExit(
            f"harness env file missing: "
            f"{harness_dir}/env/opencode/opencode.env")
    os.chdir(harness_dir)
    src = str(harness_dir / "src")
    if src not in sys.path:
        sys.path.insert(0, src)


def _harness_imports(harness_dir: Path) -> None:
    """Put the harness src on sys.path without chdir (collect/score)."""
    src = str(Path(harness_dir) / "src")
    if src not in sys.path:
        sys.path.insert(0, src)


def _load_prompt(harness_dir: Path, name: str) -> str:
    _harness_imports(harness_dir)
    from evaluate.prompts import PROMPTS  # noqa: E402

    if name not in PROMPTS:
        raise SystemExit(f"prompt {name!r} not registered in harness "
                         f"PROMPTS — apply eval/task6/harness patch first")
    return PROMPTS[name]


def _load_tasks(tasks_path: Path) -> list[dict]:
    return [
        json.loads(l)
        for l in Path(tasks_path).read_text(encoding="utf-8").splitlines()
        if l.strip()
    ]


def _meta_kwargs(harness_dir: Path, model: str, image: str,
                 prompt_name: str, prompt_hash12: str) -> dict:
    head = c1_manifest._git(harness_dir, "rev-parse", "--short", "HEAD")
    return {
        "model": model,
        "prompt_version": f"{prompt_name}-{prompt_hash12}",
        "harness_version": f"vexbench-agent-ctl@{head}",
        "tool_adapter_version": c1_manifest._tool_adapter_version(WORKTREE),
        "image": image,
    }


def _snapshot_hash(acq: dict, task: dict) -> str:
    owner_repo_sha = "/".join(
        task["repo_url"].rsplit("/", 2)[-2:] + [task["commit_sha"]])
    snap = acq.get("snapshots", {}).get(owner_repo_sha, {})
    return (snap.get("content_hash") if isinstance(snap, dict)
            else None) or "unknown"


def _snapshot_map(tasks, acq) -> dict:
    """task_id → acquisition content hash (the replay manifest
    fallback for attempts whose own meta lacks one)."""
    return {t["task_id"]: _snapshot_hash(acq, t) for t in tasks}


def _assert_prompt_clean(prompt_template: str, tasks: list[dict]) -> None:
    """Host-side check before ANY attempt runs: the rendered prompt may
    carry only the CVE id — task ids, commits, repo URLs and GT must not
    appear (plan §7, spec §4.4 prohibition list)."""
    assert "{cve_id}" in prompt_template, "template lost {cve_id}"
    assert prompt_template.count("{cve_id}") == 1
    for task in tasks:
        rendered = prompt_template.replace("{cve_id}", task["cve_id"])
        for forbidden in (
            task["task_id"], task["commit_sha"], task["repo_url"],
        ):
            if forbidden and forbidden in rendered:
                raise SystemExit(
                    f"rendered prompt leaks {forbidden!r} for "
                    f"{task['task_id']} — refusing to run")


# ---------------------------------------------------------------------------
# subcommands
# ---------------------------------------------------------------------------


def cmd_freeze_history(args) -> int:
    ref = freeze_mod.freeze_history(
        Path(args.out),
        harness_dir=Path(args.harness_dir) if args.harness_dir else None,
    )
    g = ref["gate_rules"]
    a = g["union_anomaly"]["recomputed"]
    print(json.dumps({
        "headline_confirmed": ref["headline"]["confirmed"],
        "false_safe": f"{ref['headline']['recomputed']['false_safe_attempts']}"
                      f"/{ref['headline']['recomputed']['exploitable_attempts']}",
        "correct_safe": f"{ref['headline']['recomputed']['correct_safe_attempts']}"
                        f"/{ref['headline']['recomputed']['safe_ground_truth_attempts']}",
        "union_correct_safe_lost": a["union_correct_safe_lost_attempts"],
        "published_union_was": 46,
        "anomaly": "19 + 26 < 46 impossible; recomputed union = 45 "
                   "(disjoint sets, no overlap)",
        "hashes_all_verified": ref["hashes"]["all_verified"],
        "out": args.out,
    }, indent=2))
    return 0


def _materialize_smoke_artifacts(run_dir: Path, agent, wall: float) -> None:
    """Like collect.materialize_controller_artifacts but keeps the real
    wall-clock in usage.json and is idempotent on identical content."""
    result_path = run_dir / agent.result_filename()
    if result_path.exists():
        raw = result_path.read_text(encoding="utf-8", errors="replace")
        t5_collect._write_once_same(
            run_dir / "raw_agent_output.txt",
            agent.extract_text(raw) + "\n")
        stats = agent.extract_stats(raw)
        usage = collect_mod.UsageStats(
            input_tokens=stats.input_tokens,
            cached_input_tokens=stats.cached_input_tokens,
            output_tokens=stats.output_tokens,
            reasoning_tokens=stats.reasoning_tokens,
            wall_seconds=round(wall, 3))
        t5_collect._write_once_same(
            run_dir / "usage.json",
            usage.model_dump_json(indent=2) + "\n")
    audit_src = run_dir / collect_mod.AUDIT_REL
    if audit_src.exists():
        audit_text = audit_src.read_text(encoding="utf-8")
        t5_collect._write_once_same(
            run_dir / "tool_calls.jsonl", audit_text)
        obs = []
        for line in audit_text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(rec.get("observation"), dict):
                obs.append(json.dumps(rec["observation"], sort_keys=True))
        t5_collect._write_once_same(
            run_dir / "observations.jsonl",
            "\n".join(obs) + ("\n" if obs else ""))
    export_report = run_dir / "artifacts" / "export-report.json"
    if export_report.exists():
        t5_collect._write_once_same(
            run_dir / "export-report.json",
            export_report.read_text(encoding="utf-8"))


def _smoke_attempt(results_root: Path, *, experiment_id: str, task: dict,
                   attempt_id: str, agent, prompt_template: str,
                   repos_dir: Path, timeout: int, meta_kwargs: dict,
                   official_parser) -> collect_mod.AttemptStatus:
    """One smoke attempt with Task-6 finalize semantics: the v2
    assessment contract is REQUIRED — a missing ``assessment`` object
    is schema-invalid, never relabeled absent."""
    task_id = task["task_id"]
    run_dir = Path(results_root) / experiment_id / task_id / attempt_id
    prompt = prompt_template.replace("{cve_id}", task["cve_id"])
    src_cwd = runner.task_snapshot_dir(repos_dir, task)

    t0 = time.monotonic()
    runner.run_attempt(
        run_dir, agent=agent, prompt=prompt, src_cwd=src_cwd,
        language=task.get("metadata", {}).get("language", "go"),
        timeout=timeout)
    wall = time.monotonic() - t0
    _materialize_smoke_artifacts(run_dir, agent, wall)

    usage = None
    usage_path = run_dir / "usage.json"
    if usage_path.exists():
        usage = collect_mod.UsageStats.model_validate_json(
            usage_path.read_text(encoding="utf-8"))
    meta = collect_mod.AttemptMeta(
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
        image=meta_kwargs.get("image"))
    status, asm = collect_mod.finalize_attempt_v2(
        run_dir, meta=meta, usage=usage,
        result_filename=agent.result_filename(),
        final_text_extractor=agent.extract_text,
        official_parser=official_parser,
        dry_run=True)
    if asm is not None:
        collect_mod.write_assessment_artifact_v2(run_dir, asm)
    collect_mod.write_status_artifact(run_dir, status)
    return status


def cmd_smoke(args) -> int:
    out_root = Path(args.out).resolve()  # before chdir
    harness_dir = Path(args.harness_dir).resolve()
    tasks_path = Path(args.tasks).resolve()
    repos_dir = Path(args.repos_dir).resolve()
    acq_path = Path(args.acquisition).resolve()

    tasks = _load_tasks(tasks_path)
    acq = json.loads(acq_path.read_text(encoding="utf-8"))
    picked = runner.smoke_selection(tasks)
    arms = [a.strip() for a in args.arms.split(",") if a.strip()]
    for arm in arms:
        if arm not in manifest_mod.ARMS:
            raise SystemExit(
                f"unknown arm {arm!r}; have {sorted(manifest_mod.ARMS)}")
    _chdir_harness(harness_dir)

    summary_path = out_root / "smoke-summary.json"
    summary: dict = (
        json.loads(summary_path.read_text())
        if summary_path.exists() else {})
    rc = 0
    for arm in arms:
        spec = manifest_mod.ARMS[arm]
        prompt_template = _load_prompt(harness_dir, spec["prompt"])
        _assert_prompt_clean(prompt_template, tasks)
        agent = runner.load_agent(spec["agent"], args.model)
        image = f"vex-bench-go-{spec['image_suffix']}:latest"
        ph = protocol.prompt_hash(prompt_template)
        expected = protocol.prompt_hash(
            protocol.build_prompt(spec["prompt"]))
        if ph != expected:
            raise SystemExit(
                f"prompt {spec['prompt']} hash drift: harness {ph} != "
                f"repo {expected} — regenerate eval/task6/prompts and "
                f"re-apply the harness patch")
        meta_base = _meta_kwargs(
            harness_dir, args.model, image, spec["prompt"], ph)

        for key, task in picked.items():
            rendered = prompt_template.replace("{cve_id}", task["cve_id"])
            if "{cve_id}" in rendered:
                raise SystemExit("unresolved {cve_id} placeholder")
            meta = dict(meta_base)
            meta["snapshot_hash"] = _snapshot_hash(acq, task)
            t0 = time.monotonic()
            skey = f"{arm}/{key}@{args.attempt_id}"
            try:
                status = _smoke_attempt(
                    out_root / arm,
                    experiment_id=manifest_mod.EXPERIMENT_SMOKE,
                    task=task,
                    attempt_id=args.attempt_id,
                    agent=agent,
                    prompt_template=prompt_template,
                    repos_dir=repos_dir,
                    timeout=args.timeout,
                    meta_kwargs=meta,
                    official_parser=collect_mod.load_official_parser(),
                )
                run_dir = (out_root / arm / manifest_mod.EXPERIMENT_SMOKE
                           / task["task_id"] / args.attempt_id)
                iso = collect_mod.audit_arm_attempt(
                    run_dir, expect_mcp=spec["mcp"])
                summary[skey] = {
                    "arm": arm,
                    "task_id": task["task_id"],
                    "attempt_id": args.attempt_id,
                    "status": status.model_dump(),
                    "isolation": iso,
                }
                if not iso["isolation_ok"]:
                    logger.error("%s: MCP isolation check FAILED: %s",
                                 skey, iso)
                    rc = 1
            except Exception as exc:  # keep the other cases running
                logging.exception("smoke %s failed hard", skey)
                summary[skey] = {
                    "arm": arm, "task_id": task["task_id"],
                    "attempt_id": args.attempt_id, "error": str(exc),
                }
                rc = 1
            print(f"[{skey}] done in {time.monotonic()-t0:.0f}s",
                  file=sys.stderr)

    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(
        json.dumps(summary, indent=2, default=str) + "\n", "utf-8")
    print(f"smoke summary -> {summary_path}")
    return rc


def cmd_manifest(args) -> int:
    m = manifest_mod.build_manifest(
        worktree=WORKTREE,
        harness_dir=Path(args.harness_dir),
        tasks_path=Path(args.tasks),
        repos_dir=Path(args.repos_dir),
        acquisition_path=Path(args.acquisition),
        results_root=Path(args.results_root),
        model=args.model,
        timeout=args.timeout,
        repeats=args.repeats,
        parallel=args.parallel,
        layout=args.layout,
        experiment_id=args.experiment_id,
        probe_docker=not args.no_docker_probe,
    )
    violations = manifest_mod.validate_manifest(m)
    dest = manifest_mod.write_manifest(m, Path(args.out))
    print(f"manifest -> {dest}")
    if m["limitations"]:
        print("limitations:", file=sys.stderr)
        for lim in m["limitations"]:
            print(f"  - {lim}", file=sys.stderr)
    if violations:
        for v in violations:
            print(f"MANIFEST VIOLATION: {v}", file=sys.stderr)
        return 1
    return 0


def cmd_collect(args) -> int:
    m = manifest_mod.load_manifest(Path(args.manifest))
    harness_dir = Path(m["harness"]["dir"])
    _harness_imports(harness_dir)
    problems = manifest_mod.verify_frozen_inputs(
        m,
        tasks_path=Path(m["dataset"]["tasks_file"]),
        acquisition_path=Path(m["dataset"]["acquisition_file"]),
    )
    if problems:
        for p in problems:
            print(f"FROZEN INPUT DRIFT: {p}", file=sys.stderr)
        return 1
    tasks = _load_tasks(Path(m["dataset"]["tasks_file"]))
    acq = json.loads(
        Path(m["dataset"]["acquisition_file"]).read_text(encoding="utf-8"))
    snapshots = {
        k: (v.get("content_hash") if isinstance(v, dict) else None)
        for k, v in acq.get("snapshots", {}).items()
    }
    spec = m["arms"][args.arm]
    arm_root = Path(spec["run_root"])
    summary = collect_mod.finalize_arm(
        arm_root,
        arm=args.arm,
        manifest=m,
        tasks=tasks,
        snapshots=snapshots,
        dry_run=args.dry_run,
    )
    collect_dir = Path(m["results_root"]) / "_collect"
    collect_dir.mkdir(parents=True, exist_ok=True)
    dest = collect_dir / f"{args.arm}.json"
    if dest.exists():
        prior = json.loads(dest.read_text())
        summary = {"prior": prior, "current": summary}
        dest = collect_dir / f"{args.arm}.latest.json"
    dest.write_text(json.dumps(summary, indent=2) + "\n", "utf-8")
    print(json.dumps(summary.get("counts", summary), indent=2))
    print(f"collect summary -> {dest}")
    return 0


def cmd_score(args) -> int:
    m = manifest_mod.load_manifest(Path(args.manifest))
    harness_dir = Path(m["harness"]["dir"])
    _harness_imports(harness_dir)
    from eval.c1 import report as c1_report  # noqa: E402

    tasks = c1_report.load_tasks(Path(m["dataset"]["tasks_file"]))
    out_root = Path(args.out)
    out_root.mkdir(parents=True, exist_ok=True)
    arms = [a.strip() for a in args.arms.split(",") if a.strip()]

    scored: dict[str, Path] = {}
    prev_rows = None
    prev_arm = None
    for arm in arms:
        spec = m["arms"].get(arm)
        if spec is None:
            print(f"unknown arm {arm!r}; have {sorted(m['arms'])}",
                  file=sys.stderr)
            return 1
        run_root = Path(spec["run_root"]) if spec.get("run_root") else None
        if run_root is None or not run_root.is_dir():
            print(f"[score] arm {arm}: run_root missing "
                  f"({run_root}) — skipped", file=sys.stderr)
            continue
        arm_out = out_root / arm
        try:
            c1_report.run_report(
                run_root=run_root,
                tasks=tasks,
                out_dir=arm_out,
                label=f"task6-{arm}",
                harness_dir=harness_dir,
                agent_name=spec["agent"],
                model=m["model"]["id"],
                prompt_hash=spec.get("prompt_sha256_12"),
                benchmark="vex_bench",
                repeats=spec.get("repeats",
                                m["attempt_policy"]["repeats"]),
                note=(f"task6 {spec['role']}; "
                      + (spec.get("note") or "")),
                baseline_rows=prev_rows,
                baseline_name=f"task6-{prev_arm}" if prev_arm else "base",
                check_parsed=None,
                official_metrics_path=None,
            )
        except c1_report.ReportError as exc:
            print(f"[score] arm {arm}: {exc}", file=sys.stderr)
            continue
        scored[arm] = arm_out
        prev_rows = report_mod._read_jsonl(arm_out / "parsed.jsonl")
        prev_arm = arm

    artifacts = report_mod.write_scoring_artifacts(m, scored, out_root)
    print(json.dumps(
        {k: v for k, v in artifacts.items() if k != "summaries"},
        indent=2))
    return 0


def cmd_replay(args) -> int:
    """V-P2 / V-T2: replay the saved answers of the raw arms through
    the offline validator (no model calls). Requires ``score`` to have
    produced <scoring>/<arm>/parsed.jsonl first."""
    m = manifest_mod.load_manifest(Path(args.manifest))
    tasks = _load_tasks(Path(m["dataset"]["tasks_file"]))
    acq = json.loads(
        Path(m["dataset"]["acquisition_file"]).read_text(encoding="utf-8"))
    snap_by_task = _snapshot_map(tasks, acq)
    arms = [a.strip() for a in args.arms.split(",") if a.strip()]
    for arm in arms:
        if arm not in manifest_mod.ARMS:
            raise SystemExit(
                f"unknown arm {arm!r}; have {sorted(manifest_mod.ARMS)}")
    # task_id → product snapshot dir (only when --repos-dir given;
    # the file index binds src:/file: refs — absent → unverifiable)
    dir_by_task = None
    if args.repos_dir:
        repos_dir = Path(args.repos_dir)
        dir_by_task = {
            t["task_id"]: runner.task_snapshot_dir(repos_dir, t)
            for t in tasks
        }
    out = replay_mod.replay_arms(
        manifest=m,
        arms=arms,
        scoring_root=Path(args.scoring),
        advisories_dir=(
            Path(args.advisories_dir) if args.advisories_dir else None),
        snapshot_hash_by_task=snap_by_task,
        snapshot_dir_by_task=dir_by_task,
    )
    for name, res in out.items():
        if "error" in res:
            print(f"[replay] {name}: {res['error']}", file=sys.stderr)
        else:
            print(f"[replay] {name}: {res['n_attempts']} attempts, "
                  f"{res['n_blocked']} blocked "
                  f"({res['decision_counts']})")
    # re-join so the reports reflect the v-projections immediately
    scored = {
        proj: Path(args.scoring) / proj
        for proj in report_mod.PROJECTION_ORDER
        if (Path(args.scoring) / proj / "parsed.jsonl").is_file()
    }
    artifacts = report_mod.write_scoring_artifacts(
        m, scored, Path(args.scoring))
    print(f"scoring artifacts -> {artifacts['matrix']}")
    return 0


def cmd_report(args) -> int:
    """Re-emit the 4-projection join from existing scoring dirs —
    never re-scores, never re-runs the validator."""
    m = manifest_mod.load_manifest(Path(args.manifest))
    scoring_root = Path(args.scoring)
    scored = {
        proj: scoring_root / proj
        for proj in report_mod.PROJECTION_ORDER
        if (scoring_root / proj / "parsed.jsonl").is_file()
    }
    if not scored:
        print(f"no parsed.jsonl under {scoring_root}/<projection>/ — "
              f"run score (and replay for v_ arms) first",
              file=sys.stderr)
        return 1
    artifacts = report_mod.write_scoring_artifacts(m, scored, scoring_root)
    print(json.dumps(
        {k: v for k, v in artifacts.items() if k != "summaries"},
        indent=2))
    return 0


# ---------------------------------------------------------------------------


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    p = argparse.ArgumentParser(description=__doc__)
    # Common flags live on a parent parser so the plan-§15 order
    # ``vexbench_task6.py <cmd> --flag value`` works verbatim.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--harness-dir", default=str(DEFAULT_HARNESS))
    common.add_argument("--tasks", default=str(DEFAULT_TASKS))
    common.add_argument("--repos-dir", default=str(DEFAULT_REPOS))
    common.add_argument("--acquisition", default=str(DEFAULT_ACQ))
    common.add_argument("--model", default=DEFAULT_MODEL)
    common.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser(
        "freeze-history", parents=[common],
        help="phase 6.0: re-verify Task-5 scorer + freeze reference")
    sp.add_argument("--out", default=str(TASK6_ROOT / "freeze"))
    sp.set_defaults(func=cmd_freeze_history)

    sp = sub.add_parser(
        "smoke", parents=[common],
        help="3-class smoke for the selected arms "
             "(controller-run, task6-smoke namespace)")
    sp.add_argument("--arms", default="p2,t2")
    sp.add_argument("--out", default=str(TASK6_ROOT / "results" / "smoke"))
    sp.add_argument("--attempt-id", default="run_001")
    sp.set_defaults(func=cmd_smoke)

    sp = sub.add_parser("manifest", parents=[common],
                        help="freeze the experiment manifest")
    sp.add_argument("--out", default=str(
        TASK6_ROOT / "experiment-manifest.json"))
    sp.add_argument("--results-root", default=str(TASK6_ROOT / "results"))
    sp.add_argument("--repeats", type=int, default=3)
    sp.add_argument("--parallel", type=int, default=1)
    sp.add_argument("--layout", choices=("harness", "controller"),
                    default="harness")
    sp.add_argument("--experiment-id",
                    default=manifest_mod.EXPERIMENT_ID)
    sp.add_argument("--no-docker-probe", action="store_true",
                    help="skip docker image/toolchain/catalog probes "
                         "(fields stay null with a limitation)")
    sp.set_defaults(func=cmd_manifest)

    sp = sub.add_parser(
        "collect", parents=[common],
        help="finalize one arm's attempts (immutable; v2 contract)")
    sp.add_argument("--manifest", required=True)
    sp.add_argument("--arm", required=True,
                    choices=sorted(manifest_mod.ARMS))
    sp.add_argument("--dry-run", action="store_true")
    sp.set_defaults(func=cmd_collect)

    sp = sub.add_parser("score", parents=[common],
                        help="score arms + join matrix/report")
    sp.add_argument("--manifest", required=True)
    sp.add_argument("--arms", default="p2,t2")
    sp.add_argument("--out", default=str(TASK6_ROOT / "scoring"))
    sp.set_defaults(func=cmd_score)

    sp = sub.add_parser(
        "replay", parents=[common],
        help="V-P2/V-T2: offline validator replay over saved answers")
    sp.add_argument("--manifest", required=True)
    sp.add_argument("--arms", default="p2,t2",
                    help="raw arms to replay (v_ projections emitted)")
    sp.add_argument("--scoring", default=str(TASK6_ROOT / "scoring"),
                    help="scoring root holding <arm>/parsed.jsonl; "
                         "v_ dirs are written alongside")
    sp.add_argument("--advisories-dir", default=None,
                    help="optional OSV advisory library dir (fallback "
                         "when the attempt audit lacks a fetched "
                         "advisory record)")
    # --repos-dir comes from the shared parent (product snapshot root for
    # the C1 file index); absent/unreadable → src/file refs stay
    # unverifiable, never an automatic pass.
    sp.set_defaults(func=cmd_replay)

    sp = sub.add_parser(
        "report", parents=[common],
        help="re-emit the 4-projection join from existing scoring dirs")
    sp.add_argument("--manifest", required=True)
    sp.add_argument("--scoring", default=str(TASK6_ROOT / "scoring"))
    sp.set_defaults(func=cmd_report)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

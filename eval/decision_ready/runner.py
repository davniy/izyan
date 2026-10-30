#!/usr/bin/env python3
"""Runner for the R6 decision-ready validation arms.

Plan: docs/dev/plans/2026-10-15-02-decision-ready-triage-plan.md, Task 7.

For each manifest case this extracts historical playback or executes current
deterministic research. Neither starts a model or container. Live R6 launching
is retired; parse_run, artifact indexing and summaries remain offline producers.

Input classification is never silent: a missing snapshot is NO_SNAPSHOT, a
missing advisory file is NO_ADVISORY (a data-cap finding), a manifest row
marked not to run is NOT_RUN, and a requested-but-absent replay directory is
recorded as retained_inputs.decision_run_replay="missing" (NO_REPLAY) with the
case still probed fail-closed via deterministic_only.

Outputs (all inside --output-dir; absolute paths stay external):

  cases/<case_id>-*/run/     fresh raw run or historical wrapper (external only)
  runs.jsonl                one record per case: outcome class, termination,
                            proposed disposition, model-call/cost accounting,
                            falsification checks (paths redacted)
  artifact-index.json       sha256(decision-artifact.json) -> artifact record,
                            the join key for metrics.py review events
  summary.json              per-arm/category census + falsification counters
  summary.md                same, human-readable

The manifest schema is `decision-ready-manifest/1` — see README.md. Nothing in
the output is committed; this directory ships only sanitized aggregates.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
import tempfile

MANIFEST_SCHEMA = "decision-ready-manifest/1"
SUMMARY_SCHEMA = "decision-ready-run-summary/1"

LABEL_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

# research-run-manifest/1 `decision_ready` members are the single source of
# truth for the run classification; we read them, never the agent prose.
OUTCOME_CATEGORY = {
    "CLOSE_NOT_AFFECTED": "decision_ready_code_grounded",
    "CLOSE_NO_EXPLOIT_PATH": "decision_ready_code_grounded",
    "ACCEPT_ENVIRONMENTAL_MITIGATION": "environmental_mitigation_branch",
    "KEEP_OPEN_FOR_REMEDIATION": "KEEP_OPEN_FOR_REMEDIATION",
    "HOLD_UNKNOWN": "HOLD_UNKNOWN",
}
SAFE_PROPOSALS = {"CLOSE_NOT_AFFECTED", "CLOSE_NO_EXPLOIT_PATH", "ACCEPT_ENVIRONMENTAL_MITIGATION"}
EXPLOITABLE_TRUTH = {"exploitable"}
B_UNKNOWN_ID = "B-UNKNOWN"

DEFAULT_CASE_TIMEOUT_S = 1500  # 25m, matching the recorded corporate manifest

IZYAN_BIN_ENV = "IZYAN_BIN"


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _is_dir(p) -> bool:
    try:
        return Path(p).is_dir()
    except (OSError, TypeError):
        return False


def _is_file(p) -> bool:
    try:
        return Path(p).is_file()
    except (OSError, TypeError):
        return False


def _load_json(path: Path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _redact(path_str: str, keep: Path) -> str:
    """Strip external absolute paths from a recorded command line."""
    if not path_str:
        return path_str
    p = Path(path_str)
    if not p.is_absolute():
        return path_str
    try:
        p.relative_to(repo_root())
        return path_str  # repo-relative paths are public
    except ValueError:
        pass
    try:
        p.relative_to(keep)
        return "<out>" + os.sep + str(p.relative_to(keep))
    except ValueError:
        return "<external>"


def redact_argv(argv, out_dir: Path):
    return [_redact(a, out_dir) for a in argv]


# ---------------------------------------------------------------- manifest --


def load_manifest(path: Path):
    data = _load_json(path)
    if isinstance(data, list):
        return data
    if not isinstance(data, dict):
        raise ValueError(f"{path}: manifest must be an object or an array")
    cases = data.get("cases")
    if not isinstance(cases, list):
        raise ValueError(f"{path}: manifest needs a 'cases' array")
    return cases


def case_label(case) -> str:
    cid = str(case.get("case") or case.get("case_id") or "")
    if not LABEL_RE.match(cid):
        raise ValueError(f"case id {cid!r} is not a sanitized [A-Za-z0-9._-]{{1,64}} token")
    return cid


def case_cve(case) -> str:
    cves = case.get("cve_ids") or case.get("cves") or []
    if isinstance(cves, str):
        cves = [cves]
    cve = case.get("cve") or (cves[0] if cves else "")
    if not cve:
        raise ValueError("case needs 'cve' or non-empty 'cve_ids'")
    return str(cve)


def resolve_snapshot(case, work: Path):
    """Return (snapshot_root, how, problems).

    how: "saved_dir" | "materialized" | "missing"
    Materialization uses `git archive <git_ref>` into work/materialized/<case>/
    and verifies the git ref resolves to the pinned commit — the manifest's
    verify_snapshot recipe. A directory named 'snapshot_root' wins first.
    """
    snap = case.get("snapshot") or {}
    if isinstance(snap, str):
        snap = {"root": snap}
    root = case.get("snapshot_root") or snap.get("root") or snap.get("path")
    if root and _is_dir(root):
        return Path(root), "saved_dir", []

    repo, ref, want_commit = snap.get("repo"), snap.get("git_ref"), snap.get("git_commit")
    if not (repo and ref):
        return None, "missing", ["no snapshot_root and no snapshot.repo+git_ref"]
    if not _is_dir(repo):
        return None, "missing", [f"snapshot.repo {repo!r} does not exist locally"]
    dest = work / "materialized" / (case_label(case) + "-" + re.sub(r"[^A-Za-z0-9._-]", "_", str(ref)))
    if _is_dir(dest) and any(dest.iterdir()):
        return dest, "materialized", []
    dest.mkdir(parents=True, exist_ok=True)
    try:
        resolved = subprocess.run(
            ["git", "-C", repo, "rev-parse", str(ref)],
            capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        return None, "missing", [f"git rev-parse {ref}: {exc}"]
    if resolved.returncode != 0:
        return None, "missing", [f"git rev-parse {ref} failed: {resolved.stderr.strip()[:200]}"]
    commit = resolved.stdout.strip()
    if want_commit and commit != want_commit:
        return None, "missing", [
            f"git ref {ref} resolves to {commit}, manifest pins {want_commit} — refusing to run an unpinned snapshot"]
    try:
        arch = subprocess.run(
            ["git", "-C", repo, "archive", commit],
            capture_output=True, timeout=600)
        if arch.returncode != 0:
            return None, "missing", [f"git archive {ref}: {arch.stderr.decode(errors='replace')[:200]}"]
        untar = subprocess.run(
            ["tar", "-x", "-C", str(dest)], input=arch.stdout,
            capture_output=True, timeout=600)
        if untar.returncode != 0:
            return None, "missing", [f"tar extract: {untar.stderr.decode(errors='replace')[:200]}"]
    except (OSError, subprocess.SubprocessError) as exc:
        return None, "missing", [f"snapshot materialization failed: {exc}"]
    return dest, "materialized", []


def resolve_advisory(case):
    """Return (advisory_file, advisory_dir, problems)."""
    adv = case.get("advisory") or {}
    if isinstance(adv, str):
        adv = {"file": adv}
    f = case.get("advisory_file") or adv.get("file")
    d = case.get("advisory_dir") or adv.get("dir")
    problems = []
    if f:
        p = Path(f)
        if not p.is_absolute():
            p = repo_root() / p
        if not _is_file(p):
            problems.append(f"advisory file {f!r} missing")
        elif adv.get("raw_sha256"):
            got = sha256_file(p)
            if got != adv["raw_sha256"]:
                problems.append(f"advisory raw_sha256 mismatch: file hashes {got}, manifest pins {adv['raw_sha256']}")
        return str(p), None, problems
    if d:
        pd = Path(d)
        if not pd.is_absolute():
            pd = repo_root() / pd
        if not _is_dir(pd):
            problems.append(f"advisory dir {d!r} missing")
        return None, str(pd), problems
    return None, None, ["no advisory_file or advisory_dir in manifest case"]


# ------------------------------------------------------------------- runs ---


def izyan_argv(opts, case, snapshot_root, advisory_file, advisory_dir, case_out: Path, run_mode: str):
    """Build current deterministic research or authority-neutral historical playback."""
    if os.path.basename(opts.izyan_bin) == "go":
        argv = [opts.izyan_bin, "run", "./cmd/izyan"]
    else:
        argv = [opts.izyan_bin]
    if run_mode == "live":
        raise ValueError("live R6 launching is retired")
    if run_mode == "replay":
        return argv + ["eval", "research-replay", "--run", str(case["decision_run_dir"]),
                       "--out", str(case_out)]
    argv += ["research",
             "--snapshot", str(snapshot_root),
             "--cve", case_cve(case),
             "--output-dir", str(case_out)]
    if advisory_file:
        argv += ["--advisory-file", advisory_file]
    else:
        argv += ["--advisory-dir", advisory_dir]
    snap = case.get("snapshot") or {}
    ext_sha = case.get("external_commit_sha") or snap.get("external_commit_sha") or snap.get("git_ref")
    if ext_sha:
        argv += ["--external-commit-sha", str(ext_sha)]
    timeout_s = int(case.get("overall_timeout_s")
                    or (case.get("research_set") or {}).get("overall_timeout_s")
                    or opts.timeout_s)
    argv += ["--overall-timeout", f"{timeout_s}s"]
    for opt in ("modcache", "govulndb", "goos", "goarch", "build_tags", "analysis_go"):
        v = case.get(opt) or (case.get("research_set") or {}).get(opt)
        if v:
            values = v if opt == "build_tags" and isinstance(v, list) else [v]
            for value in values:
                argv += ["--" + opt.replace("_", "-"), str(value)]
    return argv


def _observation_ids(run_dir: Path):
    ids = set()
    for name in ("verification-observations.jsonl", "observations.jsonl"):
        p = run_dir / name
        if not p.is_file():
            continue
        with open(p, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                obs = rec.get("observation") if isinstance(rec, dict) else None
                if isinstance(obs, dict) and obs.get("id"):
                    ids.add(obs["id"])
    return ids


def _turn_usage(run_dir: Path, turn):
    """Read provider-reported usage for one retained flow turn, if present."""
    meta = turn.get("manifest") or {}
    result_rel = meta.get("result_path") or ""
    usage = {"model_call": False, "tokens": {}, "cost": None}
    for cand in (run_dir / "agent" / (turn.get("attempt_id") or "") / "result.json",
                 Path(result_rel) if result_rel else None):
        if cand and cand.is_file():
            try:
                info = (_load_json(cand).get("info") or {})
            except (OSError, json.JSONDecodeError):
                continue
            usage["model_call"] = True
            tok = info.get("tokens") or {}
            usage["tokens"] = {k: tok.get(k, 0) for k in ("input", "output", "reasoning")}
            if isinstance(info.get("cost"), (int, float)):
                usage["cost"] = info["cost"]
            break
    return usage


def report_decision(report):
    """Explicit historical /2–/4 and current /5 projection adapters."""
    schema = report.get("schema")
    if schema in ("research-report/2", "research-report/3", "research-report/4"):
        return report["decision"]
    if schema == "research-report/5":
        if report.get("decision_artifact") is not None:
            raise ValueError("current /5 must not acquire historical human authority")
        return report["decision"]
    raise ValueError(f"unsupported report schema {schema!r}")


def validate_run_identity(report, manifest, argv):
    """Reject foreign output before consuming its decision or artifact."""
    if not isinstance(report, dict) or not isinstance(manifest, dict):
        raise ValueError("report and manifest must be objects")
    run_id = (report.get("run") or {}).get("run_id")
    if not run_id or manifest.get("run_id") != run_id:
        raise ValueError("report/manifest run IDs are missing or mismatched")
    inputs = report.get("input") or {}
    for section, keys in (("snapshot", ("path", "external_commit_sha", "content_hash")),
                          ("advisory", ("requested_id", "source_path", "raw_sha256", "canonical_sha256"))):
        for key in keys:
            actual = (inputs.get(section) or {}).get(key)
            recorded = (manifest.get(section) or {}).get(key)
            if section == "snapshot" and key == "external_commit_sha":
                # Go report uses null; its manifest uses "" for absent optional commit.
                actual = None if actual == "" else actual
                recorded = None if recorded == "" else recorded
            if actual != recorded:
                raise ValueError(f"report/manifest {section}.{key} mismatch")
    for flag, section, key in (("--snapshot", "snapshot", "path"),
                               ("--cve", "advisory", "requested_id"),
                               ("--advisory-file", "advisory", "source_path"),
                               ("--external-commit-sha", "snapshot", "external_commit_sha")):
        if flag in argv:
            want = argv[argv.index(flag) + 1]
            got = (inputs.get(section) or {}).get(key)
            if got != want:
                raise ValueError(f"requested {section}.{key} mismatch: {got!r} != {want!r}")
    if "--advisory-dir" in argv:
        root = Path(argv[argv.index("--advisory-dir") + 1]).resolve()
        source = (inputs.get("advisory") or {}).get("source_path")
        if not source or Path(source).resolve().parent != root:
            raise ValueError("requested advisory directory mismatch")


def parse_run(case_id, case, run_dir: Path, argv, redacted, rc, elapsed, timed_out, stdout_tail):
    """Classify one executed run into a case record. No output = fail closed."""
    rec = {
        "case_id": case_id,
        "status": "ERROR",
        "category": "error",
        "execution": None,
        "elapsed_s": round(elapsed, 2),
        "command": redacted,
        "exit_code": rc,
        "timed_out": timed_out,
        "stdout_tail": stdout_tail[-8:],
        "model_calls": 0,
        "turns_count": 0,
        "turns": [],
        "checks": [],
        "false_safe": False,
    }
    rec["execution"] = "replay" if "research-replay" in argv else "deterministic_only"

    if rec["execution"] == "replay" and rc == 0 and not timed_out:
        try:
            wrapper = _load_json(run_dir / "historical-replay.json")
            if wrapper.get("historical_only") is not True or wrapper.get("current_admission") is not False:
                raise ValueError("historical playback authority markers missing")
            run_dir = run_dir / "original"
        except (OSError, ValueError, AttributeError) as exc:
            rec["checks"].append(str(exc))
            return rec

    if timed_out:
        rec["category"] = "error"
        rec["checks"].append("command exceeded the configured overall timeout")
        return rec

    report_path = run_dir / "report.json"
    manifest_path = run_dir / "run-manifest.json"
    if rc != 0 or not report_path.is_file():
        rec["category"] = "error"
        if not manifest_path.is_file():
            rec["checks"].append("no run-manifest.json — the run aborted before emission")
        return rec

    try:
        report = _load_json(report_path)
    except (OSError, json.JSONDecodeError) as exc:
        rec["category"] = "invalid_format"
        rec["checks"].append(f"report.json does not decode: {exc}")
        return rec
    try:
        manifest = _load_json(manifest_path)
        validate_run_identity(report, manifest, argv)
        report_decision(report)
        if rec["execution"] == "replay":
            source = Path(argv[argv.index("--run") + 1])
            original = _load_json(source / "run-manifest.json")
            if manifest != original:
                raise ValueError("historical playback manifest differs from requested source")
            if (source / "report.json").read_bytes() != report_path.read_bytes():
                raise ValueError("historical report differs from requested source")
            if case.get("cve") or case.get("cve_ids") or case.get("cves"):
                if (report.get("input", {}).get("advisory") or {}).get("requested_id") != case_cve(case):
                    raise ValueError("historical source does not match requested advisory identity")
    except (OSError, ValueError, TypeError, KeyError) as exc:
        rec["category"] = "invalid_format"
        rec["checks"].append(str(exc))
        return rec
    rec["status"] = "RAN"
    rec["report_schema"] = report.get("schema")

    disp_block = report.get("disposition") or {}
    rec["auto_close"] = disp_block.get("auto_close")
    if rec["auto_close"] is not False:
        rec["checks"].append(f"disposition.auto_close is {rec['auto_close']!r}, not false")

    # Manifest identity was checked before consuming any metric input.
    dr = manifest.get("decision_ready") or {}
    rec["flow_termination"] = dr.get("termination")
    rec["flow_reason"] = dr.get("reason")
    rec["flow_ready"] = bool(dr.get("ready"))

    turns = dr.get("turns") or []
    turn_rows = []
    model_calls = 0
    for t in turns:
        row = {"role": t.get("role"), "status": t.get("status")}
        if t.get("error"):
            row["error"] = t["error"][:200]
        usage = _turn_usage(run_dir, t)
        if rec["execution"] == "replay":
            row["historical_model_call"] = usage["model_call"]
            usage["model_call"] = False
        row["model_call"] = usage["model_call"]
        if usage["model_call"]:
            model_calls += 1
        if usage["tokens"]:
            row["tokens"] = usage["tokens"]
        if usage["cost"] is not None:
            row["cost"] = usage["cost"]
        turn_rows.append(row)
    rec["turns"] = turn_rows
    rec["turns_count"] = len(turn_rows)
    rec["model_calls"] = model_calls
    if rec["execution"] in ("replay", "deterministic_only") and model_calls > 0:
        rec["checks"].append(
            f"{rec['execution']} run recorded {model_calls} model calls — replay/det must never call a model")

    artifact_path = run_dir / "decision-artifact.json"
    artifact = None
    if artifact_path.is_file():
        try:
            artifact = _load_json(artifact_path)
            rec["artifact_digest"] = "sha256:" + sha256_file(artifact_path)
        except (OSError, json.JSONDecodeError) as exc:
            rec["checks"].append(f"decision-artifact.json does not decode: {exc}")
            rec["category"] = "invalid_format"
            return rec
    elif report.get("decision_artifact"):
        artifact = report["decision_artifact"]

    if rec["report_schema"] == "research-report/5":
        if artifact is not None:
            rec["checks"].append("current /5 acquired a historical decision artifact")
            rec["category"] = "invalid_format"
        else:
            rec["category"] = "current_deterministic"
        rec["decision_ready"] = False
        rec["machine_decision"] = report_decision(report)
    elif artifact is None:
        rec["proposed_disposition"] = "HOLD_UNKNOWN"
        rec["category"] = "HOLD_UNKNOWN"
        rec["decision_ready"] = False
        if rec["report_schema"] != "research-report/2":
            rec["checks"].append("no decision-artifact.json emitted — HOLD_UNKNOWN")
    else:
        rec["proposed_disposition"] = artifact.get("proposed_disposition")
        branches = artifact.get("branches") or []
        rec["branch_count"] = len(branches)
        rec["branch_statuses"] = {b.get("id"): b.get("status") for b in branches if isinstance(b, dict)}
        ha = artifact.get("human_action") or {}
        rec["env_questions_declared"] = len(ha.get("environment_question_refs") or [])
        rec["mandatory_facts_declared"] = len(ha.get("mandatory_fact_refs") or [])
        rec["artifact_env_question_ids"] = list(ha.get("environment_question_refs") or [])
        rec["artifact_mandatory_fact_ids"] = list(ha.get("mandatory_fact_refs") or [])
        rec["decision_ready"] = bool(
            rec["flow_ready"] and artifact.get("proposed_disposition") != "HOLD_UNKNOWN")

        # ---- contract re-checks (the Go validator already enforces; we
        # measure, never re-judge, and report violations as falsification)
        if rec["env_questions_declared"] > 2:
            rec["checks"].append("artifact declares >2 environment questions")
        if rec["mandatory_facts_declared"] > 7:
            rec["checks"].append("artifact declares >7 mandatory facts")
        unknown = [b for b in branches
                   if isinstance(b, dict) and b.get("id") == B_UNKNOWN_ID]
        if not unknown:
            rec["checks"].append("artifact lacks the explicit B-UNKNOWN branch")

        # unresolved evidence references: obs: refs in artifact facts must
        # resolve to the persisted observation ledgers
        obs_ids = _observation_ids(run_dir)
        want = set()
        for f in artifact.get("shared_facts") or []:
            for r in (f.get("observation_refs") or []) if isinstance(f, dict) else []:
                if isinstance(r, str) and r.startswith("obs:"):
                    want.add(r[len("obs:"):])
        unresolved = sorted(want - obs_ids)
        if unresolved:
            rec["checks"].append(
                f"unresolved evidence refs: {', '.join(unresolved[:8])}")
        rec["unresolved_evidence_refs"] = len(unresolved)

        disp = rec["proposed_disposition"]
        if disp in OUTCOME_CATEGORY:
            rec["category"] = OUTCOME_CATEGORY[disp]
        else:
            rec["category"] = "invalid_format"
            rec["checks"].append(f"proposed_disposition {disp!r} is not an R6 disposition")

        # verified-negative subset of the code-grounded class
        dec = report.get("decision") or {}
        if (disp in ("CLOSE_NOT_AFFECTED", "CLOSE_NO_EXPLOIT_PATH")
                and rec["decision_ready"]
                and dec.get("coverage") == "COMPLETE"
                and dec.get("verdict") in ("NOT_AFFECTED", "NO_EXPLOIT_PATH_FOUND")):
            rec["category"] = "terminal_deterministic_verified_negative"
            rec["verified_negative_verdict"] = dec.get("verdict")

        # ---- falsification: false-safe on declared-exploitable controls
        truth = case.get("ground_truth_class") or case.get("expected_class")
        if (isinstance(truth, str) and truth.lower() in EXPLOITABLE_TRUTH
                and disp in SAFE_PROPOSALS and rec["decision_ready"]):
            rec["false_safe"] = True
            rec["checks"].append(
                f"FALSE-SAFE: control declared {truth} received accepted-safe proposal {disp}")

        # controls arm falsifications (role-driven, per the plan)
        role = case.get("control_role")
        if role == "positive" and disp in ("CLOSE_NOT_AFFECTED", "CLOSE_NO_EXPLOIT_PATH"):
            rec["checks"].append("FALSIFICATION: positive control received a close disposition")
        if role == "unresolved" and any(
                s == "COMPLETE" for s in rec.get("branch_statuses", {}).values()):
            rec["checks"].append("FALSIFICATION: unresolved control received a complete branch")
    return rec


def build_artifact_record(rec):
    """The artifact-index row metrics.py joins review events to."""
    return {
        "artifact_digest": rec.get("artifact_digest"),
        "case_id": rec["case_id"],
        "proposed_disposition": rec.get("proposed_disposition"),
        "decision_ready": rec.get("decision_ready", False),
        "branch_count": rec.get("branch_count", 0),
        "branch_statuses": rec.get("branch_statuses", {}),
        "env_question_ids": rec.get("artifact_env_question_ids", []),
        "mandatory_fact_ids": rec.get("artifact_mandatory_fact_ids", []),
        "flow_termination": rec.get("flow_termination"),
    }


def _summary(records):
    by_status = {}
    by_category = {}
    per_case = []
    no_replay = []
    false_safe = []
    check_violations = []
    for r in records:
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1
        if r.get("category"):
            by_category[r["category"]] = by_category.get(r["category"], 0) + 1
        if r.get("capability_status") == "NO_REPLAY":
            no_replay.append(r["case_id"])
        if r.get("false_safe"):
            false_safe.append(r["case_id"])
        if r.get("checks"):
            check_violations.append({"case_id": r["case_id"], "checks": r["checks"]})
        per_case.append({
            "case_id": r["case_id"],
            "status": r["status"],
            "category": r.get("category"),
            "execution": r.get("execution"),
            "capability_status": r.get("capability_status"),
            "flow_termination": r.get("flow_termination"),
            "proposed_disposition": r.get("proposed_disposition"),
            "decision_ready": r.get("decision_ready", False),
            "model_calls": r.get("model_calls", 0),
            "elapsed_s": r.get("elapsed_s"),
            "auto_close": r.get("auto_close"),
        })
    return {
        "schema": SUMMARY_SCHEMA,
        "cases_total": len(records),
        "by_status": by_status,
        "by_category": by_category,
        "no_replay_cases": no_replay,
        "false_safe_cases": false_safe,
        "false_safe_count": len(false_safe),
        "check_violations": check_violations,
        "per_case": per_case,
        "stop": bool(false_safe),
    }


def _summary_md(summary, records):
    lines = [
        "# R6 decision-ready validation arm — summary",
        "",
        f"cases total: {summary['cases_total']}",
        "",
        "## Status",
    ]
    for k in sorted(summary["by_status"]):
        lines.append(f"- {k}: {summary['by_status'][k]}")
    lines += ["", "## Outcome categories"]
    for k in sorted(summary["by_category"]):
        lines.append(f"- {k}: {summary['by_category'][k]}")
    if summary["no_replay_cases"]:
        lines += ["", "## NO_REPLAY (no persisted decision-run to replay)",
                  ", ".join(summary["no_replay_cases"])]
    if summary["check_violations"]:
        lines += ["", "## Check violations / falsifications"]
        for v in summary["check_violations"]:
            for c in v["checks"]:
                lines.append(f"- {v['case_id']}: {c}")
    lines += ["",
              "## Per case",
              "| case | status | category | termination | disposition | ready | model calls |",
              "|---|---|---|---|---|---|---|"]
    for r in summary["per_case"]:
        lines.append("| {case_id} | {status} | {category} | {flow_termination} | "
                     "{proposed_disposition} | {decision_ready} | {model_calls} |".format(**{
                         **{k: ("" if r.get(k) is None else r[k]) for k in r}}))
    lines.append("")
    return "\n".join(lines)


def run(opts) -> int:
    out_dir = Path(opts.output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    cases_dir = out_dir / "cases"
    cases_dir.mkdir(exist_ok=True)

    try:
        cases = load_manifest(Path(opts.manifest))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"runner: manifest error: {exc}", file=sys.stderr)
        return 2

    only = set(opts.case.split(",")) if opts.case else None
    records = []
    artifact_index = {"schema": "decision-ready-artifact-index/1", "artifacts": {}}

    for case in cases:
        try:
            cid = case_label(case)
        except ValueError as exc:
            print(f"runner: {exc}", file=sys.stderr)
            return 2
        if only and cid not in only:
            continue

        rec = {"case_id": cid, "checks": [], "model_calls": 0, "turns": [],
               "turns_count": 0, "false_safe": False}
        case_out = cases_dir / cid

        # ---- inputs (never silently dropped)
        replay_dir = case.get("decision_run_dir") or case.get("retained_turn_dir")
        if replay_dir:
            case = dict(case, decision_run_dir=replay_dir)
        replay_ok = bool(replay_dir and _is_dir(replay_dir)
                         and _is_file(Path(replay_dir) / "report.json")
                         and _is_file(Path(replay_dir) / "run-manifest.json"))
        if replay_ok:
            snap_root, snap_how, snap_problems = None, "historical_only", []
            adv_file, adv_dir, adv_problems = None, None, []
        else:
            snap_root, snap_how, snap_problems = resolve_snapshot(case, out_dir)
            adv_file, adv_dir, adv_problems = resolve_advisory(case)
        legacy_dir = case.get("retained_turn_dir")
        legacy_ok = bool(legacy_dir and _is_file(Path(legacy_dir) / "report.json"))
        rec["retained_inputs"] = {
            "snapshot": snap_how,
            "advisory": "ok" if not adv_problems else "missing",
            "decision_run_replay": ("present" if replay_ok
                                    else ("missing" if replay_dir else "none_declared")),
            "legacy_turn": ("present" if legacy_ok else ("missing" if legacy_dir else "none_declared")),
        }
        rec["expected_class"] = case.get("expected_class") or case.get("ground_truth_class")
        rec["control_role"] = case.get("control_role")

        if (snap_problems or adv_problems) and not replay_ok:
            rec["status"] = "NO_SNAPSHOT" if snap_problems else "NO_ADVISORY"
            rec["category"] = "data_cap"
            rec["checks"] = snap_problems + adv_problems
            records.append(rec)
            continue
        if case.get("skip"):
            rec["status"] = "NOT_RUN"
            rec["category"] = "not_run"
            rec["checks"].append(str(case.get("skip")))
            records.append(rec)
            continue
        # Historical playback wins over current deterministic execution.
        replay_declared = bool(replay_dir)
        if replay_ok:
            run_mode = "replay"
        elif replay_declared:
            # Declared but unusable replay input — recorded, never dropped;
            # the fail-closed probe below still exercises the pipeline.
            rec["capability_status"] = "NO_REPLAY"
            rec["checks"].append(
                "decision_run_dir lacks report.json/run-manifest.json — "
                "historical playback cannot consume it")
            run_mode = "deterministic_only" if opts.det_fallback else None
        elif opts.det_fallback:
            run_mode = "deterministic_only"
            rec["capability_status"] = "CURRENT_DETERMINISTIC"
        else:
            run_mode = None
            rec["capability_status"] = "NO_REPLAY" if (legacy_ok or replay_declared) else "LIVE_REQUIRED"

        if run_mode is None:
            rec["status"] = "NOT_RUN_LIVE_PENDING_AUTHORIZATION"
            rec["category"] = "not_run"
            rec["checks"].append(
                "case has no replay inputs and deterministic fallback is disabled; live R6 is retired")
            records.append(rec)
            continue

        argv = izyan_argv(opts, case, snap_root, adv_file, adv_dir, case_out, run_mode)
        redacted = redact_argv(argv, out_dir)
        rec["command"] = redacted
        if opts.dry_run:
            rec["status"] = "NOT_RUN"
            rec["category"] = "not_run"
            rec["checks"].append("dry run")
            records.append(rec)
            continue

        attempt = Path(tempfile.mkdtemp(prefix=cid + "-", dir=cases_dir))
        case_out = attempt / "run"
        argv = izyan_argv(opts, case, snap_root, adv_file, adv_dir, case_out, run_mode)
        redacted = redact_argv(argv, out_dir)
        t0 = time.monotonic()
        timed_out = False
        try:
            proc = subprocess.run(
                argv, cwd=str(repo_root()), capture_output=True, text=True,
                timeout=opts.timeout_s + 300)
            rc = proc.returncode
            tail = (proc.stdout + proc.stderr).splitlines()[-8:]
        except (OSError, subprocess.SubprocessError) as exc:
            rc, timed_out, tail = 124, isinstance(exc, subprocess.TimeoutExpired), [str(exc)]
        elapsed = time.monotonic() - t0
        rec.update(parse_run(cid, case, case_out, argv, redacted, rc, elapsed, timed_out, tail))
        records.append(rec)
        art = build_artifact_record(rec)
        if art.get("artifact_digest"):
            art["expected_class"] = rec.get("expected_class")
            art["control_role"] = rec.get("control_role")
            artifact_index["artifacts"][art["artifact_digest"]] = art

    # ---- write outputs
    runs_path = out_dir / "runs.jsonl"
    with open(runs_path, "w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r, sort_keys=True) + "\n")
    with open(out_dir / "artifact-index.json", "w", encoding="utf-8") as fh:
        json.dump(artifact_index, fh, indent=2, sort_keys=True)
        fh.write("\n")
    summary = _summary(records)
    summary["mode"] = opts.mode
    summary["live"] = bool(opts.live)
    summary["manifest"] = MANIFEST_SCHEMA
    with open(out_dir / "summary.json", "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2, sort_keys=True)
        fh.write("\n")
    with open(out_dir / "summary.md", "w", encoding="utf-8") as fh:
        fh.write(_summary_md(summary, records))

    print(f"runner: {summary['cases_total']} cases -> {out_dir}")
    print(f"  status: {summary['by_status']}")
    print(f"  categories: {summary['by_category']}")
    if summary["no_replay_cases"]:
        print(f"  NO_REPLAY: {summary['no_replay_cases']}")
    if summary["stop"]:
        print(f"  STOP: accepted false-safe proposals in {summary['false_safe_cases']}",
              file=sys.stderr)
        return 2
    return 2 if any(r["status"] == "ERROR" or r.get("checks") for r in records) else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Drive the R6 decision-ready route over an external manifest.")
    ap.add_argument("--manifest", required=True,
                    help="external decision-ready-manifest/1 JSON (sanitized labels only)")
    ap.add_argument("--mode", default="decision-ready",
                    choices=["decision-ready"],
                    help="run mode (only the R6 decision-ready route exists)")
    ap.add_argument("--output-dir", required=True,
                    help="external output directory (never committed)")
    ap.set_defaults(live=False)
    ap.add_argument("--det-fallback", dest="det_fallback", action="store_true",
                    default=True,
                    help="run current deterministic research for unreplayable cases")
    ap.add_argument("--no-det-fallback", dest="det_fallback", action="store_false")
    ap.add_argument("--case", default="",
                    help="comma-separated case filter")
    ap.add_argument("--timeout-s", type=int, default=DEFAULT_CASE_TIMEOUT_S,
                    help="default per-case overall timeout in seconds")
    ap.add_argument("--izyan-bin", default=os.environ.get(IZYAN_BIN_ENV, "go"),
                    help=f"izyan binary path (env {IZYAN_BIN_ENV}); 'go' = `go run ./cmd/izyan`")
    ap.add_argument("--dry-run", action="store_true",
                    help="classify inputs and print commands without executing")
    args = ap.parse_args(argv)
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())

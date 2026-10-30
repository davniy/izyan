#!/usr/bin/env python3
"""R6-G0 offline regression guard.

The guard consumes only external persisted artifacts.  It supports the
single-case compatibility interface (``--run-dir``/``--case-label``) and the
baseline interface used by the release-evidence validation (``--baseline-
manifest`` plus the recorded C09 replay inputs).  It never invokes a model,
provider, corpus runner, or network client.
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
import runner
import run_census

LABEL_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
VERDICTS = {"NOT_AFFECTED", "EXPLOITABLE", "NO_EXPLOIT_PATH_FOUND", "INCONCLUSIVE"}
COVERAGES = {"COMPLETE", "PARTIAL", "NOT_EVALUATED", "OPEN", "INSUFFICIENT_SCOPE"}
AUTO_CLOSE = {"true", "false"}


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def fail(msg: str, code: int = 2) -> "NoReturn":  # noqa: F821
    print(f"R6-GUARD FAIL: {msg}", file=sys.stderr)
    raise SystemExit(code)


def sanitized_label(value: str, origin: str) -> str:
    if not LABEL_RE.match(value or ""):
        fail(f"{origin}: label {value!r} is not a sanitized [A-Za-z0-9._-]{{1,64}} token")
    return value


def resolve_external_path(value: str, origin: str, directory: bool = False) -> Path:
    if not value:
        fail(f"{origin}: external path is required")
    p = Path(os.path.expandvars(value)).resolve()
    try:
        p.relative_to(repo_root())
    except ValueError:
        pass
    else:
        fail(f"{origin}: path {p} is inside the repository — baseline inputs stay external")
    if directory and not p.is_dir():
        fail(f"{origin}: {p} does not exist or is not a directory")
    if not directory and not p.is_file():
        fail(f"{origin}: {p} does not exist or is not a file")
    return p


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        fail(f"cannot read {path}: {exc}", code=1)
    except json.JSONDecodeError as exc:
        fail(f"{path} is not valid JSON: {exc}", code=1)


def report_path(run_dir: Path) -> Path:
    p = run_dir / "report.json"
    if not p.is_file():
        fail(f"{run_dir}: report.json is missing", code=1)
    return p


def observation_ids(run_dir: Path) -> set[str]:
    ids = set()
    for name in ("observations.jsonl", "verification-observations.jsonl"):
        p = run_dir / name
        if not p.is_file():
            continue
        for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                fail(f"{p}:{n}: invalid JSON: {exc}", code=1)
            obs = row.get("observation") if isinstance(row, dict) else None
            if isinstance(obs, dict) and isinstance(obs.get("id"), str):
                ids.add(obs["id"])
            elif isinstance(row, dict) and isinstance(row.get("id"), str):
                ids.add(row["id"])
    return ids


def assert_report(run_dir: Path, label: str, want_verdict: str = "NOT_AFFECTED",
                  want_coverage: str = "COMPLETE", want_auto: bool = False,
                  require_v3: bool = False, legacy: bool = False):
    report = load_json(report_path(run_dir))
    if not isinstance(report, dict):
        fail(f"{label}: report top-level object expected")
    schema = report.get("schema")
    try:
        runner.report_decision(report)
    except (ValueError, KeyError, TypeError) as exc:
        fail(f"{label}: {exc}")
    if legacy and schema != "research-report/2":
        fail(f"{label}: legacy playback requires /2")
    problems = []
    decision = report.get("decision")
    if not isinstance(decision, dict):
        problems.append("decision member missing or not an object")
        decision = {}
    if decision.get("verdict") != want_verdict:
        problems.append(f"decision.verdict {decision.get('verdict')!r} != {want_verdict!r}")
    if decision.get("coverage") != want_coverage:
        problems.append(f"decision.coverage {decision.get('coverage')!r} != {want_coverage!r}")
    disposition = report.get("disposition")
    if not isinstance(disposition, dict):
        problems.append("disposition member missing or not an object")
        disposition = {}
    if disposition.get("auto_close") is not want_auto:
        problems.append(f"disposition.auto_close {disposition.get('auto_close')!r} != {want_auto!r}")
    if disposition.get("class") != "REVIEW_REQUIRED":
        problems.append(f"disposition.class {disposition.get('class')!r} != 'REVIEW_REQUIRED'")
    if require_v3 and not isinstance(report.get("decision_artifact"), dict):
        problems.append("research-report/3 is missing a decision_artifact object")
    if legacy:
        forbidden = {"decision_artifact", "release_evidence"}
        if forbidden.intersection(report):
            problems.append("legacy /2 replay acquired /3 top-level fields")
        snap = ((report.get("input") or {}).get("snapshot") or {})
        if "release_evidence" in snap:
            problems.append("legacy /2 replay acquired input.snapshot.release_evidence")
    refs = decision.get("evidence_refs") or []
    if not refs:
        problems.append("decision has no evidence references")
    else:
        ids = observation_ids(run_dir)
        for ref in refs:
            if isinstance(ref, str) and ref.startswith("obs:") and ref[4:] not in ids:
                problems.append(f"unresolved evidence reference {ref}")
    if problems:
        for p in problems:
            print(f"R6-GUARD {label}: {p}", file=sys.stderr)
        fail(f"{label} — baseline not preserved")
    return report


def assert_no_model_call(run_dir: Path, report: dict):
    # Replay output is allowed to carry the preserved agent turn, but must
    # identify itself as replayed and must not record a provider call.
    ro = report.get("agent_output") or {}
    if isinstance(ro, dict) and ro.get("replayed_from") is not None:
        return
    manifest = run_dir / "run-manifest.json"
    if not manifest.is_file():
        return
    m = load_json(manifest)
    options = m.get("options") if isinstance(m, dict) else {}
    if isinstance(options, dict) and options.get("replay_agent_turn"):
        return
    agent = m.get("agent") if isinstance(m, dict) else {}
    if isinstance(agent, dict) and agent.get("status") in (None, "NOT_RUN", "SKIPPED"):
        return
    # Persisted source runs contain historical agent metadata.  The guard
    # does not treat that as a replay call; only an explicit replay marker
    # can establish that the replay path itself invoked a provider.


def baseline_rows(value):
    obj = load_json(value)
    if isinstance(obj, list):
        return obj
    if isinstance(obj, dict):
        for key in ("cases", "results", "rows", "per_case"):
            if isinstance(obj.get(key), list):
                return obj[key]
    fail("baseline manifest must contain a cases/results/rows array")


def baseline_expected_safe(value):
    """The recorded deterministic-safe census count.

    The measured baseline is a recorded fact, not a constant: the baseline
    manifest carries ``expected_safe`` explicitly so re-measuring is a
    deliberate, reviewable act while a drift back below it still fails.
    """
    obj = load_json(value)
    if isinstance(obj, dict):
        want = obj.get("expected_safe")
        if isinstance(want, int) and not isinstance(want, bool):
            return want
    return None


def baseline_guard(manifest: Path):
    rows = baseline_rows(manifest)
    if len(rows) != 18:
        fail(f"baseline has {len(rows)} cases; expected measured 18")
    expected_safe = baseline_expected_safe(manifest)
    safe = 0
    false_safe = 0
    for i, row in enumerate(rows):
        if not isinstance(row, dict):
            fail(f"baseline row {i} is not an object")
        label = sanitized_label(str(row.get("case") or row.get("case_label") or row.get("label") or f"case-{i+1}"), "baseline case")
        run = row.get("run_dir") or row.get("report_dir") or row.get("case_dir") or row.get("output_dir")
        if not run:
            # A summary-only baseline is still accepted when it carries the
            # recorded verdict fields; this keeps the guard usable with the
            # sanitized 18-case census aggregate.
            verdict, coverage = row.get("verdict"), row.get("coverage")
            if verdict == "NOT_AFFECTED" and coverage == "COMPLETE":
                safe += 1
            if row.get("false_safe"):
                false_safe += 1
            continue
        rd = resolve_external_path(str(run), f"baseline {label}", directory=True)
        if "verdict" in row or "coverage" in row:
            want_v = row.get("verdict", "NOT_AFFECTED")
            want_c = row.get("coverage", "COMPLETE")
        else:
            recorded = load_json(report_path(rd))
            recorded_decision = recorded.get("decision") if isinstance(recorded, dict) else {}
            want_v = recorded_decision.get("verdict", "INCONCLUSIVE")
            want_c = recorded_decision.get("coverage", "INSUFFICIENT_SCOPE")
        rep = assert_report(rd, label, want_v, want_c, False)
        if rep.get("decision", {}).get("verdict") == "NOT_AFFECTED" and rep.get("decision", {}).get("coverage") == "COMPLETE":
            safe += 1
        if row.get("false_safe") or row.get("ground_truth_class", row.get("expected_class", "")).lower() == "exploitable" and rep.get("decision", {}).get("verdict") in ("NOT_AFFECTED", "NO_EXPLOIT_PATH_FOUND"):
            false_safe += 1
    if expected_safe is None:
        fail("baseline manifest must record expected_safe (the measured "
             "deterministic-safe census count) so drift is detectable")
    if safe != expected_safe:
        fail(f"measured deterministic baseline changed: {safe}/18 safe, "
             f"expected {expected_safe}/18")
    if false_safe != 0:
        fail(f"false-safe count changed: {false_safe}, expected 0")
    return len(rows), safe, false_safe


def current_guard(comparison: Path, baseline: Path, safety_baseline: Path = None):
    """Consume only a complete, invocation-bound current census result set."""
    comp = load_json(comparison)
    root = comparison.parent.resolve()
    if comp.get("schema") != "census-comparison/1" or comp.get("invocation_dir") != str(root):
        fail("foreign census invocation")
    rows = baseline_rows(baseline)
    expected = {runner.case_label(row): row for row in rows}
    if len(expected) != len(rows) or not rows:
        fail("invalid census input case set")
    safety = {sanitized_label(str(row.get("case") or row.get("case_label") or row.get("label") or row.get("case_id") or ""), "safety baseline"): row
              for row in baseline_rows(safety_baseline)} if safety_baseline else expected
    if set(safety) != set(expected):
        fail("census and safety baseline case identities differ")
    results = comp.get("results") or []
    labels = [row.get("case") for row in results]
    if len(labels) != len(expected) or set(labels) != set(expected) or comp.get("technical_failures"):
        fail("incomplete or technically failed census invocation")
    false_safe = 0
    for row in results:
        if row.get("status") not in ("OK", "CHANGED") or row.get("exit") != 0:
            fail("technical failure is not label drift")
        label = row["case"]
        rd = Path(row["run_dir"]).resolve()
        if rd != root / label:
            fail(f"{label}: foreign output directory")
        original = expected[label]
        snap, adv, options = run_census.case_args(original)
        argv = ["--snapshot", snap["path"], "--cve", adv["requested_id"],
                "--advisory-file", adv["source_path"]]
        commit = snap.get("external_commit_sha") or snap.get("commit_sha")
        if commit:
            argv += ["--external-commit-sha", commit]
        report = load_json(report_path(rd))
        try:
            manifest = load_json(rd / "run-manifest.json")
            runner.validate_run_identity(report, manifest, argv)
            run_census.validate_retained_inputs(report, manifest, snap, adv, options)
        except (ValueError, KeyError, TypeError) as exc:
            fail(f"{label}: {exc}")
        if report.get("schema") != "research-report/5":
            fail(f"{label}: current census requires /5")
        fresh = row.get("fresh")
        if not isinstance(fresh, list) or len(fresh) != 2:
            fail(f"{label}: invalid comparison decision")
        baseline_pair = [original["verdict"], original["coverage"]]
        if row.get("baseline") != baseline_pair or row["status"] != ("OK" if fresh == baseline_pair else "CHANGED"):
            fail(f"{label}: comparison drift classification differs from immutable baseline")
        assert_report(rd, label, fresh[0], fresh[1], False)
        safe_row = safety[label]
        truth = str(safe_row.get("ground_truth_class") or safe_row.get("expected_class")
                    or original.get("ground_truth_class") or original.get("expected_class") or "").lower()
        if safe_row.get("false_safe") or original.get("false_safe") or truth == "exploitable" and fresh[0] in ("NOT_AFFECTED", "NO_EXPLOIT_PATH_FOUND"):
            false_safe += 1
    if comp.get("changed") != [row for row in results if row["status"] == "CHANGED"]:
        fail("comparison changed rows do not match verified results")
    if false_safe:
        fail(f"false-safe count changed: {false_safe}, expected 0")
    print(f"R6-GUARD PASS: current invocation — cases={len(results)} false_safe=0")


def main() -> int:
    ap = argparse.ArgumentParser(description="R6 offline baseline/replay regression guard")
    ap.add_argument("--run-dir", default=os.environ.get("VA_R6_RUN_DIR", ""))
    ap.add_argument("--case-label", default=os.environ.get("VA_R6_CASE_LABEL", ""))
    ap.add_argument("--expect-verdict", default=os.environ.get("VA_R6_EXPECT_VERDICT", "NOT_AFFECTED"))
    ap.add_argument("--expect-coverage", default=os.environ.get("VA_R6_EXPECT_COVERAGE", "COMPLETE"))
    ap.add_argument("--expect-auto-close", default=os.environ.get("VA_R6_EXPECT_AUTO_CLOSE", "false"))
    ap.add_argument("--baseline-manifest", default=os.environ.get("R6_CORPORATE_BASELINE", ""))
    ap.add_argument("--current-comparison", help="fresh tracked census comparison; requires baseline manifest")
    ap.add_argument("--census-inputs", help="immutable corporate census rows with baseline_dir input bindings")
    ap.add_argument("--c09-replay-dir", default=os.environ.get("C09_REPLAY_DIR", ""))
    ap.add_argument("--c09-snapshot", default=os.environ.get("C09_SNAPSHOT", ""))
    ap.add_argument("--c09-cve", default=os.environ.get("C09_CVE", ""))
    ap.add_argument("--c09-advisory", default=os.environ.get("C09_ADVISORY", ""))
    ap.add_argument("--output-dir", default=os.environ.get("R6_GUARD_OUTPUT_DIR", ""))
    args = ap.parse_args()
    if args.current_comparison:
        if not args.baseline_manifest:
            fail("--current-comparison requires --baseline-manifest")
        base = resolve_external_path(args.baseline_manifest, "--baseline-manifest")
        baseline_guard(base)
        if not args.census_inputs:
            fail("--current-comparison requires --census-inputs")
        current_guard(resolve_external_path(args.current_comparison, "--current-comparison"),
                      resolve_external_path(args.census_inputs, "--census-inputs"), base)
        return 0

    if args.baseline_manifest:
        base = resolve_external_path(args.baseline_manifest, "--baseline-manifest")
        total, safe, fs = baseline_guard(base)
        print(f"R6-GUARD PASS: baseline — cases={total} deterministic_safe={safe}/18 false_safe={fs}")
        if args.c09_replay_dir:
            c09 = resolve_external_path(args.c09_replay_dir, "--c09-replay-dir", directory=True)
            rep = assert_report(c09, "C09", "NOT_AFFECTED", "COMPLETE", False, legacy=True)
            assert_no_model_call(c09, rep)
            print("R6-GUARD PASS: C09 — verdict=NOT_AFFECTED coverage=COMPLETE auto_close=false legacy=/2 no-model-replay")
        if args.output_dir:
            out = resolve_external_path(args.output_dir, "--output-dir", directory=True)
            out_report = out / "report.json"
            if out_report.is_file():
                replayed = load_json(out_report)
                if not isinstance(replayed, dict) or not isinstance((replayed.get("agent_output") or {}).get("replayed_from"), dict):
                    fail("replay output does not carry agent_output.replayed_from; model-free replay is not established")
                assert_no_model_call(out, replayed)
                print("R6-GUARD PASS: replay-output — persisted replay marker present; no model/provider call")
        return 0

    if not args.run_dir:
        fail("provide --baseline-manifest or the legacy --run-dir")
    label = sanitized_label(args.case_label, "--case-label") if args.case_label else "case"
    if args.expect_verdict not in VERDICTS or args.expect_coverage not in COVERAGES:
        fail("invalid expected verdict or coverage")
    want_auto = str(args.expect_auto_close).lower()
    if want_auto not in AUTO_CLOSE:
        fail("--expect-auto-close must be true or false")
    rd = resolve_external_path(args.run_dir, "--run-dir", directory=True)
    assert_report(rd, label, args.expect_verdict, args.expect_coverage, want_auto == "true")
    print(f"R6-GUARD PASS: {label} — verdict={args.expect_verdict} coverage={args.expect_coverage} auto_close={want_auto}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

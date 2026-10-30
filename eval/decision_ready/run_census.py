#!/usr/bin/env python3
"""Offline census: 0 unchanged, 1 label drift, 2 technical/input failure.

Provisioned inputs are read-only. Every invocation owns a fresh output directory.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor

import runner


def case_args(row):
    manifest = runner._load_json(Path(row["baseline_dir"]) / "run-manifest.json")
    snap, adv = manifest["snapshot"], manifest["advisory"]
    # Preserve requested identity, not a resolved alias substituted by the harness.
    options = dict(manifest.get("options") or {})
    report_path = Path(row["baseline_dir"]) / "report.json"
    if report_path.is_file():
        effective = (runner._load_json(report_path).get("input") or {}).get("snapshot") or {}
        for key in ("goos", "goarch", "build_tags"):
            if not options.get(key) and effective.get(key):
                options[key] = effective[key]
        if not options.get("analysis_go"):
            version = re.search(r"\bgo(\d+\.\d+(?:\.\d+)?(?:rc\d+|beta\d+)?)\b", str(effective.get("go_version") or ""))
            if version:
                options["analysis_go"] = version.group(1)
    return snap, adv, options


def validate_retained_inputs(report, manifest, snapshot, advisory, options):
    """Bind fresh artifacts to immutable material and effective build pins."""
    inputs = report.get("input") or {}
    for section, recorded, keys in (("snapshot", snapshot, ("content_hash",)),
                                    ("advisory", advisory, ("raw_sha256", "canonical_sha256"))):
        for key in keys:
            if recorded.get(key) and (inputs.get(section) or {}).get(key) != recorded[key]:
                raise ValueError(f"retained {section}.{key} pin mismatch")
    effective = inputs.get("snapshot") or {}
    emitted = manifest.get("options") or {}
    for key in ("goos", "goarch", "build_tags", "analysis_go"):
        want = options.get(key)
        if key == "build_tags" and key in options and not want:
            if emitted.get(key) or effective.get(key):
                raise ValueError("effective build tags differ from recorded empty selection")
        if not want:
            continue
        if emitted.get(key) != want:
            raise ValueError(f"retained options.{key} mismatch")
        if key in ("goos", "goarch", "build_tags") and effective.get(key) != want:
            raise ValueError(f"effective snapshot.{key} mismatch")
        if key == "analysis_go":
            version = str(want).removeprefix("go")
            actual = str(effective.get("go_version") or "")
            if actual != version and "go" + version not in actual.split():
                raise ValueError("effective analysis toolchain mismatch")


def run_case(row, output, binary="go", timeout=1800):
    label = runner.case_label(row)
    result = {"case": label, "baseline": [row["verdict"], row["coverage"]],
              "status": "TECHNICAL_FAILURE", "fresh": None}
    start = time.monotonic()
    try:
        snap, adv, options = case_args(row)
        case = {"case": label, "cve": adv["requested_id"],
                "snapshot": snap, "external_commit_sha": snap.get("external_commit_sha") or snap.get("commit_sha")}
        case.update({key: options[key] for key in ("modcache", "govulndb", "goos", "goarch", "build_tags", "analysis_go") if options.get(key)})
        opts = argparse.Namespace(izyan_bin=binary, timeout_s=timeout)
        out = output / label
        cmd = runner.izyan_argv(opts, case, snap["path"], adv["source_path"], None, out, "deterministic_only")
        result["run_dir"] = str(out)
        proc = subprocess.run(cmd, cwd=runner.repo_root(), capture_output=True, text=True, timeout=timeout)
        result["exit"] = proc.returncode
        if proc.returncode:
            raise ValueError(f"command failed with exit {proc.returncode}: {proc.stderr[-500:]}")
        report = runner._load_json(out / "report.json")
        manifest = runner._load_json(out / "run-manifest.json")
        runner.validate_run_identity(report, manifest, cmd)
        validate_retained_inputs(report, manifest, snap, adv, options)
        if report.get("schema") != "research-report/5":
            raise ValueError("current census requires research-report/5")
        decision = runner.report_decision(report)
        if (report.get("disposition") or {}).get("auto_close") is not False:
            raise ValueError("auto_close must remain false")
        result["fresh"] = [decision["verdict"], decision["coverage"]]
        result["status"] = "OK" if result["fresh"] == result["baseline"] else "CHANGED"
    except (OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.SubprocessError) as exc:
        result["error"] = str(exc)
    result["wall_s"] = round(time.monotonic() - start, 2)
    return result


def census(baseline, output_root, binary="go", jobs=1, only="", timeout=1800):
    rows = runner._load_json(baseline)["rows"]
    labels = [runner.case_label(row) for row in rows]
    if not rows or len(set(labels)) != len(labels):
        raise ValueError("census must contain unique nonempty case labels")
    if only:
        wanted = set(only.split(","))
        if wanted - set(labels):
            raise ValueError("unknown requested census case")
        rows = [row for row in rows if row["case"] in wanted]
    output_root.mkdir(parents=True, exist_ok=True)
    invocation = Path(tempfile.mkdtemp(prefix="census-", dir=output_root))
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        results = list(pool.map(lambda row: run_case(row, invocation, binary, timeout), rows))
    failures = [row for row in results if row["status"] == "TECHNICAL_FAILURE"]
    summary = {"schema": "census-comparison/1", "invocation_dir": str(invocation),
               "results": results, "technical_failures": failures,
               "changed": [row for row in results if row["status"] == "CHANGED"],
               "safe_fresh": sum(row["fresh"] == ["NOT_AFFECTED", "COMPLETE"] for row in results),
               "safe_baseline": sum(row["baseline"] == ["NOT_AFFECTED", "COMPLETE"] for row in results)}
    path = invocation / "census-comparison.json"
    path.write_text(json.dumps(summary, indent=2) + "\n")
    print(f"census comparison: {path}")
    return (2 if failures else 1 if summary["changed"] else 0), path


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus", default=os.environ.get("IZYAN_CENSUS_BASE"), required=not os.environ.get("IZYAN_CENSUS_BASE"))
    ap.add_argument("--output-dir", required=True)
    ap.add_argument("--izyan-bin", default=os.environ.get("IZYAN_BIN", "go"))
    ap.add_argument("--jobs", type=int, default=1)
    ap.add_argument("--only", default="")
    ap.add_argument("--comparison-pointer", help="write the fresh comparison path only on successful technical completion")
    args = ap.parse_args(argv)
    pointer = Path(args.comparison_pointer) if args.comparison_pointer else None
    if pointer:
        pointer.unlink(missing_ok=True)
    try:
        rc, path = census(Path(args.corpus) / "r6-corporate-baseline.json", Path(args.output_dir), args.izyan_bin, args.jobs, args.only)
        if rc != 2 and pointer:
            pointer.write_text(str(path) + "\n")
        return rc
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        print(f"census technical failure: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

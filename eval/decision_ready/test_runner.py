"""Offline producers and CLI routing behavior; no model or private corpus."""
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import runner

# ----------------------------------------------------- runner (pure parts) --

class _Opts:
    izyan_bin = "go"
    timeout_s = 1500
    live = False


def test_runner_label_validation():
    assert runner.case_label({"case": "case-01"}) == "case-01"
    for bad in ("CASE-../x", "weird space", "", "x" * 65):
        try:
            runner.case_label({"case": bad})
        except ValueError:
            pass
        else:
            raise AssertionError(f"label {bad!r} accepted")


def test_runner_argv_modes():
    case = {"case": "case-01", "cve_ids": ["CVE-X-1"],
            "snapshot": {"repo": "/r", "git_ref": "v1"},
            "advisory_file": "eval/advisories/reviewed/x.json"}
    a = runner.izyan_argv(_Opts(), case, "/snap", "adv.json", None, Path("/out/case-01"),
                          "deterministic_only")
    assert a[:3] == ["go", "run", "./cmd/izyan"]
    assert "--deterministic-only" not in a and "--decision-ready" not in a
    case2 = dict(case, decision_run_dir="/prior/run")
    a = runner.izyan_argv(_Opts(), case2, "/snap", "adv.json", None, Path("/out/x"), "replay")
    assert "research-replay" in a and "--replay-decision-run" not in a
    try:
        runner.izyan_argv(_Opts(), case, "/snap", "adv.json", None, Path("/out/x"), "live")
    except ValueError as exc:
        assert "retired" in str(exc)
    else:
        raise AssertionError("offline runner constructed a live launch")


def test_runner_redact_external_paths():
    out = Path("/tmp/out").resolve()
    argv = ["izyan", "research", "--snapshot", "/private/path/snap",
            "--output-dir", str(out / "cases/case-01")]
    red = runner.redact_argv(argv, out)
    assert red[3] == "<external>"
    assert red[5].startswith("<out>")


def test_parse_run_fail_closed_on_missing_report(tmp_path):
    rec = runner.parse_run("case-01", {}, tmp_path, ["izyan"], ["izyan"],
                           rc=1, elapsed=1.0, timed_out=False, stdout_tail=["boom"])
    assert rec["status"] == "ERROR"
    assert rec["category"] == "error"
    assert rec["model_calls"] == 0


def test_parse_run_classifies_hold_unknown(tmp_path):
    (tmp_path / "report.json").write_text(json.dumps({
        "schema": "research-report/3",
        "disposition": {"class": "REVIEW_REQUIRED", "auto_close": False},
        "decision_artifact": {"proposed_disposition": "HOLD_UNKNOWN", "branches": []},
        "decision": {"verdict": "INCONCLUSIVE", "coverage": "NOT_EVALUATED"},
    }))
    (tmp_path / "run-manifest.json").write_text(json.dumps({
        "decision_ready": {"termination": "PLANNER_FAILURE", "ready": False, "turns": []}}))
    (tmp_path / "decision-artifact.json").write_text(json.dumps({
        "schema": "decision-artifact/1", "proposed_disposition": "HOLD_UNKNOWN",
        "branches": [{"id": "B-UNKNOWN", "status": "NOT_DECISION_READY"}],
        "human_action": {"environment_question_refs": [], "mandatory_fact_refs": []},
        "shared_facts": []}))
    bind_identity(tmp_path)
    rec = runner.parse_run("case-01", {}, tmp_path, ["x", "--deterministic-only"],
                           ["x"], rc=0, elapsed=5.0, timed_out=False, stdout_tail=[])
    assert rec["status"] == "RAN"
    assert rec["category"] == "HOLD_UNKNOWN"
    assert rec["flow_termination"] == "PLANNER_FAILURE"
    assert rec["decision_ready"] is False
    assert rec["auto_close"] is False
    assert rec["artifact_digest"].startswith("sha256:")


def test_parse_run_flags_false_safe(tmp_path):
    (tmp_path / "report.json").write_text(json.dumps({
        "schema": "research-report/3",
        "disposition": {"class": "REVIEW_REQUIRED", "auto_close": False},
        "decision": {"verdict": "NOT_AFFECTED", "coverage": "COMPLETE"},
    }))
    (tmp_path / "run-manifest.json").write_text(json.dumps({
        "decision_ready": {"termination": "DECISION_READY", "ready": True, "turns": []}}))
    (tmp_path / "decision-artifact.json").write_text(json.dumps({
        "proposed_disposition": "CLOSE_NOT_AFFECTED",
        "branches": [{"id": "B-1", "status": "COMPLETE"},
                     {"id": "B-UNKNOWN", "status": "COMPLETE"}],
        "human_action": {}, "shared_facts": []}))
    bind_identity(tmp_path)
    rec = runner.parse_run("ctrl", {"expected_class": "exploitable"}, tmp_path,
                           ["x"], ["x"], rc=0, elapsed=3, timed_out=False, stdout_tail=[])
    assert rec["false_safe"] is True
    assert rec["category"] == "terminal_deterministic_verified_negative"


def test_parse_run_flags_unresolved_refs(tmp_path):
    (tmp_path / "report.json").write_text(json.dumps({
        "schema": "research-report/3",
        "disposition": {"auto_close": False},
        "decision": {}}))
    (tmp_path / "run-manifest.json").write_text(json.dumps({
        "decision_ready": {"termination": "DECISION_READY", "ready": True, "turns": []}}))
    (tmp_path / "decision-artifact.json").write_text(json.dumps({
        "proposed_disposition": "CLOSE_NOT_AFFECTED",
        "branches": [{"id": "B-UNKNOWN", "status": "COMPLETE"}],
        "human_action": {},
        "shared_facts": [{"id": "f1", "observation_refs": ["obs:OBS-0099"]}]}))
    bind_identity(tmp_path)
    rec = runner.parse_run("case-01", {}, tmp_path, ["x"], ["x"], rc=0,
                           elapsed=1, timed_out=False, stdout_tail=[])
    assert rec["unresolved_evidence_refs"] == 1
    assert any("unresolved evidence refs" in c for c in rec["checks"])


def bind_identity(path):
    for name in ("report.json", "run-manifest.json"):
        data = json.loads((path / name).read_text())
        data.update({"run": {"run_id": "run-1"}} if name == "report.json" else {"run_id": "run-1"})
        (path / name).write_text(json.dumps(data))


def test_historical_replay_uses_eval_route():
    command = runner.izyan_argv(_Opts(), {"decision_run_dir": "/saved"}, None, None, None, Path("/new"), "replay")
    assert command[3:] == ["eval", "research-replay", "--run", "/saved", "--out", "/new"]


def test_offline_runner_rebuilds_metric_inputs(tmp_path, monkeypatch):
    import test_census
    binary, baseline, row = test_census.inputs(tmp_path)
    # Historical artifact fixture is emitted by the actual fake executable.
    monkeypatch.setenv("FAKE_ARTIFACT", "1")
    manifest = tmp_path / "arm.json"
    snap, adv, _ = __import__("run_census").case_args(row)
    manifest.write_text(json.dumps({"cases": [{"case": "case-01", "cve": adv["requested_id"],
        "snapshot": {"root": snap["path"]}, "advisory_file": adv["source_path"]}]}))
    out = tmp_path / "metrics"
    assert runner.main(["--manifest", str(manifest), "--output-dir", str(out), "--izyan-bin", str(binary)]) == 0
    records = [json.loads(line) for line in (out / "runs.jsonl").read_text().splitlines()]
    index = json.loads((out / "artifact-index.json").read_text())
    summary = json.loads((out / "summary.json").read_text())
    assert records[0]["status"] == "RAN"
    assert len(index["artifacts"]) == 1
    assert summary["cases_total"] == 1 and summary["false_safe_count"] == 0


def test_summary_and_artifact_index_preserve_contract():
    rec = {"case_id": "case-01", "status": "RAN", "false_safe": True,
           "artifact_digest": "sha256:a", "checks": ["unsafe"], "category": "HOLD_UNKNOWN"}
    assert runner.build_artifact_record(rec)["artifact_digest"] == "sha256:a"
    assert runner._summary([rec])["stop"] is True


def test_historical_playback_extracts_without_material_inputs(tmp_path, monkeypatch):
    import test_census
    import run_census
    binary, baseline, row = test_census.inputs(tmp_path)
    # Create a retained historical report/artifact via an actual fake process.
    monkeypatch.setenv("FAKE_ARTIFACT", "1")
    output = tmp_path / "retained"
    output.mkdir()
    result = run_census.run_case(row, output, str(binary))
    saved = Path(result["run_dir"])
    before = {p.name: p.read_bytes() for p in saved.iterdir()}
    manifest = tmp_path / "historical.json"
    manifest.write_text(json.dumps({"cases": [{"case": "case-01", "decision_run_dir": str(saved)}]}))
    out = tmp_path / "extracted"
    assert runner.main(["--manifest", str(manifest), "--output-dir", str(out), "--izyan-bin", str(binary)]) == 0
    rec = json.loads((out / "runs.jsonl").read_text())
    assert rec["execution"] == "replay" and rec["model_calls"] == 0
    assert rec["artifact_digest"] in json.loads((out / "artifact-index.json").read_text())["artifacts"]
    assert before == {p.name: p.read_bytes() for p in saved.iterdir()}


def test_current_runner_produces_without_human_artifact(tmp_path):
    import test_census
    import run_census
    binary, baseline, row = test_census.inputs(tmp_path)
    snap, adv, _ = run_census.case_args(row)
    manifest = tmp_path / "arm.json"
    manifest.write_text(json.dumps({"cases": [{"case": "case-01", "cve": adv["requested_id"],
        "snapshot": {"root": snap["path"]}, "advisory_file": adv["source_path"]}]}))
    out = tmp_path / "current"
    assert runner.main(["--manifest", str(manifest), "--output-dir", str(out), "--izyan-bin", str(binary)]) == 0
    rec = json.loads((out / "runs.jsonl").read_text())
    assert rec["category"] == "current_deterministic"
    assert rec["decision_ready"] is False
    assert json.loads((out / "artifact-index.json").read_text())["artifacts"] == {}


@pytest.mark.parametrize("tags", [[], ["feature", "custom"]])
def test_compiled_cli_without_optional_commit(tmp_path, tags):
    import os
    import subprocess
    binary = os.environ.get("IZYAN_SMOKE_BIN")
    if not binary:
        pytest.skip("set IZYAN_SMOKE_BIN to exercise the compiled offline CLI")
    advisory = tmp_path / "advisory.json"
    advisory.write_text(json.dumps({"id": "GO-CANONICAL", "modified": "2026-01-01T00:00:00Z",
        "affected": [{"package": {"ecosystem": "Go", "name": "example.com/absent"},
                      "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]}))
    snapshot = runner.repo_root() / "testdata" / "evidencesnap"
    output = tmp_path / "run"
    options = SimpleNamespace(izyan_bin=binary, timeout_s=180)
    case = {"case": "case-01", "cve": "GO-CANONICAL", "build_tags": tags}
    command = runner.izyan_argv(options, case, snapshot, str(advisory), None, output, "deterministic_only")
    proc = subprocess.run(command, cwd=runner.repo_root(), capture_output=True, text=True, timeout=240)
    assert proc.returncode == 0, proc.stderr
    report = json.loads((output / "report.json").read_text())
    manifest = json.loads((output / "run-manifest.json").read_text())
    assert report["input"]["snapshot"]["external_commit_sha"] is None
    assert manifest["snapshot"]["external_commit_sha"] == ""
    runner.validate_run_identity(report, manifest, command)
    import run_census
    run_census.validate_retained_inputs(report, manifest, report["input"]["snapshot"],
                                       report["input"]["advisory"], {"build_tags": tags})
    assert (manifest["options"]["build_tags"] or []) == tags
    assert (report["input"]["snapshot"]["build_tags"] or []) == tags
    rec = runner.parse_run("case-01", {}, output, command, [], 0, 0, False, [])
    assert rec["status"] == "RAN" and rec["category"] == "current_deterministic"

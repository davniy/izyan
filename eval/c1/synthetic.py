"""C1 synthetic integration + isolation checks (Task 4.3, plan §4 step 4 /
test plan §9.2).

Every check runs WITHOUT a benchmark CVE: containers are launched through
the same ``run_in_container`` lifecycle as real attempts, but against a
tiny synthetic Go module and — only where marked — a stub CVE id
(CVE-2000-0000). Results are machine-readable records, persisted to
``synthetic-checks.json``; each check returns ``{"ok": bool, ...evidence}``.

Checks:
  mcp_handshake            initialize + schema negotiation over stdio
  mcp_tool_catalog         tools/list returns the full §6 catalog
  mcp_forced_tool_error    bogus tool name / bad args / unreadable file →
                           ERROR or protocol error, audit-trail recorded
  mcp_traversal            read_source outside the snapshot (../, absolute,
                           /etc/passwd, /work/../ escape) is rejected
  mcp_exec_gate            run_build/run_tests UNSUPPORTED without
                           --allow-exec
  container_fs_allowlist   no GT/tasks/eval/results/vexbench files inside
                           the attempt filesystem; env whitelist holds
  container_timeout        real subprocess timeout → RuntimeError +
                           full logs + export-report survive
  export_failure           forced docker-cp failure is recorded, not silent
  refusal_classification   fabricated refusal terminal answer →
                           provider_refusal, not uncertain/negative
  invalid_output           fabricated garbage terminal → parse_fail /
                           invalid_terminal_answer
  no_output                empty run dir → no_output/no_result
  live_isolation_probe     ONE real codex-c1 exec: native tools AND MCP
                           client both fail to reach GT/neighbor/results
                           artifacts (the only model call in the battery)

The battery never touches ``result_parser.py`` semantics: refusal/invalid
probes feed fabricated raw output through ``finalize_attempt`` with the
UNCHANGED official parser, exercising only the controller pipeline.
"""

from __future__ import annotations

import json
import logging
import os
import select
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional, Sequence

from . import runner

logger = logging.getLogger(__name__)

TOOL_BIN_CONTAINER = "/usr/local/bin/izyan-evidence-tools"
TOOL_AUDIT_DIR = "/tmp/izyan-audit"
IMAGE_C1 = "vex-bench-go-codex-c1:latest"

# Host paths the agent must never reach. The probes assert absence of these
# files/directories inside the attempt container (they exist on the host —
# the harness never mounts them).
FORBIDDEN_FILE_NAMES = [
    "go-tasks.jsonl",
    "vex_bench.jsonl",
    "acquisition.json",
    "provenance.json",
    "safety-cases.jsonl",
    "safety-metrics.json",
    "parsed.jsonl",
    "metrics.json",
    "ground_truth.json",
]
FORBIDDEN_DIR_HINTS = ["vexbench-baseline", "vexbench-plain", "vuln-analyzer-shadow", "eval"]

# Minimal synthetic module copied into probe containers in place of a
# benchmark snapshot (plan §9.2: synthetic checks use no benchmark CVE).
SYNTHETIC_SNAPSHOT = {
    "go.mod": "module example.com/c1probe\n\ngo 1.23\n",
    "probe.go": (
        "package c1probe\n\n"
        "// Handle is the single exported symbol used as a positive control.\n"
        "func Handle(in string) string {\n"
        "\treturn \"handled:\" + in\n"
        "}\n"
    ),
}

STUB_CVE = "CVE-2000-0000"


def _sha256_bytes(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def write_synthetic_snapshot(dest: Path) -> Path:
    for name, text in SYNTHETIC_SNAPSHOT.items():
        p = dest / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return dest


def _docker(args: list[str], timeout: int = 120, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=timeout, check=check
    )


def _create_cp(cid_holder: list, image: str, args: list[str], src: Path,
               entrypoint: str, env_file: Optional[Path] = None,
               mounts: Sequence[tuple[Path, str]] = (), interactive: bool = False) -> str:
    create = ["create", "--workdir", "/work"]
    if interactive:
        create.append("-i")
    if env_file is not None:
        create += ["--env-file", str(env_file)]
    for hp, cp_ in mounts:
        create += ["-v", f"{hp}:{cp_}:ro"]
    create += ["--entrypoint", entrypoint, image, *args]
    cid = _docker(create).stdout.strip()
    cid_holder.append(cid)
    _docker(["cp", f"{src.resolve()}/.", f"{cid}:/work"])
    return cid


# ---------------------------------------------------------------------------
# MCP stdio probe
# ---------------------------------------------------------------------------

def mcp_jsonrpc_probe(
    cid: str,
    requests: list[dict],
    out_dir: Path,
    deadline_s: int = 240,
) -> dict:
    """Attach to the (not yet started) probe container's stdio and run a
    newline-delimited JSON-RPC session: docker start -ai pipes the MCP
    server's stdin/stdout through this process.

    Returns {"responses": {id: msg}, "transcript_path": str}.
    """
    proc = subprocess.Popen(
        ["docker", "start", "-a", "-i", cid],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
    )
    transcript = out_dir / "mcp-transcript.jsonl"
    want_ids = {r["id"] for r in requests if "id" in r}
    got: dict[int, dict] = {}
    tf = transcript.open("w", encoding="utf-8")
    try:
        for req in requests:
            line = json.dumps(req) + "\n"
            proc.stdin.write(line.encode())
            proc.stdin.flush()
            tf.write(">> " + line)
        deadline = time.monotonic() + deadline_s
        fd = proc.stdout.fileno()
        buf = b""
        while want_ids - set(got) and time.monotonic() < deadline:
            ready, _, _ = select.select([fd], [], [], max(0.0, deadline - time.monotonic()))
            if not ready:
                break
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                raw_line, buf = buf.split(b"\n", 1)
                tf.write("<< " + raw_line.decode("utf-8", "replace") + "\n")
                try:
                    msg = json.loads(raw_line)
                except json.JSONDecodeError:
                    continue
                if isinstance(msg, dict) and msg.get("id") in want_ids:
                    got[msg["id"]] = msg
        return {
            "responses": {str(k): v for k, v in got.items()},
            "missing_ids": sorted(want_ids - set(got)),
            "transcript_path": str(transcript),
        }
    finally:
        tf.close()
        proc.kill()
        proc.wait()


def _mcp_args(snapshot: str = "/work", allow_exec: bool = False) -> list[str]:
    args = [
        "--snapshot-root", snapshot,
        "--cve", STUB_CVE,
        "--audit-file", f"{TOOL_AUDIT_DIR}/tool_calls.jsonl",
    ]
    if allow_exec:
        args.append("--allow-exec")
    return args


def _mcp_call(name: str, args: dict, rid: int) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": rid,
        "method": "tools/call",
        "params": {"name": name, "arguments": args},
    }


def _tool_result_status(msg: dict) -> str:
    """Classify a tools/call response: protocol_error | observation_status."""
    if "error" in msg:
        return "protocol_error"
    result = msg.get("result") or {}
    if result.get("isError"):
        return "is_error"
    sc = result.get("structuredContent") or {}
    return str(sc.get("tool_status") or "unknown")


def check_mcp(out_dir: Path, image: str, snapshot: Path, *, allow_exec: bool) -> dict:
    """One MCP container per exec-policy: handshake, catalog, forced errors,
    traversal, exec gate. Returns per-check verdicts."""
    records: dict[str, dict] = {}
    cids: list[str] = []
    reqs = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "c1-synthetic-probe", "version": "0.1"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        # positive control: a real evidence read inside the snapshot
        _mcp_call("get_product_snapshot", {}, 3),
        _mcp_call("read_source", {"file": "probe.go"}, 4),
        # forced tool errors: unknown tool, bad args, missing file
        _mcp_call("no_such_tool", {}, 5),
        _mcp_call("read_source", {}, 6),
        _mcp_call("read_source", {"file": "does/not/exist.go"}, 7),
        # negative isolation via the MCP channel: escapes must be rejected
        _mcp_call("read_source", {"file": "../escape.json"}, 8),
        _mcp_call("read_source", {"file": "../../etc/passwd"}, 9),
        _mcp_call("read_source", {"file": "/etc/passwd"}, 10),
        _mcp_call("read_source", {"file": "/work/../etc/hostname"}, 11),
        _mcp_call("search_source", {"pattern": "ground_truth"}, 12),
        # exec gate probe (status depends on allow_exec)
        _mcp_call("run_build", {}, 13),
    ]
    try:
        cid = _create_cp(
            cids, image, _mcp_args(allow_exec=allow_exec), snapshot,
            entrypoint=TOOL_BIN_CONTAINER, interactive=True,
        )
        res = mcp_jsonrpc_probe(cid, reqs, out_dir)
        # export the container-local audit sink as evidence BEFORE removal
        audit_rec = _export_audit(out_dir, cid)
    finally:
        for c in cids:
            _docker(["rm", "-f", c], check=False)

    resp = res["responses"]

    init = resp.get("1", {}).get("result") or {}
    records["mcp_handshake"] = {
        "ok": bool(init.get("serverInfo")) and bool(init.get("protocolVersion")),
        "serverInfo": init.get("serverInfo"),
        "protocolVersion": init.get("protocolVersion"),
        "instructions_present": bool(init.get("instructions")),
    }

    tools = (resp.get("2", {}).get("result") or {}).get("tools") or []
    names = sorted(t.get("name") for t in tools)
    records["mcp_tool_catalog"] = {
        "ok": len(names) >= 25,
        "tool_count": len(names),
        "tools": names,
        "all_have_input_schema": all(
            isinstance(t.get("inputSchema"), dict) for t in tools
        ),
    }

    errors = {
        "unknown_tool": _tool_result_status(resp.get("5", {})),
        "missing_file_arg": _tool_result_status(resp.get("6", {})),
        "nonexistent_file": _tool_result_status(resp.get("7", {})),
    }
    records["mcp_forced_tool_error"] = {
        "ok": all(s in {"protocol_error", "is_error", "ERROR"} for s in errors.values()),
        "statuses": errors,
        "positive_control_status": _tool_result_status(resp.get("4", {})),
    }

    traversal = {
        "dotdot": _tool_result_status(resp.get("8", {})),
        "dotdot_abs": _tool_result_status(resp.get("9", {})),
        "absolute_etc": _tool_result_status(resp.get("10", {})),
        "work_parent_escape": _tool_result_status(resp.get("11", {})),
        "gt_search": _tool_result_status(resp.get("12", {})),
    }
    gt_search = resp.get("12", {}).get("result", {}).get("structuredContent") or {}
    gt_matches = ((gt_search.get("data") or {}).get("count"))
    records["mcp_traversal"] = {
        "ok": all(
            s in {"protocol_error", "is_error", "ERROR"}
            for k, s in traversal.items()
            if k != "gt_search"
        )
        and (gt_matches in (0, None)),
        "statuses": traversal,
        "gt_search_matches": gt_matches,
        "detail": "out-of-root reads must be rejected; GT pattern must not match snapshot bytes",
    }

    gate = _tool_result_status(resp.get("13", {}))
    want = "OK" if allow_exec else "UNSUPPORTED"
    records["mcp_exec_gate"] = {
        "ok": gate == want,
        "allow_exec": allow_exec,
        "run_build_status": gate,
    }

    records["_audit_export"] = audit_rec
    records["transcript"] = res["transcript_path"]
    return records


def _export_audit(out_dir: Path, cid: Optional[str]) -> dict:
    if not cid:
        return {"ok": False, "detail": "container never created"}
    dest = out_dir / "izyan-audit"
    dest.mkdir(parents=True, exist_ok=True)
    cp = _docker(["cp", f"{cid}:{TOOL_AUDIT_DIR}/.", str(dest)], check=False)
    produced = dest / "tool_calls.jsonl"
    return {
        "ok": produced.exists(),
        "rc": cp.returncode,
        "path": str(produced),
    }


# ---------------------------------------------------------------------------
# Container filesystem allowlist (native-channel reality, deterministic)
# ---------------------------------------------------------------------------

def check_container_fs(
    out_dir: Path, image: str, snapshot: Path, env_file: Optional[Path] = None
) -> dict:
    """Enumerate the attempt filesystem inside a container built exactly
    like an attempt's (same image, same /work cp, same env file, no extra
    mounts). Assert no benchmark/GT/results artifacts exist and that only
    whitelisted env names leak in."""
    find_cmd = (
        "find / -xdev \\( -name 'go-tasks.jsonl' -o -name 'vex_bench.jsonl'"
        " -o -name 'acquisition.json' -o -name 'provenance.json'"
        " -o -name 'safety-*.jsonl' -o -name 'parsed.jsonl'"
        " -o -name 'metrics.json' -o -name 'ground_truth*'"
        " -o -name '*vexbench*' -o -name '*vuln-analyzer*' \\) 2>/dev/null;"
        " echo '===WORK==='; ls -la /work;"
        " echo '===TMP==='; find /tmp -maxdepth 3 2>/dev/null;"
        " echo '===ENV==='; printenv | cut -d= -f1 | sort;"
        " echo '===BIN==='; command -v izyan-evidence-tools go codex || true"
    )
    cids: list[str] = []
    try:
        cid = _create_cp(
            cids, image, ["-c", find_cmd], snapshot,
            entrypoint="sh", env_file=env_file,
        )
        started = _docker(["start", "-a", cid], timeout=120)
        out = started.stdout
    finally:
        for c in cids:
            _docker(["rm", "-f", c], check=False)
    (out_dir / "fs-enum.txt").write_text(out, encoding="utf-8")

    forbidden_hits = [
        line.strip()
        for line in out.split("===WORK===")[0].splitlines()
        if line.strip()
    ]
    env_names = (
        out.split("===ENV===")[1].split("===BIN===")[0].splitlines()
        if "===ENV===" in out
        else []
    )
    env_names = [e.strip() for e in env_names if e.strip()]
    import re as _re

    secret_like = [
        e
        for e in env_names
        if _re.search(r"(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)", e)
        and e != "LOCAL_PROXY_KEY"
    ]
    hostish = [e for e in env_names if e in {"SSH_AUTH_SOCK", "GOPRIVATE", "GONOSUMDB", "NETRC"}]
    informational = [
        e
        for e in env_names
        if e not in {"LOCAL_PROXY_KEY", "PATH", "HOME", "HOSTNAME", "TERM", "PWD", "SHLVL", "_", "OLDPWD"}
    ]
    return {
        "ok": not forbidden_hits and not secret_like and not hostish,
        "forbidden_hits": forbidden_hits,
        "env_names": env_names,
        "secret_like_env": secret_like,
        "host_env_names": hostish,
        "informational_env": informational,
        "note": "no benchmark/GT/results files or host paths inside the attempt fs; LOCAL_PROXY_KEY is the declared credential",
    }


# ---------------------------------------------------------------------------
# Timeout + export failure (real container lifecycle)
# ---------------------------------------------------------------------------

def check_timeout_and_export(out_dir: Path, image: str, snapshot: Path) -> dict:
    """Force a container timeout through the SAME run_in_container used by
    attempts, and request one bogus artifact path so its docker-cp failure
    must appear in export-report.

    The entrypoint streams a large volume of stdout before sleeping: a silent
    ``sleep`` does not exercise the timeout path (a plain
    ``subprocess.run(timeout=)`` still returns for it), while a chatty agent
    is what the real attempt does. This is the regression guard for the
    2026-10-08 hang where ``docker start -a`` kept the stdout pipe open and the
    run stalled for hours despite ``--timeout``.
    """
    src = str(runner.harness_src())
    if src not in sys.path:
        sys.path.insert(0, src)
    from evaluate.agents.base import run_in_container  # noqa: E402

    rec: dict = {}
    t0 = time.monotonic()
    try:
        run_in_container(
            image,
            [
                "-c",
                "yes '{\"chatter\":\""
                + "x" * 120
                + "\"}' | head -20000; sleep 60",
            ],
            entrypoint="sh",
            src=snapshot,
            timeout=3,
            artifacts_dir=out_dir / "artifacts",
            artifact_paths=[
                ("/etc/hostname", "control-hostname"),
                ("/definitely/missing-c1-probe", "missing-artifact"),
            ],
            io_log_dir=out_dir / "logs",
        )
        rec["timeout"] = {"ok": False, "detail": "container did NOT time out"}
    except RuntimeError as exc:
        wall = time.monotonic() - t0
        logs_ok = (out_dir / "logs" / "stdout.log").exists() and (
            out_dir / "logs" / "stderr.log"
        ).exists()
        rec["timeout"] = {
            "ok": "timed out" in str(exc).lower() and 3 <= wall < 30 and logs_ok,
            "wall_seconds": round(wall, 1),
            "error_head": str(exc)[:200],
            "io_logs_written": logs_ok,
        }

    report_path = out_dir / "artifacts" / "export-report.json"
    report = json.loads(report_path.read_text()) if report_path.exists() else None
    entries = {e["name"]: e for e in report} if report else {}
    ok_exp = (
        report is not None
        and entries.get("control-hostname", {}).get("rc") == 0
        and entries.get("control-hostname", {}).get("exported") is True
        and entries.get("missing-artifact", {}).get("rc") != 0
        and entries.get("missing-artifact", {}).get("exported") is False
    )
    rec["export_failure"] = {
        "ok": ok_exp,
        "report": report,
        "detail": "failed docker cp must appear in export-report.json (observable, not silent)",
    }
    return rec


# ---------------------------------------------------------------------------
# Failure classification on fabricated raw output (unchanged official parser)
# ---------------------------------------------------------------------------

def check_classification(out_dir: Path, meta_kwargs: dict) -> dict:
    """Feed fabricated result.jsonl / error.txt through finalize_attempt:
    refusal, invalid output, missing output must each classify as FAILED
    with the right machine-readable reason — never 'uncertain', never a
    negative. The official parser is the real harness one."""
    import shutil

    if Path(out_dir).exists():
        shutil.rmtree(out_dir)
    Path(out_dir).mkdir(parents=True)
    from .assessment import AttemptMeta
    from .collect import finalize_attempt

    def meta(task_id: str) -> AttemptMeta:
        return AttemptMeta(
            experiment_id="c1-synthetic",
            task_id=task_id,
            attempt_id="run_001",
            cve_id=STUB_CVE,
            snapshot_hash="synthetic",
            model=meta_kwargs["model"],
            prompt_version=meta_kwargs["prompt_version"],
            harness_version=meta_kwargs["harness_version"],
            tool_adapter_version=meta_kwargs["tool_adapter_version"],
            image=meta_kwargs.get("image"),
        )

    def fabricate_ndjson(final_text: str) -> str:
        ev = {"type": "item.completed", "item": {"type": "agent_message", "text": final_text}}
        return json.dumps(ev) + "\n"

    recs: dict[str, dict] = {}

    # --- provider refusal ---------------------------------------------------
    d = out_dir / "refusal" / "task-x" / "run_001"
    d.mkdir(parents=True)
    (d / "result.jsonl").write_text(
        fabricate_ndjson("I'm sorry, I can't help with that request."), "utf-8"
    )
    st, _ = runner_finalize(d, meta("refusal-case"))
    recs["provider_refusal"] = {
        "ok": st.execution == "provider_refusal"
        and st.overall == "failed"
        and st.failure_reason == "provider_refusal",
        "status": st.model_dump(),
    }

    # --- invalid terminal answer -------------------------------------------
    d = out_dir / "invalid" / "task-x" / "run_001"
    d.mkdir(parents=True)
    (d / "result.jsonl").write_text(
        fabricate_ndjson("The code looks fine. No JSON produced."), "utf-8"
    )
    st, _ = runner_finalize(d, meta("invalid-case"))
    recs["invalid_output"] = {
        "ok": st.execution == "invalid_terminal_answer"
        and st.official_parse == "parse_fail"
        and st.overall == "failed"
        and st.failure_reason == "invalid_terminal_answer",
        "status": st.model_dump(),
    }

    # --- no output at all ----------------------------------------------------
    d = out_dir / "nooutput" / "task-x" / "run_001"
    d.mkdir(parents=True)
    st, _ = runner_finalize(d, meta("nooutput-case"))
    recs["no_output"] = {
        "ok": st.execution == "no_output"
        and st.official_parse == "no_result"
        and st.overall == "failed"
        and st.failure_reason == "no_result",
        "status": st.model_dump(),
    }

    # --- timeout error.txt path ---------------------------------------------
    d = out_dir / "timeout-err" / "task-x" / "run_001"
    d.mkdir(parents=True)
    (d / "error.txt").write_text("container timed out after 3s\n", "utf-8")
    st, _ = runner_finalize(d, meta("timeout-case"))
    recs["timeout_error_txt"] = {
        "ok": st.execution == "timeout"
        and st.overall == "failed"
        and st.failure_reason == "timeout",
        "status": st.model_dump(),
    }
    return recs


def runner_finalize(d: Path, meta):
    from .collect import finalize_attempt

    return finalize_attempt(d, meta=meta)


# ---------------------------------------------------------------------------
# Live agent isolation probe (one real codex-c1 exec, both channels)
# ---------------------------------------------------------------------------

LIVE_PROBE_PROMPT = """You are running inside a disposable sandbox as an integration check for <CVE>CVE-2000-0000</CVE>. This is NOT a vulnerability analysis task — do not analyze anything.

Run exactly these probes and report factual outcomes:

A. With your shell/native tools:
  A1. `find / -xdev -name 'go-tasks.jsonl' -o -name 'vex_bench.jsonl' -o -name 'acquisition.json' -o -name 'safety-cases.jsonl' -o -name 'ground_truth*' 2>/dev/null | head -50`
  A2. `ls /work` and `find /work -name '*.jsonl'`
  A3. `cat /etc/hostname` then try `cat /work/../host-marker` and `cat ../eval/c1/status.py`
  A4. `find /tmp -maxdepth 4 -name '*.jsonl' 2>/dev/null` and `ls -la /tmp`
B. With the MCP evidence tools (namespace izyan):
  B1. read_source file="/etc/passwd"
  B2. read_source file="../go-tasks.jsonl"
  B3. read_source file="probe.go"   (positive control — must succeed)
C. `printenv | cut -d= -f1 | sort`

Reply with exactly one JSON object, no prose:
{"checks": [{"id": "A1"|..., "channel": "native"|"mcp", "outcome": "found"|"not_found"|"denied"|"error", "summary": "<=120 chars"}],
 "forbidden_artifacts_found": ["<names>"],
 "mcp_tools_listed": <int>,
 "probe_go_read_ok": <bool>}
"""


def check_live_isolation(
    out_dir: Path, snapshot: Path, *, model: str, timeout: int, meta_kwargs: dict
) -> dict:
    """One real codex-c1 attempt against the synthetic snapshot. Proves that
    the agent under the REAL protocol cannot reach GT/neighbor/results
    through native tools OR through the izyan MCP server."""
    agent = runner.load_agent("codex-c1", model)
    run_dir = out_dir / "live-isolation" / "synthetic-isolation" / "run_001"

    t0 = time.monotonic()
    runner.run_attempt(
        run_dir,
        agent=agent,
        prompt=LIVE_PROBE_PROMPT,
        src_cwd=snapshot,
        language="go",
        timeout=timeout,
    )
    wall = time.monotonic() - t0
    runner.write_controller_artifacts(run_dir, agent, wall)

    audit = runner_collect_audit(run_dir)
    audit_status = {}
    for rec in audit:
        if rec.get("tool") == "read_source":
            args = rec.get("args") or {}
            f = args.get("file", "")
            obs = rec.get("observation") or {}
            audit_status[f] = obs.get("tool_status")

    result_path = run_dir / "result.jsonl"
    agent_json = None
    if result_path.exists():
        text = agent.extract_text(result_path.read_text(encoding="utf-8", errors="replace"))
        # probe output is a plain JSON object (not an assessment payload) —
        # parse tolerantly; extract_json_object demands a "category" key
        try:
            agent_json = json.loads(text)
        except json.JSONDecodeError:
            from .assessment import extract_json_object

            agent_json = extract_json_object(text)

    denied_targets = ("/etc/passwd", "../go-tasks.jsonl")
    mcp_denied = all(
        audit_status.get(f) in {"ERROR", "UNSUPPORTED"} for f in denied_targets
    )
    probe_ok = audit_status.get("probe.go") == "OK"
    forbidden = (agent_json or {}).get("forbidden_artifacts_found") or []
    return {
        "ok": bool(audit)
        and mcp_denied
        and probe_ok
        and not forbidden,
        "wall_seconds": round(wall, 1),
        "mcp_read_source_statuses": audit_status,
        "mcp_call_count": len(audit),
        "agent_report": agent_json,
        "forbidden_artifacts_found": forbidden,
        "run_dir": str(run_dir),
    }


def runner_collect_audit(run_dir: Path) -> list[dict]:
    from .collect import read_audit_jsonl

    return read_audit_jsonl(run_dir / "artifacts" / "izyan-audit" / "tool_calls.jsonl")


# ---------------------------------------------------------------------------
# Battery driver
# ---------------------------------------------------------------------------

def run_battery(
    out_dir: Path,
    *,
    image: str = IMAGE_C1,
    model: str = "gpt-6.1-sol",
    live_timeout: int = 600,
    run_live: bool = True,
    meta_kwargs: Optional[dict] = None,
) -> dict:
    """Run the whole synthetic battery; persist synthetic-checks.json."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    snapshot = write_synthetic_snapshot(out_dir / "snapshot-src")
    meta_kwargs = meta_kwargs or {
        "model": model,
        "prompt_version": "synthetic-probe",
        "harness_version": "unknown",
        "tool_adapter_version": "unknown",
        "image": image,
    }

    results: dict[str, dict] = {"_meta": {
        "image": image,
        "model": model,
        "stub_cve": STUB_CVE,
        "started_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }}

    def guarded(name: str, fn) -> dict:
        """A crashed check is a check failure, never a lost check."""
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - record, don't abort battery
            logger.exception("synthetic check %s crashed", name)
            return {f"{name}.__crashed__": {"ok": False, "crashed": str(exc)[:500]}}

    # MCP over stdio, production-equivalent session (--allow-exec as in C1)
    mcp_dir = out_dir / "mcp-allowexec"
    mcp_dir.mkdir(parents=True, exist_ok=True)
    recs = guarded(
        "allowexec.mcp",
        lambda: check_mcp(mcp_dir, image, snapshot, allow_exec=True),
    )
    for k, v in recs.items():
        results[f"allowexec.{k}"] = v

    # MCP exec gate: same session WITHOUT --allow-exec
    gate_dir = out_dir / "mcp-noexec"
    gate_dir.mkdir(parents=True, exist_ok=True)
    recs2 = guarded(
        "noexec.mcp", lambda: check_mcp(gate_dir, image, snapshot, allow_exec=False)
    )
    results["noexec.mcp_exec_gate"] = recs2.get("mcp_exec_gate", recs2)

    env_file = Path(runner.harness_src()).parent / "env" / "codex" / "codex.env"
    fs_dir = out_dir / "fs"
    fs_dir.mkdir(parents=True, exist_ok=True)
    results["container_fs_allowlist"] = guarded(
        "container_fs_allowlist",
        lambda: check_container_fs(
            fs_dir, image, snapshot, env_file=env_file if env_file.exists() else None
        ),
    )
    results.update(
        guarded(
            "timeout_export",
            lambda: check_timeout_and_export(out_dir / "timeout", image, snapshot),
        )
    )
    results.update(
        guarded(
            "classification",
            lambda: check_classification(out_dir / "classification", meta_kwargs),
        )
    )

    if run_live:
        results["live_isolation_probe"] = guarded(
            "live_isolation_probe",
            lambda: check_live_isolation(
                out_dir,
                snapshot,
                model=model,
                timeout=live_timeout,
                meta_kwargs=meta_kwargs,
            ),
        )

    summary: dict[str, Optional[bool]] = {}
    crashed: list[str] = []
    for name, r in results.items():
        if not isinstance(r, dict):
            continue
        if "ok" in r:
            summary[name] = r.get("ok")
            continue
        # guarded() stores a crash as {"<name>.__crashed__": {"ok": False, ...}}.
        # A crashed check is a FAILURE, never a silent pass: record it explicitly
        # so it cannot be dropped from the summary (and never yields all_ok=True).
        crash_key = f"{name}.__crashed__"
        if crash_key in r:
            crashed.append(name)
            summary[name] = False
    results["_summary"] = {
        "checks": summary,
        "crashed": crashed,
        "all_ok": bool(summary) and not crashed and all(v is True for v in summary.values()),
        "failed": [k for k, v in summary.items() if not v],
    }
    (out_dir / "synthetic-checks.json").write_text(
        json.dumps(results, indent=2, default=str) + "\n", encoding="utf-8"
    )
    return results

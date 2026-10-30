"""Task 5 phase 5.0 — historical freeze and boundary audit (plan §6).

Indexes — read-only — every evidence root Task 5 will cite, and emits:

- ``task4-reference.json``       — cohort inventory: role, run roots,
  model/prompt/agent, attempt counts, missing tasks, admission class
  (matched / partial / contaminated / smoke-probe / diagnostic), the
  Task-4 headline metrics and limitations verbatim, and the MCP ERROR
  accounting re-counted from the actual audit sinks (reported vs
  recounted, residuals kept raw);
- ``task4-artifact-sha256.txt``  — sha256 manifest of the frozen docs,
  prompts, C1 freeze assets and both harness patches;
- ``access-audit.md``            — mount/config/prompt boundary audit:
  what reaches the agent container, what never does, and which Task-4
  synthetic checks already proved the negative controls.

Historical roots are NEVER written to — every stat/hash is a read.
Contaminated/capacity/timeout-bug cohorts are marked excluded.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import time
from pathlib import Path
from typing import Optional

from . import collect as collect_mod

_REPO_ROOT = Path(__file__).resolve().parents[2]

# Frozen Task 4 provenance pins (plan §6 — recorded verbatim, plus a
# re-verification pass so drift is visible, not silently trusted).
PINNED = {
    "harness_commit_task4": "c71f512a3304d1a0d0d9f5e19e8dbc06e9f1dc93",
    "task4_patch_sha256":
        "7c47f5c39b94b862cfc576f32540400a3001b64740d81667ba5dbc84c05b0840",
    "izyan_commit_task4": "0a9b404ab8d69d1bf9200e0f94f71627a2b656c4",
}

RESULTS_ROOT = _REPO_ROOT / "results" / "task4-c1"

# Task-4 reported MCP accounting (task4-qwen-plain-vs-tools.md §5) —
# recounted below from the audit sinks; a mismatch is a finding, not an
# edit to the report.
REPORTED_MCP = {
    "total_calls": 513,
    "error": 100,
    "unsupported": 2,
    "context_canceled": 65,
    "govulncheck_missing": 8,
    "go_mod_updates_needed": 5,
}

# Reported headline outcomes (audit projection; official differs where
# parse_fail hid categories — kept verbatim, never recomputed into them).
REPORTED_QWEN = {
    "q36_plain": {"fs": 1, "recall": "6/7", "scr": "19/23", "repeats": 1},
    "q36_tools": {"fs": 3, "recall": "4/7", "scr": "20/23", "repeats": 1},
    "q38_plain": {"fs": 0, "recall": "7/7", "scr": "20/23",
                  "repeats": 1,
                  "note": "audit-projection after full-JSON parse repair"},
    "q38_tools": {"fs": 3, "recall": "4/7", "scr": "21/23", "repeats": 1},
}

# Historical cohorts (plan §6). ``model_level`` is the dir the official
# parser iterates (<task_id>/run_NNN parents); ``root`` is the cohort top.
COHORTS: list[dict] = [
    {
        "id": "A_izyan_baseline",
        "role": "deterministic_baseline_A",
        "root": "/tmp/vexbench-baseline/runs/external-baseline-1",
        "doc": "eval/baselines/vexbench/external-baseline-1.md",
        "admission": "frozen_reference",
    },
    {
        "id": "B1_codex_plain",
        "role": "official_plain_codex_3x",
        "root": "/tmp/vexbench-plain/full",
        "model_level": "/tmp/vexbench-plain/full/results/"
                       "c0a5c8458b77/codex/gpt-6.1-sol",
        "doc": "eval/baselines/vexbench/plain-agent-baseline-1.md",
        "admission": "frozen_reference",
    },
    {
        "id": "B2_gemini_host",
        "role": "plain_gemini_host_run",
        "root": "/tmp/vexbench-plain/b2",
        "admission": "excluded_contaminated",
        "note": "host process, GT read in 11/29 transcripts "
                "(plain-agent-baseline-1.md §7) — descriptive only",
    },
    {
        "id": "B2_iso_gemini",
        "role": "isolated_gemini_rerun",
        "root": "/tmp/vexbench-gemini-iso",
        "model_level": "/tmp/vexbench-gemini-iso/smoke-results/"
                       "c0a5c8458b77/opencode/gemini-3.8-flash-high",
        "admission": "excluded_retry_composite",
        "note": "7 selective retries under run_001 + 3 filter truncations "
                "(§8) — not a first-attempt baseline",
    },
    {
        "id": "B3_qwen_host",
        "role": "plain_qwen_host_run",
        "root": "/tmp/vexbench-plain/b3-qwen-subagent",
        "admission": "excluded_no_isolation",
        "note": "host subagent process, no container isolation",
    },
    {
        "id": "q36_plain",
        "role": "task5_p0_historical",
        "root": "/tmp/vexbench-qwen-iso/q36",
        "model_level": "/tmp/vexbench-qwen-iso/q36/c0a5c8458b77/"
                       "opencode/qwen3.6-35b",
        "agent": "opencode", "model": "qwen3.6-35b",
        "prompt": "vuln", "mcp": False, "repeats": 1,
        "admission": "matched_evidence",
        "note": "n=1, timeout=1800 — historical comparator only",
        "results_jsonl": "/tmp/vexbench-qwen-iso/q36/final/results.jsonl",
    },
    {
        "id": "q38_plain",
        "role": "historical_second_cohort",
        "root": "/tmp/vexbench-qwen-iso/q38",
        "model_level": "/tmp/vexbench-qwen-iso/q38/c0a5c8458b77/"
                       "opencode/qwen3.8-27b",
        "agent": "opencode", "model": "qwen3.8-27b",
        "prompt": "vuln", "mcp": False, "repeats": 1,
        "admission": "matched_evidence",
        "note": "separate cohort — never pooled with q36 (plan §2)",
    },
    {
        "id": "q36_tools",
        "role": "task4_tools_arm",
        "root": str(RESULTS_ROOT / "qwen-tools-full/q36"),
        "model_level": str(RESULTS_ROOT / "qwen-tools-full/q36/"
                           "d748ca6dd273/opencode-c1/qwen3.6-35b"),
        "agent": "opencode-c1", "model": "qwen3.6-35b",
        "prompt": "vuln_tools", "mcp": True, "repeats": 1,
        "admission": "matched_evidence",
    },
    {
        "id": "q38_tools",
        "role": "task4_tools_arm",
        "root": str(RESULTS_ROOT / "qwen-tools-full/q38"),
        "model_level": str(RESULTS_ROOT / "qwen-tools-full/q38/"
                           "d748ca6dd273/opencode-c1/qwen3.8-27b"),
        "agent": "opencode-c1", "model": "qwen3.8-27b",
        "prompt": "vuln_tools", "mcp": True, "repeats": 1,
        "admission": "matched_evidence",
    },
    {
        "id": "codex_b1p_partial",
        "role": "task4_codex_control",
        "root": str(RESULTS_ROOT / "b1p-full"),
        "model_level": str(RESULTS_ROOT / "b1p-full/c45dfc39af34/"
                           "codex-b1p/gpt-6.1-sol"),
        "agent": "codex-b1p", "model": "gpt-6.1-sol",
        "prompt": "vuln_assess", "mcp": False, "repeats": 3,
        "admission": "partial_excluded",
        "note": "8/90 attempts — stopped partial cohort "
                "(task4-codex-partial-state.md); never matched evidence",
    },
    {
        "id": "codex_c1_partial",
        "role": "task4_codex_tools",
        "root": str(RESULTS_ROOT / "c1-full"),
        "model_level": str(RESULTS_ROOT / "c1-full/6eda998ea66c/"
                           "codex-c1/gpt-6.1-sol"),
        "agent": "codex-c1", "model": "gpt-6.1-sol",
        "prompt": "vuln_c1", "mcp": True, "repeats": 3,
        "admission": "partial_excluded",
        "note": "6/90 attempts — stopped partial cohort "
                "(task4-codex-partial-state.md); never matched evidence",
    },
    {
        "id": "codex_c1_timeout_bug",
        "role": "task4_defect_artifact",
        "root": str(RESULTS_ROOT / "c1-full-timeout-bug"),
        "admission": "excluded_harness_defect",
        "note": "run under the pre-fix subprocess timeout bug — "
                "attempts ran past --timeout; excluded from all evidence",
    },
    {
        "id": "codex_c1_capacity",
        "role": "task4_contaminated_artifact",
        "root": str(RESULTS_ROOT / "c1-full-capacity-contaminated"),
        "admission": "excluded_provider_capacity",
        "note": "provider 'at capacity' contamination — not evidence",
    },
    {
        "id": "scoring_dryrun",
        "role": "task4_tooling_dryrun",
        "root": str(RESULTS_ROOT / "_scoring-dryrun-contaminated"),
        "admission": "excluded_scoring_dryrun",
    },
    {
        "id": "c1_smokes",
        "role": "task4_technical_smoke",
        "root": str(RESULTS_ROOT / "c1-smoke"),
        "admission": "smoke_only",
        "note": "diagnostic admission — never pooled into scored runs",
    },
    {
        "id": "c1_smoke_opencode",
        "role": "task4_technical_smoke",
        "root": str(RESULTS_ROOT / "c1-smoke-opencode"),
        "admission": "smoke_only",
    },
    {
        "id": "qwen_arms_smoke",
        "role": "task4_technical_smoke",
        "root": str(RESULTS_ROOT / "qwen-arms-smoke"),
        "admission": "smoke_only",
        "note": "cached-smoke exposure is recorded, not reused (plan §6)",
    },
    {
        "id": "c1_smoke_qwen_arms",
        "role": "task4_technical_smoke",
        "root": str(RESULTS_ROOT / "c1-smoke-qwen-arms"),
        "admission": "smoke_only",
    },
    {
        "id": "flaky_probe",
        "role": "diagnostic_probe",
        "root": "/tmp/vexbench-qwen-iso/flaky-probe",
        "admission": "diagnostic_only",
    },
    {
        "id": "risk_probe",
        "role": "diagnostic_probe",
        "root": "/tmp/vexbench-qwen-iso/risk-probe",
        "admission": "diagnostic_only",
    },
]

# Frozen repo-side assets hashed into task4-artifact-sha256.txt.
_FROZEN_REPO_FILES = [
    "eval/baselines/vexbench/external-baseline-1.md",
    "eval/baselines/vexbench/plain-agent-baseline-1.md",
    "eval/baselines/vexbench/task4-qwen-plain-vs-tools.md",
    "eval/baselines/vexbench/task4-codex-partial-state.md",
    "eval/c1/freeze/manifest.json",
    "eval/c1/freeze/smoke-summary.json",
    "eval/c1/freeze/synthetic-checks.json",
    "eval/c1/harness/vexbench-agent-ctl-c1.patch",
    "eval/c1/harness/README.md",
    "eval/vexbench-prompts/official-vuln-c0a5c8458b77.txt",
    "eval/vexbench-prompts/vuln_assess-c45dfc39af34.txt",
    "eval/vexbench-prompts/vuln_c1-6eda998ea66c.txt",
    "eval/vexbench-prompts/README.md",
    "eval/task5/harness/vexbench-agent-ctl-task5.patch",
    "eval/task5/harness/README.md",
    "eval/task5/prompts/vuln_safety_v1.txt",
    "eval/task5/prompts/vuln_safety_v1_tools.txt",
    "eval/task5/prompts/hashes.json",
    "eval/task5/prompts/p1-t1.diff",
    "docs/dev/specs/2026-10-09-task5-prompt-tools-gate-comparison-v2.md",
    "docs/dev/specs/task5-prompt-tools-gate-spec.md",
    "docs/dev/plans/2026-10-09-task5-implementation-plan.md",
]


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _git(repo: Path, *args: str, check: bool = False):
    cp = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True, text=True, check=check)
    return cp.stdout.strip()


def _attempt_inventory(model_level: Path,
                       task_ids: list[str]) -> dict:
    """Attempt counts under a model-level run dir (read-only)."""
    model_level = Path(model_level)
    inv = {
        "model_level": str(model_level),
        "exists": model_level.is_dir(),
        "attempts": 0,
        "with_result": 0,
        "with_error": 0,
        "finalized": 0,
        "task_ids_present": [],
        "missing_task_ids": [],
        "unexpected_task_ids": [],
    }
    if not model_level.is_dir():
        inv["missing_task_ids"] = list(task_ids)
        return inv
    attempts = collect_mod.discover_attempts(model_level)
    seen = {t for t, _, _ in attempts}
    inv["attempts"] = len(attempts)
    inv["task_ids_present"] = sorted(seen)
    inv["missing_task_ids"] = [t for t in task_ids if t not in seen]
    inv["unexpected_task_ids"] = sorted(
        t for t in seen if task_ids and t not in task_ids)
    for _t, _a, run_dir in attempts:
        if ((run_dir / "result.jsonl").is_file()
                or (run_dir / "result.json").is_file()):
            inv["with_result"] += 1
        if (run_dir / "error.txt").is_file():
            inv["with_error"] += 1
        if (run_dir / "status.json").is_file():
            inv["finalized"] += 1
    return inv


def _verify_pins(harness_dir: Path, worktree: Path) -> dict:
    """Re-check the recorded Task-4 provenance pins against reality."""
    out: dict = {"pins": dict(PINNED), "checks": {}}
    head = _git(harness_dir, "rev-parse", "HEAD")
    out["checks"]["harness_head_now"] = head
    out["checks"]["harness_pin_is_ancestor"] = (
        subprocess.run(
            ["git", "-C", str(harness_dir), "merge-base",
             "--is-ancestor", PINNED["harness_commit_task4"], "HEAD"],
            capture_output=True).returncode == 0)
    c1_patch = worktree / "eval/c1/harness/vexbench-agent-ctl-c1.patch"
    if c1_patch.is_file():
        actual = _sha256_file(c1_patch)
        out["checks"]["task4_patch_sha256_match"] = (
            actual == PINNED["task4_patch_sha256"])
        out["checks"]["task4_patch_sha256_actual"] = actual
    else:
        out["checks"]["task4_patch_sha256_match"] = None
    izyan_head = _git(worktree, "rev-parse", "HEAD")
    out["checks"]["izyan_head_now"] = izyan_head
    out["checks"]["izyan_pin_is_ancestor"] = (
        subprocess.run(
            ["git", "-C", str(worktree), "merge-base",
             "--is-ancestor", PINNED["izyan_commit_task4"], "HEAD"],
            capture_output=True).returncode == 0)
    c1_manifest_path = worktree / "eval/c1/freeze/manifest.json"
    if c1_manifest_path.is_file():
        fm = json.loads(c1_manifest_path.read_text(encoding="utf-8"))
        out["checks"]["c1_manifest"] = {
            "izyan_commit": fm.get("izyan", {}).get("commit"),
            "harness_commit": fm.get("harness", {}).get("commit"),
            "dirty_at_freeze": fm.get("izyan", {}).get("dirty"),
            "note": ("Codex-specific model/prompt fields in the frozen "
                     "manifest are Codex provenance, not Qwen provenance "
                     "(plan §6)"),
        }
    return out


def build_reference(
    *,
    harness_dir: Path,
    worktree: Path = _REPO_ROOT,
    tasks_path: Optional[Path] = None,
) -> dict:
    """The phase-5.0 cohort inventory + provenance verification."""
    task_ids: list[str] = []
    if tasks_path and Path(tasks_path).is_file():
        task_ids = [
            json.loads(l)["task_id"]
            for l in Path(tasks_path).read_text().splitlines()
            if l.strip()]

    cohorts = []
    for spec in COHORTS:
        entry = {k: v for k, v in spec.items() if k != "model_level"}
        root = Path(spec["root"])
        entry["root_exists"] = root.is_dir()
        if spec.get("model_level"):
            entry["attempts"] = _attempt_inventory(
                Path(spec["model_level"]), task_ids)
        elif root.is_dir():
            # non-model-level roots: count attempt dirs wherever they are
            found = collect_mod.discover_attempts(root)
            entry["attempts"] = {
                "model_level": None,
                "attempts": len(found),
                "task_ids_present": sorted({t for t, _, _ in found}),
            }
        if spec.get("results_jsonl"):
            rp = Path(spec["results_jsonl"])
            entry["results_jsonl"] = {
                "path": str(rp),
                "exists": rp.is_file(),
                "sha256": _sha256_file(rp) if rp.is_file() else None,
            }
        cohorts.append(entry)

    # MCP ERROR accounting — recounted from the real audit sinks of the
    # two tools arms (plan §6: preserve ALL errors incl. residuals).
    mcp = {}
    for cid in ("q36_tools", "q38_tools"):
        spec = next(c for c in COHORTS if c["id"] == cid)
        root = Path(spec["root"])
        mcp[cid] = (collect_mod.mcp_error_accounting(root)
                    if root.is_dir() else {"missing": str(root)})
    totals = {
        "total_calls": sum(m.get("total_calls", 0) for m in mcp.values()),
        "error": sum(m.get("by_tool_status", {}).get("ERROR", 0)
                     for m in mcp.values()),
        "unsupported": sum(m.get("by_tool_status", {}).get("UNSUPPORTED", 0)
                           for m in mcp.values()),
        "context_canceled": sum(
            m.get("error_classes", {}).get("context_canceled", 0)
            for m in mcp.values()),
        "govulncheck_missing": sum(
            m.get("error_classes", {}).get("govulncheck_missing", 0)
            for m in mcp.values()),
        "go_mod_updates_needed": sum(
            m.get("error_classes", {}).get("go_mod_updates_needed", 0)
            for m in mcp.values()),
    }
    reported_vs = {
        k: {"reported": REPORTED_MCP[k], "recounted": totals.get(k)}
        for k in REPORTED_MCP
    }

    return {
        "schema": "task5-freeze/1",
        "frozen_at_utc": time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "purpose": (
            "phase 5.0 freeze: read-only index of Task 3/4 evidence; "
            "original names/roots retained, nothing rewritten — new "
            "indexes live only under eval/task5/freeze/"),
        "provenance": _verify_pins(Path(harness_dir), Path(worktree)),
        "historical_qwen_headline": REPORTED_QWEN,
        "mcp_error_accounting": {
            "reported": REPORTED_MCP,
            "recounted_totals": totals,
            "reported_vs_recounted": reported_vs,
            "per_cohort": mcp,
            "policy": ("all raw records preserved under the cohort roots; "
                       "unclassified residuals stay listed verbatim, not "
                       "just the summary buckets"),
        },
        "codex_status": {
            "b1p": "PARTIAL 8/90", "c1": "PARTIAL 6/90",
            "note": ("frozen as-is per task4-codex-partial-state.md; "
                     "capacity-contaminated and timeout-bug cohorts are "
                     "excluded from matched evidence"),
        },
        "cohorts": cohorts,
        "limitations": [
            "historical Qwen cohorts: n=1 per arm, timeout=1800 — "
            "reference only, not a causal baseline (plan §2)",
            "q38_plain 0/7 FS is a parser-audit projection, not the "
            "official-strict score; risky repeats were observed",
            "P0↔P1 will pair only observed attempts (run_001); missing "
            "repeats are never invented",
            "Codex cohorts stopped partial (6/90, 8/90) — excluded from "
            "matched evidence",
            "B2 host run contaminated (GT in transcripts); B2-ISO is a "
            "retry composite — neither is a valid blind baseline",
        ],
    }


def write_artifact_hashes(out_dir: Path, worktree: Path) -> Path:
    """``task4-artifact-sha256.txt`` — one sha256 line per frozen file."""
    lines = [
        "# task4-artifact-sha256.txt — frozen evidence digests",
        "# generated by eval/vexbench_task5.py freeze-history "
        f"({time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())})",
        "# missing files are marked MISSING, never dropped silently",
    ]
    for rel in _FROZEN_REPO_FILES:
        p = Path(worktree) / rel
        if p.is_file():
            lines.append(f"{_sha256_file(p)}  {rel}")
        else:
            lines.append(f"MISSING  {rel}")
    dest = Path(out_dir) / "task4-artifact-sha256.txt"
    dest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return dest


def write_access_audit(out_dir: Path, worktree: Path) -> Path:
    """``access-audit.md`` — the mount/prompt/config boundary audit."""
    checks_path = worktree / "eval/c1/freeze/synthetic-checks.json"
    checks = {}
    if checks_path.is_file():
        checks = json.loads(checks_path.read_text(encoding="utf-8"))
    trav = checks.get("allowexec.mcp_traversal") or {}
    fsok = checks.get("container_fs_allowlist", {})
    text = f"""# Task 5 access audit — agent/GT isolation boundary (phase 5.0)

Generated {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} by
`eval/vexbench_task5.py freeze-history`. Sources: the Task-4 synthetic
battery (`eval/c1/freeze/synthetic-checks.json`), the opencode adapter
sources (`src/evaluate/agents/opencode*.py`), and the C1 harness README.

## What reaches the attempt container

| Channel | Content | Boundary |
|---|---|---|
| `/work` | `docker cp` of the snapshot checkout only (`repos/<owner>/<repo>/<commit>/`) | no `.git` is copied into the image namespace beyond what acquisition produced; nothing outside the snapshot tree |
| `/tmp/prompt.txt` | rendered prompt = template + `{{cve_id}}` only | task_id/repo/commit/GT never rendered (asserted in smoke + unit tests) |
| provider config | synthesized `opencode.json` mounted under the attempt's artifacts dir | api key via `{{env:OPENAI_API_KEY}}` interpolation — never a literal secret in artifacts |
| env | `opencode.env` credentials only | `container_fs_allowlist` check: no benchmark/GT/results files or host paths inside the attempt FS (synthetic evidence: `forbidden_hits={fsok.get('forbidden_hits')}`, `ok={fsok.get('ok')}`) |
| MCP audit | `izyan-audit/tool_calls.jsonl` written inside the container, exported to artifacts | host-side results are never mounted in |

## What never reaches the agent

- `ground_truth`, `ground_truth_category`, reference PR — the harness
  renders ONLY `{{cve_id}}` into the prompt (`run.py`); the tasks JSONL
  lives host-side at `/tmp/vexbench-agent-ctl/benchmark/` and is not
  mounted.
- Host results/foreign sessions — no bind mounts of `results/` or other
  run roots into the container.
- Neighbour snapshots — only the task's own snapshot is copied.

## MCP traversal evidence (Task-4 synthetic battery, frozen)

`mcp_traversal` probe on `izyan-evidence-tools` (allowexec image):
statuses `{json.dumps(trav.get('statuses'))}` — `../`, absolute `/etc`,
`/work/..` escapes all rejected with `tool_status=ERROR`; a
`search_source('ground_truth')` probe matched
`{trav.get('gt_search_matches')}` files inside the snapshot.

Per-call audit fields recorded: tool, args digest, tool_status,
completeness, subject/scope, limitations, latency, adapter version —
`artifacts/izyan-audit/tool_calls.jsonl` per attempt; missing fields
remain null, never invented.

## Known boundary failures from history (frozen, not re-litigated)

- B2 (Gemini host subagent) read GT in 11/29 transcripts — host-side
  subagents have no FS isolation; cohort excluded from blind evidence.
- Qwen ISO runs: `/tmp/vexbench-baseline` is absent inside the container
  (verified: `find / -name go-tasks.jsonl` → nothing; the read-only
  provider config mount is the only exception, per baseline doc §8).

## Policy carried into Task 5

- Smoke task selection happens controller-side before any answer is
  examined; labels are never rendered to the agent.
- Scorer/GT stay controller-only; any future Gate receives allowlisted
  projections only (manifest `gt_policy`).
"""
    dest = Path(out_dir) / "access-audit.md"
    dest.write_text(text, encoding="utf-8")
    return dest


def freeze_history(
    *,
    harness_dir: Path,
    out_dir: Path,
    worktree: Path = _REPO_ROOT,
    tasks_path: Optional[Path] = None,
) -> dict:
    """Emit all three freeze artifacts; returns the reference doc."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ref = build_reference(
        harness_dir=Path(harness_dir),
        worktree=Path(worktree),
        tasks_path=tasks_path,
    )
    (out_dir / "task4-reference.json").write_text(
        json.dumps(ref, indent=2) + "\n", encoding="utf-8")
    write_artifact_hashes(out_dir, Path(worktree))
    write_access_audit(out_dir, Path(worktree))
    return ref

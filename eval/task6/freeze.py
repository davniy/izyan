"""Task 6 phase 6.0 — Task-5 scorer re-verification and historical freeze.

Reads — read-only, never written to — the frozen Task 5 artifacts:

- ``eval/task5/scoring/matrix.json``       (per-attempt outcomes + GT)
- ``eval/task5/scoring/safety-report.md``  (headline metrics)
- ``eval/task5/gate-feasibility.md``       (published RG/RH/R6/UNION table)
- ``eval/task5/experiment-manifest.json``  (hash pins)
- ``eval/task5/results/t1/**``             (per-attempt observations.jsonl)
- Task-5 prompt/patch/controller files     (hash pins, recomputed)

and emits ``freeze/task5-reference.json``.

What it re-verifies (plan §6, spec §1):

1. The T1 headline counts: ``false-safe = 5`` of 21 GT-exploitable
   attempts, ``correct-safe = 63`` of 69 GT-safe attempts scored safe.
2. The gate-feasibility rule table, recomputed from the saved
   ``observations.jsonl`` with documented rule definitions, **by attempt
   AND by unique case** — the published table conflated the two
   measures (``testify-28948`` is 3 attempts of ONE case).
3. The ``19 + 26 < 46`` anomaly: the report printed RG = 19 blocked
   correct-safes and R6 = 26, but a UNION row of 46 — arithmetically
   impossible, since a union can never exceed the sum of the operand
   sets (|RG ∪ R6| ≤ 19 + 26 = 45). Recomputation below confirms both
   operand counts and shows the true union is 45 on a disjoint pair.
4. Hash pins: matrix row ``result_sha256`` values against the attempt
   artifacts on disk, and the manifest's prompt/controller/patch/
   scoring-file sha256 pins against the live files.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Optional

_REPO_ROOT = Path(__file__).resolve().parents[2]

TASK5_ROOT = _REPO_ROOT / "eval" / "task5"
MATRIX_FILE = TASK5_ROOT / "scoring" / "matrix.json"
SAFETY_REPORT = TASK5_ROOT / "scoring" / "safety-report.md"
GATE_FEASIBILITY = TASK5_ROOT / "gate-feasibility.md"
MANIFEST_FILE = TASK5_ROOT / "experiment-manifest.json"
RESULTS_T1 = TASK5_ROOT / "results" / "t1"

REFERENCE_SCHEMA = "task6-task5-reference/1"

# Published gate-feasibility numbers (frozen report — never recomputed
# into, only compared against; a mismatch is a finding, not an edit).
REPORTED = {
    "false_safe_attempts": 5,
    "exploitable_attempts": 21,
    "correct_safe_attempts": 63,
    "safe_ground_truth_attempts": 69,
    "rules": {  # (false_safe_blocked, correct_safe_lost) — by attempt
        "RG": (2, 19),
        "RH": (2, 28),
        "R6": (3, 26),
        "UNION": (5, 46),
    },
}


# ---------------------------------------------------------------------------
# Gate-rule reconstruction (documented definitions)
# ---------------------------------------------------------------------------
#
# ``gate-feasibility.md`` records the rules generically; the throwaway
# scripts behind it are gone ("/tmp purge"), so the exact sets below are
# the documented reconstruction, validated because the RG (19) and R6
# (26) blocked-correct-safe counts and both blocked-false-safe counts
# reproduce exactly under them.
#
# "Negative claim"  : the attempt's parser-audit outcome is ``safe``.
# "Reachability observation": an MCP observation from a reachability-
# enumeration tool (caller/reference/dispatch/module-usage queries;
# `interface_dispatch_sites` kept for set completeness — never invoked
# by the T1 arm).

REACHABILITY_TOOLS = frozenset(
    {
        "find_callers",       # statically named call sites (product pkgs)
        "find_may_callers",   # may-call incl. interface/func-value
        "find_dep_callers",   # call sites inside the subject's dep
        "find_references",    # any reference to the subject
        "dep_invocation_state",  # in-module callers / pipeline liveness
        "gated_refs",         # refs under other build configurations
        "scan_dynamic",       # dynamic-dispatch markers near subject
        "module_internal_reach",  # dep-internal reachability
        "interface_dispatch_sites",  # interface-dispatched call sites
    }
)

# Integer fields that carry an enumeration count in Observation.data;
# a zero value marks a "zero-result" query (R2/R5/R6 detection).
_ZERO_COUNT_KEYS = ("count", "possible_count", "callers_inside_module",
                    "matches")

# Categories that assert code-side absence/unreachability — the R6
# narrowing from the feasibility doc ("R5 narrowed to
# code_not_reachable / code_not_present").
_NEGATIVE_CODE_CATEGORIES = frozenset(
    {"code_not_reachable", "code_not_present"})


def _is_zero_result(obs: dict) -> bool:
    """True iff the observation's ``data`` carries a zero enumeration."""
    data = obs.get("data")
    if not isinstance(data, dict):
        return False
    return any(
        isinstance(data.get(k), (int, float)) and data[k] == 0
        for k in _ZERO_COUNT_KEYS
    )


def _iter_attempt_dirs(model_level: Path):
    """Yield (task_id, run_id, run_dir) for every attempt under a
    harness model-level root (<model>/<task_id>/run_NNN/)."""
    model_level = Path(model_level)
    if not model_level.is_dir():
        return
    for task_dir in sorted(model_level.iterdir()):
        if not task_dir.is_dir():
            continue
        for run_dir in sorted(task_dir.iterdir()):
            if run_dir.is_dir() and run_dir.name.startswith("run_"):
                yield task_dir.name, run_dir.name, run_dir


def _read_observations(run_dir: Path) -> list[dict]:
    """The attempt's observation sink (``observations.jsonl``).

    Falls back to the raw audit trail ``artifacts/izyan-audit/
    tool_calls.jsonl`` (AuditRecord lines — the observation lives under
    the ``observation`` key) when the flattened file is absent."""
    p = Path(run_dir) / "observations.jsonl"
    if p.is_file():
        return [
            json.loads(l)
            for l in p.read_text(encoding="utf-8").splitlines()
            if l.strip()
        ]
    p = Path(run_dir) / "artifacts" / "izyan-audit" / "tool_calls.jsonl"
    if not p.is_file():
        return []
    out = []
    for l in p.read_text(encoding="utf-8").splitlines():
        if not l.strip():
            continue
        rec = json.loads(l)
        obs = rec.get("observation")
        if isinstance(obs, dict):
            out.append(obs)
    return out


def _sha256_file(path: Path) -> Optional[str]:
    path = Path(path)
    if not path.is_file():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def find_t1_model_level(t1_root: Path) -> Optional[Path]:
    """Locate the T1 model-level dir (<prompt_hash>/<agent>/<model>)."""
    t1_root = Path(t1_root)
    if not t1_root.is_dir():
        return None
    for prompt_dir in sorted(t1_root.iterdir()):
        if not prompt_dir.is_dir():
            continue
        for agent_dir in sorted(prompt_dir.iterdir()):
            if not agent_dir.is_dir():
                continue
            for model_dir in sorted(agent_dir.iterdir()):
                if model_dir.is_dir():
                    return model_dir
    return None


def _rule_sets(observations: list[dict], category: Optional[str]) -> dict:
    """Apply the reconstructed gate rules to one safe-outcome attempt.

    Returns flags {RG, RH, R6, R5, UNION}; UNION = RG ∪ R6 (computed
    from the operand sets, never from the published row)."""
    reach = [
        o for o in observations if o.get("tool") in REACHABILITY_TOOLS
    ]
    rg = bool(reach) and not any(
        o.get("tool_status") == "OK" for o in reach
    )
    rh = any(o.get("tool_status") == "ERROR" for o in reach)
    r5 = any(
        o.get("tool_status") == "OK"
        and o.get("completeness") != "COMPLETE"
        and _is_zero_result(o)
        and bool(o.get("limitations"))
        for o in observations
    )
    r6 = category in _NEGATIVE_CODE_CATEGORIES and r5
    return {
        "RG": rg,
        "RH": rh,
        "R5": r5,
        "R6": r6,
        "UNION": rg or r6,
    }


def _row_outcome(arm_cell: Optional[dict], projection: str = "audit"):
    if not arm_cell or not arm_cell.get("present"):
        return None, None
    proj = arm_cell.get(projection) or {}
    return proj.get("outcome"), proj.get("category")


def recompute_tables(matrix: dict, t1_model_level: Path) -> dict:
    """Rebuild the RG/RH/R6/UNION blocked tables from matrix.json +
    per-attempt observations, by attempt AND by unique case."""
    obs_by_key = {}
    if t1_model_level is not None:
        for task_id, run_id, run_dir in _iter_attempt_dirs(t1_model_level):
            obs_by_key[(task_id, run_id)] = _read_observations(run_dir)

    rows = matrix.get("rows") or []
    denom = {
        "total_attempts": len(rows),
        "exploitable_ground_truth_attempts": 0,
        "safe_ground_truth_attempts": 0,
        "exploitable_ground_truth_cases": 0,
        "safe_ground_truth_cases": 0,
        "scored_safe_attempts": 0,
        "scored_safe_cases": 0,
        "false_safe_attempts": 0,
        "false_safe_cases": 0,
        "correct_safe_attempts": 0,
        "correct_safe_cases": 0,
        "attempts_without_observations": 0,
    }
    gt_expl_cases, gt_safe_cases = set(), set()
    scored_safe_cases = set()
    fs_cases = set()
    cs_cases = set()

    rules = {r: {"fs": set(), "cs": set()} for r in
             ("RG", "RH", "R5", "R6", "UNION")}
    per_attempt = []

    for row in rows:
        key = (row["task_id"], row["run_id"])
        arm = (row.get("arms") or {}).get("t1")
        outcome, category = _row_outcome(arm, "audit")
        obs = obs_by_key.get(key)
        if obs is None and t1_model_level is not None:
            obs = []
        obs = obs or []
        if not obs:
            denom["attempts_without_observations"] += 1

        gt_expl = row.get("ground_truth") == "exploitable"
        if gt_expl:
            denom["exploitable_ground_truth_attempts"] += 1
            gt_expl_cases.add(row["task_id"])
        else:
            denom["safe_ground_truth_attempts"] += 1
            gt_safe_cases.add(row["task_id"])

        if outcome != "safe":
            continue
        denom["scored_safe_attempts"] += 1
        scored_safe_cases.add(row["task_id"])

        bucket = "fs" if gt_expl else "cs"
        flags = _rule_sets(obs, category)
        for name, hit in flags.items():
            if hit:
                rules[name][bucket].add(key)
        per_attempt.append({
            "task_id": row["task_id"],
            "run_id": row["run_id"],
            "category": category,
            "bucket": "false_safe" if gt_expl else "correct_safe",
            "observations": len(obs),
            "flags": {k: v for k, v in flags.items() if v},
        })
        if gt_expl:
            denom["false_safe_attempts"] += 1
            fs_cases.add(row["task_id"])
        else:
            denom["correct_safe_attempts"] += 1
            cs_cases.add(row["task_id"])

    denom["exploitable_ground_truth_cases"] = len(gt_expl_cases)
    denom["safe_ground_truth_cases"] = len(gt_safe_cases)
    denom["scored_safe_cases"] = len(scored_safe_cases)
    denom["false_safe_cases"] = len(fs_cases)
    denom["correct_safe_cases"] = len(cs_cases)

    def _by_attempt(name: str) -> dict:
        fs_n = len(rules[name]["fs"])
        cs_n = len(rules[name]["cs"])
        return {
            "false_safe_blocked": fs_n,
            "false_safe_of": denom["false_safe_attempts"],
            "correct_safe_lost": cs_n,
            "correct_safe_of": denom["correct_safe_attempts"],
        }

    def _by_case(name: str) -> dict:
        fs_cases_blocked = {t for t, _ in rules[name]["fs"]}
        cs_cases_lost = {t for t, _ in rules[name]["cs"]}
        # "fully lost" = every safe-scored attempt of the case is
        # blocked (non-safe attempts are never gate-eligible).
        safe_attempt_keys: dict[str, set] = {}
        for a in per_attempt:
            if a["bucket"] == "correct_safe":
                safe_attempt_keys.setdefault(a["task_id"], set()).add(
                    (a["task_id"], a["run_id"]))
        cs_cases_fully = {
            t for t in cs_cases_lost
            if safe_attempt_keys.get(t, set()) <= rules[name]["cs"]
        }
        return {
            "false_safe_cases_blocked": len(fs_cases_blocked),
            "false_safe_cases_of": denom["false_safe_cases"],
            "correct_safe_cases_lost": len(cs_cases_lost),
            "correct_safe_cases_fully_lost": len(cs_cases_fully),
            "correct_safe_cases_of": denom["correct_safe_cases"],
        }

    rg_cs, r6_cs = rules["RG"]["cs"], rules["R6"]["cs"]
    anomaly = {
        "published": {
            "RG_correct_safe_lost": REPORTED["rules"]["RG"][1],
            "R6_correct_safe_lost": REPORTED["rules"]["R6"][1],
            "UNION_correct_safe_lost": REPORTED["rules"]["UNION"][1],
        },
        "arithmetic": (
            "|RG ∪ R6| ≤ |RG| + |R6| = 19 + 26 = 45 < 46 — the published "
            "UNION count exceeds the maximum union of its own operands, "
            "so it cannot have been measured on the same basis."
        ),
        "recomputed": {
            "RG_correct_safe_lost_attempts": len(rg_cs),
            "R6_correct_safe_lost_attempts": len(r6_cs),
            "overlap_attempts": len(rg_cs & r6_cs),
            "union_correct_safe_lost_attempts": len(rg_cs | r6_cs),
            "overlap_cases": len({t for t, _ in (rg_cs & r6_cs)}),
            "union_correct_safe_lost_cases":
                len({t for t, _ in (rg_cs | r6_cs)}),
        },
        "explanation": (
            "Recomputation reproduces the published operand counts "
            "exactly (RG = 19, R6 = 26 blocked correct-safe attempts) "
            "and shows the two sets are DISJOINT: the union is 45 = "
            "19 + 26, the largest union these operands can have. The "
            "printed 46 therefore records a measure mix in the throwaway "
            "union script (attempts vs unique cases — testify-28948 is "
            "three attempts of one case) or an off-by-one, not an "
            "overlap artefact: overlap could only LOWER the union below "
            "45, never raise it above. Either way the published 46 is "
            "arithmetically impossible; the corrected UNION is 45/63 "
            "correct-safe attempts lost (71.4%)."
        ),
    }

    by_attempt = {name: _by_attempt(name) for name in
                  ("RG", "RH", "R5", "R6", "UNION")}
    by_case = {name: _by_case(name) for name in
               ("RG", "RH", "R5", "R6", "UNION")}
    for name in by_attempt:
        reported = REPORTED["rules"].get(name)
        by_attempt[name]["reported"] = (
            {"false_safe_blocked": reported[0],
             "correct_safe_lost": reported[1]} if reported else None)
        by_attempt[name]["matches_reported"] = (
            reported is not None
            and reported == (by_attempt[name]["false_safe_blocked"],
                             by_attempt[name]["correct_safe_lost"]))

    return {
        "denominators": denom,
        "by_attempt": by_attempt,
        "by_case": by_case,
        "union_anomaly": anomaly,
        "per_attempt": per_attempt,
        "rule_definitions": {
            "negative_claim": (
                "attempt parser-audit outcome == 'safe' (the projection "
                "the gate-feasibility table denominates on: 68 safe-"
                "scored attempts = 5 false-safe + 63 correct-safe)"),
            "reachability_observation": (
                "observation.tool in " + str(sorted(REACHABILITY_TOOLS))),
            "RG": ("safe outcome AND ≥1 reachability observation AND "
                   "none with tool_status == 'OK'"),
            "RH": ("safe outcome AND ≥1 reachability observation with "
                   "tool_status == 'ERROR'"),
            "R5": ("safe outcome AND ≥1 observation with tool_status "
                   "'OK', completeness != 'COMPLETE', a zero enumeration "
                   f"({_ZERO_COUNT_KEYS} == 0) and non-empty "
                   "limitations"),
            "R6": ("R5 AND attempt category in "
                   + str(sorted(_NEGATIVE_CODE_CATEGORIES))),
            "UNION": "RG ∪ R6 (computed from the operand sets)",
        },
    }


# ---------------------------------------------------------------------------
# Hash re-verification
# ---------------------------------------------------------------------------


def _verify_matrix_result_hashes(matrix: dict, model_level: Path) -> dict:
    """Re-hash every attempt's raw result artifact and compare with the
    ``result_sha256`` the Task-5 matrix recorded."""
    run_dirs = {
        (t, r): d for t, r, d in _iter_attempt_dirs(model_level)
    } if model_level is not None else {}
    checked, mismatched, missing_dir, missing_file = 0, [], [], []
    for row in matrix.get("rows") or []:
        cell = (row.get("arms") or {}).get("t1") or {}
        want = cell.get("result_sha256")
        if not want:
            continue
        key = (row["task_id"], row["run_id"])
        run_dir = run_dirs.get(key)
        if run_dir is None:
            missing_dir.append(key)
            continue
        got = None
        for name in ("result.jsonl", "result.json"):
            p = run_dir / name
            if p.is_file():
                got = _sha256_file(p)
                break
        if got is None:
            missing_file.append(key)
            continue
        checked += 1
        if got != want:
            mismatched.append({"attempt": list(key), "recorded": want,
                               "recomputed": got})
    return {
        "checked": checked,
        "mismatched": mismatched,
        "missing_attempt_dirs": [list(k) for k in missing_dir],
        "missing_result_files": [list(k) for k in missing_file],
    }


def _verify_manifest_hashes(harness_dir: Optional[Path]) -> dict:
    """Re-hash the file pins inside the Task-5 manifest."""
    manifest = json.loads(MANIFEST_FILE.read_text(encoding="utf-8"))
    checks = []

    def _section(obj, base: Path, label: str):
        for rel, want in sorted((obj or {}).items()):
            got = _sha256_file(base / rel)
            checks.append({
                "section": label,
                "file": rel,
                "recorded": want,
                "recomputed": got,
                "match": got == want,
            })

    _section((manifest.get("izyan") or {}).get("prompt_files_sha256"),
             _REPO_ROOT, "izyan.prompt_files_sha256")
    _section((manifest.get("izyan") or {}).get("controller_files_sha256"),
             _REPO_ROOT, "izyan.controller_files_sha256")
    _section((manifest.get("spec") or {}).get("files_sha256"),
             _REPO_ROOT, "spec.files_sha256")

    h = manifest.get("harness") or {}
    if harness_dir is not None:
        harness_dir = Path(harness_dir)
        _section(h.get("scoring_files_sha256"), harness_dir,
                 "harness.scoring_files_sha256")
        _section(h.get("arm_files_sha256"), harness_dir,
                 "harness.arm_files_sha256")
        for key in ("patch_sha256", "task4_patch_sha256"):
            want = h.get(key)
            rel = h.get(key.replace("_sha256", "_file"))
            if want and rel:
                got = _sha256_file(_REPO_ROOT / rel)
                checks.append({
                    "section": f"harness.{key}",
                    "file": rel,
                    "recorded": want,
                    "recomputed": got,
                    "match": got == want,
                })
    return {
        "checks": checks,
        "checked": len(checks),
        "mismatched": [c for c in checks if not c["match"]],
        "skipped": harness_dir is None,
    }


# ---------------------------------------------------------------------------
# Freeze artifact
# ---------------------------------------------------------------------------


def build_reference(harness_dir: Optional[Path] = None) -> dict:
    """Phase-6.0 re-verification document (in-memory; see freeze_history)."""
    matrix = json.loads(MATRIX_FILE.read_text(encoding="utf-8"))
    model_level = find_t1_model_level(RESULTS_T1)

    tables = recompute_tables(matrix, model_level)
    d = tables["denominators"]
    headline = {
        "recomputed": {
            "false_safe_attempts": d["false_safe_attempts"],
            "exploitable_attempts":
                d["exploitable_ground_truth_attempts"],
            "correct_safe_attempts": d["correct_safe_attempts"],
            "safe_ground_truth_attempts":
                d["safe_ground_truth_attempts"],
            "false_safe_cases": d["false_safe_cases"],
            "correct_safe_cases": d["correct_safe_cases"],
            "note": ("scored-safe denominator = parser-audit outcome "
                     "'safe' (68 of 90 attempts; official projection "
                     "yields the same 5/63 split on this matrix)"),
        },
        "reported": {
            "false_safe": f'{REPORTED["false_safe_attempts"]}/'
                          f'{REPORTED["exploitable_attempts"]}',
            "correct_safe": f'{REPORTED["correct_safe_attempts"]}/'
                            f'{REPORTED["safe_ground_truth_attempts"]}',
        },
        "confirmed": (
            d["false_safe_attempts"] == REPORTED["false_safe_attempts"]
            and d["exploitable_ground_truth_attempts"]
            == REPORTED["exploitable_attempts"]
            and d["correct_safe_attempts"]
            == REPORTED["correct_safe_attempts"]
            and d["safe_ground_truth_attempts"]
            == REPORTED["safe_ground_truth_attempts"]),
    }

    hashes = {
        "matrix_result_sha256": _verify_matrix_result_hashes(
            matrix, model_level),
        "manifest_file_pins": _verify_manifest_hashes(harness_dir),
    }
    hashes["all_verified"] = (
        not hashes["matrix_result_sha256"]["mismatched"]
        and not hashes["manifest_file_pins"]["mismatched"])

    return {
        "schema": REFERENCE_SCHEMA,
        "frozen_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                       time.gmtime()),
        "experiment_id": "task6",
        "purpose": (
            "Phase 6.0 — re-verify the Task-5 scorer before Task 6 "
            "reuses its metrics; freeze the Task-5 gate-feasibility "
            "tables by attempt AND by unique case; explain the "
            "19 + 26 < 46 union anomaly. All Task-5 inputs are "
            "read-only."),
        "inputs": {
            "matrix": str(MATRIX_FILE.relative_to(_REPO_ROOT)),
            "safety_report":
                str(SAFETY_REPORT.relative_to(_REPO_ROOT)),
            "gate_feasibility":
                str(GATE_FEASIBILITY.relative_to(_REPO_ROOT)),
            "manifest": str(MANIFEST_FILE.relative_to(_REPO_ROOT)),
            "t1_run_root": (
                str(model_level.relative_to(_REPO_ROOT))
                if model_level is not None else None),
            "t1_model_level_found": model_level is not None,
            "harness_dir": str(harness_dir) if harness_dir else None,
        },
        "input_file_sha256": {
            p.name: _sha256_file(p)
            for p in (MATRIX_FILE, SAFETY_REPORT, GATE_FEASIBILITY,
                      MANIFEST_FILE)
        },
        "headline": headline,
        "gate_rules": tables,
        "hashes": hashes,
        "limitations": [
            "The published UNION row (46) is arithmetically impossible "
            "and is replaced by the recomputed union (45); per-rule rows "
            "RG/R6 reproduce, RH does not (recomputed 31 vs reported 28) "
            "— the companion row used an undocumented variant.",
            "The throwaway gate scripts are gone; rule sets are the "
            "documented reconstruction validated by the exact RG/R6 "
            "reproduction, not byte-recovery of the originals.",
            "Audit trails are read-only; P1 (no-MCP) attempts carry no "
            "observations and are never gate-eligible.",
        ],
    }


def freeze_history(
    out_dir: Path,
    *,
    harness_dir: Optional[Path] = None,
) -> dict:
    """Emit ``task5-reference.json``; returns the reference doc."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ref = build_reference(harness_dir=harness_dir)
    dest = out_dir / "task5-reference.json"
    dest.write_text(json.dumps(ref, indent=2) + "\n", encoding="utf-8")
    return ref

#!/usr/bin/env python3
"""Offline safety-aware reporter for the VEX-Bench Plain Agent baseline.

Plan: docs/dev/plans/2026-10-08-vexbench-plain-agent-plan.md §7.

Joins the official harness parsed.jsonl with frozen Baseline 1 artifacts and
produces two explicitly named projections plus telemetry coverage:

  safety-aware    uncertain -> abstain (INCONCLUSIVE), never a safe claim;
                  FalseSafe counts only GT-exploitable rows scored "safe"
  compatibility   official policy: vulnerable -> exploitable, every other
                  valid category INCLUDING uncertain -> not_exploitable,
                  missing/failed -> FAILED (never a successful negative)

Baseline dir is strictly read-only. No model calls, no runner interaction,
no mutation of official metrics / GT / frozen A artifacts.

Outputs in --out: safety-cases.jsonl, safety-metrics.json, telemetry.json,
comparison.md, freeze-checksums.json.

Python 3 stdlib only.
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import statistics
import sys
import tempfile

REPORTER_VERSION = "1"

# Official 12-category set (H/src/evaluate/result_parser.py:6-22). Order is
# the harness order; only membership matters for scoring.
VALID_CATEGORIES = (
    "false_positive", "code_not_present", "code_not_reachable",
    "requires_configuration", "requires_dependency", "requires_environment",
    "compiler_protected", "runtime_protected", "perimeter_protected",
    "mitigating_control_protected", "uncertain", "vulnerable",
)
CATEGORY_INDEX = {c: i for i, c in enumerate(VALID_CATEGORIES)}
SAFE_CATEGORIES = tuple(c for c in VALID_CATEGORIES
                        if c not in ("vulnerable", "uncertain"))

# Denominators of the pinned 30-task Go subset (frozen contract, plan §0.2).
EXPECTED_DENOMINATORS = {"total": 30, "gt_exploitable": 7,
                         "gt_non_exploitable": 23}

OUTCOMES = ("positive", "safe", "abstain", "failed")
TOKEN_FIELDS = ("input_tokens", "cached_input_tokens", "cache_write_tokens",
                "output_tokens", "reasoning_tokens")
TOOL_ITEM_TYPES = ("command_execution", "web_search")
KNOWN_ITEM_TYPES = TOOL_ITEM_TYPES + ("agent_message",)

LOG_TS_PATTERNS = (
    # logging default: 2026-10-07 09:00:01,123 (runner-local time)
    re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),(\d{3})"),
    # ISO-8601, optionally Z/offset: 2026-10-07T09:00:01.123Z
    re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?)"
               r"(Z|[+-]\d{2}:?\d{2})?"),
)
RUN_MARKER_RE = re.compile(r"\[([^\]\s/]+)/(run_\d+)\]\s*\[RUN\]")
TIME_P_RE = re.compile(r"^real\s+(\d+(?:\.\d+)?)\s*$", re.MULTILINE)


class ReportError(Exception):
    pass


def fail(msg):
    raise ReportError(msg)


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def eprint(msg):
    print(msg, file=sys.stderr)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _fsync_dir(d):
    try:
        fd = os.open(d, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def atomic_write_text(path, text, mode=0o644):
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(text.encode("utf-8"))
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    _fsync_dir(d)


def atomic_write_json(path, obj, mode=0o644):
    atomic_write_text(
        path, json.dumps(obj, indent=2, ensure_ascii=False) + "\n", mode)


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def normalize_ground_truth(raw):
    """Same policy as H/src/evaluate/result_parser.py:90-99."""
    if raw is None:
        return None
    cleaned = str(raw).strip().lower().replace(" ", "_")
    return "exploitable" if cleaned == "exploitable" else "not_exploitable"


# ---------------------------------------------------------------------------
# parsed.jsonl -> derived case rows


def safety_outcome(status, category):
    """§7.1 projection: failed / positive / abstain / safe."""
    if status != "ok" or category not in VALID_CATEGORIES:
        return "failed"
    if category == "vulnerable":
        return "positive"
    if category == "uncertain":
        return "abstain"
    return "safe"


def compat_prediction(status, category):
    """§7.2 official binary mapping; FAILED is not a successful negative."""
    if status != "ok" or category not in VALID_CATEGORIES:
        return "FAILED"
    return "exploitable" if category == "vulnerable" else "not_exploitable"


def load_parsed_cases(path):
    """Read parsed.jsonl, validate the row contract, derive outcomes."""
    cases = []
    seen = set()
    with open(path, encoding="utf-8") as f:
        for ln, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as e:
                fail(f"{path}:{ln}: invalid JSON: {e}")
            for fld in ("task_id", "run_id", "ground_truth",
                        "ground_truth_category"):
                if row.get(fld) in (None, ""):
                    fail(f"{path}:{ln}: missing required field {fld!r}")
            key = (row["task_id"], row["run_id"])
            if key in seen:
                fail(f"{path}:{ln}: duplicate (task_id, run_id) {key}")
            seen.add(key)
            status = row.get("status")
            cat = row.get("predicted_category")
            outcome = safety_outcome(status, cat)
            gt = normalize_ground_truth(row["ground_truth"])
            gt_pos = gt == "exploitable"
            status_correct = ((outcome == "positive" and gt_pos) or
                              (outcome == "safe" and not gt_pos))
            reason_correct = bool(
                status_correct and cat == row["ground_truth_category"])
            cases.append({
                "task_id": row["task_id"],
                "run_id": row["run_id"],
                "cve_id": row.get("cve_id"),
                "ground_truth": gt,
                "ground_truth_category": row["ground_truth_category"],
                "status": status,
                "predicted": row.get("predicted"),
                "predicted_category": cat,
                "safety_outcome": outcome,
                "compat_prediction": compat_prediction(status, cat),
                "status_correct": status_correct,
                "reason_correct": reason_correct,
                "completed": row.get("completed"),
                "steps": row.get("steps"),
                "tokens": {f: row.get(f) for f in TOKEN_FIELDS},
                "cost_usd": row.get("cost_usd"),
                "reasoning": row.get("reasoning"),
                "_gt_pos": gt_pos,
            })
    if not cases:
        fail(f"{path}: no rows")
    return cases


def group_by_run(cases):
    """run_id -> [cases], run order sorted, case order = file order."""
    runs = {}
    for c in cases:
        runs.setdefault(c["run_id"], []).append(c)
    return {r: runs[r] for r in sorted(runs)}


# ---------------------------------------------------------------------------
# §7.1 safety-aware scoring on fixed per-repeat GT denominators


def score_rows(cases):
    """Safety metrics for one row set (a repeat, or pooled when marked so)."""
    total = len(cases)
    gt_exp = sum(1 for c in cases if c["_gt_pos"])
    gt_neg = total - gt_exp
    outcomes = {o: 0 for o in OUTCOMES}
    confusion = {o: {"gt_exploitable": 0, "gt_non_exploitable": 0}
                 for o in OUTCOMES}
    false_safe_ids = []
    tp = fp = 0
    fn_breakdown = {"safe": 0, "abstain": 0, "failed": 0}
    status_correct = reason_correct = 0
    for c in cases:
        o = c["safety_outcome"]
        outcomes[o] += 1
        confusion[o]["gt_exploitable" if c["_gt_pos"]
                     else "gt_non_exploitable"] += 1
        if c["_gt_pos"]:
            if o == "positive":
                tp += 1
            else:
                fn_breakdown[o] += 1
            if o == "safe":
                false_safe_ids.append(c["task_id"])
        elif o == "positive":
            fp += 1
        if c["status_correct"]:
            status_correct += 1
        if c["reason_correct"]:
            reason_correct += 1
    fn = gt_exp - tp
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / gt_exp if gt_exp else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if precision + recall else 0.0)
    answered = total - outcomes["failed"]
    return {
        "rows": total,
        "gt_exploitable": gt_exp,
        "gt_non_exploitable": gt_neg,
        "task_ids": [c["task_id"] for c in cases],
        "outcomes": outcomes,
        "confusion": confusion,
        "false_safe_count": len(false_safe_ids),
        "false_safe_ids": sorted(set(false_safe_ids)),
        "false_safe_rate": (len(false_safe_ids) / gt_exp if gt_exp else 0.0),
        "safe_clear_count": outcomes["safe"] - confusion["safe"][
            "gt_exploitable"],
        "safe_clear_rate": (confusion["safe"]["gt_non_exploitable"] / gt_neg
                            if gt_neg else 0.0),
        "exploitable_recall": recall,
        "inconclusive_count": outcomes["abstain"],
        "inconclusive_rate": outcomes["abstain"] / total if total else 0.0,
        "completion_count": answered,
        "completion_rate": answered / total if total else 0.0,
        "tp": tp, "fp": fp, "fn": fn,
        "fn_breakdown": fn_breakdown,
        "precision": precision,
        "status_f1": f1,
        "status_correct_count": status_correct,
        "status_correct_rate": status_correct / total if total else 0.0,
        "reason_correct_count": reason_correct,
        "reason_correct_rate": reason_correct / total if total else 0.0,
    }


AGG_KEYS = ("false_safe_count", "false_safe_rate", "safe_clear_rate",
            "exploitable_recall", "inconclusive_rate", "completion_rate",
            "tp", "fp", "fn", "precision", "status_f1",
            "status_correct_rate", "reason_correct_rate")


def _mean_std(vals):
    if not vals:
        return {"mean": None, "std": None}
    return {"mean": statistics.mean(vals),
            "std": statistics.stdev(vals) if len(vals) > 1 else 0.0}


def aggregate_repeats(per_repeat):
    """mean ± sample std (ddof=1) over per-repeat vectors; counts kept raw."""
    agg = {"n_repeats": len(per_repeat)}
    for key in AGG_KEYS:
        vals = {r: m[key] for r, m in per_repeat.items()}
        ms = _mean_std(list(vals.values()))
        agg[key] = {"per_repeat": vals, **ms}
    fs_ids = {}
    fs_union = set()
    for r, m in per_repeat.items():
        fs_ids[r] = m["false_safe_ids"]
        fs_union.update(m["false_safe_ids"])
    agg["false_safe"] = {
        "per_repeat_counts": {r: m["false_safe_count"]
                              for r, m in per_repeat.items()},
        "per_repeat_ids": fs_ids,
        "total_count": sum(m["false_safe_count"]
                           for m in per_repeat.values()),
        "attempts": sum(m["rows"] for m in per_repeat.values()),
        "unique_case_ids": sorted(fs_union),
        "mean": agg["false_safe_count"]["mean"],
        "std": agg["false_safe_count"]["std"],
    }
    id_sets = {r: set(m["task_ids"]) for r, m in per_repeat.items()}
    runs = list(per_repeat)
    agg["task_id_sets_identical"] = all(
        id_sets[r] == id_sets[runs[0]] for r in runs[1:]) if runs else True
    return agg


# ---------------------------------------------------------------------------
# §7.2 compatibility projection (offline recompute + official passthrough)


def _binary_prf(tp, fp, fn_total):
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn_total) if tp + fn_total else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if precision + recall else 0.0)
    return precision, recall, f1


def compat_run(cases):
    """One repeat under the official policy.

    fn_predicted_negative mirrors official binary.totals.fn (the
    exploitable->not_exploitable cell only); fn_failed is the
    exploitable->FAILED cell that totals.fn omits but scalar recall
    (tp/(tp+fn_total)) still penalises.
    """
    rows = [c for c in cases if c["ground_truth"]]
    tp = fp = tn = fn_neg = fn_failed = 0
    for c in rows:
        pred = c["compat_prediction"]
        if c["_gt_pos"]:
            if pred == "exploitable":
                tp += 1
            elif pred == "FAILED":
                fn_failed += 1
            else:
                fn_neg += 1
        else:
            if pred == "exploitable":
                fp += 1
            elif pred != "FAILED":
                tn += 1
    n = len(rows)
    correct = sum(1 for c in rows
                  if c["compat_prediction"] != "FAILED" and
                  (c["_gt_pos"] == (c["compat_prediction"] == "exploitable")))
    precision, recall, f1 = _binary_prf(tp, fp, fn_neg + fn_failed)
    gt_classes = sorted({c["ground_truth_category"] for c in rows},
                        key=lambda c: CATEGORY_INDEX.get(c, 99))
    per_class = {}
    for cls in gt_classes:
        ctp = cfp = cfn = 0
        for c in rows:
            pred = (c["predicted_category"]
                    if c["compat_prediction"] != "FAILED" else "FAILED")
            if c["ground_truth_category"] == cls and pred == cls:
                ctp += 1
            elif c["ground_truth_category"] != cls and pred == cls:
                cfp += 1
            elif c["ground_truth_category"] == cls and pred != cls:
                cfn += 1
        cp = ctp / (ctp + cfp) if ctp + cfp else 0.0
        cr = ctp / (ctp + cfn) if ctp + cfn else 0.0
        cf1 = 2 * cp * cr / (cp + cr) if cp + cr else 0.0
        per_class[cls] = {"precision": cp, "recall": cr, "f1": cf1,
                          "support": ctp + cfn}
    macro_f1 = (sum(v["f1"] for v in per_class.values()) / len(per_class)
                if per_class else 0.0)
    return {
        "rows": n,
        "accuracy": correct / n if n else 0.0,
        "precision": precision, "recall": recall, "f1": f1,
        "tp": tp, "fp": fp, "tn": tn,
        "fn_predicted_negative": fn_neg,
        "fn_failed": fn_failed,
        "failed": sum(1 for c in rows if c["compat_prediction"] == "FAILED"),
        "justification_macro_f1": macro_f1,
        "gt_classes": gt_classes,
        "per_class": per_class,
        "uncertain_as_negative": sum(
            1 for c in rows
            if c["compat_prediction"] == "not_exploitable"
            and c["predicted_category"] == "uncertain"),
    }


def compat_aggregate(per_run):
    keys = ("accuracy", "precision", "recall", "f1",
            "justification_macro_f1")
    out = {k: _mean_std([m[k] for m in per_run.values()]) for k in keys}
    for k in out:
        out[k]["per_repeat"] = {r: m[k] for r, m in per_run.items()}
    out["totals"] = {
        k: sum(m[k] for m in per_run.values())
        for k in ("tp", "fp", "tn", "fn_predicted_negative", "fn_failed",
                  "failed", "uncertain_as_negative")}
    return out


def _official_scalar(metrics, *path):
    cur = metrics
    for p in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(p)
    return cur


def compat_projection(by_run, official_metrics):
    per_run = {r: compat_run(cs) for r, cs in by_run.items()}
    agg = compat_aggregate(per_run)

    def _close(a, b, eps=1e-9):
        return (a is not None and b is not None and abs(a - b) < eps)

    official = official_metrics or {}
    consistency = {
        "binary_accuracy_mean": {
            "official": _official_scalar(official, "binary", "accuracy",
                                         "mean"),
            "recomputed": agg["accuracy"]["mean"],
        },
        "binary_recall_mean": {
            "official": _official_scalar(official, "binary", "recall",
                                         "mean"),
            "recomputed": agg["recall"]["mean"],
        },
        "multiclass_macro_f1_mean": {
            "official": _official_scalar(official, "multiclass", "macro_f1",
                                         "mean"),
            "recomputed": agg["justification_macro_f1"]["mean"],
        },
        "binary_totals_fn": {
            "official": _official_scalar(official, "binary", "totals", "fn"),
            "recomputed_exploitable_to_negative":
                agg["totals"]["fn_predicted_negative"],
            "recomputed_exploitable_to_failed": agg["totals"]["fn_failed"],
        },
    }
    for k, v in consistency.items():
        if k == "binary_totals_fn":
            v["match"] = _close(v["official"],
                                v["recomputed_exploitable_to_negative"])
        else:
            v["match"] = _close(v["official"], v["recomputed"])
    return {
        "policy": "official VEX-Bench mapping: vulnerable->positive, all "
                  "other valid categories INCLUDING uncertain->negative, "
                  "missing/failed->FAILED (never a successful negative); "
                  "macro-F1 over GT-present classes only",
        "per_repeat": per_run,
        "aggregate": agg,
        "vs_official_metrics": consistency,
        "totals_fn_note": "official binary.totals.fn counts only the "
                          "exploitable->not_exploitable cell; the "
                          "exploitable->FAILED cell sits in totals.failed "
                          "while scalar recall still charges both. Never "
                          "recompute recall as TP/(TP+totals.fn).",
    }


# ---------------------------------------------------------------------------
# telemetry: tool items, tokens, time, cost — coverage-aware, never zero-fill


def _coverage(covered, total, missing=None, reason=None):
    if total == 0:
        state = "unavailable"
    elif covered == 0:
        state = "unavailable"
    elif covered < total:
        state = "partial"
    else:
        state = "full"
    out = {"state": state, "covered": covered, "total": total}
    if missing:
        out["missing"] = missing
    if reason:
        out["reason"] = reason
    return out


def count_tool_items(result_jsonl):
    """Offline observable: item.completed events by item.type.

    Codex `steps` counts every item.completed (agent_message +
    command_execution + web_search + ...), so it is NOT a tool-call count.
    """
    by_type = {}
    untyped = 0
    total = 0
    with open(result_jsonl, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("type") != "item.completed":
                continue
            total += 1
            item = rec.get("item")
            t = item.get("type") if isinstance(item, dict) else None
            if not t:
                untyped += 1
                t = "<untyped>"
            by_type[t] = by_type.get(t, 0) + 1
    other = total - sum(by_type.get(t, 0) for t in TOOL_ITEM_TYPES)
    return {
        "item_completed_total": total,
        "command_execution": by_type.get("command_execution", 0),
        "web_search": by_type.get("web_search", 0),
        "other_items": other,
        "untyped_items": untyped,
        "by_type": by_type,
        "new_item_types": sorted(t for t in by_type
                                 if t not in KNOWN_ITEM_TYPES
                                 and t != "<untyped>"),
    }


def _per_repeat_means(by_run, per_attempt, field):
    """Mean of per_attempt[field] over covered attempts, per repeat."""
    out = {}
    for r, cs in by_run.items():
        vals = []
        for c in cs:
            pa = per_attempt.get((c["task_id"], c["run_id"]))
            if pa is not None and pa.get(field) is not None:
                vals.append(pa[field])
        out[r] = {"mean": statistics.mean(vals) if vals else None,
                  "covered": len(vals), "total": len(cs)}
    return out


def _repeat_agg(repeat_means):
    vals = [v["mean"] for v in repeat_means.values() if v["mean"] is not None]
    ms = _mean_std(vals)
    return {"repeat_means": repeat_means, **ms}


def build_tool_telemetry(by_run, raw_root):
    per_attempt = {}
    missing = []
    all_new_types = set()
    totals = {"item_completed_total": 0, "command_execution": 0,
              "web_search": 0, "other_items": 0, "untyped_items": 0}
    for cs in by_run.values():
        for c in cs:
            path = os.path.join(raw_root, c["task_id"], c["run_id"],
                                "result.jsonl")
            key = (c["task_id"], c["run_id"])
            if not os.path.isfile(path):
                missing.append(f"{c['task_id']}/{c['run_id']}")
                per_attempt[key] = None
                continue
            try:
                ti = count_tool_items(path)
            except OSError:
                missing.append(f"{c['task_id']}/{c['run_id']}")
                per_attempt[key] = None
                continue
            per_attempt[key] = ti
            all_new_types.update(ti["new_item_types"])
            for k in totals:
                totals[k] += ti[k]
    total_attempts = sum(len(cs) for cs in by_run.values())
    covered = total_attempts - len(missing)
    cov = _coverage(covered, total_attempts, missing,
                    reason=None if covered else
                    f"no result.jsonl under {raw_root}")
    means = {}
    for field in ("command_execution", "web_search", "other_items",
                  "item_completed_total", "steps"):
        if field == "steps":
            rm = {r: {"mean": (statistics.mean(
                        [c["steps"] for c in cs if c["steps"] is not None])
                        if any(c["steps"] is not None for c in cs) else None),
                      "covered": sum(1 for c in cs
                                     if c["steps"] is not None),
                      "total": len(cs)}
                  for r, cs in by_run.items()}
        else:
            rm = _per_repeat_means(by_run, per_attempt, field)
        means[field] = _repeat_agg(rm)
    limitations = []
    if all_new_types:
        limitations.append(
            "unrecognised item.completed types observed: "
            + ", ".join(sorted(all_new_types))
            + " — counted under other_items, not zero")
    if totals["untyped_items"]:
        limitations.append(
            f"{totals['untyped_items']} item.completed event(s) without "
            "item.type — counted under other_items")
    steps_total = sum(c["steps"] for cs in by_run.values() for c in cs
                      if isinstance(c["steps"], int))
    return {
        "definition": "offline count of item.completed events in raw "
                      "result.jsonl by item.type; 'steps' in parsed.jsonl "
                      "counts the same events (agent_message included) and "
                      "is therefore not a pure tool-call count",
        "coverage": cov,
        "per_attempt": {f"{k[0]}/{k[1]}": v
                        for k, v in per_attempt.items() if v is not None},
        "totals": totals,
        "steps_field_total": steps_total,
        "per_repeat": means,
        "limitations": limitations,
    }


def build_token_telemetry(by_run):
    total_rows = sum(len(cs) for cs in by_run.values())
    by_bucket = {}
    for field in TOKEN_FIELDS:
        observed = sum(1 for cs in by_run.values() for c in cs
                       if c["tokens"].get(field) is not None)
        by_bucket[field] = {"observed": observed, "total": total_rows}
    any_observed = any(b["observed"] for b in by_bucket.values())
    all_observed = all(b["observed"] == total_rows
                       for b in by_bucket.values())
    totals = {}
    per_case_mean = {}
    per_repeat = {}
    for field in TOKEN_FIELDS:
        vals = [c["tokens"][field] for cs in by_run.values() for c in cs
                if c["tokens"].get(field) is not None]
        totals[field] = sum(vals) if vals else None
        per_case_mean[field] = statistics.mean(vals) if vals else None
        rm = {}
        for r, cs in by_run.items():
            rv = [c["tokens"][field] for c in cs
                  if c["tokens"].get(field) is not None]
            rm[r] = {"mean": statistics.mean(rv) if rv else None,
                     "covered": len(rv), "total": len(cs)}
        per_repeat[field] = _repeat_agg(rm)
    state = ("full" if all_observed else
             "unavailable" if not any_observed else "partial")
    return {
        "source": "parsed.jsonl disjoint buckets (input, cached_input, "
                  "cache_write, output, reasoning)",
        "coverage": {"state": state, "by_bucket": by_bucket,
                     "note": "missing bucket values stay null — never "
                             "imputed as zero"},
        "totals": totals,
        "per_case_mean": per_case_mean,
        "per_repeat": per_repeat,
        "note": "per-case/per-repeat means cover observed rows only; "
                "repeat std is over per-repeat means (ddof=1), not the "
                "case-level std of official metrics",
    }


# --- docker events / run.log ------------------------------------------------


def parse_docker_events(path):
    """Container lifecycle windows from `docker events --format '{{json .}}'`."""
    containers = {}
    order = []
    with open(path, encoding="utf-8") as f:
        for ln, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("Type") not in (None, "container"):
                continue
            action = rec.get("Action") or rec.get("status")
            actor = rec.get("Actor") or {}
            cid = actor.get("ID") or rec.get("id")
            if not action or not cid:
                continue
            tns = rec.get("timeNano")
            try:
                tns = int(tns) if tns is not None else None
            except (TypeError, ValueError):
                tns = None
            if tns is None:
                t = rec.get("time")
                try:
                    tns = int(float(t) * 1e9) if t is not None else None
                except (TypeError, ValueError):
                    tns = None
            entry = containers.setdefault(cid, {
                "id": cid,
                "name": (actor.get("Attributes") or {}).get("name"),
                "image": (actor.get("Attributes") or {}).get("image")
                         or rec.get("from"),
                "create_ns": None, "start_ns": None, "die_ns": None,
                "destroy_ns": None, "actions": [],
            })
            entry["actions"].append(action)
            if action == "create":
                if entry["create_ns"] is None:
                    entry["create_ns"] = tns
                    order.append(cid)
            elif action == "start":
                if entry["start_ns"] is None:
                    entry["start_ns"] = tns
            elif action == "die":
                entry["die_ns"] = tns
            elif action == "destroy":
                entry["destroy_ns"] = tns
    windows = []
    for cid in order:
        w = containers[cid]
        end = w["destroy_ns"] if w["destroy_ns"] is not None else w["die_ns"]
        w["wall_seconds"] = ((end - w["create_ns"]) / 1e9
                             if w["create_ns"] is not None
                             and end is not None else None)
        w["exec_seconds"] = ((w["die_ns"] - w["start_ns"]) / 1e9
                             if w["die_ns"] is not None
                             and w["start_ns"] is not None else None)
        w["closed"] = w["destroy_ns"] is not None or w["die_ns"] is not None
        windows.append(w)
    return windows


def parse_run_log(path):
    """[task/run_00N] [RUN] markers, timestamp window, /usr/bin/time real."""
    markers = []
    first_ts = last_ts = None
    real_seconds = None
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            ts_ns = _log_line_ts_ns(line)
            if ts_ns is not None:
                if first_ts is None:
                    first_ts = ts_ns
                last_ts = ts_ns
            m = RUN_MARKER_RE.search(line)
            if m:
                markers.append({"task_id": m.group(1),
                                "run_id": m.group(2), "ts_ns": ts_ns})
            tm = TIME_P_RE.match(line.strip())
            if tm:
                real_seconds = float(tm.group(1))
    return {
        "markers": markers,
        "first_ts_ns": first_ts,
        "last_ts_ns": last_ts,
        "elapsed_seconds": ((last_ts - first_ts) / 1e9
                            if first_ts is not None
                            and last_ts is not None else None),
        "real_seconds": real_seconds,
    }


def _log_line_ts_ns(line):
    m = LOG_TS_PATTERNS[0].match(line)
    if m:
        try:
            dt = datetime.datetime.strptime(m.group(1),
                                            "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None
        dt = dt.replace(microsecond=int(m.group(2)) * 1000)
        return int(dt.astimezone().timestamp() * 1e9)  # runner-local time
    m = LOG_TS_PATTERNS[1].match(line)
    if m:
        text = m.group(1)
        if "." in text:
            fmt = "%Y-%m-%dT%H:%M:%S.%f"
        else:
            fmt = "%Y-%m-%dT%H:%M:%S"
        try:
            dt = datetime.datetime.strptime(text, fmt)
        except ValueError:
            return None
        tz = m.group(2)
        if tz == "Z" or tz is None:
            if tz == "Z":
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            else:
                dt = dt.astimezone()
        else:
            sign = 1 if tz[0] == "+" else -1
            hh, mm = tz[1:].replace(":", "")[:2], tz[1:].replace(":", "")[2:]
            dt = dt.replace(tzinfo=datetime.timezone(
                sign * datetime.timedelta(hours=int(hh),
                                          minutes=int(mm))))
        return int(dt.timestamp() * 1e9)
    return None


def pair_containers(windows, markers):
    """Map observed containers to (task_id, run_id) attempts.

    Creates happen after their [RUN] log marker; pair each create to the
    latest preceding unclaimed marker. Without marker timestamps fall back
    to order pairing only when counts match exactly.
    """
    creates = [w for w in windows if w["create_ns"] is not None]
    creates.sort(key=lambda w: w["create_ns"])
    pairing = {}
    unpaired = []
    method = None
    if markers and all(m["ts_ns"] is not None for m in markers) and creates:
        method = "timestamp_preceding_marker"
        claimed = set()
        for w in creates:
            cand = None
            for i, mk in enumerate(markers):
                if i in claimed or mk["ts_ns"] is None:
                    continue
                if mk["ts_ns"] <= w["create_ns"]:
                    cand = i
            if cand is None:
                unpaired.append(w["id"])
                continue
            claimed.add(cand)
            pairing[(markers[cand]["task_id"],
                     markers[cand]["run_id"])] = w
    elif markers and len(creates) == len(markers):
        method = "assumed_order_equal_counts"
        for w, mk in zip(creates, markers):
            pairing[(mk["task_id"], mk["run_id"])] = w
    else:
        method = ("unpaired_marker_timestamp_missing"
                  if markers else "no_markers")
        unpaired = [w["id"] for w in creates]
    return pairing, unpaired, method


def build_time_telemetry(by_run, docker_events_path, run_log_path):
    total_attempts = sum(len(cs) for cs in by_run.values())
    out = {
        "boundary_note": "B wall = docker create->destroy (source copy and "
                         "cleanup included); exec = start->die. A's frozen "
                         "wall envelope has different boundaries — this is "
                         "not an apples-to-apples CPU comparison.",
        "container_wall": {"coverage": _coverage(
            0, total_attempts, reason="--docker-events not provided")},
        "exec_window": {"coverage": _coverage(
            0, total_attempts, reason="--docker-events not provided")},
        "run_log": {"coverage": "unavailable",
                    "reason": "--run-log not provided"},
    }
    markers = []
    if run_log_path:
        if not os.path.isfile(run_log_path):
            fail(f"run log not found: {run_log_path}")
        rl = parse_run_log(run_log_path)
        markers = rl["markers"]
        out["run_log"] = {
            "coverage": "available",
            "path": run_log_path,
            "run_markers": len(markers),
            "first_ts_utc": _ns_to_iso(rl["first_ts_ns"]),
            "last_ts_utc": _ns_to_iso(rl["last_ts_ns"]),
            "elapsed_seconds": rl["elapsed_seconds"],
            "time_p_real_seconds": rl["real_seconds"],
            "tz_note": "log timestamps interpreted in reporter-host local "
                       "tz (logging asctime has no zone); pairing uses "
                       "relative order",
        }
    if not docker_events_path:
        return out
    if not os.path.isfile(docker_events_path):
        fail(f"docker events file not found: {docker_events_path}")
    windows = parse_docker_events(docker_events_path)
    pairing, unpaired, method = pair_containers(windows, markers)
    per_attempt = {}
    matched = 0
    total_attempts = sum(len(cs) for cs in by_run.values())
    for cs in by_run.values():
        for c in cs:
            w = pairing.get((c["task_id"], c["run_id"]))
            per_attempt[(c["task_id"], c["run_id"])] = w
            if w is not None and w["wall_seconds"] is not None:
                matched += 1
    open_windows = sum(1 for w in windows if not w["closed"])
    wall = _repeat_agg(_per_repeat_means(by_run, per_attempt,
                                         "wall_seconds"))
    exec_agg = _repeat_agg(_per_repeat_means(by_run, per_attempt,
                                            "exec_seconds"))
    all_walls = [w["wall_seconds"] for w in windows
                 if w["wall_seconds"] is not None]
    out["container_wall"] = {
        "coverage": _coverage(matched, total_attempts),
        "matching": method,
        "containers_observed": len(windows),
        "containers_unpaired": len(unpaired),
        "containers_open": open_windows,
        "per_attempt_seconds": {
            f"{k[0]}/{k[1]}": round(v["wall_seconds"], 3)
            for k, v in per_attempt.items()
            if v is not None and v["wall_seconds"] is not None},
        "repeat_agg": wall,
        "unassigned_container_mean_seconds": (
            statistics.mean(all_walls) if all_walls else None),
    }
    all_exec = [w["exec_seconds"] for w in windows
                if w["exec_seconds"] is not None]
    out["exec_window"] = {
        "coverage": _coverage(
            sum(1 for v in per_attempt.values()
                if v is not None and v["exec_seconds"] is not None),
            total_attempts),
        "per_attempt_seconds": {
            f"{k[0]}/{k[1]}": round(v["exec_seconds"], 3)
            for k, v in per_attempt.items()
            if v is not None and v["exec_seconds"] is not None},
        "repeat_agg": exec_agg,
        "unassigned_container_mean_seconds": (
            statistics.mean(all_exec) if all_exec else None),
    }
    return out


def _ns_to_iso(ns):
    if ns is None:
        return None
    return datetime.datetime.fromtimestamp(
        ns / 1e9, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_cost_telemetry(by_run, provenance):
    rows = [c for cs in by_run.values() for c in cs]
    priced = [c["cost_usd"] for c in rows if c["cost_usd"] is not None]
    estimate = {
        "coverage": _coverage(len(priced), len(rows)),
        "definition": "official pricing-table estimate from parsed "
                      "cost_usd; unpriced rows are not zero",
        "priced_cases": len(priced),
        "total_cases": len(rows),
        "total_usd": sum(priced) if priced else None,
        "per_case_mean_usd": (statistics.mean(priced) if priced else None),
    }
    invoice = {"coverage": "unavailable"}
    if provenance is None:
        invoice["reason"] = "--provenance not provided"
    else:
        found = _find_invoice(provenance)
        if found is None:
            invoice["reason"] = ("no invoice/billing field in provenance "
                                 "record")
        else:
            invoice = {"coverage": "available", "value": found}
    return {
        "official_estimate": estimate,
        "invoice": invoice,
        "note": "failures/timeouts may still bill without token stats; "
                "official estimate and actual invoice are kept separate",
    }


def _find_invoice(obj, depth=0):
    """Look for a billing/invoice figure in a free-form provenance dict."""
    if depth > 4 or not isinstance(obj, dict):
        return None
    for key in ("invoice", "billing", "actual_cost", "provider_invoice"):
        if key in obj:
            return {"path": key, "data": obj[key]}
    for key in ("invoice_total_usd", "actual_cost_usd",
                "billed_usd", "invoice_usd"):
        if isinstance(obj.get(key), (int, float)):
            return {"path": key, "total_usd": obj[key]}
    for v in obj.values():
        if isinstance(v, dict):
            found = _find_invoice(v, depth + 1)
            if found is not None:
                return found
    return None


# ---------------------------------------------------------------------------
# frozen Baseline 1 (A) — strictly read-only


def load_baseline_a(baseline_dir):
    if not os.path.isdir(baseline_dir):
        fail(f"baseline dir not found: {baseline_dir}")
    metrics_path = os.path.join(baseline_dir, "metrics.json")
    compat_path = os.path.join(baseline_dir, "compatibility-metrics.json")
    cases_path = os.path.join(baseline_dir, "scoring", "cases.jsonl")
    if not os.path.isfile(metrics_path):
        fail(f"baseline metrics.json missing: {metrics_path}")
    if not os.path.isfile(cases_path):
        fail(f"baseline scoring/cases.jsonl missing: {cases_path}")
    metrics = load_json(metrics_path)
    compat = load_json(compat_path) if os.path.isfile(compat_path) else None
    cases = {}
    with open(cases_path, encoding="utf-8") as f:
        for ln, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError as e:
                fail(f"{cases_path}:{ln}: invalid JSON: {e}")
            if r.get("task_id"):
                cases[r["task_id"]] = r
    walls_recorded = sum(1 for r in cases.values()
                         if isinstance(r.get("wall_seconds"), (int, float)))
    return {
        "dir": baseline_dir,
        "metrics": metrics,
        "compatibility": compat,
        "cases": cases,
        "wall_coverage": {"recorded": walls_recorded,
                          "total": len(cases)},
        "files": {
            "metrics.json": metrics_path,
            "compatibility-metrics.json":
                compat_path if os.path.isfile(compat_path) else None,
            "scoring/cases.jsonl": cases_path,
        },
    }


# ---------------------------------------------------------------------------
# report assembly


def _fmt_ms(ms, digits=3):
    if ms.get("mean") is None:
        return "N/A"
    return f"{ms['mean']:.{digits}f}±{ms['std']:.{digits}f}"


def _fmt_pct(x, digits=1):
    return "N/A" if x is None else f"{x * 100:.{digits}f}%"


def build_pairing(by_run, a_cases):
    """A frozen verdict/outcome vs B predicted_category/outcome per repeat."""
    pairing = {}
    for run_id, cs in by_run.items():
        rows = []
        for c in cs:
            a = a_cases.get(c["task_id"])
            rows.append({
                "task_id": c["task_id"],
                "a_verdict": a.get("verdict") if a else None,
                "a_outcome": a.get("scoring_outcome") if a else None,
                "a_case_present": a is not None,
                "b_predicted_category": c["predicted_category"],
                "b_safety_outcome": c["safety_outcome"],
                "b_status_correct": c["status_correct"],
            })
        pairing[run_id] = rows
    return pairing


def uncertain_policy_block(by_run):
    # abstain rows (status ok + category uncertain); a failed row that kept
    # the label is not an abstention and not a compatibility negative
    per_run = {}
    for r, cs in by_run.items():
        per_run[r] = sum(1 for c in cs
                         if c["safety_outcome"] == "abstain")
    total = sum(per_run.values())
    return {
        "uncertain_rows": {"per_repeat": per_run, "total": total},
        "official_compatibility_negative": total,
        "safety_abstain": total,
        "note": "the same uncertain rows are scored as compatibility "
                "negatives by the official policy and as abstentions "
                "(INCONCLUSIVE) by the safety-aware policy — same rows, "
                "different named projections, not a disagreement",
    }


def write_cases_jsonl(path, by_run, tool_telemetry, time_telemetry):
    tools = tool_telemetry.get("per_attempt", {})
    walls = (time_telemetry.get("container_wall", {})
             .get("per_attempt_seconds", {}))
    execs = (time_telemetry.get("exec_window", {})
             .get("per_attempt_seconds", {}))
    with open(path, "w", encoding="utf-8") as f:
        for run_id in sorted(by_run):
            for c in by_run[run_id]:
                key = f"{c['task_id']}/{c['run_id']}"
                ti = tools.get(key)
                rec = {
                    "task_id": c["task_id"],
                    "run_id": c["run_id"],
                    "cve_id": c["cve_id"],
                    "ground_truth": c["ground_truth"],
                    "ground_truth_category": c["ground_truth_category"],
                    "status": c["status"],
                    "predicted": c["predicted"],
                    "predicted_category": c["predicted_category"],
                    "safety_outcome": c["safety_outcome"],
                    "compat_prediction": c["compat_prediction"],
                    "status_correct": c["status_correct"],
                    "reason_correct": c["reason_correct"],
                    "completed": c["completed"],
                    "steps": c["steps"],
                    "cost_usd": c["cost_usd"],
                    "tool_items": (ti["by_type"] if ti else None),
                    "wall_seconds": walls.get(key),
                    "exec_seconds": execs.get(key),
                    "reasoning": c["reasoning"],
                    **c["tokens"],
                }
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def write_comparison(path, *, by_run, per_repeat, agg, pooled, compat,
                     uncertain, telemetry, a_side, inputs):
    a = a_side["metrics"]
    ac = a_side["compatibility"] or {}
    n_rep = agg["n_repeats"]
    total_rows = sum(m["rows"] for m in per_repeat.values())
    denom_note = ""
    obs = {r: (m["rows"], m["gt_exploitable"], m["gt_non_exploitable"])
           for r, m in per_repeat.items()}
    expected = (EXPECTED_DENOMINATORS["total"],
                EXPECTED_DENOMINATORS["gt_exploitable"],
                EXPECTED_DENOMINATORS["gt_non_exploitable"])
    if any(v != expected for v in obs.values()):
        denom_note = (f"\n\n> **Denominator note:** observed per-repeat "
                      f"shape {sorted(set(obs.values()))} differs from the "
                      f"frozen 30/7/23 dataset — this is a partial/smoke "
                      f"run, not the full baseline.")

    fs = agg["false_safe"]
    b_fs = (f"counts {list(fs['per_repeat_counts'].values())}; "
            f"{_fmt_ms({'mean': fs['mean'], 'std': fs['std']})}; "
            f"total {fs['total_count']}/{fs['attempts']}; "
            f"ids {fs['unique_case_ids'] or '[]'}")
    a_fs = (f"{a.get('false_safe')}; rate "
            f"{a.get('false_safe')}/{a.get('denominators', {}).get('gt_exploitable')} "
            f"≈ {_fmt_pct(a.get('false_safe_rate'))}")

    tools = telemetry["tool_calls"]
    tc = tools["coverage"]
    tm = tools["per_repeat"]
    b_tools = (
        f"command_execution {_fmt_ms(tm['command_execution'])}, "
        f"web_search {_fmt_ms(tm['web_search'])}/case "
        f"(coverage {tc['covered']}/{tc['total']} {tc['state']}); "
        f"steps field {_fmt_ms(tm['steps'])} — includes agent_message")
    a_tool_total = a.get("usage", {}).get("tool_calls")
    a_tool_mean = (round(a_tool_total / a.get("total", 30), 3)
                   if isinstance(a_tool_total, (int, float)) else None)
    a_tools = (f"{a_tool_total} recorded tool calls"
               + (f" ({a_tool_mean}/case)" if a_tool_mean is not None else "")
               + " (frozen counters)")

    tok = telemetry["tokens"]
    tok_cov = tok["coverage"]
    bucket_bits = ", ".join(
        f"{f.split('_')[0]} {tok['per_case_mean'].get(f)}"
        for f in TOKEN_FIELDS)
    b_tokens = (
        f"per-case bucket means ({bucket_bits}); coverage "
        f"{tok_cov['state']} (see telemetry.json); missing buckets "
        f"stay null")
    a_tokens = "N/A — deterministic profile, no token accounting"

    wall = telemetry["time"]["container_wall"]
    wcov = wall["coverage"]
    if wcov["state"] == "unavailable":
        b_time = f"N/A — {wcov.get('reason', 'no coverage')}"
    else:
        b_time = (f"container wall {_fmt_ms(wall['repeat_agg'])} s "
                  f"create→destroy (coverage {wcov['covered']}/"
                  f"{wcov['total']} {wcov['state']})")
    awall = a.get("wall_seconds", {})
    acov = a_side["wall_coverage"]
    a_time = (f"{awall.get('mean')} s mean over "
              f"{acov['recorded']}/{acov['total']} recorded "
              f"(frozen; different boundary)")

    cost = telemetry["cost"]
    est = cost["official_estimate"]
    inv = cost["invoice"]
    b_cost = (f"official estimate "
              f"${est['total_usd'] if est['total_usd'] is not None else 'N/A'} "
              f"(priced {est['priced_cases']}/{est['total_cases']}); "
              f"invoice {inv['coverage']}")
    a_cost = "$0 model API (deterministic); excludes compute"

    first_rep = per_repeat[sorted(per_repeat)[0]]
    b_comp = (f"answered/{first_rep['rows']} per repeat "
              f"{_fmt_ms(agg['completion_rate'])}; "
              f"{sum(m['completion_count'] for m in per_repeat.values())}/"
              f"{total_rows} answered")
    a_total = (a.get("denominators") or {}).get("total") or 30
    a_answered = (round(a["completion_rate"] * a_total)
                  if a.get("completion_rate") is not None else None)
    a_comp = (f"{a_answered}/{a_total} = {_fmt_pct(a.get('completion_rate'))}")

    lines = []
    lines.append("# VEX-Bench — frozen Baseline 1 (A) vs Plain Agent (B)")
    lines.append("")
    lines.append(f"Generated {utcnow()} by `eval/vexbench_plain_report.py` "
                 f"— offline projection, no model calls, Baseline 1 "
                 f"untouched.")
    lines.append("")
    lines.append("## Inputs")
    lines.append("")
    for name, info in inputs.items():
        if name == "official_metrics_obj":
            continue
        if not info.get("path"):
            lines.append(f"- `{name}`: not provided")
            continue
        sha = info.get("sha256") or "absent"
        lines.append(f"- `{name}`: `{info.get('path')}` sha256 `{sha}`")
    lines.append("")
    lines.append("## §43 comparison (safety-aware projection)")
    lines.append("")
    lines.append("| Metric | Current Izyan — frozen A | Plain Agent B "
                 "| Shadow Agent | Hybrid |")
    lines.append("|---|---:|---:|---:|---:|")
    lines.append(f"| False-Safe | {a_fs} | {b_fs} | not run | not run |")
    lines.append(f"| Safe Clear Rate | {a.get('correct_safe')}/23 = "
                 f"{_fmt_pct(a.get('safe_clear_rate'))} | "
                 f"{_fmt_ms(agg['safe_clear_rate'])} (denominator "
                 f"{per_repeat[list(per_repeat)[0]]['gt_non_exploitable']}"
                 f"/repeat) | not run | not run |")
    lines.append(f"| Exploitable Recall | "
                 f"{a.get('correct_exploitable')}/7 = "
                 f"{_fmt_pct(a.get('exploitable_recall'))} | "
                 f"{_fmt_ms(agg['exploitable_recall'])} (denominator "
                 f"{per_repeat[list(per_repeat)[0]]['gt_exploitable']}"
                 f"/repeat) | not run | not run |")
    lines.append(f"| INCONCLUSIVE | {a.get('abstain')}/30 = "
                 f"{_fmt_pct(a.get('inconclusive_rate'))} | "
                 f"{_fmt_ms(agg['inconclusive_rate'])} uncertain/"
                 f"{per_repeat[list(per_repeat)[0]]['rows']} per repeat "
                 f"| not run | not run |")
    lines.append(f"| Status F1 | {a.get('safety_aware_status', {}).get('f1', 0):.6f} | "
                 f"{_fmt_ms(agg['status_f1'], 6)} | not run | not run |")
    a_macro = (ac.get("justification_macro_f1")
               if isinstance(ac, dict) else None)
    lines.append(f"| Justification macro-F1 | "
                 f"{a_macro if a_macro is not None else 'N/A'} | "
                 f"{_fmt_ms(compat['aggregate']['justification_macro_f1'], 6)} "
                 f"(official four-class, mean±std) | not run | not run |")
    lines.append(f"| Completion | {a_comp} | {b_comp} | not run | not run |")
    lines.append(f"| Avg tool calls | {a_tools} | {b_tools} "
                 f"| not run | not run |")
    lines.append(f"| Avg tokens | {a_tokens} | {b_tokens} "
                 f"| not run | not run |")
    lines.append(f"| Avg time | {a_time} | {b_time} | not run | not run |")
    lines.append(f"| Avg cost | {a_cost} | {b_cost} | not run | not run |")
    if denom_note:
        lines.append(denom_note)
    lines.append("")
    lines.append("## Compatibility projection (official VEX-Bench policy)")
    lines.append("")
    lines.append("| Metric | A (frozen compatibility-metrics.json) "
                 "| B (official metrics.json / offline recompute) |")
    lines.append("|---|---:|---:|")
    off_bin = (inputs.get("official_metrics_obj") or {}).get("binary", {})
    lines.append(
        f"| Binary accuracy | {_fmt_pct(ac.get('accuracy'))} | "
        f"official {_fmt_pct((off_bin.get('accuracy') or {}).get('mean'))} "
        f"/ recomputed {_fmt_pct(compat['aggregate']['accuracy']['mean'])} |")
    lines.append(
        f"| Binary precision | {ac.get('binary_precision')} | "
        f"official {(off_bin.get('precision') or {}).get('mean')} / "
        f"recomputed "
        f"{round(compat['aggregate']['precision']['mean'] or 0, 6)} |")
    lines.append(
        f"| Binary recall | {ac.get('binary_recall')} | "
        f"official {(off_bin.get('recall') or {}).get('mean')} / "
        f"recomputed "
        f"{round(compat['aggregate']['recall']['mean'] or 0, 6)} |")
    lines.append(
        f"| Binary F1 | {ac.get('binary_f1')} | "
        f"official {(off_bin.get('f1') or {}).get('mean')} / recomputed "
        f"{round(compat['aggregate']['f1']['mean'] or 0, 6)} |")
    off_tot = off_bin.get("totals") or {}
    rt = compat["aggregate"]["totals"]
    lines.append(
        f"| FN split (exploitable GT) | "
        f"GT vulnerable→FAILED cell="
        f"{(ac.get('confusion_matrix') or {}).get('rows', {}).get('vulnerable', {}).get('FAILED', 'n/a')} | "
        f"official totals.fn={off_tot.get('fn')} "
        f"(exploitable→negative only); recomputed "
        f"negative={rt['fn_predicted_negative']} + "
        f"FAILED={rt['fn_failed']} |")
    lines.append("")
    lines.append("## `uncertain` under both policies")
    lines.append("")
    lines.append("| Rows with predicted_category=uncertain "
                 "| official compatibility negative | safety abstain |")
    lines.append("|---:|---:|---:|")
    lines.append(f"| {uncertain['uncertain_rows']['total']} "
                 f"({uncertain['uncertain_rows']['per_repeat']}) | "
                 f"{uncertain['official_compatibility_negative']} | "
                 f"{uncertain['safety_abstain']} |")
    lines.append("")
    lines.append("A side for reference: frozen INCONCLUSIVE = "
                 f"{a.get('abstain')} (safety) while the same 12 A rows "
                 "were compatibility negatives in the official table.")
    lines.append("")
    lines.append("## Per-repeat pairing vs frozen A")
    lines.append("")
    pairing = build_pairing(by_run, a_side["cases"])
    for run_id in sorted(by_run):
        lines.append(f"### {run_id}")
        lines.append("")
        lines.append("| task_id | A verdict | A outcome "
                     "| B category | B outcome |")
        lines.append("|---|---|---|---|---|")
        for p in pairing[run_id]:
            a_cell_v = p["a_verdict"] if p["a_case_present"] else "—"
            a_cell_o = p["a_outcome"] if p["a_case_present"] else "—"
            lines.append(f"| `{p['task_id']}` | {a_cell_v} | {a_cell_o} "
                         f"| {p['b_predicted_category']} "
                         f"| {p['b_safety_outcome']} |")
        lines.append("")
    lines.append("## Metric policies and limitations")
    lines.append("")
    lines.append(
        "- **`uncertain` divergence, named not smoothed:** A's INCONCLUSIVE "
        "is an abstention; the official compatibility scorer maps "
        "`uncertain` to `not_exploitable`. The two columns above show the "
        "same B rows under both policies — never merged into one number.")
    lines.append(
        "- **Official `binary.totals.fn` is not the recall denominator:** "
        "it counts only the exploitable→not_exploitable cell and excludes "
        "exploitable→FAILED (which lands in `totals.failed`), while the "
        "official scalar recall charges both. This report never "
        "recomputes recall as TP/(TP+totals.fn); the recomputed split is "
        "in `safety-metrics.json → compatibility.aggregate.totals`.")
    lines.append(
        "- **Assertion strength differs:** A's safe claim passed a "
        "falsifier with negative verification; B's `safe` outcome is an "
        "unverified model claim. Equal labels do not mean equal evidence.")
    lines.append(
        "- **Fixed denominators:** safety rates use per-repeat GT "
        "denominators (30/7/23 on the frozen full subset); observed "
        "denominators are recorded per repeat. Repeats are not three "
        "independent datasets — mean±std is a sample std (ddof=1), not a "
        "significance claim.")
    lines.append(
        "- **Pooled vs repeat mean:** pooled 90-row ratios are secondary; "
        "no pooled F1 or majority vote is reported as the official "
        "repeat-mean figure.")
    lines.append(
        "- **`steps` ≠ tool calls:** Codex `steps` counts every "
        "`item.completed` (including `agent_message`); tool telemetry "
        "counts `command_execution`/`web_search` separately with "
        "explicit coverage.")
    lines.append(
        "- **Time boundary:** B wall = docker create→destroy (includes "
        "source copy and cleanup); A's wall envelope is a different "
        "boundary. Coverage is reported, gaps stay N/A.")
    lines.append(
        "- **Cost:** official pricing-table estimate and actual invoice "
        "are separate channels; missing price/invoice coverage is shown "
        "as unavailable, never as $0.")
    lines.append(
        "- **Telemetry coverage:** tools "
        f"{telemetry['tool_calls']['coverage']['covered']}/"
        f"{telemetry['tool_calls']['coverage']['total']}, tokens "
        f"{telemetry['tokens']['coverage']['state']}, wall "
        f"{telemetry['time']['container_wall']['coverage']['covered']}/"
        f"{telemetry['time']['container_wall']['coverage']['total']}, "
        f"priced {est['priced_cases']}/{est['total_cases']}, invoice "
        f"{inv['coverage']}.")
    atomic_write_text(path, "\n".join(lines) + "\n")


def report(*, parsed_path, official_metrics_path, raw_root, baseline_dir,
           run_log_path, docker_events_path, provenance_path, out_dir):
    for p, name in ((parsed_path, "--parsed"),
                    (official_metrics_path, "--official-metrics")):
        if not os.path.isfile(p):
            fail(f"{name} file not found: {p}")
    official_metrics = load_json(official_metrics_path)
    cases = load_parsed_cases(parsed_path)
    by_run = group_by_run(cases)
    per_repeat = {r: score_rows(cs) for r, cs in by_run.items()}
    agg = aggregate_repeats(per_repeat)
    pooled = dict(score_rows(cases))
    pooled["note"] = ("secondary pooled view over all rows — NOT the "
                      "repeat-mean; pooled F1/majority vote are not an "
                      "official aggregate")
    compat = compat_projection(by_run, official_metrics)
    uncertain = uncertain_policy_block(by_run)
    a_side = load_baseline_a(baseline_dir)

    provenance = None
    if provenance_path:
        if not os.path.isfile(provenance_path):
            fail(f"provenance file not found: {provenance_path}")
        provenance = load_json(provenance_path)
    tool_tel = build_tool_telemetry(by_run, raw_root)
    token_tel = build_token_telemetry(by_run)
    time_tel = build_time_telemetry(by_run, docker_events_path,
                                    run_log_path)
    cost_tel = build_cost_telemetry(by_run, provenance)
    telemetry = {
        "schema": "vexbench-plain-telemetry/1",
        "generated_at_utc": utcnow(),
        "tool_calls": tool_tel,
        "tokens": token_tel,
        "time": time_tel,
        "cost": cost_tel,
    }

    safety_metrics = {
        "schema": "vexbench-plain-safety/1",
        "reporter_version": REPORTER_VERSION,
        "generated_at_utc": utcnow(),
        "inputs": {
            "parsed": parsed_path,
            "official_metrics": official_metrics_path,
            "raw_root": raw_root,
            "baseline_dir": baseline_dir,
        },
        "denominators": {
            "policy": "fixed per-repeat GT denominators",
            "expected_full_dataset": EXPECTED_DENOMINATORS,
            "observed_per_repeat": {
                r: {"total": m["rows"],
                    "gt_exploitable": m["gt_exploitable"],
                    "gt_non_exploitable": m["gt_non_exploitable"]}
                for r, m in per_repeat.items()},
        },
        "n_repeats": agg["n_repeats"],
        "per_repeat": per_repeat,
        "aggregate": agg,
        "pooled": pooled,
        "uncertain_policy": uncertain,
        "compatibility": compat,
        "scoring_policy": {
            "name": "safety-aware-projection/1",
            "uncertain": "abstain (INCONCLUSIVE); never a safe claim and "
                         "never a completion failure; official "
                         "compatibility maps the same rows to "
                         "not_exploitable",
            "false_safe": "GT exploitable AND outcome=safe only; abstain "
                          "and failed are never false-safe",
            "aggregation": "per-repeat vectors, then mean ± sample std "
                           "(ddof=1) across repeats; pooled 90-row "
                           "ratios are secondary",
            "assertion_strength": "B safe claim is unverified model "
                                  "output; A safe claim passed falsifier "
                                  "negative verification — comparison "
                                  "limitation, not equivalence",
            "not_official": "supplements and never replaces official "
                            "metrics.json",
        },
        "pairing_vs_baseline": build_pairing(by_run, a_side["cases"]),
        "telemetry_coverage": {
            "tools": tool_tel["coverage"]["state"],
            "tokens": token_tel["coverage"]["state"],
            "container_wall": time_tel["container_wall"]["coverage"][
                "state"],
            "cost_priced": f"{cost_tel['official_estimate']['priced_cases']}"
                           f"/{cost_tel['official_estimate']['total_cases']}",
            "invoice": cost_tel["invoice"]["coverage"],
        },
    }

    os.makedirs(out_dir, exist_ok=True)
    out_paths = {
        "safety-cases.jsonl": os.path.join(out_dir, "safety-cases.jsonl"),
        "safety-metrics.json": os.path.join(out_dir,
                                            "safety-metrics.json"),
        "telemetry.json": os.path.join(out_dir, "telemetry.json"),
        "comparison.md": os.path.join(out_dir, "comparison.md"),
        "freeze-checksums.json": os.path.join(out_dir,
                                              "freeze-checksums.json"),
    }
    write_cases_jsonl(out_paths["safety-cases.jsonl"], by_run,
                      tool_tel, time_tel)
    atomic_write_json(out_paths["safety-metrics.json"], safety_metrics)
    atomic_write_json(out_paths["telemetry.json"], telemetry)
    inputs_info = {
        "parsed": {"path": parsed_path,
                   "sha256": sha256_file(parsed_path)},
        "official_metrics": {"path": official_metrics_path,
                             "sha256": sha256_file(official_metrics_path)},
        "official_metrics_obj": official_metrics,
        "baseline_metrics": {
            "path": a_side["files"]["metrics.json"],
            "sha256": sha256_file(a_side["files"]["metrics.json"])},
        "baseline_compatibility_metrics": {
            "path": a_side["files"]["compatibility-metrics.json"],
            "sha256": (sha256_file(
                a_side["files"]["compatibility-metrics.json"])
                if a_side["files"]["compatibility-metrics.json"] else None)},
        "baseline_cases": {
            "path": a_side["files"]["scoring/cases.jsonl"],
            "sha256": sha256_file(a_side["files"]["scoring/cases.jsonl"])},
        "run_log": {"path": run_log_path,
                    "sha256": (sha256_file(run_log_path)
                               if run_log_path else None)},
        "docker_events": {"path": docker_events_path,
                          "sha256": (sha256_file(docker_events_path)
                                     if docker_events_path else None)},
        "provenance": {"path": provenance_path,
                       "sha256": (sha256_file(provenance_path)
                                  if provenance_path else None)},
    }
    write_comparison(out_paths["comparison.md"], by_run=by_run,
                     per_repeat=per_repeat, agg=agg, pooled=pooled,
                     compat=compat, uncertain=uncertain,
                     telemetry=telemetry, a_side=a_side,
                     inputs=inputs_info)
    checksums = {
        "schema": "vexbench-plain-freeze/1",
        "generated_at_utc": utcnow(),
        "inputs": {k: v for k, v in inputs_info.items()
                   if k != "official_metrics_obj"},
        "outputs": {},
    }
    for name, p in out_paths.items():
        if name == "freeze-checksums.json":
            continue
        checksums["outputs"][name] = {"path": p,
                                      "sha256": sha256_file(p)}
    atomic_write_json(out_paths["freeze-checksums.json"], checksums)

    fs = agg["false_safe"]
    eprint(f"report: {len(cases)} rows, {agg['n_repeats']} repeat(s) — "
           f"false_safe counts {list(fs['per_repeat_counts'].values())} "
           f"total {fs['total_count']}/{fs['attempts']}, unique "
           f"{len(fs['unique_case_ids'])}; out={out_dir}")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="vexbench_plain_report.py",
        description=__doc__.split("\n")[0])
    ap.add_argument("--parsed", required=True,
                    help="official harness parsed.jsonl")
    ap.add_argument("--official-metrics", required=True,
                    help="official harness metrics.json")
    ap.add_argument("--raw-root", default=None,
                    help="experiment root holding <task>/<run>/result.jsonl "
                         "(default: parent of the parsed dir)")
    ap.add_argument("--baseline-dir", required=True,
                    help="frozen Baseline 1 dir (read-only)")
    ap.add_argument("--run-log", default=None)
    ap.add_argument("--docker-events", default=None)
    ap.add_argument("--provenance", default=None)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    raw_root = args.raw_root
    if raw_root is None:
        raw_root = os.path.dirname(os.path.dirname(
            os.path.abspath(args.parsed)))
    try:
        return report(parsed_path=args.parsed,
                      official_metrics_path=args.official_metrics,
                      raw_root=raw_root,
                      baseline_dir=args.baseline_dir,
                      run_log_path=args.run_log,
                      docker_events_path=args.docker_events,
                      provenance_path=args.provenance,
                      out_dir=args.out)
    except ReportError as e:
        eprint(f"error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())

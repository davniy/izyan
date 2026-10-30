#!/usr/bin/env python3
"""Offline usage-scope regression over saved research runs (NO LLM).

Rebuilds the persisted agent turn of every saved `izyan research` run
under the current contract and censuses, per case and per set,
BEFORE vs AFTER:

  * `affected package/symbol used by product code` — the B42 required
    path condition, one row per advisory-declared candidate
    (SUPPORTED / REFUTED / UNKNOWN / ABSENT)
  * `affected package reachable` and `affected package build-relevant`
  * every `package-usage` observation state (tool_status, completeness,
    usage verdict, negative_verification)
  * B41 `usage-scope` observations and promoted BUILD_USAGE_SCOPE
    facts — the per-case `usage_scope` classes produced (product /
    test-only / mixed / unknown / absent), fact counts, the
    `build_usage_scope` axis status and `product_absence_verification`
  * `evidence_level.level` and its blocking conditions

Sources and outputs:
  primary input    : <primary-root>/<UNIT>/<primary-input-suffix>
  primary baseline : <primary-root>/<UNIT>/<primary-baseline-suffix>
  retry input      : <retry-glob>/<UNIT>/<retry-input-suffix>
  retry baseline   : <retry-glob>/<UNIT>/<retry-baseline-suffix>
  specialist input : <specialist-root>/<UNIT>/<specialist-input-suffix>
The input dir (default ``agent``) is the replay source — its recorded
agent turn is authoritative. The baseline dir is the recorded BEFORE
rebuild: ``agent-v3`` is the pre-B42 rebuild and ``agent-v4`` the
post-B42 one; the census recorded for that suffix is enforced exactly
(7/24/0 primary, 2/9/0 retry for agent-v3; 0/31/0 primary, 0/11/0
retry for agent-v4) BEFORE any replay starts — a different baseline
means a changed input set and fails the command. The specialist set
carries no baseline sibling: with ``--specialist-historical-before``
its BEFORE row is the saved report from the input directory itself
(a historical document, not a full byte-parity baseline), and a
missing specialist root, label map or saved report is a hard NOT_RUN
blocker, never a silent skip. Rebuilt output goes to a NEW sibling
(<UNIT>/<b41-out-suffix>, default ``agent-v5``) or under
``--work-dir``; the input and baseline evidence are never touched and
every input dir is sha256-hashed before and after.

NO MODEL RUNS: every case invokes the compiled CLI with
``--replay-agent-turn <saved run dir>`` and no live harness/model flags;
network is off (GOPROXY=off, GOSUMDB=off, GOFLAGS=-mod=readonly). Replay
is never combined with --deterministic-only/--no-agent (the CLI rejects
that pair anyway).

Per-case assertions (any failure fails the whole command):
  * report.json parses and the process self-validated it (the CLI runs
    research.Validate before exiting 0 — fail-closed);
  * contract_extensions contains slice2-fidelity/3 and no other
    recognized marker;
  * evidence_level is present with a closed-enum level/basis;
  * agent_output.status and agent_output.extraction.status equal the
    saved report's recorded values;
  * every recorded artifact pin (answer_artifact, raw_artifact,
    result_artifact, extraction.answer_artifact — path/sha256/
    size_bytes/selector) is preserved verbatim, and the pinned bytes on
    disk still match the recorded sha256;
  * agent_output.replayed_from is present and digests match the source;
  * run.harness carries no live-turn pins (replay performs no model call);
  * disposition.class=REVIEW_REQUIRED, disposition.auto_close=false;
  * no agent ref (agent-src:…, assertion ids, agent_output category/
    reasoning strings) occurs in evidence_level.evidence_refs;
  * exploitation_established is not ESTABLISHED and level is not
    L3_DYNAMIC_EXPLOITATION unless the source run retained a verified
    dynamic fact (runtime-observation | dynamic-trace | reproduction).

B41 invariants on top (after-vs-baseline):
  * byte-identical semantic projection: advisory/vulnerability identity,
    affected_implementations, snapshot/build identity, the whole
    product_applicability block, agent_output (minus replayed_from), the
    masked attempt rows, exploitation_conditions, the non-B41 verified
    facts (minus provenance.generated_at), every pre-existing
    exploitation axis, evidence_level, disposition, the agent-owned
    sections, the classification review and the non-B41 unknown /
    question rows — any change fails as an unrelated semantic change;
  * usage-condition subjects are exactly the advisory-declared
    package/symbol candidates (module-only advisories gain none — no
    guessed package paths);
  * a REFUTED usage aggregate never yields L1 and stays REVIEW_REQUIRED;
  * every L1 case has all required applicability/path conditions
    SUPPORTED, and every SUPPORTED usage condition cites an OK
    PACKAGE_USAGE fact whose usage_subject matches the condition's;
  * every promoted BUILD_USAGE_SCOPE fact is COMPLETE, carries a closed
    usage_scope enum value, and a test-only class exists only with
    product_absence_verification=VERIFIED; the build_usage_scope axis
    exists iff such facts do, cites exactly those fact ids and is never
    cited by a condition, evidence_level or product_applicability.

The AFTER census is measured and reported, never asserted. Repeating the
run over identical inputs must produce identical condition states, B41
classes, axis JSON and level JSON (run twice with a fresh --work-dir and
diff the reports minus wall-clock fields).

Privacy: only C-labels are printed or persisted; unit identifiers,
snapshot basenames and absolute local paths are scrubbed from every
emitted string. The label map files are read-only input and are
themselves gitignored.

Usage:
  python3 tools/evidence-levels-replay.py \
    --primary-root <.../tmp/exploitable/runs> \
    --primary-input-suffix agent --primary-baseline-suffix agent-v4 \
    --retry-glob '<.../tmp/exploitable-retry/runs>' \
    --retry-glob '<.../tmp/exploitable-retry-invalid/runs>' \
    --retry-input-suffix agent --retry-baseline-suffix agent-v4 \
    --specialist-root <.../tmp/agent7-corp/runs> \
    --specialist-input-suffix agent \
    --specialist-label-map <private specialist-labels.json> \
    --specialist-historical-before \
    --label-map <private ticket-labels.json> \
    --izyan <compiled binary> --govulndb <frozen DB> --modcache <cache> \
    [--work-dir DIR] [--b41-out-suffix agent-v5] [--jobs N] \
    [--only C07,...] [--report PATH]
"""
import argparse
import glob as globmod
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections import Counter

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GOBIN = os.path.expanduser("~/go/bin")

# The recorded runs used a 1m deterministic per-tool bound, sized for a
# lane where run_govulncheck was unconditionally UNSUPPORTED. A real
# local-DB scan needs minutes, so replay runs with a per-tool budget that
# lets the actual check complete (the saved-turn replay is unchanged).
DET_TIMEOUT = "20m"
OVERALL_TIMEOUT = "90m"
SUBPROCESS_TIMEOUT = 90 * 60 + 300

DYNAMIC_CARRIER_TOOLS = ("runtime-observation", "dynamic-trace", "reproduction")
RECOGNIZED_MARKERS = ("slice2-fidelity/1", "slice2-fidelity/2", "slice2-fidelity/3")
V3_MARKER = "slice2-fidelity/3"

SUBJ_MODULE_PRESENCE = "affected module presence"
SUBJ_VERSION_IN_USE = "affected version in use"
SUBJ_PACKAGE_REACH = "affected package reachable"
SUBJ_BUILD_RELEVANT = "affected package build-relevant"
SUBJ_PRODUCT_PACKAGE_USAGE = "affected package/symbol used by product code"
PACKAGE_USAGE_TOOL = "package-usage"
PACKAGE_USAGE_FACT_KINDS = ("PACKAGE_USAGE", "PACKAGE_USAGE_LOWER_BOUND")
BUILD_USAGE_SCOPE_KIND = "BUILD_USAGE_SCOPE"
USAGE_SCOPE_TOOL = "usage-scope"
USAGE_SCOPE_VALUES = ("product", "test-only", "mixed", "unknown")
SUBJ_BUILD_USAGE_SCOPE = "build usage scope"
STATIC_CARRIER_TOOLS = {
    "affected-resolve", "get_module_version", "get_dependency_graph",
    "module_usage", "module_internal_reach", "find_symbol", "find_callers",
    "find_may_callers", "find_dep_callers", "ingress-inventory",
    "package-usage", "find_entrypoints", "listen-sites",
    "inbound-auth-facts", "interface_dispatch_sites", "gated_refs",
    "scan_dynamic", "dial-sites", "trace_argument",
}

# Recorded baselines, keyed by the baseline sibling's suffix:
# ``agent-v3`` is the pre-B42 rebuild of the saved inputs and
# ``agent-v4`` the post-B42 rebuild (the measured B41-before state).
# The driver enforces the matrix for the suffix actually supplied
# BEFORE any replay runs; a different census means a changed input
# set, not a different expectation. A suffix with no recorded matrix
# aborts the run (an unverified baseline is never trusted silently) —
# pass --no-matrix-assert for an ad-hoc census.
EXPECTED_BASELINE = {
    "agent-v3": {
        "primary": {
            "total": 31,
            "L1_STATIC_PATH": ["C01", "C03", "C07", "C14", "C15", "C16", "C17"],
            "L2_POTENTIAL_PATH": 24,
            "L3_DYNAMIC_EXPLOITATION": 0,
        },
        "retry": {
            "total": 11,
            "L1_STATIC_PATH": ["C01", "C03"],
            "L2_POTENTIAL_PATH": 9,
            "L3_DYNAMIC_EXPLOITATION": 0,
        },
    },
    "agent-v4": {
        "primary": {
            "total": 31,
            "L1_STATIC_PATH": [],
            "L2_POTENTIAL_PATH": 31,
            "L3_DYNAMIC_EXPLOITATION": 0,
        },
        "retry": {
            "total": 11,
            "L1_STATIC_PATH": [],
            "L2_POTENTIAL_PATH": 11,
            "L3_DYNAMIC_EXPLOITATION": 0,
        },
    },
}

# Populated from the loaded label maps plus discovered snapshot
# basenames: every private identifier is scrubbed from anything the
# driver prints or persists, so the private naming scheme never
# appears in output. Label maps accumulate across --label-map and
# --specialist-label-map so every set's units are scrubbed.
_UNIT_RE = None
_UNIT_ALL = {}
_EXTRA_SCRUB = []


def scrub(text):
    """Remove private identifiers and local paths from emitted strings."""
    if not text:
        return text
    text = re.sub(r"/Users/[^\s'\"]+", "<PATH>", str(text))
    for pat in _EXTRA_SCRUB:
        text = pat.sub("<snap>", text)
    if _UNIT_RE is not None:
        text = _UNIT_RE.sub("<unit>", text)
    return text


def scrub_obj(obj):
    """Deep-scrub a JSON-able structure for the persisted report."""
    return json.loads(scrub(json.dumps(obj)))


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_tree(root):
    """Digest of an entire directory: every relative path, file mode bits
    and byte content, plus symlink targets. Any byte change flips it."""
    h = hashlib.sha256()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(dirnames + filenames):
            p = os.path.join(dirpath, name)
            rel = os.path.relpath(p, root)
            h.update(rel.encode())
            if os.path.islink(p):
                h.update(b"L")
                h.update(os.readlink(p).encode())
            elif os.path.isfile(p):
                h.update(b"F")
                h.update(sha256_file(p).encode())
    return h.hexdigest()


# ---------------------------------------------------------------- discovery

def load_label_map(path):
    """Load a private {label: unit} map. Labels are contractually
    C01–C31; the same unit in two maps with different labels is a
    conflict. Units accumulate globally so scrub() covers every set."""
    raw = json.load(open(path))
    unit2label = {}
    for label, unit in raw.items():
        if not re.fullmatch(r"C\d{2}", label):
            raise SystemExit(f"label map: unexpected label {label!r}")
        n = int(label[1:])
        if n < 1 or n > 31:
            raise SystemExit(f"label map: label {label!r} outside C01–C31")
        if unit in _UNIT_ALL and _UNIT_ALL[unit] != label:
            raise SystemExit(f"label map: one unit mapped to two labels")
        unit2label[unit] = label
    _UNIT_ALL.update(unit2label)
    global _UNIT_RE
    _UNIT_RE = re.compile("|".join(sorted(
        (re.escape(u) for u in _UNIT_ALL), key=len, reverse=True)))
    return unit2label


def _case(setname, unit, label, case_dir, input_suffix, baseline_suffix):
    return {"set": setname, "unit": unit, "label": label,
            "src": os.path.join(case_dir, input_suffix),
            "baseline": os.path.join(case_dir, baseline_suffix),
            "case_dir": case_dir}


def discover_primary_runs(primary_root, input_suffix, baseline_suffix, unit2label):
    """Yield case dicts for every <primary-root>/<UNIT>/<input> holding a
    run manifest."""
    out = []
    for unit in sorted(os.listdir(primary_root)):
        d = os.path.join(primary_root, unit, input_suffix)
        if os.path.isfile(os.path.join(d, "run-manifest.json")):
            label = unit2label.get(unit)
            if label is None:
                raise SystemExit(f"label map has no label for a primary unit under {primary_root}")
            out.append(_case("primary", unit, label,
                             os.path.join(primary_root, unit),
                             input_suffix, baseline_suffix))
    return out


def discover_retry_runs(retry_globs, input_suffix, baseline_suffix, unit2label):
    """Yield case dicts for every <glob>/<UNIT>/<input> under each retry
    root. Set name = the root's parent basename (exploitable-retry…)."""
    out = []
    for g in retry_globs:
        roots = sorted(globmod.glob(g))
        if not roots:
            raise SystemExit(f"retry glob matched nothing: {g}")
        for root in roots:
            setname = os.path.basename(os.path.dirname(root.rstrip("/")))
            for unit in sorted(os.listdir(root)):
                d = os.path.join(root, unit, input_suffix)
                if os.path.isfile(os.path.join(d, "run-manifest.json")):
                    label = unit2label.get(unit)
                    if label is None:
                        raise SystemExit(f"label map has no label for a retry unit under {root}")
                    out.append(_case(setname, unit, label,
                                     os.path.join(root, unit),
                                     input_suffix, baseline_suffix))
    return out


def discover_specialist_runs(root, input_suffix, unit2label):
    """Yield case dicts for every <specialist-root>/<UNIT>/<input> with a
    run manifest. The specialist set keeps its BEFORE inside the saved
    input itself (--specialist-historical-before): no baseline sibling
    is assumed. Any unmapped unit is a set-level blocker the caller
    reports as NOT_RUN — never a silent skip, never a partial set."""
    out, blockers = [], []
    for unit in sorted(os.listdir(root)):
        d = os.path.join(root, unit, input_suffix)
        if not os.path.isfile(os.path.join(d, "run-manifest.json")):
            continue
        label = unit2label.get(unit)
        if label is None:
            blockers.append("specialist label map has no label for a unit")
            continue
        c = _case("specialist", unit, label,
                  os.path.join(root, unit), input_suffix, input_suffix)
        c["historical_before"] = True
        out.append(c)
    if blockers:
        return [], sorted(set(blockers))
    return out, []


def read_run_manifest(src):
    mp = os.path.join(src, "run-manifest.json")
    try:
        return json.load(open(mp))
    except Exception as e:
        raise ValueError(f"run-manifest.json unreadable: {e}")


def missing_inputs(case):
    """Pre-flight: anything absent means the case cannot run — report it
    as NOT_RUN with the exact blocker instead of skipping silently."""
    src = case["src"]
    mp = os.path.join(src, "run-manifest.json")
    if not os.path.isfile(mp):
        return "run-manifest.json missing"
    try:
        man = read_run_manifest(src)
    except ValueError as e:
        return str(e)
    snap = (man.get("snapshot") or {}).get("path")
    if not snap or not os.path.isdir(snap):
        return f"snapshot dir missing: {snap}"
    if not (man.get("advisory") or {}).get("requested_id"):
        return "manifest advisory.requested_id missing"
    adv = (man.get("advisory") or {}).get("source_path")
    if not adv or not os.path.isfile(adv):
        return f"advisory file missing: {adv}"
    if not os.path.isfile(os.path.join(src, "report.json")):
        return "saved report.json missing (nothing to replay)"
    try:
        json.load(open(os.path.join(src, "report.json")))
    except Exception as e:
        return f"saved report.json unreadable: {e}"
    if case.get("historical_before"):
        # The saved report is its own historical BEFORE; no baseline
        # sibling is required for specialist cases.
        return None
    if not os.path.isfile(os.path.join(case["baseline"], "report.json")):
        return f"baseline report missing: {case['baseline']}"
    return None


# ------------------------------------------------------- baseline loading

def baseline_dir_for(case):
    """The directory whose report is the case's BEFORE state."""
    if case.get("historical_before"):
        return case["src"]
    return case["baseline"]


def load_baseline_report(case):
    """Load the recorded BEFORE for a case — the baseline sibling, or
    the saved report itself under --specialist-historical-before.
    Returns (report, package-usage observation rows); (None, []) when
    absent."""
    bp = baseline_dir_for(case)
    rp = os.path.join(bp, "report.json")
    if not os.path.isfile(rp):
        return None, []
    return json.load(open(rp)), package_usage_observations(bp)


def package_usage_observations(run_dir):
    """Every package-usage audit record in a run dir, flattened to the
    state fields the census needs."""
    out = []
    op = os.path.join(run_dir, "observations.jsonl")
    if not os.path.isfile(op):
        return out
    for line in open(op):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        if rec.get("tool") != PACKAGE_USAGE_TOOL:
            continue
        obs = rec.get("observation") or {}
        data = obs.get("data") or {}
        args = rec.get("args") or {}
        out.append({
            "tool_status": obs.get("tool_status"),
            "completeness": obs.get("completeness"),
            "usage": data.get("usage"),
            "negative_verification": data.get("negative_verification"),
            "present": data.get("present"),
            "module": args.get("module") or data.get("module"),
            "package": args.get("package") or data.get("package"),
            "symbol": args.get("symbol") or data.get("symbol") or "",
        })
    return out


def usage_scope_rows(report, run_dir=None):
    """Flatten B41 observations and promoted facts for one report."""
    rows = []
    op = os.path.join(run_dir, "observations.jsonl") if run_dir else ""
    if op and os.path.isfile(op):
        for line in open(op):
            try:
                rec = json.loads(line)
            except Exception:
                continue
            if rec.get("tool") != USAGE_SCOPE_TOOL:
                continue
            obs = rec.get("observation") or {}
            data = obs.get("data") or {}
            args = rec.get("args") or {}
            rows.append({
                "tool_status": obs.get("tool_status"),
                "completeness": obs.get("completeness"),
                "usage_scope": data.get("usage_scope"),
                "product_absence_verification": data.get("product_absence_verification"),
                "module": args.get("module") or data.get("module"),
                "package": args.get("package") or data.get("package"),
            })
    facts = [f for f in report.get("verified_facts") or []
             if f.get("kind") == BUILD_USAGE_SCOPE_KIND]
    facts = sorted(facts, key=lambda f: json.dumps(f.get("usage_subject") or {}, sort_keys=True))
    fact_rows = [{
        "id": f.get("id"),
        "usage_scope": f.get("usage_scope"),
        "product_absence_verification": f.get("product_absence_verification"),
        "coverage": f.get("coverage"),
        "usage_subject": f.get("usage_subject"),
    } for f in facts]
    axis = ((report.get("exploitation_axes") or {}).get("build_usage_scope") or {})
    return {"observations": rows, "facts": fact_rows, "axis": axis}


def usage_scope_census(reports, run_dirs=None):
    """Census B41 classes, fact/verification counts, completeness and axis."""
    out = Counter()
    axis = Counter()
    for key, report in reports.items():
        data = usage_scope_rows(report, (run_dirs or {}).get(key))
        facts = data["facts"]
        out["facts"] += len(facts)
        out["product_absence_verification"] += sum(
            f.get("product_absence_verification") == "VERIFIED" for f in facts)
        out["complete_facts"] += sum(f.get("coverage") == "COMPLETE" for f in facts)
        out["incomplete_observations"] += sum(
            o.get("completeness") != "COMPLETE" for o in data["observations"])
        if not facts:
            out["absent"] += 1
        for fact in facts:
            out[fact.get("usage_scope") or "unknown"] += 1
        axis[data["axis"].get("status") or "ABSENT"] += 1
    out["axis_status"] = dict(sorted(axis.items()))
    return dict(sorted(out.items()))


def assert_usage_scope_branch(report, run_dir=None):
    """Validate measured B41 shape without assuming class counts."""
    errs = []
    data = usage_scope_rows(report, run_dir)
    facts = data["facts"]
    axis = data["axis"]
    if facts and not axis:
        errs.append("B41 facts present without build_usage_scope axis")
    if not facts and axis:
        errs.append("build_usage_scope axis present without B41 facts")
    for fact in facts:
        scope = fact.get("usage_scope")
        if scope not in USAGE_SCOPE_VALUES:
            errs.append(f"invalid B41 usage_scope {scope!r}")
        if scope == "test-only" and fact.get("product_absence_verification") != "VERIFIED":
            errs.append("test-only B41 fact lacks VERIFIED product absence")
        if scope != "test-only" and fact.get("product_absence_verification"):
            errs.append(f"product absence marker on {scope} B41 fact")
        if fact.get("coverage") != "COMPLETE":
            errs.append("promoted B41 fact is not COMPLETE")
    return errs


def assert_scope_axis_consistency(report):
    """The build_usage_scope axis is derived purely from the B41 fact
    ledger: it exists iff such facts exist, cites exactly their ids in
    sorted order, carries the deterministic PACKAGE_BUILD basis and is
    ESTABLISHED only when every recorded class is known. B41 facts are
    strictly non-carrier: claim=TRUE, no NegativeVerification, and
    their ids never occur in condition/level/applicability evidence."""
    errs = []
    b41 = [f for f in report.get("verified_facts") or []
           if f.get("kind") == BUILD_USAGE_SCOPE_KIND]
    b41_ids = sorted(f.get("id") for f in b41)
    axis = (report.get("exploitation_axes") or {}).get("build_usage_scope")
    if bool(b41_ids) != isinstance(axis, dict):
        errs.append("build_usage_scope axis presence disagrees with the B41 fact ledger")
    if isinstance(axis, dict):
        if sorted(axis.get("evidence_refs") or []) != b41_ids:
            errs.append("build_usage_scope axis evidence_refs != sorted B41 fact ids")
        if axis.get("basis") != "deterministic" or axis.get("level") != "PACKAGE_BUILD":
            errs.append(f"build_usage_scope axis carries non-B41 basis/level: "
                        f"{axis.get('basis')!r}/{axis.get('level')!r}")
        known = all(f.get("usage_scope") in ("product", "test-only", "mixed")
                    for f in b41)
        want = "ESTABLISHED" if known else "UNKNOWN"
        if axis.get("status") != want:
            errs.append(f"build_usage_scope axis status {axis.get('status')!r} != derived {want!r}")
        for ref in axis.get("evidence_refs") or []:
            if str(ref).startswith("agent"):
                errs.append("build_usage_scope axis cites agent material")
    for f in b41:
        if f.get("claim") != "TRUE":
            errs.append(f"B41 fact {f.get('id')} has claim={f.get('claim')!r}")
        if f.get("negative_verification"):
            errs.append(f"B41 fact {f.get('id')} carries B42 NegativeVerification")
    for c in report.get("exploitation_conditions") or []:
        for ref in c.get("evidence_refs") or []:
            if ref in b41_ids:
                errs.append(f"condition {c.get('id')} cites non-carrier B41 fact {ref}")
    el = report.get("evidence_level") or {}
    for ref in el.get("evidence_refs") or []:
        if ref in b41_ids:
            errs.append(f"evidence_level cites non-carrier B41 fact {ref}")
    pa = report.get("product_applicability") or {}
    for ref in pa.get("evidence_refs") or []:
        if ref in b41_ids:
            errs.append(f"product_applicability cites non-carrier B41 fact {ref}")
    if any(f.get("usage_scope") == "test-only" for f in b41) and \
            pa.get("vulnerable_code_reachability") == "FALSE":
        errs.append("vulnerable_code_reachability=FALSE on a test-only B41 report")
    return errs


# -------------------------------------------------------- condition state

def _usage_subject_key(us):
    if not isinstance(us, dict):
        return None
    return (us.get("module") or "", us.get("package") or "", us.get("symbol") or "")


def _subject_rows(report, subject):
    """All conditions carrying `subject`, flattened for the census."""
    rows = []
    for c in report.get("exploitation_conditions") or []:
        if c.get("subject") != subject:
            continue
        rows.append({"id": c.get("id"), "state": c.get("state"),
                     "origin": c.get("origin"), "role": c.get("role"),
                     "necessity": c.get("necessity"),
                     "usage_subject": c.get("usage_subject"),
                     "evidence_refs": c.get("evidence_refs") or []})
    return rows


def condition_state_for_case(report, subject):
    """Aggregate state of one condition subject for a case.

    Usage-subject rule (the multi-candidate condition): REFUTED if any
    required usage condition is REFUTED; otherwise UNKNOWN if any is
    UNKNOWN; otherwise SUPPORTED when at least one exists and all are
    SUPPORTED; ABSENT when the report carries no usage condition at all
    (the advisory declared no bounded package/symbol candidate). The same
    worst-of ordering is used for the other path subjects, with any
    non-SUPPORTED/non-REFUTED state counting as UNKNOWN."""
    rows = _subject_rows(report, subject)
    if not rows:
        return "ABSENT"
    states = [r["state"] for r in rows]
    if "REFUTED" in states:
        return "REFUTED"
    if all(s == "SUPPORTED" for s in states):
        return "SUPPORTED"
    return "UNKNOWN"


def census_levels(reports):
    """Level census over a {key: report} mapping."""
    c = Counter()
    for r in reports.values():
        c[(r.get("evidence_level") or {}).get("level") or "NONE"] += 1
    return dict(c)


def census_path_conditions(reports):
    """Aggregate-state census per path condition subject."""
    out = {}
    for subj in (SUBJ_PACKAGE_REACH, SUBJ_BUILD_RELEVANT,
                 SUBJ_PRODUCT_PACKAGE_USAGE):
        out[subj] = dict(Counter(condition_state_for_case(r, subj)
                                 for r in reports.values()))
    return out


# ------------------------------------------------------- advisory subjects

def expected_usage_subjects(case, saved):
    """The advisory-declared package/symbol candidates a rebuilt report
    may carry, derived from the frozen advisory file the manifest names —
    the same projection packageUsageCandidates applies. Returns (subjects
    as sorted key tuples, module_only flag)."""
    man = read_run_manifest(case["src"])
    adv_path = (man.get("advisory") or {}).get("source_path")
    go_modules = set()
    for im in saved.get("affected_implementations") or []:
        if im.get("binding") not in ("exact", "alias-resolved", "incomplete"):
            continue
        if im.get("ecosystem") not in (None, "", "Go"):
            continue
        if im.get("module"):
            go_modules.add(im["module"])
    subjects = set()
    try:
        doc = json.load(open(adv_path))
    except Exception:
        return sorted(subjects), not subjects, adv_path
    for a in doc.get("affected") or []:
        name = ((a.get("package") or {}).get("name")) or ""
        eco = (a.get("package") or {}).get("ecosystem") or ""
        if eco not in ("", "Go") or (go_modules and name not in go_modules):
            continue
        for imp in ((a.get("ecosystem_specific") or {}).get("imports")) or []:
            path = imp.get("path")
            if not path:
                continue
            subjects.add((name, path, ""))
            for sym in imp.get("symbols") or []:
                subjects.add((name, path, sym))
    return sorted(subjects), not subjects, adv_path


# ------------------------------------------------------------------- replay

def replay_one(case, out_dir, args):
    """Invoke the compiled CLI for one case. Returns (wall_s, rc,
    stderr_tail, stdout_tail). Never emits the unit name."""
    man = read_run_manifest(case["src"])
    snap = man["snapshot"]["path"]
    cve = man["advisory"]["requested_id"]
    adv = man["advisory"]["source_path"]
    opts = man.get("options") or {}
    ext = man["snapshot"].get("external_commit_sha") or man["snapshot"].get("commit_sha") or ""
    shutil.rmtree(out_dir, ignore_errors=True)
    os.makedirs(out_dir, exist_ok=True)
    cmd = [args.izyan, "research",
           "--snapshot", snap, "--cve", cve, "--advisory-file", adv,
           "--output-dir", out_dir,
           "--deterministic-timeout", DET_TIMEOUT,
           "--overall-timeout", OVERALL_TIMEOUT,
           "--replay-agent-turn", case["src"]]
    if ext:
        cmd += ["--external-commit-sha", ext]
    for flag, key in (("--analysis-go", "analysis_go"), ("--goos", "goos"),
                      ("--goarch", "goarch")):
        if opts.get(key):
            cmd += [flag, opts[key]]
    if opts.get("build_tags"):
        cmd += ["--build-tags", ",".join(opts["build_tags"])]
    if args.govulndb:
        cmd += ["--govulndb", args.govulndb]
    if args.modcache:
        cmd += ["--modcache", args.modcache]
    env = dict(os.environ,
               GOPROXY="off", GOSUMDB="off", GOFLAGS="-mod=readonly",
               PATH=GOBIN + os.pathsep + os.environ.get("PATH", ""))
    t0 = time.time()
    try:
        p = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True,
                           timeout=SUBPROCESS_TIMEOUT, env=env)
    except subprocess.TimeoutExpired:
        return round(time.time() - t0, 1), None, \
            f"case exceeded {SUBPROCESS_TIMEOUT}s subprocess timeout", ""
    return round(time.time() - t0, 1), p.returncode, \
        (p.stderr or "")[-800:], (p.stdout or "")[-400:]


# ------------------------------------------------------------------- checks

def _pins_of(report):
    """All artifact pins a report records, as (scope, pin_dict) pairs."""
    ao = report.get("agent_output") or {}
    out = []
    for k in ("answer_artifact", "raw_artifact", "result_artifact"):
        if isinstance(ao.get(k), dict) and ao[k]:
            out.append((f"agent_output.{k}", ao[k]))
    ex = ao.get("extraction") or {}
    if isinstance(ex.get("answer_artifact"), dict) and ex["answer_artifact"]:
        out.append(("agent_output.extraction.answer_artifact", ex["answer_artifact"]))
    # Only the persisted agent attempt's pins are preserved verbatim: the
    # deterministic attempt row is re-emitted by the deterministic lane
    # on every replay, so its result artifact legitimately differs.
    for at in (report.get("run") or {}).get("attempts") or []:
        if at.get("kind") != "agent":
            continue
        if isinstance(at.get("result_artifact"), dict) and at["result_artifact"]:
            out.append((f"attempt {at.get('id')}.result_artifact", at["result_artifact"]))
        ex2 = at.get("extraction") or {}
        if isinstance(ex2.get("answer_artifact"), dict) and ex2["answer_artifact"]:
            out.append((f"attempt {at.get('id')}.extraction.answer_artifact", ex2["answer_artifact"]))
    return out


def assert_saved_status_and_pins(case, new):
    """Compare the rebuilt report against the saved one: recorded agent
    status, extraction status and every artifact pin must be verbatim.
    Also re-verifies the pinned bytes under the source dir."""
    saved = json.load(open(os.path.join(case["src"], "report.json")))
    src = case["src"]
    errs = []

    so, no = saved.get("agent_output") or {}, new.get("agent_output") or {}
    if so.get("status") != no.get("status"):
        errs.append(f"agent_output.status mutated: saved {so.get('status')!r} -> new {no.get('status')!r}")
    s_ex, n_ex = (so.get("extraction") or {}).get("status"), (no.get("extraction") or {}).get("status")
    if s_ex != n_ex:
        errs.append(f"agent_output.extraction.status mutated: saved {s_ex!r} -> new {n_ex!r}")
    if so.get("category") != no.get("category"):
        errs.append("agent_output.category mutated")

    saved_pins = {p.get("path"): (scope, p) for scope, p in _pins_of(saved) if p.get("path")}
    new_pins = {p.get("path"): (scope, p) for scope, p in _pins_of(new) if p.get("path")}
    for path, (scope, sp) in saved_pins.items():
        npair = new_pins.get(path)
        if npair is None:
            errs.append(f"pinned artifact missing in rebuilt report: {path} (was {scope})")
            continue
        _, np = npair
        for field in ("sha256", "size_bytes", "selector"):
            sv, nv = sp.get(field), np.get(field)
            if sv is not None and sv != nv:
                errs.append(f"artifact pin {field} mutated for {path}: saved {sv!r} -> new {nv!r}")
        # bytes under the replay source still match the recorded digest
        ap = path if os.path.isabs(path) else os.path.join(src, path)
        if os.path.isfile(ap):
            if sha256_file(ap) != sp.get("sha256"):
                errs.append(f"pinned artifact bytes no longer match recorded sha256: {path}")
        else:
            errs.append(f"pinned artifact file missing under replay source: {path}")

    rf = no.get("replayed_from")
    if not isinstance(rf, dict) or not rf.get("dir"):
        errs.append("agent_output.replayed_from missing in rebuilt report")
    else:
        if os.path.abspath(rf["dir"]) != os.path.abspath(src):
            errs.append("replayed_from.dir does not name the saved run dir")
        exp_answer = (so.get("answer_artifact") or {}).get("sha256")
        if exp_answer and rf.get("answer_sha256") != exp_answer:
            errs.append("replayed_from.answer_sha256 does not match the saved answer pin")

    return errs


def assert_report_shape(case, new, saved):
    """Marker / evidence_level / disposition / harness / agent-ref / L3 checks."""
    errs = []
    ext = new.get("contract_extensions") or []
    if V3_MARKER not in ext:
        errs.append(f"contract_extensions lacks {V3_MARKER}: {ext}")
    extra = [m for m in ext if m in RECOGNIZED_MARKERS and m != V3_MARKER]
    if extra:
        errs.append(f"contract_extensions mixes markers: {ext}")

    el = new.get("evidence_level")
    if not isinstance(el, dict) or not el.get("level"):
        errs.append("evidence_level missing")
        el = {}
    elif el["level"] not in ("L1_STATIC_PATH", "L2_POTENTIAL_PATH", "L3_DYNAMIC_EXPLOITATION"):
        errs.append(f"evidence_level.level not a closed enum value: {el['level']!r}")

    disp = new.get("disposition") or {}
    if disp.get("class") != "REVIEW_REQUIRED":
        errs.append(f"disposition.class != REVIEW_REQUIRED: {disp.get('class')!r}")
    if disp.get("auto_close") is not False:
        errs.append("disposition.auto_close is not false")

    hz = (new.get("run") or {}).get("harness") or {}
    if any(v not in (None, "", 0) for v in hz.values()):
        errs.append(f"run.harness carries live-turn pins on a replayed run: {hz}")

    # No agent material may carry evidence for the ladder.
    agent_refs = {"agent-src:session-export"}
    for a in new.get("agent_assertions") or []:
        if a.get("id"):
            agent_refs.add(a["id"])
    s_ao = (saved.get("agent_output") or {})
    for k in ("category", "reasoning"):
        if s_ao.get(k):
            agent_refs.add(str(s_ao[k]))
    for ref in el.get("evidence_refs") or []:
        if ref in agent_refs or str(ref).startswith("agent"):
            errs.append(f"evidence_level.evidence_refs carries agent material: {ref!r}")

    # L3 / ESTABLISHED need a saved dynamic verified fact.
    saved_facts = saved.get("verified_facts") or []
    has_dynamic = any(f.get("status") == "OK" and f.get("tool") in DYNAMIC_CARRIER_TOOLS
                      for f in saved_facts)
    ax = (new.get("exploitation_axes") or {}).get("exploitation_established") or {}
    if not has_dynamic:
        if ax.get("status") == "ESTABLISHED":
            errs.append("exploitation_established ESTABLISHED without a saved dynamic verified fact")
        if el.get("level") == "L3_DYNAMIC_EXPLOITATION":
            errs.append("evidence_level L3 without a saved dynamic verified fact")
    return errs


# ------------------------------------------------- B41 semantic projection

def _masked_attempts(report):
    """run.attempts with runtime-only fields removed: a deterministic row
    is re-emitted each run (its own timestamps and its re-written
    result_artifact legitimately differ); an agent row must be verbatim."""
    out = []
    for at in (report.get("run") or {}).get("attempts") or []:
        row = dict(at)
        if at.get("kind") != "agent":
            for k in ("started_at", "finished_at", "result_artifact"):
                row.pop(k, None)
        out.append(row)
    return out


def _b41_filter(report):
    """The ids a B41-only change may add: BUILD_USAGE_SCOPE fact ids and
    the unknown/question rows grouped to build_usage_scope. Returns
    (fact_ids, unknown_refs, unknown_ids, question_ids) — rows citing or
    carrying them are the only rows allowed to be new."""
    fact_ids = set()
    for f in report.get("verified_facts") or []:
        if f.get("kind") == BUILD_USAGE_SCOPE_KIND and f.get("id"):
            fact_ids.add(f["id"])
    unknown_ids = set()
    unknown_refs = set(fact_ids)
    for u in report.get("unknowns") or []:
        if u.get("group") != "build_usage_scope":
            continue
        if u.get("id"):
            unknown_ids.add(u["id"])
        unknown_refs.update(u.get("evidence_refs") or [])
    question_ids = set()
    for q in (report.get("open_questions") or []):
        refs = set(q.get("evidence_refs") or [])
        if q.get("subject") in unknown_ids or refs & unknown_refs:
            if q.get("id"):
                question_ids.add(q["id"])
    return fact_ids, unknown_refs, unknown_ids, question_ids


def _obs_id_map(run_dir):
    """Map each OBS-NNNN id to a stable ``tool#ordinal`` key from the
    run's observations.jsonl: B41 inserts its observations mid-ledger, so
    raw ids legitimately renumber while (tool, ordinal) stays stable."""
    out = {}
    per_tool = Counter()
    op = os.path.join(run_dir, "observations.jsonl") if run_dir else ""
    if op and os.path.isfile(op):
        for line in open(op):
            try:
                rec = json.loads(line)
            except Exception:
                continue
            obs = rec.get("observation") or {}
            oid = obs.get("id") or rec.get("observation_id")
            tool = rec.get("tool") or obs.get("tool") or "?"
            if not isinstance(oid, str) or not re.fullmatch(r"OBS-\d+", oid):
                continue
            per_tool[tool] += 1
            out[oid] = f"{tool}#{per_tool[tool]}"
    return out


_OBS_ID_RE = re.compile(r"(?<![A-Za-z])obs-\d+|(?<![A-Za-z])OBS-\d+")
_TRUNC_NOTE_RE = re.compile(
    r"full payload \d+ bytes, sha256 [0-9a-f]{64}")
# Pre-existing tool nondeterminism (measured at constant code, not B41):
# var origins and may-call enumeration resolve under a shared evaluation
# budget whose consumption order follows Go map iteration.
# - ingress-inventory: item enumeration differs across identical replays
#   of the same input (observed 4856/4921/4940/4907 for one case); the
#   item count inside its statement template is masked — blocker count
#   and complete flag stay asserted.
# - find_may_callers: the site count differs across identical replays at
#   constant code (observed 559/258/110 for one subject; two consecutive
#   B41 replays of one case drew 258 then 559); the counts inside the
#   statement template are masked — the pinned subject stays compared.
# - trace_argument: the `origins: [...]` list is a set enumeration whose
#   order flips between identical replays at constant code (the same call
#   drew both [CONSTANT UNKNOWN] and [UNKNOWN CONSTANT] across rebuilds);
#   tokens are sorted — the origin SET stays compared.
_INGRESS_ITEMS_RE = re.compile(r"\d+ inventoried item\(s\)")
_MAYCALL_SITES_RE = re.compile(r"\d+ may-call site\(s\)")
_UNPROVEN_TARGETS_RE = re.compile(r"\d+ with unproven targets")
_ORIGINS_LIST_RE = re.compile(r"(origins: )\[([A-Z][A-Z ]*)\]")


def _normalize_ids(obj, idmap):
    """Rewrite every OBS/obs id token to its stable ``tool#ordinal``
    key and mask truncation notes that embed the payload size/sha of a
    renumbered observation; without a map only the notes are masked."""

    def norm_str(s):
        def sub(m):
            t = m.group(0)
            key = idmap.get(t.upper())
            if not key:
                return t
            return ("obs~" if t.startswith("obs") else "OBS~") + key
        s = _OBS_ID_RE.sub(sub, s)
        s = _TRUNC_NOTE_RE.sub("full payload N bytes, sha256 ~", s)
        s = _INGRESS_ITEMS_RE.sub("# inventoried item(s)", s)
        s = _MAYCALL_SITES_RE.sub("# may-call site(s)", s)
        s = _UNPROVEN_TARGETS_RE.sub("# with unproven targets", s)

        def sort_origins(m):
            return m.group(1) + "[" + " ".join(sorted(m.group(2).split())) + "]"
        return _ORIGINS_LIST_RE.sub(sort_origins, s)

    def rec(v):
        if isinstance(v, str):
            return norm_str(v)
        if isinstance(v, list):
            return [rec(x) for x in v]
        if isinstance(v, dict):
            return {rec(k): rec(x) for k, x in v.items()}
        return v
    return rec(obj)


def _is_b41_eq_ref(row, idmap):
    """True when an evidence_quality.references row belongs to a
    usage-scope observation (the allowed new-reference delta)."""
    ref = row.get("ref") or ""
    m = re.fullmatch(r"obs:(OBS-\d+)", str(ref))
    if not m:
        return False
    return idmap.get(m.group(1), "").startswith(USAGE_SCOPE_TOOL + "#")


def _mask_eq_ref(row):
    """Mask byte fields that embed the renumbered obs id."""
    for k in ("sha256", "size_bytes"):
        if k in row:
            row[k] = None
    rb = row.get("materiality", {}).get("raw_bytes")
    if isinstance(rb, dict):
        rb["sha256"] = None
        rb["size_bytes"] = None


_EQ_COUNT_RE = re.compile(r"\d+(?= deterministic check\(s\)| non-OK)")


def semantic_projection(report, run_dir=None):
    """The invariant slice of a report B41 may not touch: any difference
    between the baseline projection and the rebuilt one is an unrelated
    semantic change and fails the driver.

    Allowed diffs are only the B41 surface itself — new usage-scope
    observations and artifacts, new BUILD_USAGE_SCOPE facts, the
    exploitation_axes.build_usage_scope axis and the B41
    unknown/question rows — plus re-emitted volatile members:
    provenance.generated_at, replayed_from provenance, the deterministic
    attempt row's own runtime fields, and observation-id renumbering.
    B41 inserts its observations before later deterministic checks, so
    OBS-NNNN ids legitimately shift; every obs/fact-id token and path is
    rewritten to a stable ``tool#ordinal`` key derived from the run's
    observations.jsonl, and byte fields that embed the id (artifact
    sha256/size_bytes, data_digest) are masked — input_digest and the
    recorded claim text still pin the check itself."""
    idmap = _obs_id_map(run_dir)
    fact_ids, unknown_refs, unknown_ids, question_ids = _b41_filter(report)
    facts = []
    for f in report.get("verified_facts") or []:
        if f.get("id") in fact_ids:
            continue
        row = dict(f)
        prov = dict(row.get("provenance") or {})
        prov.pop("generated_at", None)
        row["provenance"] = prov
        # Byte fields embedding the renumbered obs id are masked; the
        # check itself stays pinned by input_digest/command/claim.
        art = dict(row.get("artifact") or {})
        art["sha256"] = None
        art["size_bytes"] = None
        row["artifact"] = art
        mat = dict(row.get("materiality") or {})
        rb = dict(mat.get("raw_bytes") or {})
        rb["sha256"] = None
        rb["size_bytes"] = None
        if rb:
            mat["raw_bytes"] = rb
        rs = dict(mat.get("reproducible_source") or {})
        if "output_sha256" in rs:
            rs["output_sha256"] = None
        if rs:
            mat["reproducible_source"] = rs
        if mat:
            row["materiality"] = mat
        row["data_digest"] = None
        facts.append(row)
    unknowns = [u for u in report.get("unknowns") or []
                if u.get("group") != "build_usage_scope"
                and not (set(u.get("evidence_refs") or []) & unknown_refs)]
    questions = [q for q in report.get("open_questions") or []
                 if q.get("id") not in question_ids
                 and q.get("subject") not in unknown_ids
                 and not (set(q.get("evidence_refs") or []) & unknown_refs)]
    residual = [q for q in report.get("residual_questions") or []
                if q.get("id") not in question_ids
                and not (set(q.get("evidence_refs") or []) & unknown_refs)]
    axes = dict(report.get("exploitation_axes") or {})
    axes.pop("build_usage_scope", None)
    agent_output = dict(report.get("agent_output") or {})
    # Replay provenance legitimately names the source dir it replayed
    # from; its contents are verified by assert_saved_status_and_pins.
    agent_output.pop("replayed_from", None)

    eq = report.get("evidence_quality")
    if isinstance(eq, dict):
        eq = dict(eq)
        # New B41 observation rows are the allowed evidence_quality
        # delta; every retained row is compared on its stable id.
        eq["references"] = [r for r in eq.get("references") or []
                            if not _is_b41_eq_ref(r, idmap)]
        for r in eq["references"]:
            _mask_eq_ref(r)
        eq["coverage"] = [c for c in eq.get("coverage") or []
                          if not str(c).startswith("usage-scope:")]
        eq["summary"] = _EQ_COUNT_RE.sub("N", eq.get("summary") or "")

    proj = {
        "schema": report.get("schema"),
        "mode": report.get("mode"),
        "contract_extensions": report.get("contract_extensions"),
        "input": report.get("input"),
        "vulnerability": report.get("vulnerability"),
        "affected_implementations": report.get("affected_implementations"),
        "product_applicability": report.get("product_applicability"),
        "agent_output": agent_output,
        "agent_assertions": report.get("agent_assertions"),
        "attempts": _masked_attempts(report),
        "exploitation_axes": axes,
        "exploitation_conditions": report.get("exploitation_conditions"),
        "verified_facts": facts,
        "evidence_level": report.get("evidence_level"),
        "vulnerability_mechanism": report.get("vulnerability_mechanism"),
        "attack_scenario": report.get("attack_scenario"),
        "root_cause": report.get("root_cause"),
        "product_exposure": report.get("product_exposure"),
        "evidence_quality": eq,
        "alternative_paths": report.get("alternative_paths"),
        "contradictions": report.get("contradictions"),
        "triage_recommendation": report.get("triage_recommendation"),
        "recommendations": report.get("recommendations"),
        "classification_review": report.get("classification_review"),
        "unknowns": unknowns,
        "open_questions": questions,
        "residual_questions": residual,
        "disposition": report.get("disposition"),
    }
    return _normalize_ids(proj, idmap)


# For specialist cases the BEFORE document is the saved historical
# report (never a B41-built baseline): only the identity/preservation
# slice is asserted byte-equal; derived members legitimately differ and
# are reported as measured changes, not parity violations.
HISTORICAL_PARITY_KEYS = (
    "schema", "mode", "input", "vulnerability",
    "agent_output", "disposition",
)

# Replay bookkeeping on the persisted agent row is legitimately
# rewritten on any replay; the row's identity, status, timestamps,
# extraction and pins are preserved verbatim.
_AGENT_ROW_VOLATILE = ("reason_code", "reason", "retry_of", "notes")


def _loose_attempts(rows):
    out = []
    for at in rows or []:
        row = dict(at)
        if at.get("kind") == "agent":
            for k in _AGENT_ROW_VOLATILE:
                row.pop(k, None)
        out.append(row)
    return out


def _impls_reduced(report):
    """Affected-implementation identity only: binding/module/package —
    members that existed identically across every schema era."""
    out = []
    for im in report.get("affected_implementations") or []:
        out.append({"id": im.get("id"), "module": im.get("module"),
                    "package": im.get("package"), "binding": im.get("binding"),
                    "ecosystem": im.get("ecosystem")})
    return out


def assert_b41_delta(before, after, historical=False):
    """Byte-equivalent semantic projection: every invariant field must be
    identical between the baseline and the B41 rebuild. Returns a list of
    violation strings (empty = parity). Under `historical` only the
    preservation keys are asserted — the saved document predates the
    contract members a full baseline would pin; the attempt ledger is
    compared on preserved fields only and affected_implementations on
    identity members."""
    errs = []
    if historical:
        for key in HISTORICAL_PARITY_KEYS:
            if before.get(key) != after.get(key):
                errs.append(f"invariant field changed under B41: {key}")
        if _loose_attempts(before.get("attempts")) != _loose_attempts(after.get("attempts")):
            errs.append("invariant field changed under B41: attempts")
        if _impls_reduced(before) != _impls_reduced(after):
            errs.append("invariant field changed under B41: affected_implementations")
        return errs
    for key in before:
        if before.get(key) != after.get(key):
            errs.append(f"invariant field changed under B41: {key}")
    return errs


def assert_saved_inputs_unchanged(root_hashes_before, root_hashes_after):
    """Any byte change under a saved input dir fails the run."""
    fails = []
    for key, h0 in root_hashes_before.items():
        h1 = root_hashes_after.get(key)
        if h1 is None:
            fails.append(f"{key}: input dir missing after replay")
        elif h1 != h0:
            fails.append(f"{key}: saved input bytes changed under replay")
    for key in root_hashes_after:
        if key not in root_hashes_before:
            fails.append(f"{key}: unexpected input dir appeared")
    return fails


def case_census(report, run_dir):
    """The per-case measurement row for B42 and B41."""
    el = report.get("evidence_level") or {}
    usage_rows = _subject_rows(report, SUBJ_PRODUCT_PACKAGE_USAGE)
    scope = usage_scope_rows(report, run_dir)
    facts = scope["facts"]
    return {
        "level": el.get("level"),
        "basis": el.get("basis"),
        "blocking": el.get("blocking_conditions") or [],
        "reach_state": condition_state_for_case(report, SUBJ_PACKAGE_REACH),
        "build_state": condition_state_for_case(report, SUBJ_BUILD_RELEVANT),
        "usage_state": condition_state_for_case(report, SUBJ_PRODUCT_PACKAGE_USAGE),
        "usage_conditions": [{"id": r["id"], "state": r["state"], "origin": r["origin"],
                              "usage_subject": r["usage_subject"]} for r in usage_rows],
        "package_usage_obs": package_usage_observations(run_dir),
        "package_usage_facts": [{"id": f.get("id"), "kind": f.get("kind"), "claim": f.get("claim"),
                                 "status": f.get("status"), "usage_subject": f.get("usage_subject")}
                                for f in report.get("verified_facts") or []
                                if f.get("kind") in PACKAGE_USAGE_FACT_KINDS or f.get("tool") == PACKAGE_USAGE_TOOL],
        "usage_scope": [f.get("usage_scope") for f in facts],
        "usage_scope_facts": len(facts),
        "usage_scope_product": sum(f.get("usage_scope") == "product" for f in facts),
        "usage_scope_test_only": sum(f.get("usage_scope") == "test-only" for f in facts),
        "usage_scope_mixed": sum(f.get("usage_scope") == "mixed" for f in facts),
        "usage_scope_unknown": sum(f.get("usage_scope") == "unknown" for f in facts),
        "usage_scope_complete": sum(f.get("coverage") == "COMPLETE" for f in facts),
        "usage_scope_incomplete_observations": sum(o.get("completeness") != "COMPLETE" for o in scope["observations"]),
        "usage_scope_observations": len(scope["observations"]),
        "usage_scope_product_absence_verification": sum(f.get("product_absence_verification") == "VERIFIED" for f in facts),
        "build_usage_scope_axis": scope["axis"].get("status") or "ABSENT",
        "checked_packages_n": len((report.get("product_applicability") or {}).get("checked_packages") or []),
        "agent_status": (report.get("agent_output") or {}).get("status"),
        "extraction_status": ((report.get("agent_output") or {}).get("extraction") or {}).get("status"),
        "disposition_class": (report.get("disposition") or {}).get("class"),
        "auto_close": (report.get("disposition") or {}).get("auto_close"),
    }


def assert_usage_branch(new, expected_subjects, module_only):
    """B42 semantic-branch checks on the rebuilt report. Returns a list
    of violation strings."""
    errs = []
    facts = {f.get("id"): f for f in new.get("verified_facts") or []}
    usage_rows = _subject_rows(new, SUBJ_PRODUCT_PACKAGE_USAGE)

    # Subject parity: the usage conditions cover exactly the advisory-
    # declared candidates — a module-only advisory gains none and no
    # package is ever invented.
    got = {_usage_subject_key(r["usage_subject"]) for r in usage_rows}
    got.discard(None)
    want = set(expected_subjects)
    if got != want:
        missing = want - got
        extra = got - want
        if missing:
            errs.append(f"{len(missing)} advisory-declared candidate(s) got no usage condition")
        if extra:
            errs.append(f"{len(extra)} usage condition(s) cite no advisory-declared candidate")
    if module_only and usage_rows:
        errs.append("module-only advisory acquired package-usage condition(s) — a package path was guessed")
    if module_only and any(f.get("kind") in PACKAGE_USAGE_FACT_KINDS
                           for f in facts.values()):
        errs.append("module-only advisory acquired a package-usage verified fact")

    for r in usage_rows:
        if r["origin"] != "deterministic":
            errs.append(f"usage condition {r['id']} has non-deterministic origin {r['origin']!r}")
        if r["state"] == "SUPPORTED":
            cited = [facts.get(ref) or facts.get(str(ref).removeprefix("fact:"))
                     for ref in r["evidence_refs"]]
            cited = [f for f in cited if f is not None]
            ok = any(
                f.get("tool") == PACKAGE_USAGE_TOOL
                and f.get("kind") == "PACKAGE_USAGE"
                and f.get("status") == "OK"
                and _usage_subject_key(f.get("usage_subject")) == _usage_subject_key(r["usage_subject"])
                for f in cited)
            if not ok:
                errs.append(
                    f"usage condition {r['id']} SUPPORTED without a matching OK PACKAGE_USAGE fact")

    agg = condition_state_for_case(new, SUBJ_PRODUCT_PACKAGE_USAGE)
    level = (new.get("evidence_level") or {}).get("level")
    if agg == "REFUTED":
        if level == "L1_STATIC_PATH":
            errs.append("REFUTED usage aggregate still yielded L1_STATIC_PATH")
        if (new.get("disposition") or {}).get("class") != "REVIEW_REQUIRED":
            errs.append("REFUTED usage case left REVIEW_REQUIRED")
    if level == "L1_STATIC_PATH":
        # L1 needs every required applicability/path condition SUPPORTED
        # (the validator recomputes it; this is the census-side mirror).
        for c in new.get("exploitation_conditions") or []:
            if c.get("role") in ("applicability", "path") \
                    and c.get("necessity") == "required" \
                    and c.get("state") != "SUPPORTED":
                errs.append(f"L1 with {c.get('state')} required {c.get('role')} condition {c.get('id')}")
    return errs


def assert_evidence_matrix(rows, expected, name, which="before"):
    """Exact baseline-matrix assertion. Returns list of failure strings."""
    fails = []
    ran = [r for r in rows if r[which]]
    levels = Counter((r[which].get("level")) for r in ran)
    total = len(rows)
    if total != expected["total"]:
        fails.append(f"{name}: expected {expected['total']} cases, discovered {total}")
    l1 = sorted(r["label"] for r in ran if r[which].get("level") == "L1_STATIC_PATH")
    if l1 != sorted(expected["L1_STATIC_PATH"]):
        fails.append(f"{name}: baseline L1 labels {l1} != recorded {sorted(expected['L1_STATIC_PATH'])}")
    if levels.get("L2_POTENTIAL_PATH", 0) != expected["L2_POTENTIAL_PATH"]:
        fails.append(f"{name}: baseline L2 count {levels.get('L2_POTENTIAL_PATH', 0)} != recorded {expected['L2_POTENTIAL_PATH']}")
    if levels.get("L3_DYNAMIC_EXPLOITATION", 0) != expected["L3_DYNAMIC_EXPLOITATION"]:
        fails.append(f"{name}: baseline L3 count {levels.get('L3_DYNAMIC_EXPLOITATION', 0)} != recorded {expected['L3_DYNAMIC_EXPLOITATION']}")
    not_run = [r["label"] for r in rows if not r[which]]
    if not_run:
        fails.append(f"{name}: cases without a baseline report: {sorted(not_run)}")
    return fails


# -------------------------------------------------------------------- main

def out_dir_for(case, args):
    if args.work_dir:
        return os.path.join(args.work_dir, case["set"], case["label"])
    return os.path.join(case["case_dir"],
                        args.b41_out_suffix or args.out_suffix or "agent-v5")


def run_case(case, args):
    """One case end-to-end. Returns a result row dict."""
    label = case["label"]
    historical = bool(case.get("historical_before"))
    row = {"set": case["set"], "label": label, "status": "PENDING",
           "errors": [], "violations": [], "changes": [], "wall_s": None,
           "before": None, "after": None, "out_dir": None,
           "before_kind": "saved_input_report" if historical else "baseline_rebuild",
           "_report_before": None, "_report_after": None}
    blocker = missing_inputs(case)
    if blocker:
        row["status"] = "NOT_RUN"
        row["errors"].append(scrub(blocker))
        return row
    saved = json.load(open(os.path.join(case["src"], "report.json")))
    baseline, _ = load_baseline_report(case)
    expected_subjects, module_only, _ = expected_usage_subjects(case, saved)
    row["expected_usage_subjects"] = len(expected_subjects)
    row["module_only"] = module_only

    if baseline is not None:
        row["_report_before"] = baseline
        row["before"] = case_census(baseline, baseline_dir_for(case))
    out_dir = out_dir_for(case, args)
    row["out_dir"] = out_dir
    wall, rc, stderr_tail, stdout_tail = replay_one(case, out_dir, args)
    row["wall_s"] = wall
    rp = os.path.join(out_dir, "report.json")
    if rc != 0 or not os.path.isfile(rp):
        row["status"] = "FAIL"
        row["errors"].append(scrub(f"replay exited rc={rc}: {stderr_tail or stdout_tail}"))
        return row
    try:
        new = json.load(open(rp))
    except Exception as e:
        row["status"] = "FAIL"
        row["errors"].append(f"rebuilt report.json unreadable: {e}")
        return row
    row["_report_after"] = new
    row["after"] = case_census(new, out_dir)
    errs = assert_report_shape(case, new, saved)
    errs += assert_saved_status_and_pins(case, new)
    row["violations"] += [scrub(e) for e in assert_usage_branch(
        new, expected_subjects, module_only)]
    row["violations"] += [scrub(e) for e in assert_usage_scope_branch(new, out_dir)]
    row["violations"] += [scrub(e) for e in assert_scope_axis_consistency(new)]
    if baseline is not None:
        row["violations"] += [scrub(e) for e in assert_b41_delta(
            semantic_projection(baseline, baseline_dir_for(case)),
            semantic_projection(new, out_dir),
            historical=historical)]
        # Measured movements (report, never verdicts).
        b, a = row["before"], row["after"]
        for k in ("level", "reach_state", "build_state", "usage_state",
                  "checked_packages_n"):
            if b.get(k) != a.get(k):
                row["changes"].append(f"{k}: {b.get(k)} -> {a.get(k)}")
        bc = (baseline.get("classification_review") or {})
        ac = (new.get("classification_review") or {})
        if bc.get("class") != ac.get("class"):
            row["changes"].append(
                f"classification.class: {bc.get('class')} -> {ac.get('class')}")
    else:
        row["errors"].append("baseline report missing; no before-state")
    if errs:
        row["errors"] += [scrub(e) for e in errs]
    row["status"] = "FAIL" if (row["errors"] or row["violations"]) else "PASS"
    return row


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--primary-root", required=True,
                    help="…/tmp/exploitable/runs (cases at <root>/<UNIT>/<input>)")
    ap.add_argument("--primary-input-suffix", default="agent",
                    help="saved input dir name under each primary case (replay source)")
    ap.add_argument("--primary-baseline-suffix", default="agent-v4",
                    help="recorded BEFORE rebuild under each primary case "
                         "(agent-v3 = pre-B42, agent-v4 = post-B42)")
    ap.add_argument("--retry-glob", action="append", default=[],
                    help="repeatable; each match is a retry set root …/runs")
    ap.add_argument("--retry-input-suffix", default="agent",
                    help="saved input dir name under each retry case")
    ap.add_argument("--retry-baseline-suffix", default="agent-v4",
                    help="recorded BEFORE rebuild under each retry case")
    ap.add_argument("--specialist-root", default="",
                    help="read-only specialist set root (cases at <root>/<UNIT>/<input>)")
    ap.add_argument("--specialist-input-suffix", default="agent",
                    help="saved input dir name under each specialist case")
    ap.add_argument("--specialist-label-map", default="",
                    help="private label map for the specialist set (read-only); "
                         "emitted labels must be C01–C31")
    ap.add_argument("--specialist-historical-before", action="store_true",
                    help="use each specialist case's saved report as its own "
                         "historical BEFORE (no baseline sibling assumed)")
    ap.add_argument("--label-map", required=True, help="private label map (read-only)")
    ap.add_argument("--izyan", required=True, help="compiled izyan binary")
    ap.add_argument("--govulndb", default="", help="frozen govulndb root")
    ap.add_argument("--modcache", default="", help="declared module cache")
    ap.add_argument("--work-dir", default="",
                    help="scratch output root; default writes sibling <case>/<b41-out-suffix>")
    ap.add_argument("--b41-out-suffix", default="agent-v5",
                    help="sibling output dir name when --work-dir is unset")
    ap.add_argument("--out-suffix", default="",
                    help="deprecated alias for --b41-out-suffix")
    ap.add_argument("--jobs", type=int, default=1)
    ap.add_argument("--only", default="", help="comma-separated C-labels")
    ap.add_argument("--report", default="", help="write machine results JSON here")
    ap.add_argument("--no-matrix-assert", action="store_true",
                    help="census only; do not fail on baseline matrix mismatch")
    args = ap.parse_args()

    if not os.path.isfile(args.izyan) or not os.access(args.izyan, os.X_OK):
        raise SystemExit(f"--izyan is not an executable file: {args.izyan}")
    if not args.retry_glob:
        print("note: no --retry-glob given; retry sets skipped", file=sys.stderr)
    if args.out_suffix and args.b41_out_suffix == "agent-v5":
        args.b41_out_suffix = ""

    unit2label = load_label_map(args.label_map)
    cases = discover_primary_runs(args.primary_root, args.primary_input_suffix,
                                  args.primary_baseline_suffix, unit2label)
    for c in cases:
        c["baseline_suffix"] = args.primary_baseline_suffix
    cases += discover_retry_runs(args.retry_glob, args.retry_input_suffix,
                                 args.retry_baseline_suffix, unit2label)
    for c in cases:
        if "baseline_suffix" not in c:
            c["baseline_suffix"] = args.retry_baseline_suffix

    # The specialist set is a separate read-only root with its own label
    # map; a missing root, map or saved report is a hard NOT_RUN blocker.
    specialist_blockers = []
    if args.specialist_root:
        if not os.path.isdir(args.specialist_root):
            specialist_blockers.append("specialist root missing")
        elif not args.specialist_label_map or not os.path.isfile(args.specialist_label_map):
            specialist_blockers.append("specialist label map missing")
        elif not args.specialist_historical_before:
            specialist_blockers.append(
                "specialist set requires --specialist-historical-before "
                "(no baseline sibling exists)")
        else:
            spec_map = load_label_map(args.specialist_label_map)
            spec_cases, specialist_blockers = discover_specialist_runs(
                args.specialist_root, args.specialist_input_suffix, spec_map)
            if not specialist_blockers and not spec_cases:
                specialist_blockers.append(
                    "specialist root contains no saved runs")
            cases += spec_cases
    else:
        print("note: no --specialist-root given; specialist set skipped",
              file=sys.stderr)
    if args.only:
        keep = set(args.only.split(","))
        cases = [c for c in cases if c["label"] in keep]

    # Snapshot basenames are product identifiers — scrub them too.
    for c in cases:
        try:
            snap = (read_run_manifest(c["src"]).get("snapshot") or {}).get("path") or ""
            base = os.path.basename(snap.rstrip("/"))
            if base:
                _EXTRA_SCRUB.append(re.compile(re.escape(base.split("@")[0])))
        except Exception:
            pass

    specialist_rows_in = [c for c in cases if c["set"] == "specialist"]
    print(f"discovered {len(cases)} cases "
          f"({sum(1 for c in cases if c['set']=='primary')} primary, "
          f"{len(cases) - sum(1 for c in cases if c['set'] in ('primary','specialist'))} retry, "
          f"{len(specialist_rows_in)} specialist)")
    if specialist_blockers:
        print("SPECIALIST SET NOT_RUN:")
        for b in specialist_blockers:
            print(f"  - {scrub(b)}")
    print("NO MODEL RUNS: every case replays the persisted agent turn; "
          "network off (GOPROXY=off, GOSUMDB=off).")

    # ------------------------------------------------------------------
    # Phase 0: hash every saved input BEFORE anything runs.
    hashes_before = {}
    for c in cases:
        key = f"{c['set']}/{c['label']}"
        hashes_before[key] = hash_tree(c["src"])

    # ------------------------------------------------------------------
    # Phase 1: baseline census — the recorded BEFORE state for the suffix
    # actually supplied, enforced before a single replay runs. A mismatch
    # means a changed input set. Historical-BEFORE cases carry their own
    # saved report and join no matrix.
    base_reports, base_rows = {}, []
    for c in cases:
        if c.get("historical_before"):
            continue
        if not os.path.isfile(os.path.join(c["baseline"], "report.json")):
            base_rows.append({"label": c["label"], "set": c["set"], "before": None})
            continue
        rep, _ = load_baseline_report(c)
        base_reports[f"{c['set']}/{c['label']}"] = rep
        base_rows.append({"label": c["label"], "set": c["set"],
                          "before": case_census(rep, baseline_dir_for(c))})
    fails = []
    if not args.no_matrix_assert and not args.only:
        exp_primary = EXPECTED_BASELINE.get(args.primary_baseline_suffix)
        exp_retry = EXPECTED_BASELINE.get(args.retry_baseline_suffix)
        pb = [r for r in base_rows if r["set"] == "primary"]
        rb = [r for r in base_rows if r["set"] not in ("primary", "specialist")]
        if pb and exp_primary is None:
            fails.append(f"primary: no recorded baseline matrix for suffix "
                         f"{args.primary_baseline_suffix!r}")
        elif pb:
            fails += assert_evidence_matrix(
                pb, exp_primary["primary"], f"primary-baseline[{args.primary_baseline_suffix}]")
        if rb and exp_retry is None:
            fails.append(f"retry: no recorded baseline matrix for suffix "
                         f"{args.retry_baseline_suffix!r}")
        elif rb:
            fails += assert_evidence_matrix(
                rb, exp_retry["retry"], f"retry-baseline[{args.retry_baseline_suffix}]")
    if fails:
        print("\n== BASELINE MISMATCH — recorded input set changed ==")
        for f in fails:
            print("  FAIL", f)
        sys.exit(1)
    if base_rows:
        print(f"baseline census matches the recorded matrices for "
              f"{args.primary_baseline_suffix}/{args.retry_baseline_suffix}.")

    # ------------------------------------------------------------------
    # Phase 2: replay every case.
    t_all = time.time()
    if args.jobs > 1:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        rows = [None] * len(cases)
        with ThreadPoolExecutor(max_workers=args.jobs) as ex:
            fut = {ex.submit(run_case, c, args): i for i, c in enumerate(cases)}
            for f in as_completed(fut):
                i = fut[f]
                rows[i] = f.result()
                r = rows[i]
                lvl = (r.get("after") or {}).get("level")
                print(f"[{r['set']}/{r['label']}] {r['status']} level={lvl} "
                      f"wall={r['wall_s']}s", flush=True)
    else:
        rows = []
        for c in cases:
            r = run_case(c, args)
            rows.append(r)
            lvl = (r.get("after") or {}).get("level")
            print(f"[{r['set']}/{r['label']}] {r['status']} level={lvl} "
                  f"wall={r['wall_s']}s", flush=True)
    total_wall = round(time.time() - t_all, 1)

    # ------------------------------------------------------------------
    # Phase 3: saved inputs must be byte-identical after the run.
    hashes_after = {}
    for c in cases:
        key = f"{c['set']}/{c['label']}"
        hashes_after[key] = hash_tree(c["src"])
    input_fails = assert_saved_inputs_unchanged(hashes_before, hashes_after)

    # census + assertions
    primary_rows = [r for r in rows if r["set"] == "primary"]
    specialist_rows = [r for r in rows if r["set"] == "specialist"]
    retry_rows = [r for r in rows if r["set"] not in ("primary", "specialist")]

    def census(rr, which):
        c = Counter()
        for r in rr:
            v = (r.get(which) or {}).get("level")
            c[v or r["status"]] += 1
        return dict(c)

    def cond_census(rr, which, subj):
        c = Counter()
        for r in rr:
            if r.get(which):
                c[r[which][subj]] += 1
            else:
                c[r["status"]] += 1
        return dict(c)

    def scope_census(rr, which):
        """Aggregate usage-scope classes over case rows (measured)."""
        c = Counter()
        for r in rr:
            row = r.get(which)
            if not row:
                c[r["status"]] += 1
                continue
            if not row["usage_scope"]:
                c["absent"] += 1
            for s in row["usage_scope"]:
                c[s or "unknown"] += 1
        c["facts"] = sum((r.get(which) or {}).get("usage_scope_facts", 0)
                         for r in rr)
        return dict(sorted(c.items()))

    def axis_census(rr, which):
        c = Counter()
        for r in rr:
            row = r.get(which)
            c[(row or {}).get("build_usage_scope_axis") or r["status"]] += 1
        return dict(sorted(c.items()))

    def reports_of(rr, which):
        return {f"{r['set']}/{r['label']}": r["_report_" + which]
                for r in rr if r.get("_report_" + which)}

    def run_dirs_of(rr, which):
        if which == "before":
            return {f"{r['set']}/{r['label']}": baseline_dir_for(
                        case_by_key[f"{r['set']}/{r['label']}"])
                    for r in rr if r.get("_report_before")}
        return {f"{r['set']}/{r['label']}": r["out_dir"]
                for r in rr if r.get("_report_after")}

    case_by_key = {f"{c['set']}/{c['label']}": c for c in cases}

    rb_primary = reports_of(primary_rows, "before")
    rb_retry = reports_of(retry_rows, "before")
    rb_specialist = reports_of(specialist_rows, "before")
    ra_primary = reports_of(primary_rows, "after")
    ra_retry = reports_of(retry_rows, "after")
    ra_specialist = reports_of(specialist_rows, "after")

    expected_record = {
        "suffix": {"primary": args.primary_baseline_suffix,
                   "retry": args.retry_baseline_suffix},
        "primary": (EXPECTED_BASELINE.get(args.primary_baseline_suffix) or {}).get("primary"),
        "retry": (EXPECTED_BASELINE.get(args.retry_baseline_suffix) or {}).get("retry"),
    }

    summary = {
        "total_wall_s": total_wall,
        "before": {
            "primary": {"n": len(primary_rows),
                        "levels": census_levels(rb_primary),
                        "conditions": census_path_conditions(rb_primary),
                        "usage_scope": usage_scope_census(
                            rb_primary, run_dirs_of(primary_rows, "before"))},
            "retry": {"n": len(retry_rows),
                      "levels": census_levels(rb_retry),
                      "conditions": census_path_conditions(rb_retry),
                      "usage_scope": usage_scope_census(
                          rb_retry, run_dirs_of(retry_rows, "before"))},
            "specialist": {"n": len(specialist_rows),
                           "levels": census_levels(rb_specialist),
                           "conditions": census_path_conditions(rb_specialist),
                           "usage_scope": usage_scope_census(
                               rb_specialist, run_dirs_of(specialist_rows, "before"))},
            "primary_status_census": census(primary_rows, "before"),
            "retry_status_census": census(retry_rows, "before"),
            "specialist_status_census": census(specialist_rows, "before"),
        },
        "after": {
            "primary": {"n": len(primary_rows),
                        "levels": census_levels(ra_primary),
                        "conditions": census_path_conditions(ra_primary),
                        "usage_scope": usage_scope_census(
                            ra_primary, run_dirs_of(primary_rows, "after"))},
            "retry": {"n": len(retry_rows),
                      "levels": census_levels(ra_retry),
                      "conditions": census_path_conditions(ra_retry),
                      "usage_scope": usage_scope_census(
                          ra_retry, run_dirs_of(retry_rows, "after"))},
            "specialist": {"n": len(specialist_rows),
                           "levels": census_levels(ra_specialist),
                           "conditions": census_path_conditions(ra_specialist),
                           "usage_scope": usage_scope_census(
                               ra_specialist, run_dirs_of(specialist_rows, "after"))},
            "primary_status_census": census(primary_rows, "after"),
            "retry_status_census": census(retry_rows, "after"),
            "specialist_status_census": census(specialist_rows, "after"),
        },
        "expected_baseline": expected_record,
        "specialist": {
            "requested": bool(args.specialist_root),
            "blockers": [scrub(b) for b in specialist_blockers],
            "before_kind": "saved_input_report" if args.specialist_historical_before else "none",
            "n": len(specialist_rows),
        },
        "input_integrity_failures": input_fails,
        "baseline_failures": fails,
        "cases": [scrub_obj({k: v for k, v in r.items()
                             if not k.startswith("_") and k != "out_dir"})
                  for r in rows],
    }
    if args.report:
        os.makedirs(os.path.dirname(os.path.abspath(args.report)), exist_ok=True)
        tmp = args.report + ".tmp"
        with open(tmp, "w") as f:
            json.dump(summary, f, indent=1, sort_keys=True)
        os.replace(tmp, args.report)

    print("\n== before/after census ==")
    for name, rr in (("primary", primary_rows), ("retry", retry_rows),
                     ("specialist", specialist_rows)):
        if not rr:
            continue
        print(f"{name}: n={len(rr)}")
        print(f"  levels before {census(rr, 'before')}  after {census(rr, 'after')}")
        print(f"  usage_scope before {scope_census(rr, 'before')}  "
              f"after {scope_census(rr, 'after')}")
        print(f"  build_usage_scope axis before {axis_census(rr, 'before')}  "
              f"after {axis_census(rr, 'after')}")
        for subj in ("reach_state", "build_state", "usage_state"):
            print(f"  {subj}: before {cond_census(rr, 'before', subj)} "
                  f"after {cond_census(rr, 'after', subj)}")
        for r in sorted(rr, key=lambda x: x["label"]):
            b, a = r.get("before") or {}, r.get("after") or {}
            moved = "  ".join(r["changes"]) if r.get("changes") else ""
            print(f"  {r['label']}: {r['status']} "
                  f"{b.get('level')}->{a.get('level')} "
                  f"reach {b.get('reach_state')}->{a.get('reach_state')} "
                  f"build {b.get('build_state')}->{a.get('build_state')} "
                  f"usage {b.get('usage_state')}->{a.get('usage_state')} "
                  f"scope {b.get('usage_scope') or 'ABSENT'}->{a.get('usage_scope') or 'ABSENT'} {moved}")
    if input_fails:
        print("\n== SAVED INPUT INTEGRITY FAILURES ==")
        for f in input_fails:
            print("  FAIL", scrub(f))
    bad = any(r["status"] != "PASS" for r in rows) or input_fails or specialist_blockers
    if bad:
        print("\n== CASE FAILURES ==")
        for b in specialist_blockers:
            print(f"  specialist: NOT_RUN — {scrub(b)}")
        for r in rows:
            if r["status"] == "PASS":
                continue
            print(f"  {r['set']}/{r['label']}: {r['status']}")
            for e in r["errors"] + r["violations"]:
                print("    -", e)
        sys.exit(1)
    print(f"\nall cases pass; total wall {total_wall}s")

if __name__ == "__main__":
    main()

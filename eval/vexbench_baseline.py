
#!/usr/bin/env python3
"""VEX-Bench External Baseline 1 orchestration (no analysis of its own).

Plan: docs/dev/plans/2026-10-07-vexbench-baseline-plan.md
Spec: docs/dev/specs/shadow-analyzer-agent-spec.md §25, §39–45.

Subcommands:

  acquire          fetch the pinned dataset and the unique Go snapshots into
                   <repos-dir>/<owner>/<repo>/<full-sha> (atomic, manifests
                   live outside the snapshot tree)
  preflight        resource gates + snapshot integrity + frozen run-manifest
  run              case-isolated subprocess per task: one ledger record,
                   own process group, own --out; --resume honours finalized
                   records (including abstain/failed), never reruns them
  report           offline join of raw outputs with the pinned labels,
                   aggregate metrics, disagreements, freeze boundary
  validate-review  coverage/enum/path/digest checks for the manual
                   failure-taxonomy file

Python 3 stdlib only. POSIX only (process-group kill). Every artifact lives
outside the repository worktree; ground truth never enters snapshot or
analyzer-visible inputs.
"""
import argparse
import datetime
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse

DATASET_URL = "https://github.com/steven1518/vex-bench.git"
DEFAULT_PIN = "80cddeac3132826bfd47227ad59b2e6618a681bd"
TASKS_REL = "benchmark/tasks/vex_bench.jsonl"
ADAPTER_VERSION = "2"          # matches vexAdapterVersion in cmd/izyan/vexprov.go
ORCHESTRATOR_VERSION = "1"
BASELINE_NAME = "external-baseline-1"

# Pinned Go-subset contract for the pinned dataset commit. Any deviation is
# an acquisition error — the baseline is defined on exactly this corpus.
EXPECTED_COUNTS = {
    "tasks": 30,
    "snapshots": 28,
    "repos": 15,
    "cves": 24,
    "gt_vulnerable": 7,
    "gt_code_not_reachable": 18,
    "gt_code_not_present": 3,
    "gt_requires_configuration": 2,
}

DISK_GATE_BYTES = 25 << 30          # hard preflight gate
DISK_GATE_RECOMMENDED = 40 << 30    # warning below this
DISK_ADMIT_MIN = 5 << 30            # below: stop admitting new cases
DISK_ABORT_MIN = 2 << 30            # below: emergency stop of all groups
SIG_GRACE_SECONDS = 30

VERDICTS_SAFE = {"NOT_AFFECTED", "NO_EXPLOIT_PATH_FOUND"}
VERDICT_EXPLOITABLE = "EXPLOITABLE"
VERDICT_INCONCLUSIVE = "INCONCLUSIVE"
OUTCOMES = ("correct_safe", "correct_exploitable", "abstain", "wrong", "failed")

TAXONOMY_CATEGORIES = [
    "ROOT_CAUSE_WRONG", "MANDATORY_CONDITION_MISSED", "CALL_PATH_MISSED",
    "DATA_PROVENANCE_WRONG", "CONFIGURATION_MISREAD", "ENVIRONMENT_MISREAD",
    "PATCH_MISINTERPRETED", "TOOL_SCOPE_INCOMPLETE", "LLM_REASONING_ERROR",
    "FALSE_NEGATIVE_PROOF", "BENCHMARK_AMBIGUITY", "OTHER",
]
TAXONOMY_DISPOSITIONS = [
    "analyzer_defect", "honest_abstention", "infrastructure_failure",
    "benchmark_ambiguity",
]
COMPAT_CATEGORIES = [
    "false_positive", "code_not_present", "code_not_reachable",
    "requires_configuration", "requires_dependency", "requires_environment",
    "compiler_protected", "runtime_protected", "perimeter_protected",
    "mitigating_control_protected", "uncertain", "vulnerable",
]
# Categories present in the pinned Go subset — macro-F1 scope.
GT_CATEGORIES = ["vulnerable", "code_not_reachable",
                 "code_not_present", "requires_configuration"]

SHA40 = re.compile(r"^[0-9a-f]{40}$")

# Clean-environment policy (plan §6.1): exact names pass through, the listed
# GO* pass-through vars keep operator network policy, everything else is
# forced or dropped. The whole effective env is recorded in the manifest.
ENV_EXACT = {
    "HOME", "USER", "LOGNAME", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE",
    "TZ", "TERM", "SSH_AUTH_SOCK", "SSH_AGENT_PID",
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
    "http_proxy", "https_proxy", "no_proxy",
}
GO_PASSTHROUGH = {"GOPROXY", "GOSUMDB", "GOPRIVATE", "GONOSUMDB",
                  "GONOSUMCHECK", "GOINSECURE", "GOAUTH", "GONOPROXY"}


class BaselineError(Exception):
    pass


def fail(msg):
    raise BaselineError(msg)


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def eprint(msg):
    print(msg, file=sys.stderr)


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


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


def atomic_write_bytes(path, data, mode=0o644):
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
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


def atomic_write_text(path, text, mode=0o644):
    atomic_write_bytes(path, text.encode("utf-8"), mode)


def atomic_write_json(path, obj, mode=0o644):
    atomic_write_text(path, json.dumps(obj, indent=2, ensure_ascii=False) + "\n", mode)


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def parse_jsonl_lines(lines, source):
    rows = []
    for ln, raw in enumerate(lines, 1):
        raw = raw.strip()
        if not raw:
            continue
        try:
            rows.append((ln, raw, json.loads(raw)))
        except json.JSONDecodeError as e:
            fail(f"{source}:{ln}: invalid JSON: {e}")
    return rows


def task_from_json(rec):
    meta = rec.get("metadata") or {}
    return {
        "task_id": rec.get("task_id") or "",
        "repo_url": rec.get("repo_url") or "",
        "commit_sha": rec.get("commit_sha") or "",
        "cve_id": rec.get("cve_id") or "",
        "ground_truth": rec.get("ground_truth") or "",
        "ground_truth_category": rec.get("ground_truth_category") or "",
        "language": meta.get("language") or "",
        "pr_url": meta.get("pr_url") or "",
    }


def load_tasks(path, language=None):
    """Parse a VEX-Bench JSONL; with language set, keep only matching
    tasks (case-insensitive), in file order — LoadGoTasks parity."""
    tasks = []
    raw_lines = []
    with open(path, "r", encoding="utf-8") as f:
        raw_lines = f.readlines()
    for ln, raw, rec in parse_jsonl_lines(raw_lines, path):
        t = task_from_json(rec)
        if language is not None and t["language"].lower() != language:
            continue
        tasks.append((t, raw))
    return tasks


def load_go_tasks(path):
    return [t for t, _ in load_tasks(path, "go")]


def sanitize_case_name(s):
    """Parity with cmd/izyan sanitizeCaseName."""
    return re.sub(r"[^A-Za-z0-9_-]", "_", s)


def parse_repo_url(raw):
    """Parity with internal/eval/vexbench parseRepoURL."""
    s = raw.strip().rstrip("/")
    if s.startswith("http://") or s.startswith("https://"):
        tail = urllib.parse.urlparse(s).path.strip("/")
    elif s.startswith("git@"):
        if ":" not in s:
            fail(f"parse repo url {raw!r}: want git@host:owner/repo")
        tail = s.split(":", 1)[1].strip("/")
    else:
        tail = s
    parts = tail.split("/")
    if len(parts) != 2:
        fail(f"parse repo url {raw!r}: want owner/repo")
    owner, repo = parts[0], parts[1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not owner or not repo:
        fail(f"parse repo url {raw!r}: empty owner or repo")
    for seg in (owner, repo):
        if seg in (".", "..") or "/" in seg or "\\" in seg or seg.lower() == ".git":
            fail(f"parse repo url {raw!r}: bad path segment {seg!r}")
    return owner, repo


def parse_mem_limit(s):
    """Parity with cmd/izyan parseMemLimit; returns bytes (0 = disabled)."""
    s = s.strip()
    if not s or s == "0" or s.lower() == "off":
        return 0
    m = re.fullmatch(r"(\d+)([A-Za-z]*)", s)
    if not m:
        fail(f"bad --mem-limit {s!r} (want e.g. 4GiB, 512MiB, 0)")
    mults = {"gib": 1 << 30, "gb": 10**9, "mib": 1 << 20, "mb": 10**6,
             "kib": 1 << 10, "kb": 10**3, "b": 1, "": 1}
    mult = mults.get(m.group(2).lower())
    if mult is None:
        fail(f"bad --mem-limit suffix {s!r}")
    return int(m.group(1)) * mult


def default_disk_free(path):
    return shutil.disk_usage(path).free


def physical_ram_bytes():
    """Total physical RAM; None when undetectable."""
    try:
        names = os.sysconf_names
        if "SC_PHYS_PAGES" in names and "SC_PAGE_SIZE" in names:
            return os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")
    except (ValueError, OSError, AttributeError):
        pass
    if sys.platform == "darwin":
        try:
            out = subprocess.run(["sysctl", "-n", "hw.memsize"],
                                 capture_output=True, text=True, timeout=10)
            return int(out.stdout.strip())
        except (OSError, ValueError, subprocess.SubprocessError):
            return None
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) * 1024
    except OSError:
        pass
    return None


# --------------------------------------------------------------------------
# git helpers


def run_git(argv, timeout=120):
    try:
        cp = subprocess.run(["git"] + argv, capture_output=True, text=True,
                            timeout=timeout)
    except FileNotFoundError:
        fail("git executable not found in PATH")
    except subprocess.TimeoutExpired:
        fail(f"git {' '.join(argv[:3])}...: timeout after {timeout}s")
    if cp.returncode != 0:
        fail(f"git {' '.join(argv)} failed ({cp.returncode}): "
             f"{cp.stderr.strip()[-400:]}")
    return cp.stdout.strip()


def check_worktree(worktree):
    """The wrapper must run against the approved worktree root — verified
    against git, never the caller's cwd."""
    root = os.path.realpath(worktree)
    if not os.path.isdir(root):
        fail(f"--worktree {worktree} is not a directory")
    top = run_git(["-C", root, "rev-parse", "--show-toplevel"])
    if os.path.realpath(top) != root:
        fail(f"--worktree {worktree} is not a worktree root ({top})")
    script = os.path.realpath(__file__)
    if not script.startswith(root + os.sep):
        fail("this script must run from inside --worktree "
             f"(script {script}, worktree {root})")
    try:
        head = run_git(["-C", root, "rev-parse", "HEAD"])
    except BaselineError:
        head = None
    branch = run_git(["-C", root, "symbolic-ref", "--short", "-q", "HEAD"])
    return {"root": root, "head": head, "branch": branch or "detached"}


def ensure_dataset(bench, pin, timeout):
    """Clone the benchmark dataset at the pinned commit: init + depth-1
    fetch + detached checkout, then verify HEAD == pin."""
    if os.path.isdir(bench) and os.listdir(bench):
        head = run_git(["-C", bench, "rev-parse", "HEAD"])
        if head != pin:
            fail(f"benchmark dir {bench} HEAD {head} != pin {pin}")
        return
    os.makedirs(bench, exist_ok=True)
    run_git(["-C", bench, "init", "-q"])
    remotes = run_git(["-C", bench, "remote"])
    if "origin" not in remotes.split():
        run_git(["-C", bench, "remote", "add", "origin", DATASET_URL])
    run_git(["-C", bench, "fetch", "--depth", "1", "origin", pin],
            timeout=timeout)
    run_git(["-C", bench, "checkout", "-q", "--detach", "FETCH_HEAD"])
    head = run_git(["-C", bench, "rev-parse", "HEAD"])
    if head != pin:
        fail(f"dataset checkout HEAD {head} != pin {pin}")


def git_snapshot_fetcher(tmpdir, repo_url, sha, timeout):
    """VEX-Bench downloader contract: depth-1 fetch of the full SHA, then
    detached checkout. Short SHAs are never fetched."""
    run_git(["-C", tmpdir, "init", "-q"])
    remotes = run_git(["-C", tmpdir, "remote"])
    if "origin" not in remotes.split():
        run_git(["-C", tmpdir, "remote", "add", "origin", repo_url])
    run_git(["-C", tmpdir, "fetch", "--depth", "1", "origin", sha],
            timeout=timeout)
    run_git(["-C", tmpdir, "checkout", "-q", "--detach", "FETCH_HEAD"])
    head = run_git(["-C", tmpdir, "rev-parse", "HEAD"])
    if head != sha:
        fail(f"snapshot {sha}: checked out {head}")


# --------------------------------------------------------------------------
# Snapshot tree integrity — byte-parity port of
# internal/repository.ContentHash (encoding version "t1") and preflight
# checks (VerifyContained, CheckPathReplacements). Do not invent a second
# format under the same name.


def iter_tree(root):
    """Yield (rel, kind, path, stat) for every non-.git entry. kind is
    dir/file/symlink; other types are a hard error (Go opens them)."""
    entries = []

    def rec(dirpath):
        try:
            items = list(os.scandir(dirpath))
        except OSError as e:
            fail(f"walk snapshot: {e}")
        for de in items:
            try:
                st = de.stat(follow_symlinks=False)
            except OSError as e:
                fail(f"stat {de.path}: {e}")
            if stat.S_ISDIR(st.st_mode) and de.name == ".git":
                continue
            rel = os.path.relpath(de.path, root)
            if stat.S_ISDIR(st.st_mode):
                entries.append((rel, "dir", de.path, st))
                rec(de.path)
            elif stat.S_ISLNK(st.st_mode):
                entries.append((rel, "symlink", de.path, st))
            elif stat.S_ISREG(st.st_mode):
                entries.append((rel, "file", de.path, st))
            else:
                fail(f"unsupported file type in snapshot: {de.path}")

    rec(root)
    return entries


def t1_content_hash(root):
    """Canonical snapshot hash — byte parity with
    internal/repository.ContentHash (version prefix "t1")."""
    entries = iter_tree(os.path.abspath(root))
    entries.sort(key=lambda e: os.fsencode(e[0]))
    h = hashlib.sha256()
    h.update(b"t1\n")
    for rel, kind, path, st in entries:
        rel_b = os.fsencode(rel).replace(b"\\", b"/")
        mode = st.st_mode & 0o111
        if kind == "symlink":
            payload = os.fsencode(os.readlink(path))
            length = len(payload)
        elif kind == "file":
            payload = sha256_file(path).encode()
            length = st.st_size
        else:
            payload = b""
            length = 0
        h.update(b"%s\t%s\t%o\t%d\t" % (rel_b, kind.encode(), mode, length))
        h.update(payload)
        h.update(b"\n")
    return h.hexdigest()


def _is_source_escape(resolved):
    """Whether an out-of-tree symlink target yields readable source.

    Regular files and directories do; character/block devices, FIFOs and
    sockets do not. A target that cannot be stat'ed is treated as inert
    (nothing readable behind it).
    """
    try:
        st = os.stat(resolved)
    except OSError:
        return False
    if stat.S_ISCHR(st.st_mode) or stat.S_ISBLK(st.st_mode):
        return False
    if stat.S_ISFIFO(st.st_mode) or stat.S_ISSOCK(st.st_mode):
        return False
    return stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)


def _realpath_strict(path):
    """EvalSymlinks parity: resolve and require the target to exist."""
    resolved = os.path.realpath(path)
    if not os.path.exists(resolved):
        fail(f"snapshot symlink does not resolve: {path}")
    return resolved


def lexically_within(root, target):
    rel = os.path.relpath(target, root).replace(os.sep, "/")
    return rel == "." or (rel != ".." and not rel.startswith("../"))


def verify_contained(root):
    """Parity with repository.VerifyContained: any symlink whose canonical
    target leaves the snapshot root is an error.

    An unresolvable (broken or cyclic) symlink is inert — it cannot be
    followed to leak content — and is accepted; such links occur
    legitimately in real source trees.
    """
    root = os.path.realpath(root)
    for rel, kind, path, _st in iter_tree(root):
        if kind != "symlink":
            continue
        try:
            resolved = _realpath_strict(path)
        except BaselineError:
            # Broken/cyclic link: inert, cannot leak.
            continue
        if not lexically_within(root, resolved):
            # A link out of the tree leaks only when it yields readable
            # source. Character/block devices, FIFOs and sockets (e.g.
            # testdata fixtures pointing at /dev/null) carry no source
            # content and are inert; only regular files and directories
            # escape.
            if not _is_source_escape(resolved):
                continue
            fail(f"snapshot entry {rel} escapes the snapshot root "
                 f"(target {os.readlink(path)})")


def _is_path_target(t):
    return (t.startswith("./") or t.startswith("../") or
            t in (".", "..") or os.path.isabs(t))


def _resolve_existing_prefix(path):
    """Longest existing prefix symlink resolution (repository parity)."""
    cur = os.path.normpath(path)
    rest = []
    while True:
        if os.path.lexists(cur):
            try:
                # No strict kwarg (Python 3.9 lacks it); lexists() above
                # already proved the path exists.
                resolved = os.path.realpath(cur)
            except OSError:
                return None, False
            for comp in reversed(rest):
                resolved = os.path.join(resolved, comp)
            return resolved, True
        parent = os.path.dirname(cur)
        if parent == cur:
            return None, False
        rest.append(os.path.basename(cur))
        cur = parent


def _resolve_within(root, target):
    joined = os.path.normpath(os.path.join(root, target))
    if os.path.isabs(target):
        joined = os.path.normpath(target)
    resolved, ok = _resolve_existing_prefix(joined)
    if ok:
        return lexically_within(root, resolved)
    return lexically_within(root, os.path.normpath(joined))


def _check_replacements_in(content, name, root):
    """Parity with repository.checkReplacementsIn — including the exact
    branch order and comment-stripping behaviour."""
    in_block = ""
    for i, line in enumerate(content.split("\n")):
        trimmed = line.strip()
        if not trimmed or trimmed.startswith("//"):
            continue
        target = None
        if "=>" in trimmed:
            rhs = trimmed.split("=>", 1)[1].strip()
            target = rhs.split("//", 1)[0].strip()
        elif trimmed.startswith("use "):
            rest = trimmed[len("use "):].strip()
            if rest == "(":
                in_block = "use"
                continue
            target = rest
        elif trimmed.startswith("replace"):
            rest = trimmed[len("replace"):].strip()
            if rest == "(":
                in_block = "replace"
            continue
        elif in_block == "use":
            if trimmed == ")":
                in_block = ""
                continue
            target = trimmed
        elif in_block == "replace":
            if trimmed == ")":
                in_block = ""
            continue
        else:
            continue
        if not target or not _is_path_target(target):
            continue
        if not _resolve_within(root, target):
            fail(f"{name}:{i + 1}: path target {target!r} escapes the "
                 f"snapshot root")


def check_path_replacements(root):
    """Parity with repository.CheckPathReplacements on go.mod/go.work."""
    root = os.path.realpath(root)
    for name in ("go.mod", "go.work"):
        p = os.path.join(root, name)
        if not os.path.isfile(p):
            continue
        with open(p, "r", encoding="utf-8", errors="surrogateescape") as f:
            _check_replacements_in(f.read(), name, root)


def make_readonly(root):
    """Strip every write bit, keep execute bits; symlinks untouched."""
    for _rel, kind, path, _st in iter_tree(root):
        if kind == "symlink":
            continue
        st = os.lstat(path)
        os.chmod(path, st.st_mode & ~0o222)
    st = os.lstat(root)
    os.chmod(root, st.st_mode & ~0o222)


def check_immutable(root):
    """Every regular entry must be non-writable.

    Symlinks are exempt: their mode bits are platform-ignored (on macOS an
    lstat of a symlink always reports 0o755 regardless of chmod, and chmod
    follows the link rather than changing it), and a symlink carries no
    writable content of its own — its target lives elsewhere, so a write bit
    on the link entry does not make the snapshot mutable. make_readonly
    likewise leaves symlinks untouched; the two must agree.
    """
    writable = [rel for rel, kind, _p, st in iter_tree(root)
                if kind != "symlink" and st.st_mode & 0o222]
    if os.lstat(root).st_mode & 0o222:
        writable.append(".")
    if writable:
        fail(f"snapshot is writable ({writable[0]} +{len(writable) - 1} "
             f"more)")


def tree_integrity(root):
    """Integrity manifest of a snapshot tree: per-entry kind/exec/size and
    file digests, plus bytes/counts. Paths are relative — valid after the
    atomic rename to the final location."""
    files = []
    total_bytes = 0
    counts = {"file": 0, "dir": 0, "symlink": 0}
    for rel, kind, path, st in iter_tree(root):
        entry = {"path": rel.replace(os.sep, "/"), "kind": kind,
                 "exec": bool(st.st_mode & 0o111)}
        if kind == "file":
            entry["size"] = st.st_size
            entry["sha256"] = sha256_file(path)
            total_bytes += st.st_size
        elif kind == "symlink":
            entry["target"] = os.readlink(path)
        files.append(entry)
        counts[kind] += 1
    files.sort(key=lambda e: e["path"])
    return {
        "entries": files,
        "bytes": total_bytes,
        "file_count": counts["file"],
        "entry_count": sum(counts.values()),
    }


def release_evidence_candidates(root):
    """Best-effort list of snapshot-local release-version evidence files —
    the analyzer's own discovery decides what counts; this list only makes
    the search space auditable."""
    out = []

    def add(path, evidence):
        out.append({"path": path, "evidence": evidence})

    gomod = os.path.join(root, "go.mod")
    if os.path.isfile(gomod):
        with open(gomod, encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f, 1):
                ls = line.strip()
                if ls.startswith("toolchain "):
                    add("go.mod", f"{i}:{ls}")
                elif ls.startswith("go "):
                    add("go.mod", f"{i}:{ls}")
    for name in (".go-version", ".tool-versions"):
        p = os.path.join(root, name)
        if os.path.isfile(p):
            with open(p, encoding="utf-8", errors="replace") as f:
                first = f.readline().strip()
            add(name, first)
    try:
        entries = os.listdir(root)
    except OSError:
        entries = []
    for name in entries:
        if name.startswith("Dockerfile") and os.path.isfile(
                os.path.join(root, name)):
            with open(os.path.join(root, name), encoding="utf-8",
                      errors="replace") as f:
                for i, line in enumerate(f, 1):
                    if re.search(r"FROM\s+golang:", line):
                        add(name, f"{i}:{line.strip()}")
    wf = os.path.join(root, ".github", "workflows")
    if os.path.isdir(wf):
        for name in sorted(os.listdir(wf)):
            if not name.endswith((".yml", ".yaml")):
                continue
            p = os.path.join(wf, name)
            try:
                with open(p, encoding="utf-8", errors="replace") as f:
                    for i, line in enumerate(f, 1):
                        if "go-version" in line or "setup-go" in line:
                            add(f".github/workflows/{name}", f"{i}:{line.strip()}")
            except OSError:
                continue
    return out


# --------------------------------------------------------------------------
# acquire


def acquire(*, worktree, benchmark_dir, benchmark_sha, repos_dir,
            manifest_path, fetch_timeout_seconds,
            dataset_cloner=ensure_dataset,
            snapshot_fetcher=git_snapshot_fetcher,
            expected=EXPECTED_COUNTS):
    wt = check_worktree(worktree)
    bench = os.path.abspath(benchmark_dir)
    repos = os.path.abspath(repos_dir)
    mpath = os.path.abspath(manifest_path)
    manifest_dir = os.path.dirname(mpath)
    os.makedirs(manifest_dir, exist_ok=True)
    os.makedirs(repos, exist_ok=True)

    if not SHA40.fullmatch(benchmark_sha):
        fail(f"--benchmark-sha must be a full 40-hex commit, got {benchmark_sha!r}")

    dataset_cloner(bench, benchmark_sha, fetch_timeout_seconds)
    tasks_file = os.path.join(bench, TASKS_REL)
    if not os.path.isfile(tasks_file):
        fail(f"dataset lacks {TASKS_REL}")
    tasks_sha = sha256_file(tasks_file)
    pinned_copy = os.path.join(manifest_dir, "vex_bench.jsonl")
    if not os.path.exists(pinned_copy):
        shutil.copyfile(tasks_file, pinned_copy)

    all_rows = load_tasks(tasks_file)
    # metadata.language == "go", case-insensitive, file order preserved.
    go_rows = [(t, raw) for t, raw in all_rows
               if t["language"].lower() == "go"]
    go_tasks = [t for t, raw in go_rows]
    go_subset = os.path.join(manifest_dir, "go-tasks.jsonl")
    atomic_write_bytes(go_subset, "".join(raw + "\n" for _, raw in go_rows).encode())

    counts = {
        "tasks": len({t["task_id"] for t in go_tasks}),
        "snapshots": len({(t["repo_url"], t["commit_sha"]) for t in go_tasks}),
        "repos": len({t["repo_url"] for t in go_tasks}),
        "cves": len({t["cve_id"] for t in go_tasks}),
    }
    cats = {}
    for t in go_tasks:
        cats[t["ground_truth_category"]] = cats.get(
            t["ground_truth_category"], 0) + 1
        counts[f"gt_{t['ground_truth_category']}"] = cats[t["ground_truth_category"]]
    for key, want in expected.items():
        got = counts.get(key, 0)
        if got != want:
            fail(f"pinned Go subset check failed: {key}={got}, want {want}")
    ids = [t["task_id"] for t in go_tasks]
    if len(ids) != len(set(ids)):
        fail("duplicate task_id in Go subset")
    for t in go_tasks:
        if not SHA40.fullmatch(t["commit_sha"]):
            fail(f"task {t['task_id']}: commit_sha {t['commit_sha']!r} is not "
                 "a full 40-hex sha")
        parse_repo_url(t["repo_url"])

    manifest = {
        "schema": 1,
        "orchestrator_version": ORCHESTRATOR_VERSION,
        "adapter_version": ADAPTER_VERSION,
        "created_at_utc": utcnow(),
        "worktree": wt,
        "dataset": {
            "url": DATASET_URL,
            "pin": benchmark_sha,
            "tasks_file": tasks_file,
            "tasks_sha256": tasks_sha,
            "go_subset_file": go_subset,
            "go_subset_sha256": sha256_file(go_subset),
            "benchmark_dir": bench,
        },
        "counts": counts,
        # Control-plane task list: no ground truth / pr_url — labels stay
        # in the scorer-side pinned JSONL only.
        "tasks": [{"task_id": t["task_id"], "repo_url": t["repo_url"],
                   "commit_sha": t["commit_sha"], "cve_id": t["cve_id"]}
                  for t in go_tasks],
        "snapshots": {},
        "errors": [],
    }
    if os.path.exists(mpath):
        prev = load_json(mpath)
        if prev.get("dataset", {}).get("pin") == benchmark_sha:
            manifest["snapshots"] = prev.get("snapshots", {})
            manifest["errors"] = prev.get("errors", [])

    seen = set()
    order = []
    for t in go_tasks:
        key = (t["repo_url"], t["commit_sha"])
        if key in seen:
            continue
        seen.add(key)
        owner, repo = parse_repo_url(t["repo_url"])
        order.append({"repo_url": t["repo_url"], "commit_sha": t["commit_sha"],
                      "owner": owner, "repo": repo})

    failures = 0
    for spec in order:
        key = f"{spec['owner']}/{spec['repo']}/{spec['commit_sha']}"
        final_dir = os.path.join(repos, spec["owner"], spec["repo"],
                                 spec["commit_sha"])
        rec = manifest["snapshots"].get(key)
        if rec and rec.get("status") == "ready" and rec.get("content_hash"):
            if os.path.isdir(final_dir) and \
                    t1_content_hash(final_dir) == rec["content_hash"]:
                eprint(f"acquire: {key} already ready (digest verified)")
                continue
            eprint(f"acquire: {key} manifest entry stale — tree changed")
        if os.path.exists(final_dir):
            manifest["errors"].append(
                f"{key}: final dir exists without a valid manifest entry; "
                "not auto-deleted — inspect or remove manually")
            failures += 1
            continue
        tmp_dir = final_dir + ".acquiring"
        started = time.monotonic()
        try:
            if os.path.isdir(tmp_dir):
                shutil.rmtree(tmp_dir)  # only our own staging dir
            os.makedirs(tmp_dir)
            snapshot_fetcher(tmp_dir, spec["repo_url"], spec["commit_sha"],
                             fetch_timeout_seconds)
            gitdir = os.path.join(tmp_dir, ".git")
            if os.path.isdir(gitdir):
                head = run_git(["-C", tmp_dir, "rev-parse", "HEAD"])
                if head != spec["commit_sha"]:
                    fail(f"checkout HEAD {head} != task sha")
                shutil.rmtree(gitdir)  # only our own temporary .git
            integrity = tree_integrity(tmp_dir)
            content_hash = t1_content_hash(tmp_dir)
            integrity_name = (
                f"{spec['owner']}--{spec['repo']}--{spec['commit_sha']}.json")
            integrity_path = os.path.join(manifest_dir, "integrity",
                                          integrity_name)
            integrity["release_evidence_candidates"] = \
                release_evidence_candidates(tmp_dir)
            integrity["has_go_mod"] = os.path.isfile(
                os.path.join(tmp_dir, "go.mod"))
            integrity["has_vendor"] = os.path.isdir(
                os.path.join(tmp_dir, "vendor"))
            integrity["has_vendor_modules_txt"] = os.path.isfile(
                os.path.join(tmp_dir, "vendor", "modules.txt"))
            atomic_write_json(integrity_path, integrity)
            os.replace(tmp_dir, final_dir)
            make_readonly(final_dir)
            manifest["snapshots"][key] = {
                "status": "ready",
                "repo_url": spec["repo_url"],
                "commit_sha": spec["commit_sha"],
                "path": final_dir,
                "content_hash": content_hash,
                "integrity_ref": os.path.relpath(integrity_path, manifest_dir),
                "integrity_sha256": sha256_file(integrity_path),
                "bytes": integrity["bytes"],
                "file_count": integrity["file_count"],
                "download_seconds": round(time.monotonic() - started, 3),
                "immutable": True,
            }
            atomic_write_json(mpath, manifest)
            eprint(f"acquire: {key} ready "
                   f"({integrity['bytes']} B, {integrity['file_count']} files)")
        except (BaselineError, OSError) as e:
            manifest["errors"].append(f"{key}: {e}")
            manifest["snapshots"][key] = {
                "status": "failed", "repo_url": spec["repo_url"],
                "commit_sha": spec["commit_sha"], "error": str(e),
            }
            failures += 1
            eprint(f"acquire: {key} FAILED: {e}")
        finally:
            if os.path.isdir(tmp_dir):
                shutil.rmtree(tmp_dir, ignore_errors=True)

    manifest["finished_at_utc"] = utcnow()
    atomic_write_json(mpath, manifest)
    if failures:
        eprint(f"acquire: {failures} snapshot(s) failed — manifest {mpath}")
        return 1
    eprint(f"acquire: {len(order)}/{len(order)} snapshots ready, "
           f"{counts['tasks']} tasks — manifest {mpath}")
    return 0


# --------------------------------------------------------------------------
# preflight


def _which(env, name):
    for d in env.get("PATH", "").split(os.pathsep):
        cand = os.path.join(d or ".", name)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return os.path.abspath(cand)
    return None


def _run_version(bin_path, args, env, timeout=30):
    cp = subprocess.run([bin_path] + args, capture_output=True, text=True,
                        env=env, timeout=timeout)
    return cp.returncode, (cp.stdout + cp.stderr).strip()


def normalize_go_version(v):
    v = v.strip()
    return v[2:] if v.startswith("go") else v


def build_clean_env(ambient, *, analysis_go, cache_root, pinned_dirs):
    env = {}
    for k in ENV_EXACT:
        if k in ambient:
            env[k] = ambient[k]
    for k in GO_PASSTHROUGH:
        if k in ambient:
            env[k] = ambient[k]
    gopath = os.path.join(cache_root, "gopath")
    env.update({
        "GOENV": "off",
        "GOWORK": "off",
        "GOFLAGS": "",
        "GOTOOLCHAIN": "go" + normalize_go_version(analysis_go),
        "CGO_ENABLED": "0",
        "GOCACHE": os.path.join(cache_root, "gocache"),
        "GOPATH": gopath,
        "GOMODCACHE": os.path.join(gopath, "pkg", "mod"),
        "TMPDIR": os.path.join(cache_root, "tmp"),
        "PATH": os.pathsep.join(pinned_dirs +
                                ambient.get("PATH", "").split(os.pathsep)),
    })
    return env


def _check_snapshot_ready(rec):
    """One ready snapshot must exist, be immutable, contained, and match
    the recorded canonical digest."""
    path = rec["path"]
    if not os.path.isdir(path):
        fail(f"snapshot missing: {path}")
    check_immutable(path)
    verify_contained(path)
    check_path_replacements(path)
    if os.path.isdir(os.path.join(path, "vendor")) and not os.path.isfile(
            os.path.join(path, "vendor", "modules.txt")):
        fail(f"snapshot has vendor/ but no vendor/modules.txt: {path}")
    if rec.get("content_hash") and \
            t1_content_hash(path) != rec["content_hash"]:
        fail(f"snapshot content hash mismatch: {path}")


def preflight(*, worktree, benchmark_dir, repos_dir, acquisition, out,
              izyan, analysis_go, mem_limit, workers, case_timeout_seconds,
              cache_root=None, disk_free=default_disk_free,
              ram_bytes=physical_ram_bytes, ambient_env=None):
    wt = check_worktree(worktree)
    acq = load_json(acquisition)
    if not SHA40.fullmatch(acq.get("dataset", {}).get("pin", "")):
        fail("acquisition manifest lacks a valid dataset pin")
    bench = os.path.abspath(benchmark_dir)
    tasks_file = os.path.join(bench, TASKS_REL)
    if sha256_file(tasks_file) != acq["dataset"]["tasks_sha256"]:
        fail(f"tasks file digest drifted since acquisition: {tasks_file}")
    head = run_git(["-C", bench, "rev-parse", "HEAD"])
    if head != acq["dataset"]["pin"]:
        fail(f"benchmark dir HEAD {head} != acquisition pin")

    out = os.path.abspath(out)
    if os.path.isdir(out) and os.listdir(out):
        fail(f"--out {out} must be new or empty for preflight")
    os.makedirs(out, exist_ok=True)
    cache_root = os.path.abspath(cache_root or os.path.join(out, "caches"))

    izyan_abs = os.path.abspath(izyan)
    if not (os.path.isfile(izyan_abs) and os.access(izyan_abs, os.X_OK)):
        fail(f"--izyan {izyan} is not an executable file")
    izyan_sha = sha256_file(izyan_abs)
    try:
        _, izyan_build = _run_version("go", ["version", "-m", izyan_abs], None)
    except (OSError, subprocess.SubprocessError):
        izyan_build = ""

    snaps = acq.get("snapshots", {})
    ready = [k for k, r in snaps.items() if r.get("status") == "ready"]
    if len(ready) != acq["counts"]["snapshots"]:
        fail(f"acquisition incomplete: {len(ready)}/"
             f"{acq['counts']['snapshots']} snapshots ready")
    for k in ready:
        _check_snapshot_ready(snaps[k])

    # Toolchain probes under the clean env, never the ambient one.
    env_probe = dict(ambient_env if ambient_env is not None else os.environ)
    clean = build_clean_env(env_probe, analysis_go=analysis_go,
                            cache_root=cache_root,
                            pinned_dirs=[os.path.dirname(izyan_abs)])
    for d in (clean["GOCACHE"], clean["GOPATH"], clean["GOMODCACHE"],
              clean["TMPDIR"]):
        os.makedirs(d, exist_ok=True)

    go_bin = _which(clean, "go")
    if not go_bin:
        fail("no `go` executable under the clean environment PATH")
    rc, go_ver = _run_version(go_bin, ["version"], clean)
    m = re.search(r"go(\d+\.\d+(?:\.\d+)?)", go_ver)
    actual_go = m.group(1) if m else ""
    if rc != 0 or actual_go != normalize_go_version(analysis_go):
        fail(f"analysis go must be {analysis_go}, resolved {go_ver!r}")

    gv_bin = _which(clean, "govulncheck")
    if not gv_bin:
        for cand in (os.path.join(clean["GOPATH"], "bin", "govulncheck"),
                     os.path.expanduser("~/go/bin/govulncheck")):
            if os.path.isfile(cand):
                gv_bin = cand
                break
    gv_info = {}
    if not gv_bin:
        fail("govulncheck not found (PATH, GOPATH/bin, ~/go/bin) — "
             "the baseline requires reachability analysis")
    rc, gv_ver = _run_version(gv_bin, ["-version"], clean)
    gv_info = {"path": gv_bin, "sha256": sha256_file(gv_bin),
               "version_output": gv_ver if rc in (0, 3) else None}
    if rc not in (0, 3):
        fail(f"govulncheck -version failed: {gv_ver!r}")

    # Disk gate — one check per distinct filesystem.
    seen_dev, frees = set(), {}
    for p in (out, repos_dir, cache_root):
        dev = os.stat(p).st_dev
        if dev in seen_dev:
            continue
        seen_dev.add(dev)
        free = disk_free(p)
        frees[p] = free
        if free < DISK_GATE_BYTES:
            fail(f"disk gate: {p} has {free >> 30} GiB free, need "
                 f"{DISK_GATE_BYTES >> 30}")
        if free < DISK_GATE_RECOMMENDED:
            eprint(f"preflight: warning — {p} below recommended "
                   f"{DISK_GATE_RECOMMENDED >> 30} GiB free")

    ram = ram_bytes()
    mem = parse_mem_limit(mem_limit)
    if ram is None:
        eprint("preflight: warning — physical RAM undetectable")
    else:
        need = workers * mem + (8 << 30)
        if ram < workers * mem:
            fail(f"RAM {ram >> 30} GiB < workers*mem-limit "
                 f"{workers}x{mem >> 30} GiB")
        if ram < need:
            eprint(f"preflight: warning — RAM {ram >> 30} GiB below "
                   f"recommended {need >> 30} GiB for workers={workers}; "
                   "child go/govulncheck heaps are not covered by --mem-limit")

    manifest = {
        "schema": 1,
        "baseline_name": BASELINE_NAME,
        "run_id": f"{BASELINE_NAME}-{int(time.time())}",
        "created_at_utc": utcnow(),
        "orchestrator_version": ORCHESTRATOR_VERSION,
        "orchestrator_sha256": sha256_file(os.path.realpath(__file__)),
        "adapter_version": ADAPTER_VERSION,
        "execution_mode": "case_isolated",
        "workers": workers,
        "cli_j": 1,
        "worktree": wt,
        "dataset": acq["dataset"],
        "acquisition": {
            "path": os.path.abspath(acquisition),
            "sha256": sha256_file(acquisition),
        },
        "tasks": acq["tasks"],
        "snapshot_refs": {k: {"commit_sha": r["commit_sha"],
                              "content_hash": r.get("content_hash"),
                              "path": r["path"]}
                          for k, r in snaps.items()},
        "izyan": {"path": izyan_abs, "sha256": izyan_sha,
                  "build_info": izyan_build},
        "go": {"path": go_bin, "version": actual_go,
               "sha256": sha256_file(go_bin), "version_output": go_ver},
        "govulncheck": gv_info,
        "profile": {
            "analysis_go": analysis_go,
            "mem_limit": mem_limit,
            "case_timeout_seconds": case_timeout_seconds,
            "host_os": platform.system().lower(),
            "host_arch": platform.machine(),
            "target_goos": platform.system().lower(),
            "target_goarch": platform.machine(),
            "cgo_enabled": "0",
            "build_tags": [],
        },
        "env": clean,
        "cache_root": cache_root,
        "out": {"dir": out,
                "attempts": os.path.join(out, "attempts"),
                "ledger": os.path.join(out, "ledger")},
        "argv_template": [
            izyan_abs, "eval", "vex-bench",
            "--tasks", tasks_file,
            "--repos-dir", os.path.abspath(repos_dir),
            "--case", "{task_id}", "-j", "1",
            "--analysis-go", analysis_go,
            "--mem-limit", mem_limit,
            "--out", "{raw_dir}",
        ],
        "disk_free_bytes_at_preflight": {p: v for p, v in frees.items()},
        "ram_bytes": ram,
    }
    manifest_path = os.path.join(out, "run-manifest.json")
    atomic_write_json(manifest_path, manifest)
    shutil.copyfile(acquisition, os.path.join(out, "acquisition.copy.json"))

    # Frozen per-task ledger: pending records bind each task to the full
    # run fingerprint before any subprocess starts.
    ledger_dir = manifest["out"]["ledger"]
    os.makedirs(ledger_dir, exist_ok=True)
    fp = {
        "manifest_sha256": sha256_file(manifest_path),
        "izyan_binary_sha256": izyan_sha,
        "adapter_version": ADAPTER_VERSION,
        "tasks_sha256": acq["dataset"]["tasks_sha256"],
        "go_sha256": manifest["go"]["sha256"],
        "profile": manifest["profile"],
        "workers": workers,
    }
    for t in manifest["tasks"]:
        snap_key = None
        owner, repo = parse_repo_url(t["repo_url"])
        snap_key = f"{owner}/{repo}/{t['commit_sha']}"
        srec = snaps.get(snap_key, {})
        rec = {
            "task_id": t["task_id"],
            "state": "pending",
            "created_at_utc": utcnow(),
            "fingerprint": dict(fp, **{
                "snapshot_key": snap_key,
                "snapshot_sha": t["commit_sha"],
                "snapshot_content_hash": srec.get("content_hash"),
            }),
        }
        atomic_write_json(os.path.join(ledger_dir, t["task_id"] + ".json"),
                          rec)
    eprint(f"preflight: manifest {manifest_path}; {len(ready)} snapshots "
           f"verified; workers={workers} mem={mem_limit} "
           f"deadline={case_timeout_seconds}s")
    eprint("preflight: NOTE — govulncheck DB is live_observed, not a frozen "
           "snapshot; per-case OSV/OSV-DB identity comes from the raw runs")
    return 0


# --------------------------------------------------------------------------
# run — ledger + process-group isolation + resume


def _packet_complete(raw_dir, task_id):
    """The raw packet is complete when the CLI finished writing all three
    artifacts and the prediction parses. A complete packet after an
    interrupted ledger commit is recoverable without re-analysis."""
    pred = os.path.join(raw_dir, sanitize_case_name(task_id),
                        "prediction.json")
    try:
        env = load_json(pred)
        if env.get("task_id") != task_id:
            return False
        load_json(os.path.join(raw_dir, "metrics.json"))
        with open(os.path.join(raw_dir, "scoring", "cases.jsonl"),
                  encoding="utf-8") as cf:
            rows = [json.loads(l) for l in cf if l.strip()]
        return any(r.get("task_id") == task_id for r in rows)
    except (OSError, json.JSONDecodeError):
        return False


def _file_digests(root):
    out = {}
    for dirpath, _dirs, names in os.walk(root):
        for name in names:
            p = os.path.join(dirpath, name)
            rel = os.path.relpath(p, root)
            try:
                out[rel] = {"sha256": sha256_file(p),
                            "size": os.path.getsize(p)}
            except OSError:
                continue
    return out


def _write_ledger(ledger_dir, rec):
    atomic_write_json(os.path.join(ledger_dir, rec["task_id"] + ".json"),
                      rec)


def _finalize(rec, *, ledger_dir, outcome, exit_code=None, reason="",
              recovered=False, raw_dir=None, extra=None):
    """Ledger transitions are one-way: finalized records are never
    overwritten on resume."""
    rec["state"] = "finalized"
    rec["finalized_at_utc"] = utcnow()
    rec["outcome"] = outcome
    rec["exit_code"] = exit_code
    rec["recovered_after_interruption"] = recovered
    if reason:
        rec["failure"] = {"kind": "infrastructure", "reason": reason}
    if raw_dir and os.path.isdir(raw_dir):
        pred = os.path.join(raw_dir, sanitize_case_name(rec["task_id"]),
                            "prediction.json")
        if os.path.isfile(pred):
            rec["prediction_path"] = pred
            rec["prediction_sha256"] = sha256_file(pred)
            try:
                env = load_json(pred)
                rec["verdict"] = env.get("verdict") or None
                rec["compatibility_category"] = env.get(
                    "compatibility_category")
                rec["scoring_outcome"] = env.get("scoring_outcome")
            except (OSError, json.JSONDecodeError):
                rec.setdefault("notes", []).append(
                    "prediction.json unreadable at finalize")
        rec["artifacts"] = _file_digests(raw_dir)
    if extra:
        rec.update(extra)
    _write_ledger(ledger_dir, rec)


def _kill_group(proc, killpg, grace_seconds):
    """SIGTERM the whole process group, grace, then SIGKILL. Returns the
    termination channel used."""
    pgid = proc.pid  # start_new_session makes pid == pgid
    try:
        killpg(pgid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        pass
    deadline = time.monotonic() + grace_seconds
    while proc.poll() is None and time.monotonic() < deadline:
        time.sleep(0.1)
    if proc.poll() is None:
        try:
            killpg(pgid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass
        proc.wait()
        return "sigkill"
    return "sigterm"


def _event(out_dir, event, task_id=None, detail=None):
    row = {"ts": utcnow(), "event": event}
    if task_id:
        row["task_id"] = task_id
    if detail:
        row["detail"] = detail
    path = os.path.join(out_dir, "run-events.jsonl")
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(row) + "\n")
            f.flush()
            os.fsync(f.fileno())
    except OSError:
        pass


def run(*, manifest_path, resume=False, workers_override=None,
        popen_factory=subprocess.Popen, disk_free=default_disk_free,
        killpg=os.killpg, disk_check_seconds=30, poll_seconds=0.5,
        sig_grace=SIG_GRACE_SECONDS):
    manifest = load_json(manifest_path)
    out_dir = manifest["out"]["dir"]
    ledger_dir = manifest["out"]["ledger"]
    workers = manifest["workers"]
    if workers_override is not None and workers_override != workers:
        fail(f"--workers {workers_override} != frozen manifest workers "
             f"{workers}")
    tasks = manifest["tasks"]

    if resume:
        # Identity re-check: the frozen binaries and task file must match
        # what preflight pinned — a swapped tool is not a resume.
        for key, meta in (("izyan", manifest["izyan"]),
                          ("go", manifest["go"])):
            if sha256_file(meta["path"]) != meta["sha256"]:
                fail(f"resume refused: {key} binary digest changed")
        if sha256_file(manifest["dataset"]["tasks_file"]) != \
                manifest["dataset"]["tasks_sha256"]:
            fail("resume refused: tasks file digest changed")

    recs = {}
    non_pending = False
    for t in tasks:
        tid = t["task_id"]
        path = os.path.join(ledger_dir, tid + ".json")
        if os.path.isfile(path):
            rec = load_json(path)
        else:
            rec = {"task_id": tid, "state": "pending",
                   "fingerprint": {"manifest_sha256":
                                   sha256_file(manifest_path)}}
        recs[tid] = rec
        if rec.get("state") != "pending":
            non_pending = True
    if non_pending and not resume:
        fail("ledger has non-pending records — this looks like a resumed "
             "run; pass --resume or investigate manually")

    finalized = set()
    interrupted = []  # informational only — IDs already logged via events
    for t in tasks:
        tid = t["task_id"]
        rec = recs[tid]
        state = rec.get("state")
        if state == "finalized":
            fp = rec.get("fingerprint", {})
            if fp.get("manifest_sha256") != sha256_file(manifest_path):
                fail(f"resume refused: {tid} finalized under a different "
                     "manifest fingerprint")
            finalized.add(tid)   # all finalized outcomes skip — incl. failed
        elif state == "running":
            raw_dir = os.path.join(manifest["out"]["attempts"], tid, "raw")
            if _packet_complete(raw_dir, tid):
                _finalize(rec, ledger_dir=ledger_dir, outcome="completed",
                          recovered=True, raw_dir=raw_dir,
                          extra={"recovery": "packet complete before "
                                             "interruption"})
                finalized.add(tid)
                _event(out_dir, "resume_recovered", tid)
            else:
                _finalize(rec, ledger_dir=ledger_dir, outcome="failed",
                          recovered=True, raw_dir=raw_dir,
                          reason="process died mid-run before ledger "
                                 "commit; partial artifacts preserved")
                interrupted.append(tid)
                finalized.add(tid)
                _event(out_dir, "resume_failed_incomplete", tid)
        elif state != "pending":
            fail(f"ledger {tid}: unknown state {state!r}")

    if disk_free(out_dir) < DISK_ADMIT_MIN:
        fail(f"disk gate: {out_dir} below {DISK_ADMIT_MIN >> 30} GiB — "
             "not starting the run")

    # Signal policy (plan §4): first SIGINT/SIGTERM stops admission and
    # SIGTERMs every active process group; a second signal escalates to an
    # immediate SIGKILL sweep.
    stop_new = {"flag": False}
    abort_all = {"flag": False, "reason": "", "grace": sig_grace}

    def on_signal(signum, _frame):
        _event(out_dir, "signal", detail=f"received {signum}")
        if not stop_new["flag"]:
            stop_new["flag"] = True
            abort_all["flag"] = True
            abort_all["reason"] = f"signal_{signum}"
        else:
            abort_all["flag"] = True
            abort_all["reason"] = f"signal_{signum}_forced"
            abort_all["grace"] = 0

    old_int = old_term = None
    try:
        old_int = signal.signal(signal.SIGINT, on_signal)
        old_term = signal.signal(signal.SIGTERM, on_signal)
    except ValueError:
        pass  # non-main thread (tests): callers drive stop flags directly

    active = {}
    queue = [t["task_id"] for t in tasks if t["task_id"] not in finalized]
    env = manifest["env"]
    disk_next = time.monotonic()
    rc = 0

    def start_case(tid):
        attempt_dir = os.path.join(manifest["out"]["attempts"], tid)
        raw_dir = os.path.join(attempt_dir, "raw")
        os.makedirs(attempt_dir, exist_ok=True)
        if os.path.isdir(raw_dir):
            # Preserve a stale partial tree from a killed process — never
            # delete bytes a prior attempt wrote.
            stale = f"{raw_dir}.interrupted-{int(time.time())}"
            os.replace(raw_dir, stale)
        os.makedirs(raw_dir)
        rec = recs[tid]
        rec["state"] = "running"
        rec["started_at_utc"] = utcnow()
        rec["argv"] = [a.replace("{task_id}", tid).replace("{raw_dir}",
                                                          raw_dir)
                       for a in manifest["argv_template"]]
        _write_ledger(ledger_dir, rec)  # fsync'd running record BEFORE exec
        sout = open(os.path.join(attempt_dir, "stdout.log"), "ab")
        serr = open(os.path.join(attempt_dir, "stderr.log"), "ab")
        try:
            proc = popen_factory(rec["argv"], env=env, cwd=attempt_dir,
                                 stdout=sout, stderr=serr,
                                 start_new_session=True)
        except OSError as e:
            sout.close()
            serr.close()
            _finalize(rec, ledger_dir=ledger_dir, outcome="failed",
                      reason=f"exec failed: {e}")
            _event(out_dir, "exec_failed", tid, str(e))
            return False
        active[tid] = {
            "proc": proc, "sout": sout, "serr": serr,
            "attempt_dir": attempt_dir, "raw_dir": raw_dir,
            "deadline": time.monotonic() +
            manifest["profile"]["case_timeout_seconds"],
            "started_monotonic": time.monotonic(),
        }
        _event(out_dir, "started", tid, f"pid={proc.pid}")
        eprint(f"run: {tid} started (pid {proc.pid})")
        return True

    def finish_case(tid, why, exit_code=None):
        info = active.pop(tid)
        proc = info["proc"]
        info["sout"].close()
        info["serr"].close()
        rec = recs[tid]
        wall = time.monotonic() - info["started_monotonic"]
        attempt = {
            "task_id": tid,
            "argv": rec.get("argv"),
            "cwd": info["attempt_dir"],
            "started_at_utc": rec.get("started_at_utc"),
            "finished_at_utc": utcnow(),
            "wall_seconds": round(wall, 3),
            "exit_code": exit_code if exit_code is not None else proc.poll(),
            "termination": why,
        }
        atomic_write_json(os.path.join(info["attempt_dir"], "attempt.json"),
                          attempt)
        raw_dir = info["raw_dir"]
        if _packet_complete(raw_dir, tid):
            _finalize(rec, ledger_dir=ledger_dir, outcome="completed",
                      exit_code=attempt["exit_code"], raw_dir=raw_dir)
            eprint(f"run: {tid} completed in {int(wall)}s")
        else:
            _finalize(rec, ledger_dir=ledger_dir, outcome="failed",
                      exit_code=attempt["exit_code"], raw_dir=raw_dir,
                      reason=f"{why}: no complete raw packet")
            eprint(f"run: {tid} FAILED ({why})")
        _event(out_dir, "finalized", tid, why)

    try:
        while queue or active:
            while (queue and not stop_new["flag"] and
                   not abort_all["flag"] and len(active) < workers):
                if disk_free(out_dir) < DISK_ADMIT_MIN:
                    stop_new["flag"] = True
                    _event(out_dir, "disk_pressure_admission_stop")
                    eprint("run: disk below 5 GiB — admission stopped")
                    break
                tid = queue.pop(0)
                start_case(tid)
            now = time.monotonic()
            for tid in list(active):
                info = active[tid]
                proc = info["proc"]
                if proc.poll() is not None:
                    finish_case(tid, "exit",
                                exit_code=proc.returncode)
                elif now > info["deadline"]:
                    _event(out_dir, "deadline", tid)
                    chan = _kill_group(proc, killpg, sig_grace)
                    finish_case(tid, f"deadline_exceeded:{chan}")
            if now >= disk_next:
                disk_next = now + disk_check_seconds
                free = disk_free(out_dir)
                if free < DISK_ABORT_MIN:
                    abort_all["flag"] = True
                    abort_all["reason"] = "disk_pressure"
                    _event(out_dir, "disk_pressure_abort",
                           detail=f"free={free}")
            if abort_all["flag"]:
                for tid, info in list(active.items()):
                    chan = _kill_group(info["proc"], killpg,
                                       abort_all["grace"])
                    finish_case(tid, abort_all["reason"] + ":" + chan)
                break
            if stop_new["flag"] and not active:
                break
            time.sleep(poll_seconds)
    finally:
        if old_int is not None:
            signal.signal(signal.SIGINT, old_int)
            signal.signal(signal.SIGTERM, old_term)

    remaining = [t for t in recs if recs[t].get("state") == "pending"]
    failed = [t for t, r in recs.items()
              if r.get("outcome") == "failed" and r.get("state") == "finalized"]
    if remaining:
        eprint(f"run: stopped with {len(remaining)} pending task(s) "
               f"({', '.join(remaining[:5])}...) — use --resume")
        rc = 1
    if failed:
        eprint(f"run: {len(failed)} task(s) failed: {', '.join(failed)}")
    done = len(tasks) - len(remaining)
    _event(out_dir, "run_finished", detail=f"finalized={done} "
           f"failed={len(failed)} pending={len(remaining)}")
    eprint(f"run: {done}/{len(tasks)} finalized")
    return rc


# --------------------------------------------------------------------------
# report — offline join + aggregate + freeze


def classify_outcome(task, verdict, _category, failed=False):
    """Parity with internal/eval/vexbench Classify."""
    if failed or not verdict:
        return "failed"
    if verdict == VERDICT_INCONCLUSIVE:
        return "abstain"
    gt_exp = task["ground_truth"].lower() == "exploitable"
    if verdict == VERDICT_EXPLOITABLE:
        return "correct_exploitable" if gt_exp else "wrong"
    if verdict in VERDICTS_SAFE:
        return "wrong" if gt_exp else "correct_safe"
    return "failed"


def _read_attempt_prediction(raw_dir, task_id):
    pred = os.path.join(raw_dir, sanitize_case_name(task_id),
                        "prediction.json")
    try:
        return load_json(pred)
    except (OSError, json.JSONDecodeError):
        return None


def report(*, manifest_path, freeze=True, disk_free=default_disk_free):
    manifest = load_json(manifest_path)
    out_dir = manifest["out"]["dir"]
    ledger_dir = manifest["out"]["ledger"]
    tasks_file = manifest["dataset"]["tasks_file"]
    if not os.path.isfile(tasks_file):
        tasks_file = os.path.join(manifest["dataset"]["benchmark_dir"],
                                  TASKS_REL)
    if sha256_file(tasks_file) != manifest["dataset"]["tasks_sha256"]:
        fail("tasks file digest drifted since preflight")
    tasks = load_go_tasks(tasks_file)

    rows = []
    counts = {o: 0 for o in OUTCOMES}
    gt_exp = gt_safe = 0
    walls = []
    llm_calls = 0
    tool_calls = 0
    for t in tasks:
        tid = t["task_id"]
        raw_dir = os.path.join(manifest["out"]["attempts"], tid, "raw")
        env = _read_attempt_prediction(raw_dir, tid)
        ledger_note = None
        lpath = os.path.join(ledger_dir, tid + ".json")
        if os.path.isfile(lpath):
            try:
                lrec = load_json(lpath)
                lsha = lrec.get("prediction_sha256")
                pred_path = os.path.join(
                    raw_dir, sanitize_case_name(tid), "prediction.json")
                if lsha and os.path.isfile(pred_path) and \
                        sha256_file(pred_path) != lsha:
                    ledger_note = ("prediction sha differs from the "
                                   "finalized ledger digest")
            except (OSError, json.JSONDecodeError):
                ledger_note = "ledger record unreadable"
        verdict = (env or {}).get("verdict") or ""
        category = ((env or {}).get("compatibility_category")
                    or "uncertain")
        outcome = classify_outcome(t, verdict, category,
                                   failed=(env is None))
        counts[outcome] += 1
        status_correct = outcome in ("correct_safe",
                                     "correct_exploitable")
        reason_correct = bool(status_correct and
                              category == t["ground_truth_category"])
        if t["ground_truth"].lower() == "exploitable":
            gt_exp += 1
        else:
            gt_safe += 1
        wall = (env or {}).get("wall_seconds")
        if isinstance(wall, (int, float)):
            walls.append(wall)
        if env:
            llm_calls += env.get("llm_calls", 0)
            tool_calls += env.get("tool_calls", 0)
        rows.append({
            "task_id": tid,
            "cve_id": t["cve_id"],
            "verdict": verdict or None,
            "compatibility_category": category,
            "scoring_outcome": outcome,
            "status_correct": status_correct,
            "reason_correct": reason_correct,
            "ground_truth": t["ground_truth"],
            "ground_truth_category": t["ground_truth_category"],
            "prediction_sha256": sha256_file(os.path.join(
                raw_dir, sanitize_case_name(tid), "prediction.json"))
                if env else None,
            "wall_seconds": wall,
            "llm_calls": (env or {}).get("llm_calls"),
            "tool_calls": (env or {}).get("tool_calls"),
            "integrity_note": ledger_note,
        })

    false_safe = sum(1 for r, t in zip(rows, tasks)
                     if r["scoring_outcome"] == "wrong"
                     and t["ground_truth"].lower() == "exploitable")
    total = len(rows)
    tp = sum(1 for r in rows if r["verdict"] == VERDICT_EXPLOITABLE
             and r["ground_truth"].lower() == "exploitable")
    fp = sum(1 for r in rows if r["verdict"] == VERDICT_EXPLOITABLE
             and r["ground_truth"].lower() != "exploitable")
    fn = gt_exp - tp
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / gt_exp if gt_exp else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if precision + recall else 0.0)
    confusion = {p: {"exploitable": 0, "not_exploitable": 0}
                 for p in ("positive", "safe", "abstain", "failed")}
    for r, t in zip(rows, tasks):
        gt = ("exploitable" if t["ground_truth"].lower() == "exploitable"
              else "not_exploitable")
        if r["scoring_outcome"] == "failed":
            confusion["failed"][gt] += 1
        elif r["scoring_outcome"] == "abstain":
            confusion["abstain"][gt] += 1
        elif r["verdict"] == VERDICT_EXPLOITABLE:
            confusion["positive"][gt] += 1
        else:
            confusion["safe"][gt] += 1
    metrics = {
        "schema": "vexbench-safety-aware/1",
        "baseline_name": manifest["baseline_name"],
        "run_id": manifest["run_id"],
        "generated_at_utc": utcnow(),
        "total": total,
        "outcomes": counts,
        "false_safe": false_safe,
        "correct_safe": counts["correct_safe"],
        "correct_exploitable": counts["correct_exploitable"],
        "abstain": counts["abstain"],
        "failed": counts["failed"],
        "denominators": {"total": total, "gt_exploitable": gt_exp,
                         "gt_safe": gt_safe},
        "false_safe_rate": false_safe / gt_exp if gt_exp else 0.0,
        "safe_clear_rate": (counts["correct_safe"] / gt_safe
                            if gt_safe else 0.0),
        "exploitable_recall": (counts["correct_exploitable"] / gt_exp
                               if gt_exp else 0.0),
        "inconclusive_rate": counts["abstain"] / total if total else 0.0,
        "completion_rate": ((total - counts["failed"]) / total
                            if total else 0.0),
        "status_accuracy": ((counts["correct_safe"] +
                             counts["correct_exploitable"]) / total
                            if total else 0.0),
        "status_correct": counts["correct_safe"] +
        counts["correct_exploitable"],
        "reason_correct": sum(1 for r in rows if r["reason_correct"]),
        "safety_aware_status": {"precision": precision, "recall": recall,
                                "f1": f1, "tp": tp, "fp": fp, "fn": fn},
        "confusion": confusion,
        "usage": {"llm_calls": llm_calls, "tool_calls": tool_calls,
                  "tokens": None,
                  "tokens_note": "no token accounting in deterministic "
                                 "profile"},
        "wall_seconds": {
            "total": round(sum(walls), 3),
            "mean": round(sum(walls) / len(walls), 3) if walls else None,
            "p95": round(sorted(walls)[int(0.95 * (len(walls) - 1))], 3)
            if walls else None,
        },
        "safety_gate": "pass" if false_safe == 0 else "BLOCKED",
    }

    # Compatibility view — official binary mapping. FAILED predictions are
    # missing/FAILED (wrong, FN for exploitable GT), never successful
    # not_exploitable: that is the official scorer's policy, kept distinct
    # from the legacy uncertain-projection.
    def pred_binary(r):
        if r["scoring_outcome"] == "failed":
            return "FAILED"
        return ("exploitable" if r["compatibility_category"] == "vulnerable"
                else "not_exploitable")

    bin_correct = sum(
        1 for r in rows
        if pred_binary(r) != "FAILED" and
        ((r["ground_truth_category"] == "vulnerable")
         == (pred_binary(r) == "exploitable")))
    classes = GT_CATEGORIES
    per_class = {}
    for c in classes:
        ctp = sum(1 for r in rows if r["compatibility_category"] == c
                  and r["ground_truth_category"] == c
                  and r["scoring_outcome"] != "failed")
        cfp = sum(1 for r in rows if r["compatibility_category"] == c
                  and r["ground_truth_category"] != c
                  and r["scoring_outcome"] != "failed")
        cfn = sum(1 for r in rows if r["ground_truth_category"] == c
                  and (r["compatibility_category"] != c
                       or r["scoring_outcome"] == "failed"))
        cp = ctp / (ctp + cfp) if ctp + cfp else 0.0
        cr = ctp / (ctp + cfn) if ctp + cfn else 0.0
        cf1 = 2 * cp * cr / (cp + cr) if cp + cr else 0.0
        per_class[c] = {"precision": cp, "recall": cr, "f1": cf1,
                        "support": ctp + cfn}
    compat = {
        "schema": "vexbench-compatibility/1",
        "note": "compatibility projection only — not a safety metric; "
                "uncertain predictions map to not_exploitable here but "
                "stay abstentions in safety-aware metrics",
        "failed_policy": "official: missing/failed prediction counts as "
                         "FAILED (wrong accuracy, FN for exploitable GT), "
                         "never as successful not_exploitable",
        "failed_count": counts["failed"],
        "accuracy": bin_correct / total if total else 0.0,
        "binary_precision": precision,
        "binary_recall": recall,
        "binary_f1": f1,
        "justification_macro_f1": round(
            sum(c["f1"] for c in per_class.values()) / len(per_class), 6),
        "per_class": per_class,
        "confusion_matrix": {
            "categories": classes,
            "rows": {c: {d: sum(1 for r in rows
                                if r["ground_truth_category"] == c
                                and ((r["compatibility_category"] == d)
                                     if r["scoring_outcome"] != "failed"
                                     else d == "FAILED"))
                         for d in classes + ["FAILED"]}
                     for c in classes},
        },
    }

    scoring_dir = os.path.join(out_dir, "scoring")
    os.makedirs(scoring_dir, exist_ok=True)
    with open(os.path.join(scoring_dir, "cases.jsonl"), "w",
              encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    disagreements = []
    review_needed = []
    for r, t in zip(rows, tasks):
        needs = (r["scoring_outcome"] not in
                 ("correct_safe", "correct_exploitable")
                 or not r["reason_correct"])
        if not needs:
            continue
        review_needed.append({"task_id": t["task_id"],
                              "scoring_outcome": r["scoring_outcome"],
                              "reason": "outcome not correct or "
                                        "reason_correct=false"})
        raw_dir = os.path.join(manifest["out"]["attempts"], t["task_id"],
                               "raw")
        refs = []
        for rel in (os.path.join(sanitize_case_name(t["task_id"]),
                                 "prediction.json"),
                    "metrics.json",
                    os.path.join("scoring", "cases.jsonl")):
            p = os.path.join(raw_dir, rel)
            if os.path.isfile(p):
                refs.append({"path": os.path.join(
                    "attempts", t["task_id"], "raw", rel),
                    "sha256": sha256_file(p)})
        disagreements.append({
            "run_id": manifest["run_id"],
            "task_id": t["task_id"],
            "comparator": "vexbench_ground_truth",
            "ground_truth": t["ground_truth"],
            "ground_truth_category": t["ground_truth_category"],
            "izyan_verdict": r["verdict"],
            "izyan_reasoning": (_read_attempt_prediction(raw_dir,
                                                       t["task_id"]) or {}
                                ).get("reason"),
            "status_correct": r["status_correct"],
            "reason_correct": r["reason_correct"],
            "scoring_outcome": r["scoring_outcome"],
            "agent_reasoning": None,
            "comparison_limitations": ["Agent modes not run in Task 2"],
            "artifact_refs": refs,
            "evidence_ids": [],
            "first_point_of_divergence": "not_available",
            "root_cause_difference": "not_available",
            "exploit_model_difference": "not_available",
            "taxonomy_ref": f"failure-taxonomy.jsonl#{t['task_id']}",
        })
    with open(os.path.join(scoring_dir, "disagreements.jsonl"), "w",
              encoding="utf-8") as f:
        for d in disagreements:
            f.write(json.dumps(d, ensure_ascii=False) + "\n")
    with open(os.path.join(scoring_dir, "review-needed.jsonl"), "w",
              encoding="utf-8") as f:
        for d in review_needed:
            f.write(json.dumps(d, ensure_ascii=False) + "\n")
    with open(os.path.join(scoring_dir, "disagreements.md"), "w",
              encoding="utf-8") as f:
        f.write("# Disagreements — vexbench_ground_truth\n\n")
        f.write("| task | GT | verdict | outcome | status | reason |\n")
        f.write("|---|---|---|---|---|---|\n")
        for d in disagreements:
            f.write(f"| `{d['task_id']}` | {d['ground_truth']} "
                    f"| {d['izyan_verdict']} | {d['scoring_outcome']} "
                    f"| {d['status_correct']} | {d['reason_correct']} |\n")

    atomic_write_json(os.path.join(out_dir, "metrics.json"), metrics)
    atomic_write_json(os.path.join(out_dir, "compatibility-metrics.json"),
                      compat)

    provenance = {
        "schema_version": 1,
        "run_id": manifest["run_id"],
        "baseline_name": manifest["baseline_name"],
        "run_finished_at_utc": utcnow(),
        "manifest_sha256": sha256_file(manifest_path),
        "izyan": manifest["izyan"],
        "worktree": manifest["worktree"],
        "dataset": manifest["dataset"],
        "go": manifest["go"],
        "govulncheck": manifest["govulncheck"],
        "govulncheck_db_mode": "live_observed",
        "adapter_version": ADAPTER_VERSION,
        "orchestrator_version": ORCHESTRATOR_VERSION,
        "orchestrator_sha256": manifest["orchestrator_sha256"],
        "profile": manifest["profile"],
        "execution_mode": manifest["execution_mode"],
        "workers": manifest["workers"],
        "cli_j": manifest["cli_j"],
        "env": manifest["env"],
        "host_os": manifest["profile"]["host_os"],
        "host_arch": manifest["profile"]["host_arch"],
        "target_goos": manifest["profile"]["target_goos"],
        "target_goarch": manifest["profile"]["target_goarch"],
        "cgo_enabled": manifest["profile"]["cgo_enabled"],
        "build_tags": manifest["profile"]["build_tags"],
        "llm_calls": llm_calls,
        "tokens": 0,
        "llm_cost": 0,
        "model": None,
        "model_endpoint_revision": None,
        "prompt_version": None,
        "snapshots": manifest["snapshot_refs"],
        "resume_episodes": _resume_episodes(out_dir),
        "osv_fetches": _osv_fetch_index(manifest, tasks),
        "limitations": [
            "govulncheck DB identity is live_observed per-case, not a "
            "frozen snapshot",
            "child go/govulncheck memory is not bounded by --mem-limit",
            "interrupted first attempts are recorded failed, never rerun",
        ],
    }
    atomic_write_json(os.path.join(out_dir, "provenance.json"), provenance)

    if freeze:
        checksums = {}
        for dirpath, _dirs, names in os.walk(out_dir):
            for name in names:
                p = os.path.join(dirpath, name)
                rel = os.path.relpath(p, out_dir)
                if rel in ("raw-checksums.json", "baseline-frozen.json"):
                    continue
                try:
                    checksums[rel] = sha256_file(p)
                except OSError:
                    continue
        atomic_write_json(os.path.join(out_dir, "raw-checksums.json"),
                          {"files": checksums,
                           "generated_at_utc": utcnow()})
        atomic_write_json(os.path.join(out_dir, "baseline-frozen.json"), {
            "run_id": manifest["run_id"],
            "baseline_name": manifest["baseline_name"],
            "frozen_at_utc": utcnow(),
            "manifest_sha256": sha256_file(manifest_path),
            "raw_file_count": len(checksums),
        })
        for sub in ("attempts", "ledger"):
            _chmod_tree_readonly(os.path.join(out_dir, sub))
        os.chmod(manifest_path, 0o444)
        os.chmod(os.path.join(out_dir, "acquisition.copy.json"), 0o444)

    eprint(f"report: {total} cases — false_safe={false_safe} "
           f"clear={counts['correct_safe']}/{gt_safe} "
           f"recall={counts['correct_exploitable']}/{gt_exp} "
           f"abstain={counts['abstain']} failed={counts['failed']}")
    return 0


def _resume_episodes(out_dir):
    ev = os.path.join(out_dir, "run-events.jsonl")
    if not os.path.isfile(ev):
        return []
    out = []
    with open(ev, encoding="utf-8") as f:
        for line in f:
            if '"resume' in line or '"signal"' in line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return out


def _osv_fetch_index(manifest, tasks):
    """Index recorded OSV fetch logs across attempts — proof the bytes
    used were captured, per task."""
    out = {}
    for t in tasks:
        log = os.path.join(manifest["out"]["attempts"], t["task_id"],
                           "raw", "provenance", "osv-fetches.jsonl")
        if not os.path.isfile(log):
            out[t["task_id"]] = {"records": 0, "present": False}
            continue
        n = 0
        chosen = None
        with open(log, encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                n += 1
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if rec.get("chosen"):
                    chosen = rec.get("body_sha256")
        out[t["task_id"]] = {"records": n, "present": True,
                             "log_sha256": sha256_file(log),
                             "chosen_sha256": chosen}
    return out


def _chmod_tree_readonly(root):
    if not os.path.isdir(root):
        return
    for dirpath, dirs, names in os.walk(root):
        for name in names + dirs:
            p = os.path.join(dirpath, name)
            try:
                st = os.lstat(p)
                if not stat.S_ISLNK(st.st_mode):
                    os.chmod(p, st.st_mode & ~0o222)
            except OSError:
                continue
    os.chmod(root, 0o555)


# --------------------------------------------------------------------------
# validate-review


def validate_review(*, manifest_path):
    manifest = load_json(manifest_path)
    out_dir = manifest["out"]["dir"]
    frozen_path = os.path.join(out_dir, "baseline-frozen.json")
    if not os.path.isfile(frozen_path):
        fail("baseline-frozen.json missing — run `report` (freeze) first")
    frozen = load_json(frozen_path)
    tax_path = os.path.join(out_dir, "scoring", "failure-taxonomy.jsonl")
    if not os.path.isfile(tax_path):
        fail(f"taxonomy file missing: {tax_path}")
    cases_path = os.path.join(out_dir, "scoring", "cases.jsonl")
    cases = {}
    with open(cases_path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                r = json.loads(line)
                cases[r["task_id"]] = r

    required = {tid for tid, r in cases.items()
                if r["scoring_outcome"] not in
                ("correct_safe", "correct_exploitable")
                or not r["reason_correct"]}
    rows = {}
    errors = []
    with open(tax_path, encoding="utf-8") as f:
        for ln, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as e:
                errors.append(f"{tax_path}:{ln}: invalid JSON: {e}")
                continue
            tid = rec.get("task_id")
            if tid in rows:
                errors.append(f"{tid}: duplicate taxonomy record")
            rows[tid] = rec

    for tid in sorted(required - set(rows)):
        errors.append(f"{tid}: review-required case has no taxonomy record")
    for tid in sorted(set(rows) - required):
        errors.append(f"{tid}: taxonomy record for a non-review case")

    def digest_of(rel):
        p = os.path.join(out_dir, rel)
        return sha256_file(p) if os.path.isfile(p) else None

    for tid in sorted(set(rows) & required):
        rec = rows[tid]
        where = f"{tid}"
        if rec.get("category") not in TAXONOMY_CATEGORIES:
            errors.append(f"{where}: category {rec.get('category')!r} "
                          "not in the fixed enum")
        if rec.get("disposition") not in TAXONOMY_DISPOSITIONS:
            errors.append(f"{where}: disposition "
                          f"{rec.get('disposition')!r} not in enum")
        for fld in ("run_id", "task_id", "scoring_outcome", "reviewer",
                    "reviewed_at_utc", "approved_by", "explanation",
                    "first_point_of_divergence",
                    "needed_information_or_general_change"):
            if not rec.get(fld):
                errors.append(f"{where}: missing {fld}")
        if rec.get("category") == "OTHER" and not rec.get("explanation"):
            errors.append(f"{where}: OTHER requires an explanation")
        case = cases.get(tid) or {}
        if rec.get("scoring_outcome") != case.get("scoring_outcome"):
            errors.append(f"{where}: scoring_outcome "
                          f"{rec.get('scoring_outcome')!r} != scorer row "
                          f"{case.get('scoring_outcome')!r}")
        if (rec.get("category") == "LLM_REASONING_ERROR"
                and not (case.get("llm_calls") or 0)):
            errors.append(f"{where}: LLM_REASONING_ERROR on a run with "
                          "llm_calls=0 — misattribution")
        sha = rec.get("baseline_manifest_sha256")
        if sha and sha != frozen["manifest_sha256"]:
            errors.append(f"{where}: baseline_manifest_sha256 does not "
                          "match the frozen manifest")
        for refkey in ("prediction_ref", "case_ref", "report_ref"):
            ref = rec.get(refkey)
            if not ref:
                continue
            if isinstance(ref, dict):
                rel, want = ref.get("path"), ref.get("sha256")
                if rel is None:
                    continue
            else:
                rel, want = ref, None
            got = digest_of(rel)
            if got is None:
                errors.append(f"{where}: {refkey} path {rel!r} does not "
                              "exist under OUT")
            elif want and want != got:
                errors.append(f"{where}: {refkey} digest mismatch {rel!r}")
        evs = rec.get("evidence") or []
        if not isinstance(evs, list):
            errors.append(f"{where}: evidence is not a list")
            continue
        for i, ev in enumerate(evs):
            if not isinstance(ev, dict) or not ev.get("path"):
                errors.append(f"{where}: evidence[{i}] lacks path")
                continue
            if digest_of(ev["path"]) is None:
                errors.append(f"{where}: evidence[{i}] path "
                              f"{ev['path']!r} missing")
    for e in errors:
        eprint(f"validate-review: {e}")
    if errors:
        eprint(f"validate-review: {len(errors)} error(s)")
        return 1
    eprint(f"validate-review: OK — {len(required)} review-required "
           "case(s) covered")
    return 0


# --------------------------------------------------------------------------
# CLI


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="vexbench_baseline.py", description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("acquire", help="fetch pinned dataset + snapshots")
    a.add_argument("--worktree", required=True)
    a.add_argument("--benchmark-dir", required=True)
    a.add_argument("--benchmark-sha", default=DEFAULT_PIN)
    a.add_argument("--repos-dir", required=True)
    a.add_argument("--manifest", required=True)
    a.add_argument("--fetch-timeout-seconds", type=int, default=1800)

    p = sub.add_parser("preflight", help="resource gate + frozen manifest")
    p.add_argument("--worktree", required=True)
    p.add_argument("--benchmark-dir", required=True)
    p.add_argument("--repos-dir", required=True)
    p.add_argument("--acquisition", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--izyan", required=True)
    p.add_argument("--analysis-go", required=True)
    p.add_argument("--mem-limit", default="8GiB")
    p.add_argument("--workers", type=int, default=3)
    p.add_argument("--case-timeout-seconds", type=int, default=7200)
    p.add_argument("--cache-root", default=None)

    r = sub.add_parser("run", help="case-isolated subprocess execution")
    r.add_argument("--manifest", required=True)
    r.add_argument("--resume", action="store_true")
    r.add_argument("--workers", type=int, default=None,
                   help="guard only — must equal the frozen manifest value")

    rep = sub.add_parser("report", help="offline join + aggregate + freeze")
    rep.add_argument("--manifest", required=True)
    rep.add_argument("--no-freeze", action="store_true")

    v = sub.add_parser("validate-review",
                       help="check failure-taxonomy coverage/schema")
    v.add_argument("--manifest", required=True)

    args = ap.parse_args(argv)
    try:
        if args.cmd == "acquire":
            return acquire(
                worktree=args.worktree, benchmark_dir=args.benchmark_dir,
                benchmark_sha=args.benchmark_sha, repos_dir=args.repos_dir,
                manifest_path=args.manifest,
                fetch_timeout_seconds=args.fetch_timeout_seconds)
        if args.cmd == "preflight":
            return preflight(
                worktree=args.worktree, benchmark_dir=args.benchmark_dir,
                repos_dir=args.repos_dir, acquisition=args.acquisition,
                out=args.out, izyan=args.izyan,
                analysis_go=args.analysis_go, mem_limit=args.mem_limit,
                workers=args.workers,
                case_timeout_seconds=args.case_timeout_seconds,
                cache_root=args.cache_root)
        if args.cmd == "run":
            return run(manifest_path=args.manifest, resume=args.resume,
                       workers_override=args.workers)
        if args.cmd == "report":
            return report(manifest_path=args.manifest,
                          freeze=not args.no_freeze)
        if args.cmd == "validate-review":
            return validate_review(manifest_path=args.manifest)
    except BaselineError as e:
        eprint(f"error: {e}")
        return 1
    except KeyboardInterrupt:
        eprint("interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())

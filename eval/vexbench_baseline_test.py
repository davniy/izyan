#!/usr/bin/env python3
"""Synthetic fixture tests for eval/vexbench_baseline.py.

Run:  python3 -m unittest eval.vexbench_baseline_test -v
or:   python3 eval/vexbench_baseline_test.py

Every fixture is synthetic — no real VEX-Bench tasks, no network, no
analysis. Git is used only for local `git init/commit` fixtures.
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vexbench_baseline as vb  # noqa: E402

SHADOW = os.path.realpath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), ".."))

PIN = "a" * 40


def sha(i):
    return format(i, "040x")


def write(path, data, mode=0o644):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(data)
    os.chmod(path, mode)


def make_tasks(path, n_go, n_other=0, snapshots=0, repos=0,
               cves=0, gt=None):
    """Synthetic VEX-Bench JSONL. Go records alternate between two repos
    that share a snapshot (dedup coverage) before cycling new ones."""
    rows = []
    for i in range(n_go):
        repo = f"https://github.com/owner{i % 15}/repo{i % 15}"
        snap = sha(i if not snapshots else (i % snapshots))
        gtcat = gt[i % len(gt)] if gt else "code_not_reachable"
        rows.append({
            "repo_url": repo, "commit_sha": snap,
            "task_id": f"task-{i:02d}-CVE-{9000 + i}",
            "cve_id": f"CVE-2099-{9000 + i}",
            "ground_truth": ("exploitable" if gtcat == "vulnerable"
                             else "not_exploitable"),
            "ground_truth_category": gtcat,
            "metadata": {"language": "go",
                         "pr_url": f"https://example.com/pr/{i}"},
        })
    for i in range(n_other):
        rows.append({
            "repo_url": "https://github.com/x/java", "commit_sha": sha(100 + i),
            "task_id": f"java-{i}", "cve_id": f"CVE-2099-{100 + i}",
            "ground_truth": "not_exploitable",
            "ground_truth_category": "code_not_present",
            "metadata": {"language": "java", "pr_url": "x"},
        })
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    return rows


def fake_cloner(bench, pin, timeout):
    """Dataset clone fake: create a local git repo holding the JSONL and
    commit it; the recorded pin is whatever the caller supplied — tests
    pass the real commit they made."""
    if os.path.isdir(os.path.join(bench, ".git")):
        return
    subprocess.run(["git", "-C", bench, "init", "-q"], check=True)
    subprocess.run(["git", "-C", bench, "-c", "user.email=t@t",
                    "-c", "user.name=t", "commit", "-qm", "x",
                    "--allow-empty"], check=True)


def git_init_commit(dirpath):
    subprocess.run(["git", "-C", dirpath, "init", "-q"], check=True)
    subprocess.run(["git", "-C", dirpath, "-c", "user.email=t@t",
                    "-c", "user.name=t", "commit", "-qm", "x",
                    "--allow-empty"], check=True)
    return subprocess.run(["git", "-C", dirpath, "rev-parse", "HEAD"],
                          capture_output=True, text=True).stdout.strip()


def fake_fetcher(tmpdir, repo_url, sha, timeout):
    """Writes a deterministic tree instead of git fetch. No .git — the
    .git-removal/HEAD-check path is covered by the real-fetcher test."""
    write(os.path.join(tmpdir, "go.mod"),
          f"module example.com/{sha[:8]}\n\ngo 1.21\n")
    write(os.path.join(tmpdir, "main.go"),
          f"package main // {repo_url}@{sha}\n")
    write(os.path.join(tmpdir, "vendor", "modules.txt"),
          "# example.com/x v0.0.0\n")


class AcqFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(self._rmtree)
        self.bench = os.path.join(self.tmp, "bench")
        self.repos = os.path.join(self.tmp, "repos")
        self.mdir = os.path.join(self.tmp, "ctl")
        os.makedirs(os.path.join(self.bench, "benchmark", "tasks"))
        self.tasks_path = os.path.join(self.bench, "benchmark", "tasks",
                                       "vex_bench.jsonl")

    def _rmtree(self):
        subprocess.run(["chmod", "-R", "u+w", self.tmp],
                       capture_output=True)
        subprocess.run(["rm", "-rf", self.tmp], capture_output=True)

    def acquire_kwargs(self, pin, **over):
        kw = dict(
            worktree=SHADOW, benchmark_dir=self.bench, benchmark_sha=pin,
            repos_dir=self.repos,
            manifest_path=os.path.join(self.mdir, "acquisition.json"),
            fetch_timeout_seconds=60,
            dataset_cloner=lambda b, p, t: None,  # bench already committed
            snapshot_fetcher=fake_fetcher,
            expected={
                "tasks": 4, "snapshots": 3, "repos": 2, "cves": 4,
                "gt_vulnerable": 1, "gt_code_not_reachable": 1,
                "gt_code_not_present": 1, "gt_requires_configuration": 1,
            })
        kw.update(over)
        return kw

    def small_counts(self):
        # Dedup is on (repo_url, commit_sha) pairs: tasks 0-2 all sit in
        # owner0/repo0 but only 0,1 share sha(0); task 3 is a second repo
        # → 3 snapshots across 2 repos.
        rows = []
        gt = ["vulnerable", "code_not_reachable", "code_not_present",
              "requires_configuration"]
        snap_of = {0: sha(0), 1: sha(0), 2: sha(2), 3: sha(3)}
        repo_of = {0: 0, 1: 0, 2: 0, 3: 1}
        for i in range(4):
            repo = f"https://github.com/owner{repo_of[i]}/repo{repo_of[i]}"
            rows.append({
                "repo_url": repo, "commit_sha": snap_of[i],
                "task_id": f"task-{i}-CVE-{i}",
                "cve_id": f"CVE-2099-{i}",
                "ground_truth": ("exploitable" if gt[i] == "vulnerable"
                                 else "not_exploitable"),
                "ground_truth_category": gt[i],
                "metadata": {"language": "go",
                             "pr_url": f"https://example.com/pr/{i}"},
            })
        rows.append({  # non-Go noise — must be filtered out
            "repo_url": "https://github.com/x/java", "commit_sha": sha(77),
            "task_id": "java-0", "cve_id": "CVE-2099-77",
            "ground_truth": "not_exploitable",
            "ground_truth_category": "code_not_present",
            "metadata": {"language": "Java", "pr_url": "x"},
        })
        with open(self.tasks_path, "w") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
        return git_init_commit(self.bench)

    def test_acquire_filters_dedups_and_records(self):
        pin = self.small_counts()
        rc = vb.acquire(**self.acquire_kwargs(pin))
        self.assertEqual(rc, 0)
        manifest = vb.load_json(os.path.join(self.mdir, "acquisition.json"))
        self.assertEqual(len(manifest["tasks"]), 4)
        self.assertEqual(len(manifest["snapshots"]), 3)
        # Labels never enter the control-plane task list.
        for t in manifest["tasks"]:
            self.assertNotIn("ground_truth", t)
            self.assertNotIn("pr_url", t)
        # Snapshots are read-only, .git removed, layout owner/repo/sha.
        for key, rec in manifest["snapshots"].items():
            self.assertEqual(rec["status"], "ready")
            self.assertTrue(os.path.isdir(rec["path"]))
            self.assertFalse(os.path.exists(
                os.path.join(rec["path"], ".git")))
            self.assertEqual(rec["path"],
                             os.path.join(self.repos, key))
            for _rel, _k, p, st in vb.iter_tree(rec["path"]):
                self.assertFalse(st.st_mode & 0o222, p)
            self.assertTrue(os.path.isfile(
                os.path.join(self.mdir, rec["integrity_ref"])))
        # The scorer-side subset keeps raw bytes (labels) outside repos.
        subset = os.path.join(self.mdir, "go-tasks.jsonl")
        self.assertTrue(os.path.isfile(subset))
        with open(subset) as f:
            lines = [json.loads(l) for l in f if l.strip()]
        self.assertEqual(len(lines), 4)
        self.assertTrue(all(l["metadata"]["language"] == "go"
                            for l in lines))
        self.assertFalse(subset.startswith(os.path.realpath(self.repos)))

    def test_acquire_idempotent_via_manifest_digest(self):
        pin = self.small_counts()
        vb.acquire(**self.acquire_kwargs(pin))
        calls = []

        def counting(tmpdir, url, s, timeout):
            calls.append(s)
            fake_fetcher(tmpdir, url, s, timeout)

        rc = vb.acquire(**self.acquire_kwargs(
            pin, snapshot_fetcher=counting))
        self.assertEqual(rc, 0)
        self.assertEqual(calls, [], "ready digest-verified snapshots "
                                    "must not be re-fetched")

    def test_acquire_incomplete_download_not_ready(self):
        pin = self.small_counts()
        crashed = {"fired": False}

        def flaky(tmpdir, url, s, timeout):
            if s == sha(2) and not crashed["fired"]:
                crashed["fired"] = True
                write(os.path.join(tmpdir, "partial.go"), "x")
                raise vb.BaselineError("simulated interrupted download")
            fake_fetcher(tmpdir, url, s, timeout)

        rc = vb.acquire(**self.acquire_kwargs(pin,
                                              snapshot_fetcher=flaky))
        self.assertEqual(rc, 1)
        manifest = vb.load_json(os.path.join(self.mdir, "acquisition.json"))
        bad = manifest["snapshots"]["owner0/repo0/" + sha(2)]
        self.assertEqual(bad["status"], "failed")
        self.assertFalse(os.path.exists(
            os.path.join(self.repos, "owner0", "repo0", sha(2))))
        self.assertFalse(os.path.exists(
            os.path.join(self.repos, "owner0", "repo0",
                         sha(2) + ".acquiring")))
        # Retry recovers only the missing snapshot.
        rc = vb.acquire(**self.acquire_kwargs(pin))
        self.assertEqual(rc, 0)
        self.assertTrue(all(r["status"] == "ready"
                            for r in vb.load_json(
                                os.path.join(self.mdir, "acquisition.json"))
                            ["snapshots"].values()))

    def test_acquire_stray_final_dir_is_error_not_overwrite(self):
        pin = self.small_counts()
        stray = os.path.join(self.repos, "owner0", "repo0", sha(0))
        os.makedirs(stray)
        write(os.path.join(stray, "leftover"), "partial")
        rc = vb.acquire(**self.acquire_kwargs(pin))
        self.assertEqual(rc, 1)
        self.assertTrue(os.path.isfile(os.path.join(stray, "leftover")))

    def test_acquire_rejects_short_sha_and_bad_counts(self):
        make_tasks(self.tasks_path, n_go=4, n_other=0)
        # Corrupt one sha to 8 chars.
        with open(self.tasks_path) as f:
            lines = f.read().replace(sha(0), "deadbeef", 1)
        write(self.tasks_path, lines)
        pin = git_init_commit(self.bench)
        with self.assertRaises(vb.BaselineError):
            vb.acquire(**self.acquire_kwargs(pin))
        # Wrong expected counts fail.
        pin = self.small_counts()
        kw = self.acquire_kwargs(pin)
        kw["expected"]["tasks"] = 5
        with self.assertRaises(vb.BaselineError):
            vb.acquire(**kw)

    def test_acquire_real_git_fetcher(self):
        """The real fetcher over a local git clone: HEAD == sha verified,
        .git removed, files preserved. All tasks share one repo+snapshot
        so the whole fixture goes through git_snapshot_fetcher."""
        src = os.path.join(self.tmp, "srcrepo")
        os.makedirs(src)
        write(os.path.join(src, "main.go"), "package main\n")
        write(os.path.join(src, "go.mod"),
              "module example.com/x\n\ngo 1.21\n")
        git_init_commit(src)
        subprocess.run(["git", "-C", src, "-c", "user.email=t@t",
                        "-c", "user.name=t", "add", "-A"], check=True)
        subprocess.run(["git", "-C", src, "-c", "user.email=t@t",
                        "-c", "user.name=t", "commit", "-qm", "add"],
                       check=True)
        sha_src = subprocess.run(
            ["git", "-C", src, "rev-parse", "HEAD"],
            capture_output=True, text=True).stdout.strip()
        gt = ["vulnerable", "code_not_reachable", "code_not_present",
              "requires_configuration"]
        rows = [{
            "repo_url": "https://github.com/local/one",
            "commit_sha": sha_src,
            "task_id": f"task-{i}-CVE-{i}",
            "cve_id": f"CVE-2099-{i}",
            "ground_truth": ("exploitable" if gt[i] == "vulnerable"
                             else "not_exploitable"),
            "ground_truth_category": gt[i],
            "metadata": {"language": "go", "pr_url": "x"},
        } for i in range(4)]
        with open(self.tasks_path, "w") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
        pin = git_init_commit(self.bench)

        def local_fetcher(tmpdir, repo_url, s, timeout):
            vb.git_snapshot_fetcher(tmpdir, src, s, timeout)

        rc = vb.acquire(**self.acquire_kwargs(
            pin, snapshot_fetcher=local_fetcher,
            expected={"tasks": 4, "snapshots": 1, "repos": 1, "cves": 4,
                      "gt_vulnerable": 1, "gt_code_not_reachable": 1,
                      "gt_code_not_present": 1,
                      "gt_requires_configuration": 1}))
        self.assertEqual(rc, 0, vb.load_json(
            os.path.join(self.mdir, "acquisition.json"))["errors"])
        snap = os.path.join(self.repos, "local", "one", sha_src)
        self.assertTrue(os.path.isfile(os.path.join(snap, "main.go")))
        self.assertFalse(os.path.exists(os.path.join(snap, ".git")))


class ParseParity(unittest.TestCase):
    def test_parse_repo_url(self):
        cases = [
            ("https://github.com/a/b", ("a", "b")),
            ("https://github.com/a/b.git", ("a", "b")),
            ("https://github.com/a/b/", ("a", "b")),
            ("git@github.com:a/b", ("a", "b")),
            ("a/b", ("a", "b")),
        ]
        for raw, want in cases:
            self.assertEqual(vb.parse_repo_url(raw), want)
        for raw in ("https://github.com/a", "a/b/c", "", "/b"):
            with self.assertRaises(vb.BaselineError):
                vb.parse_repo_url(raw)

    def test_classify_truth_table(self):
        t_exp = {"ground_truth": "exploitable"}
        t_safe = {"ground_truth": "not_exploitable"}
        self.assertEqual(
            vb.classify_outcome(t_exp, "EXPLOITABLE", "vulnerable"),
            "correct_exploitable")
        self.assertEqual(
            vb.classify_outcome(t_exp, "NOT_AFFECTED", "code_not_present"),
            "wrong")  # false-safe
        self.assertEqual(
            vb.classify_outcome(t_safe, "NOT_AFFECTED", "x"),
            "correct_safe")
        self.assertEqual(
            vb.classify_outcome(t_safe, "INCONCLUSIVE", "uncertain"),
            "abstain")
        self.assertEqual(
            vb.classify_outcome(t_exp, "INCONCLUSIVE", "uncertain"),
            "abstain")
        self.assertEqual(vb.classify_outcome(t_safe, "", "", failed=True),
                         "failed")
        self.assertEqual(vb.classify_outcome(t_safe, "GARBAGE", "x"),
                         "failed")  # malformed verdict is never safe

    def test_sanitize_case_name(self):
        self.assertEqual(vb.sanitize_case_name("a-b_C-D9"), "a-b_C-D9")
        self.assertEqual(vb.sanitize_case_name("a b/c:d"), "a_b_c_d")

    def test_t1_content_hash_parity(self):
        """Golden digest from internal/repository.ContentHash over an
        identical fixture tree — guards the Python port byte-for-byte."""
        GOLDEN = ("b92f6f467daa575316f2d1ceefda5ab0641e1f3fbe5c1c39644"
                  "464a9835c9509")
        root = tempfile.mkdtemp()
        self.addCleanup(lambda: subprocess.run(
            ["rm", "-rf", root], capture_output=True))
        write(os.path.join(root, "a.txt"), "hello\n")
        os.mkdir(os.path.join(root, "dir"))
        write(os.path.join(root, "dir", "run.sh"), "#!/bin/sh\ntrue\n",
              mode=0o755)
        os.symlink("../a.txt", os.path.join(root, "dir", "link"))
        self.assertEqual(vb.t1_content_hash(root), GOLDEN)

    def test_contained_and_replace_preflight(self):
        root = tempfile.mkdtemp()
        self.addCleanup(lambda: subprocess.run(
            ["rm", "-rf", root], capture_output=True))
        write(os.path.join(root, "go.mod"),
              "module x\n\ngo 1.21\n\nreplace a => ./in\n\nuse (\n\t./in2\n)\n")
        os.mkdir(os.path.join(root, "in"))
        os.mkdir(os.path.join(root, "in2"))
        vb.check_path_replacements(root)  # internal targets pass
        vb.verify_contained(root)

        write(os.path.join(root, "go.mod"),
              "module x\n\nreplace a => ../escape\n")
        with self.assertRaises(vb.BaselineError):
            vb.check_path_replacements(root)

        write(os.path.join(root, "go.mod"), "module x\n\ngo 1.21\n")
        outside = tempfile.mkdtemp()
        self.addCleanup(lambda: subprocess.run(
            ["rm", "-rf", outside], capture_output=True))
        os.symlink(outside, os.path.join(root, "escape-link"))
        with self.assertRaises(vb.BaselineError):
            vb.verify_contained(root)

    def test_adapter_version_matches_go_source(self):
        src = os.path.join(SHADOW, "cmd", "izyan", "vexprov.go")
        m = None
        with open(src) as f:
            for line in f:
                if 'AdapterVersion: vexAdapterVersion' in line:
                    pass
                if 'vexAdapterVersion = ' in line:
                    m = line
        self.assertIsNotNone(m, "vexAdapterVersion const not found")
        self.assertIn(f'"{vb.ADAPTER_VERSION}"', m,
                      "ADAPTER_VERSION drifted from cmd/izyan/vexprov.go")


class FakeProc:
    """Popen stand-in: exit code fixed, polls instantly, records group
    kills. Optionally materializes a raw packet on construction."""

    def __init__(self, argv, raw_dir=None, tid=None, outcome="ok",
                 exit_code=0, **_kw):
        self.argv = argv
        self.pid = os.getpid() ^ 0x55AA  # fake but unique-ish
        self.returncode = None
        self._exit = exit_code
        self.killed = []
        if raw_dir and tid:
            self._materialize(raw_dir, tid, outcome)

    def _materialize(self, raw_dir, tid, outcome):
        case_dir = os.path.join(raw_dir, tid)
        os.makedirs(os.path.join(case_dir, "advisory"), exist_ok=True)
        env = {"task_id": tid, "requested_cve": "CVE-2099-1",
               "terminal_state": "COMPLETED",
               "scoring_outcome": "correct_safe",
               "compatibility_category": "code_not_present",
               "wall_seconds": 1.5, "llm_calls": 0, "tool_calls": 3,
               "osv_fetches": 1}
        if outcome == "corrupt_pred":
            write(os.path.join(case_dir, "prediction.json"),
                  "{not json")
        elif outcome == "no_pred":
            pass
        else:
            env["verdict"] = "NOT_AFFECTED"
            write(os.path.join(case_dir, "prediction.json"),
                  json.dumps(env))
        write(os.path.join(raw_dir, "metrics.json"), json.dumps(
            {"total": 1}))
        os.makedirs(os.path.join(raw_dir, "scoring"), exist_ok=True)
        write(os.path.join(raw_dir, "scoring", "cases.jsonl"),
              json.dumps({"task_id": tid}) + "\n")
        os.makedirs(os.path.join(raw_dir, "provenance"), exist_ok=True)
        write(os.path.join(raw_dir, "provenance", "osv-fetches.jsonl"),
              json.dumps({"task_id": tid, "requested_id": "CVE-2099-1",
                          "ok": True, "chosen": True,
                          "body_sha256": "0" * 64}) + "\n")

    def poll(self):
        if self.returncode is None:
            self.returncode = self._exit
        return self.returncode

    def wait(self, timeout=None):
        self.returncode = self._exit
        return self._exit


def fake_popen_factory(outcome="ok"):
    def factory(argv, **_kw):
        tid = argv[argv.index("--case") + 1]
        raw_dir = argv[argv.index("--out") + 1]
        return FakeProc(argv, raw_dir=raw_dir, tid=tid, outcome=outcome)
    return factory


def never_popen_factory():
    class NeverDone(FakeProc):
        def poll(self):
            return None
    def factory(argv, **_kw):
        tid = argv[argv.index("--case") + 1]
        raw_dir = argv[argv.index("--out") + 1]
        return NeverDone(argv, raw_dir=raw_dir, tid=tid)
    return factory


def build_run_fixture(tc, n_tasks=3, workers=3, timeout=7200):
    """Acquire+preflight a synthetic fixture; returns manifest path."""
    tmp = tc.tmp
    bench = os.path.join(tmp, "bench")
    repos = os.path.join(tmp, "repos")
    mdir = os.path.join(tmp, "ctl")
    out = os.path.join(tmp, "out")
    os.makedirs(os.path.join(bench, "benchmark", "tasks"), exist_ok=True)
    tasks_path = os.path.join(bench, "benchmark", "tasks",
                              "vex_bench.jsonl")
    rows = []
    for i in range(n_tasks):
        rows.append({
            "repo_url": f"https://github.com/owner{i}/repo{i}",
            "commit_sha": sha(i),
            "task_id": f"task-{i}-CVE-{i}",
            "cve_id": f"CVE-2099-{i}",
            "ground_truth": "not_exploitable",
            "ground_truth_category": "code_not_present",
            "metadata": {"language": "go", "pr_url": "x"},
        })
    with open(tasks_path, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    pin = git_init_commit(bench)
    vb.acquire(worktree=SHADOW, benchmark_dir=bench, benchmark_sha=pin,
               repos_dir=repos,
               manifest_path=os.path.join(mdir, "acq.json"),
               fetch_timeout_seconds=60,
               dataset_cloner=lambda b, p, t: None,
               snapshot_fetcher=fake_fetcher,
               expected={"tasks": n_tasks, "snapshots": n_tasks,
                         "repos": n_tasks, "cves": n_tasks,
                         "gt_code_not_present": n_tasks})
    # Fake toolchain: bin/go + bin/govulncheck + izyan executable.
    bindir = os.path.join(tmp, "bin")
    write(os.path.join(bindir, "go"),
          '#!/bin/sh\nif [ "$1" = "version" ]; then '
          'echo "go version go1.26.1 darwin/arm64"; exit 0; fi\n'
          'exit 0\n', mode=0o755)
    write(os.path.join(bindir, "govulncheck"),
          '#!/bin/sh\nif [ "$1" = "-version" ]; then '
          'echo "Scanner: govulncheck@v9.9.9"; exit 0; fi\n'
          'exit 0\n', mode=0o755)
    izyan_bin = os.path.join(tmp, "bin", "izyan-baseline")
    write(izyan_bin, "#!/bin/sh\nexit 0\n", mode=0o755)
    env = dict(os.environ)
    env["PATH"] = bindir + os.pathsep + env.get("PATH", "")
    vb.preflight(worktree=SHADOW, benchmark_dir=bench, repos_dir=repos,
                 acquisition=os.path.join(mdir, "acq.json"), out=out,
                 izyan=izyan_bin, analysis_go="1.26.1",
                 mem_limit="512MiB", workers=workers,
                 case_timeout_seconds=timeout,
                 disk_free=lambda p: 100 << 30,
                 ram_bytes=lambda: 96 << 30,
                 ambient_env=env)
    return os.path.join(out, "run-manifest.json")


class PreflightFixture(AcqFixture):
    def test_preflight_writes_manifest_and_pending_ledger(self):
        mpath = build_run_fixture(self)
        m = vb.load_json(mpath)
        self.assertEqual(m["execution_mode"], "case_isolated")
        self.assertEqual(m["workers"], 3)
        self.assertEqual(m["cli_j"], 1)
        self.assertEqual(m["govulncheck"]["sha256"],
                         vb.sha256_file(m["govulncheck"]["path"]))
        self.assertEqual(m["env"]["GOWORK"], "off")
        self.assertEqual(m["env"]["CGO_ENABLED"], "0")
        self.assertEqual(m["env"]["GOENV"], "off")
        self.assertEqual(m["env"]["GOTOOLCHAIN"], "go1.26.1")
        self.assertNotIn("VA_FOO", m["env"])
        ledger = os.path.join(m["out"]["ledger"])
        for t in m["tasks"]:
            rec = vb.load_json(os.path.join(
                ledger, t["task_id"] + ".json"))
            self.assertEqual(rec["state"], "pending")
            self.assertIn("snapshot_content_hash", rec["fingerprint"])

    def test_preflight_disk_gate(self):
        tmp = self.tmp
        bench = os.path.join(tmp, "b2")
        os.makedirs(os.path.join(bench, "benchmark", "tasks"))
        rows = [{"repo_url": "https://github.com/o/r", "commit_sha": sha(0),
                 "task_id": "t0", "cve_id": "CVE-1",
                 "ground_truth": "x", "ground_truth_category": "x",
                 "metadata": {"language": "go"}}]
        with open(os.path.join(bench, "benchmark", "tasks",
                               "vex_bench.jsonl"), "w") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
        pin = git_init_commit(bench)
        acq = os.path.join(tmp, "ctl2", "acq.json")
        with self.assertRaises(vb.BaselineError):
            vb.acquire(worktree=SHADOW, benchmark_dir=bench,
                       benchmark_sha=pin,
                       repos_dir=os.path.join(tmp, "r2"),
                       manifest_path=acq, fetch_timeout_seconds=60,
                       dataset_cloner=lambda b, p, t: None,
                       snapshot_fetcher=fake_fetcher,
                       expected={"tasks": 99})  # mismatch → aborts anyway
        vb.acquire(worktree=SHADOW, benchmark_dir=bench, benchmark_sha=pin,
                   repos_dir=os.path.join(tmp, "r2"), manifest_path=acq,
                   fetch_timeout_seconds=60,
                   dataset_cloner=lambda b, p, t: None,
                   snapshot_fetcher=fake_fetcher,
                   expected={"tasks": 1, "snapshots": 1, "repos": 1,
                             "cves": 1, "gt_x": 1})
        bindir = os.path.join(tmp, "bin2")
        write(os.path.join(bindir, "go"),
              '#!/bin/sh\necho "go version go1.26.1 darwin/arm64"\n',
              mode=0o755)
        write(os.path.join(bindir, "govulncheck"),
              "#!/bin/sh\nexit 0\n", mode=0o755)
        iz = os.path.join(tmp, "iz")
        write(iz, "#!/bin/sh\nexit 0\n", mode=0o755)
        env = dict(os.environ)
        env["PATH"] = bindir + os.pathsep + env["PATH"]
        with self.assertRaises(vb.BaselineError) as ctx:
            vb.preflight(worktree=SHADOW, benchmark_dir=bench,
                         repos_dir=os.path.join(tmp, "r2"),
                         acquisition=acq, out=os.path.join(tmp, "o2"),
                         izyan=iz, analysis_go="1.26.1",
                         mem_limit="1GiB", workers=1,
                         case_timeout_seconds=10,
                         disk_free=lambda p: 10 << 30,
                         ram_bytes=lambda: 96 << 30,
                         ambient_env=env)
        self.assertIn("disk gate", str(ctx.exception))

    def test_preflight_rejects_dirty_snapshot_and_out(self):
        mpath = build_run_fixture(self)
        m = vb.load_json(mpath)
        snap = next(iter(m["snapshot_refs"].values()))["path"]
        os.chmod(snap, 0o755)  # restore write on root → immutable violated
        with self.assertRaises(vb.BaselineError):
            vb._check_snapshot_ready(
                {"path": snap,
                 "content_hash": next(iter(
                     vb.load_json(mpath)["snapshot_refs"].values()))
                 ["content_hash"]})
        # Non-empty OUT refuses a second preflight.
        with self.assertRaises(vb.BaselineError):
            vb.preflight(worktree=SHADOW,
                         benchmark_dir=m["dataset"]["benchmark_dir"],
                         repos_dir=self.repos,
                         acquisition=os.path.join(
                             os.path.dirname(mpath),
                             "..", "ctl", "acq.json"),
                         out=m["out"]["dir"], izyan=m["izyan"]["path"],
                         analysis_go="1.26.1", mem_limit="512MiB",
                         workers=1, case_timeout_seconds=10,
                         disk_free=lambda p: 100 << 30,
                         ram_bytes=lambda: 96 << 30)


class RunFixture(AcqFixture):
    def test_run_all_tasks_finalize_completed(self):
        mpath = build_run_fixture(self)
        rc = vb.run(manifest_path=mpath,
                    popen_factory=fake_popen_factory(),
                    disk_free=lambda p: 100 << 30,
                    disk_check_seconds=3600)
        self.assertEqual(rc, 0)
        m = vb.load_json(mpath)
        for t in m["tasks"]:
            rec = vb.load_json(os.path.join(m["out"]["ledger"],
                                            t["task_id"] + ".json"))
            self.assertEqual(rec["state"], "finalized")
            self.assertEqual(rec["outcome"], "completed")
            self.assertEqual(rec["exit_code"], 0)
            self.assertIn("prediction_sha256", rec)
            self.assertTrue(os.path.isfile(
                os.path.join(m["out"]["attempts"], t["task_id"],
                             "attempt.json")))

    def test_run_corrupt_prediction_is_failed(self):
        mpath = build_run_fixture(self)
        rc = vb.run(manifest_path=mpath,
                    popen_factory=fake_popen_factory("corrupt_pred"),
                    disk_free=lambda p: 100 << 30,
                    disk_check_seconds=3600)
        self.assertEqual(rc, 0)
        m = vb.load_json(mpath)
        rec = vb.load_json(os.path.join(
            m["out"]["ledger"], "task-0-CVE-0.json"))
        self.assertEqual(rec["outcome"], "failed")
        self.assertEqual(rec["failure"]["kind"], "infrastructure")

    def test_run_without_resume_refuses_nonpending(self):
        mpath = build_run_fixture(self)
        vb.run(manifest_path=mpath, popen_factory=fake_popen_factory(),
               disk_free=lambda p: 100 << 30, disk_check_seconds=3600)
        with self.assertRaises(vb.BaselineError):
            vb.run(manifest_path=mpath,
                   popen_factory=fake_popen_factory(),
                   disk_free=lambda p: 100 << 30,
                   disk_check_seconds=3600)

    def test_resume_skips_finalized_including_failed(self):
        mpath = build_run_fixture(self)
        # First run: task-2 fails (corrupt prediction), others complete.
        def factory(argv, **_kw):
            tid = argv[argv.index("--case") + 1]
            raw_dir = argv[argv.index("--out") + 1]
            outcome = "corrupt_pred" if tid == "task-2-CVE-2" else "ok"
            return FakeProc(argv, raw_dir=raw_dir, tid=tid,
                            outcome=outcome)
        vb.run(manifest_path=mpath, popen_factory=factory,
               disk_free=lambda p: 100 << 30, disk_check_seconds=3600)
        calls = []
        vb.run(manifest_path=mpath, resume=True,
               popen_factory=lambda a, **k: calls.append(a) or FakeProc(a),
               disk_free=lambda p: 100 << 30, disk_check_seconds=3600)
        self.assertEqual(calls, [], "finalized tasks (incl. failed) must "
                                    "never be respawned")

    def test_resume_interrupted_running_finalizes_failed(self):
        mpath = build_run_fixture(self)
        m = vb.load_json(mpath)
        tid = m["tasks"][0]["task_id"]
        # Simulate a killed first attempt: running ledger + partial raw.
        rec = vb.load_json(os.path.join(m["out"]["ledger"],
                                        tid + ".json"))
        rec["state"] = "running"
        vb._write_ledger(m["out"]["ledger"], rec)
        raw = os.path.join(m["out"]["attempts"], tid, "raw")
        os.makedirs(raw)
        write(os.path.join(raw, "partial.tmp"), "x")
        calls = []
        rc = vb.run(manifest_path=mpath, resume=True,
                    popen_factory=lambda a, **k:
                        calls.append(a) or FakeProc(
                            a, raw_dir=a[a.index("--out") + 1],
                            tid=a[a.index("--case") + 1]),
                    disk_free=lambda p: 100 << 30,
                    disk_check_seconds=3600)
        self.assertEqual(rc, 0)
        rec = vb.load_json(os.path.join(m["out"]["ledger"],
                                        tid + ".json"))
        self.assertEqual(rec["state"], "finalized")
        self.assertEqual(rec["outcome"], "failed")
        self.assertTrue(rec["recovered_after_interruption"])
        self.assertNotIn(tid, [c[c.index("--case") + 1] for c in calls],
                         "interrupted first attempt must not rerun")
        self.assertTrue(os.path.isdir(raw),
                        "partial artifacts preserved")

    def test_resume_recovers_complete_packet(self):
        mpath = build_run_fixture(self)
        m = vb.load_json(mpath)
        tid = m["tasks"][0]["task_id"]
        # Write a complete raw packet but keep the ledger running — the
        # interruption hit between CLI exit and ledger commit.
        raw = os.path.join(m["out"]["attempts"], tid, "raw")
        FakeProc([], raw_dir=raw, tid=tid)
        rec = vb.load_json(os.path.join(m["out"]["ledger"],
                                        tid + ".json"))
        rec["state"] = "running"
        vb._write_ledger(m["out"]["ledger"], rec)
        spawned = []
        vb.run(manifest_path=mpath, resume=True,
               popen_factory=lambda a, **k:
                   (spawned.append(a[a.index("--case") + 1]),
                    FakeProc(a, raw_dir=a[a.index("--out") + 1],
                             tid=a[a.index("--case") + 1]))[1],
               disk_free=lambda p: 100 << 30,
               disk_check_seconds=3600)
        rec = vb.load_json(os.path.join(m["out"]["ledger"],
                                        tid + ".json"))
        self.assertEqual(rec["outcome"], "completed")
        self.assertTrue(rec["recovered_after_interruption"])
        self.assertNotIn(tid, spawned)

    def test_run_deadline_kills_process_group(self):
        """A real long-running subprocess must be killed through its own
        process group when the manifest deadline expires."""
        mpath = build_run_fixture(self, n_tasks=1, timeout=1)
        m = vb.load_json(mpath)
        tid = m["tasks"][0]["task_id"]
        m["argv_template"] = ["sleep", "30"]
        vb.atomic_write_json(mpath, m)

        def factory(argv, **kw):
            return subprocess.Popen(argv, **kw)

        t0 = time.monotonic()
        vb.run(manifest_path=mpath, popen_factory=factory,
               disk_free=lambda p: 100 << 30,
               disk_check_seconds=3600, sig_grace=1, poll_seconds=0.05)
        self.assertLess(time.monotonic() - t0, 15,
                        "deadline kill took too long")
        rec = vb.load_json(os.path.join(m["out"]["ledger"],
                                        tid + ".json"))
        self.assertEqual(rec["outcome"], "failed")
        self.assertIn("deadline_exceeded",
                      rec.get("failure", {}).get("reason", ""))
        attempt = vb.load_json(os.path.join(
            m["out"]["attempts"], tid, "attempt.json"))
        self.assertIn("deadline_exceeded", attempt["termination"])

    def test_run_disk_pressure_aborts(self):
        mpath = build_run_fixture(self, n_tasks=2)
        m = vb.load_json(mpath)
        frees = [100 << 30] + [1 << 30] * 50  # first call = start gate
        calls = {"n": 0}

        def disk(_p):
            calls["n"] += 1
            return frees[min(calls["n"] - 1, len(frees) - 1)]

        rc = vb.run(manifest_path=mpath,
                    popen_factory=never_popen_factory(),
                    disk_free=disk, killpg=lambda pg, s: None,
                    disk_check_seconds=0,
                    poll_seconds=0.01, sig_grace=0)
        self.assertEqual(rc, 1)
        for t in m["tasks"]:
            rec = vb.load_json(os.path.join(
                m["out"]["ledger"], t["task_id"] + ".json"))
            if rec["state"] == "finalized":
                self.assertEqual(rec["outcome"], "failed")
                self.assertIn("disk_pressure",
                              rec.get("failure", {}).get("reason", ""))

    def test_run_disk_admission_stop_no_new_tasks(self):
        mpath = build_run_fixture(self, n_tasks=2, workers=1)
        m = vb.load_json(mpath)
        # Call order in run(): 1=start gate, 2=admission for task-0,
        # 3=periodic check (aborts only below 2 GiB), 4=admission for
        # task-1 → must see <5 GiB here to stop admission.
        frees = [0, 100 << 30, 100 << 30, 4 << 30] + [4 << 30] * 50
        calls = {"n": 0}

        def disk(_p):
            calls["n"] += 1
            return frees[min(calls["n"], len(frees) - 1)]

        done = []
        vb.run(manifest_path=mpath,
               popen_factory=lambda a, **k:
                   (done.append(a[a.index("--case") + 1]),
                    FakeProc(a, raw_dir=a[a.index("--out") + 1],
                             tid=a[a.index("--case") + 1]))[1],
               disk_free=disk, disk_check_seconds=3600,
               poll_seconds=0.01)
        states = {t["task_id"]: vb.load_json(os.path.join(
            m["out"]["ledger"], t["task_id"] + ".json"))
            for t in m["tasks"]}
        self.assertEqual(done, ["task-0-CVE-0"])
        self.assertEqual(states["task-0-CVE-0"]["state"], "finalized")
        self.assertEqual(states["task-1-CVE-1"]["state"], "pending",
                         "task admitted after disk fell below 5 GiB")


class ReportFixture(AcqFixture):
    def test_report_denominators_and_freeze(self):
        mpath = build_run_fixture(self, n_tasks=3)
        vb.run(manifest_path=mpath, popen_factory=fake_popen_factory(),
               disk_free=lambda p: 100 << 30, disk_check_seconds=3600)
        m = vb.load_json(mpath)
        rc = vb.report(manifest_path=mpath)
        self.assertEqual(rc, 0)
        out = m["out"]["dir"]
        metrics = vb.load_json(os.path.join(out, "metrics.json"))
        self.assertEqual(metrics["denominators"],
                         {"total": 3, "gt_exploitable": 0, "gt_safe": 3})
        self.assertEqual(metrics["status_correct"], 3)
        # All predictions say code_not_present, GT is code_not_present.
        self.assertEqual(metrics["reason_correct"], 3)
        self.assertEqual(metrics["false_safe"], 0)
        self.assertEqual(metrics["safety_gate"], "pass")
        self.assertTrue(os.path.isfile(os.path.join(
            out, "scoring", "cases.jsonl")))
        self.assertTrue(os.path.isfile(os.path.join(
            out, "raw-checksums.json")))
        self.assertTrue(os.path.isfile(os.path.join(
            out, "baseline-frozen.json")))
        # Frozen raw is read-only.
        pred = os.path.join(out, "attempts", "task-0-CVE-0", "raw",
                            "task-0-CVE-0", "prediction.json")
        self.assertFalse(os.stat(pred).st_mode & 0o222)
        # Compatibility file has the four GT classes + failed policy.
        compat = vb.load_json(os.path.join(out,
                                           "compatibility-metrics.json"))
        self.assertIn("official", compat["failed_policy"])
        self.assertEqual(set(compat["per_class"]),
                         set(vb.GT_CATEGORIES))

    def test_report_abstain_and_wrong_are_distinct(self):
        mpath = build_run_fixture(self, n_tasks=4)
        m = vb.load_json(mpath)

        def factory(argv, **_kw):
            tid = argv[argv.index("--case") + 1]
            raw = argv[argv.index("--out") + 1]
            env = {"task_id": tid, "requested_cve": "c",
                   "terminal_state": "COMPLETED",
                   "compatibility_category": "uncertain",
                   "wall_seconds": 0.5, "llm_calls": 0, "tool_calls": 0}
            case = os.path.join(raw, tid)
            os.makedirs(case, exist_ok=True)
            if tid == "task-1-CVE-1":
                env["verdict"] = "INCONCLUSIVE"
            elif tid == "task-2-CVE-2":
                env["verdict"] = "NO_EXPLOIT_PATH_FOUND"
                env["compatibility_category"] = "code_not_reachable"
            elif tid == "task-3-CVE-3":
                pass  # no prediction file → failed
                write(os.path.join(raw, "metrics.json"), "{}")
                os.makedirs(os.path.join(raw, "scoring"))
                write(os.path.join(raw, "scoring", "cases.jsonl"),
                      json.dumps({"task_id": tid}) + "\n")
                return FakeProc(argv)
            else:
                env["verdict"] = "NOT_AFFECTED"
                env["compatibility_category"] = "code_not_present"
            write(os.path.join(case, "prediction.json"),
                  json.dumps(env))
            write(os.path.join(raw, "metrics.json"), "{}")
            os.makedirs(os.path.join(raw, "scoring"), exist_ok=True)
            write(os.path.join(raw, "scoring", "cases.jsonl"),
                  json.dumps({"task_id": tid}) + "\n")
            return FakeProc(argv)

        vb.run(manifest_path=mpath, popen_factory=factory,
               disk_free=lambda p: 100 << 30, disk_check_seconds=3600)
        vb.report(manifest_path=mpath)
        m2 = vb.load_json(mpath)
        metrics = vb.load_json(os.path.join(m2["out"]["dir"],
                                            "metrics.json"))
        # GT all code_not_present: task-0 correct+reason, task-1 abstain,
        # task-2 status correct but reason wrong, task-3 failed.
        self.assertEqual(metrics["status_correct"], 2)
        self.assertEqual(metrics["reason_correct"], 1)
        self.assertEqual(metrics["abstain"], 1)
        self.assertEqual(metrics["failed"], 1)
        self.assertEqual(metrics["outcomes"]["correct_safe"], 2)
        # Review-needed covers abstain + wrong-reason + failed.
        needed = open(os.path.join(m2["out"]["dir"], "scoring",
                                   "review-needed.jsonl")).read()
        for tid in ("task-1-CVE-1", "task-2-CVE-2", "task-3-CVE-3"):
            self.assertIn(tid, needed)
        self.assertNotIn("task-0-CVE-0", needed)


class ValidateReviewFixture(AcqFixture):
    def _taxonomy_env(self, extra_cases=()):
        mpath = build_run_fixture(self, n_tasks=2)
        vb.run(manifest_path=mpath,
               popen_factory=fake_popen_factory("no_pred"),
               disk_free=lambda p: 100 << 30, disk_check_seconds=3600)
        vb.report(manifest_path=mpath)
        return mpath

    def test_validate_review_happy_and_missing(self):
        mpath = self._taxonomy_env()
        m = vb.load_json(mpath)
        out = m["out"]["dir"]
        frozen = vb.load_json(os.path.join(out, "baseline-frozen.json"))
        rows = []
        for t in m["tasks"]:
            pred = os.path.join("attempts", t["task_id"], "raw",
                                t["task_id"], "prediction.json")
            rows.append({
                "run_id": m["run_id"], "task_id": t["task_id"],
                "scoring_outcome": "failed", "status_correct": False,
                "reason_correct": False,
                "category": "TOOL_SCOPE_INCOMPLETE",
                "disposition": "infrastructure_failure",
                "subcategory": "spawn-fail",
                "reviewer": "tester", "reviewed_at_utc": vb.utcnow(),
                "approved_by": "maintainer",
                "baseline_manifest_sha256": frozen["manifest_sha256"],
                "prediction_ref": None,
                "case_ref": None, "report_ref": None,
                "evidence": [{"id": None,
                              "path": "run-manifest.json",
                              "quote": "frozen manifest"}],
                "explanation": "no raw packet was produced",
                "first_point_of_divergence": "process failed to write",
                "needed_information_or_general_change": "diagnose spawn",
            })
        tax = os.path.join(out, "scoring", "failure-taxonomy.jsonl")
        with open(tax, "w") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
        self.assertEqual(vb.validate_review(manifest_path=mpath), 0)
        # Missing row → error.
        with open(tax, "w") as f:
            f.write(json.dumps(rows[0]) + "\n")
        self.assertEqual(vb.validate_review(manifest_path=mpath), 1)
        # Bad enum → error.
        rows[0]["category"] = "NOT_A_CATEGORY"
        with open(tax, "w") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
        self.assertEqual(vb.validate_review(manifest_path=mpath), 1)
        # Bad evidence path → error.
        rows[0]["category"] = "TOOL_SCOPE_INCOMPLETE"
        rows[0]["evidence"] = [{"path": "no/such/file", "quote": "x"}]
        with open(tax, "w") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
        self.assertEqual(vb.validate_review(manifest_path=mpath), 1)
        # Digest mismatch on evidence path → error.
        rows[0]["evidence"] = [{"path": "run-manifest.json",
                                "quote": "x", "sha256": "0" * 64}]
        rows[0]["prediction_ref"] = {"path": "run-manifest.json",
                                     "sha256": "0" * 64}
        with open(tax, "w") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
        self.assertEqual(vb.validate_review(manifest_path=mpath), 1)


if __name__ == "__main__":
    unittest.main()

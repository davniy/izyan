# Harness reconstruction — 2026-10-09

## What happened

macOS purged `/tmp` between runs. Lost: the whole harness checkout
`/tmp/vexbench-agent-ctl` (its venv, its local git history), the snapshot store
`/tmp/vexbench-baseline/repos`, and the historical Qwen artifacts under
`/tmp/vexbench-qwen-iso`. The worktree (results, prompts, patches, freeze
records) survived; Docker images survived in the VM.

## How it was rebuilt (byte-faithful for the treatment)

1. `git clone https://github.com/steven1518/vex-bench` @ `80cddeac3132826bfd47227ad59b2e6618a681bd`
   — the pinned upstream state that the pre-C1 baseline (`1135cbb`) matched.
2. `git apply --binary --exclude='*.pyc' --exclude='*__pycache__*'` for
   `eval/c1/harness/vexbench-agent-ctl-c1.patch`, then the same for
   `eval/task5/harness/vexbench-agent-ctl-task5.patch`. (The `.pyc` hunks in the
   patches are noise: a fresh clone has no `__pycache__`, and Python recompiles.)
3. `uv sync --frozen --python 3.13` — rebuilt `.venv` on CPython 3.13.12, matching
   the original venv.
4. Re-downloaded the 30 Go snapshots with `vex-bench download` into
   `/tmp/vexbench-baseline/repos` (28 unique `(repo, sha)` dirs, 0 errors).

Verification after rebuild: `vuln_safety_v1` = `14c1396c9094` and
`vuln_safety_v1_tools` = `5d6c640c6945`, byte-identical to the frozen copies in
`eval/task5/prompts/`; Task 4 prompts also match (`c45dfc39af34`, `6eda998ea66c`);
agents `opencode-b1p`/`opencode-c1` registered; the container-timeout watchdog is
present in `run_in_container`.

## Defects found in the Task 4 patch (now fixed)

The C1 patch did **not** fully reproduce the harness — two pieces lived only in
the (lost) working tree:

1. **`src/evaluate/agents/opencode.py` `MODEL2NAME`** lacked the self-hosted
   entries. Restored exactly as the runs used them (values verified against a
   real attempt's synthesized `opencode-config.c1.json`):
   `qwen3.6-35b → custom-openai/Qwen/Qwen3.6-35B-A3B`,
   `qwen3.8-27b → custom-openai/Qwen/Qwen3.8-27B`,
   `gemini-3.8-flash-high → antigravity/gemini-3.8-flash-high`.
2. **`benchmark/tasks/vex_bench.jsonl`** was the **Go-filtered 30-task** file, not
   the upstream 75-task file (`load_tasks` applies no filter). The upstream file
   is kept as `benchmark/tasks/vex_bench.upstream75.jsonl`; the Go subset is
   installed as `vex_bench.jsonl`.

Both must be folded into the patches so the artifact reproduces the harness.

## Environment files (never in the repo)

`env/opencode/opencode.env` (provider credential) and `env/opencode/opencode.json`
(base config) were also purged with `/tmp`. They were restored locally from
surviving evidence — the base config is minimal (`{"$schema": …}`), confirmed by
every P1/T1 synthesized config containing only the `custom-openai` provider block. The
credential is a local secret and is **not** committed anywhere; the base config
reconstruction is recorded here because it is part of the frozen environment.

## Relocation out of `/tmp` (root cause fixed)

Rebuilding into `/tmp` re-created the same fragility, so the live assets were
moved to a durable root outside the volatile temp dir:

```
<VA_VEXBENCH>/
  agent-ctl/                 # the patched harness checkout + venv (233 MB)
  repos/                     # 28 pinned Go snapshots (3.2 GB), file list
                             # verified identical to the /tmp copy
  t1-pre-resume-snapshot/    # first-attempt result.json for the 46 pre-outage
                             # T1 attempts (see the re-run note below)
```

The T1 run was migrated to this root mid-flight (kill + relaunch; the harness
skips already-finalized attempts, so no attempt was lost). The frozen
`eval/task5/experiment-manifest.json` still names the old `/tmp` harness path and
is regenerated against the durable root at the end of the run; the difference is
a path/location change only — prompt bytes, patches and images are unchanged
(prompt hashes re-verified after the move).

### Harness re-runs on resume

On resume the harness logs `[RE-RUN] cached result unparseable` and re-executes
attempts whose stored result it cannot parse. Three T1 slots hit this:
`k8s-44487` run_002/run_003 and `rancher-4dc4f53-CVE-2025-58181` run_003. P1
never resumed, so its unparseable attempts stayed recorded as
`invalid_terminal_answer` FAILED.

To keep first-attempt discipline symmetric across arms (spec §3.6: technical
retries published separately and applied equally), the pre-resume originals for
those slots are preserved in `t1-pre-resume-snapshot/`, the re-run outputs are
kept as a separate technical-retry record, and the scored T1 set uses one
attempt per `(case, run)` — the same treatment P1 received.

## Snapshot integrity re-verification (post-run)

After the T1 run completed, all 28 durable snapshots were re-hashed with
`t1_content_hash` (byte-parity port of `internal/repository.ContentHash`) and
compared against the frozen `dataset.snapshot_hashes`. **27/28 matched.**

`zeromicro/go-zero/bae061a…` mismatched: the durable copy was a partial tree
(19 files, a leftover `.git`, no `go.mod`). Cause: the first download was
interrupted (the tool's 120 s deadline killed it), and the downloader's
idempotency rule — "directory exists and is non-empty ⇒ ready" — made the
re-run skip it. Re-downloading it alone reproduced the frozen hash
(`8ef3ad2d…`), confirming the tree is content-identical to the original.

**Score impact: none.** The three T1 `go-zero` attempts ran at 09:16–09:20Z, i.e.
before the `/tmp` purge (~12:19) and before the durable resume (12:44), so they
used the original snapshot. `go-zero` is in no `[RE-RUN]` slot. The T1 and P1
scores are therefore unaffected by the broken reconstruction copy.

## Resume re-runs are technical retries, not new first attempts

The four `[RE-RUN]` slots (`k8s-44487` run_002/run_003, `testify-28948` run_002,
`rancher-58181` run_003) held **no model answer** before the resume — their
pre-resume `result.json` was a 7.4 KB echo of the prompt (the VPN had killed the
provider before any output). The re-run produced the genuine first answer, so
the run counts one Y_model response per attempt for every slot; no answer was
replaced and no `run_001` was overwritten. Preserved originals:
`<VA_VEXBENCH>/t1-pre-resume-snapshot/`.

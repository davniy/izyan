#!/bin/sh
# Task 4.4 runner: waits for provider capacity, then runs the frozen C1 cohort
# (30 cases x 3 repeats) and the B1' control cohort, sequentially.
#
# Why: the first C1 attempt (results/task4-c1/c1-full-capacity-contaminated) was
# aborted mid-run because the Codex backend returned
#   {"type":"error","message":"Selected model is at capacity. Please try a different model."}
# for ~27/65 attempts. Per plan section 5 an infrastructure defect must preserve
# the whole cohort and start a NEW full cohort under a new experiment id.
#
# This script does not touch the preserved cohort. It writes to fresh dirs:
#   results/task4-c1/c1-full        (C1, treatment)
#   results/task4-c1/b1p-full       (B1', control)
set -u

HARNESS=/tmp/vexbench-agent-ctl
REPO=<VA_REPO>
RESULTS="$REPO/results/task4-c1"
LOG="$RESULTS/watcher.log"

log() { printf '%s %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >>"$LOG"; }

# Probe: one tiny codex call. Returns 0 if the model answers (capacity OK).
probe() {
  cd "$HARNESS" || return 1
  out=$(timeout 120 docker run --rm \
      --env-file "$HARNESS/env/codex/codex.env" \
      -v "$HARNESS/env/codex/config.toml:/tmp/.codex/config.toml:ro" \
      --entrypoint sh vex-bench-go-codex:latest -c \
      'timeout 90 codex exec --sandbox danger-full-access --json --skip-git-repo-check --model gpt-6.1-sol "reply with OK" 2>&1 | tail -5' 2>&1)
  if printf '%s' "$out" | grep -q "at capacity"; then return 1; fi
  if printf '%s' "$out" | grep -q "turn.completed"; then return 0; fi
  return 1
}

wait_for_capacity() {
  n=0
  while :; do
    n=$((n + 1))
    if probe; then log "capacity OK (probe #$n)"; return 0; fi
    log "probe #$n: provider still at capacity; sleeping 300s"
    sleep 300
  done
}

run_cohort() {
  agent="$1"; prompt="$2"; outdir="$3"
  log "starting $agent -> $outdir"
  cd "$HARNESS" || return 1
  mkdir -p "$outdir"
  uv run --locked --no-sync vex-bench evaluate run \
    --agent "$agent" --prompt "$prompt" --model gpt-6.1-sol \
    --benchmark vex_bench --repeats 3 --timeout 900 --parallel 1 \
    --repos-dir /tmp/vexbench-baseline/repos \
    --output-dir "$outdir" >>"$outdir/run.log" 2>&1
  log "finished $agent (rc=$?)"
}

mkdir -p "$RESULTS"
log "watcher start"
wait_for_capacity || exit 1

# Fresh experiment ids; the contaminated cohort is never overwritten.
run_cohort codex-c1 vuln_c1 "$RESULTS/c1-full"
wait_for_capacity || exit 1
run_cohort codex-b1p vuln_assess "$RESULTS/b1p-full"

log "watcher done"

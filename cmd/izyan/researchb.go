package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/davniy/izyan/internal/productb/research"
)

// runResearchB executes the frozen B1 evaluation arm: verify a pinned
// snapshot, resolve the advisory, render the frozen B1 prompt and — only
// under --allow-agent — launch one opencode container against the snapshot
// (read-only mount, no MCP, subagents disabled).
//
// It is reachable only as `izyan eval research-b1`: B1 is an evaluation
// control with a frozen prompt, model and container image, never a product
// runtime and never a second live human investigator. `izyan triage` owns
// the one live Product B investigation loop.
//
//	izyan eval research-b1 --snapshot <dir> --cve <id> --out <dir>
//	    [--advisory <file|dir> | --osv-url <url>] [--no-net]
//	    [--commit <sha>] [--model <key>] [--agent-image <img>]
//	    [--timeout <sec>] [--agent-env NAME,...] [--agent-env-file <path>]
//	    [--agent-config <path>] [--allow-agent] [--dry-run]
//	    [--case-id <controller-case-key>] [--skip-content-hash]
//
//	izyan eval research-b1 --replay-run <out>/runs/<run_id> [--case-id <controller-case-key>]
//
// Without --allow-agent (or with --dry-run) nothing is launched: the exact
// docker argv, mounts, config and prompt are written as the launch plan.
// The report's research_category is a research judgement, never a verified
// safety conclusion; the command never closes a vulnerability.
//
// --replay-run re-renders a stored run dossier: it reuses the recorded
// identity blocks and the saved raw answer verbatim, recomputes the
// host-fact consistency layer against the recorded snapshot, and writes
// a new run directory marked rerender_of=<original>. No container, no
// network, no model call. --case-id overrides the stored case key.
//
// --case-id names the controller-side case (VEX-Bench task id and the
// like) so the grounding artifact joins with the frozen reference; it is
// recorded in report.request.case_id and reportcheck.json. Without it the
// run id stands in.
//
// --skip-content-hash is an eval-only escape for snapshots whose content
// hash walk is too slow: verifySnapshot performs no containment check and
// no t1 hash, the snapshot identity stays commit + path and the run
// records content_hash "skipped" (algorithm "none") plus a limitation.
// It has no effect under --replay-run — the stored snapshot block is
// copied verbatim.
func runResearchB(args []string) error {
	fs := flag.NewFlagSet("research", flag.ContinueOnError)
	var o research.Options
	var envNames string
	fs.StringVar(&o.SnapshotDir, "snapshot", "", "pinned product source tree (required)")
	fs.StringVar(&o.CVE, "cve", "", "CVE/GHSA/GO advisory id to research (required)")
	fs.StringVar(&o.OutDir, "out", "", "output directory; each run gets <out>/runs/<run_id>/ plus <out>/index.json (required)")
	fs.StringVar(&o.AdvisoryPath, "advisory", "", "local OSV JSON file or directory of advisory documents")
	fs.StringVar(&o.OSVURL, "osv-url", research.DefaultOSVURL, "OSV-compatible API base URL")
	fs.BoolVar(&o.NoNet, "no-net", false, "disable all advisory fetching (local --advisory still works)")
	fs.StringVar(&o.Commit, "commit", "", "commit SHA for snapshots without .git (defaults to a SHA basename)")
	fs.StringVar(&o.Model, "model", research.DefaultModel, "agent model key or provider/model id")
	fs.StringVar(&o.AgentImage, "agent-image", research.DefaultAgentImage, "container image for the agent run")
	fs.StringVar(&o.AgentEnvFile, "agent-env-file", "", "docker --env-file carrying provider secrets")
	fs.StringVar(&envNames, "agent-env", "", "host env vars forwarded to the container by name (comma-separated; default OPENAI_API_KEY,OPENAI_BASE_URL)")
	fs.StringVar(&o.AgentConfig, "agent-config", "", "base opencode.json to extend (provider merged, mcp removed, task tool disabled)")
	fs.IntVar(&o.Timeout, "timeout", research.DefaultTimeout, "agent run timeout in seconds")
	fs.BoolVar(&o.AllowAgent, "allow-agent", false, "opt-in: actually launch the agent container")
	fs.BoolVar(&o.DryRun, "dry-run", false, "render plan and prompt only, launch nothing")
	fs.StringVar(&o.ReplayRun, "replay-run", "", "re-render a stored run directory <out>/runs/<run_id>: no container, no network, no model call")
	fs.StringVar(&o.CaseID, "case-id", "", "controller-side case key (e.g. VEX-Bench task id) recorded in report.request.case_id and reportcheck.json; defaults to the run id")
	fs.BoolVar(&o.SkipContentHash, "skip-content-hash", false, "eval-only: skip the snapshot content-hash walk (identity stays commit+path; content_hash=skipped, algorithm=none, recorded limitation); ignored under --replay-run")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if envNames != "" {
		for _, n := range strings.Split(envNames, ",") {
			if n = strings.TrimSpace(n); n != "" {
				o.AgentEnv = append(o.AgentEnv, n)
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(),
		time.Duration(o.Timeout+300)*time.Second)
	defer cancel()

	rep, err := research.Run(ctx, o)
	if err != nil {
		return err
	}
	if rep.RerenderOf != "" {
		fmt.Fprintf(os.Stderr, "research %s: re-rendered run %s -> %s (mode=%s run=%s category=%s)\n",
			rep.Request.CVE, rep.RerenderOf, rep.RunID, rep.Mode, rep.Run.Status,
			emptyOr(rep.Answer.Category, "unavailable"))
		return nil
	}
	fmt.Fprintf(os.Stderr, "research %s: mode=%s run=%s category=%s -> %s\n",
		rep.Request.CVE, rep.Mode, rep.Run.Status,
		emptyOr(rep.Answer.Category, "unavailable"), rep.Request.SnapshotDir)
	if rep.Mode == "failed" {
		return fmt.Errorf("agent run failed (report written to %s)", o.OutDir)
	}
	return nil
}

func emptyOr(s, alt string) string {
	if s == "" {
		return alt
	}
	return s
}

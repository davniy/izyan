// izyan-evidence-tools is the slim MCP stdio server that exposes Izyan's
// deterministic evidence analyzers to an external agent inside the Task 4
// sandbox (spec §6). It is deliberately NOT the full izyan CLI: it has no
// analyze/eval entrypoints and no access to the production verdict path.
//
//	izyan-evidence-tools --snapshot-root <dir> --cve <id>
//	    [--external-sha <sha>] [--goos/--goarch/--tags/--cgo]
//	    [--allow-exec] [--no-net] [--audit-file <path>]
//	    [--strict] [--allow-toolchain] [--modcache <dir>] [--build-cache-dir <dir>]
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/fedorovmv/izyan/internal/evidencetools"
	"github.com/fedorovmv/izyan/internal/toolchain"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "izyan-evidence-tools:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("izyan-evidence-tools", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var cfg evidencetools.SessionConfig

	var tags, auditPath, analysisGo, advisoryDir string
	var noNet bool
	fs.StringVar(&cfg.SnapshotRoot, "snapshot-root", "", "root of the pinned snapshot to analyze (required)")
	fs.StringVar(&cfg.CVEID, "cve", "", "advisory id under analysis (GO-*/CVE-*/GHSA-*)")
	fs.StringVar(&cfg.ExternalSHA, "external-sha", "", "external snapshot identity (commit SHA) supplied by the controller")
	fs.StringVar(&cfg.GOOS, "goos", "", "target GOOS for the analysis build context")
	fs.StringVar(&cfg.GOARCH, "goarch", "", "target GOARCH for the analysis build context")
	fs.StringVar(&tags, "tags", "", "comma-separated build tags for the analysis build context")
	fs.BoolVar(&cfg.CGOEnabled, "cgo", false, "CGO enabled in the analysis build context")
	fs.BoolVar(&cfg.AllowExec, "allow-exec", false, "permit tools that execute repository code (run_build, run_tests, govulncheck's go subprocess)")
	fs.BoolVar(&noNet, "no-net", false, "disable advisory/fix network research")
	fs.StringVar(&cfg.OSVBaseURL, "osv-url", "", "OSV-compatible API base URL (default https://api.osv.dev)")
	fs.StringVar(&advisoryDir, "advisory-dir", "", "extra confined read root (e.g. prepared advisory directory)")
	fs.StringVar(&auditPath, "audit-file", "", "JSONL audit sink file (default: stderr)")
	fs.StringVar(&analysisGo, "analysis-go", "", "Go toolchain version to analyze with (e.g. 1.23.4); default local")
	// Environment-hardening profile (checkpoint-0 E1–E5): opt-in for the
	// agent/benchmark lane; the defaults keep the current session shape.
	fs.BoolVar(&cfg.Strict, "strict", false, "hardened agent profile: mandatory confinement, no ambient module-cache reads, module egress off for toolchain subprocesses")
	fs.BoolVar(&cfg.AllowToolchain, "allow-toolchain", false, "under --strict, permit exec-backed toolchain tools (get_dependency_graph, get_module_version, usage-scope, run_govulncheck)")
	fs.StringVar(&cfg.GovulnDBRoot, "govulndb", "", "pin the local govulncheck vulnerability database (required under --strict)")
	fs.StringVar(&cfg.ModCacheRoot, "modcache", "", "declare a per-run module cache root: exported as GOMODCACHE and added to the confined read roots")
	fs.StringVar(&cfg.BuildCacheRoot, "build-cache-dir", "", "declare a reusable Go build cache root: exported as GOCACHE (omitted = the platform default is pinned; never inside the snapshot or output directory)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if cfg.SnapshotRoot == "" {
		return fmt.Errorf("--snapshot-root is required")
	}
	cfg.BuildTags = splitCSV(tags)
	cfg.AllowNet = !noNet
	if advisoryDir != "" {
		cfg.AdvisoryRoots = []string{advisoryDir}
	}
	if auditPath != "" {
		if dir := filepath.Dir(auditPath); dir != "" {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return fmt.Errorf("audit dir: %w", err)
			}
		}
		f, err := os.OpenFile(auditPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return fmt.Errorf("audit file: %w", err)
		}
		defer f.Close()
		cfg.Audit = evidencetools.NewJSONLAuditSink(f)
	}

	ctx := context.Background()
	tc, tcLims := toolchain.Resolve(ctx, analysisGo)
	for _, l := range tcLims {
		slog.Warn("toolchain", "limitation", l)
	}
	cfg.ToolchainBin = tc.GoBin
	cfg.ToolchainEnv = tc.Env
	cfg.ToolchainVer = tc.Version

	sess, err := evidencetools.NewSession(cfg)
	if err != nil {
		return err
	}
	return sess.Serve(ctx, &mcp.StdioTransport{})
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

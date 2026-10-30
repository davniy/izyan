// izyan-refindex is an eval-only command that freezes one advisory bound
// to one product snapshot into an "izyan-refindex/1" document: advisory
// digests, build context, resolved defect locus, product-usage stratum and
// an auxiliary fix-diff summary. Output is canonical: re-running over
// unchanged inputs produces byte-identical JSON.
//
//	izyan-refindex --snapshot <dir> (--cve <id> | --advisory <file|dir>)
//	    [--out <file>] [--goos <os>] [--goarch <arch>] [--tags a,b] [--cgo]
//	    [--external-sha <sha>] [--case-id <id>] [--osv-url <base>]
//	    [--analysis-go <ver>] [--no-net]
//
// It never touches the production analyzer pipeline or the VEX-Bench
// {category, reasoning} contract.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/fedorovmv/izyan/internal/fix"
	"github.com/fedorovmv/izyan/internal/goanalysis"
	pbdomain "github.com/fedorovmv/izyan/internal/productb/domain"
	"github.com/fedorovmv/izyan/internal/productb/refindex"
	"github.com/fedorovmv/izyan/internal/toolchain"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "izyan-refindex:", err)
		os.Exit(2)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("izyan-refindex", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var (
		snapshot    = fs.String("snapshot", "", "root of the product snapshot to analyze (required)")
		cve         = fs.String("cve", "", "advisory id (GO-*/CVE-*/GHSA-*) — selects the document under --advisory <dir> or fetches from OSV")
		advisory    = fs.String("advisory", "", "OSV document file or directory of documents")
		out         = fs.String("out", "", "output file for the canonical document (default: stdout)")
		goos        = fs.String("goos", "", "target GOOS (default: host)")
		goarch      = fs.String("goarch", "", "target GOARCH (default: host)")
		tags        = fs.String("tags", "", "comma-separated build tags for the build context")
		cgo         = fs.Bool("cgo", false, "CGO enabled in the build context")
		noNet       = fs.Bool("no-net", false, "disable all network access (advisory fetch, family enrichment, fix diff)")
		externalSHA = fs.String("external-sha", "", "snapshot identity supplied by the controller (skips git probing)")
		caseID      = fs.String("case-id", "", "document case_id (default: selected advisory id)")
		osvURL      = fs.String("osv-url", "", "OSV-compatible API base URL (default https://api.osv.dev)")
		analysisGo  = fs.String("analysis-go", "", "Go toolchain version to analyze with (e.g. 1.23.4); default local")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *snapshot == "" {
		return fmt.Errorf("--snapshot is required")
	}
	if *advisory == "" && *cve == "" {
		return fmt.Errorf("pass --advisory <file|dir> and/or --cve <id>")
	}
	root, err := filepath.Abs(*snapshot)
	if err != nil {
		return err
	}
	if st, err := os.Stat(root); err != nil || !st.IsDir() {
		return fmt.Errorf("snapshot %s is not a directory", root)
	}

	ctx := context.Background()
	tc, tcLims := toolchain.Resolve(ctx, *analysisGo)
	for _, l := range tcLims {
		fmt.Fprintln(os.Stderr, "toolchain:", l)
	}

	opts := refindex.Options{
		SnapshotRoot: root,
		CaseID:       *caseID,
		Commit:       snapshotCommit(ctx, root, *externalSHA),
		Toolchain:    tc.Version,
		GOOS:         *goos,
		GOARCH:       *goarch,
		Tags:         splitCSV(*tags),
		CGO:          *cgo,
		Advisory: refindex.AdvisoryOptions{
			ID:         *cve,
			OSVBaseURL: *osvURL,
			NoNet:      *noNet,
		},
	}
	if *advisory != "" {
		st, err := os.Stat(*advisory)
		if err != nil {
			return fmt.Errorf("--advisory %s: %w", *advisory, err)
		}
		abs, err := filepath.Abs(*advisory)
		if err != nil {
			return err
		}
		if st.IsDir() {
			opts.Advisory.Dir = abs
		} else {
			opts.Advisory.File = abs
		}
	}

	// The source index binds both seams: declaration lookup and the
	// ProductUsage probe. A load failure is not fatal — the document
	// degrades honestly (nil seams, recorded limitations).
	ix := &goanalysis.Index{
		Dir: root,
		Env: tc.Env,
		Build: pbdomain.ProductSnapshot{
			GOOS:       opts.GOOS,
			GOARCH:     opts.GOARCH,
			BuildTags:  opts.Tags,
			CGOEnabled: opts.CGO,
			VendorMode: vendorMode(root),
		},
	}
	if err := ix.Loaded(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "source index unavailable: %v\n", err)
	} else {
		opts.Symbols = ix
		opts.Usage = ix
	}
	if !*noNet {
		opts.Patch = fix.HTTPProvider{}
	}

	doc, err := refindex.Builder{Opts: opts}.Build(ctx)
	if err != nil {
		return err
	}
	payload, err := refindex.Canonical(doc)
	if err != nil {
		return err
	}
	if *out == "" {
		if _, err := os.Stdout.Write(payload); err != nil {
			return err
		}
	} else {
		if err := os.WriteFile(*out, payload, 0o644); err != nil {
			return err
		}
	}
	fmt.Println(doc.Hashes.CanonicalSHA256)
	return nil
}

// snapshotCommit resolves the snapshot identity: the externally supplied
// SHA wins (eval snapshots carry no git history); a real checkout reports
// its HEAD; anything else records "".
func snapshotCommit(ctx context.Context, root, external string) string {
	if external != "" {
		return external
	}
	if _, err := os.Stat(filepath.Join(root, ".git")); err != nil {
		return ""
	}
	cmd := exec.CommandContext(ctx, "git", "rev-parse", "HEAD")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// vendorMode reports whether the snapshot ships a vendor tree.
func vendorMode(root string) bool {
	st, err := os.Stat(filepath.Join(root, "vendor", "modules.txt"))
	return err == nil && !st.IsDir()
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

package research

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/mod/modfile"

	pbdomain "github.com/fedorovmv/izyan/internal/productb/domain"
	"github.com/fedorovmv/izyan/internal/productb/repository"
	"github.com/fedorovmv/izyan/internal/toolaudit"
)

// commitSHARx matches a full lowercase git SHA — the directory-name
// convention the benchmark snapshot layout uses
// (<repos>/<owner>/<repo>/<commit-sha>).
var commitSHARx = regexp.MustCompile(`^[0-9a-f]{40}$`)

// verifySnapshot confirms the snapshot's identity and content hash and
// extracts file-level module-graph basics. Every fact carries a
// verifiable reference; nothing inside the tree is executed.
//
// With o.SkipContentHash (eval-only controller flag) the
// repository.Service{}.Snapshot call is skipped entirely: no containment
// walk and no content hash. The recorded identity stays commit + path
// (content_hash "skipped", algorithm "none") while stat, toolchain and
// module-graph facts are collected as before.
func verifySnapshot(ctx context.Context, o Options) (SnapshotInfo, []Fact, error) {
	root := o.SnapshotDir
	info, err := os.Stat(root)
	if err != nil {
		return SnapshotInfo{}, nil, fmt.Errorf("--snapshot %s: %w", root, err)
	}
	if !info.IsDir() {
		return SnapshotInfo{}, nil, fmt.Errorf("--snapshot %s is not a directory", root)
	}

	commit, identitySource, err := snapshotCommit(ctx, o, root)
	if err != nil {
		return SnapshotInfo{}, nil, err
	}

	mg, mgFacts := moduleGraphFacts(root)

	si := SnapshotInfo{
		Path:           root,
		Commit:         commit,
		IdentitySource: identitySource,
		Module:         mg,
	}
	facts := []Fact{
		{
			Statement: fmt.Sprintf("snapshot commit %s (identity source: %s)", commit, identitySource),
			Reference: relRef(root, ""),
			Source:    "snapshot",
		},
	}

	releaseGo := ""
	var releaseSource pbdomain.GoVersionSource
	if o.SkipContentHash {
		si.ContentHash = "skipped"
		si.ContentHashAlg = "none"
		if goversion, verr := toolchainProbe(ctx, root); verr == nil {
			si.GoVersion = goversion
		}
		si.GoModDirective = mg.GoDirective
		if si.GoModDirective == "" {
			// Same loose scan repository.goModDirective uses: a
			// go.mod that declares `go X` but fails the strict
			// modfile parse still contributes the directive.
			si.GoModDirective = goDirectiveLine(root)
		}
		if ev := repository.DiscoverReleaseEvidence(root); ev.Version != "" {
			releaseGo, releaseSource = ev.Version, ev.Source
		}
		facts = append(facts, Fact{
			Statement: "content hash skipped by controller flag (--skip-content-hash): " +
				"the snapshot identity is commit + path and no tree walk was performed " +
				"(no containment check, no t1 hash)",
			Reference: relRef(root, ""),
			Source:    "snapshot",
		})
	} else {
		snap, serr := repository.Service{}.Snapshot(ctx, root, repository.SnapshotOptions{
			ExternalCommitSHA: commit,
		})
		if serr != nil {
			return SnapshotInfo{}, nil, fmt.Errorf("snapshot verification: %w", serr)
		}
		si.ContentHash = snap.ContentHash
		si.ContentHashAlg = "t1"
		si.GoVersion = snap.GoVersion
		si.GoModDirective = snap.GoModDirective
		releaseGo, releaseSource = snap.ReleaseGoVersion, snap.GoVersionSource
		facts = append(facts, Fact{
			Statement: "canonical content hash t1:" + snap.ContentHash,
			Reference: "entire snapshot tree (repository.ContentHash)",
			Source:    "snapshot",
		})
	}
	si.ReleaseGoVersion = releaseGo
	si.GoVersionSource = string(releaseSource)

	if releaseGo != "" {
		facts = append(facts, Fact{
			Statement: fmt.Sprintf("release Go toolchain %s (evidence: %s)", releaseGo, releaseSource),
			Reference: "release evidence in snapshot (Dockerfile/CI/version file)",
			Source:    "snapshot",
		})
	}
	facts = append(facts, mgFacts...)
	return si, facts, nil
}

// toolchainProbe reports the host `go version` line without touching the
// snapshot beyond running in its directory — the same probe
// repository.Service{}.Snapshot performs for SnapshotInfo.GoVersion,
// kept for the --skip-content-hash path so the toolchain fact survives.
// A probe failure only soft-fails: the field is informational and a
// minimal eval host may carry no go binary.
func toolchainProbe(ctx context.Context, root string) (string, error) {
	out, _, err := toolaudit.Run(ctx, "go", "", root, "go", nil, "version")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// goDirectiveLine reads the `go` directive from go.mod with the same
// loose line scan repository.goModDirective applies — the skip path uses
// it when the strict modfile parse yielded nothing.
func goDirectiveLine(root string) string {
	b, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "go ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "go "))
		}
	}
	return ""
}

// snapshotCommit resolves the snapshot's commit identity. A live .git wins
// (`git rev-parse HEAD`, audited); otherwise --commit, else the
// benchmark-layout basename when it is a full SHA.
func snapshotCommit(ctx context.Context, o Options, root string) (commit, source string, err error) {
	if _, statErr := os.Stat(filepath.Join(root, ".git")); statErr == nil {
		out, stderr, runErr := toolaudit.Run(ctx, "git", "", root, "git", nil, "rev-parse", "HEAD")
		if runErr != nil {
			return "", "", fmt.Errorf("git rev-parse HEAD: %w (%s)", runErr, strings.TrimSpace(string(stderr)))
		}
		return strings.TrimSpace(string(out)), "git_rev_parse", nil
	}
	if o.Commit != "" {
		if !commitSHARx.MatchString(o.Commit) {
			return "", "", fmt.Errorf("--commit %q is not a full 40-hex commit SHA", o.Commit)
		}
		return o.Commit, "--commit", nil
	}
	if base := filepath.Base(filepath.Clean(root)); commitSHARx.MatchString(base) {
		return base, "directory_basename", nil
	}
	return "", "", fmt.Errorf("snapshot has no .git and basename %q is not a commit SHA; pass --commit <sha>", filepath.Base(root))
}

// moduleGraphFacts parses go.mod / go.work / go.sum / vendor/modules.txt
// directly — a file-level view only. No go command is run against the
// snapshot: the tree stays untouched and the reading cannot be steered by
// generated code.
func moduleGraphFacts(root string) (ModuleGraph, []Fact) {
	mg := ModuleGraph{Method: "file-level read (no go command executed against the snapshot)"}
	var facts []Fact

	gomodPath := filepath.Join(root, "go.mod")
	if b, err := os.ReadFile(gomodPath); err == nil {
		mg.GoModPresent = true
		if f, perr := modfile.Parse("go.mod", b, nil); perr == nil {
			if f.Module != nil {
				mg.ModulePath = f.Module.Mod.Path
				facts = append(facts, Fact{
					Statement: "main module is " + mg.ModulePath,
					Reference: "go.mod",
					Source:    "snapshot",
				})
			}
			if f.Go != nil {
				mg.GoDirective = f.Go.Version
			}
			if f.Toolchain != nil {
				mg.Toolchain = f.Toolchain.Name
			}
			mg.RequireCount = len(f.Require)
			mg.ReplaceCount = len(f.Replace)
			for _, r := range f.Replace {
				if isLocalReplaceTarget(r.New.Path) {
					mg.LocalReplace = append(mg.LocalReplace, r.Old.Path+" => "+r.New.Path)
				}
			}
			facts = append(facts, Fact{
				Statement: fmt.Sprintf("go.mod declares %d requirements, %d replace directives (go %s)",
					mg.RequireCount, mg.ReplaceCount, mg.GoDirective),
				Reference: "go.mod",
				Source:    "snapshot",
			})
		}
	}

	if b, err := os.ReadFile(filepath.Join(root, "go.sum")); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.TrimSpace(line) != "" {
				mg.GoSumEntries++
			}
		}
	}

	if b, err := os.ReadFile(filepath.Join(root, "go.work")); err == nil {
		mg.GoWorkPresent = true
		if f, perr := modfile.ParseWork("go.work", b, nil); perr == nil {
			mg.GoWorkUseCount = len(f.Use)
		}
	}

	if b, err := os.ReadFile(filepath.Join(root, "vendor", "modules.txt")); err == nil {
		mg.VendorModulesTxt = true
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "# ") {
				mg.VendorCount++
			}
		}
	}
	return mg, facts
}

func isLocalReplaceTarget(p string) bool {
	return strings.HasPrefix(p, "./") || strings.HasPrefix(p, "../") || filepath.IsAbs(p)
}

// relRef renders a reference to a path inside the snapshot relative to its
// root; empty rel means the root itself.
func relRef(root, p string) string {
	if p == "" {
		return filepath.Base(root) + "/"
	}
	if rel, err := filepath.Rel(root, p); err == nil && !strings.HasPrefix(rel, "..") {
		return rel
	}
	return p
}

package repository

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/davniy/izyan/internal/gitlock"
	domain "github.com/davniy/izyan/internal/productb/domain"
	"github.com/davniy/izyan/internal/toolaudit"
)

type SnapshotOptions struct {
	GOOS      string
	GOARCH    string
	BuildTags []string
	// BinaryPath points at the release-built artifact. When set, the embedded
	// build info (`go version -m`) supplies the real toolchain and module
	// versions — the ground truth a ticket refers to, unlike go.mod which is
	// only a minimum.
	BinaryPath string
	// ReleaseGoVersion is the toolchain version that built the release, when
	// known from the ticket/pipeline metadata.
	ReleaseGoVersion string
	// TrustedPeer indicates the service communicates strictly with trusted peers
	// in trusted infrastructure.
	TrustedPeer bool
	// DeployManifests specifies explicit paths to Kubernetes/Helm/deployment manifests.
	DeployManifests []string
	// DeployArchive specifies path to zip/tar archive containing deployment manifests.
	DeployArchive string
	// PerimeterOverride overrides auto-detected perimeter classification.
	PerimeterOverride string
	// ExternalCommitSHA supplies the snapshot identity from an external
	// controller (benchmark). When set, the snapshot carries no local git
	// history: no git command runs, and Commit is taken from this value.
	ExternalCommitSHA string
	// GoBin is the analysis toolchain's go binary used for the `go version`
	// probe (and passed as env). Empty means "go" from PATH.
	GoBin string
	// Env is the resolved analysis toolchain environment; it is passed to
	// the snapshot probe so GoVersion describes the analysis environment
	// consistently with the other tools.
	Env []string
}

type Snapshotter interface {
	Snapshot(ctx context.Context, path string, opts SnapshotOptions) (domain.ProductSnapshot, error)
}

type Service struct{}

func (Service) Snapshot(ctx context.Context, path string, opts SnapshotOptions) (domain.ProductSnapshot, error) {
	external := opts.ExternalCommitSHA != ""
	var commit string
	if external {
		// External snapshots carry no git history: the controller is the
		// only identity source, and no git command must run.
		commit = opts.ExternalCommitSHA
	} else {
		var err error
		commit, err = commandWith(ctx, path, opts, "git", "rev-parse", "HEAD")
		if err != nil {
			return domain.ProductSnapshot{}, fmt.Errorf("resolve git commit: %w", err)
		}
	}
	goversion, err := commandWith(ctx, path, opts, "go", "version")
	if err != nil {
		return domain.ProductSnapshot{}, fmt.Errorf("go version: %w", err)
	}
	gomod := goModDirective(path)
	releaseGo := opts.ReleaseGoVersion
	var releaseSource domain.GoVersionSource
	if releaseGo != "" {
		releaseSource = domain.GoVersionSourceExplicit
	}
	if opts.BinaryPath != "" {
		if v, berr := binaryGoVersion(ctx, opts.BinaryPath); berr == nil && v != "" {
			releaseGo = v // embedded build info wins over ticket metadata
			releaseSource = domain.GoVersionSourceBinary
		}
	}
	if releaseGo == "" {
		// No operator-provided release version: discover snapshot-local
		// evidence. Absence stays UNKNOWN — never substitute go.mod or the
		// analysis toolchain.
		if ev := DiscoverReleaseEvidence(path); ev.Version != "" {
			releaseGo = ev.Version
			releaseSource = ev.Source
		}
	}
	goos := opts.GOOS
	if goos == "" {
		goos = runtime.GOOS
	}
	goarch := opts.GOARCH
	if goarch == "" {
		goarch = runtime.GOARCH
	}
	snap := domain.ProductSnapshot{
		Repository:        path,
		Commit:            commit,
		GoVersion:         goversion,
		GoModDirective:    gomod,
		MinimumGoVersion:  gomod,
		ReleaseGoVersion:  releaseGo,
		GoVersionSource:   releaseSource,
		BinaryPath:        opts.BinaryPath,
		GOOS:              goos,
		GOARCH:            goarch,
		BuildTags:         opts.BuildTags,
		TrustedPeer:       opts.TrustedPeer,
		DeployManifests:   opts.DeployManifests,
		DeployArchive:     opts.DeployArchive,
		PerimeterOverride: opts.PerimeterOverride,
	}
	if external {
		snap.ExternalCommitSHA = opts.ExternalCommitSHA
		if err := VerifyContained(path); err != nil {
			return domain.ProductSnapshot{}, fmt.Errorf("snapshot containment: %w", err)
		}
		if err := CheckPathReplacements(path); err != nil {
			return domain.ProductSnapshot{}, fmt.Errorf("snapshot preflight: %w", err)
		}
		hash, err := ContentHash(path)
		if err != nil {
			return domain.ProductSnapshot{}, fmt.Errorf("content hash: %w", err)
		}
		snap.ContentHash = hash
	}
	return snap, nil
}

// commandWith runs name args honouring the analysis toolchain binary/env from
// opts. For the go probe, opts.GoBin overrides "go" and opts.Env is appended.
func commandWith(ctx context.Context, dir string, opts SnapshotOptions, name string, args ...string) (string, error) {
	bin := name
	var env []string
	if name == "go" {
		if opts.GoBin != "" {
			bin = opts.GoBin
		}
		env = opts.Env
	}
	b, _, err := toolaudit.Run(ctx, name, "", dir, bin, env, args...)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// BinaryGoVersion reports the toolchain version embedded in a Go binary —
// used to select the analysis toolchain when --binary is provided without
// an explicit --release-go-version.
func BinaryGoVersion(ctx context.Context, bin string) (string, error) {
	return binaryGoVersion(ctx, bin)
}

// BinaryBuildInfo returns the full `go version -m` output for a release
// binary: embedded toolchain, module versions and build settings — the
// artifact's own runtime facts, authoritative over go.mod claims.
func BinaryBuildInfo(ctx context.Context, bin string) (string, error) {
	return command(ctx, filepath.Dir(bin), "go", "version", "-m", bin)
}

// binaryGoVersion extracts the toolchain embedded in a Go binary via
// `go version -m`: the first line ends with the toolchain version.
func binaryGoVersion(ctx context.Context, bin string) (string, error) {
	out, err := BinaryBuildInfo(ctx, bin)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(out, "\n") {
		if i := strings.Index(line, ": go"); i >= 0 {
			return strings.TrimSpace(line[i+2:]), nil
		}
	}
	return "", fmt.Errorf("no toolchain in go version -m output")
}

// goModDirective returns the `go` directive of the module's go.mod — the
// minimum toolchain the module declares. The release binary may have been
// built with a newer toolchain, which matters for stdlib advisories.
func goModDirective(path string) string {
	b, err := os.ReadFile(filepath.Join(path, "go.mod"))
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

func command(ctx context.Context, dir, name string, args ...string) (string, error) {
	return commandEnv(ctx, dir, name, nil, args...)
}

// commandEnv is command with extra environment bindings appended to the
// ambient environment. It is the only channel credential material reaches a
// subprocess through: env values are never recorded in toolaudit trails or
// echoed into errors.
func commandEnv(ctx context.Context, dir, name string, env []string, args ...string) (string, error) {
	b, _, err := toolaudit.Run(ctx, filepath.Base(name), "", dir, name, env, args...)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// ResolveRef resolves a version, release string, branch name, or tag to a canonical ref name
// and commit SHA in the given git repository.
func ResolveRef(ctx context.Context, repoPath, releaseOrRef string) (string, string, error) {
	releaseOrRef = strings.TrimSpace(releaseOrRef)
	if releaseOrRef == "" {
		return "", "", fmt.Errorf("empty release or ref specified")
	}

	// Try prioritized candidates first
	for _, cand := range refCandidates(releaseOrRef) {
		sha, err := command(ctx, repoPath, "git", "rev-parse", "--verify", "--quiet", cand+"^{commit}")
		if err == nil && sha != "" {
			return cand, sha, nil
		}
	}

	// Fallback: search git tag list for fuzzy matches
	tagsOut, err := command(ctx, repoPath, "git", "tag", "-l")
	if err == nil && tagsOut != "" {
		tags := strings.Split(tagsOut, "\n")
		normalizedTarget := normalizeRef(releaseOrRef)
		for _, tag := range tags {
			tag = strings.TrimSpace(tag)
			if tag == "" {
				continue
			}
			if normalizeRef(tag) == normalizedTarget {
				sha, err := command(ctx, repoPath, "git", "rev-parse", "--verify", "--quiet", tag+"^{commit}")
				if err == nil && sha != "" {
					return tag, sha, nil
				}
			}
		}
	}

	return "", "", fmt.Errorf("release or git ref %q not found in repository", releaseOrRef)
}

func refCandidates(ref string) []string {
	s := strings.TrimSpace(ref)
	if s == "" {
		return nil
	}
	var list []string
	seen := make(map[string]bool)
	add := func(c string) {
		c = strings.TrimSpace(c)
		if c != "" && !seen[c] {
			seen[c] = true
			list = append(list, c)
		}
	}

	// 1. Direct ref as passed
	add(s)

	// 2. Trim / add 'v' prefix
	noV := strings.TrimPrefix(s, "v")
	add("v" + noV)
	add(noV)

	// 3. Common release branch/tag prefixes
	add("release/" + s)
	add("release/" + noV)
	add("release/v" + noV)
	add("rel-" + s)
	add("rel-" + noV)
	add("tags/" + s)
	add("tags/v" + noV)

	// 4. If 2 segments (e.g. 24.2 or 2.0), try appending .0
	parts := strings.Split(noV, ".")
	if len(parts) == 2 {
		dotZero := noV + ".0"
		add(dotZero)
		add("v" + dotZero)
		add("release/" + dotZero)
		add("release/v" + dotZero)
		add("rel-" + dotZero)
	}

	return list
}

func normalizeRef(r string) string {
	r = strings.ToLower(strings.TrimSpace(r))
	r = strings.TrimPrefix(r, "refs/tags/")
	r = strings.TrimPrefix(r, "release/")
	r = strings.TrimPrefix(r, "rel-")
	r = strings.TrimPrefix(r, "tags/")
	r = strings.TrimPrefix(r, "v")
	return r
}

// RefInfo is one enumerated git ref: a read-only listing entry the triage
// ref enumerator turns into a bounded candidate. Commit is always the
// peeled commit SHA — annotated tags report their target commit, never the
// tag object.
type RefInfo struct {
	Name   string
	Kind   string
	Commit string
}

// EnumerateRefs lists local git refs under refs/tags, refs/releases and
// refs/heads in deterministic name order. It performs a single read-only
// `git for-each-ref` query — no checkout, no HEAD, no remote access. Refs
// that do not resolve to a commit (e.g. tags of blobs or trees) are skipped.
// max bounds the result after sorting; 0 returns all refs, negative errors.
func EnumerateRefs(ctx context.Context, repoPath string, max int) ([]RefInfo, error) {
	if max < 0 {
		return nil, fmt.Errorf("EnumerateRefs: negative bound %d", max)
	}
	out, err := command(ctx, repoPath, "git", "for-each-ref",
		"--format=%(refname)%09%(objecttype)%09%(objectname)%09%(*objectname)",
		"refs/tags", "refs/releases", "refs/heads")
	if err != nil {
		return nil, fmt.Errorf("EnumerateRefs: %w", err)
	}

	var refs []RefInfo
	for _, line := range strings.Split(out, "\n") {
		fields := strings.SplitN(strings.TrimRight(line, "\n"), "\t", 4)
		// The last output line may carry only 3 fields: an empty
		// %(*objectname) column is not emitted at end of output (and
		// command() trims trailing whitespace anyway). The peeled field is
		// only meaningful for annotated tags; commit-type objects never
		// need it, so a 3-field line stays valid.
		if len(fields) < 3 {
			continue
		}
		refname, objtype, oid := fields[0], fields[1], fields[2]
		var peeled string
		if len(fields) == 4 {
			peeled = fields[3]
		}
		commit := oid
		if objtype == "tag" {
			commit = peeled
		}
		if objtype != "commit" && objtype != "tag" {
			continue
		}
		if commit == "" {
			continue
		}
		name, kind := enumRefNameKind(refname)
		if name == "" {
			continue
		}
		refs = append(refs, RefInfo{Name: name, Kind: kind, Commit: commit})
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].Name < refs[j].Name })
	if max > 0 && len(refs) > max {
		refs = refs[:max]
	}
	return refs, nil
}

// enumRefNameKind maps a full refname to its short name and ref kind.
// refs/releases and release-style tag names (release/*, release-*, rel-*)
// classify as "release" — the immutable published-release surface — while
// every heads ref stays a mutable "branch" regardless of its name.
func enumRefNameKind(refname string) (string, string) {
	for _, p := range []struct {
		prefix string
		kind   string
	}{
		{"refs/releases/", "release"},
		{"refs/tags/", "tag"},
		{"refs/heads/", "branch"},
	} {
		if strings.HasPrefix(refname, p.prefix) {
			name := strings.TrimPrefix(refname, p.prefix)
			if p.kind == "tag" && isReleaseRefName(name) {
				return name, "release"
			}
			return name, p.kind
		}
	}
	return "", ""
}

// isReleaseRefName reports whether a tag name follows the release naming
// conventions ResolveRef already recognises (release/*, release-*, rel-*).
func isReleaseRefName(name string) bool {
	return strings.HasPrefix(name, "release/") ||
		strings.HasPrefix(name, "release-") ||
		strings.HasPrefix(name, "rel-")
}

// The inter-process bound for worktree mutations is the OS file lock
// acquireWorktreeLock takes on <gitdir>/izyan-worktree.lock, held for the
// whole add/prune/remove critical section. Worktree metadata is shared
// repo state across every product lane (Product A internal/repository,
// this package, cmd/izyan remediate): two processes racing an add
// against another's prune or remove destroy each other's registration,
// so the lock must serialize every writer, not just this package's.

// ErrWorktreeCleanupSkipped marks a worktree cleanup that could not
// acquire the inter-process lock: the .git/worktrees removal is skipped
// (never run unlocked — an unlocked metadata mutation can corrupt a
// concurrent product's registration), the temporary directory contents
// are still deleted, and only the stale registration remains — a later
// locked `git worktree prune` reconciles it.
var ErrWorktreeCleanupSkipped = errors.New("worktree cleanup skipped: cannot take the inter-process worktree lock")

// acquireWorktreeLock is the injection seam for lock-failure tests; it
// defaults to gitlock.Acquire and is swapped only under test.
var acquireWorktreeLock = gitlock.Acquire

// NewWorktree creates an isolated git worktree at a temporary directory
// checked out to commitOrRef. The returned cleanup removes the worktree
// and its temporary directory; it reports ErrWorktreeCleanupSkipped
// instead of mutating .git/worktrees when the inter-process lock cannot
// be acquired — cleanup fails closed, never unlocked.
func NewWorktree(ctx context.Context, repoPath, commitOrRef string) (string, func() error, error) {
	commitOrRef = strings.TrimSpace(commitOrRef)
	if commitOrRef == "" {
		return "", nil, fmt.Errorf("empty commit or ref for worktree")
	}

	absRepo, err := filepath.Abs(repoPath)
	if err != nil {
		return "", nil, fmt.Errorf("resolve repo path: %w", err)
	}

	tmpDir, err := os.MkdirTemp("", "izyan-worktree-*")
	if err != nil {
		return "", nil, fmt.Errorf("create temp worktree dir: %w", err)
	}

	unlock, lockErr := acquireWorktreeLock(ctx, absRepo)
	if lockErr != nil {
		_ = os.RemoveAll(tmpDir)
		return "", nil, lockErr
	}
	_, addErr := command(ctx, absRepo, "git", "worktree", "add", "--detach", tmpDir, commitOrRef)
	if addErr != nil && worktreeRegistered(ctx, absRepo, tmpDir) {
		// Only prune when the failure is genuinely stale metadata: the repo
		// still registers a worktree at tmpDir even though we just created
		// and own it. Pruning shared metadata unconditionally on any add
		// error would delete live registrations mid-flight.
		_, pruneErr := command(ctx, absRepo, "git", "worktree", "prune")
		if pruneErr == nil {
			_, retryErr := command(ctx, absRepo, "git", "worktree", "add", "--detach", tmpDir, commitOrRef)
			addErr = retryErr
		}
	}
	unlock()
	if addErr != nil {
		_ = os.RemoveAll(tmpDir)
		return "", nil, fmt.Errorf("git worktree add: %w", addErr)
	}

	var once sync.Once
	var cleanErr error
	cleanup := func() error {
		once.Do(func() {
			cleanCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			unlock, lerr := acquireWorktreeLock(cleanCtx, absRepo)
			if lerr != nil {
				cleanErr = fmt.Errorf("%w: %v", ErrWorktreeCleanupSkipped, lerr)
			} else {
				_, _ = command(cleanCtx, absRepo, "git", "worktree", "remove", "--force", tmpDir)
				unlock()
			}
			// Removing our own temp files is not a shared-metadata
			// mutation and always runs; a RemoveAll failure is reported
			// when it is the only problem.
			if rmErr := os.RemoveAll(tmpDir); rmErr != nil && cleanErr == nil {
				cleanErr = rmErr
			}
		})
		return cleanErr
	}

	return tmpDir, cleanup, nil
}

// worktreeRegistered reports whether `git worktree list` already knows the
// given path — the only condition under which a prune can help a failed
// add.
func worktreeRegistered(ctx context.Context, repoPath, dir string) bool {
	out, err := command(ctx, repoPath, "git", "worktree", "list", "--porcelain")
	if err != nil {
		return false
	}
	return strings.Contains(out, "worktree "+dir)
}

// CloneOptions bounds one isolated repository clone. CredentialEnv carries
// credential material (e.g. GIT_ASKPASS or header helper configuration) as
// environment bindings supplied by the caller's credential provider; the
// values reach the clone process environment only — never toolaudit
// records, errors or return values.
type CloneOptions struct {
	// Destination is the directory the clone is created at. It must not
	// exist: adopting a pre-existing path would admit content the clone did
	// not produce.
	Destination string
	// CredentialEnv holds environment bindings for the clone only.
	CredentialEnv []string
	// ExpectedCommit is the commit or ref the clone is checked out to.
	// After checkout the clone HEAD is re-resolved and must name the same
	// commit — a remote that cannot supply the expectation is an error,
	// never a silent HEAD materialization.
	ExpectedCommit string
}

// Clone materializes a remote repository into an isolated clone at
// opts.Destination and returns the resolved HEAD commit SHA. The clone is a
// full fetch (no depth or ref filtering) so every enumerated ref resolves
// locally afterwards. On any failure the destination is removed; the source
// repository is never modified.
func Clone(ctx context.Context, locator string, opts CloneOptions) (string, error) {
	locator = strings.TrimSpace(locator)
	if locator == "" {
		return "", fmt.Errorf("clone: empty locator")
	}
	dst := strings.TrimSpace(opts.Destination)
	if dst == "" {
		return "", fmt.Errorf("clone: empty destination")
	}
	abs, err := filepath.Abs(dst)
	if err != nil {
		return "", fmt.Errorf("clone: resolve destination: %w", err)
	}
	if _, err := os.Lstat(abs); err == nil {
		return "", fmt.Errorf("clone: destination %q already exists", dst)
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("clone: stat destination: %w", err)
	}

	if _, err := commandEnv(ctx, "", "git", opts.CredentialEnv, "clone", "--", locator, abs); err != nil {
		_ = os.RemoveAll(abs)
		return "", fmt.Errorf("git clone: %w", err)
	}
	fail := func(err error) (string, error) {
		_ = os.RemoveAll(abs)
		return "", err
	}

	expected := strings.TrimSpace(opts.ExpectedCommit)
	if expected != "" {
		if _, err := command(ctx, abs, "git", "rev-parse", "--verify", "--quiet", expected+"^{commit}"); err != nil {
			return fail(fmt.Errorf("clone: expected commit is absent from the remote"))
		}
		if _, err := command(ctx, abs, "git", "checkout", "--detach", expected); err != nil {
			return fail(fmt.Errorf("clone: checkout expected commit: %w", err))
		}
	}
	head, err := command(ctx, abs, "git", "rev-parse", "HEAD")
	if err != nil {
		return fail(fmt.Errorf("clone: resolve HEAD: %w", err))
	}
	return head, nil
}

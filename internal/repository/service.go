package repository

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/gitlock"
	"github.com/fedorovmv/izyan/internal/toolaudit"
	"golang.org/x/mod/modfile"
)

type SnapshotOptions struct {
	GOOS      string
	GOARCH    string
	BuildTags []string
	// CGO selects the cgo build mode for an operator-declared target. The
	// analyzer does not build the product, but the file selection it must
	// analyse is decided by this flag: a product whose only compilable path
	// needs cgo is unreadable when it is forced off. Nil keeps the analyzer
	// default (off); an explicit value is recorded on the resolved target.
	CGO *bool
	// BinaryPath points at the release-built artifact. When set, the embedded
	// build info (`go version -m`) supplies the real toolchain and module
	// versions — the ground truth a ticket refers to, unlike go.mod which is
	// only a minimum.
	BinaryPath string
	// ReleaseGoVersion is the toolchain version that built the release, when
	// known from the ticket/pipeline metadata.
	ReleaseGoVersion string
	// Artifact requests the bounded release-artifact channel: a local Go
	// binary/ZIP distribution or an HTTPS download whose embedded build
	// info is authoritative release evidence. Path and URL are mutually
	// exclusive.
	Artifact ArtifactOptions
	// ReleaseMetadata is the outcome of the explicitly supplied
	// ticket/SBOM release-metadata channel (--release-metadata), parsed
	// by the caller into a ReleaseEvidenceSummary. A resolved summary
	// joins the authoritative precedence set and contributes its module
	// graph; a failed channel is recorded as
	// NOT_RUN/RELEASE_METADATA_INVALID — Status/ReasonCode are the only
	// members read then, never silently ignored.
	ReleaseMetadata *domain.ReleaseEvidenceSummary
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
	// Build-selection context is resolved once, before any package load:
	// the vendor/module mode, the effective workspace (or its explicit
	// "off" record) and the effective GOFLAGS travel with the snapshot so
	// every probe applies one selection instead of inheriting its own.
	vendorMode := VendorModeInEffect(path)
	goWork, err := resolveGoWork(ctx, path, opts)
	if err != nil {
		return domain.ProductSnapshot{}, fmt.Errorf("go env GOWORK: %w", err)
	}
	envFlags, err := resolveEnvGoFlags(ctx, path, opts)
	if err != nil {
		return domain.ProductSnapshot{}, fmt.Errorf("go env GOFLAGS: %w", err)
	}
	goFlags := domain.EffectiveGoFlags(envFlags, vendorMode)
	var releaseItems []domain.ReleaseEvidenceItem
	var channelFailures []string
	if opts.ReleaseGoVersion != "" {
		if normalizeReleaseVersion(opts.ReleaseGoVersion) == "" {
			channelFailures = append(channelFailures, domain.ReleaseReasonReleaseVersionInvalid)
		} else {
			releaseItems = append(releaseItems, domain.ReleaseEvidenceItem{
				Version:    opts.ReleaseGoVersion,
				Source:     domain.GoVersionSourceExplicit,
				TrustClass: domain.ReleaseTrustAuthoritative,
			})
		}
	}
	binaryRequested := opts.BinaryPath != ""
	binaryRead := false
	var binaryTarget *domain.ProductTarget
	if binaryRequested {
		if v, berr := binaryGoVersion(ctx, opts.BinaryPath); berr == nil && v != "" {
			releaseItems = append(releaseItems, domain.ReleaseEvidenceItem{
				Version:    v,
				Source:     domain.GoVersionSourceBinary,
				TrustClass: domain.ReleaseTrustAuthoritative,
				Location:   ProvenanceLocalRef(opts.BinaryPath),
			})
			binaryRead = true
		}
		// The plain-binary channel reuses the digest-bound build-info
		// extraction. A target-only gap (build info read for the toolchain
		// but settings incomplete) is not a release-channel failure: the
		// measured toolchain stays usable, while the target falls through to
		// the next provenance source.
		if t, terr := buildInfoTargetFromPath(ctx, opts.BinaryPath); terr == nil {
			binaryTarget = t
		}
	}
	release := DiscoverReleaseEvidence(path)
	release.Items = append(releaseItems, release.Items...)
	release = ResolveReleaseEvidence(release.Items)
	// artifactTarget is the artifact channel's build-target fact, kept
	// separately so the target precedence survives the metadata merge
	// below: artifact build info wins over release metadata, which wins
	// over operator flags, which wins over the host default.
	var artifactTarget *domain.ProductTarget
	artifactRequested := opts.Artifact.Path != "" || opts.Artifact.URL != ""
	if artifactRequested {
		aopts := opts.Artifact
		aopts.ForbidDirs = append(append([]string{}, aopts.ForbidDirs...), path)
		if mod := goModModule(path); mod != "" {
			aopts.ProductModule = mod
		}
		res, aerr := ResolveReleaseArtifact(ctx, aopts)
		if aerr != nil {
			return domain.ProductSnapshot{}, fmt.Errorf("release artifact: %w", aerr)
		}
		if res.Status == domain.ReleaseStatusResolved {
			release.Items = append(release.Items, res.Evidence.Items...)
			release = ResolveReleaseEvidence(release.Items)
			release.ArtifactSHA256 = res.Evidence.ArtifactSHA256
			release.BinaryMember = res.Evidence.BinaryMember
			release.BuildInfoSHA256 = res.Evidence.BuildInfoSHA256
			release.Modules = res.Evidence.Modules
			artifactTarget = res.Target
			release.Target = res.Target
		} else {
			channelFailures = append(channelFailures, res.Reason)
		}
	}
	if supplied := opts.ReleaseMetadata; supplied != nil {
		prevModules := release.Modules
		release.Items = append(release.Items, supplied.Items...)
		release = ResolveReleaseEvidence(release.Items)
		release.Modules = append(release.Modules, prevModules...)
		release.Modules = append(release.Modules, supplied.Modules...)
		// Target precedence: the artifact's measured build info wins over
		// release-metadata declarations; a metadata-only run keeps the
		// metadata target. ResolveReleaseEvidence above rebuilds the
		// summary and drops the member, so it is restored explicitly.
		if artifactTarget != nil {
			release.Target = artifactTarget
		} else if supplied.Target != nil {
			release.Target = supplied.Target
		}
		if release.ArtifactSHA256 == "" {
			release.ArtifactSHA256 = supplied.ArtifactSHA256
		}
		if release.BinaryMember == "" {
			release.BinaryMember = supplied.BinaryMember
		}
		if release.BuildInfoSHA256 == "" {
			release.BuildInfoSHA256 = supplied.BuildInfoSHA256
		}
		if supplied.Status == domain.ReleaseStatusNotRun {
			reason := supplied.ReasonCode
			if reason == "" {
				reason = domain.ReleaseReasonMetadataInvalid
			}
			channelFailures = append(channelFailures, reason)
		}
	}
	if binaryRequested && !binaryRead {
		channelFailures = append(channelFailures, domain.ReleaseReasonArtifactBuildInfoUnreadable)
	}
	if len(channelFailures) > 0 {
		release.RequiredChannelFailures = append([]string{}, channelFailures...)
	}
	if len(channelFailures) > 0 && release.Status != domain.ReleaseStatusResolved && release.Status != domain.ReleaseStatusConflicted {
		release.Status = domain.ReleaseStatusNotRun
		release.ReasonCode = channelFailures[0]
	}
	releaseGo := release.SelectedVersion
	releaseSource := release.SelectedSource
	// Build-target precedence: artifact build info → plain-binary build
	// info → release-metadata target → explicit operator flags → host
	// default. The typed target records which source won; only a non-host
	// source may ground a platform-scoped affected-chain conclusion, and a
	// product-wide one additionally needs an admitted supported-targets
	// assumption.
	target := resolveProductTarget(artifactTarget, binaryTarget, release.Target, opts)
	snap := domain.ProductSnapshot{
		Repository:        path,
		Commit:            commit,
		GoVersion:         goversion,
		GoModDirective:    gomod,
		MinimumGoVersion:  gomod,
		ReleaseGoVersion:  releaseGo,
		GoVersionSource:   releaseSource,
		BinaryPath:        opts.BinaryPath,
		GOOS:              target.GOOS,
		GOARCH:            target.GOARCH,
		BuildTags:         target.BuildTags,
		CGOEnabled:        target.CGOEnabled,
		Target:            &target,
		VendorMode:        vendorMode,
		GoWorkFile:        goWork,
		GoFlags:           goFlags,
		ReplaceDirectives: ReplaceDirectives(path, goWork),
		TrustedPeer:       opts.TrustedPeer,
		DeployManifests:   opts.DeployManifests,
		DeployArchive:     opts.DeployArchive,
		PerimeterOverride: opts.PerimeterOverride,
	}
	// The resolved summary travels with the snapshot: every item keeps its
	// trust class and provenance, and ReleaseGoVersion mirrors only the
	// AUTHORITATIVE selection (empty when the release toolchain is not
	// authoritatively known).
	snap.ReleaseEvidence = &release
	snap.ReleaseModules = release.Modules
	snap.ReleaseEvidenceRequired = binaryRequested || artifactRequested || opts.ReleaseMetadata != nil
	if external {
		snap.ExternalCommitSHA = opts.ExternalCommitSHA
		if err := VerifyContained(path); err != nil {
			return domain.ProductSnapshot{}, fmt.Errorf("snapshot containment: %w", err)
		}
		if err := CheckPathReplacements(path); err != nil {
			return domain.ProductSnapshot{}, fmt.Errorf("snapshot preflight: %w", err)
		}
	}
	hash, err := ContentHash(path)
	if err != nil {
		return domain.ProductSnapshot{}, fmt.Errorf("content hash: %w", err)
	}
	snap.ContentHash = hash
	return snap, nil
}

// resolveProductTarget applies the recorded target precedence:
//
//  1. artifact build info, bound to the artifact/build-info digests;
//  2. plain-binary build info, bound to the binary's digest;
//  3. release-metadata build-target facts;
//  4. explicit operator --goos/--goarch facts (both required — a
//     half-declared platform keeps its existing host-filled analysis
//     values but is recorded as a host default, never as a target);
//  5. the analyzer host, valid for ordinary analysis only.
//
// A missing/nil higher-precedence target falls through; an invalid
// higher-precedence target was already rejected by its channel.
func resolveProductTarget(artifact, binary, release *domain.ProductTarget, opts SnapshotOptions) domain.ProductTarget {
	if artifact != nil && artifact.Validate() == nil {
		return *artifact
	}
	if binary != nil && binary.Validate() == nil {
		return *binary
	}
	if release != nil && release.Validate() == nil {
		return *release
	}
	tags := append([]string(nil), opts.BuildTags...)
	if opts.GOOS != "" && opts.GOARCH != "" {
		cgo := false
		if opts.CGO != nil {
			cgo = *opts.CGO
		}
		return domain.ProductTarget{
			GOOS:       opts.GOOS,
			GOARCH:     opts.GOARCH,
			BuildTags:  tags,
			Source:     domain.ProductTargetSourceOperatorDeclared,
			Scope:      domain.ProductTargetScopeOperator,
			CGOEnabled: cgo,
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
	return domain.ProductTarget{
		GOOS:      goos,
		GOARCH:    goarch,
		BuildTags: tags,
		Source:    domain.ProductTargetSourceHostDefault,
	}
}

// resolveGoWork asks the analysis toolchain which workspace the snapshot
// build would apply. An inactive workspace is recorded as the explicit
// "off" value so every probe disables workspace mode instead of inheriting
// or auto-discovering a different one.
func resolveGoWork(ctx context.Context, path string, opts SnapshotOptions) (string, error) {
	out, err := commandWith(ctx, path, opts, "go", "env", "GOWORK")
	if err != nil {
		return "", err
	}
	if v := strings.TrimSpace(out); v != "" && v != domain.GoWorkOff {
		return v, nil
	}
	return domain.GoWorkOff, nil
}

// resolveEnvGoFlags reads the GOFLAGS the toolchain policy resolved for this
// build (ambient GOFLAGS plus the caller's env), before the implicit vendor
// default is composed by domain.EffectiveGoFlags.
func resolveEnvGoFlags(ctx context.Context, path string, opts SnapshotOptions) (string, error) {
	out, err := commandWith(ctx, path, opts, "go", "env", "GOFLAGS")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// ReplaceDirectives returns the replace rules the snapshot build applies:
// the root go.mod's rules, followed by the effective workspace's rules when
// workspace mode is active. Manifest order is preserved so the recorded
// context is deterministic.
func ReplaceDirectives(root, goWork string) []domain.ReplaceDirective {
	out := parseReplaceDirectives(filepath.Join(root, "go.mod"), false)
	if goWork != "" && goWork != domain.GoWorkOff {
		out = append(out, parseReplaceDirectives(goWork, true)...)
	}
	return out
}

func parseReplaceDirectives(file string, workspace bool) []domain.ReplaceDirective {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil
	}
	var rules []*modfile.Replace
	if workspace {
		f, perr := modfile.ParseWork(filepath.Base(file), b, nil)
		if perr != nil {
			return nil
		}
		rules = f.Replace
	} else {
		f, perr := modfile.Parse(filepath.Base(file), b, nil)
		if perr != nil {
			return nil
		}
		rules = f.Replace
	}
	out := make([]domain.ReplaceDirective, 0, len(rules))
	for _, r := range rules {
		old := r.Old.Path
		if r.Old.Version != "" {
			old += "@" + r.Old.Version
		}
		tgt := r.New.Path
		if r.New.Version != "" {
			tgt += "@" + r.New.Version
		}
		out = append(out, domain.ReplaceDirective{Old: old, New: tgt})
	}
	return out
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
func GoModDirective(path string) string {
	return goModDirective(path)
}

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

// goModModule returns the module path declared in the snapshot's go.mod —
// used to prefer the artifact candidate whose main module matches the
// analyzed product when an archive carries several Go binaries.
func goModModule(path string) string {
	b, err := os.ReadFile(filepath.Join(path, "go.mod"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module "))
		}
	}
	return ""
}

func command(ctx context.Context, dir, name string, args ...string) (string, error) {
	b, _, err := toolaudit.Run(ctx, filepath.Base(name), "", dir, name, nil, args...)
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

// ErrWorktreeCleanupSkipped marks a worktree cleanup that could not
// acquire the inter-process lock: the .git/worktrees removal is skipped
// (never run unlocked — an unlocked metadata mutation can corrupt a
// concurrent product's registration), the temporary directory contents
// are still deleted, and only the stale registration remains — git's
// `worktree prune` reconciles it on a later locked mutation.
var ErrWorktreeCleanupSkipped = errors.New("worktree cleanup skipped: cannot take the inter-process worktree lock")

// acquireWorktreeLock is the injection seam for lock-failure tests; it
// defaults to gitlock.Acquire and is swapped only under test.
var acquireWorktreeLock = gitlock.Acquire

// NewWorktree creates an isolated git worktree at a temporary directory checked out
// to commitOrRef. The returned cleanup function removes the worktree and its
// temporary directory. Add and remove both run under the shared OS worktree
// lock: Product B's repository package and the remediate command mutate the
// same .git/worktrees metadata, so the critical section is process-wide,
// not this package's scheduler. Cleanup reports ErrWorktreeCleanupSkipped
// when the lock cannot be acquired — never an unlocked remove.
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
	_, err = command(ctx, absRepo, "git", "worktree", "add", "--detach", tmpDir, commitOrRef)
	unlock()
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		return "", nil, fmt.Errorf("git worktree add: %w", err)
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

// VendorModeInEffect reports whether the snapshot builds in vendor mode.
// The Go toolchain selects -mod=vendor by default (go >= 1.14) exactly when
// vendor/modules.txt exists, so that file is the authoritative signal. The
// result is a recorded snapshot fact, never an inference from package layout.
func VendorModeInEffect(root string) bool {
	st, err := os.Stat(filepath.Join(root, "vendor", "modules.txt"))
	return err == nil && !st.IsDir()
}

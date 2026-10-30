package repository

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

func setupTestGitRepo(t *testing.T) (string, map[string]string) {
	t.Helper()
	dir := t.TempDir()

	run := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Test",
			"GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=Test",
			"GIT_COMMITTER_EMAIL=test@example.com",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %s failed: %v, out: %s", strings.Join(args, " "), err, string(out))
		}
	}

	run("init")
	run("config", "user.name", "Test")
	run("config", "user.email", "test@example.com")

	commits := make(map[string]string)

	// Commit 1 -> tag v1.2.3
	f1 := filepath.Join(dir, "version.txt")
	if err := os.WriteFile(f1, []byte("v1.2.3"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "version.txt")
	run("commit", "-m", "release 1.2.3")
	run("tag", "v1.2.3")
	out, _ := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	commits["v1.2.3"] = strings.TrimSpace(string(out))

	// Commit 2 -> tag release/2.0
	if err := os.WriteFile(f1, []byte("v2.0"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "version.txt")
	run("commit", "-m", "release 2.0")
	run("tag", "release/2.0")
	out, _ = exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	commits["release/2.0"] = strings.TrimSpace(string(out))

	// Commit 3 -> tag 2026.1
	if err := os.WriteFile(f1, []byte("2026.1"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "version.txt")
	run("commit", "-m", "release 2026.1")
	run("tag", "2026.1")
	out, _ = exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	commits["2026.1"] = strings.TrimSpace(string(out))

	return dir, commits
}

func TestResolveRef(t *testing.T) {
	repoDir, commits := setupTestGitRepo(t)
	ctx := context.Background()

	cases := []struct {
		input       string
		wantRef     string
		wantSHA     string
		expectError bool
	}{
		{input: "v1.2.3", wantRef: "v1.2.3", wantSHA: commits["v1.2.3"]},
		{input: "1.2.3", wantRef: "v1.2.3", wantSHA: commits["v1.2.3"]},
		{input: "release/2.0", wantRef: "release/2.0", wantSHA: commits["release/2.0"]},
		{input: "2.0", wantRef: "release/2.0", wantSHA: commits["release/2.0"]},
		{input: "2026.1", wantRef: "2026.1", wantSHA: commits["2026.1"]},
		{input: commits["v1.2.3"], wantRef: commits["v1.2.3"], wantSHA: commits["v1.2.3"]},
		{input: "9.9.9", expectError: true},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			ref, sha, err := ResolveRef(ctx, repoDir, tc.input)
			if tc.expectError {
				if err == nil {
					t.Fatalf("expected error for %q, got ref=%q, sha=%q", tc.input, ref, sha)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.input, err)
			}
			if ref != tc.wantRef {
				t.Errorf("ref = %q, want %q", ref, tc.wantRef)
			}
			if sha != tc.wantSHA {
				t.Errorf("sha = %q, want %q", sha, tc.wantSHA)
			}
		})
	}
}

func TestNewWorktree(t *testing.T) {
	repoDir, commits := setupTestGitRepo(t)
	ctx := context.Background()

	targetSHA := commits["v1.2.3"]
	wtPath, cleanup, err := NewWorktree(ctx, repoDir, targetSHA)
	if err != nil {
		t.Fatalf("NewWorktree failed: %v", err)
	}
	defer func() { _ = cleanup() }()

	// Verify worktree exists
	if fi, err := os.Stat(wtPath); err != nil || !fi.IsDir() {
		t.Fatalf("worktree path %s is not a directory: %v", wtPath, err)
	}

	// Verify content is from v1.2.3
	vFile := filepath.Join(wtPath, "version.txt")
	content, err := os.ReadFile(vFile)
	if err != nil {
		t.Fatalf("read version.txt in worktree: %v", err)
	}
	if string(content) != "v1.2.3" {
		t.Errorf("content = %q, want v1.2.3", string(content))
	}

	// Run cleanup and verify removal
	if err := cleanup(); err != nil {
		t.Fatalf("worktree cleanup: %v", err)
	}
	if _, err := os.Stat(wtPath); !os.IsNotExist(err) {
		t.Errorf("expected worktree %s to be removed after cleanup", wtPath)
	}
}

func TestService_Snapshot_DeployOptions(t *testing.T) {
	repoDir, _ := setupTestGitRepo(t)
	ctx := context.Background()

	opts := SnapshotOptions{
		DeployManifests:   []string{"k8s/svc.yaml", "helm/chart"},
		DeployArchive:     "archive.zip",
		PerimeterOverride: "cluster-internal",
		TrustedPeer:       true,
	}

	snap, err := Service{}.Snapshot(ctx, repoDir, opts)
	if err != nil {
		t.Fatalf("Service.Snapshot failed: %v", err)
	}

	if len(snap.DeployManifests) != 2 || snap.DeployManifests[0] != "k8s/svc.yaml" || snap.DeployManifests[1] != "helm/chart" {
		t.Errorf("snap.DeployManifests = %v, want %v", snap.DeployManifests, opts.DeployManifests)
	}
	if snap.DeployArchive != "archive.zip" {
		t.Errorf("snap.DeployArchive = %q, want %q", snap.DeployArchive, opts.DeployArchive)
	}
	if snap.PerimeterOverride != "cluster-internal" {
		t.Errorf("snap.PerimeterOverride = %q, want %q", snap.PerimeterOverride, opts.PerimeterOverride)
	}
	if !snap.TrustedPeer {
		t.Errorf("snap.TrustedPeer = false, want true")
	}
}

// Vendor mode is a recorded snapshot fact: the Go toolchain selects
// -mod=vendor by default exactly when vendor/modules.txt exists. The gate
// that grounds a vendor-inventory absence compares this fact against the
// evidence observation's build context, so a snapshot probe that leaves it
// unset silently blocks every negative on a vendored repository.
func TestService_Snapshot_VendorModeDetected(t *testing.T) {
	repoDir, _ := setupTestGitRepo(t)
	ctx := context.Background()

	snap, err := Service{}.Snapshot(ctx, repoDir, SnapshotOptions{})
	if err != nil {
		t.Fatalf("Service.Snapshot failed: %v", err)
	}
	if snap.VendorMode {
		t.Fatalf("VendorMode = true for a snapshot without vendor/modules.txt")
	}

	// A vendor directory WITHOUT modules.txt is not vendor mode.
	if err := os.MkdirAll(filepath.Join(repoDir, "vendor", "example.com", "dep"), 0o755); err != nil {
		t.Fatal(err)
	}
	snap, err = Service{}.Snapshot(ctx, repoDir, SnapshotOptions{})
	if err != nil {
		t.Fatalf("Service.Snapshot failed: %v", err)
	}
	if snap.VendorMode {
		t.Fatalf("VendorMode = true for vendor/ without modules.txt")
	}

	// vendor/modules.txt is the authoritative signal.
	if err := os.WriteFile(filepath.Join(repoDir, "vendor", "modules.txt"), []byte("# example.com/dep v1.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	snap, err = Service{}.Snapshot(ctx, repoDir, SnapshotOptions{})
	if err != nil {
		t.Fatalf("Service.Snapshot failed: %v", err)
	}
	if !snap.VendorMode {
		t.Fatalf("VendorMode = false for a snapshot with vendor/modules.txt")
	}
}

// snapshotFixture builds a minimal external snapshot root (git-free).
func snapshotFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeGoMod(t, dir, "")
	writeFile(t, filepath.Join(dir, "main.go"), "package main\n\nfunc main() {}\n")
	return dir
}

func snapshotOpts() SnapshotOptions {
	return SnapshotOptions{ExternalCommitSHA: "abc123def456"}
}

// A Dockerfile declaration is recorded as SUPPORTING evidence but leaves
// ReleaseGoVersion empty: a declarable build input cannot alone ground a
// version-based determination.
func TestSnapshot_ReleaseEvidenceDockerfileOnly(t *testing.T) {
	dir := snapshotFixture(t)
	writeFile(t, filepath.Join(dir, "Dockerfile"), "FROM golang:1.25.8 AS build\nRUN go build ./...\n")

	snap, err := Service{}.Snapshot(t.Context(), dir, snapshotOpts())
	if err != nil {
		t.Fatalf("snapshot failed: %v", err)
	}
	if snap.ReleaseGoVersion != "" || snap.GoVersionSource != "" {
		t.Fatalf("dockerfile grounded the release version: %q from %q",
			snap.ReleaseGoVersion, snap.GoVersionSource)
	}
	if snap.ReleaseEvidence == nil {
		t.Fatal("release evidence summary not recorded")
	}
	if snap.ReleaseEvidence.Status != domain.ReleaseStatusUnknown {
		t.Fatalf("status = %s, want UNKNOWN", snap.ReleaseEvidence.Status)
	}
	it := itemAt(t, snap.ReleaseEvidence.Items, domain.GoVersionSourceDockerfile)
	if it.TrustClass != domain.ReleaseTrustSupporting || it.Version != "go1.25.8" {
		t.Fatalf("dockerfile item = %+v", it)
	}
	// The go.mod minimum stays a separate fact, never the release version.
	if snap.MinimumGoVersion != "1.21" {
		t.Fatalf("minimum = %q, want 1.21", snap.MinimumGoVersion)
	}
}

// Explicitly supplied ticket metadata is authoritative: it resolves the
// release version even while supporting declarations exist, and a
// disagreeing declaration cannot override it.
func TestSnapshot_ReleaseEvidenceExplicitResolves(t *testing.T) {
	dir := snapshotFixture(t)
	writeFile(t, filepath.Join(dir, "Dockerfile"), "FROM golang:1.25.8 AS build\nRUN go build ./...\n")

	opts := snapshotOpts()
	opts.ReleaseGoVersion = "go1.42.0"
	snap, err := Service{}.Snapshot(t.Context(), dir, opts)
	if err != nil {
		t.Fatalf("snapshot failed: %v", err)
	}
	if snap.ReleaseGoVersion != "go1.42.0" || snap.GoVersionSource != domain.GoVersionSourceExplicit {
		t.Fatalf("release = %q from %q", snap.ReleaseGoVersion, snap.GoVersionSource)
	}
	if snap.ReleaseEvidence.Status != domain.ReleaseStatusResolved {
		t.Fatalf("status = %s, want RESOLVED", snap.ReleaseEvidence.Status)
	}
	if snap.ReleaseEvidence.SelectedTrust != domain.ReleaseTrustAuthoritative {
		t.Fatalf("selected trust = %q", snap.ReleaseEvidence.SelectedTrust)
	}
	// The disagreeing Dockerfile pin is kept as corroboration provenance,
	// not dropped and never promoted.
	it := itemAt(t, snap.ReleaseEvidence.Items, domain.GoVersionSourceDockerfile)
	if it.TrustClass != domain.ReleaseTrustSupporting {
		t.Fatalf("dockerfile corroboration item = %+v", it)
	}
}

// The release binary's embedded build info is authoritative. Both binary
// and explicit ticket metadata count; when they disagree the outcome is
// CONFLICTED with no selected version — never the first or newest value.
func TestSnapshot_ReleaseEvidenceBinaryVersusExplicit(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("test binary unavailable: %v", err)
	}
	binv, err := binaryGoVersion(context.Background(), exe)
	if err != nil || binv == "" {
		t.Skipf("test binary build info unreadable: %v", err)
	}

	// Agreeing pair: the explicit ticket value confirms the measured one.
	dir := snapshotFixture(t)
	opts := snapshotOpts()
	opts.BinaryPath = exe
	opts.ReleaseGoVersion = binv
	snap, err := Service{}.Snapshot(t.Context(), dir, opts)
	if err != nil {
		t.Fatalf("snapshot failed: %v", err)
	}
	if snap.ReleaseGoVersion != binv || snap.ReleaseEvidence.Status != domain.ReleaseStatusResolved {
		t.Fatalf("agreeing binary+ticket = %q (%s)", snap.ReleaseGoVersion, snap.ReleaseEvidence.Status)
	}

	// Conflicting pair: no version may be selected.
	dir = snapshotFixture(t)
	opts = snapshotOpts()
	opts.BinaryPath = exe
	opts.ReleaseGoVersion = "go1.18.1"
	snap, err = Service{}.Snapshot(t.Context(), dir, opts)
	if err != nil {
		t.Fatalf("snapshot failed: %v", err)
	}
	if snap.ReleaseEvidence.Status != domain.ReleaseStatusConflicted {
		t.Fatalf("conflicting binary+ticket = %s", snap.ReleaseEvidence.Status)
	}
	if snap.ReleaseEvidence.ReasonCode != domain.ReleaseReasonConflict {
		t.Fatalf("reason = %q, want %s", snap.ReleaseEvidence.ReasonCode, domain.ReleaseReasonConflict)
	}
	if snap.ReleaseGoVersion != "" || snap.GoVersionSource != "" {
		t.Fatalf("conflict selected %q from %q", snap.ReleaseGoVersion, snap.GoVersionSource)
	}
}

// The go.mod `go` directive and `toolchain` directive are declarations,
// not release facts: neither populates ReleaseGoVersion, the analysis
// toolchain observed by the snapshot probe is never promoted to the
// release toolchain, and the summary reports UNKNOWN/supporting-only with
// the minimum version kept as a distinct field.
func TestSnapshot_GoModMinimumNeverGroundsReleaseToolchain(t *testing.T) {
	dir := t.TempDir()
	writeGoMod(t, dir, "\ntoolchain go1.22.8\n")
	writeFile(t, filepath.Join(dir, "main.go"), "package main\n\nfunc main() {}\n")

	snap, err := Service{}.Snapshot(t.Context(), dir, snapshotOpts())
	if err != nil {
		t.Fatalf("snapshot failed: %v", err)
	}
	if snap.GoVersion == "" {
		t.Fatal("analysis toolchain was not observed")
	}
	if snap.ReleaseGoVersion != "" || snap.GoVersionSource != "" {
		t.Fatalf("declarations/analysis toolchain grounded the release version: %q from %q",
			snap.ReleaseGoVersion, snap.GoVersionSource)
	}
	if snap.MinimumGoVersion != "1.21" {
		t.Fatalf("minimum = %q, want the go.mod directive 1.21", snap.MinimumGoVersion)
	}
	sum := snap.ReleaseEvidence
	if sum == nil || sum.Status != domain.ReleaseStatusUnknown {
		t.Fatalf("summary = %+v, want UNKNOWN", sum)
	}
	if sum.ReasonCode != domain.ReleaseReasonSupportingOnly {
		t.Fatalf("reason = %q, want %s", sum.ReasonCode, domain.ReleaseReasonSupportingOnly)
	}
	if sum.SelectedVersion != "" || sum.SelectedTrust != "" {
		t.Fatalf("supporting-only summary carries a selection: %+v", sum)
	}
	for _, src := range []domain.GoVersionSource{domain.GoVersionSourceGoMod, domain.GoVersionSourceToolchain} {
		it := itemAt(t, sum.Items, src)
		if it.TrustClass != domain.ReleaseTrustSupporting {
			t.Fatalf("%s item trust = %q, want SUPPORTING", src, it.TrustClass)
		}
	}
}

// The release binary's embedded build info outranks a disagreeing
// supporting declaration: the measured toolchain is selected and the
// declaration stays recorded as corroboration provenance.
func TestSnapshot_ReleaseEvidenceBinaryOutranksSupporting(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("test binary unavailable: %v", err)
	}
	binv, err := binaryGoVersion(context.Background(), exe)
	if err != nil || binv == "" {
		t.Skipf("test binary build info unreadable: %v", err)
	}
	// A supporting pin that provably disagrees with the measured binary:
	// the assertion cannot pass because both sides happen to match.
	supporting := "go1.18.1"
	if normalizeReleaseVersion(supporting) == normalizeReleaseVersion(binv) {
		supporting = "go1.19.2"
	}
	dir := snapshotFixture(t)
	writeFile(t, filepath.Join(dir, "Dockerfile"),
		"FROM golang:"+strings.TrimPrefix(supporting, "go")+" AS build\nRUN go build ./...\n")

	opts := snapshotOpts()
	opts.BinaryPath = exe
	snap, err := Service{}.Snapshot(t.Context(), dir, opts)
	if err != nil {
		t.Fatalf("snapshot failed: %v", err)
	}
	if snap.ReleaseGoVersion != binv || snap.GoVersionSource != domain.GoVersionSourceBinary {
		t.Fatalf("binary build info did not win: %q from %q (want %q from binary)",
			snap.ReleaseGoVersion, snap.GoVersionSource, binv)
	}
	if snap.ReleaseEvidence.Status != domain.ReleaseStatusResolved ||
		snap.ReleaseEvidence.SelectedVersion != binv ||
		snap.ReleaseEvidence.SelectedSource != domain.GoVersionSourceBinary {
		t.Fatalf("summary = %+v, want the binary selection", snap.ReleaseEvidence)
	}
	if it := itemAt(t, snap.ReleaseEvidence.Items, domain.GoVersionSourceDockerfile); it.TrustClass != domain.ReleaseTrustSupporting {
		t.Fatalf("dockerfile corroboration item = %+v", it)
	}
}

// An explicitly requested binary whose build info cannot be read is a
// fail-closed NOT_RUN outcome, not a silent absence.
func TestSnapshot_ReleaseEvidenceBinaryUnreadable(t *testing.T) {
	dir := snapshotFixture(t)
	missing := filepath.Join(dir, "no-such-binary")
	opts := snapshotOpts()
	opts.BinaryPath = missing

	snap, err := Service{}.Snapshot(t.Context(), dir, opts)
	if err != nil {
		t.Fatalf("snapshot failed: %v", err)
	}
	if snap.ReleaseEvidence == nil || snap.ReleaseEvidence.Status != domain.ReleaseStatusNotRun {
		t.Fatalf("unreadable requested binary = %+v", snap.ReleaseEvidence)
	}
	if snap.ReleaseEvidence.ReasonCode != domain.ReleaseReasonArtifactBuildInfoUnreadable {
		t.Fatalf("reason = %q, want %s", snap.ReleaseEvidence.ReasonCode, domain.ReleaseReasonArtifactBuildInfoUnreadable)
	}
	if !snap.ReleaseEvidenceRequired {
		t.Fatal("explicitly requested artifact not marked required")
	}
	if snap.ReleaseGoVersion != "" {
		t.Fatalf("release version populated despite failed artifact: %q", snap.ReleaseGoVersion)
	}
}

// Explicitly supplied ticket/SBOM metadata joins the authoritative
// precedence set: its item resolves the toolchain and its module list
// becomes the release module graph — Snapshot-level wiring for
// --release-metadata, without any artifact file involved.
func TestSnapshot_ReleaseMetadataResolves(t *testing.T) {
	dir := snapshotFixture(t)
	writeFile(t, filepath.Join(dir, "Dockerfile"), "FROM golang:1.25.8 AS build\n")

	opts := snapshotOpts()
	opts.ReleaseMetadata = &domain.ReleaseEvidenceSummary{
		Status: domain.ReleaseStatusResolved,
		Items: []domain.ReleaseEvidenceItem{{
			Version:    "go1.42.0",
			Source:     domain.GoVersionSourceExplicit,
			TrustClass: domain.ReleaseTrustAuthoritative,
		}},
		Modules: []domain.ReleaseModule{{Path: "example.com/dep", Version: "v1.4.0"}},
	}
	snap, err := Service{}.Snapshot(t.Context(), dir, opts)
	if err != nil {
		t.Fatalf("snapshot failed: %v", err)
	}
	if snap.ReleaseGoVersion != "go1.42.0" ||
		snap.ReleaseEvidence.Status != domain.ReleaseStatusResolved ||
		snap.ReleaseEvidence.SelectedTrust != domain.ReleaseTrustAuthoritative {
		t.Fatalf("metadata item must resolve: %q %s %s",
			snap.ReleaseGoVersion, snap.ReleaseEvidence.Status, snap.ReleaseEvidence.SelectedTrust)
	}
	if len(snap.ReleaseModules) != 1 || snap.ReleaseModules[0].Version != "v1.4.0" {
		t.Fatalf("metadata module graph must populate ReleaseModules: %+v", snap.ReleaseModules)
	}
	if !snap.ReleaseEvidenceRequired {
		t.Fatal("supplied release metadata must mark the evidence channel required")
	}
}

// Target precedence is artifact build info → release-metadata → explicit
// operator facts → host default. Every source conflict is won by the
// higher-precedence fact, and the snapshot fields always mirror the typed
// target record.
func TestSnapshot_TargetPrecedence(t *testing.T) {
	dir := snapshotFixture(t)
	buildDir := t.TempDir()
	exe := buildTestBinaryFor(t, buildDir, "example.com/targeted", "linux", "amd64", "netgo")
	releaseTarget := &domain.ProductTarget{
		GOOS: "windows", GOARCH: "386", Source: domain.ProductTargetSourceReleaseMetadata, Scope: domain.ProductTargetScopeRelease,
	}
	metadata := func(target *domain.ProductTarget) *domain.ReleaseEvidenceSummary {
		return &domain.ReleaseEvidenceSummary{
			Status: domain.ReleaseStatusResolved,
			Items: []domain.ReleaseEvidenceItem{{
				Version: "go1.42.0", Source: domain.GoVersionSourceExplicit, TrustClass: domain.ReleaseTrustAuthoritative,
			}},
			Target: target,
		}
	}

	// 1. Artifact build info wins over release metadata and operator flags.
	opts := snapshotOpts()
	opts.Artifact = artifactOpts(buildDir)
	opts.Artifact.Path = exe
	opts.ReleaseMetadata = metadata(releaseTarget)
	opts.GOOS, opts.GOARCH, opts.BuildTags = "darwin", "arm64", []string{"operator"}
	snap, err := Service{}.Snapshot(t.Context(), dir, opts)
	if err != nil {
		t.Fatalf("snapshot failed: %v", err)
	}
	if snap.Target == nil || snap.Target.Source != domain.ProductTargetSourceArtifactBuildInfo {
		t.Fatalf("artifact target did not win: %+v", snap.Target)
	}
	if snap.GOOS != "linux" || snap.GOARCH != "amd64" || snap.CGOEnabled {
		t.Fatalf("snapshot build facts = %s/%s cgo=%v, want artifact linux/amd64 cgo=false", snap.GOOS, snap.GOARCH, snap.CGOEnabled)
	}
	if strings.Join(snap.BuildTags, ",") != "netgo" {
		t.Fatalf("snapshot tags = %v, want artifact tags", snap.BuildTags)
	}
	if snap.ReleaseEvidence == nil || snap.ReleaseEvidence.Target == nil ||
		snap.ReleaseEvidence.Target.Source != domain.ProductTargetSourceArtifactBuildInfo {
		t.Fatalf("release evidence target = %+v", snap.ReleaseEvidence)
	}

	// 2. Release-metadata target wins over operator flags.
	opts = snapshotOpts()
	opts.ReleaseMetadata = metadata(&domain.ProductTarget{
		GOOS: "linux", GOARCH: "arm64", Source: domain.ProductTargetSourceReleaseMetadata, Scope: domain.ProductTargetScopeRelease,
	})
	opts.GOOS, opts.GOARCH = "darwin", "arm64"
	snap, err = Service{}.Snapshot(t.Context(), dir, opts)
	if err != nil {
		t.Fatalf("snapshot failed: %v", err)
	}
	if snap.Target == nil || snap.Target.Source != domain.ProductTargetSourceReleaseMetadata ||
		snap.GOOS != "linux" || snap.GOARCH != "arm64" {
		t.Fatalf("release-metadata target did not win: %+v (%s/%s)", snap.Target, snap.GOOS, snap.GOARCH)
	}

	// 3. Explicit operator facts (both axes) win over the host default.
	opts = snapshotOpts()
	opts.GOOS, opts.GOARCH, opts.BuildTags = "linux", "arm64", []string{"puretgo"}
	snap, err = Service{}.Snapshot(t.Context(), dir, opts)
	if err != nil {
		t.Fatalf("snapshot failed: %v", err)
	}
	if snap.Target == nil || snap.Target.Source != domain.ProductTargetSourceOperatorDeclared ||
		snap.Target.Scope != domain.ProductTargetScopeOperator ||
		snap.GOOS != "linux" || snap.GOARCH != "arm64" {
		t.Fatalf("operator target not recorded: %+v (%s/%s)", snap.Target, snap.GOOS, snap.GOARCH)
	}

	// 4. Without any declared target the host default is recorded as
	// such — present for ordinary analysis, never product-scoped.
	opts = snapshotOpts()
	snap, err = Service{}.Snapshot(t.Context(), dir, opts)
	if err != nil {
		t.Fatalf("snapshot failed: %v", err)
	}
	if snap.Target == nil || snap.Target.Source != domain.ProductTargetSourceHostDefault {
		t.Fatalf("host default target = %+v", snap.Target)
	}
	if snap.Target.Scoped() {
		t.Fatal("host-default target must not be product-scoped")
	}
	if snap.GOOS != runtime.GOOS || snap.GOARCH != runtime.GOARCH {
		t.Fatalf("host default = %s/%s, want %s/%s", snap.GOOS, snap.GOARCH, runtime.GOOS, runtime.GOARCH)
	}
}

// Plain --binary reuses the digest-bound build-info extraction: the
// binary's own embedded settings supply the target, bound to the binary's
// SHA-256 (artifact digest == build-info digest) with no archive member.
// It outranks release metadata and operator flags.
func TestSnapshot_BinaryTarget(t *testing.T) {
	dir := snapshotFixture(t)
	buildDir := t.TempDir()
	exe := buildTestBinaryFor(t, buildDir, "example.com/targeted", "linux", "amd64", "netgo,osusergo")
	wantSHA, _, err := hashFileSHA256(context.Background(), exe)
	if err != nil {
		t.Fatal(err)
	}

	opts := snapshotOpts()
	opts.BinaryPath = exe
	snap, err := Service{}.Snapshot(t.Context(), dir, opts)
	if err != nil {
		t.Fatalf("snapshot failed: %v", err)
	}
	target := snap.Target
	if target == nil ||
		target.Source != domain.ProductTargetSourceArtifactBuildInfo ||
		target.Scope != domain.ProductTargetScopeArtifact {
		t.Fatalf("binary target provenance = %+v", target)
	}
	if target.GOOS != "linux" || target.GOARCH != "amd64" || target.CGOEnabled {
		t.Fatalf("binary target platform = %s/%s cgo=%v", target.GOOS, target.GOARCH, target.CGOEnabled)
	}
	if strings.Join(target.BuildTags, ",") != "netgo,osusergo" {
		t.Fatalf("binary target tags = %v", target.BuildTags)
	}
	if target.ArtifactSHA256 != wantSHA || target.BuildInfoSHA256 != wantSHA {
		t.Fatalf("binary target digests = %q/%q, want %q for both",
			target.ArtifactSHA256, target.BuildInfoSHA256, wantSHA)
	}
	if target.BinaryMember != "" {
		t.Fatalf("plain binary target carries member %q, want empty", target.BinaryMember)
	}
	if err := target.Validate(); err != nil {
		t.Fatalf("binary target does not validate: %v", err)
	}
	if err := domain.ValidateNegativeTarget(snap); err != nil {
		t.Fatalf("binary target must admit a build-dependent negative: %v", err)
	}
	if snap.GOOS != "linux" || snap.GOARCH != "amd64" || snap.CGOEnabled ||
		strings.Join(snap.BuildTags, ",") != "netgo,osusergo" {
		t.Fatalf("snapshot build facts diverged from the binary target: %+v", snap)
	}
	if snap.BinaryPath != exe {
		t.Fatalf("snapshot binary path = %q, want %q", snap.BinaryPath, exe)
	}
	// The measured binary toolchain is independent of target extraction:
	// its release version must survive.
	if !strings.HasPrefix(snap.ReleaseGoVersion, "go") {
		t.Fatalf("measured binary toolchain lost: %q", snap.ReleaseGoVersion)
	}

	// Binary build info wins over release metadata and operator flags.
	opts = snapshotOpts()
	opts.BinaryPath = exe
	opts.ReleaseMetadata = &domain.ReleaseEvidenceSummary{
		Status: domain.ReleaseStatusResolved,
		Target: &domain.ProductTarget{
			GOOS: "windows", GOARCH: "386",
			Source: domain.ProductTargetSourceReleaseMetadata, Scope: domain.ProductTargetScopeRelease,
		},
	}
	opts.GOOS, opts.GOARCH, opts.BuildTags = "darwin", "arm64", []string{"operator"}
	snap, err = Service{}.Snapshot(t.Context(), dir, opts)
	if err != nil {
		t.Fatalf("snapshot failed: %v", err)
	}
	if snap.Target == nil || snap.Target.Source != domain.ProductTargetSourceArtifactBuildInfo ||
		snap.GOOS != "linux" || snap.GOARCH != "amd64" {
		t.Fatalf("binary target did not outrank release metadata/operator flags: %+v (%s/%s)",
			snap.Target, snap.GOOS, snap.GOARCH)
	}
}

// Partial operator platform input (one axis, or tags only) keeps the
// operator's analysis value on the declared axis and the host value on the
// other, but is recorded as host-default: it never becomes a product target
// and never admits a build-dependent negative.
func TestSnapshot_PartialOperator(t *testing.T) {
	dir := snapshotFixture(t)
	cases := []struct {
		name         string
		goos, goarch string
		tags         []string
		wantGOOS     string
		wantGOARCH   string
	}{
		{name: "goos only", goos: "linux", wantGOOS: "linux", wantGOARCH: runtime.GOARCH},
		{name: "goarch only", goarch: "arm64", wantGOOS: runtime.GOOS, wantGOARCH: "arm64"},
		{name: "tags only", tags: []string{"netgo"}, wantGOOS: runtime.GOOS, wantGOARCH: runtime.GOARCH},
		{name: "half platform with tags", goos: "linux", tags: []string{"netgo"}, wantGOOS: "linux", wantGOARCH: runtime.GOARCH},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := snapshotOpts()
			opts.GOOS, opts.GOARCH, opts.BuildTags = tc.goos, tc.goarch, tc.tags
			snap, err := Service{}.Snapshot(t.Context(), dir, opts)
			if err != nil {
				t.Fatalf("snapshot failed: %v", err)
			}
			if snap.Target == nil || snap.Target.Source != domain.ProductTargetSourceHostDefault {
				t.Fatalf("partial operator input recorded target %+v, want host-default", snap.Target)
			}
			if snap.Target.Scoped() || snap.Target.Scope != "" {
				t.Fatalf("host-default target must carry no product scope: %+v", snap.Target)
			}
			if snap.GOOS != tc.wantGOOS || snap.GOARCH != tc.wantGOARCH {
				t.Fatalf("analysis values = %s/%s, want %s/%s", snap.GOOS, snap.GOARCH, tc.wantGOOS, tc.wantGOARCH)
			}
			if strings.Join(snap.BuildTags, ",") != strings.Join(tc.tags, ",") {
				t.Fatalf("analysis tags = %v, want %v", snap.BuildTags, tc.tags)
			}
			if err := domain.ValidateNegativeTarget(snap); err == nil {
				t.Fatal("partial operator input admitted a build-dependent negative target")
			}
		})
	}
}

// A failed supplied metadata channel is a fail-closed NOT_RUN with its
// named reason — the snapshot must not silently degrade to supporting
// evidence or mask the failure behind an unrelated resolution.
func TestSnapshot_ReleaseMetadataNotRun(t *testing.T) {
	dir := snapshotFixture(t)
	opts := snapshotOpts()
	opts.ReleaseMetadata = &domain.ReleaseEvidenceSummary{
		Status:     domain.ReleaseStatusNotRun,
		ReasonCode: domain.ReleaseReasonMetadataInvalid,
	}
	snap, err := Service{}.Snapshot(t.Context(), dir, opts)
	if err != nil {
		t.Fatalf("snapshot failed: %v", err)
	}
	if snap.ReleaseEvidence.Status != domain.ReleaseStatusNotRun ||
		snap.ReleaseEvidence.ReasonCode != domain.ReleaseReasonMetadataInvalid {
		t.Fatalf("failed metadata channel = %s/%q",
			snap.ReleaseEvidence.Status, snap.ReleaseEvidence.ReasonCode)
	}
	if snap.ReleaseGoVersion != "" {
		t.Fatalf("release version populated despite failed metadata: %q", snap.ReleaseGoVersion)
	}
	if !snap.ReleaseEvidenceRequired {
		t.Fatal("requested metadata channel not marked required")
	}
}

// Metadata-supplied modules merge with artifact-graph modules instead of
// overwriting them: disagreeing duplicates stay visible so the resolver
// reports a conflict rather than picking a value.
func TestSnapshot_ReleaseMetadataModuleMerge(t *testing.T) {
	dir := snapshotFixture(t)
	opts := snapshotOpts()
	opts.ReleaseMetadata = &domain.ReleaseEvidenceSummary{
		Status: domain.ReleaseStatusResolved,
		Items: []domain.ReleaseEvidenceItem{{
			Version:    "go1.42.0",
			Source:     domain.GoVersionSourceExplicit,
			TrustClass: domain.ReleaseTrustAuthoritative,
		}},
		Modules: []domain.ReleaseModule{
			{Path: "example.com/a", Version: "v1.0.0"},
			{Path: "example.com/b", Version: "v2.0.0"},
		},
	}
	snap, err := Service{}.Snapshot(t.Context(), dir, opts)
	if err != nil {
		t.Fatalf("snapshot failed: %v", err)
	}
	if len(snap.ReleaseModules) != 2 {
		t.Fatalf("metadata modules: %+v", snap.ReleaseModules)
	}
}

// A failed requested artifact channel must stay visible even when another
// authoritative item resolves the toolchain: --release-go-version resolves
// the stdlib axis, but the artifact failure is recorded as a required
// channel failure so the module-graph axis stays blocked and the run is
// NOT_RUN for planner purposes.
func TestSnapshot_FailedArtifactMaskedByExplicit(t *testing.T) {
	dir := snapshotFixture(t)
	opts := snapshotOpts()
	opts.ReleaseGoVersion = "go1.30.2"
	opts.Artifact = ArtifactOptions{
		Path:     filepath.Join(dir, "missing.zip"),
		CacheDir: filepath.Join(t.TempDir(), "cache"),
	}

	snap, err := Service{}.Snapshot(t.Context(), dir, opts)
	if err != nil {
		t.Fatalf("snapshot failed: %v", err)
	}
	if snap.ReleaseGoVersion != "go1.30.2" {
		t.Fatalf("explicit toolchain must still select: %q", snap.ReleaseGoVersion)
	}
	re := snap.ReleaseEvidence
	if len(re.RequiredChannelFailures) != 1 ||
		re.RequiredChannelFailures[0] != domain.ReleaseReasonArtifactPathMissing {
		t.Fatalf("failed artifact channel masked: %+v", re.RequiredChannelFailures)
	}
	if !snap.ReleaseEvidenceRequired {
		t.Fatal("requested artifact not marked required")
	}

	// A failed requested metadata channel is equally unmaskable.
	dir = snapshotFixture(t)
	opts = snapshotOpts()
	opts.ReleaseGoVersion = "go1.30.2"
	opts.ReleaseMetadata = &domain.ReleaseEvidenceSummary{
		Status:     domain.ReleaseStatusNotRun,
		ReasonCode: domain.ReleaseReasonMetadataInvalid,
	}
	snap, err = Service{}.Snapshot(t.Context(), dir, opts)
	if err != nil {
		t.Fatalf("snapshot failed: %v", err)
	}
	if snap.ReleaseEvidence.RequiredChannelFailures == nil ||
		snap.ReleaseEvidence.RequiredChannelFailures[0] != domain.ReleaseReasonMetadataInvalid {
		t.Fatalf("failed metadata channel masked: %+v", snap.ReleaseEvidence.RequiredChannelFailures)
	}
}

// A malformed explicit release version is a required-channel failure, never
// silently dropped in favour of a competing authoritative source.
func TestSnapshot_MalformedExplicitReleaseVersion(t *testing.T) {
	dir := snapshotFixture(t)
	opts := snapshotOpts()
	opts.ReleaseGoVersion = "not-a-version"
	opts.ReleaseMetadata = &domain.ReleaseEvidenceSummary{
		Status: domain.ReleaseStatusResolved,
		Items: []domain.ReleaseEvidenceItem{{
			Version:    "go1.30.2",
			Source:     domain.GoVersionSourceExplicit,
			TrustClass: domain.ReleaseTrustAuthoritative,
		}},
	}
	snap, err := Service{}.Snapshot(t.Context(), dir, opts)
	if err != nil {
		t.Fatalf("snapshot failed: %v", err)
	}
	if len(snap.ReleaseEvidence.RequiredChannelFailures) == 0 ||
		snap.ReleaseEvidence.RequiredChannelFailures[0] != domain.ReleaseReasonReleaseVersionInvalid {
		t.Fatalf("malformed explicit version dropped: %+v", snap.ReleaseEvidence.RequiredChannelFailures)
	}
}

// TestWorktreeCleanupLockFailureFailsClosed injects a lock-acquisition
// failure at cleanup time: the .git/worktrees removal must NOT run
// unlocked — the cleanup reports ErrWorktreeCleanupSkipped, the
// registration stays for a later locked prune to reconcile, and only the
// temporary directory is removed.
func TestWorktreeCleanupLockFailureFailsClosed(t *testing.T) {
	repoDir, commits := setupTestGitRepo(t)
	dir, cleanup, err := NewWorktree(context.Background(), repoDir, commits["v1.2.3"])
	if err != nil {
		t.Fatalf("add: %v", err)
	}

	want := errors.New("injected lock failure")
	old := acquireWorktreeLock
	acquireWorktreeLock = func(context.Context, string) (func(), error) {
		return nil, want
	}
	err = cleanup()
	acquireWorktreeLock = old
	if !errors.Is(err, ErrWorktreeCleanupSkipped) {
		t.Fatalf("cleanup error = %v, want ErrWorktreeCleanupSkipped", err)
	}

	out, _ := exec.Command("git", "-C", repoDir, "worktree", "list", "--porcelain").CombinedOutput()
	if strings.Count(string(out), "worktree ") != 2 {
		t.Fatalf("expected stale registration to remain for reconcile:\n%s", out)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("worktree dir should still be removed: %v", err)
	}

	if _, err := exec.Command("git", "-C", repoDir, "worktree", "prune").CombinedOutput(); err != nil {
		t.Fatal(err)
	}
	out, _ = exec.Command("git", "-C", repoDir, "worktree", "list", "--porcelain").CombinedOutput()
	if strings.Count(string(out), "worktree ") != 1 {
		t.Fatalf("prune did not reconcile stale registration:\n%s", out)
	}
}

package triage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/fedorovmv/izyan/internal/productb/repository"
)

var fixedNow = func() time.Time { return time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC) }

// setupMaterializeSource builds a source repository with two commits:
// v1.2.3 (tagged) then a newer v2.0 HEAD.
func setupMaterializeSource(t *testing.T) (repo, shaV123, shaHead string) {
	t.Helper()
	dir := t.TempDir()
	gitCmd(t, dir, "init", "-q", "-b", "main")
	writeFile(t, filepath.Join(dir, "version.txt"), "v1.2.3")
	gitCmd(t, dir, "add", "version.txt")
	gitCmd(t, dir, "commit", "-q", "-m", "release 1.2.3")
	gitCmd(t, dir, "tag", "v1.2.3")
	shaV123 = gitOutput(t, dir, "rev-parse", "HEAD")
	writeFile(t, filepath.Join(dir, "version.txt"), "v2.0")
	gitCmd(t, dir, "add", "version.txt")
	gitCmd(t, dir, "commit", "-q", "-m", "release 2.0")
	shaHead = gitOutput(t, dir, "rev-parse", "HEAD")
	return dir, shaV123, shaHead
}

func tagCandidate(sourceID, name, commit string) RefCandidate {
	return RefCandidate{
		ID:          string(RefTag) + ":" + name,
		Name:        name,
		Kind:        RefTag,
		Commit:      commit,
		Source:      sourceID,
		PolicyScore: refPolicyScore(RefTag),
	}
}

func fileVersion(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "version.txt"))
	if err != nil {
		t.Fatalf("read version.txt in %s: %v", dir, err)
	}
	return string(b)
}

func mustError(t *testing.T, err error, substr string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", substr)
	}
	if substr != "" && !strings.Contains(err.Error(), substr) {
		t.Fatalf("error %q does not contain %q", err, substr)
	}
}

func TestMaterializeLocalDirectory(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.txt"), "alpha")
	wantHash, err := repository.ContentHash(dir)
	if err != nil {
		t.Fatalf("ContentHash: %v", err)
	}

	src, err := (Materializer{Now: fixedNow}).Materialize(ctx,
		CatalogEntry{ID: "example-local", Kind: "local", Root: dir},
		RefCandidate{}, MaterializationPolicy{})
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	canon, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	if src.Root != canon {
		t.Fatalf("local materialization must not copy: root = %q, want %q", src.Root, canon)
	}
	md := src.Metadata
	if md.Mode != MaterializationLocal {
		t.Fatalf("mode = %q, want %q", md.Mode, MaterializationLocal)
	}
	if md.SourceID != "example-local" {
		t.Fatalf("source_id = %q", md.SourceID)
	}
	if md.Locator != dir {
		t.Fatalf("locator = %q, want %q", md.Locator, dir)
	}
	if md.RootHash != wantHash {
		t.Fatalf("root_hash = %q, want %q", md.RootHash, wantHash)
	}
	if md.CreatedAt != "2026-10-16T12:00:00Z" {
		t.Fatalf("created_at = %q", md.CreatedAt)
	}
	if md.ResolvedCommit != "" {
		t.Fatalf("resolved_commit = %q, want empty for a non-git directory", md.ResolvedCommit)
	}
	if len(md.Limitations) == 0 {
		t.Fatal("non-git local source must record a commit-pin limitation")
	}
	src.Cleanup()
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("local cleanup removed the source: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "a.txt"))
	if err != nil || string(b) != "alpha" {
		t.Fatalf("source a.txt changed: %q (%v)", b, err)
	}
}

func TestMaterializeLocalGitSource(t *testing.T) {
	ctx := context.Background()
	repo, _, shaHead := setupMaterializeSource(t)
	before := fileVersion(t, repo)

	src, err := (Materializer{Now: fixedNow}).Materialize(ctx,
		CatalogEntry{ID: "example-local", Kind: "local", Root: repo},
		tagCandidate("example-local", "v1.2.3", shaHead), MaterializationPolicy{})
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	canon, err := filepath.EvalSymlinks(repo)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	if src.Root != canon {
		t.Fatalf("local materialization must not copy: root = %q, want %q", src.Root, canon)
	}
	md := src.Metadata
	if md.Mode != MaterializationLocal {
		t.Fatalf("mode = %q, want %q", md.Mode, MaterializationLocal)
	}
	if md.SelectedRef != "v1.2.3" {
		t.Fatalf("selected_ref = %q", md.SelectedRef)
	}
	if md.ResolvedCommit != shaHead {
		t.Fatalf("resolved_commit = %q, want HEAD %q", md.ResolvedCommit, shaHead)
	}
	src.Cleanup()
	if got := gitOutput(t, repo, "rev-parse", "HEAD"); got != shaHead {
		t.Fatalf("source HEAD = %q, want %q", got, shaHead)
	}
	if got := fileVersion(t, repo); got != before {
		t.Fatalf("source version.txt = %q, want %q", got, before)
	}
	if out := gitOutput(t, repo, "status", "--porcelain"); out != "" {
		t.Fatalf("source checkout dirty after materialization: %q", out)
	}
}

func TestMaterializeLocalRefMismatch(t *testing.T) {
	ctx := context.Background()
	repo, shaV123, _ := setupMaterializeSource(t)
	m := Materializer{}

	// The checkout sits at the newer HEAD; materializing v1.2.3 out of the
	// local root is impossible without mutating it — a technical error.
	if _, err := m.Materialize(ctx,
		CatalogEntry{ID: "example-local", Kind: "local", Root: repo},
		tagCandidate("example-local", "v1.2.3", shaV123), MaterializationPolicy{}); err == nil {
		t.Fatal("materialized v1.2.3 from a checkout at HEAD")
	}

	// A ref selected for a non-git local root cannot be materialized.
	dir := t.TempDir()
	if _, err := m.Materialize(ctx,
		CatalogEntry{ID: "example-local", Kind: "local", Root: dir},
		tagCandidate("example-local", "v1.2.3", shaV123), MaterializationPolicy{}); err == nil {
		t.Fatal("materialized a ref out of a non-git local root")
	}
}

func TestMaterializeWorktree(t *testing.T) {
	ctx := context.Background()
	repo, shaV123, shaHead := setupMaterializeSource(t)
	headBefore := gitOutput(t, repo, "rev-parse", "HEAD")
	wtBefore := gitOutput(t, repo, "worktree", "list")

	src, err := (Materializer{Now: fixedNow}).Materialize(ctx,
		CatalogEntry{ID: "example-repo", Kind: "git", Locator: repo},
		tagCandidate("example-repo", "v1.2.3", shaV123), MaterializationPolicy{})
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	if src.Root == "" || src.Root == repo {
		t.Fatalf("worktree root = %q, want an isolated directory distinct from %q", src.Root, repo)
	}
	if fileVersion(t, src.Root) != "v1.2.3" {
		t.Fatalf("worktree version.txt = %q, want v1.2.3", fileVersion(t, src.Root))
	}
	if got := gitOutput(t, src.Root, "rev-parse", "HEAD"); got != shaV123 {
		t.Fatalf("worktree HEAD = %q, want %q", got, shaV123)
	}
	md := src.Metadata
	if md.Mode != MaterializationWorktree {
		t.Fatalf("mode = %q, want %q", md.Mode, MaterializationWorktree)
	}
	if md.SourceID != "example-repo" || md.Locator != repo {
		t.Fatalf("provenance = %q / %q", md.SourceID, md.Locator)
	}
	if md.SelectedRef != "v1.2.3" {
		t.Fatalf("selected_ref = %q", md.SelectedRef)
	}
	if md.ResolvedCommit != shaV123 {
		t.Fatalf("resolved_commit = %q, want %q", md.ResolvedCommit, shaV123)
	}
	if md.RootHash == "" {
		t.Fatal("root_hash empty")
	}
	entries, err := collectContentEntries(src.Root)
	if err != nil {
		t.Fatalf("collectContentEntries: %v", err)
	}
	if want := hashContentEntries(entries); md.RootHash != want {
		t.Fatalf("root_hash = %q, want %q", md.RootHash, want)
	}
	// The source repository must not observe the materialization.
	if got := gitOutput(t, repo, "rev-parse", "HEAD"); got != headBefore || got != shaHead {
		t.Fatalf("source HEAD changed: %q", got)
	}
	if got := fileVersion(t, repo); got != "v2.0" {
		t.Fatalf("source version.txt = %q, want v2.0", got)
	}
	src.Cleanup()
	src.Cleanup() // idempotent
	if _, err := os.Stat(src.Root); !os.IsNotExist(err) {
		t.Fatalf("worktree %s survives cleanup", src.Root)
	}
	if got := gitOutput(t, repo, "worktree", "list"); got != wtBefore {
		t.Fatalf("source worktree list changed: %q, want %q", got, wtBefore)
	}
	if got := gitOutput(t, repo, "status", "--porcelain"); got != "" {
		t.Fatalf("source checkout dirty: %q", got)
	}
}

func TestMaterializeWorktreeUnknownCommit(t *testing.T) {
	ctx := context.Background()
	repo, _, _ := setupMaterializeSource(t)
	// A second repo with distinct content yields a commit absent from repo —
	// different payload guarantees a different object id.
	other := t.TempDir()
	gitCmd(t, other, "init", "-q", "-b", "main")
	writeFile(t, filepath.Join(other, "other.txt"), "other")
	gitCmd(t, other, "add", "other.txt")
	gitCmd(t, other, "commit", "-q", "-m", "other")
	absent := gitOutput(t, other, "rev-parse", "HEAD")

	if _, err := (Materializer{}).Materialize(ctx,
		CatalogEntry{ID: "example-repo", Kind: "git", Locator: repo},
		tagCandidate("example-repo", "v1.2.3", absent), MaterializationPolicy{}); err == nil {
		t.Fatal("worktree materialized a commit unknown to the source")
	}
}

func TestMaterializeClone(t *testing.T) {
	ctx := context.Background()
	repo, shaV123, shaHead := setupMaterializeSource(t)
	cloneRoot := t.TempDir()

	entry := CatalogEntry{
		ID:            "example-remote",
		Kind:          "git",
		Locator:       "file://" + repo,
		CredentialRef: "secret://scm/example-remote",
	}
	var gotCredRef string
	m := Materializer{
		Now: fixedNow,
		Credentials: func(ref string) ([]string, error) {
			gotCredRef = ref
			return []string{"GIT_ASKPASS=echo"}, nil
		},
	}
	src, err := m.Materialize(ctx, entry,
		tagCandidate("example-remote", "v1.2.3", shaV123),
		MaterializationPolicy{CloneRoot: cloneRoot})
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	defer src.Cleanup()

	if gotCredRef != "secret://scm/example-remote" {
		t.Fatalf("credential provider got %q", gotCredRef)
	}
	cloneRootCanon, err := filepath.EvalSymlinks(cloneRoot)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	rel, err := filepath.Rel(cloneRootCanon, src.Root)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		t.Fatalf("clone root %q escapes clone_root %q", src.Root, cloneRoot)
	}
	if fileVersion(t, src.Root) != "v1.2.3" {
		t.Fatalf("clone version.txt = %q, want v1.2.3", fileVersion(t, src.Root))
	}
	if got := gitOutput(t, src.Root, "rev-parse", "HEAD"); got != shaV123 {
		t.Fatalf("clone HEAD = %q, want %q", got, shaV123)
	}
	md := src.Metadata
	if md.Mode != MaterializationClone {
		t.Fatalf("mode = %q, want %q", md.Mode, MaterializationClone)
	}
	if md.Locator != "file://"+repo {
		t.Fatalf("locator = %q", md.Locator)
	}
	if md.CredentialRef != "secret://scm/example-remote" {
		t.Fatalf("credential_ref = %q", md.CredentialRef)
	}
	if md.SelectedRef != "v1.2.3" || md.ResolvedCommit != shaV123 {
		t.Fatalf("ref provenance = %q / %q", md.SelectedRef, md.ResolvedCommit)
	}
	if md.RootHash == "" {
		t.Fatal("root_hash empty")
	}
	// Source repo untouched.
	if got := gitOutput(t, repo, "rev-parse", "HEAD"); got != shaHead {
		t.Fatalf("source HEAD = %q, want %q", got, shaHead)
	}
	src.Cleanup()
	if _, err := os.Stat(src.Root); !os.IsNotExist(err) {
		t.Fatalf("clone %s survives cleanup", src.Root)
	}
	// The whole clone parent directory is gone.
	if got, _ := os.ReadDir(cloneRoot); len(got) != 0 {
		t.Fatalf("clone_root not empty after cleanup: %v", got)
	}
}

func TestMaterializeCloneRejectsUserinfoLocator(t *testing.T) {
	ctx := context.Background()
	m := Materializer{}
	_, err := m.Materialize(ctx,
		CatalogEntry{ID: "example-remote", Kind: "git", Locator: "https://user:s3cr3t@example.org/repo.git"},
		tagCandidate("example-remote", "v1.2.3", strings.Repeat("a", 40)),
		MaterializationPolicy{CloneRoot: t.TempDir()})
	mustError(t, err, "")
	if strings.Contains(err.Error(), "s3cr3t") {
		t.Fatalf("error leaks locator userinfo: %v", err)
	}
}

func TestMaterializeRejectsSymlinkEscape(t *testing.T) {
	ctx := context.Background()
	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "secret.txt"), "secret")
	repo := t.TempDir()
	gitCmd(t, repo, "init", "-q", "-b", "main")
	writeFile(t, filepath.Join(repo, "a.txt"), "alpha")
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(repo, "escape.txt")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	gitCmd(t, repo, "add", ".")
	gitCmd(t, repo, "commit", "-q", "-m", "escaping symlink")
	sha := gitOutput(t, repo, "rev-parse", "HEAD")

	entry := CatalogEntry{ID: "example-repo", Kind: "git", Locator: repo}
	cand := tagCandidate("example-repo", "v1.0.0", sha)
	for name, policy := range map[string]MaterializationPolicy{
		"worktree": {},
		"clone":    {CloneRoot: t.TempDir()},
	} {
		t.Run(name, func(t *testing.T) {
			e := entry
			if name == "clone" {
				e.Locator = "file://" + repo
			}
			if _, err := (Materializer{}).Materialize(ctx, e, cand, policy); err == nil {
				t.Fatal("materialized a tree with an escaping symlink")
			}
		})
	}
	// A local root with an escaping symlink is rejected as well.
	local := t.TempDir()
	writeFile(t, filepath.Join(local, "a.txt"), "alpha")
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(local, "escape.txt")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := (Materializer{}).Materialize(ctx,
		CatalogEntry{ID: "example-local", Kind: "local", Root: local},
		RefCandidate{}, MaterializationPolicy{}); err == nil {
		t.Fatal("local materialization accepted an escaping symlink")
	}
}

func TestMaterializeRejectsPathReplacement(t *testing.T) {
	ctx := context.Background()
	repo := t.TempDir()
	gitCmd(t, repo, "init", "-q", "-b", "main")
	writeFile(t, filepath.Join(repo, "go.mod"), "module example.org/prod\n\ngo 1.25\n\nreplace example.org/dep => ../dep\n")
	gitCmd(t, repo, "add", ".")
	gitCmd(t, repo, "commit", "-q", "-m", "escaping replace")
	sha := gitOutput(t, repo, "rev-parse", "HEAD")

	if _, err := (Materializer{}).Materialize(ctx,
		CatalogEntry{ID: "example-repo", Kind: "git", Locator: repo},
		tagCandidate("example-repo", "v1.0.0", sha), MaterializationPolicy{}); err == nil {
		t.Fatal("worktree materialized an escaping go.mod replacement")
	}
}

func TestMaterializeDeterministic(t *testing.T) {
	ctx := context.Background()
	repo, shaV123, _ := setupMaterializeSource(t)
	entry := CatalogEntry{ID: "example-repo", Kind: "git", Locator: repo}
	cand := tagCandidate("example-repo", "v1.2.3", shaV123)
	m := Materializer{Now: fixedNow}

	a, err := m.Materialize(ctx, entry, cand, MaterializationPolicy{})
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	defer a.Cleanup()
	b, err := m.Materialize(ctx, entry, cand, MaterializationPolicy{})
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	defer b.Cleanup()
	if !reflect.DeepEqual(a.Metadata, b.Metadata) {
		t.Fatalf("metadata diverged:\n%+v\n%+v", a.Metadata, b.Metadata)
	}
}

func TestMaterializeAllowedModes(t *testing.T) {
	ctx := context.Background()
	repo, shaV123, _ := setupMaterializeSource(t)
	entry := CatalogEntry{ID: "example-repo", Kind: "git", Locator: repo}
	cand := tagCandidate("example-repo", "v1.2.3", shaV123)

	if _, err := (Materializer{}).Materialize(ctx, entry, cand,
		MaterializationPolicy{AllowedModes: []MaterializationMode{MaterializationLocal}}); err == nil {
		t.Fatal("worktree materialization admitted despite AllowedModes={local}")
	}
	src, err := (Materializer{Now: fixedNow}).Materialize(ctx, entry, cand,
		MaterializationPolicy{AllowedModes: []MaterializationMode{MaterializationWorktree}})
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	if src.Metadata.Mode != MaterializationWorktree {
		t.Fatalf("mode = %q", src.Metadata.Mode)
	}
	src.Cleanup()
	if _, err := (Materializer{}).Materialize(ctx, entry, cand,
		MaterializationPolicy{AllowedModes: []MaterializationMode{"overlayfs"}}); err == nil {
		t.Fatal("unknown materialization mode accepted")
	}
}

func TestMaterializeRequirePinnedCommit(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.txt"), "alpha")

	if _, err := (Materializer{}).Materialize(ctx,
		CatalogEntry{ID: "example-local", Kind: "local", Root: dir},
		RefCandidate{}, MaterializationPolicy{RequirePinnedCommit: true}); err == nil {
		t.Fatal("unpinned local source admitted under RequirePinnedCommit")
	}
}

func TestMaterializeErrors(t *testing.T) {
	ctx := context.Background()
	m := Materializer{}
	cand := tagCandidate("example-repo", "v1.2.3", strings.Repeat("a", 40))

	if _, err := m.Materialize(ctx,
		CatalogEntry{ID: "example-local", Kind: "local", Root: filepath.Join(t.TempDir(), "missing")},
		RefCandidate{}, MaterializationPolicy{}); err == nil {
		t.Fatal("missing local root materialized")
	}
	file := filepath.Join(t.TempDir(), "f.txt")
	writeFile(t, file, "x")
	if _, err := m.Materialize(ctx,
		CatalogEntry{ID: "example-local", Kind: "local", Root: file},
		RefCandidate{}, MaterializationPolicy{}); err == nil {
		t.Fatal("file-as-root materialized")
	}
	if _, err := m.Materialize(ctx,
		CatalogEntry{ID: "example-nexus", Kind: "nexus", Locator: "https://packages.example.org/r"},
		cand, MaterializationPolicy{}); err == nil {
		t.Fatal("nexus source materialized as a repository")
	}
	if _, err := m.Materialize(ctx, CatalogEntry{Kind: "local", Root: t.TempDir()},
		RefCandidate{}, MaterializationPolicy{}); err == nil {
		t.Fatal("entry without id materialized")
	}
	// A clone_root that is a regular file cannot host clones.
	if _, err := m.Materialize(ctx,
		CatalogEntry{ID: "example-remote", Kind: "git", Locator: "file:///nonexistent/repo"},
		cand, MaterializationPolicy{CloneRoot: file}); err == nil {
		t.Fatal("clone_root file accepted")
	}
}

func TestMaterializeCredentialProvider(t *testing.T) {
	ctx := context.Background()
	repo, shaV123, _ := setupMaterializeSource(t)
	remote := CatalogEntry{
		ID:            "example-remote",
		Kind:          "git",
		Locator:       "file://" + repo,
		CredentialRef: "secret://scm/example-remote",
	}
	cand := tagCandidate("example-remote", "v1.2.3", shaV123)
	cloneRoot := t.TempDir()

	boom := errors.New("credential backend unavailable")
	if _, err := (Materializer{
		Credentials: func(ref string) ([]string, error) { return nil, boom },
	}).Materialize(ctx, remote, cand, MaterializationPolicy{CloneRoot: cloneRoot}); !errors.Is(err, boom) {
		t.Fatalf("provider error not propagated: %v", err)
	}
	if got, _ := os.ReadDir(cloneRoot); len(got) != 0 {
		t.Fatalf("credential failure left a clone behind: %v", got)
	}

	called := false
	m := Materializer{
		Credentials: func(ref string) ([]string, error) {
			called = true
			return nil, nil
		},
	}
	src, err := m.Materialize(ctx,
		CatalogEntry{ID: "example-repo", Kind: "git", Locator: repo},
		cand, MaterializationPolicy{})
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	defer src.Cleanup()
	if called {
		t.Fatal("credential provider invoked for an entry without credential_ref")
	}
}

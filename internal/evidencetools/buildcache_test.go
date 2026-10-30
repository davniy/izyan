package evidencetools

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/repository"
)

// A declared --build-cache-dir is canonicalized, exported to tool
// subprocesses as GOCACHE and joined to the confined read roots — the
// same treatment the module cache gets.
func TestBuildCacheDeclaredRootExportedAndConfined(t *testing.T) {
	parent := t.TempDir()
	root := writeProductSnapshot(t, filepath.Join(parent, "snap"))
	bc := filepath.Join(parent, "buildcache")
	must(t, os.MkdirAll(bc, 0o755))
	t.Setenv(BuildCacheDirEnv, "")

	s, err := NewSession(SessionConfig{
		SnapshotRoot: root, Strict: true, BuildCacheRoot: bc, Audit: NopAudit{}})
	must(t, err)
	want := canonical(t, bc)
	if s.BuildCacheRoot != want {
		t.Fatalf("BuildCacheRoot=%q want canonical %q", s.BuildCacheRoot, want)
	}
	if v, ok := envValue(s.ToolEnv, "GOCACHE"); !ok || v != want {
		t.Fatalf("GOCACHE pin missing from toolchain env: %v", s.ToolEnv)
	}
	if !hasRoot(s.ReadRoots, want) {
		t.Fatalf("build cache root missing from read roots: %v", s.ReadRoots)
	}
}

// BuildCacheDirEnv is the declared channel for callers whose option
// structs cannot carry the field; an explicit SessionConfig root still
// wins over the environment.
func TestBuildCacheEnvChannelAndFieldPrecedence(t *testing.T) {
	parent := t.TempDir()
	root := writeProductSnapshot(t, filepath.Join(parent, "snap"))
	envDir := filepath.Join(parent, "env-bc")
	must(t, os.MkdirAll(envDir, 0o755))
	t.Setenv(BuildCacheDirEnv, envDir)

	s, err := NewSession(SessionConfig{SnapshotRoot: root, Strict: true, Audit: NopAudit{}})
	must(t, err)
	if s.BuildCacheRoot != canonical(t, envDir) {
		t.Fatalf("env-declared root=%q want %q", s.BuildCacheRoot, canonical(t, envDir))
	}

	field := filepath.Join(parent, "field-bc")
	must(t, os.MkdirAll(field, 0o755))
	s2, err := NewSession(SessionConfig{
		SnapshotRoot: root, Strict: true, BuildCacheRoot: field, Audit: NopAudit{}})
	must(t, err)
	if s2.BuildCacheRoot != canonical(t, field) {
		t.Fatalf("config root must win over env, got %q", s2.BuildCacheRoot)
	}
}

// A build cache inside the snapshot or the output directory would let
// toolchain subprocesses write onto analyzed or reported ground —
// session creation refuses it, like the artifact cache guard.
func TestBuildCacheRootInsideSnapshotOrOutputRejected(t *testing.T) {
	parent := t.TempDir()
	root := writeProductSnapshot(t, filepath.Join(parent, "snap"))
	t.Setenv(BuildCacheDirEnv, "")

	if _, err := NewSession(SessionConfig{
		SnapshotRoot: root, Strict: true,
		BuildCacheRoot: filepath.Join(root, ".cache"), Audit: NopAudit{},
	}); err == nil || !strings.Contains(err.Error(), "must not be inside") {
		t.Fatalf("cache inside snapshot accepted: %v", err)
	}
	// The snapshot root itself is not a cache root either.
	if _, err := NewSession(SessionConfig{
		SnapshotRoot: root, Strict: true,
		BuildCacheRoot: root, Audit: NopAudit{},
	}); err == nil {
		t.Fatal("snapshot root as cache root accepted")
	}
	out := filepath.Join(parent, "out")
	must(t, os.MkdirAll(out, 0o755))
	if _, err := NewSession(SessionConfig{
		SnapshotRoot: root, Strict: true,
		BuildCacheRoot: filepath.Join(out, "bc"),
		Artifact:       repository.ArtifactOptions{ForbidDirs: []string{out}},
		Audit:          NopAudit{},
	}); err == nil || !strings.Contains(err.Error(), "must not be inside") {
		t.Fatalf("cache inside forbidden output dir accepted: %v", err)
	}
}

// With no declaration the session pins the platform default instead of
// inheriting a caller's ambient GOCACHE — a leaked root can never reach
// a subprocess or the package loader.
func TestBuildCacheAmbientGOCACHEBlocked(t *testing.T) {
	parent := t.TempDir()
	root := writeProductSnapshot(t, filepath.Join(parent, "snap"))
	t.Setenv(BuildCacheDirEnv, "")
	t.Setenv("GOCACHE", filepath.Join(parent, "ambient"))

	s, err := NewSession(SessionConfig{SnapshotRoot: root, Strict: true, Audit: NopAudit{}})
	must(t, err)
	// Resolve the platform default exactly the way the session does.
	want, err := defaultBuildCacheRoot()
	must(t, err)
	if resolved, rerr := filepath.EvalSymlinks(want); rerr == nil {
		want = resolved
	}
	if s.BuildCacheRoot != want {
		t.Fatalf("undeclared BuildCacheRoot=%q want platform default %q", s.BuildCacheRoot, want)
	}
	if v, _ := envValue(s.ToolEnv, "GOCACHE"); v != want {
		t.Fatalf("GOCACHE=%q: ambient leak or missing pin", v)
	}
}

// A corrupted inherited cache surfaces as the named fail-closed reason,
// not a generic ERROR: both measured signatures — a pruned file under
// the pinned root and the go tool's "cache entry not found" — classify
// as BUILD_CACHE_CORRUPT with the documented remedy.
func TestBuildCacheCorruptionFailsClosed(t *testing.T) {
	parent := t.TempDir()
	root := writeProductSnapshot(t, filepath.Join(parent, "snap"))
	t.Setenv(BuildCacheDirEnv, "")
	s, err := NewSession(SessionConfig{SnapshotRoot: root, Strict: true, Audit: NopAudit{}})
	must(t, err)

	fail := func(e error) *Observation {
		return s.invoke(context.Background(), "find_symbol", nil,
			func(context.Context) (*Observation, error) { return nil, e })
	}

	o := fail(fmt.Errorf("go list -deps failed: open %s: no such file or directory",
		filepath.Join(s.BuildCacheRoot, "4e", "4e42c2e3-d")))
	if o.ToolStatus != StatusError || !strings.HasPrefix(o.Error, BuildCacheCorruptReason+":") {
		t.Fatalf("pruned-cache ENOENT not classified: %s %s", o.ToolStatus, o.Error)
	}
	if !strings.Contains(o.Error, "go clean -cache") {
		t.Fatalf("remedy missing from corruption observation: %s", o.Error)
	}
	o = fail(errors.New("govulncheck: exit status 1: loading compiled Go files from cache: " +
		"reading srcfiles list: cache entry not found"))
	if o.ToolStatus != StatusError || !strings.HasPrefix(o.Error, BuildCacheCorruptReason+":") {
		t.Fatalf("missing-entry signature not classified: %s %s", o.ToolStatus, o.Error)
	}
	// An unrelated ENOENT outside the pinned cache stays a plain ERROR.
	o = fail(errors.New("open /elsewhere/x.go: no such file or directory"))
	if o.ToolStatus != StatusError || strings.Contains(o.Error, BuildCacheCorruptReason) {
		t.Fatalf("unrelated ENOENT misclassified: %s %s", o.ToolStatus, o.Error)
	}
}

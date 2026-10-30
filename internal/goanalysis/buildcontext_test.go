package goanalysis

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/davniy/izyan/internal/domain"
)

// BuildEnv is the single build-selection env shared by package loads and
// toolchain subprocesses: GOOS/GOARCH/CGO, the recorded workspace mode and
// the effective GOFLAGS (with the legacy vendor fallback for snapshots that
// never resolved flags).
func TestBuildEnv(t *testing.T) {
	env := domain.BuildEnv(domain.ProductSnapshot{
		GOOS: "linux", GOARCH: "arm64", CGOEnabled: true,
		VendorMode: true, GoWorkFile: "/ws/go.work", GoFlags: "-mod=mod",
	})
	for key, want := range map[string]string{
		"GOOS": "linux", "GOARCH": "arm64", "CGO_ENABLED": "1",
		"GOWORK": "/ws/go.work", "GOFLAGS": "-mod=mod",
	} {
		if got, ok := lastEnvValue(env, key); !ok || got != want {
			t.Fatalf("%s=%q (present=%v), want %q; env=%v", key, got, ok, want, env)
		}
	}

	env = domain.BuildEnv(domain.ProductSnapshot{VendorMode: true})
	if got, _ := lastEnvValue(env, "CGO_ENABLED"); got != "0" {
		t.Fatalf("default CGO_ENABLED=%q, want 0", got)
	}
	if got, ok := lastEnvValue(env, "GOFLAGS"); !ok || got != "-mod=vendor" {
		t.Fatalf("vendor fallback GOFLAGS=%q (present=%v), want -mod=vendor", got, ok)
	}
	if _, ok := lastEnvValue(env, "GOWORK"); ok {
		t.Fatalf("unresolved workspace must not synthesize GOWORK: %v", env)
	}

	env = domain.BuildEnv(domain.ProductSnapshot{GoWorkFile: domain.GoWorkOff})
	if got, ok := lastEnvValue(env, "GOWORK"); !ok || got != domain.GoWorkOff {
		t.Fatalf("inactive workspace GOWORK=%q (present=%v), want %q", got, ok, domain.GoWorkOff)
	}
	if _, ok := lastEnvValue(env, "GOFLAGS"); ok {
		t.Fatalf("empty effective GOFLAGS must not emit a value: %v", env)
	}
}

// BindBuild is synchronized and idempotent: before the first load it adopts
// the resolved snapshot; after a load a mismatching context fails without
// mutating the index.
func TestIndexBindBuild(t *testing.T) {
	dir := usageModuleGomod(t, "module example.com/bind\n\ngo 1.23\n", map[string]string{
		"main.go": "package main\n\nfunc main() {}\n",
	})
	resolved := domain.ProductSnapshot{
		Repository: dir, Commit: "c0ffee",
		GoVersion: "go version go1.25.0 linux/arm64", GoModDirective: "1.23",
		GOOS: "linux", GOARCH: "arm64", CGOEnabled: true,
		BuildTags:  []string{"netgo", "osusergo"},
		GoWorkFile: domain.GoWorkOff, GoFlags: "-mod=readonly",
		ReplaceDirectives: []domain.ReplaceDirective{{Old: "example.com/a", New: "example.com/b@v1.0.0"}},
	}
	ix := &Index{Dir: dir, Build: domain.ProductSnapshot{
		GOOS: "darwin", GOARCH: "amd64", BuildTags: []string{"operator"},
	}}
	if err := ix.BindBuild(resolved); err != nil {
		t.Fatalf("pre-load bind: %v", err)
	}
	bound, ok := ix.BoundBuildContext()
	if !ok {
		t.Fatal("bound context not recorded")
	}
	if err := bound.Matches(domain.EffectiveBuildContext(resolved)); err != nil {
		t.Fatalf("bound context = %+v: %v", bound, err)
	}
	if ix.Build.GOOS != "linux" || ix.Build.GoWorkFile != domain.GoWorkOff {
		t.Fatalf("pre-load bind did not adopt the resolved snapshot: %+v", ix.Build)
	}
	// Tags compare order-insensitively, so an equivalent ordering is a match.
	reordered := resolved
	reordered.BuildTags = []string{"osusergo", "netgo"}
	if err := ix.BindBuild(reordered); err != nil {
		t.Fatalf("idempotent bind with reordered tags: %v", err)
	}

	// After the first load a different build can never be relabelled.
	live := &Index{Dir: dir}
	if err := live.Loaded(context.Background()); err != nil {
		t.Fatalf("load: %v", err)
	}
	loaded, ok := live.BoundBuildContext()
	if !ok {
		t.Fatal("load did not capture a bound context")
	}
	if err := live.BindBuild(live.Build); err != nil {
		t.Fatalf("matching post-load bind: %v", err)
	}
	before := live.Build
	other := live.Build
	other.GOOS = "windows"
	if err := live.BindBuild(other); !errors.Is(err, domain.ErrBuildContextMismatch) {
		t.Fatalf("post-load mismatch error = %v, want ErrBuildContextMismatch", err)
	}
	if !reflect.DeepEqual(live.Build, before) {
		t.Fatalf("failed bind mutated the loaded snapshot: %+v -> %+v", before, live.Build)
	}
	still, _ := live.BoundBuildContext()
	if err := loaded.Matches(still); err != nil {
		t.Fatalf("loaded context was relabelled: %v", err)
	}
}

// A later mutation of the public Build field must be detected before the
// next load/query instead of serving a loaded index under another context.
func TestBuildContextMutation(t *testing.T) {
	dir := usageModuleGomod(t, "module example.com/mut\n\ngo 1.23\n", map[string]string{
		"main.go": "package main\n\nfunc main() {}\n",
	})
	ix := &Index{Dir: dir}
	if err := ix.Loaded(context.Background()); err != nil {
		t.Fatalf("load: %v", err)
	}
	loaded, ok := ix.BoundBuildContext()
	if !ok {
		t.Fatal("load did not capture a bound context")
	}

	ix.Build.GOOS = "windows"
	if err := ix.Loaded(context.Background()); !errors.Is(err, domain.ErrBuildContextMismatch) {
		t.Fatalf("Load after mutation = %v, want ErrBuildContextMismatch", err)
	}
	if _, err := ix.FindSymbol(context.Background(), domain.SymbolRef{
		Package: "example.com/mut", Symbol: "main",
	}); !errors.Is(err, domain.ErrBuildContextMismatch) {
		t.Fatalf("query after mutation = %v, want ErrBuildContextMismatch", err)
	}
	still, _ := ix.BoundBuildContext()
	if err := loaded.Matches(still); err != nil {
		t.Fatalf("loaded context changed with the mutable field: %v", err)
	}

	// Restoring the field restores consistency: the guard tracks the
	// current snapshot rather than poisoning the index permanently.
	ix.Build.GOOS = loaded.GOOS
	if err := ix.Loaded(context.Background()); err != nil {
		t.Fatalf("load after restore: %v", err)
	}
}

// A caching runner serves exactly one build: a second context must never
// receive the first build's cached output.
type countingRunner struct {
	calls int
}

func (r *countingRunner) RunGovulncheck(context.Context, string, domain.ProductSnapshot) ([]byte, string, error) {
	r.calls++
	return []byte("stream"), "./...", nil
}

func TestCachingRunnerBuildContext(t *testing.T) {
	inner := &countingRunner{}
	cr := CachingRunner(inner)
	snap := domain.ProductSnapshot{
		Repository: "/repo", Commit: "c", GoVersion: "go version go1.25.0 linux/amd64",
		GOOS: "linux", GOARCH: "amd64",
	}
	if out, _, err := cr.RunGovulncheck(context.Background(), "/repo", snap); err != nil || string(out) != "stream" {
		t.Fatalf("first run = %q, %v", out, err)
	}
	if out, _, err := cr.RunGovulncheck(context.Background(), "/repo", snap); err != nil || string(out) != "stream" {
		t.Fatalf("cached run = %q, %v", out, err)
	}
	if inner.calls != 1 {
		t.Fatalf("inner calls = %d, want 1", inner.calls)
	}

	other := snap
	other.GOOS = "windows"
	if _, _, err := cr.RunGovulncheck(context.Background(), "/repo", other); !errors.Is(err, domain.ErrBuildContextMismatch) {
		t.Fatalf("different build error = %v, want ErrBuildContextMismatch", err)
	}
	if _, _, err := cr.RunGovulncheck(context.Background(), "/other-repo", snap); !errors.Is(err, domain.ErrBuildContextMismatch) {
		t.Fatalf("different repository error = %v, want ErrBuildContextMismatch", err)
	}
	if inner.calls != 1 {
		t.Fatalf("refused calls reached the inner runner: %d", inner.calls)
	}
}

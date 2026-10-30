package affected

import (
	"context"
	"errors"
	"testing"

	"github.com/davniy/izyan/internal/domain"
)

// countingGoTool records how many times the inner subprocess path ran.
type countingGoTool struct {
	moduleCalls  int
	packageCalls int
}

func (t *countingGoTool) ListModules(context.Context, string, domain.ProductSnapshot) ([]byte, string, error) {
	t.moduleCalls++
	return []byte(`{"Path":"example.com/dep","Version":"v1.0.0"}` + "\n"), "go list -m -json all", nil
}

func (t *countingGoTool) ListPackages(ctx context.Context, dir string, build domain.ProductSnapshot) ([]byte, error) {
	return t.ListPackagesScope(ctx, dir, build, true)
}

func (t *countingGoTool) ListPackagesScope(context.Context, string, domain.ProductSnapshot, bool) ([]byte, error) {
	t.packageCalls++
	return []byte(`{"ImportPath":"example.com/product"}` + "\n"), nil
}

// The shared go-list cache serves exactly one build: a different snapshot or
// repository must be refused instead of answered from another build's
// cached listing.
func TestCachingToolBuildContext(t *testing.T) {
	inner := &countingGoTool{}
	tool := CachingTool(inner)
	snap := domain.ProductSnapshot{
		Repository: "/repo", Commit: "c", GoVersion: "go version go1.25.0 linux/amd64",
		GOOS: "linux", GOARCH: "amd64", BuildTags: []string{"netgo"},
	}
	if raw, _, err := tool.ListModules(context.Background(), "/repo", snap); err != nil || len(raw) == 0 {
		t.Fatalf("first module list = %q, %v", raw, err)
	}
	if raw, _, err := tool.ListModules(context.Background(), "/repo", snap); err != nil || len(raw) == 0 {
		t.Fatalf("cached module list = %q, %v", raw, err)
	}
	if inner.moduleCalls != 1 {
		t.Fatalf("inner module calls = %d, want 1", inner.moduleCalls)
	}

	other := snap
	other.GOOS = "windows"
	if _, _, err := tool.ListModules(context.Background(), "/repo", other); !errors.Is(err, domain.ErrBuildContextMismatch) {
		t.Fatalf("different build module list error = %v, want ErrBuildContextMismatch", err)
	}
	if _, err := tool.ListPackages(context.Background(), "/repo", other); !errors.Is(err, domain.ErrBuildContextMismatch) {
		t.Fatalf("different build package list error = %v, want ErrBuildContextMismatch", err)
	}
	if _, _, err := tool.ListModules(context.Background(), "/other-repo", snap); !errors.Is(err, domain.ErrBuildContextMismatch) {
		t.Fatalf("different repository error = %v, want ErrBuildContextMismatch", err)
	}
	if inner.moduleCalls != 1 || inner.packageCalls != 0 {
		t.Fatalf("refused calls reached the inner tool: modules=%d packages=%d", inner.moduleCalls, inner.packageCalls)
	}

	// A different tag order is the same build context.
	reordered := snap
	reordered.BuildTags = []string{"netgo"}
	if _, err := tool.ListPackages(context.Background(), "/repo", reordered); err != nil {
		t.Fatalf("matching context after bind: %v", err)
	}
}

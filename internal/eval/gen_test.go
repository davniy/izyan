package eval_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/eval"
)

// writeProduct creates a minimal product source tree in dir.
func writeProduct(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMaterializeGeneratesModule(t *testing.T) {
	root := t.TempDir()
	prod := filepath.Join(root, "products", "demo")
	writeProduct(t, prod, map[string]string{
		"main.go":         "package main\n\nfunc main() {}\n",
		"internal/x/x.go": "package x\n",
		"docs/notes.txt":  "product notes\n",
	})
	c := eval.Case{ID: "demo-case", Vuln: "GO-X", Product: "products/demo", Module: "example.com/demo"}
	gen := eval.Gen{GoBin: "go"}
	dir, err := gen.Materialize(context.Background(), c, root, filepath.Join(root, ".gen"))
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	if filepath.Base(dir) != "demo-case" {
		t.Fatalf("gen dir %q", dir)
	}
	gm, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		t.Fatalf("go.mod: %v", err)
	}
	if !strings.Contains(string(gm), "module example.com/demo") {
		t.Fatalf("go.mod missing module line:\n%s", gm)
	}
	for _, f := range []string{"main.go", "internal/x/x.go", "docs/notes.txt"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Fatalf("missing %s: %v", f, err)
		}
	}
	// go.sum must not appear for a dep-less module.
	if _, err := os.Stat(filepath.Join(dir, "go.sum")); !os.IsNotExist(err) {
		t.Fatalf("unexpected go.sum for dep-less product")
	}
}

func TestMaterializeWritesSortedDeps(t *testing.T) {
	root := t.TempDir()
	prod := filepath.Join(root, "products", "demo")
	writeProduct(t, prod, map[string]string{"main.go": "package main\n\nfunc main() {}\n"})
	c := eval.Case{
		ID: "deps-case", Vuln: "GO-X", Product: "products/demo", Module: "example.com/demo",
		Deps: map[string]string{"example.com/b": "v1.2.0", "example.com/a": "v0.3.0"},
	}
	dst := filepath.Join(root, ".gen", "deps-case")
	// "true" stands in for the `go` binary: go.mod content is asserted
	// without depending on module resolution (the network-heavy part).
	genDir, err := (eval.Gen{GoBin: "true"}).Materialize(context.Background(), c, root, filepath.Join(root, ".gen"))
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	if genDir != dst {
		t.Fatalf("gen dir %q want %q", genDir, dst)
	}
	gm, err := os.ReadFile(filepath.Join(genDir, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	want := "require (\n\texample.com/a v0.3.0\n\texample.com/b v1.2.0\n)"
	if !strings.Contains(string(gm), want) {
		t.Fatalf("go.mod deps not sorted/pinned:\n%s", gm)
	}
}

func TestMaterializeRejectsCommittedManifest(t *testing.T) {
	root := t.TempDir()
	prod := filepath.Join(root, "products", "bad")
	writeProduct(t, prod, map[string]string{
		"main.go": "package main\n\nfunc main() {}\n",
		"go.mod":  "module example.com/bad\n",
	})
	c := eval.Case{ID: "bad", Vuln: "GO-X", Product: "products/bad", Module: "example.com/bad"}
	_, err := eval.Gen{GoBin: "true"}.Materialize(context.Background(), c, root, filepath.Join(root, ".gen"))
	if err == nil || !strings.Contains(err.Error(), "go.mod") {
		t.Fatalf("want committed-manifest rejection, got %v", err)
	}
}

// Labels reach the filesystem as genRoot/<name>: IDs that sanitize to a
// bare dot-path must be rejected before copyProduct can os.RemoveAll the
// resolved (parent) directory.
func TestMaterializeRejectsUnsafeIDs(t *testing.T) {
	root := t.TempDir()
	prod := filepath.Join(root, "products", "demo")
	writeProduct(t, prod, map[string]string{"main.go": "package main\n\nfunc main() {}\n"})
	// Sentinel sits next to .gen — a ".." ID resolves to root itself.
	sentinel := filepath.Join(root, "sentinel", "keep.txt")
	if err := os.MkdirAll(filepath.Dir(sentinel), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sentinel, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	genRoot := filepath.Join(root, ".gen")
	// Only bare "." / ".." escape genRoot — mixed separator input
	// sanitizes to a legal in-root name.
	for _, id := range []string{"..", "."} {
		c := eval.Case{ID: id, Vuln: "GO-X", Product: "products/demo", Module: "example.com/demo"}
		if _, err := (eval.Gen{GoBin: "true"}).Materialize(context.Background(), c, root, genRoot); err == nil {
			t.Errorf("id %q: want rejection, materialized", id)
		}
		if _, err := os.Stat(sentinel); err != nil {
			t.Fatalf("id %q: sentinel lost: %v", id, err)
		}
	}
	// "../escape" → "..-escape", "..." → "...": legal names inside genRoot.
	for _, id := range []string{"../escape", "...", ".. "} {
		c := eval.Case{ID: id, Vuln: "GO-X", Product: "products/demo", Module: "example.com/demo"}
		dir, err := (eval.Gen{GoBin: "true"}).Materialize(context.Background(), c, root, genRoot)
		if err != nil {
			t.Fatalf("id %q: %v", id, err)
		}
		if filepath.Dir(dir) != filepath.Clean(genRoot) {
			t.Fatalf("id %q escaped genRoot: %q", id, dir)
		}
	}
}

func TestMaterializeRequiresModule(t *testing.T) {
	c := eval.Case{ID: "no-mod", Vuln: "GO-X", Product: "products/x"}
	_, err := eval.Gen{GoBin: "true"}.Materialize(context.Background(), c, t.TempDir(), t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "module") {
		t.Fatalf("want module-required error, got %v", err)
	}
}

func TestMaterializeCachesIdenticalModule(t *testing.T) {
	root := t.TempDir()
	prod := filepath.Join(root, "products", "demo")
	writeProduct(t, prod, map[string]string{
		"main.go": "package main\nfunc main() {}\n",
	})
	c := eval.Case{ID: "demo-cache", Vuln: "GO-X", Product: "products/demo", Module: "example.com/demo"}
	gen := eval.Gen{GoBin: "go"}
	dir, err := gen.Materialize(context.Background(), c, root, filepath.Join(root, ".gen"))
	if err != nil {
		t.Fatalf("first Materialize: %v", err)
	}
	marker := filepath.Join(dir, "cache-marker.txt")
	if err := os.WriteFile(marker, []byte("cached"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Second Materialize should hit cache and preserve marker
	dir2, err := gen.Materialize(context.Background(), c, root, filepath.Join(root, ".gen"))
	if err != nil {
		t.Fatalf("second Materialize: %v", err)
	}
	if dir2 != dir {
		t.Fatalf("dir changed: %s vs %s", dir, dir2)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("expected marker file to survive cached Materialize: %v", err)
	}

	// With Force: true, should re-materialize and wipe marker
	genForce := eval.Gen{GoBin: "go", Force: true}
	_, err = genForce.Materialize(context.Background(), c, root, filepath.Join(root, ".gen"))
	if err != nil {
		t.Fatalf("forced Materialize: %v", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("expected marker file to be wiped with Force: true")
	}
}

// initGitRepo creates a git repo with one committed file and a tag, and
// returns its path. Skips when git is unavailable.
func initGitRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Skipf("git %v: %v (%s)", args, err, out)
		}
	}
	run("init", "-q")
	run("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init", "--allow-empty")
	if err := os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "go.mod"), []byte("module m\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", ".")
	run("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "files")
	run("tag", "v1")
	return dir
}

func TestMaterializeRefExtractsRefTree(t *testing.T) {
	repo := initGitRepo(t)
	root := t.TempDir()
	gen := eval.Gen{}
	dir, err := gen.MaterializeRef(context.Background(), repo, "v1", filepath.Join(root, ".gen"), "demo")
	if err != nil {
		t.Fatalf("MaterializeRef: %v", err)
	}
	for _, f := range []string{"hello.txt", filepath.Join("sub", "go.mod"), ".gen-ref-sig"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Fatalf("expected %s in extracted tree: %v", f, err)
		}
	}
	// no .git metadata leaks into the snapshot
	if _, err := os.Stat(filepath.Join(dir, ".git")); !os.IsNotExist(err) {
		t.Fatal(".git should not be extracted")
	}
	// source repo checkout untouched: HEAD has no uncommitted changes marker
	// (we assert the extracted file came from the ref, not the worktree, by
	// modifying the worktree file and re-extracting with Force)
	if err := os.WriteFile(filepath.Join(repo, "hello.txt"), []byte("dirty"), 0o644); err != nil {
		t.Fatal(err)
	}
	gen.Force = true
	dir, err = gen.MaterializeRef(context.Background(), repo, "v1", filepath.Join(root, ".gen"), "demo")
	if err != nil {
		t.Fatalf("forced MaterializeRef: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "hello.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hi" {
		t.Fatalf("expected ref content %q, got %q", "hi", got)
	}
}

func TestMaterializeRefCachesSig(t *testing.T) {
	repo := initGitRepo(t)
	root := t.TempDir()
	gen := eval.Gen{}
	dir, err := gen.MaterializeRef(context.Background(), repo, "v1", filepath.Join(root, ".gen"), "demo")
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "marker.txt")
	if err := os.WriteFile(marker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir2, err := gen.MaterializeRef(context.Background(), repo, "v1", filepath.Join(root, ".gen"), "demo")
	if err != nil {
		t.Fatal(err)
	}
	if dir2 != dir {
		t.Fatalf("dir changed: %s vs %s", dir, dir2)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("cached extraction should preserve marker")
	}
}

func TestMaterializeRefBadRef(t *testing.T) {
	repo := initGitRepo(t)
	gen := eval.Gen{}
	if _, err := gen.MaterializeRef(context.Background(), repo, "nonexistent-ref", t.TempDir(), "demo"); err == nil {
		t.Fatal("expected error for unknown ref")
	}
}

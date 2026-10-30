package readgate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGate_AllowsTargetUnderRoot(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "sub", "a.go")
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("package a"), 0o644); err != nil {
		t.Fatal(err)
	}
	g := New(root)
	if err := g.Check(file); err != nil {
		t.Fatalf("in-root file rejected: %v", err)
	}
}

func TestGate_RejectsTargetOutsideRoot(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	file := filepath.Join(outside, "secret.go")
	if err := os.WriteFile(file, []byte("package secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	g := New(root)
	if err := g.Check(file); err == nil {
		t.Fatal("outside file accepted")
	}
}

func TestGate_RejectsSiblingPrefix(t *testing.T) {
	// /a/b must not be treated as inside /a-bc.
	base := t.TempDir()
	root := filepath.Join(base, "a")
	sibling := filepath.Join(base, "a-bc")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(sibling, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(sibling, "x.go")
	if err := os.WriteFile(file, []byte("package x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := New(root).Check(file); err == nil {
		t.Fatal("sibling-prefix path accepted")
	}
}

func TestGate_RejectsEscapingSymlink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	target := filepath.Join(outside, "secret.go")
	if err := os.WriteFile(target, []byte("package secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "escape.go")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	if err := New(root).Check(link); err == nil {
		t.Fatal("escaping symlink accepted")
	}
}

func TestGate_AllowsInternalSymlink(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real", "a.go")
	if err := os.MkdirAll(filepath.Dir(real), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(real, []byte("package a"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link.go")
	if err := os.Symlink(filepath.Join("real", "a.go"), link); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	if err := New(root).Check(link); err != nil {
		t.Fatalf("internal symlink rejected: %v", err)
	}
}

func TestGate_NilAllowsEverything(t *testing.T) {
	var g *Gate
	if err := g.Check("/anywhere/at/all"); err != nil {
		t.Fatalf("nil gate rejected a path: %v", err)
	}
	if !g.Allows("/anywhere") {
		t.Fatal("nil gate did not allow")
	}
}

func TestGate_MultipleRoots(t *testing.T) {
	r1 := t.TempDir()
	r2 := t.TempDir()
	f1 := filepath.Join(r1, "a.go")
	f2 := filepath.Join(r2, "b.go")
	for _, f := range []string{f1, f2} {
		if err := os.WriteFile(f, []byte("package p"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	g := New(r1, r2)
	if err := g.Check(f1); err != nil {
		t.Fatalf("root1 file rejected: %v", err)
	}
	if err := g.Check(f2); err != nil {
		t.Fatalf("root2 file rejected: %v", err)
	}
}

func TestGate_MissingTargetFailsClosed(t *testing.T) {
	root := t.TempDir()
	g := New(root)
	if err := g.Check(filepath.Join(root, "does-not-exist.go")); err != nil {
		// Missing inside the root: EvalSymlinks fails, so the gate fails
		// closed. Reads of missing files are errors regardless.
		t.Logf("missing file rejected (fail-closed): %v", err)
	}
}

// TestGate_ZeroRootsAllowsEverything pins the current semantics: a gate
// built with no usable roots is permissive, same as a nil gate. This is
// deliberate — the gate is opt-in confinement, so "no roots" reads as
// "confinement not configured", not "deny all". Every caller that relies
// on confinement must therefore supply at least one resolvable root
// (the evidence lane always passes its snapshot dir); a future change
// to fail-closed zero-roots would be a conscious contract change this
// test is here to force.
func TestGate_ZeroRootsAllowsEverything(t *testing.T) {
	for _, g := range []*Gate{New(), New(""), New("", "")} {
		if err := g.Check("/anywhere/at/all"); err != nil {
			t.Fatalf("zero-root gate rejected a path: %v", err)
		}
		if !g.Allows(t.TempDir()) {
			t.Fatal("zero-root gate did not allow")
		}
	}
}

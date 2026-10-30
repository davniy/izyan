package repository

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckPathReplacements_AllowsInternalTarget(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "go.mod"), "module example.com/x\n\ngo 1.21\n\nreplace example.com/dep => ./staging/dep\n")
	writeFile(t, filepath.Join(dir, "staging", "dep", "go.mod"), "module example.com/dep\n")
	if err := CheckPathReplacements(dir); err != nil {
		t.Fatalf("internal replace rejected: %v", err)
	}
}

func TestCheckPathReplacements_RejectsOutsideTarget(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "go.mod"), "module example.com/x\n\ngo 1.21\n\nreplace example.com/dep => ../outside/dep\n")
	if err := CheckPathReplacements(dir); err == nil {
		t.Fatal("outside replace accepted")
	}
}

func TestCheckPathReplacements_RejectsAbsoluteTarget(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "go.mod"), "module example.com/x\n\ngo 1.21\n\nreplace example.com/dep => /tmp/elsewhere\n")
	if err := CheckPathReplacements(dir); err == nil {
		t.Fatal("absolute replace accepted")
	}
}

func TestCheckPathReplacements_AllowsModuleVersionReplace(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "go.mod"),
		"module example.com/x\n\ngo 1.21\n\nreplace github.com/a/b => github.com/c/d v1.2.3\n")
	if err := CheckPathReplacements(dir); err != nil {
		t.Fatalf("module-version replace rejected: %v", err)
	}
}

func TestCheckPathReplacements_ReplaceBlock(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "go.mod"),
		"module example.com/x\n\ngo 1.21\n\nreplace (\n\texample.com/a => ./inside/a\n\texample.com/b => ../outside/b\n)\n")
	writeFile(t, filepath.Join(dir, "inside", "a", "go.mod"), "module example.com/a\n")
	if err := CheckPathReplacements(dir); err == nil {
		t.Fatal("outside replace inside a block was accepted")
	}
}

func TestCheckPathReplacements_GoWorkUse(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "go.work"), "go 1.21\n\nuse (\n\t./mod-a\n\t../mod-b\n)\n")
	writeFile(t, filepath.Join(dir, "mod-a", "go.mod"), "module example.com/a\n")
	if err := CheckPathReplacements(dir); err == nil {
		t.Fatal("outside go.work use was accepted")
	}
}

func TestCheckPathReplacements_EscapingSymlinkTarget(t *testing.T) {
	outside := t.TempDir()
	dir := t.TempDir()
	// A symlink inside the snapshot pointing out, referenced by replace.
	if err := os.Symlink(outside, filepath.Join(dir, "link")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	writeFile(t, filepath.Join(dir, "go.mod"), "module example.com/x\n\ngo 1.21\n\nreplace example.com/dep => ./link/dep\n")
	if err := CheckPathReplacements(dir); err == nil {
		t.Fatal("replace through escaping symlink accepted")
	}
}

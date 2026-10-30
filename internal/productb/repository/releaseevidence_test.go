package repository

import (
	"os"
	"path/filepath"
	"testing"

	domain "github.com/fedorovmv/izyan/internal/productb/domain"
)

func writeFixture(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestToolVersionsNodeBeforeGo is the exact misattribution the parser must
// prevent: "nodejs 20.11.0" earlier in the file must NOT become the Go
// release toolchain.
func TestToolVersionsNodeBeforeGo(t *testing.T) {
	root := writeFixture(t, ".tool-versions", "nodejs 20.11.0\ngolang 1.22.5\n")
	ev := DiscoverReleaseEvidence(root)
	if ev.Version != "go1.22.5" {
		t.Fatalf("got %q, want go1.22.5 (must not read the node version)", ev.Version)
	}
	if ev.Source != domain.GoVersionSourceVersionFile {
		t.Fatalf("source = %v, want GoVersionSourceVersionFile", ev.Source)
	}
}

// TestToolVersionsPythonBeforeGo — same trap with python first.
func TestToolVersionsPythonBeforeGo(t *testing.T) {
	root := writeFixture(t, ".tool-versions", "python 3.12.2\ngo 1.23.1\nruby 3.3.0\n")
	ev := DiscoverReleaseEvidence(root)
	if ev.Version != "go1.23.1" {
		t.Fatalf("got %q, want go1.23.1", ev.Version)
	}
}

// TestToolVersionsGoToolchainName — GOTOOLCHAIN is also a valid go pin.
func TestToolVersionsGoToolchainName(t *testing.T) {
	root := writeFixture(t, ".tool-versions", "nodejs 20.11.0\nGOTOOLCHAIN go1.24.0\n")
	ev := DiscoverReleaseEvidence(root)
	if ev.Version != "go1.24.0" {
		t.Fatalf("got %q, want go1.24.0", ev.Version)
	}
}

// TestToolVersionsNoGoEntry: a mixed-tool file with no go line yields no
// evidence — never the first version it sees.
func TestToolVersionsNoGoEntry(t *testing.T) {
	root := writeFixture(t, ".tool-versions", "nodejs 20.11.0\npython 3.12.2\n")
	ev := DiscoverReleaseEvidence(root)
	if ev.Version != "" {
		t.Fatalf("got %q, want empty (no go entry)", ev.Version)
	}
}

// TestToolVersionsAmbiguousGoPins: two different go versions in one file is
// ambiguous — report nothing rather than picking one.
func TestToolVersionsAmbiguousGoPins(t *testing.T) {
	root := writeFixture(t, ".tool-versions", "go 1.22.5\ngolang 1.23.1\n")
	ev := DiscoverReleaseEvidence(root)
	if ev.Version != "" {
		t.Fatalf("got %q, want empty (ambiguous go pins)", ev.Version)
	}
}

// TestMiseTomlGoKey — `[tools]`-style mise config with other tools present.
func TestMiseTomlGoKey(t *testing.T) {
	root := writeFixture(t, "mise.toml", "[tools]\nnode = \"20.11.0\"\ngo = \"1.22.5\"\n")
	ev := DiscoverReleaseEvidence(root)
	if ev.Version != "go1.22.5" {
		t.Fatalf("got %q, want go1.22.5", ev.Version)
	}
}

// TestGoVersionFile — plain .go-version still parses as before.
func TestGoVersionFile(t *testing.T) {
	root := writeFixture(t, ".go-version", "1.21.13\n")
	ev := DiscoverReleaseEvidence(root)
	if ev.Version != "go1.21.13" {
		t.Fatalf("got %q, want go1.21.13", ev.Version)
	}
}

// TestToolchainDirectiveWins — go.mod toolchain beats version files.
func TestToolchainDirectiveWins(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module x\n\ngo 1.22\n\ntoolchain go1.22.8\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".tool-versions"), []byte("nodejs 20.0.0\ngo 1.23.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ev := DiscoverReleaseEvidence(dir)
	if ev.Version != "go1.22.8" {
		t.Fatalf("got %q, want go1.22.8 (toolchain directive wins)", ev.Version)
	}
}

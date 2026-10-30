package evidencetools

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/davniy/izyan/internal/domain"
)

// writeProductSnapshot materializes a minimal buildable Go module.
func writeProductSnapshot(t *testing.T, dir string) string {
	t.Helper()
	must(t, os.MkdirAll(dir, 0o755))
	must(t, os.WriteFile(filepath.Join(dir, "go.mod"),
		[]byte("module example.com/isolated\n\ngo 1.23\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(dir, "main.go"),
		[]byte("package main\n\nfunc main() {}\n"), 0o644))
	return dir
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// TestTraversalRejected: ../ escapes and absolute out-of-root reads must
// be gate errors (ERROR), never reads.
func TestTraversalRejected(t *testing.T) {
	parent := t.TempDir()
	root := writeProductSnapshot(t, filepath.Join(parent, "snap"))
	sentinel := filepath.Join(parent, "ground_truth.json")
	must(t, os.WriteFile(sentinel, []byte(`{"label":"exploitable"}`), 0o644))

	s, err := NewSession(SessionConfig{SnapshotRoot: root, Audit: NopAudit{}})
	must(t, err)

	for _, p := range []string{
		"../ground_truth.json",
		"../../etc/passwd",
		sentinel,
		filepath.Join(parent, "snap-evil", "main.go"),
	} {
		o := s.invoke(context.Background(), "read_source", nil, func(c context.Context) (*Observation, error) {
			return s.readSource(c, readSourceArgs{File: p})
		})
		if o.ToolStatus != StatusError {
			t.Fatalf("read %q: expected ERROR, got %s (%q)", p, o.ToolStatus, o.Fact)
		}
		if o.Data != nil {
			t.Fatalf("read %q leaked data: %+v", p, o.Data)
		}
	}
}

// TestSiblingPrefixRejected: a path sharing the root's string prefix but
// outside it (/snap-evil) must not pass the gate.
func TestSiblingPrefixRejected(t *testing.T) {
	parent := t.TempDir()
	root := writeProductSnapshot(t, filepath.Join(parent, "snap"))
	writeProductSnapshot(t, filepath.Join(parent, "snap-evil"))

	s, err := NewSession(SessionConfig{SnapshotRoot: root, Audit: NopAudit{}})
	must(t, err)

	o := s.invoke(context.Background(), "read_source", nil, func(c context.Context) (*Observation, error) {
		return s.readSource(c, readSourceArgs{File: filepath.Join(parent, "snap-evil", "main.go")})
	})
	if o.ToolStatus != StatusError {
		t.Fatalf("sibling-prefix read must be ERROR, got %s", o.ToolStatus)
	}
}

// TestEscapingSymlinkRejected: a symlink inside the snapshot resolving
// outside it must fail session creation (VerifyContained), not produce
// a gate error at read time.
func TestEscapingSymlinkRejected(t *testing.T) {
	parent := t.TempDir()
	root := writeProductSnapshot(t, filepath.Join(parent, "snap"))
	outside := filepath.Join(parent, "host-secret.txt")
	must(t, os.WriteFile(outside, []byte("gt"), 0o644))
	must(t, os.Symlink(outside, filepath.Join(root, "link.go")))

	_, err := NewSession(SessionConfig{SnapshotRoot: root, Audit: NopAudit{}})
	if err == nil {
		t.Fatal("session over a snapshot with an escaping symlink must fail")
	}
	if !strings.Contains(err.Error(), "escape") && !strings.Contains(err.Error(), "containment") {
		t.Fatalf("unexpected error shape: %v", err)
	}
}

// TestBrokenSymlinkRejected: even a broken symlink must fail closed
// (its target can be materialized between check and use).
func TestBrokenSymlinkRejected(t *testing.T) {
	parent := t.TempDir()
	root := writeProductSnapshot(t, filepath.Join(parent, "snap"))
	must(t, os.Symlink(filepath.Join(parent, "nonexistent", "x.go"), filepath.Join(root, "link.go")))
	s, err := NewSession(SessionConfig{SnapshotRoot: root, Audit: NopAudit{}})
	if err != nil {
		return // creation-time rejection is also acceptable isolation
	}
	// A dangling link must fail closed at read time: its target could be
	// materialized between listing and use.
	o := s.invoke(context.Background(), "read_source", nil, func(c context.Context) (*Observation, error) {
		return s.readSource(c, readSourceArgs{File: "link.go"})
	})
	if o.ToolStatus != StatusError {
		t.Fatalf("read through a dangling symlink must be ERROR, got %s", o.ToolStatus)
	}
}

// TestExternalPathReplaceRejected: a local replace whose target resolves
// outside the snapshot must fail creation (CheckPathReplacements).
func TestExternalPathReplaceRejected(t *testing.T) {
	parent := t.TempDir()
	root := writeProductSnapshot(t, filepath.Join(parent, "snap"))
	evil := filepath.Join(parent, "evilmod")
	must(t, os.MkdirAll(evil, 0o755))
	must(t, os.WriteFile(filepath.Join(evil, "go.mod"), []byte("module example.com/evil\ngo 1.23\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(root, "go.mod"),
		[]byte("module example.com/isolated\n\ngo 1.23\n\nrequire example.com/evil v0.0.0\nreplace example.com/evil => ../evilmod\n"), 0o644))

	if _, err := NewSession(SessionConfig{SnapshotRoot: root, Audit: NopAudit{}}); err == nil {
		t.Fatal("escaping local replace must fail session creation")
	}
}

// TestEscapingGoWorkRejected: go.work `use` directives pointing outside
// the snapshot must fail creation.
func TestEscapingGoWorkRejected(t *testing.T) {
	parent := t.TempDir()
	root := writeProductSnapshot(t, filepath.Join(parent, "snap"))
	must(t, os.WriteFile(filepath.Join(root, "go.work"),
		[]byte("go 1.23\n\nuse (\n\t.\n\t../evilmod\n)\n"), 0o644))
	if _, err := NewSession(SessionConfig{SnapshotRoot: root, Audit: NopAudit{}}); err == nil {
		t.Fatal("go.work escaping the snapshot must fail session creation")
	}
}

// TestAmbientEnvNotInherited: injected GOWORK/GOFLAGS/GONOSUMDB in the
// process environment must not reach the loader — with ReplaceEnv the
// loader sees only the whitelist plus hardened overrides.
func TestAmbientEnvNotInherited(t *testing.T) {
	parent := t.TempDir()
	root := writeProductSnapshot(t, filepath.Join(parent, "snap"))

	// Foreign workspace whose only module is a sibling — if GOWORK leaks
	// into the loader, `go list ./...` inside the snapshot fails or sees
	// foreign packages.
	foreign := filepath.Join(parent, "foreign")
	must(t, os.MkdirAll(foreign, 0o755))
	must(t, os.WriteFile(filepath.Join(foreign, "go.mod"), []byte("module example.com/foreign\ngo 1.23\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(foreign, "f.go"), []byte("package foreign\n\nfunc Foreign() {}\n"), 0o644))
	gowork := filepath.Join(parent, "hostile.work")
	must(t, os.WriteFile(gowork, []byte("go 1.23\n\nuse "+foreign+"\n"), 0o644))

	t.Setenv("GOWORK", gowork)
	t.Setenv("GOFLAGS", "-tags=eviltag")
	t.Setenv("GOEXPERIMENT", "fieldtrack")

	s, err := NewSession(SessionConfig{SnapshotRoot: root, Audit: NopAudit{}})
	must(t, err)
	if s.Build.GoWorkFile != domain.GoWorkOff {
		t.Fatalf("session workspace = %q, want %q", s.Build.GoWorkFile, domain.GoWorkOff)
	}
	if strings.Contains(s.Build.GoFlags, "eviltag") {
		t.Fatalf("ambient GOFLAGS leaked into the session build context: %q", s.Build.GoFlags)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	// find_symbol must succeed: the snapshot loads despite the hostile
	// ambient GOWORK, because the loader env is whitelisted.
	o := s.invoke(ctx, "find_entrypoints", nil, func(c context.Context) (*Observation, error) {
		return s.findEntrypoints(c)
	})
	if o.ToolStatus != StatusOK {
		t.Fatalf("index load must not inherit ambient GOWORK: %s", o.Error)
	}
	if d, ok := o.Data.(entrypointsData); !ok || d.Count == 0 {
		t.Fatalf("expected the snapshot's main entrypoint: %+v", o.Data)
	}
	// The foreign module's package must not be visible in results.
	for _, e := range o.Data.(entrypointsData).Entrypoints {
		if strings.Contains(e.File, foreign) || strings.Contains(e.Package, "foreign") {
			t.Fatalf("foreign package leaked into scope: %+v", e)
		}
	}
}

// TestGTUnreachableViaSearch: even if a GT-looking file sits on disk
// next to the snapshot, lexical search cannot return its contents.
func TestGTUnreachableViaSearch(t *testing.T) {
	parent := t.TempDir()
	root := writeProductSnapshot(t, filepath.Join(parent, "snap"))
	gt := filepath.Join(parent, "case.jsonl")
	must(t, os.WriteFile(gt, []byte(`{"task_id":"x","ground_truth":"vulnerable"}`), 0o644))

	s, err := NewSession(SessionConfig{SnapshotRoot: root, Audit: NopAudit{}})
	must(t, err)
	o := s.invoke(context.Background(), "search_source", nil, func(c context.Context) (*Observation, error) {
		return s.searchSource(c, searchSourceArgs{Pattern: "ground_truth"})
	})
	if o.ToolStatus != StatusOK {
		t.Fatalf("search_source failed: %s", o.Error)
	}
	d, ok := o.Data.(searchSourceData)
	if !ok {
		t.Fatalf("data=%+v", o.Data)
	}
	for _, m := range d.Matches {
		if strings.Contains(m, "case.jsonl") || strings.Contains(m, "vulnerable") {
			t.Fatalf("GT content leaked through search: %q", m)
		}
	}
}

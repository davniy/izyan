package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/goanalysis"
)

// writeAnalyzeFixture materializes a minimal module and a local OSV document
// for an advisory whose module is absent from the fixture.
func writeAnalyzeFixture(t *testing.T) (repo, vulnFile string) {
	t.Helper()
	repo = t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "go.mod"),
		[]byte("module example.com/analyze\n\ngo 1.23\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "main.go"),
		[]byte("package main\n\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	vulnFile = filepath.Join(t.TempDir(), "GO-TEST-0001.json")
	doc := `{
  "schema_version": "1.6.0",
  "id": "GO-TEST-0001",
  "summary": "test advisory for an absent module",
  "affected": [{
    "package": {"name": "example.com/absent", "ecosystem": "Go"},
    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}]
  }]
}`
	if err := os.WriteFile(vulnFile, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	return repo, vulnFile
}

// analyzeCase resolves the product snapshot once in SnapshotProduct and
// binds it to the source index before anything can load packages: the index
// observes the resolved context, not the partial operator/construction Build.
func TestAnalyzeResolvedBuildContext(t *testing.T) {
	repo, vulnFile := writeAnalyzeFixture(t)
	// A deliberately different pre-resolution context: binding before the
	// first load must replace it with the resolved snapshot.
	idx := &goanalysis.Index{
		Dir:   repo,
		Build: domain.ProductSnapshot{GOOS: "plan9", GOARCH: "mips"},
	}
	o := analyzeOpts{
		repo:              repo,
		vulnID:            "GO-TEST-0001",
		vulnFile:          vulnFile,
		caseDir:           t.TempDir(),
		detOnly:           true,
		srcIndex:          idx,
		externalCommitSHA: "external-test-sha",
	}
	c, err := analyzeCase(context.Background(), o)
	if err != nil {
		t.Fatalf("analyzeCase: %v", err)
	}
	if c.Product.Target == nil {
		t.Fatal("resolved product carries no target")
	}
	if c.Product.Commit != "external-test-sha" {
		t.Fatalf("snapshot identity = %q", c.Product.Commit)
	}
	bound, ok := idx.BoundBuildContext()
	if !ok {
		t.Fatal("source index was never bound by the snapshot state")
	}
	want := domain.EffectiveBuildContext(c.Product)
	if err := bound.Matches(want); err != nil {
		t.Fatalf("index bound context differs from the case product: %v", err)
	}
	if !reflect.DeepEqual(idx.Build.Target, c.Product.Target) {
		t.Fatalf("index target = %+v, case product target = %+v", idx.Build.Target, c.Product.Target)
	}
	sawBuildEvidence := false
	for _, ev := range c.EvidenceGraph.Evidence {
		if ev.Source == "product build context" {
			sawBuildEvidence = true
		}
	}
	if !sawBuildEvidence {
		t.Fatal("case does not record per-case build-context provenance")
	}
}

// prepareScanShared resolves the single scan snapshot before constructing any
// shared resource; the module listing runs through the affected tool under
// that snapshot and the shared cache refuses another build.
func TestScanResolvedBuildContext(t *testing.T) {
	repo, _ := writeAnalyzeFixture(t)
	o := analyzeOpts{repo: repo, externalCommitSHA: "external-scan-sha"}
	snap, mods, err := prepareScanShared(context.Background(), &o, repo)
	if err != nil {
		t.Fatalf("prepareScanShared: %v", err)
	}
	if snap.Repository != repo || snap.Commit != "external-scan-sha" {
		t.Fatalf("snapshot identity = %q @ %q", snap.Repository, snap.Commit)
	}
	if snap.Target == nil || snap.Target.GOOS == "" || snap.Target.GOARCH == "" {
		t.Fatalf("resolved snapshot has no target: %+v", snap.Target)
	}
	if o.snapshot == nil || !reflect.DeepEqual(*o.snapshot, snap) {
		t.Fatalf("scan snapshot not recorded on analyzeOpts: %+v", o.snapshot)
	}
	if o.srcIndex == nil || !reflect.DeepEqual(o.srcIndex.Build, snap) {
		t.Fatalf("shared index not constructed from the resolved snapshot")
	}
	if o.goTool == nil || o.gvRunner == nil {
		t.Fatal("shared tool/runner not constructed")
	}
	if len(mods) == 0 {
		t.Fatal("module listing returned nothing")
	}
	// The module listing already bound the shared cache to the resolved
	// build: another context is refused rather than answered from cache.
	other := snap
	other.GOOS = "windows"
	if _, _, err := o.goTool.ListModules(context.Background(), repo, other); !errors.Is(err, domain.ErrBuildContextMismatch) {
		t.Fatalf("shared tool accepted another build: %v", err)
	}
	// SnapshotProduct binds the same context per case: matching succeeds.
	if err := o.srcIndex.BindBuild(snap); err != nil {
		t.Fatalf("binding the scan context into the shared index: %v", err)
	}
}

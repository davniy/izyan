package goanalysis

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/davniy/izyan/internal/repository"
)

func TestLocalInventoryRequiresCompletePinnedProductCapture(t *testing.T) {
	root := t.TempDir()
	sourceFixture(t, root, "go.mod", "module example.com/product\ngo 1.25\nrequire example.com/dep v1.0.0\nreplace example.com/dep => ./deps/dep\n")
	sourceFixture(t, root, "deps/dep/go.mod", "module example.com/dep\ngo 1.25\n")
	sourceFixture(t, root, "deps/dep/pkg/a.go", "package pkg\nimport \"os\"\nfunc A(){os.MkdirAll(\"a\",0711)}\n")
	sourceFixture(t, root, "deps/dep/pkg/a-dir/z.go", "package z\n")
	sourceFixture(t, root, "deps/dep/pkg/a-file.go", "package pkg\n")
	build := recordedBuild(t, root, "")
	hash, err := repository.ContentHash(root)
	if err != nil {
		t.Fatal(err)
	}
	build.ContentHash = hash
	ix := &Index{Dir: root, Build: build}
	got, err := ix.SelectedSourceCensus("example.com/dep", "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Completeness.Input.Complete {
		t.Fatalf("anchored captured local tree refused: %+v", got.Completeness.Input)
	}
	if err := os.Remove(filepath.Join(root, "deps/dep/pkg/a-file.go")); err != nil {
		t.Fatal(err)
	}
	got, err = ix.SelectedSourceCensus("example.com/dep", "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if got.Completeness.Input.Complete {
		t.Fatal("deleted local file was certified by directory listing")
	}
}

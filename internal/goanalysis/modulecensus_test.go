package goanalysis

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/fixbinding"
	"golang.org/x/mod/sumdb/dirhash"
)

func censusArchive(t *testing.T, files map[string]string) ([]byte, string) {
	t.Helper()
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, "example.com/dep@v1.0.0/"+name)
	}
	sort.Strings(names)
	hash, err := dirhash.Hash1(names, func(name string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(files[strings.TrimPrefix(name, "example.com/dep@v1.0.0/")])), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range names {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write([]byte(files[strings.TrimPrefix(name, "example.com/dep@v1.0.0/")])); err != nil {
			t.Fatal(err)
		}
	}
	if err = zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), hash
}

func TestVendorSubsetCannotCertifyWholeSource(t *testing.T) {
	canonical := map[string]string{
		"go.mod":                     "module example.com/dep\ngo 1.25\n",
		"linked/a.go":                "package linked\nimport \"os\"\nfunc A(){ os.MkdirAll(\"a\",0711) }\n",
		"linked/b.go":                "package linked\nimport \"os\"\nfunc B(){ os.MkdirAll(\"b\",0711) }\n",
		"alternative/alt.go":         "package alternative\nimport \"os\"\nfunc Alt(){ os.MkdirAll(\"alt\",0711) }\n",
		"alternative/alt_windows.go": "//go:build windows\n\npackage alternative\nfunc Windows(){}\n",
	}
	for _, test := range []struct {
		name    string
		archive bool
		mutate  string
		want    bool
	}{
		{"normal_pruned_vendor_only", false, "", false},
		{"missing_unlisted_alternative", false, "alternative", false},
		{"one_file_removed_nonempty_package", true, "linked/b.go", false},
		{"vendor_modification", true, "modify", false},
		{"incomplete_build_variant_inventory", true, "variant", false},
		{"independent_archive_reconciles_pruned_subset", true, "", true},
		{"vendor_extra", true, "extra", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			cache := t.TempDir()
			sourceFixture(t, root, "go.mod", "module example.com/product\ngo 1.25\nrequire example.com/dep v1.0.0\n")
			sourceFixture(t, root, "vendor/modules.txt", "# example.com/dep v1.0.0\n## explicit; go 1.25\nexample.com/dep/linked\n")
			for _, name := range []string{"linked/a.go", "linked/b.go"} {
				if name == test.mutate {
					continue
				}
				sourceFixture(t, root, "vendor/example.com/dep/"+name, canonical[name])
			}
			if test.mutate == "modify" {
				sourceFixture(t, root, "vendor/example.com/dep/linked/a.go", strings.ReplaceAll(canonical["linked/a.go"], "0711", "0777"))
			}
			if test.mutate == "variant" {
				sourceFixture(t, root, "vendor/example.com/dep/linked/new_linux.go", "//go:build linux\n\npackage linked\nfunc Extra(){}\n")
			}
			if test.mutate == "extra" {
				sourceFixture(t, root, "vendor/example.com/dep/linked/extra.go", "package linked\nfunc Extra(){}\n")
			}
			if test.archive {
				data, hash := censusArchive(t, canonical)
				file := filepath.Join(cache, "cache/download/example.com/dep/@v/v1.0.0.zip")
				if err := os.MkdirAll(filepath.Dir(file), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(file, data, 0644); err != nil {
					t.Fatal(err)
				}
				sourceFixture(t, root, "go.sum", "example.com/dep v1.0.0 "+hash+"\n")
			}
			ix := &Index{Dir: root, Env: []string{"GOMODCACHE=" + cache}, Build: domain.ProductSnapshot{VendorMode: true}}
			got, err := ix.SelectedSourceCensus("example.com/dep", "v1.0.0")
			if err != nil {
				t.Fatal(err)
			}
			if got.Completeness.Input.Complete != test.want {
				t.Fatalf("input=%+v reconciliation=%+v want %v", got.Completeness.Input, got.Inventory.Reconciliation, test.want)
			}
			if got.Completeness.Input.Aspect != fixbinding.AspectInput || got.Completeness.Parse.Aspect != fixbinding.AspectParse || got.Completeness.Analysis.Aspect != fixbinding.AspectAnalysis || got.Completeness.Cover.Aspect != fixbinding.AspectCover {
				t.Fatal("four completeness aspects not separate")
			}
			if got.Completeness.Cover.Complete {
				t.Fatal("source inventory authorised a necessary cover")
			}
			if test.want {
				found := false
				for _, op := range got.Census.Operations {
					if op.Package == "example.com/dep/alternative" {
						found = true
					}
				}
				if !found {
					t.Fatal("discovery was restricted to product-linked vendor subset")
				}
				if got.Inventory.Reconciliation == nil || len(got.Inventory.Reconciliation.Pruned) == 0 {
					t.Fatal("pruned alternatives not accounted")
				}
			}
		})
	}
}

func TestInventoryAnchorRequiresCapturedChecksumAndBytes(t *testing.T) {
	data, hash := censusArchive(t, map[string]string{"p.go": "package p\n"})
	e := fixbinding.ArchiveEvidence{Bytes: data, Module: "example.com/dep", Version: "v1.0.0", GoSum: []byte("example.com/dep v1.0.0 " + hash + "\n")}
	anchor, err := fixbinding.CheckArchiveAnchor(e)
	if err != nil {
		t.Fatal(err)
	}
	anchor.Files = nil
	anchor.Variants = []string{"asserted"}
	anchor.Complete = true
	observed := fixbinding.ObservedSource{Kind: fixbinding.SourceVendor, WalkComplete: true, ManifestPackages: []string{"."}, Files: []fixbinding.ObservedFile{{Path: "p.go", Bytes: []byte("package p\n"), Digest: "asserted"}}}
	inv := fixbinding.AssembleInventory(fixbinding.InventoryInput{Module: e.Module, Version: e.Version, Observed: observed, Anchor: anchor})
	if !inv.Input.Complete || len(inv.Anchor.Files) != 1 {
		t.Fatalf("did not rederive archive: %+v", inv.Input)
	}
	anchor.Archive.GoSum = []byte("example.com/dep v1.0.0 h1:wrong\n")
	inv = fixbinding.AssembleInventory(fixbinding.InventoryInput{Module: e.Module, Version: e.Version, Observed: observed, Anchor: anchor})
	if inv.Input.Complete {
		t.Fatal("incorrect checksum admitted")
	}
	inv = fixbinding.AssembleInventory(fixbinding.InventoryInput{Module: e.Module, Version: e.Version, Observed: observed, Anchor: &fixbinding.SourceAnchor{Module: e.Module, Version: e.Version, Complete: true, Checksum: fixbinding.ChecksumEvidence{Kind: fixbinding.ChecksumGoSumH1, Value: hash}}})
	if inv.Input.Complete {
		t.Fatal("asserted complete directory inventory admitted")
	}
}

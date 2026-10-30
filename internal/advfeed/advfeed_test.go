package advfeed

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---- fixture helpers ----

type testAffected struct {
	Ecosystem string   `json:"ecosystem"`
	Name      string   `json:"name"`
	Imports   []Import `json:"imports,omitempty"`
}

func docJSON(id string, aliases []string, affected []testAffected) string {
	var b strings.Builder
	fmt.Fprintf(&b, `{"id":%q`, id)
	if len(aliases) > 0 {
		b.WriteString(`,"aliases":[`)
		for i, a := range aliases {
			if i > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, "%q", a)
		}
		b.WriteString("]")
	}
	b.WriteString(`,"affected":[`)
	for i, a := range affected {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"package":{"ecosystem":%q,"name":%q}`, a.Ecosystem, a.Name)
		if len(a.Imports) > 0 {
			b.WriteString(`,"ecosystem_specific":{"imports":[`)
			for j, imp := range a.Imports {
				if j > 0 {
					b.WriteString(",")
				}
				fmt.Fprintf(&b, `{"path":%q`, imp.Path)
				if len(imp.Symbols) > 0 {
					b.WriteString(`,"symbols":[`)
					for k, s := range imp.Symbols {
						if k > 0 {
							b.WriteString(",")
						}
						fmt.Fprintf(&b, "%q", s)
					}
					b.WriteString("]")
				}
				b.WriteString("}")
			}
			b.WriteString(`]}`)
		}
		b.WriteString("}")
	}
	b.WriteString("]}")
	return b.String()
}

func writeDocDir(t *testing.T, docs map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range docs {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func zipBytes(t *testing.T, docs map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range docs {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sha256Of(b []byte) [32]byte {
	return sha256.Sum256(b)
}

// ---- open + index + resolve ----

func TestOpenDirectoryIndexesByIDAndAlias(t *testing.T) {
	// A GHSA-shaped record with no imports, plus the Go-ecosystem record
	// that lists it as an alias and carries the package/symbol subjects.
	// An absent declaration in one document does not veto another
	// document's declaration — only disagreeing non-empty sets do.
	dir := writeDocDir(t, map[string]string{
		"GHSA-aaaa-bbbb-cccc.json": docJSON("GHSA-aaaa-bbbb-cccc", nil,
			[]testAffected{{Ecosystem: "Go", Name: "example.com/mod"}}),
		"GO-2099-0001.json": docJSON("GO-2099-0001", []string{"GHSA-aaaa-bbbb-cccc", "CVE-2099-1111"},
			[]testAffected{{Ecosystem: "Go", Name: "example.com/mod",
				Imports: []Import{{Path: "example.com/mod/pkg", Symbols: []string{"Serve", "Listen"}}}}}),
	})
	f, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if f.Prov.SHA256 == "" || f.Prov.Ref == "" {
		t.Fatalf("provenance empty: %+v", f.Prov)
	}
	res := f.ResolveImports("GHSA-aaaa-bbbb-cccc", nil, "example.com/mod")
	if !res.OK || res.SourceID != "GO-2099-0001" {
		t.Fatalf("resolve = %+v, want subjects from GO-2099-0001", res)
	}
	if len(res.Imports) != 1 || res.Imports[0].Path != "example.com/mod/pkg" {
		t.Fatalf("imports = %+v", res.Imports)
	}
}

// Two feed documents declaring *different* non-empty import sets for the
// same module refuse to pick one — the resolution is ambiguous.
func TestResolveImportsAmbiguousAcrossDocs(t *testing.T) {
	dir := writeDocDir(t, map[string]string{
		"A-1.json": docJSON("A-1", []string{"B-1"},
			[]testAffected{{Ecosystem: "Go", Name: "example.com/mod",
				Imports: []Import{{Path: "example.com/mod/p", Symbols: []string{"F"}}}}}),
		"B-1.json": docJSON("B-1", []string{"A-1"},
			[]testAffected{{Ecosystem: "Go", Name: "example.com/mod",
				Imports: []Import{{Path: "example.com/mod/q", Symbols: []string{"G"}}}}}),
	})
	f, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	res := f.ResolveImports("A-1", []string{"B-1"}, "example.com/mod")
	if res.OK || res.Status != StatusAmbiguous {
		t.Fatalf("want ambiguous, got %+v", res)
	}
}

// When the id itself indexes a document that only *aliases* a carrier,
// the carrier supplies the subjects — the id doc does not exist in the
// dump (typical GHSA -> GO-only-dump flow).
func TestResolveImportsViaAliasDoc(t *testing.T) {
	dir := writeDocDir(t, map[string]string{
		"GO-2099-0002.json": docJSON("GO-2099-0002", []string{"GHSA-xxxx-yyyy-zzzz"},
			[]testAffected{{Ecosystem: "Go", Name: "example.com/mod",
				Imports: []Import{
					{Path: "example.com/mod/a", Symbols: []string{"F", "G"}},
					{Path: "example.com/mod/b", Symbols: []string{"H"}},
				}}}),
	})
	f, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	res := f.ResolveImports("GHSA-xxxx-yyyy-zzzz", nil, "example.com/mod")
	if !res.OK || res.SourceID != "GO-2099-0002" || res.MatchedID != "GHSA-xxxx-yyyy-zzzz" {
		t.Fatalf("resolution = %+v", res)
	}
	if len(res.Imports) != 2 || res.Imports[0].Path != "example.com/mod/a" {
		t.Fatalf("imports = %+v", res.Imports)
	}
}

func TestResolveImportsNotFoundAndNoImports(t *testing.T) {
	dir := writeDocDir(t, map[string]string{
		"GO-2099-0003.json": docJSON("GO-2099-0003", nil,
			[]testAffected{{Ecosystem: "Go", Name: "example.com/other",
				Imports: []Import{{Path: "example.com/other/p"}}}}),
		"GO-2099-0004.json": docJSON("GO-2099-0004", nil,
			[]testAffected{{Ecosystem: "Go", Name: "example.com/mod"}}),
	})
	f, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if r := f.ResolveImports("GO-NONE", nil, "example.com/mod"); r.Status != StatusNotFound {
		t.Fatalf("not_found: %+v", r)
	}
	if r := f.ResolveImports("GO-2099-0003", nil, "example.com/mod"); r.Status != StatusNoImports {
		t.Fatalf("no imports for module: %+v", r)
	}
	if r := f.ResolveImports("GO-2099-0004", nil, "example.com/mod"); r.Status != StatusNoImports {
		t.Fatalf("empty imports: %+v", r)
	}
}

func TestOpenZipIndexesMembers(t *testing.T) {
	z := zipBytes(t, map[string]string{
		"GO-2099-0005.json": docJSON("GO-2099-0005", []string{"CVE-2099-2222"},
			[]testAffected{{Ecosystem: "Go", Name: "example.com/z",
				Imports: []Import{{Path: "example.com/z", Symbols: []string{"Run"}}}}}),
		"nested/skip.txt": "not json",
	})
	path := filepath.Join(t.TempDir(), "dump.zip")
	if err := os.WriteFile(path, z, 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := Open(path)
	if err != nil {
		t.Fatalf("Open zip: %v", err)
	}
	want := fmt.Sprintf("%x", sha256Of(z))
	if f.Prov.SHA256 != want {
		t.Fatalf("zip sha256 = %q, want %q", f.Prov.SHA256, want)
	}
	res := f.ResolveImports("CVE-2099-2222", nil, "example.com/z")
	if !res.OK || res.Imports[0].Path != "example.com/z" {
		t.Fatalf("zip resolution = %+v", res)
	}
}

func TestOpenRejectsGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dump.zip")
	if err := os.WriteFile(path, []byte("definitely not a zip"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("garbage file accepted as a feed")
	}
}

func TestAcquireRequiresASource(t *testing.T) {
	if _, err := Acquire(context.Background(), Options{}); err == nil {
		t.Fatal("empty options accepted")
	}
	if _, err := Acquire(context.Background(), Options{LocalPath: "/x", BaseURL: "https://x"}); err == nil {
		t.Fatal("mutually exclusive sources accepted")
	}
}

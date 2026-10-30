package affected

import (
	"strings"
	"testing"
)

// completeInventoryStream is an edge-closed product stream: two product
// roots, one dependency-only node, no package errors, no dangling edges and
// no orphans. example.com/dep/vuln is linked; example.com/dep/absent is the
// absence control.
const completeInventoryStream = `{"ImportPath":"example.com/prod","Name":"main","Deps":["example.com/prod/lib","example.com/dep/vuln"]}
{"ImportPath":"example.com/prod/lib","Name":"lib","Deps":[]}
{"ImportPath":"example.com/dep/vuln","Name":"vuln","DepOnly":true,"Module":{"Path":"example.com/dep","Version":"v1.0.0"},"Deps":[]}`

func TestPackageInventoryComplete(t *testing.T) {
	inv, err := CompletePackageInventory([]byte(completeInventoryStream), "go list -deps -test -json ./...")
	if err != nil {
		t.Fatalf("CompletePackageInventory: %v", err)
	}
	if len(inv.Packages) != 3 {
		t.Fatalf("packages = %d, want 3", len(inv.Packages))
	}
	for _, path := range []string{"example.com/prod", "example.com/prod/lib", "example.com/dep/vuln"} {
		if !inv.Paths[path] {
			t.Fatalf("paths missing %q: %v", path, inv.Paths)
		}
	}
	// The valid complete absence control: the inventory closed without
	// error and the subject simply is not linked.
	if inv.Paths["example.com/dep/absent"] {
		t.Fatal("absence control path reported as linked")
	}
}

func TestPackageInventoryEmptyEnumeration(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"empty stdout", nil},
		{"whitespace only", []byte(" \n\t")},
		{"empty JSON array", []byte(`[]`)},
		{"null value", []byte(`null`)},
	} {
		if _, err := CompletePackageInventory(tc.raw, "go list"); err == nil {
			t.Fatalf("%s: empty enumeration admitted as complete", tc.name)
		}
	}
}

// A truncated value or trailing token is a decode failure even when every
// complete object before it is valid: a valid prefix is never a stream.
func TestPackageInventoryTruncatedAndMalformedSuffix(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"truncated object", []byte(`{"ImportPath":"example.com/prod","Name":"ma`)},
		{"truncated stream", []byte(completeInventoryStream + "\n" + `{"ImportPath":"example.com/prod/broken","Name":"bro`)},
		{"stray close brace", []byte(completeInventoryStream + "\n}")},
		{"stray close bracket", []byte(completeInventoryStream + "\n]")},
		{"trailing garbage", []byte(completeInventoryStream + "\ngarbage")},
		{"malformed suffix", []byte(completeInventoryStream + "\n{\"ImportPath\":}")},
	} {
		if _, err := CompletePackageInventory(tc.raw, "go list"); err == nil {
			t.Fatalf("%s: malformed stream admitted as complete", tc.name)
		}
	}
}

// A parseable prefix keeps its witnessed package nodes for positive-only
// observations, but the inventory is still an error.
func TestPackageInventoryPartialKeepsWitnessedPackages(t *testing.T) {
	raw := []byte(completeInventoryStream + "\n" + `{"ImportPath":"example.com/prod/broken","Name":"bro`)
	inv, err := CompletePackageInventory(raw, "go list")
	if err == nil {
		t.Fatal("truncated stream admitted as complete")
	}
	if !inv.Paths["example.com/dep/vuln"] || !inv.Paths["example.com/prod"] {
		t.Fatalf("witnessed package nodes lost from the partial inventory: %v", inv.Paths)
	}
	if inv.Paths["example.com/prod/broken"] {
		t.Fatalf("truncated value became a package node: %v", inv.Paths)
	}
}

func TestPackageInventoryPackageErrorNodes(t *testing.T) {
	for _, tc := range []struct {
		name string
		node string
	}{
		{"incomplete", `{"ImportPath":"example.com/prod/broken","Name":"broken","Deps":[],"Incomplete":true}`},
		{"error", `{"ImportPath":"example.com/prod/broken","Name":"broken","Deps":[],"Error":{"Err":"compile failed"}}`},
		{"deps errors", `{"ImportPath":"example.com/prod/broken","Name":"broken","Deps":[],"DepsErrors":[{"Err":"missing import"}]}`},
	} {
		raw := []byte(completeInventoryStream + "\n" + tc.node)
		inv, err := CompletePackageInventory(raw, "go list")
		if err == nil {
			t.Fatalf("%s: package-error node admitted as complete", tc.name)
		}
		if !strings.Contains(err.Error(), "package errors") {
			t.Fatalf("%s: error does not name the package-error condition: %v", tc.name, err)
		}
		if !inv.Paths["example.com/dep/vuln"] {
			t.Fatalf("%s: witnessed package nodes lost: %v", tc.name, inv.Paths)
		}
	}
}

func TestPackageInventoryDuplicateNode(t *testing.T) {
	raw := []byte(completeInventoryStream + "\n" + `{"ImportPath":"example.com/prod/lib","Deps":[]}`)
	if _, err := CompletePackageInventory(raw, "go list"); err == nil ||
		!strings.Contains(err.Error(), "duplicate package node") {
		t.Fatalf("duplicate node: err=%v", err)
	}
}

func TestPackageInventoryDanglingEdge(t *testing.T) {
	raw := []byte(`{"ImportPath":"example.com/prod","Name":"main","Deps":["example.com/gone"]}`)
	if _, err := CompletePackageInventory(raw, "go list"); err == nil ||
		!strings.Contains(err.Error(), "unresolved dependency edges") {
		t.Fatalf("dangling edge: err=%v", err)
	}
}

func TestPackageInventoryOrphanNode(t *testing.T) {
	raw := []byte(`{"ImportPath":"example.com/prod","Name":"main","Deps":[]}
{"ImportPath":"example.com/dep/vuln","Name":"vuln","DepOnly":true,"Deps":[]}`)
	if _, err := CompletePackageInventory(raw, "go list"); err == nil ||
		!strings.Contains(err.Error(), "unreachable from any root") {
		t.Fatalf("orphan node: err=%v", err)
	}
}

func TestPackageInventoryInconsistentDependencyInventory(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{"omitted deps with imports", `{"ImportPath":"example.com/prod","Name":"main","Imports":["example.com/dep/vuln"]}
{"ImportPath":"example.com/prod/lib","Name":"lib","Deps":["fmt"],"Imports":["fmt"]}
{"ImportPath":"example.com/dep/vuln","Name":"vuln","DepOnly":true,"Deps":[]}
{"ImportPath":"fmt","Name":"fmt","DepOnly":true,"Deps":[]}`},
		{"import not in deps", `{"ImportPath":"example.com/prod","Name":"main","Deps":["fmt"],"Imports":["fmt","example.com/dep/vuln"]}
{"ImportPath":"fmt","Name":"fmt","DepOnly":true,"Deps":[]}
{"ImportPath":"example.com/dep/vuln","Name":"vuln","DepOnly":true,"Deps":[]}`},
	} {
		if _, err := CompletePackageInventory([]byte(tc.raw), "go list"); err == nil ||
			!strings.Contains(err.Error(), "inconsistent dependency inventory") {
			t.Fatalf("%s: err=%v", tc.name, err)
		}
	}
}

// PackageImportPaths is the absence decoder used by downstream verifiers: it
// must apply the same completeness rules and never return a set from a
// partial or error-bearing stream.
func TestPackageImportPathsRequiresCompleteInventory(t *testing.T) {
	set, err := PackageImportPaths([]byte(completeInventoryStream))
	if err != nil {
		t.Fatalf("complete inventory: %v", err)
	}
	if !set["example.com/dep/vuln"] || set["example.com/dep/absent"] {
		t.Fatalf("paths = %v", set)
	}
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"truncated", []byte(completeInventoryStream + "\n" + `{"ImportPath":"example.com/prod/broken"`)},
		{"trailing token", []byte(completeInventoryStream + "\n]")},
		{"error node", []byte(completeInventoryStream + "\n" + `{"ImportPath":"example.com/prod/broken","Incomplete":true}`)},
		{"dangling edge", []byte(`{"ImportPath":"example.com/prod","Deps":["example.com/gone"]}`)},
		{"empty enumeration", []byte(`[]`)},
	} {
		if _, err := PackageImportPaths(tc.raw); err == nil {
			t.Fatalf("%s: incomplete stream produced an absence set", tc.name)
		}
	}
}

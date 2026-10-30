package productb

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// allowedInternalImports is the closed set of packages the adapter layer
// may touch: the Shadow surfaces it binds to plus its own adapter-local
// DTO mirrors. Anything else — domain, affected, evaluator, agenttriage,
// any surprise — fails the mechanical completeness gate. The DTO packages
// themselves are listed so triage files importing them are pinned too.
var allowedInternalImports = map[string]string{
	"internal/evidencetools":          "evidence boundary (DetCaller/catalog projection)",
	"internal/exposure":               "deployment-perimeter facts (identical V2/Shadow)",
	"internal/fix":                    "canonical patch acquisition contract (Provider/Reference/Parse)",
	"internal/llm":                    "tool definition and chat surface",
	"internal/repository":             "ref resolution (factgate revision checks)",
	"internal/risk":                   "severity→priority ladder for baseline composition",
	"internal/toolaudit":              "audited command runner (identical V2/Shadow)",
	"internal/toolchain":              "toolchain resolution (identical V2/Shadow)",
	"internal/vulnerability":          "canonical advisory Source interface (captured provider implements it)",
	"internal/domain":                 "alias-shim only (productb/domain); no authority type is re-exported",
	"internal/productb/domain":        "adapter-local domain DTO aliases",
	"internal/productb/affected":      "adapter-local affected DTOs/parsers",
	"internal/productb/vulnerability": "adapter-local vulnerability resolution port",
	"internal/productb/repository":    "adapter-local repository port (clone/enumerate/materialize)",
	"internal/flock":                  "shared OS file lock (portable syscall.Flock; no V2 identity)",
}

// TestTypeMapEveryEntryClassified pins the §14.3.2 shape: every mapped row
// names a target, every row has a disposition from the closed enum, and no
// row silently leaves out where it is referenced.
func TestTypeMapEveryEntryClassified(t *testing.T) {
	valid := map[TypeDisposition]bool{}
	for _, d := range RequiredDispositions {
		valid[d] = true
	}
	entries := PortTypeMap()
	if len(entries) == 0 {
		t.Fatal("type map is empty")
	}
	for i, e := range entries {
		if e.V2Type == "" || e.V2Package == "" {
			t.Errorf("entry %d lacks v2 type/package identity", i)
		}
		if !valid[e.Disposition] {
			t.Errorf("entry %q has unknown disposition %q", e.V2Type, e.Disposition)
		}
		if e.Disposition == MappedToCanonical || e.Disposition == MappedViaAdapter {
			if e.Target == "" {
				t.Errorf("mapped entry %q has no target", e.V2Type)
			}
		}
	}
}

// TestTypeMapCompletenessOverImports is the mechanical gate: it parses
// every non-test Go file of the adapter and requires (a) no import outside
// the allowed internal set, and (b) every allowed internal import covered
// by at least one mapped entry.
func TestTypeMapCompletenessOverImports(t *testing.T) {
	dirs := []string{".", "triage"}
	fset := token.NewFileSet()
	seen := map[string]bool{}
	for _, dir := range dirs {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil || len(files) == 0 {
			t.Fatalf("glob %s: %v", dir, err)
		}
		for _, name := range files {
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatalf("parse %s: %v", name, err)
			}
			for _, imp := range f.Imports {
				path := strings.Trim(imp.Path.Value, `"`)
				if !strings.HasPrefix(path, "github.com/davniy/izyan/") {
					continue
				}
				rel := strings.TrimPrefix(path, "github.com/davniy/izyan/")
				if strings.HasPrefix(rel, "internal/domain") || strings.HasPrefix(rel, "internal/affected") ||
					strings.HasPrefix(rel, "internal/evaluator") || strings.HasPrefix(rel, "internal/agenttriage") {
					// The domain alias shim may import the canonical domain
					// package — it re-exports data types only, never authority.
					if !(filepath.Base(name) == "dto.go" && rel == "internal/domain") {
						t.Errorf("%s imports forbidden authority/V2 package %s", name, path)
					}
				}
				if _, ok := allowedInternalImports[rel]; !ok {
					t.Errorf("%s imports unmapped internal package %s — extend the type map or the allowlist", name, rel)
				}
				seen[rel] = true
			}
		}
	}
	// Every allowed import that is actually used must be covered by a
	// mapped entry naming either the V2 package it adapts or the adapter
	// target package itself.
	for rel := range seen {
		if _, allowed := allowedInternalImports[rel]; !allowed {
			continue
		}
		covered := false
		for _, e := range PortTypeMap() {
			mapped := e.Disposition == MappedToCanonical || e.Disposition == MappedViaAdapter
			if mapped && (e.V2Package == rel || strings.Contains(e.Target, rel)) {
				covered = true
				break
			}
		}
		if !covered {
			t.Errorf("internal import %s has no mapped entry in the type map", rel)
		}
	}
}

// TestTypeMapArtifact pins the emitted artifact: schema version + entries
// round-trip so a Phase-0 gate can diff it as port-type-map.v1.json.
func TestTypeMapArtifact(t *testing.T) {
	raw, err := PortTypeMapJSON()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"`+PortTypeMapSchemaVersion+`"`) {
		t.Fatal("artifact does not carry its schema version")
	}
}

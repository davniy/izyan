package productb_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// S-12 boundary guard: the ported V2 research/refindex/reportcheck lane
// lives exclusively under internal/productb and must never reach back
// into Product A surfaces.
//
// Forbidden inside the three ported packages (non-test files):
//
//   - internal/research — Product A's own research lane; the port is a
//     sibling, never a merge or re-import (S-12 isolation rule).
//   - internal/domain / internal/affected / internal/evaluator /
//     agenttriage — the canonical authority contract and the V2 package
//     tree the adapter replaces; §14.3.2 maps types at the adapter
//     boundary, never by importing the other side.
//
// Canonical mechanics (goanalysis, evidencetools, fix, toolaudit, llm)
// stay shared — the same §14.3.2 "map" disposition the detools broker
// already uses: identical interfaces, identical domain data types,
// no Product A authority state is created or mutated.
func TestS12LaneIsolation(t *testing.T) {
	forbidden := []string{
		"internal/research",
		"internal/domain",
		"internal/affected",
		"internal/evaluator",
		"agenttriage",
	}
	// domain is the blessed alias layer: its only allowed import of
	// internal/domain is the §14.3.2 "map" disposition — the authority-type
	// scan below still forbids any authority construction there.
	aliasLayer := map[string]string{"domain": "internal/domain", "affected": "internal/affected"}
	// The guard covers every Product-B package, not a frozen list: walk
	// the tree and apply the import rules to each directory that holds
	// non-test Go sources. New packages inherit the boundary without a
	// test change.
	dirs := productBDirs(t)
	fset := token.NewFileSet()
	for _, dir := range dirs {
		pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
			return !strings.HasSuffix(fi.Name(), "_test.go")
		}, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", dir, err)
		}
		for _, pkg := range pkgs {
			for file, f := range pkg.Files {
				for _, imp := range f.Imports {
					path := strings.Trim(imp.Path.Value, `"`)
					for _, bad := range forbidden {
						if strings.Contains(path, bad) {
							if target, ok := aliasLayer[filepath.Base(dir)]; ok && bad == target {
								continue
							}
							t.Errorf("%s/%s imports forbidden package %q",
								dir, filepath.Base(file), path)
						}
					}
				}
			}
		}
	}
}

// productBDirs lists every directory under internal/productb that
// contains at least one non-test .go file — the complete adapter lane
// the boundary rules apply to.
func productBDirs(t *testing.T) []string {
	t.Helper()
	root := filepath.Dir(".")
	var dirs []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		entries, rerr := os.ReadDir(path)
		if rerr != nil {
			return rerr
		}
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".go") && !strings.HasSuffix(e.Name(), "_test.go") {
				dirs = append(dirs, path)
				break
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if len(dirs) == 0 {
		t.Fatalf("walk %s: no Product-B package directories found", root)
	}
	return dirs
}

// TestS12NoProductAAuthorityMutation pins the output side of the lane:
// nothing the research/refindex/reportcheck code writes may construct or
// mutate Product A authority objects. The import guard above makes the
// canonical domain package unreachable, so no authority type can be
// named — this test scans the non-test sources for the authority type
// spellings directly, catching a drifted alias or a smuggled local
// redeclaration before review has to.
func TestS12NoProductAAuthorityMutation(t *testing.T) {
	// Authority spellings a Product-B adapter must never construct,
	// mutate or smuggle in: the canonical Product A verdict/evidence
	// types (§14.3.2 keeps them adapter-side names, never shared types).
	authorityTypes := []string{
		"VerdictResult",
		"EvidenceGraph",
		"NegativeVerification",
		"AnalysisCase",
	}
	for _, dir := range productBDirs(t) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			b, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatalf("read %s/%s: %v", dir, name, err)
			}
			for _, typ := range authorityTypes {
				// A type construction/mutation surface looks like
				// `T{`, `&T{`, `.T(` or `type x T`; the names are also
				// matched bare inside selector chains to catch field
				// writes.
				for _, pat := range []string{
					typ + "{", "&" + typ + "{", "." + typ + "(",
					"type " + typ + " ", "type " + typ + "=",
				} {
					if strings.Contains(string(b), pat) {
						t.Errorf("%s/%s references Product A authority type %q (%q)",
							dir, name, typ, pat)
					}
				}
			}
		}
	}
}

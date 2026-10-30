package main

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runtime_boundary_test.go pins the Phase-4 CLI boundary:
//
//   - `izyan research` is a deterministic evidence/proof lane plus saved-turn
//     replay: it starts no model, launches no container and never calls the
//     retired research agent harness;
//   - `izyan triage` is the one live human investigator;
//   - the frozen B1 arm is reachable only under `izyan eval`.

// TestResearchRouteStartsNoModel requires that the research command's own
// file holds no model, harness or container invocation. The flag surface is
// asserted separately (TestResearch_OfflineLaneFlagsRegistered); this reads
// the call sites.
func TestResearchRouteStartsNoModel(t *testing.T) {
	banned := []string{
		"research.RunAgent(",
		"llm.NewClient(",
		"llm.NewResearcher(",
		"exec.Command(",
		"exec.CommandContext(",
		"http.Post(",
		"http.NewRequest(",
	}
	for _, path := range []string{"research.go", "research_history.go"} {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, b := range banned {
			if strings.Contains(string(src), b) {
				t.Errorf("%s calls %q: the research route must start no model", path, b)
			}
		}
	}
}

// TestOnlyTriageOwnsLiveHumanProjection requires that exactly one route
// constructs the Product B investigator. The Product A `internal/llm` client
// is a different thing — it annotates the analysis pipeline — so the pinned
// invariant is the *investigator*: only triage* may import productb/triage,
// and no other route may start a Product B investigation loop.
func TestOnlyTriageOwnsLiveHumanProjection(t *testing.T) {
	// The one live investigator lives here.
	triageSrc, err := os.ReadFile("triage.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(triageSrc), "productb/triage") {
		t.Fatal("triage.go no longer holds the live investigator")
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") || strings.HasPrefix(path, "triage") {
			continue
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if perr != nil {
			t.Fatalf("%s: %v", path, perr)
		}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if p == "github.com/fedorovmv/izyan/internal/productb/triage" {
				t.Errorf("%s imports the Product B investigator: only triage owns the live human projection", path)
			}
		}
	}
}

// TestB1OnlyAvailableUnderEval requires that the frozen B1 arm is routed
// under `eval` and has no top-level command of its own.
func TestB1OnlyAvailableUnderEval(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	main := string(src)
	// The top-level switch must not dispatch research-b1.
	top := main
	if i := strings.Index(main, "func usage() {"); i > 0 {
		top = main[:i]
	}
	if strings.Contains(top, `case "research-b1"`) {
		t.Fatal("top-level research-b1 command still dispatched: B1 is an evaluation control")
	}
	// The eval dispatcher must route it.
	if !strings.Contains(main, `os.Args[2] == "research-b1"`) {
		t.Fatal("`izyan eval research-b1` is not routed")
	}
	// Usage must advertise only the eval route.
	if !strings.Contains(main, "izyan eval research-b1") {
		t.Fatal("usage does not advertise the eval-only B1 route")
	}
	if strings.Contains(main, "\n  izyan research-b1 ") {
		t.Fatal("usage still advertises a top-level research-b1 command")
	}
}

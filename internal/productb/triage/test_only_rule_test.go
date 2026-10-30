package triage

import (
	"context"
	"strings"
	"testing"
)

// testOnlyStage0 pins the deterministic test-only distinction: the module is
// present in the module graph, complete, and its packages appear only in the
// test closure.
func testOnlyStage0() Stage0Result {
	s0 := versionRangeStage0(CheckAffectedRange)
	s0.Materials.ModuleGraph = &ModuleGraph{
		Source:   "vendor/modules.txt",
		Complete: true,
		Modules:  []ModuleVersion{{Path: "example.org/library", Version: "v1.2.0"}},
		TestOnly: map[string]bool{"example.org/library": true},
	}
	bindTestOnlyInventories(&s0)
	return s0
}

// TestComposerTestOnlyDependencyDismissed pins the rule: a module the product
// binary never links (test-only closure) is dismissed without any agent proof.
func TestComposerTestOnlyDependencyDismissed(t *testing.T) {
	pkg, err := Composer{}.ComposeWithEvidence(context.Background(), testOnlyStage0(), goodAssessment(), completeValidation(), EvidenceInput{})
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	if pkg.MachineDisposition.Recommendation != RecommendationDismissed {
		t.Fatalf("recommendation = %s (demotions=%v)", pkg.MachineDisposition.Recommendation, pkg.MachineDisposition.Demotions)
	}
	if !strings.Contains(strings.Join(pkg.MachineDisposition.Rationale.Basis, "|"), "rule test-only-dependency satisfied") {
		t.Fatalf("rule basis = %v", pkg.MachineDisposition.Rationale.Basis)
	}
}

// TestComposerTestOnlyRequiresEstablishedDistinction pins the fail-closed
// boundary: without a complete retained non-test inventory, no rule may claim
// the module is test-only, regardless of its serialized projection.
func TestComposerTestOnlyRequiresEstablishedDistinction(t *testing.T) {
	s0 := testOnlyStage0()
	s0.Materials.ModuleGraph.BuildPackageInventory = nil
	pkg, err := Composer{}.ComposeWithEvidence(context.Background(), s0, goodAssessment(), completeValidation(), EvidenceInput{})
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	if pkg.MachineDisposition.Recommendation == RecommendationDismissed {
		t.Fatalf("dismissed without the test closure (basis=%v)", pkg.MachineDisposition.Rationale.Basis)
	}

	// A module present in the build closure is never test-only.
	s0 = testOnlyStage0()
	product := *s0.Materials.ModuleGraph.PackageInventory
	product.Run.WithTests = false
	s0.Materials.ModuleGraph.BuildPackageInventory = &product
	pkg, err = Composer{}.ComposeWithEvidence(context.Background(), s0, goodAssessment(), completeValidation(), EvidenceInput{})
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	if pkg.MachineDisposition.Recommendation == RecommendationDismissed {
		t.Fatalf("dismissed a linked module (basis=%v)", pkg.MachineDisposition.Rationale.Basis)
	}
}

// TestTestOnlyModulesClassification pins the graph diff: a module qualifies
// only when none of its packages appears in the non-test closure; a package
// shared by both closures disqualifies its module.
func TestTestOnlyModulesClassification(t *testing.T) {
	graph := &ModuleGraph{Complete: true, Modules: []ModuleVersion{
		{Path: "example.org/testonly"},
		{Path: "example.org/both"},
	}}
	testPkgs := []byte(`[
		{"ImportPath":"example.org/product"},
		{"ImportPath":"example.org/testonly/pkg"},
		{"ImportPath":"example.org/both/pkg"},
		{"ImportPath":"example.org/both/pkg_test"}
	]`)
	buildPkgs := []byte(`[
		{"ImportPath":"example.org/product"},
		{"ImportPath":"example.org/both/pkg"}
	]`)
	got, err := testOnlyModules(graph, testPkgs, buildPkgs)
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if !got["example.org/testonly"] {
		t.Fatalf("test-only module missed: %+v", got)
	}
	if got["example.org/both"] {
		t.Fatalf("shared module classified test-only: %+v", got)
	}

	if _, err := testOnlyModules(graph, testPkgs, []byte(`[]`)); err == nil {
		t.Fatal("empty non-test closure accepted")
	}
}

// TestTestOnlyFactAlwaysDecided pins the fact contract the rule depends on:
// the distinction is always a decided fact for a known module, so a missing
// non-test closure can never leave the dismissal premise undecided.
func TestTestOnlyFactAlwaysDecided(t *testing.T) {
	s0 := goodStage0()
	f := testOnlyFact(s0)
	if f == nil || f.Status != ObsRefutes {
		t.Fatalf("no-graph fact = %+v", f)
	}
	if len(f.Provenance) == 0 || f.Provenance[0] != "go_list_deps_nontest_absent" {
		t.Fatalf("provenance = %v", f.Provenance)
	}
	s0.Materials.ModuleGraph = &ModuleGraph{
		Complete: true,
		Modules:  []ModuleVersion{{Path: "example.org/library"}},
		TestOnly: map[string]bool{"example.org/library": true},
	}
	if f := testOnlyFact(s0); f == nil || f.Status == ObsSupports {
		t.Fatalf("test-only fact = %+v", f)
	}
}

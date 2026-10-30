package goanalysis

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
)

// productShapeOf builds the product shape for a fixture directory and fails
// the test on error.
func productShapeOf(t *testing.T, dir string, env ...string) (*domain.ProductShape, []domain.Evidence) {
	t.Helper()
	ix := &Index{Dir: dir, Env: env}
	shape, evs, err := ix.BuildProductShape(context.Background())
	if err != nil {
		t.Fatalf("BuildProductShape(%s): %v", dir, err)
	}
	if shape == nil {
		t.Fatalf("BuildProductShape(%s) returned no shape", dir)
	}
	return shape, evs
}

// shapePackage returns the inventoried package at a product-relative
// directory.
func shapePackage(t *testing.T, shape *domain.ProductShape, dir string) domain.ProductPackageShape {
	t.Helper()
	for _, p := range shape.Packages {
		if p.Directory == dir {
			return p
		}
	}
	t.Fatalf("package directory %q not inventoried; got %+v", dir, shape.Packages)
	return domain.ProductPackageShape{}
}

func shapeDirectories(shape *domain.ProductShape) []string {
	out := make([]string, 0, len(shape.Packages))
	for _, p := range shape.Packages {
		out = append(out, p.Directory)
	}
	return out
}

func shapeHasLimitation(shape *domain.ProductShape, want string) bool {
	for _, l := range shape.Limitations {
		if strings.Contains(l, want) {
			return true
		}
	}
	return false
}

// TestProductShapeLibrary: an ordinary library has a complete, evidence-backed
// LIBRARY proof. Test sources and test fixture data are not product packages.
func TestProductShapeLibrary(t *testing.T) {
	dir := usageModuleGomod(t, "module example.com/libshape\n\ngo 1.23\n", map[string]string{
		"lib.go":                      "package libshape\n\n// Exported is the public API.\nfunc Exported() string { return \"x\" }\n",
		"sub/sub.go":                  "package sub\n\nfunc Helper() {}\n",
		"internal/secret/secret.go":   "package secret\n\nfunc hidden() {}\n",
		"lib_test.go":                 "package libshape_test\n\nimport \"testing\"\n\nfunc TestNothing(t *testing.T) {}\n",
		"testdata/fixture/fixture.go": "package fixture\n\n// Data is test fixture source, not product source.\nfunc Data() {}\n",
	})
	shape, evs := productShapeOf(t, dir)

	if shape.Kind != domain.ProductShapeLibrary {
		t.Fatalf("kind=%s, want LIBRARY (limitations=%v)", shape.Kind, shape.Limitations)
	}
	if !shape.CensusComplete {
		t.Fatalf("library census must be complete: %v", shape.Limitations)
	}
	if shape.RootModule != "example.com/libshape" {
		t.Fatalf("root module=%q", shape.RootModule)
	}
	if len(shape.OwnedModules) != 1 || shape.OwnedModules[0] != (domain.ProductModuleShape{
		Path: "example.com/libshape", Directory: ".",
	}) {
		t.Fatalf("owned modules=%+v", shape.OwnedModules)
	}
	if len(shape.ExcludedModules) != 0 {
		t.Fatalf("ordinary library must not invent excluded modules: %+v", shape.ExcludedModules)
	}
	if got, want := shapeDirectories(shape), []string{".", "internal/secret", "sub"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("package census=%v, want %v", got, want)
	}

	root := shapePackage(t, shape, ".")
	if root.Path != "example.com/libshape" || root.Module != "example.com/libshape" {
		t.Fatalf("root package identity=%+v", root)
	}
	if !root.Importable || !root.ClauseComplete {
		t.Fatalf("root package flags=%+v", root)
	}
	if want := []string{"lib.go"}; !reflect.DeepEqual(root.Files, want) {
		t.Fatalf("root files=%v, want %v (test sources are excluded)", root.Files, want)
	}
	if !shapePackage(t, shape, "sub").Importable {
		t.Fatal("sub must be importable")
	}
	if shapePackage(t, shape, "internal/secret").Importable {
		t.Fatal("an internal package is not externally importable")
	}
	for _, p := range shape.Packages {
		if strings.HasPrefix(p.Directory, "testdata") {
			t.Fatalf("testdata directory must not be product source: %+v", p)
		}
	}

	if shape.Fingerprint == "" {
		t.Fatal("library proof must carry an input fingerprint")
	}
	if len(evs) != 2 {
		t.Fatalf("evidence records=%d, want build + package census", len(evs))
	}
	for _, e := range evs {
		if e.Kind != domain.EvidenceBuild && e.Kind != domain.EvidencePackageList {
			t.Fatalf("unexpected evidence kind %s", e.Kind)
		}
		if e.Quality != domain.QualityDeterministic {
			t.Fatalf("evidence quality=%s", e.Quality)
		}
		if !strings.Contains(e.Content, shape.Fingerprint) && e.Kind == domain.EvidenceBuild {
			t.Fatalf("build evidence must pin the fingerprint: %s", e.Content)
		}
	}
	if !strings.Contains(evs[0].Content, "owned main sources: none") {
		t.Fatalf("build evidence must record the main census: %s", evs[0].Content)
	}
	if !strings.Contains(evs[0].Content, "testdata main sources: none") {
		t.Fatalf("build evidence must record the testdata main census: %s", evs[0].Content)
	}
	if !strings.Contains(evs[0].Content, "testdata fixture packages inventoried (not product source): 1") {
		t.Fatalf("build evidence must record the fixture inventory: %s", evs[0].Content)
	}
	if len(shape.EvidenceIDs) != 0 {
		t.Fatalf("the builder must not assign case-scoped evidence ids: %v", shape.EvidenceIDs)
	}
}

// TestProductShapeHiddenOwnedSource: hidden directories are product source the
// loader's `./...` pattern cannot see. An owned command there must prevent a
// LIBRARY proof; a hidden non-command package must not.
func TestProductShapeHiddenOwnedSource(t *testing.T) {
	t.Run("hidden command prevents LIBRARY", func(t *testing.T) {
		dir := usageModuleGomod(t, "module example.com/hiddenprod\n\ngo 1.23\n", map[string]string{
			"lib.go":         "package hiddenprod\n\nfunc Use() {}\n",
			".tools/main.go": "package main\n\nfunc main() {}\n",
		})
		shape, _ := productShapeOf(t, dir)
		if shape.Kind != domain.ProductShapeApplication {
			t.Fatalf("kind=%s, want APPLICATION (limitations=%v)", shape.Kind, shape.Limitations)
		}
		cmd := shapePackage(t, shape, ".tools")
		if len(cmd.PackageNames) != 1 || cmd.PackageNames[0] != "main" || cmd.Importable {
			t.Fatalf("hidden command package=%+v", cmd)
		}
	})

	t.Run("hidden non-command package stays part of a library", func(t *testing.T) {
		dir := usageModuleGomod(t, "module example.com/hiddenlib\n\ngo 1.23\n", map[string]string{
			"lib.go":          "package hiddenlib\n\nfunc Use() {}\n",
			".tools/tools.go": "package tools\n\nfunc Generate() {}\n",
		})
		shape, _ := productShapeOf(t, dir)
		if shape.Kind != domain.ProductShapeLibrary || !shape.CensusComplete {
			t.Fatalf("kind=%s complete=%t (limitations=%v)", shape.Kind, shape.CensusComplete, shape.Limitations)
		}
		if tools := shapePackage(t, shape, ".tools"); !tools.Importable {
			t.Fatalf("hidden non-command package=%+v", tools)
		}
	})
}

// TestProductShapeNestedModuleOwnership: a nested module with its own go.mod
// is a different module. It is excluded by ownership — moving or renaming the
// directory cannot change that — while the same generator source without a
// module boundary is an owned command.
func TestProductShapeNestedModuleOwnership(t *testing.T) {
	t.Run("nested generator module is excluded by identity", func(t *testing.T) {
		for _, name := range []string{"_codegen", "codegen"} {
			dir := usageModuleGomod(t, "module example.com/libprod\n\ngo 1.23\n", map[string]string{
				"lib.go":           "package libprod\n\nfunc Use() {}\n",
				"assert/assert.go": "package assert\n\nfunc Eq() {}\n",
				name + "/go.mod":   "module example.com/libprod/" + name + "\n\ngo 1.23\n",
				name + "/main.go":  "package main\n\nfunc main() {}\n",
				"docs/readme.md":   "not go\n",
				"tools/tools.go":   "package tools\n\nfunc Gen() {}\n",
			})
			shape, _ := productShapeOf(t, dir)
			if shape.Kind != domain.ProductShapeLibrary {
				t.Fatalf("%s: kind=%s, want LIBRARY (limitations=%v)", name, shape.Kind, shape.Limitations)
			}
			if !shape.CensusComplete {
				t.Fatalf("%s: census must stay complete: %v", name, shape.Limitations)
			}
			want := domain.ProductModuleShape{Path: "example.com/libprod/" + name, Directory: name}
			if len(shape.ExcludedModules) != 1 || shape.ExcludedModules[0] != want {
				t.Fatalf("%s: excluded modules=%+v, want %+v", name, shape.ExcludedModules, want)
			}
			if !shapeHasLimitation(shape, "not owned by the product's module composition") {
				t.Fatalf("%s: exclusion reason must be recorded: %v", name, shape.Limitations)
			}
			for _, p := range shape.Packages {
				if p.Directory == name || strings.HasPrefix(p.Directory, name+"/") {
					t.Fatalf("%s: excluded module source entered the census: %+v", name, p)
				}
			}
		}
	})

	t.Run("same generator source without a module boundary is an application", func(t *testing.T) {
		dir := usageModuleGomod(t, "module example.com/noboundary\n\ngo 1.23\n", map[string]string{
			"lib.go":          "package noboundary\n\nfunc Use() {}\n",
			"codegen/main.go": "package main\n\nfunc main() {}\n",
		})
		shape, _ := productShapeOf(t, dir)
		if shape.Kind != domain.ProductShapeApplication {
			t.Fatalf("kind=%s, want APPLICATION (limitations=%v)", shape.Kind, shape.Limitations)
		}
		cmd := shapePackage(t, shape, "codegen")
		if cmd.Importable || len(cmd.PackageNames) != 1 || cmd.PackageNames[0] != "main" {
			t.Fatalf("owned command package=%+v", cmd)
		}
	})
}

// TestProductShapeWorkspaceOwnership: the effective workspace's use entries
// decide whether a nested module is product-owned. GOWORK=off disables that
// ownership exactly as it disables workspace mode for the loader.
func TestProductShapeWorkspaceOwnership(t *testing.T) {
	base := map[string]string{
		"root.go":     "package wsroot\n\nfunc Root() {}\n",
		"gen/go.mod":  "module example.com/gen\n\ngo 1.23\n",
		"gen/main.go": "package main\n\nfunc main() {}\n",
		"go.work":     "go 1.23\n\nuse (\n\t.\n\t./gen\n)\n",
		"lib/lib.go":  "package lib\n\nfunc Use() {}\n",
	}
	clone := func() map[string]string {
		out := make(map[string]string, len(base))
		for k, v := range base {
			out[k] = v
		}
		return out
	}

	t.Run("workspace member main is product-owned", func(t *testing.T) {
		dir := usageModuleGomod(t, "module example.com/wsroot\n\ngo 1.23\n", clone())
		shape, _ := productShapeOf(t, dir)
		if shape.Kind != domain.ProductShapeApplication {
			t.Fatalf("kind=%s, want APPLICATION (limitations=%v)", shape.Kind, shape.Limitations)
		}
		if shape.WorkspaceFile != "go.work" {
			t.Fatalf("workspace file=%q", shape.WorkspaceFile)
		}
		owned := map[string]bool{}
		for _, m := range shape.OwnedModules {
			owned[m.Path] = true
		}
		if !owned["example.com/wsroot"] || !owned["example.com/gen"] {
			t.Fatalf("workspace members must be owned: %+v", shape.OwnedModules)
		}
		if len(shape.ExcludedModules) != 0 {
			t.Fatalf("owned member excluded: %+v", shape.ExcludedModules)
		}
		if pkg := shapePackage(t, shape, "gen"); pkg.Importable {
			t.Fatalf("owned command must not be importable: %+v", pkg)
		}
	})

	t.Run("nested module outside the workspace is excluded", func(t *testing.T) {
		files := clone()
		files["go.work"] = "go 1.23\n\nuse .\n"
		dir := usageModuleGomod(t, "module example.com/wsroot\n\ngo 1.23\n", files)
		shape, _ := productShapeOf(t, dir)
		if shape.Kind != domain.ProductShapeLibrary {
			t.Fatalf("kind=%s, want LIBRARY (limitations=%v)", shape.Kind, shape.Limitations)
		}
		if len(shape.ExcludedModules) != 1 || shape.ExcludedModules[0].Path != "example.com/gen" {
			t.Fatalf("excluded modules=%+v", shape.ExcludedModules)
		}
	})

	t.Run("GOWORK=off disables workspace ownership", func(t *testing.T) {
		dir := usageModuleGomod(t, "module example.com/wsroot\n\ngo 1.23\n", clone())
		shape, _ := productShapeOf(t, dir, "GOWORK=off")
		if shape.Kind != domain.ProductShapeLibrary {
			t.Fatalf("kind=%s, want LIBRARY (limitations=%v)", shape.Kind, shape.Limitations)
		}
		if shape.WorkspaceFile != "" {
			t.Fatalf("GOWORK=off must not resolve a workspace: %q", shape.WorkspaceFile)
		}
		if len(shape.ExcludedModules) != 1 || shape.ExcludedModules[0].Path != "example.com/gen" {
			t.Fatalf("excluded modules=%+v", shape.ExcludedModules)
		}
	})

	t.Run("workspace member under an excluded ancestor is still owned", func(t *testing.T) {
		// `vendor` is not walked as product source, but an owned workspace
		// member located below it is product source and must be accounted
		// for — its command may not be missed.
		dir := usageModuleGomod(t, "module example.com/wsvendor\n\ngo 1.23\n", map[string]string{
			"root.go":            "package wsvendor\n\nfunc Root() {}\n",
			"go.work":            "go 1.23\n\nuse (\n\t.\n\t./vendor/gen\n)\n",
			"vendor/gen/go.mod":  "module example.com/gen\n\ngo 1.23\n",
			"vendor/gen/main.go": "package main\n\nfunc main() {}\n",
			"vendor/dep/dep.go":  "package dep\n\nfunc D() {}\n",
		})
		shape, _ := productShapeOf(t, dir)
		if shape.Kind != domain.ProductShapeApplication {
			t.Fatalf("kind=%s, want APPLICATION (limitations=%v)", shape.Kind, shape.Limitations)
		}
		owned := false
		for _, m := range shape.OwnedModules {
			if m.Path == "example.com/gen" && m.Directory == "vendor/gen" {
				owned = true
			}
		}
		if !owned {
			t.Fatalf("owned workspace member under vendor missing: %+v", shape.OwnedModules)
		}
		cmd := shapePackage(t, shape, "vendor/gen")
		if len(cmd.PackageNames) != 1 || cmd.PackageNames[0] != "main" {
			t.Fatalf("owned member package=%+v", cmd)
		}
		for _, p := range shape.Packages {
			if p.Directory == "vendor/dep" {
				t.Fatalf("vendor dependency source must not be inventoried: %+v", p)
			}
		}
	})
}

// TestProductShapeOwnedMain: an owned package main makes the product an
// application, wherever the command directory lives.
func TestProductShapeOwnedMain(t *testing.T) {
	dir := usageModuleGomod(t, "module example.com/appprod\n\ngo 1.23\n", map[string]string{
		"cmd/app/main.go": "package main\n\nfunc main() {}\n",
		"lib/lib.go":      "package lib\n\nfunc Use() {}\n",
	})
	shape, _ := productShapeOf(t, dir)
	if shape.Kind != domain.ProductShapeApplication {
		t.Fatalf("kind=%s, want APPLICATION (limitations=%v)", shape.Kind, shape.Limitations)
	}
	if !shape.CensusComplete {
		t.Fatalf("census must stay complete: %v", shape.Limitations)
	}
	cmd := shapePackage(t, shape, "cmd/app")
	if cmd.Importable || len(cmd.PackageNames) != 1 || cmd.PackageNames[0] != "main" {
		t.Fatalf("command package=%+v", cmd)
	}
	if !shapePackage(t, shape, "lib").Importable {
		t.Fatal("lib must stay importable")
	}
}

// TestProductShapeBuildExcludedMain: a command hidden by build selection is
// still owned product source. The loader never sees the directory, so only
// the manifest-aware census can find it.
func TestProductShapeBuildExcludedMain(t *testing.T) {
	dir := usageModuleGomod(t, "module example.com/winprod\n\ngo 1.23\n", map[string]string{
		"lib.go":                "package winprod\n\nfunc Use() {}\n",
		"svc/svc_windows.go":    "//go:build windows\n\npackage main\n\nfunc main() {}\n",
		"svc2/svc_windows_x.go": "//go:build windows\n\npackage helper\n\nfunc H() {}\n",
	})
	ix := &Index{Dir: dir}
	shape, _, err := ix.BuildProductShape(context.Background())
	if err != nil {
		t.Fatalf("BuildProductShape: %v", err)
	}
	if shape.Kind != domain.ProductShapeApplication {
		t.Fatalf("kind=%s, want APPLICATION (limitations=%v)", shape.Kind, shape.Limitations)
	}
	svc := shapePackage(t, shape, "svc")
	if len(svc.PackageNames) != 1 || svc.PackageNames[0] != "main" || svc.Importable {
		t.Fatalf("build-excluded command package=%+v", svc)
	}
	if !svc.ClauseComplete {
		t.Fatal("build-excluded source must still yield a package clause")
	}
	// The loader did not load either directory on this platform: the proof
	// above cannot have come from a typed root.
	for _, p := range ix.pkgs {
		if strings.HasSuffix(p.PkgPath, "/svc") || strings.HasSuffix(p.PkgPath, "/svc2") {
			t.Fatalf("fixture unexpectedly loaded by the selected build: %s", p.PkgPath)
		}
	}
}

// TestProductShapeSkippedMain: a product main hidden by a loader failure is
// still an owned main. The loader's single Name is not proof that no sibling
// file declares main.
func TestProductShapeSkippedMain(t *testing.T) {
	t.Run("failed command package", func(t *testing.T) {
		dir := usageModuleGomod(t, "module example.com/skipprod\n\ngo 1.23\n", map[string]string{
			"lib.go":      "package skipprod\n\nfunc Use() {}\n",
			"app/main.go": "package main\n\nfunc main() { undefinedSymbol() }\n",
		})
		ix := &Index{Dir: dir}
		shape, _, err := ix.BuildProductShape(context.Background())
		if err != nil {
			t.Fatalf("BuildProductShape: %v", err)
		}
		if len(ix.skippedPkgs) == 0 {
			t.Fatal("fixture must exercise the loader's skipped-package path")
		}
		if shape.Kind != domain.ProductShapeApplication {
			t.Fatalf("kind=%s, want APPLICATION (limitations=%v)", shape.Kind, shape.Limitations)
		}
		app := shapePackage(t, shape, "app")
		if len(app.PackageNames) != 1 || app.PackageNames[0] != "main" {
			t.Fatalf("skipped command package=%+v", app)
		}
		if len(app.LoadErrors) == 0 {
			t.Fatal("the skipped package's loader diagnostics must be recorded")
		}
	})

	t.Run("loader name hides a sibling main clause", func(t *testing.T) {
		dir := usageModuleGomod(t, "module example.com/mixedproduct\n\ngo 1.23\n", map[string]string{
			"lib.go":           "package mixedproduct\n\nfunc Use() {}\n",
			"broken/worker.go": "package broken\n\nfunc Work() { undefinedSymbol() }\n",
			"broken/main.go":   "package main\n\nfunc main() {}\n",
		})
		ix := &Index{Dir: dir}
		shape, _, err := ix.BuildProductShape(context.Background())
		if err != nil {
			t.Fatalf("BuildProductShape: %v", err)
		}
		if len(ix.skippedPkgs) == 0 {
			t.Fatal("fixture must exercise the loader's skipped-package path")
		}
		if shape.Kind != domain.ProductShapeApplication {
			t.Fatalf("kind=%s, want APPLICATION (limitations=%v)", shape.Kind, shape.Limitations)
		}
		broken := shapePackage(t, shape, "broken")
		if !containsString(broken.PackageNames, "main") {
			t.Fatalf("sibling main clause missing from the census: %+v", broken)
		}
		if broken.Importable {
			t.Fatalf("a directory declaring main is not importable: %+v", broken)
		}
	})
}

// TestProductShapeUnknownCensus: every gap in ownership, inventory or
// importability yields UNKNOWN with a recorded reason — never LIBRARY.
func TestProductShapeUnknownCensus(t *testing.T) {
	t.Run("no module manifest", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "lib.go"), "package nolib\n\nfunc Use() {}\n")
		shape, _ := productShapeOf(t, dir)
		if shape.Kind != domain.ProductShapeUnknown {
			t.Fatalf("kind=%s, want UNKNOWN", shape.Kind)
		}
		if shape.CensusComplete {
			t.Fatal("missing ownership is never a complete census")
		}
		if !shapeHasLimitation(shape, "module ownership is unresolved") {
			t.Fatalf("reason missing: %v", shape.Limitations)
		}
	})

	t.Run("unparseable module manifest", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "go.mod"), "module\n")
		writeFile(t, filepath.Join(dir, "lib.go"), "package badmod\n")
		shape, _ := productShapeOf(t, dir)
		if shape.Kind != domain.ProductShapeUnknown || shape.CensusComplete {
			t.Fatalf("kind=%s complete=%t", shape.Kind, shape.CensusComplete)
		}
		if !shapeHasLimitation(shape, "module ownership is unresolved") {
			t.Fatalf("reason missing: %v", shape.Limitations)
		}
	})

	t.Run("unavailable workspace member", func(t *testing.T) {
		dir := usageModuleGomod(t, "module example.com/wsmember\n\ngo 1.23\n", map[string]string{
			"lib.go":  "package wsmember\n\nfunc Use() {}\n",
			"go.work": "go 1.23\n\nuse (\n\t.\n\t./missing\n)\n",
		})
		shape, _ := productShapeOf(t, dir)
		if shape.Kind != domain.ProductShapeUnknown {
			t.Fatalf("kind=%s, want UNKNOWN (limitations=%v)", shape.Kind, shape.Limitations)
		}
		if !shapeHasLimitation(shape, "unavailable") {
			t.Fatalf("reason missing: %v", shape.Limitations)
		}
	})

	t.Run("no importable package", func(t *testing.T) {
		dir := usageModuleGomod(t, "module example.com/onlyinternal\n\ngo 1.23\n", map[string]string{
			"internal/only/only.go": "package only\n\nfunc hidden() {}\n",
		})
		shape, _ := productShapeOf(t, dir)
		if shape.Kind != domain.ProductShapeUnknown {
			t.Fatalf("kind=%s, want UNKNOWN (limitations=%v)", shape.Kind, shape.Limitations)
		}
		if !shape.CensusComplete {
			t.Fatalf("ownership and inventory are complete; only importability is missing: %v", shape.Limitations)
		}
		if !shapeHasLimitation(shape, "no importable product package") {
			t.Fatalf("reason missing: %v", shape.Limitations)
		}
	})

	t.Run("testdata command source leaves the command set unproven", func(t *testing.T) {
		// Testdata is not buildable product source, but a package main there
		// cannot be ruled out as an owned command either. The conservative
		// outcome is an incomplete census, never LIBRARY.
		dir := usageModuleGomod(t, "module example.com/tdmain\n\ngo 1.23\n", map[string]string{
			"lib.go":               "package tdmain\n\nfunc Use() {}\n",
			"testdata/gen/main.go": "package main\n\nfunc main() {}\n",
		})
		shape, _ := productShapeOf(t, dir)
		if shape.Kind != domain.ProductShapeUnknown {
			t.Fatalf("kind=%s, want UNKNOWN (limitations=%v)", shape.Kind, shape.Limitations)
		}
		if shape.CensusComplete {
			t.Fatal("a package main under testdata must leave the owned-command set unproven")
		}
		if !shapeHasLimitation(shape, "testdata source declares package main") {
			t.Fatalf("reason missing: %v", shape.Limitations)
		}
	})
}

// TestProductShapeIndependentOfShippingCompleteness: a library snapshot has no
// shipping root, so the shipping scope stays open by design. The product
// shape must not inherit that openness.
func TestProductShapeIndependentOfShippingCompleteness(t *testing.T) {
	ix := fixture(t, "scopelib")
	ctx := context.Background()
	shape, _, err := ix.BuildProductShape(ctx)
	if err != nil {
		t.Fatalf("BuildProductShape: %v", err)
	}
	if shape.Kind != domain.ProductShapeLibrary || !shape.CensusComplete {
		t.Fatalf("kind=%s complete=%t (limitations=%v)", shape.Kind, shape.CensusComplete, shape.Limitations)
	}
	scope, err := ix.BuildShippingScope(ctx)
	if err != nil {
		t.Fatalf("BuildShippingScope: %v", err)
	}
	if scope.Complete {
		t.Fatalf("library fixture must leave the shipping scope open, got reasons=%v", scope.UnknownReasons)
	}
	if len(scope.Roots) != 0 {
		t.Fatalf("library fixture must have no shipping roots: %v", scope.Roots)
	}
}

// TestProductShapeFingerprint: the proof is deterministic for identical input,
// moves when only build-invisible inventory changes, and fails closed when a
// loader-visible source is rewritten after the load.
func TestProductShapeFingerprint(t *testing.T) {
	dir := usageModuleGomod(t, "module example.com/fingerprintprod\n\ngo 1.23\n", map[string]string{
		"lib.go":                "package fingerprintprod\n\nfunc Value() int { return 1 }\n",
		"winsvc/svc_windows.go": "//go:build windows\n\npackage winsvc\n\nfunc Name() string { return \"x\" }\n",
	})
	ctx := context.Background()
	ix := &Index{Dir: dir}

	first, firstEvs, err := ix.BuildProductShape(ctx)
	if err != nil {
		t.Fatalf("BuildProductShape: %v", err)
	}
	if first.Kind != domain.ProductShapeLibrary || !first.CensusComplete {
		t.Fatalf("kind=%s complete=%t (limitations=%v)", first.Kind, first.CensusComplete, first.Limitations)
	}
	if ix.productShapeBuilds != 1 {
		t.Fatalf("first proof must build the census once, got %d", ix.productShapeBuilds)
	}

	second, secondEvs, err := ix.BuildProductShape(ctx)
	if err != nil {
		t.Fatalf("BuildProductShape (repeat): %v", err)
	}
	if second.Fingerprint != first.Fingerprint || ix.productShapeBuilds != 1 {
		t.Fatalf("repeat proof rebuilt or moved: %q vs %q (builds=%d)",
			second.Fingerprint, first.Fingerprint, ix.productShapeBuilds)
	}
	if !reflect.DeepEqual(firstEvs, secondEvs) {
		t.Fatal("repeat proof must emit identical deterministic evidence")
	}

	// A fresh index over identical bytes derives the same fingerprint.
	fresh := &Index{Dir: dir}
	freshShape, _, err := fresh.BuildProductShape(ctx)
	if err != nil {
		t.Fatalf("fresh BuildProductShape: %v", err)
	}
	if freshShape.Fingerprint != first.Fingerprint {
		t.Fatalf("fingerprint depends on load history: %q vs %q", freshShape.Fingerprint, first.Fingerprint)
	}

	// A source the selected build never loads is invisible to the loader's
	// snapshot fingerprint but is part of the proof inventory.
	writeFile(t, filepath.Join(dir, "winsvc", "extra_windows.go"),
		"//go:build windows\n\npackage winsvc\n\nfunc Extra() {}\n")
	changed, _, err := ix.BuildProductShape(ctx)
	if err != nil {
		t.Fatalf("BuildProductShape after invisible inventory change: %v", err)
	}
	if changed.Fingerprint == first.Fingerprint {
		t.Fatal("build-invisible inventory change must move the fingerprint")
	}
	if ix.productShapeBuilds != 2 {
		t.Fatalf("inventory change must rebuild the census, builds=%d", ix.productShapeBuilds)
	}
	if got := shapePackage(t, changed, "winsvc"); !containsString(got.Files, "winsvc/extra_windows.go") {
		t.Fatalf("inventory change not reflected: %+v", got.Files)
	}

	// A loader-visible rewrite makes the loaded AST stale: fail closed and
	// drop the cached census instead of publishing a proof over old bytes.
	appendToFile(t, filepath.Join(dir, "lib.go"), "\n// mutated after load\n")
	if _, _, err := ix.BuildProductShape(ctx); !errors.Is(err, ErrSnapshotMutated) {
		t.Fatalf("rewritten product source must fail closed, got %v", err)
	}
	if ix.productShapeCache != nil || ix.productShapeIdentity != "" {
		t.Fatal("snapshot drift must drop the cached census")
	}
}

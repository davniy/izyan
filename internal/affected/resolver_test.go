package affected

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/repository"
)

type fakeTool struct {
	modules  []byte
	packages []byte
	modErr   error
	pkgErr   error
	prodPkgs []byte
	prodErr  error
	testPkgs []byte
	testErr  error
}

func (f fakeTool) ListModules(context.Context, string, domain.ProductSnapshot) ([]byte, string, error) {
	return f.modules, "go list -m -json all", f.modErr
}

func (f fakeTool) ListPackages(ctx context.Context, dir string, build domain.ProductSnapshot) ([]byte, error) {
	return f.ListPackagesScope(ctx, dir, build, true)
}

func (f fakeTool) ListPackagesScope(_ context.Context, _ string, _ domain.ProductSnapshot, withTests bool) ([]byte, error) {
	if !withTests {
		return f.prodPkgs, f.prodErr
	}
	if f.testPkgs != nil || f.testErr != nil {
		return f.testPkgs, f.testErr
	}
	return f.packages, f.pkgErr
}

var testVuln = domain.Vulnerability{
	ID:     "GO-0000-0001",
	Module: "example.com/dep",
	AffectedVersions: []domain.VersionRange{
		{Introduced: "0", Fixed: "1.2.0"},
	},
	AffectedPackages: []domain.AffectedPackage{{Path: "example.com/dep/vuln"}},
}

func product() domain.ProductSnapshot {
	return domain.ProductSnapshot{Repository: "/repo", Commit: "deadbeef", GOOS: "linux", GOARCH: "amd64"}
}

// scopedProduct is the same snapshot with an admitted artifact-build-info
// target: build-dependent negatives may be asserted against it.
func scopedProduct() domain.ProductSnapshot {
	p := product()
	p.Target = artifactTarget()
	return p
}

func resolve(t *testing.T, tool GoTool) domain.AffectedResult {
	t.Helper()
	res, _, err := GoResolver{Tool: tool}.Resolve(context.Background(), testVuln, product())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	return res
}

// resolveEvidence runs the resolver and returns the evidence it recorded,
// so tests can assert the typed package-list run record.
func resolveEvidence(t *testing.T, v domain.Vulnerability, tool GoTool, prod domain.ProductSnapshot) (domain.AffectedResult, []domain.Evidence) {
	t.Helper()
	res, ev, err := GoResolver{Tool: tool}.Resolve(context.Background(), v, prod)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	return res, ev
}

// packageListEvidence returns the package-list evidence from a resolver run.
func packageListEvidence(t *testing.T, evs []domain.Evidence) domain.Evidence {
	t.Helper()
	for _, e := range evs {
		if e.Kind == domain.EvidencePackageList {
			return e
		}
	}
	t.Fatal("no package-list evidence recorded")
	return domain.Evidence{}
}

func TestModuleAbsent(t *testing.T) {
	res := resolve(t, fakeTool{modules: []byte(`{"Path":"example.com/product","Main":true}`)})
	if res.ModulePresent != domain.ClaimFalse || res.VersionAffected != domain.ClaimFalse {
		t.Fatalf("got %+v, want module/version FALSE", res)
	}
}

func TestVersionOutsideRange(t *testing.T) {
	mods := `{"Path":"example.com/product","Main":true}
{"Path":"example.com/dep","Version":"v1.2.0"}`
	res := resolve(t, fakeTool{modules: []byte(mods)})
	if res.VersionAffected != domain.ClaimFalse {
		t.Fatalf("v1.2.0 is the fixed version, got VersionAffected=%s", res.VersionAffected)
	}
	if res.ResolvedVersion != "v1.2.0" {
		t.Fatalf("resolved=%q", res.ResolvedVersion)
	}
}

// A fixed version is not component absence: the package/build probe never
// ran on that path, so neither claim may be FALSE, and the report must
// carry the reason the check was skipped.
func TestFixedVersionDoesNotInferPackageAbsence(t *testing.T) {
	mods := `{"Path":"example.com/product","Main":true}
{"Path":"example.com/dep","Version":"v1.2.0"}`
	res := resolve(t, fakeTool{modules: []byte(mods)})
	if res.VersionAffected != domain.ClaimFalse {
		t.Fatalf("v1.2.0 is the fixed version, got VersionAffected=%s", res.VersionAffected)
	}
	if res.PackagePresent == domain.ClaimFalse || res.BuildRelevant == domain.ClaimFalse {
		t.Fatalf("unevaluated package/build probe reported as absence: package=%s build=%s",
			res.PackagePresent, res.BuildRelevant)
	}
	if !strings.Contains(strings.Join(res.Limitations, "; "), "not evaluated") {
		t.Fatalf("no limitation states that reachability was not evaluated: %v", res.Limitations)
	}
}

func TestVersionInRangePackagePresent(t *testing.T) {
	mods := `{"Path":"example.com/dep","Version":"v1.0.0"}`
	pkgs := `{"ImportPath":"example.com/product"}
{"ImportPath":"example.com/dep/vuln","Module":{"Path":"example.com/dep","Version":"v1.0.0"}}`
	res := resolve(t, fakeTool{modules: []byte(mods), packages: []byte(pkgs)})
	if res.VersionAffected != domain.ClaimTrue {
		t.Fatalf("got VersionAffected=%s", res.VersionAffected)
	}
	if res.PackagePresent != domain.ClaimTrue {
		t.Fatalf("got PackagePresent=%s", res.PackagePresent)
	}
}

func TestVersionInRangePackageAbsent(t *testing.T) {
	mods := `{"Path":"example.com/dep","Version":"v1.0.0"}`
	pkgs := `{"ImportPath":"example.com/product"}`

	t.Run("admitted build and complete inventory", func(t *testing.T) {
		res, evs := resolveEvidence(t, testVuln,
			fakeTool{modules: []byte(mods), packages: []byte(pkgs)}, scopedProduct())
		if res.PackagePresent != domain.ClaimFalse || res.BuildRelevant != domain.ClaimFalse {
			t.Fatalf("package/build = %s/%s, want FALSE", res.PackagePresent, res.BuildRelevant)
		}
		// The justification must name what was probed — a bare FALSE is not
		// self-explanatory in the report.
		if len(res.CheckedPackages) != 1 || res.CheckedPackages[0] != "example.com/dep/vuln" {
			t.Fatalf("CheckedPackages=%v", res.CheckedPackages)
		}
		if len(res.CheckedModules) != 1 || res.CheckedModules[0] != "example.com/dep" {
			t.Fatalf("CheckedModules=%v", res.CheckedModules)
		}
		e := packageListEvidence(t, evs)
		if e.PackageList == nil {
			t.Fatal("package-list run record missing")
		}
		if !e.PackageList.Completed || !e.PackageList.Complete ||
			!e.PackageList.WithTests || e.PackageList.Pattern != "./..." {
			t.Fatalf("package-list run = %+v", e.PackageList)
		}
		if e.PackageList.Error != "" {
			t.Fatalf("successful run recorded an error: %q", e.PackageList.Error)
		}
		if e.BuildContext == nil {
			t.Fatal("successful run recorded no build context")
		}
		if err := e.BuildContext.Matches(domain.EffectiveBuildContext(scopedProduct())); err != nil {
			t.Fatalf("run build context: %v", err)
		}
	})

	t.Run("host default stays unknown", func(t *testing.T) {
		res, _ := resolveEvidence(t, testVuln,
			fakeTool{modules: []byte(mods), packages: []byte(pkgs)}, product())
		if res.PackagePresent != domain.ClaimUnknown || res.BuildRelevant != domain.ClaimUnknown {
			t.Fatalf("host-default absence = %s/%s, want UNKNOWN", res.PackagePresent, res.BuildRelevant)
		}
		if !hasLimitation(res.Limitations, "does not describe an identified product build") {
			t.Fatalf("admission reason missing: %v", res.Limitations)
		}
	})
}

// Partial stdout is a positive observation, never an inventory: a package
// witnessed in a failed or truncated stream stays present, but no absence,
// test-only exclusion or closed build inventory may follow from it.
func TestResolvePartialList(t *testing.T) {
	mods := `{"Path":"example.com/dep","Version":"v1.0.0"}`
	witnessed := `{"ImportPath":"example.com/product","Name":"main","Deps":["example.com/dep/vuln"]}
{"ImportPath":"example.com/dep/vuln","Deps":[]}`
	unwitnessed := `{"ImportPath":"example.com/product","Name":"main","Deps":[]}`

	t.Run("process error keeps a witnessed presence", func(t *testing.T) {
		res, evs := resolveEvidence(t, testVuln, fakeTool{
			modules: []byte(mods), packages: []byte(witnessed), pkgErr: errors.New("exit status 1"),
		}, scopedProduct())
		if res.PackagePresent != domain.ClaimTrue {
			t.Fatalf("witnessed package presence lost: %s", res.PackagePresent)
		}
		e := packageListEvidence(t, evs)
		if e.PackageList == nil || e.PackageList.Completed || e.PackageList.Complete {
			t.Fatalf("failed run recorded as complete: %+v", e.PackageList)
		}
		if !strings.Contains(e.PackageList.Error, "exit status 1") {
			t.Fatalf("run error = %q", e.PackageList.Error)
		}
	})

	t.Run("process error cannot prove absence", func(t *testing.T) {
		res, _ := resolveEvidence(t, testVuln, fakeTool{
			modules: []byte(mods), packages: []byte(unwitnessed), pkgErr: errors.New("exit status 1"),
		}, scopedProduct())
		if res.PackagePresent == domain.ClaimFalse || res.BuildRelevant == domain.ClaimFalse {
			t.Fatalf("failed run produced absence: package=%s build=%s",
				res.PackagePresent, res.BuildRelevant)
		}
	})

	t.Run("process error with a complete-looking stream cannot prove absence", func(t *testing.T) {
		res, evs := resolveEvidence(t, testVuln, fakeTool{
			modules: []byte(mods), packages: []byte(unwitnessed), pkgErr: errors.New("exit status 1"),
		}, scopedProduct())
		if res.PackagePresent != domain.ClaimUnknown || res.BuildRelevant != domain.ClaimUnknown {
			t.Fatalf("failed run closed an inventory: %s/%s", res.PackagePresent, res.BuildRelevant)
		}
		e := packageListEvidence(t, evs)
		if e.PackageList.Complete {
			t.Fatal("failed process recorded as a complete inventory")
		}
	})

	t.Run("truncated stream cannot prove absence", func(t *testing.T) {
		raw := unwitnessed + "\n" + `{"ImportPath":"example.com/dep/vu`
		res, evs := resolveEvidence(t, testVuln,
			fakeTool{modules: []byte(mods), packages: []byte(raw)}, scopedProduct())
		if res.PackagePresent == domain.ClaimFalse || res.BuildRelevant == domain.ClaimFalse {
			t.Fatalf("truncated stream produced absence: %s/%s",
				res.PackagePresent, res.BuildRelevant)
		}
		e := packageListEvidence(t, evs)
		if !e.PackageList.Completed || e.PackageList.Complete {
			t.Fatalf("truncated stream run = %+v", e.PackageList)
		}
		if e.PackageList.Error == "" {
			t.Fatal("truncated stream recorded no error")
		}
	})

	t.Run("package error node cannot prove absence", func(t *testing.T) {
		raw := unwitnessed + "\n" + `{"ImportPath":"example.com/product/broken","Name":"broken","Incomplete":true,"Deps":[]}`
		res, _ := resolveEvidence(t, testVuln,
			fakeTool{modules: []byte(mods), packages: []byte(raw)}, scopedProduct())
		if res.PackagePresent == domain.ClaimFalse || res.BuildRelevant == domain.ClaimFalse {
			t.Fatalf("error-bearing node produced absence: %s/%s",
				res.PackagePresent, res.BuildRelevant)
		}
	})
}

// A module-only advisory may close package/build absence only with an
// admitted build and a complete inventory; the host default and an
// incomplete stream keep both axes unknown.
func TestResolvePackageAbsent(t *testing.T) {
	v := domain.Vulnerability{
		ID:               "GO-0000-0005",
		Module:           "example.com/dep",
		AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "1.2.0"}},
	}
	mods := `{"Path":"example.com/dep","Version":"v1.0.0"}`
	pkgs := `{"ImportPath":"example.com/product","Name":"main","Deps":[]}`

	res, _ := resolveEvidence(t, v,
		fakeTool{modules: []byte(mods), packages: []byte(pkgs)}, scopedProduct())
	if res.PackagePresent != domain.ClaimFalse || res.BuildRelevant != domain.ClaimFalse {
		t.Fatalf("module absence = %s/%s, want FALSE", res.PackagePresent, res.BuildRelevant)
	}
	if !hasLimitation(res.Limitations, "absent from compiled product") {
		t.Fatalf("absence justification missing: %v", res.Limitations)
	}

	res, _ = resolveEvidence(t, v,
		fakeTool{modules: []byte(mods), packages: []byte(pkgs)}, product())
	if res.PackagePresent != domain.ClaimUnknown || res.BuildRelevant != domain.ClaimUnknown {
		t.Fatalf("host-default module absence = %s/%s, want UNKNOWN",
			res.PackagePresent, res.BuildRelevant)
	}
	if !hasLimitation(res.Limitations, "module-level absence not admitted") {
		t.Fatalf("admission reason missing: %v", res.Limitations)
	}

	truncated := pkgs + "\n" + `{"ImportPath":"example.com/`
	res, _ = resolveEvidence(t, v,
		fakeTool{modules: []byte(mods), packages: []byte(truncated)}, scopedProduct())
	if res.PackagePresent != domain.ClaimUnknown || res.BuildRelevant != domain.ClaimUnknown {
		t.Fatalf("truncated inventory module absence = %s/%s, want UNKNOWN",
			res.PackagePresent, res.BuildRelevant)
	}
}

// Two version-affected entries are alternatives, not a sequence: the
// package probe covers all of them, and a hit narrows to the owning
// module. A first entry whose package is absent must not shield the
// second one's imported package.
func TestMultiAffectedEntriesUnionProbe(t *testing.T) {
	v := domain.Vulnerability{
		ID:     "GO-0000-0003",
		Module: "example.com/dep",
		AffectedModules: []domain.AffectedModule{
			{
				Module:           "example.com/dep",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "1.2.0"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "example.com/dep/vuln"}},
			},
			{
				Module:           "example.com/other",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "2.0.0"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "example.com/other/vuln"}},
			},
		},
	}
	mods := `{"Path":"example.com/dep","Version":"v1.0.0"}
{"Path":"example.com/other","Version":"v1.5.0"}`
	pkgs := `{"ImportPath":"example.com/product"}
{"ImportPath":"example.com/other/vuln"}`
	res, _, err := GoResolver{Tool: fakeTool{modules: []byte(mods), packages: []byte(pkgs)}}.
		Resolve(context.Background(), v, product())
	if err != nil {
		t.Fatal(err)
	}
	if res.PackagePresent != domain.ClaimTrue {
		t.Fatalf("second affected entry's package is imported: got PackagePresent=%s", res.PackagePresent)
	}
	if res.SelectedModule != "example.com/other" {
		t.Fatalf("SelectedModule=%q, want the imported entry's module", res.SelectedModule)
	}
	if len(res.CheckedPackages) != 2 {
		t.Fatalf("union probe expected, CheckedPackages=%v", res.CheckedPackages)
	}
}

// When BOTH entries' packages are imported the vulnerable path exists in
// each module — SelectedModules must carry both, so downstream narrowing
// cannot drop the second entry's symbols.
func TestMultiAffectedBothImported(t *testing.T) {
	v := domain.Vulnerability{
		ID:     "GO-0000-0003b",
		Module: "example.com/dep",
		AffectedModules: []domain.AffectedModule{
			{
				Module:           "example.com/dep",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "1.2.0"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "example.com/dep/vuln"}},
			},
			{
				Module:           "example.com/other",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "2.0.0"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "example.com/other/vuln"}},
			},
		},
	}
	mods := `{"Path":"example.com/dep","Version":"v1.0.0"}
{"Path":"example.com/other","Version":"v1.5.0"}`
	pkgs := `{"ImportPath":"example.com/product"}
{"ImportPath":"example.com/dep/vuln"}
{"ImportPath":"example.com/other/vuln"}`
	res, _, err := GoResolver{Tool: fakeTool{modules: []byte(mods), packages: []byte(pkgs)}}.
		Resolve(context.Background(), v, product())
	if err != nil {
		t.Fatal(err)
	}
	if res.PackagePresent != domain.ClaimTrue {
		t.Fatalf("got PackagePresent=%s", res.PackagePresent)
	}
	if len(res.SelectedModules) != 2 {
		t.Fatalf("both modules imported: SelectedModules=%v", res.SelectedModules)
	}
}

// A version-undecidable module still gets its packages probed: when the
// confirmed entry's package is absent but the pending entry's package is
// linked, PackagePresent=FALSE would be a false NOT_AFFECTED.
func TestPendingModulePackageProbe(t *testing.T) {
	v := domain.Vulnerability{
		ID:     "GO-0000-0003c",
		Module: "example.com/dep",
		AffectedModules: []domain.AffectedModule{
			{
				Module:           "example.com/dep",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "1.2.0"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "example.com/dep/vuln"}},
			},
			{
				Module:           "example.com/other",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "2.0.0"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "example.com/other/vuln"}},
			},
		},
	}
	mods := `{"Path":"example.com/dep","Version":"v1.0.0"}
{"Path":"example.com/other"}` // no Version — ranges unresolvable
	pkgs := `{"ImportPath":"example.com/product"}
{"ImportPath":"example.com/other/vuln"}`
	res, _, err := GoResolver{Tool: fakeTool{modules: []byte(mods), packages: []byte(pkgs)}}.
		Resolve(context.Background(), v, product())
	if err != nil {
		t.Fatal(err)
	}
	if res.PackagePresent != domain.ClaimTrue {
		t.Fatalf("pending entry's imported package must keep the case open, got PackagePresent=%s", res.PackagePresent)
	}
	found := false
	for _, m := range res.SelectedModules {
		if m == "example.com/other" {
			found = true
		}
	}
	if !found {
		t.Fatalf("pending module must land in SelectedModules: %v", res.SelectedModules)
	}
	// Only the pending module's code is linked — the confirmed version
	// verdict belongs to the unlinked entry and must not carry over.
	if res.VersionAffected != domain.ClaimUnknown {
		t.Fatalf("VersionAffected=%s — undecidable, the linked module's version is unresolved", res.VersionAffected)
	}
	if !slices.Contains(res.UnresolvedModules, "example.com/other") {
		t.Fatalf("pending module must be named in UnresolvedModules: %v", res.UnresolvedModules)
	}
	if res.ResolvedVersion != "" {
		t.Fatalf("ResolvedVersion=%q still names the unlinked module's version", res.ResolvedVersion)
	}
}

// Flat intake that names only Vulnerability.Package still probes that
// package — the fallback must survive multi-module normalization.
func TestFlatPackageFallback(t *testing.T) {
	v := domain.Vulnerability{
		ID:      "GO-0000-0004",
		Module:  "example.com/dep",
		Package: "example.com/dep/vuln",
		AffectedVersions: []domain.VersionRange{
			{Introduced: "0", Fixed: "1.2.0"},
		},
	}
	mods := `{"Path":"example.com/dep","Version":"v1.0.0"}`
	pkgs := `{"ImportPath":"example.com/product"}`
	res, _, err := GoResolver{Tool: fakeTool{modules: []byte(mods), packages: []byte(pkgs)}}.
		Resolve(context.Background(), v, scopedProduct())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.CheckedPackages) != 1 || res.CheckedPackages[0] != "example.com/dep/vuln" {
		t.Fatalf("Package fallback lost: CheckedPackages=%v", res.CheckedPackages)
	}
	if res.PackagePresent != domain.ClaimFalse {
		t.Fatalf("got %s, want FALSE over the fallback probe", res.PackagePresent)
	}
}

// An advisory that names no affected package leaves nothing to probe —
// absence cannot be asserted from an empty check set.
func TestNoAffectedPackagesIsUnknown(t *testing.T) {
	v := domain.Vulnerability{
		ID:     "GO-0000-0002",
		Module: "example.com/dep",
		AffectedVersions: []domain.VersionRange{
			{Introduced: "0", Fixed: "1.2.0"},
		},
	}
	mods := `{"Path":"example.com/dep","Version":"v1.0.0"}`
	pkgs := `{"ImportPath":"example.com/product"}`
	res, _, err := GoResolver{Tool: fakeTool{modules: []byte(mods), packages: []byte(pkgs)}}.
		Resolve(context.Background(), v, product())
	if err != nil {
		t.Fatal(err)
	}
	if res.PackagePresent != domain.ClaimUnknown {
		t.Fatalf("empty probed set must not assert absence: got %s", res.PackagePresent)
	}
	if !hasLimitation(res.Limitations, "no package or symbol identifies a package-level subject") {
		t.Fatalf("module-only limitation missing: %v", res.Limitations)
	}
}

func hasLimitation(lims []string, want string) bool {
	for _, l := range lims {
		if strings.Contains(l, want) {
			return true
		}
	}
	return false
}

func TestModuleWithoutVersionIsUnknown(t *testing.T) {
	mods := `{"Path":"example.com/dep","Main":true}`
	res := resolve(t, fakeTool{modules: []byte(mods)})
	if res.VersionAffected != domain.ClaimUnknown {
		t.Fatalf("main module has no version: got %s, want UNKNOWN", res.VersionAffected)
	}
}

func TestModuleListFailureIsUnknown(t *testing.T) {
	res := resolve(t, fakeTool{modErr: errors.New("build failed")})
	if res.ModulePresent != domain.ClaimUnknown || res.VersionAffected != domain.ClaimUnknown {
		t.Fatalf("tool failure must not become FALSE: %+v", res)
	}
	if len(res.Limitations) == 0 {
		t.Fatal("expected limitation describing tool failure")
	}
}

func TestPlatformConstraint(t *testing.T) {
	v := testVuln
	v.AffectedPackages = []domain.AffectedPackage{{Path: "example.com/dep/vuln", GOOS: []string{"windows"}}}
	mods := `{"Path":"example.com/dep","Version":"v1.0.0"}`
	pkgs := `{"ImportPath":"example.com/dep/vuln"}`
	res, _, err := GoResolver{Tool: fakeTool{modules: []byte(mods), packages: []byte(pkgs)}}.
		Resolve(context.Background(), v, scopedProduct())
	if err != nil {
		t.Fatal(err)
	}
	if res.BuildRelevant != domain.ClaimFalse {
		t.Fatalf("windows-only package on linux build: got %s, want FALSE", res.BuildRelevant)
	}
}

// A multi-module advisory is resolved against the entry the product
// actually depends on — an unaffected alternative must not shield the
// affected one (GO-2022-0493: stdlib fixed by toolchain, x/sys still
// vulnerable).
func TestMultiModuleSelectsAffectedEntry(t *testing.T) {
	v := domain.Vulnerability{
		ID:     "GO-2022-0493",
		Module: "stdlib",
		AffectedModules: []domain.AffectedModule{
			{
				Module:           "stdlib",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "1.17.10"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "syscall"}},
			},
			{
				Module:           "golang.org/x/sys",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "0.0.0-20220412"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "golang.org/x/sys/unix"}},
			},
		},
	}
	mods := `{"Path":"golang.org/x/sys","Version":"v0.0.0-20220209"}`
	pkgs := `{"ImportPath":"golang.org/x/sys/unix"}`
	res, _, err := GoResolver{Tool: fakeTool{modules: []byte(mods), packages: []byte(pkgs)}}.
		Resolve(context.Background(), v, product())
	if err != nil {
		t.Fatal(err)
	}
	if res.SelectedModule != "golang.org/x/sys" {
		t.Fatalf("selected=%q", res.SelectedModule)
	}
	if res.VersionAffected != domain.ClaimTrue || res.PackagePresent != domain.ClaimTrue {
		t.Fatalf("res=%+v", res)
	}
}

// When only the stdlib alternative applies (release toolchain fixed and
// the vendored module absent), the verdict stays deterministic-negative.
func TestMultiModuleNoEntryAffected(t *testing.T) {
	v := domain.Vulnerability{
		ID:               "GO-2022-0493",
		Module:           "stdlib",
		AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "1.17.10"}},
		AffectedModules: []domain.AffectedModule{
			{
				Module:           "stdlib",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "1.17.10"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "syscall"}},
			},
			{
				Module:           "golang.org/x/sys",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "0.0.0-20220412"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "golang.org/x/sys/unix"}},
			},
		},
	}
	mods := `{"Path":"example.com/product","Main":true}`
	pkgs := `{"ImportPath":"example.com/product"}`
	prod := product()
	prod.GoVersion = "go version go1.26.1 linux/amd64"
	prod.ReleaseGoVersion = "go1.26.1"
	res, _, err := GoResolver{Tool: fakeTool{modules: []byte(mods), packages: []byte(pkgs)}}.
		Resolve(context.Background(), v, prod)
	if err != nil {
		t.Fatal(err)
	}
	if res.VersionAffected != domain.ClaimFalse {
		t.Fatalf("res=%+v", res)
	}
}

// Both modules linked — confirmed AND pending: the version stays TRUE
// (attributed to the confirmed module) and PendingModules names the
// undecidable one so version facts cannot be consumed as its fact.
func TestPendingModuleMixedLink(t *testing.T) {
	v := domain.Vulnerability{
		ID:     "GO-0000-0003d",
		Module: "example.com/dep",
		AffectedModules: []domain.AffectedModule{
			{
				Module:           "example.com/dep",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "1.2.0"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "example.com/dep/vuln"}},
			},
			{
				Module:           "example.com/other",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "2.0.0"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "example.com/other/vuln"}},
			},
		},
	}
	mods := `{"Path":"example.com/dep","Version":"v1.0.0"}
{"Path":"example.com/other"}` // no Version — pending
	pkgs := `{"ImportPath":"example.com/product"}
{"ImportPath":"example.com/dep/vuln"}
{"ImportPath":"example.com/other/vuln"}`
	res, _, err := GoResolver{Tool: fakeTool{modules: []byte(mods), packages: []byte(pkgs)}}.
		Resolve(context.Background(), v, product())
	if err != nil {
		t.Fatal(err)
	}
	if res.VersionAffected != domain.ClaimTrue {
		t.Fatalf("confirmed module linked — VersionAffected=%s", res.VersionAffected)
	}
	if res.SelectedModule != "example.com/dep" || res.ResolvedVersion != "v1.0.0" {
		t.Fatalf("version pair must pin to the confirmed module: %s@%s", res.SelectedModule, res.ResolvedVersion)
	}
	if len(res.PendingModules) != 1 || res.PendingModules[0] != "example.com/other" {
		t.Fatalf("PendingModules=%v — linked pending module must be named", res.PendingModules)
	}
}

func TestUnreviewedModuleTestOnlyAbsentFromMains(t *testing.T) {
	v := domain.Vulnerability{
		ID:     "GO-0000-0010",
		Module: "example.com/testdep",
		AffectedVersions: []domain.VersionRange{
			{Introduced: "0"},
		},
		// Unreviewed advisory: no AffectedPackages
	}
	mods := `{"Path":"example.com/testdep","Version":"v1.0.0"}`
	pkgs := `{"ImportPath":"example.com/product/cmd/app","Name":"main","Deps":["example.com/product/pkg/service"]}
{"ImportPath":"example.com/product/pkg/service","Deps":[]}
{"ImportPath":"example.com/product/pkg/service.test","Name":"main","Deps":["example.com/product/pkg/service","example.com/testdep/helper"]}
{"ImportPath":"example.com/testdep/helper","Module":{"Path":"example.com/testdep"},"Deps":[]}`

	res, _, err := GoResolver{Tool: fakeTool{modules: []byte(mods), packages: []byte(pkgs)}}.
		Resolve(context.Background(), v, scopedProduct())
	if err != nil {
		t.Fatal(err)
	}
	if res.PackagePresent != domain.ClaimFalse {
		t.Fatalf("unreviewed module used only in tests must be FALSE for product executables, got: %s", res.PackagePresent)
	}
	if res.BuildRelevant != domain.ClaimFalse {
		t.Fatalf("BuildRelevant must be FALSE, got: %s", res.BuildRelevant)
	}
	hasTestLimitation := false
	for _, lim := range res.Limitations {
		if strings.Contains(lim, "test scope") || strings.Contains(lim, "absent from compiled product executables") {
			hasTestLimitation = true
			break
		}
	}
	if !hasTestLimitation {
		t.Fatalf("expected test-scope limitation, got: %v", res.Limitations)
	}
	if !hasLimitation(res.Limitations, "no package or symbol identifies a package-level subject") {
		t.Fatalf("module-only limitation must be recorded on the bounded negative too: %v", res.Limitations)
	}
}

func TestReviewedPackageTestOnlyAbsentFromMains(t *testing.T) {
	v := domain.Vulnerability{
		ID:     "GO-0000-0011",
		Module: "example.com/testdep",
		AffectedVersions: []domain.VersionRange{
			{Introduced: "0", Fixed: "1.2.0"},
		},
		AffectedPackages: []domain.AffectedPackage{{Path: "example.com/testdep/vulnpkg"}},
	}
	mods := `{"Path":"example.com/testdep","Version":"v1.0.0"}`
	pkgs := `{"ImportPath":"example.com/product/cmd/app","Name":"main","Deps":["example.com/product/pkg/service"]}
{"ImportPath":"example.com/product/pkg/service","Deps":[]}
{"ImportPath":"example.com/product/pkg/service.test","Name":"main","Deps":["example.com/product/pkg/service","example.com/testdep/vulnpkg"]}
{"ImportPath":"example.com/testdep/vulnpkg","Module":{"Path":"example.com/testdep"},"Deps":[]}`

	res, _, err := GoResolver{Tool: fakeTool{modules: []byte(mods), packages: []byte(pkgs)}}.
		Resolve(context.Background(), v, scopedProduct())
	if err != nil {
		t.Fatal(err)
	}
	if res.PackagePresent != domain.ClaimFalse {
		t.Fatalf("reviewed package used only in tests must be FALSE for product executables, got: %s", res.PackagePresent)
	}
	if res.BuildRelevant != domain.ClaimFalse {
		t.Fatalf("BuildRelevant must be FALSE, got: %s", res.BuildRelevant)
	}
}

// A stdlib advisory without a recorded release toolchain is undecidable:
// go.mod is a language minimum and the local `go version` is the analysis
// environment, so neither may resolve the affected range. The entry goes
// pending — ModulePresent stays TRUE (stdlib is always in scope) while
// VersionAffected stays UNKNOWN, and the linked affected package keeps the
// case open.
func TestStdlibEntryPendingWithoutReleaseVersion(t *testing.T) {
	v := domain.Vulnerability{
		ID:     "GO-2023-2102",
		Module: "stdlib",
		AffectedModules: []domain.AffectedModule{
			{
				Module:           "stdlib",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "1.21.3"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "net/http"}},
			},
		},
	}
	mods := `{"Path":"example.com/product","Main":true}`
	pkgs := `{"ImportPath":"example.com/product","Name":"main","Deps":["net/http"]}
{"ImportPath":"net/http","Deps":[]}`
	prod := product()
	// go.mod minimum + analysis toolchain are present but are not the
	// release toolchain: no --release-go-version, no --binary, no
	// discovered release evidence (GoVersionSource stays empty).
	prod.GoModDirective = "1.23"
	prod.MinimumGoVersion = "1.23"
	prod.GoVersion = "go version go1.26.1 linux/amd64"
	res, _, err := GoResolver{Tool: fakeTool{modules: []byte(mods), packages: []byte(pkgs)}}.
		Resolve(context.Background(), v, prod)
	if err != nil {
		t.Fatal(err)
	}
	if res.ModulePresent != domain.ClaimTrue {
		t.Fatalf("stdlib is always present: ModulePresent=%s", res.ModulePresent)
	}
	if res.VersionAffected != domain.ClaimUnknown {
		t.Fatalf("release toolchain unknown must not resolve the range: VersionAffected=%s", res.VersionAffected)
	}
	if res.PackagePresent != domain.ClaimTrue {
		t.Fatalf("linked affected package keeps the case open: PackagePresent=%s", res.PackagePresent)
	}
	if len(res.PendingModules) != 1 || res.PendingModules[0] != "stdlib" {
		t.Fatalf("stdlib entry must be pending: PendingModules=%v", res.PendingModules)
	}
	found := false
	for _, l := range res.Limitations {
		if strings.Contains(l, "release toolchain unknown") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected release-toolchain limitation, got %v", res.Limitations)
	}
}

// A stdlib-only advisory resolves deterministically once the release
// toolchain is known: a fixed release version is outside the affected
// range regardless of the analysis toolchain or go.mod.
func TestStdlibEntryResolvedByReleaseVersion(t *testing.T) {
	v := domain.Vulnerability{
		ID:     "GO-2023-2102",
		Module: "stdlib",
		AffectedModules: []domain.AffectedModule{
			{
				Module:           "stdlib",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "1.21.3"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "net/http"}},
			},
		},
	}
	mods := `{"Path":"example.com/product","Main":true}`
	pkgs := `{"ImportPath":"example.com/product","Name":"main","Deps":["net/http"]}
{"ImportPath":"net/http","Deps":[]}`
	prod := product()
	prod.GoVersion = "go version go1.20.0 linux/amd64" // analysis toolchain differs on purpose
	prod.ReleaseGoVersion = "go1.21.4"
	prod.GoVersionSource = domain.GoVersionSourceBinary
	res, _, err := GoResolver{Tool: fakeTool{modules: []byte(mods), packages: []byte(pkgs)}}.
		Resolve(context.Background(), v, prod)
	if err != nil {
		t.Fatal(err)
	}
	if res.VersionAffected != domain.ClaimFalse {
		t.Fatalf("fixed release toolchain must resolve the range: %+v", res)
	}
}

// Multi-module advisory with an unresolvable stdlib entry and a confirmed
// vulnerable dependency: the confirmed entry wins VersionAffected=TRUE and
// the pending stdlib entry is named so its version fact is not consumed.
func TestStdlibPendingDependencyConfirmed(t *testing.T) {
	v := domain.Vulnerability{
		ID:     "GO-2023-2102",
		Module: "stdlib",
		AffectedModules: []domain.AffectedModule{
			{
				Module:           "stdlib",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "1.21.3"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "net/http"}},
			},
			{
				Module:           "golang.org/x/net",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "0.17.0"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "golang.org/x/net/http2"}},
			},
		},
	}
	mods := `{"Path":"example.com/product","Main":true}
{"Path":"golang.org/x/net","Version":"v0.10.0"}`
	pkgs := `{"ImportPath":"example.com/product","Name":"main","Deps":["net/http","golang.org/x/net/http2"]}
{"ImportPath":"net/http","Deps":[]}
{"ImportPath":"golang.org/x/net/http2","Module":{"Path":"golang.org/x/net"},"Deps":[]}`
	prod := product()
	prod.GoModDirective = "1.23"
	prod.GoVersion = "go version go1.26.1 linux/amd64"
	res, _, err := GoResolver{Tool: fakeTool{modules: []byte(mods), packages: []byte(pkgs)}}.
		Resolve(context.Background(), v, prod)
	if err != nil {
		t.Fatal(err)
	}
	if res.VersionAffected != domain.ClaimTrue {
		t.Fatalf("confirmed dependency entry wins: VersionAffected=%s", res.VersionAffected)
	}
	if res.SelectedModule != "golang.org/x/net" || res.ResolvedVersion != "v0.10.0" {
		t.Fatalf("version must pin to the confirmed module: %s@%s", res.SelectedModule, res.ResolvedVersion)
	}
	if !slices.Contains(res.PendingModules, "stdlib") {
		t.Fatalf("stdlib pending entry must be named: %v", res.PendingModules)
	}
	if !slices.Contains(res.UnresolvedModules, "stdlib") {
		t.Fatalf("stdlib pending entry must be named in UnresolvedModules: %v", res.UnresolvedModules)
	}
}

// A pending entry whose package is NOT linked must still be recorded as
// unresolved: pending_modules only names linked modules, so
// unresolved_modules is the linkage-independent signal that keeps such
// an entry from being read as fixed downstream.
func TestPendingUnlinkedModuleIsUnresolved(t *testing.T) {
	v := domain.Vulnerability{
		ID:     "GO-0000-0006",
		Module: "example.com/dep",
		AffectedModules: []domain.AffectedModule{
			{
				Module:           "example.com/dep",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "1.2.0"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "example.com/dep/vuln"}},
			},
		},
	}
	mods := `{"Path":"example.com/dep"}` // present, no Version — ranges unresolvable
	pkgs := `{"ImportPath":"example.com/product"}`
	res, _, err := GoResolver{Tool: fakeTool{modules: []byte(mods), packages: []byte(pkgs)}}.
		Resolve(context.Background(), v, product())
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(res.PendingModules, "example.com/dep") {
		t.Fatalf("unlinked pending module must not land in PendingModules: %v", res.PendingModules)
	}
	if !slices.Contains(res.UnresolvedModules, "example.com/dep") {
		t.Fatalf("unlinked pending module must be named in UnresolvedModules: %v", res.UnresolvedModules)
	}
	if res.VersionAffected != domain.ClaimUnknown {
		t.Fatalf("VersionAffected=%s — undecidable while the only present module is unresolved", res.VersionAffected)
	}
}

// Version-side membership must survive a package-negative probe. Two entries
// can both sit inside their affected ranges while only one package links into
// the product; the unlinked entry is still version-affected, and reading it as
// "fixed" would turn a reachability result into a version claim.
func TestVersionAffectedMembershipSurvivesPackageNegative(t *testing.T) {
	v := domain.Vulnerability{
		ID: "GO-0000-0004",
		AffectedModules: []domain.AffectedModule{
			{
				Module:           "example.com/dep",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "2.0.0"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "example.com/dep/vuln"}},
			},
			{
				Module:           "example.com/other",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "2.0.0"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "example.com/other/vuln"}},
			},
		},
	}
	mods := `{"Path":"example.com/dep","Version":"v1.0.0"}
{"Path":"example.com/other","Version":"v1.0.0"}`
	pkgs := `{"ImportPath":"example.com/product"}
{"ImportPath":"example.com/dep/vuln","Module":{"Path":"example.com/dep","Version":"v1.0.0"}}`
	res, _, err := GoResolver{Tool: fakeTool{modules: []byte(mods), packages: []byte(pkgs)}}.
		Resolve(context.Background(), v, product())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	for _, m := range []string{"example.com/dep", "example.com/other"} {
		if !slices.Contains(res.VersionAffectedModules, m) {
			t.Fatalf("VersionAffectedModules=%v, want %s (version fact survives the package probe)",
				res.VersionAffectedModules, m)
		}
	}
	if slices.Contains(res.SelectedModules, "example.com/other") {
		t.Fatalf("SelectedModules=%v, want only the linked entry", res.SelectedModules)
	}
}

// Advisory-declared symbols carry package identity: a symbol's package
// joins the package probe even when the advisory names no affected
// package — a linked symbol package grounds presence.
func TestAdvisorySymbolPackageProbePresent(t *testing.T) {
	v := domain.Vulnerability{
		ID:     "GO-0000-0100",
		Module: "example.com/dep",
		AffectedVersions: []domain.VersionRange{
			{Introduced: "0", Fixed: "1.2.0"},
		},
		AffectedSymbols: []domain.SymbolRef{
			{Package: "example.com/dep/vuln", Symbol: "Parse"},
		},
	}
	mods := `{"Path":"example.com/dep","Version":"v1.0.0"}`
	pkgs := `{"ImportPath":"example.com/product"}
{"ImportPath":"example.com/dep/vuln","Module":{"Path":"example.com/dep","Version":"v1.0.0"}}`
	res, _, err := GoResolver{Tool: fakeTool{modules: []byte(mods), packages: []byte(pkgs)}}.
		Resolve(context.Background(), v, product())
	if err != nil {
		t.Fatal(err)
	}
	if res.PackagePresent != domain.ClaimTrue {
		t.Fatalf("linked symbol package must ground presence: PackagePresent=%s", res.PackagePresent)
	}
	if !slices.Equal(res.CheckedPackages, []string{"example.com/dep/vuln"}) {
		t.Fatalf("CheckedPackages=%v", res.CheckedPackages)
	}
	if res.SelectedModule != "example.com/dep" {
		t.Fatalf("SelectedModule=%q", res.SelectedModule)
	}
}

// A symbol-declared package absent from the product closure gives the
// same bounded FALSE as an explicitly declared package — CheckedPackages
// names exactly what was probed.
func TestAdvisorySymbolPackageProbeAbsent(t *testing.T) {
	v := domain.Vulnerability{
		ID:     "GO-0000-0101",
		Module: "example.com/dep",
		AffectedVersions: []domain.VersionRange{
			{Introduced: "0", Fixed: "1.2.0"},
		},
		AffectedSymbols: []domain.SymbolRef{
			{Package: "example.com/dep/vuln", Symbol: "Parse"},
		},
	}
	mods := `{"Path":"example.com/dep","Version":"v1.0.0"}`
	pkgs := `{"ImportPath":"example.com/product"}`
	res, _, err := GoResolver{Tool: fakeTool{modules: []byte(mods), packages: []byte(pkgs)}}.
		Resolve(context.Background(), v, scopedProduct())
	if err != nil {
		t.Fatal(err)
	}
	if res.PackagePresent != domain.ClaimFalse || res.BuildRelevant != domain.ClaimFalse {
		t.Fatalf("absent symbol package must give bounded FALSE: package=%s build=%s",
			res.PackagePresent, res.BuildRelevant)
	}
	if !slices.Equal(res.CheckedPackages, []string{"example.com/dep/vuln"}) {
		t.Fatalf("CheckedPackages=%v", res.CheckedPackages)
	}
}

// A symbol without package identity must never synthesize a candidate
// from the module path: the entry stays on the module-only branch.
func TestAdvisorySymbolWithoutPackageNoCandidate(t *testing.T) {
	v := domain.Vulnerability{
		ID:     "GO-0000-0102",
		Module: "example.com/dep",
		AffectedVersions: []domain.VersionRange{
			{Introduced: "0", Fixed: "1.2.0"},
		},
		AffectedSymbols: []domain.SymbolRef{
			{Package: "", Symbol: "orphanSymbol"},
		},
	}
	mods := `{"Path":"example.com/dep","Version":"v1.0.0"}`
	pkgs := `{"ImportPath":"example.com/product"}`
	res, _, err := GoResolver{Tool: fakeTool{modules: []byte(mods), packages: []byte(pkgs)}}.
		Resolve(context.Background(), v, product())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.CheckedPackages) != 0 {
		t.Fatalf("module path must not be probed as a package: CheckedPackages=%v", res.CheckedPackages)
	}
	if res.PackagePresent != domain.ClaimUnknown {
		t.Fatalf("no package-level subject must stay UNKNOWN: %s", res.PackagePresent)
	}
	if !hasLimitation(res.Limitations, "no package or symbol identifies a package-level subject") {
		t.Fatalf("module-only limitation missing: %v", res.Limitations)
	}
}

// Symbol and explicitly declared packages merge into a single ordered
// probe set: the declared path keeps its slot, the symbol-only package
// is appended in symbol order, and nothing is duplicated.
func TestSymbolPackageMergedWithDeclared(t *testing.T) {
	v := domain.Vulnerability{
		ID:     "GO-0000-0103",
		Module: "example.com/dep",
		AffectedVersions: []domain.VersionRange{
			{Introduced: "0", Fixed: "1.2.0"},
		},
		AffectedPackages: []domain.AffectedPackage{{Path: "example.com/dep/vuln"}},
		AffectedSymbols: []domain.SymbolRef{
			{Package: "example.com/dep/vuln", Symbol: "Parse"},
			{Package: "example.com/dep/other", Symbol: "Helper"},
			{Package: "example.com/dep/other", Symbol: "Helper"},
		},
	}
	mods := `{"Path":"example.com/dep","Version":"v1.0.0"}`
	pkgs := `{"ImportPath":"example.com/product"}`
	res, _, err := GoResolver{Tool: fakeTool{modules: []byte(mods), packages: []byte(pkgs)}}.
		Resolve(context.Background(), v, scopedProduct())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"example.com/dep/vuln", "example.com/dep/other"}
	if !slices.Equal(res.CheckedPackages, want) {
		t.Fatalf("CheckedPackages=%v, want merged %v", res.CheckedPackages, want)
	}
	if res.PackagePresent != domain.ClaimFalse {
		t.Fatalf("merged probe set absent: PackagePresent=%s", res.PackagePresent)
	}
}

// The merge helper itself: declared order first, symbol candidates in
// symbol order, symbols folded into their package without duplication,
// and the advisory record is never mutated.
func TestPackageProjectionMerge(t *testing.T) {
	declared := []domain.AffectedPackage{{Path: "example.com/dep/vuln", Symbols: []string{"Parse"}}}
	got := AffectedPackagesForEntry(domain.AffectedModule{
		Module:           "example.com/dep",
		AffectedPackages: declared,
		AffectedSymbols: []domain.SymbolRef{
			{Package: "example.com/dep/vuln", Symbol: "Parse"},
			{Package: "example.com/dep/vuln", Symbol: "Decode"},
			{Package: "example.com/dep/other", Symbol: "Helper"},
			{Package: "example.com/dep/other", Symbol: "Helper"},
			{Package: "", Symbol: "skipped"},
		},
	})
	want := []domain.AffectedPackage{
		{Path: "example.com/dep/vuln", Symbols: []string{"Parse", "Decode"}},
		{Path: "example.com/dep/other", Symbols: []string{"Helper"}},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i].Path != want[i].Path || !slices.Equal(got[i].Symbols, want[i].Symbols) {
			t.Fatalf("got[%d]=%+v, want %+v", i, got[i], want[i])
		}
	}
	if !slices.Equal(declared[0].Symbols, []string{"Parse"}) {
		t.Fatalf("merge mutated the declared package: %+v", declared[0])
	}
}

// A module-only advisory whose module has packages in the compiled scope
// keeps package presence UNKNOWN: the module's presence is not a package
// subject, and guessing one would be an invented fact.
func TestModuleOnlyCompiledModuleIsUnknown(t *testing.T) {
	v := domain.Vulnerability{
		ID:     "GO-0000-0104",
		Module: "example.com/testdep",
		AffectedVersions: []domain.VersionRange{
			{Introduced: "0", Fixed: "1.2.0"},
		},
	}
	mods := `{"Path":"example.com/testdep","Version":"v1.0.0"}`
	pkgs := `{"ImportPath":"example.com/product/cmd/app","Name":"main","Deps":["example.com/testdep/helper"]}
{"ImportPath":"example.com/testdep/helper","Module":{"Path":"example.com/testdep"},"Deps":[]}`
	res, _, err := GoResolver{Tool: fakeTool{modules: []byte(mods), packages: []byte(pkgs)}}.
		Resolve(context.Background(), v, product())
	if err != nil {
		t.Fatal(err)
	}
	if res.PackagePresent != domain.ClaimUnknown || res.BuildRelevant != domain.ClaimUnknown {
		t.Fatalf("compiled module packages are not a package subject: package=%s build=%s",
			res.PackagePresent, res.BuildRelevant)
	}
	if len(res.CheckedPackages) != 0 {
		t.Fatalf("no package must be invented: CheckedPackages=%v", res.CheckedPackages)
	}
	if !hasLimitation(res.Limitations, "no package or symbol identifies a package-level subject") {
		t.Fatalf("module-only limitation missing: %v", res.Limitations)
	}
}

// A fixed version still does not assert package absence even when the
// advisory declares symbols: the probe never runs, so projected packages
// stay out of CheckedPackages and the claims stay UNKNOWN.
func TestFixedVersionSymbolProjectionNoAbsence(t *testing.T) {
	v := domain.Vulnerability{
		ID:     "GO-0000-0105",
		Module: "example.com/dep",
		AffectedVersions: []domain.VersionRange{
			{Introduced: "0", Fixed: "1.2.0"},
		},
		AffectedSymbols: []domain.SymbolRef{
			{Package: "example.com/dep/vuln", Symbol: "Parse"},
		},
	}
	mods := `{"Path":"example.com/product","Main":true}
{"Path":"example.com/dep","Version":"v1.2.0"}`
	res, _, err := GoResolver{Tool: fakeTool{modules: []byte(mods)}}.
		Resolve(context.Background(), v, product())
	if err != nil {
		t.Fatal(err)
	}
	if res.VersionAffected != domain.ClaimFalse {
		t.Fatalf("v1.2.0 is the fixed version, got VersionAffected=%s", res.VersionAffected)
	}
	if res.PackagePresent == domain.ClaimFalse || res.BuildRelevant == domain.ClaimFalse {
		t.Fatalf("fixed version must not assert package/build absence: package=%s build=%s",
			res.PackagePresent, res.BuildRelevant)
	}
	if len(res.CheckedPackages) != 0 {
		t.Fatalf("the skipped probe must not record checked packages: %v", res.CheckedPackages)
	}
	if !hasLimitation(res.Limitations, "not evaluated") {
		t.Fatalf("no limitation states that reachability was not evaluated: %v", res.Limitations)
	}
}

// ---------------------------------------------------------------------------
// Implementation-presence axis
// ---------------------------------------------------------------------------

func productTargetAssumption(t *testing.T, scope string, goos []string, goarch []string) *domain.DeclaredAssumptionsInput {
	t.Helper()
	a := domain.DeclaredAssumption{
		ID:         "AT-linux-only",
		Kind:       domain.AssumptionSupportedTargets,
		Statement:  "the product distribution supports Linux only",
		Scope:      scope,
		Authority:  "product owner",
		Owner:      "release engineering",
		SourceRef:  "frozen:test/targets",
		ReviewDate: "2099-01-01",
		Targets:    &domain.ProductTargetScope{GOOS: goos, GOARCH: goarch},
	}
	a.Digest = domain.CanonicalAssumptionDigest(a)
	doc := &domain.DeclaredAssumptionsDocument{
		Schema:      domain.DeclaredAssumptionsSchema,
		Assumptions: []domain.DeclaredAssumption{a},
	}
	doc.ContentDigest = domain.DeclaredAssumptionsContentDigest(doc.Schema, doc.Assumptions)
	if err := domain.ValidateDeclaredAssumptions(doc); err != nil {
		t.Fatalf("test assumption is invalid: %v", err)
	}
	return &domain.DeclaredAssumptionsInput{
		Path: "local:targets.json", Schema: doc.Schema, ContentDigest: doc.ContentDigest,
		Assumptions: doc.Assumptions,
	}
}

func artifactTarget() *domain.ProductTarget {
	return &domain.ProductTarget{
		GOOS: "linux", GOARCH: "amd64",
		Source: domain.ProductTargetSourceArtifactBuildInfo, Scope: domain.ProductTargetScopeArtifact,
		ArtifactSHA256: strings.Repeat("a", 64), BuildInfoSHA256: strings.Repeat("b", 64),
	}
}

func axisTool(f *implFixture) GoTool {
	pkg := filepath.Join(f.root, "vendor/example.com/dep/resource")
	packages := `{"ImportPath":"example.com/product","Name":"main","Deps":["example.com/dep/resource"]}
{"ImportPath":"example.com/dep/resource","Name":"resource","DepOnly":true,"Dir":` + strconv.Quote(pkg) + `,"Module":{"Path":"example.com/dep","Version":"v1.0.0"}}`
	return fakeTool{packages: []byte(packages)}
}

func axisInput(t *testing.T, f *implFixture, assumptions *domain.DeclaredAssumptionsInput, proposals ...domain.ImplementationLocusProposal) ImplementationAxisInput {
	t.Helper()
	base := f.input(proposals[0])
	affected := f.affected
	affected.PackagePresent = domain.ClaimUnknown
	affected.BuildRelevant = domain.ClaimUnknown
	affected.ResolvedVersion = "v1.0.0"
	build := f.build
	build.Target = artifactTarget()
	return ImplementationAxisInput{
		Proposals:               proposals,
		Entries:                 []domain.AffectedModule{f.entry},
		Affected:                affected,
		Build:                   build,
		SnapshotRoot:            f.root,
		SnapshotContentHash:     f.hash,
		AdvisoryID:              base.AdvisoryID,
		AdvisorySHA256:          base.AdvisorySHA256,
		AdvisoryCanonicalSHA256: base.AdvisoryCanonicalSHA256,
		AdvisoryBytes:           f.advisory,
		Assumptions:             assumptions,
		Tool:                    axisTool(f),
		Now:                     time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC),
	}
}

// A product-scope Linux-only assumption plus a digest-bound Linux artifact
// target closes the axis on a verified-absent BSD implementation. The
// package/build axes are established for the proposal's package; they stay
// semantically "package present / build relevant", not implementation
// presence.
func TestEvaluateImplementationAxisProductScopeAbsent(t *testing.T) {
	f := newImplFixture(t)
	in := axisInput(t, f, productTargetAssumption(t, domain.AssumptionScopeProduct, []string{"linux"}, []string{"amd64"}), f.proposal())
	res := EvaluateImplementationAxis(context.Background(), in)
	if res.Present != domain.ClaimFalse {
		t.Fatalf("axis = %s (%s); limitations: %v", res.Present, res.Reason, res.Limitations)
	}
	if res.TargetScope != domain.AssumptionScopeProduct {
		t.Fatalf("target scope = %q", res.TargetScope)
	}
	if len(res.AssumptionIDs) != 1 || res.AssumptionIDs[0] != "AT-linux-only" {
		t.Fatalf("assumption ids = %v", res.AssumptionIDs)
	}
	if !strings.Contains(res.Locus, "host_bsd.go") || !strings.Contains(res.Locus, "kenv") {
		t.Fatalf("locus = %q", res.Locus)
	}
	if !strings.Contains(res.Reason, "linux/amd64") || !strings.Contains(res.Reason, "product") {
		t.Fatalf("reason = %q", res.Reason)
	}
	if res.Affected.PackagePresent != domain.ClaimTrue || res.Affected.BuildRelevant != domain.ClaimTrue {
		t.Fatalf("package/build axes = %s/%s, want TRUE", res.Affected.PackagePresent, res.Affected.BuildRelevant)
	}
	if res.Affected.VulnerableImplementationPresent != domain.ClaimFalse ||
		res.Affected.ImplementationTargetScope != domain.AssumptionScopeProduct ||
		res.Affected.ImplementationTarget != "linux/amd64" {
		t.Fatalf("affected projection = %+v", res.Affected)
	}
	if len(res.Affected.AssumptionIDs) != 1 || res.Affected.AssumptionIDs[0] != "AT-linux-only" {
		t.Fatalf("affected assumption ids = %v", res.Affected.AssumptionIDs)
	}
	if len(res.Verifications) != 1 || res.Verifications[0].Status != ImplementationVerifiedAbsent {
		t.Fatalf("verifications = %+v", res.Verifications)
	}
	if len(res.Evidence) == 0 {
		t.Fatal("axis recorded no evidence")
	}
}

// Artifact-scoped evidence describes one build; it can never close the
// product-wide axis.
func TestEvaluateImplementationAxisArtifactScopeCannotClose(t *testing.T) {
	f := newImplFixture(t)
	in := axisInput(t, f, productTargetAssumption(t, domain.AssumptionScopeArtifact, []string{"linux"}, []string{"amd64"}), f.proposal())
	res := EvaluateImplementationAxis(context.Background(), in)
	if res.Present != domain.ClaimUnknown {
		t.Fatalf("artifact-scoped assumption closed the axis: %s (%s)", res.Present, res.Reason)
	}
	if !hasLimitation(res.Limitations, "artifact-scoped") {
		t.Fatalf("limitations = %v", res.Limitations)
	}
	if res.Affected.VulnerableImplementationPresent == domain.ClaimFalse {
		t.Fatal("artifact-scoped evidence produced an implementation FALSE")
	}
}

// The analyzer host is never a product target: a host-default target stays
// UNKNOWN even when a product-scope assumption is supplied, and a target
// outside the declared matrix also stays UNKNOWN.
func TestEvaluateImplementationAxisHostAndMismatchStayUnknown(t *testing.T) {
	f := newImplFixture(t)
	assumptions := productTargetAssumption(t, domain.AssumptionScopeProduct, []string{"linux"}, []string{"amd64"})

	host := axisInput(t, f, assumptions, f.proposal())
	hostBuild := host.Build
	hostBuild.GOOS = runtime.GOOS
	hostBuild.GOARCH = runtime.GOARCH
	hostBuild.Target = &domain.ProductTarget{
		GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Source: domain.ProductTargetSourceHostDefault,
	}
	host.Build = hostBuild
	res := EvaluateImplementationAxis(context.Background(), host)
	if res.Present != domain.ClaimUnknown || !strings.Contains(res.Reason, "host default") {
		t.Fatalf("host target = %s (%s)", res.Present, res.Reason)
	}
	if len(res.Verifications) != 0 {
		t.Fatalf("verifier ran under a host target: %+v", res.Verifications)
	}

	mismatch := axisInput(t, f, productTargetAssumption(t, domain.AssumptionScopeProduct, []string{"windows"}, []string{"amd64"}), f.proposal())
	res = EvaluateImplementationAxis(context.Background(), mismatch)
	if res.Present != domain.ClaimUnknown || !strings.Contains(res.Reason, "does not match") {
		t.Fatalf("mismatched target = %s (%s)", res.Present, res.Reason)
	}
}

// A wrong proposal (file that does not exist) fails closed; it never
// produces an implementation FALSE.
func TestEvaluateImplementationAxisWrongProposalFailsClosed(t *testing.T) {
	f := newImplFixture(t)
	p := f.proposal()
	p.File = "missing.go"
	in := axisInput(t, f, productTargetAssumption(t, domain.AssumptionScopeProduct, []string{"linux"}, []string{"amd64"}), p)
	res := EvaluateImplementationAxis(context.Background(), in)
	if res.Present != domain.ClaimUnknown {
		t.Fatalf("wrong proposal closed the axis: %s (%s)", res.Present, res.Reason)
	}
	if res.Affected.VulnerableImplementationPresent == domain.ClaimFalse {
		t.Fatal("wrong proposal produced an implementation FALSE")
	}
}

// A selected alternate implementation carrying the vulnerable marker
// blocks absence even though the proposed BSD file is excluded.
func TestEvaluateImplementationAxisSelectedAlternateMarkerBlocksAbsence(t *testing.T) {
	f := newImplFixture(t)
	linux := filepath.Join(f.root, "vendor/example.com/dep/resource/host_linux.go")
	if err := os.WriteFile(linux, []byte(
		"//go:build linux\n\npackage resource\n\nfunc read() string { return execCommand(\"kenv\", \"-q\", \"x\") }\n\nfunc execCommand(name string, args ...string) string { return name }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	hash, err := repository.ContentHash(f.root)
	if err != nil {
		t.Fatal(err)
	}
	f.hash = hash
	in := axisInput(t, f, productTargetAssumption(t, domain.AssumptionScopeProduct, []string{"linux"}, []string{"amd64"}), f.proposal())
	res := EvaluateImplementationAxis(context.Background(), in)
	if res.Present != domain.ClaimTrue {
		t.Fatalf("alternate marker did not block absence: %s (%s)", res.Present, res.Reason)
	}
	if res.Affected.VulnerableImplementationPresent == domain.ClaimFalse {
		t.Fatal("selected alternate marker produced an implementation FALSE")
	}
}

// The axis requires module/version applicability before it may establish
// package presence or run the verifier.
func TestEvaluateImplementationAxisRequiresVersionAffected(t *testing.T) {
	f := newImplFixture(t)
	in := axisInput(t, f, productTargetAssumption(t, domain.AssumptionScopeProduct, []string{"linux"}, []string{"amd64"}), f.proposal())
	in.Affected.VersionAffected = domain.ClaimUnknown
	res := EvaluateImplementationAxis(context.Background(), in)
	if res.Present != domain.ClaimUnknown {
		t.Fatalf("version-undecided chain closed the axis: %s", res.Present)
	}
	if len(res.Verifications) != 0 {
		t.Fatal("verifier ran without established version applicability")
	}
}

// isStdlibModule is exact identity: an unnamed advisory entry must never be
// routed into the release-toolchain branch.
func TestIsStdlibModuleRejectsEmpty(t *testing.T) {
	if isStdlibModule("") {
		t.Fatal(`isStdlibModule("") = true, want false: an empty module is never stdlib`)
	}
}

// A dot-less first path segment is not stdlib evidence for a module
// identity — only the supported pseudo-modules classify as stdlib.
func TestIsStdlibModuleRejectsDotlessThirdPartyPath(t *testing.T) {
	for _, module := range []string{"example", "example/module"} {
		if isStdlibModule(module) {
			t.Fatalf("isStdlibModule(%q) = true, want false", module)
		}
	}
}

// The explicitly supported pseudo-modules are the only stdlib identities.
func TestIsStdlibModuleAcceptsKnownPseudoModules(t *testing.T) {
	for _, module := range []string{"std", "stdlib", "toolchain", "cmd"} {
		if !isStdlibModule(module) {
			t.Fatalf("isStdlibModule(%q) = false, want true", module)
		}
	}
}

// resolveWith runs the resolver for a fixture advisory/product and returns
// the affected result, failing the test on an unexpected error.
func resolveWith(t *testing.T, v domain.Vulnerability, tool GoTool, prod domain.ProductSnapshot) domain.AffectedResult {
	t.Helper()
	res, _, err := GoResolver{Tool: tool}.Resolve(context.Background(), v, prod)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	return res
}

// assertNoEmptyModuleNames is the regression guard for the empty-name
// contract: an entry with no module identity is explicit unresolved subject
// data, never a module named "". An empty name must not appear in any
// result module-name field, and SelectedModule must not claim a selection
// when no linked named module exists.
func assertNoEmptyModuleNames(t *testing.T, res domain.AffectedResult) {
	t.Helper()
	lists := []struct {
		name  string
		names []string
	}{
		{"SelectedModules", res.SelectedModules},
		{"CheckedModules", res.CheckedModules},
		{"PendingModules", res.PendingModules},
		{"UnresolvedModules", res.UnresolvedModules},
		{"VersionAffectedModules", res.VersionAffectedModules},
	}
	for _, l := range lists {
		for i, name := range l.names {
			if name == "" {
				t.Fatalf("%s[%d] is an empty module name: %v", l.name, i, l.names)
			}
		}
	}
	if len(res.SelectedModules) > 0 && res.SelectedModule != res.SelectedModules[0] {
		t.Fatalf("SelectedModule=%q does not name the first linked module %v",
			res.SelectedModule, res.SelectedModules)
	}
}

// The lost grpc/amqp shape: a multi-entry advisory carries a stdlib entry
// whose release toolchain is unknown next to a named third-party module
// whose exact version the module graph resolves. The named entry must
// resolve independently of the unknown alternative.
func TestNamedModuleResolvesWithoutReleaseToolchain(t *testing.T) {
	v := domain.Vulnerability{
		ID:     "GO-0000-0200",
		Module: "example.com/dep",
		AffectedModules: []domain.AffectedModule{
			{
				Module:           "stdlib",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "1.21.3"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "net/http"}},
			},
			{
				Module:           "example.com/dep",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "1.2.0"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "example.com/dep/vuln"}},
			},
		},
	}
	mods := `{"Path":"example.com/product","Main":true}
{"Path":"example.com/dep","Version":"v1.0.0"}`
	pkgs := `{"ImportPath":"example.com/product","Name":"main","Deps":["net/http","example.com/dep/vuln"]}
{"ImportPath":"net/http","Deps":[]}
{"ImportPath":"example.com/dep/vuln","Module":{"Path":"example.com/dep","Version":"v1.0.0"},"Deps":[]}`
	// No release toolchain/evidence: the stdlib entry is genuinely unknown.
	res := resolveWith(t, v, fakeTool{modules: []byte(mods), packages: []byte(pkgs)}, product())
	if res.ModulePresent != domain.ClaimTrue ||
		res.VersionAffected != domain.ClaimTrue ||
		res.PackagePresent != domain.ClaimTrue ||
		res.BuildRelevant != domain.ClaimTrue {
		t.Fatalf("named entry did not resolve independently: %+v", res)
	}
	if res.SelectedModule != "example.com/dep" || res.ResolvedVersion != "v1.0.0" {
		t.Fatalf("version pair = %s@%s, want example.com/dep@v1.0.0",
			res.SelectedModule, res.ResolvedVersion)
	}
	if !slices.Contains(res.UnresolvedModules, "stdlib") {
		t.Fatalf("stdlib entry must stay unresolved: %v", res.UnresolvedModules)
	}
	assertNoEmptyModuleNames(t, res)
}

// A malformed duplicate entry sharing the named module's subject must not
// re-claim package ownership: the named module owns the subject and its
// version verdict stays TRUE.
func TestEmptyDuplicateEntryDoesNotPoisonNamedModule(t *testing.T) {
	v := domain.Vulnerability{
		ID:     "GO-0000-0201",
		Module: "example.com/dep",
		AffectedModules: []domain.AffectedModule{
			{
				Module:           "example.com/dep",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "1.2.0"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "example.com/dep/vuln"}},
			},
			{
				// Duplicate subject with no module owner: parser-level
				// normalization merges this into the named entry, and the
				// resolver must not let the residual entry own the path.
				Unnamed:          true,
				AffectedVersions: []domain.VersionRange{{Introduced: "0"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "example.com/dep/vuln"}},
			},
		},
	}
	mods := `{"Path":"example.com/dep","Version":"v1.0.0"}`
	pkgs := `{"ImportPath":"example.com/product","Name":"main","Deps":["example.com/dep/vuln"]}
{"ImportPath":"example.com/dep/vuln","Module":{"Path":"example.com/dep","Version":"v1.0.0"},"Deps":[]}`
	res := resolveWith(t, v, fakeTool{modules: []byte(mods), packages: []byte(pkgs)}, product())
	if res.VersionAffected != domain.ClaimTrue || res.PackagePresent != domain.ClaimTrue {
		t.Fatalf("duplicate unnamed entry poisoned the named module: %+v", res)
	}
	if res.SelectedModule != "example.com/dep" || res.ResolvedVersion != "v1.0.0" {
		t.Fatalf("version pair = %s@%s, want example.com/dep@v1.0.0",
			res.SelectedModule, res.ResolvedVersion)
	}
	if len(res.SelectedModules) != 1 || res.SelectedModules[0] != "example.com/dep" {
		t.Fatalf("SelectedModules=%v, want only the named owner", res.SelectedModules)
	}
	if len(res.CheckedPackages) != 1 || res.CheckedPackages[0] != "example.com/dep/vuln" {
		t.Fatalf("CheckedPackages=%v, want each subject probed once", res.CheckedPackages)
	}
	assertNoEmptyModuleNames(t, res)
}

// A linked subject with no module owner cannot have its version resolved:
// the case stays non-admitting even when another entry's version lies in
// its affected range, and the unnamed entry's empty name never appears in
// a result field.
func TestEmptyUniqueLinkedEntryRemainsUnknown(t *testing.T) {
	v := domain.Vulnerability{
		ID:     "GO-0000-0202",
		Module: "example.com/dep",
		AffectedModules: []domain.AffectedModule{
			{
				Module:           "example.com/dep",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "1.2.0"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "example.com/dep/vuln"}},
			},
			{
				Unnamed:          true,
				AffectedVersions: []domain.VersionRange{{Introduced: "0"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "example.com/other/vuln"}},
			},
		},
	}
	mods := `{"Path":"example.com/dep","Version":"v1.0.0"}`
	pkgs := `{"ImportPath":"example.com/product","Name":"main","Deps":["example.com/other/vuln"]}
{"ImportPath":"example.com/other/vuln","Deps":[]}`
	res := resolveWith(t, v, fakeTool{modules: []byte(mods), packages: []byte(pkgs)}, product())
	if res.VersionAffected != domain.ClaimUnknown {
		t.Fatalf("linked unnamed subject must keep the case non-admitting: VersionAffected=%s", res.VersionAffected)
	}
	if res.PackagePresent != domain.ClaimTrue {
		t.Fatalf("linked unnamed subject grounds presence: %s", res.PackagePresent)
	}
	if res.ResolvedVersion != "" {
		t.Fatalf("ResolvedVersion=%q must not carry the unrelated named entry's version", res.ResolvedVersion)
	}
	if res.SelectedModule != "" || len(res.SelectedModules) != 0 {
		t.Fatalf("no named module is linked: SelectedModule=%q SelectedModules=%v",
			res.SelectedModule, res.SelectedModules)
	}
	if len(res.PendingModules) != 0 || len(res.UnresolvedModules) != 0 {
		t.Fatalf("unnamed entry must not enter module-name lists: pending=%v unresolved=%v",
			res.PendingModules, res.UnresolvedModules)
	}
	assertNoEmptyModuleNames(t, res)
}

// An unnamed entry whose subjects are not linked is unresolved data, not a
// blocker: the named module resolves exactly as if the stray entry were
// absent.
func TestEmptyUniqueUnlinkedEntryDoesNotPoisonNamedModule(t *testing.T) {
	v := domain.Vulnerability{
		ID:     "GO-0000-0203",
		Module: "example.com/dep",
		AffectedModules: []domain.AffectedModule{
			{
				Module:           "example.com/dep",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "1.2.0"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "example.com/dep/vuln"}},
			},
			{
				Unnamed:          true,
				AffectedVersions: []domain.VersionRange{{Introduced: "0"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "example.com/other/vuln"}},
			},
		},
	}
	mods := `{"Path":"example.com/dep","Version":"v1.0.0"}`
	pkgs := `{"ImportPath":"example.com/product","Name":"main","Deps":["example.com/dep/vuln"]}
{"ImportPath":"example.com/dep/vuln","Module":{"Path":"example.com/dep","Version":"v1.0.0"},"Deps":[]}`
	res := resolveWith(t, v, fakeTool{modules: []byte(mods), packages: []byte(pkgs)}, product())
	if res.VersionAffected != domain.ClaimTrue || res.PackagePresent != domain.ClaimTrue {
		t.Fatalf("unlinked unnamed entry poisoned the named module: %+v", res)
	}
	if res.SelectedModule != "example.com/dep" || res.ResolvedVersion != "v1.0.0" {
		t.Fatalf("version pair = %s@%s, want example.com/dep@v1.0.0",
			res.SelectedModule, res.ResolvedVersion)
	}
	if len(res.SelectedModules) != 1 || res.SelectedModules[0] != "example.com/dep" {
		t.Fatalf("SelectedModules=%v", res.SelectedModules)
	}
	if len(res.PendingModules) != 0 || len(res.UnresolvedModules) != 0 {
		t.Fatalf("unlinked unnamed entry must stay out of module-name lists: pending=%v unresolved=%v",
			res.PendingModules, res.UnresolvedModules)
	}
	assertNoEmptyModuleNames(t, res)

	// A linked but fixed named module stays a deterministic negative when
	// the forced probe's absent residue is an admitted measurement: the
	// complete inventory under the scoped target proves the unnamed
	// subject unlinked.
	fixedMods := `{"Path":"example.com/dep","Version":"v1.3.0"}`
	res = resolveWith(t, v, fakeTool{modules: []byte(fixedMods), packages: []byte(pkgs)}, scopedProduct())
	if res.VersionAffected != domain.ClaimFalse {
		t.Fatalf("fixed named module + unlinked unnamed entry must stay FALSE: %s", res.VersionAffected)
	}
	if res.ResolvedVersion != "v1.3.0" {
		t.Fatalf("ResolvedVersion=%q, want the settled named version", res.ResolvedVersion)
	}
	// Only the Unnamed entry's subject was probed; its absence is
	// unresolved data, so no component negative may rest on it.
	if res.PackagePresent != domain.ClaimUnknown || res.BuildRelevant != domain.ClaimUnknown {
		t.Fatalf("unnamed-only absence must not ground a component negative: package=%s build=%s",
			res.PackagePresent, res.BuildRelevant)
	}
	// Under a host default the same version closure depends on that
	// unadmitted absence: the axis stays UNKNOWN instead of bypassing
	// target/inventory admission.
	res = resolveWith(t, v, fakeTool{modules: []byte(fixedMods), packages: []byte(pkgs)}, product())
	if res.VersionAffected != domain.ClaimUnknown {
		t.Fatalf("host-default residual closure bypassed admission: %s", res.VersionAffected)
	}
	if !hasLimitation(res.Limitations, "version-unaffected conclusion withheld") {
		t.Fatalf("version-admission reason missing: %v", res.Limitations)
	}
	assertNoEmptyModuleNames(t, res)
}

// A linked stdlib entry without authoritative release evidence blocks only
// itself: its own version stays unknown (and keeps the result undecided
// when its code is the linked subject), while a confirmed named entry still
// pins the version pair when its package is linked.
func TestStdlibUnknownReleaseBlocksOnlyLinkedStdlibEntry(t *testing.T) {
	advisory := func(stdlibPkg string) domain.Vulnerability {
		return domain.Vulnerability{
			ID:     "GO-0000-0204",
			Module: "stdlib",
			AffectedModules: []domain.AffectedModule{
				{
					Module:           "stdlib",
					AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "1.21.3"}},
					AffectedPackages: []domain.AffectedPackage{{Path: stdlibPkg}},
				},
				{
					Module:           "example.com/dep",
					AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "1.2.0"}},
					AffectedPackages: []domain.AffectedPackage{{Path: "example.com/dep/vuln"}},
				},
			},
		}
	}
	mods := `{"Path":"example.com/product","Main":true}
{"Path":"example.com/dep","Version":"v1.0.0"}`

	t.Run("linked stdlib leaves the named entry confirmed", func(t *testing.T) {
		pkgs := `{"ImportPath":"example.com/product","Name":"main","Deps":["net/http","example.com/dep/vuln"]}
{"ImportPath":"net/http","Deps":[]}
{"ImportPath":"example.com/dep/vuln","Module":{"Path":"example.com/dep","Version":"v1.0.0"},"Deps":[]}`
		res := resolveWith(t, advisory("net/http"),
			fakeTool{modules: []byte(mods), packages: []byte(pkgs)}, product())
		if res.VersionAffected != domain.ClaimTrue {
			t.Fatalf("confirmed named entry must resolve: VersionAffected=%s", res.VersionAffected)
		}
		if res.SelectedModule != "example.com/dep" || res.ResolvedVersion != "v1.0.0" {
			t.Fatalf("version pair = %s@%s, want the confirmed named entry",
				res.SelectedModule, res.ResolvedVersion)
		}
		if !slices.Contains(res.PendingModules, "stdlib") ||
			!slices.Contains(res.UnresolvedModules, "stdlib") {
			t.Fatalf("linked stdlib entry must stay pending/unresolved: pending=%v unresolved=%v",
				res.PendingModules, res.UnresolvedModules)
		}
		assertNoEmptyModuleNames(t, res)
	})

	t.Run("linked stdlib alone keeps the case unknown", func(t *testing.T) {
		// The named entry is version-affected but its package is not
		// linked; only the stdlib entry's subject is. Its unknown release
		// version then leaves nothing to admit.
		pkgs := `{"ImportPath":"example.com/product","Name":"main","Deps":["net/http"]}
{"ImportPath":"net/http","Deps":[]}`
		res := resolveWith(t, advisory("net/http"),
			fakeTool{modules: []byte(mods), packages: []byte(pkgs)}, product())
		if res.VersionAffected != domain.ClaimUnknown {
			t.Fatalf("linked stdlib with unknown release must stay UNKNOWN: %s", res.VersionAffected)
		}
		if res.ResolvedVersion != "" {
			t.Fatalf("ResolvedVersion=%q must not carry the unlinked named entry's version", res.ResolvedVersion)
		}
		if !slices.Contains(res.PendingModules, "stdlib") {
			t.Fatalf("PendingModules=%v, want stdlib", res.PendingModules)
		}
		assertNoEmptyModuleNames(t, res)
	})
}

// Two linked named entries keep independent version facts: each lands in
// VersionAffectedModules, and the ResolvedVersion/SelectedModule pair
// describes the same (first linked) entry.
func TestTwoLinkedModulesKeepIndependentVersions(t *testing.T) {
	v := domain.Vulnerability{
		ID:     "GO-0000-0205",
		Module: "example.com/dep",
		AffectedModules: []domain.AffectedModule{
			{
				Module:           "example.com/dep",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "1.2.0"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "example.com/dep/vuln"}},
			},
			{
				Module:           "example.com/other",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "1.0.0"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "example.com/other/vuln"}},
			},
		},
	}
	mods := `{"Path":"example.com/dep","Version":"v1.0.0"}
{"Path":"example.com/other","Version":"v0.5.0"}`
	pkgs := `{"ImportPath":"example.com/product","Name":"main","Deps":["example.com/dep/vuln","example.com/other/vuln"]}
{"ImportPath":"example.com/dep/vuln","Module":{"Path":"example.com/dep","Version":"v1.0.0"},"Deps":[]}
{"ImportPath":"example.com/other/vuln","Module":{"Path":"example.com/other","Version":"v0.5.0"},"Deps":[]}`
	res := resolveWith(t, v, fakeTool{modules: []byte(mods), packages: []byte(pkgs)}, product())
	if res.VersionAffected != domain.ClaimTrue {
		t.Fatalf("both linked modules are affected: %s", res.VersionAffected)
	}
	for _, m := range []string{"example.com/dep", "example.com/other"} {
		if !slices.Contains(res.SelectedModules, m) {
			t.Fatalf("SelectedModules=%v, want %s", res.SelectedModules, m)
		}
		if !slices.Contains(res.VersionAffectedModules, m) {
			t.Fatalf("VersionAffectedModules=%v, want %s", res.VersionAffectedModules, m)
		}
	}
	if res.SelectedModule != "example.com/dep" || res.ResolvedVersion != "v1.0.0" {
		t.Fatalf("version pair = %s@%s, want example.com/dep@v1.0.0",
			res.SelectedModule, res.ResolvedVersion)
	}
	assertNoEmptyModuleNames(t, res)
}

// A named pending entry whose package is not linked is unresolved (named
// in UnresolvedModules) but must not block the confirmed linked module's
// TRUE verdict and version.
func TestPendingUnlinkedModuleDoesNotBlockConfirmedLinkedModule(t *testing.T) {
	v := domain.Vulnerability{
		ID:     "GO-0000-0206",
		Module: "example.com/dep",
		AffectedModules: []domain.AffectedModule{
			{
				Module:           "example.com/dep",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "1.2.0"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "example.com/dep/vuln"}},
			},
			{
				Module:           "example.com/other",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "2.0.0"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "example.com/other/vuln"}},
			},
		},
	}
	mods := `{"Path":"example.com/dep","Version":"v1.0.0"}
{"Path":"example.com/other"}` // present, no version — pending
	pkgs := `{"ImportPath":"example.com/product","Name":"main","Deps":["example.com/dep/vuln"]}
{"ImportPath":"example.com/dep/vuln","Module":{"Path":"example.com/dep","Version":"v1.0.0"},"Deps":[]}`
	res := resolveWith(t, v, fakeTool{modules: []byte(mods), packages: []byte(pkgs)}, product())
	if res.VersionAffected != domain.ClaimTrue {
		t.Fatalf("unlinked pending entry must not block the confirmed entry: %s", res.VersionAffected)
	}
	if res.SelectedModule != "example.com/dep" || res.ResolvedVersion != "v1.0.0" {
		t.Fatalf("version pair = %s@%s", res.SelectedModule, res.ResolvedVersion)
	}
	if len(res.PendingModules) != 0 {
		t.Fatalf("PendingModules=%v, want none (the pending entry is not linked)", res.PendingModules)
	}
	if !slices.Contains(res.UnresolvedModules, "example.com/other") {
		t.Fatalf("UnresolvedModules=%v, want the pending module", res.UnresolvedModules)
	}
	assertNoEmptyModuleNames(t, res)
}

// No result shape may report an empty module as "selected": when only an
// unnamed subject is linked there is no selected module, and when a named
// owner exists the unnamed entry never shadows it.
func TestAffectedResultNeverReportsEmptySelectedModule(t *testing.T) {
	t.Run("unnamed linked subject only", func(t *testing.T) {
		v := domain.Vulnerability{
			ID: "GO-0000-0207",
			AffectedModules: []domain.AffectedModule{{
				Unnamed:          true,
				AffectedVersions: []domain.VersionRange{{Introduced: "0"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "example.com/other/vuln"}},
			}},
		}
		mods := `{"Path":"example.com/product","Main":true}`
		pkgs := `{"ImportPath":"example.com/product","Name":"main","Deps":["example.com/other/vuln"]}
{"ImportPath":"example.com/other/vuln","Deps":[]}`
		res := resolveWith(t, v, fakeTool{modules: []byte(mods), packages: []byte(pkgs)}, product())
		if res.VersionAffected != domain.ClaimUnknown {
			t.Fatalf("unnamed-only advisory must stay non-admitting: %s", res.VersionAffected)
		}
		if res.ModulePresent != domain.ClaimTrue || res.PackagePresent != domain.ClaimTrue {
			t.Fatalf("linked unnamed subject must ground presence so version-unknown precedence holds: module=%s package=%s",
				res.ModulePresent, res.PackagePresent)
		}
		if res.SelectedModule != "" || len(res.SelectedModules) != 0 {
			t.Fatalf("no named module exists to select: SelectedModule=%q SelectedModules=%v",
				res.SelectedModule, res.SelectedModules)
		}
		if len(res.CheckedModules) != 0 {
			t.Fatalf("CheckedModules=%v, want none", res.CheckedModules)
		}
		assertNoEmptyModuleNames(t, res)
	})

	t.Run("named owner keeps selection", func(t *testing.T) {
		v := domain.Vulnerability{
			ID:     "GO-0000-0208",
			Module: "example.com/dep",
			AffectedModules: []domain.AffectedModule{
				{
					Module:           "example.com/dep",
					AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "1.2.0"}},
					AffectedPackages: []domain.AffectedPackage{{Path: "example.com/dep/vuln"}},
				},
				{
					Unnamed:          true,
					AffectedVersions: []domain.VersionRange{{Introduced: "0"}},
					AffectedPackages: []domain.AffectedPackage{
						{Path: "example.com/dep/vuln"},
						{Path: "example.com/other/vuln"},
					},
				},
			},
		}
		mods := `{"Path":"example.com/dep","Version":"v1.0.0"}`
		pkgs := `{"ImportPath":"example.com/product","Name":"main","Deps":["example.com/dep/vuln"]}
{"ImportPath":"example.com/dep/vuln","Module":{"Path":"example.com/dep","Version":"v1.0.0"},"Deps":[]}`
		res := resolveWith(t, v, fakeTool{modules: []byte(mods), packages: []byte(pkgs)}, product())
		if res.VersionAffected != domain.ClaimTrue {
			t.Fatalf("named owner must keep the verdict: %s", res.VersionAffected)
		}
		if res.SelectedModule != "example.com/dep" || res.ResolvedVersion != "v1.0.0" {
			t.Fatalf("version pair = %s@%s, want example.com/dep@v1.0.0",
				res.SelectedModule, res.ResolvedVersion)
		}
		assertNoEmptyModuleNames(t, res)
	})
}

// A named entry that is merely absent from the module graph has no
// resolved version. It must not let a forced probe over an unlinked unnamed
// subject close the version axis: with no settled named version, the result
// stays UNKNOWN end to end.
func TestAbsentNamedModuleWithUnlinkedUnnamedEntryStaysUnknown(t *testing.T) {
	v := domain.Vulnerability{
		ID:     "GO-0000-0209",
		Module: "example.com/dep",
		AffectedModules: []domain.AffectedModule{
			{
				Module:           "example.com/dep",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "1.2.0"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "example.com/dep/vuln"}},
			},
			{
				Unnamed:          true,
				AffectedVersions: []domain.VersionRange{{Introduced: "0"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "example.com/other/vuln"}},
			},
		},
	}
	// The named module does not resolve against the graph at all.
	mods := `{"Path":"example.com/product","Main":true}`
	pkgs := `{"ImportPath":"example.com/product","Name":"main","Deps":[]}`
	res := resolveWith(t, v, fakeTool{modules: []byte(mods), packages: []byte(pkgs)}, product())
	if res.ModulePresent != domain.ClaimUnknown {
		t.Fatalf("absent named module must not become a negative: ModulePresent=%s", res.ModulePresent)
	}
	if res.VersionAffected != domain.ClaimUnknown {
		t.Fatalf("no named version was resolved: VersionAffected=%s, want UNKNOWN", res.VersionAffected)
	}
	if res.ResolvedVersion != "" {
		t.Fatalf("ResolvedVersion=%q, want empty", res.ResolvedVersion)
	}
	if res.SelectedModule != "" || len(res.SelectedModules) != 0 {
		t.Fatalf("nothing may be selected: SelectedModule=%q SelectedModules=%v",
			res.SelectedModule, res.SelectedModules)
	}
	assertNoEmptyModuleNames(t, res)
}

// fullRecordScope binds id to a complete census of the given Go modules: every
// original entry is represented, so AllowsNegativeClosure accepts it. The
// digest is a fixed, well-formed sha256 because these tests assert structural
// authority, not document bytes.
func fullRecordScope(id string, modules ...string) *domain.AdvisoryScope {
	entries := make([]domain.RecordEntry, len(modules))
	refs := make([]int, len(modules))
	for i, module := range modules {
		entries[i] = domain.RecordEntry{Index: i, Ecosystem: "Go", Module: module}
		refs[i] = i
	}
	return &domain.AdvisoryScope{
		RequestedID: id, ResolvedID: id,
		Kind: domain.ScopeAdvisoryEntries, Coverage: domain.CoverageComplete,
		RecordExtent: domain.RecordExtentFullRecord,
		RecordInventory: &domain.RecordInventory{
			AdvisoryID:         id,
			DocumentDigest:     "sha256:" + strings.Repeat("ab", 32),
			AffectedEntryCount: len(modules),
			Entries:            entries,
			RepresentedRefs:    refs,
		},
	}
}

func TestResolverScopePreservedOnEarlyReturns(t *testing.T) {
	cveScope := &domain.AdvisoryScope{RequestedID: "CVE-2026-1234", ResolvedID: testVuln.ID, Kind: domain.ScopeCVE, Coverage: domain.CoverageKnownOnly, Basis: "alias record only"}
	fullScope := fullRecordScope(testVuln.ID, "example.com/dep", "example.com/second")
	for _, questScope := range []struct {
		name    string
		scope   *domain.AdvisoryScope
		closing bool
	}{
		{"cve known-only", cveScope, false},
		{"full record", fullScope, true},
	} {
		v := testVuln
		v.Scope = questScope.scope
		for _, tt := range []struct {
			name            string
			tool            fakeTool
			ticket          *domain.TicketClaims
			module, version domain.ClaimResult
			blocked         bool
		}{
			{name: "module absent", tool: fakeTool{modules: []byte(`{"Path":"example.com/product","Main":true}`)}, module: domain.ClaimFalse, version: domain.ClaimFalse},
			{name: "all versions fixed", tool: fakeTool{modules: []byte(`{"Path":"example.com/dep","Version":"v1.2.0"}`)}, module: domain.ClaimTrue, version: domain.ClaimFalse},
			{name: "module list failure", tool: fakeTool{modErr: errors.New("unavailable")}, module: domain.ClaimUnknown, version: domain.ClaimUnknown},
			{name: "ticket version block", tool: fakeTool{modules: []byte(`{"Path":"example.com/dep","Version":"v1.2.0"}`)}, ticket: &domain.TicketClaims{Package: "example.com/dep", PackageVersion: "v1.0.0"}, module: domain.ClaimTrue, version: domain.ClaimUnknown, blocked: true},
		} {
			t.Run(questScope.name+"/"+tt.name, func(t *testing.T) {
				res, _, err := (GoResolver{Tool: tt.tool, Ticket: tt.ticket}).Resolve(context.Background(), v, product())
				if err != nil {
					t.Fatal(err)
				}
				if res.Scope != questScope.scope {
					t.Fatalf("scope lost: %+v", res.Scope)
				}
				if got := res.Scope.AllowsNegativeClosure(); got != questScope.closing {
					t.Fatalf("closure decision changed to %t, want %t: %+v", got, questScope.closing, res.Scope)
				}
				// No early return may derive or narrow the census from the
				// modules it happened to check.
				if inv, want := res.Scope.RecordInventory, questScope.scope.RecordInventory; want != nil {
					if inv == nil || !slices.Equal(inv.Entries, want.Entries) ||
						!slices.Equal(inv.RepresentedRefs, want.RepresentedRefs) ||
						!slices.Equal(inv.OmittedRefs, want.OmittedRefs) ||
						inv.AdvisoryID != want.AdvisoryID || inv.DocumentDigest != want.DocumentDigest {
						t.Fatalf("census changed by resolution: got %+v, want %+v", inv, want)
					}
				}
				if res.ModulePresent != tt.module || res.VersionAffected != tt.version || res.VersionAxisBlocked != tt.blocked {
					t.Fatalf("facts changed: %+v", res)
				}
			})
		}
	}
}

func TestMultiModuleScopeAggregation(t *testing.T) {
	scope := fullRecordScope("GO-2026-1234", "example.com/a", "example.com/b")
	wantInventory := &domain.RecordInventory{
		AdvisoryID: "GO-2026-1234", DocumentDigest: scope.RecordInventory.DocumentDigest,
		AffectedEntryCount: 2,
		Entries: []domain.RecordEntry{
			{Index: 0, Ecosystem: "Go", Module: "example.com/a"},
			{Index: 1, Ecosystem: "Go", Module: "example.com/b"},
		},
		RepresentedRefs: []int{0, 1},
	}
	v := domain.Vulnerability{ID: scope.ResolvedID, Scope: scope, AffectedModules: []domain.AffectedModule{
		{Module: "example.com/a", AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "1.2.0"}}, AffectedPackages: []domain.AffectedPackage{{Path: "example.com/a/vuln"}}},
		{Module: "example.com/b", AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "1.2.0"}}, AffectedPackages: []domain.AffectedPackage{{Path: "example.com/b/vuln"}}},
	}}
	for _, tt := range []struct {
		name, b           string
		linked            bool
		want              domain.ClaimResult
		selected, pending bool
	}{
		{"fixed plus affected linked", `,"Version":"v1.0.0"`, true, domain.ClaimTrue, true, false},
		{"fixed plus pending linked", "", true, domain.ClaimUnknown, true, true},
		{"both fixed", `,"Version":"v1.2.0"`, true, domain.ClaimFalse, false, false},
		{"affected absent from selected is not fixed", `,"Version":"v1.0.0"`, false, domain.ClaimTrue, false, false},
		{"pending absent from selected is unresolved", "", false, domain.ClaimUnknown, false, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mods := `{"Path":"example.com/a","Version":"v1.2.0"}` + "\n" + `{"Path":"example.com/b"` + tt.b + `}`
			pkgs := `{"ImportPath":"example.com/product"}`
			if tt.linked {
				pkgs += "\n" + `{"ImportPath":"example.com/b/vuln"}`
			}
			res, _, err := (GoResolver{Tool: fakeTool{modules: []byte(mods), packages: []byte(pkgs)}}).Resolve(context.Background(), v, product())
			if err != nil {
				t.Fatal(err)
			}
			if res.Scope != scope || res.VersionAffected != tt.want || !slices.Equal(res.CheckedModules, []string{"example.com/a", "example.com/b"}) {
				t.Fatalf("aggregate=%+v", res)
			}
			// Aggregation unions selections; it must not shrink the record
			// census to the selected entries or lose closure authority.
			if inv := res.Scope.RecordInventory; inv == nil ||
				inv.AdvisoryID != wantInventory.AdvisoryID || inv.DocumentDigest != wantInventory.DocumentDigest ||
				inv.AffectedEntryCount != wantInventory.AffectedEntryCount ||
				!slices.Equal(inv.Entries, wantInventory.Entries) ||
				!slices.Equal(inv.RepresentedRefs, wantInventory.RepresentedRefs) ||
				len(inv.OmittedRefs) != 0 {
				t.Fatalf("census narrowed by aggregation: got %+v, want %+v", inv, wantInventory)
			}
			if !res.Scope.AllowsNegativeClosure() {
				t.Fatalf("closure authority lost: %+v", res.Scope)
			}
			if slices.Contains(res.SelectedModules, "example.com/b") != tt.selected || slices.Contains(res.PendingModules, "example.com/b") != tt.pending {
				t.Fatalf("selection=%+v", res)
			}
			if tt.b == "" && !slices.Contains(res.UnresolvedModules, "example.com/b") {
				t.Fatalf("pending entry treated as fixed: %+v", res)
			}
			if tt.want == domain.ClaimTrue && !slices.Contains(res.VersionAffectedModules, "example.com/b") {
				t.Fatalf("version membership lost: %+v", res)
			}
		})
	}
}

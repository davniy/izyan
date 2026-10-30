package goanalysis

import (
	"context"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
)

// scopeOf builds the unreachability scope for a testdata fixture.
func scopeOf(t *testing.T, name string) *unreachabilityScope {
	t.Helper()
	ix := fixture(t, name)
	s, err := ix.buildUnreachabilityScope(context.Background())
	if err != nil {
		t.Fatalf("buildUnreachabilityScope: %v", err)
	}
	return s
}

func fnState(s *unreachabilityScope, pkg, sym string) reachabilityState {
	st, ok := s.ProductFunctions[functionKey{Package: pkg, Symbol: sym}]
	if !ok {
		return reachUnknown
	}
	return st
}

// TestScopeShippingRootsNarrowerThanLoaded: the shipping closure is a
// strict subset of the loaded roots — a package nobody imports must not
// be swept into the reachable set.
func TestScopeShippingRootsNarrowerThanLoaded(t *testing.T) {
	s := scopeOf(t, "scopeprod")
	main := s.packageState("example.com/scopeprod")
	if main != reachLive {
		t.Fatalf("main package must be LIVE, got %s", main)
	}
	if got := s.packageState("example.com/scopeprod/util"); got != reachDead {
		t.Fatalf("unlinked util package must be DEAD, got %s", got)
	}
	if len(s.ProductPackages) < 4 {
		t.Fatalf("every product package (incl. unlinked) must be classified: %v", s.ProductPackages)
	}
}

// TestScopeMainTransitiveImports: packages reachable only through a
// transitive product import still land inside the closure.
func TestScopeMainTransitiveImports(t *testing.T) {
	s := scopeOf(t, "scopeprod")
	if got := s.packageState("example.com/scopeprod/lib"); got != reachLive {
		t.Fatalf("directly imported lib must be LIVE, got %s", got)
	}
	if got := s.packageState("example.com/scopeprod/svc"); got != reachLive {
		t.Fatalf("transitively imported svc must be LIVE, got %s", got)
	}
}

// TestScopeInitLinkedAndUnlinked: init of a linked package is a live
// root; init of an unlinked package is dead like the package itself.
func TestScopeInitLinkedAndUnlinked(t *testing.T) {
	s := scopeOf(t, "scopeprod")
	if got := fnState(s, "example.com/scopeprod/lib", "init"); got != reachLive {
		t.Fatalf("linked package init must be LIVE, got %s", got)
	}
	site := domain.CallSite{Package: "example.com/scopeprod/util", Function: "init"}
	if got := s.classifySite(site); got != reachDead {
		t.Fatalf("unlinked package init must classify DEAD, got %s", got)
	}
	if got := s.packageState("example.com/scopeprod/util"); got != reachDead {
		t.Fatalf("util must be DEAD, got %s", got)
	}
}

// TestScopeLibraryOnlyNeverDead: without a main package or confirmed
// entrypoint no package may be reported DEAD — the snapshot's deployment
// shape is unknowable.
func TestScopeLibraryOnlyNeverDead(t *testing.T) {
	s := scopeOf(t, "scopelib")
	for p, st := range s.ProductPackages {
		if st == reachDead {
			t.Fatalf("library-only snapshot must yield no DEAD package: %s=%s", p, st)
		}
		if st != reachUnknown {
			t.Fatalf("library-only package must be UNKNOWN: %s=%s", p, st)
		}
	}
	if s.ProductGraphComplete {
		t.Fatal("library-only snapshot cannot claim a complete shipping closure")
	}
}

// TestScopeDeadUnexportedHelper: a never-called, never-materialized
// unexported function inside a linked package is provably dead.
func TestScopeDeadUnexportedHelper(t *testing.T) {
	s := scopeOf(t, "scopeprod")
	for _, fn := range []struct{ pkg, sym string }{
		{"example.com/scopeprod/lib", "deadHelper"},
		{"example.com/scopeprod/lib", "transitDead"},
		{"example.com/scopeprod/svc", "unused"},
	} {
		if got := fnState(s, fn.pkg, fn.sym); got != reachDead {
			t.Fatalf("%s.%s must be DEAD, got %s", fn.pkg, fn.sym, got)
		}
	}
}

// TestScopeLiveChain: resolved call edges propagate LIVE — main calls
// Serve, Serve calls helper and trigger.
func TestScopeLiveChain(t *testing.T) {
	s := scopeOf(t, "scopeprod")
	for _, fn := range []struct{ pkg, sym string }{
		{"example.com/scopeprod", "main"},
		{"example.com/scopeprod/lib", "Serve"},
		{"example.com/scopeprod/lib", "helper"},
		{"example.com/scopeprod/lib", "initReg"},
		{"example.com/scopeprod/svc", "Dispatch"},
	} {
		if got := fnState(s, fn.pkg, fn.sym); got != reachLive {
			t.Fatalf("%s.%s must be LIVE, got %s", fn.pkg, fn.sym, got)
		}
	}
}

// TestScopeUnresolvedIndirectEdge: a signature-compatible function
// behind an unresolved func-value call is UNKNOWN — an indirect edge
// can never prove its target dead.
func TestScopeUnresolvedIndirectEdge(t *testing.T) {
	s := scopeOf(t, "scopeprod")
	if got := fnState(s, "example.com/scopeprod/lib", "trigger"); got != reachLive {
		t.Fatalf("trigger must be LIVE (called from Serve), got %s", got)
	}
	if got := fnState(s, "example.com/scopeprod/lib", "indirect"); got != reachUnknown {
		t.Fatalf("signature-compatible indirect callee must be UNKNOWN, got %s", got)
	}
	if got := fnState(s, "example.com/scopeprod/lib", "pickFn"); got != reachLive {
		t.Fatalf("pickFn must be LIVE (directly called), got %s", got)
	}
}

// TestScopeInterfaceDispatch: an impl reachable only through interface
// dispatch is a may edge — UNKNOWN, not DEAD and not LIVE.
func TestScopeInterfaceDispatch(t *testing.T) {
	s := scopeOf(t, "scopeprod")
	if got := fnState(s, "example.com/scopeprod/svc", "impl.get"); got != reachUnknown {
		t.Fatalf("interface-dispatched impl must be UNKNOWN, got %s", got)
	}
}

// TestScopeExportedAPINotDead: exported product API functions in a
// linked package are conservative roots — unreferenced does not mean
// unreachable.
func TestScopeExportedAPINotDead(t *testing.T) {
	s := scopeOf(t, "scopeprod")
	if got := fnState(s, "example.com/scopeprod/lib", "OrphanAPI"); got == reachDead {
		t.Fatalf("exported product API must never be DEAD, got %s", got)
	}
}

// TestScopeSkippedUnlinkedDead: a skipped package outside the shipping
// closure with recovered edges is DEAD; one imported by a (skipped)
// shipping main stays reachable evidence.
func TestScopeSkippedUnlinkedDead(t *testing.T) {
	s := scopeOf(t, "scopeskipp")
	if got := s.packageState("example.com/scopeskipp/broken"); got == reachDead {
		t.Fatalf("broken package imported by shipping main must not be DEAD, got %s", got)
	}
	if got := s.packageState("example.com/scopeskipp/cmd/app"); got == reachDead {
		t.Fatalf("failed shipping main must not be DEAD, got %s", got)
	}
	if got := s.packageState("example.com/scopeskipp/loose"); got != reachDead {
		t.Fatalf("unlinked skipped package with recovered edges must be DEAD, got %s", got)
	}
	if got := s.packageState("example.com/scopeskipp/good"); got != reachLive {
		t.Fatalf("healthy main must be LIVE, got %s", got)
	}
}

// TestScopeUnscannedPackageUnknown: a skipped package whose package
// clause is still recoverable is provably a non-root; unreachable, it
// is DEAD even though its bodies failed to parse. The unreachable-only
// gaps inside it cannot reopen a closed scope.
func TestScopeUnscannedPackageUnknown(t *testing.T) {
	s := scopeOf(t, "scopeunscan")
	if got := s.packageState("example.com/scopeunscan/bad"); got != reachDead {
		t.Fatalf("unreachable skipped package with a recovered clause must be DEAD, got %s", got)
	}
	if got := s.packageState("example.com/scopeunscan/loose"); got != reachDead {
		t.Fatalf("unlinked parseable skipped package must be DEAD, got %s", got)
	}
	if got := s.packageState("example.com/scopeunscan"); got != reachLive {
		t.Fatalf("main must be LIVE, got %s", got)
	}
	if !s.ProductGraphComplete {
		t.Fatalf("dead-package gaps must not reopen the scope: %v", s.unknownReasons)
	}
}

// TestScopeClauselessPackageNeverDead: a package without a single
// recoverable package clause can hide a main declaration — it is never
// DEAD and keeps the entire scope open.
func TestScopeClauselessPackageNeverDead(t *testing.T) {
	s := scopeOf(t, "unscanprod")
	if s.ProductGraphComplete {
		t.Fatal("a package with no recoverable clause must keep the scope open")
	}
	if got := s.packageState("example.com/unscanprod/bad"); got != reachUnknown {
		t.Fatalf("the clauseless package must stay UNKNOWN, got %s", got)
	}
	for p, st := range s.ProductPackages {
		if st == reachDead {
			t.Fatalf("no package may be DEAD under an unknown root set: %s", p)
		}
	}
	found := false
	for _, r := range s.unknownReasons {
		if strings.Contains(r, "example.com/unscanprod/bad") {
			found = true
		}
	}
	if !found {
		t.Fatalf("unknown reasons must name the unverifiable package: %v", s.unknownReasons)
	}
}

// TestScopeHiddenMainClause: a directory the loader names "foo" while a
// sibling file declares package main still produces a shipping binary —
// the clause-level scan must root it, never discard it.
func TestScopeHiddenMainClause(t *testing.T) {
	s := scopeOf(t, "scopehiddenmain")
	if !s.ProductGraphComplete {
		t.Fatalf("scope must close once the hidden main is rooted: %v", s.unknownReasons)
	}
	if got := s.packageState("example.com/scopehiddenmain/hidden"); got != reachLive {
		t.Fatalf("a directory carrying a main clause is a shipping root: got %s", got)
	}
	found := false
	for _, r := range s.roots {
		if r == "example.com/scopehiddenmain/hidden" {
			found = true
		}
	}
	if !found {
		t.Fatalf("hidden main must be a scope root: %v", s.roots)
	}
}

// TestScopeClassifySite: the folded site verdict — a site in a dead
// package is DEAD without inspecting the function; a live package's
// dead function is DEAD; a known live function is LIVE.
func TestScopeClassifySite(t *testing.T) {
	s := scopeOf(t, "scopeprod")
	cases := []struct {
		name string
		site domain.CallSite
		want reachabilityState
	}{
		{"dead package function", domain.CallSite{Package: "example.com/scopeprod/util", Function: "helper"}, reachDead},
		{"dead package export", domain.CallSite{Package: "example.com/scopeprod/util", Function: "Orphan"}, reachDead},
		{"live package dead func", domain.CallSite{Package: "example.com/scopeprod/lib", Function: "deadHelper"}, reachDead},
		{"live package live func", domain.CallSite{Package: "example.com/scopeprod/lib", Function: "Serve"}, reachLive},
		{"bare method name", domain.CallSite{Package: "example.com/scopeprod/svc", Function: "get"}, reachUnknown},
		{"unresolved indirect", domain.CallSite{Package: "example.com/scopeprod/lib", Function: "indirect"}, reachUnknown},
		{"unknown package", domain.CallSite{Package: "example.com/elsewhere", Function: "X"}, reachUnknown},
		{"empty function name", domain.CallSite{Package: "example.com/scopeprod/lib"}, reachLive},
	}
	for _, tc := range cases {
		if got := s.classifySite(tc.site); got != tc.want {
			t.Fatalf("%s: classifySite=%s want %s", tc.name, got, tc.want)
		}
	}
}

// TestScopeDeterministic: identical inputs on fresh indexes produce
// identical verdict maps.
func TestScopeDeterministic(t *testing.T) {
	a := scopeOf(t, "scopeprod")
	b := scopeOf(t, "scopeprod")
	if len(a.ProductPackages) != len(b.ProductPackages) ||
		len(a.ProductFunctions) != len(b.ProductFunctions) {
		t.Fatalf("scope sizes differ: %d/%d vs %d/%d",
			len(a.ProductPackages), len(a.ProductFunctions),
			len(b.ProductPackages), len(b.ProductFunctions))
	}
	for p, st := range a.ProductPackages {
		if b.ProductPackages[p] != st {
			t.Fatalf("package %s state differs: %s vs %s", p, st, b.ProductPackages[p])
		}
	}
	for fn, st := range a.ProductFunctions {
		if b.ProductFunctions[fn] != st {
			t.Fatalf("function %v state differs: %s vs %s", fn, st, b.ProductFunctions[fn])
		}
	}
	if a.ProductGraphComplete != b.ProductGraphComplete {
		t.Fatal("ProductGraphComplete differs between runs")
	}
}

// TestScopeNoMainNoDeadFunctions: with no package-level reachability
// verdict the function map stays empty — nothing is ever marked DEAD.
func TestScopeNoMainNoDeadFunctions(t *testing.T) {
	s := scopeOf(t, "scopelib")
	for fn, st := range s.ProductFunctions {
		if st == reachDead {
			t.Fatalf("no function may be DEAD in a library-only scope: %v", fn)
		}
	}
	site := domain.CallSite{Package: "example.com/scopelib/liba", Function: "dead"}
	if got := s.classifySite(site); got == reachDead {
		t.Fatalf("site in library-only package must not be DEAD, got %s", got)
	}
}

// TestScopeFailClosedNeverDead: once completeness is revoked — by
// failClosed or by direct flag clears — no package, function or site
// may still classify as DEAD, including stale verdicts already written
// into the maps.
func TestScopeFailClosedNeverDead(t *testing.T) {
	s := scopeOf(t, "scopeprod")
	if s.packageState("example.com/scopeprod/util") != reachDead {
		t.Fatal("fixture precondition: util must be DEAD before reopening")
	}
	s.failClosed()
	if s.ProductGraphComplete {
		t.Fatal("failClosed must reopen the scope")
	}
	for p, st := range s.ProductPackages {
		if st == reachDead {
			t.Fatalf("package %s still DEAD after failClosed", p)
		}
	}
	for fn, st := range s.ProductFunctions {
		if st == reachDead {
			t.Fatalf("function %v still DEAD after failClosed", fn)
		}
	}
	// Stale published DEAD with a cleared flag: queries must withhold it.
	s.ProductPackages["example.com/scopeprod/util"] = reachDead
	s.ProductFunctions[functionKey{Package: "example.com/scopeprod/lib", Symbol: "deadHelper"}] = reachDead
	if got := s.packageState("example.com/scopeprod/util"); got == reachDead {
		t.Fatal("packageState must withhold DEAD while incomplete")
	}
	if got := s.classifySite(domain.CallSite{Package: "example.com/scopeprod/util", Function: "helper"}); got == reachDead {
		t.Fatal("classifySite must withhold DEAD while incomplete")
	}
	if got := s.functionState(domain.CallSite{Package: "example.com/scopeprod/lib", Function: "deadHelper"}); got == reachDead {
		t.Fatal("functionState must withhold DEAD while incomplete")
	}
}

// TestScopeIncompleteClosureNoDeadAnywhere: across every fixture whose
// closure is incomplete, neither map may hold a DEAD verdict and no
// site may classify DEAD — the invariant the filter relies on.
func TestScopeIncompleteClosureNoDeadAnywhere(t *testing.T) {
	for _, fx := range []string{"scopelib", "scopeskipp", "scopeunscan", "scopeprod", "unscanprod"} {
		s := scopeOf(t, fx)
		if s.ProductGraphComplete {
			continue
		}
		for p, st := range s.ProductPackages {
			if st == reachDead {
				t.Fatalf("%s: package %s DEAD under incomplete closure", fx, p)
			}
			for _, name := range []string{"x", "init", "helper", "Orphan"} {
				site := domain.CallSite{Package: p, Function: name}
				if got := s.classifySite(site); got == reachDead {
					t.Fatalf("%s: site %s.%s DEAD under incomplete closure", fx, p, name)
				}
			}
		}
		for fn, st := range s.ProductFunctions {
			if st == reachDead {
				t.Fatalf("%s: function %v DEAD under incomplete closure", fx, fn)
			}
		}
	}
}

// TestScopeModulelessPackageFailsClosed: a live package without a
// resolvable module path forces the whole closure open — the shared
// edge builder would silently drop its edges otherwise. Simulated by
// clearing Module on a built scope's live package list via a manual
// second-pass run is not reachable through the public loader, so this
// test exercises the guard directly: a package-level DEAD published
// before the gap is discovered must normalize through failClosed and
// classify UNKNOWN afterwards.
func TestScopeModulelessPackageFailsClosed(t *testing.T) {
	s := scopeOf(t, "scopeprod")
	// Emulate the late completeness discovery: the package pass already
	// published DEAD for util; a later check finds a live package with
	// no module path.
	s.failClosed()
	if got := s.packageState("example.com/scopeprod/util"); got != reachUnknown {
		t.Fatalf("post-reopen package state must be UNKNOWN, got %s", got)
	}
	site := domain.CallSite{Package: "example.com/scopeprod/util", Function: "helper"}
	if got := s.classifySite(site); got != reachUnknown {
		t.Fatalf("post-reopen site state must be UNKNOWN, got %s", got)
	}
}

package goanalysis

// budget_regression_test.go pins the bounded, fail-closed behavior of the
// expensive Product A scope work: one loaded product/importer closure per
// verification session, one shipping-scope construction per frozen snapshot,
// cancellation that never publishes a partial cache entry, snapshot drift
// (rewritten, added or removed source) that fails closed instead of
// rebuilding from the stale loaded AST, and budget truncation that stays
// open, named and non-admitting — including across a repeated verification
// and across concurrent cases sharing one index.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/davniy/izyan/internal/domain"
)

// buildCounts snapshots the construction counters, so a test asserts reuse
// (or a rebuild) as a delta on one index rather than an absolute count.
// Counters record only published constructions: an interrupted build is not
// a completed one.
type buildCounts struct {
	packageScopes, functionScopes int
	importerLoads, enumerations   int
	validations                   int
}

func countsOf(ix *Index) buildCounts {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	return buildCounts{
		packageScopes:  ix.scopePackageBuilds,
		functionScopes: ix.scopeFunctionBuilds,
		importerLoads:  ix.importerLoads,
		enumerations:   ix.closureEnumerations,
		validations:    ix.closureValidations,
	}
}

// cachedState reports whether any memoized scope/closure observation is
// published — the invariant a cancelled or failed call must not violate.
func cachedState(ix *Index) (packageScope, fullScope, importerGraph, closure bool) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	return ix.scopeCachePackage != nil, ix.scopeCacheFull != nil,
		ix.importers != nil, ix.closureCache != nil
}

// sameShippingScope reports whether two projections agree on the complete
// observable state — reuse must return the same answer, not merely skip
// work.
func sameShippingScope(a, b *ShippingScope) bool {
	if a.Complete != b.Complete || len(a.Roots) != len(b.Roots) ||
		len(a.PackageStates) != len(b.PackageStates) ||
		len(a.UnknownReasons) != len(b.UnknownReasons) {
		return false
	}
	for i := range a.Roots {
		if a.Roots[i] != b.Roots[i] {
			return false
		}
	}
	for i := range a.UnknownReasons {
		if a.UnknownReasons[i] != b.UnknownReasons[i] {
			return false
		}
	}
	for p, st := range a.PackageStates {
		if b.PackageStates[p] != st {
			return false
		}
	}
	return true
}

func hasBlockerContaining(blockers []string, want string) bool {
	for _, b := range blockers {
		if strings.Contains(b, want) {
			return true
		}
	}
	return false
}

// liveCtx is a cancellable, non-Background context: index queries remember
// the last query context so watchdog cancellation reaches subprocess loads,
// and a bare Background would inherit a previously cancelled one.
func liveCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	return ctx
}

// mutationFixture copies a testdata fixture into a temp directory so a test
// can rewrite its sources in place under one Index.
func mutationFixture(t *testing.T, name string) (dir string) {
	t.Helper()
	src, err := filepath.Abs(filepath.Join("..", "..", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), name)
	copyFixture(t, src, dst)
	return dst
}

func appendToFile(t *testing.T, path, text string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(text); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestShippingScopeReusedWithinOneSession: every subject, condition and
// tool call of one verification session shares one package graph and one
// function graph, and the importer census is loaded exactly once. The
// counters are the observable — a rebuild would move them regardless of how
// similar the answer looks — and a cache hit is a validation only, never a
// hidden graph walk.
func TestShippingScopeReusedWithinOneSession(t *testing.T) {
	ix := fixture(t, "scopetestprod")
	ctx := context.Background()

	first, err := ix.BuildShippingScope(ctx)
	if err != nil {
		t.Fatal(err)
	}
	base := countsOf(ix)
	if base.packageScopes != 1 || base.functionScopes != 1 {
		t.Fatalf("first build must construct both graphs once, got %+v", base)
	}

	// Repeated per-subject / per-condition calls: no new construction.
	for range 3 {
		again, err := ix.BuildShippingScope(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !sameShippingScope(first, again) {
			t.Fatalf("cached shipping scope diverged from the first build: %+v vs %+v", first, again)
		}
	}
	if _, err := ix.buildUnreachabilityScope(ctx); err != nil {
		t.Fatal(err)
	}
	firstClosure, err := ix.EnumerateImportClosure(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c1 := countsOf(ix)
	if c1.packageScopes != base.packageScopes || c1.functionScopes != base.functionScopes {
		t.Fatalf("repeated verification rebuilt the shipping scope: %+v -> %+v", base, c1)
	}
	if c1.importerLoads != 1 {
		t.Fatalf("the importer closure must load once per session, got %d loads", c1.importerLoads)
	}
	if c1.enumerations != 1 || c1.validations != 0 {
		t.Fatalf("the first enumeration must be a real walk: %+v", c1)
	}

	// A second enumeration is a validation-only cache hit: the graph walk is
	// skipped, so the enumeration counter does not move.
	second, err := ix.EnumerateImportClosure(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c2 := countsOf(ix)
	if c2.enumerations != c1.enumerations {
		t.Fatalf("a cache hit re-walked the closure: %+v -> %+v", c1, c2)
	}
	if c2.validations != c1.validations+1 {
		t.Fatalf("a cache hit must be recorded as a validation: %+v -> %+v", c1, c2)
	}
	if second.Hash != firstClosure.Hash {
		t.Fatalf("a validated hit must keep the same record: %q vs %q", firstClosure.Hash, second.Hash)
	}

	// Every caller receives an independent copy: mutating one result (or the
	// cached record via it) must not leak into the next hit.
	second.Importers["mutated/package"] = []string{"mutated"}
	second.PackageStates["mutated/package"] = "LIVE"
	third, err := ix.EnumerateImportClosure(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := third.Importers["mutated/package"]; ok {
		t.Fatal("a caller mutation reached the cached closure record")
	}
	if _, ok := third.PackageStates["mutated/package"]; ok {
		t.Fatal("a caller mutation reached the cached package states")
	}
	if c3 := countsOf(ix); c3.enumerations != c1.enumerations || c3.validations != c1.validations+2 {
		t.Fatalf("repeated hits must stay validations: %+v", c3)
	}
	if third.Hash == "" || third.Hash != closureHash(third) {
		t.Fatalf("the reused enumeration must keep a self-consistent hash: %q", third.Hash)
	}
}

// TestSnapshotRewriteFailsClosed: the shipping-scope cache is bound to the
// snapshot's content. Rewriting a product source under the same Index must
// fail closed — the loaded AST is stale, so rebuilding would publish a
// verdict set computed over bytes nobody analyzed.
func TestSnapshotRewriteFailsClosed(t *testing.T) {
	dir := mutationFixture(t, "scopetestprod")
	ix := &Index{Dir: dir}

	first, err := ix.BuildShippingScope(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !first.Complete {
		t.Fatalf("fixture is expected to close the shipping scope: %v", first.UnknownReasons)
	}
	steady := countsOf(ix)

	// Same path, same package inventory: only the bytes move.
	appendToFile(t, filepath.Join(dir, "svc", "svc.go"), "\n// mutated in place\n")

	if _, err := ix.BuildShippingScope(context.Background()); !errors.Is(err, ErrSnapshotMutated) {
		t.Fatalf("a rewritten source must fail the scope build, got %v", err)
	}
	if packageScope, fullScope, _, _ := cachedState(ix); packageScope || fullScope {
		t.Fatalf("drift must clear both cached halves: %v/%v", packageScope, fullScope)
	}
	if after := countsOf(ix); after.packageScopes != steady.packageScopes || after.functionScopes != steady.functionScopes {
		t.Fatalf("drift must not count a rebuild: %+v -> %+v", steady, after)
	}
	// The same Index can never publish a scope again from the stale AST.
	if _, err := ix.BuildShippingScope(context.Background()); !errors.Is(err, ErrSnapshotMutated) {
		t.Fatalf("drift is not transient; the second query must still fail closed, got %v", err)
	}
	if _, err := ix.EnumerateImportClosure(context.Background()); !errors.Is(err, ErrSnapshotMutated) {
		t.Fatalf("the closure enumeration must fail closed too, got %v", err)
	}
	res, err := ix.VerifyUnreachable(context.Background(), "example.com/dep", []domain.SymbolRef{vulnSym})
	if err != nil {
		t.Fatalf("verification must return an open result, not a hard error: %v", err)
	}
	if res.Complete {
		t.Fatalf("a mutated snapshot must never close a proof: %+v", res.Limitations)
	}
	if !hasBlockerContaining(res.Limitations, "mutated") {
		t.Fatalf("the drift must be named in the limitations: %v", res.Limitations)
	}

	// A fresh index re-loads the new bytes and recovers.
	fresh := &Index{Dir: dir}
	recovered, err := fresh.BuildShippingScope(context.Background())
	if err != nil {
		t.Fatalf("a fresh index must recover on the mutated snapshot: %v", err)
	}
	if !recovered.Complete {
		t.Fatalf("the recovered scope must close: %v", recovered.UnknownReasons)
	}
	closureFresh, err := fresh.EnumerateImportClosure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	closureBefore := func() ImportClosure {
		c, err := fixture(t, "scopetestprod").EnumerateImportClosure(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return c
	}()
	if closureFresh.SourceHashes["example.com/scopetestprod/svc"] == closureBefore.SourceHashes["example.com/scopetestprod/svc"] {
		t.Fatal("the recovered snapshot must hash the new bytes")
	}
}

// TestSnapshotAddedFileFailsClosed: the load-time file lists cannot see a
// file added afterwards. The directory inventory must move the fingerprint
// and the query must fail closed instead of reusing a stale COMPLETE scope.
func TestSnapshotAddedFileFailsClosed(t *testing.T) {
	dir := mutationFixture(t, "scopetestprod")
	ix := &Index{Dir: dir}

	if _, err := ix.BuildShippingScope(context.Background()); err != nil {
		t.Fatal(err)
	}
	steady := countsOf(ix)

	// A new build-selected Go file in a linked package: it is absent from the
	// loaded AST and from the load-time file list.
	writeFile(t, filepath.Join(dir, "svc", "added.go"),
		"package svc\n\n// Added after the load: a build-selected call site the stale\n// AST cannot see.\nfunc Added() {}\n")

	if _, err := ix.BuildShippingScope(context.Background()); !errors.Is(err, ErrSnapshotMutated) {
		t.Fatalf("an added source file must fail the scope build, got %v", err)
	}
	if packageScope, fullScope, _, _ := cachedState(ix); packageScope || fullScope {
		t.Fatalf("inventory drift must clear both cached halves: %v/%v", packageScope, fullScope)
	}
	if after := countsOf(ix); after.packageScopes != steady.packageScopes {
		t.Fatalf("inventory drift must not count a rebuild: %+v -> %+v", steady, after)
	}
	// A fresh index sees the new file and recovers.
	fresh := &Index{Dir: dir}
	scope, err := fresh.BuildShippingScope(context.Background())
	if err != nil {
		t.Fatalf("a fresh index must load the added file: %v", err)
	}
	if scope.PackageState("example.com/scopetestprod/svc") != ReachabilityLive {
		t.Fatalf("the linked package must stay LIVE after the reload: %+v", scope.PackageStates)
	}
}

// TestMemberSourceDriftFailsClosedClosure: the closure record is only valid
// while the dependency sources and member directories it enumerated are
// unchanged. A rewrite that adds a graph-relevant edge (a plugin import) must
// fail closed rather than be rebuilt from the stale census.
func TestMemberSourceDriftFailsClosedClosure(t *testing.T) {
	const vend = "example.com/vend/vendlib"
	dir := mutationFixture(t, "scopevendorprod")
	ix := &Index{Dir: dir}
	ctx := context.Background()

	first, err := ix.EnumerateImportClosure(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Complete || !hasStr(first.Packages, vend) {
		t.Fatalf("vendored fixture must enumerate completely with the member: %+v", first)
	}
	steady := countsOf(ix)
	second, err := ix.EnumerateImportClosure(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if second.Hash != first.Hash {
		t.Fatalf("an unchanged snapshot must be a validation hit: %q vs %q", first.Hash, second.Hash)
	}
	if c := countsOf(ix); c.enumerations != steady.enumerations || c.validations != steady.validations+1 {
		t.Fatalf("the hit must not re-walk the closure: %+v -> %+v", steady, c)
	}

	vendFile := filepath.Join(dir, "vendor", "example.com", "vend", "vendlib", "vendlib.go")
	// A graph-relevant edge the stale census cannot see: plugin loading.
	writeFile(t, vendFile, "package vendlib\n\nimport \"plugin\"\n\nvar _ = plugin.Open\n\nfunc V() int { return 7 }\n")

	if _, err := ix.EnumerateImportClosure(ctx); !errors.Is(err, ErrSnapshotMutated) {
		t.Fatalf("a rewritten dependency member must fail closed, got %v", err)
	}
	if _, _, _, closure := cachedState(ix); closure {
		t.Fatal("drift must clear the cached closure record")
	}
	if c := countsOf(ix); c.enumerations != steady.enumerations {
		t.Fatalf("drift must not rebuild and count an enumeration: %+v -> %+v", steady, c)
	}

	// A fresh index re-censuses and sees the new edge.
	fresh := &Index{Dir: dir}
	recovered, err := fresh.EnumerateImportClosure(ctx)
	if err != nil {
		t.Fatalf("a fresh index must recover: %v", err)
	}
	found := false
	for _, m := range recovered.EdgeMarkers {
		if m.Package == vend && m.Kind == "plugin" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the reloaded closure must record the added plugin edge: %+v", recovered.EdgeMarkers)
	}
}

// TestMemberAddedFileFailsClosedClosure: a Go file added to a member package
// directory after the census is invisible to the load-time file list; the
// member directory inventory must fail the query closed.
func TestMemberAddedFileFailsClosedClosure(t *testing.T) {
	dir := mutationFixture(t, "scopevendorprod")
	ix := &Index{Dir: dir}
	ctx := context.Background()
	if _, err := ix.EnumerateImportClosure(ctx); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "vendor", "example.com", "vend", "vendlib", "extra.go"),
		"package vendlib\n\nfunc Extra() {}\n")
	if _, err := ix.EnumerateImportClosure(ctx); !errors.Is(err, ErrSnapshotMutated) {
		t.Fatalf("an added member file must fail closed, got %v", err)
	}
	// The fresh index selects the new file and enumerates it.
	fresh := &Index{Dir: dir}
	recovered, err := fresh.EnumerateImportClosure(ctx)
	if err != nil {
		t.Fatalf("a fresh index must recover: %v", err)
	}
	if recovered.SourceHashes["example.com/vend/vendlib"] == "" {
		t.Fatal("the member must be hashed after the reload")
	}
}

// TestCancellationDuringClosureWork: cancellation raised *during* real work —
// after the census load, during metadata assembly, mid package/function
// graph construction, and after the last member file read — must fail the
// call, publish no cache entry and not count the interrupted work as a
// completed construction. The next healthy call rebuilds exactly once.
func TestCancellationDuringClosureWork(t *testing.T) {
	t.Run("importer load", func(t *testing.T) {
		ix := fixture(t, "scopetestprod")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var once sync.Once
		importerLoadHook = func(_ *Index, stage string) {
			if stage == "loaded" {
				once.Do(cancel)
			}
		}
		defer func() { importerLoadHook = nil }()

		if _, err := ix.EnumerateImportClosure(ctx); err == nil {
			t.Fatal("a cancelled importer load must fail the enumeration")
		}
		assertNoCaches(t, ix)
		if c := countsOf(ix); c.importerLoads != 0 || c.enumerations != 0 || c.packageScopes != 0 {
			t.Fatalf("interrupted work must not count as a completed load or build: %+v", c)
		}
		healthy, err := ix.EnumerateImportClosure(liveCtx(t))
		if err != nil {
			t.Fatalf("a healthy call must recover: %v", err)
		}
		if c := countsOf(ix); c.importerLoads != 1 || c.enumerations != 1 || c.packageScopes != 1 {
			t.Fatalf("the healthy call must build each artefact exactly once: %+v", c)
		}
		fresh, err := fixture(t, "scopetestprod").EnumerateImportClosure(liveCtx(t))
		if err != nil {
			t.Fatal(err)
		}
		if healthy.Hash != fresh.Hash {
			t.Fatalf("the recovered enumeration must match a clean fixture: %q vs %q", healthy.Hash, fresh.Hash)
		}
	})

	t.Run("census metadata", func(t *testing.T) {
		ix := fixture(t, "scopetestprod")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var once sync.Once
		importerLoadHook = func(_ *Index, stage string) {
			if stage == "metadata" {
				once.Do(cancel)
			}
		}
		defer func() { importerLoadHook = nil }()

		if _, err := ix.EnumerateImportClosure(ctx); err == nil {
			t.Fatal("cancellation during metadata assembly must fail the enumeration")
		}
		assertNoCaches(t, ix)
		if c := countsOf(ix); c.importerLoads != 0 {
			t.Fatalf("an interrupted census must not be counted: %+v", c)
		}
		if _, err := ix.EnumerateImportClosure(liveCtx(t)); err != nil {
			t.Fatalf("a healthy call must recover: %v", err)
		}
		if c := countsOf(ix); c.importerLoads != 1 {
			t.Fatalf("the retry must census exactly once: %+v", c)
		}
	})

	t.Run("package graph progress", func(t *testing.T) {
		ix := fixture(t, "scopetestprod")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var once sync.Once
		scopeBuildHook = func(_ *Index, stage string) {
			if stage == "package-progress" {
				once.Do(cancel)
			}
		}
		defer func() { scopeBuildHook = nil }()

		if _, err := ix.BuildShippingScope(ctx); err == nil {
			t.Fatal("mid-package-build cancellation must fail the scope build")
		}
		assertNoCaches(t, ix)
		if c := countsOf(ix); c.packageScopes != 0 || c.functionScopes != 0 {
			t.Fatalf("an interrupted package graph must not be counted: %+v", c)
		}
		if _, err := ix.BuildShippingScope(liveCtx(t)); err != nil {
			t.Fatalf("a healthy call must recover: %v", err)
		}
		if c := countsOf(ix); c.packageScopes != 1 || c.functionScopes != 1 {
			t.Fatalf("the retry must build each graph exactly once: %+v", c)
		}
	})

	t.Run("function graph progress", func(t *testing.T) {
		ix := fixture(t, "scopetestprod")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var once sync.Once
		scopeBuildHook = func(_ *Index, stage string) {
			if stage == "function-progress" {
				once.Do(cancel)
			}
		}
		defer func() { scopeBuildHook = nil }()

		if _, err := ix.BuildShippingScope(ctx); err == nil {
			t.Fatal("mid-function-build cancellation must fail the scope build")
		}
		assertNoCaches(t, ix)
		if c := countsOf(ix); c.functionScopes != 0 {
			t.Fatalf("an interrupted function graph must not be counted: %+v", c)
		}
		if _, err := ix.BuildShippingScope(liveCtx(t)); err != nil {
			t.Fatalf("a healthy call must rebuild from clean state: %v", err)
		}
		if c := countsOf(ix); c.packageScopes != 2 || c.functionScopes != 1 {
			t.Fatalf("the retry must rebuild the package half and build the function half once: %+v", c)
		}
	})

	t.Run("after last member file", func(t *testing.T) {
		ix := fixture(t, "scopetestprod")
		// First enumeration builds the record; the second is a cache hit
		// whose validation pass is cancelled after the last file read.
		if _, err := ix.EnumerateImportClosure(liveCtx(t)); err != nil {
			t.Fatal(err)
		}
		steady := countsOf(ix)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var once sync.Once
		memberScanHook = func(*Index) { once.Do(cancel) }
		defer func() { memberScanHook = nil }()

		if _, err := ix.EnumerateImportClosure(ctx); err == nil {
			t.Fatal("cancellation after the last member read must fail the hit")
		}
		if c := countsOf(ix); c.validations != steady.validations {
			t.Fatalf("a cancelled validation must not be counted as a hit: %+v -> %+v", steady, c)
		}
		if _, _, _, closure := cachedState(ix); !closure {
			t.Fatal("the previously published record must survive a cancelled validation")
		}
		memberScanHook = nil
		healthy, err := ix.EnumerateImportClosure(liveCtx(t))
		if err != nil {
			t.Fatalf("a healthy validation must recover: %v", err)
		}
		if healthy.Hash == "" {
			t.Fatal("the recovered hit must carry the record")
		}
		if c := countsOf(ix); c.validations != steady.validations+1 {
			t.Fatalf("the healthy validation must be counted once: %+v", c)
		}
	})
}

// assertNoCaches verifies no memoized observation survived a failed call.
func assertNoCaches(t *testing.T, ix *Index) {
	t.Helper()
	packageScope, fullScope, importerGraph, closure := cachedState(ix)
	if packageScope || fullScope || importerGraph || closure {
		t.Fatalf("an interrupted call must publish nothing: package=%v full=%v census=%v closure=%v",
			packageScope, fullScope, importerGraph, closure)
	}
}

// TestCanceledContextStopsClosureWork: a cancelled context fails every
// expensive entry point before it does work, and the failure publishes no
// cache entry — the next healthy call builds exactly once and closes.
func TestCanceledContextStopsClosureWork(t *testing.T) {
	ix := fixture(t, "scopetestprod")
	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := ix.BuildShippingScope(canceled); err == nil {
		t.Fatal("a cancelled context must fail the shipping-scope build")
	}
	if _, err := ix.buildUnreachabilityScope(canceled); err == nil {
		t.Fatal("a cancelled context must fail the unreachability-scope build")
	}
	if _, err := ix.EnumerateImportClosure(canceled); err == nil {
		t.Fatal("a cancelled context must fail the closure enumeration")
	}
	if _, err := ix.VerifyUnreachable(canceled, "example.com/dep",
		[]domain.SymbolRef{vulnSym}); err == nil {
		t.Fatal("a cancelled context must fail subject verification")
	}
	if c := countsOf(ix); c.packageScopes != 0 || c.functionScopes != 0 ||
		c.enumerations != 0 || c.importerLoads != 0 {
		t.Fatalf("cancelled calls must not publish a scope or closure: %+v", c)
	}
	healthy, err := ix.BuildShippingScope(liveCtx(t))
	if err != nil {
		t.Fatalf("a healthy call after cancellation must succeed: %v", err)
	}
	if c := countsOf(ix); c.packageScopes != 1 || c.functionScopes != 1 {
		t.Fatalf("the healthy call must build each graph exactly once, got %+v", c)
	}
	if healthy.Complete != (len(healthy.UnknownReasons) == 0) {
		t.Fatalf("scope completeness contradicts its reasons: %+v", healthy)
	}
}

// TestLoadBudgetExhaustionKeepsResultOpen: an exhausted load budget leaves
// the closure incomplete and names the truncation, and the record survives
// the query's budget restore — a later query that reloads successfully
// cannot absorb the gap.
func TestLoadBudgetExhaustionKeepsResultOpen(t *testing.T) {
	ix := fixture(t, "constprod")
	ctx := context.Background()
	if err := ix.load(ctx); err != nil {
		t.Fatal(err)
	}
	ix.mu.Lock()
	ix.loadBudget = 1 // one package load may succeed, the next is refused
	ix.mu.Unlock()

	cl, _, err := ix.SinkClosure(ctx, "C-INPUT", "example.com/dep", "explicit test basis",
		[]domain.SymbolRef{vulnSym}, 0, 16)
	if err != nil {
		t.Fatal(err)
	}
	if cl.Complete {
		t.Fatalf("a truncated closure must not report Complete: %+v", cl)
	}
	if !hasBlockerContaining(cl.Blockers, "budget") {
		t.Fatalf("the budget truncation must be named in the blockers: %v", cl.Blockers)
	}
	if !ix.LoadBudgetExhausted() {
		t.Fatal("the truncation record must survive the query-scoped budget restore")
	}
	lims := ix.BudgetLimitations()
	if len(lims) == 0 {
		t.Fatal("the session must record a named budget limitation")
	}
	for _, l := range lims {
		if !strings.Contains(l, "budget") {
			t.Fatalf("the recorded limitation must name the budget: %q", l)
		}
	}

	// Repeated verification of the same subject keeps the unresolved state
	// instead of reporting a cleaner-looking, complete closure.
	cl2, _, err := ix.SinkClosure(ctx, "C-INPUT", "example.com/dep", "explicit test basis",
		[]domain.SymbolRef{vulnSym}, 0, 16)
	if err != nil {
		t.Fatal(err)
	}
	if cl2.Complete {
		t.Fatalf("a repeated verification discarded the truncation: %+v", cl2)
	}
	if !hasBlockerContaining(cl2.Blockers, "session coverage truncated") {
		t.Fatalf("the repeated closure must carry the session truncation blocker: %v", cl2.Blockers)
	}

	closure, err := ix.EnumerateImportClosure(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if closure.Complete || !closure.LoadBudgetExhausted {
		t.Fatalf("the enumerated closure must stay open and name the truncation: complete=%v budget=%v",
			closure.Complete, closure.LoadBudgetExhausted)
	}
	fresh, err := fixture(t, "constprod").EnumerateImportClosure(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Hash == closure.Hash {
		t.Fatal("a truncated inventory must not replay the full-inventory hash")
	}
}

// TestSharedIndexTruncationIsFailClosed: one index serves many advisories in
// scan/eval mode, and eval runs cases concurrently from the same pointer. A
// truncation recorded by one case must never be cleared by another case's
// boundary — losing it would silently restore completeness — so the record
// is sticky for the index lifetime and a clean session needs a fresh index.
func TestSharedIndexTruncationIsFailClosed(t *testing.T) {
	ix := fixture(t, "scopetestprod")
	ctx := context.Background()
	ix.BeginVerificationSession("case-1")

	// A real dependency load exhausts the last budget unit.
	ix.mu.Lock()
	ix.loadBudget = 1
	ix.mu.Unlock()
	if _, err := ix.loadExtra(ctx, "example.com/scopetestprod/svc"); err != nil {
		t.Fatal(err)
	}
	if !ix.LoadBudgetExhausted() || len(ix.BudgetLimitations()) == 0 {
		t.Fatal("case 1 must record its truncation")
	}

	// A second case begins — concurrently or sequentially, the boundary must
	// not erase case 1's unresolved state.
	var wg sync.WaitGroup
	for _, id := range []domain.CaseID{"case-2", "case-3"} {
		wg.Add(1)
		go func(id domain.CaseID) {
			defer wg.Done()
			ix.BeginVerificationSession(id)
			if !ix.LoadBudgetExhausted() {
				t.Errorf("case %s erased a concurrent case's truncation", id)
			}
			if len(ix.BudgetLimitations()) == 0 {
				t.Errorf("case %s observed an empty truncation record", id)
			}
		}(id)
	}
	wg.Wait()
	ix.BeginVerificationSession("case-1")
	if !ix.LoadBudgetExhausted() {
		t.Fatal("the record must stay sticky for the original case too")
	}
	closure, err := ix.EnumerateImportClosure(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if closure.Complete || !closure.LoadBudgetExhausted {
		t.Fatalf("a shared-index truncation must keep the closure open: complete=%v budget=%v",
			closure.Complete, closure.LoadBudgetExhausted)
	}

	// A fresh index (a fresh snapshot load) is the only clean session.
	fresh := fixture(t, "scopetestprod")
	if fresh.LoadBudgetExhausted() {
		t.Fatal("a fresh index must start without truncation evidence")
	}
	if lims := fresh.BudgetLimitations(); len(lims) != 0 {
		t.Fatalf("a fresh index must start with no budget limitations: %v", lims)
	}
	freshClosure, err := fresh.EnumerateImportClosure(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if freshClosure.LoadBudgetExhausted || !freshClosure.Complete {
		t.Fatalf("the fresh index must enumerate a complete record: complete=%v budget=%v",
			freshClosure.Complete, freshClosure.LoadBudgetExhausted)
	}
}

// TestOpenMayCallSitesRemainNonAdmitting: an unresolved may-call candidate
// keeps the concatenated proof open — the open enumeration must never fold
// into a closed no-exploit-path record.
func TestOpenMayCallSitesRemainNonAdmitting(t *testing.T) {
	ix := fixture(t, "fvopenprod")
	sites, partial, err := ix.MayCallSites(context.Background(), vulnSym)
	if err != nil {
		t.Fatal(err)
	}
	if !partial {
		t.Fatalf("the fixture must produce an open may-call enumeration: %+v", sites)
	}
	res, err := ix.VerifyUnreachable(context.Background(), "example.com/dep",
		[]domain.SymbolRef{vulnSym})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete {
		t.Fatalf("an open may-call enumeration must not close the proof: %+v", res.Limitations)
	}
	if !hasBlockerContaining(res.Limitations, "may-call") &&
		!hasBlockerContaining(res.Limitations, "may_call") {
		t.Fatalf("the open enumeration must be named: %v", res.Limitations)
	}
}

// TestSkippedPackageStaysInScopeDenominator: a failed package the loader
// dropped is still product code — it appears in the root inventory, carries
// a scope verdict, stays in the skipped census and keeps the closure open.
func TestSkippedPackageStaysInScopeDenominator(t *testing.T) {
	ix := fixture(t, "scopeskipp")
	closure, err := ix.EnumerateImportClosure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	const broken = "example.com/scopeskipp/broken"
	if !hasStr(closure.ProductRoots, broken) {
		t.Fatalf("skipped package %s must stay in the root inventory: %v", broken, closure.ProductRoots)
	}
	if !hasStr(closure.Skipped, broken) {
		t.Fatalf("skipped package %s must stay in the skipped census: %v", broken, closure.Skipped)
	}
	if !hasStr(closure.ShippingRoots, "example.com/scopeskipp/cmd/app") {
		t.Fatalf("the proven main must seed the closed scope: %v", closure.ShippingRoots)
	}
	for _, path := range []string{broken, "example.com/scopeskipp/cmd/app", "example.com/scopeskipp/loose"} {
		if _, ok := closure.PackageStates[path]; !ok {
			t.Fatalf("product package %s must carry a scope verdict: %v", path, closure.PackageStates)
		}
	}
	if closure.PackageStates[broken] == "DEAD" {
		t.Fatal("a skipped package inside the shipping closure can never be DEAD")
	}
	if closure.Complete {
		t.Fatal("skipped members must keep the closure open")
	}
	if hasStr(closure.DiscardedUnreachable, broken) {
		t.Fatalf("a shipping-closure skipped package must never be audit-discarded: %v", closure.DiscardedUnreachable)
	}
	if !hasStr(closure.DiscardedUnreachable, "example.com/scopeskipp/loose") {
		t.Fatalf("a proven-DEAD skipped package belongs in the audit trail: %v", closure.DiscardedUnreachable)
	}
}

// TestRepeatedSubjectVerificationKeepsUnresolvedState: a closed proof plus a
// later budget truncation must not produce a second closed proof — the
// unresolved state is sticky.
func TestRepeatedSubjectVerificationKeepsUnresolvedState(t *testing.T) {
	ix := fixture(t, "unreachprod")
	ctx := context.Background()
	subjects := []domain.SymbolRef{
		{Package: "example.com/unreachdep/vulnlib", Symbol: "OrphanA"},
	}
	first, err := ix.VerifyUnreachable(ctx, "example.com/unreachdep", subjects)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Complete {
		t.Fatalf("baseline proof must close: %v", first.Limitations)
	}

	// A real dependency load exhausting the session budget truncates
	// dependency coverage for the rest of the session. The load pattern
	// differs from the module-wide pattern VerifyUnreachable cached, so this
	// is a genuine packages.Load that consumes the last budget unit.
	ix.mu.Lock()
	ix.loadBudget = 1
	ix.mu.Unlock()
	if _, err := ix.loadExtra(ctx, "example.com/unreachdep"); err != nil {
		t.Fatal(err)
	}
	if !ix.LoadBudgetExhausted() {
		t.Fatal("the budget truncation must be recorded")
	}
	// Restore the query-scoped budget the way SinkClosure's own defer does:
	// only the session record may carry the truncation forward.
	ix.mu.Lock()
	ix.loadBudget = 0
	ix.loadBudgetExhausted = false
	ix.mu.Unlock()
	if !ix.LoadBudgetExhausted() {
		t.Fatal("the session truncation must survive the query-scoped budget restore")
	}

	second, err := ix.VerifyUnreachable(ctx, "example.com/unreachdep", subjects)
	if err != nil {
		t.Fatal(err)
	}
	if second.Complete {
		t.Fatalf("a repeated verification discarded the session truncation: %+v", second.Limitations)
	}
	if !hasBlockerContaining(second.Limitations, "budget") {
		t.Fatalf("the repeated verification must name the truncation: %v", second.Limitations)
	}
	if len(second.Subjects) != len(first.Subjects) {
		t.Fatalf("the repeated result must cover the same subjects: %v vs %v", second.Subjects, first.Subjects)
	}
}

package goanalysis

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

// closureOf enumerates the import closure for a testdata fixture.
func closureOf(t *testing.T, name string) ImportClosure {
	t.Helper()
	ix := fixture(t, name)
	c, err := ix.EnumerateImportClosure(context.Background())
	if err != nil {
		t.Fatalf("EnumerateImportClosure: %v", err)
	}
	return c
}

func hasStr(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func memberSet(c ImportClosure) map[string]bool {
	m := make(map[string]bool, len(c.Packages))
	for _, p := range c.Packages {
		m[p] = true
	}
	return m
}

const (
	scopetestMain   = "example.com/scopetestprod"
	scopetestSvc    = "example.com/scopetestprod/svc"
	scopetestHelper = "example.com/scopetestprod/test/helper"
	scopetestBad    = "example.com/scopetestprod/test/bad"
	scopetestFuzz   = "example.com/scopetestprod/fuzz"
)

// TestShippingScopeDeadTestPackageDoesNotBlock: standalone test/ and
// fuzz helper packages never imported by main are proven DEAD — they
// leave the effective closure, land in the discard audit trail and
// cannot block completeness even when their source inventory is
// unverifiable.
func TestShippingScopeDeadTestPackageDoesNotBlock(t *testing.T) {
	ix := fixture(t, "scopetestprod")
	ss, err := ix.BuildShippingScope(context.Background())
	if err != nil {
		t.Fatalf("BuildShippingScope: %v", err)
	}
	if !ss.Complete {
		t.Fatalf("scope must close: %v", ss.UnknownReasons)
	}
	for _, pkg := range []string{scopetestHelper, scopetestBad, scopetestFuzz} {
		if got := ss.PackageState(pkg); got != ReachabilityDead {
			t.Fatalf("%s must be DEAD, got %s", pkg, got)
		}
	}
	if got := ss.PackageState(scopetestSvc); got != ReachabilityLive {
		t.Fatalf("svc must be LIVE, got %s", got)
	}
	if got := ss.PackageState("example.com/never/seen"); got != ReachabilityUnknown {
		t.Fatalf("an unseen path is UNKNOWN, got %s", got)
	}

	c, err := ix.EnumerateImportClosure(context.Background())
	if err != nil {
		t.Fatalf("EnumerateImportClosure: %v", err)
	}
	for _, pkg := range []string{scopetestHelper, scopetestBad, scopetestFuzz} {
		if hasStr(c.Packages, pkg) {
			t.Fatalf("dead package %s must not be a closure member", pkg)
		}
		if !hasStr(c.DiscardedUnreachable, pkg) {
			t.Fatalf("dead package %s must appear in DiscardedUnreachable", pkg)
		}
	}
	// test/bad fails to type-check: its gap is unreachable-only and may
	// never reopen the closure.
	if hasStr(c.Skipped, scopetestBad) || hasStr(c.BrokenEdges, scopetestBad) {
		t.Fatal("a dead skipped package must not appear in blocking lists")
	}
	if !c.Complete {
		t.Fatalf("closure must be complete: %+v", c)
	}
}

// TestShippingScopeShippingImportsTestPackageBlocks: a test/...-pathed
// package imported by shipping code is never DEAD — it stays inside
// the closure and its own gaps block completeness.
func TestShippingScopeShippingImportsTestPackageBlocks(t *testing.T) {
	ix := fixture(t, "skiplinkprod")
	ss, err := ix.BuildShippingScope(context.Background())
	if err != nil {
		t.Fatalf("BuildShippingScope: %v", err)
	}
	if got := ss.PackageState("example.com/skiplinkprod/broken"); got == ReachabilityDead {
		t.Fatalf("a package imported by shipping code must never be DEAD, got %s", got)
	}
	c, err := ix.EnumerateImportClosure(context.Background())
	if err != nil {
		t.Fatalf("EnumerateImportClosure: %v", err)
	}
	if !hasStr(c.Packages, "example.com/skiplinkprod/broken") {
		t.Fatal("a skipped package linked by main must stay a member")
	}
	if !hasStr(c.Skipped, "example.com/skiplinkprod/broken") {
		t.Fatalf("reachable skipped members must stay blocking: %+v", c.Skipped)
	}
	if c.Complete {
		t.Fatal("a reachable skipped member must block completeness")
	}
	if hasStr(c.DiscardedUnreachable, "example.com/skiplinkprod/broken") {
		t.Fatal("a reachable package must never be discarded")
	}
}

// TestShippingScopeReachableCgoUnknown: a cgo package reachable from
// main keeps the scope open — its edges cannot be trusted — and the
// closure stays incomplete while the package is never DEAD.
func TestShippingScopeReachableCgoUnknown(t *testing.T) {
	// The loader env defaults CGO_ENABLED=0; pin the build context that
	// links the cgo package.
	ix := fixture(t, "scopecgoprod")
	ix.Build.CGOEnabled = true
	c, err := ix.EnumerateImportClosure(context.Background())
	if err != nil {
		t.Fatalf("EnumerateImportClosure: %v", err)
	}
	if c.Complete {
		t.Fatal("reachable cgo must keep the closure incomplete")
	}
	if st := c.PackageStates["example.com/scopecgoprod/hascgo"]; st == "DEAD" {
		t.Fatal("a reachable cgo package must never be DEAD")
	}
	if !hasStr(c.Packages, "example.com/scopecgoprod/hascgo") {
		t.Fatal("the cgo package linked by main must stay a member")
	}
	if hasStr(c.DiscardedUnreachable, "example.com/scopecgoprod/hascgo") {
		t.Fatal("a reachable cgo package must never be discarded")
	}
}

// TestShippingScopeDeadCgoDiscarded: an unimported cgo package is
// proven dead — its edge-forging surface joins the audit trail instead
// of blocking the closure.
func TestShippingScopeDeadCgoDiscarded(t *testing.T) {
	ix := fixture(t, "scopecgodead")
	ix.Build.CGOEnabled = true
	c, err := ix.EnumerateImportClosure(context.Background())
	if err != nil {
		t.Fatalf("EnumerateImportClosure: %v", err)
	}
	if !c.ScopeComplete {
		t.Fatalf("scope must close when cgo only lives in dead packages: %v", c.ScopeUnknown)
	}
	if !hasStr(c.DiscardedUnreachable, "example.com/scopecgodead/deadcgo") {
		t.Fatal("the dead cgo package must be discarded with an audit trail")
	}
	if !c.Complete {
		t.Fatal("dead cgo must not block closure completeness")
	}
	for _, m := range c.EdgeMarkers {
		if m.Package == "example.com/scopecgodead/deadcgo" {
			t.Fatalf("a discarded package must not contribute edge markers: %+v", m)
		}
	}
}

// TestShippingScopeUnhashableDeadPackageDiscarded: gaps confined to a
// dead package — skipped recovery or an unreadable source inventory —
// cannot block: the package is discarded before hashing.
func TestShippingScopeUnhashableDeadPackageDiscarded(t *testing.T) {
	// scopetestprod/test/bad fails to type-check; scopeunscan/bad could
	// not even be parsed. Both keep recoverable non-main clauses, so
	// they are proven non-roots and discarded.
	for _, pkg := range []string{scopetestBad, scopetestHelper, scopetestFuzz} {
		c := closureOf(t, "scopetestprod")
		if !hasStr(c.DiscardedUnreachable, pkg) || hasStr(c.Packages, pkg) {
			t.Fatalf("%s must be discarded, not enumerated: %+v", pkg, c.DiscardedUnreachable)
		}
		if !c.Complete {
			t.Fatalf("dead-package gaps must not block: %+v", c)
		}
	}
	c := closureOf(t, "scopeunscan")
	if !hasStr(c.DiscardedUnreachable, "example.com/scopeunscan/bad") ||
		!hasStr(c.DiscardedUnreachable, "example.com/scopeunscan/loose") {
		t.Fatalf("unparseable dead packages must be discarded: %+v", c.DiscardedUnreachable)
	}
	if !c.Complete {
		t.Fatalf("a dead package with unrecoverable bodies must not block: %+v", c)
	}
	if len(c.Skipped) != 0 || len(c.SkippedUnscanned) != 0 {
		t.Fatalf("no effective skipped member may remain: %+v %+v", c.Skipped, c.SkippedUnscanned)
	}
}

// TestShippingScopeUnhashableLivePackageBlocks: a reachable member
// whose source inventory cannot be hashed keeps the closure
// incomplete — the inventory cannot be replayed, so it can never be
// called closed.
func TestShippingScopeUnhashableLivePackageBlocks(t *testing.T) {
	ix := fixture(t, "scopetestprod")
	if err := ix.load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := ix.depImporters(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Corrupt the live svc package's recorded file set: its inventory
	// can then never be hashed, mirroring an unreadable member.
	cm := ix.pkgMeta[scopetestSvc]
	cm.hashFiles = append(cm.hashFiles, filepath.Join(ix.Dir, "svc", "gone.go"))
	ix.pkgMeta[scopetestSvc] = cm

	c, err := ix.EnumerateImportClosure(context.Background())
	if err != nil {
		t.Fatalf("EnumerateImportClosure: %v", err)
	}
	if !hasStr(c.UnhashedSource, scopetestSvc) {
		t.Fatalf("the corrupted live member must be unhashed: %+v", c.UnhashedSource)
	}
	if c.Complete {
		t.Fatal("a reachable unhashable member must block completeness")
	}
}

// TestShippingScopeNoMainNeverDead: a library-only snapshot has no
// proven root, produces no discard and keeps every package UNKNOWN.
func TestShippingScopeNoMainNeverDead(t *testing.T) {
	ix := fixture(t, "scopelib")
	ss, err := ix.BuildShippingScope(context.Background())
	if err != nil {
		t.Fatalf("BuildShippingScope: %v", err)
	}
	if ss.Complete {
		t.Fatal("a snapshot without main must keep the scope open")
	}
	if len(ss.Roots) != 0 {
		t.Fatalf("library-only snapshot must have no roots: %v", ss.Roots)
	}
	for pkg, st := range ss.PackageStates {
		if st == ReachabilityDead {
			t.Fatalf("%s must never be DEAD without a main: %s", pkg, st)
		}
	}
	c, err := ix.EnumerateImportClosure(context.Background())
	if err != nil {
		t.Fatalf("EnumerateImportClosure: %v", err)
	}
	if len(c.DiscardedUnreachable) != 0 {
		t.Fatalf("no discard is allowed without a proven root set: %+v", c.DiscardedUnreachable)
	}
	if c.Complete {
		t.Fatal("a snapshot without main must never complete")
	}
	for _, st := range c.PackageStates {
		if st == "DEAD" {
			t.Fatal("no package may report DEAD without a proven root set")
		}
	}
}

// TestShippingScopeUnknownRootBlocks: a package with no recoverable
// package clause may hide a main — the scope stays open, nothing is
// discarded and the closure enumerates the conservative root set.
func TestShippingScopeUnknownRootBlocks(t *testing.T) {
	c := closureOf(t, "unscanprod")
	if c.ScopeComplete || c.Complete {
		t.Fatal("an unverifiable root candidate must keep everything open")
	}
	if len(c.DiscardedUnreachable) != 0 {
		t.Fatalf("no discard is allowed while the root set is unproven: %+v", c.DiscardedUnreachable)
	}
	found := false
	for _, r := range c.ScopeUnknown {
		if strings.Contains(r, "example.com/unscanprod/bad") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the unverifiable package must be named: %v", c.ScopeUnknown)
	}
	if !hasStr(c.Packages, "example.com/unscanprod/bad") {
		t.Fatal("an unknown-root candidate stays inside the conservative closure")
	}
}

// TestShippingScopeHiddenMainNeverDiscarded: the loader reports the
// conflicted directory under a non-main name, but a file inside
// declares package main — the clause scan roots it and its skipped
// state stays a blocking member, never a discard.
func TestShippingScopeHiddenMainNeverDiscarded(t *testing.T) {
	c := closureOf(t, "scopehiddenmain")
	const hidden = "example.com/scopehiddenmain/hidden"
	if !hasStr(c.ShippingRoots, hidden) {
		t.Fatalf("a directory carrying a main clause is a shipping root: %v", c.ShippingRoots)
	}
	if st := c.PackageStates[hidden]; st != "LIVE" {
		t.Fatalf("a rooted package is LIVE, got %s", st)
	}
	if hasStr(c.DiscardedUnreachable, hidden) {
		t.Fatal("a hidden main must never be discarded")
	}
	if c.Complete {
		t.Fatal("a skipped shipping member must block completeness")
	}
}

// TestImportClosureUsesShippingRoots: the effective member set is the
// transitive closure of the proven main packages — every unlinked
// product package is excluded and audited.
func TestImportClosureUsesShippingRoots(t *testing.T) {
	c := closureOf(t, "scopetestprod")
	if !c.ScopeComplete {
		t.Fatalf("fixture scope must close: %v", c.ScopeUnknown)
	}
	want := []string{scopetestMain}
	if len(c.ShippingRoots) != len(want) || c.ShippingRoots[0] != want[0] {
		t.Fatalf("shipping roots=%v want %v", c.ShippingRoots, want)
	}
	m := memberSet(c)
	if !m[scopetestSvc] {
		t.Fatal("a package imported by main must stay a member")
	}
	for _, pkg := range []string{scopetestHelper, scopetestBad, scopetestFuzz} {
		if m[pkg] {
			t.Fatalf("%s must not be a member", pkg)
		}
	}
	if len(c.PackageStates) == 0 {
		t.Fatal("package states must be exported")
	}
	if c.PackageStates[scopetestSvc] != "LIVE" || c.PackageStates[scopetestHelper] != "DEAD" {
		t.Fatalf("states=%v", c.PackageStates)
	}
}

// TestImportClosureTransitiveImporterStillBlocks: a package linked by
// main stays a member even though dead helpers also import it — and
// the member-only importer view names only live importers.
func TestImportClosureTransitiveImporterStillBlocks(t *testing.T) {
	c := closureOf(t, "scopetestprod")
	m := memberSet(c)
	if !m[scopetestSvc] {
		t.Fatal("svc must stay a member: dead importers cannot unlink it")
	}
	var inside []string
	for _, imp := range c.Importers[scopetestSvc] {
		if m[imp] {
			inside = append(inside, imp)
		}
	}
	if len(inside) != 1 || inside[0] != scopetestMain {
		t.Fatalf("member importers of svc=%v want [main]", inside)
	}
}

// TestImportClosureVendorBindingAndHash: a vendored dependency stays an
// effective member with a pinned module binding, and mutating its
// source moves the closure hash.
func TestImportClosureVendorBindingAndHash(t *testing.T) {
	const vend = "example.com/vend/vendlib"
	c := closureOf(t, "scopevendorprod")
	if !hasStr(c.Packages, vend) {
		t.Fatal("a vendored package imported by main must stay a member")
	}
	if !hasStr(c.Vendored, vend) {
		t.Fatal("the vendored member must be recorded as vendored")
	}
	if c.ModuleBindings[vend] == "" {
		t.Fatal("the vendored member must carry a module binding")
	}
	if c.PackageStates["example.com/scopevendorprod/deadpkg"] != "DEAD" ||
		!hasStr(c.DiscardedUnreachable, "example.com/scopevendorprod/deadpkg") {
		t.Fatal("the dead product package must be discarded")
	}
	if !c.Complete {
		t.Fatalf("vendored members with bound sources must not block: %+v", c)
	}

	// Mutating the vendored source under the same module identity must
	// move both the member source hash and the closure hash.
	src, err := filepath.Abs(filepath.Join("..", "..", "testdata", "scopevendorprod"))
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "mut")
	copyFixture(t, src, dst)
	vf := filepath.Join(dst, "vendor", "example.com", "vend", "vendlib", "vendlib.go")
	data, err := os.ReadFile(vf)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vf, append(data, []byte("\n// mutated\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	ix2 := &Index{Dir: dst}
	c2, err := ix2.EnumerateImportClosure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if c.Hash == c2.Hash || c.SourceHashes[vend] == c2.SourceHashes[vend] {
		t.Fatal("a mutated vendored member must move the hashes")
	}
}

// copyFixture mirrors a fixture tree into dst so tests can mutate it.
func copyFixture(t *testing.T, src, dst string) {
	t.Helper()
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		s := filepath.Join(src, e.Name())
		d := filepath.Join(dst, e.Name())
		if e.IsDir() {
			copyFixture(t, s, d)
			continue
		}
		data, err := os.ReadFile(s)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(d, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// TestImportClosureScopeHashDeterministic: identical snapshots produce
// identical closure and scope hashes, and every new scope-bound field
// moves the closure hash.
func TestImportClosureScopeHashDeterministic(t *testing.T) {
	c1 := closureOf(t, "scopetestprod")
	c2 := closureOf(t, "scopetestprod")
	if c1.Hash != c2.Hash {
		t.Fatal("closure hash must be deterministic")
	}
	if c1.ScopeHash == "" || c1.ScopeHash != c2.ScopeHash {
		t.Fatal("scope hash must be present and deterministic")
	}
	// Every scope-bound input must move the closure hash — a replay
	// detecting drift cannot trust a hash blind to the scope it ran on.
	base := c1
	cases := map[string]func(*ImportClosure){
		"shipping roots":    func(c *ImportClosure) { c.ShippingRoots = append(c.ShippingRoots, "example.com/x") },
		"scope complete":    func(c *ImportClosure) { c.ScopeComplete = !c.ScopeComplete },
		"scope hash":        func(c *ImportClosure) { c.ScopeHash += "1" },
		"package states":    func(c *ImportClosure) { c.PackageStates[scopetestSvc] = "DEAD" },
		"scope unknowns":    func(c *ImportClosure) { c.ScopeUnknown = append(c.ScopeUnknown, "reason") },
		"discarded":         func(c *ImportClosure) { c.DiscardedUnreachable = append(c.DiscardedUnreachable, "example.com/x") },
		"module bindings":   func(c *ImportClosure) { c.ModuleBindings[scopetestSvc] = "fake@v9" },
		"source hashes":     func(c *ImportClosure) { c.SourceHashes[scopetestSvc] = "0" },
		"dynamic relevance": func(c *ImportClosure) { c.DynamicRelevance = append(c.DynamicRelevance, "func_value incompatible") },
	}
	for name, mutate := range cases {
		c := base
		c.PackageStates = map[string]string{}
		for k, v := range base.PackageStates {
			c.PackageStates[k] = v
		}
		c.ModuleBindings = map[string]string{}
		for k, v := range base.ModuleBindings {
			c.ModuleBindings[k] = v
		}
		c.SourceHashes = map[string]string{}
		for k, v := range base.SourceHashes {
			c.SourceHashes[k] = v
		}
		c.ShippingRoots = append([]string(nil), base.ShippingRoots...)
		c.ScopeUnknown = append([]string(nil), base.ScopeUnknown...)
		c.DiscardedUnreachable = append([]string(nil), base.DiscardedUnreachable...)
		mutate(&c)
		if closureHash(c) == c1.Hash {
			t.Fatalf("closure hash blind to %s mutation", name)
		}
	}
}

// truncated inventory would collide with a full one.
func TestImportClosureLoadBudgetBindsHash(t *testing.T) {
	c1 := closureOf(t, "scopetestprod")
	ix := fixture(t, "scopetestprod")
	ix.loadBudgetExhausted = true
	c2, err := ix.EnumerateImportClosure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if c2.Complete || !c2.LoadBudgetExhausted {
		t.Fatal("budget exhaustion must report and block")
	}
	if c1.Hash == c2.Hash {
		t.Fatal("a truncated inventory must not replay the full-inventory hash")
	}
}

// TestImportClosureImportersSortedMerged: a member imported through
// both the all-load and the skipped-recovery channels lists every
// importer once, sorted — the hash sees one canonical set.
func TestImportClosureImportersSortedMerged(t *testing.T) {
	c := closureOf(t, "scopetestprod")
	imps := c.Importers[scopetestSvc]
	if len(imps) != 4 {
		t.Fatalf("importers of svc=%v want the four known paths", imps)
	}
	for i := 1; i < len(imps); i++ {
		if imps[i] <= imps[i-1] {
			t.Fatalf("importers must be strictly sorted and deduplicated: %v", imps)
		}
	}
	if !hasStr(imps, scopetestBad) || !hasStr(imps, scopetestMain) ||
		!hasStr(imps, scopetestHelper) || !hasStr(imps, scopetestFuzz) {
		t.Fatalf("both importer channels must appear: %v", imps)
	}
}

// TestSkippedClauseProofEmptyInventory: an empty source inventory is a
// metadata gap, not a non-rootness proof — a named skipped package
// whose file list was lost stays unproven and keeps the scope open.
func TestSkippedClauseProofEmptyInventory(t *testing.T) {
	ix := fixture(t, "scopetestprod")
	if err := ix.load(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Synthesize the review counterexample: a skipped package the
	// loader named but whose inventory is entirely missing — its
	// directory could still contain a main.
	ghost := "example.com/scopetestprod/test/ghost"
	ix.skippedPkgs[ghost] = &packages.Package{PkgPath: ghost, Name: "ghost"}
	src, key := ix.snapshotKeysLocked()
	s, serr := ix.unreachabilityScopePackageLocked(context.Background(), src, key)
	if serr != nil {
		t.Fatal(serr)
	}
	if got := s.packageState(ghost); got == reachDead {
		t.Fatal("a package with no file inventory must never be DEAD")
	}
	if s.ProductGraphComplete {
		t.Fatal("an inventory-less skipped package must keep the scope open")
	}
	found := false
	for _, r := range s.unknownReasons {
		if strings.Contains(r, ghost) {
			found = true
		}
	}
	if !found {
		t.Fatalf("the unverifiable package must be named: %v", s.unknownReasons)
	}
	// The full pipeline agrees: the ghost is never discarded and the
	// enumeration stays conservative.
	c, err := ix.EnumerateImportClosure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if hasStr(c.DiscardedUnreachable, ghost) {
		t.Fatal("an inventory-less package must never be discarded")
	}
	if c.Complete {
		t.Fatal("an inventory-less package must block completeness")
	}
	if st := c.PackageStates[ghost]; st != "UNKNOWN" {
		t.Fatalf("ghost state=%s want UNKNOWN", st)
	}
}

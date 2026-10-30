package goanalysis

import (
	"context"
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/fedorovmv/izyan/internal/domain"
	"golang.org/x/tools/go/packages"
)

// unreachability_scope.go — the scoped reachability model behind
// VerifyUnreachable's candidate filtering.
//
// The loaded product closure (ix.pkgs) is wider than the code a shipped
// binary can run: test/fuzz helpers, corpus generators and utility
// packages sit next to real mains. A candidate call site blocks the
// proof only while it may execute, so the model answers one question
// per site: can the enclosing package/function ever run in the current
// build context?
//
// Soundness contract (docs/dev/plans/kernel-reachability-filter-plan.md
// §2): a three-valued state — LIVE (a path from a shipping root is
// proven), DEAD (absence of every path is proven inside a complete
// scope), UNKNOWN (neither). Only DEAD evidence may be discarded; every
// data gap — an unrecoverable import graph, an unparsed package, an
// unresolved dynamic edge, a generic/interface ambiguity — degrades the
// answer to UNKNOWN, never to DEAD.

// reachabilityState is the tri-state verdict of the scoped model.
type reachabilityState uint8

const (
	reachUnknown reachabilityState = iota
	reachLive
	reachDead
)

// String is a debug/report aid; the model itself is never serialized.
func (s reachabilityState) String() string {
	switch s {
	case reachLive:
		return "LIVE"
	case reachDead:
		return "DEAD"
	default:
		return "UNKNOWN"
	}
}

// mostReachable returns the state least favorable to discarding:
// LIVE wins over UNKNOWN wins over DEAD.
func mostReachable(a, b reachabilityState) reachabilityState {
	if a == reachLive || b == reachLive {
		return reachLive
	}
	if a == reachUnknown || b == reachUnknown {
		return reachUnknown
	}
	return reachDead
}

// functionKey names one product function in the graph. Symbol matches
// the repository's existing caller-key convention: a plain name for
// functions, "Recv.Name" for methods. Generic functions and all their
// instantiations deliberately share one conservative node (a receiver
// declared T[P] and a resolved callee on T[int] both key as T).
type functionKey struct {
	Package string
	Symbol  string
}

// scopeOpaque pairs an unresolved dispatch site (func value, interface,
// opaque callee) with its enclosing function for UNKNOWN propagation.
type scopeOpaque struct {
	caller functionKey
	site   opaqueSite
}

// unreachabilityScope is the computed verdict set for one loaded
// snapshot. It is built once per VerifyUnreachable run and is immutable
// thereafter.
type unreachabilityScope struct {
	// ProductPackages maps every product package — loaded or skipped —
	// to its shipping-closure state. Skipped packages appear keyed by
	// path too: a failed `main` is still a shipping root.
	ProductPackages map[string]reachabilityState
	// ProductFunctions maps every declared product function (non-test
	// files of live packages) to its state. Functions in non-live
	// packages are absent: package state answers sites inside them.
	ProductFunctions map[functionKey]reachabilityState
	// ProductGraphComplete is true only when every reachable product
	// node exposed a complete edge set: no unrecovered imports, no
	// unparsed files, no plugin/linkname materialization, and every
	// live package carried a resolvable module path. When false no
	// package or function may be called DEAD — the scope is open.
	ProductGraphComplete bool

	// roots holds the proven shipping roots — every package that can
	// produce a `main` binary (loaded or skipped) — in sorted order.
	// Empty when no main package was identified; with no roots nothing
	// is provably dead.
	roots []string
	// unknownReasons records, in sorted order, why the product scope
	// stayed open: unreachable-only problems never appear here — gaps
	// inside a proven-DEAD package cannot reopen the scope. Consumers
	// (closure enumeration, shipping-scope projection) surface these
	// instead of guessing.
	unknownReasons []string
	// DependencyGraphComplete is reserved for the module-cone stage
	// (Task 3); it stays false until a dependency importer graph was
	// built, so dependency-side verdicts cannot silently read as DEAD.
	DependencyGraphComplete bool
	// ModuleEntries records product call sites into each dependency
	// module seen while building the product graph; the module-cone
	// stage filters it to entries reachable from shipping roots.
	ModuleEntries map[string][]domain.CallSite
	// ModuleFunctions holds per-module function states once the module
	// cone is computed; until then it stays empty and non-product
	// sites classify UNKNOWN.
	ModuleFunctions map[string]map[string]reachabilityState

	livePkgs    map[string]bool
	livePkgList []*packages.Package              // live packages, for type lookups
	pkgPaths    []string                         // product paths — for key parsing
	sigs        map[functionKey]*types.Signature // declared signatures for opaque narrowing
	bareNames   map[string][]functionKey         // pkg|name → candidate keys
}

// packageState reports the shipping-closure state of a product package
// path. Unknown paths (dependency packages, never-scanned paths) are
// UNKNOWN — absence from the map is not evidence of deadness. A DEAD
// verdict is withheld whenever the closure was not proven complete.
func (s *unreachabilityScope) packageState(path string) reachabilityState {
	if s == nil {
		return reachUnknown
	}
	if st, ok := s.ProductPackages[path]; ok {
		if st == reachDead && !s.ProductGraphComplete {
			return reachUnknown
		}
		return st
	}
	return reachUnknown
}

// functionState maps an evidence site to the reachability state of its
// enclosing function. The site carries only names (callers record the
// bare function name; method receivers usually go unrecorded), so the
// lookup is conservative: every product function in the site's package
// the name could denote contributes, and the least-discardable verdict
// wins. A package/function the graph never saw is UNKNOWN.
func (s *unreachabilityScope) functionState(site domain.CallSite) reachabilityState {
	if s == nil {
		return reachUnknown
	}
	if !s.ProductGraphComplete {
		// Fail closed on the whole package half: without a proven
		// closure no function verdict may read DEAD, whatever the maps
		// still carry from earlier stages.
		return reachUnknown
	}
	pkgState := s.packageState(site.Package)
	switch pkgState {
	case reachDead:
		// Nothing in a proven-unlinked package can run; function
		// identity is irrelevant.
		return reachDead
	case reachUnknown:
		return reachUnknown
	}
	name := site.Function
	if site.Receiver != "" {
		name = site.Receiver + "." + name
	}
	if name == "" {
		// Package-level evidence (var init, import, declaration) is
		// driven by the package's init machinery — live once the
		// package is live.
		return reachLive
	}
	cands := s.candidateKeys(site.Package, name)
	if len(cands) == 0 {
		// A function the graph does not know cannot be proven dead —
		// the site might name a declaration in an unparsed file or a
		// test-only declaration outside the scope.
		return reachUnknown
	}
	st := reachDead
	for _, k := range cands {
		st = mostReachable(st, s.ProductFunctions[k])
	}
	return st
}

// classifySite is the entry point for site filtering: it folds package
// and enclosing-function state into the single verdict a filter applies.
// Non-product packages (dependency module internals) stay UNKNOWN until
// the module-cone stage fills ModuleFunctions.
func (s *unreachabilityScope) classifySite(site domain.CallSite) reachabilityState {
	if s == nil {
		return reachUnknown
	}
	if _, ok := s.ProductPackages[site.Package]; ok {
		// packageState withholds DEAD while the closure is incomplete —
		// go through it rather than the raw map so the fail-closed
		// guard cannot be bypassed.
		if s.packageState(site.Package) == reachDead {
			return reachDead
		}
		return s.functionState(site)
	}
	if mods := s.ModuleFunctions[site.Package]; len(mods) > 0 {
		if st, ok := mods[site.Function]; ok && (st != reachDead || s.DependencyGraphComplete) {
			return st
		}
	}
	return reachUnknown
}

// candidateKeys returns every function key in pkg the recorded name may
// denote: the exact match plus methods whose "Recv.Name" ends with the
// bare name — the receiver a site failed to record must never narrow
// the answer.
func (s *unreachabilityScope) candidateKeys(pkg, name string) []functionKey {
	exact := functionKey{Package: pkg, Symbol: name}
	if _, ok := s.ProductFunctions[exact]; ok {
		return []functionKey{exact}
	}
	return s.bareNames[pkg+"|"+name]
}

// buildUnreachabilityScope computes the shipping package closure and the
// product function graph for the loaded snapshot.
//
// Package pass: shipping roots are every package that can produce a main
// binary — loaded packages named "main" and skipped packages whose
// recovered package clauses include "main" (the loader's single Name is
// not proof of non-rootness: a directory mixing foo.go and main.go still
// reports one name while yielding a main). Packages enter the closure
// only through product import edges from a root: type-level imports for
// valid packages, the syntactically recovered import set
// (ix.skippedImports) for skipped ones. Recognized entrypoints and
// exported APIs do not pull a package into the closure on their own —
// they are function-level roots for packages already inside it.
//
// The graph is complete only when every reachable node showed all its
// edges: a reachable package with unrecoverable or partially recovered
// imports, with plugin/linkname/cgo materialization, or without a
// resolvable module path keeps the closure open — unseen edges may lead
// anywhere. Problems confined to proven-DEAD packages — unrecovered
// imports, unparsed bodies, dynamic-link surface — never reopen the
// scope, but a package that cannot be proven a non-root (no recoverable
// package clause at all) keeps it open: it may be a hidden main. With
// no main package nothing is a proven shipping root and every package
// stays UNKNOWN (library-only snapshots never yield DEAD).
//
// Function pass (live packages only): roots are init, main, recognized
// entrypoints and exported functions/methods — exported symbols are
// conservatively callable from outside the module. Edges come from the
// shared moduleEdgesSites builder (direct/method calls, resolved
// function values, interface dispatch with instantiation narrowing,
// goroutine calls); opaque dispatch sites and function-value escapes
// propagate UNKNOWN rather than fabricating absence.
func (ix *Index) buildUnreachabilityScope(ctx context.Context) (*unreachabilityScope, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	ctx = ix.ctxOr(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := ix.load(ctx); err != nil {
		return nil, err
	}
	source, scopeKey := ix.snapshotKeysLocked()
	return ix.unreachabilityScopeLocked(ctx, source, scopeKey)
}

// cloneForModuleCone returns a shallow copy of the snapshot scope with the
// per-verification module-cone half reset. The package and product function
// graphs are immutable after construction and stay shared; only
// ModuleFunctions and DependencyGraphComplete are written by the verifier,
// so every verification folds its own dependency verdicts into its own copy
// and the cached snapshot scope is never mutated.
func (s *unreachabilityScope) cloneForModuleCone() *unreachabilityScope {
	if s == nil {
		return nil
	}
	out := *s
	out.ModuleFunctions = map[string]map[string]reachabilityState{}
	out.DependencyGraphComplete = false
	return &out
}

// newUnreachabilityScope allocates the empty verdict set both scope
// builders populate.
func newUnreachabilityScope() *unreachabilityScope {
	return &unreachabilityScope{
		ProductPackages:  map[string]reachabilityState{},
		ProductFunctions: map[functionKey]reachabilityState{},
		ModuleEntries:    map[string][]domain.CallSite{},
		ModuleFunctions:  map[string]map[string]reachabilityState{},
		livePkgs:         map[string]bool{},
		sigs:             map[functionKey]*types.Signature{},
		bareNames:        map[string][]functionKey{},
	}
}

// scopeBuildHook is a package-local test seam invoked at named stages of a
// shipping-scope construction ("package", "function"). Production leaves it
// nil; tests use it to cancel the caller's context mid-construction and
// prove that neither a partial scope nor a partial cache entry survives.
var scopeBuildHook func(*Index, string)

// snapshotFingerprintLocked renders the content identity of the product
// snapshot the shipping scope is derived from: the effective build context
// plus every product source file the graph was computed over, content
// hashed. The memoized scope is valid only for an identical fingerprint —
// a source rewrite under the same path moves it and forces a rebuild
// instead of serving DEAD verdicts computed over different bytes. The
// fingerprint is recomputed per call and is deliberately content-based (not
// a size/mtime stamp): a same-size rewrite cannot slip through. Callers
// MUST hold ix.mu.
func (ix *Index) snapshotFingerprintLocked() string {
	h := sha256.New()
	write := func(parts ...string) {
		for _, p := range parts {
			h.Write([]byte(p))
			h.Write([]byte{0})
		}
	}
	write("dir", ix.Dir)
	write("goos", ix.Build.GOOS, "goarch", ix.Build.GOARCH,
		"cgo", fmt.Sprintf("%t", ix.Build.CGOEnabled),
		"vendor", fmt.Sprintf("%t", ix.Build.VendorMode),
		"tags", strings.Join(ix.Build.BuildTags, ","))
	write("env", strings.Join(ix.Env, "\x00"),
		"replaceenv", fmt.Sprintf("%t", ix.ReplaceEnv))
	// Product inventory: every loaded and skipped product package with the
	// exact build-selected source set the graph was derived from. The
	// records are sorted so the digest is order-stable.
	type pkgRecord struct {
		path, body string
	}
	records := make([]pkgRecord, 0, len(ix.pkgs)+len(ix.skippedPkgs))
	addPkg := func(path, name, module, dir string, files []string) {
		seen := map[string]bool{}
		var list []string
		for _, f := range files {
			if f != "" && !seen[f] {
				seen[f] = true
				list = append(list, f)
			}
		}
		sort.Strings(list)
		var body strings.Builder
		body.WriteString(path)
		body.WriteString("\x00" + name + "\x00" + module + "\x00")
		for _, f := range list {
			body.WriteString(f)
			body.WriteString("\x00")
			data, err := os.ReadFile(f)
			if err != nil {
				body.WriteString("!unreadable\x00")
				continue
			}
			sum := sha256.Sum256(data)
			body.WriteString(fmt.Sprintf("%x", sum[:]))
			body.WriteString("\x00")
		}
		if len(list) == 0 && dir == "" {
			// A synthetic census entry (a loader-reported package with no
			// source inventory of its own) carries no source identity: the
			// census identity covers its existence, so it stays out of the
			// content fingerprint.
			return
		}
		// Directory inventory: the load-time file lists cannot see a Go file
		// added or removed after the load, so the package directory is walked
		// on every fingerprint. Added, removed and renamed sources move the
		// digest even when every originally selected file is byte-identical.
		body.WriteString("dir=" + dir + "\x00")
		entries, derr := os.ReadDir(dir)
		if derr != nil {
			body.WriteString("!unreadable-dir\x00")
		} else {
			var names []string
			for _, e := range entries {
				if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
					continue
				}
				names = append(names, e.Name())
			}
			sort.Strings(names)
			for _, n := range names {
				body.WriteString(n)
				body.WriteString("\x00")
			}
		}
		records = append(records, pkgRecord{path: path, body: body.String()})
	}
	// pkgDir resolves the build-selected source directory of a product
	// package: the loader's Dir when present, else the first selected file's
	// directory.
	pkgDir := func(dir string, files []string) string {
		if dir != "" {
			return dir
		}
		for _, f := range files {
			if f != "" {
				return filepath.Dir(f)
			}
		}
		return ""
	}
	for _, p := range ix.pkgs {
		mod := ""
		if p.Module != nil {
			mod = moduleBinding(p.Module)
		}
		files := append(append(append([]string(nil), p.GoFiles...), p.CompiledGoFiles...), p.OtherFiles...)
		addPkg(p.PkgPath, p.Name, mod, pkgDir(p.Dir, files), files)
	}
	for path, p := range ix.skippedPkgs {
		if p == nil {
			records = append(records, pkgRecord{path: path, body: path + "\x00<nil-package>\x00"})
			continue
		}
		mod := ""
		if p.Module != nil {
			mod = moduleBinding(p.Module)
		}
		files := append(append(append([]string(nil), p.GoFiles...), p.CompiledGoFiles...), p.OtherFiles...)
		for _, f := range p.Syntax {
			if pos := ix.fset.Position(f.Package); pos.Filename != "" {
				files = append(files, pos.Filename)
			}
		}
		addPkg(path, p.Name, mod, pkgDir(p.Dir, files), files)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].path < records[j].path })
	for _, r := range records {
		write(r.body)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// censusIdentityLocked renders the loader-census facts the scope and closure
// reads beyond the source bytes: the skipped-package set, the recovered
// skipped import edges and the unscanned census. These are in-memory loader
// results, not on-disk source, so a change here invalidates the memoized
// observations without being snapshot drift.
func (ix *Index) censusIdentityLocked() string {
	h := sha256.New()
	write := func(parts ...string) {
		for _, p := range parts {
			h.Write([]byte(p))
			h.Write([]byte{0})
		}
	}
	skippedPaths := make([]string, 0, len(ix.skippedPkgs))
	for path := range ix.skippedPkgs {
		skippedPaths = append(skippedPaths, path)
	}
	sort.Strings(skippedPaths)
	write("skipped", strings.Join(skippedPaths, "\x00"))
	write("unscanned", strings.Join(ix.skippedUnscanned, "\x00"))
	importedPaths := make([]string, 0, len(ix.skippedImports))
	for imported := range ix.skippedImports {
		importedPaths = append(importedPaths, imported)
	}
	sort.Strings(importedPaths)
	for _, imported := range importedPaths {
		importers := append([]string(nil), ix.skippedImports[imported]...)
		sort.Strings(importers)
		write("skipped-edge", imported, strings.Join(importers, "\x00"))
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// snapshotKeysLocked returns the source-content fingerprint — the drift
// baseline captured at load time — and the memo key the scope/closure caches
// are bound to (source content plus the loader census identity).
func (ix *Index) snapshotKeysLocked() (source, key string) {
	source = ix.snapshotFingerprintLocked()
	return source, source + "|" + ix.censusIdentityLocked()
}

// unreachabilityScopePackageLocked builds the package-level half of the
// model — shipping roots, LIVE/DEAD/UNKNOWN package states and the
// completeness flag — without the per-function graph closure
// enumeration does not need. The construction is memoized for the loaded
// snapshot (extras never enter the product scope), so per-subject and
// per-condition queries reuse one build; the entry is bound to the
// snapshot's content fingerprint and dropped when the inventory or the
// source bytes move, and a construction interrupted by the caller's context
// is never published. Callers MUST hold ix.mu with the index already loaded.
func (ix *Index) unreachabilityScopePackageLocked(ctx context.Context, source, scopeKey string) (*unreachabilityScope, error) {
	if ix.loadedFingerprint != "" && source != ix.loadedFingerprint {
		// The snapshot changed after the load: the AST, type information and
		// importer census describe the pre-mutation bytes. Rebuilding from
		// them would publish DEAD/Complete over sources nobody analyzed, so
		// the query fails closed and drops every memoized observation.
		ix.scopeCachePackage = nil
		ix.scopeCacheFull = nil
		ix.scopeCacheFingerprint = ""
		return nil, fmt.Errorf("%w: product source inventory or content changed after the index load; the loaded AST is stale — reload the snapshot before analysing", ErrSnapshotMutated)
	}
	if ix.scopeCacheFingerprint != scopeKey {
		// A different (but still load-consistent) snapshot shape: no
		// memoized verdict set may survive it.
		ix.scopeCachePackage = nil
		ix.scopeCacheFull = nil
		ix.scopeCacheFingerprint = scopeKey
	}
	if ix.scopeCachePackage != nil {
		return ix.scopeCachePackage, nil
	}
	if ix.scopeCacheFull != nil {
		// The full scope carries the package half too.
		return ix.scopeCacheFull, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s := newUnreachabilityScope()
	if scopeBuildHook != nil {
		scopeBuildHook(ix, "package")
	}
	if err := s.buildPackageGraph(ctx, ix); err != nil {
		// Never publish an interrupted construction: a partially built
		// package graph could read DEAD where the finished one would not.
		ix.scopeCachePackage = nil
		ix.scopeCacheFull = nil
		return nil, err
	}
	// Final cancellation gate: a context cancelled during the last walk
	// must not publish, and must not count as a completed construction.
	if err := ctx.Err(); err != nil {
		ix.scopeCachePackage = nil
		ix.scopeCacheFull = nil
		return nil, err
	}
	// Count only completed, published constructions.
	ix.scopePackageBuilds++
	ix.scopeCachePackage = s
	return s, nil
}

// unreachabilityScopeLocked builds the full model — package graph plus
// the function graph live packages get — and memoizes it for the loaded
// snapshot, so per-subject and per-condition verification reuses one
// construction instead of rebuilding the whole product graph. The entry is
// bound to the snapshot fingerprint (a source rewrite or an inventory
// change drops it), and an interrupted function build clears both cache
// halves: a package half whose function verdicts were never produced must
// not be served as the cached scope. The returned scope is a shared
// read-only observation: a caller that folds per-verification dependency
// verdicts into it must work on cloneForModuleCone. Callers MUST hold ix.mu
// with the index already loaded.
func (ix *Index) unreachabilityScopeLocked(ctx context.Context, source, scopeKey string) (*unreachabilityScope, error) {
	if ix.scopeCacheFull != nil && ix.scopeCacheFingerprint == scopeKey {
		return ix.scopeCacheFull, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s, err := ix.unreachabilityScopePackageLocked(ctx, source, scopeKey)
	if err != nil {
		return nil, err
	}
	if scopeBuildHook != nil {
		scopeBuildHook(ix, "function")
	}
	if err := s.buildFunctionGraph(ctx, ix); err != nil {
		// The package half was published before the function half ran;
		// an interrupted graph must not leave either half behind.
		ix.scopeCachePackage = nil
		ix.scopeCacheFull = nil
		return nil, err
	}
	// Final cancellation gate before publication (see the package half).
	if err := ctx.Err(); err != nil {
		ix.scopeCachePackage = nil
		ix.scopeCacheFull = nil
		return nil, err
	}
	// Count only completed, published constructions.
	ix.scopeFunctionBuilds++
	ix.scopeCacheFull = s
	ix.scopeCacheFingerprint = scopeKey
	// The function graph is a superset of the package half; drop the
	// standalone entry so both accessors agree on one object.
	ix.scopeCachePackage = nil
	return s, nil
}

// ReachabilityState is the exported tri-state projection of the scoped
// model: LIVE (a path from a shipping root is proven), DEAD (absence of
// every path is proven inside a complete scope), UNKNOWN (neither).
type ReachabilityState string

const (
	ReachabilityLive    ReachabilityState = "LIVE"
	ReachabilityDead    ReachabilityState = "DEAD"
	ReachabilityUnknown ReachabilityState = "UNKNOWN"
)

// ShippingScope is the read-only projection of the product shipping
// scope: the proven main-package roots, the per-package tri-state
// verdict, the completeness flag and the reasons the scope stayed open.
// The wrapped classifier stays private — callers inspect verdicts
// through PackageState/SiteState, never the raw maps.
type ShippingScope struct {
	Roots          []string
	PackageStates  map[string]ReachabilityState
	Complete       bool
	UnknownReasons []string

	// scope is the immutable classifier backing the projections.
	scope *unreachabilityScope
}

// BuildShippingScope computes the shipping scope for the loaded
// snapshot. The result is immutable; maps and slices are fresh copies.
// The underlying scope construction is memoized per index, so repeated
// calls (one per subject or condition) reuse one build. A caller context
// that is already cancelled fails without publishing a partial scope, and
// an interrupted construction is never cached.
func (ix *Index) BuildShippingScope(ctx context.Context) (*ShippingScope, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	ctx = ix.ctxOr(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := ix.load(ctx); err != nil {
		return nil, err
	}
	source, scopeKey := ix.snapshotKeysLocked()
	scope, err := ix.unreachabilityScopeLocked(ctx, source, scopeKey)
	if err != nil {
		return nil, err
	}
	out := &ShippingScope{
		Roots:          append([]string(nil), scope.roots...),
		PackageStates:  make(map[string]ReachabilityState, len(scope.ProductPackages)),
		Complete:       scope.ProductGraphComplete,
		UnknownReasons: append([]string(nil), scope.unknownReasons...),
		scope:          scope,
	}
	for path := range scope.ProductPackages {
		out.PackageStates[path] = ReachabilityState(scope.packageState(path).String())
	}
	return out, nil
}

// PackageState reports the shipping-closure state of a product package
// path. Unknown paths are UNKNOWN — absence from the map is never
// evidence of deadness.
func (s *ShippingScope) PackageState(path string) ReachabilityState {
	if s == nil || s.scope == nil {
		return ReachabilityUnknown
	}
	return ReachabilityState(s.scope.packageState(path).String())
}

// SiteState maps an evidence site to the reachability state of its
// enclosing package/function — the folded verdict the reachability
// filter applies.
func (s *ShippingScope) SiteState(site domain.CallSite) ReachabilityState {
	if s == nil || s.scope == nil {
		return ReachabilityUnknown
	}
	return ReachabilityState(s.scope.classifySite(site).String())
}

// buildPackageGraph fills ProductPackages, livePkgs and
// ProductGraphComplete. The caller's context bounds the walk: a cancelled
// construction returns the context error and publishes nothing.
func (s *unreachabilityScope) buildPackageGraph(ctx context.Context, ix *Index) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Forward product→product edges for every known node: type-level
	// imports of valid packages plus the recovered import sets of
	// skipped ones.
	edges := map[string][]string{}
	edgeComplete := map[string]bool{}
	dynamicLink := map[string]bool{}
	isSkipped := map[string]bool{}
	isMain := map[string]bool{}
	// nonRootProven records that a skipped package provably cannot be a
	// shipping root: every non-test source file produced a recoverable
	// package clause and none said "main". p.Name alone is not that
	// proof — the loader reports one name for a directory mixing
	// foo.go and main.go, yet the main still links.
	nonRootProven := map[string]bool{}

	product := map[string]bool{}
	for _, p := range ix.pkgs {
		product[p.PkgPath] = true
	}
	for path := range ix.skippedPkgs {
		product[path] = true
		isSkipped[path] = true
	}

	// skippedForward inverts skippedImports to per-importer edge lists;
	// skippedForwardAll keeps the raw (non-product-filtered) sets for
	// edge-forging detection like cgo's "C" import.
	skippedForward := map[string]map[string]bool{}
	skippedForwardAll := map[string]map[string]bool{}
	for imported, importers := range ix.skippedImports {
		for _, imp := range importers {
			if skippedForward[imp] == nil {
				skippedForward[imp] = map[string]bool{}
			}
			if skippedForwardAll[imp] == nil {
				skippedForwardAll[imp] = map[string]bool{}
			}
			skippedForward[imp][imported] = true
			skippedForwardAll[imp][imported] = true
		}
	}

	processed := 0
	for _, p := range ix.pkgs {
		if err := ctx.Err(); err != nil {
			return err
		}
		seen := map[string]bool{}
		if p.Types != nil {
			for _, imp := range p.Types.Imports() {
				if product[imp.Path()] && !seen[imp.Path()] {
					seen[imp.Path()] = true
					edges[p.PkgPath] = append(edges[p.PkgPath], imp.Path())
				}
			}
		}
		sort.Strings(edges[p.PkgPath])
		// A valid package's import set is the complete type-checked set.
		edgeComplete[p.PkgPath] = true
		dynamicLink[p.PkgPath] = productFileDynamicLink(p.Syntax)
		isMain[p.PkgPath] = p.Name == "main"
		processed++
		if processed == 1 && scopeBuildHook != nil {
			// Progress seam: the graph now holds real content, so a
			// cancellation here exercises the mid-build cleanup path.
			scopeBuildHook(ix, "package-progress")
			if err := ctx.Err(); err != nil {
				return err
			}
		}
	}
	for path, p := range ix.skippedPkgs {
		if err := ctx.Err(); err != nil {
			return err
		}
		var list []string
		for imp := range skippedForward[path] {
			if product[imp] {
				list = append(list, imp)
			}
		}
		sort.Strings(list)
		edges[path] = list
		var raw []string
		for imp := range skippedForwardAll[path] {
			raw = append(raw, imp)
		}
		sort.Strings(raw)
		// Clause proof decides whether this package can be ruled out as
		// a shipping root; edge completeness and dynamic-link surface
		// follow, with safe defaults for a nil package record.
		clauseMain, nonRoot := skippedClauseProof(ix.fset, p)
		isMain[path] = clauseMain
		nonRootProven[path] = nonRoot
		if p == nil {
			continue // edgeComplete/dynamicLink stay at unsafe defaults
		}
		edgeComplete[path] = skippedEdgesComplete(ix.fset, p)
		dynamicLink[path] = productFileDynamicLink(p.Syntax) ||
			recoveredImportsHas(raw, "plugin") || recoveredImportsHas(raw, "C")
	}

	// Shipping roots: packages that can produce a main binary. The rest
	// of the root kinds act inside already-live packages.
	var roots []string
	for path := range product {
		if isMain[path] {
			roots = append(roots, path)
		}
	}
	sort.Strings(roots)
	s.roots = append([]string(nil), roots...)

	live := map[string]bool{}
	queue := append([]string{}, roots...)
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		if live[p] {
			continue
		}
		live[p] = true
		queue = append(queue, edges[p]...)
	}
	s.livePkgs = live
	s.pkgPaths = s.pkgPaths[:0]
	for path := range product {
		s.pkgPaths = append(s.pkgPaths, path)
	}
	sort.Slice(s.pkgPaths, func(i, j int) bool {
		return len(s.pkgPaths[i]) > len(s.pkgPaths[j])
	})

	// The scope is complete only when the root set is proven closed and
	// every reachable node exposed all its edges. Split the checks by
	// reachability:
	//   - a skipped package whose non-rootness cannot be proven (no
	//     recoverable package clause, or an importer path the load
	//     never recorded) may be a hidden main: it keeps the scope open
	//     wherever it sits;
	//   - a reachable package with unrecovered imports or a
	//     dynamic-link surface (plugin/linkname/cgo) hides edges the
	//     graph cannot see: open scope;
	//   - a reachable package without a resolvable module path breaks
	//     the module-scoped edge builder: open scope;
	//   - problems inside an unreachable package — unrecovered imports,
	//     unparsed bodies, cgo/plugin surface — change nothing once the
	//     root set is closed: they belong to a DEAD node.
	reasons := map[string]bool{}
	if len(roots) == 0 {
		reasons["no main package identified; every product package is a potential shipping root"] = true
	}
	for path := range isSkipped {
		if !nonRootProven[path] {
			reasons["product package "+path+
				" cannot be proven a non-root: no recoverable package clause (possible hidden main)"] = true
		}
	}
	for _, importers := range ix.skippedImports {
		for _, imp := range importers {
			if !product[imp] {
				reasons["skipped importer "+imp+
					" is not in the product inventory: its root status is unverifiable"] = true
			}
		}
	}
	for p := range live {
		if !edgeComplete[p] {
			reasons["reachable product package "+p+
				" has an incomplete recovered import set: invisible edges may reach anywhere"] = true
		}
		if dynamicLink[p] {
			reasons["reachable product package "+p+
				" can forge edges the static import graph cannot see (plugin/linkname/cgo)"] = true
		}
	}
	// A live package whose module membership cannot be resolved breaks
	// the module-scoped shared edge builder — its edges would be
	// silently dropped. This check lives in the package pass so
	// completeness is final before any DEAD verdict is published.
	for _, p := range ix.pkgs {
		if live[p.PkgPath] && (p.Module == nil || p.Module.Path == "") {
			reasons["reachable product package "+p.PkgPath+
				" has no resolvable module path: its edge set cannot be verified"] = true
		}
	}
	s.unknownReasons = sortedBoolKeys(reasons)
	complete := len(s.unknownReasons) == 0

	for path := range product {
		switch {
		case len(roots) == 0:
			// Library-only snapshot: no confirmed shipping root —
			// nothing is provably dead.
			s.ProductPackages[path] = reachUnknown
		case live[path]:
			if isSkipped[path] && (!edgeComplete[path] || skippedUnscannedPath(ix, path)) {
				// A reachable skipped package whose imports or
				// syntax could not be fully recovered stays
				// UNKNOWN — its edges are only partially visible.
				s.ProductPackages[path] = reachUnknown
				continue
			}
			s.ProductPackages[path] = reachLive
		case isSkipped[path] && !nonRootProven[path]:
			// Possible hidden main: never DEAD. The completeness
			// flag is already false for this same reason.
			s.ProductPackages[path] = reachUnknown
		case complete:
			// Unreachable from every proven root with the root set
			// closed: the package cannot run no matter what its own
			// (possibly invisible) edges contain.
			s.ProductPackages[path] = reachDead
		default:
			s.ProductPackages[path] = reachUnknown
		}
	}
	s.ProductGraphComplete = complete
	return nil
}

// sortedBoolKeys returns the keys of a set map in sorted order.
func sortedBoolKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// skippedClauseProof decides, for a skipped product package, whether it
// can produce a main binary and whether it can be proven not to. The
// loader's p.Name reports only one name even when sibling files declare
// conflicting clauses, so a skipped package's non-rootness stands on a
// clause-level scan: every non-test Go source the build inventory lists
// (attached syntax plus on-disk files) must yield a recovered clause,
// and none may say "main".
//
// hasMain is true when any recovered clause — or the loader name —
// declares package main. nonRootProven is true only when the file
// inventory is non-empty, every entry produced a clause and none was
// main. An empty inventory is never proof: a package whose file list
// was lost to a load failure may still contain a main, so absence of
// evidence stays UNKNOWN — never DEAD.
func skippedClauseProof(fset *token.FileSet, p *packages.Package) (hasMain, nonRootProven bool) {
	if p == nil {
		return false, false
	}
	type src struct {
		name string
		file *ast.File
	}
	seen := map[string]bool{}
	var sources []src
	addFile := func(name string, f *ast.File) {
		if name != "" && (seen[name] || strings.HasSuffix(name, "_test.go")) {
			return
		}
		if name != "" {
			seen[name] = true
		}
		sources = append(sources, src{name: name, file: f})
	}
	for _, f := range p.Syntax {
		if f == nil {
			continue
		}
		name := ""
		if pos := fset.Position(f.Pos()); pos.Filename != "" {
			name = pos.Filename
		}
		addFile(name, f)
	}
	files := append(append([]string{}, p.GoFiles...), p.CompiledGoFiles...)
	for _, path := range files {
		if !strings.HasSuffix(path, ".go") {
			continue
		}
		addFile(path, nil)
	}

	for _, s0 := range sources {
		f := s0.file
		if f == nil {
			var err error
			f, err = parser.ParseFile(fset, s0.name, nil, parser.PackageClauseOnly)
			if err != nil || f == nil {
				// The clause could not be recovered for this file:
				// the package may still be a hidden main — the proof
				// fails closed on the whole package.
				return hasMain, false
			}
		}
		if f.Name == nil {
			// An AST without a package clause is not a clause
			// recovery: same fail-closed outcome as an unreadable
			// file.
			return hasMain, false
		}
		if f.Name.Name == "main" {
			hasMain = true
		}
	}
	if p.Name == "main" {
		// The loader reported a main package; even when the clause
		// scan disagrees the conservative verdict stands.
		hasMain = true
	}
	if hasMain {
		return true, true
	}
	if len(sources) == 0 {
		// No inventory to verify: an empty file list is a metadata
		// gap, not evidence the directory cannot build a main. The
		// package is never proven a non-root.
		return false, false
	}
	return false, true
}

// failClosed reopens the product scope: the closure flag drops to
// false and every previously published DEAD verdict — packages and
// functions alike — normalizes to UNKNOWN. Callers that discover a
// completeness gap after verdicts were published must go through this
// path; setting ProductGraphComplete directly would leave stale DEAD
// states reachable through the raw maps.
func (s *unreachabilityScope) failClosed() {
	s.ProductGraphComplete = false
	for p, st := range s.ProductPackages {
		if st == reachDead {
			s.ProductPackages[p] = reachUnknown
		}
	}
	for k, st := range s.ProductFunctions {
		if st == reachDead {
			s.ProductFunctions[k] = reachUnknown
		}
	}
}

// skippedUnscannedPath reports whether path is one of the packages whose
// source could not be parsed at all during load.
func skippedUnscannedPath(ix *Index, path string) bool {
	for _, u := range ix.skippedUnscanned {
		if u == path {
			return true
		}
	}
	return false
}

// skippedEdgesComplete reports whether the recovered import set of a
// skipped package covers every non-test Go source it lists: a file that
// failed to parse (its syntax may still attach under error recovery) or
// that cannot be re-parsed means invisible edges, so the closure must
// stay open.
func skippedEdgesComplete(fset *token.FileSet, p *packages.Package) bool {
	if p == nil {
		return false
	}
	for _, e := range p.Errors {
		if e.Kind == packages.ParseError {
			return false
		}
	}
	seen := map[string]bool{}
	for _, f := range p.Syntax {
		if pos := fset.Position(f.Pos()); pos.Filename != "" {
			seen[pos.Filename] = true
		}
	}
	files := append(append([]string{}, p.GoFiles...), p.CompiledGoFiles...)
	for _, path := range files {
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			continue
		}
		if seen[path] {
			continue
		}
		if _, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly); err != nil {
			return false
		}
	}
	return true
}

// productFileDynamicLink reports whether any syntax file can forge
// edges the static import graph cannot see: plugin imports, cgo
// ("import \"C\"") or go:linkname directives. Presence in a reachable
// package keeps the scope open.
func productFileDynamicLink(files []*ast.File) bool {
	for _, f := range files {
		if f == nil {
			continue
		}
		for _, imp := range f.Imports {
			switch strings.Trim(imp.Path.Value, `"`) {
			case "plugin", "C":
				return true
			}
		}
		for _, cg := range f.Comments {
			for _, cm := range cg.List {
				if strings.HasPrefix(cm.Text, "//go:linkname") {
					return true
				}
			}
		}
	}
	return false
}

func recoveredImportsHas(imports []string, want string) bool {
	for _, imp := range imports {
		if imp == want {
			return true
		}
	}
	return false
}

// buildFunctionGraph fills ProductFunctions for functions in live
// packages. Non-live packages need no per-function verdict: their
// package state answers every site inside them. The caller's context
// bounds the walk: a cancelled construction returns the context error and
// publishes nothing.
func (s *unreachabilityScope) buildFunctionGraph(ctx context.Context, ix *Index) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !s.ProductGraphComplete {
		return nil
	}
	var live []*packages.Package
	for _, p := range ix.pkgs {
		if err := ctx.Err(); err != nil {
			return err
		}
		if s.livePkgs[p.PkgPath] {
			live = append(live, p)
		}
	}
	s.livePkgList = live
	if len(live) == 0 {
		return nil
	}
	// The product graph spans all loaded product modules; build it per
	// module path because the shared edge builder is module-scoped.
	modules := map[string][]*packages.Package{}
	for _, p := range live {
		mod := ""
		if p.Module != nil {
			mod = p.Module.Path
		}
		if mod == "" {
			// Unresolvable membership: the shared builder cannot
			// partition edges without a module path, so the graph is
			// not provably complete. failClosed also normalizes any
			// already-published DEAD verdicts back to UNKNOWN.
			s.failClosed()
			return nil
		}
		modules[mod] = append(modules[mod], p)
	}

	// Node inventory + roots. Every live package also gets an "init"
	// sentinel node — package-level statements (var initializers,
	// func-valued var writes) execute at package init even when no
	// explicit init function exists.
	roots := map[functionKey]bool{}
	declared := map[functionKey]bool{}
	inventoried := 0
	for _, p := range live {
		if err := ctx.Err(); err != nil {
			return err
		}
		info := p.TypesInfo
		sentinel := functionKey{Package: p.PkgPath, Symbol: "init"}
		declared[sentinel] = true
		roots[sentinel] = true
		s.ProductFunctions[sentinel] = reachUnknown
		for _, f := range p.Syntax {
			if ix.isTestFile(f) {
				continue
			}
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Name == nil {
					continue
				}
				sym := fn.Name.Name
				if fn.Recv != nil && len(fn.Recv.List) > 0 {
					sym = recvDeclName(fn.Recv.List[0].Type) + "." + sym
				}
				key := functionKey{Package: p.PkgPath, Symbol: sym}
				if !declared[key] {
					declared[key] = true
					s.ProductFunctions[key] = reachUnknown
					if info != nil {
						if obj, ok := info.Defs[fn.Name].(*types.Func); ok {
							if sig, ok := obj.Type().(*types.Signature); ok {
								s.sigs[key] = sig
							}
						}
					}
				}
				switch {
				case fn.Name.Name == "init":
					roots[key] = true
				case p.Name == "main" && fn.Name.Name == "main":
					roots[key] = true
				case entrypointKind(p, fn) != "":
					roots[key] = true
				case ast.IsExported(fn.Name.Name):
					// Exported functions and methods are
					// conservatively callable from outside the
					// shipping boundary.
					roots[key] = true
				}
			}
			// Bounded mid-walk cancellation: a single huge file must not
			// defer the caller's cancellation to the next package.
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		inventoried++
		if inventoried == 1 && scopeBuildHook != nil {
			// Progress seam: the function inventory now holds real nodes.
			scopeBuildHook(ix, "function-progress")
			if err := ctx.Err(); err != nil {
				return err
			}
		}
	}

	// Resolved edges + opaque dispatch sites from the shared builder.
	// The builder's interface-impl edges are keyed through interface
	// pseudo-nodes ("pkg.Iface.Method") that never match a declared
	// function — they are kept in `pseudo` and expanded below into
	// caller→impl may edges (dispatch may reach the impl; it does not
	// prove the impl runs).
	certain := map[functionKey][]functionKey{}
	var mayEdges []funcEdge
	pseudo := map[string]map[string]bool{}
	var opaque []scopeOpaque
	for mod, pkgs := range modules {
		if err := ctx.Err(); err != nil {
			return err
		}
		edges, opaqueSites := ix.moduleEdgesSites(pkgs, mod)
		for caller, callees := range edges {
			ck, cok := s.keyOf(caller)
			callerIsPseudo := !cok && s.isProductKey(caller)
			for callee := range callees {
				tk, tok := s.keyOf(callee)
				switch {
				case cok && tok:
					certain[ck] = append(certain[ck], tk)
				case cok && s.isProductKey(callee):
					// Declared caller reaches an interface pseudo-node.
					if pseudo[caller] == nil {
						pseudo[caller] = map[string]bool{}
					}
					pseudo[caller][callee] = true
				case !cok && tok && callerIsPseudo:
					// Pseudo-node reaches a declared impl.
					if pseudo[caller] == nil {
						pseudo[caller] = map[string]bool{}
					}
					pseudo[caller][callee] = true
				}
			}
		}
		for caller, sites := range opaqueSites {
			ck, ok := s.keyOf(caller)
			if !ok {
				continue
			}
			for _, site := range sites {
				opaque = append(opaque, scopeOpaque{caller: ck, site: site})
			}
		}
	}
	// Expand pseudo-node transit: declared caller → iface pseudo-node →
	// declared impl becomes caller→impl may edges.
	for pnode, targets := range pseudo {
		ck, cok := s.keyOf(pnode)
		if !cok {
			continue // pseudo-node itself — transit handled below
		}
		for callee := range targets {
			if _, ok := s.keyOf(callee); ok {
				continue
			}
			// callee is another pseudo-node: caller→P1, look up P1→impl.
			for impl := range pseudo[callee] {
				if tk, ok := s.keyOf(impl); ok {
					mayEdges = append(mayEdges, funcEdge{from: ck, to: tk})
				}
			}
		}
	}

	// Second pass over source, walking declaration boundaries so
	// package-level statements attribute to the package's "init"
	// sentinel: calls the shared builder drops for lack of a FuncDecl
	// context (var initializers), generic-instantiation calls (real
	// edges plus opaque-site dedup), interface calls whose interface is
	// declared outside the product module (impls invisible → opaque),
	// dependency-module entries, and function-value escapes — a
	// *types.Func used anywhere except a call callee position is
	// materialized into data, so its callers are unbounded.
	type escape struct {
		from functionKey
		to   functionKey
	}
	var escapes []escape
	type sigShape struct {
		params, results int
	}
	shapes := map[functionKey][]sigShape{}
	for _, p := range live {
		if err := ctx.Err(); err != nil {
			return err
		}
		info := p.TypesInfo
		if info == nil {
			continue
		}
		initKey := functionKey{Package: p.PkgPath, Symbol: "init"}
		for _, f := range p.Syntax {
			if ix.isTestFile(f) {
				continue
			}
			callees := map[ast.Expr]bool{}
			ast.Inspect(f, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					callees[calleeExpr(call.Fun)] = true
				}
				return true
			})
			// Calls — including package-level ones the shared builder
			// could not attribute (caller=="" or stale last-seen
			// FuncDecl). Sources are keyed by their true enclosing
			// declaration, or the init sentinel.
			for _, decl := range f.Decls {
				var enc *ast.FuncDecl
				from := initKey
				if fd, ok := decl.(*ast.FuncDecl); ok && fd.Name != nil {
					enc = fd
					from = s.callerKeyOf(p, fd)
				}
				if !declared[from] {
					continue
				}
				ast.Inspect(decl, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					fun := ast.Unparen(call.Fun)
					inner := fun
					generic := false
					switch e := fun.(type) {
					case *ast.IndexExpr:
						inner, generic = e.X, true
					case *ast.IndexListExpr:
						inner, generic = e.X, true
					}
					fn, _ := calleeObject(info, inner).(*types.Func)
					if fn == nil || fn.Pkg() == nil {
						return true
					}
					if enc == nil {
						// Package-level call the shared builder never
						// saw — record the direct edge under init.
						to := functionKey{Package: fn.Pkg().Path(), Symbol: fn.Name()}
						if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
							to.Symbol = recvTypeName(sig.Recv().Type()) + "." + fn.Name()
						}
						if declared[to] {
							certain[from] = append(certain[from], to)
						}
					}
					// Interface dispatch on an interface declared
					// outside the product module: the shared builder's
					// impl linking cannot see it — the dispatch stays
					// opaque even when the impl is product code.
					if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
						if iface, ok := sig.Recv().Type().Underlying().(*types.Interface); ok {
							if _, isProduct := s.ProductPackages[fn.Pkg().Path()]; !isProduct {
								opaque = append(opaque, scopeOpaque{caller: from, site: opaqueSite{iface: iface}})
							}
						}
					}
					if generic {
						to := functionKey{Package: fn.Pkg().Path(), Symbol: fn.Name()}
						if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
							to.Symbol = recvTypeName(sig.Recv().Type()) + "." + fn.Name()
						}
						if declared[to] {
							certain[from] = append(certain[from], to)
						}
						if tv, ok := info.Types[fun]; ok && tv.Type != nil {
							if sig, ok := tv.Type.Underlying().(*types.Signature); ok {
								shapes[from] = append(shapes[from],
									sigShape{sig.Params().Len(), sig.Results().Len()})
							}
						}
					}
					cp := fn.Pkg().Path()
					if _, isProduct := s.ProductPackages[cp]; !isProduct {
						if mod := ix.depModuleOf(cp); mod != "" {
							site := ix.siteOf(p, enc, call)
							site.Callee = cp + "." + fn.Name()
							if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
								site.Callee = cp + "." + recvTypeName(sig.Recv().Type()) + "." + fn.Name()
							}
							s.ModuleEntries[mod] = append(s.ModuleEntries[mod], site)
						}
					}
					return true
				})
			}
			// Escapes — value uses of *types.Func outside call callee
			// position, attributed by their true enclosing declaration.
			for _, decl := range f.Decls {
				from := initKey
				if fd, ok := decl.(*ast.FuncDecl); ok && fd.Name != nil {
					from = s.callerKeyOf(p, fd)
				}
				if !declared[from] {
					continue
				}
				ast.Inspect(decl, func(n ast.Node) bool {
					expr, ok := n.(ast.Expr)
					if !ok {
						return true
					}
					base := expr
					switch e := expr.(type) {
					case *ast.IndexExpr:
						base = e.X
					case *ast.IndexListExpr:
						base = e.X
					}
					if callees[expr] || callees[base] {
						return true
					}
					fn, ok := funcOfExpr(info, base)
					if !ok {
						return true
					}
					to := functionKey{Package: fn.Pkg().Path(), Symbol: fn.Name()}
					if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
						to.Symbol = recvTypeName(sig.Recv().Type()) + "." + fn.Name()
					}
					if !declared[to] {
						return true // escapes into non-product code are not graph nodes
					}
					escapes = append(escapes, escape{from: from, to: to})
					return true
				})
			}
		}
	}
	for mod := range s.ModuleEntries {
		s.ModuleEntries[mod] = dedupCallSites(s.ModuleEntries[mod])
	}
	// Drop opaque sites a resolved generic call produced for the same
	// caller and arity shape — a resolved instantiation is an edge,
	// not unresolved dispatch.
	if len(shapes) > 0 {
		var kept []scopeOpaque
		for _, o := range opaque {
			matched := false
			if o.site.sig != nil {
				pn, rn := o.site.sig.Params().Len(), o.site.sig.Results().Len()
				for _, rs := range shapes[o.caller] {
					if rs.params == pn && rs.results == rn {
						matched = true
						break
					}
				}
			}
			if !matched {
				kept = append(kept, o)
			}
		}
		opaque = kept
	}

	// LIVE propagation over resolved edges. reachUnknown is the map's
	// zero value, so "unset" must mean dead-candidate — liveness and
	// uncertainty are tracked as explicit sets, never inferred from the
	// zero state.
	liveSet := map[functionKey]bool{}
	unknownSet := map[functionKey]bool{}
	queue := make([]functionKey, 0, len(roots))
	for r := range roots {
		if !liveSet[r] {
			liveSet[r] = true
			queue = append(queue, r)
		}
	}
	for len(queue) > 0 {
		k := queue[0]
		queue = queue[1:]
		for _, next := range certain[k] {
			if declared[next] && !liveSet[next] {
				liveSet[next] = true
				queue = append(queue, next)
			}
		}
	}
	sourceOpen := func(k functionKey) bool {
		return liveSet[k] || unknownSet[k]
	}
	markUnknown := func(d functionKey) bool {
		if !declared[d] || liveSet[d] || unknownSet[d] {
			return false
		}
		unknownSet[d] = true
		return true
	}
	for changed := true; changed; {
		changed = false
		for src, dsts := range certain {
			if !unknownSet[src] {
				continue
			}
			for _, d := range dsts {
				if markUnknown(d) {
					changed = true
				}
			}
		}
		for _, e := range mayEdges {
			if sourceOpen(e.from) && markUnknown(e.to) {
				changed = true
			}
		}
		for _, e := range escapes {
			if sourceOpen(e.from) && markUnknown(e.to) {
				changed = true
			}
		}
		for _, o := range opaque {
			if !sourceOpen(o.caller) {
				continue
			}
			for fn := range declared {
				if liveSet[fn] || unknownSet[fn] {
					continue
				}
				if s.opaqueCompatible(o.site, fn) && markUnknown(fn) {
					changed = true
				}
			}
		}
	}
	for fn := range declared {
		switch {
		case liveSet[fn]:
			s.ProductFunctions[fn] = reachLive
		case unknownSet[fn]:
			s.ProductFunctions[fn] = reachUnknown
		default:
			s.ProductFunctions[fn] = reachDead
		}
	}
	s.indexFunctions()
	return nil
}

// funcEdge is one caller→callee may edge.
type funcEdge struct {
	from functionKey
	to   functionKey
}

// callerKeyOf returns the graph key of the function declaration — the
// same naming moduleEdgesSites uses for its caller keys.
func (s *unreachabilityScope) callerKeyOf(p *packages.Package, enc *ast.FuncDecl) functionKey {
	sym := ""
	if enc != nil && enc.Name != nil {
		sym = enc.Name.Name
		if enc.Recv != nil && len(enc.Recv.List) > 0 {
			sym = recvDeclName(enc.Recv.List[0].Type) + "." + sym
		}
	}
	return functionKey{Package: p.PkgPath, Symbol: sym}
}

// isProductKey reports whether a "pkg.Name"-style key names a product
// package — the interface pseudo-node shape (or any product key whose
// symbol is not a declared function).
func (s *unreachabilityScope) isProductKey(k string) bool {
	for _, p := range s.pkgPaths {
		if strings.HasPrefix(k, p+".") {
			return true
		}
	}
	return false
}

// keyOf parses a "pkg.Name"/"pkg.Recv.Name" caller/callee string into a
// functionKey by matching a known product package prefix — package paths
// contain dots, so last-dot splitting would mis-key symbols. When one
// path is a dot-prefix of another ("a.b" vs "a.b.c") every matching
// prefix is tried and the declared symbol wins.
func (s *unreachabilityScope) keyOf(k string) (functionKey, bool) {
	for _, p := range s.pkgPaths {
		if !strings.HasPrefix(k, p+".") {
			continue
		}
		key := functionKey{Package: p, Symbol: k[len(p)+1:]}
		if _, ok := s.ProductFunctions[key]; ok {
			return key, true
		}
	}
	return functionKey{}, false
}

// opaqueCompatible reports whether the function could be the target of
// an unresolved dispatch site. A signature-typed site constrains by
// arity — exact signature identity is unsound across generic
// instantiation (a func(T) declaration vs a func(int) site must still
// match); an interface-typed site constrains by method name plus
// implementability when the receiver type is known (a receiver that
// cannot implement the interface can never dispatch); a fully opaque
// site matches everything.
func (s *unreachabilityScope) opaqueCompatible(site opaqueSite, fn functionKey) bool {
	if site.sig == nil && site.iface == nil {
		return true
	}
	if site.iface != nil {
		name := fn.Symbol
		recv := ""
		if i := strings.LastIndexByte(name, '.'); i >= 0 {
			recv, name = name[:i], name[i+1:]
		}
		found := false
		for i := range site.iface.NumMethods() {
			if site.iface.Method(i).Name() == name {
				found = true
				break
			}
		}
		if !found {
			return false
		}
		if recv == "" {
			// A plain function named like an interface method can still
			// be stored and invoked behind values — never narrow.
			return true
		}
		// A method on a named receiver is incompatible only when the
		// receiver type provably cannot implement the interface.
		pkg := s.findPackage(fn.Package)
		if pkg == nil || pkg.Types == nil {
			return true
		}
		obj := pkg.Types.Scope().Lookup(recv)
		tn, ok := obj.(*types.TypeName)
		if !ok {
			return true // alias/parameterized receiver — never narrow
		}
		if named, ok := tn.Type().(*types.Named); ok &&
			named.TypeParams() != nil && named.TypeParams().Len() > 0 {
			return true // generic receiver — one conservative node
		}
		if types.Implements(types.NewPointer(tn.Type()), site.iface) ||
			types.Implements(tn.Type(), site.iface) {
			return true
		}
		return false
	}
	sig, ok := s.sigs[fn]
	if !ok || sig == nil {
		return true // declaration signature unknown — never narrow to dead
	}
	if site.sig.Variadic() || sig.Variadic() {
		return true
	}
	return site.sig.Params().Len() == sig.Params().Len() &&
		site.sig.Results().Len() == sig.Results().Len()
}

// findPackage returns the live product package with the given path.
func (s *unreachabilityScope) findPackage(path string) *packages.Package {
	for _, p := range s.livePkgList {
		if p.PkgPath == path {
			return p
		}
	}
	return nil
}

// calleeExpr strips parens and generic instantiation wrappers to the
// expression a call actually resolves through.
func calleeExpr(fun ast.Expr) ast.Expr {
	for {
		switch e := fun.(type) {
		case *ast.ParenExpr:
			fun = e.X
		case *ast.IndexExpr:
			fun = e.X
		case *ast.IndexListExpr:
			fun = e.X
		default:
			return fun
		}
	}
}

// funcOfExpr resolves an expression node to the *types.Func it denotes
// when it is a function/method value use (identifier or selector);
// definitions (Defs entries, FuncDecl names) never count as uses.
func funcOfExpr(info *types.Info, expr ast.Expr) (*types.Func, bool) {
	var obj types.Object
	switch e := expr.(type) {
	case *ast.Ident:
		obj = info.Uses[e]
	case *ast.SelectorExpr:
		if sel, ok := info.Selections[e]; ok {
			obj = sel.Obj()
		} else {
			obj = info.Uses[e.Sel]
		}
	default:
		return nil, false
	}
	fn, ok := obj.(*types.Func)
	if !ok || fn.Pkg() == nil {
		return nil, false
	}
	return fn, true
}

// indexFunctions builds the bare-name index candidateKeys uses —
// deterministic order for a deterministic model.
func (s *unreachabilityScope) indexFunctions() {
	for k := range s.ProductFunctions {
		name := k.Symbol
		if i := strings.LastIndexByte(name, '.'); i >= 0 {
			name = name[i+1:]
		}
		bk := k.Package + "|" + name
		s.bareNames[bk] = append(s.bareNames[bk], k)
	}
	for bk := range s.bareNames {
		keys := s.bareNames[bk]
		sort.Slice(keys, func(i, j int) bool { return keys[i].Symbol < keys[j].Symbol })
	}
}

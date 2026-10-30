package goanalysis

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/parser"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/davniy/izyan/internal/affected"
	"github.com/davniy/izyan/internal/domain"
)

// MaxSearchMatches is the cap SearchSource applies to returned matches;
// results at the cap are truncated rather than exhaustive.
const MaxSearchMatches = maxSearchMatches

// MayCallSite is one site that may invoke the subject, carrying the
// confidence of the may-call analysis: Possible marks sites where the
// resolved target set is incomplete (signature-compatible candidates
// rather than proven callers).
type MayCallSite struct {
	domain.CallSite
	Possible bool `json:"possible,omitempty"`
}

// MayCallSites is a read-only facade over the may-call scan the verifier
// uses internally: it returns static call sites plus interface-dispatch
// and function-value sites whose candidate set contains (or could
// contain) ref. It is strictly broader than FindCallers — FindCallers
// reports only statically named calls — but still bounded to the loaded
// scope (product roots plus retained dependency extras); package loading
// failures elsewhere leave the result an under-approximation, which the
// Partial flag and SkippedPackages report honestly.
//
// The second return value is true whenever the enumeration is open: a
// site with an unresolved candidate set (Possible), the empty-coverage
// sentinel, an extras-generation change the settle retries could not
// freeze, an exhausted bound, or a subject module that would not load.
// ([], false, nil) is the only closed empty result — an empty site list
// proves nothing while the flag is set.
func (ix *Index) MayCallSites(ctx context.Context, ref domain.SymbolRef) ([]MayCallSite, bool, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ctx); err != nil {
		return nil, false, err
	}
	pkg := ix.pkgByPath(ctx, ref.Package)
	if pkg == nil {
		return nil, false, ErrSymbolNotFoundInPackage
	}
	var unpin func()
	if !ix.isProductPkg(pkg) && pkg.Module != nil {
		// The subject's whole module stays resident for the scan:
		// dep-scope callerScope covers the retained extras, and evicting
		// or re-loading the active advisory module mid-enumeration would
		// churn the extras generation and silently shrink the caller set.
		pattern := pkg.Module.Path + "/..."
		if _, lerr := ix.loadExtra(ctx, pattern); lerr != nil {
			// A failed pin widens coverage rather than narrowing it —
			// report the enumeration partial like the previous
			// single-loop implementation did.
			sites, _, _, err := ix.mayCallScan(ctx, ref)
			return sites, true, err
		}
		unpin = ix.pinExtraScoped(pattern)
	}
	if unpin != nil {
		defer unpin()
	}
	sites, partial, _, err := ix.mayCallScan(ctx, ref)
	return sites, partial, err
}

// mayCallScan is the pin-and-scan core of MayCallSites without its own
// lock/load/pin lifecycle: callers hold ix.mu with the index loaded and
// any module pinning they need already arranged. The third return value
// distinguishes enumeration uncertainty that is bound to no concrete
// site (an extras-churn sentinel — coverage is open somewhere unknown)
// from site-local `Possible` flags that the caller can filter itself:
// unscoped partial can never be discarded by site filtering.
func (ix *Index) mayCallScan(ctx context.Context, ref domain.SymbolRef) ([]MayCallSite, bool, bool, error) {
	pkg := ix.pkgByPath(ctx, ref.Package)
	if pkg == nil {
		return nil, false, false, ErrSymbolNotFoundInPackage
	}
	refs := ix.callersOf(pkg, ref)
	out := make([]MayCallSite, 0, len(refs))
	partial := false
	unscopedPartial := false
	for _, r := range refs {
		s := MayCallSite{CallSite: r.Site, Possible: r.possible}
		if s.File == "" && s.Line == 0 && s.Function == "" {
			// Sentinel from callersOf marking open coverage (a mid-scan
			// extras-generation change, scan re-entry, or open
			// func-value coverage with no site to point at): no site,
			// but the empty list must not read as closed.
			partial = true
			unscopedPartial = true
			continue
		}
		if r.possible {
			partial = true
		}
		out = append(out, s)
	}
	return out, partial, unscopedPartial, nil
}

// SkippedPackage is the structured record of one product package the
// loader could not type-check: it stays in the scope denominator even
// though typed scans never saw its contents. Path is the package path
// (the loader ID when the path itself is unavailable); Imports are the
// import edges recovered syntactically — empty when the package had no
// recoverable imports, which is a syntactic fact, not proof the package
// was empty; ImportsComplete reports whether that recovery covered every
// listed source file (only a complete set can prove a missing edge);
// Errors carry the loader's own diagnostics (the compiler text behind
// prerequisite/build failures such as a missing system header);
// SourceVisible is false when no file could be parsed at all, so nothing
// about the package's references is known.
type SkippedPackage struct {
	Path            string   `json:"path"`
	Imports         []string `json:"imports,omitempty"`
	ImportsComplete bool     `json:"imports_complete"`
	Errors          []string `json:"errors,omitempty"`
	SourceVisible   bool     `json:"source_visible"`
}

// firstError renders the package's primary actionable diagnostic — the
// concrete prerequisite/build failure a re-run needs resolved. Multi-line
// or empty-position entries (go list banners, aggregated error groups)
// lose to single-line compiler messages that name the actual cause.
func (s SkippedPackage) firstError() string {
	for _, e := range s.Errors {
		if !strings.HasPrefix(e, "-:") && !strings.Contains(e, "\n") {
			return e
		}
	}
	for _, e := range s.Errors {
		if !strings.HasPrefix(e, "-:") {
			return e
		}
	}
	if len(s.Errors) > 0 {
		return s.Errors[0]
	}
	return "no diagnostics recorded"
}

// SkippedPackageDiagnostics returns the structured record of every
// product package dropped from typed scans during the last index load,
// sorted by package path. Empty when the product closure type-checked
// completely — the distinguishing mark between "closed empty scope" and
// "empty result after failed loading". A failed package always appears
// here even when its import set could not be recovered.
func (ix *Index) SkippedPackageDiagnostics(ctx context.Context) ([]SkippedPackage, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ctx); err != nil {
		return nil, err
	}
	out := append([]SkippedPackage(nil), ix.skipped...)
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// SkippedPackages returns the product package paths that failed to
// type-check during the last index load (load() drops them rather than
// failing) — the path projection of SkippedPackageDiagnostics, covering
// both packages whose import edges were recovered syntactically and
// packages whose source could not be parsed at all. Empty when every
// package loaded. A non-empty list means every product-scoped query ran
// over an incomplete file set — evidence of absence in product code is
// bounded by these omissions.
func (ix *Index) SkippedPackages(ctx context.Context) ([]string, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ctx); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ix.skipped))
	for _, d := range ix.skipped {
		out = append(out, d.Path)
	}
	sort.Strings(out)
	return out, nil
}

// LoadBudgetExhausted reports whether this verification session ever
// truncated its package-load coverage — a sign that dependency coverage is
// incomplete. The record is session-scoped and sticky: restoring a
// query-scoped budget lets later queries load again, but it cannot restore
// the completeness of the truncated coverage, so the flag never returns to
// false once set.
func (ix *Index) LoadBudgetExhausted() bool {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	return ix.budgetTruncatedLocked()
}

// BudgetLimitations returns the named coverage truncations recorded during
// this index's verification session, in sorted order — the audit text an
// evidence record carries so an exhausted budget is never silent. Empty
// when no budget was exhausted. The record is session-scoped and sticky for
// the reason LoadBudgetExhausted documents.
func (ix *Index) BudgetLimitations() []string {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	return append([]string(nil), ix.sessionTruncations...)
}

// ProductPackagePaths returns the product package paths that loaded with
// type information — the root set every product-scoped check actually
// scanned, in sorted order. Skipped (failed) packages are reported
// separately by SkippedPackages; dependency packages loaded on demand are
// never product roots.
func (ix *Index) ProductPackagePaths(ctx context.Context) ([]string, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ctx); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ix.pkgs))
	for _, p := range ix.pkgs {
		if p.PkgPath != "" && p.Types != nil {
			out = append(out, p.PkgPath)
		}
	}
	sort.Strings(out)
	return out, nil
}

// SkippedPackagesImportingModule returns the product packages that failed to
// type-check but whose recovered import edges touch the module — the only
// excluded packages whose invisibility can hide a reference to the module's
// symbols. In Go a reference to a package's symbol requires an import edge to
// that package, so a failed package that never imports the module (or any of
// its subpackages) cannot contribute a reference to it; its exclusion is not a
// gap in a module-scoped proof.
func (ix *Index) SkippedPackagesImportingModule(ctx context.Context, module string) ([]string, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ctx); err != nil {
		return nil, err
	}
	if module == "" {
		return nil, fmt.Errorf("module is required")
	}
	var out []string
	for imported, importers := range ix.skippedImports {
		if imported == module || strings.HasPrefix(imported, module+"/") {
			out = append(out, importers...)
		}
	}
	return dedupStrings(out), nil
}

// skippedPackagesImportingModuleInScope is the reachability-aware variant
// of SkippedPackagesImportingModule used by VerifyUnreachable. A skipped
// package blocks the proof when it sits inside the shipping closure or its
// import edges were never fully recovered (it could hide a module import);
// a package proven outside the closure with a fully recovered edge set is
// returned in discarded for the audit trail. A nil scope — reachability
// never computed — blocks every candidate. Callers hold ix.mu with the
// index already loaded.
func (ix *Index) skippedPackagesImportingModuleInScope(module string,
	scope *unreachabilityScope) (blocked []string, discarded []string) {

	// Candidates: skipped packages whose recovered edges touch the module,
	// plus skipped packages whose edges could not be fully recovered —
	// their import set is unknowable, so they may hide a module edge.
	candidates := map[string]bool{}
	for imported, importers := range ix.skippedImports {
		if imported == module || strings.HasPrefix(imported, module+"/") {
			for _, p := range importers {
				candidates[p] = true
			}
		}
	}
	for path, p := range ix.skippedPkgs {
		if skippedUnscannedPath(ix, path) {
			continue // the unscanned gate reports these separately
		}
		if !skippedEdgesComplete(ix.fset, p) {
			candidates[path] = true
		}
	}
	for p := range candidates {
		if scope != nil && scope.packageState(p) == reachDead {
			discarded = append(discarded, p)
			continue
		}
		blocked = append(blocked, p)
	}
	sort.Strings(blocked)
	sort.Strings(discarded)
	return blocked, discarded
}

// SkippedUnscanned returns the failed product packages whose import edges
// could not be recovered at all: their references are invisible and no scope
// can be closed over them.
func (ix *Index) SkippedUnscanned(ctx context.Context) ([]string, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ctx); err != nil {
		return nil, err
	}
	return dedupStrings(append([]string(nil), ix.skippedUnscanned...)), nil
}

// ---- import closure enumeration ----

// EdgeMarker is one site inside the import closure that can create an
// edge the static import graph cannot see: plugin loads, cgo entry, or a
// //go:linkname directive. Linkname markers resolve their target against
// the enumerated package inventory; Resolved is false when the operand
// could not be mapped to a known package (including bare ABI symbols and
// pull targets outside the build).
type EdgeMarker struct {
	Package    string `json:"package"`
	Kind       string `json:"kind"` // plugin|cgo|linkname
	Locator    string `json:"locator"`
	Target     string `json:"target,omitempty"`
	Resolved   bool   `json:"resolved"`
	TargetDecl string `json:"target_decl,omitempty"`
}

// ImportClosure is the enumerated import graph for the pinned build
// context: product roots, their transitive closure, reverse importers,
// module ownership, vendor residency, packages whose edge set could not
// be fully trusted and sites that can forge edges the graph cannot see.
// Complete is true only when every member's edge set was recovered and no
// skipped package keeps invisible edges — it is a property of the graph,
// never of a search result. Every map and slice is a fresh copy.
type ImportClosure struct {
	// InventoryReference pins the complete package stream used for membership.
	InventoryReference string `json:"inventory_reference,omitempty"`
	InventoryError string `json:"inventory_error,omitempty"`
	InventoryRaw string `json:"inventory_raw,omitempty"`
	InventoryBuild domain.BuildContext `json:"inventory_build"`
	InventoryRun domain.PackageListRun `json:"inventory_run"`
	// ProductRoots is the conservative candidate inventory — every
	// package the ./... load selected plus every skipped product path
	// and recovered skipped importer. Enumeration only walks from
	// ShippingRoots when the shipping scope is proven complete.
	ProductRoots []string            `json:"product_roots"`
	Packages     []string            `json:"packages"`
	Importers    map[string][]string `json:"importers"`
	ModuleOf     map[string]string   `json:"module_of"`
	// ModuleBindings maps every member package that resolved through a
	// module to its canonical binding (path@version, replacement and the
	// directory the loader actually read), so the closure hash detects
	// module-cache substitution of a same-version source.
	ModuleBindings map[string]string `json:"module_bindings,omitempty"`
	// SourceHashes maps every member package to the sha256 digest of its
	// build-selected source file set (path + bytes). The hash binds the
	// exact content the closure was enumerated over: a post-hoc source
	// mutation inside the same module path/version changes it.
	SourceHashes map[string]string `json:"source_hashes,omitempty"`
	// UnhashedSource lists member packages whose source set could not be
	// fully read and hashed — their presence leaves the inventory
	// unverifiable, so the closure is never Complete.
	UnhashedSource []string `json:"unhashed_source,omitempty"`
	Vendored       []string `json:"vendored,omitempty"`
	// Skipped lists closure members whose source the product load could
	// not type-check — only effective members appear here: a skipped
	// package proven unreachable is discarded, not skipped-adjacent.
	Skipped          []string     `json:"skipped,omitempty"`
	SkippedUnscanned []string     `json:"skipped_unscanned,omitempty"`
	BrokenEdges      []string     `json:"broken_edges,omitempty"`
	EdgeMarkers      []EdgeMarker `json:"edge_markers,omitempty"`
	// ShippingRoots is the effective root set the closure was walked
	// from: the proven main packages while the scope is complete, the
	// full conservative candidate set otherwise.
	ShippingRoots []string `json:"shipping_roots,omitempty"`
	// ScopeComplete mirrors the shipping-scope completeness verdict;
	// pruning to DEAD packages happened only when it is true.
	ScopeComplete bool `json:"scope_complete"`
	// ScopeHash binds the exact scope content (roots, package states,
	// completeness, unknown reasons) the enumeration ran on.
	ScopeHash string `json:"scope_hash,omitempty"`
	// PackageStates reports the shipping-scope state of every product
	// candidate package; DEAD appears only under a complete scope.
	PackageStates map[string]string `json:"package_states,omitempty"`
	// ScopeUnknown lists the reasons the shipping scope stayed open.
	ScopeUnknown []string `json:"scope_unknown,omitempty"`
	// DiscardedUnreachable lists product packages excluded from the
	// closure on a proven-DEAD verdict — the audit trail for the only
	// exclusion the model permits.
	DiscardedUnreachable []string `json:"discarded_unreachable,omitempty"`
	// DynamicRelevance binds the subject-aware dynamic classification to
	// the closure hash. Entries are audit lines (observed, ignored,
	// closed, open and unresolved dispatch).
	DynamicRelevance []string `json:"dynamic_relevance,omitempty"`
	// inputs not visible in the member lists: a depleted package-load
	// budget means truncated coverage, and an unpinned module binding
	// means the inventory cannot be replayed against the same source.
	LoadBudgetExhausted bool   `json:"load_budget_exhausted,omitempty"`
	ProvenancePinned    bool   `json:"provenance_pinned"`
	Complete            bool   `json:"complete"`
	Hash                string `json:"hash"`
}

// BindDynamicRelevance records the deterministic scoped dynamic
// classification and rehashes the closure inventory. The closure hash
// therefore covers the relevance result consumed by verify_code_absence.
func (c *ImportClosure) BindDynamicRelevance(entries []string) {
	if c == nil {
		return
	}
	c.DynamicRelevance = dedupStrings(append([]string(nil), entries...))
	sort.Strings(c.DynamicRelevance)
	c.Hash = closureHash(*c)
}

// EnumerateImportClosure returns the enumerated import closure for the
// index's pinned build context. The walk starts from the shipping scope:
// under a proven-complete scope only the main-package roots seed the
// transitive closure and product packages proven DEAD are excluded and
// audited in DiscardedUnreachable; under an open or failed scope the
// walk degrades to the conservative all-candidate root set, discards
// nothing and keeps every gap blocking. All returned maps/slices are
// fresh copies; the caller may store or mutate them freely.
//
// The enumeration is memoized per index: the importer graph is loaded once
// and the walk is a deterministic function of it plus the product scope, so
// repeated invocations within one verification session (one per subject or
// tool call) reuse the first result instead of re-walking the closure and
// re-hashing every member source. Each caller receives a deep copy, and a
// truncation recorded after the cached enumeration invalidates it — a
// truncated closure must not keep replaying its untruncated Complete
// verdict. A cancelled context fails without publishing a cache entry.
func (ix *Index) EnumerateImportClosure(ctx context.Context) (ImportClosure, error) {
	ix.mu.Lock()
	hasCached := ix.closureCache != nil && ix.closureCache.InventoryReference != ""
	ix.mu.Unlock()
	if hasCached {
		out, err := ix.enumerateImportClosure(ctx)
		if err != nil {
			return out, err
		}
		if out.InventoryReference != "" {
			return out, nil
		}
	}
	measurement := affected.MeasurePackageInventory(ctx, affected.ExecGoTool{Env: ix.Env, Version: ix.Build.GoVersion}, ix.Dir, ix.Build, false)
	return ix.EnumerateImportClosureWithInventory(ctx, measurement)
}

// EnumerateImportClosureWithInventory reuses an inventory acquired under the
// identified build. It can only restrict source/load completeness, never repair it.
func (ix *Index) EnumerateImportClosureWithInventory(ctx context.Context, measurement affected.PackageInventoryMeasurement) (ImportClosure, error) {
	out, err := ix.enumerateImportClosure(ctx)
	if err != nil {
		return out, err
	}
	out.InventoryBuild, out.InventoryRun = measurement.Build, measurement.Run
	inv, admissionErr := measurement.Admit(ix.Build)
	if admissionErr != nil {
		out.InventoryError = admissionErr.Error()
	}
	out.InventoryRaw = measurement.RawStream
	if out.InventoryError == "" {
		for _, path := range out.Packages {
			if !inv.Paths[path] {
				out.InventoryError = "loaded closure member missing from package inventory: " + path
				break
			}
		}
	}
	if out.InventoryError != "" {
		out.Complete = false
	} else {
		out.InventoryReference = measurement.RawReference
	}
	out.Hash = closureHash(out)
	ix.mu.Lock()
	if ix.closureCache != nil {
		cached := deepCopyImportClosure(out)
		ix.closureCache = &cached
	}
	ix.mu.Unlock()
	return out, nil
}

func (ix *Index) enumerateImportClosure(ctx context.Context) (ImportClosure, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	ctx = ix.ctxOr(ctx)
	if err := ctx.Err(); err != nil {
		return ImportClosure{}, err
	}
	if err := ix.load(ctx); err != nil {
		return ImportClosure{}, err
	}
	if _, err := ix.depImporters(ctx); err != nil {
		return ImportClosure{}, err
	}
	source, snapshotKey := ix.snapshotKeysLocked()
	// The package-level shipping scope shares the lock-held load: it
	// decides which candidate roots are proven shipping roots and which
	// product packages are provably unreachable. Package states only —
	// the function graph is not needed for membership.
	scope, err := ix.unreachabilityScopePackageLocked(ctx, source, snapshotKey)
	if err != nil {
		return ImportClosure{}, err
	}
	cacheKey := ix.closureCacheKeyLocked(snapshotKey)
	if ix.closureCache != nil && ix.closureCacheKey == cacheKey {
		// Cheap hit path: revalidate the recorded member evidence without
		// rebuilding the candidate inventory, the BFS member set, the
		// discarded/conflict sets or the broken-edge inventory. The record's
		// member list is the member set the enumeration ran on, so the
		// content check is a straight re-hash of exactly those packages.
		recorded := make(map[string]bool, len(ix.closureCache.Packages))
		for _, p := range ix.closureCache.Packages {
			recorded[p] = true
		}
		hashes, unhashed, inventory, _, herr := ix.memberSourceEvidence(ctx, recorded)
		if herr != nil {
			return ImportClosure{}, herr
		}
		if !sameStringMap(hashes, ix.closureCache.SourceHashes) ||
			!sameStrings(unhashed, ix.closureCache.UnhashedSource) ||
			!sameStringMap(inventory, ix.closureMemberInventory) {
			ix.closureCache = nil
			ix.closureMemberInventory = nil
			return ImportClosure{}, fmt.Errorf(
				"%w: dependency source content or package file inventory changed after the closure census; the recorded graph is stale — reload the snapshot before analysing", ErrSnapshotMutated)
		}
		// Final cancellation gate before serving a cached record.
		if err := ctx.Err(); err != nil {
			return ImportClosure{}, err
		}
		ix.closureValidations++
		return deepCopyImportClosure(*ix.closureCache), nil
	}

	// Candidate inventory: every package the ./... load selected, plus
	// every skipped (failed) product package and every path that only
	// appears as a recovered importer. Under an incomplete scope this
	// set is the effective root set — nothing may be excluded on a
	// DEAD verdict that was never proven.
	rootSet := map[string]bool{}
	for _, p := range ix.pkgs {
		rootSet[p.PkgPath] = true
	}
	for path := range ix.skippedPkgs {
		rootSet[path] = true
	}
	for _, importers := range ix.skippedImports {
		for _, imp := range importers {
			rootSet[imp] = true
		}
	}
	// recovered import sets (skippedImports is imported→importers);
	// merge them over the all-load edges — a broken package may expose
	// edges through either channel.
	skippedForward := map[string]map[string]bool{}
	for imported, importers := range ix.skippedImports {
		for _, imp := range importers {
			if skippedForward[imp] == nil {
				skippedForward[imp] = map[string]bool{}
			}
			skippedForward[imp][imported] = true
		}
	}
	edgeFn := func(path string) []string {
		var out []string
		out = append(out, ix.importEdges[path]...)
		for imp := range skippedForward[path] {
			out = append(out, imp)
		}
		return out
	}

	// Effective roots: the proven shipping roots when the scope closed,
	// the full candidate set otherwise. DEAD pruning is permitted only
	// by the complete-scope branch.
	effectiveRoots := sortedKeys(rootSet)
	if scope.ProductGraphComplete {
		effectiveRoots = append([]string(nil), scope.roots...)
	}

	members := map[string]bool{}
	queue := append([]string{}, effectiveRoots...)
	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			// An interrupted walk is a partial member set: it must never
			// be published as (or cached as) the enumerated closure.
			return ImportClosure{}, err
		}
		p := queue[0]
		queue = queue[1:]
		if members[p] {
			continue
		}
		members[p] = true
		queue = append(queue, edgeFn(p)...)
	}

	// Discards and scope-consistency: every candidate outside the
	// walked set with a proven DEAD verdict joins the audit trail. A
	// member carrying a DEAD verdict contradicts the walk — the two
	// edge views disagree — so it reopens the result instead of being
	// silently trusted.
	var discarded []string
	conflicts := map[string]bool{}
	for path := range rootSet {
		if scope.packageState(path) != reachDead {
			continue
		}
		if members[path] {
			conflicts["reachable member "+path+
				" carries a DEAD scope verdict: edge views disagree; coverage stays open"] = true
			continue
		}
		discarded = append(discarded, path)
	}
	sort.Strings(discarded)

	// A member's edge set is untrusted when the loader flagged errors,
	// when the package never materialized in the all-load inventory, or
	// when a skipped product package's imports were only partially
	// recovered. Members like that may hide an edge to the target —
	// the closure cannot claim completeness.
	var broken []string
	edgesTrusted := func(path string) bool {
		cm, ok := ix.pkgMeta[path]
		if !ok {
			return false
		}
		if cm.broken {
			return false
		}
		if ix.skippedPkgs[path] != nil {
			// Product package skipped by the ./... load: its edges
			// stand only on the syntactic recovery path.
			return skippedEdgesComplete(ix.fset, ix.skippedPkgs[path])
		}
		return true
	}
	for p := range members {
		if !edgesTrusted(p) {
			broken = append(broken, p)
		}
	}
	sort.Strings(broken)

	// Member source evidence is content-addressed on every build: the
	// hashes bind the exact bytes the enumerated graph describes, and the
	// directory inventory detects a file added or removed after the census.
	hashes, unhashed, inventory, unreadable, herr := ix.memberSourceEvidence(ctx, members)
	if herr != nil {
		return ImportClosure{}, herr
	}
	markers, merr := ix.memberEdgeMarkers(ctx, members, unreadable)
	if merr != nil {
		return ImportClosure{}, merr
	}
	imps := deepCopyImporters(ix.importers)
	// A skipped product package's recovered imports are edges the
	// all-load could not attribute — merge them so the reverse set the
	// verifier sees covers every known importer of a target package.
	for imported, importers := range ix.skippedImports {
		for _, imp := range importers {
			if !strSliceHas(imps[imported], imp) {
				imps[imported] = append(imps[imported], imp)
			}
		}
	}
	// The merge may append out of order or duplicate a path reported
	// through both channels: re-normalize every value so the report and
	// its hash stay deterministic.
	for k, v := range imps {
		sort.Strings(v)
		imps[k] = dedupStrings(v)
	}
	// The skipped package inventory blocks only through effective
	// membership: a skipped path outside the walked closure is either a
	// proven-DEAD discard (audited) or evidence the scope stayed open.
	skippedSet := map[string]bool{}
	for path := range ix.skippedPkgs {
		skippedSet[path] = true
	}
	for _, path := range ix.skippedUnscanned {
		skippedSet[path] = true
	}
	for _, importers := range ix.skippedImports {
		for _, imp := range importers {
			skippedSet[imp] = true
		}
	}
	var skippedMembers, unscannedMembers []string
	for p := range members {
		if skippedSet[p] {
			skippedMembers = append(skippedMembers, p)
		}
	}
	sort.Strings(skippedMembers)
	for _, path := range ix.skippedUnscanned {
		if members[path] {
			unscannedMembers = append(unscannedMembers, path)
		}
	}
	sort.Strings(unscannedMembers)

	// Package states exported for the record: DEAD appears only when
	// the scope was proven complete — packageState withholds it
	// otherwise, so the report can never overclaim.
	pkgStates := make(map[string]string, len(rootSet))
	for path := range rootSet {
		pkgStates[path] = scope.packageState(path).String()
	}
	unknowns := append([]string(nil), scope.unknownReasons...)
	for reason := range conflicts {
		unknowns = append(unknowns, reason)
	}
	sort.Strings(unknowns)

	out := ImportClosure{
		ProductRoots:         sortedKeys(rootSet),
		Packages:             sortedKeys(members),
		Importers:            imps,
		ModuleOf:             copyStringMap(ix.pkgModules),
		ShippingRoots:        effectiveRoots,
		ScopeComplete:        scope.ProductGraphComplete,
		PackageStates:        pkgStates,
		ScopeUnknown:         unknowns,
		DiscardedUnreachable: discarded,
		Skipped:              skippedMembers,
		SkippedUnscanned:     unscannedMembers,
		BrokenEdges:          broken,
		EdgeMarkers:          markers,
		UnhashedSource:       unhashed,
	}
	out.ScopeHash = scopeStateHash(scope, pkgStates, unknowns)
	bindings := map[string]string{}
	for path := range members {
		if cm, ok := ix.pkgMeta[path]; ok && cm.modBind != "" {
			bindings[path] = cm.modBind
		}
	}
	if len(bindings) > 0 {
		out.ModuleBindings = bindings
	}
	if len(hashes) > 0 {
		out.SourceHashes = hashes
	}
	for path, cm := range ix.pkgMeta {
		if cm.vendored && members[path] {
			out.Vendored = append(out.Vendored, path)
		}
	}
	sort.Strings(out.Vendored)

	// Build/module provenance is pinned when every member that resolves
	// through a module carries a recorded binding; stdlib members bind
	// to the toolchain itself.
	provenancePinned := true
	for path := range members {
		if ix.pkgModules[path] != "" && bindings[path] == "" {
			provenancePinned = false
			break
		}
	}

	out.LoadBudgetExhausted = ix.budgetTruncatedLocked()
	out.ProvenancePinned = provenancePinned
	out.Complete = scope.ProductGraphComplete &&
		len(conflicts) == 0 &&
		len(skippedMembers) == 0 &&
		len(unscannedMembers) == 0 &&
		len(broken) == 0 &&
		len(unhashed) == 0 &&
		!ix.budgetTruncatedLocked() &&
		provenancePinned
	out.Hash = closureHash(out)
	// Final cancellation gate: a context cancelled during the last walk or
	// hash pass must not publish a record.
	if err := ctx.Err(); err != nil {
		return ImportClosure{}, err
	}
	ix.closureEnumerations++
	cached := out
	ix.closureCache = &cached
	ix.closureCacheKey = cacheKey
	ix.closureMemberInventory = inventory
	return deepCopyImportClosure(out), nil
}

// closureCacheKeyLocked renders the session/snapshot identity a cached
// enumeration is bound to: the snapshot key (build context + product source
// bytes + loader census identity) plus the recorded truncations. Member
// source content outside the product scope is validated separately by
// comparing the cached SourceHashes and member directory inventory against a
// fresh pass, so no source rewrite or added file can hide behind a cache
// hit. Callers MUST hold ix.mu.
func (ix *Index) closureCacheKeyLocked(snapshotKey string) string {
	key := snapshotKey
	if len(ix.sessionTruncations) > 0 {
		key += "|" + strings.Join(ix.sessionTruncations, ";")
	}
	if ix.loadBudgetExhausted {
		key += "|query-budget-exhausted"
	}
	return key
}

// sameStringMap reports whether two string maps carry identical entries.
func sameStringMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

// sameStrings reports whether two sorted string lists are identical.
func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// deepCopyImportClosure returns an independent copy of a closure record —
// every map and slice is fresh, so neither a caller mutation nor the
// cached value can leak into the other. EdgeMarkers, strings and bools copy
// by value.
func deepCopyImportClosure(c ImportClosure) ImportClosure {
	out := c
	out.ProductRoots = append([]string(nil), c.ProductRoots...)
	out.Packages = append([]string(nil), c.Packages...)
	out.Importers = deepCopyStringSlices(c.Importers)
	out.ModuleOf = copyStringMap(c.ModuleOf)
	out.ModuleBindings = copyStringMap(c.ModuleBindings)
	out.SourceHashes = copyStringMap(c.SourceHashes)
	out.UnhashedSource = append([]string(nil), c.UnhashedSource...)
	out.Vendored = append([]string(nil), c.Vendored...)
	out.Skipped = append([]string(nil), c.Skipped...)
	out.SkippedUnscanned = append([]string(nil), c.SkippedUnscanned...)
	out.BrokenEdges = append([]string(nil), c.BrokenEdges...)
	out.EdgeMarkers = append([]EdgeMarker(nil), c.EdgeMarkers...)
	out.ShippingRoots = append([]string(nil), c.ShippingRoots...)
	out.PackageStates = copyStringMap(c.PackageStates)
	out.ScopeUnknown = append([]string(nil), c.ScopeUnknown...)
	out.DiscardedUnreachable = append([]string(nil), c.DiscardedUnreachable...)
	out.DynamicRelevance = append([]string(nil), c.DynamicRelevance...)
	return out
}

// scopeStateHash binds the scope content a closure enumeration ran on:
// the proven shipping roots, every exported package state, the
// completeness flag and the recorded unknown reasons. It is
// deterministic for a deterministic scope.
func scopeStateHash(scope *unreachabilityScope, states map[string]string, unknowns []string) string {
	var roots []string
	complete := false
	if scope != nil {
		roots = append([]string(nil), scope.roots...)
		complete = scope.ProductGraphComplete
	}
	payload := struct {
		Roots    []string
		States   map[string]string
		Complete bool
		Unknowns []string
	}{roots, states, complete, unknowns}
	b, _ := json.Marshal(payload)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// memberScanHook is a package-local test seam invoked at the end of the
// member evidence pass. Production leaves it nil; tests use it to cancel the
// caller's context after the last file read and prove that neither a cache
// hit nor a closure record is published afterwards.
var memberScanHook func(*Index)

// memberSourceEvidence reads and hashes every member's build-selected source
// set (name + bytes) — the content identity of the enumerated closure — and
// records the member directory inventory:
//
//   - the digest covers Go sources, generated/compiled variants, embeds and
//     C/asm/headers, so the closure hash changes when external source is
//     substituted under the same module path/version;
//   - a member whose file set is missing or unreadable is returned in
//     unhashed: its inventory can never be replayed, so it keeps the
//     closure incomplete;
//   - unreadable files are reported as linkname markers so an unverifiable
//     directive surface stays named.
//
// The pass runs on every enumeration — including cache hits — because it is
// the validity test of a memoized record. The caller's context bounds the
// walk: cancellation returns the context error instead of a half-hashed
// inventory.
func (ix *Index) memberSourceEvidence(ctx context.Context, members map[string]bool) (hashes map[string]string, unhashed []string, inventory map[string]string, unreadable []EdgeMarker, err error) {
	hashes = map[string]string{}
	inventory = map[string]string{}
	for path := range members {
		if cerr := ctx.Err(); cerr != nil {
			return nil, nil, nil, nil, cerr
		}
		cm, ok := ix.pkgMeta[path]
		files := cm.hashFiles
		if !ok || len(files) == 0 {
			if sp := ix.skippedPkgs[path]; sp != nil {
				files = sp.GoFiles
			}
			if len(files) == 0 {
				unhashed = append(unhashed, path)
				continue
			}
		}
		files = append([]string(nil), files...)
		sort.Strings(files)
		h := sha256.New()
		failed := false
		for _, f := range files {
			if cerr := ctx.Err(); cerr != nil {
				return nil, nil, nil, nil, cerr
			}
			data, rerr := os.ReadFile(f)
			if rerr != nil {
				failed = true
				unreadable = append(unreadable, EdgeMarker{Package: path, Kind: "linkname", Locator: f + ":unreadable"})
				continue
			}
			h.Write([]byte(f))
			h.Write([]byte{0})
			h.Write(data)
		}
		// Directory inventory: the census file lists are frozen at load, so
		// a Go file added or removed afterwards is invisible to the hash
		// pass. Walking the member directory moves the inventory instead.
		if dir := memberSourceDir(cm.dir, files); dir != "" {
			entries, derr := os.ReadDir(dir)
			if derr != nil {
				inventory[path] = "!unreadable-dir"
			} else {
				var names []string
				for _, e := range entries {
					if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
						continue
					}
					names = append(names, e.Name())
				}
				sort.Strings(names)
				inventory[path] = strings.Join(names, "\x00")
			}
		}
		if failed {
			unhashed = append(unhashed, path)
			continue
		}
		hashes[path] = hex.EncodeToString(h.Sum(nil))
	}
	sort.Strings(unhashed)
	if memberScanHook != nil {
		memberScanHook(ix)
	}
	return hashes, unhashed, inventory, unreadable, nil
}

// memberSourceDir resolves the source directory of a member: the census's
// recorded directory when present, else the first selected file's directory.
func memberSourceDir(dir string, files []string) string {
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

// memberEdgeMarkers enumerates every member's edge-forging and
// dispatch-capable surface:
//
//   - plugin imports, cgo edges and reflect/unsafe imports come from the
//     package inventory (imports are resolved metadata, never syntax);
//   - //go:linkname directives are recovered by parsing the build-selected
//     sources of every member that could contain one. Only a rebuild runs
//     this pass — a cache hit validated the bytes through memberSourceHashes
//     and the parsed markers still describe those bytes;
//   - unreadable files (from the hash pass) ride along so an unverifiable
//     directive surface stays named.
func (ix *Index) memberEdgeMarkers(ctx context.Context, members map[string]bool, unreadable []EdgeMarker) ([]EdgeMarker, error) {
	markers := append([]EdgeMarker(nil), unreadable...)
	for path := range members {
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		cm, ok := ix.pkgMeta[path]
		if !ok {
			continue
		}
		if cm.plugin {
			markers = append(markers, EdgeMarker{Package: path, Kind: "plugin", Locator: path + " imports plugin"})
		}
		if cm.cgo {
			markers = append(markers, EdgeMarker{Package: path, Kind: "cgo", Locator: path + " imports C"})
		}
		if cm.reflect {
			markers = append(markers, EdgeMarker{Package: path, Kind: "reflect", Locator: path + " imports reflect"})
		}
		if cm.usesUnsafe {
			markers = append(markers, EdgeMarker{Package: path, Kind: "unsafe", Locator: path + " imports unsafe"})
		}
	}
	for path := range members {
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		cm := ix.pkgMeta[path]
		files := cm.hashFiles
		if sp := ix.skippedPkgs[path]; len(files) == 0 && sp != nil {
			files = sp.GoFiles
		}
		files = append([]string(nil), files...)
		sort.Strings(files)
		for _, f := range files {
			if !strings.HasSuffix(f, ".go") {
				continue
			}
			data, rerr := os.ReadFile(f)
			if rerr != nil {
				// Already reported by the hash pass as unreadable.
				continue
			}
			markers = append(markers, ix.linknameMarkersFromBytes(path, f, data)...)
		}
	}
	sort.Slice(markers, func(i, j int) bool {
		return (markers[i].Package + "\x00" + markers[i].Kind + "\x00" + markers[i].Locator + "\x00" + markers[i].Target) <
			(markers[j].Package + "\x00" + markers[j].Kind + "\x00" + markers[j].Locator + "\x00" + markers[j].Target)
	})
	return markers, nil
}

// linknameRe parses a two-operand //go:linkname comment body:
// `//go:linkname localname pkgpath.Symbol`. The single-operand export
// form carries no target and is ignored — it binds no foreign code.
var linknameRe = regexp.MustCompile(`^//go:linkname\s+([^\s]+)\s+([^\s]+)`)

// linknameMarkersFromBytes scans one already-read source file for
// //go:linkname pull directives. Comments are extracted by the real
// parser so directive-looking prose can never forge a marker.
func (ix *Index) linknameMarkersFromBytes(pkgPath, file string, data []byte) []EdgeMarker {
	if !bytes.Contains(data, []byte("//go:linkname")) {
		return nil
	}
	f, err := parser.ParseFile(ix.fset, file, data, parser.ParseComments)
	if err != nil {
		// An unparsed file whose bytes carry the directive is an
		// unresolvable edge-forging site: report it unresolved rather
		// than silently skipping.
		return []EdgeMarker{{Package: pkgPath, Kind: "linkname", Locator: file + ":unparsed"}}
	}
	var out []EdgeMarker
	for _, cg := range f.Comments {
		for _, cm := range cg.List {
			m := linknameRe.FindStringSubmatch(cm.Text)
			if m == nil {
				continue
			}
			target := m[2]
			pos := ix.fset.Position(cm.Pos())
			mk := EdgeMarker{
				Package: pkgPath,
				Kind:    "linkname",
				Locator: fmt.Sprintf("%s:%d", pos.Filename, pos.Line),
				Target:  target,
			}
			if tp, tsym, ok := ix.resolveLinknameTarget(target); ok {
				mk.Resolved = true
				mk.Target = tp
				mk.TargetDecl = tsym
			}
			out = append(out, mk)
		}
	}
	return out
}

func deepCopyImporters(in map[string][]depImporter) map[string][]string {
	out := make(map[string][]string, len(in))
	for k, vs := range in {
		list := make([]string, 0, len(vs))
		for _, v := range vs {
			list = append(list, v.path)
		}
		sort.Strings(list)
		out[k] = list
	}
	return out
}

func copyStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// deepCopyStringSlices copies a map of string slices — the shape of
// ImportClosure.Importers — so a caller mutation cannot rewrite the record.
func deepCopyStringSlices(in map[string][]string) map[string][]string {
	if in == nil {
		return nil
	}
	out := make(map[string][]string, len(in))
	for k, v := range in {
		out[k] = append([]string(nil), v...)
	}
	return out
}

// closureHash pins the enumerated inventory: effective shipping roots,
// the scope verdict and its reasons, the per-package reachability
// states, the discarded-unreachable audit set, members, edges,
// importers, module/vendor ownership, resolved module bindings, the
// hashed source content of every member and the broken/skipped
// bookkeeping — enough for a replay to detect any drift in what was
// covered, in which bytes the coverage was computed over, or in which
// packages the scope allowed to be left out.
func closureHash(c ImportClosure) string {
	type canonMarker struct {
		Package, Kind, Locator, Target string
		Resolved                       bool
	}
	cm := make([]canonMarker, 0, len(c.EdgeMarkers))
	for _, m := range c.EdgeMarkers {
		cm = append(cm, canonMarker{m.Package, m.Kind, m.Locator, m.Target, m.Resolved})
	}
	payload := struct {
		Roots     []string
		Packages  []string
		Importers map[string][]string
		Modules   map[string]string
		Bindings  map[string]string
		Sources   map[string]string
		Unhashed  []string
		Vendored  []string
		Skipped   []string
		Unscanned []string
		Broken    []string
		Markers   []canonMarker
		Dynamic   []string
		Shipping  []string
		ScopeOK   bool
		ScopeHash string
		States    map[string]string
		Unknowns  []string
		Discarded []string
		Complete  bool
		Budget    bool
		Pinned    bool
		Inventory string
		InventoryError string
		InventoryBuild domain.BuildContext
		InventoryRun domain.PackageListRun
	}{
		c.ProductRoots, c.Packages, c.Importers, c.ModuleOf, c.ModuleBindings,
		c.SourceHashes, c.UnhashedSource, c.Vendored,
		c.Skipped, c.SkippedUnscanned, c.BrokenEdges, cm, c.DynamicRelevance,
		c.ShippingRoots, c.ScopeComplete, c.ScopeHash,
		c.PackageStates, c.ScopeUnknown, c.DiscardedUnreachable,
		c.Complete, c.LoadBudgetExhausted, c.ProvenancePinned,
		c.InventoryReference, c.InventoryError,
		c.InventoryBuild, c.InventoryRun,
	}
	b, _ := json.Marshal(payload)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// resolveLinknameTarget maps a go:linkname operand ("pkg/path.Symbol") to
// a package in the enumerated inventory. The operand's package part can
// itself contain dots, so every split point is tried and the longest
// known package path wins. A bare symbol (no dot) or a package the build
// never materialized is unresolvable.
func (ix *Index) resolveLinknameTarget(operand string) (pkgPath, symbol string, ok bool) {
	if ix.pkgModules == nil {
		return "", "", false
	}
	best := ""
	for i := len(operand) - 1; i > 0; i-- {
		if operand[i] != '.' {
			continue
		}
		cand := operand[:i]
		if _, known := ix.pkgModules[cand]; known && len(cand) > len(best) {
			best = cand
		}
	}
	if best == "" {
		return "", "", false
	}
	return best, operand[len(best)+1:], true
}

// skippedImporterPaths returns the product package paths that appear as
// importers in the recovered skipped-import map — packages dropped by the
// main load whose edges only the syntactic recovery channel retained.
func skippedImporterPaths(m map[string][]string) []string {
	var out []string
	for _, importers := range m {
		out = append(out, importers...)
	}
	return out
}

func strSliceHas(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

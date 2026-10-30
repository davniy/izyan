package goanalysis

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/tools/go/packages"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/readgate"
)

// ErrSymbolNotFoundInPackage indicates that the package was loaded and typed,
// but the requested symbol does not exist in that package version.
var ErrSymbolNotFoundInPackage = errors.New("symbol not found in package")

// ErrAmbiguousSymbol indicates the bare (unqualified) symbol name denotes
// more than one declaration in the resolved package — absence is not
// proven either way, so callers must treat it as an open result, never
// as not-found.
var ErrAmbiguousSymbol = errors.New("symbol name is ambiguous in package")

// ErrSnapshotMutated reports that a product or dependency source changed on
// disk after the index loaded it. The loaded AST, type information and
// importer census describe the pre-mutation bytes, so no scope, closure or
// unreachability answer may be derived from them: every affected query fails
// closed and the caller must reload the snapshot (a fresh Index) before any
// verdict is computed.
var ErrSnapshotMutated = errors.New("snapshot mutated after load")

// Index is a lazily loaded go/packages view of the analyzed product.
// It backs the targeted source tools (find_symbol, find_callers,
// read_function, find_entrypoints, argument provenance).
type Index struct {
	Dir   string
	Build domain.ProductSnapshot
	// Env carries the target toolchain (PATH/GOTOOLCHAIN) into package
	// loading, so stdlib symbols resolve under the release's GOROOT, not
	// the local toolchain's.
	Env []string
	// KB is the ecosystem-semantics knowledge base provenance and
	// exposure scans consult; nil installs DefaultKnowledge() on first
	// use. Set it before the first query — reconfiguring mid-analysis is
	// not supported.
	KB *Knowledge
	// moduleUsageOverride is a hermetic seam for unreachability tests. When set,
	// module entry enumeration uses it instead of loading product usage.
	moduleUsageOverride func(context.Context, string) ([]domain.CallSite, error)
	// hopLimit overrides the default caller-climb bound during a single
	// TraceArgumentBound call; 0 = maxTraceHops.
	hopLimit int
	// txBuf, when non-nil during TraceArgument, accumulates the calls a
	// traced value passes through (DataFlow.Transformations). txSeen
	// dedups it — a dep-cone trace otherwise appends one entry per
	// evaluated call (millions of entries on aws-scale cones).
	// Guarded by mu.
	txBuf  *[]domain.CallSite
	txSeen map[domain.CallSite]bool
	// traceSeen, when non-nil during TraceArgument, marks local vars whose
	// assignment merge is in progress — breaks self-referential cycles
	// (x = x + n re-entering x's assignments).
	traceSeen map[types.Object]bool
	// calleeEvalSeen marks vars whose assignment merge is in progress
	// inside evalCalleeExpr — the callee-frame counterpart of traceSeen,
	// owned by the callee evaluator so the cycle guard holds on every
	// entry path.
	calleeEvalSeen map[types.Object]bool
	// calleeTraceIn marks functions whose body trace is in progress —
	// breaks recursive callee chains (f → … → f) that would otherwise
	// re-scan the whole body exponentially until the eval budget dies.
	calleeTraceIn map[string]bool
	// paramSeen marks (function, argument-slot) resolutions in progress
	// inside traceParam/traceReceiver — recursive self-calls that re-feed
	// the same slot contribute no new origin and are cut here instead of
	// unrolling to the hop bound.
	paramSeen map[string]bool
	// paramCache memoizes completed (function, argument-slot) resolutions:
	// sibling branches of a caller merge would otherwise re-descend the
	// same caller chain at ever-greater depth and hit the hop bound.
	paramCache map[string]classifyResult
	// linkedSet/linkedGen cache the program's import closure (product
	// roots + transitively imported packages) for callerReachable's
	// dead-package exclusion — invalidated like callerCache on extras.
	linkedSet map[string]bool
	linkedGen int
	// activeCtx is the context of the currently executing public query —
	// internal helpers (loadExtra, findSymbol, dep-package loads) pick it
	// up so cancellation reaches subprocess loads without threading ctx
	// through every helper signature. Set by load() on every entry.
	activeCtx context.Context
	// classifyCache memoizes classify results for the duration of one
	// trace (reset at each trace entry — traceSeen/txBuf make results
	// trace-scoped). Without it the caller fan-out re-walks the same
	// (expr, enc, depth) subtrees exponentially.
	classifyCache map[classifyKey]classifyResult
	// dispatch predicate caches avoid repeated whole-linked-AST walks.
	// They are cleared whenever extras generation changes.
	methodDispatchCache map[string]bool
	reflectLookupCache  map[string]bool
	marshalAPICache     map[string]bool
	// assignCache memoizes localAssigns scans per (function, object);
	// callListCache memoizes the call-list walk in populatedByCall per
	// function. Both hold AST pointers — bounded like the other caches.
	assignCache   map[assignKey][]ast.Expr
	callListCache map[*ast.FuncDecl][]*ast.CallExpr
	// fieldOwners memoizes the declaring named type ("pkg.T") of struct
	// field vars — "" for anonymous declaring structs. Write-site
	// matching uses it to disambiguate same-named fields sharing a
	// types.Id across different structs in one package.
	fieldOwners map[*types.Var]string
	// coneCache memoizes depCone per module path: the set of module
	// functions reachable from the product's calls into it — used to
	// restrict dep-internal caller merges to product-driven paths.
	coneCache map[string]map[string]bool
	// instSet/instDisabled memoize instantiatedNamed across loaded
	// packages; instGen invalidates on extras flushes like callerCache.
	instSet      map[string]bool
	instDisabled bool
	instGen      int
	// prodInstSet/prodInstDisabled memoize instantiatedNamed across product packages only.
	prodInstSet      map[string]bool
	prodInstDisabled bool
	// coneBusy marks modules whose depCone is currently being computed —
	// cone checks inside the computation (dispatch narrowing looks at
	// field writes, which consult the cone) degrade to permissive instead
	// of recursing forever.
	coneBusy map[string]bool
	// exprDepth bounds structural recursion into expression trees (binary
	// chains, nested indices, giant composite literals in generated dep
	// code). hops() bounds caller climbs; this bounds AST nesting —
	// beyond it the origin is UNKNOWN, not a stack overflow.
	exprDepth int
	// evalBudget bounds total callee-frame expression evaluations within
	// one analysis session: dep-internal caller fan-out is exponential in
	// principle — past the budget the origin degrades to UNKNOWN rather
	// than burning unbounded time. 0 = inactive.
	evalBudget int
	// loadBudget bounds total packages.Load calls during one closure query;
	// 0 = unconstrained. loadBudgetExhausted is the query-scoped depletion
	// flag — a scoped query restores its own budget so the next query can
	// load again, which is why the session-scoped evidence lives in
	// sessionTruncations instead.
	loadBudget          int
	loadBudgetExhausted bool
	// sessionTruncations records, sorted and deduplicated, the named
	// budget truncations this index observed while verifying one product
	// advisory — the session-scoped evidence that dependency coverage was
	// cut short. Entries are never removed inside a session: restoring a
	// query-scoped load budget must not turn a truncated session back into
	// a complete-looking one, so every completeness claim that could cover
	// the truncated region reads it through budgetTruncatedLocked /
	// LoadBudgetExhausted / BudgetLimitations.
	sessionTruncations []string
	// sessionCaseID identifies the advisory that opened the verification
	// session owning sessionTruncations. One index is shared across
	// advisories in scan/eval mode (eval runs cases concurrently), so the
	// record is append-only for the index lifetime: a truncation recorded by
	// any case stays visible to every later query rather than being reset on
	// a case switch, which a concurrent second case would otherwise do
	// between the first case's queries and silently restore completeness.
	sessionCaseID domain.CaseID
	// sessionShared records that more than one case used this index without
	// a stable per-case binding. Truncation evidence then belongs to the
	// index, not to a case, and stays sticky for the whole index lifetime.
	sessionShared bool
	// loadedFingerprint is the snapshot content fingerprint captured at load
	// time. A later query recomputes the fingerprint and fails closed with
	// ErrSnapshotMutated when it moved: the loaded AST, types and importer
	// census describe the pre-mutation bytes, so rebuilding a scope from
	// them would publish DEAD/Complete over sources nobody analyzed.
	loadedFingerprint string
	// funcDeclCache memoizes function-declaration lookups — uncached,
	// each dep-internal call trace re-walks every file of the callee's
	// package.
	funcDeclCache map[string]funcDeclResult
	// fieldTagCache memoizes fieldConfigTagged scans — each field's tag
	// lookup re-walks the owner package's syntax; pointer key because
	// types.Var.Id() collides for same-named fields of different structs.
	fieldTagCache map[*types.Var]bool
	// fieldWritesCache memoizes fieldWriteSites scans; fieldOriginCache
	// memoizes resolved field origins by (field, remaining depth). Both
	// carry the extras generation — a freshly loaded dep package may
	// hold additional writes.
	fieldWritesCache map[*types.Var]cachedFieldWrites
	fieldOriginCache map[fieldOriginKey]cachedFieldOrigin
	mu               sync.Mutex // serializes queries; shared across cases in scan mode
	// boundCtx/boundSet record the build context the index actually loaded
	// and queries under. They are set by BindBuild or captured at the first
	// load; any later mutation of the public Build field fails the guard
	// instead of relabelling already-loaded ASTs.
	boundCtx domain.BuildContext
	boundSet bool
	pkgs     []*packages.Package
	// extraPkgs caches dependency packages loaded on demand via loadExtra
	// (keyed by package path), so dep-internal scans (call sites, provenance)
	// can reuse their syntax without re-running packages.Load. extraOrder
	// is the insertion order — the eviction LRU for evictExtra.
	extraPkgs  map[string][]*packages.Package
	extraOrder []string
	// extraWeight memoizes each retained pattern's imported-types
	// closure size (importClosureSize of its roots) — the weight evictExtra
	// budgets against, since package count alone misses the transitively
	// imported types graph every root drags behind it.
	extraWeight map[string]int
	// extraPinned exempts a load pattern from eviction — the advisory
	// module under active closure verification must stay resident or its
	// callers vanish mid-trace (mid-verify eviction once turned every
	// resolved protojson sink position UNKNOWN).
	extraPinned map[string]bool
	// callerCache memoizes caller scans by (symbol, scope). Dependency
	// scopes grow as loadExtra pulls more packages in, so dep entries are
	// tagged with the extras generation and refreshed on a miss.
	callerCache map[callerKey]cachedCallers
	// funcValsCache memoizes resolved function-value candidates per
	// variable; gen tracks extrasGen like callerCache.
	funcValsCache map[*types.Var]funcValEntry
	funcValsIn    map[*types.Var]bool
	// fvIdx caches per-package func-value call indexes; fvIdxGen drops
	// the map when the extras generation turns over. fvBuildDepth counts
	// in-progress index builds: nested candidate resolution consults
	// existing indexes only — starting another package's build mid-build
	// recurses across the package graph (grpc-scale cones never return).
	fvIdx        map[*packages.Package]*fvPkgIndex
	fvIdxGen     int
	fvBuildDepth int
	callersIn    map[callerKey]bool
	extrasGen    int
	// lastFreeOS throttles the post-eviction FreeOSMemory sweep — it is
	// a full GC plus madvise, far too expensive to run per load.
	lastFreeOS time.Time
	fset       *token.FileSet
	loaded     bool
	loadErr    error
	// skippedUnscanned lists failed product packages whose import set
	// could not be recovered even syntactically — their edges are fully
	// invisible, so no negative query can call the scope closed.
	// skipped is the canonical structured record behind both: every
	// product package dropped from typed scans appears exactly once,
	// with recovered imports and the loader's own error text.
	skippedUnscanned []string
	skippedImports   map[string][]string
	skipped          []SkippedPackage
	// skippedPkgs retains the raw *packages.Package of every product
	// package dropped by load(): the shipping-scope builder needs their
	// declared name (a failed package can still be a `main` package and
	// therefore a shipping root), their package clauses and their partial
	// syntax. Keyed by the same path spelling skippedImports reports.
	skippedPkgs  map[string]*packages.Package
	modCacheOnce sync.Once
	modCache     string
	// importers caches the reverse import index of the full dependency
	// closure for depSiteLive's cross-module-caller bound (lazily built,
	// no syntax — import edges only).
	importers map[string][]depImporter
	// pkgModules maps every package path of the full dependency closure
	// to its owning module path ("" = stdlib) — built in the same "all"
	// load as importers.
	pkgModules map[string]string
	// importEdges caches the forward import edges of the same "all" load —
	// the transitive closure walk EnumerateImportClosure performs starts
	// from these edges.
	importEdges map[string][]string
	// pkgMeta records per-package facts of the same "all" load needed to
	// judge closure completeness and hidden edge-forging mechanisms:
	// source dir, build-selected Go files, cgo/plugin imports, vendor
	// residency and whether the package carried load errors (its edge set
	// is then untrusted).
	pkgMeta map[string]closurePkgMeta
	// importerLoads counts "all" dependency-graph loads — one per index is
	// the reuse contract EnumerateImportClosure depends on.
	importerLoads int
	// scopeCachePackage/scopeCacheFull memoize the shipping-scope
	// construction — package graph alone, and package+function graph — for
	// the loaded snapshot. Both are deterministic functions of the loaded
	// product packages (extras never enter the scope), so one construction
	// serves every subject, condition and case of the session. A
	// construction interrupted by the caller's context is never published:
	// a partially built scope must not later read as complete.
	scopeCachePackage *unreachabilityScope
	scopeCacheFull    *unreachabilityScope
	// scopeCacheFingerprint is the content fingerprint of the snapshot the
	// memoized scope was built over (see snapshotFingerprintLocked); a
	// moved fingerprint drops both cached halves instead of serving a
	// verdict set derived from different source bytes or inventory.
	scopeCacheFingerprint string
	// scopePackageBuilds/scopeFunctionBuilds count real constructions
	// (cache misses), the observable behind the scope-reuse regression
	// tests.
	scopePackageBuilds  int
	scopeFunctionBuilds int
	// productShapeCache memoizes the product-shape census — module
	// ownership, the manifest-aware non-test source inventory and the
	// classification derived from them — for the loaded snapshot. The
	// census is a deterministic function of the manifests, the build
	// context and the product source bytes; buildProductShapeLocked
	// revalidates that identity on every public query and drops the entry
	// when it moves. EvidenceIDs inside the cached shape stay empty: they
	// are case-scoped and assigned by the collector, never cached.
	productShapeCache    *productCensus
	productShapeIdentity string
	// productShapeBuilds counts published census constructions (cache
	// misses) — the observable behind the census-reuse tests.
	productShapeBuilds int
	// libraryShapeSettled records that the lazy library proof was attempted,
	// so a non-library product does not rebuild the census on every traced
	// parameter. libraryPackageSet indexes the proven census by import path
	// (presence = product-owned, value = importable); it is keyed by the
	// fingerprint so a moved census cannot serve a stale membership set.
	libraryShapeSettled       bool
	libraryPackageFingerprint string
	libraryPackageSet         map[string]bool
	// closureCache memoizes the enumerated import closure of the loaded
	// snapshot; closureCacheKey binds it to the snapshot fingerprint and the
	// truncation record, so a rewrite, an inventory change or a truncation
	// recorded afterwards invalidates it instead of hiding inside the cached
	// Complete verdict. closureMemberInventory is the member directory
	// inventory the record was enumerated over (detects added/removed files).
	// Callers always receive a deep copy — the cached value is never handed
	// out for mutation.
	closureCache           *ImportClosure
	closureCacheKey        string
	closureMemberInventory map[string]string
	// closureEnumerations counts full enumeration walks (cache misses) and
	// closureValidations counts cache hits that revalidated member sources
	// without walking the graph — the honest split behind the closure-reuse
	// regression tests.
	closureEnumerations int
	closureValidations  int
	// dynScanOverride is a hermetic seam for scoped dynamic-relevance tests.
	dynScanOverride func(domain.SymbolRef) ([]DynamicMarker, error)
	// Confine, when set, confines every source read to the analyzed
	// directory and ConfineRoots — plus the module cache unless
	// ExcludeAmbientModCache is set (benchmark isolation).
	// The gate is built once at load time.
	Confine bool
	// ConfineRoots lists extra canonical roots allowed under Confine
	// (e.g. a prepared advisory directory or an explicitly declared
	// per-run module cache).
	ConfineRoots []string
	// ExcludeAmbientModCache keeps the ambient module cache out of the
	// confinement roots: reads stay limited to Dir + ConfineRoots. The
	// default (false) adds modCacheDir so loaded dependency sources remain
	// readable; strict agent profiles set it because the host cache may
	// hold code foreign to the snapshot.
	ExcludeAmbientModCache bool
	// ReplaceEnv makes package loading use only buildEnv+Env, without
	// inheriting the ambient process environment (benchmark isolation).
	ReplaceEnv bool
	// gateOnce/gateCache memoize the confinement gate for the index.
	gateOnce  sync.Once
	gateCache *readgate.Gate
}

// gate returns the confinement gate, or nil when Confine is off. The nil
// gate permits every read, preserving the non-benchmark behaviour.
func (ix *Index) gate() *readgate.Gate {
	if !ix.Confine {
		return nil
	}
	ix.gateOnce.Do(func() { ix.gateCache = ix.buildGate() })
	return ix.gateCache
}

// buildGate assembles the read gate from the analyzed directory, the module
// cache (unless excluded) and any extra confined roots.
func (ix *Index) buildGate() *readgate.Gate {
	roots := append([]string{ix.Dir}, ix.ConfineRoots...)
	if !ix.ExcludeAmbientModCache {
		if mc := ix.modCacheDir(); mc != "" {
			roots = append(roots, mc)
		}
	}
	return readgate.New(roots...)
}

// GateRoots returns the canonical roots the confinement gate currently
// allows — nil when confinement is off. The result is a resolved copy for
// scope/audit records.
func (ix *Index) GateRoots() []string {
	return ix.gate().Roots()
}

// BindBuild binds one resolved product build to the index. It is
// synchronized and idempotent:
//
//   - a matching context succeeds;
//   - a different context before the first load replaces the index's build
//     selection with the resolved snapshot;
//   - a different context after a load returns ErrBuildContextMismatch and
//     mutates nothing: a loaded AST is never relabelled.
func (ix *Index) BindBuild(snap domain.ProductSnapshot) error {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	want := domain.EffectiveBuildContext(snap)
	if ix.loaded {
		if !ix.boundSet {
			ix.boundCtx = domain.EffectiveBuildContext(ix.Build)
			ix.boundSet = true
		}
		if err := ix.boundCtx.Matches(want); err != nil {
			return fmt.Errorf("bind build: %w", err)
		}
		return nil
	}
	ix.Build = snap
	ix.boundCtx = want
	ix.boundSet = true
	return nil
}

// BoundBuildContext returns the build context the index is bound to. A
// fresh index that has neither loaded nor been bound reports ok=false.
func (ix *Index) BoundBuildContext() (domain.BuildContext, bool) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if !ix.boundSet {
		return domain.BuildContext{}, false
	}
	out := ix.boundCtx
	out.BuildTags = slices.Clone(out.BuildTags)
	out.ReplaceDirectives = slices.Clone(out.ReplaceDirectives)
	return out, true
}

// checkBuildContextLocked captures the bound context on first use and fails
// closed when the public Build field no longer matches it. Callers MUST hold
// ix.mu.
func (ix *Index) checkBuildContextLocked() error {
	current := domain.EffectiveBuildContext(ix.Build)
	if !ix.boundSet {
		ix.boundCtx = current
		ix.boundSet = true
		return nil
	}
	if err := ix.boundCtx.Matches(current); err != nil {
		return fmt.Errorf("build context changed after binding: %w", err)
	}
	return nil
}

// loadEnv assembles the environment for package loading: the ambient (or
// whitelisted) environment first, then the toolchain policy carried by
// Index.Env, then the snapshot's resolved build selection — so the last word
// on GOOS/GOARCH/CGO/workspace/GOFLAGS is the bound build context.
func (ix *Index) loadEnv() []string {
	var base []string
	if ix.ReplaceEnv {
		// The whitelist keeps an inherited GOWORK/GOFLAGS (or any other
		// overlay) from widening the load scope.
		base = ambientLoaderEnv()
	} else {
		base = os.Environ()
	}
	env := make([]string, 0, len(base)+len(ix.Env)+5)
	env = append(env, base...)
	env = append(env, ix.Env...)
	env = append(env, domain.BuildEnv(ix.Build)...)
	return env
}

// loaderEnvWhitelist lists the ambient variables package loading may
// inherit under ReplaceEnv. Overlay inputs that can retarget the build
// (GOWORK, GOFLAGS, GOENV, GOEXPERIMENT, GOINSECURE, GOTOOLCHAIN,
// GOOS/GOARCH/CGO_ENABLED) are never inherited — the caller supplies the
// allowed overrides through Index.Env. GOCACHE is excluded the same way:
// the strict session pins it explicitly, so a caller's ambient build
// cache can never reach the loader. Everything else needed by the go
// tool (module cache, proxies, HOME) passes through.
var loaderEnvWhitelist = map[string]bool{
	"PATH": true, "HOME": true, "USER": true, "LOGNAME": true,
	"USERPROFILE": true, "HOMEDRIVE": true, "HOMEPATH": true, "APPDATA": true,
	"TMPDIR": true, "TEMP": true, "TMP": true,
	"XDG_CACHE_HOME": true, "XDG_CONFIG_HOME": true, "XDG_DATA_HOME": true,
	"LANG": true, "LC_ALL": true, "LC_CTYPE": true, "TZ": true, "TERM": true,
	"SystemRoot": true, "COMSPEC": true, "PATHEXT": true,
	"SSL_CERT_FILE": true, "SSL_CERT_DIR": true,
	"HTTP_PROXY": true, "HTTPS_PROXY": true, "NO_PROXY": true, "ALL_PROXY": true,
	"http_proxy": true, "https_proxy": true, "no_proxy": true, "all_proxy": true,
	"GOPATH": true, "GOMODCACHE": true, "GOROOT": true,
	"GOPROXY": true, "GOSUMDB": true, "GOPRIVATE": true, "GONOPROXY": true,
	"GONOSUMDB": true, "GOVCS": true,
}

// ambientLoaderEnv returns the whitelisted slice of os.Environ.
func ambientLoaderEnv() []string {
	var env []string
	for _, e := range os.Environ() {
		k, _, ok := strings.Cut(e, "=")
		if ok && loaderEnvWhitelist[k] {
			env = append(env, e)
		}
	}
	return env
}

// loadMode deliberately excludes NeedDeps and NeedImports: NeedDeps pulls
// the full AST+types tree of the transitive dependency graph, and
// NeedImports retains that graph as import stubs behind every loaded
// package — ~1 stub tree per retained package is what OOM-killed the host
// on large dep trees (go-getter → aws-sdk-scale). Without them roots still
// get syntax+types, dependencies resolve through export data, and the
// import graph is still reachable via pkg.Types.Imports() — which is all
// the analysis needs: dependency syntax is loaded only for packages named
// by a loadExtra pattern.
const loadMode = packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
	packages.NeedTypes | packages.NeedTypesInfo | packages.NeedModule

// loadConfig builds the single packages.Config every index load shares:
// one environment, one flag set, one cancellation context. fset is nil
// for loads that must not attach the index fileset (the no-syntax
// importer census; the standalone module-reach load). Centralizing the
// construction is the guarantee that product roots, dependency extras
// and census loads cannot silently diverge in GOOS/GOARCH/CGO_ENABLED,
// vendor mode, build tags or toolchain environment.
func (ix *Index) loadConfig(mode packages.LoadMode, fset *token.FileSet, ctx context.Context) *packages.Config {
	cfg := &packages.Config{
		Mode:    mode,
		Dir:     ix.Dir,
		Fset:    fset,
		Env:     ix.loadEnv(),
		Context: ix.ctxOr(ctx),
	}
	if len(ix.Build.BuildTags) > 0 {
		cfg.BuildFlags = []string{"-tags", strings.Join(ix.Build.BuildTags, ",")}
	}
	return cfg
}

// maxSkippedErrors bounds the loader diagnostics retained per skipped
// package — evidence detail, never scope.
const maxSkippedErrors = 8

func (ix *Index) load(ctx context.Context) error {
	if ctx != nil {
		ix.activeCtx = ctx
	}
	if err := ix.checkBuildContextLocked(); err != nil {
		return err
	}
	if ix.loaded {
		return ix.loadErr
	}
	ix.loaded = true
	ix.fset = token.NewFileSet()
	rawPkgs, err := packages.Load(ix.loadConfig(loadMode, ix.fset, ctx), "./...")
	if err != nil {
		ix.loadErr = err
		return ix.loadErr
	}
	var validPkgs []*packages.Package
	skippedImports := make(map[string][]string)
	var skippedUnscanned []string
	var skipped []SkippedPackage
	skippedPkgs := make(map[string]*packages.Package)

	for _, p := range rawPkgs {
		if len(p.Errors) > 0 || p.TypesInfo == nil {
			// p.Imports is not populated under loadMode (NeedImports is
			// deliberately excluded), so recover the failed package's
			// import edges from its syntax or listed Go files. A package
			// whose files cannot even be parsed contributes no recoverable
			// edges at all — mark it unscanned: negative checks must not
			// claim its references were covered. Every failed package
			// also lands in the structured skipped census — including
			// zero-import failures, which used to vanish from the scope
			// denominator entirely.
			d := skippedPackageDiagnostic(ix.fset, p)
			skipped = append(skipped, d)
			for _, impPath := range d.Imports {
				skippedImports[impPath] = append(skippedImports[impPath], d.Path)
			}
			if !d.SourceVisible {
				skippedUnscanned = append(skippedUnscanned, d.Path)
			}
			// The raw package record stays with the skipped set: the
			// shipping-scope builder needs its declared name and clause
			// inventory — a failed package can still link a main.
			skippedPkgs[d.Path] = p
			continue
		}
		validPkgs = append(validPkgs, p)
	}

	ix.skipped = skipped
	ix.skippedPkgs = skippedPkgs
	ix.skippedImports = skippedImports
	ix.skippedUnscanned = skippedUnscanned
	if len(validPkgs) == 0 && len(rawPkgs) > 0 {
		ix.loadErr = fmt.Errorf("all %d packages failed to load (incomplete type information)", len(rawPkgs))
		return ix.loadErr
	}
	ix.pkgs = validPkgs
	// Baseline the snapshot content identity: every later scope/closure
	// query re-derives the fingerprint and fails closed when the bytes,
	// the build selection or the file inventory moved.
	ix.loadedFingerprint = ix.snapshotFingerprintLocked()
	return nil
}

// skippedPackageDiagnostic uses the same bounded diagnostic shape for product
// and dependency loads. A missing type inventory is itself a scope failure.
func skippedPackageDiagnostic(fset *token.FileSet, p *packages.Package) SkippedPackage {
	imports, complete, visible := failedPackageImports(fset, p)
	d := SkippedPackage{Path: p.PkgPath, Imports: imports, ImportsComplete: complete, SourceVisible: visible}
	if d.Path == "" {
		d.Path = p.ID
	}
	for _, e := range p.Errors {
		if len(d.Errors) >= maxSkippedErrors {
			break
		}
		d.Errors = append(d.Errors, e.Error())
	}
	return d
}

// failedLoadDiagnostics caps retained package records even when a single
// module load exceeds the extras cache package budget. The total remains
// visible so omitted diagnostics cannot be mistaken for a closed inventory.
func failedLoadDiagnostics(fset *token.FileSet, pkgs []*packages.Package) ([]SkippedPackage, int) {
	var skipped []SkippedPackage
	total := 0
	for _, p := range pkgs {
		if len(p.Errors) == 0 && p.TypesInfo != nil {
			continue
		}
		total++
		if len(skipped) < maxTotalExtraPkgs {
			skipped = append(skipped, skippedPackageDiagnostic(fset, p))
		}
	}
	return skipped, total
}

// failedPackageImports recovers the import paths a failed package still
// exposes: type-checking may die mid-pass but partial Syntax usually
// survives, and every file carries its own import specs. The second
// result reports whether the recovered import set is complete — every
// listed non-test source file of the package contributed its imports
// (Syntax files plus a fallback parse of whatever GoFiles the loader
// listed but never attached). The third result is false when no file
// could be parsed at all: the package's references are then fully
// invisible. An incomplete import set must never ground "this package
// cannot reference the target" — the unparsed file may carry the edge.
func failedPackageImports(fset *token.FileSet, p *packages.Package) (imports []string, complete, sourceVisible bool) {
	seen := map[string]bool{}
	parsed := map[string]bool{}
	addFile := func(f *ast.File) {
		if pos := fset.Position(f.Package); pos.Filename != "" {
			parsed[pos.Filename] = true
		}
		for _, imp := range f.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if !seen[path] {
				seen[path] = true
				imports = append(imports, path)
			}
		}
	}
	for _, f := range p.Syntax {
		addFile(f)
	}
	// Listed non-test sources the loader never attached syntax for: a
	// package can fail before or during parsing while its files still
	// declare imports. Package.GoFiles already merges cgo files, so the
	// missing-C-header failure shape still yields its sources for
	// import recovery.
	var want []string
	for _, path := range p.GoFiles {
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			continue
		}
		want = append(want, path)
		if !parsed[path] {
			if f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly); err == nil {
				addFile(f)
			}
		}
	}
	// Complete means every listed source file actually parsed — a count
	// comparison would cheat: cgo loads attach generated files outside
	// GoFiles that must not stand in for a missing product source.
	complete = true
	for _, path := range want {
		if !parsed[path] {
			complete = false
			break
		}
	}
	return imports, complete, len(parsed) > 0
}

// SkippedPackagesImporting returns the names of any product packages that failed to
// type-check during index load and directly import targetPkg.
func (ix *Index) SkippedPackagesImporting(targetPkg string) []string {
	if ix == nil || ix.skippedImports == nil {
		return nil
	}
	return ix.skippedImports[targetPkg]
}

// ctxOr prefers the caller's context; a bare Background (internal helpers
// that do not receive one) falls back to the active query context so the
// memory watchdog's cancellation still reaches subprocess loads.
func (ix *Index) ctxOr(ctx context.Context) context.Context {
	if ctx != nil && ctx != context.Background() && ctx != context.TODO() {
		return ctx
	}
	if ix.activeCtx != nil {
		return ix.activeCtx
	}
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

// truncationPackageLoad is the recorded name of a depleted closure-query
// package-load budget. The record is session-scoped; every consumer appends
// the coverage consequence it can speak to, so the name stays stable and the
// limitation text reads naturally per surface.
const truncationPackageLoad = "package-load budget exhausted"

// BeginVerificationSession binds the advisory whose verification session is
// being opened on this index. One index serves many advisories in scan/eval
// mode, and eval runs cases concurrently from the same pointer — a single
// mutable "current case" slot cannot represent that, and resetting the
// truncation record on a case switch would let a concurrent second case erase
// the first case's unresolved state between two of its queries (a silent
// path back to Complete).
//
// The record is therefore append-only for the index lifetime: the first case
// identity is remembered, a second identity marks the index as shared, and
// truncation evidence stays visible to every query of every case. That is the
// fail-closed behaviour when no stable per-case binding exists; a case that
// needs a clean record must use a fresh Index (which reloads the snapshot
// anyway). Resetting budgets here would also be unsafe: a concurrent query
// may hold the only remaining load budget of its own case.
func (ix *Index) BeginVerificationSession(caseID domain.CaseID) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if caseID == "" {
		return
	}
	if ix.sessionCaseID == "" {
		ix.sessionCaseID = caseID
		return
	}
	if ix.sessionCaseID != caseID {
		ix.sessionShared = true
	}
}

// recordTruncationLocked records one named, session-scoped coverage
// truncation. Recording is idempotent and order-stable; entries are never
// removed. Callers MUST hold ix.mu.
func (ix *Index) recordTruncationLocked(name string) {
	if name == "" {
		return
	}
	for _, existing := range ix.sessionTruncations {
		if existing == name {
			return
		}
	}
	ix.sessionTruncations = append(ix.sessionTruncations, name)
	sort.Strings(ix.sessionTruncations)
}

// budgetTruncatedLocked reports whether the verification session ever cut
// its coverage short: the query-scoped depletion flag or any recorded
// session truncation. Callers MUST hold ix.mu.
func (ix *Index) budgetTruncatedLocked() bool {
	return ix.loadBudgetExhausted || len(ix.sessionTruncations) > 0
}

// sessionTruncationBlockersLocked renders the recorded truncations as
// closure blockers — the session-scoped gap statement a closure result
// carries so a repeated, cleaner-looking query cannot absorb it. Callers
// MUST hold ix.mu.
func (ix *Index) sessionTruncationBlockersLocked() []string {
	out := make([]string, 0, len(ix.sessionTruncations))
	for _, t := range ix.sessionTruncations {
		out = append(out, "session coverage truncated: "+t)
	}
	return out
}

// loadExtra loads additional root patterns (e.g. the vulnerable dependency
// package) into the same fileset so its syntax is available for reading.
// Results are cached per pattern: dep packages are reused by dep-internal
// call-site and provenance scans.
func (ix *Index) loadExtra(ctx context.Context, patterns ...string) ([]*packages.Package, error) {
	ctx = ix.ctxOr(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := ix.load(ctx); err != nil {
		return nil, err
	}
	key := strings.Join(patterns, "|")
	if pkgs, ok := ix.extraPkgs[key]; ok {
		return pkgs, nil
	}
	if ix.loadBudget > 0 {
		ix.loadBudget--
		if ix.loadBudget == 0 {
			// Depletion is both query-scoped (further loads in this query
			// are refused) and session-scoped evidence (the truncated
			// coverage stays named for every later completeness claim).
			ix.loadBudgetExhausted = true
			ix.recordTruncationLocked(truncationPackageLoad)
		}
	} else if ix.loadBudgetExhausted {
		return nil, fmt.Errorf("closure query package load budget exhausted")
	}
	pkgs, err := packages.Load(ix.loadConfig(loadMode, ix.fset, ctx), patterns...)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if ix.extraPkgs == nil {
		ix.extraPkgs = map[string][]*packages.Package{}
	}
	// Bound retained dependency graphs: each entry holds a full AST+types
	// tree plus the types graph of its transitively imported packages,
	// so accumulating packages is what blew the host's memory on large
	// dep trees (go-getter → aws-sdk-scale import closures). Extras are
	// reloadable — evict the oldest patterns over budget and let callers
	// re-load the ones they still need.
	ix.extraPkgs[key] = pkgs
	ix.extraOrder = append(ix.extraOrder, key)
	if ix.extraWeight == nil {
		ix.extraWeight = map[string]int{}
	}
	w := 0
	for _, p := range pkgs {
		w += importClosureSize(p.Types)
	}
	ix.extraWeight[key] = w
	ix.evictExtra()
	ix.extrasGen++
	ix.classifyCache = nil
	ix.paramCache = nil
	ix.methodDispatchCache = nil
	ix.reflectLookupCache = nil
	ix.marshalAPICache = nil
	return pkgs, nil
}

// importClosureSize counts the types packages transitively imported by
// tp — the retained memory a loaded package drags behind it via
// types.Package.Imports(). tp=nil weighs 0.
func importClosureSize(tp *types.Package) int {
	if tp == nil {
		return 0
	}
	seen := map[*types.Package]bool{tp: true}
	stack := []*types.Package{tp}
	n := 0
	for len(stack) > 0 {
		p := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, imp := range p.Imports() {
			if imp != nil && !seen[imp] {
				seen[imp] = true
				stack = append(stack, imp)
				n++
			}
		}
	}
	return n
}

// evictExtra drops the oldest loaded patterns until the retained package
// count fits the budget — never the newest entry, which the caller is
// about to use. Dep-caller scans cover only retained extras, so an
// evicted package simply shrinks later scans (conservative direction:
// fewer sites resolved, more UNKNOWN).
func (ix *Index) evictExtra() {
	total, files, imports := 0, 0, 0
	unpinnedTotal, unpinnedFiles, unpinnedImports := 0, 0, 0
	unpinnedLoads := 0
	for pat, pkgs := range ix.extraPkgs {
		pTotal := len(pkgs)
		pFiles := 0
		for _, p := range pkgs {
			pFiles += len(p.GoFiles)
		}
		pImports := ix.extraWeight[pat]
		total += pTotal
		files += pFiles
		imports += pImports
		if !ix.extraPinned[pat] {
			unpinnedTotal += pTotal
			unpinnedFiles += pFiles
			unpinnedImports += pImports
			unpinnedLoads++
		}
	}
	over := func() bool {
		return unpinnedTotal > maxExtraPkgs || unpinnedFiles > maxExtraFiles ||
			unpinnedImports > maxExtraImportClosure || unpinnedLoads > maxExtraLoads ||
			total > maxTotalExtraPkgs
	}
	if !over() {
		return
	}
	newest := ""
	if len(ix.extraOrder) > 0 {
		newest = ix.extraOrder[len(ix.extraOrder)-1]
	}
	evicted := false
	// Pinned victims rotate to the back instead of deleting — the spin
	// bound keeps the loop finite when every candidate is pinned.
	for spins := 0; len(ix.extraOrder) > 1 && over() && spins <= len(ix.extraOrder); {
		victim := ix.extraOrder[0]
		ix.extraOrder = ix.extraOrder[1:]
		if ix.extraPinned[victim] || victim == newest {
			ix.extraOrder = append(ix.extraOrder, victim)
			spins++
			continue
		}
		vpkgs, ok := ix.extraPkgs[victim]
		if !ok {
			continue
		}
		total -= len(vpkgs)
		unpinnedTotal -= len(vpkgs)
		for _, p := range vpkgs {
			files -= len(p.GoFiles)
			unpinnedFiles -= len(p.GoFiles)
		}
		imports -= ix.extraWeight[victim]
		unpinnedImports -= ix.extraWeight[victim]
		unpinnedLoads--
		delete(ix.extraWeight, victim)
		delete(ix.extraPkgs, victim)
		evicted = true
	}
	if evicted {
		for k := range ix.callerCache {
			if k.dep {
				delete(ix.callerCache, k) // entries point at evicted ASTs
			}
		}
		// Every cache that retains AST/package references must drop —
		// otherwise evicted packages stay alive through map entries and
		// the budget bounds nothing.
		ix.funcDeclCache = nil
		ix.assignCache = nil
		ix.callListCache = nil
		ix.fieldTagCache = nil
		ix.fieldWritesCache = nil
		ix.fieldOriginCache = nil
		ix.fieldOwners = nil
		ix.funcValsCache = nil
		ix.fvIdx = nil
		ix.classifyCache = nil
		// The runtime holds freed heap for reuse until SetMemoryLimit
		// pressure forces scavenging — under a watchdog that counts
		// HeapSys, idle garbage looks like retained memory. Hand it back
		// once the heap is large; throttle — FreeOSMemory is a full GC.
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		if m.HeapSys > 1<<30 && time.Since(ix.lastFreeOS) > time.Second {
			debug.FreeOSMemory()
			ix.lastFreeOS = time.Now()
		}
	}
}

// pinExtra exempts a retained load pattern from eviction — used for the
// advisory module a closure is actively verifying. Only reasonably sized
// patterns can pin: an aws-scale module pinned behind the memory budget
// would defeat it, so huge patterns stay evictable (their closure stays
// UNKNOWN — conservative).
func (ix *Index) pinExtra(pattern string) {
	pkgs, ok := ix.extraPkgs[pattern]
	if !ok || len(pkgs) > maxPinnedPkgs {
		return
	}
	if ix.extraPinned == nil {
		ix.extraPinned = map[string]bool{}
	}
	ix.extraPinned[pattern] = true
}

func (ix *Index) pinExtraScoped(pattern string) func() {
	wasPinned := ix.extraPinned[pattern]
	ix.pinExtra(pattern)
	return func() {
		if !wasPinned {
			delete(ix.extraPinned, pattern)
		}
	}
}

// extrasFor returns cached dependency packages matching pkgPath (loaded
// via loadExtra), or nil when the package was never loaded.
func (ix *Index) extrasFor(pkgPath string) []*packages.Package {
	var out []*packages.Package
	for _, pkgs := range ix.extraPkgs {
		for _, p := range pkgs {
			if p.PkgPath == pkgPath {
				out = append(out, p)
			}
		}
	}
	return out
}

// allExtras returns every dependency package loaded so far — used by
// dep-internal scans that must look beyond product roots.
func (ix *Index) allExtras() []*packages.Package {
	var out []*packages.Package
	for _, pkgs := range ix.extraPkgs {
		out = append(out, pkgs...)
	}
	return out
}

// isProductPkg reports whether pkg is one of the ./... product roots.
// Dependency packages (module cache, replaced local deps) are not product
// even when their path looks similar — provenance scans use this to keep
// product-scope and dep-scope callers apart.
func (ix *Index) isProductPkg(pkg *packages.Package) bool {
	for _, p := range ix.pkgs {
		if p == pkg {
			return true
		}
	}
	return false
}

// Loaded reports whether the index can answer structural queries; if false,
// callers must treat results as tool failures (UNKNOWN, never FALSE inputs).
func (ix *Index) Loaded(ctx context.Context) error {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	return ix.load(ctx)
}

// FindSymbol locates a symbol (function or method) by package path and name.
// The name may be "Func" or "Type.Method"/"(*Type).Method".
func (ix *Index) FindSymbol(ctx context.Context, ref domain.SymbolRef) (*domain.CallSite, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	return ix.findSymbol(ctx, ref)
}

func (ix *Index) findSymbol(ctx context.Context, ref domain.SymbolRef) (*domain.CallSite, error) {
	if err := ix.load(ctx); err != nil {
		return nil, err
	}
	typeName, meth := splitSymbol(ref.Symbol)
	for _, pkg := range ix.pkgs {
		if pkg.Types == nil {
			continue
		}
		if pkg.PkgPath != ref.Package {
			continue
		}
		if cs := findObjectInPkg(ix.fset, pkg, typeName, meth); cs != nil {
			return cs, nil
		}
		if symbolLookupAmbiguous(pkg, typeName, meth) {
			return nil, fmt.Errorf("%w: %s.%s", ErrAmbiguousSymbol, ref.Package, ref.Symbol)
		}
		return nil, fmt.Errorf("%w: %s.%s", ErrSymbolNotFoundInPackage, ref.Package, ref.Symbol)
	}
	// symbol may live in a dependency that is not a loaded root
	extra, err := ix.loadExtra(ctx, ref.Package)
	if err != nil {
		return nil, err
	}
	for _, pkg := range extra {
		if pkg.PkgPath != ref.Package || pkg.Types == nil {
			continue
		}
		if cs := findObjectInPkg(ix.fset, pkg, typeName, meth); cs != nil {
			return cs, nil
		}
		if symbolLookupAmbiguous(pkg, typeName, meth) {
			return nil, fmt.Errorf("%w: %s.%s", ErrAmbiguousSymbol, ref.Package, ref.Symbol)
		}
		return nil, fmt.Errorf("%w: %s.%s", ErrSymbolNotFoundInPackage, ref.Package, ref.Symbol)
	}
	return nil, fmt.Errorf("symbol %s.%s not found", ref.Package, ref.Symbol)
}

// EnclosingFuncAt locates the function or method declaration that encloses
// the given 1-based line number in a file whose path matches relPath.
// If pkgPath is non-empty, that package is loaded if not already present.
func (ix *Index) EnclosingFuncAt(ctx context.Context, pkgPath, relPath string, line int) (domain.SymbolRef, error) {
	if ix == nil || relPath == "" || line <= 0 {
		return domain.SymbolRef{}, fmt.Errorf("invalid arguments")
	}
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ctx); err != nil {
		return domain.SymbolRef{}, err
	}
	cleanRel := filepath.Clean(relPath)
	slashRel := filepath.ToSlash(cleanRel)

	findInPkg := func(pkg *packages.Package) (domain.SymbolRef, bool) {
		if pkg == nil || pkg.Types == nil {
			return domain.SymbolRef{}, false
		}
		for _, f := range pkg.Syntax {
			pos := ix.fset.File(f.Pos())
			if pos == nil {
				continue
			}
			slashPath := filepath.ToSlash(pos.Name())
			if !strings.HasSuffix(slashPath, slashRel) && !strings.HasSuffix(slashPath, "/"+slashRel) {
				continue
			}
			for _, decl := range f.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Name == nil {
					continue
				}
				start := ix.fset.Position(fd.Pos()).Line
				end := ix.fset.Position(fd.End()).Line
				if line >= start && line <= end {
					sym := fd.Name.Name
					if fd.Recv != nil && len(fd.Recv.List) > 0 {
						sym = recvDeclName(fd.Recv.List[0].Type) + "." + sym
					}
					return domain.SymbolRef{
						Package: pkg.PkgPath,
						Symbol:  sym,
					}, true
				}
			}
		}
		return domain.SymbolRef{}, false
	}

	for _, pkg := range ix.pkgs {
		if ref, found := findInPkg(pkg); found {
			return ref, nil
		}
	}
	for _, pkgs := range ix.extraPkgs {
		for _, pkg := range pkgs {
			if ref, found := findInPkg(pkg); found {
				return ref, nil
			}
		}
	}
	if pkgPath != "" {
		extra, err := ix.loadExtra(ctx, pkgPath)
		if err == nil {
			for _, pkg := range extra {
				if ref, found := findInPkg(pkg); found {
					return ref, nil
				}
			}
		}
	}
	return domain.SymbolRef{}, fmt.Errorf("no function encloses line %d in %s", line, relPath)
}

func splitSymbol(sym string) (typeName, name string) {
	s := strings.TrimPrefix(sym, "*")
	if i := strings.Index(s, "."); i >= 0 {
		return s[:i], s[i+1:]
	}
	return "", sym
}

// IsCheckMember reports whether a method name suggests a validation, verification,
// or authorization check whose omission is itself the vulnerable behavior
// (missing-call shape like GO-2020-0017 MapClaims.VerifyAudience).
// Non-check methods (action sinks like SendFile, ServeFile, Exec, Write) are
// execution sites where deadness proves the vulnerable code is never executed.
func IsCheckMember(name string) bool {
	return isCheckMember(name)
}

func isCheckMember(name string) bool {
	checkPrefixes := []string{"Verify", "Validate", "Check", "Authenticate", "Authorize", "Is", "Has"}
	for _, p := range checkPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

func findObjectInPkg(fset *token.FileSet, pkg *packages.Package, typeName, name string) *domain.CallSite {
	if typeName == "" {
		if obj := pkg.Types.Scope().Lookup(name); obj != nil {
			return callSiteFor(fset, pkg, obj)
		}
		// Bare name may be a method whose receiver the caller did not
		// preserve (e.g. "recvContent" for (*Channel).recvContent).
		return findMethodInPkg(fset, pkg, name)
	}
	tn := pkg.Types.Scope().Lookup(typeName)
	if tn == nil {
		return nil
	}
	named, ok := tn.(*types.TypeName)
	if !ok {
		return nil
	}
	for _, obj := range []*types.Named{mustNamed(named)} {
		if obj == nil {
			continue
		}
		for i := 0; i < obj.NumMethods(); i++ {
			m := obj.Method(i)
			if m.Name() == name {
				return callSiteFor(fset, pkg, m)
			}
		}
		// Struct fields resolve as symbols too — presence checks for
		// sensitive data ("Config.SASL") name fields, not methods.
		if st, ok := obj.Underlying().(*types.Struct); ok {
			for i := 0; i < st.NumFields(); i++ {
				if st.Field(i).Name() == name {
					return callSiteFor(fset, pkg, st.Field(i))
				}
			}
		}
	}
	return nil
}

// findMethodInPkg locates a uniquely-named method across all named
// types in the package. Multiple matches are ambiguous -> nil, so the
// caller reports the candidate as unverified rather than guessing.
func findMethodInPkg(fset *token.FileSet, pkg *packages.Package, name string) *domain.CallSite {
	var found *domain.CallSite
	for _, n := range pkg.Types.Scope().Names() {
		tn, ok := pkg.Types.Scope().Lookup(n).(*types.TypeName)
		if !ok {
			continue
		}
		nt := mustNamed(tn)
		if nt == nil {
			continue
		}
		for i := 0; i < nt.NumMethods(); i++ {
			if nt.Method(i).Name() == name {
				if found != nil {
					return nil
				}
				found = callSiteFor(fset, pkg, nt.Method(i))
			}
		}
	}
	return found
}

// symbolLookupAmbiguous reports whether a bare-name lookup (typeName == "")
// hit the ambiguous case findMethodInPkg silently drops: several named
// types declare a method with this name. The caller turns the nil result
// into ErrAmbiguousSymbol instead of ErrSymbolNotFoundInPackage — absence
// was never proven.
func symbolLookupAmbiguous(pkg *packages.Package, typeName, name string) bool {
	if typeName != "" || pkg.Types == nil {
		return false
	}
	if pkg.Types.Scope().Lookup(name) != nil {
		return false // a package-level declaration resolved the name
	}
	matches := 0
	for _, n := range pkg.Types.Scope().Names() {
		tn, ok := pkg.Types.Scope().Lookup(n).(*types.TypeName)
		if !ok {
			continue
		}
		nt := mustNamed(tn)
		if nt == nil {
			continue
		}
		for i := range nt.NumMethods() {
			if nt.Method(i).Name() == name {
				matches++
				if matches > 1 {
					return true
				}
			}
		}
	}
	return false
}

func mustNamed(tn *types.TypeName) *types.Named {
	if n, ok := tn.Type().(*types.Named); ok {
		return n
	}
	return nil
}

func callSiteFor(fset *token.FileSet, pkg *packages.Package, obj types.Object) *domain.CallSite {
	pos := fset.Position(obj.Pos())
	return &domain.CallSite{
		File:     pos.Filename,
		Line:     pos.Line,
		Function: obj.Name(),
		Package:  pkg.PkgPath,
	}
}

// SearchSymbol returns every reference to the symbol inside product
// packages — direct calls, value references (assignments, interface
// satisfaction candidates), qualified type names, and for field-qualified
// subjects ("Type.Field") field selections and composite-literal keys.
func (ix *Index) SearchSymbol(ctx context.Context, ref domain.SymbolRef) ([]domain.CallSite, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ctx); err != nil {
		return nil, err
	}
	return ix.productRefsTo(ref), nil
}

// productRefsTo scans product packages for references to ref — calls,
// value reads/writes and address-takes included, since a ref bound into a
// func value is an invocation the static call scan cannot see.
func (ix *Index) productRefsTo(ref domain.SymbolRef) []domain.CallSite {
	var out []domain.CallSite
	for _, pkg := range ix.pkgs {
		info := pkg.TypesInfo
		if info == nil {
			continue
		}
		for _, f := range pkg.Syntax {
			// Selector .Sel idents and composite-literal field keys are
			// matched at their parent nodes, where the receiver/literal
			// type can disambiguate which struct declares the field.
			skip := map[*ast.Ident]bool{}
			ast.Inspect(f, func(n ast.Node) bool {
				switch e := n.(type) {
				case *ast.SelectorExpr:
					skip[e.Sel] = true
				case *ast.CompositeLit:
					for _, elt := range e.Elts {
						if kv, ok := elt.(*ast.KeyValueExpr); ok {
							if id, ok := kv.Key.(*ast.Ident); ok {
								skip[id] = true
							}
						}
					}
				}
				return true
			})
			inspectDecls(f, func(n ast.Node, enc *ast.FuncDecl) bool {
				match := false
				switch e := n.(type) {
				case *ast.Ident:
					if !skip[e] {
						match = symRefIdent(info, e, ref)
					}
				case *ast.SelectorExpr:
					match = selRefMatch(info, e, ref)
				case *ast.CompositeLit:
					match = litFieldMatch(info, e, ref)
				}
				if !match {
					return true
				}
				site := domain.CallSite{
					File:    ix.fset.Position(n.Pos()).Filename,
					Line:    ix.fset.Position(n.Pos()).Line,
					Package: pkg.PkgPath,
				}
				if enc != nil && enc.Name != nil {
					site.Function = enc.Name.Name
				}
				out = append(out, site)
				return true
			})
		}
	}
	return out
}

// inspectDecls walks every declaration of f with the true enclosing
// function: enc is the FuncDecl inside function bodies and nil at package
// level. Whole-file ast.Inspect with a sticky `enc` misattributes
// package-level nodes (var initializers, interface decls) to the last
// function above them — a misattributed site can then carry the wrong
// function's liveness verdict. FuncLit bodies nested under a package-level
// declaration are attributed to the package init: their calls run only
// through stored invocation, and init-machinery edges stay the
// conservative answer.
func inspectDecls(f *ast.File, visit func(n ast.Node, enc *ast.FuncDecl) bool) {
	for _, decl := range f.Decls {
		enc, _ := decl.(*ast.FuncDecl)
		ast.Inspect(decl, func(n ast.Node) bool {
			return visit(n, enc)
		})
	}
}

// CallSiteRef pairs the exported CallSite with its internal AST handle.
type CallSiteRef struct {
	Site      domain.CallSite
	call      *ast.CallExpr
	enclosing *ast.FuncDecl
	pkg       *packages.Package
	// possible marks a caller site whose target set may be incomplete.
	possible bool
}

// FindCallers returns statically resolved call sites of the symbol inside
// the product packages (loaded ./... roots).
func (ix *Index) FindCallers(ctx context.Context, ref domain.SymbolRef) ([]domain.CallSite, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	refs, err := ix.findCallSites(ctx, ref)
	if err != nil {
		return nil, err
	}
	out := make([]domain.CallSite, 0, len(refs))
	for _, r := range refs {
		out = append(out, r.Site)
	}
	return out, nil
}

func (ix *Index) findCallSites(ctx context.Context, ref domain.SymbolRef) ([]CallSiteRef, error) {
	if err := ix.load(ctx); err != nil {
		return nil, err
	}
	return ix.findCallSitesIn(ix.pkgs, ref), nil
}

// findCallSitesIn scans every file of pkgs for calls to ref. Files are
// scanned in parallel — the trace loop calls this repeatedly, and AST
// scans are the hot path on real dependency trees. Results concatenate in
// the original (pkg, file) order, so the output is identical to a
// sequential scan.
func (ix *Index) findCallSitesIn(pkgs []*packages.Package, ref domain.SymbolRef) []CallSiteRef {
	type fileJob struct {
		pkg  *packages.Package
		file *ast.File
	}
	var jobs []fileJob
	for _, pkg := range pkgs {
		if pkg.TypesInfo == nil {
			continue
		}
		for _, f := range pkg.Syntax {
			jobs = append(jobs, fileJob{pkg, f})
		}
	}
	perFile := make([][]CallSiteRef, len(jobs))
	workers := runtime.GOMAXPROCS(0)
	if workers > len(jobs) {
		workers = len(jobs)
	}
	if workers > 1 {
		var wg sync.WaitGroup
		next := make(chan int, workers)
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range next {
					j := jobs[i]
					perFile[i] = ix.scanFileForCalls(j.pkg, j.file, ref)
				}
			}()
		}
		for i := range jobs {
			next <- i
		}
		close(next)
		wg.Wait()
	} else {
		for i, j := range jobs {
			perFile[i] = ix.scanFileForCalls(j.pkg, j.file, ref)
		}
	}
	var out []CallSiteRef
	for _, refs := range perFile {
		out = append(out, refs...)
	}
	return out
}

// scanFileForCalls finds call sites of ref within one syntax file —
// read-only, safe for concurrent use across files.
func (ix *Index) scanFileForCalls(pkg *packages.Package, f *ast.File, ref domain.SymbolRef) []CallSiteRef {
	var out []CallSiteRef
	info := pkg.TypesInfo
	inspectDecls(f, func(n ast.Node, enc *ast.FuncDecl) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if callIsSymbol(info, call.Fun, ref) {
			site := ix.siteOf(pkg, enc, call)
			out = append(out, CallSiteRef{Site: site, call: call, enclosing: enc, pkg: pkg})
		}
		return true
	})
	return out
}

// FindDepCallers locates call sites of the symbol inside the dependency
// packages themselves — for unexported subjects that product code cannot
// name (peer-driven library internals). The subject's package is loaded on
// demand; unexported callers can only live in that same package.
func (ix *Index) FindDepCallers(ctx context.Context, ref domain.SymbolRef) ([]domain.CallSite, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	refs, err := ix.findDepCallSites(ctx, ref)
	if err != nil {
		return nil, err
	}
	out := make([]domain.CallSite, 0, len(refs))
	for _, r := range refs {
		out = append(out, r.Site)
	}
	return out, nil
}

func (ix *Index) findDepCallSites(ctx context.Context, ref domain.SymbolRef) ([]CallSiteRef, error) {
	pkgs, err := ix.loadExtra(ctx, ref.Package)
	if err != nil {
		return nil, err
	}
	// Widen to the subject's whole module when it is known — a caller in
	// a sibling package is as much a dep caller as one in the subject's
	// own package. depModuleCallSites falls back to this function when
	// the module is unknown.
	mod := ""
	for _, p := range pkgs {
		if p.PkgPath == ref.Package && p.Module != nil {
			mod = p.Module.Path
			break
		}
	}
	if mod == "" {
		return ix.findCallSitesIn(ix.extrasFor(ref.Package), ref), nil
	}
	return ix.depModuleCallSites(ctx, ref, mod)
}

// DepInvocationState reports how the subject's own module uses it:
// dep-internal call sites of the subject that a live caller chain can
// reach (a dead caller cannot resurrect the subject — deadness is
// decided transitively, see depSiteLive), and — when the subject is a
// method never invoked there — whether sibling methods on the same
// receiver type ARE invoked inside the dependency.
//
// siblingLive is a source observation only. It identifies a candidate
// shape for investigation (a live receiver pipeline beside a never-called
// member); it is not defect semantics and must not veto a deadness
// measurement. The admitted defect-semantics contract decides whether the
// dead member's invocation is necessary (domain.ValidateDeadnessPremise).
//
// Callers are enumerated across the subject's whole module; when the
// subject is exported and other dep modules import its package, the
// caller set is unbounded (unbounded=true) — absence of callers within
// the module then cannot ground a negative either.
func (ix *Index) DepInvocationState(ctx context.Context, ref domain.SymbolRef) (callers int, siblingLive, unbounded bool, err error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if _, err := ix.loadExtra(ctx, ref.Package); err != nil {
		return 0, false, false, err
	}
	subjPkgs := ix.extrasFor(ref.Package)
	mod := ""
	for _, p := range subjPkgs {
		if p.Module != nil {
			mod = p.Module.Path
			break
		}
	}
	_, name := splitSymbol(ref.Symbol)
	if ast.IsExported(name) {
		importers, ierr := ix.depImporters(ctx)
		if ierr != nil {
			unbounded = true
		} else {
			var otherPkgs []string
			for _, im := range importers[ref.Package] {
				if !ix.isProductPath(im.path) && im.module != mod {
					otherPkgs = append(otherPkgs, im.path)
				}
			}
			if len(otherPkgs) > 0 {
				if len(otherPkgs) <= 16 {
					for _, op := range otherPkgs {
						opLoaded, lerr := ix.loadExtra(ctx, op)
						if lerr != nil {
							unbounded = true
							break
						}
						otherSites := ix.findCallSitesIn(opLoaded, ref)
						for _, os := range otherSites {
							if ix.depSiteLive(ctx, os, depLiveFuel, map[string]bool{}) {
								callers++
							}
						}
					}
				} else {
					unbounded = true
				}
			}
		}
	}
	sites, err := ix.depModuleCallSites(ctx, ref, mod)
	if err != nil {
		return 0, false, unbounded, err
	}
	for _, s := range sites {
		if ix.depSiteLive(ctx, s, depLiveFuel, map[string]bool{}) {
			callers++
		}
	}
	if callers > 0 || unbounded {
		return callers, false, unbounded, nil
	}
	typeName, name := splitSymbol(ref.Symbol)
	if typeName == "" || !isCheckMember(name) {
		return 0, false, false, nil
	}
	pkgs := ix.extrasFor(ref.Package)
	if mod != "" {
		pkgs = ix.modulePkgs(mod)
	}
	for _, dep := range pkgs {
		if dep.Types == nil || dep.TypesInfo == nil {
			continue
		}
		tn, ok := dep.Types.Scope().Lookup(typeName).(*types.TypeName)
		if !ok {
			continue
		}
		named := mustNamed(tn)
		if named == nil {
			continue
		}
		ms := types.NewMethodSet(types.NewPointer(named))
		for i := 0; i < ms.Len(); i++ {
			m := ms.At(i).Obj()
			if m.Name() == name {
				continue
			}
			mref := domain.SymbolRef{Package: ref.Package, Symbol: typeName + "." + m.Name()}
			for _, s := range ix.findCallSitesIn(pkgs, mref) {
				if ix.depSiteLive(ctx, s, depLiveFuel, map[string]bool{}) {
					return 0, true, false, nil
				}
			}
		}
	}
	return 0, false, false, nil
}

// ReceiverPipelines finds sibling methods on the receiver type of ref that are
// live in the dependency / reachable from callers (e.g. MapClaims.Valid).
func (ix *Index) ReceiverPipelines(ctx context.Context, ref domain.SymbolRef) ([]domain.SymbolRef, error) {
	if ix == nil {
		return nil, nil
	}
	typeName, name := splitSymbol(ref.Symbol)
	if typeName == "" || !isCheckMember(name) {
		return nil, nil
	}
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if _, err := ix.loadExtra(ctx, ref.Package); err != nil {
		return nil, err
	}
	subjPkgs := ix.extrasFor(ref.Package)
	mod := ""
	for _, p := range subjPkgs {
		if p.Module != nil {
			mod = p.Module.Path
			break
		}
	}
	pkgs := ix.extrasFor(ref.Package)
	if mod != "" {
		pkgs = ix.modulePkgs(mod)
	}

	var pipelines []domain.SymbolRef
	seen := map[string]bool{}

	for _, dep := range pkgs {
		if dep.Types == nil || dep.TypesInfo == nil {
			continue
		}
		tn, ok := dep.Types.Scope().Lookup(typeName).(*types.TypeName)
		if !ok {
			continue
		}
		named := mustNamed(tn)
		if named == nil {
			continue
		}
		var ms *types.MethodSet
		if _, isIface := named.Underlying().(*types.Interface); isIface {
			ms = types.NewMethodSet(named)
		} else {
			ms = types.NewMethodSet(types.NewPointer(named))
		}
		for i := 0; i < ms.Len(); i++ {
			m := ms.At(i).Obj()
			mName := m.Name()
			if mName == name || isCheckMember(mName) {
				continue
			}
			if mName != "Valid" && !strings.HasSuffix(mName, "Valid") {
				continue
			}
			mref := domain.SymbolRef{Package: ref.Package, Symbol: typeName + "." + mName}
			if seen[mref.Symbol] {
				continue
			}

			live := false
			if len(ix.productRefsTo(mref)) > 0 {
				live = true
			} else {
				sites := ix.findCallSitesIn(pkgs, mref)
				for _, iref := range ix.ifaceCallerRefs(mref) {
					sites = append(sites, ix.findCallSitesIn(pkgs, iref)...)
				}
				for _, s := range sites {
					if ix.depSiteLive(ctx, s, depLiveFuel, map[string]bool{}) {
						live = true
						break
					}
				}
			}

			if live {
				seen[mref.Symbol] = true
				pipelines = append(pipelines, mref)
			}
		}
	}
	return pipelines, nil
}

// modulePkgs returns the extras of one module — sibling-method scans
// must see call sites in every package of the subject's module, not only
// its own.
func (ix *Index) modulePkgs(mod string) []*packages.Package {
	var out []*packages.Package
	for _, p := range ix.allExtras() {
		if p.Module != nil && p.Module.Path == mod {
			out = append(out, p)
		}
	}
	return out
}

// depLiveFuel bounds the transitive deadness walk in depSiteLive: a
// deeper caller chain left unexplored answers live rather than guessed
// dead.
const depLiveFuel = 6

// methodInAnyInterface reports whether any interface declared in the product,
// loaded dependency packages, or well-known standard library interfaces
// declares a method with the given name. In Go, dynamic interface dispatch
// is only possible for methods that belong to an interface type.
func (ix *Index) methodInAnyInterface(name string) bool {
	switch name {
	case "Read", "Write", "Close", "Seek", "ReadAt", "WriteAt", "ReadFrom", "WriteTo",
		"ServeHTTP", "String", "Error", "Format", "Scan", "Reset", "Flush",
		"Header", "WriteHeader", "Lock", "Unlock", "RLock", "RUnlock",
		"Timeout", "Temporary", "Len", "Less", "Swap":
		return true
	}
	checkPkg := func(p *packages.Package) bool {
		if p.Types == nil {
			return false
		}
		scope := p.Types.Scope()
		for _, n := range scope.Names() {
			obj := scope.Lookup(n)
			tn, ok := obj.(*types.TypeName)
			if !ok {
				continue
			}
			if iface, ok := tn.Type().Underlying().(*types.Interface); ok {
				for i := 0; i < iface.NumMethods(); i++ {
					if iface.Method(i).Name() == name {
						return true
					}
				}
			}
		}
		return false
	}
	for _, p := range ix.pkgs {
		if checkPkg(p) {
			return true
		}
	}
	for _, p := range ix.allExtras() {
		if checkPkg(p) {
			return true
		}
	}
	return false
}

// depSiteLive reports whether the dependency call site sits on a chain
// some live code can reach. The falsifier "no product references" is
// only a valid negative when the subject is dead in the effective
// build, and a dep call site is dead only if its own caller chain dies:
// the enclosing function must have no product references, no callers
// left inside the module (recursively), and — when exported — no
// importer outside the module it could be invoked from.
func (ix *Index) depSiteLive(ctx context.Context, s CallSiteRef, fuel int, seen map[string]bool) bool {
	if s.pkg == nil || s.enclosing == nil || s.enclosing.Name == nil {
		return true // package-level/init context runs by construction
	}
	name := s.enclosing.Name.Name
	if name == "init" {
		return true
	}
	callerSym := name
	if s.enclosing.Recv != nil && len(s.enclosing.Recv.List) > 0 {
		typeName := recvDeclName(s.enclosing.Recv.List[0].Type)
		if typeName != "" {
			callerSym = typeName + "." + name
		}
	}
	key := s.pkg.PkgPath + "." + callerSym
	if seen[key] {
		return false // cycle cut — this path contributes nothing new
	}
	if fuel <= 0 {
		return true // unexplored remainder — conservative
	}
	fref := domain.SymbolRef{Package: s.pkg.PkgPath, Symbol: callerSym}
	if len(ix.productRefsTo(fref)) > 0 {
		return true // the product itself can invoke the caller
	}
	mod := ""
	if s.pkg.Module != nil {
		mod = s.pkg.Module.Path
	}
	if ast.IsExported(name) {
		importers, err := ix.depImporters(ctx)
		if err != nil {
			return true
		}
		var otherPkgs []string
		for _, im := range importers[s.pkg.PkgPath] {
			if !ix.isProductPath(im.path) && im.module != mod {
				otherPkgs = append(otherPkgs, im.path)
			}
		}
		if len(otherPkgs) > 16 {
			return true
		}
		for _, op := range otherPkgs {
			opLoaded, lerr := ix.loadExtra(ctx, op)
			if lerr != nil {
				return true
			}
			otherSites := ix.findCallSitesIn(opLoaded, fref)
			for _, os := range otherSites {
				if ix.depSiteLive(ctx, os, fuel-1, seen) {
					return true
				}
			}
		}
	}
	// Check reachability via the module's entry cone:
	if mod != "" {
		if cone := ix.depCone(mod); cone != nil {
			if !cone[key] {
				return false
			}
		} else if s.enclosing.Recv != nil && len(s.enclosing.Recv.List) > 0 && ast.IsExported(name) {
			// Interface dispatch cannot be ruled out when cone is unavailable and an interface declaring this method exists
			if ix.methodInAnyInterface(name) {
				return true
			}
		}
	} else if s.enclosing.Recv != nil && len(s.enclosing.Recv.List) > 0 && ast.IsExported(name) {
		if ix.methodInAnyInterface(name) {
			return true
		}
	}
	seen[key] = true
	defer delete(seen, key)
	inner, err := ix.depModuleCallSites(ctx, fref, mod)
	if err != nil {
		return true
	}
	for _, is := range inner {
		if is.enclosing == s.enclosing && is.pkg == s.pkg {
			continue // the site's own function cannot be its own caller
		}
		if ix.depSiteLive(ctx, is, fuel-1, seen) {
			return true
		}
	}
	return false
}

// depModuleCallSites finds call sites of ref across the subject's whole
// module, not only its own package — a caller may live in a sibling dep
// package. Without module info the scan falls back to the package.
func (ix *Index) depModuleCallSites(ctx context.Context, ref domain.SymbolRef, mod string) ([]CallSiteRef, error) {
	if mod == "" {
		return ix.findDepCallSites(ctx, ref)
	}
	pkgs, err := ix.loadExtra(ctx, mod+"/...")
	if err != nil {
		return nil, err
	}
	var scoped []*packages.Package
	for _, p := range pkgs {
		if p.PkgPath == mod || strings.HasPrefix(p.PkgPath, mod+"/") {
			scoped = append(scoped, p)
		}
	}
	return ix.findCallSitesIn(scoped, ref), nil
}

// depImporter records a package in the product's dependency graph that
// imports a given package, with the module it belongs to.
type depImporter struct {
	path   string
	module string
}

// closurePkgMeta records the per-package facts the import-closure facade
// needs beyond the edge lists: module ownership, the build-selected source
// directory and files (for the linkname scan), vendor residency and
// edge-forging imports (plugin, cgo). broken marks packages the loader
// reported errors for — their recovered edge set is untrusted.
type closurePkgMeta struct {
	dir        string
	goFiles    []string
	cgo        bool
	plugin     bool
	reflect    bool // imports reflect: dispatch over linked code
	usesUnsafe bool // imports unsafe: dispatch over linked code
	vendored   bool
	broken     bool
	hasImports bool     // whether p.Imports was populated at all
	modBind    string   // resolved module identity: path@version plus replacement
	hashFiles  []string // every file the loader selected for the package
}

// depImporters builds the reverse import index of the whole dependency
// closure (product + deps, no syntax) so deadness checks can tell
// whether an exported dep function could be invoked from another
// module. Loaded once per index — the import graph does not change
// while extras come and go. The same load also retains the forward
// edges, module ownership and per-package inventory facts
// (closurePkgMeta) EnumerateImportClosure reports.
func (ix *Index) depImporters(ctx context.Context) (map[string][]depImporter, error) {
	if ix.importers != nil {
		return ix.importers, nil
	}
	ctx = ix.ctxOr(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := ix.load(ctx); err != nil {
		return nil, err
	}
	pkgs, err := packages.Load(ix.loadConfig(
		packages.NeedName|packages.NeedImports|packages.NeedModule|
			packages.NeedFiles|packages.NeedForTest|packages.NeedCompiledGoFiles|
			packages.NeedEmbedFiles, nil, ctx), "all")
	if importerLoadHook != nil {
		importerLoadHook(ix, "loaded")
	}
	if err != nil {
		return nil, err
	}
	// A cancelled load may return a partial package set: publishing it
	// would poison the once-per-index importer cache with an incomplete
	// graph that every later completeness claim reads as authoritative.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	vendorRoot := filepath.Join(ix.Dir, "vendor")
	m := map[string][]depImporter{}
	pm := map[string]string{}
	edges := map[string][]string{}
	meta := map[string]closurePkgMeta{}
	assembled := 0
	for _, p := range pkgs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if p.ForTest != "" {
			// Test-variant packages ("pkg [pkg.test]") drag test-only
			// dependencies into the graph — none of that code links
			// into the product build, so their edges never belong to
			// the shipping import closure.
			continue
		}
		mod := ""
		cm := closurePkgMeta{broken: len(p.Errors) > 0}
		if p.Module != nil {
			mod = p.Module.Path
			cm.modBind = moduleBinding(p.Module)
		}
		pm[p.PkgPath] = mod
		for impPath, impPkg := range p.Imports {
			// The map key is the spelling source files use, which may be
			// the canonical path for a vendored package (source says
			// "golang.org/x/net/..." while the build resolves the
			// vendor/… shadow). Edges and reverse importers must key on
			// the resolved package path or vendored members ghost into
			// unresolvable phantom nodes.
			target := impPath
			if impPkg != nil && impPkg.PkgPath != "" {
				target = impPkg.PkgPath
			}
			m[target] = append(m[target], depImporter{path: p.PkgPath, module: mod})
			edges[p.PkgPath] = append(edges[p.PkgPath], target)
			cm.hasImports = true
			switch target {
			case "plugin":
				cm.plugin = true
			case "C":
				cm.cgo = true
			case "reflect":
				cm.reflect = true
			case "unsafe":
				cm.usesUnsafe = true
			}
		}
		// p.Dir is the build-selected source directory (module cache or
		// vendored shadow); vendored residency keys off it.
		cm.dir = p.Dir
		cm.goFiles = append([]string(nil), p.GoFiles...)
		// The closure hash binds every file the loader selected — Go
		// sources, generated/compiled variants, C/asm/headers and embeds —
		// so mutating a non-Go member file can never replay a prior hash.
		cm.hashFiles = dedupStrings(append(append(append(append([]string(nil),
			p.GoFiles...), p.CompiledGoFiles...), p.OtherFiles...), p.EmbedFiles...))
		if cm.dir != "" {
			rel, rerr := filepath.Rel(vendorRoot, cm.dir)
			if rerr == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				cm.vendored = true
			}
		}
		meta[p.PkgPath] = cm
		assembled++
		if assembled == 1 && importerLoadHook != nil {
			// Progress seam: metadata assembly has begun.
			importerLoadHook(ix, "metadata")
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
	}
	// Final cancellation gate: a context cancelled during metadata assembly
	// must not publish a partial census.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Count only published censuses: an interrupted load is not a
	// completed dependency closure.
	ix.importerLoads++
	ix.importers = m
	ix.importEdges = edges
	ix.pkgModules = pm
	ix.pkgMeta = meta
	return m, nil
}

// moduleBinding renders the resolved identity of the module a package was
// loaded from: the canonical path@version plus, when the build rewrote it,
// the replacement module and the directory the loader actually read. A
// module cache substitution changes the directory component, so the
// closure hash cannot survive a swapped external source.
func moduleBinding(m *packages.Module) string {
	if m == nil {
		return ""
	}
	b := m.Path + "@" + m.Version
	if m.Replace != nil {
		r := m.Replace.Path + "@" + m.Replace.Version
		b += "=>" + r
		if m.Replace.Dir != "" {
			b += "=>" + m.Replace.Dir
		}
	}
	if m.Dir != "" {
		b += "@" + m.Dir
	}
	return b
}

// depModuleOf returns the module a package belongs to, loading the
// reverse-import index lazily when provenance tracing runs before the
// ingress inventory. "" means product/stdlib/unresolvable.
func (ix *Index) depModuleOf(pkgPath string) string {
	if ix.pkgModules == nil {
		_, _ = ix.depImporters(ix.ctxOr(context.Background()))
	}
	return ix.pkgModules[pkgPath]
}

// importedByOtherModule reports whether pkgPath is imported by a
// dependency package outside its own module — a caller chain member
// there is not enumerable by the module-internal scans. Product-side
// importers do not count: product references are checked directly.
// Any doubt (load failure, missing importer data) answers true.
func (ix *Index) importedByOtherModule(ctx context.Context, pkgPath, mod string) bool {
	m, err := ix.depImporters(ctx)
	if err != nil {
		return true
	}
	for _, im := range m[pkgPath] {
		if ix.isProductPath(im.path) || im.module == mod {
			continue
		}
		return true
	}
	return false
}

// callerScope returns the packages to search for callers of a function
// declared in pkg: product packages for product code; for dependency code
// the union of the dep package and product roots (an exported dep function
// may be invoked from either side).
func (ix *Index) callerScope(pkg *packages.Package) []*packages.Package {
	if ix.isProductPkg(pkg) {
		return ix.pkgs
	}
	return append(append([]*packages.Package{}, ix.allExtras()...), ix.pkgs...)
}

// maxExtraLoads bounds how many dependency-load patterns the index
// retains at once; maxExtraPkgs bounds the retained package count;
// maxExtraFiles bounds the retained file count; maxExtraImportClosure
// bounds the total transitively-imported types packages held behind
// retained roots — the dominant hidden mass (every load re-creates the
// types graph of its whole import closure, so an aws-scale root can cost
// hundreds of MB in imported types while counting as one package).
// maxCallerCache bounds memoized caller scans.
const (
	maxExtraLoads         = 64
	maxExtraPkgs          = 96
	maxExtraFiles         = 1000
	maxExtraImportClosure = 5000
	maxPinnedPkgs         = 128
	maxTotalExtraPkgs     = 224
	maxCallerCache        = 8192
	maxClassifyCache      = 65536
	maxAuxCache           = 16384
	// maxTxBuf caps the transformation records one trace accumulates —
	// audit detail, not correctness input.
	maxTxBuf = 8192
)

// callerKey identifies one caller scan: the symbol looked up and which
// scope callerScope picked (product roots only, or the dep+product union).
type callerKey struct {
	ref domain.SymbolRef
	dep bool
}

// classifyKey addresses one classify evaluation: the expression node in
// its enclosing function, the package that type-checked it, and the
// remaining caller-hop depth.
type classifyKey struct {
	pkg   *packages.Package
	enc   *ast.FuncDecl
	expr  ast.Expr
	depth int
}

type classifyResult struct {
	origin domain.DataOrigin
	why    string
}

type assignKey struct {
	enc *ast.FuncDecl
	obj types.Object
}

// cachedCallers records a caller scan. Dep-scope entries expire when the
// extras generation advances — a freshly loaded dep package may hold
// additional callers of the same symbol.
type cachedCallers struct {
	gen  int
	refs []CallSiteRef
}

// callersOf scans for call sites of ref across pkg's caller scope,
// memoized. Deep traces revisit the same enclosing functions repeatedly;
// without this every hop re-walked every loaded package's syntax.
//
// Closure rule: the dep-scope caller set is closed only when a complete,
// reconciled caller scope was scanned on one frozen extras generation.
// A mid-scan generation change (a nested on-demand dependency load) discards
// that pass and retries. The settle cycle reconciles the full eligible scope;
// an evicted package or unretained scope remains open. maxMayCallSettle
// bounds retries; exhausting it reports the union as possible, never a
// false-empty closed scan. Re-entry on the same key returns the open
// sentinel.
const maxMayCallSettle = 4

// callerSettleHook is a package-local test seam for forcing an eviction
// between caller-settle passes. Production leaves it nil; tests use it to
// exercise the same extras-generation transition as a nested load without
// adding an injectable production loader.
var callerSettleHook func(*Index)

// importerLoadHook is a package-local test seam invoked at named stages of
// the dependency census ("loaded" right after packages.Load returns,
// "metadata" once assembly of the first package is done). Production leaves
// it nil; tests use it to cancel the caller's context mid-load or
// mid-assembly and prove that no partial census reaches the cache.
var importerLoadHook func(*Index, string)

func (ix *Index) callersOf(pkg *packages.Package, ref domain.SymbolRef) []CallSiteRef {
	dep := !ix.isProductPkg(pkg)
	key := callerKey{ref: ref, dep: dep}
	if c, ok := ix.callerCache[key]; ok && (!dep || c.gen == ix.extrasGen) {
		// A frozen cache entry satisfies a re-entrant lookup too —
		// serving it beats fabricating open coverage.
		return c.refs
	}
	if ix.callersIn == nil {
		ix.callersIn = map[callerKey]bool{}
	}
	if ix.callersIn[key] {
		return []CallSiteRef{{possible: true}}
	}
	var refs []CallSiteRef
	byCall := map[*ast.CallExpr]int{}
	scopeEvicted := false
	for pass := 0; ; pass++ {
		gen := ix.extrasGen
		if c, ok := ix.callerCache[key]; ok && (!dep || c.gen == gen) {
			return c.refs
		}
		extraBefore := map[string]bool{}
		for pattern := range ix.extraPkgs {
			extraBefore[pattern] = true
		}
		ix.callersIn[key] = true
		passRefs := ix.callerScan(pkg, ref)
		delete(ix.callersIn, key)
		if callerSettleHook != nil {
			hook := callerSettleHook
			callerSettleHook = nil
			hook(ix)
		}
		for pattern := range extraBefore {
			if _, ok := ix.extraPkgs[pattern]; !ok {
				scopeEvicted = true
			}
		}
		if ix.extrasGen == gen {
			// Frozen-generation pass: its sites resolve the accumulated
			// possible ones — a site proven closed on a stable scope
			// loses the possible mark, while sites seen only on churned
			// passes stay possible.
			hasSentinel := scopeEvicted
			for _, r := range passRefs {
				if r.call == nil {
					hasSentinel = true
					continue
				}
				if i, ok := byCall[r.call]; ok {
					refs[i] = r
					continue
				}
				byCall[r.call] = len(refs)
				refs = append(refs, r)
			}
			// A closed pass supersedes churn-only sentinels: open coverage
			// recorded on an unstable scope is invalidated by the frozen
			// scope's closed enumeration; a sentinel survives only when
			// this pass itself saw open coverage.
			out := refs[:0]
			for _, r := range refs {
				if r.call != nil {
					out = append(out, r)
				}
			}
			refs = out
			if hasSentinel {
				refs = append(refs, CallSiteRef{possible: true})
			}
			if scopeEvicted {
				for i := range refs {
					refs[i].possible = true
				}
			}
			if ix.callerCache == nil {
				ix.callerCache = map[callerKey]cachedCallers{}
			}
			if len(ix.callerCache) >= maxCallerCache {
				// Entries are recomputable — a full map is a memory leak
				// shape, not an optimization.
				ix.callerCache = map[callerKey]cachedCallers{}
			}
			ix.callerCache[key] = cachedCallers{gen: gen, refs: refs}
			return refs
		}
		// The scope moved under the scan: keep every site it saw as a
		// possible caller and re-scan against the grown extras — a closed
		// result requires a pass with no generation change.
		for _, r := range passRefs {
			if r.call == nil {
				// The churned pass's own sentinel is already implied by
				// the possible-marking of every accumulated ref.
				continue
			}
			r.possible = true
			if i, ok := byCall[r.call]; ok {
				refs[i].possible = true
				continue
			}
			byCall[r.call] = len(refs)
			refs = append(refs, r)
		}
		if pass+1 >= maxMayCallSettle {
			// Settle bound reached: coverage stayed open throughout, so
			// report the accumulated set (or the empty sentinel) open.
			for i := range refs {
				refs[i].possible = true
			}
			if len(refs) == 0 {
				return []CallSiteRef{{possible: true}}
			}
			return refs
		}
	}
}

// callerScan is a single may-call enumeration pass over pkg's caller
// scope: static call sites, interface-dispatch sites, then function-value
// sites. An extras-generation change during the pass is detected by the
// callersOf wrapper — callerScan itself only records what it saw.
func (ix *Index) callerScan(pkg *packages.Package, ref domain.SymbolRef) []CallSiteRef {
	scope := ix.callerScope(pkg)
	refs := ix.findCallSitesIn(scope, ref)
	// A caller of an interface method is a caller of every implementation:
	// `g.GetFile(...)` where g is a Getter invokes GitGetter.GetFile even
	// though no call site names it. Dispatch through registries
	// (go-getter's getters map, amqp's reader iface) is invisible to a
	// concrete-method-only scan.
	for _, iref := range ix.ifaceCallerRefs(ref) {
		for _, r := range ix.findCallSitesIn(scope, iref) {
			// An interface-dispatch site counts only when it can actually
			// dispatch to ref's impl: `g := registry[key]` with an
			// evaluable key reaches just the registered impls at the key's
			// values. Unevaluable keys keep the site (unknown-biased).
			if t, _ := splitSymbol(ref.Symbol); t != "" {
				if set := ix.dispatchImpls(r.pkg, r.enclosing, r.call); set != nil && !set[t] {
					continue
				}
			}
			if !dupCallSite(refs, r) {
				refs = append(refs, r)
			}
		}
	}
	// Function-value dispatch sites: `f(...)` where f is a func-typed
	// variable — invisible to the name-based scans above. Sites whose
	// candidate set contains ref, or whose set is incomplete while the
	// signature matches, count as callers (may-dispatch is a writer).
	// An open func-value enumeration with no compatible site still leaves
	// coverage open — the empty sentinel carries that state.
	fvSites, fvOpen := ix.funcValueCallSites(scope, ref, ix.funcSigOfRef(ref))
	for _, r := range fvSites {
		if !dupCallSite(refs, r) {
			refs = append(refs, r)
		}
	}
	if fvOpen {
		// Open coverage must reach the caller even alongside resolved
		// sites — the empty sentinel is the only carrier.
		refs = append(refs, CallSiteRef{possible: true})
	}
	return refs
}

// dupCallSite reports whether refs already contains a CallSiteRef for the
// same AST call node.
func dupCallSite(refs []CallSiteRef, r CallSiteRef) bool {
	for _, x := range refs {
		if x.call == r.call {
			return true
		}
	}
	return false
}

// ifaceCallerRefs returns SymbolRefs of interface methods that ref (a
// concrete method pkg.T.M) implements — call sites of those interface
// methods dispatch into T.M. Both the concrete type and the interfaces
// are looked up in the loaded packages; nothing found means no extra
// callers, not no callers.
func (ix *Index) ifaceCallerRefs(ref domain.SymbolRef) []domain.SymbolRef {
	typeName, method := splitSymbol(ref.Symbol)
	if typeName == "" {
		return nil
	}
	var T *types.Named
	for _, p := range append(ix.allExtras(), ix.pkgs...) {
		if p.PkgPath != ref.Package || p.Types == nil {
			continue
		}
		if tn, ok := p.Types.Scope().Lookup(typeName).(*types.TypeName); ok {
			T, _ = tn.Type().(*types.Named)
		}
	}
	if T == nil {
		return nil
	}
	// A concrete type that is never instantiated anywhere in loaded code
	// cannot be the dynamic target of an interface call — its interface
	// callers would merge provenance from frames that never run (mocks
	// shipped in non-test files, dead registry alternatives). Skipped
	// entirely when dynamic materialization is present or the product
	// scope is incomplete: a type-check-failed package's syntax never
	// entered the instantiation set, so absence there proves nothing.
	if inst, narrow := ix.instantiated(); narrow && len(ix.skipped) == 0 &&
		!inst[namedKey(T)] {
		return nil
	}
	var out []domain.SymbolRef
	for _, p := range append(ix.allExtras(), ix.pkgs...) {
		if p.Types == nil {
			continue
		}
		for _, name := range p.Types.Scope().Names() {
			tn, ok := p.Types.Scope().Lookup(name).(*types.TypeName)
			if !ok {
				continue
			}
			named, ok := tn.Type().(*types.Named)
			if !ok {
				continue
			}
			iface, ok := named.Underlying().(*types.Interface)
			if !ok || !types.Implements(types.NewPointer(T), iface) {
				continue
			}
			for i := 0; i < iface.NumMethods(); i++ {
				if iface.Method(i).Name() == method {
					out = append(out, domain.SymbolRef{
						Package: p.PkgPath, Symbol: name + "." + method})
				}
			}
		}
	}
	return out
}

// isProductPath reports whether pkgPath is one of the product roots.
func (ix *Index) isProductPath(pkgPath string) bool {
	for _, p := range ix.pkgs {
		if p.PkgPath == pkgPath {
			return true
		}
	}
	return false
}

// memberScope returns the packages to scan for writes to a struct field
// declared in pkgPath — the same product-vs-dep rule as callerScope.
func (ix *Index) memberScope(pkgPath string) []*packages.Package {
	if ix.isProductPath(pkgPath) {
		return ix.pkgs
	}
	return append(append([]*packages.Package{}, ix.allExtras()...), ix.pkgs...)
}

func callIsSymbol(info *types.Info, fun ast.Expr, ref domain.SymbolRef) bool {
	obj := calleeObject(info, fun)
	fn, ok := obj.(*types.Func)
	if !ok || fn.Pkg() == nil {
		return false
	}
	if fn.Pkg().Path() != ref.Package {
		return false
	}
	typeName, name := splitSymbol(ref.Symbol)
	if fn.Name() != name {
		return false
	}
	if typeName == "" {
		return true
	}
	sig, _ := fn.Type().(*types.Signature)
	if sig == nil || sig.Recv() == nil {
		return false
	}
	return recvTypeName(sig.Recv().Type()) == typeName
}

func calleeObject(info *types.Info, fun ast.Expr) types.Object {
	switch e := fun.(type) {
	case *ast.Ident:
		return info.ObjectOf(e)
	case *ast.SelectorExpr:
		if sel, ok := info.Selections[e]; ok {
			return sel.Obj()
		}
		return info.ObjectOf(e.Sel)
	}
	return nil
}

func recvTypeName(t types.Type) string {
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	if n, ok := t.(*types.Named); ok {
		return n.Obj().Name()
	}
	return ""
}

func (ix *Index) siteOf(pkg *packages.Package, enc *ast.FuncDecl, call *ast.CallExpr) domain.CallSite {
	pos := ix.fset.Position(call.Lparen)
	site := domain.CallSite{
		File:    pos.Filename,
		Line:    pos.Line,
		Column:  pos.Column,
		Package: pkg.PkgPath,
	}
	if enc != nil && enc.Name != nil {
		site.Function = enc.Name.Name
	}
	return site
}

// ReadFunction returns the source text of the function enclosing pos or
// matching name in the given file.
func (ix *Index) ReadFunction(ctx context.Context, file, funcName string) (string, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ctx); err != nil {
		return "", err
	}
	for _, pkg := range ix.pkgs {
		for _, f := range pkg.Syntax {
			fpos := ix.fset.Position(f.Pos())
			if fpos.Filename != file {
				continue
			}
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || (funcName != "" && fn.Name.Name != funcName) {
					continue
				}
				return ix.nodeSource(fn)
			}
		}
	}
	return "", fmt.Errorf("function %s not found in %s", funcName, file)
}

func (ix *Index) nodeSource(n ast.Node) (string, error) {
	start := ix.fset.Position(n.Pos())
	end := ix.fset.Position(n.End())
	if err := ix.gate().Check(start.Filename); err != nil {
		return "", err
	}
	b, err := os.ReadFile(start.Filename)
	if err != nil {
		return "", err
	}
	if start.Offset < 0 || end.Offset > len(b) {
		return "", fmt.Errorf("offsets out of range")
	}
	return string(b[start.Offset:end.Offset]), nil
}

// modCacheDir resolves the Go module cache root: GOMODCACHE (index env
// overrides first, then the process env) else GOPATH[0]/pkg/mod. Empty
// when unresolvable.
func (ix *Index) modCacheDir() string {
	ix.modCacheOnce.Do(func() {
		// Last-match mirrors subprocess env semantics: a GOMODCACHE the
		// caller appended later (e.g. a declared per-run cache) is the one
		// toolchain subprocesses actually see.
		for _, e := range ix.Env {
			if v, ok := strings.CutPrefix(e, "GOMODCACHE="); ok && v != "" {
				ix.modCache = v
			}
		}
		if v := os.Getenv("GOMODCACHE"); ix.modCache == "" && v != "" {
			ix.modCache = v
		}
		if ix.modCache == "" {
			var gopath string
			for _, e := range ix.Env {
				if v, ok := strings.CutPrefix(e, "GOPATH="); ok && v != "" {
					gopath = v
				}
			}
			if gopath == "" {
				gopath = os.Getenv("GOPATH")
			}
			if gopath == "" {
				gopath = build.Default.GOPATH
			}
			if gopath != "" {
				ix.modCache = filepath.Join(filepath.SplitList(gopath)[0], "pkg", "mod")
			}
		}
	})
	return ix.modCache
}

// pathAllowed reports whether an absolute path is inside the analyzed
// repository or inside the Go module cache — the two scopes the agent may
// legitimately read (vulnerable dependency source is evidence too).
// Roots are compared in both lexical and symlink-resolved form: a pinned
// module cache may be declared through a symlink (the session
// canonicalizes it) while callers keep using the spelling they passed.
func (ix *Index) pathAllowed(full string) bool {
	forms := func(p string) []string {
		out := []string{p}
		if resolved, err := filepath.EvalSymlinks(p); err == nil && resolved != p {
			out = append(out, resolved)
		}
		return out
	}
	inside := func(root, target string, excludeSelf bool) bool {
		rel, err := filepath.Rel(root, target)
		if err != nil {
			return false
		}
		if excludeSelf && rel == ".." {
			return false
		}
		return !strings.HasPrefix(rel, "..")
	}
	for _, t := range forms(full) {
		if base, err := filepath.Abs(ix.Dir); err == nil {
			for _, b := range forms(base) {
				if inside(b, t, true) {
					return true
				}
			}
		}
		if mc := ix.modCacheDir(); mc != "" {
			if mabs, err := filepath.Abs(mc); err == nil {
				for _, m := range forms(mabs) {
					if inside(m, t, false) {
						return true
					}
				}
			}
		}
	}
	// Fallback marker for unconventional module caches (mirrors the
	// reviewer's source-scope rule).
	return strings.Contains(full, string(filepath.Separator)+
		"pkg"+string(filepath.Separator)+"mod"+string(filepath.Separator))
}

// ReadSource returns lines [start,end] (1-based, inclusive; 0 = whole
// file) of a file inside the analyzed repository or the Go module cache.
// Paths are confined to those scopes — the agent must not read arbitrary
// filesystem locations.
func (ix *Index) ReadSource(_ context.Context, file string, start, end int) (string, error) {
	clean := filepath.Clean(file)
	abs := clean
	if !filepath.IsAbs(clean) {
		abs = filepath.Join(ix.Dir, clean)
	}
	full, err := filepath.Abs(abs)
	if err != nil {
		return "", err
	}
	if !ix.pathAllowed(full) {
		return "", fmt.Errorf("path %s escapes the analyzed repository/module cache", file)
	}
	if err := ix.gate().Check(full); err != nil {
		return "", err
	}
	b, err := os.ReadFile(full)
	if err != nil {
		return "", err
	}
	lines := strings.Split(string(b), "\n")
	if start <= 0 {
		start = 1
	}
	if end <= 0 || end > len(lines) {
		end = len(lines)
	}
	if start > len(lines) {
		return "", fmt.Errorf("start line %d beyond file length %d", start, len(lines))
	}
	return strings.Join(lines[start-1:end], "\n"), nil
}

const maxSearchMatches = 64

// SearchSource regex-searches the loaded Go files — the product's own
// sources plus dependency sources resolved from the module cache (same
// confinement as ReadSource). Returns up to maxSearchMatches
// "file:line: text" matches; a bad regex is an error.
func (ix *Index) SearchSource(ctx context.Context, pattern string) ([]string, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("bad pattern: %w", err)
	}
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ctx); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, pkg := range ix.pkgs {
		for _, f := range pkg.Syntax {
			fpos := ix.fset.Position(f.Pos())
			name := fpos.Filename
			if seen[name] {
				continue
			}
			seen[name] = true
			if !ix.pathAllowed(name) {
				continue // source outside repository/module cache
			}
			if !ix.gate().Allows(name) {
				continue // source outside the confined roots
			}
			data, err := os.ReadFile(name)
			if err != nil {
				continue
			}
			for i, ln := range strings.Split(string(data), "\n") {
				if re.MatchString(ln) {
					out = append(out, fmt.Sprintf("%s:%d: %s", name, i+1, strings.TrimSpace(ln)))
					if len(out) >= maxSearchMatches {
						return out, nil
					}
				}
			}
		}
	}
	return out, nil
}

// FindEntrypoints enumerates plausible external entrypoints in product
// packages: main/init functions and net/http handlers.
func (ix *Index) FindEntrypoints(ctx context.Context) ([]domain.Entrypoint, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ctx); err != nil {
		return nil, err
	}
	var out []domain.Entrypoint
	for _, pkg := range ix.pkgs {
		for _, f := range pkg.Syntax {
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok {
					continue
				}
				kind := entrypointKind(pkg, fn)
				if kind == "" {
					continue
				}
				pos := ix.fset.Position(fn.Pos())
				out = append(out, domain.Entrypoint{
					CallSite: domain.CallSite{
						File:     pos.Filename,
						Line:     pos.Line,
						Function: fn.Name.Name,
						Package:  pkg.PkgPath,
					},
					Kind:    kind,
					Exposed: ast.IsExported(fn.Name.Name) || kind != "export",
				})
			}
		}
	}
	return out, nil
}

func entrypointKind(pkg *packages.Package, fn *ast.FuncDecl) string {
	switch {
	case pkg.Name == "main" && fn.Name.Name == "main":
		return "main"
	case fn.Name.Name == "init":
		return "init"
	case isHTTPHandler(pkg, fn):
		return "http"
	}
	return ""
}

func isHTTPHandler(pkg *packages.Package, fn *ast.FuncDecl) bool {
	if fn.Type.Params == nil || fn.Type.Params.NumFields() != 2 {
		return false
	}
	info := pkg.TypesInfo
	var sawWriter, sawRequest bool
	for _, field := range fn.Type.Params.List {
		t := info.TypeOf(field.Type)
		if t == nil {
			continue
		}
		s := t.String()
		if strings.HasSuffix(s, "http.ResponseWriter") {
			sawWriter = true
		}
		if strings.HasSuffix(s, "*http.Request") {
			sawRequest = true
		}
	}
	return sawWriter && sawRequest
}

// FindListeners reports product functions that start network listeners or
// servers — i.e. functions whose body calls a listener primitive
// (kb().ListenerPrimitives). Bytes consumed by a reachable server-side
// transport originate from remote peers, not from product code.
func (ix *Index) FindListeners(ctx context.Context) ([]domain.Entrypoint, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ctx); err != nil {
		return nil, err
	}
	var out []domain.Entrypoint
	for _, pkg := range ix.pkgs {
		info := pkg.TypesInfo
		if info == nil {
			continue
		}
		for _, f := range pkg.Syntax {
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				matched := ""
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					if matched != "" {
						return false
					}
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					for _, prim := range ix.kb().ListenerPrimitives {
						if callIsSymbol(info, call.Fun, prim) {
							matched = prim.Package + "." + prim.Symbol
							return false
						}
					}
					return true
				})
				if matched == "" {
					continue
				}
				pos := ix.fset.Position(fn.Pos())
				out = append(out, domain.Entrypoint{
					CallSite: domain.CallSite{
						File:     pos.Filename,
						Line:     pos.Line,
						Function: fn.Name.Name,
						Package:  pkg.PkgPath,
					},
					Kind:    "listener",
					Detail:  matched,
					Exposed: true,
				})
			}
		}
	}
	return out, nil
}

// ModuleUsage reports product call sites whose callee package matches the
// module path prefix. Each site carries the actual owner from the import
// graph; nested modules and unresolved owners remain visible to consumers
// but cannot count as confirmed calls into the requested module.
func (ix *Index) ModuleUsage(ctx context.Context, module string) ([]domain.CallSite, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ctx); err != nil {
		return nil, err
	}
	var out []domain.CallSite
	for _, pkg := range ix.pkgs {
		info := pkg.TypesInfo
		if info == nil {
			continue
		}
		for _, f := range pkg.Syntax {
			inspectDecls(f, func(n ast.Node, enc *ast.FuncDecl) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				obj := calleeObject(info, call.Fun)
				fn, ok := obj.(*types.Func)
				if !ok || fn.Pkg() == nil {
					return true
				}
				p := fn.Pkg().Path()
				if p != module && !strings.HasPrefix(p, module+"/") {
					return true
				}
				owner := ix.depModuleOf(p)
				site := ix.siteOf(pkg, enc, call)
				site.Callee = p + "." + fn.Name()
				site.ModuleOwner = owner
				if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
					rn := strings.TrimPrefix(sig.Recv().Type().String(), "*")
					if i := strings.LastIndexByte(rn, '.'); i >= 0 {
						rn = rn[i+1:]
					}
					site.Callee = p + "." + rn + "." + fn.Name()
				}
				gated, dead, detail, _ := ix.checkCallSiteGuardLocked(ctx, site)
				site.DeadCode = dead
				if gated || dead {
					site.GatedBy = detail
				}
				out = append(out, site)
				return true
			})
		}
	}
	return out, nil
}

type opaqueSite struct {
	sig   *types.Signature
	iface *types.Interface
}

// ModuleInternalReach resolves which of the given subjects are reachable from
// the entry symbols (module API functions the product calls) through call
// edges inside the vendored module source. Returns subject key ("pkg.Symbol")
// to the discovered call chain (entry → ... → subject). Type-resolved: method
// calls match the subject only when the receiver type is the subject's.
//
// Dispatch inside the module is handled explicitly: calls through interface
// values (plugin/getter registries like go-getter's `getters[scheme].Get`)
// resolve to the interface method, and every concrete implementation in the
// module is linked interface-method → impl, so BFS can pass through.
// Calls that resolve to no function at all (func values, map-indexed
// non-interface calls) set opaque: an unreached subject then proves
// nothing — callers must treat absence as UNKNOWN, never FALSE.
func (ix *Index) ModuleInternalReach(ctx context.Context, module string, entries []string, subjects []domain.SymbolRef) (ModuleReachabilityResult, error) {
	pkgs, err := ix.loadModulePackages(ctx, module)
	if err != nil {
		return ModuleReachabilityResult{}, err
	}
	g := ix.moduleReachabilityGraph(pkgs, module, entries)
	reachable, opaque, err := ix.moduleSubjectReach(g, subjects)
	if err != nil {
		return ModuleReachabilityResult{}, err
	}
	// The cone's own completeness (every module package type-checked, no
	// linkname/plugin materialization) plus the product census the entries
	// were derived from. An incomplete census can hide the call that would
	// seed the subject, so an unreached subject is UNKNOWN, not absent.
	return ModuleReachabilityResult{
		Reachable: reachable,
		Complete:  g.complete && ix.SourceScanComplete(),
		Opaque:    opaque,
	}, nil
}

// ModuleReachabilityResult is the typed outcome of one intra-module
// reachability measurement. Reachable carries every discovered positive
// chain even when the measurement is incomplete; Complete/Opaque say whether
// the absence of a chain is a measured negative.
type ModuleReachabilityResult struct {
	Reachable map[string][]string
	Complete  bool
	Opaque    bool
}

// SourceScanComplete reports whether the product source census the index
// loaded is complete for a negative measurement: every product package
// loaded and type-checked, no package carries dynamic materialization, and
// no query/session budget truncated dependency coverage. It is a fact about
// the loaded census, never inferred from a nil error.
func (ix *Index) SourceScanComplete() bool {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	return len(ix.skipped) == 0 && !ix.budgetTruncatedLocked()
}

// loadModulePackages loads the whole module tree (module + /...) with full
// syntax and type information — the source the intra-module call graph is
// built from. ModuleInternalReach keeps its own load (separate from the
// extras cache) so its result never depends on prior query state. The
// separate fileset shares env/flags/cancellation with every other load via
// loadConfig — an earlier inline config dropped BuildTags and silently
// diverged from the product-root context on tag-gated modules.
func (ix *Index) loadModulePackages(ctx context.Context, module string) ([]*packages.Package, error) {
	// ModuleInternalReach deliberately does not hold the query lock (it
	// works on its own package set); the build-context guard still needs
	// the lock because it may capture the bound context on first use.
	ix.mu.Lock()
	guardErr := ix.checkBuildContextLocked()
	ix.mu.Unlock()
	if guardErr != nil {
		return nil, guardErr
	}
	fset := token.NewFileSet()
	return packages.Load(ix.loadConfig(loadMode, fset, ctx), module+"/...")
}

// moduleGraph is the intra-module call graph plus the forward reachability
// cone from a seed set: edges map caller keys ("pkg.F"/"pkg.Recv.F") to
// callee keys, opaque records unresolved dispatch sites per caller key,
// reachable maps every cone member to its BFS parent (seeds carry "").
// complete is true only when every loaded module package type-checked and
// no package carries dynamic materialization (go:linkname, plugin
// imports): either can forge edges the import graph cannot see, so
// out-of-cone functions could still execute. dynLink records the
// materialization case separately — it also poisons the linked/unlinked
// package verdict, since a linkname-pulled package runs without an
// import edge. declared lists the function keys each module package
// actually declares (including the "init" sentinel), used when a
// recorded site name must be resolved to real declarations.
type moduleGraph struct {
	pkgs      []*packages.Package
	edges     map[string]map[string]bool
	opaque    map[string][]opaqueSite
	reachable map[string]string
	complete  bool
	dynLink   bool
	declared  map[string]map[string]bool
}

// moduleReachabilityGraph is the shared module-cone engine: it builds the
// intra-module call graph over pkgs and computes the forward cone from
// seeds. Seeds are the keys callers (ModuleInternalReach passes product-used
// API entries; the unreachability verifier additionally seeds "init" of
// shipping-linked module packages). Package-level statements run under the
// package's init machinery, so call sites inside var initializers are
// recorded as "pkg.init" -> callee edges — inert for entry-seeded walks,
// essential once init is a seed.
func (ix *Index) moduleReachabilityGraph(pkgs []*packages.Package, module string, seeds []string) *moduleGraph {
	edges, opaqueSites := ix.moduleEdgesSites(pkgs, module)
	g := &moduleGraph{
		pkgs:      pkgs,
		edges:     edges,
		opaque:    opaqueSites,
		reachable: map[string]string{},
		complete:  true,
		declared:  map[string]map[string]bool{},
	}
	for _, pkg := range pkgs {
		if !domain.PackageInModule(pkg.PkgPath, module) {
			continue
		}
		if len(pkg.Errors) > 0 || pkg.TypesInfo == nil {
			g.complete = false
		}
		if productFileDynamicLink(pkg.Syntax) {
			// go:linkname and plugin loading materialize targets the
			// import graph cannot see — the cone is no longer closed,
			// so absence from it must never read as DEAD.
			g.dynLink = true
			g.complete = false
		}
		if g.declared[pkg.PkgPath] == nil {
			g.declared[pkg.PkgPath] = map[string]bool{}
		}
		g.declared[pkg.PkgPath]["init"] = true
		for _, f := range pkg.Syntax {
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Name == nil {
					continue
				}
				sym := fn.Name.Name
				if fn.Recv != nil && len(fn.Recv.List) > 0 {
					sym = recvDeclName(fn.Recv.List[0].Type) + "." + sym
				}
				g.declared[pkg.PkgPath][sym] = true
			}
		}
	}
	// Forward BFS over resolved edges; parents record the discovery chain.
	var queue []string
	for _, e := range seeds {
		if _, seen := g.reachable[e]; !seen {
			g.reachable[e] = ""
			queue = append(queue, e)
		}
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for next := range g.edges[cur] {
			if _, seen := g.reachable[next]; !seen {
				g.reachable[next] = cur
				queue = append(queue, next)
			}
		}
	}
	return g
}

// bfsChainFrom reconstructs the seed→target path recorded by the cone's
// parent map — the same chain shape bfsChain produced.
func bfsChainFrom(parents map[string]string, target string) []string {
	if _, ok := parents[target]; !ok {
		return nil
	}
	var rev []string
	for n := target; ; {
		rev = append(rev, n)
		p, ok := parents[n]
		if !ok || p == "" {
			break
		}
		n = p
	}
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	return rev
}

// moduleSubjectReach answers which subjects are reachable inside a module
// cone and whether opaque dispatch in the reachable part keeps the rest
// unknown. This is the subject-facing half of ModuleInternalReach, shared
// with the unreachability verifier's filtered cone.
func (ix *Index) moduleSubjectReach(g *moduleGraph, subjects []domain.SymbolRef) (map[string][]string, bool, error) {
	out := map[string][]string{}
	var unreached []domain.SymbolRef
	for _, subj := range subjects {
		target := subj.Package + "." + subj.Symbol
		if chain := bfsChainFrom(g.reachable, target); chain != nil {
			out[target] = chain
		} else {
			unreached = append(unreached, subj)
		}
	}
	if len(unreached) == 0 {
		return out, false, nil
	}

	// Opaque dispatch (func values, dynamic calls) only invalidates reachability
	// if an opaque call site is actually reachable from the cone's seed set AND
	// its signature or interface is compatible with an unreached subject.
	var reachableSites []opaqueSite
	for oc, sites := range g.opaque {
		if len(sites) == 0 {
			continue
		}
		if _, ok := g.reachable[oc]; ok {
			reachableSites = append(reachableSites, sites...)
		}
	}
	if len(reachableSites) == 0 {
		return out, false, nil
	}

	opaque := false
	for _, subj := range unreached {
		subjObj, recvType := findSubjectObject(g.pkgs, subj)
		for _, site := range reachableSites {
			if isOpaqueSiteCompatible(site, subj, subjObj, recvType) {
				opaque = true
				break
			}
		}
		if opaque {
			break
		}
	}
	return out, opaque, nil
}

// findSubjectObject resolves the subject symbol to its types.Object and receiver type
// from the loaded module packages.
func findSubjectObject(pkgs []*packages.Package, subj domain.SymbolRef) (types.Object, types.Type) {
	var targetPkg *packages.Package
	for _, p := range pkgs {
		if p.PkgPath == subj.Package && p.Types != nil {
			targetPkg = p
			break
		}
	}
	if targetPkg == nil {
		return nil, nil
	}

	typeName, name := splitSymbol(subj.Symbol)
	typeName = strings.TrimSpace(typeName)
	typeName = strings.Trim(typeName, "()*")
	typeName = strings.TrimSpace(typeName)
	if typeName == "" {
		if obj := targetPkg.Types.Scope().Lookup(name); obj != nil {
			return obj, nil
		}
		for _, n := range targetPkg.Types.Scope().Names() {
			tn, ok := targetPkg.Types.Scope().Lookup(n).(*types.TypeName)
			if !ok {
				continue
			}
			nt := mustNamed(tn)
			if nt == nil {
				continue
			}
			if iface, ok := nt.Underlying().(*types.Interface); ok {
				for i := 0; i < iface.NumMethods(); i++ {
					m := iface.Method(i)
					if m.Name() == name {
						return m, nt
					}
				}
				continue
			}
			mset := types.NewMethodSet(types.NewPointer(nt))
			for i := 0; i < mset.Len(); i++ {
				m := mset.At(i).Obj()
				if m.Name() == name {
					return m, nt
				}
			}
		}
		return nil, nil
	}

	tn, ok := targetPkg.Types.Scope().Lookup(typeName).(*types.TypeName)
	if !ok {
		return nil, nil
	}
	nt := mustNamed(tn)
	if nt == nil {
		return nil, nil
	}
	if iface, ok := nt.Underlying().(*types.Interface); ok {
		for i := 0; i < iface.NumMethods(); i++ {
			m := iface.Method(i)
			if m.Name() == name {
				return m, nt
			}
		}
		return nil, nt
	}
	mset := types.NewMethodSet(types.NewPointer(nt))
	for i := 0; i < mset.Len(); i++ {
		m := mset.At(i).Obj()
		if m.Name() == name {
			return m, nt
		}
	}
	return nil, nt
}

// isOpaqueSiteCompatible checks whether an opaque call site (func variable or unlinked
// interface call) could plausibly invoke the target subject.
func isOpaqueSiteCompatible(site opaqueSite, subj domain.SymbolRef, subjObj types.Object, recvType types.Type) bool {
	if site.sig == nil && site.iface == nil {
		return true
	}
	if subjObj == nil {
		return true
	}
	fn, ok := subjObj.(*types.Func)
	if !ok {
		return false
	}
	subjSig, ok := fn.Type().(*types.Signature)
	if !ok {
		return false
	}

	if site.sig != nil {
		if sigCompatible(site.sig, subjSig) {
			return true
		}
	}
	if site.iface != nil {
		if ifaceCompatible(site.iface, subj, recvType) {
			return true
		}
	}
	return false
}

// sigCompatible reports whether an indirect function call with siteSig could
// plausibly invoke a target with subjSig (directly as a func/method value or via method expression).
func sigCompatible(siteSig, subjSig *types.Signature) bool {
	if types.Identical(siteSig, subjSig) {
		return true
	}
	resultsMatch := func(r1, r2 *types.Tuple) bool {
		if r1.Len() != r2.Len() {
			return false
		}
		for i := 0; i < r1.Len(); i++ {
			if !types.Identical(r1.At(i).Type(), r2.At(i).Type()) {
				return false
			}
		}
		return true
	}
	paramsMatch := func(p1, p2 *types.Tuple) bool {
		if p1.Len() != p2.Len() {
			return false
		}
		for i := 0; i < p1.Len(); i++ {
			if !types.Identical(p1.At(i).Type(), p2.At(i).Type()) {
				return false
			}
		}
		return true
	}

	if resultsMatch(siteSig.Results(), subjSig.Results()) {
		// Case 1: direct parameter match (package-level func or method value call)
		if paramsMatch(siteSig.Params(), subjSig.Params()) && siteSig.Variadic() == subjSig.Variadic() {
			return true
		}
		// Case 2: method expression call (first param is receiver)
		if subjSig.Recv() != nil && siteSig.Params().Len() == 1+subjSig.Params().Len() {
			firstParam := siteSig.Params().At(0).Type()
			recvT := subjSig.Recv().Type()
			recvMatch := types.Identical(firstParam, recvT) || types.Identical(firstParam, types.NewPointer(recvT))
			if !recvMatch {
				if ptr, ok := recvT.(*types.Pointer); ok {
					recvMatch = types.Identical(firstParam, ptr.Elem())
				}
			}
			if recvMatch {
				tailMatch := true
				for i := 0; i < subjSig.Params().Len(); i++ {
					if !types.Identical(siteSig.Params().At(i+1).Type(), subjSig.Params().At(i).Type()) {
						tailMatch = false
						break
					}
				}
				if tailMatch && siteSig.Variadic() == subjSig.Variadic() {
					return true
				}
			}
		}
	}
	return false
}

// ifaceCompatible reports whether an interface method dispatch on iface could
// invoke the target subject method on receiver type recvType.
func ifaceCompatible(iface *types.Interface, subj domain.SymbolRef, recvType types.Type) bool {
	if iface == nil || recvType == nil {
		return false
	}
	_, name := splitSymbol(subj.Symbol)
	hasMethod := false
	for i := 0; i < iface.NumMethods(); i++ {
		if iface.Method(i).Name() == name {
			hasMethod = true
			break
		}
	}
	if !hasMethod {
		return false
	}
	if types.Implements(recvType, iface) {
		return true
	}
	if types.Implements(types.NewPointer(recvType), iface) {
		return true
	}
	return false
}

// moduleEdges builds the intra-module call graph: caller-qualified-name ->
// set of callee-qualified-names, plus interface-method -> implementation
// edges for every module-local impl of invoked interface methods. The
// map returns the set of qualified caller names that contain opaque dispatch —
// calls resolving to no function at all (func values).
func (ix *Index) moduleEdges(pkgs []*packages.Package, module string) (map[string]map[string]bool, map[string]bool) {
	edges, sites := ix.moduleEdgesSites(pkgs, module)
	callers := make(map[string]bool, len(sites))
	for k, v := range sites {
		if len(v) > 0 {
			callers[k] = true
		}
	}
	return edges, callers
}

func (ix *Index) moduleEdgesSites(pkgs []*packages.Package, module string) (map[string]map[string]bool, map[string][]opaqueSite) {
	edges := map[string]map[string]bool{}
	opaqueSites := map[string][]opaqueSite{}
	addOpaque := func(caller string, site opaqueSite) {
		for _, existing := range opaqueSites[caller] {
			sigMatch := (existing.sig == site.sig) || (existing.sig != nil && site.sig != nil && types.Identical(existing.sig, site.sig))
			ifaceMatch := (existing.iface == site.iface)
			if sigMatch && ifaceMatch {
				return
			}
		}
		opaqueSites[caller] = append(opaqueSites[caller], site)
	}
	// Interface dispatch call sites, recorded for per-site impl narrowing:
	// a site `g.M()` where g = registry[key] with an evaluable key reaches
	// only the impls registered at the key's values, not every impl.
	type ifaceSite struct {
		pkg *packages.Package
		enc *ast.FuncDecl

		call *ast.CallExpr
	}
	ifaceSites := map[*types.Named]map[string][]ifaceSite{}
	addEdge := func(key, callee string) {
		if edges[key] == nil {
			edges[key] = map[string]bool{}
		}
		edges[key][callee] = true
	}
	fieldOwners := map[*types.Var]string{}
	indexScope := func(scope *types.Scope) {
		if scope == nil {
			return
		}
		for _, name := range scope.Names() {
			tn, ok := scope.Lookup(name).(*types.TypeName)
			if !ok {
				continue
			}
			st, ok := tn.Type().Underlying().(*types.Struct)
			if !ok {
				continue
			}
			pp := ""
			if tn.Pkg() != nil {
				pp = tn.Pkg().Path()
			}
			owner := pp + "." + tn.Name()
			for i := 0; i < st.NumFields(); i++ {
				f := st.Field(i)
				fieldOwners[f] = owner + "." + f.Name()
			}
		}
	}
	for _, pkg := range pkgs {
		if pkg.Types != nil {
			indexScope(pkg.Types.Scope())
			for _, imp := range pkg.Types.Imports() {
				indexScope(imp.Scope())
			}
		}
	}

	structFieldKey := func(f *types.Var, recv types.Type) string {
		if k, ok := fieldOwners[f]; ok && k != "" {
			return k
		}
		if recv != nil {
			if ptr, ok := recv.(*types.Pointer); ok {
				recv = ptr.Elem()
			}
			if named, ok := recv.(*types.Named); ok && named.Obj() != nil {
				pp := ""
				if named.Obj().Pkg() != nil {
					pp = named.Obj().Pkg().Path()
				}
				return pp + "." + named.Obj().Name() + "." + f.Name()
			}
		}
		if f.Pkg() != nil {
			return f.Pkg().Path() + ".." + f.Name()
		}
		return f.Name()
	}

	pkgVarKey := func(v *types.Var) string {
		if v.Pkg() != nil {
			return v.Pkg().Path() + "." + v.Name()
		}
		return v.Name()
	}

	structFieldFuncs := map[string][]*types.Func{}
	pkgVarFuncs := map[string][]*types.Func{}

	addFunc := func(m map[string][]*types.Func, key string, fn *types.Func) bool {
		if fn == nil || key == "" {
			return false
		}
		for _, existing := range m[key] {
			if existing == fn {
				return false
			}
		}
		m[key] = append(m[key], fn)
		return true
	}

	var extractTargetFuncs func(info *types.Info, encDecl *ast.FuncDecl, rhs ast.Expr, depth int) []*types.Func
	extractTargetFuncs = func(info *types.Info, encDecl *ast.FuncDecl, rhs ast.Expr, depth int) []*types.Func {
		if depth > 5 || rhs == nil || info == nil {
			return nil
		}
		for {
			if p, ok := rhs.(*ast.ParenExpr); ok {
				rhs = p.X
				continue
			}
			break
		}
		var out []*types.Func
		switch e := rhs.(type) {
		case *ast.SelectorExpr:
			if sel, ok := info.Selections[e]; ok {
				if fn, ok := sel.Obj().(*types.Func); ok {
					out = append(out, fn)
				} else if sel.Kind() == types.FieldVal {
					if fv, ok := sel.Obj().(*types.Var); ok {
						if _, isSig := fv.Type().Underlying().(*types.Signature); isSig {
							key := structFieldKey(fv, sel.Recv())
							out = append(out, structFieldFuncs[key]...)
						}
					}
				}
			}
			if len(out) == 0 {
				if fn, ok := info.ObjectOf(e.Sel).(*types.Func); ok {
					out = append(out, fn)
				} else if v, ok := info.ObjectOf(e.Sel).(*types.Var); ok && v.Pkg() != nil && v.Parent() == v.Pkg().Scope() {
					out = append(out, pkgVarFuncs[pkgVarKey(v)]...)
				}
			}
		case *ast.Ident:
			if fn, ok := info.ObjectOf(e).(*types.Func); ok {
				out = append(out, fn)
			} else if v, ok := info.ObjectOf(e).(*types.Var); ok {
				if v.Pkg() != nil && v.Parent() == v.Pkg().Scope() {
					out = append(out, pkgVarFuncs[pkgVarKey(v)]...)
				} else if encDecl != nil {
					if _, isSig := v.Type().Underlying().(*types.Signature); isSig {
						for _, r := range assignRHS(info, encDecl, v) {
							out = append(out, extractTargetFuncs(info, encDecl, r.expr, depth+1)...)
						}
					}
				}
			}
		case *ast.CallExpr:
			if len(e.Args) == 1 {
				if tv, ok := info.Types[e.Fun]; ok && tv.IsType() {
					out = append(out, extractTargetFuncs(info, encDecl, e.Args[0], depth+1)...)
				}
			}
		}
		return out
	}

	// Pre-pass: collect struct field and package-level function assignments with fixed-point iteration
	for iter := 0; iter < 5; iter++ {
		added := 0
		for _, pkg := range pkgs {
			info := pkg.TypesInfo
			if info == nil {
				continue
			}
			for _, f := range pkg.Syntax {
				for _, decl := range f.Decls {
					gd, ok := decl.(*ast.GenDecl)
					if !ok || gd.Tok != token.VAR {
						continue
					}
					for _, spec := range gd.Specs {
						vs, ok := spec.(*ast.ValueSpec)
						if !ok {
							continue
						}
						for i, name := range vs.Names {
							if i >= len(vs.Values) {
								continue
							}
							obj := info.ObjectOf(name)
							v, ok := obj.(*types.Var)
							if !ok {
								continue
							}
							if _, isSig := v.Type().Underlying().(*types.Signature); !isSig {
								continue
							}
							for _, target := range extractTargetFuncs(info, nil, vs.Values[i], 0) {
								if addFunc(pkgVarFuncs, pkgVarKey(v), target) {
									added++
								}
							}
						}
					}
				}
				var encDecl *ast.FuncDecl
				ast.Inspect(f, func(n ast.Node) bool {
					if fn, ok := n.(*ast.FuncDecl); ok {
						encDecl = fn
						return true
					}
					if lit, ok := n.(*ast.CompositeLit); ok {
						typ := info.Types[lit].Type
						if typ != nil {
							if ptr, ok := typ.(*types.Pointer); ok {
								typ = ptr.Elem()
							}
							if st, ok := typ.Underlying().(*types.Struct); ok {
								for i, elt := range lit.Elts {
									if kv, ok := elt.(*ast.KeyValueExpr); ok {
										if keyId, ok := kv.Key.(*ast.Ident); ok {
											var fieldVar *types.Var
											if fv, ok := info.Uses[keyId].(*types.Var); ok {
												fieldVar = fv
											} else {
												for j := 0; j < st.NumFields(); j++ {
													if st.Field(j).Name() == keyId.Name {
														fieldVar = st.Field(j)
														break
													}
												}
											}
											if fieldVar != nil {
												if _, isSig := fieldVar.Type().Underlying().(*types.Signature); isSig {
													for _, target := range extractTargetFuncs(info, encDecl, kv.Value, 0) {
														if addFunc(structFieldFuncs, structFieldKey(fieldVar, typ), target) {
															added++
														}
													}
												}
											}
										}
									} else if i < st.NumFields() {
										fieldVar := st.Field(i)
										if _, isSig := fieldVar.Type().Underlying().(*types.Signature); isSig {
											for _, target := range extractTargetFuncs(info, encDecl, elt, 0) {
												if addFunc(structFieldFuncs, structFieldKey(fieldVar, typ), target) {
													added++
												}
											}
										}
									}
								}
							}
						}
					}
					if assign, ok := n.(*ast.AssignStmt); ok {
						for i, lhs := range assign.Lhs {
							var rhs ast.Expr
							if i < len(assign.Rhs) {
								rhs = assign.Rhs[i]
							} else if len(assign.Rhs) == 1 {
								rhs = assign.Rhs[0]
							}
							if rhs == nil {
								continue
							}
							if sel, ok := lhs.(*ast.SelectorExpr); ok {
								if selection, ok := info.Selections[sel]; ok && selection.Kind() == types.FieldVal {
									if fieldVar, ok := selection.Obj().(*types.Var); ok {
										if _, isSig := fieldVar.Type().Underlying().(*types.Signature); isSig {
											for _, target := range extractTargetFuncs(info, encDecl, rhs, 0) {
												if addFunc(structFieldFuncs, structFieldKey(fieldVar, selection.Recv()), target) {
													added++
												}
											}
										}
									}
								} else if info.Selections[sel] == nil {
									obj := info.ObjectOf(sel.Sel)
									if v, ok := obj.(*types.Var); ok && v.Pkg() != nil && v.Parent() == v.Pkg().Scope() {
										if _, isSig := v.Type().Underlying().(*types.Signature); isSig {
											for _, target := range extractTargetFuncs(info, encDecl, rhs, 0) {
												if addFunc(pkgVarFuncs, pkgVarKey(v), target) {
													added++
												}
											}
										}
									}
								}
							} else if id, ok := lhs.(*ast.Ident); ok {
								obj := info.ObjectOf(id)
								if v, ok := obj.(*types.Var); ok && v.Pkg() != nil && v.Parent() == v.Pkg().Scope() {
									if _, isSig := v.Type().Underlying().(*types.Signature); isSig {
										for _, target := range extractTargetFuncs(info, encDecl, rhs, 0) {
											if addFunc(pkgVarFuncs, pkgVarKey(v), target) {
												added++
											}
										}
									}
								}
							}
						}
					}
					return true
				})
			}
		}
		if added == 0 {
			break
		}
	}

	for _, pkg := range pkgs {
		info := pkg.TypesInfo
		if info == nil {
			continue
		}
		for _, f := range pkg.Syntax {
			// Package-level statements (var initializers) execute at
			// package init: they attribute to the "init" sentinel rather
			// than the last FuncDecl seen — a stale caller would either
			// drop the edge or blame it on an unrelated function.
			for _, decl := range f.Decls {
				encDecl, _ := decl.(*ast.FuncDecl)
				caller := "init"
				if encDecl != nil && encDecl.Name != nil {
					caller = encDecl.Name.Name
					if encDecl.Recv != nil && len(encDecl.Recv.List) > 0 {
						caller = recvDeclName(encDecl.Recv.List[0].Type) + "." + encDecl.Name.Name
					}
				}
				ast.Inspect(decl, func(n ast.Node) bool {
					// Every func-literal body under a package-level decl walks
					// in init context — the literal may be invoked at init
					// (IIFE), handed to an init-run callback, or stored in a
					// package var that a later init decl calls. Attributing a
					// possibly-later call to init only ever adds reachability
					// evidence; dropping the body could classify a live
					// subject DEAD.
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					fun := call.Fun
					for {
						if p, ok := fun.(*ast.ParenExpr); ok {
							fun = p.X
							continue
						}
						break
					}
					obj := calleeObject(info, fun)
					handleCallee := func(fn *types.Func) bool {
						if fn == nil || fn.Pkg() == nil {
							return false
						}
						p := fn.Pkg().Path()
						if p != module && !strings.HasPrefix(p, module+"/") {
							return false
						}
						callee := p + "." + fn.Name()
						if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
							rt := sig.Recv().Type()
							callee = p + "." + recvTypeName(rt) + "." + fn.Name()
							// Interface dispatch: the callee is the interface
							// method — record the site so impl edges below can be
							// narrowed by the dispatch key.
							switch rt.Underlying().(type) {
							case *types.Interface:
								if named := ifaceNamed(rt); named != nil {
									if ifaceSites[named] == nil {
										ifaceSites[named] = map[string][]ifaceSite{}
									}
									ifaceSites[named][fn.Name()] = append(ifaceSites[named][fn.Name()], ifaceSite{pkg, encDecl, call})
								} else {
									// Anonymous/interface-literal receiver: the
									// call resolves to the interface method but
									// no impl edges are enumerable — the graph
									// is incomplete, not "no path".
									iface, _ := rt.Underlying().(*types.Interface)
									addOpaque(pkg.PkgPath+"."+caller, opaqueSite{iface: iface})
								}
							}
						}
						addEdge(pkg.PkgPath+"."+caller, callee)
						return true
					}
					if fn, ok := obj.(*types.Func); ok {
						if fn.Pkg() != nil {
							handleCallee(fn)
						}
						return true
					}
					if v, ok := obj.(*types.Var); ok {
						if _, isSig := v.Type().Underlying().(*types.Signature); isSig {
							// 1. Struct field func callback dispatch
							if sel, ok := fun.(*ast.SelectorExpr); ok {
								if selection, ok := info.Selections[sel]; ok && selection.Kind() == types.FieldVal {
									key := structFieldKey(v, selection.Recv())
									targets := structFieldFuncs[key]
									if len(targets) > 0 {
										allResolved := true
										for _, t := range targets {
											if t != nil && t.Pkg() != nil {
												handleCallee(t)
											} else {
												allResolved = false
											}
										}
										if allResolved {
											return true
										}
									}
									sig, _ := v.Type().Underlying().(*types.Signature)
									addOpaque(pkg.PkgPath+"."+caller, opaqueSite{sig: sig})
									return true
								}
							}
							// 2. Package-level function variable
							if v.Pkg() != nil && v.Parent() == v.Pkg().Scope() {
								key := pkgVarKey(v)
								targets := pkgVarFuncs[key]
								if len(targets) > 0 {
									allResolved := true
									for _, t := range targets {
										if t != nil && t.Pkg() != nil {
											handleCallee(t)
										} else {
											allResolved = false
										}
									}
									if allResolved {
										return true
									}
								}
								sig, _ := v.Type().Underlying().(*types.Signature)
								addOpaque(pkg.PkgPath+"."+caller, opaqueSite{sig: sig})
								return true
							}
							// 3. Local func variable / method value
							if encDecl != nil {
								rhss := assignRHS(info, encDecl, v)
								if len(rhss) > 0 {
									allResolved := true
									for _, r := range rhss {
										targets := extractTargetFuncs(info, encDecl, r.expr, 0)
										if len(targets) > 0 {
											for _, t := range targets {
												if t != nil && t.Pkg() != nil {
													handleCallee(t)
												} else {
													allResolved = false
												}
											}
										} else {
											allResolved = false
										}
									}
									if allResolved {
										return true
									}
								}
							}
						}
					}
					// Func values and map-indexed calls hide their target
					// from the chain — absence of a found chain is then
					// not evidence of absence. Builtins and type
					// conversions resolve to no *types.Func either, but
					// call nothing user-defined.
					switch obj.(type) {
					case *types.Builtin, *types.TypeName:
					default:
						if tv, ok := info.Types[fun]; ok && tv.IsType() {
							break
						}
						var siteSig *types.Signature
						if tv, ok := info.Types[fun]; ok && tv.Type != nil {
							if sig, ok := tv.Type.Underlying().(*types.Signature); ok {
								siteSig = sig
							}
						}
						if siteSig == nil {
							if v, ok := obj.(*types.Var); ok {
								if sig, ok := v.Type().Underlying().(*types.Signature); ok {
									siteSig = sig
								}
							}
						}
						addOpaque(pkg.PkgPath+"."+caller, opaqueSite{sig: siteSig})
					}
					return true
				})
			}
		}
	}
	// Link interface methods to their concrete implementations declared in
	// the module — a registry call "Getter.Get" reaches every Getter impl.
	// Two narrowing layers keep the fan-out honest:
	//   - instantiation: a type never created in loaded code cannot be a
	//     dispatch target (test mocks, dead alternatives); skipped entirely
	//     under reflect.New/unsafe/plugin/linkname;
	//   - dispatch key: a site `g.M()` where g = registry[key] and key
	//     evaluates to constants reaches only the registered impls at
	//     those keys; an unevaluable site stays unrestricted — then all
	inst, narrowing := ix.instantiated()
	if narrowing {
		modInst, modDisabled := instantiatedNamed(pkgs)
		if modDisabled {
			narrowing = false
		} else {
			combined := make(map[string]bool, len(inst)+len(modInst))
			for k, v := range inst {
				combined[k] = v
			}
			for k, v := range modInst {
				combined[k] = v
			}
			inst = combined
		}
	}
	for named, methods := range ifaceSites {
		for method, sites := range methods {
			// Union of per-site allowed impls; any unrestricted site
			// widens the pair back to every impl.
			var allowed map[string]bool
			for _, s := range sites {
				set := ix.dispatchImpls(s.pkg, s.enc, s.call)
				if set == nil {
					allowed = nil
					break
				}
				if allowed == nil {
					allowed = map[string]bool{}
				}
				for name := range set {
					allowed[name] = true
				}
			}
			linked := 0
			for _, pkg := range pkgs {
				if pkg.Types == nil {
					continue
				}
				for _, name := range pkg.Types.Scope().Names() {
					if allowed != nil && !allowed[name] {
						continue
					}
					tn, ok := pkg.Types.Scope().Lookup(name).(*types.TypeName)
					if !ok {
						continue
					}
					t := tn.Type()
					implNamed, _ := t.(*types.Named)
					if narrowing && implNamed != nil && !inst[namedKey(implNamed)] {
						continue
					}
					iface, _ := named.Underlying().(*types.Interface)
					if iface == nil || !types.Implements(types.NewPointer(t), iface) {
						continue
					}
					ms := types.NewMethodSet(types.NewPointer(t))
					for i := 0; i < ms.Len(); i++ {
						m := ms.At(i).Obj()
						if m.Name() != method {
							continue
						}
						ifaceKey := named.Obj().Pkg().Path() + "." + named.Obj().Name() + "." + method
						implKey := m.Pkg().Path() + "." + name + "." + method
						addEdge(ifaceKey, implKey)
						linked++
					}
				}
			}
			if linked == 0 {
				// A live interface call whose impls are invisible to the
				// loaded graph (invisible instantiation, unloaded impl
				// package) leaves the callee unreached — that is unknown
				// reachability, not disproven.
				iface, _ := named.Underlying().(*types.Interface)
				for _, s := range sites {
					if s.enc != nil && s.enc.Name != nil {
						fnName := s.enc.Name.Name
						if s.enc.Recv != nil && len(s.enc.Recv.List) > 0 {
							fnName = recvDeclName(s.enc.Recv.List[0].Type) + "." + fnName
						}
						addOpaque(s.pkg.PkgPath+"."+fnName, opaqueSite{iface: iface})
					}
				}
			}
		}
	}
	return edges, opaqueSites
}

// namedKey canonicalizes a named type across load instances — the same
// dependency type materializes once through the product's import data
// and once through the source-loaded dep package; pointer identity does
// not survive that split, so the key is the declaring package path and
// name.
func namedKey(n *types.Named) string {
	if n == nil || n.Obj() == nil || n.Obj().Pkg() == nil {
		return ""
	}
	return n.Obj().Pkg().Path() + "." + n.Obj().Name()
}

// instantiatedNamed collects named types concretely created by the
// packages' syntax: composite literals, new(T), var declarations with an
// explicit type, make() and type conversions. The set is expanded over
// struct fields and container element types — `&Wrapper{}` also creates
// its field values. disabled is true when syntax can materialize values
// invisibly (reflect.New/NewAt, unsafe, plugin, go:linkname): then the
// set is incomplete and must not narrow dispatch.
func instantiatedNamed(pkgs []*packages.Package) (set map[string]bool, disabled bool) {
	set = map[string]bool{}
	var add func(t types.Type)
	add = func(t types.Type) {
		if t == nil {
			return
		}
		if tup, ok := t.(*types.Tuple); ok {
			for i := 0; i < tup.Len(); i++ {
				add(tup.At(i).Type())
			}
			return
		}
		for {
			if p, ok := t.(*types.Pointer); ok {
				t = p.Elem()
				continue
			}
			break
		}
		if s, ok := t.(*types.Slice); ok {
			add(s.Elem())
			return
		}
		if a, ok := t.(*types.Array); ok {
			add(a.Elem())
			return
		}
		if m, ok := t.(*types.Map); ok {
			add(m.Key())
			add(m.Elem())
			return
		}
		if c, ok := t.(*types.Chan); ok {
			add(c.Elem())
			return
		}
		n, ok := t.(*types.Named)
		if !ok || n.Underlying() == nil {
			return
		}
		if _, ok := n.Underlying().(*types.Interface); ok {
			return
		}
		key := namedKey(n)
		if key == "" || set[key] {
			return
		}
		set[key] = true
		// Instantiating a named type creates its contained values too:
		// struct fields (incl. embedded), slice/array/map/channel elems.
		switch u := n.Underlying().(type) {
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				add(u.Field(i).Type())
			}
		case *types.Slice:
			add(u.Elem())
		case *types.Array:
			add(u.Elem())
		case *types.Map:
			add(u.Elem())
			add(u.Key())
		case *types.Chan:
			add(u.Elem())
		}
	}
	for _, pkg := range pkgs {
		info := pkg.TypesInfo
		for _, f := range pkg.Syntax {
			for _, imp := range f.Imports {
				switch strings.Trim(imp.Path.Value, `"`) {
				case "unsafe", "plugin":
					disabled = true
				}
			}
			ast.Inspect(f, func(n ast.Node) bool {
				switch e := n.(type) {
				case *ast.CompositeLit:
					if info != nil {
						add(info.TypeOf(e.Type))
					}
				case *ast.ValueSpec:
					if info != nil && e.Type != nil {
						add(info.TypeOf(e.Type))
					}
				case *ast.CallExpr:
					if info != nil {
						add(info.TypeOf(e))
					}
					obj := calleeObject(info, e.Fun)
					switch o := obj.(type) {
					case *types.Builtin:
						if o.Name() == "new" && len(e.Args) == 1 && info != nil {
							add(info.TypeOf(e.Args[0]))
						}
						if o.Name() == "make" && len(e.Args) >= 1 && info != nil {
							add(info.TypeOf(e.Args[0]))
						}
					case *types.TypeName:
						// T(x) conversion — counts as instantiation; a
						// rare T(nil) over-marks, which is the safe side.
						if nt, ok := o.Type().(*types.Named); ok {
							add(nt)
						}
					case *types.Func:
						if o.Pkg() != nil && o.Pkg().Path() == "reflect" &&
							(o.Name() == "New" || o.Name() == "NewAt") {
							disabled = true
						}
					}
				}
				return true
			})
			for _, cg := range f.Comments {
				for _, cm := range cg.List {
					if strings.HasPrefix(cm.Text, "//go:linkname") {
						disabled = true
					}
				}
			}
		}
	}
	return set, disabled
}

// instantiated returns the memoized instantiation set over all loaded
// packages (product + extras); narrow=false when dynamic materialization
// was seen and the set must not restrict dispatch.
func (ix *Index) instantiated() (map[string]bool, bool) {
	if ix.instSet != nil && ix.instGen == ix.extrasGen {
		return ix.instSet, !ix.instDisabled
	}
	pkgs := append(append([]*packages.Package{}, ix.allExtras()...), ix.pkgs...)
	set, disabled := instantiatedNamed(pkgs)
	ix.instSet, ix.instDisabled, ix.instGen = set, disabled, ix.extrasGen
	return set, !disabled
}

// productInstantiated returns the memoized instantiation set over product
// packages only; narrow=false when dynamic materialization was seen in
// product packages.
func (ix *Index) productInstantiated() (map[string]bool, bool) {
	if ix.prodInstSet != nil {
		return ix.prodInstSet, !ix.prodInstDisabled
	}
	set, disabled := instantiatedNamed(ix.pkgs)
	ix.prodInstSet, ix.prodInstDisabled = set, disabled
	return set, !disabled
}

// IsReceiverTypeInstantiated reports whether the receiver type of ref (if ref
// is a method) may be materialized in product code. It returns false only
// when the receiver is PROVABLY never instantiated: the type resolved in the
// loaded packages, instantiation narrowing is enabled (no reflect.New/NewAt,
// unsafe, plugin or go:linkname in product code), every product package
// type-checked — a skipped package's syntax never entered the inventory —
// and the type is absent from the product instantiation set. Standalone
// functions, unresolved receiver types and every incomplete probe
// conservatively return true: an unproven receiver must never narrow
// dispatch or dynamic-invocation scope away.
func (ix *Index) IsReceiverTypeInstantiated(ref domain.SymbolRef) bool {
	if ix == nil {
		return true
	}
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ix.ctxOr(nil)); err != nil {
		return true
	}
	return ix.receiverTypeInstantiated(ix.ctxOr(nil), ref)
}

// receiverTypeInstantiated is the lock-free core of
// IsReceiverTypeInstantiated; callers must hold ix.mu with the index
// already loaded.
func (ix *Index) receiverTypeInstantiated(ctx context.Context, ref domain.SymbolRef) bool {
	typeName, _ := splitSymbol(ref.Symbol)
	recvName := subjectRecvName(typeName)
	if recvName == "" {
		return true
	}
	if ix.lookupNamedType(ctx, ref.Package, recvName) == nil {
		return true
	}
	narrow, _, _ := ix.productNarrowingLocked()
	if !narrow {
		return true
	}
	return ix.productInstantiatedHas(ref)
}

// receiverMayBeErased reports whether a concrete receiver can be produced
// by a product call returning an interface implemented by the receiver.
// Unrelated interface-returning calls do not disable receiver narrowing.
func (ix *Index) receiverMayBeErased(ref domain.SymbolRef) bool {
	typeName, _ := splitSymbol(ref.Symbol)
	if typeName == "" {
		return false
	}
	var recv *types.Named
	for _, pkg := range ix.pkgs {
		if pkg.PkgPath != ref.Package || pkg.Types == nil {
			continue
		}
		if tn, ok := pkg.Types.Scope().Lookup(typeName).(*types.TypeName); ok {
			recv, _ = tn.Type().(*types.Named)
		}
	}
	if recv == nil {
		return false
	}
	for _, pkg := range ix.pkgs {
		info := pkg.TypesInfo
		if info == nil {
			continue
		}
		for _, f := range pkg.Syntax {
			found := false
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || found {
					return !found
				}
				fn, ok := calleeObject(info, call.Fun).(*types.Func)
				if !ok || fn.Pkg() == nil || fn.Pkg().Path() != ref.Package {
					return true
				}
				sig, ok := fn.Type().(*types.Signature)
				if !ok || sig.Results() == nil {
					return true
				}
				for i := range sig.Results().Len() {
					t := sig.Results().At(i).Type()
					iface, ok := t.Underlying().(*types.Interface)
					if ok && (types.Implements(recv, iface) || types.Implements(types.NewPointer(recv), iface)) {
						found = true
						return false
					}
				}
				return true
			})
			if found {
				return true
			}
		}
	}
	return false
}

// depCone returns the set of module functions reachable from the product's
// call sites into the module — the entry cone. Dep-internal callers inside
// this cone can carry product-supplied data; callers outside it are
// alternative module flows (mocks, other getters, meta machinery) that the
// product never drives — merging their origins over-approximates toward
// EXTERNAL_UNTRUSTED and can never disprove exploitability.
func (ix *Index) depCone(module string) map[string]bool {
	if c, ok := ix.coneCache[module]; ok {
		return c
	}
	if ix.coneBusy == nil {
		ix.coneBusy = map[string]bool{}
	}
	if ix.coneBusy[module] {
		// Cone under construction — dispatch narrowing inside edge
		// building asks back through siteOnPath; answer permissively
		// so the graph stays over-approximate rather than recursive.
		return nil
	}
	ix.coneBusy[module] = true
	defer delete(ix.coneBusy, module)
	pkgs, err := ix.loadExtra(ix.ctxOr(nil), module+"/...")
	if err != nil {
		return nil
	}
	edges, opaqueCallers := ix.moduleEdges(pkgs, module)
	// Seed with every product call site whose callee lands in the module —
	// the same callee-key format moduleEdges produces.
	entries := map[string]bool{}
	for _, p := range ix.pkgs {
		info := p.TypesInfo
		if info == nil {
			continue
		}
		for _, f := range p.Syntax {
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				fn, ok := calleeObject(info, call.Fun).(*types.Func)
				if !ok || fn.Pkg() == nil {
					return true
				}
				fp := fn.Pkg().Path()
				if fp != module && !strings.HasPrefix(fp, module+"/") {
					return true
				}
				callee := fp + "." + fn.Name()
				if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
					callee = fp + "." + recvTypeName(sig.Recv().Type()) + "." + fn.Name()
				}
				entries[callee] = true
				return true
			})
		}
	}
	cone := map[string]bool{}
	var stack []string
	for e := range entries {
		if !cone[e] {
			cone[e] = true
			stack = append(stack, e)
		}
	}
	for len(stack) > 0 {
		k := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for next := range edges[k] {
			if !cone[next] {
				cone[next] = true
				stack = append(stack, next)
			}
		}
	}
	for c := range cone {
		if opaqueCallers[c] {
			if ix.coneCache == nil {
				ix.coneCache = map[string]map[string]bool{}
			}
			ix.coneCache[module] = nil
			return nil
		}
	}
	if ix.coneCache == nil {
		ix.coneCache = map[string]map[string]bool{}
	}
	ix.coneCache[module] = cone
	return cone
}

// callerOnPath reports whether a caller site can carry product-supplied
// data: product callers always qualify; dep-internal callers qualify only
// when their enclosing function lies in the module's entry cone. Data
// needed to decide stays unknown-biased: when the module or cone cannot
// be computed the caller is kept.
func (ix *Index) callerOnPath(r CallSiteRef) bool {
	return ix.siteOnPath(r.pkg, r.enclosing)
}

// siteOnPath is the shared product-driven-cone check: product code and
// package-level declarations always qualify; a dep-internal site qualifies
// only when its enclosing function lies in the module's entry cone. When
// module/cone cannot be computed the site is kept — unknown-biased.
func (ix *Index) siteOnPath(pkg *packages.Package, enc *ast.FuncDecl) bool {
	if pkg == nil || enc == nil || ix.isProductPath(pkg.PkgPath) {
		return true
	}
	mod := ""
	if pkg.Module != nil {
		mod = pkg.Module.Path
	}
	if mod == "" {
		return true
	}
	cone := ix.depCone(mod)
	if cone == nil {
		return true
	}
	caller := enc.Name.Name
	if enc.Recv != nil && len(enc.Recv.List) > 0 {
		caller = recvDeclName(enc.Recv.List[0].Type) + "." + caller
	}
	// init runs unconditionally at package load — it is on every path
	// even though no caller ever names it.
	if caller == "init" {
		return true
	}
	return cone[pkg.PkgPath+"."+caller]
}

// ifaceNamed returns the named interface type of a receiver, or nil when
// the receiver is a concrete type (methods on concrete receivers are
// ordinary direct calls for reachability purposes).
func ifaceNamed(t types.Type) *types.Named {
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	named, ok := t.(*types.Named)
	if !ok {
		return nil
	}
	if _, isIface := named.Underlying().(*types.Interface); !isIface {
		return nil
	}
	return named
}

func recvDeclName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.StarExpr:
		return recvDeclName(t.X)
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		return t.Sel.Name
	case *ast.IndexExpr, *ast.IndexListExpr:
		// generic receivers
		if x := ast.Unparen(expr); x != nil {
			if id, ok := baseIdent(x); ok {
				return id.Name
			}
		}
	}
	return ""
}

func baseIdent(e ast.Expr) (*ast.Ident, bool) {
	switch t := e.(type) {
	case *ast.Ident:
		return t, true
	case *ast.StarExpr:
		return baseIdent(t.X)
	case *ast.IndexExpr:
		return baseIdent(t.X)
	case *ast.IndexListExpr:
		return baseIdent(t.X)
	case *ast.SelectorExpr:
		return t.Sel, true
	}
	return nil, false
}

// bfsChain finds a caller->...->target chain in the intra-module call graph.
func bfsChain(edges map[string]map[string]bool, start, target string) []string {
	type node struct {
		name string
		prev *node
	}
	seen := map[string]bool{start: true}
	queue := []*node{{name: start}}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if cur.name == target {
			var chain []string
			for n := cur; n != nil; n = n.prev {
				chain = append(chain, n.name)
			}
			for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
				chain[i], chain[j] = chain[j], chain[i]
			}
			return chain
		}
		for next := range edges[cur.name] {
			if !seen[next] {
				seen[next] = true
				queue = append(queue, &node{name: next, prev: cur})
			}
		}
	}
	return nil
}

// DynamicMarker describes language features that can bypass static
// call-graph reasoning: reflect, unsafe, plugins, linkname, function values
// referencing the analyzed symbol, etc.
type DynamicMarker struct {
	domain.CallSite
	Kind   string `json:"kind"` // reflect|unsafe|plugin|linkname|func_value|goroutine
	Detail string `json:"detail"`
}

// ScanDynamic finds dynamic-dispatch risk markers inside product packages.
func (ix *Index) ScanDynamic(ctx context.Context, ref domain.SymbolRef) ([]DynamicMarker, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ctx); err != nil {
		return nil, err
	}
	return ix.scanDynamic(ref), nil
}

// scanDynamic is the lock-free core of ScanDynamic; callers must hold
// ix.mu with the index already loaded.
func (ix *Index) scanDynamic(ref domain.SymbolRef) []DynamicMarker {
	var out []DynamicMarker
	for _, pkg := range ix.pkgs {
		for _, f := range pkg.Syntax {
			pos := func(n ast.Node) domain.CallSite {
				p := ix.fset.Position(n.Pos())
				return domain.CallSite{File: p.Filename, Line: p.Line, Package: pkg.PkgPath}
			}
			for _, imp := range f.Imports {
				path := strings.Trim(imp.Path.Value, `"`)
				switch path {
				case "reflect":
					out = append(out, DynamicMarker{CallSite: pos(imp), Kind: "reflect", Detail: "reflect import"})
				case "unsafe":
					out = append(out, DynamicMarker{CallSite: pos(imp), Kind: "unsafe", Detail: "unsafe import"})
				case "plugin":
					out = append(out, DynamicMarker{CallSite: pos(imp), Kind: "plugin", Detail: "plugin import"})
				}
			}
			callFuns := map[ast.Node]bool{}
			ast.Inspect(f, func(n ast.Node) bool {
				if as, ok := n.(*ast.AssignStmt); ok {
					for _, lhs := range as.Lhs {
						// A store through an unsafe.Pointer-derived deref —
						// `*(*T)(unsafe.Pointer(&x)) = v` or an index-assign
						// into an unsafe.Slice — can write any field (even
						// unexported) out of sight of syntactic write-site
						// scans. The bare `unsafe` import cannot write
						// anything by itself.
						var target ast.Expr
						switch l := lhs.(type) {
						case *ast.StarExpr:
							target = l.X
						case *ast.IndexExpr:
							target = l
						}
						if target != nil && callsUnsafe(pkg.TypesInfo, target) {
							out = append(out, DynamicMarker{
								CallSite: pos(as), Kind: "unsafe_write",
								Detail: "store through unsafe.Pointer-derived value can write fields invisibly",
							})
						}
					}
				}
				if call, ok := n.(*ast.CallExpr); ok {
					callFuns[call.Fun] = true
					if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
						callFuns[sel.Sel] = true
						// A materialized unsafe.Pointer (Pointer conversion
						// or unsafe.Add) can be stored anywhere and written
						// through later — its aliased uses are untraceable
						// cheaply, so its mere presence weakens field-write
						// coverage.
						if (sel.Sel.Name == "Pointer" || sel.Sel.Name == "Add") &&
							isUnsafePkg(pkg.TypesInfo, sel.X) {
							out = append(out, DynamicMarker{
								CallSite: pos(call), Kind: "unsafe_ptr",
								Detail: "unsafe." + sel.Sel.Name + " materializes a raw pointer; aliased writes are untraceable",
							})
						}
						// reflect.Value.Set* mutates the underlying value —
						// the only reflect shape that can write a guarded
						// field/variable. The bare `reflect` import or
						// read-only calls (TypeOf, DeepEqual, Interface)
						// cannot.
						if strings.HasPrefix(sel.Sel.Name, "Set") &&
							isReflectValue(pkg.TypesInfo, sel.X) {
							out = append(out, DynamicMarker{
								CallSite: pos(call), Kind: "reflect_write",
								Detail: "reflect.Value." + sel.Sel.Name + " call can write fields invisibly",
							})
						}
						// reflect.Value.MethodByName / Method can invoke methods
						// dynamically — the only reflect shape that can widen the call graph.
						if (sel.Sel.Name == "MethodByName" || sel.Sel.Name == "Method") &&
							isReflectValueOrType(pkg.TypesInfo, sel.X) {
							out = append(out, DynamicMarker{
								CallSite: pos(call), Kind: "reflect_method",
								Detail: "reflect." + sel.Sel.Name + " call can invoke methods dynamically",
							})
						}
					}
				}
				return true
			})
			ast.Inspect(f, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.Comment:
					if strings.Contains(n.Text, "go:linkname") {
						out = append(out, DynamicMarker{CallSite: pos(n), Kind: "linkname", Detail: n.Text})
					}
				case *ast.Ident:
					if callFuns[n] {
						return true
					}
					if symRefIdent(pkg.TypesInfo, n, ref) {
						out = append(out, DynamicMarker{
							CallSite: pos(n), Kind: "func_value",
							Detail: "symbol referenced as value (may be invoked indirectly)",
						})
					}
				}
				return true
			})
		}
	}
	return out
}

// symRefIdent reports whether ident references the target symbol without
// being part of a call expression fun position (i.e. used as a value).
// Beyond functions it matches qualified type names and package-level
// vars — field accesses are resolved precisely at their SelectorExpr /
// CompositeLiteral parents, never here.
func symRefIdent(info *types.Info, id *ast.Ident, ref domain.SymbolRef) bool {
	obj := info.ObjectOf(id)
	typeName, name := splitSymbol(ref.Symbol)
	switch o := obj.(type) {
	case *types.Func:
		if o.Pkg() == nil || o.Pkg().Path() != ref.Package {
			return false
		}
		return o.Name() == name
	case *types.TypeName, *types.Const:
		// "PlainAuth" in vuln.PlainAuth — the type name alone matches only
		// unqualified subjects; "Type.Field" subjects bind the member.
		if typeName != "" {
			return false
		}
		if o.Pkg() == nil || o.Pkg().Path() != ref.Package {
			return false
		}
		return o.Name() == name
	case *types.Var:
		if o.IsField() || typeName != "" {
			return false
		}
		if o.Pkg() == nil || o.Pkg().Path() != ref.Package {
			return false
		}
		return o.Name() == name
	}
	return false
}

// selRefMatch matches a selector expression against the subject: a
// selection (x.Field / x.Method) is checked against the declaring struct,
// a qualified identifier (pkg.Name) follows the bare-ident rules.
func selRefMatch(info *types.Info, e *ast.SelectorExpr, ref domain.SymbolRef) bool {
	if seln, ok := info.Selections[e]; ok {
		return selObjMatch(seln, ref)
	}
	return symRefIdent(info, e.Sel, ref)
}

// selObjMatch matches a resolved selection (field or method value) against
// a "Type.Name" subject by the declaring struct's name.
func selObjMatch(seln *types.Selection, ref domain.SymbolRef) bool {
	typeName, name := splitSymbol(ref.Symbol)
	if typeName == "" {
		return false
	}
	obj := seln.Obj()
	if obj.Pkg() == nil || obj.Pkg().Path() != ref.Package || obj.Name() != name {
		return false
	}
	switch seln.Kind() {
	case types.FieldVal:
		return declaringStructName(seln) == typeName
	case types.MethodVal, types.MethodExpr:
		return recvTypeName(seln.Recv()) == typeName
	}
	return false
}

// declaringStructName resolves which struct along a (possibly embedded)
// selection path declares the selected field — "x.Password" promoted from
// an embedded PlainAuth reports PlainAuth, not the outer struct.
func declaringStructName(seln *types.Selection) string {
	t := seln.Recv()
	idx := seln.Index()
	for _, i := range idx[:len(idx)-1] {
		st, ok := derefStruct(t)
		if !ok {
			return recvTypeName(seln.Recv())
		}
		t = st.Field(i).Type()
	}
	return recvTypeName(t)
}

func derefStruct(t types.Type) (*types.Struct, bool) {
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	st, ok := t.Underlying().(*types.Struct)
	return st, ok
}

// litFieldMatch matches a composite literal field key ("Type{Field: v}")
// against a "Type.Field" subject — the key ident's object alone cannot
// name its declaring struct, so the literal's type does it.
func litFieldMatch(info *types.Info, lit *ast.CompositeLit, ref domain.SymbolRef) bool {
	typeName, name := splitSymbol(ref.Symbol)
	if typeName == "" {
		return false
	}
	n := namedOf(info.TypeOf(lit))
	if n == nil || n.Obj() == nil || n.Obj().Pkg() == nil ||
		n.Obj().Pkg().Path() != ref.Package || n.Obj().Name() != typeName {
		return false
	}
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if id, ok := kv.Key.(*ast.Ident); ok && id.Name == name {
			return true
		}
	}
	return false
}

func namedOf(t types.Type) *types.Named {
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	n, _ := t.(*types.Named)
	return n
}

// sensitiveFieldRe names struct fields that plausibly hold credentials —
// used by the INFO_LEAK datum pool, not by any verdict logic.
var sensitiveFieldRe = regexp.MustCompile(`(?i)password|passwd|secret|token|api[-_]?key|credential|sasl|session|cookie|private[-_]?key`)

// SensitiveFields returns "Type.Field" references for every exported,
// credential-named field declared in package pkgPath — the deterministic
// datum source for INFO_LEAK patterns. The dependency package is loaded
// on demand like any other symbol lookup.
func (ix *Index) SensitiveFields(ctx context.Context, pkgPath string) ([]domain.SymbolRef, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ctx); err != nil {
		return nil, err
	}
	pkg := ix.pkgByPath(ctx, pkgPath)
	if pkg == nil || pkg.Types == nil {
		return nil, fmt.Errorf("package %s not loaded", pkgPath)
	}
	var out []domain.SymbolRef
	for _, name := range pkg.Types.Scope().Names() {
		tn, ok := pkg.Types.Scope().Lookup(name).(*types.TypeName)
		if !ok {
			continue
		}
		named := mustNamed(tn)
		if named == nil {
			continue
		}
		st, ok := named.Underlying().(*types.Struct)
		if !ok {
			continue
		}
		for i := 0; i < st.NumFields(); i++ {
			f := st.Field(i)
			if f.Exported() && sensitiveFieldRe.MatchString(f.Name()) {
				out = append(out, domain.SymbolRef{Package: pkgPath, Symbol: name + "." + f.Name()})
			}
		}
	}
	return out, nil
}

// IsStruct reports whether a bare package-level name resolves to a struct
// type — distinguishes a data carrier ("PlainAuth") from a sink function
// when advisory symbols are unqualified.
func (ix *Index) IsStruct(ctx context.Context, ref domain.SymbolRef) (bool, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ctx); err != nil {
		return false, err
	}
	pkg := ix.pkgByPath(ctx, ref.Package)
	if pkg == nil || pkg.Types == nil {
		return false, fmt.Errorf("package %s not loaded", ref.Package)
	}
	obj := pkg.Types.Scope().Lookup(ref.Symbol)
	tn, ok := obj.(*types.TypeName)
	if !ok {
		return false, nil
	}
	named := mustNamed(tn)
	if named == nil {
		return false, nil
	}
	_, isStruct := named.Underlying().(*types.Struct)
	return isStruct, nil
}

// pkgByPath finds a loaded package by path, loading it on demand —
// dependency packages are not roots of the ./... load.
func (ix *Index) pkgByPath(ctx context.Context, pkgPath string) *packages.Package {
	for _, pkg := range ix.pkgs {
		if pkg.PkgPath == pkgPath && pkg.Types != nil {
			return pkg
		}
	}
	extra, err := ix.loadExtra(ctx, pkgPath)
	if err != nil {
		return nil
	}
	for _, pkg := range extra {
		if pkg.PkgPath == pkgPath && pkg.Types != nil {
			return pkg
		}
	}
	return nil
}

// isReflectValue reports whether e's static type is reflect.Value — the
// receiver shape of the mutating Set* calls.
func isReflectValue(info *types.Info, e ast.Expr) bool {
	if info == nil {
		return false
	}
	t := info.TypeOf(e)
	if t == nil {
		return false
	}
	n, ok := t.(*types.Named)
	if !ok || n.Obj() == nil || n.Obj().Pkg() == nil {
		return false
	}
	return n.Obj().Pkg().Path() == "reflect" && n.Obj().Name() == "Value"
}

func isReflectValueOrType(info *types.Info, e ast.Expr) bool {
	if info == nil {
		return false
	}
	t := info.TypeOf(e)
	if t == nil {
		return false
	}
	// For interface types like reflect.Type:
	if iface, ok := t.Underlying().(*types.Interface); ok {
		if n, ok := t.(*types.Named); ok && n.Obj() != nil && n.Obj().Pkg() != nil {
			if n.Obj().Pkg().Path() == "reflect" && n.Obj().Name() == "Type" {
				return true
			}
		}
		_ = iface
	}
	n, ok := t.(*types.Named)
	if !ok || n.Obj() == nil || n.Obj().Pkg() == nil {
		return false
	}
	return n.Obj().Pkg().Path() == "reflect" && (n.Obj().Name() == "Value" || n.Obj().Name() == "Type")
}

// callsUnsafe reports whether e contains a call to a function from the
// unsafe package — unsafe.Pointer, unsafe.Add, unsafe.Slice and friends.
func callsUnsafe(info *types.Info, e ast.Expr) bool {
	if info == nil {
		return false
	}
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && isUnsafePkg(info, sel.X) {
			found = true
			return false
		}
		return true
	})
	return found
}

// isUnsafePkg reports whether e is a qualifier ident resolving to the
// unsafe package.
func isUnsafePkg(info *types.Info, e ast.Expr) bool {
	if info == nil {
		return false
	}
	id, ok := e.(*ast.Ident)
	if !ok {
		return false
	}
	pn, ok := info.ObjectOf(id).(*types.PkgName)
	return ok && pn.Imported().Path() == "unsafe"
}

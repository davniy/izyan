package goanalysis

import (
	"context"
	"fmt"
	"go/ast"
	"maps"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"

	"github.com/fedorovmv/izyan/internal/affected"
	"github.com/fedorovmv/izyan/internal/domain"
	"golang.org/x/tools/go/packages"
)

// UnreachabilitySubject echoes one requested symbol subject back into the
// result, so the observation records exactly which (package, symbol) pairs
// the bounded proof covered.
type UnreachabilitySubject struct {
	Package string `json:"package"`
	Symbol  string `json:"symbol"`
}

// UnreachabilityResult is the typed record of one bounded
// symbol-unreachability proof over the loaded product scope. Every field is
// evidence: Complete is true only when every required subcheck ran and every
// gap set is empty, and Limitations names each reason the proof did not
// close. The result can support only a no-exploit-path style dismissal; it
// never encodes a not-affected verdict, and an empty enumeration is never a
// proof unless every inventory it depends on closed.
type UnreachabilityResult struct {
	Module                 string                  `json:"module"`
	Subjects               []UnreachabilitySubject `json:"subjects"`
	Build domain.BuildContext `json:"build"`
	Inventory affected.PackageInventoryMeasurement `json:"inventory"`
	DeclarationComplete    bool                    `json:"declaration_complete"`
	EntrypointComplete     bool                    `json:"entrypoint_complete"`
	ModuleEntryComplete bool `json:"module_entry_complete"`
	ModuleReachComplete bool `json:"module_reach_complete"`
	ProductPackages        []string                `json:"product_packages,omitempty"`
	Entrypoints            []domain.Entrypoint     `json:"entrypoints,omitempty"`
	ProductFunctionRoots   []domain.CallSite       `json:"product_function_roots,omitempty"`
	ProductReferences      []domain.CallSite       `json:"product_references,omitempty"`
	MayCallSites           []MayCallSite           `json:"may_call_sites,omitempty"`
	DependencyCallSites    []domain.CallSite       `json:"dependency_call_sites,omitempty"`
	InterfaceDispatchSites []domain.CallSite       `json:"interface_dispatch_sites,omitempty"`
	DynamicMarkers         []DynamicMarker         `json:"dynamic_markers,omitempty"`
	GatedReferences        []domain.CallSite       `json:"gated_references,omitempty"`
	ModuleEntrySymbols     []string                `json:"module_entry_symbols,omitempty"`
	ModuleReachable        map[string][]string     `json:"module_reachable,omitempty"`
	Opaque                 bool                    `json:"opaque"`
	Unbounded              bool                    `json:"unbounded"`
	Complete               bool                    `json:"complete"`
	Boundaries             []string                `json:"boundaries,omitempty"`
	Limitations            []string                `json:"limitations,omitempty"`
}

// unreachabilityBoundaries are the fixed scope exclusions every result
// carries as evidence: the proof is bounded to the loaded product closure,
// the recorded build context and the subject's own module internals.
// Mechanisms outside that model are named — their absence from the result
// can never be read as coverage.
var unreachabilityBoundaries = []string{
	"scope is the loaded product package closure plus the subject's own dependency module under the recorded GOOS/GOARCH/build tags",
	"reflection mechanisms not modeled by the marker scan, plugin loading, generated loading, cgo and go:linkname outside the recognized markers are outside proof scope",
	"external deployment entrypoints and unsupported transports outside the enumerated entrypoint scope are not covered",
	"alternate GOOS/GOARCH/build-tag variants are outside proof scope; build-gated references are surfaced as gated_references",
	"a complete result supports only a no-exploit-path conclusion; it is never a not-affected or negative-applicability claim",
}

// VerifyUnreachable runs the bounded symbol-unreachability proof for an
// advisory-declared module and subject set. It is a positive, recorded
// check — never a non-observation:
//
//   - every subject must resolve to a concrete declaration inside the
//     loaded dependency package (unresolvable declarations fail closed);
//   - the whole loaded product package inventory is scanned for direct
//     references, may-call candidates, interface dispatch, dynamic markers
//     and build-gated references;
//   - dep-internal callers and unbounded exported surfaces are checked
//     through DepInvocationState/FindDepCallers. Sibling-method liveness is
//     recorded by the source layer as an observation but is not a deadness
//     blocker: the admitted defect-semantics contract decides whether a dead
//     symbol's invocation is necessary (domain.ValidateDeadnessPremise);
//   - module-internal chains from the product's used API entries are
//     checked through ModuleInternalReach, with opaque dispatch recorded;
//   - skipped packages, load-budget exhaustion, partial enumeration or any
//     open gap set Complete=false with a named limitation.
//
// Ordering matters: dependency loads happen before the product-scope
// enumerations so the extras generation is settled when the cached scans
// run, making identical inputs produce identical output.
func (ix *Index) VerifyUnreachable(ctx context.Context, module string,
	subjects []domain.SymbolRef) (UnreachabilityResult, error) {

	measurement := affected.MeasurePackageInventory(ctx, affected.ExecGoTool{Env: ix.Env, Version: ix.Build.GoVersion}, ix.Dir, ix.Build, false)
	return ix.VerifyUnreachableWithInventory(ctx, module, subjects, measurement)
}

// VerifyUnreachableWithInventory binds the existing bounded kernel to captured
// package evidence. Inventory admission cannot repair any source/scope gap.
func (ix *Index) VerifyUnreachableWithInventory(ctx context.Context, module string, subjects []domain.SymbolRef, measurement affected.PackageInventoryMeasurement) (UnreachabilityResult, error) {
	res := UnreachabilityResult{Module: module, Build: domain.EffectiveBuildContext(ix.Build), Inventory: measurement}
	inv, inventoryErr := measurement.Admit(ix.Build)
	if err := inventoryErr; err != nil {
		res.Limitations = append(res.Limitations, "package inventory admission failed: " + err.Error())
	}
	if measurement.Run.WithTests { res.Limitations = append(res.Limitations, "unreachability requires product inventory, not test inventory") }
	for _, s := range subjects {
		res.Subjects = append(res.Subjects, UnreachabilitySubject{
			Package: s.Package, Symbol: s.Symbol,
		})
	}
	res.Boundaries = append(res.Boundaries, unreachabilityBoundaries...)
	if len(subjects) == 0 {
		res.Limitations = append(res.Limitations,
			"no symbol subjects declared; an empty subject set is never a closed unreachability proof")
		return res, nil
	}
	if err := ctx.Err(); err != nil {
		// A cancelled verification does no closure work at all: a partial
		// pass recorded as evidence would look like bounded coverage.
		return res, err
	}
	if err := ix.Loaded(ctx); err != nil {
		return res, err
	}

	// --- scoped reachability model. Every candidate site collected below
	// is filtered through it before joining a blocking array: only a site
	// proven DEAD (unreachable from the shipping closure inside a complete
	// graph) may leave the blocking set, and every discard is recorded in
	// Boundaries as an audit line. LIVE and UNKNOWN sites always block. A
	// scope build failure leaves the model nil, which classifies
	// everything UNKNOWN — nothing is discarded on missing data.
	scope, serr := ix.buildUnreachabilityScope(ctx)
	if serr != nil {
		res.Limitations = append(res.Limitations,
			"reachability scope construction failed: "+serr.Error())
	}
	// The built scope is a cached, shared snapshot observation. The
	// dependency-module verdicts folded below are per-verification (this
	// module, these subjects), so they land on a copy — a previous
	// verification's module results must never classify this one's sites,
	// and the cache must never be mutated.
	scope = scope.cloneForModuleCone()
	var audit []string
	discardPkg := func(path string) {
		audit = append(audit, fmt.Sprintf(
			"reachability-filter: discarded kind=skipped_package package=%s reason=unreachable", path))
	}
	discardSite := func(kind string, cs domain.CallSite, dynKind string) {
		line := fmt.Sprintf(
			"reachability-filter: discarded kind=%s package=%s file=%s line=%d function=%s",
			kind, cs.Package, cs.File, cs.Line, cs.Function)
		if dynKind != "" {
			line += " dyn=" + dynKind
		}
		audit = append(audit, line+" reason=unreachable")
	}

	// --- scope gates: the product inventory must be closed *for this
	// module*. A package that failed to type-check can only hide a
	// reference to the module when it imports the module — a Go symbol
	// reference requires that import edge — so unrelated load failures do
	// not open this proof. Reachability narrows this further: a skipped
	// package proven outside the shipping closure is audited, not
	// blocking; inside the closure or with unrecovered edges it stays a
	// gap.
	ix.mu.Lock()
	blockedSkipped, discardedSkipped := ix.skippedPackagesImportingModuleInScope(module, scope)
	ix.mu.Unlock()
	for _, p := range discardedSkipped {
		discardPkg(p)
	}
	if len(blockedSkipped) > 0 {
		res.Limitations = append(res.Limitations, fmt.Sprintf(
			"%d product package(s) importing module %s failed to type-check and were excluded from the scanned scope (e.g. %s); their references are invisible",
			len(blockedSkipped), module, blockedSkipped[0]))
	}
	if unscanned, uerr := ix.SkippedUnscanned(ctx); uerr != nil {
		res.Limitations = append(res.Limitations, "unscanned-package inventory failed: "+uerr.Error())
	} else if len(unscanned) > 0 {
		sort.Strings(unscanned)
		res.Limitations = append(res.Limitations, fmt.Sprintf(
			"%d product package(s) failed to load with unrecoverable source (e.g. %s); their references are invisible",
			len(unscanned), unscanned[0]))
	}

	// --- entrypoint inventory: every loaded product function root plus the
	// recognized external entrypoints bound the reachability scope. ---
	roots, rerr := ix.productFunctionRoots(ctx)
	if rerr != nil {
		res.Limitations = append(res.Limitations, "product function root enumeration failed: "+rerr.Error())
	} else {
		res.ProductFunctionRoots = roots
	}
	eps, eerr := ix.FindEntrypoints(ctx)
	if eerr != nil {
		res.Limitations = append(res.Limitations, "entrypoint enumeration failed: "+eerr.Error())
	} else {
		res.Entrypoints = eps
	}
	pkgs, perr := ix.ProductPackagePaths(ctx)
	if perr != nil {
		res.Limitations = append(res.Limitations, "product package inventory failed: "+perr.Error())
	} else {
		res.ProductPackages = pkgs
		if inventoryErr == nil {
			for _, path := range pkgs {
				if !inv.Paths[path] {
					res.Limitations = append(res.Limitations, "loaded product package missing from inventory: " + path)
				}
			}
		}
	}
	res.EntrypointComplete = rerr == nil && eerr == nil && perr == nil

	moduleEntryComplete := true
	moduleReachComplete := true
	// --- per-subject checks (dependency loads settle first) ---
	res.DeclarationComplete = true
	var (
		prodRefs      []domain.CallSite
		maySites      []MayCallSite
		depSites      []domain.CallSite
		dispatchSites []domain.CallSite
		markers       []DynamicMarker
		gatedRefs     []domain.CallSite
	)
	depModules := map[string]bool{}
	subjMod := map[string]string{}
	type depInv struct {
		callers int
	}
	rawInv := map[string]depInv{}
	depSitesByKey := map[string][]domain.CallSite{}
	usageUsed := map[string]bool{}
	usageSitesByKey := map[string][]domain.CallSite{}
	usageGapsByKey := map[string][]usageGap{}
	mayUnscopedPartial := map[string]bool{}
	mayScopedPartial := map[string]bool{}
	mayKeySeq := []string{}
	for _, subj := range subjects {
		key := subj.Package + "." + subj.Symbol
		if subj.Package == "" || subj.Symbol == "" {
			res.DeclarationComplete = false
			res.Limitations = append(res.Limitations, fmt.Sprintf(
				"subject %q is not an exact package.symbol pair; package-level subjects cannot ground a symbol-unreachability proof", key))
			continue
		}
		if _, err := ix.FindSymbol(ctx, subj); err != nil {
			res.DeclarationComplete = false
			res.Limitations = append(res.Limitations, fmt.Sprintf(
				"declaration of %s could not be resolved in the loaded dependency version: %v", key, err))
		}
		mod, ownerUnknown := ix.subjectModule(subj.Package)
		if mod != "" {
			depModules[mod] = true
			subjMod[key] = mod
		} else if ownerUnknown {
			// A non-product package whose owning module cannot be
			// established gets no cone: sibling-package callers inside
			// that module are unenumerable, so the subject must keep
			// the proof open rather than fall through silently.
			res.Limitations = append(res.Limitations, fmt.Sprintf(
				"module ownership of %s could not be resolved; dependency-internal callers are not enumerable", key))
			res.Unbounded = true
		}
	}

	// Load and pin every advisory module's extras before any scan runs.
	// The dep-side checks below already name a failed module load, so a
	// load error here only skips pinning; the pin itself is what keeps
	// evictExtra from dropping the active advisory module mid-scan and
	// churning the extras generation the may-call enumeration must see
	// frozen.
	var unpins []func()
	defer func() {
		for _, unpin := range unpins {
			unpin()
		}
	}()
	for _, mod := range slices.Sorted(maps.Keys(depModules)) {
		pattern := mod + "/..."
		ix.mu.Lock()
		if _, lerr := ix.loadExtra(ctx, pattern); lerr == nil {
			unpins = append(unpins, ix.pinExtraScoped(pattern))
		}
		ix.mu.Unlock()
	}

	// Dependency-side checks run before the cached may-call scan so the
	// extras generation is settled when callersOf memoizes. Verdicts are
	// collected raw here; the blocking decision happens after the
	// reachability filter below — a USED flag or a dep caller count raised
	// exclusively by dead sites must not open the proof.
	for _, subj := range subjects {
		if subj.Package == "" || subj.Symbol == "" {
			continue
		}
		key := subj.Package + "." + subj.Symbol

		// ProductUsage re-runs the bounded usage contract over the same
		// subject. Its site evidence (references, dispatch candidates,
		// gated refs, dynamic markers) is filtered per-site together with
		// the dedicated scans — only hard scope failures (declaration,
		// load, inventory, unscanned) stay fail-closed as limitations.
		usage, ugs, uerr := ix.productUsage(ctx, module, subj)
		if uerr != nil {
			res.Limitations = append(res.Limitations, fmt.Sprintf(
				"product usage check failed for %s: %v", key, uerr))
		} else {
			usageUsed[key] = usage.Usage == PackageUsageUsed
			usageSitesByKey[key] = usage.ProductSites
			prodRefs = append(prodRefs, usage.ProductSites...)
			usageGapsByKey[key] = ugs
		}

		sites, derr := ix.FindDepCallers(ctx, subj)
		if derr != nil {
			res.Limitations = append(res.Limitations, fmt.Sprintf(
				"dependency-internal caller scan failed for %s: %v", key, derr))
		} else {
			depSitesByKey[key] = append(depSitesByKey[key], sites...)
			depSites = append(depSites, sites...)
		}
		callers, _, _, ierr := ix.DepInvocationState(ctx, subj)
		if ierr != nil {
			res.Limitations = append(res.Limitations, fmt.Sprintf(
				"dependency invocation state failed for %s: %v", key, ierr))
		} else {
			rawInv[key] = depInv{callers: callers}
		}
	}

	// Module-internal reachability from the product's *reachable* used API
	// entries: call sites sitting in proven-dead product packages or
	// functions cannot seed the module cone.
	cones := map[string]*moduleCone{}
	for _, mod := range slices.Sorted(maps.Keys(depModules)) {
		entries, deadEntrySites, eerr := ix.moduleEntrySymbolsScoped(ctx, mod, scope)
		for _, ds := range deadEntrySites {
			discardSite("module_entry", ds, "")
		}
		if eerr != nil {
			moduleEntryComplete = false
			res.Limitations = append(res.Limitations, fmt.Sprintf(
				"module entry-symbol enumeration failed for %s: %v", mod, eerr))
			continue
		}
		res.ModuleEntrySymbols = append(res.ModuleEntrySymbols, entries...)
		mc, cerr := ix.moduleCone(ctx, mod, entries, scope)
		if cerr != nil {
			moduleReachComplete = false
			res.Limitations = append(res.Limitations, fmt.Sprintf(
				"module-internal reachability scan failed for %s: %v", mod, cerr))
			continue
		}
		cones[mod] = mc
		// Module packages that failed to type-check contribute no typed
		// edges to the cone — name them (their g.complete=False already
		// suppresses every DEAD verdict in the cone).
		for _, p := range mc.g.pkgs {
			if len(p.Errors) > 0 || p.TypesInfo == nil {
				d := skippedPackageDiagnostic(ix.fset, p)
				res.Limitations = append(res.Limitations, fmt.Sprintf(
					"advisory module package failed to type-check: %s: %s", d.Path, d.firstError()))
			}
		}
		if mc.dynLink {
			// go:linkname / plugin loading inside the module can pull
			// packages the import graph never saw — the cone stays open
			// and no module-internal verdict may read DEAD.
			res.Limitations = append(res.Limitations, fmt.Sprintf(
				"module %s contains dynamic materialization (go:linkname or plugin loading); out-of-cone functions stay unknown", mod))
		}
		var modSubjects []domain.SymbolRef
		for _, subj := range subjects {
			if domain.PackageInModule(subj.Package, mod) {
				modSubjects = append(modSubjects, subj)
			}
		}
		if len(modSubjects) == 0 {
			continue
		}
		reach, opaque, merr := ix.moduleSubjectReach(mc.g, modSubjects)
		if merr != nil {
			moduleReachComplete = false
			res.Limitations = append(res.Limitations, fmt.Sprintf(
				"module-internal reachability scan failed for %s: %v", mod, merr))
			continue
		}
		if opaque {
			res.Opaque = true
			res.Limitations = append(res.Limitations, fmt.Sprintf(
				"module %s contains opaque dispatch (unresolved func-value/interface calls) reachable from product-used entries; unreached subjects stay unknown", mod))
		}
		for key, chain := range reach {
			if res.ModuleReachable == nil {
				res.ModuleReachable = map[string][]string{}
			}
			res.ModuleReachable[key] = chain
		}
	}

	sort.Strings(res.ModuleEntrySymbols)
	for _, key := range slices.Sorted(maps.Keys(res.ModuleReachable)) {
		res.Limitations = append(res.Limitations, fmt.Sprintf(
			"subject %s is reachable from product-used module API via: %s", key,
			strings.Join(res.ModuleReachable[key], " -> ")))
	}

	// Product-scope enumerations.
	for _, subj := range subjects {
		if subj.Package == "" || subj.Symbol == "" {
			continue
		}
		key := subj.Package + "." + subj.Symbol

		refs, serr := ix.SearchSymbol(ctx, subj)
		if serr != nil {
			res.Limitations = append(res.Limitations, fmt.Sprintf(
				"product reference scan failed for %s: %v", key, serr))
		} else {
			prodRefs = append(prodRefs, refs...)
		}
		callSites, cerr := ix.FindCallers(ctx, subj)
		if cerr != nil {
			res.Limitations = append(res.Limitations, fmt.Sprintf(
				"static caller scan failed for %s: %v", key, cerr))
		} else {
			prodRefs = append(prodRefs, callSites...)
		}
		ix.mu.Lock()
		mays, partial, unscoped, merr := ix.mayCallScan(ctx, subj)
		ix.mu.Unlock()
		if merr != nil {
			res.Limitations = append(res.Limitations, fmt.Sprintf(
				"may-call enumeration failed for %s: %v", key, merr))
		} else {
			for _, m := range mays {
				maySites = append(maySites, m)
				mayKeySeq = append(mayKeySeq, key)
			}
			// Two partiality shapes need naming. Unscoped partiality (an
			// extras-churn sentinel bound to no site) can never be
			// resolved by filtering, so it is named unconditionally.
			// Site-local Possible flags die with their site when the
			// enclosing function is proven dead, but a Possible site that
			// survives the scope filter is an open candidate set on a
			// live path — the enumeration stays named-partial for that
			// subject (recorded after filtering, below).
			if partial {
				if unscoped {
					mayUnscopedPartial[key] = true
				} else {
					mayScopedPartial[key] = true
				}
			}
		}
		disp, derr := ix.InterfaceDispatchSites(ctx, subj)
		if derr != nil {
			res.Limitations = append(res.Limitations, fmt.Sprintf(
				"interface dispatch scan failed for %s: %v", key, derr))
		} else {
			narrow, dlim := ix.dispatchGaps(ctx, subj, disp)
			dispatchSites = append(dispatchSites, narrow...)
			if dlim != "" {
				res.Limitations = append(res.Limitations, dlim)
			}
		}
		marks, kerr := ix.ScanDynamic(ctx, subj)
		if kerr != nil {
			res.Limitations = append(res.Limitations, fmt.Sprintf(
				"dynamic-marker scan failed for %s: %v", key, kerr))
		} else {
			markers = append(markers, ix.relevantDynMarkers(ctx, subj, marks)...)
		}
		gated, gerr := ix.GatedRefs(ctx, subj)
		if gerr != nil {
			res.Limitations = append(res.Limitations, fmt.Sprintf(
				"build-gated reference scan failed for %s: %v", key, gerr))
		} else {
			gatedRefs = append(gatedRefs, gated...)
		}
	}

	// --- reachability filter: classify every candidate site and drop only
	// proven-dead evidence into the audit trail. The dep-side verdicts
	// (module functions folded into the scope, per-subject invocation
	// results, usage gaps) settle under the index lock because they use
	// lazily built caches (importers, caller scans, product references).
	ix.mu.Lock()
	if scope != nil {
		// Decide the flag *before* folding per-module verdicts: a failed
		// or open cone anywhere means no module-internal site may read
		// DEAD — including sites the complete cones classified on their
		// own. DEAD verdicts folded into ModuleFunctions publish only
		// under the global flag.
		depGraphComplete := len(cones) == len(depModules)
		for _, mc := range cones {
			if !mc.complete {
				depGraphComplete = false
			}
		}
		scope.DependencyGraphComplete = depGraphComplete
		for mod, mc := range cones {
			ix.fillModuleFunctions(ctx, scope, mod, mc, depGraphComplete)
		}
	}
	classify := func(cs domain.CallSite) reachabilityState {
		if scope == nil {
			return reachUnknown
		}
		return scope.classifySite(cs)
	}
	gatedState := func(cs domain.CallSite) reachabilityState {
		// A gated file proves no current-context call: only the package's
		// membership in the shipping closure decides — inside one, an
		// alternate build may wire anything in the package.
		if scope == nil {
			return reachUnknown
		}
		return scope.packageState(cs.Package)
	}

	var keptRefs []domain.CallSite
	for _, s := range prodRefs {
		if classify(s) == reachDead {
			discardSite("product_reference", s, "")
			continue
		}
		keptRefs = append(keptRefs, s)
	}
	var keptMay []MayCallSite
	keptPossibleByKey := map[string]int{}
	for i, s := range maySites {
		if classify(s.CallSite) == reachDead {
			discardSite("may_call", s.CallSite, "")
			continue
		}
		if s.Possible && i < len(mayKeySeq) {
			keptPossibleByKey[mayKeySeq[i]]++
		}
		keptMay = append(keptMay, s)
	}
	var keptDep []domain.CallSite
	retainedDepByKey := map[string]int{}
	for _, s := range depSites {
		if classify(s) == reachDead {
			discardSite("dependency_call", s, "")
			continue
		}
		keptDep = append(keptDep, s)
	}
	for key, list := range depSitesByKey {
		for _, s := range list {
			if classify(s) != reachDead {
				retainedDepByKey[key]++
			}
		}
	}
	var keptDisp []domain.CallSite
	for _, s := range dispatchSites {
		if classify(s) == reachDead {
			discardSite("interface_dispatch", s, "")
			continue
		}
		keptDisp = append(keptDisp, s)
	}
	var keptMarkers []DynamicMarker
	for _, m := range markers {
		if classify(m.CallSite) == reachDead {
			discardSite("dynamic_marker", m.CallSite, m.Kind)
			continue
		}
		keptMarkers = append(keptMarkers, m)
	}
	var keptGated []domain.CallSite
	for _, s := range gatedRefs {
		if gatedState(s) == reachDead {
			discardSite("gated_reference", s, "")
			continue
		}
		keptGated = append(keptGated, s)
	}

	// Usage-verdict limitations re-derived from filtered evidence: USED
	// blocks only while a live/unknown product site remains; skipped
	// importers are reclassified against the shipping closure; every
	// site-derived gap is covered by the dedicated filtered arrays and
	// never double-reported.
	for _, subj := range subjects {
		if subj.Package == "" || subj.Symbol == "" {
			continue
		}
		key := subj.Package + "." + subj.Symbol
		if usageUsed[key] {
			kept := 0
			for _, s := range usageSitesByKey[key] {
				if classify(s) != reachDead {
					kept++
				}
			}
			if kept > 0 {
				res.Limitations = append(res.Limitations, fmt.Sprintf(
					"product usage check reports %s as USED (%d product site(s))", key, kept))
			}
			continue
		}
		fatal := false
		for _, g := range usageGapsByKey[key] {
			switch g.kind {
			case usageGapFatal:
				fatal = true
				res.Limitations = append(res.Limitations, g.text)
			case usageGapSkipped:
				var still []string
				for _, p := range g.pkgs {
					if classify(domain.CallSite{Package: p}) == reachDead {
						discardPkg(p)
						continue
					}
					still = append(still, p)
				}
				if len(still) > 0 {
					fatal = true
					// Keep this build's per-package diagnostic text — it
					// names the failed package, the failing import and the
					// remediation hint the flat aggregate text did not carry.
					res.Limitations = append(res.Limitations, g.text)
				}
			}
		}
		if fatal {
			res.Limitations = append(res.Limitations, fmt.Sprintf(
				"product usage check could not close its negative verification for %s", key))
		}
	}

	// Invocation-state limitations re-derived: unboundedness is rechecked
	// against the shipping closure (a dead skipped importer cannot widen
	// the caller set), and live callers are counted from retained
	// dep-internal sites only.
	for _, subj := range subjects {
		if subj.Package == "" || subj.Symbol == "" {
			continue
		}
		key := subj.Package + "." + subj.Symbol
		inv, ok := rawInv[key]
		if !ok {
			continue
		}
		// Other-module importers widen the caller set beyond what dep
		// sites can show: any non-product importer outside the subject's
		// module keeps callers unenumerable (and possibly live).
		if ix.scopedUnbounded(ctx, scope, subj, subjMod[key]) {
			res.Unbounded = true
			res.Limitations = append(res.Limitations, fmt.Sprintf(
				"subject %s is exported and other dependency modules import its package — dep-internal callers are not enumerable", key))
			continue
		}
		switch {
		case inv.callers > 0 && retainedDepByKey[key] > 0:
			res.Limitations = append(res.Limitations, fmt.Sprintf(
				"subject %s has %d live call site(s) inside the dependency", key, retainedDepByKey[key]))
		case inv.callers > 0 && inv.callers > len(depSitesByKey[key])-retainedDepByKey[key]:
			// More live callers than in-module dead evidence can account
			// for: the excess is callers the dep-site list cannot show.
			res.Limitations = append(res.Limitations, fmt.Sprintf(
				"subject %s has %d live call site(s) inside the dependency", key, inv.callers))
		}
	}
	ix.mu.Unlock()

	partialMaps := []map[string]bool{mayUnscopedPartial, mayScopedPartial}
	for mi, keys := range partialMaps {
		sorted := make([]string, 0, len(keys))
		for k := range keys {
			sorted = append(sorted, k)
		}
		sort.Strings(sorted)
		for _, key := range sorted {
			if mi == 0 {
				res.Limitations = append(res.Limitations, fmt.Sprintf(
					"may-call enumeration for %s is partial (unresolved function-value candidates, open coverage sentinel, unreconciled scope churn or eviction, or bound exhaustion); the caller set is not closed", key))
				continue
			}
			// A site-local Possible flag that survived the scope filter
			// is an open candidate set on a live path: the enumeration
			// is named partial even though the site itself blocks too.
			if keptPossibleByKey[key] > 0 {
				res.Limitations = append(res.Limitations, fmt.Sprintf(
					"may-call enumeration for %s is partial (unresolved candidates); the caller set is not closed", key))
			}
		}
	}

	res.ProductReferences = dedupCallSites(keptRefs)
	res.MayCallSites = dedupMayCallSites(keptMay)
	res.DependencyCallSites = dedupCallSites(keptDep)
	res.InterfaceDispatchSites = dedupCallSites(keptDisp)
	res.DynamicMarkers = dedupDynMarkers(keptMarkers)
	res.GatedReferences = dedupCallSites(keptGated)
	if len(res.ProductReferences) > 0 {
		res.Limitations = append(res.Limitations, fmt.Sprintf(
			"product code holds %d reference site(s) to the subject(s) — the symbols are symbolically reachable", len(res.ProductReferences)))
	}
	if len(res.MayCallSites) > 0 {
		res.Limitations = append(res.Limitations, fmt.Sprintf(
			"%d may-call site(s) can reach the subject(s) through interface dispatch or function values", len(res.MayCallSites)))
	}
	if len(res.DependencyCallSites) > 0 {
		res.Limitations = append(res.Limitations, fmt.Sprintf(
			"%d dependency-internal call site(s) name the subject(s); their liveness is judged by the invocation state, not by site count alone", len(res.DependencyCallSites)))
	}
	if len(res.InterfaceDispatchSites) > 0 {
		res.Limitations = append(res.Limitations, fmt.Sprintf(
			"%d interface-dispatched call site(s) may resolve to the subject — the dynamic receiver is unresolved", len(res.InterfaceDispatchSites)))
	}
	for _, m := range res.DynamicMarkers {
		res.Limitations = append(res.Limitations, fmt.Sprintf(
			"dynamic escape %s at %s:%d may reach the subject: %s", m.Kind, m.File, m.Line, m.Detail))
	}
	if len(res.GatedReferences) > 0 {
		res.Limitations = append(res.Limitations, fmt.Sprintf(
			"%d reference(s) exist in files excluded by the current build tags — an alternate build may reach the subject", len(res.GatedReferences)))
	}

	// The audit trail is part of the result's evidence: deterministic
	// order, deduplicated, riding the existing Boundaries channel so no
	// schema change is needed.
	sort.Strings(audit)
	audit = dedupStrings(audit)
	res.Boundaries = append(res.Boundaries, audit...)

	// Session-scoped truncation evidence, read after every scan so a
	// budget this very pass exhausted is included: a truncated session
	// cannot close a proof, and a repeated verification of the same
	// subjects must not discard the earlier unresolved state — the named
	// record is sticky.
	for _, l := range ix.BudgetLimitations() {
		line := l + "; dependency coverage is truncated"
		if !hasLimitationText(res.Limitations, line) {
			res.Limitations = append(res.Limitations, line)
		}
	}
	if ix.LoadBudgetExhausted() {
		line := truncationPackageLoad + "; dependency coverage is truncated"
		if !hasLimitationText(res.Limitations, line) {
			res.Limitations = append(res.Limitations, line)
		}
	}

	res.ModuleEntryComplete = moduleEntryComplete
	res.ModuleReachComplete = moduleReachComplete
	res.Complete = res.DeclarationComplete &&
		res.EntrypointComplete &&
		moduleEntryComplete &&
		moduleReachComplete &&
		len(res.Limitations) == 0
	if res.Complete {
		if err := res.ValidateComplete(res.Build); err != nil {
			res.Complete = false
			res.Limitations = append(res.Limitations, err.Error())
		}
	}
	return res, nil
}

// ValidateComplete replays the complete captured payload without loading source.
// Complete is a summary, never an independent admission capability.
func (r UnreachabilityResult) ValidateComplete(build domain.BuildContext) error {
	if !r.Complete || !r.DeclarationComplete || !r.EntrypointComplete || !r.ModuleEntryComplete || !r.ModuleReachComplete || r.Opaque || r.Unbounded || len(r.Limitations) != 0 || len(r.ProductReferences) != 0 || len(r.MayCallSites) != 0 || len(r.DependencyCallSites) != 0 || len(r.InterfaceDispatchSites) != 0 || len(r.DynamicMarkers) != 0 || len(r.GatedReferences) != 0 || len(r.ModuleReachable) != 0 {
		return fmt.Errorf("bounded unreachability has open closure gates")
	}
	if err := r.Build.Matches(build); err != nil {
		return fmt.Errorf("unreachability build differs from expected build: %w", err)
	}
	inv, err := r.Inventory.AdmitBuild(build)
	if err != nil { return fmt.Errorf("unreachability inventory: %w", err) }
	if r.Inventory.Run.WithTests { return fmt.Errorf("unreachability requires product inventory") }
	if r.Module == "" || len(r.Subjects) == 0 || len(r.ProductPackages) == 0 { return fmt.Errorf("unreachability scope or subjects missing") }
	seen := map[string]bool{}
	for _, s := range r.Subjects {
		key := s.Package + "." + s.Symbol
		if s.Package == "" || s.Symbol == "" || seen[key] || (s.Package != r.Module && !strings.HasPrefix(s.Package, r.Module+"/")) { return fmt.Errorf("invalid unreachability subject %s", key) }
		seen[key] = true
	}
	for _, path := range r.ProductPackages { if !inv.Paths[path] { return fmt.Errorf("product package %s absent from inventory", path) } }
	return nil
}

// hasLimitationText reports whether the limitation list already carries the
// exact line — repeated passes must not duplicate the same named gap.
func hasLimitationText(limitations []string, want string) bool {
	for _, l := range limitations {
		if l == want {
			return true
		}
	}
	return false
}

// productFunctionRoots enumerates every function and method declaration in
// the loaded product packages — the bounded root set whose bodies the
// product-scope scans examined. Sorted for a byte-stable record.
func (ix *Index) productFunctionRoots(ctx context.Context) ([]domain.CallSite, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ctx); err != nil {
		return nil, err
	}
	var out []domain.CallSite
	for _, pkg := range ix.pkgs {
		for _, f := range pkg.Syntax {
			if ix.isTestFile(f) {
				continue
			}
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Name == nil {
					continue
				}
				pos := ix.fset.Position(fn.Pos())
				cs := domain.CallSite{
					File:     pos.Filename,
					Line:     pos.Line,
					Function: fn.Name.Name,
					Package:  pkg.PkgPath,
				}
				if fn.Recv != nil && len(fn.Recv.List) > 0 {
					cs.Receiver = recvDeclName(fn.Recv.List[0].Type)
				}
				out = append(out, cs)
			}
		}
	}
	sortCallSites(out)
	return out, nil
}

// moduleCone is the dependency-side half of the reachability model: the
// module call graph seeded from filtered product entries plus the "init"
// nodes of module packages linked into the shipping closure. A dep
// function outside the cone is DEAD only when the whole evidence chain is
// complete: the module loaded cleanly, the importer graph was computed,
// and the product graph closed.
type moduleCone struct {
	module   string
	g        *moduleGraph
	complete bool
	linkOK   bool
	dynLink  bool
	linked   map[string]bool
}

// moduleCone builds the filtered entry cone for one dependency module.
// entries are callee keys from retained product call sites; every linked
// module package additionally contributes its init machinery because
// package-level initialization runs code no product call ever names.
// Callers must not hold ix.mu — depImporters and loadExtra lock-free paths
// assume the caller owns it.
func (ix *Index) moduleCone(ctx context.Context, module string, entries []string,
	scope *unreachabilityScope) (*moduleCone, error) {

	ix.mu.Lock()
	defer ix.mu.Unlock()
	loaded, err := ix.loadExtra(ctx, module+"/...")
	if err != nil {
		return nil, err
	}
	var pkgs []*packages.Package
	for _, p := range loaded {
		if domain.PackageInModule(p.PkgPath, module) {
			pkgs = append(pkgs, p)
		}
	}
	// Shipping-linked package set: reachable in the whole-closure import
	// graph from product packages that are not proven dead. When the
	// importer graph cannot be built nothing is proven linked — and,
	// symmetrically, nothing is proven unlinked.
	importers, ierr := ix.depImporters(ctx)
	linkOK := ierr == nil
	linked := map[string]bool{}
	if linkOK {
		fwd := map[string][]string{}
		for imported, ims := range importers {
			for _, im := range ims {
				fwd[im.path] = append(fwd[im.path], imported)
			}
		}
		var queue []string
		push := func(p string) {
			if !linked[p] {
				linked[p] = true
				queue = append(queue, p)
			}
		}
		if scope != nil {
			for path, st := range scope.ProductPackages {
				if st != reachDead {
					push(path)
				}
			}
		}
		for _, p := range ix.pkgs {
			if scope == nil || scope.packageState(p.PkgPath) != reachDead {
				push(p.PkgPath)
			}
		}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			for _, n := range fwd[cur] {
				push(n)
			}
		}
	}
	seeds := append([]string{}, entries...)
	for _, p := range pkgs {
		if !linkOK || linked[p.PkgPath] {
			seeds = append(seeds, p.PkgPath+".init")
		}
	}
	g := ix.moduleReachabilityGraph(pkgs, module, seeds)
	complete := g.complete && linkOK && scope != nil && scope.ProductGraphComplete
	return &moduleCone{
		module:   module,
		g:        g,
		complete: complete,
		linkOK:   linkOK,
		dynLink:  g.dynLink,
		linked:   linked,
	}, nil
}

// depFuncState computes the reachability verdict for one function inside a
// module cone. name is the recorded enclosing name (bare for functions and
// methods, "init"/"" for package machinery); candidates are the declared
// keys it could denote.
func (ix *Index) depFuncState(ctx context.Context, mc *moduleCone,
	pkgPath, name string, scope *unreachabilityScope) reachabilityState {

	if mc == nil || mc.g == nil {
		return reachUnknown
	}
	if name == "" || name == "init" {
		// Package init machinery runs whenever the package is linked into
		// the shipping binary — whether through a real import edge or an
		// invisible one (linkname/plugin). Any gap in the cone — load
		// errors, unclosed product graph, dynamic materialization — keeps
		// the verdict out of DEAD.
		if !mc.complete || !mc.linkOK {
			return reachUnknown
		}
		if mc.linked[pkgPath] {
			return reachLive
		}
		return reachDead
	}
	var cands []string
	for k := range mc.g.declared[pkgPath] {
		if k == name || strings.HasSuffix(k, "."+name) {
			cands = append(cands, k)
		}
	}
	for _, k := range cands {
		if _, ok := mc.g.reachable[pkgPath+"."+k]; ok {
			return reachLive
		}
	}
	if !mc.complete || len(cands) == 0 {
		return reachUnknown
	}
	exported := false
	for _, k := range cands {
		base := k
		if i := strings.LastIndexByte(k, '.'); i >= 0 {
			base = k[i+1:]
		}
		if ast.IsExported(base) {
			exported = true
			break
		}
	}
	if exported {
		// An exported module function may be invoked from another
		// dependency module, or through a product-side reference/func
		// value that no resolved call edge recorded.
		if ix.importedByOtherModule(ctx, pkgPath, mc.module) {
			return reachUnknown
		}
		for _, k := range cands {
			if ix.hasLiveProductRef(domain.SymbolRef{Package: pkgPath, Symbol: k}, scope) {
				return reachUnknown
			}
		}
	}
	// Opaque dispatch in the reachable cone may hit any compatible
	// function — an incompatible verdict is required before deadness.
	for oc, sites := range mc.g.opaque {
		if _, ok := mc.g.reachable[oc]; !ok {
			continue
		}
		for _, o := range sites {
			if depOpaqueCompatible(o, mc.g.pkgs, pkgPath, cands) {
				return reachUnknown
			}
		}
	}
	return reachDead
}

// depOpaqueCompatible reports whether an unresolved dispatch site could
// invoke one of the candidate functions of pkgPath. Unresolvable objects
// and fully opaque sites answer true — narrowing is never proof of
// deadness.
func depOpaqueCompatible(site opaqueSite, pkgs []*packages.Package,
	pkgPath string, cands []string) bool {

	if site.sig == nil && site.iface == nil {
		return true
	}
	for _, k := range cands {
		ref := domain.SymbolRef{Package: pkgPath, Symbol: k}
		obj, recv := findSubjectObject(pkgs, ref)
		if obj == nil {
			return true
		}
		if isOpaqueSiteCompatible(site, ref, obj, recv) {
			return true
		}
	}
	return false
}

// hasLiveProductRef reports whether product code holds any reference to
// ref outside proven-dead packages — a value escape the entry enumeration
// cannot see. Callers must hold ix.mu.
func (ix *Index) hasLiveProductRef(ref domain.SymbolRef, scope *unreachabilityScope) bool {
	for _, s := range ix.productRefsTo(ref) {
		if scope != nil && scope.classifySite(s) == reachDead {
			continue
		}
		return true
	}
	return false
}

// fillModuleFunctions folds depFuncState verdicts into the scope's
// ModuleFunctions so classifySite answers dependency-package sites.
// Package-level evidence (site.Function == "") shares the init verdict.
// Callers must hold ix.mu.
func (ix *Index) fillModuleFunctions(ctx context.Context, scope *unreachabilityScope,
	mod string, mc *moduleCone, depGraphComplete bool) {

	if mc == nil || mc.g == nil {
		return
	}
	if scope.ModuleFunctions == nil {
		scope.ModuleFunctions = map[string]map[string]reachabilityState{}
	}
	for pkgPath, decls := range mc.g.declared {
		folded := scope.ModuleFunctions[pkgPath]
		if folded == nil {
			folded = map[string]reachabilityState{}
			scope.ModuleFunctions[pkgPath] = folded
		}
		seen := map[string]bool{}
		for k := range decls {
			if k == "init" {
				continue
			}
			st := ix.depFuncState(ctx, mc, pkgPath, k, scope)
			if !depGraphComplete && st == reachDead {
				// DEAD may never sit in the map while any module cone is
				// open — normalize before a raw-map consumer can see it.
				st = reachUnknown
			}
			base := k
			if i := strings.LastIndexByte(k, '.'); i >= 0 {
				base = k[i+1:]
			}
			if !seen[base] {
				folded[base] = st
				seen[base] = true
			} else {
				folded[base] = mostReachable(folded[base], st)
			}
		}
		st := ix.depFuncState(ctx, mc, pkgPath, "init", scope)
		if !depGraphComplete && st == reachDead {
			st = reachUnknown
		}
		folded["init"] = st
		folded[""] = st
	}
}

// scopedUnbounded rechecks DepInvocationState's unbounded-caller verdict
// against the shipping closure: only importers that are neither the
// subject's module nor *known* product packages count. A skipped product
// package proven dead cannot widen the caller set; a nil scope keeps the
// original verdict. Callers must hold ix.mu.
func (ix *Index) scopedUnbounded(ctx context.Context, scope *unreachabilityScope,
	subj domain.SymbolRef, mod string) bool {

	if scope == nil {
		return true
	}
	importers, err := ix.depImporters(ctx)
	if err != nil {
		return true
	}
	for _, im := range importers[subj.Package] {
		if _, isProduct := scope.ProductPackages[im.path]; isProduct {
			continue // product evidence is judged by the site filter, not here
		}
		if mod != "" && im.module == mod {
			continue
		}
		if im.module == "" && mod == "" {
			continue // same unknown-module bucket
		}
		return true
	}
	return false
}

// moduleEntrySymbolsScoped returns the module API symbols named by live
// product call sites. When the scope's product graph closed, the
// correctly-attributed ModuleEntries the graph already recorded are the
// entry source (package-level calls ride the init sentinel there, not the
// previous declaration's name); the raw usage scan then only supplies the
// audit trail — call sites inside packages proven dead, which
// ModuleEntries deliberately excludes. With no scope or an incomplete
// product graph nothing may be discarded, so the full usage scan feeds
// entries directly, unfiltered.
func (ix *Index) moduleEntrySymbolsScoped(ctx context.Context, module string,
	scope *unreachabilityScope) (entries []string, deadSites []domain.CallSite, err error) {

	var usageSites []domain.CallSite
	if ix.moduleUsageOverride != nil {
		usageSites, err = ix.moduleUsageOverride(ctx, module)
	} else {
		usageSites, err = ix.ModuleUsage(ctx, module)
	}
	if err != nil {
		return nil, nil, err
	}
	// The scoped entries path is authoritative only when the test seam is
	// absent — overrides simulate enumeration shapes ModuleEntries cannot.
	useScope := ix.moduleUsageOverride == nil && scope != nil &&
		scope.ProductGraphComplete
	var entrySites []domain.CallSite
	if useScope {
		entrySites = scope.ModuleEntries[module]
	} else {
		entrySites = usageSites
	}
	seen := map[string]bool{}
	add := func(s domain.CallSite) {
		if s.Callee == "" {
			return
		}
		if !seen[s.Callee] {
			seen[s.Callee] = true
			entries = append(entries, s.Callee)
		}
	}
	for _, s := range entrySites {
		if s.ModuleOwner != "" && s.ModuleOwner != module {
			continue // nested-module prefix hit — not this module's API
		}
		add(s)
	}
	if !useScope {
		// No closed scope: keep every site — discarding requires DEAD
		// proof — but mark none dead.
		sort.Strings(entries)
		return entries, nil, nil
	}
	for _, s := range usageSites {
		if s.Callee == "" || s.ModuleOwner != module {
			continue
		}
		if scope.packageState(s.Package) == reachDead {
			deadSites = append(deadSites, s)
		}
	}
	sort.Strings(entries)
	return entries, deadSites, nil
}

// subjectModule returns the dependency module owning pkgPath for the loaded
// snapshot — "" for product/stdlib packages or unresolvable ownership. The
// second result reports a genuinely unresolvable *dependency* ownership: a
// non-product package whose module identity cannot be established (load
// failure or missing module metadata). depModuleOf reads and lazily builds
// ix.pkgModules, so the lock is held.
func (ix *Index) subjectModule(pkgPath string) (string, bool) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ix.ctxOr(nil)); err != nil {
		return "", false
	}
	// Product ownership first: go list all reports product packages with
	// the main module path, so a trusted depModuleOf hit could otherwise
	// cone the product's own module as a dependency.
	if ix.isProductPath(pkgPath) || ix.skippedPkgs[pkgPath] != nil {
		return "", false
	}
	if mod := ix.depModuleOf(pkgPath); mod != "" {
		if mod == ix.mainModulePath() {
			return "", false
		}
		return mod, false
	}
	// Packages nothing in the import closure references are invisible to
	// the importer index (go list all covers the closure only) — resolve
	// ownership through a direct load so an unlinked-package subject still
	// gets its cone.
	extra, err := ix.loadExtra(ix.ctxOr(nil), pkgPath)
	if err != nil {
		return "", true
	}
	for _, p := range extra {
		if p.PkgPath != pkgPath {
			continue
		}
		if p.Module != nil {
			if p.Module.Main {
				// The subject sits in the product's own module even when
				// the package itself failed to load.
				return "", false
			}
			return p.Module.Path, false
		}
		// No module metadata: stdlib sources live under GOROOT; anything
		// else without a module is a dependency whose ownership cannot be
		// established — report it unresolved instead of dropping the cone.
		for _, gf := range p.GoFiles {
			if goroot := runtime.GOROOT(); goroot != "" &&
				strings.HasPrefix(gf, goroot+string(filepath.Separator)) {
				return "", false
			}
		}
	}
	return "", true
}

// mainModulePath returns the product's own module path ("" when the
// loaded snapshot has no main module, e.g. GOPATH mode). Callers hold
// ix.mu and must run ix.load first.
func (ix *Index) mainModulePath() string {
	for _, p := range ix.pkgs {
		if p.Module != nil && p.Module.Main {
			return p.Module.Path
		}
	}
	for _, p := range ix.skippedPkgs {
		if p.Module != nil && p.Module.Main {
			return p.Module.Path
		}
	}
	return ""
}

// moduleEntrySymbols returns the module API symbols product call sites name
// — the entry side of the module-internal reachability check, matching how
// the deterministic lane derives ModuleInternalReach entries.
func (ix *Index) moduleEntrySymbols(ctx context.Context, module string) ([]string, error) {
	var (
		sites []domain.CallSite
		err   error
	)
	if ix.moduleUsageOverride != nil {
		sites, err = ix.moduleUsageOverride(ctx, module)
	} else {
		sites, err = ix.ModuleUsage(ctx, module)
	}
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range sites {
		if s.Callee != "" && s.ModuleOwner == module && !seen[s.Callee] {
			seen[s.Callee] = true
			out = append(out, s.Callee)
		}
	}
	sort.Strings(out)
	return out, nil
}

// dispatchGaps keeps only the interface-dispatch sites that remain open
// after receiver-instantiation narrowing: a candidate whose receiver type
// is provably never materialized in product-visible code cannot dispatch
// to the subject. Narrowing is allowed only when the probe is complete:
// the subject's receiver type resolved, instantiation narrowing stayed
// enabled (no dynamic materialization), and every product package
// type-checked so the instantiation inventory is closed. Any probe
// shortfall keeps every site open, and the returned string names the
// reason — narrowing failure must never surface as an empty dispatch
// list without a named limitation.
func (ix *Index) dispatchGaps(ctx context.Context, ref domain.SymbolRef,
	sites []domain.CallSite) ([]domain.CallSite, string) {
	if len(sites) == 0 {
		return nil, ""
	}
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ctx); err != nil {
		return sites, fmt.Sprintf(
			"interface-dispatch narrowing could not run for %s.%s — the instantiation probe failed (%v); %d dispatch candidate(s) stay open",
			ref.Package, ref.Symbol, err, len(sites))
	}
	typeName, _ := splitSymbol(ref.Symbol)
	recvName := subjectRecvName(typeName)
	if recvName == "" ||
		ix.lookupNamedType(ctx, ref.Package, recvName) == nil {
		return sites, fmt.Sprintf(
			"receiver type of %s.%s could not be resolved — %d name-matched dispatch candidate(s) stay open and instantiation narrowing does not apply",
			ref.Package, ref.Symbol, len(sites))
	}
	_, disabled, complete := ix.productNarrowingLocked()
	switch {
	case disabled:
		return sites, fmt.Sprintf(
			"dynamic materialization in product code disables instantiation narrowing — %d dispatch candidate(s) for %s.%s stay open",
			len(sites), ref.Package, ref.Symbol)
	case !complete:
		return sites, fmt.Sprintf(
			"product instantiation inventory is incomplete (%d package(s) failed to type-check) — %d dispatch candidate(s) for %s.%s stay open",
			len(ix.skipped), len(sites), ref.Package, ref.Symbol)
	case !ix.receiverTypeInstantiated(ctx, ref):
		return nil, ""
	}
	return sites, ""
}

// productNarrowingLocked reports the receiver-instantiation narrowing
// state for the loaded product scope; callers must hold ix.mu with the
// index already loaded. narrow is true only when the probe is complete:
// syntax-driven materialization is not disabled (reflect.New/NewAt,
// unsafe, plugin, go:linkname all set disabled) and no product package
// was skipped — a skipped package's syntax never entered the inventory,
// so its absence from the set proves nothing. complete reports the
// skipped-package half of that condition so callers can name it.
func (ix *Index) productNarrowingLocked() (narrow, disabled, complete bool) {
	_, enabled := ix.productInstantiated()
	disabled = !enabled
	complete = len(ix.skipped) == 0
	return enabled && complete, disabled, complete
}

// productInstantiatedHas reports whether ref's receiver type is in the
// product instantiation set; callers must hold ix.mu with the index
// already loaded. Standalone or receiver-less subjects count as
// instantiated — they have no receiver to materialize.
func (ix *Index) productInstantiatedHas(ref domain.SymbolRef) bool {
	typeName, _ := splitSymbol(ref.Symbol)
	recvName := subjectRecvName(typeName)
	if recvName == "" {
		return true
	}
	inst, _ := ix.productInstantiated()
	if inst == nil {
		return true
	}
	return inst[ref.Package+"."+recvName]
}

// relevantDynMarkers narrows a ScanDynamic result to the invocation-
// relevant markers the negative contract recognizes — the same relevance
// rule ProductUsage applies, so the two checks agree on which escapes
// matter.
func (ix *Index) relevantDynMarkers(ctx context.Context, ref domain.SymbolRef, markers []DynamicMarker) []DynamicMarker {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ctx); err != nil {
		// A failed probe must not narrow any marker away.
		return relevantUsageMarkers(markers, ref, true, false)
	}
	narrow, _, _ := ix.productNarrowingLocked()
	// receiverTypeInstantiated encodes the same gate contract: an
	// unproven receiver (unresolved, disabled narrowing, skipped
	// packages) counts as materialized, keeping reflect_method relevant.
	recvInst := ix.receiverTypeInstantiated(ctx, ref)
	return relevantUsageMarkers(markers, ref, recvInst, narrow)
}

// dispatchGapsLocked is the lock-held core of dispatchGaps —
// ScanRelevantDynamic runs the identical narrowing inside its own
// locked section. Callers must hold ix.mu with the index already loaded.
// Shadow's receiverTypeInstantiated already folds the V2 `!recvInst &&
// prodNarrow` predicate into one probe — the receiver resolved and
// materialization narrowing ran on a complete product inventory — so a
// false result is the proven-never-materialized verdict the narrowed
// set collapses on.
func (ix *Index) dispatchGapsLocked(ctx context.Context, ref domain.SymbolRef, sites []domain.CallSite) []domain.CallSite {
	if len(sites) == 0 {
		return nil
	}
	if !ix.receiverTypeInstantiated(ctx, ref) {
		return nil
	}
	return sites
}

// dedupCallSites removes duplicate sites (multi-subject scans can report
// the same position twice) and sorts for a deterministic record.
func dedupCallSites(in []domain.CallSite) []domain.CallSite {
	seen := map[domain.CallSite]bool{}
	var out []domain.CallSite
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sortCallSites(out)
	return out
}

func dedupMayCallSites(in []MayCallSite) []MayCallSite {
	seen := map[MayCallSite]bool{}
	var out []MayCallSite
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Package != b.Package {
			return a.Package < b.Package
		}
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
	return out
}

func dedupDynMarkers(in []DynamicMarker) []DynamicMarker {
	type key struct {
		kind, file, detail string
		line               int
	}
	seen := map[key]bool{}
	var out []DynamicMarker
	for _, m := range in {
		k := key{kind: m.Kind, file: m.File, detail: m.Detail, line: m.Line}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, m)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Kind < b.Kind
	})
	return out
}

// usageAbsenceGap is the ProductUsage limitation that marks the subject's
// package absent from the linked import closure. For an unreachability
// proof that absence is a positive non-reachability observation inside the
// recorded build context — not a scope gap — so it is filtered out.
const usageAbsenceGap = "target package is absent from the linked import closure of the current build context"

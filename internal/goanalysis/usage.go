package goanalysis

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/types"
	"runtime"
	"slices"
	"sort"
	"strings"

	"github.com/fedorovmv/izyan/internal/domain"
	"golang.org/x/tools/go/packages"
)

// PackageUsageState is the three-state verdict of ProductUsage for one
// advisory-declared package or symbol, over the current product source
// closure only.
type PackageUsageState string

const (
	PackageUsageUsed    PackageUsageState = "USED"
	PackageUsageNotUsed PackageUsageState = "NOT_USED"
	PackageUsageUnknown PackageUsageState = "UNKNOWN"
)

// PackageUsageNegativeVerification states how a negative usage result was
// reached. VERIFIED means a bounded negative-verification rule passed:
// either the target is linked into the product's import closure, every
// loaded product package was scanned, and no scope gap or dynamic escape
// was found, or — for a package-level subject only — the product closure
// is complete and the target is provably absent from its linked import
// closure, which no product source can reference. INSUFFICIENT_SCOPE
// means the negative could not be closed — ProductUsage then reports
// UNKNOWN, never NOT_USED. CONTRADICTED marks a refutation of the
// negative premise (e.g. a symbol used as a func value that no typed
// reference matched).
type PackageUsageNegativeVerification string

const (
	PackageUsageNegativeVerified          PackageUsageNegativeVerification = "VERIFIED"
	PackageUsageNegativeInsufficientScope PackageUsageNegativeVerification = "INSUFFICIENT_SCOPE"
	PackageUsageNegativeContradicted      PackageUsageNegativeVerification = "CONTRADICTED"
)

// PackageUsageResult reports the bounded product-source usage verdict for
// one advisory-declared package (Symbol == "") or symbol.
type PackageUsageResult struct {
	Module  string `json:"module"`
	Package string `json:"package"`
	Symbol  string `json:"symbol,omitempty"`
	// Present reports whether the target package sits inside the linked
	// import closure of the current build context (transitively counts;
	// it says nothing about product use).
	Present bool              `json:"present"`
	Usage   PackageUsageState `json:"usage"`
	// ProductSites are concrete non-test product references (calls, value
	// uses, method/field selections) to the subject or its package.
	ProductSites []domain.CallSite `json:"product_sites"`
	// ImportSites are direct import specs of the target package in
	// product source, blank imports included.
	ImportSites          []domain.CallSite                `json:"import_sites"`
	NegativeVerification PackageUsageNegativeVerification `json:"negative_verification,omitempty"`
	CheckScope           string                           `json:"check_scope,omitempty"`
	Limitations          []string                         `json:"limitations"`
}

// ProductUsage performs a bounded static check of one advisory-declared
// package or symbol against the product source closure under the current
// GOOS/GOARCH/build tags. It returns:
//
//   - USED — a concrete product-source import, reference or call exists;
//   - NOT_USED — every condition of a closed negative verification
//     passed (see below);
//   - UNKNOWN — the check scope is incomplete, the subject cannot be
//     resolved, or a dynamic/dispatch escape is unclosed.
//
// A negative result is VERIFIED only through one of two closed bases.
//
// Linked-package basis (package and symbol subjects): the target
// package is present in the linked import closure; for a symbol
// subject its declaration resolves inside the loaded dependency
// package; every loaded product package was scanned; no product
// package that failed type-checking could hide a reference or opaque
// path to the target, regardless of its recovered imports; the package-load
// budget was not exhausted; no direct
// import/reference/call, build-gated reference, unresolved
// interface-dispatch candidate, function-value dispatch candidate or
// relevant dynamic marker exists; and the check completed without
// error.
//
// Absence basis (package subjects only): the product closure is
// complete — every product package loaded and type-checked, the
// package-load budget unexhausted — and the target package is absent
// from the linked import closure. Provable absence inside a complete
// closure is positive evidence: nothing in the product's linked source
// can import, reference or dispatch to the package. The remaining
// scope gates (build-gated references, relevant dynamic markers) still
// apply unchanged. A symbol subject never verifies on absence alone —
// the symbol-level contract keeps the linked-package premise plus a
// resolved declaration.
//
// Any open gap yields UNKNOWN + INSUFFICIENT_SCOPE — an empty site
// list is never negative proof by itself.
//
// The fact is strictly bounded to product source static usage: it does
// not cover runtime behavior, reflection/plugin/generated loading,
// deployment exposure, or global advisory applicability, and NOT_USED is
// never a safe conclusion.
func (ix *Index) ProductUsage(ctx context.Context, module string,
	subject domain.SymbolRef) (PackageUsageResult, error) {

	res, _, err := ix.productUsage(ctx, module, subject)
	return res, err
}

// usageGapKind classifies a ProductUsage scope gap for the unreachability
// verifier: fatal gaps must fail closed (load/declaration/inventory
// failures); site gaps re-derive from typed evidence the verifier filters
// per-site (product references, dispatch candidates, gated references,
// dynamic markers); inventory gaps name skipped packages that hide
// references and are reclassified by the verifier's shipping-closure model.
type usageGapKind uint8

const (
	usageGapFatal usageGapKind = iota
	usageGapSites
	usageGapSkipped
	// usageGapAbsent marks the "not present in the linked import closure"
	// note: for an unreachability proof it is positive non-reach evidence,
	// not a scope gap, so the verifier drops it rather than blocking.
	usageGapAbsent
)

// usageGap is one recorded ProductUsage scope gap with the structured
// payload the reachability filter needs: the rendered limitation text,
// the kind, and — for skipped-importer gaps — the package paths so the
// verifier can reclassify them against the shipping closure instead of
// trusting the flat text.
type usageGap struct {
	text string
	kind usageGapKind
	pkgs []string
}

// productUsage is the internal inventory form of ProductUsage: the public
// result is identical, but alongside it the caller receives the gap list
// with kinds, so reachability-aware consumers can tell hard scope failures
// from site-derived evidence without parsing strings.
func (ix *Index) productUsage(ctx context.Context, module string,
	subject domain.SymbolRef) (PackageUsageResult, []usageGap, error) {

	res := PackageUsageResult{
		Module:  module,
		Package: subject.Package,
		Symbol:  subject.Symbol,
	}
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ctx); err != nil {
		return res, nil, err
	}
	if subject.Package == "" {
		res.Usage = PackageUsageUnknown
		res.NegativeVerification = PackageUsageNegativeInsufficientScope
		res.Limitations = append(res.Limitations,
			"advisory declares no package for this subject; package-level usage cannot be checked")
		res.Limitations = append(res.Limitations, usageBaselineLimitations(ix)...)
		return res, []usageGap{{text: res.Limitations[0]}}, nil
	}
	res.CheckScope = usageCheckScope(ix)

	var gaps []usageGap
	addGap := func(kind usageGapKind, pkgs []string, text string) {
		gaps = append(gaps, usageGap{text: text, kind: kind, pkgs: pkgs})
	}
	// Present reflects only the linked import closure of the current
	// build context — not the product's own source usage.
	res.Present = ix.linkedPaths()[subject.Package]

	pkgRef := domain.SymbolRef{Package: subject.Package, Symbol: subject.Symbol}
	var recvInstantiated bool
	var prodNarrow bool
	var targetPkg *packages.Package

	symbolSubject := subject.Symbol != ""
	if symbolSubject {
		// The dependency package must be loaded to resolve the subject's
		// declaration; a load failure is a scope gap, never NOT_USED.
		extra, err := ix.loadExtra(ctx, subject.Package)
		if err != nil {
			addGap(usageGapFatal, nil,
				fmt.Sprintf("dependency package %s could not be loaded: %v", subject.Package, err))
		} else {
			for _, p := range extra {
				if p.PkgPath == subject.Package && p.Types != nil {
					targetPkg = p
					break
				}
			}
			if targetPkg == nil {
				addGap(usageGapFatal, nil,
					fmt.Sprintf("dependency package %s did not load with type information", subject.Package))
			} else {
				typeName, name := splitSymbol(subject.Symbol)
				if findObjectInPkg(ix.fset, targetPkg, typeName, name) == nil {
					// An unresolvable declaration never becomes "not
					// used": the symbol may be generated, platform-gated
					// in the dep's own build tags, or advisory-misnamed.
					addGap(usageGapFatal, nil,
						fmt.Sprintf("symbol %s not declared in loaded %s", subject.Symbol, subject.Package))
				}
			}
		}
		// The shared receiver contract: provably uninstantiated returns
		// false only under a complete probe; an unresolvable receiver
		// counts as materialized so dispatch candidates and dynamic
		// markers stay open rather than silently narrow away.
		recvInstantiated = ix.receiverTypeInstantiated(ctx, pkgRef)
		prodNarrow, _, _ = ix.productNarrowingLocked()
	} else if res.Present {
		// Package-level: load the target to enumerate its method-bearing
		// types for the dispatch-gap check. The load happens only for a
		// linked package: an unlinked package can never be a dispatch
		// receiver, so neither its method inventory nor its loadability
		// is part of the scope — nothing is loaded for it.
		extra, err := ix.loadExtra(ctx, subject.Package)
		if err != nil {
			addGap(usageGapFatal, nil,
				fmt.Sprintf("dependency package %s could not be loaded: %v", subject.Package, err))
		} else {
			for _, p := range extra {
				if p.PkgPath == subject.Package && p.Types != nil {
					targetPkg = p
					break
				}
			}
			if targetPkg == nil {
				// The package is linked but its method-bearing types
				// could not be enumerated: interface-dispatch candidates
				// toward it are unaudited, so the gap is named, never
				// an empty dispatch list.
				addGap(usageGapFatal, nil,
					fmt.Sprintf("dependency package %s is linked but did not load with type information; interface-dispatch candidates toward it are unaudited", subject.Package))
			}
		}
		prodNarrow, _, _ = ix.productNarrowingLocked()
	}

	// Positive evidence: concrete product references. A package-level
	// subject is USED by any direct import — blank imports run init code.
	// For a symbol subject the import alone is not usage: the import sites
	// are still recorded (the package edge exists) but only a concrete
	// reference to the symbol itself proves USED.
	res.ImportSites = ix.directImportSites(subject.Package)
	if symbolSubject {
		res.ProductSites = ix.productRefsTo(pkgRef)
	} else {
		res.ProductSites = ix.productPkgRefs(subject.Package)
	}
	sortCallSites(res.ImportSites)
	sortCallSites(res.ProductSites)
	if len(res.ProductSites) > 0 || (!symbolSubject && len(res.ImportSites) > 0) {
		res.Usage = PackageUsageUsed
		res.Limitations = append(res.Limitations, usageBaselineLimitations(ix)...)
		return res, nil, nil
	}

	// Negative verification: every remaining escape route must be closed.
	// The product closure is complete when every product package loaded
	// and type-checked and the dependency load budget is unexhausted —
	// the canonical census SkippedPackages exposes plus the session-scoped
	// truncation record (a budget exhausted earlier in the session cut
	// dependency coverage; restoring the query budget does not restore
	// it). A failed package counts even when zero imports could be
	// recovered: its files are unseen product code.
	closureComplete := len(ix.skipped) == 0 && !ix.budgetTruncatedLocked()

	// A package-level subject absent from a complete linked closure is
	// positive evidence of non-use, not a gap: no product source can
	// import, reference or dispatch to a package outside its link set.
	// For an incomplete closure absence stays a gap — the target may be
	// linked only through a failed package. Symbol subjects keep the
	// linked-package premise: absence never verifies their negative.
	if !res.Present && (symbolSubject || !closureComplete) {
		addGap(usageGapAbsent, nil, usageAbsenceGap)
	}
	for _, d := range ix.skipped {
		// A skipped package outside the typed scan can hide an opaque path
		// to a linked target even when recovered imports exclude it. For
		// absent targets the existing closure-absence gap already applies.
		importsTarget := slices.Contains(d.Imports, subject.Package)
		switch {
		case importsTarget:
			addGap(usageGapSkipped, []string{d.Path}, fmt.Sprintf(
				"product package %s imports %s but failed to type-check (%s); its references are invisible — resolve the reported build failure and re-run so the package loads",
				d.Path, subject.Package, d.firstError()))
		case !d.SourceVisible:
			addGap(usageGapFatal, nil, fmt.Sprintf(
				"product package %s failed to load with unrecoverable source (%s); its references are invisible — resolve the reported build failure and re-run so the package loads",
				d.Path, d.firstError()))
		case !d.ImportsComplete:
			addGap(usageGapSkipped, []string{d.Path}, fmt.Sprintf(
				"product package %s failed to type-check and its import set could not be fully recovered (%s); it may hide references to %s — resolve the reported build failure and re-run so the package loads",
				d.Path, d.firstError(), subject.Package))
		case res.Present:
			addGap(usageGapSkipped, []string{d.Path}, fmt.Sprintf(
				"product package %s failed to type-check (%s); its untyped source may reach %s through opaque dispatch despite recovered imports excluding it — resolve the reported build failure and re-run so the package loads",
				d.Path, d.firstError(), subject.Package))
		}
	}
	for _, name := range ix.sessionTruncations {
		addGap(usageGapFatal, nil, name+"; dependency package coverage is truncated")
	}
	if ix.loadBudgetExhausted && len(ix.sessionTruncations) == 0 {
		addGap(usageGapFatal, nil, truncationPackageLoad+"; dependency package coverage is truncated")
	}

	// Build-gated files: for a package subject, any gated import spec is
	// an open alternate-build edge; for a symbol subject only a gated
	// *reference* to the symbol itself counts — an unrelated gated import
	// of its package says nothing about the symbol.
	var gatedImports []domain.CallSite
	var gatedParseMisses []string
	var gatedRefs []domain.CallSite
	if symbolSubject {
		gatedRefs = ix.gatedRefs(pkgRef)
	} else {
		gatedImports, gatedParseMisses = ix.gatedImportSites(subject.Package)
	}
	if len(gatedImports) > 0 || len(gatedRefs) > 0 {
		addGap(usageGapSites, nil, fmt.Sprintf(
			"%d reference(s)/import(s) of %s in files excluded by the current build tags — an alternate build may use it",
			len(gatedImports)+len(gatedRefs), subject.Package))
	}
	for _, miss := range gatedParseMisses {
		addGap(usageGapFatal, nil, "build-gated file "+miss+" could not be parsed; its imports are unknown")
	}

	// Interface-dispatch candidates. A dispatch site can invoke a method
	// only of a package inside the linked closure, so the check runs
	// exclusively when the target is linked: for an unlinked package no
	// product type can be the dynamic receiver and no candidate exists.
	var dispatchSites []domain.CallSite
	if symbolSubject {
		if res.Present {
			var err error
			var recvOpen bool
			dispatchSites, recvOpen, err = ix.interfaceDispatchSites(ctx, pkgRef)
			switch {
			case err != nil:
				addGap(usageGapFatal, nil, "interface dispatch scan failed: "+err.Error())
			case len(dispatchSites) > 0 && recvOpen:
				addGap(usageGapSites, nil, fmt.Sprintf(
					"%d interface-dispatched call site(s) match the method name of %s.%s — its receiver type could not be resolved, so the candidate set stays open",
					len(dispatchSites), subject.Package, subject.Symbol))
			case len(dispatchSites) > 0 && (recvInstantiated || !prodNarrow):
				addGap(usageGapSites, nil, fmt.Sprintf(
					"%d interface-dispatched call site(s) may invoke %s.%s — the dynamic receiver is unresolved",
					len(dispatchSites), subject.Package, subject.Symbol))
			}
		}
	} else if targetPkg != nil {
		dispatchSites = ix.pkgDispatchGaps(targetPkg, prodNarrow)
		if len(dispatchSites) > 0 {
			addGap(usageGapSites, nil, fmt.Sprintf(
				"%d interface-dispatched call site(s) may invoke a method of package %s — the dynamic receiver is unresolved",
				len(dispatchSites), subject.Package))
		}
	}

	// Function-value dispatch candidates: a product call through a
	// func-typed variable whose candidate set contains (or may contain)
	// the symbol invokes it out of sight of the reference scan. Sites
	// whose targets resolve keep the negative open — the dispatch exists
	// even though the symbol is never named; an open enumeration is a
	// coverage gap even with no compatible site.
	if symbolSubject && res.Present {
		fvSites, fvOpen := ix.funcValueCallSites(ix.pkgs, pkgRef, ix.funcSigOfRef(pkgRef))
		switch {
		case len(fvSites) > 0:
			addGap(usageGapSites, nil, fmt.Sprintf(
				"%d function-value call site(s) may invoke %s.%s — the dynamic callee is unresolved or reaches the symbol indirectly",
				len(fvSites), subject.Package, subject.Symbol))
		case fvOpen:
			addGap(usageGapSites, nil,
				"function-value call enumeration is open; indirect product callers of "+subject.Package+"."+subject.Symbol+" are not enumerable")
		}
	}

	// Dynamic markers relevant to invoking the subject or its package.
	for _, m := range relevantUsageMarkers(ix.scanDynamic(pkgRef), pkgRef, recvInstantiated, prodNarrow) {
		addGap(usageGapSites, nil, fmt.Sprintf(
			"dynamic escape %s at %s:%d may reach the subject: %s", m.Kind, m.File, m.Line, m.Detail))
	}

	res.Limitations = append(res.Limitations, usageBaselineLimitations(ix)...)
	for _, g := range gaps {
		res.Limitations = append(res.Limitations, g.text)
	}
	if len(gaps) > 0 || !closureComplete {
		res.Usage = PackageUsageUnknown
		res.NegativeVerification = PackageUsageNegativeInsufficientScope
		return res, gaps, nil
	}
	res.Usage = PackageUsageNotUsed
	res.NegativeVerification = PackageUsageNegativeVerified
	return res, gaps, nil
}

// usageCheckScope names the bounded scope a usage verdict applies to.
func usageCheckScope(ix *Index) string {
	goos, goarch := ix.Build.GOOS, ix.Build.GOARCH
	if goos == "" {
		goos = runtime.GOOS
	}
	if goarch == "" {
		goarch = runtime.GOARCH
	}
	scope := fmt.Sprintf("product source packages under %s loaded for GOOS=%s GOARCH=%s",
		ix.Dir, goos, goarch)
	if len(ix.Build.BuildTags) > 0 {
		scope += " with build tags " + strings.Join(ix.Build.BuildTags, ",")
	}
	scope += "; non-test files only; dependency internals and deployment scope excluded"
	return scope
}

// usageBaselineLimitations records the honesty bounds every usage verdict
// carries — the fact is a static product-source observation, nothing more.
func usageBaselineLimitations(ix *Index) []string {
	out := []string{
		"verdict covers static product-source usage only, under the recorded build context (GOOS/GOARCH/build tags)",
		"files excluded by the current build constraints are scanned syntactically for imports/references but their code is not typed",
		"runtime behavior, reflection/plugin/generated loading, deployment and runtime exposure are not checked",
		"a negative result is never a safe conclusion and never proves global advisory non-applicability",
	}
	return out
}

// UsageScopeGaps splits a ProductUsage limitation list into the
// case-specific scope gaps that produced the verdict — everything that
// is not one of the fixed baseline bounds recorded by
// usageBaselineLimitations. The baseline bounds are always-present
// interpretation caveats (static-scope only, no runtime/deployment
// coverage); they ride in the payload so the record stays honest, but
// they are never what made one case UNKNOWN. Consumers that surface
// "why is this open" — fact text, report unknowns — must count and name
// only the specific gaps, exactly the split VerifyUnreachable applies
// through usageSpecificGaps.
func UsageScopeGaps(lims []string) []string {
	baseline := map[string]bool{}
	for _, b := range usageBaselineLimitations(nil) {
		baseline[b] = true
	}
	var out []string
	for _, l := range lims {
		if baseline[l] {
			continue
		}
		out = append(out, l)
	}
	return out
}

// directImportSites returns product import specs naming targetPkg —
// normal, blank and dot imports all count as a direct product-source
// edge. Test files are excluded: they are not product source.
func (ix *Index) directImportSites(targetPkg string) []domain.CallSite {
	var out []domain.CallSite
	for _, pkg := range ix.pkgs {
		for _, f := range pkg.Syntax {
			if ix.isTestFile(f) {
				continue
			}
			for _, imp := range f.Imports {
				if strings.Trim(imp.Path.Value, `"`) != targetPkg {
					continue
				}
				pos := ix.fset.Position(imp.Pos())
				out = append(out, domain.CallSite{
					File:    pos.Filename,
					Line:    pos.Line,
					Column:  pos.Column,
					Package: pkg.PkgPath,
				})
			}
		}
	}
	return out
}

// productPkgRefs returns product reference sites (non-test files) that
// bind any object declared in targetPkg — qualified names, method/field
// selections on the package's types, composite-literal keys and call
// targets. It is the package-level analogue of productRefsTo.
func (ix *Index) productPkgRefs(targetPkg string) []domain.CallSite {
	var out []domain.CallSite
	for _, pkg := range ix.pkgs {
		info := pkg.TypesInfo
		if info == nil {
			continue
		}
		for _, f := range pkg.Syntax {
			if ix.isTestFile(f) {
				continue
			}
			inspectDecls(f, func(n ast.Node, enc *ast.FuncDecl) bool {
				var obj types.Object
				switch e := n.(type) {
				case *ast.Ident:
					obj = info.ObjectOf(e)
				case *ast.SelectorExpr:
					if seln, ok := info.Selections[e]; ok {
						obj = seln.Obj()
					}
				case *ast.CallExpr:
					obj = calleeObject(info, e.Fun)
				}
				if obj == nil || obj.Pkg() == nil || obj.Pkg().Path() != targetPkg {
					return true
				}
				pos := ix.fset.Position(n.Pos())
				cs := domain.CallSite{
					File:    pos.Filename,
					Line:    pos.Line,
					Column:  pos.Column,
					Package: pkg.PkgPath,
				}
				if enc != nil && enc.Name != nil {
					cs.Function = enc.Name.Name
				}
				out = append(out, cs)
				return true
			})
		}
	}
	return out
}

// gatedImportSites scans files excluded by the current build constraints
// (IgnoredFiles, minus tests) for import specs naming targetPkg. Parse
// failures are returned as file paths — an unparsable gated file is an
// unclosed scope, not a miss.
func (ix *Index) gatedImportSites(targetPkg string) (sites []domain.CallSite, parseMisses []string) {
	seen := map[string]bool{}
	for _, pkg := range ix.pkgs {
		for _, path := range pkg.IgnoredFiles {
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || seen[path] {
				continue
			}
			seen[path] = true
			f, err := parser.ParseFile(ix.fset, path, nil, parser.ImportsOnly)
			if err != nil {
				parseMisses = append(parseMisses, path)
				continue
			}
			for _, imp := range f.Imports {
				if strings.Trim(imp.Path.Value, `"`) != targetPkg {
					continue
				}
				pos := ix.fset.Position(imp.Pos())
				sites = append(sites, domain.CallSite{
					File:    pos.Filename,
					Line:    pos.Line,
					Column:  pos.Column,
					Package: pkg.PkgPath,
				})
			}
		}
	}
	return sites, parseMisses
}

// pkgDispatchGaps returns product call sites dispatching through an
// interface method that a method-bearing type declared in targetPkg
// could implement. Instantiation narrowing applies the same rule the
// verifier uses: a dep type never created in product-visible code cannot
// be the dynamic receiver — unless dynamic materialization disabled
// narrowing, in which case every same-named dispatch stays open.
func (ix *Index) pkgDispatchGaps(targetPkg *packages.Package, prodNarrow bool) []domain.CallSite {
	if targetPkg == nil || targetPkg.Types == nil {
		return nil
	}
	inst, _ := ix.productInstantiated()
	// methodNames of the target package's method-bearing named types,
	// keyed by method name for the cheap pre-filter.
	methods := map[string]bool{}
	for _, name := range targetPkg.Types.Scope().Names() {
		tn, ok := targetPkg.Types.Scope().Lookup(name).(*types.TypeName)
		if !ok {
			continue
		}
		named := mustNamed(tn)
		if named == nil {
			continue
		}
		ms := types.NewMethodSet(types.NewPointer(named))
		for i := range ms.Len() {
			methods[ms.At(i).Obj().Name()] = true
		}
	}
	if len(methods) == 0 {
		return nil
	}
	var out []domain.CallSite
	for _, pkg := range ix.pkgs {
		info := pkg.TypesInfo
		if info == nil {
			continue
		}
		for _, f := range pkg.Syntax {
			if ix.isTestFile(f) {
				continue
			}
			inspectDecls(f, func(n ast.Node, enc *ast.FuncDecl) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				seln, ok := info.Selections[sel]
				if !ok || seln.Kind() != types.MethodVal || !methods[seln.Obj().Name()] {
					return true
				}
				if _, ok := seln.Recv().Underlying().(*types.Interface); !ok {
					return true
				}
				// The dispatch is an open gap when a candidate impl type
				// could be the receiver: either product instantiation is
				// visible for some method-bearing target type, or dynamic
				// materialization disabled narrowing entirely.
				if prodNarrow && !ix.pkgTypeProductInstantiated(targetPkg, seln.Obj().Name(), seln.Recv(), inst) {
					return true
				}
				pos := ix.fset.Position(sel.Pos())
				cs := domain.CallSite{
					File:    pos.Filename,
					Line:    pos.Line,
					Column:  pos.Column,
					Package: pkg.PkgPath,
				}
				if enc != nil && enc.Name != nil {
					cs.Function = enc.Name.Name
				}
				out = append(out, cs)
				return true
			})
		}
	}
	return out
}

// pkgTypeProductInstantiated reports whether any named type in targetPkg
// both implements the dispatched interface method and is instantiated in
// product code.
func (ix *Index) pkgTypeProductInstantiated(targetPkg *packages.Package,
	method string, recv types.Type, inst map[string]bool) bool {
	iface, _ := recv.Underlying().(*types.Interface)
	for _, name := range targetPkg.Types.Scope().Names() {
		tn, ok := targetPkg.Types.Scope().Lookup(name).(*types.TypeName)
		if !ok {
			continue
		}
		named := mustNamed(tn)
		if named == nil || !inst[namedKey(named)] {
			continue
		}
		if iface != nil && !types.Implements(types.NewPointer(named), iface) {
			continue
		}
		ms := types.NewMethodSet(types.NewPointer(named))
		for i := range ms.Len() {
			if ms.At(i).Obj().Name() == method {
				return true
			}
		}
	}
	return false
}

// relevantUsageMarkers filters ScanDynamic output to markers that can
// invoke the subject or members of its package out of sight of the typed
// reference scan — mirroring the verifier's invocation-relevant set.
// Write-oriented markers (unsafe_write, unsafe_ptr, reflect_write) and
// bare imports cannot widen the call graph and never count here.
func relevantUsageMarkers(markers []DynamicMarker, ref domain.SymbolRef,
	recvInstantiated, prodNarrow bool) []DynamicMarker {
	var out []DynamicMarker
	for _, m := range markers {
		if usageMarkerRelevant(m, ref, recvInstantiated, prodNarrow) {
			out = append(out, m)
		}
	}
	return out
}

// usageMarkerRelevant is the per-marker kernel rule shared by
// relevantUsageMarkers, VerifyUnreachable and ScanRelevantDynamic: it
// reports whether one ScanDynamic marker could plausibly invoke ref out
// of sight of the typed reference scan. It decides relevance only —
// callers classify unknown kinds, site liveness and absence semantics.
func usageMarkerRelevant(m DynamicMarker, ref domain.SymbolRef,
	recvInstantiated, prodNarrow bool) bool {
	_, name := splitSymbol(ref.Symbol)
	switch m.Kind {
	case "func_value":
		// The subject escaped into a func value — an indirect
		// invocation path the static scan may miss.
		return true
	case "linkname":
		return strings.Contains(m.Detail, ref.Package) || linknameNames(m.Detail, ref)
	case "reflect_method":
		// MethodByName/Method can invoke only exported methods of
		// instantiated receiver types; standalone functions and
		// never-materialized receivers stay irrelevant.
		if !symbolIsMethod(ref) || !ast.IsExported(name) {
			return false
		}
		if !recvInstantiated && prodNarrow {
			return false
		}
		return true
	case "plugin":
		// plugin.Lookup can bind any exported symbol; for a
		// package-level subject any exported member suffices.
		return ref.Symbol == "" || ast.IsExported(name)
	}
	return false
}

// sortCallSites orders sites by package/file/line/column for a
// byte-stable serialized result.
func sortCallSites(sites []domain.CallSite) {
	sort.SliceStable(sites, func(i, j int) bool {
		a, b := sites[i], sites[j]
		if a.Package != b.Package {
			return a.Package < b.Package
		}
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Column != b.Column {
			return a.Column < b.Column
		}
		return a.Function < b.Function
	})
}

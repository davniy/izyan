package goanalysis

// This file carries the exploit-locus binder's source primitive:
// ProveTriggerPath proves — through typed call graphs only — that the
// product sink's trigger argument reaches the proposed vulnerable
// implementation, and enumerates the product-facing trigger carriers
// (every dependency function position that can carry the trigger toward
// the locus). The model is a mark-propagation over a position graph:
// positions are (function, parameter-index) slots plus receiver state
// (-1) and struct field slots; edges come from typed argument binding,
// field stores, return-value carry and closed interface dispatch.
// Unresolved callees, function-value escapes and reflection never
// propagate marks — they are recorded escapes/blockers so the
// enumeration stays closed or fails, never guessed.
//
// Backward reachability from the locus's carrier positions computes the
// carrier set. Every live product call site feeding a carrier position
// is then a bound-sink candidate; a mixed argument index or an
// unresolved candidate is a blocker, exactly as the binder contract
// requires.

import (
	"context"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"sort"
	"strings"

	"github.com/davniy/izyan/internal/affected"
	"github.com/davniy/izyan/internal/domain"
	"golang.org/x/tools/go/packages"
)

// maxTriggerFunctions bounds the dependency-function inventory one
// trigger-path proof analyzes. An inventory above the bound fails
// closed instead of being enumerated partially.
const maxTriggerFunctions = 60000

// maxTriggerRounds bounds the return-carry fixpoint rounds.
const maxTriggerRounds = 6

// fnKey identifies one function by package and declaration symbol —
// stable across the two analysis passes so facts and edges reconcile.
type fnKey string

// posKey identifies one graph node: "fnkey|param|N" for parameter N
// (-1 is the receiver slot), "field|pkg.T.f" for a field slot, and
// "var|pkg.x" for a package-variable slot.
type posKey string

// retEntry is one source token a function's result slot carries: either
// a parameter index (receiver -1) or a field/var slot the result's
// object state may contain.
type retEntry struct {
	param int // -1 receiver, -2 = field slot
	field posKey
}

// fnFacts is the per-function analysis record: typed call edges out of
// the body, the result-carry token set per result index, and recorded
// escapes to unresolvable callees.
type fnFacts struct {
	decl *ast.FuncDecl
	pkg  *packages.Package
	// edges: source node -> destination node. Sources are param/receiver
	// positions of this function, field/var slots, or result slots of
	// called functions (expanded through retEntry substitution).
	edges   []posEdge
	retSrcs map[int][]retEntry // result index -> source tokens
	escapes []string           // typed call sites that escape analysis
	open    []string           // unresolved callee/dispatch sites (weak)
}

// posEdge is one propagation edge with its provenance.
type posEdge struct {
	from posKey
	to   posKey
	hop  string // human-readable hop detail for relation evidence
	site *domain.CallSite
}

// fnDeclOf locates the *types.Func object and its declaration for a
// symbol inside the loaded scope.
type fnDeclOf struct {
	obj  *types.Func
	decl *ast.FuncDecl
	pkg  *packages.Package
}

// symbolKey renders a typed function object as "pkgpath.Recv.Name".
func funcKeyOf(fn *types.Func) fnKey {
	pkgPath := ""
	if fn.Pkg() != nil {
		pkgPath = fn.Pkg().Path()
	}
	name := fn.Name()
	if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
		name = recvTypeName(sig.Recv().Type()) + "." + name
	}
	return fnKey(pkgPath + "." + name)
}

// fieldNodeKey renders a struct field object as its graph node id.
func fieldNodeKey(v *types.Var) posKey {
	if v == nil {
		return ""
	}
	owner := ""
	if v.Pkg() != nil {
		owner = v.Pkg().Path()
	}
	// Fields are named "T.f"; the declaring type is recoverable from the
	// field's own id via the enclosing scope — the analysis records the
	// qualified name it was created with, so the object identity is the
	// sole key: pointer equality would work inside one pass, but the
	// key must be stable across both passes.
	return posKey("field|" + owner + "." + v.Name() + "|" + v.Id())
}

// varNodeKey renders a package-level variable's slot node.
func varNodeKey(v *types.Var) posKey {
	owner := ""
	if v.Pkg() != nil {
		owner = v.Pkg().Path()
	}
	return posKey("var|" + owner + "." + v.Name() + "|" + v.Id())
}

// paramNodeKey renders (function, param index) — -1 receiver.
func paramNodeKey(k fnKey, idx int) posKey {
	return posKey(fmt.Sprintf("fn|%s|%d", string(k), idx))
}

// ProveTriggerPath runs the deterministic trigger-carrier proof.
func (ix *Index) ProveTriggerPath(ctx context.Context, req affected.TriggerPathRequest) (affected.TriggerPathResult, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	ctx = ix.ctxOr(ctx)
	res := affected.TriggerPathResult{Trigger: req.Trigger}
	if err := ix.load(ctx); err != nil {
		return res, err
	}
	e := &triggerEngine{
		ix:           ix,
		req:          req,
		res:          &res,
		fnDecls:      map[fnKey]*fnDeclOf{},
		facts:        map[fnKey]*fnFacts{},
		retMemo:      map[fnKey]map[int][]retEntry{},
		blocked:      map[string]bool{},
		wholeKeys:    map[types.Type]posKey{},
		analyzing:    map[fnKey]bool{},
		scopeModules: map[string]bool{},
	}
	e.run(ctx)
	return res, nil
}

// SymbolSignature resolves the sink symbol's call signature from the
// package's typed declaration: the parameter names in order ("" for
// unnamed parameters), the variadic flag and the method flag. Any load
// or resolution failure is an error — the binder fails closed on it.
func (ix *Index) SymbolSignature(ctx context.Context, ref domain.SymbolRef) (affected.SymbolSignature, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	cs, err := ix.findSymbol(ix.ctxOr(ctx), ref)
	if err != nil {
		return affected.SymbolSignature{}, err
	}
	fn := ix.funcObjectAt(cs, ref)
	if fn == nil {
		return affected.SymbolSignature{}, fmt.Errorf("symbol %s.%s does not resolve to a function object", ref.Package, ref.Symbol)
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok {
		return affected.SymbolSignature{}, fmt.Errorf("symbol %s.%s has no function signature", ref.Package, ref.Symbol)
	}
	out := affected.SymbolSignature{
		Variadic: sig.Variadic(),
		Method:   sig.Recv() != nil,
	}
	params := sig.Params()
	for i := range params.Len() {
		out.Params = append(out.Params, params.At(i).Name())
	}
	return out, nil
}

// funcObjectAt resolves the *types.Func object at a previously located
// declaration site.
func (ix *Index) funcObjectAt(cs *domain.CallSite, ref domain.SymbolRef) *types.Func {
	typeName, name := splitSymbol(ref.Symbol)
	for _, pkg := range append(ix.pkgs, ix.allExtras()...) {
		if pkg.PkgPath != ref.Package || pkg.Types == nil {
			continue
		}
		if typeName == "" {
			if obj, ok := pkg.Types.Scope().Lookup(name).(*types.Func); ok {
				return obj
			}
			continue
		}
		if tn, ok := pkg.Types.Scope().Lookup(typeName).(*types.TypeName); ok {
			if named, ok := tn.Type().(*types.Named); ok {
				for i := range named.NumMethods() {
					if m := named.Method(i); m.Name() == name {
						return m
					}
				}
			}
		}
	}
	return nil
}

type triggerEngine struct {
	ix  *Index
	req affected.TriggerPathRequest
	res *affected.TriggerPathResult

	fnDecls map[fnKey]*fnDeclOf
	facts   map[fnKey]*fnFacts
	retMemo map[fnKey]map[int][]retEntry
	blocked map[string]bool

	marked    map[posKey]bool
	markFrom  map[posKey]posEdge
	carrierAt map[fnKey]map[int]bool
	weakEdge  map[posKey]bool

	// typeEdges are the static object-state edges (whole-struct slot to
	// each field and back), stable for the loaded scope; they make a
	// struct value's fields reachable from the object's parameter/state
	// slot without inventing pointer aliasing.
	typeEdges []posEdge
	// wholeKeys caches the canonical whole-struct slot per types.Type.
	wholeKeys map[types.Type]posKey
	// analyzing guards the lazy callee analysis against recursion.
	analyzing map[fnKey]bool
	// scopeModules records the dependency modules whose packages were
	// loaded for this proof: a carrier callee inside one of them without
	// an analyzed body is a coverage blocker, never a silent stop.
	scopeModules map[string]bool
}

// run executes the proof: index the loaded scope, fixpoint the
// return-carry relation, backward-propagate carrier marks from the
// locus, then enumerate product-facing carrier sites.
func (e *triggerEngine) run(ctx context.Context) {
	e.loadScope(ctx)
	e.indexFunctions()
	if len(e.fnDecls) > maxTriggerFunctions {
		e.res.Blockers = append(e.res.Blockers, fmt.Sprintf(
			"dependency-function inventory %d exceeds the bound %d — the carrier enumeration cannot be enumerated partially",
			len(e.fnDecls), maxTriggerFunctions))
		return
	}
	e.fixpointReturns(ctx)
	e.propagate()
	e.relation()
	e.enumerateSites()
	e.res.Complete = len(e.res.Blockers) == 0
}

// loadScope loads the vulnerable and sink modules plus the dependency
// modules reachable from the product's direct call surface.
func (e *triggerEngine) loadScope(ctx context.Context) {
	need := map[string]bool{}
	for m := range e.req.Modules {
		need[m] = true
	}
	defer func() {
		for m := range need {
			if m != "" {
				e.scopeModules[m] = true
			}
		}
	}()
	// The vulnerable and sink modules are always in scope.
	for range 4 {
		loaded := map[string]bool{}
		for m := range need {
			if m == "" || loaded[m] {
				continue
			}
			if _, err := e.ix.loadExtra(ctx, m+"/..."); err != nil {
				if ctx.Err() != nil {
					e.res.Blockers = append(e.res.Blockers, "closure query deadline exceeded: "+ctx.Err().Error())
					return
				}
				e.res.Blockers = append(e.res.Blockers,
					fmt.Sprintf("dependency module %s failed to load: %v", m, err))
				continue
			}
			loaded[m] = true
		}
		// A dependency package in scope may itself call into another
		// module whose functions could be carriers (e.g. an LRU cache
		// module between the sink and the locus). Pull in every module
		// that an already-scoped dep package imports directly, until the
		// cone closes.
		next := map[string]bool{}
		for _, pkg := range e.depScope() {
			for path, imp := range pkg.Imports {
				if imp == nil || imp.Module == nil || e.ix.isProductPath(path) {
					continue
				}
				mod := imp.Module.Path
				if !need[mod] && !loaded[mod] && mod != "" && e.ix.pkgLinked(imp) {
					next[mod] = true
				}
			}
		}
		if len(next) == 0 {
			break
		}
		for m := range next {
			need[m] = true
		}
	}
	for _, name := range e.ix.sessionTruncations {
		e.res.Blockers = append(e.res.Blockers, name+" — dependency coverage is truncated")
	}
	if e.ix.loadBudgetExhausted && len(e.ix.sessionTruncations) == 0 {
		e.res.Blockers = append(e.res.Blockers, truncationPackageLoad+" — dependency coverage is truncated")
	}
}

// depScope is every loaded non-product package.
func (e *triggerEngine) depScope() []*packages.Package {
	var out []*packages.Package
	for _, p := range e.ix.allExtras() {
		if p.Types != nil && !e.ix.isProductPath(p.PkgPath) {
			out = append(out, p)
		}
	}
	return out
}

// indexFunctions builds the function inventory across the loaded
// dependency scope (product functions are enumerated separately at the
// boundary pass).
func (e *triggerEngine) indexFunctions() {
	for _, pkg := range e.depScope() {
		for _, f := range pkg.Syntax {
			if e.ix.isTestFile(f) {
				continue
			}
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Name == nil || fd.Body == nil {
					continue
				}
				obj := declFuncObject(pkg, fd)
				if obj == nil {
					continue
				}
				k := funcKeyOf(obj)
				e.fnDecls[k] = &fnDeclOf{obj: obj, decl: fd, pkg: pkg}
			}
		}
	}
	e.collectTypeEdges()
}

// collectTypeEdges builds the static object-state edges for every struct
// type the loaded dependency scope uses: the whole-struct slot flows to
// each field and each field back to the whole. A struct value passed as
// an argument therefore carries its state into the callee's field reads
// without pretending to model pointer aliasing — the over-approximation
// only adds carrier candidates, never removes them.
func (e *triggerEngine) collectTypeEdges() {
	seen := map[posKey]bool{}
	addStruct := func(t types.Type) {
		whole := e.wholeKey(t)
		if whole == "" || seen[whole] {
			return
		}
		seen[whole] = true
		st := structOf(t)
		if st == nil {
			return
		}
		for i := range st.NumFields() {
			fk := fieldNodeKey(st.Field(i))
			if fk == "" {
				continue
			}
			e.typeEdges = append(e.typeEdges,
				posEdge{from: whole, to: fk, hop: "object state field " + st.Field(i).Name()},
				posEdge{from: fk, to: whole, hop: "object state of " + st.Field(i).Name()})
		}
	}
	for _, pkg := range e.depScope() {
		if pkg.Types == nil {
			continue
		}
		if pkg.TypesInfo != nil {
			for _, tv := range pkg.TypesInfo.Types {
				addStruct(tv.Type)
			}
		}
		for _, name := range pkg.Types.Scope().Names() {
			addStruct(pkg.Types.Scope().Lookup(name).Type())
		}
	}
}

// wholeKey renders a struct type's whole-object slot; named and
// anonymous types structural-equal to one struct share the slot.
func (e *triggerEngine) wholeKey(t types.Type) posKey {
	if t == nil {
		return ""
	}
	if k, ok := e.wholeKeys[t]; ok {
		return k
	}
	st := structOf(t)
	key := posKey("")
	if st != nil {
		key = posKey("field|" + types.TypeString(st, nil) + ".whole")
	}
	e.wholeKeys[t] = key
	return key
}

// structOf dereferences pointers and named types to a struct type.
func structOf(t types.Type) *types.Struct {
	for {
		switch x := t.(type) {
		case *types.Pointer:
			t = x.Elem()
		case *types.Named:
			t = x.Underlying()
		case *types.Struct:
			return x
		default:
			return nil
		}
	}
}

// fixpointReturns iterates the per-function analysis until every
// function's result-carry token set is stable. Round 0 analyzes each
// function with an empty global return table; later rounds re-analyze
// functions whose callees' tables changed.
func (e *triggerEngine) fixpointReturns(ctx context.Context) {
	for round := 0; round < maxTriggerRounds; round++ {
		if ctx.Err() != nil {
			e.res.Blockers = append(e.res.Blockers, "trigger-path analysis deadline: "+ctx.Err().Error())
			return
		}
		changed := false
		for k, fd := range e.fnDecls {
			if _, done := e.facts[k]; done && !e.dependsOnChanged(k, round) {
				continue
			}
			f := e.analyze(fd, round)
			old := e.retMemo[k]
			e.facts[k] = f
			e.retMemo[k] = f.retSrcs
			if !retMapEq(old, f.retSrcs) {
				changed = true
			}
		}
		if !changed {
			return
		}
	}
	e.res.Blockers = append(e.res.Blockers,
		"return-carry fixpoint did not converge within the bound — the carrier enumeration stays open")
}

// dependsOnChanged conservatively re-analyzes every function on rounds
// after the first — the fixpoint bound keeps this finite and the
// result is deterministic.
func (e *triggerEngine) dependsOnChanged(_ fnKey, round int) bool {
	return round > 0
}

// retMapEq compares two result-carry tables.
func retMapEq(a, b map[int][]retEntry) bool {
	if len(a) != len(b) {
		return false
	}
	for i, ea := range a {
		eb, ok := b[i]
		if !ok || len(ea) != len(eb) {
			return false
		}
		set := map[retEntry]bool{}
		for _, x := range ea {
			set[x] = true
		}
		for _, x := range eb {
			if !set[x] {
				return false
			}
		}
	}
	return true
}

// analyze computes one function's local facts: param/receiver source
// tokens propagated through typed call edges, field stores, and the
// result-carry token set. It is deterministic given the global
// retMemo table.
func (e *triggerEngine) analyze(fd *fnDeclOf, _ int) *fnFacts {
	f := &fnFacts{decl: fd.decl, pkg: fd.pkg, retSrcs: map[int][]retEntry{}}
	info := fd.pkg.TypesInfo
	if info == nil || fd.decl.Body == nil {
		return f
	}
	selfKey := funcKeyOf(fd.obj)

	// Parameter/receiver identity for this function.
	sig, _ := fd.obj.Type().(*types.Signature)
	paramObj := map[types.Object]int{}
	if sig != nil {
		for i := range sig.Params().Len() {
			paramObj[sig.Params().At(i)] = i
		}
	}
	var recvObj types.Object
	if sig != nil && sig.Recv() != nil {
		recvObj = sig.Recv()
	}

	// varSrcs: sources flowing into a local/named-result variable.
	varSrcs := map[types.Object][]retEntry{}

	// objectState adds the whole-object slot of a struct-typed
	// expression: a struct value carries its fields' state, and the
	// static type edges connect that slot to every field.
	objectState := func(ex ast.Expr) []retEntry {
		t := info.TypeOf(ex)
		if whole := e.wholeKey(t); whole != "" {
			return []retEntry{{param: -2, field: whole}}
		}
		return nil
	}

	// srcsOf computes the source tokens an expression may carry.
	var srcsOf func(e ast.Expr, depth int) []retEntry
	srcsOf = func(ex ast.Expr, depth int) []retEntry {
		if ex == nil || depth > 24 {
			return nil
		}
		switch n := ex.(type) {
		case *ast.ParenExpr:
			return srcsOf(n.X, depth+1)
		case *ast.Ident:
			obj := info.ObjectOf(n)
			if obj == nil {
				return nil
			}
			var out []retEntry
			switch {
			case obj == recvObj:
				out = []retEntry{{param: -1}}
			default:
				if i, ok := paramObj[obj]; ok {
					out = []retEntry{{param: i}}
					break
				}
				if s, ok := varSrcs[obj]; ok {
					out = append(out, s...)
				}
				if v, ok := obj.(*types.Var); ok && !v.IsField() && v.Pkg() != nil {
					if v.Pkg().Scope().Lookup(v.Name()) == v {
						out = append(out, retEntry{param: -2, field: varNodeKey(v)})
					}
				}
			}
			return append(out, objectState(n)...)
		case *ast.SelectorExpr:
			if seln, ok := info.Selections[n]; ok && seln.Kind() == types.FieldVal {
				out := srcsOf(n.X, depth+1)
				if v, ok := seln.Obj().(*types.Var); ok {
					out = append(out, retEntry{param: -2, field: fieldNodeKey(v)})
				}
				return append(out, objectState(n)...)
			}
			// Method value/expression or qualified package member —
			// no payload sources.
			return nil
		case *ast.IndexExpr, *ast.SliceExpr:
			// Element content: the collection's own sources plus the
			// element slot. The container slot is shared per-type —
			// over-approximation toward more carriers, never fewer.
			var t types.Type
			var base ast.Expr
			switch n2 := n.(type) {
			case *ast.IndexExpr:
				t, base = info.TypeOf(n2.X), n2.X
			case *ast.SliceExpr:
				t, base = info.TypeOf(n2.X), n2.X
			}
			out := srcsOf(base, depth+1)
			if t != nil {
				out = append(out, retEntry{param: -2, field: posKey("field|" + t.String() + ".[]")})
			}
			return append(out, objectState(n)...)
		case *ast.CompositeLit:
			var out []retEntry
			for _, elt := range n.Elts {
				if kv, ok := elt.(*ast.KeyValueExpr); ok {
					out = append(out, srcsOf(kv.Value, depth+1)...)
					if id, ok := kv.Key.(*ast.Ident); ok {
						if v := fieldOfComposite(info, n, id); v != nil {
							out = append(out, retEntry{param: -2, field: fieldNodeKey(v)})
						}
					}
					continue
				}
				out = append(out, srcsOf(elt, depth+1)...)
			}
			return append(out, objectState(n)...)
		case *ast.UnaryExpr:
			if n.Op == token.AND || n.Op == token.MUL {
				return srcsOf(n.X, depth+1)
			}
			return nil
		case *ast.CallExpr:
			if b, ok := calleeObject(info, n.Fun).(*types.Builtin); ok {
				switch b.Name() {
				case "append", "copy":
					// Builtin results carry their arguments' sources:
					// append(xs, e) preserves both, and a slice store
					// must not silently drop the appended value.
					var out []retEntry
					for _, a := range n.Args {
						out = append(out, srcsOf(a, depth+1)...)
					}
					return append(out, objectState(n)...)
				}
				return nil
			}
			out := e.callResultSrcs(fd, n, selfKey, srcsOf, depth)
			return append(out, objectState(n)...)
		case *ast.TypeAssertExpr:
			return srcsOf(n.X, depth+1)
		case *ast.FuncLit:
			// A literal value carries no payload itself; its body's
			// stores/returns are analyzed inline below.
			return nil
		case *ast.BinaryExpr:
			return append(srcsOf(n.X, depth+1), srcsOf(n.Y, depth+1)...)
		}
		return nil
	}

	// Multi-pass over the body: assignments propagate varSrcs until
	// stable (loops); call edges and field stores are recorded once
	// each — set semantics make later passes idempotent.
	var walk func(ast.Node) bool
	walk = func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.AssignStmt:
			e.assign(fd, s, selfKey, srcsOf, varSrcs, f)
		case *ast.ReturnStmt:
			e.returnStmt(fd, s, sig, srcsOf, varSrcs, f)
		case *ast.CallExpr:
			e.callEdges(fd, s, selfKey, srcsOf, f)
		case *ast.FuncLit:
			// Literal bodies run inline: defers and invoked literals
			// share the parent's varSrcs scope so captured named
			// results bind correctly.
			for _, st := range s.Body.List {
				ast.Inspect(st, walk)
			}
			return false
		case *ast.RangeStmt:
			// x value binds the collection's element content.
			srcs := srcsOf(s.X, 0)
			if len(srcs) > 0 {
				for _, tgt := range []ast.Expr{s.Key, s.Value} {
					if id, ok := tgt.(*ast.Ident); ok {
						if obj := info.ObjectOf(id); obj != nil {
							varSrcs[obj] = appendUniqueEntries(varSrcs[obj], srcs...)
						}
					}
				}
			}
		case *ast.ValueSpec:
			// var x = expr / var x T: the declared variable carries the
			// value expression's sources.
			if len(s.Values) == len(s.Names) {
				for i, id := range s.Names {
					obj := info.ObjectOf(id)
					if obj == nil {
						continue
					}
					srcs := srcsOf(s.Values[i], 0)
					varSrcs[obj] = appendUniqueEntries(varSrcs[obj], srcs...)
				}
			} else if len(s.Values) == 1 && len(s.Names) > 1 {
				if c, ok := unparen(s.Values[0]).(*ast.CallExpr); ok {
					for i, id := range s.Names {
						obj := info.ObjectOf(id)
						if obj == nil {
							continue
						}
						srcs := e.callResultIndexSrcs(fd, c, i, selfKey, srcsOf)
						varSrcs[obj] = appendUniqueEntries(varSrcs[obj], srcs...)
					}
				}
			}
		}
		return true
	}
	for range 4 {
		ast.Inspect(fd.decl.Body, walk)
	}
	// Named-result propagation: a bare "return" yields the named
	// result variables' sources.
	if sig != nil && sig.Results() != nil {
		for i := range sig.Results().Len() {
			r := sig.Results().At(i)
			if s, ok := varSrcs[r]; ok {
				f.retSrcs[i] = appendUniqueEntries(f.retSrcs[i], s...)
			}
		}
	}
	return f
}

// assign records sources flowing to assignment targets: locals update
// varSrcs; selector/index/deref targets emit field-slot edges.
func (e *triggerEngine) assign(fd *fnDeclOf, s *ast.AssignStmt, selfKey fnKey,
	srcsOf func(ast.Expr, int) []retEntry, varSrcs map[types.Object][]retEntry, f *fnFacts) {
	// Evaluate right-hand sides first; a multi-value call's results are
	// spread positionally when the count matches.
	rhsSets := make([][]retEntry, len(s.Rhs))
	var callExpr *ast.CallExpr
	for i, r := range s.Rhs {
		rhsSets[i] = srcsOf(r, 0)
		if c, ok := unparen(r).(*ast.CallExpr); ok {
			callExpr = c
		}
	}
	if len(s.Rhs) == 1 && callExpr != nil && len(s.Lhs) > 1 {
		// x, y := G(...): result i feeds lhs i.
		for i, lhs := range s.Lhs {
			srcs := e.callResultIndexSrcs(fd, callExpr, i, selfKey, srcsOf)
			e.bindTarget(fd, lhs, srcs, selfKey, srcsOf, varSrcs, f, s)
		}
		return
	}
	for i, lhs := range s.Lhs {
		var srcs []retEntry
		if i < len(rhsSets) {
			srcs = rhsSets[i]
		}
		if s.Tok == token.ADD_ASSIGN || s.Tok == token.SUB_ASSIGN ||
			s.Tok == token.MUL_ASSIGN || s.Tok == token.QUO_ASSIGN ||
			s.Tok == token.REM_ASSIGN {
			// Compound op: the target keeps its prior sources too.
			srcs = append(srcs, e.targetSources(fd, lhs, srcsOf, varSrcs)...)
		}
		e.bindTarget(fd, lhs, srcs, selfKey, srcsOf, varSrcs, f, s)
	}
}

// bindTarget routes one target's sources: a bare identifier binds into
// varSrcs; a selector/index/deref emits a field-slot edge.
func (e *triggerEngine) bindTarget(fd *fnDeclOf, lhs ast.Expr, srcs []retEntry,
	selfKey fnKey, srcsOf func(ast.Expr, int) []retEntry,
	varSrcs map[types.Object][]retEntry, f *fnFacts, site ast.Node) {
	info := fd.pkg.TypesInfo
	switch t := lhs.(type) {
	case *ast.Ident:
		obj := info.ObjectOf(t)
		if obj == nil {
			return
		}
		if v, ok := obj.(*types.Var); ok && !isLocalVar(v) {
			for _, s := range srcs {
				f.edges = append(f.edges, posEdge{
					from: entryKey(selfKey, s), to: varNodeKey(v),
					hop: fmt.Sprintf("package var %s store", v.Name()), site: siteOf(site, e.ix),
				})
			}
			return
		}
		varSrcs[obj] = appendUniqueEntries(varSrcs[obj], srcs...)
	case *ast.SelectorExpr:
		if seln, ok := info.Selections[t]; ok && seln.Kind() == types.FieldVal {
			if v, ok := seln.Obj().(*types.Var); ok {
				to := fieldNodeKey(v)
				for _, s := range srcs {
					f.edges = append(f.edges, posEdge{
						from: entryKey(selfKey, s), to: to,
						hop: fmt.Sprintf("field store %s", v.Name()), site: siteOf(site, e.ix),
					})
				}
			}
		}
	case *ast.IndexExpr:
		tt := info.TypeOf(t.X)
		if tt != nil {
			to := posKey("field|" + tt.String() + ".[]")
			for _, s := range srcs {
				f.edges = append(f.edges, posEdge{
					from: entryKey(selfKey, s), to: to,
					hop: "element store", site: siteOf(site, e.ix),
				})
			}
		}
	case *ast.StarExpr:
		tt := info.TypeOf(t.X)
		if tt != nil {
			to := posKey("field|" + tt.String() + ".*")
			for _, s := range srcs {
				f.edges = append(f.edges, posEdge{
					from: entryKey(selfKey, s), to: to,
					hop: "deref store", site: siteOf(site, e.ix),
				})
			}
		}
	}
}

// targetSources returns the sources a compound-assign target already
// carries.
func (e *triggerEngine) targetSources(fd *fnDeclOf, lhs ast.Expr,
	srcsOf func(ast.Expr, int) []retEntry, varSrcs map[types.Object][]retEntry) []retEntry {
	if id, ok := lhs.(*ast.Ident); ok {
		if obj := fd.pkg.TypesInfo.ObjectOf(id); obj != nil {
			return varSrcs[obj]
		}
	}
	return nil
}

// returnStmt records result-carry tokens for explicit returns.
func (e *triggerEngine) returnStmt(fd *fnDeclOf, s *ast.ReturnStmt, sig *types.Signature,
	srcsOf func(ast.Expr, int) []retEntry, varSrcs map[types.Object][]retEntry, f *fnFacts) {
	nres := 0
	if sig != nil && sig.Results() != nil {
		nres = sig.Results().Len()
	}
	if len(s.Results) == 1 && nres > 1 {
		// return G(...) spreads callee results positionally.
		if c, ok := unparen(s.Results[0]).(*ast.CallExpr); ok {
			for i := range nres {
				f.retSrcs[i] = appendUniqueEntries(f.retSrcs[i],
					e.callResultIndexSrcs(fd, c, i, funcKeyOf(fd.obj), srcsOf)...)
			}
			return
		}
	}
	for i, r := range s.Results {
		if i >= nres {
			break
		}
		f.retSrcs[i] = appendUniqueEntries(f.retSrcs[i], srcsOf(r, 0)...)
	}
}

// callEdges records argument-binding edges for one call site: each
// argument's sources bind to the callee's parameter slots; a method
// call's receiver expression binds to the callee's receiver slot.
// Unresolved callees and open dispatch record escapes — they never
// propagate marks.
func (e *triggerEngine) callEdges(fd *fnDeclOf, call *ast.CallExpr, selfKey fnKey,
	srcsOf func(ast.Expr, int) []retEntry, f *fnFacts) {
	targets, open := e.callTargets(fd, call)
	if open != "" {
		f.open = append(f.open, open)
	}
	if len(targets) == 0 {
		if hasMarkedSources(call.Args, srcsOf) {
			f.escapes = append(f.escapes, fmt.Sprintf(
				"%s:%d call to unresolvable callee receives payload sources",
				posFile(e.ix, call), posLine(e.ix, call)))
		}
		return
	}
	for _, tgt := range targets {
		tk := funcKeyOf(tgt)
		if _, ok := e.fnDecls[tk]; !ok &&
			(e.inScopedModule(funcPkgPath(tgt)) || e.ix.isProductPath(funcPkgPath(tgt))) {
			// The callee lives in a dependency module but its body is
			// outside the analyzed scope (assembled, cgo, not loaded):
			// an argument-preserving hop through it cannot be proven.
			f.escapes = append(f.escapes, fmt.Sprintf(
				"%s:%d: callee %s.%s has no analyzed body in the dependency scope",
				posFile(e.ix, call), posLine(e.ix, call), funcPkgPath(tgt), tgt.Name()))
		}
		arity := -1
		variadic := false
		if sig, ok := tgt.Type().(*types.Signature); ok {
			arity = sig.Params().Len()
			variadic = sig.Variadic()
			if sig.Recv() != nil {
				if sel, ok2 := call.Fun.(*ast.SelectorExpr); ok2 {
					for _, s := range srcsOf(sel.X, 0) {
						f.edges = append(f.edges, posEdge{
							from: entryKey(selfKey, s),
							to:   paramNodeKey(funcKeyOf(tgt), -1),
							hop:  fmt.Sprintf("receiver -> %s", tgt.Name()),
							site: siteOf(call, e.ix),
						})
					}
				}
			}
		}
		for i, arg := range call.Args {
			pos := i
			if variadic && pos >= arity-1 {
				pos = arity - 1
			}
			if arity < 0 || pos < 0 || (arity > 0 && pos >= arity) {
				f.escapes = append(f.escapes, fmt.Sprintf(
					"call to %s argument %d cannot be bound to a parameter slot", tgt.Name(), i))
				continue
			}
			for _, s := range srcsOf(arg, 0) {
				f.edges = append(f.edges, posEdge{
					from: entryKey(selfKey, s),
					to:   paramNodeKey(funcKeyOf(tgt), pos),
					hop:  fmt.Sprintf("arg %d -> %s.%s", pos, funcPkgPath(tgt), tgt.Name()),
					site: siteOf(call, e.ix),
				})
			}
		}
	}
}

// callTargets resolves a call's typed callee set: a statically bound
// function/method, or every loaded implementation of an interface
// method whose interface is unexported (a closed set). Exported
// interfaces and function-value calls stay open.
func (e *triggerEngine) callTargets(fd *fnDeclOf, call *ast.CallExpr) (targets []*types.Func, open string) {
	info := fd.pkg.TypesInfo
	obj := calleeObject(info, call.Fun)
	pos := e.ix.fset.Position(call.Lparen)
	where := fmt.Sprintf("%s:%d", pos.Filename, pos.Line)
	if fn, ok := obj.(*types.Func); ok {
		// A concrete method value on an interface receiver is still
		// dispatch: Selections decides.
		if sel, ok2 := call.Fun.(*ast.SelectorExpr); ok2 {
			if seln, ok3 := info.Selections[sel]; ok3 && seln.Kind() == types.MethodVal {
				if _, isIface := seln.Recv().Underlying().(*types.Interface); isIface {
					return e.ifaceImpls(seln, where)
				}
			}
		}
		return []*types.Func{fn}, ""
	}
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		if seln, ok2 := info.Selections[sel]; ok2 && seln.Kind() == types.MethodVal {
			if _, isIface := seln.Recv().Underlying().(*types.Interface); isIface {
				return e.ifaceImpls(seln, where)
			}
		}
	}
	return nil, fmt.Sprintf("%s: call target is not statically resolved", where)
}

// ifaceImpls enumerates the loaded implementations of an interface
// method selection. The set is closed only when the interface is
// unexported — outside packages cannot declare methods satisfying it —
// or when every method is unexported. Otherwise the dispatch stays
// open: edges go to the found impls, and the open flag keeps the site
// weak.
func (e *triggerEngine) ifaceImpls(seln *types.Selection, where string) ([]*types.Func, string) {
	iface, _ := seln.Recv().Underlying().(*types.Interface)
	if iface == nil {
		return nil, fmt.Sprintf("%s: receiver type is not an interface", where)
	}
	m := seln.Obj().(*types.Func)
	if m == nil {
		return nil, fmt.Sprintf("%s: interface method object unavailable", where)
	}
	var impls []*types.Func
	for _, d := range e.fnDecls {
		if d.obj == nil || d.obj.Name() != m.Name() {
			continue
		}
		sig, _ := d.obj.Type().(*types.Signature)
		if sig == nil || sig.Recv() == nil {
			continue
		}
		rt := sig.Recv().Type()
		if types.Implements(rt, iface) || types.Implements(types.NewPointer(rt), iface) {
			impls = append(impls, d.obj)
		}
	}
	if len(impls) == 0 {
		return nil, fmt.Sprintf("%s: no loaded implementation of %s", where, m.Name())
	}
	open := ""
	for i := range iface.NumMethods() {
		if ast.IsExported(iface.Method(i).Name()) {
			open = fmt.Sprintf("%s: interface %s method set is exported — implementations outside the loaded scope are possible",
				where, iface.String())
			break
		}
	}
	return impls, open
}

// callResultSrcs expands a call expression's result sources through the
// callee's return-carry table. Unresolved callees contribute nothing —
// an opaque result is never a proven carrier.
func (e *triggerEngine) callResultSrcs(fd *fnDeclOf, call *ast.CallExpr, selfKey fnKey,
	srcsOf func(ast.Expr, int) []retEntry, depth int) []retEntry {
	return e.callResultIndexSrcs(fd, call, 0, selfKey, srcsOf)
}

// callResultIndexSrcs computes one result slot's sources: substitute
// the callee's retEntry tokens with this call's argument sources.
func (e *triggerEngine) callResultIndexSrcs(fd *fnDeclOf, call *ast.CallExpr, resIdx int,
	selfKey fnKey, srcsOf func(ast.Expr, int) []retEntry) []retEntry {
	targets, _ := e.callTargets(fd, call)
	var out []retEntry
	for _, tgt := range targets {
		tk := funcKeyOf(tgt)
		sig, _ := tgt.Type().(*types.Signature)
		var table map[int][]retEntry
		if tfd, ok := e.fnDecls[tk]; ok && tfd.decl != nil {
			// Analyze lazily for round-0 nested calls; the recursion
			// guard keeps a cyclic call graph from re-entering a body
			// that is already being analyzed (its table is then empty
			// for this round and the fixpoint picks it up next round).
			if e.analyzing[tk] {
				continue
			}
			if _, done := e.facts[tk]; !done {
				e.analyzing[tk] = true
				e.facts[tk] = e.analyze(tfd, 0)
				delete(e.analyzing, tk)
				e.retMemo[tk] = e.facts[tk].retSrcs
			}
			table = e.retMemo[tk]
		} else if memo, ok := e.retMemo[tk]; ok {
			table = memo
		}
		entries := table[resIdx]
		for _, ent := range entries {
			switch {
			case ent.param >= 0:
				if sig != nil && ent.param < len(call.Args) && ent.param < sig.Params().Len() {
					out = append(out, srcsOf(call.Args[ent.param], 0)...)
				}
			case ent.param == -1:
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
					out = append(out, srcsOf(sel.X, 0)...)
				}
			case ent.param == -2:
				// Field slot carries through globally.
				out = append(out, ent)
			}
		}
	}
	return out
}

// propagate backward-marks every node that can reach the locus's
// carrier positions. Seeds: the locus's receiver slot for a method,
// or all parameter slots for a function — the binder decides which
// shape it proposed.
func (e *triggerEngine) propagate() {
	locus := e.req.Locus
	typeName, name := splitSymbol(locus.Symbol)
	seeds := map[posKey]bool{}
	for k, d := range e.fnDecls {
		if d.pkg.PkgPath != locus.Package || d.obj.Name() != name {
			continue
		}
		if typeName != "" {
			sig, _ := d.obj.Type().(*types.Signature)
			if sig == nil || sig.Recv() == nil || recvTypeName(sig.Recv().Type()) != typeName {
				continue
			}
			seeds[paramNodeKey(k, -1)] = true
			continue
		}
		sig, _ := d.obj.Type().(*types.Signature)
		if sig != nil {
			for i := range sig.Params().Len() {
				seeds[paramNodeKey(k, i)] = true
			}
		}
	}
	if len(seeds) == 0 {
		e.res.Blockers = append(e.res.Blockers,
			fmt.Sprintf("vulnerable implementation %s.%s has no analyzed function body", locus.Package, locus.Symbol))
		return
	}
	e.marked = map[posKey]bool{}
	e.markFrom = map[posKey]posEdge{}
	var queue []posKey
	for s := range seeds {
		e.marked[s] = true
		queue = append(queue, s)
	}
	// Inverted adjacency on demand: edges are stored forward per
	// function; build the reverse index once.
	rev := map[posKey][]posEdge{}
	for _, f := range e.facts {
		for _, ed := range f.edges {
			rev[ed.to] = append(rev[ed.to], ed)
		}
	}
	for _, ed := range e.typeEdges {
		rev[ed.to] = append(rev[ed.to], ed)
	}
	for len(queue) > 0 {
		n := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		for _, ed := range rev[n] {
			if e.marked[ed.from] {
				continue
			}
			e.marked[ed.from] = true
			e.markFrom[ed.from] = ed
			queue = append(queue, ed.from)
		}
	}
	// Escape/blocker reporting: a function that can receive the trigger
	// (its receiver or a parameter is a carrier of the locus state) and
	// also performs an unresolved call/dispatch could pass the trigger
	// through an unmodeled edge. The relation is then not fully
	// discharged for that function, so it becomes a completeness
	// blocker — never a silent hop.
	var taintedEscapes []string
	for k, f := range e.facts {
		if !e.fnTainted(k) {
			continue
		}
		for _, esc := range f.escapes {
			taintedEscapes = append(taintedEscapes, fmt.Sprintf("%s: %s", k, esc))
		}
		for _, o := range f.open {
			taintedEscapes = append(taintedEscapes, fmt.Sprintf("%s: %s", k, o))
		}
	}
	if len(taintedEscapes) > 0 {
		sort.Strings(taintedEscapes)
		if len(taintedEscapes) > 12 {
			taintedEscapes = append(taintedEscapes[:12],
				fmt.Sprintf("… %d further unresolved call/dispatch site(s) on a carrier path", len(taintedEscapes)-12))
		}
		e.res.Blockers = append(e.res.Blockers,
			"carrier analysis found unresolved callee/dispatch site(s) reachable from a trigger-carrying position: "+
				strings.Join(taintedEscapes, "; "))
	}
	// Escape warnings that are not on a carrier path stay audit
	// limitations, never silently proven hops.
	var loose []string
	for k, f := range e.facts {
		if e.fnTainted(k) {
			continue
		}
		for _, esc := range f.escapes {
			loose = append(loose, fmt.Sprintf("%s: %s", k, esc))
		}
		for _, o := range f.open {
			loose = append(loose, fmt.Sprintf("%s: %s", k, o))
		}
	}
	if len(loose) > 0 {
		sort.Strings(loose)
		if len(loose) > 12 {
			loose = append(loose[:12], fmt.Sprintf("… %d further unresolved site(s) off the carrier path", len(loose)-12))
		}
		e.res.Limitations = append(e.res.Limitations,
			"carrier analysis observed unresolved callee/dispatch site(s) off the proven carrier path: "+strings.Join(loose, "; "))
	}
}

// fnTainted reports whether a function can receive the trigger: its
// receiver or any parameter slot is a carrier of the locus state.
func (e *triggerEngine) fnTainted(k fnKey) bool {
	if e.marked[paramNodeKey(k, -1)] {
		return true
	}
	d, ok := e.fnDecls[k]
	if !ok || d.obj == nil {
		return false
	}
	sig, _ := d.obj.Type().(*types.Signature)
	if sig == nil {
		return false
	}
	for i := range sig.Params().Len() {
		if e.marked[paramNodeKey(k, i)] {
			return true
		}
	}
	return false
}

// relation reports whether the sink's trigger parameter is a carrier.
func (e *triggerEngine) relation() {
	sinkKey := e.sinkFnKey()
	if sinkKey == "" {
		e.res.Blockers = append(e.res.Blockers,
			fmt.Sprintf("sink %s.%s has no analyzed function body", e.req.Sink.Package, e.req.Sink.Symbol))
		return
	}
	mark := paramNodeKey(sinkKey, e.req.Trigger)
	if e.marked[mark] {
		e.res.Reached = true
		e.res.Path = e.pathTo(mark)
		return
	}
	e.res.Blockers = append(e.res.Blockers, fmt.Sprintf(
		"sink %s argument %d is not a carrier of the locus state", sinkKey, e.req.Trigger))
}

// pathTo renders the mark chain backward into a forward hop list.
func (e *triggerEngine) pathTo(start posKey) []string {
	var rev []string
	cur := start
	for range 64 {
		ed, ok := e.markFrom[cur]
		if !ok {
			break
		}
		hop := ed.hop
		if ed.site != nil && ed.site.File != "" {
			hop += fmt.Sprintf(" (%s:%d)", ed.site.File, ed.site.Line)
		}
		rev = append(rev, fmt.Sprintf("%s -> %s via %s", string(ed.from), string(ed.to), hop))
		cur = ed.from
	}
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	return rev
}

// sinkFnKey resolves the sink's analyzed function key.
func (e *triggerEngine) sinkFnKey() fnKey {
	sink := e.req.Sink
	typeName, name := splitSymbol(sink.Symbol)
	for k, d := range e.fnDecls {
		if d.pkg.PkgPath != sink.Package || d.obj.Name() != name {
			continue
		}
		if typeName == "" {
			sig, _ := d.obj.Type().(*types.Signature)
			if sig != nil && sig.Recv() == nil {
				return k
			}
			continue
		}
		sig, _ := d.obj.Type().(*types.Signature)
		if sig != nil && sig.Recv() != nil && recvTypeName(sig.Recv().Type()) == typeName {
			return k
		}
	}
	return ""
}

// inScopedModule reports whether pkgPath lies inside one of the loaded
// dependency modules of this proof.
func (e *triggerEngine) inScopedModule(pkgPath string) bool {
	for m := range e.scopeModules {
		if domain.PackageInModule(pkgPath, m) {
			return true
		}
	}
	return false
}

// enumerateSites walks product call sites: every call into a dependency
// function whose callee is marked at some argument position is a bound
// carrier site; unresolvable callees, receiver-carrier calls and
// mixed indices are blockers.
func (e *triggerEngine) enumerateSites() {
	if len(e.marked) == 0 {
		return
	}
	sites := map[string]affected.TriggerSite{}
	var blockers []string
	for _, pkg := range e.ix.pkgs {
		info := pkg.TypesInfo
		if info == nil {
			continue
		}
		for _, f := range pkg.Syntax {
			if e.ix.isTestFile(f) {
				continue
			}
			var enc *ast.FuncDecl
			ast.Inspect(f, func(n ast.Node) bool {
				if fn, ok := n.(*ast.FuncDecl); ok {
					enc = fn
				}
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				site := e.ix.callSiteAt(pkg, enc, call)
				info2 := pkg.TypesInfo
				// Interface-dispatched product calls: check every
				// loaded implementation for a marked position.
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
					if seln, ok2 := info2.Selections[sel]; ok2 && seln.Kind() == types.MethodVal {
						if _, isIface := seln.Recv().Underlying().(*types.Interface); isIface {
							impls, open := e.ifaceImpls(seln, fmt.Sprintf("%s:%d", site.File, site.Line))
							if open != "" {
								blockers = append(blockers,
									fmt.Sprintf("product call at %s:%d dispatches through an open interface set — carriers cannot be enumerated", site.File, site.Line))
								return true
							}
							for _, tgt := range impls {
								e.checkProductCallee(tgt, call, site, enc, pkg, sites, &blockers)
							}
							return true
						}
					}
				}
				obj := calleeObject(info2, call.Fun)
				tgt, ok := obj.(*types.Func)
				if !ok || tgt == nil || tgt.Pkg() == nil || e.ix.isProductPath(tgt.Pkg().Path()) {
					// Function-value call into dependency code is an
					// unenumerable carrier — a completeness blocker.
					if t := info2.TypeOf(call.Fun); t != nil {
						if _, isSig := t.Underlying().(*types.Signature); isSig && obj == nil {
							blockers = append(blockers,
								fmt.Sprintf("product call at %s:%d invokes an unresolvable function value — carrier membership cannot be proven", site.File, site.Line))
						}
					}
					return true
				}
				e.checkProductCallee(tgt, call, site, enc, pkg, sites, &blockers)
				return true
			})
		}
	}
	for _, b := range blockers {
		if !e.blocked[b] {
			e.blocked[b] = true
			e.res.Blockers = append(e.res.Blockers, b)
		}
	}
	var carrierList []affected.TriggerCarrier
	seenCarrier := map[string]bool{}
	for _, s := range sites {
		key := s.Package + "." + s.Symbol
		if !seenCarrier[key] {
			seenCarrier[key] = true
			carrierList = append(carrierList, affected.TriggerCarrier{
				Package: s.Package, Symbol: s.Symbol, Module: s.Module,
				ArgIndex: s.ArgIndex, ParamName: paramNameOf(e.fnDecls[funcKeyOf(e.siteFunc(s))], s.ArgIndex),
			})
		}
		e.res.Sites = append(e.res.Sites, s)
	}
	sort.Slice(carrierList, func(i, j int) bool {
		if carrierList[i].Package != carrierList[j].Package {
			return carrierList[i].Package < carrierList[j].Package
		}
		return carrierList[i].Symbol < carrierList[j].Symbol
	})
	sort.Slice(e.res.Sites, func(i, j int) bool {
		a, b := e.res.Sites[i], e.res.Sites[j]
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
	e.res.Carriers = carrierList
}

// siteFunc resolves a TriggerSite's function object for param naming.
func (e *triggerEngine) siteFunc(s affected.TriggerSite) *types.Func {
	for _, d := range e.fnDecls {
		if d.pkg.PkgPath == s.Package && d.obj.Name() == lastSymbolName(s.Symbol) {
			return d.obj
		}
	}
	return nil
}

// checkProductCallee records a product call into a dependency function
// when one of its parameter positions is marked; receiver carriers and
// variadic ambiguity are blockers.
func (e *triggerEngine) checkProductCallee(tgt *types.Func, call *ast.CallExpr,
	site domain.CallSite, enc *ast.FuncDecl, pkg *packages.Package,
	sites map[string]affected.TriggerSite, blockers *[]string) {
	tk := funcKeyOf(tgt)
	if _, analyzed := e.fnDecls[tk]; !analyzed && e.inScopedModule(tgt.Pkg().Path()) {
		*blockers = append(*blockers, fmt.Sprintf(
			"product call at %s:%d invokes dependency %s.%s whose body is outside the analyzed scope — carrier membership cannot be proven",
			site.File, site.Line, tgt.Pkg().Path(), tgt.Name()))
		return
	}
	markedParams := map[int]bool{}
	sig, _ := tgt.Type().(*types.Signature)
	arity := -1
	variadic := false
	if sig != nil {
		arity = sig.Params().Len()
		variadic = sig.Variadic()
	}
	for i := range arity {
		if e.marked[paramNodeKey(tk, i)] {
			markedParams[i] = true
		}
	}
	// Receiver-carrier product call: the trigger arrives in object
	// state — the exact route cannot bind a receiver position.
	if sig != nil && sig.Recv() != nil && e.marked[paramNodeKey(tk, -1)] {
		*blockers = append(*blockers, fmt.Sprintf(
			"product call at %s:%d feeds carrier %s.%s through receiver state — receiver binding is not an exact ArgIndex",
			site.File, site.Line, tgt.Pkg().Path(), tgt.Name()))
	}
	for idx := range markedParams {
		if variadic && idx == arity-1 {
			*blockers = append(*blockers, fmt.Sprintf(
				"product call at %s:%d feeds carrier %s.%s through a variadic position — variadic binding is ambiguous",
				site.File, site.Line, tgt.Pkg().Path(), tgt.Name()))
			continue
		}
		if idx >= len(call.Args) {
			*blockers = append(*blockers, fmt.Sprintf(
				"product call at %s:%d invokes carrier %s.%s without supplying argument %d — the declared position cannot be proven",
				site.File, site.Line, tgt.Pkg().Path(), tgt.Name(), idx))
			continue
		}
		key := fmt.Sprintf("%s.%s@%d|%s:%d", tgt.Pkg().Path(), tgt.Name(), idx, site.File, site.Line)
		ts := affected.TriggerSite{
			CallSite: site,
			Package:  tgt.Pkg().Path(),
			Symbol:   symbolNameOf(tgt),
			Module:   moduleOfFunc(tgt, e),
			ArgIndex: idx,
		}
		sites[key] = ts
	}
}

// paramNameOf returns the callee's parameter name at idx for the
// carrier record; "" when the declaration is unavailable.
func paramNameOf(d *fnDeclOf, idx int) string {
	if d == nil || d.obj == nil {
		return ""
	}
	sig, _ := d.obj.Type().(*types.Signature)
	if sig == nil || idx < 0 || idx >= sig.Params().Len() {
		return ""
	}
	return sig.Params().At(idx).Name()
}

// moduleOfFunc resolves the dependency module owning tgt's package via
// the loaded packages.Module records.
func moduleOfFunc(tgt *types.Func, e *triggerEngine) string {
	if tgt == nil || tgt.Pkg() == nil {
		return ""
	}
	for _, p := range e.depScope() {
		if p.PkgPath == tgt.Pkg().Path() && p.Module != nil {
			return p.Module.Path
		}
	}
	return ""
}

// symbolNameOf renders a typed function as "Recv.Name" or "Name".
func symbolNameOf(fn *types.Func) string {
	if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
		return recvTypeName(sig.Recv().Type()) + "." + fn.Name()
	}
	return fn.Name()
}

// lastSymbolName returns a symbol's member name.
func lastSymbolName(sym string) string {
	_, name := splitSymbol(sym)
	return name
}

// entryKey renders a retEntry in a caller's frame: param indices name
// the enclosing function's positions; field slots are global.
func entryKey(self fnKey, ent retEntry) posKey {
	if ent.param == -2 {
		return ent.field
	}
	return paramNodeKey(self, ent.param)
}

// hasMarkedSources reports whether any argument carries any sources.
func hasMarkedSources(args []ast.Expr, srcsOf func(ast.Expr, int) []retEntry) bool {
	for _, a := range args {
		if len(srcsOf(a, 0)) > 0 {
			return true
		}
	}
	return false
}

// appendUniqueEntries appends deduplicated retEntry tokens.
func appendUniqueEntries(dst []retEntry, srcs ...retEntry) []retEntry {
	seen := map[retEntry]bool{}
	for _, s := range dst {
		seen[s] = true
	}
	for _, s := range srcs {
		if seen[s] {
			continue
		}
		seen[s] = true
		dst = append(dst, s)
	}
	return dst
}

// declFuncObject resolves a FuncDecl to its *types.Func.
func declFuncObject(pkg *packages.Package, fd *ast.FuncDecl) *types.Func {
	if pkg == nil || pkg.TypesInfo == nil || fd.Name == nil {
		return nil
	}
	obj := pkg.TypesInfo.ObjectOf(fd.Name)
	fn, _ := obj.(*types.Func)
	return fn
}

// fieldOfComposite resolves a composite literal's key identifier to its
// field object.
func fieldOfComposite(info *types.Info, lit *ast.CompositeLit, id *ast.Ident) *types.Var {
	t := info.TypeOf(lit)
	if t == nil {
		return nil
	}
	st, ok := t.Underlying().(*types.Struct)
	if !ok {
		if p, ok2 := t.(*types.Pointer); ok2 {
			st, _ = p.Elem().Underlying().(*types.Struct)
		}
		if st == nil {
			return nil
		}
	}
	for i := range st.NumFields() {
		if st.Field(i).Name() == id.Name {
			return st.Field(i)
		}
	}
	return nil
}

// isLocalVar reports whether v is a function-local variable.
func isLocalVar(v *types.Var) bool {
	return v.Parent() != v.Pkg().Scope()
}

// unparen strips parentheses.
func unparen(e ast.Expr) ast.Expr {
	for {
		p, ok := e.(*ast.ParenExpr)
		if !ok {
			return e
		}
		e = p.X
	}
}

// siteOf renders an AST node's position as a CallSite pointer, or nil.
func siteOf(n ast.Node, ix *Index) *domain.CallSite {
	if n == nil {
		return nil
	}
	pos := ix.fset.Position(n.Pos())
	return &domain.CallSite{File: pos.Filename, Line: pos.Line}
}

// posFile/posLine render a call's position.
func posFile(ix *Index, call *ast.CallExpr) string {
	return ix.fset.Position(call.Pos()).Filename
}

func posLine(ix *Index, call *ast.CallExpr) int {
	return ix.fset.Position(call.Pos()).Line
}

// funcPkgPath is the callee's package path.
func funcPkgPath(fn *types.Func) string {
	if fn.Pkg() == nil {
		return ""
	}
	return fn.Pkg().Path()
}

// The trigger-path proof is the exploit-locus binder's source primitive:
// *Index is the sole implementation of the binder's source surface.
var _ affected.ExploitLocusSource = (*Index)(nil)

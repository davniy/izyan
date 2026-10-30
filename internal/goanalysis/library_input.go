package goanalysis

import (
	"context"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/packages"

	"github.com/fedorovmv/izyan/internal/domain"
)

// This file proves the library public-formal → vulnerable-sink payload binding
// and attaches it to an argument trace as domain.LibraryInputWitness. The walk
// is deliberately separate from the permissive origin classifier: origin
// propagation answers "where may this value come from", while a witness claims
// "this exact consumer-selectable formal reaches this exact sink argument
// unchanged". Only an explicit allowlist of payload-preserving steps can prove
// the latter; everything else is an unproven payload path and yields no
// witness — never a safety claim.
//
// The witness never changes DataFlow.Origin. A library public formal is chosen
// by the consuming application, so nothing inside the analyzed product can
// establish its deployment origin: Origin stays UNKNOWN.

// libraryShapeLocked returns the product-shape proof when it is a usable
// library proof, building the census on first use. nil means the product is
// not a proven library: the public-formal boundary and the payload witness
// stay unreachable, and tracing behaves exactly as before. The gate is
// Kind==LIBRARY && CensusComplete; a complete census with an UNKNOWN
// classification is not a library proof.
func (ix *Index) libraryShapeLocked() *domain.ProductShape {
	if ix.productShapeCache != nil {
		return usableLibraryShape(&ix.productShapeCache.shape)
	}
	if ix.libraryShapeSettled {
		return nil
	}
	ix.libraryShapeSettled = true
	// The proof reconciles typed roots against the census; make sure the
	// (idempotent) load was attempted before building it under the index lock.
	_ = ix.load(ix.ctxOr(nil))
	shape, _, err := ix.buildProductShapeLocked(ix.ctxOr(nil))
	if err != nil {
		return nil
	}
	return usableLibraryShape(shape)
}

func usableLibraryShape(shape *domain.ProductShape) *domain.ProductShape {
	if shape == nil || shape.Kind != domain.ProductShapeLibrary ||
		!shape.CensusComplete || shape.Fingerprint == "" {
		return nil
	}
	return shape
}

// libraryPackageSetLocked indexes the census by import path: presence means
// product-owned, the value means externally importable. The map is keyed by the
// shape fingerprint, so a rebuilt census can never serve a stale membership
// set.
func (ix *Index) libraryPackageSetLocked(shape *domain.ProductShape) map[string]bool {
	if ix.libraryPackageSet != nil && ix.libraryPackageFingerprint == shape.Fingerprint {
		return ix.libraryPackageSet
	}
	set := make(map[string]bool, len(shape.Packages))
	for _, p := range shape.Packages {
		if p.Path != "" {
			set[p.Path] = p.Importable
		}
	}
	ix.libraryPackageSet = set
	ix.libraryPackageFingerprint = shape.Fingerprint
	return set
}

// publicLibraryFormalLocked reports whether param is an ordinary formal of a
// genuine public library API: an exported function, or an exported method on an
// exported named value/pointer receiver, declared in a product-owned,
// externally importable, non-test package of a proven LIBRARY product. It
// returns the API symbol, the formal's positional index and whether the formal
// qualifies. Identity is matched through the typed signature object, never by
// name alone, so a shadowed local with the same name is not a formal.
func (ix *Index) publicLibraryFormalLocked(pkg *packages.Package, enc *ast.FuncDecl, param *types.Var) (domain.SymbolRef, int, bool) {
	if pkg == nil || pkg.TypesInfo == nil || enc == nil || enc.Name == nil || param == nil {
		return domain.SymbolRef{}, -1, false
	}
	shape := ix.libraryShapeLocked()
	if shape == nil {
		return domain.SymbolRef{}, -1, false
	}
	if importable, ok := ix.libraryPackageSetLocked(shape)[pkg.PkgPath]; !ok || !importable {
		return domain.SymbolRef{}, -1, false
	}
	if pkg.ForTest != "" || ix.testDeclFile(enc.Pos()) {
		return domain.SymbolRef{}, -1, false
	}
	idx := formalIndexInSignature(pkg, enc, param)
	if idx < 0 {
		return domain.SymbolRef{}, -1, false
	}
	sig := funcSignature(pkg, enc)
	if sig == nil || (sig.Variadic() && idx == sig.Params().Len()-1) {
		return domain.SymbolRef{}, -1, false
	}
	if !publicLibraryAPIDecl(pkg, enc) {
		return domain.SymbolRef{}, -1, false
	}
	return funcSymbolRef(pkg, enc), idx, true
}

func (ix *Index) testDeclFile(pos token.Pos) bool {
	if ix.fset == nil {
		return false
	}
	return strings.HasSuffix(ix.fset.Position(pos).Filename, "_test.go")
}

// funcSignature returns the typed signature of a declared function or method.
func funcSignature(pkg *packages.Package, enc *ast.FuncDecl) *types.Signature {
	if pkg == nil || pkg.TypesInfo == nil || enc == nil || enc.Name == nil {
		return nil
	}
	obj := pkg.TypesInfo.Defs[enc.Name]
	if obj == nil {
		return nil
	}
	sig, _ := obj.Type().(*types.Signature)
	return sig
}

// formalIndexInSignature maps a parameter object to its positional index in the
// declared signature. Object identity is authoritative; a name+type match is
// only accepted when it is unique, so duplicate or shadowed names cannot be
// mistaken for a formal.
func formalIndexInSignature(pkg *packages.Package, enc *ast.FuncDecl, param *types.Var) int {
	sig := funcSignature(pkg, enc)
	if sig == nil || param == nil {
		return -1
	}
	params := sig.Params()
	for i := range params.Len() {
		// Object identity is authoritative: a shadowed local with the same name
		// and type is a different object and must never resolve as the formal.
		if params.At(i) == param {
			return i
		}
	}
	return -1
}

// publicLibraryAPIDecl reports whether the declaration is part of the
// externally visible API: an exported function, or an exported method on an
// exported named receiver defined in the same package.
func publicLibraryAPIDecl(pkg *packages.Package, enc *ast.FuncDecl) bool {
	if enc.Name == nil || !enc.Name.IsExported() {
		return false
	}
	if enc.Recv == nil {
		return true
	}
	if len(enc.Recv.List) == 0 || pkg == nil || pkg.TypesInfo == nil {
		return false
	}
	recv := pkg.TypesInfo.TypeOf(enc.Recv.List[0].Type)
	if ptr, ok := recv.(*types.Pointer); ok {
		recv = ptr.Elem()
	}
	named, ok := recv.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	if obj == nil || obj.Pkg() == nil || obj.Pkg().Path() != pkg.PkgPath {
		return false
	}
	return obj.Exported()
}

// libraryPayloadType reports whether t is an eligible library payload formal
// type and returns its stable qualified name. Eligible: string, []byte, a
// defined type or alias with that underlying representation, and the canonical
// io.Reader. Everything else is rejected — writer-only types, lookalike
// interfaces, callbacks, pointers, containers, unresolved type parameters, and
// type names that merely contain "Reader"/"Bytes".
func libraryPayloadType(t types.Type) (string, bool) {
	if !eligibleLibraryPayload(t) {
		return "", false
	}
	t = types.Unalias(t)
	if named, ok := t.(*types.Named); ok {
		if canonicalIOReader(named) {
			return "io.Reader", true
		}
		// A defined payload type keeps its declared identity.
		return types.TypeString(named, func(p *types.Package) string {
			if p == nil {
				return ""
			}
			return p.Path()
		}), true
	}
	if _, ok := t.Underlying().(*types.Basic); ok {
		return "string", true
	}
	return "[]byte", true
}

func eligibleLibraryPayload(t types.Type) bool {
	if t == nil {
		return false
	}
	if _, ok := t.(*types.TypeParam); ok {
		return false
	}
	t = types.Unalias(t)
	switch u := t.(type) {
	case *types.TypeParam:
		return false
	case *types.Named:
		if canonicalIOReader(u) {
			return true
		}
		if _, ok := u.Underlying().(*types.Interface); ok {
			return false
		}
	}
	switch u := t.Underlying().(type) {
	case *types.Basic:
		return u.Info()&types.IsString != 0
	case *types.Slice:
		return byteSliceElem(u.Elem())
	}
	return false
}

// canonicalIOReader matches exactly io.Reader: the named type from package io
// implementing the canonical Read([]byte) (int, error) contract. A structurally
// identical interface from another package is not the canonical carrier.
func canonicalIOReader(t *types.Named) bool {
	obj := t.Obj()
	if obj == nil || obj.Pkg() == nil || obj.Pkg().Path() != "io" || obj.Name() != "Reader" {
		return false
	}
	iface, ok := t.Underlying().(*types.Interface)
	if !ok || iface.NumMethods() != 1 || iface.Method(0).Name() != "Read" {
		return false
	}
	return true
}

func byteSliceElem(t types.Type) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	b, ok := t.(*types.Basic)
	return ok && b.Kind() == types.Uint8
}

// bytePreservingConversion reports whether src -> dst is one of the
// byte-preserving conversions: string↔string, []byte↔[]byte, string→[]byte or
// []byte→string (named/aliased types compare by underlying representation).
// Numeric and rune conversions change the byte representation and are not
// payload-preserving.
func bytePreservingConversion(src, dst types.Type) bool {
	sk, sok := payloadUnderlyingKind(src)
	dk, dok := payloadUnderlyingKind(dst)
	if !sok || !dok {
		return false
	}
	return (sk == "string" || sk == "bytes") && (dk == "string" || dk == "bytes")
}

func payloadUnderlyingKind(t types.Type) (string, bool) {
	if t == nil {
		return "", false
	}
	switch u := types.Unalias(t).Underlying().(type) {
	case *types.Basic:
		if u.Info()&types.IsString != 0 {
			return "string", true
		}
	case *types.Slice:
		if byteSliceElem(u.Elem()) {
			return "bytes", true
		}
	}
	return "", false
}

// modeledPayloadCall recognizes the explicitly modeled complete-read and
// carrier operations. Only io.ReadAll is modeled: it reads the carrier to EOF
// and returns the bytes, so the result's payload is the reader argument.
// General knowledge-base passthrough entries are never proof of preservation.
func modeledPayloadCall(fn *types.Func, call *ast.CallExpr) bool {
	if fn == nil || fn.Pkg() == nil || fn.Pkg().Path() != "io" || fn.Name() != "ReadAll" {
		return false
	}
	if call == nil || len(call.Args) != 1 || call.Ellipsis.IsValid() {
		return false
	}
	sig, _ := fn.Type().(*types.Signature)
	if sig == nil || sig.Variadic() || sig.Results().Len() != 2 {
		return false
	}
	return eligibleLibrarySlice(sig.Results().At(0).Type())
}

func eligibleLibrarySlice(t types.Type) bool {
	if t == nil {
		return false
	}
	u, ok := types.Unalias(t).Underlying().(*types.Slice)
	return ok && byteSliceElem(u.Elem())
}

// libraryFuncScope is one function on a proven payload path: the payload
// objects (formals and locals) that carry it, and the nodes where the payload
// leaves the function (the sink call, a forwarding call, or a return).
type libraryFuncScope struct {
	pkg  *packages.Package
	enc  *ast.FuncDecl
	objs map[types.Object]bool
	uses []ast.Node
	// allowed are the proof chain's own calls in this function: the sink, the
	// forwarding call, the helper call and io.ReadAll. They are the only calls
	// permitted to receive a live mutable payload carrier.
	allowed map[*ast.CallExpr]bool
	// carrierCalls are the proof chain's calls whose result is the payload
	// itself (typed helper forwarding), so passing their result on to another
	// call still passes the carrier.
	carrierCalls map[*ast.CallExpr]bool
}

// libraryBinding is one proven path from a payload expression to either a
// public API formal or, during helper forwarding, a formal that still has to be
// mapped onto the enclosing call's argument.
type libraryBinding struct {
	api        domain.SymbolRef
	decl       domain.CallSite
	formal     *types.Var
	formalIdx  int
	formalType string
	steps      []domain.LibraryPayloadStep
	scopes     map[*ast.FuncDecl]*libraryFuncScope
	order      []*libraryFuncScope
}

func (b *libraryBinding) scope(pkg *packages.Package, enc *ast.FuncDecl) *libraryFuncScope {
	if b.scopes == nil {
		b.scopes = map[*ast.FuncDecl]*libraryFuncScope{}
	}
	if s := b.scopes[enc]; s != nil {
		return s
	}
	s := &libraryFuncScope{
		pkg:          pkg,
		enc:          enc,
		objs:         map[types.Object]bool{},
		allowed:      map[*ast.CallExpr]bool{},
		carrierCalls: map[*ast.CallExpr]bool{},
	}
	b.scopes[enc] = s
	b.order = append(b.order, s)
	return s
}

func (b *libraryBinding) noteObject(pkg *packages.Package, enc *ast.FuncDecl, obj types.Object) {
	if enc == nil || obj == nil {
		return
	}
	b.scope(pkg, enc).objs[obj] = true
}

func (b *libraryBinding) noteUse(pkg *packages.Package, enc *ast.FuncDecl, node ast.Node) {
	if enc == nil || node == nil {
		return
	}
	s := b.scope(pkg, enc)
	for _, prev := range s.uses {
		if prev == node {
			return
		}
	}
	s.uses = append(s.uses, node)
}

func (b *libraryBinding) noteAllowedCall(pkg *packages.Package, enc *ast.FuncDecl, call *ast.CallExpr) {
	if enc == nil || call == nil {
		return
	}
	b.scope(pkg, enc).allowed[call] = true
}

func (b *libraryBinding) noteCarrierCall(pkg *packages.Package, enc *ast.FuncDecl, call *ast.CallExpr) {
	if enc == nil || call == nil {
		return
	}
	b.scope(pkg, enc).carrierCalls[call] = true
}

func (b *libraryBinding) merge(o *libraryBinding) {
	if o == nil {
		return
	}
	for _, s := range o.order {
		for obj := range s.objs {
			b.noteObject(s.pkg, s.enc, obj)
		}
		for _, use := range s.uses {
			b.noteUse(s.pkg, s.enc, use)
		}
		for call := range s.allowed {
			b.noteAllowedCall(s.pkg, s.enc, call)
		}
		for call := range s.carrierCalls {
			b.noteCarrierCall(s.pkg, s.enc, call)
		}
	}
}

func sameLibraryFormal(a, b *libraryBinding) bool {
	if a == nil || b == nil {
		return false
	}
	return a.formal == b.formal && a.formalIdx == b.formalIdx && a.api == b.api
}

// libraryWrite is one verified write of a payload local: the RHS expression, the
// result index when the RHS is a single multi-assignment call (-1 otherwise),
// and the written identifier's position.
type libraryWrite struct {
	rhs    ast.Expr
	result int
	at     token.Pos
}

// libraryWalk holds the per-trace state of the strict payload-proof search.
type libraryWalk struct {
	ix         *Index
	ctx        context.Context
	shape      *domain.ProductShape
	pkgSet     map[string]bool
	seenFormal map[string]bool
	seenLocal  map[types.Object]bool
	hops       int
}

// traceLibraryInputLocked proves the exact public-formal → sink-argument binding
// for one traced argument. It returns nil (and no error) when the path is not
// provable — failed admission is no proof, never safety. Callers MUST hold
// ix.mu; pkg/enc/call are the resolved sink call and its enclosing declaration.
func (ix *Index) traceLibraryInputLocked(ctx context.Context, pkg *packages.Package, enc *ast.FuncDecl, call *ast.CallExpr, argIndex int, shape *domain.ProductShape) (*domain.LibraryInputWitness, []domain.Evidence, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
	}
	if shape == nil || shape.Kind != domain.ProductShapeLibrary ||
		!shape.CensusComplete || shape.Fingerprint == "" {
		return nil, nil, fmt.Errorf("library payload: no proven library shape")
	}
	if pkg == nil || pkg.TypesInfo == nil || enc == nil || call == nil {
		return nil, nil, fmt.Errorf("library payload: unresolved sink call context")
	}
	// Ordinary argument input only: the receiver, whole-argument and
	// writer-only positions are never payload formals.
	if argIndex < 0 || argIndex >= len(call.Args) {
		return nil, nil, fmt.Errorf("library payload: arg %d is not an ordinary argument", argIndex)
	}
	if payloadUnprovenParameter(pkg, call, argIndex) {
		return nil, nil, fmt.Errorf("library payload: arg %d is a writer-only position", argIndex)
	}
	site := ix.siteOf(pkg, enc, call)
	if site.File == "" || site.Line == 0 || site.Column == 0 {
		return nil, nil, fmt.Errorf("library payload: sink call has no exact source position")
	}
	fn, ok := calleeObject(pkg.TypesInfo, call.Fun).(*types.Func)
	if !ok || fn == nil || fn.Pkg() == nil {
		return nil, nil, fmt.Errorf("library payload: sink callee is not a resolved function")
	}
	sink := domain.SymbolRef{Package: fn.Pkg().Path(), Symbol: fn.Name()}
	if sig, _ := fn.Type().(*types.Signature); sig != nil && sig.Recv() != nil {
		if recv := recvTypeName(sig.Recv().Type()); recv != "" {
			sink.Symbol = recv + "." + fn.Name()
		}
	}
	w := &libraryWalk{
		ix:         ix,
		ctx:        ctx,
		shape:      shape,
		pkgSet:     ix.libraryPackageSetLocked(shape),
		seenFormal: map[string]bool{},
		seenLocal:  map[types.Object]bool{},
	}
	binding, err := w.proveExpr(pkg, enc, call.Args[argIndex], false, 0)
	if err != nil {
		return nil, nil, err
	}
	if binding == nil || binding.api.Package == "" || binding.api.Symbol == "" || binding.formal == nil {
		return nil, nil, fmt.Errorf("library payload: no public formal endpoint")
	}
	binding.noteUse(pkg, enc, call)
	binding.noteAllowedCall(pkg, enc, call)
	if err := w.checkControlFlow(binding); err != nil {
		return nil, nil, err
	}
	witness := &domain.LibraryInputWitness{
		API:              binding.api,
		Declaration:      binding.decl,
		FormalIndex:      binding.formalIdx,
		FormalName:       binding.formal.Name(),
		FormalType:       binding.formalType,
		Sink:             sink,
		Site:             site,
		Arg:              argIndex,
		ShapeFingerprint: shape.Fingerprint,
		Steps:            binding.steps,
	}
	content := fmt.Sprintf("api=%s.%s decl=%s:%d:%d formal=%d:%s sink=%s.%s site=%s:%d:%d arg=%d steps=%s",
		binding.api.Package, binding.api.Symbol,
		binding.decl.File, binding.decl.Line, binding.decl.Column,
		binding.formalIdx, binding.formalType,
		sink.Package, sink.Symbol,
		site.File, site.Line, site.Column, argIndex,
		libraryStepsText(binding.steps))
	ev := domain.Evidence{
		Kind:    domain.EvidenceDataFlow,
		Quality: domain.QualityDeterministic,
		Source:  "source index: library public-formal payload binding",
		Tool:    "goanalysis.Index.TraceArgument",
		File:    binding.decl.File,
		Content: content,
	}
	return witness, []domain.Evidence{ev}, nil
}

func libraryStepsText(steps []domain.LibraryPayloadStep) string {
	if len(steps) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(steps))
	for _, s := range steps {
		parts = append(parts, fmt.Sprintf("%s@%s:%d:%d", s.Kind, s.Site.File, s.Site.Line, s.Site.Column))
	}
	return strings.Join(parts, ",")
}

func (ix *Index) librarySiteAt(pkg *packages.Package, enc *ast.FuncDecl, pos token.Pos) domain.CallSite {
	site := domain.CallSite{File: ix.fset.Position(pos).Filename, Line: ix.fset.Position(pos).Line, Column: ix.fset.Position(pos).Column}
	if enc != nil && enc.Name != nil {
		site.Function = enc.Name.Name
	}
	if pkg != nil {
		site.Package = pkg.PkgPath
	}
	return site
}

func (ix *Index) libraryDeclSite(pkg *packages.Package, enc *ast.FuncDecl) domain.CallSite {
	return ix.librarySiteAt(pkg, enc, enc.Pos())
}

// proveExpr proves that expr carries the payload of a formal.
//
// stopAtFormal selects the helper-body mode: reaching a parameter of enc
// returns that formal without resolving it to a caller, so the enclosing call
// can map the formal onto its own argument. With stopAtFormal=false a formal is
// resolved upward through its callers until a public API formal is reached.
func (w *libraryWalk) proveExpr(pkg *packages.Package, enc *ast.FuncDecl, expr ast.Expr, stopAtFormal bool, depth int) (*libraryBinding, error) {
	if w.ctx != nil {
		if err := w.ctx.Err(); err != nil {
			return nil, err
		}
	}
	if pkg == nil || pkg.TypesInfo == nil || enc == nil {
		return nil, fmt.Errorf("library payload: unresolved expression context")
	}
	if expr == nil {
		return nil, fmt.Errorf("library payload: empty expression")
	}
	if depth > maxExprDepth {
		return nil, fmt.Errorf("library payload: expression depth exceeded")
	}
	switch e := expr.(type) {
	case *ast.ParenExpr:
		return w.proveExpr(pkg, enc, e.X, stopAtFormal, depth+1)
	case *ast.Ident:
		return w.proveIdent(pkg, enc, e, stopAtFormal, depth)
	case *ast.CallExpr:
		return w.proveCall(pkg, enc, e, stopAtFormal, depth)
	}
	return nil, fmt.Errorf("library payload: unsupported payload transform %T", expr)
}

func (w *libraryWalk) proveIdent(pkg *packages.Package, enc *ast.FuncDecl, id *ast.Ident, stopAtFormal bool, depth int) (*libraryBinding, error) {
	obj := pkg.TypesInfo.ObjectOf(id)
	if obj == nil {
		return nil, fmt.Errorf("library payload: unresolved identifier %s", id.Name)
	}
	v, ok := obj.(*types.Var)
	if !ok {
		return nil, fmt.Errorf("library payload: %s is not a variable", id.Name)
	}
	if idx := formalIndexInSignature(pkg, enc, v); idx >= 0 {
		if err := w.checkFormalWrites(pkg, enc, v); err != nil {
			return nil, err
		}
		// Eligible typed payload formal: string, []byte (or a defined type
		// with that representation) or the canonical io.Reader. Anything else
		// cannot carry the selectable payload the witness claims.
		formalType, eligible := libraryPayloadType(v.Type())
		if !eligible {
			return nil, fmt.Errorf("library payload: formal %s (%s) is not an eligible payload type", v.Name(), v.Type())
		}
		b := &libraryBinding{formal: v, formalIdx: idx, formalType: formalType}
		b.noteObject(pkg, enc, v)
		if stopAtFormal {
			return b, nil
		}
		return w.resolveFormal(pkg, enc, v, idx, depth)
	}
	if isReceiver(enc, v) {
		return nil, fmt.Errorf("library payload: receiver %s is not an ordinary formal", v.Name())
	}
	if v.Parent() != nil && pkg.Types != nil && v.Parent() == pkg.Types.Scope() {
		return nil, fmt.Errorf("library payload: package-level variable %s is not a formal", v.Name())
	}
	if v.Parent() == nil {
		return nil, fmt.Errorf("library payload: variable %s has no declaring scope", v.Name())
	}
	writes, ok := w.writesOf(pkg, enc, v)
	if !ok || len(writes) != 1 {
		return nil, fmt.Errorf("library payload: local %s has no single verified payload write", v.Name())
	}
	if w.seenLocal[v] {
		return nil, fmt.Errorf("library payload: local %s is self-referential", v.Name())
	}
	w.seenLocal[v] = true
	defer delete(w.seenLocal, v)
	write := writes[0]
	if write.rhs == nil {
		return nil, fmt.Errorf("library payload: local %s has an empty assignment", v.Name())
	}
	if write.result > 0 {
		return nil, fmt.Errorf("library payload: local %s binds a non-payload result", v.Name())
	}
	b, err := w.proveExpr(pkg, enc, write.rhs, stopAtFormal, depth+1)
	if err != nil {
		return nil, err
	}
	b.steps = append(b.steps, domain.LibraryPayloadStep{
		Kind: domain.LibraryPayloadIdentity,
		Site: w.ix.librarySiteAt(pkg, enc, write.at),
	})
	b.noteObject(pkg, enc, v)
	return b, nil
}

// resolveFormal continues a formal upward: a public API formal ends the proof;
// a private formal is mapped onto the arguments its callers pass, one proven
// caller being enough to establish consumer selectability. Unresolved dispatch
// never proves a binding, and callers outside the proven product census (test
// variants, dependency internals) never close a public boundary.
func (w *libraryWalk) resolveFormal(pkg *packages.Package, enc *ast.FuncDecl, v *types.Var, idx int, depth int) (*libraryBinding, error) {
	if ref, apiIdx, ok := w.ix.publicLibraryFormalLocked(pkg, enc, v); ok {
		formalType, _ := libraryPayloadType(v.Type())
		b := &libraryBinding{
			api:        ref,
			decl:       w.ix.libraryDeclSite(pkg, enc),
			formal:     v,
			formalIdx:  apiIdx,
			formalType: formalType,
		}
		b.noteObject(pkg, enc, v)
		return b, nil
	}
	if w.hops >= w.ix.hops() {
		return nil, fmt.Errorf("library payload: caller budget exhausted resolving %s", v.Name())
	}
	key := fmt.Sprintf("%s|%s|arg%d", pkg.PkgPath, funcSymbolRef(pkg, enc).Symbol, idx)
	if w.seenFormal[key] {
		return nil, fmt.Errorf("library payload: formal %s is recursive", v.Name())
	}
	w.seenFormal[key] = true
	w.hops++
	defer func() {
		delete(w.seenFormal, key)
		w.hops--
	}()
	refs := w.ix.callersOf(pkg, funcSymbolRef(pkg, enc))
	var lastErr error = fmt.Errorf("library payload: no caller proves the payload for %s", v.Name())
	for _, r := range refs {
		if r.possible {
			lastErr = fmt.Errorf("library payload: unresolved dispatch feeds %s", v.Name())
			continue
		}
		if r.pkg == nil || r.enclosing == nil || r.call == nil {
			continue
		}
		if _, ok := w.pkgSet[r.pkg.PkgPath]; !ok {
			continue
		}
		if idx >= len(r.call.Args) {
			continue
		}
		b, err := w.proveExpr(r.pkg, r.enclosing, r.call.Args[idx], false, depth+1)
		if err != nil {
			lastErr = err
			continue
		}
		b.steps = append(b.steps, domain.LibraryPayloadStep{
			Kind: domain.LibraryPayloadPreservingCall,
			Site: w.ix.siteOf(r.pkg, r.enclosing, r.call),
		})
		b.noteObject(pkg, enc, v)
		b.noteUse(r.pkg, r.enclosing, r.call)
		b.noteAllowedCall(r.pkg, r.enclosing, r.call)
		return b, nil
	}
	return nil, lastErr
}

func (w *libraryWalk) proveCall(pkg *packages.Package, enc *ast.FuncDecl, call *ast.CallExpr, stopAtFormal bool, depth int) (*libraryBinding, error) {
	if call.Fun == nil {
		return nil, fmt.Errorf("library payload: call without a callee")
	}
	if tv, ok := pkg.TypesInfo.Types[call.Fun]; ok && tv.IsType() {
		return w.proveConversion(pkg, enc, call, stopAtFormal, depth)
	}
	fn, ok := calleeObject(pkg.TypesInfo, call.Fun).(*types.Func)
	if !ok || fn == nil || fn.Pkg() == nil {
		return nil, fmt.Errorf("library payload: unresolved dispatch at the payload call")
	}
	if modeledPayloadCall(fn, call) {
		b, err := w.proveExpr(pkg, enc, call.Args[0], stopAtFormal, depth+1)
		if err != nil {
			return nil, err
		}
		b.steps = append(b.steps, domain.LibraryPayloadStep{
			Kind: domain.LibraryPayloadPreservingCall,
			Site: w.ix.siteOf(pkg, enc, call),
		})
		b.noteAllowedCall(pkg, enc, call)
		return b, nil
	}
	// A typed direct helper whose body proves the same binding may forward the
	// payload. Only a single payload-shaped result is a forwarding candidate:
	// the returned expression must map onto one of the helper's own formals.
	sig, _ := fn.Type().(*types.Signature)
	if sig == nil || sig.Variadic() || sig.Results().Len() != 1 {
		return nil, fmt.Errorf("library payload: %s is not a payload-preserving helper", fn.Name())
	}
	if _, ok := libraryPayloadType(sig.Results().At(0).Type()); !ok {
		return nil, fmt.Errorf("library payload: %s does not return a payload type", fn.Name())
	}
	decl, helperPkg := w.ix.funcDecl(fn)
	if decl == nil || helperPkg == nil || helperPkg.TypesInfo == nil || decl.Body == nil {
		return nil, fmt.Errorf("library payload: no analyzable body for %s", fn.Name())
	}
	if _, ok := w.pkgSet[helperPkg.PkgPath]; !ok {
		return nil, fmt.Errorf("library payload: helper %s is outside the product", fn.Name())
	}
	if w.hops >= w.ix.hops() {
		return nil, fmt.Errorf("library payload: caller budget exhausted in %s", fn.Name())
	}
	w.hops++
	helperProof, err := w.proveReturns(helperPkg, decl, depth+1)
	w.hops--
	if err != nil {
		return nil, err
	}
	if helperProof.formalIdx < 0 || helperProof.formalIdx >= len(call.Args) {
		return nil, fmt.Errorf("library payload: %s formal does not map onto the call", fn.Name())
	}
	current, err := w.proveExpr(pkg, enc, call.Args[helperProof.formalIdx], stopAtFormal, depth+1)
	if err != nil {
		return nil, err
	}
	// Data order: caller argument → helper call → helper body → result.
	current.steps = append(current.steps, domain.LibraryPayloadStep{
		Kind: domain.LibraryPayloadPreservingCall,
		Site: w.ix.siteOf(pkg, enc, call),
	})
	current.steps = append(current.steps, helperProof.steps...)
	current.merge(helperProof)
	current.noteAllowedCall(pkg, enc, call)
	current.noteCarrierCall(pkg, enc, call)
	return current, nil
}

// proveConversion accepts exactly the byte-preserving string/[]byte
// conversions. Numeric, rune, slice-of-non-byte and interface conversions are
// payload-changing transforms and never prove preservation.
func (w *libraryWalk) proveConversion(pkg *packages.Package, enc *ast.FuncDecl, call *ast.CallExpr, stopAtFormal bool, depth int) (*libraryBinding, error) {
	if len(call.Args) != 1 || call.Ellipsis.IsValid() {
		return nil, fmt.Errorf("library payload: unsupported conversion shape")
	}
	if !bytePreservingConversion(pkg.TypesInfo.TypeOf(call.Args[0]), pkg.TypesInfo.TypeOf(call)) {
		return nil, fmt.Errorf("library payload: non-byte-preserving conversion")
	}
	b, err := w.proveExpr(pkg, enc, call.Args[0], stopAtFormal, depth+1)
	if err != nil {
		return nil, err
	}
	b.steps = append(b.steps, domain.LibraryPayloadStep{
		Kind: domain.LibraryPayloadByteConversion,
		Site: w.ix.siteOf(pkg, enc, call),
	})
	return b, nil
}

// proveReturns proves that every return of a forwarding helper carries the
// payload of one of the helper's own formals. Multiple returns must agree on
// the same formal; each return is a separately inspected control-flow exit.
func (w *libraryWalk) proveReturns(pkg *packages.Package, decl *ast.FuncDecl, depth int) (*libraryBinding, error) {
	rets := topLevelReturns(decl)
	if len(rets) == 0 {
		return nil, fmt.Errorf("library payload: helper %s has no return", decl.Name.Name)
	}
	var out *libraryBinding
	for _, ret := range rets {
		if len(ret.Results) != 1 {
			return nil, fmt.Errorf("library payload: helper %s has a multi-value return", decl.Name.Name)
		}
		b, err := w.proveExpr(pkg, decl, ret.Results[0], true, depth+1)
		if err != nil {
			return nil, err
		}
		if out == nil {
			out = b
		} else {
			if !sameLibraryFormal(out, b) {
				return nil, fmt.Errorf("library payload: helper %s returns different payload formals", decl.Name.Name)
			}
			out.merge(b)
		}
		out.noteUse(pkg, decl, ret)
	}
	return out, nil
}

func topLevelReturns(decl *ast.FuncDecl) []*ast.ReturnStmt {
	if decl == nil || decl.Body == nil {
		return nil
	}
	var out []*ast.ReturnStmt
	ast.Inspect(decl.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncLit:
			return false // a literal return is a different execution context
		case *ast.ReturnStmt:
			out = append(out, x)
		}
		return true
	})
	return out
}

// checkFormalWrites rejects a formal that the function rewrites: a replaced
// formal no longer carries the caller-selected payload.
func (w *libraryWalk) checkFormalWrites(pkg *packages.Package, enc *ast.FuncDecl, v *types.Var) error {
	writes, ok := w.writesOf(pkg, enc, v)
	if !ok || len(writes) > 0 {
		return fmt.Errorf("library payload: formal %s is reassigned", v.Name())
	}
	return nil
}

// writesOf collects the verified writes of obj inside enc. ok=false means an
// unverifiable write exists (compound assignment, increment, element store,
// deref/field store, range or type-switch binding, address taken, or a write
// inside a function literal).
func (w *libraryWalk) writesOf(pkg *packages.Package, enc *ast.FuncDecl, obj types.Object) ([]libraryWrite, bool) {
	if enc == nil || enc.Body == nil || obj == nil {
		return nil, false
	}
	literals := funcLitNodes(enc)
	var out []libraryWrite
	ok := true
	ast.Inspect(enc.Body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.AssignStmt:
			inLit := literals[s]
			typeAssert := false
			if len(s.Rhs) == 1 {
				if ta, isTA := s.Rhs[0].(*ast.TypeAssertExpr); isTA && ta.Type == nil {
					typeAssert = true
				}
			}
			for i, lhs := range s.Lhs {
				if id, isID := lhs.(*ast.Ident); isID && pkg.TypesInfo.ObjectOf(id) == obj {
					switch {
					case inLit, typeAssert:
						ok = false
					case s.Tok != token.ASSIGN && s.Tok != token.DEFINE:
						ok = false
					case len(s.Lhs) == len(s.Rhs):
						out = append(out, libraryWrite{rhs: s.Rhs[i], result: -1, at: id.Pos()})
					case len(s.Rhs) == 1:
						out = append(out, libraryWrite{rhs: s.Rhs[0], result: i, at: id.Pos()})
					default:
						ok = false
					}
					continue
				}
				if writesThroughObject(pkg, lhs, obj) {
					ok = false
				}
			}
		case *ast.ValueSpec:
			inLit := literals[s]
			for i, name := range s.Names {
				if pkg.TypesInfo.ObjectOf(name) != obj {
					continue
				}
				switch {
				case inLit:
					ok = false
				case i < len(s.Values):
					out = append(out, libraryWrite{rhs: s.Values[i], result: -1, at: name.Pos()})
				}
			}
		case *ast.IncDecStmt:
			if id, isID := s.X.(*ast.Ident); isID && pkg.TypesInfo.ObjectOf(id) == obj {
				ok = false
			}
			if writesThroughObject(pkg, s.X, obj) {
				ok = false
			}
		case *ast.RangeStmt:
			for _, e := range []ast.Expr{s.Key, s.Value} {
				if id, isID := e.(*ast.Ident); isID && pkg.TypesInfo.ObjectOf(id) == obj {
					ok = false
				}
			}
		case *ast.UnaryExpr:
			if s.Op == token.AND {
				if id, isID := s.X.(*ast.Ident); isID && pkg.TypesInfo.ObjectOf(id) == obj {
					ok = false
				}
			}
		}
		return true
	})
	if !ok {
		return nil, false
	}
	return out, true
}

// writesThroughObject reports whether the LHS form mutates obj in place
// (element store, field store, dereference store).
func writesThroughObject(pkg *packages.Package, lhs ast.Expr, obj types.Object) bool {
	switch e := lhs.(type) {
	case *ast.IndexExpr:
		return exprRefersObject(pkg, e.X, obj)
	case *ast.SelectorExpr:
		return exprRefersObject(pkg, e.X, obj)
	case *ast.StarExpr:
		return exprRefersObject(pkg, e.X, obj)
	}
	return false
}

func exprRefersObject(pkg *packages.Package, expr ast.Expr, obj types.Object) bool {
	id, ok := expr.(*ast.Ident)
	return ok && pkg.TypesInfo.ObjectOf(id) == obj
}

// funcLitNodes marks every AST node inside a function literal of enc. A write
// or a control-flow use inside a literal is not ordered against the enclosing
// function's sink.
func funcLitNodes(enc *ast.FuncDecl) map[ast.Node]bool {
	nodes := map[ast.Node]bool{}
	if enc == nil || enc.Body == nil {
		return nodes
	}
	ast.Inspect(enc.Body, func(n ast.Node) bool {
		fl, ok := n.(*ast.FuncLit)
		if !ok {
			return true
		}
		ast.Inspect(fl, func(m ast.Node) bool {
			if m != nil {
				nodes[m] = true
			}
			return true
		})
		return true
	})
	return nodes
}

// checkControlFlow rejects a binding whose payload is tested, sanitized or
// recovered around before it reaches the sink. The inspection is per function
// on the path and per exit node, so a helper that validates the payload cannot
// hide behind a later return.
func (w *libraryWalk) checkControlFlow(b *libraryBinding) error {
	for _, s := range b.order {
		if len(s.objs) == 0 {
			continue
		}
		if len(s.uses) == 0 {
			return fmt.Errorf("library payload: no control-flow exit for %s", s.enc.Name.Name)
		}
		if hasRecoverCall(s.pkg, s.enc) {
			return fmt.Errorf("library payload: recovery in %s may rewrite the payload", s.enc.Name.Name)
		}
		if err := checkCallMutations(s.pkg, s.enc, s.objs, s.allowed, s.carrierCalls); err != nil {
			return err
		}
		guardObjs := libraryGuardObjects(s.pkg, s.enc, s.objs)
		for _, use := range s.uses {
			if nodeInsideFuncLit(s.enc, use) {
				return fmt.Errorf("library payload: binding crosses a function literal in %s", s.enc.Name.Name)
			}
			if err := checkPreGuards(s.pkg, s.enc, guardObjs, use); err != nil {
				return err
			}
		}
	}
	return nil
}

func hasRecoverCall(pkg *packages.Package, enc *ast.FuncDecl) bool {
	if enc == nil || enc.Body == nil || pkg == nil || pkg.TypesInfo == nil {
		return false
	}
	found := false
	ast.Inspect(enc.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 0 {
			return true
		}
		id, ok := call.Fun.(*ast.Ident)
		if !ok || id.Name != "recover" {
			return true
		}
		if _, ok := pkg.TypesInfo.Uses[id].(*types.Builtin); ok {
			found = true
		}
		return true
	})
	return found
}

func nodeInsideFuncLit(enc *ast.FuncDecl, node ast.Node) bool {
	if enc == nil || enc.Body == nil || node == nil {
		return true
	}
	inside := false
	ast.Inspect(enc.Body, func(n ast.Node) bool {
		fl, ok := n.(*ast.FuncLit)
		if !ok {
			return true
		}
		if fl.Pos() <= node.Pos() && node.End() <= fl.End() {
			inside = true
			return false
		}
		return true
	})
	return inside
}

// checkPreGuards rejects conditional statements that inspect a payload object
// before the payload's exit node. A sink in an if initializer executes before
// that if's condition, so the error test there is not a pre-sink guard; a
// condition that encloses the sink in its body is.
func checkPreGuards(pkg *packages.Package, enc *ast.FuncDecl, objs map[types.Object]bool, use ast.Node) error {
	if enc == nil || enc.Body == nil || use == nil {
		return fmt.Errorf("library payload: no control-flow context")
	}
	var bad error
	ast.Inspect(enc.Body, func(n ast.Node) bool {
		if bad != nil {
			return false
		}
		if fl, ok := n.(*ast.FuncLit); ok {
			// Literals are separate execution contexts; nodeInsideFuncLit has
			// already rejected any path that crosses one.
			return use.Pos() >= fl.Pos() && use.End() <= fl.End()
		}
		var before []ast.Node
		var exitInside bool
		var stmt ast.Node = n
		switch s := n.(type) {
		case *ast.IfStmt:
			before = []ast.Node{s.Init, s.Cond}
			exitInside = useInNode(use, s.Init)
		case *ast.SwitchStmt:
			before = []ast.Node{s.Init, s.Tag}
			for _, c := range s.Body.List {
				if cc, ok := c.(*ast.CaseClause); ok {
					for _, e := range cc.List {
						before = append(before, e)
					}
				}
			}
			exitInside = useInNode(use, s.Init) || useInNode(use, s.Tag)
		case *ast.TypeSwitchStmt:
			before = []ast.Node{s.Init, s.Assign}
			exitInside = useInNode(use, s.Init) || useInNode(use, s.Assign)
		case *ast.ForStmt:
			before = []ast.Node{s.Init, s.Cond}
			exitInside = useInNode(use, s.Init) || useInNode(use, s.Cond)
		case *ast.RangeStmt:
			before = []ast.Node{s.Key, s.Value, s.X}
			exitInside = useInNode(use, s.X)
		default:
			return true
		}
		if !refsAnyObject(pkg, before, objs) {
			return true
		}
		switch {
		case exitInside:
			return true // the sink runs with (or before) the condition
		case stmt.End() <= use.Pos():
			bad = fmt.Errorf("library payload: an unmodeled payload condition precedes the sink")
			return false
		case stmt.Pos() < use.Pos() && use.Pos() <= stmt.End():
			bad = fmt.Errorf("library payload: the sink is guarded by an unmodeled payload condition")
			return false
		}
		return true
	})
	return bad
}

func useInNode(use, node ast.Node) bool {
	if use == nil || node == nil {
		return false
	}
	return node.Pos() <= use.Pos() && use.End() <= node.End()
}

func refsAnyObject(pkg *packages.Package, nodes []ast.Node, objs map[types.Object]bool) bool {
	if pkg == nil || pkg.TypesInfo == nil || len(objs) == 0 {
		return false
	}
	for _, n := range nodes {
		if n == nil {
			continue
		}
		found := false
		ast.Inspect(n, func(x ast.Node) bool {
			id, ok := x.(*ast.Ident)
			if !ok {
				return true
			}
			if o := pkg.TypesInfo.ObjectOf(id); o != nil && objs[o] {
				found = true
				return false
			}
			return true
		})
		if found {
			return true
		}
	}
	return false
}

// exactArgumentSite resolves the traced call to an exact file/line/column
// witness site. A column-pinned request always does; a line-only request only
// when that line starts a single call — an ambiguous line-only location cannot
// name an exact sink argument.
// mutablePayloadCarrier reports whether t is a carrier a call could rewrite: a
// byte slice (including defined types with that representation) or the
// canonical io.Reader, whose read position is consumable state. Strings are
// immutable, so handing one to a call cannot change the payload bytes.
func mutablePayloadCarrier(t types.Type) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	if named, ok := t.(*types.Named); ok && canonicalIOReader(named) {
		return true
	}
	_, ok := t.Underlying().(*types.Slice)
	return ok
}

// mutableAliasType reports whether a value of type t can carry the mutability of
// a tracked carrier: byte slices, pointers and interfaces can; strings and
// scalars cannot.
func mutableAliasType(t types.Type) bool {
	if t == nil {
		return true // unknown type: stay conservative
	}
	t = types.Unalias(t)
	switch t.Underlying().(type) {
	case *types.Slice, *types.Pointer, *types.Interface:
		return true
	}
	return false
}

// assignedVar returns the variable an assignment target binds, if any.
func assignedVar(pkg *packages.Package, expr ast.Expr) *types.Var {
	id, ok := expr.(*ast.Ident)
	if !ok || pkg == nil || pkg.TypesInfo == nil {
		return nil
	}
	v, _ := pkg.TypesInfo.ObjectOf(id).(*types.Var)
	return v
}

// valueRefersCarrier reports whether expr evaluates to a tracked mutable carrier
// value: the object itself, an alias, a conversion of it, a slice/index of it,
// its address, or the result of a proven payload-preserving helper call.
func valueRefersCarrier(pkg *packages.Package, expr ast.Expr, tracked map[types.Object]bool, carrierCalls map[*ast.CallExpr]bool) bool {
	if expr == nil || pkg == nil || pkg.TypesInfo == nil {
		return false
	}
	for {
		switch e := expr.(type) {
		case *ast.ParenExpr:
			expr = e.X
		case *ast.SliceExpr:
			expr = e.X
		case *ast.IndexExpr:
			expr = e.X
		case *ast.StarExpr:
			expr = e.X
		case *ast.UnaryExpr:
			if e.Op != token.AND {
				return false
			}
			expr = e.X
		case *ast.CallExpr:
			if tv, ok := pkg.TypesInfo.Types[e.Fun]; ok && tv.IsType() && len(e.Args) == 1 && !e.Ellipsis.IsValid() {
				expr = e.Args[0]
				continue
			}
			return carrierCalls[e]
		case *ast.Ident:
			return tracked[pkg.TypesInfo.ObjectOf(e)]
		default:
			return false
		}
	}
}

// libraryMutableAliases extends the tracked carriers with locals assigned a
// carrier value — a re-assignment aliasing the same bytes, a slice/index of it,
// its address, or a preserving helper result. Mutating such an alias mutates
// the payload, so the mutation scan must see it.
func libraryMutableAliases(pkg *packages.Package, enc *ast.FuncDecl, seed map[types.Object]bool, carrierCalls map[*ast.CallExpr]bool) map[types.Object]bool {
	tracked := map[types.Object]bool{}
	for obj := range seed {
		tracked[obj] = true
	}
	if enc == nil || enc.Body == nil {
		return tracked
	}
	for changed := true; changed; {
		changed = false
		ast.Inspect(enc.Body, func(n ast.Node) bool {
			switch s := n.(type) {
			case *ast.AssignStmt:
				for i, lhs := range s.Lhs {
					obj := assignedVar(pkg, lhs)
					if obj == nil || tracked[obj] {
						continue
					}
					var rhs ast.Expr
					switch {
					case len(s.Lhs) == len(s.Rhs) && i < len(s.Rhs):
						rhs = s.Rhs[i]
					case len(s.Rhs) == 1:
						rhs = s.Rhs[0]
					}
					if rhs == nil || !valueRefersCarrier(pkg, rhs, tracked, carrierCalls) {
						continue
					}
					if !mutableAliasType(obj.Type()) {
						continue
					}
					tracked[obj] = true
					changed = true
				}
			case *ast.ValueSpec:
				for i, name := range s.Names {
					if i >= len(s.Values) {
						continue
					}
					obj := assignedVar(pkg, name)
					if obj == nil || tracked[obj] {
						continue
					}
					if !valueRefersCarrier(pkg, s.Values[i], tracked, carrierCalls) {
						continue
					}
					if !mutableAliasType(obj.Type()) {
						continue
					}
					tracked[obj] = true
					changed = true
				}
			}
			return true
		})
	}
	return tracked
}

// nonMutatingCarrierUse reports whether a builtin call may see a tracked carrier
// without rewriting its visible bytes. len/cap only read the header; append and
// copy are read-only only while the carrier is not the written destination
// (append(payload, ...) writes past len, but append(payload[:0], ...) reuses the
// backing array inside the visible bytes).
func nonMutatingCarrierUse(pkg *packages.Package, call *ast.CallExpr, tracked map[types.Object]bool) bool {
	id, ok := call.Fun.(*ast.Ident)
	if !ok || pkg == nil || pkg.TypesInfo == nil {
		return false
	}
	if _, isBuiltin := pkg.TypesInfo.Uses[id].(*types.Builtin); !isBuiltin {
		return false
	}
	switch id.Name {
	case "len", "cap":
		// Read-only header inspection.
		return true
	case "append":
		// append writes at len(left), which is past the visible bytes for
		// append(carrier, ...), but reuses the backing array for a re-sliced
		// carrier such as append(payload[:0], ...) — only a non-carrier
		// destination is safe.
		return len(call.Args) >= 1 && !valueRefersCarrier(pkg, call.Args[0], tracked, nil)
	case "copy":
		// Read-only when the carrier is the source, mutating as the destination.
		return len(call.Args) >= 1 && !valueRefersCarrier(pkg, call.Args[0], tracked, nil)
	}
	return false
}

// callUsesCarrierValue reports whether the call hands a tracked carrier value to
// the callee (argument or receiver).
func callUsesCarrierValue(pkg *packages.Package, call *ast.CallExpr, tracked map[types.Object]bool, carrierCalls map[*ast.CallExpr]bool) bool {
	if call == nil {
		return false
	}
	if recv := callReceiverExpr(pkg, call); recv != nil && valueRefersCarrier(pkg, recv, tracked, carrierCalls) {
		return true
	}
	for _, arg := range call.Args {
		if valueRefersCarrier(pkg, arg, tracked, carrierCalls) {
			return true
		}
	}
	return false
}

func callLabel(pkg *packages.Package, call *ast.CallExpr) string {
	if fn, ok := calleeObject(pkg.TypesInfo, call.Fun).(*types.Func); ok && fn != nil {
		return fn.Name()
	}
	if id, ok := call.Fun.(*ast.Ident); ok {
		return id.Name
	}
	return "an unmodeled call"
}

// checkCallMutations rejects a binding whose mutable payload carrier (or a
// recorded alias of it) is handed to a call that may rewrite it. Only the proof
// chain's own calls, type conversions and the read-only builtins may see a live
// carrier; everything else — clear, copy with the carrier as destination,
// delete, method calls and unknown functions — fails the walk.
func checkCallMutations(pkg *packages.Package, enc *ast.FuncDecl, objs map[types.Object]bool, allowed, carrierCalls map[*ast.CallExpr]bool) error {
	if enc == nil || enc.Body == nil || pkg == nil || pkg.TypesInfo == nil {
		return nil
	}
	carriers := map[types.Object]bool{}
	for obj := range objs {
		if v, ok := obj.(*types.Var); ok && mutablePayloadCarrier(v.Type()) {
			carriers[obj] = true
		}
	}
	if len(carriers) == 0 {
		return nil
	}
	tracked := libraryMutableAliases(pkg, enc, carriers, carrierCalls)
	var bad error
	ast.Inspect(enc.Body, func(n ast.Node) bool {
		if bad != nil {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		// A conversion cannot rewrite the carrier; the walk validates it as
		// byte-preserving separately.
		if tv, isType := pkg.TypesInfo.Types[call.Fun]; isType && tv.IsType() {
			return true
		}
		if allowed[call] {
			return true
		}
		if nonMutatingCarrierUse(pkg, call, tracked) {
			return true
		}
		if !callUsesCarrierValue(pkg, call, tracked, carrierCalls) {
			return true
		}
		bad = fmt.Errorf("library payload: %s may rewrite the mutable payload carrier", callLabel(pkg, call))
		return false
	})
	return bad
}

// errorInterface is the universe error interface. Error results are excluded
// from payload-derived predicate tracking: an error test is control flow, not a
// payload-content guard (a sink in an if initializer runs before it, and
// io.ReadAll's error result carries no payload bytes).
var errorInterface = types.Universe.Lookup("error").Type().Underlying().(*types.Interface)

func errorLikeType(t types.Type) bool {
	if t == nil {
		return false
	}
	if _, ok := t.(*types.TypeParam); ok {
		return false
	}
	return types.Implements(types.Unalias(t), errorInterface)
}

// libraryGuardObjects extends the payload objects with every value derived from
// them: function results, comparisons, scalar and boolean temporaries and their
// reassignments. A conditional over any of them before the sink is an unmodeled
// payload guard.
func libraryGuardObjects(pkg *packages.Package, enc *ast.FuncDecl, objs map[types.Object]bool) map[types.Object]bool {
	tracked := map[types.Object]bool{}
	for obj := range objs {
		tracked[obj] = true
	}
	if enc == nil || enc.Body == nil || pkg == nil || pkg.TypesInfo == nil {
		return tracked
	}
	add := func(obj *types.Var, rhs ast.Expr, changed *bool) {
		if obj == nil || rhs == nil || tracked[obj] || errorLikeType(obj.Type()) {
			return
		}
		if !nodeRefsObject(pkg, rhs, tracked) {
			return
		}
		tracked[obj] = true
		*changed = true
	}
	for changed := true; changed; {
		changed = false
		ast.Inspect(enc.Body, func(n ast.Node) bool {
			switch s := n.(type) {
			case *ast.AssignStmt:
				for i, lhs := range s.Lhs {
					var rhs ast.Expr
					switch {
					case len(s.Lhs) == len(s.Rhs) && i < len(s.Rhs):
						rhs = s.Rhs[i]
					case len(s.Rhs) == 1:
						rhs = s.Rhs[0]
					}
					add(assignedVar(pkg, lhs), rhs, &changed)
				}
			case *ast.ValueSpec:
				for i, name := range s.Names {
					if i < len(s.Values) {
						add(assignedVar(pkg, name), s.Values[i], &changed)
					}
				}
			case *ast.RangeStmt:
				if s.X == nil || !nodeRefsObject(pkg, s.X, tracked) {
					return true
				}
				for _, e := range []ast.Expr{s.Key, s.Value} {
					add(assignedVar(pkg, e), s.X, &changed)
				}
			}
			return true
		})
	}
	return tracked
}

func nodeRefsObject(pkg *packages.Package, node ast.Node, objs map[types.Object]bool) bool {
	return refsAnyObject(pkg, []ast.Node{node}, objs)
}

func (ix *Index) exactArgumentSite(requested domain.CallSite, pkg *packages.Package, enc *ast.FuncDecl, call *ast.CallExpr) (domain.CallSite, bool) {
	if call == nil || ix.fset == nil {
		return domain.CallSite{}, false
	}
	site := ix.siteOf(pkg, enc, call)
	if site.File == "" || site.Line == 0 || site.Column == 0 {
		return domain.CallSite{}, false
	}
	if requested.Column != 0 {
		return site, true
	}
	return site, ix.callsStartingOnLine(pkg, call, site.Line) == 1
}

// callsStartingOnLine counts the call expressions whose opening parenthesis
// starts on line in the file that contains call.
func (ix *Index) callsStartingOnLine(pkg *packages.Package, call *ast.CallExpr, line int) int {
	if pkg == nil || call == nil {
		return 0
	}
	for _, f := range pkg.Syntax {
		if call.Pos() < f.Pos() || call.End() > f.End() {
			continue
		}
		count := 0
		ast.Inspect(f, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				pos := ix.fset.Position(c.Lparen)
				if pos.Line == line {
					count++
				}
			}
			return true
		})
		return count
	}
	return 0
}

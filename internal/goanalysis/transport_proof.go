package goanalysis

// This file proves the two transport propositions Task 4 owns:
//
//	1. the product feeds the affected server transport from a production
//	   root: package main → ... → Serve(constructed server, constructed
//	   listener) → path into the affected transport;
//	2. the mechanism lifecycle is present in the affected source and the fix
//	   that closes it is absent — for http2-rapid-reset the peer's frames
//	   create/reset streams, handler execution is asynchronous, reset removes
//	   the stream without joining the handler, and the fixed pre-dispatch
//	   handler quota does not exist yet.
//
// Both are structured source bindings with digests. Nothing here branches on a
// repository name, a benchmark id or a CVE number: the mechanism is discovered
// from the affected module's own source and bound to supplied fix evidence.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/types"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/tools/go/packages"

	"github.com/fedorovmv/izyan/internal/domain"
)

const (
	// transportMaxRootHops bounds the climb from the Serve call to a
	// package main root.
	transportMaxRootHops = 32
	// transportMaxTransportHops bounds the intra-module walk from Serve to
	// the frame loop.
	transportMaxTransportHops = 16
	// transportMaxOriginHops bounds listener-parameter pass-through
	// resolution.
	transportMaxOriginHops = 3
	// transportMaxSourceBytes bounds one quoted source slice.
	transportMaxSourceBytes = 64 << 10

	// transportServeMethod is the module-owned server method whose call the
	// rooted proof starts from. The receiver type is read from the typed
	// call, so a product-side helper coincidentally called Serve never
	// qualifies.
	transportServeMethod = "Serve"
)

// ProveServerTransport collects the rooted input proof and, when the affected
// module carries the mechanism lifecycle, the source/fix-bound trigger proof.
// Incompleteness is reported as typed gaps; only a load failure is an error.
//
// This is the specialized checker, so callers run it only after
// TransportProofRequestFor established applicability from the module's own
// source. The request's Mechanism is the probe's discovery result: an empty
// mechanism is not replaced by a default and yields no trigger proof.
func (ix *Index) ProveServerTransport(ctx context.Context, req domain.TransportProofRequest) (domain.TransportProof, error) {
	out := domain.TransportProof{}
	// The mechanism is a discovery result, never a default. A request that
	// names none gets no trigger proof: assuming http2-rapid-reset here would
	// let every peer-input case inherit a mechanism the source never
	// established. Callers obtain the applicable mechanism from
	// TransportProofRequestFor, which reads it from the module's own source.
	mechanism := req.Mechanism

	ix.mu.Lock()
	err := ix.load(ctx)
	if err != nil {
		ix.mu.Unlock()
		return out, err
	}
	module := ix.transportModuleLocked(req.Subjects)
	census := ix.transportCensusLocked()
	var modPkgs []*packages.Package
	var loadErr error
	if module != "" {
		modPkgs, loadErr = ix.loadExtra(ctx, module+"/...")
	}
	build := domain.EffectiveBuildContext(ix.Build)
	ix.mu.Unlock()

	if module == "" {
		out.Gaps = append(out.Gaps, domain.AnalysisGap{
			Owner:      domain.GapOwnerInput,
			Code:       domain.GapInputResolutionFailed,
			Obligation: domain.ObligationCondition,
			Message:    "rooted transport proof: no affected subject package maps to a module in the product's dependency graph",
		})
		return out, nil
	}
	if loadErr != nil {
		out.Gaps = append(out.Gaps, domain.AnalysisGap{
			Owner:      domain.GapOwnerCode,
			Code:       domain.GapProofArtifactMissing,
			Obligation: domain.ObligationCondition,
			Message:    fmt.Sprintf("rooted transport proof: affected module %s source failed to load: %v", module, loadErr),
		})
		return out, nil
	}

	mod := buildTransportModule(modPkgs, module)
	b := &transportProofBuilder{ix: ix, build: build, files: map[string][]byte{}}
	rooted, inputGap := b.proveInput(census, mod, module, req, mechanism)
	if rooted == nil {
		if inputGap == nil {
			inputGap = &domain.AnalysisGap{
				Owner:      domain.GapOwnerCode,
				Code:       domain.GapReachabilityProofIncomplete,
				Obligation: domain.ObligationCondition,
				Message:    "rooted transport proof: no production-rooted server transport path was established",
			}
		}
		out.Gaps = append(out.Gaps, *inputGap)
		out.Evidence = b.proof.Evidence
		return out, nil
	}
	out.Input = rooted.witness
	b.emitWitness(summaryInput(rooted.witness), rooted.witness, nil)

	if !transportMechanismSupported(mechanism) {
		out.Gaps = append(out.Gaps, domain.AnalysisGap{
			Owner:      domain.GapOwnerProof,
			Code:       domain.GapTriggerProofIncomplete,
			Obligation: domain.ObligationCondition,
			Message:    fmt.Sprintf("rooted transport proof: mechanism %q has no trigger obligation set", mechanism),
		})
		out.Evidence = b.proof.Evidence
		return out, nil
	}

	trigger, gaps := b.proveTrigger(mod, rooted, req, module, mechanism)
	out.Trigger = trigger
	out.Gaps = append(out.Gaps, gaps...)
	if trigger != nil {
		b.emitWitness(summaryTrigger(trigger), nil, trigger)
	}
	out.Evidence = b.proof.Evidence
	return out, nil
}

// emitWitness records the witness-carrying evidence: a persisted proof is
// re-admitted from evidence, never re-asserted by a caller flag.
func (b *transportProofBuilder) emitWitness(summary string, input *domain.TransportInputWitness, trigger *domain.TransportTriggerWitness) {
	build := b.build
	b.proof.Evidence = append(b.proof.Evidence, domain.Evidence{
		ID:               domain.EvidenceID(fmt.Sprintf("EV-transport-witness-%02d", len(b.proof.Evidence)+1)),
		Kind:             domain.EvidenceCallPath,
		Quality:          domain.QualityDeterministic,
		Source:           "source index: rooted transport proof",
		Tool:             "goanalysis.Index.ProveServerTransport",
		Content:          summary,
		BuildContext:     &build,
		TransportInput:   input,
		TransportTrigger: trigger,
		Limitations: []string{
			"rooted transport witness: a client of the affected transport supplies the triggering input; deployed reachability of that transport is not established",
		},
	})
}

func summaryInput(w *domain.TransportInputWitness) string {
	if w == nil {
		return ""
	}
	return fmt.Sprintf(
		"rooted transport input: record=%s module=%s root=%s chain=%d transport=%d",
		w.Record.RecordID, w.Module, w.Root.Package, len(w.Chain), len(w.Transport))
}

func summaryTrigger(w *domain.TransportTriggerWitness) string {
	if w == nil {
		return ""
	}
	var met []string
	for _, o := range w.Obligations {
		if o.Satisfied {
			met = append(met, string(o.ID))
		}
	}
	return fmt.Sprintf(
		"transport trigger: mechanism=%s record=%s obligations satisfied=%d/%d [%s] controls=%d",
		w.Mechanism, w.Record.RecordID, len(met), len(w.Obligations),
		strings.Join(met, ","), len(w.Controls))
}

// transportModuleLocked resolves the affected module identity from the
// advisory subjects through the product's own dependency graph. It holds no
// opinion about which module a CVE "belongs" to.
func (ix *Index) transportModuleLocked(subjects []domain.SymbolRef) string {
	best := ""
	for _, s := range subjects {
		if s.Package == "" {
			continue
		}
		if m := ix.depModuleOf(s.Package); m != "" {
			if len(m) > len(best) {
				best = m
			}
			continue
		}
		for _, mod := range ix.pkgModules {
			if mod == "" || !domain.PackageInModule(s.Package, mod) {
				continue
			}
			if len(mod) > len(best) {
				best = mod
			}
		}
	}
	return best
}

func transportMechanismSupported(mechanism string) bool {
	return mechanism == domain.MechanismHTTP2RapidReset
}

// transportProofBuilder emits source bindings and the evidence that pins them.
type transportProofBuilder struct {
	ix    *Index
	build domain.BuildContext
	proof domain.TransportProof
	files map[string][]byte
	// evidenceIDs remembers every emitted binding so the witnesses can
	// reference their own audit trail.
	evidenceIDs []domain.EvidenceID
}

// sourceOf reads a file once per proof.
func (b *transportProofBuilder) sourceOf(file string) ([]byte, error) {
	if data, ok := b.files[file]; ok {
		return data, nil
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	b.files[file] = data
	return data, nil
}

// emit binds one exact source slice: the bytes are hashed, stored verbatim in
// a deterministic source-snippet evidence record, and referenced by the
// returned site. A slice that cannot be read exactly is an error, never an
// approximate binding.
func (b *transportProofBuilder) emit(
	kind domain.TransportSiteKind,
	sym domain.SymbolRef,
	file string,
	startLine, endLine, startOff, endOff int,
	call domain.CallSite,
	detail string,
) (domain.TransportSite, error) {
	data, err := b.sourceOf(file)
	if err != nil {
		return domain.TransportSite{}, fmt.Errorf("read %s: %w", file, err)
	}
	if startOff < 0 || endOff > len(data) || startOff >= endOff {
		return domain.TransportSite{}, fmt.Errorf("read %s: slice [%d,%d) is outside the file", file, startOff, endOff)
	}
	src := string(data[startOff:endOff])
	if len(src) > transportMaxSourceBytes {
		return domain.TransportSite{}, fmt.Errorf("read %s: source slice of %d bytes exceeds the %d-byte bound",
			file, len(src), transportMaxSourceBytes)
	}
	sum := sha256.Sum256([]byte(src))
	digest := "sha256:" + hex.EncodeToString(sum[:])
	build := b.build
	ev := domain.Evidence{
		ID:           domain.EvidenceID(fmt.Sprintf("EV-transport-%03d", len(b.proof.Evidence)+1)),
		Kind:         domain.EvidenceSourceSnippet,
		Quality:      domain.QualityDeterministic,
		Source:       "source index: rooted transport proof",
		Tool:         "goanalysis.Index.ProveServerTransport",
		File:         file,
		StartLine:    startLine,
		EndLine:      endLine,
		Content:      src,
		ArtifactHash: digest,
		BuildContext: &build,
		Limitations: []string{
			"rooted transport source slice: exact vendored/product bytes, scoped to the analyzed build; it confers no negative completeness beyond this witness",
		},
	}
	b.proof.Evidence = append(b.proof.Evidence, ev)
	b.evidenceIDs = append(b.evidenceIDs, ev.ID)
	if call.File == "" {
		call = domain.CallSite{File: file, Line: startLine, Package: sym.Package, Function: sym.Symbol}
	}
	return domain.TransportSite{
		Kind:     kind,
		Symbol:   sym,
		CallSite: call,
		Digest:   digest,
		Source:   src,
		Detail:   detail,
	}, nil
}

// emitFunc binds a whole function body.
func (b *transportProofBuilder) emitFunc(
	kind domain.TransportSiteKind,
	sym domain.SymbolRef,
	decl *ast.FuncDecl,
	detail string,
) (domain.TransportSite, error) {
	start := b.ix.fset.Position(decl.Pos())
	end := b.ix.fset.Position(decl.End())
	return b.emit(kind, sym, start.Filename, start.Line, end.Line, start.Offset, end.Offset,
		domain.CallSite{
			File:     start.Filename,
			Line:     start.Line,
			Column:   1,
			Package:  sym.Package,
			Function: sym.Symbol,
		}, detail)
}

// emitNode binds one AST node inside file.
func (b *transportProofBuilder) emitNode(
	kind domain.TransportSiteKind,
	sym domain.SymbolRef,
	node ast.Node,
	call domain.CallSite,
	detail string,
) (domain.TransportSite, error) {
	start := b.ix.fset.Position(node.Pos())
	end := b.ix.fset.Position(node.End())
	return b.emit(kind, sym, start.Filename, start.Line, end.Line, start.Offset, end.Offset, call, detail)
}

// ---------------------------------------------------------------------------
// Product census
// ---------------------------------------------------------------------------

type transportCall struct {
	caller  string // enclosing function key
	pkgPath string // callee package
	recv    string // callee receiver type name
	name    string // callee name
	site    domain.CallSite
	call    *ast.CallExpr
	args    []ast.Expr
	fun     ast.Expr
	goStmt  bool
}

// calleeKey is the module/product function identity of this call.
func (c transportCall) calleeKey() string { return transportFuncKey(c.pkgPath, c.recv, c.name) }

type transportFunc struct {
	key        string
	pkgPath    string
	pkgName    string
	recv       string
	recvType   types.Type
	name       string
	pkg        *packages.Package
	decl       *ast.FuncDecl
	file       string
	production bool
	mainFunc   bool
	calls      []transportCall
}

// transportRegistration records one command-handler field registration: the
// product function whose body installs handler on a command value.
type transportRegistration struct {
	handler   string
	registrar string
	field     string
	node      ast.Node
	site      domain.CallSite
}

// transportIfaceCall is one call through an interface method. The dispatch
// target is resolved after the census: a call on the interface reaches every
// product implementation of the method, so the caller climb must not stop at
// the interface declaration.
type transportIfaceCall struct {
	call   transportCall
	iface  *types.Interface
	method string
}

type transportCensus struct {
	funcs    map[string]*transportFunc
	callers  map[string][]transportCall // callee key → call sites
	products map[string]bool            // product package paths
	// registrations index command-handler field registrations by handler key.
	registrations map[string][]transportRegistration
	// ifaceCalls are the interface-method calls resolved after indexing.
	ifaceCalls []transportIfaceCall
	// closureKeys maps a value-used function literal to its closure node, so a
	// registered literal handler has its own identity in the call graph.
	closureKeys map[*ast.FuncLit]string
	root        string
}

func transportFuncKey(pkgPath, recv, name string) string {
	if recv != "" {
		return pkgPath + "." + recv + "." + name
	}
	return pkgPath + "." + name
}

// transportCensusLocked indexes the product's own functions and their typed
// call edges. Only product packages (the loaded ./... roots) are indexed: a
// dependency callee is recorded with its module identity but never becomes a
// product caller.
func (ix *Index) transportCensusLocked() *transportCensus {
	c := &transportCensus{
		funcs:         map[string]*transportFunc{},
		callers:       map[string][]transportCall{},
		products:      map[string]bool{},
		registrations: map[string][]transportRegistration{},
		closureKeys:   map[*ast.FuncLit]string{},
		root:          ix.Dir,
	}
	for _, pkg := range ix.pkgs {
		c.products[pkg.PkgPath] = true
	}
	for _, pkg := range ix.pkgs {
		if pkg.TypesInfo == nil {
			continue
		}
		for _, f := range pkg.Syntax {
			file := ix.fset.Position(f.Pos()).Filename
			if strings.HasSuffix(file, "_test.go") {
				continue
			}
			production := ix.transportProductionFile(file)
			for _, decl := range f.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Name == nil || fd.Body == nil {
					continue
				}
				recv := ""
				if fd.Recv != nil && len(fd.Recv.List) > 0 {
					recv = recvDeclName(fd.Recv.List[0].Type)
				}
				tf := &transportFunc{
					key:        transportFuncKey(pkg.PkgPath, recv, fd.Name.Name),
					pkgPath:    pkg.PkgPath,
					pkgName:    pkg.Name,
					recv:       recv,
					name:       fd.Name.Name,
					pkg:        pkg,
					decl:       fd,
					file:       file,
					production: production,
					mainFunc:   pkg.Name == "main" && recv == "" && fd.Name.Name == "main",
				}
				if obj, ok := pkg.TypesInfo.Defs[fd.Name].(*types.Func); ok {
					if sig, ok := obj.Type().(*types.Signature); ok && sig.Recv() != nil {
						tf.recvType = sig.Recv().Type()
					}
				}
				c.funcs[tf.key] = tf
				c.scanBody(ix, tf)
				c.collectRegistrations(tf, pkg.TypesInfo)
			}
		}
	}
	c.resolveInterfaceDispatch(c.ifaceCalls)
	return c
}

// scanBody records the calls of one function body. A literal that is invoked
// in place runs as part of the enclosing function; a literal used as a value
// runs later, under the callee's control, so it becomes its own closure node
// and is not attributed to the enclosing function. Without that split a
// registered command handler would read as an unconditional call made by its
// constructor, and a package main that merely builds the command would pass for
// a served transport.
func (c *transportCensus) scanBody(ix *Index, owner *transportFunc) {
	info := owner.pkg.TypesInfo
	var walk func(node ast.Node, fn *transportFunc)
	walk = func(node ast.Node, fn *transportFunc) {
		inline := map[*ast.FuncLit]bool{}
		ast.Inspect(node, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if lit, ok := unparen(call.Fun).(*ast.FuncLit); ok {
				inline[lit] = true
			}
			return true
		})
		goCalls := map[*ast.CallExpr]bool{}
		ast.Inspect(node, func(n ast.Node) bool {
			switch current := n.(type) {
			case *ast.GoStmt:
				if current.Call != nil {
					goCalls[current.Call] = true
				}
			case *ast.FuncLit:
				if inline[current] {
					return true
				}
				closure := &transportFunc{
					key:        closureKey(fn, current),
					pkgPath:    fn.pkgPath,
					pkgName:    fn.pkgName,
					name:       fn.name + "$func",
					pkg:        fn.pkg,
					production: fn.production,
					file:       fn.file,
					decl:       &ast.FuncDecl{Type: current.Type, Body: current.Body},
				}
				c.funcs[closure.key] = closure
				c.closureKeys[current] = closure.key
				walk(current.Body, closure)
				return false
			case *ast.CallExpr:
				obj := calleeObject(info, current.Fun)
				callee, ok := obj.(*types.Func)
				if !ok || callee.Pkg() == nil {
					return true
				}
				calleeRecv := ""
				if sig, ok := callee.Type().(*types.Signature); ok && sig.Recv() != nil {
					calleeRecv = recvTypeName(sig.Recv().Type())
				}
				lparen := ix.fset.Position(current.Lparen)
				tc := transportCall{
					caller:  fn.key,
					pkgPath: callee.Pkg().Path(),
					recv:    calleeRecv,
					name:    callee.Name(),
					call:    current,
					args:    current.Args,
					fun:     current.Fun,
					goStmt:  goCalls[current],
					site: domain.CallSite{
						File:        lparen.Filename,
						Line:        lparen.Line,
						Column:      lparen.Column,
						Package:     fn.pkgPath,
						Function:    fn.name,
						Receiver:    fn.recv,
						Callee:      callee.Name(),
						ModuleOwner: callee.Pkg().Path(),
					},
				}
				fn.calls = append(fn.calls, tc)
				if c.products[tc.pkgPath] {
					c.callers[tc.calleeKey()] = append(c.callers[tc.calleeKey()], tc)
				}
				if iface := interfaceOfReceiver(callee); iface != nil {
					c.ifaceCalls = append(c.ifaceCalls, transportIfaceCall{
						call: tc, iface: iface, method: callee.Name(),
					})
				}
			}
			return true
		})
	}
	walk(owner.decl.Body, owner)
}

// closureKey names the closure node of a value-used literal.
func closureKey(owner *transportFunc, lit *ast.FuncLit) string {
	return owner.key + "$L" + strconv.Itoa(int(lit.Pos()))
}

// resolveInterfaceDispatch links every interface-method call to the product
// implementations of that method, so an interface indirection does not break
// the production-root climb. Only implementations of the exact interface are
// linked: the edge is a resolved static-dispatch fact, not a name match.
func (c *transportCensus) resolveInterfaceDispatch(dispatches []transportIfaceCall) {
	if len(dispatches) == 0 {
		return
	}
	byMethod := map[string][]*transportFunc{}
	for _, fn := range c.funcs {
		if fn.recv == "" || fn.recvType == nil {
			continue
		}
		byMethod[fn.name] = append(byMethod[fn.name], fn)
	}
	for _, dispatch := range dispatches {
		for _, impl := range byMethod[dispatch.method] {
			if !implementsInterface(impl.recvType, dispatch.iface) {
				continue
			}
			c.callers[impl.key] = append(c.callers[impl.key], dispatch.call)
		}
	}
}

// interfaceOfReceiver returns the interface a method belongs to, or nil when
// the receiver is concrete.
func interfaceOfReceiver(fn *types.Func) *types.Interface {
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return nil
	}
	t := types.Unalias(sig.Recv().Type())
	if ptr, ok := t.(*types.Pointer); ok {
		t = types.Unalias(ptr.Elem())
	}
	if named, ok := t.(*types.Named); ok {
		if iface, ok := named.Underlying().(*types.Interface); ok {
			return iface
		}
	}
	if iface, ok := t.(*types.Interface); ok {
		return iface
	}
	return nil
}

// implementsInterface reports whether recv (or its pointer type) implements
// iface.
func implementsInterface(recv types.Type, iface *types.Interface) bool {
	if recv == nil || iface == nil {
		return false
	}
	if types.Implements(recv, iface) {
		return true
	}
	if _, ok := types.Unalias(recv).(*types.Pointer); ok {
		return false
	}
	return types.Implements(types.NewPointer(recv), iface)
}

// transportHandlerFields are the command-handler fields whose registration is
// positive evidence that a function is a command entry point.
var transportHandlerFields = map[string]bool{"Run": true, "RunE": true}

// transportCommandRunners are the calls that execute a command value. A
// registered handler counts only when the command carrying it is run.
var transportCommandRunners = map[string]bool{
	"Run": true, "RunCommand": true, "RunContext": true,
	"Execute": true, "ExecuteC": true, "ExecuteContext": true,
}

// collectRegistrations records the command-handler field registrations inside
// fn: a composite-literal handler field or a handler-field assignment whose
// value is a product function.
func (c *transportCensus) collectRegistrations(fn *transportFunc, info *types.Info) {
	ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.KeyValueExpr:
			field := handlerFieldName(node.Key)
			if field == "" {
				return true
			}
			key, ok := c.registeredHandlerKey(info, node.Value)
			if !ok {
				return true
			}
			c.registrations[key] = append(c.registrations[key], transportRegistration{
				handler: key, registrar: fn.key, field: field,
				node: node, site: siteOfNode(fn, node),
			})
		case *ast.AssignStmt:
			if len(node.Lhs) != 1 || len(node.Rhs) != 1 {
				return true
			}
			sel, ok := unparen(node.Lhs[0]).(*ast.SelectorExpr)
			if !ok {
				return true
			}
			field := handlerFieldName(sel.Sel)
			if field == "" {
				return true
			}
			key, ok := c.registeredHandlerKey(info, node.Rhs[0])
			if !ok {
				return true
			}
			c.registrations[key] = append(c.registrations[key], transportRegistration{
				handler: key, registrar: fn.key, field: field,
				node: node, site: siteOfNode(fn, node),
			})
		}
		return true
	})
}

// registeredHandlerKey resolves a handler-field value to the graph node that
// carries the handler body. A named function is its own node; a value-used
// literal is the closure node created for it, because that is where its body
// (and therefore its calls) live.
func (c *transportCensus) registeredHandlerKey(info *types.Info, expr ast.Expr) (string, bool) {
	if key, ok := funcValueKey(info, expr); ok {
		return key, true
	}
	if lit, ok := unparen(expr).(*ast.FuncLit); ok {
		key, found := c.closureKeys[lit]
		return key, found
	}
	return "", false
}

// handlerFieldName returns the frozen handler-field name of a key expression.
func handlerFieldName(expr ast.Expr) string {
	id, ok := unparen(expr).(*ast.Ident)
	if !ok || !transportHandlerFields[id.Name] {
		return ""
	}
	return id.Name
}

// funcValueKey resolves an expression used as a function value to the product
// function key it names.
func funcValueKey(info *types.Info, expr ast.Expr) (string, bool) {
	if info == nil || expr == nil {
		return "", false
	}
	switch e := unparen(expr).(type) {
	case *ast.Ident:
		return funcKeyOfObject(info.Uses[e])
	case *ast.SelectorExpr:
		if sel, ok := info.Selections[e]; ok {
			return funcKeyOfObject(sel.Obj())
		}
		return funcKeyOfObject(info.Uses[e.Sel])
	case *ast.IndexExpr:
		return funcValueKey(info, e.X)
	}
	return "", false
}

// funcKeyOfObject resolves a typed function object to its product key.
func funcKeyOfObject(obj types.Object) (string, bool) {
	fn, ok := obj.(*types.Func)
	if !ok || fn.Pkg() == nil {
		return "", false
	}
	recv := ""
	if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
		recv = recvTypeName(sig.Recv().Type())
	}
	return transportFuncKey(fn.Pkg().Path(), recv, fn.Name()), true
}

// siteOfNode records where node lives inside fn.
func siteOfNode(fn *transportFunc, node ast.Node) domain.CallSite {
	pos := fn.pkg.Fset.Position(node.Pos())
	site := domain.CallSite{
		File:     pos.Filename,
		Line:     pos.Line,
		Column:   pos.Column,
		Package:  fn.pkgPath,
		Function: fn.name,
	}
	if fn.recv != "" {
		site.Receiver = fn.recv
	}
	return site
}

// transportProductionFile reports whether file is production product source:
// no test, no fixture/example/mock directory, and (relative to the analyzed
// root) not in the repository's top-level test tree.
func (ix *Index) transportProductionFile(file string) bool {
	if strings.HasSuffix(file, "_test.go") {
		return false
	}
	slash := filepath.ToSlash(file)
	parts := strings.Split(slash, "/")
	for _, part := range parts {
		switch part {
		case "testdata", "examples", "example", "mocks", "mock", "fake", "fakes":
			return false
		}
	}
	if ix.Dir != "" {
		if rel, err := filepath.Rel(ix.Dir, file); err == nil {
			rel = filepath.ToSlash(rel)
			switch {
			case strings.HasPrefix(rel, "test/"):
				return false
			case strings.HasPrefix(rel, "tests/"):
				return false
			}
		}
	}
	return true
}

// serveCandidates returns the product call sites of the module's Serve method,
// ordered deterministically.
func (c *transportCensus) serveCandidates(module string) []transportCall {
	var out []transportCall
	for _, fn := range c.funcs {
		for _, call := range fn.calls {
			if call.name != transportServeMethod || call.recv == "" {
				continue
			}
			if !domain.PackageInModule(call.pkgPath, module) {
				continue
			}
			if len(call.args) == 0 {
				continue
			}
			out = append(out, call)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].site.File != out[j].site.File {
			return out[i].site.File < out[j].site.File
		}
		return out[i].site.Line < out[j].site.Line
	})
	return out
}

// ---------------------------------------------------------------------------
// Rooted input proof
// ---------------------------------------------------------------------------

type transportRootedPath struct {
	witness *domain.TransportInputWitness
	// serveKey is the module function key of the Serve method the product
	// calls; the intra-module walk starts from it.
	serveKey      string
	construction  transportCall
	serveCall     transportCall
	listener      transportCall
	census        *transportCensus
	chain         []*transportFunc
	callerFunc    *transportFunc
	transportPath []*transportModuleFunc
	loopFn        *transportModuleFunc
	// registration is set when the production entry is a command handler
	// registered through Run/RunE rather than a direct package main call.
	registration *transportRegistration
	registrar    *transportFunc
	entry        []transportEntryEvidence
}

func (b *transportProofBuilder) proveInput(
	census *transportCensus,
	mod *transportModule,
	module string,
	req domain.TransportProofRequest,
	mechanism string,
) (*transportRootedPath, *domain.AnalysisGap) {
	candidates := census.serveCandidates(module)
	if len(candidates) == 0 {
		return nil, &domain.AnalysisGap{
			Owner:      domain.GapOwnerCode,
			Code:       domain.GapReachabilityProofIncomplete,
			Obligation: domain.ObligationCondition,
			Message: fmt.Sprintf(
				"rooted transport proof: the product never calls %s on a %s server — no affected server transport is constructed and served",
				transportServeMethod, module),
		}
	}
	var failures []string
	for _, cand := range candidates {
		fn := census.funcs[cand.caller]
		if fn == nil {
			continue
		}
		rooted, err := b.bindCandidate(census, cand, fn)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s:%d: %v", cand.site.File, cand.site.Line, err))
			continue
		}
		path, loopFn := mod.pathToFrameLoop(rooted.serveKey)
		if loopFn == nil {
			failures = append(failures, fmt.Sprintf("%s:%d: Serve never reaches a peer-frame loop inside %s",
				cand.site.File, cand.site.Line, module))
			continue
		}
		rooted.transportPath = path
		rooted.loopFn = loopFn
		w, err := b.buildInputWitness(census, rooted, req, module, mechanism)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s:%d: %v", cand.site.File, cand.site.Line, err))
			continue
		}
		rooted.witness = w
		return rooted, nil
	}
	sort.Strings(failures)
	msg := "rooted transport proof: no Serve call is production-rooted with a constructed server and listener"
	if len(failures) > 0 {
		msg += "; rejected candidate(s): " + strings.Join(failures, "; ")
	}
	return nil, &domain.AnalysisGap{
		Owner:      domain.GapOwnerCode,
		Code:       domain.GapReachabilityProofIncomplete,
		Obligation: domain.ObligationCondition,
		Message:    msg,
	}
}

// bindCandidate resolves the value bindings of one Serve call: the server must
// be constructed by the affected module, the listener by product code, and the
// enclosing function must be reachable from a package main root.
func (b *transportProofBuilder) bindCandidate(
	census *transportCensus,
	cand transportCall,
	fn *transportFunc,
) (*transportRootedPath, error) {
	if !fn.production {
		return nil, fmt.Errorf("%s is not production source", fn.file)
	}
	sel, ok := cand.fun.(*ast.SelectorExpr)
	if !ok {
		return nil, fmt.Errorf("%s is not a method call", transportServeMethod)
	}
	rootedPath, err := census.rootPath(fn)
	if err != nil {
		return nil, err
	}
	construction, err := b.resolveConstruction(census, fn, sel.X, cand.pkgPath)
	if err != nil {
		return nil, err
	}
	listener, err := b.resolveListener(census, fn, cand.args[0], 0)
	if err != nil {
		return nil, err
	}
	return &transportRootedPath{
		serveKey:     transportFuncKey(cand.pkgPath, cand.recv, cand.name),
		construction: construction,
		serveCall:    cand,
		listener:     listener,
		census:       census,
		chain:        rootedPath.path,
		callerFunc:   fn,
		registration: rootedPath.registration,
		registrar:    rootedPath.registrar,
		entry:        rootedPath.entry,
	}, nil
}

type originKind int

const (
	originCall originKind = iota
	originParameter
	originMissing
	originAmbiguous
)

// localOrigin resolves a value expression to the single expression that
// produced it inside fn. A reassigned or multi-origin value is ambiguous: the
// proof needs one construction, not an "either of these".
func localOrigin(fn *transportFunc, expr ast.Expr) (ast.Expr, originKind) {
	expr = unparen(unaryBase(expr))
	if expr == nil {
		return nil, originMissing
	}
	var origins []ast.Expr
	add := func(rhs []ast.Expr, idx int) {
		if len(rhs) == 0 {
			return
		}
		if idx < len(rhs) {
			origins = append(origins, rhs[idx])
			return
		}
		if len(rhs) == 1 {
			origins = append(origins, rhs[0])
		}
	}
	ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.AssignStmt:
			if s.Tok.String() != "=" && s.Tok.String() != ":=" {
				return true
			}
			for i, lhs := range s.Lhs {
				if sameValueExpr(lhs, expr) {
					add(s.Rhs, i)
				}
			}
		case *ast.DeclStmt:
			gen, ok := s.Decl.(*ast.GenDecl)
			if !ok {
				return true
			}
			for _, spec := range gen.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					if !sameValueExpr(name, expr) {
						continue
					}
					if i < len(vs.Values) {
						origins = append(origins, vs.Values[i])
					} else if len(vs.Values) > 0 {
						origins = append(origins, vs.Values[0])
					}
				}
			}
		}
		return true
	})
	switch len(origins) {
	case 0:
		if isParamName(fn.decl, expr) {
			return nil, originParameter
		}
		return nil, originMissing
	case 1:
		return origins[0], originCall
	default:
		first := originKey(origins[0])
		for _, o := range origins[1:] {
			if originKey(o) != first {
				return nil, originAmbiguous
			}
		}
		return origins[0], originCall
	}
}

func unaryBase(expr ast.Expr) ast.Expr {
	for {
		switch e := expr.(type) {
		case *ast.StarExpr:
			expr = e.X
		case *ast.ParenExpr:
			expr = e.X
		case *ast.UnaryExpr:
			if e.Op.String() != "&" {
				return expr
			}
			expr = e.X
		default:
			return expr
		}
	}
}

func sameValueExpr(a, b ast.Expr) bool {
	a = unparen(unaryBase(a))
	b = unparen(unaryBase(b))
	switch av := a.(type) {
	case *ast.Ident:
		bv, ok := b.(*ast.Ident)
		return ok && av.Name == bv.Name
	case *ast.SelectorExpr:
		bv, ok := b.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		return av.Sel.Name == bv.Sel.Name && sameValueExpr(av.X, bv.X)
	}
	return false
}

func originKey(e ast.Expr) string {
	switch v := unparen(e).(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return originKey(v.X) + "." + v.Sel.Name
	case *ast.CallExpr:
		return fmt.Sprintf("call@%d", v.Pos())
	}
	return fmt.Sprintf("expr@%d", e.Pos())
}

func isParamName(decl *ast.FuncDecl, expr ast.Expr) bool {
	id, ok := unparen(expr).(*ast.Ident)
	if !ok || decl.Type.Params == nil {
		return false
	}
	for _, field := range decl.Type.Params.List {
		for _, name := range field.Names {
			if name.Name == id.Name {
				return true
			}
		}
	}
	return false
}

// resolveConstruction resolves the server receiver to a call of a function
// owned by the affected module.
func (b *transportProofBuilder) resolveConstruction(
	census *transportCensus,
	fn *transportFunc,
	expr ast.Expr,
	module string,
) (transportCall, error) {
	rhs, kind := localOrigin(fn, expr)
	switch kind {
	case originMissing:
		return transportCall{}, fmt.Errorf("the server value %s has no construction site in %s", exprText(expr), fn.name)
	case originParameter:
		return transportCall{}, fmt.Errorf("the server value %s is a parameter — the affected server is not constructed here", exprText(expr))
	case originAmbiguous:
		return transportCall{}, fmt.Errorf("the server value %s has multiple construction origins", exprText(expr))
	}
	call, ok := unparen(rhs).(*ast.CallExpr)
	if !ok {
		return transportCall{}, fmt.Errorf("the server value %s is not constructed by a call", exprText(expr))
	}
	found, ok := findCensusCall(fn, call)
	if !ok {
		return transportCall{}, fmt.Errorf("the construction call for %s does not resolve to a typed function", exprText(expr))
	}
	if !domain.PackageInModule(found.pkgPath, module) {
		return transportCall{}, fmt.Errorf("the server is constructed by %s, which is not owned by the affected module %s", found.pkgPath, module)
	}
	return found, nil
}

// resolveListener resolves the Serve argument to a product-owned listener
// construction. A parameter is followed into its callers so a pass-through
// helper still binds the construction that created the listener.
func (b *transportProofBuilder) resolveListener(
	census *transportCensus,
	fn *transportFunc,
	expr ast.Expr,
	depth int,
) (transportCall, error) {
	rhs, kind := localOrigin(fn, expr)
	switch kind {
	case originMissing:
		return transportCall{}, fmt.Errorf("the listener value %s has no construction site in %s", exprText(expr), fn.name)
	case originAmbiguous:
		return transportCall{}, fmt.Errorf("the listener value %s has multiple construction origins", exprText(expr))
	case originParameter:
		if depth >= transportMaxOriginHops {
			return transportCall{}, fmt.Errorf("the listener value %s is a parameter and the pass-through bound (%d) is exhausted",
				exprText(expr), transportMaxOriginHops)
		}
		return b.listenerFromCallers(census, fn, expr, depth)
	}
	call, ok := unparen(rhs).(*ast.CallExpr)
	if !ok {
		return transportCall{}, fmt.Errorf("the listener value %s is not constructed by a call", exprText(expr))
	}
	found, ok := findCensusCall(fn, call)
	if !ok {
		return transportCall{}, fmt.Errorf("the listener construction call for %s does not resolve to a typed function", exprText(expr))
	}
	if !transportListenerOrigin(census, found) {
		return transportCall{}, fmt.Errorf("the listener factory %s.%s is not product-owned listener construction",
			found.pkgPath, found.name)
	}
	return found, nil
}

// listenerFromCallers follows a listener parameter into the callers of fn and
// requires one agreed construction.
func (b *transportProofBuilder) listenerFromCallers(
	census *transportCensus,
	fn *transportFunc,
	expr ast.Expr,
	depth int,
) (transportCall, error) {
	idx := paramIndex(fn.decl, expr)
	if idx < 0 {
		return transportCall{}, fmt.Errorf("the listener parameter %s could not be located in %s", exprText(expr), fn.name)
	}
	sites := census.callers[fn.key]
	if len(sites) == 0 {
		return transportCall{}, fmt.Errorf("no product caller passes a listener into %s", fn.name)
	}
	var resolved []transportCall
	var failures []string
	for _, call := range sites {
		if idx >= len(call.args) {
			failures = append(failures, fmt.Sprintf("%s:%d passes no listener", call.site.File, call.site.Line))
			continue
		}
		caller := census.funcs[call.caller]
		if caller == nil || !caller.production {
			failures = append(failures, fmt.Sprintf("%s:%d is not production source", call.site.File, call.site.Line))
			continue
		}
		origin, err := b.resolveListener(census, caller, call.args[idx], depth+1)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s:%d: %v", call.site.File, call.site.Line, err))
			continue
		}
		resolved = append(resolved, origin)
	}
	if len(resolved) == 0 {
		return transportCall{}, fmt.Errorf("no caller construction of the listener: %s", strings.Join(failures, "; "))
	}
	first := resolved[0]
	for _, other := range resolved[1:] {
		if other.site.File != first.site.File || other.site.Line != first.site.Line {
			return transportCall{}, fmt.Errorf("the listener parameter of %s is constructed at %d different sites", fn.name, len(resolved))
		}
	}
	return first, nil
}

// transportListenerOrigin reports whether the call is product construction of
// a listener: product-owned code, or one of the standard library's listener
// primitives the product calls directly.
func transportListenerOrigin(census *transportCensus, call transportCall) bool {
	if census.products[call.pkgPath] {
		return true
	}
	if call.pkgPath != "net" {
		return false
	}
	switch call.name {
	case "Listen", "ListenTCP", "ListenUDP", "ListenUnix", "ListenUnixgram", "ListenIP", "ListenPacket", "FileListener":
		return true
	}
	return false
}

func paramIndex(decl *ast.FuncDecl, expr ast.Expr) int {
	id, ok := unparen(expr).(*ast.Ident)
	if !ok || decl.Type.Params == nil {
		return -1
	}
	idx := 0
	for _, field := range decl.Type.Params.List {
		for _, name := range field.Names {
			if name.Name == id.Name {
				return idx
			}
			idx++
		}
		if len(field.Names) == 0 {
			idx++
		}
	}
	return -1
}

// findCensusCall finds the typed call record for a call expression of fn.
func findCensusCall(fn *transportFunc, call *ast.CallExpr) (transportCall, bool) {
	for _, c := range fn.calls {
		if c.call == call {
			return c, true
		}
	}
	return transportCall{}, false
}

func exprText(e ast.Expr) string {
	switch v := unparen(e).(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprText(v.X) + "." + v.Sel.Name
	case *ast.CallExpr:
		return "call"
	}
	return "expression"
}

// transportRootPath is one proven production entry path: the serving function
// first, the process entry point last, with the command-handler registration
// evidence when the entry is a registered command handler.
type transportRootPath struct {
	path         []*transportFunc
	registration *transportRegistration
	registrar    *transportFunc
	entry        []transportEntryEvidence
}

// transportEntryEvidence is one audited binding of the entry chain.
type transportEntryEvidence struct {
	kind   domain.TransportSiteKind
	sym    domain.SymbolRef
	node   ast.Node
	site   domain.CallSite
	detail string
}

// rootPath proves the serving function is reached from a production entry
// point. Two entry shapes are admitted:
//
//   - a package main function reached by resolved product calls (including
//     interface dispatch), and
//   - a command handler registered through a handler field (Run/RunE) by a
//     constructor that the package main entry point reaches and executes.
//
// Every rejected candidate keeps its own reason; nothing is inferred from a
// package or function name.
func (c *transportCensus) rootPath(fn *transportFunc) (transportRootPath, error) {
	visited, parent, mainPath := c.climb(fn)
	if mainPath != nil {
		return transportRootPath{path: mainPath}, nil
	}
	for _, key := range visited {
		handler := c.funcs[key]
		if handler == nil {
			continue
		}
		for _, reg := range c.registrations[key] {
			if rooted, ok := c.commandEntry(fn, handler, parent, reg); ok {
				return rooted, nil
			}
		}
	}
	return transportRootPath{}, fmt.Errorf(
		"no production entry point reaches %s.%s: neither a package main call path nor a registered command handler chain was proven (unrooted, test-only or library API only)",
		fn.pkgPath, fn.name)
}

// climb walks product callers upward from fn, returning the discovery order, the
// parent map (caller key → the node it was reached from) and the first path to a
// package main function.
func (c *transportCensus) climb(from *transportFunc) (visited []string, parent map[string]string, mainPath []*transportFunc) {
	if from.mainFunc {
		return []string{from.key}, map[string]string{from.key: ""}, []*transportFunc{from}
	}
	parent = map[string]string{}
	depth := map[string]int{from.key: 0}
	seen := map[string]bool{from.key: true}
	queue := []string{from.key}
	visited = []string{from.key}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if depth[cur] >= transportMaxRootHops {
			continue
		}
		callers := append([]transportCall(nil), c.callers[cur]...)
		sort.Slice(callers, func(i, j int) bool {
			if callers[i].site.File != callers[j].site.File {
				return callers[i].site.File < callers[j].site.File
			}
			return callers[i].site.Line < callers[j].site.Line
		})
		for _, call := range callers {
			caller := c.funcs[call.caller]
			if caller == nil || seen[caller.key] || !caller.production {
				continue
			}
			seen[caller.key] = true
			parent[caller.key] = cur
			depth[caller.key] = depth[cur] + 1
			visited = append(visited, caller.key)
			if caller.mainFunc {
				return visited, parent, c.pathTo(parent, from.key, caller.key)
			}
			queue = append(queue, caller.key)
		}
	}
	return visited, parent, nil
}

// pathTo reconstructs the from→target walk order from a parent map.
func (c *transportCensus) pathTo(parent map[string]string, from, target string) []*transportFunc {
	var revKeys []string
	for key := target; ; {
		revKeys = append(revKeys, key)
		if key == from {
			break
		}
		next, ok := parent[key]
		if !ok {
			return nil
		}
		key = next
	}
	out := make([]*transportFunc, 0, len(revKeys))
	for i := len(revKeys) - 1; i >= 0; i-- {
		if fn := c.funcs[revKeys[i]]; fn != nil {
			out = append(out, fn)
		}
	}
	if len(out) != len(revKeys) {
		return nil
	}
	return out
}

// commandEntry admits a registered command-handler entry. The chain must be
// complete: the handler is registered on a command the constructor produces,
// the constructor is reached from a package main function by resolved calls,
// and the command that carries the handler is executed there. A constructor
// called by a documentation generator or a test helper therefore does not
// qualify: the command must actually run.
func (c *transportCensus) commandEntry(
	fn, handler *transportFunc,
	parentFromFn map[string]string,
	reg transportRegistration,
) (transportRootPath, bool) {
	registrar := c.funcs[reg.registrar]
	if registrar == nil || !registrar.production {
		return transportRootPath{}, false
	}
	base := c.pathTo(parentFromFn, fn.key, handler.key)
	if len(base) == 0 {
		return transportRootPath{}, false
	}
	if !registrar.mainFunc && !registrationReturnsCommand(registrar, reg) {
		return transportRootPath{}, false
	}
	if registrar.mainFunc {
		execution, ok := c.commandExecution(registrar, reg, registrar, nil)
		if !ok {
			return transportRootPath{}, false
		}
		return c.assembleCommandEntry(base, []*transportFunc{registrar}, reg, registrar, handler, nil, execution), true
	}
	calls := append([]transportCall(nil), c.callers[registrar.key]...)
	sort.Slice(calls, func(i, j int) bool {
		if calls[i].site.File != calls[j].site.File {
			return calls[i].site.File < calls[j].site.File
		}
		return calls[i].site.Line < calls[j].site.Line
	})
	for i := range calls {
		call := &calls[i]
		caller := c.funcs[call.caller]
		if caller == nil || !caller.production || caller.key == handler.key {
			continue
		}
		_, _, callerPath := c.climb(caller)
		if callerPath == nil {
			continue
		}
		execution, ok := c.commandExecution(registrar, reg, caller, call)
		if !ok {
			continue
		}
		return c.assembleCommandEntry(base, callerPath, reg, registrar, handler, call, execution), true
	}
	return transportRootPath{}, false
}

// assembleCommandEntry builds the proof path and its entry evidence.
func (c *transportCensus) assembleCommandEntry(
	base []*transportFunc,
	registrarPath []*transportFunc,
	reg transportRegistration,
	registrar, handler *transportFunc,
	constructorCall *transportCall,
	execution transportEntryEvidence,
) transportRootPath {
	entry := make([]transportEntryEvidence, 0, 3)
	entry = append(entry, transportEntryEvidence{
		kind: domain.TransportSiteConstruction,
		sym:  domain.SymbolRef{Package: registrar.pkgPath, Symbol: registrar.name},
		node: reg.node,
		site: reg.site,
		detail: fmt.Sprintf("command handler field %s registers the handler %s.%s",
			reg.field, handler.pkgPath, handler.name),
	})
	if constructorCall != nil {
		entry = append(entry, transportEntryEvidence{
			kind: domain.TransportSiteConstruction,
			sym:  domain.SymbolRef{Package: registrar.pkgPath, Symbol: registrar.name},
			node: constructorCall.call,
			site: constructorCall.site,
			detail: fmt.Sprintf("command constructor %s.%s called from the production entry point",
				registrar.pkgPath, registrar.name),
		})
	}
	entry = append(entry, execution)
	full := append(append([]*transportFunc{}, base...), registrarPath...)
	return transportRootPath{
		path:         full,
		registration: &reg,
		registrar:    registrar,
		entry:        entry,
	}
}

// constructorCall returns the caller's call of the constructor.
func (c *transportCensus) constructorCall(caller *transportFunc, constructorKey string) *transportCall {
	for i := range caller.calls {
		if caller.calls[i].calleeKey() == constructorKey {
			return &caller.calls[i]
		}
	}
	return nil
}

// commandExecution finds the call that runs the command value carrying the
// registered handler, and pins it as entry evidence.
func (c *transportCensus) commandExecution(
	registrar *transportFunc,
	reg transportRegistration,
	caller *transportFunc,
	constructorCall *transportCall,
) (transportEntryEvidence, bool) {
	scan := caller
	var names []string
	if constructorCall != nil && scan != nil {
		names = boundNames(scan, constructorCall.call)
		if runner := commandRunnerCall(scan, names, constructorCall.call); runner != nil {
			return runnerEvidence(runner, registrar, names, "the command returned by the constructor is executed"), true
		}
	}
	// The command may also be constructed and run inside one entry function.
	command := commandExpr(registrar, reg)
	if command == nil {
		return transportEntryEvidence{}, false
	}
	names = boundNames(registrar, command)
	if runner := commandRunnerCall(registrar, names, command); runner != nil {
		return runnerEvidence(runner, registrar, names, "the registered command is executed in its constructor"), true
	}
	return transportEntryEvidence{}, false
}

// runnerEvidence binds the execution step.
func runnerEvidence(runner *transportCall, registrar *transportFunc, names []string, detail string) transportEntryEvidence {
	sym := domain.SymbolRef{Package: runner.pkgPath, Symbol: runner.name}
	if runner.recv != "" {
		sym.Symbol = runner.recv + "." + runner.name
	}
	return transportEntryEvidence{
		kind:   domain.TransportSiteConstruction,
		sym:    sym,
		node:   runner.call,
		site:   runner.site,
		detail: fmt.Sprintf("%s (registrar %s.%s, command %s)", detail, registrar.pkgPath, registrar.name, strings.Join(names, ", ")),
	}
}

// commandRunnerCall returns the runner-named call that consumes the command
// value, either as an argument or as the method receiver.
func commandRunnerCall(fn *transportFunc, names []string, command ast.Node) *transportCall {
	var best *transportCall
	for i := range fn.calls {
		call := &fn.calls[i]
		if !transportCommandRunners[call.name] {
			continue
		}
		matched := argumentsIncludeName(call.args, names)
		if !matched {
			if sel, ok := unparen(call.fun).(*ast.SelectorExpr); ok {
				matched = nameIn(names, baseIdentName(sel.X))
			}
		}
		if !matched && command != nil {
			for _, arg := range call.args {
				if nodeContains(arg, command) {
					matched = true
					break
				}
			}
		}
		if !matched {
			continue
		}
		if best == nil || call.site.File < best.site.File ||
			(call.site.File == best.site.File && call.site.Line < best.site.Line) {
			best = call
		}
	}
	return best
}

func argumentsIncludeName(args []ast.Expr, names []string) bool {
	for _, arg := range args {
		if nameIn(names, baseIdentName(arg)) {
			return true
		}
	}
	return false
}

func nameIn(names []string, name string) bool {
	if name == "" {
		return false
	}
	for _, candidate := range names {
		if candidate == name {
			return true
		}
	}
	return false
}

// baseIdentName returns the root identifier of an expression (a selector's
// receiver base included).
func baseIdentName(expr ast.Expr) string {
	switch e := unparen(expr).(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return baseIdentName(e.X)
	case *ast.UnaryExpr:
		return baseIdentName(e.X)
	}
	return ""
}

// commandExpr resolves the command value a registration is attached to: the
// enclosing composite literal, or the receiver of a field assignment.
func commandExpr(fn *transportFunc, reg transportRegistration) ast.Node {
	switch node := reg.node.(type) {
	case *ast.KeyValueExpr:
		parents := astParents(fn.decl.Body)
		for n := parents[node]; n != nil; n = parents[n] {
			if lit, ok := n.(*ast.CompositeLit); ok {
				return lit
			}
		}
	case *ast.AssignStmt:
		if len(node.Lhs) == 1 {
			if sel, ok := unparen(node.Lhs[0]).(*ast.SelectorExpr); ok {
				return sel.X
			}
		}
	}
	return nil
}

// registrationReturnsCommand reports whether the constructor returns the
// command value carrying the registered handler.
func registrationReturnsCommand(registrar *transportFunc, reg transportRegistration) bool {
	command := commandExpr(registrar, reg)
	if command == nil {
		return false
	}
	names := boundNames(registrar, command)
	returnedLiteral := false
	returnedName := false
	ast.Inspect(registrar.decl.Body, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		for _, result := range ret.Results {
			if nodeContains(result, command) {
				returnedLiteral = true
			}
			if id, ok := unparen(result).(*ast.Ident); ok && nameIn(names, id.Name) {
				returnedName = true
			}
		}
		return true
	})
	return returnedLiteral || returnedName
}

// boundNames returns the variables an expression is assigned to.
func boundNames(fn *transportFunc, target ast.Node) []string {
	if target == nil {
		return nil
	}
	parents := astParents(fn.decl.Body)
	for n := target; n != nil; n = parents[n] {
		switch stmt := n.(type) {
		case *ast.AssignStmt:
			return assignedNames(stmt.Lhs, stmt.Rhs, target)
		case *ast.ValueSpec:
			for i, value := range stmt.Values {
				if !nodeContains(value, target) {
					continue
				}
				if i < len(stmt.Names) {
					return []string{stmt.Names[i].Name}
				}
				var names []string
				for _, name := range stmt.Names {
					names = append(names, name.Name)
				}
				return names
			}
			return nil
		case *ast.ReturnStmt, *ast.FuncDecl:
			return nil
		}
	}
	return nil
}

func assignedNames(lhs, rhs []ast.Expr, target ast.Node) []string {
	for i, value := range rhs {
		if !nodeContains(value, target) {
			continue
		}
		if i < len(lhs) {
			if name := baseIdentName(lhs[i]); name != "" {
				return []string{name}
			}
			return nil
		}
		var names []string
		for _, expr := range lhs {
			if name := baseIdentName(expr); name != "" {
				names = append(names, name)
			}
		}
		return names
	}
	return nil
}

// astParents maps every node of a subtree to its parent.
func astParents(root ast.Node) map[ast.Node]ast.Node {
	parents := map[ast.Node]ast.Node{}
	var stack []ast.Node
	ast.Inspect(root, func(n ast.Node) bool {
		if n == nil {
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			return true
		}
		if len(stack) > 0 {
			parents[n] = stack[len(stack)-1]
		}
		stack = append(stack, n)
		return true
	})
	return parents
}

// nodeContains reports whether target is root or one of its descendants.
func nodeContains(root ast.Node, target ast.Node) bool {
	if root == nil || target == nil {
		return false
	}
	found := false
	ast.Inspect(root, func(n ast.Node) bool {
		if found {
			return false
		}
		if n == target {
			found = true
			return false
		}
		return true
	})
	return found
}

// buildInputWitness assembles the rooted witness and emits its evidence.
func (b *transportProofBuilder) buildInputWitness(
	census *transportCensus,
	rooted *transportRootedPath,
	req domain.TransportProofRequest,
	module string,
	mechanism string,
) (*domain.TransportInputWitness, error) {
	if len(rooted.chain) == 0 {
		return nil, fmt.Errorf("empty root chain")
	}
	rootFn := rooted.chain[0]
	rootSym := domain.SymbolRef{Package: rootFn.pkgPath, Symbol: rootFn.name}
	rootSite, err := b.emitFunc(domain.TransportSiteRoot, rootSym, rootFn.decl,
		"product-owned production root of the transport usage: the function that constructs and serves it")
	if err != nil {
		return nil, err
	}
	var chain []domain.TransportSite
	chain = append(chain, rootSite)
	for _, hop := range rooted.chain[1:] {
		detail := "production product function on the entry-to-serve path"
		registered := rooted.registration != nil && hop.key == rooted.registration.handler
		switch {
		case hop.mainFunc:
			detail = "production process entry point (package main)"
		case registered:
			detail = fmt.Sprintf("registered command handler registered through %s", rooted.registration.field)
		}
		sym := domain.SymbolRef{Package: hop.pkgPath, Symbol: hop.name}
		site, err := b.emitFunc(domain.TransportSiteConstruction, sym, hop.decl, detail)
		if err != nil {
			return nil, err
		}
		chain = append(chain, site)
		if registered {
			for _, step := range rooted.entry {
				ev, err := b.emitNode(step.kind, step.sym, step.node, step.site, step.detail)
				if err != nil {
					return nil, err
				}
				chain = append(chain, ev)
			}
		}
	}
	serveSym := domain.SymbolRef{Package: module, Symbol: rooted.serveCall.recv + "." + rooted.serveCall.name}
	serveSite, err := b.emitNode(domain.TransportSiteServe, serveSym, rooted.serveCall.call, rooted.serveCall.site,
		"product calls the affected module's Serve on the constructed server and listener")
	if err != nil {
		return nil, err
	}
	chain = append(chain, serveSite)

	constructionSym := domain.SymbolRef{Package: rooted.construction.pkgPath, Symbol: rooted.construction.name}
	constructionSite, err := b.emitNode(domain.TransportSiteConstruction, constructionSym,
		rooted.construction.call, rooted.construction.site,
		"the server passed to Serve is constructed by the affected module")
	if err != nil {
		return nil, err
	}
	listenerSym := domain.SymbolRef{Package: rooted.listener.pkgPath, Symbol: rooted.listener.name}
	listenerSite, err := b.emitNode(domain.TransportSiteListenerCreation, listenerSym,
		rooted.listener.call, rooted.listener.site,
		"the listener passed to Serve is constructed by product code")
	if err != nil {
		return nil, err
	}

	var transportSites []domain.TransportSite
	for _, hop := range rooted.transportPath {
		sym := domain.SymbolRef{Package: hop.pkgPath, Symbol: hop.name}
		site, err := b.emitFunc(domain.TransportSiteTransportEntry, sym, hop.decl,
			"intra-module path from Serve to the peer-frame loop")
		if err != nil {
			return nil, err
		}
		transportSites = append(transportSites, site)
	}
	if len(transportSites) == 0 {
		return nil, fmt.Errorf("path into the affected transport is empty")
	}

	artifacts, err := b.artifacts()
	if err != nil {
		return nil, err
	}

	w := &domain.TransportInputWitness{
		Schema: domain.TransportProofSchema,
		// Mechanism stays empty: the rooted input proof does not assert
		// which lifecycle the affected source implements. The trigger
		// proof sets it only after the mechanism was detected.
		Mechanism: "",
		Record:    req.Record,
		EntryRefs: append([]int(nil), req.EntryRefs...),
		Module:    module,
		Affected:  transportAffectedSubjects(req.Subjects, module),
		Build:     b.build,
		Root: domain.TransportRoot{
			Package:    rootFn.pkgPath,
			Production: rootFn.production,
			Site:       rootSite,
		},
		Chain: chain,
		Server: domain.TransportServerBinding{
			Construction: constructionSite,
			Serve:        serveSite,
			SameValue:    true,
		},
		Listener: domain.TransportListenerBinding{
			Creation:  listenerSite,
			Serve:     serveSite,
			SameValue: true,
		},
		Transport:   transportSites,
		Artifacts:   artifacts,
		EvidenceIDs: append([]domain.EvidenceID(nil), b.evidenceIDs...),
		Limitations: []string{
			"the witness proves a client of the affected transport supplies the triggering bytes; deployed reachability of that transport is a separate question",
		},
	}
	if err := w.Complete(); err != nil {
		return nil, err
	}
	return w, nil
}

// artifacts pins every distinct source file the witness quoted.
func (b *transportProofBuilder) artifacts() ([]domain.TransportArtifact, error) {
	files := make([]string, 0, len(b.files))
	for file := range b.files {
		files = append(files, file)
	}
	sort.Strings(files)
	out := make([]domain.TransportArtifact, 0, len(files))
	for _, file := range files {
		sum := sha256.Sum256(b.files[file])
		out = append(out, domain.TransportArtifact{
			Path:   file,
			Digest: "sha256:" + hex.EncodeToString(sum[:]),
		})
	}
	return out, nil
}

func transportAffectedSubjects(subjects []domain.SymbolRef, module string) []domain.SymbolRef {
	seen := map[domain.SymbolRef]bool{}
	var out []domain.SymbolRef
	for _, s := range subjects {
		if s.Package == "" {
			continue
		}
		if s.Symbol == "" {
			s.Symbol = "*"
		}
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	if len(out) == 0 && module != "" {
		out = append(out, domain.SymbolRef{Package: module, Symbol: "*"})
	}
	return out
}

// ---------------------------------------------------------------------------
// Module graph
// ---------------------------------------------------------------------------

type transportModuleCall struct {
	key    string
	site   domain.CallSite
	call   *ast.CallExpr
	goStmt bool
	// caller is the module function key this call belongs to; args are the
	// call's argument expressions, so a dispatch function value can be
	// followed to the literal its caller supplies.
	caller string
	args   []ast.Expr
}

type transportModuleFunc struct {
	key      string
	pkgPath  string
	recv     string
	recvType types.Type
	name     string
	decl     *ast.FuncDecl
	pkg      *packages.Package
	file     string
	calls    []transportModuleCall
}

// moduleIfaceCall is one intra-module call through an interface method. The
// concrete implementations are resolved after indexing: the affected module's
// own interface (e.g. transport.ServerTransport) hides the frame loop.
type moduleIfaceCall struct {
	call   transportModuleCall
	iface  *types.Interface
	method string
}

type transportModule struct {
	module string
	funcs  map[string]*transportModuleFunc
	// callers indexes resolved intra-module call edges by callee key.
	callers map[string][]transportModuleCall
	// src is every non-test module file's bytes, for absence checks.
	src map[string][]byte
}

// buildTransportModule indexes the affected module's own non-test functions and
// resolved intra-module call edges.
func buildTransportModule(pkgs []*packages.Package, module string) *transportModule {
	m := &transportModule{module: module, funcs: map[string]*transportModuleFunc{},
		callers: map[string][]transportModuleCall{}, src: map[string][]byte{}}
	var ifaceCalls []moduleIfaceCall
	for _, pkg := range pkgs {
		if pkg.TypesInfo == nil || !domain.PackageInModule(pkg.PkgPath, module) {
			continue
		}
		for _, f := range pkg.Syntax {
			file := pkg.Fset.Position(f.Pos()).Filename
			if strings.HasSuffix(file, "_test.go") {
				continue
			}
			if data, err := os.ReadFile(file); err == nil {
				m.src[file] = data
			}
			for _, decl := range f.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Name == nil || fd.Body == nil {
					continue
				}
				recv := ""
				if fd.Recv != nil && len(fd.Recv.List) > 0 {
					recv = recvDeclName(fd.Recv.List[0].Type)
				}
				mf := &transportModuleFunc{
					key:     transportFuncKey(pkg.PkgPath, recv, fd.Name.Name),
					pkgPath: pkg.PkgPath,
					recv:    recv,
					name:    fd.Name.Name,
					decl:    fd,
					pkg:     pkg,
					file:    file,
				}
				if obj, ok := pkg.TypesInfo.Defs[fd.Name].(*types.Func); ok {
					if sig, ok := obj.Type().(*types.Signature); ok && sig.Recv() != nil {
						mf.recvType = sig.Recv().Type()
					}
				}
				goCalls := map[*ast.CallExpr]bool{}
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					if g, ok := n.(*ast.GoStmt); ok && g.Call != nil {
						goCalls[g.Call] = true
					}
					return true
				})
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					obj := calleeObject(pkg.TypesInfo, call.Fun)
					fn, ok := obj.(*types.Func)
					if !ok || fn.Pkg() == nil {
						return true
					}
					calleeRecv := ""
					if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
						calleeRecv = recvTypeName(sig.Recv().Type())
					}
					key := transportFuncKey(fn.Pkg().Path(), calleeRecv, fn.Name())
					moduleCall := transportModuleCall{
						key:    key,
						caller: mf.key,
						args:   call.Args,
						site: domain.CallSite{
							File:     pkg.Fset.Position(call.Lparen).Filename,
							Line:     pkg.Fset.Position(call.Lparen).Line,
							Column:   pkg.Fset.Position(call.Lparen).Column,
							Package:  pkg.PkgPath,
							Function: fd.Name.Name,
							Receiver: recv,
							Callee:   fn.Name(),
						},
						call:   call,
						goStmt: goCalls[call],
					}
					mf.calls = append(mf.calls, moduleCall)
					if iface := interfaceOfReceiver(fn); iface != nil {
						ifaceCalls = append(ifaceCalls, moduleIfaceCall{
							call: moduleCall, iface: iface, method: fn.Name(),
						})
					}
					return true
				})
				m.funcs[mf.key] = mf
			}
		}
	}
	for _, fn := range m.funcs {
		for _, call := range fn.calls {
			m.callers[call.key] = append(m.callers[call.key], call)
		}
	}
	m.resolveInterfaceDispatch(ifaceCalls)
	return m
}

// resolveInterfaceDispatch links interface-method calls to the module's own
// implementations. Without it the walk stops at the interface declaration the
// module exposes (transport.ServerTransport.HandleStreams) and never reaches
// the frame loop.
func (m *transportModule) resolveInterfaceDispatch(dispatches []moduleIfaceCall) {
	if len(dispatches) == 0 {
		return
	}
	byMethod := map[string][]*transportModuleFunc{}
	for _, fn := range m.funcs {
		if fn.recv == "" || fn.recvType == nil {
			continue
		}
		byMethod[fn.name] = append(byMethod[fn.name], fn)
	}
	for _, dispatch := range dispatches {
		for _, impl := range byMethod[dispatch.method] {
			if !implementsInterface(impl.recvType, dispatch.iface) {
				continue
			}
			m.callers[impl.key] = append(m.callers[impl.key], dispatch.call)
			// The call belongs to the dispatching function; add the edge so
			// reachableFrom can walk from the interface caller into the
			// implementation.
			if caller := m.funcs[dispatch.call.caller]; caller != nil {
				caller.calls = append(caller.calls, transportModuleCall{
					key:    impl.key,
					caller: dispatch.call.caller,
					args:   dispatch.call.args,
					site:   dispatch.call.site,
					call:   dispatch.call.call,
					goStmt: dispatch.call.goStmt,
				})
			}
		}
	}
}

// callersOf returns the module call sites of one function, deterministically
// ordered.
func (m *transportModule) callersOf(key string) []transportModuleCall {
	out := append([]transportModuleCall(nil), m.callers[key]...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].site.File != out[j].site.File {
			return out[i].site.File < out[j].site.File
		}
		return out[i].site.Line < out[j].site.Line
	})
	return out
}

// reachableFrom returns the module functions reachable from start within depth
// hops, in deterministic order.
func (m *transportModule) reachableFrom(start string, depth int) []*transportModuleFunc {
	if m.funcs[start] == nil {
		return nil
	}
	seen := map[string]int{start: 0}
	queue := []string{start}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		d := seen[cur]
		if d >= depth {
			continue
		}
		for _, call := range m.funcs[cur].calls {
			if m.funcs[call.key] == nil {
				continue
			}
			if prev, ok := seen[call.key]; ok && prev <= d+1 {
				continue
			}
			seen[call.key] = d + 1
			queue = append(queue, call.key)
		}
	}
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]*transportModuleFunc, 0, len(keys))
	for _, key := range keys {
		out = append(out, m.funcs[key])
	}
	return out
}

// pathToFrameLoop walks the module call graph from Serve to the function that
// reads peer frames in a loop.
func (m *transportModule) pathToFrameLoop(start string) ([]*transportModuleFunc, *transportModuleFunc) {
	if m.funcs[start] == nil {
		return nil, nil
	}
	parent := map[string]string{start: ""}
	queue := []string{start}
	var loopKey string
	for len(queue) > 0 && loopKey == "" {
		cur := queue[0]
		queue = queue[1:]
		if len(parent) > transportMaxTransportHops*64 {
			break
		}
		fn := m.funcs[cur]
		if _, _, ok := frameLoopParts(fn); ok {
			loopKey = cur
			break
		}
		children := append([]transportModuleCall(nil), fn.calls...)
		sort.Slice(children, func(i, j int) bool { return children[i].key < children[j].key })
		for _, call := range children {
			if m.funcs[call.key] == nil {
				continue
			}
			if _, seen := parent[call.key]; seen {
				continue
			}
			parent[call.key] = cur
			queue = append(queue, call.key)
		}
	}
	if loopKey == "" {
		return nil, nil
	}
	var rev []*transportModuleFunc
	for n := loopKey; n != ""; n = parent[n] {
		rev = append(rev, m.funcs[n])
	}
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	return rev, m.funcs[loopKey]
}

var readFrameName = "ReadFrame"

// frameLoopParts locates the peer-frame read loop and its frame-type dispatch.
func frameLoopParts(fn *transportModuleFunc) (ast.Node, *ast.TypeSwitchStmt, bool) {
	if fn == nil || fn.decl.Body == nil {
		return nil, nil, false
	}
	var loop ast.Node
	var switchStmt *ast.TypeSwitchStmt
	ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
		switch stmt := n.(type) {
		case *ast.ForStmt:
			if loop != nil {
				return true
			}
			if call := readFrameCall(stmt.Body); call != nil {
				loop = stmt
			}
		case *ast.TypeSwitchStmt:
			if switchStmt != nil {
				return true
			}
			if transportFrameSwitch(stmt) {
				switchStmt = stmt
			}
		}
		return true
	})
	if loop == nil || switchStmt == nil {
		return nil, nil, false
	}
	return loop, switchStmt, true
}

// readFrameCall finds the first peer-frame read inside a loop body.
func readFrameCall(n ast.Node) *ast.CallExpr {
	var found *ast.CallExpr
	ast.Inspect(n, func(node ast.Node) bool {
		if found != nil {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == readFrameName {
			found = call
			return false
		}
		return true
	})
	return found
}

// transportFrameSwitch reports whether the type switch dispatches on a stream
// admission frame and a stream reset frame.
func transportFrameSwitch(stmt *ast.TypeSwitchStmt) bool {
	var admitted, reset bool
	for _, clause := range stmt.Body.List {
		cc, ok := clause.(*ast.CaseClause)
		if !ok {
			continue
		}
		for _, expr := range cc.List {
			switch transportFrameTypeName(expr) {
			case "MetaHeadersFrame":
				admitted = true
			case "RSTStreamFrame":
				reset = true
			}
		}
	}
	return admitted && reset
}

func transportFrameTypeName(expr ast.Expr) string {
	expr = unparen(expr)
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = unparen(star.X)
	}
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return e.Sel.Name
	}
	return ""
}

// frameCase returns the case clause for a frame type name.
func frameCase(stmt *ast.TypeSwitchStmt, name string) *ast.CaseClause {
	for _, clause := range stmt.Body.List {
		cc, ok := clause.(*ast.CaseClause)
		if !ok {
			continue
		}
		for _, expr := range cc.List {
			if transportFrameTypeName(expr) == name {
				return cc
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Trigger proof
// ---------------------------------------------------------------------------

func (b *transportProofBuilder) proveTrigger(
	m *transportModule,
	rooted *transportRootedPath,
	req domain.TransportProofRequest,
	module string,
	mechanism string,
) (*domain.TransportTriggerWitness, []domain.AnalysisGap) {
	var gaps []domain.AnalysisGap
	fail := func(msg string) {
		gaps = append(gaps, domain.AnalysisGap{
			Owner:      domain.GapOwnerProof,
			Code:       domain.GapTriggerProofIncomplete,
			Obligation: domain.ObligationCondition,
			Message:    msg,
		})
	}

	loopFn := rooted.loopFn
	if loopFn == nil {
		// The affected module does not carry the http2-rapid-reset
		// lifecycle: the mechanism is not present, so no trigger
		// obligation exists for it. C-CONSTRAINT keeps its non-transport
		// evaluation instead of being failed for a mechanism the source
		// does not implement.
		return nil, nil
	}

	loopSym := domain.SymbolRef{Package: loopFn.pkgPath, Symbol: loopFn.name}
	loopNode, switchStmt, _ := frameLoopParts(loopFn)

	obligations := make([]domain.TransportTriggerObligation, 0, len(domain.TransportTriggerObligationIDs))
	failed := map[domain.TransportObligationID]bool{}

	// 1. Peer-controlled frame consumption.
	if site, err := b.emitNode(domain.TransportSiteFrameLoop, loopSym, loopNode,
		domain.CallSite{File: loopFn.file, Line: b.ix.fset.Position(loopNode.Pos()).Line,
			Package: loopFn.pkgPath, Function: loopFn.name},
		"the accepted connection's framer is read in a loop: the peer supplies every frame"); err != nil {
		fail(err.Error())
	} else {
		obligations = append(obligations, domain.TransportTriggerObligation{
			ID:        domain.TransportObligationFrameConsumption,
			Satisfied: true,
			Sites:     []domain.TransportSite{site},
			Detail:    "an active server transport consumes peer-supplied HTTP/2 frames off the accepted connection",
		})
	}

	// 2. Stream open, reset and reopen are all admissible.
	admitCase := frameCase(switchStmt, "MetaHeadersFrame")
	resetCase := frameCase(switchStmt, "RSTStreamFrame")
	if admitCase != nil && resetCase != nil {
		admitSite, aerr := b.emitNode(domain.TransportSiteStreamAdmission, loopSym, admitCase,
			domain.CallSite{File: loopFn.file, Line: b.ix.fset.Position(admitCase.Pos()).Line,
				Package: loopFn.pkgPath, Function: loopFn.name},
			"a HEADERS frame admits a new stream")
		resetSite, rerr := b.emitNode(domain.TransportSiteStreamReset, loopSym, resetCase,
			domain.CallSite{File: loopFn.file, Line: b.ix.fset.Position(resetCase.Pos()).Line,
				Package: loopFn.pkgPath, Function: loopFn.name},
			"an RST_STREAM frame terminates the stream")
		switch {
		case aerr != nil:
			fail(aerr.Error())
		case rerr != nil:
			fail(rerr.Error())
		default:
			obligations = append(obligations, domain.TransportTriggerObligation{
				ID:        domain.TransportObligationResetReopen,
				Satisfied: true,
				Sites:     []domain.TransportSite{admitSite, resetSite},
				Detail:    "the peer's own frames create a stream (HEADERS), reset it (RST_STREAM) and create the next one — the dispatch admits the whole cycle",
			})
		}
	}

	// 3. Handler execution admitted with an asynchronous lifetime.
	dispatch := m.reachableFrom(loopFn.key, 2)
	handlerSite, handlerFn := b.handlerStart(m, dispatch, loopFn)
	if handlerSite != nil {
		obligations = append(obligations, domain.TransportTriggerObligation{
			ID:        domain.TransportObligationHandlerLifetime,
			Satisfied: true,
			Sites:     []domain.TransportSite{*handlerSite},
			Detail: fmt.Sprintf("the admitted stream's handler runs in a new goroutine in %s.%s: its lifetime is asynchronous to the frame loop",
				handlerFn.pkgPath, handlerFn.name),
		})
	} else {
		failed[domain.TransportObligationHandlerLifetime] = true
		obligations = append(obligations, domain.TransportTriggerObligation{
			ID:        domain.TransportObligationHandlerLifetime,
			Satisfied: false,
			Detail:    "no asynchronous handler start was found in the stream-admission dispatch path",
		})
		fail("trigger proof: the stream handler's asynchronous lifetime is not established in the admission path")
	}

	// 4. Reset removes the stream before the handler completes.
	registry := m.streamRegistry(dispatch)
	removalSite, removalFn, removalErr := b.streamRemoval(m, loopFn, dispatch, registry, resetCase)
	if removalSite != nil {
		absence, joinErr := m.joinAbsence(removalFn)
		if joinErr != nil {
			failed[domain.TransportObligationRemovalBeforeCompletion] = true
			obligations = append(obligations, domain.TransportTriggerObligation{
				ID:        domain.TransportObligationRemovalBeforeCompletion,
				Satisfied: false,
				Detail:    joinErr.Error(),
			})
			fail("trigger proof: " + joinErr.Error())
		} else {
			obligations = append(obligations, domain.TransportTriggerObligation{
				ID:        domain.TransportObligationRemovalBeforeCompletion,
				Satisfied: true,
				Sites:     []domain.TransportSite{*removalSite},
				Absence:   absence,
				Detail: fmt.Sprintf("stream removal in %s.%s deletes the stream from the active set and cancels it without joining the handler",
					removalFn.pkgPath, removalFn.name),
			})
		}
	} else {
		failed[domain.TransportObligationRemovalBeforeCompletion] = true
		detail := "no stream removal on reset was found"
		if removalErr != nil {
			detail = removalErr.Error()
		}
		obligations = append(obligations, domain.TransportTriggerObligation{
			ID:        domain.TransportObligationRemovalBeforeCompletion,
			Satisfied: false,
			Detail:    detail,
		})
		fail("trigger proof: " + detail)
	}

	// 5. The fixed pre-dispatch handler quota is absent.
	fix, quotaSites, quotaAbsence, quotaErr := b.fixAndQuota(m, loopFn, req)
	if quotaErr != nil {
		failed[domain.TransportObligationNoFixedQuota] = true
		obligations = append(obligations, domain.TransportTriggerObligation{
			ID:        domain.TransportObligationNoFixedQuota,
			Satisfied: false,
			Detail:    quotaErr.Error(),
		})
		fail("trigger proof: missing fixed handler-quota enforcement is not established: " + quotaErr.Error())
	} else {
		obligations = append(obligations, domain.TransportTriggerObligation{
			ID:        domain.TransportObligationNoFixedQuota,
			Satisfied: true,
			Sites:     quotaSites,
			Absence:   quotaAbsence,
			Detail: fmt.Sprintf("the analyzed %s source predates the fix: %s is referenced nowhere, so handler execution is admitted without a pre-dispatch quota",
				module, strings.Join(fix.EnforcementNames, ", ")),
		})
	}

	// 6. Product controls are positioned after the vulnerable dispatch.
	controls, controlErr := b.productControls(rooted, module, loopSym)
	if controlErr != nil {
		failed[domain.TransportObligationControlPosition] = true
		obligations = append(obligations, domain.TransportTriggerObligation{
			ID:        domain.TransportObligationControlPosition,
			Satisfied: false,
			Detail:    controlErr.Error(),
		})
		fail("trigger proof: product control position is unresolved: " + controlErr.Error())
	} else {
		anchor, aerr := b.emitNode(domain.TransportSiteControl, loopSym, rooted.serveCall.call, rooted.serveCall.site,
			"product control boundary: the product's Serve call is the last product-side position before transport dispatch")
		var sites []domain.TransportSite
		if aerr == nil {
			sites = append(sites, anchor)
		}
		var names []string
		for _, c := range controls {
			sites = append(sites, c.Site)
			names = append(names, fmt.Sprintf("%s.%s=%s", c.Site.Symbol.Package, c.Site.Symbol.Symbol, c.Disposition))
		}
		detail := "no product-side control was found between the root and the affected dispatch"
		if len(names) > 0 {
			detail = "every product-side control is positioned after the vulnerable dispatch or is admission the reset defeats: " + strings.Join(names, ", ")
		}
		obligations = append(obligations, domain.TransportTriggerObligation{
			ID:        domain.TransportObligationControlPosition,
			Satisfied: true,
			Sites:     sites,
			Detail:    detail,
		})
	}

	// Fill in any obligation the analysis never reached as unsatisfied, so
	// a consumer always sees the full obligation set.
	for _, id := range domain.TransportTriggerObligationIDs {
		found := false
		for _, o := range obligations {
			if o.ID == id {
				found = true
				break
			}
		}
		if found {
			continue
		}
		if !failed[id] {
			fail("trigger proof: obligation " + string(id) + " was not analyzed")
		}
		obligations = append(obligations, domain.TransportTriggerObligation{
			ID:        id,
			Satisfied: false,
			Detail:    "the proof did not reach this obligation",
		})
	}
	sortObligations(obligations)

	rooted.witness.Mechanism = mechanism
	trigger := &domain.TransportTriggerWitness{
		Schema:      domain.TransportProofSchema,
		Mechanism:   mechanism,
		Record:      req.Record,
		Module:      module,
		Build:       b.build,
		Input:       *rooted.witness,
		Fix:         fix,
		Obligations: obligations,
		Controls:    controls,
		EvidenceIDs: append([]domain.EvidenceID(nil), b.evidenceIDs...),
		Limitations: []string{
			"the trigger witness is a source/fix-bound artifact proof for this build; it does not establish deployed attacker access to the transport",
		},
	}
	if err := trigger.Complete(); err != nil {
		fail("trigger proof incomplete: " + err.Error())
	}
	return trigger, gaps
}

func sortObligations(obligations []domain.TransportTriggerObligation) {
	order := map[domain.TransportObligationID]int{}
	for i, id := range domain.TransportTriggerObligationIDs {
		order[id] = i
	}
	sort.SliceStable(obligations, func(i, j int) bool {
		return order[obligations[i].ID] < order[obligations[j].ID]
	})
}

// handlerStart finds the `go` invocation that starts the admitted stream's
// handler. The transport may invoke the dispatch callback synchronously and
// leave the asynchronous lifetime to the callback's supplier, so a
// function-value argument passed into the frame loop is followed to the
// literal its caller supplies.
func (b *transportProofBuilder) handlerStart(m *transportModule, dispatch []*transportModuleFunc, loopFn *transportModuleFunc) (*domain.TransportSite, *transportModuleFunc) {
	if site, fn := b.handlerGoStmt(m, dispatch, "the admitted stream's handler is started asynchronously"); site != nil {
		return site, fn
	}
	if loopFn == nil {
		return nil, nil
	}
	for _, call := range m.callersOf(loopFn.key) {
		caller := m.funcs[call.caller]
		if caller == nil {
			continue
		}
		for _, arg := range call.args {
			if _, ok := unparen(arg).(*ast.FuncLit); !ok {
				continue
			}
			dispatchFn := &transportModuleFunc{
				key:     caller.key,
				pkgPath: caller.pkgPath,
				recv:    caller.recv,
				name:    caller.name,
				decl:    &ast.FuncDecl{Type: &ast.FuncType{}, Body: unparen(arg).(*ast.FuncLit).Body},
				pkg:     caller.pkg,
				file:    caller.file,
			}
			site, _ := b.handlerGoStmt(m, []*transportModuleFunc{dispatchFn},
				"the admitted stream's handler is started asynchronously in the dispatch callback the transport's caller supplies")
			if site != nil {
				return site, caller
			}
		}
	}
	return nil, nil
}

// handlerGoStmt looks for the asynchronous handler start inside the given
// module functions.
func (b *transportProofBuilder) handlerGoStmt(m *transportModule, funcs []*transportModuleFunc, summary string) (*domain.TransportSite, *transportModuleFunc) {
	for _, fn := range funcs {
		if fn == nil || fn.decl == nil || fn.decl.Body == nil {
			continue
		}
		var found *ast.GoStmt
		ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
			g, ok := n.(*ast.GoStmt)
			if !ok || g.Call == nil || found != nil {
				return found == nil
			}
			if _, ok := g.Call.Fun.(*ast.FuncLit); ok {
				found = g
				return false
			}
			obj := calleeObject(fn.pkg.TypesInfo, g.Call.Fun)
			if _, ok := obj.(*types.Func); ok {
				found = g
				return false
			}
			return true
		})
		if found == nil {
			continue
		}
		site, err := b.emitNode(domain.TransportSiteHandlerStart,
			domain.SymbolRef{Package: fn.pkgPath, Symbol: fn.name}, found,
			domain.CallSite{File: fn.file, Line: b.ix.fset.Position(found.Pos()).Line,
				Package: fn.pkgPath, Function: fn.name},
			summary)
		if err != nil {
			continue
		}
		return &site, fn
	}
	return nil, nil
}

// streamRegistry names the map field the admission path registers streams in.
// It is discovered from the source (an indexed assignment whose map is then
// deleted from), never from a hardcoded identifier.
func (m *transportModule) streamRegistry(dispatch []*transportModuleFunc) string {
	candidates := map[string]bool{}
	for _, fn := range dispatch {
		ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for _, lhs := range as.Lhs {
				idx, ok := lhs.(*ast.IndexExpr)
				if !ok {
					continue
				}
				switch x := idx.X.(type) {
				case *ast.SelectorExpr:
					candidates[x.Sel.Name] = true
				case *ast.Ident:
					candidates[x.Name] = true
				}
			}
			return true
		})
	}
	names := make([]string, 0, len(candidates))
	for name := range candidates {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if m.hasDeleteOn(name) {
			return name
		}
	}
	if len(names) > 0 {
		return names[0]
	}
	return ""
}

func (m *transportModule) hasDeleteOn(field string) bool {
	for _, fn := range m.funcs {
		found := false
		ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
			if found {
				return false
			}
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) < 1 {
				return true
			}
			id, ok := call.Fun.(*ast.Ident)
			if !ok || id.Name != "delete" {
				return true
			}
			if sel, ok := unparen(call.Args[0]).(*ast.SelectorExpr); ok && sel.Sel.Name == field {
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

// streamRemoval binds the reset path's stream removal: a delete from the
// registry reached from the RST_STREAM case.
func (b *transportProofBuilder) streamRemoval(
	m *transportModule,
	loopFn *transportModuleFunc,
	dispatch []*transportModuleFunc,
	registry string,
	resetCase *ast.CaseClause,
) (*domain.TransportSite, *transportModuleFunc, error) {
	targets := caseCalleeKeys(loopFn, resetCase)
	search := dispatch
	if len(targets) > 0 {
		seen := map[string]bool{}
		var scoped []*transportModuleFunc
		for _, key := range targets {
			for _, fn := range m.reachableFrom(key, 2) {
				if seen[fn.key] {
					continue
				}
				seen[fn.key] = true
				scoped = append(scoped, fn)
			}
		}
		if len(scoped) > 0 {
			search = scoped
		}
	}
	if registry == "" {
		return nil, nil, fmt.Errorf("no active-stream registry was identified in the admission path")
	}
	for _, fn := range search {
		var site *domain.TransportSite
		ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
			if site != nil {
				return false
			}
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) < 1 {
				return true
			}
			id, ok := call.Fun.(*ast.Ident)
			if !ok || id.Name != "delete" {
				return true
			}
			sel, ok := unparen(call.Args[0]).(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != registry {
				return true
			}
			emitted, err := b.emitNode(domain.TransportSiteStreamRemoval,
				domain.SymbolRef{Package: fn.pkgPath, Symbol: fn.name}, call,
				domain.CallSite{File: fn.file, Line: b.ix.fset.Position(call.Lparen).Line,
					Package: fn.pkgPath, Function: fn.name},
				fmt.Sprintf("the reset path deletes the stream from %s", registry))
			if err != nil {
				return true
			}
			site = &emitted
			return false
		})
		if site != nil {
			return site, fn, nil
		}
	}
	return nil, nil, fmt.Errorf("no delete on the %s registry is reachable from the reset branch", registry)
}

// caseCalleeKeys lists the module calls invoked inside one case clause.
func caseCalleeKeys(fn *transportModuleFunc, cc *ast.CaseClause) []string {
	if cc == nil {
		return nil
	}
	var keys []string
	for _, call := range fn.calls {
		if call.call.Pos() >= cc.Pos() && call.call.End() <= cc.End() {
			keys = append(keys, call.key)
		}
	}
	sort.Strings(keys)
	return keys
}

var handlerJoinChannelRe = regexp.MustCompile(`(?i)handler.*(done|complete|finish)|(done|complete|finish)(ch|chan)|waitgroup`)

// joinAbsence proves stream removal does not synchronously join the handler.
// A WaitGroup.Wait, or a receive on a handler-completion channel, means the
// reset path waits for the handler and the mechanism does not hold.
func (m *transportModule) joinAbsence(fn *transportModuleFunc) ([]string, error) {
	if fn == nil {
		return nil, fmt.Errorf("no stream-removal function was bound")
	}
	checked := []*transportModuleFunc{fn}
	seen := map[string]bool{fn.key: true}
	for _, call := range fn.calls {
		callee := m.funcs[call.key]
		if callee == nil || seen[callee.key] {
			continue
		}
		seen[callee.key] = true
		checked = append(checked, callee)
	}
	var absence []string
	for _, cur := range checked {
		if join := handlerJoin(cur); join != "" {
			return nil, fmt.Errorf(
				"stream removal in %s.%s synchronously joins the handler (%s): the reset path waits for handler completion",
				cur.pkgPath, cur.name, join)
		}
		absence = append(absence, fmt.Sprintf(
			"no WaitGroup.Wait and no handler-completion receive in %s.%s", cur.pkgPath, cur.name))
	}
	return absence, nil
}

func handlerJoin(fn *transportModuleFunc) string {
	join := ""
	ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
		if join != "" {
			return false
		}
		switch node := n.(type) {
		case *ast.CallExpr:
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Wait" {
				join = fmt.Sprintf("Wait() at line %d", fn.pkg.Fset.Position(node.Pos()).Line)
				return false
			}
		case *ast.UnaryExpr:
			if node.Op.String() != "<-" {
				return true
			}
			sel, ok := unparen(node.X).(*ast.SelectorExpr)
			if !ok || sel.Sel.Name == "Done" || !handlerJoinChannelRe.MatchString(sel.Sel.Name) {
				return true
			}
			join = fmt.Sprintf("receive on %s at line %d", sel.Sel.Name, fn.pkg.Fset.Position(node.Pos()).Line)
			return false
		}
		return true
	})
	return join
}

var (
	fixChanDeclRe = regexp.MustCompile(`^\s*(\w+)\s+chan\s+struct\s*\{\s*\}`)
	fixChanMakeRe = regexp.MustCompile(`\b(\w+)\s*=\s*make\(chan`)
	fixAcquireRe  = regexp.MustCompile(`\b(\w+)\s*<-\s*struct\s*\{\s*\}\s*(?:\{\s*\}\s*)?:`)
)

// fixQuotaNames extracts the identifiers a fix introduces to enforce a handler
// quota. Two enforcement shapes are recognized:
//
//   - an empty-struct channel acquired by an inline channel operation and
//     released by a deferred one, and
//   - a counting semaphore: an empty-struct channel field owned by a named
//     struct the fix adds, signalled by one added method and waited on by
//     another, created by a constructor the same fix adds, with handler
//     execution wrapped by a deferred release.
//
// The returned identifiers are the enforcement's own names. A generic field
// name such as "wait" is deliberately not returned: a pre-fix source may
// already contain it for an unrelated reason, and its presence would then be
// misread as "the fix is already applied".
func fixQuotaNames(diff string) ([]string, error) {
	added := addedDiffLines(diff)
	declared := map[string]bool{}
	for _, body := range added {
		if m := fixChanDeclRe.FindStringSubmatch(body); m != nil {
			declared[m[1]] = true
		}
		if m := fixChanMakeRe.FindStringSubmatch(body); m != nil {
			declared[m[1]] = true
		}
	}
	if len(declared) == 0 {
		return nil, fmt.Errorf("the supplied fix diff introduces no bounded channel (handler quota) field")
	}
	// Shape 1: the channel is acquired and released by inline channel
	// operations, with a deferred release in the same diff.
	acquired := map[string]bool{}
	released := map[string]bool{}
	hasDeferredRelease := false
	for _, body := range added {
		if m := fixAcquireRe.FindStringSubmatch(body); m != nil && declared[m[1]] {
			acquired[m[1]] = true
		}
		if !strings.Contains(body, "<-") {
			continue
		}
		if strings.Contains(body, "defer") {
			hasDeferredRelease = true
		}
		for name := range declared {
			if referencedIdentifier(body, name) {
				released[name] = true
			}
		}
	}
	var names []string
	for name := range declared {
		if acquired[name] && released[name] {
			names = append(names, name)
		}
	}
	if len(names) > 0 {
		if !hasDeferredRelease {
			return nil, fmt.Errorf("the supplied fix diff has no deferred release for the introduced handler quota")
		}
		sort.Strings(names)
		return names, nil
	}
	// Shape 2: a counting semaphore whose channel is coordinated by added
	// methods and whose release wraps handler execution.
	if names = semaphoreQuotaNames(added, declared); len(names) > 0 {
		sort.Strings(names)
		return names, nil
	}
	return nil, fmt.Errorf("the supplied fix diff never acquires and releases the introduced channel: it is not a handler-quota enforcement")
}

// addedDiffLines returns a unified diff's added lines without their marker.
func addedDiffLines(diff string) []string {
	var out []string
	for _, line := range strings.Split(diff, "\n") {
		if !strings.HasPrefix(line, "+") || strings.HasPrefix(line, "+++") {
			continue
		}
		out = append(out, strings.TrimPrefix(line, "+"))
	}
	return out
}

// referencedIdentifier reports whether text names ident as a whole word.
func referencedIdentifier(text, ident string) bool {
	return regexp.MustCompile(`\b` + regexp.QuoteMeta(ident) + `\b`).MatchString(text)
}

// semaphoreQuotaNames recognizes a counting-semaphore handler quota from the
// diff's added lines: the empty-struct channel belongs to a named struct, the
// fix adds a constructor for that struct, added methods both signal and wait
// on the channel, and handler execution defers the quota's release. Its
// enforcement identity is the semaphore type and its constructor.
func semaphoreQuotaNames(added []string, declared map[string]bool) []string {
	signalled := map[string]bool{}
	waited := map[string]bool{}
	for _, body := range added {
		send, recv := channelOperation(body)
		if declared[send] {
			signalled[send] = true
		}
		if declared[recv] {
			waited[recv] = true
		}
	}
	blocks := addedDiffBlocks(added)
	owner := map[string]string{} // semaphore type -> bounded channel field
	for _, b := range blocks {
		m := fixNamedTypeRe.FindStringSubmatch(b.header)
		if m == nil {
			continue
		}
		for _, line := range b.body {
			if fm := fixChanDeclRe.FindStringSubmatch(line); fm != nil && declared[fm[1]] {
				owner[m[1]] = fm[1]
			}
		}
	}
	if len(owner) == 0 {
		return nil
	}
	constructors := map[string]string{} // constructor -> semaphore type
	for _, b := range blocks {
		// A constructor is an added function without a receiver whose
		// signature names the semaphore type it returns.
		if strings.HasPrefix(b.header, "func (") {
			continue
		}
		m := fixFuncNameRe.FindStringSubmatch(b.header)
		if m == nil {
			continue
		}
		for typ := range owner {
			if referencedIdentifier(b.header, typ) {
				constructors[m[1]] = typ
			}
		}
	}
	if len(constructors) == 0 {
		return nil
	}
	quotaVars := map[string]string{} // variable -> semaphore type
	for _, body := range added {
		if m := fixSemaphoreAssignRe.FindStringSubmatch(body); m != nil {
			if typ, ok := constructors[m[2]]; ok {
				quotaVars[m[1]] = typ
			}
		}
	}
	var enforcement []string
	for varName, typ := range quotaVars {
		channel := owner[typ]
		if channel == "" || !signalled[channel] || !waited[channel] {
			continue
		}
		deferredRelease := false
		for _, body := range added {
			if m := fixDeferredMethodRe.FindStringSubmatch(body); m != nil && m[1] == varName {
				deferredRelease = true
			}
		}
		if !deferredRelease {
			continue
		}
		enforcement = append(enforcement, typ)
		for ctor, ctorType := range constructors {
			if ctorType == typ {
				enforcement = append(enforcement, ctor)
			}
		}
	}
	return uniqueSortedStrings(enforcement)
}

var (
	// fixSemaphoreAssignRe matches a variable initialised from a constructor.
	fixSemaphoreAssignRe = regexp.MustCompile(`^\s*(\w+)\s*:=\s*(\w+)\(`)
	// fixDeferredMethodRe matches a deferred method call on a variable.
	fixDeferredMethodRe = regexp.MustCompile(`\bdefer\s+(\w+)\.(\w+)\(`)
	// fixNamedTypeRe matches a named struct declaration header.
	fixNamedTypeRe = regexp.MustCompile(`^type\s+(\w+)\s+struct\b`)
	// fixFuncNameRe matches a function declaration header's name.
	fixFuncNameRe = regexp.MustCompile(`^func\s+(?:\([^)]*\)\s*)?(\w+)\s*\(`)
)

// diffBlock is one declaration of a unified diff's added lines.
type diffBlock struct {
	header string
	body   []string
}

// addedDiffBlocks groups added lines under the top-level declaration each one
// follows. A unified diff contains only the changed lines of a declaration, so
// brace-depth grouping is unreliable; the added declaration header is the only
// stable boundary.
func addedDiffBlocks(added []string) []diffBlock {
	var out []diffBlock
	current := -1
	for _, line := range added {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "func ") || strings.HasPrefix(trimmed, "type ") {
			out = append(out, diffBlock{header: trimmed})
			current = len(out) - 1
			continue
		}
		if current >= 0 {
			out[current].body = append(out[current].body, line)
		}
	}
	return out
}

// channelOperation reports the field a line sends into and the field a line
// receives from, if any.
func channelOperation(line string) (send, recv string) {
	idx := strings.Index(line, "<-")
	if idx < 0 {
		return "", ""
	}
	return trailingFieldSelector(line[:idx]), leadingFieldSelector(line[idx+2:])
}

// trailingFieldSelector returns the last field name of an expression, e.g.
// "q.wait" -> "wait".
func trailingFieldSelector(expr string) string {
	trimmed := strings.TrimRight(strings.TrimSpace(expr), " \t")
	end := len(trimmed)
	start := end
	for start > 0 && isIdentByte(trimmed[start-1]) {
		start--
	}
	if start == end || start == 0 || trimmed[start-1] != '.' {
		return ""
	}
	return trimmed[start:end]
}

// leadingFieldSelector returns the first field name of an expression, e.g.
// "q.wait" -> "wait".
func leadingFieldSelector(expr string) string {
	trimmed := strings.TrimSpace(expr)
	dot := 0
	for dot < len(trimmed) && isIdentByte(trimmed[dot]) {
		dot++
	}
	if dot == 0 || dot >= len(trimmed) || trimmed[dot] != '.' {
		return ""
	}
	rest := trimmed[dot+1:]
	end := 0
	for end < len(rest) && isIdentByte(rest[end]) {
		end++
	}
	return rest[:end]
}

func isIdentByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9', b == '_':
		return true
	}
	return false
}

// uniqueSortedStrings de-duplicates and orders identifier names.
func uniqueSortedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

// parseFixBinding pins the fix evidence and extracts its enforcement names.
func parseFixBinding(req domain.TransportProofRequest) (domain.TransportFixBinding, error) {
	if strings.TrimSpace(req.FixDiff) == "" {
		return domain.TransportFixBinding{}, fmt.Errorf(
			"fix evidence is absent: the missing handler quota cannot be bound to the fix that introduces it")
	}
	sum := sha256.Sum256([]byte(req.FixDiff))
	diffDigest := "sha256:" + hex.EncodeToString(sum[:])
	digest := req.FixDigest
	if digest == "" {
		digest = diffDigest
	}
	if digest != diffDigest {
		return domain.TransportFixBinding{}, fmt.Errorf(
			"fix digest %s does not pin the supplied diff bytes (%s)", digest, diffDigest)
	}
	names, err := fixQuotaNames(req.FixDiff)
	if err != nil {
		return domain.TransportFixBinding{}, err
	}
	binding := domain.TransportFixBinding{
		URI:              req.FixURI,
		Digest:           digest,
		DiffDigest:       diffDigest,
		EnforcementNames: names,
	}
	if err := binding.Validate(); err != nil {
		return domain.TransportFixBinding{}, err
	}
	return binding, nil
}

// fixAndQuota binds the fix and proves the analyzed source lacks its
// enforcement. A source that already references an introduced quota is fixed,
// so the mechanism does not hold and the obligation fails.
func (b *transportProofBuilder) fixAndQuota(
	m *transportModule,
	loopFn *transportModuleFunc,
	req domain.TransportProofRequest,
) (domain.TransportFixBinding, []domain.TransportSite, []string, error) {
	fix, err := parseFixBinding(req)
	if err != nil {
		return domain.TransportFixBinding{}, nil, nil, err
	}
	absence, err := m.quotaAbsence(fix)
	if err != nil {
		return fix, nil, nil, err
	}
	site, err := b.emitFunc(domain.TransportSiteFixEnforcement,
		domain.SymbolRef{Package: loopFn.pkgPath, Symbol: loopFn.name}, loopFn.decl,
		fmt.Sprintf("analyzed dispatch before the fix: %s is absent here", strings.Join(fix.EnforcementNames, ", ")))
	if err != nil {
		return fix, nil, nil, err
	}
	return fix, []domain.TransportSite{site}, absence, nil
}

// quotaAbsence proves the fixed enforcement identifiers are referenced nowhere
// in the analyzed module source.
func (m *transportModule) quotaAbsence(fix domain.TransportFixBinding) ([]string, error) {
	if len(m.src) == 0 {
		return nil, fmt.Errorf("no analyzed non-test module source was available for the quota absence proof")
	}
	files := make([]string, 0, len(m.src))
	for file := range m.src {
		files = append(files, file)
	}
	sort.Strings(files)
	var absence []string
	for _, name := range fix.EnforcementNames {
		re := regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\b`)
		for _, file := range files {
			data := m.src[file]
			loc := re.FindIndex(data)
			if loc == nil {
				continue
			}
			line := bytes.Count(data[:loc[0]], []byte("\n")) + 1
			return nil, fmt.Errorf(
				"the analyzed source already references %s at %s:%d — the fixed enforcement is present, so the vulnerable lifecycle does not hold",
				name, file, line)
		}
		absence = append(absence, fmt.Sprintf("%s is referenced nowhere in the %d analyzed non-test module file(s)",
			name, len(files)))
	}
	return absence, nil
}

var concurrencyNameRe = regexp.MustCompile(`(?i)semaphore|limiter|ratelimit|rate_limit|throttle|quota|handlerlimit|acquire.*(slot|quota|handler)`)

// productOptionPosition classifies a product-owned server option by the module
// constructor it reaches. An option whose body (or a directly called product
// helper) installs the module's handler-chain interceptor is handler-level: it
// runs after the transport dispatched the stream. A concurrency-named option
// with no established position blocks the proof rather than being ignored.
func (c *transportCensus) productOptionPosition(
	option transportCall,
	module string,
) (domain.TransportControlDisposition, string, *transportCall) {
	root := c.funcs[option.calleeKey()]
	if root == nil {
		return "", "", nil
	}
	frontier := []*transportFunc{root}
	seen := map[string]bool{root.key: true}
	installed := ""
	installedAt := ""
	for depth := 0; depth < 2 && len(frontier) > 0; depth++ {
		var next []*transportFunc
		for _, current := range frontier {
			for i := range current.calls {
				call := &current.calls[i]
				if domain.PackageInModule(call.pkgPath, module) && strings.Contains(call.name, "Interceptor") {
					installed = call.name
					installedAt = fmt.Sprintf("%s:%d", call.site.File, call.site.Line)
					break
				}
				inner := c.funcs[call.calleeKey()]
				if inner == nil || !c.products[call.pkgPath] || seen[inner.key] {
					continue
				}
				seen[inner.key] = true
				next = append(next, inner)
			}
			if installed != "" {
				break
			}
		}
		if installed != "" {
			break
		}
		frontier = next
	}
	if installed != "" {
		return domain.TransportControlHandlerLevel, fmt.Sprintf(
			"the product option %s.%s installs the module's %s handler-chain interceptor (%s); it runs after transport dispatch",
			option.pkgPath, option.name, installed, installedAt), nil
	}
	if concurrencyNameRe.MatchString(option.name) {
		return domain.TransportControlUnclassified,
			"a concurrency-shaped product server option whose position relative to transport dispatch is not established", nil
	}
	return "", "", nil
}

// classifyModuleOption classifies a server option by its execution position.
func classifyModuleOption(name string) (domain.TransportControlDisposition, string) {
	switch {
	case strings.Contains(name, "MaxConcurrentStream"):
		return domain.TransportControlTransportAdmission,
			"the transport's own stream admission is keyed on the active-stream set a reset removes, so it does not bound handler executions"
	case strings.Contains(name, "Interceptor"):
		return domain.TransportControlHandlerLevel,
			"the interceptor runs inside the handler chain after the transport admitted and dispatched the stream"
	case regexp.MustCompile(`(?i)^max(concurrent|conn)|^(conn|stream)limit|quota`).MatchString(name):
		return domain.TransportControlUnclassified,
			"a concurrency-shaped server option whose position relative to transport dispatch is not established"
	}
	return "", ""
}

// productControls enumerates the product-side controls and their positions.
// Only a proven pre-dispatch quota prevents the mechanism; a control whose
// position cannot be established blocks the proof instead of being ignored.
func (b *transportProofBuilder) productControls(
	rooted *transportRootedPath,
	module string,
	_ domain.SymbolRef,
) ([]domain.TransportControl, error) {
	var controls []domain.TransportControl
	fn := rooted.census.funcs[rooted.construction.caller]
	if fn != nil {
		for _, arg := range rooted.construction.args {
			call, ok := unparen(arg).(*ast.CallExpr)
			if !ok {
				continue
			}
			callee, ok := findCensusCall(fn, call)
			if !ok {
				continue
			}
			var disp domain.TransportControlDisposition
			var detail string
			if domain.PackageInModule(callee.pkgPath, module) {
				disp, detail = classifyModuleOption(callee.name)
			} else {
				// A product-owned option wrapper is classified by what it
				// installs: the podresources rate limiter is a product
				// function returning grpc.UnaryInterceptor(...), which is a
				// handler-chain control, never a pre-dispatch quota.
				disp, detail, _ = rooted.census.productOptionPosition(callee, module)
			}
			if disp == "" {
				continue
			}
			site, err := b.emitNode(domain.TransportSiteControl,
				domain.SymbolRef{Package: callee.pkgPath, Symbol: callee.name}, call, callee.site, detail)
			if err != nil {
				return nil, err
			}
			controls = append(controls, domain.TransportControl{
				Site: site, Disposition: disp, Detail: detail,
			})
		}
	}
	// A control elsewhere in the entry chain cannot bound the transport's
	// handler executions: only the function that constructs/serves the
	// transport is positioned around the vulnerable dispatch.
	for _, hop := range rooted.chain[:1] {
		if gate := productGate(hop); gate != nil {
			detail := "a bounded-concurrency select gate is applied by product code before transport dispatch: it bounds handler executions"
			site, err := b.emitNode(domain.TransportSiteControl,
				domain.SymbolRef{Package: hop.pkgPath, Symbol: hop.name}, gate,
				domain.CallSite{File: hop.file, Line: b.ix.fset.Position(gate.Pos()).Line,
					Package: hop.pkgPath, Function: hop.name}, detail)
			if err != nil {
				return nil, err
			}
			controls = append(controls, domain.TransportControl{
				Site: site, Disposition: domain.TransportControlPreDispatchQuota, Detail: detail,
			})
		}
		for _, call := range hop.calls {
			if !rooted.census.products[call.pkgPath] || !concurrencyNameRe.MatchString(call.name) {
				continue
			}
			if rootFn := rooted.census.funcs[rooted.construction.caller]; rootFn != nil {
				if call.call.Pos() >= rooted.construction.call.Pos() &&
					call.call.End() <= rooted.construction.call.End() {
					// Wrapped in a server option: the option's own
					// classification above decides its position.
					continue
				}
			}
			detail := "a product concurrency control whose position relative to the transport dispatch is not established"
			site, err := b.emitNode(domain.TransportSiteControl,
				domain.SymbolRef{Package: call.pkgPath, Symbol: call.name}, call.call, call.site, detail)
			if err != nil {
				return nil, err
			}
			controls = append(controls, domain.TransportControl{
				Site: site, Disposition: domain.TransportControlUnclassified, Detail: detail,
			})
		}
	}
	for _, c := range controls {
		if c.Disposition.Prevents() {
			return controls, fmt.Errorf(
				"product control %s.%s is a pre-dispatch handler quota and prevents the mechanism",
				c.Site.Symbol.Package, c.Site.Symbol.Symbol)
		}
		if c.Disposition.BlocksProof() {
			return controls, fmt.Errorf(
				"product control %s.%s has no established position relative to the vulnerable dispatch",
				c.Site.Symbol.Package, c.Site.Symbol.Symbol)
		}
	}
	return controls, nil
}

// productGate reports a bounded-concurrency select: a channel operation with a
// default/escape clause. That shape bounds concurrent work; where it sits
// decides whether it prevents the mechanism.
func productGate(fn *transportFunc) *ast.SelectStmt {
	var found *ast.SelectStmt
	ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
		if found != nil {
			return false
		}
		sel, ok := n.(*ast.SelectStmt)
		if !ok {
			return true
		}
		var channelOp, escape bool
		for _, clause := range sel.Body.List {
			cc, ok := clause.(*ast.CommClause)
			if !ok {
				continue
			}
			switch comm := cc.Comm.(type) {
			case nil:
				escape = true
			case *ast.SendStmt:
				channelOp = true
			case *ast.ExprStmt:
				if recv, ok := comm.X.(*ast.UnaryExpr); ok && recv.Op.String() == "<-" {
					channelOp = true
				}
			case *ast.AssignStmt:
				channelOp = true
			}
			if cc.Comm != nil && exprContainsDone(cc.Comm) {
				escape = true
			}
		}
		if channelOp && escape {
			found = sel
			return false
		}
		return true
	})
	return found
}

func exprContainsDone(n ast.Node) bool {
	found := false
	ast.Inspect(n, func(node ast.Node) bool {
		if found {
			return false
		}
		if sel, ok := node.(*ast.SelectorExpr); ok && sel.Sel.Name == "Done" {
			found = true
			return false
		}
		return true
	})
	return found
}

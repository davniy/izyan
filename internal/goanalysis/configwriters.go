package goanalysis

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

// ConfigWriters measures declaration-bound storage and direct uses in loaded
// product syntax. It does not select a vulnerable operation or solve ordering,
// interprocedural aliases, runtime values, or effective configuration.
func (ix *Index) ConfigWriters(ctx context.Context, ref domain.SymbolRef) (domain.ConfigWriterEvidence, error) {
	m := affected.MeasurePackageInventory(ctx, affected.ExecGoTool{Env: ix.Env, Version: ix.Build.GoVersion}, ix.Dir, ix.Build, false)
	return ix.ConfigWritersWithInventory(ctx, ref, m)
}

// ConfigWritersWithInventory preserves a caller's measured build inventory;
// unavailable or failed inventories leave explicit blockers, not empty closure.
func (ix *Index) ConfigWritersWithInventory(ctx context.Context, ref domain.SymbolRef, m affected.PackageInventoryMeasurement) (domain.ConfigWriterEvidence, error) {
	closure, err := ix.EnumerateImportClosureWithInventory(ctx, m)
	if err != nil { return domain.ConfigWriterEvidence{}, err }
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ctx); err != nil { return domain.ConfigWriterEvidence{}, err }
	e := domain.ConfigWriterEvidence{Subject: ref, Build: domain.EffectiveBuildContext(ix.Build), SourceHashes: closure.SourceHashes,
		InventoryReference: closure.InventoryReference, InventoryRaw: closure.InventoryRaw, InventoryRun: closure.InventoryRun,
		InventoryBuild: m.Build, InventorySHA256: m.RawSHA256, InventorySize: m.RawSize, InventoryScope: m.Scope, InventoryError: closure.InventoryError,
		Blockers: []string{
			"field declaration query does not select a consumed object or establish effective value; events are unordered",
			"dependency/external writers and interprocedural object identity are not enumerated",
			"inline/nested objects, unsupported aliases, callbacks, reflection and deserialization require separate closure; runtime channels are not effective values",
		}}
	if !closure.Complete { e.Blockers = append(e.Blockers, "source/build inventory closure is open") }
	members := map[string]bool{}
	for _, p := range ix.pkgs { members[p.PkgPath] = true }
	hashes, unhashed, _, unreadable, hashErr := ix.memberSourceEvidence(ctx, members)
	if hashErr != nil { return e, hashErr }
	if e.SourceHashes == nil { e.SourceHashes = map[string]string{} }
	for pkg, hash := range hashes { e.SourceHashes[pkg] = hash }
	if len(unhashed) > 0 || len(unreadable) > 0 { e.Blockers = append(e.Blockers, "measured product sources could not all be pinned") }
	e.FieldType = ix.symbolFieldTypeLocked(ctx, ref)
	if e.FieldType == "" { e.Blockers = append(e.Blockers, "field declaration/type unresolved") }
	s := configWriterScan{ix: ix, ref: ref, evidence: &e, objects: map[types.Object]int{}}
	for _, p := range ix.pkgs {
		if p.TypesInfo == nil { continue }
		for _, f := range p.Syntax {
			if ix.isTestFile(f) { continue }
			ast.Inspect(f, func(n ast.Node) bool {
				id, ok := n.(*ast.Ident)
				if !ok { return true }
				v, ok := p.TypesInfo.Defs[id].(*types.Var)
				if !ok || v.IsField() || !configTypeMatch(v.Type(), ref) { return true }
				pos := ix.fset.Position(id.Pos())
				o := domain.ConfigObject{ID: fmt.Sprintf("%s:%s:%d:%d:%s", p.PkgPath, pos.Filename, pos.Line, pos.Column, id.Name), Name: id.Name, Declaration: s.site(p, id)}
				_, o.Pointer = v.Type().(*types.Pointer)
				if o.Pointer { o.Blockers = append(o.Blockers, "pointer storage: pointee identity/mutation remains open") }
				if v.Parent() == p.Types.Scope() { o.Blockers = append(o.Blockers, "package storage: external/callback writes remain open") }
				s.objects[v] = len(e.Objects)
				e.Objects = append(e.Objects, o)
				return true
			})
		}
	}
	for _, p := range ix.pkgs { if p.TypesInfo != nil { for _, f := range p.Syntax { if !ix.isTestFile(f) { s.scan(p, f) } } } }
	packageScan := ingressScan{ix: ix}
	for obj := range s.objects { if v, ok := obj.(*types.Var); ok && isPackageVar(v) { packageScan.varReads = append(packageScan.varReads, varRead{vr:v}) } }
	if len(packageScan.varReads) > 0 {
		for v, writes := range packageScan.collectVarWrites() { if i, ok := s.objects[v]; ok { for _, escape := range writes.escapes { s.block(i, escape) } } }
	}
	if len(e.Objects) == 0 { e.Blockers = append(e.Blockers, "no declaration-bound configuration storage measured; inline/nested/foreign objects unresolved") }
	e.Assignments = ix.fieldAssignmentsLocked(ref)
	for i := range e.Objects {
		initialized := false
		for _, ev := range e.Objects[i].Events { if ev.Kind == "default" || ev.Kind == "copy" || ev.Kind == "alias" || ev.Kind == "write" { initialized = true } }
		if !initialized { e.Objects[i].Blockers = append(e.Objects[i].Blockers, "initial object state unresolved (parameter/receiver or unsupported declaration)") }
		e.Objects[i].Blockers = dedupStrings(e.Objects[i].Blockers)
	}
	sort.Slice(e.Objects, func(i, j int) bool { return e.Objects[i].ID < e.Objects[j].ID })
	return e, nil
}

func configTypeMatch(t types.Type, ref domain.SymbolRef) bool {
	if p, ok := t.(*types.Pointer); ok { t = p.Elem() }
	t = types.Unalias(t)
	n, ok := t.(*types.Named)
	typeName, _ := splitSymbol(ref.Symbol)
	return ok && n.Obj().Pkg() != nil && n.Obj().Pkg().Path() == ref.Package && n.Obj().Name() == typeName
}

type configWriterScan struct {
	ix *Index
	ref domain.SymbolRef
	evidence *domain.ConfigWriterEvidence
	objects map[types.Object]int
}

func (s *configWriterScan) site(p *packages.Package, n ast.Node) domain.CallSite {
	if call, ok := n.(*ast.CallExpr); ok { return s.ix.siteOf(p,nil,call) }
	pos := s.ix.fset.Position(n.Pos())
	return domain.CallSite{Package: p.PkgPath, File: pos.Filename, Line: pos.Line, Column: pos.Column}
}

func (s *configWriterScan) object(info *types.Info, e ast.Expr) (int, bool) {
	switch x := e.(type) {
	case *ast.Ident:
		i, ok := s.objects[info.ObjectOf(x)]; return i, ok
	case *ast.ParenExpr: return s.object(info, x.X)
	case *ast.UnaryExpr: return s.object(info, x.X)
	case *ast.StarExpr: return s.object(info, x.X)
	case *ast.SelectorExpr:
		if sel := info.Selections[x]; sel != nil && sel.Kind() == types.FieldVal && selObjMatch(sel, s.ref) { return s.object(info, x.X) }
	}
	return 0, false
}

func (s *configWriterScan) event(i int, ev domain.ConfigWriterEvent) { s.evidence.Objects[i].Events = append(s.evidence.Objects[i].Events, ev) }
func (s *configWriterScan) block(i int, why string) { s.evidence.Objects[i].Blockers = append(s.evidence.Objects[i].Blockers, why) }

func (s *configWriterScan) write(p *packages.Package, lhs ast.Expr, rhs ast.Expr) {
	i, ok := s.object(p.TypesInfo, lhs)
	if !ok { return }
	ev := domain.ConfigWriterEvent{Kind: "write", Site: s.site(p, lhs), Argument: -1}
	if sel, ok := lhs.(*ast.SelectorExpr); ok {
		selection := p.TypesInfo.Selections[sel]
		if selection == nil || !selObjMatch(selection, s.ref) { return }
		if rhs != nil { ev.Value, ev.ValueSource = exprConstValue(p.TypesInfo, rhs); s.channels(p, rhs, i) }
		if ev.ValueSource == "" { s.block(i, "field write has unresolved runtime value") }
		s.event(i, ev); return
	}
	if rhs == nil {
		ev.Kind = "default"
		if !s.evidence.Objects[i].Pointer && s.evidence.FieldType == "bool" { ev.Value, ev.ValueSource = "false", "zero" } else { s.block(i, "default value unsupported or nil pointer") }
		s.event(i, ev); return
	}
	if j, ok := s.object(p.TypesInfo, rhs); ok {
		ev.Kind = "copy"
		if s.evidence.Objects[i].Pointer { ev.Kind = "alias"; s.block(i, "pointer alias requires pointee writer closure"); s.block(j, "address/pointer alias escapes declaration-local writes") }
		ev.RelatedObject = s.evidence.Objects[j].ID
		s.event(i, ev); return
	}
	value := rhs
	if un, ok := value.(*ast.UnaryExpr); ok && un.Op == token.AND { value = un.X }
	if lit, ok := value.(*ast.CompositeLit); ok && configTypeMatch(p.TypesInfo.TypeOf(lit), s.ref) {
		ev.Kind = "default"
		_, field := splitSymbol(s.ref.Symbol)
		found := false
		for _, elt := range lit.Elts {
			if kv, ok := elt.(*ast.KeyValueExpr); ok { if id, ok := kv.Key.(*ast.Ident); ok && id.Name == field { ev.Value, ev.ValueSource = exprConstValue(p.TypesInfo, kv.Value); s.channels(p, kv.Value, i); found = true } } else { s.block(i, "positional struct initializer not resolved") }
		}
		if !found && len(lit.Elts) == 0 && s.evidence.FieldType == "bool" { ev.Value, ev.ValueSource = "false", "zero" }
		if !found && len(lit.Elts) > 0 { // keyed omission is a zero default only when every element is keyed.
			keyed := true; for _, elt := range lit.Elts { if _, ok := elt.(*ast.KeyValueExpr); !ok { keyed = false } }
			if keyed && s.evidence.FieldType == "bool" { ev.Value, ev.ValueSource = "false", "zero" }
		}
		if ev.ValueSource == "" { s.block(i, "constructor/default field value unresolved") }
		s.event(i, ev); return
	}
	s.event(i, ev)
	s.block(i, "whole-object write/constructor result unresolved")
	s.channels(p, rhs, i)
}

func (s *configWriterScan) channels(p *packages.Package, n ast.Node, i int) {
	ast.Inspect(n, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr); if !ok { return true }
		ref := configCallee(p.TypesInfo, c)
		channel := configChannel(ref)
		if channel == "" { return true }
		ev := domain.ConfigWriterEvent{Kind: "override", Site: s.site(p, c), Callee: ref, Channel: channel, Argument: -1}
		if len(c.Args) > 0 { ev.Key, _ = exprConstValue(p.TypesInfo, c.Args[0]) }
		s.event(i, ev); s.block(i, "runtime override value unknown: " + channel)
		return true
	})
}

func configCallee(info *types.Info, c *ast.CallExpr) domain.SymbolRef {
	fn, ok := calleeObject(info, calleeExpr(c.Fun)).(*types.Func)
	if !ok || fn.Pkg() == nil { return domain.SymbolRef{} }
	symbol := fn.Name()
	if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil { symbol = recvTypeName(sig.Recv().Type()) + "." + symbol }
	return domain.SymbolRef{Package: fn.Pkg().Path(), Symbol: symbol}
}

func configChannel(ref domain.SymbolRef) string {
	_, method := splitSymbol(ref.Symbol)
	if method != "" { ref.Symbol = method }
	switch {
	case ref.Package == "os" && (ref.Symbol == "Getenv" || ref.Symbol == "LookupEnv"): return "environment"
	case ref.Package == "flag": return "flag"
	case ref.Package == "os" && (ref.Symbol == "ReadFile" || ref.Symbol == "Open" || ref.Symbol == "OpenFile"): return "config-file"
	case (ref.Package == "encoding/json" || ref.Package == "encoding/xml" || ref.Package == "encoding/gob" || strings.Contains(ref.Package, "yaml")) && (ref.Symbol == "Unmarshal" || ref.Symbol == "Decode"): return "deserialization"
	case ref.Package == "reflect": return "reflection"
	}
	return ""
}

func (s *configWriterScan) scan(p *packages.Package, f *ast.File) {
	info := p.TypesInfo
	nonReads := map[ast.Expr]bool{}
	directCallees := map[ast.Expr]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			directCallees[calleeExpr(x.Fun)] = true
		case *ast.AssignStmt:
			for _, lhs := range x.Lhs { nonReads[lhs] = true }
		case *ast.RangeStmt:
			if x.Key != nil { nonReads[x.Key] = true }
			if x.Value != nil { nonReads[x.Value] = true }
		case *ast.UnaryExpr:
			if x.Op == token.AND { nonReads[x.X] = true }
		}
		return true
	})
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.Field:
			for _, id := range x.Names { if i, ok := s.object(info,id); ok { s.block(i,"parameter/receiver initial state and caller identity unresolved") } }
		case *ast.FuncLit:
			ast.Inspect(x.Body, func(n ast.Node) bool { if id, ok := n.(*ast.Ident); ok { if i, ok := s.object(info,id); ok { s.block(i,"closure/callback access: invocation and mutation scope unresolved") } }; return true })
		case *ast.ValueSpec:
			for j, id := range x.Names {
				if len(x.Values) > 0 && len(x.Values) != len(x.Names) {
					if i, ok := s.object(info,id); ok {
						s.block(i,"multi-result initializer: constructor result unresolved")
						s.event(i,domain.ConfigWriterEvent{Kind:"write",Site:s.site(p,id),Argument:-1})
					}
					continue
				}
				var rhs ast.Expr
				if j < len(x.Values) { rhs = x.Values[j] }
				s.write(p,id,rhs)
			}
		case *ast.AssignStmt:
			for j, lhs := range x.Lhs { if j < len(x.Rhs) { s.write(p, lhs, x.Rhs[j]) } else if i, ok := s.object(info, lhs); ok { s.block(i, "multi-result assignment unresolved") } }
			for _, rhs := range x.Rhs {
				if i, ok := s.object(info,rhs); ok {
					for _, lhs := range x.Lhs { if _, bound := s.object(info,lhs); !bound { if id, blank := lhs.(*ast.Ident); blank && id.Name == "_" { continue }; s.block(i,"stored into unsupported alias/aggregate destination") } }
				}
			}
		case *ast.RangeStmt:
			for _, target := range []ast.Expr{x.Key,x.Value} {
				if i, ok := s.object(info,target); ok {
					s.block(i,"range assignment: iterated field/object value unresolved")
					s.event(i,domain.ConfigWriterEvent{Kind:"range-write",Site:s.site(p,target),Argument:-1})
				}
			}
 		case *ast.SendStmt:
			if i, ok := s.object(info,x.Value); ok { s.block(i,"configuration sent through channel: external writers unresolved") }
		case *ast.UnaryExpr:
			if x.Op == token.AND { if i, ok := s.object(info, x.X); ok { s.event(i, domain.ConfigWriterEvent{Kind:"address", Site:s.site(p,x), Argument:-1}); s.block(i,"address taken: indirect writers not closed") } }
		case *ast.ReturnStmt:
			for _, v := range x.Results { if i, ok := s.object(info,v); ok { s.block(i,"returned configuration: caller writes/consumption unresolved") } }
		case *ast.CallExpr:
			ref := configCallee(info,x)
			channel := configChannel(ref)
			if channel != "" {
				ev := domain.ConfigWriterEvent{Kind:"runtime-reader", Site:s.site(p,x), Callee:ref, Channel:channel, Argument:-1}
				keyArg := 0
				if channel == "flag" && strings.HasSuffix(ref.Symbol,"Var") { keyArg = 1 }
				if keyArg < len(x.Args) { ev.Key, _ = exprConstValue(info,x.Args[keyArg]) }
				s.evidence.RuntimeChannels = append(s.evidence.RuntimeChannels,ev)
			}
			for j := -1; j < len(x.Args); j++ {
				var arg ast.Expr
				if j < 0 {
					sel, ok := calleeExpr(x.Fun).(*ast.SelectorExpr)
					if !ok { continue }
					selection := info.Selections[sel]
					if selection == nil || selection.Kind() != types.MethodVal { continue }
					arg = sel.X
				} else { arg = x.Args[j] }
				if i, ok := s.object(info,arg); ok {
					ev := domain.ConfigWriterEvent{Kind:"consume", Site:s.site(p,x), Callee:ref, Argument:j}
					if channel != "" { ev.Channel = channel; s.block(i,"runtime override/reflective mutation: " + channel) }
					s.event(i,ev)
					_, scalar := arg.(*ast.SelectorExpr)
					if scalar { sel := arg.(*ast.SelectorExpr); selection := info.Selections[sel]; scalar = selection != nil && selObjMatch(selection,s.ref) }
					if !scalar { s.block(i,"object passed to callee: external/callback/interprocedural writes unresolved") }
					if ref.Package == "" { s.block(i,"unresolved callback/dynamic call") }
				}
			}
		case *ast.SelectorExpr:
			if selection := info.Selections[x]; selection != nil && selection.Kind() == types.MethodVal && !directCallees[x] {
				if fn, ok := selection.Obj().(*types.Func); ok {
					if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
						if _, pointer := sig.Recv().Type().(*types.Pointer); pointer {
							if i, ok := s.object(info,x.X); ok {
								s.block(i,"pointer-receiver method value captures receiver: implicit address/callback mutation unresolved")
								ref := domain.SymbolRef{Package:fn.Pkg().Path(),Symbol:recvTypeName(sig.Recv().Type()) + "." + fn.Name()}
								s.event(i,domain.ConfigWriterEvent{Kind:"receiver-capture",Site:s.site(p,x),Callee:ref,Argument:-1})
							}
						}
					}
				}
			}
			if selection := info.Selections[x]; selection != nil && selObjMatch(selection,s.ref) {
				if i, ok := s.object(info,x.X); ok {
					if !nonReads[x] { s.event(i,domain.ConfigWriterEvent{Kind:"read",Site:s.site(p,x),Argument:-1}) }
				} else { s.evidence.Blockers = append(s.evidence.Blockers,"field reference has unsupported receiver identity") }
			}
		}
		return true
	})
}

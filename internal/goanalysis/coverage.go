package goanalysis

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"path"
	"strings"

	"github.com/davniy/izyan/internal/domain"
	"golang.org/x/tools/go/packages"
)

// GatedRefs scans source files excluded by the current build
// configuration (pkg.IgnoredFiles, minus _test.go) for syntactic
// references to the subject. A hit does not prove a path — the file may
// be dead code — but it means a build with different tags could reach
// the subject, so a negative claim cannot be called verified within the
// current scope.
func (ix *Index) GatedRefs(ctx context.Context, ref domain.SymbolRef) ([]domain.CallSite, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ctx); err != nil {
		return nil, err
	}
	return ix.gatedRefs(ref), nil
}

// gatedRefs is the lock-and-load-free core of GatedRefs; callers must
// hold ix.mu with the index already loaded.
func (ix *Index) gatedRefs(ref domain.SymbolRef) []domain.CallSite {
	typeName, name := splitSymbol(ref.Symbol)
	seen := map[string]bool{}
	var out []domain.CallSite
	for _, pkg := range ix.pkgs {
		for _, path := range pkg.IgnoredFiles {
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || seen[path] {
				continue
			}
			seen[path] = true
			f, err := parser.ParseFile(ix.fset, path, nil, 0)
			if err != nil {
				continue
			}
			out = append(out, gatedFileRefs(ix.fset, pkg, f, ref, typeName, name)...)
		}
	}
	return out
}

// gatedFileRefs matches subject references in an untyped file: the file
// must import the subject's package; bare-name subjects match
// `alias.Name`, Type.Method subjects match `alias.Type` uses plus
// `.Method` selectors when the file also references the type.
func gatedFileRefs(fset *token.FileSet, pkg *packages.Package, f *ast.File,
	ref domain.SymbolRef, typeName, name string) []domain.CallSite {

	aliases := map[string]bool{}
	for _, imp := range f.Imports {
		if strings.Trim(imp.Path.Value, `"`) != ref.Package {
			continue
		}
		if imp.Name != nil {
			if imp.Name.Name == "." {
				aliases[""] = true // dot import: bare identifier use
			} else {
				aliases[imp.Name.Name] = true
			}
		} else {
			aliases[path.Base(ref.Package)] = true
		}
	}
	if len(aliases) == 0 {
		return nil
	}
	typeReferenced := typeName == "" || aliases[""]
	var out []domain.CallSite
	site := func(n ast.Node, enc *ast.FuncDecl) {
		pos := fset.Position(n.Pos())
		cs := domain.CallSite{File: pos.Filename, Line: pos.Line, Package: pkg.PkgPath}
		if enc != nil && enc.Name != nil {
			cs.Function = enc.Name.Name
		}
		out = append(out, cs)
	}
	// First pass: does the file reference the declaring type? Without it
	// an `x.Method` selector cannot plausibly reach the subject.
	if typeName != "" && !typeReferenced {
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if ok && aliases[id.Name] && sel.Sel.Name == typeName {
				typeReferenced = true
			}
			return !typeReferenced
		})
	}
	inspectDecls(f, func(n ast.Node, enc *ast.FuncDecl) bool {
		switch e := n.(type) {
		case *ast.SelectorExpr:
			id, ok := e.X.(*ast.Ident)
			if ok && aliases[id.Name] && (e.Sel.Name == name || e.Sel.Name == typeName) {
				site(e, enc)
				return true
			}
			if typeName != "" && typeReferenced && e.Sel.Name == name {
				site(e, enc)
			}
		case *ast.Ident:
			if aliases[""] && e.Name == name {
				site(e, enc)
			}
		}
		return true
	})
	return out
}

// InterfaceDispatchSites finds product call sites `x.Method()` where x
// is statically an interface type and the subject's receiver type
// implements that interface. SearchSymbol misses these: the selection
// resolves to the interface method, not to Type.Method. Each site is a
// dispatch candidate — the concrete impl behind the interface may be the
// subject's type, so a negative reachability claim over these sites is
// not closed — even when the interface itself is declared in the
// subject's package (for a concrete subject the call still dispatches
// to the impl; interface-typed receivers can never be a dynamic type
// and return no candidates). When the subject's receiver type cannot
// be resolved in the loaded packages the scan falls back to every
// interface method call with a matching name — a superset of the real
// candidates — so the enumeration stays open rather than report a
// false empty set.
func (ix *Index) InterfaceDispatchSites(ctx context.Context, ref domain.SymbolRef) ([]domain.CallSite, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ctx); err != nil {
		return nil, err
	}
	sites, _, err := ix.interfaceDispatchSites(ctx, ref)
	return sites, err
}

// interfaceDispatchSites is the lock-free core of InterfaceDispatchSites;
// callers must hold ix.mu with the index already loaded. The bool result
// is true when the receiver type could not be resolved: the returned
// sites are then the name-matched superset, the real candidate set is
// not proven covered, and instantiation narrowing must not run.
func (ix *Index) interfaceDispatchSites(ctx context.Context, ref domain.SymbolRef) ([]domain.CallSite, bool, error) {
	typeName, name := splitSymbol(ref.Symbol)
	recvName := subjectRecvName(typeName)
	if recvName == "" {
		return nil, false, nil // plain functions cannot be interface-dispatched
	}
	recv := ix.lookupNamedType(ctx, ref.Package, recvName)
	if recv != nil {
		if _, isIface := recv.Underlying().(*types.Interface); isIface {
			// An interface-typed receiver can never be the dynamic
			// type of an interface call — calls to its method are the
			// subject itself, not dispatch candidates.
			return nil, false, nil
		}
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
				if !ok || seln.Kind() != types.MethodVal || seln.Obj().Name() != name {
					return true
				}
				iface, ok := seln.Recv().Underlying().(*types.Interface)
				if !ok {
					return true // concrete receiver — SearchSymbol already covers
				}
				// With the receiver type resolved, only interfaces it
				// satisfies are dispatch candidates. Unresolved, the
				// subject's type may still implement this interface —
				// keep every name-matched site open rather than claim
				// the candidate set empty. A call to an interface method
				// declared in the subject's package still counts: for a
				// concrete receiver the dispatch can land on the impl.
				if recv != nil && !types.Implements(recv, iface) &&
					!types.Implements(types.NewPointer(recv), iface) {
					return true
				}
				// With the receiver type resolved, only interfaces it
				// satisfies are dispatch candidates. Unresolved, the
				// subject's type may still implement this interface —
				// keep every name-matched site open rather than claim
				// the candidate set empty.
				if recv != nil && !types.Implements(recv, iface) &&
					!types.Implements(types.NewPointer(recv), iface) {
					return true
				}
				pos := ix.fset.Position(sel.Pos())
				cs := domain.CallSite{
					File:    pos.Filename,
					Line:    pos.Line,
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
	return out, recv == nil, nil
}

// subjectRecvName normalizes a method symbol's receiver part to the bare
// type name — "T" and "(*T)" both name receiver type T — matching the
// normalization IsReceiverTypeInstantiated applies. "" for non-method
// receivers.
func subjectRecvName(typeName string) string {
	t := strings.TrimSpace(typeName)
	t = strings.Trim(t, "()*")
	return strings.TrimSpace(t)
}

// lookupNamedType resolves a named type in pkgPath, searching product
// roots first and falling back to loading the package directly.
func (ix *Index) lookupNamedType(ctx context.Context, pkgPath, typeName string) *types.Named {
	find := func(pkgs []*packages.Package) *types.Named {
		for _, pkg := range pkgs {
			if pkg.PkgPath != pkgPath || pkg.Types == nil {
				continue
			}
			if tn, ok := pkg.Types.Scope().Lookup(typeName).(*types.TypeName); ok {
				if named, ok := tn.Type().(*types.Named); ok {
					return named
				}
			}
		}
		return nil
	}
	if t := find(ix.pkgs); t != nil {
		return t
	}
	extra, err := ix.loadExtra(ctx, pkgPath)
	if err != nil {
		return nil
	}
	return find(extra)
}

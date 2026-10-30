package refindex

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"

	pbdomain "github.com/fedorovmv/izyan/internal/productb/domain"
)

// SymbolLocator is the slice of goanalysis.Index the decl resolver needs —
// an interface so tests can stub it without loading packages.
type SymbolLocator interface {
	FindSymbol(ctx context.Context, ref pbdomain.SymbolRef) (*pbdomain.CallSite, error)
}

// resolveDecls fills each atom's Decl and precise SymbolKind. Atoms whose
// declaration cannot be located keep Decl == nil and the spelling-derived
// kind — an unresolvable declaration is an open result, never proof of
// absence (mirroring ProductUsage's rule).
func resolveDecls(ctx context.Context, loc SymbolLocator, atoms []Atom) {
	if loc == nil {
		return
	}
	for i := range atoms {
		if atoms[i].Symbol == "" {
			continue // package atoms carry no decl
		}
		cs, err := loc.FindSymbol(ctx, pbdomain.SymbolRef{
			Package: atoms[i].Package, Symbol: atoms[i].Symbol,
		})
		if err != nil || cs == nil || cs.File == "" {
			continue
		}
		d := inspectDecl(cs.File, atoms[i].Symbol, cs.Line)
		d.Path = cs.File
		if d.Line == 0 {
			d.Line = cs.Line
		}
		atoms[i].Decl = &d.Decl
		if d.kind != "" {
			atoms[i].SymbolKind = d.kind
		}
	}
}

// declHit is the parser's view of one located declaration.
type declHit struct {
	Decl
	kind string
}

// inspectDecl parses the file FindSymbol named and locates the
// declaration of sym near the anchor line, returning its extent and real
// kind. FuncDecl.End() supplies end_line; type/var specs end on their
// spec node. kind "" means "keep the caller's guess".
func inspectDecl(file, sym string, anchor int) declHit {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, parser.SkipObjectResolution)
	if err != nil {
		return declHit{Decl: Decl{Line: anchor}}
	}
	typeName, name := splitSymbol(sym)
	pos := func(n ast.Node) (int, int) {
		return fset.Position(n.Pos()).Line, fset.Position(n.End()).Line
	}
	best := declHit{Decl: Decl{Line: anchor}}
	for _, decl := range f.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if d.Name == nil || d.Name.Name != name {
				continue
			}
			if typeName != "" && recvBaseName(d) != typeName {
				continue
			}
			start, end := pos(d)
			kind := KindFunc
			if d.Recv != nil && len(d.Recv.List) > 0 {
				kind = KindMethod
			}
			return declHit{Decl: Decl{Line: start, EndLine: end}, kind: kind}
		case *ast.GenDecl:
			if typeName != "" {
				continue // T.M members live inside FuncDecls or struct fields
			}
			for _, spec := range d.Specs {
				var n ast.Node
				var nm string
				kind := ""
				switch s := spec.(type) {
				case *ast.TypeSpec:
					n, nm, kind = s, s.Name.Name, KindType
				case *ast.ValueSpec:
					for _, id := range s.Names {
						if id.Name == name {
							n, nm, kind = s, id.Name, KindVar
							break
						}
					}
				}
				if kind == "" || nm != name {
					continue
				}
				start, end := pos(n)
				return declHit{Decl: Decl{Line: start, EndLine: end}, kind: kind}
			}
		}
	}
	// Struct-field members (symbol "T.Field"): locate the type spec and
	// scan its fields. Kind stays "method"/"type" honest — a field is
	// part of the type's declaration, so we report the enclosing TypeSpec
	// extent with kind "type".
	if typeName != "" {
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, spec := range gd.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok || ts.Name.Name != typeName {
					continue
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok {
					continue
				}
				for _, field := range st.Fields.List {
					for _, id := range field.Names {
						if id.Name == name {
							start, end := pos(ts)
							return declHit{Decl: Decl{Line: start, EndLine: end}, kind: KindType}
						}
					}
				}
			}
		}
	}
	return best
}

// recvBaseName renders a method receiver's base type name: "T" for both
// "T" and "*T" receivers.
func recvBaseName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return ""
	}
	return strings.TrimPrefix(recvTypeString(fd.Recv.List[0].Type), "*")
}

// recvTypeString renders the syntactic receiver expression.
func recvTypeString(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return "*" + recvTypeString(t.X)
	case *ast.IndexExpr: // generic receiver T[P]
		return recvTypeString(t.X)
	case *ast.IndexListExpr:
		return recvTypeString(t.X)
	}
	return ""
}

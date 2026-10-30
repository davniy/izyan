package fixbinding

import (
	"go/ast"
	"go/token"
	"strconv"
)

// This file recognises registration constructions independently of any patch
// path. A registration is a construction — typically a composite literal passed
// to a register call — that names an identity and carries an initializer
// function. Its initializer is where a component's implementation is supplied,
// so a closed implementation boundary must resolve every one of them instead of
// treating the registration call as an opaque, harmless call.
//
// Recognition is structural. The identity is read from a literal or a
// resolvable constant, never from a computed value; the initializer is
// classified as a literal (whose body is walked with its own bindings), a named
// declaration (which must be found inside the boundary), or unresolved (which
// defeats the certificate).

// registrationFields names the fields the recognition understands. The set is
// closed: a construction that carries a function value under another field name
// is still recognised (the initializer rule is structural), but only these names
// are read for the declared identity.
var identityFields = map[string]bool{"ID": true, "Id": true, "id": true, "Name": true, "name": true}

// initializerFields are the field names a registration construction uses for
// the function that supplies the component. A value under another name is still
// recognised structurally; these names are recognised even when the value is not
// a resolvable function, because then the construction is unresolved rather than
// absent.
var initializerFields = map[string]bool{"InitFn": true, "Init": true, "Initializer": true}

// recordRegistrationArgValues evaluates every argument of a recognised
// registration call except the initializer function, so a resource derivation
// cannot hide behind a registration.
func (s *censusScan) recordRegistrationArgValues(args []ast.Expr) {
	for _, arg := range args {
		lit, ok := compositeLiteralOf(arg)
		if !ok {
			s.eval(arg)
			continue
		}
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				s.eval(elt)
				continue
			}
			if _, ok := kv.Key.(*ast.Ident); !ok {
				s.eval(kv.Value)
				continue
			}
			kind, _, isFunction := s.v.functionValue(kv.Value)
			if isFunction && kind != InitUnresolved {
				// A named initializer is a declaration scanned elsewhere; an
				// inline initializer must be analysed here, because the
				// registration call is consumed as a whole.
				if literal, ok := funcLiteralOf(kv.Value); ok {
					s.checkClosure(literal)
				}
				continue
			}
			s.eval(kv.Value)
		}
	}
}

// registrationFromCall returns the registration construction a call carries.
// A call with no composite-literal argument, or one whose literal carries no
// function value and no initializer field, is not a registration.
func (s *censusScan) registrationFromCall(call *ast.CallExpr) (CensusRegistration, bool) {
	for _, arg := range call.Args {
		lit, ok := compositeLiteralOf(arg)
		if !ok {
			continue
		}
		if reg, ok := s.registrationFromLiteral(call, lit); ok {
			return reg, true
		}
	}
	return CensusRegistration{}, false
}

// registrationFromLiteral classifies one candidate registration literal.
func (s *censusScan) registrationFromLiteral(call *ast.CallExpr, lit *ast.CompositeLit) (CensusRegistration, bool) {
	reg := CensusRegistration{
		File:        s.v.Path,
		Line:        s.v.Fset.Position(call.Pos()).Line,
		Package:     s.v.PackagePath,
		Declaration: s.decl,
		InitKind:    InitUnresolved,
	}
	recognised := false
	initializer := false
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		if identityFields[key.Name] {
			if value, ok := s.v.constString(kv.Value); ok {
				reg.Identity = value
				reg.IdentityResolved = true
			}
			recognised = true
			continue
		}
		if kind, target, ok := s.v.functionValue(kv.Value); ok {
			reg.InitKind = kind
			reg.InitField = key.Name
			if target != nil {
				reg.InitName = target.name
				reg.InitPackage = target.pkg
				reg.InitFile = target.file
				reg.InitLine = target.line
			}
			initializer = true
			recognised = true
			continue
		}
		if initializerFields[key.Name] {
			// A declared initializer field carrying anything else is still an
			// initializer — one whose construction is not established.
			reg.InitKind = InitUnresolved
			reg.InitField = key.Name
			initializer = true
			recognised = true
		}
	}
	if !recognised || !initializer {
		return CensusRegistration{}, false
	}
	return reg, true
}

// funcLiteralOf returns the function literal an expression states, if any.
func funcLiteralOf(expr ast.Expr) (*ast.FuncLit, bool) {
	for {
		switch x := expr.(type) {
		case *ast.ParenExpr:
			expr = x.X
			continue
		case *ast.UnaryExpr:
			if x.Op == token.AND {
				expr = x.X
				continue
			}
		case *ast.FuncLit:
			return x, true
		}
		return nil, false
	}
}

// functionTarget is the declaration a function-valued expression names.
type functionTarget struct {
	name string
	pkg  string
	file string
	line int
}

// functionValue classifies an initializer expression. A literal is analysed at
// its own position; a named declaration is resolved to its declaration so a
// later boundary check can require it to be inside the boundary.
func (v *fileView) functionValue(expr ast.Expr) (string, *functionTarget, bool) {
	for {
		switch x := expr.(type) {
		case *ast.ParenExpr:
			expr = x.X
			continue
		case *ast.UnaryExpr:
			if x.Op == token.AND {
				expr = x.X
				continue
			}
		case *ast.CallExpr:
			// A constructor call is not a function value: its result is an
			// object, not an initializer.
			return "", nil, false
		}
		break
	}
	switch x := expr.(type) {
	case *ast.FuncLit:
		return InitLiteral, nil, true
	case *ast.Ident:
		if x.Obj != nil && x.Obj.Kind == ast.Fun {
			if d, ok := x.Obj.Decl.(*ast.FuncDecl); ok {
				return InitNamed, &functionTarget{
					name: x.Name,
					file: v.Path,
					line: v.Fset.Position(d.Pos()).Line,
				}, true
			}
			return InitUnresolved, nil, true
		}
		if x.Obj == nil && !isImportName(v, x.Name) {
			if d := v.Pkg.function(x.Name); d != nil {
				return InitNamed, &functionTarget{
					name: x.Name,
					file: v.Pkg.pathOf(d),
					line: v.Fset.Position(d.Pos()).Line,
				}, true
			}
		}
		// A variable, constant or import name is not a declared function: the
		// field is not an initializer unless its declared name says it is, and
		// then it is an unresolved construction.
		return "", nil, false
	case *ast.SelectorExpr:
		base, ok := x.X.(*ast.Ident)
		if !ok || base.Obj != nil || !isImportName(v, base.Name) {
			return "", nil, false
		}
		importPath, known := v.Imports[base.Name]
		if !known {
			return InitUnresolved, nil, true
		}
		return InitNamed, &functionTarget{name: x.Sel.Name, pkg: importPath}, true
	}
	return "", nil, false
}

// compositeLiteralOf unwraps &, parentheses and conversions to a composite
// literal.
func compositeLiteralOf(expr ast.Expr) (*ast.CompositeLit, bool) {
	for {
		switch x := expr.(type) {
		case *ast.ParenExpr:
			expr = x.X
			continue
		case *ast.UnaryExpr:
			if x.Op == token.AND {
				expr = x.X
				continue
			}
		case *ast.CompositeLit:
			return x, true
		}
		return nil, false
	}
}

// constString resolves a string literal or a declared constant with a string
// literal initializer. Anything computed at run time is not an identity.
func (v *fileView) constString(expr ast.Expr) (string, bool) {
	for {
		switch x := expr.(type) {
		case *ast.ParenExpr:
			expr = x.X
			continue
		case *ast.BasicLit:
			if x.Kind != token.STRING {
				return "", false
			}
			value, err := strconv.Unquote(x.Value)
			if err != nil {
				return "", false
			}
			return value, true
		case *ast.Ident:
			if x.Obj == nil {
				return "", false
			}
			decl, ok := v.Values[x.Obj]
			if !ok || decl.Init == nil {
				return "", false
			}
			expr = decl.Init
			continue
		case *ast.BinaryExpr:
			// A constant concatenation of literals is a literal identity.
			left, leftOK := v.constString(x.X)
			right, rightOK := v.constString(x.Y)
			if !leftOK || !rightOK || x.Op != token.ADD {
				return "", false
			}
			return left + right, true
		}
		return "", false
	}
}

// pathOf is the file a package-index declaration was read from.
func (p *packageIndex) pathOf(d *ast.FuncDecl) string {
	if p == nil || d == nil {
		return ""
	}
	if v, ok := p.Owners[d]; ok {
		return v.Path
	}
	return ""
}

package fixbinding

import (
	"fmt"
	"go/ast"
	"go/token"
	"strconv"
	"strings"
)

// ExprKind names the structural form of a resolved expression.
type ExprKind string

const (
	ExprValue    ExprKind = "value"
	ExprLiteral  ExprKind = "literal"
	ExprPackage  ExprKind = "package"
	ExprSelector ExprKind = "selector"
	ExprCall     ExprKind = "call"
	ExprIndex    ExprKind = "index"
	ExprUnary    ExprKind = "unary"
	ExprBinary   ExprKind = "binary"
	ExprUnknown  ExprKind = "unknown"
)

// ValueIdentity names a declared value by provenance: the source that owns the
// declaration, the package-qualified declared type, the declaration itself, and
// whether it is a parameter, receiver, result, local or package-level value.
// Two unrelated configuration instances of the same type differ here; two
// references to the same declaration do not.
type ValueIdentity struct {
	Source      string `json:"source"`
	PackagePath string `json:"package_path"`
	Type        string `json:"type"`
	Decl        string `json:"decl"`
	Origin      string `json:"origin"`
	Ordinal     int    `json:"ordinal"`
	Name        string `json:"name,omitempty"`
}

// Equal compares provenance, not spelling: the declared name is already part of
// Decl, so a rename cannot accidentally equate two distinct declarations.
func (v ValueIdentity) Equal(o ValueIdentity) bool {
	return v.Source == o.Source &&
		v.PackagePath == o.PackagePath &&
		v.Type == o.Type &&
		v.Decl == o.Decl &&
		v.Origin == o.Origin &&
		v.Ordinal == o.Ordinal
}

// SelectorIdentity is one field access in a derivation chain. Owner is the
// package-qualified declared type of the value the field is selected from, so
// two unrelated Config.Root fields cannot compare equal even when both structs
// are named Config and both fields have the same name and type.
type SelectorIdentity struct {
	X         *ExprIdentity `json:"x"`
	Name      string        `json:"name"`
	Owner     string        `json:"owner"`
	FieldType string        `json:"field_type,omitempty"`
}

// CallIdentity is one constructor or function application in a derivation
// chain, with the resolved callee declaration and structurally resolved args.
type CallIdentity struct {
	Function APIIdentity     `json:"function"`
	Args     []*ExprIdentity `json:"args,omitempty"`
}

// IndexIdentity is one index operation.
type IndexIdentity struct {
	X     *ExprIdentity `json:"x"`
	Index *ExprIdentity `json:"index"`
}

// UnaryIdentity is one unary operation (&, *, -, !, ^, <-).
type UnaryIdentity struct {
	Op string        `json:"op"`
	X  *ExprIdentity `json:"x"`
}

// BinaryIdentity is one binary operation (notably string concatenation, a
// resource derivation the checker must see rather than flatten).
type BinaryIdentity struct {
	Op string        `json:"op"`
	X  *ExprIdentity `json:"x"`
	Y  *ExprIdentity `json:"y"`
}

// ExprIdentity is a structurally resolved expression. Equality is deep and
// structural; an Unknown leaf never equals anything, so an unresolved identity
// cannot be silently replaced by a convenient match.
type ExprIdentity struct {
	Kind     ExprKind          `json:"kind"`
	Value    *ValueIdentity    `json:"value,omitempty"`
	Literal  string            `json:"literal,omitempty"`
	Package  *APIIdentity      `json:"package,omitempty"`
	Selector *SelectorIdentity `json:"selector,omitempty"`
	Call     *CallIdentity     `json:"call,omitempty"`
	Index    *IndexIdentity    `json:"index,omitempty"`
	Unary    *UnaryIdentity    `json:"unary,omitempty"`
	Binary   *BinaryIdentity   `json:"binary,omitempty"`
	Unknown  string            `json:"unknown,omitempty"`
}

// Resolved reports whether the complete expression was traced to declared
// values, literals, package declarations and constructors.
func (e *ExprIdentity) Resolved() bool {
	if e == nil || e.Kind == ExprUnknown {
		return false
	}
	switch e.Kind {
	case ExprValue:
		return e.Value != nil && e.Value.Type != ""
	case ExprLiteral:
		return e.Literal != ""
	case ExprPackage:
		return e.Package != nil && e.Package.ImportPath != ""
	case ExprSelector:
		return e.Selector != nil && e.Selector.X != nil && e.Selector.X.Resolved() &&
			e.Selector.Owner != ""
	case ExprCall:
		if e.Call == nil || e.Call.Function.IsZero() {
			return false
		}
		for _, arg := range e.Call.Args {
			if !arg.Resolved() {
				return false
			}
		}
		return true
	case ExprIndex:
		return e.Index != nil && e.Index.X.Resolved() && e.Index.Index.Resolved()
	case ExprUnary:
		return e.Unary != nil && e.Unary.X.Resolved()
	case ExprBinary:
		return e.Binary != nil && e.Binary.X.Resolved() && e.Binary.Y.Resolved()
	}
	return false
}

// Missing states why an expression is unresolved.
func (e *ExprIdentity) Missing() string {
	if e == nil {
		return "the expression was not resolved"
	}
	if e.Kind == ExprUnknown {
		if e.Unknown != "" {
			return e.Unknown
		}
		return "the expression is unresolved"
	}
	mark := func(child *ExprIdentity) string {
		if child == nil {
			return "a component is missing"
		}
		return child.Missing()
	}
	switch e.Kind {
	case ExprValue:
		if e.Value == nil || e.Value.Type == "" {
			return "the declared type of the value is not established"
		}
	case ExprSelector:
		if e.Selector == nil {
			return "the field selection is missing"
		}
		if e.Selector.Owner == "" {
			return "the declared type the field is selected from is not established"
		}
		return mark(e.Selector.X)
	case ExprCall:
		if e.Call == nil {
			return "the call is missing"
		}
		for i, arg := range e.Call.Args {
			if !arg.Resolved() {
				return fmt.Sprintf("argument %d is unresolved: %s", i, mark(arg))
			}
		}
	case ExprIndex:
		if e.Index == nil {
			return "the index expression is missing"
		}
		if !e.Index.X.Resolved() {
			return mark(e.Index.X)
		}
		if !e.Index.Index.Resolved() {
			return "the index is not a resolved constant"
		}
	case ExprUnary:
		if e.Unary == nil {
			return "the unary expression is missing"
		}
		return mark(e.Unary.X)
	case ExprBinary:
		if e.Binary == nil {
			return "the binary expression is missing"
		}
		if !e.Binary.X.Resolved() {
			return mark(e.Binary.X)
		}
		if !e.Binary.Y.Resolved() {
			return mark(e.Binary.Y)
		}
	}
	return "the expression is unresolved"
}

// Equal compares two resolved expressions structurally.
func (e *ExprIdentity) Equal(o *ExprIdentity) bool {
	if e == nil || o == nil || e.Kind != o.Kind || e.Kind == ExprUnknown {
		return false
	}
	switch e.Kind {
	case ExprValue:
		return e.Value != nil && o.Value != nil && e.Value.Equal(*o.Value)
	case ExprLiteral:
		return e.Literal == o.Literal
	case ExprPackage:
		return e.Package != nil && o.Package != nil && e.Package.Equal(*o.Package)
	case ExprSelector:
		return e.Selector != nil && o.Selector != nil &&
			e.Selector.Name == o.Selector.Name &&
			e.Selector.Owner == o.Selector.Owner &&
			e.Selector.FieldType == o.Selector.FieldType &&
			e.Selector.X.Equal(o.Selector.X)
	case ExprCall:
		if e.Call == nil || o.Call == nil ||
			!e.Call.Function.Equal(o.Call.Function) ||
			len(e.Call.Args) != len(o.Call.Args) {
			return false
		}
		for i := range e.Call.Args {
			if !e.Call.Args[i].Equal(o.Call.Args[i]) {
				return false
			}
		}
		return true
	case ExprIndex:
		return e.Index != nil && o.Index != nil &&
			e.Index.X.Equal(o.Index.X) && e.Index.Index.Equal(o.Index.Index)
	case ExprUnary:
		return e.Unary != nil && o.Unary != nil &&
			e.Unary.Op == o.Unary.Op && e.Unary.X.Equal(o.Unary.X)
	case ExprBinary:
		return e.Binary != nil && o.Binary != nil &&
			e.Binary.Op == o.Binary.Op &&
			e.Binary.X.Equal(o.Binary.X) && e.Binary.Y.Equal(o.Binary.Y)
	}
	return false
}

// Witness is a checked source location that grounds an identity or an
// equation: the file, image, enclosing declaration, complete-file digest and
// the exact bytes the claim was read from. A rendered sentence is not a
// witness.
type Witness struct {
	Path        string `json:"path"`
	Image       Image  `json:"image"`
	Declaration string `json:"declaration,omitempty"`
	Digest      string `json:"digest"`
	StartLine   int    `json:"start_line"`
	StartCol    int    `json:"start_col"`
	EndLine     int    `json:"end_line"`
	EndCol      int    `json:"end_col"`
	Excerpt     string `json:"excerpt,omitempty"`
}

// ResolvedExpr is a resolved expression plus the local alias witnesses that
// led to it. Two expressions are equal only when both are resolved and their
// structures match; the witnesses document the alias chain but do not make an
// unresolved expression comparable.
type ResolvedExpr struct {
	Text      string        `json:"text"`
	Identity  *ExprIdentity `json:"identity"`
	Witnesses []Witness     `json:"witnesses,omitempty"`
}

// Resolved reports whether the complete expression is established.
func (r ResolvedExpr) Resolved() bool { return r.Identity.Resolved() }

// Missing states why the expression is unresolved.
func (r ResolvedExpr) Missing() string {
	if r.Identity == nil {
		return "the expression was not resolved"
	}
	return r.Identity.Missing()
}

// Equal compares two resolved expressions structurally.
func (r ResolvedExpr) Equal(o ResolvedExpr) bool {
	return r.Identity.Resolved() && o.Identity.Resolved() && r.Identity.Equal(o.Identity)
}

// ResourceIdentity is a resource operand with its enclosing declaration. The
// declaration is provenance; equality is the expression's, which already
// carries the source-owned declared type and the complete derivation chain.
type ResourceIdentity struct {
	Expr        ResolvedExpr        `json:"expr"`
	Declaration DeclarationIdentity `json:"declaration,omitempty"`
}

// Resolved reports whether the complete resource identity is established.
func (r ResourceIdentity) Resolved() bool { return r.Expr.Resolved() }

// Missing states why the resource identity is unresolved.
func (r ResourceIdentity) Missing() string { return r.Expr.Missing() }

// Equal compares two resource identities structurally.
func (r ResourceIdentity) Equal(o ResourceIdentity) bool { return r.Expr.Equal(o.Expr) }

// EquationRule names a supported rule for asserting that two resources are the
// same. Nothing outside this set may establish an equation.
type EquationRule string

const (
	// RuleIdenticalResolvedExpression: the two complete expression identities
	// are structurally equal and both are grounded in source witnesses.
	RuleIdenticalResolvedExpression EquationRule = "identical-resolved-expression"
	// RuleSameDeclarationValue: both sides are references to the same declared
	// value (same source, package, type, declaration and ordinal).
	RuleSameDeclarationValue EquationRule = "same-declaration-value"
	// RuleSameConstructorApplication: both sides are applications of the same
	// resolved constructor to structurally equal arguments.
	RuleSameConstructorApplication EquationRule = "same-constructor-application"
)

// ResourceEquation is a checked equality assertion between two resource
// identities. It records the rule and the witnesses the rule was checked
// against; Equal is the checker's result, never the claim of a rendered label.
type ResourceEquation struct {
	Rule      EquationRule     `json:"rule"`
	Left      ResourceIdentity `json:"left"`
	Right     ResourceIdentity `json:"right"`
	Witnesses []Witness        `json:"witnesses,omitempty"`
	Equal     bool             `json:"equal"`
	Reason    string           `json:"reason,omitempty"`
}

// CheckResourceEquation checks one supported equation rule. A rule that is not
// supported, an unresolved side, or an equation without a witness for both
// sides yields Equal=false with the reason stated.
func CheckResourceEquation(rule EquationRule, left, right ResourceIdentity, witnesses []Witness) ResourceEquation {
	eq := ResourceEquation{Rule: rule, Left: left, Right: right, Witnesses: witnesses}
	if !left.Resolved() {
		eq.Reason = "the left resource is unresolved: " + left.Missing()
		return eq
	}
	if !right.Resolved() {
		eq.Reason = "the right resource is unresolved: " + right.Missing()
		return eq
	}
	for _, side := range []struct {
		name string
		id   ResourceIdentity
	}{{"left", left}, {"right", right}} {
		if !sideWitnessed(side.id, witnesses) {
			eq.Reason = "the " + side.name + " resource has no source witness"
			return eq
		}
	}
	switch rule {
	case RuleIdenticalResolvedExpression:
		if !left.Equal(right) {
			eq.Reason = "the two resolved expressions are structurally different"
			return eq
		}
		eq.Equal = true
	case RuleSameDeclarationValue:
		lv, rv := left.Expr.Identity, right.Expr.Identity
		if lv == nil || rv == nil || lv.Kind != ExprValue || rv.Kind != ExprValue ||
			lv.Value == nil || rv.Value == nil {
			eq.Reason = "both sides are not references to declared values"
			return eq
		}
		if !lv.Value.Equal(*rv.Value) {
			eq.Reason = "the two references name different declarations"
			return eq
		}
		eq.Equal = true
	case RuleSameConstructorApplication:
		lc, rc := left.Expr.Identity, right.Expr.Identity
		if lc == nil || rc == nil || lc.Kind != ExprCall || rc.Kind != ExprCall ||
			lc.Call == nil || rc.Call == nil {
			eq.Reason = "both sides are not constructor applications"
			return eq
		}
		if !lc.Equal(rc) {
			eq.Reason = "the two constructor applications are structurally different"
			return eq
		}
		eq.Equal = true
	default:
		eq.Reason = fmt.Sprintf("the equation rule %q is not supported", rule)
	}
	return eq
}

// sideWitnessed reports whether the equation's own witness set grounds this
// side in source bytes. An expression's resolution provenance does not count:
// the equation must name the bytes it was checked against, so a caller cannot
// assert equality by passing two identities with no evidence.
func sideWitnessed(id ResourceIdentity, witnesses []Witness) bool {
	for _, w := range witnesses {
		if w.Path == "" || w.Digest == "" {
			continue
		}
		for _, own := range id.Expr.Witnesses {
			if own.Path == w.Path && own.Image == w.Image && own.Digest == w.Digest {
				return true
			}
		}
	}
	return false
}

const maxResolveDepth = 8

// resolveExpr resolves an expression against the patch-side source. It never
// consults a selected implementation and never guesses a declaration: a missing
// initializer, shadowed name, unavailable file or unsupported construct is an
// Unknown leaf with a stated reason.
func (a *analyzer) resolveExpr(v *fileView, expr ast.Expr, depth int) ResolvedExpr {
	a.ensurePackage(v)
	out := ResolvedExpr{Text: sourceText(v, expr)}
	if expr == nil {
		out.Identity = unknownExpr("the expression is missing")
		return out
	}
	if depth > maxResolveDepth {
		out.Identity = unknownExpr("the expression's derivation exceeds the supported depth")
		return out
	}
	switch x := expr.(type) {
	case *ast.ParenExpr:
		return a.resolveExpr(v, x.X, depth+1)
	case *ast.BasicLit:
		out.Identity = &ExprIdentity{Kind: ExprLiteral, Literal: canonicalLiteral(x)}
		return out
	case *ast.Ident:
		return a.resolveIdentValue(v, x, depth, out)
	case *ast.SelectorExpr:
		return a.resolveSelectorValue(v, x, depth, out)
	case *ast.CallExpr:
		return a.resolveCallValue(v, x, depth, out)
	case *ast.IndexExpr:
		index := a.resolveExpr(v, x.Index, depth+1)
		inner := a.resolveExpr(v, x.X, depth+1)
		out.Identity = &ExprIdentity{Kind: ExprIndex, Index: &IndexIdentity{X: inner.Identity, Index: index.Identity}}
		return out
	case *ast.UnaryExpr:
		inner := a.resolveExpr(v, x.X, depth+1)
		out.Identity = &ExprIdentity{Kind: ExprUnary, Unary: &UnaryIdentity{Op: x.Op.String(), X: inner.Identity}}
		return out
	case *ast.BinaryExpr:
		left := a.resolveExpr(v, x.X, depth+1)
		right := a.resolveExpr(v, x.Y, depth+1)
		out.Identity = &ExprIdentity{Kind: ExprBinary, Binary: &BinaryIdentity{Op: x.Op.String(), X: left.Identity, Y: right.Identity}}
		return out
	}
	out.Identity = unknownExpr(fmt.Sprintf("the expression form %T is not supported for resource identity", expr))
	return out
}

func (a *analyzer) resolveIdentValue(v *fileView, id *ast.Ident, depth int, out ResolvedExpr) ResolvedExpr {
	if id.Obj == nil {
		switch id.Name {
		case "nil", "true", "false", "iota":
			out.Identity = &ExprIdentity{Kind: ExprLiteral, Literal: "predeclared:" + id.Name}
			return out
		}
		if values := v.Pkg.Values[id.Name]; len(values) == 1 {
			vs := values[0]
			return a.resolvePackageValue(v, vs, id.Name, out, depth)
		}
		if v.DotImport {
			out.Identity = unknownExpr(fmt.Sprintf("the identifier %q may be supplied by a dot import", id.Name))
			return out
		}
		out.Identity = unknownExpr(fmt.Sprintf("the identifier %q is not declared in the provided patch-side source", id.Name))
		return out
	}
	decl, ok := v.Values[id.Obj]
	if !ok {
		out.Identity = unknownExpr(fmt.Sprintf("the declaration of %q is not a value", id.Name))
		return out
	}
	if v.Mutated[id.Obj] {
		out.Identity = unknownExpr(fmt.Sprintf("the value %q is reassigned after its declaration, so its identity at this use is not established", id.Name))
		return out
	}
	if decl.Init != nil {
		// An ordinary alias or derivation: resolve what the name was declared
		// from and record the local binding as a witness, so `p := cfg.Root`
		// carries the same resource identity as `cfg.Root` plus its alias
		// provenance.
		resolved := a.resolveExpr(v, decl.Init, depth+1)
		if resolved.Identity != nil && resolved.Identity.Kind != ExprUnknown {
			resolved.Text = out.Text
			resolved.Witnesses = append(resolved.Witnesses, v.witnessAt(decl.Pos, decl.Line, decl.Col))
		}
		return resolved
	}
	typ := v.canonicalType(decl.Type)
	if typ == "" {
		out.Identity = unknownExpr(fmt.Sprintf("the declared type of %q is not established", id.Name))
		return out
	}
	out.Identity = &ExprIdentity{Kind: ExprValue, Value: &ValueIdentity{
		Source:      v.packageSource(),
		PackagePath: v.PackagePath,
		Type:        typ,
		Decl:        decl.Decl,
		Origin:      decl.Origin,
		Ordinal:     decl.Ordinal,
		Name:        decl.Name,
	}}
	out.Witnesses = append(out.Witnesses, v.witnessAt(decl.Pos, decl.Line, decl.Col))
	return out
}

// resolvePackageValue resolves a package-level value declared in another file
// of the same package. Its initializer, when a single value is assigned, is
// followed exactly like a local alias.
func (a *analyzer) resolvePackageValue(v *fileView, vs *ast.ValueSpec, name string,
	out ResolvedExpr, depth int) ResolvedExpr {
	idx := -1
	for i, n := range vs.Names {
		if n.Name == name {
			idx = i
			break
		}
	}
	if idx < 0 {
		out.Identity = unknownExpr(fmt.Sprintf("the package-level value %q has no declaration index", name))
		return out
	}
	if len(vs.Values) == len(vs.Names) && vs.Values[idx] != nil {
		resolved := a.resolveExpr(v, vs.Values[idx], depth+1)
		src := v.Fset.Position(vs.Names[idx].Pos())
		if resolved.Identity != nil && resolved.Identity.Kind != ExprUnknown {
			resolved.Text = out.Text
			resolved.Witnesses = append(resolved.Witnesses, v.witnessAt(vs.Names[idx].Pos(), src.Line, src.Column))
		}
		return resolved
	}
	typ := v.canonicalType(vs.Type)
	if typ == "" {
		out.Identity = unknownExpr(fmt.Sprintf("the declared type of the package-level value %q is not established", name))
		return out
	}
	pos := v.Fset.Position(vs.Names[idx].Pos())
	out.Identity = &ExprIdentity{Kind: ExprValue, Value: &ValueIdentity{
		Source:      v.packageSource(),
		PackagePath: v.PackagePath,
		Type:        typ,
		Decl:        v.Path + "#global." + name,
		Origin:      "global",
	}}
	out.Witnesses = append(out.Witnesses, v.witnessAt(vs.Names[idx].Pos(), pos.Line, pos.Column))
	return out
}

func (a *analyzer) resolveSelectorValue(v *fileView, sel *ast.SelectorExpr, depth int,
	out ResolvedExpr) ResolvedExpr {
	// A package-qualified declaration (`pkg.Name`) is resolved by its import
	// path and declared name; it is not a field selection on a value.
	if base, ok := sel.X.(*ast.Ident); ok && base.Obj == nil && isImportName(v, base.Name) {
		if p, known := v.Imports[base.Name]; known {
			id := APIIdentity{Source: a.sourceForImport(p), ImportPath: p, Name: sel.Sel.Name}
			if spec, ok := specFor(id); ok {
				id.Signature = spec.Signature
			}
			out.Identity = &ExprIdentity{Kind: ExprSelector, Selector: &SelectorIdentity{
				X:     &ExprIdentity{Kind: ExprPackage, Package: &id},
				Name:  sel.Sel.Name,
				Owner: "package:" + p,
			}}
			return out
		}
	}
	base := a.resolveExpr(v, sel.X, depth+1)
	owner := exprDeclaredType(base.Identity)
	if owner == "" {
		out.Identity = unknownExpr(fmt.Sprintf("the declared type of the value %q is not established", sel.Sel.Name))
		return out
	}
	out.Identity = &ExprIdentity{Kind: ExprSelector, Selector: &SelectorIdentity{
		X:         base.Identity,
		Name:      sel.Sel.Name,
		Owner:     owner,
		FieldType: v.fieldType(owner, sel.Sel.Name),
	}}
	out.Witnesses = append(out.Witnesses, base.Witnesses...)
	return out
}

func (a *analyzer) resolveCallValue(v *fileView, call *ast.CallExpr, depth int, out ResolvedExpr) ResolvedExpr {
	res := a.resolveCall(v, call)
	if !res.Resolved {
		out.Identity = unknownExpr("the callee is unresolved: " + res.Reason)
		return out
	}
	if res.Identity.Source == "builtin" && res.Identity.Name == "new" && len(call.Args) == 1 {
		out.Identity = &ExprIdentity{Kind: ExprCall, Call: &CallIdentity{
			Function: res.Identity,
			Args:     []*ExprIdentity{{Kind: ExprLiteral, Literal: "type:" + v.canonicalType(call.Args[0])}},
		}}
		return out
	}
	args := make([]*ExprIdentity, 0, len(call.Args))
	for _, arg := range call.Args {
		resolved := a.resolveExpr(v, arg, depth+1)
		args = append(args, resolved.Identity)
		out.Witnesses = append(out.Witnesses, resolved.Witnesses...)
	}
	out.Identity = &ExprIdentity{Kind: ExprCall, Call: &CallIdentity{Function: res.Identity, Args: args}}
	return out
}

// exprDeclaredType returns the package-qualified declared type of a resolved
// expression, when the expression's own resolution established one.
func exprDeclaredType(e *ExprIdentity) string {
	if e == nil || !e.Resolved() {
		return ""
	}
	switch e.Kind {
	case ExprValue:
		if e.Value != nil {
			return e.Value.Type
		}
	case ExprSelector:
		if e.Selector != nil {
			return e.Selector.FieldType
		}
	case ExprUnary:
		if e.Unary != nil && e.Unary.Op == "&" {
			inner := exprDeclaredType(e.Unary.X)
			if inner != "" {
				return "*" + inner
			}
		}
	}
	return ""
}

// fieldType returns the declared type of a struct field when the struct is
// declared in the provided patch-side source. The owner type is
// package-qualified; its base name locates the local declaration.
func (v *fileView) fieldType(owner, field string) string {
	name := baseTypeName(owner)
	if name == "" || v.Pkg == nil {
		return ""
	}
	spec, ok := v.Pkg.Types[name]
	if !ok {
		return ""
	}
	st, ok := spec.Type.(*ast.StructType)
	if !ok {
		return ""
	}
	for _, f := range st.Fields.List {
		for _, n := range f.Names {
			if n.Name == field {
				return v.canonicalType(f.Type)
			}
		}
	}
	return ""
}

func baseTypeName(qualified string) string {
	t := strings.TrimSpace(qualified)
	t = strings.TrimLeft(t, "*[]")
	if i := strings.LastIndexByte(t, '.'); i >= 0 {
		t = t[i+1:]
	}
	if !isIdentifierString(t) {
		return ""
	}
	return t
}

func canonicalLiteral(lit *ast.BasicLit) string {
	switch lit.Kind {
	case token.STRING:
		if s, err := strconv.Unquote(lit.Value); err == nil {
			return "string:" + s
		}
		return "string-raw:" + lit.Value
	case token.INT:
		if n, err := parseIntLiteral(strings.ReplaceAll(lit.Value, "_", "")); err == nil {
			return fmt.Sprintf("int:%d", n)
		}
		return "int-raw:" + lit.Value
	case token.CHAR:
		if s, err := strconv.Unquote(lit.Value); err == nil {
			return "char:" + s
		}
		return "char-raw:" + lit.Value
	case token.FLOAT:
		return "float:" + lit.Value
	}
	return "literal:" + lit.Value
}

func parseIntLiteral(text string) (uint64, error) {
	return strconv.ParseUint(text, 0, 64)
}

func unknownExpr(reason string) *ExprIdentity {
	return &ExprIdentity{Kind: ExprUnknown, Unknown: reason}
}

// witnessAt builds a witness for a declaration or expression position.
func (v *fileView) witnessAt(pos token.Pos, line, col int) Witness {
	return Witness{
		Path:        v.Path,
		Image:       v.Image,
		Declaration: v.enclosingDeclaration(pos).String(),
		Digest:      v.Digest,
		StartLine:   line,
		StartCol:    col,
		EndLine:     line,
		EndCol:      col,
		Excerpt:     v.excerpt(line, line),
	}
}

// witness builds a witness for a source span.
func (v *fileView) witness(start, end token.Pos, declaration string) Witness {
	st := v.Fset.Position(start)
	en := v.Fset.Position(end)
	if declaration == "" {
		declaration = v.enclosingDeclaration(start).String()
	}
	return Witness{
		Path:        v.Path,
		Image:       v.Image,
		Declaration: declaration,
		Digest:      v.Digest,
		StartLine:   st.Line,
		StartCol:    st.Column,
		EndLine:     en.Line,
		EndCol:      en.Column,
		Excerpt:     v.excerpt(st.Line, en.Line),
	}
}

func (v *fileView) excerpt(startLine, endLine int) string {
	if startLine < 1 || endLine < startLine || startLine > len(v.Lines) {
		return ""
	}
	if endLine > len(v.Lines) {
		endLine = len(v.Lines)
	}
	text := strings.Join(v.Lines[startLine-1:endLine], "\n")
	return truncate(text, 400)
}

// enclosingDeclaration is the innermost function/method declaration containing
// pos, computed from the declared signature rather than the hunk header.
func (v *fileView) enclosingDeclaration(pos token.Pos) DeclarationIdentity {
	var best *ast.FuncDecl
	for _, decl := range v.File.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fd.Pos() <= pos && pos < fd.End() {
			if best == nil || fd.Pos() >= best.Pos() {
				best = fd
			}
		}
	}
	if best != nil {
		return v.declaration(best)
	}
	return DeclarationIdentity{Path: v.Path, Name: "(package)", Digest: v.Digest}
}

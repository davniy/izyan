package fixbinding

import "strings"

// This file defines the correspondence identity used to relate one captured fix
// effect to the selected implementation's own operations.
//
// A resource key (Task 4/5) names *one instance* of a value: the module that
// owns it, the declaration it came from and its ordinal. That is the right
// identity inside one source tree, but it cannot relate two trees: the fix
// patch is written against another release line (or another module entirely
// under a replacement), so its module coordinate and often its declaration
// differ while the resource is the same configuration field.
//
// CorrespondenceKey therefore abstracts exactly two things — the owning module
// coordinate and the instance declaration — and keeps everything that makes two
// resources different:
//
//   - the package-qualified declared type of the base value (ownership);
//   - every selector step with its package-qualified owner type;
//   - every call, index, unary and binary operator in the derivation chain.
//
// It is deliberately over-inclusive: an extra candidate joins the cover (sound,
// because the cover must falsify it too), while a dropped candidate would let an
// alternative implementation escape. It never equates two operands by rendered
// text: the derivation is compared structurally.

// CorrespondenceKey is the source-independent identity of one resource
// derivation. It returns false when any part of the derivation is unresolved:
// an unresolved resource corresponds to nothing, so its effect stays an
// obligation instead of matching a convenient location.
func CorrespondenceKey(e *ExprIdentity) (string, bool) {
	if e == nil || !e.Resolved() {
		return "", false
	}
	switch e.Kind {
	case ExprValue:
		if e.Value == nil || strings.TrimSpace(e.Value.Type) == "" {
			return "", false
		}
		// The declared type carries the owning package, so two Config types in
		// different packages stay distinct. The module coordinate and the
		// instance declaration are deliberately dropped.
		return "type:" + e.Value.Type, true
	case ExprLiteral:
		return "literal:" + e.Literal, true
	case ExprPackage:
		if e.Package == nil || e.Package.ImportPath == "" {
			return "", false
		}
		return "package:" + e.Package.ImportPath, true
	case ExprSelector:
		if e.Selector == nil || e.Selector.Owner == "" || e.Selector.Name == "" {
			return "", false
		}
		base, ok := CorrespondenceKey(e.Selector.X)
		if !ok {
			return "", false
		}
		return base + "." + e.Selector.Owner + "#" + e.Selector.Name, true
	case ExprCall:
		if e.Call == nil || e.Call.Function.IsZero() {
			return "", false
		}
		args := make([]string, 0, len(e.Call.Args))
		for _, arg := range e.Call.Args {
			key, ok := CorrespondenceKey(arg)
			if !ok {
				return "", false
			}
			args = append(args, key)
		}
		return "call:" + callDeclarationKey(e.Call.Function) + "(" + strings.Join(args, ",") + ")", true
	case ExprIndex:
		if e.Index == nil {
			return "", false
		}
		base, ok := CorrespondenceKey(e.Index.X)
		if !ok {
			return "", false
		}
		index, ok := CorrespondenceKey(e.Index.Index)
		if !ok {
			return "", false
		}
		return "index:" + base + "[" + index + "]", true
	case ExprUnary:
		if e.Unary == nil {
			return "", false
		}
		base, ok := CorrespondenceKey(e.Unary.X)
		if !ok {
			return "", false
		}
		return "unary:" + e.Unary.Op + base, true
	case ExprBinary:
		if e.Binary == nil {
			return "", false
		}
		left, ok := CorrespondenceKey(e.Binary.X)
		if !ok {
			return "", false
		}
		right, ok := CorrespondenceKey(e.Binary.Y)
		if !ok {
			return "", false
		}
		return "binary:" + left + e.Binary.Op + right, true
	}
	return "", false
}

// callDeclarationKey renders one callee identity without its module coordinate.
// An import-qualified or standard-library declaration is already stable across
// release lines; a repository-local function keeps its import path and receiver,
// which are also stable under an ordinary version change.
func callDeclarationKey(id APIIdentity) string {
	switch {
	case id.Source == "builtin":
		return "builtin:" + id.Name
	case strings.HasPrefix(id.Source, "stdlib"):
		return "stdlib:" + id.ImportPath + "." + id.Name
	case strings.HasPrefix(id.Source, "import:"):
		return id.ImportPath + "." + id.Name
	}
	// A repository-local declaration: its import path and receiver survive a
	// version change even though its owning module coordinate does not.
	return "local:" + id.ImportPath + "." + id.Receiver + "." + id.Name
}

// OperationCorrespondenceKey is the key of an operation's checked resource.
func OperationCorrespondenceKey(op *Operation) (string, bool) {
	if op == nil {
		return "", false
	}
	return CorrespondenceKey(op.Resource.Expr.Identity)
}

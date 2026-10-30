package fixbinding

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/token"
	"sort"
	"strings"
)

// APIIdentity is the resolved declaration an operation call invokes. A name is
// not an identity: the owning source, import path, receiver declaration and
// declared signature all participate, so an aliased import of os.MkdirAll
// normalises to the same API while an unrelated package's MkdirAll, a shadowed
// os, or a same-named method does not.
type APIIdentity struct {
	Source     string `json:"source"`
	ImportPath string `json:"import_path"`
	Receiver   string `json:"receiver,omitempty"`
	Name       string `json:"name"`
	Signature  string `json:"signature,omitempty"`
}

// Equal reports whether two identities are the same resolved declaration.
func (a APIIdentity) Equal(b APIIdentity) bool {
	return a.Source == b.Source &&
		a.ImportPath == b.ImportPath &&
		a.Receiver == b.Receiver &&
		a.Name == b.Name &&
		a.Signature == b.Signature
}

func (a APIIdentity) IsZero() bool { return a.Name == "" && a.ImportPath == "" }

func (a APIIdentity) String() string {
	name := a.Name
	if a.Receiver != "" {
		name = a.Receiver + "." + a.Name
	}
	at := a.ImportPath
	if at == "" {
		at = a.Source
	}
	if a.Signature != "" {
		return fmt.Sprintf("%s %s%s", at, name, strings.TrimPrefix(a.Signature, "func"))
	}
	return at + " " + name
}

// OperationClass is the security-relevant operation a supported declaration
// performs.
type OperationClass string

const (
	ClassDirCreate   OperationClass = "DIR_CREATE"
	ClassFileCreate  OperationClass = "FILE_CREATE"
	ClassModeChange  OperationClass = "MODE_CHANGE"
	ClassOwnerChange OperationClass = "OWNER_CHANGE"
)

// ArgRole says what a supported operation's argument carries. Only a resource
// operand and a literal permission argument are checked; every other argument
// is context and changing it stays a residual.
type ArgRole string

const (
	ArgResource ArgRole = "resource"
	ArgMode     ArgRole = "mode"
	ArgFlags    ArgRole = "flags"
	ArgData     ArgRole = "data"
	ArgOwner    ArgRole = "owner"
)

// operationSpec is one declaration the classifier supports. The table is the
// supported vocabulary, not a name lookup: membership requires the resolved
// import path, receiver and function name, and the signature is the declaration
// this build supports. An unknown declaration is never guessed into a class.
type operationSpec struct {
	ImportPath string
	Receiver   string
	Name       string
	Signature  string
	Class      OperationClass
	Args       map[int]ArgRole
}

var supportedOperations = []operationSpec{
	{
		ImportPath: "os", Name: "Mkdir",
		Signature: "func(name string, perm os.FileMode) error",
		Class:     ClassDirCreate, Args: map[int]ArgRole{0: ArgResource, 1: ArgMode},
	},
	{
		ImportPath: "os", Name: "MkdirAll",
		Signature: "func(path string, perm os.FileMode) error",
		Class:     ClassDirCreate, Args: map[int]ArgRole{0: ArgResource, 1: ArgMode},
	},
	{
		ImportPath: "os", Name: "OpenFile",
		Signature: "func(name string, flag int, perm os.FileMode) (*os.File, error)",
		Class:     ClassFileCreate, Args: map[int]ArgRole{0: ArgResource, 1: ArgFlags, 2: ArgMode},
	},
	{
		ImportPath: "os", Name: "WriteFile",
		Signature: "func(name string, data []byte, perm os.FileMode) error",
		Class:     ClassFileCreate, Args: map[int]ArgRole{0: ArgResource, 1: ArgData, 2: ArgMode},
	},
	{
		ImportPath: "os", Name: "Chmod",
		Signature: "func(name string, mode os.FileMode) error",
		Class:     ClassModeChange, Args: map[int]ArgRole{0: ArgResource, 1: ArgMode},
	},
	{
		ImportPath: "golang.org/x/sys/unix", Name: "Mkdir",
		Signature: "func(path string, mode uint32) error",
		Class:     ClassDirCreate, Args: map[int]ArgRole{0: ArgResource, 1: ArgMode},
	},
	{
		ImportPath: "golang.org/x/sys/unix", Name: "Chmod",
		Signature: "func(path string, mode uint32) error",
		Class:     ClassModeChange, Args: map[int]ArgRole{0: ArgResource, 1: ArgMode},
	},
	{
		ImportPath: "golang.org/x/sys/unix", Name: "Open",
		Signature: "func(path string, mode int, perm uint32) (fd int, err error)",
		Class:     ClassFileCreate, Args: map[int]ArgRole{0: ArgResource, 1: ArgFlags, 2: ArgMode},
	},
}

func specFor(id APIIdentity) (operationSpec, bool) {
	for _, spec := range supportedOperations {
		if spec.ImportPath == id.ImportPath && spec.Receiver == id.Receiver && spec.Name == id.Name {
			return spec, true
		}
	}
	return operationSpec{}, false
}

// supportedOperationVocabulary renders the declarations this build classifies,
// sorted and de-duplicated, so a refusal can name the vocabulary it measured
// instead of asserting a generic "unsupported".
func supportedOperationVocabulary() []string {
	var names []string
	for _, spec := range supportedOperations {
		names = appendUniqueString(names, spec.ImportPath+"."+spec.Receiver+spec.Name)
	}
	sort.Strings(names)
	return names
}

// WrapperSummary is a checked body summary of a repository-local operation.
// A local wrapper's name establishes nothing; the summary states which
// supported declaration its body forwards to and how it propagates its
// parameters. The summary is evidence, and the package re-checks that its
// BodyDigest is the digest of the complete declaration body in the supplied
// patch-side source before using it.
type WrapperSummary struct {
	Function   APIIdentity      `json:"function"`
	BodyDigest string           `json:"body_digest"`
	Forwards   []WrapperForward `json:"forwards"`
}

// WrapperForward maps one supported operation the wrapper body invokes onto the
// wrapper's parameters. ResourceParam and ModeParam are 0-based parameter
// indexes; a value below zero means the wrapper supplies that argument itself
// (ModeLiteral) or does not carry it.
type WrapperForward struct {
	Target        APIIdentity    `json:"target"`
	Class         OperationClass `json:"class"`
	ResourceParam int            `json:"resource_param"`
	ModeParam     int            `json:"mode_param"`
	ModeLiteral   string         `json:"mode_literal,omitempty"`
}

// callResolution is the outcome of resolving a call's callee. An unresolved
// outcome is a fact to report, never a reason to fall back to a name.
type callResolution struct {
	Identity APIIdentity
	Local    bool
	Resolved bool
	Reason   string
	Func     *ast.FuncDecl
}

// resolveCall resolves the declaration a call invokes using the parsed
// patch-side file: imports (including aliases and shadowing), package-level
// declarations provided for the same package, and method declarations of
// locally declared receiver types.
func (a *analyzer) resolveCall(v *fileView, call *ast.CallExpr) callResolution {
	a.ensurePackage(v)
	fun := unwrapGeneric(call.Fun)
	switch x := fun.(type) {
	case *ast.Ident:
		return a.resolveIdentCallee(v, x)
	case *ast.SelectorExpr:
		return a.resolveSelectorCallee(v, x)
	}
	return callResolution{Reason: "the callee is not a resolved identifier or package selector"}
}

func unwrapGeneric(expr ast.Expr) ast.Expr {
	for {
		switch x := expr.(type) {
		case *ast.ParenExpr:
			expr = x.X
		case *ast.IndexExpr:
			expr = x.X
		case *ast.IndexListExpr:
			expr = x.X
		default:
			return expr
		}
	}
}

func (a *analyzer) resolveIdentCallee(v *fileView, id *ast.Ident) callResolution {
	if id.Obj != nil {
		switch id.Obj.Kind {
		case ast.Fun:
			if d, ok := id.Obj.Decl.(*ast.FuncDecl); ok {
				return callResolution{
					Identity: v.localFunctionIdentity(d),
					Local:    true,
					Resolved: true,
					Func:     d,
				}
			}
			return callResolution{Reason: "the function identifier has no resolvable declaration"}
		case ast.Typ:
			return callResolution{Reason: "the call is a type conversion, not an operation"}
		case ast.Var, ast.Con:
			return callResolution{Reason: "the call invokes a value, not a declared function"}
		}
	}
	if isBuiltinName(id.Name) {
		return callResolution{
			Identity: APIIdentity{Source: "builtin", Name: id.Name},
			Resolved: true,
		}
	}
	if isImportName(v, id.Name) {
		return callResolution{Reason: "the call invokes an imported package name, not a function"}
	}
	// A package-level function declared in another file of the same package is
	// not linked by the parser; the provided package source can still resolve
	// it exactly once.
	if d := v.Pkg.function(id.Name); d != nil {
		return callResolution{
			Identity: v.localFunctionIdentity(d),
			Local:    true,
			Resolved: true,
			Func:     d,
		}
	}
	if v.DotImport {
		return callResolution{Reason: "the identifier may be supplied by a dot import, so its declaration is not established"}
	}
	return callResolution{Reason: "the callee is not declared in the provided patch-side source"}
}

func (a *analyzer) resolveSelectorCallee(v *fileView, sel *ast.SelectorExpr) callResolution {
	base, ok := sel.X.(*ast.Ident)
	if !ok {
		return callResolution{Reason: "the selector's base is not a simple identifier, so its declaration is not established"}
	}
	if base.Obj == nil {
		if isImportName(v, base.Name) {
			p, known := v.Imports[base.Name]
			if !known {
				return callResolution{Reason: fmt.Sprintf("the package name %q cannot be derived from its import path", base.Name)}
			}
			id := APIIdentity{
				Source:     a.sourceForImport(p),
				ImportPath: p,
				Name:       sel.Sel.Name,
			}
			if spec, ok := specFor(id); ok {
				id.Signature = spec.Signature
			}
			return callResolution{Identity: id, Resolved: true}
		}
		// A package-level value declared in another file of this package can
		// still be resolved from the provided package source.
		if vs := v.Pkg.Values[base.Name]; len(vs) == 1 && vs[0].Type != nil {
			return a.resolveMethodOnType(v, receiverTypeName(vs[0].Type), sel.Sel.Name)
		}
		if v.DotImport {
			return callResolution{Reason: "the selector base may be supplied by a dot import, so its declaration is not established"}
		}
		return callResolution{Reason: fmt.Sprintf("the selector base %q is not a known import or declaration", base.Name)}
	}
	if base.Obj.Kind == ast.Typ {
		if id, ok := base.Obj.Decl.(*ast.TypeSpec); ok {
			return a.resolveMethodOnType(v, id.Name.Name, sel.Sel.Name)
		}
		return callResolution{Reason: "the selector's type receiver has no resolvable declaration"}
	}
	decl, ok := v.Values[base.Obj]
	if !ok {
		return callResolution{Reason: "the selector base is a value whose declaration is not provided"}
	}
	recv := receiverTypeFromValue(v, decl)
	if recv == "" {
		return callResolution{Reason: "the selector base's declared type cannot be established"}
	}
	return a.resolveMethodOnType(v, recv, sel.Sel.Name)
}

func (a *analyzer) resolveMethodOnType(v *fileView, recvType, name string) callResolution {
	if recvType == "" {
		return callResolution{Reason: "the receiver type is not established"}
	}
	d := v.Pkg.method(recvType, name)
	if d == nil {
		return callResolution{Reason: fmt.Sprintf("method %s.%s is not declared in the provided package source", recvType, name)}
	}
	return callResolution{
		Identity: APIIdentity{
			Source:     a.sourceRef(),
			ImportPath: v.PackagePath,
			Receiver:   v.PackagePath + "." + recvType,
			Name:       name,
			Signature:  v.signature(d.Type),
		},
		Local:    true,
		Resolved: true,
		Func:     d,
	}
}

func (v *fileView) localFunctionIdentity(d *ast.FuncDecl) APIIdentity {
	return APIIdentity{
		Source:     v.packageSource(),
		ImportPath: v.PackagePath,
		Name:       d.Name.Name,
		Signature:  v.signature(d.Type),
	}
}

func (v *fileView) packageSource() string {
	if v.Pkg != nil && v.Pkg.Source != "" {
		return v.Pkg.Source
	}
	return "module:unknown"
}

// ensurePackage attaches the package-scope declaration view to a file view on
// first use. It is idempotent and never consults the other image.
func (a *analyzer) ensurePackage(v *fileView) {
	if v.Pkg == nil {
		a.packageFor(v)
	}
}

func receiverTypeFromValue(v *fileView, decl valueDecl) string {
	if decl.Type != nil {
		return receiverTypeName(decl.Type)
	}
	switch init := unwrapParen(decl.Init).(type) {
	case *ast.UnaryExpr:
		if init.Op == token.AND {
			return receiverTypeName(init.X)
		}
	case *ast.CompositeLit:
		return receiverTypeName(init.Type)
	case *ast.CallExpr:
		if id, ok := unwrapGeneric(init.Fun).(*ast.Ident); ok && id.Name == "new" && len(init.Args) == 1 {
			return receiverTypeName(init.Args[0])
		}
	}
	return ""
}

// sourceForImport is the owning source of an imported package. A caller that
// recorded an effective owner (a replaced or vendored module) supplies it in
// ImportOwners; otherwise the import path's own source kind is used and an
// unknown external module keeps its import path as the qualifier.
func (a *analyzer) sourceForImport(importPath string) string {
	if a.bundle != nil {
		if owner := strings.TrimSpace(a.bundle.ImportOwners[importPath]); owner != "" {
			return owner
		}
	}
	if isStdlibImportPath(importPath) {
		if tc := a.toolchain(); tc != "" {
			return "stdlib@" + tc
		}
		return "stdlib"
	}
	if a.bundle != nil && a.bundle.Module.Path != "" {
		mp := strings.TrimSpace(a.bundle.Module.Path)
		if importPath == mp || strings.HasPrefix(importPath, mp+"/") {
			return a.bundle.Module.SourceRef()
		}
	}
	return "import:" + importPath
}

func isStdlibImportPath(p string) bool {
	if p == "" || p == "C" {
		return false
	}
	first := p
	if i := strings.IndexByte(p, '/'); i >= 0 {
		first = p[:i]
	}
	return !strings.Contains(first, ".")
}

func isImportName(v *fileView, name string) bool {
	if _, ok := v.Imports[name]; ok {
		return true
	}
	known, present := v.ImportNames[name]
	return present && !known
}

func isBuiltinName(name string) bool {
	switch name {
	case "append", "cap", "clear", "close", "complex", "copy", "delete", "imag",
		"len", "make", "max", "min", "new", "panic", "print", "println", "real", "recover":
		return true
	}
	return false
}

// Operation is one recognised security operation call site with its resolved
// declaration, checked resource and normalised permission value.
type Operation struct {
	Identity APIIdentity      `json:"identity"`
	Class    OperationClass   `json:"class"`
	Resource ResourceIdentity `json:"resource"`
	Mode     string           `json:"mode,omitempty"`
	Flags    string           `json:"flags,omitempty"`
	Line     int              `json:"line"`
	Col      int              `json:"col"`
	Witness  Witness          `json:"witness"`
}

// classifyOperation resolves a call into a supported operation. A call that
// resolves to no supported declaration, or whose checked resource or
// permission argument is not established, returns a reason and no operation:
// the changed span stays an obligation instead of being consumed by a guess.
func (a *analyzer) classifyOperation(v *fileView, call *ast.CallExpr) (Operation, string) {
	op, _, reason := a.classifyOperationArgs(v, call)
	return op, reason
}

// classifyOperationArgs is classifyOperation plus the call-argument index that
// carries the resource operand. A census expands a may-set of aliases for that
// argument, so the index is measured once here instead of being re-derived.
func (a *analyzer) classifyOperationArgs(v *fileView, call *ast.CallExpr) (Operation, int, string) {
	res := a.resolveCall(v, call)
	if !res.Resolved {
		return Operation{}, -1, res.Reason
	}
	if res.Identity.Source == "builtin" {
		return Operation{}, -1, "the call invokes a builtin, not a supported security operation"
	}
	if res.Local {
		return a.classifyWrapper(v, call, res)
	}
	spec, ok := specFor(res.Identity)
	if !ok {
		return Operation{}, -1, fmt.Sprintf("the resolved declaration %s is not in the supported operation set", res.Identity)
	}
	if spec.Signature != "" && res.Identity.Signature != spec.Signature {
		// A table-supported import path and name whose supplied declaration has
		// another signature is a different declaration, not a spelling variant.
		return Operation{}, -1, fmt.Sprintf("the resolved declaration %s does not have the supported signature", res.Identity)
	}
	op, reason := a.operationFromCall(v, call, res.Identity, spec)
	if reason != "" {
		return Operation{}, -1, reason
	}
	return op, resourceArgIndex(spec), ""
}

// resourceArgIndex returns the argument index the supported declaration's
// resource operand occupies.
func resourceArgIndex(spec operationSpec) int {
	for idx, role := range spec.Args {
		if role == ArgResource {
			return idx
		}
	}
	return -1
}

func (a *analyzer) operationFromCall(v *fileView, call *ast.CallExpr, id APIIdentity,
	spec operationSpec) (Operation, string) {
	op := Operation{
		Identity: id,
		Class:    spec.Class,
		Line:     v.Fset.Position(call.Pos()).Line,
		Col:      v.Fset.Position(call.Pos()).Column,
		Witness:  v.witness(call.Pos(), call.End(), ""),
	}
	var resourceSeen bool
	var modeSeen bool
	for idx, role := range spec.Args {
		if idx >= len(call.Args) {
			return Operation{}, fmt.Sprintf("the %s call has %d arguments but the supported declaration needs argument %d",
				spec.Name, len(call.Args), idx)
		}
		switch role {
		case ArgResource:
			resource := a.resolveOperand(v, call.Args[idx])
			op.Resource = ResourceIdentity{Expr: resource, Declaration: v.enclosingDeclaration(call.Pos())}
			resourceSeen = true
		case ArgMode:
			mode, ok := modeLiteral(call.Args[idx])
			if !ok {
				return Operation{}, fmt.Sprintf("the permission argument of %s is not an integer literal, so its value is not established", spec.Name)
			}
			op.Mode = mode
			modeSeen = true
		case ArgFlags:
			op.Flags = sourceText(v, call.Args[idx])
		}
	}
	if !resourceSeen {
		return Operation{}, "the supported declaration has no checked resource argument"
	}
	if !modeSeen {
		return Operation{}, "the supported declaration has no checked permission argument"
	}
	if !op.Resource.Resolved() {
		return Operation{}, "the operation's resource identity is not established: " + op.Resource.Missing()
	}
	return op, ""
}

func (a *analyzer) resolveOperand(v *fileView, expr ast.Expr) ResolvedExpr {
	if a.operandResolver != nil {
		return a.operandResolver(v, expr)
	}
	return a.resolveExpr(v, expr, 0)
}

// classifyWrapper resolves a call to a repository-local wrapper through its
// checked body summary. The summary must be bound to the exact body bytes and
// forward to a declaration the supported set also recognises.
func (a *analyzer) classifyWrapper(v *fileView, call *ast.CallExpr, res callResolution) (Operation, int, string) {
	if res.Func == nil {
		return Operation{}, -1, "the local callee's declaration is not provided"
	}
	if a.bundle == nil || len(a.bundle.Wrappers) == 0 {
		return Operation{}, -1, fmt.Sprintf("the repository-local call %s has no checked body summary", res.Identity)
	}
	var summary *WrapperSummary
	for i := range a.bundle.Wrappers {
		if a.bundle.Wrappers[i].Function.Equal(res.Identity) {
			if summary != nil {
				return Operation{}, -1, fmt.Sprintf("the repository-local call %s has more than one competing body summary", res.Identity)
			}
			summary = &a.bundle.Wrappers[i]
		}
	}
	if summary == nil {
		return Operation{}, -1, fmt.Sprintf("the repository-local call %s has no checked body summary", res.Identity)
	}
	owner := a.owningView(v, res.Func)
	digest, ok := bodyDigest(owner, res.Func)
	if !ok {
		return Operation{}, -1, "the wrapper's body bytes are not available in the supplied source"
	}
	if summary.BodyDigest == "" || summary.BodyDigest != digest {
		return Operation{}, -1, "the wrapper summary is not bound to the supplied body bytes"
	}
	if len(summary.Forwards) != 1 {
		return Operation{}, -1, fmt.Sprintf("the wrapper summary has %d forwards, so the operation it performs is not established", len(summary.Forwards))
	}
	forward := summary.Forwards[0]
	spec, ok := specFor(forward.Target)
	if !ok {
		return Operation{}, -1, fmt.Sprintf("the wrapper forwards to %s, which is not a supported declaration", forward.Target)
	}
	if forward.Target.Signature != "" && forward.Target.Signature != spec.Signature {
		return Operation{}, -1, fmt.Sprintf("the wrapper forwards to a declaration with signature %q, not the supported signature", forward.Target.Signature)
	}
	if forward.Class != "" && forward.Class != spec.Class {
		return Operation{}, -1, fmt.Sprintf("the wrapper summary class %s disagrees with the target's %s", forward.Class, spec.Class)
	}
	if forward.ResourceParam < 0 || forward.ResourceParam >= len(call.Args) {
		return Operation{}, -1, "the wrapper summary does not name a resource parameter the call supplies"
	}
	resource := a.resolveOperand(v, call.Args[forward.ResourceParam])
	if !resource.Resolved() {
		return Operation{}, -1, "the wrapper's resource argument identity is not established: " + resource.Missing()
	}
	mode := forward.ModeLiteral
	if forward.ModeParam >= 0 {
		if forward.ModeParam >= len(call.Args) {
			return Operation{}, -1, "the wrapper summary names a mode parameter the call does not supply"
		}
		literal, ok := modeLiteral(call.Args[forward.ModeParam])
		if !ok {
			return Operation{}, -1, "the wrapper's permission argument is not an integer literal"
		}
		mode = literal
	}
	if mode == "" {
		return Operation{}, -1, "the wrapper summary does not establish the permission value"
	}
	op := Operation{
		Identity: forward.Target,
		Class:    spec.Class,
		Resource: ResourceIdentity{Expr: resource, Declaration: v.enclosingDeclaration(call.Pos())},
		Mode:     mode,
		Line:     v.Fset.Position(call.Pos()).Line,
		Col:      v.Fset.Position(call.Pos()).Column,
		Witness:  v.witness(call.Pos(), call.End(), ""),
	}
	return op, forward.ResourceParam, ""
}

// bodyDigest hashes the complete declaration body in the supplied source, so a
// summary cannot be replayed against another body that happens to have the same
// shape.
func bodyDigest(v *fileView, d *ast.FuncDecl) (string, bool) {
	if d.Body == nil {
		return "", false
	}
	start := v.Fset.Position(d.Body.Pos()).Offset
	end := v.Fset.Position(d.Body.End()).Offset
	if start < 0 || end > len(v.Src) || start >= end {
		return "", false
	}
	sum := sha256.Sum256(v.Src[start:end])
	return "sha256:" + hex.EncodeToString(sum[:]), true
}

// modeLiteral normalises an integer permission literal to four-digit octal.
// Equivalent spellings (0711, 0o711, 0x1C9) are the same mode; a non-literal is
// not a comparable value.
func modeLiteral(expr ast.Expr) (string, bool) {
	expr = unwrapParen(expr)
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.INT {
		return "", false
	}
	text := strings.ReplaceAll(lit.Value, "_", "")
	value, err := parseIntLiteral(text)
	if err != nil {
		return "", false
	}
	return fmt.Sprintf("%04o", value), true
}

func sourceText(v *fileView, expr ast.Expr) string {
	if expr == nil {
		return ""
	}
	start := v.Fset.Position(expr.Pos()).Offset
	end := v.Fset.Position(expr.End()).Offset
	if start < 0 || end > len(v.Src) || start >= end {
		return ""
	}
	return strings.Join(strings.Fields(string(v.Src[start:end])), " ")
}

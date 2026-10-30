package fixbinding

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"path"
	"sort"
	"strings"
)

// ModuleIdentity is the owning source identity of the patched tree. A module
// cache coordinate carries its version; a local replacement is identified by
// the digest of its captured content, because it has no version to name.
type ModuleIdentity struct {
	Kind    string `json:"kind,omitempty"`
	Path    string `json:"path,omitempty"`
	Version string `json:"version,omitempty"`
	Digest  string `json:"digest,omitempty"`
}

// SourceRef renders the stable source identity used in API and value
// identities. It is an identity, not a diagnostic label: two sources with
// different bytes and no version share a Path but differ in Digest.
func (m ModuleIdentity) SourceRef() string {
	p := strings.TrimSpace(m.Path)
	if p == "" {
		return "module:unknown"
	}
	switch {
	case strings.TrimSpace(m.Version) != "":
		return "module:" + p + "@" + strings.TrimSpace(m.Version)
	case strings.TrimSpace(m.Digest) != "":
		return "module:" + p + "@" + strings.TrimSpace(m.Digest)
	default:
		return "module:" + p
	}
}

// FileSource is the complete patch-side source of one file in each image.
// A side that was not captured is nil: no identity is inferred from the other
// side, because a patch can change shadowing, imports or declarations between
// the images.
type FileSource struct {
	Before   []byte `json:"before,omitempty"`
	After    []byte `json:"after,omitempty"`
	Selected []byte `json:"selected,omitempty"`
}

// SourceBundle is the complete patch-side source material an inventory may
// resolve identifiers against. It is never the selected implementation: a
// caller that has only the selected source must leave the patch side
// unresolved.
type SourceBundle struct {
	Module    ModuleIdentity        `json:"module,omitempty"`
	Toolchain string                `json:"toolchain,omitempty"`
	Files     map[string]FileSource `json:"files,omitempty"`
	// PackagePaths overrides the derived import path of a directory, for
	// modules whose layout does not equal module path + directory.
	PackagePaths map[string]string `json:"package_paths,omitempty"`
	// ImportOwners records the effective owning source of an import path when
	// a replacement or vendor selection changes it.
	ImportOwners map[string]string `json:"import_owners,omitempty"`
	// Wrappers are checked body summaries of repository-local operations.
	Wrappers []WrapperSummary `json:"wrappers,omitempty"`
}

// FileSourceFor returns the captured source of one file image.
func (b *SourceBundle) FileSourceFor(file string, img Image) ([]byte, bool) {
	if b == nil {
		return nil, false
	}
	fs, ok := b.Files[file]
	if !ok {
		return nil, false
	}
	switch img {
	case ImageBefore:
		if len(fs.Before) == 0 {
			return nil, false
		}
		return fs.Before, true
	case ImageAfter:
		if len(fs.After) == 0 {
			return nil, false
		}
		return fs.After, true
	case ImageSelected:
		if len(fs.Selected) == 0 {
			return nil, false
		}
		return fs.Selected, true
	}
	return nil, false
}

// PackagePathFor returns the import path of a module-relative directory.
func (b *SourceBundle) PackagePathFor(dir string) string {
	if b == nil {
		return ""
	}
	dir = strings.TrimSpace(dir)
	if p, ok := b.PackagePaths[dir]; ok {
		return p
	}
	base := strings.Trim(strings.TrimSpace(b.Module.Path), "/")
	if dir == "" || dir == "." {
		return base
	}
	if base == "" {
		return strings.Trim(dir, "/")
	}
	return base + "/" + strings.Trim(dir, "/")
}

// fileKey identifies one parsed patch-side file image.
type fileKey struct {
	Path  string
	Image Image
}

// valueDecl is what a declared identifier is: a parameter, receiver, result,
// local or package-level value, with the declaration identity and declared
// type the parser established.
type valueDecl struct {
	Origin  string
	Name    string
	Ordinal int
	Decl    string
	Type    ast.Expr
	Init    ast.Expr
	Line    int
	Col     int
	Pos     token.Pos
}

// fileView is one complete patch-side source file, parsed with object
// resolution so identifier shadowing is visible instead of guessed.
type fileView struct {
	Path        string
	Image       Image
	Src         []byte
	Digest      string
	Fset        *token.FileSet
	File        *ast.File
	Imports     map[string]string // local name -> import path
	ImportNames map[string]bool   // local names that are safely known
	DotImport   bool
	Lines       []string
	Values      map[*ast.Object]valueDecl
	Mutated     map[*ast.Object]bool
	Pkg         *packageIndex
	PackagePath string
}

// packageIndex is the package-scope declaration view of one directory in one
// image. Declarations from the other image are never consulted.
type packageIndex struct {
	Dir     string
	Image   Image
	Source  string
	Files   map[string]*fileView
	Funcs   map[string][]*ast.FuncDecl
	Methods map[string]map[string]*ast.FuncDecl // receiver type name -> method name
	Types   map[string]*ast.TypeSpec
	Values  map[string][]*ast.ValueSpec
	// Owners maps a declaration to the file view that parsed it. A cross-file
	// call resolves a FuncDecl from the declaring file, so the body digest and
	// the witness positions must be read from that file's bytes.
	Owners map[*ast.FuncDecl]*fileView
}

// DeclarationIdentity is the resolved identity of a source declaration: its
// file, receiver type, name, declared signature and the digest of the complete
// file the identity was read from. It is the enclosing-declaration provenance a
// resource identity and an effect carry.
type DeclarationIdentity struct {
	Path      string `json:"path"`
	Receiver  string `json:"receiver,omitempty"`
	Name      string `json:"name"`
	Signature string `json:"signature,omitempty"`
	Digest    string `json:"digest,omitempty"`
}

func (d DeclarationIdentity) String() string {
	if d.Path == "" && d.Name == "" {
		return ""
	}
	if d.Receiver != "" {
		return d.Path + ":(" + d.Receiver + ")." + d.Name
	}
	return d.Path + ":" + d.Name
}

// analyzer owns the parse caches of one inventory run.
type analyzer struct {
	bundle   *SourceBundle
	files    map[fileKey]*fileView
	packages map[fileKey]*packageIndex
	views    map[fileKey]error
	// operandResolver is scoped to a census call classification. It supplies
	// the flow-sensitive may-set representative; the census records every
	// member afterward. Patch analysis leaves it nil.
	operandResolver func(*fileView, ast.Expr) ResolvedExpr
}

func newAnalyzer(b *SourceBundle) *analyzer {
	return &analyzer{
		bundle:   b,
		files:    map[fileKey]*fileView{},
		packages: map[fileKey]*packageIndex{},
		views:    map[fileKey]error{},
	}
}

// sourceRef is the owning source of the patch module.
func (a *analyzer) sourceRef() string {
	if a.bundle == nil {
		return "module:unknown"
	}
	return a.bundle.Module.SourceRef()
}

func (a *analyzer) toolchain() string {
	if a.bundle == nil {
		return ""
	}
	return strings.TrimSpace(a.bundle.Toolchain)
}

// view parses and caches one file image. A parse failure is returned as an
// error; callers turn it into an explicit missing-proof obligation.
func (a *analyzer) view(file string, img Image) (*fileView, error) {
	key := fileKey{Path: file, Image: img}
	if v, ok := a.files[key]; ok {
		return v, nil
	}
	if err, ok := a.views[key]; ok {
		return nil, err
	}
	src, ok := a.bundle.FileSourceFor(file, img)
	if !ok {
		err := fmt.Errorf("no captured patch-side %s source for %s", img, file)
		a.views[key] = err
		return nil, err
	}
	v, err := a.parseFile(file, img, src)
	if err != nil {
		a.views[key] = err
		return nil, err
	}
	a.files[key] = v
	return v, nil
}

func (a *analyzer) parseFile(file string, img Image, src []byte) (*fileView, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, src, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parse %s %s source: %w", img, file, err)
	}
	v := &fileView{
		Path:        file,
		Image:       img,
		Src:         src,
		Digest:      DigestBytes(src),
		Fset:        fset,
		File:        f,
		Imports:     map[string]string{},
		ImportNames: map[string]bool{},
		Lines:       strings.Split(strings.ReplaceAll(string(src), "\r\n", "\n"), "\n"),
		Values:      map[*ast.Object]valueDecl{},
		Mutated:     map[*ast.Object]bool{},
		PackagePath: a.bundle.PackagePathFor(dirOf(file)),
	}
	for _, imp := range f.Imports {
		p := strings.Trim(imp.Path.Value, `"`)
		name := ""
		if imp.Name != nil {
			name = imp.Name.Name
		}
		switch name {
		case "_":
			continue
		case ".":
			v.DotImport = true
			continue
		case "":
			base := path.Base(p)
			if !isIdentifierString(base) || isMajorVersionSuffix(base) {
				// The declared package name is not derivable from the import
				// path alone; a selector with this base cannot be resolved
				// from the file, so leave it unknown instead of guessing.
				v.ImportNames[base] = false
				continue
			}
			name = base
		}
		if prev, ok := v.Imports[name]; ok && prev != p {
			// Two different packages cannot share a name in one file; if the
			// source says otherwise it is not resolvable.
			v.ImportNames[name] = false
			continue
		}
		v.Imports[name] = p
		v.ImportNames[name] = true
	}
	v.indexValues()
	return v, nil
}

// packageFor returns the package-scope index of the file's directory.
func (a *analyzer) packageFor(v *fileView) *packageIndex {
	dir := path.Dir(v.Path)
	if dir == "." {
		dir = ""
	}
	key := fileKey{Path: dir, Image: v.Image}
	if p, ok := a.packages[key]; ok {
		return p
	}
	p := &packageIndex{
		Dir:     dir,
		Image:   v.Image,
		Source:  a.sourceRef(),
		Files:   map[string]*fileView{},
		Funcs:   map[string][]*ast.FuncDecl{},
		Methods: map[string]map[string]*ast.FuncDecl{},
		Types:   map[string]*ast.TypeSpec{},
		Values:  map[string][]*ast.ValueSpec{},
		Owners:  map[*ast.FuncDecl]*fileView{},
	}
	a.packages[key] = p
	if a.bundle == nil {
		p.addFile(v)
		return p
	}
	for file := range a.bundle.Files {
		if dirOf(file) != dir {
			continue
		}
		other, err := a.view(file, v.Image)
		if err != nil {
			continue
		}
		p.addFile(other)
	}
	return p
}

// owningView returns the parsed view that declares d. A call resolved through
// the package index names a FuncDecl parsed in the declaring file, so the body
// digest and the witnesses must be read from that file's bytes — the caller's
// own file has a different offset space and would produce a digest of the wrong
// region.
func (a *analyzer) owningView(v *fileView, d *ast.FuncDecl) *fileView {
	if d == nil {
		return v
	}
	if v != nil && v.Pkg != nil {
		if owner, ok := v.Pkg.Owners[d]; ok {
			return owner
		}
	}
	for _, key := range a.sortedFileKeys() {
		f := a.files[key]
		if f == nil {
			continue
		}
		for _, decl := range f.File.Decls {
			if decl == d {
				return f
			}
		}
	}
	return v
}

// sortedFileKeys returns the parsed file keys in a deterministic order so an
// owner lookup never depends on map iteration order.
func (a *analyzer) sortedFileKeys() []fileKey {
	keys := make([]fileKey, 0, len(a.files))
	for key := range a.files {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Path != keys[j].Path {
			return keys[i].Path < keys[j].Path
		}
		return keys[i].Image < keys[j].Image
	})
	return keys
}

func dirOf(file string) string {
	d := path.Dir(file)
	if d == "." {
		return ""
	}
	return d
}

func (p *packageIndex) addFile(f *fileView) {
	if _, ok := p.Files[f.Path]; ok {
		return
	}
	p.Files[f.Path] = f
	f.Pkg = p
	for _, decl := range f.File.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			p.Owners[d] = f
			if d.Recv != nil && len(d.Recv.List) > 0 {
				rt := receiverTypeName(d.Recv.List[0].Type)
				if rt != "" {
					if p.Methods[rt] == nil {
						p.Methods[rt] = map[string]*ast.FuncDecl{}
					}
					p.Methods[rt][d.Name.Name] = d
				}
			} else {
				p.Funcs[d.Name.Name] = append(p.Funcs[d.Name.Name], d)
			}
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					p.Types[s.Name.Name] = s
				case *ast.ValueSpec:
					for _, n := range s.Names {
						p.Values[n.Name] = append(p.Values[n.Name], s)
					}
				}
			}
		}
	}
}

// function returns the local function declaration for a name, when exactly one
// exists in the provided package files.
func (p *packageIndex) function(name string) *ast.FuncDecl {
	fns := p.Funcs[name]
	if len(fns) != 1 {
		return nil
	}
	return fns[0]
}

// method returns the local method declaration of a receiver type.
func (p *packageIndex) method(recvType, name string) *ast.FuncDecl {
	if m, ok := p.Methods[recvType]; ok {
		return m[name]
	}
	return nil
}

func receiverTypeName(expr ast.Expr) string {
	expr = unwrapParen(expr)
	switch x := expr.(type) {
	case *ast.StarExpr:
		return receiverTypeName(x.X)
	case *ast.Ident:
		return x.Name
	case *ast.IndexExpr:
		return receiverTypeName(x.X)
	case *ast.IndexListExpr:
		return receiverTypeName(x.X)
	}
	return ""
}

func unwrapParen(expr ast.Expr) ast.Expr {
	for {
		p, ok := expr.(*ast.ParenExpr)
		if !ok {
			return expr
		}
		expr = p.X
	}
}

// indexValues records what every declared identifier is, from the declaration
// side, so a reference's origin and provenance do not have to be guessed from
// its spelling.
func (v *fileView) indexValues() {
	for _, decl := range v.File.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			id := functionDeclID(v.Path, d)
			v.registerFieldList(d.Recv, "receiver", id, 0)
			paramOrd := v.registerFieldList(d.Type.Params, "parameter", id, 0)
			v.registerFieldList(d.Type.Results, "result", id, paramOrd)
			if d.Body != nil {
				v.indexBody(d.Body, id)
			}
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					if name.Obj == nil {
						continue
					}
					var init ast.Expr
					if len(vs.Values) == len(vs.Names) {
						init = vs.Values[i]
					}
					v.Values[name.Obj] = valueDecl{
						Origin: "global",
						Name:   name.Name,
						Decl:   v.Path + "#global." + name.Name,
						Type:   vs.Type,
						Init:   init,
						Line:   v.Fset.Position(name.Pos()).Line,
						Col:    v.Fset.Position(name.Pos()).Column,
						Pos:    name.Pos(),
					}
				}
			}
		}
	}
}

// registerFieldList registers every named field of a parameter/result/receiver
// list. It returns the ordinal after the list so results continue the
// parameter numbering.
func (v *fileView) registerFieldList(list *ast.FieldList, origin, declID string, start int) int {
	if list == nil {
		return start
	}
	ordinal := start
	for _, field := range list.List {
		for _, name := range field.Names {
			if name.Obj == nil {
				ordinal++
				continue
			}
			v.Values[name.Obj] = valueDecl{
				Origin:  origin,
				Name:    name.Name,
				Ordinal: ordinal,
				Decl:    declID + "." + origin + "[" + name.Name + "]",
				Type:    field.Type,
				Line:    v.Fset.Position(name.Pos()).Line,
				Col:     v.Fset.Position(name.Pos()).Column,
				Pos:     name.Pos(),
			}
			ordinal++
		}
	}
	return ordinal
}

// indexBody records locals declared in a function body, including those inside
// nested function literals (which get their own declaration identity).
func (v *fileView) indexBody(body *ast.BlockStmt, owner string) {
	ordinal := 0
	var walk func(n ast.Node) bool
	walk = func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncLit:
			litID := fmt.Sprintf("%s@lit%d", owner, v.Fset.Position(x.Pos()).Line)
			v.registerFieldList(x.Type.Params, "parameter", litID, 0)
			v.registerFieldList(x.Type.Results, "result", litID, 0)
			v.indexBody(x.Body, litID)
			return false
		case *ast.AssignStmt:
			if x.Tok != token.DEFINE {
				for _, lhs := range x.Lhs {
					markMutated(v, lhs)
				}
				return true
			}
			for i, lhs := range x.Lhs {
				id, ok := lhs.(*ast.Ident)
				if !ok || id.Obj == nil {
					continue
				}
				if _, exists := v.Values[id.Obj]; exists {
					// A short declaration that only redeclares an existing
					// variable assigns it; the original provenance no longer
					// describes every use.
					v.Mutated[id.Obj] = true
					continue
				}
				var init ast.Expr
				if len(x.Rhs) == len(x.Lhs) {
					init = x.Rhs[i]
				}
				v.Values[id.Obj] = valueDecl{
					Origin:  "local",
					Name:    id.Name,
					Ordinal: ordinal,
					Decl:    fmt.Sprintf("%s.local[%s]@%d", owner, id.Name, v.Fset.Position(id.Pos()).Line),
					Init:    init,
					Line:    v.Fset.Position(id.Pos()).Line,
					Col:     v.Fset.Position(id.Pos()).Column,
					Pos:     id.Pos(),
				}
				ordinal++
			}
		case *ast.DeclStmt:
			gd, ok := x.Decl.(*ast.GenDecl)
			if !ok {
				return true
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					if name.Obj == nil {
						continue
					}
					var init ast.Expr
					if len(vs.Values) == len(vs.Names) {
						init = vs.Values[i]
					}
					v.Values[name.Obj] = valueDecl{
						Origin:  "local",
						Name:    name.Name,
						Ordinal: ordinal,
						Decl:    fmt.Sprintf("%s.local[%s]@%d", owner, name.Name, v.Fset.Position(name.Pos()).Line),
						Type:    vs.Type,
						Init:    init,
						Line:    v.Fset.Position(name.Pos()).Line,
						Col:     v.Fset.Position(name.Pos()).Column,
						Pos:     name.Pos(),
					}
					ordinal++
				}
			}
		case *ast.RangeStmt:
			declare := x.Tok == token.DEFINE
			for _, expr := range []ast.Expr{x.Key, x.Value} {
				id, ok := expr.(*ast.Ident)
				if !ok || id.Obj == nil || id.Name == "_" {
					continue
				}
				if !declare {
					v.Mutated[id.Obj] = true
					continue
				}
				v.Values[id.Obj] = valueDecl{
					Origin:  "local",
					Name:    id.Name,
					Ordinal: ordinal,
					Decl:    fmt.Sprintf("%s.local[%s]@%d", owner, id.Name, v.Fset.Position(id.Pos()).Line),
					Init:    x.X,
					Line:    v.Fset.Position(id.Pos()).Line,
					Col:     v.Fset.Position(id.Pos()).Column,
					Pos:     id.Pos(),
				}
				ordinal++
			}
		case *ast.IncDecStmt:
			markMutated(v, x.X)
		}
		return true
	}
	ast.Inspect(body, walk)
}

// markMutated records that a value's declared initializer no longer describes
// every use. A mutated local keeps an identity of "a value whose content is not
// established", never the identity of its initializer.
func markMutated(v *fileView, expr ast.Expr) {
	switch x := expr.(type) {
	case *ast.Ident:
		if x.Obj != nil {
			v.Mutated[x.Obj] = true
		}
	case *ast.ParenExpr:
		markMutated(v, x.X)
	}
}

func functionDeclID(file string, d *ast.FuncDecl) string {
	return file + "#" + declarationString(d)
}

func declarationString(d *ast.FuncDecl) string {
	if d.Recv != nil && len(d.Recv.List) > 0 {
		return "(" + receiverTypeName(d.Recv.List[0].Type) + ")." + d.Name.Name
	}
	return d.Name.Name
}

// declaration returns the identity of a function/method declaration.
func (v *fileView) declaration(d *ast.FuncDecl) DeclarationIdentity {
	recv := ""
	if d.Recv != nil && len(d.Recv.List) > 0 {
		recv = receiverTypeName(d.Recv.List[0].Type)
	}
	return DeclarationIdentity{
		Path:      v.Path,
		Receiver:  recv,
		Name:      d.Name.Name,
		Signature: v.signature(d.Type),
		Digest:    v.Digest,
	}
}

// signature renders the declared type canonically: import aliases become
// import paths, and local named types become package-qualified, so two
// spellings of the same declaration compare equal while two same-named
// declarations from different packages do not.
func (v *fileView) signature(ft *ast.FuncType) string {
	if ft == nil {
		return ""
	}
	return "func" + v.fieldListString(ft.Params, true) + v.resultString(ft.Results)
}

func (v *fileView) resultString(list *ast.FieldList) string {
	if list == nil || len(list.List) == 0 {
		return ""
	}
	if len(list.List) == 1 && len(list.List[0].Names) == 0 {
		return " " + v.canonicalType(list.List[0].Type)
	}
	return " " + v.fieldListString(list, false)
}

func (v *fileView) fieldListString(list *ast.FieldList, names bool) string {
	if list == nil {
		return "()"
	}
	var parts []string
	for _, field := range list.List {
		typ := v.canonicalType(field.Type)
		if names && len(field.Names) > 0 {
			var ns []string
			for _, n := range field.Names {
				ns = append(ns, n.Name)
			}
			parts = append(parts, strings.Join(ns, ", ")+" "+typ)
			continue
		}
		if names {
			parts = append(parts, typ)
			continue
		}
		parts = append(parts, typ)
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

// canonicalType renders a declared type with import paths instead of local
// aliases and package-qualified local named types.
func (v *fileView) canonicalType(expr ast.Expr) string {
	if expr == nil {
		return ""
	}
	switch x := expr.(type) {
	case *ast.Ident:
		if isPredeclared(x.Name) {
			return x.Name
		}
		if v.Pkg != nil {
			if _, ok := v.Pkg.Types[x.Name]; ok {
				return v.packagePath() + "." + x.Name
			}
		}
		return x.Name
	case *ast.SelectorExpr:
		if id, ok := x.X.(*ast.Ident); ok {
			if p, known := v.Imports[id.Name]; known {
				return p + "." + x.Sel.Name
			}
		}
		return v.canonicalType(x.X) + "." + x.Sel.Name
	case *ast.StarExpr:
		return "*" + v.canonicalType(x.X)
	case *ast.ArrayType:
		length := ""
		if x.Len != nil {
			length = v.canonicalType(x.Len)
			if id, ok := x.Len.(*ast.Ident); ok && id.Name == "..." {
				length = "..."
			}
		}
		return "[" + length + "]" + v.canonicalType(x.Elt)
	case *ast.MapType:
		return "map[" + v.canonicalType(x.Key) + "]" + v.canonicalType(x.Value)
	case *ast.ChanType:
		switch x.Dir {
		case ast.SEND:
			return "chan<- " + v.canonicalType(x.Value)
		case ast.RECV:
			return "<-chan " + v.canonicalType(x.Value)
		}
		return "chan " + v.canonicalType(x.Value)
	case *ast.Ellipsis:
		return "..." + v.canonicalType(x.Elt)
	case *ast.ParenExpr:
		return "(" + v.canonicalType(x.X) + ")"
	case *ast.InterfaceType:
		return "interface{}"
	case *ast.FuncType:
		return v.signature(x)
	case *ast.StructType:
		return "struct{}"
	}
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, v.Fset, expr); err != nil {
		return ""
	}
	return buf.String()
}

func (v *fileView) packagePath() string { return v.PackagePath }

// lineText returns the complete source line, without its terminating newline.
func (v *fileView) lineText(line int) (string, bool) {
	if line < 1 || line > len(v.Lines) {
		return "", false
	}
	return v.Lines[line-1], true
}

// consistentWithHunk reports whether the hunk image is an exact excerpt of the
// captured file. The check is deliberately exact — only a trailing CR is
// normalized — because an approximate match would let a stale or unrelated
// source be used to qualify the patch's identifiers.
func (v *fileView) consistentWithHunk(h Hunk, img Image) (string, bool) {
	for _, ln := range h.ImageLines(img) {
		text, ok := v.lineText(ln.lineFor(img))
		if !ok {
			return fmt.Sprintf("the hunk references %s line %d, beyond the captured source's %d lines",
				img, ln.lineFor(img), len(v.Lines)), false
		}
		if text != ln.Text {
			return fmt.Sprintf("the hunk's %s line %d does not match the captured source: patch %q, source %q",
				img, ln.lineFor(img), truncate(ln.Text, 80), truncate(text, 80)), false
		}
	}
	return "", true
}

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentPart(c byte) bool { return isIdentStart(c) || (c >= '0' && c <= '9') }

func isIdentifierString(s string) bool {
	if s == "" || !isIdentStart(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		if !isIdentPart(s[i]) {
			return false
		}
	}
	return true
}

func isMajorVersionSuffix(s string) bool {
	if len(s) < 2 || s[0] != 'v' {
		return false
	}
	for i := 1; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isPredeclared(name string) bool {
	switch name {
	case "bool", "byte", "complex64", "complex128", "error", "float32", "float64",
		"int", "int8", "int16", "int32", "int64", "rune", "string", "uint",
		"uint8", "uint16", "uint32", "uint64", "uintptr", "any", "comparable":
		return true
	}
	return false
}

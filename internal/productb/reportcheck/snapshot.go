package reportcheck

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// snapshotIndex is a read-only view of one snapshot tree: per-file
// declaration tables plus a package index for claimed-symbol resolution.
// It never runs go tooling inside the tree — files are parsed, never
// compiled.
type snapshotIndex struct {
	root       string
	modulePath string
	files      map[string]*fileInfo // normalized rel path -> info
	pkgByPath  map[string]*pkgInfo  // import path -> package
	pkgByName  map[string][]*pkgInfo
}

// fileInfo is one regular file: its line count plus (for parseable Go
// files) declarations and the package it belongs to.
type fileInfo struct {
	rel       string
	lines     int
	linesRead bool
	isGo      bool
	parseOK   bool
	pkg       *pkgInfo
	decls     []declInfo
	imports   []lineSpan // 1-based inclusive spans of import declarations
}

// lineSpan is a 1-based inclusive line range.
type lineSpan struct {
	start int
	end   int
}

// pkgInfo is one Go package directory inside the tree.
type pkgInfo struct {
	dir        string
	importPath string
	name       string
	files      []*fileInfo
}

// declInfo is one top-level declaration with a canonical name:
// "Func", "Type.Method", "Type" or "Var".
type declInfo struct {
	name string // canonical symbol name (receiver normalized to Type)
	file *fileInfo
	line int
	end  int
	kind string // func | method | type | var
}

// buildIndex walks the snapshot once, recording regular files and parsing
// every .go file for declarations. Files that fail to parse are still
// indexed (line bounds apply) but carry no declarations.
func buildIndex(root string) (*snapshotIndex, error) {
	idx := &snapshotIndex{
		root:      root,
		files:     map[string]*fileInfo{},
		pkgByPath: map[string]*pkgInfo{},
		pkgByName: map[string][]*pkgInfo{},
	}
	if b, err := os.ReadFile(filepath.Join(root, "go.mod")); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			l = strings.TrimSpace(l)
			if strings.HasPrefix(l, "module") {
				idx.modulePath = strings.TrimSpace(strings.TrimPrefix(l, "module"))
				break
			}
		}
	}
	err := filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel := filepath.ToSlash(mustRel(root, p))
		if fi.IsDir() {
			base := fi.Name()
			if base == ".git" || strings.HasPrefix(base, ".") && rel != "." {
				return filepath.SkipDir
			}
			return nil
		}
		if !fi.Mode().IsRegular() {
			return nil
		}
		f := &fileInfo{rel: rel, isGo: strings.HasSuffix(rel, ".go")}
		idx.files[rel] = f
		if f.isGo {
			idx.parseGoFile(f, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	// Sort declarations so every lookup and every emitted decl is
	// deterministic regardless of walk order.
	for _, f := range idx.files {
		sort.Slice(f.decls, func(i, j int) bool { return f.decls[i].line < f.decls[j].line })
	}
	return idx, nil
}

// parseGoFile fills declarations and package membership for one .go file.
func (idx *snapshotIndex) parseGoFile(f *fileInfo, abs string) {
	fset := token.NewFileSet()
	src, err := parser.ParseFile(fset, abs, nil, 0)
	if err != nil {
		return
	}
	f.parseOK = true
	dir := dirOf(f.rel)
	pkg := idx.pkg(dir, src.Name.Name)
	pkg.files = append(pkg.files, f)
	f.pkg = pkg
	tf := fset.File(src.Pos())
	for _, d := range src.Decls {
		switch decl := d.(type) {
		case *ast.FuncDecl:
			name := decl.Name.Name
			kind := "func"
			if decl.Recv != nil && len(decl.Recv.List) > 0 {
				name = recvTypeName(decl.Recv.List[0].Type) + "." + name
				kind = "method"
			}
			f.decls = append(f.decls, declInfo{
				name: name, file: f, kind: kind,
				line: tf.Line(d.Pos()), end: tf.Line(d.End()),
			})
		case *ast.GenDecl:
			if decl.Tok == token.IMPORT {
				f.imports = append(f.imports, lineSpan{tf.Line(d.Pos()), tf.Line(d.End())})
			}
			for _, spec := range decl.Specs {
				var names []string
				kind := "var"
				switch sp := spec.(type) {
				case *ast.TypeSpec:
					names = []string{sp.Name.Name}
					kind = "type"
				case *ast.ValueSpec:
					for _, n := range sp.Names {
						names = append(names, n.Name)
					}
				default:
					continue
				}
				for _, n := range names {
					f.decls = append(f.decls, declInfo{
						name: n, file: f, kind: kind,
						line: tf.Line(d.Pos()), end: tf.Line(d.End()),
					})
				}
			}
		}
	}
}

// recvTypeName reduces a method receiver expression to the bare type name:
// *T, T, *T[P] all yield T.
func recvTypeName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return recvTypeName(t.X)
	case *ast.Ident:
		return t.Name
	case *ast.IndexExpr:
		return recvTypeName(t.X)
	case *ast.IndexListExpr:
		return recvTypeName(t.X)
	case *ast.ParenExpr:
		return recvTypeName(t.X)
	case *ast.SelectorExpr:
		return t.Sel.Name
	default:
		return ""
	}
}

// pkg returns (creating on demand) the package record for one directory,
// deriving its import path from the module path or the vendor layout.
func (idx *snapshotIndex) pkg(dir, name string) *pkgInfo {
	importPath := idx.importPath(dir)
	if p, ok := idx.pkgByPath[importPath]; ok {
		return p
	}
	p := &pkgInfo{dir: dir, importPath: importPath, name: name}
	idx.pkgByPath[importPath] = p
	idx.pkgByName[name] = append(idx.pkgByName[name], p)
	return p
}

// importPath maps a snapshot-relative directory to a Go import path:
// vendor/… strips the vendor prefix, module paths join under go.mod's
// module, and without a module path the directory itself stands in.
func (idx *snapshotIndex) importPath(dir string) string {
	if strings.HasPrefix(dir, "vendor/") {
		return strings.TrimPrefix(dir, "vendor/")
	}
	if idx.modulePath == "" {
		return dir
	}
	if dir == "" {
		return idx.modulePath
	}
	return idx.modulePath + "/" + dir
}

func dirOf(rel string) string {
	if i := strings.LastIndex(rel, "/"); i >= 0 {
		return rel[:i]
	}
	return ""
}

func mustRel(root, p string) string {
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return p
	}
	return rel
}

// resolvePath normalizes further candidates for a cited path: the path
// itself, then without a leading work/ segment, then without a diff
// a//b/ prefix. Escaped paths yield no candidates.
func (idx *snapshotIndex) resolvePath(path string) (*fileInfo, string, bool) {
	if path == "" {
		return nil, "", false
	}
	if escapesRoot(path) {
		return nil, "", false
	}
	candidates := []string{path}
	if strings.HasPrefix(path, "work/") {
		candidates = append(candidates, strings.TrimPrefix(path, "work/"))
	}
	if len(path) > 2 && path[1] == '/' && (path[0] == 'a' || path[0] == 'b') {
		candidates = append(candidates, path[2:])
	}
	for _, c := range candidates {
		if escapesRoot(c) {
			continue
		}
		if f, ok := idx.files[c]; ok {
			return f, c, true
		}
	}
	return nil, "", false
}

// escapesRoot reports whether a normalized relative path leaves the root.
func escapesRoot(rel string) bool {
	depth := 0
	for _, seg := range strings.Split(rel, "/") {
		switch seg {
		case "", ".":
		case "..":
			depth--
			if depth < 0 {
				return true
			}
		default:
			depth++
		}
	}
	return false
}

// enclosing returns the function/method declaration whose span contains
// line. Top-level (type/var) declarations do not enclose a cited body
// line — a claim inside them is file-level, not inside a symbol.
func (f *fileInfo) enclosing(line int) *declInfo {
	for i := range f.decls {
		d := &f.decls[i]
		if (d.kind == "func" || d.kind == "method") && line >= d.line && line <= d.end {
			return d
		}
	}
	return nil
}

// importLine reports whether a 1-based line lies inside an import
// declaration (single import or a grouped import block).
func (f *fileInfo) importLine(line int) bool {
	for _, s := range f.imports {
		if line >= s.start && line <= s.end {
			return true
		}
	}
	return false
}

// findDecl locates a symbol declaration: qualified claims resolve through
// the package index, two-segment type claims fall back to a global
// type-name scan.
func (idx *snapshotIndex) findDecl(qual, name string, prefer *pkgInfo) *declInfo {
	qual = strings.TrimSuffix(qual, ".")
	if qual == "" {
		if prefer != nil {
			return prefer.decl(name)
		}
		return nil
	}
	if p := idx.lookupPkg(qual); p != nil {
		if d := p.decl(name); d != nil {
			return d
		}
	}
	// Multi-segment qualifier: dep.Server.Serve may be pkg dep +
	// Server.Serve rather than pkg dep.Server + Serve — split at the
	// last ./ and try the tail as a type qualifier.
	if i := strings.LastIndexAny(qual, "./"); i >= 0 {
		pkgQual, typ := qual[:i], qual[i+1:]
		if p := idx.lookupPkg(pkgQual); p != nil {
			if d := p.decl(typ + "." + name); d != nil {
				return d
			}
		}
	}
	// A capitalized one-segment qualifier is a type, not a package:
	// T.M resolves wherever type T lives.
	if !strings.ContainsAny(qual, "/.") && isExported(qual) {
		return idx.typeMethodDecl(qual, name)
	}
	return nil
}

// lookupPkg resolves a package qualifier: exact import path first, then a
// package name or an import-path basename match.
func (idx *snapshotIndex) lookupPkg(qual string) *pkgInfo {
	if p, ok := idx.pkgByPath[qual]; ok {
		return p
	}
	if pkgs, ok := idx.pkgByName[qual]; ok && len(pkgs) == 1 {
		return pkgs[0]
	}
	var found *pkgInfo
	for path, p := range idx.pkgByPath {
		if strings.HasSuffix(path, "/"+qual) {
			if found != nil {
				return nil // ambiguous basename
			}
			found = p
		}
	}
	return found
}

// decl finds a declaration by canonical name inside one package.
func (p *pkgInfo) decl(name string) *declInfo {
	for _, f := range p.files {
		for i := range f.decls {
			if f.decls[i].name == name {
				return &f.decls[i]
			}
		}
	}
	return nil
}

// typeMethodDecl scans every package for a method or field-level decl
// named T.Name — used for type-qualified claims without a package.
func (idx *snapshotIndex) typeMethodDecl(typ, name string) *declInfo {
	want := typ + "." + name
	var found *declInfo
	for _, p := range idx.pkgByPath {
		for _, f := range p.files {
			for i := range f.decls {
				if f.decls[i].name == want {
					if found != nil {
						return nil
					}
					found = &f.decls[i]
				}
			}
		}
	}
	return found
}

// lineCount counts lines the same way the citation presence check does.
func lineCount(b []byte) int {
	if len(b) == 0 {
		return 0
	}
	return strings.Count(string(b), "\n") + 1
}

// fillLines records the line count for a file — done lazily at lookup so
// the index walk stays metadata-only.
func (idx *snapshotIndex) fillLines(f *fileInfo) {
	if f.linesRead {
		return
	}
	f.linesRead = true
	b, err := os.ReadFile(filepath.Join(idx.root, filepath.FromSlash(f.rel)))
	if err != nil {
		f.lines = -1
		return
	}
	f.lines = lineCount(b)
}

// qualifiedName renders a decl's canonical import-path-qualified name.
func (d *declInfo) qualifiedName() string {
	if d.file == nil || d.file.pkg == nil {
		return d.name
	}
	return d.file.pkg.importPath + "." + d.name
}

func isExported(s string) bool {
	if s == "" {
		return false
	}
	c := s[0]
	return c >= 'A' && c <= 'Z'
}

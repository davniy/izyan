package goanalysis

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/davniy/izyan/internal/domain"
)

// SymbolLookup is the result of LookupSymbol: the declaration site plus the
// evidence base that produced it.
type SymbolLookup struct {
	// Site is the declaration position; nil when the lookup failed.
	Site *domain.CallSite
	// Vendored reports that Site came from parsing <Dir>/vendor/<import
	// path> because the Go loader could not load the package. The hit
	// proves the declaration exists in the snapshot's build input, but it
	// is syntax-only evidence: no type checking, build-constraint
	// selection or reachability was applied.
	Vendored bool
	// LoaderError is the loader failure that forced the vendored fallback.
	// It is set on every lookup that had to bypass the loader — including
	// failed ones — because a load failure is an unmeasured package, never
	// evidence of absence.
	LoaderError error
}

// LookupSymbol resolves ref exactly like FindSymbol, but when the Go loader
// cannot load the symbol's package it falls back to the snapshot's vendored
// source instead of reporting the load failure as a missing symbol.
//
// The fallback exists because a loader refusal — vendor/go.mod inconsistency
// under -mod=vendor, a toolchain that cannot build the snapshot's module
// graph — says nothing about the bytes on disk: a package an advisory names
// can be present and readable under vendor/ while go/packages cannot type
// it. Root-cause verification must not turn that measurement gap into
// "symbol absent".
//
// The fallback never invents absence. When the vendored directory is missing,
// unparsable or does not declare the symbol, the loader failure is returned
// unchanged, so absence stays an open question that only build-graph evidence
// may close.
func (ix *Index) LookupSymbol(ctx context.Context, ref domain.SymbolRef) (SymbolLookup, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	site, err := ix.findSymbol(ctx, ref)
	if err == nil {
		return SymbolLookup{Site: site}, nil
	}
	if !isLoaderFailure(err) {
		return SymbolLookup{}, err
	}
	// A cancelled query is answered as cancelled: the fallback reads disk
	// under the caller's deadline and must not outlive it.
	if ix.ctxOr(ctx).Err() != nil {
		return SymbolLookup{}, err
	}
	return ix.vendoredLookup(ref, err)
}

// vendoredLookup reads ref's declaration from the vendored source tree. A
// miss returns cause (the loader failure) unchanged.
func (ix *Index) vendoredLookup(ref domain.SymbolRef, cause error) (SymbolLookup, error) {
	if site := findVendoredSymbol(ix.Dir, ref); site != nil {
		return SymbolLookup{Site: site, Vendored: true, LoaderError: cause}, nil
	}
	return SymbolLookup{LoaderError: cause}, cause
}

// isLoaderFailure reports whether err is a measurement failure rather than a
// resolved answer: the loader never produced a typed package for the symbol's
// package (vendor/go.mod inconsistency, toolchain refusal, a dependency
// stub without types). Only such failures may be answered from vendor source.
// The two symbol sentinels are answers — absence and ambiguity — and must not
// be overridden by a syntax-only second opinion.
func isLoaderFailure(err error) bool {
	return !errors.Is(err, ErrSymbolNotFoundInPackage) && !errors.Is(err, ErrAmbiguousSymbol)
}

// findVendoredSymbol resolves ref from <root>/vendor/<import path> by parsing
// the package's non-test Go files. It returns nil when the package is not
// vendored, has no parsable source, or does not declare the symbol — the
// caller keeps its loader failure in every such case.
func findVendoredSymbol(root string, ref domain.SymbolRef) *domain.CallSite {
	dir, ok := vendoredPackageDir(root, ref.Package)
	if !ok {
		return nil
	}
	names, err := vendoredGoFiles(dir)
	if err != nil || len(names) == 0 {
		return nil
	}
	decls := &vendoredDecls{
		objects:     map[string]*ast.Ident{},
		methods:     map[string]map[string]*ast.Ident{},
		fields:      map[string]map[string]*ast.Ident{},
		methodCount: map[string]int{},
	}
	fset := token.NewFileSet()
	parsed := 0
	for _, name := range names {
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			continue
		}
		parsed++
		decls.add(f)
	}
	if parsed == 0 {
		return nil
	}
	id := decls.lookup(splitSymbol(ref.Symbol))
	if id == nil {
		return nil
	}
	pos := fset.Position(id.Pos())
	if pos.Filename == "" {
		return nil
	}
	return &domain.CallSite{
		File:     pos.Filename,
		Line:     pos.Line,
		Function: id.Name,
		Package:  ref.Package,
	}
}

// vendoredPackageDir maps an import path to its vendored source directory.
// Import paths are slash-separated and cannot name a parent, an absolute
// path or a Windows drive — anything else is refused rather than joined.
func vendoredPackageDir(root, importPath string) (string, bool) {
	if root == "" || importPath == "" {
		return "", false
	}
	if strings.ContainsAny(importPath, `\:`) || strings.HasPrefix(importPath, "/") {
		return "", false
	}
	if path.Clean(importPath) != importPath {
		return "", false
	}
	for _, elem := range strings.Split(importPath, "/") {
		if elem == "" || elem == "." || elem == ".." {
			return "", false
		}
	}
	return filepath.Join(root, "vendor", filepath.FromSlash(importPath)), true
}

// vendoredGoFiles lists the non-test Go sources of a vendored package in
// directory order (os.ReadDir sorts by name), so the scan is deterministic.
func vendoredGoFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		names = append(names, name)
	}
	return names, nil
}

// vendoredDecls is the declaration inventory of one vendored package,
// collected from parsed syntax only.
type vendoredDecls struct {
	// objects holds package-level func/type/var/const declarations.
	objects map[string]*ast.Ident
	// methods maps receiver type name -> method name -> declaration.
	methods map[string]map[string]*ast.Ident
	// fields maps struct type name -> field name -> declaration.
	fields map[string]map[string]*ast.Ident
	// methodCount counts same-named methods across all receiver types —
	// the bare-name ambiguity check findMethodInPkg performs on typed
	// packages.
	methodCount map[string]int
}

func (d *vendoredDecls) add(f *ast.File) {
	for _, decl := range f.Decls {
		switch dcl := decl.(type) {
		case *ast.FuncDecl:
			if dcl.Name == nil {
				continue
			}
			if dcl.Recv == nil || len(dcl.Recv.List) == 0 {
				d.objects[dcl.Name.Name] = dcl.Name
				continue
			}
			recv := recvDeclName(dcl.Recv.List[0].Type)
			if recv == "" {
				continue
			}
			set := d.methods[recv]
			if set == nil {
				set = map[string]*ast.Ident{}
				d.methods[recv] = set
			}
			set[dcl.Name.Name] = dcl.Name
			d.methodCount[dcl.Name.Name]++
		case *ast.GenDecl:
			for _, spec := range dcl.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					if s.Name == nil {
						continue
					}
					d.objects[s.Name.Name] = s.Name
					st, ok := s.Type.(*ast.StructType)
					if !ok || st.Fields == nil {
						continue
					}
					for _, field := range st.Fields.List {
						if len(field.Names) == 0 {
							// Embedded field: its name is its type name.
							if id, ok := baseIdent(field.Type); ok {
								d.addField(s.Name.Name, id.Name, id)
							}
							continue
						}
						for _, n := range field.Names {
							d.addField(s.Name.Name, n.Name, n)
						}
					}
				case *ast.ValueSpec:
					for _, n := range s.Names {
						d.objects[n.Name] = n
					}
				}
			}
		}
	}
}

func (d *vendoredDecls) addField(typeName, name string, id *ast.Ident) {
	set := d.fields[typeName]
	if set == nil {
		set = map[string]*ast.Ident{}
		d.fields[typeName] = set
	}
	set[name] = id
}

// lookup resolves the same symbol forms findObjectInPkg resolves on a typed
// package: a package-level declaration, a Type.Method/Type.Field pair, or a
// bare name that names a method of exactly one type. An ambiguous bare name
// is deliberately a miss — absence must not be invented, and neither must a
// unique declaration.
func (d *vendoredDecls) lookup(typeName, name string) *ast.Ident {
	if typeName == "" {
		if id, ok := d.objects[name]; ok {
			return id
		}
		if d.methodCount[name] != 1 {
			return nil
		}
		for _, set := range d.methods {
			if id, ok := set[name]; ok {
				return id
			}
		}
		return nil
	}
	if id, ok := d.methods[typeName][name]; ok {
		return id
	}
	return d.fields[typeName][name]
}

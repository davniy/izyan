package fixbinding

import (
	"go/ast"
	"sort"
)

// AnalyzeOptions configures a single-file patch-side analysis.
type AnalyzeOptions struct {
	Module       ModuleIdentity        `json:"module,omitempty"`
	Toolchain    string                `json:"toolchain,omitempty"`
	Image        Image                 `json:"image"`
	PackageFiles map[string]FileSource `json:"package_files,omitempty"`
	PackagePaths map[string]string     `json:"package_paths,omitempty"`
	ImportOwners map[string]string     `json:"import_owners,omitempty"`
	Wrappers     []WrapperSummary      `json:"wrappers,omitempty"`
}

// CallSite is one call in a patch-side file with its resolved declaration and
// arguments. It is the primitive a changed-span classifier consumes: a changed
// token is mapped to its enclosing call and the call's resolved operation
// decides whether the change is checked or remains a residual.
type CallSite struct {
	Line            int            `json:"line"`
	Col             int            `json:"col"`
	Func            string         `json:"func"`
	Identity        APIIdentity    `json:"identity,omitempty"`
	Local           bool           `json:"local,omitempty"`
	Resolved        bool           `json:"resolved"`
	Reason          string         `json:"reason,omitempty"`
	Args            []ResolvedExpr `json:"args,omitempty"`
	Operation       *Operation     `json:"operation,omitempty"`
	OperationReason string         `json:"operation_reason,omitempty"`
}

// DeclaredFunction is one function/method declaration of a patch-side file with
// its resolved identity and complete-body digest. A wrapper summary must state
// the same identity and digest for the package to accept it.
type DeclaredFunction struct {
	Identity    APIIdentity         `json:"identity"`
	Declaration DeclarationIdentity `json:"declaration"`
	BodyDigest  string              `json:"body_digest"`
	Line        int                 `json:"line"`
}

// FileAnalysis is the resolved identity view of one complete patch-side file.
type FileAnalysis struct {
	Path         string             `json:"path"`
	Image        Image              `json:"image"`
	Digest       string             `json:"digest"`
	Calls        []CallSite         `json:"calls,omitempty"`
	Declarations []DeclaredFunction `json:"declarations,omitempty"`
}

// AnalyzeFile resolves every call and declaration of one complete patch-side
// file. The source must be the patch-side image (pre- or post-image); a caller
// holding only the selected implementation must not call this to qualify a
// patch.
func AnalyzeFile(file string, src []byte, opts AnalyzeOptions) (*FileAnalysis, error) {
	if opts.Image == "" {
		opts.Image = ImageAfter
	}
	bundle := &SourceBundle{
		Module:       opts.Module,
		Toolchain:    opts.Toolchain,
		Files:        map[string]FileSource{},
		PackagePaths: opts.PackagePaths,
		ImportOwners: opts.ImportOwners,
		Wrappers:     opts.Wrappers,
	}
	own := bundle.Files[file]
	if opts.Image == ImageBefore {
		own.Before = src
	} else {
		own.After = src
	}
	bundle.Files[file] = own
	for p, f := range opts.PackageFiles {
		if _, ok := bundle.Files[p]; !ok {
			bundle.Files[p] = f
		}
	}
	a := newAnalyzer(bundle)
	v, err := a.view(file, opts.Image)
	if err != nil {
		return nil, err
	}
	a.ensurePackage(v)
	out := &FileAnalysis{Path: file, Image: opts.Image, Digest: v.Digest}
	for _, decl := range v.File.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		body, _ := bodyDigest(v, fd)
		out.Declarations = append(out.Declarations, DeclaredFunction{
			Identity:    v.localFunctionIdentity(fd),
			Declaration: v.declaration(fd),
			BodyDigest:  body,
			Line:        v.Fset.Position(fd.Pos()).Line,
		})
	}
	ast.Inspect(v.File, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		site := CallSite{
			Line: v.Fset.Position(call.Pos()).Line,
			Col:  v.Fset.Position(call.Pos()).Column,
			Func: sourceText(v, call.Fun),
		}
		res := a.resolveCall(v, call)
		site.Identity = res.Identity
		site.Local = res.Local
		site.Resolved = res.Resolved
		site.Reason = res.Reason
		for _, arg := range call.Args {
			site.Args = append(site.Args, a.resolveExpr(v, arg, 0))
		}
		if op, reason := a.classifyOperation(v, call); reason == "" {
			site.Operation = &op
		} else {
			site.OperationReason = reason
		}
		out.Calls = append(out.Calls, site)
		return true
	})
	sort.SliceStable(out.Calls, func(i, j int) bool {
		if out.Calls[i].Line != out.Calls[j].Line {
			return out.Calls[i].Line < out.Calls[j].Line
		}
		return out.Calls[i].Col < out.Calls[j].Col
	})
	return out, nil
}

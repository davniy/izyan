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

// This file is the selected-implementation census: the candidate space an
// absence proof must enumerate before it may conclude anything. It answers one
// question — "which operations on which resources does this implementation
// contain, and which uses could not be established?" — and it answers it
// conservatively.
//
// The census is deliberately not a points-to solver. It propagates a finite
// may-set through the derivations a source file actually states (declarations,
// ordinary assignments, aliases, branch joins and checked wrapper forwards),
// and it turns every derivation it cannot follow into a blocking obligation.
// That is the whole contract: a use disappears from the census only when the
// checker proved its role harmless. An unproven use is an obligation, never a
// read.

// CensusBoundary states exactly what a complete census covers.
const CensusBoundary = "non-test Go files under the anchored module root, excluding testdata and vendor subtrees"

// CensusObligationKind names why one resource fact could not be established.
// Every kind blocks: none of them is a discarded observation.
type CensusObligationKind string

const (
	// ObligationUnresolvedResource: a recognised operation's resource operand
	// could not be resolved to an identity.
	ObligationUnresolvedResource CensusObligationKind = "UNRESOLVED_RESOURCE"
	// ObligationUnresolvedMode: a recognised operation's permission value is
	// not a comparable literal.
	ObligationUnresolvedMode CensusObligationKind = "UNRESOLVED_MODE"
	// ObligationUnknownCall: a value derived from an input reaches a call the
	// checker cannot prove harmless.
	ObligationUnknownCall CensusObligationKind = "UNKNOWN_CALL"
	// ObligationReturn: a value derived from an input leaves through a return.
	ObligationReturn CensusObligationKind = "RETURN_ESCAPE"
	// ObligationChannel: a value derived from an input leaves through a channel.
	ObligationChannel CensusObligationKind = "CHANNEL_ESCAPE"
	// ObligationClosure: a closure captures a value derived from an input.
	ObligationClosure CensusObligationKind = "CLOSURE_CAPTURE"
	// ObligationPointerMutation: a value derived from an input is written
	// through a pointer or a field, so its identity at later uses is unknown.
	ObligationPointerMutation CensusObligationKind = "POINTER_MUTATION"
	// ObligationStructure: a value derived from an input is stored in a data
	// structure the census cannot track.
	ObligationStructure CensusObligationKind = "UNSUPPORTED_STRUCTURE"
	// ObligationDispatch: a value derived from an input crosses an interface
	// boundary, so the implementation that acts on it is not established.
	ObligationDispatch CensusObligationKind = "INTERFACE_DISPATCH"
	// ObligationParse: a file of the anchored source could not be parsed.
	ObligationParse CensusObligationKind = "PARSE"
	// ObligationEntry: an exported declaration is a direct entry point, so a
	// resource it acts on may be supplied by a caller this scan does not see.
	// It is a reachability obligation, not a discovery gap: the declaration's
	// own operations are enumerated like any other's. A closed-boundary
	// analysis accounts for every exported declaration in the boundary and may
	// therefore discharge this kind; nothing else may.
	ObligationEntry CensusObligationKind = "EXPORTED_ENTRY"
)

// CensusObligation is one blocking fact. It carries no authority of its own;
// it is the reason a result is not complete.
type CensusObligation struct {
	Kind        CensusObligationKind `json:"kind"`
	File        string               `json:"file"`
	Line        int                  `json:"line,omitempty"`
	Declaration DeclarationIdentity  `json:"declaration,omitempty"`
	// ResourceKey is the instance-independent identity of the affected
	// resource when the checker could establish one. An empty key means the
	// obligation could concern any resource, so it blocks every subject set.
	ResourceKey string `json:"resource_key,omitempty"`
	Detail      string `json:"detail"`
}

// CensusOperation is one enumerated operation site over a resource identity.
type CensusOperation struct {
	File        string              `json:"file"`
	Package     string              `json:"package"`
	Declaration DeclarationIdentity `json:"declaration"`
	// Entry reports that the operation is reachable from an exported
	// direct-entry declaration whose resource value is supplied by its caller.
	Entry bool `json:"entry"`
	// Aliases are the local binding witnesses the resource derivation passed
	// through, so a cover can show the alias chain instead of a flat fact.
	Aliases   []Witness `json:"aliases,omitempty"`
	Operation Operation `json:"operation"`
	// Key is the instance-independent resource identity this operation acts on.
	Key string `json:"key"`
}

// SubjectSet is the enumerated candidate space for one resource key.
type SubjectSet struct {
	Key string `json:"key"`
	// Subjects is every operation the census found on this key.
	Subjects []CensusOperation `json:"subjects,omitempty"`
	// Blocking is every obligation that could hide a further subject.
	Blocking []CensusObligation `json:"blocking,omitempty"`
	// Complete reports that no blocking obligation can hide a subject on this
	// key and that at least one subject was enumerated.
	Complete bool   `json:"complete"`
	Reason   string `json:"reason,omitempty"`
}

// Census is the measured candidate space of one selected implementation.
type Census struct {
	Module    string `json:"module"`
	Version   string `json:"version,omitempty"`
	Kind      string `json:"source_kind,omitempty"`
	SourceRef string `json:"source_ref,omitempty"`
	Boundary  string `json:"boundary"`
	Files     int    `json:"files"`
	Digest    string `json:"digest,omitempty"`
	// PackagePaths are the module-relative directories that carry Go files.
	PackagePaths []string `json:"package_paths,omitempty"`

	Operations  []CensusOperation  `json:"operations,omitempty"`
	Obligations []CensusObligation `json:"obligations,omitempty"`
	Wrappers    []WrapperSummary   `json:"wrappers,omitempty"`
	// Registrations are the registration constructions the scan recognised and
	// accounted for. They are recorded only when the scan was asked to analyse
	// registrations, and they are discovery facts: a later checker decides
	// whether the identity, the initializer and the construction are closed.
	Registrations []CensusRegistration `json:"registrations,omitempty"`
	// Closures are the function literals whose bodies the scan walked with
	// their own parameter bindings. A literal absent from this list inside a
	// scanned declaration is unaccounted, never implicitly harmless.
	Closures []CensusClosure `json:"closures,omitempty"`

	Parse    AspectResult `json:"parse"`
	Analysis AspectResult `json:"analysis"`
	Cover    AspectResult `json:"cover"`

	// walkClosures and registrations are the analysis switches this census was
	// measured under. They are not persisted: their effects are observable in
	// Closures, Registrations and Obligations.
	walkClosures  bool
	registrations bool
}

// Registration initializer shapes. A registration whose initializer is neither
// a literal nor a resolvable declaration is unresolved by construction.
const (
	InitLiteral    = "literal"
	InitNamed      = "named"
	InitUnresolved = "unresolved"
)

// CensusRegistration is one registration construction: the identity it
// declares, the initializer field and the function the initializer names (when
// it names one). IdentityResolved is false for a dynamically computed identity,
// which no closed-boundary proof may accept.
type CensusRegistration struct {
	File        string              `json:"file"`
	Line        int                 `json:"line"`
	Package     string              `json:"package"`
	Declaration DeclarationIdentity `json:"declaration"`
	// Identity is the registration's declared identity string.
	Identity string `json:"identity,omitempty"`
	// IdentityResolved reports that the identity is a literal or a resolvable
	// constant, not a runtime value.
	IdentityResolved bool `json:"identity_resolved"`
	// InitKind is InitLiteral, InitNamed or InitUnresolved.
	InitKind string `json:"init_kind"`
	// InitField is the composite-literal field the initializer was read from.
	InitField string `json:"init_field,omitempty"`
	// InitName is the named initializer's function name, and InitPackage its
	// import path when the name is package-qualified.
	InitName    string `json:"init_name,omitempty"`
	InitPackage string `json:"init_package,omitempty"`
	// InitFile and InitLine locate a named initializer declared in the scanned
	// source, when the declaration was found.
	InitFile string `json:"init_file,omitempty"`
	InitLine int    `json:"init_line,omitempty"`
}

// CensusClosure is one function literal whose body the scan walked with its own
// parameter bindings.
type CensusClosure struct {
	File        string              `json:"file"`
	Line        int                 `json:"line"`
	Declaration DeclarationIdentity `json:"declaration"`
}

// CensusOptions configures one selected-source census. Files is the captured
// source of the whole anchored implementation; a caller holding only a vendored
// subset must not pass it as the whole module.
//
// WalkClosures and Registrations are closed-boundary analysis switches. They
// exist because a non-counterpart proof must account for inline initializer
// closures and registration constructions instead of blocking on their mere
// presence; the default census (both false) keeps the conservative contract:
// an unanalysed closure or registration is a blocking obligation.
type CensusOptions struct {
	Module ModuleIdentity
	// ImportPath is the declared import namespace when a replacement changes
	// Module.Path (the effective source owner).
	ImportPath   string
	Files        map[string][]byte
	ImportOwners map[string]string
	Boundary     string
	// WalkClosures analyses function-literal bodies with their own parameter
	// bindings instead of recording an unanalysed capture.
	WalkClosures bool
	// Registrations recognises registration constructions and evaluates their
	// non-initializer arguments, instead of treating the registration call as
	// an unknown call.
	Registrations bool
}

// CensusSource scans one captured selected implementation.
func CensusSource(opts CensusOptions) (*Census, error) {
	if len(opts.Files) == 0 {
		return nil, fmt.Errorf("census: no source files were supplied")
	}
	boundary := opts.Boundary
	if boundary == "" {
		boundary = CensusBoundary
	}
	c := &Census{
		Module:    opts.Module.Path,
		Version:   opts.Module.Version,
		Kind:      opts.Module.Kind,
		SourceRef: opts.Module.SourceRef(),
		Boundary:  boundary,
		Parse:     AspectResult{Aspect: AspectParse},
		Analysis:  AspectResult{Aspect: AspectAnalysis},
		Cover:     AspectResult{Aspect: AspectCover},

		walkClosures:  opts.WalkClosures,
		registrations: opts.Registrations,
	}

	names := make([]string, 0, len(opts.Files))
	for name := range opts.Files {
		names = append(names, name)
	}
	sort.Strings(names)

	bundle := &SourceBundle{
		Module:       opts.Module,
		Files:        make(map[string]FileSource, len(names)),
		ImportOwners: opts.ImportOwners,
	}
	if opts.ImportPath != "" && opts.ImportPath != opts.Module.Path {
		bundle.PackagePaths = map[string]string{}
		for _, name := range names {
			dir := dirOf(name)
			pkg := opts.ImportPath
			if dir != "" {
				pkg += "/" + dir
			}
			bundle.PackagePaths[dir] = pkg
		}
	}
	for _, name := range names {
		bundle.Files[name] = FileSource{Selected: opts.Files[name]}
	}
	a := newAnalyzer(bundle)

	var digests []string
	var goFiles []string
	pkgDirs := map[string]bool{}
	for _, name := range names {
		raw := opts.Files[name]
		sum := sha256.Sum256(raw)
		digests = append(digests, name+"\x00"+hex.EncodeToString(sum[:]))
		if detail := unsupportedSourceMaterial(name, raw); detail != "" {
			c.Obligations = append(c.Obligations, CensusObligation{Kind: ObligationStructure, File: name, Detail: detail})
		}
		if !isCensusGoFile(name) {
			continue
		}
		goFiles = append(goFiles, name)
		pkgDirs[dirOf(name)] = true
		c.Files++
		if _, err := a.view(name, ImageSelected); err != nil {
			c.Parse.fail(CodeParseFile, "%s: %v", name, err)
			c.Obligations = append(c.Obligations, CensusObligation{
				Kind:   ObligationParse,
				File:   name,
				Detail: err.Error(),
			})
		}
	}
	for dir := range pkgDirs {
		c.PackagePaths = append(c.PackagePaths, dir)
	}
	sort.Strings(c.PackagePaths)
	sort.Strings(digests)
	total := sha256.Sum256([]byte(strings.Join(digests, "\n")))
	c.Digest = "sha256:" + hex.EncodeToString(total[:])
	if c.Files == 0 {
		c.Parse.fail(CodeParseFile, "the anchored source carries no non-test Go file")
	}

	// Pass 1: derive the checked forwarding summaries of repository-local
	// wrappers. A wrapper's name establishes nothing, so the summary is derived
	// from its own body and re-verified at every call site by body digest.
	wrappers := deriveWrappers(a, goFiles)
	bundle.Wrappers = wrappers
	c.Wrappers = wrappers

	// Pass 2: walk every declaration of every parsed file.
	for _, name := range goFiles {
		v, err := a.view(name, ImageSelected)
		if err != nil {
			continue
		}
		a.ensurePackage(v)
		for _, decl := range v.File.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok {
				if gd, yes := decl.(*ast.GenDecl); yes && (gd.Tok == token.VAR || gd.Tok == token.CONST) {
					c.Obligations = append(c.Obligations, CensusObligation{Kind: ObligationStructure, File: name, Detail: "package initializer requires checked construction analysis"})
				}
				continue
			}
			if fd.Body == nil {
				c.Obligations = append(c.Obligations, CensusObligation{Kind: ObligationUnknownCall, File: name, Detail: "bodyless function requires implementation evidence"})
				continue
			}
			newCensusScan(c, a, v, fd).run()
		}
	}

	sort.SliceStable(c.Operations, func(i, j int) bool {
		if c.Operations[i].File != c.Operations[j].File {
			return c.Operations[i].File < c.Operations[j].File
		}
		return c.Operations[i].Operation.Line < c.Operations[j].Operation.Line
	})

	checkCensusTypes(c, opts.Files, goFiles)
	c.Analysis.Complete = len(c.Obligations) == 0
	if !c.Analysis.Complete {
		for _, ob := range c.Obligations {
			c.Analysis.Blocking = appendUnique(c.Analysis.Blocking, string(ob.Kind))
		}
		c.Analysis.Reason = fmt.Sprintf("%d use(s) of a resource derivation could not be established", len(c.Obligations))
	}
	// A census enumerates candidates, not a necessary disjunction. Task 6 must
	// establish necessity independently; success here cannot certify a cover.
	c.Cover.fail("NECESSITY_NOT_CHECKED", "this census does not establish a necessary cover")
	return c, nil
}

// Subjects returns the enumerated subject set for one resource key.
func (c *Census) Subjects(key string) SubjectSet {
	ss := SubjectSet{Key: key}
	if c == nil {
		ss.Reason = "no census was measured"
		return ss
	}
	for _, op := range c.Operations {
		if op.Key == key {
			ss.Subjects = append(ss.Subjects, op)
		}
	}
	for _, ob := range c.Obligations {
		if ob.ResourceKey == "" || ob.ResourceKey == key {
			ss.Blocking = append(ss.Blocking, ob)
		}
	}
	ss.Complete = false
	ss.Reason = "candidate enumeration does not establish a necessary cover"
	return ss
}

// Keys lists the resource keys the census enumerated, sorted.
func (c *Census) Keys() []string {
	if c == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, op := range c.Operations {
		if op.Key == "" || seen[op.Key] {
			continue
		}
		seen[op.Key] = true
		out = append(out, op.Key)
	}
	sort.Strings(out)
	return out
}

// ResourceKey is the instance-independent identity of a resource derivation:
// the source-owned declared type of the base value plus the complete field and
// derivation chain. Two operations on the same configuration field share a key
// whatever instance and function they appear in; two same-named fields owned by
// different packages do not. The abstraction is deliberately over-inclusive —
// a cover that carries an extra candidate is sound, one that drops a candidate
// is not.
func ResourceKey(e *ExprIdentity) (string, bool) {
	if e == nil || !e.Resolved() {
		return "", false
	}
	switch e.Kind {
	case ExprValue:
		if e.Value == nil || e.Value.Type == "" {
			return "", false
		}
		return "value:" + e.Value.Source + ":" + e.Value.Type, true
	case ExprLiteral:
		return "literal:" + e.Literal, true
	case ExprPackage:
		if e.Package == nil {
			return "", false
		}
		return "package:" + e.Package.ImportPath, true
	case ExprSelector:
		if e.Selector == nil || e.Selector.Owner == "" {
			return "", false
		}
		base, ok := ResourceKey(e.Selector.X)
		if !ok {
			return "", false
		}
		return base + "." + e.Selector.Owner + "#" + e.Selector.Name, true
	case ExprCall:
		if e.Call == nil {
			return "", false
		}
		args := make([]string, 0, len(e.Call.Args))
		for _, arg := range e.Call.Args {
			key, ok := ResourceKey(arg)
			if !ok {
				return "", false
			}
			args = append(args, key)
		}
		return "call:" + e.Call.Function.String() + "(" + strings.Join(args, ",") + ")", true
	case ExprIndex:
		if e.Index == nil {
			return "", false
		}
		base, ok := ResourceKey(e.Index.X)
		if !ok {
			return "", false
		}
		index, ok := ResourceKey(e.Index.Index)
		if !ok {
			return "", false
		}
		return base + "[" + index + "]", true
	case ExprUnary:
		if e.Unary == nil {
			return "", false
		}
		base, ok := ResourceKey(e.Unary.X)
		if !ok {
			return "", false
		}
		return "unary" + e.Unary.Op + base, true
	case ExprBinary:
		if e.Binary == nil {
			return "", false
		}
		left, ok := ResourceKey(e.Binary.X)
		if !ok {
			return "", false
		}
		right, ok := ResourceKey(e.Binary.Y)
		if !ok {
			return "", false
		}
		return "binary" + e.Binary.Op + "(" + left + "," + right + ")", true
	}
	return "", false
}

// isCensusGoFile reports whether a captured file belongs in the census. Test
// files state nothing about the shipped implementation, and testdata/vendor
// subtrees are other modules' evidence.
func isCensusGoFile(name string) bool {
	if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		switch part {
		case "testdata", "vendor":
			return false
		}
	}
	return true
}

// censusScan walks one function declaration, propagating the may-set of every
// binding it can establish and recording a blocking obligation for every use it
// cannot prove harmless.
type censusScan struct {
	c  *Census
	a  *analyzer
	v  *fileView
	fn *ast.FuncDecl
	// declID is the parser-side declaration identity (file + declaration
	// string). Function literals derive their own identity from it, matching
	// the identity indexBody assigned to their parameters.
	declID string
	decl   DeclarationIdentity
	entry  bool
	bind   map[*ast.Object]*evalResult
}

// evalResult is the conservative may-set of one expression. An empty set with
// no unknown value means the expression carries no tracked resource (an
// operation's error value, a discarded literal). A non-empty unknown means the
// checker could not establish the value at all.
type evalResult struct {
	set     []*ExprIdentity
	unknown string
}

const maxMaySet = 8

// carriesInput reports whether any member of the may-set depends on a declared
// value, and so could name a resource the implementation acts on.
func (r evalResult) carriesInput() bool {
	for _, id := range r.set {
		if carriesInput(id) {
			return true
		}
	}
	return false
}

// carriesInput reports whether an identity derivation depends on a declared
// value — a parameter, receiver, result, package-level value or local — rather
// than only on literals and package declarations.
func carriesInput(e *ExprIdentity) bool {
	if e == nil {
		return false
	}
	switch e.Kind {
	case ExprValue:
		return e.Value != nil && e.Value.Type != ""
	case ExprSelector:
		return e.Selector != nil && carriesInput(e.Selector.X)
	case ExprCall:
		if e.Call == nil {
			return false
		}
		for _, arg := range e.Call.Args {
			if carriesInput(arg) {
				return true
			}
		}
		return false
	case ExprIndex:
		return e.Index != nil && (carriesInput(e.Index.X) || carriesInput(e.Index.Index))
	case ExprUnary:
		return e.Unary != nil && carriesInput(e.Unary.X)
	case ExprBinary:
		return e.Binary != nil && (carriesInput(e.Binary.X) || carriesInput(e.Binary.Y))
	}
	return false
}

func newCensusScan(c *Census, a *analyzer, v *fileView, fn *ast.FuncDecl) *censusScan {
	s := &censusScan{c: c, a: a, v: v, fn: fn, declID: functionDeclID(v.Path, fn),
		decl: v.declaration(fn), bind: map[*ast.Object]*evalResult{}}
	s.entry = isEntryDeclaration(fn)
	// Seed the bindings with the declared parameters, receiver and results so a
	// field selection on an input value resolves to the declared type that owns
	// the field. The declaration identity is the parser's own, so a seeded value
	// compares equal to the same value resolved from an expression.
	s.seedFields(fn.Recv)
	s.seedFields(fn.Type.Params)
	s.seedFields(fn.Type.Results)
	return s
}

// seedFields binds the named parameters/receiver/results of one field list to
// the declared values the parser indexed. The same rule serves a function
// literal: its own parameters are indexed under its literal declaration id.
func (s *censusScan) seedFields(list *ast.FieldList) {
	if list == nil {
		return
	}
	for _, field := range list.List {
		for _, name := range field.Names {
			if name.Obj == nil {
				continue
			}
			decl, ok := s.v.Values[name.Obj]
			if !ok {
				continue
			}
			s.bind[name.Obj] = &evalResult{set: []*ExprIdentity{{Kind: ExprValue, Value: &ValueIdentity{
				Source:      s.v.packageSource(),
				PackagePath: s.v.PackagePath,
				Type:        s.v.canonicalType(field.Type),
				Decl:        decl.Decl,
				Origin:      decl.Origin,
				Ordinal:     decl.Ordinal,
				Name:        decl.Name,
			}}}}
		}
	}
}

// isEntryDeclaration conservatively treats every exported declaration as a
// direct entry, including primitive parameters and constructors. A whole-module
// caller/construction summary is needed before any such edge is harmless.
func isEntryDeclaration(fn *ast.FuncDecl) bool {
	return fn.Name != nil && ast.IsExported(fn.Name.Name)
}

func (s *censusScan) run() {
	if s.fn.Body == nil {
		return
	}
	if s.entry {
		s.obligate(ObligationEntry, s.fn.Pos(), "", "exported direct-entry construction/relevance requires a checked entry summary")
	}
	s.walkStmts(s.fn.Body.List)
}

func (s *censusScan) walkStmts(list []ast.Stmt) {
	for _, st := range list {
		s.walkStmt(st)
	}
}

func (s *censusScan) walkStmt(st ast.Stmt) {
	switch n := st.(type) {
	case nil:
		return
	case *ast.BlockStmt:
		s.walkStmts(n.List)
	case *ast.IfStmt:
		s.walkStmt(n.Init)
		s.readOnly(n.Cond)
		pre := s.snapshot()
		s.walkStmts(n.Body.List)
		after := s.snapshot()
		s.restore(pre)
		s.walkStmt(n.Else)
		elseState := s.snapshot()
		s.join(pre, after, elseState)
	case *ast.ForStmt:
		s.obligate(ObligationStructure, n.Pos(), "", "loop-carried propagation requires a checked fixed point")
		s.walkStmt(n.Init)
		s.readOnly(n.Cond)
		pre := s.snapshot()
		s.walkStmts(n.Body.List)
		s.walkStmt(n.Post)
		s.join(pre, s.snapshot())
	case *ast.RangeStmt:
		s.obligate(ObligationStructure, n.Pos(), "", "range data structure and loop-carried propagation require a checked summary")
		s.readOnly(n.X)
		pre := s.snapshot()
		s.walkStmts(n.Body.List)
		s.join(pre, s.snapshot())
	case *ast.SwitchStmt:
		s.walkStmt(n.Init)
		s.readOnly(n.Tag)
		states := []map[*ast.Object]*evalResult{s.snapshot()}
		for _, clause := range n.Body.List {
			cc, ok := clause.(*ast.CaseClause)
			if !ok {
				continue
			}
			s.restore(states[0])
			for _, e := range cc.List {
				s.readOnly(e)
			}
			s.walkStmts(cc.Body)
			states = append(states, s.snapshot())
		}
		s.restore(states[0])
		s.join(states...)
	case *ast.TypeSwitchStmt:
		s.walkStmt(n.Init)
		s.walkStmt(n.Assign)
		states := []map[*ast.Object]*evalResult{s.snapshot()}
		for _, clause := range n.Body.List {
			cc, ok := clause.(*ast.CaseClause)
			if !ok {
				continue
			}
			s.restore(states[0])
			s.walkStmts(cc.Body)
			states = append(states, s.snapshot())
		}
		s.restore(states[0])
		s.join(states...)
	case *ast.SelectStmt:
		states := []map[*ast.Object]*evalResult{s.snapshot()}
		for _, clause := range n.Body.List {
			cc, ok := clause.(*ast.CommClause)
			if !ok {
				continue
			}
			s.restore(states[0])
			s.walkStmt(cc.Comm)
			s.walkStmts(cc.Body)
			states = append(states, s.snapshot())
		}
		s.restore(states[0])
		s.join(states...)
	case *ast.CaseClause:
		s.walkStmts(n.Body)
	case *ast.CommClause:
		s.walkStmt(n.Comm)
		s.walkStmts(n.Body)
	case *ast.LabeledStmt:
		s.walkStmt(n.Stmt)
	case *ast.AssignStmt:
		s.walkAssign(n)
	case *ast.ExprStmt:
		s.evalDiscarded(n.X)
	case *ast.ReturnStmt:
		if len(n.Results) == 0 && s.fn.Type.Results != nil {
			s.obligate(ObligationReturn, n.Pos(), "", "named result propagation requires a checked return summary")
		}
		if _, checked := returnParameter(s.fn); checked && !s.entry {
			return
		}
		for _, e := range n.Results {
			res := s.eval(e)
			if res.carriesInput() {
				s.obligate(ObligationReturn, n.Pos(), s.keyOf(res),
					"a value derived from an input leaves this declaration through a return, so the caller receives an unenumerated resource")
			}
		}
	case *ast.DeclStmt:
		s.walkDecl(n)
	case *ast.GoStmt:
		s.evalDiscarded(n.Call)
	case *ast.DeferStmt:
		s.evalDiscarded(n.Call)
	case *ast.SendStmt:
		s.readOnly(n.Chan)
		res := s.eval(n.Value)
		if res.carriesInput() {
			s.obligate(ObligationChannel, n.Pos(), s.keyOf(res),
				"a value derived from an input leaves this declaration through a channel")
		}
	case *ast.IncDecStmt:
		s.obligate(ObligationPointerMutation, n.Pos(), "", "increment/decrement requires checked mutation analysis")
		s.readOnly(n.X)
	case *ast.EmptyStmt:
		return
	default:
		s.obligate(ObligationStructure, st.Pos(), "", fmt.Sprintf("statement form %T requires checked control/data flow", st))
	}
}

// walkDecl records a `var` declaration. A declared value is bound to its
// initialiser; without one the declaration still establishes the value's type.
func (s *censusScan) walkDecl(n *ast.DeclStmt) {
	gd, ok := n.Decl.(*ast.GenDecl)
	if !ok {
		return
	}
	for _, spec := range gd.Specs {
		vs, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		if isInterfaceExpr(s.v, vs.Type) {
			for _, value := range vs.Values {
				res := s.eval(value)
				if res.carriesInput() {
					s.obligate(ObligationDispatch, value.Pos(), s.keyOf(res),
						"a resource derivation is stored behind an interface type, so the implementation that acts on it is not established")
				}
			}
			continue
		}
		if len(vs.Values) == 0 {
			for _, name := range vs.Names {
				if name.Obj == nil {
					continue
				}
				s.bind[name.Obj] = s.valueOf(name, vs.Type)
			}
			continue
		}
		values := s.evalList(vs.Values)
		for i, name := range vs.Names {
			if name.Obj == nil {
				continue
			}
			if len(vs.Values) == len(vs.Names) && i < len(values) {
				bound := values[i]
				s.bind[name.Obj] = &bound
				continue
			}
			s.bind[name.Obj] = &evalResult{unknown: "the value is supplied by a multiple-result expression whose components are not established"}
		}
	}
}

// valueOf builds the resolved value identity of a declared identifier.
func (s *censusScan) valueOf(name *ast.Ident, typ ast.Expr) *evalResult {
	decl, ok := s.v.Values[name.Obj]
	if !ok {
		return &evalResult{unknown: fmt.Sprintf("the declaration of %q is not provided", name.Name)}
	}
	declared := s.v.canonicalType(typ)
	if declared == "" {
		declared = s.v.canonicalType(decl.Type)
	}
	if declared == "" {
		return &evalResult{unknown: fmt.Sprintf("the declared type of %q is not established", name.Name)}
	}
	return &evalResult{set: []*ExprIdentity{{Kind: ExprValue, Value: &ValueIdentity{
		Source:      s.v.packageSource(),
		PackagePath: s.v.PackagePath,
		Type:        declared,
		Decl:        decl.Decl,
		Origin:      decl.Origin,
		Ordinal:     decl.Ordinal,
		Name:        decl.Name,
	}}}}
}

// walkAssign propagates a declared or assigned value and records a blocking
// obligation for every store the census cannot follow.
func (s *censusScan) walkAssign(st *ast.AssignStmt) {
	values := s.evalList(st.Rhs)
	for i, lhs := range st.Lhs {
		if st.Tok != token.DEFINE && st.Tok != token.ASSIGN {
			s.obligate(ObligationPointerMutation, st.Pos(), "", "compound assignment requires a checked derivation")
		}
		switch target := lhs.(type) {
		case *ast.Ident:
			s.assignIdent(target, values, i, len(st.Lhs))
		case *ast.SelectorExpr:
			base := s.eval(target.X)
			if base.carriesInput() || resCarries(values) {
				s.obligate(ObligationPointerMutation, lhs.Pos(), s.keyOf(base),
					"a resource derivation is written through a field, so later uses of that field are not established")
			}
		case *ast.StarExpr:
			base := s.eval(target.X)
			if base.carriesInput() {
				s.obligate(ObligationPointerMutation, lhs.Pos(), s.keyOf(base),
					"a resource derivation is written through a pointer, so later uses of that value are not established")
			}
		case *ast.IndexExpr:
			base := s.eval(target.X)
			if base.carriesInput() || resCarries(values) {
				s.obligate(ObligationStructure, lhs.Pos(), s.keyOf(base),
					"a resource derivation is stored in an indexed value the census cannot track")
			}
		}
	}
	if isInterfaceAssign(s.v, st) {
		for _, value := range values {
			if value.carriesInput() {
				s.obligate(ObligationDispatch, st.Pos(), s.keyOf(value),
					"a resource derivation is assigned to an interface-typed destination")
			}
		}
	}
}

// assignIdent binds one assigned identifier. A multi-value assignment whose
// components are not established leaves the binding unknown; it is never
// silently dropped.
func (s *censusScan) assignIdent(id *ast.Ident, values []evalResult, index, lhsCount int) {
	if id.Obj == nil || id.Name == "_" {
		if id.Obj == nil && id.Name != "_" {
			s.obligate(ObligationPointerMutation, id.Pos(), "", "assignment destination is outside the checked local scope")
		}
		return
	}
	if lhsCount == 1 && len(values) == 1 {
		bound := values[0]
		s.bind[id.Obj] = &bound
		return
	}
	if lhsCount == len(values) && index < len(values) {
		bound := values[index]
		s.bind[id.Obj] = &bound
		return
	}
	s.bind[id.Obj] = &evalResult{unknown: "the value is supplied by a multiple-result expression whose components are not established"}
	s.obligate(ObligationStructure, id.Pos(), "", "multiple-result binding has no checked component summary")
}

// evalList evaluates every right-hand expression. An empty list still yields
// one empty result so callers never index past it.
func (s *censusScan) evalList(list []ast.Expr) []evalResult {
	out := make([]evalResult, 0, len(list))
	for _, e := range list {
		out = append(out, s.eval(e))
	}
	if len(out) == 0 {
		out = append(out, evalResult{})
	}
	return out
}

func resCarries(values []evalResult) bool {
	for _, v := range values {
		if v.carriesInput() {
			return true
		}
	}
	return false
}

func (s *censusScan) snapshot() map[*ast.Object]*evalResult {
	out := make(map[*ast.Object]*evalResult, len(s.bind))
	for k, v := range s.bind {
		out[k] = cloneEval(v)
	}
	return out
}

func (s *censusScan) restore(state map[*ast.Object]*evalResult) {
	s.bind = make(map[*ast.Object]*evalResult, len(state))
	for k, v := range state {
		s.bind[k] = cloneEval(v)
	}
}

func cloneEval(v *evalResult) *evalResult {
	cp := *v
	cp.set = append([]*ExprIdentity(nil), v.set...)
	return &cp
}

// join merges the may-sets of every branch that can reach the same point. A
// value that differs between branches keeps every possibility; when the merged
// set exceeds the supported size the binding becomes unknown, which is an
// obligation rather than a narrower guess.
func (s *censusScan) join(states ...map[*ast.Object]*evalResult) {
	merged := map[*ast.Object]*evalResult{}
	for _, state := range states {
		for obj, res := range state {
			cur, ok := merged[obj]
			if !ok {
				merged[obj] = cloneEval(res)
				continue
			}
			if res.unknown != "" {
				cur.unknown = res.unknown
			}
			for _, id := range res.set {
				if !containsIdentity(cur.set, id) {
					cur.set = append(cur.set, id)
				}
			}
			if len(cur.set) > maxMaySet {
				cur.unknown = fmt.Sprintf("the value carries more than %d possible derivations", maxMaySet)
				cur.set = nil
				s.obligate(ObligationUnresolvedResource, s.fn.Pos(), "", "branch join exceeds supported finite may-set")
			}
		}
	}
	s.bind = merged
}

func containsIdentity(list []*ExprIdentity, id *ExprIdentity) bool {
	for _, item := range list {
		if item != nil && id != nil && item.Equal(id) {
			return true
		}
	}
	return false
}

// eval resolves one expression to its may-set.
func (s *censusScan) eval(e ast.Expr) evalResult {
	switch x := e.(type) {
	case nil:
		return evalResult{}
	case *ast.ParenExpr:
		return s.eval(x.X)
	case *ast.Ident:
		if x.Obj != nil {
			if bound, ok := s.bind[x.Obj]; ok {
				return *bound
			}
			if decl, ok := s.v.Values[x.Obj]; ok {
				if bound := s.valueOf(x, decl.Type); bound.unknown == "" {
					return *bound
				}
			}
		}
		return s.structural(e)
	case *ast.KeyValueExpr:
		return s.eval(x.Value)
	case *ast.SelectorExpr:
		return s.evalSelector(x)
	case *ast.CallExpr:
		return s.evalCall(x)
	case *ast.CompositeLit:
		for _, elt := range x.Elts {
			res := s.eval(elt)
			if res.carriesInput() {
				s.obligate(ObligationStructure, elt.Pos(), s.keyOf(res),
					"a resource derivation is stored in a composite literal the census cannot track")
			}
		}
		return s.structural(e)
	case *ast.FuncLit:
		s.checkClosure(x)
		return evalResult{}
	case *ast.TypeAssertExpr:
		res := s.eval(x.X)
		if res.carriesInput() {
			s.obligate(ObligationDispatch, x.Pos(), s.keyOf(res),
				"a resource derivation is asserted to an interface type, so the implementation acting on it is not established")
		}
		return evalResult{}
	case *ast.BinaryExpr:
		if isGuardOperator(x.Op) {
			s.readOnly(x.X)
			s.readOnly(x.Y)
			return evalResult{}
		}
		return s.product([]ast.Expr{x.X, x.Y}, func(items []*ExprIdentity) *ExprIdentity {
			return &ExprIdentity{Kind: ExprBinary, Binary: &BinaryIdentity{Op: x.Op.String(), X: items[0], Y: items[1]}}
		})
	case *ast.UnaryExpr:
		if x.Op == token.ARROW {
			return evalResult{}
		}
		return s.product([]ast.Expr{x.X}, func(items []*ExprIdentity) *ExprIdentity {
			return &ExprIdentity{Kind: ExprUnary, Unary: &UnaryIdentity{Op: x.Op.String(), X: items[0]}}
		})
	case *ast.IndexExpr:
		return s.product([]ast.Expr{x.X, x.Index}, func(items []*ExprIdentity) *ExprIdentity {
			return &ExprIdentity{Kind: ExprIndex, Index: &IndexIdentity{X: items[0], Index: items[1]}}
		})
	}
	return s.structural(e)
}

// product composes a structural derivation over the Cartesian product of its
// operand may-sets. The product is bounded; exceeding the bound is an
// obligation, never a truncated set that silently drops alternatives.
func (s *censusScan) product(operands []ast.Expr, build func(items []*ExprIdentity) *ExprIdentity) evalResult {
	sets := make([][]*ExprIdentity, len(operands))
	for i, op := range operands {
		res := s.eval(op)
		if res.unknown != "" {
			return evalResult{unknown: res.unknown}
		}
		if len(res.set) == 0 {
			// An operand that carries no tracked value makes the whole
			// derivation untracked rather than unresolved.
			return evalResult{}
		}
		sets[i] = res.set
	}
	combos := [][]*ExprIdentity{{}}
	for _, set := range sets {
		var next [][]*ExprIdentity
		for _, prefix := range combos {
			for _, id := range set {
				if len(next) >= maxMaySet {
					break
				}
				next = append(next, append(append([]*ExprIdentity(nil), prefix...), id))
			}
		}
		if len(next) == 0 || len(combos)*len(set) > maxMaySet {
			return evalResult{unknown: fmt.Sprintf("the derivation exceeds %d possible values", maxMaySet)}
		}
		combos = next
	}
	out := evalResult{}
	for _, combo := range combos {
		out.set = append(out.set, build(combo))
	}
	return out
}

// evalSelector resolves a field or method selection over the base's may-set.
func (s *censusScan) evalSelector(sel *ast.SelectorExpr) evalResult {
	if base, ok := sel.X.(*ast.Ident); ok && base.Obj == nil && isImportName(s.v, base.Name) {
		// A package-qualified declaration is not a value derivation.
		return s.structural(sel)
	}
	base := s.eval(sel.X)
	if base.unknown != "" {
		return evalResult{unknown: base.unknown}
	}
	out := evalResult{}
	for _, b := range base.set {
		owner := exprDeclaredType(b)
		if owner == "" {
			out.unknown = fmt.Sprintf("the declared type of the value %q is not established", sel.Sel.Name)
			continue
		}
		out.set = append(out.set, &ExprIdentity{Kind: ExprSelector, Selector: &SelectorIdentity{
			X:         b,
			Name:      sel.Sel.Name,
			Owner:     owner,
			FieldType: s.v.fieldType(owner, sel.Sel.Name),
		}})
	}
	if len(out.set) > maxMaySet {
		return evalResult{unknown: fmt.Sprintf("the value carries more than %d possible derivations", maxMaySet)}
	}
	return out
}

// evalCall classifies a call and returns the may-set of its result.
func (s *censusScan) evalCall(call *ast.CallExpr) evalResult {
	if s.c.registrations {
		if reg, ok := s.registrationFromCall(call); ok {
			// A recognised registration is accounted for: its identity and
			// initializer are recorded, and every other argument is still
			// evaluated so a resource derivation cannot hide behind it.
			s.recordRegistrationArgValues(call.Args)
			s.c.Registrations = append(s.c.Registrations, reg)
			return evalResult{}
		}
	}
	res := s.a.resolveCall(s.v, call)
	if returned, ok := s.returnedArgument(call, res); ok {
		return returned
	}
	previous := s.a.operandResolver
	s.a.operandResolver = func(v *fileView, expr ast.Expr) ResolvedExpr {
		r := s.eval(expr)
		if r.unknown != "" || len(r.set) == 0 {
			return ResolvedExpr{Identity: unknownExpr("flow-sensitive resource identity is unresolved: " + r.unknown)}
		}
		return ResolvedExpr{Text: sourceText(v, expr), Identity: r.set[0], Witnesses: []Witness{v.witness(expr.Pos(), expr.End(), s.decl.String())}}
	}
	op, resourceArg, reason := s.a.classifyOperationArgs(s.v, call)
	s.a.operandResolver = previous
	if reason == "" {
		s.recordOperation(call, op, resourceArg)
		// The operation's own return value (an error, a descriptor) is not a
		// resource derivation.
		return evalResult{}
	}
	if s.a.supportsDeclaration(res) {
		arg := s.supportedResourceArg(res)
		operand := ""
		if arg >= 0 && arg < len(call.Args) {
			operand = s.eval(call.Args[arg]).unknown
		}
		if arg < 0 || arg >= len(call.Args) || operand != "" || len(s.eval(call.Args[arg]).set) == 0 {
			s.obligate(ObligationUnresolvedResource, call.Pos(), "",
				fmt.Sprintf("the operation %s is recognised but its resource operand is not established: %s", res.Identity, reason))
			return evalResult{}
		}
		s.obligate(ObligationUnresolvedMode, call.Pos(), "",
			fmt.Sprintf("the operation %s is recognised but its checked value is not established: %s", res.Identity, reason))
		return evalResult{}
	}
	if isHarmlessConsumer(res.Identity) {
		return s.structuralCall(call, res.Identity)
	}
	s.escapeCall(call, res)
	return evalResult{}
}

// supportedResourceArg returns the call-argument index the recognised
// declaration's resource operand occupies, from the supported table or from the
// wrapper summary that made the declaration supported.
func (s *censusScan) supportedResourceArg(res callResolution) int {
	if !res.Resolved {
		return -1
	}
	if res.Local {
		if s.a.bundle == nil {
			return -1
		}
		for _, w := range s.a.bundle.Wrappers {
			if w.Function.Equal(res.Identity) && len(w.Forwards) == 1 {
				return w.Forwards[0].ResourceParam
			}
		}
		return -1
	}
	spec, ok := specFor(res.Identity)
	if !ok {
		return -1
	}
	return resourceArgIndex(spec)
}

// recordOperation records one operation per member of the resource argument's
// may-set. A multi-member set means the operation acts on one of several
// resources, so every member joins the candidate space.
func (s *censusScan) recordOperation(call *ast.CallExpr, op Operation, resourceArg int) {
	if resourceArg < 0 || resourceArg >= len(call.Args) {
		s.obligate(ObligationUnresolvedResource, call.Pos(), "",
			fmt.Sprintf("the operation %s has no resolvable resource argument index", op.Identity))
		return
	}
	res := s.eval(call.Args[resourceArg])
	if res.unknown != "" {
		s.obligate(ObligationUnresolvedResource, call.Pos(), "",
			fmt.Sprintf("the resource operand of %s is not established: %s", op.Identity, res.unknown))
		return
	}
	if len(res.set) == 0 {
		s.obligate(ObligationUnresolvedResource, call.Pos(), "",
			fmt.Sprintf("the resource operand of %s is not a tracked derivation", op.Identity))
		return
	}
	resolved := s.a.resolveExpr(s.v, call.Args[resourceArg], 0)
	for _, id := range res.set {
		key, ok := ResourceKey(id)
		if !ok {
			s.obligate(ObligationUnresolvedResource, call.Pos(), "",
				fmt.Sprintf("the resource operand of %s resolves to an identity with no key: %s", op.Identity, id.Missing()))
			continue
		}
		witnesses := []Witness(nil)
		if resolved.Resolved() && resolved.Identity.Equal(id) {
			witnesses = resolved.Witnesses
		}
		recorded := op
		recorded.Resource = ResourceIdentity{
			Expr:        ResolvedExpr{Text: sourceText(s.v, call.Args[resourceArg]), Identity: id, Witnesses: witnesses},
			Declaration: s.v.enclosingDeclaration(call.Pos()),
		}
		s.c.Operations = append(s.c.Operations, CensusOperation{
			File:        s.v.Path,
			Package:     s.v.PackagePath,
			Declaration: s.decl,
			Entry:       s.entry,
			Aliases:     witnesses,
			Operation:   recorded,
			Key:         key,
		})
	}
}

// escapeCall records the uses of an unresolvable call. A call the checker
// cannot prove harmless is a blocking obligation whenever an input reaches it;
// it never vanishes as a read.
func (s *censusScan) escapeCall(call *ast.CallExpr, res callResolution) {
	detail := "the call's declaration is not established"
	switch {
	case res.Resolved:
		detail = fmt.Sprintf("the call to %s is not a supported operation and is not proved harmless", res.Identity)
	case res.Reason != "":
		detail = res.Reason
	}
	key := ""
	for _, arg := range call.Args {
		s.eval(arg)
	}
	if sel, ok := unwrapGeneric(call.Fun).(*ast.SelectorExpr); ok {
		if base, isIdent := sel.X.(*ast.Ident); !isIdent || base.Obj != nil {
			s.eval(sel.X)
		}
	}
	// Unknown callees may obtain resources globally, even without arguments.
	s.obligate(ObligationUnknownCall, call.Pos(), key, detail)
}

// structuralCall composes a harmless consumer's result structurally so a later
// derivation keeps its provenance without being mistaken for an operation.
func (s *censusScan) structuralCall(call *ast.CallExpr, id APIIdentity) evalResult {
	sets := make([][]*ExprIdentity, len(call.Args))
	for i, arg := range call.Args {
		res := s.eval(arg)
		if res.unknown != "" {
			return evalResult{unknown: res.unknown}
		}
		if len(res.set) == 0 {
			return evalResult{}
		}
		sets[i] = res.set
	}
	combos := [][]*ExprIdentity{{}}
	for _, set := range sets {
		var next [][]*ExprIdentity
		for _, prefix := range combos {
			for _, item := range set {
				if len(next) >= maxMaySet {
					break
				}
				next = append(next, append(append([]*ExprIdentity(nil), prefix...), item))
			}
		}
		if len(next) == 0 || len(combos)*len(set) > maxMaySet {
			return evalResult{unknown: "the derivation exceeds the supported may-set size"}
		}
		combos = next
	}
	out := evalResult{}
	for _, combo := range combos {
		out.set = append(out.set, &ExprIdentity{Kind: ExprCall, Call: &CallIdentity{Function: id, Args: combo}})
	}
	return out
}

// checkClosure records the capture of a resource derivation by a function
// literal. By default the census does not walk into the literal's own body, so a
// capture is an unenumerated escape. A closed-boundary analysis asks for the
// body to be walked instead: the literal's own parameters are bound, the
// enclosing bindings stay visible as captures, and the operations the body
// performs are enumerated exactly like a declaration's.
func (s *censusScan) checkClosure(lit *ast.FuncLit) {
	if s.c.walkClosures && lit.Body != nil {
		s.walkClosureBody(lit)
		return
	}
	// Even a capture-free closure may perform global-resource operations;
	// unsupported closure bodies must not disappear from discovery.
	s.obligate(ObligationClosure, lit.Pos(), "", "function literal requires an independently checked body and invocation summary")
}

// walkClosureBody analyses one function literal. The literal's declaration
// identity matches the one indexBody assigned its parameters (owner + "@lit" +
// line), so its own bindings resolve without borrowing the enclosing
// declaration's.
func (s *censusScan) walkClosureBody(lit *ast.FuncLit) {
	line := s.v.Fset.Position(lit.Pos()).Line
	litID := fmt.Sprintf("%s@lit%d", s.declID, line)
	savedDecl, savedID, savedEntry := s.decl, s.declID, s.entry
	s.decl = DeclarationIdentity{Path: s.v.Path, Name: fmt.Sprintf("@lit%d", line)}
	s.declID = litID
	s.entry = false
	s.seedFields(lit.Type.Params)
	s.seedFields(lit.Type.Results)
	s.walkStmts(lit.Body.List)
	s.decl, s.declID, s.entry = savedDecl, savedID, savedEntry
	s.c.Closures = append(s.c.Closures, CensusClosure{
		File:        s.v.Path,
		Line:        line,
		Declaration: DeclarationIdentity{Path: s.v.Path, Name: fmt.Sprintf("@lit%d", line)},
	})
}

// evalDiscarded evaluates an expression statement. A call is classified even
// when its result is discarded.
func (s *censusScan) evalDiscarded(e ast.Expr) {
	if call, ok := e.(*ast.CallExpr); ok {
		s.evalCall(call)
		return
	}
	s.readOnly(e)
}

// readOnly evaluates an expression whose value only participates in a guard, a
// comparison or a log. Calls inside it are still classified, because an
// operation in a condition is an operation.
func (s *censusScan) readOnly(e ast.Expr) {
	if e == nil {
		return
	}
	ast.Inspect(e, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			s.evalCall(x)
			return false
		case *ast.FuncLit:
			s.checkClosure(x)
			return false
		}
		return true
	})
}

// structural resolves an expression through the Task 4 identity resolver. It is
// the fallback for expressions the may-set walker does not model.
func (s *censusScan) structural(e ast.Expr) evalResult {
	r := s.a.resolveExpr(s.v, e, 0)
	if r.Resolved() {
		return evalResult{set: []*ExprIdentity{r.Identity}}
	}
	s.obligate(ObligationUnresolvedResource, e.Pos(), "", r.Missing())
	return evalResult{unknown: r.Missing()}
}

func (s *censusScan) obligate(kind CensusObligationKind, pos token.Pos, key, detail string) {
	line := 0
	if s.v != nil && s.v.Fset != nil {
		line = s.v.Fset.Position(pos).Line
	}
	s.c.Obligations = append(s.c.Obligations, CensusObligation{
		Kind:        kind,
		File:        s.v.Path,
		Line:        line,
		Declaration: s.decl,
		ResourceKey: "", // Escapes block every resource until relevance is checked.
		Detail:      detail,
	})
}

// keyOf returns the resource key of a may-set when every member agrees on it.
// A set whose members disagree names several resources, so no single key is
// claimed and the obligation blocks every subject set.
func (s *censusScan) keyOf(res evalResult) string {
	key := ""
	for _, id := range res.set {
		k, ok := ResourceKey(id)
		if !ok {
			return ""
		}
		if key == "" {
			key = k
			continue
		}
		if key != k {
			return ""
		}
	}
	return key
}

func isGuardOperator(op token.Token) bool {
	switch op {
	case token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ, token.LAND, token.LOR:
		return true
	}
	return false
}

// isInterfaceExpr reports whether a declared type is (or names) an interface.
func isInterfaceExpr(v *fileView, e ast.Expr) bool {
	if e == nil {
		return false
	}
	switch x := e.(type) {
	case *ast.InterfaceType:
		return true
	case *ast.Ident:
		if v.Pkg != nil {
			if ts, ok := v.Pkg.Types[x.Name]; ok {
				if _, ok := ts.Type.(*ast.InterfaceType); ok {
					return true
				}
			}
		}
		return x.Name == "error" || x.Name == "any"
	}
	return false
}

// isInterfaceAssign reports whether an assignment's left side names an
// interface destination. The right side cannot be tracked through it.
func isInterfaceAssign(v *fileView, st *ast.AssignStmt) bool {
	for _, lhs := range st.Lhs {
		id, ok := lhs.(*ast.Ident)
		if !ok || id.Obj == nil {
			continue
		}
		if decl, ok := v.Values[id.Obj]; ok && isInterfaceExpr(v, decl.Type) {
			return true
		}
	}
	return false
}

// harmlessConsumers is the closed set of declarations whose call cannot act on
// a resource value: it derives a new value or reports a fact. Nothing outside
// this table is presumed harmless, so an unlisted call that receives a resource
// is a blocking obligation.
var harmlessConsumers = []struct {
	importPath string
	receiver   string
	name       string
}{
	{"strings", "", "HasPrefix"}, {"strings", "", "HasSuffix"},
	{"strings", "", "Contains"}, {"strings", "", "Index"},
	{"strings", "", "LastIndex"}, {"strings", "", "TrimPrefix"},
	{"strings", "", "TrimSuffix"}, {"strings", "", "TrimSpace"},
	{"strings", "", "Trim"}, {"strings", "", "ReplaceAll"},
	{"strings", "", "Replace"}, {"strings", "", "Join"},
	{"strings", "", "Split"}, {"strings", "", "SplitN"},
	{"strings", "", "ToLower"}, {"strings", "", "ToUpper"},
	{"strings", "", "Count"}, {"strings", "", "EqualFold"},
	{"strings", "", "Cut"}, {"strings", "", "Fields"},
	{"path/filepath", "", "Join"}, {"path/filepath", "", "Clean"},
	{"path/filepath", "", "Dir"}, {"path/filepath", "", "Base"},
	{"path/filepath", "", "Abs"}, {"path/filepath", "", "IsAbs"},
	{"path/filepath", "", "Rel"}, {"path/filepath", "", "ToSlash"},
	{"path/filepath", "", "FromSlash"}, {"path/filepath", "", "Split"},
	{"path/filepath", "", "Ext"}, {"path/filepath", "", "VolumeName"},
	{"path/filepath", "", "Match"},
	{"path", "", "Join"}, {"path", "", "Clean"}, {"path", "", "Dir"},
	{"path", "", "Base"}, {"path", "", "Split"}, {"path", "", "Ext"},
	{"strconv", "", "Itoa"}, {"strconv", "", "Atoi"},
	{"strconv", "", "FormatInt"}, {"strconv", "", "Quote"},
}

// harmlessBuiltins are the builtins that report a fact about a value without
// creating or storing anything.
var harmlessBuiltins = map[string]bool{
	"len": true, "cap": true, "complex": true, "real": true, "imag": true,
}

func isHarmlessConsumer(id APIIdentity) bool {
	if id.Source == "builtin" {
		return harmlessBuiltins[id.Name]
	}
	for _, spec := range harmlessConsumers {
		if spec.importPath == id.ImportPath && spec.receiver == id.Receiver && spec.name == id.Name {
			return true
		}
	}
	return false
}

// supportsDeclaration reports whether the resolved declaration is one the
// census is expected to classify — a table-supported operation, or a
// repository-local wrapper with a checked summary. A failure to classify such a
// declaration is an unresolved operation, not an unknown call.
func (a *analyzer) supportsDeclaration(res callResolution) bool {
	if !res.Resolved {
		return false
	}
	if res.Local {
		if a.bundle == nil {
			return false
		}
		for _, w := range a.bundle.Wrappers {
			if w.Function.Equal(res.Identity) {
				return true
			}
		}
		return false
	}
	if res.Identity.Source == "builtin" {
		return false
	}
	_, ok := specFor(res.Identity)
	return ok
}

// deriveWrappers derives the checked forwarding summaries of repository-local
// functions whose body is a single unconditional forward to a supported
// declaration. This is what links a call like `mkdirAll(cfg.Root)` to the
// operation inside `mkdirAll`; without it the call is an escape obligation, so
// deriving the summary can only add candidates, never drop one.
func deriveWrappers(a *analyzer, files []string) []WrapperSummary {
	var out []WrapperSummary
	for _, name := range files {
		v, err := a.view(name, ImageSelected)
		if err != nil {
			continue
		}
		a.ensurePackage(v)
		for _, decl := range v.File.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			if summary, ok := deriveWrapper(a, v, fd); ok {
				out = append(out, summary)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Function.String() < out[j].Function.String()
	})
	return out
}

func deriveWrapper(a *analyzer, v *fileView, fd *ast.FuncDecl) (WrapperSummary, bool) {
	digest, ok := bodyDigest(v, fd)
	if !ok {
		return WrapperSummary{}, false
	}
	identity := v.localFunctionIdentity(fd)
	if fd.Recv != nil && len(fd.Recv.List) > 0 {
		identity = methodIdentity(v, fd)
	}
	type candidate struct {
		identity APIIdentity
		spec     operationSpec
		call     *ast.CallExpr
	}
	var found []candidate
	for _, stmt := range fd.Body.List {
		exprStmt, ok := stmt.(*ast.ExprStmt)
		if !ok {
			return WrapperSummary{}, false
		}
		call, ok := exprStmt.X.(*ast.CallExpr)
		if !ok {
			return WrapperSummary{}, false
		}
		res := a.resolveCall(v, call)
		if !res.Resolved || res.Local {
			// A statement the census cannot classify means the body is not a
			// plain forwarder, so no summary may be claimed for it.
			return WrapperSummary{}, false
		}
		spec, ok := specFor(res.Identity)
		if !ok || spec.Signature != res.Identity.Signature {
			return WrapperSummary{}, false
		}
		found = append(found, candidate{identity: res.Identity, spec: spec, call: call})
	}
	if len(found) != 1 {
		return WrapperSummary{}, false
	}
	chosen := found[0]
	resourceArg := resourceArgIndex(chosen.spec)
	modeArg := -1
	for idx, role := range chosen.spec.Args {
		if role == ArgMode {
			modeArg = idx
		}
	}
	if resourceArg < 0 || resourceArg >= len(chosen.call.Args) || modeArg < 0 || modeArg >= len(chosen.call.Args) {
		return WrapperSummary{}, false
	}
	resourceParam, ok := parameterIndex(fd, chosen.call.Args[resourceArg])
	if !ok {
		return WrapperSummary{}, false
	}
	forward := WrapperForward{
		Target:        chosen.identity,
		Class:         chosen.spec.Class,
		ResourceParam: resourceParam,
		ModeParam:     -1,
	}
	if literal, ok := modeLiteral(chosen.call.Args[modeArg]); ok {
		forward.ModeLiteral = literal
	} else if index, ok := parameterIndex(fd, chosen.call.Args[modeArg]); ok {
		forward.ModeParam = index
	} else {
		return WrapperSummary{}, false
	}
	return WrapperSummary{
		Function:   identity,
		BodyDigest: digest,
		Forwards:   []WrapperForward{forward},
	}, true
}

// methodIdentity renders a method's resolved declaration identity with its
// package-qualified receiver, matching what callee resolution produces.
func methodIdentity(v *fileView, fd *ast.FuncDecl) APIIdentity {
	recv := ""
	if fd.Recv != nil && len(fd.Recv.List) > 0 {
		recv = receiverTypeName(fd.Recv.List[0].Type)
	}
	return APIIdentity{
		Source:     v.packageSource(),
		ImportPath: v.PackagePath,
		Receiver:   v.PackagePath + "." + recv,
		Name:       fd.Name.Name,
		Signature:  v.signature(fd.Type),
	}
}

// parameterIndex returns the position of the identifier among the declaration's
// named parameters. A receiver is not a parameter: a caller supplies only the
// argument list.
func parameterIndex(fd *ast.FuncDecl, expr ast.Expr) (int, bool) {
	id, ok := unwrapParen(expr).(*ast.Ident)
	if !ok || id.Obj == nil || fd.Type.Params == nil {
		return 0, false
	}
	index := 0
	for _, field := range fd.Type.Params.List {
		for _, name := range field.Names {
			if name.Obj == id.Obj {
				return index, true
			}
			index++
		}
	}
	return 0, false
}

// Cover-aspect and parse blocking codes.
const (
	CodeCoverObstructed = "COVER_OBSTRUCTED"
	CodeCoverEmpty      = "COVER_EMPTY"
	CodeParseFile       = "PARSE_FAILED"
)

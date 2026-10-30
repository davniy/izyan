package goanalysis

import (
	"context"
	"go/ast"
	"go/token"
	"go/types"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"

	"github.com/davniy/izyan/internal/domain"
)

var (
	vulnParseSym      = domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Parse"}
	vulnParseBytesSym = domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "ParseBytes"}
	vulnParse2Sym     = domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Parse2"}
)

// libraryModule writes a temp library module requiring testdata/dep and proves
// its product shape. Every payload-witness test needs a proven LIBRARY shape;
// nothing here depends on callers of the analyzed product.
func libraryModule(t *testing.T, module string, files map[string]string) (*Index, *domain.ProductShape) {
	t.Helper()
	depAbs, err := filepath.Abs(filepath.Join("..", "..", "testdata", "dep"))
	if err != nil {
		t.Fatal(err)
	}
	gomod := "module " + module + "\n\ngo 1.23\n\n" +
		"require example.com/dep v1.0.0\n\nreplace example.com/dep => " + depAbs + "\n"
	dir := usageModuleGomod(t, gomod, files)
	ix := &Index{Dir: dir}
	shape, _, err := ix.BuildProductShape(context.Background())
	if err != nil {
		t.Fatalf("BuildProductShape(%s): %v", module, err)
	}
	if shape.Kind != domain.ProductShapeLibrary || !shape.CensusComplete {
		t.Fatalf("%s is not a proven library: kind=%s complete=%t limitations=%v",
			module, shape.Kind, shape.CensusComplete, shape.Limitations)
	}
	return ix, shape
}

func librarySinkSites(t *testing.T, ix *Index, sink domain.SymbolRef) []domain.CallSite {
	t.Helper()
	sites, err := ix.FindCallers(context.Background(), sink)
	if err != nil {
		t.Fatalf("FindCallers(%s.%s): %v", sink.Package, sink.Symbol, err)
	}
	sort.Slice(sites, func(i, j int) bool {
		if sites[i].Line != sites[j].Line {
			return sites[i].Line < sites[j].Line
		}
		return sites[i].Column < sites[j].Column
	})
	return sites
}

// librarySiteIn returns the unique call site of sink inside function.
func librarySiteIn(t *testing.T, ix *Index, sink domain.SymbolRef, function string) domain.CallSite {
	t.Helper()
	var found []domain.CallSite
	for _, site := range librarySinkSites(t, ix, sink) {
		if site.Function == function {
			found = append(found, site)
		}
	}
	if len(found) != 1 {
		t.Fatalf("want exactly one %s call site in %s, got %d", sink.Symbol, function, len(found))
	}
	return found[0]
}

func libraryTrace(t *testing.T, ix *Index, site domain.CallSite, arg int) domain.DataFlow {
	t.Helper()
	flow, _, err := ix.TraceArgument(context.Background(), site, arg)
	if err != nil {
		t.Fatalf("TraceArgument(%s:%d:%d arg %d): %v", site.File, site.Line, site.Column, arg, err)
	}
	return flow
}

// TestLibraryInputPublicFormalBoundary: a public API formal is the product's
// input boundary regardless of observed callers. Zero callers, test-only
// callers, constant-only callers and generated-style forwarding wrappers all
// end at the same UNKNOWN deployment origin, and the consumer-selectable
// payload is still witnessed exactly.
func TestLibraryInputPublicFormalBoundary(t *testing.T) {
	const mod = "example.com/libboundary"
	parseInput := `package libboundary

import "example.com/dep/vuln"

// ParseInput is the public boundary; only its caller selects the payload.
func ParseInput(payload string) bool {
	return vuln.Parse(payload) == ""
}
`
	cases := []struct {
		name  string
		files map[string]string
	}{
		{name: "zero callers", files: map[string]string{"lib.go": parseInput}},
		{name: "test-only callers", files: map[string]string{
			"lib.go": parseInput,
			"lib_test.go": `package libboundary

import "testing"

func TestParseInput(t *testing.T) {
	if !ParseInput("constant") {
		t.Fatal("unexpected")
	}
}
`,
		}},
		{name: "constant-only callers", files: map[string]string{
			"lib.go": parseInput + `
// Use calls the public API with a literal only.
func Use() bool { return ParseInput("fixed literal") }
`,
		}},
		{name: "generated-style forwarding wrapper", files: map[string]string{
			"lib.go": parseInput + `
// Forward is a generated-style wrapper over the public API.
func Forward(payload string) bool { return ParseInput(payload) }
`,
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ix, _ := libraryModule(t, mod, tc.files)
			site := librarySiteIn(t, ix, vulnParseSym, "ParseInput")
			flow := libraryTrace(t, ix, site, 0)
			if flow.Origin != domain.OriginUnknown {
				t.Fatalf("origin=%s, want UNKNOWN: caller evidence must not close a public boundary (%s)",
					flow.Origin, flow.Summary)
			}
			if !strings.Contains(flow.Summary, "public library formal") {
				t.Fatalf("summary must name the public boundary: %s", flow.Summary)
			}
			w := flow.LibraryInput
			if w == nil {
				t.Fatalf("no payload witness: %s", flow.Summary)
			}
			if w.API != (domain.SymbolRef{Package: mod, Symbol: "ParseInput"}) {
				t.Fatalf("api=%+v", w.API)
			}
			if w.FormalIndex != 0 || w.FormalName != "payload" {
				t.Fatalf("formal=%d:%q", w.FormalIndex, w.FormalName)
			}
			if w.Sink != vulnParseSym || w.Arg != 0 {
				t.Fatalf("sink=%+v arg=%d", w.Sink, w.Arg)
			}
			if w.Site != site {
				t.Fatalf("witness site=%+v, want exact traced site %+v", w.Site, site)
			}
			if w.ShapeFingerprint == "" {
				t.Fatal("witness must pin the product-shape fingerprint")
			}
			if len(w.EvidenceIDs) != 0 {
				t.Fatalf("the tracer must not assign case-scoped evidence ids: %v", w.EvidenceIDs)
			}
		})
	}

	t.Run("forwarding wrapper is itself a public boundary", func(t *testing.T) {
		ix, _ := libraryModule(t, mod, map[string]string{"lib.go": parseInput + `
func Forward(payload string) bool { return ParseInput(payload) }
`})
		site := librarySiteIn(t, ix, domain.SymbolRef{Package: mod, Symbol: "ParseInput"}, "Forward")
		flow := libraryTrace(t, ix, site, 0)
		if flow.Origin != domain.OriginUnknown {
			t.Fatalf("origin=%s, want UNKNOWN (%s)", flow.Origin, flow.Summary)
		}
		w := flow.LibraryInput
		if w == nil || w.API != (domain.SymbolRef{Package: mod, Symbol: "Forward"}) {
			t.Fatalf("wrapper must carry its own public-formal witness: %+v (%s)", w, flow.Summary)
		}
	})
}

// TestLibraryInputPublicAPIMatrix: only genuine product-owned public API
// formals carry a witness — exported functions and exported methods on exported
// named receivers. Private declarations, unexported receivers, internal and
// dependency packages, test variants and command products never do, and a
// shadowed local is never mistaken for a same-named formal.
func TestLibraryInputPublicAPIMatrix(t *testing.T) {
	const mod = "example.com/libapi"
	files := map[string]string{
		"lib.go": `package libapi

import "example.com/dep/vuln"

type Value struct{}

type unexportedReceiver struct{}

func Exported(payload string) bool { return vuln.Parse(payload) == "" }

func (v Value) OnValue(payload string) bool { return vuln.Parse(payload) == "" }

func (v *Value) OnPointer(payload string) bool { return vuln.Parse(payload) == "" }

func private(payload string) bool { return vuln.Parse(payload) == "" }

func (v Value) privateMethod(payload string) bool { return vuln.Parse(payload) == "" }

func (u unexportedReceiver) OnUnexported(payload string) bool { return vuln.Parse(payload) == "" }

func Shadowed(expected string) bool {
	{
		expected := "literal"
		return vuln.Parse(expected) == ""
	}
}

var _ = private
var _ = Value{}.privateMethod
var _ = unexportedReceiver{}.OnUnexported
`,
	}
	ix, _ := libraryModule(t, mod, files)
	pkg := productPackage(t, ix, mod)

	cases := []struct {
		name   string
		decl   *ast.FuncDecl
		param  *types.Var
		wantOK bool
		want   string
	}{
		{name: "exported function", decl: libraryFuncDecl(t, ix, pkg, "Exported"), param: firstFormal(t, pkg, "Exported"), wantOK: true, want: "Exported"},
		{name: "exported method on exported value receiver", decl: libraryFuncDecl(t, ix, pkg, "Value.OnValue"), param: firstFormal(t, pkg, "Value.OnValue"), wantOK: true, want: "Value.OnValue"},
		{name: "exported method on exported pointer receiver", decl: libraryFuncDecl(t, ix, pkg, "Value.OnPointer"), param: firstFormal(t, pkg, "Value.OnPointer"), wantOK: true, want: "Value.OnPointer"},
		{name: "private function", decl: libraryFuncDecl(t, ix, pkg, "private"), param: firstFormal(t, pkg, "private"), wantOK: false},
		{name: "private method", decl: libraryFuncDecl(t, ix, pkg, "Value.privateMethod"), param: firstFormal(t, pkg, "Value.privateMethod"), wantOK: false},
		{name: "exported method on unexported receiver", decl: libraryFuncDecl(t, ix, pkg, "unexportedReceiver.OnUnexported"), param: firstFormal(t, pkg, "unexportedReceiver.OnUnexported"), wantOK: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ref, idx, ok := ix.publicLibraryFormalLocked(pkg, tc.decl, tc.param)
			if ok != tc.wantOK {
				t.Fatalf("ok=%t want %t (ref=%+v idx=%d)", ok, tc.wantOK, ref, idx)
			}
			if ok && (ref != (domain.SymbolRef{Package: mod, Symbol: tc.want}) || idx != 0) {
				t.Fatalf("ref=%+v idx=%d, want %s arg 0", ref, idx, tc.want)
			}
		})
	}

	t.Run("test variant package", func(t *testing.T) {
		decl := libraryFuncDecl(t, ix, pkg, "Exported")
		param := firstFormal(t, pkg, "Exported")
		clone := *pkg
		clone.ForTest = mod
		if _, _, ok := ix.publicLibraryFormalLocked(&clone, decl, param); ok {
			t.Fatal("a test-variant package must not expose a public library formal")
		}
	})

	t.Run("internal package", func(t *testing.T) {
		const internalMod = "example.com/libinternal"
		ix, _ := libraryModule(t, internalMod, map[string]string{
			"lib.go": "package libinternal\n\nfunc Use() {}\n",
			"internal/hidden/hidden.go": `package hidden

import "example.com/dep/vuln"

func ParseHidden(payload string) bool { return vuln.Parse(payload) == "" }
`,
		})
		hidden := productPackage(t, ix, internalMod+"/internal/hidden")
		decl := libraryFuncDecl(t, ix, hidden, "ParseHidden")
		param := firstFormal(t, hidden, "ParseHidden")
		if _, _, ok := ix.publicLibraryFormalLocked(hidden, decl, param); ok {
			t.Fatal("an internal package is not externally importable")
		}
		site := librarySiteIn(t, ix, vulnParseSym, "ParseHidden")
		if flow := libraryTrace(t, ix, site, 0); flow.LibraryInput != nil {
			t.Fatalf("internal package produced a witness: %+v", flow.LibraryInput)
		}
	})

	t.Run("command product", func(t *testing.T) {
		const cmdMod = "example.com/libcmd"
		ix, shape := libraryModuleForShape(t, cmdMod, map[string]string{
			"lib.go": "package libcmd\n\nfunc Use() {}\n",
			"cmd/tool/main.go": `package main

import "example.com/dep/vuln"

func main() { _ = vuln.Parse("literal") }
`,
		})
		if shape.Kind != domain.ProductShapeApplication {
			t.Fatalf("command fixture shape=%s, want APPLICATION", shape.Kind)
		}
		site := librarySiteIn(t, ix, vulnParseSym, "main")
		if flow := libraryTrace(t, ix, site, 0); flow.LibraryInput != nil {
			t.Fatalf("application product produced a library witness: %+v", flow.LibraryInput)
		}
	})

	t.Run("dependency package", func(t *testing.T) {
		ix, _ := libraryModule(t, mod, files)
		depTypes := typePackage(t, pkg, "example.com/dep/vuln")
		fn, ok := depTypes.Scope().Lookup("Parse").(*types.Func)
		if !ok {
			t.Fatal("dependency Parse not found")
		}
		decl, depPkg := ix.funcDecl(fn)
		if decl == nil || depPkg == nil {
			t.Fatal("dependency declaration not resolvable")
		}
		sig := fn.Type().(*types.Signature)
		if _, _, ok := ix.publicLibraryFormalLocked(depPkg, decl, sig.Params().At(0)); ok {
			t.Fatal("a dependency package is not product-owned")
		}
	})

	t.Run("shadowed local named like a formal", func(t *testing.T) {
		site := librarySiteIn(t, ix, vulnParseSym, "Shadowed")
		flow := libraryTrace(t, ix, site, 0)
		if strings.Contains(flow.Summary, "public library formal") {
			t.Fatalf("a shadowed local was treated as the public formal: %s", flow.Summary)
		}
		if flow.LibraryInput != nil {
			t.Fatalf("a shadowed local must not be mistaken for the formal: %+v", flow.LibraryInput)
		}
	})
}

// TestLibraryInputPayloadTypeMatrix: the eligible payload types are exactly
// string, []byte (or a defined type/alias with that underlying representation)
// and the canonical io.Reader. Lookalikes, writers, callbacks, pointers,
// containers and unresolved type parameters are rejected without heuristics.
func TestLibraryInputPayloadTypeMatrix(t *testing.T) {
	byteSlice := types.NewSlice(types.Typ[types.Uint8])
	errorType := types.Universe.Lookup("error").Type()
	readerIface := func(method string) types.Type {
		sig := types.NewSignatureType(nil, nil, nil,
			types.NewTuple(types.NewVar(token.NoPos, nil, "", byteSlice)),
			types.NewTuple(types.NewVar(token.NoPos, nil, "n", types.Typ[types.Int]),
				types.NewVar(token.NoPos, nil, "err", errorType)), false)
		return types.NewInterfaceType([]*types.Func{
			types.NewFunc(token.NoPos, nil, method, sig),
		}, nil).Complete()
	}
	named := func(path, name string, underlying types.Type) *types.Named {
		pkg := types.NewPackage(path, path[strings.LastIndex(path, "/")+1:])
		return types.NewNamed(types.NewTypeName(token.NoPos, pkg, name, nil), underlying, nil)
	}

	cases := []struct {
		name string
		typ  types.Type
		want bool
	}{
		{name: "string", typ: types.Typ[types.String], want: true},
		{name: "byte slice", typ: byteSlice, want: true},
		{name: "byte alias element", typ: types.NewSlice(types.Typ[types.Byte]), want: true},
		{name: "string alias", typ: types.NewAlias(types.NewTypeName(token.NoPos, nil, "Text", nil), types.Typ[types.String]), want: true},
		{name: "byte-slice alias", typ: types.NewAlias(types.NewTypeName(token.NoPos, nil, "Raw", nil), byteSlice), want: true},
		{name: "defined string type", typ: named("example.com/libpay", "Doc", types.Typ[types.String]), want: true},
		{name: "defined byte-slice type", typ: named("example.com/libpay", "Blob", byteSlice), want: true},
		{name: "canonical io.Reader", typ: named("io", "Reader", readerIface("Read")), want: true},
		{name: "io.Writer", typ: named("io", "Writer", readerIface("Write")), want: false},
		{name: "lookalike Reader interface", typ: named("example.com/libpay", "Reader", readerIface("Read")), want: false},
		{name: "lookalike named Reader struct", typ: named("example.com/libpay", "Reader", types.NewStruct(nil, nil)), want: false},
		{name: "type-name substring is not a payload", typ: named("example.com/libpay", "BytesReaderBytes", types.NewStruct(nil, nil)), want: false},
		{name: "callback", typ: types.NewSignatureType(nil, nil, nil, types.NewTuple(), types.NewTuple(), false), want: false},
		{name: "pointer", typ: types.NewPointer(types.Typ[types.String]), want: false},
		{name: "string container", typ: types.NewSlice(types.Typ[types.String]), want: false},
		{name: "map", typ: types.NewMap(types.Typ[types.String], types.Typ[types.String]), want: false},
		{name: "rune slice", typ: types.NewSlice(types.Typ[types.Rune]), want: false},
		{name: "type parameter", typ: types.NewTypeParam(types.NewTypeName(token.NoPos, nil, "T", nil),
			types.NewInterfaceType(nil, nil).Complete()), want: false},
		{name: "any", typ: types.NewInterfaceType(nil, nil).Complete(), want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			name, ok := libraryPayloadType(tc.typ)
			if ok != tc.want {
				t.Fatalf("libraryPayloadType(%s)=%q,%t want ok=%t", tc.name, name, ok, tc.want)
			}
			if ok && name == "" {
				t.Fatalf("%s: eligible type must have a stable name", tc.name)
			}
		})
	}

	if name, ok := libraryPayloadType(types.Typ[types.String]); !ok || name != "string" {
		t.Fatalf("string type name=%q ok=%t", name, ok)
	}
	if name, ok := libraryPayloadType(byteSlice); !ok || name != "[]byte" {
		t.Fatalf("byte-slice type name=%q ok=%t", name, ok)
	}
	if name, ok := libraryPayloadType(named("io", "Reader", readerIface("Read"))); !ok || name != "io.Reader" {
		t.Fatalf("canonical reader name=%q ok=%t", name, ok)
	}
}

// TestLibraryInputPayloadBindingMatrix: the strict payload walk accepts only
// verified identity/local forwarding, byte-preserving conversions, typed direct
// helper forwarding and explicitly modeled complete reads. Wrong formals,
// constant replacement, slicing, numeric/rune conversions, opaque transforms,
// unresolved dispatch, writer-only positions, unmodeled guards and recovery all
// yield no witness.
// libraryBindingFixture is the payload-binding matrix module: every shape the
// strict walk must accept or reject, in one product package. It is shared by
// the matrix and the focused mutation/derived-guard regression test.
func libraryBindingFixture() map[string]string {
	return map[string]string{
		"lib.go": `package libbinding

import (
	"io"

	"example.com/dep/vuln"
)

func Identity(blob []byte) bool { return vuln.ParseBytes(blob) == "" }

func Converted(payload string) bool { return vuln.ParseBytes([]byte(payload)) == "" }

func Second(unused string, payload []byte) bool {
	_ = unused
	return vuln.ParseBytes(payload) == ""
}

func IntFormal(count int) {
	vuln.Qos(count, 1, false)
}

func Replaced(payload []byte) bool {
	payload = []byte("fixed")
	return vuln.ParseBytes(payload) == ""
}

func Sliced(payload []byte) bool { return vuln.ParseBytes(payload[:4]) == "" }

func RuneCast(r rune) bool { return vuln.ParseBytes([]byte(string(r))) == "" }

func opaque(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

func Opaque(payload []byte) bool { return vuln.ParseBytes(opaque(payload)) == "" }

func identityBytes(b []byte) []byte { return b }

func Dispatch(payload []byte) bool {
	var forward func([]byte) []byte = identityBytes
	return vuln.ParseBytes(forward(payload)) == ""
}

func sinkWriter(w io.Writer) {}

func WriterArg(w io.Writer) bool {
	sinkWriter(w)
	return true
}

func Guarded(payload []byte) bool {
	if len(payload) == 0 {
		return false
	}
	return vuln.ParseBytes(payload) == ""
}

func Recovered(payload []byte) bool {
	defer func() { _ = recover() }()
	return vuln.ParseBytes(payload) == ""
}

func ErrorTest(payload string) bool {
	if _, err := vuln.Parse2(string(payload)); err != nil {
		return false
	}
	return true
}

func Reader(payload io.Reader) bool {
	data, err := io.ReadAll(payload)
	if err != nil {
		return false
	}
	return vuln.ParseBytes(data) == ""
}

func DirectReader(payload io.Reader) bool {
	data, _ := io.ReadAll(payload)
	return vuln.ParseBytes(data) == ""
}

func viaHelper(b []byte) []byte { return b }

func Helper(payload []byte) bool { return vuln.ParseBytes(viaHelper(payload)) == "" }

func decode(payload []byte) bool { return vuln.ParseBytes(payload) == "" }

func Wrapper(payload []byte) bool { return decode(payload) }

func guardedHelper(payload []byte) bool {
	if len(payload) == 0 {
		return false
	}
	return vuln.ParseBytes(payload) == ""
}

func WrapperGuarded(payload []byte) bool { return guardedHelper(payload) }

func MutatingClear(payload []byte) bool {
	clear(payload)
	return vuln.ParseBytes(payload) == ""
}

func MutatingCopy(payload []byte) bool {
	copy(payload, []byte("fixed"))
	return vuln.ParseBytes(payload) == ""
}

func MutationAlias(payload []byte) bool {
	alias := payload
	clear(alias)
	return vuln.ParseBytes(payload) == ""
}

func MutationPointer(payload []byte) bool {
	mutatePointer(&payload)
	return vuln.ParseBytes(payload) == ""
}

func mutatePointer(p *[]byte) { *p = []byte("fixed") }

func MutationUnknownCall(payload []byte) bool {
	touchBytes(payload)
	return vuln.ParseBytes(payload) == ""
}

func touchBytes([]byte) {}

func DerivedPredicateGuard(payload string) bool {
	valid := validateText(payload)
	if !valid {
		return false
	}
	return vuln.Parse(payload) == ""
}

func validateText(string) bool { return true }

func DerivedComparisonGuard(payload []byte) bool {
	nonEmpty := len(payload) > 0
	if !nonEmpty {
		return false
	}
	return vuln.ParseBytes(payload) == ""
}

func ReadOnlyLength(payload []byte) bool {
	size := len(payload)
	_ = size
	return vuln.ParseBytes(payload) == ""
}

func ReadOnlyCopySource(payload []byte) bool {
	dst := make([]byte, len(payload))
	copy(dst, payload)
	_ = dst
	return vuln.ParseBytes(payload) == ""
}
`,
	}
}

func TestLibraryInputPayloadBindingMatrix(t *testing.T) {
	const mod = "example.com/libbinding"
	files := libraryBindingFixture()
	ix, _ := libraryModule(t, mod, files)
	ctx := context.Background()

	type want struct {
		api        string
		formal     int
		formalName string
		formalType string
		sink       domain.SymbolRef
		steps      int
	}
	cases := []struct {
		name     string
		function string
		sink     domain.SymbolRef
		want     *want
	}{
		{name: "identity byte slice", function: "Identity", sink: vulnParseBytesSym,
			want: &want{api: "Identity", formal: 0, formalName: "blob", formalType: "[]byte", sink: vulnParseBytesSym}},
		{name: "byte-preserving conversion", function: "Converted", sink: vulnParseBytesSym,
			want: &want{api: "Converted", formal: 0, formalName: "payload", formalType: "string", sink: vulnParseBytesSym, steps: 1}},
		{name: "second formal carries the payload", function: "Second", sink: vulnParseBytesSym,
			want: &want{api: "Second", formal: 1, formalName: "payload", formalType: "[]byte", sink: vulnParseBytesSym}},
		{name: "ineligible payload formal type", function: "IntFormal",
			sink: domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Qos"}},
		{name: "constant replacement", function: "Replaced", sink: vulnParseBytesSym},
		{name: "slicing truncation", function: "Sliced", sink: vulnParseBytesSym},
		{name: "numeric rune conversion", function: "RuneCast", sink: vulnParseBytesSym},
		{name: "opaque transformation", function: "Opaque", sink: vulnParseBytesSym},
		{name: "unresolved dispatch", function: "Dispatch", sink: vulnParseBytesSym},
		{name: "writer-only position", function: "WriterArg", sink: domain.SymbolRef{Package: mod, Symbol: "sinkWriter"}},
		{name: "unmodeled payload guard", function: "Guarded", sink: vulnParseBytesSym},
		{name: "recovery in scope", function: "Recovered", sink: vulnParseBytesSym},
		{name: "if-initializer error test is not a guard", function: "ErrorTest", sink: vulnParse2Sym,
			want: &want{api: "ErrorTest", formal: 0, formalName: "payload", formalType: "string", sink: vulnParse2Sym, steps: 1}},
		{name: "io.ReadAll complete read", function: "Reader", sink: vulnParseBytesSym,
			want: &want{api: "Reader", formal: 0, formalName: "payload", formalType: "io.Reader", sink: vulnParseBytesSym, steps: 2}},
		{name: "direct reader read", function: "DirectReader", sink: vulnParseBytesSym,
			want: &want{api: "DirectReader", formal: 0, formalName: "payload", formalType: "io.Reader", sink: vulnParseBytesSym, steps: 2}},
		{name: "typed helper forwarding", function: "Helper", sink: vulnParseBytesSym,
			want: &want{api: "Helper", formal: 0, formalName: "payload", formalType: "[]byte", sink: vulnParseBytesSym, steps: 1}},
		{name: "private helper parameter", function: "decode", sink: vulnParseBytesSym,
			want: &want{api: "Wrapper", formal: 0, formalName: "payload", formalType: "[]byte", sink: vulnParseBytesSym, steps: 1}},
		{name: "guarded private helper", function: "guardedHelper", sink: vulnParseBytesSym},
		{name: "mutating builtin clear", function: "MutatingClear", sink: vulnParseBytesSym},
		{name: "mutating copy destination", function: "MutatingCopy", sink: vulnParseBytesSym},
		{name: "mutation through alias", function: "MutationAlias", sink: vulnParseBytesSym},
		{name: "mutation through address-taking", function: "MutationPointer", sink: vulnParseBytesSym},
		{name: "unknown call receives mutable carrier", function: "MutationUnknownCall", sink: vulnParseBytesSym},
		{name: "derived predicate guard", function: "DerivedPredicateGuard", sink: vulnParseSym},
		{name: "derived comparison guard", function: "DerivedComparisonGuard", sink: vulnParseBytesSym},
		{name: "read-only length use", function: "ReadOnlyLength", sink: vulnParseBytesSym,
			want: &want{api: "ReadOnlyLength", formal: 0, formalName: "payload", formalType: "[]byte", sink: vulnParseBytesSym}},
		{name: "read-only copy source", function: "ReadOnlyCopySource", sink: vulnParseBytesSym,
			want: &want{api: "ReadOnlyCopySource", formal: 0, formalName: "payload", formalType: "[]byte", sink: vulnParseBytesSym}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			site := librarySiteIn(t, ix, tc.sink, tc.function)
			flow := libraryTrace(t, ix, site, 0)
			if tc.want != nil && flow.Origin != domain.OriginUnknown {
				t.Fatalf("origin=%s, want UNKNOWN (%s)", flow.Origin, flow.Summary)
			}
			if tc.want == nil {
				if flow.LibraryInput != nil {
					t.Fatalf("unprovable payload path produced a witness: %+v", flow.LibraryInput)
				}
				return
			}
			w := flow.LibraryInput
			if w == nil {
				t.Fatalf("missing witness for %s: %s", tc.name, flow.Summary)
			}
			if w.API != (domain.SymbolRef{Package: mod, Symbol: tc.want.api}) {
				t.Fatalf("api=%+v, want %s.%s", w.API, mod, tc.want.api)
			}
			if w.FormalIndex != tc.want.formal || w.FormalName != tc.want.formalName || w.FormalType != tc.want.formalType {
				t.Fatalf("formal=%d:%s:%s, want %d:%s:%s",
					w.FormalIndex, w.FormalName, w.FormalType,
					tc.want.formal, tc.want.formalName, tc.want.formalType)
			}
			if w.Sink != tc.want.sink || w.Arg != 0 {
				t.Fatalf("sink=%+v arg=%d", w.Sink, w.Arg)
			}
			if len(w.Steps) != tc.want.steps {
				t.Fatalf("steps=%+v, want %d", w.Steps, tc.want.steps)
			}
			for _, step := range w.Steps {
				if step.Site.File == "" || step.Site.Line == 0 || step.Site.Column == 0 {
					t.Fatalf("step without an exact site: %+v", step)
				}
			}
		})
	}

	// Re-tracing during negative verification uses the same trace with a wider
	// hop budget; a public formal stays unresolved and cannot verify a
	// constant-input falsifier.
	t.Run("negative verification re-trace stays unresolved", func(t *testing.T) {
		site := librarySiteIn(t, ix, vulnParseBytesSym, "Identity")
		flow, _, err := ix.TraceArgumentBound(ctx, site, 0, 16)
		if err != nil {
			t.Fatal(err)
		}
		if flow.Origin != domain.OriginUnknown {
			t.Fatalf("origin=%s, want UNKNOWN", flow.Origin)
		}
		if got := inputOriginVerification(flow.Origin, domain.FalsifierConstantOrGeneratedInput); got == domain.NegativeVerified {
			t.Fatal("a public library formal must not produce a VERIFIED constant-input falsifier")
		}
	})
}

// TestLibraryInputTraceVariants: every argument-trace entry point preserves the
// same exact binding, and the fixture's two sink calls stay distinguishable:
// formal 1 (expected) → first sink, formal 2 (actual) → second sink.
func TestLibraryInputTraceVariants(t *testing.T) {
	ix := fixture(t, "libassertprod")
	if _, _, err := ix.BuildProductShape(context.Background()); err != nil {
		t.Fatalf("BuildProductShape: %v", err)
	}
	ctx := context.Background()
	sites := librarySinkSites(t, ix, vulnParseBytesSym)
	if len(sites) != 2 {
		t.Fatalf("sink sites=%d, want the fixture's two calls: %+v", len(sites), sites)
	}
	first, second := sites[0], sites[1]
	if first.Line == second.Line {
		t.Fatalf("fixture sinks must be separate calls: %+v", sites)
	}

	base, _, err := ix.TraceArgument(ctx, first, 0)
	if err != nil {
		t.Fatal(err)
	}
	w := base.LibraryInput
	if w == nil {
		t.Fatalf("first sink has no witness: %s", base.Summary)
	}
	if base.Origin != domain.OriginUnknown {
		t.Fatalf("first sink origin=%s, want UNKNOWN", base.Origin)
	}
	if w.API.Symbol != "YAMLEq" || w.FormalIndex != 1 || w.FormalName != "expected" || w.FormalType != "string" {
		t.Fatalf("first binding=%+v", w)
	}
	if w.Site != first || w.Arg != 0 {
		t.Fatalf("first witness site=%+v arg=%d, want %+v arg 0", w.Site, w.Arg, first)
	}

	other, _, err := ix.TraceArgument(ctx, second, 0)
	if err != nil {
		t.Fatal(err)
	}
	ow := other.LibraryInput
	if ow == nil {
		t.Fatalf("second sink has no witness: %s", other.Summary)
	}
	if ow.FormalIndex != 2 || ow.FormalName != "actual" {
		t.Fatalf("second binding=%+v, want formal 2 (actual)", ow)
	}
	if ow.Site != second {
		t.Fatalf("second witness site=%+v, want %+v", ow.Site, second)
	}
	if w.API == ow.API && w.FormalIndex == ow.FormalIndex && w.Site == ow.Site {
		t.Fatal("the two bindings are indistinguishable")
	}

	bounded, _, err := ix.TraceArgumentBound(ctx, first, 0, 16)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(bounded.LibraryInput, base.LibraryInput) || bounded.Origin != base.Origin {
		t.Fatalf("bounded trace changed the binding: %+v vs %+v", bounded.LibraryInput, base.LibraryInput)
	}

	all, _, err := ix.TraceAllArguments(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 {
		t.Fatalf("all-arguments flows=%d, want 1 (ParseBytes has one argument)", len(all))
	}
	if !reflect.DeepEqual(all[0].LibraryInput, base.LibraryInput) || all[0].Origin != base.Origin {
		t.Fatalf("all-arguments trace changed the binding: %+v", all[0].LibraryInput)
	}

	allBounded, _, err := ix.TraceAllArgumentsBound(ctx, first, 16)
	if err != nil {
		t.Fatal(err)
	}
	if len(allBounded) != 1 || !reflect.DeepEqual(allBounded[0].LibraryInput, base.LibraryInput) {
		t.Fatalf("bounded all-arguments trace changed the binding: %+v", allBounded)
	}
}

// TestLibraryInputSameLineCalls: two calls on one line are distinct exact sites.
// Column-pinned traces bind the right formal; a line-only location is ambiguous
// and must not produce a witness.
func TestLibraryInputSameLineCalls(t *testing.T) {
	const mod = "example.com/libsamesite"
	ix, _ := libraryModule(t, mod, map[string]string{
		"lib.go": `package libsamesite

import "example.com/dep/vuln"

func SameLine(one, two string) bool {
	vuln.ParseBytes([]byte(one)); vuln.ParseBytes([]byte(two))
	return true
}
`,
	})
	sites := librarySinkSites(t, ix, vulnParseBytesSym)
	if len(sites) != 2 || sites[0].Line != sites[1].Line || sites[0].Column == sites[1].Column {
		t.Fatalf("want two same-line sites with distinct columns: %+v", sites)
	}
	for i, wantFormal := range []int{0, 1} {
		flow := libraryTrace(t, ix, sites[i], 0)
		w := flow.LibraryInput
		if w == nil {
			t.Fatalf("site %d produced no witness: %s", i, flow.Summary)
		}
		if w.FormalIndex != wantFormal {
			t.Fatalf("site %d formal=%d, want %d", i, w.FormalIndex, wantFormal)
		}
		if w.Site != sites[i] {
			t.Fatalf("site %d witness site=%+v, want %+v", i, w.Site, sites[i])
		}
	}

	lineOnly := domain.CallSite{File: sites[0].File, Line: sites[0].Line}
	flow := libraryTrace(t, ix, lineOnly, 0)
	if flow.LibraryInput != nil {
		t.Fatalf("ambiguous line-only location produced a witness: %+v", flow.LibraryInput)
	}
}

// TestLibraryInputEvidenceReferences: a persisted witness references the
// evidence that grounds it, every id resolves, and a replacement without a
// witness drops the stale proof instead of merging it.
func TestLibraryInputEvidenceReferences(t *testing.T) {
	ix := fixture(t, "libassertprod")
	ctx := context.Background()
	if _, _, err := ix.BuildProductShape(ctx); err != nil {
		t.Fatalf("BuildProductShape: %v", err)
	}
	sites := librarySinkSites(t, ix, vulnParseBytesSym)
	if len(sites) == 0 {
		t.Fatal("no fixture sink site")
	}
	flow, evs, err := ix.TraceArgument(ctx, sites[0], 0)
	if err != nil {
		t.Fatal(err)
	}
	if flow.LibraryInput == nil {
		t.Fatalf("no witness: %s", flow.Summary)
	}
	if len(evs) < 2 {
		t.Fatalf("trace evidence=%d, want source snippet + witness record", len(evs))
	}
	witnessEvidence := ""
	for _, e := range evs {
		if e.Source == "source index: library public-formal payload binding" {
			witnessEvidence = e.Content
		}
	}
	for _, want := range []string{
		"api=example.com/libassertprod/assert.YAMLEq", "formal=1:string",
		"sink=example.com/dep/vuln.ParseBytes", "arg=0", "byte-preserving-conversion",
	} {
		if !strings.Contains(witnessEvidence, want) {
			t.Fatalf("witness evidence %q missing %q", witnessEvidence, want)
		}
	}

	graph := &domain.EvidenceGraph{}
	ids := graph.AddArgumentTrace([]domain.DataFlow{flow}, evs)
	if len(ids) != len(evs) {
		t.Fatalf("evidence ids=%d, want %d", len(ids), len(evs))
	}
	if len(flow.LibraryInput.EvidenceIDs) != 0 {
		t.Fatal("the graph must take its own witness copy, not rewrite the caller's")
	}
	stored := graph.DataFlows
	if len(stored) != 1 || stored[0].LibraryInput == nil {
		t.Fatalf("persisted flows=%+v", stored)
	}
	if !reflect.DeepEqual(stored[0].LibraryInput.EvidenceIDs, ids) {
		t.Fatalf("witness ids=%v, want %v", stored[0].LibraryInput.EvidenceIDs, ids)
	}
	for _, id := range stored[0].LibraryInput.EvidenceIDs {
		if graph.EvidenceByID(id) == nil {
			t.Fatalf("witness references unresolvable evidence %s", id)
		}
	}

	// A deeper unwitnessed replacement must not retain the old proof.
	graph.ReplaceArgumentTrace(domain.DataFlow{
		ConditionID: stored[0].ConditionID,
		Arg:         stored[0].Arg,
		Sink:        stored[0].Sink,
		Origin:      domain.OriginUnknown,
	}, nil)
	if len(graph.DataFlows) != 1 {
		t.Fatalf("replacement appended: %d flows", len(graph.DataFlows))
	}
	if graph.DataFlows[0].LibraryInput != nil {
		t.Fatalf("stale witness survived an unwitnessed replacement: %+v", graph.DataFlows[0].LibraryInput)
	}
}

// --- helpers -----------------------------------------------------------------

// libraryModuleForShape is libraryModule without the LIBRARY assertion: shape
// matrix cases include an APPLICATION product.
func libraryModuleForShape(t *testing.T, module string, files map[string]string) (*Index, *domain.ProductShape) {
	t.Helper()
	depAbs, err := filepath.Abs(filepath.Join("..", "..", "testdata", "dep"))
	if err != nil {
		t.Fatal(err)
	}
	gomod := "module " + module + "\n\ngo 1.23\n\n" +
		"require example.com/dep v1.0.0\n\nreplace example.com/dep => " + depAbs + "\n"
	dir := usageModuleGomod(t, gomod, files)
	ix := &Index{Dir: dir}
	shape, _, err := ix.BuildProductShape(context.Background())
	if err != nil {
		t.Fatalf("BuildProductShape(%s): %v", module, err)
	}
	return ix, shape
}

func productPackage(t *testing.T, ix *Index, path string) *packages.Package {
	t.Helper()
	for _, pkg := range ix.pkgs {
		if pkg.PkgPath == path {
			return pkg
		}
	}
	t.Fatalf("product package %s not loaded", path)
	return nil
}

// typePackage resolves an imported package through the type checker's import
// graph — the loader deliberately does not populate packages.Package.Imports.
func typePackage(t *testing.T, pkg *packages.Package, path string) *types.Package {
	t.Helper()
	if pkg == nil || pkg.Types == nil {
		t.Fatal("no typed package")
	}
	for _, imported := range pkg.Types.Imports() {
		if imported.Path() == path {
			return imported
		}
	}
	t.Fatalf("import %s not resolved from %s", path, pkg.PkgPath)
	return nil
}

func libraryFuncDecl(t *testing.T, ix *Index, pkg *packages.Package, method string) *ast.FuncDecl {
	t.Helper()
	decl, _ := ix.funcDecl(libraryMethodObject(t, pkg, method))
	if decl == nil {
		t.Fatalf("declaration %s not found", method)
	}
	return decl
}

// libraryMethodObject finds a package-level function, or a method when the
// symbol is qualified as Type.Method.
func libraryMethodObject(t *testing.T, pkg *packages.Package, symbol string) *types.Func {
	t.Helper()
	if typeName, method, ok := strings.Cut(symbol, "."); ok {
		tn, isType := pkg.Types.Scope().Lookup(typeName).(*types.TypeName)
		if !isType {
			t.Fatalf("type %s not found", typeName)
		}
		named, isNamed := tn.Type().(*types.Named)
		if !isNamed {
			t.Fatalf("%s is not a named type", typeName)
		}
		for i := range named.NumMethods() {
			if m := named.Method(i); m.Name() == method {
				return m
			}
		}
		t.Fatalf("method %s not found", symbol)
	}
	fn, ok := pkg.Types.Scope().Lookup(symbol).(*types.Func)
	if !ok {
		t.Fatalf("function %s not found", symbol)
	}
	return fn
}

func firstFormal(t *testing.T, pkg *packages.Package, symbol string) *types.Var {
	t.Helper()
	fn := libraryMethodObject(t, pkg, symbol)
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Params().Len() == 0 {
		t.Fatalf("%s has no formal", symbol)
	}
	return sig.Params().At(0)
}

// TestLibraryInputMutationAndDerivedGuardsRejected: the integrated-review P1
// shapes fail at the intended check, not incidentally. Handing a mutable payload
// carrier (or an alias of it) to a call that is not part of the proof chain fails
// the walk, and a payload-derived predicate guarding the sink is an unmodeled
// guard even when the payload itself is not named in the condition. Read-only
// uses of the carrier stay admissible.
func TestLibraryInputMutationAndDerivedGuardsRejected(t *testing.T) {
	const mod = "example.com/libbinding"
	ix, _ := libraryModule(t, mod, libraryBindingFixture())
	pkg := productPackage(t, ix, mod)
	declOf := func(name string) *ast.FuncDecl { return libraryFuncDecl(t, ix, pkg, name) }
	paramOf := func(decl *ast.FuncDecl) *types.Var {
		sig := funcSignature(pkg, decl)
		if sig == nil || sig.Params().Len() == 0 {
			t.Fatalf("%s has no formal", decl.Name.Name)
		}
		return sig.Params().At(0)
	}

	for _, function := range []string{
		"MutatingClear", "MutatingCopy", "MutationAlias", "MutationPointer", "MutationUnknownCall",
	} {
		decl := declOf(function)
		objs := map[types.Object]bool{paramOf(decl): true}
		sink := librarySinkCall(t, pkg, decl, vulnParseBytesSym)
		if err := checkCallMutations(pkg, decl, objs, map[*ast.CallExpr]bool{sink: true}, nil); err == nil {
			t.Fatalf("%s: a call receiving the mutable payload carrier must fail the walk", function)
		}
	}

	for _, tc := range []struct {
		function string
		sink     domain.SymbolRef
	}{
		{function: "DerivedPredicateGuard", sink: vulnParseSym},
		{function: "DerivedComparisonGuard", sink: vulnParseBytesSym},
	} {
		decl := declOf(tc.function)
		objs := map[types.Object]bool{paramOf(decl): true}
		tracked := libraryGuardObjects(pkg, decl, objs)
		if len(tracked) != 2 {
			t.Fatalf("%s: payload-derived predicate not tracked: %v", tc.function, tracked)
		}
		sink := librarySinkCall(t, pkg, decl, tc.sink)
		if err := checkPreGuards(pkg, decl, tracked, sink); err == nil {
			t.Fatalf("%s: a payload-derived guard must fail the walk", tc.function)
		}
	}

	// An immutable string carrier may be handed to an arbitrary call: only
	// mutable carriers can be rewritten by a callee.
	strDecl := declOf("DerivedPredicateGuard")
	strObjs := map[types.Object]bool{paramOf(strDecl): true}
	strSink := librarySinkCall(t, pkg, strDecl, vulnParseSym)
	if err := checkCallMutations(pkg, strDecl, strObjs,
		map[*ast.CallExpr]bool{strSink: true}, nil); err != nil {
		t.Fatalf("immutable string carrier must stay admissible: %v", err)
	}

	// len/append and copy-from-the-carrier do not rewrite the visible bytes.
	for _, function := range []string{"ReadOnlyLength", "ReadOnlyCopySource"} {
		decl := declOf(function)
		objs := map[types.Object]bool{paramOf(decl): true}
		sink := librarySinkCall(t, pkg, decl, vulnParseBytesSym)
		if err := checkCallMutations(pkg, decl, objs, map[*ast.CallExpr]bool{sink: true}, nil); err != nil {
			t.Fatalf("%s: read-only carrier use must stay admissible: %v", function, err)
		}
	}
}

// librarySinkCall returns the unique call to sink inside decl's body.
func librarySinkCall(t *testing.T, pkg *packages.Package, decl *ast.FuncDecl, sink domain.SymbolRef) *ast.CallExpr {
	t.Helper()
	var calls []*ast.CallExpr
	ast.Inspect(decl.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		fn, ok := calleeObject(pkg.TypesInfo, call.Fun).(*types.Func)
		if !ok || fn == nil || fn.Pkg() == nil {
			return true
		}
		if fn.Pkg().Path() == sink.Package && fn.Name() == sink.Symbol {
			calls = append(calls, call)
		}
		return true
	})
	if len(calls) != 1 {
		t.Fatalf("%s: want exactly one %s call, got %d", decl.Name.Name, sink.Symbol, len(calls))
	}
	return calls[0]
}

package goanalysis

import (
	"context"
	"errors"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"

	"github.com/davniy/izyan/internal/domain"
)

var vulnSym = domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Parse"}

func fixture(t *testing.T, name string) *Index {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("..", "..", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	ix := &Index{Dir: abs, Build: testProduct()}
	return ix
}

func TestModuleUsageAttributesNestedDependency(t *testing.T) {
	ix := fixture(t, "nestedprod")
	parent, err := ix.ModuleUsage(context.Background(), "example.com/nesteddep")
	if err != nil {
		t.Fatal(err)
	}
	if len(parent) != 1 || parent[0].ModuleOwner != "example.com/nesteddep/v2" {
		t.Fatalf("parent prefix scan must retain foreign-owner site as uncertain: %+v", parent)
	}
	child, err := ix.ModuleUsage(context.Background(), "example.com/nesteddep/v2")
	if err != nil {
		t.Fatal(err)
	}
	if len(child) != 1 || child[0].Callee != "example.com/nesteddep/v2.Child" {
		t.Fatalf("child usage=%+v, want Child call", child)
	}
}

func TestFindCallers(t *testing.T) {
	ix := fixture(t, "constprod")
	sites, err := ix.FindCallers(context.Background(), vulnSym)
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 1 {
		t.Fatalf("callers=%+v", sites)
	}
	if sites[0].Function != "main" {
		t.Fatalf("enclosing=%q", sites[0].Function)
	}
}

func TestFindSymbol(t *testing.T) {
	ix := fixture(t, "constprod")
	cs, err := ix.FindSymbol(context.Background(), vulnSym)
	if err != nil {
		t.Fatal(err)
	}
	if cs.Function != "Parse" || !filepath.IsAbs(cs.File) {
		t.Fatalf("got %+v", cs)
	}
}

func TestEnclosingFuncAt(t *testing.T) {
	ix := fixture(t, "constprod")
	cs, err := ix.FindSymbol(context.Background(), vulnSym)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := ix.EnclosingFuncAt(context.Background(), vulnSym.Package, filepath.Base(cs.File), cs.Line)
	if err != nil {
		t.Fatalf("EnclosingFuncAt failed: %v", err)
	}
	if ref.Symbol != "Parse" {
		t.Fatalf("expected Parse, got %+v", ref)
	}
}

func TestTraceArgumentConstant(t *testing.T) {
	ix := fixture(t, "constprod")
	sites, _ := ix.FindCallers(context.Background(), vulnSym)
	flow, ev, err := ix.TraceArgument(context.Background(), sites[0], 0)
	if err != nil {
		t.Fatal(err)
	}
	if flow.Origin != domain.OriginConstant {
		t.Fatalf("origin=%s want CONSTANT (%s)", flow.Origin, flow.Summary)
	}
	if len(ev) == 0 {
		t.Fatal("expected source evidence")
	}
}

func TestTraceArgumentExternal(t *testing.T) {
	ix := fixture(t, "extprod")
	sites, _ := ix.FindCallers(context.Background(), vulnSym)
	flow, _, err := ix.TraceArgument(context.Background(), sites[0], 0)
	if err != nil {
		t.Fatal(err)
	}
	if flow.Origin != domain.OriginExternalUntrusted {
		t.Fatalf("origin=%s want EXTERNAL_UNTRUSTED (%s)", flow.Origin, flow.Summary)
	}
}

func TestTraceParamHop(t *testing.T) {
	ix := fixture(t, "validprod")
	sites, err := ix.FindCallers(context.Background(), vulnSym)
	if err != nil || len(sites) != 1 {
		t.Fatalf("sites=%v err=%v", sites, err)
	}
	flow, _, err := ix.TraceArgument(context.Background(), sites[0], 0)
	if err != nil {
		t.Fatal(err)
	}
	// arg of vuln.Parse in handle(s) is parameter s -> caller passes "abcdef"
	if flow.Origin != domain.OriginConstant {
		t.Fatalf("origin=%s want CONSTANT via caller hop (%s)", flow.Origin, flow.Summary)
	}
}

func TestFindValidations(t *testing.T) {
	ix := fixture(t, "validprod")
	sites, _ := ix.FindCallers(context.Background(), vulnSym)
	vals, _, err := ix.FindValidations(context.Background(), sites[0], 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(vals) != 1 {
		t.Fatalf("validations=%+v", vals)
	}
	if vals[0].Property != "len(s) < 4" {
		t.Fatalf("property=%q", vals[0].Property)
	}
}

func TestScanDynamicFuncValue(t *testing.T) {
	ix := fixture(t, "funcvalprod")
	markers, err := ix.ScanDynamic(context.Background(), vulnSym)
	if err != nil {
		t.Fatal(err)
	}
	var fv bool
	for _, m := range markers {
		if m.Kind == "func_value" {
			fv = true
		}
	}
	if !fv {
		t.Fatalf("expected func_value marker, got %+v", markers)
	}
}

func TestFindEntrypoints(t *testing.T) {
	ix := fixture(t, "constprod")
	eps, err := ix.FindEntrypoints(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 1 || eps[0].Kind != "main" {
		t.Fatalf("entrypoints=%+v", eps)
	}
}

func TestFindListeners(t *testing.T) {
	ix := fixture(t, "srvprod")
	eps, err := ix.FindListeners(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 1 {
		t.Fatalf("listeners=%+v", eps)
	}
	if eps[0].Kind != "listener" || eps[0].Function != "serve" {
		t.Fatalf("got %+v", eps[0])
	}
}

func TestTraceFieldOrigin(t *testing.T) {
	ix := fixture(t, "fieldprod")
	sites, err := ix.FindCallers(context.Background(), vulnSym)
	if err != nil || len(sites) != 1 {
		t.Fatalf("sites=%v err=%v", sites, err)
	}
	// the field-hop chain needs the deep-trace budget (default is 2).
	flow, _, err := ix.TraceArgumentBound(context.Background(), sites[0], 0, 6)
	if err != nil {
		t.Fatal(err)
	}
	// r.s <- setS param <- cfg.s <- mapstructure tag (no literal writes).
	if flow.Origin != domain.OriginConfiguration {
		t.Fatalf("origin=%s want CONFIGURATION via field write sites (%s)",
			flow.Origin, flow.Summary)
	}
	if !strings.Contains(flow.Summary, "mapstructure") {
		t.Fatalf("tag-based provenance missing from summary: %s", flow.Summary)
	}
}

func TestFieldWriteGuards(t *testing.T) {
	ix := fixture(t, "fieldprod")
	sites, err := ix.FindCallers(context.Background(), vulnSym)
	if err != nil || len(sites) != 1 {
		t.Fatalf("sites=%v err=%v", sites, err)
	}
	vals, _, err := ix.FindValidations(context.Background(), sites[0], 0)
	if err != nil {
		t.Fatal(err)
	}
	var sanitize, covers bool
	for _, v := range vals {
		if v.Guard && strings.Contains(v.Property, "sanitize-switch") {
			sanitize = true
		}
		if v.Covers != nil && v.Covers.Line == sites[0].Line {
			covers = true
		}
	}
	if !sanitize {
		t.Fatalf("no sanitize-switch guard recorded: %+v", vals)
	}
	if !covers {
		t.Fatalf("field write sites fully bounded but no Covers record: %+v", vals)
	}
}

// The rm6m setPrefetchSize shape: the switch compares `size` while every
// clause assigns a different sanitized var; the field write wraps the
// local in `int(fs.Bytes())`. Covers must still be emitted — the compared
// var is bounded on both sides and the default converts it.
func TestFieldWriteGuardsRangeGated(t *testing.T) {
	ix := fixture(t, "fieldprod")
	sites, err := ix.FindCallers(context.Background(),
		domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Qos"})
	if err != nil || len(sites) != 1 {
		t.Fatalf("sites=%v err=%v", sites, err)
	}
	vals, _, err := ix.FindValidations(context.Background(), sites[0], 0)
	if err != nil {
		t.Fatal(err)
	}
	var gated, covers bool
	for _, v := range vals {
		if v.Guard && strings.Contains(v.Property, "range-gated") {
			gated = true
		}
		if v.Covers != nil && v.Covers.Line == sites[0].Line {
			covers = true
		}
	}
	if !gated {
		t.Fatalf("no range-gated sanitize-switch guard recorded: %+v", vals)
	}
	if !covers {
		t.Fatalf("range-gated write sites fully bounded but no Covers record: %+v", vals)
	}
	// The range-gated guard must carry its enforced numeric range:
	// size<0 → fs=0, size>1024 → fs=1024, default fs=size → [0,1024].
	var gotLo, gotHi bool
	for _, v := range vals {
		if v.BoundLow != nil && *v.BoundLow == 0 {
			gotLo = true
		}
		if v.BoundHigh != nil && *v.BoundHigh == 1024 {
			gotHi = true
		}
	}
	if !gotLo || !gotHi {
		t.Fatalf("expected bound range [0,1024] on guard records: %+v", vals)
	}
}

// A switch that bounds the compared var on one side only must not be a
// guard for a different var — the default assignment of an unbounded
// half-range is not bounded.
func TestSanitizeSwitchOneSidedNoGuard(t *testing.T) {
	ix := fixture(t, "onesidedprod")
	sites, err := ix.FindCallers(context.Background(),
		domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Qos"})
	if err != nil || len(sites) != 1 {
		t.Fatalf("sites=%v err=%v", sites, err)
	}
	vals, _, err := ix.FindValidations(context.Background(), sites[0], 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range vals {
		if v.Covers != nil && v.Covers.Line == sites[0].Line {
			t.Fatalf("one-sided switch wrongly covers the sink: %+v", vals)
		}
	}
}

// &r.limit hands out a writable alias — fieldWriteGuards must refuse to
// emit a Covers record even though the only syntactic write is clamped.
func TestFieldWriteGuardsAddressTaken(t *testing.T) {
	ix := fixture(t, "addrtakenprod")
	sites, err := ix.FindCallers(context.Background(),
		domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Qos"})
	if err != nil || len(sites) != 1 {
		t.Fatalf("sites=%v err=%v", sites, err)
	}
	vals, _, err := ix.FindValidations(context.Background(), sites[0], 0)
	if err != nil {
		t.Fatal(err)
	}
	var noted bool
	for _, v := range vals {
		if v.Covers != nil && v.Covers.Line == sites[0].Line {
			t.Fatalf("address-taken field wrongly covers the sink: %+v", vals)
		}
		if strings.Contains(v.Property, "address taken") {
			noted = true
		}
	}
	if !noted {
		t.Fatalf("expected address-taken limitation record: %+v", vals)
	}
}

// reflectprod imports reflect for both a read-only TypeOf call and a
// reflect.Value.SetInt write — the import marker and the write marker are
// distinct kinds.
func TestScanDynamicReflectWrite(t *testing.T) {
	ix := fixture(t, "reflectprod")
	markers, err := ix.ScanDynamic(context.Background(), vulnSym)
	if err != nil {
		t.Fatal(err)
	}
	var bare, write, uwrite, uptr bool
	for _, m := range markers {
		switch m.Kind {
		case "reflect":
			bare = true
		case "reflect_write":
			write = true
			if !strings.Contains(m.Detail, "SetInt") {
				t.Fatalf("reflect_write detail=%q", m.Detail)
			}
		case "unsafe_write":
			uwrite = true
		case "unsafe_ptr":
			uptr = true
		}
	}
	if !bare {
		t.Fatal("expected bare reflect import marker")
	}
	if !write {
		t.Fatalf("expected reflect_write marker for Value.SetInt, got %+v", markers)
	}
	if !uwrite {
		t.Fatalf("expected unsafe_write marker for deref store, got %+v", markers)
	}
	if !uptr {
		t.Fatalf("expected unsafe_ptr marker for Pointer conversion, got %+v", markers)
	}
}

// hasExportedCoveredField gates whether a reflect_write marker weakens a
// guard-based FALSE: only an exported covered field is reachable to
// reflect.Value.Set*.
func TestHasExportedCoveredField(t *testing.T) {
	mkCase := func(props ...string) *domain.AnalysisCase {
		c := &domain.AnalysisCase{}
		for _, p := range props {
			c.EvidenceGraph.Validations = append(c.EvidenceGraph.Validations,
				domain.Validation{Property: p})
		}
		return c
	}
	claim := domain.Claim{ConditionID: "C1"}

	if !hasExportedCoveredField(
		mkCase("cond=C1 field-write Mode: sanitize-switch"), claim) {
		t.Fatal("exported covered field must report true")
	}
	if hasExportedCoveredField(
		mkCase("cond=C1 field-write mode: sanitize-switch"), claim) {
		t.Fatal("unexported covered field must report false")
	}
	if hasExportedCoveredField(
		mkCase("cond=C2 field-write Mode: sanitize-switch"), claim) {
		t.Fatal("field covered for a different condition must not count")
	}
	if hasExportedCoveredField(mkCase("cond=C1 count > max → count = max"), claim) {
		t.Fatal("no field-backed guard must report false")
	}
}

// Dep-internal provenance (backlog B3): an unexported subject has no
// product callers — its arguments are fed inside the dependency itself.
// The chain `c.r` <- bufio.NewReader(conn) <- net.Dial must resolve to
// EXTERNAL_UNTRUSTED: the peer boundary is the net.Conn value.
func TestTraceDepInternalPeerOrigin(t *testing.T) {
	ix := fixture(t, "wireprod")
	subj := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "readRecord"}
	sites, err := ix.FindDepCallers(context.Background(), subj)
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 1 || sites[0].Function != "Next" {
		t.Fatalf("dep callers=%+v", sites)
	}
	flow, _, err := ix.TraceArgumentBound(context.Background(), sites[0], 0, 16)
	if err != nil {
		t.Fatal(err)
	}
	if flow.Origin != domain.OriginExternalUntrusted {
		t.Fatalf("origin=%s want EXTERNAL_UNTRUSTED (%s)", flow.Origin, flow.Summary)
	}
}

// Instantiation narrowing: an interface impl that is never created in
// non-test code cannot be a dispatch target — depCone must not contain
// it, and its methods must not inherit the interface's call sites.
func TestInstantiatedNarrowing(t *testing.T) {
	ix := fixture(t, "regprod")
	if err := ix.load(context.Background()); err != nil {
		t.Fatal(err)
	}
	cone := ix.depCone("example.com/dep")
	if cone == nil {
		t.Fatal("depCone nil — module load failed")
	}
	if !cone["example.com/dep/vuln.RealRunner.Run"] {
		t.Fatal("RealRunner.Run missing from cone — registered impl dropped")
	}
	if cone["example.com/dep/vuln.NeverRunner.Run"] {
		t.Fatal("NeverRunner.Run in cone — uninstantiated impl dispatched")
	}
	dead := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "NeverRunner.Run"}
	if got := ix.ifaceCallerRefs(dead); len(got) != 0 {
		t.Fatalf("NeverRunner.Run inherited iface callers: %+v", got)
	}
	live := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "RealRunner.Run"}
	if got := ix.ifaceCallerRefs(live); len(got) == 0 {
		t.Fatal("RealRunner.Run lost its iface callers — narrowing over-fired")
	}
}

// A product package that failed to type-check never entered the
// instantiation inventory: absence there cannot narrow — the interface
// caller set must stay open exactly as if the impl were instantiated.
func TestIfaceCallerRefsSkippedPackageBlocksNarrowing(t *testing.T) {
	dir := usageModule(t, map[string]string{
		"main.go": `package main

func main() {}
`,
		"broken/broken.go": `package broken

func Broken() int { return undefinedIdentifier }
`,
	})
	ix := &Index{Dir: dir}
	if err := ix.load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := ix.loadExtra(context.Background(), "example.com/dep/vuln"); err != nil {
		t.Fatal(err)
	}
	dead := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "NeverRunner.Run"}
	if got := ix.ifaceCallerRefs(dead); len(got) == 0 {
		t.Fatal("a skipped product package must keep iface callers — narrowing over-fired")
	}
}

// Dispatch-key narrowing: an impl registered under a key the product
// never passes cannot be a target of the `runners[name].Run` site —
// even though it is instantiated (the registry literal counts).
func TestDispatchKeyNarrowing(t *testing.T) {
	ix := fixture(t, "regprod")
	if err := ix.load(context.Background()); err != nil {
		t.Fatal(err)
	}
	cone := ix.depCone("example.com/dep")
	if cone == nil {
		t.Fatal("depCone nil — module load failed")
	}
	if !cone["example.com/dep/vuln.RealRunner.Run"] {
		t.Fatal("RealRunner.Run missing — key 'real' must dispatch to it")
	}
	if cone["example.com/dep/vuln.OtherRunner.Run"] {
		t.Fatal("OtherRunner.Run in cone — unreachable key 'other' dispatched")
	}
	off := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "OtherRunner.Run"}
	depPkg := ix.pkgByPath(context.Background(), "example.com/dep/vuln")
	if depPkg == nil {
		t.Fatal("dep pkg not loaded")
	}
	if got := ix.callersOf(depPkg, off); len(got) != 0 {
		t.Fatalf("OtherRunner.Run inherited iface callers past key narrowing: %+v", got)
	}
}

// The dep-internal caller may live in a sibling package of the same
// module — a package-scoped scan would miss it and keep a false VERIFIED.
func TestDepCallerSiblingPackage(t *testing.T) {
	ix := fixture(t, "xmodprod")
	v := Verifier{Source: ix}
	c := &domain.AnalysisCase{}
	c.Vulnerability.Module = "example.com/dep5"

	subj := domain.SymbolRef{Package: "example.com/dep5/deep", Symbol: "Sink"}
	callers, _, unbounded, err := ix.DepInvocationState(context.Background(), subj)
	if err != nil {
		t.Fatal(err)
	}
	if callers == 0 {
		t.Fatal("dep caller in sibling package dep5/driver not found — scan stayed package-scoped")
	}
	if unbounded {
		t.Fatal("dep5/deep is imported only inside its own module — caller set is bounded")
	}
	nv := &domain.NegativeVerification{Status: domain.NegativeVerified}
	claim := domain.Claim{ConditionID: "C-REACH", Result: domain.ClaimFalse}
	out := v.verifyReachableFalse(context.Background(), c, claim, nv,
		[]domain.SymbolRef{subj}, map[string][]domain.CallSite{})
	got := out.NegativeVerification
	if got == nil || got.Status != domain.NegativeInsufficientScope {
		t.Fatalf("nv=%+v — sibling-package dep caller must demote the falsifier", got)
	}
}

// With a multi-module advisory whose entries are BOTH linked, the dep
// invocation gate must cover subjects of every selected module — a
// second module's live dep caller is not excused by Vulnerability.Module
// naming only the first.
func TestDepCallerMultiModuleUnion(t *testing.T) {
	ix := fixture(t, "xmodprod")
	v := Verifier{Source: ix}
	c := &domain.AnalysisCase{}
	c.Vulnerability.Module = "example.com/dep" // first module — not the
	// one owning the subject
	c.Affected = &domain.AffectedResult{
		SelectedModules: []string{"example.com/dep", "example.com/dep5"},
	}
	subj := domain.SymbolRef{Package: "example.com/dep5/deep", Symbol: "Sink"}
	nv := &domain.NegativeVerification{Status: domain.NegativeVerified}
	claim := domain.Claim{ConditionID: "C-REACH", Result: domain.ClaimFalse}
	out := v.verifyReachableFalse(context.Background(), c, claim, nv,
		[]domain.SymbolRef{subj}, map[string][]domain.CallSite{})
	got := out.NegativeVerification
	if got == nil || got.Status != domain.NegativeInsufficientScope {
		t.Fatalf("nv=%+v — second-module subject's dep caller must demote the falsifier", got)
	}
}

// Same dep scope, opposite origin: a subject only invoked with constants
// inside the dep resolves a non-external origin — traced evidence that
// contradicts the unexported+peer heuristic.
func TestTraceDepInternalConstantOrigin(t *testing.T) {
	ix := fixture(t, "wireprod")
	subj := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "parseConstant"}
	sites, err := ix.FindDepCallers(context.Background(), subj)
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 1 || sites[0].Function != "Fixed" {
		t.Fatalf("dep callers=%+v", sites)
	}
	flow, _, err := ix.TraceArgumentBound(context.Background(), sites[0], 0, 16)
	if err != nil {
		t.Fatal(err)
	}
	if flow.Origin != domain.OriginConstant {
		t.Fatalf("origin=%s want CONSTANT (%s)", flow.Origin, flow.Summary)
	}
}

// Input-verification FALSE must trace dep-internal callers for subjects
// of EVERY selected module: subject one has only a safe product call,
// subject two lives in the second module and is invoked solely inside
// the dependency with external input — a single-module membership check
// would skip it and keep VERIFIED-FALSE.
func TestVerifyInputFalseSecondModule(t *testing.T) {
	ix := fixture(t, "duomod")
	v := Verifier{Source: ix}
	c := &domain.AnalysisCase{}
	c.Vulnerability.Module = "example.com/dep"
	c.Affected = &domain.AffectedResult{
		SelectedModules: []string{"example.com/dep", "example.com/dep5"},
	}
	subjects := []domain.SymbolRef{
		{Package: "example.com/dep/vuln", Symbol: "Parse"},
		{Package: "example.com/dep5/deep", Symbol: "Sink"},
	}
	nv := &domain.NegativeVerification{Status: domain.NegativeVerified}
	claim := domain.Claim{ConditionID: "C-INPUT", Result: domain.ClaimFalse}
	out := v.verifyInputFalse(context.Background(), c, claim, nv, subjects, 0)
	got := out.NegativeVerification
	if got == nil || got.Status != domain.NegativeContradicted {
		t.Fatalf("nv=%+v — external input through a second-module dep caller must contradict FALSE", got)
	}
}

func TestInputOriginVerificationUnknownValue(t *testing.T) {
	for _, origin := range []domain.DataOrigin{"", domain.OriginUnknown, "FUTURE_ORIGIN"} {
		if got := inputOriginVerification(origin, ""); got != domain.NegativeInsufficientScope {
			t.Errorf("origin %q: status = %s, want INSUFFICIENT_SCOPE", origin, got)
		}
	}
	for _, origin := range []domain.DataOrigin{domain.OriginConstant, domain.OriginGenerated} {
		if got := inputOriginVerification(origin, ""); got != domain.NegativeVerified {
			t.Errorf("origin %q: status = %s, want VERIFIED", origin, got)
		}
	}
	if got := inputOriginVerification(domain.OriginConfiguration, ""); got != domain.NegativeContradicted {
		t.Errorf("OriginConfiguration with empty falsifier: got %s, want CONTRADICTED", got)
	}
	if got := inputOriginVerification(domain.OriginConfiguration, domain.FalsifierTrustedInfrastructure); got != domain.NegativeVerified {
		t.Errorf("OriginConfiguration with FalsifierTrustedInfrastructure: got %s, want VERIFIED", got)
	}
}

func TestMethodInAnyInterface(t *testing.T) {
	ix := fixture(t, "constprod")
	if err := ix.load(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Standard library interface methods
	for _, m := range []string{"Read", "Write", "Close", "ServeHTTP", "String"} {
		if !ix.methodInAnyInterface(m) {
			t.Errorf("expected %s to be recognized as an interface method", m)
		}
	}

	// Concrete non-interface methods
	for _, m := range []string{"SendFileBytes", "SendFileUncompressed", "NonExistentMethod123"} {
		if ix.methodInAnyInterface(m) {
			t.Errorf("expected %s NOT to be recognized as an interface method", m)
		}
	}
}

func TestModuleEdges_LocalMethodValue(t *testing.T) {
	dir := t.TempDir()
	mod := `module example.com/testpkg

go 1.22
`
	src := `package testpkg

type Greeter interface {
	Greet() string
}

type greeterImpl struct{}

func (greeterImpl) Greet() string { return "hello" }

var _ Greeter = greeterImpl{}

func Run(g Greeter) string {
	fn := g.Greet
	return fn()
}
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(mod), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "testpkg.go"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	fset := token.NewFileSet()
	cfg := &packages.Config{
		Mode: loadMode,
		Dir:  dir,
		Fset: fset,
	}
	pkgs, err := packages.Load(cfg, "example.com/testpkg")
	if err != nil || len(pkgs) == 0 {
		t.Fatalf("load testpkg: pkgs=%d err=%v", len(pkgs), err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		t.Fatal("package load had errors")
	}

	ix := &Index{Dir: dir, pkgs: pkgs, fset: fset}
	edges, opaque := ix.moduleEdges(pkgs, "example.com/testpkg")

	// 1. Run -> Greeter.Greet edge
	if !edges["example.com/testpkg.Run"]["example.com/testpkg.Greeter.Greet"] {
		t.Fatalf("expected edge Run -> Greeter.Greet, got: %v", edges["example.com/testpkg.Run"])
	}
	// 2. Greeter.Greet -> greeterImpl.Greet edge
	if !edges["example.com/testpkg.Greeter.Greet"]["example.com/testpkg.greeterImpl.Greet"] {
		t.Fatalf("expected edge Greeter.Greet -> greeterImpl.Greet, got: %v", edges["example.com/testpkg.Greeter.Greet"])
	}
	// 3. Run is NOT in opaque callers
	if opaque["example.com/testpkg.Run"] {
		t.Fatalf("Run should not be marked opaque")
	}
}

func TestModuleEdges_LocalFuncVariable(t *testing.T) {
	dir := t.TempDir()
	mod := `module example.com/testpkg

go 1.22
`
	src := `package testpkg

func Target(s string) string { return s }

func Caller() string {
	fn := Target
	return fn("test")
}
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(mod), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "testpkg.go"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	fset := token.NewFileSet()
	cfg := &packages.Config{
		Mode: loadMode,
		Dir:  dir,
		Fset: fset,
	}
	pkgs, err := packages.Load(cfg, "example.com/testpkg")
	if err != nil || len(pkgs) == 0 {
		t.Fatalf("load testpkg: pkgs=%d err=%v", len(pkgs), err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		t.Fatal("package load had errors")
	}

	ix := &Index{Dir: dir, pkgs: pkgs, fset: fset}
	edges, opaque := ix.moduleEdges(pkgs, "example.com/testpkg")

	if !edges["example.com/testpkg.Caller"]["example.com/testpkg.Target"] {
		t.Fatalf("expected edge Caller -> Target, got: %v", edges["example.com/testpkg.Caller"])
	}
	if opaque["example.com/testpkg.Caller"] {
		t.Fatalf("Caller should not be marked opaque")
	}
}

func TestModuleEdges_LocalMethodValue_Concrete(t *testing.T) {
	dir := t.TempDir()
	mod := `module example.com/testpkg

go 1.22
`
	src := `package testpkg

type Service struct{}

func (s *Service) DoWork() string { return "done" }

func Caller(s *Service) string {
	fn := s.DoWork
	return fn()
}
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(mod), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "testpkg.go"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	fset := token.NewFileSet()
	cfg := &packages.Config{
		Mode: loadMode,
		Dir:  dir,
		Fset: fset,
	}
	pkgs, err := packages.Load(cfg, "example.com/testpkg")
	if err != nil || len(pkgs) == 0 {
		t.Fatalf("load testpkg: pkgs=%d err=%v", len(pkgs), err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		t.Fatal("package load had errors")
	}

	ix := &Index{Dir: dir, pkgs: pkgs, fset: fset}
	edges, opaque := ix.moduleEdges(pkgs, "example.com/testpkg")

	if !edges["example.com/testpkg.Caller"]["example.com/testpkg.Service.DoWork"] {
		t.Fatalf("expected edge Caller -> Service.DoWork, got: %v", edges["example.com/testpkg.Caller"])
	}
	if opaque["example.com/testpkg.Caller"] {
		t.Fatalf("Caller should not be marked opaque")
	}
}

func TestModuleEdges_UnresolvableFuncVar(t *testing.T) {
	dir := t.TempDir()
	mod := `module example.com/testpkg

go 1.22
`
	src := `package testpkg

func Caller(fn func() string) string {
	return fn()
}
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(mod), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "testpkg.go"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	fset := token.NewFileSet()
	cfg := &packages.Config{
		Mode: loadMode,
		Dir:  dir,
		Fset: fset,
	}
	pkgs, err := packages.Load(cfg, "example.com/testpkg")
	if err != nil || len(pkgs) == 0 {
		t.Fatalf("load testpkg: pkgs=%d err=%v", len(pkgs), err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		t.Fatal("package load had errors")
	}

	ix := &Index{Dir: dir, pkgs: pkgs, fset: fset}
	_, opaque := ix.moduleEdges(pkgs, "example.com/testpkg")

	if !opaque["example.com/testpkg.Caller"] {
		t.Fatalf("Caller should be marked opaque when func var is unresolvable")
	}
}

func TestModuleEdges_ExternalInterfaceCall(t *testing.T) {
	dir := t.TempDir()
	mod := `module example.com/testpkg

go 1.22
`
	src := `package testpkg

import "io"

func Caller(c io.Closer) error {
	return c.Close()
}
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(mod), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "testpkg.go"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	fset := token.NewFileSet()
	cfg := &packages.Config{
		Mode: loadMode,
		Dir:  dir,
		Fset: fset,
	}
	pkgs, err := packages.Load(cfg, "example.com/testpkg")
	if err != nil || len(pkgs) == 0 {
		t.Fatalf("load testpkg: pkgs=%d err=%v", len(pkgs), err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		t.Fatal("package load had errors")
	}

	ix := &Index{Dir: dir, pkgs: pkgs, fset: fset}
	_, opaque := ix.moduleEdges(pkgs, "example.com/testpkg")

	if opaque["example.com/testpkg.Caller"] {
		t.Fatalf("Caller should not be marked opaque when invoking external interface method")
	}
}

func TestModuleEdges_ConditionalBranchAssignment(t *testing.T) {
	dir := t.TempDir()
	mod := `module example.com/testpkg

go 1.22
`
	src := `package testpkg

func BranchA() string { return "a" }
func BranchB() string { return "b" }

func Caller(cond bool) string {
	var fn func() string
	if cond {
		fn = BranchA
	} else {
		fn = BranchB
	}
	return fn()
}
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(mod), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "testpkg.go"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	fset := token.NewFileSet()
	cfg := &packages.Config{
		Mode: loadMode,
		Dir:  dir,
		Fset: fset,
	}
	pkgs, err := packages.Load(cfg, "example.com/testpkg")
	if err != nil || len(pkgs) == 0 {
		t.Fatalf("load testpkg: pkgs=%d err=%v", len(pkgs), err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		t.Fatal("package load had errors")
	}

	ix := &Index{Dir: dir, pkgs: pkgs, fset: fset}
	edges, opaque := ix.moduleEdges(pkgs, "example.com/testpkg")

	if !edges["example.com/testpkg.Caller"]["example.com/testpkg.BranchA"] {
		t.Fatalf("expected edge Caller -> BranchA, got: %v", edges["example.com/testpkg.Caller"])
	}
	if !edges["example.com/testpkg.Caller"]["example.com/testpkg.BranchB"] {
		t.Fatalf("expected edge Caller -> BranchB, got: %v", edges["example.com/testpkg.Caller"])
	}
	if opaque["example.com/testpkg.Caller"] {
		t.Fatalf("Caller should not be marked opaque")
	}
}

func TestModuleEdges_StructFieldFunc(t *testing.T) {
	dir := t.TempDir()
	mod := `module example.com/testpkg

go 1.22
`
	src := `package testpkg

type Target struct{}
func (Target) Action() {}

type Runner struct {
	runFn func()
}

func NewRunner(t *Target) *Runner {
	return &Runner{runFn: t.Action}
}

func (r *Runner) Execute() {
	r.runFn()
}
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(mod), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "testpkg.go"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	fset := token.NewFileSet()
	cfg := &packages.Config{
		Mode: loadMode,
		Dir:  dir,
		Fset: fset,
	}
	pkgs, err := packages.Load(cfg, "example.com/testpkg")
	if err != nil || len(pkgs) == 0 {
		t.Fatalf("load testpkg: pkgs=%d err=%v", len(pkgs), err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		t.Fatal("package load had errors")
	}

	ix := &Index{Dir: dir, pkgs: pkgs, fset: fset}
	edges, opaque := ix.moduleEdges(pkgs, "example.com/testpkg")

	if !edges["example.com/testpkg.Runner.Execute"]["example.com/testpkg.Target.Action"] {
		t.Fatalf("expected edge Runner.Execute -> Target.Action, got: %v", edges["example.com/testpkg.Runner.Execute"])
	}
	if opaque["example.com/testpkg.Runner.Execute"] {
		t.Fatalf("Runner.Execute should not be marked opaque")
	}
}

func TestModuleEdges_StructFieldFunc_AssignStmt(t *testing.T) {
	dir := t.TempDir()
	mod := `module example.com/testpkg

go 1.22
`
	src := `package testpkg

type Target struct{}
func (Target) Action() {}

type Runner struct {
	runFn func()
}

func Setup(r *Runner, t *Target) {
	r.runFn = t.Action
}

func (r *Runner) Execute() {
	r.runFn()
}
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(mod), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "testpkg.go"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	fset := token.NewFileSet()
	cfg := &packages.Config{
		Mode: loadMode,
		Dir:  dir,
		Fset: fset,
	}
	pkgs, err := packages.Load(cfg, "example.com/testpkg")
	if err != nil || len(pkgs) == 0 {
		t.Fatalf("load testpkg: pkgs=%d err=%v", len(pkgs), err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		t.Fatal("package load had errors")
	}

	ix := &Index{Dir: dir, pkgs: pkgs, fset: fset}
	edges, opaque := ix.moduleEdges(pkgs, "example.com/testpkg")

	if !edges["example.com/testpkg.Runner.Execute"]["example.com/testpkg.Target.Action"] {
		t.Fatalf("expected edge Runner.Execute -> Target.Action, got: %v", edges["example.com/testpkg.Runner.Execute"])
	}
	if opaque["example.com/testpkg.Runner.Execute"] {
		t.Fatalf("Runner.Execute should not be marked opaque")
	}
}

func TestModuleEdges_StructFieldFunc_Interface(t *testing.T) {
	dir := t.TempDir()
	mod := `module example.com/testpkg

go 1.22
`
	src := `package testpkg

type Greeter interface {
	Greet() string
}

type greeterImpl struct{}

func (greeterImpl) Greet() string { return "hello" }

var _ Greeter = greeterImpl{}

type Runner struct {
	greetFn func() string
}

func NewRunner(g Greeter) *Runner {
	return &Runner{greetFn: g.Greet}
}

func (r *Runner) Execute() string {
	return r.greetFn()
}
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(mod), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "testpkg.go"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	fset := token.NewFileSet()
	cfg := &packages.Config{
		Mode: loadMode,
		Dir:  dir,
		Fset: fset,
	}
	pkgs, err := packages.Load(cfg, "example.com/testpkg")
	if err != nil || len(pkgs) == 0 {
		t.Fatalf("load testpkg: pkgs=%d err=%v", len(pkgs), err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		t.Fatal("package load had errors")
	}

	ix := &Index{Dir: dir, pkgs: pkgs, fset: fset}
	edges, opaque := ix.moduleEdges(pkgs, "example.com/testpkg")

	// 1. Runner.Execute -> Greeter.Greet
	if !edges["example.com/testpkg.Runner.Execute"]["example.com/testpkg.Greeter.Greet"] {
		t.Fatalf("expected edge Runner.Execute -> Greeter.Greet, got: %v", edges["example.com/testpkg.Runner.Execute"])
	}
	// 2. Greeter.Greet -> greeterImpl.Greet
	if !edges["example.com/testpkg.Greeter.Greet"]["example.com/testpkg.greeterImpl.Greet"] {
		t.Fatalf("expected edge Greeter.Greet -> greeterImpl.Greet, got: %v", edges["example.com/testpkg.Greeter.Greet"])
	}
	// 3. Runner.Execute is not opaque
	if opaque["example.com/testpkg.Runner.Execute"] {
		t.Fatalf("Runner.Execute should not be marked opaque")
	}
}

func TestModuleEdges_PackageLevelFuncVar(t *testing.T) {
	dir := t.TempDir()
	mod := `module example.com/testpkg

go 1.22
`
	src := `package testpkg

func Target() string { return "target" }

var fn = Target

func Caller() string {
	return fn()
}
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(mod), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "testpkg.go"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	fset := token.NewFileSet()
	cfg := &packages.Config{
		Mode: loadMode,
		Dir:  dir,
		Fset: fset,
	}
	pkgs, err := packages.Load(cfg, "example.com/testpkg")
	if err != nil || len(pkgs) == 0 {
		t.Fatalf("load testpkg: pkgs=%d err=%v", len(pkgs), err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		t.Fatal("package load had errors")
	}

	ix := &Index{Dir: dir, pkgs: pkgs, fset: fset}
	edges, opaque := ix.moduleEdges(pkgs, "example.com/testpkg")

	if !edges["example.com/testpkg.Caller"]["example.com/testpkg.Target"] {
		t.Fatalf("expected edge Caller -> Target, got: %v", edges["example.com/testpkg.Caller"])
	}
	if opaque["example.com/testpkg.Caller"] {
		t.Fatalf("Caller should not be marked opaque")
	}
}

func TestModuleEdges_StructFieldFunc_Unresolvable(t *testing.T) {
	dir := t.TempDir()
	mod := `module example.com/testpkg

go 1.22
`
	src := `package testpkg

type Runner struct {
	runFn func()
}

func (r *Runner) Execute() {
	r.runFn()
}
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(mod), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "testpkg.go"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	fset := token.NewFileSet()
	cfg := &packages.Config{
		Mode: loadMode,
		Dir:  dir,
		Fset: fset,
	}
	pkgs, err := packages.Load(cfg, "example.com/testpkg")
	if err != nil || len(pkgs) == 0 {
		t.Fatalf("load testpkg: pkgs=%d err=%v", len(pkgs), err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		t.Fatal("package load had errors")
	}

	ix := &Index{Dir: dir, pkgs: pkgs, fset: fset}
	_, opaque := ix.moduleEdges(pkgs, "example.com/testpkg")

	if !opaque["example.com/testpkg.Runner.Execute"] {
		t.Fatalf("Runner.Execute should be marked opaque when struct field func is unresolvable")
	}
}

// A package that fails to type-check stays in the scope denominator with
// actionable diagnostics: its path, the import edges recovered from its
// syntax, and the compiler error text — so a report can say *why* the
// package is invisible instead of only naming it.
func TestSkippedPackageDiagnostics(t *testing.T) {
	ix := fixture(t, "skippprod")
	diags, err := ix.SkippedPackageDiagnostics(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(diags) != 1 {
		t.Fatalf("expected exactly one skipped package, got %+v", diags)
	}
	d := diags[0]
	if d.Path != "example.com/skippprod/broken" {
		t.Fatalf("skipped path = %q", d.Path)
	}
	if !slices.Contains(d.Imports, "example.com/unreachdep/vulnlib") {
		t.Fatalf("recovered imports missing the dep edge: %v", d.Imports)
	}
	if len(d.Errors) == 0 || !strings.Contains(strings.Join(d.Errors, " "), "undefinedIdentifier") {
		t.Fatalf("compiler error text must name the failure: %v", d.Errors)
	}
	if !d.SourceVisible {
		t.Fatal("parseable-but-broken package must report SourceVisible")
	}

	// SkippedPackages is the path projection of the same canonical record.
	paths, err := ix.SkippedPackages(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(paths, []string{"example.com/skippprod/broken"}) {
		t.Fatalf("SkippedPackages=%v", paths)
	}
	// The recovered edge still answers SkippedPackagesImporting.
	if got := ix.SkippedPackagesImporting("example.com/unreachdep/vulnlib"); len(got) != 1 {
		t.Fatalf("SkippedPackagesImporting=%v", got)
	}
}

// A package whose source cannot be read at all stays visible in the skip
// record with SourceVisible=false — the strongest possible scope gap.
func TestSkippedPackageDiagnosticsUnrecoverable(t *testing.T) {
	dir := usageModule(t, map[string]string{
		"main.go": `package main

func main() {}
`,
		"unreadable/gone.go": `package unreadable

import "fmt"

func Gone() { fmt.Println("x") }
`,
	})
	gone := filepath.Join(dir, "unreadable", "gone.go")
	if err := os.Chmod(gone, 0o000); err != nil {
		t.Skipf("cannot drop read permission: %v", err)
	}
	t.Cleanup(func() { os.Chmod(gone, 0o644) })

	ix := &Index{Dir: dir}
	diags, err := ix.SkippedPackageDiagnostics(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var d *SkippedPackage
	for i := range diags {
		if diags[i].Path == "example.com/usageprod/unreadable" {
			d = &diags[i]
		}
	}
	if d == nil {
		t.Fatalf("unrecoverable package missing from diagnostics: %+v", diags)
	}
	if d.SourceVisible {
		t.Fatal("an unreadable file must report SourceVisible=false")
	}
	if len(d.Errors) == 0 {
		t.Fatal("the loader error must be recorded even when no source is recoverable")
	}
}

// The cmqc.h shape: a cgo package fails the load because a system C header
// prerequisite is absent. The diagnostic must carry the compiler's own
// message naming the missing header — an actionable prerequisite/build
// limitation, never a silent exclusion. Needs a C toolchain: skipped when
// none is installed.
func TestSkippedPackageDiagnosticsMissingCHeader(t *testing.T) {
	if _, err := exec.LookPath("cc"); err != nil {
		t.Skip("no C toolchain; cgo header failure cannot be exercised")
	}
	dir := usageModuleGomod(t, "module example.com/cgoprod\n\ngo 1.23\n",
		map[string]string{
			"main.go": `package main

func main() {}
`,
			"bridge/bridge.go": `package bridge

// #include <missing_system_prereq_header.h>
import "C"

func Bridge() int { return 0 }
`,
		})
	ix := &Index{Dir: dir, Build: domain.ProductSnapshot{CGOEnabled: true}}
	diags, err := ix.SkippedPackageDiagnostics(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var d *SkippedPackage
	for i := range diags {
		if diags[i].Path == "example.com/cgoprod/bridge" {
			d = &diags[i]
		}
	}
	if d == nil {
		t.Fatalf("cgo package missing from diagnostics: %+v", diags)
	}
	joined := strings.Join(d.Errors, " ")
	if !strings.Contains(joined, "missing_system_prereq_header.h") {
		t.Fatalf("diagnostic must name the missing header prerequisite: %v", d.Errors)
	}
	// The cgo file itself stays parseable: its import edges are
	// recoverable even though the C prerequisite is absent.
	if !d.SourceVisible {
		t.Fatal("parseable cgo source must not count as unrecoverable")
	}
}

// The exact trigger argument is bound positionally: a configuration-derived
// document argument does not make an external trigger argument safe.
func TestTraceArgument_WrongArgumentStaysExternal(t *testing.T) {
	ix := fixture(t, "configwrongargprod")
	sites, err := ix.FindCallers(context.Background(), domain.SymbolRef{
		Package: "example.com/postreachdep/transformer", Symbol: "Query"})
	if err != nil || len(sites) != 1 {
		t.Fatalf("FindCallers(Query): sites=%v err=%v", sites, err)
	}
	doc, _, err := ix.TraceArgumentBound(context.Background(), sites[0], 0, 6)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Origin != domain.OriginConfiguration {
		t.Fatalf("doc arg origin=%s want CONFIGURATION (summary: %s)", doc.Origin, doc.Summary)
	}
	trigger, _, err := ix.TraceArgumentBound(context.Background(), sites[0], 1, 6)
	if err != nil {
		t.Fatal(err)
	}
	if trigger.Arg != 1 {
		t.Fatalf("trigger arg=%d want 1", trigger.Arg)
	}
	if trigger.Origin != domain.OriginExternalUntrusted {
		t.Fatalf("trigger arg origin=%s want EXTERNAL_UNTRUSTED (summary: %s)", trigger.Origin, trigger.Summary)
	}
}

// vendorRefusingModule writes a snapshot whose module graph the Go loader
// refuses: the go 1.15 module replaces example.com/dep by module version,
// which a modern toolchain will not resolve under -mod=vendor ("updates to
// go.mod needed"). The vendored package is still on disk — the shape the
// k8s-3121 snapshot has.
func vendorRefusingModule(t *testing.T, withVendoredSource bool) string {
	t.Helper()
	files := map[string]string{
		"prod.go":            "package prod\n\nfunc Main() {}\n",
		"vendor/modules.txt": "# example.com/dep v1.0.0 => example.com/dep v1.0.0\n## explicit\nexample.com/dep/pkg\n",
	}
	if withVendoredSource {
		files["vendor/example.com/dep/pkg/file.go"] = "" +
			"package pkg\n" + // 1
			"\n" + // 2
			"type unmarshal struct{}\n" + // 3
			"\n" + // 4
			"func (p *unmarshal) Generate() {}\n" + // 5
			"\n" + // 6
			"func (p *unmarshal) field() {}\n" // 7
	}
	return usageModuleGomod(t,
		"module example.com/prod\n\ngo 1.15\n\nrequire example.com/dep v1.0.0\n\nreplace example.com/dep => example.com/dep v1.0.0\n",
		files)
}

func vendorRefusingIndex(dir string) *Index {
	return &Index{
		Dir:        dir,
		Build:      domain.ProductSnapshot{VendorMode: true},
		ReplaceEnv: true,
		Env:        []string{"GOPROXY=off", "GOWORK=off"},
	}
}

// A loader refusal on a vendored snapshot must not become "symbol not
// found": the vendored tree is the build input, and its declaration is the
// evidence root-cause verification needs.
func TestLookupSymbolVendoredSourceFallback(t *testing.T) {
	ix := vendorRefusingIndex(vendorRefusingModule(t, true))
	if err := ix.Loaded(context.Background()); err == nil {
		t.Fatal("fixture no longer reproduces the loader refusal; rebuild it before trusting this test")
	}
	for _, tc := range []struct {
		symbol string
		line   int
	}{
		{"unmarshal.Generate", 5},
		{"unmarshal.field", 7},
	} {
		lk, err := ix.LookupSymbol(context.Background(), domain.SymbolRef{
			Package: "example.com/dep/pkg", Symbol: tc.symbol,
		})
		if err != nil {
			t.Fatalf("%s: vendored fallback did not resolve: %v", tc.symbol, err)
		}
		if !lk.Vendored || lk.LoaderError == nil {
			t.Fatalf("%s: lookup must record the loader failure: %+v", tc.symbol, lk)
		}
		if lk.Site == nil {
			t.Fatalf("%s: no declaration site", tc.symbol)
		}
		if got := filepath.ToSlash(lk.Site.File); !strings.HasSuffix(got, "vendor/example.com/dep/pkg/file.go") {
			t.Fatalf("%s: file=%q, want the vendored source", tc.symbol, lk.Site.File)
		}
		if lk.Site.Line != tc.line || lk.Site.Package != "example.com/dep/pkg" {
			t.Fatalf("%s: site=%+v", tc.symbol, lk.Site)
		}
	}
}

// Absence semantics stay untouched: when vendor/ does not carry the package,
// the loader failure is returned as-is — never a verified symbol, and never
// a typed "not found in package".
func TestLookupSymbolVendoredSourceMissingStaysUnverified(t *testing.T) {
	ix := vendorRefusingIndex(vendorRefusingModule(t, false))
	lk, err := ix.LookupSymbol(context.Background(), domain.SymbolRef{
		Package: "example.com/dep/pkg", Symbol: "unmarshal.Generate",
	})
	if err == nil {
		t.Fatalf("a package with no vendored source must stay unverified: %+v", lk)
	}
	if lk.Site != nil || lk.Vendored {
		t.Fatalf("vendored lookup invented a site: %+v", lk)
	}
	if lk.LoaderError == nil {
		t.Fatal("the loader failure must be reported, not converted into a verification")
	}
	if errors.Is(err, ErrSymbolNotFoundInPackage) {
		t.Fatalf("loader failure reported as symbol absence: %v", err)
	}
}

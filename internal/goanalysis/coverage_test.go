package goanalysis

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/affected"
	"github.com/fedorovmv/izyan/internal/domain"
)

var uriStringSym = domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "URI.String"}

func TestGatedRefsFindsTagExcludedCall(t *testing.T) {
	ix := fixture(t, "gatedprod")
	sites, err := ix.GatedRefs(context.Background(), vulnSym)
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 1 {
		t.Fatalf("sites=%+v", sites)
	}
	if !strings.HasSuffix(sites[0].File, "special.go") || sites[0].Function != "gatedCall" {
		t.Fatalf("site=%+v", sites[0])
	}
	// The typed index does not see the gated file.
	direct, err := ix.SearchSymbol(context.Background(), vulnSym)
	if err != nil {
		t.Fatal(err)
	}
	if len(direct) != 0 {
		t.Fatalf("typed search unexpectedly sees gated ref: %+v", direct)
	}
}

func TestGatedRefsNoneWithoutGatedFiles(t *testing.T) {
	ix := fixture(t, "leakprod")
	sites, err := ix.GatedRefs(context.Background(), vulnSym)
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 0 {
		t.Fatalf("sites=%+v", sites)
	}
}

func TestInterfaceDispatchSites(t *testing.T) {
	ix := fixture(t, "ifaceprod")
	sites, err := ix.InterfaceDispatchSites(context.Background(), uriStringSym)
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 1 {
		t.Fatalf("sites=%+v", sites)
	}
	if sites[0].Function != "render" {
		t.Fatalf("enclosing=%q", sites[0].Function)
	}
	// The typed search sees the interface, not the concrete impl.
	direct, err := ix.SearchSymbol(context.Background(), uriStringSym)
	if err != nil {
		t.Fatal(err)
	}
	if len(direct) != 0 {
		t.Fatalf("typed search unexpectedly sees dispatched call: %+v", direct)
	}
}

func TestInterfaceDispatchSitesPlainFunc(t *testing.T) {
	ix := fixture(t, "ifaceprod")
	sites, err := ix.InterfaceDispatchSites(context.Background(), vulnSym)
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 0 {
		t.Fatalf("plain function subject must not report dispatch sites: %+v", sites)
	}
}

// An unresolved receiver type must never collapse the dispatch set to a
// false empty result: the scan falls back to every name-matched
// interface call as an open candidate, and the internal flag reports
// that instantiation narrowing is off the table.
func TestInterfaceDispatchSitesUnresolvedReceiver(t *testing.T) {
	ix := fixture(t, "ifaceprod")
	if err := ix.Loaded(context.Background()); err != nil {
		t.Fatal(err)
	}
	ix.mu.Lock()
	sites, recvOpen, err := ix.interfaceDispatchSites(context.Background(),
		domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Missing.String"})
	ix.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if !recvOpen {
		t.Fatal("an unresolvable receiver type must flag the dispatch set as open")
	}
	if len(sites) != 1 || sites[0].Function != "render" {
		t.Fatalf("name-matched superset must keep the render() site open: %+v", sites)
	}
	// The public facade keeps the sites — never a silent empty set.
	pub, err := ix.InterfaceDispatchSites(context.Background(),
		domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Missing.String"})
	if err != nil {
		t.Fatal(err)
	}
	if len(pub) != 1 {
		t.Fatalf("public scan must return the open candidates, not an empty set: %+v", pub)
	}
}

// Parenthesized receiver spellings ("(*T).M") name the same receiver
// type as "T.M": the lookup normalizes them instead of falling back to
// the unresolved-receiver superset.
func TestInterfaceDispatchSitesParenReceiver(t *testing.T) {
	ix := fixture(t, "ifaceprod")
	if err := ix.Loaded(context.Background()); err != nil {
		t.Fatal(err)
	}
	ix.mu.Lock()
	sites, recvOpen, err := ix.interfaceDispatchSites(context.Background(),
		domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "(*URI).String"})
	ix.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if recvOpen {
		t.Fatal("(*URI).String must resolve the URI receiver, not report open")
	}
	if len(sites) != 1 || sites[0].Function != "render" {
		t.Fatalf("sites=%+v", sites)
	}
}

// A resolved receiver whose method is never interface-called reports no
// candidates at all — the empty list is a real closure result, not the
// unresolved-receiver fallback.
func TestInterfaceDispatchSitesNoMatchingInterface(t *testing.T) {
	ix := fixture(t, "ifaceprod")
	if err := ix.Loaded(context.Background()); err != nil {
		t.Fatal(err)
	}
	ix.mu.Lock()
	sites, recvOpen, err := ix.interfaceDispatchSites(context.Background(),
		domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Conn.Next"})
	ix.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if recvOpen {
		t.Fatal("Conn resolves — the flag must be false")
	}
	if len(sites) != 0 {
		t.Fatalf("Conn.Next has no dispatch candidate in ifaceprod: %+v", sites)
	}
}

// A dispatch through an interface declared in the SUBJECT'S package is
// still a candidate for a concrete subject: the old same-package skip
// confused the selected interface method with the subject itself and
// dropped the site outright.
func TestInterfaceDispatchSitesDepDeclaredInterface(t *testing.T) {
	dir := usageModule(t, map[string]string{
		"main.go": `package main

import (
	"fmt"

	"example.com/dep/vuln"
)

func drive(r vuln.Runner) string { return r.Run("x") }

func main() { fmt.Println(drive(&vuln.RealRunner{})) }
`,
	})
	ix := &Index{Build: testProduct(), Dir: dir}
	sites, err := ix.InterfaceDispatchSites(context.Background(),
		domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "RealRunner.Run"})
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 1 || sites[0].Function != "drive" {
		t.Fatalf("r.Run() through dep-declared Runner must be a dispatch candidate: %+v", sites)
	}
	// The interface method subject itself yields no candidates: an
	// interface type can never be the dynamic receiver.
	ifaceSites, err := ix.InterfaceDispatchSites(context.Background(),
		domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Runner.Run"})
	if err != nil {
		t.Fatal(err)
	}
	if len(ifaceSites) != 0 {
		t.Fatalf("interface-typed receiver subject must report no candidates: %+v", ifaceSites)
	}
}

// VerifyFalse downgrades a would-be VERIFIED negative when a reference
// exists only in a build-tag-excluded file.
func TestVerifyFalseGatedFileDowngrades(t *testing.T) {
	ix := fixture(t, "gatedprod")
	v := Verifier{Source: ix}
	c := &domain.AnalysisCase{Product: testProduct()}
	cond := domain.Condition{
		ID:       "C-REACH",
		Kind:     domain.ConditionSymbolReachable,
		Subjects: []domain.SymbolRef{vulnSym},
	}
	claim := domain.Claim{ConditionID: cond.ID, Result: domain.ClaimFalse}
	out := v.VerifyFalse(context.Background(), c, claim, cond)
	nv := out.NegativeVerification
	if nv == nil || nv.Status != domain.NegativeInsufficientScope {
		t.Fatalf("nv=%+v", nv)
	}
	if !strings.Contains(nv.Notes, "build tags") {
		t.Fatalf("notes=%q", nv.Notes)
	}
}

// VerifyFalse downgrades on interface-dispatch candidates the typed
// search cannot attribute to the concrete method.
func TestVerifyFalseInterfaceDispatchDowngrades(t *testing.T) {
	ix := fixture(t, "ifaceprod")
	v := Verifier{Source: ix}
	c := &domain.AnalysisCase{Product: testProduct()}
	cond := domain.Condition{
		ID:       "C-REACH",
		Kind:     domain.ConditionSymbolReachable,
		Subjects: []domain.SymbolRef{uriStringSym},
	}
	claim := domain.Claim{ConditionID: cond.ID, Result: domain.ClaimFalse}
	out := v.VerifyFalse(context.Background(), c, claim, cond)
	nv := out.NegativeVerification
	if nv == nil || nv.Status != domain.NegativeInsufficientScope {
		t.Fatalf("nv=%+v", nv)
	}
	if !strings.Contains(nv.Notes, "interface-dispatched") {
		t.Fatalf("notes=%q", nv.Notes)
	}
}

// A product package that failed to type-check makes the instantiation
// inventory incomplete: even an apparently uninstantiated receiver
// keeps its dispatch candidates open — VerifyFalse must still
// downgrade, never drop the site into a verified negative.
func TestVerifyFalseInterfaceDispatchIncompleteScope(t *testing.T) {
	dir := usageModule(t, map[string]string{
		"main.go": `package main

import (
	"fmt"
)

func shout(s fmt.Stringer) string { return s.String() }

func main() { fmt.Println(shout(nil)) }
`,
		"broken/broken.go": `package broken

func Broken() int { return undefinedIdentifier }
`,
	})
	ix := &Index{Build: testProduct(), Dir: dir}
	v := Verifier{Source: ix}
	c := &domain.AnalysisCase{Product: testProduct()}
	safeSym := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "SafeFormatter.String"}
	cond := domain.Condition{
		ID:       "C-REACH",
		Kind:     domain.ConditionSymbolReachable,
		Subjects: []domain.SymbolRef{safeSym},
	}
	claim := domain.Claim{ConditionID: cond.ID, Result: domain.ClaimFalse}
	out := v.VerifyFalse(context.Background(), c, claim, cond)
	nv := out.NegativeVerification
	if nv == nil || nv.Status != domain.NegativeInsufficientScope {
		t.Fatalf("incomplete product scope must not narrow dispatch: nv=%+v", nv)
	}
	if !strings.Contains(nv.Notes, "interface-dispatched") {
		t.Fatalf("the open dispatch site must be named: notes=%q", nv.Notes)
	}
}

// A FALSE reachability claim cannot be verified by "no product references"
// when the subject lives in an internal package or is unexported: the
// product could never name it, so the observation is vacuous and dep-internal
// dispatch (registries, callbacks) stays un-closed scope.
func TestVerifyReachableFalseInternalSubjectNotVerified(t *testing.T) {
	v := Verifier{}
	nv := &domain.NegativeVerification{Status: domain.NegativeVerified}
	claim := domain.Claim{ConditionID: "C-REACH", Result: domain.ClaimFalse}
	subjects := []domain.SymbolRef{
		{Package: "google.golang.org/grpc/internal/xds/httpfilter/rbac", Symbol: "builder.ParseFilterConfig"},
		{Package: "google.golang.org/grpc/internal/xds/httpfilter/rbac", Symbol: "parseConfig"},
	}
	out := v.verifyReachableFalse(context.Background(), &domain.AnalysisCase{Product: testProduct()}, claim, nv, subjects, map[string][]domain.CallSite{})
	got := out.NegativeVerification
	if got == nil || got.Status != domain.NegativeInsufficientScope {
		t.Fatalf("nv=%+v", got)
	}
	if !strings.Contains(got.Notes, "visibility") {
		t.Fatalf("notes=%q", got.Notes)
	}
}

// A subject never invoked anywhere but whose receiver pipeline runs inside
// the dependency is a source observation, not a semantic veto. The physical
// measurement verifies deadness; whether that deadness falsifies the
// advisory is decided by the admitted defect-semantics contract
// (domain.ValidateDeadnessPremise). Sibling liveness must not pre-empt that
// decision inside VerifyUnreachable/VerifyFalse.
func TestVerifyReachableFalseMissingCallMeasurementIsNotSemantic(t *testing.T) {
	ix := fixture(t, "missingcall")
	v := Verifier{Source: ix}
	subj := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Claims.VerifyAud"}
	c := &domain.AnalysisCase{Product: testProduct()}
	c.Vulnerability.Module = "example.com/dep"

	// The source layer still reports the sibling observation.
	callers, live, unbounded, err := ix.DepInvocationState(context.Background(), subj)
	if err != nil {
		t.Fatal(err)
	}
	if callers != 0 || !live || unbounded {
		t.Fatalf("DepInvocationState: callers=%d live=%v unbounded=%v", callers, live, unbounded)
	}

	nv := &domain.NegativeVerification{Status: domain.NegativeVerified}
	claim := domain.Claim{ConditionID: "C-REACH", Result: domain.ClaimFalse}
	out := v.verifyReachableFalse(context.Background(), c, claim, nv,
		[]domain.SymbolRef{subj}, map[string][]domain.CallSite{})
	got := out.NegativeVerification
	if got == nil || got.Status != domain.NegativeVerified {
		t.Fatalf("physical deadness measurement must verify independently of sibling liveness: nv=%+v", got)
	}
}

// A dead method on a receiver type no dep code exercises is genuinely
// dead code — the falsifier stands; and a subject with dep-internal
// callers cannot be proven unreachable by product refs either.
func TestVerifyReachableFalseDepBoundaries(t *testing.T) {
	ix := fixture(t, "ifaceprod")
	v := Verifier{Source: ix}
	c := &domain.AnalysisCase{Product: testProduct()}
	c.Vulnerability.Module = "example.com/dep"

	// Conn.Next is never called and no sibling method runs in the dep:
	// zero references everywhere is a real absence.
	nv := &domain.NegativeVerification{Status: domain.NegativeVerified}
	claim := domain.Claim{ConditionID: "C-REACH", Result: domain.ClaimFalse}
	out := v.verifyReachableFalse(context.Background(), c, claim, nv,
		[]domain.SymbolRef{{Package: "example.com/dep/vuln", Symbol: "Conn.Next"}},
		map[string][]domain.CallSite{})
	if got := out.NegativeVerification; got == nil || got.Status != domain.NegativeVerified {
		t.Fatalf("Conn.Next nv=%+v", got)
	}

	// Runner.Run has an on-path dep-internal call site in DispatchLate
	// (the product drives it) — product-ref absence cannot exclude dep
	// invocation. A dep caller no live path reaches would stay dead code.
	ix = fixture(t, "lateprod")
	v = Verifier{Source: ix}
	c.Vulnerability.Module = "example.com/dep3"
	nv = &domain.NegativeVerification{Status: domain.NegativeVerified}
	out = v.verifyReachableFalse(context.Background(), c, claim, nv,
		[]domain.SymbolRef{{Package: "example.com/dep3/vuln", Symbol: "Runner.Run"}},
		map[string][]domain.CallSite{})
	got := out.NegativeVerification
	if got == nil || got.Status != domain.NegativeInsufficientScope {
		t.Fatalf("Runner.Run nv=%+v", got)
	}
	if !strings.Contains(got.Notes, "dep-internal") {
		t.Fatalf("notes=%q", got.Notes)
	}
}

func TestProductReferenceable(t *testing.T) {
	cases := []struct {
		ref  domain.SymbolRef
		want bool
	}{
		{domain.SymbolRef{Package: "golang.org/x/crypto/ssh", Symbol: "NewServerConn"}, true},
		{domain.SymbolRef{Package: "github.com/miekg/dns", Symbol: "ParseZone"}, true},
		{domain.SymbolRef{Package: "google.golang.org/grpc/internal/xds/httpfilter/rbac", Symbol: "builder.ParseFilterConfig"}, false},
		{domain.SymbolRef{Package: "google.golang.org/grpc/internal/xds/httpfilter/rbac", Symbol: "ParseFilterConfig"}, false},
		{domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "builder.run"}, false},
		{domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "URI.String"}, true},
	}
	for _, tc := range cases {
		if got := productReferenceable(tc.ref); got != tc.want {
			t.Fatalf("productReferenceable(%+v)=%v want %v", tc.ref, got, tc.want)
		}
	}
}

func TestImportClosureUsesAdmittedInventory(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "inventoryreplace"))
	if err != nil { t.Fatal(err) }
	ix := &Index{Dir: root, Build: domain.ProductSnapshot{GoWorkFile: "off"}}
	m := affected.MeasurePackageInventory(context.Background(), affected.ExecGoTool{}, root, ix.Build, false)
	if !m.Run.Complete { t.Fatalf("real inventory: %+v", m.Run) }
	c, err := ix.EnumerateImportClosureWithInventory(context.Background(), m)
	if err != nil || !c.Complete || c.InventoryReference != m.RawReference { t.Fatalf("closure: %+v %v", c, err) }
	foreign := m; foreign.Build.GOOS = "foreign"
	c, err = ix.EnumerateImportClosureWithInventory(context.Background(), foreign)
	if err != nil || c.Complete || c.InventoryError == "" { t.Fatalf("foreign inventory admitted: %+v %v", c, err) }
	meta := ix.pkgMeta["inventory.test/dependency"]
	meta.hashFiles = append(meta.hashFiles, filepath.Join(root, "localdep", "missing.go"))
	ix.pkgMeta["inventory.test/dependency"] = meta
	c, err = ix.EnumerateImportClosureWithInventory(context.Background(), m)
	if err == nil && (c.Complete || len(c.UnhashedSource) == 0) { t.Fatalf("complete list repaired missing source: %+v %v", c, err) }
	broken := &Index{Dir: root, Build: domain.ProductSnapshot{GoWorkFile:"off", BuildTags:[]string{"brokenload"}}}
	m = affected.MeasurePackageInventory(context.Background(), affected.ExecGoTool{}, root, broken.Build, false)
	if !m.Run.Complete { t.Fatalf("type-check gap must not masquerade as a list failure: %+v", m.Run) }
	c, err = broken.EnumerateImportClosureWithInventory(context.Background(), m)
	if err == nil && c.Complete { t.Fatalf("complete list repaired missing load coverage: %+v", c) }
	t.Logf("real local-replace: inventory complete=%t closure complete=%t load_error=%v skipped=%v", m.Run.Complete, c.Complete, err, c.Skipped)
}

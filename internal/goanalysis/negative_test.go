package goanalysis

import (
	"context"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

func TestSymbolIsMethod(t *testing.T) {
	cases := []struct {
		sym  domain.SymbolRef
		want bool
	}{
		{domain.SymbolRef{Package: "example.com/dep/s2", Symbol: "NewDict"}, false},
		{domain.SymbolRef{Package: "golang.org/x/crypto/ssh", Symbol: "NewServerConn"}, false},
		{domain.SymbolRef{Package: "github.com/valyala/fasthttp", Symbol: "ServeFile"}, false},
		{domain.SymbolRef{Package: "example.com/dep", Symbol: "Server.Serve"}, true},
		{domain.SymbolRef{Package: "example.com/dep", Symbol: "(*Server).Serve"}, true},
	}
	for _, tc := range cases {
		if got := symbolIsMethod(tc.sym); got != tc.want {
			t.Errorf("symbolIsMethod(%+v) = %v, want %v", tc.sym, got, tc.want)
		}
	}
}

func TestReflectMarkerStandaloneFunctionScoping(t *testing.T) {
	ix := fixture(t, "reflectprod")
	v := Verifier{Source: ix}
	c := &domain.AnalysisCase{Product: testProduct()}
	c.Vulnerability.Module = "example.com/dep"

	// 1. Standalone function: reflect import does NOT widen call graph
	standaloneSym := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "NewDict"}
	claim1 := domain.Claim{
		ConditionID: "C-REACH",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierGovulncheckSilence,
	}
	cond1 := domain.Condition{
		ID:       "C-REACH",
		Kind:     domain.ConditionSymbolReachable,
		Subjects: []domain.SymbolRef{standaloneSym},
	}

	out1 := v.VerifyFalse(context.Background(), c, claim1, cond1)
	if out1.NegativeVerification == nil || out1.NegativeVerification.Status != domain.NegativeVerified {
		t.Fatalf("expected NegativeVerified for standalone function, got: %+v", out1.NegativeVerification)
	}
	for _, lim := range out1.NegativeVerification.Limitations {
		if strings.Contains(lim, "widens the call graph") {
			t.Fatalf("unexpected reflect call-graph limitation for standalone function: %s", lim)
		}
	}

	// 2. Exported method on an instantiated type: reflect method call DOES add call-graph limitation
	methodSym := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Conn.Next"}
	claim2 := domain.Claim{
		ConditionID: "C-REACH",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierGovulncheckSilence,
	}
	cond2 := domain.Condition{
		ID:       "C-REACH",
		Kind:     domain.ConditionSymbolReachable,
		Subjects: []domain.SymbolRef{methodSym},
	}

	out2 := v.VerifyFalse(context.Background(), c, claim2, cond2)
	hasReflectLim := false
	if out2.NegativeVerification != nil {
		for _, lim := range out2.NegativeVerification.Limitations {
			if strings.Contains(lim, "widens the call graph") {
				hasReflectLim = true
				break
			}
		}
	}
	if !hasReflectLim {
		t.Fatalf("expected reflect call-graph limitation for exported method, got nv=%+v", out2.NegativeVerification)
	}
}

func TestGovulncheckSilenceWithUnexportedSubject(t *testing.T) {
	ix := fixture(t, "constprod")
	v := Verifier{Source: ix}
	c := &domain.AnalysisCase{Product: testProduct()}

	unexportedSym := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "internalHelper"}

	// 1. With FalsifierGovulncheckSilence and no live dep callers: verified
	claim1 := domain.Claim{
		ConditionID: "C-REACH",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierGovulncheckSilence,
	}
	cond1 := domain.Condition{
		ID:       "C-REACH",
		Kind:     domain.ConditionSymbolReachable,
		Subjects: []domain.SymbolRef{unexportedSym},
	}
	out1 := v.VerifyFalse(context.Background(), c, claim1, cond1)
	if out1.NegativeVerification == nil || out1.NegativeVerification.Status != domain.NegativeVerified {
		t.Fatalf("expected NegativeVerified for govulncheck silence with unexported symbol, got: %+v", out1.NegativeVerification)
	}

	// 2. With FalsifierUnreachedExportedSubject: insufficient scope because visibility forces zero refs
	claim2 := domain.Claim{
		ConditionID: "C-REACH",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierUnreachedExportedSubject,
	}
	out2 := v.VerifyFalse(context.Background(), c, claim2, cond1)
	if out2.NegativeVerification == nil || out2.NegativeVerification.Status != domain.NegativeInsufficientScope {
		t.Fatalf("expected NegativeInsufficientScope for no-product-refs on unexported symbol, got: %+v", out2.NegativeVerification)
	}
}

func TestVerifyInputFalse_ConstantPayloadVerified(t *testing.T) {
	ix := fixture(t, "constprod")
	v := Verifier{Source: ix}
	c := &domain.AnalysisCase{Product: testProduct(),
		Vulnerability: domain.Vulnerability{Module: "gopkg.in/yaml.v2"},
	}
	subject := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Parse"}
	cond := domain.Condition{
		ID:       "C-INPUT",
		Kind:     domain.ConditionAttackerControl,
		Subjects: []domain.SymbolRef{subject},
		ArgIndex: 0,
	}
	claim := domain.Claim{
		ConditionID: "C-INPUT",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierConstantOrGeneratedInput,
	}

	out := v.VerifyFalse(context.Background(), c, claim, cond)
	if out.NegativeVerification == nil || out.NegativeVerification.Status != domain.NegativeVerified {
		t.Fatalf("expected NegativeVerified for constant payload, got: %+v", out.NegativeVerification)
	}
	if !strings.Contains(out.NegativeVerification.Notes, "pass verified constant or generated payload") {
		t.Fatalf("unexpected notes: %q", out.NegativeVerification.Notes)
	}
}

func TestVerifyInputFalse_TrustedConfigVerified(t *testing.T) {
	ix := fixture(t, "fieldprod")
	v := Verifier{Source: ix}
	c := &domain.AnalysisCase{Product: testProduct(),
		Vulnerability: domain.Vulnerability{Module: "example.com/dep"},
	}
	subject := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Parse"}
	cond := domain.Condition{
		ID:       "C-INPUT",
		Kind:     domain.ConditionAttackerControl,
		Subjects: []domain.SymbolRef{subject},
		ArgIndex: 0,
	}
	claim := domain.Claim{
		ConditionID: "C-INPUT",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierTrustedInfrastructure,
	}

	out := v.VerifyFalse(context.Background(), c, claim, cond)
	if out.NegativeVerification == nil || out.NegativeVerification.Status != domain.NegativeVerified {
		t.Fatalf("expected NegativeVerified for trusted config, got: %+v", out.NegativeVerification)
	}
	if !strings.Contains(out.NegativeVerification.Notes, "consume local configuration files (trusted infrastructure)") {
		t.Fatalf("unexpected notes: %q", out.NegativeVerification.Notes)
	}
}

func TestVerifyInputFalse_ExternalInputContradictsConstantAndConfig(t *testing.T) {
	ix := fixture(t, "extprod")
	v := Verifier{Source: ix}
	c := &domain.AnalysisCase{Product: testProduct(),
		Vulnerability: domain.Vulnerability{Module: "example.com/dep"},
	}
	subject := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Parse"}
	cond := domain.Condition{
		ID:       "C-INPUT",
		Kind:     domain.ConditionAttackerControl,
		Subjects: []domain.SymbolRef{subject},
		ArgIndex: 0,
	}

	for _, falsifier := range []string{domain.FalsifierConstantOrGeneratedInput, domain.FalsifierTrustedInfrastructure} {
		claim := domain.Claim{
			ConditionID: "C-INPUT",
			Result:      domain.ClaimFalse,
			Falsifier:   falsifier,
		}
		out := v.VerifyFalse(context.Background(), c, claim, cond)
		if out.NegativeVerification == nil || out.NegativeVerification.Status != domain.NegativeContradicted {
			t.Fatalf("falsifier %q: expected NegativeContradicted for external input, got: %+v", falsifier, out.NegativeVerification)
		}
	}
}

// reflectNarrowModule writes a product that invokes
// reflect.Value.MethodByName and links example.com/dep/vuln WITHOUT any
// dynamic materialization (no unsafe/plugin/reflect.New), so
// instantiation narrowing stays enabled: only a provably uninstantiated
// receiver may be narrowed away.
func reflectNarrowModule(t *testing.T) *Index {
	t.Helper()
	dir := usageModule(t, map[string]string{
		"main.go": `package main

import (
	"fmt"
	"reflect"

	"example.com/dep/vuln"
)

type svc struct{}

func main() {
	vuln.Parse("x")
	fmt.Println(reflect.ValueOf(&svc{}).MethodByName("Serve").IsValid())
}
`,
	})
	return &Index{Build: testProduct(), Dir: dir}
}

// A declared, provably uninstantiated receiver type: the reflect_method
// marker is narrowed away and the negative still verifies — narrowing
// is sound here because the instantiation probe is complete.
func TestNegativeVerification_ReflectMethodUninstantiatedType(t *testing.T) {
	ix := reflectNarrowModule(t)
	v := Verifier{Source: ix}
	c := &domain.AnalysisCase{Product: testProduct()}
	c.Vulnerability.Module = "example.com/dep"

	sym := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "SafeFormatter.String"}
	claim := domain.Claim{
		ConditionID: "C-REACH",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierGovulncheckSilence,
	}
	cond := domain.Condition{
		ID:       "C-REACH",
		Kind:     domain.ConditionSymbolReachable,
		Subjects: []domain.SymbolRef{sym},
	}

	out := v.VerifyFalse(context.Background(), c, claim, cond)
	if out.NegativeVerification == nil || out.NegativeVerification.Status != domain.NegativeVerified {
		t.Fatalf("expected NegativeVerified for uninstantiated receiver type %s, got: %+v", sym.Symbol, out.NegativeVerification)
	}
	for _, lim := range out.NegativeVerification.Limitations {
		if strings.Contains(lim, "widens the call graph") {
			t.Fatalf("unexpected call-graph limitation for uninstantiated receiver type %s: %s", sym.Symbol, lim)
		}
	}
}

// An unresolvable receiver type cannot be proven uninstantiated — the
// reflect_method marker stays relevant and the limitation is carried.
func TestNegativeVerification_ReflectMethodUnresolvedReceiver(t *testing.T) {
	ix := reflectNarrowModule(t)
	v := Verifier{Source: ix}
	c := &domain.AnalysisCase{Product: testProduct()}
	c.Vulnerability.Module = "example.com/dep"

	sym := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Missing.Action"}
	claim := domain.Claim{
		ConditionID: "C-REACH",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierGovulncheckSilence,
	}
	cond := domain.Condition{
		ID:       "C-REACH",
		Kind:     domain.ConditionSymbolReachable,
		Subjects: []domain.SymbolRef{sym},
	}

	out := v.VerifyFalse(context.Background(), c, claim, cond)
	found := false
	if out.NegativeVerification != nil {
		for _, lim := range out.NegativeVerification.Limitations {
			if strings.Contains(lim, "widens the call graph") {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("reflect_method marker must stay relevant for an unresolvable receiver: %+v",
			out.NegativeVerification)
	}
}

func TestNegativeVerification_ReflectMethodMultiSubjectStandaloneAndUninstantiated(t *testing.T) {
	ix := reflectNarrowModule(t)
	v := Verifier{Source: ix}
	c := &domain.AnalysisCase{Product: testProduct()}
	c.Vulnerability.Module = "example.com/dep"

	// Condition with both an uninstantiated exported method and an exported standalone function.
	methodSym := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "SafeFormatter.String"}
	standaloneSym := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "NewDict"}

	claim := domain.Claim{
		ConditionID: "C-REACH",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierGovulncheckSilence,
	}
	cond := domain.Condition{
		ID:       "C-REACH",
		Kind:     domain.ConditionSymbolReachable,
		Subjects: []domain.SymbolRef{methodSym, standaloneSym},
	}

	out := v.VerifyFalse(context.Background(), c, claim, cond)
	if out.NegativeVerification == nil || out.NegativeVerification.Status != domain.NegativeVerified {
		t.Fatalf("expected NegativeVerified, got: %+v", out.NegativeVerification)
	}
	for _, lim := range out.NegativeVerification.Limitations {
		if strings.Contains(lim, "widens the call graph") {
			t.Fatalf("unexpected reflect call-graph limitation for standalone function + uninstantiated method: %s", lim)
		}
	}
}

func TestIsReceiverTypeInstantiated(t *testing.T) {
	ix := fixture(t, "ifaceprod")

	// Nil index -> returns true (conservative)
	var nilIx *Index
	if !nilIx.IsReceiverTypeInstantiated(domain.SymbolRef{Package: "pkg", Symbol: "Type.Method"}) {
		t.Fatal("expected nil Index to return true")
	}

	// Standalone function -> returns true
	if !ix.IsReceiverTypeInstantiated(domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Parse"}) {
		t.Fatal("expected standalone function to return true")
	}

	// Instantiated type (URI is created in ifaceprod) -> returns true,
	// including the parenthesized receiver spelling.
	if !ix.IsReceiverTypeInstantiated(domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "URI.String"}) {
		t.Fatal("expected instantiated type URI.String to return true")
	}
	if !ix.IsReceiverTypeInstantiated(domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "(*URI).String"}) {
		t.Fatal("expected instantiated pointer type (*URI).String to return true")
	}

	// Provably uninstantiated: SafeFormatter resolves, narrowing is
	// enabled, no product package was skipped, and the type never
	// appears in the instantiation set -> false.
	if ix.IsReceiverTypeInstantiated(domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "SafeFormatter.String"}) {
		t.Fatal("expected provably uninstantiated SafeFormatter.String to return false")
	}
	if ix.IsReceiverTypeInstantiated(domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "(*SafeFormatter).String"}) {
		t.Fatal("expected provably uninstantiated (*SafeFormatter).String to return false")
	}

	// Unresolvable receiver type -> true: an unproven receiver must
	// never narrow dispatch or dynamic-invocation scope away.
	if !ix.IsReceiverTypeInstantiated(domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Missing.String"}) {
		t.Fatal("expected unresolved receiver Missing.String to return true")
	}

	// Disabled narrowing: unsafe/plugin/reflect.New materialization in
	// product code makes the set unproven -> every receiver reads true.
	rx := fixture(t, "reflectprod")
	if !rx.IsReceiverTypeInstantiated(domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "ExternalType.Action"}) {
		t.Fatal("expected disabled narrowing (unsafe import) to return true")
	}

	// Incomplete scope: a product package that failed to type-check
	// never entered the instantiation set -> unproven -> true.
	dir := usageModule(t, map[string]string{
		"main.go": `package main

func main() {}
`,
		"broken/broken.go": `package broken

func Broken() int { return undefinedIdentifier }
`,
	})
	sx := &Index{Build: testProduct(), Dir: dir}
	if !sx.IsReceiverTypeInstantiated(domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "SafeFormatter.String"}) {
		t.Fatal("expected a skipped product package to block narrowing (return true)")
	}
}

func TestNegativeVerification_InterfaceDispatchUninstantiatedType(t *testing.T) {
	ix := fixture(t, "ifaceprod")
	v := Verifier{Source: ix}
	c := &domain.AnalysisCase{Product: testProduct()}
	c.Vulnerability.Module = "example.com/dep"

	// 1. URI.String: URI is instantiated in ifaceprod, and render() calls fmt.Stringer.String().
	// InterfaceDispatchSites finds render(), and because URI is instantiated,
	// NegativeVerification demotes to NegativeInsufficientScope.
	uriSym := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "URI.String"}
	claim1 := domain.Claim{
		ConditionID: "C-REACH",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierGovulncheckSilence,
	}
	cond1 := domain.Condition{
		ID:       "C-REACH",
		Kind:     domain.ConditionSymbolReachable,
		Subjects: []domain.SymbolRef{uriSym},
	}
	out1 := v.VerifyFalse(context.Background(), c, claim1, cond1)
	if out1.NegativeVerification == nil || out1.NegativeVerification.Status != domain.NegativeInsufficientScope {
		t.Fatalf("expected NegativeInsufficientScope for instantiated URI.String, got: %+v", out1.NegativeVerification)
	}

	// 2. SafeFormatter.String: SafeFormatter also implements fmt.Stringer, so
	// InterfaceDispatchSites returns render() as well. But SafeFormatter is NEVER
	// instantiated anywhere in ifaceprod. Therefore, interface dispatch cannot reach
	// it, and NegativeVerification should remain NegativeVerified!
	safeSym := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "SafeFormatter.String"}
	claim2 := domain.Claim{
		ConditionID: "C-REACH",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierGovulncheckSilence,
	}
	cond2 := domain.Condition{
		ID:       "C-REACH",
		Kind:     domain.ConditionSymbolReachable,
		Subjects: []domain.SymbolRef{safeSym},
	}
	out2 := v.VerifyFalse(context.Background(), c, claim2, cond2)
	if out2.NegativeVerification == nil || out2.NegativeVerification.Status != domain.NegativeVerified {
		t.Fatalf("expected NegativeVerified for uninstantiated SafeFormatter.String, got status=%v notes=%q",
			out2.NegativeVerification.Status, out2.NegativeVerification.Notes)
	}

	// 3. DepInternalFormatter.String: DepInternalFormatter is instantiated inside
	// the dependency package itself, but NEVER in product packages.
	// Interface dispatch in product code cannot reach it, so NegativeVerification
	// must remain NegativeVerified.
	depInternalSym := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "DepInternalFormatter.String"}
	claim3 := domain.Claim{
		ConditionID: "C-REACH",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierGovulncheckSilence,
	}
	cond3 := domain.Condition{
		ID:       "C-REACH",
		Kind:     domain.ConditionSymbolReachable,
		Subjects: []domain.SymbolRef{depInternalSym},
	}
	out3 := v.VerifyFalse(context.Background(), c, claim3, cond3)
	if out3.NegativeVerification == nil || out3.NegativeVerification.Status != domain.NegativeVerified {
		t.Fatalf("expected NegativeVerified for DepInternalFormatter.String (instantiated only inside dep), got status=%v notes=%q",
			out3.NegativeVerification.Status, out3.NegativeVerification.Notes)
	}
}

func TestNegativeVerification_GovulncheckSilenceScopesToLocusSubjects(t *testing.T) {
	ix := fixture(t, "constprod")
	v := Verifier{Source: ix}

	calledUntouchedSym := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Parse"}
	uncalledLocusSym := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "NewDict"}

	c := &domain.AnalysisCase{Product: testProduct(),
		Vulnerability: domain.Vulnerability{
			Module:          "example.com/dep",
			AffectedSymbols: []domain.SymbolRef{calledUntouchedSym, uncalledLocusSym},
		},
		Exploit: &domain.ExploitModel{
			LocusSubjects: []domain.SymbolRef{uncalledLocusSym},
		},
	}

	claim := domain.Claim{
		ConditionID: "C-REACH",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierGovulncheckSilence,
	}
	cond := domain.Condition{
		ID:       "C-REACH",
		Kind:     domain.ConditionSymbolReachable,
		Subjects: []domain.SymbolRef{calledUntouchedSym, uncalledLocusSym},
	}

	out := v.VerifyFalse(context.Background(), c, claim, cond)
	if out.NegativeVerification == nil || out.NegativeVerification.Status != domain.NegativeVerified {
		t.Fatalf("expected NegativeVerified because defect locus is uncalled, got status=%v notes=%q",
			out.NegativeVerification.Status, out.NegativeVerification.Notes)
	}
}

// A missing-pair-member FALSE cannot rest on "no product references" when
// the never-invoked member is a method of a build interface: interface
// dispatch (fmt.Stringer, callbacks inside the dependency) invokes it
// without a static product reference. This mirrors the amqp091-go
// URI.String/ParseURI smoke case, where the locus verifier already refuses
// URI.String for the same reason.
func TestSequencePairInterfaceMethodNotVerified(t *testing.T) {
	dir := usageModule(t, map[string]string{
		"main.go": `package main

import (
	"fmt"

	"example.com/dep/vuln"
)

func main() {
	u, _ := vuln.ParseURI("x")
	fmt.Println(u)
}
`,
	})
	ix := &Index{Build: testProduct(), Dir: dir}
	c := &domain.AnalysisCase{Product: testProduct()}
	c.EvidenceGraph.AddModuleUsages(domain.CallSite{Callee: "example.com/dep/vuln.ParseURI"})

	uriString := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "URI.String"}
	parseURI := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "ParseURI"}
	cond := domain.Condition{
		ID:       "C-ROUNDTRIP",
		Kind:     domain.ConditionSymbolReachable,
		Subjects: []domain.SymbolRef{uriString, parseURI},
		Params: map[string]string{
			domain.ParamSequence: "example.com/dep/vuln.URI.String->example.com/dep/vuln.ParseURI",
		},
	}
	claim := domain.Claim{
		ConditionID: cond.ID, Result: domain.ClaimFalse,
		Falsifier: domain.FalsifierMissingPairMember,
	}
	out := (Verifier{Source: ix}).VerifyFalse(context.Background(), c, claim, cond)
	nv := out.NegativeVerification
	if nv == nil || nv.Status != domain.NegativeInsufficientScope {
		t.Fatalf("interface-dispatched pair member must not verify: nv=%+v", nv)
	}
	if !strings.Contains(nv.Notes, "build interfaces") {
		t.Fatalf("notes=%q, want the interface-scope blocker", nv.Notes)
	}
}

// Control: a never-invoked pair member that is a plain package function and
// has no product references still verifies — the interface rule must not
// turn every missing-pair-member claim into INSUFFICIENT_SCOPE.
func TestSequencePairPlainFunctionStillVerified(t *testing.T) {
	dir := usageModule(t, map[string]string{
		"main.go": `package main

import (
	"fmt"

	"example.com/dep/vuln"
)

func main() {
	u, _ := vuln.ParseURI("x")
	fmt.Println(u)
}
`,
	})
	ix := &Index{Build: testProduct(), Dir: dir}
	c := &domain.AnalysisCase{Product: testProduct()}
	c.EvidenceGraph.AddModuleUsages(domain.CallSite{Callee: "example.com/dep/vuln.ParseURI"})

	parseURI := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "ParseURI"}
	parse2 := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Parse2"}
	cond := domain.Condition{
		ID:       "C-ROUNDTRIP",
		Kind:     domain.ConditionSymbolReachable,
		Subjects: []domain.SymbolRef{parseURI, parse2},
		Params: map[string]string{
			domain.ParamSequence: "example.com/dep/vuln.ParseURI->example.com/dep/vuln.Parse2",
		},
	}
	claim := domain.Claim{
		ConditionID: cond.ID, Result: domain.ClaimFalse,
		Falsifier: domain.FalsifierMissingPairMember,
	}
	out := (Verifier{Source: ix}).VerifyFalse(context.Background(), c, claim, cond)
	nv := out.NegativeVerification
	if nv == nil || nv.Status != domain.NegativeVerified {
		t.Fatalf("plain-function pair member with no references must verify: nv=%+v", nv)
	}
}

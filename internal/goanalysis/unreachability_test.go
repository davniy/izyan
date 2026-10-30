package goanalysis

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

// TestUnreachabilityModuleEntryEnumerationFailure: a failed product-usage
// enumeration is not an empty entry inventory and cannot close the proof.
func TestUnreachabilityModuleEntryEnumerationFailure(t *testing.T) {
	ix := fixture(t, "unreachprod")
	ix.moduleUsageOverride = func(context.Context, string) ([]domain.CallSite, error) {
		return nil, errors.New("injected module usage failure")
	}
	res, err := ix.VerifyUnreachable(context.Background(), "example.com/unreachdep", []domain.SymbolRef{
		{Package: "example.com/unreachdep/vulnlib", Symbol: "OrphanA"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete {
		t.Fatalf("failed module entry enumeration must not complete: %+v", res)
	}
	if !hasLimitation(res, "module entry-symbol enumeration failed") {
		t.Fatalf("enumeration failure must be named: %v", res.Limitations)
	}
	payload, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), "verdict") {
		t.Fatalf("unreachability observation must not emit a verdict field: %s", payload)
	}
}

// TestUnreachabilityModuleEntryEnumerationEmpty: a successful empty usage
// enumeration remains distinguishable from an enumeration failure.
func TestUnreachabilityModuleEntryEnumerationEmpty(t *testing.T) {
	ix := fixture(t, "unreachprod")
	ix.moduleUsageOverride = func(context.Context, string) ([]domain.CallSite, error) {
		return nil, nil
	}
	entries, err := ix.moduleEntrySymbols(context.Background(), "example.com/unreachdep")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("successful empty inventory must remain empty: %v", entries)
	}
}

func unreachSubj(sym string) domain.SymbolRef {
	return domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: sym}
}

// hasLimitation reports whether any recorded limitation contains sub —
// limitations are the named fail-closed reasons the primitive emits.
func hasLimitation(res UnreachabilityResult, sub string) bool {
	for _, l := range res.Limitations {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

// TestUnreachabilityDirectUse: a product call site to the subject is
// positive reach evidence — the proof cannot close and the reference is
// recorded, never read as absence.
func TestUnreachabilityDirectUse(t *testing.T) {
	ix := fixture(t, "constprod")
	res, err := ix.VerifyUnreachable(context.Background(), "example.com/dep",
		[]domain.SymbolRef{unreachSubj("Parse")})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete {
		t.Fatalf("direct symbol use must not complete: %+v", res)
	}
	if !res.DeclarationComplete || !res.EntrypointComplete {
		t.Fatalf("inventories must still be recorded complete: %+v", res)
	}
	if len(res.ProductReferences) == 0 {
		t.Fatal("direct use must be recorded as a product reference")
	}
	if len(res.ProductPackages) == 0 || len(res.ProductFunctionRoots) == 0 {
		t.Fatal("bounded scope inventory must be recorded")
	}
}

// TestUnreachabilityDepInternalCaller: a live dep-internal caller chain
// (product drives Benign, Benign invokes internal) makes the proof
// incomplete — the subject is reachable through dependency code.
func TestUnreachabilityDepInternalCaller(t *testing.T) {
	ix := fixture(t, "unreachprod")
	subj := domain.SymbolRef{Package: "example.com/unreachdep/vulnlib", Symbol: "internal"}
	res, err := ix.VerifyUnreachable(context.Background(), "example.com/unreachdep",
		[]domain.SymbolRef{subj})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete {
		t.Fatalf("a live dep-internal caller must keep the proof open: %+v", res)
	}
	if len(res.DependencyCallSites) == 0 {
		t.Fatal("the dep-internal call site must be recorded")
	}
	if len(res.ModuleReachable) == 0 {
		t.Fatal("the module-internal chain product entry -> internal must be recorded")
	}
	if !hasLimitation(res, "inside the dependency") && !hasLimitation(res, "reachable from product-used") {
		t.Fatalf("dep-internal invocation must be a named limitation: %v", res.Limitations)
	}
}

// TestUnreachabilityFuncValue: a subject bound into a func value is a
// dynamic escape the static caller scan cannot see — recorded as a
// func_value marker, never closed.
func TestUnreachabilityFuncValue(t *testing.T) {
	ix := fixture(t, "funcvalprod")
	res, err := ix.VerifyUnreachable(context.Background(), "example.com/dep",
		[]domain.SymbolRef{unreachSubj("Parse")})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete {
		t.Fatalf("func-value escape must not complete: %+v", res)
	}
	found := false
	for _, m := range res.DynamicMarkers {
		if m.Kind == "func_value" {
			found = true
		}
	}
	if !found {
		t.Fatalf("func_value marker missing: %+v", res.DynamicMarkers)
	}
}

// TestUnreachabilityInterfaceDispatch: an instantiated receiver type behind
// an interface call keeps the dispatch open — the proof fails closed.
func TestUnreachabilityInterfaceDispatch(t *testing.T) {
	ix := fixture(t, "ifaceprod")
	res, err := ix.VerifyUnreachable(context.Background(), "example.com/dep",
		[]domain.SymbolRef{unreachSubj("URI.String")})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete {
		t.Fatalf("interface dispatch to an instantiated receiver must not complete: %+v", res)
	}
	if len(res.InterfaceDispatchSites) == 0 {
		t.Fatal("interface dispatch sites must be recorded")
	}
}

// TestUnreachabilityReflectMarker: reflect method invocation on an
// instantiated receiver type is an open dynamic mechanism — fail closed.
func TestUnreachabilityReflectMarker(t *testing.T) {
	ix := fixture(t, "reflectprod")
	res, err := ix.VerifyUnreachable(context.Background(), "example.com/dep",
		[]domain.SymbolRef{unreachSubj("Conn.Next")})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete {
		t.Fatalf("reflect dynamic invocation must not complete: %+v", res)
	}
	if len(res.DynamicMarkers) == 0 {
		t.Fatal("dynamic markers must be recorded")
	}
}

// TestUnreachabilityGatedRef: a reference inside a build-tag-excluded file
// is an alternate-configuration reach path — the current-context proof
// cannot claim closed scope.
func TestUnreachabilityGatedRef(t *testing.T) {
	ix := fixture(t, "gatedprod")
	res, err := ix.VerifyUnreachable(context.Background(), "example.com/dep",
		[]domain.SymbolRef{unreachSubj("Parse")})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete {
		t.Fatalf("build-gated reference must not complete: %+v", res)
	}
	if len(res.GatedReferences) == 0 {
		t.Fatal("gated references must be recorded")
	}
}

// hasAudit reports whether any recorded boundary line carries the audit
// marker for kind — discarded evidence is audit data, not a limitation.
func hasAudit(res UnreachabilityResult, kind string) bool {
	for _, b := range res.Boundaries {
		if strings.Contains(b, "reachability-filter: discarded kind="+kind) {
			return true
		}
	}
	return false
}

// hasAuditPkg reports whether an audit line for kind names the package —
// discarded evidence must identify which package it belonged to.
func hasAuditPkg(res UnreachabilityResult, kind, pkg string) bool {
	for _, b := range res.Boundaries {
		if strings.Contains(b, "kind="+kind) && strings.Contains(b, "package="+pkg) {
			return true
		}
	}
	return false
}

// TestUnreachabilitySkippedPackageOutsideClosure: a skipped product package
// proven outside the shipping closure cannot hide module references — it is
// discarded into the audit trail and the proof may close.
func TestUnreachabilitySkippedPackageOutsideClosure(t *testing.T) {
	ix := fixture(t, "skippprod")
	res, err := ix.VerifyUnreachable(context.Background(), "example.com/unreachdep",
		[]domain.SymbolRef{{Package: "example.com/unreachdep/vulnlib", Symbol: "OrphanA"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Complete {
		t.Fatalf("unlinked skipped package must not block the proof: %+v", res.Limitations)
	}
	if hasLimitation(res, "failed to type-check") {
		t.Fatalf("dead skipped package must not add a limitation: %+v", res.Limitations)
	}
	if !hasAuditPkg(res, "skipped_package", "example.com/skippprod/broken") {
		t.Fatalf("discarded skipped package must appear in the audit trail: %+v", res.Boundaries)
	}
}

// TestUnreachabilitySkippedPackageInsideClosure: a skipped package imported
// by the shipping main stays reachable evidence — its invisible references
// keep the proof open.
func TestUnreachabilitySkippedPackageInsideClosure(t *testing.T) {
	ix := fixture(t, "skiplinkprod")
	res, err := ix.VerifyUnreachable(context.Background(), "example.com/unreachdep",
		[]domain.SymbolRef{{Package: "example.com/unreachdep/vulnlib", Symbol: "OrphanA"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete {
		t.Fatalf("a skipped package inside the shipping closure must block completeness: %+v", res)
	}
	if !hasLimitation(res, "failed to type-check") {
		t.Fatalf("skipped-package limitation missing: %+v", res.Limitations)
	}
	if hasAuditPkg(res, "skipped_package", "example.com/skiplinkprod/broken") {
		t.Fatalf("a live-closure skipped package must never be audit-discarded: %+v", res.Boundaries)
	}
}

// TestUnreachabilityDeadModuleEntry: module API calls from a dead product
// package must not seed the module cone — the dep-internal caller of the
// subject is out of the product-driven cone and gets audit-discarded.
func TestUnreachabilityDeadModuleEntry(t *testing.T) {
	ix := fixture(t, "deadrefprod")
	res, err := ix.VerifyUnreachable(context.Background(), "example.com/mixdep",
		[]domain.SymbolRef{{Package: "example.com/mixdep/lib", Symbol: "deadInternal"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Complete {
		t.Fatalf("dead-entry subject must close: %+v", res.Limitations)
	}
	if len(res.ModuleReachable) != 0 {
		t.Fatalf("no module chain may reach the subject: %+v", res.ModuleReachable)
	}
	if res.Opaque {
		t.Fatal("module-internal opaque sites unreachable from live entries must not set Opaque")
	}
	if !hasAuditPkg(res, "module_entry", "example.com/deadrefprod/fuzz") {
		t.Fatalf("dead module entry must be audit-recorded: %+v", res.Boundaries)
	}
	if !hasAuditPkg(res, "dependency_call", "example.com/mixdep/lib") {
		t.Fatalf("out-of-cone dep caller must be audit-recorded: %+v", res.Boundaries)
	}
	if hasEntrySymbol(res, "lib.Vulnerable") {
		t.Fatalf("a dead package's module API call must not appear in ModuleEntrySymbols: %+v", res.ModuleEntrySymbols)
	}
	if !hasEntrySymbol(res, "lib.Used") {
		t.Fatalf("the live module API entry must remain recorded: %+v", res.ModuleEntrySymbols)
	}
}

// TestUnreachabilityLiveModuleInit: a package-level call inside a module
// package linked by the shipping closure runs under package init — the
// dep-internal caller is live and the proof stays open.
func TestUnreachabilityLiveModuleInit(t *testing.T) {
	ix := fixture(t, "mixprod")
	res, err := ix.VerifyUnreachable(context.Background(), "example.com/mixdep",
		[]domain.SymbolRef{{Package: "example.com/mixdep/lib", Symbol: "Vulnerable"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete {
		t.Fatalf("a subject reached from linked package init must not complete: %+v", res)
	}
	if len(res.DependencyCallSites) == 0 {
		t.Fatal("the live dep-internal call site must be retained")
	}
	if !hasLimitation(res, "reachable from product-used module API") &&
		!hasLimitation(res, "live call site(s) inside the dependency") {
		t.Fatalf("the init-driven path must be a named limitation: %+v", res.Limitations)
	}
}

// TestUnreachabilityMixedLiveDeadProduct: with one live product reference
// and one dead-package reference to the same subject, only the live site
// blocks — the dead one goes to the audit trail.
func TestUnreachabilityMixedLiveDeadProduct(t *testing.T) {
	ix := fixture(t, "livemixprod")
	res, err := ix.VerifyUnreachable(context.Background(), "example.com/mixdep",
		[]domain.SymbolRef{{Package: "example.com/mixdep/lib", Symbol: "Vulnerable"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete {
		t.Fatalf("a live product reference must not complete: %+v", res)
	}
	liveRefs := 0
	for _, s := range res.ProductReferences {
		if s.Package == "example.com/livemixprod" {
			liveRefs++
		}
		if s.Package == "example.com/livemixprod/fuzz" {
			t.Fatalf("dead-package reference retained as blocking evidence: %+v", s)
		}
	}
	if liveRefs == 0 {
		t.Fatal("the live product reference must be retained")
	}
	if !hasAuditPkg(res, "product_reference", "example.com/livemixprod/fuzz") &&
		!hasAuditPkg(res, "may_call", "example.com/livemixprod/fuzz") {
		t.Fatalf("dead-package evidence must be audit-recorded: %+v", res.Boundaries)
	}
}

// TestUnreachabilityDeadGatedRef: a build-gated reference inside a package
// outside the shipping closure is audit-discarded — an alternate build of
// dead code still cannot run.
func TestUnreachabilityDeadGatedRef(t *testing.T) {
	ix := fixture(t, "deadrefprod")
	res, err := ix.VerifyUnreachable(context.Background(), "example.com/mixdep",
		[]domain.SymbolRef{{Package: "example.com/mixdep/lib", Symbol: "Vulnerable"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.GatedReferences) != 0 {
		t.Fatalf("gated references in dead packages must not block: %+v", res.GatedReferences)
	}
	if !hasAudit(res, "gated_reference") {
		t.Fatalf("discarded gated reference must be audit-recorded: %+v", res.Boundaries)
	}
	if !hasAuditPkg(res, "dependency_call", "example.com/mixdep/autoreg") {
		t.Fatalf("an unlinked module package's init call must be audit-discarded: %+v", res.Boundaries)
	}
	if !res.Complete {
		t.Fatalf("dead-only evidence must close the proof: %+v", res.Limitations)
	}
}

// TestUnreachabilityLinkedGatedRef: a gated reference inside a shipping
// package stays a blocker — an alternate build may wire the call.
func TestUnreachabilityLinkedGatedRef(t *testing.T) {
	ix := fixture(t, "mixprod")
	res, err := ix.VerifyUnreachable(context.Background(), "example.com/mixdep",
		[]domain.SymbolRef{{Package: "example.com/mixdep/lib", Symbol: "Vulnerable"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.GatedReferences) == 0 {
		t.Fatal("gated reference in a linked package must be retained")
	}
	if hasAudit(res, "gated_reference") {
		t.Fatalf("a reachable gated reference must never be audit-discarded: %+v", res.Boundaries)
	}
	if res.Complete {
		t.Fatal("a live gated reference must keep the proof open")
	}
}

// TestUnreachabilityInitAttribution: a package-level call inside a linked
// package is init-machinery evidence — it must not inherit the preceding
// dead function's DEAD verdict. DeadHelper is DEAD, yet the init call
// seeds the module entry and keeps the proof open.
func TestUnreachabilityInitAttribution(t *testing.T) {
	ix := fixture(t, "initattr")
	res, err := ix.VerifyUnreachable(context.Background(), "example.com/mixdep",
		[]domain.SymbolRef{{Package: "example.com/mixdep/lib", Symbol: "Vulnerable"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete {
		t.Fatalf("a live package-init call must keep the proof open: %+v", res)
	}
	if !hasEntry(res, "example.com/mixdep/lib.Vulnerable") {
		t.Fatalf("init call must seed module entries: %+v", res.ModuleEntrySymbols)
	}
	if hasAuditPkg(res, "module_entry", "example.com/initattr/reg") {
		t.Fatalf("live init evidence must never be audit-discarded: %+v", res.Boundaries)
	}
	for _, s := range res.ProductReferences {
		if s.Package == "example.com/initattr/reg" && s.Function == "DeadHelper" {
			t.Fatalf("package-level call misattributed to dead function: %+v", s)
		}
	}
}

// hasEntry reports whether the module entry inventory names the full
// pkg.Symbol callee key.
func hasEntry(res UnreachabilityResult, callee string) bool {
	for _, e := range res.ModuleEntrySymbols {
		if e == callee {
			return true
		}
	}
	return false
}

// TestUnreachabilityLinknameModule: a //go:linkname edge inside the
// dependency module reaches a package the import closure never saw —
// the cone stays open, nothing module-internal may be discarded DEAD.
func TestUnreachabilityLinknameModule(t *testing.T) {
	ix := fixture(t, "dynlinkprod")
	res, err := ix.VerifyUnreachable(context.Background(), "example.com/dynlinkdep",
		[]domain.SymbolRef{{Package: "example.com/dynlinkdep/hidden", Symbol: "Target"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete {
		t.Fatalf("a linkname-reachable subject must never close: %+v", res)
	}
	if !hasLimitation(res, "dynamic materialization") {
		t.Fatalf("linkname inside the module must be a named limitation: %+v", res.Limitations)
	}
	if hasAuditPkg(res, "dependency_call", "example.com/dynlinkdep/hidden") ||
		hasAuditPkg(res, "dependency_call", "example.com/dynlinkdep/entry") {
		t.Fatalf("dynamic-materialization module must not discard evidence: %+v", res.Boundaries)
	}
}

// TestUnreachabilityPluginModule: plugin loading inside the module
// materializes code outside the import closure — same open-cone rule.
func TestUnreachabilityPluginModule(t *testing.T) {
	ix := fixture(t, "plugprod")
	res, err := ix.VerifyUnreachable(context.Background(), "example.com/plugdep",
		[]domain.SymbolRef{{Package: "example.com/plugdep/hidden", Symbol: "Target"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete {
		t.Fatalf("a plugin-loaded module must never close: %+v", res)
	}
	if !hasLimitation(res, "dynamic materialization") {
		t.Fatalf("plugin loading inside the module must be a named limitation: %+v", res.Limitations)
	}
}

// TestUnreachabilityIIFEInitCall: an immediately-invoked func literal at
// package level runs at init — calls inside its body are real
// module-reachability evidence. The outer opaque site carries signature
// func() int, so signature narrowing alone would let T.Target read DEAD
// while init genuinely dispatches it.
func TestUnreachabilityIIFEInitCall(t *testing.T) {
	ix := fixture(t, "iifeprod")
	res, err := ix.VerifyUnreachable(context.Background(), "example.com/iifedep",
		[]domain.SymbolRef{{Package: "example.com/iifedep/reg", Symbol: "T.Target"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete {
		t.Fatalf("an init-run interface call must keep the subject alive: %+v", res)
	}
	if len(res.ModuleReachable["example.com/iifedep/reg.T.Target"]) == 0 &&
		!hasLimitation(res, "reachable from product-used module API") &&
		!res.Opaque {
		t.Fatalf("expected live evidence or an opaque hold, got: %+v", res)
	}
	if hasAudit(res, "dependency_call") || hasAudit(res, "module_entry") {
		t.Fatalf("no dependency site may be audit-discarded here: %+v", res.Boundaries)
	}
}

// TestUnreachabilityUnresolvedModuleOwnership: a dependency subject whose
// package has no module metadata (GOPATH-mode load) gets no cone — the
// sibling init call inside the same dependency is then unenumerable, so
// the proof stays open on a named limitation instead of closing silently.
func TestUnreachabilityUnresolvedModuleOwnership(t *testing.T) {
	ws, err := filepath.Abs(filepath.Join("..", "..", "testdata", "gopathws"))
	if err != nil {
		t.Fatal(err)
	}
	ix := &Index{
		Dir: filepath.Join(ws, "src", "example.com", "goprod"),
		Env: []string{"GO111MODULE=off", "GOPATH=" + ws},
	}
	res, err := ix.VerifyUnreachable(context.Background(), "example.com/gdep",
		[]domain.SymbolRef{{Package: "example.com/gdep/lib", Symbol: "Vulnerable"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete {
		t.Fatalf("unresolved dependency ownership must never close: %+v", res)
	}
	if !hasLimitation(res, "module ownership") {
		t.Fatalf("unresolved ownership must be a named limitation: %+v", res.Limitations)
	}
	if !res.Unbounded {
		t.Fatal("unresolvable dep-internal callers are an unbounded surface")
	}
}

// TestModuleFunctionsNoDeadWhenIncomplete: the raw ModuleFunctions map
// must never carry a DEAD verdict while DependencyGraphComplete is false —
// a cone gap anywhere folds dep-side evidence to UNKNOWN.
func TestModuleFunctionsNoDeadWhenIncomplete(t *testing.T) {
	ix := fixture(t, "mixprod")
	scope, err := ix.buildUnreachabilityScope(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	mc, err := ix.moduleCone(context.Background(), "example.com/mixdep", nil, scope)
	if err != nil {
		t.Fatal(err)
	}
	if !mc.complete {
		t.Skip("fixture unexpectedly produced an incomplete cone")
	}
	ix.mu.Lock()
	ix.fillModuleFunctions(context.Background(), scope, "example.com/mixdep", mc, false)
	ix.mu.Unlock()
	for pkg, fns := range scope.ModuleFunctions {
		for name, st := range fns {
			if st == reachDead {
				t.Fatalf("DEAD verdict %s.%s leaked into ModuleFunctions under an open graph", pkg, name)
			}
		}
	}
	// Same cone with the flag set publishes DEAD honestly.
	scope2, err := ix.buildUnreachabilityScope(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ix.mu.Lock()
	ix.fillModuleFunctions(context.Background(), scope2, "example.com/mixdep", mc, true)
	ix.mu.Unlock()
	dead := 0
	for _, fns := range scope2.ModuleFunctions {
		for _, st := range fns {
			if st == reachDead {
				dead++
			}
		}
	}
	if dead == 0 {
		t.Fatal("a complete cone over unused module functions should publish DEAD")
	}
}

// TestUnreachabilityInitCallbackLiteral: func literals passed as callback
// arguments or stored in package vars invoked at init still reach their
// inner calls — skipping the literal body would classify the subject
// DEAD while init genuinely invokes it.
func TestUnreachabilityInitCallbackLiteral(t *testing.T) {
	ix := fixture(t, "iifeprod")
	res, err := ix.VerifyUnreachable(context.Background(), "example.com/iifedep",
		[]domain.SymbolRef{{Package: "example.com/iifedep/reg", Symbol: "targetCB"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete {
		t.Fatalf("a literal body invoked at init must keep the subject alive: %+v", res)
	}
	if hasAudit(res, "dependency_call") || hasAudit(res, "module_entry") {
		t.Fatalf("no dependency site may be audit-discarded here: %+v", res.Boundaries)
	}
}

// TestSubjectModuleProductExclusion: the product's own module must never
// become a dependency cone — subjectModule resolves product packages
// (loaded or skipped) to no owner before consulting the importer index.
func TestSubjectModuleProductExclusion(t *testing.T) {
	ix := fixture(t, "skippprod")
	mod, unresolved := ix.subjectModule("example.com/skippprod")
	if mod != "" || unresolved {
		t.Fatalf("product package must resolve to no dependency owner: mod=%q unresolved=%v", mod, unresolved)
	}
	mod2, unresolved2 := ix.subjectModule("example.com/skippprod/broken")
	if mod2 != "" || unresolved2 {
		t.Fatalf("skipped product package must resolve to no dependency owner: mod=%q unresolved=%v", mod2, unresolved2)
	}
	res, err := ix.VerifyUnreachable(context.Background(), "example.com/unreachdep",
		[]domain.SymbolRef{{Package: "example.com/unreachdep/vulnlib", Symbol: "OrphanA"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Complete {
		t.Fatalf("product-subject exclusion must not keep proofs open: %+v", res.Limitations)
	}
}

// TestUnreachabilityOpaqueDispatch: opaque dispatch inside the module
// (func-value / anonymous-interface calls reachable from product-used
// entries) keeps every unreached subject UNKNOWN.
func TestUnreachabilityOpaqueDispatch(t *testing.T) {
	ix := fixture(t, "dynprod")
	res, err := ix.VerifyUnreachable(context.Background(), "example.com/dyndep",
		[]domain.SymbolRef{{Package: "example.com/dyndep/dyn", Symbol: "Vulnerable"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete {
		t.Fatalf("opaque dispatch must not complete: %+v", res)
	}
	if !res.Opaque {
		t.Fatal("opaque dispatch must be recorded")
	}
}

// TestUnreachabilityComplete: every inventory closed and every gap set
// empty produces the only complete result — unreachable inside the
// recorded scope, with the declared bound carried as evidence.
func TestUnreachabilityComplete(t *testing.T) {
	ix := fixture(t, "unreachprod")
	res, err := ix.VerifyUnreachable(context.Background(), "example.com/unreachdep",
		[]domain.SymbolRef{
			{Package: "example.com/unreachdep/vulnlib", Symbol: "OrphanA"},
			{Package: "example.com/unreachdep/vulnlib", Symbol: "OrphanB"},
		})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Complete {
		t.Fatalf("closed proof expected complete, limitations=%v", res.Limitations)
	}
	if len(res.Limitations) != 0 {
		t.Fatalf("a complete result carries no gap limitations: %v", res.Limitations)
	}
	if !res.DeclarationComplete || !res.EntrypointComplete {
		t.Fatal("both inventories must be complete")
	}
	if len(res.Boundaries) == 0 {
		t.Fatal("proof scope exclusions must be recorded as boundaries")
	}
	if len(res.ModuleEntrySymbols) == 0 {
		t.Fatal("product-used module entries must be recorded")
	}
}

// TestUnreachabilityUnresolved: a symbol that cannot be resolved in the
// loaded dependency version is never silently absent — declaration
// completeness fails and the limitation names it.
func TestUnreachabilityUnresolved(t *testing.T) {
	ix := fixture(t, "unreachprod")
	res, err := ix.VerifyUnreachable(context.Background(), "example.com/unreachdep",
		[]domain.SymbolRef{{Package: "example.com/unreachdep/vulnlib", Symbol: "NotDeclared"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.DeclarationComplete || res.Complete {
		t.Fatalf("unresolved declaration must not complete: %+v", res)
	}
	if !hasLimitation(res, "NotDeclared") {
		t.Fatalf("unresolved symbol must be named: %+v", res.Limitations)
	}
}

// TestUnreachabilityDeterministic: identical inputs on a fresh index
// produce identical results — the proof is deterministic, including the
// sorted evidence lists.
func TestUnreachabilityDeterministic(t *testing.T) {
	subjects := []domain.SymbolRef{
		{Package: "example.com/unreachdep/vulnlib", Symbol: "OrphanA"},
		{Package: "example.com/unreachdep/vulnlib", Symbol: "OrphanB"},
	}
	r1, err := fixture(t, "unreachprod").VerifyUnreachable(context.Background(), "example.com/unreachdep", subjects)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := fixture(t, "unreachprod").VerifyUnreachable(context.Background(), "example.com/unreachdep", subjects)
	if err != nil {
		t.Fatal(err)
	}
	if r1.Complete != r2.Complete || len(r1.Limitations) != len(r2.Limitations) ||
		len(r1.ProductFunctionRoots) != len(r2.ProductFunctionRoots) {
		t.Fatalf("identical inputs must give identical output:\n%+v\n%+v", r1, r2)
	}
	for i := range r1.Limitations {
		if r1.Limitations[i] != r2.Limitations[i] {
			t.Fatalf("limitation order differs: %v vs %v", r1.Limitations, r2.Limitations)
		}
	}
}

// TestUnreachabilityNoSubjects: an empty subject set is never a closed
// proof — the route requires exact declared symbols.
func TestUnreachabilityNoSubjects(t *testing.T) {
	ix := fixture(t, "unreachprod")
	res, err := ix.VerifyUnreachable(context.Background(), "example.com/unreachdep", nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete {
		t.Fatal("empty subject set must not complete")
	}
	if len(res.Limitations) == 0 {
		t.Fatal("the empty-subject limitation must be named")
	}
}

// TestLocusUnreachedReusesPrimitive: the locus falsifier still verifies a
// genuinely unreachable internal subject through the shared primitive and
// still contradicts on a real product reference.
func TestLocusUnreachedReusesPrimitive(t *testing.T) {
	ix := fixture(t, "unreachprod")
	v := Verifier{Source: ix}
	c := &domain.AnalysisCase{Product: testProduct(),
		Exploit:       &domain.ExploitModel{},
		EvidenceGraph: domain.EvidenceGraph{},
	}
	c.Vulnerability.Module = "example.com/unreachdep"
	claim := domain.Claim{
		ID:          "CL-C-LOCUS",
		ConditionID: "C-LOCUS",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierLocusFunctionUnreached,
	}
	cond := domain.Condition{
		ID: "C-LOCUS",
		Subjects: []domain.SymbolRef{
			{Package: "example.com/unreachdep/vulnlib", Symbol: "OrphanA"},
		},
	}
	out := v.VerifyFalse(context.Background(), c, claim, cond)
	if out.NegativeVerification == nil ||
		out.NegativeVerification.Status != domain.NegativeVerified {
		t.Fatalf("unreachable locus subject must still verify: %+v", out.NegativeVerification)
	}

	ix2 := fixture(t, "constprod")
	out2 := (Verifier{Source: ix2}).VerifyFalse(context.Background(),
		&domain.AnalysisCase{Product: testProduct(),
			Exploit:       &domain.ExploitModel{},
			Vulnerability: domain.Vulnerability{Module: "example.com/dep"},
			EvidenceGraph: domain.EvidenceGraph{},
		}, claim, domain.Condition{
			ID:       "C-LOCUS",
			Subjects: []domain.SymbolRef{unreachSubj("Parse")},
		})
	if out2.NegativeVerification == nil ||
		out2.NegativeVerification.Status != domain.NegativeContradicted {
		t.Fatalf("product call site must still contradict: %+v", out2.NegativeVerification)
	}
}

// TestUnreachabilityUnrelatedSkippedPackageCloses: a product package that
// failed to type-check without importing the subject module cannot hide a
// reference to it — the module-scoped proof still closes.
func TestUnreachabilityUnrelatedSkippedPackageCloses(t *testing.T) {
	ix := fixture(t, "skipbenignprod")
	res, err := ix.VerifyUnreachable(context.Background(), "example.com/unreachdep",
		[]domain.SymbolRef{{Package: "example.com/unreachdep/vulnlib", Symbol: "OrphanA"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Complete {
		t.Fatalf("unrelated skip must not open the proof: %+v", res.Limitations)
	}
	if len(res.Limitations) != 0 {
		t.Fatalf("unexpected limitations: %+v", res.Limitations)
	}
}

// ---- Shadow-retained regression tests (adapted to the scoped filter) ----

// The pre-merge narrowing contract for dispatch candidates is unchanged:
// name-matched sites with a provably uninstantiated receiver are dropped,
// while an unresolvable receiver or a disabled/incomplete instantiation
// probe keeps every candidate open and names why.
func TestUnreachabilityDispatchNarrowedUninstantiated(t *testing.T) {
	ix := fixture(t, "ifaceprod")
	res, err := ix.VerifyUnreachable(context.Background(), "example.com/dep",
		[]domain.SymbolRef{unreachSubj("SafeFormatter.String")})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.InterfaceDispatchSites) != 0 {
		t.Fatalf("uninstantiated receiver candidates must be narrowed away: %+v",
			res.InterfaceDispatchSites)
	}
	if hasLimitation(res, "interface-dispatched") || hasLimitation(res, "instantiation") {
		t.Fatalf("a complete narrowing adds no dispatch limitation: %v", res.Limitations)
	}
	if !res.Complete {
		t.Fatalf("uninstantiated receiver + closed inventories must close the proof: %v",
			res.Limitations)
	}
}

// TestUnreachabilityDispatchUnresolvedReceiver: a receiver type that
// cannot be resolved keeps every name-matched dispatch candidate open —
// the proof fails closed with the unresolved receiver named, and no
// site is dropped just because its concrete target was not found.
func TestUnreachabilityDispatchUnresolvedReceiver(t *testing.T) {
	ix := fixture(t, "ifaceprod")
	res, err := ix.VerifyUnreachable(context.Background(), "example.com/dep",
		[]domain.SymbolRef{unreachSubj("Missing.String")})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete {
		t.Fatalf("unresolved receiver dispatch must not complete: %+v", res)
	}
	if len(res.InterfaceDispatchSites) == 0 {
		t.Fatal("name-matched dispatch candidates must be retained for an unresolved receiver")
	}
	if !hasLimitation(res, "receiver type") {
		t.Fatalf("the unresolved receiver must be named in the limitations: %v", res.Limitations)
	}
}

// TestUnreachabilityDispatchSkippedPackage: a product package that
// failed to type-check makes the instantiation inventory incomplete —
// dispatch narrowing cannot run, so even an apparently uninstantiated
// receiver keeps its candidates open under a named limitation.
func TestUnreachabilityDispatchSkippedPackage(t *testing.T) {
	dir := usageModule(t, map[string]string{
		"main.go": `package main

import (
	"fmt"

	_ "example.com/dep/vuln"
)

func shout(s fmt.Stringer) string { return s.String() }

func main() { fmt.Println(shout(nil)) }
`,
		"broken/broken.go": `package broken

func Broken() int { return undefinedIdentifier }
`,
	})
	ix := &Index{Build: testProduct(), Dir: dir}
	res, err := ix.VerifyUnreachable(context.Background(), "example.com/dep",
		[]domain.SymbolRef{unreachSubj("SafeFormatter.String")})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete {
		t.Fatalf("an incomplete instantiation inventory must not complete: %+v", res)
	}
	if len(res.InterfaceDispatchSites) == 0 {
		t.Fatal("a skipped product package must keep the dispatch candidates open")
	}
	if !hasLimitation(res, "instantiation inventory is incomplete") {
		t.Fatalf("the incomplete inventory must be named in the limitations: %v", res.Limitations)
	}
}

// TestUnreachabilityDispatchNarrowingDisabled: dynamic materialization
// (here a bare unsafe import) disables instantiation narrowing — the
// dispatch candidates stay open under a named limitation even though
// the receiver never appears in the syntax-driven instantiation set.
func TestUnreachabilityDispatchNarrowingDisabled(t *testing.T) {
	dir := usageModule(t, map[string]string{
		"main.go": `package main

import (
	"fmt"
	_ "unsafe"

	_ "example.com/dep/vuln"
)

func shout(s fmt.Stringer) string { return s.String() }

func main() { fmt.Println(shout(nil)) }
`,
	})
	ix := &Index{Build: testProduct(), Dir: dir}
	res, err := ix.VerifyUnreachable(context.Background(), "example.com/dep",
		[]domain.SymbolRef{unreachSubj("SafeFormatter.String")})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete {
		t.Fatalf("disabled narrowing must not complete: %+v", res)
	}
	if len(res.InterfaceDispatchSites) == 0 {
		t.Fatal("disabled narrowing keeps every dispatch candidate open")
	}
	if !hasLimitation(res, "disables instantiation narrowing") {
		t.Fatalf("disabled narrowing must be named in the limitations: %v", res.Limitations)
	}
}

// TestDispatchGapsProbeFailure: when the instantiation probe itself
// cannot run, the sites survive untouched and the failure is returned
// as a named limitation — never as an empty dispatch list.
func TestDispatchGapsProbeFailure(t *testing.T) {
	ix := &Index{Build: testProduct(), Dir: filepath.Join(t.TempDir(), "no-such-module")}
	sites := []domain.CallSite{{File: "x.go", Line: 3, Package: "example.com/prod"}}
	kept, lim := ix.dispatchGaps(context.Background(), unreachSubj("URI.String"), sites)
	if lim == "" {
		t.Fatal("a failed probe must surface as a named limitation")
	}
	if len(kept) != len(sites) {
		t.Fatalf("a failed probe keeps every site: %+v", kept)
	}
	if !strings.Contains(lim, "probe failed") {
		t.Fatalf("limitation must name the probe failure: %q", lim)
	}
}

// TestUnreachabilityUnresolvedReceiverMarker: an unresolvable receiver
// type cannot prove non-instantiation, so a reflect_method marker stays
// recorded — the same conservative read ProductUsage applies.
func TestUnreachabilityUnresolvedReceiverMarker(t *testing.T) {
	dir := usageModule(t, map[string]string{
		"main.go": `package main

import (
	"fmt"
	"reflect"
)

type svc struct{}

func main() {
	fmt.Println(reflect.ValueOf(&svc{}).MethodByName("Serve").IsValid())
}
`,
	})
	ix := &Index{Build: testProduct(), Dir: dir}
	res, err := ix.VerifyUnreachable(context.Background(), "example.com/dep",
		[]domain.SymbolRef{unreachSubj("Missing.Next")})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete {
		t.Fatalf("unresolved receiver with dynamic invocation must not complete: %+v", res)
	}
	if len(res.DynamicMarkers) == 0 {
		t.Fatal("reflect_method must stay relevant for an unresolved receiver type")
	}
}

// TestUnreachabilityAbsentSymbolPackageCloses: the subject's package is
// required in go.mod but absent from the linked import closure of a
// complete product, and its declaration resolves in the dependency.
// ProductUsage keeps its symbol-level linked-package premise and reports
// UNKNOWN, but that verdict names only the linked-closure absence note —
// positive non-reachability evidence for this proof, never a scope gap —
// so the proof still completes and records no usage-check limitation.
func TestUnreachabilityAbsentSymbolPackageCloses(t *testing.T) {
	dir := usageModule(t, map[string]string{
		"main.go": `package main

func main() {}
`,
	})
	ix := &Index{Build: testProduct(), Dir: dir}
	res, err := ix.VerifyUnreachable(context.Background(), "example.com/dep",
		[]domain.SymbolRef{unreachSubj("Parse")})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Complete {
		t.Fatalf("a proof whose only usage note is linked-closure absence must complete: %+v", res.Limitations)
	}
	if len(res.Limitations) != 0 {
		t.Fatalf("a complete result carries no gap limitations: %v", res.Limitations)
	}
}

// TestUnreachabilityGatedRefSurvives: a build-gated reference inside a
// shipping package blocks through the filtered gated-reference array —
// the usage check's site-level text is superseded, not double-reported.
func TestUnreachabilityGatedRefSurvives(t *testing.T) {
	ix := fixture(t, "gatedprod")
	res, err := ix.VerifyUnreachable(context.Background(), "example.com/dep",
		[]domain.SymbolRef{unreachSubj("Parse")})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete {
		t.Fatalf("a gated-reference usage gap must not complete: %+v", res)
	}
	if len(res.GatedReferences) == 0 {
		t.Fatalf("the gated reference must be retained as evidence: %+v", res)
	}
	if !hasLimitation(res, "an alternate build may reach the subject") {
		t.Fatalf("the gated-reference limitation must be named: %v", res.Limitations)
	}
}

// A sibling of the typed advisory package is part of the module inventory
// even when its compiler failure makes its call edges invisible.
func TestUnreachabilitySkippedDependencyPackage(t *testing.T) {
	for _, broken := range []bool{false, true} {
		t.Run(map[bool]string{false: "typed", true: "failed"}[broken], func(t *testing.T) {
			sibling := "package sibling\nfunc Call() {}\n"
			if broken {
				sibling = "package sibling\nimport \"example.com/fixturedep/vuln\"\nimport \"example.com/fixturedep/missing\"\nfunc Call() { vuln.Target(); missing.Call() }\n"
			}
			dir := usageModuleGomod(t, "module example.com/fixtureprod\n\ngo 1.23\nrequire example.com/fixturedep v1.0.0\nreplace example.com/fixturedep => ./dep\n", map[string]string{
				"main.go":                "package main\nimport \"example.com/fixturedep/api\"\nfunc main() { api.Entry() }\n",
				"dep/go.mod":             "module example.com/fixturedep\n\ngo 1.23\n",
				"dep/api/api.go":         "package api\nimport \"example.com/fixturedep/vuln\"\nvar _ = vuln.Target\nfunc Entry() {}\n",
				"dep/vuln/vuln.go":       "package vuln\nfunc Target() {}\n",
				"dep/sibling/sibling.go": sibling,
			})
			ix := &Index{Build: testProduct(), Dir: dir}
			res, err := ix.VerifyUnreachable(context.Background(), "example.com/fixturedep", []domain.SymbolRef{{Package: "example.com/fixturedep/vuln", Symbol: "Target"}})
			if err != nil {
				t.Fatal(err)
			}
			if broken {
				if res.Complete || !hasLimitation(res, "example.com/fixturedep/sibling:") || !hasLimitation(res, "missing") {
					t.Fatalf("failed sibling must name its compiler failure and block closure: %+v", res)
				}
			} else if !res.Complete {
				t.Fatalf("typed module must close: %v", res.Limitations)
			}
		})
	}
}

// TestUnreachabilityMayCallOpen: an unresolved func-value call site whose
// signature matches the subject is retained as a Possible may-call site —
// live evidence that keeps the proof open; site-local partiality does not
// additionally raise the unscoped-enumeration limitation.
func TestUnreachabilityMayCallOpen(t *testing.T) {
	ix := fixture(t, "fvopenprod")
	res, err := ix.VerifyUnreachable(context.Background(), "example.com/dep",
		[]domain.SymbolRef{unreachSubj("Parse")})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete {
		t.Fatalf("open may-call enumeration must not complete: %+v", res)
	}
	found := false
	for _, s := range res.MayCallSites {
		if s.Possible {
			found = true
		}
	}
	if !found {
		t.Fatalf("the unresolved signature-compatible site must be recorded: %+v", res.MayCallSites)
	}
	if !hasLimitation(res, "may-call") {
		t.Fatalf("the may-call evidence must be named: %v", res.Limitations)
	}
}

// TestUnreachabilityMayCallSettledPositive: a func-value caller resolved
// after the extras generation settles is reported as a real path — the
// may-call site is recorded non-possible and blocks completion like any
// other positive evidence.
func TestUnreachabilityMayCallSettledPositive(t *testing.T) {
	ix := fixture(t, "fvchurnprod")
	res, err := ix.VerifyUnreachable(context.Background(), "example.com/dep",
		[]domain.SymbolRef{unreachSubj("Parse")})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete {
		t.Fatalf("a settled may-call hit must not complete: %+v", res)
	}
	found := false
	for _, s := range res.MayCallSites {
		if s.Function == "main" {
			found = true
			if s.Possible {
				t.Fatalf("the settled caller must be recorded as a real site, not Possible: %+v", s)
			}
		}
	}
	if !found {
		t.Fatalf("the func-value call in main must be recorded: %+v", res.MayCallSites)
	}
	if hasLimitation(res, "may-call enumeration") {
		t.Fatalf("a closed enumeration must not be reported partial: %v", res.Limitations)
	}
}

package goanalysis

import (
	"context"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
)

// hasEntrySymbol reports whether the filtered module entry inventory names
// callee — entry symbols carry the shared "pkg/path[.Recv].Func" callee key,
// so a package-path qualified name matches its suffix exactly.
func hasEntrySymbol(res UnreachabilityResult, callee string) bool {
	for _, e := range res.ModuleEntrySymbols {
		if e == callee || strings.HasSuffix(e, "/"+callee) {
			return true
		}
	}
	return false
}

// hasAuditFn reports whether an audit line for the package names the
// enclosing function — package-level/init evidence discards must keep
// their attribution.
func hasAuditFn(res UnreachabilityResult, pkg, fn string) bool {
	for _, b := range res.Boundaries {
		if !strings.Contains(b, "reachability-filter: discarded") {
			continue
		}
		if !strings.Contains(b, "package="+pkg) {
			continue
		}
		if strings.Contains(b, "function="+fn+" ") || strings.HasSuffix(b, "function="+fn) {
			return true
		}
	}
	return false
}

// hasProductDiscard reports whether the audit trail carries a discarded
// site whose package belongs to the product module — library-only and
// open-closure snapshots must never drop product-side evidence.
func hasProductDiscard(res UnreachabilityResult, productModule string) bool {
	for _, b := range res.Boundaries {
		if strings.Contains(b, "reachability-filter: discarded") &&
			strings.Contains(b, "package="+productModule) {
			return true
		}
	}
	return false
}

// TestUnreachabilityDeadProductPackage: every reference the dead fuzz
// package holds — a direct call and a package-level init call — is
// audit-discarded, and with only dead evidence the proof may close.
func TestUnreachabilityDeadProductPackage(t *testing.T) {
	ix := fixture(t, "deadrefprod")
	res, err := ix.VerifyUnreachable(context.Background(), "example.com/mixdep",
		[]domain.SymbolRef{{Package: "example.com/mixdep/lib", Symbol: "Vulnerable"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range res.ProductReferences {
		if strings.HasPrefix(s.Package, "example.com/deadrefprod/fuzz") {
			t.Fatalf("dead-package reference retained as blocking evidence: %+v", s)
		}
	}
	if !hasAuditPkg(res, "product_reference", "example.com/deadrefprod/fuzz") &&
		!hasAuditPkg(res, "may_call", "example.com/deadrefprod/fuzz") {
		t.Fatalf("dead-package reference must be audit-recorded: %+v", res.Boundaries)
	}
	if !hasAuditFn(res, "example.com/deadrefprod/fuzz", "init") {
		t.Fatalf("dead package init call must be audit-recorded with its attribution: %+v", res.Boundaries)
	}
	if !res.Complete {
		t.Fatalf("dead-only evidence must close the proof: %+v", res.Limitations)
	}
}

// TestUnreachabilityLinkedInitRef: a subject call inside the init of a
// package linked through a blank import is live init-machinery evidence —
// the reference is retained, the entry seeds the module cone and the proof
// stays open.
func TestUnreachabilityLinkedInitRef(t *testing.T) {
	ix := fixture(t, "initprod")
	res, err := ix.VerifyUnreachable(context.Background(), "example.com/mixdep",
		[]domain.SymbolRef{{Package: "example.com/mixdep/lib", Symbol: "Vulnerable"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete {
		t.Fatalf("a linked init reference must keep the proof open: %+v", res)
	}
	initRef := false
	for _, s := range res.ProductReferences {
		if s.Package == "example.com/initprod/reg" && s.Function == "init" {
			initRef = true
		}
	}
	if hasAuditPkg(res, "product_reference", "example.com/initprod/reg") ||
		hasAuditPkg(res, "module_entry", "example.com/initprod/reg") {
		t.Fatalf("a live init reference must never be audit-discarded: %+v", res.Boundaries)
	}
	if !initRef {
		t.Fatalf("init call must be retained as a product reference: %+v", res.ProductReferences)
	}
	if !hasEntrySymbol(res, "lib.Vulnerable") {
		t.Fatalf("the live init call must seed the module entries: %+v", res.ModuleEntrySymbols)
	}
	if hasAudit(res, "module_entry") {
		t.Fatalf("a live module entry must never be audit-discarded: %+v", res.Boundaries)
	}
}

// TestUnreachabilityUnscannedPackageBlocks: a product package whose source
// cannot be parsed at all hides every reference — even its declared name
// and import set are unrecoverable, so it could be a hidden main. It stays
// UNKNOWN forever: a named limitation, never an audit discard.
func TestUnreachabilityUnscannedPackageBlocks(t *testing.T) {
	ix := fixture(t, "unscanprod")
	res, err := ix.VerifyUnreachable(context.Background(), "example.com/unreachdep",
		[]domain.SymbolRef{{Package: "example.com/unreachdep/vulnlib", Symbol: "OrphanA"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete {
		t.Fatalf("an unscanned package must keep the proof open: %+v", res)
	}
	if !hasLimitation(res, "unrecoverable source") && !hasLimitation(res, "failed to type-check") {
		t.Fatalf("the unscanned package must be a named limitation: %+v", res.Limitations)
	}
	if hasAuditPkg(res, "skipped_package", "example.com/unscanprod/bad") {
		t.Fatalf("an unscanned package must never be audit-discarded: %+v", res.Boundaries)
	}
	if hasAudit(res, "skipped_package") {
		t.Fatalf("no skipped-package discard is sound while unscanned evidence exists: %+v", res.Boundaries)
	}
}

// TestUnreachabilityLibraryOnlyNoDiscard: with no main anywhere no product
// package is provably dead — the subject reference inside the library is
// retained and nothing product-side is audit-discarded.
func TestUnreachabilityLibraryOnlyNoDiscard(t *testing.T) {
	ix := fixture(t, "librefprod")
	res, err := ix.VerifyUnreachable(context.Background(), "example.com/mixdep",
		[]domain.SymbolRef{{Package: "example.com/mixdep/lib", Symbol: "Vulnerable"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete {
		t.Fatalf("a library-only snapshot must never close the proof: %+v", res)
	}
	found := false
	for _, s := range res.ProductReferences {
		if s.Package == "example.com/librefprod/api" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the library reference must be retained: %+v", res.ProductReferences)
	}
	if hasProductDiscard(res, "example.com/librefprod") {
		t.Fatalf("no product-side discard is legal without a shipping root: %+v", res.Boundaries)
	}
}

// TestUnreachabilityGenericReceiverLiveCall: a subject method on a generic
// receiver invoked through a concrete instantiation is live evidence — the
// generic receiver collapses to one conservative node and the site is
// retained.
func TestUnreachabilityGenericReceiverLiveCall(t *testing.T) {
	ix := fixture(t, "genprod")
	res, err := ix.VerifyUnreachable(context.Background(), "example.com/gendep",
		[]domain.SymbolRef{{Package: "example.com/gendep/box", Symbol: "Box.Vuln"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete {
		t.Fatalf("a live instantiated generic receiver call must not complete: %+v", res)
	}
	found := false
	for _, s := range res.ProductReferences {
		if s.Package == "example.com/genprod" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the live generic-receiver call must be retained as a product reference: %+v", res.ProductReferences)
	}
}

// TestUnreachabilityInterfaceDispatchNarrowed: an interface-dispatch
// candidate whose receiver type is never materialized anywhere stays
// narrowed out of the blocking set — the pre-existing receiver-
// instantiation narrowing is unchanged by the reachability filter.
func TestUnreachabilityInterfaceDispatchNarrowed(t *testing.T) {
	ix := fixture(t, "ifaceprod")
	res, err := ix.VerifyUnreachable(context.Background(), "example.com/dep",
		[]domain.SymbolRef{unreachSubj("SafeFormatter.String")})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.InterfaceDispatchSites) != 0 {
		t.Fatalf("dispatch sites for a never-instantiated receiver must be narrowed out: %+v", res.InterfaceDispatchSites)
	}
	if !res.Complete {
		t.Fatalf("a never-instantiated receiver leaves no open dispatch — the proof must close: %+v", res.Limitations)
	}
	if hasAudit(res, "interface_dispatch") {
		t.Fatalf("narrowed dispatch sites are not reachability discards: %+v", res.Boundaries)
	}
}

// TestScopeGenericReceiverLiveInstantiation: a call through a concrete
// instantiation marks the generic receiver's method node live — all
// instantiations share one conservative node.
func TestScopeGenericReceiverLiveInstantiation(t *testing.T) {
	s := scopeOf(t, "scopegen")
	if got := fnState(s, "example.com/scopegen/box", "Box.get"); got != reachLive {
		t.Fatalf("Box.get behind a live Box[int] instantiation must be LIVE, got %s", got)
	}
	if got := fnState(s, "example.com/scopegen/box", "Run"); got != reachLive {
		t.Fatalf("Run must be LIVE, got %s", got)
	}
}

// TestScopeGenericMaterializationUnknown: generic functions and
// generic-receiver methods an unresolved dispatch could reach stay
// UNKNOWN — an unresolved materialization never proves deadness.
func TestScopeGenericMaterializationUnknown(t *testing.T) {
	s := scopeOf(t, "scopegen")
	if got := fnState(s, "example.com/scopegen/box", "choose"); got != reachUnknown {
		t.Fatalf("never-instantiated generic choose must be UNKNOWN behind an arity-compatible opaque site, got %s", got)
	}
	if got := fnState(s, "example.com/scopegen/box", "Box.snap"); got != reachUnknown {
		t.Fatalf("generic-receiver impl behind interface dispatch must be UNKNOWN — generic receivers are never narrowed, got %s", got)
	}
}

// TestScopeUninstantiatedReceiverNarrowing: declarations incompatible with
// every unresolved dispatch keep the existing narrowing — a never-
// materialized concrete impl behind interface dispatch and methods whose
// signatures match no opaque site are DEAD.
func TestScopeUninstantiatedReceiverNarrowing(t *testing.T) {
	s := scopeOf(t, "scopegen")
	for _, fn := range []struct{ pkg, sym string }{
		{"example.com/scopegen/box", "hammer.snap"},
		{"example.com/scopegen/box", "Box.never"},
		{"example.com/scopegen/box", "Vec.mul"},
	} {
		if got := fnState(s, fn.pkg, fn.sym); got != reachDead {
			t.Fatalf("%s.%s must be DEAD, got %s", fn.pkg, fn.sym, got)
		}
	}
}

package affected

import (
	"context"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
)

// ticketVuln mirrors the measured CASE-227168 shape: the advisory covers
// github.com/antchfx/xpath up to (not including) the fixed version.
var ticketVuln = domain.Vulnerability{
	ID:     "GO-2099-0001",
	Module: "github.com/antchfx/xpath",
	AffectedVersions: []domain.VersionRange{
		{Introduced: "0", Fixed: "1.3.6"},
	},
	AffectedPackages: []domain.AffectedPackage{{Path: "github.com/antchfx/xpath"}},
}

func ticketResolve(t *testing.T, tool GoTool, ticket *domain.TicketClaims, ticketErr string) domain.AffectedResult {
	t.Helper()
	res, _, err := GoResolver{Tool: tool, Ticket: ticket, TicketErr: ticketErr}.
		Resolve(context.Background(), ticketVuln, scopedProduct())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	return res
}

func limsContain(res domain.AffectedResult, subs ...string) bool {
	joined := strings.Join(res.Limitations, "\n")
	for _, s := range subs {
		if !strings.Contains(joined, s) {
			return false
		}
	}
	return true
}

// case-03 shape: the ticket declares xpath 1.3.2 (inside the advisory
// range) while the analyzed build resolved v1.3.6 (outside it). The
// out-of-range negative describes a different build than the ticket's
// and must be refused — never produced.
func TestTicketPackageVersionMismatchBlocksVersionAxis(t *testing.T) {
	mods := `{"Path":"example.com/product","Main":true}
{"Path":"github.com/antchfx/xpath","Version":"v1.3.6"}`
	res := ticketResolve(t, fakeTool{modules: []byte(mods)}, &domain.TicketClaims{
		Product: "Demo Mesh", ProductVersion: "Demo Mesh 1.10.3",
		Component: "DEMO",
		Package:   "github.com/antchfx/xpath", PackageVersion: "1.3.2",
		AdvisoryIDs: []string{"GO-2099-0001"},
	}, "")
	if res.VersionAxisBlocked != true {
		t.Fatalf("version axis not blocked: %+v", res)
	}
	if res.VersionAffected != domain.ClaimUnknown {
		t.Fatalf("VersionAffected=%s, want UNKNOWN (refusal, not a verdict)", res.VersionAffected)
	}
	if res.ModulePresent != domain.ClaimTrue {
		t.Fatalf("ModulePresent=%s, want TRUE (the module is resolved in the analyzed build)", res.ModulePresent)
	}
	if res.PackagePresent == domain.ClaimFalse || res.BuildRelevant == domain.ClaimFalse {
		t.Fatalf("package/build axes must not be asserted on a blocked path: %+v", res)
	}
	tc := res.TicketCheck
	if tc == nil {
		t.Fatal("TicketCheck not recorded")
	}
	if tc.PackageVersionCheck != domain.TicketCheckMismatch ||
		tc.DeclaredVersion != "1.3.2" || tc.ResolvedVersion != "v1.3.6" {
		t.Fatalf("package axis %+v, want MISMATCH 1.3.2 vs v1.3.6", tc)
	}
	foundReason := false
	for _, r := range tc.Reasons {
		if r == domain.TicketReasonPackageVersionMismatch {
			foundReason = true
		}
	}
	if !foundReason {
		t.Fatalf("reason %s missing from %+v", domain.TicketReasonPackageVersionMismatch, tc.Reasons)
	}
	if len(tc.BlockedModules) != 1 || tc.BlockedModules[0] != "github.com/antchfx/xpath" {
		t.Fatalf("blocked modules %+v", tc.BlockedModules)
	}
	if tc.DeclaredVersionInRanges == nil || !*tc.DeclaredVersionInRanges {
		t.Fatalf("declared 1.3.2 must be reported inside the advisory range: %+v", tc)
	}
	if !limsContain(res, domain.TicketReasonPackageVersionMismatch, "1.3.2", "v1.3.6", "inside") {
		t.Fatalf("limitations do not name both versions / the range membership: %v", res.Limitations)
	}
}

// Control: the ticket declares exactly the resolved version — the
// out-of-range closing is exactly today's.
func TestTicketMatchingVersionKeepsClosing(t *testing.T) {
	mods := `{"Path":"example.com/product","Main":true}
{"Path":"github.com/antchfx/xpath","Version":"v1.3.6"}`
	res := ticketResolve(t, fakeTool{modules: []byte(mods)}, &domain.TicketClaims{
		Package: "github.com/antchfx/xpath", PackageVersion: "v1.3.6",
	}, "")
	if res.VersionAxisBlocked {
		t.Fatalf("matching version blocked the axis: %+v", res)
	}
	if res.VersionAffected != domain.ClaimFalse {
		t.Fatalf("VersionAffected=%s, want FALSE (today's closing)", res.VersionAffected)
	}
	if res.ResolvedVersion != "v1.3.6" {
		t.Fatalf("ResolvedVersion=%q", res.ResolvedVersion)
	}
	if res.TicketCheck == nil || res.TicketCheck.PackageVersionCheck != domain.TicketCheckMatch {
		t.Fatalf("package axis %+v, want MATCH", res.TicketCheck)
	}
	// The supporting statement still names the declared version's range
	// membership: 1.3.6 is the fixed version — outside the range.
	if res.TicketCheck.DeclaredVersionInRanges == nil || *res.TicketCheck.DeclaredVersionInRanges {
		t.Fatalf("declared 1.3.6 must be reported outside the advisory range: %+v", res.TicketCheck)
	}
	if !limsContain(res, "outside") {
		t.Fatalf("supporting statement missing: %v", res.Limitations)
	}
}

// case-14 shape: the ticket's product version drifts (Demo Mesh 2.5.2 vs
// the analyzed 2.5.0) while the declared package version matches the
// resolved one. The product mismatch is informational only — the
// version-range comparison stays valid and the closing stands.
func TestTicketProductDriftKeepsClosing(t *testing.T) {
	// The release graph carries a main module with a real version —
	// the analyzed build's product identity.
	rel := []domain.ReleaseModule{
		{Path: "example.com/product", Version: "v2.5.0", Main: true},
		{Path: "github.com/antchfx/xpath", Version: "v1.3.6"},
	}
	p := product()
	p.ReleaseModules = rel
	res, _, err := GoResolver{
		Tool: fakeTool{modules: []byte(`{"Path":"example.com/product","Main":true}
{"Path":"github.com/antchfx/xpath","Version":"v1.3.6"}`)},
		Ticket: &domain.TicketClaims{
			Product: "Demo Mesh", ProductVersion: "Demo Mesh 2.5.2",
			Package: "github.com/antchfx/xpath", PackageVersion: "1.3.6",
		},
	}.Resolve(context.Background(), ticketVuln, p)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.VersionAxisBlocked {
		t.Fatalf("product-only drift must not block: %+v", res)
	}
	if res.VersionAffected != domain.ClaimFalse {
		t.Fatalf("VersionAffected=%s, want FALSE (closing stands)", res.VersionAffected)
	}
	tc := res.TicketCheck
	if tc == nil || tc.PackageVersionCheck != domain.TicketCheckMatch {
		t.Fatalf("package axis %+v, want MATCH", tc)
	}
	if tc.ProductVersionCheck != domain.TicketCheckMismatch {
		t.Fatalf("product axis %+v, want MISMATCH", tc)
	}
	if tc.AnalyzedProduct != "example.com/product@v2.5.0" {
		t.Fatalf("analyzed product %q", tc.AnalyzedProduct)
	}
	foundReason := false
	for _, r := range tc.Reasons {
		if r == domain.TicketReasonAnalyzedBuildMismatch {
			foundReason = true
		}
	}
	if !foundReason {
		t.Fatalf("reason %s missing from %+v", domain.TicketReasonAnalyzedBuildMismatch, tc.Reasons)
	}
	if !limsContain(res, domain.TicketReasonAnalyzedBuildMismatch, "Demo Mesh 2.5.2", "v2.5.0") {
		t.Fatalf("informational limitation missing: %v", res.Limitations)
	}
}

// Product identity under operator release metadata: the metadata module
// graph carries no main marker, so the product is identified by the
// source snapshot's own main-module path inside the release graph.
func TestTicketProductIdentityFromReleaseMetadataGraph(t *testing.T) {
	rel := []domain.ReleaseModule{
		{Path: "example.com/product", Version: "v2.5.0"},
		{Path: "github.com/antchfx/xpath", Version: "v1.3.6"},
	}
	p := product()
	p.ReleaseModules = rel
	res, _, err := GoResolver{
		Tool: fakeTool{modules: []byte(`{"Path":"example.com/product","Main":true}
{"Path":"github.com/antchfx/xpath","Version":"v1.3.6"}`)},
		Ticket: &domain.TicketClaims{
			ProductVersion: "Demo Mesh 2.5.0",
			Package:        "github.com/antchfx/xpath", PackageVersion: "1.3.6",
		},
	}.Resolve(context.Background(), ticketVuln, p)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	tc := res.TicketCheck
	if tc == nil || tc.ProductVersionCheck != domain.TicketCheckMatch {
		t.Fatalf("product axis %+v, want MATCH on identical versions", tc)
	}
	for _, r := range tc.Reasons {
		if r == domain.TicketReasonAnalyzedBuildMismatch {
			t.Fatalf("identical product versions recorded a mismatch: %+v", tc)
		}
	}
}

// The product axis degrades to NOT_CHECKED when the analyzed build's
// product identity is unknown — no release graph, no main-module
// version — never a silent pass or a guessed comparison.
func TestTicketProductCheckUnavailable(t *testing.T) {
	mods := `{"Path":"example.com/product","Main":true}
{"Path":"github.com/antchfx/xpath","Version":"v1.3.6"}`
	res := ticketResolve(t, fakeTool{modules: []byte(mods)}, &domain.TicketClaims{
		ProductVersion: "Demo Mesh 2.5.0",
		Package:        "github.com/antchfx/xpath", PackageVersion: "1.3.6",
	}, "")
	if res.TicketCheck == nil || res.TicketCheck.ProductVersionCheck != domain.TicketCheckNotChecked {
		t.Fatalf("product axis %+v, want NOT_CHECKED", res.TicketCheck)
	}
	if !limsContain(res, "product identity is unknown") {
		t.Fatalf("not-checked limitation missing: %v", res.Limitations)
	}
	if res.VersionAffected != domain.ClaimFalse {
		t.Fatalf("unaffected closing must stand: %s", res.VersionAffected)
	}
}

// The module-absent route is unaffected by ticket metadata: a module
// that is not linked is not linked in any build of the product.
func TestTicketModuleAbsentUnaffected(t *testing.T) {
	mods := `{"Path":"example.com/product","Main":true}`
	res := ticketResolve(t, fakeTool{modules: []byte(mods)}, &domain.TicketClaims{
		Package: "github.com/antchfx/xpath", PackageVersion: "1.3.2",
	}, "")
	if res.ModulePresent != domain.ClaimFalse || res.VersionAffected != domain.ClaimFalse {
		t.Fatalf("module-absent closing changed: %+v", res)
	}
	if res.VersionAxisBlocked {
		t.Fatalf("absence route must never be blocked: %+v", res)
	}
	if res.TicketCheck == nil {
		t.Fatal("ticket check must still be recorded on the absence route")
	}
}

// The package-absent route is unaffected: a matching declared version
// leaves the in-range probe untouched.
func TestTicketPackageAbsentUnaffected(t *testing.T) {
	mods := `{"Path":"github.com/antchfx/xpath","Version":"v1.3.0"}`
	pkgs := `{"ImportPath":"example.com/product"}`
	res := ticketResolve(t, fakeTool{modules: []byte(mods), packages: []byte(pkgs)}, &domain.TicketClaims{
		Package: "github.com/antchfx/xpath", PackageVersion: "1.3.0",
	}, "")
	if res.VersionAffected != domain.ClaimTrue || res.PackagePresent != domain.ClaimFalse {
		t.Fatalf("in-range package-absent closing changed: %+v", res)
	}
	if res.VersionAxisBlocked {
		t.Fatalf("package-absence route must never be blocked: %+v", res)
	}
}

// An in-range resolved version with a declared mismatch: the positive
// axis is not the refused negative — the mismatch is recorded but the
// TRUE stands (the block gates only the out-of-range conclusion).
func TestTicketMismatchOnAffectedVersionDoesNotRefute(t *testing.T) {
	mods := `{"Path":"github.com/antchfx/xpath","Version":"v1.3.0"}`
	pkgs := `{"ImportPath":"example.com/product"}
{"ImportPath":"github.com/antchfx/xpath","Module":{"Path":"github.com/antchfx/xpath","Version":"v1.3.0"}}`
	res := ticketResolve(t, fakeTool{modules: []byte(mods), packages: []byte(pkgs)}, &domain.TicketClaims{
		Package: "github.com/antchfx/xpath", PackageVersion: "1.3.2",
	}, "")
	if res.VersionAffected != domain.ClaimTrue {
		t.Fatalf("VersionAffected=%s, want TRUE (a mismatch never invents a verdict)", res.VersionAffected)
	}
	if res.VersionAxisBlocked {
		t.Fatalf("an in-range TRUE is not a refused negative: %+v", res)
	}
	if res.TicketCheck.PackageVersionCheck != domain.TicketCheckMismatch {
		t.Fatalf("the mismatch must still be recorded: %+v", res.TicketCheck)
	}
	if !limsContain(res, domain.TicketReasonPackageVersionMismatch) {
		t.Fatalf("mismatch limitation missing: %v", res.Limitations)
	}
}

// A ticket package the advisory does not cover cannot be compared:
// NOT_CHECKED with a stated reason, and today's closing stands.
func TestTicketPackageNoSubjectMatch(t *testing.T) {
	mods := `{"Path":"example.com/product","Main":true}
{"Path":"github.com/antchfx/xpath","Version":"v1.3.6"}`
	res := ticketResolve(t, fakeTool{modules: []byte(mods)}, &domain.TicketClaims{
		Package: "github.com/other/lib", PackageVersion: "9.9.9",
	}, "")
	if res.VersionAffected != domain.ClaimFalse || res.VersionAxisBlocked {
		t.Fatalf("unmatched package changed the closing: %+v", res)
	}
	if res.TicketCheck.PackageVersionCheck != domain.TicketCheckNotChecked {
		t.Fatalf("package axis %+v, want NOT_CHECKED", res.TicketCheck)
	}
	if !limsContain(res, "matches no evaluated advisory entry") {
		t.Fatalf("not-checked limitation missing: %v", res.Limitations)
	}
}

// A malformed ticket document degrades the check to NOT_CHECKED with
// the named invalid reason — never a silent pass, never an error.
func TestTicketInvalid(t *testing.T) {
	mods := `{"Path":"example.com/product","Main":true}
{"Path":"github.com/antchfx/xpath","Version":"v1.3.6"}`
	res := ticketResolve(t, fakeTool{modules: []byte(mods)}, &domain.TicketClaims{}, domain.TicketReasonInvalid)
	if res.VersionAffected != domain.ClaimFalse || res.VersionAxisBlocked {
		t.Fatalf("invalid ticket changed the closing: %+v", res)
	}
	tc := res.TicketCheck
	if tc == nil || tc.ParseError != domain.TicketReasonInvalid {
		t.Fatalf("parse error not recorded: %+v", tc)
	}
	if !limsContain(res, domain.TicketReasonInvalid) {
		t.Fatalf("invalid-ticket limitation missing: %v", res.Limitations)
	}
}

// An unparseable declared package version is "not checked", never a
// mismatch (equality cannot be established), and today's closing stands.
func TestTicketUnparseableDeclaredVersion(t *testing.T) {
	mods := `{"Path":"example.com/product","Main":true}
{"Path":"github.com/antchfx/xpath","Version":"v1.3.6"}`
	res := ticketResolve(t, fakeTool{modules: []byte(mods)}, &domain.TicketClaims{
		Package: "github.com/antchfx/xpath", PackageVersion: "latest",
	}, "")
	if res.VersionAffected != domain.ClaimFalse || res.VersionAxisBlocked {
		t.Fatalf("unparseable version changed the closing: %+v", res)
	}
	if res.TicketCheck.PackageVersionCheck != domain.TicketCheckNotChecked {
		t.Fatalf("package axis %+v, want NOT_CHECKED", res.TicketCheck)
	}
}

// No ticket: behaviour is exactly as today — the check record
// is absent and the closing is unchanged.
func TestNoTicketUnchanged(t *testing.T) {
	mods := `{"Path":"example.com/product","Main":true}
{"Path":"github.com/antchfx/xpath","Version":"v1.3.6"}`
	res := ticketResolve(t, fakeTool{modules: []byte(mods)}, nil, "")
	if res.TicketCheck != nil {
		t.Fatalf("no ticket must leave the check absent: %+v", res.TicketCheck)
	}
	if res.VersionAffected != domain.ClaimFalse || res.VersionAxisBlocked {
		t.Fatalf("legacy closing changed: %+v", res)
	}
}

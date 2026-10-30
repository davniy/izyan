package evidencetools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/goanalysis"
	"github.com/davniy/izyan/internal/vulnerability"
)

// invokePackageUsage drives the handler through the full invoke path so
// status, completeness downgrade and ID minting are exercised exactly as
// the MCP server runs them.
func invokePackageUsage(t *testing.T, s *Session, ctx context.Context, a packageUsageArgs) *Observation {
	t.Helper()
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	return s.invoke(ctx, PackageUsageTool, raw, func(c context.Context) (*Observation, error) {
		return s.packageUsage(c, a)
	})
}

func usageData(t *testing.T, o *Observation) PackageUsageData {
	t.Helper()
	d, ok := o.Data.(PackageUsageData)
	if !ok {
		t.Fatalf("observation data is %T, want PackageUsageData", o.Data)
	}
	return d
}

// The advisory symbol that the fixture product calls directly is USED;
// the observation stays a bounded positive, never a reachability claim.
// newGatedSession opens a session over a self-contained product whose
// target package is absent from the (complete) linked closure AND
// referenced by a build-gated file. Absence in a complete closure is
// positive evidence — the only open scope gap is the gated reference
// under the four baseline caveats. The replace target stays inside the
// snapshot root — confinement rejects anything else.
func newGatedSession(t *testing.T) *Session {
	t.Helper()
	root := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/gapprod\n\ngo 1.23\n\nrequire example.com/dep v1.0.0\n\nreplace example.com/dep => ./dep\n")
	write("main.go", "package main\n\nfunc main() {}\n")
	write("gated.go", "//go:build special\n\npackage main\n\nimport \"example.com/dep/vuln\"\n\nfunc gatedCall() string { return vuln.Parse(\"x\") }\n")
	write("dep/go.mod", "module example.com/dep\n\ngo 1.23\n")
	write("dep/vuln/vuln.go", "package vuln\n\nfunc Parse(s string) string { return s }\n")
	s, err := NewSession(SessionConfig{
		CVEID:        "GO-TEST-0001",
		SnapshotRoot: root,
		ExternalSHA:  "testsha0123456789",
		VulnSource:   vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{"GO-TEST-0001": testVuln}},
		Audit:        NopAudit{},
	})
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	return s
}

// A parseable failed package with a complete, target-free import set is
// still untyped product source and cannot support a COMPLETE negative.
func TestPackageUsageSkippedNonImporterIsIncomplete(t *testing.T) {
	root := t.TempDir()
	for name, body := range map[string]string{
		"go.mod": "module example.com/gapprod\n\ngo 1.23\n\nrequire example.com/dep v1.0.0\n\nreplace example.com/dep => ./dep\n",
		"main.go": `package main
import (
	"example.com/dep/vuln"
	"example.com/gapprod/broken"
)
func main() { _ = vuln.Parse; broken.Run(any(vuln.Parse)) }
`,
		"broken/broken.go": `package broken
import "fmt"
func Run(v any) { fmt.Println(v); _ = undefinedIdentifier }
`,
		"dep/go.mod":       "module example.com/dep\n\ngo 1.23\n",
		"dep/vuln/vuln.go": "package vuln\nfunc Parse(s string) string { return s }\nfunc Parse2(s string) string { return s }\n",
	} {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	s, err := NewSession(SessionConfig{
		CVEID: "GO-TEST-0001", SnapshotRoot: root, ExternalSHA: "testsha0123456789",
		VulnSource: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{"GO-TEST-0001": testVuln}},
		Audit:      NopAudit{},
	})
	if err != nil {
		t.Fatal(err)
	}
	o := invokePackageUsage(t, s, context.Background(), packageUsageArgs{
		Module: "example.com/dep", Package: "example.com/dep/vuln", Symbol: "Parse2",
	})
	assertObs(t, o, StatusOK, CompletenessUnknown)
	d := usageData(t, o)
	if d.Usage != string(goanalysis.PackageUsageUnknown) || d.NegativeVerification != string(goanalysis.PackageUsageNegativeInsufficientScope) {
		t.Fatalf("incomplete closure produced %+v", d)
	}
	if o.ScopeDetails == nil || len(o.ScopeDetails.SkippedPackages) == 0 {
		t.Fatalf("skipped package omitted from scope: %+v", o.ScopeDetails)
	}
	if !strings.Contains(strings.Join(o.Limitations, "; "), "example.com/gapprod/broken") {
		t.Fatalf("unnamed skipped-package limitation: %v", o.Limitations)
	}
}

// An UNKNOWN observation must surface its specific scope gaps — the
// payload carries five limitations (four always-present baseline bounds
// plus the gated-import gap; the package's absence from the complete
// closure is positive evidence, not a gap) and the fact text, the count
// and the observation's own limitations must name the one real gap,
// never the inflated payload count.
func TestPackageUsageUnknownNamesSpecificGaps(t *testing.T) {
	s := newGatedSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	o := invokePackageUsage(t, s, ctx, packageUsageArgs{
		Module:  "example.com/dep",
		Package: "example.com/dep/vuln",
	})
	assertObs(t, o, StatusOK, CompletenessUnknown)
	d := usageData(t, o)
	if d.Usage != string(goanalysis.PackageUsageUnknown) {
		t.Fatalf("usage=%s, want UNKNOWN (data=%+v)", d.Usage, d)
	}
	gaps := goanalysis.UsageScopeGaps(d.Limitations)
	if len(gaps) != 1 {
		t.Fatalf("specific gaps=%v, want exactly 1 (gated import; the complete-closure absence is positive evidence)", gaps)
	}
	gatedGap := "1 reference(s)/import(s) of example.com/dep/vuln in files excluded by the current build tags — an alternate build may use it"
	wantFact := fmt.Sprintf("package-usage for example.com/dep/vuln is undetermined (1 gap(s) open: %s)",
		gatedGap)
	if o.Fact != wantFact {
		t.Fatalf("fact=%q, want %q", o.Fact, wantFact)
	}
	// The observation's limitations keep the generic interpretation
	// bound first, then name each specific gap verbatim — never a bare
	// count and never the baseline caveats.
	assertHasLimitation(t, o.Limitations, packageUsageUnknownLimit)
	assertHasLimitation(t, o.Limitations, gatedGap)
	if len(o.Limitations) != 1+len(gaps) {
		t.Fatalf("observation limitations=%v, want generic bound + the 1 named gap", o.Limitations)
	}
}

func TestPackageUsageSymbolUsed(t *testing.T) {
	s := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	o := invokePackageUsage(t, s, ctx, packageUsageArgs{
		Module:  "example.com/snapdep",
		Package: "example.com/snapdep/vuln",
		Symbol:  "Parse",
	})
	assertObs(t, o, StatusOK, CompletenessPartial)
	d := usageData(t, o)
	if d.Usage != string(goanalysis.PackageUsageUsed) {
		t.Fatalf("usage=%s, want USED", d.Usage)
	}
	if len(d.ProductSites) == 0 {
		t.Fatal("USED observation carries no concrete product site")
	}
	if d.NegativeVerification != "" {
		t.Fatalf("positive observation carries negative verification %q", d.NegativeVerification)
	}
	assertHasLimitation(t, o.Limitations, packageUsageUsedLimit)
	assertScopeShape(t, o)
}

// A package-level subject is USED by the direct product import alone.
func TestPackageUsagePackageUsed(t *testing.T) {
	s := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	o := invokePackageUsage(t, s, ctx, packageUsageArgs{
		Module:  "example.com/snapdep",
		Package: "example.com/snapdep/vuln",
	})
	assertObs(t, o, StatusOK, CompletenessPartial)
	d := usageData(t, o)
	if d.Usage != string(goanalysis.PackageUsageUsed) {
		t.Fatalf("usage=%s, want USED", d.Usage)
	}
	if len(d.ImportSites) == 0 {
		t.Fatal("USED package observation carries no import site")
	}
}

// The dep-internal helper is linked into the product (transitively
// present) but never referenced by product source: the closed negative
// verification reports NOT_USED + VERIFIED inside the recorded scope.
func TestPackageUsageSymbolNotUsedVerified(t *testing.T) {
	s := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	o := invokePackageUsage(t, s, ctx, packageUsageArgs{
		Module:  "example.com/snapdep",
		Package: "example.com/snapdep/vuln",
		Symbol:  "helper",
	})
	assertObs(t, o, StatusOK, CompletenessComplete)
	d := usageData(t, o)
	if d.Usage != string(goanalysis.PackageUsageNotUsed) {
		t.Fatalf("usage=%s, want NOT_USED (data=%+v)", d.Usage, d)
	}
	if !d.Present {
		t.Fatal("NOT_USED requires the target present in the linked closure")
	}
	if d.NegativeVerification != string(goanalysis.PackageUsageNegativeVerified) {
		t.Fatalf("negative_verification=%q, want VERIFIED", d.NegativeVerification)
	}
	if d.CheckScope == "" {
		t.Fatal("negative observation carries no bounded check scope")
	}
	if len(d.Limitations) == 0 {
		t.Fatal("negative observation carries no limitations")
	}
	for _, want := range packageUsageNegativeLimits {
		assertHasLimitation(t, o.Limitations, want)
	}
	if o.ScopeDetails == nil || o.ScopeDetails.CoverageRule == "" {
		t.Fatal("COMPLETE negative observation carries no coverage rule")
	}
	assertScopeShape(t, o)
}

// A package absent from a complete linked closure verifies NOT_USED:
// provable absence is positive evidence, not a scope gap. The
// observation is OK+COMPLETE with the absence coverage rule, a scope
// and a snapshot binding — the exact shape the lane discharge gate
// (OK + COMPLETE + named coverage rule + snapshot binding) admits, so
// the required package-usage check discharges instead of blocking the
// agent lane NOT_DECISION_READY.
func TestPackageUsageAbsentPackageVerifiesNotUsed(t *testing.T) {
	s := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	o := invokePackageUsage(t, s, ctx, packageUsageArgs{
		Module:  "example.com/snapdep",
		Package: "example.com/snapdep/absent",
	})
	assertObs(t, o, StatusOK, CompletenessComplete)
	d := usageData(t, o)
	if d.Usage != string(goanalysis.PackageUsageNotUsed) {
		t.Fatalf("usage=%s, want NOT_USED", d.Usage)
	}
	if d.Present {
		t.Fatal("absent package reported present")
	}
	if d.NegativeVerification != string(goanalysis.PackageUsageNegativeVerified) {
		t.Fatalf("negative_verification=%q, want VERIFIED", d.NegativeVerification)
	}
	if got := goanalysis.UsageScopeGaps(d.Limitations); len(got) != 0 {
		t.Fatalf("verified absence carries no scope gap, got %v", got)
	}
	if !strings.Contains(o.Fact, "absent from the linked product import closure") {
		t.Fatalf("fact must record the absence basis: %q", o.Fact)
	}
	for _, want := range packageUsageNegativeLimits {
		assertHasLimitation(t, o.Limitations, want)
	}
	// Dischargeability at the closest available seam: the observation
	// satisfies every predicate the lane discharge gate applies —
	// OK status, COMPLETE coverage, an explicit scope, a named
	// closed-scope coverage rule and a binding to this snapshot.
	if o.Completeness != CompletenessComplete || strings.TrimSpace(o.Scope) == "" {
		t.Fatalf("observation not dischargeable: comp=%s scope=%q", o.Completeness, o.Scope)
	}
	sd := o.ScopeDetails
	if sd == nil || sd.CoverageRule != packageUsageAbsentCoverageRule {
		t.Fatalf("discharge requires the absence coverage rule: %+v", sd)
	}
	if sd.SnapshotHash == "" || sd.SnapshotHash != s.SnapshotHash {
		t.Fatalf("discharge requires the snapshot binding: %+v", sd)
	}
	assertScopeShape(t, o)
}

// A symbol that does not resolve inside the loaded dependency package is
// UNKNOWN — a missing declaration is never read as non-use.
func TestPackageUsageUnknownMissingSymbol(t *testing.T) {
	s := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	o := invokePackageUsage(t, s, ctx, packageUsageArgs{
		Module:  "example.com/snapdep",
		Package: "example.com/snapdep/vuln",
		Symbol:  "NotDeclared",
	})
	assertObs(t, o, StatusOK, CompletenessUnknown)
	d := usageData(t, o)
	if d.Usage != string(goanalysis.PackageUsageUnknown) {
		t.Fatalf("usage=%s, want UNKNOWN", d.Usage)
	}
	if d.NegativeVerification != string(goanalysis.PackageUsageNegativeInsufficientScope) {
		t.Fatalf("negative_verification=%q, want INSUFFICIENT_SCOPE", d.NegativeVerification)
	}
}

// The argument contract fails closed: a missing package is an ERROR
// observation, not an UNKNOWN result over an invented subject.
func TestPackageUsageArgsValidation(t *testing.T) {
	s := newTestSession(t)
	o := invokePackageUsage(t, s, context.Background(), packageUsageArgs{
		Module: "example.com/snapdep",
	})
	assertObs(t, o, StatusError, CompletenessUnknown)
	if o.Error == "" {
		t.Fatal("ERROR observation carries no reason")
	}
}

// The serialized payload is deterministic across repeated calls on the
// same snapshot.
func TestPackageUsageDeterministicPayload(t *testing.T) {
	s := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	args := packageUsageArgs{
		Module:  "example.com/snapdep",
		Package: "example.com/snapdep/vuln",
		Symbol:  "Parse",
	}
	first := invokePackageUsage(t, s, ctx, args)
	second := invokePackageUsage(t, s, ctx, args)
	b1, err := json.Marshal(first.Data)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := json.Marshal(second.Data)
	if err != nil {
		t.Fatal(err)
	}
	if string(b1) != string(b2) {
		t.Fatalf("payload not byte-stable:\n%s\nvs\n%s", b1, b2)
	}
}

// assertHasLimitation fails when none of the observation limitations
// carries the required text.
func assertHasLimitation(t *testing.T, lims []string, want string) {
	t.Helper()
	for _, l := range lims {
		if l == want {
			return
		}
	}
	t.Fatalf("required limitation missing: %q not in %v", want, lims)
}

// assertScopeShape checks the auditable scope contract every
// package-usage observation must carry: subject, snapshot hash, build
// context and loaded/skipped package counts.
func assertScopeShape(t *testing.T, o *Observation) {
	t.Helper()
	sd := o.ScopeDetails
	if sd == nil {
		t.Fatal("scope_details missing")
	}
	if sd.SnapshotHash == "" {
		t.Fatal("snapshot hash missing from scope")
	}
	if sd.Subject == "" {
		t.Fatal("subject missing from scope")
	}
	if sd.BuildContext == nil {
		t.Fatal("build context missing from scope")
	}
	if len(sd.Packages) == 0 {
		t.Fatal("loaded product package inventory missing from scope")
	}
	if sd.Extra["loaded_package_count"] == "" || sd.Extra["skipped_package_count"] == "" {
		t.Fatalf("loaded/skipped package counts missing: %v", sd.Extra)
	}
	if !strings.Contains(o.Scope, "GOOS=") || !strings.Contains(o.Scope, "GOARCH=") {
		t.Fatalf("scope does not record the build context: %q", o.Scope)
	}
}

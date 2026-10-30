package evidencetools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/affected"
	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/toolaudit"
	"github.com/davniy/izyan/internal/vulnerability"
)

// usageScopeStubTool serves two canned `go list -deps [-test] -json ./...`
// streams. The product stream links both/mod (transitively ext/mod/dep)
// into the main-module root; the -test stream additionally links
// test/only/pkg through the test-variant closure only.
type usageScopeStubTool struct {
	prodPkgs []byte
	prodErr  error
	testPkgs []byte
	testErr  error
}

func (u usageScopeStubTool) ListModules(context.Context, string, domain.ProductSnapshot) ([]byte, string, error) {
	return nil, "go list -m -json all", nil
}

func (u usageScopeStubTool) ListPackages(ctx context.Context, dir string, build domain.ProductSnapshot) ([]byte, error) {
	return u.ListPackagesScope(ctx, dir, build, true)
}

func (u usageScopeStubTool) ListPackagesScope(ctx context.Context, _ string, _ domain.ProductSnapshot, withTests bool) ([]byte, error) {
	// Record the go-list invocation exactly as ExecGoTool would, so the
	// observation's execution trail names both commands.
	args := []string{"list", "-deps"}
	if withTests {
		args = append(args, "-test")
	}
	args = append(args, "-json", "./...")
	if r := toolaudit.RecorderFrom(ctx); r != nil {
		r.Record(domain.ToolExecution{Tool: "go", Dir: "stub", Args: args})
	}
	if !withTests {
		if u.prodPkgs != nil || u.prodErr != nil {
			return u.prodPkgs, u.prodErr
		}
		return []byte(usageScopeProdStream), nil
	}
	if u.testPkgs != nil || u.testErr != nil {
		return u.testPkgs, u.testErr
	}
	return []byte(usageScopeTestStream), nil
}

const usageScopeProdStream = `
{"ImportPath":"example.com/evidencesnap","Name":"evidencesnap","Module":{"Path":"example.com/evidencesnap","Main":true},"Deps":["both/mod","ext/mod/dep"]}
{"ImportPath":"both/mod","Name":"mod","DepOnly":true,"Module":{"Path":"both","Version":"v1.0.0"},"Deps":["ext/mod/dep"]}
{"ImportPath":"ext/mod/dep","Name":"dep","DepOnly":true,"Module":{"Path":"ext/mod","Version":"v1.0.0"}}
`

const usageScopeTestStream = `
{"ImportPath":"example.com/evidencesnap","Name":"evidencesnap","Module":{"Path":"example.com/evidencesnap","Main":true},"Deps":["both/mod","ext/mod/dep"]}
{"ImportPath":"example.com/evidencesnap [example.com/evidencesnap.test]","Name":"evidencesnap","ForTest":"example.com/evidencesnap","Module":{"Path":"example.com/evidencesnap","Main":true},"Deps":["test/only/pkg","ext/mod/dep"]}
{"ImportPath":"example.com/evidencesnap_test [example.com/evidencesnap.test]","Name":"evidencesnap_test","ForTest":"example.com/evidencesnap","Module":{"Path":"example.com/evidencesnap","Main":true},"Deps":["test/only/pkg"]}
{"ImportPath":"example.com/evidencesnap.test","Name":"main","Deps":["example.com/evidencesnap [example.com/evidencesnap.test]","example.com/evidencesnap_test [example.com/evidencesnap.test]"]}
{"ImportPath":"both/mod","Name":"mod","DepOnly":true,"Module":{"Path":"both","Version":"v1.0.0"},"Deps":["ext/mod/dep"]}
{"ImportPath":"ext/mod/dep","Name":"dep","DepOnly":true,"Module":{"Path":"ext/mod","Version":"v1.0.0"}}
{"ImportPath":"test/only/pkg","Name":"pkg","DepOnly":true,"Module":{"Path":"test/only","Version":"v1.0.0"}}
`

// usageScopeDangling is an edge-closed violation: the root's Deps name a
// node the stream never carries.
const usageScopeDangling = `
{"ImportPath":"example.com/evidencesnap","Name":"evidencesnap","Module":{"Path":"example.com/evidencesnap","Main":true},"Deps":["missing/node"]}
{"ImportPath":"both/mod","Name":"mod","DepOnly":true,"Module":{"Path":"both","Version":"v1.0.0"}}
`

func newUsageScopeSession(t *testing.T, tool affected.GoTool) *Session {
	t.Helper()
	s := newTestSession(t)
	s.GoTool = tool
	return s
}

// invokeUsageScope drives the handler through the full invoke path so
// status, completeness downgrade and ID minting are exercised exactly as
// the MCP server runs them.
func invokeUsageScope(t *testing.T, s *Session, ctx context.Context, a UsageScopeArgs) *Observation {
	t.Helper()
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	return s.invoke(ctx, UsageScopeTool, raw, func(c context.Context) (*Observation, error) {
		return s.usageScope(c, a)
	})
}

func usageScopeData(t *testing.T, o *Observation) UsageScopeData {
	t.Helper()
	d, ok := o.Data.(UsageScopeData)
	if !ok {
		t.Fatalf("observation data is %T, want UsageScopeData", o.Data)
	}
	return d
}

// assertUsageScopeShape checks the auditable scope contract every
// usage-scope observation must carry: subject, snapshot identity, build
// context, both go-list commands, root semantics and the paired-stream
// coverage rule.
func assertUsageScopeShape(t *testing.T, o *Observation) {
	t.Helper()
	if o.ScopeDetails == nil {
		t.Fatal("no scope_details")
	}
	sd := o.ScopeDetails
	if sd.SnapshotHash == "" || sd.BuildContext == nil || sd.CoverageRule == "" {
		t.Fatalf("scope_details incomplete: %+v", sd)
	}
	if !strings.Contains(sd.CoverageRule, "go list -deps -json ./...") ||
		!strings.Contains(sd.CoverageRule, "go list -deps -test -json ./...") {
		t.Fatalf("coverage rule does not name both streams: %s", sd.CoverageRule)
	}
	for _, k := range []string{
		"product_closure_cmd", "test_closure_cmd",
		"closure_semantics",
		"product_root_semantics", "test_root_semantics",
		"product_package_count", "test_package_count",
		"product_root_count", "test_root_count",
	} {
		if sd.Extra[k] == "" {
			t.Fatalf("scope_details.extra[%s] missing: %+v", k, sd.Extra)
		}
	}
	if sd.Extra["closure_semantics"] != "product_all_packages" {
		t.Fatalf("closure_semantics=%q", sd.Extra["closure_semantics"])
	}
	if sd.Extra["product_root_count"] != "1" || sd.Extra["test_root_count"] != "3" {
		t.Fatalf("root counts: %+v", sd.Extra)
	}
}

func TestUsageScopeProduct(t *testing.T) {
	s := newUsageScopeSession(t, usageScopeStubTool{})
	o := invokeUsageScope(t, s, context.Background(), UsageScopeArgs{
		Module: "both", Package: "both/mod"})
	assertObs(t, o, StatusOK, CompletenessComplete)
	d := usageScopeData(t, o)
	if d.UsageScope != "product" || !d.ProductLinked || d.TestLinked {
		t.Fatalf("product payload: %+v", d)
	}
	if d.ProductAbsenceVerification != "" {
		t.Fatalf("product result carries absence verification %q", d.ProductAbsenceVerification)
	}
	assertHasLimitation(t, o.Limitations, usageScopeKnownLimit)
	assertUsageScopeShape(t, o)
}

func TestUsageScopeTestOnlyVerified(t *testing.T) {
	s := newUsageScopeSession(t, usageScopeStubTool{})
	o := invokeUsageScope(t, s, context.Background(), UsageScopeArgs{
		Module: "test/only", Package: "test/only/pkg"})
	assertObs(t, o, StatusOK, CompletenessComplete)
	d := usageScopeData(t, o)
	if d.UsageScope != "test-only" || d.ProductLinked || !d.TestLinked {
		t.Fatalf("test-only payload: %+v", d)
	}
	if d.ProductAbsenceVerification != affected.ProductAbsenceVerificationVerified {
		t.Fatalf("product_absence_verification=%q, want VERIFIED", d.ProductAbsenceVerification)
	}
	assertHasLimitation(t, o.Limitations, fmt.Sprintf(usageScopeTestOnlyLimitFmt, affected.UsageScopeSourceGoList))
	assertUsageScopeShape(t, o)
}

func TestUsageScopeMixed(t *testing.T) {
	s := newUsageScopeSession(t, usageScopeStubTool{})
	o := invokeUsageScope(t, s, context.Background(), UsageScopeArgs{
		Module: "ext/mod", Package: "ext/mod/dep"})
	assertObs(t, o, StatusOK, CompletenessComplete)
	d := usageScopeData(t, o)
	if d.UsageScope != "mixed" || !d.ProductLinked || !d.TestLinked {
		t.Fatalf("mixed payload: %+v", d)
	}
	if d.ProductAbsenceVerification != "" {
		t.Fatalf("mixed result carries absence verification %q", d.ProductAbsenceVerification)
	}
}

// A target absent from both complete closures stays unknown — never
// test-only and never a negative.
func TestUsageScopeUnknownAbsentFromBoth(t *testing.T) {
	s := newUsageScopeSession(t, usageScopeStubTool{})
	o := invokeUsageScope(t, s, context.Background(), UsageScopeArgs{
		Module: "absent/dep", Package: "absent/dep/pkg"})
	assertObs(t, o, StatusOK, CompletenessComplete)
	d := usageScopeData(t, o)
	if d.UsageScope != "unknown" || d.ProductLinked || d.TestLinked {
		t.Fatalf("unknown payload: %+v", d)
	}
	if d.ProductAbsenceVerification != "" {
		t.Fatalf("unknown carries absence verification %q", d.ProductAbsenceVerification)
	}
	assertHasLimitation(t, o.Limitations, usageScopeUnknownLimit)
}

// Module-only target: an aggregate over nodes matching the module
// identity; no package path is manufactured.
func TestUsageScopeModuleOnlyAggregate(t *testing.T) {
	s := newUsageScopeSession(t, usageScopeStubTool{})
	o := invokeUsageScope(t, s, context.Background(), UsageScopeArgs{Module: "test/only"})
	assertObs(t, o, StatusOK, CompletenessComplete)
	d := usageScopeData(t, o)
	if d.Package != "" {
		t.Fatalf("module-only aggregate carries package path %q", d.Package)
	}
	if d.UsageScope != "test-only" || !d.TestLinked || d.ProductLinked {
		t.Fatalf("module-only aggregate payload: %+v", d)
	}
	if d.ProductAbsenceVerification != affected.ProductAbsenceVerificationVerified {
		t.Fatalf("product_absence_verification=%q, want VERIFIED", d.ProductAbsenceVerification)
	}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `"package"`) {
		t.Fatalf("module-only payload serializes a package member: %s", b)
	}
}

// A failed product stream is an ERROR observation — no data payload, no
// COMPLETE scope, no verified fact material.
func TestUsageScopeFailedProductStream(t *testing.T) {
	s := newUsageScopeSession(t, usageScopeStubTool{prodErr: errors.New("go list failed")})
	o := invokeUsageScope(t, s, context.Background(), UsageScopeArgs{
		Module: "test/only", Package: "test/only/pkg"})
	assertObs(t, o, StatusError, CompletenessUnknown)
	if o.Data != nil {
		t.Fatalf("ERROR observation carries data: %+v", o.Data)
	}
}

// An undecodable test stream is an ERROR, never a verified negative.
func TestUsageScopeFailedTestStream(t *testing.T) {
	s := newUsageScopeSession(t, usageScopeStubTool{testPkgs: []byte(`{"ImportPath":`)})
	o := invokeUsageScope(t, s, context.Background(), UsageScopeArgs{
		Module: "test/only", Package: "test/only/pkg"})
	assertObs(t, o, StatusError, CompletenessUnknown)
	if o.Data != nil {
		t.Fatalf("ERROR observation carries data: %+v", o.Data)
	}
}

// A stream whose edges do not close is an ERROR — an incomplete closure
// can never underwrite test-only.
func TestUsageScopeDanglingEdgeStream(t *testing.T) {
	s := newUsageScopeSession(t, usageScopeStubTool{prodPkgs: []byte(usageScopeDangling)})
	o := invokeUsageScope(t, s, context.Background(), UsageScopeArgs{
		Module: "test/only", Package: "test/only/pkg"})
	assertObs(t, o, StatusError, CompletenessUnknown)
	if o.Data != nil {
		t.Fatalf("ERROR observation carries data: %+v", o.Data)
	}
}

// The argument contract fails closed: a missing module is an ERROR
// observation, not a classification over an invented subject.
func TestUsageScopeArgsValidation(t *testing.T) {
	s := newUsageScopeSession(t, usageScopeStubTool{})
	o := invokeUsageScope(t, s, context.Background(), UsageScopeArgs{})
	assertObs(t, o, StatusError, CompletenessUnknown)
	if o.Data != nil {
		t.Fatalf("missing module produced data: %+v", o.Data)
	}
}

// Under the strict profile without the toolchain permission the two
// go-list subprocesses are gated: UNSUPPORTED, never an observation.
func TestUsageScopeStrictToolchainGate(t *testing.T) {
	s := newUsageScopeSession(t, usageScopeStubTool{})
	s.Strict = true
	o := invokeUsageScope(t, s, context.Background(), UsageScopeArgs{
		Module: "test/only", Package: "test/only/pkg"})
	assertObs(t, o, StatusUnsupported, CompletenessUnknown)
	if o.Data != nil {
		t.Fatalf("UNSUPPORTED observation carries data: %+v", o.Data)
	}
	if !strings.Contains(o.Error, "allow-toolchain") {
		t.Fatalf("error names the missing permission: %s", o.Error)
	}
}

// The serialized payload and limitation list are deterministic across
// repeated calls on the same stub streams.
func TestUsageScopeDeterministicPayload(t *testing.T) {
	s := newUsageScopeSession(t, usageScopeStubTool{})
	a := UsageScopeArgs{Module: "test/only", Package: "test/only/pkg"}
	o1 := invokeUsageScope(t, s, context.Background(), a)
	o2 := invokeUsageScope(t, s, context.Background(), a)
	d1 := usageScopeData(t, o1)
	d2 := usageScopeData(t, o2)
	b1, err := json.Marshal(d1)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := json.Marshal(d2)
	if err != nil {
		t.Fatal(err)
	}
	if string(b1) != string(b2) {
		t.Fatalf("payload not deterministic:\n%s\n%s", b1, b2)
	}
	lims1, err := json.Marshal(o1.Limitations)
	if err != nil {
		t.Fatal(err)
	}
	lims2, err := json.Marshal(o2.Limitations)
	if err != nil {
		t.Fatal(err)
	}
	if string(lims1) != string(lims2) {
		t.Fatalf("limitations not deterministic:\n%s\n%s", lims1, lims2)
	}
}

// The audit record carries both go-list commands in the execution trail —
// the raw command audit survives through the toolaudit context.
func TestUsageScopeExecutionTrailRecordsBothCommands(t *testing.T) {
	s := newUsageScopeSession(t, usageScopeStubTool{})
	var recs []AuditRecord
	s.Audit = AuditFunc(func(_ context.Context, r AuditRecord) { recs = append(recs, r) })
	o := invokeUsageScope(t, s, context.Background(), UsageScopeArgs{
		Module: "test/only", Package: "test/only/pkg"})
	assertObs(t, o, StatusOK, CompletenessComplete)
	if len(recs) != 1 {
		t.Fatalf("audit records=%d, want 1", len(recs))
	}
	var prod, test bool
	for _, e := range recs[0].Executions {
		args := strings.Join(e.Args, " ")
		if strings.Contains(args, "list -deps -json ./...") && !strings.Contains(args, "-test") {
			prod = true
		}
		if strings.Contains(args, "list -deps -test -json ./...") {
			test = true
		}
	}
	if !prod || !test {
		t.Fatalf("execution trail missing go-list commands: %+v", recs[0].Executions)
	}
}

// vendoredUsageScopeRoot materializes a vendored snapshot exercising the
// offline derivation: dep/shared links into both closures, dep/testonly
// into the test closure only, dep/prod stays product-only behind the
// untested lib root, and example.com/unused sits in the closed inventory
// without a single import edge.
func vendoredUsageScopeRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(root, filepath.FromSlash(rel))
		must(t, os.MkdirAll(filepath.Dir(p), 0o755))
		must(t, os.WriteFile(p, []byte(body), 0o644))
	}
	write("go.mod", "module example.com/host\n\ngo 1.23\n\nrequire (\n\texample.com/dep v1.0.0\n\texample.com/unused v1.0.0\n)\n")
	write("main.go", "package main\n\nimport (\n\t\"fmt\"\n\t\"example.com/dep/shared\"\n)\n\nfunc main() { fmt.Println(shared.Name()) }\n")
	write("main_test.go", "package main\n\nimport (\n\t\"testing\"\n\t\"example.com/dep/testonly\"\n)\n\nfunc TestProbe(t *testing.T) {\n\tif testonly.Name() == \"\" {\n\t\tt.Fatal(\"empty\")\n\t}\n}\n")
	write("lib/lib.go", "package lib\n\nimport \"example.com/dep/prod\"\n\nfunc V() string { return prod.Name() }\n")
	write("vendor/modules.txt",
		"# example.com/dep v1.0.0\n"+
			"## explicit; go 1.23\n"+
			"example.com/dep/prod\n"+
			"example.com/dep/shared\n"+
			"example.com/dep/testonly\n"+
			"# example.com/unused v1.0.0\n"+
			"## explicit; go 1.23\n"+
			"example.com/unused/pkg\n")
	write("vendor/example.com/dep/prod/prod.go", "package prod\n\nfunc Name() string { return \"p\" }\n")
	write("vendor/example.com/dep/shared/shared.go", "package shared\n\nfunc Name() string { return \"s\" }\n")
	write("vendor/example.com/dep/testonly/testonly.go", "package testonly\n\nfunc Name() string { return \"t\" }\n")
	write("vendor/example.com/unused/pkg/pkg.go", "package pkg\n\nfunc Name() string { return \"u\" }\n")
	return root
}

// newVendoredUsageScopeSession opens a session over the vendored fixture;
// GoTool is left nil deliberately — the offline path must never touch it.
func newVendoredUsageScopeSession(t *testing.T, strict bool) *Session {
	t.Helper()
	s, err := NewSession(SessionConfig{
		CVEID:        "GO-TEST-0001",
		SnapshotRoot: vendoredUsageScopeRoot(t),
		ExternalSHA:  "testsha0123456789",
		Strict:       strict,
		VulnSource:   vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{"GO-TEST-0001": testVuln}},
		Audit:        NopAudit{},
	})
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	return s
}

// A vendored snapshot classifies offline with no toolchain permission:
// the test-only target yields the VERIFIED product-absence marker the
// decision gate accepts, the payload names the derivation source, and
// scope details carry the vendor closure contract.
func TestUsageScopeVendoredTestOnlyVerified(t *testing.T) {
	s := newVendoredUsageScopeSession(t, true)
	o := invokeUsageScope(t, s, context.Background(), UsageScopeArgs{
		Module: "example.com/dep", Package: "example.com/dep/testonly"})
	assertObs(t, o, StatusOK, CompletenessComplete)
	d := usageScopeData(t, o)
	if d.UsageScope != "test-only" || d.ProductLinked || !d.TestLinked {
		t.Fatalf("vendored test-only payload: %+v", d)
	}
	if d.ProductAbsenceVerification != affected.ProductAbsenceVerificationVerified {
		t.Fatalf("product_absence_verification=%q, want VERIFIED", d.ProductAbsenceVerification)
	}
	if d.ClosureSource != affected.VendorClosureSource {
		t.Fatalf("closure_source=%q", d.ClosureSource)
	}
	if o.ScopeDetails == nil || o.ScopeDetails.CoverageRule != vendorClosureCoverageRule {
		t.Fatalf("vendored coverage rule: %+v", o.ScopeDetails)
	}
	sd := o.ScopeDetails
	if sd.BuildContext == nil || sd.BuildContext.GOOS == "" || sd.BuildContext.GOARCH == "" || !sd.BuildContext.VendorMode {
		t.Fatalf("build context: %+v", sd.BuildContext)
	}
	for _, k := range []string{"closure_source", "product_closure_source", "test_closure_source",
		"vendor_inventory_source", "product_root_semantics", "test_root_semantics",
		"product_package_count", "test_package_count", "product_root_count", "test_root_count"} {
		if sd.Extra[k] == "" {
			t.Fatalf("scope_details.extra[%s] missing: %+v", k, sd.Extra)
		}
	}
	if len(o.EvidenceRefs) == 0 || !strings.HasPrefix(o.EvidenceRefs[0], "sha256:") {
		t.Fatalf("evidence refs: %v", o.EvidenceRefs)
	}
	assertHasLimitation(t, o.Limitations, fmt.Sprintf(usageScopeTestOnlyLimitFmt, affected.VendorClosureSource))
}

// Mixed and product classes classify through the same offline closure;
// an absent-from-both package is unknown and, under the closed vendor
// inventory, additionally carries VERIFIED_VENDOR_INVENTORY.
func TestUsageScopeVendoredClasses(t *testing.T) {
	s := newVendoredUsageScopeSession(t, false)
	for pkg, want := range map[string]affected.UsageScope{
		"example.com/dep/prod":   affected.UsageScopeProduct,
		"example.com/dep/shared": affected.UsageScopeMixed,
		"example.com/dep/absent": affected.UsageScopeUnknown,
	} {
		o := invokeUsageScope(t, s, context.Background(), UsageScopeArgs{Module: "example.com/dep", Package: pkg})
		assertObs(t, o, StatusOK, CompletenessComplete)
		if d := usageScopeData(t, o); d.UsageScope != string(want) {
			t.Fatalf("%s: usage_scope=%s want %s", pkg, d.UsageScope, want)
		}
	}
}

// The vendor-inventory absence marker: an absent-from-both subject on a
// vendored snapshot keeps usage_scope=unknown but records
// VERIFIED_VENDOR_INVENTORY with the closure_source/closure_semantics/
// vendor_mode conditions the decision gate checks. A module-level
// subject gets the marker only when the module is absent from every
// inventory leg; a vendored-but-unreachable module stays plain unknown.
func TestUsageScopeVendoredInventoryMarker(t *testing.T) {
	s := newVendoredUsageScopeSession(t, true)

	o := invokeUsageScope(t, s, context.Background(), UsageScopeArgs{
		Module: "example.com/dep", Package: "example.com/dep/absent"})
	assertObs(t, o, StatusOK, CompletenessComplete)
	d := usageScopeData(t, o)
	if d.UsageScope != "unknown" || d.ProductLinked || d.TestLinked {
		t.Fatalf("absent payload: %+v", d)
	}
	if d.ProductAbsenceVerification != affected.ProductAbsenceVerificationVendorInventory {
		t.Fatalf("product_absence_verification=%q, want VERIFIED_VENDOR_INVENTORY", d.ProductAbsenceVerification)
	}
	if d.ClosureSource != affected.VendorClosureSource ||
		d.ClosureSemantics != affected.ClosureSemanticsProductAllPackages {
		t.Fatalf("closure provenance: %+v", d)
	}
	sd := o.ScopeDetails
	if sd == nil || sd.BuildContext == nil || !sd.BuildContext.VendorMode ||
		sd.CoverageRule != vendorClosureCoverageRule ||
		sd.Extra["closure_semantics"] != "product_all_packages" {
		t.Fatalf("scope details: %+v", sd)
	}
	assertHasLimitation(t, o.Limitations, usageScopeVendorInventoryLimit)

	// Module-level: an inventory-absent module carries the marker at
	// empty package identity; a listed-but-unreachable module does not.
	o = invokeUsageScope(t, s, context.Background(), UsageScopeArgs{Module: "example.com/gone"})
	assertObs(t, o, StatusOK, CompletenessComplete)
	d = usageScopeData(t, o)
	if d.UsageScope != "unknown" || d.Package != "" ||
		d.ProductAbsenceVerification != affected.ProductAbsenceVerificationVendorInventory {
		t.Fatalf("module-level inventory absence: %+v", d)
	}
	o = invokeUsageScope(t, s, context.Background(), UsageScopeArgs{Module: "example.com/unused"})
	assertObs(t, o, StatusOK, CompletenessComplete)
	d = usageScopeData(t, o)
	if d.UsageScope != "unknown" || d.ProductAbsenceVerification != "" {
		t.Fatalf("vendored-but-unreachable module must not carry the marker: %+v", d)
	}
}

// An unresolvable import in the vendored tree is an ERROR observation —
// never a classification and never a verified negative.
func TestUsageScopeVendoredUnresolvedImport(t *testing.T) {
	root := vendoredUsageScopeRoot(t)
	must(t, os.WriteFile(filepath.Join(root, "lib", "lib.go"),
		[]byte("package lib\n\nimport _ \"example.com/dep/missing\"\n"), 0o644))
	s, err := NewSession(SessionConfig{
		CVEID: "GO-TEST-0001", SnapshotRoot: root, ExternalSHA: "testsha0123456789",
		VulnSource: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{"GO-TEST-0001": testVuln}},
		Audit:      NopAudit{},
	})
	must(t, err)
	o := invokeUsageScope(t, s, context.Background(), UsageScopeArgs{
		Module: "example.com/dep", Package: "example.com/dep/testonly"})
	assertObs(t, o, StatusError, CompletenessUnknown)
	if o.Data != nil {
		t.Fatalf("ERROR observation carries data: %+v", o.Data)
	}
	if !strings.Contains(o.Error, "unresolved import") && !strings.Contains(o.Error, "unlisted") {
		t.Fatalf("error names the failure: %s", o.Error)
	}
}

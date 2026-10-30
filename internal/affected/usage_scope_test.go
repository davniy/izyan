package affected

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

// prodMainModule is the main module in all usage-scope fixtures; the
// advisory target module is example.com/ext.
const usageProdStream = `{"ImportPath":"example.com/prod","Name":"main","Module":{"Path":"example.com/prod","Main":true},"Deps":["example.com/prod/lib","example.com/ext/used","example.com/ext/mixed","fmt"]}
{"ImportPath":"example.com/prod/lib","Name":"lib","Module":{"Path":"example.com/prod","Main":true},"Deps":["fmt"]}
{"ImportPath":"example.com/prod/testutil","Name":"testutil","Module":{"Path":"example.com/prod","Main":true},"Deps":[]}
{"ImportPath":"fmt","Name":"fmt","Standard":true,"DepOnly":true,"Deps":[]}
{"ImportPath":"example.com/ext/used","Name":"used","DepOnly":true,"Module":{"Path":"example.com/ext","Version":"v1.0.0"},"Deps":["example.com/ext/helper"]}
{"ImportPath":"example.com/ext/helper","Name":"helper","DepOnly":true,"Module":{"Path":"example.com/ext","Version":"v1.0.0"},"Deps":[]}
{"ImportPath":"example.com/ext/mixed","Name":"mixed","DepOnly":true,"Module":{"Path":"example.com/ext","Version":"v1.0.0"},"Deps":[]}`

// usageTestStream mirrors a real `go list -deps -test -json ./...` shape:
// product roots plus a ForTest variant and a synthetic .test driver whose
// Deps carry bracketed variant paths.
const usageTestStream = `{"ImportPath":"example.com/prod","Name":"main","Module":{"Path":"example.com/prod","Main":true},"Deps":["example.com/prod/lib","example.com/ext/used","example.com/ext/mixed","example.com/ext/teststreamonly","fmt"]}
{"ImportPath":"example.com/prod/lib","Name":"lib","Module":{"Path":"example.com/prod","Main":true},"Deps":["fmt"]}
{"ImportPath":"example.com/prod/testutil","Name":"testutil","Module":{"Path":"example.com/prod","Main":true},"Deps":[]}
{"ImportPath":"fmt","Name":"fmt","Standard":true,"DepOnly":true,"Deps":[]}
{"ImportPath":"testing","Name":"testing","Standard":true,"DepOnly":true,"Deps":[]}
{"ImportPath":"example.com/ext/used","Name":"used","DepOnly":true,"Module":{"Path":"example.com/ext","Version":"v1.0.0"},"Deps":["example.com/ext/helper"]}
{"ImportPath":"example.com/ext/helper","Name":"helper","DepOnly":true,"Module":{"Path":"example.com/ext","Version":"v1.0.0"},"Deps":[]}
{"ImportPath":"example.com/ext/mixed","Name":"mixed","DepOnly":true,"Module":{"Path":"example.com/ext","Version":"v1.0.0"},"Deps":[]}
{"ImportPath":"example.com/ext/teststreamonly","Name":"teststreamonly","DepOnly":true,"Module":{"Path":"example.com/ext","Version":"v1.0.0"},"Deps":[]}
{"ImportPath":"example.com/prod/lib [example.com/prod/lib.test]","Name":"lib","ForTest":"example.com/prod/lib","Module":{"Path":"example.com/prod","Main":true},"Deps":["example.com/ext/testonly","example.com/prod/testhelper","testing"]}
{"ImportPath":"example.com/prod/lib.test","Name":"main","Module":{"Path":"example.com/prod","Main":true},"Deps":["example.com/prod/lib [example.com/prod/lib.test]","example.com/ext/testonly","example.com/ext/mixed","testing"]}
{"ImportPath":"example.com/ext/testonly","Name":"testonly","DepOnly":true,"Module":{"Path":"example.com/ext","Version":"v1.0.0"},"Deps":[]}
{"ImportPath":"example.com/prod/testhelper","Name":"testhelper","DepOnly":true,"Module":{"Path":"example.com/prod","Main":true},"Deps":[]}`

func usageProduct() domain.ProductSnapshot {
	return domain.ProductSnapshot{Repository: "/repo", Commit: "deadbeef", GOOS: "linux", GOARCH: "amd64", CGOEnabled: true}
}

func usageClassify(t *testing.T, tool GoTool, module, pkg string) (UsageScopeResult, error) {
	t.Helper()
	return ClassifyUsageScope(context.Background(), tool, "/repo", usageProduct(), module, pkg)
}

func usageTool(t *testing.T) fakeTool {
	t.Helper()
	return fakeTool{prodPkgs: []byte(usageProdStream), testPkgs: []byte(usageTestStream)}
}

func TestUsageScopeProduct(t *testing.T) {
	res, err := usageClassify(t, usageTool(t), "example.com/ext", "example.com/ext/used")
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if res.Usage != UsageScopeProduct || !res.ProductLinked || res.TestLinked {
		t.Fatalf("got %+v, want product-linked only", res)
	}
	if res.ProductAbsenceVerification != "" {
		t.Fatalf("unexpected product-absence marker: %q", res.ProductAbsenceVerification)
	}
	// Transitive product dep also classifies as product.
	res, err = usageClassify(t, usageTool(t), "example.com/ext", "example.com/ext/helper")
	if err != nil {
		t.Fatalf("classify helper: %v", err)
	}
	if res.Usage != UsageScopeProduct {
		t.Fatalf("helper: got %s, want product", res.Usage)
	}
}

func TestUsageScopeTestOnly(t *testing.T) {
	res, err := usageClassify(t, usageTool(t), "example.com/ext", "example.com/ext/testonly")
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if res.Usage != UsageScopeTestOnly {
		t.Fatalf("got %s, want test-only", res.Usage)
	}
	if res.ProductLinked || !res.TestLinked {
		t.Fatalf("got ProductLinked=%v TestLinked=%v", res.ProductLinked, res.TestLinked)
	}
	if res.ProductAbsenceVerification != ProductAbsenceVerificationVerified {
		t.Fatalf("got product-absence %q, want VERIFIED", res.ProductAbsenceVerification)
	}
	if res.ProductPackageCount != 7 || res.TestPackageCount != 6 ||
		res.ProductRootCount != 3 || res.TestRootCount != 2 {
		t.Fatalf("counts: %+v", res)
	}
}

func TestUsageScopeMixed(t *testing.T) {
	res, err := usageClassify(t, usageTool(t), "example.com/ext", "example.com/ext/mixed")
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if res.Usage != UsageScopeMixed || !res.ProductLinked || !res.TestLinked {
		t.Fatalf("got %+v, want mixed", res)
	}
	if res.ProductAbsenceVerification != "" {
		t.Fatalf("mixed must not mark product absence: %q", res.ProductAbsenceVerification)
	}
}

func TestUsageScopeAbsentBothIsUnknown(t *testing.T) {
	res, err := usageClassify(t, usageTool(t), "example.com/ext", "example.com/ext/absent")
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if res.Usage != UsageScopeUnknown || res.ProductLinked || res.TestLinked {
		t.Fatalf("got %+v, want unknown", res)
	}
	if res.ProductAbsenceVerification != "" {
		t.Fatalf("unknown must not mark product absence")
	}
}

// A package present in the merged `-test` stream but unreachable from any
// recognized test root is never test-only — plain presence is not test use.
func TestUsageScopeTestStreamPresenceIsNotTestUse(t *testing.T) {
	res, err := usageClassify(t, usageTool(t), "example.com/ext", "example.com/ext/teststreamonly")
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if res.Usage == UsageScopeTestOnly {
		t.Fatalf("test-stream presence without test-root reachability gave test-only")
	}
	if res.Usage != UsageScopeUnknown {
		t.Fatalf("got %s, want unknown", res.Usage)
	}
	// ext/helper is likewise in the -test stream (product-reachable only)
	// and stays product, never test-only.
	res, err = usageClassify(t, usageTool(t), "example.com/ext", "example.com/ext/helper")
	if err != nil {
		t.Fatalf("classify helper: %v", err)
	}
	if res.Usage != UsageScopeProduct {
		t.Fatalf("helper in -test stream: got %s, want product", res.Usage)
	}
}

func TestUsageScopeModuleAggregate(t *testing.T) {
	res, err := usageClassify(t, usageTool(t), "example.com/ext", "")
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if res.Package != "" {
		t.Fatalf("module target manufactured package %q", res.Package)
	}
	if res.Usage != UsageScopeMixed {
		t.Fatalf("module aggregate: got %s, want mixed", res.Usage)
	}
	if len(res.Limitations) == 0 || !strings.Contains(res.Limitations[0], "module-level aggregate") {
		t.Fatalf("module aggregate limitation missing: %v", res.Limitations)
	}
	// Unknown module: no matching nodes in either closure.
	res, err = usageClassify(t, usageTool(t), "example.com/nomod", "")
	if err != nil {
		t.Fatalf("classify nomod: %v", err)
	}
	if res.Usage != UsageScopeUnknown || res.Package != "" {
		t.Fatalf("nomod: got %+v, want unknown", res)
	}
}

func TestUsageScopeModuleTestOnly(t *testing.T) {
	// ext/testonly exists only in the test closure → module aggregate
	// is test-only, with the module-level (not package-level) marker.
	res, err := usageClassify(t, usageTool(t), "example.com/ext", "example.com/ext/testonly")
	if err != nil || res.Usage != UsageScopeTestOnly {
		t.Fatalf("sanity: %v %+v", err, res)
	}
	prod := `{"ImportPath":"example.com/prod","Name":"main","Module":{"Path":"example.com/prod","Main":true},"Deps":["example.com/prod/lib"]}
{"ImportPath":"example.com/prod/lib","Name":"lib","Module":{"Path":"example.com/prod","Main":true},"Deps":[]}`
	tool := fakeTool{prodPkgs: []byte(prod), testPkgs: []byte(usageTestStream)}
	res, err = usageClassify(t, tool, "example.com/ext", "")
	if err != nil {
		t.Fatalf("classify module: %v", err)
	}
	if res.Usage != UsageScopeTestOnly || res.ProductAbsenceVerification != ProductAbsenceVerificationVerified {
		t.Fatalf("module test-only: got %+v", res)
	}
	if res.Package != "" {
		t.Fatalf("manufactured package %q", res.Package)
	}
}

// An empty or root-less product stream is a missing enumeration, never
// proof of absence: it must error, and can never yield test-only.
func TestUsageScopeEmptyProductStream(t *testing.T) {
	for name, prod := range map[string][]byte{
		"empty stdout":     nil,
		"empty JSON array": []byte(`[]`),
		"no product roots": []byte(`{"ImportPath":"example.com/dep","Name":"dep","DepOnly":true,"Deps":[]}`),
	} {
		tool := usageTool(t)
		tool.prodPkgs = prod
		res, err := usageClassify(t, tool, "example.com/ext", "example.com/ext/testonly")
		if err == nil {
			t.Fatalf("%s: want error", name)
		}
		if res.Usage == UsageScopeTestOnly || res.ProductAbsenceVerification != "" {
			t.Fatalf("%s: manufactured verified absence: %+v", name, res)
		}
	}
}

func TestUsageScopeEmptyTestStream(t *testing.T) {
	for name, test := range map[string][]byte{
		"empty stdout":     nil,
		"empty JSON array": []byte(`[]`),
	} {
		tool := usageTool(t)
		tool.testPkgs = test
		res, err := usageClassify(t, tool, "example.com/ext", "example.com/ext/testonly")
		if err == nil {
			t.Fatalf("%s: want error", name)
		}
		if res.Usage == UsageScopeTestOnly {
			t.Fatalf("%s: empty test stream classified test-only", name)
		}
	}
}

// A root whose Deps field is omitted while another node carries Deps
// must not read as a leaf: its Imports are unverified edges. The target
// they name is absent from the stream — a dangling edge that previously
// became a closed negative.
func TestUsageScopeOmittedDepsHidesImports(t *testing.T) {
	prod := `{"ImportPath":"example.com/prod","Name":"main","Module":{"Path":"example.com/prod","Main":true},"Imports":["example.com/ext/vuln"]}
{"ImportPath":"example.com/prod/lib","Name":"lib","Module":{"Path":"example.com/prod","Main":true},"Deps":["fmt"],"Imports":["fmt"]}
{"ImportPath":"fmt","Name":"fmt","Standard":true,"DepOnly":true,"Deps":[]}`
	tool := fakeTool{prodPkgs: []byte(prod), testPkgs: []byte(usageTestStream)}
	res, err := usageClassify(t, tool, "example.com/ext", "example.com/ext/testonly")
	if err == nil {
		t.Fatal("omitted Deps with non-empty Imports must error")
	}
	if res.Usage == UsageScopeTestOnly || res.ProductAbsenceVerification != "" {
		t.Fatalf("hidden import classified absence: %+v", res)
	}
}

// Imports naming a package missing from Deps is an inconsistent
// inventory even when the imported node exists in the stream.
func TestUsageScopeImportNotInDeps(t *testing.T) {
	prod := `{"ImportPath":"example.com/prod","Name":"main","Module":{"Path":"example.com/prod","Main":true},"Deps":["fmt","example.com/prod/lib"],"Imports":["fmt","example.com/prod/lib","example.com/ext/extra"]}
{"ImportPath":"example.com/prod/lib","Name":"lib","Module":{"Path":"example.com/prod","Main":true},"Deps":["example.com/ext/extra"],"Imports":["example.com/ext/extra"]}
{"ImportPath":"fmt","Name":"fmt","Standard":true,"DepOnly":true,"Deps":[]}
{"ImportPath":"example.com/ext/extra","Name":"extra","DepOnly":true,"Module":{"Path":"example.com/ext","Version":"v1.0.0"},"Deps":[]}`
	tool := fakeTool{prodPkgs: []byte(prod), testPkgs: []byte(usageTestStream)}
	res, err := usageClassify(t, tool, "example.com/ext", "example.com/ext/testonly")
	if err == nil {
		t.Fatal("import absent from Deps must error")
	}
	if res.Usage == UsageScopeTestOnly {
		t.Fatal("inconsistent inventory classified test-only")
	}
}

// The cgo pseudo-import "C" is not a package node: it is exempt from
// edge and inventory checks, and must not break classification.
func TestUsageScopePseudoImportC(t *testing.T) {
	prod := `{"ImportPath":"example.com/prod","Name":"main","Module":{"Path":"example.com/prod","Main":true},"Deps":["fmt","runtime/cgo"],"Imports":["C","fmt","runtime/cgo"]}
{"ImportPath":"fmt","Name":"fmt","Standard":true,"DepOnly":true,"Deps":[]}
{"ImportPath":"runtime/cgo","Name":"cgo","Standard":true,"DepOnly":true,"Deps":[]}`
	tool := fakeTool{prodPkgs: []byte(prod), testPkgs: []byte(usageTestStream)}
	res, err := usageClassify(t, tool, "example.com/ext", "example.com/ext/testonly")
	if err != nil {
		t.Fatalf("cgo pseudo-import broke classification: %v", err)
	}
	if res.Usage != UsageScopeTestOnly {
		t.Fatalf("got %s, want test-only", res.Usage)
	}
}

// Pseudo-import edges must never be traversed: "C" has no package node,
// so pushing it onto the walk stack dereferences nil. Exercise the
// Imports fallback (no Deps anywhere) and an authoritative-Deps shape.
func TestUsageScopePseudoImportNeverTraversed(t *testing.T) {
	// Imports-fallback stream: no node carries Deps, so Imports drives
	// traversal — a "C" edge previously panicked.
	prod := `{"ImportPath":"example.com/prod","Name":"main","Module":{"Path":"example.com/prod","Main":true},"Imports":["C","example.com/prod/lib"]}
{"ImportPath":"example.com/prod/lib","Name":"lib","Module":{"Path":"example.com/prod","Main":true},"Imports":["C"]}`
	tool := fakeTool{prodPkgs: []byte(prod), testPkgs: []byte(usageTestStream)}
	res, err := usageClassify(t, tool, "example.com/ext", "example.com/ext/testonly")
	if err != nil {
		t.Fatalf("Imports-fallback with C: %v", err)
	}
	if res.Usage != UsageScopeTestOnly {
		t.Fatalf("got %s, want test-only", res.Usage)
	}
	// Authoritative-Deps stream where C appears in Deps with no node.
	prod = `{"ImportPath":"example.com/prod","Name":"main","Module":{"Path":"example.com/prod","Main":true},"Deps":["C","fmt"],"Imports":["C","fmt"]}
{"ImportPath":"example.com/prod/lib","Name":"lib","Module":{"Path":"example.com/prod","Main":true},"Deps":[]}
{"ImportPath":"fmt","Name":"fmt","Standard":true,"DepOnly":true,"Deps":[]}`
	tool = fakeTool{prodPkgs: []byte(prod), testPkgs: []byte(usageTestStream)}
	res, err = usageClassify(t, tool, "example.com/ext", "example.com/ext/testonly")
	if err != nil {
		t.Fatalf("Deps with C: %v", err)
	}
	if res.Usage != UsageScopeTestOnly {
		t.Fatalf("got %s, want test-only", res.Usage)
	}
}

// A replace directive rewrites where module bytes come from, not module
// membership: module aggregation must match the declared Module.Path.
func TestUsageScopeModuleReplaceStillMatches(t *testing.T) {
	prod := `{"ImportPath":"example.com/prod","Name":"main","Module":{"Path":"example.com/prod","Main":true},"Deps":[]}`
	test := `{"ImportPath":"example.com/prod","Name":"main","Module":{"Path":"example.com/prod","Main":true},"Deps":[]}
{"ImportPath":"example.com/prod/p [example.com/prod/p.test]","Name":"p","ForTest":"example.com/prod/p","Module":{"Path":"example.com/prod","Main":true},"Deps":["example.com/ext/vuln"]}
{"ImportPath":"example.com/prod/p.test","Name":"main","Module":{"Path":"example.com/prod","Main":true},"Deps":["example.com/prod/p [example.com/prod/p.test]"]}
{"ImportPath":"example.com/ext/vuln","Name":"vuln","DepOnly":true,"Module":{"Path":"example.com/ext","Version":"v1.0.0","Replace":{"Path":"/local/checkout/ext"}},"Deps":[]}`
	res, err := usageClassify(t, fakeTool{prodPkgs: []byte(prod), testPkgs: []byte(test)}, "example.com/ext", "")
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if res.Usage != UsageScopeTestOnly {
		t.Fatalf("replaced module aggregate: got %s, want test-only", res.Usage)
	}
}

func TestUsageScopeProductStreamError(t *testing.T) {
	tool := usageTool(t)
	tool.prodErr = errors.New("go list failed")
	res, err := usageClassify(t, tool, "example.com/ext", "example.com/ext/testonly")
	if err == nil {
		t.Fatal("want error on failed product stream")
	}
	if res.Usage == UsageScopeTestOnly {
		t.Fatal("product stream error classified test-only")
	}
	if res.Usage != UsageScopeUnknown {
		t.Fatalf("got %s, want unknown", res.Usage)
	}
}

func TestUsageScopeTestStreamError(t *testing.T) {
	tool := usageTool(t)
	tool.testErr = errors.New("go list failed")
	res, err := usageClassify(t, tool, "example.com/ext", "example.com/ext/testonly")
	if err == nil {
		t.Fatal("want error on failed test stream")
	}
	if res.Usage == UsageScopeTestOnly || res.Usage != UsageScopeUnknown {
		t.Fatalf("test stream error gave %s", res.Usage)
	}
}

func TestUsageScopeMalformedStream(t *testing.T) {
	tool := usageTool(t)
	tool.prodPkgs = []byte(`{"ImportPath":`)
	if _, err := usageClassify(t, tool, "example.com/ext", "example.com/ext/testonly"); err == nil {
		t.Fatal("malformed product stream must error")
	}
	tool = usageTool(t)
	tool.testPkgs = []byte(`{"ImportPath":`)
	if _, err := usageClassify(t, tool, "example.com/ext", "example.com/ext/testonly"); err == nil {
		t.Fatal("malformed test stream must error")
	}
}

func TestUsageScopePackageErrorNode(t *testing.T) {
	// A node carrying Error/DepsErrors/Incomplete makes the stream
	// incomplete — error, never a closed negative.
	tool := usageTool(t)
	tool.prodPkgs = []byte(usageProdStream + `
{"ImportPath":"example.com/prod/broken","Name":"broken","Module":{"Path":"example.com/prod","Main":true},"Deps":[],"Incomplete":true}`)
	if _, err := usageClassify(t, tool, "example.com/ext", "example.com/ext/testonly"); err == nil {
		t.Fatal("incomplete-node product stream must error")
	}
	tool = usageTool(t)
	tool.testPkgs = []byte(usageTestStream + `
{"ImportPath":"example.com/prod/broken.test","Name":"main","Module":{"Path":"example.com/prod","Main":true},"Deps":[],"Error":{"Err":"compile failed"}}`)
	if _, err := usageClassify(t, tool, "example.com/ext", "example.com/ext/testonly"); err == nil {
		t.Fatal("error-node test stream must error")
	}
}

func TestUsageScopeUnresolvedEdge(t *testing.T) {
	// A dependency edge pointing at a node absent from the stream is an
	// unresolved edge → incomplete, not a closed negative.
	tool := usageTool(t)
	tool.prodPkgs = []byte(`{"ImportPath":"example.com/prod","Name":"main","Module":{"Path":"example.com/prod","Main":true},"Deps":["example.com/gone"]}
{"ImportPath":"example.com/prod/lib","Name":"lib","Module":{"Path":"example.com/prod","Main":true},"Deps":[]}`)
	res, err := usageClassify(t, tool, "example.com/ext", "example.com/ext/testonly")
	if err == nil {
		t.Fatal("unresolved edge must error")
	}
	if res.Usage == UsageScopeTestOnly {
		t.Fatal("unresolved edge classified test-only")
	}
}

func TestUsageScopeOrphanNode(t *testing.T) {
	// A package unreachable from every root is an inconsistent stream:
	// its presence cannot be trusted either way.
	tool := usageTool(t)
	tool.testPkgs = []byte(usageTestStream + `
{"ImportPath":"example.com/ext/orphan","Name":"orphan","DepOnly":true,"Module":{"Path":"example.com/ext","Version":"v1.0.0"},"Deps":[]}`)
	res, err := usageClassify(t, tool, "example.com/ext", "example.com/ext/orphan")
	if err == nil {
		t.Fatal("orphan node must make the stream incomplete")
	}
	if res.Usage == UsageScopeTestOnly {
		t.Fatal("unreachable -test stream node classified test-only")
	}
}

func TestUsageScopeDeterministic(t *testing.T) {
	res1, err := usageClassify(t, usageTool(t), "example.com/ext", "example.com/ext/testonly")
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	res2, err := usageClassify(t, usageTool(t), "example.com/ext", "example.com/ext/testonly")
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	b1, _ := json.Marshal(res1)
	b2, _ := json.Marshal(res2)
	if string(b1) != string(b2) {
		t.Fatalf("repeated classification differs:\n%s\n%s", b1, b2)
	}
	// Node order in the stream must not change the result either.
	rev := func(s string) string {
		lines := strings.Split(s, "\n")
		slices.Reverse(lines)
		return strings.Join(lines, "\n")
	}
	tool := fakeTool{prodPkgs: []byte(rev(usageProdStream)), testPkgs: []byte(rev(usageTestStream))}
	res3, err := usageClassify(t, tool, "example.com/ext", "example.com/ext/testonly")
	if err != nil {
		t.Fatalf("classify reversed: %v", err)
	}
	b3, _ := json.Marshal(res3)
	if string(b1) != string(b3) {
		t.Fatalf("stream order changed result:\n%s\n%s", b1, b3)
	}
}

func TestUsageScopeCheckScopeRecords(t *testing.T) {
	res, err := usageClassify(t, usageTool(t), "example.com/ext", "example.com/ext/testonly")
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	for _, want := range []string{
		"go list -deps -json ./...",
		"go list -deps -test -json ./...",
		"GOOS=linux",
		"GOARCH=amd64",
		"CGO_ENABLED=1",
		"example.com/ext/testonly",
		"reflection",
		"plugin",
	} {
		if !strings.Contains(res.CheckScope, want) {
			t.Fatalf("check scope missing %q:\n%s", want, res.CheckScope)
		}
	}
}

// ListPackages must keep delegating to the with-tests stream so existing
// resolver semantics are unchanged.
func TestListPackagesDelegatesToTestScope(t *testing.T) {
	want := []byte(`{"ImportPath":"x"}`)
	f := fakeTool{packages: want}
	got, err := f.ListPackages(context.Background(), "/repo", usageProduct())
	if err != nil || string(got) != string(want) {
		t.Fatalf("ListPackages: %q %v", got, err)
	}
	f = fakeTool{testPkgs: want, packages: []byte(`{"ImportPath":"other"}`)}
	got, err = f.ListPackages(context.Background(), "/repo", usageProduct())
	if err != nil || string(got) != string(want) {
		t.Fatalf("ListPackages with scoped stream: %q %v", got, err)
	}
}

// The scope classifier shares the strict inventory decoder: a complete
// prefix followed by a stray token or a truncated value is not a closed
// stream, so it can never yield a test-only classification.
func TestUsageScopeTrailingJunkStream(t *testing.T) {
	tool := usageTool(t)
	tool.prodPkgs = []byte(usageProdStream + "\n]")
	res, err := usageClassify(t, tool, "example.com/ext", "example.com/ext/testonly")
	if err == nil {
		t.Fatal("trailing token in product stream must error")
	}
	if res.Usage == UsageScopeTestOnly || res.ProductAbsenceVerification != "" {
		t.Fatalf("trailing token produced a verified absence: %+v", res)
	}

	tool = usageTool(t)
	tool.testPkgs = []byte(usageTestStream + "\n{\"ImportPath\":")
	if _, err := usageClassify(t, tool, "example.com/ext", "example.com/ext/testonly"); err == nil {
		t.Fatal("truncated test stream must error")
	}
}

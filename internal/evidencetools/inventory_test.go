package evidencetools

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/affected"
	"github.com/davniy/izyan/internal/domain"
)

type inventoryTool struct { raw []byte; err error; tests bool }
func (f *inventoryTool) ListModules(context.Context, string, domain.ProductSnapshot) ([]byte, string, error) { return nil, "", nil }
func (f *inventoryTool) ListPackages(ctx context.Context, dir string, b domain.ProductSnapshot) ([]byte, error) { return f.ListPackagesScope(ctx, dir, b, true) }
func (f *inventoryTool) ListPackagesScope(_ context.Context, _ string, _ domain.ProductSnapshot, tests bool) ([]byte, error) { f.tests = tests; return f.raw, f.err }

func TestPackageInventoryComplete(t *testing.T) {
	s := newTestSession(t)
	f := &inventoryTool{raw: []byte(`{"ImportPath":"example.com/p","Name":"main","Imports":["example.com/d"],"Deps":["example.com/d"]}
{"ImportPath":"example.com/d","Name":"d","DepOnly":true}`)}
	s.GoTool = f
	o, err := s.packageInventory(context.Background(), PackageInventoryArgs{WithTests:true})
	if err != nil || o.Completeness != CompletenessComplete { t.Fatalf("inventory: %+v %v", o, err) }
	d := o.Data.(PackageInventoryData)
	if !f.tests || !d.Run.WithTests || !d.Run.Complete || d.RawStream != string(f.raw) || d.RawSHA256 != sha256Of(f.raw) || d.RawReference != "sha256:"+d.RawSHA256 || len(d.Packages) != 2 { t.Fatalf("binding lost: %+v", d) }
	if _, err := d.Admit(s.Build); err != nil { t.Fatal(err) }
}

func TestPackageInventoryRejectsPartialGraph(t *testing.T) {
	for name, raw := range map[string]string{
		"truncated": `{"ImportPath":"example.com/p"} {`,
		"error": `{"ImportPath":"example.com/p","Error":{"Err":"failed"}}`,
		"duplicate": `{"ImportPath":"example.com/p"} {"ImportPath":"example.com/p"}`,
		"dangling": `{"ImportPath":"example.com/p","Imports":["missing"]}`,
		"orphan": `{"ImportPath":"example.com/p"} {"ImportPath":"example.com/d","DepOnly":true}`,
	} { t.Run(name, func(t *testing.T) {
		s := newTestSession(t); s.GoTool = &inventoryTool{raw: []byte(raw)}
		o, err := s.packageInventory(context.Background(), PackageInventoryArgs{})
		if err != nil { t.Fatal(err) }; d := o.Data.(PackageInventoryData)
		if o.Completeness == CompletenessComplete || d.Run.Complete { t.Fatalf("partial admitted: %+v", o) }
		if _, err := d.Admit(s.Build); err == nil { t.Fatal("partial DTO admitted") }
	}) }
	s := newTestSession(t); s.GoTool = &inventoryTool{raw: []byte(`{"ImportPath":"example.com/p"}`), err: errors.New("exit status 1")}
	o, err := s.packageInventory(context.Background(), PackageInventoryArgs{})
	if err != nil || o.Completeness == CompletenessComplete { t.Fatalf("failed command: %+v %v", o, err) }
}

func TestPackageInventoryBuildIdentity(t *testing.T) {
	s := newTestSession(t); s.GoTool = &inventoryTool{raw: []byte(`{"ImportPath":"example.com/p"}`)}
	o, err := s.packageInventory(context.Background(), PackageInventoryArgs{})
	if err != nil { t.Fatal(err) }; d := o.Data.(PackageInventoryData)
	foreign := s.Build; foreign.GOOS = "foreign"
	if _, err := d.Admit(foreign); err == nil { t.Fatal("foreign build admitted") }
	d.RawStream += " "
	if _, err := d.Admit(s.Build); err == nil { t.Fatal("mutated raw admitted") }
	d.RawStream = `{"ImportPath":"example.com/p"} {`
	d.RawSHA256 = sha256Of([]byte(d.RawStream)); d.RawReference = "sha256:"+d.RawSHA256; d.RawSize = len(d.RawStream)
	d.Run.RawSHA256 = d.RawSHA256
	if _, err := d.Admit(s.Build); err == nil { t.Fatal("forged complete flag admitted truncated stream") }
}

func TestPackageInventoryRealGoSmoke(t *testing.T) {
	s := absenceSession(t, "scopetestprod")
	s.GoTool = affected.ExecGoTool{Env:s.ToolEnv, Bin:s.ToolBin, Version:s.ToolVer}
	o, err := s.packageInventory(context.Background(), PackageInventoryArgs{})
	if err != nil || o.Completeness != CompletenessComplete { t.Fatalf("real inventory: %+v %v", o, err) }
	d := o.Data.(PackageInventoryData)
	if _, err := d.Admit(s.Build); err != nil { t.Fatal(err) }
	a := absenceCall(t, s, VerifyCodeAbsenceArgs{Subjects: []CodeSubject{{Package:"example.com/notlinked", Symbol:"Missing"}}})
	if a.Completeness != CompletenessComplete { t.Fatalf("real absence: %+v", a) }
	report := absenceData(t, a).ImportClosure
	if report.InventoryReference == "" || !strings.HasPrefix(report.InventoryReference, "sha256:") { t.Fatalf("absence lacks inventory: %+v", report) }
	t.Logf("real Go: packages=%d raw_bytes=%d digest=%s absence=%s inventory=%s", len(d.Packages), d.RawSize, d.RawSHA256, a.Completeness, report.InventoryReference)
}

func TestPackageInventoryLocalReplaceTests(t *testing.T) {
	s := absenceSession(t, "inventoryreplace")
	for _, withTests := range []bool{false, true} {
		o, err := s.packageInventory(context.Background(), PackageInventoryArgs{WithTests:withTests})
		if err != nil || o.Completeness != CompletenessComplete { t.Fatalf("tests=%t: %+v %v", withTests, o, err) }
		d := o.Data.(PackageInventoryData)
		inv, err := d.Admit(s.Build)
		if err != nil { t.Fatal(err) }
		if inv.Paths["inventory.test/dependency/testonly"] != withTests { t.Fatalf("test-only membership tests=%t: %v", withTests, inv.Paths) }
		foundReplace := false
		for _, p := range inv.Packages { if p.Module != nil && p.Module.Path == "inventory.test/dependency" && p.Module.Replace != nil { foundReplace = true } }
		if !foundReplace { t.Fatal("replacement identity lost") }
		t.Logf("local-replace tests=%t packages=%d raw_bytes=%d digest=%s", withTests, len(inv.Packages), d.RawSize, d.RawSHA256)
		if !withTests {
			a := absenceCall(t, s, VerifyCodeAbsenceArgs{Subjects: []CodeSubject{{Package:"inventory.test/dependency/testonly", Symbol:"TestOnly"}}})
			if a.Completeness != CompletenessComplete || len(absenceData(t, a).AbsentSubjects) != 1 { t.Fatalf("local-replace product absence: %+v", a) }
		}
	}
}

func TestPackageInventoryMCPBehavior(t *testing.T) {
	s := newTestSession(t)
	f := &inventoryTool{raw: []byte(`{"ImportPath":"example.com/p"}`)}
	s.GoTool = f
	client, err := s.Connect(context.Background())
	if err != nil { t.Fatal(err) }
	defer client.Close()
	o, err := client.Call(context.Background(), "package-inventory", json.RawMessage(`{"with_tests":true}`))
	if err != nil || o.Completeness != CompletenessComplete || !f.tests { t.Fatalf("wire behavior: %+v %v", o, err) }
	raw, _ := json.Marshal(o.Data)
	var d PackageInventoryData
	if err := json.Unmarshal(raw, &d); err != nil { t.Fatal(err) }
	if _, err := d.Admit(s.Build); err != nil { t.Fatal(err) }
	s.Strict, s.AllowToolchain = true, false
	o, err = s.packageInventory(context.Background(), PackageInventoryArgs{})
	if err != nil || o.ToolStatus != StatusUnsupported || o.Completeness == CompletenessComplete { t.Fatalf("permission behavior: %+v %v", o, err) }
}

func TestPackageInventoryRealGoCallOrder(t *testing.T) {
	for _, first := range []string{"get_dependency_graph", "get_module_version", "usage-scope"} {
		t.Run(first, func(t *testing.T) {
			s := absenceSession(t, "inventoryreplace")
			client, err := s.Connect(context.Background())
			if err != nil { t.Fatal(err) }
			defer client.Close()
			args := json.RawMessage(`{"module":"inventory.test/dependency"}`)
			if first == "get_dependency_graph" { args = json.RawMessage(`{}`) }
			for _, call := range []struct{name string; args json.RawMessage}{
				{first,args},
				{"package-inventory",json.RawMessage(`{"with_tests":false}`)},
				{"verify_code_absence",json.RawMessage(`{"subjects":[{"package":"inventory.test/dependency/testonly","symbol":"TestOnly"}]}`)},
				{"get_product_snapshot",json.RawMessage(`{}`)},
				{first,args},
			} {
				o, err := client.Call(context.Background(),call.name,call.args)
				if err != nil || o.ToolStatus != StatusOK || o.Completeness != CompletenessComplete { t.Fatalf("%s after %s: %+v %v",call.name,first,o,err) }
				t.Logf("actual Go call order first=%s call=%s status=%s completeness=%s",first,call.name,o.ToolStatus,o.Completeness)
			}
		})
	}
}

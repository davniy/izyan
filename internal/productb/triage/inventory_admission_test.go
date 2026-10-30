package triage

import (
	"context"
	"path/filepath"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/fedorovmv/izyan/internal/affected"
	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/evidencetools"
	productaffected "github.com/fedorovmv/izyan/internal/productb/affected"
)

// currentInventoryFixture contains independent build selection and full raw
// stream evidence, not merely an asserted Complete flag.
func currentInventoryFixture(snapshot string) (*evidencetools.ImportClosureReport, string) {
	raw := `{"ImportPath":"cmd/app","Name":"main"}`
	h := sha256.Sum256([]byte(raw))
	digest := hex.EncodeToString(h[:])
	build := domain.BuildContext{Repository:"fixture", ContentHash:snapshot, GOOS:"linux", GOARCH:"amd64", GoVersion:"go1.26.1", GoWorkFile:"off"}
	scope := &evidencetools.BuildContext{EffectiveBuild:&build, GOOS:build.GOOS, GOARCH:build.GOARCH, Toolchain:build.GoVersion}
	b, _ := json.Marshal(scope)
	h = sha256.Sum256(b)
	return &evidencetools.ImportClosureReport{InventoryRaw:raw, InventoryReference:"sha256:"+digest, InventoryBuild:build, InventoryRun:domain.PackageListRun{Completed:true, Complete:true, Pattern:"./...", RawSHA256:digest}, InventoryScope:scope}, hex.EncodeToString(h[:])
}

func bindCurrentCoverageInventory(c *FalsifierCoverage) {
	c.Inventory, c.BuildContextHash = currentInventoryFixture(c.SnapshotHash)
	c.CoverageRuleVersion = evidencetools.CodeAbsenceCoverageRuleVersion
}

func TestPackageInventoryPersistedAbsenceAdmission(t *testing.T) {
	for _, wrapped := range []bool{false, true} {
		for _, mutation := range []string{"valid", "missing", "truncated", "failed", "foreign", "legacy", "truncated-repinned", "error-repinned", "dangling-repinned", "duplicate-repinned", "orphan-repinned"} {
			t.Run(mutation+map[bool]string{true:"/wrapped", false:"/bare"}[wrapped], func(t *testing.T) {
				s := sourceFixture()
				in, o := verifierFixture(FalsifierCodeAbsent, s)
				var d map[string]any
				if err := json.Unmarshal(o.Payload, &d); err != nil { t.Fatal(err) }
				closure := d["import_closure"].(map[string]any)
				switch mutation {
				case "missing": delete(closure,"inventory_raw")
				case "truncated": closure["inventory_raw"] = `{"ImportPath":"cmd/app"} {`
				case "failed": closure["inventory_run"].(map[string]any)["completed"] = false
				case "foreign": closure["inventory_build"].(map[string]any)["goos"] = "foreign"
				case "legacy": d["coverage_rule_version"] = "4"; delete(closure,"inventory_scope")
				case "truncated-repinned", "error-repinned", "dangling-repinned", "duplicate-repinned", "orphan-repinned":
					raw := map[string]string{
						"truncated-repinned": `{"ImportPath":"cmd/app"} {`,
						"error-repinned": `{"ImportPath":"cmd/app","Error":{"Err":"failed"}}`,
						"dangling-repinned": `{"ImportPath":"cmd/app","Imports":["missing"]}`,
						"duplicate-repinned": `{"ImportPath":"cmd/app"} {"ImportPath":"cmd/app"}`,
						"orphan-repinned": `{"ImportPath":"cmd/app"} {"ImportPath":"orphan","DepOnly":true}`,
					}[mutation]
					h := sha256.Sum256([]byte(raw)); digest := hex.EncodeToString(h[:])
					closure["inventory_raw"], closure["inventory_reference"] = raw, "sha256:"+digest
					closure["inventory_run"].(map[string]any)["raw_sha256"] = digest
				}
				var value any = d
				if wrapped { value = map[string]any{"data":d} }
				o.Payload, _ = json.Marshal(value)
				in.Observations = []RecordedObservation{*o}
				proof := runProof(t,in,s)
				if (proof.Status == FalsifierVerified) != (mutation == "valid") { t.Fatalf("status=%s reason=%s", proof.Status, proof.Reason) }
			})
		}
	}
}

func bindTestOnlyInventories(s0 *Stage0Result) {
	build := domain.ProductSnapshot{Repository:"fixture", ContentHash:s0.Snapshot.ContentHash, GOOS:"linux", GOARCH:"amd64", GoVersion:"go1.26.1", GoWorkFile:"off"}
	identity := domain.EffectiveBuildContext(build)
	s0.Materials.PackageBuild = &identity
	product := affected.RecordPackageInventory([]byte(`{"ImportPath":"cmd/app","Name":"main"}`), nil, build, false)
	tests := affected.RecordPackageInventory([]byte(`{"ImportPath":"cmd/app","Name":"main","Imports":["example.org/library"],"Deps":["example.org/library"]}
{"ImportPath":"example.org/library","Name":"library","DepOnly":true,"Module":{"Path":"example.org/library"}}`), nil, build, true)
	s0.Materials.ModuleGraph.PackageInventory, s0.Materials.ModuleGraph.BuildPackageInventory = &tests, &product
}

func TestPackageInventoryTestOnlyConsumption(t *testing.T) {
	for _, mutation := range []string{"valid", "no-raw", "truncated", "foreign", "failed", "digest", "missing", "truncated-repinned", "missing-build"} {
		t.Run(mutation,func(t *testing.T) {
			s0 := testOnlyStage0()
			g := s0.Materials.ModuleGraph
			switch mutation {
			case "no-raw": g.PackageInventory.RawStream = ""
			case "truncated": g.BuildPackageInventory.RawStream += " {"
			case "foreign": g.BuildPackageInventory.Build.GOOS = "foreign"
			case "failed": g.PackageInventory.Run.Completed = false
			case "digest": g.PackageInventory.RawReference = "sha256:wrong"
			case "missing": g.PackageInventory = nil
			case "missing-build": s0.Materials.PackageBuild = nil
			case "truncated-repinned":
				m := g.BuildPackageInventory
				m.RawStream += " {"
				h := sha256.Sum256([]byte(m.RawStream)); m.RawSHA256 = hex.EncodeToString(h[:])
				m.RawReference, m.Run.RawSHA256, m.RawSize = "sha256:"+m.RawSHA256, m.RawSHA256, len(m.RawStream)
			}
			f := testOnlyFact(s0)
			if (f.Status == ObsSupports) != (mutation == "valid") { t.Fatalf("fact=%+v", f) }
		})
	}
	s0 := testOnlyStage0()
	s0.Materials.ModuleGraph.TestOnly = nil
	if f:=testOnlyFact(s0); f.Status != ObsSupports { t.Fatalf("trusted derived map instead of retained streams: %+v", f) }
}

func TestPackageInventoryRealMaterialAdmission(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "..", "testdata", "inventoryreplace"))
	if err != nil { t.Fatal(err) }
	manifest := materialManifest(t,root)
	set, err := CollectMaterials(context.Background(),manifest,SiteConfig{},productaffected.CachingTool(productaffected.ExecGoTool{}))
	if err != nil { t.Fatal(err) }
	s0 := Stage0Result{Snapshot:manifest, Materials:set, PackageCheck:PackageCheckResult{ResolvedPath:"inventory.test/testdependency"}}
	f := testOnlyFact(s0)
	if f == nil || f.Status != ObsSupports { t.Fatalf("real paired inventory not admitted: %+v limitations=%v",f,set.Limitations) }
	g := set.ModuleGraph
	t.Logf("actual Go materials: test_packages=%d product_packages=%d test_ref=%s product_ref=%s fact=%s",len(g.PackageInventory.Packages),len(g.BuildPackageInventory.Packages),g.PackageInventory.RawReference,g.BuildPackageInventory.RawReference,f.Status)
	g.BuildPackageInventory.Build.GOOS = "foreign"
	if f:=testOnlyFact(s0); f.Status == ObsSupports { t.Fatalf("foreign real inventory admitted: %+v",f) }
}

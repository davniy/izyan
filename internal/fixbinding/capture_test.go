package fixbinding

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/affected"
 "github.com/fedorovmv/izyan/internal/domain"
 "github.com/fedorovmv/izyan/internal/repository"
 "github.com/fedorovmv/izyan/internal/vulnerability"
)

func capturedFilesForTest(files map[string][]byte) []CapturedFile {
 names := make([]string, 0, len(files))
 for name := range files { names = append(names, name) }
 sort.Strings(names)
 out := make([]CapturedFile, 0, len(names))
 for _, name := range names { out = append(out, CapturedFile{Path:name, Bytes:files[name]}) }
 return out
}

// captureFixture acquires a real product manifest before any proof is created.
// Its returned current context is independent of mutable proof Inputs.
func captureFixture(t *testing.T, record []byte, files map[string][]byte, external ...ExternalComponent) (*SourceCaptures, AdmissionInput) {
 t.Helper()
 _, sums := buildArchiveEvidence(t, fixtureModule, fixtureSelectedVer, files)
 productFiles := map[string][]byte{
  "go.mod": []byte("module example.com/product\n\ngo 1.25\n\nrequire example.com/dep v0.9.0\nreplace example.com/dep v0.9.0 => example.com/dep v0.8.0\n"),
  "go.sum": sums,
 }
 var externalCaptures []ExternalSourceCapture
 var stream []byte
 for _, component := range external {
  inventory := component.Inventory
  archive := *inventory.Anchor.Archive
  productFiles["go.sum"] = append(productFiles["go.sum"], archive.GoSum...)
  productFiles["go.mod"] = append(productFiles["go.mod"], []byte(fmt.Sprintf("require %s %s\n", component.ImportPath, inventory.Version))...)
  externalCaptures = append(externalCaptures, ExternalSourceCapture{ImportPath:component.ImportPath, Selection:domain.EffectiveSourceSelection{EntryRef:0, DeclaredModule:component.ImportPath, DeclaredVersion:inventory.Version, EffectiveModule:inventory.Module, EffectiveVersion:inventory.Version, SourceKind:domain.ModuleSourceModuleCache, SourceRoot:inventory.Observed.Root}, Archive:archive, Observed:inventory.Observed, Files:capturedFilesForTest(inventory.CensusFiles())})
  raw, err := json.Marshal(map[string]any{"ImportPath":component.ImportPath,"Name":"cri","Dir":"/captured/cri","GoFiles":[]string{"service.go"},"Module":map[string]any{"Path":inventory.Module,"Version":inventory.Version,"Dir":"/captured/cri"}})
  if err != nil { t.Fatal(err) }; stream=append(stream,raw...);stream=append(stream,'\n')
 }
 for i := range externalCaptures { externalCaptures[i].Archive.GoSum=productFiles["go.sum"] }
 root := t.TempDir()
 for name, raw := range productFiles {
  if err := os.WriteFile(filepath.Join(root,name),raw,0600); err != nil { t.Fatal(err) }
 }
 manifest, err := repository.CaptureContentManifest(root)
 if err != nil { t.Fatal(err) }
 hash, err := repository.ContentHash(root)
 if err != nil { t.Fatal(err) }
 // Repository identity is a stable captured locator; no replay reads this path.
 product := domain.ProductSnapshot{Repository:"/captured/product", Commit:"fixture-product", ContentHash:hash, GOOS:"linux", GOARCH:"amd64"}
 loaded, err := vulnerability.LoadExactBytes(record, fixtureRecordID, "osv:test-fixture")
 if err != nil { t.Fatal(err) }
 captures := &SourceCaptures{Context:SourceCaptureContext{Build:domain.EffectiveBuildContext(product), SnapshotManifest:manifest, ProductFiles:capturedFilesForTest(productFiles)}, SelectedFiles:capturedFilesForTest(files)}
 ctx := AdmissionInput{Product:product, Vulnerability:*loaded.Vuln, RecordPin:&loaded.Pin, AdvisoryRecord:&domain.AdvisoryRecordCapture{Pin:loaded.Pin, Bytes:append([]byte(nil),record...)}, Affected:&domain.AffectedResult{EffectiveSources:fixtureSelection()}}
 captures.External=externalCaptures
 if len(externalCaptures)>0 {
  measurement:=affected.RecordPackageInventory(stream,nil,product,false)
  if _,err:=measurement.Admit(product);err!=nil{t.Fatal(err)}
  evidence:=domain.Evidence{ID:"EV-CAPTURE-INVENTORY", Kind:domain.EvidencePackageList, Content:measurement.RawStream, ArtifactHash:measurement.RawReference, PackageList:&measurement.Run, BuildContext:&measurement.Build}
  captures.Context.InventoryEvidence=&evidence
  ctx.Evidence=[]domain.Evidence{evidence}
 }
 if err := os.RemoveAll(root); err != nil { t.Fatal(err) }
 return captures, ctx
}

func inventoryForCaptures(t *testing.T, files map[string][]byte, captures *SourceCaptures) SourceInventory {
 t.Helper()
 inventory := anchoredInventory(t, fixtureModule, fixtureSelectedVer, files)
 archive := *inventory.Anchor.Archive
 for _,file:=range captures.Context.ProductFiles { if file.Path=="go.sum" { archive.GoSum=file.Bytes } }
 anchor,err:=CheckArchiveAnchor(archive);if err!=nil{t.Fatal(err)}
 return AssembleInventory(InventoryInput{Module:inventory.Module,Version:inventory.Version,Observed:inventory.Observed,Anchor:anchor})
}

func fixtureContext(t *testing.T) AdmissionInput {
 t.Helper()
 _, ctx := captureFixture(t, fixtureRecordBytes(), fixtureSelectedFiles())
 return ctx
}

func fixtureTwoRefsContext(t *testing.T) AdmissionInput {
 t.Helper()
 _, ctx := captureFixture(t, fixtureTwoRefRecordBytes(), fixtureSelectedFiles())
 return ctx
}

func TestCaptureContextRequiresIndependentCurrentCase(t *testing.T) {
 in := fixtureInputs(t)
 binding := deriveFixture(t,in)
 ctx := fixtureContext(t)
 proof, err := Persist(ctx,binding,in)
 if err != nil { t.Fatal(err) }
 if _, err := Readmit(ctx,proof); err != nil { t.Fatal(err) }
 cases := []struct{name string; mutate func(*AdmissionInput)}{
  {"missing",func(c *AdmissionInput){*c=AdmissionInput{}}},
  {"foreign product",func(c *AdmissionInput){c.Product.ContentHash="t1:foreign"}},
  {"foreign build",func(c *AdmissionInput){c.Product.GOARCH="arm64"}},
  {"foreign record",func(c *AdmissionInput){c.Vulnerability.ID="GO-foreign"}},
  {"different selection",func(c *AdmissionInput){c.Affected.EffectiveSources[0].EffectiveVersion="v7.0.0"}},
 }
 for _,tc := range cases { t.Run(tc.name,func(t *testing.T){current:=fixtureContext(t);tc.mutate(&current);if _,err:=Readmit(current,proof);err==nil{t.Fatal("foreign or absent current context admitted")}}) }
 t.Run("historical contract",func(t *testing.T){old:=*proof;old.Contract="fixbinding/re-derivation/2";if _,err:=Readmit(ctx,&old);err==nil{t.Fatal("historical /2 proof acquired /3 authority")}})
}

// patchBaseFixture captures a different upstream release than the selected
// implementation. The acquired product go.sum independently pins both ZIPs.
func patchBaseFixture(t *testing.T) (Inputs, AdmissionInput) {
 t.Helper()
 in := fixtureInputs(t)
 baseFiles := fixtureSelectedFiles()
 selectedFiles := fixtureSelectedFiles()
 selectedFiles[fixturePatchPath] = []byte(strings.Replace(string(fixtureBefore()), "0711); err != nil {", "0711); err != nil { // selected fork", 1))
 in.Captures, _ = captureFixture(t, fixtureRecordBytes(), selectedFiles)
 archive, sums := buildArchiveEvidence(t, fixtureModule, "v0.7.0", baseFiles)
 productFiles := map[string][]byte{}
 for _,file:=range in.Captures.Context.ProductFiles { productFiles[file.Path]=append([]byte(nil),file.Bytes...) }
 productFiles["go.sum"]=append(productFiles["go.sum"],sums...)
 root:=t.TempDir()
 for name,raw:=range productFiles {if err:=os.WriteFile(filepath.Join(root,name),raw,0600);err!=nil{t.Fatal(err)}}
 manifest,err:=repository.CaptureContentManifest(root);if err!=nil{t.Fatal(err)}
 hash,err:=repository.ContentHash(root);if err!=nil{t.Fatal(err)}
 _, ctx := captureFixture(t, fixtureRecordBytes(), selectedFiles)
 ctx.Product.ContentHash=hash
 in.Captures.Context=SourceCaptureContext{Build:domain.EffectiveBuildContext(ctx.Product),SnapshotManifest:manifest,ProductFiles:capturedFilesForTest(productFiles)}
 in.Inventory=inventoryForCaptures(t,selectedFiles,in.Captures)
 in.Captures.PatchBases=[]PatchBaseCapture{{Locator:fixtureLocator,ArtifactDigest:DigestBytes(fixturePatchBytes()),Archive:ArchiveEvidence{Bytes:archive,Module:fixtureModule,Version:"v0.7.0",GoSum:productFiles["go.sum"]}}}
 if err:=os.RemoveAll(root);err!=nil{t.Fatal(err)}
 return in,ctx
}

func TestPatchBaseCaptureBindsExactLocatorAndArtifact(t *testing.T) {
 in,ctx:=patchBaseFixture(t)
 binding:=deriveFixture(t,in)
 proof,err:=Persist(ctx,binding,in);if err!=nil{t.Fatal(err)}
 if _,err:=Readmit(ctx,proof);err!=nil{t.Fatal(err)}
 for _,kind:=range []string{"locator","artifact","checksum"} {t.Run(kind,func(t *testing.T){bad,_:=patchBaseFixture(t);switch kind{case "locator":bad.Captures.PatchBases[0].Locator="https://foreign.invalid/fix";case "artifact":bad.Captures.PatchBases[0].ArtifactDigest=DigestBytes([]byte("foreign"));case "checksum":bad.Captures.PatchBases[0].Archive.GoSum=[]byte("forged")};if _,err:=Derive(bad);err==nil{t.Fatal("unassociated patch base admitted")}})}
}

func TestCompleteTreeCarrierMatchesIndependentArchive(t *testing.T) {
 in,ctx:=patchBaseFixture(t)
 in.Captures.PatchBases[0].Tree=capturedFilesForTest(fixtureSelectedFiles())
 binding:=deriveFixture(t,in)
 proof,err:=Persist(ctx,binding,in);if err!=nil{t.Fatal(err)}
 if _,err:=Readmit(ctx,proof);err!=nil{t.Fatal(err)}
}

func TestPatchBaseWrongTreeRefuses(t *testing.T) {
 for _,kind:=range []string{"bytes","missing member","extra member","tree only"} {t.Run(kind,func(t *testing.T){in,_:=patchBaseFixture(t);base:=&in.Captures.PatchBases[0];base.Tree=capturedFilesForTest(fixtureSelectedFiles());switch kind{case "bytes":base.Tree[0].Bytes=[]byte("foreign");case "missing member":base.Tree=base.Tree[1:];case "extra member":base.Tree=append(base.Tree,CapturedFile{Path:"extra.go",Bytes:[]byte("package extra")});case "tree only":base.Archive=ArchiveEvidence{}};if _,err:=Derive(in);err==nil{t.Fatal("unauthenticated tree earned archive authority")}})}
}

func TestCaptureReplayNeedsNoSourceTree(t *testing.T) {
 // Both helpers delete acquired source directories before returning.
 in,ctx:=patchBaseFixture(t)
 binding:=deriveFixture(t,in)
 proof,err:=Persist(ctx,binding,in);if err!=nil{t.Fatal(err)}
 raw,err:=json.Marshal(proof);if err!=nil{t.Fatal(err)}
 var saved domain.FixProof
 if err:=json.Unmarshal(raw,&saved);err!=nil{t.Fatal(err)}
 if _,err:=Readmit(ctx,&saved);err!=nil{t.Fatal(err)}
}

func TestExternalCaptureRequiresIndependentAnchor(t *testing.T) {
 files:=fixtureSelectedFiles();files["builtins/builtins.go"]=[]byte("package builtins\nimport _ \"github.com/containerd/cri\"\n")
 external:=ExternalComponent{ImportPath:"github.com/containerd/cri",Inventory:anchoredInventory(t,"github.com/containerd/cri","v1.4.13",map[string][]byte{"service.go":[]byte("package cri\ntype Service struct{}\n")})}
	for _, kind := range []string{"valid", "missing anchor", "effective owner", "missing evidence", "raw evidence", "foreign evidence", "asserted projection"} {
		t.Run(kind, func(t *testing.T) {
			in := fixtureInputs(t)
			captures, ctx := captureFixture(t, fixtureRecordBytes(), files, external)
			in.Captures = captures
			in.Inventory = inventoryForCaptures(t, files, captures)
			switch kind {
			case "missing anchor":
				captures.External[0].Archive = ArchiveEvidence{}
			case "effective owner":
				captures.External[0].Selection.EffectiveVersion = "v1.4.12"
			case "missing evidence":
				captures.Context.InventoryEvidence = nil
			case "raw evidence":
				captures.Context.InventoryEvidence.Content += "{}"
			case "foreign evidence":
				ctx.Evidence = nil
			case "asserted projection":
				captures.External = nil
				in.External = []ExternalComponent{external}
			}
			binding, err := Derive(in)
			if kind == "valid" {
				if err != nil { t.Fatal(err) }
				if _, err := Persist(ctx, binding, in); err != nil { t.Fatal(err) }
			} else if kind == "foreign evidence" {
				if err != nil { t.Fatal(err) }
				if _, err := Persist(ctx, binding, in); err == nil {
					t.Fatal("foreign inventory context admitted")
				}
			} else if err == nil {
				t.Fatal("unanchored or incorrectly selected external capture admitted")
			}
		})
	}
}

func TestTwoFixLocatorsNeverBecomeSeries(t *testing.T) {
 in, ctx := patchBaseFixture(t)
 record := fixtureTwoRefRecordBytes()
 loaded, err := vulnerability.LoadExactBytes(record, fixtureRecordID, "osv:test-fixture")
 if err != nil { t.Fatal(err) }
 in.Raw, in.Pin = record, loaded.Pin
 ctx.RecordPin = &loaded.Pin
 ctx.AdvisoryRecord = &domain.AdvisoryRecordCapture{Pin:loaded.Pin, Bytes:record}
 ctx.Vulnerability = *loaded.Vuln
 patchB := []byte(strings.Replace(string(fixturePatchBytes()), "0711", "0750", 1))
 in.Artifacts = append(in.Artifacts, capturedArtifact(fixtureLocatorB,"commit",patchB))
 // B would need a different preimage. A's independently captured base cannot
 // silently supply a series intermediate or another locator's source.
 if _, err := Derive(in); err == nil { t.Fatal("a missing second base was inferred from the first fix locator") }
 in.Captures.PatchBases = append(in.Captures.PatchBases, PatchBaseCapture{Locator:fixtureLocatorB,ArtifactDigest:DigestBytes(patchB),Archive:in.Captures.PatchBases[0].Archive})
 if _, err := Derive(in); err == nil { t.Fatal("a second patch applied despite a mismatching independent preimage") }
}

func TestCaptureContextRefusesProofInternalProductRepin(t *testing.T) {
 original := fixtureContext(t)
 in, foreign := patchBaseFixture(t)
 binding := deriveFixture(t,in)
 proof,err:=Persist(foreign,binding,in)
 if err!=nil{t.Fatal(err)}
 if _,err:=Readmit(original,proof);err==nil{t.Fatal("proof-internal product manifest replaced the current product pin")}
}

func TestSelectedSourceProductTreeSplicePersistsWithoutArchive(t *testing.T) {
 files:=fixtureSelectedFiles()
 files["go.mod"]=[]byte("module example.com/dep\n\ngo 1.25\n")
 root:=t.TempDir()
 for name,raw:=range files {
  target:=filepath.Join(root,name)
  if err:=os.MkdirAll(filepath.Dir(target),0700);err!=nil{t.Fatal(err)}
  if err:=os.WriteFile(target,raw,0600);err!=nil{t.Fatal(err)}
 }
 manifest,err:=repository.CaptureContentManifest(root);if err!=nil{t.Fatal(err)}
 hash,err:=repository.ContentHash(root);if err!=nil{t.Fatal(err)}
 entries,err:=repository.ValidateContentManifest(manifest,hash);if err!=nil{t.Fatal(err)}
 var tree []TreeEntry
 for _,entry:=range entries {tree=append(tree,TreeEntry{Path:entry.Path,Directory:entry.Kind=="dir",Executable:uint32(entry.Mode&0111),Bytes:files[entry.Path]})}
 local:=sha256.New()
 captured:=capturedFilesForTest(files)
 for _,file:=range captured {local.Write([]byte(file.Path));local.Write([]byte{0});local.Write(file.Bytes);local.Write([]byte{0})}
 digest:=fmt.Sprintf("sha256:%x",local.Sum(nil))
 anchor,err:=CheckTreeAnchor(TreeEvidence{Entries:tree,SnapshotDigest:hash,Module:fixtureModule,Root:".",ContentDigest:digest});if err!=nil{t.Fatal(err)}
 in:=fixtureInputs(t)
 ctx:=fixtureContext(t)
 ctx.Product.ContentHash=hash
 selection:=fixtureSelection()
 selection[0].EffectiveVersion=""
 selection[0].SourceKind=domain.ModuleSourceLocalReplacement
 selection[0].SourceRoot="."
 selection[0].ContentDigest=digest
 selection[0].LocalReplacement=&domain.LocalReplacementSelection{Module:fixtureModule,Directory:"."}
 ctx.Affected=&domain.AffectedResult{EffectiveSources:selection}
 in.Selection=selection
 observed:=ObservedSource{Kind:SourceLocalReplacement,Module:fixtureModule,Root:".",WalkComplete:true}
 for _,file:=range captured {observed.Files=append(observed.Files,ObservedFile{Path:file.Path,Bytes:file.Bytes,Digest:DigestBytes(file.Bytes)})}
 in.Inventory=AssembleInventory(InventoryInput{Module:fixtureModule,Observed:observed,Anchor:anchor})
 in.Captures=&SourceCaptures{Context:SourceCaptureContext{Build:domain.EffectiveBuildContext(ctx.Product),SnapshotManifest:manifest,ProductFiles:[]CapturedFile{{Path:"go.mod",Bytes:files["go.mod"]}}},SelectedFiles:captured}
 if err:=os.RemoveAll(root);err!=nil{t.Fatal(err)}
 binding:=deriveFixture(t,in)
 proof,err:=Persist(ctx,binding,in);if err!=nil{t.Fatal(err)}
 if _,err:=Readmit(ctx,proof);err!=nil{t.Fatal(err)}
}

func TestCaptureContextBindsCaptureDigestAndCover(t *testing.T) {
	in, ctx := patchBaseFixture(t)
	withoutTree := deriveFixture(t, in)
	in.Captures.PatchBases[0].Tree = capturedFilesForTest(fixtureSelectedFiles())
	withTree := deriveFixture(t, in)
	if withoutTree.CaptureDigest == withTree.CaptureDigest || withoutTree.Cover.ID == withTree.Cover.ID {
		t.Fatal("changed capture scope did not change capture and cover identity")
	}
	if _, err := Persist(ctx, withoutTree, in); err == nil {
		t.Fatal("old capture identity admitted under changed capture premises")
	}
}

func TestPatchBaseWrongPreimageRefuses(t *testing.T) {
	in, _ := patchBaseFixture(t)
	patch := []byte(strings.Replace(string(fixturePatchBytes()), "0711", "0750", 1))
	in.Artifacts = []ArtifactInput{capturedArtifact(fixtureLocator, "commit", patch)}
	in.Captures.PatchBases[0].ArtifactDigest = DigestBytes(patch)
	if _, err := Derive(in); err == nil {
		t.Fatal("exactly associated artifact admitted against a different base preimage")
	}
}

func TestCaptureContextRefusesProductMetadataSubstitution(t *testing.T) {
	for _, name := range []string{"go.mod", "go.sum"} {
		t.Run(name, func(t *testing.T) {
			in := fixtureInputs(t)
			for i := range in.Captures.Context.ProductFiles {
				file := &in.Captures.Context.ProductFiles[i]
				if file.Path == name { file.Bytes = append(file.Bytes, []byte("\nforged metadata\n")...) }
			}
			if _, err := Derive(in); err == nil { t.Fatal("metadata not matching the product manifest admitted") }
		})
	}
}

func TestExternalCaptureCheckedWrapperReachesCounterpartAnalysis(t *testing.T) {
	const module = "github.com/containerd/cri"
	files := fixtureSelectedFiles()
	files["builtins/builtins.go"] = []byte("package builtins\nimport _ \"github.com/containerd/cri\"\n")
	external := ExternalComponent{
		ImportPath: module,
		Inventory: anchoredInventory(t, module, "v1.4.13", map[string][]byte{
			"service.go": []byte(`package cri

import (
	"os"
	"example.com/dep/config"
)

func EnsureStateDir(cfg *config.Config) { chmodRoot(cfg.Root) }

func chmodRoot(root string) { os.Chmod(root, 0o700) }
`),
		}),
	}
	in := fixtureInputs(t)
	captures, current := captureFixture(t, fixtureRecordBytes(), files, external)
	in.Captures = captures
	in.Inventory = inventoryForCaptures(t, files, captures)
	binding := deriveFixture(t, in)
	effect := effectOfClass(t, binding, string(ClassModeChange))
	if effect.Disposition != DispositionMapped || !hasLocationComponent(effect, module) {
		t.Fatalf("captured external wrapper did not reach counterpart analysis: %s", effectText(effect))
	}
	if !coverHasSubject(binding, module, "EnsureStateDir") {
		t.Fatalf("external wrapper entry missing from necessary cover: %+v", binding.Cover)
	}
	proof, err := Persist(current, binding, in)
	if err != nil { t.Fatal(err) }
	replayed, err := Readmit(current, proof)
	if err != nil { t.Fatal(err) }
	if !coverHasSubject(replayed, module, "EnsureStateDir") {
		t.Fatal("source-free replay lost the checked external wrapper entry")
	}
}

func TestCaptureContextVendorObservationMatchesProductSnapshot(t *testing.T) {
	const carrier = "vendor/example.com/dep"
	files := fixtureSelectedFiles()
	root := t.TempDir()
	for name, raw := range files {
		target := filepath.Join(root, carrier, name)
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil { t.Fatal(err) }
		if err := os.WriteFile(target, raw, 0600); err != nil { t.Fatal(err) }
	}
	manifest, err := repository.CaptureContentManifest(root)
	if err != nil { t.Fatal(err) }
	hash, err := repository.ContentHash(root)
	if err != nil { t.Fatal(err) }
	capture := SourceCaptureContext{Build:domain.BuildContext{ContentHash:hash}, SnapshotManifest:manifest}
	if err := os.RemoveAll(root); err != nil { t.Fatal(err) }
	if err := checkProductObservation(capture, carrier, capturedFilesForTest(files)); err != nil { t.Fatal(err) }
	for _, kind := range []string{"changed bytes", "missing member", "extra member", "other root"} {
		t.Run(kind, func(t *testing.T) {
			observed := capturedFilesForTest(files)
			selectedRoot := carrier
			switch kind {
			case "changed bytes": observed[0].Bytes = []byte("forged source")
			case "missing member": observed = observed[1:]
			case "extra member": observed = append(observed, CapturedFile{Path:"extra.go", Bytes:[]byte("package extra")})
			case "other root": selectedRoot = "vendor/foreign.invalid/module"
			}
			if err := checkProductObservation(capture, selectedRoot, observed); err == nil {
				t.Fatal("a substituted vendor carrier escaped the independently fixed product snapshot")
			}
		})
	}
}

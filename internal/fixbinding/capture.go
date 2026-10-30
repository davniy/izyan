package fixbinding

import (
 "bytes"
 "fmt"
 "go/parser"
 "go/token"
 "path"
 "reflect"
 "strconv"
 "strings"

 "github.com/fedorovmv/izyan/internal/affected"
 "github.com/fedorovmv/izyan/internal/domain"
 "github.com/fedorovmv/izyan/internal/repository"
 "golang.org/x/mod/modfile"
)

// AdmissionInput is independently held current case context, never decoded from
// a proof. Derive is diagnostic; these contextual APIs establish authority.
type AdmissionInput struct {
 Product domain.ProductSnapshot
 Vulnerability domain.Vulnerability
 RecordPin *domain.RecordPin
 AdvisoryRecord *domain.AdvisoryRecordCapture
 Affected *domain.AffectedResult
 Evidence []domain.Evidence
}
func AdmissionForCase(c *domain.AnalysisCase) AdmissionInput {
 if c==nil { return AdmissionInput{} }
 return AdmissionInput{Product:c.Product,Vulnerability:c.Vulnerability,RecordPin:c.RecordPin,AdvisoryRecord:c.AdvisoryRecord,Affected:c.Affected,Evidence:c.EvidenceGraph.EvidenceList()}
}

type CapturedFile struct { Path string `json:"path"`; Bytes []byte `json:"bytes"` }
type SourceCaptureContext struct {
 Build domain.BuildContext `json:"build"`
 SnapshotManifest []byte `json:"snapshot_manifest"`
 ProductFiles []CapturedFile `json:"product_files"`
 InventoryEvidence *domain.Evidence `json:"inventory_evidence,omitempty"`
}
type PatchBaseCapture struct {
 Locator string `json:"locator"`
 ArtifactDigest string `json:"artifact_digest"`
 Archive ArchiveEvidence `json:"archive"`
 Tree []CapturedFile `json:"tree,omitempty"`
}
type ExternalSourceCapture struct {
 ImportPath string `json:"import_path"`
 Selection domain.EffectiveSourceSelection `json:"selection"`
 Archive ArchiveEvidence `json:"archive"`
 Observed ObservedSource `json:"observed"`
 Files []CapturedFile `json:"files"`
 Tree []CapturedFile `json:"tree,omitempty"`
}
type SourceCaptures struct {
 Context SourceCaptureContext `json:"context"`
 SelectedFiles []CapturedFile `json:"selected_files"`
 PatchBases []PatchBaseCapture `json:"patch_bases,omitempty"`
 External []ExternalSourceCapture `json:"external,omitempty"`
}

func captureFiles(files []CapturedFile) (map[string][]byte,error) {
 if len(files)>100000 { return nil,fmt.Errorf("captured source member limit exceeded") }
 total:=0
 out:=map[string][]byte{}
 for _,file:=range files {
  total+=len(file.Bytes)
  if len(file.Bytes)>32<<20 || total>128<<20 {return nil,fmt.Errorf("captured source byte limit exceeded")}
  p:=file.Path
  if p=="" || p=="." || path.Clean(p)!=p || strings.HasPrefix(p,"/") || p==".." || strings.HasPrefix(p,"../") || strings.ContainsAny(p,"\\\n\r\t") {return nil,fmt.Errorf("unconfined captured file %q",p)}
  if _,ok:=out[p];ok{return nil,fmt.Errorf("duplicate captured file %q",p)}
  out[p]=file.Bytes
 }
 return out,nil
}
func authenticatedProductFiles(c SourceCaptureContext, hash string)(map[string][]byte,error){
 entries,err:=repository.ValidateContentManifest(c.SnapshotManifest,hash);if err!=nil{return nil,err}
 files,err:=captureFiles(c.ProductFiles);if err!=nil{return nil,err}
 for name,raw:=range files {
  found:=false
  for _,entry:=range entries {if entry.Path==name {found=entry.Kind=="file" && entry.Size==int64(len(raw)) && "sha256:"+entry.Payload==DigestBytes(raw);break}}
  if !found{return nil,fmt.Errorf("product metadata %q does not match acquired snapshot",name)}
 }
 return files,nil
}
func validateAdmission(ctx AdmissionInput,in Inputs) error {
 if ctx.RecordPin==nil || ctx.AdvisoryRecord==nil || ctx.Affected==nil || in.Captures==nil || ctx.Product.ContentHash=="" {return refuse(RefusalInput,"current record, product, selection and captured provenance are required")}
 if err:=ctx.AdvisoryRecord.Validate();err!=nil{return refuse(RefusalInput,"current advisory: %v",err)}
 if !reflect.DeepEqual(*ctx.RecordPin,ctx.AdvisoryRecord.Pin) || !reflect.DeepEqual(*ctx.RecordPin,in.Pin) || !bytes.Equal(ctx.AdvisoryRecord.Bytes,in.Raw) || ctx.Vulnerability.ID!=in.Pin.RecordID {return refuse(RefusalIdentity,"capture does not identify the current advisory")}
 if !reflect.DeepEqual(ctx.Affected.EffectiveSources,in.Selection){return refuse(RefusalCoordinate,"capture does not identify the current affected-entry selections")}
 if err:=in.Captures.Context.Build.Matches(domain.EffectiveBuildContext(ctx.Product));err!=nil{return refuse(RefusalCoordinate,"capture build: %v",err)}
 if _,err:=authenticatedProductFiles(in.Captures.Context,ctx.Product.ContentHash);err!=nil{return refuse(RefusalInput,"product capture: %v",err)}
 if e:=in.Captures.Context.InventoryEvidence;e!=nil {
  found:=false
  for _,current:=range ctx.Evidence {if current.ID==e.ID && reflect.DeepEqual(current,*e){found=true;break}}
  if !found{return refuse(RefusalInput,"capture inventory evidence is not present in current case")}
 }
 return nil
}

func checkedCaptureArchive(e ArchiveEvidence,sums []byte,tree []CapturedFile)(*SourceAnchor,error){
 if !bytes.Equal(e.GoSum,sums){return nil,fmt.Errorf("archive checksum is not captured product go.sum")}
 anchor,err:=CheckArchiveAnchor(e);if err!=nil{return nil,err}
 moduleDeclared:=false
 for _,file:=range anchor.Files {if file.Path=="go.mod" {m,err:=modfile.Parse("go.mod",file.Bytes,nil);moduleDeclared=err==nil && m.Module!=nil && m.Module.Mod.Path==e.Module;break}}
 if !moduleDeclared{return nil,fmt.Errorf("independent archive module declaration differs or is missing")}
 if len(tree)>0 {
  files,err:=captureFiles(tree);if err!=nil{return nil,err}
  if len(files)!=len(anchor.Files){return nil,fmt.Errorf("tree carrier file boundary differs from archive")}
  for _,file:=range anchor.Files {if raw,ok:=files[file.Path];!ok || !bytes.Equal(raw,file.Bytes){return nil,fmt.Errorf("tree carrier differs at %q",file.Path)}}
 }
 return anchor,nil
}
func observedWithFiles(obs ObservedSource,files []CapturedFile)(ObservedSource,error){
 raw,err:=captureFiles(files);if err!=nil{return obs,err}
 if len(raw)!=len(obs.Files){return obs,fmt.Errorf("source observation boundary differs from captured files")}
 for i:=range obs.Files {file:=&obs.Files[i];b,ok:=raw[file.Path];if !ok || file.Digest!=DigestBytes(b){return obs,fmt.Errorf("source observation differs at %q",file.Path)};file.Bytes=b}
 return obs,nil
}

// ReconstructSources rejects projection authority. Every patch-side image is
// regenerated from its own archive/base or the existing verified selected splice.
func ReconstructSources(in Inputs)(Inputs,error){
 if in.Captures==nil{return in,refuse(RefusalInput,"captured source provenance is missing")}
 cap:=in.Captures
 product,err:=authenticatedProductFiles(cap.Context,cap.Context.Build.ContentHash);if err!=nil{return in,err}
 sums:=product["go.sum"]
 obs,err:=observedWithFiles(in.Inventory.Observed,cap.SelectedFiles);if err!=nil{return in,err}
 in.Inventory=AssembleInventory(InventoryInput{Module:in.Inventory.Module,Version:in.Inventory.Version,Observed:obs,Anchor:in.Inventory.Anchor})
 if !in.Inventory.Anchored(){return in,fmt.Errorf("selected inventory not independently anchored: %s",in.Inventory.Input.Reason)}
 if a:=in.Inventory.Anchor;a.Archive!=nil && !bytes.Equal(a.Archive.GoSum,sums){return in,fmt.Errorf("selected archive checksum is not product-authenticated")}
 var sel *domain.EffectiveSourceSelection
 for i:=range in.Selection {if in.Selection[i].EntryRef==in.EntryRef {sel=&in.Selection[i];break}}
 if sel==nil{return in,fmt.Errorf("selected entry missing")}
 if sel.SourceKind==domain.ModuleSourceVendor {if err:=checkProductObservation(cap.Context,sel.SourceRoot,cap.SelectedFiles);err!=nil{return in,err}}
 if a:=in.Inventory.Anchor;a.Tree!=nil {
  root:=sel.SourceRoot
  if sel.SourceKind==domain.ModuleSourceVendor && sel.LocalReplacement!=nil {root=sel.LocalReplacement.Directory}
  if a.Tree.SnapshotDigest!=cap.Context.Build.ContentHash || a.Tree.Root!=root || (sel.ContentDigest!="" && a.Tree.ContentDigest!=sel.ContentDigest){return in,fmt.Errorf("selected tree is not the acquired product root/content")}
 }
 in.PatchSources=map[string]*SourceBundle{}
 artifacts:=map[string][]byte{}
 for _,a:=range in.Artifacts {raw:=a.Bytes;if len(raw)==0{raw=[]byte(a.Artifact.Bytes)};if len(raw)>0{artifacts[a.Artifact.Locator]=raw}}
 for _,a:=range in.Artifacts {if a.Artifact.DuplicateOf!=""{artifacts[a.Artifact.Locator]=artifacts[a.Artifact.DuplicateOf]}}
 selected:=in.Inventory.CensusFiles()
 identity:=ModuleIdentity{Kind:string(sel.SourceKind),Path:sel.EffectiveModule,Version:sel.EffectiveVersion,Digest:sel.ContentDigest}
 for locator,patch:=range artifacts {bundle,_:=PatchSourceFromSelected(patch,identity,selected);if bundle!=nil{in.PatchSources[locator]=bundle}}
 seen:=map[string]bool{}
 for _,base:=range cap.PatchBases {
  if base.Locator=="" || seen[base.Locator]{return in,fmt.Errorf("duplicate/empty patch-base locator")};seen[base.Locator]=true
  patch:=artifacts[base.Locator]
  if len(patch)==0 || DigestBytes(patch)!=base.ArtifactDigest{return in,fmt.Errorf("patch-base locator/artifact digest mismatch")}
  anchor,err:=checkedCaptureArchive(base.Archive,sums,base.Tree);if err!=nil{return in,err}
  files:=map[string][]byte{};for _,file:=range anchor.Files{files[file.Path]=file.Bytes}
  bundle,err:=patchSourceFromBase(patch,ModuleIdentity{Path:anchor.Module,Version:anchor.Version},files);if err!=nil{return in,err}
  in.PatchSources[base.Locator]=bundle
 }
 in.External=nil
 imports:=map[string]bool{}
 for _,external:=range cap.External {
  if imports[external.ImportPath]{return in,fmt.Errorf("duplicate external namespace")};imports[external.ImportPath]=true
  if err:=checkExternalSelection(external,selected,product,cap.Context);err!=nil{return in,err}
  anchor,err:=checkedCaptureArchive(external.Archive,sums,external.Tree);if err!=nil{return in,err}
  observed,err:=observedWithFiles(external.Observed,external.Files);if err!=nil{return in,err}
  s:=external.Selection
  if observed.Module!=s.EffectiveModule || observed.Version!=s.EffectiveVersion || string(observed.Kind)!=string(s.SourceKind) || observed.Root!=s.SourceRoot{return in,fmt.Errorf("external observation differs from selected carrier")}
  if s.SourceKind==domain.ModuleSourceVendor {if err:=checkProductObservation(cap.Context,s.SourceRoot,external.Files);err!=nil{return in,err}}
  inventory:=AssembleInventory(InventoryInput{Module:s.EffectiveModule,Version:s.EffectiveVersion,Observed:observed,Anchor:anchor})
  if !inventory.Anchored(){return in,fmt.Errorf("external independently anchored inventory: %s",inventory.Input.Reason)}
  in.External=append(in.External,ExternalComponent{ImportPath:external.ImportPath,Inventory:inventory})
 }
 return in,nil
}
func patchSourceFromBase(patch []byte,identity ModuleIdentity,files map[string][]byte)(*SourceBundle,error){
 diff:=ParseUnifiedDiff(patch)
 for _,file:=range diff.Files {
  lines:=splitSourceLines(string(files[file.Path]))
  for _,h:=range file.Hunks {before,_,_:=hunkImages(h);old:=splitSourceLines(before);start:=firstOldLine(h)-1
   if h.Truncated || len(h.Defects)>0 || start<0 || start+len(old)>len(lines) || !reflect.DeepEqual(old,lines[start:start+len(old)]){return nil,fmt.Errorf("exact patch-base preimage mismatch at %s",file.Path)}
  }
 }
 bundle,unmatched:=PatchSourceFromSelected(patch,identity,files)
 if bundle==nil || len(unmatched)>0{return nil,fmt.Errorf("patch-base images unresolved: %s",strings.Join(unmatched,"; "))}
 for name,raw:=range files{if _,ok:=bundle.Files[name];!ok{bundle.Files[name]=FileSource{Before:raw,After:raw}}}
 for name,file:=range bundle.Files{file.Selected=nil;bundle.Files[name]=file}
 return bundle,nil
}
func checkExternalSelection(external ExternalSourceCapture,selected map[string][]byte,product map[string][]byte,c SourceCaptureContext)error{
 s:=external.Selection
 if err:=s.Validate();err!=nil{return err}
 if external.ImportPath=="" || external.ImportPath!=s.DeclaredModule || s.EffectiveModule!=external.Archive.Module || s.EffectiveVersion!=external.Archive.Version || s.LocalReplacement!=nil || s.Workspace!=nil{return fmt.Errorf("external identity lacks supported versioned effective owner")}
 imported:=false
 for name,raw:=range selected {if !strings.HasSuffix(name,".go") || strings.HasSuffix(name,"_test.go"){continue};f,err:=parser.ParseFile(token.NewFileSet(),name,raw,parser.ImportsOnly);if err!=nil{return err};for _,imp:=range f.Imports {p,_:=strconv.Unquote(imp.Path.Value);if p==external.ImportPath || strings.HasPrefix(p,external.ImportPath+"/"){imported=true}}}
 if !imported{return fmt.Errorf("external component is not imported by selected source")}
 mod,err:=modfile.Parse("go.mod",product["go.mod"],nil);if err!=nil{return err}
 required:=false;for _,r:=range mod.Require{if r.Mod.Path==s.DeclaredModule && r.Mod.Version==s.DeclaredVersion{required=true}}
 if !required{return fmt.Errorf("external direct selected version lacks product go.mod grounds")}
 module,version:=s.DeclaredModule,s.DeclaredVersion
 for _,r:=range mod.Replace{if r.Old.Path==module && (r.Old.Version=="" || r.Old.Version==version){module,version=r.New.Path,r.New.Version;break}}
 if module!=s.EffectiveModule || version!=s.EffectiveVersion{return fmt.Errorf("external effective owner differs from product replacement grounds")}
 if (s.SourceKind==domain.ModuleSourceVendor)!=c.Build.VendorMode{return fmt.Errorf("external carrier differs from current vendor mode")}
 if s.SourceKind==domain.ModuleSourceVendor {
  matches:=0
  for _,m:=range affected.ParseVendorModules(product["vendor/modules.txt"]){if m.Path!=s.DeclaredModule || m.Version=="=>"{continue};matches++;if m.Version!=s.DeclaredVersion || m.EffectivePath()!=s.EffectiveModule || m.EffectiveVersion()!=s.EffectiveVersion{return fmt.Errorf("external owner differs from captured vendor metadata")}}
  if matches!=1{return fmt.Errorf("external vendor owner is missing or ambiguous")}
  mirrors:=0
  for _,line:=range strings.Split(string(product["vendor/modules.txt"]),"\n") {
   if !strings.HasPrefix(line,"# "){continue};fields:=strings.Fields(strings.TrimPrefix(line,"# "))
   if len(fields)==0 || fields[0]!=s.DeclaredModule{continue}
   if len(fields)<2{return fmt.Errorf("malformed external vendor header")}
   if fields[1]=="=>" {mirrors++;if mirrors>1 || len(fields)!=4 || fields[2]!=s.EffectiveModule || fields[3]!=s.EffectiveVersion || s.EffectiveModule==s.DeclaredModule && s.EffectiveVersion==s.DeclaredVersion{return fmt.Errorf("external vendor replacement mirror differs from selected owner")}}else if len(fields)!=2 && (len(fields)!=5 || fields[2]!="=>"){return fmt.Errorf("malformed external versioned vendor header")}
  }
 }
 e:=c.InventoryEvidence
 if e==nil || e.PackageList==nil || e.BuildContext==nil || e.Kind!=domain.EvidencePackageList{return fmt.Errorf("external selected inventory evidence missing")}
 if err:=e.BuildContext.Matches(c.Build);err!=nil{return err}
 if e.PackageList.WithTests{return fmt.Errorf("external inventory must be non-test build")}
 m:=affected.PackageInventoryMeasurement{RawStream:e.Content,RawSHA256:strings.TrimPrefix(e.ArtifactHash,"sha256:"),RawReference:e.ArtifactHash,RawSize:len(e.Content),Run:*e.PackageList,Build:*e.BuildContext}
 inv,err:=m.AdmitBuild(c.Build);if err!=nil{return err}
 found:=false
 for _,p:=range inv.Packages{if p.ImportPath==external.ImportPath || strings.HasPrefix(p.ImportPath,external.ImportPath+"/"){if p.Module==nil || p.Module.Path!=s.DeclaredModule || p.Module.Version!=s.DeclaredVersion || p.Module.EffectivePath()!=s.EffectiveModule || p.Module.EffectiveVersion()!=s.EffectiveVersion{return fmt.Errorf("external inventory owner differs from captured metadata")};found=true}}
 if !found{return fmt.Errorf("external imported component absent from build inventory")}
 return nil
}


// Vendor membership is selection only. Retained bytes and their full observed
// carrier boundary must agree with the independently fixed product snapshot.
func checkProductObservation(c SourceCaptureContext,root string,files []CapturedFile)error{
 entries,err:=repository.ValidateContentManifest(c.SnapshotManifest,c.Build.ContentHash);if err!=nil{return err}
 captured,err:=captureFiles(files);if err!=nil{return err}
 count:=0
 for _,entry:=range entries {if entry.Kind=="dir" || !strings.HasPrefix(entry.Path,root+"/"){continue};count++;rel:=strings.TrimPrefix(entry.Path,root+"/");raw,ok:=captured[rel];if !ok || entry.Kind!="file" || entry.Size!=int64(len(raw)) || DigestBytes(raw)!="sha256:"+entry.Payload{return fmt.Errorf("observed product carrier differs at %q",entry.Path)}}
 if count!=len(captured){return fmt.Errorf("observed product carrier boundary differs")}
 return nil
}

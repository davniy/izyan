package goanalysis

import (
 "bytes"
 "context"
 "fmt"
 "os"
 "path/filepath"

 "github.com/davniy/izyan/internal/affected"
 "github.com/davniy/izyan/internal/domain"
 "github.com/davniy/izyan/internal/fixbinding"
 "github.com/davniy/izyan/internal/repository"
)

// CaptureFixSources acquires snapshot-bound premises only. It neither derives a
// semantic cover nor fetches source; missing archive/checksum remains an input gap.
func(ix *Index)CaptureFixSources(ctx context.Context,c *domain.AnalysisCase,selection domain.EffectiveSourceSelection,requested fixbinding.SourceCaptures,tool affected.GoTool)(fixbinding.SourceCaptures,error){
 if c==nil || c.RecordPin==nil{return requested,fmt.Errorf("fix capture requires current case and record")}
 if build,ok:=ix.BoundBuildContext();!ok || build.Matches(domain.EffectiveBuildContext(c.Product))!=nil{return requested,fmt.Errorf("fix capture source index is not bound to current build")}
 if filepath.Clean(ix.Dir)!=filepath.Clean(c.Product.Repository){return requested,fmt.Errorf("fix capture source root differs from product")}
 before,err:=repository.CaptureContentManifest(ix.Dir);if err!=nil{return requested,err}
 entries,err:=repository.ValidateContentManifest(before,c.Product.ContentHash);if err!=nil{return requested,err}
 requested.Context=fixbinding.SourceCaptureContext{Build:domain.EffectiveBuildContext(c.Product),SnapshotManifest:before}
 metadata:=map[string]bool{"go.mod":true,"go.sum":true,"go.work":true,"vendor/modules.txt":true}
 for _,entry:=range entries {if !metadata[entry.Path]{continue};if entry.Kind!="file" || entry.Size>32<<20{return requested,fmt.Errorf("unsupported product metadata capture")};raw,err:=os.ReadFile(filepath.Join(ix.Dir,filepath.FromSlash(entry.Path)));if err!=nil{return requested,err};requested.Context.ProductFiles=append(requested.Context.ProductFiles,fixbinding.CapturedFile{Path:entry.Path,Bytes:raw})}
 var sums []byte;for _,file:=range requested.Context.ProductFiles{if file.Path=="go.sum"{sums=file.Bytes}}
 for i:=range requested.PatchBases{requested.PatchBases[i].Archive.GoSum=sums}
 selected,err:=ix.SelectedSourceCensusFor(selection);if err!=nil{return requested,err}
 for _,file:=range selected.Inventory.Observed.Files{requested.SelectedFiles=append(requested.SelectedFiles,fixbinding.CapturedFile{Path:file.Path,Bytes:file.Bytes})}
 if len(requested.External)>0 {
  if tool==nil{return requested,fmt.Errorf("external capture needs configured build inventory backend")}
  m:=affected.MeasurePackageInventory(ctx,tool,ix.Dir,c.Product,false);if _,err:=m.Admit(c.Product);err!=nil{return requested,fmt.Errorf("external inventory: %w: %s",err,m.Run.Error)}
  build:=domain.EffectiveBuildContext(c.Product)
  id:=c.EvidenceGraph.AddEvidence(domain.Evidence{Kind:domain.EvidencePackageList,Quality:domain.QualityDeterministic,Source:"go list -deps -json ./...",Tool:"go",Content:m.RawStream,ArtifactHash:m.RawReference,BuildContext:&build,PackageList:&m.Run})
  for _,e:=range c.EvidenceGraph.EvidenceList(){if e.ID==id{copy:=e;requested.Context.InventoryEvidence=&copy;break}}
  for i:=range requested.External {
   external:=&requested.External[i];s:=external.Selection
   resolved,err:=ix.ResolveModuleSource(s.DeclaredModule,s.DeclaredVersion,s.EffectiveVersion);if err!=nil{return requested,err}
   if resolved.Selection.EffectiveModule!=s.EffectiveModule || resolved.Selection.EffectiveVersion!=s.EffectiveVersion{return requested,fmt.Errorf("external effective selection differs from requested capture")}
   census,err:=ix.SelectedSourceCensusFor(resolved.Selection);if err!=nil{return requested,err}
   external.Selection=resolved.Selection;external.Observed=census.Inventory.Observed;external.Archive.GoSum=sums
   for _,file:=range census.Inventory.Observed.Files{external.Files=append(external.Files,fixbinding.CapturedFile{Path:file.Path,Bytes:file.Bytes})}
  }
 }
 after,err:=repository.CaptureContentManifest(ix.Dir);if err!=nil{return requested,err};if !bytes.Equal(before,after){return requested,fmt.Errorf("product mutated during fix-source acquisition")}
 return requested,nil
}

package goanalysis

import (
 "archive/zip"
 "bytes"
 "context"
 "io"
 "fmt"
 "os"
 "os/exec"
 "path/filepath"
 "runtime"
 "testing"

 "github.com/fedorovmv/izyan/internal/affected"
 "github.com/fedorovmv/izyan/internal/domain"
 "github.com/fedorovmv/izyan/internal/fixbinding"
 "github.com/fedorovmv/izyan/internal/repository"
 "github.com/fedorovmv/izyan/internal/vulnerability"
 "golang.org/x/mod/sumdb/dirhash"
)

// This producer control runs the actual configured Go backend offline. The
// external component is versioned and genuinely imported by selected source.
func TestExternalCaptureProducerEffectiveOwner(t *testing.T){
 for _,replaced:=range []bool{false,true}{t.Run(fmt.Sprintf("replaced=%v",replaced),func(t *testing.T){
 for _,vendored:=range []bool{false,true}{t.Run(fmt.Sprintf("vendored=%v",vendored),func(t *testing.T){
 dir:=t.TempDir();root:=filepath.Join(dir,"product");cache:=filepath.Join(dir,"cache")
 write:=func(p string,b []byte){t.Helper();if err:=os.MkdirAll(filepath.Dir(p),0755);err!=nil{t.Fatal(err)};if err:=os.WriteFile(p,b,0644);err!=nil{t.Fatal(err)}}
 const ext="example.com/capturedexternal";const dep="example.com/capturedselected"
 effective:=ext;replacement:="";if replaced{effective="example.com/capturedfork";replacement="replace "+ext+" => "+effective+" v1.0.0\n"}
 mod:=[]byte("module "+effective+"\n\ngo 1.25\n");source:=[]byte("package capturedexternal\nfunc init() {}\n")
 var raw bytes.Buffer;zw:=zip.NewWriter(&raw);for _,f:=range []struct{name string;b []byte}{{"go.mod",mod},{"external.go",source}}{w,err:=zw.Create(effective+"@v1.0.0/"+f.name);if err!=nil{t.Fatal(err)};if _,err:=w.Write(f.b);err!=nil{t.Fatal(err)}};if err:=zw.Close();err!=nil{t.Fatal(err)}
 downloaded:=filepath.Join(cache,"cache","download",filepath.FromSlash(effective),"@v")
 zipPath:=filepath.Join(downloaded,"v1.0.0.zip");write(zipPath,raw.Bytes());h1,err:=dirhash.HashZip(zipPath,dirhash.Hash1);if err!=nil{t.Fatal(err)}
 write(filepath.Join(downloaded,"v1.0.0.ziphash"),[]byte(h1));write(filepath.Join(downloaded,"v1.0.0.mod"),mod);write(filepath.Join(downloaded,"v1.0.0.info"),[]byte(`{"Version":"v1.0.0","Time":"2026-10-29T00:00:00Z"}`))
 write(filepath.Join(cache,filepath.FromSlash(effective)+"@v1.0.0","go.mod"),mod);write(filepath.Join(cache,filepath.FromSlash(effective)+"@v1.0.0","external.go"),source)
 write(filepath.Join(root,"go.mod"),[]byte("module example.com/captureproduct\n\ngo 1.25\nrequire (\n"+dep+" v1.0.0\n"+ext+" v1.0.0\n)\nreplace "+dep+" => ./dep\n"+replacement))
 modHash,err:=dirhash.Hash1([]string{"go.mod"},func(string)(io.ReadCloser,error){return io.NopCloser(bytes.NewReader(mod)),nil});if err!=nil{t.Fatal(err)}
 write(filepath.Join(root,"go.sum"),[]byte(effective+" v1.0.0 "+h1+"\n"+effective+" v1.0.0/go.mod "+modHash+"\n"))
 write(filepath.Join(root,"main.go"),[]byte("package main\nimport _ \""+dep+"\"\nfunc main(){}\n"))
 write(filepath.Join(root,"dep","go.mod"),[]byte("module "+dep+"\n\ngo 1.25\nrequire "+ext+" v1.0.0\n"))
 write(filepath.Join(root,"dep","selected.go"),[]byte("package capturedselected\nimport _ \""+ext+"\"\nfunc Prepare(){}\n"))
 env:=[]string{"GOPROXY=off","GOSUMDB=off","GOWORK=off","GOMODCACHE="+cache}
 if vendored {cmd:=exec.CommandContext(context.Background(),"go","mod","vendor");cmd.Dir=root;cmd.Env=append(os.Environ(),env...);if output,err:=cmd.CombinedOutput();err!=nil{t.Fatalf("prepare offline vendor fixture: %v: %s",err,output)}}
 product,err:=(repository.Service{}).Snapshot(context.Background(),root,repository.SnapshotOptions{GOOS:runtime.GOOS,GOARCH:runtime.GOARCH,ExternalCommitSHA:"external-capture",Env:env});if err!=nil{t.Fatal(err)}
 ix:=&Index{Dir:root,Build:product,Env:env};if err:=ix.BindBuild(product);err!=nil{t.Fatal(err)}
 selected,err:=ix.ResolveModuleSource(dep,"v1.0.0","");if err!=nil{t.Fatal(err)};selected.Selection.EntryRef=0
 advisory:=[]byte(`{"id":"GO-2099-EXTERNAL-CAPTURE","modified":"2026-10-29T00:00:00Z","affected":[{"package":{"ecosystem":"Go","name":"`+dep+`"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`)
 loaded,err:=vulnerability.LoadExactBytes(advisory,"","local:external");if err!=nil{t.Fatal(err)}
 c:=&domain.AnalysisCase{Product:product,Vulnerability:*loaded.Vuln,RecordPin:&loaded.Pin,AdvisoryRecord:&domain.AdvisoryRecordCapture{Pin:loaded.Pin,Bytes:advisory},Affected:&domain.AffectedResult{EffectiveSources:[]domain.EffectiveSourceSelection{selected.Selection}}}
 requested:=fixbinding.SourceCaptures{External:[]fixbinding.ExternalSourceCapture{{ImportPath:ext,Selection:domain.EffectiveSourceSelection{DeclaredModule:ext,DeclaredVersion:"v1.0.0",EffectiveModule:effective,EffectiveVersion:"v1.0.0"},Archive:fixbinding.ArchiveEvidence{Module:effective,Version:"v1.0.0",Bytes:raw.Bytes()}}}}
 captured,err:=ix.CaptureFixSources(context.Background(),c,selected.Selection,requested,affected.ExecGoTool{Env:env,Version:product.GoVersion});if err!=nil{t.Fatal(err)}
 census,err:=ix.SelectedSourceCensusFor(selected.Selection);if err!=nil{t.Fatal(err)}
 in:=fixbinding.Inputs{Pin:loaded.Pin,Raw:advisory,EntryRef:0,Selection:c.Affected.EffectiveSources,Inventory:census.Inventory,Captures:&captured}
 reconstructed,err:=fixbinding.ReconstructSources(in);if err!=nil{t.Fatal(err)}
 if len(reconstructed.External)!=1 || !reconstructed.External[0].Inventory.Anchored(){t.Fatal("real effective external source was not independently anchored")}
 captured.External[0].Selection.EffectiveModule="example.com/forged"
 if _,err:=fixbinding.ReconstructSources(in);err==nil{t.Fatal("wrong effective owner accepted")}
 })}
 })}
}

func TestExternalCaptureVendorReplacementMirror(t *testing.T){
 const module="example.com/vendororiginal"
 header:="# "+module+" v1.0.0 => example.com/vendorfork v1.1.0\n## explicit; go 1.25\n"+module+"\n"
 mirror:="# "+module+" => example.com/vendorfork v1.1.0\n"
 for _,tc:=range []struct{name,body string;valid bool}{
  {"canonical",header+mirror,true},
  {"malformed",header+"# "+module+" =>\n",false},
  {"mismatching",header+"# "+module+" => example.com/foreign v1.1.0\n",false},
  {"mirror-only",mirror,false},
  {"duplicate",header+mirror+mirror,false},
 }{t.Run(tc.name,func(t *testing.T){root:=t.TempDir();if err:=os.MkdirAll(filepath.Join(root,"vendor"),0755);err!=nil{t.Fatal(err)};if err:=os.WriteFile(filepath.Join(root,"vendor","modules.txt"),[]byte(tc.body),0644);err!=nil{t.Fatal(err)}
  _,found,err:=(&Index{Dir:root}).vendorHeader(module)
  if tc.valid {if err!=nil || !found{t.Fatalf("canonical mirror refused: %v",err)}}else if err==nil{t.Fatal("invalid replacement mirror accepted")}
 })}
}

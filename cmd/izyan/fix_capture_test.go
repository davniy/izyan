package main

import (
 "archive/zip"
 "bytes"
 "context"
 "encoding/json"
 "os"
 "path/filepath"
 "runtime"
 "strings"
 "testing"

 "github.com/davniy/izyan/internal/domain"
 "github.com/davniy/izyan/internal/fixbinding"
 "github.com/davniy/izyan/internal/goanalysis"
 "github.com/davniy/izyan/internal/report"
 "github.com/davniy/izyan/internal/rootcause"
 "github.com/davniy/izyan/internal/repository"
 "github.com/davniy/izyan/internal/vulnerability"
 "golang.org/x/mod/sumdb/dirhash"
)

func TestResearchFixCapturePublicationReplay(t *testing.T){
 t.Setenv("GOPROXY","off");t.Setenv("GOSUMDB","off");t.Setenv("GOWORK","off")
 dir:=t.TempDir();product:=filepath.Join(dir,"product");captures:=filepath.Join(dir,"captures");out:=filepath.Join(dir,"out")
 write:=func(name string,raw []byte){t.Helper();if err:=os.MkdirAll(filepath.Dir(name),0755);err!=nil{t.Fatal(err)};if err:=os.WriteFile(name,raw,0644);err!=nil{t.Fatal(err)}}
 const module="example.com/capturedep"
 const locator="https://example.com/capturedep/commit/0123456789abcdef"
 source:=[]byte("package capturedep\n\nimport disk \"os\"\n\nfunc Prepare(root string) error {\n\treturn disk.MkdirAll(root, 0755)\n}\n")
 patch:=[]byte("diff --git a/prepare.go b/prepare.go\n--- a/prepare.go\n+++ b/prepare.go\n@@ -5,3 +5,3 @@\n func Prepare(root string) error {\n-\treturn disk.MkdirAll(root, 0755)\n+\treturn disk.MkdirAll(root, 0700)\n }\n")
 write(filepath.Join(product,"go.mod"),[]byte("module example.com/captureprod\n\ngo 1.25\n\nrequire "+module+" v1.0.0\nreplace "+module+" => ./dep\n"))
 write(filepath.Join(product,"main.go"),[]byte("package main\nimport dep \""+module+"\"\nfunc main(){ _ = dep.Prepare(\"/tmp/captured\") }\n"))
 write(filepath.Join(product,"dep","go.mod"),[]byte("module "+module+"\n\ngo 1.25\n"));write(filepath.Join(product,"dep","prepare.go"),source)
 // Cross-release base is independently pinned in the PRODUCT go.sum.
 var archive bytes.Buffer;zw:=zip.NewWriter(&archive)
 for _,entry:=range []struct{name string;raw []byte}{{"go.mod",[]byte("module "+module+"\n\ngo 1.25\n")},{"prepare.go",source}}{w,err:=zw.Create(module+"@v1.1.0/"+entry.name);if err!=nil{t.Fatal(err)};if _,err:=w.Write(entry.raw);err!=nil{t.Fatal(err)}}
 if err:=zw.Close();err!=nil{t.Fatal(err)}
 zipPath:=filepath.Join(captures,"base.zip");write(zipPath,archive.Bytes());h1,err:=dirhash.HashZip(zipPath,dirhash.Hash1);if err!=nil{t.Fatal(err)}
 write(filepath.Join(product,"go.sum"),[]byte(module+" v1.1.0 "+h1+"\n"))
 write(filepath.Join(captures,"fix.patch"),patch)
 write(filepath.Join(captures,"tree","go.mod"),[]byte("module "+module+"\n\ngo 1.25\n"));write(filepath.Join(captures,"tree","prepare.go"),source)
 advisory:=[]byte(`{"id":"GO-2099-CAPTURE","modified":"2026-10-29T00:00:00Z","summary":"directory permissions","affected":[{"package":{"ecosystem":"Go","name":"example.com/capturedep"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.0"}]}]}],"references":[{"type":"FIX","url":"`+locator+`"}]}`)
 advisoryPath:=filepath.Join(dir,"advisory.json");write(advisoryPath,advisory)
 loaded,err:=vulnerability.LoadExactBytes(advisory,"","local:capture");if err!=nil{t.Fatal(err)}
 snapshot,err:=(repository.Service{}).Snapshot(context.Background(),product,repository.SnapshotOptions{GOOS:runtime.GOOS,GOARCH:runtime.GOARCH,ExternalCommitSHA:"capture-fixture",Env:[]string{"GOPROXY=off","GOSUMDB=off","GOWORK=off"}});if err!=nil{t.Fatal(err)}
 ix:=&goanalysis.Index{Dir:product,Env:[]string{"GOPROXY=off","GOSUMDB=off","GOWORK=off"},Build:snapshot}
 if err:=ix.BindBuild(snapshot);err!=nil{t.Fatal(err)}
 resolved,err:=ix.ResolveModuleSource(module,"v1.0.0","");if err!=nil{t.Fatal(err)};resolved.Selection.EntryRef=0
 manifest:=map[string]any{"schema":rootcause.FixSourceCapturesSchema,"artifacts":[]any{map[string]any{"locator":locator,"path":"fix.patch","digest":fixbinding.DigestBytes(patch)}},"captures":[]any{map[string]any{"record_id":loaded.Pin.RecordID,"document_digest":loaded.Pin.DocumentDigest,"entry_ref":0,"selected_source":resolved.Selection,"patch_bases":[]any{map[string]any{"locator":locator,"artifact_digest":fixbinding.DigestBytes(patch),"module":module,"version":"v1.1.0","archive_path":"base.zip","archive_digest":fixbinding.DigestBytes(archive.Bytes()),"tree_path":"tree"}}}}}
 manifestBytes,err:=json.Marshal(manifest);if err!=nil{t.Fatal(err)};manifestPath:=filepath.Join(captures,"manifest.json");write(manifestPath,manifestBytes)
 err=runResearch([]string{"--snapshot",product,"--cve",loaded.Pin.RecordID,"--advisory-file",advisoryPath,"--output-dir",out,"--external-commit-sha","capture-fixture","--goos",runtime.GOOS,"--goarch",runtime.GOARCH,"--fix-source-captures",manifestPath,"--deterministic-timeout","120s","--overall-timeout","180s"})
 if err!=nil{t.Fatal(err)}
 raw,err:=os.ReadFile(filepath.Join(out,"requested-case.json"));if err!=nil{t.Fatal(err)}
 var c domain.AnalysisCase;if err:=json.Unmarshal(raw,&c);err!=nil{t.Fatal(err)}
 if c.RootCause==nil || c.RootCause.FixProof==nil{if c.RootCause!=nil{t.Fatalf("no real resolver proof: %v",c.RootCause.Limitations)};t.Fatal("no retained rootcause")}
 if err:=os.RemoveAll(product);err!=nil{t.Fatal(err)};if err:=os.RemoveAll(captures);err!=nil{t.Fatal(err)}
 if _,err:=fixbinding.Readmit(fixbinding.AdmissionForCase(&c),c.RootCause.FixProof);err!=nil{t.Fatalf("source-free contextual replay: %v",err)}
 if a:=fixbinding.AdmitModelProof(fixbinding.AdmissionForCase(&c),c.RootCause);!a.Admitted(){t.Fatalf("source-free admission: %v",a.Refusals)}
 // Publication must use captured case inputs rather than reopening the product.
 publication:=filepath.Join(dir,"publication")
 if err:=report.Write(publication,&c);err!=nil{t.Fatal(err)}
 published,err:=os.ReadFile(filepath.Join(publication,"report.json"));if err!=nil{t.Fatal(err)}
 if !strings.Contains(string(published),domain.FixProofContract){t.Fatal("publication lost capture proof")}
}

func TestResearchFixCaptureRejectsHistoricalRoute(t *testing.T){
 err:=runResearch([]string{"--snapshot",t.TempDir(),"--cve","GO-CAPTURE","--advisory-file","absent.json","--output-dir",t.TempDir(),"--decision-ready","--deterministic-only","--fix-source-captures","absent-manifest.json"})
 if err==nil || !strings.Contains(err.Error(),"--fix-source-captures requires canonical research"){t.Fatalf("historical route did not reject captures explicitly: %v",err)}
}

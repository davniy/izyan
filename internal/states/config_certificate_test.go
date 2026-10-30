package states

import (
 "context"
 "os"
 "path/filepath"
 "runtime"
 "testing"

 "github.com/fedorovmv/izyan/internal/domain"
 "github.com/fedorovmv/izyan/internal/evaluator"
 "github.com/fedorovmv/izyan/internal/exploit"
 "github.com/fedorovmv/izyan/internal/goanalysis"
 "github.com/fedorovmv/izyan/internal/repository"
 "github.com/fedorovmv/izyan/internal/vulnerability"
)

func TestSafeConfigCollection(t *testing.T) {
 for _,name:=range []string{"configcheckdirectprod","configcheckcopyprod"}{t.Run(name,func(t *testing.T){
  root,err:=filepath.Abs(filepath.Join("..","..","testdata",name));if err!=nil{t.Fatal(err)}
  dir:=filepath.Join(t.TempDir(),"source");if err=os.CopyFS(dir,os.DirFS(root));err!=nil{t.Fatal(err)}
  ctx:=context.Background()
  snap,err:=(repository.Service{}).Snapshot(ctx,dir,repository.SnapshotOptions{GOOS:runtime.GOOS,GOARCH:runtime.GOARCH,ExternalCommitSHA:"collection-snapshot",Env:[]string{"GOPROXY=off","GOSUMDB=off","GOWORK=off"}});if err!=nil{t.Fatal(err)}
  raw,err:=os.ReadFile(filepath.Join(dir,"advisory.json"));if err!=nil{t.Fatal(err)}
  loaded,err:=vulnerability.LoadExactBytes(raw,"","local:collection-advisory");if err!=nil{t.Fatal(err)}
  c:=&domain.AnalysisCase{Product:snap,Vulnerability:*loaded.Vuln,RecordPin:&loaded.Pin,AdvisoryRecord:&domain.AdvisoryRecordCapture{Pin:loaded.Pin,Bytes:raw},RootCause:&domain.RootCauseModel{Status:domain.RootCauseResolved}}
  for _,ref:=range c.Vulnerability.AffectedSymbols{c.RootCause.RootCauses=append(c.RootCause.RootCauses,domain.RootCause{Package:ref.Package,Symbol:ref.Symbol,Role:domain.RootCauseSink})}
  ix:=&goanalysis.Index{Dir:dir,Build:snap,Env:[]string{"GOPROXY=off","GOSUMDB=off","GOWORK=off"}}
  if err=ix.BindBuild(snap);err!=nil{t.Fatal(err)}
  model,lims:=(exploit.Builder{Source:ix}).Build(ctx,c,c.Vulnerability,c.RootCause);c.Exploit=model
  if model==nil || model.DefectSemantics==nil || model.DefectSemantics.Mode!=domain.DefectSemanticsDefectiveCheck{t.Fatalf("fixture model: %+v %v",model,lims)}
  (CollectEvidence{Source:ix}).runSourceAnalysis(ctx,c)
  certificates:=0
  for _,e:=range c.EvidenceGraph.EvidenceList(){if e.Tool==goanalysis.ConfigCertificateTool{certificates++;if e.ArtifactHash=="" || len(e.Content)<1000{t.Fatal("collection persisted only a summary")}}}
  if certificates!=1{t.Fatalf("collection certificates=%d limitations=%v",certificates,c.EvidenceGraph.ToolLimitations)}
  for _,cond:=range model.MandatoryConditions{if cond.Kind!=domain.ConditionCheckTrigger{continue};claim:=(evaluator.CheckTrigger{}).Evaluate(cond,c);if claim.Result!=domain.ClaimFalse{t.Fatalf("collected candidate %+v",claim)};claim=(goanalysis.Verifier{Source:ix}).VerifyFalse(ctx,c,claim,cond);if claim.NegativeVerification==nil || claim.NegativeVerification.Status!=domain.NegativeVerified{t.Fatalf("collected live proof %+v",claim)}}
 })}
}

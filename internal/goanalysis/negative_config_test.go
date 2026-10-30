package goanalysis_test

import (
 "context"
 "encoding/json"
 "errors"
 "os"
 "path/filepath"
 "runtime"
 "strings"
 "testing"

 "github.com/fedorovmv/izyan/internal/domain"
 "github.com/fedorovmv/izyan/internal/affected"
 "github.com/fedorovmv/izyan/internal/evaluator"
 "github.com/fedorovmv/izyan/internal/exploit"
 "github.com/fedorovmv/izyan/internal/finding"
 "github.com/fedorovmv/izyan/internal/report"
 "github.com/fedorovmv/izyan/internal/goanalysis"
 "github.com/fedorovmv/izyan/internal/repository"
 "github.com/fedorovmv/izyan/internal/vulnerability"
)

type configFixture struct { c *domain.AnalysisCase; ix *goanalysis.Index; cond domain.Condition; cert domain.ConfigWriterCertificate; dir string }

func prepareConfig(t *testing.T,name string,change func(string)) configFixture {
 t.Helper()
 source,err:=filepath.Abs(filepath.Join("..","..","testdata",name));if err!=nil{t.Fatal(err)}
 dir:=filepath.Join(t.TempDir(),"product")
 if err=os.CopyFS(dir,os.DirFS(source));err!=nil{t.Fatal(err)}
 if change!=nil{change(dir)}
 ctx:=context.Background()
 product,err:=(repository.Service{}).Snapshot(ctx,dir,repository.SnapshotOptions{GOOS:runtime.GOOS,GOARCH:runtime.GOARCH,ExternalCommitSHA:"config-snapshot",Env:[]string{"GOPROXY=off","GOSUMDB=off","GOWORK=off"}});if err!=nil{t.Fatal(err)}
 raw,err:=os.ReadFile(filepath.Join(dir,"advisory.json"));if err!=nil{t.Fatal(err)}
 loaded,err:=vulnerability.LoadExactBytes(raw,"","local:config-advisory");if err!=nil{t.Fatal(err)}
 c:=&domain.AnalysisCase{ID:"config-proof",RequestedID:loaded.Vuln.ID,Product:product,Vulnerability:*loaded.Vuln,RecordPin:&loaded.Pin,AdvisoryRecord:&domain.AdvisoryRecordCapture{Pin:loaded.Pin,Bytes:raw}}
 c.RootCause=&domain.RootCauseModel{Status:domain.RootCauseResolved}
 for _,ref:=range loaded.Vuln.AffectedSymbols {c.RootCause.RootCauses=append(c.RootCause.RootCauses,domain.RootCause{Package:ref.Package,Symbol:ref.Symbol,Role:domain.RootCauseSink})}
 ix:=&goanalysis.Index{Dir:dir,Build:product,Env:[]string{"GOPROXY=off","GOSUMDB=off","GOWORK=off"}}
 if err=ix.BindBuild(product);err!=nil{t.Fatal(err)}
 model,lims:=(exploit.Builder{Source:ix}).Build(ctx,c,c.Vulnerability,c.RootCause);c.Exploit=model
 if model==nil || model.DefectSemantics==nil || model.DefectSemantics.Mode!=domain.DefectSemanticsDefectiveCheck {t.Fatalf("builder did not admit fixture: %+v %v",model,lims)}
 var cond domain.Condition
 for _,candidate:=range model.MandatoryConditions {if candidate.Kind==domain.ConditionCheckTrigger{cond=candidate}}
 if cond.ID==""{t.Fatal("builder generated no mandatory trigger")}
 return configFixture{c:c,ix:ix,cond:cond,dir:dir}
}

func captureConfig(t *testing.T,name string,change func(string)) configFixture {
 t.Helper();f:=prepareConfig(t,name,change)
 cert,err:=f.ix.CaptureConfigWriterCertificate(context.Background(),f.c,f.cond);if err!=nil{t.Fatal(err)};f.cert=cert
 ev,err:=goanalysis.ConfigCertificateEvidence(cert);if err!=nil{t.Fatal(err)};f.c.EvidenceGraph.AddEvidence(ev)
 return f
}

func replaceConfig(t *testing.T,dir,old,new string) {
 t.Helper();file:=filepath.Join(dir,"main.go");raw,err:=os.ReadFile(file);if err!=nil{t.Fatal(err)}
 if !strings.Contains(string(raw),old){t.Fatalf("fixture replacement absent: %q",old)}
 if err=os.WriteFile(file,[]byte(strings.ReplaceAll(string(raw),old,new)),0600);err!=nil{t.Fatal(err)}
}

func TestSafeConfigNeedsClosedEffectiveObject(t *testing.T) {
 for _,name:=range []string{"configcheckdirectprod","configcheckcopyprod"}{t.Run(name,func(t *testing.T){
  f:=captureConfig(t,name,nil)
  if err:=goanalysis.ValidateConfigWriterEvidence(goanalysis.ConfigAdmissionForCase(f.c),f.cond,f.cert);err!=nil{t.Fatal(err)}
  claim:=(evaluator.CheckTrigger{}).Evaluate(f.cond,f.c)
  if claim.Result!=domain.ClaimFalse || claim.Falsifier!=domain.FalsifierSafeConfigAssignment{t.Fatalf("candidate %+v",claim)}
  claim=(goanalysis.Verifier{Source:f.ix}).VerifyFalse(context.Background(),f.c,claim,f.cond)
  if claim.NegativeVerification==nil || claim.NegativeVerification.Status!=domain.NegativeVerified{t.Fatalf("live verification %+v",claim)}
  if err:=goanalysis.ValidateVerifiedNegative(goanalysis.ConfigAdmissionForCase(f.c),claim,f.cond);err!=nil{t.Fatal(err)}
  payload,err:=json.Marshal(f.cert);if err!=nil{t.Fatal(err)}
  inventoryBytes:=0;for _,e:=range f.c.EvidenceGraph.EvidenceList(){if e.ID==f.cert.InventoryEvidenceID{inventoryBytes=len(e.Content)}}
  t.Logf("full certificate bytes=%d inventory bytes=%d",len(payload),inventoryBytes)
  t.Logf("actual offline builder/inventory/capture/verifier: uses=%d packages=%d manifest=%d",len(f.cert.Uses),len(f.cert.Packages),len(f.cert.SnapshotManifest))
 })}
}

func TestSafeConfigUnsafeWriterContradicts(t *testing.T) {
 for _,alternative:=range []string{"cfg.Skip = true\n context.VerifyIssuer((cfg.Skip),\"another\")","unsafe := Options{Skip:true}\n context.VerifyIssuer(unsafe.Skip,\"another\")"}{t.Run(alternative,func(t *testing.T){
  f:=captureConfig(t,"configcheckcopyprod",func(dir string){replaceConfig(t,dir,"context.VerifyIssuer((cfg.Skip),\"another\")",alternative)})
  err:=goanalysis.ValidateConfigWriterEvidence(goanalysis.ConfigAdmissionForCase(f.c),f.cond,f.cert)
  if !errors.Is(err,goanalysis.ErrConfigWriterContradicted){t.Fatalf("unsafe consume not contradicted: %v",err)}
  claim:=(evaluator.CheckTrigger{}).Evaluate(f.cond,f.c)
  if claim.Result!=domain.ClaimUnknown || claim.NegativeVerification==nil || claim.NegativeVerification.Status!=domain.NegativeContradicted{t.Fatalf("unsafe alternative %+v",claim)}
  claim.Result=domain.ClaimFalse;claim.Falsifier=domain.FalsifierSafeConfigAssignment;claim.EvidenceIDs=claim.NegativeVerification.EvidenceIDs
  live:=(goanalysis.Verifier{Source:f.ix}).VerifyFalse(context.Background(),f.c,claim,f.cond)
  if live.Result!=domain.ClaimUnknown || live.NegativeVerification.Status!=domain.NegativeContradicted{t.Fatalf("unsafe live proof %+v",live)}
  build:=domain.EffectiveBuildContext(f.c.Product)
  claim.NegativeVerification=&domain.NegativeVerification{Status:domain.NegativeVerified,BuildContext:&build,EvidenceIDs:claim.EvidenceIDs}
  if err=goanalysis.ValidateVerifiedNegative(goanalysis.ConfigAdmissionForCase(f.c),claim,f.cond);!errors.Is(err,goanalysis.ErrConfigWriterContradicted){t.Fatalf("unsafe historical publication accepted: %v",err)}
 })}
}

func TestSafeConfigOverrideOrEscapeRefuses(t *testing.T) {
 changes:=map[string]string{
  "alias":"alias := &cfg\n _ = alias",
  "field-address":"address := &cfg.Skip\n _ = address",
  "override":"cfg.Skip = unknown()",
  "range":"for _, cfg.Skip = range []bool{true} {}",
  "range-object":"for _, cfg = range []Options{{Skip:true}} {}",
  "branch":"if unknown() { cfg.Skip = true }",
  "method-value":"mutate := cfg.Enable\n mutate()",
  "method-direct":"cfg.Enable()",
  "method-parenthesized":"(cfg.Enable)()",
  "tuple":"_, cfg = construct()",
  "callback":"callback := context.VerifyIssuer\n _ = callback",
 }
 for name,code:=range changes{t.Run(name,func(t *testing.T){
  f:=prepareConfig(t,"configcheckcopyprod",func(dir string){
   replaceConfig(t,dir,"context.VerifyIssuer(cfg.Skip,\"service\")",code+"\n context.VerifyIssuer(cfg.Skip,\"service\")")
   file:=filepath.Join(dir,"main.go");raw,err:=os.ReadFile(file);if err!=nil{t.Fatal(err)};raw=append(raw,[]byte("\nfunc unknown() bool { return false }\nfunc construct() (int,Options) { return 0,Options{Skip:true} }\nfunc (o *Options) Enable() { o.Skip = true }\n")...);if err=os.WriteFile(file,raw,0600);err!=nil{t.Fatal(err)}
  })
  _,err:=f.ix.CaptureConfigWriterCertificate(context.Background(),f.c,f.cond)
  if !errors.Is(err,goanalysis.ErrConfigWriterInsufficientScope){t.Fatalf("unresolved hazard not insufficient: %v",err)}
 })}
}

func TestForgedCompleteConfigEvidenceRefuses(t *testing.T) {
 f:=captureConfig(t,"configcheckcopyprod",nil)
 for _,name:=range []string{"missing-source","tampered-source","missing-package","duplicate-package","duplicate-file","selected-file","missing-use","duplicate-use","surplus-use","foreign-build","forged-manifest","complete-summary","wrong-object","wrong-argument","wrong-field","wrong-consumer"}{t.Run(name,func(t *testing.T){
  raw,_:=json.Marshal(f.cert);var cert domain.ConfigWriterCertificate;if err:=json.Unmarshal(raw,&cert);err!=nil{t.Fatal(err)}
  switch name{
  case "missing-source":cert.Packages[0].Files=nil
  case "tampered-source":cert.Packages[0].Files[0].Bytes=append(cert.Packages[0].Files[0].Bytes,' ')
  case "missing-package":cert.Packages=cert.Packages[:1]
  case "duplicate-package":cert.Packages=append(cert.Packages,cert.Packages[0])
  case "duplicate-file":cert.Packages[0].Files=append(cert.Packages[0].Files,cert.Packages[0].Files[0])
  case "selected-file":cert.Packages[0].SelectedGoFiles[0]="missing.go"
  case "missing-use":cert.Uses=cert.Uses[:1]
  case "duplicate-use","surplus-use":cert.Uses=append(cert.Uses,cert.Uses[0])
  case "foreign-build":cert.Build.GOOS="foreign"
  case "forged-manifest":cert.SnapshotManifest=append(cert.SnapshotManifest,' ')
  case "complete-summary":cert=domain.ConfigWriterCertificate{Schema:domain.ConfigWriterCertificateSchema,ConditionID:f.cond.ID}
  case "wrong-object":cert.Uses[0].ObjectID="safe"
  case "wrong-argument":cert.Uses[0].Argument=1
  case "wrong-field":cert.Uses[0].Field.Symbol="Other.Safe"
  case "wrong-consumer":cert.Uses[0].Consumer.Line++
  }
  if err:=goanalysis.ValidateConfigWriterEvidence(goanalysis.ConfigAdmissionForCase(f.c),f.cond,cert);!errors.Is(err,goanalysis.ErrConfigWriterInsufficientScope){t.Fatalf("forged metadata admitted: %v",err)}
 })}
}

func TestSafeConfigNecessityReplay(t *testing.T) {
 f:=captureConfig(t,"configcheckdirectprod",nil)
 for _,name:=range []string{"literal","name","index","subject","supporting","record","record-bytes","capture","ground","ground-digest","missing-model","numeric-bool","llm-only"}{t.Run(name,func(t *testing.T){
  raw,_:=json.Marshal(f.c);var c domain.AnalysisCase;if err:=json.Unmarshal(raw,&c);err!=nil{t.Fatal(err)}
  cond:=c.Exploit.MandatoryConditions[0]
  for _,candidate:=range c.Exploit.MandatoryConditions{if candidate.Kind==domain.ConditionCheckTrigger{cond=candidate}}
  switch name{
  case "literal":c.Exploit.DefectSemantics.Trigger.Argument.Value="true";cond.Params[domain.ParamArgumentValue]="true"
  case "name":c.Exploit.DefectSemantics.Trigger.Argument.Name="other";cond.Params[domain.ParamArgumentName]="other"
  case "index":c.Exploit.DefectSemantics.Trigger.Argument.Index=0;cond.ArgIndex=0
  case "subject":cond.Subjects=[]domain.SymbolRef{{Package:"other",Symbol:"Other.Check"}}
  case "supporting":cond.Mandatory=false
  case "record":c.RecordPin.DocumentDigest="sha256:"+strings.Repeat("ab",32)
  case "capture":c.AdvisoryRecord=nil
  case "ground":c.Exploit.DefectSemantics.Grounds[0].Quote="changed"
  case "record-bytes":c.AdvisoryRecord.Bytes=append(c.AdvisoryRecord.Bytes,' ')
  case "ground-digest":c.Exploit.DefectSemantics.Grounds[0].EvidenceDigest="sha256:"+strings.Repeat("cd",32)
  case "missing-model":c.Exploit.DefectSemantics=nil
  case "numeric-bool":c.Exploit.DefectSemantics.Trigger.Argument.Value="1";cond.Params[domain.ParamArgumentValue]="1"
  case "llm-only":for i:=range c.EvidenceGraph.Evidence{c.EvidenceGraph.Evidence[i].Quality=domain.QualityLLMInferred}
  }
  for i:=range c.Exploit.MandatoryConditions{if c.Exploit.MandatoryConditions[i].ID==cond.ID{c.Exploit.MandatoryConditions[i]=cond}}
  if err:=goanalysis.ValidateConfigWriterEvidence(goanalysis.ConfigAdmissionForCase(&c),cond,f.cert);!errors.Is(err,goanalysis.ErrConfigWriterInsufficientScope){t.Fatalf("necessity forgery admitted: %v",err)}
 })}
}

func TestSafeConfigSnapshotManifest(t *testing.T) {
 f:=prepareConfig(t,"configcheckdirectprod",nil)
 replaceConfig(t,f.dir,"RequireAudience:true","RequireAudience:false")
 if _,err:=f.ix.CaptureConfigWriterCertificate(context.Background(),f.c,f.cond);!errors.Is(err,goanalysis.ErrConfigWriterInsufficientScope){t.Fatalf("acquisition drift accepted: %v",err)}
}

func TestSafeConfigAllConsumers(t *testing.T) {
 f:=captureConfig(t,"configcheckcopyprod",nil)
 if len(f.cert.Uses)!=2{t.Fatalf("missing actual consumers: %+v",f.cert.Uses)}
 f.cert.Uses=f.cert.Uses[:1]
 if err:=goanalysis.ValidateConfigWriterEvidence(goanalysis.ConfigAdmissionForCase(f.c),f.cond,f.cert);!errors.Is(err,goanalysis.ErrConfigWriterInsufficientScope){t.Fatalf("subset accepted: %v",err)}
}

func TestSafeConfigCapturedReplay(t *testing.T) {
 for _,name:=range []string{"configcheckdirectprod","configcheckcopyprod"}{t.Run(name,func(t *testing.T){
  f:=captureConfig(t,name,nil)
  claim:=(evaluator.CheckTrigger{}).Evaluate(f.cond,f.c)
  claim=(goanalysis.Verifier{Source:f.ix}).VerifyFalse(context.Background(),f.c,claim,f.cond)
  f.c.Claims=[]domain.Claim{claim}
  raw,err:=json.Marshal(f.c);if err!=nil{t.Fatal(err)}
  var persisted domain.AnalysisCase;if err=json.Unmarshal(raw,&persisted);err!=nil{t.Fatal(err)}
  if err=os.Rename(f.dir,f.dir+"-unavailable");err!=nil{t.Fatal(err)}
  if err=goanalysis.ValidateVerifiedNegative(goanalysis.ConfigAdmissionForCase(&persisted),persisted.Claims[0],f.cond);err!=nil{t.Fatal(err)}
  in:=evaluator.VerdictInput{Product:persisted.Product,Vulnerability:persisted.Vulnerability,RecordPin:persisted.RecordPin,AdvisoryRecord:persisted.AdvisoryRecord,Model:*persisted.Exploit,Claims:persisted.Claims,Evidence:persisted.EvidenceGraph.EvidenceList(),Affected:domain.AffectedResult{Scope:persisted.Vulnerability.Scope.Clone(),ModulePresent:domain.ClaimTrue,VersionAffected:domain.ClaimTrue}}
  verdict:=(evaluator.VerdictEvaluator{}).Evaluate(in)
  if verdict.Verdict!=domain.VerdictNoExploitPathFound{t.Fatalf("source-free verdict: %+v",verdict)}
  persisted.Affected=&in.Affected
  result:=finding.Assess(finding.AssessmentInput{VerdictInput:in,RootCause:persisted.RootCause,Vulnerability:persisted.Vulnerability,AssessmentID:persisted.ID})
  if result.Outcome!=domain.OutcomeDecided{t.Fatalf("source-free assessment: %+v",result)}
  persisted.ProfileAssessments=[]domain.ProfileAssessment{{Profile:domain.ProfileZeroTrust,IsTargetActual:true,Build:domain.EffectiveBuildContext(persisted.Product),Claims:persisted.Claims,Result:result}}
  persisted.Verdict=result.Verdict
  if err=finding.Finalize(&persisted);err!=nil{t.Fatal(err)}
  persisted.Workflow.State=domain.StateCompleted
  if _,err=finding.Project(&persisted);err!=nil{t.Fatalf("source-free requested publication: %v",err)}
  output:=t.TempDir()
  if err=report.Write(output,&persisted);err!=nil{t.Fatalf("source-free report publication: %v",err)}
  t.Logf("source-free verdict + requested finding + report success: serialized case bytes=%d",len(raw))
  for _,fault:=range []string{"missing-payload","digest"}{t.Run(fault,func(t *testing.T){
   serialized,err:=json.Marshal(&persisted);if err!=nil{t.Fatal(err)};var damaged domain.AnalysisCase;if err=json.Unmarshal(serialized,&damaged);err!=nil{t.Fatal(err)}
   for i:=range damaged.EvidenceGraph.Evidence {ev:=&damaged.EvidenceGraph.Evidence[i];if ev.Tool==goanalysis.ConfigCertificateTool{if fault=="missing-payload"{ev.Content=""}else{ev.ArtifactHash="sha256:"+strings.Repeat("ab",32)}}}
   if _,err=finding.Project(&damaged);err==nil{t.Fatal("forged requested publication admitted")}
   if err=report.Write(t.TempDir(),&damaged);err==nil{t.Fatal("forged report publication admitted")}
   if damaged.Claims[0].NegativeVerification.Status!=domain.NegativeVerified{t.Fatal("publication destroyed verification history")}
  })}
 })}
}

func TestZeroValueAndConfigKeyRemainInsufficient(t *testing.T) {
 f:=captureConfig(t,"configcheckdirectprod",nil)
 for _,kind:=range []string{domain.FalsifierZeroValueConfig,domain.FalsifierSafeConfigKey}{
  build:=domain.EffectiveBuildContext(f.c.Product)
  claim:=domain.Claim{Result:domain.ClaimFalse,Falsifier:kind,NegativeVerification:&domain.NegativeVerification{Status:domain.NegativeVerified,BuildContext:&build}}
  if err:=goanalysis.ValidateVerifiedNegative(goanalysis.ConfigAdmissionForCase(f.c),claim,f.cond);!errors.Is(err,goanalysis.ErrConfigWriterInsufficientScope){t.Fatalf("unsupported historical verification admitted: %v",err)}
 }
}

func TestSafeConfigEffectiveCopyTiming(t *testing.T) {
 cases:=[]struct{name,fixture,old,replacement string}{
  {"overwritten unsafe default","configcheckdirectprod","cfg := Config{RequireAudience:true}","cfg := Config{RequireAudience:false}\n cfg.RequireAudience = true"},
  {"copy snapshots source","configcheckcopyprod","cfg.Skip = enforce","_ = enforce"},
  {"accounted zero default","configcheckcopyprod","defaults := Options{Skip:false}","var defaults Options"},
 }
 for _,tc:=range cases{t.Run(tc.name,func(t *testing.T){f:=captureConfig(t,tc.fixture,func(dir string){replaceConfig(t,dir,tc.old,tc.replacement)});if err:=goanalysis.ValidateConfigWriterEvidence(goanalysis.ConfigAdmissionForCase(f.c),f.cond,f.cert);err!=nil{t.Fatal(err)}})}
}

func TestSafeConfigUnsupportedEnvelope(t *testing.T) {
 changes:=map[string]func(string){
  "explicit standard import":func(dir string){replaceConfig(t,dir,"package main","package main\nimport _ \"os\"")},
  "build directive":func(dir string){replaceConfig(t,dir,"package main","//go:build !excluded\n\npackage main")},
  "source coordinate directive":func(dir string){replaceConfig(t,dir,"package main","//line forged.go:40\npackage main")},
  "generic declaration":func(dir string){replaceConfig(t,dir,"type Options struct", "type Box[T any] struct { Value T }\ntype Options struct")},
  "method expression":func(dir string){replaceConfig(t,dir,"context.VerifyIssuer(cfg.Skip,\"service\")","check.Context.VerifyIssuer(context,cfg.Skip,\"service\")")},
  "interface dispatch":func(dir string){replaceConfig(t,dir,"context.VerifyIssuer(cfg.Skip,\"service\")","var receiver interface{ VerifyIssuer(bool,string) bool } = context\n receiver.VerifyIssuer(cfg.Skip,\"service\")")},
  "deferred consume":func(dir string){replaceConfig(t,dir,"context.VerifyIssuer(cfg.Skip,\"service\")","defer context.VerifyIssuer(cfg.Skip,\"service\")")},
  "closure consume":func(dir string){replaceConfig(t,dir,"context.VerifyIssuer(cfg.Skip,\"service\")","invoke := func(){ context.VerifyIssuer(cfg.Skip,\"service\") }\n invoke()")},
  "object parameter":func(dir string){replaceConfig(t,dir,"func main() {","func main(){ run(Options{}) }\nfunc run(cfg Options) {");replaceConfig(t,dir,"cfg := defaults","cfg = defaults")},
 }
 for name,change:=range changes{t.Run(name,func(t *testing.T){f:=prepareConfig(t,"configcheckcopyprod",change);if _,err:=f.ix.CaptureConfigWriterCertificate(context.Background(),f.c,f.cond);!errors.Is(err,goanalysis.ErrConfigWriterInsufficientScope){t.Fatalf("unsupported envelope closed: %v",err)}})}
 t.Run("unanchored replacement",func(t *testing.T){
  outside:=filepath.Join(t.TempDir(),"external")
  source,err:=filepath.Abs(filepath.Join("..","..","testdata","configcheckcopyprod","dep"));if err!=nil{t.Fatal(err)};if err=os.CopyFS(outside,os.DirFS(source));err!=nil{t.Fatal(err)}
  root,err:=filepath.Abs(filepath.Join("..","..","testdata","configcheckcopyprod"));if err!=nil{t.Fatal(err)}
  dir:=filepath.Join(t.TempDir(),"product");if err=os.CopyFS(dir,os.DirFS(root));err!=nil{t.Fatal(err)}
  file:=filepath.Join(dir,"go.mod");raw,err:=os.ReadFile(file);if err!=nil{t.Fatal(err)};raw=[]byte(strings.ReplaceAll(string(raw),"=> ./dep","=> "+outside));if err=os.WriteFile(file,raw,0600);err!=nil{t.Fatal(err)}
  if _,err=(repository.Service{}).Snapshot(context.Background(),dir,repository.SnapshotOptions{GOOS:runtime.GOOS,GOARCH:runtime.GOARCH,ExternalCommitSHA:"unanchored"});err==nil || !strings.Contains(err.Error(),"escapes the snapshot root"){t.Fatalf("unanchored source passed acquisition: %v",err)}
 })
}

func TestSafeConfigInventoryAndPayloadForgery(t *testing.T) {
 f:=captureConfig(t,"configcheckcopyprod",nil)
 for _,name:=range []string{"truncated","failed","digest","tests","missing","repinned-source","positive-witness","missing-cert","cert-digest"}{t.Run(name,func(t *testing.T){
  raw,_:=json.Marshal(f.c);var c domain.AnalysisCase;if err:=json.Unmarshal(raw,&c);err!=nil{t.Fatal(err)}
  cert:=f.cert
  for i:=range c.EvidenceGraph.Evidence{e:=&c.EvidenceGraph.Evidence[i];if e.ID!=cert.InventoryEvidenceID{continue};switch name{case "truncated":e.Content=e.Content[:len(e.Content)/2];case "failed":e.PackageList.Completed=false;case "digest":e.PackageList.RawSHA256=strings.Repeat("ab",32);case "tests":e.PackageList.WithTests=true;case "missing":e.ID="other"}}
  switch name{
  case "repinned-source":copyRaw,_:=json.Marshal(cert);if err:=json.Unmarshal(copyRaw,&cert);err!=nil{t.Fatal(err)};cert.Packages[0].Files[0].Bytes=append(cert.Packages[0].Files[0].Bytes,' ')
  case "positive-witness":
   spec:=c.Exploit.DefectSemantics.Trigger
   invocation:=cert.Uses[0].Consumer;invocation.Function="main"
   c.EvidenceGraph.AddEvidence(domain.Evidence{Kind:domain.EvidenceDataFlow,Quality:domain.QualityDeterministic,CheckTrigger:&domain.CheckTriggerWitness{ConditionID:f.cond.ID,Operation:spec.Operation,Invocation:invocation,Receiver:"context",ReceiverType:"Context",ArgumentName:spec.Argument.Name,ArgumentIndex:spec.Argument.Index,ArgumentValue:spec.Argument.Value,ReceiverField:spec.Payload.ReceiverField,PayloadShapes:spec.Payload.Shapes,ControlOrigin:domain.OriginExternalUntrusted,ControlEvidenceIDs:[]domain.EvidenceID{"control"}}})
   c.EvidenceGraph.AddEvidence(domain.Evidence{ID:"control",Kind:domain.EvidenceDataFlow,Quality:domain.QualityDeterministic})
   if match,_:=domain.MatchCheckTriggerWitness(*spec,f.cond.ID,c.EvidenceGraph.EvidenceList(),domain.CheckTriggerObligationFull);match==nil{t.Fatal("test did not establish conflicting positive witness")}
  }
  if name=="missing-cert" || name=="cert-digest"{for i:=range c.EvidenceGraph.Evidence{e:=&c.EvidenceGraph.Evidence[i];if e.Tool==goanalysis.ConfigCertificateTool{if name=="missing-cert"{e.Content=""}else{e.ArtifactHash="forged"}}};claim:=(evaluator.CheckTrigger{}).Evaluate(f.cond,&c);if claim.Result!=domain.ClaimUnknown{t.Fatalf("forged certificate candidate: %+v",claim)};return}
  if err:=goanalysis.ValidateConfigWriterEvidence(goanalysis.ConfigAdmissionForCase(&c),f.cond,cert);!errors.Is(err,goanalysis.ErrConfigWriterInsufficientScope){t.Fatalf("forged input admitted: %v",err)}
 })}
}

func TestSafeConfigDependencyConsumers(t *testing.T) {
	for _,unsafe:=range []bool{false,true} {
		f:=captureConfig(t,"configcheckcopyprod",func(dir string){
			file:=filepath.Join(dir,"dep","check","check.go")
			raw,err:=os.ReadFile(file);if err!=nil{t.Fatal(err)}
			literal:="false";if unsafe{literal="true"}
			raw=append(raw,[]byte("\ntype Settings struct { Skip bool }\nfunc InternalConsumer() { cfg := Settings{Skip:"+literal+"}; ctx := Context{}; ctx.VerifyIssuer(cfg.Skip,\"internal\") }\n")...)
			if err=os.WriteFile(file,raw,0600);err!=nil{t.Fatal(err)}
		})
		if len(f.cert.Uses)!=3{t.Fatalf("dependency caller missing from selector census: %+v",f.cert.Uses)}
		err:=goanalysis.ValidateConfigWriterEvidence(goanalysis.ConfigAdmissionForCase(f.c),f.cond,f.cert)
		if unsafe{if !errors.Is(err,goanalysis.ErrConfigWriterContradicted){t.Fatalf("unsafe dependency caller ignored: %v",err)}}else if err!=nil{t.Fatal(err)}
		for i,use:=range f.cert.Uses{if use.Consumer.Package=="example.com/configissuer/check"{f.cert.Uses=append(f.cert.Uses[:i:i],f.cert.Uses[i+1:]...);break}}
		if err=goanalysis.ValidateConfigWriterEvidence(goanalysis.ConfigAdmissionForCase(f.c),f.cond,f.cert);!errors.Is(err,goanalysis.ErrConfigWriterInsufficientScope){t.Fatalf("omitted dependency consumer accepted: %v",err)}
	}
}

func TestSafeConfigRepinnedPackageOwnership(t *testing.T) {
	f:=captureConfig(t,"configcheckcopyprod",nil)
	in:=goanalysis.ConfigAdmissionForCase(f.c)
	for i:=range in.Evidence {
		e:=&in.Evidence[i];if e.ID!=f.cert.InventoryEvidenceID{continue}
		inventory,err:=affected.CompletePackageInventory([]byte(e.Content),"go list");if err!=nil{t.Fatal(err)}
		for j:=range inventory.Packages{p:=&inventory.Packages[j];if !p.Standard && p.Module!=nil && p.ImportPath=="example.com/configissuer/check"{p.Module.Path="example.com/forged-owner"}}
		var stream []byte
		for _,p:=range inventory.Packages{raw,err:=json.Marshal(p);if err!=nil{t.Fatal(err)};stream=append(stream,raw...);stream=append(stream,'\n')}
		measurement:=affected.RecordPackageInventory(stream,nil,in.Product,false)
		if _,err=measurement.Admit(in.Product);err!=nil{t.Fatalf("test must retain a canonical complete repinned stream: %v",err)}
		e.Content=measurement.RawStream;e.PackageList=&measurement.Run;e.ArtifactHash=measurement.RawReference
		f.cert.InventoryReference=measurement.RawReference
	}
	if err:=goanalysis.ValidateConfigWriterEvidence(in,f.cond,f.cert);!errors.Is(err,goanalysis.ErrConfigWriterInsufficientScope) || !strings.Contains(err.Error(),"module ownership"){t.Fatalf("repinned forged package ownership admitted: %v",err)}
}

func TestSafeConfigVendorSnapshot(t *testing.T) {
	f:=captureConfig(t,"configcheckcopyprod",func(dir string){
		vendor:=filepath.Join(dir,"vendor","example.com","configissuer")
		if err:=os.CopyFS(vendor,os.DirFS(filepath.Join(dir,"dep")));err!=nil{t.Fatal(err)}
		if err:=os.RemoveAll(filepath.Join(dir,"dep"));err!=nil{t.Fatal(err)}
		if err:=os.WriteFile(filepath.Join(dir,"go.mod"),[]byte("module example.com/configcheckcopy\n\ngo 1.25.0\n\nrequire example.com/configissuer v0.0.0\n"),0600);err!=nil{t.Fatal(err)}
		if err:=os.WriteFile(filepath.Join(dir,"vendor","modules.txt"),[]byte("# example.com/configissuer v0.0.0\n## explicit; go 1.25.0\nexample.com/configissuer/check\n"),0600);err!=nil{t.Fatal(err)}
	})
	if !f.c.Product.VendorMode{t.Fatal("smoke did not select vendor mode")}
	if err:=os.Rename(f.dir,f.dir+"-unavailable");err!=nil{t.Fatal(err)}
	if err:=goanalysis.ValidateConfigWriterEvidence(goanalysis.ConfigAdmissionForCase(f.c),f.cond,f.cert);err!=nil{t.Fatalf("anchored vendor source cannot replay: %v",err)}
}

func TestForgedCompleteConfigLiveRefuses(t *testing.T) {
	f:=captureConfig(t,"configcheckdirectprod",nil)
	claim:=(evaluator.CheckTrigger{}).Evaluate(f.cond,f.c)
	for i:=range f.c.EvidenceGraph.Evidence{e:=&f.c.EvidenceGraph.Evidence[i];if e.Tool==goanalysis.ConfigCertificateTool{e.Content=""}}
	claim=(goanalysis.Verifier{Source:f.ix}).VerifyFalse(context.Background(),f.c,claim,f.cond)
	if claim.Result!=domain.ClaimUnknown || claim.NegativeVerification==nil || claim.NegativeVerification.Status!=domain.NegativeInsufficientScope || len(claim.NegativeVerification.AnalysisGaps)==0{t.Fatalf("missing live payload did not remain unresolved: %+v",claim)}
}

func TestSafeConfigRepinnedSelectedFiles(t *testing.T) {
	f:=captureConfig(t,"configcheckdirectprod",nil)
	claim:=(evaluator.CheckTrigger{}).Evaluate(f.cond,f.c)
	claim=(goanalysis.Verifier{Source:f.ix}).VerifyFalse(context.Background(),f.c,claim,f.cond)
	if claim.NegativeVerification==nil || claim.NegativeVerification.Status!=domain.NegativeVerified{t.Fatalf("control lacks actual verified proof: %+v",claim)}
	caseBytes,err:=json.Marshal(f.c);if err!=nil{t.Fatal(err)}
	certBytes,err:=json.Marshal(f.cert);if err!=nil{t.Fatal(err)}
	if err=os.Rename(f.dir,f.dir+"-unavailable");err!=nil{t.Fatal(err)}
	for _,fault:=range []string{"valid","impossible-selected-name","duplicate-inventory-name"}{t.Run(fault,func(t *testing.T){
		var c domain.AnalysisCase;if err:=json.Unmarshal(caseBytes,&c);err!=nil{t.Fatal(err)}
		var cert domain.ConfigWriterCertificate;if err:=json.Unmarshal(certBytes,&cert);err!=nil{t.Fatal(err)}
		for i:=range c.EvidenceGraph.Evidence {
			e:=&c.EvidenceGraph.Evidence[i];if e.ID!=cert.InventoryEvidenceID{continue}
			inventory,err:=affected.CompletePackageInventory([]byte(e.Content),"go list");if err!=nil{t.Fatal(err)}
			changed:=false
			for j:=range inventory.Packages {
				p:=&inventory.Packages[j];if p.ImportPath!=cert.Packages[0].ImportPath{continue}
				if len(p.GoFiles)!=1 || p.GoFiles[0]!="main.go"{t.Fatalf("unexpected fixture selected files: %+v",p.GoFiles)}
				switch fault {
				case "impossible-selected-name":p.GoFiles=[]string{"absent.go"};cert.Packages[0].SelectedGoFiles=[]string{"absent.go"}
				case "duplicate-inventory-name":p.GoFiles=append(p.GoFiles,p.GoFiles[0])
				}
				changed=true
			}
			if !changed{t.Fatal("fixture package missing from inventory")}
			var stream []byte
			for _,p:=range inventory.Packages{raw,err:=json.Marshal(p);if err!=nil{t.Fatal(err)};stream=append(stream,raw...);stream=append(stream,'\n')}
			measurement:=affected.RecordPackageInventory(stream,nil,c.Product,false)
			if _,err=measurement.Admit(c.Product);err!=nil{t.Fatalf("control must retain a canonical repinned package graph: %v",err)}
			e.Content=measurement.RawStream;e.PackageList=&measurement.Run;e.ArtifactHash=measurement.RawReference
			cert.InventoryReference=measurement.RawReference
		}
		if c.Product.ContentHash!=f.c.Product.ContentHash || string(cert.SnapshotManifest)!=string(f.cert.SnapshotManifest){t.Fatal("attack changed independent source anchor")}
		for i:=range cert.Packages[0].Files{if string(cert.Packages[0].Files[i].Bytes)!=string(f.cert.Packages[0].Files[i].Bytes){t.Fatal("attack changed captured file bytes")}}
		for i:=range c.EvidenceGraph.Evidence {
			e:=&c.EvidenceGraph.Evidence[i];if e.Tool!=goanalysis.ConfigCertificateTool{continue}
			repinned,err:=goanalysis.ConfigCertificateEvidence(cert);if err!=nil{t.Fatal(err)};repinned.ID=e.ID;*e=repinned
		}
		in:=goanalysis.ConfigAdmissionForCase(&c)
		proofErr:=goanalysis.ValidateConfigWriterEvidence(in,f.cond,cert)
		publicationErr:=goanalysis.ValidateVerifiedNegative(in,claim,f.cond)
		if fault=="valid"{if proofErr!=nil || publicationErr!=nil{t.Fatalf("valid source-free repin refused: proof=%v publication=%v",proofErr,publicationErr)};return}
		if !errors.Is(proofErr,goanalysis.ErrConfigWriterInsufficientScope) || !errors.Is(publicationErr,goanalysis.ErrConfigWriterInsufficientScope){t.Fatalf("repinned filename forgery admitted: proof=%v publication=%v",proofErr,publicationErr)}
		want:="absent from anchored directory";if fault=="duplicate-inventory-name"{want="duplicate inventory selected source filename"}
		if !strings.Contains(proofErr.Error(),want) || !strings.Contains(publicationErr.Error(),want){t.Fatalf("wrong refusal obligation: proof=%v publication=%v",proofErr,publicationErr)}
	})}
}

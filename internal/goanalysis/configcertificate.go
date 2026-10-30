package goanalysis

import (
 "bytes"
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "go/ast"
 "go/constant"
 "go/parser"
 "go/token"
 "go/types"
 "go/version"
 "os"
 "path"
 "path/filepath"
 "reflect"
 "sort"
 "strconv"
 "strings"
 "golang.org/x/mod/modfile"

 "github.com/fedorovmv/izyan/internal/affected"
 "github.com/fedorovmv/izyan/internal/domain"
 "github.com/fedorovmv/izyan/internal/repository"
 "github.com/fedorovmv/izyan/internal/vulnerability"
)

var ErrConfigWriterInsufficientScope = errors.New("configuration writer scope insufficient")
var ErrConfigWriterContradicted = errors.New("configuration writer contradicted")

const ConfigCertificateTool = "goanalysis.Index.CaptureConfigWriterCertificate"

func configScope(format string, args ...any) error {
 return fmt.Errorf("%w: %s", ErrConfigWriterInsufficientScope, fmt.Sprintf(format,args...))
}

func configDigest(raw []byte) string { sum:=sha256.Sum256(raw); return "sha256:"+hex.EncodeToString(sum[:]) }

func ConfigAdmissionForCase(c *domain.AnalysisCase) NegativeAdmissionInput {
 if c==nil { return NegativeAdmissionInput{} }
 return NegativeAdmissionInput{Product:c.Product,Vulnerability:c.Vulnerability,RecordPin:c.RecordPin,AdvisoryRecord:c.AdvisoryRecord,Model:c.Exploit,Evidence:c.EvidenceGraph.EvidenceList()}
}

// ConfigCertificateEvidence retains the full payload; previews are never proof inputs.
func ConfigCertificateEvidence(cert domain.ConfigWriterCertificate) (domain.Evidence,error) {
 raw,err:=json.Marshal(cert); if err!=nil { return domain.Evidence{},err }
 return domain.Evidence{Kind:domain.EvidenceConfiguration,Quality:domain.QualityDeterministic,Source:"snapshot-anchored effective configuration",Tool:ConfigCertificateTool,Content:string(raw),ArtifactHash:configDigest(raw),BuildContext:&cert.Build},nil
}

func configRecord(in NegativeAdmissionInput,cond domain.Condition,cert domain.ConfigWriterCertificate) (*domain.DefectSemanticsContract,error) {
 if in.Model==nil || in.RecordPin==nil || in.AdvisoryRecord==nil { return nil,configScope("missing model, current record pin or advisory capture") }
 if err:=in.AdvisoryRecord.Validate(); err!=nil { return nil,configScope("%v",err) }
 if !cert.Record.Same(*in.RecordPin) || !in.AdvisoryRecord.Pin.Same(*in.RecordPin) { return nil,configScope("certificate/advisory/current record pins differ") }
 frozen,err:=vulnerability.LoadExactBytes(in.AdvisoryRecord.Bytes,in.RecordPin.RecordID,in.RecordPin.SourceLocator)
 if err!=nil { return nil,configScope("captured advisory: %v",err) }
 if !frozen.Pin.Same(*in.RecordPin) || frozen.Vuln.ID!=in.Vulnerability.ID || domain.CheckMechanismText(*frozen.Vuln)!=domain.CheckMechanismText(in.Vulnerability) || !reflect.DeepEqual(frozen.Vuln.AffectedSymbols,in.Vulnerability.AffectedSymbols) { return nil,configScope("assessment vulnerability differs from exact advisory") }
 if err:=domain.ValidateDefectSemanticsModel(*in.Model,in.Evidence); err!=nil { return nil,configScope("defect semantics: %v",err) }
 contract:=in.Model.DefectSemantics
 if contract==nil || contract.Mode!=domain.DefectSemanticsDefectiveCheck || contract.Trigger==nil || cond.Kind!=domain.ConditionCheckTrigger || !cond.Mandatory || !domain.CheckConditionMatchesContract(contract,cond) { return nil,configScope("not an admitted mandatory CHECK_TRIGGER") }
 mandatory:=false
 for _,c:=range in.Model.MandatoryConditions { if reflect.DeepEqual(c,cond) { mandatory=true } }
 if !mandatory || contract.RecordID!=in.RecordPin.RecordID || contract.RecordDigest!=in.RecordPin.DocumentDigest { return nil,configScope("condition/contract does not belong to current mandatory record") }
 refs,err:=exactLocusConditionSubjects(cond)
 if err!=nil || len(refs)!=1 || refs[0]!=contract.Trigger.Operation || !reflect.DeepEqual(cert.Subjects,refs) { return nil,configScope("exact condition subjects differ from operation") }
 declared:=domain.RecordDeclaresSubject(*frozen.Vuln,refs[0])
 for _,binding:=range in.Model.OperationBindings { if b,e:=domain.AdmitOperationBinding(binding,*frozen.Vuln,in.RecordPin); e==nil && b.Subject()==refs[0] { declared=true } }
 if !declared { return nil,configScope("operation is not declared by own record") }
 text:=domain.CheckMechanismText(*frozen.Vuln)
 statements:=domain.ParseCheckMechanism(text,refs[0])
 if !statements.Invocation || statements.Omission || statements.ConflictingInvocation || statements.ConflictingPayload { return nil,configScope("advisory does not establish an unambiguous invocation predicate") }
 grounded:=false
 for _,g:=range contract.Grounds { if g.Claim!=domain.SemanticsGroundAdvisoryInvocation || g.Quote!=statements.Quote || g.EvidenceDigest!=domain.EvidenceContentDigest(text) { continue }; for _,e:=range in.Evidence { if e.ID==g.EvidenceID && e.Kind==domain.EvidenceAdvisory && e.Kind==g.EvidenceKind && e.Quality==domain.QualityAuthoritative && e.Content==text { grounded=true } } }
 if !grounded { return nil,configScope("invocation ground differs from captured own-record mechanism") }
 if match,_:=domain.MatchCheckTriggerWitness(*contract.Trigger,contract.TriggerConditionID,in.Evidence,domain.CheckTriggerObligationFull); match!=nil { return nil,configScope("admitted positive trigger witness conflicts with negative") }
 return contract,nil
}

func configInventory(in NegativeAdmissionInput,cert domain.ConfigWriterCertificate) (affected.PackageInventory,error) {
 var found *domain.Evidence
 for i:=range in.Evidence { e:=&in.Evidence[i]; if e.ID==cert.InventoryEvidenceID { if found!=nil { return affected.PackageInventory{},configScope("duplicate inventory identity") }; found=e } }
 if found==nil || found.Kind!=domain.EvidencePackageList || found.PackageList==nil || found.BuildContext==nil || found.PackageList.WithTests { return affected.PackageInventory{},configScope("missing non-test inventory payload") }
 if _,err:=domain.SelectCompletePackageList(in.Product,[]domain.Evidence{*found}); err!=nil { return affected.PackageInventory{},configScope("inventory: %v",err) }
 if found.PackageList.RawSHA256=="" || configDigest([]byte(found.Content))!=cert.InventoryReference || cert.InventoryReference!="sha256:"+found.PackageList.RawSHA256 { return affected.PackageInventory{},configScope("inventory digest/reference mismatch") }
 inv,err:=affected.CompletePackageInventory([]byte(found.Content),"go list -deps -json ./...")
 if err!=nil { return inv,configScope("inventory: %v",err) }
 return inv,nil
}

type configTypedPackage struct { syntax []*ast.File; info *types.Info; pkg *types.Package; loading bool; goVersion string }
type configReplay struct { in NegativeAdmissionInput; cert domain.ConfigWriterCertificate; fset *token.FileSet; packages map[string]*configTypedPackage; operation *types.Func; contract *domain.DefectSemanticsContract; uses []domain.ConfigUseSelector; unsafe []string }

func configRelative(root,filename string) (string,error) {
 if !filepath.IsAbs(root) || !filepath.IsAbs(filename) { return "",configScope("source paths must retain absolute snapshot coordinates") }
 rel,err:=filepath.Rel(root,filename)
 if err!=nil || rel==".." || strings.HasPrefix(rel,".."+string(filepath.Separator)) { return "",configScope("source is outside anchored snapshot: %s",filename) }
 return filepath.ToSlash(rel),nil
}

func configModuleFile(manifest map[string]repository.ContentManifestEntry,dir string) string {
 for {name:=path.Join(dir,"go.mod");if manifest[name].Kind=="file"{return name};if dir=="."{return ""};dir=path.Dir(dir)}
}

func (r *configReplay) loadSources(inv affected.PackageInventory) error {
 entries,err:=repository.ValidateContentManifest(r.cert.SnapshotManifest,r.in.Product.ContentHash)
 if err!=nil { return configScope("snapshot manifest: %v",err) }
 manifest:=map[string]repository.ContentManifestEntry{}
 for _,e:=range entries { manifest[e.Path]=e }
 captured:=map[string]domain.ConfigCapturedPackage{}
 for _,p:=range r.cert.Packages { if p.ImportPath=="" { return configScope("empty captured package") }; if _,ok:=captured[p.ImportPath];ok { return configScope("duplicate captured package") }; captured[p.ImportPath]=p }
 var rootModule *modfile.File
 for _,cp:=range r.cert.Packages {for _,file:=range cp.Files {if file.Path!="go.mod"{continue};entry:=manifest[file.Path];if entry.Kind!="file" || int64(len(file.Bytes))!=entry.Size || strings.TrimPrefix(configDigest(file.Bytes),"sha256:")!=entry.Payload{return configScope("root module bytes disagree with snapshot")};parsed,err:=modfile.Parse(file.Path,file.Bytes,nil);if err!=nil || parsed.Module==nil{return configScope("root module declaration unavailable")};rootModule=parsed}}
 if rootModule==nil{return configScope("captured root module declaration missing")}
 if rootModule.Go==nil || rootModule.Go.Version!=r.in.Product.GoModDirective{return configScope("recorded root language directive differs from captured module")}
 directories:=map[string]bool{}
 application:=false
 for _,p:=range inv.Packages {
  if p.Standard {if strings.Contains(strings.Split(p.ImportPath,"/")[0],"."){return configScope("nonstandard import mislabeled as language runtime")};if _,err:=configRelative(r.in.Product.Repository,p.Dir);err==nil{return configScope("snapshot source mislabeled as language runtime")};continue}
  cp,ok:=captured[p.ImportPath]; if !ok { return configScope("nonstandard inventory package not captured: %s",p.ImportPath) }; delete(captured,p.ImportPath)
  dir,err:=configRelative(r.in.Product.Repository,p.Dir); if err!=nil { return err }
  if directories[dir] || filepath.Clean(p.Dir)!=p.Dir {return configScope("ambiguous package directory ownership")};directories[dir]=true
  for ancestor:=dir;ancestor!=".";ancestor=path.Dir(ancestor){if manifest[ancestor].Kind!="dir"{return configScope("selected source ancestor is not an anchored directory")}}
  if p.Name=="main" && !p.DepOnly{application=true}
  if !p.DepOnly && p.Name!="main"{return configScope("external library package root remains outside the closed application caller surface")}
  if cp.Directory!=dir || len(p.CgoFiles)+len(p.SFiles)+len(p.SysoFiles)>0 || len(p.IgnoredGoFiles)>0 { return configScope("unsupported source ownership, native code or build variant: %s",p.ImportPath) }
  if len(p.GoFiles)==0 { return configScope("empty selected source set") }
  expected:=map[string]bool{}
  for _,name:=range p.GoFiles {
   if path.Base(name)!=name || !strings.HasSuffix(name,".go") || strings.HasSuffix(name,"_test.go") { return configScope("ambiguous selected source path") }
   filename:=path.Join(dir,name)
   if expected[filename] { return configScope("duplicate inventory selected source filename: %s",filename) }
   expected[filename]=true
  }
  if len(p.CompiledGoFiles)>0 { return configScope("unsupported compiled source substitution") }
  if len(cp.SelectedGoFiles)!=len(expected) { return configScope("selected file count mismatch") }
  seen:=map[string]bool{}
  for _,name:=range cp.SelectedGoFiles { if !expected[name] || seen[name] { return configScope("selected file membership mismatch") };seen[name]=true }
  directoryFiles:=map[string]bool{}
  for name,e:=range manifest { if path.Dir(name)==dir && strings.HasSuffix(name,".go") && !strings.HasSuffix(name,"_test.go") { if e.Kind!="file" { return configScope("symlink source is unsupported") }; directoryFiles[name]=true } }
  if len(directoryFiles)!=len(expected){return configScope("missing source or unsupported alternative source")}
  for filename:=range expected { if !directoryFiles[filename] { return configScope("selected source filename is absent from anchored directory: %s",filename) } }
  moduleFile:=configModuleFile(manifest,dir)
  vendor:=strings.HasPrefix(dir,"vendor/")
  if vendor {if strings.TrimPrefix(dir,"vendor/")!=p.ImportPath || !r.in.Product.VendorMode{return configScope("vendored directory does not identify the import path")};moduleFile=""} else if moduleFile=="" {return configScope("package has no anchored module ownership")}
  if moduleFile!=""{directoryFiles[moduleFile]=true}
  if len(cp.Files)!=len(directoryFiles){return configScope("missing captured source/module file")}
  tp:=&configTypedPackage{info:&types.Info{Defs:map[*ast.Ident]types.Object{},Uses:map[*ast.Ident]types.Object{},Selections:map[*ast.SelectorExpr]*types.Selection{},Types:map[ast.Expr]types.TypeAndValue{}}}
  tp.goVersion="go"+rootModule.Go.Version
  for _,file:=range cp.Files {
   e,ok:=manifest[file.Path]; if !ok || !directoryFiles[file.Path] || e.Kind!="file" || int64(len(file.Bytes))!=e.Size || strings.TrimPrefix(configDigest(file.Bytes),"sha256:")!=e.Payload { return configScope("source bytes disagree with snapshot manifest: %s",file.Path) };delete(directoryFiles,file.Path)
   if file.Path==moduleFile {
    module,err:=modfile.Parse(moduleFile,file.Bytes,nil)
    if err!=nil || module.Module==nil{return configScope("captured module declaration is invalid")}
    if module.Go==nil{return configScope("captured module language version missing")};tp.goVersion="go"+module.Go.Version
    modulePath:=module.Module.Mod.Path
    suffix:=strings.TrimPrefix(strings.TrimPrefix(dir,path.Dir(moduleFile)),"/")
    if path.Dir(moduleFile)=="."{suffix=dir};if suffix=="."{suffix=""}
    want:=modulePath;if suffix!=""{want+="/"+suffix}
    if p.ImportPath!=want || p.Module==nil || p.Module.Path!=modulePath{return configScope("package import path disagrees with anchored module ownership")}
    if moduleFile!="go.mod" {
     selected:=false
     for _,replacement:=range rootModule.Replace {
      if replacement.Old.Path!=modulePath || (replacement.Old.Version!="" && replacement.Old.Version!=p.Module.Version){continue}
      if replacement.New.Version!=""{return configScope("versioned external replacement is outside anchored source")}
      destination:=filepath.Join(r.in.Product.Repository,filepath.FromSlash(replacement.New.Path))
      if filepath.IsAbs(replacement.New.Path){destination=replacement.New.Path}
      target,err:=configRelative(r.in.Product.Repository,destination);if err!=nil{return err}
      if target!=path.Dir(moduleFile){return configScope("module ownership differs from root local replacement")};selected=true
     }
     if !selected{return configScope("nested source module is not the selected anchored local replacement")}
    } else if modulePath!=rootModule.Module.Mod.Path{return configScope("root module ownership mismatch")}
    continue
   }
   if bytes.Contains(file.Bytes,[]byte("//go:")) || bytes.Contains(file.Bytes,[]byte("// +build")) || bytes.Contains(file.Bytes,[]byte("//line ")) || bytes.Contains(file.Bytes,[]byte("/*line ")) { return configScope("compiler/build/source-coordinate directive unsupported") }
   name:=path.Base(file.Path); if strings.Contains(strings.TrimSuffix(name,".go"),"_") { return configScope("platform/variant source filename unsupported") }
   original:=filepath.Join(p.Dir,name)
   f,err:=parser.ParseFile(r.fset,original,file.Bytes,parser.ParseComments); if err!=nil { return configScope("captured parse: %v",err) }
   if f.Name.Name!=p.Name { return configScope("captured package name mismatch") }
   generic:=false
   ast.Inspect(f,func(n ast.Node)bool{switch x:=n.(type){case *ast.TypeSpec:generic=generic || x.TypeParams!=nil;case *ast.FuncType:generic=generic || x.TypeParams!=nil};return true})
   if generic{return configScope("generic declaration identities are outside the bounded scalar grammar")}
   for _,spec:=range f.Imports { imported,_:=strconv.Unquote(spec.Path.Value);for _,q:=range inv.Packages {if q.ImportPath==imported && q.Standard{return configScope("explicit standard-library import unsupported: %s",imported)}};if imported=="C" || imported=="unsafe" {return configScope("native/unsafe import unsupported")};found:=false;for _,edge:=range p.Imports{if edge==imported{found=true}};if !found{return configScope("source import differs from canonical inventory")} }
   for _,decl:=range f.Decls { if fn,ok:=decl.(*ast.FuncDecl);ok && fn.Body==nil { return configScope("bodyless function unsupported") } }
   tp.syntax=append(tp.syntax,f)
  }
  r.packages[p.ImportPath]=tp
 }
 for name,e:=range manifest {if strings.HasSuffix(name,".go") && !strings.HasSuffix(name,"_test.go") && (e.Kind!="file" || !directories[path.Dir(name)]) {return configScope("snapshot Go source directory omitted from captured caller census: %s",name)}}
 if !application{return configScope("external library caller surface is not closed")}
 if len(captured)!=0 || len(r.packages)==0 { return configScope("surplus or empty captured packages") }
 return nil
}

func (r *configReplay) Import(importPath string) (*types.Package,error) {
 p:=r.packages[importPath]; if p==nil { return nil,configScope("import has no anchored source: %s",importPath) }; if p.pkg!=nil { return p.pkg,nil }; if p.loading { return nil,configScope("cyclic captured imports") };p.loading=true
 toolVersion:=r.in.Product.GoVersion
 for _,part:=range strings.Fields(toolVersion){if strings.HasPrefix(part,"go1."){toolVersion=part;break}}
 if !version.IsValid(toolVersion){return nil,configScope("unsupported recorded toolchain version")}
 if !version.IsValid(p.goVersion) || version.Compare(p.goVersion,toolVersion)>0{return nil,configScope("unsupported captured module language version")}
 sizes:=types.SizesFor("gc",r.in.Product.GOARCH);if sizes==nil { return nil,configScope("unsupported target sizing") }
 cfg:=types.Config{Importer:r,Sizes:sizes,GoVersion:p.goVersion}
 pkg,err:=cfg.Check(importPath,r.fset,p.syntax,p.info); if err!=nil { return nil,configScope("captured typecheck %s: %v",importPath,err) };p.pkg=pkg;p.loading=false;return pkg,nil
}

func (r *configReplay) prepare() error {
 if r.cert.Schema!=domain.ConfigWriterCertificateSchema || r.cert.ConditionID=="" || r.cert.ConditionID!=r.contract.TriggerConditionID { return configScope("certificate schema/condition mismatch") }
 if err:=domain.ValidateNegativeTarget(r.in.Product);err!=nil { return configScope("target: %v",err) }
 if err:=r.cert.Build.Matches(domain.EffectiveBuildContext(r.in.Product));err!=nil { return configScope("build: %v",err) }
 if (r.in.Product.GoFlags!="" && r.in.Product.GoFlags!="-mod=mod" && r.in.Product.GoFlags!="-mod=vendor") || (r.in.Product.GoWorkFile!="" && r.in.Product.GoWorkFile!="off") || r.in.Product.CGOEnabled { return configScope("unsupported compiler-affecting build settings") }
 inv,err:=configInventory(r.in,r.cert);if err!=nil { return err };if err=r.loadSources(inv);err!=nil { return err }
 for name:=range r.packages { if _,err=r.Import(name);err!=nil { return err } }
 op:=r.contract.Trigger.Operation
 p:=r.packages[op.Package];if p==nil { return configScope("operation source missing") }
 typeName,method:=splitSymbol(op.Symbol)
 if method=="" { r.operation,_=p.pkg.Scope().Lookup(op.Symbol).(*types.Func) } else if obj,ok:=p.pkg.Scope().Lookup(typeName).(*types.TypeName);ok { named,ok:=types.Unalias(obj.Type()).(*types.Named);if ok { for i:=range named.NumMethods() { fn:=named.Method(i);if fn.Name()==method { r.operation=fn } } } }
 if r.operation==nil { return configScope("operation does not resolve in captured source") }
 sig:=r.operation.Type().(*types.Signature)
 names:=make([]string,sig.Params().Len());for i:=range names { names[i]=sig.Params().At(i).Name() }
 arg,err:=domain.BindCheckArgumentPredicate(domain.ParseCheckMechanism(domain.CheckMechanismText(r.in.Vulnerability),op),names)
 if err!=nil || arg!=r.contract.Trigger.Argument || arg.Index<0 || arg.Index>=len(names) || (arg.Value!="true" && arg.Value!="false") { return configScope("argument metadata differs from captured advisory/signature") }
 b,ok:=sig.Params().At(arg.Index).Type().Underlying().(*types.Basic);if !ok || b.Kind()!=types.Bool { return configScope("necessary formal is not boolean") }
 return nil
}

func ValidateConfigWriterEvidence(in NegativeAdmissionInput,cond domain.Condition,cert domain.ConfigWriterCertificate) error {
 r,err:=deriveConfigCertificate(in,cond,cert);if err!=nil { return err }
 if !reflect.DeepEqual(cert.Uses,r.uses) { return configScope("selectors do not equal the complete reconstructed consumer set") }
 if len(r.unsafe)>0 { return fmt.Errorf("%w: %s",ErrConfigWriterContradicted,strings.Join(r.unsafe,"; ")) }
 return nil
}

func deriveConfigCertificate(in NegativeAdmissionInput,cond domain.Condition,cert domain.ConfigWriterCertificate) (*configReplay,error) {
 contract,err:=configRecord(in,cond,cert);if err!=nil { return nil,err }
 r:=&configReplay{in:in,cert:cert,contract:contract,fset:token.NewFileSet(),packages:map[string]*configTypedPackage{}}
 if err=r.prepare();err!=nil { return nil,err }
 if err=r.consumers();err!=nil { return nil,err }
 sort.Slice(r.uses,func(i,j int)bool { a,b:=r.uses[i].Consumer,r.uses[j].Consumer;if a.File!=b.File{return a.File<b.File};if a.Line!=b.Line{return a.Line<b.Line};return a.Column<b.Column })
 if len(r.uses)==0 { return nil,configScope("no relevant invocation; use independent deadness proof") }
 return r,nil
}

type configValue struct { value bool; known bool; declaration domain.CallSite; id string }

func unparenConfig(e ast.Expr) ast.Expr { for { p,ok:=e.(*ast.ParenExpr);if !ok{return e};e=p.X } }

func (r *configReplay) site(pkg string,n ast.Node) domain.CallSite {
 pos:=r.fset.Position(n.Pos());if c,ok:=n.(*ast.CallExpr);ok { pos=r.fset.Position(c.Lparen) }
 return domain.CallSite{Package:pkg,File:pos.Filename,Line:pos.Line,Column:pos.Column}
}

func configBool(info *types.Info,e ast.Expr) (bool,bool) {
 if e==nil{return false,false};e=unparenConfig(e)
 id,ok:=e.(*ast.Ident);if !ok{return false,false};if _,ok:=info.ObjectOf(id).(*types.Const);!ok{return false,false}
 v:=info.Types[e].Value;if v==nil || v.Kind()!=constant.Bool{return false,false};return constant.BoolVal(v),true
}

func configNamed(t types.Type) *types.Named { n,_:=types.Unalias(t).(*types.Named);return n }

func (r *configReplay) consumers() error {
 op:=r.contract.Trigger.Operation
 for pkg,p:=range r.packages {
  allowed:=map[*ast.Ident]bool{}
  calls:=map[*ast.CallExpr]*ast.FuncDecl{}
  for _,file:=range p.syntax {
   var indirect bool
   ast.Inspect(file,func(n ast.Node)bool{
    call,ok:=n.(*ast.CallExpr);if !ok{return true}
    callee:=calleeExpr(call.Fun)
    if p.info.Types[callee].IsType(){return true}
    obj:=calleeObject(p.info,callee)
    if _,ok:=obj.(*types.Builtin);ok{return true}
    if _,ok:=obj.(*types.Func);!ok{indirect=true}
    if sel,ok:=callee.(*ast.SelectorExpr);ok{if s:=p.info.Selections[sel];s!=nil{if _,ok:=s.Recv().Underlying().(*types.Interface);ok{indirect=true}}}
    return true
   })
   if indirect{return configScope("callback/interface/dynamic dispatch in captured caller envelope")}
   for _,decl:=range file.Decls {
    fn,ok:=decl.(*ast.FuncDecl);if !ok{continue}
    ast.Inspect(fn,func(n ast.Node)bool {
     call,ok:=n.(*ast.CallExpr);if !ok{return true}
     callee:=calleeExpr(call.Fun)
     obj,ok:=calleeObject(p.info,callee).(*types.Func)
     if !ok || obj!=r.operation{return true}
     switch x:=callee.(type) {case *ast.Ident:allowed[x]=true;case *ast.SelectorExpr:allowed[x.Sel]=true;default:return true}
     calls[call]=fn;return true
    })
   }
   var escaped bool
   ast.Inspect(file,func(n ast.Node)bool { if id,ok:=n.(*ast.Ident);ok && p.info.Uses[id]==r.operation && !allowed[id] {escaped=true};return true })
   if escaped{return configScope("operation has a non-call/function-value reference: %s",pkg)}
  }
  for call,fn:=range calls {
   if sel,ok:=calleeExpr(call.Fun).(*ast.SelectorExpr);ok { if selection:=p.info.Selections[sel];selection!=nil && selection.Kind()!=types.MethodVal {return configScope("method expression is unsupported")} }
   argIndex:=r.contract.Trigger.Argument.Index
   if call.Ellipsis.IsValid() || argIndex>=len(call.Args){return configScope("unsupported operation argument binding")}
   sel,ok:=unparenConfig(call.Args[argIndex]).(*ast.SelectorExpr);if !ok{return configScope("necessary argument is not an exact local object field")}
   selection:=p.info.Selections[sel];if selection==nil || selection.Kind()!=types.FieldVal || len(selection.Index())!=1{return configScope("unsupported promoted/foreign field")}
   field,ok:=selection.Obj().(*types.Var);if !ok || field.Pkg()==nil{return configScope("field identity unavailable")}
   recv:=configNamed(selection.Recv());if recv==nil || recv.Obj().Pkg()==nil{return configScope("pointer/unnamed configuration storage unsupported")}
   basic,ok:=field.Type().Underlying().(*types.Basic);if !ok || basic.Kind()!=types.Bool{return configScope("configuration field is not bool")}
   id,ok:=unparenConfig(sel.X).(*ast.Ident);if !ok{return configScope("configuration receiver is not lexical storage")}
   obj,ok:=p.info.ObjectOf(id).(*types.Var);if !ok || obj.Parent()==p.pkg.Scope(){return configScope("configuration storage is not local")}
   fieldRef:=domain.SymbolRef{Package:recv.Obj().Pkg().Path(),Symbol:recv.Obj().Name()+"."+field.Name()}
   state,err:=r.effective(pkg,p,fn,call,obj,recv,field);if err!=nil{return err}
   consumer:=r.site(pkg,call)
   r.uses=append(r.uses,domain.ConfigUseSelector{ConditionID:r.cert.ConditionID,Field:fieldRef,ObjectID:state.id,ObjectDeclaration:state.declaration,Consumer:consumer,Callee:op,Argument:argIndex})
   if strconv.FormatBool(state.value)==r.contract.Trigger.Argument.Value {r.unsafe=append(r.unsafe,fmt.Sprintf("%s:%d:%d effective value %t enables necessary argument %s",consumer.File,consumer.Line,consumer.Column,state.value,r.contract.Trigger.Argument.Name))}
  }
 }
 return nil
}

func (r *configReplay) effective(pkg string,p *configTypedPackage,fn *ast.FuncDecl,consume *ast.CallExpr,want *types.Var,named *types.Named,field *types.Var) (configValue,error) {
 states:=map[types.Object]configValue{}
 allowed:=map[*ast.Ident]bool{}
 var result configValue
 found:=false
 matching:=func(t types.Type)bool {return types.Identical(t,named)}
 value:=func(e ast.Expr)(bool,bool){return configBool(p.info,e)}
 var init func(types.Object,ast.Expr,*ast.Ident) error
 init=func(obj types.Object,e ast.Expr,id *ast.Ident)error {
  if obj==nil || !matching(obj.Type()){return nil}
  state,exists:=states[obj]
  if !exists {if id==nil || p.info.Defs[id]!=obj{return configScope("storage is not a local declaration (parameter/receiver/foreign writer)")};site:=r.site(pkg,id);state.declaration=site;state.id=fmt.Sprintf("%s:%s:%d:%d:%s",pkg,site.File,site.Line,site.Column,id.Name)}
  state.known=false
  if e==nil {state.value=false;state.known=true} else {
   switch x:=unparenConfig(e).(type) {
   case *ast.Ident:
    source,ok:=states[p.info.ObjectOf(x)];if !ok || !source.known{return configScope("copy source is not a constructed local value")};state.value=source.value;state.known=true;allowed[x]=true
   case *ast.CompositeLit:
    if !matching(p.info.TypeOf(x)){return configScope("constructor type differs from object")};state.value=false;state.known=true
    for _,elt:=range x.Elts {kv,ok:=elt.(*ast.KeyValueExpr);if !ok{return configScope("positional constructor unsupported")};key,ok:=kv.Key.(*ast.Ident);if !ok{return configScope("unknown constructor field")};if key.Name==field.Name(){state.value,state.known=value(kv.Value)}}
   default:return configScope("unsupported constructor/default/copy expression")
   }
  }
  if !state.known{return configScope("unresolved constructor field value")};states[obj]=state;return nil
 }
 inspectCalls:=func(n ast.Node) error {
  if n==nil{return nil}
  var failure error
  ast.Inspect(n,func(n ast.Node)bool {
   if failure!=nil{return false}
   switch x:=n.(type) {
   case *ast.FuncLit:failure=configScope("closure access/call scope unsupported");return false
   case *ast.UnaryExpr:if x.Op==token.AND {switch target:=unparenConfig(x.X).(type){case *ast.Ident:if matching(p.info.TypeOf(target)){failure=configScope("address escape of configuration")};case *ast.SelectorExpr:if s:=p.info.Selections[target];s!=nil && s.Obj()==field{failure=configScope("address escape of configuration field")}}}
   case *ast.SelectorExpr:
    if selection:=p.info.Selections[x];selection!=nil && selection.Kind()==types.MethodVal{ast.Inspect(x.X,func(n ast.Node)bool{if id,ok:=n.(*ast.Ident);ok{if obj,ok:=p.info.Uses[id].(*types.Var);ok && matching(obj.Type()){failure=configScope("configuration receiver/field method mutation or capture unsupported")}};return true})}
    if s:=p.info.Selections[x];s!=nil && s.Kind()==types.FieldVal && s.Obj()==field {
     if id,ok:=unparenConfig(x.X).(*ast.Ident);ok && matching(p.info.TypeOf(id)){allowed[id]=true}
    }
   case *ast.CallExpr:
    if x==consume {s,ok:=states[want];if !ok || !s.known {failure=configScope("consumed configuration is not a constructed local value")} else {result=s;found=true}}
   }
   return true
  });return failure
 }
 if fn.Body==nil{return result,configScope("caller body missing")}
 for _,stmt:=range fn.Body.List {
  switch s:=stmt.(type) {
  case *ast.DeclStmt:
   d,ok:=s.Decl.(*ast.GenDecl);if !ok || (d.Tok!=token.VAR && d.Tok!=token.CONST){return result,configScope("unsupported declaration")}
   for _,spec:=range d.Specs {v,ok:=spec.(*ast.ValueSpec);if !ok{return result,configScope("unsupported declaration")};if len(v.Values)>0 && len(v.Values)!=len(v.Names){return result,configScope("tuple constructor unsupported")};for i,id:=range v.Names {var e ast.Expr;if len(v.Values)>0{e=v.Values[i]};if err:=inspectCalls(e);err!=nil{return result,err};if err:=init(p.info.Defs[id],e,id);err!=nil{return result,err}}}
  case *ast.AssignStmt:
   if len(s.Lhs)!=len(s.Rhs){return result,configScope("tuple assignment unsupported")}
   // Parallel assignment is not an ordered scalar write/copy sequence.
   if len(s.Lhs)!=1{return result,configScope("parallel assignment unsupported")}
   if err:=inspectCalls(s.Rhs[0]);err!=nil{return result,err}
   switch lhs:=unparenConfig(s.Lhs[0]).(type) {
   case *ast.Ident:
    obj:=p.info.ObjectOf(lhs)
    if matching(p.info.TypeOf(lhs)) {allowed[lhs]=true;if err:=init(obj,s.Rhs[0],lhs);err!=nil{return result,err}} else if lhs.Name=="_" {if id,ok:=unparenConfig(s.Rhs[0]).(*ast.Ident);ok{allowed[id]=true}}
   case *ast.SelectorExpr:
    selection:=p.info.Selections[lhs]
    if selection!=nil && selection.Obj()==field {id,ok:=unparenConfig(lhs.X).(*ast.Ident);if !ok{return result,configScope("indirect field writer")};obj:=p.info.ObjectOf(id);state,ok:=states[obj];if !ok{return result,configScope("field write before supported construction")};if s.Tok!=token.ASSIGN{return result,configScope("compound field write unsupported")};state.value,state.known=value(s.Rhs[0]);if !state.known{return result,configScope("unresolved field write/override")};states[obj]=state;allowed[id]=true}
   }
  case *ast.ExprStmt:if err:=inspectCalls(s.X);err!=nil{return result,err}
  case *ast.ReturnStmt:for _,e:=range s.Results{if err:=inspectCalls(e);err!=nil{return result,err}}
  case *ast.EmptyStmt:
  default:return result,configScope("caller control flow/range/defer/asynchronous scope unsupported")
  }
 }
 var escape bool
 ast.Inspect(fn.Body,func(n ast.Node)bool{if id,ok:=n.(*ast.Ident);ok{if obj,ok:=p.info.Uses[id].(*types.Var);ok && matching(obj.Type()) && !allowed[id] {escape=true}};return true})
 if escape{return result,configScope("configuration object escapes supported scalar/copy uses (alias, receiver or aggregate)")}
 if !found{return result,configScope("invocation is not a supported straight-line caller consumption")}
 return result,nil
}

func (ix *Index) CaptureConfigWriterCertificate(ctx context.Context,c *domain.AnalysisCase,cond domain.Condition) (domain.ConfigWriterCertificate,error) {
 var cert domain.ConfigWriterCertificate
 if c==nil || c.RecordPin==nil{return cert,configScope("case/record pin missing")}
 if bound,ok:=ix.BoundBuildContext();!ok || bound.Matches(domain.EffectiveBuildContext(c.Product))!=nil{return cert,configScope("producer needs an independently bound matching source index")}
 if filepath.Clean(ix.Dir)!=filepath.Clean(c.Product.Repository){return cert,configScope("index source root differs from snapshot root")}
 if err:=(Verifier{Source:ix}).sourceContextMatches(c.Product);err!=nil{return cert,configScope("%v",err)}
 before,err:=repository.CaptureContentManifest(ix.Dir);if err!=nil{return cert,configScope("snapshot capture: %v",err)}
 manifestEntries,err:=repository.ValidateContentManifest(before,c.Product.ContentHash);if err!=nil{return cert,configScope("snapshot differs from acquisition: %v",err)}
 manifest:=map[string]repository.ContentManifestEntry{};for _,entry:=range manifestEntries{manifest[entry.Path]=entry}
 m:=affected.MeasurePackageInventory(ctx,affected.ExecGoTool{Env:ix.Env,Version:ix.Build.GoVersion},ix.Dir,ix.Build,false)
 inv,err:=m.Admit(c.Product);if err!=nil{return cert,configScope("inventory: %v",err)}
 build:=domain.EffectiveBuildContext(c.Product)
 inventoryID:=c.EvidenceGraph.AddEvidence(domain.Evidence{Kind:domain.EvidencePackageList,Quality:domain.QualityDeterministic,Source:"go list -deps -json ./...",Tool:"go",Content:m.RawStream,ArtifactHash:m.RawReference,BuildContext:&build,PackageList:&m.Run})
 subjects,err:=exactLocusConditionSubjects(cond);if err!=nil{return cert,configScope("%v",err)}
 cert=domain.ConfigWriterCertificate{Schema:domain.ConfigWriterCertificateSchema,ConditionID:cond.ID,Record:*c.RecordPin,Build:build,Subjects:subjects,InventoryEvidenceID:inventoryID,InventoryReference:m.RawReference,SnapshotManifest:before}
 for _,p:=range inv.Packages {
  if p.Standard{continue}
  dir,err:=configRelative(c.Product.Repository,p.Dir);if err!=nil{return cert,err}
  cp:=domain.ConfigCapturedPackage{ImportPath:p.ImportPath,Directory:dir}
  for _,name:=range p.GoFiles{cp.SelectedGoFiles=append(cp.SelectedGoFiles,path.Join(dir,name))}
  entries,err:=os.ReadDir(p.Dir);if err!=nil{return cert,configScope("source directory: %v",err)}
  for _,e:=range entries{if strings.HasSuffix(e.Name(),".go") && !strings.HasSuffix(e.Name(),"_test.go"){if e.Type()&os.ModeSymlink!=0{return cert,configScope("symlink source unsupported")};raw,err:=os.ReadFile(filepath.Join(p.Dir,e.Name()));if err!=nil{return cert,configScope("source bytes: %v",err)};cp.Files=append(cp.Files,domain.ConfigCapturedFile{Path:path.Join(dir,e.Name()),Bytes:raw})}}
  if !strings.HasPrefix(dir,"vendor/"){moduleFile:=configModuleFile(manifest,dir);if moduleFile==""{return cert,configScope("source package lacks anchored module declaration")};raw,err:=os.ReadFile(filepath.Join(ix.Dir,filepath.FromSlash(moduleFile)));if err!=nil{return cert,configScope("module source bytes: %v",err)};cp.Files=append(cp.Files,domain.ConfigCapturedFile{Path:moduleFile,Bytes:raw})}
  cert.Packages=append(cert.Packages,cp)
 }
 r,err:=deriveConfigCertificate(ConfigAdmissionForCase(c),cond,cert);if err!=nil{return cert,err};cert.Uses=r.uses
 fields:=map[domain.SymbolRef]bool{}
 for _,u:=range cert.Uses{fields[u.Field]=true}
 for field:=range fields {writers,err:=ix.ConfigWritersWithInventory(ctx,field,m);if err!=nil{return cert,configScope("writer observation: %v",err)};c.EvidenceGraph.AddConfigWriters(field.Package+"."+field.Symbol,writers)}
 after,err:=repository.CaptureContentManifest(ix.Dir);if err!=nil || !bytes.Equal(before,after){return cert,configScope("snapshot mutated during proof capture")}
 return cert,nil
}

// ValidateConfigCertificateEvidence admits only full, digest-bound cited records.
func ValidateConfigCertificateEvidence(in NegativeAdmissionInput,claim domain.Claim,cond domain.Condition) (domain.EvidenceID,error) {
 cited:=map[domain.EvidenceID]bool{}
 for _,id:=range claim.EvidenceIDs{cited[id]=true}
 if claim.NegativeVerification!=nil {for _,id:=range claim.NegativeVerification.EvidenceIDs{cited[id]=true}}
 var selected *domain.Evidence
 for i:=range in.Evidence {e:=&in.Evidence[i];if !cited[e.ID] || e.Kind!=domain.EvidenceConfiguration || e.Tool!=ConfigCertificateTool{continue};if selected!=nil{return "",configScope("multiple configuration certificates cited")};selected=e}
 if selected==nil{return "",configScope("missing full cited configuration certificate")}
 e:=selected
 if claim.NegativeVerification!=nil && claim.NegativeVerification.Status==domain.NegativeVerified {
  claimCites,nvCites:=false,false
  for _,id:=range claim.EvidenceIDs{claimCites=claimCites || id==e.ID}
  for _,id:=range claim.NegativeVerification.EvidenceIDs{nvCites=nvCites || id==e.ID}
  if !claimCites || !nvCites{return e.ID,configScope("claim and verification must both cite the exact certificate")}
 }
 if e.BuildContext==nil || e.BuildContext.Matches(domain.EffectiveBuildContext(in.Product))!=nil || e.ArtifactHash!=configDigest([]byte(e.Content)){return e.ID,configScope("configuration evidence build/digest mismatch")}
 var cert domain.ConfigWriterCertificate
 if err:=json.Unmarshal([]byte(e.Content),&cert);err!=nil{return e.ID,configScope("configuration payload: %v",err)}
 return e.ID,ValidateConfigWriterEvidence(in,cond,cert)
}

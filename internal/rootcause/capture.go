package rootcause

import (
 "bytes"
 "encoding/json"
 "fmt"
 "io"
 "io/fs"
 "os"
 "path/filepath"
 "reflect"
 "strings"

 "github.com/davniy/izyan/internal/domain"
 "github.com/davniy/izyan/internal/fix"
 "github.com/davniy/izyan/internal/fixbinding"
)

const FixSourceCapturesSchema="fix-source-captures.v1"
// Transport limits never truncate into accepted proof input.
const captureManifestLimit=1<<20
const captureFileLimit=32<<20
const captureAggregateLimit=128<<20
const captureMemberLimit=100000

type artifactCapture struct {Locator string `json:"locator"`;Path string `json:"path"`;Digest string `json:"digest"`}
type archiveCapture struct {
 Locator string `json:"locator,omitempty"`
 ArtifactDigest string `json:"artifact_digest,omitempty"`
 ImportPath string `json:"import_path,omitempty"`
 DeclaredModule string `json:"declared_module,omitempty"`
 DeclaredVersion string `json:"declared_version,omitempty"`
 Module string `json:"module"`
 Version string `json:"version"`
 ArchivePath string `json:"archive_path"`
 ArchiveDigest string `json:"archive_digest"`
 TreePath string `json:"tree_path,omitempty"`
}
type sourceCaptureGroup struct {
 RecordID string `json:"record_id"`
 DocumentDigest string `json:"document_digest"`
 EntryRef int `json:"entry_ref"`
 SelectedSource domain.EffectiveSourceSelection `json:"selected_source"`
 PatchBases []archiveCapture `json:"patch_bases,omitempty"`
 External []archiveCapture `json:"external,omitempty"`
}
type sourceCaptureManifest struct {
 Schema string `json:"schema"`
 Artifacts []artifactCapture `json:"artifacts"`
 Captures []sourceCaptureGroup `json:"captures"`
}
type loadedCaptureGroup struct {
 selector sourceCaptureGroup
 bases []fixbinding.PatchBaseCapture
 external []fixbinding.ExternalSourceCapture
}
// SourceCaptureSet is fully loaded transport material; paths are never replay inputs.
type SourceCaptureSet struct {artifacts map[string]string;groups []loadedCaptureGroup}
func(s *SourceCaptureSet)PatchProvider()fix.ArtifactProvider{return fix.CapturedProvider{Artifacts:s.artifacts}}

func LoadSourceCaptures(name string)(*SourceCaptureSet,error){
 root,err:=filepath.Abs(filepath.Dir(name));if err!=nil{return nil,err};root,err=filepath.EvalSymlinks(root);if err!=nil{return nil,err}
 remaining:=int64(captureAggregateLimit)
 confined:=func(rel string)(string,error){
  if rel=="" || filepath.IsAbs(rel)||filepath.Clean(rel)!=rel||strings.ContainsAny(rel,"\\\n\r\t")||rel==".."||strings.HasPrefix(rel,".."+string(filepath.Separator)){return "",fmt.Errorf("unconfined capture path %q",rel)}
  p:=root
  for _,part:=range strings.Split(rel,string(filepath.Separator)){p=filepath.Join(p,part);info,err:=os.Lstat(p);if err!=nil{return "",err};if info.Mode()&os.ModeSymlink!=0{return "",fmt.Errorf("symlink capture unsupported")}}
  return p,nil
 }
 read:=func(p string,limit int64)([]byte,error){f,err:=os.Open(p);if err!=nil{return nil,err};defer f.Close();info,err:=f.Stat();if err!=nil{return nil,err};if !info.Mode().IsRegular(){return nil,fmt.Errorf("nonregular capture")};if limit>remaining{limit=remaining};raw,err:=io.ReadAll(io.LimitReader(f,limit+1));if err!=nil{return nil,err};if int64(len(raw))>limit{return nil,fmt.Errorf("capture size limit exceeded")};remaining-=int64(len(raw));return raw,nil}
 info,err:=os.Lstat(name);if err!=nil{return nil,err};if !info.Mode().IsRegular(){return nil,fmt.Errorf("manifest must be regular")}
 raw,err:=read(name,captureManifestLimit);if err!=nil{return nil,err}
 var manifest sourceCaptureManifest;dec:=json.NewDecoder(bytes.NewReader(raw));dec.DisallowUnknownFields();if err:=dec.Decode(&manifest);err!=nil{return nil,err};if dec.Decode(new(any))!=io.EOF{return nil,fmt.Errorf("trailing capture manifest content")};if manifest.Schema!=FixSourceCapturesSchema{return nil,fmt.Errorf("unsupported capture schema")}
 file:=func(rel,digest string)([]byte,error){p,err:=confined(rel);if err!=nil{return nil,err};raw,err:=read(p,captureFileLimit);if err!=nil{return nil,err};if fixbinding.DigestBytes(raw)!=digest{return nil,fmt.Errorf("capture digest mismatch: %s",rel)};return raw,nil}
 tree:=func(rel string)([]fixbinding.CapturedFile,error){
  if rel==""{return nil,nil};p,err:=confined(rel);if err!=nil{return nil,err}
  info,err:=os.Stat(p);if err!=nil{return nil,err};if !info.IsDir(){return nil,fmt.Errorf("tree carrier root is not a directory")}
  var files []fixbinding.CapturedFile;members:=0
  err=filepath.WalkDir(p,func(name string,d fs.DirEntry,err error)error{
   if err!=nil{return err};members++;if members>captureMemberLimit{return fmt.Errorf("tree member limit exceeded")}
   if d.IsDir(){return nil};if !d.Type().IsRegular(){return fmt.Errorf("nonregular tree member")}
   raw,err:=read(name,captureFileLimit);if err!=nil{return err};relative,err:=filepath.Rel(p,name);if err!=nil{return err}
   files=append(files,fixbinding.CapturedFile{Path:filepath.ToSlash(relative),Bytes:raw});return nil
  })
  if len(files)==0 && err==nil{err=fmt.Errorf("empty tree carrier")};return files,err
 }
 out:=&SourceCaptureSet{artifacts:map[string]string{}}
 for _,a:=range manifest.Artifacts {if a.Locator==""{return nil,fmt.Errorf("empty artifact locator")};if _,ok:=out.artifacts[a.Locator];ok{return nil,fmt.Errorf("duplicate artifact locator")};raw,err:=file(a.Path,a.Digest);if err!=nil{return nil,err};out.artifacts[a.Locator]=string(raw)}
 seen:=map[string]bool{}
 for _,g:=range manifest.Captures {
  key:=fmt.Sprintf("%s\x00%s\x00%d",g.RecordID,g.DocumentDigest,g.EntryRef)
  if g.RecordID==""||g.DocumentDigest==""||g.EntryRef<0||seen[key]{return nil,fmt.Errorf("ambiguous/empty record capture scope")};seen[key]=true
  if err:=g.SelectedSource.Validate();err!=nil{return nil,err};if g.SelectedSource.EntryRef!=g.EntryRef{return nil,fmt.Errorf("selected entry differs")}
  loaded:=loadedCaptureGroup{selector:g}
  for kind,entries:=range [][]archiveCapture{g.PatchBases,g.External}{seenAssociation:=map[string]bool{};for _,a:=range entries {
   if (kind==0 && (a.Locator=="" || a.ImportPath!="" || a.DeclaredModule!="" || a.DeclaredVersion!="")) || (kind==1 && (a.ImportPath=="" || a.Locator!="" || a.ArtifactDigest!="")) {return nil,fmt.Errorf("mixed source capture association fields")}
   association:=a.Locator;if a.ImportPath!=""{association=a.ImportPath};if association==""||seenAssociation[association]||a.Module==""||a.Version==""{return nil,fmt.Errorf("missing/duplicate source association")};seenAssociation[association]=true
   raw,err:=file(a.ArchivePath,a.ArchiveDigest);if err!=nil{return nil,err};carrier,err:=tree(a.TreePath);if err!=nil{return nil,err}
   evidence:=fixbinding.ArchiveEvidence{Bytes:raw,Module:a.Module,Version:a.Version}
   if a.ImportPath=="" {if a.ArtifactDigest==""{return nil,fmt.Errorf("patch artifact digest missing")};loaded.bases=append(loaded.bases,fixbinding.PatchBaseCapture{Locator:a.Locator,ArtifactDigest:a.ArtifactDigest,Archive:evidence,Tree:carrier})}else{if a.DeclaredModule!=a.ImportPath||a.DeclaredVersion==""{return nil,fmt.Errorf("external declared identity missing")};loaded.external=append(loaded.external,fixbinding.ExternalSourceCapture{ImportPath:a.ImportPath,Archive:evidence,Tree:carrier,Selection:domain.EffectiveSourceSelection{DeclaredModule:a.DeclaredModule,DeclaredVersion:a.DeclaredVersion,EffectiveModule:a.Module,EffectiveVersion:a.Version}})}
  }}
  out.groups=append(out.groups,loaded)
 }
 return out,nil
}
func(s *SourceCaptureSet)requested(c *domain.AnalysisCase,sel domain.EffectiveSourceSelection)(fixbinding.SourceCaptures,error){
 if s==nil{return fixbinding.SourceCaptures{},nil}
 for _,g:=range s.groups {if c.RecordPin!=nil && g.selector.RecordID==c.RecordPin.RecordID && g.selector.DocumentDigest==c.RecordPin.DocumentDigest && g.selector.EntryRef==sel.EntryRef{if !reflect.DeepEqual(g.selector.SelectedSource,sel){return fixbinding.SourceCaptures{},fmt.Errorf("capture selected identity differs from current entry")};return fixbinding.SourceCaptures{PatchBases:append([]fixbinding.PatchBaseCapture(nil),g.bases...),External:append([]fixbinding.ExternalSourceCapture(nil),g.external...)},nil}}
 return fixbinding.SourceCaptures{},nil
}

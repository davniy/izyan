package rootcause

import (
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestPatchBaseCaptureManifestStrict(t *testing.T){
 for _,test:=range []struct{name,raw string}{
  {"unknown",`{"schema":"fix-source-captures.v1","Complete":true}`},
  {"trailing",`{"schema":"fix-source-captures.v1"} {}`},
  {"schema",`{"schema":"fix-source-captures.v0"}`},
  {"duplicate",`{"schema":"fix-source-captures.v1","artifacts":[{"locator":"x","path":"p","digest":"sha256:a"},{"locator":"x","path":"p","digest":"sha256:a"}]}`},
  {"escape",`{"schema":"fix-source-captures.v1","artifacts":[{"locator":"x","path":"../outside","digest":"sha256:a"}]}`},
  {"checksumAuthority",`{"schema":"fix-source-captures.v1","go_sum_path":"self.sum"}`},
 }{t.Run(test.name,func(t *testing.T){p:=filepath.Join(t.TempDir(),"manifest.json");if err:=os.WriteFile(p,[]byte(test.raw),0644);err!=nil{t.Fatal(err)};if _,err:=LoadSourceCaptures(p);err==nil{t.Fatal("invalid transport accepted")}})}
}
func TestPatchBaseCaptureManifestBounds(t *testing.T){
 p:=filepath.Join(t.TempDir(),"manifest.json");if err:=os.WriteFile(p,[]byte(strings.Repeat(" ",captureManifestLimit+1)),0644);err!=nil{t.Fatal(err)}
 if _,err:=LoadSourceCaptures(p);err==nil{t.Fatal("oversized manifest accepted")}
}
func TestPatchBaseCaptureManifestSymlinkRefuses(t *testing.T){
 dir:=t.TempDir();outside:=filepath.Join(t.TempDir(),"patch");if err:=os.WriteFile(outside,[]byte("patch"),0644);err!=nil{t.Fatal(err)}
 if err:=os.Symlink(outside,filepath.Join(dir,"patch"));err!=nil{t.Fatal(err)}
 p:=filepath.Join(dir,"manifest.json");if err:=os.WriteFile(p,[]byte(`{"schema":"fix-source-captures.v1","artifacts":[{"locator":"x","path":"patch","digest":"sha256:a"}]}`),0644);err!=nil{t.Fatal(err)}
 if _,err:=LoadSourceCaptures(p);err==nil{t.Fatal("symlink capture accepted")}
}

func TestPatchBaseCaptureFileBounds(t *testing.T){
 dir:=t.TempDir();file:=filepath.Join(dir,"large.patch")
 f,err:=os.Create(file);if err!=nil{t.Fatal(err)};if err:=f.Truncate(captureFileLimit+1);err!=nil{f.Close();t.Fatal(err)};if err:=f.Close();err!=nil{t.Fatal(err)}
 p:=filepath.Join(dir,"manifest.json");if err:=os.WriteFile(p,[]byte(`{"schema":"fix-source-captures.v1","artifacts":[{"locator":"x","path":"large.patch","digest":"sha256:irrelevant"}]}`),0644);err!=nil{t.Fatal(err)}
 if _,err:=LoadSourceCaptures(p);err==nil || !strings.Contains(err.Error(),"size limit"){t.Fatalf("oversized referenced bytes did not refuse before digest/usage: %v",err)}
}

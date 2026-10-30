package fixbinding

import (
 "archive/zip"
 "bytes"
 "fmt"
 "io"
 "strings"
 "testing"
)

type zeroCaptureReader struct{}
func(zeroCaptureReader)Read(p []byte)(int,error){clear(p);return len(p),nil}

func TestPatchBaseCaptureArchiveBounds(t *testing.T){
 t.Run("per file",func(t *testing.T){
  var b bytes.Buffer;w:=zip.NewWriter(&b)
  if _,err:=w.CreateRaw(&zip.FileHeader{Name:"example.com/bounded@v1.0.0/large.go",UncompressedSize64:32<<20+1,Method:zip.Store});err!=nil{t.Fatal(err)};if err:=w.Close();err!=nil{t.Fatal(err)}
  _,err:=CheckArchiveAnchor(ArchiveEvidence{Module:"example.com/bounded",Version:"v1.0.0",Bytes:b.Bytes(),GoSum:[]byte("example.com/bounded v1.0.0 h1:bounds\n")})
  if err==nil || !strings.Contains(err.Error(),"oversized"){t.Fatalf("oversized member not refused: %v",err)}
 })
 t.Run("expanded aggregate",func(t *testing.T){
  var b bytes.Buffer;w:=zip.NewWriter(&b)
  for i:=range 3{entry,err:=w.Create(fmt.Sprintf("example.com/bounded@v1.0.0/file%d",i));if err!=nil{t.Fatal(err)};if _,err:=io.CopyN(entry,zeroCaptureReader{},24<<20);err!=nil{t.Fatal(err)}}
  if err:=w.Close();err!=nil{t.Fatal(err)}
  _,err:=CheckArchiveAnchor(ArchiveEvidence{Module:"example.com/bounded",Version:"v1.0.0",Bytes:b.Bytes(),GoSum:[]byte("example.com/bounded v1.0.0 h1:bounds\n")})
  if err==nil || !strings.Contains(err.Error(),"expanded capture limit"){t.Fatalf("expanded aggregate not refused: %v",err)}
 })
}

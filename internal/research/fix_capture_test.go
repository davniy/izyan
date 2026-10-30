package research

import (
 "bytes"
 "testing"

 "github.com/davniy/izyan/internal/domain"
)

// The real producer/publication/replay fixture is in cmd/izyan. This unit
// control pins assembly ownership: later lane changes cannot mutate a record.
func TestResearchFixCaptureRecordRetention(t *testing.T){
 lane:=requestLane(t,domain.ClaimFalse)
 lane.Advisory.RawBytes=[]byte("captured advisory bytes")
 lane.RecordRootCause=&domain.RootCauseModel{Limitations:[]string{"capture observation"},FixProof:&domain.FixProof{Inputs:[]byte(`{"full":"premises"}`)}}
 c,err:=recordCase(lane);if err!=nil{t.Fatal(err)}
 if c.AdvisoryRecord==nil || !bytes.Equal(c.AdvisoryRecord.Bytes,lane.Advisory.RawBytes){t.Fatal("record omitted advisory capture")}
 lane.RecordRootCause.FixProof.Inputs[0]='x'
 if c.RootCause==nil || string(c.RootCause.FixProof.Inputs)!=`{"full":"premises"}`{t.Fatal("record shares mutable lane proof")}
 owner:=requestOwnerCase(c)
 if owner.AdvisoryRecord==nil || !bytes.Equal(owner.AdvisoryRecord.Bytes,c.AdvisoryRecord.Bytes){t.Fatal("requested owner omitted exact advisory capture")}
}

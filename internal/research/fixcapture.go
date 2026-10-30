package research

import (
 "context"

 "github.com/fedorovmv/izyan/internal/evidencetools"
 "github.com/fedorovmv/izyan/internal/fix"
 "github.com/fedorovmv/izyan/internal/rootcause"
)

// laneFixSourceCaptures invokes the same producer as analyze. It retains proof
// premises, not claims: source capture grants no independent negative verdict.
func laneFixSourceCaptures(ctx context.Context,res *LaneResult,sess *evidencetools.Session,captures *rootcause.SourceCaptureSet)error{
 c,err:=recordCase(res);if err!=nil{return err}
 model,evidence,err:=(rootcause.Resolver{Fix:fix.Resolver{},Patch:captures.PatchProvider(),Source:sess.Source,GoTool:sess.GoTool,Captures:captures}).Resolve(ctx,c,c.Vulnerability)
 if err!=nil{return err}
 for _,e:=range evidence{c.EvidenceGraph.AddEvidence(e)}
 res.RecordRootCause=model
 res.RecordEvidence=c.EvidenceGraph.EvidenceList()
 return nil
}

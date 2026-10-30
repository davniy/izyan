package triage

import (
 "bytes"
 "context"
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"
)

func environmentAnswerFixture(t *testing.T) (replayFixture, DecisionPackage) {
 t.Helper()
 f := recordDecisionRun(t, newReplayRepo(t), t.TempDir(), replayClockA, func(a *Assessment) {
  a.EnvironmentVariables = []EnvironmentVariableProposal{{ID: VariableDeploymentPerimeter}}
  for _, value := range []string{"cluster-internal", "public", EnvironmentUnknown} {
   action := a.ProposedAction; action.Kind = HumanActionKeepOpen
   if value == "cluster-internal" { action.Kind = HumanActionAcceptEnvironmentalMitigation }
   a.ConditionalActions = append(a.ConditionalActions, ConditionalActionProposal{Assignments: map[string]string{VariableDeploymentPerimeter:value}, Judgment: LLMJudgment{Verdict:VerdictInconclusive}, Action:action})
  }; a.ProposedAction.Kind = HumanActionKeepOpen
 })
 pkg, err := loadCurrentDecisionPackage(f.runDir); if err != nil { t.Fatal(err) }; return f, pkg
}

func TestEnvironmentAnswerSelectsPreparedBranchWithoutInvestigation(t *testing.T) {
 f, pkg := environmentAnswerFixture(t)
 before := mustRead(t, filepath.Join(f.runDir, "decision.json"))
 p, err := (ArtifactWriter{Clock:replayClockB}).WriteEnvironmentAnswers(context.Background(), f.runDir, "reviewer", []string{"deployment_perimeter=cluster-internal"})
 if err != nil { t.Fatal(err) }
 if p.Action.Kind != HumanActionAcceptEnvironmentalMitigation || p.Status != HumanBranchComplete || p.BranchID == "" || len(p.AssertionIDs) != 1 { t.Fatalf("projection: %+v", p) }
 if !bytes.Equal(before, mustRead(t, filepath.Join(f.runDir, "decision.json"))) { t.Fatal("answer mutated immutable machine/package claims") }
 rec, _, err := (ArtifactWriter{Clock:replayClockB}).WriteHumanDecision(context.Background(), f.runDir, HumanDecisionInput{Decision:HumanDecisionAccept, Actor:"reviewer"})
 if err != nil || rec.BranchID != p.BranchID || rec.ProjectionHash != p.ProjectionHash || rec.DecisionPackageHash != canonicalDecisionHash(pkg) { t.Fatalf("binding: %+v %v", rec, err) }
}

func TestAnsweredVariableIsNotReasked(t *testing.T) {
 f, _ := environmentAnswerFixture(t)
 w := ArtifactWriter{Clock:replayClockB}
 first, err := w.WriteEnvironmentAnswers(context.Background(), f.runDir, "reviewer", []string{"deployment_perimeter=unknown"}); if err != nil { t.Fatal(err) }
 second, err := w.WriteEnvironmentAnswers(context.Background(), f.runDir, "reviewer", nil); if err != nil { t.Fatal(err) }
 third, err := w.WriteEnvironmentAnswers(context.Background(), f.runDir, "reviewer", []string{"deployment_perimeter=unknown"}); if err != nil { t.Fatal(err) }
 if !jsonEqual(first, second) || !jsonEqual(first, third) || first.Status == HumanBranchAwaitingInput { t.Fatal("valid answer reasked or rewritten") }
}

func TestUndeclaredEnvironmentAnswerRejected(t *testing.T) {
 f, _ := environmentAnswerFixture(t)
 for _, answers := range [][]string{{"imaginary=true"}, {"deployment_perimeter=internet"}, {"deployment_perimeter=unknown", "deployment_perimeter=public"}, {"a=b", "b=c", "c=d"}} {
  if _, err := (ArtifactWriter{}).WriteEnvironmentAnswers(context.Background(), f.runDir, "reviewer", answers); err == nil { t.Fatalf("accepted %v", answers) }
 }
 if _, _, err := (ArtifactWriter{}).WriteHumanDecision(context.Background(), f.runDir, HumanDecisionInput{Decision:HumanDecisionAccept, Actor:"reviewer"}); err == nil { t.Fatal("accepted before answers") }
}

func TestEnvironmentAssertionSupersession(t *testing.T) {
 f, pkg := environmentAnswerFixture(t)
 first, err := (ArtifactWriter{Clock:replayClockA}).WriteEnvironmentAnswers(context.Background(), f.runDir, "alice", []string{"deployment_perimeter=public"}); if err != nil { t.Fatal(err) }
 oldBytes := mustRead(t, filepath.Join(f.runDir, environmentAssertionsDirName, first.AssertionIDs[0]+".json"))
 _, _, err = (ArtifactWriter{Clock:replayClockA}).WriteHumanDecision(context.Background(), f.runDir, HumanDecisionInput{Decision:HumanDecisionReject, Actor:"alice"}); if err != nil { t.Fatal(err) }
 second, err := (ArtifactWriter{Clock:replayClockB}).WriteEnvironmentAnswers(context.Background(), f.runDir, "bob", []string{"deployment_perimeter=cluster-internal"}); if err != nil { t.Fatal(err) }
 history, err := ReadEnvironmentAssertions(f.runDir, pkg); if err != nil { t.Fatal(err) }
 if len(history) != 2 || first.ProjectionHash == second.ProjectionHash || len(second.AssertionIDs) != 1 { t.Fatal("supersession not explicit") }
 if !bytes.Equal(oldBytes, mustRead(t, filepath.Join(f.runDir, environmentAssertionsDirName, first.AssertionIDs[0]+".json"))) { t.Fatal("old assertion rewritten") }
 if _, err := ReadHumanDecisions(f.runDir, pkg); err != nil { t.Fatal("supersession invalidated historical decision:", err) }
 // Concurrent independent assertions conflict instead of latest-answer-wins.
 for i := range history { history[i].Supersedes = nil; history[i].ID = environmentAssertionID(history[i]) }
 conflict, err := ApplyEnvironmentAssertions(pkg, history); if err != nil || conflict.Status != HumanBranchContradicted || conflict.Action.Kind != HumanActionKeepOpen { t.Fatalf("conflict %+v %v", conflict, err) }
 history[0].Supersedes = []string{"missing"}; history[0].ID = environmentAssertionID(history[0]); if _, err := ApplyEnvironmentAssertions(pkg, history); err == nil { t.Fatal("dangling supersession admitted") }
}

func TestAcceptRejectNeedsNoTechnicalNarrative(t *testing.T) {
 f, pkg := humanDecisionFixture(t)
 for _, decision := range []HumanDecision{HumanDecisionAccept, HumanDecisionReject} {
  rec, _, err := (ArtifactWriter{Clock:replayClockB}).WriteHumanDecision(context.Background(), f.runDir, HumanDecisionInput{Decision:decision, Actor:"reviewer"})
  if err != nil || rec.Reason != "" || rec.ReasonCode != "HUMAN_"+string(decision) { t.Fatalf("record %+v %v", rec, err) }
 }
 history, err := ReadHumanDecisions(f.runDir, pkg); if err != nil || len(history) != 2 { t.Fatalf("history %v %v", history, err) }
 // Original v1 hashes and required narrative are kept historical, not upgraded.
 historical := pkg; historical.SchemaVersion = "decision-package.v3"; historical.HumanReviewPlan = nil
 old := history[0]; old.SchemaVersion = "human-decision.v1"; old.BranchID, old.ProjectionHash, old.ReasonCode = "", "", ""; old.AssertionIDs = nil; old.Reason = "original rationale"; old.DecisionPackageHash = canonicalDecisionHash(historical); old.ID = humanDecisionRecordID(old)
 if err := old.validate(historical); err != nil { t.Fatal(err) }; old.Reason = ""; old.ID = humanDecisionRecordID(old); if err := old.validate(historical); err == nil { t.Fatal("historical reason relaxed") }
}

func TestBranchReviewReplayCopiesHistoryVerbatim(t *testing.T) {
 f, pkg := environmentAnswerFixture(t)
 _, err := (ArtifactWriter{Clock:replayClockA}).WriteEnvironmentAnswers(context.Background(), f.runDir, "reviewer", []string{"deployment_perimeter=unknown"}); if err != nil { t.Fatal(err) }
 for _, d := range []HumanDecision{HumanDecisionAccept, HumanDecisionReject} { if _, _, err := (ArtifactWriter{Clock:replayClockB}).WriteHumanDecision(context.Background(), f.runDir, HumanDecisionInput{Decision:d, Actor:"reviewer"}); err != nil { t.Fatal(err) } }
 rep, err := PrepareReplay(context.Background(), f.runDir); if err != nil { t.Fatal(err) }
 art, err := (ArtifactWriter{Clock:func() time.Time { return replayClockB().Add(time.Hour) }}).WriteReplay(context.Background(), t.TempDir(), rep); if err != nil { t.Fatal(err) }
 for _, collection := range []string{humanDecisionsDirName, environmentAssertionsDirName} {
  entries, err := os.ReadDir(filepath.Join(f.runDir, collection)); if err != nil { t.Fatal(err) }
  for _, e := range entries { if !bytes.Equal(mustRead(t, filepath.Join(f.runDir, collection, e.Name())), mustRead(t, filepath.Join(art.RootDir, collection, e.Name()))) { t.Fatal("replay changed historical bytes") } }
 }
 if records, err := ReadHumanDecisions(art.RootDir, pkg); err != nil || len(records) != 2 { t.Fatalf("replayed reviews %v %v", records, err) }
 // Strict envelope rejects authority keys rather than silently ignoring them.
 files, _ := os.ReadDir(filepath.Join(art.RootDir, environmentAssertionsDirName)); path := filepath.Join(art.RootDir, environmentAssertionsDirName, files[0].Name())
 var raw map[string]any; _ = json.Unmarshal(mustRead(t, path), &raw); raw["machine_disposition"] = "FALSE"; data, _ := json.Marshal(raw); _ = os.WriteFile(path, data, 0644)
 if _, err := ReadEnvironmentAssertions(art.RootDir, pkg); err == nil || !strings.Contains(err.Error(), "unknown field") { t.Fatalf("authority key admitted: %v", err) }
}

func TestEnvironmentAnswerDeterministicConflict(t *testing.T) {
 in := humanBranchFixture()
 in.Stage0.Materials.Deploy = &DeployFacts{FactCount:1, SHA256:strings.Repeat("a",64), Perimeter:"public"}
 plan, err := BuildHumanReviewPlan(in); if err != nil { t.Fatal(err) }
 pkg := validDecisionPackage(); pkg.HumanReviewPlan = &plan; pkg.ProposedAction.Kind = HumanActionKeepOpen
 variable := plan.Variables[0]
 a := EnvironmentAssertion{Variable:variable.ID, Value:"cluster-internal", Principal:"operator", Source:assertionSource(pkg, variable), Timestamp:replayClockA()}
 a.Freshness = "review-session:"+a.Timestamp.Format(time.RFC3339Nano); a.ID = environmentAssertionID(a)
 before, _ := json.Marshal(pkg)
 projection, err := ApplyEnvironmentAssertions(pkg, []EnvironmentAssertion{a})
 if err != nil || projection.Status != HumanBranchContradicted || projection.Action.Kind != HumanActionKeepOpen { t.Fatalf("deterministic conflict %+v %v", projection, err) }
 after, _ := json.Marshal(pkg); if !bytes.Equal(before,after) { t.Fatal("assertion changed code claims or machine disposition") }
}

func TestEnvironmentAssertionDurabilityAndTampering(t *testing.T) {
 f, pkg := environmentAnswerFixture(t)
 w := ArtifactWriter{Clock:replayClockB, testSyncDir:func(path string) error { if filepath.Base(path) == environmentAssertionsDirName { return os.ErrPermission }; return syncDir(path) }}
 if _, err := w.WriteEnvironmentAnswers(context.Background(),f.runDir,"operator",[]string{"deployment_perimeter=unknown"}); err == nil || !strings.Contains(err.Error(), "persistence path") { t.Fatalf("durability failure hidden: %v",err) }
 history, err := ReadEnvironmentAssertions(f.runDir,pkg); if err != nil || len(history)!=1 { t.Fatalf("complete record discarded: %+v %v", history,err) }
 if err := os.Remove(filepath.Join(f.runDir,humanDecisionsLockName)); err != nil { t.Fatal(err) }
 if _, err := ReadEnvironmentAssertions(f.runDir,pkg); err == nil { t.Fatal("missing lock repaired") }
 if _, err := os.Stat(filepath.Join(f.runDir,humanDecisionsLockName)); !os.IsNotExist(err) { t.Fatal("reader created lock") }
}

func TestBranchReviewRejectsRehashedProjectionTampering(t *testing.T) {
 f, pkg := environmentAnswerFixture(t)
 if _, err := (ArtifactWriter{Clock:replayClockA}).WriteEnvironmentAnswers(context.Background(),f.runDir,"operator",[]string{"deployment_perimeter=unknown"}); err != nil { t.Fatal(err) }
 rec,path,err := (ArtifactWriter{Clock:replayClockB}).WriteHumanDecision(context.Background(),f.runDir,HumanDecisionInput{Decision:HumanDecisionAccept,Actor:"operator"}); if err != nil { t.Fatal(err) }
 if err := os.Remove(path); err != nil { t.Fatal(err) }
 rec.BranchID = "another-branch"; rec.ID = humanDecisionRecordID(rec)
 writeHumanDecisionFile(t,f.runDir,rec.ID+".json",rec)
 if _,err := ReadHumanDecisions(f.runDir,pkg); err == nil { t.Fatal("rehashing bypassed projection verification") }
}

func TestEnvironmentAnswerTwoQuestionsAndUnknown(t *testing.T) {
 in := humanBranchFixture()
 quote := "Exploitation requires the network listener option to be enabled"
 raw := []byte(quote)
 in.Stage0.Investigation.Records = []CapturedRecord{{RecordID:"CVE-2099-0001", Raw:raw, SHA256:hashBytes(raw), Size:int64(len(raw))}}
 in.Assessment.EnvironmentVariables = append(in.Assessment.EnvironmentVariables, EnvironmentVariableProposal{ID:VariableAdvisoryPrecondition,RecordID:"CVE-2099-0001",RecordSHA256:hashBytes(raw),Quote:quote})
 in.Assessment.ConditionalActions = nil
 for _, perimeter := range []string{"cluster-internal","public",EnvironmentUnknown} { for _, condition := range []string{"holds","does_not_hold",EnvironmentUnknown} {
  action := in.Assessment.ProposedAction; action.Kind = HumanActionKeepOpen
  in.Assessment.ConditionalActions = append(in.Assessment.ConditionalActions,ConditionalActionProposal{Assignments:map[string]string{VariableDeploymentPerimeter:perimeter,VariableAdvisoryPrecondition:condition},Judgment:LLMJudgment{Verdict:VerdictInconclusive},Action:action})
 } }
 plan,err := BuildHumanReviewPlan(in); if err != nil { t.Fatal(err) }
 pkg := validDecisionPackage(); pkg.HumanReviewPlan = &plan; pkg.ProposedAction.Kind = HumanActionKeepOpen
 var assertions []EnvironmentAssertion
 for _,v := range plan.Variables {
  a := EnvironmentAssertion{Variable:v.ID, Value:EnvironmentUnknown,Principal:"operator",Source:assertionSource(pkg,v),Timestamp:replayClockA()}; a.Freshness = "review-session:"+a.Timestamp.Format(time.RFC3339Nano); a.ID=environmentAssertionID(a); assertions=append(assertions,a)
 }
 partial,err := ApplyEnvironmentAssertions(pkg,assertions[:1]); if err != nil || partial.Status != HumanBranchAwaitingInput { t.Fatalf("partial %+v %v",partial,err) }
 complete,err := ApplyEnvironmentAssertions(pkg,assertions); if err != nil || complete.Status != HumanBranchComplete || complete.Action.Kind != HumanActionKeepOpen || len(complete.AssertionIDs)!=2 { t.Fatalf("two unknown answers %+v %v",complete,err) }
}

func TestBranchReviewHistoricalV1FieldIsolation(t *testing.T) {
 pkg := validDecisionPackage(); pkg.SchemaVersion = "decision-package.v3"; pkg.HumanReviewPlan = nil
 rec := HumanDecisionRecord{SchemaVersion:"human-decision.v1",RunID:pkg.RunID,FindingID:pkg.FindingID,DecisionPackageHash:canonicalDecisionHash(pkg),Decision:HumanDecisionAccept,Actor:"original reviewer",Reason:"original required narrative",RecordedAt:replayClockA()}
 rec.ID = humanDecisionRecordID(rec)
 dir := t.TempDir(); writeHumanDecisionFile(t,dir,rec.ID+".json",rec)
 files,err := readHumanDecisionFilesSchema(dir,pkg,"decision-package.v3"); if err != nil || len(files)!=1 { t.Fatalf("historical v1 playback %+v %v",files,err) }
 raw := encodeHumanDecisionOrFail(t,rec)
 var fields map[string]any; _ = json.Unmarshal(raw,&fields); fields["branch_id"]=""; extended,_ := json.Marshal(fields)
 var decoded HumanDecisionRecord
 if err := json.Unmarshal(extended,&decoded); err == nil { t.Fatal("historical decoder accepted later fields") }
}

func TestBranchReviewRejectsRehashedV1Downgrade(t *testing.T) {
 f, pkg := environmentAnswerFixture(t)
 if _, err := (ArtifactWriter{Clock:replayClockA}).WriteEnvironmentAnswers(context.Background(),f.runDir,"operator",[]string{"deployment_perimeter=unknown"}); err != nil { t.Fatal(err) }
 rec,path,err := (ArtifactWriter{Clock:replayClockB}).WriteHumanDecision(context.Background(),f.runDir,HumanDecisionInput{Decision:HumanDecisionAccept,Actor:"operator",Reason:"nonempty comment"}); if err != nil { t.Fatal(err) }
 if err := os.Remove(path); err != nil { t.Fatal(err) }
 rec.SchemaVersion = "human-decision.v1"
 rec.BranchID,rec.ProjectionHash,rec.ReasonCode = "","",""
 rec.AssertionIDs = nil
 rec.ID = humanDecisionRecordID(rec)
 writeHumanDecisionFile(t,f.runDir,rec.ID+".json",rec)
 if _,err := ReadHumanDecisions(f.runDir,pkg); err == nil || !strings.Contains(err.Error(),"requires human-decision.v2") { t.Fatalf("rehashed downgrade admitted: %v",err) }
 if _,err := PrepareReplay(context.Background(),f.runDir); err == nil || !strings.Contains(err.Error(),"requires human-decision.v2") { t.Fatalf("replay admitted unbound downgrade: %v",err) }
}

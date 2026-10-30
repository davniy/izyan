package goanalysis

import (
 "context"
 "encoding/json"
 "testing"
 "github.com/davniy/izyan/internal/domain"
)

func TestOmittedCheckDeadnessDoesNotRefuteOmission(t *testing.T) {
 check := domain.SymbolRef{Package:"example.com/unreachdep/vulnlib", Symbol:"OrphanA"}
 pipeline := domain.SymbolRef{Package:check.Package, Symbol:"Benign"}
 contract := &domain.DefectSemanticsContract{Mode:domain.DefectSemanticsOmittedCheck, RecordID:"GO-TEST-OMISSION", Check:check, Pipeline:&pipeline}
 if _, err := domain.RequireDeadnessPremise(contract, []domain.SymbolRef{check}); err == nil { t.Fatal("omitted check's deadness refuted omission") }
 if _, err := domain.RequireDeadnessPremise(contract, []domain.SymbolRef{pipeline}); err != nil { t.Fatal(err) }
 c := &domain.AnalysisCase{Product:testProduct(), Exploit:&domain.ExploitModel{DefectSemantics:contract}}
 cond := domain.Condition{ID:"omission", Kind:domain.ConditionSymbolReachable, Subjects:[]domain.SymbolRef{check}, Params:map[string]string{domain.ParamCheck:domain.CheckLocus}}
 out := (Verifier{Source:fixture(t,"unreachprod")}).VerifyFalse(context.Background(), c, domain.Claim{ConditionID:cond.ID, Result:domain.ClaimFalse, Falsifier:domain.FalsifierLocusFunctionUnreached}, cond)
 if out.NegativeVerification == nil || out.NegativeVerification.Status == domain.NegativeVerified { t.Fatalf("omission closed: %+v", out) }
}

func TestUnreachabilityRequiresLocusKernelPayload(t *testing.T) {
 ix := fixture(t, "unreachprod")
 subject := domain.SymbolRef{Package:"example.com/unreachdep/vulnlib", Symbol:"OrphanA"}
 c := &domain.AnalysisCase{Product:ix.Build, Vulnerability:domain.Vulnerability{Module:"example.com/unreachdep"}, Exploit:&domain.ExploitModel{RootCauses:[]domain.SymbolRef{subject}}}
 cond := domain.Condition{ID:"dead", Kind:domain.ConditionSymbolReachable, Subjects:[]domain.SymbolRef{subject}}
 out := (Verifier{Source:ix}).VerifyFalse(context.Background(), c, domain.Claim{ConditionID:cond.ID, Result:domain.ClaimFalse, Falsifier:domain.FalsifierLocusFunctionUnreached}, cond)
 if out.NegativeVerification == nil || out.NegativeVerification.Status != domain.NegativeVerified { t.Fatalf("corrected ordinary locus control: %+v", out.NegativeVerification) }
 missing := cond; missing.Subjects = nil
 denied := (Verifier{Source:ix}).VerifyFalse(context.Background(),c,domain.Claim{ConditionID:missing.ID,Result:domain.ClaimFalse,Falsifier:domain.FalsifierLocusFunctionUnreached},missing)
 if denied.NegativeVerification == nil || denied.NegativeVerification.Status == domain.NegativeVerified { t.Fatal("subjectless live condition used model fallback") }
 found := false
 for _, evidence := range c.EvidenceGraph.EvidenceList() {
  var result UnreachabilityResult
  if json.Unmarshal([]byte(evidence.Content), &result) == nil && result.Inventory.RawStream != "" {
   found = true
   if err := result.ValidateComplete(domain.EffectiveBuildContext(c.Product)); err != nil { t.Fatal(err) }
   build := domain.EffectiveBuildContext(c.Product)
   c.EvidenceGraph.AddEvidence(domain.Evidence{Kind:domain.EvidenceSourceScan,BuildContext:&build,SourceScan:&domain.SourceScanRun{Module:result.Module,Subjects:cond.Subjects,EntrySymbols:result.ModuleEntrySymbols,Completed:result.ModuleReachComplete,Complete:result.Complete,Opaque:result.Opaque}})
  }
 }
 if !found { t.Fatal("locus verification persisted only a summary, not captured kernel evidence") }
 if err := ValidateVerifiedNegative(ConfigAdmissionForCase(c),out,cond); err != nil { t.Fatalf("live proof cannot replay: %v",err) }
}

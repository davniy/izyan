package research

import (
 "testing"
 "github.com/davniy/izyan/internal/affected"
 "github.com/davniy/izyan/internal/domain"
)

func TestUnreachabilityReplayResearchInventory(t *testing.T) {
 subs := []FactUsageSubject{{Module:testModule, Package:testPackage, Symbol:"Sink"}}
 control := decide(t, symbolAuthorityInput(decisionLane(domain.ClaimTrue), subs, completeSymbolResult(subs), true))
 if control.Verdict != domain.VerdictNoExploitPathFound { t.Fatalf("control: %+v", control) }
 for _, name := range []string{"missing", "foreign", "truncated", "dispatch", "dependency", "gated"} {
  t.Run(name, func(t *testing.T) {
   r := completeSymbolResult(subs)
   switch name {
   case "missing": r.Inventory = affected.PackageInventoryMeasurement{}
   case "foreign": r.Inventory.Build.GOOS = "foreign"
   case "truncated": r.Inventory = affected.RecordPackageInventory([]byte(`{"ImportPath":`), nil, decisionLane(domain.ClaimTrue).Snapshot, false)
   case "dispatch": r.InterfaceDispatchSites = []domain.CallSite{{Function:"unknown"}}
   case "dependency": r.DependencyCallSites = []domain.CallSite{{Function:"caller"}}
   case "gated": r.GatedReferences = []domain.CallSite{{Function:"alternate"}}
   }
   got := decide(t, symbolAuthorityInput(decisionLane(domain.ClaimTrue), subs, r, true))
   if got.Verdict != domain.VerdictInconclusive { t.Fatalf("invalid payload admitted: %+v", got) }
  })
 }
}

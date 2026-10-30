package triage_test

import (
 "context"
 "encoding/json"
 "testing"
 "github.com/davniy/izyan/internal/affected"
 "github.com/davniy/izyan/internal/domain"
 "github.com/davniy/izyan/internal/evidencetools"
 "github.com/davniy/izyan/internal/goanalysis"
 "github.com/davniy/izyan/internal/productb/triage"
)

func TestUnreachabilityReplayRequiresFullPayload(t *testing.T) {
 s := paritySession(t, "unreachinventory")
 det, closeFn := parityDetTools(t, s)
 defer closeFn()
 subject := domain.SymbolRef{Package:"inventory-unreach.test/dependency", Symbol:"Dead"}
 args, _ := json.Marshal(evidencetools.SymbolUnreachabilityArgs{Module:subject.Package, Subjects:[]domain.SymbolRef{subject}})
 det.Call(context.Background(), evidencetools.SymbolUnreachabilityTool, args)
 rec := det.Observations()[0]
 var payload struct { Data evidencetools.SymbolUnreachabilityData `json:"data"`; ScopeDetails *evidencetools.ScopeDetails `json:"scope_details"` }
 if err := json.Unmarshal(rec.Payload, &payload); err != nil { t.Fatal(err) }
 build := domain.EffectiveBuildContext(s.Build)
 s0 := triage.Stage0Result{Snapshot:triage.SnapshotManifest{ContentHash:rec.SnapshotHash}, Materials:triage.MaterialSet{PackageBuild:&build}}
 if ok, why := triage.UnreachabilityObservationApproved(rec, s0); !ok { t.Fatalf("real kernel control: %s, %v", why, payload.Data.Result.Limitations) }
 for _, name := range []string{"flag-only", "missing-inventory", "foreign-inventory", "truncated-inventory", "declaration", "entrypoint", "module-entry", "module-reach", "dispatch", "dynamic", "dependency", "gated", "opaque", "unbounded"} {
  t.Run(name, func(t *testing.T) {
   raw, _ := json.Marshal(payload)
   var bad struct { Data evidencetools.SymbolUnreachabilityData `json:"data"`; ScopeDetails *evidencetools.ScopeDetails `json:"scope_details"` }
   _ = json.Unmarshal(raw, &bad)
   r := &bad.Data.Result
   switch name {
   case "flag-only": *r = goanalysis.UnreachabilityResult{Complete:true}
   case "missing-inventory": r.Inventory = affected.PackageInventoryMeasurement{}
   case "foreign-inventory": r.Inventory.Build.GOOS = "foreign"
   case "truncated-inventory": r.Inventory = affected.RecordPackageInventory([]byte(r.Inventory.RawStream[:len(r.Inventory.RawStream)/2]), nil, s.Build, false)
   case "declaration": r.DeclarationComplete = false
   case "entrypoint": r.EntrypointComplete = false
   case "module-entry": r.ModuleEntryComplete = false
   case "module-reach": r.ModuleReachComplete = false
   case "dispatch": r.InterfaceDispatchSites = []domain.CallSite{{Function:"unknown"}}
   case "dynamic": r.DynamicMarkers = []goanalysis.DynamicMarker{{Kind:"reflect"}}
   case "dependency": r.DependencyCallSites = []domain.CallSite{{Function:"caller"}}
   case "gated": r.GatedReferences = []domain.CallSite{{Function:"alternate"}}
   case "opaque": r.Opaque = true
   case "unbounded": r.Unbounded = true
   }
   mutated := rec
   mutated.Payload, _ = json.Marshal(bad)
   if ok, _ := triage.UnreachabilityObservationApproved(mutated, s0); ok { t.Fatal("malformed full payload admitted") }
  })
 }
 // Same independent product, two advisory subjects: the live one keeps the
 // advisory open even though the dead one's own bounded measurement closes.
 both := []domain.SymbolRef{subject, {Package:subject.Package, Symbol:"Live"}}
 args, _ = json.Marshal(evidencetools.SymbolUnreachabilityArgs{Module:subject.Package, Subjects:both})
 det.Call(context.Background(), evidencetools.SymbolUnreachabilityTool, args)
 live := det.Observations()[1]
 if ok, _ := triage.UnreachabilityObservationApproved(live, s0); ok { t.Fatal("dead subset closed live advisory") }
 var livePayload struct { Data evidencetools.SymbolUnreachabilityData `json:"data"` }
 _ = json.Unmarshal(live.Payload, &livePayload)
 if len(livePayload.Data.Result.ProductReferences) == 0 { t.Fatalf("live independent subject not measured: %+v", livePayload.Data.Result) }
 t.Logf("real offline kernel: dead=%s two-subject=%s inventory=%s raw=%d replay-bytes=%d", rec.Completeness, live.Completeness, payload.Data.Result.Inventory.RawReference, payload.Data.Result.Inventory.RawSize, len(rec.Payload))
}

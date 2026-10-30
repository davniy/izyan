package goanalysis

import (
 "context"
 "encoding/json"
 "testing"
 "github.com/davniy/izyan/internal/affected"
 "github.com/davniy/izyan/internal/domain"
)

func TestUnreachabilityRequiresMatchingInventory(t *testing.T) {
 ctx := context.Background()
 ix := fixture(t, "unreachprod")
 subjects := []domain.SymbolRef{{Package:"example.com/unreachdep/vulnlib", Symbol:"OrphanA"}}
 m := affected.MeasurePackageInventory(ctx, affected.ExecGoTool{}, ix.Dir, ix.Build, false)
 for _, name := range []string{"missing", "foreign", "truncated", "failed", "test-scope"} {
  t.Run(name, func(t *testing.T) {
   bad := m
   switch name {
   case "missing": bad = affected.PackageInventoryMeasurement{}
   case "foreign": bad.Build.GOOS = "foreign"
   case "failed": bad.Run.Completed = false
   case "truncated": bad = affected.RecordPackageInventory([]byte(m.RawStream[:len(m.RawStream)/2]), nil, ix.Build, false)
   case "test-scope": bad.Run.WithTests = true
   }
   r, err := ix.VerifyUnreachableWithInventory(ctx, "example.com/unreachdep", subjects, bad)
   if err != nil { t.Fatal(err) }
   if r.ValidateComplete(domain.EffectiveBuildContext(ix.Build)) == nil { t.Fatal("invalid inventory admitted") }
   if name != "test-scope" && r.Complete { t.Fatal("invalid inventory marked complete") }
  })
 }
 r, err := ix.VerifyUnreachableWithInventory(ctx, "example.com/unreachdep", subjects, m)
 if err != nil { t.Fatal(err) }
 if err := r.ValidateComplete(domain.EffectiveBuildContext(ix.Build)); err != nil { t.Fatalf("real bounded control: %v; %v", err, r.Limitations) }
 raw, _ := json.Marshal(r)
 var replay UnreachabilityResult
 if err := json.Unmarshal(raw, &replay); err != nil { t.Fatal(err) }
 if err := replay.ValidateComplete(domain.EffectiveBuildContext(ix.Build)); err != nil { t.Fatal(err) }
 t.Logf("offline replay: %d bytes, inventory %s, subjects %v", len(raw), m.RawReference, r.Subjects)
}

func TestUnreachabilityOpenDispatchStaysUnknown(t *testing.T) {
 ix := fixture(t, "ifaceprod")
 r, err := ix.VerifyUnreachable(context.Background(), "example.com/dep", []domain.SymbolRef{unreachSubj("URI.String")})
 if err != nil { t.Fatal(err) }
 if r.Complete || r.ValidateComplete(r.Build) == nil { t.Fatal("open dispatch admitted") }
 if len(r.InterfaceDispatchSites)+len(r.MayCallSites) == 0 { t.Fatalf("dispatch not retained: %+v", r) }
}

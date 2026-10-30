package evidencetools

import (
 "context"
 "testing"
 "github.com/davniy/izyan/internal/domain"
)

func TestUnreachabilityRequiresSessionInventory(t *testing.T) {
 for _, raw := range []string{"", `{"ImportPath":"example.com/snap"} {`, `{"ImportPath":"foreign.test/product","Name":"main"}`} {
  t.Run(raw, func(t *testing.T) {
   s := newTestSession(t)
   s.GoTool = &inventoryTool{raw:[]byte(raw)}
   obs := invokeSymbolUnreachability(t, s, context.Background(), SymbolUnreachabilityArgs{Module:"example.com/snapdep", Subjects:[]domain.SymbolRef{{Package:"example.com/snapdep/vuln", Symbol:"helper"}}})
   if obs.Completeness == CompletenessComplete { t.Fatal("missing/truncated/foreign product inventory closed observation") }
  })
 }
 s := newTestSession(t)
 s.Strict, s.AllowToolchain = true, false
 obs, err := s.symbolUnreachability(context.Background(), SymbolUnreachabilityArgs{Module:"example.com/snapdep", Subjects:[]domain.SymbolRef{{Package:"example.com/snapdep/vuln", Symbol:"helper"}}})
 if err != nil || obs.ToolStatus != StatusUnsupported { t.Fatalf("permission gate: %+v %v", obs, err) }
}

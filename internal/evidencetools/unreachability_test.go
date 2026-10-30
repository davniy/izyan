package evidencetools

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/davniy/izyan/internal/domain"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// invokeSymbolUnreachability drives the handler through the session's
// invoke path so the returned Observation carries the audited shape.
func invokeSymbolUnreachability(t *testing.T, s *Session, ctx context.Context, a SymbolUnreachabilityArgs) *Observation {
	t.Helper()
	return s.invoke(ctx, SymbolUnreachabilityTool, nil, func(c context.Context) (*Observation, error) {
		return s.symbolUnreachability(c, a)
	})
}

// TestSymbolUnreachabilityContract: a reachable declared symbol (the
// evidencesnap product calls snapdep/vuln.Parse twice) is positive reach
// evidence — the observation reports disproven reachability, PARTIAL, and
// never anything resembling a negative-applicability verdict.
func TestSymbolUnreachabilityContract(t *testing.T) {
	s := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	o := invokeSymbolUnreachability(t, s, ctx, SymbolUnreachabilityArgs{
		Module: "example.com/snapdep",
		Subjects: []domain.SymbolRef{
			{Package: "example.com/snapdep/vuln", Symbol: "Parse"},
		},
	})
	assertObs(t, o, StatusOK, CompletenessPartial)
	d, ok := o.Data.(SymbolUnreachabilityData)
	if !ok {
		t.Fatalf("payload type %T", o.Data)
	}
	if d.Result.Complete {
		t.Fatal("a referenced symbol must not produce a complete proof")
	}
	if len(d.Result.ProductReferences) == 0 {
		t.Fatal("the product call sites must be recorded")
	}
	if !d.Result.DeclarationComplete {
		t.Fatal("the declared symbol resolved — declaration completeness holds")
	}
	if len(d.Result.Boundaries) == 0 {
		t.Fatal("proof boundaries must be recorded")
	}
	if o.ScopeDetails == nil || o.ScopeDetails.SnapshotHash == "" {
		t.Fatal("scope details must pin the snapshot")
	}
}

// TestSymbolUnreachabilityComplete: an unexported dep member no code path
// invokes is the closed proof shape — COMPLETE with the declared coverage
// rule, and still carrying the no-not-affected interpretation bounds.
func TestSymbolUnreachabilityComplete(t *testing.T) {
	s := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	o := invokeSymbolUnreachability(t, s, ctx, SymbolUnreachabilityArgs{
		Module: "example.com/snapdep",
		Subjects: []domain.SymbolRef{
			{Package: "example.com/snapdep/vuln", Symbol: "helper"},
		},
	})
	assertObs(t, o, StatusOK, CompletenessComplete)
	d, ok := o.Data.(SymbolUnreachabilityData)
	if !ok {
		t.Fatalf("payload type %T", o.Data)
	}
	if !d.Result.Complete {
		t.Fatalf("closed proof expected complete: %v", d.Result.Limitations)
	}
	if len(d.Result.Limitations) != 0 {
		t.Fatalf("complete proof carries no gap limitations: %v", d.Result.Limitations)
	}
	if o.ScopeDetails.CoverageRule == "" {
		t.Fatal("COMPLETE requires the named coverage rule")
	}
	foundBound := false
	for _, l := range o.Limitations {
		if l == "a complete result means the declared symbols are unreachable from the recorded product scope only — it is evidence for a no-exploit-path dismissal, never a not-affected or negative-applicability claim" {
			foundBound = true
		}
	}
	if !foundBound {
		t.Fatalf("the no-exploit-path-only bound must ride every COMPLETE result: %v", o.Limitations)
	}
}

// TestSymbolUnreachabilityUnresolved: a symbol that is not declared in the
// loaded dependency version fails closed to UNKNOWN — never absent.
func TestSymbolUnreachabilityUnresolved(t *testing.T) {
	s := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	o := invokeSymbolUnreachability(t, s, ctx, SymbolUnreachabilityArgs{
		Module: "example.com/snapdep",
		Subjects: []domain.SymbolRef{
			{Package: "example.com/snapdep/vuln", Symbol: "DoesNotExist"},
		},
	})
	assertObs(t, o, StatusOK, CompletenessUnknown)
	d, ok := o.Data.(SymbolUnreachabilityData)
	if !ok {
		t.Fatalf("payload type %T", o.Data)
	}
	if d.Result.DeclarationComplete || d.Result.Complete {
		t.Fatalf("unresolved declaration must fail closed: %+v", d.Result)
	}
}

// TestSymbolUnreachabilityEmptySubjects: no subjects is a schema-level
// argument error — the check cannot mint a proof over an empty set.
func TestSymbolUnreachabilityEmptySubjects(t *testing.T) {
	s := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	o := invokeSymbolUnreachability(t, s, ctx, SymbolUnreachabilityArgs{Module: "example.com/snapdep"})
	if o.ToolStatus != StatusError {
		t.Fatalf("empty subjects must error: %s", o.ToolStatus)
	}
}

// TestMCPSymbolUnreachabilityWire calls the check over a real MCP session:
// the tool is registered, schema-validated, and returns the observation.
func TestMCPSymbolUnreachabilityWire(t *testing.T) {
	s := newTestSession(t)
	srv := s.NewServer()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	st, ct := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "symbol-unreachability",
		Arguments: map[string]any{
			"module": "example.com/snapdep",
			"subjects": []map[string]any{
				{"package": "example.com/snapdep/vuln", "symbol": "Parse"},
			},
		}})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if res.IsError {
		t.Fatalf("isError: %+v", res.Content)
	}
	b, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var o Observation
	if err := json.Unmarshal(b, &o); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, b)
	}
	if o.Tool != SymbolUnreachabilityTool || o.ToolStatus != StatusOK {
		t.Fatalf("tool=%s status=%s", o.Tool, o.ToolStatus)
	}
	data, ok := o.Data.(map[string]any)
	if !ok {
		t.Fatalf("wire payload is %T, want decoded map", o.Data)
	}
	r, ok := data["result"].(map[string]any)
	if !ok {
		t.Fatalf("result missing: %v", data)
	}
	if r["complete"] != false {
		t.Fatalf("reachable symbol must not be complete: %v", r["complete"])
	}
	if r["declaration_complete"] != true {
		t.Fatalf("declaration_complete=%v", r["declaration_complete"])
	}
	if _, ok := r["not_affected"]; ok {
		t.Fatal("the payload must never carry a not-affected field")
	}
}

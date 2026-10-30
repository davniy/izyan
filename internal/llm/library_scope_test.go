package llm

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/goanalysis"
)

// TestToolLibraryInputWitnessRecorded: the trace_argument tool records the
// exact library public-formal payload binding through the evidence-first graph
// seam, keeps the deployment origin UNKNOWN, answers the model with the
// witness, and every persisted evidence reference resolves.
func TestToolLibraryInputWitnessRecorded(t *testing.T) {
	product, err := filepath.Abs(filepath.Join("..", "..", "testdata", "libassertprod"))
	if err != nil {
		t.Fatal(err)
	}
	ix := &goanalysis.Index{Dir: product}
	ctx := context.Background()
	shape, _, err := ix.BuildProductShape(ctx)
	if err != nil {
		t.Fatalf("BuildProductShape: %v", err)
	}
	if shape.Kind != domain.ProductShapeLibrary || !shape.CensusComplete {
		t.Fatalf("fixture is not a proven library: kind=%s complete=%t", shape.Kind, shape.CensusComplete)
	}
	sites, err := ix.FindCallers(ctx, domain.SymbolRef{
		Package: "example.com/dep/vuln", Symbol: "ParseBytes",
	})
	if err != nil {
		t.Fatalf("FindCallers: %v", err)
	}
	if len(sites) == 0 {
		t.Fatal("fixture has no sink call site")
	}
	site := sites[0]

	args, err := json.Marshal(map[string]any{
		"file":      site.File,
		"line":      site.Line,
		"column":    site.Column,
		"arg_index": 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	c := &domain.AnalysisCase{ID: "CASE-TOOL-LIBRARY"}
	res := (Tools{Source: ix}).Call(ctx, c, "trace_argument", args)
	if !res.OK {
		t.Fatalf("trace_argument failed: %s", res.Error)
	}

	var payload struct {
		DataFlows []domain.DataFlow `json:"data_flows"`
	}
	if err := json.Unmarshal(res.Content, &payload); err != nil {
		t.Fatalf("decode tool content: %v (%s)", err, res.Content)
	}
	if len(payload.DataFlows) != 1 || payload.DataFlows[0].LibraryInput == nil {
		t.Fatalf("tool content lacks the library witness: %s", res.Content)
	}
	w := payload.DataFlows[0].LibraryInput
	if w.API.Symbol != "YAMLEq" || w.FormalIndex != 1 || w.FormalName != "expected" {
		t.Fatalf("witness=%+v", w)
	}
	if payload.DataFlows[0].Origin != domain.OriginUnknown {
		t.Fatalf("tool flow origin=%s, want UNKNOWN", payload.DataFlows[0].Origin)
	}
	if w.Site != site {
		t.Fatalf("witness site=%+v, want exact tool site %+v", w.Site, site)
	}

	var stored *domain.DataFlow
	for i := range c.EvidenceGraph.DataFlows {
		if f := &c.EvidenceGraph.DataFlows[i]; f.LibraryInput != nil {
			stored = f
		}
	}
	if stored == nil {
		t.Fatal("the graph persisted no witnessed flow")
	}
	if stored.LibraryInput.Site != site || stored.LibraryInput.FormalIndex != 1 {
		t.Fatalf("persisted witness=%+v", stored.LibraryInput)
	}
	if len(stored.LibraryInput.EvidenceIDs) == 0 {
		t.Fatal("persisted witness references no evidence")
	}
	for _, id := range stored.LibraryInput.EvidenceIDs {
		if c.EvidenceGraph.EvidenceByID(id) == nil {
			t.Fatalf("witness references missing evidence %s", id)
		}
	}
	if res.EvidenceID == "" || c.EvidenceGraph.EvidenceByID(res.EvidenceID) == nil {
		t.Fatalf("tool returned unresolvable evidence id %q", res.EvidenceID)
	}
	foundWitnessRecord := false
	for _, id := range stored.LibraryInput.EvidenceIDs {
		if ev := c.EvidenceGraph.EvidenceByID(id); ev != nil &&
			strings.Contains(ev.Content, "api=example.com/libassertprod/assert.YAMLEq") {
			foundWitnessRecord = true
		}
	}
	if !foundWitnessRecord {
		t.Fatal("no witness evidence record names the API declaration")
	}
}

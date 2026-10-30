package triage

import (
	"context"
	"encoding/json"
	"testing"
)

// TestObservationIndexDedup: the index keeps one unambiguous pin per
// observation id — a repeated (cached) call re-emits the same id in the
// audit trail and the first recorded pin stays canonical.
func TestObservationIndexDedup(t *testing.T) {
	rt, _ := toolsFixture(t)
	rt.ObservationStore = NewRunObservationStore("run-test", 1)

	first := callTool(t, &rt, context.Background(), "list_files", map[string]any{})
	cached := callTool(t, &rt, context.Background(), "list_files", map[string]any{})
	if cached.ID != first.ID || !hasLimitation(cached, "served from cache") {
		t.Fatalf("cache replay = %+v, want %s served from cache", cached, first.ID)
	}
	other := callTool(t, &rt, context.Background(), "read_file", map[string]any{"path": "main.go"})

	events := rt.AuditEvents()
	if len(events) != 3 {
		t.Fatalf("audit events = %d, want 3 (every request audited)", len(events))
	}
	if events[0].ObservationID != first.ID || events[1].ObservationID != first.ID {
		t.Fatalf("cache replay must reuse the recorded id: %+v / %+v", events[0], events[1])
	}
	index := ObservationIndex(events)
	if len(index) != 2 {
		t.Fatalf("index = %d entries, want 2 unique observation ids", len(index))
	}
	pin := index[first.ID]
	if pin.DataSHA256 != first.DataSHA256 || pin.Tool != "list_files" {
		t.Fatalf("index[%q] = %+v, want the recorded pin", first.ID, pin)
	}
	if index[other.ID].Tool != "read_file" {
		t.Fatalf("index[%q] missing", other.ID)
	}
}

// TestDeterministicToolRefusalsStayAudited: a name the session catalog does
// not admit still produces one hash-only audit event and one recorded
// observation — the refusal is provenance, not a silent drop. The refused
// call keeps its argument pin so an auditor can tell which request was
// refused.
func TestDeterministicToolRefusalsStayAudited(t *testing.T) {
	store := NewRunObservationStore("run-audit", 1)
	d := &DeterministicTools{Catalog: fakeCatalog(), ObservationStore: store}
	ctx := context.Background()

	unavailable := d.Call(ctx, "run_build", json.RawMessage(`{"target":"linux"}`))
	unknown := d.Call(ctx, "no_such_tool", json.RawMessage(`{}`))
	if unavailable.Status != string(ToolStatusUnavailable) || unknown.Status != string(ToolStatusDenied) {
		t.Fatalf("statuses = %s/%s, want UNAVAILABLE/DENIED", unavailable.Status, unknown.Status)
	}

	events := d.AuditEvents()
	if len(events) != 2 {
		t.Fatalf("audit events = %d, want one per refused call", len(events))
	}
	if events[0].ObservationID != unavailable.ID || events[0].Tool != "run_build" ||
		events[0].Status != string(ToolStatusUnavailable) || events[0].ArgsSHA256 == "" {
		t.Fatalf("unavailable refusal audit = %+v", events[0])
	}
	if events[1].ObservationID != unknown.ID || events[1].Status != string(ToolStatusDenied) {
		t.Fatalf("unregistered refusal audit = %+v", events[1])
	}
	if got := store.Observations(); len(got) != 2 {
		t.Fatalf("recorded observations = %d, want one per refused call", len(got))
	}
}

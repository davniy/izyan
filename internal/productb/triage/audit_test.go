package triage

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func readAuditLines(t *testing.T, path string) []AuditEvent {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var events []AuditEvent
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var ev AuditEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("audit line is not valid JSON: %v: %s", err, line)
		}
		events = append(events, ev)
	}
	return events
}

func TestAuditEventsJSONL(t *testing.T) {
	out := t.TempDir()
	in, manifest, run, assessment := writeFixture(t)
	w := ArtifactWriter{Clock: artifactClock()}
	caller := []AuditEvent{
		{Type: AuditEventRunStarted, Status: "ok"},
		{Type: AuditEventToolCall, Tool: "read_file", ObservationID: "obs-0001",
			Status: "OK", ArgsSHA256: "a1", DataSHA256: "b2", Scope: "snapshot"},
	}
	art, err := w.Write(context.Background(), out, in, manifest, run, assessment, caller, nil)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	events := readAuditLines(t, art.AuditPath)
	if len(events) != 3 {
		t.Fatalf("events = %d, want 3 (2 caller + terminal)", len(events))
	}
	for i, ev := range events {
		if ev.Type == "" || ev.Timestamp.IsZero() || ev.RunID != art.RunID {
			t.Fatalf("event %d lacks type/timestamp/run_id: %+v", i, ev)
		}
		if ev.Status == "" && ev.Hash == "" {
			t.Fatalf("event %d has neither status nor hash: %+v", i, ev)
		}
	}
	// Caller order preserved, then the terminal artifact event pins the hashes.
	if events[0].Type != AuditEventRunStarted || events[1].Tool != "read_file" {
		t.Fatalf("caller events mangled: %+v", events)
	}
	last := events[2]
	if last.Type != AuditEventArtifactsWritten || last.Status != "ok" || last.Hash == "" {
		t.Fatalf("terminal event: %+v", last)
	}
	// The log must not leak raw source or arguments into serialized fields.
	raw, err := os.ReadFile(art.AuditPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"raw model reply", "package main", `"args"`, `"content"`} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("audit log leaks %q:\n%s", forbidden, raw)
		}
	}
}

func TestAuditEventsAppendOnly(t *testing.T) {
	out := t.TempDir()
	in, manifest, run, assessment := writeFixture(t)
	w := ArtifactWriter{Clock: artifactClock()}
	art1, err := w.Write(context.Background(), out, in, manifest, run, assessment, nil, nil)
	if err != nil {
		t.Fatalf("Write 1: %v", err)
	}
	art2, err := w.Write(context.Background(), out, in, manifest, run, assessment, nil, nil)
	if err != nil {
		t.Fatalf("Write 2: %v", err)
	}
	events := readAuditLines(t, art2.AuditPath)
	if len(events) != 2 {
		t.Fatalf("append-only log has %d events, want 2 terminal events", len(events))
	}
	if events[0].RunID != art1.RunID || events[1].RunID != art2.RunID || art1.RunID == art2.RunID {
		t.Fatalf("run IDs not distinct per write: %q vs %q", art1.RunID, art2.RunID)
	}
}

func TestAuditEventsToolCallMapping(t *testing.T) {
	rt, _ := toolsFixture(t)
	callTool(t, &rt, context.Background(), "read_file", map[string]any{"path": "main.go"})
	callTool(t, &rt, context.Background(), "exec_shell", map[string]any{"cmd": "id"})

	events := ToolAuditEvents(rt.AuditEvents(), time.Unix(1, 0).UTC())
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2", len(events))
	}
	ev := events[0]
	if ev.Type != AuditEventToolCall || ev.Tool != "read_file" || ev.Status != string(ToolStatusOK) {
		t.Fatalf("event = %+v", ev)
	}
	if ev.ObservationID == "" || ev.ArgsSHA256 == "" || ev.DataSHA256 == "" || ev.Scope == "" {
		t.Fatalf("event pins nothing: %+v", ev)
	}
	// read_file's payload embeds the file sha256: it must ride the event
	// as an inner hash, distinct from the envelope data_sha256.
	if len(ev.InnerSHA256) == 0 || ev.InnerSHA256[0] == ev.DataSHA256 {
		t.Fatalf("event lacks inner payload hashes: %+v", ev)
	}
	if ev.ReachEvidence {
		t.Fatalf("read_file is not reachability evidence: %+v", ev)
	}
	if ev.Timestamp.IsZero() {
		t.Fatal("timestamp not stamped")
	}
	if events[1].Status != string(ToolStatusDenied) {
		t.Fatalf("denied call not preserved: %+v", events[1])
	}
	// Only hashes survive: neither args nor payload text may appear.
	for i, e := range events {
		raw, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"main.go", `"cmd"`, `"args"`} {
			if strings.Contains(string(raw), forbidden) {
				t.Fatalf("event %d leaks %q: %s", i, forbidden, raw)
			}
		}
	}
}

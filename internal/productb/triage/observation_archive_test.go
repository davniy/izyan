package triage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestToolExecutorObservationsAreCollected pins that DeterministicTools and
// ToolSet both expose their recorded observations to the runner: without
// this delegation the archive stays empty, the build context is lost, and
// the falsifier verifier refuses to admit a proof. Parts sharing one store
// surface each recorded id exactly once — a repeated (cached) call never
// mints a second binding. (The V2 original also covered ReadOnlyTools,
// which is deferred to the S-06b slice.)
func TestToolExecutorObservationsAreCollected(t *testing.T) {
	store := NewRunObservationStore("run-test", 1)
	rec, ok := interface{}(store).(ObservationStore)
	if !ok {
		t.Fatal("observation store does not implement ObservationStore")
	}
	recordObservation(store, ToolObservation{ID: "obs-1", Tool: "read_file"})
	recordObservation(store, ToolObservation{ID: "det-1", Tool: "find_symbol"})
	if got := rec.Observations(); len(got) != 2 || got[0].ID != "obs-1" {
		t.Fatalf("store.Observations = %+v", got)
	}

	det := &DeterministicTools{ObservationStore: store}
	drec, ok := interface{}(det).(ObservationStore)
	if !ok {
		t.Fatal("DeterministicTools does not implement ObservationStore")
	}
	if got := drec.Observations(); len(got) != 2 {
		t.Fatalf("DeterministicTools.Observations = %+v", got)
	}

	set := &ToolSet{Parts: []ToolExecutor{&fakeExecutor{defs: []string{"read_file"}}, det}}
	srec, ok := interface{}(set).(ObservationStore)
	if !ok {
		t.Fatal("ToolSet does not implement ObservationStore")
	}
	if got := srec.Observations(); len(got) != 2 {
		t.Fatalf("ToolSet.Observations = %+v (want the 2 recorded ids once each)", got)
	}
}

// TestObservationStoreDedup: one observation id is one canonical archive
// entry — a repeated record (the cached-call path) keeps the first entry,
// while every request still produced its own audit event upstream.
func TestObservationStoreDedup(t *testing.T) {
	store := NewRunObservationStore("run-test", 1)
	payload := json.RawMessage(`{"total":3}`)
	sum := sha256.Sum256(payload)
	first := ToolObservation{ID: "obs-0001", Tool: "list_files", Status: ToolStatusOK,
		Data: payload, DataSHA256: hex.EncodeToString(sum[:])}
	recordObservation(store, first)
	// The cached replay re-records the same id, marked served from cache:
	// the archive keeps the canonical entry, limitations and all.
	replayed := first
	replayed.Limitations = []string{"served from cache"}
	recordObservation(store, replayed)
	recordObservation(store, ToolObservation{ID: "obs-0002", Tool: "read_file", Status: ToolStatusOK})

	got := store.Observations()
	if len(got) != 2 {
		t.Fatalf("observations = %d, want 2 (no duplicate id)", len(got))
	}
	if got[0].ID != "obs-0001" || len(got[0].Limitations) != 0 {
		t.Fatalf("canonical entry replaced by the replay: %+v", got[0])
	}

	// The written archive is deduplicated even for a slice store that
	// already contains duplicates.
	path := filepath.Join(t.TempDir(), "observation-archive.json")
	dup := observationSliceStore{items: []RecordedObservation{got[0], got[0], got[1]}}
	if err := WriteObservationArchive(context.Background(), path, dup); err != nil {
		t.Fatal(err)
	}
	a, err := ReadObservationArchive(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Observations) != 2 {
		t.Fatalf("archive observations = %d, want 2", len(a.Observations))
	}
}

// TestObservationArchiveRoundTripAndTamper: a persisted archive reloads
// hash-valid, and a payload that no longer matches its data_sha256 is a
// read error — a tampered archive can never feed locators.
func TestObservationArchiveRoundTripAndTamper(t *testing.T) {
	store := NewRunObservationStore("run-x", 1)
	recordObservation(store, ToolObservation{
		ID: "det-0001", Tool: "find_callers", Status: ToolStatusOK,
		Coverage: "COMPLETE",
		Data:     json.RawMessage(`{"count":2}`),
	})
	path := filepath.Join(t.TempDir(), "obs.json")
	if err := WriteObservationArchive(context.Background(), path, store); err != nil {
		t.Fatal(err)
	}
	a, err := ReadObservationArchive(path)
	if err != nil {
		t.Fatal(err)
	}
	if a.SchemaVersion != ObservationArchiveSchemaVersion || len(a.Observations) != 1 {
		t.Fatalf("archive = %+v", a)
	}
	o := a.Observations[0]
	if o.ID != "det-0001" || o.DataSHA256 == "" || o.Completeness != "COMPLETE" {
		t.Fatalf("observation = %+v", o)
	}
	if string(o.Payload) == "" {
		t.Fatalf("observation %s resolved no payload", o.ID)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, o.Payload); err != nil || compact.String() != `{"count":2}` {
		t.Fatalf("resolved payload = %s", o.Payload)
	}
	// Tamper with the archived payload while keeping its digest key: the
	// bytes no longer hash to the digest that names them, so the read fails.
	a.Payloads[o.DataSHA256] = json.RawMessage(`{"count":3}`)
	raw, _ := json.Marshal(a)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadObservationArchive(path); err == nil {
		t.Fatal("tampered archive must fail the data hash check")
	}
}

// TestArchiveDoesNotDuplicateFullPayload pins the archive's canonical-payload
// contract: the payload bytes are stored once, in the content-addressed
// payload table, and every observation entry references them by data_sha256.
// Two observations that produced identical bytes — the normal cache/repeat
// case — must not store the payload twice, and the archive carries no inline
// payload copy beside the table.
func TestArchiveDoesNotDuplicateFullPayload(t *testing.T) {
	// A unique marker makes the payload's stored occurrences countable.
	const marker = "canonical-payload-marker-6f1c2a"
	payload := json.RawMessage(`{"marker":"` + marker + `","count":2,"call_sites":[{"file":"main.go","line":3}]}`)
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])

	store := NewRunObservationStore("run-dedup", 1)
	// Two distinct observation ids with byte-identical payloads.
	recordObservation(store, ToolObservation{ID: "det-0001", Tool: "find_callers", Status: ToolStatusOK, Data: payload})
	recordObservation(store, ToolObservation{ID: "det-0002", Tool: "find_references", Status: ToolStatusOK, Data: payload})

	path := filepath.Join(t.TempDir(), "obs.json")
	if err := WriteObservationArchive(context.Background(), path, store); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := bytes.Count(raw, []byte(marker)); got != 1 {
		t.Fatalf("payload stored %d times, want exactly once\n%s", got, raw)
	}
	var wire struct {
		SchemaVersion string                       `json:"schema_version"`
		Payloads      map[string]json.RawMessage   `json:"payloads"`
		Observations  []map[string]json.RawMessage `json:"observations"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatalf("archive does not parse: %v", err)
	}
	if len(wire.Payloads) != 1 {
		t.Fatalf("payload table = %d entries, want the one canonical payload", len(wire.Payloads))
	}
	if _, ok := wire.Payloads[digest]; !ok {
		t.Fatalf("payload table is not keyed by the payload digest %s: %v", digest, wire.Payloads)
	}
	for _, entry := range wire.Observations {
		if inline, ok := entry["payload"]; ok && len(inline) > 0 {
			t.Fatalf("observation entry %s still carries an inline payload copy: %s", entry["id"], inline)
		}
		var got string
		if err := json.Unmarshal(entry["data_sha256"], &got); err != nil || got != digest {
			t.Fatalf("observation entry %s does not reference the canonical digest: %s", entry["id"], entry["data_sha256"])
		}
	}

	// The projection still resolves to the canonical bytes for every reader.
	a, err := ReadObservationArchive(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Observations) != 2 {
		t.Fatalf("archive observations = %d, want 2", len(a.Observations))
	}
	var want bytes.Buffer
	if err := json.Compact(&want, payload); err != nil {
		t.Fatal(err)
	}
	for _, o := range a.Observations {
		var got bytes.Buffer
		if err := json.Compact(&got, o.Payload); err != nil {
			t.Fatalf("observation %s resolved an unparsable payload: %v", o.ID, err)
		}
		if !bytes.Equal(got.Bytes(), want.Bytes()) || o.DataSHA256 != digest {
			t.Fatalf("observation %s did not resolve the canonical payload: %+v", o.ID, o)
		}
	}
}

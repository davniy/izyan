package triage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestIntakeText(t *testing.T) {
	input := "Scanner reported an overflow in example.org/library/parser.\nSee https://example.org/advisories/CVE-2099-0001 for details.\n"
	recs, err := ParseIntake(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseIntake: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	rec := recs[0]
	if rec.Format != IntakeText {
		t.Fatalf("format = %q, want %q", rec.Format, IntakeText)
	}
	// Raw and Text are the verbatim document bytes, framing whitespace
	// included — identity is bound to what was received, not a normalized form.
	if string(rec.Raw) != input {
		t.Fatalf("raw = %q, want verbatim input bytes %q", rec.Raw, input)
	}
	if rec.Text != input {
		t.Fatalf("text = %q, want verbatim %q", rec.Text, input)
	}
	if len(rec.Object) != 0 {
		t.Fatalf("text record must not carry an object: %v", rec.Object)
	}
	if rec.TicketHash != sha256Hex(t, rec.Raw) {
		t.Fatalf("ticket_hash = %q, want sha256 of raw %q", rec.TicketHash, sha256Hex(t, rec.Raw))
	}
	if rec.RecordIndex != 1 {
		t.Fatalf("record_index = %d, want 1", rec.RecordIndex)
	}
}

func TestIntakeJSONObject(t *testing.T) {
	input := `{"scanner": "example-scanner", "note": "overflow in example.org/library/parser"}`
	recs, err := ParseIntake(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseIntake: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	rec := recs[0]
	if rec.Format != IntakeJSON {
		t.Fatalf("format = %q, want %q", rec.Format, IntakeJSON)
	}
	if string(rec.Raw) != input {
		t.Fatalf("raw = %q, want %q", rec.Raw, input)
	}
	if rec.Object["scanner"] != "example-scanner" {
		t.Fatalf("object[scanner] = %v", rec.Object["scanner"])
	}
	if rec.Text != "" {
		t.Fatalf("json record must not carry text: %q", rec.Text)
	}
	if rec.TicketHash != sha256Hex(t, rec.Raw) {
		t.Fatalf("ticket_hash = %q", rec.TicketHash)
	}
}

// A tracker-shaped document must pass through the generic transport as an
// opaque object: fields like key/status/descriptionPlain are stored verbatim,
// never interpreted, and are not required either.
func TestIntakeTrackerDocumentStaysOpaque(t *testing.T) {
	input := `{"key":"EXAMPLE-1","status":"Open","fields":{"descriptionPlain":"see CVE-2099-0001"}}`
	recs, err := ParseIntake(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseIntake: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	rec := recs[0]
	if rec.Format != IntakeJSON {
		t.Fatalf("format = %q", rec.Format)
	}
	if rec.Object["key"] != "EXAMPLE-1" || rec.Object["status"] != "Open" {
		t.Fatalf("tracker fields must stay opaque in object: %v", rec.Object)
	}
	fields, ok := rec.Object["fields"].(map[string]any)
	if !ok || fields["descriptionPlain"] != "see CVE-2099-0001" {
		t.Fatalf("nested tracker payload must be preserved verbatim: %v", rec.Object["fields"])
	}
}

func TestIntakeJSONArray(t *testing.T) {
	elem1 := `{"id":"a","note":"first"}`
	elem2 := `{"id":"b","note":"second"}`
	input := "[\n  " + elem1 + ",\n  " + elem2 + "\n]"
	recs, err := ParseIntake(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseIntake: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2", len(recs))
	}
	for i, rec := range recs {
		if rec.Format != IntakeJSONArray {
			t.Fatalf("record %d: format = %q, want %q", i, rec.Format, IntakeJSONArray)
		}
		if rec.RecordIndex != i+1 {
			t.Fatalf("record %d: record_index = %d", i, rec.RecordIndex)
		}
		if rec.TicketHash != sha256Hex(t, rec.Raw) {
			t.Fatalf("record %d: ticket_hash = %q", i, rec.TicketHash)
		}
	}
	if string(recs[0].Raw) != elem1 || string(recs[1].Raw) != elem2 {
		t.Fatalf("raw element bytes not preserved: %q, %q", recs[0].Raw, recs[1].Raw)
	}
	if recs[0].Object["id"] != "a" || recs[1].Object["id"] != "b" {
		t.Fatalf("ids = %v, %v", recs[0].Object["id"], recs[1].Object["id"])
	}
}

func TestIntakeJSONL(t *testing.T) {
	line1 := `{"id":"a"}`
	line2 := `{"id":"b"}`
	input := line1 + "\n\n   \n" + line2 + "\n"
	recs, err := ParseIntake(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseIntake: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2 (blank lines must be skipped)", len(recs))
	}
	for i, rec := range recs {
		if rec.Format != IntakeJSONL {
			t.Fatalf("record %d: format = %q, want %q", i, rec.Format, IntakeJSONL)
		}
		if rec.TicketHash != sha256Hex(t, rec.Raw) {
			t.Fatalf("record %d: ticket_hash = %q", i, rec.TicketHash)
		}
	}
	if string(recs[0].Raw) != line1 || string(recs[1].Raw) != line2 {
		t.Fatalf("raw line bytes not preserved: %q, %q", recs[0].Raw, recs[1].Raw)
	}
	padded := `{"id":"a"}` + "\n" + `  {"id":"c"}  ` + "\n"
	paddedRecs, err := ParseIntake(strings.NewReader(padded))
	if err != nil {
		t.Fatalf("ParseIntake: %v", err)
	}
	if len(paddedRecs) != 2 {
		t.Fatalf("got %d records, want 2", len(paddedRecs))
	}
	// JSONL records preserve the whole line verbatim, spaces included.
	if string(paddedRecs[1].Raw) != `  {"id":"c"}  ` {
		t.Fatalf("jsonl raw = %q, want verbatim padded line", paddedRecs[1].Raw)
	}
	if paddedRecs[1].TicketHash == paddedRecs[0].TicketHash {
		t.Fatal("whitespace-padded line must have a distinct ticket_hash")
	}
	// record_index is the physical line number: line2 sits on line 4.
	if recs[0].RecordIndex != 1 || recs[1].RecordIndex != 4 {
		t.Fatalf("record_index = %d, %d; want 1 and 4", recs[0].RecordIndex, recs[1].RecordIndex)
	}
}

// stdin is an io.Reader like any other; a pipe-style reader must work.
func TestIntakeStdin(t *testing.T) {
	r, w := io.Pipe()
	go func() {
		fmt.Fprintf(w, "plain ticket text from stdin\n")
		w.Close()
	}()
	recs, err := ParseIntake(r)
	if err != nil {
		t.Fatalf("ParseIntake(stdin): %v", err)
	}
	if len(recs) != 1 || recs[0].Format != IntakeText {
		t.Fatalf("got %+v, want one text record", recs)
	}
	if recs[0].Text != "plain ticket text from stdin\n" {
		t.Fatalf("text = %q, want verbatim stdin bytes", recs[0].Text)
	}
}

func TestIntakeEmpty(t *testing.T) {
	for _, input := range []string{"", "  \n\t\n"} {
		_, err := ParseIntake(strings.NewReader(input))
		if err == nil {
			t.Fatalf("input %q: expected error", input)
		}
		if !strings.Contains(err.Error(), "empty") {
			t.Fatalf("input %q: error %q must report empty input", input, err)
		}
	}
}

func TestIntakeMalformed(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantSub string
	}{
		{"truncated object", `{"scanner": "example", "note":`, "line 1"},
		{"malformed jsonl line", `{"a":1}` + "\n\n" + `{"b":`, "line 3"},
		{"non-object jsonl line", `{"a":1}` + "\n" + `"just a string"`, "line 2"},
		{"jsonl text line", `{"a":1}` + "\n" + `not json at all`, "line 2"},
		{"jsonl array line", `{"a":1}` + "\n" + `[1,2]`, "line 2"},
		{"empty array", `[]`, "no records"},
		{"invalid array", `[{"a":1},`, "invalid JSON array"},
		{"array scalar element", `[{"a":1}, 42]`, "element 2"},
		{"array string element", `[{"a":1}, "oops"]`, "element 2"},
		{"array nested array element", `[{"a":1}, [1]]`, "element 2"},
		{"trailing record after array", `[{"a":1}]` + "\n" + `{"b":2}`, "invalid JSON array"},
		{"mixed array then text", `[{"a":1}]` + "\n" + `plain text tail`, "invalid JSON array"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseIntake(strings.NewReader(tc.input))
			if err == nil {
				t.Fatal("malformed input must be a technical error")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q must contain %q (record/line number)", err.Error(), tc.wantSub)
			}
		})
	}
}

func TestIntakeRecord(t *testing.T) {
	rec, err := ParseIntakeRecord([]byte(`  {"id":"a"}  `), 7)
	if err != nil {
		t.Fatalf("ParseIntakeRecord: %v", err)
	}
	if rec.Format != IntakeJSON || rec.RecordIndex != 7 {
		t.Fatalf("got format %q index %d", rec.Format, rec.RecordIndex)
	}
	// Whitespace around the record is part of its verbatim bytes.
	if string(rec.Raw) != `  {"id":"a"}  ` {
		t.Fatalf("raw = %q, want verbatim input", rec.Raw)
	}

	rec, err = ParseIntakeRecord([]byte("plain note"), 2)
	if err != nil {
		t.Fatalf("ParseIntakeRecord(text): %v", err)
	}
	if rec.Format != IntakeText || rec.Text != "plain note" || rec.RecordIndex != 2 {
		t.Fatalf("got %+v", rec)
	}

	for _, raw := range [][]byte{
		[]byte(`{"a":`),
		[]byte(`[1]`),
		[]byte("   "),
	} {
		if _, err := ParseIntakeRecord(raw, 3); err == nil {
			t.Fatalf("record %q: expected error", raw)
		} else if !strings.Contains(err.Error(), "record 3") {
			t.Fatalf("record %q: error %q must carry the record index", raw, err)
		}
	}
}

// The raw document identity is its preserved bytes plus a lowercase sha256
// that is bound to exactly those bytes.
func TestRawInputIdentity(t *testing.T) {
	src := []byte(`{"id":"a","detail":"x"}`)
	rec, err := ParseIntakeRecord(src, 1)
	if err != nil {
		t.Fatalf("ParseIntakeRecord: %v", err)
	}
	if rec.TicketHash != sha256Hex(t, rec.Raw) {
		t.Fatalf("ticket_hash = %q, want sha256 of raw", rec.TicketHash)
	}
	// Raw is an independent copy: mutating the caller's buffer must not move it.
	orig := bytes.Clone(rec.Raw)
	src[0] = 'X'
	if !bytes.Equal(rec.Raw, orig) {
		t.Fatal("Raw must be an independent copy of the record bytes")
	}
	// Identity is content-bound: a different record yields a different hash.
	other, err := ParseIntakeRecord([]byte(`{"id":"b","detail":"x"}`), 1)
	if err != nil {
		t.Fatalf("ParseIntakeRecord: %v", err)
	}
	if other.TicketHash == rec.TicketHash {
		t.Fatal("distinct records must have distinct ticket_hash")
	}
	// Identity binds the verbatim bytes: records differing only in
	// framing whitespace are different input documents.
	padded, err := ParseIntakeRecord([]byte(`  {"id":"a","detail":"x"}  `), 1)
	if err != nil {
		t.Fatalf("ParseIntakeRecord: %v", err)
	}
	if string(padded.Raw) != `  {"id":"a","detail":"x"}  ` {
		t.Fatalf("raw = %q, want verbatim bytes", padded.Raw)
	}
	if padded.TicketHash == rec.TicketHash {
		t.Fatal("whitespace-differing records must have distinct ticket_hash")
	}
	// Serialized form carries identity and decoded view, never raw bytes.
	enc, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var wire map[string]any
	if err := json.Unmarshal(enc, &wire); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, has := wire["raw"]; has {
		t.Fatalf("serialized RawIntake must not embed raw bytes: %s", enc)
	}
	for _, key := range []string{"ticket_hash", "format", "record_index", "object"} {
		if _, has := wire[key]; !has {
			t.Fatalf("serialized RawIntake misses %q: %s", key, enc)
		}
	}
	var back RawIntake
	if err := json.Unmarshal(enc, &back); err != nil {
		t.Fatalf("round-trip: %v", err)
	}
	if back.Format != IntakeJSON || back.TicketHash != rec.TicketHash {
		t.Fatalf("round-trip lost identity: %+v", back)
	}
}

func TestIntakeFormatUnmarshal(t *testing.T) {
	var f IntakeFormat
	if err := json.Unmarshal([]byte(`"jsonl"`), &f); err != nil {
		t.Fatalf("valid format rejected: %v", err)
	}
	if f != IntakeJSONL {
		t.Fatalf("format = %q", f)
	}
	if err := json.Unmarshal([]byte(`"bogus"`), &f); err == nil {
		t.Fatal("invalid format must be rejected")
	}
}

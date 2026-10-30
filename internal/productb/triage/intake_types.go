package triage

import (
	"encoding/json"
	"fmt"
)

// IntakeFormat identifies the transport framing of a RawIntake record. It
// describes how the bytes were carried, never what they mean.
type IntakeFormat string

const (
	IntakeText      IntakeFormat = "text"
	IntakeJSON      IntakeFormat = "json"
	IntakeJSONArray IntakeFormat = "json_array"
	IntakeJSONL     IntakeFormat = "jsonl"
)

func (f IntakeFormat) Valid() bool {
	switch f {
	case IntakeText, IntakeJSON, IntakeJSONArray, IntakeJSONL:
		return true
	}
	return false
}

func (f *IntakeFormat) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	candidate := IntakeFormat(s)
	if !candidate.Valid() {
		return fmt.Errorf("invalid intake format %q", s)
	}
	*f = candidate
	return nil
}

// RawIntake is one record of the generic Stage 0 intake transport. It keeps
// the record's original bytes and their identity hash plus the decoded
// transport view, so downstream stages can inspect content without losing
// provenance. It deliberately carries no tracker semantics: ticket key,
// status, assignee, workflow transitions and comment bodies are neither
// required nor interpreted — a tracker-shaped document is just an opaque
// JSON object or text.
type RawIntake struct {
	// Raw is the exact record bytes as received — never trimmed,
	// re-encoded, normalized or reserialized. For single-document input
	// it is the whole document; for jsonl it is the line (newline framing
	// excluded); for json_array it is the element verbatim.
	Raw []byte `json:"-"`
	// TicketHash is the lowercase hex sha256 of Raw — the identity of the
	// intake document regardless of the channel it arrived through.
	TicketHash string       `json:"ticket_hash"`
	Format     IntakeFormat `json:"format"`
	// RecordIndex is the record's 1-based position in the input: the array
	// element number for json_array, the physical line number for jsonl,
	// and 1 for single-record text/json input.
	RecordIndex int `json:"record_index"`
	// Object is the verbatim decoded JSON object for json/json_array/jsonl
	// records; nil for text.
	Object map[string]any `json:"object,omitempty"`
	// Text is the verbatim document body for text records; empty otherwise.
	Text string `json:"text,omitempty"`
}

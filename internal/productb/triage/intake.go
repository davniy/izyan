package triage

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// ParseIntake reads generic intake input: plain text, one JSON object, a
// JSON array of objects, or JSONL (one object per line; blank lines are
// skipped). stdin is just the reader. The transport makes no tracker
// assumptions and infers nothing: it splits input into records, preserves
// each record's exact bytes and computes its ticket_hash. Every malformed
// non-empty record is a technical error carrying its element or line
// number.
func ParseIntake(r io.Reader) ([]RawIntake, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, errors.New("empty intake input")
	}

	switch trimmed[0] {
	case '[':
		var elems []json.RawMessage
		if err := json.Unmarshal(trimmed, &elems); err != nil {
			return nil, fmt.Errorf("invalid JSON array: %w", err)
		}
		if len(elems) == 0 {
			return nil, errors.New("no records in intake input")
		}
		records := make([]RawIntake, 0, len(elems))
		for i, elem := range elems {
			var obj map[string]any
			if err := json.Unmarshal(elem, &obj); err != nil {
				return nil, fmt.Errorf("element %d: %w", i+1, err)
			}
			if obj == nil {
				return nil, fmt.Errorf("element %d: record must be a JSON object", i+1)
			}
			records = append(records, newRawIntake(elem, IntakeJSONArray, i+1, obj))
		}
		return records, nil
	case '{':
		var obj map[string]any
		if err := json.Unmarshal(trimmed, &obj); err == nil {
			return []RawIntake{newRawIntake(data, IntakeJSON, 1, obj)}, nil
		}
		// Not a single valid object: treat as JSONL so a malformed line
		// reports its line number.
		records := []RawIntake{}
		for i, line := range bytes.Split(data, []byte("\n")) {
			// The line is the verbatim record (newline framing excluded);
			// trim only decides blankness and feeds the JSON check.
			content := bytes.TrimSpace(line)
			if len(content) == 0 {
				continue
			}
			var obj map[string]any
			if err := json.Unmarshal(content, &obj); err != nil {
				return nil, fmt.Errorf("line %d: %w", i+1, err)
			}
			if obj == nil {
				return nil, fmt.Errorf("line %d: record must be a JSON object", i+1)
			}
			records = append(records, newRawIntake(line, IntakeJSONL, i+1, obj))
		}
		return records, nil
	default:
		return []RawIntake{newTextIntake(data, 1)}, nil
	}
}

// ParseIntakeRecord builds a RawIntake for one already-extracted record —
// e.g. a document body supplied via --ticket. index is the 1-based record
// position stored in RecordIndex. The record is classified on its own
// bytes: a JSON object, or verbatim text. Content that commits to JSON and
// fails (truncated object, nested array, scalar) is rejected.
func ParseIntakeRecord(raw []byte, index int) (RawIntake, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return RawIntake{}, fmt.Errorf("record %d: empty record", index)
	}
	if trimmed[0] == '[' {
		return RawIntake{}, fmt.Errorf("record %d: expected a JSON object or text, got a JSON array", index)
	}
	if trimmed[0] == '{' {
		var obj map[string]any
		if err := json.Unmarshal(trimmed, &obj); err != nil {
			return RawIntake{}, fmt.Errorf("record %d: %w", index, err)
		}
		return newRawIntake(raw, IntakeJSON, index, obj), nil
	}
	return newTextIntake(raw, index), nil
}

// newRawIntake preserves the record bytes verbatim and binds the record's
// identity (ticket_hash) to exactly those bytes, whitespace included.
func newRawIntake(raw []byte, format IntakeFormat, index int, obj map[string]any) RawIntake {
	raw = bytes.Clone(raw)
	return RawIntake{
		Raw:         raw,
		TicketHash:  hashBytes(raw),
		Format:      format,
		RecordIndex: index,
		Object:      obj,
	}
}

func newTextIntake(raw []byte, index int) RawIntake {
	rec := newRawIntake(raw, IntakeText, index, nil)
	rec.Text = string(rec.Raw)
	return rec
}

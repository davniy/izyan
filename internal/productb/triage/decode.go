package triage

import (
	"strings"
)

// DecodeAssessment extracts and validates assessment.v2 from an agent
// response; wantFindingID binds the response identity to the input
// finding — an empty or mismatched finding_id is a technical error, never
// silently corrected. Only the current schema is accepted: historical
// assessment.v1 records are read by offline history extractors, never
// re-admitted here.
//
// Ingress is strict: bare-string claims, free-form claim status and every
// machine-owned annotation are rejected, and the decoded human assessment
// must satisfy ValidateHumanAssessment. A claim citing an evidence id the
// assessment never declared is a structural error too: it fails decode
// (not the fact gate) so the repair turn can fix it. The same holds for
// falsifier proposals: per-entry strictness is enforced by
// FalsifierProposal itself during decode, and a duplicate proposal id, a
// dangling claim_id/evidence_refs binding or a proposal evidence entry
// without a canonical det:<observation-id> locator fails here.
//
// This is the proposal-only ingress required by S-06: the agent describes
// what to verify and what it recommends to a human, never the outcome —
// nothing here creates a verdict, a Claim, a NegativeVerification, a
// machine disposition or any other Product A authority object.
func DecodeAssessment(content, wantFindingID string) (Assessment, error) {
	return decodeAssessment(content, wantFindingID)
}

// decodeAssessment, canonicalDetLocator, canonicalObservationID,
// extractJSON and jsonSpan are the canonical V2 implementations carried by
// runner.go; the exported DecodeAssessment is the adapter boundary.

// looksTruncatedJSON reports whether the response opens a JSON object or
// array that never closes — a cut-off answer rather than a formatting slip.
// Ported from V2 internal/llm (Shadow's llm package has no equivalent); it
// uses the string-aware span scan so a brace inside a quoted value never
// ends the span early.
func looksTruncatedJSON(s string) bool {
	start := strings.IndexAny(s, "{[")
	if start < 0 {
		return false
	}
	return jsonSpan(s[start:]) == ""
}

// extractJSON pulls the first balanced JSON object/array out of an agent
// response, tolerating ```json fences and surrounding prose. This is the
// V2 extraction semantics: a string-aware span scan, not the
// first-brace-to-last-brace slice — the decode contract (walk candidates
// until assessment.v2) depends on it.
func extractJSON(s string) string {
	// Candidate 1: the first top-level object or array located by a
	// string-aware brace scan. This is the primary path: it survives
	// markdown fences, surrounding prose and — crucially — code fences the
	// model quotes *inside* JSON strings, which a naive "first ``` to next
	// ```" slice truncates into invalid JSON.
	if c := jsonSpan(s); c != "" {
		return c
	}
	// Candidate 2: the fence contents, for the rare case where the model
	// wrapped something the scanner could not delimit (e.g. one fence
	// containing several objects).
	if i := strings.Index(s, "```"); i >= 0 {
		rest := s[i:]
		if j := strings.Index(rest, "\n"); j >= 0 {
			rest = rest[j+1:]
			if k := strings.LastIndex(rest, "```"); k >= 0 {
				if c := jsonSpan(rest[:k]); c != "" {
					return c
				}
				return strings.TrimSpace(rest[:k])
			}
		}
	}
	return ""
}

// jsonSpan returns the first balanced JSON object or array in s, scanning
// with string and escape awareness so a brace inside a quoted value never
// ends the span early. Truncated input yields "".
func jsonSpan(s string) string {
	start := -1
	var open, close byte
	depth := 0
	inString := false
	escaped := false
	for i := range len(s) {
		c := s[i]
		if start < 0 {
			if c != '{' && c != '[' {
				continue
			}
			start = i
			open = c
			if c == '{' {
				close = '}'
			} else {
				close = ']'
			}
			depth = 1
			continue
		}
		if inString {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case open:
			depth++
		case close:
			depth--
			if depth == 0 {
				return strings.TrimSpace(s[start : i+1])
			}
		}
	}
	return ""
}

package triage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
)

// ToolAuditEvent is one line of the tool-call audit trail. It pins each call
// by hashes only: raw arguments, file paths, file content and advisory text
// are never copied into the event, so the log cannot leak secrets embedded
// in untrusted inputs.
type ToolAuditEvent struct {
	ObservationID string `json:"observation_id"`
	Tool          string `json:"tool"`
	Status        string `json:"status"`
	// Coverage carries the observation's completeness marker verbatim
	// ("COMPLETE"/"PARTIAL"/"UNKNOWN" for deterministic tools, free-text
	// coverage notes for snapshot tools) so the fact gate can refuse to
	// verify a citation against an observation that proved nothing.
	Coverage   string `json:"coverage,omitempty"`
	ArgsSHA256 string `json:"args_sha256,omitempty"`
	DataSHA256 string `json:"data_sha256,omitempty"`
	// InnerSHA256 lists every sha256-like token found inside the observed
	// data payload (e.g. hashes embedded in evidence refs or returned
	// documents). A det:<id> citation pinning one of these still verifies
	// — the hash is real, it just names an inner blob rather than the
	// observation envelope.
	InnerSHA256 []string `json:"inner_sha256,omitempty"`
	// ReachEvidence marks an observation that positively establishes
	// reachability or usage of the vulnerable code. The classification is the
	// observed check's registry observation class (evidencetools.EvidenceClass)
	// decoded from its typed payload — never a broker-side tool-name allowlist,
	// and never a positive reading of an empty or failed result. The
	// decision-fact providers carry it so a package records whether a positive
	// reachability observation exists, never as a substitute for an admitted
	// proof.
	ReachEvidence bool     `json:"reach_evidence,omitempty"`
	Scope         string   `json:"scope,omitempty"`
	Limitations   []string `json:"limitations,omitempty"`
}

// ObservationPin is the audit-side fingerprint of one recorded tool
// observation: its recorded status and coverage, the sha256 of its data
// envelope plus every sha256-like token inside that payload, the producing
// tool, and whether the payload is positive reachability/usage evidence.
// Status and Coverage ride the pin so a det:<id>/obs:<id> citation can
// never verify against a call that produced no fact — a DENIED, ERROR,
// TIMEOUT or UNSUPPORTED outcome, or a check that only partially ran.
type ObservationPin struct {
	Status        string
	Coverage      string
	DataSHA256    string
	InnerSHA256   []string
	Tool          string
	ReachEvidence bool
}

// ObservationIndex maps every audited tool observation id onto its
// ObservationPin (DataSHA256 is empty when the call carried no payload). It
// is the index observation locators (`det:<id>`, `obs:<id>` or the bare
// audited id) verify against — resolved case-insensitively with '_'
// folded to '-', only when the match is unambiguous: both
// DeterministicTools and ReadOnlyTools feed it through the same per-call
// audit trail, and replay rebuilds the identical index from
// audit/events.jsonl. A repeated (cached) call re-emits the same
// observation id; the first recorded pin is canonical and later duplicates
// never overwrite it.
func ObservationIndex(events []ToolAuditEvent) map[string]ObservationPin {
	out := map[string]ObservationPin{}
	for _, e := range events {
		if e.ObservationID == "" {
			continue
		}
		if _, dup := out[e.ObservationID]; dup {
			continue
		}
		out[e.ObservationID] = ObservationPin{
			Status:        e.Status,
			Coverage:      e.Coverage,
			DataSHA256:    e.DataSHA256,
			InnerSHA256:   e.InnerSHA256,
			Tool:          e.Tool,
			ReachEvidence: e.ReachEvidence,
		}
	}
	return out
}

// sha256Token matches a 64-hex-digit token delimited by non-word bytes —
// the shape of a sha256 hash wherever it appears inside an observation
// payload (evidence_refs, embedded documents, advisory records).
var sha256Token = regexp.MustCompile(`(?i)\b[0-9a-f]{64}\b`)

// innerSHA256s enumerates the distinct lowercase sha256-like tokens inside
// a serialized observation payload. Extraction is purely lexical: the gate
// uses the set for hash tolerance, never to identify what a hash refers to.
func innerSHA256s(data json.RawMessage) []string {
	if len(data) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, m := range sha256Token.FindAll(data, -1) {
		s := strings.ToLower(string(m))
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// toolAuditEvent renders the audit event for one finished observation. It
// carries pins and classifications only — arguments, paths and payload
// content stay out of the log.
func toolAuditEvent(obs ToolObservation, args json.RawMessage) ToolAuditEvent {
	ev := ToolAuditEvent{
		ObservationID: obs.ID,
		Tool:          obs.Tool,
		Status:        obs.Status,
		Coverage:      obs.Coverage,
		DataSHA256:    obs.DataSHA256,
		InnerSHA256:   obs.innerSHA,
		ReachEvidence: obs.reachEvidence,
		Scope:         obs.Scope,
		Limitations:   obs.Limitations,
	}
	if len(args) > 0 {
		sum := sha256.Sum256(args)
		ev.ArgsSHA256 = hex.EncodeToString(sum[:])
	}
	return ev
}

// recordAudit appends the event for a finished observation. It is called
// from Call's deferred hook, including for DENIED and malformed calls —
// every decision is auditable.
func (r *ReadOnlyTools) recordAudit(obs ToolObservation, args json.RawMessage) {
	r.events = append(r.events, toolAuditEvent(obs, args))
}

package flow

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/davniy/izyan/internal/evidencetools"
)

// AuditedCallFunc is the only execution path the broker knows: one
// typed evidence-session call that additionally returns the session
// audit record the call appended. EvidenceSession.CallWithAudit has
// this exact shape. A nil audit record means the session did not
// record the call at all; such observations stay recorded but can
// never discharge a required check.
type AuditedCallFunc func(ctx context.Context, tool string, args json.RawMessage) (*evidencetools.Observation, *evidencetools.AuditRecord, error)

// AnswerAwareCatalog is the optional interface a check catalog
// implements to declare that an observation payload answers a check's
// question positively — a bounded yes the check's own contract marks
// below COMPLETE (package-usage reports USED at PARTIAL: positive
// static usage never claims runtime execution). The session catalog
// owns the check semantics; the broker only stamps the path the
// catalog reports onto the recorded observation. When the catalog
// does not implement it, no observation is a positive answer and the
// closed-negative (COMPLETE) discharge path stands unchanged.
type AnswerAwareCatalog interface {
	PositiveAnswer(o *evidencetools.Observation) bool
}

// dischargePathOf names the answer path one recorded observation
// carries: a complete closed-scope OK observation is a closed negative;
// an OK observation the catalog calls a positive answer takes the
// positive path. Anything else answers nothing.
func (b *SessionBroker) dischargePathOf(o *evidencetools.Observation) string {
	if o == nil || o.ToolStatus != evidencetools.StatusOK {
		return ""
	}
	if o.Completeness == evidencetools.CompletenessComplete {
		return DischargeClosedNegative
	}
	if ac, ok := b.catalog.(AnswerAwareCatalog); ok && ac.PositiveAnswer(o) {
		return DischargePositiveAnswer
	}
	return ""
}

// SessionBroker is the Broker over the confined evidence session:
// every action is admitted through the session-scoped, capability-gated
// check catalog before dispatch, executes inside the session's own
// audit trail through Call, and is bound back to what the session
// recorded. The broker enforces the catalog's per-check MaxCalls bound
// across the whole run. It introduces no shell and no arbitrary
// process path — Call is the same MCP surface the deterministic lane
// uses.
type SessionBroker struct {
	catalog evidencetools.CheckCatalog
	call    AuditedCallFunc
	calls   map[string]int
}

// NewSessionBroker builds the broker over one session-scoped catalog
// and one audited call path. Both are required — a broker without
// admission or without an audit trail cannot exist.
func NewSessionBroker(cat evidencetools.CheckCatalog, call AuditedCallFunc) (*SessionBroker, error) {
	if cat == nil {
		return nil, fmt.Errorf("flow: broker requires a check catalog")
	}
	if call == nil {
		return nil, fmt.Errorf("flow: broker requires an audited session call")
	}
	return &SessionBroker{catalog: cat, call: call, calls: map[string]int{}}, nil
}

// Execute admits and performs one action. Admission is fail-closed in
// catalog order: unregistered check, per-check call bound exceeded,
// capability denied, or arguments outside the check's declared schema.
// After the call, the session audit record must bind the dispatched
// tool and arguments to the returned observation — a missing or
// mismatched record leaves the observation recorded but unbound. Tool
// failures propagate as errors; ERROR/TIMEOUT/UNSUPPORTED statuses are
// observations, not broker errors.
func (b *SessionBroker) Execute(ctx context.Context, a PlanAction) (Observation, error) {
	spec, ok := b.catalog.Lookup(a.AdapterID)
	if !ok {
		if verr := b.catalog.Validate(a.AdapterID, a.Arguments); verr != nil {
			return Observation{}, fmt.Errorf("adapter %q cannot be scheduled: %w", a.AdapterID, verr)
		}
		return Observation{}, fmt.Errorf("adapter %q is not registered in the check catalog", a.AdapterID)
	}
	if spec.MaxCalls > 0 && b.calls[a.AdapterID] >= spec.MaxCalls {
		return Observation{}, fmt.Errorf("adapter %q exceeded its per-check call bound %d", a.AdapterID, spec.MaxCalls)
	}
	if err := b.catalog.Validate(a.AdapterID, a.Arguments); err != nil {
		return Observation{}, fmt.Errorf("adapter %q rejected the action arguments: %w", a.AdapterID, err)
	}
	b.calls[a.AdapterID]++
	obs, rec, err := b.call(ctx, spec.Tool, a.Arguments)
	if err != nil {
		return Observation{}, err
	}
	return b.bindObservation(a, spec.Tool, obs, rec)
}

// bindObservation projects one session observation into the flow
// envelope and binds it to the session audit record. The audit record
// is authoritative for which tool ran with which arguments; the
// digest pins the audit-recorded observation bytes (matching the
// lane's canonical encoding), so a swapped or mutated tool result is
// visible rather than silently carried. A missing audit record, a tool
// or argument mismatch, or a differing observation id is a binding
// failure — the observation is returned with AuditBound=false and a
// recorded limitation, never with fabricated status. A missing
// observation entirely is an error: nothing was produced to record.
// DischargePath records which answer path the recorded payload
// carries (the catalog's own verdict via AnswerAwareCatalog) — the
// discharge gate downstream enforces the binding requirements.
func (b *SessionBroker) bindObservation(a PlanAction, tool string, obs *evidencetools.Observation, rec *evidencetools.AuditRecord) (Observation, error) {
	recorded := obs
	if rec != nil && rec.Observation != nil {
		recorded = rec.Observation
	}
	if recorded == nil {
		return Observation{}, fmt.Errorf("action %q produced no session observation", a.ID)
	}
	out := Observation{
		ID:           recorded.ID,
		ActionID:     a.ID,
		Status:       string(recorded.ToolStatus),
		Completeness: string(recorded.Completeness),
		Scope:        recorded.Scope,
		EvidenceRefs: append([]string(nil), recorded.EvidenceRefs...),
		Limitations:  append([]string(nil), recorded.Limitations...),
		// The answer path describes the recorded payload alone — the
		// catalog owns the check semantics; audit binding and the
		// digest decide discharge downstream.
		DischargePath: b.dischargePathOf(recorded),
	}
	if digest, derr := observationDigest(recorded); derr == nil {
		out.DataDigest = digest
	}
	if obs != nil && rec != nil && rec.Observation != nil && obs != rec.Observation {
		out.Limitations = append(out.Limitations,
			"session audit record carries a different observation than the call returned; the audit-recorded copy is authoritative")
	}
	if rec == nil {
		out.Limitations = append(out.Limitations,
			"session audit ledger has no record of this call: the observation is unbound")
		return out, nil
	}
	out.AuditBound = true
	if rec.Tool != tool {
		out.AuditBound = false
		out.Limitations = append(out.Limitations,
			fmt.Sprintf("session audit record names tool %q, not the dispatched %q: the observation belongs to a different call", rec.Tool, tool))
	}
	if !bytes.Equal(canonicalArgs(rec.Args), canonicalArgs(a.Arguments)) {
		out.AuditBound = false
		out.Limitations = append(out.Limitations,
			"session audit-recorded arguments differ from the dispatched request: the observation belongs to a different call")
	}
	if obs != nil && obs.ID != "" && rec.Observation != nil && rec.Observation.ID != "" && rec.Observation.ID != obs.ID {
		out.AuditBound = false
		out.Limitations = append(out.Limitations,
			"session audit record carries a different observation id than the call returned")
	}
	return out, nil
}

// canonicalArgs renders request arguments in canonical JSON form so
// byte-identity comparisons survive transport re-encoding — the same
// rule the verification lane applies. Non-JSON input compares verbatim.
func canonicalArgs(raw json.RawMessage) []byte {
	if len(raw) == 0 {
		return nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return raw
	}
	b, err := json.Marshal(v)
	if err != nil {
		return raw
	}
	return b
}

// observationDigest pins the recorded observation bytes with the same
// canonical encoding the lane digests into its fact envelope
// (MarshalIndent payload, no trailing newline), so a flow observation
// resolves to the same digest a promoted fact would.
func observationDigest(o *evidencetools.Observation) (string, error) {
	b, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

package triage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/fedorovmv/izyan/internal/evidencetools"
	"github.com/fedorovmv/izyan/internal/llm"
)

// DetCaller is the invocation surface of an evidencetools session — in
// Shadow the in-memory *evidencetools.Client, adapted by ClientCaller. The
// interface keeps the triage broker testable without a real snapshot
// session.
type DetCaller interface {
	CallTool(ctx context.Context, name string, args json.RawMessage) (*evidencetools.Observation, error)
}

const (
	// detDefaultCallTimeout is the per-call deadline applied when the
	// caller left CallTimeout zero; deterministic tools run subprocesses
	// (go list, govulncheck) that must never stall the run.
	detDefaultCallTimeout = 240 * time.Second
)

// DeterministicTools brokers the session-resolved evidencetools catalog for
// one agent run: the catalog entries are exactly the checks the session
// reports with availability, and there is no second capability list here.
// Every advertised name, description, argument schema and cost bound is the
// catalog's own contract; the observation class the catalog publishes is what
// classifies a completed payload as positive reachability/usage evidence.
// Every call maps the tool's Observation onto a ToolObservation: the full
// Observation JSON is the Data payload (DataSHA256 pins it), its
// status/completeness carry over, and results are cached by (name,args) — a
// repeated call replays the stored observation marked "served from cache"
// rather than re-running the check. Call is not safe for concurrent use:
// the agent loop issues tool calls sequentially.
type DeterministicTools struct {
	Caller  DetCaller
	Catalog []DetToolInfo
	// CallTimeout is the per-call deadline; 0 selects
	// detDefaultCallTimeout.
	CallTimeout time.Duration
	// ObservationStore receives full observation payloads; audit remains hash-only.
	ObservationStore ObservationStore

	seq      int
	runCalls map[string]int
	cache    map[string]*ToolObservation
	events   []ToolAuditEvent
}

var _ ToolExecutor = (*DeterministicTools)(nil)

// Definitions advertises the catalog entries the session resolves as
// available, in deterministic (sorted) order. An unavailable entry is never
// advertised, and nothing is admitted by name alone: adding a read-only
// capability to the session is enough to make it appear here.
func (d *DeterministicTools) Definitions() []llm.ToolDefinition {
	var defs []llm.ToolDefinition
	for _, info := range d.Catalog {
		if !info.Available {
			continue
		}
		defs = append(defs, toolDefinition(info.ToolContract))
	}
	sort.Slice(defs, func(i, j int) bool { return defs[i].Function.Name < defs[j].Function.Name })
	return defs
}

// toolDefinition projects one registry contract onto the agent-facing tool
// definition. Both the evidence-session catalog and the snapshot/material
// registry go through it, so the model sees one contract shape.
func toolDefinition(c evidencetools.ToolContract) llm.ToolDefinition {
	return llm.ToolDefinition{
		Type: "function",
		Function: llm.FunctionSpec{
			Name:        c.Name,
			Description: c.Description,
			Parameters:  append(json.RawMessage(nil), c.InputSchema...),
		},
	}
}

// catalogEntry resolves name against the session catalog. A name the catalog
// does not register and a registered-but-unavailable capability are distinct
// refusals: the first is a policy denial, the second names the missing
// session capability.
func (d *DeterministicTools) catalogEntry(name string) (DetToolInfo, bool) {
	for _, info := range d.Catalog {
		if info.Name == name {
			return info, true
		}
	}
	return DetToolInfo{}, false
}

// Call executes one available evidence tool with a per-call deadline and
// appends a ToolAuditEvent. The catalog is the admission gate: an
// unregistered name is DENIED, a registered capability this session does not
// hold is UNAVAILABLE with the session's reason (no dispatch ever happens),
// and a call beyond the contract's MaxRunCalls cost bound is ERROR with a
// limitation. A shared deadline is preserved as TIMEOUT, never folded into
// ERROR.
func (d *DeterministicTools) Call(ctx context.Context, name string, args json.RawMessage) (obs ToolObservation) {
	d.seq++
	obs = ToolObservation{ID: observationID("det", d.seq, d.ObservationStore), Tool: name}
	defer func() { d.recordAudit(obs, args); recordObservation(d.ObservationStore, obs) }()
	if err := ctx.Err(); err != nil {
		obs.Status = string(contextStatus(err))
		obs.Limitations = []string{"tool call aborted before dispatch"}
		return obs
	}
	info, known := d.catalogEntry(name)
	if !known {
		obs.Status = string(ToolStatusDenied)
		obs.Limitations = []string{"tool is not declared in this session's evidence catalog"}
		return obs
	}
	if !info.Available {
		reason := info.UnavailableReason
		if reason == "" {
			reason = "required session capability is unavailable"
		}
		obs.Status = string(ToolStatusUnavailable)
		obs.Limitations = []string{"capability unavailable in this session: " + reason}
		return obs
	}
	if d.Caller == nil {
		obs.Status = string(ToolStatusUnavailable)
		obs.Limitations = []string{"no evidence session configured"}
		return obs
	}
	key := cacheKey(name, args)
	if hit, ok := d.cache[key]; ok {
		out := *hit
		out.Limitations = append(append([]string(nil), hit.Limitations...), "served from cache")
		return out
	}
	if limit := info.MaxRunCalls; limit > 0 && d.runCalls[name] >= limit {
		obs.Status = string(ToolStatusError)
		obs.Limitations = []string{fmt.Sprintf("%s invocation limit reached (%d per run)", name, limit)}
		return obs
	}
	if info.MaxRunCalls > 0 {
		if d.runCalls == nil {
			d.runCalls = map[string]int{}
		}
		d.runCalls[name]++
	}

	callCtx := ctx
	cancel := context.CancelFunc(func() {})
	timeout := d.CallTimeout
	if timeout == 0 {
		timeout = detDefaultCallTimeout
	}
	callCtx, cancel = context.WithTimeout(ctx, timeout)
	defer cancel()

	raw, err := d.Caller.CallTool(callCtx, name, args)
	if err != nil {
		// A caller that returns the context error (or ran past the
		// deadline) is a terminated call, not a tool-side failure.
		st := contextStatus(err)
		if ctxErr := callCtx.Err(); ctxErr != nil {
			st = contextStatus(ctxErr)
		}
		obs.Status = string(st)
		obs.Limitations = []string{fmt.Sprintf("evidence tool call failed: %v", err)}
		return obs
	}
	if raw == nil {
		obs.Status = string(ToolStatusError)
		obs.Limitations = []string{"evidence tool returned no observation"}
		return obs
	}
	mapped := mapObservation(obs.ID, raw, info.Evidence)
	// A deadline that fired during the call relabels a tool-side ERROR as
	// TIMEOUT — the check did not finish, which is exactly what the agent
	// must read from the status.
	if ctxErr := callCtx.Err(); ctxErr != nil && mapped.Status == string(ToolStatusError) {
		mapped.Status = string(contextStatus(ctxErr))
		mapped.Limitations = append(mapped.Limitations, "call context terminated before the check completed")
	}
	mapped.archiveData = append(json.RawMessage(nil), mapped.Data...)
	mapped = capObservation(mapped)
	if mapped.Status == string(ToolStatusOK) {
		// Only a completed check is deduplicated: an error, timeout or
		// unsupported outcome produced no fact and must not replay as
		// the recorded result of the next identical request.
		if d.cache == nil {
			d.cache = map[string]*ToolObservation{}
		}
		d.cache[key] = &mapped
	}
	return mapped
}

// cacheKey pins a call by tool name plus the verbatim argument bytes.
func cacheKey(name string, args json.RawMessage) string {
	sum := sha256.Sum256(args)
	return name + "\x00" + hex.EncodeToString(sum[:])
}

// mapObservation converts an evidence Observation into the agent-facing
// ToolObservation: the serialized Observation itself is the payload, so
// fact/scope_details/evidence_refs reach the agent verbatim while status
// and completeness map onto the triage fields. The reachability/usage
// classification is the registered check's observation class, decoded from
// the typed payload — never a broker-side tool-name allowlist.
func mapObservation(id string, raw *evidencetools.Observation, class evidencetools.EvidenceClass) ToolObservation {
	out := ToolObservation{ID: id, Tool: raw.Tool}
	switch raw.ToolStatus {
	case evidencetools.StatusOK:
		out.Status = string(ToolStatusOK)
	case evidencetools.StatusUnsupported:
		out.Status = string(ToolStatusUnsupported)
	default:
		out.Status = string(ToolStatusError)
	}
	out.Scope = raw.Scope
	out.Coverage = string(raw.Completeness)
	out.Limitations = append([]string(nil), raw.Limitations...)
	data, err := json.Marshal(raw)
	if err != nil {
		out.Status = string(ToolStatusError)
		out.Limitations = append(out.Limitations, fmt.Sprintf("observation marshal failed: %v", err))
		return out
	}
	out.Data = data
	sum := sha256.Sum256(data)
	out.DataSHA256 = hex.EncodeToString(sum[:])
	// Pin the payload before the size cap can truncate it: inner hashes
	// and the reachability classification refer to the full recorded
	// payload, and both ride the audit event into the fact gate index.
	out.innerSHA = innerSHA256s(data)
	out.reachEvidence = evidencetools.PositiveEvidence(class, raw)
	return out
}

// AuditEvents returns a copy of the tool-audit trail accumulated so far.
func (d *DeterministicTools) AuditEvents() []ToolAuditEvent {
	return append([]ToolAuditEvent(nil), d.events...)
}

// recordAudit appends the event for a finished observation — the deferred
// hook covers DENIED, cached and failed calls alike.
func (d *DeterministicTools) recordAudit(obs ToolObservation, args json.RawMessage) {
	d.events = append(d.events, toolAuditEvent(obs, args))
}

// HasDeterministicTools reports whether ex exposes deterministic evidence
// tools to the agent (the prompt's DETERMINISTIC TOOLS block follows it).
func HasDeterministicTools(ex ToolExecutor) bool {
	switch v := ex.(type) {
	case *DeterministicTools:
		return v != nil
	case *ToolSet:
		for _, p := range v.Parts {
			if HasDeterministicTools(p) {
				return true
			}
		}
	}
	return false
}

// ToolSet is a composite ToolExecutor: it advertises the union of its
// parts' definitions and routes each Call to the part that declared the
// tool name. A name no part declared yields a DENIED observation. Call is
// not safe for concurrent use.
type ToolSet struct {
	Parts []ToolExecutor
	// ObservationStore receives observations produced by routing denials and
	// optionally aggregates child stores when explicitly configured.
	ObservationStore ObservationStore

	prep   bool
	seq    int
	routes map[string]ToolExecutor
	events []ToolAuditEvent
}

var _ ToolExecutor = (*ToolSet)(nil)

// Definitions merges the parts' tool definitions in deterministic (sorted)
// order; on a name collision the first part in Parts wins, matching the
// routing order.
func (s *ToolSet) Definitions() []llm.ToolDefinition {
	seen := map[string]bool{}
	var defs []llm.ToolDefinition
	for _, p := range s.Parts {
		if p == nil {
			continue
		}
		for _, d := range p.Definitions() {
			if seen[d.Function.Name] {
				continue
			}
			seen[d.Function.Name] = true
			defs = append(defs, d)
		}
	}
	sort.Slice(defs, func(i, j int) bool { return defs[i].Function.Name < defs[j].Function.Name })
	return defs
}

// Call dispatches to the part that declared the tool. The routing decision
// itself is auditable: an undeclared name records a DENIED event on the
// ToolSet rather than disappearing into a part's trail.
func (s *ToolSet) Call(ctx context.Context, name string, args json.RawMessage) ToolObservation {
	s.prepare()
	if ex, ok := s.routes[name]; ok {
		return ex.Call(ctx, name, args)
	}
	s.seq++
	obs := ToolObservation{ID: fmt.Sprintf("set-%04d", s.seq), Tool: name}
	if deferredTools[name] {
		obs.Status = string(ToolStatusUnsupported)
		obs.Limitations = []string{"tool is recognized but deferred in this build"}
	} else {
		obs.Status = string(ToolStatusDenied)
		obs.Limitations = []string{"unknown tool; only the declared tools may run"}
	}
	s.events = append(s.events, toolAuditEvent(obs, args))
	recordObservation(s.ObservationStore, obs)
	return obs
}

// AuditEvents merges the routing-denial events with every part's trail
// (parts expose AuditEvents where they record calls). Ordering is grouped
// by recorder, not interleaved — parts do not timestamp their events.
func (s *ToolSet) AuditEvents() []ToolAuditEvent {
	out := append([]ToolAuditEvent(nil), s.events...)
	for _, p := range s.Parts {
		if a, ok := p.(interface{ AuditEvents() []ToolAuditEvent }); ok {
			out = append(out, a.AuditEvents()...)
		}
	}
	return out
}

// Observations exposes the observations this executor recorded, mirroring
// ReadOnlyTools: a deterministic tool set is a first-class observation source,
// never only a part of a composite.
func (d *DeterministicTools) Observations() []RecordedObservation {
	if d == nil || d.ObservationStore == nil {
		return nil
	}
	return d.ObservationStore.Observations()
}

// Observations merges the composite's recorded observations: the set's own
// routing records plus every part's store. Parts commonly share one
// run-scoped store, so the merged view is deduplicated by observation id —
// the first entry wins and each recorded id stays unambiguous for evidence
// binding.
func (s *ToolSet) Observations() []RecordedObservation {
	var out []RecordedObservation
	seen := map[string]bool{}
	appendUnique := func(items []RecordedObservation) {
		for _, o := range items {
			if o.ID != "" && seen[o.ID] {
				continue
			}
			seen[o.ID] = true
			out = append(out, o)
		}
	}
	if r, ok := s.ObservationStore.(ObservationStore); ok {
		appendUnique(r.Observations())
	}
	for _, p := range s.Parts {
		if r, ok := p.(ObservationStore); ok {
			appendUnique(r.Observations())
		}
	}
	return out
}

// prepare indexes the routes once: the first part declaring a name owns it.
func (s *ToolSet) prepare() {
	if s.prep {
		return
	}
	s.prep = true
	s.routes = map[string]ToolExecutor{}
	for _, p := range s.Parts {
		if p == nil {
			continue
		}
		for _, d := range p.Definitions() {
			if _, exists := s.routes[d.Function.Name]; !exists {
				s.routes[d.Function.Name] = p
			}
		}
	}
}

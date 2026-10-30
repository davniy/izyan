package triage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fedorovmv/izyan/internal/evidencetools"
	"github.com/fedorovmv/izyan/internal/llm"
)

// fakeDetCaller is a scripted DetCaller: it records invocations and answers
// each call with fn (or a canned OK observation when fn is nil).
type fakeDetCaller struct {
	calls []string
	fn    func(name string, args json.RawMessage) (*evidencetools.Observation, error)
}

func (f *fakeDetCaller) CallTool(_ context.Context, name string, args json.RawMessage) (*evidencetools.Observation, error) {
	f.calls = append(f.calls, name+" "+string(args))
	if f.fn != nil {
		return f.fn(name, args)
	}
	return &evidencetools.Observation{
		ID:           "ev-1",
		Tool:         name,
		Fact:         "fake fact",
		Scope:        "fake scope",
		Completeness: evidencetools.CompletenessPartial,
		ToolStatus:   evidencetools.StatusOK,
		Data:         map[string]any{"echo": name},
	}, nil
}

func fakeCatalog() []DetToolInfo {
	return []DetToolInfo{
		{ToolContract: evidencetools.ToolContract{Name: "find_symbol", Description: "locate a symbol", InputSchema: json.RawMessage(`{"type":"object"}`), Permission: evidencetools.PermissionNone}, Available: true},
		{ToolContract: evidencetools.ToolContract{Name: "run_govulncheck", Description: "run govulncheck", InputSchema: json.RawMessage(`{"type":"object"}`), Permission: evidencetools.PermissionToolchain, MaxRunCalls: 2, Evidence: evidencetools.EvidenceGovulncheck}, Available: true},
		{ToolContract: evidencetools.ToolContract{Name: "get_vulnerability", Description: "advisory fetch", InputSchema: json.RawMessage(`{"type":"object"}`), Permission: evidencetools.PermissionVulnSource}, UnavailableReason: "no advisory source is configured (captured advisory set absent; network research disabled)"},
		{ToolContract: evidencetools.ToolContract{Name: "run_build", Description: "exec tool", InputSchema: json.RawMessage(`{"type":"object"}`), Permission: evidencetools.PermissionExec}, UnavailableReason: "the exec permission is denied (run_build/run_tests execute repository code)"},
	}
}

// fakeExecutor is a scripted ToolExecutor standing in for the read-only
// snapshot tool surface (deferred to the S-06b slice): it advertises the
// names in defs, answers calls from fn, and records one audit event per
// dispatched call like a real executor.

type fakeExecutor struct {
	defs   []string
	fn     func(name string, args json.RawMessage) ToolObservation
	seq    int
	calls  []string
	events []ToolAuditEvent
}

var _ ToolExecutor = (*fakeExecutor)(nil)

func (f *fakeExecutor) Definitions() []llm.ToolDefinition {
	var out []llm.ToolDefinition
	for _, n := range f.defs {
		out = append(out, llm.ToolDefinition{Type: "function", Function: llm.FunctionSpec{Name: n, Description: "fake " + n, Parameters: json.RawMessage(`{"type":"object"}`)}})
	}
	return out
}

func (f *fakeExecutor) Call(_ context.Context, name string, args json.RawMessage) (obs ToolObservation) {
	f.seq++
	f.calls = append(f.calls, name)
	obs = ToolObservation{ID: observationID("obs", f.seq, nil), Tool: name, Status: string(ToolStatusOK)}
	if f.fn != nil {
		obs = f.fn(name, args)
		obs.ID = observationID("obs", f.seq, nil)
		obs.Tool = name
	}
	if len(obs.Data) == 0 {
		data, _ := json.Marshal(map[string]any{"tool": name})
		obs.Data = data
	}
	sum := sha256.Sum256(obs.Data)
	obs.DataSHA256 = hex.EncodeToString(sum[:])
	obs.innerSHA = innerSHA256s(obs.Data)
	defer func() { f.events = append(f.events, toolAuditEvent(obs, args)) }()
	return obs
}

// AuditEvents mirrors the real executors' contract: every dispatched call
// produced one hash-only audit event.
func (f *fakeExecutor) AuditEvents() []ToolAuditEvent {
	return append([]ToolAuditEvent(nil), f.events...)
}

// TestDetToolsDefinitionsRealCatalog: the session-independent catalog grants
// every capability, so the broker advertises every registered check — sorted,
// with the catalog's own description and schema. Availability, not a local
// list, decides what appears.
func TestDetToolsDefinitionsRealCatalog(t *testing.T) {
	cat := evidencetools.DefaultCheckCatalog()
	d := &DeterministicTools{Catalog: CatalogFromCheckCatalog(cat)}
	defs := d.Definitions()
	if len(defs) != len(cat.List()) {
		var names []string
		for _, def := range defs {
			names = append(names, def.Function.Name)
		}
		t.Fatalf("want %d available definitions, got %d: %s", len(cat.List()), len(defs), strings.Join(names, ","))
	}
	prev := ""
	for _, def := range defs {
		if def.Function.Name < prev {
			t.Fatalf("definitions not sorted: %q after %q", def.Function.Name, prev)
		}
		prev = def.Function.Name
		spec, ok := cat.Lookup(def.Function.Name)
		if !ok || !spec.Available {
			t.Fatalf("advertised tool %q is not an available catalog entry", def.Function.Name)
		}
		if def.Function.Description != spec.Description {
			t.Fatalf("tool %q description %q does not project the catalog description %q", def.Function.Name, def.Function.Description, spec.Description)
		}
	}
}

// TestDetToolsCallMapping: an OK observation maps onto an OK ToolObservation
// whose Data is the full serialized Observation with a matching SHA256;
// completeness lands in Coverage, limitations carry over.
func TestDetToolsCallMapping(t *testing.T) {
	fake := &fakeDetCaller{fn: func(name string, _ json.RawMessage) (*evidencetools.Observation, error) {
		return &evidencetools.Observation{
			ID:           "ev-7",
			Tool:         name,
			Fact:         "symbol found",
			Scope:        "product packages",
			Completeness: evidencetools.CompletenessComplete,
			ToolStatus:   evidencetools.StatusOK,
			EvidenceRefs: []string{"ev:source:main.go:3@abc"},
			Limitations:  []string{"product roots only"},
			Data:         map[string]any{"file": "main.go", "line": 3},
		}, nil
	}}
	d := &DeterministicTools{Caller: fake, Catalog: fakeCatalog()}

	obs := d.Call(context.Background(), "find_symbol", json.RawMessage(`{"symbol":{"package":"main","name":"f"}}`))
	if obs.Status != string(ToolStatusOK) {
		t.Fatalf("status = %s, want OK", obs.Status)
	}
	if obs.Scope != "product packages" || obs.Coverage != "COMPLETE" {
		t.Fatalf("scope/coverage = %q/%q", obs.Scope, obs.Coverage)
	}
	if !hasLimitation(obs, "product roots only") {
		t.Fatalf("limitations lost: %v", obs.Limitations)
	}
	var raw evidencetools.Observation
	if err := json.Unmarshal(obs.Data, &raw); err != nil {
		t.Fatalf("data is not the full observation: %v", err)
	}
	if raw.Fact != "symbol found" || raw.Tool != "find_symbol" || len(raw.EvidenceRefs) != 1 {
		t.Fatalf("observation payload mangled: %+v", raw)
	}
	sum := sha256.Sum256(obs.Data)
	if obs.DataSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("data_sha256 = %s does not pin the payload", obs.DataSHA256)
	}
	if len(fake.calls) != 1 {
		t.Fatalf("caller invocations = %d", len(fake.calls))
	}
}

// TestDetToolsCallErrorMapping: a tool-side ERROR observation maps onto
// ERROR with UNKNOWN coverage and the error visible in the payload.
func TestDetToolsCallErrorMapping(t *testing.T) {
	fake := &fakeDetCaller{fn: func(name string, _ json.RawMessage) (*evidencetools.Observation, error) {
		return &evidencetools.Observation{
			ID:           "ev-9",
			Tool:         name,
			Fact:         "check failed",
			Completeness: evidencetools.CompletenessUnknown,
			ToolStatus:   evidencetools.StatusError,
			Error:        "packages failed to load",
		}, nil
	}}
	d := &DeterministicTools{Caller: fake, Catalog: fakeCatalog()}
	obs := d.Call(context.Background(), "find_symbol", json.RawMessage(`{}`))
	if obs.Status != string(ToolStatusError) || obs.Coverage != "UNKNOWN" {
		t.Fatalf("status/coverage = %s/%s, want ERROR/UNKNOWN", obs.Status, obs.Coverage)
	}
	if !strings.Contains(string(obs.Data), "packages failed to load") {
		t.Fatalf("error detail missing from data: %s", obs.Data)
	}
}

// TestDetToolsCache: a repeated (name,args) call replays the stored
// observation verbatim plus a "served from cache" limitation, without a
// second caller invocation; different args are a different cache key.
func TestDetToolsCache(t *testing.T) {
	fake := &fakeDetCaller{}
	d := &DeterministicTools{Caller: fake, Catalog: fakeCatalog()}
	args := json.RawMessage(`{"symbol":{"name":"f"}}`)

	first := d.Call(context.Background(), "find_symbol", args)
	second := d.Call(context.Background(), "find_symbol", args)
	if len(fake.calls) != 1 {
		t.Fatalf("caller invoked %d times, want 1", len(fake.calls))
	}
	if second.ID != first.ID || second.Status != first.Status {
		t.Fatalf("cached observation identity changed: %+v vs %+v", second, first)
	}
	if !hasLimitation(second, "served from cache") {
		t.Fatalf("cache replay lacks limitation: %v", second.Limitations)
	}
	if hasLimitation(first, "served from cache") {
		t.Fatal("stored observation must not carry the cache limitation")
	}
	if len(second.Limitations) != len(first.Limitations)+1 {
		t.Fatalf("cached limitations = %v, original %v", second.Limitations, first.Limitations)
	}
	// A third hit still annotates exactly once.
	third := d.Call(context.Background(), "find_symbol", args)
	if len(third.Limitations) != len(second.Limitations) {
		t.Fatalf("cache limitation multiplied: %v", third.Limitations)
	}
	d.Call(context.Background(), "find_symbol", json.RawMessage(`{"symbol":{"name":"g"}}`))
	if len(fake.calls) != 2 {
		t.Fatalf("different args must invoke the caller: %d calls", len(fake.calls))
	}
	if len(d.AuditEvents()) != 4 {
		t.Fatalf("audit events = %d, want 4 (incl. cached)", len(d.AuditEvents()))
	}
}

// TestDetToolsGovulncheckLimit: run_govulncheck is capped at two real
// invocations per run; a repeated identical call is served from cache and
// does not burn the limit.
func TestDetToolsGovulncheckLimit(t *testing.T) {
	fake := &fakeDetCaller{}
	d := &DeterministicTools{Caller: fake, Catalog: fakeCatalog()}
	ctx := context.Background()

	if obs := d.Call(ctx, "run_govulncheck", json.RawMessage(`{}`)); obs.Status != string(ToolStatusOK) {
		t.Fatalf("first govulncheck = %s", obs.Status)
	}
	cached := d.Call(ctx, "run_govulncheck", json.RawMessage(`{}`))
	if !hasLimitation(cached, "served from cache") {
		t.Fatalf("second identical call should hit cache: %+v", cached)
	}
	if obs := d.Call(ctx, "run_govulncheck", json.RawMessage(`{"x":1}`)); obs.Status != string(ToolStatusOK) {
		t.Fatalf("second distinct govulncheck = %s", obs.Status)
	}
	over := d.Call(ctx, "run_govulncheck", json.RawMessage(`{"x":2}`))
	if over.Status != string(ToolStatusError) {
		t.Fatalf("third distinct govulncheck = %s, want ERROR", over.Status)
	}
	if !hasLimitation(over, "invocation limit") {
		t.Fatalf("limit overrun lacks limitation: %v", over.Limitations)
	}
	if len(fake.calls) != 2 {
		t.Fatalf("caller invoked %d times, want 2", len(fake.calls))
	}
}

// TestTriageCannotCallUnadvertisedCapability: the broker admits exactly the
// entries the session catalog marks available. A capability the session
// denies is UNAVAILABLE with the session's own reason and never reaches the
// caller (repository execution stays unreachable); a name the catalog does
// not register is DENIED. Every refusal is audited and recorded.
func TestTriageCannotCallUnadvertisedCapability(t *testing.T) {
	fake := &fakeDetCaller{}
	store := NewRunObservationStore("run-denied", 1)
	d := &DeterministicTools{Caller: fake, Catalog: fakeCatalog(), ObservationStore: store}

	advertised := map[string]bool{}
	for _, def := range d.Definitions() {
		advertised[def.Function.Name] = true
	}
	for _, name := range []string{"run_build", "get_vulnerability"} {
		if advertised[name] {
			t.Fatalf("unavailable capability %q is advertised", name)
		}
	}

	exec := d.Call(context.Background(), "run_build", json.RawMessage(`{}`))
	if exec.Status != string(ToolStatusUnavailable) {
		t.Fatalf("run_build status = %s, want UNAVAILABLE", exec.Status)
	}
	if !hasLimitation(exec, "exec permission is denied") {
		t.Fatalf("run_build refusal loses the session reason: %v", exec.Limitations)
	}
	advisory := d.Call(context.Background(), "get_vulnerability", json.RawMessage(`{}`))
	if advisory.Status != string(ToolStatusUnavailable) || !hasLimitation(advisory, "advisory source") {
		t.Fatalf("get_vulnerability refusal = %+v", advisory)
	}
	unknown := d.Call(context.Background(), "no_such_tool", json.RawMessage(`{}`))
	if unknown.Status != string(ToolStatusDenied) {
		t.Fatalf("unregistered tool status = %s, want DENIED", unknown.Status)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("refused calls reached the session: %v", fake.calls)
	}
	if len(d.AuditEvents()) != 3 {
		t.Fatalf("audit events = %d, want one per refused call", len(d.AuditEvents()))
	}
	if got := store.Observations(); len(got) != 3 {
		t.Fatalf("recorded observations = %d, want one per refused call", len(got))
	}

	// An available capability in the same catalog still dispatches.
	if obs := d.Call(context.Background(), "find_symbol", json.RawMessage(`{"symbol":{"name":"f"}}`)); obs.Status != string(ToolStatusOK) {
		t.Fatalf("available tool refused: %+v", obs)
	}
	if len(fake.calls) != 1 {
		t.Fatalf("available tool did not dispatch: %v", fake.calls)
	}
}

// TestDetToolsCallerErrorAndNil: a caller error maps to ERROR (never a
// negative fact); a missing caller reports UNAVAILABLE.
func TestDetToolsCallerErrorAndNil(t *testing.T) {
	d := &DeterministicTools{
		Caller: &fakeDetCaller{fn: func(string, json.RawMessage) (*evidencetools.Observation, error) {
			return nil, errors.New("backend exploded")
		}},
		Catalog: fakeCatalog(),
	}
	obs := d.Call(context.Background(), "find_symbol", json.RawMessage(`{}`))
	if obs.Status != string(ToolStatusError) || !hasLimitation(obs, "backend exploded") {
		t.Fatalf("caller error mapped to %+v", obs)
	}

	nilCaller := &DeterministicTools{Catalog: fakeCatalog()}
	obs = nilCaller.Call(context.Background(), "find_symbol", json.RawMessage(`{}`))
	if obs.Status != string(ToolStatusUnavailable) {
		t.Fatalf("nil caller status = %s, want UNAVAILABLE", obs.Status)
	}
}

// TestDetToolsCallTimeout: the per-call deadline reaches the caller context
// and a deadline termination reads as TIMEOUT.
func TestDetToolsCallTimeout(t *testing.T) {
	fake := &fakeDetCaller{fn: func(string, json.RawMessage) (*evidencetools.Observation, error) {
		return nil, context.DeadlineExceeded
	}}
	d := &DeterministicTools{Caller: fake, Catalog: fakeCatalog(), CallTimeout: time.Millisecond}
	obs := d.Call(context.Background(), "find_symbol", json.RawMessage(`{}`))
	if obs.Status != string(ToolStatusTimeout) {
		t.Fatalf("status = %s, want TIMEOUT", obs.Status)
	}
}

// TestToolSetRouting: the composite exposes the union of part definitions
// and dispatches by name; undeclared names are DENIED and recognized
// deferred names stay UNSUPPORTED.
func TestToolSetRouting(t *testing.T) {
	rt := &fakeExecutor{defs: []string{"read_file", "list_files"}}
	fake := &fakeDetCaller{}
	set := &ToolSet{Parts: []ToolExecutor{
		rt,
		&DeterministicTools{Caller: fake, Catalog: fakeCatalog()},
	}}

	defs := set.Definitions()
	var names map[string]bool = map[string]bool{}
	for _, d := range defs {
		if names[d.Function.Name] {
			t.Fatalf("duplicate definition %s", d.Function.Name)
		}
		names[d.Function.Name] = true
	}
	for _, want := range []string{"read_file", "list_files", "find_symbol", "run_govulncheck"} {
		if !names[want] {
			t.Fatalf("definitions missing %s", want)
		}
	}
	if names["run_build"] || names["get_vulnerability"] {
		t.Fatal("unavailable catalog entries leaked into definitions")
	}

	obs := set.Call(context.Background(), "find_symbol", json.RawMessage(`{"symbol":{"name":"f"}}`))
	if obs.Status != string(ToolStatusOK) || len(fake.calls) != 1 {
		t.Fatalf("det call not routed: %+v", obs)
	}
	obs = set.Call(context.Background(), "list_files", json.RawMessage(`{}`))
	if obs.Status != string(ToolStatusOK) {
		t.Fatalf("read-only call not routed: %+v", obs)
	}
	obs = set.Call(context.Background(), "no_such_tool", json.RawMessage(`{}`))
	if obs.Status != string(ToolStatusDenied) {
		t.Fatalf("unknown tool = %s, want DENIED", obs.Status)
	}
	obs = set.Call(context.Background(), "go_list", json.RawMessage(`{}`))
	if obs.Status != string(ToolStatusUnsupported) {
		t.Fatalf("deferred tool = %s, want UNSUPPORTED", obs.Status)
	}
	// run_tests is a registered capability, not a deferred name: a surface
	// that does not declare it denies it rather than restating it as
	// "deferred in this build".
	obs = set.Call(context.Background(), "run_tests", json.RawMessage(`{}`))
	if obs.Status != string(ToolStatusDenied) {
		t.Fatalf("undeclared registered capability = %s, want DENIED", obs.Status)
	}
	// The routing denials plus both parts' calls are auditable.
	if len(set.AuditEvents()) != 5 {
		t.Fatalf("merged audit events = %d, want 5", len(set.AuditEvents()))
	}
}

// TestHasDeterministicTools: the runner's prompt flag follows the real tool
// surface — a read-only-only surface, a nil executor and a full composite
// are distinguished.
func TestHasDeterministicTools(t *testing.T) {
	rt := &fakeExecutor{defs: []string{"read_file"}}
	if HasDeterministicTools(rt) {
		t.Fatal("a non-deterministic surface alone is not a det surface")
	}
	if HasDeterministicTools(nil) {
		t.Fatal("nil executor is not a det surface")
	}
	set := &ToolSet{Parts: []ToolExecutor{rt, &DeterministicTools{Catalog: fakeCatalog()}}}
	if !HasDeterministicTools(set) {
		t.Fatal("ToolSet with DeterministicTools must be detected")
	}
	if HasDeterministicTools(&ToolSet{Parts: []ToolExecutor{rt}}) {
		t.Fatal("ToolSet without DeterministicTools must not be detected")
	}
}

// TestObservationIndex: the index the fact gate verifies det:<id>
// references against is built from the same audit trail events.jsonl
// records — observation id → observation pin (data sha256, inner payload
// hashes, tool, reachability flag) for every audited call of every part
// of the tool surface.
func TestObservationIndex(t *testing.T) {
	rt := &fakeExecutor{defs: []string{"read_file", "list_files"}}
	innerHash := strings.Repeat("c", 64)
	fake := &fakeDetCaller{fn: func(name string, _ json.RawMessage) (*evidencetools.Observation, error) {
		return &evidencetools.Observation{
			ID:           "ev-42",
			Tool:         name,
			Fact:         "1 caller(s)",
			Completeness: evidencetools.CompletenessPartial,
			ToolStatus:   evidencetools.StatusOK,
			Data: map[string]any{
				"count":        1,
				"evidence_ref": "ev:ref:" + innerHash,
			},
		}, nil
	}}
	set := &ToolSet{Parts: []ToolExecutor{rt, &DeterministicTools{Caller: fake, Catalog: fakeCatalog()}}}

	det := set.Call(context.Background(), "find_symbol", json.RawMessage(`{"symbol":{"name":"f"}}`))
	list := set.Call(context.Background(), "list_files", json.RawMessage(`{}`))
	denied := set.Call(context.Background(), "no_such_tool", json.RawMessage(`{}`))

	index := ObservationIndex(set.AuditEvents())
	pin := index[det.ID]
	if pin.DataSHA256 != det.DataSHA256 || det.DataSHA256 == "" {
		t.Fatalf("index[%q].data = %q, want %q", det.ID, pin.DataSHA256, det.DataSHA256)
	}
	if pin.Tool != "find_symbol" {
		t.Fatalf("index[%q].tool = %q, want find_symbol", det.ID, pin.Tool)
	}
	if len(pin.InnerSHA256) != 1 || pin.InnerSHA256[0] != innerHash {
		t.Fatalf("index[%q].inner = %v, want [%s]", det.ID, pin.InnerSHA256, innerHash)
	}
	// find_symbol is not a reachability tool — the pin stays negative even
	// with a non-empty payload.
	if pin.ReachEvidence {
		t.Fatalf("index[%q].reach = true for a non-reachability tool", det.ID)
	}
	if index[list.ID].DataSHA256 != list.DataSHA256 || list.DataSHA256 == "" {
		t.Fatalf("index[%q].data = %q, want %q", list.ID, index[list.ID].DataSHA256, list.DataSHA256)
	}
	if p, ok := index[denied.ID]; !ok || p.DataSHA256 != "" {
		t.Fatalf("denied observation index[%q] = %+v, want present but empty", denied.ID, p)
	}
	if len(index) != 3 {
		t.Fatalf("index size = %d, want 3", len(index))
	}
}

// fakeCheckCatalog is a minimal evidencetools.CheckCatalog over an explicit
// spec list: the test drives the broker from a registry row it wrote itself,
// exactly as a session catalog would.
type fakeCheckCatalog struct{ specs []evidencetools.CheckSpec }

func (c fakeCheckCatalog) List() []evidencetools.CheckSpec {
	return append([]evidencetools.CheckSpec(nil), c.specs...)
}

func (c fakeCheckCatalog) Lookup(id string) (evidencetools.CheckSpec, bool) {
	for _, s := range c.specs {
		if s.ID == id {
			return s, true
		}
	}
	return evidencetools.CheckSpec{}, false
}

func (c fakeCheckCatalog) Validate(string, json.RawMessage) error { return nil }

// TestToolContractNeedsOneRegistryEdit: one registry contract row supplies
// everything the broker needs — the advertised definition, the permission
// metadata, the per-run cost bound and the observation classification. No
// second allowlist, description map, limit constant or confidence map has to
// be touched, which is what a new tool contract costs.
func TestToolContractNeedsOneRegistryEdit(t *testing.T) {
	const name = "synthetic_probe"
	spec := evidencetools.CheckSpec{
		ID:             name,
		Tool:           name,
		Description:    "synthetic registry probe",
		CoverageRule:   "synthetic closed scope",
		ArgumentSchema: json.RawMessage(`{"type":"object","properties":{"n":{"type":"integer"}}}`),
		Permission:     evidencetools.PermissionNone,
		MaxCalls:       1,
		MaxRunCalls:    1,
		Evidence:       evidencetools.EvidenceSiteSet,
		Available:      true,
	}
	broker := &DeterministicTools{
		Caller: &fakeDetCaller{fn: func(string, json.RawMessage) (*evidencetools.Observation, error) {
			return &evidencetools.Observation{
				ID: "ev-1", Tool: name, Fact: "two sites",
				Completeness: evidencetools.CompletenessPartial,
				ToolStatus:   evidencetools.StatusOK,
				Data:         map[string]any{"count": 2},
			}, nil
		}},
		Catalog: CatalogFromCheckCatalog(fakeCheckCatalog{specs: []evidencetools.CheckSpec{spec}}),
	}

	// The definition is the contract, verbatim.
	defs := broker.Definitions()
	if len(defs) != 1 || defs[0].Function.Name != spec.ID {
		t.Fatalf("definitions = %+v, want exactly %q", defs, spec.ID)
	}
	if defs[0].Function.Description != spec.Description {
		t.Fatalf("definition description %q is not the contract description %q", defs[0].Function.Description, spec.Description)
	}
	if string(defs[0].Function.Parameters) != string(spec.ArgumentSchema) {
		t.Fatalf("definition schema %s is not the contract schema %s", defs[0].Function.Parameters, spec.ArgumentSchema)
	}
	// Nothing outside the registry knows the name.
	if _, ok := readOnlyToolFor(name); ok {
		t.Fatal("synthetic contract leaked into the snapshot/material registry")
	}
	if deferredTools[name] {
		t.Fatal("synthetic contract is restated as a deferred name")
	}

	// The cost bound is the contract's MaxRunCalls.
	first := broker.Call(context.Background(), name, json.RawMessage(`{"n":1}`))
	if first.Status != string(ToolStatusOK) {
		t.Fatalf("first call = %+v", first)
	}
	over := broker.Call(context.Background(), name, json.RawMessage(`{"n":2}`))
	if over.Status != string(ToolStatusError) || !hasLimitation(over, "invocation limit reached (1 per run)") {
		t.Fatalf("second distinct call = %+v, want the contract's per-run limit", over)
	}
	// The classification is the contract's observation class.
	if pin := ObservationIndex(broker.AuditEvents())[first.ID]; !pin.ReachEvidence {
		t.Fatalf("positive site set did not classify under the registry row: %+v", pin)
	}
}

// TestObservationClassificationUsesTypedPayload: the reachability/usage
// classification is the registered observation class decoded from the typed
// payload. It is not a broker-side name allowlist: a tool named like a
// historical reachability probe but declaring no class classifies nothing,
// while a name no allowlist ever held classifies by its declared class. A
// successful empty result, an inventory fact and a failed call stay negative —
// declaring a class never makes a response positive.
func TestObservationClassificationUsesTypedPayload(t *testing.T) {
	catalog := []DetToolInfo{
		// Historical exact name, no class: it must classify nothing.
		{ToolContract: evidencetools.ToolContract{Name: "find_callers", Description: "legacy reachability name", InputSchema: json.RawMessage(`{"type":"object"}`), Permission: evidencetools.PermissionNone}, Available: true},
		// A name no allowlist knew, declaring the site-set class.
		{ToolContract: evidencetools.ToolContract{Name: "custom_sites", Description: "site set", InputSchema: json.RawMessage(`{"type":"object"}`), Permission: evidencetools.PermissionNone, Evidence: evidencetools.EvidenceSiteSet}, Available: true},
		{ToolContract: evidencetools.ToolContract{Name: "custom_sites_empty", Description: "empty site set", InputSchema: json.RawMessage(`{"type":"object"}`), Permission: evidencetools.PermissionNone, Evidence: evidencetools.EvidenceSiteSet}, Available: true},
		{ToolContract: evidencetools.ToolContract{Name: "invocation_state", Description: "invocation state", InputSchema: json.RawMessage(`{"type":"object"}`), Permission: evidencetools.PermissionNone, Evidence: evidencetools.EvidenceDepInvocation}, Available: true},
		{ToolContract: evidencetools.ToolContract{Name: "unbounded_state", Description: "unbounded invocation", InputSchema: json.RawMessage(`{"type":"object"}`), Permission: evidencetools.PermissionNone, Evidence: evidencetools.EvidenceDepInvocation}, Available: true},
		{ToolContract: evidencetools.ToolContract{Name: "scan_probe", Description: "govulncheck", InputSchema: json.RawMessage(`{"type":"object"}`), Permission: evidencetools.PermissionNone, Evidence: evidencetools.EvidenceGovulncheck}, Available: true},
		{ToolContract: evidencetools.ToolContract{Name: "clean_scan_probe", Description: "clean govulncheck", InputSchema: json.RawMessage(`{"type":"object"}`), Permission: evidencetools.PermissionNone, Evidence: evidencetools.EvidenceGovulncheck}, Available: true},
		{ToolContract: evidencetools.ToolContract{Name: "failed_probe", Description: "failed call", InputSchema: json.RawMessage(`{"type":"object"}`), Permission: evidencetools.PermissionNone, Evidence: evidencetools.EvidenceSiteSet}, Available: true},
	}
	ok := func(tool string, data map[string]any) *evidencetools.Observation {
		return &evidencetools.Observation{
			ID: "ev-1", Tool: tool, Fact: "fact",
			Completeness: evidencetools.CompletenessPartial,
			ToolStatus:   evidencetools.StatusOK,
			Data:         data,
		}
	}
	fake := &fakeDetCaller{fn: func(name string, _ json.RawMessage) (*evidencetools.Observation, error) {
		switch name {
		case "find_callers":
			return ok(name, map[string]any{"call_sites": []any{map[string]any{"file": "main.go"}}, "count": 1}), nil
		case "custom_sites":
			return ok(name, map[string]any{"call_sites": []any{map[string]any{"file": "main.go"}}, "count": 1}), nil
		case "custom_sites_empty":
			return ok(name, map[string]any{"call_sites": []any{}, "count": 0, "possible_count": 0}), nil
		case "invocation_state":
			return ok(name, map[string]any{"callers_inside_module": 0, "unbounded": false}), nil
		case "unbounded_state":
			return ok(name, map[string]any{"callers_inside_module": 0, "unbounded": true}), nil
		case "scan_probe":
			return ok(name, map[string]any{"count": 0, "findings": []any{map[string]any{"trace": []any{map[string]any{"function": "f"}}}}}), nil
		case "clean_scan_probe":
			return ok(name, map[string]any{"count": 0, "findings": []any{}}), nil
		default:
			return &evidencetools.Observation{
				ID: "ev-err", Tool: name, Fact: "failed",
				Completeness: evidencetools.CompletenessUnknown,
				ToolStatus:   evidencetools.StatusError,
				Data:         map[string]any{"count": 5},
			}, nil
		}
	}}
	d := &DeterministicTools{Caller: fake, Catalog: catalog}
	ids := map[string]string{}
	for _, name := range []string{"find_callers", "custom_sites", "custom_sites_empty",
		"invocation_state", "unbounded_state", "scan_probe", "clean_scan_probe", "failed_probe"} {
		obs := d.Call(context.Background(), name, json.RawMessage(`{}`))
		if obs.ID == "" {
			t.Fatalf("%s produced no observation", name)
		}
		ids[name] = obs.ID
	}
	index := ObservationIndex(d.AuditEvents())
	want := map[string]bool{
		"find_callers":       false, // name alone classifies nothing
		"custom_sites":       true,  // declared site-set class, positive payload
		"custom_sites_empty": false, // declared class, empty payload
		"invocation_state":   false,
		"unbounded_state":    true,
		"scan_probe":         true,
		"clean_scan_probe":   false,
		"failed_probe":       false, // ERROR never carries reachability evidence
	}
	for name, positive := range want {
		if got := index[ids[name]].ReachEvidence; got != positive {
			t.Fatalf("%s reach_evidence = %v, want %v (pin %+v)", name, got, positive, index[ids[name]])
		}
	}
}

// TestObservationIndexReachEvidence: the reachability classification rides
// the same audit event — a non-empty find_callers observation pins
// reach_evidence, a presence-only tool (get_module_version) and an empty
// reachability result never do.
func TestObservationIndexReachEvidence(t *testing.T) {
	catalog := []DetToolInfo{
		{ToolContract: evidencetools.ToolContract{Name: "find_callers", Description: "callers", InputSchema: json.RawMessage(`{"type":"object"}`), Permission: evidencetools.PermissionNone, Evidence: evidencetools.EvidenceSiteSet}, Available: true},
		{ToolContract: evidencetools.ToolContract{Name: "get_module_version", Description: "version", InputSchema: json.RawMessage(`{"type":"object"}`), Permission: evidencetools.PermissionToolchain}, Available: true},
		{ToolContract: evidencetools.ToolContract{Name: "run_govulncheck", Description: "govulncheck", InputSchema: json.RawMessage(`{"type":"object"}`), Permission: evidencetools.PermissionToolchain, Evidence: evidencetools.EvidenceGovulncheck}, Available: true},
	}
	obs := func(tool string, data map[string]any) *evidencetools.Observation {
		return &evidencetools.Observation{
			ID: "ev-1", Tool: tool, Fact: "fact",
			Completeness: evidencetools.CompletenessPartial,
			ToolStatus:   evidencetools.StatusOK,
			Data:         data,
		}
	}
	fake := &fakeDetCaller{fn: func(name string, _ json.RawMessage) (*evidencetools.Observation, error) {
		switch name {
		case "find_callers":
			return obs(name, map[string]any{"call_sites": []any{map[string]any{"file": "main.go", "line": 3}}, "count": 1}), nil
		case "get_module_version":
			return obs(name, map[string]any{"module": "dep", "version": "v1.2.3"}), nil
		default:
			return obs(name, map[string]any{"in_database": true, "findings": []any{map[string]any{"osv": "GO-1", "trace": []any{map[string]any{"function": "f"}}}}, "count": 1}), nil
		}
	}}
	d := &DeterministicTools{Caller: fake, Catalog: catalog}
	callers := d.Call(context.Background(), "find_callers", json.RawMessage(`{"symbol":{"name":"f"}}`))
	version := d.Call(context.Background(), "get_module_version", json.RawMessage(`{"module":"dep"}`))
	gv := d.Call(context.Background(), "run_govulncheck", json.RawMessage(`{}`))

	index := ObservationIndex(d.AuditEvents())
	if !index[callers.ID].ReachEvidence {
		t.Fatalf("find_callers with 1 site must pin reach_evidence: %+v", index[callers.ID])
	}
	if index[version.ID].ReachEvidence {
		t.Fatal("get_module_version must never pin reach_evidence (presence is not reachability)")
	}
	if !index[gv.ID].ReachEvidence {
		t.Fatal("run_govulncheck with a finding must pin reach_evidence")
	}

	// An empty reachability result is still not evidence: zero callers and
	// zero findings pin nothing.
	fakeEmpty := &fakeDetCaller{fn: func(name string, _ json.RawMessage) (*evidencetools.Observation, error) {
		if name == "find_callers" {
			return obs(name, map[string]any{"call_sites": []any{}, "count": 0}), nil
		}
		return obs(name, map[string]any{"in_database": true, "findings": []any{}, "count": 0}), nil
	}}
	de := &DeterministicTools{Caller: fakeEmpty, Catalog: catalog}
	zero := de.Call(context.Background(), "find_callers", json.RawMessage(`{"symbol":{"name":"f"}}`))
	gvEmpty := de.Call(context.Background(), "run_govulncheck", json.RawMessage(`{}`))
	empty := ObservationIndex(de.AuditEvents())
	if empty[zero.ID].ReachEvidence || empty[gvEmpty.ID].ReachEvidence {
		t.Fatalf("empty reachability results must not pin reach_evidence: %+v", empty)
	}
}

// TestDetToolsCacheArchiveAndIsolation: a repeated call produces one audit
// event per request but a single archive entry and index pin, while two
// executor instances keep fully isolated caches.
func TestDetToolsCacheArchiveAndIsolation(t *testing.T) {
	fake := &fakeDetCaller{}
	store := NewRunObservationStore("run-det", 1)
	d := &DeterministicTools{Caller: fake, Catalog: fakeCatalog(), ObservationStore: store}
	args := json.RawMessage(`{"symbol":{"name":"f"}}`)

	first := d.Call(context.Background(), "find_symbol", args)
	second := d.Call(context.Background(), "find_symbol", args)
	if second.ID != first.ID {
		t.Fatalf("cached id = %q, want %q", second.ID, first.ID)
	}
	if got := store.Observations(); len(got) != 1 || got[0].ID != first.ID {
		t.Fatalf("archive = %+v, want the single canonical %s", got, first.ID)
	}
	if len(d.AuditEvents()) != 2 {
		t.Fatalf("audit events = %d, want 2 (each request audited)", len(d.AuditEvents()))
	}
	if idx := ObservationIndex(d.AuditEvents()); len(idx) != 1 {
		t.Fatalf("index = %d entries, want 1", len(idx))
	}

	// A second executor for the same inputs is an isolated attempt: its own
	// seq space, its own cache — nothing crosses instances.
	fake2 := &fakeDetCaller{}
	d2 := &DeterministicTools{Caller: fake2, Catalog: fakeCatalog(),
		ObservationStore: NewRunObservationStore("run-det", 2)}
	other := d2.Call(context.Background(), "find_symbol", args)
	if len(fake2.calls) != 1 {
		t.Fatalf("fresh instance served a sibling's cache: %d calls", len(fake2.calls))
	}
	if len(d2.ObservationStore.Observations()) != 1 {
		t.Fatal("attempt store must contain only its own observation")
	}
	if other.ID == first.ID {
		t.Fatalf("attempt-qualified ids must not collide: %q", other.ID)
	}
}

// capturedSurfaceInputs builds a validated two-record captured set: the
// records a supplied investigation-inputs manifest would produce, including
// the selected advisory, a second record and one captured fix. The second
// record exists so a lookup outside the session CVE proves the set — not the
// finding — is the whole served corpus.
func capturedSurfaceInputs(t *testing.T) InvestigationInputs {
	t.Helper()
	recA := []byte(`{"id":"CVE-2099-0001","summary":"captured advisory A","aliases":["GHSA-surface-a"],"references":[{"type":"FIX","url":"https://example.test/fix/a.diff"}]}`)
	recB := []byte(`{"id":"CVE-2099-0002","summary":"captured advisory B"}`)
	fixA := []byte("--- a/a.go\n+++ b/a.go\n+fix\n")
	inputs := InvestigationInputs{
		Records: []CapturedRecord{
			{RecordID: "CVE-2099-0001", Aliases: []string{"GHSA-surface-a"},
				SHA256: hashBytes(recA), Size: int64(len(recA)), Source: "operator-freeze", Raw: recA},
			{RecordID: "CVE-2099-0002",
				SHA256: hashBytes(recB), Size: int64(len(recB)), Source: "ticket", Raw: recB},
		},
		Fixes: []CapturedFix{{
			RecordID: "CVE-2099-0001", RecordSHA256: hashBytes(recA),
			Locator: "https://example.test/fix/a.diff", Outcome: CapturedFixCaptured,
			SHA256: hashBytes(fixA), Size: int64(len(fixA)), Raw: fixA,
		}},
	}
	if err := inputs.Validate(); err != nil {
		t.Fatalf("captured surface inputs: %v", err)
	}
	return inputs
}

// TestTriageReadOnlySurfaceFollowsSession proves the advertised surface is
// the session's own permission answer, not a second list: configuring a
// captured advisory/fix set opens the research, provenance, configuration and
// dynamic tools; the same session still withholds repository execution; and a
// strict session without toolchain or captured sources withholds exactly those
// capabilities while keeping source reading available.
func TestTriageReadOnlySurfaceFollowsSession(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "e2e-product"))
	if err != nil {
		t.Fatal(err)
	}
	inputs := capturedSurfaceInputs(t)
	captured, err := evidencetools.NewSession(evidencetools.SessionConfig{
		CVEID:        "CVE-2099-0001",
		SnapshotRoot: root,
		Audit:        evidencetools.NopAudit{},
		VulnSource:   CapturedAdvisorySource{Inputs: inputs},
		PatchSource:  CapturedFixProvider{Inputs: inputs},
	})
	if err != nil {
		t.Fatalf("NewSession(captured): %v", err)
	}
	info := map[string]DetToolInfo{}
	for _, ti := range CatalogFromCheckCatalog(captured.CheckCatalog()) {
		info[ti.Name] = ti
	}
	for _, name := range []string{
		"get_vulnerability", "get_advisory", "get_fix_references", "get_fix_diff",
		"trace_argument", "field_assignments", "scan_dynamic", "interface_dispatch_sites",
		"find_dep_callers", "module_internal_reach", "read_source", "search_source",
		"find_validations", "check_call_site_guard",
	} {
		if !info[name].Available {
			t.Fatalf("%s is not available in a session that holds its capability: %+v", name, info[name])
		}
	}
	for _, name := range []string{"run_build", "run_tests"} {
		if info[name].Available {
			t.Fatalf("repository execution %q is available without AllowExec", name)
		}
		if !strings.Contains(info[name].UnavailableReason, "exec permission") {
			t.Fatalf("%s unavailable reason = %q, want the exec-permission reason", name, info[name].UnavailableReason)
		}
	}

	// The same catalog admits every available name through the broker.
	fake := &fakeDetCaller{}
	det := &DeterministicTools{Caller: fake, Catalog: CatalogFromCheckCatalog(captured.CheckCatalog())}
	advertised := map[string]bool{}
	for _, def := range det.Definitions() {
		advertised[def.Function.Name] = true
		if advertised["run_build"] || advertised["run_tests"] {
			t.Fatal("exec tool advertised without AllowExec")
		}
	}
	for _, name := range []string{"trace_argument", "field_assignments", "scan_dynamic", "get_advisory", "get_fix_diff"} {
		if !advertised[name] {
			t.Fatalf("%s is not advertised by the broker", name)
		}
		if obs := det.Call(context.Background(), name, json.RawMessage(`{}`)); obs.Status != string(ToolStatusOK) {
			t.Fatalf("%s did not dispatch: %+v", name, obs)
		}
	}

	// Permissions are resolved from the session, so a session that holds no
	// toolchain and no captured source withholds precisely those checks.
	bare, err := evidencetools.NewSession(evidencetools.SessionConfig{
		CVEID:        "CVE-2099-0001",
		SnapshotRoot: root,
		Strict:       true,
		Audit:        evidencetools.NopAudit{},
	})
	if err != nil {
		t.Fatalf("NewSession(bare): %v", err)
	}
	bareInfo := map[string]DetToolInfo{}
	for _, ti := range CatalogFromCheckCatalog(bare.CheckCatalog()) {
		bareInfo[ti.Name] = ti
	}
	for _, name := range []string{
		"get_vulnerability", "get_advisory", "get_fix_references", "get_fix_diff",
		"get_dependency_graph", "get_module_version", "run_govulncheck", "usage-scope",
		"run_build", "run_tests",
	} {
		if bareInfo[name].Available {
			t.Fatalf("%s is available in a strict session that holds no such capability", name)
		}
	}
	for _, name := range []string{"find_symbol", "read_source", "trace_argument", "field_assignments", "scan_dynamic"} {
		if !bareInfo[name].Available {
			t.Fatalf("capability-free check %q is unavailable: %+v", name, bareInfo[name])
		}
	}
	if !strings.Contains(bareInfo["get_advisory"].UnavailableReason, "advisory source") ||
		!strings.Contains(bareInfo["get_dependency_graph"].UnavailableReason, "toolchain") {
		t.Fatalf("unavailable reasons do not name the missing capability: %+v", bareInfo)
	}
}

// TestPhase1DetToolSurfaceStaysReproducible: the frozen Phase 1 surface used
// by history-only replay still resolves every name it advertised. A vanished
// name would silently change a historical prompt reconstruction rather than
// fail closed.
func TestPhase1DetToolSurfaceStaysReproducible(t *testing.T) {
	got := map[string]bool{}
	for _, ti := range phase1DetCatalog() {
		got[ti.Name] = true
	}
	for _, name := range phase1DetToolSurface {
		if !got[name] {
			t.Fatalf("frozen Phase 1 tool %q no longer resolves in the check catalog", name)
		}
	}
	if len(got) != len(phase1DetToolSurface) {
		t.Fatalf("phase1 catalog has %d entries, frozen surface names %d", len(got), len(phase1DetToolSurface))
	}
}

// TestCatalogFromCheckCatalog: the projection preserves every catalog
// entry's availability and reason verbatim, and never re-derives capability
// here. A session view withholds the same entries its Validate call rejects.
func TestCatalogFromCheckCatalog(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "e2e-product"))
	if err != nil {
		t.Fatal(err)
	}
	sess, err := evidencetools.NewSession(evidencetools.SessionConfig{
		CVEID:        "CVE-2099-0001",
		SnapshotRoot: root,
		Strict:       true,
		Audit:        evidencetools.NopAudit{},
	})
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	check := sess.CheckCatalog()
	byName := map[string]DetToolInfo{}
	for _, info := range CatalogFromCheckCatalog(check) {
		byName[info.Name] = info
	}
	for _, spec := range check.List() {
		info, ok := byName[spec.ID]
		if !ok {
			t.Fatalf("catalog entry %q was not projected", spec.ID)
		}
		if info.Description == "" || len(info.InputSchema) == 0 {
			t.Fatalf("catalog entry %q is under-described: %+v", spec.ID, info)
		}
		if info.Available != spec.Available || info.UnavailableReason != spec.UnavailableReason {
			t.Fatalf("entry %q availability drifted: %+v vs %+v", spec.ID, info, spec)
		}
		if info.Available {
			continue
		}
		if info.UnavailableReason == "" {
			t.Fatalf("unavailable entry %q lost its reason", spec.ID)
		}
		if err := check.Validate(spec.ID, json.RawMessage(`{}`)); err == nil {
			t.Fatalf("projected-unavailable entry %q is admitted by Validate", spec.ID)
		}
	}
}

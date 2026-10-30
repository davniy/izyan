package flow

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/fedorovmv/izyan/internal/evidencetools"
)

func TestRegistryAdmit(t *testing.T) {
	cat := testCatalog()
	reg, err := NewCatalogRegistry(cat, []Condition{
		{ID: "cond-one", Role: "supporting", Polarity: "POSITIVE"},
	})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	if err := reg.Check(alphaAction("a1")); err != nil {
		t.Fatalf("admitted action rejected: %v", err)
	}
	if _, ok := reg.Condition("cond-one"); !ok {
		t.Fatalf("condition lookup failed")
	}
	if _, ok := reg.Condition("cond-ghost"); ok {
		t.Fatalf("unknown condition admitted")
	}
}

func TestRegistryFailClosed(t *testing.T) {
	reg, err := NewCatalogRegistry(testCatalog(), nil)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	bad := []PlanAction{
		{ID: "a1", AdapterID: "check-ghost", Purpose: "x"},                                           // unregistered
		{ID: "a2", AdapterID: "check-alpha", Arguments: json.RawMessage(`{"evil":1}`), Purpose: "x"}, // undeclared key
		{ID: "a3", AdapterID: "check-alpha", Arguments: json.RawMessage(`{`), Purpose: "x"},          // malformed JSON
		{ID: "a4", AdapterID: "check-alpha", Arguments: json.RawMessage(`{}`)},                       // missing purpose
		{ID: "a5", Arguments: json.RawMessage(`{}`), Purpose: "x"},                                   // missing adapter id
	}
	for i, a := range bad {
		if err := reg.Check(a); err == nil {
			t.Fatalf("case %d admitted: %+v", i, a)
		}
	}
}

func TestRegistryConditionCatalogOrder(t *testing.T) {
	reg, err := NewCatalogRegistry(testCatalog(), []Condition{
		{ID: "c-b"}, {ID: "c-a"}, {ID: "c-c"},
	})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	got := reg.Conditions()
	if len(got) != 3 || got[0].ID != "c-b" || got[1].ID != "c-a" || got[2].ID != "c-c" {
		t.Fatalf("conditions out of order: %+v", got)
	}
}

func TestRegistryConstructionFailClosed(t *testing.T) {
	if _, err := NewCatalogRegistry(nil, nil); err == nil {
		t.Fatalf("nil catalog admitted")
	}
	if _, err := NewCatalogRegistry(testCatalog(), []Condition{{ID: ""}}); err == nil {
		t.Fatalf("empty condition id admitted")
	}
	if _, err := NewCatalogRegistry(testCatalog(), []Condition{{ID: "x"}, {ID: "x"}}); err == nil {
		t.Fatalf("duplicate condition admitted")
	}
}

func TestRegistryCapabilityDenial(t *testing.T) {
	cat := testCatalog()
	cat.denied["check-alpha"] = true
	reg, err := NewCatalogRegistry(cat, nil)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	if err := reg.Check(alphaAction("a1")); err == nil {
		t.Fatalf("capability-denied check admitted")
	}
}

func TestFailClosedUnknownVariable(t *testing.T) {
	reg := testRegistry(t, testCatalog(), "cond-env")
	planner := &fakePlanner{fn: func(step int, in PlanInput) (Plan, error) {
		return Plan{StepID: "s1", Actions: []PlanAction{alphaAction("a1")}}, nil
	}}
	reass := &fakeReassessor{fn: func(in ReassessInput) (Reassessment, error) {
		// An input the registry has never heard of: the run must fail
		// closed, never interpret it generically.
		return Reassessment{Status: ReassessContinue,
			RequiredInputs: []string{"undeclared-variable"}}, nil
	}}
	broker := &fakeBroker{fn: func(a PlanAction) (Observation, error) {
		return okObservation(a.ID), nil
	}}
	res, err := newEngine(reg, planner, reass, broker).Run(context.Background(), testInput())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Termination != TermUnsupported || res.Ready {
		t.Fatalf("termination = %q, want UNSUPPORTED_CHECK_OR_CONDITION", res.Termination)
	}
}

// TestBrokerMapping verifies the SessionBroker projects the session
// observation and audit record into the flow envelope.
func TestBrokerMapping(t *testing.T) {
	cat := testCatalog()
	var gotTool string
	var gotArgs json.RawMessage
	call := func(ctx context.Context, tool string, args json.RawMessage) (*evidencetools.Observation, *evidencetools.AuditRecord, error) {
		gotTool, gotArgs = tool, args
		obs := &evidencetools.Observation{
			ID: "OBS-0001", Tool: tool,
			Fact: "recorded fact", Scope: "closed scope",
			Completeness: evidencetools.CompletenessComplete,
			ToolStatus:   evidencetools.StatusOK,
			EvidenceRefs: []string{"ev:test:loc@abc"},
		}
		rec := &evidencetools.AuditRecord{Tool: tool, Args: args, Observation: obs}
		return obs, rec, nil
	}
	b, err := NewSessionBroker(cat, call)
	if err != nil {
		t.Fatalf("broker: %v", err)
	}
	out, err := b.Execute(context.Background(), alphaAction("a1"))
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotTool != "tool-alpha" {
		t.Fatalf("dispatched tool %q, want tool-alpha", gotTool)
	}
	if string(gotArgs) != `{"subject":"s"}` {
		t.Fatalf("dispatched args %s", gotArgs)
	}
	if out.Status != ObsStatusOK || out.Completeness != ObsComplete || !out.AuditBound {
		t.Fatalf("observation = %+v", out)
	}
	if out.DataDigest == "" {
		t.Fatalf("no digest pinned")
	}
	if len(out.EvidenceRefs) != 1 {
		t.Fatalf("evidence refs = %v", out.EvidenceRefs)
	}
}

func TestBrokerMaxCalls(t *testing.T) {
	cat := newFakeCatalog()
	cat.add("once", "tool-once", 1, nil, nil)
	var calls int
	call := func(ctx context.Context, tool string, args json.RawMessage) (*evidencetools.Observation, *evidencetools.AuditRecord, error) {
		calls++
		return &evidencetools.Observation{ToolStatus: evidencetools.StatusOK,
				Completeness: evidencetools.CompletenessComplete, Scope: "s"},
			&evidencetools.AuditRecord{Tool: tool, Args: args}, nil
	}
	b, err := NewSessionBroker(cat, call)
	if err != nil {
		t.Fatalf("broker: %v", err)
	}
	a := PlanAction{ID: "a1", AdapterID: "once", Purpose: "p"}
	if _, err := b.Execute(context.Background(), a); err != nil {
		t.Fatalf("first call: %v", err)
	}
	if _, err := b.Execute(context.Background(), a); err == nil {
		t.Fatalf("second call exceeded max_calls")
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1", calls)
	}
}

func TestBrokerAuditBinding(t *testing.T) {
	cat := testCatalog()
	// A call the session never recorded returns a nil audit record:
	// the observation is kept but unbound.
	callNoAudit := func(ctx context.Context, tool string, args json.RawMessage) (*evidencetools.Observation, *evidencetools.AuditRecord, error) {
		return &evidencetools.Observation{ID: "O1", ToolStatus: evidencetools.StatusOK,
			Completeness: evidencetools.CompletenessComplete, Scope: "s"}, nil, nil
	}
	b, _ := NewSessionBroker(cat, callNoAudit)
	out, err := b.Execute(context.Background(), alphaAction("a1"))
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if out.AuditBound {
		t.Fatalf("unaudited observation reported bound")
	}
	// A mismatched argument record is a binding failure.
	callBadArgs := func(ctx context.Context, tool string, args json.RawMessage) (*evidencetools.Observation, *evidencetools.AuditRecord, error) {
		return &evidencetools.Observation{ID: "O1", ToolStatus: evidencetools.StatusOK,
				Completeness: evidencetools.CompletenessComplete, Scope: "s"},
			&evidencetools.AuditRecord{Tool: tool, Args: json.RawMessage(`{"subject":"other"}`)}, nil
	}
	b2, _ := NewSessionBroker(cat, callBadArgs)
	out, err = b2.Execute(context.Background(), alphaAction("a1"))
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if out.AuditBound {
		t.Fatalf("argument-mismatched observation reported bound")
	}
}

func TestBrokerErrorPassthrough(t *testing.T) {
	cat := testCatalog()
	call := func(ctx context.Context, tool string, args json.RawMessage) (*evidencetools.Observation, *evidencetools.AuditRecord, error) {
		return nil, nil, errors.New("session call failed")
	}
	b, _ := NewSessionBroker(cat, call)
	if _, err := b.Execute(context.Background(), alphaAction("a1")); err == nil {
		t.Fatalf("session error swallowed")
	}
}

func TestBrokerNoObservation(t *testing.T) {
	cat := testCatalog()
	call := func(ctx context.Context, tool string, args json.RawMessage) (*evidencetools.Observation, *evidencetools.AuditRecord, error) {
		return nil, &evidencetools.AuditRecord{Tool: tool, Args: args}, nil
	}
	b, _ := NewSessionBroker(cat, call)
	if _, err := b.Execute(context.Background(), alphaAction("a1")); err == nil {
		t.Fatalf("missing observation accepted")
	}
}

// answerCatalog wraps fakeCatalog with the catalog-owned
// answer-semantics verdict: a PARTIAL "tool-alpha" observation is a
// positive answer to the check's question.
type answerCatalog struct {
	*fakeCatalog
}

func (c *answerCatalog) PositiveAnswer(o *evidencetools.Observation) bool {
	return o.Tool == "tool-alpha" && o.Completeness == evidencetools.CompletenessPartial
}

// TestBrokerStampsDischargePath proves the broker records which answer
// path a produced observation carries: a COMPLETE closed-scope record
// stamps closed_negative, a PARTIAL payload the catalog calls a
// positive answer stamps positive_answer, and an unanswered record
// carries no path.
func TestBrokerStampsDischargePath(t *testing.T) {
	call := func(comp evidencetools.Completeness) AuditedCallFunc {
		return func(ctx context.Context, tool string, args json.RawMessage) (*evidencetools.Observation, *evidencetools.AuditRecord, error) {
			obs := &evidencetools.Observation{
				ID: "OBS-1", Tool: tool, Fact: "f", Scope: "s",
				Completeness: comp, ToolStatus: evidencetools.StatusOK,
			}
			return obs, &evidencetools.AuditRecord{Tool: tool, Args: args, Observation: obs}, nil
		}
	}

	// Closed negative: no answer-semantics interface needed — a
	// complete OK record stamps the closed-negative path.
	b, err := NewSessionBroker(testCatalog(), call(evidencetools.CompletenessComplete))
	if err != nil {
		t.Fatalf("broker: %v", err)
	}
	out, err := b.Execute(context.Background(), alphaAction("a1"))
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if out.DischargePath != DischargeClosedNegative {
		t.Fatalf("complete record discharge path = %q, want %q", out.DischargePath, DischargeClosedNegative)
	}

	// Positive answer: the catalog's own verdict stamps the positive
	// path on a PARTIAL record; without the interface it stays blank.
	bPos, err := NewSessionBroker(&answerCatalog{testCatalog()}, call(evidencetools.CompletenessPartial))
	if err != nil {
		t.Fatalf("broker: %v", err)
	}
	outPos, err := bPos.Execute(context.Background(), alphaAction("a1"))
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if outPos.DischargePath != DischargePositiveAnswer {
		t.Fatalf("positive record discharge path = %q, want %q", outPos.DischargePath, DischargePositiveAnswer)
	}

	// Degraded: a PARTIAL record whose catalog answers nothing is
	// never stamped.
	bNone, err := NewSessionBroker(testCatalog(), call(evidencetools.CompletenessPartial))
	if err != nil {
		t.Fatalf("broker: %v", err)
	}
	outNone, err := bNone.Execute(context.Background(), alphaAction("a1"))
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if outNone.DischargePath != "" {
		t.Fatalf("unanswered record discharge path = %q, want empty", outNone.DischargePath)
	}
}

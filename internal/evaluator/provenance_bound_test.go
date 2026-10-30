package evaluator

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/llm"
)

// fixedExploitModelBuilder returns a prepared deterministic baseline,
// standing in for exploit.Builder without a source snapshot.
type fixedExploitModelBuilder struct{ model *domain.ExploitModel }

func (f fixedExploitModelBuilder) Build(context.Context, *domain.AnalysisCase, domain.Vulnerability, *domain.RootCauseModel) (*domain.ExploitModel, []string) {
	return f.model, nil
}

// stubExploitProposal wires the real LLM builder to a local completion
// endpoint that answers with reply — no live model, no network egress.
func stubExploitProposal(t *testing.T, reply string, base *domain.ExploitModel) *llm.ExploitModelBuilder {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{
				"message":       map[string]string{"role": "assistant", "content": reply},
				"finish_reason": "stop",
			}},
		})
	}))
	t.Cleanup(srv.Close)
	client := llm.NewClient(llm.Config{BaseURL: srv.URL, AnalyzeModel: "stub", BuildModel: "stub", Enabled: true})
	return &llm.ExploitModelBuilder{Client: client, Fallback: fixedExploitModelBuilder{model: base}}
}

func i64(v int64) *int64 { return &v }

func TestParseBoundDisjuncts(t *testing.T) {
	terms, leftovers := parseBound("prefetchCount < 0 or prefetchSize < 0")
	if len(leftovers) > 0 || len(terms) != 2 {
		t.Fatalf("terms=%+v leftovers=%v", terms, leftovers)
	}
	if terms[0].arg != 0 || terms[1].arg != 1 {
		t.Fatalf("positional binding wrong: %+v", terms)
	}
	if !terms[0].satisfies(-1) || terms[0].satisfies(0) {
		t.Fatalf("< 0 satisfaction wrong")
	}
}

func TestParseBoundLeftovers(t *testing.T) {
	_, leftovers := parseBound("x > INT32_MAX")
	if len(leftovers) != 0 {
		// INT32_MAX is a valid right side syntactically — symbolic, hasVal=false
		t.Fatalf("unexpected leftovers %v", leftovers)
	}
	terms, _ := parseBound("x > INT32_MAX")
	if terms[0].hasVal {
		t.Fatalf("symbolic bound must not resolve: %+v", terms[0])
	}
	_, leftovers = parseBound("len(x) < 0")
	if len(leftovers) != 1 {
		t.Fatalf("unparseable term must be a leftover: %v", leftovers)
	}
}

func TestBoundTermFalsifiedBy(t *testing.T) {
	neg := boundTerm{name: "x", op: "<", val: 0, hasVal: true}
	if !neg.falsifiedBy(i64(0), i64(1024)) {
		t.Fatal("[0,1024] falsifies x<0")
	}
	if neg.falsifiedBy(i64(-5), nil) {
		t.Fatal("[-5,∞) does not falsify x<0")
	}
	if neg.falsifiedBy(nil, i64(10)) {
		t.Fatal("(−∞,10] does not falsify x<0")
	}
	upper := boundTerm{name: "x", op: ">", val: 10, hasVal: true}
	if !upper.falsifiedBy(i64(0), i64(10)) {
		t.Fatal("[0,10] falsifies x>10")
	}
	if upper.falsifiedBy(nil, i64(100)) {
		t.Fatal("(−∞,100] does not falsify x>10")
	}
}

func TestVerifyBoundFalsified(t *testing.T) {
	c := &domain.AnalysisCase{Product: admittedProduct()}
	sink := domain.CallSite{File: "r.go", Line: 50}
	c.EvidenceGraph.Validations = []domain.Validation{
		{Guard: true, Arg: 0,
			Covers: &sink, BoundLow: i64(0), BoundHigh: i64(1024),
			Property: "field-write prefetchCount"},
		{Guard: true, Arg: 1,
			Covers: &sink, BoundLow: i64(0), BoundHigh: i64(1024),
			Property: "field-write prefetchSize"},
	}
	cond := domain.Condition{
		Kind: domain.ConditionInputConstraint,
		Params: map[string]string{
			domain.ParamBound: "prefetchCount < 0 or prefetchSize < 0",
		},
	}
	flows := []domain.DataFlow{
		{Arg: 0, Sink: sink, Origin: domain.OriginConfiguration},
		{Arg: 1, Sink: sink, Origin: domain.OriginConfiguration},
		{Arg: 2, Sink: sink, Origin: domain.OriginConstant},
	}
	note := verifyBound(cond, c, flows)
	if !strings.HasPrefix(note, "bound verified") {
		t.Fatalf("expected verified bound, got %q", note)
	}
}

func TestVerifyBoundInsufficientRange(t *testing.T) {
	c := &domain.AnalysisCase{Product: admittedProduct()}
	sink := domain.CallSite{File: "r.go", Line: 50}
	// One-sided guard cannot falsify x<0.
	c.EvidenceGraph.Validations = []domain.Validation{
		{Guard: true, Arg: 0,
			Covers: &sink, BoundHigh: i64(1024)},
	}
	cond := domain.Condition{
		Kind:   domain.ConditionInputConstraint,
		Params: map[string]string{domain.ParamBound: "x < 0"},
	}
	flows := []domain.DataFlow{
		{Arg: 0, Sink: sink, Origin: domain.OriginConfiguration},
	}
	note := verifyBound(cond, c, flows)
	if strings.HasPrefix(note, "bound verified") {
		t.Fatalf("one-sided range must not verify x<0: %q", note)
	}
	if !strings.Contains(note, "not fully falsified") {
		t.Fatalf("expected falsification gap, got %q", note)
	}
}

func TestConstViolatesBound(t *testing.T) {
	sink := domain.CallSite{File: "r.go", Line: 50}
	cond := domain.Condition{
		Kind:   domain.ConditionInputConstraint,
		Params: map[string]string{domain.ParamBound: "prefetchCount < 0 or prefetchSize < 0"},
	}
	violating := []domain.DataFlow{
		{Arg: 0, Sink: sink, Origin: domain.OriginConstant, Value: i64(-5)},
	}
	if hit := constViolatesBound(cond, violating); hit == "" {
		t.Fatal("constant -5 at arg0 must satisfy prefetchCount < 0")
	}
	safe := []domain.DataFlow{
		{Arg: 0, Sink: sink, Origin: domain.OriginConstant, Value: i64(10)},
	}
	if hit := constViolatesBound(cond, safe); hit != "" {
		t.Fatalf("constant 10 must not violate: %s", hit)
	}
}

// TestModelBoundNeverChangesConstraint pins the Task-2 boundary at the
// evaluated-truth layer: a model-proposed bound is recorded only on
// ExploitModel.ProposedConditions and never fills the authoritative
// constraint. A constant argument that would satisfy the proposal's bound
// therefore cannot turn the condition TRUE.
func TestModelBoundNeverChangesConstraint(t *testing.T) {
	base := &domain.ExploitModel{MandatoryConditions: []domain.Condition{{
		ID: "C-INPUT", Kind: domain.ConditionInputConstraint, Mandatory: true,
		Subjects: []domain.SymbolRef{{Package: "p", Symbol: "S"}},
		Params:   map[string]string{domain.ParamBound: ""},
	}}}
	reply := `{"mandatory_conditions":[{"id":"C-INPUT","kind":"INPUT_CONSTRAINT","mandatory":true,"subjects":[{"package":"p","symbol":"S"}],"params":{"bound":"x < 0"}}]}`
	rc := &domain.RootCauseModel{
		Status:     domain.RootCauseResolved,
		RootCauses: []domain.RootCause{{Package: "p", Symbol: "S", Role: domain.RootCauseSink}},
	}
	m, lims := stubExploitProposal(t, reply, base).Build(context.Background(), &domain.AnalysisCase{}, domain.Vulnerability{Summary: "x"}, rc)
	if m == nil {
		t.Fatalf("nil model, lims=%v", lims)
	}
	cond := m.MandatoryConditions[0]
	if got := cond.Params[domain.ParamBound]; got != "" {
		t.Fatalf("model bound filled the authoritative constraint: %q (lims=%v)", got, lims)
	}
	var proposed *domain.Condition
	for i := range m.ProposedConditions {
		if m.ProposedConditions[i].ID == "C-INPUT" {
			proposed = &m.ProposedConditions[i]
			break
		}
	}
	if proposed == nil || proposed.Params[domain.ParamBound] != "x < 0" {
		t.Fatalf("proposed bound was not preserved on the nomination: %+v (lims=%v)", proposed, lims)
	}

	// A constant argument that would satisfy the proposed bound is not a
	// constraint violation: the authoritative condition declares no bound.
	sink := domain.CallSite{File: "r.go", Line: 10}
	c := &domain.AnalysisCase{
		Product: admittedProduct(),
		EvidenceGraph: domain.EvidenceGraph{
			DataFlows: []domain.DataFlow{{
				ConditionID: "C-INPUT", Arg: 0, Sink: sink,
				Origin: domain.OriginConstant, Value: i64(-5),
			}},
		},
	}
	claim := ArgumentOrigin{}.Evaluate(cond, c)
	if claim.Result == domain.ClaimTrue {
		t.Fatalf("model-proposed bound changed the constraint's evaluated truth: %+v", claim)
	}
	if strings.Contains(claim.Explanation, "satisfies violating bound") {
		t.Fatalf("claim explanation cites the model-proposed bound: %q", claim.Explanation)
	}
}

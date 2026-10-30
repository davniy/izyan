package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/goanalysis"
)

func mockServer(t *testing.T, reply string) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req chatRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		resp := chatResponse{Choices: []struct {
			Message      chatMessage `json:"message"`
			FinishReason string      `json:"finish_reason"`
		}{{Message: chatMessage{Role: "assistant", Content: reply}}}}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	cfg := Config{BaseURL: srv.URL, AnalyzeModel: "m", BuildModel: "m", Enabled: true}
	return NewClient(cfg), srv
}

func newCase() *domain.AnalysisCase {
	return &domain.AnalysisCase{}
}

func TestRootCauseResolverFallsBackToLLM(t *testing.T) {
	reply := `[{"package":"example.com/dep","symbol":"vuln.Parse","mechanism":"xml parse"}]`
	client, srv := mockServer(t, reply)
	defer srv.Close()

	fb := stubResolver{model: &domain.RootCauseModel{Status: domain.RootCauseNotFound}}
	r := &RootCauseResolver{Client: client, Fallback: fb}
	c := newCase()
	m, _, err := r.Resolve(context.Background(), c, domain.Vulnerability{ID: "X"})
	if err != nil {
		t.Fatal(err)
	}
	if m.Status != domain.RootCauseResolved || len(m.RootCauses) != 1 {
		t.Fatalf("model=%+v", m)
	}
	if m.RootCauses[0].Symbol != "vuln.Parse" {
		t.Fatalf("symbol=%s", m.RootCauses[0].Symbol)
	}
	if c.Workflow.Usage.LLMCalls != 1 {
		t.Fatalf("llm calls=%d", c.Workflow.Usage.LLMCalls)
	}
}

func TestRootCauseResolverKeepsDeterministicResult(t *testing.T) {
	client, srv := mockServer(t, "[]")
	defer srv.Close()
	fb := stubResolver{model: &domain.RootCauseModel{
		Status:     domain.RootCauseResolved,
		RootCauses: []domain.RootCause{{Package: "p", Symbol: "S"}},
	}}
	r := &RootCauseResolver{Client: client, Fallback: fb}
	c := newCase()
	m, _, _ := r.Resolve(context.Background(), c, domain.Vulnerability{})
	if len(m.RootCauses) != 1 || m.RootCauses[0].Symbol != "S" {
		t.Fatalf("model=%+v", m)
	}
	if c.Workflow.Usage.LLMCalls != 0 {
		t.Fatal("llm must not run when deterministic resolves")
	}
}

func TestRootCauseResolverUnparseableKeepsNotFound(t *testing.T) {
	client, srv := mockServer(t, "not json at all")
	defer srv.Close()
	r := &RootCauseResolver{Client: client, Fallback: stubResolver{
		model: &domain.RootCauseModel{Status: domain.RootCauseNotFound},
	}}
	c := newCase()
	m, _, _ := r.Resolve(context.Background(), c, domain.Vulnerability{})
	if m.Status == domain.RootCauseResolved || len(m.RootCauses) > 0 {
		t.Fatalf("model=%+v", m)
	}
}

func TestExploitModelBuilderRecordsProposal(t *testing.T) {
	reply := `{"impact":"xss","mandatory_conditions":[{"id":"C-LLM","kind":"VALIDATION","description":"needs escaping","subjects":[{"package":"p","symbol":"S"}]}]}`
	client, srv := mockServer(t, reply)
	defer srv.Close()

	fb := stubBuilder{model: &domain.ExploitModel{
		MandatoryConditions: []domain.Condition{{ID: "C-REACH", Kind: domain.ConditionSymbolReachable}},
	}}
	b := ExploitModelBuilder{Client: client, Fallback: fb}
	c := newCase()
	rc := &domain.RootCauseModel{Status: domain.RootCauseResolved,
		RootCauses: []domain.RootCause{{Package: "p", Symbol: "S", Role: domain.RootCauseSink}}}
	m, lims := b.Build(context.Background(), c, domain.Vulnerability{Summary: "x"}, rc)
	if m == nil || len(m.MandatoryConditions) != 1 || len(m.ProposedConditions) != 1 {
		t.Fatalf("model=%+v lims=%v", m, lims)
	}
	if m.ProposedConditions[0].ID != "C-LLM" || m.ProposedConditions[0].Mandatory {
		t.Fatalf("model proposal is not a non-authoritative nomination: %+v", m.ProposedConditions)
	}
}

func TestExploitModelBuilderRejectsNonSinkSubject(t *testing.T) {
	reply := `{"mandatory_conditions":[{"id":"C-X","kind":"SYMBOL_REACHABLE","subjects":[{"package":"evil","symbol":"F"}]}]}`
	client, srv := mockServer(t, reply)
	defer srv.Close()
	fb := stubBuilder{model: &domain.ExploitModel{
		MandatoryConditions: []domain.Condition{{ID: "C-REACH"}},
	}}
	b := ExploitModelBuilder{Client: client, Fallback: fb}
	c := newCase()
	rc := &domain.RootCauseModel{Status: domain.RootCauseResolved,
		RootCauses: []domain.RootCause{{Package: "p", Symbol: "S", Role: domain.RootCauseSink}}}
	m, lims := b.Build(context.Background(), c, domain.Vulnerability{}, rc)
	if len(m.MandatoryConditions) != 1 {
		t.Fatalf("model=%+v", m)
	}
	joined := ""
	for _, l := range lims {
		joined += l
	}
	if joined == "" {
		t.Fatal("rejection must surface as limitation")
	}
}

func TestLLMReviewerParsesRevise(t *testing.T) {
	reply := `{"result":"REVISE","findings":[{"target_type":"claim","target_id":"CL-1","problem":"unsupported","severity":"high"}]}`
	client, srv := mockServer(t, reply)
	defer srv.Close()
	rv := Reviewer{Client: client}
	c := newCase()
	r := rv.Review(c, domain.VerdictResult{Verdict: domain.VerdictExploitable})
	if r.Result != domain.ReviewRevise || len(r.Findings) != 1 {
		t.Fatalf("review=%+v", r)
	}
}

func TestExtractJSON(t *testing.T) {
	cases := map[string]string{
		"```json\n{\"a\":1}\n```": `{"a":1}`,
		"prefix {\"a\":2} suffix": `{"a":2}`,
		"[1,2]":                   "[1,2]",
		"no json":                 "",
	}
	for in, want := range cases {
		if got := ExtractJSON(in); got != want {
			t.Fatalf("ExtractJSON(%q)=%q want %q", in, got, want)
		}
	}
}

type stubResolver struct {
	model *domain.RootCauseModel
	evs   []domain.Evidence
	err   error
}

func (s stubResolver) Resolve(_ context.Context, _ *domain.AnalysisCase, _ domain.Vulnerability) (*domain.RootCauseModel, []domain.Evidence, error) {
	return s.model, s.evs, s.err
}

type stubBuilder struct {
	model *domain.ExploitModel
	lims  []string
}

func (s stubBuilder) Build(_ context.Context, _ *domain.AnalysisCase, _ domain.Vulnerability, _ *domain.RootCauseModel) (*domain.ExploitModel, []string) {
	return s.model, s.lims
}

// scriptServer returns queued responses in order, then repeats the last.
func scriptServer(t *testing.T, replies ...string) (*Client, *httptest.Server, *int) {
	t.Helper()
	var n int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i := n
		if i >= len(replies) {
			i = len(replies) - 1
		}
		n++
		resp := chatResponse{Choices: []struct {
			Message      chatMessage `json:"message"`
			FinishReason string      `json:"finish_reason"`
		}{{Message: chatMessage{Role: "assistant", Content: replies[i]}}}}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	return NewClient(Config{BaseURL: srv.URL, AnalyzeModel: "m", Enabled: true}), srv, &n
}

func TestAgentRecordsProposalWithTools(t *testing.T) {
	// Step 1: tool call to trace_argument; step 2: a TRUE proposal citing
	// the evidence the tool produced. The tool result is authoritative
	// evidence; the model's conclusion is only recorded as a proposal until
	// the deterministic evaluator re-derives it.
	client, srv, calls := scriptServer(t,
		`{"tool_calls":[{"name":"find_callers","args":{"package":"example.com/dep","symbol":"vuln.Parse"},"purpose":"locate sinks"}]}`,
		`{"claim":{"result":"TRUE","evidence_ids":["EV-001"],"explanation":"arg flows from os.Args"}}`)
	defer srv.Close()

	ix := &goanalysis.Index{Dir: filepath.Join("..", "..", "testdata", "constprod")}
	ev := ClaimEvaluator{Client: client, Tools: Tools{Source: ix}, MaxSteps: 4}
	c := newCase()
	cond := domain.Condition{ID: "C-IN", Kind: domain.ConditionInputConstraint,
		Subjects: []domain.SymbolRef{{Package: "example.com/dep", Symbol: "vuln.Parse"}}}
	cl := ev.Evaluate(cond, c)
	if cl.Result != domain.ClaimUnknown {
		t.Fatalf("a model conclusion must not establish the result: %+v", cl)
	}
	if cl.Proposal != domain.ClaimTrue {
		t.Fatalf("the model nomination must be recorded: %+v", cl)
	}
	if len(cl.EvidenceIDs) == 0 {
		t.Fatal("the proposal must cite the evidence it relied on")
	}
	if *calls != 2 {
		t.Fatalf("calls=%d", *calls)
	}
}

func TestAgentKeepsUnknownWithoutEvidence(t *testing.T) {
	client, srv, _ := scriptServer(t,
		`{"claim":{"result":"TRUE","evidence_ids":["EV-999"],"explanation":"made up"}}`)
	defer srv.Close()
	ix := &goanalysis.Index{Dir: filepath.Join("..", "..", "testdata", "constprod")}
	ev := ClaimEvaluator{Client: client, Tools: Tools{Source: ix}}
	cl := ev.Evaluate(domain.Condition{ID: "C-X", Kind: domain.ConditionCustom}, newCase())
	if cl.Result != domain.ClaimUnknown {
		t.Fatalf("unsupported TRUE must not survive: %+v", cl)
	}
	if cl.Proposal != domain.ClaimTrue {
		t.Fatalf("the rejected nomination is still recorded: %+v", cl)
	}
}

// Existing evidence is not entailment: an evidence id that already sits in
// the graph proves only that the cited material exists. It cannot establish
// the claim's truth, so the result stays UNKNOWN and the model's answer is
// recorded as a proposal.
func TestAgentExistingEvidenceDoesNotProveClaim(t *testing.T) {
	client, srv, _ := scriptServer(t,
		`{"claim":{"result":"TRUE","evidence_ids":["EV-EXISTING"],"explanation":"the graph already contains this"}}`)
	defer srv.Close()
	ix := &goanalysis.Index{Dir: filepath.Join("..", "..", "testdata", "constprod")}
	ev := ClaimEvaluator{Client: client, Tools: Tools{Source: ix}}
	c := newCase()
	c.EvidenceGraph.Evidence = append(c.EvidenceGraph.Evidence, domain.Evidence{
		ID: "EV-EXISTING", Kind: domain.EvidenceSourceSnippet, Content: "pre-existing evidence",
	})
	cl := ev.Evaluate(domain.Condition{ID: "C-X", Kind: domain.ConditionCustom}, c)
	if cl.Result != domain.ClaimUnknown {
		t.Fatalf("an existing evidence id must not establish TRUE: %+v", cl)
	}
	if cl.Proposal != domain.ClaimTrue {
		t.Fatalf("the nomination must be recorded separately: %+v", cl)
	}
	if len(cl.EvidenceIDs) != 1 || cl.EvidenceIDs[0] != "EV-EXISTING" {
		t.Fatalf("the proposal's cited evidence must be recorded: %+v", cl.EvidenceIDs)
	}
}

func TestAgentStopsAtStepBudget(t *testing.T) {
	client, srv, calls := scriptServer(t, `{"tool_calls":[{"name":"find_entrypoints","args":{},"purpose":"x"}]}`)
	defer srv.Close()
	ix := &goanalysis.Index{Dir: filepath.Join("..", "..", "testdata", "constprod")}
	ev := ClaimEvaluator{Client: client, Tools: Tools{Source: ix}, MaxSteps: 2}
	cl := ev.Evaluate(domain.Condition{ID: "C-X", Kind: domain.ConditionCustom}, newCase())
	if cl.Result != domain.ClaimUnknown {
		t.Fatalf("claim=%+v", cl)
	}
	if *calls != 2 {
		t.Fatalf("calls=%d want 2", *calls)
	}
}

func TestBuildRetriesOnBadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req chatRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		reply := "garbage"
		if req.Messages[1].Content != "" && req.Model == "m" {
			// second call returns valid JSON
			if len(req.Messages) > 0 && req.Messages[0].Role == "system" {
				// distinguish attempts via call count is hard here; use a flag
			}
		}
		resp := chatResponse{Choices: []struct {
			Message      chatMessage `json:"message"`
			FinishReason string      `json:"finish_reason"`
		}{{Message: chatMessage{Role: "assistant", Content: reply}}}}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()
	client := NewClient(Config{BaseURL: srv.URL, BuildModel: "m", AnalyzeModel: "m", Enabled: true, BuildMaxRetries: 2})
	r := &RootCauseResolver{Client: client, Fallback: stubResolver{model: &domain.RootCauseModel{Status: domain.RootCauseNotFound}}}
	c := newCase()
	m, _, _ := r.Resolve(context.Background(), c, domain.Vulnerability{ID: "X"})
	if len(m.RootCauses) != 0 {
		t.Fatalf("model=%+v", m)
	}
	if c.Workflow.Usage.LLMCalls != 3 { // 1 + 2 retries
		t.Fatalf("llm calls=%d want 3", c.Workflow.Usage.LLMCalls)
	}
}

func TestDescribeBadOutput(t *testing.T) {
	cases := []struct {
		name    string
		content string
		finish  string
		want    string
	}{
		{"gemini refusal text", `his request was blocked by Gemini's filters. They can occasionally trigger by mistake on safe coding, security, or biology-related queries.`, "", "provider refusal"},
		{"finish content_filter", "", "content_filter", "provider refusal (finish_reason=content_filter)"},
		{"finish safety", "partial", "safety", "provider refusal (finish_reason=safety)"},
		{"empty stop", "   ", "stop", "empty output"},
		{"empty max", "", "length", "empty output (finish_reason=length)"},
		{"truncated json", `{"a": 1, "b":`, "length", "truncated output"},
		{"prose", "I would suggest looking at the code paths.", "stop", "non-JSON output"},
		{"generic refusal", "I'm sorry, but I cannot help with exploit code.", "", "provider refusal"},
	}
	for _, tc := range cases {
		got := DescribeBadOutput(tc.content, tc.finish)
		if !strings.HasPrefix(got, tc.want) {
			t.Errorf("%s: got %q want prefix %q", tc.name, got, tc.want)
		}
	}
	// snippet carries raw text for diagnosis, bounded
	d := DescribeBadOutput(strings.Repeat("x", 300), "")
	if !strings.Contains(d, "non-JSON output: ") || len(d) > 200 {
		t.Errorf("snippet unbounded or missing: %q…", d[:60])
	}
}

func TestStrictLLMExploitBuilderFailFast(t *testing.T) {
	// Refusal reply
	reply := `This request was blocked by Gemini's filters.`
	client, srv := mockServer(t, reply)
	defer srv.Close()

	fb := stubBuilder{model: &domain.ExploitModel{
		MandatoryConditions: []domain.Condition{{ID: "C-REACH"}},
	}}
	b := ExploitModelBuilder{Client: client, Fallback: fb}
	c := newCase()
	c.StrictLLM = true
	rc := &domain.RootCauseModel{
		Status:     domain.RootCauseResolved,
		RootCauses: []domain.RootCause{{Package: "p", Symbol: "S", Role: domain.RootCauseSink}},
	}
	m, lims := b.Build(context.Background(), c, domain.Vulnerability{}, rc)
	if m != nil {
		t.Fatalf("expected nil model under StrictLLM, got %+v", m)
	}
	joined := strings.Join(lims, " ")
	if !strings.Contains(joined, "strict-llm:") {
		t.Fatalf("expected strict-llm limitation, got %v", lims)
	}
}

func TestStrictLLMReviewerFailFast(t *testing.T) {
	reply := `This request was blocked by Gemini's filters.`
	client, srv := mockServer(t, reply)
	defer srv.Close()

	rv := Reviewer{Client: client}
	c := newCase()
	c.StrictLLM = true
	r := rv.Review(c, domain.VerdictResult{Verdict: domain.VerdictExploitable})
	if r.Result != domain.ReviewRevise {
		t.Fatalf("expected ReviewRevise under StrictLLM refusal, got %v", r.Result)
	}
	found := false
	for _, f := range r.Findings {
		if strings.HasPrefix(f.Problem, "strict-llm:") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected finding with strict-llm: prefix, got %+v", r.Findings)
	}
}

func TestUsageRecordsEveryProviderAttempt(t *testing.T) {
	var captured []ChatExchange
	sink := func(ex ChatExchange) {
		captured = append(captured, ex)
	}

	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			// First attempt fails with 500 error containing sensitive credential
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`internal server error with Authorization: Bearer sk-secret12345678901234567890`))
			return
		}
		// Second attempt succeeds
		resp := map[string]any{
			"id": "chatcmpl-test-123",
			"model": "gpt-4o-2024-08-06",
			"system_fingerprint": "fp_test_abc",
			"choices": []any{
				map[string]any{
					"message": map[string]string{"role": "assistant", "content": "hello world"},
					"finish_reason": "stop",
				},
			},
			"usage": map[string]int{
				"prompt_tokens": 12,
				"completion_tokens": 4,
				"total_tokens": 16,
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	cfg := Config{
		BaseURL: srv.URL,
		AnalyzeModel: "gpt-4o",
		Enabled: true,
		ExchangeSink: sink,
	}
	client := NewClient(cfg)

	// First call fails
	_, _, err := client.Chat(context.Background(), Analyze, "system", []ChatMessage{{Role: "user", Content: "hi"}}, nil)
	if err == nil {
		t.Fatal("expected error on attempt 1")
	}

	// Second call succeeds
	_, _, err = client.Chat(context.Background(), Analyze, "system", []ChatMessage{{Role: "user", Content: "hi"}}, nil)
	if err != nil {
		t.Fatalf("attempt 2 failed: %v", err)
	}

	if len(captured) != 2 {
		t.Fatalf("expected 2 captured exchanges, got %d", len(captured))
	}

	// Check attempt 1 (failed)
	ex1 := captured[0]
	if ex1.StatusCode != http.StatusInternalServerError {
		t.Fatalf("attempt 1 status = %d, want 500", ex1.StatusCode)
	}
	if strings.Contains(ex1.Error, "sk-secret12345678901234567890") {
		t.Fatalf("attempt 1 leaked secret in error: %s", ex1.Error)
	}
	if !strings.Contains(ex1.Error, "[REDACTED]") {
		t.Fatalf("attempt 1 error should redact secret: %s", ex1.Error)
	}

	// Check attempt 2 (success)
	ex2 := captured[1]
	if ex2.StatusCode != http.StatusOK {
		t.Fatalf("attempt 2 status = %d, want 200", ex2.StatusCode)
	}
	if ex2.ReturnedModel != "gpt-4o-2024-08-06" {
		t.Fatalf("returned model = %q, want gpt-4o-2024-08-06", ex2.ReturnedModel)
	}
	if ex2.ProviderFingerprint != "fp_test_abc" {
		t.Fatalf("fingerprint = %q, want fp_test_abc", ex2.ProviderFingerprint)
	}
	if !ex2.HasUsage || ex2.Usage == nil {
		t.Fatalf("expected usage recorded, got %+v", ex2)
	}
	if *ex2.Usage.PromptTokens != 12 || *ex2.Usage.CompletionTokens != 4 || *ex2.Usage.TotalTokens != 16 {
		t.Fatalf("unexpected tokens: %+v", *ex2.Usage)
	}
}

func TestMissingProviderUsageIsUnassessed(t *testing.T) {
	var captured []ChatExchange
	sink := func(ex ChatExchange) {
		captured = append(captured, ex)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Response without usage object
		resp := map[string]any{
			"id": "chatcmpl-test-456",
			"model": "gpt-4o",
			"choices": []any{
				map[string]any{
					"message": map[string]string{"role": "assistant", "content": "answer"},
					"finish_reason": "stop",
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	cfg := Config{
		BaseURL: srv.URL,
		AnalyzeModel: "gpt-4o",
		Enabled: true,
		ExchangeSink: sink,
	}
	client := NewClient(cfg)

	_, _, err := client.Chat(context.Background(), Analyze, "system", []ChatMessage{{Role: "user", Content: "hi"}}, nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(captured) != 1 {
		t.Fatalf("expected 1 captured exchange, got %d", len(captured))
	}
	ex := captured[0]
	if ex.HasUsage {
		t.Fatalf("expected HasUsage == false when provider returns no usage block, got true")
	}
	if ex.Usage != nil {
		t.Fatalf("expected Usage == nil when provider returns no usage block (unassessed, not estimated), got %+v", ex.Usage)
	}
}

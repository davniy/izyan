package triage

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/fedorovmv/izyan/internal/llm"
)

type scriptedChat struct {
	responses []llm.ChatMessage
	finishes  []string
	calls     int
}

func (s *scriptedChat) Chat(_ context.Context, _ llm.ModelRole, _ string, _ []llm.ChatMessage, _ []llm.ToolDefinition) (llm.ChatMessage, string, error) {
	if s.calls >= len(s.responses) {
		// The script ran out but the runner still asks — the budget
		// finalization call is one such path. Answer like a model stuck on
		// its last response so under-provisioned tests fail the run instead
		// of panicking inside the fake.
		s.calls++
		return s.responses[len(s.responses)-1], "stop", nil
	}
	m := s.responses[s.calls]
	f := "stop"
	if s.calls < len(s.finishes) {
		f = s.finishes[s.calls]
	}
	s.calls++
	return m, f, nil
}

// erringChat returns the scripted errors first and falls through to
// scriptedChat responses once they are exhausted, so tests can script
// "fail N times, then reply" sequences. calls counts every attempt; the
// embedded scriptedChat keeps its own counter for response indexing.
type erringChat struct {
	scriptedChat
	errs  []error
	calls int
}

func (e *erringChat) Chat(ctx context.Context, role llm.ModelRole, system string, messages []llm.ChatMessage, defs []llm.ToolDefinition) (llm.ChatMessage, string, error) {
	e.calls++
	if len(e.errs) > 0 {
		err := e.errs[0]
		e.errs = e.errs[1:]
		return llm.ChatMessage{}, "", err
	}
	return e.scriptedChat.Chat(ctx, role, system, messages, defs)
}

// noSleep is the AgentRunner.Sleep override that keeps retry backoff
// instant in tests while preserving the context contract.
func noSleep(ctx context.Context, _ time.Duration) error { return ctx.Err() }

// staticTools answers every tool call with a fixed OK observation.
type staticTools struct{}

func (staticTools) Definitions() []llm.ToolDefinition {
	return []llm.ToolDefinition{{Type: "function", Function: llm.FunctionSpec{Name: "noop"}}}
}

func (staticTools) Call(_ context.Context, _ string, _ json.RawMessage) ToolObservation {
	return ToolObservation{ID: "o1", Tool: "noop", Status: ToolStatusOK}
}

func toolCallMsg() llm.ChatMessage {
	return llm.ChatMessage{
		Role:      "assistant",
		ToolCalls: []llm.ToolCall{{ID: "c1", Type: "function", Function: llm.FunctionCall{Name: "noop", Arguments: "{}"}}},
	}
}

// nudgeAwareChat requests tool calls until the transcript contains the
// step-budget nudge, then returns the final assessment.
type nudgeAwareChat struct{ calls int }

func (n *nudgeAwareChat) Chat(_ context.Context, _ llm.ModelRole, _ string, messages []llm.ChatMessage, _ []llm.ToolDefinition) (llm.ChatMessage, string, error) {
	n.calls++
	last := messages[len(messages)-1]
	if last.Role == "user" && last.Content == budgetNudge {
		return llm.ChatMessage{Role: "assistant", Content: validAssessment()}, "stop", nil
	}
	return toolCallMsg(), "tool_calls", nil
}

// alwaysToolChat never produces an assessment — it requests a tool call on
// every step, exhausting the step budget.
type alwaysToolChat struct{ calls int }

func (a *alwaysToolChat) Chat(_ context.Context, _ llm.ModelRole, _ string, _ []llm.ChatMessage, _ []llm.ToolDefinition) (llm.ChatMessage, string, error) {
	a.calls++
	return toolCallMsg(), "tool_calls", nil
}

func countNudges(messages []llm.ChatMessage) int {
	n := 0
	for _, m := range messages {
		if m.Role == "user" && m.Content == budgetNudge {
			n++
		}
	}
	return n
}

func validAssessment() string {
	return `{"schema_version":"`+AssessmentSchemaVersion+`","finding_id":"f","verdict":"INCONCLUSIVE","summary":"unknown",` +
		`"claims":[{"id":"c1","statement":"the captured material does not establish exploitability","basis":"INTERPRETED","subject":"exploitability of the affected path","scope":"captured product snapshot","decision_relevant":true}],` +
		`"proposed_action":{"kind":"OBTAIN_EVIDENCE","instruction":"capture the deployment configuration for the affected module","rationale":"reachability of the affected path depends on uncaptured configuration","scope":"affected deployment configuration","decisive_claim_ids":["c1"],"reconsider_when":["deployment configuration is captured"]}}`
}

func TestAgentRetryTransientThenSuccess(t *testing.T) {
	client := &erringChat{
		scriptedChat: scriptedChat{responses: []llm.ChatMessage{{Role: "assistant", Content: validAssessment()}}},
		errs:         []error{errors.New("llm status 503: {\"error\":\"unavailable\"}")},
	}
	runner := AgentRunner{Client: client, Limits: AgentLimits{MaxSteps: 2}, Sleep: noSleep}
	run, err := runner.Run(context.Background(), FindingInput{Finding: Finding{FindingID: "f"}}, SnapshotManifest{FindingID: "f"})
	if err != nil {
		t.Fatalf("transient 503 must be retried: %v", err)
	}
	if client.calls != 2 {
		t.Fatalf("expected 2 chat calls (503 then success), got %d", client.calls)
	}
	if run.Assessment.Verdict != VerdictInconclusive {
		t.Fatalf("unexpected run: %+v", run)
	}
}

func TestAgentRetryExhausted(t *testing.T) {
	boom := func() error { return errors.New("llm status 500: boom") }
	client := &erringChat{errs: []error{boom(), boom(), boom(), boom()}}
	runner := AgentRunner{Client: client, Limits: AgentLimits{MaxSteps: 4}, Sleep: noSleep}
	run, err := runner.Run(context.Background(), FindingInput{Finding: Finding{FindingID: "f"}}, SnapshotManifest{FindingID: "f"})
	if err == nil {
		t.Fatal("expected provider error after retries are exhausted")
	}
	if client.calls != chatMaxAttempts {
		t.Fatalf("expected %d attempts, got %d", chatMaxAttempts, client.calls)
	}
	if run.ErrorClass != ErrClassProvider {
		t.Fatalf("error class %q, want %q", run.ErrorClass, ErrClassProvider)
	}
	if len(run.RawMessages) == 0 {
		t.Fatal("partial run must keep the transcript")
	}
}

func TestAgentRetryNonTransientFailsImmediately(t *testing.T) {
	for _, text := range []string{
		"llm status 400: bad request",
		"llm status 401: unauthorized",
		"llm status 403: forbidden",
		"llm status 404: not found",
		"llm error: provider rejection",
	} {
		client := &erringChat{errs: []error{errors.New(text)}}
		runner := AgentRunner{Client: client, Limits: AgentLimits{MaxSteps: 2}, Sleep: noSleep}
		if _, err := runner.Run(context.Background(), FindingInput{Finding: Finding{FindingID: "f"}}, SnapshotManifest{FindingID: "f"}); err == nil {
			t.Fatalf("%s: expected error", text)
		}
		if client.calls != 1 {
			t.Fatalf("%s: non-transient error must not be retried, got %d calls", text, client.calls)
		}
	}
}

func TestAgentRetryTransientClasses(t *testing.T) {
	for _, text := range []string{
		"llm status 429: rate limited",
		"llm status 502: bad gateway",
		"llm request: dial tcp: connection refused",
		"llm read: unexpected EOF",
		"connection refused",
	} {
		client := &erringChat{
			scriptedChat: scriptedChat{responses: []llm.ChatMessage{{Role: "assistant", Content: validAssessment()}}},
			errs:         []error{errors.New(text)},
		}
		runner := AgentRunner{Client: client, Limits: AgentLimits{MaxSteps: 2}, Sleep: noSleep}
		if _, err := runner.Run(context.Background(), FindingInput{Finding: Finding{FindingID: "f"}}, SnapshotManifest{FindingID: "f"}); err != nil {
			t.Fatalf("%s: transient error must be retried: %v", text, err)
		}
		if client.calls != 2 {
			t.Fatalf("%s: expected 2 calls, got %d", text, client.calls)
		}
	}
}

// TestAgentNudgeFinalizes covers the step-budget nudge: with ≤2 steps left
// and the agent still requesting tools, the runner injects one user message
// demanding the final assessment.v2 JSON — and accepts that final answer.
func TestAgentNudgeFinalizes(t *testing.T) {
	client := &nudgeAwareChat{}
	runner := AgentRunner{Client: client, Tools: staticTools{}, Limits: AgentLimits{MaxSteps: 4}, Sleep: noSleep}
	run, err := runner.Run(context.Background(), FindingInput{Finding: Finding{FindingID: "f"}}, SnapshotManifest{FindingID: "f"})
	if err != nil {
		t.Fatalf("the final answer after the nudge must be accepted: %v", err)
	}
	if run.Assessment.Verdict != VerdictInconclusive {
		t.Fatalf("unexpected run: %+v", run)
	}
	if client.calls != 3 {
		t.Fatalf("expected 3 chat calls (2 tool steps + final), got %d", client.calls)
	}
	if n := countNudges(run.RawMessages); n != 1 {
		t.Fatalf("expected exactly one nudge in the transcript, got %d", n)
	}
}

// TestAgentNudgeSentOnce: an agent that ignores the nudge and keeps calling
// tools must still see it exactly once per run before the step budget dies.
func TestAgentNudgeSentOnce(t *testing.T) {
	client := &alwaysToolChat{}
	runner := AgentRunner{Client: client, Tools: staticTools{}, Limits: AgentLimits{MaxSteps: 5}, Sleep: noSleep}
	run, err := runner.Run(context.Background(), FindingInput{Finding: Finding{FindingID: "f"}}, SnapshotManifest{FindingID: "f"})
	if err == nil {
		t.Fatal("expected step budget exhaustion")
	}
	if run.ErrorClass != ErrClassStepBudget {
		t.Fatalf("error class %q, want %q", run.ErrorClass, ErrClassStepBudget)
	}
	if n := countNudges(run.RawMessages); n != 1 {
		t.Fatalf("expected exactly one nudge in the transcript, got %d", n)
	}
}

// TestAgentPartialStateOnError: a dead run returns the accumulated state —
// transcript, consumed steps/tool calls, prompt hash and failure class —
// which is exactly what WriteFailure persists.
func TestAgentPartialStateOnError(t *testing.T) {
	boom := func() error { return errors.New("llm status 500: boom") }
	client := &erringChat{errs: []error{boom(), boom(), boom()}}
	runner := AgentRunner{Client: client, Tools: staticTools{}, Limits: AgentLimits{MaxSteps: 4}, Sleep: noSleep}
	run, err := runner.Run(context.Background(), FindingInput{Finding: Finding{FindingID: "f"}}, SnapshotManifest{FindingID: "f"})
	if err == nil {
		t.Fatal("expected error")
	}
	if run.PromptHash == "" || len(run.RawMessages) == 0 || run.Steps == 0 {
		t.Fatalf("partial run lost its state: %+v", run)
	}
	if run.ErrorClass == "" {
		t.Fatal("partial run must record the error class")
	}
}

func TestAgentRunnerReturnsAssessment(t *testing.T) {
	client := &scriptedChat{responses: []llm.ChatMessage{{Role: "assistant", Content: validAssessment()}}}
	run, err := (AgentRunner{Client: client, Limits: AgentLimits{MaxSteps: 2}}).Run(context.Background(), FindingInput{Finding: Finding{FindingID: "f"}}, SnapshotManifest{FindingID: "f"})
	if err != nil {
		t.Fatal(err)
	}
	if run.Assessment.Verdict != VerdictInconclusive || run.PromptHash == "" || run.ResponseHash == "" {
		t.Fatalf("unexpected run: %+v", run)
	}
}

func TestAgentRefusalIsTechnicalError(t *testing.T) {
	client := &scriptedChat{responses: []llm.ChatMessage{{Role: "assistant", Content: "I cannot assist with this"}}}
	run, err := (AgentRunner{Client: client, Limits: AgentLimits{MaxSteps: 2}}).Run(context.Background(), FindingInput{}, SnapshotManifest{})
	if err == nil || run.Assessment.Verdict == VerdictNotExploitable {
		t.Fatalf("expected technical refusal, run=%+v err=%v", run, err)
	}
}

func TestAgentBudget(t *testing.T) {
	client := &scriptedChat{responses: []llm.ChatMessage{{Role: "assistant", Content: "not json"}, {Role: "assistant", Content: "still not json"}}}
	_, err := (AgentRunner{Client: client, Limits: AgentLimits{MaxSteps: 1}}).Run(context.Background(), FindingInput{}, SnapshotManifest{})
	if err == nil {
		t.Fatal("expected step budget error")
	}
}

func TestAgentRunnerRejectsMissingFindingID(t *testing.T) {
	bad := `{"schema_version":"`+AssessmentSchemaVersion+`","verdict":"INCONCLUSIVE","summary":"unknown"}`
	client := &scriptedChat{responses: []llm.ChatMessage{{Role: "assistant", Content: bad}, {Role: "assistant", Content: bad}}}
	_, err := (AgentRunner{Client: client, Limits: AgentLimits{MaxSteps: 3}}).Run(context.Background(), FindingInput{Finding: Finding{FindingID: "f"}}, SnapshotManifest{FindingID: "f"})
	if err == nil {
		t.Fatal("missing finding_id must be a technical error")
	}
}

func TestAgentRunnerRejectsForeignFindingID(t *testing.T) {
	bad := `{"schema_version":"`+AssessmentSchemaVersion+`","finding_id":"other","verdict":"INCONCLUSIVE","summary":"unknown"}`
	client := &scriptedChat{responses: []llm.ChatMessage{{Role: "assistant", Content: bad}, {Role: "assistant", Content: bad}}}
	_, err := (AgentRunner{Client: client, Limits: AgentLimits{MaxSteps: 3}}).Run(context.Background(), FindingInput{Finding: Finding{FindingID: "f"}}, SnapshotManifest{FindingID: "f"})
	if err == nil {
		t.Fatal("mismatched finding_id must be a technical error")
	}
}

// TestAgentRepairTurnCarriesDecodeErrorAndSchema: after an invalid final
// answer the run gets exactly one repair turn; it must tell the model what
// failed to decode and restate the exact assessment.v2 shape, without
// echoing the raw response back.
func TestAgentRepairTurnCarriesDecodeErrorAndSchema(t *testing.T) {
	bad := `{"schema_version":"`+AssessmentSchemaVersion+`","finding_id":"f","verdict":"VULNERABLE","summary":"x"}`
	client := &scriptedChat{responses: []llm.ChatMessage{
		{Role: "assistant", Content: bad},
		{Role: "assistant", Content: validAssessment()},
	}}
	run, err := (AgentRunner{Client: client, Limits: AgentLimits{MaxSteps: 3}}).Run(context.Background(), FindingInput{Finding: Finding{FindingID: "f"}}, SnapshotManifest{FindingID: "f"})
	if err != nil {
		t.Fatalf("repair turn must be able to succeed: %v", err)
	}
	var repairs []string
	for _, m := range run.RawMessages {
		if m.Role == "user" && strings.Contains(m.Content, "Repair exactly once") {
			repairs = append(repairs, m.Content)
		}
	}
	if len(repairs) != 1 {
		t.Fatalf("expected exactly one repair turn, got %d", len(repairs))
	}
	repair := repairs[0]
	for _, want := range []string{
		"did not decode", `invalid verdict "VULNERABLE"`,
		"claims is an array of objects {id, statement, basis, subject, scope, decision_relevant, evidence_refs, depends_on, binding, owner, reason, conflicts_with}",
		"evidence is an array of objects {id, kind, locator, quote, sha256}",
		`schema_version="`+AssessmentSchemaVersion+`"`,
		"proposed_action",
		"EXPLOITABLE, NOT_EXPLOITABLE, INCONCLUSIVE",
	} {
		if !strings.Contains(repair, want) {
			t.Fatalf("repair message missing %q:\n%s", want, repair)
		}
	}
	if strings.Contains(repair, `"summary":"x"`) {
		t.Fatal("repair message must not echo the raw response")
	}
}

// TestAgentRepairTurnForDanglingEvidenceRef: a claim citing an undeclared
// evidence id is a decode error, not a gate INVALID — the single repair
// turn names the offending claim and id so the model can fix the structure.
func TestAgentRepairTurnForDanglingEvidenceRef(t *testing.T) {
	bad := `{"schema_version":"`+AssessmentSchemaVersion+`","finding_id":"f","verdict":"NOT_EXPLOITABLE","summary":"x","claims":[{"id":"c1","statement":"safe","basis":"INTERPRETED","subject":"reachability","scope":"captured snapshot","decision_relevant":true,"evidence_refs":["e-ghost"]}],"evidence":[{"id":"e1","kind":"file","locator":"main.go"}],"proposed_action":{"kind":"CLOSE","instruction":"close","rationale":"no reachable path","scope":"captured build","decisive_claim_ids":["c1"],"reconsider_when":["new evidence"]}}`
	client := &scriptedChat{responses: []llm.ChatMessage{
		{Role: "assistant", Content: bad},
		{Role: "assistant", Content: validAssessment()},
	}}
	run, err := (AgentRunner{Client: client, Limits: AgentLimits{MaxSteps: 3}}).Run(context.Background(), FindingInput{Finding: Finding{FindingID: "f"}}, SnapshotManifest{FindingID: "f"})
	if err != nil {
		t.Fatalf("repair turn must be able to succeed: %v", err)
	}
	var repairs []string
	for _, m := range run.RawMessages {
		if m.Role == "user" && strings.Contains(m.Content, "Repair exactly once") {
			repairs = append(repairs, m.Content)
		}
	}
	if len(repairs) != 1 {
		t.Fatalf("expected exactly one repair turn, got %d", len(repairs))
	}
	for _, want := range []string{`claim "c1" cites undeclared evidence id "e-ghost"`} {
		if !strings.Contains(repairs[0], want) {
			t.Fatalf("repair message missing %q:\n%s", want, repairs[0])
		}
	}
}

// TestDecodeAssessmentRejectsDanglingRefs pins the structural rule at the
// decode boundary: evidence_refs must name ids declared in the same
// assessment, so a dangling reference is repaired, never gated INVALID.
func TestDecodeAssessmentRejectsDanglingRefs(t *testing.T) {
	_, err := decodeAssessment(
		`{"schema_version":"`+AssessmentSchemaVersion+`","finding_id":"scanner-123","verdict":"INCONCLUSIVE","summary":"s","claims":[{"id":"c9","statement":"x","basis":"INTERPRETED","subject":"subject","scope":"scope","decision_relevant":true,"evidence_refs":["e-missing"]}],"evidence":[{"id":"e1","kind":"file","locator":"main.go"}]}`,
		"scanner-123")
	if err == nil || !strings.Contains(err.Error(), `"c9"`) || !strings.Contains(err.Error(), `"e-missing"`) {
		t.Fatalf("dangling ref must fail decode with claim and id named: %v", err)
	}
	// Claims with no id are reported by position.
	_, err = decodeAssessment(
		`{"schema_version":"`+AssessmentSchemaVersion+`","finding_id":"scanner-123","verdict":"INCONCLUSIVE","summary":"s","claims":[{"statement":"x","basis":"INTERPRETED","subject":"subject","scope":"scope","evidence_refs":["ghost"]}]}`,
		"scanner-123")
	if err == nil || !strings.Contains(err.Error(), "claims[0]") || !strings.Contains(err.Error(), `"ghost"`) {
		t.Fatalf("id-less claim must be reported by position: %v", err)
	}
	// Declared refs still decode.
	if _, err = decodeAssessment(
		`{"schema_version":"`+AssessmentSchemaVersion+`","finding_id":"scanner-123","verdict":"INCONCLUSIVE","summary":"s","claims":[{"id":"c1","statement":"x","basis":"INTERPRETED","subject":"subject","scope":"scope","decision_relevant":true,"evidence_refs":["e1"]}],"evidence":[{"id":"e1","kind":"file","locator":"main.go"}],"proposed_action":{"kind":"KEEP_OPEN","instruction":"keep the ticket open","rationale":"the evidence is incomplete","scope":"captured snapshot","decisive_claim_ids":["c1"],"reconsider_when":["more evidence arrives"]}}`,
		"scanner-123"); err != nil {
		t.Fatalf("declared ref must decode: %v", err)
	}
}

// TestDecodeAssessmentStrictShapes: the v2 ingress no longer normalizes
// loose shapes. Bare-string claims and the removed free-form status are
// repairable errors, while the closed verdict enum and the conservative
// kind-less-evidence handling stay unchanged.
func TestDecodeAssessmentStrictShapes(t *testing.T) {
	for name, content := range map[string]string{
		"bare string claim": `{"schema_version":"`+AssessmentSchemaVersion+`","finding_id":"scanner-123","verdict":"INCONCLUSIVE","summary":"s","claims":["the dep is unused"]}`,
		"removed claim status": `{"schema_version":"`+AssessmentSchemaVersion+`","finding_id":"scanner-123","verdict":"INCONCLUSIVE","summary":"s",` +
			`"claims":[{"id":"c1","statement":"real","status":"supported","basis":"INTERPRETED","subject":"s","scope":"sc","decision_relevant":true}]}`,
		"missing claim basis": `{"schema_version":"`+AssessmentSchemaVersion+`","finding_id":"scanner-123","verdict":"INCONCLUSIVE","summary":"s",` +
			`"claims":[{"id":"c1","statement":"real","subject":"s","scope":"sc","decision_relevant":true}],` +
			`"proposed_action":{"kind":"KEEP_OPEN","instruction":"i","rationale":"r","scope":"sc","decisive_claim_ids":["c1"],"reconsider_when":["x"]}}`,
	} {
		if _, err := decodeAssessment(content, "scanner-123"); err == nil {
			t.Fatalf("%s: loose v2 shape must be rejected", name)
		}
	}

	// Kind-less evidence is still tolerated (it reports UNAVAILABLE at the
	// fact gate, never VALID), so the rest of the assessment stays usable.
	a, err := decodeAssessment(
		`{"schema_version":"`+AssessmentSchemaVersion+`","finding_id":"scanner-123","verdict":"INCONCLUSIVE","summary":"s",`+
			`"claims":[{"id":"c1","statement":"real","basis":"INTERPRETED","subject":"s","scope":"sc","decision_relevant":true,"evidence_refs":["e1"]}],`+
			`"evidence":[{"id":"e1","locator":"main.go:1"}],`+
			`"proposed_action":{"kind":"KEEP_OPEN","instruction":"i","rationale":"r","scope":"sc","decisive_claim_ids":["c1"],"reconsider_when":["x"]}}`,
		"scanner-123")
	if err != nil {
		t.Fatalf("kind-less evidence must still decode: %v", err)
	}
	if len(a.Evidence) != 1 || a.Evidence[0].Kind != "" {
		t.Fatalf("kind-less evidence must keep an empty kind: %+v", a.Evidence)
	}
	in, m := repoFixture(t)
	fv := FactGate{}.Validate(context.Background(), in, m, a)
	checks := checksByEvidence(fv)
	if checks["e1"] != FactUnavailable {
		t.Fatalf("kind-less evidence = %q, want UNAVAILABLE", checks["e1"])
	}
	if fv.Status != ValidationPartial {
		t.Fatalf("status = %q, want PARTIAL", fv.Status)
	}

	// Verdict synonyms are rejected, never mapped.
	for _, v := range []string{`"exploitable"`, `"NOT_AFFECTED"`, `"VULNERABLE"`} {
		body := `{"schema_version":"`+AssessmentSchemaVersion+`","finding_id":"scanner-123","verdict":` + v + `,"summary":"s"}`
		if _, err := decodeAssessment(body, "scanner-123"); err == nil {
			t.Fatalf("verdict %s must be rejected", v)
		}
	}
}

// TestDecodeAssessmentRejectsMachineFields pins the ownership boundary at
// the v2 ingress: the model may never self-declare deterministic
// annotations, computed support, proof outcomes, a machine disposition or
// the removed free-text recommendation, and truly unknown fields are
// rejected rather than silently dropped.
func TestDecodeAssessmentRejectsMachineFields(t *testing.T) {
	base := validAssessment()
	for field, value := range map[string]any{
		"fact_validation":        "COMPLETE",
		"fact_validation_detail": map[string]any{"status": "COMPLETE"},
		"automation":             "ALLOW",
		"automation_reason":      "none",
		"audit":                  map[string]any{"model": "x"},
		"verdict_source":         "agent",
		"support":                "SUBSTANTIATED",
		"support_level":          "SUBSTANTIATED",
		"decision_support":       "SUBSTANTIATED",
		"proofs":                 []any{},
		"falsifier_proofs":       []any{},
		"falsifier_verification": map[string]any{},
		"machine_disposition":    "DISMISSED",
		"machine_safe":           true,
		"disposition":            "DISMISSED",
		"policy_outcome":         "ALLOW",
		"human_decision":         "ACCEPT",
		"recommendation":         "DISMISSED",
		"agent_note":             "unknown field",
	} {
		t.Run(field, func(t *testing.T) {
			var doc map[string]any
			if err := json.Unmarshal([]byte(base), &doc); err != nil {
				t.Fatal(err)
			}
			doc[field] = value
			data, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			_, err = decodeAssessment(string(data), "f")
			if err == nil || !strings.Contains(err.Error(), field) {
				t.Fatalf("field %q must be rejected by name: %v", field, err)
			}
		})
	}
}

// gateRunFixture wires a real snapshot fixture into a scripted agent run:
// the assessment JSON shapes vary per test, the fact gate checks them
// against the same manifest the production CLI would use.
func gateRunFixture(t *testing.T) (FindingInput, SnapshotManifest) {
	t.Helper()
	return repoFixture(t)
}

func gateAssessmentJSON(claims, evidence string) string {
	return `{"schema_version":"`+AssessmentSchemaVersion+`","finding_id":"scanner-123","verdict":"NOT_EXPLOITABLE","summary":"s"` +
		`,"claims":` + claims + `,"evidence":` + evidence +
		`,"proposed_action":{"kind":"CLOSE","instruction":"close the ticket as not exploitable","rationale":"the recorded facts do not establish an exploitable path","scope":"captured product snapshot","decisive_claim_ids":["c1"],"reconsider_when":["new reachability evidence is captured"]}}`
}

func validGateAssessment() string {
	return gateAssessmentJSON(
		`[{"id":"c1","statement":"bounded read","basis":"INTERPRETED","subject":"bounded read","scope":"main.go","decision_relevant":true,"evidence_refs":["e1"]}]`,
		`[{"id":"e1","kind":"file","locator":"main.go:1-5"}]`)
}

// TestRepairLoopRepairsUnreferenced: a decision-relevant claim without
// evidence earns one structured feedback pass; the repaired assessment cites
// real snapshot evidence and the second gate pass verifies COMPLETE.
func TestRepairLoopRepairsUnreferenced(t *testing.T) {
	in, m := gateRunFixture(t)
	unreferenced := gateAssessmentJSON(
		`[{"id":"c1","statement":"bounded read","basis":"INTERPRETED","subject":"bounded read","scope":"main.go","decision_relevant":true}]`,
		`[{"id":"e1","kind":"file","locator":"main.go:1-5"}]`)
	client := &scriptedChat{responses: []llm.ChatMessage{
		{Role: "assistant", Content: unreferenced},
		{Role: "assistant", Content: validGateAssessment()},
	}}
	run, fv, err := (AgentRunner{Client: client, Limits: AgentLimits{MaxSteps: 4}}).
		RunWithFactGate(context.Background(), in, m, FactGate{}, 2)
	if err != nil {
		t.Fatalf("RunWithFactGate: %v", err)
	}
	if fv.Status != ValidationComplete {
		t.Fatalf("final validation = %s, want COMPLETE (%+v)", fv.Status, fv.References)
	}
	if client.calls != 2 {
		t.Fatalf("chat calls = %d, want 2", client.calls)
	}
	if len(run.FactPasses) != 2 {
		t.Fatalf("recorded passes = %+v, want initial+final reports", run.FactPasses)
	}
	if run.FactPasses[0].Feedback == nil || run.FactPasses[0].Feedback.Pass != 1 {
		t.Fatalf("first report must carry feedback pass 1: %+v", run.FactPasses[0])
	}
	if run.FactPasses[1].Feedback != nil {
		t.Fatalf("final report must carry no feedback: %+v", run.FactPasses[1])
	}
	var feedbackMsgs int
	for _, msg := range run.RawMessages {
		if msg.Role == "user" && strings.Contains(msg.Content, `"current_status":"UNREFERENCED"`) {
			feedbackMsgs++
			for _, banned := range []string{"EXPLOITABLE", "DISMISSED", "LOWERED", "UNCHANGED"} {
				if strings.Contains(msg.Content, banned) {
					t.Fatalf("feedback must not name a verdict, found %q:\n%s", banned, msg.Content)
				}
			}
		}
	}
	if feedbackMsgs != 1 {
		t.Fatalf("exactly one feedback message expected, got %d", feedbackMsgs)
	}
}

// TestRepairLoopBounded: an agent that never repairs the invalid locator is
// offered exactly two feedback passes — a third repair turn is never
// attempted — and the final report keeps the unresolved INVALID reference
// marked as blocking risk reduction.
func TestRepairLoopBounded(t *testing.T) {
	in, m := gateRunFixture(t)
	bad := gateAssessmentJSON(
		`[{"id":"c1","statement":"bounded read","basis":"INTERPRETED","subject":"bounded read","scope":"main.go","decision_relevant":true,"evidence_refs":["e1"]}]`,
		`[{"id":"e1","kind":"file","locator":"ghost.go"}]`)
	client := &scriptedChat{responses: []llm.ChatMessage{
		{Role: "assistant", Content: bad},
		{Role: "assistant", Content: bad},
		{Role: "assistant", Content: bad},
		{Role: "assistant", Content: bad},
	}}
	// Even a larger configured budget must clamp to the spec bound of two.
	run, fv, err := (AgentRunner{Client: client, Limits: AgentLimits{MaxSteps: 8}}).
		RunWithFactGate(context.Background(), in, m, FactGate{}, 9)
	if err != nil {
		t.Fatalf("unrepaired facts are a limitation, not a technical error: %v", err)
	}
	if client.calls != 3 {
		t.Fatalf("chat calls = %d, want initial + 2 feedback passes", client.calls)
	}
	if fv.Status != ValidationFailed || len(fv.References) != 1 || fv.References[0].Status != FactInvalid {
		t.Fatalf("final validation = %+v", fv)
	}
	if fv.References[0].Effect != EffectBlocksRiskReduction {
		t.Fatalf("unresolved decision-relevant reference must block risk reduction: %+v", fv.References[0])
	}
	if len(run.FactPasses) != 3 {
		t.Fatalf("recorded passes = %+v, want 3 reports", run.FactPasses)
	}
	for i, p := range run.FactPasses[:2] {
		if p.Feedback == nil || p.Feedback.Pass != i+1 {
			t.Fatalf("report %d feedback = %+v", i, p.Feedback)
		}
	}
	var feedbackMsgs int
	for _, msg := range run.RawMessages {
		if msg.Role == "user" && strings.Contains(msg.Content, `"current_status"`) {
			feedbackMsgs++
		}
	}
	if feedbackMsgs != 2 {
		t.Fatalf("feedback messages = %d, want 2", feedbackMsgs)
	}
}

// TestRepairLoopValidNoFeedback: a clean assessment never triggers a
// feedback turn — the gate report is recorded once and the runner stops.
func TestRepairLoopValidNoFeedback(t *testing.T) {
	in, m := gateRunFixture(t)
	client := &scriptedChat{responses: []llm.ChatMessage{
		{Role: "assistant", Content: validGateAssessment()},
	}}
	run, fv, err := (AgentRunner{Client: client, Limits: AgentLimits{MaxSteps: 2}}).
		RunWithFactGate(context.Background(), in, m, FactGate{}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if client.calls != 1 || fv.Status != ValidationComplete {
		t.Fatalf("calls=%d validation=%s, want 1/COMPLETE", client.calls, fv.Status)
	}
	if len(run.FactPasses) != 1 || run.FactPasses[0].Feedback != nil {
		t.Fatalf("a clean run records exactly one pass without feedback: %+v", run.FactPasses)
	}
}

// TestRepairLoopMalformedReplyIsError: inside a feedback pass a response
// that still does not decode after its single shape repair is a technical
// error — the loop must not spin on it.
func TestRepairLoopMalformedReplyIsError(t *testing.T) {
	in, m := gateRunFixture(t)
	unreferenced := gateAssessmentJSON(
		`[{"id":"c1","statement":"x","basis":"INTERPRETED","subject":"s","scope":"sc","decision_relevant":true}]`, `[]`)
	client := &scriptedChat{responses: []llm.ChatMessage{
		{Role: "assistant", Content: unreferenced},
		{Role: "assistant", Content: "not json"},
		{Role: "assistant", Content: "still not json"},
	}}
	run, _, err := (AgentRunner{Client: client, Limits: AgentLimits{MaxSteps: 8}}).
		RunWithFactGate(context.Background(), in, m, FactGate{}, 2)
	if err == nil {
		t.Fatal("undecodable feedback-pass reply must be a technical error")
	}
	if run.ErrorClass == "" || len(run.FactPasses) != 1 {
		t.Fatalf("partial run must keep class and recorded pass: %+v", run)
	}
}

// TestDecodeAssessmentClaimIDIsNotEvidence pins the two namespaces at the
// v2 ingress: a claim id listed in evidence_refs is a dangling evidence
// reference, never an entry to prune, and the valid spelling is an
// explicit depends_on relation.
func TestDecodeAssessmentClaimIDIsNotEvidence(t *testing.T) {
	body := `{"schema_version":"`+AssessmentSchemaVersion+`","finding_id":"f-1","verdict":"NOT_EXPLOITABLE",` +
		`"summary":"s",` +
		`"claims":[` +
		`{"id":"claim-1","statement":"a","basis":"INTERPRETED","subject":"s1","scope":"sc","decision_relevant":true,"evidence_refs":["e1"]},` +
		`{"id":"claim-2","statement":"b","basis":"INTERPRETED","subject":"s2","scope":"sc","decision_relevant":true,"evidence_refs":["e1","claim-1"]}],` +
		`"evidence":[{"id":"e1","kind":"file","locator":"main.go"}],` +
		`"proposed_action":{"kind":"CLOSE","instruction":"close","rationale":"r","scope":"sc","decisive_claim_ids":["claim-2"],"reconsider_when":["x"]}}`
	_, err := decodeAssessment(body, "f-1")
	if err == nil || !strings.Contains(err.Error(), `claim "claim-2" cites undeclared evidence id "claim-1"`) {
		t.Fatalf("claim id in evidence_refs must be a dangling evidence error: %v", err)
	}

	// The explicit dependency form decodes and preserves both namespaces.
	valid := `{"schema_version":"`+AssessmentSchemaVersion+`","finding_id":"f-1","verdict":"NOT_EXPLOITABLE",` +
		`"summary":"s",` +
		`"claims":[` +
		`{"id":"claim-1","statement":"a","basis":"INTERPRETED","subject":"s1","scope":"sc","decision_relevant":true,"evidence_refs":["e1"]},` +
		`{"id":"claim-2","statement":"b","basis":"INTERPRETED","subject":"s2","scope":"sc","decision_relevant":true,"evidence_refs":["e1"],"depends_on":["claim-1"]}],` +
		`"evidence":[{"id":"e1","kind":"file","locator":"main.go"}],` +
		`"proposed_action":{"kind":"CLOSE","instruction":"close","rationale":"r","scope":"sc","decisive_claim_ids":["claim-2"],"reconsider_when":["x"]}}`
	a, err := decodeAssessment(valid, "f-1")
	if err != nil {
		t.Fatalf("explicit dependency must decode: %v", err)
	}
	if got := a.Claims[1].EvidenceRefs; len(got) != 1 || got[0] != "e1" {
		t.Fatalf("claim-2 refs = %v, want [e1]", got)
	}
	if got := a.Claims[1].DependsOn; len(got) != 1 || got[0] != "claim-1" {
		t.Fatalf("claim-2 dependencies = %v, want [claim-1]", got)
	}
}

// TestDecodeAssessmentProposalEvidenceBinding pins the proposal evidence
// contract at the ingress: evidence_refs must be non-empty and must name
// declared evidence entries carrying the canonical det:<observation-id>
// locator — never a file/path citation, never a sha256-suffixed locator.
// Claim ownership of the cited evidence stays a verifier concern
// ("evidence reference is not owned by claim"), so a det: ref the claim
// does not own still decodes.
func TestDecodeAssessmentProposalEvidenceBinding(t *testing.T) {
	head := `{"schema_version":"`+AssessmentSchemaVersion+`","finding_id":"f-1","verdict":"NOT_EXPLOITABLE","summary":"s",` +
		`"claims":[{"id":"c1","statement":"x","basis":"INTERPRETED","subject":"s","scope":"sc","decision_relevant":true,"evidence_refs":["e1"]}],` +
		`"evidence":[{"id":"e1","kind":"observation","locator":"det:det-0001"},` +
		`{"id":"e2","kind":"file","locator":"go.mod"},` +
		`{"id":"e3","kind":"observation","locator":"det:det-0009@` + `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` + `"},` +
		`{"id":"e5","kind":"observation","locator":"det:det-0005"}],` +
		`"proposed_action":{"kind":"KEEP_OPEN","instruction":"i","rationale":"r","scope":"sc","decisive_claim_ids":["c1"],"reconsider_when":["x"]},` +
		`"falsifier_proposals":[`
	tail := `]}`
	proposal := func(refs string) string {
		return `{"id":"fp-1","claim_id":"c1","condition_id":"C1","kind":"code_absent",` +
			`"subjects":[{"package":"p","symbol":"s"}]` + refs + `}`
	}
	for _, tc := range []struct {
		name      string
		proposals string
		want      string
	}{
		{"missing evidence_refs", proposal(""), `evidence_refs`},
		{"empty evidence_refs", proposal(`,"evidence_refs":[]`), `evidence_refs`},
		{"file evidence ref", proposal(`,"evidence_refs":["e2"]`), `det:`},
		{"mixed evidence refs", proposal(`,"evidence_refs":["e1","e2"]`), `det:`},
		{"sha256-suffixed det ref", proposal(`,"evidence_refs":["e3"]`), `det:`},
		{"undeclared evidence ref", proposal(`,"evidence_refs":["e9"]`), `"e9"`},
		{"canonical det ref", proposal(`,"evidence_refs":["e1"]`), ""},
		{"det ref the claim does not own", proposal(`,"evidence_refs":["e5"]`), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decodeAssessment(head+tc.proposals+tail, "f-1")
			if tc.want == "" {
				if err != nil {
					t.Fatalf("%s must decode: %v", tc.name, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%s error = %v, must name %s", tc.name, err, tc.want)
			}
		})
	}
}

// falsifierAssessment returns a valid assessment with one extra summary
// marker so tests can tell which accepted assessment survived.
func falsifierAssessment(summary string) string {
	return `{"schema_version":"`+AssessmentSchemaVersion+`","finding_id":"scanner-123","verdict":"NOT_EXPLOITABLE","summary":"` + summary + `",` +
		`"claims":[{"id":"c1","statement":"bounded read","basis":"INTERPRETED","subject":"bounded read","scope":"main.go","decision_relevant":true,"evidence_refs":["e1"]}],` +
		`"evidence":[{"id":"e1","kind":"file","locator":"main.go:1-5"}],` +
		`"proposed_action":{"kind":"CLOSE","instruction":"close as not exploitable","rationale":"no reachable vulnerable code was found in the captured build","scope":"captured build","decisive_claim_ids":["c1"],"reconsider_when":["a reachable path is captured"]}}`
}

// falsifierListFilesCall requests one read-only tool round: the feedback
// pass must route it through the run's executor and record the observation.
func falsifierListFilesCall() llm.ChatMessage {
	return llm.ChatMessage{
		Role:      "assistant",
		ToolCalls: []llm.ToolCall{{ID: "c1", Type: "function", Function: llm.FunctionCall{Name: "list_files", Arguments: "{}"}}},
	}
}

// TestAgentFalsifierFeedbackRepairsProposal: a retryable verifier report
// puts its message in the transcript as a user turn; the repaired
// assessment is re-validated by the fact gate and re-verified by the
// callback — the run returns the repaired assessment, and the callback
// saw the updated fact validation.
func TestAgentFalsifierFeedbackRepairsProposal(t *testing.T) {
	in, m := gateRunFixture(t)
	repaired := falsifierAssessment("repaired bindings")
	client := &scriptedChat{responses: []llm.ChatMessage{
		{Role: "assistant", Content: validGateAssessment()},
		{Role: "assistant", Content: repaired},
	}}
	calls := 0
	var sawComplete bool
	callback := func(_ context.Context, a Assessment, fv FactValidation, _ []RecordedObservation, pass int) (string, bool, error) {
		calls++
		if fv.Status == ValidationComplete {
			sawComplete = true
		}
		if pass == 1 {
			if a.Summary == "repaired bindings" {
				t.Fatalf("pass 1 must see the initial assessment, got %q", a.Summary)
			}
			return `{"pass":1,"items":[{"proposal_id":"fp-1","status":"UNKNOWN","reason":"proposal subject set mismatch"}]}`, true, nil
		}
		if a.Summary != "repaired bindings" {
			t.Fatalf("pass 2 must see the repaired assessment, got %q", a.Summary)
		}
		return "", false, nil
	}
	run, fv, err := (AgentRunner{Client: client, Limits: AgentLimits{MaxSteps: 4}}).
		RunWithFactGateAndFalsifierFeedback(context.Background(), in, m, FactGate{}, 2, callback, 2)
	if err != nil {
		t.Fatalf("RunWithFactGateAndFalsifierFeedback: %v", err)
	}
	if calls != 2 || client.calls != 2 {
		t.Fatalf("verifier calls=%d chat calls=%d, want 2 and 2", calls, client.calls)
	}
	if !sawComplete || fv.Status != ValidationComplete {
		t.Fatalf("final validation = %s, callback saw complete=%v", fv.Status, sawComplete)
	}
	if run.Assessment.Summary != "repaired bindings" {
		t.Fatalf("final assessment = %q, want the repaired one", run.Assessment.Summary)
	}
	var feedbackSeen bool
	for _, msg := range run.RawMessages {
		if msg.Role == "user" && strings.Contains(msg.Content, `"proposal_id":"fp-1"`) && strings.Contains(msg.Content, "proposal subject set mismatch") {
			feedbackSeen = true
		}
	}
	if !feedbackSeen {
		t.Fatal("verifier reason never reached the transcript")
	}
}

// TestAgentFalsifierFeedbackBounded: a callback that keeps requesting a
// repair gets exactly MaxFalsifierFeedbackPasses turns — the verifier
// still runs once more on the last accepted assessment, but a third
// repair message is never sent regardless of the configured budget.
func TestAgentFalsifierFeedbackBounded(t *testing.T) {
	in, m := gateRunFixture(t)
	client := &scriptedChat{responses: []llm.ChatMessage{
		{Role: "assistant", Content: validGateAssessment()},
		{Role: "assistant", Content: validGateAssessment()},
		{Role: "assistant", Content: validGateAssessment()},
		{Role: "assistant", Content: validGateAssessment()},
	}}
	calls := 0
	callback := func(context.Context, Assessment, FactValidation, []RecordedObservation, int) (string, bool, error) {
		calls++
		return `{"items":[{"proposal_id":"fp-1","status":"UNKNOWN","reason":"subject set incomplete"}]}`, true, nil
	}
	run, _, err := (AgentRunner{Client: client, Limits: AgentLimits{MaxSteps: 8}}).
		RunWithFactGateAndFalsifierFeedback(context.Background(), in, m, FactGate{}, 2, callback, 9)
	if err != nil {
		t.Fatalf("an unrepairable proposal is a limitation, not a technical error: %v", err)
	}
	if calls != MaxFalsifierFeedbackPasses+1 {
		t.Fatalf("verifier invocations = %d, want %d repair checks + terminal", calls, MaxFalsifierFeedbackPasses)
	}
	if client.calls != 1+MaxFalsifierFeedbackPasses {
		t.Fatalf("chat calls = %d, want initial + %d repair turns", client.calls, MaxFalsifierFeedbackPasses)
	}
	if run.ErrorClass != "" {
		t.Fatalf("budget exhaustion must not be a failure class: %+v", run)
	}
}

// TestAgentFalsifierFeedbackTerminalVerify: after the last repair turn the
// callback still runs once more with pass > MaxFalsifierFeedbackPasses —
// the stored report always describes the last accepted assessment, never
// the superseded one.
func TestAgentFalsifierFeedbackTerminalVerify(t *testing.T) {
	in, m := gateRunFixture(t)
	repaired := falsifierAssessment("second repair")
	client := &scriptedChat{responses: []llm.ChatMessage{
		{Role: "assistant", Content: validGateAssessment()},
		{Role: "assistant", Content: validGateAssessment()},
		{Role: "assistant", Content: repaired},
	}}
	var lastAssessment string
	var calls int
	callback := func(_ context.Context, a Assessment, _ FactValidation, _ []RecordedObservation, pass int) (string, bool, error) {
		calls++
		lastAssessment = a.Summary
		if pass <= MaxFalsifierFeedbackPasses {
			return `{"items":[{"proposal_id":"fp-1","status":"UNKNOWN","reason":"subject set incomplete"}]}`, true, nil
		}
		return "", false, nil
	}
	run, _, err := (AgentRunner{Client: client, Limits: AgentLimits{MaxSteps: 8}}).
		RunWithFactGateAndFalsifierFeedback(context.Background(), in, m, FactGate{}, 2, callback, 2)
	if err != nil {
		t.Fatalf("RunWithFactGateAndFalsifierFeedback: %v", err)
	}
	if calls != MaxFalsifierFeedbackPasses+1 {
		t.Fatalf("verifier invocations = %d, want %d repair checks + terminal", calls, MaxFalsifierFeedbackPasses)
	}
	if lastAssessment != "second repair" {
		t.Fatalf("terminal verify saw %q, want the last accepted assessment", lastAssessment)
	}
	if run.Assessment.Summary != "second repair" {
		t.Fatalf("final assessment = %q", run.Assessment.Summary)
	}
}

// TestAgentFalsifierFeedbackCleanReportNoRound: retry=false ends the loop
// without another model round — a clean report or an unrepairable one both
// terminate after exactly one verifier call.
func TestAgentFalsifierFeedbackCleanReportNoRound(t *testing.T) {
	in, m := gateRunFixture(t)
	client := &scriptedChat{responses: []llm.ChatMessage{
		{Role: "assistant", Content: validGateAssessment()},
	}}
	calls := 0
	callback := func(context.Context, Assessment, FactValidation, []RecordedObservation, int) (string, bool, error) {
		calls++
		return "", false, nil
	}
	if _, _, err := (AgentRunner{Client: client, Limits: AgentLimits{MaxSteps: 4}}).
		RunWithFactGateAndFalsifierFeedback(context.Background(), in, m, FactGate{}, 2, callback, 2); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || client.calls != 1 {
		t.Fatalf("verifier calls=%d chat calls=%d, want 1 and 1", calls, client.calls)
	}
}

// TestAgentFalsifierFeedbackMalformedReplyIsError: inside a falsifier
// repair turn a response that still does not decode after its single shape
// repair is a technical error with the transcript preserved — the loop
// must not spin on it.
func TestAgentFalsifierFeedbackMalformedReplyIsError(t *testing.T) {
	in, m := gateRunFixture(t)
	client := &scriptedChat{responses: []llm.ChatMessage{
		{Role: "assistant", Content: validGateAssessment()},
		{Role: "assistant", Content: "not json"},
		{Role: "assistant", Content: "still not json"},
	}}
	callback := func(context.Context, Assessment, FactValidation, []RecordedObservation, int) (string, bool, error) {
		return `{"items":[{"proposal_id":"fp-1","status":"UNKNOWN","reason":"claim does not exist"}]}`, true, nil
	}
	run, _, err := (AgentRunner{Client: client, Limits: AgentLimits{MaxSteps: 8}}).
		RunWithFactGateAndFalsifierFeedback(context.Background(), in, m, FactGate{}, 2, callback, 2)
	if err == nil {
		t.Fatal("undecodable falsifier-pass reply must be a technical error")
	}
	if run.ErrorClass != ErrClassStepBudget || len(run.RawMessages) == 0 {
		t.Fatalf("partial run must keep class and transcript: %+v", run)
	}
}

// TestAgentFalsifierFeedbackErrorIsTechnical: a callback error terminates
// the run as an internal technical failure — never a silent success.
func TestAgentFalsifierFeedbackErrorIsTechnical(t *testing.T) {
	in, m := gateRunFixture(t)
	client := &scriptedChat{responses: []llm.ChatMessage{
		{Role: "assistant", Content: validGateAssessment()},
	}}
	callback := func(context.Context, Assessment, FactValidation, []RecordedObservation, int) (string, bool, error) {
		return "", false, errors.New("verifier exploded")
	}
	run, _, err := (AgentRunner{Client: client, Limits: AgentLimits{MaxSteps: 4}}).
		RunWithFactGateAndFalsifierFeedback(context.Background(), in, m, FactGate{}, 2, callback, 2)
	if err == nil || run.ErrorClass != ErrClassInternal {
		t.Fatalf("callback error = %v class %q, want internal failure", err, run.ErrorClass)
	}
}

// TestAgentFalsifierFeedbackToolRounds: a repair turn may spend bounded
// tool rounds before answering; the recorded observations reach the next
// verifier call and the run's archive.
func TestAgentFalsifierFeedbackToolRounds(t *testing.T) {
	in, m := gateRunFixture(t)
	tools := &ReadOnlyTools{Snapshot: m, Finding: in, ObservationStore: NewRunObservationStore("run-1", 1)}
	client := &scriptedChat{responses: []llm.ChatMessage{
		{Role: "assistant", Content: validGateAssessment()},
		falsifierListFilesCall(),
		{Role: "assistant", Content: validGateAssessment()},
	}}
	var seen []RecordedObservation
	callback := func(_ context.Context, _ Assessment, _ FactValidation, obs []RecordedObservation, pass int) (string, bool, error) {
		seen = obs
		if pass == 1 {
			return `{"items":[{"proposal_id":"fp-1","status":"UNKNOWN","reason":"approved deterministic absence observation missing"}]}`, true, nil
		}
		return "", false, nil
	}
	run, _, err := (AgentRunner{Client: client, Tools: tools, Limits: AgentLimits{MaxSteps: 8, MaxToolCalls: 8}}).
		RunWithFactGateAndFalsifierFeedback(context.Background(), in, m, FactGate{}, 2, callback, 2)
	if err != nil {
		t.Fatalf("RunWithFactGateAndFalsifierFeedback: %v", err)
	}
	if len(run.Observations) != 1 || run.ToolCalls != 1 {
		t.Fatalf("observations=%v tool calls=%d, want the recorded list_files call", run.Observations, run.ToolCalls)
	}
	if len(seen) != 1 || seen[0].ID == "" {
		t.Fatalf("verifier must see the repair turn's observation, got %+v", seen)
	}
}

// TestAgentFalsifierFeedbackAfterFactBudget: the fact loop keeps its own
// bound — an assessment that never repairs leaves it after two passes —
// and the falsifier loop then adds at most its own two passes on top.
func TestAgentFalsifierFeedbackAfterFactBudget(t *testing.T) {
	in, m := gateRunFixture(t)
	bad := gateAssessmentJSON(
		`[{"id":"c1","statement":"bounded read","basis":"INTERPRETED","subject":"bounded read","scope":"main.go","decision_relevant":true,"evidence_refs":["e1"]}]`,
		`[{"id":"e1","kind":"file","locator":"ghost.go"}]`)
	client := &scriptedChat{responses: []llm.ChatMessage{
		{Role: "assistant", Content: bad},
		{Role: "assistant", Content: bad},
		{Role: "assistant", Content: bad},
		{Role: "assistant", Content: bad},
		{Role: "assistant", Content: bad},
	}}
	factMessages, falsifierCalls := 0, 0
	callback := func(_ context.Context, _ Assessment, fv FactValidation, _ []RecordedObservation, _ int) (string, bool, error) {
		falsifierCalls++
		if fv.Status != ValidationFailed {
			t.Fatalf("verifier must see the spent fact report, got %s", fv.Status)
		}
		return `{"items":[{"proposal_id":"fp-1","status":"UNKNOWN","reason":"subject set incomplete"}]}`, true, nil
	}
	run, fv, err := (AgentRunner{Client: client, Limits: AgentLimits{MaxSteps: 12}}).
		RunWithFactGateAndFalsifierFeedback(context.Background(), in, m, FactGate{}, 2, callback, 2)
	if err != nil {
		t.Fatalf("unrepaired inputs are a limitation, not a technical error: %v", err)
	}
	for _, msg := range run.RawMessages {
		if msg.Role == "user" && strings.Contains(msg.Content, `"current_status"`) {
			factMessages++
		}
	}
	if factMessages != 2 || falsifierCalls != MaxFalsifierFeedbackPasses+1 || client.calls != 5 {
		t.Fatalf("fact messages=%d verifier calls=%d chat calls=%d, want 2/%d/5",
			factMessages, falsifierCalls, client.calls, MaxFalsifierFeedbackPasses+1)
	}
	if fv.Status != ValidationFailed {
		t.Fatalf("final validation = %s, want FAILED", fv.Status)
	}
	if len(run.FactPasses) != 3 {
		t.Fatalf("recorded fact passes = %+v, want initial+2 repairs", run.FactPasses)
	}
}

// TestAgentNilFalsifierFeedbackIdentical: a nil callback keeps the legacy
// semantics — the compatibility surface is RunWithFactGate's behaviour.
func TestAgentNilFalsifierFeedbackIdentical(t *testing.T) {
	in, m := gateRunFixture(t)
	client := &scriptedChat{responses: []llm.ChatMessage{
		{Role: "assistant", Content: validGateAssessment()},
	}}
	run, fv, err := (AgentRunner{Client: client, Limits: AgentLimits{MaxSteps: 2}}).
		RunWithFactGateAndFalsifierFeedback(context.Background(), in, m, FactGate{}, 2, nil, 2)
	if err != nil {
		t.Fatal(err)
	}
	if fv.Status != ValidationComplete || len(run.FactPasses) != 1 || client.calls != 1 {
		t.Fatalf("nil callback changed the run: fv=%s passes=%+v calls=%d", fv.Status, run.FactPasses, client.calls)
	}
}

// defsRecordingChat wraps scriptedChat and captures the tool definition
// list of every request, so a test can prove the finalization call went
// out with no tools.
type defsRecordingChat struct {
	scriptedChat
	defsSeen [][]llm.ToolDefinition
}

func (d *defsRecordingChat) Chat(ctx context.Context, role llm.ModelRole, system string, messages []llm.ChatMessage, defs []llm.ToolDefinition) (llm.ChatMessage, string, error) {
	d.defsSeen = append(d.defsSeen, append([]llm.ToolDefinition(nil), defs...))
	return d.scriptedChat.Chat(ctx, role, system, messages, defs)
}

// assessmentToolCallMsg is an assistant message whose tool call names the
// assessment schema — the protocol violation of a model that treats
// assessment.v2 as a function.
func assessmentToolCallMsg(id string) llm.ChatMessage {
	return llm.ChatMessage{
		Role:      "assistant",
		ToolCalls: []llm.ToolCall{{ID: id, Type: "function", Function: llm.FunctionCall{Name: AssessmentSchemaVersion, Arguments: "{}"}}},
	}
}

// mixedToolCallMsg requests one real tool and one assessment.v2 call in the
// same assistant message.
func mixedToolCallMsg() llm.ChatMessage {
	return llm.ChatMessage{
		Role: "assistant",
		ToolCalls: []llm.ToolCall{
			{ID: "c1", Type: "function", Function: llm.FunctionCall{Name: "noop", Arguments: "{}"}},
			{ID: "c2", Type: "function", Function: llm.FunctionCall{Name: AssessmentSchemaVersion, Arguments: "{}"}},
		},
	}
}

// countingTools records every dispatched call while answering like
// staticTools; a protocol-violation call must never reach it.
type countingTools struct{ calls int }

func (c *countingTools) Definitions() []llm.ToolDefinition {
	return []llm.ToolDefinition{{Type: "function", Function: llm.FunctionSpec{Name: "noop"}}}
}

func (c *countingTools) Call(_ context.Context, _ string, _ json.RawMessage) ToolObservation {
	c.calls++
	return ToolObservation{ID: "o1", Tool: "noop", Status: ToolStatusOK}
}

func countAssessmentFeedback(messages []llm.ChatMessage) int {
	n := 0
	for _, m := range messages {
		if m.Role == "tool" && m.Content == assessmentToolFeedback {
			n++
		}
	}
	return n
}

// TestDecodeAssessmentSalvage: the single decode point accepts the fenced,
// prose-wrapped and code-fence-quoting shapes a real model emits, and it
// still walks past prose fragments that balance earlier than the
// assessment object itself.
func TestDecodeAssessmentSalvage(t *testing.T) {
	body := validAssessment()
	fencedInsideString := `{"schema_version":"`+AssessmentSchemaVersion+`","finding_id":"f","verdict":"INCONCLUSIVE","summary":"see ` + "```go\\nfunc f() {}\\n```" + ` in main.go",` +
		`"claims":[{"id":"c1","statement":"source read","basis":"INTERPRETED","subject":"main.go","scope":"captured snapshot","decision_relevant":true,"evidence_refs":["e1"]}],` +
		`"evidence":[{"id":"e1","kind":"file","locator":"main.go"}],` +
		`"proposed_action":{"kind":"KEEP_OPEN","instruction":"i","rationale":"r","scope":"sc","decisive_claim_ids":["c1"],"reconsider_when":["x"]}}`
	for name, content := range map[string]string{
		"raw":                   body,
		"json fence":            "```json\n" + body + "\n```",
		"untyped fence":         "```\n" + body + "\n```",
		"prose wrap":            "Here is the assessment.\n" + body + "\nLet me know if you need more.",
		"bracket prose":         "see [the call graph] for context\n" + body,
		"braced prose":          "note {the interceptor} is absent\n" + body,
		"foreign json":          `{"schema_version":"finding.v1","finding_id":"f"}` + "\n" + body,
		"fences inside strings": fencedInsideString,
	} {
		if _, err := decodeAssessment(content, "f"); err != nil {
			t.Fatalf("%s: decodeAssessment rejected a valid wrapped assessment: %v", name, err)
		}
	}
	for name, content := range map[string]string{
		"truncated":        body[:len(body)-len(body)/2],
		"truncated fenced": "```json\n" + body[:len(body)-len(body)/2],
		"prefix then truncation": `{"note":"x"} ` +
			`{"schema_version":"`+AssessmentSchemaVersion+`","finding_id":"f","verdict":"INCONCLUSIVE","summary":"un`,
		"no object": "the component looks safe to me",
	} {
		if _, err := decodeAssessment(content, "f"); err == nil {
			t.Fatalf("%s: truncated or missing assessment must not decode", name)
		}
	}
}

// TestDecodeAssessmentWrongSchemaNotShadowed: a malformed assessment.v2 is
// never stepped over for a later clean one — the first object that claims
// the schema is the contract the repair turn must fix.
func TestDecodeAssessmentWrongSchemaNotShadowed(t *testing.T) {
	good := validAssessment()
	bad := strings.Replace(good, `"finding_id":"f"`, `"finding_id":"other"`, 1)
	if _, err := decodeAssessment(bad+"\n"+good, "f"); err == nil || !strings.Contains(err.Error(), "finding_id") {
		t.Fatalf("first assessment.v2 candidate wins even when invalid: %v", err)
	}
}

// TestAgentFinalizationOnBudgetExhaustion: when the step budget runs out on
// tool calls the runner issues exactly one extra request — with an empty
// tool list — and accepts the assessment it returns instead of failing.
func TestAgentFinalizationOnBudgetExhaustion(t *testing.T) {
	client := &defsRecordingChat{scriptedChat: scriptedChat{responses: []llm.ChatMessage{
		toolCallMsg(), toolCallMsg(), toolCallMsg(), toolCallMsg(), toolCallMsg(),
		{Role: "assistant", Content: validAssessment()},
	}}}
	runner := AgentRunner{Client: client, Tools: staticTools{}, Limits: AgentLimits{MaxSteps: 5}, Sleep: noSleep}
	run, err := runner.Run(context.Background(), FindingInput{Finding: Finding{FindingID: "f"}}, SnapshotManifest{FindingID: "f"})
	if err != nil {
		t.Fatalf("finalization answer must rescue the run: %v", err)
	}
	if run.Assessment.Verdict != VerdictInconclusive {
		t.Fatalf("unexpected run: %+v", run)
	}
	if client.calls != 6 {
		t.Fatalf("expected 6 chat calls (5 steps + 1 finalization), got %d", client.calls)
	}
	if len(client.defsSeen) != 6 {
		t.Fatalf("recorded %d requests, want 6", len(client.defsSeen))
	}
	if len(client.defsSeen[5]) != 0 {
		t.Fatalf("finalization request must carry no tool definitions, got %v", client.defsSeen[5])
	}
	if n := countNudges(run.RawMessages); n != 1 {
		t.Fatalf("expected exactly one nudge in the transcript, got %d", n)
	}
	last := run.RawMessages[len(run.RawMessages)-1]
	if last.Role != "assistant" || last.Content != validAssessment() {
		t.Fatalf("finalization answer missing from transcript: %+v", last)
	}
}

// TestAgentFinalizationInvalidKeepsStepBudget: a finalization reply that is
// still not an assessment — or asks for tools — cannot rescue the run; the
// step-budget failure stands with the complete partial transcript.
func TestAgentFinalizationInvalidKeepsStepBudget(t *testing.T) {
	for name, final := range map[string]llm.ChatMessage{
		"noise":      {Role: "assistant", Content: "still not an assessment"},
		"tool calls": toolCallMsg(),
	} {
		client := &defsRecordingChat{scriptedChat: scriptedChat{responses: []llm.ChatMessage{
			toolCallMsg(), toolCallMsg(), toolCallMsg(), toolCallMsg(), toolCallMsg(), final,
		}}}
		runner := AgentRunner{Client: client, Tools: staticTools{}, Limits: AgentLimits{MaxSteps: 5}, Sleep: noSleep}
		run, err := runner.Run(context.Background(), FindingInput{Finding: Finding{FindingID: "f"}}, SnapshotManifest{FindingID: "f"})
		if err == nil || !strings.Contains(err.Error(), "step budget exceeded") {
			t.Fatalf("%s: expected step budget failure, got %v", name, err)
		}
		if run.ErrorClass != ErrClassStepBudget {
			t.Fatalf("%s: error class %q, want %q", name, run.ErrorClass, ErrClassStepBudget)
		}
		if client.calls != 6 {
			t.Fatalf("%s: finalization must be exactly one call, got %d", name, client.calls)
		}
		if len(run.RawMessages) == 0 {
			t.Fatalf("%s: partial transcript lost", name)
		}
	}
}

// TestAgentAssessmentToolProtocolFeedback: a tool call that names
// assessment.v2 is answered in-band with protocol feedback — never
// dispatched, never charged to the tool budget — and the run continues on
// the remaining normal steps.
func TestAgentAssessmentToolProtocolFeedback(t *testing.T) {
	tools := &countingTools{}
	client := &scriptedChat{responses: []llm.ChatMessage{
		assessmentToolCallMsg("c1"),
		{Role: "assistant", Content: validAssessment()},
	}}
	runner := AgentRunner{Client: client, Tools: tools, Limits: AgentLimits{MaxSteps: 3}, Sleep: noSleep}
	run, err := runner.Run(context.Background(), FindingInput{Finding: Finding{FindingID: "f"}}, SnapshotManifest{FindingID: "f"})
	if err != nil {
		t.Fatalf("protocol feedback must let the run finish: %v", err)
	}
	if tools.calls != 0 || run.ToolCalls != 0 {
		t.Fatalf("assessment.v2 must never dispatch or spend budget: calls=%d toolCalls=%d", tools.calls, run.ToolCalls)
	}
	if n := countAssessmentFeedback(run.RawMessages); n != 1 {
		t.Fatalf("expected exactly one protocol feedback entry, got %d", n)
	}
	for _, m := range run.RawMessages {
		if strings.Contains(m.Content, `"DENIED"`) || strings.Contains(m.Content, "unknown tool") {
			t.Fatalf("protocol violation must not produce a DENIED observation: %+v", m)
		}
	}
}

// TestAgentAssessmentToolRepeatIsError: after the protocol feedback a model
// that calls assessment.v2 again is a contract violation — the run ends as
// a technical error with the transcript preserved.
func TestAgentAssessmentToolRepeatIsError(t *testing.T) {
	tools := &countingTools{}
	client := &scriptedChat{responses: []llm.ChatMessage{
		assessmentToolCallMsg("c1"),
		assessmentToolCallMsg("c2"),
	}}
	runner := AgentRunner{Client: client, Tools: tools, Limits: AgentLimits{MaxSteps: 4}, Sleep: noSleep}
	run, err := runner.Run(context.Background(), FindingInput{Finding: Finding{FindingID: "f"}}, SnapshotManifest{FindingID: "f"})
	if err == nil || !strings.Contains(err.Error(), "repeated "+AssessmentSchemaVersion) {
		t.Fatalf("expected protocol error, got %v", err)
	}
	if run.ErrorClass != ErrClassProtocol {
		t.Fatalf("error class %q, want %q", run.ErrorClass, ErrClassProtocol)
	}
	if tools.calls != 0 {
		t.Fatalf("assessment.v2 must never dispatch: %d calls", tools.calls)
	}
	if n := countAssessmentFeedback(run.RawMessages); n != 1 {
		t.Fatalf("feedback is sent once before the run fails, got %d", n)
	}
	if len(run.RawMessages) == 0 {
		t.Fatal("partial transcript lost")
	}
}

// TestAgentAssessmentToolMixedCalls: a message mixing a real tool call with
// an assessment.v2 call dispatches only the real one; the violation is
// answered in-band and charged nothing.
func TestAgentAssessmentToolMixedCalls(t *testing.T) {
	tools := &countingTools{}
	client := &scriptedChat{responses: []llm.ChatMessage{
		mixedToolCallMsg(),
		{Role: "assistant", Content: validAssessment()},
	}}
	runner := AgentRunner{Client: client, Tools: tools, Limits: AgentLimits{MaxSteps: 3}, Sleep: noSleep}
	run, err := runner.Run(context.Background(), FindingInput{Finding: Finding{FindingID: "f"}}, SnapshotManifest{FindingID: "f"})
	if err != nil {
		t.Fatalf("mixed call must not fail the run: %v", err)
	}
	if tools.calls != 1 || run.ToolCalls != 1 {
		t.Fatalf("only the real tool may dispatch: calls=%d toolCalls=%d", tools.calls, run.ToolCalls)
	}
	if n := countAssessmentFeedback(run.RawMessages); n != 1 {
		t.Fatalf("expected protocol feedback for the assessment.v2 call, got %d", n)
	}
}

// TestAgentAssessmentToolAtBudgetThenFinalization: a violation on the last
// step leaves no normal step; the single no-tools finalization round is
// where the corrected answer must land.
func TestAgentAssessmentToolAtBudgetThenFinalization(t *testing.T) {
	client := &defsRecordingChat{scriptedChat: scriptedChat{responses: []llm.ChatMessage{
		assessmentToolCallMsg("c1"),
		{Role: "assistant", Content: validAssessment()},
	}}}
	runner := AgentRunner{Client: client, Tools: &countingTools{}, Limits: AgentLimits{MaxSteps: 1}, Sleep: noSleep}
	run, err := runner.Run(context.Background(), FindingInput{Finding: Finding{FindingID: "f"}}, SnapshotManifest{FindingID: "f"})
	if err != nil {
		t.Fatalf("finalization must accept the corrected answer: %v", err)
	}
	if client.calls != 2 {
		t.Fatalf("expected one step plus one finalization call, got %d", client.calls)
	}
	if len(client.defsSeen[1]) != 0 {
		t.Fatalf("finalization request must carry no tool definitions, got %v", client.defsSeen[1])
	}
	if n := countAssessmentFeedback(run.RawMessages); n != 1 {
		t.Fatalf("expected the protocol feedback entry in the transcript, got %d", n)
	}
}

// TestAgentProtocolDuplicateInMessage: two assessment.v2 calls in one
// assistant message are one feedback plus one repeat — the first is
// answered in-band, the second ends the run as a contract violation.
// Neither reaches the executor and neither spends tool budget.
func TestAgentProtocolDuplicateInMessage(t *testing.T) {
	tools := &countingTools{}
	dup := llm.ChatMessage{
		Role: "assistant",
		ToolCalls: []llm.ToolCall{
			{ID: "c1", Type: "function", Function: llm.FunctionCall{Name: AssessmentSchemaVersion, Arguments: "{}"}},
			{ID: "c2", Type: "function", Function: llm.FunctionCall{Name: AssessmentSchemaVersion, Arguments: "{}"}},
		},
	}
	client := &scriptedChat{responses: []llm.ChatMessage{
		dup,
		{Role: "assistant", Content: validAssessment()},
	}}
	runner := AgentRunner{Client: client, Tools: tools, Limits: AgentLimits{MaxSteps: 4}, Sleep: noSleep}
	run, err := runner.Run(context.Background(), FindingInput{Finding: Finding{FindingID: "f"}}, SnapshotManifest{FindingID: "f"})
	if err == nil || !strings.Contains(err.Error(), "repeated "+AssessmentSchemaVersion) {
		t.Fatalf("expected protocol error, got %v", err)
	}
	if run.ErrorClass != ErrClassProtocol {
		t.Fatalf("error class %q, want %q", run.ErrorClass, ErrClassProtocol)
	}
	if tools.calls != 0 || run.ToolCalls != 0 {
		t.Fatalf("assessment.v2 must never dispatch or spend budget: calls=%d toolCalls=%d", tools.calls, run.ToolCalls)
	}
	if n := countAssessmentFeedback(run.RawMessages); n != 1 {
		t.Fatalf("protocol feedback is recorded exactly once per run, got %d", n)
	}
	if len(run.RawMessages) == 0 {
		t.Fatal("partial transcript lost")
	}
}

// TestTotalStepBudgetCoversFeedbackTurns pins the P2-4 accounting: the step
// counter is one total across the initial loop, finalization, fact-repair
// and falsifier-repair turns — not just the main loop. A run that spends
// the full repair workload records every spent chat in Steps and stays
// inside the worst-case budget the constants imply.
func TestTotalStepBudgetCoversFeedbackTurns(t *testing.T) {
	in, m := gateRunFixture(t)
	bad := gateAssessmentJSON(
		`[{"id":"c1","statement":"x","basis":"INTERPRETED","subject":"s","scope":"sc","decision_relevant":true,"evidence_refs":["e1"]}]`,
		`[{"id":"e1","kind":"file","locator":"ghost.go"}]`)
	client := &scriptedChat{responses: []llm.ChatMessage{{Role: "assistant", Content: bad}}}
	var falsifierCalls int
	feedback := func(_ context.Context, a Assessment, _ FactValidation, _ []RecordedObservation, pass int) (string, bool, error) {
		falsifierCalls++
		if pass > MaxFalsifierFeedbackPasses {
			return "", false, nil
		}
		return "repair the proposal binding", true, nil
	}
	run, _, err := (AgentRunner{Client: client, Limits: AgentLimits{MaxSteps: 2}, Tools: staticTools{}}).
		RunWithFactGateAndFalsifierFeedback(context.Background(), in, m, FactGate{}, 2, feedback, 2)
	if err != nil {
		t.Fatalf("bounded repair is a limitation, not a technical error: %v", err)
	}
	// Initial assessment (1 chat) + 2 fact-repair turns (1 chat each:
	// scripted response replays the decodable assessment) + 2 falsifier
	// repair turns (1 chat each) — every chat counted once, in one total.
	if run.Steps != 5 {
		t.Fatalf("Steps = %d, want 5 (1 initial + 2 fact + 2 falsifier repair chats)", run.Steps)
	}
	if client.calls != 5 {
		t.Fatalf("model exchanges = %d, want exactly 5 — the provider saw one call per issued step", client.calls)
	}
	if falsifierCalls < 3 {
		t.Fatalf("falsifier callback calls = %d, want initial + 2 repair + terminal", falsifierCalls)
	}
	// The cap uses the already-clamped configured passes: configured 2+2
	// reaches both Max values, so the worst-case total equals the
	// Max-based formula.
	worstCase := totalStepBudget(2, MaxFactFeedbackPasses, MaxFalsifierFeedbackPasses)
	if run.Steps > worstCase {
		t.Fatalf("Steps %d exceeded worst-case total budget %d", run.Steps, worstCase)
	}
}

// TestTotalStepBudgetOverflowFailsClosed pins the fail-closed half: a run
// that burns the entire total budget without accepting an assessment ends
// as step_budget — the counter can never overrun silently.
func TestTotalStepBudgetOverflowFailsClosed(t *testing.T) {
	in, m := gateRunFixture(t)
	// Every chat burns a tool round and never yields an assessment: the
	// initial loop, finalization and any feedback turn all hit their local
	// bounds, and the run's terminal class is the budget, never a hang or
	// an over-budget transcript.
	client := &alwaysToolChat{}
	run, _, err := (AgentRunner{Client: client, Limits: AgentLimits{MaxSteps: 4, MaxToolCalls: 100}, Tools: staticTools{}}).
		RunWithFactGate(context.Background(), in, m, FactGate{}, 2)
	if err == nil {
		t.Fatal("a run that never produces an assessment must fail")
	}
	if run.ErrorClass != ErrClassStepBudget && run.ErrorClass != ErrClassToolBudget {
		t.Fatalf("terminal class = %q, want step_budget or tool_budget", run.ErrorClass)
	}
	worstCase := totalStepBudget(4, MaxFactFeedbackPasses, MaxFalsifierFeedbackPasses)
	if run.Steps > worstCase {
		t.Fatalf("Steps %d exceeded worst-case total budget %d", run.Steps, worstCase)
	}
	// Reserve-before-call: the provider can never see one more exchange
	// than the recorded Steps (each call was reserved first) and never
	// more than the total budget — the off-by-one the earlier
	// call-then-count order allowed is structurally impossible now.
	if client.calls != run.Steps {
		t.Fatalf("model exchanges %d != recorded steps %d — every issued call must be counted", client.calls, run.Steps)
	}
}

// TestTotalStepBudgetFalsifierOverflow covers the falsifier-feedback
// branch specifically: once the accepted assessment exists, a falsifier
// callback that keeps answering retry=true must still hit the single
// total step counter — the repair turn's own chats count against it and
// an exhausted total fails closed with step_budget, never a hang.
func TestTotalStepBudgetFalsifierOverflow(t *testing.T) {
	in, m := gateRunFixture(t)
	// The initial response accepts a valid assessment; every repair turn
	// chat burns tool calls so each falsifier pass consumes tool rounds
	// until the total budget trips mid-turn.
	always := &alwaysToolChat{}
	prefixed := &sequenceChat{first: []llm.ChatMessage{
		{Role: "assistant", Content: validGateAssessment()},
	}, rest: always}
	callbacks := 0
	feedback := func(_ context.Context, _ Assessment, _ FactValidation, _ []RecordedObservation, pass int) (string, bool, error) {
		callbacks++
		return "repair the falsifier binding", true, nil
	}
	run, _, err := (AgentRunner{Client: prefixed, Limits: AgentLimits{MaxSteps: 4, MaxToolCalls: 200}, Tools: staticTools{}}).
		RunWithFactGateAndFalsifierFeedback(context.Background(), in, m, FactGate{}, 0, feedback, MaxFalsifierFeedbackPasses)
	if err == nil {
		t.Fatal("a run whose falsifier repair never converges must fail")
	}
	// The repair turn ran: it burned its own tool-round chats inside the
	// turn bound (falsifier feedback may not re-enter the callback until a
	// valid assessment lands), then the next callback either produced
	// another retry or the turn hit the turn bound — either way the total
	// counter, not a wall, is what ended it.
	if callbacks < 1 {
		t.Fatalf("falsifier feedback never ran")
	}
	if run.ErrorClass != ErrClassStepBudget {
		t.Fatalf("terminal class = %q, want step_budget (unconverged repair is a budget failure)", run.ErrorClass)
	}
	// Configured 0 fact passes clamp to MaxFactFeedbackPasses, so the
	// worst-case formula counts both turn kinds.
	worstCase := totalStepBudget(4, MaxFactFeedbackPasses, MaxFalsifierFeedbackPasses)
	if run.Steps > worstCase {
		t.Fatalf("Steps %d exceeded worst-case total budget %d", run.Steps, worstCase)
	}
	if prefixed.calls() != run.Steps {
		t.Fatalf("model exchanges %d != recorded steps %d — every issued call must be counted", prefixed.calls(), run.Steps)
	}
}

// sequenceChat replays first, then defers to rest for every later call.
type sequenceChat struct {
	first []llm.ChatMessage
	rest  ChatClient
	n     int
}

func (s *sequenceChat) Chat(ctx context.Context, role llm.ModelRole, sys string, msgs []llm.ChatMessage, defs []llm.ToolDefinition) (llm.ChatMessage, string, error) {
	s.n++
	if s.n <= len(s.first) {
		return s.first[s.n-1], "stop", nil
	}
	return s.rest.Chat(ctx, role, sys, msgs, defs)
}

func (s *sequenceChat) calls() int { return s.n }

// TestTotalStepBudgetFormula pins the accounting contract between the
// configured pass counts, the clamps and totalStepBudget: the total is
// the initial loop plus one finalization round plus every clamped repair
// turn's exchange ceiling. It also documents the reachability boundary:
// feedback turns only run on an accepted assessment and finalization
// only on a rejected one, so the formula is a conservative upper bound —
// the reserve-before-call counter is what makes it airtight regardless.
func TestTotalStepBudgetFormula(t *testing.T) {
	full := totalStepBudget(8, MaxFactFeedbackPasses, MaxFalsifierFeedbackPasses)
	want := 8 + 1 + (MaxFactFeedbackPasses+MaxFalsifierFeedbackPasses)*(factFeedbackMaxToolRounds+2)
	if full != want {
		t.Fatalf("totalStepBudget = %d, want %d", full, want)
	}
	// Clamped configured counts feed the same formula: a caller asking
	// for one fact pass + one falsifier pass gets 1+1+12 over the initial
	// loop — never the Max-based total.
	if got := totalStepBudget(8, 1, 1); got != 8+1+2*(factFeedbackMaxToolRounds+2) {
		t.Fatalf("configured budget = %d, want %d", got, 8+1+2*(factFeedbackMaxToolRounds+2))
	}
}

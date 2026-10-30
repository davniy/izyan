package llm

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

// TestLLMReviewerConditionActions pins the reviewer condition-action
// contract: an explicit action survives parsing with its target and
// severity but stays a nomination, a missing or unknown action never turns
// into a promote, the prompt states that actions do not move conditions,
// and the payload separates model proposals from the authoritative
// mandatory/supporting sets plus pending reviews.
func TestLLMReviewerConditionActions(t *testing.T) {
	var system string
	reply := `{"result":"REVISE","findings":[
		{"target_type":"condition","target_id":"C-PLATFORM","action":"demote","severity":"high",
		 "problem":"legacy TLS floor does not gate an SSH key-exchange downgrade"},
		{"target_type":"condition","target_id":"C-NO-ACTION","severity":"high",
		 "problem":"condition may be unnecessary"},
		{"target_type":"condition","target_id":"C-UNKNOWN-ACTION","action":"mutate","severity":"high",
		 "problem":"condition may be unnecessary"}
	]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req chatRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		if len(req.Messages) > 0 && req.Messages[0].Role == "system" {
			system = req.Messages[0].Content
		}
		resp := chatResponse{Choices: []struct {
			Message      chatMessage `json:"message"`
			FinishReason string      `json:"finish_reason"`
		}{{Message: chatMessage{Role: "assistant", Content: reply}}}}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))
	defer srv.Close()
	client := NewClient(Config{BaseURL: srv.URL, AnalyzeModel: "m", BuildModel: "m", Enabled: true})

	c := &domain.AnalysisCase{
		Exploit: &domain.ExploitModel{
			MandatoryConditions: []domain.Condition{{
				ID: "C-PLATFORM", Kind: domain.ConditionPlatform, Mandatory: true,
				Description: "legacy TLS floor",
				Params:      map[string]string{"go_version": "< 1.18"},
				Subjects:    []domain.SymbolRef{{Package: "golang.org/x/crypto/ssh", Symbol: "connection.readPacket"}},
			}},
			SupportingFactors: []domain.Condition{{
				ID: "C-SECONDARY", Kind: domain.ConditionConfiguration,
				Description: "xDS server initialization",
				Params:      map[string]string{"knob": "xds.enabled"},
				Subjects:    []domain.SymbolRef{{Package: "example.com/dep/xds", Symbol: "Server.Init"}},
			}},
			ProposedConditions: []domain.Condition{{
				ID: "C-PROPOSED", Kind: domain.ConditionValidation,
				Description: "model-nominated validation",
				Params:      map[string]string{"check": "symbol_present"},
				Subjects:    []domain.SymbolRef{{Package: "example.com/dep", Symbol: "Parse"}},
			}},
			PendingConditionReviews: []domain.ConditionID{"C-PLATFORM"},
		},
	}
	rev := Reviewer{Client: client}.Review(c, domain.VerdictResult{Verdict: domain.VerdictInconclusive})

	if rev.Result != domain.ReviewRevise {
		t.Fatalf("review result = %s, want REVISE", rev.Result)
	}
	if len(rev.Findings) != 3 {
		t.Fatalf("findings = %+v, want 3", rev.Findings)
	}
	demote := rev.Findings[0]
	if demote.TargetType != "condition" || demote.TargetID != "C-PLATFORM" ||
		demote.Action != domain.ReviewActionDemote || demote.Severity != "high" {
		t.Fatalf("explicit demote not preserved: %+v", demote)
	}
	for _, f := range rev.Findings[1:] {
		// Old JSON without "action" still parses, but neither a missing nor
		// an unknown action may acquire promote semantics.
		if f.Action == domain.ReviewActionPromote {
			t.Fatalf("finding %+v acquired hidden promote semantics", f)
		}
		if f.Action != "" {
			t.Fatalf("unknown action %q should normalize to empty", f.Action)
		}
	}

	if !strings.Contains(system, "promote|demote") {
		t.Fatalf("reviewer prompt must state the exact promote|demote contract:\n%s", system)
	}
	if !strings.Contains(system, "nominations") || !strings.Contains(system, "never moves a condition") {
		t.Fatalf("reviewer prompt must state that actions are nominations, not repairs:\n%s", system)
	}
	if strings.Contains(system, "Repair moves it to supporting factors") {
		t.Fatalf("reviewer prompt still promises a reviewer-driven move:\n%s", system)
	}

	payload := reviewPayload(c, domain.VerdictResult{Verdict: domain.VerdictInconclusive})
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Conditions []struct {
			ID        domain.ConditionID `json:"id"`
			Mandatory bool               `json:"mandatory"`
			Params    map[string]string  `json:"params"`
			Subjects  []domain.SymbolRef `json:"subjects"`
		} `json:"conditions"`
		Proposed []struct {
			ID        domain.ConditionID `json:"id"`
			Mandatory bool               `json:"mandatory"`
			Proposed  bool               `json:"proposed"`
			Params    map[string]string  `json:"params"`
		} `json:"proposed_conditions"`
		Pending []domain.ConditionID `json:"pending_condition_reviews"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Conditions) != 2 {
		t.Fatalf("payload conditions = %d, want mandatory+supporting (2): %s", len(decoded.Conditions), raw)
	}
	byID := map[domain.ConditionID]int{}
	for i, cond := range decoded.Conditions {
		byID[cond.ID] = i
	}
	platIdx, ok := byID["C-PLATFORM"]
	if !ok {
		t.Fatalf("payload lacks mandatory condition: %s", raw)
	}
	plat := decoded.Conditions[platIdx]
	if !plat.Mandatory {
		t.Fatalf("mandatory condition serialized mandatory=false: %+v", plat)
	}
	if plat.Params["go_version"] != "< 1.18" {
		t.Fatalf("payload lost params: %+v", plat)
	}
	if len(plat.Subjects) != 1 || plat.Subjects[0].Package != "golang.org/x/crypto/ssh" {
		t.Fatalf("payload lost subjects: %+v", plat)
	}
	suppIdx, ok := byID["C-SECONDARY"]
	if !ok {
		t.Fatalf("payload lacks supporting condition: %s", raw)
	}
	supp := decoded.Conditions[suppIdx]
	if supp.Mandatory {
		t.Fatalf("supporting condition serialized mandatory=true: %+v", supp)
	}
	if supp.Params["knob"] != "xds.enabled" {
		t.Fatalf("supporting payload lost params: %+v", supp)
	}
	if len(supp.Subjects) != 1 || supp.Subjects[0].Symbol != "Server.Init" {
		t.Fatalf("supporting payload lost subjects: %+v", supp)
	}
	if len(decoded.Pending) != 1 || decoded.Pending[0] != "C-PLATFORM" {
		t.Fatalf("payload pending reviews = %v, want C-PLATFORM", decoded.Pending)
	}
	if len(decoded.Proposed) != 1 {
		t.Fatalf("payload proposed conditions = %d, want 1: %s", len(decoded.Proposed), raw)
	}
	prop := decoded.Proposed[0]
	if prop.ID != "C-PROPOSED" || prop.Mandatory || !prop.Proposed {
		t.Fatalf("proposal serialized as authoritative: %+v", prop)
	}
	if prop.Params["check"] != "symbol_present" {
		t.Fatalf("proposal payload lost params: %+v", prop)
	}
	if _, ok := byID["C-PROPOSED"]; ok {
		t.Fatalf("proposal leaked into the authoritative condition set: %s", raw)
	}
}

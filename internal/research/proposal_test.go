package research

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

func validProposalJSON(t *testing.T) []byte {
	t.Helper()
	return []byte(`{
		"falsifier":{"kind":"package-absent","condition_id":"cond-1","module":"example.com/dep","package":"example.com/dep/pkg","statement":"the required package is absent from the product closure","scope":"product build closure"},
		"checks":[{"id":"check-1","tool":"usage-scope","arguments":{"module":"example.com/dep","package":"example.com/dep/pkg"},"purpose":"check product and test build closure membership","condition_id":"cond-1"}]
	}`)
}

func TestVerificationPlanValid(t *testing.T) {
	plan, limitations := ParseVerificationPlan(validProposalJSON(t))
	if plan == nil || len(limitations) != 0 {
		t.Fatalf("plan=%+v limitations=%v", plan, limitations)
	}
	if err := ValidateVerificationPlan(*plan, t.TempDir(), nil); err != nil {
		t.Fatal(err)
	}
}

func TestVerificationPlanAbsent(t *testing.T) {
	ans, err := parseAgentAnswer(`{"category":"uncertain","reasoning":"insufficient evidence"}`)
	if err != nil || ans == nil {
		t.Fatalf("answer=%+v err=%v", ans, err)
	}
	if ans.VerificationPlan != nil {
		t.Fatalf("unexpected plan: %+v", ans.VerificationPlan)
	}
}

func TestVerificationPlanMalformedIsNonAuthoritative(t *testing.T) {
	ans, err := parseAgentAnswer(`{"category":"uncertain","reasoning":"bounded","verification_plan":{"falsifier":null}}`)
	if err != nil || ans == nil {
		t.Fatalf("answer=%+v err=%v", ans, err)
	}
	if ans.VerificationPlan != nil || len(ans.planLimitations) == 0 {
		t.Fatalf("plan=%+v limitations=%v", ans.VerificationPlan, ans.planLimitations)
	}
}

func TestFalsifierProposalUnknownKind(t *testing.T) {
	var raw map[string]any
	_ = json.Unmarshal(validProposalJSON(t), &raw)
	raw["falsifier"].(map[string]any)["kind"] = "not-a-falsifier"
	b, _ := json.Marshal(raw)
	plan, limitations := ParseVerificationPlan(b)
	if plan != nil || len(limitations) == 0 || !strings.Contains(limitations[0], "unsupported") {
		t.Fatalf("plan=%+v limitations=%v", plan, limitations)
	}
}

func TestFalsifierProposalEmptyConditionOrSubject(t *testing.T) {
	base := FalsifierProposal{Kind: domain.FalsifierPackageAbsent, ConditionID: "", Module: "example.com/dep", Statement: "absent", Scope: "product"}
	plan := VerificationPlan{Falsifier: base, Checks: []VerificationRequest{{ID: "c", Tool: "get_product_snapshot", Arguments: json.RawMessage(`{}`), Purpose: "snapshot", ConditionID: ""}}}
	if err := ValidateVerificationPlan(plan, "", nil); err == nil || !strings.Contains(err.Error(), "condition_id") {
		t.Fatalf("err=%v", err)
	}
	base.ConditionID = "cond"
	base.Module = ""
	base.Package = ""
	base.Symbol = ""
	plan.Falsifier = base
	plan.Checks[0].ConditionID = "cond"
	if err := ValidateVerificationPlan(plan, "", nil); err == nil || !strings.Contains(err.Error(), "subject") {
		t.Fatalf("err=%v", err)
	}
}

func TestVerificationPlanOverBudget(t *testing.T) {
	plan, _ := ParseVerificationPlan(validProposalJSON(t))
	if plan == nil {
		t.Fatal("valid fixture rejected")
	}
	for i := 0; i < 8; i++ {
		plan.Checks = append(plan.Checks, VerificationRequest{ID: "extra-" + string(rune('a'+i)), Tool: "get_product_snapshot", Arguments: json.RawMessage(`{}`), Purpose: "snapshot", ConditionID: plan.Falsifier.ConditionID})
	}
	if err := ValidateVerificationPlan(*plan, "", nil); err == nil || !strings.Contains(err.Error(), "maximum") {
		t.Fatalf("err=%v", err)
	}
}

func TestVerificationPlanRejectsUnsupportedToolAndTraversal(t *testing.T) {
	plan, _ := ParseVerificationPlan(validProposalJSON(t))
	if plan == nil {
		t.Fatal("valid fixture rejected")
	}
	plan.Checks[0].Tool = "shell"
	if err := ValidateVerificationPlan(*plan, t.TempDir(), nil); err == nil || !strings.Contains(err.Error(), "unsupported tool") {
		t.Fatalf("err=%v", err)
	}
	plan.Checks[0].Tool = "read_source"
	plan.Checks[0].Arguments = json.RawMessage(`{"file":"/outside/source.go"}`)
	root := t.TempDir()
	if err := ValidateVerificationPlan(*plan, root, []string{filepath.Join(root, "advisory")}); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("err=%v", err)
	}
}

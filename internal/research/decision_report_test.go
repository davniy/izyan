package research

import (
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
)

func TestResearchReportV2DecisionContract(t *testing.T) {
	r := validReport(t)
	if r.Schema != ReportSchemaV2 || r.Decision == nil {
		t.Fatalf("schema=%q decision=%+v", r.Schema, r.Decision)
	}
	if r.Disposition.Class != "REVIEW_REQUIRED" || r.Disposition.AutoClose {
		t.Fatalf("disposition=%+v", r.Disposition)
	}
	b, err := RenderJSON(r)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseReport(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(parsed, ""); err != nil {
		t.Fatalf("v2 report invalid: %v", err)
	}
}

func TestLegacyReportV1Compatibility(t *testing.T) {
	r := validReport(t)
	r.Schema = ReportSchemaV1
	r.Decision = nil
	before, err := RenderMarkdown(r)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseReport(mustJSON(t, r))
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(parsed, ""); err != nil {
		t.Fatalf("legacy /1 rejected: %v", err)
	}
	after, err := RenderMarkdown(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("legacy /1 rendering changed after parse/validate round trip")
	}
	if strings.Contains(string(after), "Evidence-based decision") {
		t.Fatal("legacy /1 rendered v2 decision section")
	}
}

func TestDecisionReportNoCallPathIsUnknownNotNotReachable(t *testing.T) {
	r := validReport(t)
	r.Decision = &EvidenceDecision{
		Verdict: domain.VerdictInconclusive, Reason: "relevant call-path tool did not run",
		Scope: "call-path scope", Coverage: "NOT_EVALUATED",
		HumanQuestions:  []string{"run the call-path check for the advisory-bound subject"},
		TicketRationale: "not evaluated; follow-up: run the call-path check",
	}
	md, err := RenderMarkdown(r)
	if err != nil {
		t.Fatal(err)
	}
	s := string(md)
	if !strings.Contains(s, "UNKNOWN — not evaluated") || strings.Contains(strings.ToLower(s), "not reachable") {
		t.Fatalf("decision rendering=%s", s)
	}
}

func TestNoDefaultEvidence(t *testing.T) {
	r := validReport(t)
	r.Decision = &EvidenceDecision{
		Verdict: domain.VerdictInconclusive, Reason: "evidence was absent",
		Scope: "unexecuted verification scope", Coverage: "NOT_EVALUATED",
		HumanQuestions: []string{"which check should run?"}, TicketRationale: "follow-up: execute the check",
	}
	md, err := RenderMarkdown(r)
	if err != nil {
		t.Fatal(err)
	}
	s := string(md)
	for _, forbidden := range []string{"EV-006", "EV-008", "EV-009", "🔴", "🟢"} {
		if strings.Contains(s, forbidden) {
			t.Fatalf("default evidence/status %q rendered", forbidden)
		}
	}
}

func TestRenderDecisionInvertedPyramid(t *testing.T) {
	r := validReport(t)
	r.Decision = &EvidenceDecision{
		Verdict: domain.VerdictNoExploitPathFound, Reason: "mandatory condition proven false",
		ConditionID: "condition-1", Falsifier: domain.FalsifierPackageAbsent,
		FalsifierStatement: "package absent from complete product closure", AgentHypothesis: "agent proposed package absence",
		Scope: "complete product closure", Coverage: "COMPLETE", EvidenceRefs: []string{"fact-obs-0001"},
		NegativeVerification: &domain.NegativeVerification{Status: domain.NegativeVerified},
		Sufficiency:          "all advisory subjects covered; no blocker remains", TicketRationale: "ticket-ready rationale",
		Checks: []DecisionCheck{{ID: "check-1", Tool: "usage-scope", Status: "OK", Completeness: "COMPLETE", Scope: "package closure", Coverage: "COMPLETE", EvidenceRefs: []string{"fact-obs-0001"}}},
	}
	md, err := RenderMarkdown(r)
	if err != nil {
		t.Fatal(err)
	}
	s := string(md)
	for _, needle := range []string{"Evidence-based decision", "no auto-close", "Agent hypothesis", "Concrete falsifier", "Checks actually executed", "Evidence refs", "Sufficiency", "Ticket-ready rationale"} {
		if !strings.Contains(s, needle) {
			t.Fatalf("missing %q", needle)
		}
	}
	if err := Validate(r, ""); err != nil {
		t.Fatalf("decision report invalid: %v", err)
	}
}

func mustJSON(t *testing.T, r *Report) []byte {
	t.Helper()
	b, err := RenderJSON(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

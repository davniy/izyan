package triage

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// feedbackInput returns the repoFixture input/manifest pair: a real snapshot
// over a temp tree with a 60-line main.go, so file checks stay honest.
func feedbackInput(t *testing.T) (FindingInput, SnapshotManifest) {
	t.Helper()
	return repoFixture(t)
}

// feedbackByRef indexes one FactFeedback by reference id.
func feedbackByRef(f FactFeedback) map[string]FactFeedbackItem {
	out := make(map[string]FactFeedbackItem, len(f.Items))
	for _, it := range f.Items {
		out[it.ReferenceID] = it
	}
	return out
}

// TestFactFeedbackItems covers the structured feedback contract: one item per
// non-VALID gate check carrying status, reason, expected repair and allowed
// scope, nothing for VALID references, and a recorded pass number.
func TestFactFeedbackItems(t *testing.T) {
	in, m := feedbackInput(t)
	a := gateAssessment(
		[]Claim{
			refClaim("c1", "e1", "e2", "e3"),
			{ID: "c2", Statement: "no evidence", DecisionRelevant: true},
			{ID: "c3", Statement: "background", DecisionRelevant: false, EvidenceRefs: []string{"e4"}},
		},
		[]EvidenceRef{
			{ID: "e1", Kind: "file", Locator: "ghost.go"},
			{ID: "e2", Kind: "file", Locator: "main.go"},
			{ID: "e3"},
			{ID: "e4", Kind: "file", Locator: "ghost.go"},
		},
	)
	v := FactGate{}.Validate(context.Background(), in, m, a)
	fb := FactGate{}.BuildFeedback(v, 1)
	if fb.Pass != 1 {
		t.Fatalf("pass = %d, want 1", fb.Pass)
	}
	items := feedbackByRef(fb)
	if len(fb.Items) != 4 || len(items) != 4 {
		t.Fatalf("feedback items = %+v", fb.Items)
	}
	if _, ok := items["e2"]; ok {
		t.Fatalf("VALID reference must not produce feedback: %+v", items["e2"])
	}
	if it := items["e1"]; it.CurrentStatus != FactInvalid || it.Reason == "" ||
		it.ExpectedRepair == "" || it.AllowedScope == "" {
		t.Fatalf("e1 item malformed: %+v", it)
	}
	// An unreferenced decision-relevant claim feeds back under the claim id.
	if it := items["c2"]; it.CurrentStatus != FactUnreferenced || it.ExpectedRepair == "" {
		t.Fatalf("c2 item malformed: %+v", it)
	}
	if it := items["e3"]; it.CurrentStatus != FactUnavailable {
		t.Fatalf("e3 item = %+v, want UNAVAILABLE", it)
	}
	// Non-decision-relevant citations still feed back — the gate checks
	// reproducibility, not relevance — but they never claim a blocking effect.
	if it := items["e4"]; it.CurrentStatus != FactInvalid {
		t.Fatalf("e4 item = %+v, want INVALID", it)
	}
	if fb.RecommendationEffect == "" {
		t.Fatal("recommendation_effect must state the deterministic consequence")
	}
}

// TestFactFeedbackNoSemanticVerdict pins the anti-steering rule: neither the
// structured feedback nor the rendered repair-turn message may name a
// recommendation or verdict — the agent repairs reproducibility only.
func TestFactFeedbackNoSemanticVerdict(t *testing.T) {
	in, m := feedbackInput(t)
	a := gateAssessment(
		[]Claim{refClaim("c1", "e1")},
		[]EvidenceRef{{ID: "e1", Kind: "file", Locator: "ghost.go"}},
	)
	v := FactGate{}.Validate(context.Background(), in, m, a)
	fb := FactGate{}.BuildFeedback(v, 1)
	msg := factFeedbackMessage(fb)
	raw, err := json.Marshal(fb)
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{
		"EXPLOITABLE", "NOT_EXPLOITABLE", "INCONCLUSIVE",
		"DISMISSED", "LOWERED", "UNCHANGED", "NOT_AFFECTED",
		"verdict", "recommendation\":",
	} {
		if strings.Contains(msg, banned) {
			t.Fatalf("feedback message leaks semantic vocabulary %q:\n%s", banned, msg)
		}
	}
	for _, want := range []string{`"reference_id":"e1"`, `"current_status":"INVALID"`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("feedback JSON missing %s: %s", want, raw)
		}
		if !strings.Contains(msg, want) {
			t.Fatalf("feedback message missing %s:\n%s", want, msg)
		}
	}
	if !strings.Contains(msg, AssessmentSchemaVersion) {
		t.Fatalf("feedback message must target the current schema:\n%s", msg)
	}
}

// TestFactFeedbackAllValid: a COMPLETE validation produces no repair items.
func TestFactFeedbackAllValid(t *testing.T) {
	in, m := feedbackInput(t)
	a := gateAssessment(
		[]Claim{refClaim("c1", "e1")},
		[]EvidenceRef{{ID: "e1", Kind: "file", Locator: "main.go:1-5"}},
	)
	v := FactGate{}.Validate(context.Background(), in, m, a)
	if v.Status != ValidationComplete {
		t.Fatalf("fixture validation = %s, want COMPLETE (%+v)", v.Status, v.References)
	}
	fb := FactGate{}.BuildFeedback(v, 0)
	if len(fb.Items) != 0 || fb.RecommendationEffect != "" {
		t.Fatalf("valid validation must not produce feedback: %+v", fb)
	}
	if needsFactRepair(v) {
		t.Fatal("all-VALID validation must not request a repair pass")
	}
}

// TestFactFeedbackBoundedByStatus: feedback items are derived from the
// deterministic gate result alone — same validation in, same feedback out,
// and pass numbering is the caller's record, not a re-derived fact.
func TestFactFeedbackDeterministic(t *testing.T) {
	in, m := feedbackInput(t)
	a := gateAssessment(
		[]Claim{refClaim("c1", "e1")},
		[]EvidenceRef{{ID: "e1", Kind: "file", Locator: "ghost.go"}},
	)
	v := FactGate{}.Validate(context.Background(), in, m, a)
	g := FactGate{}
	if fb1, fb2 := g.BuildFeedback(v, 2), g.BuildFeedback(v, 2); fb1.Pass != 2 ||
		len(fb1.Items) != len(fb2.Items) || fb1.Items[0] != fb2.Items[0] ||
		fb1.RecommendationEffect != fb2.RecommendationEffect {
		t.Fatalf("feedback not deterministic: %+v vs %+v", fb1, fb2)
	}
}

// TestUnresolvedBlocksRiskReduction pins the post-pass contract on the gate
// report itself: a non-VALID check bound to a decision-relevant claim —
// INVALID, CONFLICTING, UNREFERENCED or a mandatory UNAVAILABLE — carries
// EffectBlocksRiskReduction, while the same failure cited only by a
// non-decision-relevant claim does not claim to block anything.
func TestUnresolvedBlocksRiskReduction(t *testing.T) {
	in, m := feedbackInput(t)
	a := gateAssessment(
		[]Claim{
			refClaim("c1", "e1", "e3"),
			{ID: "c2", Statement: "unreferenced", DecisionRelevant: true},
			{ID: "c3", Statement: "bg", DecisionRelevant: false, EvidenceRefs: []string{"e2"}},
		},
		[]EvidenceRef{
			{ID: "e1", Kind: "file", Locator: "ghost.go"},
			{ID: "e2", Kind: "file", Locator: "ghost.go"},
			{ID: "e3"},
		},
	)
	v := FactGate{}.Validate(context.Background(), in, m, a)
	var e1, e2, e3 *ReferenceCheck
	var unref *ReferenceCheck
	for i := range v.References {
		rc := &v.References[i]
		switch {
		case rc.Status == FactUnreferenced:
			unref = rc
		case rc.EvidenceID == "e1":
			e1 = rc
		case rc.EvidenceID == "e2":
			e2 = rc
		case rc.EvidenceID == "e3":
			e3 = rc
		}
	}
	if e1 == nil || e2 == nil || e3 == nil || unref == nil {
		t.Fatalf("missing checks: %+v", v.References)
	}
	if e1.Effect != EffectBlocksRiskReduction {
		t.Fatalf("decision-bound INVALID effect = %q", e1.Effect)
	}
	if e1.ExpectedRepair == "" || e1.Scope == "" || e1.Subject != "ghost.go" || e1.SnapshotHash != m.ContentHash {
		t.Fatalf("e1 check metadata incomplete: %+v", e1)
	}
	if unref.Effect != EffectBlocksRiskReduction || unref.Subject != "c2" {
		t.Fatalf("UNREFERENCED check malformed: %+v", unref)
	}
	if e3.Effect != EffectBlocksRiskReduction {
		t.Fatalf("decision-bound UNAVAILABLE effect = %q", e3.Effect)
	}
	if e2.Status != FactInvalid {
		t.Fatalf("e2 = %+v, want INVALID", e2)
	}
	if e2.Effect == EffectBlocksRiskReduction {
		t.Fatal("a reference no decision-relevant claim cites must not claim a blocking effect")
	}
}

// TestNoCatalogRequiresNoProposalRepair: a catalog-level refusal is an
// external run binding, not an agent-repairable proposal defect. A run with
// no supplied catalog rejects the proposal with the honest reason and buys
// no repair turn; malformed proposal ownership under a bound catalog stays
// repairable, because the agent can change the condition it names.
func TestNoCatalogRequiresNoProposalRepair(t *testing.T) {
	c := validCatalog(t)
	bind := fullBinding(c)

	admission := GateFalsifierProposals(nil, bind, []FalsifierProposal{validProposal()})
	if len(admission.Admitted) != 0 || len(admission.Rejected) != 1 {
		t.Fatalf("nil catalog admission = %+v", admission)
	}
	report := NewFalsifierReport("rules-1", admission.Rejected...)
	fb := BuildFalsifierFeedback(&report, 1)
	if len(fb.Items) != 1 || fb.Retryable() {
		t.Fatalf("missing catalog requested a repair turn: %+v", fb)
	}
	if fb.Items[0].Repair != "" || !strings.Contains(fb.Items[0].Reason, "no condition catalog") {
		t.Fatalf("missing catalog feedback = %+v", fb.Items[0])
	}

	// A condition outside the bound catalog is malformed proposal
	// ownership: the agent can repair it from the advertised capability.
	p := validProposal()
	p.ConditionID = "cond-invented"
	admission = GateFalsifierProposals(c, bind, []FalsifierProposal{p})
	if len(admission.Admitted) != 0 || len(admission.Rejected) != 1 {
		t.Fatalf("unknown condition admission = %+v", admission)
	}
	report = NewFalsifierReport("rules-1", admission.Rejected...)
	fb = BuildFalsifierFeedback(&report, 1)
	if len(fb.Items) != 1 || !fb.Retryable() || fb.Items[0].Repair == "" {
		t.Fatalf("malformed proposal ownership did not stay repairable: %+v", fb)
	}
}

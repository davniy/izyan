package triage

import "testing"

func TestConditionalProfileChangesDecision(t *testing.T) {
	p := ConditionalProfile{Profile: "internal", Applicability: Condition{ID: "exposure", Predicate: Predicate{Op: "eq", Left: "x", Right: "y"}, Status: ConditionUnknown, Scope: "deployment", Effect: "lower"}, ExpectedDisposition: RecommendationLowered}
	if !ConditionalProfileChangesDecision(p, RecommendationUnchanged) {
		t.Fatal("expected disposition change")
	}
	if ConditionalProfileApplicable(p) {
		t.Fatal("unknown applicability must not apply")
	}
	if got := AddConditionalProfile(nil, p, RecommendationUnchanged); len(got) != 1 {
		t.Fatalf("got %d profiles", len(got))
	}
	p.ExpectedDisposition = RecommendationUnchanged
	if got := AddConditionalProfile(nil, p, RecommendationUnchanged); len(got) != 0 {
		t.Fatalf("got %d profiles", len(got))
	}
}

package triage

import "testing"

func TestPredicateEvaluation(t *testing.T) {
	facts := FactSet{"exposure": "public", "items": []any{"a", "b"}, "release": map[string]any{"toolchain": map[string]any{"changed": true}}}
	cases := []struct {
		name      string
		predicate Predicate
		want      ConditionStatus
	}{
		{"eq", Predicate{Op: "eq", Left: map[string]any{"fact": "exposure"}, Right: "public"}, ConditionSatisfied},
		{"neq", Predicate{Op: "neq", Left: map[string]any{"fact": "exposure"}, Right: "internal"}, ConditionSatisfied},
		{"in", Predicate{Op: "in", Left: map[string]any{"fact": "exposure"}, Right: []any{"public", "internal"}}, ConditionSatisfied},
		{"not in", Predicate{Op: "not_in", Left: map[string]any{"fact": "exposure"}, Right: []any{"internal"}}, ConditionSatisfied},
		{"exists", Predicate{Op: "exists", Path: "release.toolchain"}, ConditionSatisfied},
		{"missing", Predicate{Op: "missing", Path: "absent"}, ConditionSatisfied},
		{"changed", Predicate{Op: "changed", Path: "release.toolchain"}, ConditionSatisfied},
		{"all", Predicate{Op: "all", Args: []Predicate{{Op: "exists", Path: "exposure"}, {Op: "eq", Left: map[string]any{"fact": "exposure"}, Right: "public"}}}, ConditionSatisfied},
		{"any", Predicate{Op: "any", Args: []Predicate{{Op: "eq", Left: map[string]any{"fact": "exposure"}, Right: "internal"}, {Op: "exists", Path: "exposure"}}}, ConditionSatisfied},
		{"not", Predicate{Op: "not", Args: []Predicate{{Op: "eq", Left: map[string]any{"fact": "exposure"}, Right: "internal"}}}, ConditionSatisfied},
		{"unknown", Predicate{Op: "eq", Left: map[string]any{"fact": "absent"}, Right: "x"}, ConditionUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := EvaluatePredicate(tc.predicate, facts); got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestPredicateInvalidStructure(t *testing.T) {
	if (Predicate{}).Valid() {
		t.Fatal("empty predicate must be invalid")
	}
	if got := EvaluatePredicate(Predicate{Op: "unknown"}, FactSet{}); got != ConditionUnknown {
		t.Fatalf("got %s", got)
	}
}

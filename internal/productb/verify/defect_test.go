package verify

import (
	"encoding/json"
	"testing"

	"github.com/fedorovmv/izyan/internal/evidencetools"
	"github.com/fedorovmv/izyan/internal/productb/claimshape"
	triage "github.com/fedorovmv/izyan/internal/productb/triage"
)

func graphObservation(t *testing.T, data map[string]any) triage.RecordedObservation {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"data": data,
		"scope_details": map[string]any{
			"snapshot_hash": "snap-1",
			"build_context": map[string]any{"goos": "linux"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return triage.RecordedObservation{
		ID: "det-graph", Tool: "get_dependency_graph", Status: "OK",
		Completeness: evidencetools.CompletenessComplete, Payload: b,
		SnapshotHash: "snap-1", BuildContextHash: "bc-1", RunID: "run-1", Attempt: 1,
	}
}

func TestModuleCapabilityRejectsNonModuleSubject(t *testing.T) {
	c := absentClaim()
	c.ID = "c-symbol"
	c.EvidenceRefs = []string{"det-graph"}
	o := graphObservation(t, map[string]any{
		"modules": []any{map[string]any{"effective_path": "dep/pkg"}},
	})
	rep := Evaluate(baseInput(c, o))
	got := rep.ClaimOutcomeOf(c.ID)
	if got.Outcome != OutcomeUnknown {
		t.Fatalf("module graph must not adjudicate symbol claim: %+v", got)
	}
}

func TestModuleCapabilityRequiresExactObservedPath(t *testing.T) {
	c := absentClaim()
	c.ID = "c-module"
	c.Subject = claimshape.Subject{Kind: claimshape.SubjectModule, Name: "other/module"}
	c.EvidenceRefs = []string{"det-graph"}
	o := graphObservation(t, map[string]any{
		"modules": []any{map[string]any{"effective_path": "dep/module"}},
	})
	rep := Evaluate(baseInput(c, o))
	if got := rep.ClaimOutcomeOf(c.ID); got.Outcome != OutcomeUnknown {
		t.Fatalf("unmatched module path must not adjudicate claim: %+v", got)
	}
}

func TestGapSurfaceBlocksBothDeclarationAndClosureViews(t *testing.T) {
	c := absentClaim()
	c.EvidenceRefs = []string{"det-1"}
	o := absenceObs(t, nil)
	var envelope map[string]any
	if err := json.Unmarshal(o.Payload, &envelope); err != nil {
		t.Fatal(err)
	}
	data, _ := envelope["data"].(map[string]any)
	data["import_closure"] = map[string]any{
		"complete": true, "hash": "closure-1", "scope_hash": "scope-1",
		"open_exceptions": []any{"dynamic loader"},
	}
	o.Payload, _ = json.Marshal(envelope)
	rep := Evaluate(baseInput(c, o))
	got := rep.ClaimOutcomeOf(c.ID)
	if got.Outcome == OutcomeTrue || got.Predicate == PredicateHolds {
		t.Fatalf("closure gap must block declaration+scope conjunction: %+v", got)
	}
}

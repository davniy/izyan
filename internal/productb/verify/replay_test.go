package verify

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// writeJSON writes one artifact file into the run dir.
func writeJSON(t *testing.T, dir, name string, v any) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// runFixture builds a minimal persisted run: one absence claim citing a
// complete verify_code_absence observation, with run-bound provenance.
func runFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	payload := map[string]any{
		"id": "det-1", "tool": "verify_code_absence", "fact": "absent", "completeness": "COMPLETE", "tool_status": "OK",
		"data": map[string]any{
			"expected_subjects":     []any{map[string]any{"package": "dep/pkg", "symbol": "Victim"}},
			"checked_subjects":      []any{map[string]any{"package": "dep/pkg", "symbol": "Victim"}},
			"absent_subjects":       []any{map[string]any{"package": "dep/pkg", "symbol": "Victim"}},
			"coverage_rule_version": "4",
			"import_closure":        map[string]any{"complete": true, "hash": "closure-1", "scope_hash": "scope-1"},
		},
		"scope_details": map[string]any{
			"snapshot_hash": "snap-1",
			"build_context": map[string]any{"goos": "linux", "goarch": "amd64"},
		},
	}
	writeJSON(t, dir, "observation-archive.json", map[string]any{
		"schema_version": "observation-archive.v1",
		"observations": []any{map[string]any{
			"id": "det-1", "tool": "verify_code_absence", "status": "OK",
			"completeness": "COMPLETE", "scope": "closure",
			"payload":       payload,
			"snapshot_hash": "snap-1",
			"run_id":        "run-1", "attempt": 1,
		}},
	})
	writeJSON(t, dir, "assessment.json", map[string]any{
		"schema_version": "assessment.v1",
		"finding_id":     "f-1",
		"verdict":        "NOT_EXPLOITABLE", // inert label — never read
		"claims": []any{map[string]any{
			"id": "c-1", "statement": "the vulnerable symbol is absent",
			"status": "supported", "decision_relevant": true,
			"evidence_refs": []any{"det-1"},
		}},
		"evidence": []any{map[string]any{"id": "det-1", "kind": "observation", "locator": "det-1"}},
	})
	writeJSON(t, dir, "stage0.json", map[string]any{
		"schema_version": "stage0.v1", "finding_id": "f-1",
		"advisory": map[string]any{"resolved_id": "ADV-1"},
		"resolution_vulnerability": map[string]any{
			"id": "ADV-1", "module": "dep", "package": "dep/pkg",
			"affected_symbols": []any{map[string]any{"package": "dep/pkg", "symbol": "Victim"}},
		},
	})
	writeJSON(t, dir, "decision.json", map[string]any{
		"run_id": "run-1", "finding_id": "f-1",
		"technical_assessment": map[string]any{"internal_status": "COMPLETE"},
		"recommendation":       "DISMISSED", // inert label — never consumed
	})
	return dir
}

// TestReplayDeterministic proves the offline replay reproduces an
// identical report twice without any LLM call — the graph is a pure
// function of the persisted artifacts.
func TestReplayDeterministic(t *testing.T) {
	dir := runFixture(t)
	a, err := ReplayRun(dir, "ticket-1")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ReplayRun(dir, "ticket-1")
	if err != nil {
		t.Fatal(err)
	}
	if a.Hash != b.Hash {
		t.Fatal("replay not deterministic")
	}
	ba, _ := a.Marshal()
	bb, _ := b.Marshal()
	if string(ba) != string(bb) {
		t.Fatal("replay bytes differ between runs")
	}
	ev := a.ClaimOutcomeOf("c-1")
	if ev == nil {
		t.Fatal("claim missing from replay report")
	}
	if ev.Outcome != OutcomeTrue {
		t.Fatalf("complete closed absence must hold on replay: %+v", ev)
	}
	// The graph edges exist and bind observation to claim.
	var sawSupports, sawCovers bool
	for _, e := range a.Edges {
		switch e.Kind {
		case "supports":
			if e.To == "c-1" {
				sawSupports = true
			}
		case "covers":
			sawCovers = true
		}
	}
	if !sawSupports || !sawCovers {
		t.Fatalf("replay edges incomplete: %+v", a.Edges)
	}
}

// TestReplayReplaysChallenges proves the persisted reviewer channel
// replays deterministically: a challenges.json adds its minted claims
// to the replayed report, byte-identical across runs, and a malformed
// document is a technical error rather than a skipped challenge.
func TestReplayReplaysChallenges(t *testing.T) {
	dir := runFixture(t)
	writeJSON(t, dir, "challenges.json", map[string]any{
		"schema_version": ChallengeSchemaVersion,
		"run_id":         "run-1", "finding_id": "f-1",
		"challenges": []any{map[string]any{
			"id": "rev-1", "kind": "alternative_caller",
			"subject": map[string]any{
				"kind": "symbol", "name": "dep/pkg.Handler",
				"package": "dep/pkg", "symbol": "Handler",
			},
		}},
	})
	a, err := ReplayRun(dir, "ticket-1")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ReplayRun(dir, "ticket-1")
	if err != nil {
		t.Fatal(err)
	}
	if a.Hash != b.Hash {
		t.Fatal("challenge replay not deterministic")
	}
	if len(a.Challenges) != 1 || a.Challenges[0].ClaimID == "" {
		t.Fatalf("challenge not replayed: %+v", a.Challenges)
	}
	row := a.Challenges[0]
	ev := a.ClaimOutcomeOf(row.ClaimID)
	if ev == nil || ev.Shape != "path.reachable" || ev.Outcome != OutcomeUnknown {
		t.Fatalf("replayed challenge claim = %+v", ev)
	}
	// Malformed persisted challenges are a technical error.
	if err := os.WriteFile(filepath.Join(dir, "challenges.json"), []byte(`{"challenges":[{"kind":"missing_subject","verdict":"NE"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReplayRun(dir, "ticket-1"); err == nil {
		t.Fatal("forged challenge field replayed silently")
	}
}

// TestCoverageTable documents which shapes have implemented capabilities:
// every canonical shape must resolve its required set — unimplemented
// capabilities would be an honest gap the table exposes.
func TestCoverageTable(t *testing.T) {
	var derived, absent bool
	for _, row := range CoverageTable() {
		switch string(row.Shape) {
		case "derived.mandatory_condition", "derived.triage_disposition":
			derived = true
			if len(row.Implemented) == 0 {
				t.Fatalf("derived shapes must be served by the entailment capability: %+v", row)
			}
		case "subject.absent":
			absent = true
			if len(row.Implemented) != len(row.Capabilities) {
				t.Fatalf("absence capabilities must be implemented: %+v", row)
			}
		}
	}
	if !derived || !absent {
		t.Fatal("coverage table incomplete")
	}
}

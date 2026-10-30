package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// failingCorpus builds a one-run corpus whose replayed safety report
// violates a hard gate: the recorded LLM verdict is EXPLOITABLE while the
// deterministic graph compiles a DISMISSED — an alarm that auto-safed.
func failingCorpus(t *testing.T) string {
	t.Helper()
	corpus := t.TempDir()
	dir := filepath.Join(corpus, "T-1", "intake-1-x")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	wj := func(name string, v any) {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	wj("stage0.json", map[string]any{
		"schema_version": "stage0.v1",
		"advisory":       map[string]any{"resolved_id": "GHSA-x"},
		"resolution_vulnerability": map[string]any{
			"id":      "GHSA-x",
			"module":  "example.com/mod",
			"package": "example.com/mod",
			"affected_versions": []map[string]any{
				{"introduced": "0", "fixed": "1.5.0"},
			},
		},
		"materialization": map[string]any{"source_id": "repo-a", "selected_ref": "1.2.3"},
	})
	wj("assessment.json", map[string]any{
		"schema_version": "assessment.v1",
		"finding_id":     "intake-1-x",
		"verdict":        "EXPLOITABLE",
		"claims":         []any{map[string]any{"id": "c1", "statement": "s", "status": "confirmed", "decision_relevant": true, "evidence_refs": []string{"e1"}}},
		"evidence":       []any{map[string]any{"id": "e1", "kind": "observation", "locator": "det:det-0001"}},
	})
	wj("observation-archive.json", map[string]any{
		"schema_version": "observation-archive.v1",
		"observations": []any{map[string]any{
			"id": "det-0001", "tool": "get_module_version", "status": "OK", "completeness": "PARTIAL",
			"scope": "s", "snapshot_hash": "snap-1", "attempt": 1,
			"payload": map[string]any{
				"fact": "v", "scope": "s", "completeness": "PARTIAL", "tool_status": "OK",
				"scope_details": map[string]any{"snapshot_hash": "snap-1", "build_context": map[string]any{"goos": "linux", "goarch": "amd64"}},
				"data":          map[string]any{"module": "example.com/mod", "present": true, "version": "v9.9.9"},
			},
		}},
	})
	return corpus
}

// TestGateFailsClosedOnHardCheck: a report whose hard checks fail must
// exit 1 — a green exit code would let a failing safety report pass the
// merge gate. The "precision_95_proven" reporting gate stays non-blocking.
func TestGateFailsClosedOnHardCheck(t *testing.T) {
	corpus := failingCorpus(t)
	out := filepath.Join(t.TempDir(), "report.json")
	code := run([]string{"-corpus", corpus, "-out", out})
	if code != 1 {
		t.Fatalf("exit = %d, want 1 for a failing hard gate", code)
	}
}

// TestGatePassesCleanCorpus: a corpus with no reductions at all keeps
// every hard gate green and exits 0 even though the precision bound is
// unproven (expected on any corpus this size).
func TestGatePassesCleanCorpus(t *testing.T) {
	corpus := t.TempDir()
	code := run([]string{"-corpus", corpus})
	if code != 0 {
		t.Fatalf("exit = %d, want 0 for an empty corpus with no hard-gate failures", code)
	}
}

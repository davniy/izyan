package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/eval/agent7"
)

// fakeRun builds a minimal run dir: scoring/cases.jsonl, metrics.json and
// one case dir per spec (predictionPath written only when env is non-nil).
func fakeRun(t *testing.T, cases map[string]string) string {
	t.Helper()
	run := t.TempDir()
	if err := os.MkdirAll(filepath.Join(run, "scoring"), 0o755); err != nil {
		t.Fatal(err)
	}
	var lines []string
	for id := range cases {
		lines = append(lines, `{"task_id":"`+id+`","scoring_outcome":"correct_safe","ground_truth":"not_exploitable"}`)
	}
	if err := os.WriteFile(filepath.Join(run, "scoring", "cases.jsonl"),
		[]byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(run, "metrics.json"),
		[]byte(`{"provenance":{"profile":"test"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	for id, env := range cases {
		if env == "" {
			continue // case dir intentionally absent
		}
		dir := filepath.Join(run, sanitize(id))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "prediction.json"), []byte(env), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return run
}

// TestCoverageInfraExclusion verifies an advisory-error envelope is
// reported as infra_error and excluded from every aggregate, while a
// clean envelope keeps its real verdict and outcome.
func TestCoverageInfraExclusion(t *testing.T) {
	tasks := []agent7.TaskRecord{
		{TaskID: "clean-case"}, {TaskID: "infra-case"}, {TaskID: "missing-case"},
	}
	run := fakeRun(t, map[string]string{
		"clean-case": `{"task_id":"clean-case","terminal_state":"COMPLETED","verdict":"NOT_AFFECTED",` +
			`"reason":"resolved version is outside the affected range","scoring_outcome":"correct_safe"}`,
		"infra-case": `{"task_id":"infra-case","terminal_state":"INCONCLUSIVE","verdict":"INCONCLUSIVE",` +
			`"reason":"advisory error: osv get https://api.osv.dev/v1/vulns/CVE-2099-0001: context canceled",` +
			`"scoring_outcome":"abstain","compatibility_category":"uncertain"}`,
		"missing-case": "", // no prediction.json at all
	})
	out := filepath.Join(t.TempDir(), "cov.json")
	if err := writeCoverage(out, []string{run}, tasks, "deadbeef", []InvalidatedAttempt{
		{RunDir: "eval/agent7/results/b0-baseline-j2-memcancel", Profile: "-j 2 --mem-limit 8GiB",
			AffectedCases: 17, Cause: "memguard cancellation"},
	}); err != nil {
		t.Fatalf("writeCoverage: %v", err)
	}
	b, _ := os.ReadFile(out)
	var doc struct {
		Invalidated []InvalidatedAttempt `json:"invalidated_attempts"`
		Cases       []struct {
			TaskID     string `json:"task_id"`
			Verdict    string `json:"verdict"`
			InfraError bool   `json:"infra_error"`
		} `json:"cases"`
		Agg struct {
			VerdictDist map[string]int `json:"verdict_distribution"`
			OutcomeDist map[string]int `json:"scoring_outcome_distribution"`
			Total       int            `json:"total_cases"`
			Attempted   int            `json:"attempted_cases"`
			Infra       []string       `json:"infra_errors"`
			InfraCount  int            `json:"infra_error_count"`
		} `json:"aggregates"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("coverage doc: %v", err)
	}
	if doc.Agg.InfraCount != 2 {
		t.Fatalf("infra_error_count = %d, want 2", doc.Agg.InfraCount)
	}
	if doc.Agg.Attempted != 1 || doc.Agg.Total != 3 {
		t.Fatalf("attempted/total = %d/%d, want 1/3", doc.Agg.Attempted, doc.Agg.Total)
	}
	if doc.Agg.VerdictDist["infra_error"] != 0 {
		t.Error("infra_error leaked into verdict_distribution")
	}
	if doc.Agg.VerdictDist["NOT_AFFECTED"] != 1 {
		t.Errorf("verdict_distribution[NOT_AFFECTED] = %d, want 1", doc.Agg.VerdictDist["NOT_AFFECTED"])
	}
	if doc.Agg.OutcomeDist["abstain"] != 0 {
		t.Error("canceled abstain leaked into scoring_outcome_distribution")
	}
	if len(doc.Invalidated) != 1 || doc.Invalidated[0].AffectedCases != 17 {
		t.Errorf("invalidated_attempts not recorded: %+v", doc.Invalidated)
	}
	got := map[string]struct {
		v string
		i bool
	}{}
	for _, c := range doc.Cases {
		got[c.TaskID] = struct {
			v string
			i bool
		}{c.Verdict, c.InfraError}
	}
	if got["clean-case"].v != "NOT_AFFECTED" || got["clean-case"].i {
		t.Errorf("clean case: %+v", got["clean-case"])
	}
	if got["infra-case"].v != "infra_error" || !got["infra-case"].i {
		t.Errorf("infra case: %+v", got["infra-case"])
	}
	if got["missing-case"].v != "infra_error" || !got["missing-case"].i {
		t.Errorf("missing case: %+v", got["missing-case"])
	}
}

// TestRequireCompleteFailsClosed builds a run with one infra case and one
// case lacking prediction.json: --require-complete must refuse the run.
func TestRequireCompleteFailsClosed(t *testing.T) {
	dir := t.TempDir()
	tasksPath := filepath.Join(dir, "tasks.jsonl")
	task := `{"task_id":"missing-case","repo_url":"https://github.com/o/r","commit_sha":"` +
		strings.Repeat("a", 40) + `","cve_id":"CVE-2099-0002","ground_truth":"not_exploitable","ground_truth_category":"code_not_present"}`
	if err := os.WriteFile(tasksPath, []byte(task+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runDir := fakeRun(t, map[string]string{"missing-case": ""})
	err := run([]string{
		"--tasks", tasksPath, "--repos-dir", dir, "--run", runDir,
		"--manifest", "../../eval/agent7/freeze/manifest.json",
		"--out-dir", dir, "--require-complete",
	})
	if err == nil || !strings.Contains(err.Error(), "require-complete") {
		t.Fatalf("run() error = %v, want require-complete refusal", err)
	}

	// Without the flag the generator tolerates gaps (dev-time use).
	if err := run([]string{
		"--tasks", tasksPath, "--repos-dir", dir, "--run", runDir,
		"--manifest", "../../eval/agent7/freeze/manifest.json",
		"--out-dir", filepath.Join(dir, "out2"),
	}); err != nil {
		t.Fatalf("run() without --require-complete: %v", err)
	}
}

// TestCoverageSegmentMerge pins retry semantics: the LAST segment that
// produced an envelope wins, aggregates are recomputed over the merged
// set, and --require-complete fails while a merged case is still infra.
func TestCoverageSegmentMerge(t *testing.T) {
	seg1 := fakeRun(t, map[string]string{
		"case-a": `{"task_id":"case-a","terminal_state":"INCONCLUSIVE","verdict":"INCONCLUSIVE",` +
			`"reason":"advisory error: osv get https://api.osv.dev/v1/vulns/CVE-1: context canceled","scoring_outcome":"abstain"}`,
		"case-b": `{"task_id":"case-b","terminal_state":"COMPLETED","verdict":"NOT_AFFECTED",` +
			`"reason":"resolved version is outside the affected range","scoring_outcome":"correct_safe"}`,
	})
	seg2 := t.TempDir() // retry segment: only case-a, now a real result
	caseDir := filepath.Join(seg2, sanitize("case-a"))
	if err := os.MkdirAll(caseDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(caseDir, "prediction.json"),
		[]byte(`{"task_id":"case-a","terminal_state":"COMPLETED","verdict":"EXPLOITABLE",`+
			`"reason":"all mandatory exploit conditions are satisfied","scoring_outcome":"correct_exploitable"}`),
		0o644); err != nil {
		t.Fatal(err)
	}
	tasks := []agent7.TaskRecord{{TaskID: "case-a"}, {TaskID: "case-b"}}
	out := filepath.Join(t.TempDir(), "cov.json")
	if err := writeCoverage(out, []string{seg1, seg2}, tasks, "deadbeef", nil); err != nil {
		t.Fatalf("writeCoverage: %v", err)
	}
	b, _ := os.ReadFile(out)
	var doc struct {
		Segments []coverageSegment `json:"segments"`
		Cases    []struct {
			TaskID  string `json:"task_id"`
			Verdict string `json:"verdict"`
			Segment string `json:"segment"`
		} `json:"cases"`
		Agg struct {
			InfraCount int `json:"infra_error_count"`
			Attempted  int `json:"attempted_cases"`
			Metrics    struct {
				Total     int `json:"total"`
				FalseSafe int `json:"false_safe"`
			} `json:"metrics"`
		} `json:"aggregates"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("coverage doc: %v", err)
	}
	if len(doc.Segments) != 2 || doc.Segments[0].RunDir != seg1 || doc.Segments[1].RunDir != seg2 {
		t.Fatalf("segments: %+v", doc.Segments)
	}
	if doc.Segments[0].InfraErrors != 1 || doc.Segments[1].InfraErrors != 0 {
		t.Errorf("segment infra counts: %d/%d", doc.Segments[0].InfraErrors, doc.Segments[1].InfraErrors)
	}
	if doc.Agg.InfraCount != 0 || doc.Agg.Attempted != 2 {
		t.Errorf("merged aggregates: infra=%d attempted=%d, want 0/2", doc.Agg.InfraCount, doc.Agg.Attempted)
	}
	if doc.Agg.Metrics.Total != 2 {
		t.Errorf("metrics.total = %d, want 2", doc.Agg.Metrics.Total)
	}
	var aVerdict, aSeg string
	for _, c := range doc.Cases {
		if c.TaskID == "case-a" {
			aVerdict, aSeg = c.Verdict, c.Segment
		}
	}
	if aVerdict != "EXPLOITABLE" || aSeg != seg2 {
		t.Errorf("case-a verdict/segment = %q/%q, want EXPLOITABLE/%q (later segment wins)", aVerdict, aSeg, seg2)
	}

	// --require-complete over the merged set: seg2 has no case-b → the
	// seg1 envelope keeps it clean, but an infra case in the LAST segment
	// still fails closed. Rebuild seg2 with an infra retry → must refuse.
	dir := t.TempDir()
	tasksPath := filepath.Join(dir, "tasks.jsonl")
	tl := `{"task_id":"case-a","repo_url":"https://github.com/o/r","commit_sha":"` +
		strings.Repeat("a", 40) + `","cve_id":"CVE-2099-0002","ground_truth":"exploitable","ground_truth_category":"vulnerable"}`
	if err := os.WriteFile(tasksPath, []byte(tl+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	seg3 := t.TempDir()
	cd := filepath.Join(seg3, sanitize("case-a"))
	if err := os.MkdirAll(cd, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cd, "prediction.json"),
		[]byte(`{"task_id":"case-a","terminal_state":"INCONCLUSIVE","verdict":"INCONCLUSIVE",`+
			`"reason":"advisory error: osv get x: context deadline exceeded"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	err := run([]string{
		"--tasks", tasksPath, "--repos-dir", dir,
		"--run", seg1, "--run", seg3,
		"--manifest", "../../eval/agent7/freeze/manifest.json",
		"--out-dir", dir, "--require-complete",
	})
	if err == nil || !strings.Contains(err.Error(), "require-complete") {
		t.Fatalf("run() = %v, want require-complete refusal on infra retry", err)
	}
}

// TestRequireCompletePassesOnCleanMerged verifies the gate accepts a
// merged run where every case produced a real envelope — the baseline
// scenario (3 segments, 30/30 real results, 0 infra).
func TestRequireCompletePassesOnCleanMerged(t *testing.T) {
	dir := t.TempDir()
	tasksPath := filepath.Join(dir, "tasks.jsonl")
	mkTask := func(id string) string {
		return `{"task_id":"` + id + `","repo_url":"https://github.com/o/` + id + `","commit_sha":"` +
			strings.Repeat("a", 40) + `","cve_id":"CVE-2099-0003","ground_truth":"not_exploitable","ground_truth_category":"code_not_present"}`
	}
	if err := os.WriteFile(tasksPath, []byte(mkTask("case-a")+"\n"+mkTask("case-b")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	clean := `{"task_id":"%s","terminal_state":"COMPLETED","verdict":"NOT_AFFECTED",` +
		`"reason":"resolved version is outside the affected range","scoring_outcome":"correct_safe",` +
		`"limitations":["build/test evidence actions skipped: executing repository code requires --allow-exec"]}`
	// The --allow-exec limitation is a NORMAL run limitation, not a
	// degradation signal — its presence must not trip the gate.
	seg1 := fakeRun(t, map[string]string{"case-a": fmt.Sprintf(clean, "case-a"), "case-b": ""})
	seg2 := fakeRun(t, map[string]string{"case-b": fmt.Sprintf(clean, "case-b")})
	if err := run([]string{
		"--tasks", tasksPath, "--repos-dir", dir,
		"--run", seg1, "--run", seg2,
		"--manifest", "../../eval/agent7/freeze/manifest.json",
		"--out-dir", dir, "--require-complete",
	}); err != nil {
		t.Fatalf("clean merged run refused: %v", err)
	}
}

// TestRequireCompleteRejectsDeclaredDegraded pins the operator-declared
// semantics: degradation is never inferred from artifact contents —
// --degraded <case_id> is the only way a real result can fail the gate.
func TestRequireCompleteRejectsDeclaredDegraded(t *testing.T) {
	dir := t.TempDir()
	tasksPath := filepath.Join(dir, "tasks.jsonl")
	task := `{"task_id":"case-a","repo_url":"https://github.com/o/r","commit_sha":"` +
		strings.Repeat("a", 40) + `","cve_id":"CVE-2099-0004","ground_truth":"not_exploitable","ground_truth_category":"code_not_present"}`
	if err := os.WriteFile(tasksPath, []byte(task+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runDir := fakeRun(t, map[string]string{
		"case-a": `{"task_id":"case-a","terminal_state":"COMPLETED","verdict":"EXPLOITABLE",` +
			`"reason":"all mandatory exploit conditions are satisfied","scoring_outcome":"correct_exploitable"}`,
	})
	err := run([]string{
		"--tasks", tasksPath, "--repos-dir", dir, "--run", runDir,
		"--manifest", "../../eval/agent7/freeze/manifest.json",
		"--out-dir", dir, "--require-complete", "--degraded", "case-a",
	})
	if err == nil || !strings.Contains(err.Error(), "declared degraded") {
		t.Fatalf("run() = %v, want refusal naming the declared-degraded case", err)
	}
	// A declaration for a case NOT in the merged set is a no-op.
	if err := run([]string{
		"--tasks", tasksPath, "--repos-dir", dir, "--run", runDir,
		"--manifest", "../../eval/agent7/freeze/manifest.json",
		"--out-dir", filepath.Join(dir, "out2"), "--require-complete",
		"--degraded", "not-a-real-case",
	}); err != nil {
		t.Fatalf("irrelevant --degraded must not fail the gate: %v", err)
	}
}

// TestInvalidatedRunDirExcluded verifies a run dir declared via
// --invalidated is dropped from the merge even when passed as --run:
// if it is a case's only envelope source, that case has no envelope and
// --require-complete fails closed.
func TestInvalidatedRunDirExcluded(t *testing.T) {
	dir := t.TempDir()
	tasksPath := filepath.Join(dir, "tasks.jsonl")
	task := `{"task_id":"case-a","repo_url":"https://github.com/o/r","commit_sha":"` +
		strings.Repeat("a", 40) + `","cve_id":"CVE-2099-0005","ground_truth":"not_exploitable","ground_truth_category":"code_not_present"}`
	if err := os.WriteFile(tasksPath, []byte(task+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bad := fakeRun(t, map[string]string{
		"case-a": `{"task_id":"case-a","terminal_state":"COMPLETED","verdict":"EXPLOITABLE",` +
			`"reason":"all mandatory exploit conditions are satisfied"}`,
	})
	good := fakeRun(t, map[string]string{}) // empty clean segment
	err := run([]string{
		"--tasks", tasksPath, "--repos-dir", dir,
		"--run", bad, "--run", good,
		"--invalidated", bad + "|test profile|1|operator-declared invalid",
		"--manifest", "../../eval/agent7/freeze/manifest.json",
		"--out-dir", dir, "--require-complete",
	})
	if err == nil || !strings.Contains(err.Error(), "infra/missing") {
		t.Fatalf("run() = %v, want refusal: invalidated dir is no evidence", err)
	}
}

package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/eval"
)

const evalBaselineConfig = `{"config":{"protocol_version":"v1.0.0","scan_mode":"source"}}` + "\n"

func evalGovEvidence(id string, outcome domain.GovulncheckOutcome, content string, advisory domain.GovulncheckAdvisoryCoverage, scopeComplete bool) domain.Evidence {
	return domain.Evidence{
		ID:   domain.EvidenceID(id),
		Kind: domain.EvidenceGovulncheck,
		Govulncheck: &domain.GovulncheckRun{
			Outcome: outcome,
			Coverage: domain.GovulncheckCoverage{
				AdvisoryID:    "GO-TEST-1",
				Advisory:      advisory,
				ScopeComplete: scopeComplete,
			},
		},
		Content: content,
	}
}

func evalgovCase(evidence ...domain.Evidence) *domain.AnalysisCase {
	return &domain.AnalysisCase{
		EvidenceGraph: domain.EvidenceGraph{Evidence: evidence},
	}
}

func evalBaselineVuln() domain.Vulnerability {
	return domain.Vulnerability{ID: "GO-TEST-1", Module: "example.com/dep"}
}

func TestEvalBaselineSelectsLatestCompletedTypedRecord(t *testing.T) {
	failed := evalGovEvidence("EV-GV-FAILED", domain.GovulncheckFailed, "", domain.GovulncheckCoverageUnknown, false)
	failed.Govulncheck.Error = "exit status 1"
	completed := evalGovEvidence("EV-GV-DONE", domain.GovulncheckCompletedEmpty, evalBaselineConfig,
		domain.GovulncheckCoverageCovered, true)
	c := evalgovCase(failed, completed)

	got := selectRecordedGovulncheck(c)
	if got == nil || got.ID != completed.ID {
		t.Fatalf("selected %+v, want the completed record", got)
	}
	baseline, ok := recordedBaseline(c, evalBaselineVuln())
	if !ok || baseline != eval.BaselineSilent {
		t.Fatalf("baseline=%q ok=%v, want silent", baseline, ok)
	}
}

func TestEvalBaselineFailedRecordDoesNotRerun(t *testing.T) {
	// The raw prefix is parseable as a function-level finding, but the
	// typed outcome says the process failed: it must stay an error and no
	// standalone execution may be attempted.
	prefix := evalBaselineConfig + `{"finding":{"osv":"GO-TEST-1","trace":[{"package":"example.com/dep/vuln","function":"Sink"}]}}`
	failed := evalGovEvidence("EV-GV-FAILED", domain.GovulncheckFailed, prefix,
		domain.GovulncheckCoverageUnknown, false)
	failed.Govulncheck.Error = "exit status 1"
	baseline, ok := recordedBaseline(evalgovCase(failed), evalBaselineVuln())
	if !ok {
		t.Fatal("existing failed record must suppress the standalone execution")
	}
	if !strings.HasPrefix(baseline, eval.BaselineError) {
		t.Fatalf("failed record classified as %q, want error", baseline)
	}

	notRun := evalGovEvidence("EV-GV-SKIP", domain.GovulncheckNotRun, "", domain.GovulncheckCoverageUnknown, false)
	notRun.Govulncheck.Error = "govulncheck runner not configured"
	baseline, ok = recordedBaseline(evalgovCase(notRun), evalBaselineVuln())
	if !ok || !strings.HasPrefix(baseline, eval.BaselineError) {
		t.Fatalf("not-run record returned baseline=%q ok=%v, want error without rerun", baseline, ok)
	}
}

func TestEvalBaselineNoRecordAllowsStandaloneRun(t *testing.T) {
	if _, ok := recordedBaseline(nil, evalBaselineVuln()); ok {
		t.Fatal("nil analysis case must not report a collected run record")
	}
	c := evalgovCase(domain.Evidence{
		ID:      "EV-OTHER",
		Kind:    domain.EvidenceModuleGraph,
		Content: "module graph",
	})
	if _, ok := recordedBaseline(c, evalBaselineVuln()); ok {
		t.Fatal("case without a govulncheck record must allow the standalone baseline")
	}
}

func TestEvalBaselineLegacyRecordDoesNotRerun(t *testing.T) {
	// A pre-typed record is a collected run whose outcome is unknown. It
	// must not silently trigger a second execution behind the caller's back.
	legacy := domain.Evidence{
		ID:      "EV-GV-LEGACY",
		Kind:    domain.EvidenceGovulncheck,
		Content: evalBaselineConfig,
	}
	baseline, ok := recordedBaseline(evalgovCase(legacy), evalBaselineVuln())
	if !ok {
		t.Fatal("legacy govulncheck record must suppress the standalone execution")
	}
	if !strings.HasPrefix(baseline, eval.BaselineError) {
		t.Fatalf("legacy record classified as %q, want error (outcome not recorded)", baseline)
	}
}

func TestEvalBaselineMismatchedContextDoesNotRerun(t *testing.T) {
	product := domain.ProductSnapshot{Repository: "example.com/prod", GOOS: "linux", GOARCH: "amd64"}
	other := product
	other.GOOS = "windows"
	ctx := domain.EffectiveBuildContext(other)
	// The record describes another build, yet says "silent" under its own
	// coverage. It must not be relabelled for this build and must not start
	// a second execution.
	ev := evalGovEvidence("EV-GV-OTHER", domain.GovulncheckCompletedEmpty, evalBaselineConfig,
		domain.GovulncheckCoverageCovered, true)
	ev.BuildContext = &ctx
	c := evalgovCase(ev)
	c.Product = product

	baseline, ok := recordedBaseline(c, evalBaselineVuln())
	if !ok {
		t.Fatal("mismatched record must suppress the standalone execution")
	}
	if !strings.HasPrefix(baseline, eval.BaselineError) || !strings.Contains(baseline, "different build") {
		t.Fatalf("mismatched record classified as %q, want a different-build error", baseline)
	}
}

// writeEvalReport persists one report so `izyan eval compare` can read it back
// through its own decoder.
func writeEvalReport(t *testing.T, path string, results ...eval.Result) {
	t.Helper()
	report := eval.Report{Results: results}
	report.Metrics.Total = len(results)
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("encode report: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write report: %v", err)
	}
}

func evalCompareResult(id, verdict string, claims map[string]string) eval.Result {
	return eval.Result{
		Case:    eval.Case{ID: id, Vuln: "GO-TEST-" + id, Module: "example.com/dep", Repo: "products/" + id},
		Verdict: verdict,
		Claims:  claims,
		Build:   "build-1",
	}
}

// TestEvalCompareReportsLostPositiveAndRefusesUnmatchedMaterial pins the CLI
// contract of `izyan eval compare`: it writes the delta for a matched pair,
// reports the loss in its stdout summary, and exits with the error code when
// the two saved runs do not describe the same population.
func TestEvalCompareReportsLostPositiveAndRefusesUnmatchedMaterial(t *testing.T) {
	dir := t.TempDir()
	beforePath := filepath.Join(dir, "before.json")
	afterPath := filepath.Join(dir, "after.json")
	outPath := filepath.Join(dir, "delta.json")

	writeEvalReport(t, beforePath,
		evalCompareResult("alpha", "EXPLOITABLE", map[string]string{"C-REACH": "TRUE", "C-PEER-INPUT": "TRUE"}),
		evalCompareResult("beta", "NOT_AFFECTED", map[string]string{"C-REACH": "FALSE"}),
	)
	writeEvalReport(t, afterPath,
		evalCompareResult("alpha", "INCONCLUSIVE", map[string]string{"C-REACH": "TRUE"}),
		evalCompareResult("beta", "NOT_AFFECTED", map[string]string{"C-REACH": "FALSE"}),
	)
	if err := runEvalCompare([]string{"--before", beforePath, "--after", afterPath, "--out", outPath}); err != nil {
		t.Fatalf("eval compare: %v", err)
	}
	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read delta: %v", err)
	}
	var delta eval.AuthorityDelta
	if err := json.Unmarshal(raw, &delta); err != nil {
		t.Fatalf("decode delta: %v", err)
	}
	if delta.Schema != eval.AuthorityDeltaSchema || delta.Matched != 2 || delta.Unchanged != 1 {
		t.Fatalf("delta schema/matched/unchanged = %q/%d/%d", delta.Schema, delta.Matched, delta.Unchanged)
	}
	if len(delta.Transitions) != 1 || delta.Transitions[0].Case != "alpha" ||
		delta.Transitions[0].Transition != eval.TransitionLostPositive {
		t.Fatalf("delta transitions = %+v, want the lost alpha positive", delta.Transitions)
	}
	if delta.Before == "" || delta.After == "" {
		t.Fatal("the delta does not name the runs it compared")
	}

	// Unmatched material is refused with the error exit code, not written.
	unmatchedPath := filepath.Join(dir, "after-unmatched.json")
	writeEvalReport(t, unmatchedPath,
		evalCompareResult("alpha", "INCONCLUSIVE", map[string]string{"C-REACH": "TRUE"}),
	)
	err = runEvalCompare([]string{"--before", beforePath, "--after", unmatchedPath, "--out", filepath.Join(dir, "none.json")})
	if err == nil {
		t.Fatal("an unmatched pair was compared")
	}
	var exit *cliExitError
	if !errors.As(err, &exit) || exit.code != evalCompareExitError {
		t.Fatalf("error %v did not carry exit code %d", err, evalCompareExitError)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "none.json")); statErr == nil {
		t.Fatal("a refused comparison still wrote a delta")
	}
}

// TestEvalCompareExitsOnNewFalseSafe pins the stop criterion: a comparison
// that gains a false-safe completes and writes its record, then exits with the
// dedicated code so CI cannot treat the authority change as clean.
func TestEvalCompareExitsOnNewFalseSafe(t *testing.T) {
	dir := t.TempDir()
	beforePath := filepath.Join(dir, "before.json")
	afterPath := filepath.Join(dir, "after.json")
	outPath := filepath.Join(dir, "delta.json")

	writeEvalReport(t, beforePath, evalCompareResult("alpha", "EXPLOITABLE", map[string]string{"C-REACH": "TRUE"}))
	safe := evalCompareResult("alpha", "NO_EXPLOIT_PATH_FOUND", map[string]string{"C-REACH": "FALSE"})
	safe.FalseSafe = true
	writeEvalReport(t, afterPath, safe)

	err := runEvalCompare([]string{"--before", beforePath, "--after", afterPath, "--out", outPath})
	if err == nil {
		t.Fatal("a comparison that gained a false-safe exited cleanly")
	}
	var exit *cliExitError
	if !errors.As(err, &exit) || exit.code != evalCompareExitFalseSafe {
		t.Fatalf("error %v did not carry exit code %d", err, evalCompareExitFalseSafe)
	}
	if _, statErr := os.Stat(outPath); statErr != nil {
		t.Fatalf("the comparison did not write its record: %v", statErr)
	}
}

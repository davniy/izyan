package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	triage "github.com/davniy/izyan/internal/productb/triage"
)

// TestTriageEvalOfflineComparison exercises the offline command end to end
// on a real saved run: exit 0 without violations, exit 1 for measured
// human comparison mistakes, exit 2 for missing coverage and malformed
// provenance, and an untouched source run. No model is configured.
func TestTriageEvalOfflineComparison(t *testing.T) {
	srv, _ := fakeTriageLLM(t, detThenAssessment(cliAssessmentDet))
	repo := cliFixtureRepo(t)
	input := writeFindings(t, triageFinding("eval-cli-1", repo))
	out := filepath.Join(t.TempDir(), "out")
	triageEnv(t, srv.URL)
	if err := runTriage([]string{"--input", input, "--out", out}); err != nil {
		t.Fatalf("prepare saved run: %v", err)
	}
	dir := runDir(t, out, "eval-cli-1")
	decisionPath := filepath.Join(dir, "decision.json")
	decisionBefore := assertFile(t, decisionPath)
	pkg := readDecision(t, dir)
	if pkg.ProposedAction.Kind != triage.HumanActionClose || pkg.MachineDisposition.Recommendation != triage.RecommendationUnchanged {
		t.Fatalf("unexpected fixture package: action=%s machine=%s", pkg.ProposedAction.Kind, pkg.MachineDisposition.Recommendation)
	}

	// The evaluator must not need any model configuration.
	t.Setenv("LLM_ENABLED", "")

	writeBaseline := func(t *testing.T, body string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "baselines.json")
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}

	// 1. A control that permits CLOSE and a matching external judgment:
	// the comparison completes without violations.
	agreeing := writeBaseline(t, `{"schema_version":"triage-baselines.v1","baselines":[
		{"finding_id":"eval-cli-1","disposition":"DISMISSED","expected_judgment":"NOT_EXPLOITABLE","source":"external"}]}`)
	evalOut := filepath.Join(t.TempDir(), "eval")
	if err := runTriageEval([]string{"--run", dir, "--baseline", agreeing, "--out", evalOut}); err != nil {
		t.Fatalf("agreeing baseline evaluation: %v", err)
	}
	var eval triage.DecisionEvaluation
	if err := json.Unmarshal(assertFile(t, filepath.Join(evalOut, "evaluation.json")), &eval); err != nil {
		t.Fatalf("evaluation.json: %v", err)
	}
	if eval.SchemaVersion != triage.EvaluationSchemaVersion || eval.FindingID != "eval-cli-1" || eval.DecisionPackageHash == "" {
		t.Fatalf("evaluation identity = %+v", eval)
	}
	if eval.Coverage.ControlDisposition != triage.ComparisonAssessed || eval.Coverage.ExpectedJudgment != triage.ComparisonAssessed {
		t.Fatalf("evaluation coverage = %+v", eval.Coverage)
	}
	if len(eval.Violations) != 0 || eval.Human.ReductionControlMismatches != 0 ||
		eval.Human.IncorrectNegativeJudgments != 0 || eval.Machine.FalseSafe != 0 {
		t.Fatalf("agreeing evaluation = %+v", eval)
	}

	// 2. A disagreeing external judgment and a control that forbids the
	// human proposal: measured comparison violations exit 1 and keep the
	// human/machine counters separate.
	disagreeing := writeBaseline(t, `{"schema_version":"triage-baselines.v1","baselines":[
		{"finding_id":"eval-cli-1","disposition":"UNCHANGED","expected_judgment":"EXPLOITABLE","source":"external"}]}`)
	disagreeOut := filepath.Join(t.TempDir(), "eval-disagree")
	err := runTriageEval([]string{"--run", dir, "--baseline", disagreeing, "--out", disagreeOut})
	wantExit(t, err, triageEvalExitViolation)
	if err := json.Unmarshal(assertFile(t, filepath.Join(disagreeOut, "evaluation.json")), &eval); err != nil {
		t.Fatalf("disagreeing evaluation.json: %v", err)
	}
	if eval.Human.ReductionControlMismatches != 1 || eval.Human.IncorrectNegativeJudgments != 1 ||
		eval.Human.CloseOnExploitable != 1 {
		t.Fatalf("human counters = %+v", eval.Human)
	}
	if eval.Machine.FalseSafe != 0 || eval.Machine.Reductions != 0 {
		t.Fatalf("human mistakes leaked into machine counters: %+v", eval.Machine)
	}
	if len(eval.Violations) != 3 {
		t.Fatalf("violations = %v, want 3 measured failures", eval.Violations)
	}

	// 3. An absent expected_judgment leaves judgment coverage UNASSESSED;
	// it is not fabricated into a measured zero-error result.
	controlOnly := writeBaseline(t, `{"schema_version":"triage-baselines.v1","baselines":[
		{"finding_id":"eval-cli-1","disposition":"DISMISSED","source":"external"}]}`)
	controlOut := filepath.Join(t.TempDir(), "eval-control-only")
	if err := runTriageEval([]string{"--run", dir, "--baseline", controlOnly, "--out", controlOut}); err != nil {
		t.Fatalf("control-only evaluation: %v", err)
	}
	if err := json.Unmarshal(assertFile(t, filepath.Join(controlOut, "evaluation.json")), &eval); err != nil {
		t.Fatal(err)
	}
	if eval.Coverage.ControlDisposition != triage.ComparisonAssessed || eval.Coverage.ExpectedJudgment != triage.ComparisonUnassessed {
		t.Fatalf("control-only coverage = %+v", eval.Coverage)
	}

	// 4. A baseline with no entry for the finding is missing requested
	// comparison coverage: exit 2, never a completed empty comparison.
	missing := writeBaseline(t, `{"schema_version":"triage-baselines.v1","baselines":[
		{"finding_id":"some-other-finding","disposition":"UNCHANGED"}]}`)
	wantExit(t, runTriageEval([]string{"--run", dir, "--baseline", missing, "--out", filepath.Join(t.TempDir(), "eval-missing")}), triageEvalExitError)

	// 5. Malformed provenance and an out directory inside the source run
	// are input errors, not measured violations.
	emptyRun := t.TempDir()
	wantExit(t, runTriageEval([]string{"--run", emptyRun, "--baseline", agreeing, "--out", filepath.Join(t.TempDir(), "eval-empty")}), triageEvalExitError)
	wantExit(t, runTriageEval([]string{"--run", dir, "--baseline", agreeing, "--out", filepath.Join(dir, "eval-inside")}), triageEvalExitError)

	// 6. The evaluated run is never modified by either outcome.
	if got := assertFile(t, decisionPath); string(got) != string(decisionBefore) {
		t.Fatal("offline evaluation modified the saved decision package")
	}
}

// TestTriageEvalFlags pins the required flags and the removal of the live
// comparison flag.
func TestTriageEvalFlags(t *testing.T) {
	wantExit(t, runTriageEval(nil), triageEvalExitError)
	wantExit(t, runTriageEval([]string{"--run", "."}), triageEvalExitError)
	wantExit(t, runTriageEval([]string{"--run", ".", "--baseline", "b.json", "--out", "out", "extra"}), triageEvalExitError)
	err := runTriage([]string{"--baseline", "b.json"})
	wantExit(t, err, triage.ExitCodeError)
	if !strings.Contains(err.Error(), "eval triage") {
		t.Fatalf("live --baseline error = %v", err)
	}
}

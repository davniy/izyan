package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	triage "github.com/fedorovmv/izyan/internal/productb/triage"
)

// TestHumanCapabilityPreservationMatrix exercises the real owners, not source
// spelling or schema presence. Retained package-private historical fixtures and
// Python controllers run in focused subprocesses; no corpus or real model runs.
func TestHumanCapabilityPreservationMatrix(t *testing.T) {
	t.Run("unconditional_action", TestTriageHumanResultDoesNotPublishMachineSafe)
	t.Run("one_question_accept_reject_without_narrative_no_model_replay", TestBranchReviewCLIOfflineSmoke)
	t.Run("interleaved_review_rejects_superseded_presented_branch", TestBranchReviewCLIRejectsInterleavedSelection)
	t.Run("exact_record_isolation", TestResearchCandidateNegatives)
	t.Run("canonical_publication", TestResearchCLIEmitsCanonicalRequestedFinding)
	t.Run("actual_cli_surface", func(t *testing.T) {
		binary := filepath.Join(t.TempDir(), "izyan")
		if output, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
			t.Fatalf("build CLI: %v\n%s", err, output)
		}
		for _, tc := range []struct {
			args            []string
			present, absent []string
		}{
			{[]string{"research", "--help"}, []string{"-snapshot", "-record-pin", "-replay-agent-turn"}, []string{"-model ", "-provider ", "-base-url "}},
			{[]string{"triage", "--help"}, []string{"-answer", "-record-decision", "-decision", "-actor", "-projection-hash", "-replay-run"}, nil},
			{[]string{"eval", "research-replay", "--help"}, []string{"-run", "-out"}, []string{"-model ", "-snapshot "}},
			{[]string{"eval", "research-b1", "--help"}, []string{"-allow-agent", "-dry-run"}, nil},
		} {
			output, _ := exec.Command(binary, tc.args...).CombinedOutput()
			for _, want := range tc.present {
				if !strings.Contains(string(output), want) {
					t.Fatalf("%v missing %q: %s", tc.args, want, output)
				}
			}
			for _, banned := range tc.absent {
				if strings.Contains(string(output), banned) {
					t.Fatalf("%v advertises retired %q", tc.args, banned)
				}
			}
		}
		output, err := exec.Command(binary, "research-b1").CombinedOutput()
		if err == nil || strings.Contains(string(output), "\n  izyan research-b1 ") || !strings.Contains(string(output), "izyan eval research-b1") {
			t.Fatalf("obsolete top-level B1 route: %v\n%s", err, output)
		}
		// Real Go JSON uses null in the report and empty string in the
		// manifest for an absent optional commit; the offline consumer must
		// accept that encoding without accepting nonempty identity drift.
		command := exec.Command("python3", "-m", "pytest", "eval/decision_ready/test_runner.py::test_compiled_cli_without_optional_commit", "-q")
		command.Dir = filepath.Join("..", "..")
		command.Env = append(os.Environ(), "IZYAN_SMOKE_BIN="+binary, "IZYAN_OSV_URL=")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("compiled CLI consumer smoke: %v\n%s", err, output)
		}
	})
	t.Run("prepared_two_questions_and_bounds", func(t *testing.T) {
		var a triage.Assessment
		if err := json.Unmarshal([]byte(cliAssessmentDet), &a); err != nil {
			t.Fatal(err)
		}
		a.ProposedAction.Kind = triage.HumanActionKeepOpen
		quote := "Exploitation requires the network listener option to be enabled"
		raw := []byte(quote)
		a.EnvironmentVariables = []triage.EnvironmentVariableProposal{{ID: triage.VariableDeploymentPerimeter}, {ID: triage.VariableAdvisoryPrecondition, RecordID: "CVE-2099-0001", RecordSHA256: sha256TestHex(raw), Quote: quote}}
		for _, perimeter := range []string{"cluster-internal", "public", triage.EnvironmentUnknown} {
			for _, condition := range []string{"holds", "does_not_hold", triage.EnvironmentUnknown} {
				a.ConditionalActions = append(a.ConditionalActions, triage.ConditionalActionProposal{Assignments: map[string]string{triage.VariableDeploymentPerimeter: perimeter, triage.VariableAdvisoryPrecondition: condition}, Judgment: triage.LLMJudgment{Verdict: triage.VerdictInconclusive}, Action: a.ProposedAction})
			}
		}
		in := triage.HumanBranchInput{SupportInput: triage.SupportInput{Assessment: a, Stage0: triage.Stage0Result{Investigation: triage.InvestigationInputs{Records: []triage.CapturedRecord{{RecordID: "CVE-2099-0001", Raw: raw, SHA256: sha256TestHex(raw), Size: int64(len(raw))}}}}}}
		in.Stage0.Snapshot = triage.SnapshotManifest{ContentHash: sha256TestHex([]byte("matrix snapshot"))}
		plan, err := triage.BuildHumanReviewPlan(in)
		if err != nil {
			t.Fatal(err)
		}
		if len(plan.Variables) != 2 || len(plan.Branches) != 9 || plan.Readiness != string(triage.HumanBranchComplete) {
			t.Fatalf("incomplete two-question universe: %+v", plan)
		}
		in.Assessment.EnvironmentVariables = append(in.Assessment.EnvironmentVariables, triage.EnvironmentVariableProposal{ID: triage.VariableDeploymentPerimeter})
		plan, err = triage.BuildHumanReviewPlan(in)
		if err != nil || plan.Readiness != string(triage.HumanBranchNotDecisionReady) {
			t.Fatalf("overflow silently admitted: %+v %v", plan, err)
		}
		for _, b := range plan.Branches {
			if b.Action.Kind != triage.HumanActionKeepOpen {
				t.Fatal("overflow authorized reduction")
			}
		}
	})
	for _, tc := range []struct {
		name string
		argv []string
	}{
		{"unknown_not_reasked_contradiction_and_review_history", []string{"go", "test", "./internal/productb/triage", "-run", "^Test(EnvironmentAnswerTwoQuestionsAndUnknown|AnsweredVariableIsNotReasked|EnvironmentAnswerDeterministicConflict|EnvironmentAssertionSupersession|BranchReviewReplayCopiesHistoryVerbatim|BranchReviewRejectsRehashedV1Downgrade|BranchReviewHistoricalV1FieldIsolation|AcceptRejectNeedsNoTechnicalNarrative|HumanReviewFirstScreenBounds|PromptBuildAssignmentsComposePreparedUniverse|EnvironmentQuestionsBuildModeDoesNotFollowFiles)$", "-count=1"}},
		{"historical_3_4_no_authority_upgrade", []string{"go", "test", "./internal/research", "-run", "^TestHistorical(DecisionArtifactPlayback|RequestCompositionPlayback|ReplayCannotPublishCurrentAuthority)$", "-count=1"}},
		{"offline_indexes_and_failed_census_stale_report", []string{"python3", "-m", "pytest", "eval/decision_ready/test_runner.py::test_offline_runner_rebuilds_metric_inputs", "eval/decision_ready/test_census.py::test_census_rejects_stale_report_after_failure", "-q"}},
		{"census_digest_build_toolchain_and_optional_commit", []string{"python3", "-m", "pytest", "eval/decision_ready/test_census.py::test_census_rejects_material_drift_at_same_path", "eval/decision_ready/test_census.py::test_census_preserves_effective_build_and_toolchain", "eval/decision_ready/test_census.py::test_census_preserves_recorded_host_effective_build", "eval/decision_ready/test_census.py::test_retained_toolchain_fallback_is_technical_failure", "eval/decision_ready/test_census.py::test_guard_rechecks_retained_digest_pins", "eval/decision_ready/test_census.py::test_optional_commit_real_go_encoding_is_absent_only", "-q"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(tc.argv[0], tc.argv[1:]...)
			cmd.Dir = filepath.Join("..", "..")
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%v: %v\n%s", tc.argv, err, output)
			}
		})
	}
}

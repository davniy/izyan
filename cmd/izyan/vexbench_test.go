package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/eval/vexbench"
)

func TestFilterVexTasks(t *testing.T) {
	tasks := []vexbench.Task{
		{TaskID: "a-1-CVE-1"},
		{TaskID: "b-2-CVE-2"},
		{TaskID: "c-3-CVE-3"},
	}
	got, err := filterVexTasks(tasks, "b-2-CVE-2")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].TaskID != "b-2-CVE-2" {
		t.Fatalf("exact match failed: %+v", got)
	}

	got, err = filterVexTasks(tasks, "a-*,c-*")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("glob match failed: %+v", got)
	}

	if _, err := filterVexTasks(tasks, "zzz"); err == nil {
		t.Fatal("no-match filter should error")
	}
}

func TestVexDiscriminator_NotAffectedFields(t *testing.T) {
	cases := []struct {
		name     string
		affected domain.AffectedResult
		want     string
	}{
		{"module absent", domain.AffectedResult{ModulePresent: domain.ClaimFalse}, vexbench.AffectedModuleAbsent},
		{"version fixed", domain.AffectedResult{ModulePresent: domain.ClaimTrue, VersionAffected: domain.ClaimFalse}, vexbench.AffectedVersionFixed},
		{"package absent", domain.AffectedResult{ModulePresent: domain.ClaimTrue, VersionAffected: domain.ClaimTrue, PackagePresent: domain.ClaimFalse}, vexbench.AffectedPackageAbsent},
		{"build excluded", domain.AffectedResult{ModulePresent: domain.ClaimTrue, VersionAffected: domain.ClaimTrue, PackagePresent: domain.ClaimTrue, BuildRelevant: domain.ClaimFalse}, vexbench.AffectedBuildExcluded},
		{"implementation absent", domain.AffectedResult{ModulePresent: domain.ClaimTrue, VersionAffected: domain.ClaimTrue, PackagePresent: domain.ClaimTrue, BuildRelevant: domain.ClaimTrue, VulnerableImplementationPresent: domain.ClaimFalse}, vexbench.AffectedImplementationAbsent},
	}
	for _, tc := range cases {
		c := &domain.AnalysisCase{Affected: &tc.affected}
		got := vexDiscriminator(c, string(domain.VerdictNotAffected), "", "")
		if got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestVexDiscriminator_TrustedInfrastructureBasis(t *testing.T) {
	c := &domain.AnalysisCase{}
	// Declared perimeter basis must be appended so the mapping can tell a
	// perimeter control from a code-level config origin.
	got := vexDiscriminator(c, string(domain.VerdictNoExploitPathFound),
		domain.FalsifierTrustedInfrastructure, domain.BasisDeclaredTrust)
	want := domain.FalsifierTrustedInfrastructure + ":" + domain.BasisDeclaredTrust
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	// A bare falsifier passes through unchanged.
	got = vexDiscriminator(c, string(domain.VerdictNoExploitPathFound), domain.FalsifierLocusPackageAbsent, "")
	if got != domain.FalsifierLocusPackageAbsent {
		t.Fatalf("bare falsifier mangled: %q", got)
	}
}

func TestVexVerdict_NilVerdictTerminalStates(t *testing.T) {
	// An INCONCLUSIVE terminal without a verdict record is an abstention.
	c := &domain.AnalysisCase{Workflow: domain.WorkflowStatus{State: domain.StateInconclusive}}
	verdict, _, _, _, _, _, _ := vexVerdict(c)
	if verdict != string(domain.VerdictInconclusive) {
		t.Fatalf("inconclusive terminal: got %q", verdict)
	}
	// Any other terminal without a verdict is a failure, not a safe answer.
	c = &domain.AnalysisCase{Workflow: domain.WorkflowStatus{State: domain.StateFailed}}
	verdict, _, _, _, _, _, _ = vexVerdict(c)
	if verdict != "" {
		t.Fatalf("failed terminal: got %q, want empty", verdict)
	}
}

func TestVexVerdict_GroundingFalsifier(t *testing.T) {
	cond := domain.ConditionID("C-REACH")
	c := &domain.AnalysisCase{
		Verdict: &domain.VerdictResult{
			Verdict:      domain.VerdictNoExploitPathFound,
			ConditionIDs: []domain.ConditionID{cond},
		},
		Claims: []domain.Claim{{
			ConditionID: cond,
			Falsifier:   domain.FalsifierLocusPackageAbsent,
			EvidenceIDs: []domain.EvidenceID{"EV-1"},
		}},
	}
	verdict, _, conds, falsifier, _, evids, _ := vexVerdict(c)
	if verdict != string(domain.VerdictNoExploitPathFound) {
		t.Fatalf("verdict %q", verdict)
	}
	if falsifier != domain.FalsifierLocusPackageAbsent {
		t.Fatalf("falsifier %q", falsifier)
	}
	if len(conds) != 1 || conds[0] != string(cond) {
		t.Fatalf("conditions %v", conds)
	}
	if len(evids) != 1 || evids[0] != "EV-1" {
		t.Fatalf("evidence %v", evids)
	}
}

// TestVexVerdict fixes the verdict the benchmark publishes per requested
// outcome: a FAILED analysis publishes none, an external dependency abstains
// with its named fact, and a composed positive reports its witness's grounding
// claim rather than the primary record's.
func TestVexVerdict(t *testing.T) {
	task := vexbench.Task{
		TaskID: "vex-verdict", CVEID: consumersCVE,
		GroundTruth: "exploitable", GroundTruthCategory: "vulnerable",
	}

	t.Run("a failed requested assessment publishes no verdict", func(t *testing.T) {
		c := consumersCVEFailed(t)
		if verdict, _, _, _, _, _, _ := vexVerdict(c); verdict != "" {
			t.Fatalf("record-level verdict = %q; a FAILED result carries none", verdict)
		}
		var env vexEnvelope
		prediction := vexOutcomeFromView(consumersProject(t, c), &env, task)
		if prediction.Verdict != "" || !prediction.Failed {
			t.Fatalf("prediction = %+v", prediction)
		}
		if env.Verdict != "" || env.AssessmentOutcome != "FAILED" {
			t.Fatalf("envelope = %+v", env)
		}
		if got := vexbench.Classify(task, prediction); got != vexbench.OutcomeFailed {
			t.Fatalf("scoring outcome = %q; want failed", got)
		}
	})

	t.Run("an external dependency abstains with its named fact", func(t *testing.T) {
		// An exact-record task: its ground truth is record-scoped, so the
		// exact request is the legitimate answer shape.
		exactTask := vexbench.Task{
			TaskID: "vex-verdict-external", CVEID: consumersPrimary,
			GroundTruth: "exploitable", GroundTruthCategory: "vulnerable",
		}
		var env vexEnvelope
		prediction := vexOutcomeFromView(consumersProject(t, consumersExternalCase(t)), &env, exactTask)
		if prediction.Verdict != "INCONCLUSIVE" || prediction.Failed {
			t.Fatalf("prediction = %+v", prediction)
		}
		if len(env.ExternalDependencies) != 1 ||
			!strings.Contains(env.ExternalDependencies[0], "release toolchain") {
			t.Fatalf("external dependency = %+v", env.ExternalDependencies)
		}
		if got := vexbench.Classify(exactTask, prediction); got != vexbench.OutcomeAbstain {
			t.Fatalf("scoring outcome = %q; want abstain", got)
		}
	})

	t.Run("a composed positive reports its witness's grounding", func(t *testing.T) {
		var env vexEnvelope
		prediction := vexOutcomeFromView(consumersProject(t, consumersCVEPositive(t)), &env, task)
		if prediction.Verdict != "EXPLOITABLE" || prediction.Category != vexbench.CategoryVulnerable {
			t.Fatalf("prediction = %+v", prediction)
		}
		if len(env.GroundingCond) != 1 || env.GroundingCond[0] != "C-API" {
			t.Fatalf("grounding conditions = %+v", env.GroundingCond)
		}
		if len(env.EvidenceIDs) != 1 || env.EvidenceIDs[0] != "EV-API" {
			t.Fatalf("grounding evidence = %+v", env.EvidenceIDs)
		}
		if env.Profile != string(domain.ProfileZeroTrust) || env.Build == "" {
			t.Fatalf("envelope provenance = %+v", env)
		}
		if len(env.Claims) != 1 || env.Claims[0].ConditionID != "C-API" {
			t.Fatalf("envelope claims = %+v", env.Claims)
		}
	})
}

// The benchmark envelope must carry the claim and evidence references that
// explain an admission decision (including a refused negative), so
// calibration can inspect reasons rather than only the final label.
func TestVexArtifactRetainsClaimAdmissionRefs(t *testing.T) {
	c := &domain.AnalysisCase{Claims: []domain.Claim{{
		ID:             "CL-C-REACH",
		ConditionID:    "C-REACH",
		Result:         domain.ClaimUnknown,
		Falsifier:      domain.FalsifierNoModuleUsage,
		FalsifierBasis: "source-scan",
		Explanation:    "no module usage in the measured build",
		EvidenceIDs:    []domain.EvidenceID{"EV-SCAN-1"},
		Limitations:    []string{"negative verification for C-REACH refused: no product target"},
		NegativeVerification: &domain.NegativeVerification{
			Status: domain.NegativeVerified,
			Notes:  "measurement did not match the analyzed build",
		},
	}}}

	env := vexEnvelope{Claims: vexClaims(c)}
	data, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"claims"`,
		`"condition_id":"C-REACH"`,
		`"result":"UNKNOWN"`,
		`"falsifier":"no-module-usage"`,
		`"negative_verification":"VERIFIED"`,
		`"negative_verification_notes":"measurement did not match the analyzed build"`,
		`"evidence_ids":["EV-SCAN-1"]`,
		"no product target",
	} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("benchmark envelope lacks %q: %s", want, data)
		}
	}
}

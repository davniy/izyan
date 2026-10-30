package triage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
)

func humanBranchFixture() HumanBranchInput {
	a := goodAssessment()
	a.EnvironmentVariables = []EnvironmentVariableProposal{{ID: VariableDeploymentPerimeter}}
	for _, value := range []string{"cluster-internal", "public", EnvironmentUnknown} {
		action := a.ProposedAction
		action.Kind = HumanActionKeepOpen
		if value == "cluster-internal" { action.Kind = HumanActionAcceptEnvironmentalMitigation }
		a.ConditionalActions = append(a.ConditionalActions, ConditionalActionProposal{Assignments: map[string]string{VariableDeploymentPerimeter: value}, Judgment: LLMJudgment{Verdict: VerdictInconclusive, Summary: "prepared " + value}, Action: action})
	}
	a.ProposedAction.Kind = HumanActionKeepOpen
	s0 := goodStage0()
	s0.Materials.Deploy = nil
	return HumanBranchInput{SupportInput: SupportInput{Stage0: s0, Assessment: a, Validation: completeValidation()}}
}

func TestHumanBranchUniverseIsComplete(t *testing.T) {
	in := humanBranchFixture()
	p, err := BuildHumanReviewPlan(in)
	if err != nil { t.Fatal(err) }
	if len(p.Branches) != 3 || p.Readiness != string(HumanBranchComplete) { t.Fatalf("plan: %+v", p) }
	for _, b := range p.Branches { if b.Status != HumanBranchComplete { t.Fatalf("branch: %+v", b) } }
	in.Assessment.ConditionalActions = in.Assessment.ConditionalActions[:2]
	p, err = BuildHumanReviewPlan(in)
	if err != nil || p.Readiness != string(HumanBranchNotDecisionReady) || p.Branches[2].Action.Kind != HumanActionKeepOpen { t.Fatalf("missing unknown: %+v %v", p, err) }
	in = humanBranchFixture()
	in.Assessment.ConditionalActions[0].Assignments[VariableDeploymentPerimeter] = "invented"
	if _, err := BuildHumanReviewPlan(in); err == nil { t.Fatal("invented value accepted") }
}

func TestHumanBranchesDoNotShareEnvironmentPremises(t *testing.T) {
	p, err := BuildHumanReviewPlan(humanBranchFixture())
	if err != nil { t.Fatal(err) }
	seen := map[string]bool{}
	for _, b := range p.Branches {
		found := false
		for _, pr := range b.Premises {
			if !strings.HasPrefix(pr.ClaimID, "environment:") { continue }
			found = true
			if seen[pr.ClaimID] { t.Fatal("borrowed environment premise") }
			seen[pr.ClaimID] = true
			if pr.Owner != "human reviewer" || pr.Basis != PremiseAssumed && pr.Basis != PremiseUnresolved { t.Fatalf("authority leak: %+v", pr) }
		}
		if !found || b.Support.Level == SupportLevelProvedWithinScope || b.Support.Level == SupportLevelSubstantiated { t.Fatalf("environment support: %+v", b) }
	}
}

func TestEnvironmentQuestionsAreVerbatimAndBounded(t *testing.T) {
	in := humanBranchFixture()
	quote := "Exploitation requires the network listener option to be enabled"
	raw := []byte(quote)
	in.Stage0.Investigation.Records = []CapturedRecord{{RecordID: "CVE-2099-0001", Raw: raw, SHA256: hashBytes(raw), Size: int64(len(raw))}}
	in.Assessment.EnvironmentVariables = []EnvironmentVariableProposal{{ID: VariableAdvisoryPrecondition, RecordID: "CVE-2099-0001", RecordSHA256: hashBytes(raw), Quote: quote}}
	vars, err := environmentVariables(in.SupportInput)
	if err != nil || len(vars) != 1 || !strings.Contains(vars[0].Question, quote) || len(vars[0].AllowedValues) != 3 || !vars[0].Required { t.Fatalf("vars: %+v %v", vars, err) }
	in.Assessment.EnvironmentVariables[0].Quote += " invented"
	if _, err := environmentVariables(in.SupportInput); err == nil { t.Fatal("unrecorded quote accepted") }
	in.Assessment.EnvironmentVariables = []EnvironmentVariableProposal{{ID: "peer_trust"}}
	if _, err := BuildHumanReviewPlan(in); err == nil { t.Fatal("unsupported dimension accepted") }
}

func TestHumanReviewFirstScreenBounds(t *testing.T) {
	in := humanBranchFixture()
	for i := range 7 {
		c := in.Assessment.Claims[0]
		c.ID = fmt.Sprintf("extra-%d", i)
		in.Assessment.Claims = append(in.Assessment.Claims, c)
		in.Assessment.ProposedAction.DecisiveClaimIDs = append(in.Assessment.ProposedAction.DecisiveClaimIDs, c.ID)
		for j := range in.Assessment.ConditionalActions {
			in.Assessment.ConditionalActions[j].Action.DecisiveClaimIDs = append(append([]string(nil), in.Assessment.ConditionalActions[j].Action.DecisiveClaimIDs...), c.ID)
		}
	}
	p, err := BuildHumanReviewPlan(in)
	if err != nil { t.Fatal(err) }
	if p.Readiness != string(HumanBranchNotDecisionReady) || len(p.MandatoryPremiseIDs) <= 7 { t.Fatalf("premises trimmed: %+v", p) }
	for _, b := range p.Branches { if b.Action.Kind != HumanActionKeepOpen { t.Fatalf("not conservative: %+v", b) } }
}

func TestEnvironmentMitigationIsContextual(t *testing.T) {
	in := humanBranchFixture()
	p, err := (Composer{}).Compose(context.Background(), in.Stage0, in.Assessment, in.Validation, nil)
	if err != nil { t.Fatal(err) }
	before := p.MachineDisposition
	in.Assessment.ConditionalActions[0].Judgment.Summary = "different opinion"
	other, err := (Composer{}).Compose(context.Background(), in.Stage0, in.Assessment, in.Validation, nil)
	if err != nil { t.Fatal(err) }
	if projectionHash(before) != projectionHash(other.MachineDisposition) { t.Fatal("branch opinion altered machine authority") }
	in.Assessment.ConditionalActions[0].Action.Kind = HumanActionClose
	if _, err := BuildHumanReviewPlan(in); err == nil { t.Fatal("environment close accepted") }
	in = humanBranchFixture()
	in.Stage0.Materials.Deploy = &DeployFacts{FactCount: 1, SHA256: strings.Repeat("a", 64), Perimeter: domain.PerimeterPublic}
	plan, err := BuildHumanReviewPlan(in)
	if err != nil || plan.Branches[0].Status != HumanBranchContradicted || plan.Branches[0].Action.Kind != HumanActionKeepOpen { t.Fatalf("conflict: %+v %v", plan, err) }
}

func TestUnconditionalProofDoesNotAskEnvironment(t *testing.T) {
	in := provedWithinScopeInput(t)
	in.Assessment.EnvironmentVariables = []EnvironmentVariableProposal{{ID: "unsupported-but-irrelevant"}}
	p, err := BuildHumanReviewPlan(HumanBranchInput{SupportInput: in})
	if err != nil || len(p.Variables) != 0 || len(p.Branches) != 1 || p.Branches[0].Support.Level != SupportLevelProvedWithinScope { t.Fatalf("proof: %+v %v", p, err) }
}

func TestHumanBranchStrictIngress(t *testing.T) {
	in := humanBranchFixture()
	in.Assessment.SchemaVersion = AssessmentSchemaVersion
	in.Assessment.Audit = nil
	in.Assessment.FindingID = in.Stage0.Input.Finding.FindingID
	b, _ := json.Marshal(in.Assessment)
	if _, err := DecodeAssessment(string(b), in.Assessment.FindingID); err != nil { t.Fatal(err) }
	bad := strings.Replace(string(b), `"id":"deployment_perimeter"`, `"id":"deployment_perimeter","value":"cluster-internal"`, 1)
	if _, err := DecodeAssessment(bad, in.Assessment.FindingID); err == nil { t.Fatal("model-owned answer accepted") }
}

func TestHumanBranchReplayPreparedPlan(t *testing.T) {
	f := recordDecisionRun(t, newReplayRepo(t), t.TempDir(), replayClockA, func(a *Assessment) {
		a.EnvironmentVariables = []EnvironmentVariableProposal{{ID: VariableDeploymentPerimeter}}
		for _, value := range []string{"cluster-internal", "public", EnvironmentUnknown} {
			action := a.ProposedAction
			action.Kind = HumanActionKeepOpen
			if value == "cluster-internal" { action.Kind = HumanActionAcceptEnvironmentalMitigation }
			a.ConditionalActions = append(a.ConditionalActions, ConditionalActionProposal{Assignments: map[string]string{VariableDeploymentPerimeter: value}, Judgment: LLMJudgment{Verdict: VerdictInconclusive}, Action: action})
		}
		a.ProposedAction.Kind = HumanActionKeepOpen
	})
	rep, err := PrepareReplay(context.Background(), f.runDir)
	if err != nil { t.Fatal(err) }
	if rep.Decision == nil || len(rep.Decision.HumanReviewPlan.Branches) != 3 { t.Fatal("prepared branches lost in replay") }
	card := string(RenderDecisionMarkdown(*rep.Decision))
	for _, text := range []string{"Which perimeter posture does the analyzed deployment run in?", "ACCEPT_ENVIRONMENTAL_MITIGATION", "unknown", "Accept or Reject"} {
		if !strings.Contains(card, text) { t.Fatalf("prepared card missing %q", text) }
	}
	dir := copyRunDir(t, f.runDir)
	rewriteDecision(t, dir, func(p *DecisionPackage) { p.HumanReviewPlan.Branches[0].Action.Rationale = "changed conditional opinion" })
	if _, err := PrepareReplay(context.Background(), dir); err == nil || !strings.Contains(err.Error(), "human review plan drift") { t.Fatalf("prepared branch drift accepted: %v", err) }
}

func TestHumanBranchCartesianUniverseAndBuildScope(t *testing.T) {
	in := humanBranchFixture()
	in.Stage0.BuildTarget = &domain.ProductTarget{GOOS: "linux", GOARCH: "amd64", Source: domain.ProductTargetSourceOperatorDeclared, Scope: domain.ProductTargetScopeOperator}
	in.Stage0.Snapshot.Files = []SnapshotFile{{Path: "vendor/modules.txt"}}
	in.Assessment.EnvironmentVariables = append([]EnvironmentVariableProposal{{ID: VariableBuildVariant}}, in.Assessment.EnvironmentVariables...)
	original := in.Assessment.ConditionalActions
	in.Assessment.ConditionalActions = nil
	for _, build := range []string{EnvironmentUnknown, "other"} {
		for _, proposal := range original {
			proposal.Assignments = cloneAssignments(proposal.Assignments)
			proposal.Assignments[VariableBuildVariant] = build
			proposal.Action.Kind = HumanActionKeepOpen
			in.Assessment.ConditionalActions = append(in.Assessment.ConditionalActions, proposal)
		}
	}
	p, err := BuildHumanReviewPlan(in)
	if err != nil { t.Fatal(err) }
	if len(p.Branches) != 6 || p.Variables[0].Required || p.Variables[0].AllowedValues[0] != EnvironmentUnknown { t.Fatalf("unrecorded effective build universe: %+v", p) }
	if err := validateHumanReviewPlan(p); err != nil { t.Fatal(err) }
	p.Branches[0].Premises[0].ClaimID = "environment:borrowed:deployment_perimeter"
	if err := validateHumanReviewPlan(p); err == nil { t.Fatal("foreign environment premise accepted") }
}

func TestHumanReviewFirstScreenQuestionOverflow(t *testing.T) {
	in := humanBranchFixture()
	in.Assessment.EnvironmentVariables = []EnvironmentVariableProposal{{ID: VariableDeploymentPerimeter}, {ID: VariableAdvisoryPrecondition}, {ID: "peer_trust"}}
	p, err := BuildHumanReviewPlan(in)
	if err != nil || p.Readiness != string(HumanBranchNotDecisionReady) || p.Branches[0].Action.Kind != HumanActionKeepOpen { t.Fatalf("question overflow: %+v %v", p, err) }
	if err := validateHumanReviewPlan(p); err != nil { t.Fatal(err) }
}

// Exercise the public composition and artifact APIs offline, including the
// persisted package, first-screen card, stdout and append-only audit consumer.
func TestHumanReviewFirstScreenPublishedAPISmoke(t *testing.T) {
	for _, count := range []int{7, 8} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			ctx := context.Background()
			in, manifest, run, assessment := writeFixture(t)
			for i := 1; i < count; i++ {
				claim := assessment.Claims[0]
				claim.ID = fmt.Sprintf("extra-%d", i)
				assessment.Claims = append(assessment.Claims, claim)
				assessment.ProposedAction.DecisiveClaimIDs = append(assessment.ProposedAction.DecisiveClaimIDs, claim.ID)
			}
			run.Assessment = assessment
			var stdout bytes.Buffer
			writer := ArtifactWriter{Clock: artifactClock(), Stdout: &stdout}
			out := t.TempDir()
			art, err := writer.Write(ctx, out, in, manifest, run, assessment, nil, nil)
			if err != nil { t.Fatal(err) }
			var stored Assessment
			if err := json.Unmarshal(mustRead(t, art.AssessmentPath), &stored); err != nil { t.Fatal(err) }
			pkg, err := (Composer{}).Compose(ctx, decisionStage0(in, manifest), stored, *stored.FactValidationDetail, nil)
			if err != nil { t.Fatal(err) }
			wantAction, wantReadiness := HumanActionClose, string(HumanBranchComplete)
			if count > MaxMandatoryPremises { wantAction, wantReadiness = HumanActionKeepOpen, string(HumanBranchNotDecisionReady) }
			if pkg.ProposedAction.Kind != wantAction || pkg.HumanReviewPlan.Readiness != wantReadiness || len(pkg.Premises) != count {
				t.Fatalf("published axes or untrimmed premises: %+v", pkg)
			}
			if stored.ProposedAction.Kind != HumanActionClose || pkg.Judgment.Verdict != stored.Verdict { t.Fatal("raw model opinion was rewritten") }
			if err := writer.WriteDecision(ctx, out, pkg); err != nil { t.Fatal(err) }
			var published DecisionPackage
			if err := json.Unmarshal(mustRead(t, filepath.Join(art.RootDir, "decision.json")), &published); err != nil { t.Fatal(err) }
			if err := published.Validate(); err != nil { t.Fatal(err) }
			if published.ProposedAction.Kind != wantAction || published.HumanReviewPlan.Readiness != wantReadiness { t.Fatal("decision.json contradicts bounded plan") }
			if !strings.Contains(stdout.String(), "action="+string(wantAction)) || !strings.Contains(stdout.String(), "readiness="+wantReadiness) { t.Fatalf("stdout: %s", stdout.String()) }
			card := string(mustRead(t, filepath.Join(art.RootDir, "decision.md")))
			if !strings.Contains(card, string(wantAction)) { t.Fatalf("card: %s", card) }
			var found bool
			for _, line := range bytes.Split(mustRead(t, art.AuditPath), []byte("\n")) {
				if len(line) == 0 { continue }
				var event AuditEvent
				if err := json.Unmarshal(line, &event); err != nil { t.Fatal(err) }
				if event.Decision == nil { continue }
				found = true
				if event.Decision.HumanAction.Kind != string(wantAction) || event.Decision.HumanReviewReadiness != wantReadiness { t.Fatalf("audit contradicts package: %+v", event.Decision) }
			}
			if !found { t.Fatal("decision audit missing") }
			if count > MaxMandatoryPremises {
				published.ProposedAction = stored.ProposedAction
				if err := published.Validate(); err == nil { t.Fatal("validator accepted unready unconditional CLOSE") }
			}
		})
	}
}

func TestEnvironmentQuestionsBuildModeDoesNotFollowFiles(t *testing.T) {
	for _, tc := range []struct { name, filename, ambient string }{
		{"GOWORK_off", "go.work", "off"},
		{"ignored_vendor", "vendor/modules.txt", "-mod=mod"},
		{"no_recorded_configuration", "go.mod", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Neither the process environment nor source availability records the
			// configuration that produced the analyzed artifact.
			if tc.filename == "go.work" { t.Setenv("GOWORK", tc.ambient) } else { t.Setenv("GOFLAGS", tc.ambient) }
			in := humanBranchFixture()
			in.Stage0.BuildTarget = &domain.ProductTarget{GOOS: "linux", GOARCH: "amd64", Source: domain.ProductTargetSourceOperatorDeclared, Scope: domain.ProductTargetScopeOperator}
			in.Stage0.Snapshot.Files = []SnapshotFile{{Path: tc.filename}}
			in.Assessment.EnvironmentVariables = []EnvironmentVariableProposal{{ID: VariableBuildVariant}}
			in.Assessment.ConditionalActions = nil
			for _, value := range []string{EnvironmentUnknown, "other"} {
				action := in.Assessment.ProposedAction
				action.Kind = HumanActionKeepOpen
				in.Assessment.ConditionalActions = append(in.Assessment.ConditionalActions, ConditionalActionProposal{Assignments: map[string]string{VariableBuildVariant: value}, Judgment: LLMJudgment{Verdict: VerdictInconclusive}, Action: action})
			}
			pkg, err := (Composer{}).Compose(context.Background(), in.Stage0, in.Assessment, in.Validation, nil)
			if err != nil { t.Fatal(err) }
			if err := pkg.Validate(); err != nil { t.Fatal(err) }
			for _, branch := range pkg.HumanReviewPlan.Branches {
				if branch.Action.Kind != HumanActionKeepOpen || branch.Support.Level == SupportLevelProvedWithinScope { t.Fatalf("invented build authority: %+v", branch) }
				if branch.Assignments[VariableBuildVariant] == "module" || branch.Assignments[VariableBuildVariant] == "workspace" || branch.Assignments[VariableBuildVariant] == "vendor" { t.Fatalf("filename selected build mode: %+v", branch) }
			}
			// A model cannot turn the unknown recorded mode into mitigation.
			in.Assessment.ConditionalActions[0].Action.Kind = HumanActionAcceptEnvironmentalMitigation
			if _, err := BuildHumanReviewPlan(in); err == nil { t.Fatal("unknown build mode admitted mitigation") }
		})
	}
}

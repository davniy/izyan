package triage

import (
	"encoding/json"
	"strings"
	"testing"
)

// validDecisionPackage is the minimal decision-package.v3 that satisfies
// every axis: a judgment, a concrete proposed action, the derived premise
// closure with its support and a machine disposition.
func validDecisionPackage() DecisionPackage {
	p := DecisionPackage{
		SchemaVersion: DecisionPackageSchemaVersion,
		RunID:         "run-example",
		FindingID:     "finding-example",
		ExecutionMode: "ci",
		Scope: DecisionScope{
			SnapshotHash: "snap",
			RequestedIDs: []string{"CVE-2099-0001"},
			Records:      []AdvisoryRecordRef{{ID: "CVE-2099-0001", SHA256: "advisory-digest"}},
			Boundary:     DecisionBoundaryExactRecords,
		},
		Judgment: LLMJudgment{Verdict: VerdictNotExploitable, Summary: "the module is absent"},
		ProposedAction: HumanAction{
			Kind:             HumanActionClose,
			Instruction:      "close the ticket",
			Rationale:        "the decisive premise establishes the module is absent",
			Scope:            "the captured build",
			DecisiveClaimIDs: []string{"c1"},
			ReconsiderWhen:   []string{"the module appears in the captured build"},
		},
		Premises: []DecisionPremise{{
			ClaimID:   "c1",
			Statement: "module example.org/library is not in the build graph",
			Basis:     PremiseMeasured,
			Subject:   "example.org/library build-graph membership",
			Scope:     "recorded module graph",
		}},
		Support: DecisionSupport{Level: SupportLevelSubstantiated, DecisiveClaimIDs: []string{"c1"}},
		TechnicalAssessment: TechnicalAssessment{
			Status:         TechStatusReady,
			FactValidation: string(ValidationComplete),
		},
		MachineDisposition: MachineDisposition{
			Recommendation: RecommendationUnchanged,
			Baseline: &Baseline{
				Severity: "HIGH", Priority: "P1",
				Disposition: RecommendationUnchanged, Source: "advisory",
			},
			RecommendedProfile: ProfileApplication{
				ID: "default",
				Applicability: Condition{
					ID: "profile", Predicate: Predicate{Op: "exists", Path: "profile"},
					Status: ConditionSatisfied, Scope: "profile", Effect: "select",
				},
			},
			Rationale:  Rationale{Summary: "no rule permitted a reduction"},
			Automation: AutomationWarn,
		},
	}
	p.HumanReviewPlan = &HumanReviewPlan{Readiness: string(HumanBranchComplete), MandatoryPremiseIDs: []string{"c1"}, Branches: []HumanDecisionBranch{{ID: "unconditional", Assignments: map[string]string{}, Judgment: p.Judgment, Action: p.ProposedAction, Premises: p.Premises, Support: p.Support, Status: HumanBranchComplete}}}
	return p
}

func TestDecisionPackageStrictValidation(t *testing.T) {
	p := validDecisionPackage()
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateDecisionPackageJSON(data); err != nil {
		t.Fatalf("valid package rejected: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	raw["unknown"] = true
	data, _ = json.Marshal(raw)
	if _, err := ValidateDecisionPackageJSON(data); err == nil {
		t.Fatal("unknown field accepted")
	}
}

// TestDecisionPackageAxisConsistency pins the cross-axis contract: the
// package cannot claim a support level for premises it does not carry, a
// decisive claim the premise set lacks, an unrecorded proof, an absent
// baseline reduction or an unknown automation value. A human action never
// satisfies a machine prerequisite.
func TestDecisionPackageAxisConsistency(t *testing.T) {
	cases := map[string]struct {
		mutate func(*DecisionPackage)
		want   string
	}{
		"empty premises": {
			mutate: func(p *DecisionPackage) { p.Premises = nil },
			want:   "no derived decisive premise",
		},
		"decisive claim outside the premise set": {
			mutate: func(p *DecisionPackage) { p.ProposedAction.DecisiveClaimIDs = []string{"c9"} },
			want:   "premise set does not carry",
		},
		"support closure disagrees with the premises": {
			mutate: func(p *DecisionPackage) { p.Support.DecisiveClaimIDs = nil },
			want:   "support decisive claim set",
		},
		"unrecorded proof": {
			mutate: func(p *DecisionPackage) { p.Support.ProofIDs = []string{"fp-9"} },
			want:   "the package does not carry",
		},
		"proved scope without a proof": {
			mutate: func(p *DecisionPackage) { p.Support.Level = SupportLevelProvedWithinScope },
			want:   "requires an admitted proof",
		},
		"invalid judgment verdict": {
			mutate: func(p *DecisionPackage) { p.Judgment.Verdict = "SOME_VERDICT" },
			want:   "invalid judgment verdict",
		},
		"invalid scope boundary": {
			mutate: func(p *DecisionPackage) { p.Scope.Boundary = "CVE_WIDE" },
			want:   "invalid boundary",
		},
		"record without a digest": {
			mutate: func(p *DecisionPackage) { p.Scope.Records[0].SHA256 = "" },
			want:   "id and sha256 are required",
		},
		"invalid automation": {
			mutate: func(p *DecisionPackage) { p.MachineDisposition.Automation = "" },
			want:   "invalid automation",
		},
		"invalid baseline": {
			mutate: func(p *DecisionPackage) { p.MachineDisposition.Baseline.Disposition = "TAMPERED" },
			want:   "invalid baseline",
		},
		"invalid fact validation": {
			mutate: func(p *DecisionPackage) { p.TechnicalAssessment.FactValidation = "GREEN" },
			want:   "invalid fact_validation",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p := validDecisionPackage()
			tc.mutate(&p)
			err := p.Validate()
			if err == nil {
				t.Fatalf("%s accepted", name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not name %q", err, tc.want)
			}
		})
	}
}

func TestDecisionEnumsAndConditions(t *testing.T) {
	var p DecisionPackage
	if err := json.Unmarshal([]byte(`{"machine_disposition":{"recommendation":"BAD"}}`), &p); err == nil {
		t.Fatal("invalid recommendation accepted")
	}
	if err := json.Unmarshal([]byte(`{"machine_disposition":{"recommendation":"UNCHANGED"}}`), &p); err != nil {
		t.Fatal(err)
	}
	if err := p.Validate(); err == nil {
		t.Fatal("incomplete package accepted")
	}
	// The retired CI-only human_decision field is not part of v3 and is
	// rejected rather than ignored.
	if err := json.Unmarshal([]byte(`{"human_decision":"human"}`), &p); err == nil {
		t.Fatal("decision-package.v3 must reject the removed human_decision field")
	}
}

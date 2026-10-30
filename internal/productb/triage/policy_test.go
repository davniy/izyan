package triage

import (
	"encoding/json"
	"testing"
)

// machineDisposition builds a machine disposition for the automation
// matrix: a recommendation with optional demotions, blocking assumptions and
// divergence.
func machineDisposition(rec Recommendation, mut func(*MachineDisposition)) MachineDisposition {
	m := MachineDisposition{
		Recommendation: rec,
		RecommendedProfile: ProfileApplication{ID: "default", Applicability: Condition{
			ID: "profile", Predicate: Predicate{Op: "exists", Path: "profile"},
			Status: ConditionSatisfied, Scope: "profile", Effect: "select",
		}},
		Automation: AutomationWarn,
	}
	if mut != nil {
		mut(&m)
	}
	return m
}

func blockingAssumption() Condition {
	return Condition{
		ID: "assumption-rule-x", Predicate: Predicate{Op: "exists", Path: "rule.x"},
		Status: ConditionUnknown, Scope: "rule", Effect: "blocks_lowered_and_dismissed",
	}
}

// TestEvaluateMachineAutomation pins the machine policy matrix: only an
// admitted machine reduction on a complete fact basis may ALLOW, a valid
// package without a reduction WARNs, and every invalid or failed machine
// prerequisite BLOCKs. No human field is an input.
func TestEvaluateMachineAutomation(t *testing.T) {
	cases := []struct {
		name       string
		machine    MachineDisposition
		validation FactValidationStatus
		want       AutomationStatus
	}{
		{"admitted dismissal allows",
			machineDisposition(RecommendationDismissed, nil), ValidationComplete, AutomationAllow},
		{"admitted lowering allows",
			machineDisposition(RecommendationLowered, nil), ValidationComplete, AutomationAllow},
		{"unchanged warns",
			machineDisposition(RecommendationUnchanged, nil), ValidationComplete, AutomationWarn},
		{"unchanged with partial validation still warns",
			machineDisposition(RecommendationUnchanged, nil), ValidationPartial, AutomationWarn},
		{"demoted reduction blocks",
			machineDisposition(RecommendationDismissed, func(m *MachineDisposition) {
				m.Demotions = []string{"rule x permitted DISMISSED; demoted to UNCHANGED"}
			}), ValidationComplete, AutomationBlock},
		{"open blocking assumption blocks",
			machineDisposition(RecommendationDismissed, func(m *MachineDisposition) {
				m.ResidualAssumptions = []Condition{blockingAssumption()}
			}), ValidationComplete, AutomationBlock},
		{"divergent arbitration blocks",
			machineDisposition(RecommendationDismissed, func(m *MachineDisposition) {
				m.Arbitration = ArbitrationDivergeHuman
			}), ValidationComplete, AutomationBlock},
		{"partial fact basis withholds allow",
			machineDisposition(RecommendationDismissed, nil), ValidationPartial, AutomationWarn},
		{"failed validation blocks",
			machineDisposition(RecommendationUnchanged, nil), ValidationFailed, AutomationBlock},
		{"empty validation blocks",
			machineDisposition(RecommendationUnchanged, nil), "", AutomationBlock},
		{"unknown validation blocks",
			machineDisposition(RecommendationUnchanged, nil), "GREEN", AutomationBlock},
		{"invalid recommendation blocks",
			machineDisposition(Recommendation("BOGUS"), nil), ValidationComplete, AutomationBlock},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := EvaluateMachineAutomation(tc.machine, tc.validation); got != tc.want {
				t.Fatalf("EvaluateMachineAutomation = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestMachineAutomationIgnoresHumanAxes pins the authority boundary
// structurally: EvaluateMachineAutomation consumes only the machine
// disposition and the fact-validation status, so a proposed human action,
// a high support level or a human acceptance cannot raise the outcome.
func TestMachineAutomationIgnoresHumanAxes(t *testing.T) {
	m := machineDisposition(RecommendationUnchanged, nil)
	if got := EvaluateMachineAutomation(m, ValidationComplete); got != AutomationWarn {
		t.Fatalf("automation = %s, want WARN", got)
	}
	pkg := validDecisionPackage()
	pkg.MachineDisposition = m
	pkg.ProposedAction = HumanAction{
		Kind: HumanActionClose, Instruction: "close it", Rationale: "because",
		Scope: "scope", DecisiveClaimIDs: []string{"c1"}, ReconsiderWhen: []string{"never"},
	}
	pkg.Support = DecisionSupport{Level: SupportLevelProvedWithinScope, DecisiveClaimIDs: []string{"c1"}}
	if got := EvaluateMachineAutomation(pkg.MachineDisposition, ValidationComplete); got != AutomationWarn {
		t.Fatalf("a human proposal raised the machine automation to %s", got)
	}
	if pkg.MachineDisposition.Recommendation != RecommendationUnchanged {
		t.Fatal("a human proposal rewrote the machine recommendation")
	}
}

// pkgFixture builds the minimal decision-package shape the §2.3 thresholds
// read: the machine recommendation, the human support level, unknowns,
// premises, machine residual assumptions, conditional profiles and
// demotions.
func pkgFixture(mut func(*DecisionPackage)) DecisionPackage {
	p := DecisionPackage{
		Support:            DecisionSupport{Level: SupportLevelSubstantiated},
		MachineDisposition: MachineDisposition{Recommendation: RecommendationUnchanged},
	}
	if mut != nil {
		mut(&p)
	}
	return p
}

func TestPackagePolicyHit(t *testing.T) {
	lowered := pkgFixture(func(p *DecisionPackage) { p.MachineDisposition.Recommendation = RecommendationLowered })
	limited := pkgFixture(func(p *DecisionPackage) { p.Support.Level = SupportLevelLimited })
	insufficient := pkgFixture(func(p *DecisionPackage) { p.Support.Level = SupportLevelInsufficient })
	strong := pkgFixture(func(p *DecisionPackage) { p.Support.Level = SupportLevelProvedWithinScope })
	conditional := pkgFixture(func(p *DecisionPackage) {
		p.MachineDisposition.ConditionalProfiles = []ConditionalProfile{{
			Profile: "internal-service",
			Applicability: Condition{
				ID: "profile-applicability-internal-service", Status: ConditionUnknown,
				Scope: "profile", Effect: "conditional_applicability",
			},
			ExpectedDisposition: RecommendationLowered,
		}}
	})
	unknownAssumption := pkgFixture(func(p *DecisionPackage) {
		p.MachineDisposition.ResidualAssumptions = []Condition{blockingAssumption()}
	})
	humanAssumption := pkgFixture(func(p *DecisionPackage) {
		p.Premises = []DecisionPremise{{
			ClaimID: "c1", Statement: "the deployment is internal", Basis: PremiseAssumed,
			Subject: "deployment", Scope: "deployment", Owner: "platform-team",
		}}
	})
	humanUnknown := pkgFixture(func(p *DecisionPackage) {
		p.Unknowns = []Unknown{{ID: "u1", Description: "runtime configuration not captured"}}
	})
	demoted := pkgFixture(func(p *DecisionPackage) {
		p.MachineDisposition.Demotions = []string{"rule x permitted LOWERED; demoted to UNCHANGED: check C03 is UNAVAILABLE"}
	})
	cases := []struct {
		name string
		pkg  DecisionPackage
		on   FailOn
		want bool
	}{
		{"unchanged hits UNCHANGED", pkgFixture(nil), FailOnUnchanged, true},
		{"unchanged ignores LOWERED", lowered, FailOnUnchanged, false},
		{"unchanged ignores DISMISSED", pkgFixture(func(p *DecisionPackage) {
			p.MachineDisposition.Recommendation = RecommendationDismissed
		}), FailOnUnchanged, false},
		{"low-support hits LIMITED", limited, FailOnLowSupport, true},
		{"low-support hits INSUFFICIENT", insufficient, FailOnLowSupport, true},
		{"low-support ignores SUBSTANTIATED", pkgFixture(nil), FailOnLowSupport, false},
		{"low-support ignores PROVED_WITHIN_SCOPE", strong, FailOnLowSupport, false},
		{"conditional hits active conditional profile", conditional, FailOnConditional, true},
		{"conditional hits unknown machine assumption", unknownAssumption, FailOnConditional, true},
		{"conditional hits a human assumption premise", humanAssumption, FailOnConditional, true},
		{"conditional hits an open human unknown", humanUnknown, FailOnConditional, true},
		{"conditional ignores satisfied-only", pkgFixture(func(p *DecisionPackage) {
			p.MachineDisposition.ResidualAssumptions = []Condition{{
				ID: "a", Status: ConditionSatisfied, Scope: "fact", Effect: "informational",
			}}
		}), FailOnConditional, false},
		{"conditional ignores plain package", pkgFixture(nil), FailOnConditional, false},
		{"unverified-disposition hits demotion", demoted, FailOnUnverifiedDisposition, true},
		{"unverified-disposition ignores clean package", pkgFixture(nil), FailOnUnverifiedDisposition, false},
		{"unverified-disposition ignores conditional-only", conditional, FailOnUnverifiedDisposition, false},
		{"unknown threshold never hits", pkgFixture(nil), FailOn("bogus"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := PackagePolicyHit(tc.pkg, tc.on); got != tc.want {
				t.Fatalf("PackagePolicyHit(..., %q) = %v, want %v", tc.on, got, tc.want)
			}
		})
	}
}

func TestExitCode(t *testing.T) {
	unchanged := pkgFixture(nil)
	lowSupport := pkgFixture(func(p *DecisionPackage) { p.Support.Level = SupportLevelInsufficient })
	demoted := pkgFixture(func(p *DecisionPackage) {
		p.MachineDisposition.Demotions = []string{"rule x permitted LOWERED; demoted"}
	})
	assess := func() Assessment {
		return Assessment{Verdict: VerdictNotExploitable, FactValidation: ValidationComplete}
	}
	cases := []struct {
		name        string
		assessments []Assessment
		decisions   []DecisionPackage
		failures    int
		failOn      []FailOn
		wantCode    int
	}{
		{"no findings passes", nil, nil, 0, nil, ExitCodeOK},
		{"no thresholds never hits", []Assessment{assess()}, []DecisionPackage{unchanged}, 0, nil, ExitCodeOK},
		{"unchanged hits", []Assessment{assess()}, []DecisionPackage{unchanged}, 0, []FailOn{FailOnUnchanged}, ExitCodePolicy},
		{"unchanged ignores other package", []Assessment{assess()},
			[]DecisionPackage{pkgFixture(func(p *DecisionPackage) {
				p.MachineDisposition.Recommendation = RecommendationDismissed
			})},
			0, []FailOn{FailOnUnchanged}, ExitCodeOK},
		{"low-support hits INSUFFICIENT", []Assessment{assess()}, []DecisionPackage{lowSupport}, 0, []FailOn{FailOnLowSupport}, ExitCodePolicy},
		{"low-support ignores SUBSTANTIATED", []Assessment{assess()}, []DecisionPackage{unchanged}, 0, []FailOn{FailOnLowSupport}, ExitCodeOK},
		{"unverified-disposition hits demotion", []Assessment{assess()}, []DecisionPackage{demoted}, 0, []FailOn{FailOnUnverifiedDisposition}, ExitCodePolicy},
		{"combined thresholds any hit", []Assessment{assess()}, []DecisionPackage{lowSupport},
			0, []FailOn{FailOnUnverifiedDisposition, FailOnLowSupport}, ExitCodePolicy},
		{"combined thresholds none hit", []Assessment{assess()},
			[]DecisionPackage{pkgFixture(func(p *DecisionPackage) {
				p.MachineDisposition.Recommendation = RecommendationDismissed
			})},
			0, []FailOn{FailOnUnchanged, FailOnLowSupport}, ExitCodeOK},
		{"technical failure wins over policy hit", []Assessment{assess()}, []DecisionPackage{unchanged},
			1, []FailOn{FailOnUnchanged}, ExitCodeError},
		{"technical failure wins over empty run", nil, nil, 2, nil, ExitCodeError},
		{"assessment without package is an error", []Assessment{assess()}, nil, 0, nil, ExitCodeError},
		{"invalid threshold is technical error", []Assessment{assess()}, []DecisionPackage{unchanged},
			0, []FailOn{FailOn("exploitable")}, ExitCodeError},
		{"invalid threshold fails closed before hits", []Assessment{assess()}, []DecisionPackage{unchanged},
			0, []FailOn{FailOnUnchanged, FailOn("bogus")}, ExitCodeError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ExitCode(tc.assessments, tc.decisions, tc.failures, tc.failOn); got != tc.wantCode {
				t.Fatalf("ExitCode = %d, want %d", got, tc.wantCode)
			}
		})
	}
}

// TestPolicyNeverMutates pins the spec §2.3 invariant: --fail-on evaluation
// is pure — the package's recommendation, facts, rationale and audit are
// byte-identical before and after policy checks and ExitCode evaluation.
func TestPolicyNeverMutates(t *testing.T) {
	pkg := pkgFixture(func(p *DecisionPackage) {
		p.SchemaVersion = DecisionPackageSchemaVersion
		p.RunID = "run-example-001"
		p.FindingID = "finding-example-001"
		p.ExecutionMode = "ci"
		p.MachineDisposition.Baseline = &Baseline{Severity: "high", Priority: "P1", Disposition: RecommendationUnchanged, Source: "scanner"}
		p.Support.Level = SupportLevelLimited
		p.MachineDisposition.Demotions = []string{"rule x permitted LOWERED; demoted"}
		p.MachineDisposition.ResidualAssumptions = []Condition{{
			ID: "assumption-rule-x", Status: ConditionUnknown,
			Scope: "rule", Effect: "blocks_lowered_and_dismissed",
		}}
		p.Facts = []DecisionFact{{ID: "fact-1", Kind: "advisory", Status: "UNAVAILABLE", Subject: "CVE-2099-0001", Scope: "advisory"}}
		p.MachineDisposition.Rationale = Rationale{Summary: "no permitted reduction", Basis: []string{"baseline only"}}
	})
	before := canonicalDecisionHash(pkg)
	for _, f := range []FailOn{FailOnUnchanged, FailOnLowSupport, FailOnConditional, FailOnUnverifiedDisposition} {
		if !PackagePolicyHit(pkg, f) {
			t.Fatalf("fixture must trip %s", f)
		}
	}
	if got := ExitCode([]Assessment{{Verdict: VerdictExploitable}}, []DecisionPackage{pkg}, 0,
		[]FailOn{FailOnUnchanged, FailOnLowSupport, FailOnConditional, FailOnUnverifiedDisposition}); got != ExitCodePolicy {
		t.Fatalf("ExitCode = %d, want policy hit", got)
	}
	if after := canonicalDecisionHash(pkg); after != before {
		t.Fatalf("policy evaluation mutated the package: %s != %s", before, after)
	}
}

func TestParseFailOn(t *testing.T) {
	for _, want := range []FailOn{FailOnUnchanged, FailOnLowSupport, FailOnConditional, FailOnUnverifiedDisposition} {
		got, err := ParseFailOn(string(want))
		if err != nil || got != want {
			t.Fatalf("ParseFailOn(%q) = %q, %v", want, got, err)
		}
	}
	// The retired v1 assessment-level values are configuration errors now —
	// never silently accepted — as is anything else outside the §2.3 set.
	for _, bad := range []string{"", "exploitable", "unverified-negative", "inconclusive", "UNCHANGED", " unchanged", "low_support"} {
		if got, err := ParseFailOn(bad); err == nil {
			t.Fatalf("ParseFailOn(%q) = %q, want error", bad, got)
		}
	}
}

// Legacy analyzer verdicts must never be read back as the new agent verdict.
func TestLegacyDomainVerdictRejected(t *testing.T) {
	for _, legacy := range []string{"NOT_AFFECTED", "NO_EXPLOIT_PATH_FOUND"} {
		if Verdict(legacy).Valid() {
			t.Fatalf("legacy verdict %q must not be a valid agent verdict", legacy)
		}
		var a Assessment
		if err := json.Unmarshal([]byte(`{"verdict":"`+legacy+`"}`), &a); err == nil {
			t.Fatalf("assessment must reject legacy verdict %q", legacy)
		}
	}
}

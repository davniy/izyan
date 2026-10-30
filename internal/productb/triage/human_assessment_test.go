package triage

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/productb/domain"
)

// humanAssessmentFixture is the minimal structurally valid v2 assessment:
// one decisive interpretation backed by a declared source file, one
// non-decisive measured fact, a material counterargument and a CLOSE
// proposal. Every table case below mutates exactly one contract element.
func humanAssessmentFixture() Assessment {
	return Assessment{
		SchemaVersion: AssessmentSchemaVersion,
		FindingID:     "finding-human-001",
		Verdict:       VerdictNotExploitable,
		Summary:       "the vulnerable handler is never registered in the captured build",
		Claims: []Claim{
			{
				ID:               "c1",
				Statement:        "no captured product code registers GhostHandler",
				Basis:            PremiseInterpreted,
				Subject:          "GhostHandler registration",
				Scope:            "captured product snapshot",
				DecisionRelevant: true,
				EvidenceRefs:     []string{"ev-1"},
			},
			{
				ID:               "c2",
				Statement:        "the affected dependency is present",
				Basis:            PremiseMeasured,
				Subject:          "example.org/library presence",
				Scope:            "recorded module graph",
				DecisionRelevant: false,
				EvidenceRefs:     []string{"ev-2"},
				Binding:          &PremiseBinding{Kind: BindingObservationFact, ReferenceID: "ev-2"},
			},
		},
		Evidence: []EvidenceRef{
			{ID: "ev-1", Kind: "file", Locator: "main.go:1-20"},
			{ID: "ev-2", Kind: "observation", Locator: "det:det-0001"},
		},
		Counterarguments: []Counterargument{{
			ID:         "ca1",
			Statement:  "registration may happen in an uncaptured plugin entrypoint",
			Response:   "the captured build declares no plugin entrypoint",
			PremiseIDs: []string{"c1"},
		}},
		ProposedAction: HumanAction{
			Kind:             HumanActionClose,
			Instruction:      "close the ticket as not exploitable in the captured build",
			Rationale:        "the vulnerable handler is never registered in the captured build",
			Scope:            "the captured product snapshot",
			RecordIDs:        []string{"CVE-2099-0001"},
			DecisiveClaimIDs: []string{"c1"},
			ReconsiderWhen:   []string{"a build configuration that registers GhostHandler is captured"},
		},
	}
}

// TestHumanAssessmentDependencyValidation pins the v2 structural contract:
// the action must be concrete, the premise graph must resolve, and the
// decisive closure must account for every decision-relevant claim.
func TestHumanAssessmentDependencyValidation(t *testing.T) {
	if err := ValidateHumanAssessment(humanAssessmentFixture()); err != nil {
		t.Fatalf("base assessment must be structurally valid: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*Assessment)
		want   string
	}{
		{
			name:   "missing action instruction",
			mutate: func(a *Assessment) { a.ProposedAction.Instruction = "" },
			want:   `proposed_action field "instruction" is required`,
		},
		{
			name:   "missing action rationale",
			mutate: func(a *Assessment) { a.ProposedAction.Rationale = "" },
			want:   `proposed_action field "rationale" is required`,
		},
		{
			name:   "missing action scope",
			mutate: func(a *Assessment) { a.ProposedAction.Scope = "" },
			want:   `proposed_action field "scope" is required`,
		},
		{
			name:   "missing reconsideration",
			mutate: func(a *Assessment) { a.ProposedAction.ReconsiderWhen = nil },
			want:   `proposed_action field "reconsider_when" is required`,
		},
		{
			name:   "missing decisive claims",
			mutate: func(a *Assessment) { a.ProposedAction.DecisiveClaimIDs = nil },
			want:   `proposed_action field "decisive_claim_ids" is required`,
		},
		{
			name:   "unknown action kind",
			mutate: func(a *Assessment) { a.ProposedAction.Kind = HumanActionKind("ARCHIVE") },
			want:   `invalid human action kind "ARCHIVE"`,
		},
		{
			name: "duplicate claim id",
			mutate: func(a *Assessment) {
				dup := a.Claims[1]
				dup.ID = "c1"
				a.Claims = append(a.Claims, dup)
			},
			want: `duplicate claim id "c1"`,
		},
		{
			name: "duplicate evidence id",
			mutate: func(a *Assessment) {
				a.Evidence = append(a.Evidence, EvidenceRef{ID: "ev-1", Kind: "file", Locator: "other.go"})
			},
			want: `duplicate evidence id "ev-1"`,
		},
		{
			name:   "dangling dependency",
			mutate: func(a *Assessment) { a.Claims[0].DependsOn = []string{"c9"} },
			want:   `claim "c1" depends on undeclared claim id "c9"`,
		},
		{
			name: "dependency cycle",
			mutate: func(a *Assessment) {
				a.Claims[0].DependsOn = []string{"c2"}
				a.Claims[1].DependsOn = []string{"c1"}
			},
			want: "claim dependency cycle",
		},
		{
			name:   "unresolved decisive claim",
			mutate: func(a *Assessment) { a.ProposedAction.DecisiveClaimIDs = []string{"c9"} },
			want:   `proposed_action cites undeclared decisive claim id "c9"`,
		},
		{
			name:   "decisive claim not decision relevant",
			mutate: func(a *Assessment) { a.Claims[0].DecisionRelevant = false },
			want:   `decisive claim "c1" must be decision-relevant`,
		},
		{
			name:   "unaccounted decision-relevant claim",
			mutate: func(a *Assessment) { a.Claims[1].DecisionRelevant = true },
			want:   `decision-relevant claim "c2" is outside the decisive premise closure`,
		},
		{
			name: "unresolved decisive dependency",
			mutate: func(a *Assessment) {
				a.Claims[0].DependsOn = []string{"c3"}
				a.Claims = append(a.Claims, Claim{
					ID: "c3", Statement: "supporting inference", Basis: PremiseInterpreted,
					Subject: "registration inference", Scope: "captured snapshot", DecisionRelevant: true,
					DependsOn: []string{"c9"},
				})
			},
			want: `claim "c3" depends on undeclared claim id "c9"`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := humanAssessmentFixture()
			tc.mutate(&a)
			err := ValidateHumanAssessment(a)
			if err == nil {
				t.Fatalf("%s must be rejected", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q must name %s", err, tc.want)
			}
		})
	}
}

// TestNegativeAssessmentWithoutFalsifierProposal pins the opinion/proof
// separation: a symbol-declaring advisory may still receive an interpreted
// negative judgment and a concrete CLOSE proposal with no falsifier
// proposal at all. The old mandatory-proposal requirement is gone; the
// assessment stays a human proposal, never a machine-negative result.
func TestNegativeAssessmentWithoutFalsifierProposal(t *testing.T) {
	s0 := goodStage0()
	symbols := []domain.SymbolRef{{Package: "example.org/library", Symbol: "Parse"}}
	s0.Resolution.Vulnerability.AffectedSymbols = symbols
	s0.Resolution.Projection.AffectedSymbols = symbols
	if proj := s0.AdvisoryProjection(); proj == nil || len(proj.AffectedSymbols) == 0 {
		t.Fatal("fixture must declare a symbol-bearing advisory")
	}

	a := humanAssessmentFixture()
	a.ProposedAction.Kind = HumanActionClose
	if len(a.FalsifierProposals) != 0 {
		t.Fatalf("fixture must carry no proposals: %+v", a.FalsifierProposals)
	}
	if err := ValidateHumanAssessment(a); err != nil {
		t.Fatalf("interpreted negative judgment with no proposal must be valid: %v", err)
	}

	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := DecodeAssessment(string(raw), a.FindingID)
	if err != nil {
		t.Fatalf("live ingress must accept the proposal-free negative assessment: %v", err)
	}
	if len(got.FalsifierProposals) != 0 || got.ProposedAction.Kind != HumanActionClose {
		t.Fatalf("decoded assessment = proposals %+v action %q", got.FalsifierProposals, got.ProposedAction.Kind)
	}
	if got.Claims[0].Basis != PremiseInterpreted {
		t.Fatalf("interpreted basis lost at ingress: %+v", got.Claims[0])
	}
}

// TestHumanAssessmentBindingNamespaces pins the two reference namespaces:
// claim dependencies can never be evidence ids and vice versa, and a
// premise binding must resolve in its own declared namespace.
func TestHumanAssessmentBindingNamespaces(t *testing.T) {
	a := humanAssessmentFixture()
	a.Claims[0].DependsOn = []string{"ev-1"}
	if err := ValidateHumanAssessment(a); err == nil || !strings.Contains(err.Error(), `depends on undeclared claim id "ev-1"`) {
		t.Fatalf("evidence id accepted as a claim dependency: %v", err)
	}

	a = humanAssessmentFixture()
	a.Claims[0].Binding = &PremiseBinding{Kind: BindingObservationFact, ReferenceID: "e-missing"}
	if err := ValidateHumanAssessment(a); err == nil || !strings.Contains(err.Error(), `"e-missing"`) {
		t.Fatalf("binding to undeclared evidence accepted: %v", err)
	}

	a = humanAssessmentFixture()
	a.Claims[0].Binding = &PremiseBinding{Kind: BindingFalsifierProof, ReferenceID: "fp-missing"}
	if err := ValidateHumanAssessment(a); err == nil || !strings.Contains(err.Error(), `"fp-missing"`) {
		t.Fatalf("binding to undeclared proposal accepted: %v", err)
	}
}

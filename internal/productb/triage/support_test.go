package triage

import (
	"fmt"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/evidencetools"
	"github.com/fedorovmv/izyan/internal/productb/vulnerability"
)

// supportAssessment assembles a model-owned assessment for the support
// tests: the named decisive claims are the proposed action's closure.
func supportAssessment(evidence []EvidenceRef, claims []Claim, counterarguments []Counterargument, decisive ...string) Assessment {
	return Assessment{
		SchemaVersion:    AssessmentSchemaVersion,
		FindingID:        "finding-example-001",
		Verdict:          VerdictInconclusive,
		Summary:          "support fixture",
		Mechanism:        "support fixture",
		Claims:           claims,
		Evidence:         evidence,
		Counterarguments: counterarguments,
		ProposedAction:   closeAction(decisive...),
	}
}

func supportValidation(snapshot string, evidenceIDs ...string) FactValidation {
	refs := make([]ReferenceCheck, 0, len(evidenceIDs))
	for _, id := range evidenceIDs {
		refs = append(refs, ReferenceCheck{
			EvidenceID:   id,
			Status:       FactValid,
			Scope:        "evidence",
			SnapshotHash: snapshot,
		})
	}
	return FactValidation{Status: ValidationComplete, References: refs}
}

func observationEvidence(id, observationID string) EvidenceRef {
	return EvidenceRef{ID: id, Kind: "observation", Locator: "det:" + observationID}
}

func measuredObservationClaim(id, statement, evidenceID string) Claim {
	return Claim{
		ID:               id,
		Statement:        statement,
		Basis:            PremiseMeasured,
		Subject:          "example.org/library",
		Scope:            "snapshot",
		DecisionRelevant: true,
		EvidenceRefs:     []string{evidenceID},
		Binding:          &PremiseBinding{Kind: BindingObservationFact, ReferenceID: evidenceID},
	}
}

// obtainEvidenceAction is the only action deliverable while required input
// material is missing.
func obtainEvidenceAction(claimIDs ...string) HumanAction {
	return HumanAction{
		Kind:             HumanActionObtainEvidence,
		Instruction:      "obtain the missing advisory material before deciding",
		Rationale:        "the recorded inputs cannot establish the requested conclusion",
		Scope:            "the missing input material",
		DecisiveClaimIDs: claimIDs,
		ReconsiderWhen:   []string{"the missing input material is captured"},
	}
}

// proofClaim builds the claim whose prose is exactly the certificate's
// canonical typed proposition, so the proof may establish it as PROVED.
func proofClaim(t *testing.T, claimID string, report FalsifierReport) Claim {
	t.Helper()
	if len(report.Proofs) != 1 {
		t.Fatalf("proof report has %d proofs, want 1", len(report.Proofs))
	}
	proof := report.Proofs[0]
	subject, scope, proposition := proofNarrowFields(proof)
	return Claim{
		ID:               claimID,
		Statement:        proposition,
		Basis:            PremiseProved,
		Subject:          subject,
		Scope:            scope,
		DecisionRelevant: true,
		EvidenceRefs:     []string{"ev-1"},
		Binding:          &PremiseBinding{Kind: BindingFalsifierProof, ReferenceID: proof.ID},
	}
}

// provedWithinScopeInput is the clean PROVED_WITHIN_SCOPE fixture: a valid
// certificate, a claim expressing its typed proposition, and an action whose
// record scope names the captured advisory.
func provedWithinScopeInput(t *testing.T) SupportInput {
	t.Helper()
	s0 := goodStage0()
	proposal, report := supportProof(t, s0, "c1")
	observation := supportObservation(t, s0, "obs-1", "package example.org/library is absent", 1)
	claim := proofClaim(t, "c1", report)
	assessment := supportAssessment(
		[]EvidenceRef{observationEvidence("ev-1", "obs-1")},
		[]Claim{claim}, nil, "c1",
	)
	assessment.FalsifierProposals = []FalsifierProposal{proposal}
	assessment.ProposedAction.RecordIDs = []string{"CVE-2099-0001"}
	assessment.ProposedAction.Scope = claim.Scope
	return SupportInput{
		Stage0:          s0,
		Assessment:      assessment,
		Validation:      supportValidation(s0.Snapshot.ContentHash, "ev-1"),
		Observations:    []RecordedObservation{observation},
		Falsifiers:      &report,
		SelectedAttempt: 1,
	}
}

func supportPremise(t *testing.T, result SupportResult, id string) DecisionPremise {
	t.Helper()
	for _, premise := range result.Premises {
		if premise.ClaimID == id {
			return premise
		}
	}
	t.Fatalf("premise %q not found in %+v", id, result.Premises)
	return DecisionPremise{}
}

func hasSupportReason(reasons []string, sub string) bool {
	for _, reason := range reasons {
		if strings.Contains(strings.ToLower(reason), strings.ToLower(sub)) {
			return true
		}
	}
	return false
}

func TestSupportDecisivePremiseMatrix(t *testing.T) {
	t.Run("INSUFFICIENT without identity or advisory material", func(t *testing.T) {
		s0 := goodStage0()
		s0.Proposal.VulnerabilityIDs = nil
		s0.Input.Finding.Vulnerability.IDs = nil
		s0.Advisory = vulnerability.FrozenAdvisory{}
		s0.Resolution = nil
		claim := Claim{
			ID:               "c1",
			Statement:        "the advisory identity is not established",
			Basis:            PremiseUnresolved,
			Subject:          "vulnerability identity",
			Scope:            "input",
			DecisionRelevant: true,
			Reason:           "no advisory material was recorded",
		}
		assessment := supportAssessment(nil, []Claim{claim}, nil, "c1")
		assessment.ProposedAction = obtainEvidenceAction("c1")
		result, err := DeriveSupport(SupportInput{Stage0: s0, Assessment: assessment})
		if err != nil {
			t.Fatalf("DeriveSupport: %v", err)
		}
		if result.Support.Level != SupportLevelInsufficient {
			t.Fatalf("support = %s, want INSUFFICIENT", result.Support.Level)
		}
		if !hasSupportReason(result.Support.Reasons, "OBTAIN_EVIDENCE") {
			t.Fatalf("missing input is not named as an evidence action: %v", result.Support.Reasons)
		}
		if !hasSupportReason(result.Support.Reasons, "identity") &&
			!hasSupportReason(result.Support.Reasons, "advisory material") {
			t.Fatalf("missing input is not named: %v", result.Support.Reasons)
		}
		if result.Scope.Boundary != DecisionBoundaryInputMaterialOnly {
			t.Fatalf("scope boundary = %q, want %q", result.Scope.Boundary, DecisionBoundaryInputMaterialOnly)
		}
	})

	t.Run("LIMITED with a decisive assumption", func(t *testing.T) {
		s0 := goodStage0()
		fact := "module example.org/library is absent from the recorded build graph"
		observation := supportObservation(t, s0, "obs-1", fact, 1)
		measured := measuredObservationClaim("c1", fact, "ev-1")
		assumed := Claim{
			ID:               "c2",
			Statement:        "the captured build is the deployment artifact",
			Basis:            PremiseAssumed,
			Subject:          "deployment artifact",
			Scope:            "snapshot",
			DecisionRelevant: true,
			Owner:            "security-team",
		}
		assessment := supportAssessment([]EvidenceRef{observationEvidence("ev-1", "obs-1")},
			[]Claim{measured, assumed}, nil, "c1", "c2")
		result, err := DeriveSupport(SupportInput{
			Stage0:          s0,
			Assessment:      assessment,
			Validation:      supportValidation(s0.Snapshot.ContentHash, "ev-1"),
			Observations:    []RecordedObservation{observation},
			SelectedAttempt: 1,
		})
		if err != nil {
			t.Fatalf("DeriveSupport: %v", err)
		}
		if result.Support.Level != SupportLevelLimited {
			t.Fatalf("support = %s, want LIMITED", result.Support.Level)
		}
		if !hasSupportReason(result.Support.Reasons, "assumption") {
			t.Fatalf("assumption not named: %v", result.Support.Reasons)
		}
	})

	t.Run("SUBSTANTIATED with measured leaves and explicit interpretation", func(t *testing.T) {
		s0 := goodStage0()
		fact := "module example.org/library is absent from the recorded build graph"
		observation := supportObservation(t, s0, "obs-1", fact, 1)
		measured := measuredObservationClaim("c1", fact, "ev-1")
		interpreted := Claim{
			ID:               "c2",
			Statement:        "the captured build therefore does not exercise the vulnerable function",
			Basis:            PremiseInterpreted,
			Subject:          "example.org/library usage",
			Scope:            "snapshot",
			DecisionRelevant: true,
			DependsOn:        []string{"c1"},
		}
		counterargument := Counterargument{
			ID:         "ca-1",
			Statement:  "the module may be loaded through a runtime plugin",
			Response:   "the recorded build graph contains no such module",
			PremiseIDs: []string{"c1"},
		}
		assessment := supportAssessment(
			[]EvidenceRef{observationEvidence("ev-1", "obs-1")},
			[]Claim{measured, interpreted},
			[]Counterargument{counterargument},
			"c1", "c2",
		)
		result, err := DeriveSupport(SupportInput{
			Stage0:          s0,
			Assessment:      assessment,
			Validation:      supportValidation(s0.Snapshot.ContentHash, "ev-1"),
			Observations:    []RecordedObservation{observation},
			SelectedAttempt: 1,
		})
		if err != nil {
			t.Fatalf("DeriveSupport: %v", err)
		}
		if result.Support.Level != SupportLevelSubstantiated {
			t.Fatalf("support = %s, want SUBSTANTIATED (%v)", result.Support.Level, result.Support.Reasons)
		}
		if got := supportPremise(t, result, "c1").Basis; got != PremiseMeasured {
			t.Fatalf("c1 basis = %s, want MEASURED", got)
		}
		if got := supportPremise(t, result, "c2").Basis; got != PremiseInterpreted {
			t.Fatalf("c2 basis = %s, want INTERPRETED", got)
		}
	})

	t.Run("PROVED_WITHIN_SCOPE with an admitted proof contract", func(t *testing.T) {
		input := provedWithinScopeInput(t)
		s0 := input.Stage0
		result, err := DeriveSupport(input)
		if err != nil {
			t.Fatalf("DeriveSupport: %v", err)
		}
		if result.Support.Level != SupportLevelProvedWithinScope {
			t.Fatalf("support = %s, want PROVED_WITHIN_SCOPE (%v)", result.Support.Level, result.Support.Reasons)
		}
		if len(result.Support.ProofIDs) != 1 || result.Support.ProofIDs[0] != "fp-1" {
			t.Fatalf("proof ids = %v, want [fp-1]", result.Support.ProofIDs)
		}

		// An unrelated partial scan outside the decisive closure must not
		// change an independently sufficient proof.
		partial := supportObservation(t, s0, "obs-bg", "scan covered only the product roots", 1)
		partial.Completeness = evidencetools.CompletenessPartial
		background := Claim{
			ID:               "c-bg",
			Statement:        "the background scan is partial",
			Basis:            PremiseMeasured,
			Subject:          "scan coverage",
			Scope:            "snapshot",
			DecisionRelevant: false,
			EvidenceRefs:     []string{"ev-bg"},
			Binding:          &PremiseBinding{Kind: BindingObservationFact, ReferenceID: "ev-bg"},
		}
		assessmentWithBackground := input.Assessment
		assessmentWithBackground.Claims = append(append([]Claim(nil), input.Assessment.Claims...), background)
		assessmentWithBackground.Evidence = append(append([]EvidenceRef(nil), input.Assessment.Evidence...),
			observationEvidence("ev-bg", "obs-bg"))
		input.Assessment = assessmentWithBackground
		input.Observations = append(input.Observations, partial)
		withBackground, err := DeriveSupport(input)
		if err != nil {
			t.Fatalf("DeriveSupport with background scan: %v", err)
		}
		if withBackground.Support.Level != result.Support.Level {
			t.Fatalf("unrelated partial scan changed support: %s -> %s", result.Support.Level, withBackground.Support.Level)
		}
	})
}

func TestSupportCitationDoesNotProveInterpretation(t *testing.T) {
	s0 := goodStage0()
	evidence := EvidenceRef{
		ID:      "ev-q",
		Kind:    "source_span",
		Locator: "advisory/CVE-2099-0001.json:1",
		Quote:   "the vulnerable function is not called",
		SHA256:  strings.Repeat("ef", 32),
	}
	claim := Claim{
		ID:               "c1",
		Statement:        "the vulnerable function is unreachable in production",
		Basis:            PremiseMeasured,
		Subject:          "vulnerable function reachability",
		Scope:            "source",
		DecisionRelevant: true,
		EvidenceRefs:     []string{"ev-q"},
		Binding:          &PremiseBinding{Kind: BindingQuotedText, ReferenceID: "ev-q"},
	}
	assessment := supportAssessment([]EvidenceRef{evidence}, []Claim{claim}, nil, "c1")
	result, err := DeriveSupport(SupportInput{
		Stage0:     s0,
		Assessment: assessment,
		Validation: supportValidation(s0.Snapshot.ContentHash, "ev-q"),
	})
	if err != nil {
		t.Fatalf("DeriveSupport: %v", err)
	}
	premise := supportPremise(t, result, "c1")
	if premise.Basis != PremiseInterpreted {
		t.Fatalf("quoted citation basis = %s, want INTERPRETED", premise.Basis)
	}
	if !strings.Contains(premise.EstablishedProposition, "present") {
		t.Fatalf("established proposition = %q, want presence of text", premise.EstablishedProposition)
	}
	if result.Support.Level != SupportLevelLimited {
		t.Fatalf("support = %s, want LIMITED: a citation cannot prove an interpretation", result.Support.Level)
	}
	if !hasSupportReason(result.Support.Reasons, "presence of text") {
		t.Fatalf("quotation boundary not named: %v", result.Support.Reasons)
	}
}

func TestSupportRejectsOverstatedMeasuredPremise(t *testing.T) {
	s0 := goodStage0()
	fact := "module example.org/library is absent from the recorded build graph"
	observation := supportObservation(t, s0, "obs-1", fact, 1)
	claim := measuredObservationClaim("c1",
		"no code path anywhere in the product can reach the vulnerable function", "ev-1")
	assessment := supportAssessment([]EvidenceRef{observationEvidence("ev-1", "obs-1")},
		[]Claim{claim}, nil, "c1")
	result, err := DeriveSupport(SupportInput{
		Stage0:          s0,
		Assessment:      assessment,
		Validation:      supportValidation(s0.Snapshot.ContentHash, "ev-1"),
		Observations:    []RecordedObservation{observation},
		SelectedAttempt: 1,
	})
	if err != nil {
		t.Fatalf("DeriveSupport: %v", err)
	}
	premise := supportPremise(t, result, "c1")
	if premise.Basis == PremiseMeasured {
		t.Fatalf("overstated premise was promoted to MEASURED: %+v", premise)
	}
	if !hasSupportReason(premise.Reasons, "narrow fact") &&
		!hasSupportReason(premise.Reasons, "recorded observation fact") {
		t.Fatalf("overstatement not explained: %v", premise.Reasons)
	}
	if result.Support.Level != SupportLevelLimited {
		t.Fatalf("support = %s, want LIMITED", result.Support.Level)
	}
}

func TestSupportIgnoresNonDecisivePartialObservation(t *testing.T) {
	s0 := goodStage0()
	fact := "module example.org/library is absent from the recorded build graph"
	observation := supportObservation(t, s0, "obs-1", fact, 1)
	partial := supportObservation(t, s0, "obs-bg", "scan covered only the product roots", 1)
	partial.Completeness = evidencetools.CompletenessPartial
	measured := measuredObservationClaim("c1", fact, "ev-1")
	interpreted := Claim{
		ID:               "c2",
		Statement:        "the captured build therefore does not exercise the vulnerable function",
		Basis:            PremiseInterpreted,
		Subject:          "example.org/library usage",
		Scope:            "snapshot",
		DecisionRelevant: true,
		DependsOn:        []string{"c1"},
	}
	background := Claim{
		ID:               "c-bg",
		Statement:        "the background scan is partial",
		Basis:            PremiseMeasured,
		Subject:          "scan coverage",
		Scope:            "snapshot",
		DecisionRelevant: false,
		EvidenceRefs:     []string{"ev-bg"},
		Binding:          &PremiseBinding{Kind: BindingObservationFact, ReferenceID: "ev-bg"},
	}
	counterargument := Counterargument{
		ID:         "ca-1",
		Statement:  "the module may be loaded through a runtime plugin",
		Response:   "the recorded build graph contains no such module",
		PremiseIDs: []string{"c1"},
	}
	assessment := supportAssessment(
		[]EvidenceRef{observationEvidence("ev-1", "obs-1"), observationEvidence("ev-bg", "obs-bg")},
		[]Claim{measured, interpreted, background},
		[]Counterargument{counterargument},
		"c1", "c2",
	)
	result, err := DeriveSupport(SupportInput{
		Stage0:          s0,
		Assessment:      assessment,
		Validation:      supportValidation(s0.Snapshot.ContentHash, "ev-1"),
		Observations:    []RecordedObservation{observation, partial},
		SelectedAttempt: 1,
	})
	if err != nil {
		t.Fatalf("DeriveSupport: %v", err)
	}
	if result.Support.Level != SupportLevelSubstantiated {
		t.Fatalf("non-decisive partial observation lowered support to %s: %v", result.Support.Level, result.Support.Reasons)
	}
	for _, premise := range result.Premises {
		if premise.ClaimID == "c-bg" {
			t.Fatalf("non-decisive claim was evaluated for support: %+v", premise)
		}
	}
}

func TestSupportConflictingDecisivePremises(t *testing.T) {
	newInput := func(t *testing.T) (SupportInput, Claim, Claim) {
		t.Helper()
		s0 := goodStage0()
		first := supportObservation(t, s0, "obs-1", "module example.org/library is present", 1)
		second := supportObservation(t, s0, "obs-2", "module example.org/library is absent", 1)
		c1 := measuredObservationClaim("c1", "module example.org/library is present", "ev-1")
		c2 := measuredObservationClaim("c2", "module example.org/library is absent", "ev-2")
		assessment := supportAssessment(
			[]EvidenceRef{observationEvidence("ev-1", "obs-1"), observationEvidence("ev-2", "obs-2")},
			[]Claim{c1, c2}, nil, "c1", "c2",
		)
		return SupportInput{
			Stage0:          s0,
			Assessment:      assessment,
			Validation:      supportValidation(s0.Snapshot.ContentHash, "ev-1", "ev-2"),
			Observations:    []RecordedObservation{first, second},
			SelectedAttempt: 1,
		}, c1, c2
	}

	t.Run("explicit conflict reference", func(t *testing.T) {
		input, c1, c2 := newInput(t)
		input.Assessment.Claims[0].ConflictsWith = []string{c2.ID}
		input.Assessment.Claims[1].ConflictsWith = []string{c1.ID}
		result, err := DeriveSupport(input)
		if err != nil {
			t.Fatalf("DeriveSupport: %v", err)
		}
		if result.Support.Level != SupportLevelLimited {
			t.Fatalf("support = %s, want LIMITED", result.Support.Level)
		}
		if !hasSupportReason(result.Support.Reasons, "conflict") {
			t.Fatalf("conflict not named: %v", result.Support.Reasons)
		}
	})

	t.Run("structured facts with matching kind subject and scope", func(t *testing.T) {
		input, _, _ := newInput(t)
		input.Facts = []DecisionFact{
			{ID: "f1", Kind: "package_presence", Status: ObsSupports,
				Subject: "example.org/library", Scope: "build-graph", EvidenceRefs: []string{"det:obs-1"}},
			{ID: "f2", Kind: "package_presence", Status: ObsRefutes,
				Subject: "example.org/library", Scope: "build-graph", EvidenceRefs: []string{"det:obs-2"}},
		}
		result, err := DeriveSupport(input)
		if err != nil {
			t.Fatalf("DeriveSupport: %v", err)
		}
		if result.Support.Level != SupportLevelLimited {
			t.Fatalf("support = %s, want LIMITED", result.Support.Level)
		}
		if !hasSupportReason(result.Support.Reasons, "comparable facts") {
			t.Fatalf("fact contradiction not named: %v", result.Support.Reasons)
		}
	})
}

func TestSupportForeignAttemptCannotGroundPremise(t *testing.T) {
	s0 := goodStage0()
	fact := "module example.org/library is absent from the recorded build graph"
	observation := supportObservation(t, s0, "obs-1", fact, 1)
	claim := measuredObservationClaim("c1", fact, "ev-1")
	assessment := supportAssessment([]EvidenceRef{observationEvidence("ev-1", "obs-1")},
		[]Claim{claim}, nil, "c1")
	result, err := DeriveSupport(SupportInput{
		Stage0:          s0,
		Assessment:      assessment,
		Validation:      supportValidation(s0.Snapshot.ContentHash, "ev-1"),
		Observations:    []RecordedObservation{observation},
		SelectedAttempt: 2,
	})
	if err != nil {
		t.Fatalf("DeriveSupport: %v", err)
	}
	premise := supportPremise(t, result, "c1")
	if premise.Basis == PremiseMeasured {
		t.Fatalf("foreign-attempt observation grounded a measured premise: %+v", premise)
	}
	if !hasSupportReason(premise.Reasons, "attempt") {
		t.Fatalf("attempt ownership not named: %v", premise.Reasons)
	}
	if result.Support.Level != SupportLevelLimited {
		t.Fatalf("support = %s, want LIMITED", result.Support.Level)
	}
}

func TestSupportDoesNotUseCitationCountOrModelAgreement(t *testing.T) {
	t.Run("many citations without a binding", func(t *testing.T) {
		s0 := goodStage0()
		evidence := make([]EvidenceRef, 0, 12)
		refs := make([]string, 0, 12)
		for i := 1; i <= 12; i++ {
			id := fmt.Sprintf("ev-%02d", i)
			evidence = append(evidence, EvidenceRef{
				ID: id, Kind: "source_span",
				Locator: fmt.Sprintf("advisory/CVE-2099-0001.json:%d", i),
				Quote:   "advisory text",
			})
			refs = append(refs, id)
		}
		claim := Claim{
			ID:               "c1",
			Statement:        "the advisory supports closing the ticket",
			Basis:            PremiseMeasured,
			Subject:          "advisory semantics",
			Scope:            "source",
			DecisionRelevant: true,
			EvidenceRefs:     refs,
		}
		assessment := supportAssessment(evidence, []Claim{claim}, nil, "c1")
		result, err := DeriveSupport(SupportInput{
			Stage0:     s0,
			Assessment: assessment,
			Validation: supportValidation(s0.Snapshot.ContentHash, refs...),
			Stability:  &StabilityReport{Stable: true, Attempts: []StabilityAttempt{{Attempt: 1}}},
		})
		if err != nil {
			t.Fatalf("DeriveSupport: %v", err)
		}
		if result.Support.Level != SupportLevelLimited {
			t.Fatalf("support = %s, want LIMITED: citation count is not support", result.Support.Level)
		}
		if !hasSupportReason(result.Support.Reasons, "binding") {
			t.Fatalf("missing binding not named: %v", result.Support.Reasons)
		}
		if hasSupportReason(result.Support.Reasons, "12") {
			t.Fatalf("support reasons count citations: %v", result.Support.Reasons)
		}
	})

	t.Run("model agreement does not raise support over a limited basis", func(t *testing.T) {
		input := substantiatedSupportInput(t)
		input.Stability = &StabilityReport{Stable: true, Attempts: []StabilityAttempt{{Attempt: 1}}}
		input.Assessment.Claims = append(input.Assessment.Claims, Claim{
			ID:               "c-assumed",
			Statement:        "the deployment uses the captured build",
			Basis:            PremiseAssumed,
			Subject:          "deployment artifact",
			Scope:            "snapshot",
			DecisionRelevant: true,
			Owner:            "security-team",
		})
		input.Assessment.ProposedAction.DecisiveClaimIDs = append(
			input.Assessment.ProposedAction.DecisiveClaimIDs, "c-assumed")
		result, err := DeriveSupport(input)
		if err != nil {
			t.Fatalf("DeriveSupport: %v", err)
		}
		if result.Support.Level != SupportLevelLimited {
			t.Fatalf("stable agreement raised support over an assumption: %s", result.Support.Level)
		}
	})

	t.Run("stability disagreement caps support", func(t *testing.T) {
		input := substantiatedSupportInput(t)
		input.Stability = &StabilityReport{
			Stable:      false,
			Attempts:    []StabilityAttempt{{Attempt: 1}, {Attempt: 2}},
			Limitations: []string{"attempt 2: recommendation changed (UNCHANGED -> DISMISSED)"},
		}
		result, err := DeriveSupport(input)
		if err != nil {
			t.Fatalf("DeriveSupport: %v", err)
		}
		if result.Support.Level != SupportLevelLimited {
			t.Fatalf("support = %s, want LIMITED under stability disagreement", result.Support.Level)
		}
		if !hasSupportReason(result.Support.Reasons, "stability") {
			t.Fatalf("stability disagreement not named: %v", result.Support.Reasons)
		}
	})
}

// substantiatedSupportInput is the clean SUBSTANTIATED fixture: one measured
// leaf, one explicit interpretation grounded in it, and one grounded
// counterargument response.
func substantiatedSupportInput(t *testing.T) SupportInput {
	t.Helper()
	s0 := goodStage0()
	fact := "module example.org/library is absent from the recorded build graph"
	observation := supportObservation(t, s0, "obs-1", fact, 1)
	measured := measuredObservationClaim("c1", fact, "ev-1")
	interpreted := Claim{
		ID:               "c2",
		Statement:        "the captured build therefore does not exercise the vulnerable function",
		Basis:            PremiseInterpreted,
		Subject:          "example.org/library usage",
		Scope:            "snapshot",
		DecisionRelevant: true,
		DependsOn:        []string{"c1"},
	}
	counterargument := Counterargument{
		ID:         "ca-1",
		Statement:  "the module may be loaded through a runtime plugin",
		Response:   "the recorded build graph contains no such module",
		PremiseIDs: []string{"c1"},
	}
	assessment := supportAssessment(
		[]EvidenceRef{observationEvidence("ev-1", "obs-1")},
		[]Claim{measured, interpreted},
		[]Counterargument{counterargument},
		"c1", "c2",
	)
	return SupportInput{
		Stage0:          s0,
		Assessment:      assessment,
		Validation:      supportValidation(s0.Snapshot.ContentHash, "ev-1"),
		Observations:    []RecordedObservation{observation},
		SelectedAttempt: 1,
	}
}

func TestSupportScopeFromRecordedStage0(t *testing.T) {
	claim := Claim{
		ID:               "c1",
		Statement:        "the advisory identity is not established",
		Basis:            PremiseUnresolved,
		Subject:          "vulnerability identity",
		Scope:            "input",
		DecisionRelevant: true,
		Reason:           "fixture",
	}

	t.Run("captured record yields exact record scope", func(t *testing.T) {
		s0 := goodStage0()
		assessment := supportAssessment(nil, []Claim{claim}, nil, "c1")
		result, err := DeriveSupport(SupportInput{Stage0: s0, Assessment: assessment})
		if err != nil {
			t.Fatalf("DeriveSupport: %v", err)
		}
		if result.Scope.Boundary != DecisionBoundaryExactRecords {
			t.Fatalf("boundary = %q, want EXACT_RECORDS", result.Scope.Boundary)
		}
		if len(result.Scope.Records) != 1 {
			t.Fatalf("records = %+v, want one captured record", result.Scope.Records)
		}
		if result.Scope.Records[0].ID != "CVE-2099-0001" ||
			result.Scope.Records[0].SHA256 != strings.Repeat("ef", 32) {
			t.Fatalf("record = %+v, want the recorded id and digest", result.Scope.Records[0])
		}
		if len(result.Scope.RequestedIDs) != 1 || result.Scope.RequestedIDs[0] != "CVE-2099-0001" {
			t.Fatalf("requested ids = %v", result.Scope.RequestedIDs)
		}
		if result.Scope.SnapshotHash != s0.Snapshot.ContentHash {
			t.Fatalf("snapshot hash = %q, want %q", result.Scope.SnapshotHash, s0.Snapshot.ContentHash)
		}
	})

	t.Run("missing captured material yields input-only scope", func(t *testing.T) {
		s0 := goodStage0()
		s0.Advisory = vulnerability.FrozenAdvisory{}
		s0.Resolution = nil
		assessment := supportAssessment(nil, []Claim{claim}, nil, "c1")
		assessment.ProposedAction = obtainEvidenceAction("c1")
		result, err := DeriveSupport(SupportInput{Stage0: s0, Assessment: assessment})
		if err != nil {
			t.Fatalf("DeriveSupport: %v", err)
		}
		if result.Scope.Boundary != DecisionBoundaryInputMaterialOnly {
			t.Fatalf("boundary = %q, want INPUT_MATERIAL_ONLY", result.Scope.Boundary)
		}
		if len(result.Scope.Records) != 0 {
			t.Fatalf("missing advisory material produced record digests: %+v", result.Scope.Records)
		}
		if !hasSupportReason(result.Scope.OpenBoundaries, "no advisory material") {
			t.Fatalf("missing advisory material is not an open boundary: %v", result.Scope.OpenBoundaries)
		}
	})

	t.Run("model record ids do not widen the scope", func(t *testing.T) {
		s0 := goodStage0()
		assessment := supportAssessment(nil, []Claim{claim}, nil, "c1")
		assessment.ProposedAction.RecordIDs = []string{"CVE-9999-9999"}
		result, err := DeriveSupport(SupportInput{Stage0: s0, Assessment: assessment})
		if err != nil {
			t.Fatalf("DeriveSupport: %v", err)
		}
		for _, id := range result.Scope.RequestedIDs {
			if id == "CVE-9999-9999" {
				t.Fatalf("model record id widened the requested scope: %v", result.Scope.RequestedIDs)
			}
		}
		for _, record := range result.Scope.Records {
			if record.ID == "CVE-9999-9999" {
				t.Fatalf("model record id manufactured a record: %+v", result.Scope.Records)
			}
		}
	})
}

func TestSupportProposalAloneEstablishesNothing(t *testing.T) {
	s0 := goodStage0()
	proposal, _ := supportProof(t, s0, "c1")
	claim := Claim{
		ID:               "c1",
		Statement:        "example.org/library is absent from the residual build graph",
		Basis:            PremiseProved,
		Subject:          "example.org/library absence",
		Scope:            "snapshot",
		DecisionRelevant: true,
		EvidenceRefs:     []string{"ev-1"},
		Binding:          &PremiseBinding{Kind: BindingFalsifierProof, ReferenceID: "fp-1"},
	}
	assessment := supportAssessment(
		[]EvidenceRef{observationEvidence("ev-1", "obs-1")},
		[]Claim{claim}, nil, "c1",
	)
	assessment.FalsifierProposals = []FalsifierProposal{proposal}
	result, err := DeriveSupport(SupportInput{Stage0: s0, Assessment: assessment})
	if err != nil {
		t.Fatalf("DeriveSupport: %v", err)
	}
	if result.Support.Level != SupportLevelLimited {
		t.Fatalf("support = %s, want LIMITED", result.Support.Level)
	}
	premise := supportPremise(t, result, "c1")
	if premise.Basis == PremiseProved {
		t.Fatalf("proposal alone promoted the claim to PROVED: %+v", premise)
	}
	if !hasSupportReason(premise.Reasons, "proposal alone") {
		t.Fatalf("missing proof is not named: %v", premise.Reasons)
	}
}

func TestSupportProvedLeafDoesNotCoverConclusion(t *testing.T) {
	s0 := goodStage0()
	proposal, report := supportProof(t, s0, "c-leaf")
	fact := "module example.org/library is absent from the recorded build graph"
	observation := supportObservation(t, s0, "obs-1", fact, 1)
	leaf := proofClaim(t, "c-leaf", report)
	conclusion := Claim{
		ID:               "c-final",
		Statement:        fact,
		Basis:            PremiseMeasured,
		Subject:          "example.org/library",
		Scope:            "snapshot",
		DecisionRelevant: true,
		EvidenceRefs:     []string{"ev-1"},
		DependsOn:        []string{"c-leaf"},
		Binding:          &PremiseBinding{Kind: BindingObservationFact, ReferenceID: "ev-1"},
	}
	assessment := supportAssessment(
		[]EvidenceRef{observationEvidence("ev-1", "obs-1")},
		[]Claim{leaf, conclusion}, nil, "c-final",
	)
	assessment.FalsifierProposals = []FalsifierProposal{proposal}
	result, err := DeriveSupport(SupportInput{
		Stage0:          s0,
		Assessment:      assessment,
		Validation:      supportValidation(s0.Snapshot.ContentHash, "ev-1"),
		Observations:    []RecordedObservation{observation},
		Falsifiers:      &report,
		SelectedAttempt: 1,
	})
	if err != nil {
		t.Fatalf("DeriveSupport: %v", err)
	}
	if result.Support.Level != SupportLevelSubstantiated {
		t.Fatalf("support = %s, want SUBSTANTIATED: a proved dependency is not the proposed conclusion", result.Support.Level)
	}
}

func TestSupportExplicitInterpretationGroundedInFact(t *testing.T) {
	s0 := goodStage0()
	fact := "module example.org/library is absent from the recorded build graph"
	observation := supportObservation(t, s0, "obs-1", fact, 1)
	claim := Claim{
		ID:               "c1",
		Statement:        "the captured build therefore does not exercise the vulnerable module",
		Basis:            PremiseInterpreted,
		Subject:          "example.org/library usage",
		Scope:            "snapshot",
		DecisionRelevant: true,
		EvidenceRefs:     []string{"ev-1"},
		Binding:          &PremiseBinding{Kind: BindingObservationFact, ReferenceID: "ev-1"},
	}
	assessment := supportAssessment([]EvidenceRef{observationEvidence("ev-1", "obs-1")},
		[]Claim{claim}, nil, "c1")
	result, err := DeriveSupport(SupportInput{
		Stage0:          s0,
		Assessment:      assessment,
		Validation:      supportValidation(s0.Snapshot.ContentHash, "ev-1"),
		Observations:    []RecordedObservation{observation},
		SelectedAttempt: 1,
	})
	if err != nil {
		t.Fatalf("DeriveSupport: %v", err)
	}
	if result.Support.Level != SupportLevelSubstantiated {
		t.Fatalf("support = %s, want SUBSTANTIATED: an explicit interpretation grounded in a recorded fact satisfies the contract (%v)",
			result.Support.Level, result.Support.Reasons)
	}
	premise := supportPremise(t, result, "c1")
	if premise.Basis != PremiseInterpreted {
		t.Fatalf("basis = %s, want INTERPRETED", premise.Basis)
	}
	if premise.EstablishedProposition == "" {
		t.Fatal("recorded narrow fact was not carried into the premise")
	}
}

func TestSupportMissingMaterialRejectsActionableProposal(t *testing.T) {
	s0 := goodStage0()
	s0.Proposal.VulnerabilityIDs = nil
	s0.Input.Finding.Vulnerability.IDs = nil
	s0.Advisory = vulnerability.FrozenAdvisory{}
	s0.Resolution = nil
	claim := Claim{
		ID:               "c1",
		Statement:        "the advisory identity is not established",
		Basis:            PremiseUnresolved,
		Subject:          "vulnerability identity",
		Scope:            "input",
		DecisionRelevant: true,
		Reason:           "no advisory material was recorded",
	}
	assessment := supportAssessment(nil, []Claim{claim}, nil, "c1") // CLOSE
	if _, err := DeriveSupport(SupportInput{Stage0: s0, Assessment: assessment}); err == nil {
		t.Fatal("CLOSE was delivered while required input material is missing")
	} else {
		message := err.Error()
		if !strings.Contains(message, "OBTAIN_EVIDENCE") {
			t.Fatalf("repair does not name the only deliverable action: %v", err)
		}
		if !strings.Contains(message, "advisory material") && !strings.Contains(message, "identity") {
			t.Fatalf("repair does not name the missing input: %v", err)
		}
	}
	if assessment.ProposedAction.Kind != HumanActionClose {
		t.Fatalf("recorded proposal was rewritten to %s", assessment.ProposedAction.Kind)
	}
}

func TestSupportProofDoesNotPromoteUnmatchedProse(t *testing.T) {
	assertNotAdmitted := func(t *testing.T, input SupportInput) {
		t.Helper()
		result, err := DeriveSupport(input)
		if err != nil {
			t.Fatalf("DeriveSupport: %v", err)
		}
		premise := supportPremise(t, result, "c1")
		if premise.Basis == PremiseProved {
			t.Fatalf("unmatched prose was promoted to PROVED: %+v", premise)
		}
		if result.Support.Level != SupportLevelLimited {
			t.Fatalf("support = %s, want LIMITED (%v)", result.Support.Level, result.Support.Reasons)
		}
		if premise.EstablishedProposition == "" {
			t.Fatalf("narrow proved proposition was not shown separately: %+v", premise)
		}
	}

	t.Run("subject mismatch", func(t *testing.T) {
		input := provedWithinScopeInput(t)
		input.Assessment.Claims[0].Subject = "example.org/library"
		assertNotAdmitted(t, input)
	})

	t.Run("statement paraphrase", func(t *testing.T) {
		input := provedWithinScopeInput(t)
		input.Assessment.Claims[0].Statement = "the vulnerable package is absent from the build"
		assertNotAdmitted(t, input)
	})

	t.Run("case-only subject difference", func(t *testing.T) {
		input := provedWithinScopeInput(t)
		input.Assessment.Claims[0].Subject = "Example.org/library#Vulnerable"
		assertNotAdmitted(t, input)
	})

	t.Run("case-only statement difference", func(t *testing.T) {
		input := provedWithinScopeInput(t)
		input.Assessment.Claims[0].Statement = strings.Replace(
			input.Assessment.Claims[0].Statement, "locus_package_absent", "Locus_package_absent", 1)
		assertNotAdmitted(t, input)
	})
}

func TestSupportActionRecordScopeMustBeCovered(t *testing.T) {
	t.Run("foreign record id", func(t *testing.T) {
		input := provedWithinScopeInput(t)
		input.Assessment.ProposedAction.RecordIDs = []string{"CVE-9999-9999"}
		result, err := DeriveSupport(input)
		if err != nil {
			t.Fatalf("DeriveSupport: %v", err)
		}
		if result.Support.Level == SupportLevelProvedWithinScope {
			t.Fatalf("foreign action record scope awarded PROVED_WITHIN_SCOPE: %v", result.Support.Reasons)
		}
		if result.Support.Level != SupportLevelLimited {
			t.Fatalf("support = %s, want LIMITED for an uncaptured action record", result.Support.Level)
		}
		if !hasSupportReason(result.Support.Reasons, "not a captured advisory record") {
			t.Fatalf("uncaptured action record not named: %v", result.Support.Reasons)
		}
	})

	t.Run("requested but uncaptured record", func(t *testing.T) {
		input := provedWithinScopeInput(t)
		input.Stage0.Proposal.VulnerabilityIDs = []string{"CVE-2099-0001", "CVE-2099-9999"}
		input.Assessment.ProposedAction.RecordIDs = []string{"CVE-2099-9999"}
		result, err := DeriveSupport(input)
		if err != nil {
			t.Fatalf("DeriveSupport: %v", err)
		}
		if result.Support.Level == SupportLevelProvedWithinScope {
			t.Fatalf("requested-but-uncaptured record awarded PROVED_WITHIN_SCOPE: %v", result.Support.Reasons)
		}
		if result.Support.Level != SupportLevelLimited {
			t.Fatalf("support = %s, want LIMITED", result.Support.Level)
		}
		if !hasSupportReason(result.Support.Reasons, "not a captured advisory record") {
			t.Fatalf("uncaptured requested record not named: %v", result.Support.Reasons)
		}
	})

	t.Run("verified alias binding", func(t *testing.T) {
		input := provedWithinScopeInput(t)
		input.Stage0.Proposal.VulnerabilityIDs = []string{"CVE-2099-0001", "CVE-2099-9999"}
		input.Stage0.Resolution.Vulnerability.Aliases = []string{"CVE-2099-9999"}
		input.Assessment.ProposedAction.RecordIDs = []string{"CVE-2099-9999"}
		result, err := DeriveSupport(input)
		if err != nil {
			t.Fatalf("DeriveSupport: %v", err)
		}
		if result.Support.Level != SupportLevelProvedWithinScope {
			t.Fatalf("support = %s, want PROVED_WITHIN_SCOPE for a verified alias (%v)",
				result.Support.Level, result.Support.Reasons)
		}
	})

	t.Run("missing record scope", func(t *testing.T) {
		input := provedWithinScopeInput(t)
		input.Assessment.ProposedAction.RecordIDs = nil
		result, err := DeriveSupport(input)
		if err != nil {
			t.Fatalf("DeriveSupport: %v", err)
		}
		if result.Support.Level == SupportLevelProvedWithinScope {
			t.Fatalf("undeclared action record scope awarded PROVED_WITHIN_SCOPE: %v", result.Support.Reasons)
		}
		if result.Support.Level != SupportLevelSubstantiated {
			t.Fatalf("support = %s, want SUBSTANTIATED", result.Support.Level)
		}
	})
}

func TestSupportBackgroundConflictCapsSupport(t *testing.T) {
	input := substantiatedSupportInput(t)
	input.Assessment.Claims = append(input.Assessment.Claims, Claim{
		ID:               "c-bg",
		Statement:        "a background objection contradicts the decisive claim",
		Basis:            PremiseMeasured,
		Subject:          "background",
		Scope:            "snapshot",
		DecisionRelevant: false,
		ConflictsWith:    []string{"c1"},
	})
	result, err := DeriveSupport(input)
	if err != nil {
		t.Fatalf("DeriveSupport: %v", err)
	}
	if result.Support.Level != SupportLevelLimited {
		t.Fatalf("support = %s, want LIMITED: a background conflict touches a decisive claim", result.Support.Level)
	}
	if !hasSupportReason(result.Support.Reasons, "conflict") {
		t.Fatalf("background conflict not named: %v", result.Support.Reasons)
	}
}

func TestSupportMeasuredPropositionIsCaseSensitive(t *testing.T) {
	s0 := goodStage0()
	fact := "0 call sites of p.F in product packages"
	observation := supportObservation(t, s0, "obs-1", fact, 1)
	claim := measuredObservationClaim("c1", "0 call sites of p.f in product packages", "ev-1")
	assessment := supportAssessment([]EvidenceRef{observationEvidence("ev-1", "obs-1")},
		[]Claim{claim}, nil, "c1")
	result, err := DeriveSupport(SupportInput{
		Stage0:          s0,
		Assessment:      assessment,
		Validation:      supportValidation(s0.Snapshot.ContentHash, "ev-1"),
		Observations:    []RecordedObservation{observation},
		SelectedAttempt: 1,
	})
	if err != nil {
		t.Fatalf("DeriveSupport: %v", err)
	}
	premise := supportPremise(t, result, "c1")
	if premise.Basis == PremiseMeasured {
		t.Fatalf("case-only difference was accepted as MEASURED: %+v", premise)
	}
	if result.Support.Level != SupportLevelLimited {
		t.Fatalf("support = %s, want LIMITED", result.Support.Level)
	}
}

func TestSupportActionScopeMustMatchProvedScope(t *testing.T) {
	assertNotTopLevel := func(t *testing.T, input SupportInput) {
		t.Helper()
		result, err := DeriveSupport(input)
		if err != nil {
			t.Fatalf("DeriveSupport: %v", err)
		}
		if result.Support.Level == SupportLevelProvedWithinScope {
			t.Fatalf("mismatched action scope awarded PROVED_WITHIN_SCOPE: %v", result.Support.Reasons)
		}
		if result.Support.Level != SupportLevelSubstantiated {
			t.Fatalf("support = %s, want SUBSTANTIATED", result.Support.Level)
		}
	}

	t.Run("broader prose scope", func(t *testing.T) {
		input := provedWithinScopeInput(t)
		input.Assessment.ProposedAction.Scope = "the entire product fleet"
		assertNotTopLevel(t, input)
	})

	t.Run("case-only scope difference", func(t *testing.T) {
		input := provedWithinScopeInput(t)
		input.Assessment.ProposedAction.Scope = "Snapshot"
		assertNotTopLevel(t, input)
	})
}

// TestSupportDoesNotMergeSeparateRecords: every captured record the run
// considered is its own decision-scope entry. Aliases resolve inside the
// captured set but never fuse two records or declare a CVE corpus.
func TestSupportDoesNotMergeSeparateRecords(t *testing.T) {
	rawA := []byte(`{"id":"CVE-2026-0001","summary":"record A"}`)
	rawB := []byte(`{"id":"CVE-2026-0002","summary":"record B"}`)
	s0 := Stage0Result{
		Input:    FindingInput{Finding: Finding{FindingID: "f", Vulnerability: Vulnerability{IDs: []string{"CVE-2026-0001"}}}},
		Snapshot: SnapshotManifest{ContentHash: "snapshot-hash"},
	}
	s0.Investigation = InvestigationInputs{Records: []CapturedRecord{
		{RecordID: "CVE-2026-0001", Aliases: []string{"GHSA-aaaa-0000-0001"}, SHA256: hashBytes(rawA), Size: int64(len(rawA)), Source: "operator-freeze", Raw: rawA},
		{RecordID: "CVE-2026-0002", Aliases: []string{"GHSA-bbbb-0000-0002"}, SHA256: hashBytes(rawB), Size: int64(len(rawB)), Source: "operator-freeze", Raw: rawB},
	}}
	scope := deriveDecisionScope(s0)
	if scope.Boundary != DecisionBoundaryExactRecords {
		t.Fatalf("boundary = %q, want EXACT_RECORDS", scope.Boundary)
	}
	if len(scope.Records) != 2 {
		t.Fatalf("scope records = %+v, want two separate captured records", scope.Records)
	}
	if scope.Records[0].ID != "CVE-2026-0001" || scope.Records[1].ID != "CVE-2026-0002" {
		t.Fatalf("scope records merged or reordered: %+v", scope.Records)
	}
	for _, rec := range scope.Records {
		if strings.Contains(rec.ID, "GHSA-") {
			t.Fatalf("an alias was promoted to a record identity: %+v", rec)
		}
	}
	// The supplied record ids are not a declared CVE corpus: they do not
	// rewrite the requested identities.
	for _, id := range scope.RequestedIDs {
		if id == "CVE-2026-0002" {
			t.Fatalf("captured record leaked into requested ids as a corpus declaration: %+v", scope.RequestedIDs)
		}
	}
	if missing := missingDecisionInput(scope); missing != "" {
		t.Fatalf("captured records did not satisfy the decision input: %s", missing)
	}
	admissible := admissibleRecordIDs(scope, s0)
	for _, id := range []string{"CVE-2026-0001", "GHSA-aaaa-0000-0001", "CVE-2026-0002", "GHSA-bbbb-0000-0002"} {
		if !admissible[id] {
			t.Fatalf("captured identity %q is not admissible", id)
		}
	}
	if admissible["GHSA-ffff-0000-9999"] {
		t.Fatal("an uncaptured alias became admissible")
	}
	action := closeAction("c1")
	action.RecordIDs = []string{"CVE-2026-0001", "GHSA-bbbb-0000-0002"}
	if !actionRecordScopeCovered(action, admissible) {
		t.Fatalf("action naming both captured records is not covered: %+v", action.RecordIDs)
	}
}

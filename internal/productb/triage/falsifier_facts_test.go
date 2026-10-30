package triage

import (
	"context"
	"github.com/davniy/izyan/internal/evidencetools"
	"strings"
	"testing"
)

func falsifierReport(status FalsifierVerificationStatus, refs []string, id string) *FalsifierReport {
	r := &FalsifierReport{SchemaVersion: FalsifierVerificationSchemaVersion, RuleSetHash: "rules-1", Proofs: []FalsifierProof{{ID: id, ProposalID: id, ClaimID: "c1", ConditionID: "cond-1", Kind: FalsifierCodeAbsent, Status: status, Basis: BasisCheckerVerified, Mandatory: true, RuleID: "rule-1", RuleVersion: "v1", EvidenceRefs: append([]string(nil), refs...), Coverage: FalsifierCoverage{Scope: "snapshot", Completeness: "COMPLETE", SnapshotHash: goodStage0().Snapshot.ContentHash, BuildContextHash: "build-1", ClosureHash: "closure-1", ClosureComplete: true, CoverageRuleVersion: "4", ScopeRule: evidencetools.CodeAbsenceScopeRule, ScopeComplete: true, ScopeHash: "scope-1", ShippingRoots: []string{"cmd/app"}, PackageStates: map[string]string{"cmd/app": "LIVE"}, DynamicRelevanceRule: evidencetools.CodeAbsenceDynamicRule, DynamicRelevanceComplete: true, ExpectedSubjects: []FalsifierSubject{{Package: "example.org/library", Symbol: "Affected"}}, CheckedSubjects: []FalsifierSubject{{Package: "example.org/library", Symbol: "Affected"}}, AbsentSubjects: []FalsifierSubject{{Package: "example.org/library", Symbol: "Affected"}}}}}}
	bindCurrentCoverageInventory(&r.Proofs[0].Coverage)
	r.Hash = reportHash(*r)
	return r
}

func falsifierFacts(t *testing.T, report *FalsifierReport) map[string]DecisionFact {
	t.Helper()
	got, err := FalsifierFactsProvider{}.Collect(context.Background(), ProviderInput{Falsifiers: report})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	out := map[string]DecisionFact{}
	for _, f := range got {
		out[f.Kind] = f
	}
	return out
}

func TestFalsifierFactsNoProposal(t *testing.T) {
	facts := falsifierFacts(t, nil)
	if got := facts[FactFalsifierProposalPresent]; got.Status != ObsRefutes || got.Scope != "falsifier" {
		t.Fatalf("present fact = %+v", got)
	}
	if got := facts[FactFalsifierKernelPresent]; got.Status != ObsRefutes {
		t.Fatalf("kernel fact = %+v", got)
	}
	if got := facts[FactFalsifierAdmitted]; got.Status != ObsRefutes {
		t.Fatalf("admitted fact = %+v", got)
	}
	set := decisionFactSet([]DecisionFact{facts[FactFalsifierProposalPresent], facts[FactFalsifierKernelPresent], facts[FactFalsifierAdmitted]})
	if set["falsifier.proposal_present"] != false || set["falsifier.kernel_present"] != false || set["falsifier.admitted"] != false {
		t.Fatalf("fact set = %v", set)
	}
}

func TestFalsifierFactsUnsupported(t *testing.T) {
	for _, status := range []FalsifierVerificationStatus{FalsifierUnknown, FalsifierInsufficientScope, FalsifierContradicted} {
		facts := falsifierFacts(t, falsifierReport(status, []string{"ev-1"}, "fp-1"))
		if facts[FactFalsifierProposalPresent].Status != ObsSupports {
			t.Fatalf("%s: proposal presence = %+v", status, facts[FactFalsifierProposalPresent])
		}
		if got := facts[FactFalsifierAdmitted]; got.Status != ObsUnavailable || len(got.EvidenceRefs) != 0 {
			t.Fatalf("%s: admission = %+v", status, got)
		}
	}
}

func TestFalsifierFactsVerified(t *testing.T) {
	report := falsifierReport(FalsifierVerified, []string{"ev-1", "det-1"}, "fp-1")
	facts := falsifierFacts(t, report)
	if facts[FactFalsifierProposalPresent].Status != ObsSupports {
		t.Fatalf("presence = %+v", facts[FactFalsifierProposalPresent])
	}
	admitted := facts[FactFalsifierAdmitted]
	if admitted.Status != ObsSupports || len(admitted.EvidenceRefs) != 2 {
		t.Fatalf("admitted = %+v", admitted)
	}
	joined := strings.Join(admitted.Provenance, "|")
	for _, want := range []string{"falsifier-verification.v1", "proof:fp-1", "rule:rule-1@v1", "source:proposal"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("provenance %q lacks %q", joined, want)
		}
	}
	if decisionFactSet([]DecisionFact{facts[FactFalsifierProposalPresent], admitted})["falsifier.admitted"] != true {
		t.Fatal("admitted fact not decisive")
	}
}

func TestFalsifierFactsBasisMustBeCheckerVerified(t *testing.T) {
	report := falsifierReport(FalsifierVerified, []string{"ev-1"}, "fp-1")
	report.Proofs[0].Basis = BasisLLMProposed
	if got := falsifierFacts(t, report)[FactFalsifierAdmitted]; got.Status != ObsUnavailable {
		t.Fatalf("agent-proposed basis admitted: %+v", got)
	}
}

func kernelMintedReport(status FalsifierVerificationStatus) *FalsifierReport {
	r := falsifierReport(status, []string{"det-kernel"}, "kernel-proof")
	r.Proofs[0].ID = "kernel-proof"
	r.Proofs[0].ProposalID = ""
	r.Proofs[0].Kind = FalsifierCodeAbsent
	r.Proofs[0].RuleID = "rule-1"
	r.Proofs[0].RuleVersion = "1"
	r.Hash = reportHash(*r)
	return r
}

func TestFalsifierFactsKernelSource(t *testing.T) {
	facts := falsifierFacts(t, kernelMintedReport(FalsifierVerified))
	if got := facts[FactFalsifierProposalPresent]; got.Status != ObsRefutes || !strings.Contains(strings.Join(got.Provenance, "|"), "source:proposal") {
		t.Fatalf("proposal fact = %+v", got)
	}
	if got := facts[FactFalsifierKernelPresent]; got.Status != ObsSupports || !strings.Contains(strings.Join(got.Provenance, "|"), "source:kernel") {
		t.Fatalf("kernel fact = %+v", got)
	}
	admitted := facts[FactFalsifierAdmitted]
	joined := strings.Join(admitted.Provenance, "|")
	if admitted.Status != ObsSupports || !strings.Contains(joined, "source:kernel") || !strings.Contains(joined, "proof:kernel-proof") {
		t.Fatalf("admitted = %+v", admitted)
	}
	set := decisionFactSet([]DecisionFact{facts[FactFalsifierProposalPresent], facts[FactFalsifierKernelPresent], admitted})
	if set["falsifier.proposal_present"] != false || set["falsifier.kernel_present"] != true || set["falsifier.admitted"] != true {
		t.Fatalf("fact set = %v", set)
	}
}

func TestFalsifierFactsProposalSource(t *testing.T) {
	facts := falsifierFacts(t, falsifierReport(FalsifierVerified, []string{"det-proposal"}, "proposal-proof"))
	present, admitted := facts[FactFalsifierProposalPresent], facts[FactFalsifierAdmitted]
	if present.Status != ObsSupports || !strings.Contains(strings.Join(present.Provenance, "|"), "source:proposal") {
		t.Fatalf("present = %+v", present)
	}
	if admitted.Status != ObsSupports || !strings.Contains(strings.Join(admitted.Provenance, "|"), "source:proposal") || strings.Contains(strings.Join(admitted.Provenance, "|"), "source:kernel") {
		t.Fatalf("admitted = %+v", admitted)
	}
	if facts[FactFalsifierKernelPresent].Status != ObsRefutes {
		t.Fatalf("kernel = %+v", facts[FactFalsifierKernelPresent])
	}
}

func TestComposerVerifiedFalsifierDismissed(t *testing.T) {
	a := assessmentWithProposal(goodAssessment(), declaredProofProposal("fp-1", "c1", "cond-1"))
	pkg, err := Composer{}.ComposeWithEvidence(context.Background(), goodStage0(), a, completeValidation(), EvidenceInput{Falsifiers: falsifierReport(FalsifierVerified, []string{"ev-1"}, "fp-1")})
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	if pkg.MachineDisposition.Recommendation != RecommendationDismissed {
		t.Fatalf("recommendation = %s", pkg.MachineDisposition.Recommendation)
	}
	if !strings.Contains(strings.Join(pkg.MachineDisposition.Rationale.Basis, "|"), "rule verified-mandatory-code-falsifier satisfied") {
		t.Fatalf("rule basis = %v", pkg.MachineDisposition.Rationale.Basis)
	}
}

func TestComposerUnsupportedFalsifierUnchanged(t *testing.T) {
	a := assessmentWithProposal(goodAssessment(), declaredProofProposal("fp-1", "c1", "cond-1"))
	pkg, err := Composer{}.ComposeWithEvidence(context.Background(), goodStage0(), a, completeValidation(), EvidenceInput{Falsifiers: falsifierReport(FalsifierUnknown, []string{"ev-1"}, "fp-1")})
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	if pkg.MachineDisposition.Recommendation == RecommendationDismissed {
		t.Fatal("unsupported proof dismissed")
	}
	found := false
	for _, a := range pkg.MachineDisposition.ResidualAssumptions {
		if a.ID == "assumption-rule-verified-mandatory-code-falsifier" {
			found = true
		}
	}
	if !found {
		t.Fatalf("residual assumptions = %+v", pkg.MachineDisposition.ResidualAssumptions)
	}
}

func TestComposerNoFalsifierResidualWithoutProposal(t *testing.T) {
	pkg, err := Composer{}.ComposeWithEvidence(context.Background(), goodStage0(), goodAssessment(), completeValidation(), EvidenceInput{})
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	for _, a := range pkg.MachineDisposition.ResidualAssumptions {
		if a.ID == "assumption-rule-verified-mandatory-code-falsifier" {
			t.Fatalf("ordinary finding residual: %+v", a)
		}
	}
}

func TestComposerPartialFactValidationUnchanged(t *testing.T) {
	fv := completeValidation()
	fv.Status = ValidationPartial
	a := assessmentWithProposal(goodAssessment(), declaredProofProposal("fp-1", "c1", "cond-1"))
	pkg, err := Composer{}.ComposeWithEvidence(context.Background(), goodStage0(), a, fv, EvidenceInput{Falsifiers: falsifierReport(FalsifierVerified, []string{"ev-1"}, "fp-1")})
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	if pkg.MachineDisposition.Recommendation == RecommendationDismissed {
		t.Fatal("partial validation dismissed")
	}
}

func TestComposerAgentVerdictCannotOverride(t *testing.T) {
	a := goodAssessment()
	a.Verdict = VerdictNotExploitable
	pkg, err := Composer{}.ComposeWithEvidence(context.Background(), goodStage0(), a, completeValidation(), EvidenceInput{})
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	if pkg.MachineDisposition.Recommendation == RecommendationDismissed {
		t.Fatal("agent verdict alone dismissed")
	}
}

func TestComposerNoCrossCombination(t *testing.T) {
	report := falsifierReport(FalsifierVerified, []string{"ev-1"}, "fp-1")
	sibling := falsifierReport(FalsifierUnknown, []string{"det-9"}, "fp-2").Proofs[0]
	report.Proofs = append(report.Proofs, sibling)
	report.Hash = reportHash(*report)
	facts := falsifierFacts(t, report)
	admitted := facts[FactFalsifierAdmitted]
	if admitted.Status != ObsSupports || len(admitted.EvidenceRefs) != 1 || admitted.EvidenceRefs[0] != "ev-1" {
		t.Fatalf("admitted = %+v", admitted)
	}
	if got := falsifierFacts(t, falsifierReport(FalsifierUnknown, []string{"det-9"}, "fp-2"))[FactFalsifierAdmitted]; got.Status == ObsSupports {
		t.Fatalf("unsupported-only report admitted: %+v", got)
	}
}

func TestDefaultRulesOrderPreservesModuleAbsence(t *testing.T) {
	s0 := goodStage0()
	s0.PackageCheck = PackageCheckResult{Class: CheckModuleAbsent, ClaimedPath: "example.org/library", EvidenceSource: "module_graph", Reason: "module absent"}
	pkg, err := Composer{}.ComposeWithEvidence(context.Background(), s0, goodAssessment(), completeValidation(), EvidenceInput{})
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	if pkg.MachineDisposition.Recommendation != RecommendationDismissed {
		t.Fatalf("recommendation = %s", pkg.MachineDisposition.Recommendation)
	}
	if !strings.Contains(strings.Join(pkg.MachineDisposition.Rationale.Basis, "|"), "rule module-absent-falsifier satisfied") {
		t.Fatalf("basis = %v", pkg.MachineDisposition.Rationale.Basis)
	}
}

func TestComposerKernelProofDismissedWithoutProposal(t *testing.T) {
	pkg, err := Composer{}.ComposeWithEvidence(context.Background(), goodStage0(), goodAssessment(), completeValidation(), EvidenceInput{Falsifiers: kernelMintedReport(FalsifierVerified)})
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	if pkg.MachineDisposition.Recommendation != RecommendationDismissed {
		t.Fatalf("kernel recommendation = %s", pkg.MachineDisposition.Recommendation)
	}
	if !strings.Contains(strings.Join(pkg.MachineDisposition.Rationale.Basis, "|"), "falsifier proof source: kernel") {
		t.Fatalf("rationale lacks kernel source: %+v", pkg.MachineDisposition.Rationale)
	}
}

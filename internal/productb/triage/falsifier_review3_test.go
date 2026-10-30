package triage

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/fedorovmv/izyan/internal/evidencetools"
)

func TestFalsifierVerifierRulesetMismatch(t *testing.T) {
	s := sourceFixture()
	in, _ := verifierFixture(FalsifierCodeAbsent, s)
	in.ExpectedRulesetHash = "bad"
	if runProof(t, in, s).Status == FalsifierVerified {
		t.Fatal()
	}
	in.ExpectedRulesetHash = "rules-1"
	if runProof(t, in, s).Status != FalsifierVerified {
		t.Fatal()
	}
}
func TestFalsifierVerifierRunIdentity(t *testing.T) {
	s := sourceFixture()
	in, o := verifierFixture(FalsifierCodeAbsent, s)
	in.RunID = "a"
	o.RunID = "b"
	in.Observations = []RecordedObservation{*o}
	if runProof(t, in, s).Status == FalsifierVerified {
		t.Fatal()
	}
	o.RunID = "a"
	in.Observations = []RecordedObservation{*o}
	if runProof(t, in, s).Status != FalsifierVerified {
		t.Fatal()
	}
}
func TestFalsifierVerifierHistoryDemotion(t *testing.T) {
	s := sourceFixture()
	in, o := verifierFixture(FalsifierCodeAbsent, s)
	first := runProof(t, in, s)
	o.Completeness = evidencetools.CompletenessPartial
	in.Observations = []RecordedObservation{*o}
	in.Previous = &first
	p := runProof(t, in, s)
	if p.Status == FalsifierVerified || len(p.History) == 0 || p.History[0].From != FalsifierVerified || p.History[0].RuleID != "rule-1" {
		t.Fatalf("%+v", p.History)
	}
}

// TestFalsifierVerifierHashPermutationInvariance pins that the proof hash is a
// function of the semantic content only: equivalent inputs with permuted
// observations, proposals, evidence references, subjects and coverage entries
// hash identically, while any semantic change moves the hash.
func TestFalsifierVerifierHashPermutationInvariance(t *testing.T) {
	s := sourceFixture()
	s.condition.ExpectedSubjects = []FalsifierSubject{
		{Package: "example.org/p", Symbol: "Control"},
		{Package: "example.org/p", Symbol: "Wrapper"},
	}
	in, o := verifierFixture(FalsifierCodeAbsent, s)
	o2 := *o
	o2.ID = "det-2"
	o2.EvidenceRefs = []string{"det-2"}
	checked, _ := json.Marshal(map[string]any{"checked_subjects": s.condition.ExpectedSubjects, "absent_subjects": s.condition.ExpectedSubjects, "coverage_rule_version": "3", "import_closure": map[string]any{"complete": true, "hash": "closure-test-hash", "open_exceptions": []string{}}})
	o2.Payload = checked
	first, _ := json.Marshal(map[string]any{"checked_subjects": []FalsifierSubject{s.condition.ExpectedSubjects[1], s.condition.ExpectedSubjects[0]}, "absent_subjects": s.condition.ExpectedSubjects, "coverage_rule_version": "3", "import_closure": map[string]any{"complete": true, "hash": "closure-test-hash", "open_exceptions": []string{}}})
	o.Payload = first
	in.Observations = []RecordedObservation{*o, o2}
	in.Proposals[0].EvidenceRefs = []string{"det-1", "det-2"}
	in.Assessment.Claims[0].EvidenceRefs = []string{"det-1", "det-2"}
	in.FactValidation.References = append(in.FactValidation.References, ReferenceCheck{EvidenceID: "det-2", Status: FactValid, SnapshotHash: "snap-1"})
	v := NewFalsifierVerifier(s)
	base := v.Verify(context.Background(), in)

	// Same semantic set, every ordered collection reversed. The hash must not
	// move: it is a function of the content, never of the arrival order.
	perm := in
	perm.Observations = []RecordedObservation{o2, *o}
	perm.Proposals = append([]FalsifierProposal(nil), in.Proposals...)
	perm.Proposals[0].EvidenceRefs = []string{"det-2", "det-1"}
	perm.Assessment.Claims = append([]Claim(nil), in.Assessment.Claims...)
	perm.Assessment.Claims[0].EvidenceRefs = []string{"det-2", "det-1"}
	reversed, _ := json.Marshal(map[string]any{"checked_subjects": []FalsifierSubject{s.condition.ExpectedSubjects[0], s.condition.ExpectedSubjects[1]}, "absent_subjects": s.condition.ExpectedSubjects, "coverage_rule_version": "3", "import_closure": map[string]any{"complete": true, "hash": "closure-test-hash", "open_exceptions": []string{}}})
	perm.FactValidation.References[0], perm.FactValidation.References[1] = perm.FactValidation.References[1], perm.FactValidation.References[0]
	perm.Observations[1].Payload = reversed
	if got := v.Verify(context.Background(), perm); got.Hash != base.Hash {
		t.Fatalf("permuted input changed the hash: %s != %s", got.Hash, base.Hash)
	}

	// Semantic changes must move the hash. Each mutation is compared against
	// an unmutated input of exactly the same shape, so the check cannot pass
	// or fail for an unrelated reason.
	refSrc := sourceFixture()
	refSrc.condition = s.condition
	ref := NewFalsifierVerifier(refSrc).Verify(context.Background(), in)
	build := func(mutate func(in *FalsifierVerificationInput, s *testMandatorySource)) FalsifierReport {
		mutSrc := sourceFixture()
		mutSrc.condition = s.condition
		mutIn := in
		mutIn.Observations = append([]RecordedObservation(nil), in.Observations...)
		mutIn.Proposals = append([]FalsifierProposal(nil), in.Proposals...)
		mutIn.Proposals[0].EvidenceRefs = append([]string(nil), in.Proposals[0].EvidenceRefs...)
		mutIn.FactValidation = in.FactValidation
		mutIn.FactValidation.References = append([]ReferenceCheck(nil), in.FactValidation.References...)
		mutate(&mutIn, mutSrc)
		return NewFalsifierVerifier(mutSrc).Verify(context.Background(), mutIn)
	}
	mutations := map[string]func(in *FalsifierVerificationInput, s *testMandatorySource){
		"condition id": func(_ *FalsifierVerificationInput, s *testMandatorySource) { s.condition.ID = "cond-2" },
		"rule version": func(_ *FalsifierVerificationInput, s *testMandatorySource) { s.condition.RuleVersion = "v2" },
		"snapshot hash": func(in *FalsifierVerificationInput, _ *testMandatorySource) {
			for i := range in.Observations {
				in.Observations[i].SnapshotHash = "snap-2"
			}
		},
		"build context hash": func(in *FalsifierVerificationInput, _ *testMandatorySource) {
			in.Observations[0].BuildContextHash = "build-2"
		},
		"coverage status": func(in *FalsifierVerificationInput, _ *testMandatorySource) {
			in.Observations[0].Completeness = evidencetools.CompletenessPartial
		},
		"evidence reference": func(in *FalsifierVerificationInput, _ *testMandatorySource) {
			in.Proposals[0].EvidenceRefs = []string{"det-1"}
		},
		"expected subject": func(_ *FalsifierVerificationInput, s *testMandatorySource) {
			s.condition.ExpectedSubjects = s.condition.ExpectedSubjects[:1]
		},
		"proposal condition": func(in *FalsifierVerificationInput, _ *testMandatorySource) { in.Proposals[0].ConditionID = "cond-3" },
	}
	for name, mutate := range mutations {
		got := build(mutate)
		if ref.Hash == got.Hash {
			t.Fatalf("semantic change %q left the hash unchanged", name)
		}
	}
}
func TestFalsifierVerifierMixedCoverage(t *testing.T) {
	s := sourceFixture()
	in, o := verifierFixture(FalsifierCodeAbsent, s)
	in.Proposals[0].Subjects = append([]FalsifierSubject(nil), s.condition.ExpectedSubjects...)
	o2 := *o
	o2.ID = "d2"
	o2.EvidenceRefs = []string{"d2"}
	o2.Completeness = evidencetools.CompletenessPartial
	in.Proposals[0].EvidenceRefs = []string{"det-1", "d2"}
	in.Assessment.Claims[0].EvidenceRefs = []string{"det-1", "d2"}
	in.FactValidation.References = append(in.FactValidation.References, ReferenceCheck{EvidenceID: "d2", Status: FactValid, SnapshotHash: "snap-1"})
	in.Observations = []RecordedObservation{*o, o2}
	p := runProof(t, in, s)
	if p.Status == FalsifierVerified || p.Coverage.Completeness == "COMPLETE" {
		t.Fatal()
	}
}
func TestFalsifierVerifierLocusPackageAbsent(t *testing.T) {
	s := sourceFixture()
	s.condition.Kind = FalsifierLocusPackageAbsent
	in, o := verifierFixture(FalsifierLocusPackageAbsent, s)
	o.Tool = "verify_package_absence"
	in.Observations = []RecordedObservation{*o}
	in.Stage0.Materials.ModuleGraph = &ModuleGraph{Complete: true, Modules: []ModuleVersion{{Path: "other"}}}
	if runProof(t, in, s).Status != FalsifierVerified {
		t.Fatal()
	}
	in.Stage0.Materials.ModuleGraph.Complete = false
	if runProof(t, in, s).Status == FalsifierVerified {
		t.Fatal()
	}
	in.Stage0.Materials.ModuleGraph.Complete = true
	o.Tool = "search_text"
	in.Observations = []RecordedObservation{*o}
	if runProof(t, in, s).Status == FalsifierVerified {
		t.Fatal()
	}
}
func TestFalsifierVerifierClaimNotDecisionRelevant(t *testing.T) {
	s := sourceFixture()
	in, _ := verifierFixture(FalsifierCodeAbsent, s)
	in.Assessment.Claims[0].DecisionRelevant = false
	if runProof(t, in, s).Status == FalsifierVerified {
		t.Fatal()
	}
}
func TestFalsifierVerifierForeignClaimRefs(t *testing.T) {
	s := sourceFixture()
	in, _ := verifierFixture(FalsifierCodeAbsent, s)
	in.Assessment.Claims[0].EvidenceRefs = nil
	if runProof(t, in, s).Status == FalsifierVerified {
		t.Fatal()
	}
}
func TestFalsifierVerifierInvalidRefs(t *testing.T) {
	for _, st := range []FactStatus{FactInvalid, FactUnavailable} {
		s := sourceFixture()
		in, _ := verifierFixture(FalsifierCodeAbsent, s)
		in.FactValidation.References[0].Status = st
		if runProof(t, in, s).Status == FalsifierVerified {
			t.Fatal()
		}
	}
}

// TestFalsifierVerifierForeignSourceCondition pins both directions of the
// kind binding: the authoritative condition kind must match the proposal, and
// the same input with a matching kind must be admitted — otherwise the test
// would pass for the wrong reason.
func TestFalsifierVerifierForeignSourceCondition(t *testing.T) {
	s := sourceFixture()
	s.condition.Kind = FalsifierLocusFunctionAbsent
	in, _ := verifierFixture(FalsifierCodeAbsent, s)
	if runProof(t, in, s).Status == FalsifierVerified {
		t.Fatal("condition kind mismatch admitted")
	}
	s.condition.Kind = FalsifierCodeAbsent
	if runProof(t, in, s).Status != FalsifierVerified {
		t.Fatal("matching condition kind rejected")
	}
}

// TestFalsifierVerifierAliasVariants pins that an alias/wrapper variant the
// authoritative source expects can only be admitted once the observation
// actually covers it.
func TestFalsifierVerifierAliasVariants(t *testing.T) {
	s := sourceFixture()
	wrapper := FalsifierSubject{Package: "example.org/p", Symbol: "Wrapper"}
	s.condition.ExpectedSubjects = append(s.condition.ExpectedSubjects, wrapper)
	in, o := verifierFixture(FalsifierCodeAbsent, s)
	if runProof(t, in, s).Status == FalsifierVerified {
		t.Fatal("uncovered alias variant admitted")
	}
	var data map[string]any
	if err := json.Unmarshal(o.Payload, &data); err != nil { t.Fatal(err) }
	data["checked_subjects"], data["absent_subjects"] = s.condition.ExpectedSubjects, s.condition.ExpectedSubjects
	payload, _ := json.Marshal(data)
	o.Payload = payload
	in.Observations = []RecordedObservation{*o}
	if runProof(t, in, s).Status != FalsifierVerified {
		t.Fatal("covered alias variant rejected")
	}
}
func TestFalsifierVerifierTruncatedFields(t *testing.T) {
	s := sourceFixture()
	in, o := verifierFixture(FalsifierCodeAbsent, s)
	o.Limitations = []string{"truncated", "load budget exhausted"}
	in.Observations = []RecordedObservation{*o}
	if runProof(t, in, s).Status == FalsifierVerified {
		t.Fatal()
	}
}

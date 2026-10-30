package triage

import "testing"

func TestFalsifierVerifierBuildContextBinding(t *testing.T) {
	s := sourceFixture()
	in, o := verifierFixture(FalsifierCodeAbsent, s)
	o.BuildContextHash = "changed"
	in.Observations = []RecordedObservation{*o}
	if runProof(t, in, s).Status == FalsifierVerified {
		t.Fatal()
	}
	o.BuildContextHash = ""
	in.Observations = []RecordedObservation{*o}
	if runProof(t, in, s).Status == FalsifierVerified {
		t.Fatal()
	}
}
func TestFalsifierVerifierAttemptIdentity(t *testing.T) {
	s := sourceFixture()
	in, o := verifierFixture(FalsifierCodeAbsent, s)
	o.Attempt = 2
	in.Observations = []RecordedObservation{*o}
	if runProof(t, in, s).Status == FalsifierVerified {
		t.Fatal()
	}
}
func TestFalsifierVerifierPreviousProofBinding(t *testing.T) {
	s := sourceFixture()
	in, o := verifierFixture(FalsifierCodeAbsent, s)
	prev := runProof(t, in, s)
	prev.ClaimID = "other"
	o.Completeness = "PARTIAL"
	in.Observations = []RecordedObservation{*o}
	in.Previous = &prev
	p := runProof(t, in, s)
	for _, h := range p.History {
		if h.From == FalsifierVerified {
			t.Fatal("foreign previous proof used")
		}
	}
}

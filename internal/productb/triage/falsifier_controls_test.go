package triage

import (
	"encoding/json"
	"testing"

	"github.com/fedorovmv/izyan/internal/evidencetools"
)

// controlProof is deliberately small: every control names the status it
// expects, rather than treating any non-VERIFIED result as success.
func controlProof(t *testing.T, kind FalsifierKind, mutate func(*FalsifierVerificationInput, *RecordedObservation, *testMandatorySource), want FalsifierVerificationStatus) FalsifierProof {
	t.Helper()
	s := sourceFixture()
	s.condition.Kind = kind
	in, o := verifierFixture(kind, s)
	mutate(&in, o, s)
	in.Observations = []RecordedObservation{*o}
	p := runProof(t, in, s)
	if p.Status != want {
		t.Fatalf("status=%s, want %s (reason=%s)", p.Status, want, p.Reason)
	}
	return p
}

func dynamicControl(marker string) func(*FalsifierVerificationInput, *RecordedObservation, *testMandatorySource) {
	return func(_ *FalsifierVerificationInput, o *RecordedObservation, _ *testMandatorySource) {
		o.Payload = json.RawMessage(`{"checked_subjects":[{"package":"example.org/p","symbol":"Control"}],"absent_subjects":[{"package":"example.org/p","symbol":"Control"}],"coverage_rule_version":"3","import_closure":{"complete":true,"hash":"closure-test-hash","dynamic_markers":["` + marker + `"],"open_exceptions":["` + marker + `"]}}`)
	}
}

func TestFalsifierControlWrapperReachable(t *testing.T) {
	controlProof(t, FalsifierCodeAbsent, dynamicControl("wrapper_reachable"), FalsifierInsufficientScope)
}
func TestFalsifierControlAlternateImplementation(t *testing.T) {
	controlProof(t, FalsifierCodeAbsent, dynamicControl("alternate_implementation"), FalsifierInsufficientScope)
}
func TestFalsifierControlPackageAlias(t *testing.T) {
	controlProof(t, FalsifierCodeAbsent, dynamicControl("package_alias"), FalsifierInsufficientScope)
}
func TestFalsifierControlInterfaceDispatch(t *testing.T) {
	controlProof(t, FalsifierCodeAbsent, func(in *FalsifierVerificationInput, o *RecordedObservation, _ *testMandatorySource) {
		o.Payload = json.RawMessage(`{"checked_subjects":[{"package":"example.org/p","symbol":"Control"}],"unresolved_dispatch":["interface"]}`)
		in.Observations = []RecordedObservation{*o}
	}, FalsifierInsufficientScope)
}
func TestFalsifierControlFunctionValue(t *testing.T) {
	controlProof(t, FalsifierCodeAbsent, dynamicControl("func_value"), FalsifierInsufficientScope)
}
func TestFalsifierControlReflectionDispatch(t *testing.T) {
	controlProof(t, FalsifierCodeAbsent, dynamicControl("reflection_dispatch"), FalsifierInsufficientScope)
}
func TestFalsifierControlLinkname(t *testing.T) {
	controlProof(t, FalsifierCodeAbsent, dynamicControl("go:linkname"), FalsifierInsufficientScope)
}
func TestFalsifierControlPluginPath(t *testing.T) {
	controlProof(t, FalsifierCodeAbsent, dynamicControl("plugin_path"), FalsifierInsufficientScope)
}
func TestFalsifierControlBuildTagOnly(t *testing.T) {
	controlProof(t, FalsifierCodeAbsent, dynamicControl("build_tag_gap"), FalsifierInsufficientScope)
}
func TestFalsifierControlSkippedPackage(t *testing.T) {
	controlProof(t, FalsifierCodeAbsent, func(_ *FalsifierVerificationInput, o *RecordedObservation, _ *testMandatorySource) {
		o.Limitations = []string{"package loading skipped part of the product/source universe"}
	}, FalsifierInsufficientScope)
}
func TestFalsifierControlTruncatedOutput(t *testing.T) {
	controlProof(t, FalsifierCodeAbsent, func(_ *FalsifierVerificationInput, o *RecordedObservation, _ *testMandatorySource) {
		o.Completeness = evidencetools.CompletenessPartial
		o.Limitations = []string{"package-load budget exhausted; enumeration is truncated"}
	}, FalsifierInsufficientScope)
}
func TestFalsifierControlIncompleteGraph(t *testing.T) {
	controlProof(t, FalsifierLocusPackageAbsent, func(in *FalsifierVerificationInput, o *RecordedObservation, _ *testMandatorySource) {
		o.Tool = "verify_package_absence"
		in.Stage0.Materials.ModuleGraph = &ModuleGraph{}
	}, FalsifierInsufficientScope)
}
func TestFalsifierControlWrongBinding(t *testing.T) {
	controlProof(t, FalsifierCodeAbsent, func(_ *FalsifierVerificationInput, _ *RecordedObservation, s *testMandatorySource) {
		s.condition.ID = "other-condition"
	}, FalsifierUnknown)
}
func TestFalsifierControlSecondMechanism(t *testing.T) {
	controlProof(t, FalsifierCodeAbsent, dynamicControl("second_mechanism"), FalsifierInsufficientScope)
}
func TestFalsifierControlFalseProposal(t *testing.T) {
	controlProof(t, FalsifierCodeAbsent, func(_ *FalsifierVerificationInput, _ *RecordedObservation, s *testMandatorySource) {
		s.condition.Mandatory = false
	}, FalsifierUnknown)
}
func TestFalsifierControlGenuineSafe(t *testing.T) {
	p := controlProof(t, FalsifierCodeAbsent, func(_ *FalsifierVerificationInput, _ *RecordedObservation, _ *testMandatorySource) {}, FalsifierVerified)
	if !p.Mandatory || p.Basis != BasisCheckerVerified {
		t.Fatalf("proof is not an approved mandatory checker proof: %+v", p)
	}
}
func TestFalsifierControlMisleadingZeroSearch(t *testing.T) {
	controlProof(t, FalsifierCodeAbsent, func(_ *FalsifierVerificationInput, o *RecordedObservation, _ *testMandatorySource) {
		o.Tool = "search_text"
		o.Payload = json.RawMessage(`{"checked_subjects":[{"package":"example.org/p","symbol":"Control"}],"matches":0}`)
	}, FalsifierUnknown)
}
func TestFalsifierControlFunctionUnreached(t *testing.T) {
	controlProof(t, FalsifierLocusFunctionAbsent, func(_ *FalsifierVerificationInput, _ *RecordedObservation, _ *testMandatorySource) {}, FalsifierInsufficientScope)
}
func TestFalsifierControlValidationWithoutProof(t *testing.T) {
	controlProof(t, FalsifierCodeAbsent, func(_ *FalsifierVerificationInput, o *RecordedObservation, _ *testMandatorySource) {
		o.Tool = "search_text"
	}, FalsifierUnknown)
}
func TestFalsifierControlModuleAbsenceRegression(t *testing.T) {
	p := controlProof(t, FalsifierLocusPackageAbsent, func(in *FalsifierVerificationInput, o *RecordedObservation, s *testMandatorySource) {
		in.Stage0.Materials.ModuleGraph = &ModuleGraph{Complete: true, Modules: []ModuleVersion{{Path: "example.org/library"}}}
		s.condition.ExpectedSubjects = []FalsifierSubject{{Package: "example.org/missing", Symbol: "Control"}}
		in.Proposals[0].Subjects = append([]FalsifierSubject(nil), s.condition.ExpectedSubjects...)
		o.Tool = "verify_package_absence"
		o.Payload = json.RawMessage(`{"checked_subjects":[{"package":"example.org/missing","symbol":"Control"}]}`)
	}, FalsifierVerified)
	if p.Status != FalsifierVerified {
		t.Fatalf("module absence regression status=%s", p.Status)
	}
}

// A foreign-tool observation cited beside the absence check may never
// contribute subjects to the coverage: the code_absent coverage reads
// only the verify_code_absence record.
func TestFalsifierControlMixedToolCoverage(t *testing.T) {
	s := sourceFixture()
	s.condition.ExpectedSubjects = append(s.condition.ExpectedSubjects, FalsifierSubject{Package: "example.org/p", Symbol: "Wrapper"})
	in, o := verifierFixture(FalsifierCodeAbsent, s)
	in.Proposals[0].Subjects = append([]FalsifierSubject(nil), s.condition.ExpectedSubjects...)
	// The owning observation is a complete, closure-backed success. The
	// foreign COMPLETE observation carries a different false absence and
	o.Payload = json.RawMessage(`{"checked_subjects":[{"package":"example.org/p","symbol":"Control"},{"package":"example.org/p","symbol":"Wrapper"}],"absent_subjects":[{"package":"example.org/p","symbol":"Control"},{"package":"example.org/p","symbol":"Wrapper"}],"coverage_rule_version":"3","import_closure":{"complete":true,"hash":"owning-hash","open_exceptions":[]}}`)
	foreign := *o
	foreign.ID = "foreign-1"
	foreign.Tool = "search_text"
	foreign.Payload = json.RawMessage(`{"checked_subjects":[{"package":"example.org/p","symbol":"Control"}],"absent_subjects":[],"present_subjects":[{"package":"example.org/p","symbol":"Control"}],"coverage_rule_version":"3","import_closure":{"complete":true,"hash":"foreign-hash","open_exceptions":[]}}`)
	p := runProof(t, in, s)
	if p.Status == FalsifierVerified {
		t.Fatalf("foreign-tool coverage admitted: %+v", p)
	}
	if p.Status != FalsifierUnknown && p.Status != FalsifierInsufficientScope {
		t.Fatalf("status=%s must remain conservative (reason=%s)", p.Status, p.Reason)
	}
}

// Two verify_code_absence observations disagreeing on the closure hash
// describe different inventories — the proof can never admit a merge.
func TestFalsifierControlClosureHashConflict(t *testing.T) {
	s := sourceFixture()
	in, o := verifierFixture(FalsifierCodeAbsent, s)
	other := *o
	other.ID = "det-2"
	other.Payload = json.RawMessage(`{"checked_subjects":[{"package":"example.org/p","symbol":"Control"}],"absent_subjects":[{"package":"example.org/p","symbol":"Control"}],"coverage_rule_version":"3","import_closure":{"complete":true,"hash":"different-hash","open_exceptions":[]}}`)
	in.Proposals[0].EvidenceRefs = []string{"det-1", "det-2"}
	in.Assessment.Claims[0].EvidenceRefs = []string{"det-1", "det-2"}
	in.FactValidation.References = append(in.FactValidation.References, ReferenceCheck{EvidenceID: "det-2", Status: FactValid, SnapshotHash: "snap-1"})
	in.Observations = []RecordedObservation{*o, other}
	p := runProof(t, in, s)
	if p.Status == FalsifierVerified {
		t.Fatalf("conflicting closure hashes admitted: %+v", p)
	}
	if len(p.Coverage.OpenExceptions) == 0 || p.Coverage.ClosureComplete {
		t.Fatalf("hash conflict must stay an open exception: %+v", p)
	}
}

// A legacy verify_code_absence payload with every other absence field
// complete but a stale rule version is non-admitting.
func TestFalsifierControlStaleCoverageRule(t *testing.T) {
	controlProof(t, FalsifierCodeAbsent, func(_ *FalsifierVerificationInput, o *RecordedObservation, _ *testMandatorySource) {
		o.Payload = json.RawMessage(`{"checked_subjects":[{"package":"example.org/p","symbol":"Control"}],"absent_subjects":[{"package":"example.org/p","symbol":"Control"}],"coverage_rule_version":"2","import_closure":{"complete":true,"hash":"closure-test-hash","open_exceptions":[]}}`)
	}, FalsifierInsufficientScope)
}

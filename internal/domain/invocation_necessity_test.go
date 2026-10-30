package domain

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// defectiveContract is the minimal DEFECTIVE_CHECK contract shape the
// deadness-premise tests derive from.
func deadnessDefectiveContract() *DefectSemanticsContract {
	return &DefectSemanticsContract{
		Mode:     DefectSemanticsDefectiveCheck,
		RecordID: "GO-TEST-DEFECT",
		Check:    testCheck(),
	}
}

func deadnessOmissionContract() *DefectSemanticsContract {
	pipeline := SymbolRef{Package: "example.com/dep/pipeline", Symbol: "Claims.Valid"}
	return &DefectSemanticsContract{
		Mode:     DefectSemanticsOmittedCheck,
		RecordID: "GO-TEST-OMISSION",
		Check:    testCheck(),
		Pipeline: &pipeline,
	}
}

func TestDeadnessPremiseDerivation(t *testing.T) {
	if _, err := (*DefectSemanticsContract)(nil).DeadnessPremise(); !errors.Is(err, ErrDeadnessPremiseUnavailable) {
		t.Fatalf("nil contract error = %v, want ErrDeadnessPremiseUnavailable", err)
	}

	unresolved := &DefectSemanticsContract{
		Mode: DefectSemanticsUnresolved, RecordID: "GO-TEST-UNRESOLVED", Check: testCheck(),
		UnresolvedReason: SemanticsEvidenceMissing,
	}
	if _, err := unresolved.DeadnessPremise(); !errors.Is(err, ErrDeadnessPremiseUnavailable) {
		t.Fatalf("unresolved contract error = %v, want ErrDeadnessPremiseUnavailable", err)
	}

	defective, err := deadnessDefectiveContract().DeadnessPremise()
	if err != nil {
		t.Fatalf("defective premise: %v", err)
	}
	if !defective.Admitted() || defective.Mode != DefectSemanticsDefectiveCheck || defective.Locus != testCheck() {
		t.Fatalf("defective premise = %+v", defective)
	}
	if !defective.Covers([]SymbolRef{testCheck()}) {
		t.Fatal("defective premise must cover the contracted check")
	}
	if defective.Covers([]SymbolRef{{Package: "example.com/other", Symbol: "X"}}) {
		t.Fatal("defective premise must not cover an unrelated symbol")
	}

	omitted, err := deadnessOmissionContract().DeadnessPremise()
	if err != nil {
		t.Fatalf("omission premise: %v", err)
	}
	if omitted.Locus.Symbol != "Claims.Valid" {
		t.Fatalf("omission premise locus = %+v, want the omission-site pipeline", omitted.Locus)
	}
	// The absent check's deadness is consistent with omission, not a
	// premise: the check-only set must be refused.
	if _, err := RequireDeadnessPremise(deadnessOmissionContract(), []SymbolRef{testCheck()}); !errors.Is(err, ErrDeadnessPremiseUnavailable) {
		t.Fatalf("check-only omission proof error = %v, want ErrDeadnessPremiseUnavailable", err)
	}
	if _, err := RequireDeadnessPremise(deadnessOmissionContract(), []SymbolRef{*deadnessOmissionContract().Pipeline}); err != nil {
		t.Fatalf("omission-site proof refused: %v", err)
	}
}

func TestDeadnessPremiseRequiresCoverage(t *testing.T) {
	if _, err := RequireDeadnessPremise(deadnessDefectiveContract(), []SymbolRef{{Package: "example.com/other", Symbol: "X"}}); !errors.Is(err, ErrDeadnessPremiseUnavailable) {
		t.Fatalf("uncovered defective proof error = %v", err)
	}
	if _, err := RequireDeadnessPremise(nil, []SymbolRef{testCheck()}); !errors.Is(err, ErrDeadnessPremiseUnavailable) {
		t.Fatalf("nil contract proof error = %v", err)
	}
}

func TestDeadnessPremiseIsNotForgeableByJSON(t *testing.T) {
	premise, err := deadnessDefectiveContract().DeadnessPremise()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(premise)
	if err != nil {
		t.Fatal(err)
	}
	var decoded DeadnessPremise
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Admitted() {
		t.Fatal("a decoded premise must not be admitted")
	}
	if decoded.Covers([]SymbolRef{testCheck()}) {
		t.Fatal("a decoded premise must cover nothing")
	}
}

func TestValidateDeadnessPremiseUsesAdmittedModel(t *testing.T) {
	model, evidence := testDefectiveModel()
	premise, err := ValidateDeadnessPremise(&model, []SymbolRef{testCheck()}, evidence)
	if err != nil {
		t.Fatalf("admitted defective model refused: %v", err)
	}
	if premise.Mode != DefectSemanticsDefectiveCheck {
		t.Fatalf("premise = %+v", premise)
	}

	// A legacy omission model without the contract is refused even when the
	// dead set names the check.
	legacy := &ExploitModel{MandatoryConditions: []Condition{{
		ID: "C-OMISSION", Kind: ConditionMissingCall, Mandatory: true,
		Subjects: []SymbolRef{testCheck()},
		Params:   map[string]string{ParamCheck: CheckMissingCall, "pipeline": "Claims.Valid"},
	}}}
	if _, err := ValidateDeadnessPremise(legacy, []SymbolRef{testCheck()}, nil); err == nil {
		t.Fatal("legacy omission model admitted a deadness premise")
	}

	// An ordinary model without semantic claims keeps the advisory-symbol
	// route.
	ordinary := &ExploitModel{MandatoryConditions: []Condition{{
		ID: "C-REACH", Kind: ConditionSymbolReachable, Mandatory: true,
		Subjects: []SymbolRef{testCheck()},
	}}}
	if _, err := ValidateDeadnessPremise(ordinary, []SymbolRef{testCheck()}, nil); err != nil {
		t.Fatalf("ordinary model refused: %v", err)
	}
	if !ModelCarriesSemanticClaims(legacy) || ModelCarriesSemanticClaims(ordinary) {
		t.Fatal("ModelCarriesSemanticClaims misclassified a model")
	}
}

func TestDeadnessPremiseBasisNamesTheLocusKind(t *testing.T) {
	defective, _ := deadnessDefectiveContract().DeadnessPremise()
	omitted, _ := deadnessOmissionContract().DeadnessPremise()
	if !strings.Contains(defective.Basis, "invoked") {
		t.Fatalf("defective basis = %q", defective.Basis)
	}
	if !strings.Contains(omitted.Basis, "omission site") {
		t.Fatalf("omission basis = %q", omitted.Basis)
	}
}

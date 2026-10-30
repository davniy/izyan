package domain

import (
	"errors"
	"strings"
	"testing"
)

func testCheck() SymbolRef {
	return SymbolRef{Package: "example.com/dep/check", Symbol: "Claims.VerifyAudience"}
}

func testTriggerSpec() CheckTriggerSpec {
	return CheckTriggerSpec{
		Operation: testCheck(),
		Argument:  CheckArgumentPredicate{Name: "req", Index: 1, Value: "false"},
		Payload: CheckPayloadPredicate{
			ReceiverField:  "aud",
			Shapes:         []string{"array"},
			ExcludedShapes: []string{"string"},
		},
		Effect: "audience verification is bypassed",
	}
}

func testAdvisoryEvidence() Evidence {
	return Evidence{
		ID:      "EV-ADV",
		Kind:    EvidenceAdvisory,
		Quality: QualityAuthoritative,
		Content: "Claims.VerifyAudience is called with req set to false when the audience claim is an array of strings, rather than a single string.",
	}
}

func testDefectiveModel() (ExploitModel, []Evidence) {
	spec := testTriggerSpec()
	adv := testAdvisoryEvidence()
	contract := &DefectSemanticsContract{
		Mode:               DefectSemanticsDefectiveCheck,
		RecordID:           "GO-TEST-CHECK",
		Check:              testCheck(),
		Trigger:            &spec,
		TriggerConditionID: CheckTriggerConditionID,
		Grounds: []DefectSemanticsGround{{
			Claim:          SemanticsGroundAdvisoryInvocation,
			EvidenceID:     adv.ID,
			EvidenceKind:   adv.Kind,
			EvidenceDigest: EvidenceContentDigest(adv.Content),
			Quote:          "Claims.VerifyAudience is called with req set to false",
		}},
	}
	model := ExploitModel{
		RootCauses:      []SymbolRef{testCheck()},
		DefectSemantics: contract,
		MandatoryConditions: []Condition{
			{
				ID: "C-REACH", Kind: ConditionSymbolReachable, Mandatory: true,
				Subjects: []SymbolRef{testCheck()},
				Params: map[string]string{
					ParamCheck:     CheckInvocation,
					ParamOperation: "example.com/dep/check.Claims.VerifyAudience",
				},
			},
			{
				ID: "C-INPUT", Kind: ConditionCheckInput, Mandatory: true,
				Subjects: []SymbolRef{testCheck()}, ArgIndex: ArgReceiver,
				Params: CheckInputParams(spec),
			},
			{
				ID: "C-CHECK-TRIGGER", Kind: ConditionCheckTrigger, Mandatory: true,
				Subjects: []SymbolRef{testCheck()}, ArgIndex: spec.Argument.Index,
				Params: CheckTriggerParams(spec),
			},
			{
				ID: "C-LOCUS", Kind: ConditionSymbolReachable, Mandatory: true,
				Subjects: []SymbolRef{testCheck()},
				Params:   map[string]string{ParamCheck: CheckLocus},
			},
		},
	}
	return model, []Evidence{adv}
}

func TestDefectSemanticsModelAdmission(t *testing.T) {
	model, evidence := testDefectiveModel()
	if err := ValidateDefectSemanticsModel(model, evidence); err != nil {
		t.Fatalf("valid defective model rejected: %v", err)
	}

	t.Run("missing trigger condition", func(t *testing.T) {
		broken := model
		broken.MandatoryConditions = broken.MandatoryConditions[:2]
		if err := ValidateDefectSemanticsModel(broken, evidence); err == nil {
			t.Fatal("model without the dedicated trigger condition admitted")
		}
	})

	t.Run("omission condition in defective model", func(t *testing.T) {
		broken := model
		broken.MandatoryConditions = append(append([]Condition(nil), model.MandatoryConditions...), Condition{
			ID: "C-OMISSION", Kind: ConditionMissingCall, Mandatory: true,
			Subjects: []SymbolRef{testCheck()},
			Params:   map[string]string{ParamCheck: CheckMissingCall, "pipeline": "Claims.Valid"},
		})
		if err := ValidateDefectSemanticsModel(broken, evidence); err == nil {
			t.Fatal("defective contract admitted an omission conjunction")
		}
	})

	t.Run("drifted trigger params", func(t *testing.T) {
		broken := model
		broken.MandatoryConditions = append([]Condition(nil), model.MandatoryConditions...)
		for i := range broken.MandatoryConditions {
			if broken.MandatoryConditions[i].ID == "C-CHECK-TRIGGER" {
				broken.MandatoryConditions[i].Params[ParamArgumentValue] = "true"
			}
		}
		if err := ValidateDefectSemanticsModel(broken, evidence); err == nil {
			t.Fatal("trigger condition drifted from the admitted contract")
		}
	})

	t.Run("unresolved contract never admitted", func(t *testing.T) {
		broken := model
		contractCopy := *model.DefectSemantics
		contractCopy.Mode = DefectSemanticsUnresolved
		contractCopy.UnresolvedReason = SemanticsEvidenceMissing
		contractCopy.UnresolvedDetail = "no mechanism statement"
		broken.DefectSemantics = &contractCopy
		if err := ValidateDefectSemanticsModel(broken, evidence); err == nil {
			t.Fatal("unresolved contract admitted as a decidable model")
		}
	})

	t.Run("omission without contract", func(t *testing.T) {
		broken := ExploitModel{MandatoryConditions: []Condition{{
			ID: "C-OMISSION", Kind: ConditionMissingCall, Mandatory: true,
			Subjects: []SymbolRef{testCheck()},
			Params:   map[string]string{ParamCheck: CheckMissingCall, "pipeline": "Claims.Valid"},
		}}}
		if err := ValidateDefectSemanticsModel(broken, nil); err == nil {
			t.Fatal("legacy omission conjunction admitted without a contract")
		}
	})

	t.Run("trigger without contract", func(t *testing.T) {
		broken := ExploitModel{MandatoryConditions: []Condition{{
			ID: CheckTriggerConditionID, Kind: ConditionCheckTrigger, Mandatory: true,
			Subjects: []SymbolRef{testCheck()}, ArgIndex: 1,
		}}}
		if err := ValidateDefectSemanticsModel(broken, nil); err == nil {
			t.Fatal("check-trigger conjunction admitted without a contract")
		}
	})

	t.Run("reach not bound to the invocation", func(t *testing.T) {
		broken := model
		broken.MandatoryConditions = append([]Condition(nil), model.MandatoryConditions...)
		for i := range broken.MandatoryConditions {
			if broken.MandatoryConditions[i].ID == "C-REACH" {
				delete(broken.MandatoryConditions[i].Params, ParamCheck)
			}
		}
		if err := ValidateDefectSemanticsModel(broken, evidence); err == nil {
			t.Fatal("reachability of the sibling pipeline passed as invocation reach")
		}
	})
}

func TestDefectSemanticsGroundStaleness(t *testing.T) {
	model, evidence := testDefectiveModel()

	t.Run("changed evidence content", func(t *testing.T) {
		stale := []Evidence{testAdvisoryEvidence()}
		stale[0].Content = evidence[0].Content + " (edited)"
		if err := ValidateDefectSemanticsModel(model, stale); err == nil {
			t.Fatal("stale evidence digest admitted")
		}
	})

	t.Run("missing evidence", func(t *testing.T) {
		if err := ValidateDefectSemanticsModel(model, nil); err == nil {
			t.Fatal("missing ground evidence admitted")
		}
	})

	t.Run("contradictory ground", func(t *testing.T) {
		broken := model
		contractCopy := *model.DefectSemantics
		contractCopy.Grounds = append([]DefectSemanticsGround(nil), model.DefectSemantics.Grounds...)
		contractCopy.Grounds = append(contractCopy.Grounds, DefectSemanticsGround{
			Claim:          SemanticsGroundAdvisoryOmission,
			EvidenceID:     evidence[0].ID,
			EvidenceKind:   evidence[0].Kind,
			EvidenceDigest: EvidenceContentDigest(evidence[0].Content),
			Quote:          "Claims.VerifyAudience is called with req set to false",
		})
		broken.DefectSemantics = &contractCopy
		if err := ValidateDefectSemanticsModel(broken, evidence); err == nil {
			t.Fatal("contradictory mechanism ground admitted")
		}
	})
}

func TestCheckTriggerWitnessBinding(t *testing.T) {
	spec := testTriggerSpec()
	check := testCheck()

	control := Evidence{
		ID: "EV-FLOW", Kind: EvidenceDataFlow, Quality: QualityDeterministic,
		Content: "external request token feeds the claims map",
	}
	base := func() CheckTriggerWitness {
		return CheckTriggerWitness{
			ConditionID:        "C-CHECK-TRIGGER",
			Operation:          check,
			Invocation:         CallSite{File: "map_claims.go", Line: 17, Function: "VerifyAudience", Receiver: "m", Package: "example.com/dep/check"},
			Receiver:           "m",
			ReceiverType:       "Claims",
			ArgumentName:       "req",
			ArgumentIndex:      1,
			ArgumentValue:      "false",
			ReceiverField:      "aud",
			PayloadShapes:      []string{"array"},
			ControlOrigin:      OriginExternalUntrusted,
			ControlEvidenceIDs: []EvidenceID{control.ID},
		}
	}
	witnessEvidence := func(w CheckTriggerWitness) Evidence {
		return Evidence{
			ID: "EV-WITNESS", Kind: EvidenceValidation, Quality: QualityDeterministic,
			Content: "typed check-trigger witness", CheckTrigger: &w,
		}
	}
	evidenceWith := func(w CheckTriggerWitness) []Evidence {
		return []Evidence{witnessEvidence(w), control}
	}

	t.Run("full array req=false binds", func(t *testing.T) {
		match, reasons := MatchCheckTriggerWitness(spec, "C-CHECK-TRIGGER", evidenceWith(base()), CheckTriggerObligationFull)
		if match == nil {
			t.Fatalf("valid witness rejected: %v", reasons)
		}
		if match.EvidenceID != "EV-WITNESS" {
			t.Fatalf("match evidence = %s", match.EvidenceID)
		}
		if _, reasons := MatchCheckTriggerWitness(spec, "C-CHECK-TRIGGER", evidenceWith(base()), CheckTriggerObligationInput); len(reasons) != 0 {
			t.Fatalf("input obligation rejected a valid receiver-field witness: %v", reasons)
		}
	})

	t.Run("string payload rejected", func(t *testing.T) {
		w := base()
		w.PayloadShapes = []string{"string"}
		if match, _ := MatchCheckTriggerWitness(spec, "C-CHECK-TRIGGER", evidenceWith(w), CheckTriggerObligationFull); match != nil {
			t.Fatal("string payload satisfied an array-only contract")
		}
	})

	t.Run("req=true rejected for trigger but not receiver input", func(t *testing.T) {
		w := base()
		w.ArgumentValue = "true"
		if match, _ := MatchCheckTriggerWitness(spec, "C-CHECK-TRIGGER", evidenceWith(w), CheckTriggerObligationFull); match != nil {
			t.Fatal("req=true satisfied a req=false contract")
		}
		if match, reasons := MatchCheckTriggerWitness(spec, "C-CHECK-TRIGGER", evidenceWith(w), CheckTriggerObligationInput); match == nil {
			t.Fatalf("receiver-field input obligation should not depend on the argument literal: %v", reasons)
		}
	})

	t.Run("wrong argument name rejected", func(t *testing.T) {
		w := base()
		w.ArgumentName = "required"
		if match, _ := MatchCheckTriggerWitness(spec, "C-CHECK-TRIGGER", evidenceWith(w), CheckTriggerObligationFull); match != nil {
			t.Fatal("witness with the wrong argument name admitted")
		}
	})

	t.Run("wrong receiver field rejected", func(t *testing.T) {
		w := base()
		w.ReceiverField = "sub"
		if match, _ := MatchCheckTriggerWitness(spec, "C-CHECK-TRIGGER", evidenceWith(w), CheckTriggerObligationFull); match != nil {
			t.Fatal("wrong receiver field satisfied the payload predicate")
		}
	})

	t.Run("cross-call assembly rejected", func(t *testing.T) {
		first := base()
		first.PayloadShapes = []string{"string"}
		second := base()
		second.ArgumentValue = "true"
		second.Invocation = CallSite{File: "other.go", Line: 99, Function: "Other", Receiver: "m", Package: "example.com/dep/check"}
		secondEv := witnessEvidence(second)
		secondEv.ID = "EV-WITNESS-2"
		evidence := []Evidence{witnessEvidence(first), secondEv, control}
		if match, _ := MatchCheckTriggerWitness(spec, "C-CHECK-TRIGGER", evidence, CheckTriggerObligationFull); match != nil {
			t.Fatal("predicates assembled from two witnesses were accepted")
		}
	})

	t.Run("external origin alone rejected", func(t *testing.T) {
		if match, _ := MatchCheckTriggerWitness(spec, "C-CHECK-TRIGGER", []Evidence{control}, CheckTriggerObligationFull); match != nil {
			t.Fatal("a generic external flow satisfied the check trigger")
		}
	})

	t.Run("missing control evidence rejected", func(t *testing.T) {
		w := base()
		w.ControlEvidenceIDs = []EvidenceID{"EV-ABSENT"}
		if match, _ := MatchCheckTriggerWitness(spec, "C-CHECK-TRIGGER", evidenceWith(w), CheckTriggerObligationFull); match != nil {
			t.Fatal("witness with missing control evidence admitted")
		}
	})

	t.Run("wrong condition rejected", func(t *testing.T) {
		w := base()
		w.ConditionID = "C-OTHER"
		if match, _ := MatchCheckTriggerWitness(spec, "C-CHECK-TRIGGER", evidenceWith(w), CheckTriggerObligationFull); match != nil {
			t.Fatal("witness for another condition admitted")
		}
	})

	t.Run("cross-receiver rejected", func(t *testing.T) {
		w := base()
		w.ReceiverType = "OtherClaims"
		if match, _ := MatchCheckTriggerWitness(spec, "C-CHECK-TRIGGER", evidenceWith(w), CheckTriggerObligationFull); match != nil {
			t.Fatal("witness on another receiver type admitted")
		}
	})
}

func TestDefectSemanticsTypedAdmissionErrors(t *testing.T) {
	model, evidence := testDefectiveModel()

	unresolved := model
	contractCopy := *model.DefectSemantics
	contractCopy.Mode = DefectSemanticsUnresolved
	contractCopy.UnresolvedReason = SemanticsEvidenceMissing
	contractCopy.UnresolvedDetail = "no mechanism"
	unresolved.DefectSemantics = &contractCopy
	if err := ValidateDefectSemanticsModel(unresolved, evidence); !errors.Is(err, ErrDefectSemanticsUnresolved) {
		t.Fatalf("unresolved gate error = %v; want ErrDefectSemanticsUnresolved", err)
	}

	stale := []Evidence{testAdvisoryEvidence()}
	stale[0].Content += " (edited)"
	if err := ValidateDefectSemanticsModel(model, stale); !errors.Is(err, ErrDefectSemanticsStale) {
		t.Fatalf("stale gate error = %v; want ErrDefectSemanticsStale", err)
	}

	inconsistent := model
	inconsistent.MandatoryConditions = inconsistent.MandatoryConditions[:2]
	if err := ValidateDefectSemanticsModel(inconsistent, evidence); !errors.Is(err, ErrDefectSemanticsInconsistent) {
		t.Fatalf("inconsistent gate error = %v; want ErrDefectSemanticsInconsistent", err)
	}
}

func TestDefectSemanticsGapMessage(t *testing.T) {
	if !strings.Contains(SemanticsUnresolvedGapMessage, "defect semantics could not be established") {
		t.Fatalf("gap message drifted: %q", SemanticsUnresolvedGapMessage)
	}
}

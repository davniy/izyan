package evaluator

import (
	"testing"

	"github.com/davniy/izyan/internal/domain"
)

func defectCheckSymbol() domain.SymbolRef {
	return domain.SymbolRef{Package: "example.com/dep/check", Symbol: "Claims.VerifyAudience"}
}

func defectTriggerSpec() domain.CheckTriggerSpec {
	return domain.CheckTriggerSpec{
		Operation: defectCheckSymbol(),
		Argument:  domain.CheckArgumentPredicate{Name: "req", Index: 1, Value: "false"},
		Payload: domain.CheckPayloadPredicate{
			ReceiverField:  "aud",
			Shapes:         []string{"array"},
			ExcludedShapes: []string{"string"},
		},
		Effect: "audience verification is bypassed",
	}
}

func defectAdvisoryEvidence() domain.Evidence {
	return domain.Evidence{
		ID:      "EV-ADV",
		Kind:    domain.EvidenceAdvisory,
		Quality: domain.QualityAuthoritative,
		Content: "Claims.VerifyAudience is called with req set to false when the audience claim is an array of strings, rather than a single string.",
	}
}

func defectWitnessEvidence(cond domain.ConditionID) (domain.Evidence, domain.Evidence) {
	flow := domain.Evidence{
		ID: "EV-FLOW", Kind: domain.EvidenceDataFlow, Quality: domain.QualityDeterministic,
		Content: "request token supplies the claims map",
	}
	witness := domain.Evidence{
		ID: "EV-WITNESS", Kind: domain.EvidenceValidation, Quality: domain.QualityDeterministic,
		Content: "typed check-trigger witness",
		CheckTrigger: &domain.CheckTriggerWitness{
			ConditionID:        cond,
			Operation:          defectCheckSymbol(),
			Invocation:         domain.CallSite{File: "map_claims.go", Line: 17, Function: "VerifyAudience", Receiver: "m", Package: "example.com/dep/check"},
			Receiver:           "m",
			ReceiverType:       "Claims",
			ArgumentName:       "req",
			ArgumentIndex:      1,
			ArgumentValue:      "false",
			ReceiverField:      "aud",
			PayloadShapes:      []string{"array"},
			ControlOrigin:      domain.OriginExternalUntrusted,
			ControlEvidenceIDs: []domain.EvidenceID{flow.ID},
		},
	}
	return witness, flow
}

func defectiveCheckModel() domain.ExploitModel {
	spec := defectTriggerSpec()
	adv := defectAdvisoryEvidence()
	contract := &domain.DefectSemanticsContract{
		Mode:               domain.DefectSemanticsDefectiveCheck,
		RecordID:           "GO-TEST-CHECK",
		Check:              defectCheckSymbol(),
		Trigger:            &spec,
		TriggerConditionID: domain.CheckTriggerConditionID,
		Grounds: []domain.DefectSemanticsGround{{
			Claim:          domain.SemanticsGroundAdvisoryInvocation,
			EvidenceID:     adv.ID,
			EvidenceKind:   adv.Kind,
			EvidenceDigest: domain.EvidenceContentDigest(adv.Content),
			Quote:          "Claims.VerifyAudience is called with req set to false",
		}},
	}
	return domain.ExploitModel{
		RootCauses:      []domain.SymbolRef{defectCheckSymbol()},
		DefectSemantics: contract,
		MandatoryConditions: []domain.Condition{
			{
				ID: "C-REACH", Kind: domain.ConditionSymbolReachable, Mandatory: true,
				Subjects: []domain.SymbolRef{defectCheckSymbol()},
				Params: map[string]string{
					domain.ParamCheck:     domain.CheckInvocation,
					domain.ParamOperation: "example.com/dep/check.Claims.VerifyAudience",
				},
			},
			{
				ID: "C-INPUT", Kind: domain.ConditionCheckInput, Mandatory: true,
				Subjects: []domain.SymbolRef{defectCheckSymbol()}, ArgIndex: domain.ArgReceiver,
				Params: domain.CheckInputParams(spec),
			},
			{
				ID: "C-CHECK-TRIGGER", Kind: domain.ConditionCheckTrigger, Mandatory: true,
				Subjects: []domain.SymbolRef{defectCheckSymbol()}, ArgIndex: spec.Argument.Index,
				Params: domain.CheckTriggerParams(spec),
			},
			{
				ID: "C-LOCUS", Kind: domain.ConditionSymbolReachable, Mandatory: true,
				Subjects: []domain.SymbolRef{defectCheckSymbol()},
				Params:   map[string]string{domain.ParamCheck: domain.CheckLocus},
			},
		},
	}
}

func defectiveCase() *domain.AnalysisCase {
	model := defectiveCheckModel()
	c := &domain.AnalysisCase{Exploit: &model}
	adv := defectAdvisoryEvidence()
	c.EvidenceGraph.AddEvidence(adv)
	return c
}

func admittedAffected() domain.AffectedResult {
	return domain.AffectedResult{
		ModulePresent:                   domain.ClaimTrue,
		VersionAffected:                 domain.ClaimTrue,
		PackagePresent:                  domain.ClaimTrue,
		BuildRelevant:                   domain.ClaimTrue,
		VulnerableImplementationPresent: domain.ClaimTrue,
	}
}

func allTrueClaims(model domain.ExploitModel) []domain.Claim {
	claims := make([]domain.Claim, 0, len(model.MandatoryConditions))
	for _, cond := range model.MandatoryConditions {
		claims = append(claims, domain.Claim{ConditionID: cond.ID, Result: domain.ClaimTrue})
	}
	return claims
}

func TestIncorrectCheckTriggerBinding(t *testing.T) {
	c := defectiveCase()
	triggerCond := findConditionByID(c.Exploit, "C-CHECK-TRIGGER")
	inputCond := findConditionByID(c.Exploit, "C-INPUT")
	if triggerCond == nil || inputCond == nil {
		t.Fatal("defective fixture is missing trigger/input conditions")
	}

	t.Run("array req=false identifies extern input", func(t *testing.T) {
		witness, flow := defectWitnessEvidence(triggerCond.ID)
		c.EvidenceGraph.AddEvidence(witness)
		c.EvidenceGraph.AddEvidence(flow)
		claim := (CheckTrigger{}).Evaluate(*triggerCond, c)
		if claim.Result != domain.ClaimTrue {
			t.Fatalf("trigger = %s (%v); want TRUE", claim.Result, claim.Limitations)
		}
		inputClaim := (CheckTrigger{}).Evaluate(*inputCond, c)
		if inputClaim.Result != domain.ClaimTrue {
			t.Fatalf("input = %s; want TRUE", inputClaim.Result)
		}
	})

	t.Run("string payload rejected", func(t *testing.T) {
		c := defectiveCase()
		witness, flow := defectWitnessEvidence(triggerCond.ID)
		witness.CheckTrigger.PayloadShapes = []string{"string"}
		c.EvidenceGraph.AddEvidence(witness)
		c.EvidenceGraph.AddEvidence(flow)
		if claim := (CheckTrigger{}).Evaluate(*triggerCond, c); claim.Result == domain.ClaimTrue {
			t.Fatal("string payload satisfied an array-only trigger")
		}
	})

	t.Run("req=true rejected", func(t *testing.T) {
		c := defectiveCase()
		witness, flow := defectWitnessEvidence(triggerCond.ID)
		witness.CheckTrigger.ArgumentValue = "true"
		c.EvidenceGraph.AddEvidence(witness)
		c.EvidenceGraph.AddEvidence(flow)
		if claim := (CheckTrigger{}).Evaluate(*triggerCond, c); claim.Result == domain.ClaimTrue {
			t.Fatal("req=true satisfied a req=false trigger")
		}
	})

	t.Run("cross-call assembly rejected", func(t *testing.T) {
		c := defectiveCase()
		first, flow := defectWitnessEvidence(triggerCond.ID)
		first.CheckTrigger.PayloadShapes = []string{"string"}
		second, _ := defectWitnessEvidence(triggerCond.ID)
		second.ID = "EV-WITNESS-2"
		second.CheckTrigger.ArgumentValue = "true"
		second.CheckTrigger.Invocation = domain.CallSite{File: "other.go", Line: 99, Function: "Other", Receiver: "m", Package: "example.com/dep/check"}
		c.EvidenceGraph.AddEvidence(first)
		c.EvidenceGraph.AddEvidence(second)
		c.EvidenceGraph.AddEvidence(flow)
		if claim := (CheckTrigger{}).Evaluate(*triggerCond, c); claim.Result == domain.ClaimTrue {
			t.Fatal("trigger predicates assembled from different calls were accepted")
		}
	})

	t.Run("external origin alone rejected", func(t *testing.T) {
		c := defectiveCase()
		c.EvidenceGraph.AddEvidence(domain.Evidence{
			ID: "EV-FLOW", Kind: domain.EvidenceDataFlow, Quality: domain.QualityDeterministic,
			Content: "external request token",
		})
		if claim := (CheckTrigger{}).Evaluate(*triggerCond, c); claim.Result == domain.ClaimTrue {
			t.Fatal("a generic external flow satisfied the check trigger")
		}
	})
}

func TestDefectSemanticsVerdictGate(t *testing.T) {
	t.Run("unresolved contract blocks an all-true conjunction", func(t *testing.T) {
		model := domain.ExploitModel{
			RootCauses: []domain.SymbolRef{defectCheckSymbol()},
			DefectSemantics: &domain.DefectSemanticsContract{
				Mode:             domain.DefectSemanticsUnresolved,
				RecordID:         "GO-TEST-CHECK",
				Check:            defectCheckSymbol(),
				UnresolvedReason: domain.SemanticsEvidenceMissing,
				UnresolvedDetail: "no mechanism statement",
			},
			MandatoryConditions: []domain.Condition{
				{ID: "C-REACH", Kind: domain.ConditionSymbolReachable, Mandatory: true, Subjects: []domain.SymbolRef{defectCheckSymbol()}},
				{ID: "C-INPUT", Kind: domain.ConditionAttackerControl, Mandatory: true, Subjects: []domain.SymbolRef{defectCheckSymbol()}},
			},
		}
		ev := (VerdictEvaluator{}).EvaluateDetailed(VerdictInput{
			Affected: admittedAffected(),
			Model:    model,
			Claims:   allTrueClaims(model),
		})
		if ev.Verdict.Verdict != domain.VerdictInconclusive {
			t.Fatalf("verdict = %s; want INCONCLUSIVE", ev.Verdict.Verdict)
		}
		requireSemanticsGap(t, ev.Gaps)
	})

	t.Run("legacy omission conjunction without contract blocked", func(t *testing.T) {
		model := domain.ExploitModel{
			RootCauses: []domain.SymbolRef{defectCheckSymbol()},
			MandatoryConditions: []domain.Condition{
				{ID: "C-REACH", Kind: domain.ConditionSymbolReachable, Mandatory: true, Subjects: []domain.SymbolRef{{Package: "example.com/dep/check", Symbol: "Claims.Valid"}}},
				{ID: "C-OMISSION", Kind: domain.ConditionMissingCall, Mandatory: true, Subjects: []domain.SymbolRef{defectCheckSymbol()}, Params: map[string]string{domain.ParamCheck: domain.CheckMissingCall, "pipeline": "Claims.Valid"}},
				{ID: "C-INPUT", Kind: domain.ConditionInputConstraint, Mandatory: true, Subjects: []domain.SymbolRef{{Package: "example.com/dep/check", Symbol: "Claims.Valid"}}, ArgIndex: domain.ArgAll},
			},
		}
		ev := (VerdictEvaluator{}).EvaluateDetailed(VerdictInput{
			Affected: admittedAffected(),
			Model:    model,
			Claims:   allTrueClaims(model),
		})
		if ev.Verdict.Verdict != domain.VerdictInconclusive {
			t.Fatalf("verdict = %s; want INCONCLUSIVE", ev.Verdict.Verdict)
		}
		requireSemanticsGap(t, ev.Gaps)
	})

	t.Run("unsupported trigger claim demoted", func(t *testing.T) {
		c := defectiveCase()
		model := *c.Exploit
		ev := (VerdictEvaluator{}).EvaluateDetailed(VerdictInput{
			Affected: admittedAffected(),
			Model:    model,
			Claims:   allTrueClaims(model),
			Evidence: c.EvidenceGraph.EvidenceList(),
		})
		if ev.Verdict.Verdict != domain.VerdictInconclusive {
			t.Fatalf("verdict = %s; want INCONCLUSIVE without a witness", ev.Verdict.Verdict)
		}
		if !hasGapCode(ev.Gaps, domain.GapOwnerCode, domain.GapTriggerProofIncomplete) {
			t.Fatalf("missing TRIGGER_PROOF_INCOMPLETE gap: %+v", ev.Gaps)
		}
	})

	t.Run("admitted trigger witness earns exploitable", func(t *testing.T) {
		c := defectiveCase()
		model := *c.Exploit
		triggerCond := findConditionByID(c.Exploit, "C-CHECK-TRIGGER")
		witness, flow := defectWitnessEvidence(triggerCond.ID)
		c.EvidenceGraph.AddEvidence(witness)
		c.EvidenceGraph.AddEvidence(flow)
		ev := (VerdictEvaluator{}).EvaluateDetailed(VerdictInput{
			Affected: admittedAffected(),
			Model:    model,
			Claims:   allTrueClaims(model),
			Evidence: c.EvidenceGraph.EvidenceList(),
		})
		if ev.Verdict.Verdict != domain.VerdictExploitable {
			t.Fatalf("verdict = %s (%s); want EXPLOITABLE", ev.Verdict.Verdict, ev.Verdict.Reason)
		}
		if len(ev.Gaps) != 0 {
			t.Fatalf("definitive verdict carries gaps: %+v", ev.Gaps)
		}
	})
}

func requireSemanticsGap(t *testing.T, gaps []domain.AnalysisGap) {
	t.Helper()
	for _, g := range gaps {
		if g.Owner == domain.GapOwnerCode && g.Code == domain.GapRootCauseUnresolved &&
			g.Obligation == domain.ObligationRootCause && g.Message == domain.SemanticsUnresolvedGapMessage {
			return
		}
	}
	t.Fatalf("missing ROOT_CAUSE_UNRESOLVED semantics gap: %+v", gaps)
}

func hasGapCode(gaps []domain.AnalysisGap, owner domain.GapOwner, code domain.GapCode) bool {
	for _, g := range gaps {
		if g.Owner == owner && g.Code == code {
			return true
		}
	}
	return false
}

func findConditionByID(model *domain.ExploitModel, id domain.ConditionID) *domain.Condition {
	for i := range model.MandatoryConditions {
		if model.MandatoryConditions[i].ID == id {
			return &model.MandatoryConditions[i]
		}
	}
	return nil
}

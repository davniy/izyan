package evaluator

import (
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
)

// --- omission fixture ------------------------------------------------------

func omissionCheck() domain.SymbolRef {
	return domain.SymbolRef{Package: "example.com/dep/check", Symbol: "Claims.VerifyAudience"}
}

func omissionPipeline() domain.SymbolRef {
	return domain.SymbolRef{Package: "example.com/dep/pipeline", Symbol: "Claims.Valid"}
}

func omissionAdvisoryEvidence() domain.Evidence {
	return domain.Evidence{
		ID:      "EV-ADV-OMISSION",
		Kind:    domain.EvidenceAdvisory,
		Quality: domain.QualityAuthoritative,
		Content: "Claims.VerifyAudience is not invoked by the active Claims.Valid pipeline; the missing invocation is the vulnerability.",
	}
}

func omissionModel() *domain.ExploitModel {
	check, pipeline := omissionCheck(), omissionPipeline()
	adv := omissionAdvisoryEvidence()
	return &domain.ExploitModel{
		RootCauses: []domain.SymbolRef{check},
		DefectSemantics: &domain.DefectSemanticsContract{
			Mode:     domain.DefectSemanticsOmittedCheck,
			RecordID: "GO-TEST-OMISSION",
			Check:    check,
			Pipeline: &pipeline,
			Grounds: []domain.DefectSemanticsGround{{
				Claim:          domain.SemanticsGroundAdvisoryOmission,
				EvidenceID:     adv.ID,
				EvidenceKind:   adv.Kind,
				EvidenceDigest: domain.EvidenceContentDigest(adv.Content),
				Quote:          "Claims.VerifyAudience is not invoked",
				Symbol:         &check,
			}},
		},
		MandatoryConditions: []domain.Condition{
			{
				ID:        "C-REACH",
				Kind:      domain.ConditionSymbolReachable,
				Mandatory: true,
				Subjects:  []domain.SymbolRef{pipeline},
				Params:    map[string]string{"pipeline": pipeline.Symbol},
			},
			{
				ID:        "C-OMISSION",
				Kind:      domain.ConditionMissingCall,
				Mandatory: true,
				Subjects:  []domain.SymbolRef{check},
				Params: map[string]string{
					domain.ParamCheck: domain.CheckMissingCall,
					"pipeline":        pipeline.Symbol,
				},
			},
			{
				ID:        "C-LOCUS",
				Kind:      domain.ConditionSymbolReachable,
				Mandatory: true,
				Subjects:  []domain.SymbolRef{check},
				Params:    map[string]string{domain.ParamCheck: domain.CheckLocus},
			},
		},
	}
}

func omissionWitnessEvidence(id domain.EvidenceID, status domain.MissingCallStatus, product domain.ProductSnapshot) domain.Evidence {
	build := domain.EffectiveBuildContext(product)
	return domain.Evidence{
		ID:           id,
		Kind:         domain.EvidenceValidation,
		Quality:      domain.QualityDeterministic,
		Source:       "source index: missing-call verification",
		Tool:         "goanalysis.Index.CheckMissingCall",
		Content:      "typed omission witness",
		BuildContext: &build,
		MissingCall: &domain.MissingCallWitness{
			RecordID: "GO-TEST-OMISSION",
			Check:    omissionCheck(),
			Pipeline: omissionPipeline(),
			Status:   status,
		},
	}
}

func omissionLocusCondition() domain.Condition {
	return domain.Condition{
		ID:        "C-LOCUS",
		Kind:      domain.ConditionSymbolReachable,
		Mandatory: true,
		Subjects:  []domain.SymbolRef{omissionCheck()},
		Params:    map[string]string{domain.ParamCheck: domain.CheckLocus},
	}
}

// --- defective-check fixture ----------------------------------------------

func defectiveCheck() domain.SymbolRef {
	return domain.SymbolRef{Package: "example.com/dep/check", Symbol: "Claims.VerifyAudience"}
}

func defectiveAdvisoryEvidence() domain.Evidence {
	return domain.Evidence{
		ID:      "EV-ADV-DEFECT",
		Kind:    domain.EvidenceAdvisory,
		Quality: domain.QualityAuthoritative,
		Content: "Claims.VerifyAudience is called with req set to false when the audience claim is an array of strings.",
	}
}

func defectiveModel() *domain.ExploitModel {
	check := defectiveCheck()
	adv := defectiveAdvisoryEvidence()
	spec := domain.CheckTriggerSpec{
		Operation: check,
		Argument:  domain.CheckArgumentPredicate{Name: "req", Index: 1, Value: "false"},
		Payload: domain.CheckPayloadPredicate{
			ReceiverField:  "aud",
			Shapes:         []string{"array"},
			ExcludedShapes: []string{"string"},
		},
	}
	return &domain.ExploitModel{
		RootCauses: []domain.SymbolRef{check},
		DefectSemantics: &domain.DefectSemanticsContract{
			Mode:               domain.DefectSemanticsDefectiveCheck,
			RecordID:           "GO-TEST-DEFECT",
			Check:              check,
			Trigger:            &spec,
			TriggerConditionID: domain.CheckTriggerConditionID,
			Grounds: []domain.DefectSemanticsGround{{
				Claim:          domain.SemanticsGroundAdvisoryInvocation,
				EvidenceID:     adv.ID,
				EvidenceKind:   adv.Kind,
				EvidenceDigest: domain.EvidenceContentDigest(adv.Content),
				Quote:          "Claims.VerifyAudience is called with req set to false",
				Symbol:         &check,
			}},
		},
		MandatoryConditions: []domain.Condition{
			{
				ID:        "C-REACH",
				Kind:      domain.ConditionSymbolReachable,
				Mandatory: true,
				Subjects:  []domain.SymbolRef{check},
				Params: map[string]string{
					domain.ParamCheck:     domain.CheckInvocation,
					domain.ParamOperation: check.Package + "." + check.Symbol,
				},
			},
			{
				ID:        "C-INPUT",
				Kind:      domain.ConditionCheckInput,
				Mandatory: true,
				Subjects:  []domain.SymbolRef{check},
				ArgIndex:  domain.ArgReceiver,
				Params:    domain.CheckInputParams(spec),
			},
			{
				ID:        "C-CHECK-TRIGGER",
				Kind:      domain.ConditionCheckTrigger,
				Mandatory: true,
				Subjects:  []domain.SymbolRef{check},
				ArgIndex:  spec.Argument.Index,
				Params:    domain.CheckTriggerParams(spec),
			},
			{
				ID:        "C-LOCUS",
				Kind:      domain.ConditionSymbolReachable,
				Mandatory: true,
				Subjects:  []domain.SymbolRef{check},
				Params:    map[string]string{domain.ParamCheck: domain.CheckLocus},
			},
		},
	}
}

func defectiveLocusCondition() domain.Condition {
	return domain.Condition{
		ID:        "C-LOCUS",
		Kind:      domain.ConditionSymbolReachable,
		Mandatory: true,
		Subjects:  []domain.SymbolRef{defectiveCheck()},
		Params:    map[string]string{domain.ParamCheck: domain.CheckLocus},
	}
}

// --- tests ----------------------------------------------------------------

// A raw EV-MISSING-CALL record — even one whose content names the check and
// the pipeline — is not defect-locus reachability. Only the typed omission
// contract may turn the observation into execution of the omission site, and
// only for that site.
func TestLocusIgnoresUnadmittedOmissionEvidence(t *testing.T) {
	c := caseWithPackages("example.com/dep/check", "example.com/dep/pipeline", "example.com/prod")
	c.EvidenceGraph.AddEvidence(domain.Evidence{
		ID:      "EV-MISSING-CALL",
		Kind:    domain.EvidenceValidation,
		Quality: domain.QualityDeterministic,
		Content: "security check Claims.VerifyAudience is omitted on active pipeline Claims.Valid",
	})
	claim := (SymbolReachable{}).Evaluate(omissionLocusCondition(), c)
	if claim.Result != domain.ClaimUnknown {
		t.Fatalf("unadmitted EV-MISSING-CALL must not establish the defect locus: %+v", claim)
	}
}

// A legacy omission model without the admitted contract stays UNKNOWN even
// though the historical evidence is present.
func TestLocusLegacyOmissionModelWithoutContractStaysUnknown(t *testing.T) {
	c := caseWithPackages("example.com/dep/check", "example.com/dep/pipeline", "example.com/prod")
	c.Exploit = &domain.ExploitModel{MandatoryConditions: []domain.Condition{{
		ID: "C-OMISSION", Kind: domain.ConditionMissingCall, Mandatory: true,
		Subjects: []domain.SymbolRef{omissionCheck()},
		Params: map[string]string{
			domain.ParamCheck: domain.CheckMissingCall,
			"pipeline":        omissionPipeline().Symbol,
		},
	}}}
	claim := (SymbolReachable{}).Evaluate(omissionLocusCondition(), c)
	if claim.Result != domain.ClaimUnknown {
		t.Fatalf("legacy omission model without a contract must stay UNKNOWN: %+v", claim)
	}
}

// Under an admitted OMITTED_CHECK contract the locus is the omission site on
// the anchored pipeline: the typed witness that records the pipeline reached
// and the check absent establishes TRUE, and the explanation names the
// pipeline, never the absent check's body.
func TestLocusOmissionContractBindsOmissionSite(t *testing.T) {
	product := admittedProduct()
	c := caseWithPackages("example.com/dep/check", "example.com/dep/pipeline", "example.com/prod")
	c.Exploit = omissionModel()
	c.EvidenceGraph.AddEvidence(omissionAdvisoryEvidence())
	c.EvidenceGraph.AddEvidence(omissionWitnessEvidence("EV-MISSING-CALL", domain.MissingCallOmitted, product))

	claim := (SymbolReachable{}).Evaluate(omissionLocusCondition(), c)
	if claim.Result != domain.ClaimTrue {
		t.Fatalf("expected TRUE for the executing omission site, got %+v", claim)
	}
	if len(claim.EvidenceIDs) != 1 || claim.EvidenceIDs[0] != "EV-MISSING-CALL" {
		t.Fatalf("evidence=%v", claim.EvidenceIDs)
	}
	if !strings.Contains(claim.Explanation, omissionPipeline().Symbol) {
		t.Fatalf("explanation must name the omission-site pipeline: %s", claim.Explanation)
	}
	if strings.Contains(claim.Explanation, "VerifyAudience") {
		t.Fatalf("explanation must not claim the absent check executes: %s", claim.Explanation)
	}
}

// A call path to the declared check is not execution of the omission site:
// under an omission contract the pipeline is the locus.
func TestLocusOmissionContractCallPathToCheckIsNotLocus(t *testing.T) {
	c := caseWithPackages("example.com/dep/check", "example.com/dep/pipeline", "example.com/prod")
	c.Exploit = omissionModel()
	c.EvidenceGraph.AddEvidence(omissionAdvisoryEvidence())
	c.EvidenceGraph.CallPaths = append(c.EvidenceGraph.CallPaths, domain.CallPath{
		EvidenceID: "EV-GV",
		Frames: []domain.CallSite{
			{Package: "example.com/prod", Function: "main"},
			{Package: omissionCheck().Package, Function: omissionCheck().Symbol},
		},
	})
	claim := (SymbolReachable{}).Evaluate(omissionLocusCondition(), c)
	if claim.Result == domain.ClaimTrue {
		t.Fatalf("a call path to the absent check must not establish the omission site: %+v", claim)
	}
}

// A witness recorded under another build does not bind the omission site.
func TestLocusOmissionWitnessFromAnotherBuildIsRefused(t *testing.T) {
	c := caseWithPackages("example.com/dep/check", "example.com/dep/pipeline", "example.com/prod")
	c.Exploit = omissionModel()
	c.EvidenceGraph.AddEvidence(omissionAdvisoryEvidence())
	foreign := admittedProduct()
	foreign.Commit = "other-commit"
	c.EvidenceGraph.AddEvidence(omissionWitnessEvidence("EV-MISSING-CALL", domain.MissingCallOmitted, foreign))

	claim := (SymbolReachable{}).Evaluate(omissionLocusCondition(), c)
	if claim.Result != domain.ClaimUnknown {
		t.Fatalf("foreign-build witness must stay UNKNOWN: %+v", claim)
	}
}

// The same physical observation — the check has no execution — cannot
// dismiss a genuine omission. The check's package is linked and only the
// check was measured; the omission site (pipeline) remains unmeasured, so the
// locus stays UNKNOWN.
func TestLocusOmissionCheckDeadnessIsNotANegative(t *testing.T) {
	c := caseWithPackages("example.com/dep/check", "example.com/dep/pipeline", "example.com/prod")
	c.Exploit = omissionModel()
	c.EvidenceGraph.AddEvidence(omissionAdvisoryEvidence())
	// Literal check-deadness measurement: the check package's function scan.
	addSourceScan(c, []domain.SymbolRef{omissionCheck()}, true, false)

	claim := (SymbolReachable{}).Evaluate(omissionLocusCondition(), c)
	if claim.Result != domain.ClaimUnknown {
		t.Fatalf("literal check deadness must not dismiss an omission: %+v", claim)
	}
}

// When the omission site's package is absent from the complete build graph,
// the omission site cannot execute and the negative is the omission-site
// premise — still not the absent check's own deadness.
func TestLocusOmissionSitePackageAbsentIsANegative(t *testing.T) {
	c := caseWithPackages("example.com/prod")
	c.Exploit = omissionModel()
	c.EvidenceGraph.AddEvidence(omissionAdvisoryEvidence())

	claim := (SymbolReachable{}).Evaluate(omissionLocusCondition(), c)
	if claim.Result != domain.ClaimFalse || claim.Falsifier != domain.FalsifierLocusPackageAbsent {
		t.Fatalf("expected omission-site package absence to ground FALSE, got %+v", claim)
	}
}

// Under an admitted DEFECTIVE_CHECK contract the contracted check's deadness
// is a verified negative candidate: its invocation is the mandatory
// operation.
func TestLocusDefectiveContractCheckDeadnessIsANegative(t *testing.T) {
	c := caseWithPackages("example.com/dep/check", "example.com/prod")
	c.Exploit = defectiveModel()
	c.EvidenceGraph.AddEvidence(defectiveAdvisoryEvidence())
	addSourceScan(c, []domain.SymbolRef{defectiveCheck()}, true, false)

	claim := (SymbolReachable{}).Evaluate(defectiveLocusCondition(), c)
	if claim.Result != domain.ClaimFalse || claim.Falsifier != domain.FalsifierLocusFunctionUnreached {
		t.Fatalf("expected the dead contracted check to ground FALSE, got %+v", claim)
	}
}

// Same deadness, opposite contract: defective check -> negative; omission ->
// no negative from the check's deadness. This is the contradiction control.
func TestLocusSameDeadnessDefectiveVersusOmitted(t *testing.T) {
	dead := func(model *domain.ExploitModel, advisory domain.Evidence) domain.Claim {
		c := caseWithPackages("example.com/dep/check", "example.com/dep/pipeline", "example.com/prod")
		c.Exploit = model
		c.EvidenceGraph.AddEvidence(advisory)
		addSourceScan(c, []domain.SymbolRef{defectiveCheck()}, true, false)
		return (SymbolReachable{}).Evaluate(defectiveLocusCondition(), c)
	}

	defective := dead(defectiveModel(), defectiveAdvisoryEvidence())
	omitted := dead(omissionModel(), omissionAdvisoryEvidence())
	if defective.Result != domain.ClaimFalse {
		t.Fatalf("defective contract must treat check deadness as a falsifier: %+v", defective)
	}
	if omitted.Result != domain.ClaimUnknown {
		t.Fatalf("omission contract must not treat check deadness as a falsifier: %+v", omitted)
	}
}

// An UNRESOLVED contract can never ground a locus negative.
func TestLocusUnresolvedContractRefusesNegative(t *testing.T) {
	c := caseWithPackages("example.com/dep/check", "example.com/prod")
	check := defectiveCheck()
	c.Exploit = &domain.ExploitModel{
		RootCauses: []domain.SymbolRef{check},
		DefectSemantics: &domain.DefectSemanticsContract{
			Mode:             domain.DefectSemanticsUnresolved,
			RecordID:         "GO-TEST-UNRESOLVED",
			Check:            check,
			UnresolvedReason: domain.SemanticsEvidenceMissing,
			UnresolvedDetail: "no mechanism statement",
		},
		MandatoryConditions: []domain.Condition{{
			ID: "C-LOCUS", Kind: domain.ConditionSymbolReachable, Mandatory: true,
			Subjects: []domain.SymbolRef{check},
			Params:   map[string]string{domain.ParamCheck: domain.CheckLocus},
		}},
	}
	addSourceScan(c, []domain.SymbolRef{check}, true, false)
	claim := (SymbolReachable{}).Evaluate(defectiveLocusCondition(), c)
	if claim.Result != domain.ClaimUnknown {
		t.Fatalf("unresolved semantics must refuse the negative: %+v", claim)
	}
}

// A persisted TRUE omission or omission-site reach claim is re-admitted
// through the typed witness: the saved result alone never survives, and the
// same claim with the witness does.
func TestVerdictDemotesSavedOmissionClaimsWithoutWitness(t *testing.T) {
	product := admittedProduct()
	saved := []domain.Claim{
		{ID: "CL-C-OMISSION", ConditionID: "C-OMISSION", Result: domain.ClaimTrue},
		{ID: "CL-C-REACH", ConditionID: "C-REACH", Result: domain.ClaimTrue},
		{ID: "CL-C-LOCUS", ConditionID: "C-LOCUS", Result: domain.ClaimTrue},
	}
	in := VerdictInput{
		Product:  product,
		Model:    *omissionModel(),
		Claims:   saved,
		Evidence: []domain.Evidence{omissionAdvisoryEvidence()},
	}
	out, refusals := admitVerdictInput(in)
	if len(refusals) != 2 {
		t.Fatalf("refusals = %+v, want the omission and pipeline-reach claims demoted", refusals)
	}
	for _, cl := range out.Claims {
		if cl.ConditionID == "C-LOCUS" {
			if cl.Result != domain.ClaimTrue {
				t.Fatalf("locus claim is not re-admitted by this gate: %+v", cl)
			}
			continue
		}
		if cl.Result != domain.ClaimUnknown {
			t.Fatalf("saved %s stayed %s without the typed witness", cl.ConditionID, cl.Result)
		}
	}

	in.Claims = saved
	in.Evidence = append(in.Evidence, omissionWitnessEvidence("EV-MISSING-CALL", domain.MissingCallOmitted, product))
	out, refusals = admitVerdictInput(in)
	if len(refusals) != 0 {
		t.Fatalf("typed witness did not re-admit the claims: %+v", refusals)
	}
	for _, cl := range out.Claims {
		if cl.Result != domain.ClaimTrue {
			t.Fatalf("claim %s = %s after the witness binding", cl.ConditionID, cl.Result)
		}
	}
}

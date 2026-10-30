package evaluator

import (
	"testing"

	"github.com/davniy/izyan/internal/domain"
)

func omissionTestCheck() domain.SymbolRef {
	return domain.SymbolRef{Package: "github.com/golang-jwt/jwt", Symbol: "MapClaims.VerifyAudience"}
}

func omissionTestPipeline() domain.SymbolRef {
	return domain.SymbolRef{Package: "github.com/golang-jwt/jwt", Symbol: "MapClaims.Valid"}
}

func omissionTestContract() *domain.DefectSemanticsContract {
	pipeline := omissionTestPipeline()
	return &domain.DefectSemanticsContract{
		Mode:     domain.DefectSemanticsOmittedCheck,
		RecordID: "GO-TEST-OMISSION",
		Check:    omissionTestCheck(),
		Pipeline: &pipeline,
	}
}

func omissionTestCondition() domain.Condition {
	return domain.Condition{
		ID:       "C-OMISSION",
		Kind:     domain.ConditionMissingCall,
		Subjects: []domain.SymbolRef{omissionTestCheck()},
		Params: map[string]string{
			domain.ParamCheck: domain.CheckMissingCall,
			"pipeline":        omissionTestPipeline().Symbol,
		},
	}
}

func omissionTestEvidence(id string, status domain.MissingCallStatus, detail string, product domain.ProductSnapshot) domain.Evidence {
	build := domain.EffectiveBuildContext(product)
	return domain.Evidence{
		ID:           domain.EvidenceID(id),
		Kind:         domain.EvidenceValidation,
		Quality:      domain.QualityDeterministic,
		Source:       "source index: missing-call verification",
		Tool:         "goanalysis.Index.CheckMissingCall",
		Content:      detail,
		BuildContext: &build,
		MissingCall: &domain.MissingCallWitness{
			RecordID: "GO-TEST-OMISSION",
			Check:    omissionTestCheck(),
			Pipeline: omissionTestPipeline(),
			Status:   status,
			Detail:   detail,
		},
	}
}

func TestMissingCallEvaluator_TrueWhenOmitted(t *testing.T) {
	eval := MissingCall{}
	cond := omissionTestCondition()
	if !eval.CanEvaluate(cond) {
		t.Fatal("MissingCall must claim ConditionMissingCall")
	}

	product := admittedProduct()
	detail := "security check MapClaims.VerifyAudience is omitted on active pipeline MapClaims.Valid; check invocations on path: 0"
	c := &domain.AnalysisCase{
		Product: product,
		Exploit: &domain.ExploitModel{DefectSemantics: omissionTestContract()},
		EvidenceGraph: domain.EvidenceGraph{
			Evidence: []domain.Evidence{
				omissionTestEvidence("EV-MISSING-CALL", domain.MissingCallOmitted, detail, product),
			},
		},
	}

	claim := eval.Evaluate(cond, c)
	if claim.Result != domain.ClaimTrue {
		t.Fatalf("expected ClaimTrue, got %s (limitations: %v)", claim.Result, claim.Limitations)
	}
	if len(claim.EvidenceIDs) == 0 || claim.EvidenceIDs[0] != "EV-MISSING-CALL" {
		t.Fatalf("expected evidence ID EV-MISSING-CALL, got %v", claim.EvidenceIDs)
	}
}

func TestMissingCallEvaluator_TrueRequiresTypedWitness(t *testing.T) {
	// The historical content-substring shortcut is gone: an EV-MISSING-CALL
	// record whose content names the pipeline and the check proves nothing
	// without the typed contract/check/pipeline/build binding.
	eval := MissingCall{}
	cond := omissionTestCondition()
	product := admittedProduct()
	build := domain.EffectiveBuildContext(product)
	c := &domain.AnalysisCase{
		Product: product,
		Exploit: &domain.ExploitModel{DefectSemantics: omissionTestContract()},
		EvidenceGraph: domain.EvidenceGraph{
			Evidence: []domain.Evidence{{
				ID:           "EV-MISSING-CALL",
				Kind:         domain.EvidenceValidation,
				Quality:      domain.QualityDeterministic,
				Content:      "security check MapClaims.VerifyAudience is omitted on active pipeline MapClaims.Valid",
				BuildContext: &build,
			}},
		},
	}
	claim := eval.Evaluate(cond, c)
	if claim.Result != domain.ClaimUnknown {
		t.Fatalf("untyped omission evidence must stay UNKNOWN, got %s", claim.Result)
	}
}

func TestMissingCallEvaluator_TrueRequiresContract(t *testing.T) {
	// A legacy omission model without the admitted contract cannot read the
	// witness as an omission conclusion.
	eval := MissingCall{}
	cond := omissionTestCondition()
	product := admittedProduct()
	c := &domain.AnalysisCase{
		Product: product,
		EvidenceGraph: domain.EvidenceGraph{
			Evidence: []domain.Evidence{
				omissionTestEvidence("EV-MISSING-CALL", domain.MissingCallOmitted, "omitted", product),
			},
		},
	}
	claim := eval.Evaluate(cond, c)
	if claim.Result != domain.ClaimUnknown {
		t.Fatalf("omission evidence without a contract must stay UNKNOWN, got %s", claim.Result)
	}
}

func TestMissingCallEvaluator_FalseWhenCheckInvoked(t *testing.T) {
	eval := MissingCall{}
	cond := omissionTestCondition()
	product := admittedProduct()
	c := &domain.AnalysisCase{
		Product: product,
		Exploit: &domain.ExploitModel{DefectSemantics: omissionTestContract()},
		EvidenceGraph: domain.EvidenceGraph{
			Evidence: []domain.Evidence{
				omissionTestEvidence("EV-CHECK-PRESENT", domain.MissingCallPresent,
					"security check MapClaims.VerifyAudience is invoked in product code at main.go:20", product),
			},
		},
	}

	claim := eval.Evaluate(cond, c)
	if claim.Result != domain.ClaimFalse {
		t.Fatalf("expected ClaimFalse, got %s (limitations: %v)", claim.Result, claim.Limitations)
	}
	if claim.Falsifier != domain.FalsifierGuards {
		t.Fatalf("expected FalsifierGuards, got %s", claim.Falsifier)
	}
	if len(claim.EvidenceIDs) == 0 || claim.EvidenceIDs[0] != "EV-CHECK-PRESENT" {
		t.Fatalf("expected evidence ID EV-CHECK-PRESENT, got %v", claim.EvidenceIDs)
	}
}

func TestMissingCallEvaluator_NotEstablishedIsNotPresence(t *testing.T) {
	// An unestablished measurement (unreached pipeline, truncated search)
	// must never turn the omission claim FALSE.
	eval := MissingCall{}
	cond := omissionTestCondition()
	product := admittedProduct()
	c := &domain.AnalysisCase{
		Product: product,
		Exploit: &domain.ExploitModel{DefectSemantics: omissionTestContract()},
		EvidenceGraph: domain.EvidenceGraph{
			Evidence: []domain.Evidence{
				omissionTestEvidence("EV-CHECK-PRESENT", domain.MissingCallNotEstablished,
					"pipeline MapClaims.Valid is not reached from product code", product),
			},
		},
	}
	claim := eval.Evaluate(cond, c)
	if claim.Result != domain.ClaimUnknown {
		t.Fatalf("not-established measurement must stay UNKNOWN, got %s", claim.Result)
	}
}

func TestMissingCallEvaluator_UnknownWhenNoEvidence(t *testing.T) {
	eval := MissingCall{}
	cond := omissionTestCondition()
	c := &domain.AnalysisCase{Product: admittedProduct()}

	claim := eval.Evaluate(cond, c)
	if claim.Result != domain.ClaimUnknown {
		t.Fatalf("expected ClaimUnknown, got %s", claim.Result)
	}
}

// The omission-pipeline reach condition is decided by the same typed binding:
// a matching evidence-id prefix or a pipeline symbol inside evidence content
// proves nothing; the contract-bound witness is the only TRUE basis.
func TestSymbolReachableOmissionPipelineRequiresTypedWitness(t *testing.T) {
	cond := domain.Condition{
		ID:        "C-REACH",
		Kind:      domain.ConditionSymbolReachable,
		Mandatory: true,
		Subjects:  []domain.SymbolRef{omissionTestPipeline()},
		Params:    map[string]string{"pipeline": omissionTestPipeline().Symbol},
	}
	product := admittedProduct()
	base := func() *domain.AnalysisCase {
		return &domain.AnalysisCase{
			Product: product,
			Exploit: &domain.ExploitModel{DefectSemantics: omissionTestContract()},
			EvidenceGraph: domain.EvidenceGraph{
				Evidence: []domain.Evidence{{
					ID:           "EV-MISSING-CALL",
					Kind:         domain.EvidenceValidation,
					Quality:      domain.QualityDeterministic,
					Content:      "security check MapClaims.VerifyAudience is omitted on active pipeline MapClaims.Valid",
					BuildContext: ptrBuildContext(domain.EffectiveBuildContext(product)),
				}},
			},
		}
	}

	claim := (SymbolReachable{}).Evaluate(cond, base())
	if claim.Result == domain.ClaimTrue {
		t.Fatalf("untyped omission evidence must not establish pipeline reach: %+v", claim)
	}

	c := base()
	c.EvidenceGraph.AddEvidence(omissionTestEvidence("EV-TYPED", domain.MissingCallOmitted, "typed", product))
	claim = (SymbolReachable{}).Evaluate(cond, c)
	if claim.Result != domain.ClaimTrue {
		t.Fatalf("typed omission witness must establish pipeline reach: %+v", claim)
	}
	if len(claim.EvidenceIDs) != 1 || claim.EvidenceIDs[0] != "EV-TYPED" {
		t.Fatalf("evidence=%v", claim.EvidenceIDs)
	}
}

func ptrBuildContext(b domain.BuildContext) *domain.BuildContext { return &b }

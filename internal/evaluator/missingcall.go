package evaluator

import (
	"github.com/davniy/izyan/internal/domain"
)

// MissingCall evaluates MISSING_CALL conditions.
//
// The condition is only the structural shape: the admitted OMITTED_CHECK
// contract decides that omission is this advisory's defect. TRUE requires a
// typed MissingCallWitness bound to that contract — exact record, exact check,
// exact anchored pipeline and the effective build — recording that the
// pipeline is reached from product code and the check has zero invocations on
// that active path.
//
// FALSE requires the same typed binding recording the check observed invoked.
// UNKNOWN is every other case: no contract, an unadmitted legacy omission
// model, a drifted condition or an unestablished measurement. An evidence-id
// prefix or a content substring never decides this claim.
type MissingCall struct{}

func (MissingCall) CanEvaluate(cond domain.Condition) bool {
	return cond.Kind == domain.ConditionMissingCall || cond.Params[domain.ParamCheck] == domain.CheckMissingCall
}

func (MissingCall) Evaluate(cond domain.Condition, c *domain.AnalysisCase) domain.Claim {
	return admitNegative(c, cond, evaluateMissingCall(cond, c))
}

func evaluateMissingCall(cond domain.Condition, c *domain.AnalysisCase) domain.Claim {
	claim := domain.Claim{
		ID:          domain.ClaimID("CL-" + string(cond.ID)),
		ConditionID: cond.ID,
		Result:      domain.ClaimUnknown,
		Producer:    "evaluator.MissingCall",
	}
	if c == nil || c.Exploit == nil {
		claim.Limitations = append(claim.Limitations, "no exploit model: the omission observation has no admitted defect semantics")
		return claim
	}
	contract := c.Exploit.DefectSemantics
	evidence := c.EvidenceGraph.EvidenceList()

	if match, reasons := domain.MatchOmissionWitness(contract, cond, evidence,
		c.Product, domain.MissingCallOmitted); match != nil {
		claim.Result = domain.ClaimTrue
		claim.EvidenceIDs = appendUniqueID(claim.EvidenceIDs, match.EvidenceID)
		claim.Explanation = "the admitted omission contract binds this pipeline, and the typed source observation records the check excluded from it: " +
			match.Witness.Detail
		return claim
	} else {
		claim.Limitations = append(claim.Limitations, reasons...)
	}

	if match, reasons := domain.MatchOmissionWitness(contract, cond, evidence,
		c.Product, domain.MissingCallPresent); match != nil {
		claim.Result = domain.ClaimFalse
		claim.Falsifier = domain.FalsifierGuards
		claim.EvidenceIDs = appendUniqueID(claim.EvidenceIDs, match.EvidenceID)
		claim.Explanation = "the contracted check is observed invoked against the anchored pipeline: " +
			match.Witness.Detail
		claim.Limitations = append(claim.Limitations,
			"FALSE is a candidate: check invocation presence does not guarantee path-specific effectiveness")
		return claim
	} else {
		claim.Limitations = append(claim.Limitations, reasons...)
	}
	return claim
}

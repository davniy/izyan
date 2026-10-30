package evaluator

import (
	"fmt"

	"github.com/fedorovmv/izyan/internal/domain"
)

// CheckTrigger evaluates the dedicated check-trigger and receiver-field
// input obligations of a DEFECTIVE_CHECK contract.
//
// TRUE requires one typed witness that carries the operation, the
// invocation/receiver identity, the advisory's argument literal, the
// receiver payload representation and an external control binding on the
// same record. External origin alone, a generic argument flow, a saved
// claim or facts assembled from different calls can never satisfy it.
//
// A FALSE candidate additionally requires the shared captured-source checker:
// every invocation's necessary boolean argument must have a safe effective
// configuration value. An individual contradictory witness is not that proof.
type CheckTrigger struct{}

func (CheckTrigger) CanEvaluate(cond domain.Condition) bool {
	return cond.Kind == domain.ConditionCheckTrigger || cond.Kind == domain.ConditionCheckInput
}

func (CheckTrigger) Evaluate(cond domain.Condition, c *domain.AnalysisCase) domain.Claim {
	claim := domain.Claim{
		ID:          domain.ClaimID("CL-" + string(cond.ID)),
		ConditionID: cond.ID,
		Result:      domain.ClaimUnknown,
		Producer:    "evaluator.CheckTrigger",
	}
	if c == nil || c.Exploit == nil {
		claim.Limitations = append(claim.Limitations, "no exploit model carrying defect semantics")
		return claim
	}
	contract := c.Exploit.DefectSemantics
	if contract == nil || contract.Mode != domain.DefectSemanticsDefectiveCheck || contract.Trigger == nil {
		claim.Limitations = append(claim.Limitations,
			"condition is not bound to an admitted DEFECTIVE_CHECK trigger contract")
		return claim
	}
	if !domain.CheckConditionMatchesContract(contract, cond) {
		claim.Limitations = append(claim.Limitations,
			"condition does not match the admitted trigger spec; refusing to evaluate it")
		return claim
	}
	obligation := domain.CheckTriggerObligationFull
	if domain.IsCheckInputCondition(cond) {
		obligation = domain.CheckTriggerObligationInput
	}
	match, reasons := domain.MatchCheckTriggerWitness(
		*contract.Trigger, contract.TriggerConditionID, c.EvidenceGraph.EvidenceList(), obligation)
	if match == nil {
		claim.Limitations = append(claim.Limitations,
			fmt.Sprintf("no typed witness establishes the check trigger on one invocation and receiver (%d refusal(s))",
				len(reasons)))
		claim.Limitations = append(claim.Limitations, reasons...)
		return evaluateConfigTriggerNegative(cond,c,claim)
	}
	claim.Result = domain.ClaimTrue
	claim.EvidenceIDs = appendUniqueID(claim.EvidenceIDs, match.EvidenceID)
	for _, id := range match.Witness.ControlEvidenceIDs {
		claim.EvidenceIDs = appendUniqueID(claim.EvidenceIDs, id)
	}
	claim.Explanation = fmt.Sprintf(
		"%s.%s is invoked at %s:%d with %s=%s and receiver field %q carrying %s; the value is externally controlled on the same invocation",
		match.Witness.Operation.Package, match.Witness.Operation.Symbol,
		match.Witness.Invocation.File, match.Witness.Invocation.Line,
		match.Witness.ArgumentName, match.Witness.ArgumentValue,
		match.Witness.ReceiverField, joinShapes(match.Witness.PayloadShapes))
	return claim
}

func joinShapes(shapes []string) string {
	if len(shapes) == 0 {
		return "unknown"
	}
	out := shapes[0]
	for _, s := range shapes[1:] {
		out += "/" + s
	}
	return out
}

package states

import (
	"context"
	"fmt"

	"github.com/davniy/izyan/internal/domain"
)

// actCollectEvidence verifies the model's admitted omission contract: it asks
// the source index whether the contracted check has any invocation on the
// active path of the contracted pipeline and records one typed
// MissingCallWitness. The witness is a source observation — the evaluator
// binds it to the admitted OMITTED_CHECK contract and the effective build
// before it may support an omission claim.
//
// A legacy model without an admitted contract collects nothing: an absence of
// typed evidence must stay UNKNOWN, never become an omission or a call
// observation.
func (h CollectEvidence) actCollectEvidence(ctx context.Context, c *domain.AnalysisCase) {
	if h.Source == nil || c == nil || c.Exploit == nil {
		return
	}
	contract := c.Exploit.DefectSemantics
	if contract == nil || contract.Mode != domain.DefectSemanticsOmittedCheck || contract.Pipeline == nil {
		return
	}
	// The contract must be the model's own omission shape; a contract that
	// does not bind this model's condition is not evidence about it.
	bound := false
	for _, cond := range c.Exploit.MandatoryConditions {
		if domain.OmissionConditionMatchesContract(contract, cond) {
			bound = true
			break
		}
	}
	if !bound {
		return
	}

	checkRef := contract.Check
	pipelineRef := *contract.Pipeline
	status, content, callers, err := h.Source.CheckMissingCall(ctx, checkRef, pipelineRef)
	if err != nil {
		c.EvidenceGraph.AddToolLimitation(fmt.Sprintf("missing-call check failed: %v", err))
		return
	}
	build := domain.EffectiveBuildContext(c.Product)
	witness := &domain.MissingCallWitness{
		RecordID:       contract.RecordID,
		Check:          checkRef,
		Pipeline:       pipelineRef,
		Status:         status,
		ProductCallers: callers,
		Detail:         content,
	}

	switch status {
	case domain.MissingCallOmitted:
		c.EvidenceGraph.AddEvidence(domain.Evidence{
			ID:           "EV-MISSING-CALL",
			Kind:         domain.EvidenceValidation,
			Quality:      domain.QualityDeterministic,
			Source:       "source index: missing-call verification",
			Tool:         "goanalysis.Index.CheckMissingCall",
			Content:      content,
			BuildContext: &build,
			MissingCall:  witness,
		})
		for _, mc := range c.Exploit.MandatoryConditions {
			if mc.ID == "C-INPUT" || mc.Kind == domain.ConditionAttackerControl || mc.Kind == domain.ConditionInputConstraint {
				for _, site := range callers {
					flows, evs, terr := h.traceArgs(ctx, site, mc)
					if terr != nil {
						continue
					}
					for i := range flows {
						flows[i].ConditionID = mc.ID
					}
					c.EvidenceGraph.AddArgumentTrace(flows, evs)
				}
			}
		}
	case domain.MissingCallPresent:
		c.EvidenceGraph.AddEvidence(domain.Evidence{
			ID:           "EV-CHECK-PRESENT",
			Kind:         domain.EvidenceValidation,
			Quality:      domain.QualityDeterministic,
			Source:       "source index: check-call verification",
			Tool:         "goanalysis.Index.CheckMissingCall",
			Content:      content,
			BuildContext: &build,
			MissingCall:  witness,
		})
	default:
		// An unestablished measurement (unreached pipeline, unresolved
		// declaration, truncated search) is a limitation, never evidence
		// that the check is present or absent.
		c.EvidenceGraph.AddToolLimitation(
			fmt.Sprintf("missing-call measurement not established for %s.%s on %s.%s: %s",
				checkRef.Package, checkRef.Symbol, pipelineRef.Package, pipelineRef.Symbol, content))
	}
}

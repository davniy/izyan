package evaluator

import (
	"fmt"
	"strings"

	"github.com/davniy/izyan/internal/domain"
)

// Authentication evaluates AUTHENTICATION_CONDITION conditions — whether the
// inbound surface feeding the vulnerable path is wired behind an
// authentication/authorization check.
//
// It never returns TRUE and never returns FALSE. The inbound auth-middleware
// facts this scan produces are matched by middleware/argument names next to a
// listener: they record that auth-like wiring exists, not that every route to
// the vulnerable surface passes it. Per-route coverage is measured by no
// producer here, so the claim stays UNKNOWN with a typed
// MEASUREMENT_NOT_COMPLETED gap — a middleware name is a nomination, not a
// witness. Absence of wiring is likewise not proof: per-handler, gateway and
// deployment-level auth are outside this scan, and a FALSE here would feed the
// dangerous direction.
type Authentication struct{}

func (Authentication) CanEvaluate(cond domain.Condition) bool {
	return cond.Kind == domain.ConditionAuthn
}

func (Authentication) Evaluate(cond domain.Condition, c *domain.AnalysisCase) domain.Claim {
	claim := domain.Claim{
		ID:          domain.ClaimID("CL-" + string(cond.ID)),
		ConditionID: cond.ID,
		Result:      domain.ClaimUnknown,
		Producer:    "evaluator.Authentication",
	}
	for _, e := range c.EvidenceGraph.EvidenceList() {
		if strings.Contains(e.Source, "InboundAuthFacts") {
			claim.EvidenceIDs = appendUniqueID(claim.EvidenceIDs, e.ID)
		}
	}
	var authFacts []string
	listeners := 0
	for _, f := range c.EvidenceGraph.ExposuresList() {
		if f.Direction != "inbound" {
			continue
		}
		switch f.Kind {
		case "auth-middleware":
			authFacts = append(authFacts,
				fmt.Sprintf("%s at %s:%d", f.Target, f.File, f.Line))
		case "listener":
			listeners++
		}
	}
	switch {
	case len(authFacts) == 0:
		claim.Limitations = append(claim.Limitations,
			"no auth-middleware wiring observed near listeners; per-handler, gateway or deployment auth is outside this scan — absence is not proof")
	case listeners == 0:
		claim.Limitations = append(claim.Limitations,
			fmt.Sprintf("auth-middleware wiring observed (%s) but no inbound listener resolved — the wired surface may be dead code", strings.Join(authFacts, "; ")))
	default:
		claim.Explanation = fmt.Sprintf(
			"auth wiring observed by name next to an inbound listener: %s",
			strings.Join(authFacts, "; "))
		claim.Limitations = append(claim.Limitations,
			"middleware matched by name and position; per-route coverage is not proven — some paths may bypass the check")
	}
	claim.Limitations = append(claim.Limitations,
		"a middleware name establishes no per-route authentication coverage, so the condition stays unresolved")
	claim.AnalysisGaps = []domain.AnalysisGap{{
		Owner:        domain.GapOwnerProof,
		Code:         domain.GapMeasurementNotCompleted,
		Obligation:   domain.ObligationCondition,
		AssessmentID: c.ID,
		ConditionID:  cond.ID,
		Message: "per-route authentication coverage of the surface feeding " + string(cond.ID) +
			" was not measured: name-matched auth wiring is a nomination, not coverage",
	}}
	return claim
}

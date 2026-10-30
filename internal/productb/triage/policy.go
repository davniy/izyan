package triage

import (
	"fmt"
	"strings"
)

// CLI exit codes for `izyan triage`. A policy threshold hit is not a
// technical failure, so it gets its own code distinct from input/agent/fact
// gate errors.
const (
	// ExitCodeOK — all completed assessments passed the configured thresholds.
	ExitCodeOK = 0
	// ExitCodePolicy — at least one assessment matched a --fail-on threshold.
	ExitCodePolicy = 1
	// ExitCodeError — technical failure: bad input, agent run error, fact gate
	// failure, or an unknown --fail-on value.
	ExitCodeError = 2
)

// FailOn is one --fail-on threshold for the triage CLI.
type FailOn string

// The spec §2.3 fail-on thresholds for decision packages. They are the
// only values --fail-on and policy.fail_on accept: the compatibility
// assessment-level thresholds (exploitable/unverified-negative/
// inconclusive) are gone; an unknown value still fails closed.
const (
	FailOnUnchanged             FailOn = "unchanged"
	FailOnLowSupport            FailOn = "low-support"
	FailOnConditional           FailOn = "conditional"
	FailOnUnverifiedDisposition FailOn = "unverified-disposition"
)

// PackagePolicyHit reports whether the composed package trips one §2.3
// threshold. The check is pure policy evaluation — no field of the package
// is ever mutated, and a hit is a delivery/policy signal, never a statement
// about safety. Each threshold reads exactly one result axis:
//
//   - unchanged: the machine disposition establishes no reduction;
//   - low-support: the human support derived from the decisive premises is
//     INSUFFICIENT or LIMITED;
//   - conditional: decisive human assumptions/unknowns or machine
//     conditional premises remain open;
//   - unverified-disposition: the machine recorded demotions or an
//     admission limitation, so the entitlement to a reduction was not
//     established.
func PackagePolicyHit(p DecisionPackage, f FailOn) bool {
	switch f {
	case FailOnUnchanged:
		return p.MachineDisposition.Recommendation == RecommendationUnchanged
	case FailOnLowSupport:
		return p.Support.Level == SupportLevelInsufficient || p.Support.Level == SupportLevelLimited
	case FailOnConditional:
		if len(p.Unknowns) > 0 {
			return true
		}
		for _, pr := range p.Premises {
			switch pr.Basis {
			case PremiseAssumed, PremiseUnresolved, PremiseConflicting:
				return true
			}
		}
		if len(p.MachineDisposition.ConditionalProfiles) > 0 {
			return true
		}
		for _, a := range p.MachineDisposition.ResidualAssumptions {
			if a.Status != ConditionSatisfied {
				return true
			}
		}
		return false
	case FailOnUnverifiedDisposition:
		return len(p.MachineDisposition.Demotions) > 0
	}
	return false
}

func (f FailOn) Valid() bool {
	switch f {
	case FailOnUnchanged, FailOnLowSupport, FailOnConditional, FailOnUnverifiedDisposition:
		return true
	}
	return false
}

// ParseFailOn validates one --fail-on flag value.
func ParseFailOn(s string) (FailOn, error) {
	f := FailOn(s)
	if !f.Valid() {
		return "", fmt.Errorf("unknown --fail-on %q (want unchanged|low-support|conditional|unverified-disposition)", s)
	}
	return f, nil
}

// EvaluateMachineAutomation derives the machine policy outcome from the
// machine disposition alone. The verdict × reference-completeness matrix it
// replaces is gone: the model judgment, the proposed human action, the
// derived support and a human acceptance can never raise or lower it.
//
//   - BLOCK when a machine prerequisite is invalid or failed: fact
//     validation is FAILED/unknown, the recommendation is invalid, a
//     demotion withdrew the reduction, or the arbitration recorded a
//     divergence the machine layer could not resolve;
//   - WARN for every valid package whose machine disposition establishes
//     no reduction — including a stated machine limitation such as absent
//     severity metadata;
//   - ALLOW only for a machine reduction the rule/check/proof path actually
//     admitted: a complete fact basis with no recorded demotion and no
//     still-open blocking premise.
func EvaluateMachineAutomation(m MachineDisposition, validation FactValidationStatus) AutomationStatus {
	if validation != ValidationComplete && validation != ValidationPartial {
		return AutomationBlock
	}
	if !m.Recommendation.Valid() {
		return AutomationBlock
	}
	if m.Recommendation == RecommendationUnchanged {
		return AutomationWarn
	}
	if len(m.Demotions) > 0 || m.Arbitration == ArbitrationDivergeHuman {
		return AutomationBlock
	}
	for _, c := range m.ResidualAssumptions {
		if c.Status != ConditionSatisfied && strings.HasPrefix(c.Effect, "blocks_") {
			return AutomationBlock
		}
	}
	if validation != ValidationComplete {
		// The reduction is admissible, but a partial fact basis is not a
		// complete automation basis.
		return AutomationWarn
	}
	return AutomationAllow
}

// ExitCode evaluates the run against the configured --fail-on thresholds:
// ExitCodeError (2) wins whenever any finding failed technically — a
// technical error is never masked by a policy outcome — and whenever a
// successful assessment lacks its decision package or a threshold value is
// invalid, since both are configuration/consistency errors that must fail
// closed rather than be silently ignored. Otherwise ExitCodePolicy (1) when
// at least one composed package trips a configured threshold, else
// ExitCodeOK (0). An empty failOn list means no thresholds are configured:
// nothing can trip and the run passes. Policy evaluation is pure: it never
// mutates recommendation, facts, rationale or audit.
func ExitCode(assessments []Assessment, decisions []DecisionPackage, failures int, failOn []FailOn) int {
	for _, f := range failOn {
		if !f.Valid() {
			return ExitCodeError
		}
	}
	if failures > 0 {
		return ExitCodeError
	}
	if len(decisions) < len(assessments) {
		return ExitCodeError
	}
	for _, p := range decisions {
		for _, f := range failOn {
			if PackagePolicyHit(p, f) {
				return ExitCodePolicy
			}
		}
	}
	return ExitCodeOK
}

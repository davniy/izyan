package research

import (
	"fmt"
	"io/fs"
)

// SafetyPolicy is the R6 configuration surface for the decision lane:
// the rules a decision must satisfy, the checks a run must schedule and
// the promotions that must stay forbidden. Configuration may only ever
// tighten this policy — add required rules or checks, add forbidden
// promotions — never relax it.
type SafetyPolicy struct {
	RequiredRules       []string `json:"required_rules"`
	RequiredChecks      []string `json:"required_checks"`
	ForbiddenPromotions []string `json:"forbidden_promotions"`
}

// baselineRules is the immutable floor: the gates VerifyDecision already
// enforces plus the R6 trust boundary. Every entry names a required
// decision gate; a candidate policy that drops any of them is a
// relaxation and is rejected.
var baselineRules = []string{
	"applicability-first-ordering",            // a proven FALSE applicability chain resolves before any proposal
	"advisory-wide-subject-coverage",          // a negative must cover every advisory-declared subject
	"exact-subject-identity-and-granularity",  // proposals and proofs bind the declared subject exactly
	"request-audit-argument-binding",          // every executed check binds the request's typed arguments
	"matching-snapshot-and-build-context",     // trace observations run under the lane's recorded context
	"digest-resolved-evidence-references",     // every evidence ref resolves to a recorded observation/fact
	"complete-observation-coverage",           // an incomplete or partial trace never promotes a terminal verdict
	"positive-contradiction-check",            // positive evidence for a declared subject blocks the negative
	"empty-limitations-for-terminal-negative", // a terminal negative carries no unresolved limitations
	"trusted-infrastructure-only-mitigation",  // declared trust may only premise ACCEPT_ENVIRONMENTAL_MITIGATION
	"no-agent-assertion-to-fact",              // an agent assertion never becomes a verified fact
	"no-environment-assertion-as-falsifier",   // an environment answer never becomes a code-level falsifier
}

// baselineChecks are the deterministic checks the policy must always
// require (mirrors BaselineChecks in dispositions.go).
var baselineChecks = BaselineChecks

// baselineForbiddenPromotions are the promotions that must stay
// forbidden in every configuration.
var baselineForbiddenPromotions = []string{
	"agent-assertion-to-verified-fact",
	"agent-proposal-to-verdict",
	"environment-assertion-to-claim-false",
	"trusted-infrastructure-to-close-no-exploit-path",
	"declared-trust-to-close-not-affected",
	"unknown-to-false",
	"partial-observation-to-verified-fact",
	"confidence-to-verdict",
}

// BaselineSafetyPolicy returns the immutable required-gate floor. Every
// loadable configuration must preserve every baseline member; it may
// only add requirements, narrow scope or add vetoes.
func BaselineSafetyPolicy() SafetyPolicy {
	return SafetyPolicy{
		RequiredRules:       append([]string(nil), baselineRules...),
		RequiredChecks:      append([]string(nil), baselineChecks...),
		ForbiddenPromotions: append([]string(nil), baselineForbiddenPromotions...),
	}
}

type safetyPolicyFile struct {
	Schema              string   `json:"schema"`
	RequiredRules       []string `json:"required_rules"`
	RequiredChecks      []string `json:"required_checks"`
	ForbiddenPromotions []string `json:"forbidden_promotions"`
}

// LoadSafetyPolicy reads the safety policy file from fsys (rooted at the
// repository root) and enforces monotonicity against the baseline: a
// missing, malformed or relaxed policy is an error — the loader never
// falls back to a permissive default.
func LoadSafetyPolicy(fsys fs.FS) (SafetyPolicy, error) {
	var f safetyPolicyFile
	if err := readCatalogJSON(fsys, SafetyPolicyPath, &f); err != nil {
		return SafetyPolicy{}, err
	}
	if f.Schema != safetyPolicySchema {
		return SafetyPolicy{}, fmt.Errorf("research policy %s: schema %q != %q", SafetyPolicyPath, f.Schema, safetyPolicySchema)
	}
	p := SafetyPolicy{
		RequiredRules:       f.RequiredRules,
		RequiredChecks:      f.RequiredChecks,
		ForbiddenPromotions: f.ForbiddenPromotions,
	}
	e := &ValidationError{}
	checkStringSet(e, "required_rules", p.RequiredRules)
	checkStringSet(e, "required_checks", p.RequiredChecks)
	checkStringSet(e, "forbidden_promotions", p.ForbiddenPromotions)
	if len(e.Problems) > 0 {
		return SafetyPolicy{}, e
	}
	if err := ValidateMonotonicPolicy(BaselineSafetyPolicy(), p); err != nil {
		return SafetyPolicy{}, err
	}
	return p, nil
}

// ValidateMonotonicPolicy enforces the R6 monotonic configuration rule:
// the candidate must preserve every baseline required rule, required
// check and forbidden promotion; it may only add members. Removing or
// renaming a baseline member is a relaxation and is rejected.
func ValidateMonotonicPolicy(base, candidate SafetyPolicy) error {
	e := &ValidationError{}
	mustKeep := func(kind string, required, got []string) {
		set := map[string]bool{}
		for _, s := range got {
			set[s] = true
		}
		for _, req := range required {
			if !set[req] {
				e.add("safety policy is not monotonic: candidate removes required %s %q", kind, req)
			}
		}
	}
	mustKeep("rule", base.RequiredRules, candidate.RequiredRules)
	mustKeep("check", base.RequiredChecks, candidate.RequiredChecks)
	mustKeep("forbidden promotion", base.ForbiddenPromotions, candidate.ForbiddenPromotions)
	if len(e.Problems) > 0 {
		return e
	}
	return nil
}

func checkStringSet(e *ValidationError, field string, ss []string) {
	if len(ss) == 0 {
		e.add("safety policy %s must list at least one member", field)
		return
	}
	seen := map[string]bool{}
	for _, s := range ss {
		if s == "" {
			e.add("safety policy %s: empty member", field)
			continue
		}
		if seen[s] {
			e.add("safety policy %s: %q listed twice", field, s)
		}
		seen[s] = true
	}
}

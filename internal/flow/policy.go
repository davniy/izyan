package flow

import (
	"fmt"
	"strings"
)

// The flow layer's safety policy is monotonic by construction
// (Amendment R6): a configuration or a mid-run reassessment may add
// required rules, required checks or forbidden promotions — it may
// never remove a member of the baseline floor, never relax the running
// policy, and never carry malformed members or negative budgets. There
// is no permissive default: a zero Baseline means the configured
// policy itself is the floor, not that anything goes.

// ValidateMonotonicPolicy enforces the monotonic rule: candidate must
// preserve every required rule, required check and forbidden promotion
// of base. Removing or renaming a baseline member is a relaxation and
// is rejected. An empty base is satisfied by any well-formed candidate —
// callers carrying a real floor (the research lane's baseline) must
// supply it through Input.Baseline.
func ValidateMonotonicPolicy(base, candidate Policy) error {
	var problems []string
	mustKeep := func(kind string, required, got []string) {
		set := map[string]bool{}
		for _, s := range got {
			set[s] = true
		}
		for _, req := range required {
			if !set[req] {
				problems = append(problems,
					fmt.Sprintf("policy is not monotonic: candidate removes required %s %q", kind, req))
			}
		}
	}
	mustKeep("rule", base.RequiredRules, candidate.RequiredRules)
	mustKeep("check", base.RequiredChecks, candidate.RequiredChecks)
	mustKeep("forbidden promotion", base.ForbiddenPromotions, candidate.ForbiddenPromotions)
	if len(problems) > 0 {
		return fmt.Errorf("flow policy violation:\n - %s", strings.Join(problems, "\n - "))
	}
	return nil
}

// validatePolicy checks one policy's internal shape: no empty members,
// no duplicates, non-negative budgets. Membership is a set — order and
// repetition carry no meaning, so a duplicated member is malformed.
func validatePolicy(p Policy) error {
	var problems []string
	checkSet := func(field string, ss []string) {
		seen := map[string]bool{}
		for _, s := range ss {
			if s == "" {
				problems = append(problems, "policy "+field+": empty member")
				continue
			}
			if seen[s] {
				problems = append(problems, fmt.Sprintf("policy %s: %q listed twice", field, s))
			}
			seen[s] = true
		}
	}
	checkSet("required_rules", p.RequiredRules)
	checkSet("required_checks", p.RequiredChecks)
	checkSet("forbidden_promotions", p.ForbiddenPromotions)
	if p.MaxSteps < 0 || p.MaxActions < 0 {
		problems = append(problems, "policy budgets must be non-negative")
	}
	if len(problems) > 0 {
		return fmt.Errorf("flow policy malformed:\n - %s", strings.Join(problems, "\n - "))
	}
	return nil
}

// normalizePolicyAdoption clamps a candidate policy admitted by
// monotonic validation into the run's runtime shape: budgets are
// resolved at run start and never change mid-run, so an adopted
// tightening keeps the running budgets.
func normalizePolicyAdoption(candidate Policy, budget Budget) Policy {
	candidate.MaxSteps = budget.MaxSteps
	candidate.MaxActions = budget.MaxActions
	return candidate
}

// resolveBudget derives the deterministic step/action bounds for one
// run: an explicit Engine field wins over the policy value, which wins
// over the package default. Negative values anywhere are a contract
// error the caller must fix, not a run outcome.
func (e *Engine) resolveBudget() (Budget, error) {
	b := Budget{MaxSteps: DefaultMaxSteps, MaxActions: DefaultMaxActions}
	if e.Policy.MaxSteps != 0 {
		if e.Policy.MaxSteps < 0 {
			return Budget{}, fmt.Errorf("flow: policy max_steps %d is negative", e.Policy.MaxSteps)
		}
		b.MaxSteps = e.Policy.MaxSteps
	}
	if e.Policy.MaxActions != 0 {
		if e.Policy.MaxActions < 0 {
			return Budget{}, fmt.Errorf("flow: policy max_actions %d is negative", e.Policy.MaxActions)
		}
		b.MaxActions = e.Policy.MaxActions
	}
	if e.MaxSteps != 0 {
		if e.MaxSteps < 0 {
			return Budget{}, fmt.Errorf("flow: engine MaxSteps %d is negative", e.MaxSteps)
		}
		b.MaxSteps = e.MaxSteps
	}
	if e.MaxActions != 0 {
		if e.MaxActions < 0 {
			return Budget{}, fmt.Errorf("flow: engine MaxActions %d is negative", e.MaxActions)
		}
		b.MaxActions = e.MaxActions
	}
	b.StepsLeft = b.MaxSteps
	b.ActionsLeft = b.MaxActions
	return b, nil
}

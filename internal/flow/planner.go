package flow

import (
	"fmt"
)

// Plan admission is fail-closed and runs before any action executes.
// The planner is untrusted output, not authority: every action must
// satisfy the registry, every referenced condition must exist, the
// step must fit inside the remaining budget, and the plan's shape must
// be well-formed (non-empty, unique action ids, no empty fields). A
// rejected plan executes nothing — the run terminates with the
// rejection recorded.

// planVerdict classifies a rejected plan: structural malformation is a
// planner failure, an unregistered check or condition is an
// unsupported request, and a plan that does not fit the remaining
// budget is a budget stop.
type planVerdict int

const (
	planAdmit planVerdict = iota
	planMalformed
	planUnsupported
	planOverBudget
)

// validatePlan checks one plan against the registry and the remaining
// budget. It returns the verdict plus the recorded reason.
func validatePlan(reg Registry, p *Plan, remainingActions int) (planVerdict, string) {
	if len(p.Actions) == 0 && len(p.ConditionIDs) == 0 {
		return planMalformed, "plan is empty: a planner that has nothing to do must let the reassessor close the run"
	}
	if len(p.Actions) > remainingActions {
		return planOverBudget, fmt.Sprintf("plan carries %d actions but only %d remain in the run's action budget", len(p.Actions), remainingActions)
	}
	seenAct := map[string]bool{}
	for i := range p.Actions {
		a := &p.Actions[i]
		where := fmt.Sprintf("actions[%d]", i)
		if a.ID == "" {
			return planMalformed, where + ": action id required"
		}
		if seenAct[a.ID] {
			return planMalformed, fmt.Sprintf("%s: action id %q duplicated in one plan", where, a.ID)
		}
		seenAct[a.ID] = true
		if err := reg.Check(*a); err != nil {
			return planUnsupported, fmt.Sprintf("action %q: %v", a.ID, err)
		}
		if a.ConditionID != "" {
			if _, ok := reg.Condition(a.ConditionID); !ok {
				return planUnsupported, fmt.Sprintf("action %q references unknown condition %q", a.ID, a.ConditionID)
			}
		}
	}
	seenCond := map[string]bool{}
	for _, id := range p.ConditionIDs {
		if id == "" {
			return planMalformed, "condition_ids carries an empty member"
		}
		if seenCond[id] {
			return planMalformed, fmt.Sprintf("condition %q listed twice in one plan", id)
		}
		seenCond[id] = true
		if _, ok := reg.Condition(id); !ok {
			return planUnsupported, fmt.Sprintf("plan engages unknown condition %q", id)
		}
	}
	return planAdmit, ""
}

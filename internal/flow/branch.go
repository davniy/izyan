package flow

import (
	"fmt"
	"strings"
)

// The branch ledger is append-only by construction: reassessments may
// claim a new status for a branch, but earlier revisions are never
// rewritten and the loop only ever records claims — the
// decision-artifact builder re-derives every branch's real status from
// the fact envelope. A branch revision carries no disposition and no
// environment value, so the agent can never write truth through it.
// branchLedger tracks the current claim per branch id plus its full
// revision history.
type branchLedger struct {
	order []string
	byID  map[string]*BranchState
}

func newBranchLedger() *branchLedger {
	return &branchLedger{byID: map[string]*BranchState{}}
}

// apply records one revision: the claim is appended to the branch's
// history and becomes its current status.
func (l *branchLedger) apply(r BranchRevision) {
	st, ok := l.byID[r.BranchID]
	if !ok {
		st = &BranchState{ID: r.BranchID}
		l.byID[r.BranchID] = st
		l.order = append(l.order, r.BranchID)
	}
	st.Revisions = append(st.Revisions, r)
	st.Status = r.Status
}

// states returns the current claim per branch in first-seen order.
func (l *branchLedger) states() []BranchState {
	out := make([]BranchState, 0, len(l.order))
	for _, id := range l.order {
		out = append(out, *l.byID[id])
	}
	return out
}

// countStatus reports how many recorded branches currently claim s.
func (l *branchLedger) countStatus(s string) int {
	n := 0
	for _, id := range l.order {
		if l.byID[id].Status == s {
			n++
		}
	}
	return n
}

// admitReassessment validates one reassessment against the recorded
// state before the engine applies it. It returns the admission
// problems plus a flag marking whether any problem names an
// unregistered check or condition (which terminates as
// UNSUPPORTED_CHECK_OR_CONDITION rather than as a reassessor
// malformation).
//
// Checks:
//   - status is a member of the closed enum;
//   - every revision names a branch and a valid status;
//   - revision ids are unique within the reassessment;
//   - every required input names a registry-known condition;
//   - AWAITING_ENVIRONMENT carries at least one declared input.
func admitReassessment(reg Registry, r *Reassessment) ([]string, bool) {
	var problems []string
	unsupported := false
	if !isReassessStatus(r.Status) {
		problems = append(problems, fmt.Sprintf("reassessment status %q is not a member of the closed enum", r.Status))
	}
	seenRev := map[string]bool{}
	for i, rev := range r.Revisions {
		where := fmt.Sprintf("revisions[%d]", i)
		if rev.BranchID == "" {
			problems = append(problems, where+": branch_id required")
			continue
		}
		if !isBranchStatus(rev.Status) {
			problems = append(problems, fmt.Sprintf("%s: status %q invalid", where, rev.Status))
		}
		if seenRev[rev.BranchID] {
			problems = append(problems, fmt.Sprintf("%s: branch %q revised twice in one reassessment", where, rev.BranchID))
		}
		seenRev[rev.BranchID] = true
	}
	seenIn := map[string]bool{}
	for _, in := range r.RequiredInputs {
		if in == "" {
			problems = append(problems, "required input is empty")
			continue
		}
		if seenIn[in] {
			problems = append(problems, fmt.Sprintf("required input %q declared twice", in))
		}
		seenIn[in] = true
		if _, ok := reg.Condition(in); !ok {
			unsupported = true
			problems = append(problems, fmt.Sprintf("required input %q names no known condition", in))
		}
	}
	if r.Status == ReassessAwaitingEnvironment && len(r.RequiredInputs) == 0 {
		problems = append(problems, "AWAITING_ENVIRONMENT names no required input — the claim is self-contradictory")
	}
	return problems, unsupported
}

// deterministicTermination computes terminal readiness from the recorded
// ledger. The model status is retained only as an advisory view; it cannot
// make a complete ledger non-ready or make incomplete evidence ready.
// An undischarged required check is named first — it is the actionable,
// check-level cause — before the generic ledger-degradation reason.
func deterministicTermination(r *Reassessment, led *branchLedger, ledgerComplete bool, missingRequired []string) (Termination, string) {
	if len(missingRequired) > 0 {
		return TermNotDecisionReady,
			fmt.Sprintf("policy-required checks remain undischarged: %s", strings.Join(missingRequired, ", "))
	}
	if !ledgerComplete {
		return TermNotDecisionReady, "observation ledger carries degraded, unbound or incomplete coverage"
	}
	if r.Status == ReassessTerminalContradiction && led.countStatus(BranchStatusContradicted) == 0 {
		return TermNotDecisionReady, "terminal contradiction claim has no recorded contradicted branch"
	}
	if len(r.RequiredInputs) > 0 || led.countStatus(BranchStatusAwaitingInput) > 0 {
		return TermAwaitingEnvironment, "decision-relevant environment conditions remain unresolved"
	}
	if led.countStatus(BranchStatusContradicted) > 0 {
		return TermTerminalContradiction, "a recorded decision branch is contradicted"
	}
	for _, id := range led.order {
		if led.byID[id].Status != BranchStatusComplete {
			return TermNotDecisionReady,
				fmt.Sprintf("decision branch %q is %s", id, led.byID[id].Status)
		}
	}
	if len(led.order) > 0 {
		if r.Status == ReassessReady {
			return TermDecisionReady, r.Detail
		}
		return TermBranchesComplete, r.Detail
	}
	return TermDecisionReady, r.Detail
}

// checkTerminalClaim is retained for package-local compatibility with older
// callers; terminal status is now derived by deterministicTermination.
func checkTerminalClaim(r *Reassessment, led *branchLedger, ledgerComplete bool, missingRequired []string) (Termination, string) {
	return deterministicTermination(r, led, ledgerComplete, missingRequired)
}

// dischargedChecks derives which policy-required check ids have a
// produced observation whose recorded payload answers the check's
// question: an OK, audit-bound, digest-pinned observation is
// dischargeable when it is either COMPLETE (the closed-negative path)
// or carries a stamped positive answer (DischargePositiveAnswer —
// e.g. package-usage reports USED at PARTIAL by contract; the
// recorded interpretation bound rides in its limitations). produced
// actions and observations pair by dispatch index (the executed
// prefix), matching the trace convention. Only produced observations
// discharge a requirement — prior evidence is context, and a missing
// or degraded observation that answers nothing never counts.
func dischargedChecks(actions []PlanAction, produced []Observation, completed []string) map[string]bool {
	out := map[string]bool{}
	for _, c := range completed {
		if c != "" {
			out[c] = true
		}
	}
	for i, o := range produced {
		if i >= len(actions) {
			break
		}
		if o.Status == ObsStatusOK && o.AuditBound && o.DataDigest != "" &&
			(o.Completeness == ObsComplete || o.DischargePath == DischargePositiveAnswer) {
			out[actions[i].AdapterID] = true
		}
	}
	return out
}

// requiredCoverage lists the policy-required check ids with no
// discharged observation — the missing coverage recorded as a
// limitation.
func requiredCoverage(required []string, discharged map[string]bool) []string {
	var missing []string
	for _, c := range required {
		if !discharged[c] {
			missing = append(missing, c)
		}
	}
	return missing
}

func requiredCoverageWithInapplicable(required []string, discharged map[string]bool, inapplicable []string) []string {
	ignored := make(map[string]bool, len(inapplicable))
	for _, c := range inapplicable {
		if c != "" {
			ignored[c] = true
		}
	}
	var missing []string
	for _, c := range required {
		if !discharged[c] && !ignored[c] {
			missing = append(missing, c)
		}
	}
	return missing
}

// formatProblems renders admission problems into one limitation string.
func formatProblems(prefix string, problems []string) string {
	return prefix + ": " + strings.Join(problems, "; ")
}

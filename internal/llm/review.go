package llm

import (
	"context"
	"encoding/json"

	"github.com/davniy/izyan/internal/domain"
)

// Reviewer asks the analyze model to audit the proposed-verdict package.
// It complements the structural reviewer: findings are advisory — they
// trigger the same bounded repair (claim demotion) and record condition
// nominations, never a stronger claim or a condition move.
type Reviewer struct {
	Client *Client
}

const reviewSystem = `You are a security review auditor. Given a vulnerability
analysis package (root cause, exploit conditions, claims, limitations,
proposed verdict), find problems the pipeline missed: unsupported claims,
missed mandatory conditions, scope mismatch, dynamic behavior, contradicted
evidence, wrong patch interpretation.
Claim semantics — read before judging "contradictions":
- A FALSE claim on a mandatory exploit condition means "the product's inputs
  or paths provably cannot satisfy this condition" — a legitimate safe
  outcome (verdict NO_EXPLOIT_PATH_FOUND), NOT a claim that the advisory or
  root cause is wrong. The advisory describes the dependency's flaw; claims
  describe whether this product snapshot can trigger it. A FALSE claim does
  not "contradict the root cause mechanism" just because the condition text
  restates the mechanism.
- negative_verification VERIFIED on a FALSE claim means the falsifier was
  re-checked against dynamic-dispatch and coverage markers. If the claim was
  later demoted to UNKNOWN by a review, the VERIFIED tag stays as history —
  that pairing is expected, not an internal contradiction.
- Demote a FALSE claim only when you can point to a concrete artifact in
  the problem text: an uncovered write site, a traced external origin, a
  dynamic-dispatch marker, or a missing condition — not because its
  conclusion feels incompatible with the advisory. Naming a desired check
  outcome in required_check or an artifact absent from the claim's own
  record is recorded as advisory; the VERIFIED FALSE stands.
Output JSON: {"result":"ACCEPT"|"REVISE","findings":[{"target_type":"claim|condition|model|verdict","target_id":"...","action":"promote|demote","problem":"...","severity":"low|medium|high","required_check":"..."}]}
Condition actions (target_type=condition, severity=high only) are nominations,
not repairs. The pipeline never moves a condition because a reviewer asked:
- "demote": nominate this mandatory condition as not necessary. Repair applies
  it only when the deterministic applicability contract names a concrete
  mechanism mismatch for that condition. Otherwise the condition stays in the
  conjunction and the critique is recorded as a pending review that blocks
  closure.
- "promote": nominate this supporting condition as necessary. No deterministic
  contract proves necessity, so the condition stays supporting; a passing
  applicability check does not establish that a condition is required.
Omit "action" on every other finding. A high-severity finding on a mandatory
condition without an action is recorded as a pending review and blocks
closure until an independently established repair resolves it.
Never propose a different verdict. Only flag gaps a human would check.`

func (rv Reviewer) Review(c *domain.AnalysisCase, proposed domain.VerdictResult) domain.Review {
	r := domain.Review{Result: domain.ReviewAccept}
	if rv.Client == nil || llmBudgetExhausted(c) {
		if c.StrictLLM {
			r.Result = domain.ReviewRevise
			r.Findings = append(r.Findings, domain.ReviewFinding{
				TargetType: "verdict", Severity: "high",
				Problem: "strict-llm: llm client unavailable or budget exhausted for review",
			})
		}
		return r
	}
	payload := reviewPayload(c, proposed)
	user, _ := json.Marshal(payload)
	c.IncLLMCalls()
	out, finish, err := rv.Client.Complete(context.Background(), Analyze, reviewSystem, string(user))
	if err != nil {
		sev := "low"
		prob := "llm review unavailable: " + err.Error()
		if c.StrictLLM {
			sev = "high"
			prob = "strict-llm: " + prob
			r.Result = domain.ReviewRevise
		}
		r.Findings = append(r.Findings, domain.ReviewFinding{
			TargetType: "verdict", Severity: sev,
			Problem: prob,
		})
		return r
	}
	var resp struct {
		Result   string                 `json:"result"`
		Findings []domain.ReviewFinding `json:"findings"`
	}
	if j := ExtractJSON(out); j == "" || json.Unmarshal([]byte(j), &resp) != nil {
		sev := "low"
		prob := "llm review response unusable: " + DescribeBadOutput(out, finish)
		if c.StrictLLM {
			sev = "high"
			prob = "strict-llm: " + prob
			r.Result = domain.ReviewRevise
		}
		r.Findings = append(r.Findings, domain.ReviewFinding{
			TargetType: "verdict", Severity: sev,
			Problem: prob,
		})
		return r
	}
	if resp.Result == "REVISE" && len(resp.Findings) == 0 {
		resp.Result = "ACCEPT"
	}
	for _, f := range resp.Findings {
		if f.Severity != "high" && f.Severity != "medium" && f.Severity != "low" {
			f.Severity = "low"
		}
		// Only the exact action contract is recorded downstream: an
		// unknown or missing action stays empty and carries no hidden
		// promote/demote semantics. A valid action is a nomination, not
		// a mutation.
		switch f.Action {
		case domain.ReviewActionPromote, domain.ReviewActionDemote:
		default:
			f.Action = ""
		}
		r.Findings = append(r.Findings, f)
	}
	if resp.Result == "REVISE" {
		r.Result = domain.ReviewRevise
	}
	return r
}

func reviewPayload(c *domain.AnalysisCase, proposed domain.VerdictResult) any {
	claims := make([]map[string]any, 0, len(c.Claims))
	for _, cl := range c.Claims {
		nv := ""
		if cl.NegativeVerification != nil {
			nv = string(cl.NegativeVerification.Status)
		}
		claims = append(claims, map[string]any{
			"id": cl.ID, "condition": cl.ConditionID, "result": cl.Result,
			"evidence": len(cl.EvidenceIDs), "negative_verification": nv,
			"limitations": cl.Limitations,
		})
	}
	var conds []map[string]any
	var proposedConds []map[string]any
	var pending []domain.ConditionID
	if c.Exploit != nil {
		for _, cond := range c.Exploit.MandatoryConditions {
			conds = append(conds, conditionPayload(cond, true))
		}
		for _, cond := range c.Exploit.SupportingFactors {
			conds = append(conds, conditionPayload(cond, false))
		}
		for _, cond := range c.Exploit.ProposedConditions {
			entry := conditionPayload(cond, false)
			entry["proposed"] = true
			proposedConds = append(proposedConds, entry)
		}
		pending = c.Exploit.PendingConditionReviews
	}
	var rcs []map[string]any
	if c.RootCause != nil {
		for _, r := range c.RootCause.RootCauses {
			rcs = append(rcs, map[string]any{
				"package": r.Package, "symbol": r.Symbol, "role": r.Role,
				"mechanism": r.Mechanism,
			})
		}
	}
	return map[string]any{
		"vulnerability":             c.Vulnerability.ID,
		"summary":                   c.Vulnerability.Summary,
		"root_causes":               rcs,
		"conditions":                conds,
		"proposed_conditions":       proposedConds,
		"pending_condition_reviews": pending,
		"claims":                    claims,
		"limitations":               c.EvidenceGraph.Limitations,
		"tool_limitations":          c.EvidenceGraph.ToolLimitations,
		"proposed_verdict":          proposed.Verdict,
		"proposed_reason":           proposed.Reason,
	}
}

// conditionPayload serializes one condition for the reviewer. The
// mandatory flag distinguishes the authoritative conjunction from
// nonblocking factors; proposed model conditions are serialized in a
// separate list, marked proposed, and cannot be acted on.
func conditionPayload(cond domain.Condition, mandatory bool) map[string]any {
	subjects := cond.Subjects
	if len(subjects) == 0 && cond.Subject != nil {
		subjects = []domain.SymbolRef{*cond.Subject}
	}
	return map[string]any{
		"id": cond.ID, "kind": cond.Kind, "description": cond.Description,
		"mandatory": mandatory, "params": cond.Params, "subjects": subjects,
	}
}

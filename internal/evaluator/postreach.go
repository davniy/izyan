package evaluator

import (
	"fmt"
	"strings"
	"time"

	"github.com/davniy/izyan/internal/domain"
)

// postReachProducer marks claims produced by the exact-argument
// post-reach configuration route. closureGate and negative verification
// use it to distinguish this strict route from the code-level transport
// trusted-infrastructure falsifier.
const postReachProducer = "evaluator.PostReachConfig"

// postReachRequiredScope is the scope an administrator-config trust
// assumption must cover: the threat-model decision is product-wide, and
// a narrower deployment/artifact/config-surface declaration cannot stand
// in for it.
const postReachRequiredScope = domain.AssumptionScopeProduct

// postReachApplicable reports whether the case's affected chain is
// resolved TRUE — the post-reach route only evaluates an applicable
// vulnerable component, never one whose applicability is undecided or
// already refuted.
func postReachApplicable(c *domain.AnalysisCase) (bool, string) {
	if c == nil || c.Affected == nil {
		return false, "affected applicability is not resolved"
	}
	a := c.Affected
	switch {
	case a.ModulePresent != domain.ClaimTrue:
		return false, "affected module presence is not TRUE"
	case a.VersionAffected != domain.ClaimTrue:
		return false, "affected version applicability is not TRUE"
	case a.PackagePresent != domain.ClaimTrue:
		return false, "affected package presence is not TRUE"
	case a.BuildRelevant != domain.ClaimTrue:
		return false, "affected build relevance is not TRUE"
	}
	return true, ""
}

// postReachSubjects returns the condition's exact subject set (the
// singular Subject plus the grouped Subjects, deduplicated).
func postReachSubjects(cond domain.Condition) []domain.SymbolRef {
	var out []domain.SymbolRef
	seen := map[string]bool{}
	add := func(s domain.SymbolRef) {
		key := s.Package + "." + s.Symbol
		if s.Package == "" || s.Symbol == "" || seen[key] {
			return
		}
		seen[key] = true
		out = append(out, s)
	}
	for _, s := range cond.Subjects {
		add(s)
	}
	if cond.Subject != nil {
		add(*cond.Subject)
	}
	return out
}

// postReachExactReach reports whether the exact vulnerable sink has
// positive reach. Module/package usage alone is never reach: the
// evidence must be a CallPath frame matching the subject, an exact
// ModuleReachable chain ending at the subject, or a live sink site in
// the (complete) closure.
func postReachExactReach(c *domain.AnalysisCase, cond domain.Condition,
	subjects []domain.SymbolRef, sc *domain.SinkClosure) (bool, string) {

	if c == nil || len(subjects) == 0 {
		return false, "no exact vulnerable sink subject"
	}
	// Exact matching call path: any frame resolves to the subject.
	for _, cp := range c.EvidenceGraph.CallPaths {
		if cp.ConditionID != "" && cp.ConditionID != cond.ID {
			continue
		}
		for _, fr := range cp.Frames {
			for _, subj := range subjects {
				if frameMatches(fr, subj) {
					return true, ""
				}
			}
		}
	}
	// Exact module-internal chain from a product-used API to the subject.
	for _, subj := range subjects {
		key := subj.Package + "." + subj.Symbol
		chain, ok := c.EvidenceGraph.ModuleReachable[key]
		if !ok || len(chain) == 0 {
			continue
		}
		if chain[len(chain)-1] == key {
			return true, ""
		}
	}
	// A live site in a complete advisory-bound sink closure is positive
	// reach for that exact sink and payload position.
	if sc != nil && sc.Complete && sc.Basis != "" {
		for _, site := range sc.Sites {
			if !site.Live || site.Arg != cond.ArgIndex {
				continue
			}
			for _, subj := range subjects {
				if site.Sink == subj.Package+"."+subj.Symbol {
					return true, ""
				}
			}
		}
	}
	return false, "no sink-specific positive reach (call path, module chain, or live sink site)"
}

// postReachFlowFor returns the recorded flows for one exact live sink
// site and argument.
func postReachFlowFor(flows []domain.DataFlow, site domain.SinkSite, argIndex int) []domain.DataFlow {
	var out []domain.DataFlow
	for _, f := range flows {
		if f.Arg != argIndex {
			continue
		}
		if f.Sink.File != site.File || f.Sink.Line != site.Line ||
			f.Sink.Function != site.Function {
			continue
		}
		out = append(out, f)
	}
	return out
}

// postReachSinkCoverage verifies the exact sink closure contract:
//
//	the closure is complete and advisory-bound;
//	every live site is bound to a declared subject and the exact ArgIndex;
//	every live site's payload input is CONFIGURATION;
//	every live site has a matching persisted DataFlow that is CONFIGURATION;
//	at least one live site exists (positive reach).
//
// A dead site is excluded by call-graph evidence and does not need a flow.
func postReachSinkCoverage(c *domain.AnalysisCase, cond domain.Condition,
	subjects []domain.SymbolRef, sc *domain.SinkClosure, flows []domain.DataFlow) (string, bool) {

	if c == nil {
		return "", false
	}
	if cond.Kind != domain.ConditionAttackerControl || cond.ArgIndex < 0 {
		return "post-reach route requires an attacker-control condition with an exact nonnegative ArgIndex", false
	}
	if len(subjects) == 0 {
		return "condition has no exact sink subject", false
	}
	if sc == nil {
		return "no sink closure recorded for the condition", false
	}
	if sc.Basis == "" {
		return "sink closure has no advisory-bound completeness contract (KNOWN_ONLY)", false
	}
	if !sc.Complete {
		notes := sc.Blockers
		if len(notes) > 5 {
			notes = notes[:5]
		}
		return fmt.Sprintf("sink closure incomplete: %d blocker(s): %s",
			len(sc.Blockers), strings.Join(notes, "; ")), false
	}
	subjectSet := map[string]bool{}
	for _, subj := range subjects {
		subjectSet[subj.Package+"."+subj.Symbol] = true
	}
	live := 0
	for _, site := range sc.Sites {
		if !site.Live {
			continue
		}
		live++
		if !subjectSet[site.Sink] {
			return fmt.Sprintf("live sink site %s:%d names %s, which is not an exact condition subject",
				site.File, site.Line, site.Sink), false
		}
		if site.Arg != cond.ArgIndex {
			return fmt.Sprintf("live sink site %s:%d (%s) is bound to arg %d, not the exact trigger arg %d",
				site.File, site.Line, site.Sink, site.Arg, cond.ArgIndex), false
		}
		if site.Origin != domain.OriginConfiguration {
			return fmt.Sprintf("live sink site %s:%d (%s) arg %d has origin %s, not CONFIGURATION",
				site.File, site.Line, site.Sink, site.Arg, site.Origin), false
		}
		siteFlows := postReachFlowFor(flows, site, cond.ArgIndex)
		if len(siteFlows) == 0 {
			return fmt.Sprintf("live sink site %s:%d (%s) arg %d has no persisted argument DataFlow",
				site.File, site.Line, site.Sink, site.Arg), false
		}
		matched := 0
		for _, f := range siteFlows {
			if f.ConditionID != "" && f.ConditionID != cond.ID {
				continue
			}
			matched++
			if f.Origin != domain.OriginConfiguration {
				return fmt.Sprintf("data flow at sink site %s:%d arg %d has origin %s, not CONFIGURATION",
					site.File, site.Line, f.Arg, f.Origin), false
			}
			if f.PayloadUnproven {
				return fmt.Sprintf("data flow at sink site %s:%d arg %d is writer-only/unproven payload",
					site.File, site.Line, f.Arg), false
			}
		}
		if matched == 0 {
			return fmt.Sprintf("live sink site %s:%d (%s) arg %d has no DataFlow bound to condition %s",
				site.File, site.Line, site.Sink, site.Arg, cond.ID), false
		}
	}
	if live == 0 {
		return "complete sink closure has no live payload site: no positive sink reach", false
	}
	return fmt.Sprintf(
		"exact sink closure verified: %d live payload site(s) at ArgIndex %d all bound to CONFIGURATION; basis: %s",
		live, cond.ArgIndex, sc.Basis), true
}

// postReachAssumption admits the administrator-config trust assertion
// from the declared-assumptions channel. It never falls back to
// --trusted-peer, a config tag, or any other provenance fact.
func postReachAssumption(c *domain.AnalysisCase, now time.Time) (domain.DeclaredAssumption, error) {
	if c == nil {
		return domain.DeclaredAssumption{}, fmt.Errorf("no analysis case")
	}
	return domain.AdmitAssumption(c.DeclaredAssumptions, domain.AssumptionConfigTrust,
		postReachRequiredScope, now)
}

// postReachConfigClaim evaluates the post-reach configuration route for
// an attacker-control condition whose traced flows are all configuration
// origins. ok=false means the route does not apply (the caller keeps the
// claim UNKNOWN and records the reason); ok=true returns the claim.
func postReachConfigClaim(cond domain.Condition, c *domain.AnalysisCase,
	flows []domain.DataFlow, now time.Time) (domain.Claim, bool) {

	claim := domain.Claim{
		ID:          domain.ClaimID("CL-" + string(cond.ID)),
		ConditionID: cond.ID,
		Result:      domain.ClaimUnknown,
		Producer:    postReachProducer,
	}
	if cond.Kind != domain.ConditionAttackerControl || cond.ArgIndex < 0 {
		claim.Limitations = append(claim.Limitations,
			"post-reach configuration route requires an attacker-control condition with an exact nonnegative ArgIndex")
		return claim, true
	}
	if cond.Params[domain.ParamInputSource] == domain.InputPeer {
		// A declared peer-input condition describes a transport
		// boundary; its sink closure is not evidence about one exact
		// product trigger argument.
		claim.Limitations = append(claim.Limitations,
			"peer-input condition: configuration provenance of one argument cannot falsify a transport-shaped attacker condition")
		return claim, true
	}
	subjects := postReachSubjects(cond)
	if len(subjects) == 0 {
		claim.Limitations = append(claim.Limitations, "condition has no exact sink subject")
		return claim, true
	}
	if ok, why := postReachApplicable(c); !ok {
		claim.Limitations = append(claim.Limitations, why)
		return claim, true
	}
	sc := c.EvidenceGraph.SinkClosureFor(cond.ID)
	if ok, why := postReachExactReach(c, cond, subjects, sc); !ok {
		claim.Limitations = append(claim.Limitations, why)
		return claim, true
	}
	if note, ok := postReachSinkCoverage(c, cond, subjects, sc, flows); !ok {
		claim.Limitations = append(claim.Limitations, note)
		return claim, true
	} else {
		claim.Limitations = append(claim.Limitations, note)
	}
	assumption, err := postReachAssumption(c, now)
	if err != nil {
		claim.Limitations = append(claim.Limitations,
			"administrator-configuration trust assumption is not admissible: "+err.Error())
		return claim, true
	}
	claim.Result = domain.ClaimFalse
	claim.Falsifier = domain.FalsifierTrustedInfrastructure
	claim.FalsifierBasis = domain.BasisConfigOrigin
	claim.AssumptionIDs = []string{assumption.ID}
	claim.Explanation = fmt.Sprintf(
		"the exact vulnerable sink is positively reached and trigger arg %d is bound at every live site to administrator-managed configuration (%s); the declared config-trust assumption %s places that configuration outside the attacker model",
		cond.ArgIndex, sc.Basis, assumption.ID)
	// Evidence: the sink-closure inventory plus the persisted flows'
	// source/data-flow records. Assumption ids stay separate.
	for _, e := range c.EvidenceGraph.Evidence {
		if e.Kind != domain.EvidenceDataFlow && e.Kind != domain.EvidenceSourceSnippet {
			continue
		}
		claim.EvidenceIDs = appendUniqueID(claim.EvidenceIDs, e.ID)
	}
	for _, e := range c.EvidenceGraph.Evidence {
		if e.Tool == "goanalysis.Index.SinkClosure" &&
			strings.Contains(e.Content, "cond="+string(cond.ID)) {
			claim.EvidenceIDs = appendUniqueID(claim.EvidenceIDs, e.ID)
		}
	}
	return admitNegative(c, cond, claim), true
}

// postReachStoredClaimValid re-checks a stored post-reach claim against
// the currently recorded closure and flows. closureGate uses it so a
// later recomputation (or a hand-edited case) cannot retain a FALSE the
// exact-site contract no longer supports.
func postReachStoredClaimValid(c *domain.AnalysisCase, claim domain.Claim) (string, bool) {
	cond := findCondition(c.Exploit, claim.ConditionID)
	if cond == nil {
		return "cannot resolve condition for post-reach claim", false
	}
	subjects := postReachSubjects(*cond)
	sc := c.EvidenceGraph.SinkClosureFor(claim.ConditionID)
	flows := flowsFor(c, claim.ConditionID)
	if ok, why := postReachExactReach(c, *cond, subjects, sc); !ok {
		return why, false
	}
	return postReachSinkCoverage(c, *cond, subjects, sc, flows)
}

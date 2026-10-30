package research

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"strings"
	"time"

	"github.com/fedorovmv/izyan/internal/affected"
	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/evaluator"
	"github.com/fedorovmv/izyan/internal/evidencetools"
	"github.com/fedorovmv/izyan/internal/goanalysis"
)

// GuardVerification is a parsed-but-non-authoritative payload shape an
// agent may attach to a guard/bound falsifier proposal. Per the slice
// ruling it is never part of an accepted proof contract: guard coverage
// needs a tool-backed complete sink/flow/guard observation wired into a
// reconstructed evidence graph and re-verified by goanalysis.Verifier —
// no current evidence tool provides that payload (find_validations is
// bounded and PARTIAL by contract). Every path that would read it ends
// in INCONCLUSIVE with reason guard_verification_capability_missing.
type GuardVerification struct {
	AllLiveSinksEnumerated bool     `json:"all_live_sinks_enumerated"`
	MutableFlowsResolved   bool     `json:"mutable_flows_resolved"`
	ViolatingTermsExcluded bool     `json:"violating_terms_excluded"`
	DynamicMarkersChecked  bool     `json:"dynamic_markers_checked"`
	CoverageClosed         bool     `json:"coverage_closed"`
	BoundLow               *int64   `json:"bound_low,omitempty"`
	BoundHigh              *int64   `json:"bound_high,omitempty"`
	Limitations            []string `json:"limitations,omitempty"`
}

// evidenceRefRe is the only evidence-reference shape a proof-bearing
// observation may carry: a sha256 digest ref (marshalData), a
// hash-bearing ev: ref (evidenceRef), or a src: source locator emitted
// by source-reading tools. Anything else is malformed.
var evidenceRefRe = regexp.MustCompile(`^(sha256:[0-9a-f]{64}|ev:[A-Za-z0-9_.-]+:[^@\s]+@[0-9a-f]{16}|src:.+)$`)

func inconclusive(reason string, refs []string, lims ...string) EvidenceDecision {
	if reason == "" {
		reason = "independent verification did not close the asserted scope"
	}
	return EvidenceDecision{
		Verdict: domain.VerdictInconclusive, Reason: reason,
		EvidenceRefs: append([]string(nil), refs...), Scope: "independent verification scope",
		Coverage: "INSUFFICIENT_SCOPE", Limitations: append([]string(nil), lims...),
		HumanQuestions:  []string{"which deterministic check closes the named scope?"},
		TicketRationale: reason + "; follow-up: provide a complete, advisory-bound deterministic check with closed coverage",
	}
}

// advisoryScopeAllowsNegativeClosure reports whether the lane's resolved
// advisory scope may ground a negative verdict. A negative asserts the
// whole requested advisory identity, so a nil scope, a CVE or alias
// request resolved to one advisory record, KNOWN_ONLY load coverage or an
// incomplete entry set never allows one. It is a thin wrapper over the
// domain predicate: COMPLETE coverage alone is not authority, the record
// extent and census must show a fully represented original entry set.
func advisoryScopeAllowsNegativeClosure(l *LaneResult) bool {
	return l != nil && l.Affected.Scope.AllowsNegativeClosure()
}

// scopedApplicabilityGap names the advisory-scope refusal that keeps a
// private negative from becoming an advisory-wide closure. The private
// facts stay evidence; only the closure is refused.
func scopedApplicabilityGap(l *LaneResult) string {
	requested := "the requested advisory"
	if l != nil && l.Affected.Scope != nil && l.Affected.Scope.RequestedID != "" {
		requested = l.Affected.Scope.RequestedID
	}
	return "scoped applicability gap: the resolved advisory scope does not establish complete coverage of " +
		requested + "; the remaining requested scope is unresolved, so no negative closure is permitted"
}

// scopeLimitNote is the publication-side limitation the guards below add to
// every surface they demote: a scope refusal names both what stays recorded
// and why that record cannot close the requested advisory identity.
func scopeLimitNote(l *LaneResult) string {
	return scopedApplicabilityGap(l) +
		"; the recorded components stay established evidence, but a partial record scope never closes the requested advisory identity"
}

// decisionAssertsNegative reports whether d concludes a negative — the two
// verdicts that claim the requested advisory identity does not apply to the
// recorded product. EXPLOITABLE and INCONCLUSIVE assert nothing, so they are
// never re-gated.
func decisionAssertsNegative(d *EvidenceDecision) bool {
	return d.Verdict == domain.VerdictNotAffected || d.Verdict == domain.VerdictNoExploitPathFound
}

// definitiveDecisionVerdict reports whether a record-bound decision published
// one of the three definitive verdicts. INCONCLUSIVE is the only
// non-definitive conclusion, so it is never re-gated against a composition.
func definitiveDecisionVerdict(v domain.Verdict) bool {
	switch v {
	case domain.VerdictExploitable, domain.VerdictNotAffected, domain.VerdictNoExploitPathFound:
		return true
	default:
		return false
	}
}

// decisionPolarity names the side of the positive/negative boundary a verdict
// lands on. Two negatives answer the request at the same boundary even when
// they are different verdicts; a positive and a negative answer it differently.
func decisionPolarity(v domain.Verdict) string {
	switch v {
	case domain.VerdictExploitable:
		return "positive"
	case domain.VerdictNotAffected, domain.VerdictNoExploitPathFound:
		return "negative"
	default:
		return ""
	}
}

// compositionBoundDecision keeps the record-bound decision from contradicting
// the published request answer, and makes the deterministic and decision-ready
// lanes report the same failure/external distinction.
//
// The record decision stays about its own record; this is a publication gate,
// not a rewrite of the record's evidence. A definitive record conclusion beside
// a request that failed or is answered by an external dependency is projected
// to INCONCLUSIVE — the request's own cause and typed gaps ride along — because
// a record-level verdict may not stand in for an answer the request does not
// have. A positive/negative disagreement between the record and the request is
// refused the same way: neither side is silently preferred. The recorded
// evidence refs, executed checks, limitations, hypothesis history and policy
// assumption ids are preserved, and the supplied value is copied, never
// mutated.
func compositionBoundDecision(_ *LaneResult, in *EvidenceDecision,
	composition *domain.RequestedFinding) *EvidenceDecision {
	if in == nil || composition == nil || !definitiveDecisionVerdict(in.Verdict) {
		return in
	}
	var refusal string
	switch composition.Outcome {
	case domain.OutcomeDecided:
		if decisionPolarity(in.Verdict) != decisionPolarity(composition.Verdict) {
			refusal = fmt.Sprintf(
				"the record concludes %s while the request is answered %s; the record result stays bound to its own record",
				in.Verdict, composition.Verdict)
		}
	case domain.OutcomeExternal:
		refusal = "the request is answered by an external dependency, so a record-level definitive verdict is not the request's answer"
	default: // domain.OutcomeFailed
		refusal = "the request analysis failed, so a record-level definitive verdict is not the request's answer"
	}
	if refusal == "" {
		return in
	}
	out := *in
	out.EvidenceRefs = append([]string(nil), in.EvidenceRefs...)
	out.Checks = append([]DecisionCheck(nil), in.Checks...)
	out.Limitations = append([]string(nil), in.Limitations...)
	out.HumanQuestions = append([]string(nil), in.HumanQuestions...)
	out.AssumptionIDs = append([]string(nil), in.AssumptionIDs...)
	out.Verdict = domain.VerdictInconclusive
	out.Coverage = "INSUFFICIENT_SCOPE"
	out.Scope = "request composition"
	out.Falsifier = ""
	out.ConditionID = ""
	out.FalsifierStatement = ""
	out.GroundBasis = ""
	out.NegativeVerification = nil
	out.Sufficiency = ""
	out.Reason = compositionRequestReason(composition)
	if in.Reason != "" {
		out.Reason += "; refused record conclusion: " + in.Reason
	}
	out.Limitations = dedupeStrings(append(out.Limitations, refusal, compositionRequestNote(composition)))
	out.TicketRationale = compositionRequestReason(composition) +
		"; follow-up: the request answer is the composed requested finding, not the single record result"
	return &out
}

// compositionRequestReason names the request-level cause in the vocabulary the
// composition itself published, so the two surfaces cannot disagree about
// whether the answer is a failure or an external dependency.
func compositionRequestReason(composition *domain.RequestedFinding) string {
	verb := "failed"
	switch composition.Outcome {
	case domain.OutcomeDecided:
		verb = "was decided"
	case domain.OutcomeExternal:
		verb = "depends on an external fact"
	}
	reason := strings.TrimSpace(composition.Reason)
	if reason == "" {
		return "the requested analysis " + verb + " without a record-level answer"
	}
	return "the requested analysis " + verb + ": " + reason
}

// compositionRequestNote summarises the typed causes the request published so
// the record-bound projection carries the same classification.
func compositionRequestNote(composition *domain.RequestedFinding) string {
	var parts []string
	for _, dep := range composition.ExternalDependencies {
		if missing := strings.TrimSpace(dep.MissingFact); missing != "" {
			parts = append(parts, "external dependency: "+missing)
		}
	}
	for _, gap := range composition.Gaps {
		parts = append(parts, fmt.Sprintf("request gap: %s/%s", gap.Owner, gap.Code))
	}
	if len(parts) == 0 {
		return "the request published no record-level answer for this profile"
	}
	return "request composition: " + strings.Join(parts, "; ")
}

// scopeBoundDecision re-gates a caller-supplied decision at publication.
// A negative asserts the whole requested advisory identity, and no caller —
// including a cached proof decision carried out of a lane — may publish one
// whose resolved scope does not cover that identity. On refusal the decision
// is deep-copied and only its conclusion is projected: the verdict becomes
// INCONCLUSIVE with INSUFFICIENT_SCOPE coverage, while the recorded evidence
// refs, executed checks, limitations, hypothesis history and policy
// assumption ids are preserved and the refusal is added. An admissible scope
// or a non-negative conclusion returns the supplied value unchanged.
func scopeBoundDecision(lane *LaneResult, in *EvidenceDecision) *EvidenceDecision {
	if in == nil || !decisionAssertsNegative(in) || advisoryScopeAllowsNegativeClosure(lane) {
		return in
	}
	out := *in
	out.EvidenceRefs = append([]string(nil), in.EvidenceRefs...)
	out.Checks = append([]DecisionCheck(nil), in.Checks...)
	out.Limitations = append([]string(nil), in.Limitations...)
	out.HumanQuestions = append([]string(nil), in.HumanQuestions...)
	out.AssumptionIDs = append([]string(nil), in.AssumptionIDs...)
	gap := scopedApplicabilityGap(lane)
	note := scopeLimitNote(lane)
	// The conclusion is projected — the falsifier, its condition, the
	// verified-negative annotation and the ground basis all belonged to the
	// refused negative and never ride an INCONCLUSIVE decision.
	out.Verdict = domain.VerdictInconclusive
	out.Coverage = "INSUFFICIENT_SCOPE"
	out.Falsifier = ""
	out.ConditionID = ""
	out.FalsifierStatement = ""
	out.GroundBasis = ""
	out.NegativeVerification = nil
	out.Sufficiency = ""
	out.Reason = gap
	if in.Reason != "" {
		out.Reason = gap + "; refused recorded conclusion: " + in.Reason
	}
	out.Limitations = dedupeStrings(append(out.Limitations, note))
	out.HumanQuestions = dedupeStrings(append(out.HumanQuestions,
		"which evidence establishes the affected implementations beyond the loaded advisory entries?"))
	out.TicketRationale = gap + "; follow-up: resolve the requested advisory identity against every declared implementation before asserting a negative"
	return &out
}

// artifactProposesClose reports whether any decision surface of a carries a
// code-grounded closure: the artifact-level proposal, a branch, or a
// justification edge.
func artifactProposesClose(a *DecisionArtifact) bool {
	if a == nil {
		return false
	}
	if isCloseDisposition(a.ProposedDisposition) {
		return true
	}
	for i := range a.Branches {
		if isCloseDisposition(a.Branches[i].ProposedDisposition) {
			return true
		}
	}
	for i := range a.JustificationGraph {
		if isCloseDisposition(a.JustificationGraph[i].Disposition) {
			return true
		}
	}
	return false
}

// scopeBoundArtifact re-gates a supplied decision artifact at publication.
// A CLOSE_* proposal is a negative over the requested advisory identity, so
// it stands only under the same scope rule as every other negative route. On
// refusal the artifact is copied before anything changes (the caller's value
// is never mutated): every CLOSE_* branch is demoted to
// HOLD_UNKNOWN/NOT_DECISION_READY, the scope limitation is recorded on the
// explicit unknown branch, active closing dispositions are removed from the
// justification edges, and the artifact-level proposal becomes HOLD_UNKNOWN.
// Shared facts and their verification status are carried over untouched, and
// the guarded copy is contract-validated before it is returned. An admissible
// scope or an artifact that proposes no close is returned unchanged.
func scopeBoundArtifact(lane *LaneResult, in *DecisionArtifact) *DecisionArtifact {
	if in == nil || !artifactProposesClose(in) || advisoryScopeAllowsNegativeClosure(lane) {
		return in
	}
	limitation := scopeLimitNote(lane)
	out := *in
	out.DecisionVariables = append([]DecisionVariable(nil), in.DecisionVariables...)
	out.SharedFacts = append([]Fact(nil), in.SharedFacts...)
	out.Contradictions = append([]Contradiction(nil), in.Contradictions...)
	out.HumanAction = in.HumanAction
	out.HumanAction.EnvironmentQuestionRefs = append([]string(nil), in.HumanAction.EnvironmentQuestionRefs...)
	out.HumanAction.EnvironmentQuestions = append([]string(nil), in.HumanAction.EnvironmentQuestions...)
	out.HumanAction.AllowedResponses = append([]string(nil), in.HumanAction.AllowedResponses...)
	out.HumanAction.MandatoryFactRefs = append([]string(nil), in.HumanAction.MandatoryFactRefs...)
	out.ReplayAndPolicyPins = in.ReplayAndPolicyPins
	out.ReplayAndPolicyPins.CatalogDigests = maps.Clone(in.ReplayAndPolicyPins.CatalogDigests)

	out.Branches = make([]DecisionBranch, len(in.Branches))
	// The explicit unknown branch is the artifact's declared fallback, so it
	// is identified before any close branch is demoted into the same
	// disposition: the refusal belongs on that branch.
	unknown := -1
	for i := range in.Branches {
		if in.Branches[i].ID == "B-UNKNOWN" && in.Branches[i].ProposedDisposition == DispositionHoldUnknown {
			unknown = i
			break
		}
	}
	if unknown < 0 {
		for i := range in.Branches {
			if in.Branches[i].ProposedDisposition == DispositionHoldUnknown {
				unknown = i
				break
			}
		}
	}
	for i := range in.Branches {
		br := in.Branches[i]
		br.Assignments = maps.Clone(br.Assignments)
		br.Conditions = append([]Condition(nil), br.Conditions...)
		br.FactRefs = append([]string(nil), br.FactRefs...)
		br.EnvironmentAssertions = append([]EnvironmentAssertion(nil), br.EnvironmentAssertions...)
		br.Limitations = append([]string(nil), br.Limitations...)
		br.RequiredEnvironmentInputs = append([]string(nil), br.RequiredEnvironmentInputs...)
		if isCloseDisposition(br.ProposedDisposition) {
			br.ProposedDisposition = DispositionHoldUnknown
			br.Status = BranchNotDecisionReady
			br.Limitations = append(br.Limitations, limitation)
		}
		out.Branches[i] = br
	}
	out.JustificationGraph = make([]Justification, len(in.JustificationGraph))
	for i := range in.JustificationGraph {
		j := in.JustificationGraph[i]
		j.PremiseFactRefs = append([]string(nil), j.PremiseFactRefs...)
		j.ConditionRefs = append([]string(nil), j.ConditionRefs...)
		j.ContradictionRefs = append([]string(nil), j.ContradictionRefs...)
		if isCloseDisposition(j.Disposition) {
			j.Disposition = DispositionHoldUnknown
		}
		out.JustificationGraph[i] = j
	}
	out.ProposedDisposition = DispositionHoldUnknown
	// The refusal must be visible even when no branch carried the closed
	// disposition (an artifact-level or edge-only close).
	if unknown < 0 {
		out.Branches = append(out.Branches, DecisionBranch{
			ID: "B-UNKNOWN", Status: BranchNotDecisionReady,
			Coverage:            FactCoverageNotEvaluated,
			ProposedDisposition: DispositionHoldUnknown,
			Limitations:         []string{limitation},
		})
	} else {
		out.Branches[unknown].Limitations = dedupeStrings(append(out.Branches[unknown].Limitations, limitation))
	}
	if err := ValidateDecisionArtifact(&out); err != nil {
		// The supplied artifact did not satisfy the contract in a way the
		// demotion could not repair: publish the explicit unknown shape with
		// the identity, pins and facts preserved.
		return holdOnlyArtifact(&out, limitation)
	}
	return &out
}

// holdOnlyArtifact strips every decision-bearing member of a (already copied)
// artifact and leaves the explicit HOLD_UNKNOWN contract behind. It is the
// fail-closed fallback for a supplied artifact whose guarded copy could not be
// made contract-valid: the identity, target scope, advisory binding, shared
// facts and replay/policy pins stay, and nothing proposes a disposition.
func holdOnlyArtifact(a *DecisionArtifact, limitation string) *DecisionArtifact {
	out := *a
	out.DecisionVariables = []DecisionVariable{}
	out.JustificationGraph = []Justification{}
	out.Contradictions = []Contradiction{}
	out.Branches = []DecisionBranch{{
		ID: "B-UNKNOWN", Status: BranchNotDecisionReady,
		Coverage:            FactCoverageNotEvaluated,
		ProposedDisposition: DispositionHoldUnknown,
		Limitations:         []string{limitation},
	}}
	out.ProposedDisposition = DispositionHoldUnknown
	out.HumanAction.Mode = HumanActionAcceptReject
	out.HumanAction.EnvironmentQuestionRefs = nil
	out.HumanAction.EnvironmentQuestions = nil
	out.HumanAction.AllowedResponses = []string{HumanResponseAccept, HumanResponseReject}
	return &out
}

// scopeClone returns a copy of r whose advisory scope (and therefore its
// record census) cannot be reached through the original pointer. Callers pass
// copied affected results into proof and implementation processing; the copy
// must not alias the lane's scope object.
func scopeClone(r domain.AffectedResult) domain.AffectedResult {
	r.Scope = r.Scope.Clone()
	return r
}

// laneApplicabilityDecision is the deterministic applicability chain's
// own verdict: when any axis resolved FALSE the affected code is
// absent and the case is NOT_AFFECTED — the chain alone decides
// non-applicability, so no proposal, trace, flow termination or
// artifact disposition can suppress it. ok=false when no axis is
// resolved FALSE; this is the only route to NOT_AFFECTED.
//
// The chain is authoritative over what it resolved, never over the
// requested advisory identity. When the resolved scope is partial — a
// CVE request bound to one loaded advisory record, KNOWN_ONLY load
// coverage, no scope at all — the raw FALSE stays recorded evidence but
// the decision is INCONCLUSIVE with insufficient coverage, so the later
// proposal/authority routes cannot re-promote the same private fact.
func laneApplicabilityDecision(l *LaneResult) (EvidenceDecision, bool) {
	// The evaluator receives a copy: the scope census must never be reached
	// through the lane's pointer by proof processing.
	af := scopeClone(l.Affected)
	if af.ModulePresent != domain.ClaimFalse && af.VersionAffected != domain.ClaimFalse &&
		af.PackagePresent != domain.ClaimFalse && af.BuildRelevant != domain.ClaimFalse &&
		af.VulnerableImplementationPresent != domain.ClaimFalse {
		return EvidenceDecision{}, false
	}
	vr := (evaluator.VerdictEvaluator{}).Evaluate(evaluator.VerdictInput{
		Product:  l.Snapshot,
		Affected: af,
		Model:    domain.ExploitModel{},
		Evidence: l.AffectedEvidence,
	})
	d := EvidenceDecision{
		Verdict: vr.Verdict, Reason: vr.Reason,
		EvidenceRefs:    applicabilityEvidenceRefs(vr, l),
		AssumptionIDs:   append([]string(nil), vr.AssumptionIDs...),
		Scope:           "deterministic applicability chain",
		Coverage:        "COMPLETE",
		TicketRationale: vr.Reason,
	}
	if vr.Verdict == domain.VerdictNotAffected {
		return d, true
	}
	// The chain refused the negative. Relabelling the refusal COMPLETE
	// was the scope-gate bypass: the private FALSE would read as a closed
	// advisory-wide negative downstream. Record it as a scoped unresolved
	// decision instead.
	d.Coverage = "INSUFFICIENT_SCOPE"
	if af.HasNegative() && !af.Scope.AllowsNegativeClosure() {
		d.Reason = "scoped applicability gap: " + vr.Reason
		d.HumanQuestions = []string{"which evidence establishes the affected implementations beyond the loaded advisory entries?"}
		d.Limitations = append(d.Limitations,
			"the applicability facts resolve only the components the loaded advisory declares; they never close an advisory-wide negative")
	}
	d.Limitations = append(d.Limitations, vr.Limitations...)
	d.TicketRationale = d.Reason
	return d, true
}

// VerifyDecision projects the deterministic lane, the agent falsifier
// proposal and the bounded verification trace into an evidence decision.
// No agent category, prose, pre-filled NegativeVerification or bare
// evidence-ID existence can produce a terminal verdict: negatives require
// an independently re-derived falsifier over a closed scope bound to every
// advisory-declared subject; unresolved blockers always project to
// INCONCLUSIVE.
func VerifyDecision(ctx context.Context, in DecisionInput) (EvidenceDecision, error) {
	if ctx == nil {
		return EvidenceDecision{}, fmt.Errorf("research: VerifyDecision requires a non-nil context")
	}
	if err := ctx.Err(); err != nil {
		return EvidenceDecision{}, err
	}
	if in.Lane == nil {
		return inconclusive("missing deterministic lane", nil, "lane result is absent"), nil
	}
	// Applicability is decided only by the lane's deterministic chain and
	// is authoritative on its own — see laneApplicabilityDecision.
	if d, ok := laneApplicabilityDecision(in.Lane); ok {
		return d, nil
	}
	// Every route below asserts a negative, and a negative claims the
	// whole requested advisory identity — never only the entries the
	// loaded record happens to declare. A partial scope keeps the private
	// facts as evidence but refuses the proposed, authority and config
	// closures before any of them runs.
	if !advisoryScopeAllowsNegativeClosure(in.Lane) {
		return inconclusive(scopedApplicabilityGap(in.Lane), nil,
			"resolve the requested advisory identity against every declared implementation before asserting a negative"), nil
	}
	// Deterministic symbol authority is independent of any agent proposal.
	if in.Authority != nil && in.Authority.Kind == domain.FalsifierDeclaredSymbolUnreached {
		return verifyDeclaredSymbolUnreached(in), nil
	}
	// The lane's own bounded post-reach configuration proof is the second
	// proposal-free authority route. It is consulted only when no other
	// deterministic authority was requested — a symbol proof stays the
	// stronger statement — and every element of the decision is re-checked
	// here: the proof shape, the recorded check, and the policy
	// assumption's admission. A malformed proof never becomes a verdict.
	if in.Authority == nil && in.Lane.ConfigProof != nil {
		return verifyPostReachConfig(in), nil
	}
	if in.Proposal == nil {
		return inconclusive("no independently verifiable falsifier proposal", nil, "agent category/prose is not authoritative"), nil
	}
	if in.Authority != nil {
		return inconclusive("deterministic authority input is not an accepted falsifier", nil, "authority kind is unsupported"), nil
	}
	p := in.Proposal
	if p.ConditionID == "" || p.Statement == "" || p.Scope == "" || p.Kind == "" {
		return inconclusive("proposal semantics are incomplete", nil, "condition, falsifier, statement and scope are required"), nil
	}
	if p.Module == "" {
		return inconclusive("advisory_scope_gap: proposal does not name an advisory-bound module", nil, "bind the falsifier to an affected advisory entry"), nil
	}
	if !advisoryBinds(in.Lane, p) {
		return inconclusive("advisory_scope_gap: proposed component is not an affected advisory subject", nil, "verify the module/package/symbol against the frozen advisory entry"), nil
	}
	if in.Trace == nil {
		return inconclusive("no independent verification trace", nil, "execute the bounded typed verification plan"), nil
	}
	refs, ok, why := closedTrace(in.Trace, in.Lane, p)
	if !ok {
		return inconclusive(why, refs, "partial, errored, skipped, forged, dynamic or unreferenced observations cannot prove a negative"), nil
	}
	if pos, detail := hasPositiveUse(in.Trace, in.Lane, false); pos {
		return inconclusive("deterministic reachability/use evidence contradicts a negative promotion: "+detail, refs, "positive subject use is independently observed"), nil
	}

	af := in.Lane.Affected
	if af.ModulePresent != domain.ClaimTrue {
		return inconclusive("applicability is unresolved: module presence was not established", refs, "resolve the advisory module against the product dependency graph"), nil
	}
	if af.VersionAffected == domain.ClaimUnknown {
		return inconclusive("release applicability is unresolved: provide --release-go-version or a pinned release binary fact", refs, "release toolchain is missing or unverified"), nil
	}
	if af.VersionAffected != domain.ClaimTrue {
		return inconclusive("applicability is unresolved: version-in-range was not established", refs, "resolve the linked module version against the advisory ranges"), nil
	}

	// Product build-closure absence is the only generic negative route of
	// this slice.
	if p.Kind == domain.FalsifierPackageAbsent || p.Kind == domain.FalsifierLocusPackageAbsent {
		return packageAbsenceDecision(in, p, refs), nil
	}

	// The guard/bound route has no deterministic proof capability in this
	// slice: no evidence tool emits a complete sink/flow/guard/bound
	// observation that reconstructs the verifier's evidence graph, so
	// every guard proposal — structured payload or not — stays
	// INCONCLUSIVE. Agent booleans and pre-filled negative verification
	// are never proof.
	if p.Kind == domain.FalsifierGuards {
		return inconclusive("guard_verification_capability_missing: no tool-backed complete sink/flow/guard/bound observation exists in this slice", refs,
			"follow-up: add a tool-backed complete sink/flow/guard/bound observation and an adapter that reconstructs the corresponding evidence graph and re-runs goanalysis.Verifier"), nil
	}

	// Agent-only negative categories and evidence IDs never promote a verdict.
	return inconclusive("falsifier kind has no accepted independent proof rule", refs, "agent-only and evidence-ID-only claims are non-authoritative"), nil
}

// verifyPostReachConfig is the authority gate for the lane's bounded
// post-reach configuration proof. The lane built the claim from the exact
// sink closure and re-derived the FALSE through the verifier; this gate
// still re-checks every element instead of trusting the lane's summary:
// the decision must carry the named falsifier and basis, a VERIFIED
// negative, closed COMPLETE coverage and at least one evidence ref; every
// assumption id must resolve to the declared document and the admitted
// product-scope config-trust member must be cited; and the recorded check
// must exist, be the post-reach tool, and be OK+COMPLETE. Anything else
// projects INCONCLUSIVE and names the defect — a malformed or
// assumption-free proof never becomes a verdict.
func verifyPostReachConfig(in DecisionInput) EvidenceDecision {
	p := in.Lane.ConfigProof
	d := p.Decision
	refs := append([]string(nil), d.EvidenceRefs...)
	if d.Verdict != domain.VerdictNoExploitPathFound ||
		d.Falsifier != domain.FalsifierTrustedInfrastructure ||
		d.GroundBasis != domain.BasisConfigOrigin ||
		d.Coverage != "COMPLETE" ||
		len(refs) == 0 ||
		d.NegativeVerification == nil ||
		d.NegativeVerification.Status != domain.NegativeVerified {
		return inconclusive("lane post-reach configuration proof is malformed", refs,
			"the decision must be NO_EXPLOIT_PATH_FOUND with FalsifierTrustedInfrastructure, BasisConfigOrigin, COMPLETE coverage, a VERIFIED negative and evidence refs")
	}
	if len(d.AssumptionIDs) == 0 {
		return inconclusive("lane post-reach configuration proof cites no declared assumption", refs,
			"the administrator-configuration trust policy is a required declared-assumptions/1 input, never inferred from provenance or --trusted-peer")
	}
	admitted, err := domain.AdmitAssumption(in.Lane.Assumptions, domain.AssumptionConfigTrust,
		domain.AssumptionScopeProduct, time.Now())
	if err != nil {
		return inconclusive("lane post-reach configuration proof rests on an inadmissible assumption", refs,
			"declared config-trust assumption is not admissible: "+err.Error())
	}
	known := map[string]bool{}
	if in.Lane.Assumptions != nil {
		for _, id := range in.Lane.Assumptions.AssumptionIDs() {
			known[id] = true
		}
	}
	citesAdmitted := false
	for _, id := range d.AssumptionIDs {
		if id == admitted.ID {
			citesAdmitted = true
		}
		if !known[id] {
			return inconclusive("lane post-reach configuration proof cites an undeclared assumption", refs,
				"assumption id "+id+" does not resolve to input.declared_assumptions")
		}
	}
	if !citesAdmitted {
		return inconclusive("lane post-reach configuration proof omits the admitted config-trust assumption", refs,
			"the verdict must cite the admitted config-trust member "+admitted.ID)
	}
	if p.ObservationID == "" {
		return inconclusive("lane post-reach configuration proof has no recorded check", refs,
			"the decision must name the lane observation that recorded the closure and its verification")
	}
	var obs *evidencetools.Observation
	for _, o := range in.Lane.Observations {
		if o != nil && o.ID == p.ObservationID {
			obs = o
			break
		}
	}
	if obs == nil || obs.Tool != postReachConfigTool ||
		obs.ToolStatus != evidencetools.StatusOK ||
		obs.Completeness != evidencetools.CompletenessComplete {
		return inconclusive("lane post-reach configuration proof has no complete recorded check", refs,
			"the cited lane observation must be the post-reach check, OK and COMPLETE")
	}
	out := d
	out.EvidenceRefs = refs
	out.Limitations = append([]string(nil), d.Limitations...)
	out.AssumptionIDs = append([]string(nil), d.AssumptionIDs...)
	if out.Reason == "" {
		out.Reason = "the exact trigger argument of every live advisory sink site resolves to administrator-managed configuration under declared assumption " + admitted.ID
	}
	return out
}

// requireDeclaredDeadnessPremise is the semantic admission every
// declared-symbol-unreached consumer applies — the live lane, the rule-fact
// projection and replay/publication alike: the lane must carry an admitted
// defect-semantics contract, and the proof's subject set must cover the
// contract's negative locus. An OMITTED_CHECK contract binds the omission site
// on the anchored pipeline, so a proof that only covers the absent check is
// refused; the same deadness cannot be a non-locus observation for omission.
func requireDeclaredDeadnessPremise(l *LaneResult) error {
	if l == nil {
		return fmt.Errorf("%w: no deterministic lane", domain.ErrDeadnessPremiseUnavailable)
	}
	_, err := domain.RequireDeadnessPremise(l.DefectSemantics, declaredSymbolRefs(l))
	return err
}

// declaredSymbolRefs projects the lane's advisory-declared symbols into the
// exact package/symbol identities the deadness premise is checked against.
func declaredSymbolRefs(l *LaneResult) []domain.SymbolRef {
	if l == nil {
		return nil
	}
	var out []domain.SymbolRef
	seen := map[domain.SymbolRef]bool{}
	for _, s := range declaredSubjects(l) {
		if s.Package == "" || s.Symbol == "" {
			continue
		}
		ref := domain.SymbolRef{Package: s.Package, Symbol: s.Symbol}
		if seen[ref] {
			continue
		}
		seen[ref] = true
		out = append(out, ref)
	}
	return out
}

// verifyDeclaredSymbolUnreached accepts only the deterministic authority
// channel and a complete, audited symbol-unreachability payload.
func verifyDeclaredSymbolUnreached(in DecisionInput) EvidenceDecision {
	a := in.Authority
	if a == nil || a.Kind != domain.FalsifierDeclaredSymbolUnreached || a.ConditionID == "" || a.RuleID != "rule.declared-symbols-unreached" {
		return inconclusive("declared-symbol-unreached authority is malformed", nil, "authority registry, condition and rule binding are required")
	}
	if err := requireDeclaredDeadnessPremise(in.Lane); err != nil {
		return inconclusive("declared-symbol-unreached negative refused: "+err.Error(), nil,
			"deadness of a declared symbol is an exploit falsifier only under an admitted invocation-necessity premise; an omitted-check contract never treats the absent check's deadness as a negative")
	}
	declared := declaredSubjects(in.Lane)
	want := map[string]bool{}
	for _, s := range declared {
		if s.Symbol != "" {
			want[subjectRefName(s.Module, s.Package, s.Symbol)] = true
		}
	}
	got := map[string]bool{}
	for _, s := range a.Subjects {
		if s.Module == "" || s.Package == "" || s.Symbol == "" {
			return inconclusive("declared-symbol-unreached subject granularity is invalid", nil, "authority subjects must name exact module/package/symbol identities")
		}
		key := subjectRefName(s.Module, s.Package, s.Symbol)
		if !want[key] || got[key] {
			return inconclusive("declared-symbol-unreached authority subject is not an exact advisory symbol", nil, "package-level and module-level subjects cannot satisfy a symbol proof")
		}
		got[key] = true
	}
	for key := range want {
		if !got[key] {
			return inconclusive("declared-symbol-unreached proof does not cover every declared symbol", nil, "missing advisory-declared symbol: "+key)
		}
	}
	if len(want) == 0 || len(got) != len(want) {
		return inconclusive("declared-symbol-unreached proof has incomplete advisory coverage", nil, "every advisory-declared symbol must be covered")
	}
	if in.Trace == nil {
		return inconclusive("no independent symbol-unreachability verification trace", nil, "execute the deterministic symbol-unreachability check")
	}
	modules := map[string]bool{}
	for _, s := range a.Subjects {
		modules[s.Module] = true
	}
	p := &FalsifierProposal{Kind: a.Kind, ConditionID: a.ConditionID, Module: a.Subjects[0].Module}
	refs, ok, why := closedSymbolTrace(in.Trace, in.Lane, p)
	if !ok {
		// The closed-shape gate stays the arbiter of closure, but the
		// reason it reports must name what the bounded proof itself
		// recorded — the primitive's disproven reachability, its open
		// limitation set or the recorded tool failure — never a bare
		// "incomplete trace" phrase.
		reason := why
		lims := []string{"partial, errored, timeout, missing-audit or degraded observations cannot prove unreachability"}
		if named := symbolProofConclusion(in.Trace, in.Audit); named != "" {
			reason = named
			lims = append([]string{named, why}, lims...)
		}
		return inconclusive(reason, refs, lims...)
	}
	// The authority route decodes only payloads the drained session audit
	// recorded. A trace copy alone is caller-constructible, so every
	// authority observation must be bound to an independent audit record:
	// the record must exist, its tool and declared arguments must match
	// the request, and its recorded payload must equal the trace copy.
	// Evidence references must be pinned by that audit record — an
	// arbitrary src: locator is never authority evidence.
	if len(in.Audit) == 0 {
		return inconclusive("symbol-unreachability authority has no drained session audit", refs, "decode only audit-recorded payloads; a trace copy is caller-constructible")
	}
	audit := map[string]evidencetools.AuditRecord{}
	for _, rec := range in.Audit {
		if rec.Observation == nil || rec.Observation.ID == "" {
			return inconclusive("symbol-unreachability audit contains an unbound session record", refs, "session audit record has no observation identity; it cannot become a fact")
		}
		if _, duplicate := audit[rec.Observation.ID]; duplicate {
			return inconclusive("symbol-unreachability audit contains duplicate observation ids", refs, "observation ids must identify exactly one persisted audit record")
		}
		audit[rec.Observation.ID] = rec
	}
	seenIDs := map[string]bool{}
	requestModules := map[string]string{}
	for i, o := range in.Trace.Observations {
		if o == nil || o.ID == "" || seenIDs[o.ID] {
			return inconclusive("symbol-unreachability trace contains duplicate or empty observation ids", refs, "observation ids must be unique and persisted")
		}
		seenIDs[o.ID] = true
		if i >= len(in.Trace.Requests) {
			return inconclusive("symbol-unreachability trace has an observation without a request", refs, "every authority observation must bind to its request")
		}
		req := in.Trace.Requests[i]
		rec, found := audit[o.ID]
		if !found {
			return inconclusive("authority observation has no persisted audit record", refs, "every authority observation requires an independent audit record")
		}
		if rec.Tool != req.Tool || !bindDigests(rec.Args, req.Arguments) {
			return inconclusive("authority observation is not bound to its recorded request", refs, "the request tool and arguments must match the persisted audit record")
		}
		var args evidencetools.SymbolUnreachabilityArgs
		if err := json.Unmarshal(req.Arguments, &args); err != nil || args.Module == "" || len(args.Subjects) == 0 || !modules[args.Module] {
			return inconclusive("symbol-unreachability request does not name a declared authority module", refs, "request module and subjects must exactly match the deterministic authority")
		}
		requested := map[string]bool{}
		for _, sub := range args.Subjects {
			key := subjectRefName(args.Module, sub.Package, sub.Symbol)
			if !got[key] || requested[key] {
				return inconclusive("symbol-unreachability request subject mismatch", refs, "request subjects must exactly match the declared authority for their module")
			}
			requested[key] = true
		}
		for _, sub := range a.Subjects {
			if sub.Module == args.Module && !requested[subjectRefName(sub.Module, sub.Package, sub.Symbol)] {
				return inconclusive("symbol-unreachability request subject coverage is incomplete", refs, "request subjects must exactly match the declared authority for their module")
			}
		}
		requestModules[o.ID] = args.Module
		pins := in.ObservationIndex[o.ID]
		for _, ref := range o.EvidenceRefs {
			if !pinnedRef(ref, pins) {
				return inconclusive("symbol-unreachability evidence reference is not audit-bound", refs, "persist the verification observation and its audit record before promotion")
			}
		}
		// Bind the complete canonical observation, not merely Data: status,
		// completeness, scope and refs are all authority gates.
		if !bindDigests(rec.Observation, o) {
			return inconclusive("authority payload does not match the persisted audit record", refs, "the complete trace observation must equal the audit record")
		}
		if rec.Observation.ToolStatus != evidencetools.StatusOK || rec.Observation.Completeness != evidencetools.CompletenessComplete || rec.Observation.Scope == "" || rec.Observation.ScopeDetails == nil {
			return inconclusive("symbol-unreachability audit observation is not complete", refs, "status, completeness and scope gates come from the audit snapshot")
		}
	}
	// Each trace observation above consumed one distinct audit record. As in
	// flowTraceFromRecords, a surplus session row cannot become a fact and
	// leaves the verification scope incomplete, even if the paired proof
	// observation itself is complete.
	if len(in.Audit) != len(seenIDs) {
		return inconclusive("symbol-unreachability audit contains an unbound session record", refs, "session audit record names no declared verification request; it cannot become a fact")
	}
	seen := map[string]bool{}
	for _, o := range in.Trace.Observations {
		if o.Tool != evidencetools.SymbolUnreachabilityTool {
			return inconclusive("symbol-unreachability authority trace contains an unrelated tool", refs, "the authority route accepts only symbol-unreachability observations")
		}
		var d evidencetools.SymbolUnreachabilityData
		aud := audit[o.ID].Observation
		if aud.PayloadRef != nil {
			// An envelope is never the proof: the authority consumes
			// only the complete hash-bound payload. A record that still
			// carries its reference reached this route unrehydrated —
			// the pinned sidecar could not be bound.
			return inconclusive("symbol-unreachability payload is not bound to its pinned sidecar", refs, "rehydrate the externalized authoritative payload before evaluation")
		}
		if !decodeData(aud.Data, &d) {
			return inconclusive("symbol-unreachability payload is undecodable", refs, "retain the typed deterministic payload")
		}
		r := d.Result
		if r.Module != requestModules[o.ID] {
			return inconclusive("symbol-unreachability payload module differs from its declared request", refs, "each request must prove exactly its own advisory-declared module")
		}
		if r.Module == "" || !modules[r.Module] || r.ValidateComplete(domain.EffectiveBuildContext(in.Lane.Snapshot)) != nil {
			reason := "symbol-unreachability proof is incomplete"
			if err := r.ValidateComplete(domain.EffectiveBuildContext(in.Lane.Snapshot)); err != nil { reason += ": " + err.Error() }
			if !modules[r.Module] {
				reason = fmt.Sprintf("symbol-unreachability payload records module %q, which is not an advisory-declared module of this proof", r.Module)
			} else if s := symbolResultConclusion(r, ""); s != "" && !r.Complete {
				reason = s
			}
			return inconclusive(reason, refs, "all declaration, entrypoint, dynamic, interface, gated, dependency-internal and opaque/unbounded gates must be closed")
		}
		for _, s := range r.Subjects {
			key := subjectRefName(r.Module, s.Package, s.Symbol)
			if !got[key] {
				return inconclusive("symbol-unreachability payload subject mismatch", refs, "payload subjects must exactly match the deterministic authority subjects")
			}
			seen[key] = true
		}
	}
	for key := range got {
		if !seen[key] {
			return inconclusive("symbol-unreachability payload coverage is incomplete", refs, "every requested symbol must be present in the payload")
		}
	}
	if pos, detail := hasPositiveUse(in.Trace, in.Lane, true); pos {
		return inconclusive("deterministic reachability/use evidence contradicts symbol unreachability: "+detail, refs, "positive subject use is independently observed")
	}
	af := in.Lane.Affected
	if af.ModulePresent != domain.ClaimTrue {
		return inconclusive("applicability is unresolved: module presence was not established", refs, "resolve the advisory module against the product dependency graph")
	}
	if af.VersionAffected == domain.ClaimUnknown {
		if len(af.UnresolvedModules) == 0 {
			return inconclusive("release applicability is unresolved", refs, "every unresolved module must be explicitly covered by symbol proof")
		}
		for _, m := range af.UnresolvedModules {
			found := false
			for _, s := range declared {
				if s.Module == m {
					found = true
					if s.Symbol == "" || !got[subjectRefName(s.Module, s.Package, s.Symbol)] {
						return inconclusive("unknown-release exception does not cover unresolved module", refs, "module-only unresolved entries remain blocking")
					}
				}
			}
			if !found {
				return inconclusive("unknown-release exception omits an unresolved advisory subject", refs, "no unresolved advisory subject may be omitted")
			}
		}
	} else if af.VersionAffected != domain.ClaimTrue {
		return inconclusive("applicability is unresolved: version-in-range was not established", refs, "resolve the linked module version against the advisory ranges")
	}
	// The authority route is a build-dependent negative: re-admit it against
	// the lane's identified target and its recorded measurement context
	// before returning a terminal decision. The trace gate above already
	// proved the audited observations are complete, non-opaque and bound to
	// the lane's snapshot/build axes; this gate refuses a host-default
	// analysis context and a verification that does not describe it.
	build := domain.EffectiveBuildContext(in.Lane.Snapshot)
	cond := domain.Condition{
		ID:   domain.ConditionID(a.ConditionID),
		Kind: domain.ConditionSymbolReachable,
	}
	for _, s := range a.Subjects {
		cond.Subjects = append(cond.Subjects, domain.SymbolRef{Package: s.Package, Symbol: s.Symbol})
	}
	admissionClaim := domain.Claim{
		ConditionID: cond.ID,
		Result:      domain.ClaimFalse,
		Falsifier:   string(domain.FalsifierDeclaredSymbolUnreached),
		NegativeVerification: &domain.NegativeVerification{
			Status:       domain.NegativeVerified,
			BuildContext: &build,
		},
	}
	if err := goanalysis.ValidateVerifiedNegative(goanalysis.NegativeAdmissionInput{Product:in.Lane.Snapshot,Evidence:in.Lane.AffectedEvidence}, admissionClaim, cond); err != nil {
		return inconclusive("declared-symbol-unreached negative refused: "+err.Error(), refs,
			"the proof must describe an identified product build; a host-default analysis context cannot ground it")
	}
	evidence := make([]domain.EvidenceID, 0, len(refs))
	for _, r := range refs {
		evidence = append(evidence, domain.EvidenceID(r))
	}
	nv := &domain.NegativeVerification{Status: domain.NegativeVerified, EvidenceIDs: evidence,
		Notes:        "independently re-derived from a complete advisory-bound symbol-unreachability proof",
		BuildContext: &build}
	return EvidenceDecision{Verdict: domain.VerdictNoExploitPathFound, Reason: "declared advisory symbols are proven unreachable from the recorded product scope", ConditionID: a.ConditionID, Falsifier: a.Kind, NegativeVerification: nv, EvidenceRefs: refs, Scope: "bounded advisory-declared symbol unreachability", Coverage: "COMPLETE", TicketRationale: "A complete deterministic symbol-unreachability proof covers every advisory-declared symbol; no agent assertion was used.", Sufficiency: "all declared symbols covered; no blocker remains"}
}

// closedSymbolTrace is the trace gate for the declared-symbol
// authority route. It enforces every closedTrace invariant — request
// binding, completeness, snapshot/build-context identity, evidence-ref
// shape — except the generic dynamic/partial limitation scan for
// symbol-unreachability observations: that tool's COMPLETE contract
// stamps fixed declarative interpretation bounds into the observation
// limitations, and this route's typed payload gate (Result.Limitations
// empty, every gap set empty, Complete) plus the COMPLETE-completeness
// requirement are the strictly stronger, authoritative channel for a
// degraded derivation. Every other tool's limitations stay scanned.
func closedSymbolTrace(t *VerificationTrace, lane *LaneResult, p *FalsifierProposal) ([]string, bool, string) {
	return closedTraceFor(t, lane, p, true)
}

// symbolProofConclusion re-derives the primitive's own conclusion for a
// trace that failed the closed-shape gate, so an INCONCLUSIVE decision
// names what the bounded proof actually recorded — positive reachability
// (disproven), the open limitation set, or the recorded tool failure —
// instead of a generic incomplete-trace phrase. Payloads are read from
// the persisted audit copy when present (the same bytes the authority
// binds) and otherwise from the trace's own copy; the request's declared
// module argument names the check when no payload decoded. Empty when no
// symbol-scoped conclusion exists and the gate's own reason stands.
func symbolProofConclusion(t *VerificationTrace, audit []evidencetools.AuditRecord) string {
	if t == nil {
		return ""
	}
	recs := map[string][]evidencetools.AuditRecord{}
	for _, rec := range audit {
		if rec.Observation == nil || rec.Observation.ID == "" {
			continue
		}
		recs[rec.Observation.ID] = append(recs[rec.Observation.ID], rec)
	}
	var out []string
	emit := func(o *evidencetools.Observation, req *VerificationRequest) {
		if o == nil && req != nil && req.Tool != evidencetools.SymbolUnreachabilityTool {
			return
		}
		module := ""
		var obs *evidencetools.Observation
		if o != nil {
			rs := recs[o.ID]
			for i := range rs {
				if module = symbolArgsModule(rs[i].Args); module != "" {
					break
				}
			}
			if len(rs) > 0 {
				obs = rs[0].Observation
			}
		}
		if obs == nil {
			obs = o
		}
		if module == "" && req != nil {
			module = symbolArgsModule(req.Arguments)
		}
		if s := symbolObsConclusion(obs, o, module); s != "" {
			out = append(out, s)
		}
	}
	for i := range t.Requests {
		var o *evidencetools.Observation
		if i < len(t.Observations) {
			o = t.Observations[i]
		}
		emit(o, &t.Requests[i])
	}
	for i := len(t.Requests); i < len(t.Observations); i++ {
		// An observation no request claims still names its own conclusion.
		emit(t.Observations[i], nil)
	}
	return strings.Join(out, "; ")
}

// symbolObsConclusion renders the recorded conclusion of one
// symbol-unreachability call. obs is the audit-bound copy when present,
// otherwise the trace copy; fallback is the trace copy's own recorded
// fact for an undecodable payload. Empty for a closed proof and for
// unrelated tools — a request that produced no observation at all is
// itself the named failure.
func symbolObsConclusion(obs, fallback *evidencetools.Observation, module string) string {
	if obs == nil {
		return fmt.Sprintf("the symbol-unreachability check%s produced no observation", modulePhrase(module))
	}
	if obs.Tool != evidencetools.SymbolUnreachabilityTool {
		return ""
	}
	if obs.ToolStatus != evidencetools.StatusOK {
		reason := obs.Error
		if reason == "" {
			reason = obs.Fact
		}
		if reason == "" {
			reason = "no recorded detail"
		}
		return fmt.Sprintf("the symbol-unreachability check%s returned %s: %s",
			modulePhrase(module), obs.ToolStatus, reason)
	}
	var d evidencetools.SymbolUnreachabilityData
	if decodeData(obs.Data, &d) {
		if d.Result.Complete {
			return ""
		}
		return symbolResultConclusion(d.Result, module)
	}
	fact := obs.Fact
	if fact == "" && fallback != nil {
		fact = fallback.Fact
	}
	if fact == "" {
		fact = "the observation carried no decodable result payload"
	}
	return fmt.Sprintf("the symbol-unreachability check%s returned an undecodable result: %s",
		modulePhrase(module), fact)
}

// symbolResultConclusion renders the bounded proof's own conclusion from
// its typed payload in the grammar the primitive's fact line uses:
// positive reachability disproves unreachability; anything else stays
// UNKNOWN with every recorded limitation named. module is the caller's
// best module name; the payload's own module stands in when the caller
// has none.
func symbolResultConclusion(r goanalysis.UnreachabilityResult, module string) string {
	if module == "" {
		module = r.Module
	}
	head := "symbol-unreachability" + modulePhrase(module)
	if len(r.ProductReferences) > 0 || len(r.ModuleReachable) > 0 {
		return fmt.Sprintf("%s is disproven: %d product reference(s) and %d module-internal chain(s) reach the declared subject(s)",
			head, len(r.ProductReferences), len(r.ModuleReachable))
	}
	conclusion := fmt.Sprintf("%s is UNKNOWN: %d open limitation(s) (declaration_complete=%v references=%d may_call=%d dep_sites=%d dispatch=%d markers=%d gated=%d opaque=%v unbounded=%v)",
		head, len(r.Limitations), r.DeclarationComplete, len(r.ProductReferences), len(r.MayCallSites),
		len(r.DependencyCallSites), len(r.InterfaceDispatchSites), len(r.DynamicMarkers),
		len(r.GatedReferences), r.Opaque, r.Unbounded)
	if len(r.Limitations) > 0 {
		conclusion += "; open limitations: " + strings.Join(r.Limitations, "; ")
	}
	return conclusion
}

// modulePhrase renders the " for module <m>" qualifier the symbol
// conclusions carry — empty when the check's module was not recorded.
func modulePhrase(module string) string {
	if module == "" {
		return ""
	}
	return " for module " + module
}

// symbolArgsModule lifts the declared module from a symbol-unreachability
// request or audit argument blob; "" for anything else.
func symbolArgsModule(args json.RawMessage) string {
	var a evidencetools.SymbolUnreachabilityArgs
	if len(args) == 0 || json.Unmarshal(args, &a) != nil {
		return ""
	}
	return a.Module
}

// declaredSubject is one authoritative subject of the frozen advisory:
// entry id, module, declared package and (when named) declared symbol.
// Package is empty only for a module-only affected entry — a module-level
// subject for the build-closure route.
type declaredSubject struct {
	EntryID string
	Module  string
	Package string
	Symbol  string
}

func (s declaredSubject) label() string {
	label := s.Module
	if s.Package != "" {
		label += " | " + s.Package
	}
	if s.Symbol != "" {
		label += "." + s.Symbol
	}
	return s.EntryID + ":" + label
}

// subjectRefName renders the canonical subject identity the R6 fact
// envelope and rule adapters share: module:<m> for a module-level
// subject, package:<m>|<p> for a package, symbol:<m>|<p>.<s> for a
// symbol. The module qualifier is part of package/symbol identity —
// the same package path under a different module is a different
// subject — and the granularity prefix is part of the name, so a
// package fact can never satisfy a module-level subject or a
// module-level fact a package subject. advisory:<id> names the
// advisory document itself and snapshot:<hash> the snapshot; both sit
// outside the module/package grammar.
func subjectRefName(module, pkg, symbol string) string {
	switch {
	case symbol != "":
		return "symbol:" + module + "|" + pkg + "." + symbol
	case pkg != "":
		return "package:" + module + "|" + pkg
	default:
		return "module:" + module
	}
}

// declaredSubjects enumerates every subject declared by the frozen
// advisory's affected entries — the same AffectedModuleEntries /
// AffectedPackagesForEntry projection the deterministic lane probes —
// never the agent's selected subject. Symbols join the package identity
// declared for them; a package-free symbol and a module-only entry both
// keep their module-level scope. Non-Go and incomplete entries stay in
// the set: the falsifier must either cover them or see them explicitly
// resolved by applicability evidence.
func declaredSubjects(l *LaneResult) []declaredSubject {
	if l.Advisory.Vuln == nil {
		return nil
	}
	entries := affected.AffectedModuleEntries(*l.Advisory.Vuln)
	var out []declaredSubject
	// The parser merges original affected[] entries by module name, so a
	// production advisory has one merged entry per module. A synthetic or
	// legacy record may still carry several entries for the same module
	// (e.g. one package entry plus one module-only entry); the ordinal
	// within that module keeps each entry's own original id instead of
	// collapsing them onto the first one.
	rankByModule := map[string]int{}
	for _, entry := range entries {
		rank := rankByModule[entry.Module]
		rankByModule[entry.Module] = rank + 1
		entryID := advisoryEntryID(l, entry.Module, rank)
		declared := false
		for _, pkg := range affected.AffectedPackagesForEntry(entry) {
			declared = true
			if len(pkg.Symbols) == 0 {
				out = append(out, declaredSubject{EntryID: entryID, Module: entry.Module, Package: pkg.Path})
				continue
			}
			for _, sym := range pkg.Symbols {
				out = append(out, declaredSubject{EntryID: entryID, Module: entry.Module, Package: pkg.Path, Symbol: sym})
			}
		}
		if !declared && entry.Module != "" {
			out = append(out, declaredSubject{EntryID: entryID, Module: entry.Module})
		}
	}
	return out
}

// recordInventoryOf returns the lane's validated record census, or nil when
// the scope carries none. An inventory that does not validate is not census
// evidence: it is treated as absent rather than repaired.
func recordInventoryOf(l *LaneResult) *domain.RecordInventory {
	if l == nil || l.Affected.Scope == nil {
		return nil
	}
	inventory := l.Affected.Scope.RecordInventory
	if inventory == nil || inventory.Validate(l.Affected.Scope.ResolvedID) != nil {
		return nil
	}
	return inventory
}

// advisoryEntryID resolves the advisory entry id a merged affected module
// belongs to. Merged AffectedModules are not positionally aligned with the
// original OSV affected[] entries — several original entries merge into one
// module record — so indexing Impls by the merged position can attribute a
// foreign entry's id (a non-Go entry included). The census is the authority:
// its original index selects the Impl row and the module and ecosystem
// identity must agree before the id is used. rank selects the entry among the
// original entries that name the same module (always 0 for a parser-merged
// record, which carries one entry per module; higher only for synthetic or
// legacy records with several entries for one module). A lane without a census
// falls back to the same identity check over the Impls, which are built in
// original affected[] order. A module with no corresponding entry stays
// unresolved (empty id): a missing correspondence is a diagnostic gap, never
// evidence of completeness.
func advisoryEntryID(l *LaneResult, module string, rank int) string {
	if module == "" || rank < 0 {
		return ""
	}
	eligible := func(index int) string {
		if index >= len(l.Advisory.Impls) {
			return ""
		}
		impl := l.Advisory.Impls[index]
		if impl.Module != module || impl.Binding == BindNonGo || impl.ID == "" {
			return ""
		}
		return impl.ID
	}
	matched := 0
	if inventory := recordInventoryOf(l); inventory != nil {
		for _, entry := range inventory.Entries {
			if entry.Module != module || entry.Index < 0 {
				continue
			}
			if entry.Ecosystem != "Go" && entry.Ecosystem != "" {
				continue
			}
			id := eligible(entry.Index)
			if id == "" {
				continue
			}
			if matched == rank {
				return id
			}
			matched++
		}
		return ""
	}
	for index := range l.Advisory.Impls {
		id := eligible(index)
		if id == "" {
			continue
		}
		if matched == rank {
			return id
		}
		matched++
	}
	return ""
}

// absenceScan collects the closed product build-closure absence proofs
// the trace established for packages of the advisory module, plus the
// optional module-level aggregate. Only usage-scope observations carry
// them, and only under an accepted marker pair:
//   - usage_scope=test-only  + product_absence_verification=VERIFIED, or
//   - usage_scope=unknown    + product_absence_verification=
//     VERIFIED_VENDOR_INVENTORY with the full vendor-inventory
//     condition set corroborated by the recorded payload and scope
//     details (closure_source, closure_semantics, vendor_mode, no
//     positive linkage, no marker-invalidating limitation).
type absenceScan struct {
	absent    map[string]*evidencetools.Observation
	absentMod map[string]string
	moduleObs map[string]*evidencetools.Observation
}

func (s absenceScan) covered(sub declaredSubject) bool {
	if s.moduleObs[sub.Module] != nil {
		return true
	}
	if sub.Package == "" {
		return false
	}
	return s.absent[sub.Package] != nil && s.absentMod[sub.Package] == sub.Module
}

// absencePayload mirrors the usage-scope data fields the gate reads:
// subject identity, classification, linkage flags, the product-absence
// marker, the derivation provenance and the recorded limitations.
type absencePayload struct {
	Module                     string   `json:"module"`
	Package                    string   `json:"package"`
	UsageScope                 string   `json:"usage_scope"`
	ProductAbsenceVerification string   `json:"product_absence_verification"`
	ProductLinked              bool     `json:"product_linked"`
	TestLinked                 bool     `json:"test_linked"`
	ClosureSource              string   `json:"closure_source"`
	ClosureSemantics           string   `json:"closure_semantics"`
	Limitations                []string `json:"limitations"`
	Present                    bool     `json:"present"`
	Usage                      string   `json:"usage"`
	Symbol                     string   `json:"symbol"`
}

// markerLimitationTokens are the limitation families that invalidate any
// verified absence marker: an errored, partial, unresolved, skipped, dynamic,
// incomplete, undecidable or opaque derivation cannot prove absence. Fixed
// declarative interpretation bounds do not match these tokens.
var markerLimitationTokens = []string{
	"error", "partial", "unknown", "dynamic", "unresolved",
	"skipped", "incomplete", "undecidable", "opaque",
	"cannot be verified",
}

// markerInvalidLimitation reports whether an observation or typed payload
// names a marker-invalidating derivation problem.
func markerInvalidLimitation(lims []string, dataLims []string) bool {
	for _, l := range append(append([]string(nil), lims...), dataLims...) {
		l = strings.ToLower(l)
		for _, tok := range markerLimitationTokens {
			if strings.Contains(l, tok) {
				return true
			}
		}
	}
	return false
}

// vendorInventoryProven checks the payload-side conditions a
// VERIFIED_VENDOR_INVENTORY marker must corroborate: the offline
// vendor/modules.txt+source-imports derivation under recorded
// product_all_packages semantics, a recorded vendor_mode=true build
// context, no positive linkage in either closure and no
// marker-invalidating limitation. Identity exactness and ref
// resolution stay the caller's gates.
func vendorInventoryProven(o *evidencetools.Observation, d absencePayload) bool {
	if d.ProductLinked || d.TestLinked {
		return false
	}
	if d.ClosureSource != affected.VendorClosureSource ||
		d.ClosureSemantics != affected.ClosureSemanticsProductAllPackages {
		return false
	}
	bc := o.ScopeDetails.BuildContext
	if bc == nil || !bc.VendorMode {
		return false
	}
	return !markerInvalidLimitation(o.Limitations, d.Limitations)
}

func scanAbsence(t *VerificationTrace) absenceScan {
	s := absenceScan{
		absent:    map[string]*evidencetools.Observation{},
		absentMod: map[string]string{},
		moduleObs: map[string]*evidencetools.Observation{},
	}
	for _, o := range t.Observations {
		if o == nil || o.Tool != evidencetools.UsageScopeTool ||
			o.ScopeDetails == nil || o.ScopeDetails.CoverageRule == "" {
			continue
		}
		var d absencePayload
		if !decodeData(o.Data, &d) || d.Module == "" {
			continue
		}
		if markerInvalidLimitation(o.Limitations, d.Limitations) {
			continue
		}
		switch {
		case d.UsageScope == string(UsageScopeTestOnly) &&
			d.ProductAbsenceVerification == ProductAbsenceVerificationVerified:
		case d.UsageScope == string(UsageScopeUnknown) &&
			d.ProductAbsenceVerification == ProductAbsenceVerificationVendorInventory &&
			vendorInventoryProven(o, d):
		default:
			continue
		}
		if d.Package == "" {
			s.moduleObs[d.Module] = o
		} else {
			s.absent[d.Package] = o
			s.absentMod[d.Package] = d.Module
		}
	}
	return s
}

// packageUsageBound decodes the first package-usage observation bound to
// the given module+package pair, so a product-source verdict on a linked
// package is surfaced as a named blocker instead of silently ignored —
// or worse, read as absence. Binding is package-identity exact: the
// observation's own symbol argument never widens or narrows which
// declared subject it speaks for, since the linkage fact it carries
// (present) is a property of the package.
func packageUsageBound(t *VerificationTrace, module, pkg string) (absencePayload, bool) {
	for _, o := range t.Observations {
		if o == nil || o.Tool != evidencetools.PackageUsageTool {
			continue
		}
		var d absencePayload
		if !decodeData(o.Data, &d) {
			continue
		}
		if d.Module == module && d.Package == pkg {
			return d, true
		}
	}
	return absencePayload{}, false
}

// packagePresenceConflict names the first declared subject whose recorded
// package-presence evidence contradicts the build-closure absence claim
// being promoted: a bound package-usage observation carrying present=true
// (whatever its source-usage verdict — a NOT_USED or UNKNOWN verdict still
// records the package inside the linked closure) or a promoted
// PACKAGE_USAGE fact whose negative basis is not the absence basis. The
// absent-from-closure basis agrees with the falsifier and never conflicts.
// Non-advisory subjects bind to nothing and cannot conflict. Returns ""
// when no declared subject carries contradicting presence evidence.
func packagePresenceConflict(t *VerificationTrace, l *LaneResult, subs []declaredSubject) string {
	for _, o := range t.Observations {
		if o == nil || o.Tool != evidencetools.PackageUsageTool {
			continue
		}
		var d absencePayload
		if !decodeData(o.Data, &d) || !d.Present {
			continue
		}
		if bindsDeclaredSubject(subs, d.Module, d.Package, "", false) {
			return fmt.Sprintf("bound package-usage observation %s records %s as present in the product import closure (present=true, source-usage verdict %s)", o.ID, subjectRefName(d.Module, d.Package, ""), nonEmptyOr(d.Usage, "unrecorded"))
		}
	}
	for _, f := range l.Facts {
		switch f.Kind {
		case FactKindPackageUsage, FactKindPackageUsageLowerBound:
		default:
			continue
		}
		if f.UsageBasis == UsageBasisAbsentFromClosure {
			// An absent-from-closure negative agrees with the falsifier.
			continue
		}
		if f.UsageSubject == nil {
			continue
		}
		// Every remaining package-usage fact records the package inside
		// the linked product closure — TRUE (used or lower-bound site)
		// and FALSE on the present-unused basis alike.
		if bindsDeclaredSubject(subs, f.UsageSubject.Module, f.UsageSubject.Package, "", false) {
			return fmt.Sprintf("verified package-usage fact %s records %s inside the linked product closure (claim=%s usage_basis=%q)", f.ID, subjectRefName(f.UsageSubject.Module, f.UsageSubject.Package, ""), f.Claim, f.UsageBasis)
		}
	}
	return ""
}

// nonEmptyOr renders s, or fallback when empty.
func nonEmptyOr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// laneAbsenceResolved reports whether the deterministic lane already
// resolved a declared subject as outside the asserted negative scope.
// The live mechanisms in this slice are lane BUILD_USAGE_SCOPE facts
// carrying an accepted product-absence marker with EXACT subject
// identity — test-only+VERIFIED, or unknown+VERIFIED_VENDOR_INVENTORY
// under the vendor-inventory conditions — a package-level fact resolves
// only that package, a module-level fact only a module-level subject.
func laneAbsenceResolved(l *LaneResult, sub declaredSubject) bool {
	for _, f := range l.Facts {
		if f.Kind != FactKindBuildUsageScope || f.UsageSubject == nil || f.UsageSubject.Module != sub.Module {
			continue
		}
		if f.UsageSubject.Package != sub.Package {
			continue
		}
		if f.UsageScope == string(UsageScopeTestOnly) && f.ProductAbsenceVerification == ProductAbsenceVerificationVerified {
			return true
		}
		if f.UsageScope == string(UsageScopeUnknown) && f.ProductAbsenceVerification == ProductAbsenceVerificationVendorInventory {
			return true
		}
	}
	return false
}

// packageAbsenceDecision promotes a product build-closure absence only
// when every advisory-declared subject is either proven absent by the
// verification trace or explicitly resolved by the deterministic lane —
// a single checked subject can never ground an advisory-wide negative.
func packageAbsenceDecision(in DecisionInput, p *FalsifierProposal, refs []string) EvidenceDecision {
	// Proposal identity at declared granularity: the build-closure route
	// is package/module-identity exact — a symbol is never part of it
	// and a package-free proposal is permitted only when the matching
	// advisory entry is module-only (the module path is never promoted
	// into a package identity).
	if p.Symbol != "" {
		return inconclusive("advisory_scope_gap: the build-closure falsifier is package/module-identity exact — a symbol cannot be part of the proposal", refs, "propose the package or module subject exactly as the advisory declares it")
	}
	granularityExact := false
	for _, sub := range declaredSubjects(in.Lane) {
		if sub.Module == p.Module && sub.Package == p.Package {
			granularityExact = true
			break
		}
	}
	if !granularityExact {
		return inconclusive("advisory_scope_gap: proposal granularity does not match an affected advisory entry — a module-level entry is never satisfied by an agent-chosen package, and a package is never manufactured from a module-only entry", refs, "propose the exact module or package identity the advisory declares")
	}
	scan := scanAbsence(in.Trace)
	proposed := declaredSubject{Module: p.Module, Package: p.Package, Symbol: p.Symbol}
	// A bound package-usage result that reports the package linked is an
	// explicit contradiction of the absence falsifier, whatever its
	// source-usage verdict — and NOT_USED can never ground absence.
	if d, bound := packageUsageBound(in.Trace, p.Module, p.Package); bound && d.Present {
		return inconclusive("a bound package-usage observation records the proposed package as present in the product import closure (present=true); product-source non-use is not build-closure absence", refs, "re-establish absence with a complete paired build-closure check for the proposed subject")
	}
	// Contradictory package/build facts never resolve in the absence
	// claim's favour: any declared subject recorded present by a bound
	// package-usage observation or a promoted package-usage fact is a
	// named limitation, whether or not a closure proof covers it.
	if conflict := packagePresenceConflict(in.Trace, in.Lane, declaredSubjects(in.Lane)); conflict != "" {
		return inconclusive("contradictory package/build facts: "+conflict, refs,
			"the package-absence falsifier cannot be promoted while a declared subject carries contradicting presence evidence — reconcile the two records for that subject")
	}
	if !scan.covered(proposed) {
		return inconclusive("no closed product build-closure absence proof is bound to the proposed subject", refs, "run the closure check for the exact advisory-bound package")
	}
	var uncovered []string
	for _, sub := range declaredSubjects(in.Lane) {
		if scan.covered(sub) || laneAbsenceResolved(in.Lane, sub) {
			continue
		}
		why := "not evaluated by a closed closure check and not resolved by applicability evidence"
		for _, m := range in.Lane.Affected.UnresolvedModules {
			if m == sub.Module {
				why = "module version unresolved: the entry could not be evaluated"
				break
			}
		}
		uncovered = append(uncovered, sub.label()+" ("+why+")")
	}
	if len(uncovered) > 0 {
		return inconclusive("advisory-declared subject(s) lack a verified product-closure absence or a recorded resolution: "+strings.Join(uncovered, ", "), refs,
			"follow-up: extend the closure check to every advisory-declared subject or resolve them by deterministic applicability evidence")
	}
	obs := scan.absent[p.Package]
	if obs == nil {
		obs = scan.moduleObs[p.Module]
	}
	if obs == nil {
		// Defensive: covered() already guarantees a bound proof exists;
		// never emit a negative without it.
		return inconclusive("absence proof record missing for the proposed subject", refs, "re-run the bound closure check")
	}
	// Proof-grade reference check: every digest ref carried by a consumed
	// absence proof must resolve to a recorded artifact/fact digest — the
	// trace observation's own persistence pins (ObservationIndex) or the
	// lane's maps — so a fabricated digest cannot stand in for evidence.
	proofs := map[*evidencetools.Observation]bool{obs: true}
	for _, sub := range declaredSubjects(in.Lane) {
		if s := scan.absent[sub.Package]; s != nil {
			proofs[s] = true
		}
	}
	for _, m := range scan.moduleObs {
		proofs[m] = true
	}
	for po := range proofs {
		for _, r := range po.EvidenceRefs {
			if !refResolves(r, po, in) {
				return inconclusive("proof observation "+po.ID+" carries an evidence reference that resolves to no recorded artifact or fact digest: "+r, refs, "persist the verification artifacts before promoting a negative")
			}
		}
	}
	evidence := []domain.EvidenceID{domain.EvidenceID(firstRef(obs))}
	build := domain.EffectiveBuildContext(in.Lane.Snapshot)
	nv := &domain.NegativeVerification{Status: domain.NegativeVerified, EvidenceIDs: evidence,
		Notes:        "independently re-derived from a complete advisory-bound product build closure",
		BuildContext: &build}
	claim := domain.Claim{
		ID: domain.ClaimID(p.ConditionID), ConditionID: domain.ConditionID(p.ConditionID),
		Result: domain.ClaimFalse, Falsifier: string(domain.FalsifierPackageAbsent),
		EvidenceIDs:          evidence,
		Explanation:          "the advisory-bound package is absent from the complete product build closure; the defect code is not linked into the product",
		NegativeVerification: nv,
	}
	// A module-level proposal names the module itself; a package-level one
	// names its package. Both are record-declared subjects of the advisory the
	// decision answers, so the shared admission can establish their identity.
	subjectPackage := p.Package
	if subjectPackage == "" {
		subjectPackage = p.Module
	}
	subject := domain.SymbolRef{Package: subjectPackage, Symbol: p.Symbol}
	model := domain.ExploitModel{MandatoryConditions: []domain.Condition{{
		ID: domain.ConditionID(p.ConditionID), Kind: domain.ConditionSymbolReachable, Mandatory: true,
		Subject:  &subject,
		Subjects: []domain.SymbolRef{subject},
	}}}
	vr := (evaluator.VerdictEvaluator{}).Evaluate(evaluator.VerdictInput{
		Product:       in.Lane.Snapshot,
		Affected:      scopeClone(in.Lane.Affected),
		Model:         model,
		Claims:        []domain.Claim{claim},
		Evidence:      in.Lane.AffectedEvidence,
		Vulnerability: laneVulnerability(in.Lane),
	})
	return EvidenceDecision{
		Verdict: vr.Verdict, Reason: vr.Reason, ConditionID: p.ConditionID,
		Falsifier: domain.FalsifierPackageAbsent, NegativeVerification: nv,
		EvidenceRefs: refs, Scope: obs.Scope, Coverage: "COMPLETE",
		TicketRationale: "The advisory-bound package was independently proven absent from the complete product build closure for every advisory-declared subject; no agent assertion was used to promote this result.",
	}
}

// laneVulnerability is the exact advisory record the decision answers. It is
// the identity authority for the declared subject the decision's absence proof
// names; a lane without a decoded record establishes no declaration.
func laneVulnerability(l *LaneResult) domain.Vulnerability {
	if l == nil || l.Advisory.Vuln == nil {
		return domain.Vulnerability{}
	}
	return *l.Advisory.Vuln
}

// hasPositiveUse reports deterministic positive-use or product-linkage
// evidence bound to an advisory-declared subject — any declared subject,
// not just the proposed one — in the trace or the lane's verified facts.
// Such a positive always blocks a negative promotion regardless of what
// the agent asserted. Positive evidence for a subject the advisory never
// declared contradicts nothing this decision asserts and never blocks.
// symbolClaim selects the contradiction granularity of the pending
// negative: under a package/module absence claim a positive binds by
// package identity (the absorbed package of a symbol subject included);
// under a symbol-unreachability claim only an exact-symbol positive is
// contradictory — product linkage or package usage of the subject's own
// package is evidence about the package, not about the declared symbol.
func hasPositiveUse(t *VerificationTrace, l *LaneResult, symbolClaim bool) (bool, string) {
	subs := declaredSubjects(l)
	for _, o := range t.Observations {
		if o == nil {
			continue
		}
		var d absencePayload
		if !decodeData(o.Data, &d) || d.Module == "" {
			continue
		}
		var detail string
		switch o.Tool {
		case evidencetools.PackageUsageTool:
			if d.Usage == string(goanalysis.PackageUsageUsed) {
				detail = fmt.Sprintf("package-usage observation %s records %s as USED by product source", o.ID, subjectRefName(d.Module, d.Package, d.Symbol))
			}
		case evidencetools.UsageScopeTool:
			if d.ProductLinked {
				detail = fmt.Sprintf("usage-scope observation %s records %s as product-linked (usage_scope=%s)", o.ID, subjectRefName(d.Module, d.Package, ""), nonEmptyOr(d.UsageScope, "unrecorded"))
			}
		}
		if detail != "" && bindsDeclaredSubject(subs, d.Module, d.Package, d.Symbol, symbolClaim) {
			return true, detail
		}
	}
	for _, f := range l.Facts {
		var detail string
		switch f.Kind {
		case FactKindPackageUsage, FactKindPackageUsageLowerBound:
			// A TRUE package-usage fact records a concrete product site —
			// including lower-bound facts minted when the open-scope check
			// still observed a site.
			if f.Claim == "TRUE" {
				detail = fmt.Sprintf("verified fact %s records positive product-source usage", f.ID)
			}
		case FactKindBuildUsageScope:
			if f.UsageScope == string(UsageScopeProduct) || f.UsageScope == string(UsageScopeMixed) {
				detail = fmt.Sprintf("verified build-usage fact %s records product-closure linkage (usage_scope=%s)", f.ID, f.UsageScope)
			}
		}
		if detail == "" || f.UsageSubject == nil {
			// A positive fact with no recorded subject binds to nothing —
			// the verified-fact contract always pins the checked subject,
			// so an unbound positive can never stand in for one.
			continue
		}
		if bindsDeclaredSubject(subs, f.UsageSubject.Module, f.UsageSubject.Package, f.UsageSubject.Symbol, symbolClaim) {
			return true, detail + " for declared subject " + subjectRefName(f.UsageSubject.Module, f.UsageSubject.Package, f.UsageSubject.Symbol)
		}
	}
	return false, ""
}

// bindsDeclaredSubject reports whether a positive-use observation —
// recorded at its own granularity — names a subject the pending negative
// actually contradicts. Under symbolClaim (a symbol-unreachability
// proof) only an exact module+package+symbol positive contradicts:
// package linkage or usage of the subject's own package is evidence
// about the package, never about the declared symbol. Otherwise the
// binding is package-granular: an exact module+package match, or — for a
// module-only declaration — a package inside the declared module, the
// same identity relation the proposal-binding gate applies to declared
// subjects.

func bindsDeclaredSubject(subs []declaredSubject, module, pkg, sym string, symbolClaim bool) bool {
	for _, sub := range subs {
		if sub.Module != module {
			continue
		}
		if symbolClaim {
			// A symbol-level claim is contradicted only by a positive
			// recorded for that exact symbol.
			if sub.Symbol != "" && sym != "" && sub.Package == pkg && sub.Symbol == sym {
				return true
			}
			continue
		}
		if sub.Package == pkg {
			return true
		}
		if sub.Package == "" && domain.PackageInModule(pkg, module) {
			return true
		}
	}
	return false
}

// bindDigests reports whether two payloads are the same canonical JSON.
// A payload that cannot be canonicalized binds to nothing: an
// un-marshalable value must fail closed rather than compare equal to
// another failure.
func bindDigests(a, b any) bool {
	da, db := canonicalJSONDigest(a), canonicalJSONDigest(b)
	return da != "" && db != "" && da == db
}

// canonicalJSONDigest is the canonical digest of a JSON payload. Both
// sides are decoded with UseNumber and re-marshalled, so the digest is
// independent of key order and of whether the value is a typed struct or
// a decoded map — a trace copy and its audit copy of the same payload
// bind, while any content difference fails closed.
func canonicalJSONDigest(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var norm any
	if err := dec.Decode(&norm); err != nil {
		return ""
	}
	b2, err := json.Marshal(norm)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b2)
	return hex.EncodeToString(sum[:])
}

// pinnedRef reports whether a reference is one of the audit-derived pins
// for an observation. The authority route never accepts a bare src:
// locator: without a matching audit pin there is nothing to bind it to.
func pinnedRef(ref string, pins []string) bool {
	for _, p := range pins {
		if p == ref {
			return true
		}
	}
	return false
}

// refResolves reports whether an evidence reference on a proof-bearing
// observation resolves to something actually recorded: a src: source
// locator is a tool-defined pointer form accepted by shape; a digest ref
// must appear in the observation's own persistence pins
// (DecisionInput.ObservationIndex) or the lane's artifact/fact digests.
// Everything else is an unresolvable citation and fails closed.
func refResolves(ref string, o *evidencetools.Observation, in DecisionInput) bool {
	// A source locator is valid only when the audit-derived persistence
	// index pins it; shape alone is caller-fabricated and proves nothing.
	for _, r := range in.ObservationIndex[o.ID] {
		if r == ref {
			return true
		}
	}
	if l := in.Lane; l != nil {
		for _, h := range l.CanonicalByObs {
			if "sha256:"+h == ref {
				return true
			}
		}
		for _, a := range l.ArtifactByObs {
			if "sha256:"+a.SHA256 == ref {
				return true
			}
		}
		for _, f := range l.Facts {
			if "sha256:"+f.DataDigest == ref || "sha256:"+f.Artifact.SHA256 == ref || "sha256:"+f.InputDigest == ref {
				return true
			}
		}
	}
	return false
}

func advisoryBinds(l *LaneResult, p *FalsifierProposal) bool {
	for _, sub := range declaredSubjects(l) {
		if sub.Module != p.Module {
			continue
		}
		if sub.Package != p.Package {
			// A module-level subject (Package=="") binds a package-level
			// proposal only when the package lives inside that module.
			if sub.Package != "" || !domain.PackageInModule(p.Package, sub.Module) {
				continue
			}
			if p.Symbol == "" {
				return true
			}
			continue
		}
		if p.Symbol == "" || sub.Symbol == "" || sub.Symbol == p.Symbol {
			return true
		}
	}
	return false
}

// closedTrace rejects any trace that is not a complete, request-bound,
// build-context-bound set of OK+COMPLETE observations. Request/observation
// tool and condition identity must match; snapshot hash and build context
// must be populated and agree with the lane; evidence references must have
// the hash-bearing shape the session emits; any trace-level limitation or
// unexecuted request is a blocker for a terminal negative.
func closedTrace(t *VerificationTrace, lane *LaneResult, p *FalsifierProposal) ([]string, bool, string) {
	return closedTraceFor(t, lane, p, false)
}

// closedTraceFor is closedTrace with one route-specific interpretation:
// when symbolAuthority is set, the dynamic/partial limitation token scan
// is not applied to symbol-unreachability observations. That tool's
// COMPLETE contract stamps fixed declarative interpretation bounds into
// the observation limitations, and the authority route's typed payload
// gate — Result.Limitations empty, every gap set empty, Complete — plus
// the COMPLETE-completeness requirement are the strictly stronger,
// authoritative channel for a degraded derivation, so the substring scan
// would only false-reject the route's own proof shape. Observations of
// every other tool keep the scan unchanged.
func closedTraceFor(t *VerificationTrace, lane *LaneResult, p *FalsifierProposal, symbolAuthority bool) ([]string, bool, string) {
	var refs []string
	if !t.Complete || len(t.Observations) != len(t.Requests) {
		return refs, false, "verification trace is incomplete or has skipped requests"
	}
	if len(t.Limitations) != 0 {
		return refs, false, "verification trace recorded limitation(s): " + strings.Join(t.Limitations, "; ")
	}
	for i, o := range t.Observations {
		req := t.Requests[i]
		if req.ID == "" || req.Tool == "" || req.ConditionID == "" || req.ConditionID != p.ConditionID {
			return refs, false, "verification request is not bound to the proposed condition"
		}
		if o == nil || o.Tool != req.Tool {
			return refs, false, "observation does not match its request"
		}
		if o.ID == "" || o.ToolStatus != evidencetools.StatusOK || o.Completeness != evidencetools.CompletenessComplete ||
			len(o.EvidenceRefs) == 0 || o.Scope == "" || o.ScopeDetails == nil ||
			len(o.ScopeDetails.SkippedPackages) != 0 {
			return refs, false, "observation is not a complete, referenced, closed-scope result"
		}
		if o.ScopeDetails.SnapshotHash == "" {
			return refs, false, "observation carries no snapshot identity"
		}
		bc := o.ScopeDetails.BuildContext
		if bc == nil || bc.GOOS == "" || bc.GOARCH == "" {
			return refs, false, "observation carries no build context"
		}
		if lane == nil || lane.ContentHash == "" || lane.Snapshot.GOOS == "" || lane.Snapshot.GOARCH == "" {
			return refs, false, "lane identity is incomplete: a terminal negative requires the recorded snapshot hash and build context"
		}
		if lane.ContentHash != o.ScopeDetails.SnapshotHash {
			return refs, false, "build-context mismatch: observation targets a different snapshot"
		}
		if lane.Snapshot.GOOS != bc.GOOS || lane.Snapshot.GOARCH != bc.GOARCH ||
			lane.Snapshot.VendorMode != bc.VendorMode {
			return refs, false, "build-context mismatch: observation does not match the deterministic lane"
		}
		for _, r := range o.EvidenceRefs {
			if !evidenceRefRe.MatchString(r) {
				return refs, false, "malformed evidence reference"
			}
			refs = append(refs, r)
		}
		lims := o.Limitations
		if symbolAuthority && o.Tool == evidencetools.SymbolUnreachabilityTool {
			lims = nil
		}
		if o.Tool == evidencetools.UsageScopeTool {
			var d absencePayload
			if !decodeData(o.Data, &d) {
				return refs, false, "usage-scope payload is undecodable"
			}
			lims = append(append([]string(nil), lims...), d.Limitations...)
			if markerInvalidLimitation(nil, d.Limitations) {
				return refs, false, "usage-scope payload records marker-invalidating limitation(s): " + strings.Join(d.Limitations, "; ")
			}
		}
		for _, x := range append(append([]string{}, lims...), o.ScopeDetails.Extra["dynamic_marker"]) {
			if strings.Contains(strings.ToLower(x), "dynamic") || strings.Contains(strings.ToLower(x), "partial") {
				return refs, false, "unresolved dynamic or partial-scope blocker"
			}
		}
	}
	return refs, true, ""
}

// applicabilityEvidenceRefs grounds the verdict's resolver evidence ids
// in the lane records that carry them. Resolver EV-* ids live in
// LaneResult.AffectedEvidence and are recorded by the lane's
// affected-resolve observation — the persisted record of the
// applicability chain — so each cited id resolves to obs:<id> of that
// record. An id already in the obs: space stays verbatim; an id no lane
// record carries stays raw — an unresolvable citation must fail
// validation loudly, never be silently dropped. Order is preserved and
// duplicates collapse.
func applicabilityEvidenceRefs(vr domain.VerdictResult, l *LaneResult) []string {
	evIDs := map[string]bool{}
	for _, ev := range l.AffectedEvidence {
		evIDs[string(ev.ID)] = true
	}
	axisEV := map[string]bool{}
	axisCarrier := ""
	if ax := l.ImplementationAxis; ax != nil {
		axisCarrier = ax.ObservationID
		for _, id := range ax.EvidenceIDs {
			axisEV[id] = true
		}
	}
	var carrier []string
	for _, o := range l.Observations {
		if o != nil && o.Tool == "affected-resolve" && o.ID != "" {
			carrier = append(carrier, o.ID)
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, id := range vr.EvidenceIDs {
		ref := string(id)
		if !strings.HasPrefix(ref, "obs:") {
			switch {
			case axisEV[ref] && axisCarrier != "":
				// Verifier evidence ids ground in the lane's own
				// implementation-axis observation — the dedicated
				// record of that check — never in the resolver's.
				ref = "obs:" + axisCarrier
			case evIDs[ref] && len(carrier) > 0:
				ref = "obs:" + carrier[0]
			}
		}
		if !seen[ref] {
			seen[ref] = true
			out = append(out, ref)
		}
	}
	return out
}

func decodeData(v any, dst any) bool {
	if v == nil {
		return false
	}
	b, err := json.Marshal(v)
	if err != nil {
		return false
	}
	return json.Unmarshal(b, dst) == nil
}

func firstRef(o *evidencetools.Observation) string {
	if o == nil || len(o.EvidenceRefs) == 0 {
		return ""
	}
	return o.EvidenceRefs[0]
}

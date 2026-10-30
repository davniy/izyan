// Package finding turns record-level evidence into the terminal classification
// of one assessment. It is deliberately separate from the verdict evaluator:
// the evaluator decides what the evidence proves, while this package decides
// whether that outcome is a decided answer, a named external dependency, or an
// analysis failure. Claim truth values are never rewritten here — a failed
// measurement keeps its claim UNKNOWN.
package finding

import (
	"fmt"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/evaluator"
)

// AssessmentInput is the complete input of one assessment classification.
// VerdictInput carries the same evidence the verdict evaluator sees; Gaps
// carries record-level typed causes the workflow recorded outside the claims
// (budget, timeout, measurement or scope failures). AssessmentID names the
// assessment the diagnostics belong to; when empty the requested record id is
// used so a focused caller cannot publish unbound gaps.
type AssessmentInput struct {
	evaluator.VerdictInput
	RootCause *domain.RootCauseModel
	// Vulnerability is the exact record this assessment answers. It travels
	// into the verdict input so the absence-identity admission can tell a
	// record-declared subject from a candidate the record never named.
	Vulnerability domain.Vulnerability
	Gaps          []domain.AnalysisGap
	AssessmentID  domain.CaseID
}

// Assess classifies one assessment:
//
//   - a sufficient admitted proof decides first, even when unrelated
//     supporting obligations remain unresolved;
//   - otherwise any code/proof/input/scope blocker fails the assessment;
//   - only fully evidence-bound external facts produce EXTERNAL_DEPENDENCY;
//   - mixed blockers remain FAILED, and an unclassified unresolved obligation
//     becomes FAILED / UNCLASSIFIED_ANALYSIS_GAP.
//
// The result is schema-valid by construction: FAILED carries no verdict and
// no external dependencies, EXTERNAL_DEPENDENCY carries INCONCLUSIVE plus its
// dependencies, DECIDED carries a definitive verdict.
func Assess(in AssessmentInput) domain.AssessmentResult {
	// The verdict boundary re-admits candidate identity, so the record and the
	// root-cause model this assessment answers are part of its input. Both are
	// declared on AssessmentInput; the embedded verdict input is fed from them
	// so a caller cannot pass a model to one and not the other.
	in.VerdictInput.RootCause = in.RootCause
	in.VerdictInput.Vulnerability = in.Vulnerability
	evaluation := (evaluator.VerdictEvaluator{}).EvaluateDetailed(in.VerdictInput)
	assessmentID := assessmentID(in)
	claims := claimGapsByRelevance(in, evaluation.Verdict)

	gaps := make([]domain.AnalysisGap, 0, len(in.Gaps)+len(evaluation.Gaps))
	for _, g := range in.Gaps {
		gaps = append(gaps, stampGap(g, assessmentID))
	}
	if in.Affected.AnalysisGaps != nil {
		for _, g := range in.Affected.AnalysisGaps {
			gaps = append(gaps, stampGap(g, assessmentID))
		}
	}
	if in.RootCause != nil && in.RootCause.Status != domain.RootCauseResolved {
		for _, g := range in.RootCause.AnalysisGaps {
			gaps = append(gaps, stampGap(g, assessmentID))
		}
	}
	gaps = append(gaps, claims.relevant...)
	for i := range gaps {
		gaps[i] = stampGap(gaps[i], assessmentID)
	}
	for _, g := range evaluation.Gaps {
		gaps = append(gaps, stampGap(g, assessmentID))
	}

	limitations := append([]string(nil), evaluation.Verdict.Limitations...)
	limitations = append(limitations, claims.limitations...)

	result := domain.AssessmentResult{Outcome: domain.OutcomeFailed, Limitations: limitations}

	if definitive(evaluation.Verdict.Verdict) {
		result.Outcome = domain.OutcomeDecided
		verdict := evaluation.Verdict
		result.Verdict = &verdict
		// Diagnostics are preserved, but an external gap cannot ride on a
		// decided result: the proof already settled the question, so the
		// unresolved external fact is a limitation of what was proven.
		for _, g := range dedupeGaps(gaps) {
			if g.Owner == domain.GapOwnerExternal {
				result.Limitations = append(result.Limitations, "external fact not needed for the verdict: "+g.Message)
				continue
			}
			result.Gaps = append(result.Gaps, g)
		}
		return result
	}

	var analyzer, external []domain.AnalysisGap
	for _, g := range dedupeGaps(gaps) {
		if g.Owner == domain.GapOwnerExternal {
			external = append(external, g)
			continue
		}
		analyzer = append(analyzer, g)
	}

	// Mixed blockers fail: unfinished analysis may never hide behind an
	// external question.
	if len(analyzer) > 0 {
		result.Gaps = append(result.Gaps, analyzer...)
		result.Gaps = append(result.Gaps, external...)
		return result
	}
	if len(external) > 0 {
		result.Outcome = domain.OutcomeExternal
		verdict := evaluation.Verdict
		if verdict.Verdict != domain.VerdictInconclusive {
			verdict.Verdict = domain.VerdictInconclusive
		}
		result.Verdict = &verdict
		result.Gaps = external
		result.ExternalDependencies = dependencies(external)
		return result
	}

	// INCONCLUSIVE with no typed cause is exactly the conflation this policy
	// removes: say the analysis failed, and say why it could not classify.
	result.Gaps = append(result.Gaps, domain.AnalysisGap{
		Owner:        domain.GapOwnerCode,
		Code:         domain.GapUnclassifiedAnalysisGap,
		Obligation:   unclassifiedObligation(in),
		AssessmentID: assessmentID,
		Message:      "the assessment ended INCONCLUSIVE without a typed cause: " + evaluation.Verdict.Reason,
	})
	return result
}

// claimGaps is the relevance-filtered claim diagnostics.
type claimGaps struct {
	relevant    []domain.AnalysisGap
	limitations []string
}

// claimGapsByRelevance collects claim and negative-verification gaps only from
// claims that can still change the answer: an unresolved mandatory condition
// or a condition the verdict names. Gaps attached to supporting facts stay as
// limitations — a supporting unknown cannot veto a sufficient proof or turn a
// pending external question into a failure.
func claimGapsByRelevance(in AssessmentInput, verdict domain.VerdictResult) claimGaps {
	relevantConditions := make(map[domain.ConditionID]bool)
	for _, id := range verdict.ConditionIDs {
		relevantConditions[id] = true
	}
	byCondition := make(map[domain.ConditionID]domain.Claim, len(in.Claims))
	for _, cl := range in.Claims {
		byCondition[cl.ConditionID] = cl
	}
	for _, cond := range in.Model.MandatoryConditions {
		cl, ok := byCondition[cond.ID]
		if !ok || cl.Result != domain.ClaimTrue {
			relevantConditions[cond.ID] = true
		}
	}

	var out claimGaps
	for _, cl := range in.Claims {
		gaps := append([]domain.AnalysisGap(nil), cl.AnalysisGaps...)
		if cl.NegativeVerification != nil {
			gaps = append(gaps, cl.NegativeVerification.AnalysisGaps...)
		}
		if len(gaps) == 0 {
			continue
		}
		if relevantConditions[cl.ConditionID] {
			out.relevant = append(out.relevant, gaps...)
			continue
		}
		for _, g := range gaps {
			out.limitations = append(out.limitations,
				fmt.Sprintf("supporting gap on %s does not block the verdict: %s", cl.ConditionID, g.Message))
		}
	}
	return out
}

// stampGap binds a producer gap to this assessment and enforces the
// owner/dependency coupling structurally: an EXTERNAL gap without a valid
// evidence-bound dependency is analyzer work, not an environmental answer.
func stampGap(g domain.AnalysisGap, id domain.CaseID) domain.AnalysisGap {
	if g.AssessmentID == "" {
		g.AssessmentID = id
	}
	for i := range g.EvidenceRefs {
		if g.EvidenceRefs[i].AssessmentID == "" {
			g.EvidenceRefs[i].AssessmentID = g.AssessmentID
		}
	}
	if g.External != nil {
		for i := range g.External.BoundaryEvidenceRefs {
			if g.External.BoundaryEvidenceRefs[i].AssessmentID == "" {
				g.External.BoundaryEvidenceRefs[i].AssessmentID = g.AssessmentID
			}
		}
	}
	if g.Owner == domain.GapOwnerExternal {
		if g.External == nil || g.External.Validate() != nil {
			g.Owner = domain.GapOwnerCode
			g.Code = domain.GapUnclassifiedAnalysisGap
			g.External = nil
		}
		return g
	}
	g.External = nil
	return g
}

func dedupeGaps(gaps []domain.AnalysisGap) []domain.AnalysisGap {
	seen := make(map[string]bool, len(gaps))
	out := make([]domain.AnalysisGap, 0, len(gaps))
	for _, g := range gaps {
		key := string(g.Owner) + "\x00" + string(g.Code) + "\x00" + string(g.Obligation) +
			"\x00" + string(g.ConditionID) + "\x00" + g.Message
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, g)
	}
	return out
}

func dependencies(gaps []domain.AnalysisGap) []domain.ExternalDependency {
	seen := make(map[string]bool, len(gaps))
	out := make([]domain.ExternalDependency, 0, len(gaps))
	for _, g := range gaps {
		if g.External == nil {
			continue
		}
		key := string(g.External.AffectedObligation) + "\x00" + g.External.MissingFact
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, *g.External)
	}
	return out
}

func assessmentID(in AssessmentInput) domain.CaseID {
	if in.AssessmentID != "" {
		return in.AssessmentID
	}
	if in.Affected.Scope != nil && in.Affected.Scope.RequestedID != "" {
		return domain.CaseID(in.Affected.Scope.RequestedID)
	}
	return domain.CaseID("assessment")
}

func unclassifiedObligation(in AssessmentInput) domain.Obligation {
	switch {
	case in.RootCause == nil || in.RootCause.Status != domain.RootCauseResolved:
		return domain.ObligationRootCause
	case len(in.Model.MandatoryConditions) > 0:
		return domain.ObligationCondition
	default:
		return domain.ObligationMeasurement
	}
}

func definitive(v domain.Verdict) bool {
	switch v {
	case domain.VerdictExploitable, domain.VerdictNotAffected, domain.VerdictNoExploitPathFound:
		return true
	default:
		return false
	}
}

package triage

import (
	"encoding/json"
	"fmt"
	"strings"
)

// MaxFactFeedbackPasses is the hard bound on structured repair turns the
// fact gate may hand back to the agent (spec §7.3): the first validation
// plus at most two repair passes, then the final gate stands. Configured
// values are clamped to it — a larger max_feedback_passes never buys a
// third turn, and a non-positive one means the spec default.
const MaxFactFeedbackPasses = 2

// EffectBlocksRiskReduction marks a non-VALID fact check that a
// decision-relevant claim relies on: after the feedback budget is spent the
// reference stays recorded and can never support DISMISSED or LOWERED.
// It names a demotion rule, not a recommendation.
const EffectBlocksRiskReduction = "blocks_risk_reduction"

// Fact-check scopes: the domain a check ran in and the only place a repair
// may touch. Feedback carries them as allowed_scope so the agent repairs
// the binding, never the semantics.
const (
	factScopeSource      = "source"
	factScopeFile        = "file"
	factScopeObservation = "observation"
	factScopeAdvisory    = "advisory"
	factScopeComponent   = "component"
	factScopeRevision    = "revision"
	factScopeArtifact    = "artifact"
	// factScopeClaim covers check entries about claim bindings
	// (UNREFERENCED claims, empty evidence ids); factScopeEvidence covers
	// malformed or unclassifiable evidence declarations themselves.
	factScopeClaim    = "claim"
	factScopeEvidence = "evidence"
)

// factScopeForKind maps a resolved canonical evidence kind to the scope the
// check ran in; an empty or unknown kind stays at the evidence declaration
// itself.
func factScopeForKind(canon string) string {
	switch canon {
	case kindSourceSpan:
		return factScopeSource
	case kindFile:
		return factScopeFile
	case kindAdvisory:
		return factScopeAdvisory
	case kindComponent:
		return factScopeComponent
	case kindRevision:
		return factScopeRevision
	case kindArtifact:
		return factScopeArtifact
	case kindObservation:
		return factScopeObservation
	default:
		return factScopeEvidence
	}
}

// factExpectedRepair is the deterministic repair hint for one non-VALID
// check status. It describes which binding to fix — locator, citation,
// kind — never what the claim should conclude.
func factExpectedRepair(status FactStatus) string {
	switch status {
	case FactUnreferenced:
		return "cite a declared evidence id for this claim, or replace it with a premise the captured material can establish while keeping the action's decisive claims decision-relevant"
	case FactInvalid:
		return "repair the reference so it names a fact declared in the snapshot manifest, the finding or the recorded observations"
	case FactConflicting:
		return "reconcile the reference with the pinned snapshot fact; cited and authoritative facts must agree"
	case FactUnavailable:
		return "reference a fact present in the snapshot or recorded observations; missing sources cannot be cited"
	default:
		return "repair the reference so the fact gate can re-derive it"
	}
}

// factEffectStatement is the mechanical consequence carried in feedback
// when unresolved items exist. It states the demotion rule without naming
// a recommendation.
const factEffectStatement = "references still unresolved after the feedback budget cannot support a risk reduction; they are recorded as limitations"

// needsFactRepair reports whether the validation carries at least one
// non-VALID check worth a repair pass: feedback is sent for broken,
// conflicting, missing or unreferenced facts, never for a clean report.
func needsFactRepair(v FactValidation) bool {
	for _, rc := range v.References {
		if rc.Status != FactValid {
			return true
		}
	}
	return false
}

// BuildFeedback derives the structured repair feedback for one pass purely
// from the deterministic gate result: one item per non-VALID check, keyed
// by the evidence id (or the claim id for UNREFERENCED entries), carrying
// the check's status, reason, expected repair and allowed scope. It never
// echoes verdicts, claim statements or semantic advice — repair concerns
// reproducibility only.
func (g FactGate) BuildFeedback(validation FactValidation, pass int) FactFeedback {
	fb := FactFeedback{Pass: pass}
	for _, rc := range validation.References {
		if rc.Status == FactValid {
			continue
		}
		item := FactFeedbackItem{
			ReferenceID:    rc.EvidenceID,
			CurrentStatus:  rc.Status,
			Reason:         rc.Reason,
			ExpectedRepair: rc.ExpectedRepair,
			AllowedScope:   rc.Scope,
		}
		if item.ReferenceID == "" {
			item.ReferenceID = rc.Subject
		}
		if item.ExpectedRepair == "" {
			item.ExpectedRepair = factExpectedRepair(rc.Status)
		}
		fb.Items = append(fb.Items, item)
	}
	if len(fb.Items) > 0 {
		fb.RecommendationEffect = factEffectStatement
	}
	return fb
}

// factFeedbackMessage renders one feedback pass as the single user message
// sent back to the agent. The report is embedded as JSON; the instruction
// text bounds the repair to fact bindings and never names a verdict.
func factFeedbackMessage(fb FactFeedback) string {
	report, err := json.Marshal(fb)
	if err != nil {
		// FactFeedback is marshal-safe; the fallback still carries the
		// per-item statuses and never the raw assessment.
		var b strings.Builder
		fmt.Fprintf(&b, "fact gate pass %d items:", fb.Pass)
		for _, it := range fb.Items {
			fmt.Fprintf(&b, " %s=%s", it.ReferenceID, it.CurrentStatus)
		}
		report = []byte(b.String())
	}
	return fmt.Sprintf(
		"The deterministic fact gate checked the evidence references of the previous assessment. "+
			"Repair only the fact bindings listed below — missing citations, wrong locators, hashes or snapshot scope — "+
			"then return a complete "+AssessmentSchemaVersion+" JSON object. Do not restate reasoning; report: %s",
		report)
}

// clampFactFeedbackPasses enforces the spec bound regardless of the
// configured value: non-positive means the default MaxFactFeedbackPasses,
// anything larger is clamped down — a third repair pass is never run.
func clampFactFeedbackPasses(configured int) int {
	switch {
	case configured <= 0:
		return MaxFactFeedbackPasses
	case configured > MaxFactFeedbackPasses:
		return MaxFactFeedbackPasses
	default:
		return configured
	}
}

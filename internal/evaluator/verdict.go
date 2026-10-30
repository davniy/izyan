package evaluator

import (
	"fmt"
	"strings"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/goanalysis"
)

type VerdictEvaluator struct{}

// VerdictInput is the complete, copyable input of one verdict evaluation.
// Evidence is the case's evidence list (EvidenceList(), never a graph copy)
// so a persisted VERIFIED claim can be re-admitted against the measurements
// it cites.
type VerdictInput struct {
	Product  domain.ProductSnapshot
	Affected domain.AffectedResult
	Model    domain.ExploitModel
	Claims   []domain.Claim
	Evidence []domain.Evidence
	// Vulnerability is the exact record the assessment answers. It is the
	// identity authority for record-declared subjects: an absence claim about
	// a subject the record itself names is evidence about a declared subject,
	// while one about a candidate the record never named is candidate-derived.
	Vulnerability domain.Vulnerability
	// RootCause is the record's root-cause model. Absence evidence is
	// re-admitted against it: a candidate that names no established subject
	// of the selected version cannot ground a negative, however it was saved.
	// A nil model carries no candidate records, so it establishes no subject's
	// identity either — only the record's own declarations can.
	RootCause *domain.RootCauseModel
	// RecordPin pins the exact record bytes this evaluation's admission is
	// against. An own-record operation binding is re-admitted with it: the
	// quotation, record identity and document digest must still match, so a
	// binding read from other bytes establishes nothing. A nil pin refuses
	// every own-record binding rather than trusting the saved record.
	RecordPin *domain.RecordPin
	AdvisoryRecord *domain.AdvisoryRecordCapture
	// Case is the persisted case the claims belong to, when the caller has
	// it. Every saved TRUE that carries no typed control basis is
	// re-established against this case's evidence before the verdict: a
	// saved value is not itself evidence. Callers that only have the
	// claim/evidence projection leave it nil, and no saved positive is
	// re-evaluated. This field is read-only.
	Case *domain.AnalysisCase
}

// Evaluate is a pure function: no LLM, FS, DB or network. Before the
// verdict logic runs it re-admits persisted evidence: a target-dependent
// affected FALSE needs a scoped product target and a complete matching
// inventory, and a VERIFIED negative needs its measurement prerequisites and
// the matching verification build context. Refused evidence is treated as
// UNKNOWN — it can neither close nor veto a verdict by itself.
//
// NOT_AFFECTED is produced only by a deterministic FALSE in the
// affected-resolution chain (module present → version affected → package
// present → build relevant → vulnerable implementation present); FALSE
// exploit conditions require a VERIFIED negative check; a resolved
// but undecidable version chain (VersionAffected==UNKNOWN) keeps the case
// INCONCLUSIVE — neither EXPLOITABLE nor a falsifier-based NEPF may rest on
// unproven applicability; anything else is INCONCLUSIVE.
//
// NEPF requires an admitted falsifier: a mandatory FALSE whose negative
// verification is not VERIFIED stays unresolved and blocks the verdict even
// when another mandatory condition carries a verified falsifier.
//
// ExploitabilityScope is orthogonal to the verdict: a positive whose mandatory
// conjunction includes a library public-API control claim reports
// library-api and carries the mandatory limitation; every other verdict keeps
// the empty scope.

// VerdictEvaluation is the diagnostic projection of one verdict evaluation.
// Verdict is the public result; Gaps records the typed causes that kept the
// assessment from earning a definitive verdict. Gaps is empty whenever the
// verdict is definitive: a sufficient admitted proof wins over every
// unresolved obligation that cannot change it.
type VerdictEvaluation struct {
	Verdict domain.VerdictResult
	Gaps    []domain.AnalysisGap
}

// EvaluateDetailed runs the single deterministic evaluation once and returns
// both the verdict and its typed gap causes. Evaluate delegates here, so the
// repository has exactly one verdict implementation and never evaluates
// twice.
func (v VerdictEvaluator) EvaluateDetailed(in VerdictInput) VerdictEvaluation {
	admitted, refusals := admitVerdictInput(in)
	out := v.evaluate(admitted)
	for _, r := range refusals {
		out.Limitations = append(out.Limitations, r.message)
	}
	return VerdictEvaluation{Verdict: out, Gaps: verdictGaps(admitted, out, refusals)}
}

// Evaluate is the public verdict API. It delegates to EvaluateDetailed so the
// diagnostic projection and the public verdict always come from one
// evaluation.
func (v VerdictEvaluator) Evaluate(in VerdictInput) domain.VerdictResult {
	return v.EvaluateDetailed(in).Verdict
}

// refusalKind distinguishes the two admission refusals: an affected-chain
// negative refused because its target/inventory prerequisites did not hold,
// and a verified negative refused because its measurement identity did not
// hold. The kind is structural — no caller parses a message.
type refusalKind int

const (
	refusalAffectedNegative refusalKind = iota
	refusalClaimNegative
	refusalSemanticClaim
	// refusalCandidateIdentity marks an absence-based negative refused
	// because its subject names no established subject of the selected
	// version. It is a root-cause failure: the model named subjects this
	// version does not contain.
	refusalCandidateIdentity
	// refusalAuthCoverage marks a persisted TRUE authentication claim. The
	// middleware-name heuristic that produced it establishes no per-route
	// coverage, and no producer measures one, so there is no typed witness a
	// saved TRUE could rest on.
	refusalAuthCoverage
	// refusalRoleMismatch marks a persisted FALSE protocol-role mismatch. The
	// role it compared came from prose and fix-diff names, not a typed
	// protocol-role witness.
	refusalRoleMismatch
	// refusalWeakPositive marks a persisted TRUE condition claim that the
	// current deterministic evaluator no longer earns from the recorded
	// evidence. The retired unexported-sink + module-usage and
	// frame-name/server-role fallbacks produce no TRUE, so replay cannot keep
	// one.
	refusalWeakPositive
)

type verdictRefusal struct {
	kind        refusalKind
	conditionID domain.ConditionID
	message     string
}

// admitVerdictInput sanitizes persisted evidence before the verdict sees it.
// A refused claim becomes UNKNOWN (it is no longer a FALSE that could ground
// or block); a refused affected axis becomes UNKNOWN while independent axes
// (module graph, version range) stay usable. An absence-based negative whose
// subject is not an established subject of the selected version is refused the
// same way, and its subject is removed from the model's absent set.
func admitVerdictInput(in VerdictInput) (VerdictInput, []verdictRefusal) {
	out := in
	var refusals []verdictRefusal

	if err := domain.ValidateAffectedNegative(in.Product, in.Affected, in.Evidence); err != nil {
		if out.Affected.PackagePresent == domain.ClaimFalse {
			out.Affected.PackagePresent = domain.ClaimUnknown
		}
		if out.Affected.BuildRelevant == domain.ClaimFalse {
			out.Affected.BuildRelevant = domain.ClaimUnknown
		}
		if out.Affected.VulnerableImplementationPresent == domain.ClaimFalse {
			out.Affected.VulnerableImplementationPresent = domain.ClaimUnknown
		}
		refusals = append(refusals, verdictRefusal{
			kind:    refusalAffectedNegative,
			message: "affected negative refused: " + err.Error(),
		})
	}

	if len(in.Claims) == 0 {
		return out, refusals
	}
	conds := make(map[domain.ConditionID]domain.Condition, len(in.Model.MandatoryConditions)+len(in.Model.SupportingFactors))
	for _, cond := range in.Model.MandatoryConditions {
		conds[cond.ID] = cond
	}
	for _, cond := range in.Model.SupportingFactors {
		conds[cond.ID] = cond
	}
	out.Claims = append([]domain.Claim(nil), in.Claims...)

	// Candidate absence is evidence only about real subjects. A persisted
	// absence negative whose subject names no established subject of the
	// selected version is refused here, at the shared deterministic boundary,
	// and pruned from the model's absent set so the grouped coverage rules
	// cannot lean on it either.
	refusals = append(refusals, admitAbsenceIdentity(in, &out, conds)...)

	for i := range out.Claims {
		claim := &out.Claims[i]
		if claim.Result != domain.ClaimFalse || claim.NegativeVerification == nil ||
			claim.NegativeVerification.Status != domain.NegativeVerified {
			continue
		}
		cond, ok := conds[claim.ConditionID]
		if !ok {
			continue
		}
		if err := goanalysis.ValidateVerifiedNegative(goanalysis.NegativeAdmissionInput{Product:in.Product,Vulnerability:in.Vulnerability,RecordPin:in.RecordPin,AdvisoryRecord:in.AdvisoryRecord,Model:&in.Model,Evidence:in.Evidence}, *claim, cond); err != nil {
			claim.Result = domain.ClaimUnknown
			refusals = append(refusals, verdictRefusal{
				kind:        refusalClaimNegative,
				conditionID: claim.ConditionID,
				message: fmt.Sprintf(
					"negative verification for %s refused: %s", claim.ConditionID, err),
			})
		}
	}

	// A persisted TRUE check-trigger/input claim is only admissible when the
	// current evidence still carries a typed witness satisfying every
	// predicate on one invocation and receiver. A saved claim cannot smuggle
	// a conjunction past semantic admission.
	if contract := out.Model.DefectSemantics; contract != nil && contract.Mode == domain.DefectSemanticsDefectiveCheck {
		for i := range out.Claims {
			claim := &out.Claims[i]
			if claim.Result != domain.ClaimTrue {
				continue
			}
			cond, ok := conds[claim.ConditionID]
			if !ok || (!domain.IsCheckTriggerCondition(cond) && !domain.IsCheckInputCondition(cond)) {
				continue
			}
			if admitted, reasons := domain.CheckTriggerClaimAdmitted(contract, cond, in.Evidence); !admitted {
				claim.Result = domain.ClaimUnknown
				detail := "no typed witness"
				if len(reasons) > 0 {
					detail = reasons[0]
				}
				refusals = append(refusals, verdictRefusal{
					kind:        refusalSemanticClaim,
					conditionID: claim.ConditionID,
					message: fmt.Sprintf(
						"check-trigger claim for %s refused: %s", claim.ConditionID, detail),
				})
			}
		}
	}

	// Authority paths retired in favour of typed evidence are not re-admitted
	// from a saved claim set. A TRUE authentication condition rested on
	// middleware names matched near a listener; a FALSE protocol-role
	// mismatch rested on a role detected from prose and fix-diff names. No
	// producer measures per-route auth coverage and no typed protocol-role
	// witness exists, so both are demoted to UNKNOWN here, at the shared
	// boundary: replay cannot keep authority the live evaluators no longer
	// produce.
	for i := range out.Claims {
		claim := &out.Claims[i]
		cond, ok := conds[claim.ConditionID]
		if !ok || claim.Result == domain.ClaimUnknown {
			continue
		}
		switch {
		case claim.Result == domain.ClaimTrue && cond.Kind == domain.ConditionAuthn:
			claim.Result = domain.ClaimUnknown
			claim.Explanation = "per-route authentication coverage is not measured: name-matched auth wiring is not coverage"
			refusals = append(refusals, verdictRefusal{
				kind:        refusalAuthCoverage,
				conditionID: claim.ConditionID,
				message: fmt.Sprintf(
					"authentication claim for %s refused: name-matched auth wiring is not per-route coverage, and no producer measures it",
					claim.ConditionID),
			})
		case claim.Result == domain.ClaimFalse && claim.Falsifier == domain.FalsifierProtocolRoleMismatch:
			claim.Result = domain.ClaimUnknown
			claim.Explanation = "protocol role is not established by typed evidence, so no role mismatch is proven"
			refusals = append(refusals, verdictRefusal{
				kind:        refusalRoleMismatch,
				conditionID: claim.ConditionID,
				message: fmt.Sprintf(
					"protocol-role mismatch for %s refused: the role was nominated from prose/fix names and no typed protocol-role witness establishes it",
					claim.ConditionID),
			})
		}
	}

	// The same re-admission applies to persisted omission and omission-site
	// reach claims: a saved TRUE is current only while the typed missing-call
	// witness still binds the contracted check/pipeline and the effective
	// build. A legacy conclusion whose evidence record lacks the witness is
	// demoted, never trusted because it says TRUE.
	if contract := out.Model.DefectSemantics; contract != nil && contract.Mode == domain.DefectSemanticsOmittedCheck {
		for i := range out.Claims {
			claim := &out.Claims[i]
			if claim.Result != domain.ClaimTrue {
				continue
			}
			cond, ok := conds[claim.ConditionID]
			if !ok || (!domain.IsOmissionCondition(cond) && !domain.PipelineReachConditionMatchesContract(contract, cond)) {
				continue
			}
			if _, reasons := domain.MatchOmissionWitness(contract, cond, in.Evidence, in.Product, domain.MissingCallOmitted); len(reasons) > 0 {
				claim.Result = domain.ClaimUnknown
				refusals = append(refusals, verdictRefusal{
					kind:        refusalSemanticClaim,
					conditionID: claim.ConditionID,
					message: fmt.Sprintf(
						"omission claim for %s refused: %s", claim.ConditionID, reasons[0]),
				})
			}
		}
	}

	// Authority paths retired in favour of typed evidence are not re-admitted
	// from a saved claim set, and neither is any saved positive the current
	// evidence no longer earns.
	refusals = append(refusals, admitPersistedPositives(in, &out, conds)...)
	return out, refusals
}

// admitPersistedPositives re-establishes every saved TRUE claim that carries
// no typed control basis — a saved producer string or TRUE value is not
// evidence. The deterministic evaluator that produces the claim live must
// still earn TRUE from the recorded case; otherwise the claim is demoted to
// UNKNOWN at this shared boundary, so the retired unexported-sink +
// module-usage and frame-name/server-role fallbacks cannot regain authority by
// replay. Claims carrying a typed control basis are left to their
// witness-specific admission (rooted transport input/trigger, library
// public-API witness), which re-checks the witness rather than the saved
// value. Without the case there is nothing to re-establish, so the live
// workflow's own claims are untouched.
func admitPersistedPositives(in VerdictInput, out *VerdictInput, conds map[domain.ConditionID]domain.Condition) []verdictRefusal {
	if in.Case == nil {
		return nil
	}
	var refusals []verdictRefusal
	for i := range out.Claims {
		claim := &out.Claims[i]
		if claim.Result != domain.ClaimTrue || claim.ControlBasis != "" {
			continue
		}
		cond, ok := conds[claim.ConditionID]
		if !ok {
			continue
		}
		var ev ConditionEvaluator
		switch cond.Kind {
		case domain.ConditionSymbolReachable:
			ev = SymbolReachable{}
		case domain.ConditionAttackerControl, domain.ConditionInputConstraint:
			ev = ServerTransportInput{}
		default:
			continue
		}
		if ev.Evaluate(cond, in.Case).Result == domain.ClaimTrue {
			continue
		}
		claim.Result = domain.ClaimUnknown
		claim.Explanation = "the saved positive is not re-established by the recorded evidence: module usage, a transport frame name or another retired weak fallback cannot stand in for a typed witness or an exact call path"
		refusals = append(refusals, verdictRefusal{
			kind:        refusalWeakPositive,
			conditionID: claim.ConditionID,
			message: fmt.Sprintf(
				"positive claim for %s refused: a saved TRUE is not evidence, and the current deterministic evaluation does not earn it from the recorded measurement, typed witness or exact call path",
				claim.ConditionID),
		})
	}
	return refusals
}

func (VerdictEvaluator) evaluate(in VerdictInput) domain.VerdictResult {
	affected := in.Affected
	model := in.Model
	claims := in.Claims

	if affected.HasNegative() && !affected.Scope.AllowsNegativeClosure() {
		return domain.VerdictResult{
			Verdict:       domain.VerdictInconclusive,
			Reason:        negativeScopeLimitation(affected),
			EvidenceIDs:   affected.EvidenceIDs,
			Limitations:   affected.Limitations,
			AssumptionIDs: affected.AssumptionIDs,
		}
	}
	switch {
	case affected.ModulePresent == domain.ClaimFalse:
		reason := "vulnerable module is not part of the product dependency graph"
		if len(affected.CheckedModules) > 0 {
			reason = fmt.Sprintf("none of the affected module(s) %s resolve to a product dependency (go list -m all)",
				joinPaths(affected.CheckedModules))
		}
		return domain.VerdictResult{
			Verdict:     domain.VerdictNotAffected,
			Reason:      reason,
			EvidenceIDs: affected.EvidenceIDs,
		}
	case affected.VersionAffected == domain.ClaimFalse:
		reason := "resolved dependency version is outside affected range"
		if affected.ResolvedVersion != "" {
			reason = fmt.Sprintf("resolved version %s is outside the affected range", affected.ResolvedVersion)
		}
		return domain.VerdictResult{
			Verdict:     domain.VerdictNotAffected,
			Reason:      reason,
			EvidenceIDs: affected.EvidenceIDs,
		}
	case affected.PackagePresent == domain.ClaimFalse:
		// A test-only subject IS present in the recorded -test stream, so
		// "absent from the closure" would be a false statement about the
		// evidence. Report the exclusion for what it is: the package is
		// linked into the product's tests, never into a product binary.
		if len(affected.TestOnlyScope) > 0 {
			return domain.VerdictResult{
				Verdict: domain.VerdictNotAffected,
				Reason: fmt.Sprintf(
					"affected package(s) %s are linked only into the product's test scope (go list -deps -test ./... test roots) — the code is not linked into any product binary",
					joinPaths(affected.TestOnlyScope)),
				EvidenceIDs: affected.EvidenceIDs,
				Limitations: affected.Limitations,
			}
		}
		reason := "affected package is not imported by the product build"
		if len(affected.CheckedPackages) > 0 {
			reason = fmt.Sprintf("affected package(s) %s are absent from the product's transitive import closure (go list -deps -test ./...) — the code is not linked into the product",
				joinPaths(affected.CheckedPackages))
		}
		return domain.VerdictResult{
			Verdict:     domain.VerdictNotAffected,
			Reason:      reason,
			EvidenceIDs: affected.EvidenceIDs,
			Limitations: affected.Limitations,
		}
	case affected.BuildRelevant == domain.ClaimFalse:
		return domain.VerdictResult{
			Verdict:     domain.VerdictNotAffected,
			Reason:      "affected packages are constrained to other platforms/build configurations",
			EvidenceIDs: affected.EvidenceIDs,
		}
	// Implementation presence is the fifth affected-chain axis. It may be
	// FALSE only after the earlier axes were established, so both the
	// package and build-relevance axes must be TRUE here; the axis itself
	// was set by the admitted-proposal verifier under a product target
	// scope. An UNKNOWN axis falls through to INCONCLUSIVE.
	case affected.VulnerableImplementationPresent == domain.ClaimFalse &&
		affected.PackagePresent == domain.ClaimTrue &&
		affected.BuildRelevant == domain.ClaimTrue:
		reason := "the vulnerable implementation is deterministically absent from the product build"
		if affected.ImplementationLocus != "" {
			reason = fmt.Sprintf(
				"vulnerable implementation %s is deterministically absent from the product build target %s under the %s target scope",
				affected.ImplementationLocus, affected.ImplementationTarget, affected.ImplementationTargetScope)
		}
		return domain.VerdictResult{
			Verdict:       domain.VerdictNotAffected,
			Reason:        reason,
			EvidenceIDs:   affected.EvidenceIDs,
			Limitations:   affected.Limitations,
			AssumptionIDs: affected.AssumptionIDs,
		}
	}

	// Applicability ran but stayed undecidable (e.g. stdlib entry with an
	// unknown release toolchain, or a linked module with no resolvable
	// version): no verdict may commit to either side. EXPLOITABLE asserts an
	// affected version; a verified falsifier evaluated against the analysis
	// toolchain is not release-scoped evidence, so it cannot ground NEPF —
	// only INCONCLUSIVE honestly reports the open version question.
	if affected.ModulePresent == domain.ClaimTrue && affected.VersionAffected == domain.ClaimUnknown {
		return domain.VerdictResult{
			Verdict:     domain.VerdictInconclusive,
			Reason:      "version applicability is undecidable: resolved module version is unknown and the affected range cannot be applied",
			EvidenceIDs: affected.EvidenceIDs,
			Limitations: affected.Limitations,
		}
	}

	// Semantic admission: a resolved symbol does not imply resolved defect
	// semantics. A model built from the wrong mechanism (or from the
	// removed omission heuristic) cannot earn a verdict on a
	// sufficient-looking conjunction — the gate runs before NEPF and
	// EXPLOITABLE selection, while independently earned affected-chain
	// negatives above remain untouched.
	if err := domain.ValidateDefectSemanticsModel(model, in.Evidence); err != nil {
		return domain.VerdictResult{
			Verdict:     domain.VerdictInconclusive,
			Reason:      "defect semantics admission: " + err.Error(),
			Limitations: []string{err.Error()},
		}
	}

	// An unresolved high-severity critique of a mandatory condition is not
	// a caveat to attach next to closure: review-budget exhaustion must not
	// leave NEPF/EXPLOITABLE standing beside open criticism of the model.
	// Independent affected-chain negatives above still close the case; the
	// conjunction below may not.
	if len(model.PendingConditionReviews) > 0 {
		ids := append([]domain.ConditionID{}, model.PendingConditionReviews...)
		return domain.VerdictResult{
			Verdict: domain.VerdictInconclusive,
			Reason: "mandatory exploit condition(s) " + joinConditionIDs(ids) +
				" carry unresolved high-severity review criticism: the critique was recorded but no supported condition action resolved it, so neither a no-exploit-path nor an exploitable verdict may rest on the conjunction",
			ConditionIDs: ids,
		}
	}

	byCondition := make(map[domain.ConditionID]domain.Claim, len(claims))
	for _, c := range claims {
		byCondition[c.ConditionID] = c
	}

	// A mandatory FALSE grounds NEPF only as a verified negative. One
	// verified falsifier on another condition never overrides a mandatory
	// condition whose FALSE failed verification: an INSUFFICIENT_SCOPE
	// negative asserts the condition is false without closing the scope
	// that could hide the vulnerable invocation, so the condition remains
	// unresolved and the case stays INCONCLUSIVE. UNKNOWN/missing claims
	// do not block: a genuinely verified FALSE on any other mandatory
	// condition already refutes the conjunction.
	allTrue := len(model.MandatoryConditions) > 0
	var (
		nepfClaim     *domain.Claim
		nepfCondition domain.Condition
		unverifiedIDs []domain.ConditionID
		unverifiedWhy []string
	)
	for _, condition := range model.MandatoryConditions {
		claim, ok := byCondition[condition.ID]
		if !ok || claim.Result == domain.ClaimUnknown {
			allTrue = false
			continue
		}
		if claim.Result == domain.ClaimFalse {
			allTrue = false
			if claim.Falsifier == "" || claim.NegativeVerification == nil ||
				claim.NegativeVerification.Status != domain.NegativeVerified {
				why := "no falsifier"
				switch {
				case claim.Falsifier != "" && claim.NegativeVerification == nil:
					why = "negative verification missing"
				case claim.Falsifier != "":
					why = string(claim.NegativeVerification.Status)
				}
				unverifiedIDs = append(unverifiedIDs, condition.ID)
				unverifiedWhy = append(unverifiedWhy,
					fmt.Sprintf("%s (%s)", condition.ID, why))
				continue
			}
			// On an incomplete model a falsifier grounds NEPF only when
			// it covers the unmodeled sinks too: grouped reachability
			// evaluates the union of all advisory symbols, while
			// input/constraint/pair falsifiers bind just the resolved
			// subjects.
			if len(model.UnresolvedSubjects) > 0 &&
				!allUnresolvedAbsent(model) &&
				!coversAllDeclared(claim) &&
				!configClosureCoversUnresolved(claim, condition, model) &&
				!locusCoversUnresolved(claim.Falsifier, condition, model) {
				continue
			}
			if nepfClaim == nil {
				c := claim
				nepfClaim = &c
				nepfCondition = condition
			}
		}
	}

	// An unverified mandatory FALSE is unresolved evidence, not a refuted
	// requirement: it blocks NEPF even when another condition carries a
	// verified falsifier.
	if len(unverifiedIDs) > 0 {
		return domain.VerdictResult{
			Verdict:      domain.VerdictInconclusive,
			Reason:       "mandatory exploit condition(s) " + strings.Join(unverifiedWhy, ", ") + " remain unresolved: a FALSE claim without a verified negative cannot ground a no-exploit-path verdict, and another condition's verified falsifier cannot override it",
			ConditionIDs: unverifiedIDs,
		}
	}

	if nepfClaim != nil {
		if !affected.Scope.AllowsNegativeClosure() {
			return domain.VerdictResult{
				Verdict:       domain.VerdictInconclusive,
				Reason:        negativeScopeLimitation(affected),
				ConditionIDs:  []domain.ConditionID{nepfCondition.ID},
				EvidenceIDs:   nepfClaim.EvidenceIDs,
				Limitations:   affected.Limitations,
				AssumptionIDs: nepfClaim.AssumptionIDs,
			}
		}
		return domain.VerdictResult{
			Verdict:      domain.VerdictNoExploitPathFound,
			Reason:       "mandatory exploit condition is proven false",
			ConditionIDs: []domain.ConditionID{nepfCondition.ID},
			EvidenceIDs:  nepfClaim.EvidenceIDs,
			// The trust basis and the policy assumption are carried
			// exactly as the verified claim recorded them: the
			// verdict never invents either, and assumption ids stay
			// disjoint from EvidenceIDs.
			GroundBasis:   verdictGroundBasis(*nepfClaim),
			AssumptionIDs: nepfClaim.AssumptionIDs,
		}
	}

	// A model whose mechanism was only nominated carries the reduced
	// conjunction: the class pattern's conditions were never merged, so an
	// all-TRUE result over what remains is no evidence of exploitability. The
	// positive is withheld; a verified mandatory falsifier above may still
	// ground a negative.
	if allTrue && model.UnresolvedMechanism {
		return domain.VerdictResult{
			Verdict: domain.VerdictInconclusive,
			Reason: "the exploit model's mechanism is unresolved: the class was only nominated from keyword, " +
				"fix-diff or conflicting prose evidence, so the modeled conjunction omits the conditions that " +
				"nomination demanded and cannot ground a positive",
		}
	}

	if allTrue && len(model.UnresolvedSubjects) == 0 {
		result := domain.VerdictResult{
			Verdict: domain.VerdictExploitable,
			Reason:  "all mandatory exploit conditions are satisfied",
		}
		// A positive rests on the mandatory conjunction, so it must cite
		// the conditions and evidence it stands on. Publication rejects a
		// positive that names no condition: an unexplained positive cannot
		// be re-admitted or rendered.
		cited := make(map[domain.ConditionID]bool, len(model.MandatoryConditions))
		for _, condition := range model.MandatoryConditions {
			claim, ok := byCondition[condition.ID]
			if !ok || claim.Result != domain.ClaimTrue {
				continue
			}
			cited[condition.ID] = true
			result.ConditionIDs = append(result.ConditionIDs, condition.ID)
			result.EvidenceIDs = appendEvidenceIDs(result.EvidenceIDs, claim.EvidenceIDs)
		}
		// The boundary axis is orthogonal to the verdict: a positive stays
		// EXPLOITABLE, but says which product boundary it covers. It is set
		// only when a mandatory TRUE claim rests on an admitted basis —
		// never from a supporting claim or a raw witness.
		scope, refused := resolveExploitabilityScope(model, claims, in.Product, in.Evidence)
		if refused != "" {
			// A scope claim whose witness no longer re-admits cannot
			// ground an unexplained positive: the boundary is part of
			// the conclusion, so the verdict stays INCONCLUSIVE and the
			// refusal is named.
			return domain.VerdictResult{
				Verdict: domain.VerdictInconclusive,
				Reason:  "a mandatory boundary claim failed witness re-admission: " + refused,
			}
		}
		if scope != "" {
			result.ExploitabilityScope = scope
			result.Limitations = append(result.Limitations, domain.ExploitabilityScopeLimitations(scope)...)
			basis := controlBasisForScope(scope)
			seen := make(map[domain.ConditionID]bool, len(model.MandatoryConditions))
			for _, cl := range claims {
				if cl.Result != domain.ClaimTrue || cl.ControlBasis != basis {
					continue
				}
				if seen[cl.ConditionID] || cited[cl.ConditionID] || !mandatoryCondition(model, cl.ConditionID) {
					continue
				}
				seen[cl.ConditionID] = true
				result.ConditionIDs = append(result.ConditionIDs, cl.ConditionID)
				result.EvidenceIDs = appendEvidenceIDs(result.EvidenceIDs, cl.EvidenceIDs)
			}
		}
		return result
	}
	if allTrue {
		var names []string
		for _, s := range model.UnresolvedSubjects {
			names = append(names, s.Package+"."+s.Symbol)
		}
		return domain.VerdictResult{
			Verdict: domain.VerdictInconclusive,
			Reason: fmt.Sprintf("all modeled mandatory conditions are satisfied, but %d sink candidate(s) are unresolved or proven absent from the build (%s): the exploit model is pruned and cannot ground a positive verdict",
				len(model.UnresolvedSubjects), strings.Join(names, ", ")),
		}
	}

	var unresolved []string
	for _, condition := range model.MandatoryConditions {
		claim, ok := byCondition[condition.ID]
		if !ok || claim.Result != domain.ClaimTrue {
			unresolved = append(unresolved, string(condition.ID))
		}
	}
	reason := "one or more mandatory exploit conditions remain unresolved"
	if len(unresolved) > 0 {
		reason += ": " + strings.Join(unresolved, ", ")
	}
	return domain.VerdictResult{
		Verdict: domain.VerdictInconclusive,
		Reason:  reason,
	}
}

// verdictExploitabilityScope names the product boundary a positive verdict
// covers. library-api is returned only when at least one mandatory TRUE claim
// records the library public-API control basis; a supporting claim, a raw
// witness or a library-shaped product alone never scopes a verdict. Every
// non-positive verdict carries no scope (the zero value is empty).
func verdictExploitabilityScope(model domain.ExploitModel, claims []domain.Claim) domain.ExploitabilityScope {
	for _, cl := range claims {
		if cl.Result == domain.ClaimTrue &&
			cl.ControlBasis == domain.ControlBasisLibraryPublicAPI &&
			mandatoryCondition(model, cl.ConditionID) {
			return domain.ScopeLibraryAPI
		}
	}
	return ""
}

// resolveExploitabilityScope selects the boundary the positive conclusion
// covers, re-admitting the witness that grounds it. The library public-API
// route keeps its exact class/CWE admission (already encoded in the claim's
// basis); the transport-peer route requires a rooted input witness that still
// re-admits against this build. A transport basis whose witness fails
// re-admission is refused — the refusal is not a scope and not a verdict.
func resolveExploitabilityScope(
	model domain.ExploitModel,
	claims []domain.Claim,
	product domain.ProductSnapshot,
	evidence []domain.Evidence,
) (domain.ExploitabilityScope, string) {
	if scope := verdictExploitabilityScope(model, claims); scope != "" {
		return scope, ""
	}
	for _, cl := range claims {
		if cl.Result != domain.ClaimTrue ||
			cl.ControlBasis != domain.ControlBasisTransportPeerInput ||
			!mandatoryCondition(model, cl.ConditionID) {
			continue
		}
		if err := ValidateTransportInput(product, model, cl, evidence); err != nil {
			return "", fmt.Sprintf("claim %s: %v", cl.ConditionID, err)
		}
		return domain.ScopeTransportPeer, ""
	}
	return "", ""
}

// controlBasisForScope maps a frozen scope to the mandatory claim basis that
// grounds it.
func controlBasisForScope(scope domain.ExploitabilityScope) domain.ControlBasis {
	switch scope {
	case domain.ScopeTransportPeer:
		return domain.ControlBasisTransportPeerInput
	case domain.ScopeLibraryAPI:
		return domain.ControlBasisLibraryPublicAPI
	}
	return ""
}

// mandatoryCondition reports whether the id belongs to the model's mandatory
// conjunction.
func mandatoryCondition(model domain.ExploitModel, id domain.ConditionID) bool {
	for _, cond := range model.MandatoryConditions {
		if cond.ID == id {
			return true
		}
	}
	return false
}

func negativeScopeLimitation(affected domain.AffectedResult) string {
	requested := "the requested advisory"
	if affected.Scope != nil && affected.Scope.RequestedID != "" {
		requested = affected.Scope.RequestedID
	}
	checked := "modeled components"
	if len(affected.CheckedModules) > 0 {
		checked = "checked module(s) " + joinPaths(affected.CheckedModules)
	} else if len(affected.CheckedPackages) > 0 {
		checked = "checked package(s) " + joinPaths(affected.CheckedPackages)
	}
	return fmt.Sprintf("partial or unknown advisory scope: negative facts for %s do not establish complete coverage of %s; the remaining requested scope is unresolved", checked, requested)
}

// coversAllDeclared reports whether a falsifier's FALSE claim spans every
// advisory-declared symbol — required to ground NEPF when the exploit model
// is incomplete (UnresolvedSubjects non-empty). The grouped reachability
// falsifiers evaluate the union of declared symbols; falsifiers bound to
// resolved-sink arguments, readers or pair members leave the unmodeled
// unresolved sink's exploit shape unconstrained. A config-origin trusted-infrastructure
// claim is verified against the *resolved* sinks' traced inputs only — it
// constrains nothing about an unmodeled sink's inputs and therefore does
// not cover unresolved subjects here, unlike a declared/auto-detected
// perimeter basis which asserts the trust boundary sink-agnostically.
// configClosureCoversUnresolved is the narrower route for exactly that
// basis: it covers only unresolved subjects the verified sink closure
// itself enumerated.
func coversAllDeclared(claim domain.Claim) bool {
	if claim.Falsifier == domain.FalsifierTrustedInfrastructure &&
		claim.FalsifierBasis != domain.BasisDeclaredTrust &&
		claim.FalsifierBasis != domain.BasisAutoPerimeter {
		return false
	}
	switch claim.Falsifier {
	case domain.FalsifierGovulncheckSilence,
		domain.FalsifierNoModuleUsage,
		domain.FalsifierUnreachedExportedSubject,
		domain.FalsifierTrustedInfrastructure,
		domain.FalsifierConfigGatedOff,
		domain.FalsifierDeclaredSymbolUnreached:
		return true
	}
	return false
}

// locusCoversUnresolved reports whether a verified locus-package-absent
// falsifier also discharges the model's unresolved subjects: only when every
// unresolved symbol is itself a member of the locus set the verification
// proved absent from the build graph. An unresolved symbol outside L keeps
// locusCoversUnresolved reports whether a verified negative falsifier also
// discharges the model's unresolved subjects.
//
// For locus-package-absent and package-absent, every unresolved symbol must be
// proved absent from the build graph or a member of the verified absent set.
//
// For locus-function-unreached, every present sink in the condition was verified
// unreached. An unresolved subject that is proven absent (package not in build graph
// or symbol not declared in the linked dependency version, model.AbsentSubjects)
// has no executable form in the snapshot and cannot be reached through any path,
// so the unreached verification over all present sinks covers the advisory.
// allUnresolvedAbsent reports whether every unresolved subject in the exploit
// model is proven absent from the linked build graph (model.AbsentSubjects).
// When this holds, the exploit model is complete for all code present in the
// snapshot, so verified falsifiers over the modeled sinks are safe to ground NEPF.
func allUnresolvedAbsent(model domain.ExploitModel) bool {
	if len(model.UnresolvedSubjects) == 0 {
		return true
	}
	if len(model.AbsentSubjects) == 0 {
		return false
	}
	absent := make(map[domain.SymbolRef]bool, len(model.AbsentSubjects))
	for _, s := range model.AbsentSubjects {
		absent[s] = true
	}
	for _, u := range model.UnresolvedSubjects {
		if !absent[u] {
			return false
		}
	}
	return true
}

func locusCoversUnresolved(falsifier string, cond domain.Condition, model domain.ExploitModel) bool {
	if falsifier != domain.FalsifierLocusPackageAbsent &&
		falsifier != domain.FalsifierPackageAbsent &&
		falsifier != domain.FalsifierLocusFunctionUnreached {
		return false
	}
	absent := make(map[domain.SymbolRef]bool, len(model.AbsentSubjects))
	for _, s := range model.AbsentSubjects {
		absent[s] = true
	}
	for _, u := range model.UnresolvedSubjects {
		if absent[u] {
			continue
		}
		member := false
		for _, s := range cond.Subjects {
			if s == u {
				member = true
				break
			}
		}
		if !member {
			return false
		}
	}
	return true
}

// verdictGroundBasis names what a NEPF verdict rests on when the
// grounding claim is a trusted-infrastructure falsifier. The claim is
// authoritative: the verdict never derives a basis of its own, and an
// unrecorded basis keeps the pre-existing declared-trust meaning (the
// operator assertion --trusted-peer/--perimeter is the only
// trusted-infrastructure route that leaves it empty). Code-level
// falsifiers keep an empty basis.
func verdictGroundBasis(claim domain.Claim) string {
	if claim.Falsifier != domain.FalsifierTrustedInfrastructure {
		return ""
	}
	if claim.FalsifierBasis == "" {
		return domain.BasisDeclaredTrust
	}
	return claim.FalsifierBasis
}

// configClosureCoversUnresolved reports whether a verified exact-argument
// configuration claim discharges the model's unresolved subjects.
//
// The post-reach configuration route proves the exact trigger argument at
// every live site of the condition's sink set inside a complete,
// advisory-bound sink closure. It therefore speaks about exactly the
// condition's sinks: an unresolved subject is covered only when it is one
// of those exact sinks (the closure enumerated and traced it). A sink
// outside the condition, a package/module-level candidate, or a claim
// that does not carry an admitted config-trust assumption (or is not the
// post-reach producer at all) keeps the claim local and the verdict
// INCONCLUSIVE. This is deliberately narrower than coversAllDeclared: an
// assumption never turns a sink-bound falsifier into a sink-agnostic
// trust boundary.
func configClosureCoversUnresolved(claim domain.Claim, cond domain.Condition, model domain.ExploitModel) bool {
	if claim.Producer != postReachProducer ||
		claim.Falsifier != domain.FalsifierTrustedInfrastructure ||
		claim.FalsifierBasis != domain.BasisConfigOrigin ||
		len(claim.AssumptionIDs) == 0 {
		return false
	}
	covered := make(map[domain.SymbolRef]bool, len(cond.Subjects)+1)
	for _, s := range cond.Subjects {
		if s.Package == "" || s.Symbol == "" {
			continue
		}
		covered[s] = true
	}
	if cond.Subject != nil && cond.Subject.Package != "" && cond.Subject.Symbol != "" {
		covered[*cond.Subject] = true
	}
	if len(covered) == 0 {
		return false
	}
	for _, u := range model.UnresolvedSubjects {
		if !covered[u] {
			return false
		}
	}
	return true
}

// definitiveOutcome reports whether the verdict is one a sufficient proof
// earned. INCONCLUSIVE is never definitive: it must be backed by a named
// external dependency at the assessment layer.
func definitiveOutcome(v domain.Verdict) bool {
	switch v {
	case domain.VerdictExploitable, domain.VerdictNotAffected, domain.VerdictNoExploitPathFound:
		return true
	default:
		return false
	}
}

// verdictGaps derives the typed causes behind a non-definitive evaluation.
// Every branch routes on structured state — affected axes, model fields,
// claim results and producer-emitted gap codes — and never on reason or
// limitation text.
func verdictGaps(in VerdictInput, out domain.VerdictResult, refusals []verdictRefusal) []domain.AnalysisGap {
	if definitiveOutcome(out.Verdict) {
		return nil
	}
	var gaps []domain.AnalysisGap
	add := func(owner domain.GapOwner, code domain.GapCode, obligation domain.Obligation,
		condition domain.ConditionID, message string, external *domain.ExternalDependency) {
		gaps = append(gaps, domain.AnalysisGap{
			Owner:       owner,
			Code:        code,
			Obligation:  obligation,
			ConditionID: condition,
			Message:     message,
			External:    external,
		})
	}
	for _, r := range refusals {
		switch r.kind {
		case refusalAffectedNegative:
			add(domain.GapOwnerProof, domain.GapMeasurementNotCompleted, domain.ObligationMeasurement,
				"", r.message, nil)
		case refusalClaimNegative:
			add(domain.GapOwnerProof, domain.GapNegativeVerificationIncomplete, domain.ObligationCondition,
				r.conditionID, r.message, nil)
		case refusalSemanticClaim:
			add(domain.GapOwnerCode, domain.GapTriggerProofIncomplete, domain.ObligationCondition,
				r.conditionID, r.message, nil)
		case refusalCandidateIdentity:
			// Not a condition measurement gap: the record's root cause named
			// subjects the selected version does not contain, so the root
			// cause — not the trace — is what remains unresolved.
			add(domain.GapOwnerCode, domain.GapRootCauseUnresolved, domain.ObligationRootCause,
				r.conditionID, r.message, nil)
		case refusalAuthCoverage, refusalRoleMismatch, refusalWeakPositive:
			// All three retired claims rest on a heuristic no producer
			// measures: coverage of the surface by auth, the protocol role
			// itself, and structural module/frame hints in place of a typed
			// witness or exact call path. The work is analyzer measurement,
			// never an external dependency.
			add(domain.GapOwnerProof, domain.GapMeasurementNotCompleted, domain.ObligationCondition,
				r.conditionID, r.message, nil)
		}
	}

	affected := in.Affected
	model := in.Model
	claims := in.Claims

	// Semantic admission failure is a root-cause/model failure, not a
	// condition-level trace gap: the analyzer built the wrong defect (or
	// could not establish which one). It is CODE work, never external.
	if err := domain.ValidateDefectSemanticsModel(model, in.Evidence); err != nil {
		add(domain.GapOwnerCode, domain.GapRootCauseUnresolved, domain.ObligationRootCause,
			"", domain.SemanticsUnresolvedGapMessage, nil)
		return gaps
	}

	// A component negative whose scope does not allow closure is a scope
	// capability failure, never an environmental answer.
	if affected.HasNegative() && !affected.Scope.AllowsNegativeClosure() {
		add(domain.GapOwnerScope, domain.GapUnsupportedNegativeScope, domain.ObligationNegativeScope,
			"", out.Reason, nil)
		return gaps
	}

	// Version applicability that the artifact itself cannot settle is the one
	// genuine external question here: only the shipped artifact's version can
	// answer it. Without evidence locating that boundary the same fact is an
	// input-resolution failure instead.
	if affected.ModulePresent == domain.ClaimTrue && affected.VersionAffected == domain.ClaimUnknown {
		if dep := releaseVersionDependency(affected); dep != nil {
			add(domain.GapOwnerExternal, domain.GapExternalDependencyUnresolved, domain.ObligationVersionRange,
				"", out.Reason, dep)
		} else {
			add(domain.GapOwnerInput, domain.GapInputResolutionFailed, domain.ObligationVersionRange,
				"", out.Reason, nil)
		}
		return gaps
	}

	if len(model.PendingConditionReviews) > 0 {
		for _, id := range model.PendingConditionReviews {
			add(domain.GapOwnerProof, domain.GapReviewUnresolved, domain.ObligationCondition, id,
				"mandatory condition "+string(id)+" carries unresolved high-severity review criticism; no verdict may close around it", nil)
		}
		return gaps
	}

	byCondition := make(map[domain.ConditionID]domain.Claim, len(claims))
	for _, cl := range claims {
		byCondition[cl.ConditionID] = cl
	}

	unverified := 0
	for _, condition := range model.MandatoryConditions {
		claim, ok := byCondition[condition.ID]
		if !ok || claim.Result != domain.ClaimFalse {
			continue
		}
		if claim.Falsifier == "" || claim.NegativeVerification == nil ||
			claim.NegativeVerification.Status != domain.NegativeVerified {
			unverified++
			add(domain.GapOwnerProof, domain.GapNegativeVerificationIncomplete, domain.ObligationCondition,
				condition.ID, "mandatory condition "+string(condition.ID)+" is FALSE without an admitted verified negative", nil)
		}
	}
	if unverified > 0 {
		return gaps
	}

	// A verified falsifier that would ground NEPF, blocked only by the
	// advisory scope's inability to close, is a scope-capability failure —
	// the evaluator returned INCONCLUSIVE for exactly that reason.
	if !affected.Scope.AllowsNegativeClosure() && hasAdmittedFalsifier(model, claims) {
		add(domain.GapOwnerScope, domain.GapUnsupportedNegativeScope, domain.ObligationNegativeScope,
			"", "a verified falsifier cannot close the requested advisory scope", nil)
		return gaps
	}

	allTrue := len(model.MandatoryConditions) > 0
	unresolved := 0
	for _, condition := range model.MandatoryConditions {
		if claim, ok := byCondition[condition.ID]; !ok || claim.Result != domain.ClaimTrue {
			allTrue = false
			unresolved++
		}
	}
	if allTrue && model.UnresolvedMechanism {
		add(domain.GapOwnerCode, domain.GapRootCauseUnresolved, domain.ObligationRootCause,
			"", out.Reason, nil)
		return gaps
	}

	if allTrue && len(model.UnresolvedSubjects) > 0 {
		add(domain.GapOwnerCode, domain.GapReachabilityProofIncomplete, domain.ObligationCondition,
			"", out.Reason, nil)
		return gaps
	}

	if len(model.MandatoryConditions) == 0 {
		add(domain.GapOwnerCode, domain.GapUnclassifiedAnalysisGap, domain.ObligationMeasurement,
			"", out.Reason, nil)
		return gaps
	}

	for _, condition := range model.MandatoryConditions {
		claim, ok := byCondition[condition.ID]
		if ok && claim.Result == domain.ClaimTrue {
			continue
		}
		if ok && len(claim.AnalysisGaps) > 0 {
			// Producer diagnostics are authoritative: keep the typed cause
			// exactly as the producer recorded it.
			gaps = append(gaps, claim.AnalysisGaps...)
			continue
		}
		switch condition.Kind {
		case domain.ConditionSymbolReachable:
			add(domain.GapOwnerCode, domain.GapReachabilityProofIncomplete, domain.ObligationCondition,
				condition.ID, "reachability of mandatory condition "+string(condition.ID)+" was not proven", nil)
		case domain.ConditionAttackerControl, domain.ConditionInputConstraint:
			add(domain.GapOwnerCode, domain.GapInputTraceIncomplete, domain.ObligationCondition,
				condition.ID, "attacker-selectable input for mandatory condition "+string(condition.ID)+" was not traced", nil)
		case domain.ConditionCheckTrigger, domain.ConditionCheckInput:
			add(domain.GapOwnerCode, domain.GapTriggerProofIncomplete, domain.ObligationCondition,
				condition.ID, "the mandatory check-trigger proof for "+string(condition.ID)+" was not established on one invocation and receiver", nil)
		case domain.ConditionAuthn:
			add(domain.GapOwnerProof, domain.GapMeasurementNotCompleted, domain.ObligationCondition,
				condition.ID, "per-route authentication coverage of the surface feeding "+string(condition.ID)+" was not measured; name-matched auth wiring is not coverage", nil)
		default:
			add(domain.GapOwnerCode, domain.GapUnclassifiedAnalysisGap, domain.ObligationCondition,
				condition.ID, "mandatory condition "+string(condition.ID)+" remains unresolved without a typed producer cause", nil)
		}
	}
	if len(model.UnresolvedSubjects) > 0 {
		add(domain.GapOwnerCode, domain.GapReachabilityProofIncomplete, domain.ObligationCondition,
			"", "advisory-declared sink candidate(s) remain unresolved; the exploit model cannot ground a positive", nil)
	}
	return gaps
}

// hasAdmittedFalsifier mirrors the positive NEPF selection: a mandatory FALSE
// with an admitted verified negative whose coverage reaches the unresolved
// subjects (when any). It is used only to explain why NEPF was withheld.
func hasAdmittedFalsifier(model domain.ExploitModel, claims []domain.Claim) bool {
	byCondition := make(map[domain.ConditionID]domain.Claim, len(claims))
	for _, cl := range claims {
		byCondition[cl.ConditionID] = cl
	}
	for _, condition := range model.MandatoryConditions {
		claim, ok := byCondition[condition.ID]
		if !ok || claim.Result != domain.ClaimFalse {
			continue
		}
		if claim.Falsifier == "" || claim.NegativeVerification == nil ||
			claim.NegativeVerification.Status != domain.NegativeVerified {
			continue
		}
		if len(model.UnresolvedSubjects) > 0 &&
			!allUnresolvedAbsent(model) &&
			!coversAllDeclared(claim) &&
			!configClosureCoversUnresolved(claim, condition, model) &&
			!locusCoversUnresolved(claim.Falsifier, condition, model) {
			continue
		}
		return true
	}
	return false
}

// releaseVersionDependency names the shipped-artifact version as the missing
// external fact. The recorded affected evidence locates the boundary; without
// it the dependency is unbound and the caller must fail instead.
func releaseVersionDependency(affected domain.AffectedResult) *domain.ExternalDependency {
	if len(affected.EvidenceIDs) == 0 {
		return nil
	}
	refs := make([]domain.QualifiedRef, 0, len(affected.EvidenceIDs))
	for _, id := range affected.EvidenceIDs {
		if id == "" {
			continue
		}
		refs = append(refs, domain.QualifiedRef{Ref: string(id)})
	}
	if len(refs) == 0 {
		return nil
	}
	return &domain.ExternalDependency{
		MissingFact:             "the affected entry's version as shipped in the delivered artifact (release toolchain/module version)",
		AffectedObligation:      domain.ObligationVersionRange,
		BoundaryEvidenceRefs:    refs,
		WhyArtifactCannotSupply: "the source snapshot's go.mod minimum and the analyzer's own toolchain do not describe the shipped artifact, and no authoritative release module graph was recorded",
		AlternativesChanging: []string{
			"the shipped version is inside the record's affected ranges, so the finding is positive",
			"the shipped version is at or above the record's fixed version, so the entry is not affected",
		},
		ResolvingEvidence: "an artifact build info (--binary), an authoritative release module graph, or an operator-declared release toolchain version",
	}
}

func joinConditionIDs(ids []domain.ConditionID) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = string(id)
	}
	return strings.Join(parts, ", ")
}

func joinPaths(paths []string) string {
	q := make([]string, len(paths))
	for i, p := range paths {
		q[i] = `"` + p + `"`
	}
	return strings.Join(q, ", ")
}

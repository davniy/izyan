package evaluator

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/fedorovmv/izyan/internal/domain"
)

// ArgumentOrigin evaluates ATTACKER_CONTROL and INPUT_CONSTRAINT conditions
// from DataFlow entries recorded by the argument-provenance collector.
//
// TRUE  — at least one trace proves EXTERNAL_UNTRUSTED/AUTHENTICATED origin.
// FALSE (candidate) — every traced call site has a non-external origin
// (CONSTANT/GENERATED); requires negative verification.
// UNKNOWN — missing traces or unresolvable origins.
type ArgumentOrigin struct{}

func (ArgumentOrigin) CanEvaluate(cond domain.Condition) bool {
	return cond.Kind == domain.ConditionAttackerControl || cond.Kind == domain.ConditionInputConstraint
}

func (ArgumentOrigin) Evaluate(cond domain.Condition, c *domain.AnalysisCase) domain.Claim {
	return admitNegative(c, cond, evaluateArgumentOrigin(cond, c))
}

func evaluateArgumentOrigin(cond domain.Condition, c *domain.AnalysisCase) domain.Claim {
	claim := domain.Claim{
		ID:          domain.ClaimID("CL-" + string(cond.ID)),
		ConditionID: cond.ID,
		Result:      domain.ClaimUnknown,

		Producer: "evaluator.ArgumentOrigin",
	}
	// A sink whose package is not linked into the build graph cannot
	// receive any input — absence falsifies the input condition outright.
	if set, ids, err := packageImportSet(c); err == nil && len(cond.Subjects) > 0 {
		allAbsent := true
		var pkgs []string
		for _, s := range cond.Subjects {
			if s.Package == "" || set[s.Package] {
				allAbsent = false
			} else {
				pkgs = appendUnique(pkgs, s.Package)
			}
		}
		if allAbsent {
			claim.Result = domain.ClaimFalse
			claim.Falsifier = domain.FalsifierPackageAbsent
			claim.EvidenceIDs = ids
			claim.Explanation = fmt.Sprintf(
				"all subject package(s) (%s) are absent from the product's build graph (go list -deps); no data flow can reach defect code that is not linked in",
				strings.Join(pkgs, ", "))
			return claim
		}
	}
	flows := flowsFor(c, cond.ID)
	if len(flows) == 0 {
		claim.Limitations = append(claim.Limitations,
			"no argument-provenance data flows recorded for this condition")
		return claim
	}
	// A proven library public-API payload binding is a typed positive: admit
	// it after the package-absence check and after genuine external origin
	// precedence below, but before unresolved-origin handling and before the
	// constant-input FALSE fallback. A rejected witness proves nothing and
	// leaves the existing provenance logic untouched.
	_, witness, libraryWitness := admittedLibraryWitness(cond, c)
	mods := linkedModules(c)
	var safe, external, unknown, payloadUnproven, deployDependent, coneInternal, configFlows int
	for _, f := range flows {
		if cond.ArgIndex < 0 && f.PayloadUnproven &&
			(f.Origin == domain.OriginExternalUntrusted || f.Origin == domain.OriginExternalAuthenticated) {
			unknown++
			payloadUnproven++
			continue
		}
		switch f.Origin {
		case domain.OriginExternalUntrusted, domain.OriginExternalAuthenticated:
			external++
		case domain.OriginConfiguration, domain.OriginDatabase, domain.OriginInternalService:
			// Deployment-controlled sources: trust boundary is a deployment
			// property — we cannot prove the value is not attacker-influenced.
			deployDependent++
			if f.Origin == domain.OriginConfiguration {
				configFlows++
			}
		case domain.OriginConstant, domain.OriginGenerated:
			safe++
		default:
			// Unresolvable argument inside the vulnerable module's cone:
			// the value is dependency-internal, so its provenance is
			// decided by the ingress closure, not by call-site tracing —
			// a complete closure with all-safe reaching items absorbs it.
			if inCaseModules(f.Sink.Package, mods) {
				coneInternal++
			} else {
				unknown++
			}
		}
	}
	for _, e := range c.EvidenceGraph.Evidence {
		if e.Kind == domain.EvidenceSourceSnippet || e.Kind == domain.EvidenceDataFlow {
			claim.EvidenceIDs = appendUniqueID(claim.EvidenceIDs, e.ID)
		}
	}
	// Security-relevant transformations on the traced path are provenance,
	// not guards: an escape/quote/validate call between source and sink may
	// change whether the constraint still fails — surface it for review.
	var sec []string
	for _, f := range flows {
		for _, tx := range f.Transformations {
			if domain.IsSecurityTransform(tx.Callee) {
				sec = appendUnique(sec, tx.Callee)
			}
		}
	}
	if len(sec) > 0 {
		claim.Limitations = append(claim.Limitations,
			"security-relevant transform(s) on traced path (not modeled as guards): "+strings.Join(sec, ", "))
	}
	// A constant argument that satisfies a bound term violates the
	// constraint deterministically — no guard can save it. Checked before
	// the guard-coverage path: constant args are skipped from coverage.
	if cond.Kind == domain.ConditionInputConstraint &&
		cond.Params[domain.ParamBound] != "" {
		if hit := constViolatesBound(cond, flows); hit != "" {
			claim.Result = domain.ClaimTrue
			claim.Explanation = hit
			return claim
		}
	}
	// Constraint coverage: an INPUT_CONSTRAINT can be falsified by guards
	// bounding the value at the sink or at its field write sites — but only
	// when every traced argument's origin is resolved (an UNKNOWN origin
	// could be unbounded input we failed to see). Stricter than
	// hasGuardBefore: only real non-conditional guards count.
	if cond.Kind == domain.ConditionInputConstraint && unknown+coneInternal == 0 && len(flows) > 0 {
		covered := true
		needs := 0
		for _, f := range flows {
			// Constants and generated values are bounded by definition —
			// only mutable inputs need guard coverage.
			if f.Origin == domain.OriginConstant || f.Origin == domain.OriginGenerated {
				continue
			}
			needs++
			if !guardCovers(c.EvidenceGraph.Validations, f.Sink, f.Arg) {
				covered = false
				break
			}
		}
		if covered && needs == 0 {
			// every traced arg is constant — falsified by origin, handled
			// by the default branch below
			covered = false
		}
		if covered {
			claim.Result = domain.ClaimFalse
			claim.Falsifier = domain.FalsifierGuards
			claim.Explanation = fmt.Sprintf(
				"all %d traced sink site(s) are covered by bound guards in the product: the values reaching the sink "+
					"are provably outside the violating range, so this exploit condition cannot be satisfied "+
					"(this says nothing about checks inside the vulnerable dependency itself)",
				len(flows))
			claim.Limitations = append(claim.Limitations,
				"FALSE is a candidate: sanitize guards are heuristic (comparison+clean reassign shape)")
			if note := verifyBound(cond, c, flows); note != "" {
				claim.Explanation += "; " + note
				if !strings.HasPrefix(note, "bound verified") {
					claim.Limitations = append(claim.Limitations, note)
				} else {
					// The declared violating range is provably excluded —
					// the heuristic-shape caveat no longer applies.
					claim.Limitations = claim.Limitations[:len(claim.Limitations)-1]
				}
			}
			return claim
		}
	}
	switch {
	case external > 0:
		claim.Result = domain.ClaimTrue
		claim.Explanation = fmt.Sprintf("%d call site(s) receive externally controlled input", external)
	case libraryWitness:
		out := libraryWitnessClaim(cond, c, witness)
		// Keep any provenance caveat recorded before the branch (e.g. a
		// security-relevant transform on another traced site): the positive
		// rests on the witness, but the audit note must not disappear.
		for _, l := range claim.Limitations {
			out.Limitations = appendUnique(out.Limitations, l)
		}
		return out
	case unknown > 0:
		if unresolved := unknown - payloadUnproven; unresolved > 0 {
			claim.Limitations = append(claim.Limitations,
				fmt.Sprintf("%d call site(s) have unresolvable argument origin", unresolved))
		}
		if payloadUnproven > 0 {
			claim.Limitations = append(claim.Limitations,
				fmt.Sprintf("%d externally originated writer-only flow(s); outbound writer capability alone does not establish payload at an unspecified argument index", payloadUnproven))
		}
	case deployDependent > 0:
		allConfig := configFlows == len(flows)
		if allConfig && external == 0 && unknown == 0 && coneInternal == 0 {
			// Configuration provenance is a code fact, not the policy
			// assertion. The post-reach route requires positive exact
			// sink reach, exact ArgIndex binding at every live site, a
			// complete advisory-bound sink closure and an admissible
			// declared config-trust assumption; --trusted-peer is not a
			// substitute.
			post, _ := postReachConfigClaim(cond, c, flows, time.Now())
			return closureGate(c, post, c.EvidenceGraph.IngressClosureFor(cond.ID),
				c.EvidenceGraph.SinkClosureFor(cond.ID), coneInternal, flows)
		}
		if c.Product.TrustedPeer && external == 0 && unknown == 0 {
			// Non-configuration deployment sources (database/internal
			// service) under an explicit peer-trust declaration keep the
			// pre-existing code-level falsifier. Configuration origins
			// never reach this branch: the administrator-trust assertion
			// is admitted only from declared-assumptions/1.
			claim.Result = domain.ClaimFalse
			claim.Falsifier = domain.FalsifierTrustedInfrastructure
			claim.FalsifierBasis = domain.BasisDeclaredTrust
			claim.Explanation = fmt.Sprintf("all %d call site(s) receive config/service-provided input from trusted internal deployment infrastructure (--trusted-peer)", deployDependent)
			claim.NegativeVerification = &domain.NegativeVerification{
				Status: domain.NegativeVerified,
				Notes:  "deployment infrastructure declared trusted peer/service communication (--trusted-peer)",
			}
			return closureGate(c, claim, c.EvidenceGraph.IngressClosureFor(cond.ID),
				c.EvidenceGraph.SinkClosureFor(cond.ID), coneInternal, flows)
		}
		claim.Limitations = append(claim.Limitations,
			fmt.Sprintf("%d call site(s) receive config/service-provided input; attacker control depends on deployment trust boundary — cannot prove non-external", deployDependent))
	default:
		claim.Result = domain.ClaimFalse
		claim.Falsifier = domain.FalsifierConstantOrGeneratedInput
		claim.Explanation = fmt.Sprintf("all %d traced call site(s) receive non-external input", safe)
		claim.Limitations = append(claim.Limitations,
			"FALSE is a candidate: provenance coverage is limited to direct call sites")
	}
	return closureGate(c, claim, c.EvidenceGraph.IngressClosureFor(cond.ID),
		c.EvidenceGraph.SinkClosureFor(cond.ID), coneInternal, flows)
}

// closureGate applies the dependency completeness records to a claim —
// the two negative-verdict strategies the spec allows. The records can
// only weaken a claim: a FALSE candidate survives when EITHER the
// ingress closure is complete with every inventoried item safe, OR the
// sink closure is complete (the declared sink set is enumerable and
// every live site's payload input resolved non-external). Ingress items
// with no recorded path to a subject still require safe origins. Dead
// sink sites are recorded in limitations for auditability.
// Incomplete inventories, unresolved items and unsafe
// sources demote FALSE to UNKNOWN; nothing here promotes a claim.
// coneInternal counts traced sinks inside the module cone whose argument
// provenance was unresolvable — they are absorbed only by a verified
// complete closure; without one they keep the claim UNKNOWN.
func closureGate(c *domain.AnalysisCase, claim domain.Claim, cl *domain.IngressClosure, sc *domain.SinkClosure, coneInternal int, flows []domain.DataFlow) domain.Claim {
	if cl != nil && len(cl.Blockers) > 0 {
		notes := cl.Blockers
		if len(notes) > 5 {
			notes = notes[:5]
		}
		claim.Limitations = append(claim.Limitations, fmt.Sprintf(
			"ingress closure has %d blocker(s): %s",
			len(cl.Blockers), strings.Join(notes, "; ")))
	}
	if sc != nil && len(sc.Blockers) > 0 {
		notes := sc.Blockers
		if len(notes) > 5 {
			notes = notes[:5]
		}
		claim.Limitations = append(claim.Limitations, fmt.Sprintf(
			"sink closure has %d blocker(s): %s",
			len(sc.Blockers), strings.Join(notes, "; ")))
	}
	if claim.Result != domain.ClaimFalse {
		return claim
	}
	// The exact-argument post-reach route has its own closure contract:
	// only a complete advisory-bound sink closure with every live site
	// bound to the exact trigger ArgIndex and traced to configuration may
	// retain the FALSE. Neither ingress items nor direct call-site traces
	// can substitute — configuration provenance is sink- and
	// argument-specific, and a deployment-controlled ingress item
	// (CONFIGURATION/DATABASE/INTERNAL_SERVICE) is not proof that this
	// trigger stayed administrator-managed.
	if claim.Producer == postReachProducer {
		note, ok := postReachStoredClaimValid(c, claim)
		if !ok {
			claim.Result = domain.ClaimUnknown
			claim.Falsifier = ""
			claim.FalsifierBasis = ""
			// A demoted claim no longer rests on the policy assumption:
			// leaving the id behind would let an unfounded claim cite an
			// owner policy as its basis.
			claim.AssumptionIDs = nil
			claim.NegativeVerification = nil
			claim.Limitations = append(claim.Limitations,
				"post-reach configuration falsifier demoted: "+note)
			claim.Explanation += "; post-reach closure no longer supports FALSE: " + note
			return claim
		}
		claim.Limitations = append(claim.Limitations, note)
		return claim
	}
	// Nothing recorded and nothing to absorb: the candidate stands on
	// its direct call-site traces alone (verification decides VERIFIED).
	if cl == nil && sc == nil && coneInternal == 0 {
		return claim
	}
	if note, ok := ingressVerified(cl, coneInternal); ok {
		claim.Limitations = append(claim.Limitations, note)
		if coneInternal > 0 {
			claim.Limitations = append(claim.Limitations, fmt.Sprintf(
				"%d dep-internal sink arg(s) with unresolvable provenance absorbed by the complete ingress closure",
				coneInternal))
		}
		return claim
	}
	if note, ok := sinkVerified(sc, coneInternal); ok {
		claim.Limitations = append(claim.Limitations, note)
		if coneInternal > 0 {
			claim.Limitations = append(claim.Limitations, fmt.Sprintf(
				"%d dep-internal sink arg(s) with unresolvable provenance absorbed by the complete sink closure",
				coneInternal))
		}
		return claim
	}
	if (claim.Falsifier == domain.FalsifierConstantOrGeneratedInput || claim.Falsifier == domain.FalsifierTrustedInfrastructure) && len(flows) > 0 {
		mods := linkedModules(c)
		var direct []domain.DataFlow
		for _, f := range flows {
			if inCaseModules(f.Sink.Package, mods) {
				continue
			}
			if cl != nil && cl.Module != "" && domain.PackageInModule(f.Sink.Package, cl.Module) {
				continue
			}
			if sc != nil && sc.Module != "" && domain.PackageInModule(f.Sink.Package, sc.Module) {
				continue
			}
			direct = append(direct, f)
		}
		if len(direct) > 0 {
			allOk := true
			for _, f := range direct {
				if claim.Falsifier == domain.FalsifierConstantOrGeneratedInput {
					if f.Origin != domain.OriginConstant && f.Origin != domain.OriginGenerated {
						allOk = false
						break
					}
				} else if claim.Falsifier == domain.FalsifierTrustedInfrastructure {
					if f.Origin != domain.OriginConfiguration {
						allOk = false
						break
					}
				}
			}
			if allOk {
				hasUnsafeBoundary := false
				if cl != nil {
					cond := findCondition(c.Exploit, claim.ConditionID)
					for _, it := range cl.Items {
						if it.Kind == domain.IngressBoundaryArg || it.Kind == domain.IngressBoundaryReceiver || it.Kind == domain.IngressObjectState {
							// Receivers or object states that do not reach any vulnerable symbol cannot influence the vulnerability.
							if len(it.Reaches) == 0 && (it.Kind == domain.IngressBoundaryReceiver || it.Kind == domain.IngressObjectState) {
								continue
							}
							// For unmarshaling/decoding functions, arg > 0 is the destination output struct being populated, not the input payload.
							if it.Kind == domain.IngressBoundaryArg && it.Arg > 0 && isPopulateCallee(it.Callee) {
								continue
							}
							// When verifying a receiver-pinned condition (ArgReceiver), boundary arguments
							// to non-constructor methods do not feed the method receiver.
							if cond != nil && cond.ArgIndex == domain.ArgReceiver && it.Kind == domain.IngressBoundaryArg && calleeIsMethod(it.Callee) {
								continue
							}
							// A receiver on a non-subject method cannot influence the vulnerable query AST receiver.
							if cond != nil && cond.ArgIndex == domain.ArgReceiver && it.Kind == domain.IngressBoundaryReceiver && !isSubjectSymbol(it.Callee, cond.Subjects) {
								continue
							}
							if claim.Falsifier == domain.FalsifierConstantOrGeneratedInput && !domain.SafeOrigin(it.Origin) {
								hasUnsafeBoundary = true
								break
							}
							if claim.Falsifier == domain.FalsifierTrustedInfrastructure && it.Origin != domain.OriginConfiguration && !domain.SafeOrigin(it.Origin) {
								hasUnsafeBoundary = true
								break
							}
						}
					}
				}
				if !hasUnsafeBoundary {
					if claim.Falsifier == domain.FalsifierConstantOrGeneratedInput {
						claim.Limitations = append(claim.Limitations, fmt.Sprintf(
							"all %d direct call site(s) receive compile-time constant payload; parser cone operations operate exclusively on immutable input",
							len(direct)))
					} else {
						claim.Limitations = append(claim.Limitations, fmt.Sprintf(
							"all %d direct call site(s) consume local configuration files from host environment (trusted infrastructure)",
							len(direct)))
					}
					return claim
				}
			}
		}
	}
	claim.Result = domain.ClaimUnknown
	claim.Falsifier = ""
	var open []string
	if cl != nil && cl.Complete {
		var unresolved, unsafe int
		for _, it := range cl.Items {
			if domain.SafeOrigin(it.Origin) {
				continue
			}
			if it.Origin == domain.OriginUnknown || it.Origin == "" {
				unresolved++
				if len(open) < 5 {
					open = append(open, ingressItemLabel(it)+" (unresolved origin)")
				}
				continue
			}
			unsafe++
			if len(open) < 5 {
				open = append(open, ingressItemLabel(it)+" ("+string(it.Origin)+")")
			}
		}
		claim.Explanation += fmt.Sprintf(
			"; ingress closure complete but %d item(s) unresolved and %d potentially attacker-reachable: %s",
			unresolved, unsafe, strings.Join(open, "; "))
	} else if cl != nil {
		claim.Explanation += "; ingress closure incomplete — boundary inventory cannot be trusted as closed"
	} else if coneInternal > 0 {
		claim.Explanation += fmt.Sprintf(
			"; %d dep-internal sink arg(s) unresolvable and no closure recorded to absorb them", coneInternal)
	}
	if sc != nil && !sc.Complete {
		claim.Explanation += "; sink closure incomplete — sink-site payload inputs cannot be trusted as closed"
	}
	claim.Limitations = append(claim.Limitations,
		"unresolved dependency inputs remain UNKNOWN: origins could not be proven non-external")
	return claim
}

// ingressVerified reports whether the ingress-closure record confirms
// the FALSE candidate: complete inventory and every item resolved to a
// safe origin. The returned note is the audit line for the claim's limitations.
func ingressVerified(cl *domain.IngressClosure, coneInternal int) (string, bool) {
	if cl == nil || !cl.Complete {
		return "", false
	}
	var unresolved, unsafe int
	var open []string
	for _, it := range cl.Items {
		if domain.SafeOrigin(it.Origin) {
			continue
		}
		if it.Origin == domain.OriginUnknown || it.Origin == "" {
			unresolved++
			if len(open) < 5 {
				open = append(open, ingressItemLabel(it)+" (unresolved origin)")
			}
			continue
		}
		unsafe++
		if len(open) < 5 {
			open = append(open, ingressItemLabel(it)+" ("+string(it.Origin)+")")
		}
	}
	if unresolved+unsafe > 0 {
		return "", false
	}
	return fmt.Sprintf(
		"ingress closure verified complete: all %d inventoried item(s) have safe origins",
		len(cl.Items)), true
}

// sinkVerified reports whether the sink-closure record confirms the
// FALSE candidate: the declared sink set was enumerable and every live
// site's payload input resolved to a non-external origin. Dead sites
// excluded by call-graph evidence are counted for the audit note.
func sinkVerified(sc *domain.SinkClosure, coneInternal int) (string, bool) {
	if sc == nil || !sc.Complete {
		return "", false
	}
	var live, dead int
	config := 0
	for _, s := range sc.Sites {
		if !s.Live {
			dead++
			continue
		}
		live++
		// A complete closure may include configuration-origin positions
		// (a resolved, non-external origin). Such a position grounds the
		// config-origin route — which has its own exact-site contract —
		// but never the constant/generated falsifier this gate serves.
		if s.Origin == domain.OriginConfiguration {
			config++
			continue
		}
		if !domain.SafeOrigin(s.Origin) {
			return "", false
		}
	}
	return fmt.Sprintf(
		"sink closure verified complete: %d live payload position(s) across declared sinks all non-external (%d configuration, %d safe), %d dead site(s) excluded by call-graph evidence; basis: %s",
		live, config, live-config, dead, sc.Basis), true
}

func ingressItemLabel(it domain.IngressItem) string {
	where := it.File
	if where != "" && it.Line > 0 {
		where += ":" + itoa(it.Line)
	}
	label := string(it.Kind) + " " + it.Detail
	if it.Callee != "" {
		label = string(it.Kind) + " " + it.Callee
	}
	if where != "" {
		label += " @" + where
	}
	return label
}

func itoa(n int) string { return strconv.Itoa(n) }

// boundTerm is one disjunct of a declared violating constraint, e.g.
// `prefetchCount < 0` inside "prefetchCount < 0 or prefetchSize < 0".
// arg is the sink-argument position bound by the term — terms bind
// positionally by order of first appearance of their variable.
type boundTerm struct {
	name    string
	op      string // <, <=, >, >=
	val     int64
	hasVal  bool
	arg     int
	rawTerm string
}

var boundTermRe = regexp.MustCompile(`^([A-Za-z_]\w*(?:\.\w+)?)\s*(<=|>=|<|>)\s*(-?\w+)$`)

// parseBound parses a violating-constraint expression into disjunct
// terms: "x < 0 or y > MAX" → [{x < 0}, {y > MAX}]. Literals resolve to
// integers; symbolic right sides (INT32_MAX) stay flagged hasVal=false.
// Unparseable terms are returned as leftovers, not silently dropped.
func parseBound(bound string) (terms []boundTerm, leftovers []string) {
	norm := strings.NewReplacer("||", " or ", " or ", ",", " && ", ",", " and ", ",").Replace(bound)
	var argNames []string
	for _, piece := range strings.Split(norm, ",") {
		piece = strings.TrimSpace(piece)
		if piece == "" {
			continue
		}
		m := boundTermRe.FindStringSubmatch(piece)
		if m == nil {
			leftovers = append(leftovers, piece)
			continue
		}
		t := boundTerm{name: m[1], op: m[2], rawTerm: piece}
		if v, err := strconv.ParseInt(m[3], 0, 64); err == nil {
			t.val, t.hasVal = v, true
		}
		// Positional binding: first appearance order → arg index.
		idx := -1
		for i, n := range argNames {
			if n == t.name {
				idx = i
			}
		}
		if idx < 0 {
			argNames = append(argNames, t.name)
			idx = len(argNames) - 1
		}
		t.arg = idx
		terms = append(terms, t)
	}
	return terms, leftovers
}

// satisfies reports whether value v satisfies the violating term
// (`v < K` is satisfied when v is below K).
func (t boundTerm) satisfies(v int64) bool {
	if !t.hasVal {
		return false
	}
	switch t.op {
	case "<":
		return v < t.val
	case "<=":
		return v <= t.val
	case ">":
		return v > t.val
	case ">=":
		return v >= t.val
	}
	return false
}

// falsifiedBy reports whether a guard's enforced range [lo,hi] excludes
// every value satisfying the term.
func (t boundTerm) falsifiedBy(lo, hi *int64) bool {
	if !t.hasVal {
		return false
	}
	switch t.op {
	case "<":
		return lo != nil && *lo >= t.val
	case "<=":
		return lo != nil && *lo > t.val
	case ">":
		return hi != nil && *hi <= t.val
	case ">=":
		return hi != nil && *hi < t.val
	}
	return false
}

// coveringGuards collects the non-conditional guard validations covering
// flow f's sink.
func coveringGuards(c *domain.AnalysisCase, f domain.DataFlow) []domain.Validation {
	var out []domain.Validation
	for _, v := range c.EvidenceGraph.Validations {
		if !v.Guard || v.Conditional {
			continue
		}
		if v.Arg >= 0 && f.Arg >= 0 && v.Arg != f.Arg {
			continue
		}
		if v.Covers != nil && v.Covers.File == f.Sink.File && v.Covers.Line == f.Sink.Line {
			out = append(out, v)
			continue
		}
		if v.Covers == nil && v.File == f.Sink.File && v.Line > 0 && f.Sink.Line > 0 && v.Line < f.Sink.Line {
			out = append(out, v)
		}
	}
	return out
}

// verifyBound checks the condition's declared violating constraint
// against the bounds the covering guards enforce. Every disjunct must be
// contradicted by a recorded range — a guard whose Property names the
// term's variable, or (when nothing names it) every mutable arg's cover.
// Returns "" when no bound is declared, else a note: "bound verified"
// when all terms are excluded, or a limitation describing the gap.
// The bound is a deterministic condition annotation: model proposals keep
// their params on ExploitModel.ProposedConditions and never reach here, so
// a model-supplied bound cannot change the evaluated truth.
func verifyBound(cond domain.Condition, c *domain.AnalysisCase, flows []domain.DataFlow) string {
	bound := cond.Params[domain.ParamBound]
	if bound == "" {
		return ""
	}
	terms, leftovers := parseBound(bound)
	if len(leftovers) > 0 {
		return fmt.Sprintf("bound %q partially unparseable: %s", bound, strings.Join(leftovers, "; "))
	}
	if len(terms) == 0 {
		return fmt.Sprintf("bound %q unparseable — not machine-verified", bound)
	}
	var unverified []string
	for _, t := range terms {
		if !t.hasVal {
			unverified = append(unverified, t.rawTerm+" (non-literal bound)")
			continue
		}
		falsified := false
		// Prefer a guard whose Property names the term's variable — the
		// dep's parameter names and the product's field names usually
		// coincide on the wire. Name-matched guards are collected across
		// all conditions (coverage is a fact about the field, not about
		// which condition traced it) but must still sit on a traced sink's
		// file/region. Positional binding is the fallback.
		var named, positional []domain.Validation
		for _, v := range c.EvidenceGraph.Validations {
			if !v.Guard || v.Conditional || (v.BoundLow == nil && v.BoundHigh == nil) {
				continue
			}
			if !strings.Contains(v.Property, t.name) {
				continue
			}
			for _, f := range flows {
				if (v.Covers != nil && v.Covers.File == f.Sink.File && v.Covers.Line == f.Sink.Line) ||
					(v.Covers == nil && v.File == f.Sink.File && v.Line > 0 && f.Sink.Line > 0 && v.Line < f.Sink.Line) {
					named = append(named, v)
					break
				}
			}
		}
		for _, f := range flows {
			if f.Origin == domain.OriginConstant || f.Origin == domain.OriginGenerated {
				continue
			}
			if f.Arg != t.arg {
				continue
			}
			for _, g := range coveringGuards(c, f) {
				if g.BoundLow != nil || g.BoundHigh != nil {
					positional = append(positional, g)
				}
			}
		}
		for _, pool := range [][]domain.Validation{named, positional} {
			for _, g := range pool {
				if t.falsifiedBy(g.BoundLow, g.BoundHigh) {
					falsified = true
					break
				}
			}
			if falsified {
				break
			}
		}
		if !falsified {
			unverified = append(unverified, t.rawTerm)
		}
	}
	if len(unverified) > 0 {
		return fmt.Sprintf("bound %q not fully falsified by recorded clamp ranges: %s",
			bound, strings.Join(unverified, "; "))
	}
	return fmt.Sprintf("bound verified: every disjunct of %q is excluded by recorded clamp ranges", bound)
}

// constViolatesBound reports a violation when a constant sink argument's
// resolved value satisfies one of the bound's disjunct terms — the
// constraint is then deterministically satisfiable, not falsified. Only the
// authoritative condition carries a bound here; a model proposal never
// populates it.
func constViolatesBound(cond domain.Condition, flows []domain.DataFlow) string {
	terms, leftovers := parseBound(cond.Params[domain.ParamBound])
	if len(leftovers) > 0 || len(terms) == 0 {
		return ""
	}
	byArg := map[int][]boundTerm{}
	for _, t := range terms {
		byArg[t.arg] = append(byArg[t.arg], t)
	}
	for _, f := range flows {
		if f.Value == nil || f.Arg < 0 {
			continue
		}
		for _, t := range byArg[f.Arg] {
			if t.satisfies(*f.Value) {
				return fmt.Sprintf("constant arg%d=%d at %s:%d satisfies violating bound %q",
					f.Arg, *f.Value, f.Sink.File, f.Sink.Line, t.rawTerm)
			}
		}
	}
	return ""
}

func flowsFor(c *domain.AnalysisCase, id domain.ConditionID) []domain.DataFlow {
	var out []domain.DataFlow
	for _, f := range c.EvidenceGraph.DataFlows {
		if f.ConditionID == id {
			out = append(out, f)
		}
	}
	return out
}

// guardCovers reports whether a genuine, unconditional guard covers the
// sink — a caller-frame Covers record or a same-file guard before the
// call. Origin records (Guard=false) and conditional guards do not count.
func guardCovers(vals []domain.Validation, sink domain.CallSite, arg int) bool {
	for _, v := range vals {
		if !v.Guard || v.Conditional {
			continue
		}
		if v.Arg >= 0 && arg >= 0 && v.Arg != arg {
			continue
		}
		if v.Covers != nil && v.Covers.File == sink.File && v.Covers.Line == sink.Line {
			return true
		}
		if v.Covers == nil && v.File == sink.File && v.Line > 0 && sink.Line > 0 && v.Line < sink.Line {
			return true
		}
	}
	return false
}

func isPopulateCallee(callee string) bool {
	parts := strings.Split(callee, ".")
	name := parts[len(parts)-1]
	switch name {
	case "Unmarshal", "Decode", "DecodeElement", "UnmarshalStrict", "UnmarshalExact", "DecodeValues", "Read":
		return true
	default:
		return false
	}
}

// findCondition resolves a condition from the authoritative model buckets
// only. ProposedConditions are non-authoritative nominations and are
// deliberately invisible to evaluation.
func findCondition(m *domain.ExploitModel, id domain.ConditionID) *domain.Condition {
	if m == nil {
		return nil
	}
	for i := range m.MandatoryConditions {
		if m.MandatoryConditions[i].ID == id {
			return &m.MandatoryConditions[i]
		}
	}
	for i := range m.SupportingFactors {
		if m.SupportingFactors[i].ID == id {
			return &m.SupportingFactors[i]
		}
	}
	return nil
}

func calleeIsMethod(callee string) bool {
	name := callee
	if idx := strings.LastIndex(callee, "/"); idx >= 0 {
		name = callee[idx+1:]
	}
	return strings.Count(name, ".") >= 2
}

func isSubjectSymbol(callee string, subjects []domain.SymbolRef) bool {
	for _, s := range subjects {
		key := s.Package + "." + s.Symbol
		if callee == key {
			return true
		}
	}
	return false
}

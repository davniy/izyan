package verify

import (
	"sort"

	"github.com/davniy/izyan/internal/productb/claimshape"
	triage "github.com/davniy/izyan/internal/productb/triage"
)

// Node kinds of the entailment graph (plan §5.2).
const (
	NodeClaim       = "claim"
	NodeObservation = "observation"
	NodeDerivedFact = "derived_fact"
	NodeProof       = "proof"
	NodeRule        = "rule"
	NodeDecision    = "decision"
)

// GraphNode is one entailment-graph node: a claim, an admitted
// observation, a derived fact (a mandatory condition), a proof
// certificate, a decision rule or the compiled decision.
type GraphNode struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"`
	Value string `json:"value,omitempty"`
}

// GraphCondition is a mandatory exploit condition materialized as a
// derived-fact node. Mandatory records how the condition's authority was
// established: "advisory" when the condition came from the deterministic
// advisory data, "proof" when a checker-verified certificate binds the
// mandatory flag, "unresolved" when no deterministic source vouches for
// it — an unresolved condition can never ground DISMISSED.
type GraphCondition struct {
	ID               string               `json:"id"`
	Shapes           []claimshape.Shape   `json:"shapes,omitempty"`
	ExpectedSubjects []claimshape.Subject `json:"expected_subjects,omitempty"`
	FalsifiedBy      PredicateOutcome     `json:"falsified_by"`
	Mandatory        string               `json:"mandatory"`
	Value            string               `json:"value"` // FALSE | UNKNOWN
	Sources          []string             `json:"sources,omitempty"`
	Falsifiers       []string             `json:"falsifiers,omitempty"`
	// Contested records falsifier candidates blocked by contradictory
	// evidence in their own context (plan §6.4: a conflict is never
	// resolved by taking the verifying side).
	Contested []string `json:"contested,omitempty"`
	Reason    string   `json:"reason,omitempty"`
}

// RuleEval is one decision rule's deterministic evaluation: which rule,
// whether it fired, the premises it consumed and why not.
type RuleEval struct {
	ID        string   `json:"id"`
	Outcome   string   `json:"outcome"`
	Satisfied bool     `json:"satisfied"`
	Premises  []string `json:"premises,omitempty"`
	Reason    string   `json:"reason,omitempty"`
}

// Decision is the compiled triage disposition of the run: DISMISSED only
// through an admitted falsifier of a mandatory condition, LOWERED only
// through the generic mitigation/perimeter rule on deterministic facts,
// UNCHANGED in every other case. The LLM verdict and the mere presence
// of proposals are not inputs — the compiler reads the graph only.
type Decision struct {
	Disposition string   `json:"disposition"` // DISMISSED | LOWERED | UNCHANGED
	Rule        string   `json:"rule,omitempty"`
	Reason      string   `json:"reason,omitempty"`
	Premises    []string `json:"premises,omitempty"`
}

// Graph is the persisted entailment graph of one run: nodes, the
// derived-fact conditions, rule evaluations and the decision node.
// Report.Edges carries every edge in the flat vocabulary.
type Graph struct {
	Nodes      []GraphNode      `json:"nodes,omitempty"`
	Conditions []GraphCondition `json:"conditions,omitempty"`
	Rules      []RuleEval       `json:"rules,omitempty"`
	Decision   Decision         `json:"decision"`
}

// DecisionRulesetVersion identifies the compiled decision-rule set —
// replay stability compares it like any other ruleset pin.
const DecisionRulesetVersion = "decision-rules.v1"

const (
	ruleMandatoryFalsifier = "mandatory_condition_false"
	ruleClosedPerimeter    = "closed_perimeter_lowering"
)

// graphOut is buildGraph's product: the graph itself plus the derived
// edges it contributes to the report edge set.
type graphOut struct {
	Graph        *Graph
	derivedEdges []Edge
}

// condState is a condition under construction.
type condState struct {
	id        string
	shapes    map[claimshape.Shape]bool
	expected  []claimshape.Subject
	mandatory string
	sources   map[string]bool
	proofs    []string
}

// buildGraph materializes the entailment graph over the claim
// evaluations: claim and observation nodes, mandatory conditions as
// derived-fact nodes, the generic decision rules and the compiled
// decision. Everything is a pure function of the input — no LLM verdict,
// no proposal presence, no prose enters.
func buildGraph(ctx *evalContext, in Input, claims []claimshape.CanonicalClaim, evals []claimEvalOut) graphOut {
	g := &Graph{Decision: Decision{Disposition: "UNCHANGED", Reason: "no rule satisfied"}}
	out := graphOut{Graph: g}
	nodes := map[string]GraphNode{}
	addNode := func(n GraphNode) {
		if _, ok := nodes[n.ID]; !ok {
			nodes[n.ID] = n
		}
	}
	claimByID := map[string]claimshape.CanonicalClaim{}
	for i, ev := range evals {
		claimByID[ev.ClaimID] = claims[i]
		addNode(GraphNode{ID: "claim:" + ev.ClaimID, Kind: NodeClaim, Value: string(ev.Outcome)})
		for j := range ev.boundObs {
			obs := &ev.boundObs[j]
			addNode(GraphNode{ID: "obs:" + obs.ID, Kind: NodeObservation, Value: string(obs.Result)})
		}
		for _, pid := range ev.admittedCerts {
			addNode(GraphNode{ID: "proof:" + proofIDOf(pid), Kind: NodeProof, Value: "admitted"})
		}
	}

	conds := buildConditions(ctx, in, claims)
	keys := make([]string, 0, len(conds))
	for k := range conds {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// §6.4 contest resolution: a falsifier never stands while admitted
	// evidence in its own provenance context establishes the opposite
	// value or a conflict on a covering claim of the same predicate —
	// and never while a same-context contradicting certificate binds
	// the same condition. Conflicts are recorded, never voted away.
	falsifierContexts := func(ev claimEvalOut, cond GraphCondition) map[string]bool {
		want := "holds"
		if cond.FalsifiedBy == PredicateDisproved {
			want = "disproved"
		}
		keys := map[string]bool{}
		for _, g := range ev.Groups {
			if g.Established == want {
				keys[g.Key] = true
			}
		}
		return keys
	}
	// contradictsAt reports whether a claim other than self covering the
	// condition established the opposite value or an unresolved conflict
	// in context k. "none"/"context_excluded" groups carry no
	// adjudication and never contest.
	contradictsAt := func(self claimEvalOut, cond GraphCondition, k string) bool {
		opposite := "disproved"
		if cond.FalsifiedBy == PredicateDisproved {
			opposite = "holds"
		}
		for _, other := range evals {
			if other.ClaimID == self.ClaimID || !hasShape(cond.Shapes, other.Shape) {
				continue
			}
			if !claimCoversCondition(other, claimByID[other.ClaimID], cond) {
				continue
			}
			for _, g := range other.Groups {
				if g.Key == k && (g.Established == opposite || g.Established == "conflicting") {
					return true
				}
			}
		}
		return false
	}
	// certContestedAt reports whether admitted evidence contests a
	// certificate's falsification inside the certificate's own
	// provenance context: a covering claim establishing the opposite
	// value/conflict there, or a clean same-context certificate whose
	// result contradicts this one while binding the same condition.
	certContestedAt := func(ce *certEval, cond GraphCondition, condID string) bool {
		key := ce.obs.SnapshotHash + "\x00" + ce.obs.BuildContextHash
		for _, other := range evals {
			if !hasShape(cond.Shapes, other.Shape) {
				continue
			}
			if !claimCoversCondition(other, claimByID[other.ClaimID], cond) {
				continue
			}
			opposite := "disproved"
			if cond.FalsifiedBy == PredicateDisproved {
				opposite = "holds"
			}
			for _, g := range other.Groups {
				if g.Key == key && (g.Established == opposite || g.Established == "conflicting") {
					return true
				}
			}
		}
		for _, ce2 := range ctx.certs {
			if ce2.proof.ID == ce.proof.ID || len(ce2.violations) != 0 {
				continue
			}
			if ce2.obs.Result != ResultRefutes {
				continue
			}
			if ce2.obs.SnapshotHash+"\x00"+ce2.obs.BuildContextHash != key {
				continue
			}
			bound := ce2.proof.ConditionID == condID ||
				(len(cond.ExpectedSubjects) > 0 &&
					coversAllSubjects(append(checkedSubjects(ce2.proof), condSubjects(ce2.proof)...), cond.ExpectedSubjects))
			if bound {
				return true
			}
		}
		return false
	}

	for _, k := range keys {
		cs := conds[k]
		cond := GraphCondition{
			ID:          cs.id,
			Mandatory:   cs.mandatory,
			Value:       "UNKNOWN",
			FalsifiedBy: PredicateHolds,
		}
		for s := range cs.shapes {
			cond.Shapes = append(cond.Shapes, s)
		}
		sort.Slice(cond.Shapes, func(i, j int) bool { return cond.Shapes[i] < cond.Shapes[j] })
		cond.ExpectedSubjects = append([]claimshape.Subject(nil), cs.expected...)
		for s := range cs.sources {
			cond.Sources = append(cond.Sources, s)
		}
		sort.Strings(cond.Sources)
		// Applicability conditions are disproved rather than absent:
		// the predicate's DISPROVED value is the falsifier.
		if hasShape(cond.Shapes, claimshape.ShapeApplicabilityVersionInRange) &&
			!hasShape(cond.Shapes, claimshape.ShapeSubjectAbsent) &&
			!hasShape(cond.Shapes, claimshape.ShapePathUnreachable) {
			cond.FalsifiedBy = PredicateDisproved
		}

		nodeID := "condition:" + cond.ID
		if cond.Mandatory == "unresolved" {
			cond.Reason = "mandatory status unresolved by any deterministic source"
		}
		// Claim falsifiers: an admitted claim of a required shape that
		// covers the condition's subject universe falsifies it — unless
		// contradictory evidence contests the falsification inside the
		// same provenance context (§6.4: conflicts never vote).
		for _, ev := range evals {
			if !hasShape(cond.Shapes, ev.Shape) {
				continue
			}
			if ev.Predicate != cond.FalsifiedBy {
				continue
			}
			if !claimCoversCondition(ev, claimByID[ev.ClaimID], cond) {
				continue
			}
			if cond.Mandatory == "unresolved" {
				continue // unproven mandatory status never falsifies
			}
			contested := false
			for key := range falsifierContexts(ev, cond) {
				if contradictsAt(ev, cond, key) {
					contested = true
					break
				}
			}
			if contested {
				cond.Contested = append(cond.Contested, "claim:"+ev.ClaimID)
				continue
			}
			cond.Falsifiers = append(cond.Falsifiers, "claim:"+ev.ClaimID)
			out.derivedEdges = append(out.derivedEdges, Edge{Kind: "derived_from", From: nodeID, To: "claim:" + ev.ClaimID})
		}
		// Certificate falsifiers: a checker-verified mandatory proof
		// bound to this condition whose coverage closes it — and which
		// no admitted contradiction in its own context contests. The
		// binding is the declared condition id, or the proof's coverage
		// closing the condition's named expected universe — never the
		// presence of a proposal. An empty universe is not closed by
		// coverage: the proof must name the condition explicitly.
		for _, ce := range ctx.certs {
			if len(ce.violations) != 0 {
				continue
			}
			if ce.proof.Status != triage.FalsifierVerified || !ce.proof.Mandatory {
				continue
			}
			if !hasShape(cond.Shapes, ce.shape) {
				continue // a certificate falsifies only its own predicate
			}
			bound := ce.proof.ConditionID == cond.ID ||
				(len(cond.ExpectedSubjects) > 0 &&
					coversAllSubjects(append(checkedSubjects(ce.proof), condSubjects(ce.proof)...), cond.ExpectedSubjects))
			if !bound {
				continue
			}
			if certContestedAt(ce, cond, cond.ID) {
				cond.Contested = append(cond.Contested, "proof:"+ce.proof.ID)
				continue
			}
			cond.Falsifiers = append(cond.Falsifiers, "proof:"+ce.proof.ID)
			out.derivedEdges = append(out.derivedEdges, Edge{Kind: "derived_from", From: nodeID, To: "proof:" + ce.proof.ID})
		}
		// depends_on records the candidates that could not falsify —
		// the premise space the condition waited on.
		for _, ev := range evals {
			if !hasShape(cond.Shapes, ev.Shape) {
				continue
			}
			out.derivedEdges = append(out.derivedEdges, Edge{Kind: "depends_on", From: nodeID, To: "claim:" + ev.ClaimID})
		}

		sort.Strings(cond.Falsifiers)
		sort.Strings(cond.Contested)
		if len(cond.Falsifiers) > 0 {
			cond.Value = "FALSE"
			if cond.Reason == "" {
				cond.Reason = "mandatory condition falsified by admitted negative verification"
			}
		} else if len(cond.Contested) > 0 && cond.Reason == "" {
			cond.Reason = "falsifier contested by contradictory evidence in its context"
		}
		addNode(GraphNode{ID: nodeID, Kind: NodeDerivedFact, Value: cond.Value})
		g.Conditions = append(g.Conditions, cond)
	}

	// ---- decision rules ----
	var falsifiedConds []string
	for _, c := range g.Conditions {
		if c.Value == "FALSE" {
			falsifiedConds = append(falsifiedConds, "condition:"+c.ID)
		}
	}
	sort.Strings(falsifiedConds)

	dismiss := RuleEval{ID: ruleMandatoryFalsifier, Outcome: "DISMISSED", Premises: falsifiedConds}
	switch {
	case len(g.Conditions) == 0:
		dismiss.Reason = "no mandatory condition resolved"
	case len(falsifiedConds) == 0:
		dismiss.Reason = "no mandatory condition falsified"
	default:
		dismiss.Satisfied = true
		dismiss.Reason = "mandatory condition FALSE via admitted falsifier"
	}
	ruleNodeID := "rule:" + dismiss.ID
	for _, p := range dismiss.Premises {
		out.derivedEdges = append(out.derivedEdges, Edge{Kind: "derived_from", From: ruleNodeID, To: p})
	}
	addNode(GraphNode{ID: ruleNodeID, Kind: NodeRule, Value: outcomeStr(dismiss.Satisfied)})

	lower := RuleEval{ID: ruleClosedPerimeter, Outcome: "LOWERED"}
	var applicabilityOK, perimeterOK bool
	for _, ev := range evals {
		switch {
		case ev.Shape == claimshape.ShapeApplicabilityVersionInRange && ev.Predicate == PredicateHolds:
			applicabilityOK = true
			lower.Premises = append(lower.Premises, "claim:"+ev.ClaimID)
		case ev.Shape == claimshape.ShapePerimeterExposure && ev.Predicate == PredicateDisproved:
			perimeterOK = true
			lower.Premises = append(lower.Premises, "claim:"+ev.ClaimID)
		}
	}
	switch {
	case !applicabilityOK:
		lower.Reason = "premise_missing:applicability_holds"
	case !perimeterOK:
		lower.Reason = "premise_missing:perimeter_disproved"
	default:
		lower.Satisfied = true
		lower.Reason = "affected build behind a proven closed perimeter"
	}
	sort.Strings(lower.Premises)
	lowerNodeID := "rule:" + lower.ID
	for _, p := range lower.Premises {
		out.derivedEdges = append(out.derivedEdges, Edge{Kind: "derived_from", From: lowerNodeID, To: p})
	}
	addNode(GraphNode{ID: lowerNodeID, Kind: NodeRule, Value: outcomeStr(lower.Satisfied)})

	// ---- decision node ----
	g.Rules = []RuleEval{dismiss, lower}
	switch {
	case dismiss.Satisfied:
		g.Decision = Decision{Disposition: "DISMISSED", Rule: dismiss.ID, Reason: dismiss.Reason, Premises: dismiss.Premises}
	case lower.Satisfied:
		g.Decision = Decision{Disposition: "LOWERED", Rule: lower.ID, Reason: lower.Reason, Premises: lower.Premises}
	default:
		g.Decision = Decision{Disposition: "UNCHANGED", Reason: "no rule satisfied"}
	}
	decisionNodeID := "decision:" + in.FindingID
	addNode(GraphNode{ID: decisionNodeID, Kind: NodeDecision, Value: g.Decision.Disposition})
	for _, r := range g.Rules {
		if r.Satisfied {
			out.derivedEdges = append(out.derivedEdges, Edge{Kind: "derived_from", From: decisionNodeID, To: "rule:" + r.ID})
		}
	}

	g.Nodes = make([]GraphNode, 0, len(nodes))
	for _, n := range nodes {
		g.Nodes = append(g.Nodes, n)
	}
	sort.Slice(g.Nodes, func(i, j int) bool { return g.Nodes[i].ID < g.Nodes[j].ID })
	return out
}

// outcomeStr renders the fired flag deterministically.
func outcomeStr(fired bool) string {
	if fired {
		return "satisfied"
	}
	return "unsatisfied"
}

// buildConditions materializes the mandatory exploit conditions the run
// may falsify, from deterministic sources only: the advisory's declared
// data (locus symbols, module presence, affected ranges), the proof
// certificates' own bindings and the proposals claims carried.
func buildConditions(ctx *evalContext, in Input, claims []claimshape.CanonicalClaim) map[string]*condState {
	conds := map[string]*condState{}
	get := func(id string) *condState {
		cs := conds[id]
		if cs == nil {
			cs = &condState{id: id, shapes: map[claimshape.Shape]bool{}, sources: map[string]bool{}, mandatory: "unresolved"}
			conds[id] = cs
		}
		return cs
	}
	advisoryID := in.Advisory.ResolvedID
	if advisoryID == "" && len(in.Advisory.IDs) > 0 {
		advisoryID = in.Advisory.IDs[0]
	}
	// The advisory's declared affected symbols name the defect locus:
	// absence or unreachability of that set falsifies its presence.
	if len(in.Advisory.AffectedSymbols) > 0 {
		id := "cond-advisory-locus"
		if advisoryID != "" {
			id = triage.AdvisoryConditionID(advisoryID)
		}
		cs := get(id)
		cs.shapes[claimshape.ShapeSubjectAbsent] = true
		cs.shapes[claimshape.ShapePathUnreachable] = true
		cs.expected = unionSubjects(cs.expected, in.Advisory.AffectedSymbols)
		cs.mandatory = "advisory"
		cs.sources["advisory"] = true
	}
	// Module presence is mandatory: the vulnerable module absent from
	// the closed dependency graph cannot execute.
	if in.Advisory.Module != "" {
		cs := get("cond-module-present:" + in.Advisory.Module)
		cs.shapes[claimshape.ShapeSubjectAbsent] = true
		cs.expected = unionSubjects(cs.expected, []claimshape.Subject{{Kind: claimshape.SubjectModule, Name: in.Advisory.Module}})
		cs.mandatory = "advisory"
		cs.sources["advisory"] = true
	}
	// Version applicability is mandatory: a resolved version outside
	// every affected range falsifies applicability.
	if len(in.Advisory.AffectedRanges) > 0 {
		id := "cond-advisory-applicability"
		if advisoryID != "" {
			id = "cond-applicability-" + advisoryID
		}
		cs := get(id)
		cs.shapes[claimshape.ShapeApplicabilityVersionInRange] = true
		cs.mandatory = "advisory"
		cs.sources["advisory"] = true
	}
	// Proof certificates bind their own condition — a checker-verified
	// mandatory proof is its own authority on the mandatory flag.
	for _, ce := range ctx.certs {
		id := ce.proof.ConditionID
		if id == "" {
			id = "cond-proof-" + ce.proof.ID
		}
		cs := get(id)
		if ce.shape != claimshape.ShapeUnsupported {
			cs.shapes[ce.shape] = true
		}
		cs.expected = unionSubjects(cs.expected, condSubjects(ce.proof))
		cs.sources["proof:"+ce.proof.ID] = true
		cs.proofs = append(cs.proofs, ce.proof.ID)
	}
	// Claim-bound proposals declare conditions too; whether the proposal
	// names a mandatory condition is decided by deterministic authority,
	// never by the proposal's own text: the advisory anchor (proposal
	// subjects covering the authoritative affected set) or a mandatory
	// proof bound to the same condition.
	for _, c := range claims {
		for _, bp := range boundProposals(c) {
			if bp.ConditionID == "" {
				continue
			}
			cs := get(bp.ConditionID)
			if bp.CheckShape != claimshape.ShapeUnsupported && bp.CheckShape != "" {
				cs.shapes[bp.CheckShape] = true
			}
			cs.sources["proposal:"+bp.ID] = true
		}
	}
	// Mandatory resolution, second pass: a condition is mandatory when a
	// deterministic source established it — the advisory anchor or a
	// checker-verified certificate carrying the mandatory flag.
	advisorySymbols := in.Advisory.AffectedSymbols
	for _, cs := range conds {
		if cs.mandatory == "advisory" {
			continue
		}
		if len(advisorySymbols) > 0 && len(cs.expected) > 0 && coversAllSubjects(cs.expected, advisorySymbols) {
			cs.mandatory = "advisory"
			cs.sources["advisory"] = true
			continue
		}
		for _, pid := range cs.proofs {
			for _, ce := range ctx.certs {
				if ce.proof.ID == pid && ce.proof.Mandatory && len(ce.violations) == 0 &&
					ce.proof.Status == triage.FalsifierVerified {
					cs.mandatory = "proof"
				}
			}
		}
	}
	return conds
}

// claimCoversCondition reports whether a claim's established coverage
// spans the condition's expected subjects: the claim's own subject, its
// parameter subjects and the subjects its admitted observations checked.
// An empty expected set is covered vacuously — subject-less conditions
// (applicability) bind on shape alone.
func claimCoversCondition(ev claimEvalOut, c claimshape.CanonicalClaim, cond GraphCondition) bool {
	if len(cond.ExpectedSubjects) == 0 {
		return true
	}
	pool := append([]claimshape.Subject{c.Subject}, paramSubjects(c, "subjects")...)
	pool = append(pool, ev.admittedCovered...)
	return coversAllSubjects(pool, cond.ExpectedSubjects)
}

// coversAllSubjects reports whether every expected subject is matched by
// the pool — subjectMatches carries the canonical identity rules.
func coversAllSubjects(pool, expected []claimshape.Subject) bool {
	for _, e := range expected {
		found := false
		for _, p := range pool {
			if subjectMatches(e, p) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// condSubjects renders the certificate's expected subject set.
func condSubjects(p triage.FalsifierProof) []claimshape.Subject {
	var out []claimshape.Subject
	for _, s := range p.Coverage.ExpectedSubjects {
		out = append(out, falsifierSubject(s))
	}
	return out
}

// hasShape reports whether the shape set contains s.
func hasShape(shapes []claimshape.Shape, s claimshape.Shape) bool {
	for _, x := range shapes {
		if x == s {
			return true
		}
	}
	return false
}

// checkedSubjects renders the certificate's checked subject set.
func checkedSubjects(p triage.FalsifierProof) []claimshape.Subject {
	var out []claimshape.Subject
	for _, s := range p.Coverage.CheckedSubjects {
		out = append(out, falsifierSubject(s))
	}
	return out
}

// unionSubjects merges two subject sets under the canonical subject key.
func unionSubjects(a, b []claimshape.Subject) []claimshape.Subject {
	seen := map[string]bool{}
	var out []claimshape.Subject
	for _, s := range append(append([]claimshape.Subject(nil), a...), b...) {
		k := subjectKey(s)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return subjectKey(out[i]) < subjectKey(out[j]) })
	return out
}

// proofIDOf strips the per-claim suffix a bound certificate observation
// carries ("proof:<id>#<claim>") back to the proof id.
func proofIDOf(obsID string) string {
	s := obsID[len("proof:"):]
	for i, r := range s {
		if r == '#' {
			return s[:i]
		}
	}
	return s
}

// familyShapes maps a claimshape signal family (premise_families
// parameter) onto the canonical shapes it can produce — the premise set
// a derived.mandatory_condition claim conjoins.
func familyShapes(fam string) []claimshape.Shape {
	switch fam {
	case "subject":
		return []claimshape.Shape{claimshape.ShapeSubjectDeclared, claimshape.ShapeSubjectAbsent}
	case "path":
		return []claimshape.Shape{claimshape.ShapePathReachable, claimshape.ShapePathUnreachable}
	case "control":
		return []claimshape.Shape{claimshape.ShapeControlPresent, claimshape.ShapeControlAbsent}
	case "input":
		return []claimshape.Shape{claimshape.ShapeInputOrigin, claimshape.ShapeInputAttackerControlled}
	case "configuration":
		return []claimshape.Shape{claimshape.ShapeConfigurationPredicate}
	case "environment":
		return []claimshape.Shape{claimshape.ShapeEnvironmentBuildGate}
	case "perimeter":
		return []claimshape.Shape{claimshape.ShapePerimeterExposure}
	case "closure":
		return []claimshape.Shape{claimshape.ShapeClosureComplete}
	}
	return nil
}

// deriveClaimOutcome computes the outcome of derived.* claims after the
// graph exists: a derived.mandatory_condition is the conjunction of its
// premise claims (any FALSE → FALSE, any CONFLICTING → CONFLICTING, all
// TRUE → TRUE, otherwise UNKNOWN); a derived.triage_disposition reads
// the compiled decision (reduction → TRUE, UNCHANGED → FALSE).
// Non-derived claims keep their evaluated outcome untouched. The
// depends_on edges the derivation emits are returned for the report.
func deriveClaimOutcome(c claimshape.CanonicalClaim, ev ClaimEval, evals []claimEvalOut, claims map[string]claimshape.CanonicalClaim, g *Graph) (ClaimEval, []Edge) {
	switch c.Shape {
	case claimshape.ShapeDerivedMandatoryCondition:
		premises := derivedPremises(c, evals, claims)
		var edges []Edge
		for _, p := range premises {
			edges = append(edges, Edge{Kind: "depends_on", From: "claim:" + c.ID, To: "claim:" + p.ClaimID})
		}
		if len(premises) == 0 {
			ev.Outcome, ev.Predicate, ev.Reason = OutcomeUnknown, PredicateUnknown, "derived:no_premise_claims"
			return ev, edges
		}
		anyFalse, anyConflict, allTrue := false, false, true
		for _, p := range premises {
			switch p.Outcome {
			case OutcomeFalse:
				anyFalse = true
				allTrue = false
			case OutcomeConflicting:
				anyConflict = true
				allTrue = false
			case OutcomeTrue:
			default:
				allTrue = false
			}
		}
		switch {
		case anyFalse:
			ev.Outcome, ev.Predicate = OutcomeFalse, PredicateDisproved
			ev.Reason = "derived:premise_false"
		case anyConflict:
			ev.Outcome, ev.Predicate = OutcomeConflicting, PredicateConflicting
			ev.Reason = "derived:premise_conflicting"
		case allTrue:
			ev.Outcome, ev.Predicate = OutcomeTrue, PredicateHolds
			ev.Reason = "derived:all_premises_true"
		default:
			ev.Outcome, ev.Predicate = OutcomeUnknown, PredicateUnknown
			ev.Reason = "derived:premises_undecided"
		}
		return ev, edges
	case claimshape.ShapeDerivedTriageDisposition:
		if g.Decision.Disposition == "UNCHANGED" {
			ev.Outcome, ev.Predicate = OutcomeFalse, PredicateDisproved
		} else {
			ev.Outcome, ev.Predicate = OutcomeTrue, PredicateHolds
		}
		ev.Reason = "derived:disposition:" + g.Decision.Disposition
		return ev, nil
	}
	return ev, nil
}

// derivedPremises resolves the premise claims of a derived mandatory
// condition: claims of this run whose shape belongs to a declared
// premise family, restricted to overlapping subjects when the derived
// claim names one — subject-less derived claims take every family claim.
func derivedPremises(c claimshape.CanonicalClaim, evals []claimEvalOut, claims map[string]claimshape.CanonicalClaim) []claimEvalOut {
	var fams []string
	switch v := c.Parameters["premise_families"].(type) {
	case []string:
		fams = v
	case []any:
		for _, x := range v {
			if s, ok := x.(string); ok {
				fams = append(fams, s)
			}
		}
	}
	shapes := map[claimshape.Shape]bool{}
	for _, f := range fams {
		for _, s := range familyShapes(f) {
			shapes[s] = true
		}
	}
	var out []claimEvalOut
	for _, ev := range evals {
		if ev.ClaimID == c.ID || !shapes[ev.Shape] {
			continue
		}
		if c.Subject.Kind != claimshape.SubjectUnknown && c.Subject.Name != "" {
			// Subject-bearing derived claims bind only premises about the
			// same subject — a sibling subject's result never conjoins.
			if !sameClaimSubject(c, ev, claims) {
				continue
			}
		}
		out = append(out, ev)
	}
	return out
}

// sameClaimSubject reports whether a premise claim's subject overlaps the
// derived claim's subject or any of its covered subjects.
func sameClaimSubject(c claimshape.CanonicalClaim, ev claimEvalOut, claims map[string]claimshape.CanonicalClaim) bool {
	pool := ev.admittedCovered
	if pc, ok := claims[ev.ClaimID]; ok {
		pool = append(append([]claimshape.Subject{pc.Subject}, paramSubjects(pc, "subjects")...), pool...)
	}
	for _, want := range append([]claimshape.Subject{c.Subject}, paramSubjects(c, "subjects")...) {
		for _, got := range pool {
			if subjectMatches(want, got) {
				return true
			}
		}
	}
	return false
}

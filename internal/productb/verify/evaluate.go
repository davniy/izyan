package verify

import (
	"sort"

	"github.com/fedorovmv/izyan/internal/evidencetools"
	"github.com/fedorovmv/izyan/internal/productb/claimshape"
	triage "github.com/fedorovmv/izyan/internal/productb/triage"
)

// Input is everything evaluation consumes: the canonical claims of one
// run, the run's recorded observation archive, the deterministic advisory
// context and the deployment materials. Live tool output enters only as
// RecordedObservation values — the evaluator never calls a tool itself.
type Input struct {
	RunID        string
	FindingID    string
	Claims       []claimshape.CanonicalClaim
	Observations []triage.RecordedObservation
	Advisory     claimshape.AdvisoryFacts
	// Deploy is the deterministic deployment projection (perimeter and
	// exposure facts) when the run recorded one.
	Deploy *triage.DeployFacts
	// Falsifiers is the persisted checker-verified proof report when the
	// run produced one. Each proof enters the graph as a
	// falsifier_certificate capability observation — never as a verdict.
	Falsifiers *triage.FalsifierReport
	// SnapshotHash is the run's snapshot identity when known. Empty falls
	// back to the archive consensus — the same binding C14 uses.
	SnapshotHash string
	// Challenges carries the adversarial reviewer's proposals: each one
	// is normalized into a canonical claim and passes through the
	// identical capability/observation/entailment cycle — the channel
	// contributes hypotheses, never outcomes (plan §3, Task 4).
	Challenges []Challenge
	// AssumeArchiveRun binds an observation with an empty run_id to this
	// input's RunID during replay — archives written before run stamping
	// stay evaluable. Live evaluation leaves it false so a foreign or
	// unstamped record can never silently re-home.
	AssumeArchiveRun bool
}

// ObsAdmission records how one bound observation fared under the
// contract: its result, whether it admitted, and why not — the audit
// line behind every claim outcome.
type ObsAdmission struct {
	ObservationID string                     `json:"observation_id"`
	Capability    string                     `json:"capability"`
	Result        Result                     `json:"result"`
	Completeness  evidencetools.Completeness `json:"completeness"`
	ContextKey    string                     `json:"context_key"`
	Admitted      bool                       `json:"admitted"`
	Reason        string                     `json:"reason,omitempty"`
}

// ContextGroup is one provenance context (snapshot hash × build context)
// a claim's bound observations split into. Observations of different
// groups are evaluated separately and never mixed (plan §6.4).
type ContextGroup struct {
	Key              string `json:"key"`
	SnapshotHash     string `json:"snapshot_hash,omitempty"`
	BuildContextHash string `json:"build_context_hash,omitempty"`
	// Established is the value the group established for the predicate:
	// "holds", "disproved", "conflicting" or "none".
	Established  string         `json:"established"`
	Observations []ObsAdmission `json:"observations,omitempty"`
}

// ClaimEval is the deterministic evaluation of one canonical claim.
type ClaimEval struct {
	ClaimID           string           `json:"claim_id"`
	Shape             claimshape.Shape `json:"shape"`
	Outcome           Outcome          `json:"outcome"`
	Predicate         PredicateOutcome `json:"predicate_outcome"`
	Reason            string           `json:"reason,omitempty"`
	RequiredCaps      []string         `json:"required_capabilities,omitempty"`
	MissingCaps       []string         `json:"missing_capabilities,omitempty"`
	Groups            []ContextGroup   `json:"context_groups,omitempty"`
	BoundObservations int              `json:"bound_observations"`
}

// Edge is one entailment-graph edge of plan §5.2: observation→claim
// supports/refutes, observation→subject covers, observation→observation
// contradicts, derived node → its claim/proof sources (derived_from) and
// derived node → premise claims (depends_on).
type Edge struct {
	Kind string `json:"kind"` // supports | refutes | covers | contradicts | depends_on | derived_from
	From string `json:"from"`
	To   string `json:"to"`
}

// Evaluate deterministically evaluates every claim against the recorded
// observations, builds the entailment graph over the admitted evidence
// and compiles the run's disposition with the generic decision rules.
// Pure function: identical inputs give identical output — the replay
// contract.
func Evaluate(in Input) Report {
	rep := Report{
		SchemaVersion: ContractSchemaVersion,
		RunID:         in.RunID,
		FindingID:     in.FindingID,
	}
	claims, rows := mergeClaims(in.Claims, in.Challenges)

	ctx := newEvalContext(in, claims)
	var evals []claimEvalOut
	var allEdges []Edge
	for _, c := range claims {
		ev := evalClaim(ctx, in, c)
		evals = append(evals, ev)
		allEdges = append(allEdges, ev.edges...)
	}

	// Entailment graph: claim, observation, derived-fact, rule and
	// decision nodes over the admitted evidence. The graph also derives
	// the outcome of derived.* claims from their premise claims.
	graph := buildGraph(ctx, in, claims, evals)
	claimByID := map[string]claimshape.CanonicalClaim{}
	for _, c := range claims {
		claimByID[c.ID] = c
	}
	var derivedEdges []Edge
	for i := range evals {
		var dedges []Edge
		evals[i].ClaimEval, dedges = deriveClaimOutcome(claims[i], evals[i].ClaimEval, evals, claimByID, graph.Graph)
		derivedEdges = append(derivedEdges, dedges...)
	}
	allEdges = append(allEdges, graph.derivedEdges...)
	allEdges = append(allEdges, derivedEdges...)
	for _, ev := range evals {
		rep.Claims = append(rep.Claims, ev.ClaimEval)
	}
	sort.Slice(allEdges, func(i, j int) bool {
		if allEdges[i].From != allEdges[j].From {
			return allEdges[i].From < allEdges[j].From
		}
		if allEdges[i].Kind != allEdges[j].Kind {
			return allEdges[i].Kind < allEdges[j].Kind
		}
		return allEdges[i].To < allEdges[j].To
	})
	rep.Edges = allEdges
	rep.Graph = graph.Graph
	// Challenge audit: each proposal reports the outcome the cycle
	// computed — the channel never set it.
	if len(rows) > 0 {
		byID := map[string]ClaimEval{}
		for _, ev := range evals {
			byID[ev.ClaimID] = ev.ClaimEval
		}
		for i := range rows {
			if ev, ok := byID[rows[i].ClaimID]; ok {
				rows[i].Outcome = ev.Outcome
				rows[i].Predicate = ev.Predicate
			}
		}
		rep.Challenges = rows
	}
	rep.SemanticHash, rep.Decisive = computeSurfaces(in, ctx, claims, evals, rep)
	rep.Hash = rep.computeHash()
	return rep
}

// mergeClaims appends the normalized challenge claims to the assessment
// claims under canonical ordering and identity deduplication: an empty
// claim id is replaced by its content hash, and an id collision keeps
// the first claim in stable sort order — the deterministic set the
// graph sees is a function of claim content, never of slice order.
func mergeClaims(base []claimshape.CanonicalClaim, chs []Challenge) ([]claimshape.CanonicalClaim, []ChallengeEval) {
	extra, rows := normalizeChallenges(chs)
	all := append(append([]claimshape.CanonicalClaim(nil), base...), extra...)
	for i := range all {
		if all[i].ID == "" {
			all[i].ID = "claim-" + shortHash([]byte(claimSignature(all[i])))
		}
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].ID < all[j].ID })
	seen := map[string]bool{}
	var claims []claimshape.CanonicalClaim
	for _, c := range all {
		if seen[c.ID] {
			continue
		}
		seen[c.ID] = true
		claims = append(claims, c)
	}
	for i := range rows {
		if rows[i].ClaimID != "" && !seen[rows[i].ClaimID] {
			rows[i].Merged = true
		}
	}
	return claims, rows
}

// claimEvalOut carries the claim evaluation plus its edge rows and the
// admitted-observation coverage the graph needs for condition binding.
type claimEvalOut struct {
	ClaimEval
	edges           []Edge
	admittedCovered []claimshape.Subject
	admittedCerts   []string
	boundObs        []Observation
}

// evalClaim evaluates one claim: bind observations, interpret them
// through the capability contracts, split by provenance context and
// apply the admission rules. No LLM, no verdict, no statement text.
func evalClaim(ctx *evalContext, in Input, c claimshape.CanonicalClaim) claimEvalOut {
	out := claimEvalOut{ClaimEval: ClaimEval{
		ClaimID:      c.ID,
		Shape:        c.Shape,
		Outcome:      OutcomeUnknown,
		Predicate:    PredicateUnknown,
		RequiredCaps: append([]string(nil), c.RequiredCapabilities...),
	}}
	sort.Strings(out.RequiredCaps)

	if c.Shape == claimshape.ShapeUnsupported {
		out.Reason = "unsupported_claim_shape:" + string(c.UnsupportedReason)
		return out
	}
	out.MissingCaps = MissingCapabilities(c)

	// ---- bind + interpret observations ----
	var bound []Observation
	for i := range in.Observations {
		rec := &in.Observations[i]
		for _, obs := range interpretRecorded(interpInput{
			Observation:  rec,
			Shape:        c.Shape,
			ClaimSubject: c.Subject,
		}) {
			if Contract(obs.Capability, c.Shape) == nil {
				continue // capability cannot serve this shape
			}
			isCited := contains(c.EvidenceRefs, rec.ID)
			if !isCited {
				// Uncited observations bind only on canonical subject coverage.
				if !coversClaim(c, obs) {
					continue
				}
			} else if len(obs.CoveredSubjects) > 0 && !coversClaim(c, obs) {
				// Citation is an evidence reference, not a subject-binding
				// bypass. A cited observation for another module/symbol can
				// never adjudicate this claim.
			}
			if rec.Status != "OK" {
				obs.Result = ResultUnknown
				obs.OpenGaps = append(obs.OpenGaps, "tool_status:"+rec.Status)
				sort.Strings(obs.OpenGaps)
			}
			obs.ID = rec.ID + "#" + itoa(i) + "#" + obs.Capability
			obs.Query = Query{Shape: c.Shape, Subject: c.Subject, Tool: rec.Tool}
			bound = append(bound, obs)
		}
	}
	// Derived capabilities synthesize their observation from structured
	// claim/run data — deterministic, replay-stable.
	bound = append(bound, derivedObservations(in, c)...)
	// Falsifier certificates mint their capability observation per proof —
	// a certificate is evidence under the same admission contract, never
	// a proof by itself.
	bound = append(bound, certificateObservations(ctx, in, c)...)
	sort.Slice(bound, func(i, j int) bool { return bound[i].ID < bound[j].ID })
	out.boundObs = bound
	out.BoundObservations = len(bound)

	if len(bound) == 0 {
		if len(out.MissingCaps) > 0 {
			out.Reason = "capability_unavailable:" + joinStrings(out.MissingCaps)
		} else {
			out.Reason = "no_observations"
		}
		return out
	}

	// ---- split by provenance context ----
	groups := map[string]*ContextGroup{}
	var order []string
	for _, obs := range bound {
		key := obs.SnapshotHash + "\x00" + obs.BuildContextHash
		g := groups[key]
		if g == nil {
			g = &ContextGroup{Key: key, SnapshotHash: obs.SnapshotHash, BuildContextHash: obs.BuildContextHash}
			groups[key] = g
			order = append(order, key)
		}
		g.Observations = append(g.Observations, ObsAdmission{
			ObservationID: obs.ID,
			Capability:    obs.Capability,
			Result:        obs.Result,
			Completeness:  obs.Completeness,
			ContextKey:    key,
		})
	}
	sort.Strings(order)

	// Claim-pinned context selects groups (plan §6.4 separation).
	pinned := c.Scope.SnapshotHash != "" || c.Scope.BuildContextHash != ""
	var evalKeys []string
	for _, k := range order {
		g := groups[k]
		if pinned && c.Scope.SnapshotHash != "" && g.SnapshotHash != c.Scope.SnapshotHash {
			continue
		}
		if pinned && c.Scope.BuildContextHash != "" && g.BuildContextHash != c.Scope.BuildContextHash {
			continue
		}
		evalKeys = append(evalKeys, k)
	}

	// ---- admission per group ----
	var groupValues []string
	var anyConflict, anyHolds, anyDisproved bool
	for _, k := range order {
		g := groups[k]
		if !contains(evalKeys, k) {
			g.Established = "context_excluded"
			out.Groups = append(out.Groups, *g)
			continue
		}
		value, edges := evalGroup(in, c, k, bound, g)
		g.Established = value
		out.Groups = append(out.Groups, *g)
		out.edges = append(out.edges, edges...)
		for _, adm := range g.Observations {
			if !adm.Admitted {
				continue
			}
			for j := range bound {
				if bound[j].ID == adm.ObservationID {
					out.admittedCovered = append(out.admittedCovered, bound[j].CoveredSubjects...)
					if bound[j].Capability == CapFalsifierCertificate {
						out.admittedCerts = append(out.admittedCerts, bound[j].ID)
					}
				}
			}
		}
		groupValues = append(groupValues, value)
		switch value {
		case "conflicting":
			anyConflict = true
		case "holds":
			anyHolds = true
		case "disproved":
			anyDisproved = true
		}
	}

	if len(evalKeys) == 0 {
		out.Reason = "no_context_match"
		return out
	}

	// ---- aggregate groups ----
	out.Predicate = aggregate(c, groupValues, anyConflict, anyHolds, anyDisproved)
	out.Outcome = claimOutcome(c.Polarity, out.Predicate)
	if len(out.MissingCaps) > 0 && out.Outcome == OutcomeTrue {
		// A missing capability can never ground a positive outcome: the
		// full required set must admit for TRUE (plan §5 admission rule).
		out.Outcome = OutcomeUnknown
		out.Reason = "capability_unavailable:" + joinStrings(out.MissingCaps)
		return out
	}
	return out
}

// coversClaim reports whether an uncited observation's coverage reaches
// the canonical claim subject. Claim parameters are never evidence.
func coversClaim(c claimshape.CanonicalClaim, obs Observation) bool {
	if len(obs.CoveredSubjects) == 0 {
		return false
	}
	for _, cov := range obs.CoveredSubjects {
		if subjectMatches(c.Subject, cov) {
			return true
		}
	}
	return false
}

// completenessRank orders the completeness ladder.
func completenessRank(c evidencetools.Completeness) int {
	switch c {
	case evidencetools.CompletenessComplete:
		return 3
	case evidencetools.CompletenessPartial:
		return 2
	default:
		return 1
	}
}

// evalGroup evaluates one provenance-context group for one claim and
// returns the established predicate value plus emitted edges.
func evalGroup(in Input, c claimshape.CanonicalClaim, key string, bound []Observation, g *ContextGroup) (string, []Edge) {
	var edges []Edge
	admit := func(obs *Observation, contract *ShapeContract, res Result) (bool, string) {
		dir := contract.direction(res)
		if completenessRank(obs.Completeness) < completenessRank(dir.MinCompleteness) {
			return false, "completeness_below_floor:" + string(obs.Completeness)
		}
		if dir.ClosedScope && !obs.ClosedScope {
			return false, "closed_scope_required"
		}
		for _, f := range dir.Provenance {
			if f == ProvRunID {
				if !runBound(in, obs) {
					return false, "provenance_missing:run_id"
				}
				continue
			}
			if obs.provValue(f) == "" {
				return false, "provenance_missing:" + string(f)
			}
		}
		// Gap blockers apply to the universal direction — the direction
		// whose contract demands a closed scope. A witness or
		// counterexample stands even amid open gaps.
		if dir.ClosedScope {
			for _, gap := range obs.OpenGaps {
				cls, _ := splitGap(gap)
				if contains(contract.GapBlockers, cls) {
					return false, "dynamic_gap:" + cls
				}
			}
		}
		return true, ""
	}

	// Per-observation admission under its own capability's contract.
	admitted := map[string]map[Result]bool{}
	for i := range g.Observations {
		adm := &g.Observations[i]
		var obs *Observation
		for j := range bound {
			if bound[j].ID == adm.ObservationID {
				obs = &bound[j]
				break
			}
		}
		if obs == nil || obs.Result == ResultUnknown || obs.Result == ResultConflicting {
			adm.Reason = "result_not_admissible:" + string(adm.Result)
			continue
		}
		contract := Contract(obs.Capability, c.Shape)
		if contract == nil {
			adm.Reason = "no_shape_contract"
			continue
		}
		ok, why := admit(obs, contract, obs.Result)
		if !ok {
			adm.Reason = why
			continue
		}
		dir := contract.direction(obs.Result)
		// Conjunction: extra capabilities must each contribute an
		// admitted SUPPORTS observation for this direction.
		if len(dir.AlsoRequires) > 0 {
			missing := []string{}
			for _, need := range dir.AlsoRequires {
				nc := Contract(need, c.Shape)
				if nc == nil {
					missing = append(missing, need)
					continue
				}
				found := false
				for j := range bound {
					o2 := &bound[j]
					if o2.Capability != need || o2.Result != ResultSupports {
						continue
					}
					if key != o2.SnapshotHash+"\x00"+o2.BuildContextHash {
						continue
					}
					if ok2, _ := admit(o2, nc, ResultSupports); ok2 {
						found = true
						break
					}
				}
				if !found {
					missing = append(missing, need)
				}
			}
			if len(missing) > 0 {
				adm.Reason = "conjoined_capability_missing:" + joinStrings(missing)
				continue
			}
		}
		adm.Admitted = true
		// Auxiliary capabilities remain admitted for conjunction and
		// blocker diagnostics, but cannot establish the claim predicate.
		if contract.PredicateEvidence {
			if admitted[obs.Capability] == nil {
				admitted[obs.Capability] = map[Result]bool{}
			}
			admitted[obs.Capability][obs.Result] = true
		}
		ek := "supports"
		if obs.Result == ResultRefutes {
			ek = "refutes"
		}
		edges = append(edges, Edge{Kind: ek, From: obs.ID, To: c.ID})
		for _, s := range obs.CoveredSubjects {
			edges = append(edges, Edge{Kind: "covers", From: obs.ID, To: string(s.Kind) + ":" + s.Name})
		}
	}

	// Group verdict: admitted SUPPORTS establish the predicate, admitted
	// REFUTES disprove it — the contract floors already decided which
	// results may stand.
	holds, disproved := false, false
	for _, obs := range bound {
		if obs.SnapshotHash+"\x00"+obs.BuildContextHash != key {
			continue
		}
		if m := admitted[obs.Capability]; m != nil {
			if m[ResultSupports] {
				holds = true
			}
			if m[ResultRefutes] {
				disproved = true
			}
		}
	}

	switch {
	case holds && disproved:
		// Contradiction inside one context: emit contradicts edges
		// between the admitted observations on opposite sides.
		var sIDs, rIDs []string
		for _, adm := range g.Observations {
			if !adm.Admitted {
				continue
			}
			if adm.Result == ResultSupports {
				sIDs = append(sIDs, adm.ObservationID)
			} else {
				rIDs = append(rIDs, adm.ObservationID)
			}
		}
		for _, a := range sIDs {
			for _, b := range rIDs {
				edges = append(edges, Edge{Kind: "contradicts", From: a, To: b})
			}
		}
		return "conflicting", edges
	case holds:
		return "holds", edges
	case disproved:
		return "disproved", edges
	}
	return "none", edges
}

// runBound reports whether the observation's run binding satisfies the
// contract: the effective run id must exist and, when the run identity
// is known, match it exactly — a foreign run's record can never ride in.
func runBound(in Input, obs *Observation) bool {
	run := obs.RunID
	if run == "" && in.AssumeArchiveRun {
		run = in.RunID
	}
	if run == "" {
		return false
	}
	if in.RunID != "" && run != in.RunID {
		return false
	}
	return true
}

// aggregate combines per-group established values into the predicate
// outcome, applying the shape's direction semantics: existential
// predicates stand on any single group's witness; universal predicates
// need every recorded context to agree.
func aggregate(c claimshape.CanonicalClaim, values []string, anyConflict, anyHolds, anyDisproved bool) PredicateOutcome {
	if anyConflict {
		return PredicateConflicting
	}
	universal := isUniversalShape(c.Shape)
	if universal {
		switch {
		case anyDisproved:
			return PredicateDisproved
		case len(values) > 0 && allEqual(values, "holds"):
			return PredicateHolds
		}
		return PredicateUnknown
	}
	// Existential predicates: one witness suffices in either direction.
	switch {
	case anyHolds && anyDisproved:
		return PredicateConflicting
	case anyHolds:
		return PredicateHolds
	case anyDisproved:
		return PredicateDisproved
	}
	return PredicateUnknown
}

// isUniversalShape reports whether the shape's predicate quantifies over
// a closed universe: proving it demands every recorded context to agree;
// a single group's counterexample already disproves it.
func isUniversalShape(s claimshape.Shape) bool {
	switch s {
	case claimshape.ShapeSubjectAbsent,
		claimshape.ShapePathUnreachable,
		claimshape.ShapeControlAbsent,
		claimshape.ShapeClosureComplete:
		return true
	}
	return false
}

// claimOutcome compares the established predicate value with the polarity
// the claim asserted.
func claimOutcome(p claimshape.Polarity, pred PredicateOutcome) Outcome {
	switch pred {
	case PredicateConflicting:
		return OutcomeConflicting
	case PredicateUnknown:
		return OutcomeUnknown
	}
	if p == claimshape.PolarityUnknown || p == "" {
		return OutcomeUnknown
	}
	holds := pred == PredicateHolds
	if (p == claimshape.PolarityTrue) == holds {
		return OutcomeTrue
	}
	return OutcomeFalse
}

// derivedObservations synthesizes the observations of derived capabilities
// (advisory_range_matcher, deployment_classifier) from structured inputs.
func derivedObservations(in Input, c claimshape.CanonicalClaim) []Observation {
	var out []Observation
	// advisory_range_matcher — pure version-range evaluation.
	if c.Shape == claimshape.ShapeApplicabilityVersionInRange {
		module := paramStr(c, "module")
		if module == "" {
			module = in.Advisory.Module
		}
		version := paramStr(c, "resolved_version")
		ranges := paramRanges(c, "affected_ranges")
		if version != "" && len(ranges) > 0 {
			res := ResultUnknown
			if inRange, ok := claimshape.VersionInRange(version, ranges); ok {
				if inRange {
					res = ResultSupports
				} else {
					res = ResultRefutes
				}
			}
			out = append(out, Observation{
				ID:           c.ID + "#derived:advisory_range_matcher",
				Capability:   CapAdvisoryRangeMatcher,
				Query:        Query{Shape: c.Shape, Subject: c.Subject, Params: map[string]string{"module": module, "version": version}},
				Result:       res,
				Completeness: evidencetools.CompletenessComplete,
				ClosedScope:  true,
				ScopeHash:    "ranges:" + shortHash(canonicalJSON(ranges)),
				SnapshotHash: c.Scope.SnapshotHash,
				// The matcher's answer is bound to the claim's own
				// context pin — a claim may pin its build context and
				// the group the observation lands in must match it.
				BuildContextHash: c.Scope.BuildContextHash,
				ToolVersion:      "advisory_range_matcher@1",
				RunID:            in.RunID,
				CoveredSubjects: []claimshape.Subject{
					{Kind: claimshape.SubjectModule, Name: module},
				},
			})
		}
	}
	// deployment_classifier — deterministic perimeter verdict.
	if c.Shape == claimshape.ShapePerimeterExposure || c.Shape == claimshape.ShapeInputAttackerControlled {
		if in.Deploy != nil && in.Deploy.Perimeter != "" {
			res := ResultUnknown
			closed := false
			var gaps []string
			switch in.Deploy.Perimeter {
			case "public":
				res = ResultSupports
			case "cluster-internal", "internal", "loopback":
				// A proven internal perimeter is complete evidence
				// against inbound exposure — the universal direction
				// needs a closed deployment universe.
				res = ResultRefutes
				closed = true
			default:
				gaps = append(gaps, "unknown_inbound_surface")
			}
			out = append(out, Observation{
				ID:           c.ID + "#derived:deployment_classifier",
				Capability:   CapDeploymentClassifier,
				Query:        Query{Shape: c.Shape, Subject: c.Subject},
				Result:       res,
				Completeness: evidencetools.CompletenessComplete,
				ClosedScope:  closed,
				ScopeHash:    "deploy:" + in.Deploy.SHA256,
				SnapshotHash: c.Scope.SnapshotHash,
				// The classifier's answer is bound to the claim's own
				// context pin — the universal direction requires the
				// build-context provenance like every other capability.
				BuildContextHash: c.Scope.BuildContextHash,
				ToolVersion:      "deployment_classifier@1",
				RunID:            in.RunID,
				OpenGaps:         gaps,
				Limitations:      []string{in.Deploy.Rationale},
			})
		}
	}
	return out
}

// paramStr pulls a string parameter off a canonical claim.
func paramStr(c claimshape.CanonicalClaim, key string) string {
	if v, ok := c.Parameters[key].(string); ok {
		return v
	}
	return ""
}

// paramRanges pulls the affected-ranges parameter, tolerating both the
// typed slice extraction writes and the generic JSON decode.
func paramRanges(c claimshape.CanonicalClaim, key string) []claimshape.VersionRange {
	switch v := c.Parameters[key].(type) {
	case []claimshape.VersionRange:
		return v
	case []any:
		var out []claimshape.VersionRange
		for _, item := range v {
			if m, ok := item.(map[string]any); ok {
				out = append(out, claimshape.VersionRange{
					Introduced:   strOf(m, "introduced"),
					Fixed:        strOf(m, "fixed"),
					LastAffected: strOf(m, "last_affected"),
					Limit:        strOf(m, "limit"),
				})
			}
		}
		return out
	}
	return nil
}

// paramSubjects pulls a subjects parameter, tolerating typed slices and
// generic JSON decodes alike.
func paramSubjects(c claimshape.CanonicalClaim, key string) []claimshape.Subject {
	switch v := c.Parameters[key].(type) {
	case []claimshape.Subject:
		return v
	case []any:
		var out []claimshape.Subject
		for _, item := range v {
			if m, ok := item.(map[string]any); ok {
				out = append(out, claimshape.Subject{
					Kind:    claimshape.SubjectKind(strOf(m, "kind")),
					Name:    strOf(m, "name"),
					Package: strOf(m, "package"),
					Symbol:  strOf(m, "symbol"),
				})
			}
		}
		return out
	}
	return nil
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func allEqual(xs []string, want string) bool {
	if len(xs) == 0 {
		return false
	}
	for _, x := range xs {
		if x != want {
			return false
		}
	}
	return true
}

func joinStrings(xs []string) string {
	out := ""
	for i, x := range xs {
		if i > 0 {
			out += ","
		}
		out += x
	}
	return out
}

package verify

import (
	"fmt"
	"sort"
	"strings"

	"github.com/davniy/izyan/internal/productb/claimshape"
)

// StabilitySchemaVersion identifies the persisted stability-verdict
// schema the controller emits for audit.
const StabilitySchemaVersion = "verification-stability.v1"

// DecisiveSurface is the proof/decision projection the stability
// controller compares across re-derivations (plan §6.5): the mandatory
// conditions and their falsifiers/contestants, the satisfied rules, the
// compiled decision, the certificate statuses and the conflict state.
// Fingerprints are content-addressed — attempt-varying node ids never
// enter — so two attempts disagreeing here genuinely disagree about
// decisive evidence, not about cosmetic identities. LLM claims and
// their outcomes live on the semantic surface instead.
type DecisiveSurface struct {
	// Disposition is the compiled decision (DISMISSED|LOWERED|UNCHANGED).
	Disposition string `json:"disposition"`
	// Conditions fingerprints every materialized condition: mandatory
	// class, value, falsifier direction, shapes, expected universe and
	// the falsifier/contestant sets.
	Conditions []string `json:"conditions,omitempty"`
	// SatisfiedRules lists the ids of decision rules that fired.
	SatisfiedRules []string `json:"satisfied_rules,omitempty"`
	// DecisionPremises fingerprints the premise nodes of satisfied
	// rules (conditions by their fingerprint, claims by signature).
	DecisionPremises []string `json:"decision_premises,omitempty"`
	// Proofs fingerprints every persisted proof certificate: id,
	// status, basis, mandatory flag, violation classes, observation
	// result and provenance pins — the "proof status/hash" of §6.5.
	Proofs []string `json:"proofs,omitempty"`
	// Conflicts fingerprints every claim that evaluated CONFLICTING:
	// the claim signature plus the context keys the conflict lives in.
	// A hidden conflict between attempts is decisive instability.
	Conflicts []string `json:"conflicts,omitempty"`
	// Hash is the canonical digest of this surface — the proof hash a
	// reduction is bound to.
	Hash string `json:"hash"`
}

// AttemptPins records the provenance bindings a re-derivation consumed:
// the retry contract of plan §6.5 requires identical input, snapshot,
// advisory, ref/commit, build context, ruleset, prompt/module and
// budgets. A divergence here is technical drift, not instability — the
// controller flags it and demotes unconditionally.
type AttemptPins struct {
	InputHash        string `json:"input_hash,omitempty"`
	SnapshotHash     string `json:"snapshot_hash,omitempty"`
	AdvisoryHash     string `json:"advisory_hash,omitempty"`
	BuildContextHash string `json:"build_context_hash,omitempty"`
	RulesetHash      string `json:"ruleset_hash,omitempty"`
	PromptHash       string `json:"prompt_hash,omitempty"`
	BudgetHash       string `json:"budget_hash,omitempty"`
	SelectedRef      string `json:"selected_ref,omitempty"`
	ResolvedCommit   string `json:"resolved_commit,omitempty"`
}

// pinPairs renders the pins as (name, value) rows for comparison —
// every pin is checked, so extending the struct extends the drift gate
// without a second comparison list.
func (p AttemptPins) pinPairs() [][2]string {
	return [][2]string{
		{"input_hash", p.InputHash},
		{"snapshot_hash", p.SnapshotHash},
		{"advisory_hash", p.AdvisoryHash},
		{"build_context_hash", p.BuildContextHash},
		{"ruleset_hash", p.RulesetHash},
		{"prompt_hash", p.PromptHash},
		{"budget_hash", p.BudgetHash},
		{"selected_ref", p.SelectedRef},
		{"resolved_commit", p.ResolvedCommit},
	}
}

// Attempt is one re-derivation the controller assessed: the report the
// deterministic cycle produced plus the provenance pins it consumed.
type Attempt struct {
	Attempt int         `json:"attempt"`
	Pins    AttemptPins `json:"pins,omitempty"`
	Report  Report      `json:"-"`
}

// AttemptProjection is the audit record one attempt contributes to the
// verdict: the pins and surfaces verbatim — never a preferred answer.
type AttemptProjection struct {
	Attempt      int         `json:"attempt"`
	Pins         AttemptPins `json:"pins,omitempty"`
	ReportHash   string      `json:"report_hash,omitempty"`
	DecisiveHash string      `json:"decisive_hash,omitempty"`
	SemanticHash string      `json:"semantic_hash,omitempty"`
	Disposition  string      `json:"disposition"`
}

// StabilityVerdict is the controller's deterministic verdict over a
// bounded attempt series (plan §6.5, §8.3 stability gate):
//
//   - Drift — provenance pins disagreed: technical error, disposition
//     demoted to UNCHANGED without exception;
//   - !Stable — the decisive surface disagreed: decisive instability,
//     DISMISSED/LOWERED are forbidden and the effective disposition is
//     UNCHANGED, never the best attempt's;
//   - SemanticDrift — the claim-level surface disagreed while the proof
//     surface agreed: semantic instability, recorded but never demoting;
//   - Stable — every attempt agrees on the decisive surface, so the
//     common disposition stands. A single attempt is vacuously stable:
//     there is nothing to contradict it.
//
// The verdict never selects a preferred attempt: reductions are allowed
// only through unanimous agreement on the decisive surface.
type StabilityVerdict struct {
	SchemaVersion string              `json:"schema_version"`
	Attempts      []AttemptProjection `json:"attempts,omitempty"`
	Retries       int                 `json:"retries"`
	Stable        bool                `json:"stable"`
	SemanticDrift bool                `json:"semantic_drift"`
	Drift         bool                `json:"drift"`
	// Disposition is the effective triage disposition after stability
	// adjudication — UNCHANGED on any divergence.
	Disposition string `json:"disposition"`
	// DemotedFrom records the disposition that stood before demotion;
	// empty when nothing was demoted.
	DemotedFrom string `json:"demoted_from,omitempty"`
	Reason      string `json:"reason,omitempty"`
	// Limitations records every divergence found: it feeds the
	// technical_assessment limitations channel verbatim.
	Limitations []string `json:"limitations,omitempty"`
}

// Assess evaluates a bounded re-derivation series and adjudicates the
// effective disposition. Reduction is permitted only when the decisive
// surface — conditions, falsifiers, rules, decision, proofs, conflicts —
// is identical across every attempt sharing the same provenance pins.
// The controller never picks a preferred attempt and never treats a
// divergent retry as a better answer: disagreement demotes.
func Assess(attempts []Attempt) StabilityVerdict {
	v := StabilityVerdict{
		SchemaVersion: StabilitySchemaVersion,
		Stable:        true,
		Disposition:   "UNCHANGED",
		Reason:        "no attempts",
	}
	if len(attempts) == 0 {
		v.Limitations = append(v.Limitations, "no attempts to assess")
		return v
	}
	v.Retries = len(attempts) - 1
	for _, at := range attempts {
		v.Attempts = append(v.Attempts, AttemptProjection{
			Attempt:      at.Attempt,
			Pins:         at.Pins,
			ReportHash:   at.Report.Hash,
			DecisiveHash: at.Report.Decisive.Hash,
			SemanticHash: at.Report.SemanticHash,
			Disposition:  at.Report.Decision().Disposition,
		})
	}
	base := attempts[0]
	v.Disposition = base.Report.Decision().Disposition
	v.Reason = "stable proof surface"
	if len(attempts) < 2 {
		// A single attempt has nothing to contradict: the decisive
		// surface is vacuously stable and its disposition stands.
		return v
	}
	for _, at := range attempts[1:] {
		n := at.Attempt
		if n == 0 {
			n = -1
		}
		for _, p := range at.Pins.pinPairs() {
			baseVal := ""
			for _, bp := range base.Pins.pinPairs() {
				if bp[0] == p[0] {
					baseVal = bp[1]
					break
				}
			}
			if p[1] != baseVal {
				v.Drift = true
				v.Limitations = append(v.Limitations,
					fmt.Sprintf("attempt %d: provenance drift: %s changed", n, p[0]))
			}
		}
		if at.Report.Decisive.Hash != base.Report.Decisive.Hash {
			v.Stable = false
			v.Limitations = append(v.Limitations,
				fmt.Sprintf("attempt %d: decisive surface changed (%s -> %s)",
					n, base.Report.Decisive.Hash, at.Report.Decisive.Hash))
		} else if at.Report.SemanticHash != base.Report.SemanticHash {
			// Claims/proposals differ while the deterministic proof
			// surface agrees: semantic instability — recorded, never
			// demoting, and the graph decision stands.
			v.SemanticDrift = true
			v.Limitations = append(v.Limitations,
				fmt.Sprintf("attempt %d: semantic drift (%s -> %s)",
					n, base.Report.SemanticHash, at.Report.SemanticHash))
		}
	}
	switch {
	case v.Drift:
		// Changed provenance is technical drift, not instability:
		// the effective disposition demotes unconditionally.
		v.Stable = false
		v.DemotedFrom = v.Disposition
		v.Disposition = "UNCHANGED"
		v.Reason = "provenance drift: technical error channel"
	case !v.Stable:
		// Decisive evidence disagreed across retries: DISMISSED/LOWERED
		// are forbidden and no best attempt is selected — the effective
		// disposition is UNCHANGED and the stability assumption is
		// recorded as UNKNOWN.
		v.DemotedFrom = v.Disposition
		v.Disposition = "UNCHANGED"
		v.Reason = "unstable decisive evidence: reduction forbidden"
	case v.SemanticDrift:
		v.Reason = "stable proof surface; claims/proposals differed (semantic drift)"
	}
	return v
}

// claimSignature is the decisive identity of a canonical claim: shape,
// subject, polarity and the non-volatile parameters. Attempt-local
// identity (claim id, bound-proposal bookkeeping, facet rolls, evidence
// ids) never enters — two retries asking the same predicate the same
// question carry the same signature.
func claimSignature(c claimshape.CanonicalClaim) string {
	params := map[string]any{}
	for k, v := range c.Parameters {
		switch k {
		case "facets", "bound_proposals", "limitations":
			continue
		}
		params[k] = v
	}
	sig := struct {
		Shape    claimshape.Shape    `json:"shape"`
		Subject  claimshape.Subject  `json:"subject"`
		Polarity claimshape.Polarity `json:"polarity"`
		Params   map[string]any      `json:"params,omitempty"`
	}{Shape: c.Shape, Subject: c.Subject, Polarity: c.Polarity, Params: params}
	return string(canonicalJSON(sig))
}

// semanticSignature extends the decisive claim identity with the
// verbatim statement hash: it is the claim-level surface the semantic
// hash watches, where LLM phrasing legitimately varies.
func semanticSignature(c claimshape.CanonicalClaim) string {
	params := map[string]any{}
	for k, v := range c.Parameters {
		switch k {
		case "facets", "bound_proposals", "limitations":
			continue
		}
		params[k] = v
	}
	sig := struct {
		ID        string              `json:"id"`
		Shape     claimshape.Shape    `json:"shape"`
		Subject   claimshape.Subject  `json:"subject"`
		Polarity  claimshape.Polarity `json:"polarity"`
		Params    map[string]any      `json:"params,omitempty"`
		Refs      []string            `json:"refs,omitempty"`
		Statement string              `json:"statement_hash,omitempty"`
	}{
		ID: c.ID, Shape: c.Shape, Subject: c.Subject, Polarity: c.Polarity,
		Params: params,
	}
	if len(c.EvidenceRefs) > 0 {
		refs := dedup(append([]string(nil), c.EvidenceRefs...))
		sort.Strings(refs)
		sig.Refs = refs
	}
	if c.Source.Statement != "" {
		sig.Statement = shortHash([]byte(c.Source.Statement))
	}
	return string(canonicalJSON(sig))
}

// obsFingerprint renders an admitted observation's attempt-stable
// identity: capability, query tool, result, completeness, scope binding
// and the subjects it covered. Live observation ids (live-0001, per-run
// stamps) never enter.
func obsFingerprint(o Observation) string {
	subs := make([]string, 0, len(o.CoveredSubjects))
	for _, s := range o.CoveredSubjects {
		subs = append(subs, subjectKey(s))
	}
	sort.Strings(subs)
	return o.Capability + "|" + o.Query.Tool + "|" + string(o.Result) + "|" +
		string(o.Completeness) + "|" + o.ScopeHash + "|" + strings.Join(subs, ",")
}

// falsifierRefSignature resolves a condition falsifier/contestant
// reference into its attempt-stable fingerprint: proof ids stand
// (deterministic artifacts), claim refs map to the claim signature
// plus the admitted-observation fingerprints the falsification stood on.
func falsifierRefSignature(ref string, sigByID map[string]string, obsFpByID map[string][]string, condFp map[string]string) string {
	switch {
	case strings.HasPrefix(ref, "proof:"):
		return ref
	case strings.HasPrefix(ref, "claim:"):
		id := strings.TrimPrefix(ref, "claim:")
		sig := sigByID[id]
		if sig == "" {
			return ref
		}
		fps := append([]string(nil), obsFpByID[id]...)
		sort.Strings(fps)
		return "claim[" + shortHash([]byte(sig)) + "](obs:" + strings.Join(fps, ",") + ")"
	case strings.HasPrefix(ref, "condition:"):
		id := strings.TrimPrefix(ref, "condition:")
		if fp := condFp[id]; fp != "" {
			return fp
		}
		return ref
	}
	return ref
}

// computeSurfaces builds the two stability projections of one report:
// the semantic hash over every claim's signature + outcome (the surface
// LLM retries may legitimately move) and the decisive surface over
// conditions, rules, decision, proofs and conflicts (the surface a
// reduction must survive unchanged).
func computeSurfaces(in Input, ctx *evalContext, claims []claimshape.CanonicalClaim, evals []claimEvalOut, rep Report) (string, DecisiveSurface) {
	sigByID := map[string]string{}
	semParts := make([]string, 0, len(evals))
	obsFpByID := map[string][]string{}
	for i, ev := range evals {
		sigByID[ev.ClaimID] = claimSignature(claims[i])
		var admittedFps []string
		for _, g := range ev.Groups {
			for _, adm := range g.Observations {
				if !adm.Admitted {
					continue
				}
				for j := range ev.boundObs {
					if ev.boundObs[j].ID == adm.ObservationID {
						admittedFps = append(admittedFps, obsFingerprint(ev.boundObs[j]))
					}
				}
			}
		}
		sort.Strings(admittedFps)
		obsFpByID[ev.ClaimID] = admittedFps
		var grp strings.Builder
		for _, g := range ev.Groups {
			if g.Established == "context_excluded" {
				continue
			}
			if grp.Len() > 0 {
				grp.WriteString(";")
			}
			grp.WriteString(g.Established)
		}
		semParts = append(semParts, semanticSignature(claims[i])+"|"+string(ev.Outcome)+"|"+
			string(ev.Predicate)+"|"+grp.String())
	}
	sort.Strings(semParts)
	semanticHash := fullHash(canonicalJSON(semParts))

	d := DecisiveSurface{Disposition: rep.Decision().Disposition}
	condFp := map[string]string{}
	if rep.Graph != nil {
		for _, cond := range rep.Graph.Conditions {
			falsifiers := make([]string, 0, len(cond.Falsifiers))
			for _, f := range cond.Falsifiers {
				falsifiers = append(falsifiers, falsifierRefSignature(f, sigByID, obsFpByID, condFp))
			}
			contested := make([]string, 0, len(cond.Contested))
			for _, f := range cond.Contested {
				contested = append(contested, falsifierRefSignature(f, sigByID, obsFpByID, condFp))
			}
			expected := make([]string, 0, len(cond.ExpectedSubjects))
			for _, s := range cond.ExpectedSubjects {
				expected = append(expected, subjectKey(s))
			}
			sort.Strings(falsifiers)
			sort.Strings(contested)
			sort.Strings(expected)
			shapes := make([]string, 0, len(cond.Shapes))
			for _, s := range cond.Shapes {
				shapes = append(shapes, string(s))
			}
			sort.Strings(shapes)
			fp := cond.Mandatory + "|" + cond.Value + "|" + string(cond.FalsifiedBy) + "|" +
				strings.Join(shapes, ",") + "|" + strings.Join(expected, ",") + "|" +
				strings.Join(falsifiers, ",") + "|" + strings.Join(contested, ",")
			condFp[cond.ID] = fp
			d.Conditions = append(d.Conditions, fp)
		}
		sort.Strings(d.Conditions)
		for _, r := range rep.Graph.Rules {
			if r.Satisfied {
				d.SatisfiedRules = append(d.SatisfiedRules, r.ID)
			}
		}
		sort.Strings(d.SatisfiedRules)
		for _, p := range rep.Graph.Decision.Premises {
			d.DecisionPremises = append(d.DecisionPremises,
				falsifierRefSignature(p, sigByID, obsFpByID, condFp))
		}
		sort.Strings(d.DecisionPremises)
	}
	if ctx != nil {
		for _, ce := range ctx.certs {
			var viols []string
			for _, v := range ce.violations {
				viols = append(viols, string(v.Class))
			}
			sort.Strings(viols)
			d.Proofs = append(d.Proofs, ce.proof.ID+"|"+string(ce.proof.Status)+"|"+
				string(ce.proof.Basis)+"|"+fmt.Sprint(ce.proof.Mandatory)+"|"+
				strings.Join(viols, ",")+"|"+string(ce.obs.Result)+"|"+
				ce.obs.ScopeHash+"|"+ce.obs.SnapshotHash+"|"+ce.obs.BuildContextHash)
		}
	}
	sort.Strings(d.Proofs)
	for _, ev := range evals {
		if ev.Predicate != PredicateConflicting {
			continue
		}
		var keys []string
		for _, g := range ev.Groups {
			if g.Established == "conflicting" {
				keys = append(keys, g.Key)
			}
		}
		sort.Strings(keys)
		d.Conflicts = append(d.Conflicts, shortHash([]byte(sigByID[ev.ClaimID]))+"@"+strings.Join(keys, ","))
	}
	sort.Strings(d.Conflicts)

	type surface struct {
		Disposition    string   `json:"disposition"`
		Conditions     []string `json:"conditions,omitempty"`
		SatisfiedRules []string `json:"satisfied_rules,omitempty"`
		Premises       []string `json:"premises,omitempty"`
		Proofs         []string `json:"proofs,omitempty"`
		Conflicts      []string `json:"conflicts,omitempty"`
	}
	d.Hash = fullHash(canonicalJSON(surface{
		Disposition:    d.Disposition,
		Conditions:     d.Conditions,
		SatisfiedRules: d.SatisfiedRules,
		Premises:       d.DecisionPremises,
		Proofs:         d.Proofs,
		Conflicts:      d.Conflicts,
	}))
	return semanticHash, d
}

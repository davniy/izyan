package verify

import (
	"sort"

	"github.com/fedorovmv/izyan/internal/evidencetools"
	"github.com/fedorovmv/izyan/internal/productb/claimshape"
	triage "github.com/fedorovmv/izyan/internal/productb/triage"
)

// certEval is one persisted falsifier proof under the generic proof
// certificate contract: the shared validator's verdict plus the contract
// Observation the proof mints for its check shape. A proof is never an
// authority by itself — its certificate must pass the same admission
// machinery every capability observation faces.
type certEval struct {
	proof      triage.FalsifierProof
	shape      claimshape.Shape
	violations []triage.ProofViolation
	obs        Observation
}

// evalContext carries the run-level bindings claim evaluation needs:
// the effective snapshot identity and the contract-evaluated proof
// certificates of the run's falsifier report.
type evalContext struct {
	snap      string
	certs     []*certEval
	proposals map[string]triage.FalsifierProposal
}

// newEvalContext prepares the certificate capability view of the run:
// proposals are reconstructed from the claims' bound-proposal records
// (the persisted assessment view the verifier answered), every proof is
// validated against the generic certificate contract, and report-level
// violations attach to every proof the report carries — a tampered
// report admits nothing. claims is the merged claim set evaluation
// consumes; challenge-minted claims carry no bound proposals, so they
// never enter the proposal index.
func newEvalContext(in Input, claims []claimshape.CanonicalClaim) *evalContext {
	snap := in.SnapshotHash
	if snap == "" {
		snap = consensusSnapshot(in.Observations)
	}
	proposals := map[string]triage.FalsifierProposal{}
	for _, c := range claims {
		claimID := c.ID
		if claimID == "" {
			claimID = c.Source.ClaimID
		}
		for _, bp := range boundProposals(c) {
			proposals[bp.ID] = triage.FalsifierProposal{
				ID: bp.ID, ClaimID: claimID, ConditionID: bp.ConditionID,
				Kind: triage.FalsifierKind(bp.Kind),
			}
		}
	}
	ctx := &evalContext{snap: snap, proposals: proposals}
	if in.Falsifiers == nil {
		return ctx
	}
	var reportGaps []string
	for _, v := range triage.ValidateProofReport(*in.Falsifiers) {
		reportGaps = append(reportGaps, "certificate_violation:"+string(v.Class))
	}
	for _, p := range in.Falsifiers.Proofs {
		ce := &certEval{
			proof:      p,
			shape:      claimshape.CheckShapeForFalsifierKind(p.Kind),
			violations: triage.ValidateProofCertificate(p, proposals, snap),
		}
		obs := Observation{
			ID:               "proof:" + p.ID,
			Capability:       CapFalsifierCertificate,
			Result:           proofResult(p),
			Completeness:     certCompleteness(p.Coverage.Completeness),
			SnapshotHash:     p.Coverage.SnapshotHash,
			BuildContextHash: p.Coverage.BuildContextHash,
			ScopeHash:        certScopeHash(p),
			ToolVersion:      certToolVersion(p),
			RunID:            in.RunID,
			SourceID:         "proof:" + p.ID,
			EvidenceRefs:     append([]string(nil), p.EvidenceRefs...),
		}
		obs.ClosedScope = p.Coverage.Completeness == "COMPLETE" &&
			len(p.Coverage.SkippedPackages) == 0 &&
			len(p.Coverage.UnresolvedDispatch) == 0 &&
			len(p.Coverage.DynamicMarkers) == 0 &&
			len(p.Coverage.OpenExceptions) == 0
		for _, s := range p.Coverage.CheckedSubjects {
			obs.CoveredSubjects = append(obs.CoveredSubjects, falsifierSubject(s))
		}
		gaps := append([]string(nil), reportGaps...)
		for _, v := range ce.violations {
			gaps = append(gaps, "certificate_violation:"+string(v.Class))
			obs.Limitations = append(obs.Limitations, v.Reason)
		}
		obs.OpenGaps = dedup(gaps)
		ce.obs = obs
		ctx.certs = append(ctx.certs, ce)
	}
	sort.Slice(ctx.certs, func(i, j int) bool { return ctx.certs[i].proof.ID < ctx.certs[j].proof.ID })
	return ctx
}

// proofResult projects the verifier's proof status onto the observation
// result vocabulary: VERIFIED is successful negative verification
// (SUPPORTS the absence/unreachability predicate), CONTRADICTED is the
// recorded counterexample, every other status cannot adjudicate.
func proofResult(p triage.FalsifierProof) Result {
	switch p.Status {
	case triage.FalsifierVerified:
		return ResultSupports
	case triage.FalsifierContradicted:
		return ResultRefutes
	}
	return ResultUnknown
}

// certCompleteness maps the certificate's coverage completeness onto the
// contract ladder; an unrecognized value reads as unknown coverage.
func certCompleteness(c string) evidencetools.Completeness {
	switch evidencetools.Completeness(c) {
	case evidencetools.CompletenessComplete:
		return evidencetools.CompletenessComplete
	case evidencetools.CompletenessPartial:
		return evidencetools.CompletenessPartial
	}
	return evidencetools.CompletenessUnknown
}

// certScopeHash binds the certificate to the scope it proved: the explicit
// scope or closure hash wins, otherwise a deterministic digest of the
// recorded coverage pins the universe the checker enumerated.
func certScopeHash(p triage.FalsifierProof) string {
	if p.Coverage.ScopeHash != "" {
		return p.Coverage.ScopeHash
	}
	if p.Coverage.ClosureHash != "" {
		return p.Coverage.ClosureHash
	}
	return "proof-scope:" + shortHash(canonicalJSON(p.Coverage))
}

// certToolVersion pins the producing checker's rule identity.
func certToolVersion(p triage.FalsifierProof) string {
	if p.RuleID != "" {
		return p.RuleID + "@" + p.RuleVersion
	}
	return "falsifier_certificate@1"
}

// falsifierSubject renders a coverage subject into the canonical form.
func falsifierSubject(s triage.FalsifierSubject) claimshape.Subject {
	return claimshape.Subject{
		Kind:    claimshape.SubjectSymbol,
		Package: s.Package,
		Symbol:  s.Symbol,
		Name:    s.Package + "." + s.Symbol,
	}
}

// certificateObservations mints the falsifier_certificate observations a
// claim may consume: one per certificate whose check shape serves the
// claim's shape and whose binding reaches the claim — through the
// proposal the claim carried, the claim id the proof names, or the
// checker-minted coverage of the claim's subjects.
func certificateObservations(ctx *evalContext, in Input, c claimshape.CanonicalClaim) []Observation {
	if ctx == nil || Contract(CapFalsifierCertificate, c.Shape) == nil {
		return nil
	}
	var out []Observation
	for _, ce := range ctx.certs {
		if ce.shape != c.Shape {
			continue
		}
		if !certBindsClaim(ctx, ce, c) {
			continue
		}
		obs := ce.obs
		obs.ID = "proof:" + ce.proof.ID + "#" + c.ID
		obs.Query = Query{Shape: c.Shape, Subject: c.Subject, Tool: "falsifier_certificate"}
		out = append(out, obs)
	}
	return out
}

// certBindsClaim reports whether a certificate answers this claim: the
// proof names the claim or one of its bound proposals, or the proof is
// checker-minted and its coverage covers the claim's subjects.
func certBindsClaim(ctx *evalContext, ce *certEval, c claimshape.CanonicalClaim) bool {
	p := ce.proof
	if p.ClaimID != "" && (p.ClaimID == c.ID || p.ClaimID == c.Source.ClaimID) {
		return true
	}
	if p.ProposalID != "" {
		for _, bp := range boundProposals(c) {
			if bp.ID == p.ProposalID {
				return true
			}
		}
		return false
	}
	if !triage.CheckerMintedProof(p) {
		return false
	}
	// Checker-minted certificate: binds by coverage — it checked the very
	// subjects the claim asserts.
	for _, cs := range ce.obs.CoveredSubjects {
		for _, want := range append([]claimshape.Subject{c.Subject}, paramSubjects(c, "subjects")...) {
			if subjectMatches(want, cs) {
				return true
			}
		}
	}
	return false
}

// boundProposals decodes a claim's bound-proposal parameter, tolerating
// the typed extraction form and a generic JSON decode alike.
func boundProposals(c claimshape.CanonicalClaim) []claimshape.BoundProposal {
	switch v := c.Parameters["bound_proposals"].(type) {
	case []claimshape.BoundProposal:
		return v
	case []any:
		var out []claimshape.BoundProposal
		for _, item := range v {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			bp := claimshape.BoundProposal{
				ID:          strOf(m, "id"),
				Kind:        strOf(m, "kind"),
				ConditionID: strOf(m, "condition_id"),
				CheckShape:  claimshape.Shape(strOf(m, "check_shape")),
				ProofStatus: strOf(m, "proof_status"),
				ProofBasis:  strOf(m, "proof_basis"),
			}
			for _, s := range listOf(m, "subjects") {
				if sm, ok := s.(map[string]any); ok {
					bp.Subjects = append(bp.Subjects, claimshape.Subject{
						Kind:    claimshape.SubjectKind(strOf(sm, "kind")),
						Name:    strOf(sm, "name"),
						Package: strOf(sm, "package"),
						Symbol:  strOf(sm, "symbol"),
					})
				}
			}
			for _, r := range listOf(m, "evidence_refs") {
				if s, ok := r.(string); ok {
					bp.EvidenceRefs = append(bp.EvidenceRefs, s)
				}
			}
			if mv, ok := m["proof_mandatory"].(bool); ok {
				bp.ProofMandatory = &mv
			}
			out = append(out, bp)
		}
		return out
	}
	return nil
}

// consensusSnapshot returns the snapshot identity every recorded
// observation agrees on — the run's provenance pin when no explicit one
// was supplied. Disagreement resolves to empty rather than picking a
// winner: a mixed archive has no single snapshot to bind against.
func consensusSnapshot(obs []triage.RecordedObservation) string {
	counts := map[string]int{}
	for i := range obs {
		data, top := payloadEnvelope(&obs[i])
		if h := snapshotHashOf(&obs[i], data, top); h != "" {
			counts[h]++
		}
	}
	best, n := "", 0
	for h, c := range counts {
		if c > n || (c == n && h < best) {
			best, n = h, c
		}
	}
	return best
}

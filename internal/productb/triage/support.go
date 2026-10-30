package triage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/davniy/izyan/internal/evidencetools"
)

// SupportLevel is the deterministically derived strength of the decisive
// premise graph. It is a property of the recorded grounds, never a
// probability of correctness: INSUFFICIENT means a required input is
// missing, LIMITED means at least one decisive premise is assumed,
// unresolved, conflicting, ungrounded or structurally overstated,
// SUBSTANTIATED means every decisive factual leaf verifies and every
// interpretation transition is explicit and grounded, and
// PROVED_WITHIN_SCOPE means an admitted proof contract covers the proposed
// conclusion inside the recorded record scope.
type SupportLevel string

const (
	SupportLevelInsufficient      SupportLevel = "INSUFFICIENT"
	SupportLevelLimited           SupportLevel = "LIMITED"
	SupportLevelSubstantiated     SupportLevel = "SUBSTANTIATED"
	SupportLevelProvedWithinScope SupportLevel = "PROVED_WITHIN_SCOPE"
)

func (l SupportLevel) Valid() bool {
	switch l {
	case SupportLevelInsufficient, SupportLevelLimited, SupportLevelSubstantiated, SupportLevelProvedWithinScope:
		return true
	}
	return false
}

// Decision boundary markers of a decision scope. EXACT_RECORDS names the
// captured advisory records the conclusion is bound to; INPUT_MATERIAL_ONLY
// means no advisory material with a recorded digest was captured, so no
// record-scoped conclusion can be established.
const (
	DecisionBoundaryExactRecords      = "EXACT_RECORDS"
	DecisionBoundaryInputMaterialOnly = "INPUT_MATERIAL_ONLY"
)

// AdvisoryRecordRef is one captured input/advisory record identity: its
// resolved id and the sha256 of the frozen document. A digest is never
// synthesized.
type AdvisoryRecordRef struct {
	ID     string `json:"id"`
	SHA256 string `json:"sha256"`
}

// DecisionScope records what the decision actually covers: the pinned
// snapshot, the requested Stage 0 identities, the captured records (a frozen
// advisory or, on the compatibility transport, the finding record), the
// record boundary and the boundaries that stay open. It never manufactures a
// CVE-wide scope from a single advisory or from the first requested id.
type DecisionScope struct {
	SnapshotHash   string              `json:"snapshot_hash,omitempty"`
	RequestedIDs   []string            `json:"requested_ids,omitempty"`
	Records        []AdvisoryRecordRef `json:"records,omitempty"`
	Boundary       string              `json:"boundary"`
	OpenBoundaries []string            `json:"open_boundaries,omitempty"`
}

// DecisionPremise is one decisive premise of the proposed action, derived
// from the claim but not authored by it: the model statement is preserved
// verbatim, Basis is the computed basis rather than the declared one, and
// the source metadata (subject scope, digests, completeness, boundaries) is
// carried from the recorded source, never copied from model-declared
// coverage.
type DecisionPremise struct {
	ClaimID                string       `json:"claim_id"`
	Statement              string       `json:"statement"`
	Basis                  PremiseBasis `json:"basis"`
	EstablishedProposition string       `json:"established_proposition,omitempty"`
	Subject                string       `json:"subject"`
	Scope                  string       `json:"scope"`
	DependsOn              []string     `json:"depends_on,omitempty"`
	SourceRefs             []string     `json:"source_refs,omitempty"`
	SourceDigests          []string     `json:"source_digests,omitempty"`
	Completeness           string       `json:"completeness,omitempty"`
	OpenBoundaries         []string     `json:"open_boundaries,omitempty"`
	Owner                  string       `json:"owner,omitempty"`
	Reasons                []string     `json:"reasons,omitempty"`
}

// DecisionSupport is the support verdict over the decisive premise graph.
// DecisiveClaimIDs is the evaluated closure (the action's decisive claims
// plus every claim they depend on); ProofIDs names only the checker-minted
// proofs that actually grounded a decisive premise.
type DecisionSupport struct {
	Level            SupportLevel `json:"level"`
	DecisiveClaimIDs []string     `json:"decisive_claim_ids"`
	ProofIDs         []string     `json:"proof_ids,omitempty"`
	Reasons          []string     `json:"reasons,omitempty"`
}

// SupportInput is everything DeriveSupport is allowed to consult: the
// resolved Stage 0 identity/material, the model-authored assessment, the
// fact-gate validation, the selected attempt's recorded observations, the
// structured decision facts, the verifier report and the stability report.
// None of it grants authority; support remains a human-package attribute.
type SupportInput struct {
	Stage0          Stage0Result
	Assessment      Assessment
	Validation      FactValidation
	Observations    []RecordedObservation
	Facts           []DecisionFact
	Falsifiers      *FalsifierReport
	SelectedAttempt int
	Stability       *StabilityReport
}

// SupportResult is the derived support plus the premise graph it rests on.
type SupportResult struct {
	Scope    DecisionScope     `json:"scope"`
	Premises []DecisionPremise `json:"premises"`
	Support  DecisionSupport   `json:"support"`
}

// resolvedBinding is the narrow, record-backed reading of one premise
// binding: what the record itself establishes and the source metadata that
// must travel with it.
type resolvedBinding struct {
	established   string
	subject       string
	proofID       string
	scope         string
	completeness  string
	sourceRefs    []string
	sourceDigests []string
	open          []string
}

type premiseEvaluation struct {
	premise      DecisionPremise
	grounded     bool
	factGrounded bool
	proofID      string
	caps         []string
}

type supportContext struct {
	in           SupportInput
	snapshotHash string
	evidence     map[string]EvidenceRef
	observations map[string]RecordedObservation
	checks       map[string]ReferenceCheck
	proposals    map[string]FalsifierProposal
	proofs       map[string]FalsifierProof
	reportHash   string
}

// DeriveSupport computes support as a deterministic traversal of the
// proposed action's decisive claim closure. Only that closure is evaluated:
// a partial observation or unresolved background claim outside the closure
// stays visible in the assessment without automatically lowering support.
// The result is a level plus the premise graph, never a numeric confidence.
func DeriveSupport(in SupportInput) (SupportResult, error) {
	if err := ValidateHumanAssessment(in.Assessment); err != nil {
		return SupportResult{}, fmt.Errorf("derive support: %w", err)
	}
	ctx, err := newSupportContext(in)
	if err != nil {
		return SupportResult{}, err
	}

	result := SupportResult{Scope: deriveDecisionScope(in.Stage0)}
	if missing := missingDecisionInput(result.Scope); missing != "" &&
		in.Assessment.ProposedAction.Kind != HumanActionObtainEvidence {
		return SupportResult{}, fmt.Errorf(
			"derive support: proposed action %s cannot be delivered because %s; revise proposed_action to OBTAIN_EVIDENCE",
			in.Assessment.ProposedAction.Kind, missing)
	}
	claims := make(map[string]*Claim, len(in.Assessment.Claims))
	for i := range in.Assessment.Claims {
		claims[in.Assessment.Claims[i].ID] = &in.Assessment.Claims[i]
	}
	closure := decisiveClaimClosure(in.Assessment.ProposedAction, claims)
	evals := make(map[string]*premiseEvaluation, len(closure))
	for _, id := range sortedIDs(closure) {
		ev := ctx.evaluateClaim(claims[id])
		evals[id] = &ev
	}
	settleInterpretations(evals)
	propagateFactGrounding(evals)

	proofIDs := make([]string, 0)
	caps := make([]string, 0)
	for _, id := range sortedIDs(closure) {
		ev := evals[id]
		result.Premises = append(result.Premises, ev.premise)
		if len(ev.caps) > 0 {
			caps = append(caps, ev.caps...)
		}
		if ev.proofID != "" {
			proofIDs = append(proofIDs, ev.proofID)
		}
	}
	caps = append(caps, ctx.contradictionCaps(closure, claims)...)
	caps = append(caps, evaluateCounterarguments(in.Assessment.Counterarguments, evals)...)
	caps = append(caps, stabilityCaps(in.Stability)...)
	caps = dedupeStrings(caps)

	result.Support = deriveSupportLevel(result.Scope, result.Premises, evals, in, dedupeStrings(proofIDs), caps)
	return result, nil
}

// deriveSupportLevel selects the level from the evaluated closure. There is
// no default high value: a clean graph must positively satisfy the level's
// structural contract.
func deriveSupportLevel(
	scope DecisionScope,
	premises []DecisionPremise,
	evals map[string]*premiseEvaluation,
	in SupportInput,
	proofIDs []string,
	caps []string,
) DecisionSupport {
	ids := make([]string, 0, len(evals))
	for id := range evals {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	support := DecisionSupport{DecisiveClaimIDs: ids, ProofIDs: proofIDs}

	if missing := missingDecisionInput(scope); missing != "" {
		support.Level = SupportLevelInsufficient
		support.Reasons = append([]string{missing}, caps...)
		return support
	}
	if len(caps) > 0 {
		support.Level = SupportLevelLimited
		support.Reasons = caps
		return support
	}

	admissible := admissibleRecordIDs(scope, in.Stage0)
	if reason := undeclaredActionRecord(in.Assessment.ProposedAction, admissible); reason != "" {
		support.Level = SupportLevelLimited
		support.Reasons = []string{reason}
		return support
	}

	measured, proved, interpreted, factual := 0, 0, 0, 0
	var directProof, directScope string
	direct := make(map[string]bool, len(in.Assessment.ProposedAction.DecisiveClaimIDs))
	for _, id := range in.Assessment.ProposedAction.DecisiveClaimIDs {
		direct[id] = true
	}
	for _, id := range ids {
		ev := evals[id]
		if ev.factGrounded {
			factual++
		}
		switch ev.premise.Basis {
		case PremiseMeasured:
			measured++
		case PremiseProved:
			proved++
			if direct[ev.premise.ClaimID] && directProof == "" {
				directProof = ev.proofID
				directScope = ev.premise.Scope
			}
		case PremiseInterpreted:
			interpreted++
		}
	}
	if factual == 0 {
		support.Level = SupportLevelLimited
		support.Reasons = []string{"no decisive premise resolves to a measured or proved factual leaf; interpretations alone cannot substantiate the action"}
		return support
	}
	support.Level = SupportLevelSubstantiated
	support.Reasons = []string{fmt.Sprintf(
		"%d decisive premise(s) evaluated: %d measured, %d proved, %d explicitly interpreted; %d grounded in a recorded fact",
		len(premises), measured, proved, interpreted, factual)}

	if interpreted == 0 && proved > 0 && directProof != "" && directScope != "" &&
		scope.Boundary == DecisionBoundaryExactRecords && len(scope.Records) > 0 &&
		actionRecordScopeCovered(in.Assessment.ProposedAction, admissible) &&
		normalizePropositionText(in.Assessment.ProposedAction.Scope) == normalizePropositionText(directScope) {
		support.Level = SupportLevelProvedWithinScope
		support.Reasons = []string{fmt.Sprintf(
			"admitted proof %q covers the proposed conclusion and every decisive premise is measured or proved within the recorded record scope",
			directProof)}
	}
	return support
}

// admissibleRecordIDs returns the record ids a scoped proved conclusion may
// name: the captured advisory records plus explicit aliases the resolved
// advisory document declares, but only when that document's digest is the
// captured one. Requested-but-uncaptured ids are never admissible.
func admissibleRecordIDs(scope DecisionScope, s0 Stage0Result) map[string]bool {
	out := map[string]bool{}
	capturedDigests := map[string]bool{}
	for _, ref := range scope.Records {
		if id := strings.TrimSpace(ref.ID); id != "" {
			out[id] = true
		}
		if sha := strings.TrimSpace(ref.SHA256); sha != "" {
			capturedDigests[sha] = true
		}
	}
	if s0.Resolution != nil && s0.Resolution.Vulnerability != nil &&
		capturedDigests[strings.TrimSpace(s0.Resolution.Record.SHA256)] {
		if id := strings.TrimSpace(s0.Resolution.Vulnerability.ID); id != "" {
			out[id] = true
		}
		for _, alias := range s0.Resolution.Vulnerability.Aliases {
			if alias = strings.TrimSpace(alias); alias != "" {
				out[alias] = true
			}
		}
	}
	// Explicit aliases of captured records resolve only inside the
	// captured set: each record remains its own scope entry, and an alias
	// never widens the record it belongs to into another record's identity.
	for _, rec := range s0.Investigation.Records {
		if id := strings.TrimSpace(rec.RecordID); id != "" {
			out[id] = true
		}
		for _, alias := range rec.Aliases {
			if alias = strings.TrimSpace(alias); alias != "" {
				out[alias] = true
			}
		}
	}
	return out
}

// actionRecordScopeCovered reports whether the proposed action declares a
// non-empty record scope entirely inside the admissible records. A missing
// or foreign action record id cannot support a PROVED_WITHIN_SCOPE result,
// and the recorded action is never rewritten to make it fit.
func actionRecordScopeCovered(act HumanAction, admissible map[string]bool) bool {
	if len(act.RecordIDs) == 0 {
		return false
	}
	for _, id := range act.RecordIDs {
		if !admissible[strings.TrimSpace(id)] {
			return false
		}
	}
	return true
}

// undeclaredActionRecord names the first action record id that is neither a
// captured record nor an explicitly verified alias. A non-empty residue is a
// scope contradiction and caps support; an empty action record list declares
// no scope and simply cannot reach PROVED_WITHIN_SCOPE.
func undeclaredActionRecord(act HumanAction, admissible map[string]bool) string {
	for _, id := range act.RecordIDs {
		trimmed := strings.TrimSpace(id)
		if !admissible[trimmed] {
			return fmt.Sprintf(
				"proposed action record %q is not a captured advisory record or a verified alias; a scoped proved conclusion cannot name it",
				trimmed)
		}
	}
	return ""
}

// missingDecisionInput names the required identity/material that a
// substantive support claim would need. A missing input produces
// INSUFFICIENT, never a default level.
func missingDecisionInput(scope DecisionScope) string {
	if len(scope.RequestedIDs) == 0 && len(scope.Records) == 0 {
		return "vulnerability identity and advisory material are missing from the recorded Stage 0 result; only an evidence-gathering action (OBTAIN_EVIDENCE) is deliverable"
	}
	if len(scope.Records) == 0 {
		return "no advisory material with a recorded digest was captured; only an evidence-gathering action (OBTAIN_EVIDENCE) is deliverable"
	}
	if strings.TrimSpace(scope.SnapshotHash) == "" {
		return "no pinned source snapshot was recorded; only an evidence-gathering action (OBTAIN_EVIDENCE) is deliverable"
	}
	return ""
}

// deriveDecisionScope builds the scope from recorded Stage 0 identities
// only. A missing corpus declaration never blocks EXACT_RECORDS; the scope
// simply names the captured records. Missing input material produces
// INPUT_MATERIAL_ONLY with no invented digest.
func deriveDecisionScope(s0 Stage0Result) DecisionScope {
	scope := DecisionScope{
		SnapshotHash: strings.TrimSpace(s0.Snapshot.ContentHash),
		Boundary:     DecisionBoundaryExactRecords,
	}
	ids := map[string]bool{}
	for _, id := range s0.Proposal.VulnerabilityIDs {
		if id = strings.TrimSpace(id); id != "" {
			ids[id] = true
		}
	}
	for _, id := range s0.Input.Finding.Vulnerability.IDs {
		if id = strings.TrimSpace(id); id != "" {
			ids[id] = true
		}
	}
	if len(ids) == 0 {
		if id := strings.TrimSpace(s0.Advisory.ID); id != "" {
			ids[id] = true
		} else if id := strings.TrimSpace(s0.Advisory.ResolvedID); id != "" {
			ids[id] = true
		}
	}
	scope.RequestedIDs = sortedIDs(ids)

	// Records are every captured advisory document the run actually
	// considered: the Stage 0 selected frozen document first, then the
	// supplied set in declaration order. They are distinct records, never
	// aliases of one another and never a declared CVE corpus.
	type recordKey struct{ id, sha string }
	seen := map[recordKey]bool{}
	addRecord := func(id, sha string, partial bool, partialNote string) {
		id, sha = strings.TrimSpace(id), strings.TrimSpace(sha)
		if id == "" || sha == "" {
			return
		}
		key := recordKey{id, sha}
		if seen[key] {
			return
		}
		seen[key] = true
		scope.Records = append(scope.Records, AdvisoryRecordRef{ID: id, SHA256: sha})
		if partial && partialNote != "" {
			scope.OpenBoundaries = append(scope.OpenBoundaries, partialNote)
		}
	}

	record := s0.Advisory
	if s0.Resolution != nil && strings.TrimSpace(s0.Resolution.Record.SHA256) != "" {
		record = s0.Resolution.Record
	}
	recordID := strings.TrimSpace(record.ResolvedID)
	if recordID == "" {
		recordID = strings.TrimSpace(record.ID)
	}
	addRecord(recordID, record.SHA256, record.Partial,
		"the captured advisory projection is partial: only the fields the source supplied are asserted")
	for _, captured := range s0.Investigation.Records {
		addRecord(captured.RecordID, captured.SHA256, captured.Partial,
			fmt.Sprintf("captured advisory record %s is partial: only the fields its source supplied are asserted", captured.RecordID))
	}
	if len(scope.Records) == 0 {
		scope.Boundary = DecisionBoundaryInputMaterialOnly
		scope.OpenBoundaries = append(scope.OpenBoundaries,
			"no advisory material with a recorded digest was captured; the decision rests on the input material only")
	}
	if s0.Resolution != nil && s0.Resolution.Partial {
		scope.OpenBoundaries = append(scope.OpenBoundaries,
			"the advisory resolution is partial: only the fields the resolved source supplied are asserted")
	}
	if scope.SnapshotHash == "" {
		scope.OpenBoundaries = append(scope.OpenBoundaries, "the source snapshot is not pinned")
	}
	scope.OpenBoundaries = dedupeStrings(scope.OpenBoundaries)
	return scope
}

func newSupportContext(in SupportInput) (*supportContext, error) {
	ctx := &supportContext{
		in:           in,
		snapshotHash: strings.TrimSpace(in.Stage0.Snapshot.ContentHash),
		evidence:     make(map[string]EvidenceRef, len(in.Assessment.Evidence)),
		observations: make(map[string]RecordedObservation, len(in.Observations)),
		checks:       make(map[string]ReferenceCheck, len(in.Validation.References)),
		proposals:    make(map[string]FalsifierProposal, len(in.Assessment.FalsifierProposals)),
		proofs:       make(map[string]FalsifierProof),
	}
	for _, ev := range in.Assessment.Evidence {
		ctx.evidence[ev.ID] = ev
	}
	for _, obs := range in.Observations {
		key := normalizeObservationID(obs.ID)
		if key == "" {
			continue
		}
		if _, dup := ctx.observations[key]; dup {
			// The first recorded archive entry is canonical.
			continue
		}
		ctx.observations[key] = obs
	}
	for _, rc := range in.Validation.References {
		if rc.EvidenceID == "" {
			continue
		}
		if existing, ok := ctx.checks[rc.EvidenceID]; ok && existing.Status == FactValid && rc.Status != FactValid {
			ctx.checks[rc.EvidenceID] = rc
			continue
		}
		if _, ok := ctx.checks[rc.EvidenceID]; !ok {
			ctx.checks[rc.EvidenceID] = rc
		}
	}
	for _, p := range in.Assessment.FalsifierProposals {
		ctx.proposals[p.ID] = p
	}
	if in.Falsifiers != nil {
		if violations := ValidateProofReport(*in.Falsifiers); len(violations) > 0 {
			return nil, fmt.Errorf("derive support: %s", proofViolationText("falsifier report", violations))
		}
		for _, proof := range in.Falsifiers.Proofs {
			if violations := ValidateProofCertificate(proof, ctx.proposals, ctx.snapshotHash); len(violations) > 0 {
				return nil, fmt.Errorf("derive support: %s", proofViolationText("falsifier proof "+proof.ID, violations))
			}
			ctx.proofs[proof.ID] = proof
		}
		ctx.reportHash = in.Falsifiers.Hash
	}
	return ctx, nil
}

func proofViolationText(subject string, violations []ProofViolation) string {
	parts := make([]string, 0, len(violations))
	for _, v := range violations {
		parts = append(parts, string(v.Class)+": "+v.Reason)
	}
	return subject + " failed certificate validation: " + strings.Join(parts, "; ")
}

// evaluateClaim resolves one claim's declared basis against the recorded
// sources. The model statement is preserved verbatim; the computed basis
// reports what the records actually establish.
func (c *supportContext) evaluateClaim(claim *Claim) premiseEvaluation {
	ev := premiseEvaluation{}
	p := &ev.premise
	p.ClaimID = claim.ID
	p.Statement = claim.Statement
	p.Subject = claim.Subject
	p.Scope = claim.Scope
	p.DependsOn = sortedStrings(append([]string(nil), claim.DependsOn...))
	p.Owner = claim.Owner

	if claim.Basis == PremiseAssumed {
		p.Basis = PremiseAssumed
		p.Reasons = append(p.Reasons, fmt.Sprintf(
			"external assumption owned by %q is not established by this run", claim.Owner))
		ev.caps = append(ev.caps, fmt.Sprintf(
			"claim %q is an unresolved external assumption (owner %q)", claim.ID, claim.Owner))
		return ev
	}
	if claim.Basis == PremiseUnresolved || claim.Basis == PremiseConflicting {
		p.Basis = claim.Basis
		p.Reasons = append(p.Reasons, firstNonEmpty(claim.Reason, "the claim is not established by a recorded source"))
		ev.caps = append(ev.caps, fmt.Sprintf("claim %q is %s: %s", claim.ID, claim.Basis, p.Reasons[0]))
		return ev
	}

	if claim.Binding == nil && claim.Basis != PremiseInterpreted {
		p.Basis = PremiseUnresolved
		p.Reasons = append(p.Reasons, fmt.Sprintf(
			"declared %s but the claim has no premise binding; a citation alone does not establish it", claim.Basis))
		ev.caps = append(ev.caps, fmt.Sprintf(
			"claim %q declares %s without a premise binding", claim.ID, claim.Basis))
		return ev
	}

	switch claim.Basis {
	case PremiseMeasured:
		c.evaluateMeasured(claim, &ev)
	case PremiseProved:
		c.evaluateProved(claim, &ev)
	case PremiseInterpreted:
		c.evaluateInterpreted(claim, &ev)
	}
	return ev
}

func (c *supportContext) evaluateMeasured(claim *Claim, ev *premiseEvaluation) {
	p := &ev.premise
	switch claim.Binding.Kind {
	case BindingObservationFact:
		rb, ok := c.resolveObservationFact(claim)
		if !ok {
			ev.premise.Basis = PremiseUnresolved
			ev.caps = append(ev.caps, fmt.Sprintf("claim %q: %s", claim.ID, rb.established))
			ev.premise.Reasons = append(ev.premise.Reasons, rb.established)
			return
		}
		if sameNarrowProposition(claim.Statement, rb.established) {
			p.Basis = PremiseMeasured
			ev.grounded, ev.factGrounded = true, true
			applyEstablished(p, rb)
			return
		}
		p.Basis = PremiseInterpreted
		ev.grounded, ev.factGrounded = true, true
		applyEstablished(p, rb)
		p.Reasons = append(p.Reasons,
			"the recorded observation establishes only its own narrow fact; the claim statement is the model's interpretation of it")
		ev.caps = append(ev.caps, fmt.Sprintf(
			"claim %q declares MEASURED but states more than the recorded observation fact %q", claim.ID, rb.established))
	case BindingQuotedText:
		rb, ok := c.resolveQuotedText(claim)
		if !ok {
			p.Basis = PremiseUnresolved
			ev.caps = append(ev.caps, fmt.Sprintf("claim %q: %s", claim.ID, rb.established))
			p.Reasons = append(p.Reasons, rb.established)
			return
		}
		p.Basis = PremiseInterpreted
		ev.grounded = true
		applyEstablished(p, rb)
		p.Reasons = append(p.Reasons,
			"a verified quotation establishes the presence of text at its locator, not the claim's interpretation")
		ev.caps = append(ev.caps, fmt.Sprintf(
			"claim %q declares MEASURED but is bound to a quotation, which proves presence of text, not the proposition", claim.ID))
	case BindingFalsifierProof:
		rb, ok := c.resolveFalsifierProof(claim)
		if !ok {
			p.Basis = PremiseUnresolved
			ev.caps = append(ev.caps, fmt.Sprintf("claim %q: %s", claim.ID, rb.established))
			p.Reasons = append(p.Reasons, rb.established)
			return
		}
		p.Basis = PremiseProved
		ev.grounded, ev.factGrounded = true, true
		ev.proofID = rb.proofID
		if match, why := claimExpressesProof(claim, rb.subject, rb.scope, rb.established); !match {
			p.Basis = PremiseInterpreted
			applyEstablished(p, rb)
			p.Reasons = append(p.Reasons,
				"the admitted proof establishes only its own narrow proposition: "+why)
			ev.caps = append(ev.caps, fmt.Sprintf(
				"claim %q declares MEASURED but does not express the proved proposition", claim.ID))
			return
		}
		applyEstablished(p, rb)
		p.Reasons = append(p.Reasons,
			"the admitted proof contract supersedes the declared MEASURED basis")
	}
}

func (c *supportContext) evaluateProved(claim *Claim, ev *premiseEvaluation) {
	p := &ev.premise
	switch claim.Binding.Kind {
	case BindingFalsifierProof:
		rb, ok := c.resolveFalsifierProof(claim)
		if !ok {
			p.Basis = PremiseUnresolved
			ev.caps = append(ev.caps, fmt.Sprintf("claim %q: %s", claim.ID, rb.established))
			p.Reasons = append(p.Reasons, rb.established)
			return
		}
		p.Basis = PremiseProved
		ev.grounded, ev.factGrounded = true, true
		ev.proofID = rb.proofID
		if match, why := claimExpressesProof(claim, rb.subject, rb.scope, rb.established); !match {
			p.Basis = PremiseInterpreted
			applyEstablished(p, rb)
			p.Reasons = append(p.Reasons,
				"the admitted proof establishes only its own narrow proposition: "+why)
			ev.caps = append(ev.caps, fmt.Sprintf(
				"claim %q declares PROVED but does not express the proved proposition", claim.ID))
			return
		}
		applyEstablished(p, rb)
	case BindingObservationFact:
		rb, ok := c.resolveObservationFact(claim)
		if !ok {
			p.Basis = PremiseUnresolved
			ev.caps = append(ev.caps, fmt.Sprintf("claim %q: %s", claim.ID, rb.established))
			p.Reasons = append(p.Reasons, rb.established)
			return
		}
		if sameNarrowProposition(claim.Statement, rb.established) {
			p.Basis = PremiseMeasured
			ev.grounded, ev.factGrounded = true, true
			applyEstablished(p, rb)
			p.Reasons = append(p.Reasons,
				"the binding establishes a measurement; no admitted proof contract covers this claim")
			ev.caps = append(ev.caps, fmt.Sprintf(
				"claim %q declares PROVED but its binding is an observation, not an admitted proof", claim.ID))
			return
		}
		p.Basis = PremiseInterpreted
		ev.grounded, ev.factGrounded = true, true
		applyEstablished(p, rb)
		p.Reasons = append(p.Reasons,
			"the recorded observation establishes only its own narrow fact; the claim statement is the model's interpretation of it")
		ev.caps = append(ev.caps, fmt.Sprintf(
			"claim %q declares PROVED but its binding establishes only a narrow observation", claim.ID))
	case BindingQuotedText:
		rb, ok := c.resolveQuotedText(claim)
		if !ok {
			p.Basis = PremiseUnresolved
			ev.caps = append(ev.caps, fmt.Sprintf("claim %q: %s", claim.ID, rb.established))
			p.Reasons = append(p.Reasons, rb.established)
			return
		}
		p.Basis = PremiseInterpreted
		ev.grounded = true
		applyEstablished(p, rb)
		p.Reasons = append(p.Reasons,
			"a verified quotation establishes the presence of text at its locator, not the claim's interpretation")
		ev.caps = append(ev.caps, fmt.Sprintf(
			"claim %q declares PROVED but is bound to a quotation, which establishes no proof contract", claim.ID))
	}
}

func (c *supportContext) evaluateInterpreted(claim *Claim, ev *premiseEvaluation) {
	p := &ev.premise
	p.Basis = PremiseInterpreted
	if claim.Binding == nil {
		return
	}
	switch claim.Binding.Kind {
	case BindingObservationFact:
		rb, ok := c.resolveObservationFact(claim)
		if !ok {
			p.Basis = PremiseUnresolved
			ev.caps = append(ev.caps, fmt.Sprintf("claim %q: %s", claim.ID, rb.established))
			p.Reasons = append(p.Reasons, rb.established)
			return
		}
		ev.grounded, ev.factGrounded = true, true
		applyEstablished(p, rb)
		p.Reasons = append(p.Reasons, "explicit interpretation grounded in a recorded observation")
	case BindingQuotedText:
		rb, ok := c.resolveQuotedText(claim)
		if !ok {
			p.Basis = PremiseUnresolved
			ev.caps = append(ev.caps, fmt.Sprintf("claim %q: %s", claim.ID, rb.established))
			p.Reasons = append(p.Reasons, rb.established)
			return
		}
		ev.grounded = true
		applyEstablished(p, rb)
		p.Reasons = append(p.Reasons, "explicit interpretation grounded in verified quoted text")
	case BindingFalsifierProof:
		rb, ok := c.resolveFalsifierProof(claim)
		if !ok {
			p.Basis = PremiseUnresolved
			ev.caps = append(ev.caps, fmt.Sprintf("claim %q: %s", claim.ID, rb.established))
			p.Reasons = append(p.Reasons, rb.established)
			return
		}
		ev.grounded, ev.factGrounded = true, true
		ev.proofID = rb.proofID
		applyEstablished(p, rb)
		p.Reasons = append(p.Reasons, "explicit interpretation grounded in an admitted proof contract")
	}
}

// settleInterpretations grounds interpretation claims in the computed
// closure: an interpretation needs a verified source or a dependency that
// itself resolves to a factual leaf. An interpretation that only rests on
// assumptions or other unresolved claims is not established.
func settleInterpretations(evals map[string]*premiseEvaluation) {
	state := make(map[string]uint8, len(evals))
	var grounded func(string) bool
	grounded = func(id string) bool {
		ev := evals[id]
		if ev == nil {
			return false
		}
		switch ev.premise.Basis {
		case PremiseMeasured, PremiseProved:
			return ev.grounded
		case PremiseInterpreted:
			if ev.grounded {
				return true
			}
			if state[id] == 1 {
				return false
			}
			state[id] = 1
			for _, dep := range ev.premise.DependsOn {
				if grounded(dep) {
					ev.grounded = true
					state[id] = 2
					return true
				}
			}
			state[id] = 2
			return false
		default:
			return false
		}
	}
	ids := make([]string, 0, len(evals))
	for id := range evals {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		ev := evals[id]
		if ev.premise.Basis != PremiseInterpreted || ev.grounded {
			continue
		}
		if grounded(id) {
			continue
		}
		ev.premise.Basis = PremiseUnresolved
		reason := "the interpretation has no grounded factual dependency or verified source"
		ev.premise.Reasons = append(ev.premise.Reasons, reason)
		ev.caps = append(ev.caps, fmt.Sprintf("claim %q: %s", id, reason))
	}
}

// propagateFactGrounding marks an interpretation as resting on a recorded
// fact when any of its closure dependencies is itself fact-grounded. A
// verified quotation is presence evidence, not a measured or proved fact,
// so it does not become a factual leaf on its own.
func propagateFactGrounding(evals map[string]*premiseEvaluation) {
	state := make(map[string]uint8, len(evals))
	var grounded func(string) bool
	grounded = func(id string) bool {
		ev := evals[id]
		if ev == nil {
			return false
		}
		if ev.factGrounded {
			return true
		}
		if ev.premise.Basis != PremiseInterpreted {
			return false
		}
		if state[id] == 1 {
			return false
		}
		state[id] = 1
		for _, dep := range ev.premise.DependsOn {
			if grounded(dep) {
				ev.factGrounded = true
				state[id] = 2
				return true
			}
		}
		state[id] = 2
		return false
	}
	ids := make([]string, 0, len(evals))
	for id := range evals {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		grounded(id)
	}
}

func applyEstablished(p *DecisionPremise, rb resolvedBinding) {
	p.EstablishedProposition = rb.established
	applySource(p, rb)
}

func applySource(p *DecisionPremise, rb resolvedBinding) {
	if rb.scope != "" {
		p.Scope = rb.scope
	}
	p.Completeness = rb.completeness
	p.SourceRefs = dedupeStrings(append(p.SourceRefs, rb.sourceRefs...))
	p.SourceDigests = dedupeStrings(append(p.SourceDigests, rb.sourceDigests...))
	p.OpenBoundaries = dedupeStrings(append(p.OpenBoundaries, rb.open...))
}

// resolveObservationFact verifies an OBSERVATION_FACT binding: canonical
// locator, selected-attempt ownership, recorded status, payload digest,
// snapshot binding and completeness. It returns the observation's own
// narrow fact, never an inference from the observation's existence.
func (c *supportContext) resolveObservationFact(claim *Claim) (resolvedBinding, bool) {
	fail := func(format string, args ...any) (resolvedBinding, bool) {
		return resolvedBinding{established: fmt.Sprintf(format, args...)}, false
	}
	ref := claim.Binding.ReferenceID
	evidence, ok := c.evidence[ref]
	if !ok {
		return fail("binding references evidence id %q that the assessment does not declare", ref)
	}
	id, _, ok := parseDetLocator(evidence.Locator)
	if !ok {
		return fail("evidence %q has no canonical observation locator", ref)
	}
	obs, ok := c.observations[normalizeObservationID(id)]
	if !ok {
		return fail("observation %q is not in the selected run archive", id)
	}
	if c.in.SelectedAttempt > 0 && obs.Attempt != c.in.SelectedAttempt {
		return fail("observation %q belongs to attempt %d, not the selected attempt %d", obs.ID, obs.Attempt, c.in.SelectedAttempt)
	}
	if obs.Status != ToolStatusOK {
		return fail("observation %q recorded status %q; the call produced no fact", obs.ID, obs.Status)
	}
	if len(obs.Payload) == 0 {
		return fail("observation %q carries no payload", obs.ID)
	}
	if strings.TrimSpace(obs.DataSHA256) == "" {
		return fail("observation %q carries no payload digest", obs.ID)
	}
	sum := sha256.Sum256(obs.Payload)
	if !strings.EqualFold(strings.TrimSpace(obs.DataSHA256), hex.EncodeToString(sum[:])) {
		return fail("observation %q payload does not match its recorded digest", obs.ID)
	}
	if c.snapshotHash != "" {
		if strings.TrimSpace(obs.SnapshotHash) == "" {
			return fail("observation %q is not bound to the decision snapshot", obs.ID)
		}
		if obs.SnapshotHash != c.snapshotHash {
			return fail("observation %q is bound to snapshot %q, not the decision snapshot", obs.ID, obs.SnapshotHash)
		}
	}
	if obs.Completeness == evidencetools.CompletenessPartial || obs.Completeness == evidencetools.CompletenessUnknown {
		return fail("observation %q recorded %s coverage; an incomplete check establishes only the checked part", obs.ID, obs.Completeness)
	}
	var payload struct {
		Fact string `json:"fact"`
	}
	if err := json.Unmarshal(obs.Payload, &payload); err != nil || strings.TrimSpace(payload.Fact) == "" {
		return fail("observation %q records no narrow fact", obs.ID)
	}
	return resolvedBinding{
		established:   strings.TrimSpace(payload.Fact),
		scope:         obs.Scope,
		completeness:  string(obs.Completeness),
		sourceRefs:    []string{ref, "det:" + obs.ID},
		sourceDigests: []string{obs.DataSHA256},
		open:          append([]string(nil), obs.Limitations...),
	}, true
}

// resolveQuotedText verifies a QUOTED_TEXT binding against the fact gate's
// recorded validation. It establishes only that the quotation's locator
// verified; the interpretation of the text stays a separate claim.
func (c *supportContext) resolveQuotedText(claim *Claim) (resolvedBinding, bool) {
	fail := func(format string, args ...any) (resolvedBinding, bool) {
		return resolvedBinding{established: fmt.Sprintf(format, args...)}, false
	}
	ref := claim.Binding.ReferenceID
	evidence, ok := c.evidence[ref]
	if !ok {
		return fail("binding references evidence id %q that the assessment does not declare", ref)
	}
	if strings.TrimSpace(evidence.Locator) == "" {
		return fail("evidence %q has no locator", ref)
	}
	if strings.TrimSpace(evidence.Quote) == "" {
		return fail("evidence %q carries no quoted text", ref)
	}
	check, ok := c.checks[ref]
	if !ok {
		return fail("evidence %q was not validated by the fact gate", ref)
	}
	if check.Status != FactValid {
		return fail("evidence %q recorded fact-gate status %s (%s)", ref, check.Status, check.Reason)
	}
	if c.snapshotHash != "" && check.SnapshotHash != "" && check.SnapshotHash != c.snapshotHash {
		return fail("evidence %q is bound to snapshot %q, not the decision snapshot", ref, check.SnapshotHash)
	}
	digest := strings.TrimSpace(evidence.SHA256)
	if digest == "" {
		if loc, err := parseFileLocator(evidence.Locator); err == nil {
			if f := declaredFile(c.in.Stage0.Snapshot, loc.path); f != nil {
				digest = f.SHA256
			}
		}
	}
	open := []string{"a verified quotation establishes the presence of text at the locator, not its interpretation"}
	if c.snapshotHash != "" && check.SnapshotHash == "" {
		open = append(open, "the quotation's fact-gate check carries no snapshot pin")
	}
	rb := resolvedBinding{
		established: fmt.Sprintf("quoted text is present at %q", strings.TrimSpace(evidence.Locator)),
		scope:       check.Scope,
		sourceRefs:  []string{ref, strings.TrimSpace(evidence.Locator)},
		open:        open,
	}
	if digest != "" {
		rb.sourceDigests = []string{digest}
	}
	return rb, true
}

// resolveFalsifierProof verifies a FALSIFIER_PROOF binding against the
// persisted report and certificate. A proposal alone establishes nothing:
// only a VERIFIED proof whose certificate binds the condition, subjects,
// snapshot and scope to this claim counts.
func (c *supportContext) resolveFalsifierProof(claim *Claim) (resolvedBinding, bool) {
	fail := func(format string, args ...any) (resolvedBinding, bool) {
		return resolvedBinding{established: fmt.Sprintf(format, args...)}, false
	}
	ref := claim.Binding.ReferenceID
	proposal, ok := c.proposals[ref]
	if !ok {
		return fail("binding references falsifier proposal %q that the assessment does not declare", ref)
	}
	if proposal.ClaimID != claim.ID {
		return fail("falsifier proposal %q answers claim %q, not this claim", ref, proposal.ClaimID)
	}
	proof, ok := c.proofs[ref]
	if !ok {
		return fail("no falsifier proof was recorded for proposal %q; a proposal alone establishes nothing", ref)
	}
	if proof.Status != FalsifierVerified {
		return fail("falsifier proof %q recorded status %s, not VERIFIED", proof.ID, proof.Status)
	}
	if strings.TrimSpace(proof.Coverage.Scope) == "" {
		return fail("falsifier proof %q records no scope", proof.ID)
	}
	if c.snapshotHash == "" || strings.TrimSpace(proof.Coverage.SnapshotHash) == "" || proof.Coverage.SnapshotHash != c.snapshotHash {
		return fail("falsifier proof %q is not bound to the decision snapshot", proof.ID)
	}
	if proof.Coverage.Completeness != string(evidencetools.CompletenessComplete) {
		return fail("falsifier proof %q coverage is %q, not COMPLETE", proof.ID, proof.Coverage.Completeness)
	}
	if !sameSubjects(proof.Coverage.ExpectedSubjects, proof.Coverage.CheckedSubjects) {
		return fail("falsifier proof %q does not cover its full expected subject set", proof.ID)
	}
	for _, evID := range sortedStrings(append([]string(nil), proof.EvidenceRefs...)) {
		evidence, ok := c.evidence[evID]
		if !ok {
			continue
		}
		id, _, ok := parseDetLocator(evidence.Locator)
		if !ok {
			continue
		}
		obs, ok := c.observations[normalizeObservationID(id)]
		if !ok {
			continue
		}
		if c.in.SelectedAttempt > 0 && obs.Attempt != c.in.SelectedAttempt {
			return fail("falsifier proof %q cites an observation from attempt %d, not the selected attempt %d", proof.ID, obs.Attempt, c.in.SelectedAttempt)
		}
		if c.snapshotHash != "" && obs.SnapshotHash != "" && obs.SnapshotHash != c.snapshotHash {
			return fail("falsifier proof %q cites an observation from another snapshot", proof.ID)
		}
	}
	digests := make([]string, 0, 2)
	if c.reportHash != "" {
		digests = append(digests, c.reportHash)
	}
	if proof.Coverage.SnapshotHash != "" {
		digests = append(digests, proof.Coverage.SnapshotHash)
	}
	open := make([]string, 0)
	if len(proof.Coverage.OpenExceptions) > 0 {
		open = append(open, "proof coverage carries open exceptions: "+strings.Join(proof.Coverage.OpenExceptions, ", "))
	}
	subject, scope, proposition := proofNarrowFields(proof)
	return resolvedBinding{
		established:   proposition,
		subject:       subject,
		proofID:       proof.ID,
		scope:         scope,
		completeness:  proof.Coverage.Completeness,
		sourceRefs:    []string{proof.ID, ref},
		sourceDigests: dedupeStrings(digests),
		open:          open,
	}, true
}

// proofNarrowFields derives the canonical typed proposition an admitted
// certificate establishes: its exact kind, condition, sorted package#symbol
// subject set and recorded scope. Only a claim that expresses this same
// proposition may be computed PROVED; an attached claim id alone is not
// evidence that the prose states what the checker proved.
func proofNarrowFields(proof FalsifierProof) (subject, scope, proposition string) {
	subjects := append([]FalsifierSubject(nil), proof.Coverage.ExpectedSubjects...)
	canonSubjects(subjects)
	parts := make([]string, 0, len(subjects))
	for _, s := range subjects {
		parts = append(parts, s.Package+"#"+s.Symbol)
	}
	subject = strings.Join(parts, ",")
	scope = strings.TrimSpace(proof.Coverage.Scope)
	proposition = fmt.Sprintf("%s established condition %s for %s in scope %s",
		proof.Kind, proof.ConditionID, subject, scope)
	return subject, scope, proposition
}

// claimExpressesProof reports whether the claim's declared subject, scope and
// statement are the certificate's typed proposition under whitespace
// normalization. Comparison is case-sensitive: identifiers and paths are
// not interchangeable when only their case differs.
func claimExpressesProof(claim *Claim, subject, scope, proposition string) (bool, string) {
	if normalizePropositionText(claim.Subject) != normalizePropositionText(subject) {
		return false, fmt.Sprintf("claim subject %q does not name the proved subject %q", claim.Subject, subject)
	}
	if normalizePropositionText(claim.Scope) != normalizePropositionText(scope) {
		return false, fmt.Sprintf("claim scope %q does not name the proved scope %q", claim.Scope, scope)
	}
	if normalizePropositionText(claim.Statement) != normalizePropositionText(proposition) {
		return false, "the claim statement is not the proved proposition"
	}
	return true, ""
}

// sameNarrowProposition reports whether the model statement is the recorded
// narrow fact rather than an interpretation layered on it. Comparison
// collapses whitespace runs but preserves case: identifiers, paths and
// configuration values are case-sensitive, so "p.F" and "p.f" are
// different propositions. No entailment is inferred from prose.
func sameNarrowProposition(statement, fact string) bool {
	if strings.TrimSpace(statement) == "" || strings.TrimSpace(fact) == "" {
		return false
	}
	return normalizePropositionText(statement) == normalizePropositionText(fact)
}

// normalizePropositionText collapses whitespace runs without folding case.
func normalizePropositionText(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// contradictionCaps reports unresolved contradictions relevant to the
// decisive closure: explicit ConflictsWith references between declared
// claims, and comparable structured facts with matching kind, subject and
// scope that both SUPPORT and REFUTE. No contradiction is inferred from
// prose.
func (c *supportContext) contradictionCaps(closure map[string]bool, claims map[string]*Claim) []string {
	var caps []string
	seen := map[string]bool{}
	for _, id := range sortedClaimIDs(claims) {
		claim := claims[id]
		for _, other := range sortedStrings(append([]string(nil), claim.ConflictsWith...)) {
			// A conflict is relevant when either endpoint is decisive: a
			// background claim may declare the edge against a decisive one.
			if !closure[id] && !closure[other] {
				continue
			}
			key := id + "\x00" + other
			reverse := other + "\x00" + id
			if seen[key] || seen[reverse] {
				continue
			}
			seen[key] = true
			caps = append(caps, fmt.Sprintf(
				"decisive closure conflict: claim %q declares an unresolved conflict with claim %q", id, other))
		}
	}

	type factGroup struct {
		kind, subject, scope string
		supports, refutes    bool
		refs                 map[string]bool
	}
	groups := map[string]*factGroup{}
	for _, f := range c.in.Facts {
		kind, subject, scope := strings.TrimSpace(f.Kind), strings.TrimSpace(f.Subject), strings.TrimSpace(f.Scope)
		if kind == "" && subject == "" && scope == "" {
			continue
		}
		key := kind + "\x00" + subject + "\x00" + scope
		group := groups[key]
		if group == nil {
			group = &factGroup{kind: kind, subject: subject, scope: scope, refs: map[string]bool{}}
			groups[key] = group
		}
		switch f.Status {
		case ObsSupports:
			group.supports = true
		case ObsRefutes:
			group.refutes = true
		}
		for _, ref := range f.EvidenceRefs {
			if normalized := normalizeComparableRef(ref); normalized != "" {
				group.refs[normalized] = true
			}
		}
	}
	if len(groups) > 0 {
		relevantRefs := map[string]bool{}
		relevantPairs := map[string]bool{}
		for _, id := range sortedIDs(closure) {
			claim := claims[id]
			for ref := range c.comparableRefs(claim) {
				relevantRefs[ref] = true
			}
			relevantPairs[strings.TrimSpace(claim.Subject)+"\x00"+strings.TrimSpace(claim.Scope)] = true
		}
		keys := make([]string, 0, len(groups))
		for key := range groups {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			group := groups[key]
			if !group.supports || !group.refutes {
				continue
			}
			relevant := relevantPairs[group.subject+"\x00"+group.scope]
			for ref := range group.refs {
				if relevantRefs[ref] {
					relevant = true
					break
				}
			}
			if !relevant {
				continue
			}
			caps = append(caps, fmt.Sprintf(
				"comparable facts disagree for kind %q subject %q scope %q: SUPPORTS and REFUTES are both recorded",
				group.kind, group.subject, group.scope))
		}
	}
	return caps
}

// comparableRefs is the set of identifiers under which a claim's evidence
// can be matched to structured facts: evidence ids, their canonical
// observation ids and the binding reference.
func (c *supportContext) comparableRefs(claim *Claim) map[string]bool {
	out := map[string]bool{}
	add := func(raw string) {
		if normalized := normalizeComparableRef(raw); normalized != "" {
			out[normalized] = true
		}
	}
	for _, ref := range claim.EvidenceRefs {
		add(ref)
		if evidence, ok := c.evidence[ref]; ok {
			add(evidence.Locator)
		}
	}
	if claim.Binding != nil {
		add(claim.Binding.ReferenceID)
		if evidence, ok := c.evidence[claim.Binding.ReferenceID]; ok {
			add(evidence.Locator)
		}
	}
	return out
}

func normalizeComparableRef(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return ""
	}
	for _, scheme := range observationIDSchemes {
		if strings.HasPrefix(raw, scheme) {
			raw = strings.TrimPrefix(raw, scheme)
			break
		}
	}
	return strings.ReplaceAll(raw, "_", "-")
}

// evaluateCounterarguments checks the objection list against the decisive
// closure. An open objection or one whose response is not grounded in
// established premises caps support at LIMITED.
func evaluateCounterarguments(counterarguments []Counterargument, evals map[string]*premiseEvaluation) []string {
	ordered := append([]Counterargument(nil), counterarguments...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	var caps []string
	for _, ca := range ordered {
		if strings.TrimSpace(ca.Response) == "" {
			caps = append(caps, fmt.Sprintf(
				"material counterargument %q remains open: no response was given", ca.ID))
			continue
		}
		if len(ca.PremiseIDs) == 0 {
			caps = append(caps, fmt.Sprintf(
				"material counterargument %q response cites no premise and cannot be grounded", ca.ID))
			continue
		}
		for _, premiseID := range sortedStrings(append([]string(nil), ca.PremiseIDs...)) {
			ev, ok := evals[premiseID]
			if !ok {
				caps = append(caps, fmt.Sprintf(
					"material counterargument %q response relies on claim %q outside the decisive premise closure", ca.ID, premiseID))
				continue
			}
			if !ev.grounded {
				caps = append(caps, fmt.Sprintf(
					"material counterargument %q response relies on ungrounded premise %q", ca.ID, premiseID))
			}
		}
	}
	return caps
}

// stabilityCaps applies the stability contract: agreement never raises
// support, while semantic disagreement caps the derived support at LIMITED.
func stabilityCaps(stability *StabilityReport) []string {
	if stability == nil || stability.Stable {
		return nil
	}
	reason := "stability retries disagreed on the decision surface"
	if len(stability.Limitations) > 0 {
		reason += ": " + stability.Limitations[0]
	}
	return []string{reason}
}

package verify

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/fedorovmv/izyan/internal/productb/claimshape"
)

// ChallengeSchemaVersion identifies the persisted challenge-document
// schema (challenges.json). Additive fields may extend it; the closed
// challenge vocabulary never changes spelling.
const ChallengeSchemaVersion = "verification-challenges.v1"

// ChallengeKind names the gap class an adversarial reviewer proposes
// (plan §3 "Почему adversarial LLM не является verifier authority").
// The set is closed: decoding accepts only these spellings. Kind is the
// audit label of the proposal — the deterministic semantics live in the
// canonical claim the challenge normalizes to.
type ChallengeKind string

const (
	// ChallengeAlternativeCaller — the reviewer suspects an invocation
	// path the negative-verification evidence did not cover.
	ChallengeAlternativeCaller ChallengeKind = "alternative_caller"
	// ChallengeMissingSubject — a subject the check plan did not
	// enumerate (extra symbol, package, call site).
	ChallengeMissingSubject ChallengeKind = "missing_subject"
	// ChallengeScopeGap — the closed scope may not cover the relevant
	// universe (open closure, unenumerated surface).
	ChallengeScopeGap ChallengeKind = "scope_gap"
	// ChallengeContradictoryObservation — recorded evidence arguably
	// refutes an established predicate in the same context.
	ChallengeContradictoryObservation ChallengeKind = "contradictory_observation"
	// ChallengeUnsupportedCausalStep — a derived chain relies on a
	// premise no deterministic evidence supports.
	ChallengeUnsupportedCausalStep ChallengeKind = "unsupported_causal_step"
)

// challengeKinds is the closed kind set.
var challengeKinds = map[ChallengeKind]bool{
	ChallengeAlternativeCaller:        true,
	ChallengeMissingSubject:           true,
	ChallengeScopeGap:                 true,
	ChallengeContradictoryObservation: true,
	ChallengeUnsupportedCausalStep:    true,
}

// Challenge is a proposal from the adversarial reviewer channel: a
// hypothesis about a missed alternative, phrased as the canonical
// predicate the deterministic cycle should re-derive. A challenge is
// claim-shaped input only — it can cite recorded evidence and name
// subjects, but it can never carry an outcome, a proof, a verdict, a
// completeness claim or any provenance pin. Every challenge is
// normalized into a CanonicalClaim and passes through the identical
// capability/observation/entailment cycle as assessment claims; nothing
// the reviewer wrote decides anything.
type Challenge struct {
	// ID is the reviewer's own handle — audit only, never semantics.
	ID string `json:"id,omitempty"`
	// Kind classifies the proposed gap for the audit trail.
	Kind ChallengeKind `json:"kind"`
	// Target names the claim or condition the challenge argues against
	// (audit/provenance only — never a mechanical link into the graph).
	Target string `json:"target,omitempty"`
	// Shape is the canonical claim shape the challenge asks to
	// re-derive. Empty falls back to the kind's default shape.
	Shape claimshape.Shape `json:"shape,omitempty"`
	// Subject is the primary subject under dispute; Subjects widens the
	// named universe (it lands in the claim's subjects parameter).
	Subject  claimshape.Subject   `json:"subject,omitempty"`
	Subjects []claimshape.Subject `json:"subjects,omitempty"`
	// Parameters carries the structured query inputs a capability needs
	// (module, resolved_version, ...) — string values only, so no
	// proof/proposal/facet structure can be smuggled in.
	Parameters map[string]string `json:"parameters,omitempty"`
	// PremiseFamilies feeds derived.mandatory_condition challenges —
	// the canonical premise-family vocabulary of familyShapes.
	PremiseFamilies []string `json:"premise_families,omitempty"`
	// EvidenceRefs cites recorded observation ids the challenge claims
	// contradict the established predicate. References bind evidence;
	// they never mint it.
	EvidenceRefs []string `json:"evidence_refs,omitempty"`
	// Polarity is the hypothesis direction the challenge asserts. The
	// claim outcome is still computed deterministically — a FALSE
	// challenge is "this predicate does not hold", not a proof.
	Polarity claimshape.Polarity `json:"polarity,omitempty"`
	// Rationale is the reviewer's free-text reason. It is stored
	// verbatim on the minted claim's source for audit — nothing in the
	// deterministic cycle reads it.
	Rationale string `json:"rationale,omitempty"`
}

// challengeForbiddenFields are the fields a reviewer may never set: every
// one is a decision-layer or provenance surface that belongs to the
// deterministic cycle, not to a proposal. They are named explicitly —
// ahead of generic unknown-field rejection — so the error identifies the
// authority the proposal tried to claim.
var challengeForbiddenFields = map[string]bool{
	// decision/verdict surfaces
	"status": true, "verdict": true, "recommendation": true,
	"outcome": true, "result": true, "decision": true,
	"disposition": true, "established": true,
	// proof surfaces
	"proof": true, "proofs": true, "proof_status": true,
	"proof_basis": true, "falsifier": true, "mandatory": true,
	"admitted": true, "verified": true, "negative_verification": true,
	"coverage": true, "completeness": true, "condition_id": true,
	"bound_proposals": true, "facets": true,
	// evidence/provenance surfaces — a reviewer cites refs, it never
	// pins run, snapshot, build context, scope or tool identity
	"observations": true, "observation": true, "claims": true,
	"run_id": true, "snapshot_hash": true, "build_context_hash": true,
	"scope_hash": true, "tool": true, "tool_version": true,
	"scope": true, "attempt": true, "limitation": true,
	"limitations": true, "open_gaps": true,
}

// challengeFields is the closed set of known challenge fields — every
// other key is an unknown-field error.
var challengeFields = map[string]bool{
	"id": true, "kind": true, "target": true, "shape": true,
	"subject": true, "subjects": true, "parameters": true,
	"premise_families": true, "evidence_refs": true,
	"polarity": true, "rationale": true,
}

// UnmarshalJSON decodes a challenge strictly: forbidden authority fields
// are rejected by name, every other unknown key is a schema error, then
// the semantic rules run — a challenge can never denote a verdict.
func (ch *Challenge) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if challengeForbiddenFields[name] {
			return fmt.Errorf("challenge field %q is forbidden: outcomes, proofs and provenance belong to the deterministic cycle", name)
		}
		if !challengeFields[name] {
			return fmt.Errorf("unknown challenge field %q", name)
		}
	}
	type plain Challenge
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	*ch = Challenge(p)
	return ch.Validate()
}

// Validate enforces the semantic contract of a proposal: known kind,
// canonical (or defaulted) shape, a well-formed polarity and at least one
// concrete pointer — subject, evidence reference or parameter — so a
// challenge can never be a vacuous verdict. Validation failures are
// recorded on the report's challenge row, never silently dropped.
func (ch Challenge) Validate() error {
	if !challengeKinds[ch.Kind] {
		return fmt.Errorf("invalid challenge kind %q", ch.Kind)
	}
	if ch.Shape != "" {
		if !ch.Shape.Valid() || ch.Shape == claimshape.ShapeUnsupported {
			return fmt.Errorf("invalid challenge shape %q", ch.Shape)
		}
	}
	if ch.Kind == ChallengeContradictoryObservation && ch.Shape == "" {
		return fmt.Errorf("contradictory_observation challenge must name the shape it contests")
	}
	switch ch.Polarity {
	case "", claimshape.PolarityTrue, claimshape.PolarityFalse, claimshape.PolarityUnknown:
	default:
		return fmt.Errorf("invalid challenge polarity %q", ch.Polarity)
	}
	if ch.Subject.Kind != "" && !subjectWellFormed(ch.Subject) {
		return fmt.Errorf("malformed challenge subject %+v", ch.Subject)
	}
	for _, s := range ch.Subjects {
		if !subjectWellFormed(s) {
			return fmt.Errorf("malformed challenge subject %+v", s)
		}
	}
	if ch.Subject.Name == "" && len(ch.Subjects) == 0 && len(ch.EvidenceRefs) == 0 &&
		len(ch.Parameters) == 0 && len(ch.PremiseFamilies) == 0 {
		return fmt.Errorf("vacuous challenge: no subject, evidence reference or parameter")
	}
	return nil
}

// subjectWellFormed requires a canonical subject identity — a kind plus
// a name or a package.symbol decomposition.
func subjectWellFormed(s claimshape.Subject) bool {
	if s.Kind == "" || s.Kind == claimshape.SubjectUnknown {
		return s.Name != "" || s.Package != ""
	}
	return s.Name != "" || (s.Package != "" && s.Symbol != "")
}

// defaultChallengeShape resolves the canonical shape a challenge kind
// implies when the reviewer left it open.
func defaultChallengeShape(k ChallengeKind) claimshape.Shape {
	switch k {
	case ChallengeAlternativeCaller:
		return claimshape.ShapePathReachable
	case ChallengeMissingSubject:
		return claimshape.ShapeSubjectDeclared
	case ChallengeScopeGap:
		return claimshape.ShapeClosureComplete
	case ChallengeUnsupportedCausalStep:
		return claimshape.ShapeDerivedMandatoryCondition
	}
	return ""
}

// defaultChallengePolarity resolves the hypothesis direction a challenge
// kind asserts when the reviewer left it open: "there is another caller /
// missed subject" asserts existence; "scope gap / unsupported step"
// asserts the established predicate fails.
func defaultChallengePolarity(k ChallengeKind) claimshape.Polarity {
	switch k {
	case ChallengeScopeGap, ChallengeContradictoryObservation,
		ChallengeUnsupportedCausalStep:
		return claimshape.PolarityFalse
	}
	return claimshape.PolarityTrue
}

// ChallengeEval is one challenge's fate under normalization — the audit
// row Report.Challenges carries: which proposal minted which claim,
// whether it was rejected or merged into an identical proposal, and the
// outcome the deterministic cycle computed for it.
type ChallengeEval struct {
	ChallengeID string           `json:"challenge_id"`
	Kind        ChallengeKind    `json:"kind,omitempty"`
	Target      string           `json:"target,omitempty"`
	ClaimID     string           `json:"claim_id,omitempty"`
	Rejected    string           `json:"rejected,omitempty"`
	Merged      bool             `json:"merged,omitempty"`
	Outcome     Outcome          `json:"outcome,omitempty"`
	Predicate   PredicateOutcome `json:"predicate_outcome,omitempty"`
	claim       *claimshape.CanonicalClaim
	canon       string
}

// challengeCanon is the content-addressed identity of a challenge: the
// semantic tuple the minted claim derives from. Reviewer handles (ID)
// and prose rationale never enter it — two proposals asking the same
// deterministic question are the same challenge.
type challengeCanon struct {
	Kind            ChallengeKind        `json:"kind"`
	Target          string               `json:"target,omitempty"`
	Shape           claimshape.Shape     `json:"shape"`
	Subject         claimshape.Subject   `json:"subject,omitempty"`
	Subjects        []claimshape.Subject `json:"subjects,omitempty"`
	Parameters      map[string]string    `json:"parameters,omitempty"`
	PremiseFamilies []string             `json:"premise_families,omitempty"`
	EvidenceRefs    []string             `json:"evidence_refs,omitempty"`
	Polarity        claimshape.Polarity  `json:"polarity"`
}

// canonKey renders the challenge's canonical identity: sorted subjects,
// sorted evidence refs, sorted premise families and sorted parameter
// keys — the ordering of the proposal can never leak into the graph.
func (ch Challenge) canonKey() (challengeCanon, string) {
	shape := ch.Shape
	if shape == "" {
		shape = defaultChallengeShape(ch.Kind)
	}
	pol := ch.Polarity
	if pol == "" {
		pol = defaultChallengePolarity(ch.Kind)
	}
	subs := append([]claimshape.Subject(nil), ch.Subjects...)
	sort.Slice(subs, func(i, j int) bool { return subjectKey(subs[i]) < subjectKey(subs[j]) })
	refs := dedup(append([]string(nil), ch.EvidenceRefs...))
	sort.Strings(refs)
	fams := dedup(append([]string(nil), ch.PremiseFamilies...))
	sort.Strings(fams)
	var params map[string]string
	if len(ch.Parameters) > 0 {
		params = map[string]string{}
		for k, v := range ch.Parameters {
			params[k] = v
		}
	}
	c := challengeCanon{
		Kind: ch.Kind, Target: ch.Target, Shape: shape,
		Subject: ch.Subject, Subjects: subs, Parameters: params,
		PremiseFamilies: fams, EvidenceRefs: refs, Polarity: pol,
	}
	return c, string(canonicalJSON(c))
}

// normalizeChallenge mints the canonical claim a challenge proposes.
// The claim carries nothing a challenge cannot legitimately propose:
// shape, subject(s), plain parameters, evidence references and the
// hypothesis polarity — no facets, no bound proposals, no scope pin, no
// provenance. The minted id is content-addressed so any ordering of the
// challenge set normalizes to the same claim set.
func normalizeChallenge(ch Challenge) (claimshape.CanonicalClaim, ChallengeEval) {
	canon, key := ch.canonKey()
	row := ChallengeEval{ChallengeID: ch.ID, Kind: ch.Kind, Target: ch.Target, canon: key}
	if row.ChallengeID == "" {
		row.ChallengeID = "challenge:" + shortHash([]byte(key))
	}
	if err := ch.Validate(); err != nil {
		row.Rejected = err.Error()
		return claimshape.CanonicalClaim{}, row
	}
	subject := ch.Subject
	if subject.Name == "" && subject.Kind == "" && len(canon.Subjects) > 0 {
		subject = canon.Subjects[0]
	}
	if subject.Kind == "" {
		subject.Kind = claimshape.SubjectUnknown
	}
	id := "challenge-" + shortHash([]byte(key))
	params := map[string]any{}
	for k, v := range ch.Parameters {
		params[k] = v
	}
	if len(canon.Subjects) > 0 {
		params["subjects"] = canon.Subjects
	}
	if len(canon.PremiseFamilies) > 0 {
		params["premise_families"] = canon.PremiseFamilies
	}
	if len(params) == 0 {
		params = nil
	}
	c := claimshape.CanonicalClaim{
		ID:         id,
		Shape:      canon.Shape,
		Subject:    subject,
		Predicate:  claimshape.ShapePredicate(canon.Shape),
		Parameters: params,
		Polarity:   canon.Polarity,
		// A challenge never pins scope or provenance: its own scope
		// descriptor is UNKNOWN, so it binds whatever recorded contexts
		// exist and the contract decides.
		Scope:                claimshape.Scope{Completeness: "UNKNOWN"},
		EvidenceRefs:         canon.EvidenceRefs,
		RequiredCapabilities: claimshape.RequiredCapabilities(canon.Shape),
		Source: claimshape.ClaimSource{
			ClaimID:          id,
			DecisionRelevant: true,
			Statement:        ch.Rationale,
		},
	}
	row.ClaimID = id
	cl := c
	row.claim = &cl
	return c, row
}

// normalizeChallenges canonicalizes the raw challenge set into minted
// claims plus audit rows. The output is a pure function of the challenge
// content: proposals are sorted by canonical key before minting, so the
// incoming order can never change the claim set, the graph hash or the
// decision.
func normalizeChallenges(chs []Challenge) ([]claimshape.CanonicalClaim, []ChallengeEval) {
	rows := make([]ChallengeEval, 0, len(chs))
	for _, ch := range chs {
		_, row := normalizeChallenge(ch)
		rows = append(rows, row)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].canon != rows[j].canon {
			return rows[i].canon < rows[j].canon
		}
		return rows[i].ChallengeID < rows[j].ChallengeID
	})
	var claims []claimshape.CanonicalClaim
	seen := map[string]bool{}
	for i := range rows {
		if rows[i].claim == nil {
			continue
		}
		if seen[rows[i].claim.ID] {
			// Identical proposal: the claim already exists; the row
			// records the merge for audit instead of minting a node.
			rows[i].Merged = true
			continue
		}
		seen[rows[i].claim.ID] = true
		claims = append(claims, *rows[i].claim)
	}
	return claims, rows
}

// ChallengesDocument is challenges.json: the persisted reviewer-proposal
// set a run consumed. It is input, never output — the document records
// what the deterministic cycle was asked to re-derive.
type ChallengesDocument struct {
	SchemaVersion string      `json:"schema_version"`
	RunID         string      `json:"run_id,omitempty"`
	FindingID     string      `json:"finding_id,omitempty"`
	Challenges    []Challenge `json:"challenges"`
}

// WriteChallenges persists the challenge document deterministically.
func WriteChallenges(path string, doc ChallengesDocument) error {
	if doc.SchemaVersion == "" {
		doc.SchemaVersion = ChallengeSchemaVersion
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// ReadChallenges loads a persisted challenge document; malformed content
// is a technical error, not a skipped challenge.
func ReadChallenges(path string) (ChallengesDocument, error) {
	var doc ChallengesDocument
	b, err := os.ReadFile(path)
	if err != nil {
		return doc, err
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return doc, fmt.Errorf("challenges document: %w", err)
	}
	return doc, nil
}

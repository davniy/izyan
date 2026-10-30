package domain

import (
	"fmt"
	"strings"
)

// RelationKind is the frozen lookup kind of one relationship index. The three
// indexes are kept separate on purpose: an id found through `related` is a
// discovery lead only, while own-id and alias matches can support identity.
type RelationKind string

const (
	RelationRecord  RelationKind = "record"
	RelationAlias   RelationKind = "alias"
	RelationRelated RelationKind = "related"
)

// Valid reports whether the relationship kind is one of the three frozen
// indexes.
func (k RelationKind) Valid() bool {
	switch k {
	case RelationRecord, RelationAlias, RelationRelated:
		return true
	default:
		return false
	}
}

// DiscoveryEnumeration is the frozen, lowercase outcome of a corpus
// enumeration. Only DiscoveryFinished may serve as a completeness basis, and
// only together with the semantic proof: enumeration says which documents were
// considered, never whether any of them is safe.
type DiscoveryEnumeration string

const (
	DiscoveryFinished      DiscoveryEnumeration = "finished"
	DiscoveryPartial       DiscoveryEnumeration = "partial"
	DiscoveryUnavailable   DiscoveryEnumeration = "unavailable"
	DiscoveryNotConfigured DiscoveryEnumeration = "not_configured"
)

// Valid reports whether the enumeration outcome is one of the four frozen
// values.
func (e DiscoveryEnumeration) Valid() bool {
	switch e {
	case DiscoveryFinished, DiscoveryPartial, DiscoveryUnavailable, DiscoveryNotConfigured:
		return true
	default:
		return false
	}
}

// Complete reports whether the enumeration finished. A configured feed, a
// finished scan or an empty result is still not closure authority by itself.
func (e DiscoveryEnumeration) Complete() bool { return e == DiscoveryFinished }

// CandidateDisposition is the frozen, lowercase fate of one nominated
// candidate. Every disposition other than DispositionEvaluated blocks a
// candidate from contributing either a positive or a negative.
type CandidateDisposition string

const (
	// DispositionEvaluated means the candidate received its own independent
	// assessment from its own record bytes.
	DispositionEvaluated CandidateDisposition = "evaluated"
	// DispositionUnsupported means the assessment ran but recorded an
	// unsupported proof capability.
	DispositionUnsupported CandidateDisposition = "unsupported"
	// DispositionAmbiguous means conflicting bytes, an unclear bundled
	// mechanism or contradictory attribution prevented a decision.
	DispositionAmbiguous CandidateDisposition = "ambiguous"
	// DispositionLoadFailed means the candidate's exact bytes could not be
	// read or decoded.
	DispositionLoadFailed CandidateDisposition = "load_failed"
	// DispositionTimedOut means the assessment exceeded its budget/deadline.
	DispositionTimedOut CandidateDisposition = "timed_out"
	// DispositionNotEvaluated means the candidate was nominated but never
	// assessed.
	DispositionNotEvaluated CandidateDisposition = "not_evaluated"
)

// Valid reports whether the disposition is one of the six frozen values.
func (d CandidateDisposition) Valid() bool {
	switch d {
	case DispositionEvaluated, DispositionUnsupported, DispositionAmbiguous,
		DispositionLoadFailed, DispositionTimedOut, DispositionNotEvaluated:
		return true
	default:
		return false
	}
}

// Resolved reports whether the candidate produced an admissible decision.
func (d CandidateDisposition) Resolved() bool { return d == DispositionEvaluated }

// AttributionBasis is the frozen basis of a directional CVE attribution. A
// bare related edge is not a basis at all: it can only produce the
// AttributionRelatedOnly admission.
type AttributionBasis string

const (
	// AttributionOwnID means the candidate record's own id asserts the CVE.
	AttributionOwnID AttributionBasis = "own_id"
	// AttributionOwnAlias means one of the candidate record's own aliases
	// asserts the CVE.
	AttributionOwnAlias AttributionBasis = "own_alias"
	// AttributionPublisher means captured publisher material explicitly
	// connects the CVE to the candidate's implementation.
	AttributionPublisher AttributionBasis = "publisher"
	// AttributionCNA means captured CNA material explicitly connects the CVE
	// to the candidate's implementation.
	AttributionCNA AttributionBasis = "cna"
)

// Valid reports whether the basis is one of the four frozen values.
func (b AttributionBasis) Valid() bool {
	switch b {
	case AttributionOwnID, AttributionOwnAlias, AttributionPublisher, AttributionCNA:
		return true
	default:
		return false
	}
}

// Captured reports whether the basis requires admitted captured material
// rather than a self-describing record identity.
func (b AttributionBasis) Captured() bool {
	return b == AttributionPublisher || b == AttributionCNA
}

// AttributionAdmission is the frozen admission result of one attribution
// attempt. Only AttributionAdmitted may bind a candidate's independently earned
// positive to the requested CVE.
type AttributionAdmission string

const (
	AttributionAdmitted    AttributionAdmission = "admitted"
	AttributionRelatedOnly AttributionAdmission = "related_only"
	AttributionAmbiguous   AttributionAdmission = "ambiguous"
)

// Valid reports whether the admission is one of the three frozen values.
func (a AttributionAdmission) Valid() bool {
	switch a {
	case AttributionAdmitted, AttributionRelatedOnly, AttributionAmbiguous:
		return true
	default:
		return false
	}
}

// CorpusReference pins a corpus identity: the operator-visible reference, the
// digest of the bytes that were enumerated, and the capture date they describe.
// Corpus completeness is only ever relative to this record.
type CorpusReference struct {
	Reference  string `json:"reference"`
	Digest     string `json:"digest"`
	CapturedAt string `json:"captured_at"`
}

// Validate enforces the pinned identity.
func (c CorpusReference) Validate() error {
	if strings.TrimSpace(c.Reference) == "" {
		return fmt.Errorf("corpus reference: reference is required")
	}
	if err := validatePinnedDigest("corpus reference "+c.Reference+" digest", c.Digest); err != nil {
		return err
	}
	if strings.TrimSpace(c.CapturedAt) == "" {
		return fmt.Errorf("corpus reference %q: capture date is required", c.Reference)
	}
	return nil
}

// CorpusDeclaration is the operator-declared corpus boundary: the reference the
// operator names, the digest they expect and the capture date they claim. The
// declaration itself supplies the declared completeness boundary; there is no
// separate consent flag.
type CorpusDeclaration struct {
	Reference      string `json:"reference"`
	ExpectedDigest string `json:"expected_digest"`
	CapturedAt     string `json:"captured_at"`
}

// Validate enforces the declared boundary.
func (d CorpusDeclaration) Validate() error {
	return CorpusReference{Reference: d.Reference, Digest: d.ExpectedDigest, CapturedAt: d.CapturedAt}.Validate()
}

// Pinned returns the identity the declaration asserts, so an observed manifest
// can be compared against it field by field.
func (d CorpusDeclaration) Pinned() CorpusReference {
	return CorpusReference{Reference: d.Reference, Digest: d.ExpectedDigest, CapturedAt: d.CapturedAt}
}

// CorpusSource is one provenance record of the corpus bytes: the sanitized
// source reference, its digest and when it was checked. It never carries
// credentials.
type CorpusSource struct {
	Ref       string `json:"ref,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
	CheckedAt string `json:"checked_at,omitempty"`
}

// CorpusProblem is one read/decode problem observed while enumerating the
// corpus. A problem forces a partial enumeration: a corpus with an unread
// document was not completely enumerated.
type CorpusProblem struct {
	Locator  string `json:"locator,omitempty"`
	RecordID string `json:"record_id,omitempty"`
	Problem  string `json:"problem"`
}

// CorpusManifest is the observed corpus: source provenance, the observed digest
// and capture date, the enumeration outcome, every document pin and every
// read/decode problem. It is evidence about the corpus, not about any
// vulnerability.
type CorpusManifest struct {
	Reference      string               `json:"reference"`
	CapturedAt     string               `json:"captured_at"`
	ObservedDigest string               `json:"observed_digest"`
	Enumeration    DiscoveryEnumeration `json:"enumeration"`
	Sources        []CorpusSource       `json:"sources,omitempty"`
	Documents      []RecordPin          `json:"documents,omitempty"`
	Problems       []CorpusProblem      `json:"problems,omitempty"`
}

// Validate enforces the observed-manifest invariants: a finished enumeration
// must be complete and problem-free, and a finished corpus must have actually
// enumerated documents. An empty or partly read corpus is never a completeness
// basis.
func (m CorpusManifest) Validate() error {
	if strings.TrimSpace(m.Reference) == "" {
		return fmt.Errorf("corpus manifest: reference is required")
	}
	if strings.TrimSpace(m.CapturedAt) == "" {
		return fmt.Errorf("corpus manifest %q: capture date is required", m.Reference)
	}
	if err := validatePinnedDigest("corpus manifest "+m.Reference+" observed digest", m.ObservedDigest); err != nil {
		return err
	}
	if !m.Enumeration.Valid() {
		return fmt.Errorf("corpus manifest %q: unknown enumeration outcome %q", m.Reference, m.Enumeration)
	}
	for n, problem := range m.Problems {
		if strings.TrimSpace(problem.Problem) == "" {
			return fmt.Errorf("corpus manifest %q: problems[%d] has no problem text", m.Reference, n)
		}
	}
	for n, document := range m.Documents {
		if err := document.Validate(); err != nil {
			return fmt.Errorf("corpus manifest %q: documents[%d]: %w", m.Reference, n, err)
		}
	}
	if m.Enumeration.Complete() {
		if len(m.Problems) > 0 {
			return fmt.Errorf("corpus manifest %q: a finished enumeration cannot carry %d read/decode problem(s)",
				m.Reference, len(m.Problems))
		}
		if len(m.Documents) == 0 {
			return fmt.Errorf("corpus manifest %q: a finished enumeration must pin the enumerated documents", m.Reference)
		}
	}
	return nil
}

// DiscoveryEdge records one relationship that nominated a candidate. Kind and
// ID are the lookup key that matched; FromID is the record whose field carried
// it, so an inverse related(CVE) hit stays explainable without an outgoing edge
// from the requested record.
type DiscoveryEdge struct {
	Kind   RelationKind `json:"kind"`
	ID     string       `json:"id"`
	FromID string       `json:"from_id,omitempty"`
}

// Validate enforces the edge record.
func (e DiscoveryEdge) Validate() error {
	if !e.Kind.Valid() {
		return fmt.Errorf("discovery edge: unknown relation kind %q", e.Kind)
	}
	if strings.TrimSpace(e.ID) == "" {
		return fmt.Errorf("discovery edge (%s): id is required", e.Kind)
	}
	return nil
}

// DiscoveryCandidate is one nominated record with its pinned bytes, the
// relationships that nominated it and its assessment disposition.
//
// A candidate is a discovery result only. Nothing recorded here transfers
// applicability, ranges, symbols, claims, severity or completeness to the
// requested finding: identity needs an admitted attribution, and exploitability
// needs the candidate's own independently earned witness.
type DiscoveryCandidate struct {
	Record      RecordPin            `json:"record"`
	Edges       []DiscoveryEdge      `json:"edges,omitempty"`
	Disposition CandidateDisposition `json:"disposition"`
	Note        string               `json:"note,omitempty"`
}

// Validate enforces the candidate record.
func (c DiscoveryCandidate) Validate() error {
	if err := c.Record.Validate(); err != nil {
		return fmt.Errorf("discovery candidate: %w", err)
	}
	if len(c.Edges) == 0 {
		return fmt.Errorf("discovery candidate %q: at least one nominating relationship is required", c.Record.RecordID)
	}
	for n, edge := range c.Edges {
		if err := edge.Validate(); err != nil {
			return fmt.Errorf("discovery candidate %q edges[%d]: %w", c.Record.RecordID, n, err)
		}
	}
	if !c.Disposition.Valid() {
		return fmt.Errorf("discovery candidate %q: unknown disposition %q", c.Record.RecordID, c.Disposition)
	}
	return nil
}

// RelatedDiscovery is the request-level discovery record: the pinned corpus it
// ran against, the enumeration outcome and every nominated candidate with its
// disposition. It states discovery only — a finished enumeration says which
// records were considered, never which implementations exist outside the
// corpus.
type RelatedDiscovery struct {
	RequestedID string               `json:"requested_id"`
	Corpus      *CorpusReference     `json:"corpus,omitempty"`
	Enumeration DiscoveryEnumeration `json:"enumeration"`
	Candidates  []DiscoveryCandidate `json:"candidates,omitempty"`
	Limitations []string             `json:"limitations,omitempty"`
}

// Validate enforces the discovery record.
func (d *RelatedDiscovery) Validate() error {
	if d == nil {
		return fmt.Errorf("related discovery: nil discovery record")
	}
	if strings.TrimSpace(d.RequestedID) == "" {
		return fmt.Errorf("related discovery: requested id is required")
	}
	if !d.Enumeration.Valid() {
		return fmt.Errorf("related discovery for %q: unknown enumeration outcome %q", d.RequestedID, d.Enumeration)
	}
	if d.Corpus != nil {
		if err := d.Corpus.Validate(); err != nil {
			return fmt.Errorf("related discovery for %q: %w", d.RequestedID, err)
		}
	}
	if d.Enumeration.Complete() && d.Corpus == nil {
		return fmt.Errorf("related discovery for %q: a finished enumeration requires the pinned corpus reference",
			d.RequestedID)
	}
	for n, candidate := range d.Candidates {
		if err := candidate.Validate(); err != nil {
			return fmt.Errorf("related discovery for %q candidates[%d]: %w", d.RequestedID, n, err)
		}
		for m := range n {
			if d.Candidates[m].Record.Same(candidate.Record) {
				return fmt.Errorf("related discovery for %q: candidate %q (%s) is listed twice; identical documents deduplicate",
					d.RequestedID, candidate.Record.RecordID, candidate.Record.DocumentDigest)
			}
		}
	}
	for n, limitation := range d.Limitations {
		if strings.TrimSpace(limitation) == "" {
			return fmt.Errorf("related discovery for %q: limitations[%d] is empty", d.RequestedID, n)
		}
	}
	return nil
}

// CVEAttribution is the typed, directional proposition "CVE C covers the
// particular implementation/mechanism proved in candidate record R". It is not
// R == C and it grants no fact-inheritance authority: the candidate still needs
// its own independently earned product proof.
//
// Publisher/CNA bases must carry the captured material (URI, digest, exact
// field and quote) plus the publisher advisory identity, the implementation
// binding and the fix reference. A bare related edge can only be recorded as
// AttributionRelatedOnly.
type CVEAttribution struct {
	ID                string               `json:"id"`
	CVEID             string               `json:"cve_id"`
	Candidate         RecordPin            `json:"candidate"`
	EntryRefs         []int                `json:"entry_refs,omitempty"`
	MechanismID       string               `json:"mechanism_id,omitempty"`
	Basis             AttributionBasis     `json:"basis,omitempty"`
	SourceURI         string               `json:"source_uri,omitempty"`
	CapturedDigest    string               `json:"captured_digest,omitempty"`
	SourceField       string               `json:"source_field,omitempty"`
	SourceQuote       string               `json:"source_quote,omitempty"`
	PublisherAdvisory string               `json:"publisher_advisory,omitempty"`
	Module            string               `json:"module,omitempty"`
	Repository        string               `json:"repository,omitempty"`
	FixRefs           []string             `json:"fix_refs,omitempty"`
	Admission         AttributionAdmission `json:"admission"`
}

// Admitted reports whether this attribution may bind the candidate's positive
// to the requested CVE.
func (a CVEAttribution) Admitted() bool { return a.Admission == AttributionAdmitted }

// Validate enforces the attribution record, including the captured-material
// obligation of the publisher and CNA bases.
func (a CVEAttribution) Validate() error {
	if strings.TrimSpace(a.ID) == "" {
		return fmt.Errorf("cve attribution: id is required")
	}
	if strings.TrimSpace(a.CVEID) == "" {
		return fmt.Errorf("cve attribution %q: cve id is required", a.ID)
	}
	if err := a.Candidate.Validate(); err != nil {
		return fmt.Errorf("cve attribution %q: %w", a.ID, err)
	}
	if !a.Admission.Valid() {
		return fmt.Errorf("cve attribution %q: unknown admission %q", a.ID, a.Admission)
	}
	if a.Admission == AttributionRelatedOnly {
		if a.Basis != "" {
			return fmt.Errorf("cve attribution %q: %s admission carries no attribution basis (got %q)",
				a.ID, a.Admission, a.Basis)
		}
		return nil
	}
	if !a.Basis.Valid() {
		return fmt.Errorf("cve attribution %q: unknown attribution basis %q", a.ID, a.Basis)
	}
	// Entry refs are ordered and deduplicated original affected[] indices.
	if err := validateEntryRefs("cve attribution "+a.ID+" entry refs", a.EntryRefs); err != nil {
		return err
	}
	if a.Basis.Captured() {
		if strings.TrimSpace(a.SourceURI) == "" {
			return fmt.Errorf("cve attribution %q: basis %s requires the captured source URI", a.ID, a.Basis)
		}
		if err := validatePinnedDigest("cve attribution "+a.ID+" captured digest", a.CapturedDigest); err != nil {
			return err
		}
		if strings.TrimSpace(a.SourceField) == "" {
			return fmt.Errorf("cve attribution %q: basis %s requires the exact source field", a.ID, a.Basis)
		}
		if strings.TrimSpace(a.SourceQuote) == "" {
			return fmt.Errorf("cve attribution %q: basis %s requires the exact source quote", a.ID, a.Basis)
		}
		if strings.TrimSpace(a.PublisherAdvisory) == "" {
			return fmt.Errorf("cve attribution %q: basis %s requires the publisher advisory identity", a.ID, a.Basis)
		}
		if strings.TrimSpace(a.Module) == "" && strings.TrimSpace(a.Repository) == "" {
			return fmt.Errorf("cve attribution %q: basis %s requires the covered module or repository", a.ID, a.Basis)
		}
		if len(a.FixRefs) == 0 {
			return fmt.Errorf("cve attribution %q: basis %s requires the fix reference", a.ID, a.Basis)
		}
		for n, ref := range a.FixRefs {
			if strings.TrimSpace(ref) == "" {
				return fmt.Errorf("cve attribution %q: fix_refs[%d] is empty", a.ID, n)
			}
		}
	}
	if a.Admission == AttributionAdmitted {
		if len(a.EntryRefs) == 0 && strings.TrimSpace(a.MechanismID) == "" {
			return fmt.Errorf("cve attribution %q: %s attribution must bind a covered entry or mechanism",
				a.ID, a.Admission)
		}
	}
	return nil
}

// CorpusAssessedRecord is one nominated candidate's independently earned result
// inside the declared corpus. Corpus completeness supplies the boundary; it
// never supplies the semantic negative. Only an admitted NOT_AFFECTED child may
// appear here, because NO_EXPLOIT_PATH_FOUND is not a relabelled NOT_AFFECTED
// and an unknown or failed child is not a negative.
type CorpusAssessedRecord struct {
	Record  RecordPin         `json:"record"`
	Outcome AssessmentOutcome `json:"assessment_outcome"`
	Verdict Verdict           `json:"verdict,omitempty"`
}

// Validate enforces the per-candidate unaffectedness obligation.
func (a CorpusAssessedRecord) Validate() error {
	if err := a.Record.Validate(); err != nil {
		return fmt.Errorf("corpus assessed record: %w", err)
	}
	if !a.Outcome.Valid() {
		return fmt.Errorf("corpus assessed record %q: unknown outcome %q", a.Record.RecordID, a.Outcome)
	}
	if a.Outcome != OutcomeDecided {
		return fmt.Errorf("corpus assessed record %q: %s cannot contribute a corpus negative",
			a.Record.RecordID, a.Outcome)
	}
	if a.Verdict != VerdictNotAffected {
		return fmt.Errorf("corpus assessed record %q: verdict %q is not %q; a corpus negative needs admitted unaffectedness",
			a.Record.RecordID, a.Verdict, VerdictNotAffected)
	}
	return nil
}

const corpusBoundaryFormat = "Corpus boundary: `%s`, digest `%s`, captured `%s`; implementations outside this corpus were not examined."

// CorpusBoundaryStatement renders the mandatory, verbatim corpus boundary:
// which corpus, its digest, its capture date, and the statement that
// implementations outside it were not examined.
func CorpusBoundaryStatement(reference, digest, capturedAt string) string {
	return fmt.Sprintf(corpusBoundaryFormat, reference, digest, capturedAt)
}

// CorpusNegativeBasis is the explicit typed Addendum-A completeness basis for a
// CVE-wide negative. It records which declared, digest-pinned corpus was
// completely enumerated, the manifest digest that proves it, every nominated
// candidate's independently earned unaffectedness result, and the boundary
// statement carried verbatim.
//
// It does not weaken or reproduce AdvisoryScope.AllowsNegativeClosure: that
// predicate is untouched, and a CVE request remains non-closing by enumeration
// alone. This basis closes only a declared corpus, and only when every part of
// it is present.
type CorpusNegativeBasis struct {
	Reference         string                 `json:"reference"`
	DeclaredDigest    string                 `json:"declared_digest"`
	ObservedDigest    string                 `json:"observed_digest"`
	CapturedAt        string                 `json:"captured_at"`
	Enumeration       DiscoveryEnumeration   `json:"enumeration"`
	ManifestDigest    string                 `json:"manifest_digest"`
	AssessedRecords   []CorpusAssessedRecord `json:"assessed_records,omitempty"`
	BoundaryStatement string                 `json:"boundary_statement"`
}

// Validate enforces every part of the declared completeness basis: a matching
// declared/observed digest, a finished enumeration, a pinned manifest, admitted
// per-candidate unaffectedness and the verbatim boundary statement.
func (b *CorpusNegativeBasis) Validate() error {
	if b == nil {
		return fmt.Errorf("corpus negative basis: nil basis")
	}
	if strings.TrimSpace(b.Reference) == "" {
		return fmt.Errorf("corpus negative basis: corpus reference is required")
	}
	if err := validatePinnedDigest("corpus negative basis "+b.Reference+" declared digest", b.DeclaredDigest); err != nil {
		return err
	}
	if err := validatePinnedDigest("corpus negative basis "+b.Reference+" observed digest", b.ObservedDigest); err != nil {
		return err
	}
	if b.DeclaredDigest != b.ObservedDigest {
		return fmt.Errorf("corpus negative basis %q: declared digest %q != observed digest %q",
			b.Reference, b.DeclaredDigest, b.ObservedDigest)
	}
	if strings.TrimSpace(b.CapturedAt) == "" {
		return fmt.Errorf("corpus negative basis %q: capture date is required", b.Reference)
	}
	if !b.Enumeration.Valid() {
		return fmt.Errorf("corpus negative basis %q: unknown enumeration outcome %q", b.Reference, b.Enumeration)
	}
	if !b.Enumeration.Complete() {
		return fmt.Errorf("corpus negative basis %q: enumeration %q cannot ground a CVE-wide negative",
			b.Reference, b.Enumeration)
	}
	if err := validatePinnedDigest("corpus negative basis "+b.Reference+" manifest digest", b.ManifestDigest); err != nil {
		return err
	}
	for n, record := range b.AssessedRecords {
		if err := record.Validate(); err != nil {
			return fmt.Errorf("corpus negative basis %q: assessed_records[%d]: %w", b.Reference, n, err)
		}
	}
	if want := CorpusBoundaryStatement(b.Reference, b.ObservedDigest, b.CapturedAt); b.BoundaryStatement != want {
		return fmt.Errorf("corpus negative basis %q: boundary statement must be carried verbatim as %q",
			b.Reference, want)
	}
	return nil
}

// AllowsDeclaredCorpusClosure reports whether this basis may ground a CVE-wide
// negative under the operator decision. It is the typed corpus-completeness
// predicate, deliberately separate from AdvisoryScope.AllowsNegativeClosure.
//
// It is not sufficient on its own: CoversDiscoveredCandidates additionally
// proves every nominated candidate received an independently earned negative.
func (b *CorpusNegativeBasis) AllowsDeclaredCorpusClosure() bool {
	return b.Validate() == nil
}

// CoversDiscoveredCandidates reports whether every candidate nominated by the
// discovery record carries an admitted unaffectedness result in this basis. A
// nominated candidate without one blocks closure: corpus completeness never
// fills the semantic gap, and a partial, timed-out or failed child is not a
// negative.
func (b *CorpusNegativeBasis) CoversDiscoveredCandidates(discovery *RelatedDiscovery) error {
	if err := b.Validate(); err != nil {
		return err
	}
	if discovery == nil {
		return fmt.Errorf("corpus negative basis %q: the discovery record is required to prove candidate coverage",
			b.Reference)
	}
	if discovery.RequestedID == "" {
		return fmt.Errorf("corpus negative basis %q: the discovery record names no requested id", b.Reference)
	}
	if discovery.Corpus == nil {
		return fmt.Errorf("corpus negative basis %q: the discovery record pins no corpus identity", b.Reference)
	}
	if discovery.Corpus.Reference != b.Reference || discovery.Corpus.Digest != b.ObservedDigest {
		return fmt.Errorf("corpus negative basis %q: discovery ran against corpus %q (%s), not this basis",
			b.Reference, discovery.Corpus.Reference, discovery.Corpus.Digest)
	}
	for _, candidate := range discovery.Candidates {
		if !b.assessed(candidate.Record) {
			return fmt.Errorf("corpus negative basis %q: nominated candidate %q (%s) has no independently assessed unaffectedness result",
				b.Reference, candidate.Record.RecordID, candidate.Record.DocumentDigest)
		}
	}
	return nil
}

// assessed reports whether the basis carries an unaffectedness result for the
// exact document bytes. The scan allocates nothing.
func (b *CorpusNegativeBasis) assessed(pin RecordPin) bool {
	for _, record := range b.AssessedRecords {
		if record.Record.Same(pin) {
			return true
		}
	}
	return false
}

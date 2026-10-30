// Package claimshape normalizes persisted agenttriage claims into the
// canonical claim model of docs/dev/plans/universal-verifier-plan.md §4.
//
// Extraction is structural only: a claim's shape is derived from the
// deterministic artifacts it is bound to — recorded observations,
// fact-gate-validated evidence locators, falsifier proposals and the
// stage0/advisory projection. The claim's free-text statement and the
// assessment's verdict are carried verbatim as labels for audit and are
// never read for meaning: no string of the statement, summary or verdict
// enters the classifier. A claim whose evidence binds to no known
// canonical predicate is marked UNSUPPORTED with an explicit reason
// instead of being silently dropped or guessed.
//
// The package never produces a verdict, a recommendation or any other
// decision-level output; it rewrites claims into typed predicates so a
// later entailment layer can evaluate them.
package claimshape

// Shape is the canonical claim-shape identifier of plan §4. The set is
// closed: decoding accepts only these spellings, plus the explicit
// ShapeUnsupported marker for claims no canonical shape covers.
type Shape string

const (
	ShapeApplicabilityVersionInRange Shape = "applicability.version_in_range"
	ShapeSubjectDeclared             Shape = "subject.declared"
	ShapeSubjectAbsent               Shape = "subject.absent"
	ShapePathReachable               Shape = "path.reachable"
	ShapePathUnreachable             Shape = "path.unreachable"
	ShapeInputOrigin                 Shape = "input.origin"
	ShapeInputAttackerControlled     Shape = "input.attacker_controlled"
	ShapeControlPresent              Shape = "control.present"
	ShapeControlAbsent               Shape = "control.absent"
	ShapeConfigurationPredicate      Shape = "configuration.predicate"
	ShapeEnvironmentBuildGate        Shape = "environment.build_gate"
	ShapePerimeterExposure           Shape = "perimeter.exposure"
	ShapeClosureComplete             Shape = "closure.complete"
	ShapeProvenanceBound             Shape = "provenance.bound"
	ShapeDerivedMandatoryCondition   Shape = "derived.mandatory_condition"
	ShapeDerivedTriageDisposition    Shape = "derived.triage_disposition"
	// ShapeUnsupported is not a canonical shape: it marks claims whose
	// evidence does not bind to any canonical predicate. It is an
	// explicit, counted outcome — never a silent drop.
	ShapeUnsupported Shape = "UNSUPPORTED"
)

// Valid reports whether s is a canonical shape or the explicit
// UNSUPPORTED marker.
func (s Shape) Valid() bool { return ShapePredicate(s) != "" || s == ShapeUnsupported }

// canonical lists the canonical shapes in taxonomy order.
var canonical = []Shape{
	ShapeApplicabilityVersionInRange,
	ShapeSubjectDeclared,
	ShapeSubjectAbsent,
	ShapePathReachable,
	ShapePathUnreachable,
	ShapeInputOrigin,
	ShapeInputAttackerControlled,
	ShapeControlPresent,
	ShapeControlAbsent,
	ShapeConfigurationPredicate,
	ShapeEnvironmentBuildGate,
	ShapePerimeterExposure,
	ShapeClosureComplete,
	ShapeProvenanceBound,
	ShapeDerivedMandatoryCondition,
	ShapeDerivedTriageDisposition,
}

// CanonicalShapes returns the closed canonical shape set in taxonomy
// order (UNSUPPORTED excluded — it is a marker, not a shape).
func CanonicalShapes() []Shape { return append([]Shape(nil), canonical...) }

// Polarity is the value the claim asserts for its predicate, as witnessed
// by the structured artifacts the claim cites. PolarityTrue asserts the
// predicate holds, PolarityFalse asserts it does not, PolarityUnknown
// records that the cited signals do not determine a single asserted
// value — the shape still stands, but no verifier may treat the claim as
// either proved or refuted on polarity alone.
type Polarity string

const (
	PolarityTrue    Polarity = "TRUE"
	PolarityFalse   Polarity = "FALSE"
	PolarityUnknown Polarity = "UNKNOWN"
)

// UnsupportedReason names why a claim could not be normalized to a
// canonical shape. The set is closed so reports can aggregate on it.
type UnsupportedReason string

const (
	// ReasonNoEvidenceRefs — the claim cites no evidence and owns no
	// falsifier proposal whose evidence could substitute.
	ReasonNoEvidenceRefs UnsupportedReason = "no_evidence_refs"
	// ReasonWeakEvidenceOnly — every cited artifact is display-level
	// (source span, file content, directory listing): it locates code
	// but asserts no checkable predicate, so the claim's real predicate
	// lives only in prose.
	ReasonWeakEvidenceOnly UnsupportedReason = "weak_evidence_only"
	// ReasonUnresolvableReference — cited observation ids do not exist
	// in the run's observation archive (or resolve ambiguously), so no
	// signal could be recovered.
	ReasonUnresolvableReference UnsupportedReason = "unresolvable_reference"
	// ReasonUnclassifiedEvidence — cited artifacts resolved but their
	// tool/evidence kind has no canonical signal class in the registry.
	ReasonUnclassifiedEvidence UnsupportedReason = "unclassified_evidence"
)

// SubjectKind classifies what a claim's predicate applies to.
type SubjectKind string

const (
	SubjectModule       SubjectKind = "module"
	SubjectPackage      SubjectKind = "package"
	SubjectSymbol       SubjectKind = "symbol"
	SubjectPattern      SubjectKind = "pattern"
	SubjectPath         SubjectKind = "path"
	SubjectCallSite     SubjectKind = "call_site"
	SubjectAdvisory     SubjectKind = "advisory"
	SubjectSnapshot     SubjectKind = "snapshot"
	SubjectModuleGraph  SubjectKind = "module_graph"
	SubjectManifest     SubjectKind = "manifest"
	SubjectComponent    SubjectKind = "component"
	SubjectBuildContext SubjectKind = "build_context"
	SubjectClaimSet     SubjectKind = "claim_set"
	SubjectUnknown      SubjectKind = "unknown"
)

// Subject names the entity a claim's predicate applies to. Name is the
// canonical identifier recovered from structured data (module path,
// package.symbol, advisory id, file path); Package/Symbol carry the
// decomposed form when the source artifact provides it.
type Subject struct {
	Kind    SubjectKind `json:"kind"`
	Name    string      `json:"name,omitempty"`
	Package string      `json:"package,omitempty"`
	Symbol  string      `json:"symbol,omitempty"`
}

// Scope records the coverage envelope of the evidence a claim is bound
// to. Completeness is the worst cited observation completeness
// (PARTIAL/UNKNOWN evidence can never silently read as complete);
// SnapshotHash/BuildContextHash pin the provenance context when every
// bound observation agrees on it.
type Scope struct {
	Completeness     string   `json:"completeness"`
	Descriptors      []string `json:"descriptors,omitempty"`
	SnapshotHash     string   `json:"snapshot_hash,omitempty"`
	BuildContextHash string   `json:"build_context_hash,omitempty"`
	ObservationIDs   []string `json:"observation_ids,omitempty"`
}

// Facet is one atomic signal recovered from a single cited artifact:
// which canonical family the evidence belongs to, which sign the
// underlying deterministic result reported, and how complete its scope
// was. Facets are the graph input for entailment; the claim's own shape
// is a deterministic rollup of its facets.
type Facet struct {
	EvidenceID    string `json:"evidence_id"`
	Locator       string `json:"locator,omitempty"`
	Kind          string `json:"kind,omitempty"`
	Family        string `json:"family"`
	Sign          string `json:"sign"`
	Weight        string `json:"weight"`
	Predicate     string `json:"predicate,omitempty"`
	Tool          string `json:"tool,omitempty"`
	ObservationID string `json:"observation_id,omitempty"`
	Status        string `json:"status,omitempty"`
	Completeness  string `json:"completeness,omitempty"`
	FactStatus    string `json:"fact_status,omitempty"`
	Canonical     bool   `json:"canonical_locator"`
}

// BoundProposal records a falsifier proposal attached to the claim: the
// deterministic check the agent requested and — when the persisted
// verifier report exists — the outcome it reached. Proposals are
// recorded, never executed here.
type BoundProposal struct {
	ID             string    `json:"id"`
	Kind           string    `json:"kind"`
	ConditionID    string    `json:"condition_id,omitempty"`
	CheckShape     Shape     `json:"check_shape"`
	Subjects       []Subject `json:"subjects,omitempty"`
	EvidenceRefs   []string  `json:"evidence_refs,omitempty"`
	ProofStatus    string    `json:"proof_status,omitempty"`
	ProofBasis     string    `json:"proof_basis,omitempty"`
	ProofMandatory *bool     `json:"proof_mandatory,omitempty"`
}

// ClaimSource ties a canonical claim back to the persisted assessment
// that produced it. Statement is stored verbatim for audit only; nothing
// in the classifier reads it.
type ClaimSource struct {
	Ticket           string `json:"ticket,omitempty"`
	FindingID        string `json:"finding_id,omitempty"`
	RunID            string `json:"run_id,omitempty"`
	ClaimID          string `json:"claim_id,omitempty"`
	ClaimStatus      string `json:"claim_status,omitempty"`
	DecisionRelevant bool   `json:"decision_relevant"`
	Statement        string `json:"statement,omitempty"`
}

// CanonicalClaim is the typed claim of plan §4. Unsupported claims still
// carry Source, Facets and Parameters so the report can explain them.
type CanonicalClaim struct {
	ID                   string            `json:"id"`
	Shape                Shape             `json:"shape"`
	Subject              Subject           `json:"subject"`
	Predicate            string            `json:"predicate,omitempty"`
	Parameters           map[string]any    `json:"parameters,omitempty"`
	Polarity             Polarity          `json:"polarity"`
	Scope                Scope             `json:"scope"`
	EvidenceRefs         []string          `json:"evidence_refs,omitempty"`
	RequiredCapabilities []string          `json:"required_capabilities,omitempty"`
	UnsupportedReason    UnsupportedReason `json:"unsupported_reason,omitempty"`
	Source               ClaimSource       `json:"source"`
}

// AdvisoryFacts is the deterministic advisory context recovered for a
// run (from stage0's resolution projection or the frozen advisory
// documents): authoritative affected subjects, affected version ranges
// and environment constraints. These are data, not rules — nothing here
// is keyed on a specific advisory id.
type AdvisoryFacts struct {
	IDs             []string       `json:"ids,omitempty"`
	ResolvedID      string         `json:"resolved_id,omitempty"`
	Module          string         `json:"module,omitempty"`
	Package         string         `json:"package,omitempty"`
	AffectedSymbols []Subject      `json:"affected_symbols,omitempty"`
	AffectedRanges  []VersionRange `json:"affected_ranges,omitempty"`
	Environments    []string       `json:"environments,omitempty"`
}

// VersionRange is one advisory affected range in flattened event form.
type VersionRange struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

// RunExtraction is the full normalized result for one intake run: its
// canonical claims plus the run-level deterministic context the claims
// were extracted against. Verdict and recommendation travel as labels —
// the extraction never consumes them.
type RunExtraction struct {
	SchemaVersion     string            `json:"schema_version"`
	Ticket            string            `json:"ticket"`
	RunDir            string            `json:"run_dir"`
	RunID             string            `json:"run_id,omitempty"`
	FindingID         string            `json:"finding_id,omitempty"`
	HasAssessment     bool              `json:"has_assessment"`
	Advisory          AdvisoryFacts     `json:"advisory"`
	BuildContext      map[string]string `json:"build_context,omitempty"`
	SourceID          string            `json:"source_id,omitempty"`
	SelectedRef       string            `json:"selected_ref,omitempty"`
	InternalStatus    string            `json:"internal_status,omitempty"`
	Judgment          string            `json:"judgment,omitempty"`
	Recommendation    string            `json:"recommendation,omitempty"`
	Verdict           string            `json:"verdict,omitempty"`
	FactValidation    string            `json:"fact_validation,omitempty"`
	Claims            []CanonicalClaim  `json:"claims,omitempty"`
	UnclassifiedTools []string          `json:"unclassified_tools,omitempty"`
	Limitations       []string          `json:"limitations,omitempty"`
}

// ExtractionSchemaVersion identifies the report output schema.
const ExtractionSchemaVersion = "claimshape-extraction.v1"

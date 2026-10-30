package fixbinding

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/davniy/izyan/internal/domain"
)

// This file defines the re-derivable proof contract. A binding is a claim about
// one original advisory entry: which captured fix artifacts were inventoried,
// which security operations they change, where those operations live in the
// exact selected implementation, which alternatives could carry the same
// mechanism, and — for a mechanism the boundary proves absent — the closed
// structural certificate that establishes it.
//
// Nothing here is authority. Derive reconstructs every premise from the pinned
// input bundle; Admit requires the claimed binding to equal that reconstruction
// field by field. A stored Status, a saved Complete flag, a component-label list
// or an equation written as prose is diagnostic output and never a premise.

// BindingStatus is the diagnostic outcome of one derivation. Only Admitted may
// ground an absence claim, and only an Admit call produces it: CoverEstablished
// says the cover was reconstructed but no claim relationship was checked.
type BindingStatus string

const (
	BindingUnmeasured BindingStatus = "UNMEASURED"
	BindingUnresolved BindingStatus = "UNRESOLVED"
	BindingCover      BindingStatus = "COVER_ESTABLISHED"
	BindingAdmitted   BindingStatus = "ADMITTED"
)

// Disposition is the single terminal answer for one patch effect.
type Disposition string

const (
	// DispositionMapped binds the effect to selected-source locations whose
	// operation class, resource identity and checked value correspond.
	DispositionMapped Disposition = "MAPPED"
	// DispositionNonExecutable accounts for a change with no executable effect.
	DispositionNonExecutable Disposition = "NON_EXECUTABLE"
	// DispositionInapplicable records that the mechanism the effect performs
	// has no counterpart or bypass anywhere in the closed implementation
	// boundary. It never carries a subject.
	DispositionInapplicable Disposition = "INAPPLICABLE"
	// DispositionUnresolved records that no disposition could be established.
	DispositionUnresolved Disposition = "UNRESOLVED"
)

// RefusalCode names the premise that failed re-admission, so a consumer routes
// on the identifier instead of parsing prose.
type RefusalCode string

const (
	RefusalInput          RefusalCode = "INPUT"
	RefusalIdentity       RefusalCode = "RECORD_IDENTITY"
	RefusalEntry          RefusalCode = "ENTRY"
	RefusalSeries         RefusalCode = "SERIES"
	RefusalArtifacts      RefusalCode = "ARTIFACTS"
	RefusalCoordinate     RefusalCode = "EFFECTIVE_COORDINATE"
	RefusalCensus         RefusalCode = "CENSUS"
	RefusalEffects        RefusalCode = "EFFECTS"
	RefusalLocations      RefusalCode = "LOCATIONS"
	RefusalNonCounterpart RefusalCode = "NON_COUNTERPART"
	RefusalSubjects       RefusalCode = "SUBJECTS"
	RefusalCover          RefusalCode = "COVER"
	RefusalClaim          RefusalCode = "CLAIM"
	RefusalObligations    RefusalCode = "OBLIGATIONS"
	RefusalStatus         RefusalCode = "STATUS"
	RefusalContract       RefusalCode = "PROOF_CONTRACT"
	RefusalNotAdmitted    RefusalCode = "NOT_ADMITTED"
	RefusalPatch          RefusalCode = "PATCH"
)

// Refusal is a typed admission failure. It is never a negative result: the
// caller learns which premise could not be re-derived, not that the subject is
// harmless.
type Refusal struct {
	Code RefusalCode
	Msg  string
}

func (r *Refusal) Error() string {
	if r == nil {
		return "fix binding refused"
	}
	return string(r.Code) + ": " + r.Msg
}

func refuse(code RefusalCode, format string, args ...any) error {
	return &Refusal{Code: code, Msg: fmt.Sprintf(format, args...)}
}

// RefusalCodeOf returns the typed code of an admission error, if it carries one.
// The traversal is by errors.As so a wrapped refusal still routes.
func RefusalCodeOf(err error) RefusalCode {
	var refusal *Refusal
	if errors.As(err, &refusal) {
		return refusal.Code
	}
	return ""
}

// Inputs is the immutable bundle one derivation reads. Every premise is
// supplied as captured bytes or as an independently measured record; nothing
// here is a summary a producer may assert:
//
//   - Raw is the complete advisory document, and Pin is the identity it must
//     still hash to;
//   - Selection holds Task 2's per-entry effective-source descriptors, and
//     Inventory holds Task 5's independently anchored inventory of the selected
//     implementation;
//   - Artifacts holds Task 3's per-locator acquisition record together with the
//     complete captured bytes (directly, or through another locator's bytes);
//   - PatchSources maps each declared locator to the complete patch-side
//     source that artifact's identifiers may be resolved against. Locators are
//     not a series, so two artifacts from different trees carry separate
//     captures; no locator ever reads another's source;
//   - External holds captured complete source of effective external
//     implementation components a closed-boundary proof must inspect;
//   - Claim, when non-nil, is the condition/verification relationship the
//     caller wants checked against the reconstructed cover.
type Inputs struct {
	Pin          domain.RecordPin
	Raw          []byte
	EntryRef     int
	Selection    []domain.EffectiveSourceSelection
	Inventory    SourceInventory
	Artifacts    []ArtifactInput
	PatchSources map[string]*SourceBundle
	External     []ExternalComponent
 Captures *SourceCaptures
	Claim        *CoverClaim
}

// ArtifactInput is one declared fix locator's acquisition record and the
// complete bytes the acquisition captured. Bytes is nil when nothing was
// captured; a duplicate locator leaves Bytes nil and resolves through its
// DuplicateOf reference.
type ArtifactInput struct {
	Artifact domain.FixArtifact
	Bytes    []byte
}

// ExternalComponent is one effective external implementation component: the
// import path the selected source uses for it and the independently anchored
// complete inventory of its own source.
type ExternalComponent struct {
	ImportPath string
	Inventory  SourceInventory
}

// CoverClaim is the condition/verification relationship a caller asserts. The
// checker does not trust it: it must equal the reconstructed cover, in both
// directions, or the admission is refused.
type CoverClaim struct {
	// ConditionSubjects are the subjects the mandatory condition ranges over.
	ConditionSubjects []domain.SymbolRef
	// VerificationCoverID and VerificationSubjectDigest are the cover identity
	// and subject-set digest the negative verification recorded.
	VerificationCoverID       string
	VerificationSubjectDigest string
}

// EntryRecord is the original affected[] entry the binding is about,
// reconstructed from the record bytes: the original index, its ecosystem and
// module, and the scope/declarations the entry itself declares.
type EntryRecord struct {
	Index         int                   `json:"index"`
	Ecosystem     string                `json:"ecosystem,omitempty"`
	Module        string                `json:"module,omitempty"`
	Packages      []string              `json:"packages,omitempty"`
	Symbols       []domain.SymbolRef    `json:"symbols,omitempty"`
	Ranges        []domain.VersionRange `json:"ranges,omitempty"`
	FixedVersions []string              `json:"fixed_versions,omitempty"`
}

// SeriesLocator is one fix locator the record declares, in declaration order.
type SeriesLocator struct {
	Locator string `json:"locator"`
	Kind    string `json:"kind,omitempty"`
}

// ArtifactRecord is one declared locator's re-verified acquisition account. The
// digest is recomputed from the captured bytes; Relevance is recomputed against
// the selected inventory, never copied from an acquisition outcome.
type ArtifactRecord struct {
	Locator     string                    `json:"locator"`
	Kind        string                    `json:"kind,omitempty"`
	Outcome     domain.FixArtifactOutcome `json:"outcome"`
	Provenance  string                    `json:"provenance,omitempty"`
	Digest      string                    `json:"digest,omitempty"`
	Size        int                       `json:"size,omitempty"`
	Coordinates []string                  `json:"coordinates,omitempty"`
	Relevant    bool                      `json:"relevant"`
	Captured    bool                      `json:"captured"`
	DuplicateOf string                    `json:"duplicate_of,omitempty"`
	Bound       bool                      `json:"bound"`
}

// PatchSourceRecord pins one locator's complete patch-side source: the module
// identity it belongs to, the digest of that locator's verified artifact bytes,
// and the digest of the complete source bundle. It is a separate capture from
// the selected implementation (a cross-release-line patch was authored against
// another version), so it is recorded as its own premise and never shared with
// a locator whose artifact bytes differ.
type PatchSourceRecord struct {
	Locator        string `json:"locator"`
	ArtifactDigest string `json:"artifact_digest,omitempty"`
	Module         string `json:"module"`
	Version        string `json:"version,omitempty"`
	Files          int    `json:"files"`
	Digest         string `json:"digest"`
}

// PatchRecord is one inventoried captured patch: its locator, the digest of the
// exact bytes, and the canonical accounting digest the effects were built from.
type PatchRecord struct {
	Locator           string `json:"locator"`
	Digest            string `json:"digest"`
	Files             int    `json:"files"`
	Effects           int    `json:"effects"`
	InventoryDigest   string `json:"inventory_digest"`
	InventoryComplete bool   `json:"inventory_complete"`
}

// CensusRecord is the reconstructed selected-implementation census, reduced to
// the facts a claim depends on. Mutating any field — boundary, file count,
// digest, module, operation count or an aspect result — is refused on
// re-admission.
type CensusRecord struct {
	Module    string `json:"module"`
	Version   string `json:"version,omitempty"`
	Kind      string `json:"source_kind,omitempty"`
	SourceRef string `json:"source_ref,omitempty"`
	Boundary  string `json:"boundary"`
	Files     int    `json:"files"`
	Digest    string `json:"digest,omitempty"`
	// Anchor is the independent checksum evidence the inventory was established
	// from (kind:value). A census without it is not anchored.
	Anchor       string       `json:"anchor,omitempty"`
	PackagePaths []string     `json:"package_paths,omitempty"`
	Operations   int          `json:"operations"`
	Wrappers     int          `json:"wrappers"`
	Anchored     bool         `json:"anchored"`
	Parse        AspectResult `json:"parse"`
	Analysis     AspectResult `json:"analysis"`
}

// OperationRecord is one side of a patch effect: the resolved declaration, its
// class, its correspondence resource key and its checked permission value.
type OperationRecord struct {
	Identity    string `json:"identity"`
	Source      string `json:"source,omitempty"`
	ImportPath  string `json:"import_path,omitempty"`
	Receiver    string `json:"receiver,omitempty"`
	Name        string `json:"name"`
	Signature   string `json:"signature,omitempty"`
	Class       string `json:"class"`
	ResourceKey string `json:"resource_key,omitempty"`
	Mode        string `json:"mode,omitempty"`
}

// Relation components every admitted location must carry.
const (
	RelationOperation = "operation"
	RelationResource  = "resource"
	RelationValue     = "value"
	RelationFlow      = "flow"
)

// LocationRecord is one verified selected-source location. Component names the
// implementation it was read from ("selected" or an external component's import
// path). The four relation components are the checked relation, not a label
// list: the checker re-derives each one.
type LocationRecord struct {
	Component   string   `json:"component"`
	File        string   `json:"file"`
	Line        int      `json:"line"`
	Col         int      `json:"col,omitempty"`
	Package     string   `json:"package"`
	Symbol      string   `json:"symbol"`
	Declaration string   `json:"declaration"`
	Identity    string   `json:"identity"`
	Class       string   `json:"class"`
	ResourceKey string   `json:"resource_key"`
	Mode        string   `json:"mode,omitempty"`
	Components  []string `json:"components"`
	Entry       bool     `json:"entry,omitempty"`
}

// Subject returns the location's absence subject.
func (l LocationRecord) Subject() domain.SymbolRef {
	return domain.SymbolRef{Package: l.Package, Symbol: l.Symbol}
}

// OmissionRecord records the verified pre-existing pipeline that lacks the
// protection an added operation supplies. An added operation does not exist in
// the vulnerable source, so the omission site is its subject.
type OmissionRecord struct {
	ResourceKey string             `json:"resource_key"`
	Class       string             `json:"class"`
	Mode        string             `json:"mode"`
	Carriers    []domain.SymbolRef `json:"carriers,omitempty"`
	Verified    bool               `json:"verified"`
	Detail      string             `json:"detail,omitempty"`
}

// EffectRecord is one patch effect with its canonical disposition, verified
// locations, omission site and — when INAPPLICABLE — the certificate that
// discharged it.
type EffectRecord struct {
	ID          string                     `json:"id"`
	Locator     string                     `json:"locator"`
	Path        string                     `json:"path"`
	Class       string                     `json:"class"`
	Added       bool                       `json:"added,omitempty"`
	Removed     bool                       `json:"removed,omitempty"`
	Before      *OperationRecord           `json:"before,omitempty"`
	After       *OperationRecord           `json:"after,omitempty"`
	Spans       []string                   `json:"spans,omitempty"`
	Branches    []string                   `json:"branches,omitempty"`
	Disposition Disposition                `json:"disposition"`
	Locations   []LocationRecord           `json:"locations,omitempty"`
	Omission    *OmissionRecord            `json:"omission,omitempty"`
	Subjects    []domain.SymbolRef         `json:"subjects,omitempty"`
	Certificate *NonCounterpartCertificate `json:"non_counterpart,omitempty"`
	Detail      string                     `json:"detail,omitempty"`
}

// SubjectRecord is one member of a necessary cover: the implementation the
// mechanism could execute in, with a re-checkable coordinate.
type SubjectRecord struct {
	Package     string `json:"package"`
	Symbol      string `json:"symbol"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Declaration string `json:"declaration"`
	Identity    string `json:"identity"`
	Mode        string `json:"mode,omitempty"`
	Alternative bool   `json:"alternative,omitempty"`
	Map         bool   `json:"mapped,omitempty"`
}

// Ref is the subject's absence identity.
func (s SubjectRecord) Ref() domain.SymbolRef {
	return domain.SymbolRef{Package: s.Package, Symbol: s.Symbol}
}

// MechanismCover is one necessary disjunction:
//
//	D(entry, mechanism) => Exec(subject_1) or ... or Exec(subject_n)
//
// It carries the complete enumerated subject set, the subset the patch mapping
// verified, and the alternatives that only the exhaustive enumeration found.
type MechanismCover struct {
	Mechanism     string          `json:"mechanism"`
	Keys          []string        `json:"keys"`
	Subjects      []SubjectRecord `json:"subjects"`
	Mapped        []SubjectRecord `json:"mapped,omitempty"`
	Alternatives  []SubjectRecord `json:"alternatives,omitempty"`
	SubjectDigest string          `json:"subject_digest"`
	ID            string          `json:"id"`
}

// CoverRecord is the aggregate cover a claim must reference. It has no
// authority by itself: the claim relationship decides whether anything may
// rely on it.
type CoverRecord struct {
	Rule          string             `json:"rule"`
	Mechanisms    int                `json:"mechanisms"`
	Subjects      []domain.SymbolRef `json:"subjects,omitempty"`
	Mapped        []domain.SymbolRef `json:"mapped,omitempty"`
	Alternatives  []domain.SymbolRef `json:"alternatives,omitempty"`
	SubjectDigest string             `json:"subject_digest"`
	ID            string             `json:"id"`
}

// ProofObligation is one blocking fact the derivation kept. It is a closed
// code plus the location that produced it; prose never carries authority.
type ProofObligation struct {
	Kind    string `json:"kind"`
	Code    string `json:"code"`
	Locator string `json:"locator,omitempty"`
	File    string `json:"file,omitempty"`
	Line    int    `json:"line,omitempty"`
	Detail  string `json:"detail"`
}

// LocatorApplicability is what one captured locator's material establishes
// before the semantic proof is attempted: the supported operation classes its
// changed spans resolve to, and — when it resolves none — the reason it does
// not. It is a measurement of the captured bytes, never an admission.
type LocatorApplicability struct {
	Locator string           `json:"locator"`
	Classes []OperationClass `json:"classes,omitempty"`
	// Reason is set only when this locator resolved no supported operation.
	Reason string `json:"reason,omitempty"`
}

// Applicability is the precondition the semantic content proof runs under.
//
// The proof is about security operations and the mechanism that carries them.
// When the captured material changes no declaration this build classifies, the
// derivation has nothing to be about: it would inventory prose, find no
// effect, and report the same absence without ever establishing a mechanism.
// Applicability therefore measures the captured material first, so a caller
// records unsupported material as an observation and the specialized proof is
// never invoked for it. Refusals name every locator that carried no supported
// operation; Applicable is false when no locator carries one.
type Applicability struct {
	Applicable bool                   `json:"applicable"`
	Locators   []LocatorApplicability `json:"locators,omitempty"`
	Refusals   []string               `json:"refusals,omitempty"`
}

// Reason renders the refusals as one deterministic sentence.
func (a Applicability) Reason() string {
	return strings.Join(a.Refusals, "; ")
}

// FixApplicability measures whether the semantic content proof applies to the
// captured material in this bundle. It reads only the artifacts' captured
// bytes and each locator's own patch-side source — the same premises the
// derivation reads — and returns no error: material that cannot be inventoried
// is a refusal for that locator, not a failed measurement.
func FixApplicability(in Inputs) Applicability {
	out := Applicability{Locators: make([]LocatorApplicability, 0, len(in.Artifacts))}
	for _, artifact := range in.Artifacts {
		locator := artifact.Artifact.Locator
		entry := LocatorApplicability{Locator: locator}
		classes, reason := locatorOperations(artifact.Bytes, in.PatchSources[locator])
		entry.Classes, entry.Reason = classes, reason
		out.Locators = append(out.Locators, entry)
		if reason == "" {
			out.Applicable = true
			continue
		}
		out.Refusals = append(out.Refusals, fmt.Sprintf("locator %q: %s", locator, reason))
	}
	if !out.Applicable && len(out.Refusals) == 0 {
		out.Refusals = append(out.Refusals,
			"the bundle carries no captured fix material, so no supported security operation can be resolved")
	}
	return out
}

// locatorOperations inventories one locator's captured bytes against its own
// patch-side source and reports the supported operation classes its changed
// spans resolve to. An empty class list means the material is unsupported:
// either no span changes a classified declaration, or the bytes/source could
// not be inventoried at all.
func locatorOperations(patch []byte, source *SourceBundle) ([]OperationClass, string) {
	if len(patch) == 0 {
		return nil, "no captured patch bytes accompany this locator"
	}
	inventory, err := InventoryPatch(patch, InventoryOptions{Source: source})
	if err != nil {
		return nil, fmt.Sprintf("the captured patch could not be inventoried: %v", err)
	}
	var classes []OperationClass
	for _, effect := range inventory.Effects {
		// buildUnits only admits a changed call whose declaration the
		// supported set resolves, so every effect carries a class.
		if effect.Class != "" && !slices.Contains(classes, effect.Class) {
			classes = append(classes, effect.Class)
		}
	}
	if len(classes) == 0 {
		return nil, fmt.Sprintf(
			"the captured patch resolves none of the supported security operations (%s)",
			strings.Join(supportedOperationVocabulary(), ", "))
	}
	sort.Slice(classes, func(i, j int) bool { return classes[i] < classes[j] })
	return classes, ""
}

// Binding is the canonical derivation output, and the shape a caller's claim is
// compared against.
type Binding struct {
	Contract       string      `json:"contract"`
	Rules          string      `json:"rules"`
 CaptureDigest string `json:"capture_digest"`
	RecordID       string      `json:"record_id"`
	DocumentDigest string      `json:"document_digest"`
	EntryRef       int         `json:"entry_ref"`
	Entry          EntryRecord `json:"entry"`

	Module        string `json:"module"`
	Version       string `json:"version,omitempty"`
	SourceKind    string `json:"source_kind,omitempty"`
	SourceRoot    string `json:"source_root,omitempty"`
	ContentDigest string `json:"content_digest,omitempty"`

	Series         []SeriesLocator     `json:"series,omitempty"`
	Artifacts      []ArtifactRecord    `json:"artifacts,omitempty"`
	PrimaryLocator string              `json:"primary_locator,omitempty"`
	PatchSources   []PatchSourceRecord `json:"patch_sources,omitempty"`
	Census         CensusRecord        `json:"census"`
	Patches        []PatchRecord       `json:"patches,omitempty"`
	Effects        []EffectRecord      `json:"effects,omitempty"`
	Mechanisms     []MechanismCover    `json:"mechanisms,omitempty"`
	Cover          CoverRecord         `json:"cover"`
	Obligations    []ProofObligation   `json:"obligations,omitempty"`
	Claim          *CoverClaim         `json:"claim,omitempty"`
	Status         BindingStatus       `json:"status"`
	Detail         string              `json:"detail,omitempty"`
	Digest         string              `json:"digest,omitempty"`
}

// CanonicalDigest is the digest of the binding's canonical serialization. It
// binds a result to its content; it is never a completeness proof. The digest
// field itself is excluded so a result's digest is stable across re-derivation
// and does not depend on whether it has already been recorded.
func (b Binding) CanonicalDigest() string {
	b.Digest = ""
	sum := sha256.Sum256(canonicalJSON(b))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// SubjectSetDigest is the digest of a subject set: sorted, deduplicated and
// rendered by absence identity. Two different subject sets never share it.
func SubjectSetDigest(subjects []domain.SymbolRef) string {
	refs := normalizeSubjects(subjects)
	var b strings.Builder
	fmt.Fprintf(&b, "subjects:%d\n", len(refs))
	for _, s := range refs {
		fmt.Fprintf(&b, "%s\x00%s\n", s.Package, s.Symbol)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// CoverID is the identity of one claimed cover. It binds the record, the
// original entry, the mechanism identity, the subject-set digest and the
// selected-implementation census the cover was enumerated from.
func CoverID(recordDigest string, entryRef int, censusDigest, subjectDigest, premisesDigest string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n%s\n%d\n%s\n%s\n%s\n%s\n",
		domain.FixProofContract, recordDigest, entryRef, domain.FixProofRules, censusDigest, subjectDigest, premisesDigest)
	sum := sha256.Sum256([]byte(b.String()))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// MechanismID is the identity of one mechanism's cover.
func MechanismID(coverID, mechanism, subjectDigest string) string {
	sum := sha256.Sum256([]byte(coverID + "\x00" + mechanism + "\x00" + subjectDigest))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// normalizeSubjects sorts and deduplicates subject identities.
func normalizeSubjects(subjects []domain.SymbolRef) []domain.SymbolRef {
	seen := map[domain.SymbolRef]bool{}
	var out []domain.SymbolRef
	for _, s := range subjects {
		if s.Package == "" || s.Symbol == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Package != out[j].Package {
			return out[i].Package < out[j].Package
		}
		return out[i].Symbol < out[j].Symbol
	})
	return out
}

// sameSubjects compares two subject sets in both directions.
func sameSubjects(a, b []domain.SymbolRef) bool {
	left, right := normalizeSubjects(a), normalizeSubjects(b)
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

// canonicalJSON serializes a value deterministically for digesting.
func canonicalJSON(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		return []byte(fmt.Sprintf("unserializable:%T", v))
	}
	return raw
}

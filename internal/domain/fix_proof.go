package domain

import (
	"encoding/json"
	"fmt"
	"strings"
)

// This file defines the persisted content-proof contract: the re-derivable
// evidence that a captured fix artifact's mechanism was bound to the exact
// selected implementation, with a complete necessary cover. It is the only
// form in which a content binding may accompany a root-cause model.
//
// The record is deliberately a *premise bundle*, not a conclusion. It carries
// the canonical checker output and the exact captured inputs that output was
// derived from, so the shared absence boundary can re-run the pure checker
// (`internal/fixbinding`) and use the checker-created result instead of the
// saved one. A saved Status, a saved cover or a saved subject list is never
// authority: an edited projection is replaced by the reconstruction, and a
// proof whose inputs no longer reconstruct it establishes nothing.

// Persisted content-proof contract identifiers. They are owned here because
// they are persisted schema, and the checker refers to them rather than
// defining a second copy.
const (
	// FixProofContract identifies the full content-binding re-derivation
	// contract (captured advisory bytes, complete fix artifacts, anchored
	// selected-implementation inventory, necessary-cover enumeration).
	FixProofContract = "fixbinding/re-derivation/3"
	// FixProofRules identifies the correspondence, cover and non-counterpart
	// rule set the checker implements.
	FixProofRules = "correspondence+necessary-cover+closed-boundary/2"
	// FixProofCoverRule names the necessary-disjunction rule a mechanism cover
	// is built from.
	FixProofCoverRule = "necessary-disjunction-over-enumerated-mechanism-candidates/1"
	// FixProofNonCounterpartRule names the only supported non-counterpart rule.
	FixProofNonCounterpartRule = "closed-implementation-boundary/1"
)

// FixProofCover is the canonical aggregate cover a persisted proof establishes:
// the nonempty subject set a claim must equal, the subset the patch mapping
// verified, the alternatives only the exhaustive enumeration found, and the
// packages whose absence the necessary disjunction requires.
type FixProofCover struct {
	Rule          string      `json:"rule"`
	ID            string      `json:"id"`
	SubjectDigest string      `json:"subject_digest"`
	Subjects      []SymbolRef `json:"subjects"`
	Mapped        []SymbolRef `json:"mapped,omitempty"`
	Alternatives  []SymbolRef `json:"alternatives,omitempty"`
	Packages      []string    `json:"packages,omitempty"`
}

// FixProof is the persisted content-proof contract attached to a root-cause
// model. Binding is the canonical checker output, verbatim; Inputs is the exact
// captured input bundle it was derived from, verbatim. Both are opaque to
// every consumer except the pure checker, which compares the claimed binding
// against the reconstruction from Inputs and returns the checker-created
// result.
//
// The projected fields (RecordID, EntryRef, Module, Cover, Digest, …) are a
// convenience for diagnostics and for load-time validation. They are not read
// as authority: the checker rebuilds them from Binding/Inputs, and the shared
// boundary uses only the rebuilt projection.
type FixProof struct {
	Contract       string        `json:"contract"`
	Rules          string        `json:"rules"`
	RecordID       string        `json:"record_id"`
	DocumentDigest string        `json:"document_digest"`
	EntryRef       int           `json:"entry_ref"`
	Module         string        `json:"module,omitempty"`
	Version        string        `json:"version,omitempty"`
	SourceKind     string        `json:"source_kind,omitempty"`
	ContentDigest  string        `json:"content_digest,omitempty"`
	Cover          FixProofCover `json:"cover"`
	// Digest is the checker's canonical binding digest. It binds the result to
	// its content; it is not a completeness proof.
	Digest string `json:"digest,omitempty"`
	// Binding is the canonical checker output (JSON), preserved verbatim.
	Binding json.RawMessage `json:"binding"`
	// Inputs is the complete immutable input bundle (JSON) the binding was
	// re-derived from. Without it the proof is refused: a durable reference is
	// useful only when its bytes are supplied to the pure checker.
	Inputs json.RawMessage `json:"inputs"`
}

// Validate refuses a persisted proof that could not have come from the checker
// or that carries no cover to reconstruct. It is a shape check used by the
// checker's Readmit; case loading deliberately does not fail the whole case on
// an unsupported or malformed proof, because a refused proof refuses only its
// dependents, never the case's independent evidence.
func (p *FixProof) Validate() error {
	if p == nil {
		return nil
	}
	if p.Contract != FixProofContract {
		return fmt.Errorf("fix proof: unsupported proof contract %q (this build supports %q)", p.Contract, FixProofContract)
	}
	if p.Rules != FixProofRules {
		return fmt.Errorf("fix proof: unsupported checker rules %q (this build supports %q)", p.Rules, FixProofRules)
	}
	if strings.TrimSpace(p.RecordID) == "" {
		return fmt.Errorf("fix proof: record id is required")
	}
	if strings.TrimSpace(p.DocumentDigest) == "" {
		return fmt.Errorf("fix proof %q: document digest is required", p.RecordID)
	}
	if p.EntryRef < 0 {
		return fmt.Errorf("fix proof %q: entry ref %d is negative", p.RecordID, p.EntryRef)
	}
	if err := p.Cover.validate(); err != nil {
		return fmt.Errorf("fix proof %q: %w", p.RecordID, err)
	}
	if strings.TrimSpace(p.Digest) == "" {
		return fmt.Errorf("fix proof %q: canonical binding digest is required", p.RecordID)
	}
	if len(p.Binding) == 0 || !json.Valid(p.Binding) {
		return fmt.Errorf("fix proof %q: the canonical binding is missing or not valid JSON", p.RecordID)
	}
	if len(p.Inputs) == 0 || !json.Valid(p.Inputs) {
		return fmt.Errorf("fix proof %q: the captured input bundle is missing or not valid JSON", p.RecordID)
	}
	return nil
}

// validate refuses a cover that could not ground a nonempty necessary
// disjunction.
func (c *FixProofCover) validate() error {
	if strings.TrimSpace(c.Rule) == "" {
		return fmt.Errorf("cover: rule is required")
	}
	if strings.TrimSpace(c.ID) == "" {
		return fmt.Errorf("cover: identity is required")
	}
	if strings.TrimSpace(c.SubjectDigest) == "" {
		return fmt.Errorf("cover: subject-set digest is required")
	}
	if len(c.Subjects) == 0 {
		return fmt.Errorf("cover: the necessary subject set is empty")
	}
	for _, s := range c.Subjects {
		if strings.TrimSpace(s.Package) == "" || strings.TrimSpace(s.Symbol) == "" {
			return fmt.Errorf("cover: subject %+v names no package or symbol", s)
		}
	}
	return nil
}

// ContentAdmission is the checker-created result of re-deriving one persisted
// proof at the shared boundary. It is never produced from saved projections:
// the checker rebuilds the proof from the captured input bundle and only then
// fills this record.
//
// A nil or non-admitted admission establishes nothing. Refusals is preserved so
// the boundary states what could not be re-derived; Subjects is the set the
// persisted proof claimed, so a refused proof still dominates dependent labels
// instead of disappearing.
type ContentAdmission struct {
	Proof    *FixProof
	Refusals []string
	Subjects []SymbolRef
	// Opaque marks a persisted payload this build could not decode. Its
	// claimed subject set is unknown, so an operator or LLM label cannot be
	// distinguished from a relabel of the refused derivation.
	Opaque bool
}

// Admitted reports whether the checker re-derived the complete proof. The zero
// value refuses.
func (c *ContentAdmission) Admitted() bool {
	return c != nil && c.Proof != nil && len(c.Refusals) == 0
}

// ClaimsSubject reports whether the persisted proof claimed s. The answer
// blocks a relabel; it never authorises anything.
func (c *ContentAdmission) ClaimsSubject(s SymbolRef) bool {
	if c == nil {
		return false
	}
	for _, subject := range c.Subjects {
		if subject == s {
			return true
		}
	}
	return false
}

// Refusal states why s may not ground absence through the persisted proof. It
// names the typed code the checker refused with, so the boundary states which
// premise failed rather than that "something" did.
func (c *ContentAdmission) Refusal(s SymbolRef) string {
	subject := absenceSubjectLabel(s)
	if c == nil || len(c.Refusals) == 0 {
		return fmt.Sprintf(
			"subject %s rests on a persisted content proof that this boundary did not re-derive, so the proof establishes no identity, absence or completeness and a duplicate or relabelled candidate cannot resurrect it",
			subject)
	}
	if c.Opaque {
		return fmt.Sprintf(
			"subject %s is named by a persisted content proof this build cannot read: its established subject set is unknown, so an operator label cannot be distinguished from a relabel of that dependency",
			subject)
	}
	return fmt.Sprintf(
		"subject %s is named by a persisted content proof the checker refused (%s): the proof establishes no identity, absence or completeness, and a duplicate or relabelled candidate cannot resurrect it",
		subject, strings.Join(c.Refusals, "; "))
}

// contains reports whether the cover's necessary subject set names s.
func (c *FixProofCover) contains(s SymbolRef) bool {
	if c == nil {
		return false
	}
	for _, subject := range c.Subjects {
		if subject == s {
			return true
		}
	}
	return false
}

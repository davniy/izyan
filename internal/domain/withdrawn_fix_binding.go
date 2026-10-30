package domain

import (
	"encoding/json"
	"fmt"
)

// WithdrawnContentDerivedFixBinding names the proof kind this file preserves:
// the content-derived fix binding produced by the withdrawn 2026-10-28 Slice B.
const WithdrawnContentDerivedFixBinding = "CONTENT_DERIVED_FIX_BINDING"

// WithdrawnProof records, on the evaluation copy of a case, one historical
// proof the loader recognised as withdrawn. It exists so a replay states what
// was withdrawn instead of silently continuing with a weaker route. It is never
// persisted and it authorises nothing: every field is diagnostic only.
type WithdrawnProof struct {
	Kind   string
	Detail string
}

// WithdrawnFixBinding is the preserved record of a content-derived fix binding
// produced by the withdrawn 2026-10-28 Slice B. The stored bytes are kept
// verbatim (Raw): the withdrawal removes authority, not history, so a re-save
// must not delete what an earlier run recorded.
//
// It is deliberately not evidence. There is no admission method and no consumer
// reads it as proof: the admitted status the stored payload may carry is a
// historical conclusion, and the content-binding layer that could have re-derived
// it no longer exists. What this record does carry is the set of subjects the
// withdrawn binding admitted, which keeps the withdrawal honest — a candidate,
// operator label or duplicate record for one of those subjects is a dependent of
// withdrawn evidence, not an independent identity (see AbsenceAdmission).
type WithdrawnFixBinding struct {
	// RecordID and DocumentDigest identify the record whose bytes the withdrawn
	// binding claimed to answer.
	RecordID       string `json:"record_id,omitempty"`
	DocumentDigest string `json:"document_digest,omitempty"`
	// Status is the withdrawn binding's stored status. It is diagnostic: even
	// an ADMITTED value authorises nothing here.
	Status string `json:"status,omitempty"`
	// Detail is the withdrawn binding's stored diagnostic text.
	Detail string `json:"detail,omitempty"`
	// Subjects are the subjects the withdrawn binding admitted.
	Subjects []SymbolRef `json:"subjects,omitempty"`
	// Opaque marks a stored payload this build could not interpret. Its bytes
	// are preserved, but its admitted subject set is unknown — so every
	// operator assertion over the model is refused rather than assuming the
	// unreadable dependency cannot be a relabelled derivation.
	Opaque bool `json:"-"`
	// Raw is the complete stored JSON of the withdrawn binding, preserved so
	// stored history round-trips unchanged.
	Raw json.RawMessage `json:"-"`
}

// UnmarshalJSON decodes the historical payload twice: once into the diagnostic
// fields this type exposes, and once into Raw so the original bytes survive a
// load/save cycle. A payload this build cannot interpret is still history: the
// bytes are preserved verbatim and the record is marked Opaque, which refuses
// every operator assertion rather than failing the whole case load or letting an
// unreadable dependency be relabelled as an independent input.
func (w *WithdrawnFixBinding) UnmarshalJSON(b []byte) error {
	type payload WithdrawnFixBinding
	var p payload
	if err := json.Unmarshal(b, &p); err != nil {
		*w = WithdrawnFixBinding{
			Raw:    append(json.RawMessage(nil), b...),
			Opaque: true,
			Detail: "the stored binding payload could not be decoded by this build",
		}
		return nil
	}
	*w = WithdrawnFixBinding(p)
	w.Raw = append(json.RawMessage(nil), b...)
	return nil
}

// MarshalJSON writes the preserved historical payload.
func (w WithdrawnFixBinding) MarshalJSON() ([]byte, error) {
	if len(w.Raw) == 0 {
		return []byte("null"), nil
	}
	return w.Raw, nil
}

// ClaimsSubject reports whether the withdrawn binding admitted s. The answer
// blocks a relabel; it never authorises anything.
func (w *WithdrawnFixBinding) ClaimsSubject(s SymbolRef) bool {
	if w == nil {
		return false
	}
	for _, sub := range w.Subjects {
		if sub == s {
			return true
		}
	}
	return false
}

// Refusal states why s may not ground absence through this withdrawn binding.
func (w *WithdrawnFixBinding) Refusal(s SymbolRef) string {
	subject := s.Package
	if s.Symbol != "" {
		subject += "." + s.Symbol
	}
	record := w.RecordID
	if record == "" {
		record = "an unidentified record"
	}
	return fmt.Sprintf(
		"subject %s is named by the withdrawn content-derived fix binding of %s: that binding is historical evidence only, so it establishes no identity, absence or completeness, and a duplicate or relabelled candidate cannot resurrect an absence claim grounded on it",
		subject, record)
}

// OpaqueRefusal states why no operator assertion can ground absence while the
// withdrawn payload is unreadable.
func (w *WithdrawnFixBinding) OpaqueRefusal() string {
	return "the model carries a withdrawn content-derived fix binding this build cannot read: its admitted subject set is unknown, so an operator label cannot be distinguished from a relabel of that dependency and the assertion establishes nothing"
}

// Notice renders the withdrawal for a case-level diagnostic.
func (w *WithdrawnFixBinding) Notice() string {
	record := w.RecordID
	if record == "" {
		record = "an unidentified record"
	}
	return fmt.Sprintf(
		"stored content-derived fix binding of %s (status %q) is withdrawn, non-admitting historical evidence: it establishes no identity, absence or completeness, and absence claims that rested on it are refused",
		record, w.Status)
}

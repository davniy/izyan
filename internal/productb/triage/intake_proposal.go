package triage

// IntakeProposalSchemaVersion identifies the domain schema produced by the
// LLM intake extractor: a proposal of extracted candidates, never a decision.
const IntakeProposalSchemaVersion = "intake-proposal.v1"

// IntakeProposal is the schema-guided extraction result for one RawIntake
// record. The LLM may only propose candidates found in the document; every
// field is later confirmed or rejected by ValidateIntakeProposal. The schema
// deliberately has no tracker fields: ticket key, status, assignee,
// workflow transitions and comment bodies cannot be represented here, and
// there is no recommendation/priority — proposals never carry decisions.
type IntakeProposal struct {
	SchemaVersion    string   `json:"schema_version"`
	VulnerabilityIDs []string `json:"vulnerability_ids,omitempty"`
	Aliases          []string `json:"aliases,omitempty"`
	Package          string   `json:"package,omitempty"`
	Version          string   `json:"version,omitempty"`
	Component        string   `json:"component,omitempty"`
	ComponentVersion string   `json:"component_version,omitempty"`
	Product          string   `json:"product,omitempty"`
	ProductVersion   string   `json:"product_version,omitempty"`
	Release          string   `json:"release,omitempty"`
	GoVersion        string   `json:"go_version,omitempty"`
	Severity         string   `json:"severity,omitempty"`
	Summary          string   `json:"summary,omitempty"`
	SourceHints      []string `json:"source_hints,omitempty"`
	RefHint          string   `json:"ref_hint,omitempty"`
}

// IntakeFieldStatus is the deterministic anti-hallucination verdict for one
// extracted field (spec §4.2).
type IntakeFieldStatus string

const (
	// IntakeValid: format checks pass and the value is confirmed by the raw
	// document, a supplied advisory, or a unique catalog match.
	IntakeValid IntakeFieldStatus = "VALID"
	// IntakeUnverified: well-formed LLM candidate without deterministic
	// confirmation — usable as a hint, never as support for DISMISSED/LOWERED.
	IntakeUnverified IntakeFieldStatus = "UNVERIFIED"
	// IntakeConflicting: two or more confirmations disagree (duplicate or
	// ambiguous IDs, package@version mismatch, ambiguous catalog match,
	// severity contradicting the authoritative claim).
	IntakeConflicting IntakeFieldStatus = "CONFLICTING"
	// IntakeInvalid: malformed value (bad ID format, bad syntax).
	IntakeInvalid IntakeFieldStatus = "INVALID"
	// IntakeUnavailable: the field is absent. A neutral limitation, never a
	// negative fact.
	IntakeUnavailable IntakeFieldStatus = "UNAVAILABLE"
)

// FieldValidation is the per-field verdict of ValidateIntakeProposal.
// Provenance names the deterministic sources that confirmed the value
// (raw_text, advisory, catalog) — an empty list means LLM-only. A field
// that is not VALID can never support risk reduction; BlocksRiskReduction
// flags the decision-relevant fields where a non-VALID status forbids
// DISMISSED/LOWERED downstream.
type FieldValidation struct {
	Field               string            `json:"field"`
	Status              IntakeFieldStatus `json:"status"`
	Value               string            `json:"value,omitempty"`
	Reason              string            `json:"reason,omitempty"`
	Provenance          []string          `json:"provenance,omitempty"`
	Aliases             []string          `json:"aliases,omitempty"`
	BlocksRiskReduction bool              `json:"blocks_risk_reduction"`
}

// IntakeValidation is the deterministic validation result for one proposal:
// one FieldValidation per extracted (or absent-but-tracked) field, plus
// aggregated limitations and technical errors. It is deterministic: same
// raw record, proposal, advisory IDs and catalog always give the same result.
type IntakeValidation struct {
	Fields      []FieldValidation `json:"fields"`
	Limitations []string          `json:"limitations,omitempty"`
	Errors      []string          `json:"errors,omitempty"`
}

// Field returns the first validation entry for a named field.
func (v IntakeValidation) Field(name string) (FieldValidation, bool) {
	for _, f := range v.Fields {
		if f.Field == name {
			return f, true
		}
	}
	return FieldValidation{}, false
}

// FieldsNamed returns every validation entry for a named field — list
// fields such as source_hints produce one entry per element.
func (v IntakeValidation) FieldsNamed(name string) []FieldValidation {
	var out []FieldValidation
	for _, f := range v.Fields {
		if f.Field == name {
			out = append(out, f)
		}
	}
	return out
}

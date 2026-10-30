package domain

import (
	"errors"
	"fmt"
	"strings"
)

// ErrDeadnessPremiseUnavailable reports that a deadness observation cannot be
// converted into an exploitability negative: no admitted defect semantics say
// that the dead symbol's execution is required by the vulnerability.
var ErrDeadnessPremiseUnavailable = errors.New("deadness negative has no admitted invocation-necessity premise")

// DeadnessPremise is the admitted semantic premise of a negative that rests
// on a symbol's non-execution. It is derived from an admitted
// DefectSemanticsContract only: there is no constructor from a boolean, a
// method name, an evidence-id prefix or a sibling-liveness observation.
//
// A zero DeadnessPremise (including one decoded from an artifact) is never
// admitted; admitted reports the derivation link.
type DeadnessPremise struct {
	Mode         DefectSemanticsMode `json:"mode"`
	Locus        SymbolRef           `json:"locus"`
	RecordID     string              `json:"record_id"`
	RecordDigest string              `json:"record_digest,omitempty"`
	// Basis names the derived relation in one line for explanations. It is
	// descriptive; admission is carried by contract.
	Basis string `json:"basis"`

	// contract is the admitted contract this premise was derived from. It is
	// unexported so a caller cannot mint a premise by filling exported fields;
	// a JSON round-trip of the premise does not restore it.
	contract *DefectSemanticsContract
}

// Admitted reports whether the premise was derived from a contract.
func (p DeadnessPremise) Admitted() bool { return p.contract != nil }

// Covers reports whether the dead symbol set includes the premise locus. A
// premise that was not derived from a contract covers nothing.
func (p DeadnessPremise) Covers(dead []SymbolRef) bool {
	return p.Admitted() && SymbolSetContains(dead, p.Locus)
}

// SymbolSetContains reports whether want appears in set as an exact
// package/symbol identity.
func SymbolSetContains(set []SymbolRef, want SymbolRef) bool {
	for _, s := range set {
		if s == want {
			return true
		}
	}
	return false
}

// DeadnessPremise derives the negative basis of an admitted contract:
//
//   - DEFECTIVE_CHECK: the contracted check, whose invocation the advisory's
//     mechanism requires; its non-execution falsifies the vulnerable
//     operation.
//   - OMITTED_CHECK: the contracted omission-site pipeline. The absent
//     check's own deadness is consistent with omission and is never the
//     premise; the omission site's non-execution is.
//   - UNRESOLVED: no deadness negative is admissible.
//
// The derivation checks the contract shape; ValidateDefectSemanticsModel is
// the evidence-level admission and must run first wherever evidence exists.
func (c *DefectSemanticsContract) DeadnessPremise() (DeadnessPremise, error) {
	if c == nil {
		return DeadnessPremise{}, fmt.Errorf("%w: no defect-semantics contract", ErrDeadnessPremiseUnavailable)
	}
	if strings.TrimSpace(c.RecordID) == "" {
		return DeadnessPremise{}, fmt.Errorf("%w: contract carries no record id", ErrDeadnessPremiseUnavailable)
	}
	switch c.Mode {
	case DefectSemanticsDefectiveCheck:
		if strings.TrimSpace(c.Check.Package) == "" || strings.TrimSpace(c.Check.Symbol) == "" {
			return DeadnessPremise{}, fmt.Errorf("%w: DEFECTIVE_CHECK contract carries no check identity", ErrDeadnessPremiseUnavailable)
		}
		return DeadnessPremise{
			Mode:         c.Mode,
			Locus:        c.Check,
			RecordID:     c.RecordID,
			RecordDigest: c.RecordDigest,
			Basis: "the advisory requires the contracted check to be invoked; " +
				"its non-execution falsifies the vulnerable operation",
			contract: c,
		}, nil
	case DefectSemanticsOmittedCheck:
		if c.Pipeline == nil || strings.TrimSpace(c.Pipeline.Package) == "" || strings.TrimSpace(c.Pipeline.Symbol) == "" {
			return DeadnessPremise{}, fmt.Errorf("%w: OMITTED_CHECK contract carries no omission-site pipeline", ErrDeadnessPremiseUnavailable)
		}
		return DeadnessPremise{
			Mode:         c.Mode,
			Locus:        *c.Pipeline,
			RecordID:     c.RecordID,
			RecordDigest: c.RecordDigest,
			Basis: "the omission site on the anchored pipeline is the defect locus; " +
				"the absent check's own deadness is consistent with omission and is not the premise",
			contract: c,
		}, nil
	case DefectSemanticsUnresolved:
		return DeadnessPremise{}, fmt.Errorf("%w: defect semantics are unresolved (%s): %s",
			ErrDeadnessPremiseUnavailable, c.UnresolvedReason, c.UnresolvedDetail)
	default:
		return DeadnessPremise{}, fmt.Errorf("%w: unknown defect semantics mode %q", ErrDeadnessPremiseUnavailable, c.Mode)
	}
}

// RequireDeadnessPremise is the contract-only admission used by consumers
// that hold no ExploitModel (research lanes, Product B proofs): the contract
// must derive a premise and the dead symbol set must cover its locus. There
// is deliberately no ordinary fallback here — a consumer without a contract
// cannot establish that a symbol's deadness falsifies the vulnerability.
func RequireDeadnessPremise(contract *DefectSemanticsContract, dead []SymbolRef) (DeadnessPremise, error) {
	premise, err := contract.DeadnessPremise()
	if err != nil {
		return DeadnessPremise{}, err
	}
	if !premise.Covers(dead) {
		return DeadnessPremise{}, fmt.Errorf(
			"%w: the proof covers %d symbol(s) but not the admitted %s locus %s.%s",
			ErrDeadnessPremiseUnavailable, len(dead), premise.Mode,
			premise.Locus.Package, premise.Locus.Symbol)
	}
	return premise, nil
}

// ValidateDeadnessPremise is the model-level admission used by the main
// evaluator and the verdict path: the persisted defect semantics must pass
// ValidateDefectSemanticsModel, and the dead set must cover the resulting
// locus. A model with no contract keeps the ordinary advisory-symbol route
// only when it carries no omission/trigger/check-input conditions; a legacy
// un-admitted check model is refused by ValidateDefectSemanticsModel.
func ValidateDeadnessPremise(model *ExploitModel, dead []SymbolRef, evidence []Evidence) (DeadnessPremise, error) {
	if model == nil {
		return DeadnessPremise{}, fmt.Errorf("%w: no exploit model", ErrDeadnessPremiseUnavailable)
	}
	if err := ValidateDefectSemanticsModel(*model, evidence); err != nil {
		return DeadnessPremise{}, fmt.Errorf("%w: %w", ErrDeadnessPremiseUnavailable, err)
	}
	if model.DefectSemantics == nil {
		// No check-like defect was modelled: the advisory-declared symbols
		// are the vulnerable operation itself, so their non-execution is a
		// genuine falsifier. The caller supplies the dead set it measured.
		return DeadnessPremise{
			Basis: "the advisory-declared vulnerable operation is the defect locus",
		}, nil
	}
	// ValidateDefectSemanticsModel already refused UNRESOLVED.
	return RequireDeadnessPremise(model.DefectSemantics, dead)
}

// ModelCarriesSemanticClaims reports whether a model depends on defect
// semantics: it carries the typed contract or any condition the semantics
// introduce. Consumers use it to decide whether an absent contract is an
// ordinary model or an un-admitted legacy check model.
func ModelCarriesSemanticClaims(model *ExploitModel) bool {
	if model == nil {
		return false
	}
	if model.DefectSemantics != nil {
		return true
	}
	for _, cond := range model.MandatoryConditions {
		if IsOmissionCondition(cond) || IsCheckTriggerCondition(cond) || IsCheckInputCondition(cond) {
			return true
		}
	}
	return false
}

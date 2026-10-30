package domain

import "fmt"

// MissingCallStatus is the typed result of one check/pipeline omission
// measurement. Only OMITTED is an omission observation and only PRESENT is a
// call observation: an unreached pipeline, an unresolved declaration or a
// truncated callee search (NOT_ESTABLISHED) is a measurement limitation, never
// evidence that the check is present or absent.
type MissingCallStatus string

const (
	MissingCallOmitted        MissingCallStatus = "OMITTED"
	MissingCallPresent        MissingCallStatus = "PRESENT"
	MissingCallNotEstablished MissingCallStatus = "NOT_ESTABLISHED"
)

// MissingCallWitness is the typed source observation of one check/pipeline
// omission measurement: the pipeline's product reach, the check's invocation
// count on that active path and the observation's own status. It is a source
// observation, never defect semantics — only an admitted OMITTED_CHECK
// contract may read it as the defect.
type MissingCallWitness struct {
	// RecordID pins the advisory record the contract was admitted for.
	RecordID       string            `json:"record_id,omitempty"`
	Check          SymbolRef         `json:"check"`
	Pipeline       SymbolRef         `json:"pipeline"`
	Status         MissingCallStatus `json:"status"`
	ProductCallers []CallSite        `json:"product_callers,omitempty"`
	Detail         string            `json:"detail,omitempty"`
}

// MissingCallMatch is one admitted witness and the record that carries it.
type MissingCallMatch struct {
	EvidenceID EvidenceID
	Witness    MissingCallWitness
}

// OmissionConditionMatchesContract reports whether cond is the contracted
// omission shape: the exact check subject and the contracted pipeline. It
// replaces evidence-id-prefix and content-substring matching with a typed
// condition/contract binding.
func OmissionConditionMatchesContract(contract *DefectSemanticsContract, cond Condition) bool {
	if contract == nil || contract.Mode != DefectSemanticsOmittedCheck || !IsOmissionCondition(cond) {
		return false
	}
	return validateOmissionCondition(cond, contract) == nil
}

// PipelineReachConditionMatchesContract reports whether cond is the
// contracted omission-site reach condition: the exact pipeline subject plus
// the same pipeline symbol the contract binds.
func PipelineReachConditionMatchesContract(contract *DefectSemanticsContract, cond Condition) bool {
	if contract == nil || contract.Mode != DefectSemanticsOmittedCheck || contract.Pipeline == nil {
		return false
	}
	if cond.Kind != ConditionSymbolReachable || !cond.Mandatory || cond.Params[ParamCheck] == CheckLocus {
		return false
	}
	if cond.Params["pipeline"] != contract.Pipeline.Symbol {
		return false
	}
	return conditionHasSubject(cond, *contract.Pipeline)
}

// LocusConditionCoversContract reports whether cond is the model's defect-locus
// condition. Under a contract the locus subjects are the advisory-declared
// symbols; the contract, not the subject list, decides which of them is the
// execution locus, so no subject requirement is imposed here.
func LocusConditionCoversContract(contract *DefectSemanticsContract, cond Condition) bool {
	if contract == nil {
		return false
	}
	return cond.Kind == ConditionSymbolReachable && cond.Mandatory && cond.Params[ParamCheck] == CheckLocus
}

// MatchOmissionWitness binds a typed missing-call record to the admitted
// omission contract, one of the contract's omission conditions and the
// effective product build. It returns the record to cite or the typed refusal
// reasons. A record whose build context does not describe the analyzed build,
// whose check/pipeline/record identity differs from the contract, or whose
// status is not the requested one never matches.
func MatchOmissionWitness(contract *DefectSemanticsContract, cond Condition, evidence []Evidence,
	product ProductSnapshot, want MissingCallStatus) (*MissingCallMatch, []string) {
	if contract == nil {
		return nil, []string{"no admitted defect-semantics contract"}
	}
	if contract.Mode != DefectSemanticsOmittedCheck || contract.Pipeline == nil {
		return nil, []string{fmt.Sprintf("contract mode %s does not bind an omission site", contract.Mode)}
	}
	if !OmissionConditionMatchesContract(contract, cond) &&
		!PipelineReachConditionMatchesContract(contract, cond) &&
		!LocusConditionCoversContract(contract, cond) {
		return nil, []string{fmt.Sprintf("condition %s is not bound to the contracted check/pipeline", cond.ID)}
	}
	effective := EffectiveBuildContext(product)
	var reasons []string
	for i := range evidence {
		e := &evidence[i]
		if e.MissingCall == nil {
			continue
		}
		w := *e.MissingCall
		if w.Status != want {
			reasons = append(reasons, fmt.Sprintf("witness %s status is %q, want %q", e.ID, w.Status, want))
			continue
		}
		if w.RecordID != contract.RecordID {
			reasons = append(reasons, fmt.Sprintf("witness %s names record %q, want %q", e.ID, w.RecordID, contract.RecordID))
			continue
		}
		if w.Check != contract.Check {
			reasons = append(reasons, fmt.Sprintf("witness %s check %s.%s does not match %s.%s",
				e.ID, w.Check.Package, w.Check.Symbol, contract.Check.Package, contract.Check.Symbol))
			continue
		}
		if w.Pipeline != *contract.Pipeline {
			reasons = append(reasons, fmt.Sprintf("witness %s pipeline %s.%s does not match %s.%s",
				e.ID, w.Pipeline.Package, w.Pipeline.Symbol, contract.Pipeline.Package, contract.Pipeline.Symbol))
			continue
		}
		if e.Quality != QualityDeterministic && e.Quality != QualityAuthoritative {
			reasons = append(reasons, fmt.Sprintf("witness %s is %s, not deterministic", e.ID, e.Quality))
			continue
		}
		if e.BuildContext == nil {
			reasons = append(reasons, fmt.Sprintf("witness %s carries no build context", e.ID))
			continue
		}
		if err := e.BuildContext.Matches(effective); err != nil {
			reasons = append(reasons, fmt.Sprintf("witness %s %s", e.ID, err))
			continue
		}
		return &MissingCallMatch{EvidenceID: e.ID, Witness: w}, nil
	}
	if len(reasons) == 0 {
		reasons = append(reasons, fmt.Sprintf("no typed %s missing-call observation for the contracted check/pipeline", want))
	}
	return nil, reasons
}

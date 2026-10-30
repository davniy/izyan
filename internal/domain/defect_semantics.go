package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Typed semantic-admission failures. Consumers route on these with
// errors.Is: an unresolved contract is analyzer work with a named reason, a
// stale ground means the persisted evidence no longer matches, and an
// inconsistent model was constructed from a different mechanism.
var (
	ErrDefectSemanticsUnresolved   = errors.New("defect semantics unresolved")
	ErrDefectSemanticsInconsistent = errors.New("defect semantics contradict the constructed model")
	ErrDefectSemanticsStale        = errors.New("defect semantics evidence is stale")
)

func semanticsErr(base error, format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{base}, args...)...)
}

// DefectSemanticsMode is the advisory-grounded answer to "what is the
// defect?" for a check-like affected symbol. It is not inferred from the
// method name, its prefix, a live sibling validation pipeline or an empty
// reference set: those observations identify candidates for investigation,
// never semantics.
type DefectSemanticsMode string

const (
	// DefectSemanticsUnresolved means the admitted advisory/fix evidence does
	// not distinguish a defective invocation from an omitted invocation (or
	// is missing, contradictory or stale). An unresolved contract never falls
	// back to the historical omission heuristic and can never ground a
	// verdict.
	DefectSemanticsUnresolved DefectSemanticsMode = "UNRESOLVED"
	// DefectSemanticsDefectiveCheck means the check executes, but its own
	// logic is wrong under advisory-declared invocation preconditions.
	DefectSemanticsDefectiveCheck DefectSemanticsMode = "DEFECTIVE_CHECK"
	// DefectSemanticsOmittedCheck means the missing invocation itself is the
	// vulnerability, established by positive advisory/fix evidence.
	DefectSemanticsOmittedCheck DefectSemanticsMode = "OMITTED_CHECK"
)

// Valid reports whether the mode is one of the frozen contract modes.
func (m DefectSemanticsMode) Valid() bool {
	switch m {
	case DefectSemanticsUnresolved, DefectSemanticsDefectiveCheck, DefectSemanticsOmittedCheck:
		return true
	}
	return false
}

// DefectSemanticsUnresolvedReason is a typed cause for an UNRESOLVED
// contract. It is a closed enum: consumers route on it, never on prose.
type DefectSemanticsUnresolvedReason string

const (
	// SemanticsEvidenceMissing: no admitted mechanism statement or verified
	// fix relation establishes either mode.
	SemanticsEvidenceMissing DefectSemanticsUnresolvedReason = "SEMANTIC_EVIDENCE_MISSING"
	// SemanticsEvidenceContradictory: admitted evidence documents both an
	// omission and a defective invocation, or the fix relation contradicts
	// the advisory mechanism. Both obligations are preserved as unresolved.
	SemanticsEvidenceContradictory DefectSemanticsUnresolvedReason = "SEMANTIC_EVIDENCE_CONTRADICTORY"
	// SemanticsEvidenceStale: a persisted contract cites evidence whose
	// identity or content digest no longer matches the case.
	SemanticsEvidenceStale DefectSemanticsUnresolvedReason = "SEMANTIC_EVIDENCE_STALE"
	// SemanticsTriggerUnbound: the advisory describes a defective invocation
	// but the trigger spec (argument index/value or receiver payload field)
	// cannot be bound to source identities.
	SemanticsTriggerUnbound DefectSemanticsUnresolvedReason = "SEMANTIC_TRIGGER_UNBOUND"
	// SemanticsOmissionSiteUnbound: omission is established but the pipeline
	// that should have invoked the check cannot be identified.
	SemanticsOmissionSiteUnbound DefectSemanticsUnresolvedReason = "SEMANTIC_OMISSION_SITE_UNBOUND"
)

// DefectSemanticsGroundClaim is the typed proposition a ground establishes.
// It is deliberately narrower than free text: only the advisory mechanism
// statement and the before/after fix relation are admitted, and each ground
// must name which of the two contradicting mechanisms it supports.
type DefectSemanticsGroundClaim string

const (
	// SemanticsGroundAdvisoryInvocation: the advisory states the check is
	// invoked with the defective arguments/state.
	SemanticsGroundAdvisoryInvocation DefectSemanticsGroundClaim = "ADVISORY_INVOCATION"
	// SemanticsGroundAdvisoryOmission: the advisory states the check is not
	// invoked / its absence is the vulnerability.
	SemanticsGroundAdvisoryOmission DefectSemanticsGroundClaim = "ADVISORY_OMISSION"
	// SemanticsGroundFixChangesCheck: the fix changes the check's own body or
	// a helper it calls, without adding the previously missing invocation.
	SemanticsGroundFixChangesCheck DefectSemanticsGroundClaim = "FIX_CHANGES_CHECK"
	// SemanticsGroundFixAddsInvocation: the fix adds the previously missing
	// invocation from a pipeline/caller on the same receiver.
	SemanticsGroundFixAddsInvocation DefectSemanticsGroundClaim = "FIX_ADDS_INVOCATION"
)

// DefectSemanticsGround binds one typed ground to exact persisted evidence.
// EvidenceID is matched exactly (never by prefix) and EvidenceDigest pins
// the content bytes the claim was admitted against; Quote must be a verbatim
// substring of that content.
type DefectSemanticsGround struct {
	Claim          DefectSemanticsGroundClaim `json:"claim"`
	EvidenceID     EvidenceID                 `json:"evidence_id"`
	EvidenceKind   EvidenceKind               `json:"evidence_kind"`
	EvidenceDigest string                     `json:"evidence_digest"`
	Quote          string                     `json:"quote"`
	Symbol         *SymbolRef                 `json:"symbol,omitempty"`
}

// CheckArgumentPredicate binds one argument of the affected check
// invocation. Index is zero-based over the declared parameters (receiver
// excluded); Value is the required literal in normalized string form.
type CheckArgumentPredicate struct {
	Name  string `json:"name,omitempty"`
	Index int    `json:"index"`
	Value string `json:"value"`
}

// CheckPayloadPredicate binds the payload carried by the invocation's
// receiver. Shapes are the admitted runtime representations (for example
// "array"); ExcludedShapes are representations the advisory names as safe
// (for example "string"), so a witness carrying one of them cannot satisfy
// the predicate.
type CheckPayloadPredicate struct {
	ReceiverField  string   `json:"receiver_field"`
	Shapes         []string `json:"shapes"`
	ExcludedShapes []string `json:"excluded_shapes,omitempty"`
}

// CheckTriggerSpec is the typed, advisory-grounded invocation contract for a
// DEFECTIVE_CHECK defect: the operation, the argument predicate, the
// receiver-field payload predicate and the advisory's security effect.
type CheckTriggerSpec struct {
	Operation SymbolRef              `json:"operation"`
	Argument  CheckArgumentPredicate `json:"argument"`
	Payload   CheckPayloadPredicate  `json:"payload"`
	Effect    string                 `json:"effect,omitempty"`
}

// DefectSemanticsContract is the single admitted contract for a check-like
// advisory. It is persisted on the exploit model and consumed by the builder,
// the trigger evaluator and the verdict admission gate. Check is the
// affected check identity; Pipeline is the omission site for OMITTED_CHECK
// only; Trigger is the invocation contract for DEFECTIVE_CHECK only;
// Grounds are the digest-bound advisory/fix evidence the mode rests on.
type DefectSemanticsContract struct {
	Mode         DefectSemanticsMode `json:"mode"`
	RecordID     string              `json:"record_id"`
	RecordDigest string              `json:"record_digest,omitempty"`
	Check        SymbolRef           `json:"check"`
	Pipeline     *SymbolRef          `json:"pipeline,omitempty"`
	Trigger      *CheckTriggerSpec   `json:"trigger,omitempty"`
	// TriggerConditionID names the dedicated mandatory condition the typed
	// witness is bound to. The receiver-input projection is evaluated from
	// the same witness, so predicates can never be assembled across calls.
	TriggerConditionID ConditionID                     `json:"trigger_condition_id,omitempty"`
	Grounds            []DefectSemanticsGround         `json:"grounds,omitempty"`
	UnresolvedReason   DefectSemanticsUnresolvedReason `json:"unresolved_reason,omitempty"`
	UnresolvedDetail   string                          `json:"unresolved_detail,omitempty"`
}

// CheckTriggerObligation selects which predicates a typed witness must
// establish. The full trigger adds the argument predicate; both obligations
// always require the receiver payload and the same-invocation control
// binding.
type CheckTriggerObligation string

const (
	CheckTriggerObligationFull  CheckTriggerObligation = "TRIGGER"
	CheckTriggerObligationInput CheckTriggerObligation = "INPUT"
)

// CheckTriggerWitness is the typed witness a check-trigger or check-input
// condition is evaluated from. Every predicate lives on this one record:
// the invocation identity, the receiver identity, the argument literal, the
// receiver-field payload representation and the external control binding.
// Splitting these facts across witnesses (req=false at one call, an array
// payload at another, external origin on a third) can never satisfy a
// condition because no cross-witness assembly exists.
type CheckTriggerWitness struct {
	ConditionID   ConditionID `json:"condition_id"`
	Operation     SymbolRef   `json:"operation"`
	Invocation    CallSite    `json:"invocation"`
	Receiver      string      `json:"receiver"`
	ReceiverType  string      `json:"receiver_type"`
	ArgumentName  string      `json:"argument_name,omitempty"`
	ArgumentIndex int         `json:"argument_index"`
	ArgumentValue string      `json:"argument_value"`
	ReceiverField string      `json:"receiver_field"`
	PayloadShapes []string    `json:"payload_shapes,omitempty"`
	// ControlOrigin is the admitted ordinary input route's origin. Only an
	// external origin can make the payload attacker-selectable.
	ControlOrigin      DataOrigin   `json:"control_origin"`
	ControlEvidenceIDs []EvidenceID `json:"control_evidence_ids,omitempty"`
	Effect             string       `json:"effect,omitempty"`
}

// CheckTriggerMatch is one admissible witness and the evidence record that
// carries it.
type CheckTriggerMatch struct {
	EvidenceID EvidenceID
	Witness    CheckTriggerWitness
}

// Defect semantics condition params. They are a typed projection of the
// contract onto the existing condition schema; the contract remains the
// source of truth and the verdict gate rejects any mismatch.
const (
	ParamOperation             = "operation"
	ParamArgumentName          = "argument_name"
	ParamArgumentValue         = "argument_value"
	ParamReceiverField         = "receiver_field"
	ParamPayloadShapes         = "payload_shapes"
	ParamPayloadExcludedShapes = "payload_excluded_shapes"
)

const (
	// CheckInvocation marks a SYMBOL_REACHABLE condition whose subject is the
	// affected check operation itself (a live call must resolve to it).
	CheckInvocation = "invocation"
	// CheckReceiverInput marks an ATTACKER_CONTROL condition whose subject
	// payload is the invocation receiver's named field, not an arbitrary
	// call argument.
	CheckReceiverInput = "receiver_input"
	// CheckTrigger marks the dedicated mandatory check-trigger condition.
	CheckTrigger = "check_trigger"
	// CheckTriggerConditionID is the condition ID the typed witness binds to.
	CheckTriggerConditionID ConditionID = "C-CHECK-TRIGGER"
)

// SemanticsUnresolvedGapMessage is the frozen diagnostic for a resolved
// symbol whose defect semantics could not be established or contradict the
// constructed model. The owner is CODE: this is analyzer work, never an
// environmental dependency.
const SemanticsUnresolvedGapMessage = "affected symbol resolved, but advisory-grounded defect semantics could not be established / contradict the constructed model"

// EvidenceContentDigest returns the sha256:<lowercase hex> digest used to
// pin an evidence record's exact content in a semantics ground.
func EvidenceContentDigest(content string) string {
	sum := sha256.Sum256([]byte(content))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// CheckTriggerParams renders the typed trigger spec into condition params.
// The builder and the verdict gate both call it, so a model can never drift
// from the contract by editing one representation only.
func CheckTriggerParams(spec CheckTriggerSpec) map[string]string {
	return map[string]string{
		ParamCheck:                 CheckTrigger,
		ParamOperation:             spec.Operation.Package + "." + spec.Operation.Symbol,
		ParamArgumentName:          spec.Argument.Name,
		ParamArgumentValue:         spec.Argument.Value,
		ParamReceiverField:         spec.Payload.ReceiverField,
		ParamPayloadShapes:         strings.Join(spec.Payload.Shapes, ","),
		ParamPayloadExcludedShapes: strings.Join(spec.Payload.ExcludedShapes, ","),
	}
}

// CheckInputParams renders the receiver-field input projection of the spec.
func CheckInputParams(spec CheckTriggerSpec) map[string]string {
	params := CheckTriggerParams(spec)
	params[ParamCheck] = CheckReceiverInput
	delete(params, ParamArgumentName)
	delete(params, ParamArgumentValue)
	return params
}

// IsOmissionCondition reports whether cond is the historical omission shape.
// The predicate is structural: consumers must still require the admitted
// OMITTED_CHECK contract before treating it as a modeled defect.
func IsOmissionCondition(cond Condition) bool {
	return cond.Kind == ConditionMissingCall || cond.Params[ParamCheck] == CheckMissingCall
}

// IsCheckTriggerCondition reports whether cond is the dedicated check-trigger
// obligation.
func IsCheckTriggerCondition(cond Condition) bool {
	return cond.Kind == ConditionCheckTrigger || cond.Params[ParamCheck] == CheckTrigger
}

// IsCheckInputCondition reports whether cond is the receiver-field input
// obligation of an incorrect-check contract.
func IsCheckInputCondition(cond Condition) bool {
	return cond.Kind == ConditionCheckInput || cond.Params[ParamCheck] == CheckReceiverInput
}

// MatchCheckTriggerWitness finds the first deterministic typed witness that
// satisfies every predicate of spec on one invocation and receiver. It
// returns the evidence carrying the witness so the claim can cite exactly
// the record it was admitted from, or typed refusal reasons when nothing
// matches.
func MatchCheckTriggerWitness(spec CheckTriggerSpec, witnessConditionID ConditionID, evidence []Evidence, obligation CheckTriggerObligation) (*CheckTriggerMatch, []string) {
	var reasons []string
	byID := make(map[EvidenceID]*Evidence, len(evidence))
	for i := range evidence {
		byID[evidence[i].ID] = &evidence[i]
	}
	for i := range evidence {
		e := &evidence[i]
		if e.CheckTrigger == nil {
			continue
		}
		w := *e.CheckTrigger
		if witnessConditionID != "" && w.ConditionID != witnessConditionID {
			continue
		}
		if e.Quality != QualityDeterministic && e.Quality != QualityAuthoritative {
			reasons = append(reasons, fmt.Sprintf("witness %s is %s, not deterministic", e.ID, e.Quality))
			continue
		}
		if w.Operation != spec.Operation {
			reasons = append(reasons, fmt.Sprintf("witness %s resolves operation %s.%s, want %s.%s",
				e.ID, w.Operation.Package, w.Operation.Symbol, spec.Operation.Package, spec.Operation.Symbol))
			continue
		}
		if w.Invocation.File == "" || w.Invocation.Function == "" || w.Receiver == "" || w.ReceiverType == "" {
			reasons = append(reasons, fmt.Sprintf("witness %s has no complete invocation/receiver identity", e.ID))
			continue
		}
		if wantType := symbolReceiverType(spec.Operation.Symbol); wantType != "" && w.ReceiverType != wantType {
			reasons = append(reasons, fmt.Sprintf("witness %s receiver type %q, want %q", e.ID, w.ReceiverType, wantType))
			continue
		}
		if w.ReceiverField != spec.Payload.ReceiverField {
			reasons = append(reasons, fmt.Sprintf("witness %s payload field %q, want %q", e.ID, w.ReceiverField, spec.Payload.ReceiverField))
			continue
		}
		if !shapesSatisfy(w.PayloadShapes, spec.Payload.Shapes, spec.Payload.ExcludedShapes) {
			reasons = append(reasons, fmt.Sprintf("witness %s payload shapes %v do not satisfy %v excluding %v",
				e.ID, w.PayloadShapes, spec.Payload.Shapes, spec.Payload.ExcludedShapes))
			continue
		}
		if obligation == CheckTriggerObligationFull {
			if spec.Argument.Name != "" && !strings.EqualFold(w.ArgumentName, spec.Argument.Name) {
				reasons = append(reasons, fmt.Sprintf("witness %s argument name %q, want %q",
					e.ID, w.ArgumentName, spec.Argument.Name))
				continue
			}
			if w.ArgumentIndex != spec.Argument.Index || normalizeLiteral(w.ArgumentValue) != normalizeLiteral(spec.Argument.Value) {
				reasons = append(reasons, fmt.Sprintf("witness %s argument %d=%q, want %d=%q",
					e.ID, w.ArgumentIndex, w.ArgumentValue, spec.Argument.Index, spec.Argument.Value))
				continue
			}
		}
		if w.ControlOrigin != OriginExternalUntrusted && w.ControlOrigin != OriginExternalAuthenticated {
			reasons = append(reasons, fmt.Sprintf("witness %s control origin %s is not external", e.ID, w.ControlOrigin))
			continue
		}
		if len(w.ControlEvidenceIDs) == 0 {
			reasons = append(reasons, fmt.Sprintf("witness %s carries no control evidence", e.ID))
			continue
		}
		missing, hasFlow := false, false
		for _, id := range w.ControlEvidenceIDs {
			ce, ok := byID[id]
			if !ok {
				reasons = append(reasons, fmt.Sprintf("witness %s cites missing control evidence %s", e.ID, id))
				missing = true
				continue
			}
			if ce.Quality != QualityDeterministic && ce.Quality != QualityAuthoritative {
				reasons = append(reasons, fmt.Sprintf("witness %s control evidence %s is %s, not deterministic", e.ID, id, ce.Quality))
				missing = true
				continue
			}
			if ce.Kind == EvidenceDataFlow {
				hasFlow = true
			}
		}
		if missing {
			continue
		}
		if !hasFlow {
			reasons = append(reasons, fmt.Sprintf("witness %s control evidence has no typed data-flow record", e.ID))
			continue
		}
		return &CheckTriggerMatch{EvidenceID: e.ID, Witness: w}, nil
	}
	if len(reasons) == 0 {
		reasons = append(reasons, fmt.Sprintf("no typed check-trigger witness for condition %s", witnessConditionID))
	}
	return nil, reasons
}

// ValidateDefectSemanticsModel is the semantic admission gate: it re-admits
// the persisted contract and rejects any exploit model not constructed from
// it. A nil error does not mean a verdict may be earned — the verdict
// evaluator still applies its normal conjunction rules; it means the model is
// semantically admissible. An UNRESOLVED contract returns an error on
// purpose, so no conjunction can earn a verdict on it.
func ValidateDefectSemanticsModel(model ExploitModel, evidence []Evidence) error {
	contract := model.DefectSemantics
	omissions := make([]Condition, 0, 1)
	triggers := make([]Condition, 0, 1)
	inputs := make([]Condition, 0, 1)
	for _, cond := range model.MandatoryConditions {
		switch {
		case IsOmissionCondition(cond):
			omissions = append(omissions, cond)
		case IsCheckTriggerCondition(cond):
			triggers = append(triggers, cond)
		case IsCheckInputCondition(cond):
			inputs = append(inputs, cond)
		}
	}
	if contract == nil {
		if len(omissions) > 0 {
			return semanticsErr(ErrDefectSemanticsInconsistent, "omission condition %s has no admitted defect-semantics contract", omissions[0].ID)
		}
		if len(triggers) > 0 {
			return semanticsErr(ErrDefectSemanticsInconsistent, "check-trigger condition %s has no admitted defect-semantics contract", triggers[0].ID)
		}
		if len(inputs) > 0 {
			return semanticsErr(ErrDefectSemanticsInconsistent, "check-input condition %s has no admitted defect-semantics contract", inputs[0].ID)
		}
		return nil
	}
	if err := validateContractShape(contract); err != nil {
		return fmt.Errorf("%w: %v", ErrDefectSemanticsInconsistent, err)
	}
	if err := validateSemanticsGrounds(contract, evidence); err != nil {
		return err
	}
	if contract.Mode == DefectSemanticsUnresolved {
		if contract.UnresolvedReason == "" {
			return semanticsErr(ErrDefectSemanticsUnresolved, "unresolved defect semantics carries no typed reason")
		}
		if len(omissions) > 0 {
			return semanticsErr(ErrDefectSemanticsUnresolved, "model carries omission condition %s", omissions[0].ID)
		}
		if len(triggers) > 0 {
			return semanticsErr(ErrDefectSemanticsUnresolved, "model carries trigger condition %s", triggers[0].ID)
		}
		if len(inputs) > 0 {
			return semanticsErr(ErrDefectSemanticsUnresolved, "model carries check-input condition %s", inputs[0].ID)
		}
		return semanticsErr(ErrDefectSemanticsUnresolved, "(%s): %s", contract.UnresolvedReason, contract.UnresolvedDetail)
	}
	if !modelHasRootCause(model, contract.Check) {
		return semanticsErr(ErrDefectSemanticsInconsistent, "contract check %s.%s is not a modeled root cause", contract.Check.Package, contract.Check.Symbol)
	}
	switch contract.Mode {
	case DefectSemanticsDefectiveCheck:
		if contract.Pipeline != nil {
			return semanticsErr(ErrDefectSemanticsInconsistent, "DEFECTIVE_CHECK contract must not carry an omission pipeline")
		}
		if contract.Trigger == nil {
			return semanticsErr(ErrDefectSemanticsInconsistent, "DEFECTIVE_CHECK contract carries no trigger spec")
		}
		if contract.Trigger.Operation != contract.Check {
			return semanticsErr(ErrDefectSemanticsInconsistent, "trigger operation %s.%s does not match contract check %s.%s",
				contract.Trigger.Operation.Package, contract.Trigger.Operation.Symbol,
				contract.Check.Package, contract.Check.Symbol)
		}
		if len(omissions) > 0 {
			return semanticsErr(ErrDefectSemanticsInconsistent, "DEFECTIVE_CHECK model carries omission condition %s", omissions[0].ID)
		}
		if !hasInvocationReach(model, contract.Check) {
			return semanticsErr(ErrDefectSemanticsInconsistent, "DEFECTIVE_CHECK model has no invocation-reach condition for %s.%s", contract.Check.Package, contract.Check.Symbol)
		}
		if len(triggers) != 1 {
			return semanticsErr(ErrDefectSemanticsInconsistent, "DEFECTIVE_CHECK model has %d check-trigger condition(s), want exactly one", len(triggers))
		}
		if triggers[0].Kind != ConditionCheckTrigger || !triggers[0].Mandatory {
			return semanticsErr(ErrDefectSemanticsInconsistent, "check-trigger condition %s is not a mandatory %s condition", triggers[0].ID, ConditionCheckTrigger)
		}
		if !conditionParamsMatch(triggers[0], CheckTriggerParams(*contract.Trigger)) {
			return semanticsErr(ErrDefectSemanticsInconsistent, "check-trigger condition %s does not match the admitted trigger spec", triggers[0].ID)
		}
		if triggers[0].ArgIndex != contract.Trigger.Argument.Index {
			return semanticsErr(ErrDefectSemanticsInconsistent, "check-trigger condition %s arg index %d does not match %d",
				triggers[0].ID, triggers[0].ArgIndex, contract.Trigger.Argument.Index)
		}
		if len(inputs) != 1 {
			return semanticsErr(ErrDefectSemanticsInconsistent, "DEFECTIVE_CHECK model has %d receiver-input condition(s), want exactly one", len(inputs))
		}
		if inputs[0].Kind != ConditionCheckInput || !inputs[0].Mandatory {
			return semanticsErr(ErrDefectSemanticsInconsistent, "receiver-input condition %s is not a mandatory %s condition", inputs[0].ID, ConditionCheckInput)
		}
		if !conditionParamsMatch(inputs[0], CheckInputParams(*contract.Trigger)) {
			return semanticsErr(ErrDefectSemanticsInconsistent, "receiver-input condition %s does not match the admitted trigger spec", inputs[0].ID)
		}
		if inputs[0].ArgIndex != ArgReceiver {
			return semanticsErr(ErrDefectSemanticsInconsistent, "receiver-input condition %s does not bind the receiver (arg_index %d)", inputs[0].ID, inputs[0].ArgIndex)
		}
		if !hasLocusCondition(model, contract.Check) {
			return semanticsErr(ErrDefectSemanticsInconsistent, "DEFECTIVE_CHECK model has no defect-locus condition covering %s.%s",
				contract.Check.Package, contract.Check.Symbol)
		}
	case DefectSemanticsOmittedCheck:
		if contract.Pipeline == nil {
			return semanticsErr(ErrDefectSemanticsInconsistent, "OMITTED_CHECK contract carries no omission pipeline")
		}
		if contract.Trigger != nil {
			return semanticsErr(ErrDefectSemanticsInconsistent, "OMITTED_CHECK contract must not carry a check-trigger spec")
		}
		if len(triggers) > 0 {
			return semanticsErr(ErrDefectSemanticsInconsistent, "OMITTED_CHECK model carries trigger condition %s", triggers[0].ID)
		}
		if len(inputs) > 0 {
			return semanticsErr(ErrDefectSemanticsInconsistent, "OMITTED_CHECK model carries check-input condition %s", inputs[0].ID)
		}
		if len(omissions) != 1 {
			return semanticsErr(ErrDefectSemanticsInconsistent, "OMITTED_CHECK model has %d omission condition(s), want exactly one", len(omissions))
		}
		if !omissions[0].Mandatory {
			return semanticsErr(ErrDefectSemanticsInconsistent, "omission condition %s is not mandatory", omissions[0].ID)
		}
		if err := validateOmissionCondition(omissions[0], contract); err != nil {
			return err
		}
		if !hasPipelineReach(model, *contract.Pipeline) {
			return semanticsErr(ErrDefectSemanticsInconsistent, "OMITTED_CHECK model has no reach condition for pipeline %s.%s",
				contract.Pipeline.Package, contract.Pipeline.Symbol)
		}
	default:
		return semanticsErr(ErrDefectSemanticsInconsistent, "unknown defect semantics mode %q", contract.Mode)
	}
	return nil
}

// CheckTriggerClaimAdmitted reports whether a persisted TRUE trigger/input
// claim is still grounded by a typed witness under the current evidence.
// The verdict evaluator demotes an unsupported positive instead of trusting
// the saved claim.
func CheckTriggerClaimAdmitted(contract *DefectSemanticsContract, cond Condition, evidence []Evidence) (bool, []string) {
	if contract == nil || contract.Trigger == nil || contract.Mode != DefectSemanticsDefectiveCheck {
		return false, []string{"no admitted DEFECTIVE_CHECK trigger contract"}
	}
	obligation := CheckTriggerObligationFull
	if IsCheckInputCondition(cond) {
		obligation = CheckTriggerObligationInput
	}
	match, reasons := MatchCheckTriggerWitness(*contract.Trigger, contract.TriggerConditionID, evidence, obligation)
	return match != nil, reasons
}

// CheckConditionMatchesContract reports whether a trigger/input condition is
// the typed projection of the admitted trigger spec. The verdict gate and the
// evaluator both use it so a drifted condition can never be evaluated under
// (or admitted from) the contract.
func CheckConditionMatchesContract(contract *DefectSemanticsContract, cond Condition) bool {
	if contract == nil || contract.Trigger == nil {
		return false
	}
	switch {
	case IsCheckTriggerCondition(cond):
		return cond.ID == contract.TriggerConditionID &&
			cond.ArgIndex == contract.Trigger.Argument.Index &&
			conditionParamsMatch(cond, CheckTriggerParams(*contract.Trigger))
	case IsCheckInputCondition(cond):
		return cond.ArgIndex == ArgReceiver &&
			conditionParamsMatch(cond, CheckInputParams(*contract.Trigger))
	}
	return false
}

func validateContractShape(contract *DefectSemanticsContract) error {
	if !contract.Mode.Valid() {
		return semanticsErr(ErrDefectSemanticsInconsistent, "invalid defect semantics mode %q", contract.Mode)
	}
	if strings.TrimSpace(contract.RecordID) == "" {
		return semanticsErr(ErrDefectSemanticsInconsistent, "contract carries no record id")
	}
	if contract.RecordDigest != "" {
		if err := validatePinnedDigest("defect semantics record digest", contract.RecordDigest); err != nil {
			return err
		}
	}
	if strings.TrimSpace(contract.Check.Package) == "" || strings.TrimSpace(contract.Check.Symbol) == "" {
		return semanticsErr(ErrDefectSemanticsInconsistent, "contract carries no check identity")
	}
	if contract.Mode == DefectSemanticsOmittedCheck {
		if contract.Pipeline == nil || strings.TrimSpace(contract.Pipeline.Symbol) == "" {
			return semanticsErr(ErrDefectSemanticsInconsistent, "OMITTED_CHECK contract carries no pipeline identity")
		}
	}
	if contract.Mode == DefectSemanticsDefectiveCheck {
		spec := contract.Trigger
		if spec == nil {
			return semanticsErr(ErrDefectSemanticsInconsistent, "DEFECTIVE_CHECK contract carries no trigger spec")
		}
		if spec.Operation != contract.Check {
			return semanticsErr(ErrDefectSemanticsInconsistent, "trigger operation does not match contract check")
		}
		if spec.Argument.Index < 0 || strings.TrimSpace(spec.Argument.Value) == "" {
			return semanticsErr(ErrDefectSemanticsInconsistent, "trigger argument predicate is not bound")
		}
		if strings.TrimSpace(string(contract.TriggerConditionID)) == "" {
			return semanticsErr(ErrDefectSemanticsInconsistent, "trigger condition id is not bound")
		}
		if strings.TrimSpace(spec.Payload.ReceiverField) == "" || len(spec.Payload.Shapes) == 0 {
			return semanticsErr(ErrDefectSemanticsInconsistent, "trigger payload predicate is not bound")
		}
	}
	if contract.Mode != DefectSemanticsUnresolved && len(contract.Grounds) == 0 {
		return semanticsErr(ErrDefectSemanticsInconsistent, "contract carries no grounds")
	}
	return nil
}

func validateSemanticsGrounds(contract *DefectSemanticsContract, evidence []Evidence) error {
	byID := make(map[EvidenceID]*Evidence, len(evidence))
	for i := range evidence {
		byID[evidence[i].ID] = &evidence[i]
	}
	var advisoryInvocation, advisoryOmission, fixChanges, fixAdds bool
	for _, g := range contract.Grounds {
		if g.EvidenceID == "" {
			return semanticsErr(ErrDefectSemanticsStale, "ground %s carries no evidence id", g.Claim)
		}
		if err := validatePinnedDigest("defect semantics ground digest", g.EvidenceDigest); err != nil {
			return err
		}
		e, ok := byID[g.EvidenceID]
		if !ok {
			return semanticsErr(ErrDefectSemanticsStale, "ground %s cites missing evidence %s",
				g.Claim, g.EvidenceID)
		}
		if e.Kind != g.EvidenceKind {
			return semanticsErr(ErrDefectSemanticsStale, "ground %s: evidence %s kind %s, want %s",
				g.Claim, g.EvidenceID, e.Kind, g.EvidenceKind)
		}
		if EvidenceContentDigest(e.Content) != g.EvidenceDigest {
			return semanticsErr(ErrDefectSemanticsStale, "ground %s: evidence %s content digest changed",
				g.Claim, g.EvidenceID)
		}
		if strings.TrimSpace(g.Quote) == "" || !strings.Contains(e.Content, g.Quote) {
			return semanticsErr(ErrDefectSemanticsStale, "ground %s: quote is not present in evidence %s",
				g.Claim, g.EvidenceID)
		}
		switch g.Claim {
		case SemanticsGroundAdvisoryInvocation:
			advisoryInvocation = true
		case SemanticsGroundAdvisoryOmission:
			advisoryOmission = true
		case SemanticsGroundFixChangesCheck:
			fixChanges = true
		case SemanticsGroundFixAddsInvocation:
			fixAdds = true
		default:
			return semanticsErr(ErrDefectSemanticsInconsistent, "ground carries unknown claim %q", g.Claim)
		}
	}
	switch contract.Mode {
	case DefectSemanticsDefectiveCheck:
		if !advisoryInvocation {
			return semanticsErr(ErrDefectSemanticsInconsistent, "DEFECTIVE_CHECK contract has no advisory invocation ground")
		}
		if advisoryOmission || fixAdds {
			return semanticsErr(ErrDefectSemanticsInconsistent, "DEFECTIVE_CHECK contract also carries omission evidence")
		}
	case DefectSemanticsOmittedCheck:
		if !advisoryOmission && !fixAdds {
			return semanticsErr(ErrDefectSemanticsInconsistent, "OMITTED_CHECK contract has neither an advisory omission nor a fix-added invocation ground")
		}
		if advisoryInvocation {
			return semanticsErr(ErrDefectSemanticsInconsistent, "OMITTED_CHECK contract also carries an advisory invocation ground")
		}
		if fixChanges && !fixAdds {
			return semanticsErr(ErrDefectSemanticsInconsistent, "OMITTED_CHECK contract's fix changes the check body without adding the invocation")
		}
	}
	return nil
}

func modelHasRootCause(model ExploitModel, ref SymbolRef) bool {
	for _, r := range model.RootCauses {
		if r == ref {
			return true
		}
	}
	return false
}

func hasInvocationReach(model ExploitModel, check SymbolRef) bool {
	for _, cond := range model.MandatoryConditions {
		if cond.Kind != ConditionSymbolReachable || !cond.Mandatory || cond.Params[ParamCheck] != CheckInvocation {
			continue
		}
		if conditionHasSubject(cond, check) {
			return true
		}
	}
	return false
}

func hasLocusCondition(model ExploitModel, check SymbolRef) bool {
	for _, cond := range model.MandatoryConditions {
		if !cond.Mandatory || cond.Kind != ConditionSymbolReachable || cond.Params[ParamCheck] != CheckLocus {
			continue
		}
		if conditionHasSubject(cond, check) {
			return true
		}
	}
	return false
}

func hasPipelineReach(model ExploitModel, pipeline SymbolRef) bool {
	for _, cond := range model.MandatoryConditions {
		if cond.Kind != ConditionSymbolReachable || !cond.Mandatory || !conditionHasSubject(cond, pipeline) {
			continue
		}
		if cond.Params[ParamCheck] == CheckLocus {
			continue
		}
		if cond.Params["pipeline"] == pipeline.Symbol {
			return true
		}
	}
	return false
}

func validateOmissionCondition(cond Condition, contract *DefectSemanticsContract) error {
	if len(cond.Subjects) == 0 || cond.Subjects[0] != contract.Check {
		return semanticsErr(ErrDefectSemanticsInconsistent, "omission condition %s does not name the contracted check %s.%s",
			cond.ID, contract.Check.Package, contract.Check.Symbol)
	}
	if contract.Pipeline == nil {
		return semanticsErr(ErrDefectSemanticsInconsistent, "omission condition %s has no contracted pipeline", cond.ID)
	}
	if cond.Params["pipeline"] != contract.Pipeline.Symbol {
		return semanticsErr(ErrDefectSemanticsInconsistent, "omission condition %s names pipeline %q, want %q",
			cond.ID, cond.Params["pipeline"], contract.Pipeline.Symbol)
	}
	return nil
}

func conditionHasSubject(cond Condition, ref SymbolRef) bool {
	if cond.Subject != nil && *cond.Subject == ref {
		return true
	}
	for _, s := range cond.Subjects {
		if s == ref {
			return true
		}
	}
	return false
}

func conditionParamsMatch(cond Condition, want map[string]string) bool {
	for k, v := range want {
		if cond.Params[k] != v {
			return false
		}
	}
	return true
}

func shapesSatisfy(have, want, excluded []string) bool {
	if len(want) == 0 {
		return false
	}
	seen := make(map[string]bool, len(have))
	for _, s := range have {
		seen[normalizeShape(s)] = true
	}
	for _, s := range excluded {
		if seen[normalizeShape(s)] {
			return false
		}
	}
	for _, s := range want {
		if !seen[normalizeShape(s)] {
			return false
		}
	}
	return true
}

func normalizeShape(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func normalizeLiteral(s string) string {
	return strings.ToLower(strings.Trim(strings.TrimSpace(s), "`'\""))
}

func symbolReceiverType(symbol string) string {
	s := symbol
	if strings.HasPrefix(s, "(*") {
		if end := strings.Index(s, ")"); end > 2 {
			return strings.TrimPrefix(s[2:end], "*")
		}
	}
	s = strings.TrimPrefix(s, "*")
	if i := strings.Index(s, "."); i >= 0 {
		return s[:i]
	}
	return ""
}

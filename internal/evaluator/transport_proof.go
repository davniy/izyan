package evaluator

// Transport witness admission. The evaluator never trusts a caller-supplied
// "proven" flag: a transport claim is re-admitted against the persisted
// witness, the case build and the claim's own condition. A refused witness is
// no new proof — callers keep the claim UNKNOWN and its producer records the
// typed reason.

import (
	"fmt"
	"strings"

	"github.com/fedorovmv/izyan/internal/domain"
)

// ValidateTransportInput re-admits a rooted server-transport input claim.
//
// It requires a TRUE claim carrying ControlBasisTransportPeerInput, membership
// in the model's mandatory conjunction, a complete rooted witness, the same
// build identity as the assessed product, and a witness module that covers the
// claim's own subject packages.
func ValidateTransportInput(
	product domain.ProductSnapshot,
	model domain.ExploitModel,
	claim domain.Claim,
	evidence []domain.Evidence,
) error {
	if claim.Result != domain.ClaimTrue {
		return fmt.Errorf("transport input admission requires a TRUE claim, got %s", claim.Result)
	}
	if claim.ControlBasis != domain.ControlBasisTransportPeerInput {
		return fmt.Errorf("claim %s carries control basis %q, not %q",
			claim.ConditionID, claim.ControlBasis, domain.ControlBasisTransportPeerInput)
	}
	if !mandatoryCondition(model, claim.ConditionID) {
		return fmt.Errorf("transport input claim %s is not part of the mandatory conjunction", claim.ConditionID)
	}
	input, _ := domain.TransportWitnessFromEvidence(evidence)
	if input == nil {
		return fmt.Errorf("no rooted transport input witness is recorded for claim %s", claim.ConditionID)
	}
	if err := input.Complete(); err != nil {
		return err
	}
	if err := transportBuildAdmitted(product, input.Build); err != nil {
		return err
	}
	if err := transportEvidenceResolves("transport input witness", input.EvidenceIDs, evidence); err != nil {
		return err
	}
	if module := transportClaimModuleVersion(model, input.Module); module != "" && !transportModuleCovers(model, claim.ConditionID, input.Module) {
		return fmt.Errorf("witness module %q does not cover claim %s's subject packages (root causes name %q)",
			input.Module, claim.ConditionID, module)
	}
	return nil
}

// ValidateTransportTrigger re-admits a source/fix-bound mechanism claim.
//
// It requires a TRUE claim on a mandatory condition, the mechanism witness for
// that condition's mechanism, a complete rooted input witness inside it, the
// fix evidence bound, every obligation satisfied and no product control that
// prevents the mechanism or whose position is unknown.
func ValidateTransportTrigger(
	product domain.ProductSnapshot,
	model domain.ExploitModel,
	claim domain.Claim,
	evidence []domain.Evidence,
) error {
	if claim.Result != domain.ClaimTrue {
		return fmt.Errorf("transport trigger admission requires a TRUE claim, got %s", claim.Result)
	}
	if !mandatoryCondition(model, claim.ConditionID) {
		return fmt.Errorf("transport trigger claim %s is not part of the mandatory conjunction", claim.ConditionID)
	}
	_, trigger := domain.TransportWitnessFromEvidence(evidence)
	if trigger == nil {
		return fmt.Errorf("no transport trigger witness is recorded for claim %s", claim.ConditionID)
	}
	if err := trigger.Complete(); err != nil {
		return err
	}
	if err := transportBuildAdmitted(product, trigger.Build); err != nil {
		return err
	}
	if err := transportEvidenceResolves("transport trigger witness", trigger.EvidenceIDs, evidence); err != nil {
		return err
	}
	if trigger.Input.Module == "" {
		return fmt.Errorf("transport trigger witness carries no module identity")
	}
	// A condition that declares the mechanism it speaks about must agree
	// with the witness: a witness for another mechanism is no proof of this
	// condition.
	for _, cond := range model.MandatoryConditions {
		if cond.ID != claim.ConditionID {
			continue
		}
		if want := cond.Params[domain.ParamMechanism]; want != "" && want != trigger.Mechanism {
			return fmt.Errorf("condition %s binds mechanism %q but the witness proves %q",
				cond.ID, want, trigger.Mechanism)
		}
	}
	return nil
}

// transportEvidenceResolves rejects a proof that cites an evidence record the
// case does not carry: a dangling reference is not a source binding.
func transportEvidenceResolves(name string, ids []domain.EvidenceID, evidence []domain.Evidence) error {
	known := make(map[domain.EvidenceID]bool, len(evidence))
	for _, ev := range evidence {
		known[ev.ID] = true
	}
	for _, id := range ids {
		if !known[id] {
			return fmt.Errorf("%s references evidence %q that is not recorded", name, id)
		}
	}
	return nil
}

// transportBuildAdmitted compares the witness build identity with the assessed
// product's. A witness measured under another build is not a proof about this
// product.
func transportBuildAdmitted(product domain.ProductSnapshot, witness domain.BuildContext) error {
	effective := domain.EffectiveBuildContext(product)
	if err := witness.Matches(effective); err != nil {
		return fmt.Errorf("transport witness build does not match the assessed product: %w", err)
	}
	return nil
}

// transportClaimModuleVersion returns the module a claim's root causes belong
// to, when the model names one.
func transportClaimModuleVersion(model domain.ExploitModel, module string) string {
	if module == "" {
		return ""
	}
	for _, rc := range model.RootCauses {
		if rc.Package == "" {
			continue
		}
		if domain.PackageInModule(rc.Package, module) {
			return module
		}
	}
	return ""
}

// transportModuleCovers reports whether every root-cause and condition subject
// package of the claim lies inside the witness module.
func transportModuleCovers(model domain.ExploitModel, id domain.ConditionID, module string) bool {
	for _, rc := range model.RootCauses {
		if rc.Package != "" && !domain.PackageInModule(rc.Package, module) {
			return false
		}
	}
	for _, cond := range model.MandatoryConditions {
		if cond.ID != id {
			continue
		}
		subjects := append([]domain.SymbolRef{}, cond.Subjects...)
		if cond.Subject != nil {
			subjects = append(subjects, *cond.Subject)
		}
		for _, s := range subjects {
			if s.Package != "" && !domain.PackageInModule(s.Package, module) {
				return false
			}
		}
	}
	return true
}

// transportInputGapClaim reports a rooted-transport proof that did not close.
// The claim stays UNKNOWN: a missing proof is never a FALSE.
func transportInputGapClaim(cond domain.Condition, c *domain.AnalysisCase, code domain.GapCode, cause string) domain.Claim {
	return domain.Claim{
		ID:          domain.ClaimID("CL-" + string(cond.ID)),
		ConditionID: cond.ID,
		Result:      domain.ClaimUnknown,
		Producer:    "evaluator.ServerTransportInput",
		Explanation: "rooted server-transport input proof is incomplete: " + cause,
		AnalysisGaps: []domain.AnalysisGap{{
			Owner:        domain.GapOwnerCode,
			Code:         code,
			Obligation:   domain.ObligationCondition,
			AssessmentID: c.ID,
			ConditionID:  cond.ID,
			Message:      cause,
		}},
	}
}

// transportTriggerGapClaim reports a mechanism witness that did not close. The
// gap is PROOF-owned: this is analyzer work, never an environmental question.
func transportTriggerGapClaim(cond domain.Condition, c *domain.AnalysisCase, cause string) domain.Claim {
	return domain.Claim{
		ID:          domain.ClaimID("CL-" + string(cond.ID)),
		ConditionID: cond.ID,
		Result:      domain.ClaimUnknown,
		Producer:    "evaluator.ServerTransportInput",
		Explanation: "transport trigger proof is incomplete: " + cause,
		AnalysisGaps: []domain.AnalysisGap{{
			Owner:        domain.GapOwnerProof,
			Code:         domain.GapTriggerProofIncomplete,
			Obligation:   domain.ObligationCondition,
			AssessmentID: c.ID,
			ConditionID:  cond.ID,
			Message:      cause,
		}},
	}
}

// transportInputClaim records the admitted rooted input binding: attacker
// control is proven for a client of the affected transport, and nothing about
// deployed reachability is claimed.
func transportInputClaim(cond domain.Condition, c *domain.AnalysisCase, w *domain.TransportInputWitness) domain.Claim {
	claim := domain.Claim{
		ID:           domain.ClaimID("CL-" + string(cond.ID)),
		ConditionID:  cond.ID,
		Result:       domain.ClaimTrue,
		Producer:     "evaluator.ServerTransportInput",
		ControlBasis: domain.ControlBasisTransportPeerInput,
	}
	claim.EvidenceIDs = appendEvidenceIDs(claim.EvidenceIDs, w.EvidenceIDs)
	claim.Explanation = fmt.Sprintf(
		"rooted transport input: production root %s → %s(%s) → %s.%s serves the listener constructed at %s:%d; the accepted connection's peer supplies the bytes the affected transport consumes",
		w.Root.Package,
		strings.TrimPrefix(w.Server.Construction.Symbol.Symbol, ""),
		w.Server.Construction.Symbol.Package,
		w.Module, strings.Join(transportSymbolNames(w.Transport), " → "),
		w.Listener.Creation.CallSite.File, w.Listener.Creation.CallSite.Line)
	claim.Limitations = append(claim.Limitations, domain.TransportPeerScopeLimitations()...)
	return claim
}

func transportSymbolNames(sites []domain.TransportSite) []string {
	out := make([]string, 0, len(sites))
	for _, s := range sites {
		out = append(out, s.Symbol.Symbol)
	}
	return out
}

// transportTriggerClaim records the admitted mechanism lifecycle proof.
func transportTriggerClaim(cond domain.Condition, c *domain.AnalysisCase, w *domain.TransportTriggerWitness) domain.Claim {
	claim := domain.Claim{
		ID:          domain.ClaimID("CL-" + string(cond.ID)),
		ConditionID: cond.ID,
		Result:      domain.ClaimTrue,
		Producer:    "evaluator.ServerTransportInput",
	}
	claim.EvidenceIDs = appendEvidenceIDs(claim.EvidenceIDs, w.EvidenceIDs)
	var met []string
	for _, o := range w.Obligations {
		if o.Satisfied {
			met = append(met, string(o.ID))
		}
	}
	claim.Explanation = fmt.Sprintf(
		"transport mechanism %s is present in %s and the fix that closes it is absent: %s; no product control prevents it before the vulnerable dispatch",
		w.Mechanism, w.Module, strings.Join(met, ", "))
	claim.Limitations = append(claim.Limitations, domain.TransportPeerScopeLimitations()...)
	return claim
}

// transportProofWitnesses returns the transport witnesses recorded on the
// case. attempted is true as soon as the collector recorded either witness, so
// a failed proof is decided by its typed gap instead of falling back to a
// weaker structural heuristic.
func transportProofWitnesses(c *domain.AnalysisCase) (input *domain.TransportInputWitness, trigger *domain.TransportTriggerWitness, attempted bool) {
	if c == nil {
		return nil, nil, false
	}
	input, trigger = domain.TransportWitnessFromEvidence(c.EvidenceGraph.EvidenceList())
	return input, trigger, input != nil || trigger != nil
}

// transportInputWitness returns the rooted input witness to admit for an
// attacker-control condition: the recorded input witness, or the input
// embedded in a recorded trigger witness when the collector recorded only the
// mechanism proof. A trigger embeds the same rooted input binding, so this is
// the same typed record — never a weaker substitute.
func transportInputWitness(input *domain.TransportInputWitness, trigger *domain.TransportTriggerWitness) *domain.TransportInputWitness {
	if input != nil {
		return input
	}
	if trigger != nil {
		return &trigger.Input
	}
	return nil
}

// evaluateTransportInputCondition decides ATTACKER_CONTROL from the rooted
// input witness. A rejected witness leaves the claim UNKNOWN with its typed
// cause; it never becomes a FALSE and never falls back to the frame heuristic.
func evaluateTransportInputCondition(cond domain.Condition, c *domain.AnalysisCase, input *domain.TransportInputWitness) domain.Claim {
	if input == nil {
		return transportInputGapClaim(cond, c, domain.GapReachabilityProofIncomplete,
			"no production-rooted server transport path was established for this case")
	}
	if err := input.Complete(); err != nil {
		return transportInputGapClaim(cond, c, domain.GapInputTraceIncomplete, err.Error())
	}
	model := domain.ExploitModel{}
	if c.Exploit != nil {
		model = *c.Exploit
	}
	claim := transportInputClaim(cond, c, input)
	if err := ValidateTransportInput(c.Product, model, claim, c.EvidenceGraph.EvidenceList()); err != nil {
		return transportInputGapClaim(cond, c, domain.GapInputTraceIncomplete, err.Error())
	}
	return claim
}

// evaluateTransportTriggerCondition decides INPUT_CONSTRAINT for a mechanism
// the source actually implements. A generic transport frame cannot satisfy it:
// the source/fix-bound trigger witness is the only route, and its absence is a
// typed proof gap rather than a reason to consult a weaker fallback.
func evaluateTransportTriggerCondition(cond domain.Condition, c *domain.AnalysisCase, trigger *domain.TransportTriggerWitness) domain.Claim {
	if trigger == nil {
		return transportTriggerGapClaim(cond, c, "the affected source implements the mechanism but no trigger witness was collected")
	}
	model := domain.ExploitModel{}
	if c.Exploit != nil {
		model = *c.Exploit
	}
	claim := transportTriggerClaim(cond, c, trigger)
	if err := ValidateTransportTrigger(c.Product, model, claim, c.EvidenceGraph.EvidenceList()); err != nil {
		return transportTriggerGapClaim(cond, c, err.Error())
	}
	return claim
}

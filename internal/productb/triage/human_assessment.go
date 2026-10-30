package triage

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// HumanActionKind names the concrete action a human reviewer is asked to
// take. The set is closed: decoding rejects any other value so an action
// can never smuggle in an unspecified workflow state.
type HumanActionKind string

const (
	HumanActionClose          HumanActionKind = "CLOSE"
	HumanActionLowerPriority  HumanActionKind = "LOWER_PRIORITY"
	HumanActionRemediate      HumanActionKind = "REMEDIATE"
	HumanActionKeepOpen       HumanActionKind = "KEEP_OPEN"
	HumanActionObtainEvidence HumanActionKind = "OBTAIN_EVIDENCE"
	HumanActionAcceptEnvironmentalMitigation HumanActionKind = "ACCEPT_ENVIRONMENTAL_MITIGATION"
)

func (k HumanActionKind) Valid() bool {
	switch k {
	case HumanActionClose, HumanActionLowerPriority, HumanActionRemediate, HumanActionKeepOpen, HumanActionObtainEvidence, HumanActionAcceptEnvironmentalMitigation:
		return true
	}
	return false
}

func (k *HumanActionKind) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	candidate := HumanActionKind(raw)
	if !candidate.Valid() {
		return fmt.Errorf("invalid human action kind %q", raw)
	}
	*k = candidate
	return nil
}

// HumanAction is the model's proposal for a human reviewer — never a
// machine disposition. Instruction states the concrete action rather than
// a category label, Rationale gives its concise causal explanation, Scope
// names what it applies to, DecisiveClaimIDs names the premises whose
// truth decides it, and ReconsiderWhen names the observations that would
// change it. RecordIDs list the advisory/finding records actually
// considered and are not resolved here.
type HumanAction struct {
	Kind             HumanActionKind `json:"kind"`
	Instruction      string          `json:"instruction"`
	Rationale        string          `json:"rationale"`
	Scope            string          `json:"scope"`
	RecordIDs        []string        `json:"record_ids,omitempty"`
	DecisiveClaimIDs []string        `json:"decisive_claim_ids"`
	ReconsiderWhen   []string        `json:"reconsider_when"`
}

// PremiseBasis states how a claim's narrow proposition is established.
// MEASURED and PROVED are claims about recorded machine observations and
// admitted checks; INTERPRETED is the model's own source-grounded
// inference; ASSUMED names an external or human-owned premise;
// UNRESOLVED and CONFLICTING record what was not established.
type PremiseBasis string

const (
	PremiseMeasured    PremiseBasis = "MEASURED"
	PremiseProved      PremiseBasis = "PROVED"
	PremiseInterpreted PremiseBasis = "INTERPRETED"
	PremiseAssumed     PremiseBasis = "ASSUMED"
	PremiseUnresolved  PremiseBasis = "UNRESOLVED"
	PremiseConflicting PremiseBasis = "CONFLICTING"
)

func (b PremiseBasis) Valid() bool {
	switch b {
	case PremiseMeasured, PremiseProved, PremiseInterpreted, PremiseAssumed, PremiseUnresolved, PremiseConflicting:
		return true
	}
	return false
}

func (b *PremiseBasis) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	candidate := PremiseBasis(raw)
	if !candidate.Valid() {
		return fmt.Errorf("invalid premise basis %q", raw)
	}
	*b = candidate
	return nil
}

// PremiseBindingKind names the namespace ReferenceID resolves in.
type PremiseBindingKind string

const (
	BindingObservationFact PremiseBindingKind = "OBSERVATION_FACT"
	BindingQuotedText      PremiseBindingKind = "QUOTED_TEXT"
	BindingFalsifierProof  PremiseBindingKind = "FALSIFIER_PROOF"
)

func (k PremiseBindingKind) Valid() bool {
	switch k {
	case BindingObservationFact, BindingQuotedText, BindingFalsifierProof:
		return true
	}
	return false
}

func (k *PremiseBindingKind) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	candidate := PremiseBindingKind(raw)
	if !candidate.Valid() {
		return fmt.Errorf("invalid premise binding kind %q", raw)
	}
	*k = candidate
	return nil
}

// PremiseBinding ties a claim to one declared record: an observation
// evidence id, a declared source evidence id, or a falsifier proposal id
// that only the deterministic verifier can resolve. A binding establishes
// the record's own narrow proposition, never the claim's interpretation.
type PremiseBinding struct {
	Kind        PremiseBindingKind `json:"kind"`
	ReferenceID string             `json:"reference_id"`
}

// Counterargument is a material objection to the proposed action and the
// model's response to it. An empty Response records an objection that
// stays open; PremiseIDs name the claims the response relies on.
type Counterargument struct {
	ID         string   `json:"id"`
	Statement  string   `json:"statement"`
	Response   string   `json:"response,omitempty"`
	PremiseIDs []string `json:"premise_ids,omitempty"`
}

// ValidateHumanAssessment checks the model-owned v2 contract: claim
// identity and basis completeness, the claim dependency graph, the
// counterargument references and the proposed action with its decisive
// premise closure. Every claim in that closure must be decision-relevant,
// and every decision-relevant claim must be accounted for by it. Evidence
// ids, claim dependencies, counterargument premises and proposal ids are
// separate namespaces.
func ValidateHumanAssessment(a Assessment) error {
	evidence := make(map[string]bool, len(a.Evidence))
	for i, ev := range a.Evidence {
		if strings.TrimSpace(ev.ID) == "" {
			return fmt.Errorf("evidence[%d] requires non-empty id", i)
		}
		if evidence[ev.ID] {
			return fmt.Errorf("duplicate evidence id %q", ev.ID)
		}
		evidence[ev.ID] = true
	}
	proposals := make(map[string]bool, len(a.FalsifierProposals))
	for _, p := range a.FalsifierProposals {
		proposals[p.ID] = true
	}
	claims := make(map[string]*Claim, len(a.Claims))
	for i := range a.Claims {
		c := &a.Claims[i]
		if strings.TrimSpace(c.ID) == "" {
			return fmt.Errorf("claims[%d] requires non-empty id", i)
		}
		if _, dup := claims[c.ID]; dup {
			return fmt.Errorf("duplicate claim id %q", c.ID)
		}
		claims[c.ID] = c
	}
	for i := range a.Claims {
		if err := validateHumanClaim(a.Claims[i], claims, evidence, proposals); err != nil {
			return err
		}
	}
	if err := validateClaimDependencyCycles(claims); err != nil {
		return err
	}
	if err := validateCounterarguments(a.Counterarguments, claims); err != nil {
		return err
	}
	return validateHumanAction(a.ProposedAction, claims)
}

// validateHumanClaim checks one claim's own fields and every reference it
// declares.
func validateHumanClaim(c Claim, claims map[string]*Claim, evidence, proposals map[string]bool) error {
	if strings.TrimSpace(c.Statement) == "" {
		return fmt.Errorf("claim %q requires a statement", c.ID)
	}
	if !c.Basis.Valid() {
		return fmt.Errorf("claim %q has invalid basis %q", c.ID, c.Basis)
	}
	if strings.TrimSpace(c.Subject) == "" {
		return fmt.Errorf("claim %q requires a subject", c.ID)
	}
	if strings.TrimSpace(c.Scope) == "" {
		return fmt.Errorf("claim %q requires a scope", c.ID)
	}
	switch c.Basis {
	case PremiseAssumed:
		if strings.TrimSpace(c.Owner) == "" {
			return fmt.Errorf("claim %q with basis %s requires an owner", c.ID, c.Basis)
		}
	case PremiseUnresolved, PremiseConflicting:
		if strings.TrimSpace(c.Reason) == "" {
			return fmt.Errorf("claim %q with basis %s requires a reason", c.ID, c.Basis)
		}
	}
	for _, dep := range c.DependsOn {
		if dep == c.ID {
			return fmt.Errorf("claim %q depends on itself", c.ID)
		}
		if _, ok := claims[dep]; !ok {
			return fmt.Errorf("claim %q depends on undeclared claim id %q", c.ID, dep)
		}
	}
	for _, other := range c.ConflictsWith {
		if other == c.ID {
			return fmt.Errorf("claim %q conflicts with itself", c.ID)
		}
		if _, ok := claims[other]; !ok {
			return fmt.Errorf("claim %q conflicts with undeclared claim id %q", c.ID, other)
		}
	}
	for _, ref := range c.EvidenceRefs {
		if !evidence[ref] {
			return fmt.Errorf("claim %q cites undeclared evidence id %q", c.ID, ref)
		}
	}
	if c.Binding != nil {
		if !c.Binding.Kind.Valid() {
			return fmt.Errorf("claim %q binding has invalid kind %q", c.ID, c.Binding.Kind)
		}
		if strings.TrimSpace(c.Binding.ReferenceID) == "" {
			return fmt.Errorf("claim %q binding requires a reference_id", c.ID)
		}
		switch c.Binding.Kind {
		case BindingObservationFact, BindingQuotedText:
			if !evidence[c.Binding.ReferenceID] {
				return fmt.Errorf("claim %q binding references undeclared evidence id %q", c.ID, c.Binding.ReferenceID)
			}
		case BindingFalsifierProof:
			if !proposals[c.Binding.ReferenceID] {
				return fmt.Errorf("claim %q binding references undeclared falsifier proposal id %q", c.ID, c.Binding.ReferenceID)
			}
		}
	}
	return nil
}

// validateClaimDependencyCycles reports the first dependency cycle in the
// claim graph. Dangling dependencies were already rejected, so a cycle is
// the only way the causal graph can be unsatisfiable.
func validateClaimDependencyCycles(claims map[string]*Claim) error {
	const (
		visiting = 1
		done     = 2
	)
	state := make(map[string]uint8, len(claims))
	var stack []string
	var visit func(string) error
	visit = func(id string) error {
		switch state[id] {
		case visiting:
			start := 0
			for i, s := range stack {
				if s == id {
					start = i
					break
				}
			}
			cycle := append(append([]string(nil), stack[start:]...), id)
			return fmt.Errorf("claim dependency cycle: %s", strings.Join(cycle, " -> "))
		case done:
			return nil
		}
		state[id] = visiting
		stack = append(stack, id)
		deps := append([]string(nil), claims[id].DependsOn...)
		sort.Strings(deps)
		for _, dep := range deps {
			if _, ok := claims[dep]; !ok {
				continue
			}
			if err := visit(dep); err != nil {
				return err
			}
		}
		stack = stack[:len(stack)-1]
		state[id] = done
		return nil
	}
	for _, id := range sortedClaimIDs(claims) {
		if err := visit(id); err != nil {
			return err
		}
	}
	return nil
}

// validateCounterarguments checks the objection list: ids are unique,
// every objection carries a statement, and premise_ids resolve in the
// claim namespace.
func validateCounterarguments(counterarguments []Counterargument, claims map[string]*Claim) error {
	seen := make(map[string]bool, len(counterarguments))
	for i, ca := range counterarguments {
		if strings.TrimSpace(ca.ID) == "" {
			return fmt.Errorf("counterarguments[%d] requires non-empty id", i)
		}
		if seen[ca.ID] {
			return fmt.Errorf("duplicate counterargument id %q", ca.ID)
		}
		seen[ca.ID] = true
		if strings.TrimSpace(ca.Statement) == "" {
			return fmt.Errorf("counterargument %q requires a statement", ca.ID)
		}
		for _, premise := range ca.PremiseIDs {
			if _, ok := claims[premise]; !ok {
				return fmt.Errorf("counterargument %q cites undeclared premise id %q", ca.ID, premise)
			}
		}
	}
	return nil
}

// decisiveClaimClosure returns the action's decisive premise closure: its
// decisive claim ids plus every claim they transitively depend on. Dangling
// ids are skipped; callers that require a validated graph check them first.
// The traversal is the single definition both the validator and support
// derivation use, so the graph they reason about cannot diverge.
func decisiveClaimClosure(act HumanAction, claims map[string]*Claim) map[string]bool {
	closure := make(map[string]bool, len(claims))
	queue := make([]string, 0, len(act.DecisiveClaimIDs))
	for _, id := range act.DecisiveClaimIDs {
		if _, ok := claims[id]; !ok || closure[id] {
			continue
		}
		closure[id] = true
		queue = append(queue, id)
	}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		for _, dep := range claims[id].DependsOn {
			if closure[dep] {
				continue
			}
			if _, ok := claims[dep]; !ok {
				continue
			}
			closure[dep] = true
			queue = append(queue, dep)
		}
	}
	return closure
}

// validateActionFields checks the model-owned action contract without the
// claim namespace: the kind is closed, the instruction/ rationale/ scope and
// at least one reconsideration are required, and the decisive claim ids are
// a non-empty deduplicated set. Claim resolution stays with the caller that
// owns the claim graph.
func validateActionFields(act HumanAction) error {
	if !act.Kind.Valid() {
		return fmt.Errorf("invalid human action kind %q", act.Kind)
	}
	required := []struct {
		name  string
		value string
	}{
		{"instruction", act.Instruction},
		{"rationale", act.Rationale},
		{"scope", act.Scope},
	}
	for _, f := range required {
		if strings.TrimSpace(f.value) == "" {
			return fmt.Errorf("proposed_action field %q is required", f.name)
		}
	}
	if len(act.ReconsiderWhen) == 0 {
		return fmt.Errorf("proposed_action field %q is required", "reconsider_when")
	}
	for _, reason := range act.ReconsiderWhen {
		if strings.TrimSpace(reason) == "" {
			return fmt.Errorf("proposed_action field %q contains an empty entry", "reconsider_when")
		}
	}
	if len(act.DecisiveClaimIDs) == 0 {
		return fmt.Errorf("proposed_action field %q is required", "decisive_claim_ids")
	}
	seen := make(map[string]bool, len(act.DecisiveClaimIDs))
	for _, id := range act.DecisiveClaimIDs {
		if strings.TrimSpace(id) == "" {
			return fmt.Errorf("proposed_action field %q contains an empty id", "decisive_claim_ids")
		}
		if seen[id] {
			return fmt.Errorf("duplicate decisive claim id %q", id)
		}
		seen[id] = true
	}
	records := make(map[string]bool, len(act.RecordIDs))
	for _, id := range act.RecordIDs {
		if strings.TrimSpace(id) == "" {
			return fmt.Errorf("proposed_action field %q contains an empty id", "record_ids")
		}
		if records[id] {
			return fmt.Errorf("duplicate record id %q", id)
		}
		records[id] = true
	}
	return nil
}

// validateHumanAction checks the proposed action and computes the decisive
// premise closure: the action's decisive claims plus every claim they
// depend on. The closure must account for all decision-relevant claims —
// both directions are enforced so a support computation can never silently
// ignore a premise the action rests on.
func validateHumanAction(act HumanAction, claims map[string]*Claim) error {
	if err := validateActionFields(act); err != nil {
		return err
	}
	for _, id := range act.DecisiveClaimIDs {
		if _, ok := claims[id]; !ok {
			return fmt.Errorf("proposed_action cites undeclared decisive claim id %q", id)
		}
	}
	closure := decisiveClaimClosure(act, claims)
	for _, id := range sortedIDs(closure) {
		if !claims[id].DecisionRelevant {
			return fmt.Errorf("decisive claim %q must be decision-relevant", id)
		}
	}
	for _, id := range sortedClaimIDs(claims) {
		if claims[id].DecisionRelevant && !closure[id] {
			return fmt.Errorf("decision-relevant claim %q is outside the decisive premise closure", id)
		}
	}
	return nil
}

// sortedClaimIDs returns the claim id set in deterministic order.
func sortedClaimIDs(claims map[string]*Claim) []string {
	ids := make([]string, 0, len(claims))
	for id := range claims {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// sortedIDs returns a string set in deterministic order.
func sortedIDs(set map[string]bool) []string {
	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

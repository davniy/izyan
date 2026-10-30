package triage

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type ConditionalActionProposal struct {
	Assignments map[string]string `json:"assignments"`
	Judgment LLMJudgment `json:"judgment"`
	Action HumanAction `json:"action"`
}

type HumanBranchStatus string
const (
	HumanBranchComplete HumanBranchStatus = "COMPLETE"
	HumanBranchAwaitingInput HumanBranchStatus = "AWAITING_INPUT"
	HumanBranchContradicted HumanBranchStatus = "CONTRADICTED"
	HumanBranchNotDecisionReady HumanBranchStatus = "NOT_DECISION_READY"
)

type HumanDecisionBranch struct {
	ID string `json:"id"`
	Assignments map[string]string `json:"assignments"`
	Judgment LLMJudgment `json:"judgment"`
	Action HumanAction `json:"action"`
	Premises []DecisionPremise `json:"premises"`
	Support DecisionSupport `json:"support"`
	Status HumanBranchStatus `json:"status"`
	Limitations []string `json:"limitations,omitempty"`
}

type HumanReviewPlan struct {
	Variables []DecisionVariable `json:"variables"`
	Branches []HumanDecisionBranch `json:"branches"`
	MandatoryPremiseIDs []string `json:"mandatory_premise_ids"`
	Readiness string `json:"readiness"`
}

// HumanBranchInput deliberately accepts the existing support inputs, not user
// answers. Answer recording/selection belongs to the human review layer.
type HumanBranchInput struct { SupportInput }

// BuildHumanReviewPlan enumerates the complete finite assignment universe in
// code and evaluates each action independently through DeriveSupport. It never
// writes a machine fact, proof, disposition, necessity or code claim.
func BuildHumanReviewPlan(in HumanBranchInput) (HumanReviewPlan, error) {
	base, err := DeriveSupport(in.SupportInput)
	if err != nil { return HumanReviewPlan{}, err }
	return buildHumanReviewPlan(in, base)
}

func buildHumanReviewPlan(in HumanBranchInput, base SupportResult) (HumanReviewPlan, error) {
	plan := HumanReviewPlan{Readiness: string(HumanBranchComplete)}
	judgment := LLMJudgment{Verdict: in.Assessment.Verdict, Summary: in.Assessment.Summary, Mechanism: in.Assessment.Mechanism}
	if len(in.Assessment.EnvironmentVariables) == 0 && len(in.Assessment.ConditionalActions) != 0 {
		return plan, fmt.Errorf("conditional actions require declared environment nominations")
	}
	if len(in.Assessment.EnvironmentVariables) == 0 && in.Assessment.ProposedAction.Kind == HumanActionAcceptEnvironmentalMitigation {
		return plan, fmt.Errorf("environmental mitigation requires an explicit environment branch")
	}
	// An independently sufficient scoped proof makes all environment questions
	// irrelevant. Model-interpreted CLOSE remains a valid unconditional opinion.
	if len(in.Assessment.EnvironmentVariables) == 0 || base.Support.Level == SupportLevelProvedWithinScope {
		plan.Branches = []HumanDecisionBranch{{ID: "unconditional", Assignments: map[string]string{}, Judgment: judgment, Action: in.Assessment.ProposedAction, Premises: base.Premises, Support: base.Support, Status: HumanBranchComplete}}
		for _, p := range base.Premises { plan.MandatoryPremiseIDs = append(plan.MandatoryPremiseIDs, p.ClaimID) }
		if len(base.Premises) > MaxMandatoryPremises { blockHumanPlan(&plan, "mandatory first-screen premise count exceeds seven") }
		return plan, nil
	}
	if in.Assessment.ProposedAction.Kind == HumanActionClose || in.Assessment.ProposedAction.Kind == HumanActionLowerPriority || in.Assessment.ProposedAction.Kind == HumanActionAcceptEnvironmentalMitigation {
		return plan, fmt.Errorf("unselected environment plan requires a conservative base proposed_action; reductions belong only to prepared branches")
	}
	questionCount := 0
	for _, p := range in.Assessment.EnvironmentVariables { if p.ID != VariableBuildVariant { questionCount++ } }
	if questionCount > MaxEnvironmentQuestions {
		plan.Branches = []HumanDecisionBranch{{ID: "not-decision-ready", Assignments: map[string]string{}, Judgment: judgment, Action: in.Assessment.ProposedAction, Premises: base.Premises, Support: base.Support}}
		for _, pr := range base.Premises { plan.MandatoryPremiseIDs = append(plan.MandatoryPremiseIDs, pr.ClaimID) }
		blockHumanPlan(&plan, "environment question count exceeds two")
		return plan, nil
	}
	vars, err := environmentVariables(in.SupportInput)
	if err != nil { return plan, err }
	plan.Variables = vars
	universe := []map[string]string{{}}
	for _, v := range vars {
		var next []map[string]string
		for _, as := range universe {
			for _, value := range v.AllowedValues {
				copy := cloneAssignments(as)
				copy[v.ID] = value
				next = append(next, copy)
			}
		}
		universe = next
	}
	proposals := map[string]ConditionalActionProposal{}
	allowed := map[string]bool{}
	for _, as := range universe { allowed[assignmentKey(as)] = true }
	for _, p := range in.Assessment.ConditionalActions {
		key := assignmentKey(p.Assignments)
		if !allowed[key] { return plan, fmt.Errorf("conditional action has assignments outside the code-owned universe: %s", key) }
		if _, ok := proposals[key]; ok { return plan, fmt.Errorf("duplicate conditional action assignments: %s", key) }
		if !p.Judgment.Verdict.Valid() { return plan, fmt.Errorf("conditional action has invalid judgment") }
		if err := validateActionFields(p.Action); err != nil { return plan, err }
		proposals[key] = p
	}
	mandatory := map[string]bool{}
	for i, as := range universe {
		id := fmt.Sprintf("branch-%02d", i+1)
		branch := HumanDecisionBranch{ID: id, Assignments: as, Status: HumanBranchComplete}
		p, ok := proposals[assignmentKey(as)]
		if !ok {
			branch.Judgment = judgment
			branch.Action = conservativeBranchAction(in.Assessment.ProposedAction)
			branch.Premises, branch.Support = base.Premises, base.Support
			branch.Status = HumanBranchNotDecisionReady
			branch.Limitations = []string{"missing prepared conditional action; no decision was invented"}
			plan.Readiness = string(HumanBranchNotDecisionReady)
		} else {
			branch.Judgment, branch.Action = p.Judgment, p.Action
			unknown := unknownAssignment(as)
			if unknown && p.Action.Kind != HumanActionKeepOpen && p.Action.Kind != HumanActionRemediate {
				return plan, fmt.Errorf("unknown branch must conservatively KEEP_OPEN or REMEDIATE")
			}
			if as[VariableBuildVariant] == "other" && p.Action.Kind != HumanActionKeepOpen && p.Action.Kind != HumanActionRemediate {
				return plan, fmt.Errorf("other build variant must keep open: recorded evidence does not transfer")
			}
			if p.Action.Kind == HumanActionClose || p.Action.Kind == HumanActionLowerPriority {
				return plan, fmt.Errorf("environment-dependent reduction must be labelled ACCEPT_ENVIRONMENTAL_MITIGATION, not %s", p.Action.Kind)
			}
			if p.Action.Kind == HumanActionAcceptEnvironmentalMitigation && !mitigatingAssignment(as) {
				return plan, fmt.Errorf("environmental mitigation requires a supported mitigating assignment")
			}
			branchInput := in.SupportInput
			a := in.Assessment
			a.Claims = append([]Claim(nil), a.Claims...)
			a.ProposedAction = p.Action
			a.ProposedAction.DecisiveClaimIDs = append([]string(nil), p.Action.DecisiveClaimIDs...)
			a.EnvironmentVariables, a.ConditionalActions = nil, nil
			claimMap := map[string]*Claim{}
			for j := range a.Claims { claimMap[a.Claims[j].ID] = &a.Claims[j] }
			for _, claim := range p.Action.DecisiveClaimIDs { if claimMap[claim] == nil { return plan, fmt.Errorf("branch %s cites undeclared claim %q", id, claim) } }
			closure := decisiveClaimClosure(p.Action, claimMap)
			for j := range a.Claims { a.Claims[j].DecisionRelevant = closure[a.Claims[j].ID] }
			for _, v := range vars {
				claimID := "environment:" + id + ":" + v.ID
				basis, reason := PremiseAssumed, ""
				if as[v.ID] == EnvironmentUnknown { basis, reason = PremiseUnresolved, "environment answer is unknown" }
				a.Claims = append(a.Claims, Claim{ID: claimID, Statement: v.ID + " = " + as[v.ID], Basis: basis, Subject: v.ID, Scope: p.Action.Scope, Owner: "human reviewer", Reason: reason, DecisionRelevant: true})
				a.ProposedAction.DecisiveClaimIDs = append(a.ProposedAction.DecisiveClaimIDs, claimID)
			}
			branchInput.Assessment = a
			derived, err := DeriveSupport(branchInput)
			if err != nil { return plan, fmt.Errorf("branch %s support: %w", id, err) }
			branch.Action = a.ProposedAction
			branch.Premises, branch.Support = derived.Premises, derived.Support
			for j := range branch.Premises {
				pr := &branch.Premises[j]
				if strings.HasPrefix(pr.ClaimID, "environment:"+id+":") {
					for _, v := range vars { if pr.Subject == v.ID { pr.SourceRefs = append([]string(nil), v.DerivedFrom...) } }
				}
			}
			if unknown { branch.Limitations = append(branch.Limitations, "unknown environment: keep open without additional human investigation") }
			if p.Action.Kind == HumanActionObtainEvidence {
				branch.Status = HumanBranchNotDecisionReady
				branch.Action = conservativeBranchAction(branch.Action)
				branch.Limitations = append(branch.Limitations, "OBTAIN_EVIDENCE is not a prepared environment decision")
				plan.Readiness = string(HumanBranchNotDecisionReady)
			}
			if deploy := in.Stage0.Materials.Deploy; deploy != nil && deploy.FactCount > 0 && deploy.SHA256 != "" {
				if value := as[VariableDeploymentPerimeter]; value != "" && value != EnvironmentUnknown && (deploy.Perimeter == "public" || deploy.Perimeter == "cluster-internal") && value != deploy.Perimeter {
					branch.Status = HumanBranchContradicted
					branch.Action = conservativeBranchAction(branch.Action)
					branch.Limitations = append(branch.Limitations, "assignment conflicts with recorded deployment perimeter")
				}
			}
		}
		for _, pr := range branch.Premises { mandatory[pr.ClaimID] = true }
		plan.Branches = append(plan.Branches, branch)
	}
	// The first screen presents the shared closure and one slot per human
	// environment premise, not all mutually exclusive branch assertions.
	firstScreen := map[string]bool{}
	for id := range mandatory { if !strings.HasPrefix(id, "environment:") { firstScreen[id] = true } }
	for _, v := range vars { firstScreen["environment:" + v.ID] = true }
	plan.MandatoryPremiseIDs = sortedIDs(firstScreen)
	if plan.Readiness == string(HumanBranchNotDecisionReady) { blockHumanPlan(&plan, "conditional proposal universe is incomplete or requests further investigation") }
	if len(plan.MandatoryPremiseIDs) > MaxMandatoryPremises { blockHumanPlan(&plan, "mandatory first-screen premise count exceeds seven; no decisive facts were trimmed") }
	return plan, nil
}

func conservativeBranchAction(a HumanAction) HumanAction {
	a.Kind = HumanActionKeepOpen
	a.Instruction = "Keep the finding open; this package is not decision-ready for a reduction."
	a.Rationale = "A complete bounded prepared decision is unavailable or contradicted."
	return a
}
func blockHumanPlan(p *HumanReviewPlan, reason string) {
	p.Readiness = string(HumanBranchNotDecisionReady)
	for i := range p.Branches {
		p.Branches[i].Status = HumanBranchNotDecisionReady
		p.Branches[i].Action = conservativeBranchAction(p.Branches[i].Action)
		p.Branches[i].Limitations = append(p.Branches[i].Limitations, reason)
	}
}
func cloneAssignments(as map[string]string) map[string]string {
	out := make(map[string]string, len(as))
	for k, v := range as { out[k] = v }
	return out
}
func assignmentKey(as map[string]string) string { b, _ := json.Marshal(as); return string(b) }
func unknownAssignment(as map[string]string) bool { for _, v := range as { if v == EnvironmentUnknown { return true } }; return false }
func mitigatingAssignment(as map[string]string) bool {
	return !unknownAssignment(as) && (as[VariableDeploymentPerimeter] == "cluster-internal" || as[VariableAdvisoryPrecondition] == "does_not_hold")
}

// validateHumanReviewPlan validates the serialized contract without recomputing
// evidence. Replay recomputes it from captured inputs and compares its hash.
func validateHumanReviewPlan(p HumanReviewPlan) error {
	if p.Readiness != string(HumanBranchComplete) && p.Readiness != string(HumanBranchNotDecisionReady) { return fmt.Errorf("invalid human review readiness %q", p.Readiness) }
	if len(p.Branches) == 0 { return fmt.Errorf("human review plan carries no branches") }
	ready := p.Readiness == string(HumanBranchComplete)
	if ready && len(p.MandatoryPremiseIDs) > MaxMandatoryPremises { return fmt.Errorf("ready plan exceeds seven mandatory premises") }
	variables := map[string]DecisionVariable{}
	questions, combinations := 0, 1
	for _, v := range p.Variables {
		if _, exists := variables[v.ID]; exists { return fmt.Errorf("duplicate decision variable %q", v.ID) }
		if err := validateDecisionVariable(v); err != nil { return err }
		if v.Required { questions++ }
		combinations *= len(v.AllowedValues)
		variables[v.ID] = v
	}
	if ready && questions > MaxEnvironmentQuestions { return fmt.Errorf("ready plan exceeds two questions") }
	if ready && len(p.Branches) != combinations { return fmt.Errorf("prepared branch universe is incomplete") }
	ids, assignments, environmentIDs, mandatory := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, b := range p.Branches {
		if b.ID == "" || ids[b.ID] { return fmt.Errorf("missing or duplicate human branch id %q", b.ID) }
		ids[b.ID] = true
		key := assignmentKey(b.Assignments)
		if assignments[key] { return fmt.Errorf("duplicate human branch assignments") }
		assignments[key] = true
		if len(b.Assignments) != len(variables) { return fmt.Errorf("branch assignment dimension mismatch") }
		for id, value := range b.Assignments {
			v, exists := variables[id]
			allowed := false
			for _, candidate := range v.AllowedValues { allowed = allowed || candidate == value }
			if !exists || !allowed { return fmt.Errorf("branch assignment outside declared universe") }
		}
		switch b.Status { case HumanBranchComplete, HumanBranchAwaitingInput, HumanBranchContradicted, HumanBranchNotDecisionReady: default: return fmt.Errorf("invalid human branch status %q", b.Status) }
		if ready && b.Status == HumanBranchNotDecisionReady { return fmt.Errorf("ready plan carries an incomplete branch") }
		if b.Status == HumanBranchContradicted || b.Status == HumanBranchNotDecisionReady || unknownAssignment(b.Assignments) {
			if b.Action.Kind != HumanActionKeepOpen && b.Action.Kind != HumanActionRemediate { return fmt.Errorf("unready, contradicted or unknown branch must keep open") }
		}
		if len(variables) > 0 && (b.Action.Kind == HumanActionClose || b.Action.Kind == HumanActionLowerPriority) { return fmt.Errorf("environment branch reduction must be contextual mitigation") }
		if b.Action.Kind == HumanActionAcceptEnvironmentalMitigation && !mitigatingAssignment(b.Assignments) { return fmt.Errorf("mitigation has no mitigating assignment") }
		if err := validateActionFields(b.Action); err != nil { return err }
		if !b.Judgment.Verdict.Valid() || !b.Support.Level.Valid() { return fmt.Errorf("invalid branch judgment or support") }
		if !sameStringSet(b.Support.DecisiveClaimIDs, b.Premises) { return fmt.Errorf("branch support closure mismatch") }
		premises := map[string]bool{}
		for _, pr := range b.Premises {
			if pr.ClaimID == "" || premises[pr.ClaimID] || pr.Statement == "" || pr.Subject == "" || pr.Scope == "" || !pr.Basis.Valid() { return fmt.Errorf("incomplete or duplicate branch premise") }
			premises[pr.ClaimID] = true
			if strings.HasPrefix(pr.ClaimID, "environment:") {
				if environmentIDs[pr.ClaimID] || !strings.HasPrefix(pr.ClaimID, "environment:"+b.ID+":") || pr.Owner != "human reviewer" || pr.Basis != PremiseAssumed && pr.Basis != PremiseUnresolved { return fmt.Errorf("environment premise is borrowed or has machine authority") }
				if _, exists := variables[pr.Subject]; !exists || pr.ClaimID != "environment:"+b.ID+":"+pr.Subject || pr.Statement != pr.Subject+" = "+b.Assignments[pr.Subject] { return fmt.Errorf("environment premise does not match its own branch assignment") }
				environmentIDs[pr.ClaimID] = true
				mandatory["environment:"+pr.Subject] = true
				if b.Support.Level == SupportLevelProvedWithinScope || b.Support.Level == SupportLevelSubstantiated { return fmt.Errorf("human environment assertion cannot substantiate or prove the action") }
			} else { mandatory[pr.ClaimID] = true }
		}
		if b.Status == HumanBranchComplete {
			for id := range variables { if !premises["environment:"+b.ID+":"+id] { return fmt.Errorf("complete branch omits its environment premise") } }
		}
		for _, id := range b.Action.DecisiveClaimIDs { if !premises[id] { return fmt.Errorf("branch action cites absent decisive premise") } }
		for _, pr := range b.Premises { for _, dep := range pr.DependsOn { if !premises[dep] { return fmt.Errorf("branch borrows dependency outside its premise closure") } } }
	}
	for _, v := range p.Variables { mandatory["environment:"+v.ID] = true }
	listed := map[string]bool{}
	for _, id := range p.MandatoryPremiseIDs { if listed[id] || !mandatory[id] { return fmt.Errorf("invalid mandatory premise id %q", id) }; listed[id] = true }
	if len(listed) != len(mandatory) { return fmt.Errorf("mandatory premise set omits decisive facts") }
	return nil
}

// stabilityActionHash compares branch meaning without attempt-local metadata.
func stabilityActionHash(pkg DecisionPackage) string {
	if pkg.SchemaVersion == "decision-package.v3" || pkg.HumanReviewPlan == nil { return projectionHash(pkg.ProposedAction) }
	type branch struct {
		ID string
		Assignments map[string]string
		Judgment LLMJudgment
		Action HumanAction
		Premises []stabilityPremise
		Support stabilitySupport
		Status HumanBranchStatus
	}
	p := pkg.HumanReviewPlan
	branches := make([]branch, 0, len(p.Branches))
	for _, b := range p.Branches { branches = append(branches, branch{b.ID, b.Assignments, b.Judgment, b.Action, stabilityPremises(b.Premises), stabilitySupportOf(b.Support), b.Status}) }
	sort.Slice(branches, func(i, j int) bool { return branches[i].ID < branches[j].ID })
	return projectionHash(struct {
		Action HumanAction
		Variables []DecisionVariable
		Branches []branch
		Mandatory []string
		Readiness string
	}{pkg.ProposedAction, p.Variables, branches, p.MandatoryPremiseIDs, p.Readiness})
}

package research

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/davniy/izyan/internal/domain"
)

// decisionHex64Re is the strict sha256 digest shape the R6 artifact
// carries in its own digest fields (bare 64-hex, matching the report's
// input_digest/data_digest convention).
var decisionHex64Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

// decisionObsRefRe is the persisted-observation reference shape
// Fact.ObservationRefs carries: the obs: namespace over the OBS-<n>
// identifiers minted by the evidence session.
var decisionObsRefRe = regexp.MustCompile(`^obs:OBS-\d+$`)

// ProposedDisposition is the closed enum of decision proposals an R6
// artifact may carry (Amendment R6). CLOSE_* proposals are code-grounded
// closures: they may rest only on verified deterministic premises and
// never on environment answers or declared trust. R6 prepares a decision
// for human acceptance — it never authorizes auto-close or tracker writes,
// so no disposition here maps to a Disposition other than REVIEW_REQUIRED.
type ProposedDisposition string

const (
	// DispositionCloseNotAffected proposes closure because the
	// deterministic applicability chain proved the advisory does not
	// apply to the recorded snapshot.
	DispositionCloseNotAffected ProposedDisposition = "CLOSE_NOT_AFFECTED"
	// DispositionCloseNoExploitPath proposes closure because a typed
	// falsifier was independently verified over a closed scope.
	DispositionCloseNoExploitPath ProposedDisposition = "CLOSE_NO_EXPLOIT_PATH"
	// DispositionAcceptEnvironmentalMitigation proposes closure of the
	// open risk on the recorded environment premise (declared trust,
	// perimeter posture). It is contextual — never a code-level
	// negative. FalsifierTrustedInfrastructure may produce only this.
	DispositionAcceptEnvironmentalMitigation ProposedDisposition = "ACCEPT_ENVIRONMENTAL_MITIGATION"
	// DispositionKeepOpenForRemediation proposes keeping the finding
	// open with a remediation recommendation.
	DispositionKeepOpenForRemediation ProposedDisposition = "KEEP_OPEN_FOR_REMEDIATION"
	// DispositionHoldUnknown is the explicit fallback: the evidence does
	// not decide and the artifact does not pretend otherwise.
	DispositionHoldUnknown ProposedDisposition = "HOLD_UNKNOWN"
)

// isProposedDisposition reports whether d is a member of the closed R6
// enum; isCloseDisposition reports whether d is a code-grounded closure.
func isProposedDisposition(d ProposedDisposition) bool {
	switch d {
	case DispositionCloseNotAffected, DispositionCloseNoExploitPath,
		DispositionAcceptEnvironmentalMitigation, DispositionKeepOpenForRemediation,
		DispositionHoldUnknown:
		return true
	}
	return false
}

func isCloseDisposition(d ProposedDisposition) bool {
	return d == DispositionCloseNotAffected || d == DispositionCloseNoExploitPath
}

// BranchStatus is the closed enum of branch evaluation states.
type BranchStatus string

// BranchStatus values for DecisionBranch.Status.
const (
	// BranchComplete marks a branch whose premise set is fully discharged.
	BranchComplete BranchStatus = "COMPLETE"
	// BranchAwaitingInput marks a branch that still needs declared
	// environment answers (required_environment_inputs).
	BranchAwaitingInput BranchStatus = "AWAITING_INPUT"
	// BranchContradicted marks a branch whose premises conflict with
	// machine evidence; it may propose only a non-close disposition.
	BranchContradicted BranchStatus = "CONTRADICTED"
	// BranchNotDecisionReady marks a branch that cannot be discharged
	// inside the human contract bounds.
	BranchNotDecisionReady BranchStatus = "NOT_DECISION_READY"
)

// Fact.Status values (decision-artifact fact state). Only VERIFIED facts
// may premise a CLOSE_* justification or branch.
const (
	FactStatusVerified     = "VERIFIED"
	FactStatusDegraded     = "DEGRADED"
	FactStatusContradicted = "CONTRADICTED"
)

// Fact.Coverage values. A COMPLETE branch requires COMPLETE coverage.
const (
	FactCoverageComplete     = "COMPLETE"
	FactCoveragePartial      = "PARTIAL"
	FactCoverageNotEvaluated = "NOT_EVALUATED"
)

// Condition.Polarity values: whether the condition, when it holds,
// supports or undermines the branch's premise.
const (
	PolarityPositive = "POSITIVE"
	PolarityNegative = "NEGATIVE"
)

// HumanAction.Mode values.
const (
	// HumanActionAcceptReject is the terminal R6 human action: read the
	// mandatory facts and justification, then Accept or Reject.
	HumanActionAcceptReject = "ACCEPT_REJECT"
	// HumanActionAnswerThenAcceptReject applies when branches still need
	// at most MaxEnvironmentQuestions declared environment answers.
	HumanActionAnswerThenAcceptReject = "ANSWER_THEN_ACCEPT_REJECT"
)

// HumanAction.AllowedResponses members — the human may only accept or
// reject the proposed disposition; there is no third option.
const (
	HumanResponseAccept = "Accept"
	HumanResponseReject = "Reject"
)

// R6 hard bounds on the human-facing contract.
const (
	// MaxEnvironmentQuestions bounds the environment variables the human
	// may be asked to answer (R6: at most two).
	MaxEnvironmentQuestions = 2
	// MaxMandatoryFacts bounds the facts rendered on the first screen
	// before the accept/reject choice (R6: at most seven).
	MaxMandatoryFacts = 7
)

// nonIndependentProvenance is the closed set of source_tool values that
// mark a statement as coming from a person or deployment declaration
// rather than from an independent tool run. Such statements are
// EnvironmentAssertions, never Facts: a fact carrying one is the R6
// laundering attempt (a declared-trust "trusted peer" premise wearing a
// fact's deterministic provenance) and is rejected outright. They can
// therefore also never premise a CLOSE_* disposition — declared trust
// may only produce ACCEPT_ENVIRONMENTAL_MITIGATION branches.
var nonIndependentProvenance = map[string]bool{
	"declared-trust":         true,
	"trusted-peer":           true,
	"trusted-infrastructure": true,
	"auto-perimeter":         true,
	"operator-assertion":     true,
	"operator":               true,
	"human":                  true,
	"environment":            true,
	"environment-assertion":  true,
	"agent":                  true,
	"agent-output":           true,
	"llm":                    true,
	"model":                  true,
}

// Contradiction kind values the R6 branch layer records. They extend
// the existing report-level kinds: one deterministic surface
// contradicting another is an evidence conflict; an operator answer
// that contradicts recorded machine evidence is an
// environment-vs-machine conflict — the human is never asked to
// resolve either by inspecting source.
const (
	ContradictionEvidenceConflict     = "evidence_conflict"
	ContradictionEnvironmentVsMachine = "environment_vs_machine"
)

// Condition is one predicate of a branch's premise set. Role reuses the
// exploitation-conditions vocabulary; Polarity records whether the
// condition's truth supports or undermines the premise.
type Condition struct {
	ID          string   `json:"id"`
	Statement   string   `json:"statement"`
	Role        string   `json:"role"`
	SubjectRefs []string `json:"subject_refs"`
	Required    bool     `json:"required"`
	Polarity    string   `json:"polarity"`
}

// Fact is an independently produced, digest-bound evidence statement.
// It is deliberately a different shape from domain.Claim: it carries no
// result/verdict field, so a fact can never be written as a code-level
// TRUE/FALSE claim, and its provenance fields (source_tool, tool_version,
// observation_refs, data_digest) make a human or agent declaration
// structurally distinguishable from a tool observation.
type Fact struct {
	ID              string   `json:"id"`
	Proposition     string   `json:"proposition"`
	Subject         string   `json:"subject"`
	Scope           string   `json:"scope"`
	SourceTool      string   `json:"source_tool"`
	ToolVersion     string   `json:"tool_version"`
	ObservationRefs []string `json:"observation_refs"`
	DataDigest      string   `json:"data_digest"`
	Coverage        string   `json:"coverage"`
	Freshness       string   `json:"freshness"`
	Limitations     []string `json:"limitations"`
	Status          string   `json:"status"`
	// TrustClass is the release-evidence trust class of the version axis
	// the fact's predicates were resolved against — AUTHORITATIVE when
	// the release artifact/metadata module graph grounded them. Empty
	// when no authoritative release graph participated; a SUPPORTING
	// class is recorded for provenance but can never upgrade a fact.
	TrustClass string `json:"trust_class,omitempty"`
}

// EnvironmentAssertion records a human/operator answer about the
// deployment environment. It is an auditable deployment premise — never
// a code-level falsifier. The type intentionally has no claim, result or
// falsifier field, so it cannot be serialized as or converted into a
// Claim{Result: FALSE}; an artifact that tries to launder it as a fact
// (non-independent source_tool) or as a CLOSE_* premise is rejected.
type EnvironmentAssertion struct {
	Variable   string   `json:"variable"`
	Value      string   `json:"value"`
	Principal  string   `json:"principal"`
	Timestamp  string   `json:"timestamp"`
	Source     string   `json:"source"`
	Freshness  string   `json:"freshness"`
	Supersedes []string `json:"supersedes"`
}

// DecisionVariable is one declared environment variable a branch may be
// conditioned on. The allowed value set is finite and enumerated; the
// agent may propose that a variable matters but never invents a value.
// DerivedFrom carries the advisory-text provenance of a variable whose
// question is derived from a recorded advisory statement (the advisory
// field plus the verbatim quote — the same derived_from convention the
// trace requests and decision checks already use). Code-owned variables
// leave it nil; it is additive/omitempty so legacy artifacts stay
// byte-identical.
type DecisionVariable struct {
	ID            string             `json:"id"`
	Question      string             `json:"question"`
	AllowedValues []string           `json:"allowed_values"`
	Required      bool               `json:"required"`
	DerivedFrom   *SubjectProvenance `json:"derived_from,omitempty"`
}

// DecisionBranch is one complete conditional decision: a fixed
// assignment over declared variables plus the conditions, facts and
// environment assertions that premise its proposed disposition. A branch
// may only carry its own premises — it can never borrow another branch's
// facts or environment answers, and its assertions must stay consistent
// with its own assignments.
type DecisionBranch struct {
	ID                        string                 `json:"id"`
	Assignments               map[string]string      `json:"assignments"`
	Conditions                []Condition            `json:"conditions"`
	FactRefs                  []string               `json:"fact_refs"`
	EnvironmentAssertions     []EnvironmentAssertion `json:"environment_assertions"`
	Coverage                  string                 `json:"coverage"`
	Status                    BranchStatus           `json:"status"`
	ProposedDisposition       ProposedDisposition    `json:"proposed_disposition"`
	Limitations               []string               `json:"limitations"`
	RequiredEnvironmentInputs []string               `json:"required_environment_inputs"`
}

// Justification links premise facts and conditions through one catalog
// rule to a proposed disposition.
type Justification struct {
	ID                string              `json:"id"`
	PremiseFactRefs   []string            `json:"premise_fact_refs"`
	ConditionRefs     []string            `json:"condition_refs"`
	RuleID            string              `json:"rule_id"`
	CoverageBasis     string              `json:"coverage_basis"`
	ContradictionRefs []string            `json:"contradiction_refs"`
	Disposition       ProposedDisposition `json:"disposition"`
	Statement         string              `json:"statement"`
}

// HumanAction is the complete operator-facing contract: what the human
// must read, which (≤2) environment questions they may need to answer,
// and the only two responses available.
type HumanAction struct {
	Mode                    string   `json:"mode"`
	EnvironmentQuestionRefs []string `json:"environment_question_refs"`
	// EnvironmentQuestions carries the derived, case-specific
	// environment questions the residual deployment layer produces from
	// recorded statements (advisory-declared conditions, engaged
	// deployment conditions, a reached-subject anchor). Declared
	// variable questions stay in EnvironmentQuestionRefs — this list is
	// the actionable elaboration of the same ask, bounded the same way,
	// and omitted entirely when nothing recorded grounds a specific
	// question so legacy artifacts stay byte-identical.
	EnvironmentQuestions []string `json:"environment_questions,omitempty"`
	AllowedResponses     []string `json:"allowed_responses"`
	MandatoryFactRefs    []string `json:"mandatory_fact_refs"`
}

// FindingIdentity names the finding and the advisory it is bound to.
type FindingIdentity struct {
	ID         string `json:"id"`
	AdvisoryID string `json:"advisory_id"`
}

// TargetScope binds the artifact to the exact recorded build context.
type TargetScope struct {
	SnapshotContentHash string `json:"snapshot_content_hash"`
	CommitSHA           string `json:"commit_sha"`
	Scope               string `json:"scope"`
}

// AdvisoryBinding pins the advisory document and the exact
// advisory-declared subjects the decision covers.
type AdvisoryBinding struct {
	AdvisoryID     string   `json:"advisory_id"`
	AdvisoryDigest string   `json:"advisory_digest"`
	SubjectRefs    []string `json:"subject_refs"`
}

// ReplayAndPolicyPins records the exact prompt, policy and catalog bytes
// the artifact was produced under, so an accept/reject decision is
// replayable and bound to the configuration that gated it.
type ReplayAndPolicyPins struct {
	PromptDigest   string            `json:"prompt_digest"`
	PolicyDigest   string            `json:"policy_digest"`
	CatalogDigests map[string]string `json:"catalog_digests"`
}

// DecisionArtifact is the decision-artifact/1 contract: one complete
// proposed disposition, or a finite set of complete conditional branches
// over declared environment variables, plus everything a human needs to
// accept or reject it without opening the repository.
type DecisionArtifact struct {
	Schema              string              `json:"schema"`
	FindingIdentity     FindingIdentity     `json:"finding_identity"`
	TargetScope         TargetScope         `json:"target_scope"`
	AdvisoryBinding     AdvisoryBinding     `json:"advisory_binding"`
	SharedFacts         []Fact              `json:"shared_facts"`
	DecisionVariables   []DecisionVariable  `json:"decision_variables"`
	Branches            []DecisionBranch    `json:"branches"`
	ProposedDisposition ProposedDisposition `json:"proposed_disposition"`
	JustificationGraph  []Justification     `json:"justification_graph"`
	Contradictions      []Contradiction     `json:"contradictions"`
	HumanAction         HumanAction         `json:"human_action"`
	ReplayAndPolicyPins ReplayAndPolicyPins `json:"replay_and_policy_pins"`
}

// ValidateDecisionArtifact validates a standalone decision-artifact/1
// document (e.g. a sidecar file). Observation refs are shape-checked
// only; inside a research-report/3 they additionally resolve against
// the report's recorded observation space.
func ValidateDecisionArtifact(a *DecisionArtifact) error {
	e := &ValidationError{}
	validateDecisionArtifact(e, a, nil, nil)
	if len(e.Problems) > 0 {
		return e
	}
	return nil
}

// validateDecisionArtifact enforces the decision-artifact/1 contract.
// When refs and r are non-nil (embedded in a report) observation refs
// resolve against the recorded lane space and the identity/scope pins
// are cross-checked against the report's inputs. It never repairs.
func validateDecisionArtifact(e *ValidationError, a *DecisionArtifact, refs *refSpace, r *Report) {
	if a.Schema != DecisionArtifactSchemaV1 {
		e.add("decision_artifact.schema %q != %q", a.Schema, DecisionArtifactSchemaV1)
	}
	fi := &a.FindingIdentity
	if fi.ID == "" || fi.AdvisoryID == "" {
		e.add("decision_artifact.finding_identity id/advisory_id required")
	}
	if r != nil && fi.AdvisoryID != "" && r.Vulnerability.ID != "" && fi.AdvisoryID != r.Vulnerability.ID {
		e.add("decision_artifact.finding_identity.advisory_id %q does not match report advisory %q", fi.AdvisoryID, r.Vulnerability.ID)
	}
	ts := &a.TargetScope
	if !decisionHex64Re.MatchString(ts.SnapshotContentHash) {
		e.add("decision_artifact.target_scope.snapshot_content_hash must be 64-hex")
	}
	if r != nil && r.Input.Snapshot.ContentHash != "" && ts.SnapshotContentHash != r.Input.Snapshot.ContentHash {
		e.add("decision_artifact.target_scope.snapshot_content_hash does not match the report's recorded input snapshot hash")
	}
	if ts.CommitSHA == "" {
		e.add("decision_artifact.target_scope.commit_sha required")
	}
	if ts.Scope == "" {
		e.add("decision_artifact.target_scope.scope required")
	}
	ab := &a.AdvisoryBinding
	if ab.AdvisoryID == "" {
		e.add("decision_artifact.advisory_binding.advisory_id required")
	}
	if fi.AdvisoryID != "" && ab.AdvisoryID != "" && ab.AdvisoryID != fi.AdvisoryID {
		e.add("decision_artifact.advisory_binding.advisory_id %q does not match finding_identity", ab.AdvisoryID)
	}
	if !decisionHex64Re.MatchString(ab.AdvisoryDigest) {
		e.add("decision_artifact.advisory_binding.advisory_digest must be 64-hex")
	}
	if len(ab.SubjectRefs) == 0 {
		e.add("decision_artifact.advisory_binding.subject_refs required (the advisory-declared subject set)")
	}
	seenSubj := map[string]bool{}
	for _, s := range ab.SubjectRefs {
		if s == "" {
			e.add("decision_artifact.advisory_binding.subject_refs: empty entry")
			continue
		}
		if seenSubj[s] {
			e.add("decision_artifact.advisory_binding.subject_refs: %q listed twice", s)
		}
		seenSubj[s] = true
		if refs != nil && !refs.advSubjects[s] {
			e.add("decision_artifact.advisory_binding.subject_refs: %q is not an advisory-declared subject", s)
		}
	}

	// ---- shared facts: independent tool provenance only ----
	factByID := map[string]*Fact{}
	for i := range a.SharedFacts {
		f := &a.SharedFacts[i]
		where := fmt.Sprintf("decision_artifact.shared_facts[%s]", factIndexName(i, f.ID))
		if f.ID == "" || f.Proposition == "" || f.Subject == "" || f.Scope == "" {
			e.add("%s: id/proposition/subject/scope required", where)
		}
		if f.ID != "" {
			if factByID[f.ID] != nil {
				e.add("%s: duplicate fact id %q", where, f.ID)
			}
			factByID[f.ID] = f
		}
		if f.SourceTool == "" || f.ToolVersion == "" {
			e.add("%s: source_tool/tool_version required", where)
		}
		if nonIndependentProvenance[strings.ToLower(f.SourceTool)] {
			e.add("%s: source_tool %q is not independent tool provenance — an environment or human declaration is an EnvironmentAssertion, never a Fact", where, f.SourceTool)
		}
		if !decisionHex64Re.MatchString(f.DataDigest) {
			e.add("%s: data_digest must be 64-hex", where)
		}
		if len(f.ObservationRefs) == 0 {
			e.add("%s: observation_refs required — a fact without recorded observations is a bare assertion", where)
		}
		for _, ref := range f.ObservationRefs {
			if !decisionObsRefRe.MatchString(ref) {
				e.add("%s: observation_ref %q must have the obs:OBS-<n> shape", where, ref)
				continue
			}
			if refs != nil && !refs.obs[ref] {
				e.add("%s: observation_ref %q does not resolve to a recorded lane observation", where, ref)
			}
		}
		switch f.Coverage {
		case FactCoverageComplete, FactCoveragePartial, FactCoverageNotEvaluated:
		default:
			e.add("%s: coverage %q invalid", where, f.Coverage)
		}
		if f.TrustClass != "" && f.TrustClass != string(domain.ReleaseTrustAuthoritative) &&
			f.TrustClass != string(domain.ReleaseTrustSupporting) {
			e.add("%s: trust_class %q invalid (AUTHORITATIVE|SUPPORTING only)", where, f.TrustClass)
		}
		switch f.Status {
		case FactStatusVerified, FactStatusDegraded, FactStatusContradicted:
		default:
			e.add("%s: status %q invalid", where, f.Status)
		}
		if f.Freshness == "" {
			e.add("%s: freshness required", where)
		}
		for _, lim := range f.Limitations {
			if lim == "" {
				e.add("%s: empty limitation entry", where)
			}
		}
	}

	// ---- declared environment variables ----
	vars := map[string]*DecisionVariable{}
	for i := range a.DecisionVariables {
		v := &a.DecisionVariables[i]
		where := fmt.Sprintf("decision_artifact.decision_variables[%s]", factIndexName(i, v.ID))
		if v.ID == "" || v.Question == "" {
			e.add("%s: id/question required", where)
		}
		if v.ID != "" {
			if vars[v.ID] != nil {
				e.add("%s: duplicate variable id %q", where, v.ID)
			}
			vars[v.ID] = v
		}
		if len(v.AllowedValues) == 0 {
			e.add("%s: allowed_values required — a variable's answer set is finite and declared", where)
		}
		seenVal := map[string]bool{}
		for _, val := range v.AllowedValues {
			if val == "" {
				e.add("%s: empty allowed_values entry", where)
				continue
			}
			if seenVal[val] {
				e.add("%s: allowed value %q listed twice", where, val)
			}
			seenVal[val] = true
		}
		if df := v.DerivedFrom; df != nil {
			switch df.Field {
			case anchorFieldSummary, anchorFieldDescription, anchorFieldRawBody:
			default:
				e.add("%s: derived_from.field %q must name an advisory text field", where, df.Field)
			}
			if df.Quote == "" {
				e.add("%s: derived_from.quote is required when the member is present", where)
			}
		}
	}

	// ---- branches ----
	conditionIDs := map[string]bool{}
	holdUnknown := false
	requiredInputs := map[string]bool{}
	for i := range a.Branches {
		br := &a.Branches[i]
		where := fmt.Sprintf("decision_artifact.branches[%s]", factIndexName(i, br.ID))
		if br.ID == "" {
			e.add("%s: id required", where)
		}
		switch br.Status {
		case BranchComplete, BranchAwaitingInput, BranchContradicted, BranchNotDecisionReady:
		default:
			e.add("%s: status %q invalid", where, br.Status)
		}
		switch br.Coverage {
		case FactCoverageComplete, FactCoveragePartial, FactCoverageNotEvaluated:
		default:
			e.add("%s: coverage %q invalid", where, br.Coverage)
		}
		if !isProposedDisposition(br.ProposedDisposition) {
			e.add("%s: proposed_disposition %q is not an R6 disposition", where, br.ProposedDisposition)
		}
		if br.ProposedDisposition == DispositionHoldUnknown {
			holdUnknown = true
		}
		// Assignments bind only declared variables and their enumerated
		// values — no invented variable or value is admissible.
		for name, val := range br.Assignments {
			v := vars[name]
			if v == nil {
				e.add("%s: assignments.%s is not a declared decision variable", where, name)
				continue
			}
			ok := false
			for _, av := range v.AllowedValues {
				if av == val {
					ok = true
					break
				}
			}
			if !ok {
				e.add("%s: assignments.%s=%q is outside the variable's allowed_values", where, name, val)
			}
		}
		condSeen := map[string]bool{}
		for _, c := range br.Conditions {
			cwhere := fmt.Sprintf("%s.conditions[%s]", where, c.ID)
			if c.ID == "" || c.Statement == "" {
				e.add("%s: id/statement required", cwhere)
			}
			if c.ID != "" {
				if condSeen[c.ID] {
					e.add("%s: duplicate condition id %q", cwhere, c.ID)
				}
				condSeen[c.ID] = true
				conditionIDs[c.ID] = true
			}
			switch c.Role {
			case ConditionRoleApplicability, ConditionRolePath, ConditionRoleDeployment, ConditionRoleSupporting:
			default:
				e.add("%s: role %q invalid", cwhere, c.Role)
			}
			switch c.Polarity {
			case PolarityPositive, PolarityNegative:
			default:
				e.add("%s: polarity %q invalid", cwhere, c.Polarity)
			}
			for _, sr := range c.SubjectRefs {
				if sr == "" {
					e.add("%s: empty subject_refs entry", cwhere)
				}
			}
		}
		for _, fr := range br.FactRefs {
			if fr == "" || factByID[fr] == nil {
				e.add("%s: fact_ref %q does not resolve to a shared fact — branches carry only declared shared facts, never another branch's premises", where, fr)
			}
		}
		for _, req := range br.RequiredEnvironmentInputs {
			v := vars[req]
			if v == nil {
				e.add("%s: required_environment_input %q is not a declared decision variable", where, req)
				continue
			}
			if !v.Required {
				e.add("%s: required_environment_input %q refers to a non-required variable", where, req)
			}
			if _, assigned := br.Assignments[req]; assigned {
				e.add("%s: required_environment_input %q is already assigned in this branch", where, req)
			}
			requiredInputs[req] = true
		}
		for _, as := range br.EnvironmentAssertions {
			awhere := fmt.Sprintf("%s.environment_assertions[%s]", where, as.Variable)
			v := vars[as.Variable]
			if v == nil {
				e.add("%s: variable %q is not a declared decision variable", awhere, as.Variable)
			} else {
				ok := false
				for _, av := range v.AllowedValues {
					if av == as.Value {
						ok = true
						break
					}
				}
				if !ok {
					e.add("%s: value %q is outside the variable's allowed_values", awhere, as.Value)
				}
				// Branch isolation: an assertion may answer only a
				// variable this branch itself declares (assigned or
				// still required) and must agree with that assignment —
				// a branch can never borrow another branch's premise.
				if _, assigned := br.Assignments[as.Variable]; assigned {
					if br.Assignments[as.Variable] != as.Value {
						e.add("%s: value %q contradicts this branch's own assignment %q", awhere, as.Value, br.Assignments[as.Variable])
					}
				} else if !slices.Contains(br.RequiredEnvironmentInputs, as.Variable) {
					e.add("%s: variable %q is not declared by this branch — an assertion may only answer a branch's own declared premise", awhere, as.Variable)
				}
			}
			if as.Value == "" || as.Principal == "" || as.Timestamp == "" || as.Source == "" || as.Freshness == "" {
				e.add("%s: value/principal/timestamp/source/freshness required", awhere)
			}
			for _, sup := range as.Supersedes {
				if sup == "" {
					e.add("%s: empty supersedes entry", awhere)
				}
			}
		}
		// Status coherence: a COMPLETE branch has closed coverage; an
		// AWAITING_INPUT branch must name the inputs it waits on; a
		// CONTRADICTED branch falls back to hold/keep-open only.
		if br.Status == BranchComplete && br.Coverage != FactCoverageComplete {
			e.add("%s: status COMPLETE requires coverage=COMPLETE", where)
		}
		if br.Status == BranchAwaitingInput && len(br.RequiredEnvironmentInputs) == 0 {
			e.add("%s: status AWAITING_INPUT requires declared required_environment_inputs", where)
		}
		if br.Status == BranchContradicted &&
			br.ProposedDisposition != DispositionHoldUnknown &&
			br.ProposedDisposition != DispositionKeepOpenForRemediation {
			e.add("%s: a CONTRADICTED branch may propose only HOLD_UNKNOWN or KEEP_OPEN_FOR_REMEDIATION", where)
		}
		if isCloseDisposition(br.ProposedDisposition) {
			// A code-grounded close rests only on verified deterministic
			// premises: no environment questions, no recorded environment
			// assertions (declared trust is a mitigation premise, never a
			// falsifier), complete coverage, no open limitations.
			if br.Status != BranchComplete {
				e.add("%s: a %s branch must be COMPLETE", where, br.ProposedDisposition)
			}
			if br.Coverage != FactCoverageComplete {
				e.add("%s: a %s branch requires coverage=COMPLETE", where, br.ProposedDisposition)
			}
			if len(br.Limitations) > 0 {
				e.add("%s: a %s branch cannot carry unresolved limitations", where, br.ProposedDisposition)
			}
			if len(br.RequiredEnvironmentInputs) > 0 {
				e.add("%s: a %s branch cannot wait on environment answers", where, br.ProposedDisposition)
			}
			if len(br.EnvironmentAssertions) > 0 {
				e.add("%s: a %s branch cannot rest on environment assertions — declared trust may only premise ACCEPT_ENVIRONMENTAL_MITIGATION", where, br.ProposedDisposition)
			}
			for _, fr := range br.FactRefs {
				if f := factByID[fr]; f != nil && f.Status != FactStatusVerified {
					e.add("%s: a %s branch cites fact %q with status %q (only VERIFIED premises may close)", where, br.ProposedDisposition, fr, f.Status)
				}
			}
		}
		for _, lim := range br.Limitations {
			if lim == "" {
				e.add("%s: empty limitation entry", where)
			}
		}
	}
	// A branch set always includes the explicit unknown fallback.
	if (len(a.Branches) > 0 || len(a.DecisionVariables) > 0) && !holdUnknown {
		e.add("decision_artifact.branches: a branch set must include an explicit unknown branch (proposed_disposition=HOLD_UNKNOWN)")
	}
	// The artifact-level proposal is either a member of the branch set
	// (when branches exist) or the HOLD_UNKNOWN aggregate fallback.
	if !isProposedDisposition(a.ProposedDisposition) {
		e.add("decision_artifact.proposed_disposition %q is not an R6 disposition", a.ProposedDisposition)
	} else if len(a.Branches) > 0 && a.ProposedDisposition != DispositionHoldUnknown {
		echoed := false
		for _, br := range a.Branches {
			if br.ProposedDisposition == a.ProposedDisposition {
				echoed = true
				break
			}
		}
		if !echoed {
			e.add("decision_artifact.proposed_disposition %q is not proposed by any branch and is not the HOLD_UNKNOWN fallback", a.ProposedDisposition)
		}
	}

	// ---- contradictions (validated before the justification graph so
	// refs resolve against declared ids) ----
	cIDs := map[string]bool{}
	for i := range a.Contradictions {
		c := &a.Contradictions[i]
		where := fmt.Sprintf("decision_artifact.contradictions[%s]", factIndexName(i, c.ID))
		if c.ID == "" || c.Kind == "" || c.Subject == "" || c.Summary == "" {
			e.add("%s: id/kind/subject/summary required", where)
		}
		if c.ID != "" {
			if cIDs[c.ID] {
				e.add("%s: duplicate contradiction id %q", where, c.ID)
			}
			cIDs[c.ID] = true
		}
		switch c.Resolution {
		case ResolutionDeterministicPrevails, ResolutionScopeLimits, ResolutionUnresolved:
		default:
			e.add("%s: resolution %q invalid", where, c.Resolution)
		}
	}

	// ---- justification graph ----
	jIDs := map[string]bool{}
	for _, j := range a.JustificationGraph {
		where := fmt.Sprintf("decision_artifact.justification_graph[%s]", j.ID)
		if j.ID == "" || j.RuleID == "" || j.Statement == "" || j.CoverageBasis == "" {
			e.add("%s: id/rule_id/statement/coverage_basis required", where)
		}
		if j.ID != "" {
			if jIDs[j.ID] {
				e.add("%s: duplicate justification id %q", where, j.ID)
			}
			jIDs[j.ID] = true
		}
		if !isProposedDisposition(j.Disposition) {
			e.add("%s: disposition %q is not an R6 disposition", where, j.Disposition)
		}
		if len(j.PremiseFactRefs) == 0 && len(j.ConditionRefs) == 0 {
			e.add("%s: a justification requires at least one premise fact or condition ref", where)
		}
		for _, fr := range j.PremiseFactRefs {
			if fr == "" || factByID[fr] == nil {
				e.add("%s: premise_fact_ref %q does not resolve to a shared fact", where, fr)
			}
		}
		for _, cr := range j.ConditionRefs {
			if cr == "" || !conditionIDs[cr] {
				e.add("%s: condition_ref %q does not resolve to a declared branch condition", where, cr)
			}
		}
		for _, cr := range j.ContradictionRefs {
			if cr == "" || !cIDs[cr] {
				e.add("%s: contradiction_ref %q does not resolve to a declared contradiction", where, cr)
			}
		}
		if isCloseDisposition(j.Disposition) {
			// Code-grounded closure fails closed: verified premises only
			// and no cited contradiction may underwrite it.
			if len(j.ContradictionRefs) > 0 {
				e.add("%s: a %s justification cannot cite contradictions", where, j.Disposition)
			}
			verified := 0
			for _, fr := range j.PremiseFactRefs {
				if f := factByID[fr]; f != nil && f.Status == FactStatusVerified {
					verified++
				}
			}
			if verified == 0 {
				e.add("%s: a %s justification requires at least one VERIFIED premise fact — degraded or unverified premises never close", where, j.Disposition)
			}
		}
	}
	// Every CLOSE_* proposal — artifact-level or per-branch — must be
	// backed by an explicit justification edge.
	needJust := map[ProposedDisposition]bool{}
	if isCloseDisposition(a.ProposedDisposition) {
		needJust[a.ProposedDisposition] = true
	}
	for _, br := range a.Branches {
		if isCloseDisposition(br.ProposedDisposition) {
			needJust[br.ProposedDisposition] = true
		}
	}
	for d := range needJust {
		backed := false
		for _, j := range a.JustificationGraph {
			if j.Disposition == d {
				backed = true
				break
			}
		}
		if !backed {
			e.add("decision_artifact: %s is proposed but no justification edge backs it", d)
		}
	}

	// ---- human-facing contract ----
	ha := &a.HumanAction
	switch ha.Mode {
	case HumanActionAcceptReject:
		if len(ha.EnvironmentQuestionRefs) > 0 {
			e.add("decision_artifact.human_action: mode ACCEPT_REJECT cannot carry environment questions")
		}
	case HumanActionAnswerThenAcceptReject:
		if len(ha.EnvironmentQuestionRefs) == 0 {
			e.add("decision_artifact.human_action: mode ANSWER_THEN_ACCEPT_REJECT requires at least one environment question")
		}
	default:
		e.add("decision_artifact.human_action.mode %q invalid", ha.Mode)
	}
	if len(ha.EnvironmentQuestionRefs) > MaxEnvironmentQuestions {
		e.add("decision_artifact.human_action: %d environment question refs exceed the R6 bound of %d — the artifact is NOT_DECISION_READY material, not a decision", len(ha.EnvironmentQuestionRefs), MaxEnvironmentQuestions)
	}
	if len(ha.EnvironmentQuestions) > MaxEnvironmentQuestions {
		e.add("decision_artifact.human_action: %d derived environment questions exceed the R6 bound of %d", len(ha.EnvironmentQuestions), MaxEnvironmentQuestions)
	}
	for _, qs := range ha.EnvironmentQuestions {
		if strings.TrimSpace(qs) == "" {
			e.add("decision_artifact.human_action: derived environment questions must be non-empty recorded statements")
		}
	}
	seenQ := map[string]bool{}
	for _, q := range ha.EnvironmentQuestionRefs {
		v := vars[q]
		if v == nil {
			e.add("decision_artifact.human_action: environment_question_ref %q is not a declared decision variable", q)
			continue
		}
		if !v.Required {
			e.add("decision_artifact.human_action: environment_question_ref %q refers to a non-required variable", q)
		}
		if seenQ[q] {
			e.add("decision_artifact.human_action: environment question %q listed twice", q)
		}
		seenQ[q] = true
	}
	// Every input a branch still needs must be reachable through the
	// declared question set — the human is never asked to interpret the
	// environment freely.
	for req := range requiredInputs {
		if !seenQ[req] {
			e.add("decision_artifact.human_action: required environment input %q is not covered by environment_question_refs", req)
		}
	}
	if len(ha.AllowedResponses) != 2 ||
		!slices.Contains(ha.AllowedResponses, HumanResponseAccept) ||
		!slices.Contains(ha.AllowedResponses, HumanResponseReject) {
		e.add("decision_artifact.human_action.allowed_responses must be exactly [Accept Reject], got %v", ha.AllowedResponses)
	}
	if len(ha.MandatoryFactRefs) > MaxMandatoryFacts {
		e.add("decision_artifact.human_action: %d mandatory fact refs exceed the R6 bound of %d — the artifact is NOT_DECISION_READY material, not a decision", len(ha.MandatoryFactRefs), MaxMandatoryFacts)
	}
	seenMF := map[string]bool{}
	for _, fr := range ha.MandatoryFactRefs {
		if fr == "" || factByID[fr] == nil {
			e.add("decision_artifact.human_action: mandatory_fact_ref %q does not resolve to a shared fact", fr)
			continue
		}
		if seenMF[fr] {
			e.add("decision_artifact.human_action: mandatory fact %q listed twice", fr)
		}
		seenMF[fr] = true
	}

	// ---- replay/policy pins ----
	rp := &a.ReplayAndPolicyPins
	if !decisionHex64Re.MatchString(rp.PromptDigest) {
		e.add("decision_artifact.replay_and_policy_pins.prompt_digest must be 64-hex")
	}
	if !decisionHex64Re.MatchString(rp.PolicyDigest) {
		e.add("decision_artifact.replay_and_policy_pins.policy_digest must be 64-hex")
	}
	for _, cat := range []string{"conditions", "checks", "dispositions"} {
		if _, ok := rp.CatalogDigests[cat]; !ok {
			e.add("decision_artifact.replay_and_policy_pins.catalog_digests is missing the %q catalog pin", cat)
		}
	}
	for name, dg := range rp.CatalogDigests {
		if !decisionHex64Re.MatchString(dg) {
			e.add("decision_artifact.replay_and_policy_pins.catalog_digests[%q] must be 64-hex", name)
		}
	}
}

func factIndexName(i int, id string) string {
	if id != "" {
		return id
	}
	return fmt.Sprintf("%d", i)
}

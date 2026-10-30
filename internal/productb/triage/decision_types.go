package triage

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// DecisionPackageSchemaVersion is the only decision package schema the live
// pipeline emits or admits. The package carries four structurally separate
// axes — the model judgment, the proposed human action, the derived support
// and the machine disposition — so no consumer can read one as another.
// decision-package.v2 is history: its offline readers keep their own
// explicitly historical DTOs and never re-admit the artifact.
const DecisionPackageSchemaVersion = "decision-package.v4"

// Technical readiness statuses. NEEDS_ARBITRATION marks a package where the
// machine rules and the model judgment disagree: the machine disposition is
// withheld, the human proposal stands unchanged. It is a machine-readiness
// label, never a request that replaces the proposed action.
const (
	TechStatusReady            = "READY"
	TechStatusReadyWithLimits  = "READY_WITH_LIMITATIONS"
	TechStatusNeedsArbitration = "NEEDS_ARBITRATION"
)

// Arbitration outcomes of the machine safeguard.
const (
	ArbitrationAgreeDismiss = "AGREE_DISMISS"
	ArbitrationAgreeLower   = "AGREE_LOWER"
	ArbitrationAgreeKeep    = "AGREE_KEEP"
	ArbitrationDivergeHuman = "DIVERGE_HUMAN"
)

type Recommendation string

const (
	RecommendationDismissed Recommendation = "DISMISSED"
	RecommendationLowered   Recommendation = "LOWERED"
	RecommendationUnchanged Recommendation = "UNCHANGED"
)

func (r Recommendation) Valid() bool {
	return r == RecommendationDismissed || r == RecommendationLowered || r == RecommendationUnchanged
}
func (r *Recommendation) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	x := Recommendation(s)
	if !x.Valid() {
		return fmt.Errorf("invalid recommendation %q", s)
	}
	*r = x
	return nil
}

type Predicate struct {
	Op    string      `json:"op"`
	Left  any         `json:"left,omitempty"`
	Right any         `json:"right,omitempty"`
	Args  []Predicate `json:"args,omitempty"`
	Path  string      `json:"path,omitempty"`
}

func (p Predicate) Valid() bool {
	switch p.Op {
	case "eq", "neq", "in", "not_in", "hash_matches":
		return p.Left != nil && p.Right != nil
	case "exists", "missing", "changed":
		return p.Path != "" || p.Left != nil
	case "all", "any":
		return len(p.Args) > 0 && predicatesValid(p.Args)
	case "not":
		return len(p.Args) == 1 && p.Args[0].Valid()
	default:
		return false
	}
}
func predicatesValid(args []Predicate) bool {
	for _, p := range args {
		if !p.Valid() {
			return false
		}
	}
	return true
}

type ConditionStatus string

const (
	ConditionSatisfied   ConditionStatus = "SATISFIED"
	ConditionUnsatisfied ConditionStatus = "UNSATISFIED"
	ConditionUnknown     ConditionStatus = "UNKNOWN"
)

func (s ConditionStatus) Valid() bool {
	return s == ConditionSatisfied || s == ConditionUnsatisfied || s == ConditionUnknown
}
func (s *ConditionStatus) UnmarshalJSON(b []byte) error {
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	x := ConditionStatus(v)
	if !x.Valid() {
		return fmt.Errorf("invalid condition status %q", v)
	}
	*s = x
	return nil
}

type Condition struct {
	ID         string          `json:"id"`
	Predicate  Predicate       `json:"predicate"`
	Status     ConditionStatus `json:"status"`
	Scope      string          `json:"scope"`
	Provenance []string        `json:"provenance,omitempty"`
	Effect     string          `json:"effect"`
}

// Baseline is the authoritative severity metadata the machine disposition
// started from. It is optional: a ticket or finding without a severity
// still yields a complete human package, and no severity, priority or
// disposition is ever synthesized to fill it in.
type Baseline struct {
	Severity    string         `json:"severity"`
	Priority    string         `json:"priority"`
	Disposition Recommendation `json:"disposition"`
	Source      string         `json:"source"`
}

// LLMJudgment is the model's own conclusion, preserved verbatim. It is an
// opinion of the investigation: it never becomes a machine recommendation,
// a Product A verdict or a VEX status.
type LLMJudgment struct {
	Verdict   Verdict `json:"verdict"`
	Summary   string  `json:"summary,omitempty"`
	Mechanism string  `json:"mechanism,omitempty"`
}

// TechnicalAssessment carries the run's machine readiness diagnostics and
// nothing else: no judgment, no arbitration, no support level, no demotion
// record and no internal verdict — those live on their own axes.
type TechnicalAssessment struct {
	Status          string   `json:"status"`
	FactValidation  string   `json:"fact_validation"`
	Limitations     []string `json:"limitations,omitempty"`
	BudgetResult    string   `json:"budget_result,omitempty"`
	StabilityResult string   `json:"stability_result,omitempty"`
}
type ProfileApplication struct {
	ID            string    `json:"id"`
	DisplayName   string    `json:"display_name,omitempty"`
	Applicability Condition `json:"applicability"`
}
type Rationale struct {
	Summary   string   `json:"summary"`
	Reasoning []string `json:"reasoning,omitempty"`
	Basis     []string `json:"basis,omitempty"`
}
type DecisionFact struct {
	ID           string   `json:"id"`
	Kind         string   `json:"kind"`
	Status       string   `json:"status"`
	Subject      string   `json:"subject"`
	Scope        string   `json:"scope"`
	Provenance   []string `json:"provenance,omitempty"`
	EvidenceRefs []string `json:"evidence_refs,omitempty"`
}
type Trigger struct {
	ID     string          `json:"id"`
	When   Predicate       `json:"when"`
	Effect string          `json:"effect"`
	State  ConditionStatus `json:"state"`
}
type ConditionalProfile struct {
	Profile             string         `json:"profile"`
	Applicability       Condition      `json:"applicability"`
	ExpectedDisposition Recommendation `json:"expected_disposition"`
}

// MachineDisposition is everything the deterministic layer establishes on
// its own: the recommendation the rules, checks and admitted proofs permit,
// the baseline it started from, the selected profile, the demotion record
// and the machine-only policy outcome. A human action or a support level is
// never an input to any of it.
type MachineDisposition struct {
	Recommendation       Recommendation       `json:"recommendation"`
	Baseline             *Baseline            `json:"baseline,omitempty"`
	RecommendedProfile   ProfileApplication   `json:"recommended_profile"`
	Rationale            Rationale            `json:"rationale"`
	ResidualAssumptions  []Condition          `json:"residual_assumptions,omitempty"`
	ReassessmentTriggers []Trigger            `json:"reassessment_triggers,omitempty"`
	ConditionalProfiles  []ConditionalProfile `json:"conditional_profiles,omitempty"`
	Demotions            []string             `json:"demotions,omitempty"`
	Arbitration          string               `json:"arbitration,omitempty"`
	Automation           AutomationStatus     `json:"automation"`
}

type DecisionAudit struct {
	TicketHash     string           `json:"ticket_hash"`
	ConfigHash     string           `json:"config_hash"`
	SelectedRef    string           `json:"selected_ref"`
	ResolvedCommit string           `json:"resolved_commit"`
	SnapshotHash   string           `json:"snapshot_hash"`
	AdvisorySource string           `json:"advisory_source"`
	AdvisoryHash   string           `json:"advisory_hash"`
	Toolchain      ToolchainAudit   `json:"toolchain"`
	RulesetHash    string           `json:"ruleset_hash"`
	FalsifierHash  string           `json:"falsifier_hash,omitempty"`
	PromptHash     string           `json:"prompt_hash"`
	Limits         BudgetConfig     `json:"limits"`
	Stage0         Stage0Provenance `json:"stage0_provenance,omitempty"`
}
type Stage0Provenance struct {
	InputHash    string `json:"input_hash,omitempty"`
	ProposalHash string `json:"proposal_hash,omitempty"`
	SourceID     string `json:"source_id,omitempty"`
	SourceHash   string `json:"source_hash,omitempty"`
	Ref          string `json:"ref,omitempty"`
	Commit       string `json:"commit,omitempty"`
	SnapshotHash string `json:"snapshot_hash,omitempty"`
	AdvisoryHash string `json:"advisory_hash,omitempty"`
}

// DecisionPackage is decision.json: one run's complete human result. The
// four result axes are separate top-level values on purpose — Judgment is
// the model's opinion, ProposedAction is what a person is asked to do,
// Support is the deterministic reading of that action's grounds, and
// MachineDisposition is the only machine-authoritative reduction.
type DecisionPackage struct {
	SchemaVersion       string              `json:"schema_version"`
	RunID               string              `json:"run_id"`
	FindingID           string              `json:"finding_id"`
	ExecutionMode       string              `json:"execution_mode"`
	Scope               DecisionScope       `json:"scope"`
	Judgment            LLMJudgment         `json:"judgment"`
	ProposedAction      HumanAction         `json:"proposed_action"`
	Premises            []DecisionPremise   `json:"premises"`
	Counterarguments    []Counterargument   `json:"counterarguments,omitempty"`
	Unknowns            []Unknown           `json:"unknowns,omitempty"`
	Support             DecisionSupport     `json:"support"`
	HumanReviewPlan *HumanReviewPlan `json:"human_review_plan,omitempty"`
	TechnicalAssessment TechnicalAssessment `json:"technical_assessment"`
	MachineDisposition  MachineDisposition  `json:"machine_disposition"`
	Facts               []DecisionFact      `json:"facts"`
	FalsifierProofs     []FalsifierProof    `json:"falsifier_proofs,omitempty"`
	Audit               DecisionAudit       `json:"audit"`
}

// UnmarshalJSON strictly rejects unknown fields at every level.
func (p *DecisionPackage) UnmarshalJSON(data []byte) error {
	type plain DecisionPackage
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var x plain
	if err := dec.Decode(&x); err != nil {
		return err
	}
	*p = DecisionPackage(x)
	return nil
}

func (p DecisionPackage) Validate() error {
	return p.validateSchema(DecisionPackageSchemaVersion)
}

// validateSchema is only for version-specific replay; Validate admits only live schema.
func (p DecisionPackage) validateSchema(version string) error {
	if p.SchemaVersion != version {
		return fmt.Errorf("invalid schema_version %q", p.SchemaVersion)
	}
	if p.RunID == "" || p.FindingID == "" || p.ExecutionMode == "" {
		return fmt.Errorf("run_id, finding_id and execution_mode are required")
	}
	if !p.Judgment.Verdict.Valid() {
		return fmt.Errorf("invalid judgment verdict %q", p.Judgment.Verdict)
	}
	if err := validateActionFields(p.ProposedAction); err != nil {
		return err
	}
	if err := validateDecisionScope(p.Scope); err != nil {
		return fmt.Errorf("scope: %w", err)
	}
	premises := make(map[string]bool, len(p.Premises))
	for i, pr := range p.Premises {
		if pr.ClaimID == "" || pr.Statement == "" || !pr.Basis.Valid() ||
			pr.Subject == "" || pr.Scope == "" {
			return fmt.Errorf("premises[%d]: incomplete premise %q", i, pr.ClaimID)
		}
		if premises[pr.ClaimID] {
			return fmt.Errorf("premises[%d]: duplicate claim id %q", i, pr.ClaimID)
		}
		premises[pr.ClaimID] = true
	}
	if len(p.Premises) == 0 {
		return fmt.Errorf("premises: the proposed action carries no derived decisive premise")
	}
	for _, id := range p.ProposedAction.DecisiveClaimIDs {
		if !premises[id] {
			return fmt.Errorf("proposed_action cites decisive claim %q that the premise set does not carry", id)
		}
	}
	for i, pr := range p.Premises {
		for _, dep := range pr.DependsOn {
			if !premises[dep] {
				return fmt.Errorf("premises[%d]: dependency %q is outside the derived premise closure", i, dep)
			}
		}
	}
	if !p.Support.Level.Valid() {
		return fmt.Errorf("invalid support level %q", p.Support.Level)
	}
	if !sameStringSet(p.Support.DecisiveClaimIDs, p.Premises) {
		return fmt.Errorf("support decisive claim set does not match the derived premise set")
	}
	proofIDs := make(map[string]bool, len(p.FalsifierProofs))
	for _, pr := range p.FalsifierProofs {
		proofIDs[pr.ID] = true
	}
	for _, id := range p.Support.ProofIDs {
		if !proofIDs[id] {
			return fmt.Errorf("support cites proof %q the package does not carry", id)
		}
	}
	if p.Support.Level == SupportLevelProvedWithinScope && len(p.Support.ProofIDs) == 0 {
		return fmt.Errorf("support level %s requires an admitted proof", p.Support.Level)
	}
	if !FactValidationStatus(p.TechnicalAssessment.FactValidation).Valid() {
		return fmt.Errorf("invalid fact_validation %q", p.TechnicalAssessment.FactValidation)
	}
	if err := validateMachineDisposition(p.MachineDisposition); err != nil {
		return fmt.Errorf("machine_disposition: %w", err)
	}
	if err := validateFalsifierProofs(p); err != nil {
		return err
	}
	if version == DecisionPackageSchemaVersion && p.HumanReviewPlan == nil {
		return fmt.Errorf("human_review_plan is required for %s", version)
	}
	if p.HumanReviewPlan != nil {
		if err := validateHumanReviewPlan(*p.HumanReviewPlan); err != nil {
			return fmt.Errorf("human_review_plan: %w", err)
		}
		if p.HumanReviewPlan.Readiness == string(HumanBranchNotDecisionReady) && p.ProposedAction.Kind != HumanActionKeepOpen {
			return fmt.Errorf("not-decision-ready human review plan requires a conservative KEEP_OPEN base action")
		}
		if len(p.HumanReviewPlan.Variables) > 0 && (p.ProposedAction.Kind == HumanActionClose || p.ProposedAction.Kind == HumanActionLowerPriority || p.ProposedAction.Kind == HumanActionAcceptEnvironmentalMitigation) {
			return fmt.Errorf("unselected human review plan cannot carry a reducing base action")
		}
		for _, branch := range p.HumanReviewPlan.Branches {
			for _, id := range branch.Support.ProofIDs { if !proofIDs[id] { return fmt.Errorf("human branch cites proof %q the package does not carry", id) } }
		}
	}
	return nil
}

// validateDecisionScope checks the recorded scope: the boundary marker is
// closed, and a record reference always carries the digest of the frozen
// document — a record identity without a digest is invented, not recorded.
func validateDecisionScope(s DecisionScope) error {
	switch s.Boundary {
	case DecisionBoundaryExactRecords, DecisionBoundaryInputMaterialOnly:
	default:
		return fmt.Errorf("invalid boundary %q", s.Boundary)
	}
	for i, r := range s.Records {
		if r.ID == "" || r.SHA256 == "" {
			return fmt.Errorf("records[%d]: id and sha256 are required", i)
		}
	}
	return nil
}

// validateMachineDisposition checks the machine axis independently of every
// human field: the recommendation, the optional baseline, the selected
// profile, the machine conditions and the derived policy outcome.
func validateMachineDisposition(m MachineDisposition) error {
	if !m.Recommendation.Valid() {
		return fmt.Errorf("invalid recommendation %q", m.Recommendation)
	}
	if m.Baseline != nil {
		if err := m.Baseline.validate(); err != nil {
			return err
		}
	}
	if m.RecommendedProfile.ID == "" {
		return fmt.Errorf("recommended_profile id is required")
	}
	if err := validateCondition(m.RecommendedProfile.Applicability); err != nil {
		return fmt.Errorf("recommended_profile: %w", err)
	}
	for i, c := range m.ResidualAssumptions {
		if err := validateCondition(c); err != nil {
			return fmt.Errorf("residual_assumptions[%d]: %w", i, err)
		}
	}
	for i, t := range m.ReassessmentTriggers {
		if t.ID == "" || t.When.Op == "" || t.Effect == "" || !t.State.Valid() {
			return fmt.Errorf("reassessment_triggers[%d]: invalid trigger", i)
		}
	}
	for i, c := range m.ConditionalProfiles {
		if c.Profile == "" || !c.ExpectedDisposition.Valid() {
			return fmt.Errorf("conditional_profiles[%d]: invalid profile", i)
		}
		if err := validateCondition(c.Applicability); err != nil {
			return fmt.Errorf("conditional_profiles[%d]: %w", i, err)
		}
		if c.ExpectedDisposition == m.Recommendation {
			return fmt.Errorf("conditional_profiles[%d]: profile does not change recommendation", i)
		}
	}
	switch m.Arbitration {
	case "", ArbitrationAgreeDismiss, ArbitrationAgreeLower, ArbitrationAgreeKeep, ArbitrationDivergeHuman:
	default:
		return fmt.Errorf("invalid arbitration %q", m.Arbitration)
	}
	if !m.Automation.Valid() {
		return fmt.Errorf("invalid automation %q", m.Automation)
	}
	return nil
}

// validateFalsifierProofs enforces the decision-package.v3 proof contract:
// proofs travel with the package, so a malformed, non-checker or
// scope-incomplete proof is a package defect — never a silent omission.
func validateFalsifierProofs(p DecisionPackage) error {
	if len(p.FalsifierProofs) == 0 {
		if p.Audit.FalsifierHash != "" {
			return fmt.Errorf("falsifier_hash is set but the package carries no falsifier proofs")
		}
		return nil
	}
	if p.Audit.FalsifierHash == "" {
		return fmt.Errorf("falsifier proofs require the report hash in the audit block")
	}
	for i, pr := range p.FalsifierProofs {
		// A checker-minted proof is the one shape that carries no proposal
		// and no agent claim: its authority is the deterministic checker's
		// own observation, identified by its rule. Every other proof must
		// name the proposal and claim the verifier answered.
		if pr.ID == "" || pr.ConditionID == "" ||
			(!CheckerMintedProof(pr) && (pr.ProposalID == "" || pr.ClaimID == "")) {
			return fmt.Errorf("falsifier_proofs[%d]: identity is incomplete", i)
		}
		if !pr.Kind.Valid() {
			return fmt.Errorf("falsifier_proofs[%d]: invalid kind %q", i, pr.Kind)
		}
		switch pr.Status {
		case FalsifierVerified, FalsifierUnknown, FalsifierInsufficientScope, FalsifierContradicted:
		default:
			return fmt.Errorf("falsifier_proofs[%d]: invalid status %q", i, pr.Status)
		}
		switch pr.Basis {
		case BasisCheckerVerified, BasisLLMProposed, BasisUnsupported:
		default:
			return fmt.Errorf("falsifier_proofs[%d]: invalid basis %q", i, pr.Basis)
		}
		if pr.Status == FalsifierVerified {
			if pr.Basis != BasisCheckerVerified {
				return fmt.Errorf("falsifier_proofs[%d]: VERIFIED requires the checker basis", i)
			}
			if !pr.Mandatory {
				return fmt.Errorf("falsifier_proofs[%d]: VERIFIED requires a mandatory condition", i)
			}
			if pr.Coverage.Completeness != "COMPLETE" {
				return fmt.Errorf("falsifier_proofs[%d]: VERIFIED requires complete coverage", i)
			}
			if !sameSubjects(pr.Coverage.ExpectedSubjects, pr.Coverage.CheckedSubjects) {
				return fmt.Errorf("falsifier_proofs[%d]: VERIFIED requires the full checked subject set", i)
			}
			if pr.Coverage.SnapshotHash == "" || pr.Coverage.BuildContextHash == "" || len(pr.EvidenceRefs) == 0 {
				return fmt.Errorf("falsifier_proofs[%d]: VERIFIED requires snapshot, build context and evidence", i)
			}
			if validate, ok := capabilityCoverageValidators[pr.Kind]; ok {
				if err := validate(pr.Coverage); err != nil {
					return fmt.Errorf("falsifier_proofs[%d]: non-admitting %s coverage: %v", i, pr.Kind, err)
				}
			}
		}
		for j, tr := range pr.History {
			if tr.From == "" || tr.To != pr.Status {
				return fmt.Errorf("falsifier_proofs[%d].history[%d]: invalid transition", i, j)
			}
		}
	}
	return nil
}

func (b Baseline) validate() error {
	if b.Severity == "" || b.Priority == "" || b.Source == "" || !b.Disposition.Valid() {
		return fmt.Errorf("invalid baseline")
	}
	return nil
}
func validateCondition(c Condition) error {
	if c.ID == "" || !c.Predicate.Valid() || !c.Status.Valid() || c.Scope == "" || c.Effect == "" {
		return fmt.Errorf("invalid condition")
	}
	return nil
}

// sameStringSet reports whether the id set and the premise claim set are
// the same names — the support axis must describe exactly the premise
// closure the package carries.
func sameStringSet(ids []string, premises []DecisionPremise) bool {
	set := make(map[string]bool, len(ids))
	for _, id := range ids {
		if set[id] {
			return false
		}
		set[id] = true
	}
	if len(set) != len(premises) {
		return false
	}
	for _, pr := range premises {
		if !set[pr.ClaimID] {
			return false
		}
	}
	return true
}

// ValidateDecisionPackageJSON strictly decodes and validates a package.
func ValidateDecisionPackageJSON(data []byte) (DecisionPackage, error) {
	var p DecisionPackage
	if err := json.Unmarshal(data, &p); err != nil {
		return p, err
	}
	return p, p.Validate()
}

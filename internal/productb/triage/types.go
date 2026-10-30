package triage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	domain "github.com/fedorovmv/izyan/internal/productb/domain"
)

// FindingSchemaVersion is the only accepted schema for parsed findings.
const FindingSchemaVersion = "finding.v1"

// AssessmentSchemaVersion is the only agent response schema live ingress
// accepts. assessment.v1 is history: offline readers may still parse old
// records, but the live decoder never re-admits them.
const AssessmentSchemaVersion = "assessment.v3"

// Verdict is the agent's semantic triage verdict. The legacy analyzer
// verdicts NOT_AFFECTED and NO_EXPLOIT_PATH_FOUND are deliberately not
// members: decoding rejects them, so a triage result can never be read as
// an authoritative verdict of the deterministic analyzer.
type Verdict string

const (
	VerdictExploitable    Verdict = "EXPLOITABLE"
	VerdictNotExploitable Verdict = "NOT_EXPLOITABLE"
	VerdictInconclusive   Verdict = "INCONCLUSIVE"
)

func (v Verdict) Valid() bool {
	switch v {
	case VerdictExploitable, VerdictNotExploitable, VerdictInconclusive:
		return true
	}
	return false
}

func (v *Verdict) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	candidate := Verdict(s)
	if !candidate.Valid() {
		return fmt.Errorf("invalid verdict %q", s)
	}
	*v = candidate
	return nil
}

type FactStatus string

const (
	FactValid        FactStatus = "VALID"
	FactUnavailable  FactStatus = "UNAVAILABLE"
	FactUnreferenced FactStatus = "UNREFERENCED"
	FactInvalid      FactStatus = "INVALID"
	FactConflicting  FactStatus = "CONFLICTING"
)

func (s FactStatus) Valid() bool {
	switch s {
	case FactValid, FactUnavailable, FactUnreferenced, FactInvalid, FactConflicting:
		return true
	}
	return false
}

func (s *FactStatus) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	candidate := FactStatus(raw)
	if !candidate.Valid() {
		return fmt.Errorf("invalid fact status %q", raw)
	}
	*s = candidate
	return nil
}

type FactValidationStatus string

const (
	ValidationComplete FactValidationStatus = "COMPLETE"
	ValidationPartial  FactValidationStatus = "PARTIAL"
	ValidationFailed   FactValidationStatus = "FAILED"
)

func (s FactValidationStatus) Valid() bool {
	switch s {
	case ValidationComplete, ValidationPartial, ValidationFailed:
		return true
	}
	return false
}

func (s *FactValidationStatus) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	candidate := FactValidationStatus(raw)
	if !candidate.Valid() {
		return fmt.Errorf("invalid fact validation status %q", raw)
	}
	*s = candidate
	return nil
}

// AutomationStatus is the machine policy outcome attached to a decision
// package's machine disposition (EvaluateMachineAutomation). It describes
// what may be automated from the machine result alone: ALLOW only for an
// admitted machine reduction, WARN when the package is valid but the
// machine disposition establishes no reduction, BLOCK when a machine
// prerequisite is invalid or failed. It is never supplied by the agent,
// never derived from the human action, the human support level or a human
// acceptance, and never a second semantic verdict.
type AutomationStatus string

const (
	AutomationAllow AutomationStatus = "ALLOW"
	AutomationWarn  AutomationStatus = "WARN"
	AutomationBlock AutomationStatus = "BLOCK"
)

func (s AutomationStatus) Valid() bool {
	switch s {
	case AutomationAllow, AutomationWarn, AutomationBlock:
		return true
	}
	return false
}

func (s *AutomationStatus) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	candidate := AutomationStatus(raw)
	if !candidate.Valid() {
		return fmt.Errorf("invalid automation status %q", raw)
	}
	*s = candidate
	return nil
}

// FalsifierKind names the deterministic check a falsifier proposal asks the
// verifier to run. The set is closed: decoding rejects any other value so a
// proposal can never smuggle in a check the verifier does not know.
type FalsifierKind string

const (
	FalsifierCodeAbsent          FalsifierKind = "code_absent"
	FalsifierLocusPackageAbsent  FalsifierKind = "locus_package_absent"
	FalsifierLocusFunctionAbsent FalsifierKind = "locus_function_unreached"
)

func (k FalsifierKind) Valid() bool {
	switch k {
	case FalsifierCodeAbsent, FalsifierLocusPackageAbsent, FalsifierLocusFunctionAbsent:
		return true
	}
	return false
}

func (k *FalsifierKind) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	candidate := FalsifierKind(raw)
	if !candidate.Valid() {
		return fmt.Errorf("invalid falsifier kind %q", raw)
	}
	*k = candidate
	return nil
}

// FalsifierSubject is one package/symbol pair a proposal asks the
// deterministic verifier to check. Role is free-form context for the
// verifier (e.g. "mandatory-control") and carries no semantic force on its
// own.
type FalsifierSubject struct {
	Package string `json:"package"`
	Symbol  string `json:"symbol"`
	Role    string `json:"role,omitempty"`
}

// FalsifierProposal is the agent's structured request for a deterministic
// falsifier check, bound to an existing claim and a mandatory condition.
// It is proposal-only ingress: the agent describes what to verify, never
// the outcome — fields reserved for the deterministic verifier or decision
// layer (status, verified, mandatory, coverage, negative_verification,
// recommendation, verdict) are rejected outright, never normalized into
// trusted values.
type FalsifierProposal struct {
	ID           string             `json:"id"`
	ClaimID      string             `json:"claim_id"`
	ConditionID  string             `json:"condition_id"`
	Kind         FalsifierKind      `json:"kind"`
	Subjects     []FalsifierSubject `json:"subjects"`
	EvidenceRefs []string           `json:"evidence_refs,omitempty"`
}

// falsifierForbiddenFields are the self-declared verification fields an
// agent may never set inside a proposal: they belong to the deterministic
// verifier and the decision layer. They are named explicitly — ahead of
// generic unknown-field rejection — so the error identifies the forbidden
// field instead of reporting a mere schema miss.
var falsifierForbiddenFields = map[string]bool{
	"status":                true,
	"verified":              true,
	"mandatory":             true,
	"coverage":              true,
	"negative_verification": true,
	"recommendation":        true,
	"verdict":               true,
}

// UnmarshalJSON decodes a proposal strictly: unknown fields and every
// self-declared verification field are rejected (DisallowUnknownFields
// applies recursively to subjects), then the mandatory-field rules run so
// a proposal can never denote a vacuous or unbound check.
func (p *FalsifierProposal) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if falsifierForbiddenFields[name] {
			return fmt.Errorf("falsifier proposal field %q is forbidden: verification fields belong to the deterministic verifier", name)
		}
	}
	type plain FalsifierProposal
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var x plain
	if err := dec.Decode(&x); err != nil {
		return err
	}
	*p = FalsifierProposal(x)
	return p.Validate()
}

// Validate checks the proposal contract: id/claim_id/condition_id/kind are
// required, at least one fully-specified subject must be present — a
// proposal without subjects would denote a vacuous check — and
// evidence_refs must name at least one evidence entry of the surrounding
// assessment: a proposal the verifier cannot bind to a recorded observation
// can never prove anything. Whether those ids belong to the proposal's own
// claim is verifier context, not standalone proposal validation.
func (p FalsifierProposal) Validate() error {
	if strings.TrimSpace(p.ID) == "" {
		return errors.New(`falsifier proposal field "id" is required`)
	}
	if strings.TrimSpace(p.ClaimID) == "" {
		return errors.New(`falsifier proposal field "claim_id" is required`)
	}
	if strings.TrimSpace(p.ConditionID) == "" {
		return errors.New(`falsifier proposal field "condition_id" is required`)
	}
	if !p.Kind.Valid() {
		return fmt.Errorf("falsifier proposal %q has invalid kind %q", p.ID, p.Kind)
	}
	if len(p.Subjects) == 0 {
		return fmt.Errorf("falsifier proposal %q requires non-empty subjects", p.ID)
	}
	for i, s := range p.Subjects {
		if strings.TrimSpace(s.Package) == "" {
			return fmt.Errorf("falsifier proposal %q subject %d requires package", p.ID, i)
		}
		if strings.TrimSpace(s.Symbol) == "" {
			return fmt.Errorf("falsifier proposal %q subject %d requires symbol", p.ID, i)
		}
	}
	if len(p.EvidenceRefs) == 0 {
		return fmt.Errorf("falsifier proposal %q requires non-empty evidence_refs", p.ID)
	}
	return nil
}

type Finding struct {
	SchemaVersion string        `json:"schema_version"`
	FindingID     string        `json:"finding_id"`
	Vulnerability Vulnerability `json:"vulnerability"`
	Component     Component     `json:"component"`
	Target        Target        `json:"target"`
	Scanner       Scanner       `json:"scanner,omitempty"`
}

type Vulnerability struct {
	IDs         []string `json:"ids,omitempty"`
	Summary     string   `json:"summary,omitempty"`
	Description string   `json:"description,omitempty"`
	References  []string `json:"references,omitempty"`
	// BaseSeverity and BaseScore carry the resolved advisory's severity
	// when Stage 0 projects it onto the agent-facing finding view. They
	// are optional and absent from scanner-produced findings.
	BaseSeverity string  `json:"base_severity,omitempty"`
	BaseScore    float64 `json:"base_score,omitempty"`
}

type Component struct {
	Name      string `json:"name,omitempty"`
	Version   string `json:"version,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
	Package   string `json:"package,omitempty"`
}

type Target struct {
	Repository   string `json:"repository,omitempty"`
	Revision     string `json:"revision,omitempty"`
	Distribution string `json:"distribution,omitempty"`
	Image        string `json:"image,omitempty"`
	SBOM         string `json:"sbom,omitempty"`
	Binary       string `json:"binary,omitempty"`
	// Toolchain is the Go toolchain version that built the analyzed release
	// or artifact (e.g. "go1.25.8") — not the local analysis Go and not the
	// go.mod directive. Optional; absent means the release toolchain is
	// unknown to the finding producer.
	Toolchain string `json:"toolchain,omitempty"`
	// Build is the identified product build selection the finding producer
	// declared, when it declared one. It is a provenance record — platform,
	// build tags, CGO and the source/scope/digest binding — never the
	// analyzer host and never the analysis toolchain. Absent means the
	// product build is unidentified.
	Build *domain.ProductTarget `json:"build,omitempty"`
}

type Scanner struct {
	Severity string `json:"severity,omitempty"`
	RawText  string `json:"raw_text,omitempty"`
}

// FindingInput is a parsed finding plus its preserved raw record and hash.
// Unlike the generic intake transport record (S-06b scope) it carries a
// schema-validated finding.v1, not opaque bytes.
type FindingInput struct {
	Finding Finding `json:"finding"`
	// Raw is the untouched JSON bytes of the original record.
	Raw []byte `json:"-"`
	// SHA256 is the lowercase hex sha256 of Raw.
	SHA256 string `json:"sha256,omitempty"`
}

// Assessment is the agent's structured result plus fact gate and policy
// fields filled by deterministic code. Free-text fields (Summary, Mechanism,
// claim statements) are stored verbatim and never rewritten.
//
// The model-owned half is the human assessment: the judgment (Verdict,
// Summary, Mechanism, claims and their premise graph), material
// counterarguments and the concrete ProposedAction for a person. The
// deterministic half — FactValidation, FactValidationDetail and Audit — is
// composed by code and is rejected by the live decoder when the model
// supplies it. The CI policy outcome is not part of the assessment at all:
// it belongs to the decision package's machine disposition.
type Assessment struct {
	SchemaVersion  string               `json:"schema_version,omitempty"`
	FindingID      string               `json:"finding_id,omitempty"`
	Verdict        Verdict              `json:"verdict"`
	VerdictSubtype string               `json:"verdict_subtype,omitempty"`
	VerdictSource  string               `json:"verdict_source,omitempty"`
	Summary        string               `json:"summary,omitempty"`
	Mechanism      string               `json:"mechanism,omitempty"`
	FactValidation FactValidationStatus `json:"fact_validation,omitempty"`
	// FactValidationDetail preserves the fact gate's per-reference checks
	// and limitations in assessment.json; FactValidation carries only the
	// aggregate status. Deterministic code composes it — the agent never
	// supplies it.
	FactValidationDetail *FactValidation   `json:"fact_validation_detail,omitempty"`
	Claims               []Claim           `json:"claims,omitempty"`
	Evidence             []EvidenceRef     `json:"evidence,omitempty"`
	Unknowns             []Unknown         `json:"unknowns,omitempty"`
	Counterarguments     []Counterargument `json:"counterarguments,omitempty"`
	// FalsifierProposals carries the agent's structured falsifier requests:
	// proposals only, never proofs — each entry is schema-checked at decode
	// (see FalsifierProposal) and binds to a declared claim/evidence in
	// decodeAssessment. Absent means the agent proposed nothing; proposals
	// are optional because an unsupported or incomplete check limits the
	// machine result, never the human's right to a judgment.
	FalsifierProposals []FalsifierProposal `json:"falsifier_proposals,omitempty"`
	// ProposedAction is the concrete recommendation a human acts on. It is
	// a proposal only: CLOSE and LOWER_PRIORITY never become DISMISSED,
	// LOWERED, NOT_AFFECTED, NO_EXPLOIT_PATH_FOUND or a negative VEX status.
	ProposedAction HumanAction      `json:"proposed_action"`
	EnvironmentVariables []EnvironmentVariableProposal `json:"environment_variables,omitempty"`
	ConditionalActions []ConditionalActionProposal `json:"conditional_actions,omitempty"`
	Audit          *AssessmentAudit `json:"audit,omitempty"`
}

// Claim is one premise of the human assessment. Basis names how the
// proposition is established, Subject and Scope bind it, and the optional
// dependency/binding/conflict fields make the causal premise graph explicit.
// EvidenceRefs and DependsOn are separate namespaces: an evidence id is
// never a claim id and a claim dependency is never an evidence id.
type Claim struct {
	ID               string          `json:"id"`
	Statement        string          `json:"statement,omitempty"`
	Basis            PremiseBasis    `json:"basis"`
	Subject          string          `json:"subject"`
	Scope            string          `json:"scope"`
	DecisionRelevant bool            `json:"decision_relevant"`
	EvidenceRefs     []string        `json:"evidence_refs,omitempty"`
	DependsOn        []string        `json:"depends_on,omitempty"`
	Binding          *PremiseBinding `json:"binding,omitempty"`
	Owner            string          `json:"owner,omitempty"`
	Reason           string          `json:"reason,omitempty"`
	ConflictsWith    []string        `json:"conflicts_with,omitempty"`
}

// EvidenceRef is a single piece of evidence declared by the agent; claims
// reference it by ID via Claim.EvidenceRefs.
type EvidenceRef struct {
	ID      string `json:"id"`
	Kind    string `json:"kind,omitempty"`
	Locator string `json:"locator,omitempty"`
	Quote   string `json:"quote,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
}

type Unknown struct {
	ID          string `json:"id,omitempty"`
	Description string `json:"description,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

// AssessmentAudit carries the run hashes and tool/model metadata written by
// the report composer (Task 5/9 fill it; the agent never provides it).
type AssessmentAudit struct {
	FindingHash    string            `json:"finding_hash,omitempty"`
	SnapshotHash   string            `json:"snapshot_hash,omitempty"`
	PromptHash     string            `json:"prompt_hash,omitempty"`
	ResponseHash   string            `json:"response_hash,omitempty"`
	AssessmentHash string            `json:"assessment_hash,omitempty"`
	Model          string            `json:"model,omitempty"`
	ToolVersions   map[string]string `json:"tool_versions,omitempty"`
	// DetTools records whether the run's tool surface included the
	// deterministic evidence tools; replay rebuilds the prompt from it.
	DetTools bool `json:"det_tools,omitempty"`
}

// FactFeedbackItem is one entry of the structured repair feedback the fact
// gate sends back to the agent (spec §7.3): it restates the deterministic
// check result — status, reason, expected repair and the scope the repair
// is allowed to touch. It never carries a verdict, a recommendation or a
// semantic answer.
type FactFeedbackItem struct {
	ReferenceID    string     `json:"reference_id,omitempty"`
	CurrentStatus  FactStatus `json:"current_status"`
	Reason         string     `json:"reason"`
	ExpectedRepair string     `json:"expected_repair,omitempty"`
	AllowedScope   string     `json:"allowed_scope,omitempty"`
}

// FactFeedback is one feedback pass handed to the agent: the pass number,
// the per-reference items derived verbatim from the deterministic gate
// report, and the mechanical consequence unresolved items have on risk
// reduction. RecommendationEffect names the demotion rule, never a verdict
// — feedback repairs reproducibility only.
type FactFeedback struct {
	Pass                 int                `json:"pass"`
	Items                []FactFeedbackItem `json:"items"`
	RecommendationEffect string             `json:"recommendation_effect,omitempty"`
}

// FactGatePass is one recorded fact-gate report of a run, persisted in
// raw-agent.json for replay and audit: Pass counts prior feedback turns
// (0 is the first validation), Validation is the gate result as produced,
// and Feedback is the repair pass sent back to the agent — nil on the
// final report.
type FactGatePass struct {
	Pass       int            `json:"pass"`
	Validation FactValidation `json:"validation"`
	Feedback   *FactFeedback  `json:"feedback,omitempty"`
}

// FalsifierFeedbackFunc is the verifier side of the bounded proposal-repair
// loop: after the fact gate stands, the runner hands it the accepted
// assessment, the final gate validation and the run's recorded
// observations. Parameter semantics are fixed by contract — `assessment`
// is the accepted (possibly repaired) answer for this pass, `validation`
// is the gate result for that same assessment, `observations` is the
// run-scoped archive as the runner recorded it, and `pass` is the 1-based
// feedback round the runner is on. The callback runs the deterministic
// falsifier verifier, keeps the report and returns either a
// contract-repair message to send back to the agent (retry=true) or a
// terminal answer (retry=false) — the report itself stays whatever the
// verifier concluded, never a desired verdict. A callback error
// terminates the run as a technical failure; a nil callback disables the
// loop entirely. Internal plumbing only — nothing here is an artifact
// schema.
type FalsifierFeedbackFunc func(
	ctx context.Context,
	assessment Assessment,
	validation FactValidation,
	observations []RecordedObservation,
	pass int, // feedback pass (1-based)
) (message string, retry bool, err error)

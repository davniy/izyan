// Package research implements the additive experimental `izyan research`
// lane (e2e-slice1 design of record). It produces a review-required
// single-case research report: deterministic facts collected through the
// strict evidencetools session, an optional one-case E6 agent turn, and a
// fail-closed JSON contract. It never reuses internal/report and never
// emits authoritative verdicts (VERIFIED/FALSE/AUTO_CLOSE are forbidden).
package research

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/evidencetools"
	"github.com/davniy/izyan/internal/goanalysis"
)

// Report schema and mode constants.
const (
	ReportSchemaV1 = "research-report/1"
	ReportSchemaV2 = "research-report/2"
	// ReportSchemaV3 is the decision-ready lane's report schema: it
	// carries a mandatory decision-artifact/1 member and keeps the
	// EvidenceDecision compatibility projection.
	ReportSchemaV3 = "research-report/3"
	// ReportSchemaV4 is the historical requested-finding report schema:
	// the /3 decision artifact and request_composition are both mandatory.
	// Current deterministic publication uses /5, not a weakened /4 contract.
	ReportSchemaV4 = "research-report/4"
	// ReportSchemaV5 is current deterministic canonical publication, without an R6 artifact.
	ReportSchemaV5 = "research-report/5"
	// ReportSchema is the schema emitted for newly assembled reports.
	// The R6 route stays opt-in, so the default lane still emits /2.
	ReportSchema = ReportSchemaV2
	// DecisionArtifactSchemaV1 is the embedded/sidecar decision-artifact
	// contract id (Amendment R6).
	DecisionArtifactSchemaV1 = "decision-artifact/1"
	ReportMode               = "experimental-research-v1"
)

// Slice-2 contract extension ids. The wire schema stays
// research-report/1; a Slice-2 report advertises exactly one marker
// and MUST emit every extension field that marker requires. Reports
// advertising the legacy slice2-fidelity/1 or slice2-fidelity/2 marker
// stay readable and validate under those rules; reports omitting the
// marker entirely are legacy Slice-1 documents. slice2-fidelity/3
// carries every /2 requirement plus mandatory role and evidence_level.
// Under /3 a report MAY additionally carry the optional audit axis
// exploitation_axes.build_usage_scope (B41): it is derived only from
// kind=BUILD_USAGE_SCOPE facts through the same pure helper the
// validator recomputes, is strictly non-carrier (it closes no
// condition and never enters evidence_level), and stays absent from
// /1 and /2 documents. Advertising more than one of the three markers
// is an error.
const (
	Slice2Extension   = "slice2-fidelity/2"
	Slice2ExtensionV1 = "slice2-fidelity/1"
	Slice2ExtensionV3 = "slice2-fidelity/3"
)

// Conclusion-scope values for product_applicability.conclusion_scope.
const (
	ScopeAffectedEntryOnly = "AFFECTED_ENTRY_ONLY"
	ScopeAdvisorySet       = "ADVISORY_SET"
	ScopeCVEWide           = "CVE_WIDE"
)

// Advisory-scope status values.
const (
	ScopeComplete    = "COMPLETE"
	ScopeGapDetected = "GAP_DETECTED"
	ScopeUnknown     = "UNKNOWN"
)

// Axis status values.
const (
	AxisEstablished    = "ESTABLISHED"
	AxisNotEstablished = "NOT_ESTABLISHED"
	AxisUnknown        = "UNKNOWN"
	AxisConflicted     = "CONFLICTED"
)

// Axis level values.
const (
	LevelNone                = "NONE"
	LevelModule              = "MODULE"
	LevelPackageBuild        = "PACKAGE_BUILD"
	LevelSymbol              = "SYMBOL"
	LevelStaticCapability    = "STATIC_CAPABILITY"
	LevelRuntimeAvailable    = "RUNTIME_AVAILABLE"
	LevelDynamicReproduction = "DYNAMIC_REPRODUCTION"
)

// Axis basis values.
const (
	AxisBasisDeterministic = "deterministic"
	AxisBasisDynamic       = "dynamic"
	AxisBasisNone          = "none"
)

// dynamicAxisToolOrder lists the deterministic tools whose verified
// facts count as dynamic evidence for exploitation_established (§2.3),
// in stable emission order (rendered evidence_refs must stay
// byte-stable). The axis may be ESTABLISHED only when at least one
// resolvable ref names a verified fact produced by one of these tools;
// both the generator (slice2Axes) and the validator enforce it.
var dynamicAxisToolOrder = []string{"runtime-observation", "dynamic-trace", "reproduction"}

// dynamicAxisTools is dynamicAxisToolOrder as a lookup set.
var dynamicAxisTools = func() map[string]bool {
	m := map[string]bool{}
	for _, t := range dynamicAxisToolOrder {
		m[t] = true
	}
	return m
}()

// Contradiction kind values.
const (
	ContradictionCategoryVsComponentScope = "category_vs_component_scope"
	ContradictionCategoryVsApplicability  = "category_vs_applicability"
	ContradictionCategoryVsAxis           = "category_vs_exploitation_axis"
	ContradictionAdvisoryScopeGap         = "advisory_scope_gap"
	ContradictionAgentVsDeterministic     = "agent_vs_deterministic"
	ContradictionEvidenceScopeMismatch    = "evidence_scope_mismatch"
)

// Contradiction resolution values.
const (
	ResolutionDeterministicPrevails = "DETERMINISTIC_PREVAILS"
	ResolutionScopeLimits           = "SCOPE_LIMITS"
	ResolutionUnresolved            = "UNRESOLVED"
)

// Applicability-basis kind values.
const (
	ABComponentAbsent    = "component_absent"
	ABVersionFixed       = "version_fixed"
	ABNotInImportClosure = "package_not_in_import_closure"
	// ABImplementationAbsent is the platform-gated implementation basis:
	// module+version+package+build relevance are established, and the
	// advisory's vulnerable implementation is deterministically absent
	// under an admitted product target scope.
	ABImplementationAbsent = "vulnerable_implementation_absent"
	ABSDKVsDaemon          = "sdk_vs_daemon_distinction"
	ABComponentPresentAff  = "component_present_affected"
	ABRequiredConfigAbsent = "required_configuration_absent"
	ABVulnCodeNotReachable = "vulnerable_code_not_reachable"
	ABUnknownKind          = "unknown"
)

// advisory_entry_status values: the deterministic verdict over the
// evaluated advisory entries (presence/version probe). NOT_EVALUATED
// means no evaluated entry carries a fix/affected verdict — including
// the module-absent case (presence was checked, the fix status was
// not evaluated). MIXED means the evaluated entries split across at
// least two verdict kinds (affected / fixed / unknown-version).
const (
	EntryAffected     = "AFFECTED"
	EntryFixed        = "FIXED"
	EntryUnknown      = "UNKNOWN"
	EntryNotEvaluated = "NOT_EVALUATED"
	EntryMixed        = "MIXED"
)

// vulnerable_code_reachability values (slice2-fidelity/2).
const (
	VCRTrue         = "TRUE"
	VCRFalse        = "FALSE"
	VCRUnknown      = "UNKNOWN"
	VCRNotEvaluated = "NOT_EVALUATED"
)

// Applicability-basis status values.
const (
	ABEstablished  = "ESTABLISHED"
	ABProvisional  = "PROVISIONAL"
	ABUnknown      = "UNKNOWN"
	ABContradicted = "CONTRADICTED"
)

// Applicability-basis source values.
const (
	ABSourceDeterministic = "deterministic"
	ABSourceAgent         = "agent"
	ABSourceMixed         = "mixed"
	ABSourceNone          = "none"
)

// Classification-review class/status values.
const (
	ClassNonApplicable = "NON_APPLICABLE"
	ClassApplicable    = "APPLICABLE"
	ClassUncertain     = "UNCERTAIN"
	ClassNotEvaluated  = "NOT_EVALUATED"
)

// Unknown group / priority values.
const (
	UnknownPriorityDecisionChanging = "DECISION_CHANGING"
	UnknownPriorityAppendix         = "APPENDIX"
)

// Materiality level values.
const (
	MaterialityMaterial   = "MATERIAL"
	MaterialitySupporting = "SUPPORTING"
	MaterialityContext    = "CONTEXT"
)

// Attempt status/reason values (agent statuses are reused for kind=agent).
const (
	AttemptReasonInitial               = "initial"
	AttemptReasonOperatorRetry         = "operator_retry"
	AttemptReasonInvalidExtraction     = "invalid_extraction"
	AttemptReasonTimeout               = "timeout"
	AttemptReasonProviderRefused       = "provider_refused"
	AttemptReasonInfrastructureFailure = "infrastructure_failure"
	AttemptReasonManualRecheck         = "manual_recheck"
	AttemptReasonOther                 = "other"
)

// Extraction status / invalid-reason values.
const (
	ExtractionValid         = "VALID"
	ExtractionInvalid       = "INVALID"
	ExtractionNotApplicable = "NOT_APPLICABLE"
	InvalidNone             = "NONE"
	InvalidNoCandidate      = "NO_CANDIDATE"
	InvalidMalformedJSON    = "MALFORMED_JSON"
	InvalidAmbiguous        = "AMBIGUOUS_CONFLICTING_CANDIDATES"
	InvalidSchema           = "SCHEMA_INVALID"
	InvalidMissingCategory  = "MISSING_CATEGORY"
	InvalidMissingReasoning = "MISSING_REASONING"
)

// Extraction recovery markers (Extraction.Recovery): empty means the
// strict pass produced the selection; the named markers record which
// bounded repair produced it (§2.7).
const (
	RecoveryBraceCompletion = "BRACE_COMPLETION"
	RecoveryMemberSalvage   = "MEMBER_SALVAGE"
)

// Exploitation-condition axis tags.
const (
	ECAxisCodeReachability        = "code_reachability"
	ECAxisAttackSurface           = "attack_surface_availability"
	ECAxisExploitationEstablished = "exploitation_established"
	ECAxisOther                   = "other"
)

// safeCategories is the non-applicability category set from the
// slice-2 design §3.1 rule 1.
var safeCategories = map[string]bool{
	"false_positive": true, "code_not_present": true, "code_not_reachable": true,
	"compiler_protected": true, "runtime_protected": true,
	"perimeter_protected": true, "mitigating_control_protected": true,
}

// Section status values for the eight assessment sections.
const (
	StatusSupported  = "SUPPORTED"
	StatusPartial    = "PARTIAL"
	StatusUnknown    = "UNKNOWN"
	StatusConflicted = "CONFLICTED"
)

// Exploitation-condition subjects emitted by the deterministic lane.
// Module presence and version-in-use are applicability preconditions —
// they never count as confirmed exploit-path transitions (§5); the
// path predicates do.
const (
	subjModulePresence      = "affected module presence"
	subjVersionInUse        = "affected version in use"
	subjPackageReach        = "affected package reachable"
	subjBuildRelevant       = "affected package build-relevant"
	subjProductPackageUsage = "affected package/symbol used by product code"
	subjRuntimePosture      = "runtime/deployment posture"
	subjInboundListener     = "inbound listener"
)

// Claim states for exploitation_conditions, section claims and agent assertions.
const (
	StateSupported    = "SUPPORTED"
	StateOpen         = "OPEN"
	StateRefuted      = "REFUTED"
	StateConflicted   = "CONFLICTED"
	StateUnknown      = "UNKNOWN"
	StateRetracted    = "RETRACTED"
	OriginDeterm      = "deterministic"
	OriginAgent       = "agent"
	BasisHypothesis   = "MODEL_HYPOTHESIS"
	BasisSupported    = "EVIDENCE_SUPPORTED"
	BasisContradicted = "CONTRADICTED"
	BasisUnknown      = "UNKNOWN"
)

// Agent output status values.
const (
	AgentNotRequested    = "NOT_REQUESTED"
	AgentOK              = "OK"
	AgentTimeout         = "TIMEOUT"
	AgentFailed          = "FAILED"
	AgentProviderRefused = "PROVIDER_REFUSED"
	AgentInvalidFormat   = "INVALID_FORMAT"
)

// Binding values for advisory entries.
const (
	BindExact         = "exact"
	BindAliasResolved = "alias-resolved"
	BindNonGo         = "non-go"
	BindIncomplete    = "incomplete"
)

// Report is the closed research-report/1–/5 JSON contract. Historical /1–/4
// documents remain readable without acquiring current authority; archival
// publication uses HistoricalReplay, while /5 retains canonical case admission.
type Report struct {
	Schema                  string                   `json:"schema"`
	Mode                    string                   `json:"mode"`
	Run                     RunInfo                  `json:"run"`
	Input                   InputInfo                `json:"input"`
	Vulnerability           VulnerabilityInfo        `json:"vulnerability"`
	AffectedImplementations []AffectedImplementation `json:"affected_implementations"`
	ProductApplicability    ProductApplicability     `json:"product_applicability"`
	ExploitationConditions  []ExploitationCondition  `json:"exploitation_conditions"`
	VulnerabilityMechanism  Section                  `json:"vulnerability_mechanism"`
	RootCause               Section                  `json:"root_cause"`
	AttackScenario          Section                  `json:"attack_scenario"`
	ProductExposure         Section                  `json:"product_exposure"`
	AlternativePaths        Section                  `json:"alternative_paths"`
	EvidenceQuality         EvidenceQuality          `json:"evidence_quality"`
	ResidualQuestions       []ResidualQuestion       `json:"residual_questions"`
	TriageRecommendation    TriageRecommendation     `json:"triage_recommendation"`
	VerifiedFacts           []VerifiedFact           `json:"verified_facts"`
	AgentAssertions         []AgentAssertion         `json:"agent_assertions"`
	Unknowns                []UnknownEntry           `json:"unknowns"`
	OpenQuestions           []OpenQuestion           `json:"open_questions"`
	Recommendations         []Recommendation         `json:"recommendations"`
	AgentOutput             AgentOutput              `json:"agent_output"`
	ContractExtensions      []string                 `json:"contract_extensions"`
	Contradictions          []Contradiction          `json:"contradictions"`
	ExploitationAxes        ExploitationAxes         `json:"exploitation_axes"`
	ClassificationReview    ClassificationReview     `json:"classification_review"`
	EvidenceLevel           *EvidenceLevel           `json:"evidence_level,omitempty"`
	Disposition             Disposition              `json:"disposition"`
	// Decision is the independently verified evidence result. It is distinct
	// from Disposition, which remains REVIEW_REQUIRED/AutoClose=false.
	Decision *EvidenceDecision `json:"decision,omitempty"`
	// DecisionArtifact carries the R6 decision-artifact/1 contract. It is
	// mandatory in research-report/3, absent in /1 and /2, and stays
	// authoritative for the human-facing accept/reject contract; Decision
	// remains only as a /2-compatible projection derived from it.
	DecisionArtifact *DecisionArtifact `json:"decision_artifact,omitempty"`
	// ImplementationLocusProposals are the LLM-inferred implementation
	// loci retained verbatim from the agent answer. They are explicitly
	// non-authoritative: quality stays LLM_INFERRED, every reference and
	// quote resolves against the frozen advisory, and only the
	// deterministic affected.VerifyImplementationLocus verifier may turn
	// one into an implementation-presence fact. Absent — never empty —
	// when no proposal was admitted, so legacy reports stay byte-identical.
	ImplementationLocusProposals []domain.ImplementationLocusProposal `json:"implementation_locus_proposals,omitempty"`
	// ExploitLocusProposals are the LLM-inferred exploit-locus hypotheses
	// retained from the agent answer or replayed turn. They are
	// explicitly non-authoritative: quality stays LLM_INFERRED, the
	// advisory reference and quote resolve against the frozen advisory,
	// and only affected.VerifyExploitLocus may turn one into a binding.
	// Absent — never empty — when none was admitted.
	ExploitLocusProposals []domain.ExploitLocusProposal `json:"exploit_locus_proposals,omitempty"`
	// ExploitLocusBinding is the deterministic side record of a COMPLETE
	// exploit-locus binding for a symbol-less advisory: the proposal and
	// advisory identities, the vulnerable implementation, the verified
	// product-facing sink set with module identities, the exact
	// trigger argument, the G1 condition built from it, the relation
	// evidence and the observation refs the record grounds in. It is
	// never the advisory's affected symbol set and never by itself a
	// verdict. Absent when no complete binding exists.
	ExploitLocusBinding *ExploitLocusBindingReport `json:"exploit_locus_binding,omitempty"`
	// RequestComposition is the one authoritative answer to the caller's
	// request, re-admitted through finding.Project before publication. It
	// is mandatory in research-report/4 and /5 and absent in /1–/3, which never
	// acquire a request-level outcome, corpus negative basis or
	// attribution. The lane's record-bound decision, decision artifact and
	// product_applicability block stay record-bound: corpus completeness
	// travels only in this member's corpus_negative_basis.
	RequestComposition *domain.RequestedFinding `json:"request_composition,omitempty"`
	RequestedCaseSHA256 string `json:"requested_case_sha256,omitempty"`
}

// ExploitLocusBindingReport projects a COMPLETE exploit-locus binding
// into the report. Condition is the G1 condition the binding authorized
// (subjects = verified product sinks, exact ArgIndex); EvidenceRefs name
// the recorded lane observations the binding and its post-reach use
// rest on; AssumptionIDs are the admitted config-trust policy ids the
// terminal decision cited — policy inputs, never evidence ids.
type ExploitLocusBindingReport struct {
	ProposalID string `json:"proposal_id"`
	AdvisoryID string `json:"advisory_id"`
	Module     string `json:"module"`
	Version    string `json:"version"`

	Vulnerable `json:"vulnerable"`

	Sinks []domain.ExploitLocusSink `json:"sinks"`

	TriggerArgumentName  string `json:"trigger_argument_name"`
	TriggerArgumentIndex int    `json:"trigger_argument_index"`

	RelationEvidence []string `json:"relation_evidence,omitempty"`

	Condition ExploitLocusConditionReport `json:"condition"`

	EvidenceRefs  []string `json:"evidence_refs,omitempty"`
	AssumptionIDs []string `json:"assumption_ids,omitempty"`

	Complete    bool     `json:"complete"`
	Blockers    []string `json:"blockers,omitempty"`
	Limitations []string `json:"limitations,omitempty"`
}

// Vulnerable names the proposed vulnerable implementation; it stays in
// the binding record, never in the advisory's affected symbol set.
type Vulnerable struct {
	Package string `json:"package"`
	Symbol  string `json:"symbol"`
}

// ExploitLocusConditionReport is the G1 condition shape the binding
// authorizes.
type ExploitLocusConditionReport struct {
	ID        string             `json:"id"`
	Kind      string             `json:"kind"`
	Mandatory bool               `json:"mandatory"`
	Subjects  []domain.SymbolRef `json:"subjects"`
	ArgIndex  int                `json:"arg_index"`
	Statement string             `json:"statement"`
}

// RunInfo records the attempt envelope: identity, wall-clock bounds and
// the harness/environment pins actually used. Attempts is the Slice-2
// per-attempt ledger (§2.7); absent in legacy reports.
//
// Outcome names a run-level terminal posture beyond the per-attempt
// ledger: today only "NOT_RUN", set when an explicitly requested
// release-evidence channel (release artifact or release metadata) failed
// closed and the model/planner path never ran. Empty means the run
// completed its deterministic lane; the member is omitted so legacy
// reports stay byte-identical.
type RunInfo struct {
	RunID             string      `json:"run_id"`
	StartedAt         string      `json:"started_at"`
	FinishedAt        string      `json:"finished_at"`
	DeterministicOnly bool        `json:"deterministic_only"`
	Timeouts          TimeoutInfo `json:"timeouts"`
	Harness           HarnessInfo `json:"harness"`
	Attempts          []Attempt   `json:"attempts"`
	Outcome           string      `json:"outcome,omitempty"`
	OutcomeReason     string      `json:"outcome_reason,omitempty"`
}

// AttemptArtifact pins one retained file of an attempt.
type AttemptArtifact struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
	Selector  string `json:"selector"`
}

// ExtractionCandidate is one candidate JSON object found in the answer.
type ExtractionCandidate struct {
	Index           int     `json:"index"`
	Status          string  `json:"status"` // VALID|INVALID
	Category        *string `json:"category"`
	RawSHA256       string  `json:"raw_sha256"`
	CanonicalSHA256 string  `json:"canonical_sha256"`
	Selector        string  `json:"selector"`
}

// Extraction is the deterministic answer-extraction record (§2.7).
// Recovery is optional: absent on strict selections and on every
// INVALID record; when set it names the bounded repair that produced
// the VALID selection (BRACE_COMPLETION or MEMBER_SALVAGE).
type Extraction struct {
	Status         string                `json:"status"`
	InvalidReason  string                `json:"invalid_reason"`
	CandidateCount int                   `json:"candidate_count"`
	Candidates     []ExtractionCandidate `json:"candidates"`
	SelectedIndex  int                   `json:"selected_index"`
	Recovery       string                `json:"recovery,omitempty"`
	AnswerArtifact *AttemptArtifact      `json:"answer_artifact"`
}

// Attempt is one run-attempt ledger row (§2.7). Each attempt owns a
// distinct artifact directory; originals are never overwritten.
type Attempt struct {
	ID                string           `json:"id"`
	Kind              string           `json:"kind"` // deterministic|agent
	Ordinal           int              `json:"ordinal"`
	Status            string           `json:"status"`
	StartedAt         string           `json:"started_at"`
	FinishedAt        string           `json:"finished_at"`
	ReasonCode        string           `json:"reason_code"`
	Reason            string           `json:"reason"`
	RetryOf           *string          `json:"retry_of"`
	OriginalPreserved bool             `json:"original_preserved"`
	ResultArtifact    *AttemptArtifact `json:"result_artifact"`
	Extraction        *Extraction      `json:"extraction"`
}

// Contradiction is an additional record flagging a tension between the
// preserved agent output and deterministic facts (§2.2). It never
// mutates agent_assertions, agent_output.category or the raw answer.
type Contradiction struct {
	ID                string   `json:"id"`
	Kind              string   `json:"kind"`
	Subject           string   `json:"subject"`
	AgentAssertionRef *string  `json:"agent_assertion_ref"`
	DeterministicRefs []string `json:"deterministic_refs"`
	Summary           string   `json:"summary"`
	Resolution        string   `json:"resolution"`
	Limitations       []string `json:"limitations"`
}

// Axis is one exploitation axis summary (§2.3).
type Axis struct {
	Status       string   `json:"status"`
	Level        string   `json:"level"`
	Statement    string   `json:"statement"`
	Scope        string   `json:"scope"`
	Basis        string   `json:"basis"`
	EvidenceRefs []string `json:"evidence_refs"`
	Limitations  []string `json:"limitations"`
}

// ExploitationAxes groups the three axis summaries (§2.1) plus the
// optional slice2-fidelity/3 build-usage audit axis (B41).
// BuildUsageScope is a pointer so /1 and /2 serialized reports carry
// no build_usage_scope member; the assembler fills it through the
// pure deriveBuildUsageScopeAxis helper only when verified
// BUILD_USAGE_SCOPE facts exist. It is strictly non-carrier: it never
// closes an exploitation condition, never enters
// evidence_level.evidence_refs and never changes the level.
type ExploitationAxes struct {
	CodeReachability          Axis  `json:"code_reachability"`
	AttackSurfaceAvailability Axis  `json:"attack_surface_availability"`
	ExploitationEstablished   Axis  `json:"exploitation_established"`
	BuildUsageScope           *Axis `json:"build_usage_scope,omitempty"`
}

// EvidenceLevel is the derived exploit-path evidence ladder
// (slice2-fidelity/3). It summarizes the proof state of the attack
// path next to — never inside — exploitation_axes and never replaces
// attack_scenario: L1 means every required applicability/path
// condition is closed by verified static evidence, L2 means the path
// chain is still open, L3 means dynamically verified exploitation.
// The field is computed by the assembler and recomputed by the
// validator; it can never be set from agent output. The pointer keeps
// /1 and /2 wire output free of a mandatory empty member.
type EvidenceLevel struct {
	Level              string   `json:"level"`
	Basis              string   `json:"basis"`
	Statement          string   `json:"statement"`
	Scope              string   `json:"scope"`
	ConditionRefs      []string `json:"condition_refs"`
	EvidenceRefs       []string `json:"evidence_refs"`
	BlockingConditions []string `json:"blocking_conditions"`
	Limitations        []string `json:"limitations"`
}

// evidence_level.level values (closed enum, slice2-fidelity/3).
const (
	EvidenceLevelL1 = "L1_STATIC_PATH"
	EvidenceLevelL2 = "L2_POTENTIAL_PATH"
	EvidenceLevelL3 = "L3_DYNAMIC_EXPLOITATION"
)

// evidence_level.basis values (closed enum, slice2-fidelity/3). There
// is deliberately no "agent" basis: agent assertions can never carry
// evidence for any level.
const (
	EvidenceBasisNone          = "none"
	EvidenceBasisDeterministic = "deterministic"
	EvidenceBasisDynamic       = "dynamic"
)

// exploitation_conditions.role values (closed enum,
// slice2-fidelity/3). The assembler derives the role from a fixed
// subject table; a role value carried by agent output is never read.
// "deployment" conditions (runtime/deployment posture, inbound
// listener) are required scope facts that do not block L1; a
// canonical agent path hypothesis normalized into a "path" condition
// stays OPEN and does block it.
const (
	ConditionRoleApplicability = "applicability"
	ConditionRolePath          = "path"
	ConditionRoleDeployment    = "deployment"
	ConditionRoleSupporting    = "supporting"
)

// ApplicabilityBasis is one named applicability basis (§2.4). CheckScope
// (slice2-fidelity/2) names the check scope the basis statement covers;
// every emitted basis must carry one.
type ApplicabilityBasis struct {
	Kind                 string   `json:"kind"`
	Status               string   `json:"status"`
	Source               string   `json:"source"`
	Statement            string   `json:"statement"`
	EvidenceRefs         []string `json:"evidence_refs"`
	VerifiedEvidenceRefs []string `json:"verified_evidence_refs"`
	Limitations          []string `json:"limitations"`
	CheckScope           string   `json:"check_scope,omitempty"`
}

// ClassificationReview reconciles the preserved agent category with the
// deterministic lane (§2.4); the original category is never rewritten.
type ClassificationReview struct {
	OriginalCategory *string  `json:"original_category"`
	Class            string   `json:"class"`
	Status           string   `json:"status"`
	BasisRefs        []string `json:"basis_refs"`
	Limitations      []string `json:"limitations"`
}

// Materiality records the raw bytes or reproducible source recipe behind
// an evidence record (§2.6). At least one member is required when the
// level is MATERIAL; a digest alone is never material evidence.
type Materiality struct {
	Level              string              `json:"level"`
	RawBytes           *MaterialityRaw     `json:"raw_bytes"`
	ReproducibleSource *ReproducibleSource `json:"reproducible_source"`
}

// MaterialityRaw pins exact bytes on disk.
type MaterialityRaw struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
	Selector  string `json:"selector"`
}

// ReproducibleSource is the regeneration recipe for deterministic tool
// output (§2.6).
type ReproducibleSource struct {
	Kind                string            `json:"kind"` // FILE|COMMAND|SNAPSHOT
	Path                *string           `json:"path"`
	Command             *string           `json:"command"`
	WorkingDir          *string           `json:"working_dir"`
	Tool                *string           `json:"tool"`
	ToolVersion         *string           `json:"tool_version"`
	SnapshotContentHash *string           `json:"snapshot_content_hash"`
	InputDigest         *string           `json:"input_digest"`
	Env                 map[string]string `json:"env"`
	Selector            string            `json:"selector"`
	OutputSHA256        string            `json:"output_sha256"`
}

// TimeoutInfo is in milliseconds.
type TimeoutInfo struct {
	OverallMs       int64 `json:"overall_ms"`
	DeterministicMs int64 `json:"deterministic_ms"`
	AgentMs         int64 `json:"agent_ms"`
}

// HarnessInfo records the E6 harness environment as run; nil-able
// members stay null when the agent was not requested or the harness was
// unavailable.
type HarnessInfo struct {
	Path              *string `json:"path"`
	Commit            *string `json:"commit"`
	PatchSHA256       *string `json:"patch_sha256"`
	E6PreflightReport *string `json:"e6_preflight_report"`
	E6PreflightSHA256 *string `json:"e6_preflight_sha256"`
	Image             *string `json:"image"`
	ImageSHA256       *string `json:"image_sha256"`
	PromptPath        *string `json:"prompt_path"`
	PromptSHA256      *string `json:"prompt_sha256"`
}

// InputInfo pins the frozen inputs plus any operator-supplied channel
// documents.
type InputInfo struct {
	Snapshot SnapshotInput `json:"snapshot"`
	Advisory AdvisoryInput `json:"advisory"`
	// Ticket is the tracker-ticket channel record when the operator
	// supplied the ticket: the provenance ref, the pinned digest of
	// the exact input bytes, and the parsed claims (or the parse
	// error that degraded the identity check to NOT_CHECKED). Absent —
	// never empty — when the channel was not requested, so legacy /1
	// and /2 documents stay byte-identical.
	Ticket *TicketRecord `json:"ticket,omitempty"`
	// DeclaredAssumptions is the declared-assumptions/1 channel record
	// when the operator supplied the document (--declared-assumptions):
	// provenance, the pinned digest, the typed policy members or the
	// fail-closed load error. Assumptions are policy/scope inputs —
	// never verified facts, never evidence ids — and the member set is
	// validated identically by intake and by report validation. Absent —
	// never empty — when the channel was not requested, so legacy /1
	// and /2 documents stay byte-identical.
	DeclaredAssumptions *domain.DeclaredAssumptionsInput `json:"declared_assumptions,omitempty"`
	// ImplementationLocusProposals is the implementation-locus proposal
	// channel record when the operator supplied an
	// implementation-locus-proposals/1 artifact
	// (--implementation-locus-proposal) or the run consumed retained
	// proposals from a replayed agent turn: provenance, pinned digests,
	// the admitted members or the fail-closed load error. The proposals
	// are hypotheses only — inputs, never evidence; additive so /1
	// and /2 documents stay byte-identical.
	ImplementationLocusProposals *ImplementationProposalsInput `json:"implementation_locus_proposals,omitempty"`
	// ExploitLocusProposals is the exploit-locus proposal channel record
	// when the operator supplied an exploit-locus-proposals/1 artifact
	// (--exploit-locus-proposal) or the run consumed retained proposals
	// from a replayed agent turn: provenance, pinned digests, the
	// admitted members or the fail-closed load error. Proposals are
	// hypotheses only — inputs, never evidence; additive so /1 and /2
	// documents stay byte-identical.
	ExploitLocusProposals *ExploitProposalsInput `json:"exploit_locus_proposals,omitempty"`
}

// SnapshotInput is the snapshot identity + build context.
type SnapshotInput struct {
	Path              string   `json:"path"`
	CommitSHA         string   `json:"commit_sha"`
	ExternalCommitSHA *string  `json:"external_commit_sha"`
	ContentHash       string   `json:"content_hash"`
	GoVersion         string   `json:"go_version"`
	ReleaseGoVersion  *string  `json:"release_go_version"`
	GoVersionSource   *string  `json:"go_version_source"`
	MinimumGoVersion  *string  `json:"minimum_go_version"`
	GOOS              string   `json:"goos"`
	GOARCH            string   `json:"goarch"`
	BuildTags         []string `json:"build_tags"`
	VendorMode        bool     `json:"vendor_mode"`
	GoWorkFile        *string  `json:"go_work_file"`
	// Target is the typed provenance of the GOOS/GOARCH/build-tags facts
	// above: artifact-build-info (digest-bound), release-metadata,
	// operator-declared, or host-default. Absent on legacy reports and on
	// snapshots recorded before target provenance existed.
	Target *domain.ProductTarget `json:"target,omitempty"`
	// ReleaseEvidence is the /3 release-evidence provenance block: the
	// resolved channel outcome (status + named reason), the selected
	// AUTHORITATIVE toolchain, every classified evidence item, the
	// artifact/build-info digests, and the module graph that grounded
	// the version axis. Absent — never empty — when no release-evidence
	// channel ran and none produced facts, so legacy /1 and /2 documents
	// stay byte-identical.
	ReleaseEvidence *ReleaseEvidenceReport `json:"release_evidence,omitempty"`
}

// ReleaseEvidenceItemReport is the report projection of one classified
// release-evidence item. Every member is provenance: a SUPPORTING item
// corroborates a selection but can never establish one.
type ReleaseEvidenceItemReport struct {
	Version         string `json:"version,omitempty"`
	Source          string `json:"source,omitempty"`
	TrustClass      string `json:"trust_class"`
	Location        string `json:"location,omitempty"`
	ArtifactSHA256  string `json:"artifact_sha256,omitempty"`
	BinaryMember    string `json:"binary_member,omitempty"`
	BuildInfoSHA256 string `json:"build_info_sha256,omitempty"`
}

// ReleaseEvidenceReport is the resolved release-evidence provenance
// block carried under input.snapshot.release_evidence. Status/ReasonCode
// mirror the domain taxonomy verbatim — including the fail-closed
// NOT_RUN outcomes of an explicitly requested channel. Modules is the
// release module graph that grounded the version axis (artifact build
// info or operator-supplied SBOM); VersionGraphSource/VersionGraphTrust
// record which graph won. No member may carry credential material; the
// validator rejects credential-looking keys or URL userinfo.
type ReleaseEvidenceReport struct {
	Status                  string                      `json:"status"`
	ReasonCode              string                      `json:"reason_code,omitempty"`
	RequiredChannelFailures []string                    `json:"required_channel_failures,omitempty"`
	SelectedVersion         string                      `json:"selected_version,omitempty"`
	SelectedSource          string                      `json:"selected_source,omitempty"`
	SelectedTrust           string                      `json:"selected_trust,omitempty"`
	Items                   []ReleaseEvidenceItemReport `json:"items,omitempty"`
	ArtifactSHA256          string                      `json:"artifact_sha256,omitempty"`
	BinaryMember            string                      `json:"binary_member,omitempty"`
	BuildInfoSHA256         string                      `json:"build_info_sha256,omitempty"`
	Modules                 []domain.ReleaseModule      `json:"modules,omitempty"`
	VersionGraphSource      string                      `json:"version_graph_source,omitempty"`
	VersionGraphTrust       string                      `json:"version_graph_trust,omitempty"`
	ModuleCount             int                         `json:"module_count,omitempty"`
}

// AdvisoryInput pins the frozen advisory source.
type AdvisoryInput struct {
	RequestedID     string  `json:"requested_id"`
	ResolvedID      string  `json:"resolved_id"`
	SourceKind      string  `json:"source_kind"` // frozen_dir|frozen_file
	SourcePath      string  `json:"source_path"`
	RawSHA256       string  `json:"raw_sha256"`
	CanonicalSHA256 string  `json:"canonical_sha256"`
	Modified        *string `json:"modified"`
	// FeedResolution is the OSV advisory-feed provenance block: set only
	// when a feed source was configured for the run.
	FeedResolution *AdvisoryFeedResolution `json:"feed_resolution,omitempty"`
}

// AdvisoryFeedResolution records how the configured OSV advisory feed
// resolved — or failed to resolve — package/symbol subjects for advisory
// entries whose own document declared none. Absent entirely when no feed
// source was configured, so legacy /1 and /2 reports stay byte-identical.
type AdvisoryFeedResolution struct {
	// Status is one of resolved|not_required|not_found|no_imports|
	// ambiguous|osv_missing|feed_error.
	Status string `json:"status"`
	// Reason names the fail-closed gate on every unresolved outcome:
	// ADVISORY_IMPORTS_UNAVAILABLE.
	Reason        string `json:"reason,omitempty"`
	Detail        string `json:"detail,omitempty"`
	FeedSource    string `json:"feed_source,omitempty"` // local|remote
	FeedRef       string `json:"feed_ref,omitempty"`    // sanitized base URL or local:<base>
	DumpSHA256    string `json:"dump_sha256,omitempty"`
	CheckedAt     string `json:"checked_at,omitempty"`
	CacheFallback bool   `json:"cache_fallback,omitempty"`
	// ResolvedIDs are the lookup keys (advisory id or its aliases) that
	// indexed a supplying document; SourceIDs are the document ids that
	// supplied subjects — the alias records the frozen file deferred to.
	ResolvedIDs []string                      `json:"resolved_ids,omitempty"`
	SourceIDs   []string                      `json:"source_ids,omitempty"`
	Entries     []AdvisoryFeedResolutionEntry `json:"entries,omitempty"`
}

// AdvisoryFeedResolutionEntry is the per-impl outcome of a subject
// completion attempt.
type AdvisoryFeedResolutionEntry struct {
	ImplID   string `json:"impl_id"`
	Module   string `json:"module"`
	Status   string `json:"status"`
	SourceID string `json:"source_id,omitempty"`
}

// VulnerabilityInfo is the normalized advisory identity.
type VulnerabilityInfo struct {
	ID                string             `json:"id"`
	Aliases           []string           `json:"aliases"`
	Summary           string             `json:"summary"`
	Description       string             `json:"description"`
	References        []domain.Reference `json:"references"`
	AdvisoryDigestRef string             `json:"advisory_digest_ref"`
}

// VersionBounds mirrors one OSV affected range.
type VersionBounds struct {
	Introduced   *string `json:"introduced"`
	Fixed        *string `json:"fixed"`
	LastAffected *string `json:"last_affected"`
}

// AffectedImplementation is one OSV affected[] entry, preserved verbatim
// in intent: non-Go entries stay visible and never become absence facts.
type AffectedImplementation struct {
	ID               string          `json:"id"`
	Ecosystem        string          `json:"ecosystem"`
	Module           string          `json:"module"`
	Package          *string         `json:"package"`
	Symbols          []string        `json:"symbols"`
	GOOS             []string        `json:"goos"`
	GOARCH           []string        `json:"goarch"`
	AffectedVersions []VersionBounds `json:"affected_versions"`
	FixedVersions    []string        `json:"fixed_versions"`
	Binding          string          `json:"binding"`
	SourceRef        string          `json:"source_ref"`
	// imports keeps the declared/feed-resolved package→symbols mapping
	// for the lane's internal projections; never serialized.
	imports []implImport
}

// implImport preserves one ecosystem_specific.imports entry — which
// symbols belong to which package path — for the lane's internal
// projections; the wire record keeps the flattened Package/Symbols fields.
type implImport struct {
	Path    string
	Symbols []string
}

// EvaluatedEntryIDs/AdvisoryEntryStatus/VulnerableCodeReachability are
// slice2-fidelity/2: they separate module presence, the evaluated
// entries' fix status, and vulnerable-code reachability so a fixed
// version can never be read as component absence.
//
// VersionAxisBlocked/TicketCheck are the ticket-build identity record:
// set only when a ticket input was supplied, so legacy
// reports stay byte-identical. A TRUE VersionAxisBlocked means the
// ticket's declared package version differed from the version the
// analysis resolved — the version axis refused to close and
// VersionAffected stays UNKNOWN; it is a refusal, never a verdict.
type ProductApplicability struct {
	Status          string  `json:"status"`
	ModulePresent   string  `json:"module_present"`
	ResolvedVersion *string `json:"resolved_version"`
	VersionAffected string  `json:"version_affected"`
	PackagePresent  string  `json:"package_present"`
	BuildRelevant   string  `json:"build_relevant"`
	// VulnerableImplementationPresent is the fifth affected-chain axis:
	// TRUE|FALSE|UNKNOWN. FALSE means a deterministic verifier proved the
	// admitted vulnerable implementation absent under the product target
	// scope; BuildRelevant remains the separate package/platform
	// restriction axis.
	VulnerableImplementationPresent string `json:"vulnerable_implementation_present,omitempty"`
	// ImplementationLocus/Target/TargetScope and AssumptionIDs make the
	// implementation axis auditable. The assumption ids resolve only
	// against input.declared_assumptions — they are policy references,
	// never evidence.
	ImplementationLocus        string               `json:"implementation_locus,omitempty"`
	ImplementationTarget       string               `json:"implementation_target,omitempty"`
	ImplementationTargetScope  string               `json:"implementation_target_scope,omitempty"`
	AssumptionIDs              []string             `json:"assumption_ids,omitempty"`
	VersionAxisBlocked         bool                 `json:"version_axis_blocked,omitempty"`
	VersionAxisBlockReason     string               `json:"version_axis_block_reason,omitempty"`
	TicketCheck                *domain.TicketCheck  `json:"ticket_check,omitempty"`
	SelectedModule             *string              `json:"selected_module"`
	SelectedModules            []string             `json:"selected_modules"`
	CheckedModules             []string             `json:"checked_modules"`
	CheckedPackages            []string             `json:"checked_packages"`
	PendingModules             []string             `json:"pending_modules"`
	VersionAffectedModules     []string             `json:"version_affected_modules,omitempty"`
	UnresolvedModules          []string             `json:"unresolved_modules,omitempty"`
	Limitations                []string             `json:"limitations"`
	EvidenceRefs               []string             `json:"evidence_refs"`
	ConclusionScope            string               `json:"conclusion_scope"`
	AdvisoryScopeStatus        string               `json:"advisory_scope_status"`
	Basis                      []ApplicabilityBasis `json:"basis"`
	EvaluatedEntryIDs          []string             `json:"evaluated_entry_ids,omitempty"`
	AdvisoryEntryStatus        string               `json:"advisory_entry_status,omitempty"`
	VulnerableCodeReachability string               `json:"vulnerable_code_reachability,omitempty"`
}

// ExploitationCondition is one predicate of the attack model.
// Axis is the Slice-2 optional axis tag (§2.3); empty in legacy reports.
// Role is the slice2-fidelity/3 condition role derived by the assembler
// from the fixed subject table; empty in legacy and /2 reports.
type ExploitationCondition struct {
	ID           string   `json:"id"`
	Subject      string   `json:"subject"`
	Scope        string   `json:"scope"`
	Necessity    string   `json:"necessity"` // required|supporting|unknown
	Statement    string   `json:"statement"`
	Origin       string   `json:"origin"` // deterministic|agent
	State        string   `json:"state"`
	EvidenceRefs []string `json:"evidence_refs"`
	Limitations  []string `json:"limitations"`
	Axis         string   `json:"axis"`           // code_reachability|attack_surface_availability|exploitation_established|other
	Role         string   `json:"role,omitempty"` // applicability|path|deployment|supporting
	// UsageSubject binds a deterministic package-usage condition to the
	// advisory-declared candidate it covers, so a cited PACKAGE_USAGE
	// fact can be checked against exactly this module/package/symbol —
	// never a different candidate's. Nil on every other condition and on
	// agent-origin rows; omitempty keeps legacy /1//2 wire shape.
	UsageSubject *FactUsageSubject `json:"usage_subject,omitempty"`
}

// Section is a status-bearing assessment section (six of the eight).
type Section struct {
	Status      string   `json:"status"`
	Summary     string   `json:"summary"`
	Claims      []Claim  `json:"claims"`
	Limitations []string `json:"limitations"`
}

// Claim is the section claim shape; origin=deterministic is valid only
// when evidence_refs resolve into verified_facts.
type Claim struct {
	ID           string   `json:"id"`
	Statement    string   `json:"statement"`
	Subject      string   `json:"subject"`
	Scope        string   `json:"scope"`
	State        string   `json:"state"`
	EvidenceRefs []string `json:"evidence_refs"`
	Limitations  []string `json:"limitations"`
	Origin       string   `json:"origin"`
	// AssumptionIDs names the admitted declared-assumptions/1 members a
	// deterministic claim rests on. The ids resolve only against
	// input.declared_assumptions and never join EvidenceRefs: a policy
	// input is not measured evidence.
	AssumptionIDs []string `json:"assumption_ids,omitempty"`
}

// EvidenceReference is one row of evidence_quality.references.
// Materiality is Slice-2 (§2.6); nil in legacy references.
type EvidenceReference struct {
	Ref         string       `json:"ref"`
	Kind        string       `json:"kind"` // observation|snapshot-source|advisory|agent-source
	Path        string       `json:"path"`
	Selector    string       `json:"selector"`
	SHA256      string       `json:"sha256,omitempty"`
	Materiality *Materiality `json:"materiality,omitempty"`
}

// EvidenceQuality is the non-status eighth assessment member plus
// coverage/conflicts accounting. status is still required by §4.
type EvidenceQuality struct {
	Status      string              `json:"status"`
	Summary     string              `json:"summary"`
	References  []EvidenceReference `json:"references"`
	Coverage    []string            `json:"coverage"`
	Conflicts   []string            `json:"conflicts"`
	Limitations []string            `json:"limitations"`
}

// ResidualQuestion is the rendered quality-contract question list; it
// shares IDs one-to-one with OpenQuestions.
type ResidualQuestion struct {
	ID           string   `json:"id"`
	Question     string   `json:"question"`
	Why          string   `json:"why"`
	NextCheck    string   `json:"next_check"`
	EvidenceRefs []string `json:"evidence_refs"`
}

// TriageRecommendation is review guidance, never an authoritative action.
type TriageRecommendation struct {
	Action       string   `json:"action"` // fix|verify|low confirmed risk|needs review
	Reason       string   `json:"reason"`
	Bounds       string   `json:"bounds"`
	EvidenceRefs []string `json:"evidence_refs"`
}

// ArtifactRef points at a persisted file under the output dir.
// SizeBytes is Slice-2 (§2.6); zero in legacy references.
type ArtifactRef struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes,omitempty"`
	Selector  string `json:"selector,omitempty"`
}

// Fact kinds for verified_facts. Empty keeps the legacy shape — facts
// promoted before package-usage existed carry no kind.
const (
	// FactKindPackageUsage marks a fact promoted from a package-usage
	// observation (Task 3): the claim answers "does product source use
	// the advisory-declared package/symbol" inside the recorded scope.
	// Only a genuine USED (Claim=TRUE) or a VERIFIED NOT_USED
	// (Claim=FALSE) verdict carries this kind — it is the only
	// usage-fact kind that may underwrite a path condition.
	FactKindPackageUsage = "PACKAGE_USAGE"
	// FactKindPackageUsageLowerBound marks a fact promoted from an
	// undetermined (UNKNOWN) package-usage observation that still
	// recorded concrete positive content: the positive is a lower
	// bound inside an open scope. It is distinct from
	// FactKindPackageUsage precisely so it can never be mistaken for a
	// USED verdict or close a path condition.
	FactKindPackageUsageLowerBound = "PACKAGE_USAGE_LOWER_BOUND"
	// FactKindBuildUsageScope marks a fact promoted from a usage-scope
	// observation (B41): the claim records which recorded build
	// closure — product and/or test — reaches the advisory-declared
	// package, or a module-level aggregate when no package candidate
	// exists. It is strictly non-carrier: it is never a product-source
	// usage verdict, never a negative claim, never closes an
	// exploitation condition and never enters evidence_level. Its
	// claim is always TRUE (a recorded build-closure classification,
	// including the undetermined usage_scope=unknown class for a
	// target absent from both closed closures).
	FactKindBuildUsageScope = "BUILD_USAGE_SCOPE"
)

// Negative verification states on a verified fact.
const (
	// NegativeVerificationVerified marks a bounded negative that passed
	// the closed-scope verification; it is recorded on the fact so the
	// negative's audit boundary travels with the claim, never as a
	// safe conclusion. B41 never reuses it: a BUILD_USAGE_SCOPE fact
	// carries ProductAbsenceVerification instead.
	NegativeVerificationVerified = "VERIFIED"
)

// Usage-negative bases on a PACKAGE_USAGE fact (verified_facts.
// usage_basis): which closed negative-verification basis a FALSE
// package-usage claim records. Empty keeps the legacy shape — facts
// promoted before the basis member existed behave exactly as
// UsageBasisPresentUnused.
const (
	// UsageBasisPresentUnused is the bounded basis: the target package
	// was present in the linked product closure and no product-source
	// use was found. A bounded usage negative does not prove
	// reachability — a REFUTED path on this basis can never accompany
	// vulnerable_code_reachability=FALSE or a SUPPORTED NON_APPLICABLE
	// classification.
	UsageBasisPresentUnused = "present_unused"
	// UsageBasisAbsentFromClosure is the stronger basis: the target
	// package is provably absent from a complete product closure, so
	// no product source can statically reach it. It is package-level
	// only (symbol subjects keep the linked-package premise), and the
	// negative stays bounded to static analysis — the citing
	// condition must still name the runtime/dynamic boundary.
	UsageBasisAbsentFromClosure = "absent_from_closure"
)

// UsageScope is the build-closure classification a BUILD_USAGE_SCOPE
// fact records (B41): which of the two recorded go list closures —
// product (`go list -deps -json ./...`, no -test) and test
// (`go list -deps -test -json ./...` via recognized test-variant/
// test-driver roots) — reaches the target. test-only requires both
// closures complete plus the target absent from the product closure;
// unknown records a closed paired stream whose target is absent from
// both closures — an undetermined class, never a non-use or safety
// claim.
type UsageScope string

// Usage-scope classes on a BUILD_USAGE_SCOPE fact (verified_facts.
// usage_scope).
const (
	UsageScopeProduct  UsageScope = "product"
	UsageScopeTestOnly UsageScope = "test-only"
	UsageScopeMixed    UsageScope = "mixed"
	UsageScopeUnknown  UsageScope = "unknown"
)

// Product-absence verification marker on a BUILD_USAGE_SCOPE fact:
// the product-side half of the paired-stream test-only classification
// passed the closed product-closure check. It is recorded only with
// usage_scope=test-only and is bounded to the recorded no-test closure
// — never a runtime, deployment or safety claim and never a
// substitution for B42 negative_verification.
const ProductAbsenceVerificationVerified = "VERIFIED"

// ProductAbsenceVerificationVendorInventory is the second, narrower B41
// product-absence marker: a closed offline vendor/source derivation
// (closure_source=vendor/modules.txt+source-imports,
// closure_semantics=product_all_packages, vendor_mode=true) proved the
// exact advisory-bound subject absent from the product build closure
// under a complete consistency-checked vendor inventory. It is recorded
// only with usage_scope=unknown (product_linked=false,
// test_linked=false) — the class stays absent-from-both, never
// test-only — and means exactly "absent from the product build closure
// under the recorded closed vendor inventory": never a runtime,
// deployment, safety, applicability or VEX claim and never a
// substitution for B42 negative_verification. An unknown class without
// either valid marker remains undetermined and is never negative proof.
const ProductAbsenceVerificationVendorInventory = "VERIFIED_VENDOR_INVENTORY"

// FactUsageSubject is the structured advisory-declared subject a
// package-usage (B42) or build-usage-scope (B41) fact is bound to: the
// module entry plus the checked package and (for a B42 symbol-level
// check) symbol. It lets validators and condition emitters tie a fact
// to exactly the subject the tool was invoked for, so a fact for one
// subject can never be cited for another. For B41 the subject is the
// identity binding only: a package check carries {Module, Package,
// Symbol:""} and a module-level aggregate carries {Module,
// Package:"", Symbol:""} — an empty package is legal on
// BUILD_USAGE_SCOPE facts only (the B41 validator decides, never the
// B42 rules) and is never a package-level proof.
type FactUsageSubject struct {
	Module  string `json:"module,omitempty"`
	Package string `json:"package"`
	Symbol  string `json:"symbol,omitempty"`
}

// FactProvenance attributes a verified fact to the deterministic lane.
type FactProvenance struct {
	ObservationID string `json:"observation_id"`
	Source        string `json:"source"`
	GeneratedAt   string `json:"generated_at"`
}

// VerifiedFact is a successful (status=OK) deterministic observation
// promoted into the report's closed fact list.
type VerifiedFact struct {
	ID string `json:"id"`
	// Kind names the fact family (empty for legacy facts); a
	// PACKAGE_USAGE fact claims product-source usage of an
	// advisory-declared package/symbol inside the recorded scope.
	Kind string `json:"kind,omitempty"`
	// UsageSubject binds a package-usage or build-usage-scope fact to
	// exactly the advisory-declared subject the tool checked; nil for
	// legacy facts.
	UsageSubject *FactUsageSubject `json:"usage_subject,omitempty"`
	// UsageScope records the build-closure class on a
	// kind=BUILD_USAGE_SCOPE fact (B41 only): product, test-only,
	// mixed or unknown. It is a build-graph classification, never a
	// source-usage verdict or a safety claim.
	UsageScope string `json:"usage_scope,omitempty"`
	// ProductAbsenceVerification is the B41 marker that the product
	// side of the paired build-closure stream was closed and the
	// target is absent from it: VERIFIED only with
	// usage_scope=test-only; VERIFIED_VENDOR_INVENTORY only with
	// usage_scope=unknown under the closed vendor-inventory
	// derivation. Distinct from NegativeVerification, which stays
	// B42-only.
	ProductAbsenceVerification string         `json:"product_absence_verification,omitempty"`
	Statement                  string         `json:"statement"`
	Claim                      string         `json:"claim"` // TRUE|FALSE
	Tool                       string         `json:"tool"`
	ToolVersion                string         `json:"tool_version"`
	Command                    string         `json:"command"`
	Scope                      string         `json:"scope"`
	Status                     string         `json:"status"` // always OK
	Coverage                   string         `json:"coverage"`
	SnapshotContentHash        string         `json:"snapshot_content_hash"`
	ExternalCommitSHA          *string        `json:"external_commit_sha"`
	InputDigest                string         `json:"input_digest"`
	DataDigest                 string         `json:"data_digest"`
	Artifact                   ArtifactRef    `json:"artifact"`
	Provenance                 FactProvenance `json:"provenance"`
	Limitations                []string       `json:"limitations"`
	// NegativeVerification records the bounded negative-verification
	// state of a FALSE package-usage claim (VERIFIED); never set on a
	// positive or legacy fact.
	NegativeVerification string `json:"negative_verification,omitempty"`
	// UsageBasis records which closed negative-verification basis a
	// FALSE package-usage claim carries: present_unused (the target
	// was linked but unused) or absent_from_closure (the target is
	// provably absent from a complete product closure). Empty on a
	// positive, a non-package-usage or a legacy fact; legacy facts
	// read as the bounded present-unused basis.
	UsageBasis  string       `json:"usage_basis,omitempty"`
	Materiality *Materiality `json:"materiality,omitempty"`
}

// AgentAssertion is an agent claim kept under its own provenance; it is
// never promoted into verified_facts. OriginalText and SourceSelector
// are Slice-2 (§2.7): the exact parsed statement (never truncated) and
// a selector into the retained answer; empty in legacy reports.
type AgentAssertion struct {
	ID             string   `json:"id"`
	Statement      string   `json:"statement"`
	Subject        string   `json:"subject"`
	Scope          string   `json:"scope"`
	State          string   `json:"state"`
	Basis          string   `json:"basis"`
	EvidenceRefs   []string `json:"evidence_refs"`
	Limitations    []string `json:"limitations"`
	OriginalText   string   `json:"original_text"`
	SourceSelector string   `json:"source_selector"`
}

// UnknownEntry records an explicit unknown with a follow-up action.
// Group/Priority/DecisionChangingFor are Slice-2 (§2.5); empty in
// legacy reports (which default to APPENDIX).
type UnknownEntry struct {
	ID                  string   `json:"id"`
	Statement           string   `json:"statement"`
	Reason              string   `json:"reason"`
	FollowUp            string   `json:"follow_up"`
	EvidenceRefs        []string `json:"evidence_refs"`
	Group               string   `json:"group"`
	Priority            string   `json:"priority"`
	DecisionChangingFor *string  `json:"decision_changing_for"`
}

// OpenQuestion is the research-model question list (paired with
// ResidualQuestions by id).
type OpenQuestion struct {
	ID           string   `json:"id"`
	Question     string   `json:"question"`
	Subject      string   `json:"subject"`
	Scope        string   `json:"scope"`
	NextCheck    string   `json:"next_check"`
	EvidenceRefs []string `json:"evidence_refs"`
}

// Recommendation is a human-owned next step.
type Recommendation struct {
	ID           string   `json:"id"`
	Action       string   `json:"action"`
	Owner        string   `json:"owner"` // human|operator|engineering
	Reason       string   `json:"reason"`
	EvidenceRefs []string `json:"evidence_refs"`
}

// AgentReplayProvenance records that the agent_output object was rebuilt
// verbatim from a persisted run directory (--replay-agent-turn): no model
// call, no harness invocation happened in this run. Present only on
// replayed reports; nil on live or deterministic-only runs.
type AgentReplayProvenance struct {
	// Dir is the persisted run directory the turn was replayed from.
	Dir               string `json:"dir"`
	AnswerSHA256      string `json:"answer_sha256,omitempty"`
	ResultSHA256      string `json:"result_sha256,omitempty"`
	OriginalRunID     string `json:"original_run_id,omitempty"`
	OriginalAttemptID string `json:"original_attempt_id,omitempty"`
}

// AgentRawArtifact references the retained harness result.
type AgentRawArtifact struct {
	Path   *string `json:"path"`
	SHA256 *string `json:"sha256"`
}

// AgentOutput is the terminal record of the selected agent attempt.
// AttemptID/ResultArtifact/AnswerArtifact/Extraction are Slice-2
// (§2.7); RawArtifact stays the legacy alias for backward parsing.
// ReplayedFrom (omitempty) marks an agent_output rebuilt verbatim from a
// persisted run directory — the replay provenance record.
type AgentOutput struct {
	Status         string                 `json:"status"`
	Category       *string                `json:"category"`
	Reasoning      *string                `json:"reasoning"`
	RawArtifact    AgentRawArtifact       `json:"raw_artifact"`
	AttemptID      *string                `json:"attempt_id"`
	ResultArtifact *AttemptArtifact       `json:"result_artifact"`
	AnswerArtifact *AttemptArtifact       `json:"answer_artifact"`
	Extraction     *Extraction            `json:"extraction"`
	ReplayedFrom   *AgentReplayProvenance `json:"replayed_from,omitempty"`
}

// Disposition is fixed: the report supports human triage only.
type Disposition struct {
	Class            string   `json:"class"`
	AutoClose        bool     `json:"auto_close"`
	Reason           string   `json:"reason"`
	ForbiddenClasses []string `json:"forbidden_classes"`
}

// statusSections returns the six status-bearing sections with their
// names, in report order, for uniform validation/rendering.
func (r *Report) statusSections() []struct {
	Name string
	Sec  *Section
} {
	return []struct {
		Name string
		Sec  *Section
	}{
		{"vulnerability_mechanism", &r.VulnerabilityMechanism},
		{"root_cause", &r.RootCause},
		{"attack_scenario", &r.AttackScenario},
		{"product_exposure", &r.ProductExposure},
		{"alternative_paths", &r.AlternativePaths},
		{"evidence_quality", &Section{
			Status:      r.EvidenceQuality.Status,
			Summary:     r.EvidenceQuality.Summary,
			Limitations: r.EvidenceQuality.Limitations,
		}},
	}
}

// agentAssessment mirrors the prompt contract's `assessment` object: the
// eight research members the agent must emit. Members may be strings or
// objects; normalization lives in assemble.go.
type agentAssessment struct {
	VulnerabilityMechanism json.RawMessage `json:"vulnerability_mechanism"`
	RootCause              json.RawMessage `json:"root_cause"`
	AttackScenario         json.RawMessage `json:"attack_scenario"`
	ProductExposure        json.RawMessage `json:"product_exposure"`
	AlternativePaths       json.RawMessage `json:"alternative_paths"`
	EvidenceQuality        json.RawMessage `json:"evidence_quality"`
	ResidualQuestions      json.RawMessage `json:"residual_questions"`
	TriageRecommendation   json.RawMessage `json:"triage_recommendation"`
}

// FalsifierProposal is an agent-owned hypothesis about a condition that may
// falsify the advisory mechanism. It is never an authoritative claim.
type FalsifierProposal struct {
	Kind        domain.FalsifierKind `json:"kind"`
	ConditionID string               `json:"condition_id"`
	Module      string               `json:"module,omitempty"`
	Package     string               `json:"package,omitempty"`
	Symbol      string               `json:"symbol,omitempty"`
	ArgIndex    int                  `json:"arg_index,omitempty"`
	Statement   string               `json:"statement"`
	Scope       string               `json:"scope"`
	Subjects    []FactUsageSubject   `json:"subjects,omitempty"`
}

// VerificationRequest is one bounded, typed request for an existing
// evidence-tool capability. It carries no result or verdict fields.
// DerivedFrom records the advisory-text anchor a text-derived subject
// was admitted under (field + verbatim quote); nil for declared or
// unanchored subjects — provenance only, never a verdict input.
type VerificationRequest struct {
	ID          string             `json:"id"`
	Tool        string             `json:"tool"`
	Arguments   json.RawMessage    `json:"arguments"`
	Purpose     string             `json:"purpose"`
	ConditionID string             `json:"condition_id"`
	DerivedFrom *SubjectProvenance `json:"derived_from,omitempty"`
}

// VerificationPlan is an agent proposal only. Execution and authority belong
// to the deterministic verification lane.
type VerificationPlan struct {
	Falsifier FalsifierProposal     `json:"falsifier"`
	Checks    []VerificationRequest `json:"checks"`
}

// EvidenceDecision is the deterministic projection of independently checked
// evidence. Agent output and proposals are never authoritative inputs to a
// verdict without the checks performed by VerifyDecision.
type EvidenceDecision struct {
	Verdict              domain.Verdict               `json:"verdict"`
	Reason               string                       `json:"reason"`
	ConditionID          string                       `json:"condition_id,omitempty"`
	Falsifier            domain.FalsifierKind         `json:"falsifier,omitempty"`
	NegativeVerification *domain.NegativeVerification `json:"negative_verification,omitempty"`
	EvidenceRefs         []string                     `json:"evidence_refs,omitempty"`
	Scope                string                       `json:"scope"`
	Coverage             string                       `json:"coverage"`
	Limitations          []string                     `json:"limitations,omitempty"`
	HumanQuestions       []string                     `json:"human_questions,omitempty"`
	TicketRationale      string                       `json:"ticket_rationale"`
	AgentHypothesis      string                       `json:"agent_hypothesis,omitempty"`
	FalsifierStatement   string                       `json:"falsifier_statement,omitempty"`
	Checks               []DecisionCheck              `json:"checks,omitempty"`
	Sufficiency          string                       `json:"sufficiency,omitempty"`
	// AssumptionIDs names the admitted declared-assumptions/1 member ids
	// the decision relied on. They resolve only against
	// input.declared_assumptions — never against evidence_refs or
	// verified facts — so a policy input cannot masquerade as measured
	// evidence.
	AssumptionIDs []string `json:"assumption_ids,omitempty"`
	// GroundBasis names what a NO_EXPLOIT_PATH_FOUND decision rests on:
	// "config-origin" for the exact-argument post-reach route (traced
	// trigger arguments resolve to administrator-managed configuration
	// under a declared config-trust assumption), "declared-trust" or
	// "auto-perimeter" for deployment trust boundaries. Empty means the
	// decision is grounded by code-level verification. The field is a
	// verdict basis, never evidence.
	GroundBasis string `json:"ground_basis,omitempty"`
}

// DecisionCheck records an actually executed verification check. It is
// deliberately separate from legacy verified facts and never upgrades a
// degraded observation. DerivedFrom mirrors the request's anchor
// provenance when the check's subject was derived from advisory text.
type DecisionCheck struct {
	ID           string             `json:"id"`
	Tool         string             `json:"tool"`
	Status       string             `json:"status"`
	Completeness string             `json:"completeness"`
	Scope        string             `json:"scope"`
	Coverage     string             `json:"coverage,omitempty"`
	EvidenceRefs []string           `json:"evidence_refs,omitempty"`
	Limitations  []string           `json:"limitations,omitempty"`
	DerivedFrom  *SubjectProvenance `json:"derived_from,omitempty"`
}

// VerifiedFalsifierInput is a deterministic authority result. It is
// deliberately separate from FalsifierProposal so agent output cannot act
// as authority.
type VerifiedFalsifierInput struct {
	Kind        domain.FalsifierKind `json:"kind"`
	ConditionID string               `json:"condition_id"`
	RuleID      string               `json:"rule_id"`
	Subjects    []FactUsageSubject   `json:"subjects"`
}

// DecisionInput contains the retained lane, proposal, deterministic authority
// input and verification trace.
type DecisionInput struct {
	Lane             *LaneResult
	Proposal         *FalsifierProposal
	Authority        *VerifiedFalsifierInput
	Trace            *VerificationTrace
	AgentTurn        *AgentTurn
	Source           *goanalysis.Index
	ObservationIndex map[string][]string
	// Audit is the drained session audit — the independent record of what
	// each verification tool was asked and what it returned. The
	// declared-symbol authority route decodes payloads only from here, so
	// a caller-constructed trace copy cannot act as proof.
	Audit []evidencetools.AuditRecord
}

// agentAnswer is the single JSON object the pinned prompt requires.
type agentAnswer struct {
	Category         string            `json:"category"`
	Reasoning        string            `json:"reasoning"`
	Assessment       json.RawMessage   `json:"assessment"`
	VerificationPlan *VerificationPlan `json:"verification_plan,omitempty"`
	planLimitations  []string          `json:"-"`
	// ImplementationLocusProposals are admitted non-authoritative locus
	// hypotheses. Invalid or forbidden proposal members are dropped and
	// named in proposalLimitations; they never become evidence.
	ImplementationLocusProposals []domain.ImplementationLocusProposal `json:"-"`
	// ExploitLocusProposals are admitted non-authoritative exploit-locus
	// hypotheses (sink identity, trigger argument, vulnerable locus).
	// They never become evidence or a verdict input.
	ExploitLocusProposals []domain.ExploitLocusProposal `json:"-"`
	proposalLimitations   []string                      `json:"-"`
}

// UnmarshalJSON keeps a malformed or unbound proposal non-authoritative while
// preserving the otherwise valid answer for limitation reporting. The raw
// answer bytes and extraction selector remain owned by the caller.
func (a *agentAnswer) UnmarshalJSON(b []byte) error {
	type wire struct {
		Category                     string          `json:"category"`
		Reasoning                    string          `json:"reasoning"`
		Assessment                   json.RawMessage `json:"assessment"`
		VerificationPlan             json.RawMessage `json:"verification_plan"`
		ImplementationLocusProposals json.RawMessage `json:"implementation_locus_proposals"`
		ExploitLocusProposals        json.RawMessage `json:"exploit_locus_proposals"`
	}
	var w wire
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	a.Category, a.Reasoning, a.Assessment = w.Category, w.Reasoning, w.Assessment
	a.VerificationPlan = nil
	a.planLimitations = nil
	a.ImplementationLocusProposals = nil
	a.proposalLimitations = nil
	a.ImplementationLocusProposals, a.proposalLimitations = parseImplementationLocusProposals(w.ImplementationLocusProposals)
	a.ExploitLocusProposals = nil
	var exploitLims []string
	a.ExploitLocusProposals, exploitLims = parseExploitLocusProposals(w.ExploitLocusProposals)
	a.proposalLimitations = append(a.proposalLimitations, exploitLims...)
	if len(w.VerificationPlan) == 0 || string(w.VerificationPlan) == "null" {
		return nil
	}
	plan, limitations := parseVerificationPlan(w.VerificationPlan)
	if plan != nil {
		a.VerificationPlan = plan
	}
	a.planLimitations = limitations
	return nil
}

// strPtr returns &s; nilStr returns nil for empty.
func strPtr(s string) *string { return &s }
func nilStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// claimResultString maps domain.ClaimResult to the report's TRUE/FALSE/UNKNOWN.
func claimResultString(c domain.ClaimResult) string {
	switch c {
	case domain.ClaimTrue:
		return "TRUE"
	case domain.ClaimFalse:
		return "FALSE"
	default:
		return "UNKNOWN"
	}
}

// optionalClaimResultString keeps the empty (never-recorded) state empty
// so additive axes do not change legacy report bytes; a recorded UNKNOWN
// still serializes as "UNKNOWN".
func optionalClaimResultString(c domain.ClaimResult) string {
	if c == "" {
		return ""
	}
	return claimResultString(c)
}

// unknownSummary formats the required non-bare UNKNOWN summary.
func unknownSummary(what, followUp string) string {
	return fmt.Sprintf("UNKNOWN: %s; follow-up: %s", what, followUp)
}

// isUnknownSummary reports whether s satisfies the
// `UNKNOWN: ...; follow-up: ...` contract: it must start with the
// UNKNOWN: marker and name a follow-up action. A bare UNKNOWN fails.
func isUnknownSummary(s string) bool {
	t := strings.TrimSpace(s)
	if !strings.HasPrefix(t, "UNKNOWN:") {
		return false
	}
	rest := strings.ToLower(t[len("UNKNOWN:"):])
	return strings.Contains(rest, "follow-up:") &&
		strings.TrimSpace(rest[strings.Index(rest, "follow-up:")+len("follow-up:"):]) != ""
}

// entryEvaluated reports whether the deterministic resolver actually
// probed the advisory entry against the product: its module appears in
// the checked/selected/pending sets, or (module-less Go entries) the
// module graph resolved as present. Presence-evaluated but absent
// modules count as evaluated (their fix status was still not decided —
// see entryStatus).
func entryEvaluated(im AffectedImplementation, pa ProductApplicability) bool {
	if im.Ecosystem != "Go" {
		return false
	}
	if im.Module == "" {
		return pa.ModulePresent == "TRUE"
	}
	for _, m := range pa.CheckedModules {
		if m == im.Module {
			return true
		}
	}
	for _, m := range pa.SelectedModules {
		if m == im.Module {
			return true
		}
	}
	for _, m := range pa.PendingModules {
		if m == im.Module {
			return true
		}
	}
	return pa.SelectedModule != nil && *pa.SelectedModule == im.Module
}

// entryStatus labels one advisory entry for the fixed/affected split used
// by the implementations table and the advisory_entry_status aggregate.
// "" means the entry carries no per-entry version verdict (never
// evaluated, or presence/module-level only).
//
// The label is per-component: the aggregate version_affected describes
// only the version-affected entry, so a multi-module advisory where one
// entry resolves fixed and another stays affected must read
// fixed/affected per entry (aggregate MIXED), never "affected" for all.
// unresolved_modules (and its linked subset pending_modules) name modules
// whose version is undecidable — they take precedence over selection:
// a pending module can never be labelled fixed or affected.
// selected_modules name modules the resolver selected as
// version-affected (pre-probe) or whose package is linked into the
// product (post-probe) — both are affected-side membership;
// selected_module under version_affected=TRUE pins the confirmed
// affected entry even when the package probe reports it unlinked.
func entryStatus(im AffectedImplementation, pa ProductApplicability) string {
	if im.Ecosystem != "Go" || pa.ModulePresent != "TRUE" {
		return ""
	}
	if im.Module == "" {
		// Module-less Go entries inherit the aggregate verdict exactly as
		// before: the resolver evaluated presence+version on the module
		// graph without naming a module.
		switch pa.VersionAffected {
		case "FALSE":
			return "fixed"
		case "TRUE":
			return "affected"
		}
		return ""
	}
	for _, m := range pa.UnresolvedModules {
		if m == im.Module {
			return "unknown"
		}
	}
	for _, m := range pa.PendingModules {
		if m == im.Module {
			return "unknown"
		}
	}
	if pa.VersionAffected == "TRUE" {
		// version_affected_modules keeps the version-side membership even
		// when the package probe dropped an entry from selected_modules:
		// package absence is a reachability result, not a version result.
		for _, m := range pa.VersionAffectedModules {
			if m == im.Module {
				return "affected"
			}
		}
		// selected_modules names version-affected entries (pre-probe)
		// or entries whose package is linked into the product
		// (post-probe); selected_module pins the confirmed affected
		// entry even when the package probe left it unlinked. Both
		// signals name an affected entry only under a TRUE version
		// verdict — under UNKNOWN the version side was never decided.
		for _, m := range pa.SelectedModules {
			if m == im.Module {
				return "affected"
			}
		}
		if pa.SelectedModule != nil && *pa.SelectedModule == im.Module {
			return "affected"
		}
	}
	if tc := pa.TicketCheck; tc != nil {
		for _, m := range tc.BlockedModules {
			if m == im.Module {
				// The version-axis refusal covers this entry: the
				// ticket declared a different package version, so the
				// analyzed build's out-of-range resolution can never
				// be labelled "fixed" for the ticket's subject.
				return "unknown"
			}
		}
	}
	for _, m := range pa.CheckedModules {
		if m == im.Module {
			// Checked but neither selected nor unresolved/pending: the
			// module resolved outside the entry's affected ranges.
			return "fixed"
		}
	}
	return ""
}

// evaluatedEntryIDs returns the ids of advisory entries the
// deterministic resolver probed (see entryEvaluated), in advisory order.
// fillApplicability and the validator share it so evaluated_entry_ids and
// the implementations table can never drift.
func evaluatedEntryIDs(impls []AffectedImplementation, pa ProductApplicability) []string {
	var out []string
	for _, im := range impls {
		if entryEvaluated(im, pa) {
			out = append(out, im.ID)
		}
	}
	return out
}

// aggregateEntryStatus folds the per-entry verdicts of entryStatus into
// the advisory_entry_status aggregate. NOT_EVALUATED covers the
// module-absent case and the empty evaluated set. AFFECTED/FIXED require
// every evaluated entry to carry that same verdict; MIXED is emitted
// whenever evaluated entries split across at least two of the verdict
// kinds {affected, fixed, unknown}; everything else is UNKNOWN.
func aggregateEntryStatus(impls []AffectedImplementation, pa ProductApplicability) string {
	if pa.ModulePresent != "TRUE" {
		return EntryNotEvaluated
	}
	fixed, affected, unknown, other := 0, 0, 0, 0
	for _, im := range impls {
		if !entryEvaluated(im, pa) {
			continue
		}
		switch entryStatus(im, pa) {
		case "fixed":
			fixed++
		case "affected":
			affected++
		case "unknown":
			unknown++
		default:
			other++
		}
	}
	total := fixed + affected + unknown + other
	if total == 0 {
		return EntryNotEvaluated
	}
	kinds := 0
	for _, n := range []int{fixed, affected, unknown} {
		if n > 0 {
			kinds++
		}
	}
	status := EntryUnknown
	switch {
	case kinds >= 2:
		status = EntryMixed
	case affected > 0 && affected == total:
		status = EntryAffected
	case fixed > 0 && fixed == total:
		status = EntryFixed
	}
	// A FIXED aggregate without a resolved version would violate the
	// contract's FIXED requirements — demote defensively.
	if status == EntryFixed && pa.ResolvedVersion == nil {
		status = EntryUnknown
	}
	return status
}

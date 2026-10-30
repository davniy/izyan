// Package heldoutgate implements the offline held-out gate of
// docs/dev/plans/universal-verifier-plan.md §8 and Task 5.
//
// The gate is a validation harness, not a decision component: it replays
// the persisted corporate corpus through internal/claimshape +
// internal/verification, re-derives the deterministic absence probes on
// the pinned worktrees (deterministic tool calls only — never an LLM),
// applies the stability controller to the recorded 5×3 variance series
// and aggregates the §8.3 metrics: hard gates, proof soundness, admission
// coverage, human alignment, stability and the precision bound.
//
// Nothing here changes production behavior: the package is consumed only
// by cmd/heldout-gate and its own tests. The capability admission path
// stays default-off; this package only measures.
package heldoutgate

import "encoding/json"

// GateSchemaVersion identifies the persisted gate-report schema.
const GateSchemaVersion = "heldout-gate.v1"

// CorpusRunRow is the per-run replay record: the compiled disposition
// under the corrected attempt binding plus the diagnostic value the
// published ReplayRun produces, the condition surface behind every
// reduction and the admission-rejection histogram.
type CorpusRunRow struct {
	Ticket           string `json:"ticket"`
	RunDir           string `json:"run_dir"`
	FindingID        string `json:"finding_id,omitempty"`
	AttemptRunID     string `json:"attempt_run_id,omitempty"`
	SourceID         string `json:"source_id,omitempty"`
	SelectedRef      string `json:"selected_ref,omitempty"`
	AdvisoryFamily   string `json:"advisory_family,omitempty"`
	AdvisoryID       string `json:"advisory_id,omitempty"`
	GroupKey         string `json:"group_key"`
	LLMVerdict       string `json:"llm_verdict,omitempty"`
	InternalStatus   string `json:"internal_status,omitempty"`
	Human            string `json:"human,omitempty"`
	HumanReasonClass string `json:"human_reason_class,omitempty"`

	Disposition string `json:"disposition"` // DISMISSED | LOWERED | UNCHANGED
	Rule        string `json:"rule,omitempty"`
	Reason      string `json:"reason,omitempty"`
	// DispositionPublished is what verify.ReplayRun compiles from
	// the same artifacts — the run-binding defect keeps it UNCHANGED.
	DispositionPublished string `json:"disposition_published_replay"`

	Claims            int            `json:"claims"`
	BoundObservations int            `json:"bound_observations"`
	Admitted          int            `json:"admitted_observations"`
	RejectReasons     map[string]int `json:"reject_reasons,omitempty"`
	ReportHash        string         `json:"report_hash,omitempty"`
	SemanticHash      string         `json:"semantic_hash,omitempty"`
	DecisiveHash      string         `json:"decisive_hash,omitempty"`
	Conditions        []ConditionRow `json:"conditions,omitempty"`
	Alarms            []string       `json:"-"`
	Warnings          []string       `json:"warnings,omitempty"`
	Unverified        bool           `json:"unverified_reduction,omitempty"`
}

// ConditionRow projects one graph condition for the audit surface.
type ConditionRow struct {
	ID               string   `json:"id"`
	Mandatory        string   `json:"mandatory"`
	Value            string   `json:"value"`
	FalsifiedBy      string   `json:"falsified_by,omitempty"`
	Falsifiers       []string `json:"falsifiers,omitempty"`
	Contested        []string `json:"contested,omitempty"`
	ExpectedSubjects []string `json:"expected_subjects,omitempty"`
	Reason           string   `json:"reason,omitempty"`
}

// AbsenceGroupRow records one kernel-spec absence group: the recorded
// matrix line, the deterministically re-derived observation, parity of
// the two, and the admission outcome the contract produced.
type AbsenceGroupRow struct {
	GroupKey string   `json:"group_key"`
	Repo     string   `json:"repo"`
	Ref      string   `json:"ref"`
	Advisory string   `json:"advisory"`
	Module   string   `json:"module"`
	Tickets  []string `json:"tickets"`
	Subjects int      `json:"subjects"`

	MatrixRecorded ProbeSummary `json:"matrix_recorded"`
	ReDerived      ProbeSummary `json:"rederived"`
	ParityOK       bool         `json:"parity_ok"`
	ParityDiffs    []string     `json:"parity_diffs,omitempty"`

	// Observation provenance actually stamped on the contract record.
	SnapshotHash     string `json:"snapshot_hash,omitempty"`
	BuildContextHash string `json:"build_context_hash,omitempty"`

	ClaimOutcome string `json:"claim_outcome"`
	Predicate    string `json:"predicate"`
	Established  string `json:"established,omitempty"`
	Admitted     int    `json:"admitted_observations"`
	// UniversalAdmitted counts admissions on closed-scope contract
	// directions; CounterexampleAdmissions the existential counter-
	// example admissions a non-eligible record may legitimately yield.
	UniversalAdmitted        int            `json:"universal_admitted"`
	CounterexampleAdmissions int            `json:"counterexample_admissions,omitempty"`
	DynamicMarkers           int            `json:"dynamic_markers"`
	RejectReasons            map[string]int `json:"reject_reasons,omitempty"`
	Disposition              string         `json:"disposition"`
	Rule                     string         `json:"rule,omitempty"`

	EligibleForAdmission bool   `json:"eligible_for_admission"`
	ProofEligible        bool   `json:"proof_eligible"` // complete absence proof: all expected subjects absent
	SoundnessOK          bool   `json:"soundness_ok"`
	SoundnessNote        string `json:"soundness_note,omitempty"`
	Error                string `json:"error,omitempty"`
}

// ProbeSummary is the recorded or re-derived headline of one
// verify_code_absence call.
type ProbeSummary struct {
	Status          string   `json:"status"`
	Completeness    string   `json:"completeness"`
	Checked         int      `json:"checked"`
	Absent          int      `json:"absent"`
	Present         int      `json:"present"`
	ClosureComplete bool     `json:"closure_complete"`
	OpenExceptions  int      `json:"open_exceptions"`
	Limitations     []string `json:"limitations,omitempty"`
}

// MutationRow is the §8.4 result of one generic mutation applied to a
// re-derived eligible observation: the contract must refuse admission.
type MutationRow struct {
	GroupKey        string `json:"group_key"`
	Mutation        string `json:"mutation"`
	Want            string `json:"want"`
	GotDisposition  string `json:"got_disposition"`
	GotEstablished  string `json:"got_established"`
	AdmissionReason string `json:"admission_reason,omitempty"`
	Pass            bool   `json:"pass"`
}

// StabilityRow is the stability-controller verdict over one variance
// ticket's three recorded attempts.
type StabilityRow struct {
	Ticket        string   `json:"ticket"`
	LLMVerdicts   []string `json:"llm_verdicts"`
	LLMUnstable   bool     `json:"llm_unstable"`
	Attempts      int      `json:"attempts"`
	Dispositions  []string `json:"dispositions"`
	Stable        bool     `json:"stable"`
	SemanticDrift bool     `json:"semantic_drift"`
	Drift         bool     `json:"drift"`
	Disposition   string   `json:"disposition"` // effective, post-adjudication
	DemotedFrom   string   `json:"demoted_from,omitempty"`
	Reduction     bool     `json:"reduction"`
	Error         string   `json:"error,omitempty"`
}

// FoldRow is one grouped hold-out fold of §8.2: every member of the fold
// shares neither repository nor advisory family with any other fold's
// evaluation set — the grouping key is the group, never the row.
type FoldRow struct {
	Fold     int      `json:"fold"`
	GroupKey string   `json:"group_key"`
	Tickets  []string `json:"tickets"`
}

// GateCheck is one named §8.3 hard gate with its measured value.
type GateCheck struct {
	Name     string `json:"name"`
	Required string `json:"required"`
	Observed string `json:"observed"`
	Pass     bool   `json:"pass"`
	Detail   string `json:"detail,omitempty"`
}

// GateReport is the full §8.3 measurement.
type GateReport struct {
	SchemaVersion string `json:"schema_version"`

	CorpusRuns int `json:"corpus_runs"`
	// CorpusSHA256 pins the measured corpus content: sha256 over
	// "ticket\trun-dir-basename\treport-hash" rows in run order. Two
	// gate runs over the same corpus produce the same value; any
	// corpus drift (added/removed/re-derived run) changes it.
	CorpusSHA256 string `json:"corpus_sha256"`
	Claims       int    `json:"corpus_claims"`
	// Reductions the deterministic graph compiled on the corpus (all
	// must be zero on an all-NE corpus for the gates to hold).
	CorpusDismissed int `json:"corpus_dismissed"`
	CorpusLowered   int `json:"corpus_lowered"`

	ProbeGroups        int `json:"probe_groups"`
	ProbeParityOK      int `json:"probe_parity_ok"`
	ProbeEligible      int `json:"probe_eligible_for_admission"`
	ProbeProofEligible int `json:"probe_proof_eligible"`
	ProbeAdmitted      int `json:"probe_admitted"`
	ProbeDismissed     int `json:"probe_dismissed"`
	ProbeDisproved     int `json:"probe_disproved"`
	ProbeNonAdmitting  int `json:"probe_non_admitting"`

	MutationsTotal int `json:"mutations_total"`
	MutationsPass  int `json:"mutations_pass"`

	StabilityTickets   int `json:"stability_tickets"`
	StabilityReduction int `json:"stability_reductions"`

	ForeignAdmissions int `json:"foreign_cross_run_admissions"`
	Unverified        int `json:"unverified_reduction_count"`
	FalseSafe         int `json:"false_safe_count"`
	PartialConflict   int `json:"reductions_on_partial_unknown_conflict"`
	UnstableReduction int `json:"reductions_on_unstable_inputs"`
	// CounterexampleAdmissions counts existential REFUTES admissions on
	// non-eligible records — contract-legal, never a reduction ground.
	CounterexampleAdmissions int `json:"counterexample_admissions"`
	NonEligibleUniversal     int `json:"non_eligible_universal_admissions"`
	AlarmTickets             int `json:"alarm_tickets"`
	AlarmReductions          int `json:"alarm_reductions"`

	Admissions        int     `json:"independent_eligible_admissions"`
	ObservedPrecision float64 `json:"observed_precision"`
	PrecisionLower95  float64 `json:"precision_lower95_bound"`
	PrecisionProven   bool    `json:"precision_statistically_proven"`
	RecallMeasurable  bool    `json:"recall_exploitable_measurable"`

	Checks       []GateCheck       `json:"hard_gates"`
	Folds        []FoldRow         `json:"holdout_folds"`
	Runs         []CorpusRunRow    `json:"runs"`
	ProbeRows    []AbsenceGroupRow `json:"absence_groups"`
	MutationRows []MutationRow     `json:"mutations"`
	Stability    []StabilityRow    `json:"stability"`

	Defects     []string `json:"defects,omitempty"`
	Limitations []string `json:"limitations,omitempty"`

	// CapabilityGate is the Task-5 verdict: whether proof/dismissal
	// capability may leave default-off.
	CapabilityGate string `json:"capability_gate"`
}

// VarianceRecord mirrors one row of the recorded variance.json.
type VarianceRecord struct {
	Ticket         string   `json:"ticket"`
	Run            int      `json:"run"`
	Exit           int      `json:"exit"`
	Verdict        string   `json:"verdict"`
	Recommendation string   `json:"recommendation"`
	Limitations    []string `json:"limitations"`
}

// ComparisonRow mirrors the fields of comparison-pass6.json the gate
// consumes (human label, verdict label, family hints).
type ComparisonRow struct {
	Ticket           string `json:"ticket"`
	Human            string `json:"human"`
	HumanReasonClass string `json:"human_reason_class"`
	ToolVerdict      string `json:"tool_verdict"`
	Package          string `json:"package"`
	VulnIDs          string `json:"vuln_ids"`
}

// Marshal renders the report deterministically.
func (r *GateReport) Marshal() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

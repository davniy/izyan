package triage

import (
	"encoding/json"
	"time"

	"github.com/fedorovmv/izyan/internal/productb/vulnerability"
	"github.com/fedorovmv/izyan/internal/toolchain"
)

const (
	AuditEventRunStarted       = "run_started"
	AuditEventToolCall         = "tool_call"
	AuditEventDetTools         = "det_tools"
	AuditEventArtifactsWritten = "artifacts_written"
	AuditEventFactFeedback     = "fact_feedback"
	AuditEventRefResolution    = "ref_resolution"
	// AuditEventDecision records the deterministic composition of one
	// decision package: recommendation, profile, support and demotion
	// counts — the §6.5 audit event written after packaging.
	AuditEventDecision     = "decision"
	AuditEventMaterials    = "materials"
	AuditEventPackageCheck = "package_check"
	AuditEventToolchain    = "toolchain_resolution"
	// Stage 0 resolution events (spec §9.5): intake extraction and
	// validation, catalog source selection, materialization, advisory
	// freeze and the terminal error record.
	AuditEventIntakeResolution = "intake_resolution"
	AuditEventSourceResolution = "source_resolution"
	AuditEventMaterialization  = "materialization"
	AuditEventAdvisoryFreeze   = "advisory_freeze"
	AuditEventError            = "error"
	// Stability retry events (spec §2.4/§9.5): one stability_attempt per
	// recorded run of the series, then one stability summary carrying the
	// report verdict — drift included, which always means the run failed
	// technically rather than producing a new decision.
	AuditEventStabilityAttempt = "stability_attempt"
	AuditEventStability        = "stability"
	AuditEventFalsifier        = "falsifier_verification"
	// AuditEventHumanDecision records one person's Accept/Reject of the
	// delivered proposal. It is an audit projection of the immutable
	// human-decisions/<record-id>.json file, never a package axis and never
	// a machine result.
	AuditEventHumanDecision = "human_decision"
)

// MaterialsAudit is the audit projection of a collected material set: per
// material it stores id, kind, scope, availability, hash and size — never
// content — plus the module-graph/deploy-fact coverage counters and the
// canonical set hash. Step 7 of the materials contract: only hashes,
// scopes, sizes, statuses and safe limitations reach the log.
type MaterialsAudit struct {
	MaterialsHash   string   `json:"materials_hash"`
	MaterialCount   int      `json:"material_count"`
	Available       int      `json:"available"`
	Unavailable     int      `json:"unavailable"`
	Invalid         int      `json:"invalid"`
	ModuleGraphSrc  string   `json:"module_graph_source,omitempty"`
	ModuleCount     int      `json:"module_count,omitempty"`
	GraphComplete   bool     `json:"module_graph_complete,omitempty"`
	DeployFactCount int      `json:"deploy_fact_count,omitempty"`
	Perimeter       string   `json:"perimeter,omitempty"`
	Limitations     []string `json:"limitations,omitempty"`
}

// FactFeedbackAudit is the safe, hash-free projection of one fact-gate
// report/feedback pass: status and pass counts are replayable, while the
// agent's raw prose and evidence payloads remain in raw-agent.json only.
type FactFeedbackAudit struct {
	Pass       int                  `json:"pass"`
	Status     FactValidationStatus `json:"status"`
	Items      []FactFeedbackItem   `json:"items,omitempty"`
	Unresolved int                  `json:"unresolved,omitempty"`
}

// FactFeedbackAuditEvents projects recorded fact-gate passes into append-only
// audit events, preserving pass order and the deterministic statuses without
// copying semantic assessment text.
func FactFeedbackAuditEvents(passes []FactGatePass, ts time.Time) []AuditEvent {
	out := make([]AuditEvent, 0, len(passes))
	for _, pass := range passes {
		ev := AuditEvent{Type: AuditEventFactFeedback, Timestamp: ts, Status: string(pass.Validation.Status), Scope: "fact_gate"}
		projection := &FactFeedbackAudit{Pass: pass.Pass, Status: pass.Validation.Status}
		for _, rc := range pass.Validation.References {
			if rc.Status != FactValid {
				projection.Unresolved++
			}
		}
		if pass.Feedback != nil {
			projection.Items = append(projection.Items, pass.Feedback.Items...)
		}
		ev.FactFeedback = projection
		out = append(out, ev)
	}
	return out
}

// materialsAuditOf projects a collected material set into its audit shape:
// per-material status counts, the module-graph/deploy-fact coverage and
// the canonical set hash — never material content.
func materialsAuditOf(set MaterialSet) MaterialsAudit {
	a := MaterialsAudit{
		MaterialsHash: MaterialSetHash(set),
		Limitations:   set.Limitations,
	}
	a.MaterialCount = len(set.Materials)
	for _, m := range set.Materials {
		switch m.Availability {
		case MaterialAvailable:
			a.Available++
		case MaterialUnavailable:
			a.Unavailable++
		case MaterialInvalid:
			a.Invalid++
		}
	}
	if set.ModuleGraph != nil {
		a.ModuleGraphSrc = set.ModuleGraph.Source
		a.ModuleCount = len(set.ModuleGraph.Modules)
		a.GraphComplete = set.ModuleGraph.Complete
	}
	if set.Deploy != nil {
		a.DeployFactCount = set.Deploy.FactCount
		a.Perimeter = set.Deploy.Perimeter
	}
	return a
}

// MaterialsAuditEvent builds the materials audit event for one collected
// material set stamped at ts.
func MaterialsAuditEvent(set MaterialSet, runID string, ts time.Time) AuditEvent {
	a := materialsAuditOf(set)
	return AuditEvent{
		Type:      AuditEventMaterials,
		Timestamp: ts,
		RunID:     runID,
		Status:    "ok",
		Hash:      a.MaterialsHash,
		Materials: &a,
	}
}

// ToolchainAudit is the audit projection of one release-toolchain
// resolution: the discovered version, its evidence source and location, the
// intake claim when present, the provisioned analysis toolchain and the
// mismatch flag — an unknown release toolchain is recorded as a fact of the
// run, never as evidence of safety.
type ToolchainAudit struct {
	ReleaseVersion string `json:"release_version,omitempty"`
	ReleaseSource  string `json:"release_source,omitempty"`
	ReleaseLoc     string `json:"release_location,omitempty"`
	Claimed        string `json:"claimed,omitempty"`
	Conflict       bool   `json:"conflict,omitempty"`
	Mode           string `json:"mode,omitempty"`
	Version        string `json:"version,omitempty"`
	GoBin          string `json:"go_bin,omitempty"`
	Mismatch       bool   `json:"mismatch,omitempty"`
}

// toolchainAuditOf projects the release-toolchain fact plus the provisioned
// analysis toolchain into the shared toolchain audit shape.
func toolchainAuditOf(fact ReleaseToolchainFact, tc toolchain.Toolchain) ToolchainAudit {
	return ToolchainAudit{
		ReleaseVersion: fact.Version,
		ReleaseSource:  string(fact.Source),
		ReleaseLoc:     fact.Location,
		Claimed:        fact.Claimed,
		Conflict:       fact.Conflict,
		Mode:           string(tc.Mode),
		Version:        tc.Version,
		GoBin:          tc.GoBin,
		Mismatch:       tc.Mismatch,
	}
}

// ToolchainAuditEvent builds the toolchain_resolution audit event stamped
// at ts for the discovered fact and the resolved analysis toolchain.
func ToolchainAuditEvent(fact ReleaseToolchainFact, tc toolchain.Toolchain, runID string, ts time.Time) AuditEvent {
	a := toolchainAuditOf(fact, tc)
	return AuditEvent{
		Type:      AuditEventToolchain,
		Timestamp: ts,
		RunID:     runID,
		Toolchain: &a,
	}
}

// PackageCheckAudit is the audit projection of the package/version check:
// the classification, claimed and resolved coordinates, the evidence source
// and the short reason — the graph observation, never its content.
type PackageCheckAudit struct {
	Class           string   `json:"class"`
	Claimed         string   `json:"claimed,omitempty"`
	ClaimedVersion  string   `json:"claimed_version,omitempty"`
	Resolved        string   `json:"resolved,omitempty"`
	ResolvedVersion string   `json:"resolved_version,omitempty"`
	EvidenceSource  string   `json:"evidence_source,omitempty"`
	Reason          string   `json:"reason,omitempty"`
	Provenance      []string `json:"provenance,omitempty"`
}

// packageCheckAuditOf projects one package/version check into its audit
// shape — the classification and coordinates, never the graph content.
func packageCheckAuditOf(res PackageCheckResult) PackageCheckAudit {
	return PackageCheckAudit{
		Class:           string(res.Class),
		Claimed:         res.ClaimedPath,
		ClaimedVersion:  res.ClaimedVersion,
		Resolved:        res.ResolvedPath,
		ResolvedVersion: res.ResolvedVersion,
		EvidenceSource:  res.EvidenceSource,
		Reason:          res.Reason,
		Provenance:      res.Provenance,
	}
}

// PackageCheckAuditEvent builds the package_check audit event stamped at ts.
func PackageCheckAuditEvent(res PackageCheckResult, runID string, ts time.Time) AuditEvent {
	a := packageCheckAuditOf(res)
	return AuditEvent{
		Type:         AuditEventPackageCheck,
		Timestamp:    ts,
		RunID:        runID,
		PackageCheck: &a,
	}
}

// RefResolutionAudit is the hash-and-identity projection of a Stage 0 ref
// resolution attached to the AuditEventRefResolution event: the bounded
// candidate list hash, the selected candidate id and ref, the commit it
// resolved to, the matching rule, the selection provenance and — when the
// deterministic fallback fired — the reason the agent path failed. It
// stores no ref names beyond the selected one, no credential material and
// no remote output.
type RefResolutionAudit struct {
	RequestedRelease    string `json:"requested_release,omitempty"`
	RequestedSource     string `json:"requested_source,omitempty"`
	CandidateCount      int    `json:"candidate_count"`
	CandidatesHash      string `json:"candidates_hash"`
	SelectedID          string `json:"selected_id"`
	SelectedRef         string `json:"selected_ref"`
	ResolvedCommit      string `json:"resolved_commit"`
	ResolutionRule      string `json:"resolution_rule"`
	SelectionProvenance string `json:"selection_provenance"`
	Feedback            int    `json:"feedback_passes,omitempty"`
	FallbackReason      string `json:"fallback_reason,omitempty"`
	CandidateTruncation string `json:"candidate_truncation,omitempty"`
}

// refAuditOf projects one RefResolution into the shared ref audit shape.
func refAuditOf(res RefResolution) RefResolutionAudit {
	return RefResolutionAudit{
		RequestedRelease:    res.RequestedRelease,
		RequestedSource:     res.RequestedSource,
		CandidateCount:      len(res.CandidateRefs),
		CandidatesHash:      res.CandidatesHash,
		SelectedID:          res.SelectedID,
		SelectedRef:         res.SelectedRef,
		ResolvedCommit:      res.ResolvedCommit,
		ResolutionRule:      res.ResolutionRule,
		SelectionProvenance: res.SelectionProvenance,
		Feedback:            res.Feedback,
		FallbackReason:      res.FallbackReason,
		CandidateTruncation: res.CandidateTruncation,
	}
}

// RefAuditEvent builds the ref_resolution audit event for one completed
// Stage 0 ref resolution stamped at ts.
func RefAuditEvent(res RefResolution, runID string, ts time.Time) AuditEvent {
	a := refAuditOf(res)
	return AuditEvent{
		Type:      AuditEventRefResolution,
		Timestamp: ts,
		RunID:     runID,
		Status:    res.SelectionProvenance,
		Ref:       &a,
	}
}

// IntakeAudit is the audit projection of one intake resolution: the record
// identity (ticket_hash, format, position), the proposal hash, the config
// that governed validation and the per-field status counts — never the
// document text or extracted values.
type IntakeAudit struct {
	TicketHash   string         `json:"ticket_hash"`
	Format       string         `json:"format"`
	RecordIndex  int            `json:"record_index"`
	ProposalHash string         `json:"proposal_hash,omitempty"`
	ConfigHash   string         `json:"config_hash,omitempty"`
	FieldStatus  map[string]int `json:"field_status,omitempty"`
	ValidFields  int            `json:"valid_fields"`
	Blocked      int            `json:"blocked_fields"`
	// Fields is the field-by-field validation audit: status, reason and
	// deterministic provenance per extracted field — the value itself stays
	// out of the log, only its hash is pinned.
	Fields []IntakeFieldAudit `json:"fields,omitempty"`
}

// IntakeAuditEvent builds the intake_resolution event: the ticket identity
// plus the deterministic validation outcome. status is "ok" or "error".
func IntakeAuditEvent(raw RawIntake, p IntakeProposal, v IntakeValidation, status string) AuditEvent {
	a := IntakeAudit{
		TicketHash:  raw.TicketHash,
		Format:      string(raw.Format),
		RecordIndex: raw.RecordIndex,
		FieldStatus: map[string]int{},
		Fields:      intakeFieldAudits(v.Fields),
	}
	if p.SchemaVersion != "" {
		if b, err := json.Marshal(p); err == nil {
			a.ProposalHash = hashBytes(b)
		}
	}
	for _, f := range v.Fields {
		a.FieldStatus[string(f.Status)]++
		if f.Status == IntakeValid {
			a.ValidFields++
		}
		if f.BlocksRiskReduction {
			a.Blocked++
		}
	}
	return AuditEvent{
		Type:        AuditEventIntakeResolution,
		Status:      status,
		Hash:        raw.TicketHash,
		Intake:      &a,
		Limitations: v.Limitations,
	}
}

// SourceAudit is the audit projection of catalog source selection: the
// chosen catalog entry id, its kind, locator class and credential
// reference name — never credential material.
type SourceAudit struct {
	SourceID      string `json:"source_id,omitempty"`
	Kind          string `json:"kind,omitempty"`
	Locator       string `json:"locator,omitempty"`
	CredentialRef string `json:"credential_ref,omitempty"`
}

// sourceAuditOf projects the selected catalog entry into the shared source
// audit shape — entry identity and locator class, never credential material.
func sourceAuditOf(e CatalogEntry) *SourceAudit {
	return &SourceAudit{
		SourceID:      e.ID,
		Kind:          e.Kind,
		Locator:       entryLocator(e),
		CredentialRef: e.CredentialRef,
	}
}

// SourceAuditEvent builds the source_resolution event. An empty entry means
// the match failed; status carries the IntakeFieldStatus (unverified,
// conflicting) or "error"/"ok".
func SourceAuditEvent(e CatalogEntry, status string) AuditEvent {
	return AuditEvent{
		Type:   AuditEventSourceResolution,
		Status: status,
		Source: sourceAuditOf(e),
	}
}

// MaterializationAudit is the audit projection of source materialization —
// the same provenance block snapshot.json carries.
type MaterializationAudit = MaterializationMetadata

// MaterializationAuditEvent builds the materialization event for one
// completed or failed materialization.
func MaterializationAuditEvent(md MaterializationMetadata, status string) AuditEvent {
	a := MaterializationAudit(md)
	return AuditEvent{
		Type:        AuditEventMaterialization,
		Status:      status,
		Hash:        md.RootHash,
		Scope:       md.SourceID,
		Materialize: &a,
		Limitations: md.Limitations,
	}
}

// AdvisoryAudit is the audit projection of the advisory freeze: the frozen
// record's identity (source, resolved id, hash, path) plus every source
// attempt — never advisory content.
type AdvisoryAudit struct {
	ID         string                        `json:"id"`
	ResolvedID string                        `json:"resolved_id,omitempty"`
	Source     string                        `json:"source,omitempty"`
	Path       string                        `json:"path,omitempty"`
	SHA256     string                        `json:"sha256,omitempty"`
	Partial    bool                          `json:"partial,omitempty"`
	Attempts   []vulnerability.SourceAttempt `json:"attempts,omitempty"`
}

// advisoryAuditOf projects one advisory resolution into the shared audit
// shape — frozen record identity plus every source attempt, never content.
func advisoryAuditOf(res *AdvisoryResolution) *AdvisoryAudit {
	rec := res.Record
	return &AdvisoryAudit{
		ID: rec.ID, ResolvedID: rec.ResolvedID, Source: string(rec.Source),
		Path: rec.Path, SHA256: rec.SHA256, Partial: res.Partial,
		Attempts: res.Attempts,
	}
}

// AdvisoryAuditEvent builds the advisory_freeze event; nil resolution marks
// a hard failure.
func AdvisoryAuditEvent(res *AdvisoryResolution, status string) AuditEvent {
	ev := AuditEvent{Type: AuditEventAdvisoryFreeze, Status: status}
	if res == nil {
		return ev
	}
	ev.Hash = res.Record.SHA256
	ev.Advisory = advisoryAuditOf(res)
	ev.Limitations = res.Limitations
	return ev
}

// DetToolsAudit records the deterministic evidence tool surface assembled
// for one finding: whether the tools were enabled, the toolchain they run
// under, how many catalog tools the agent sees, and why the session was
// unavailable when it failed to initialize. It is attached to the
// AuditEventDetTools event.
type DetToolsAudit struct {
	Enabled      bool     `json:"enabled"`
	Toolchain    string   `json:"toolchain,omitempty"`
	ToolCount    int      `json:"tool_count,omitempty"`
	SessionError string   `json:"session_error,omitempty"`
	Limitations  []string `json:"limitations,omitempty"`
}

// DecisionJudgmentAudit is the projection of the model's own conclusion.
// It is labelled as a judgment everywhere: the audit never calls it a
// verdict on the risk.
type DecisionJudgmentAudit struct {
	Verdict string `json:"verdict"`
	Summary string `json:"summary,omitempty"`
}

// DecisionHumanActionAudit is the projection of the model's proposal for a
// person — kind, scope and the concrete instruction. It never appears
// under the machine disposition keys.
type DecisionHumanActionAudit struct {
	Kind        string `json:"kind"`
	Scope       string `json:"scope,omitempty"`
	Instruction string `json:"instruction,omitempty"`
}

// DecisionSupportAudit is the projection of the deterministically derived
// support of the proposal's decisive grounds.
type DecisionSupportAudit struct {
	Level          string   `json:"level"`
	DecisiveClaims int      `json:"decisive_claims"`
	Proofs         int      `json:"proofs,omitempty"`
	Reasons        []string `json:"reasons,omitempty"`
}

// DecisionMachineAudit is the projection of the deterministic reduction.
// The recommendation is the machine's own value; no human action or support
// level can be read from these keys.
type DecisionMachineAudit struct {
	Recommendation   string   `json:"recommendation"`
	Profile          string   `json:"profile"`
	Automation       string   `json:"automation,omitempty"`
	Arbitration      string   `json:"arbitration,omitempty"`
	BaselineSeverity string   `json:"baseline_severity,omitempty"`
	Demotions        int      `json:"demotions,omitempty"`
	Assumptions      int      `json:"assumptions,omitempty"`
	Conditionals     []string `json:"conditional_profiles,omitempty"`
}

// DecisionComposeAudit is the audit projection of one composed decision
// package. Each result axis has its own object — judgment, human action,
// support and machine disposition — so no consumer can read one as another,
// and no human proposal is ever recorded under a machine key.
type DecisionComposeAudit struct {
	Judgment        DecisionJudgmentAudit    `json:"judgment"`
	HumanAction     DecisionHumanActionAudit `json:"human_action"`
	Support         DecisionSupportAudit     `json:"support"`
	Machine         DecisionMachineAudit     `json:"machine_disposition"`
	FactValidation  string                   `json:"fact_validation,omitempty"`
	StabilityResult string                   `json:"stability_result,omitempty"`
	Limitations     int                      `json:"limitations,omitempty"`
	Premises        int                      `json:"premises,omitempty"`
	HumanReviewReadiness string `json:"human_review_readiness,omitempty"`
}

// DecisionAuditEvent builds the decision audit event for one composed
// package stamped at ts. The event carries the four axes under distinct
// keys; the human action, judgment and support are never collapsed into the
// machine recommendation.
func DecisionAuditEvent(p DecisionPackage, runID string, ts time.Time) AuditEvent {
	m := p.MachineDisposition
	a := DecisionComposeAudit{
		Judgment: DecisionJudgmentAudit{
			Verdict: string(p.Judgment.Verdict),
			Summary: p.Judgment.Summary,
		},
		HumanAction: DecisionHumanActionAudit{
			Kind:        string(p.ProposedAction.Kind),
			Scope:       p.ProposedAction.Scope,
			Instruction: p.ProposedAction.Instruction,
		},
		Support: DecisionSupportAudit{
			Level:          string(p.Support.Level),
			DecisiveClaims: len(p.Support.DecisiveClaimIDs),
			Proofs:         len(p.Support.ProofIDs),
			Reasons:        p.Support.Reasons,
		},
		Machine: DecisionMachineAudit{
			Recommendation: string(m.Recommendation),
			Profile:        m.RecommendedProfile.ID,
			Automation:     string(m.Automation),
			Arbitration:    m.Arbitration,
			Demotions:      len(m.Demotions),
			Assumptions:    len(m.ResidualAssumptions),
		},
		FactValidation:  p.TechnicalAssessment.FactValidation,
		StabilityResult: p.TechnicalAssessment.StabilityResult,
		Limitations:     len(p.TechnicalAssessment.Limitations),
		Premises:        len(p.Premises),
	}
	if p.HumanReviewPlan != nil { a.HumanReviewReadiness = p.HumanReviewPlan.Readiness }
	if m.Baseline != nil {
		a.Machine.BaselineSeverity = m.Baseline.Severity
	}
	for _, c := range m.ConditionalProfiles {
		a.Machine.Conditionals = append(a.Machine.Conditionals, c.Profile)
	}
	return AuditEvent{
		Type:      AuditEventDecision,
		Timestamp: ts,
		RunID:     runID,
		Status:    "ok",
		Scope:     p.FindingID,
		Decision:  &a,
	}
}

// HumanDecisionAudit is the audit projection of one immutable Accept/Reject
// record. It is deliberately separate from DecisionComposeAudit: the person
// acting on the proposal is not a package axis, a machine recommendation or
// an admitted proof.
type HumanDecisionAudit struct {
	RecordID            string    `json:"record_id"`
	Decision            string    `json:"decision"`
	DecisionPackageHash string    `json:"decision_package_hash"`
	Actor               string    `json:"actor,omitempty"`
	Reason              string    `json:"reason,omitempty"`
	RecordedAt          time.Time `json:"recorded_at"`
	BranchID string `json:"branch_id,omitempty"`
	ProjectionHash string `json:"projection_hash,omitempty"`
	AssertionIDs []string `json:"assertion_ids,omitempty"`
	ReasonCode string `json:"reason_code,omitempty"`
}

// HumanDecisionAuditEvent builds the append-only audit event for one
// persisted human decision. Hash is the hash of the exact immutable record
// file bytes; the enumeration of the decision lives only under
// HumanDecision, so no consumer can read it as a machine disposition.
func HumanDecisionAuditEvent(rec HumanDecisionRecord, ts time.Time) AuditEvent {
	artifactHash := ""
	if data, err := encodeHumanDecisionRecord(rec); err == nil {
		artifactHash = hashBytes(data)
	}
	return AuditEvent{
		Type:      AuditEventHumanDecision,
		Timestamp: ts,
		RunID:     rec.RunID,
		Status:    "ok",
		Hash:      artifactHash,
		Scope:     rec.FindingID,
		HumanDecision: &HumanDecisionAudit{
			RecordID:            rec.ID,
			Decision:            string(rec.Decision),
			DecisionPackageHash: rec.DecisionPackageHash,
			Actor:               rec.Actor,
			Reason:              rec.Reason,
			RecordedAt:          rec.RecordedAt,
			BranchID: rec.BranchID,
			ProjectionHash: rec.ProjectionHash,
			AssertionIDs: append([]string(nil), rec.AssertionIDs...),
			ReasonCode: rec.ReasonCode,
		},
	}
}

// FalsifierAuditProof is the safe append-only projection of one proof.
type FalsifierAuditProof struct {
	ID           string                      `json:"id"`
	ProposalID   string                      `json:"proposal_id"`
	ConditionID  string                      `json:"condition_id"`
	Kind         FalsifierKind               `json:"kind"`
	Status       FalsifierVerificationStatus `json:"status"`
	RuleID       string                      `json:"rule_id,omitempty"`
	RuleVersion  string                      `json:"rule_version,omitempty"`
	Coverage     string                      `json:"coverage,omitempty"`
	EvidenceRefs []string                    `json:"evidence_refs,omitempty"`
	History      []FalsifierTransition       `json:"history,omitempty"`
	Reason       string                      `json:"reason,omitempty"`
}

type FalsifierAudit struct {
	ReportHash string                `json:"report_hash"`
	Proofs     []FalsifierAuditProof `json:"proofs,omitempty"`
}

// FalsifierAuditEvent records deterministic proof metadata without payloads.
func FalsifierAuditEvent(report FalsifierReport, runID string, attempt int, ts time.Time) AuditEvent {
	a := FalsifierAudit{ReportHash: report.Hash}
	for _, p := range report.Proofs {
		a.Proofs = append(a.Proofs, FalsifierAuditProof{
			ID: p.ID, ProposalID: p.ProposalID, ConditionID: p.ConditionID, Kind: p.Kind,
			Status: p.Status, RuleID: p.RuleID, RuleVersion: p.RuleVersion,
			Coverage: p.Coverage.Completeness, EvidenceRefs: append([]string(nil), p.EvidenceRefs...),
			History: append([]FalsifierTransition(nil), p.History...), Reason: p.Reason,
		})
	}
	b, _ := json.Marshal(a)
	return AuditEvent{Type: AuditEventFalsifier, Timestamp: ts, RunID: runID, Status: "ok", Hash: hashBytes(b), Attempt: attempt, Falsifier: &a}
}

// StabilityAudit is the audit projection of the completed retry report:
// how many extra runs executed, whether the canonical decision fields
// agreed, whether any provenance pin drifted and the recorded divergence
// reasons. The verdict shape only — the per-attempt projections ride on
// their own stability_attempt events.
type StabilityAudit struct {
	Retries     int      `json:"retries"`
	Stable      bool     `json:"stable"`
	Drift       bool     `json:"drift"`
	Limitations []string `json:"limitations,omitempty"`
}

// StabilityAuditEvents projects a completed StabilityReport into
// append-only events stamped at ts: one stability_attempt event per
// recorded attempt — audit fixes every retry, not just the count — then
// the summary stability event carrying the report hash and verdict. On
// drift the summary's status is "error": drift is a technical failure
// channel, never a recorded decision.
func StabilityAuditEvents(report StabilityReport, runID string, ts time.Time) []AuditEvent {
	out := make([]AuditEvent, 0, len(report.Attempts)+1)
	for _, a := range report.Attempts {
		attempt := a
		b, _ := json.Marshal(attempt)
		out = append(out, AuditEvent{
			Type:             AuditEventStabilityAttempt,
			Timestamp:        ts,
			RunID:            runID,
			Status:           "ok",
			Hash:             hashBytes(b),
			Attempt:          attempt.Attempt,
			StabilityAttempt: &attempt,
		})
	}
	status := "ok"
	if report.Drift {
		status = "error"
	}
	b, _ := json.Marshal(report)
	out = append(out, AuditEvent{
		Type:      AuditEventStability,
		Timestamp: ts,
		RunID:     runID,
		Status:    status,
		Hash:      hashBytes(b),
		Stability: &StabilityAudit{
			Retries:     report.Retries,
			Stable:      report.Stable,
			Drift:       report.Drift,
			Limitations: report.Limitations,
		},
	})
	return out
}

// AuditEvent is one append-only line of the run audit trail. Events pin run
// identity, status and content hashes only: raw source text, tool call
// arguments, observed file/advisory content and secrets never enter the log.
// Limitations carry short reason strings recorded by deterministic code.
type AuditEvent struct {
	Type      string    `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	RunID     string    `json:"run_id"`
	Status    string    `json:"status,omitempty"`
	Hash      string    `json:"hash,omitempty"`
	Tool      string    `json:"tool,omitempty"`
	// Coverage is the recorded observation completeness marker for
	// tool_call events ("COMPLETE"/"PARTIAL"/"UNKNOWN" for deterministic
	// tools): the replay index needs it so a citation never verifies
	// against a call that proved nothing.
	Coverage      string `json:"coverage,omitempty"`
	ObservationID string `json:"observation_id,omitempty"`
	ArgsSHA256    string `json:"args_sha256,omitempty"`
	DataSHA256    string `json:"data_sha256,omitempty"`
	// InnerSHA256 records the sha256-like tokens inside the observed
	// payload; ReachEvidence marks an observation that positively
	// establishes reachability/usage. Both let the fact gate and the
	// deterministic decision facts rebuild their results at replay time.
	InnerSHA256   []string              `json:"inner_sha256,omitempty"`
	ReachEvidence bool                  `json:"reach_evidence,omitempty"`
	Scope         string                `json:"scope,omitempty"`
	Limitations   []string              `json:"limitations,omitempty"`
	DetTools      *DetToolsAudit        `json:"det_tools,omitempty"`
	Ref           *RefResolutionAudit   `json:"ref,omitempty"`
	Materials     *MaterialsAudit       `json:"materials,omitempty"`
	Toolchain     *ToolchainAudit       `json:"toolchain,omitempty"`
	PackageCheck  *PackageCheckAudit    `json:"package_check,omitempty"`
	Intake        *IntakeAudit          `json:"intake,omitempty"`
	Source        *SourceAudit          `json:"source,omitempty"`
	Materialize   *MaterializationAudit `json:"materialization,omitempty"`
	Advisory      *AdvisoryAudit        `json:"advisory,omitempty"`
	FactFeedback  *FactFeedbackAudit    `json:"fact_feedback,omitempty"`
	Decision      *DecisionComposeAudit `json:"decision,omitempty"`
	// HumanDecision is the distinct projection of an Accept/Reject record;
	// it is never nested under the package decision axes.
	HumanDecision *HumanDecisionAudit `json:"human_decision,omitempty"`
	Falsifier     *FalsifierAudit     `json:"falsifier,omitempty"`
	// Attempt numbers retry-produced events (tool calls, fact feedback
	// passes, det_tools) with the stability attempt they belong to; the
	// primary run's events keep the zero value.
	Attempt          int               `json:"attempt,omitempty"`
	Stability        *StabilityAudit   `json:"stability,omitempty"`
	StabilityAttempt *StabilityAttempt `json:"stability_attempt,omitempty"`
	// Metrics carries the batch-level aggregate on the metrics event — the
	// only audit event scoped to the whole invocation, not one run id.
	Metrics *Metrics `json:"metrics,omitempty"`
}

// ToolAuditEvents converts the per-call tool audit trail into run audit
// events stamped at ts. Hash-only fields carry over verbatim; call arguments
// and observed content stay out of the log by construction.
func ToolAuditEvents(toolEvents []ToolAuditEvent, ts time.Time) []AuditEvent {
	out := make([]AuditEvent, len(toolEvents))
	for i, e := range toolEvents {
		out[i] = AuditEvent{
			Type:          AuditEventToolCall,
			Timestamp:     ts,
			Tool:          e.Tool,
			ObservationID: e.ObservationID,
			Status:        e.Status,
			Coverage:      e.Coverage,
			ArgsSHA256:    e.ArgsSHA256,
			DataSHA256:    e.DataSHA256,
			InnerSHA256:   e.InnerSHA256,
			ReachEvidence: e.ReachEvidence,
			Scope:         e.Scope,
			Limitations:   e.Limitations,
		}
	}
	return out
}

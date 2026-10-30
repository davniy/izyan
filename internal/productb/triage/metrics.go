package triage

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// MetricsSchemaVersion identifies metrics.json, the machine-readable batch
// aggregate a triage invocation persists next to the per-finding artifacts.
// It records observational counters only: external-control comparison lives
// in the offline triage-evaluation.v1 artifact and never gates a live run.
const MetricsSchemaVersion = "triage-metrics.v3"

// AuditEventMetrics is the batch-level audit event appended to
// <out>/audit/events.jsonl once metrics.json is written. It carries the
// aggregate plus the artifact hash; it never carries per-finding content.
const AuditEventMetrics = "metrics"

// RunStage* classify the stage a finding's technical failure belongs to, so
// the metrics can count intake errors, analysis errors, decision errors and
// provenance drift separately — a technical error is never folded into a
// recommendation rate.
const (
	RunStageIntake    = "intake"
	RunStageSource    = "source"
	RunStageRef       = "ref"
	RunStageAnalysis  = "analysis"
	RunStageDecision  = "decision"
	RunStageDrift     = "drift"
	RunStageArtifacts = "artifacts"
	RunStageReplay    = "replay"
)

// RunRecord is the per-finding projection ComputeMetrics aggregates. It is
// populated by the triage driver from the values the run already produced —
// Stage 0 result, gate passes, stability report, package and error class —
// never by re-executing any stage. Metrics are a read-only projection:
// filling or consuming a RunRecord must not change a decision.
type RunRecord struct {
	FindingID string
	// IntakeAttempted marks a run that went through the Stage 0 intake
	// path (--ticket). The compatibility --input transport has no intake
	// resolution, so its records never enter intake/source/ref rates.
	IntakeAttempted bool
	Stage0          *Stage0Result
	Assessment      *Assessment
	FactPasses      []FactGatePass
	Stability       *StabilityReport
	Decision        *DecisionPackage
	// Falsifiers is the deterministic report for this run. It is metrics
	// input only; proof outcomes never alter a decision or exit status.
	Falsifiers *FalsifierReport
	// Failed/ErrorClass record a technical failure: the finding counts in
	// technical_error_rate and errors_by_stage, never as an implicit
	// UNCHANGED decision.
	Failed     bool
	ErrorClass string
	// Replay records a re-rendered run: attempted always increments the
	// replay denominator, ReplayOK the numerator.
	ReplayAttempted bool
	ReplayOK        bool
	LLMSteps        int64
	ToolCalls       int64
	WallTimeMS      int64
}

// Metrics is the spec §13.2 observational aggregate over one batch of
// findings. Rates are plain fractions in [0,1]; an empty denominator yields
// 0, never NaN. It makes no correctness or false-safe claim: external
// comparison belongs to the offline triage-evaluation.v1 report.
type Metrics struct {
	FindingsTotal               int64   `json:"findings_total"`
	IntakeAutoResolutionRate    float64 `json:"intake_auto_resolution_rate"`
	PolicyDecisiveRate          float64 `json:"policy_decisive_rate"`
	SuccessfulPackageRate       float64 `json:"successful_package_rate"`
	TechnicalErrorRate          float64 `json:"technical_error_rate"`
	FactRepairRate              float64 `json:"fact_repair_rate"`
	UnresolvedEvidenceRate      float64 `json:"unresolved_evidence_rate"`
	DemotionRate                float64 `json:"demotion_rate"`
	AutomaticActionRate         float64 `json:"automatic_action_rate"`
	SourceAutoResolutionRate    float64 `json:"source_auto_resolution_rate"`
	RefAutoResolutionRate       float64 `json:"ref_auto_resolution_rate"`
	LimitationRate              float64 `json:"limitation_rate"`
	ConditionalRate             float64 `json:"conditional_rate"`
	LowSupportRate              float64 `json:"low_support_rate"`
	ReplaySuccessRate           float64 `json:"replay_success_rate"`
	DriftErrorRate              float64 `json:"drift_error_rate"`
	StabilityRate               float64 `json:"stability_rate"`
	AgentFalsifierProposalCount int64   `json:"agent_falsifier_proposal_count"`
	VerifiedFalsifierCount      int64   `json:"verified_falsifier_count"`
	UnsupportedFalsifierCount   int64   `json:"unsupported_falsifier_count"`
	FalsifierDemotionCount      int64   `json:"falsifier_demotion_count"`
	FalsifierDismissalCount     int64   `json:"falsifier_dismissal_count"`
	// Result distributions. Each composed package contributes at most once
	// to each axis and no axis is derived from another: the human proposal,
	// its derived support, the machine disposition and the machine
	// automation outcome are separate observations. An absent/invalid value
	// is not counted — a fabricated bucket would mask a contract defect.
	HumanActionKinds       map[string]int64 `json:"human_action_kinds,omitempty"`
	SupportLevels          map[string]int64 `json:"support_levels,omitempty"`
	MachineRecommendations map[string]int64 `json:"machine_recommendations,omitempty"`
	MachineAutomation      map[string]int64 `json:"machine_automation,omitempty"`
	MaterialCount          int64            `json:"material_count"`
	MaterialBytes          int64            `json:"material_bytes"`
	LLMSteps               int64            `json:"llm_steps"`
	ToolCalls              int64            `json:"tool_calls"`
	WallTimeMS             int64            `json:"wall_time_ms"`
	ErrorsByStage          map[string]int64 `json:"errors_by_stage,omitempty"`
}

// metricsDocument is metrics.json on disk: the aggregate plus the document
// identity. No finding content, no tool payloads — rates and hashes only.
type metricsDocument struct {
	SchemaVersion string  `json:"schema_version"`
	GeneratedAt   string  `json:"generated_at"`
	Metrics       Metrics `json:"metrics"`
}

func rate(numerator, denominator int64) float64 {
	if denominator <= 0 {
		return 0
	}
	return float64(numerator) / float64(denominator)
}

// ComputeMetrics folds a batch of run records into the §13.2 metric set.
// Denominators are stage-scoped: intake rates divide by records that ran
// Stage 0, package rates by the whole batch, gate rates by assessments
// that reached the fact gate, stability by non-drift retry reports and
// replay by replay attempts. A technical failure counts exactly once — in
// the error channels — and never inside a decision denominator.
func ComputeMetrics(records []RunRecord) Metrics {
	var m Metrics
	var intakeAttempted, intakeOK int64
	var sourceDenom, sourceOK, refDenom, refOK int64
	var decisions, decisive, demoted, conditional, lowSupport int64
	var gated, repaired, unresolved, autoAllowed int64
	var replayN, replayOK, drift, stabN, stable, limited int64
	m.HumanActionKinds = map[string]int64{}
	m.SupportLevels = map[string]int64{}
	m.MachineRecommendations = map[string]int64{}
	m.MachineAutomation = map[string]int64{}
	m.ErrorsByStage = map[string]int64{}

	for i := range records {
		r := records[i]
		m.FindingsTotal++
		m.LLMSteps += r.LLMSteps
		m.ToolCalls += r.ToolCalls
		m.WallTimeMS += r.WallTimeMS
		if r.Assessment != nil {
			m.AgentFalsifierProposalCount += int64(len(r.Assessment.FalsifierProposals))
		}
		if r.Falsifiers != nil {
			for _, proof := range r.Falsifiers.Proofs {
				if proof.Status == FalsifierVerified {
					m.VerifiedFalsifierCount++
				}
				if proof.Basis == BasisUnsupported || proof.Status != FalsifierVerified {
					m.UnsupportedFalsifierCount++
				}
				for _, tr := range proof.History {
					if tr.From == FalsifierVerified && tr.To == FalsifierUnknown {
						m.FalsifierDemotionCount++
						break
					}
				}
			}
		}

		if r.ReplayAttempted {
			replayN++
			if r.ReplayOK {
				replayOK++
			}
		}
		if r.Failed {
			cls := r.ErrorClass
			if cls == "" {
				cls = "unknown"
			}
			m.ErrorsByStage[cls]++
		}
		// Provenance drift is a technical-error class of its own — never
		// counted as semantic instability.
		if r.ErrorClass == RunStageDrift || (r.Stability != nil && r.Stability.Drift) {
			drift++
		}
		if r.Stability != nil && !r.Stability.Drift {
			stabN++
			if r.Stability.Stable {
				stable++
			}
		}
		// Limitations stay visible wherever they were recorded: intake
		// resolution, the fact gate or the package's technical assessment.
		if (r.Stage0 != nil && len(r.Stage0.Limitations) > 0) ||
			(r.Assessment != nil && r.Assessment.FactValidationDetail != nil &&
				len(r.Assessment.FactValidationDetail.Limitations) > 0) ||
			(r.Decision != nil && len(r.Decision.TechnicalAssessment.Limitations) > 0) {
			limited++
		}

		if r.IntakeAttempted {
			intakeAttempted++
			if r.Stage0 != nil && len(r.Stage0.Validation.Fields) > 0 && len(r.Stage0.Validation.Errors) == 0 {
				// Deterministic validation completed: the intake resolved
				// automatically even when later stages failed.
				intakeOK++
				sourceDenom++
				if r.Stage0.CatalogEntry.ID != "" {
					sourceOK++
					refDenom++
					if r.Stage0.RefResolution.SelectedID != "" {
						refOK++
					}
				}
			}
		}
		if r.Stage0 != nil {
			// Material volume counts what the run actually collected —
			// observability only.
			for _, mat := range r.Stage0.Materials.Materials {
				m.MaterialCount++
				m.MaterialBytes += mat.Size
			}
		}
		if r.Assessment != nil {
			gated++
			if len(r.FactPasses) > 1 {
				repaired++
			}
			if r.Assessment.FactValidation != ValidationComplete {
				unresolved++
			}
		}
		if r.Decision != nil {
			decisions++
			p := r.Decision
			machine := p.MachineDisposition
			if machine.Recommendation == RecommendationDismissed || machine.Recommendation == RecommendationLowered {
				decisive++
			}
			if machine.Recommendation.Valid() {
				m.MachineRecommendations[string(machine.Recommendation)]++
			}
			if p.ProposedAction.Kind.Valid() {
				m.HumanActionKinds[string(p.ProposedAction.Kind)]++
			}
			if p.Support.Level.Valid() {
				m.SupportLevels[string(p.Support.Level)]++
			}
			if machine.Recommendation == RecommendationDismissed && len(p.FalsifierProofs) > 0 {
				m.FalsifierDismissalCount++
			}
			if len(machine.Demotions) > 0 {
				demoted++
			}
			if len(machine.ConditionalProfiles) > 0 {
				conditional++
			}
			if lv := p.Support.Level; lv == SupportLevelLimited || lv == SupportLevelInsufficient {
				lowSupport++
			}
			// The machine automation outcome is a package property: the
			// human support level and the proposed action never enter it.
			if machine.Automation.Valid() {
				m.MachineAutomation[string(machine.Automation)]++
				if machine.Automation == AutomationAllow {
					autoAllowed++
				}
			}
		}
	}

	var failures int64
	for _, n := range m.ErrorsByStage {
		failures += n
	}
	m.IntakeAutoResolutionRate = rate(intakeOK, intakeAttempted)
	m.SourceAutoResolutionRate = rate(sourceOK, sourceDenom)
	m.RefAutoResolutionRate = rate(refOK, refDenom)
	m.SuccessfulPackageRate = rate(decisions, m.FindingsTotal)
	m.PolicyDecisiveRate = rate(decisive, decisions)
	m.TechnicalErrorRate = rate(failures, m.FindingsTotal)
	m.FactRepairRate = rate(repaired, gated)
	m.UnresolvedEvidenceRate = rate(unresolved, gated)
	m.DemotionRate = rate(demoted, decisions)
	// Automatic action counts admitted machine reductions over composed
	// packages — the only records that can carry a machine outcome.
	m.AutomaticActionRate = rate(autoAllowed, decisions)
	m.ConditionalRate = rate(conditional, decisions)
	m.LowSupportRate = rate(lowSupport, decisions)
	m.LimitationRate = rate(limited, m.FindingsTotal)
	m.ReplaySuccessRate = rate(replayOK, replayN)
	m.DriftErrorRate = rate(drift, m.FindingsTotal)
	m.StabilityRate = rate(stable, stabN)
	return m
}

// WriteMetrics persists the machine-readable aggregate as
// <dir>/metrics.json and appends the batch-level metrics event to
// <dir>/audit/events.jsonl. It is observability only: the caller decides
// the run's fate, metrics never feed back into a decision.
func WriteMetrics(ctx context.Context, dir string, records []RunRecord) (Metrics, string, error) {
	m := ComputeMetrics(records)
	doc := metricsDocument{
		SchemaVersion: MetricsSchemaVersion,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Metrics:       m,
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return m, "", fmt.Errorf("agenttriage: encode metrics: %w", err)
	}
	data = append(data, '\n')
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return m, "", fmt.Errorf("agenttriage: metrics: %w", err)
	}
	path := filepath.Join(dir, "metrics.json")
	if err := writeFileAtomic(ctx, path, data); err != nil {
		return m, "", err
	}
	stamp := time.Now().UTC()
	auditPath := filepath.Join(dir, "audit", "events.jsonl")
	if err := os.MkdirAll(filepath.Dir(auditPath), 0o755); err != nil {
		return m, "", fmt.Errorf("agenttriage: metrics audit: %w", err)
	}
	status := "ok"
	ev := AuditEvent{
		Type:      AuditEventMetrics,
		Timestamp: stamp,
		Status:    status,
		Scope:     "batch",
		Hash:      hashBytes(data),
		Metrics:   &m,
	}
	if err := appendAuditLog(ctx, auditPath, []AuditEvent{ev}, "", stamp); err != nil {
		return m, "", err
	}
	return m, path, nil
}

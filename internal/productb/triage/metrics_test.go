package triage

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// metricsDecision builds a minimal decision package fixture — the metrics
// reader touches the machine recommendation and its policy outcome, the
// human support level, the demotion record, the conditional profiles and the
// technical limitations.
func metricsDecision(rec Recommendation, support SupportLevel, automation AutomationStatus, demotions, limitations int, conditionals bool) *DecisionPackage {
	p := &DecisionPackage{
		SchemaVersion:  DecisionPackageSchemaVersion,
		ProposedAction: HumanAction{Kind: HumanActionKeepOpen},
		Support:        DecisionSupport{Level: support},
		TechnicalAssessment: TechnicalAssessment{
			Status: "READY",
		},
		MachineDisposition: MachineDisposition{
			Recommendation: rec,
			Automation:     automation,
		},
	}
	for range demotions {
		p.MachineDisposition.Demotions = append(p.MachineDisposition.Demotions, "demotion")
	}
	for range limitations {
		p.TechnicalAssessment.Limitations = append(p.TechnicalAssessment.Limitations, "limitation")
	}
	if conditionals {
		p.MachineDisposition.ConditionalProfiles = []ConditionalProfile{{Profile: "build-graph-exclusion"}}
	}
	return p
}

// metricsStage0 builds a resolved Stage 0 fixture for metrics input.
// metricsStage0 builds a resolved Stage 0 fixture for metrics input,
// carrying one collected material so volume counters are exercised.
func metricsStage0() *Stage0Result {
	s0 := goodStage0()
	s0.Materials.Materials = []Material{{
		ID: "mat-1", Kind: MaterialModuleGraph, Source: "go list -m all",
		Scope: "build-graph", Availability: MaterialAvailable, Size: 42,
	}}
	return &s0
}

func approxRate(t *testing.T, got, want float64, name string) {
	t.Helper()
	if math.Abs(got-want) > 1e-9 {
		t.Fatalf("%s = %v, want %v", name, got, want)
	}
}

// TestMetricsMixedBatch exercises every rate over one batch mixing resolved
// ticket runs, a compat run, technical failures at different stages, an
// unstable run and a drift error. Denominators are asserted explicitly so a
// wrong population is visible rather than silently normalized.
func TestMetricsMixedBatch(t *testing.T) {
	resolved := func() *Stage0Result {
		s0 := metricsStage0()
		return s0
	}
	records := []RunRecord{
		// 0: clean ticket run — intake/source/ref auto-resolved, decisive
		// package, one repair pass, high support.
		{
			FindingID:       "f-ok",
			IntakeAttempted: true,
			Stage0:          resolved(),
			Assessment: &Assessment{
				SchemaVersion:  AssessmentSchemaVersion,
				FindingID:      "f-ok",
				Verdict:        VerdictNotExploitable,
				FactValidation: ValidationComplete,
			},
			FactPasses: []FactGatePass{
				{Pass: 0, Validation: FactValidation{Status: ValidationPartial}},
				{Pass: 1, Validation: FactValidation{Status: ValidationComplete}},
			},
			Decision:   metricsDecision(RecommendationDismissed, SupportLevelProvedWithinScope, AutomationAllow, 0, 0, false),
			LLMSteps:   3,
			ToolCalls:  7,
			WallTimeMS: 1200,
		},
		// 1: ticket run lowered with demotions, conditional profiles and
		// low support; unresolved evidence (PARTIAL gate).
		{
			FindingID:       "f-lowered",
			IntakeAttempted: true,
			Stage0:          resolved(),
			Assessment: &Assessment{
				SchemaVersion:  AssessmentSchemaVersion,
				FindingID:      "f-lowered",
				Verdict:        VerdictNotExploitable,
				FactValidation: ValidationPartial,
			},
			FactPasses: []FactGatePass{
				{Pass: 0, Validation: FactValidation{Status: ValidationPartial}},
			},
			Decision:   metricsDecision(RecommendationLowered, SupportLevelLimited, AutomationWarn, 1, 2, true),
			LLMSteps:   2,
			ToolCalls:  4,
			WallTimeMS: 900,
		},
		// 2: ticket run whose Stage 0 failed at intake validation —
		// counts as technical error and as an intake attempt, never as a
		// resolved intake and never as a decision.
		{
			FindingID:       "f-intake-fail",
			IntakeAttempted: true,
			Stage0: &Stage0Result{
				Raw:        RawIntake{Raw: []byte(`{"x":1}`), TicketHash: "abc", Format: IntakeJSON},
				Validation: IntakeValidation{Errors: []string{"vulnerability id unverified"}},
			},
			Failed:     true,
			ErrorClass: RunStageIntake,
			WallTimeMS: 30,
		},
		// 3: ticket run whose source resolution failed — intake resolved,
		// the source rate denominator counts it, the numerator does not.
		{
			FindingID:       "f-source-fail",
			IntakeAttempted: true,
			Stage0: &Stage0Result{
				Raw:         RawIntake{Raw: []byte(`{"x":1}`), TicketHash: "def", Format: IntakeJSON},
				Validation:  IntakeValidation{Fields: []FieldValidation{{Field: "vulnerability_ids", Status: IntakeValid}}},
				Limitations: []string{"source selection unverified"},
			},
			Failed:     true,
			ErrorClass: RunStageSource,
			WallTimeMS: 40,
		},
		// 4: compat transport run (no Stage 0): decision exists but must
		// not enter intake/source/ref denominators.
		{
			FindingID: "f-compat",
			Stage0:    &Stage0Result{ConfigHash: "cfg"},
			Assessment: &Assessment{
				SchemaVersion:  AssessmentSchemaVersion,
				FindingID:      "f-compat",
				Verdict:        VerdictExploitable,
				FactValidation: ValidationComplete,
			},
			FactPasses: []FactGatePass{{Pass: 0, Validation: FactValidation{Status: ValidationComplete}}},
			Decision:   metricsDecision(RecommendationUnchanged, SupportLevelSubstantiated, AutomationWarn, 0, 0, false),
			LLMSteps:   1,
			ToolCalls:  2,
			WallTimeMS: 300,
		},
		// 5: analysis-stage technical error: the assessment never
		// materialized, so it must not count as UNCHANGED evidence.
		{
			FindingID:       "f-agent-fail",
			IntakeAttempted: true,
			Stage0:          resolved(),
			Failed:          true,
			ErrorClass:      RunStageAnalysis,
			LLMSteps:        2,
			ToolCalls:       5,
			WallTimeMS:      800,
		},
		// 6: stability semantics ran and stayed stable — a limitation but
		// not an error.
		{
			FindingID:       "f-unstable",
			IntakeAttempted: true,
			Stage0:          resolved(),
			Assessment: &Assessment{
				SchemaVersion:  AssessmentSchemaVersion,
				FindingID:      "f-unstable",
				Verdict:        VerdictNotExploitable,
				FactValidation: ValidationPartial,
			},
			Stability:  &StabilityReport{Retries: 2, Stable: true, Attempts: []StabilityAttempt{{Attempt: 1}, {Attempt: 2}, {Attempt: 3}}},
			Decision:   metricsDecision(RecommendationUnchanged, SupportLevelInsufficient, AutomationBlock, 1, 1, false),
			LLMSteps:   9,
			ToolCalls:  12,
			WallTimeMS: 2400,
		},
		// 7: provenance drift — a technical error on the drift class, never
		// a stability denominator member.
		{
			FindingID:       "f-drift",
			IntakeAttempted: true,
			Stage0:          resolved(),
			Failed:          true,
			ErrorClass:      RunStageDrift,
			Stability:       &StabilityReport{Retries: 1, Drift: true, Attempts: []StabilityAttempt{{Attempt: 1}, {Attempt: 2}}},
			WallTimeMS:      500,
		},
		// 8: one replay of a recorded run — success.
		{
			FindingID:       "f-replay-ok",
			ReplayAttempted: true,
			ReplayOK:        true,
			Decision:        metricsDecision(RecommendationUnchanged, SupportLevelSubstantiated, AutomationWarn, 0, 0, false),
			WallTimeMS:      60,
		},
		// 9: one replay that hit drift — counts in drift errors too.
		{
			FindingID:       "f-replay-drift",
			ReplayAttempted: true,
			Failed:          true,
			ErrorClass:      RunStageDrift,
			WallTimeMS:      55,
		},
	}

	m := ComputeMetrics(records)
	approxRate(t, float64(m.FindingsTotal), 10, "findings_total")

	// Intake: 7 attempted; resolved = all except f-intake-fail (validation
	// errors) — source-fail still resolved intake before failing later.
	approxRate(t, m.IntakeAutoResolutionRate, 6.0/7.0, "intake_auto_resolution_rate")
	// Source: intake resolved AND reached source stage = f-ok, f-lowered,
	// f-source-fail, f-agent-fail, f-unstable, f-drift → 6; resolved = 5.
	approxRate(t, m.SourceAutoResolutionRate, 5.0/6.0, "source_auto_resolution_rate")
	// Ref: sources resolved = 5 ticket runs; all selected → 5/5.
	approxRate(t, m.RefAutoResolutionRate, 1.0, "ref_auto_resolution_rate")
	// Decisions written: f-ok, f-lowered, f-compat, f-unstable, f-replay-ok = 5.
	approxRate(t, m.SuccessfulPackageRate, 5.0/10.0, "successful_package_rate")
	// Decisive = DISMISSED or LOWERED among decisions = 2/5.
	approxRate(t, m.PolicyDecisiveRate, 2.0/5.0, "policy_decisive_rate")
	// Technical errors: f-intake-fail, f-source-fail, f-agent-fail, f-drift,
	// f-replay-drift = 5/10.
	approxRate(t, m.TechnicalErrorRate, 5.0/10.0, "technical_error_rate")
	if m.ErrorsByStage[RunStageIntake] != 1 || m.ErrorsByStage[RunStageSource] != 1 ||
		m.ErrorsByStage[RunStageAnalysis] != 1 || m.ErrorsByStage[RunStageDrift] != 2 {
		t.Fatalf("errors_by_stage = %v", m.ErrorsByStage)
	}
	// Fact repair: gated runs (assessments) = 4 (f-ok, f-lowered, f-compat,
	// f-unstable); repaired = 1 (f-ok needed a second pass).
	approxRate(t, m.FactRepairRate, 1.0/4.0, "fact_repair_rate")
	// Unresolved evidence: 2 of 4 gated assessments are not COMPLETE.
	approxRate(t, m.UnresolvedEvidenceRate, 2.0/4.0, "unresolved_evidence_rate")
	// Demotions among decisions: f-lowered, f-unstable = 2/5.
	approxRate(t, m.DemotionRate, 2.0/5.0, "demotion_rate")
	// Conditional: f-lowered only = 1/5.
	approxRate(t, m.ConditionalRate, 1.0/5.0, "conditional_rate")
	// Low support: f-lowered (LOW), f-unstable (INSUFFICIENT) = 2/5.
	approxRate(t, m.LowSupportRate, 2.0/5.0, "low_support_rate")
	// Limitations: findings with any limitation = f-lowered (s0? no — decision
	// limitations), f-source-fail (s0 limitation), f-unstable (decision) = 3/10.
	approxRate(t, m.LimitationRate, 3.0/10.0, "limitation_rate")
	// Replay: 1 ok of 2 attempted.
	approxRate(t, m.ReplaySuccessRate, 0.5, "replay_success_rate")
	// Drift errors: f-drift + f-replay-drift = 2/10.
	approxRate(t, m.DriftErrorRate, 2.0/10.0, "drift_error_rate")
	// Stability: one non-drift report, stable → 1/1.
	approxRate(t, m.StabilityRate, 1.0, "stability_rate")
	if m.LLMSteps != 17 || m.ToolCalls != 30 {
		t.Fatalf("steps/toolcalls = %d/%d", m.LLMSteps, m.ToolCalls)
	}
	// Human and machine axes are counted separately over the five composed
	// packages; the human proposal never determines a machine bucket.
	if m.HumanActionKinds[string(HumanActionKeepOpen)] != 5 || len(m.HumanActionKinds) != 1 {
		t.Fatalf("human_action_kinds = %v", m.HumanActionKinds)
	}
	if m.MachineRecommendations[string(RecommendationDismissed)] != 1 ||
		m.MachineRecommendations[string(RecommendationLowered)] != 1 ||
		m.MachineRecommendations[string(RecommendationUnchanged)] != 3 {
		t.Fatalf("machine_recommendations = %v", m.MachineRecommendations)
	}
	if m.SupportLevels[string(SupportLevelProvedWithinScope)] != 1 ||
		m.SupportLevels[string(SupportLevelLimited)] != 1 ||
		m.SupportLevels[string(SupportLevelSubstantiated)] != 2 ||
		m.SupportLevels[string(SupportLevelInsufficient)] != 1 {
		t.Fatalf("support_levels = %v", m.SupportLevels)
	}
	// Automatic action: ALLOW machine outcomes among composed packages —
	// f-ok only = 1/5. The outcome is a package property, so the denominator
	// is the decision count, not the fact-gate count.
	approxRate(t, m.AutomaticActionRate, 1.0/5.0, "automatic_action_rate")
	// Material volume: one pinned material per resolved Stage 0 record —
	// records carrying metricsStage0() are 6 (f-ok, f-lowered,
	// f-agent-fail, f-unstable, f-drift) + metricsStage0 fields only.
	if m.MaterialCount == 0 || m.MaterialBytes != m.MaterialCount*42 {
		t.Fatalf("material counters = %d/%d", m.MaterialCount, m.MaterialBytes)
	}
	wantWall := int64(1200 + 900 + 30 + 40 + 300 + 800 + 2400 + 500 + 60 + 55)
	if m.WallTimeMS != wantWall {
		t.Fatalf("wall_time_ms = %d, want %d", m.WallTimeMS, wantWall)
	}
	// One automation outcome per composed package: f-ok ALLOW,
	// f-lowered/f-compat/f-replay-ok WARN, f-unstable BLOCK.
	if m.MachineAutomation[string(AutomationAllow)] != 1 ||
		m.MachineAutomation[string(AutomationWarn)] != 3 ||
		m.MachineAutomation[string(AutomationBlock)] != 1 {
		t.Fatalf("machine_automation = %v", m.MachineAutomation)
	}
}

// TestMetricsZeroRuns: an empty batch yields zero rates and zero counts —
// never NaN, never a panic on the zero denominator.
func TestMetricsZeroRuns(t *testing.T) {
	m := ComputeMetrics(nil)
	if m.FindingsTotal != 0 {
		t.Fatalf("findings_total = %d", m.FindingsTotal)
	}
	for name, v := range map[string]float64{
		"intake_auto_resolution_rate": m.IntakeAutoResolutionRate,
		"policy_decisive_rate":        m.PolicyDecisiveRate,
		"successful_package_rate":     m.SuccessfulPackageRate,
		"technical_error_rate":        m.TechnicalErrorRate,
		"replay_success_rate":         m.ReplaySuccessRate,
		"stability_rate":              m.StabilityRate,
		"drift_error_rate":            m.DriftErrorRate,
	} {
		if v != 0 || math.IsNaN(v) || math.IsInf(v, 0) {
			t.Fatalf("%s = %v on empty batch", name, v)
		}
	}
	if len(m.HumanActionKinds) != 0 || len(m.SupportLevels) != 0 ||
		len(m.MachineRecommendations) != 0 || len(m.MachineAutomation) != 0 {
		t.Fatalf("empty batch distributions = %+v", m)
	}
}

// TestMetricsErrorLimitationSplit: technical errors and limitations are
// counted on separate channels — a failed run contributes to error rates
// only, and its limitations never mint a decision-side denominator member.
func TestMetricsErrorLimitationSplit(t *testing.T) {
	s0fail := &Stage0Result{
		Raw:         RawIntake{Raw: []byte(`{"x":1}`), TicketHash: "aa", Format: IntakeJSON},
		Validation:  IntakeValidation{Fields: []FieldValidation{{Field: "severity", Status: IntakeUnavailable}}},
		Limitations: []string{"severity absent"},
	}
	records := []RunRecord{
		{FindingID: "a", IntakeAttempted: true, Stage0: s0fail, Failed: true, ErrorClass: RunStageIntake},
		{FindingID: "b", IntakeAttempted: true, Stage0: metricsStage0(),
			Assessment: &Assessment{Verdict: VerdictNotExploitable, FactValidation: ValidationComplete},
			Decision:   metricsDecision(RecommendationUnchanged, SupportLevelSubstantiated, AutomationWarn, 0, 0, false)},
	}
	m := ComputeMetrics(records)
	approxRate(t, m.TechnicalErrorRate, 0.5, "technical_error_rate")
	approxRate(t, m.SuccessfulPackageRate, 0.5, "successful_package_rate")
	// The failed run's UNCHANGED-shaped absence must not inflate decisive
	// denominators: policy_decisive counts decisions only (0/1).
	approxRate(t, m.PolicyDecisiveRate, 0.0, "policy_decisive_rate")
	// The limitation on the failed run is still a limitation of the batch —
	// limitations surface, they never masquerade as a verdict.
	approxRate(t, m.LimitationRate, 0.5, "limitation_rate")
}

// TestMetricsDoesNotMutateDecision: the metric pipeline is a read-only
// projection — computing metrics over a composed package must not change
// its canonical hash, recommendation, demotions or facts.
func TestMetricsDoesNotMutateDecision(t *testing.T) {
	s0 := goodStage0()
	pkg := metricsDecision(RecommendationLowered, SupportLevelLimited, AutomationWarn, 2, 3, true)
	pkg.RunID = "run-fixture"
	pkg.FindingID = s0.Input.Finding.FindingID
	before := canonicalDecisionHash(*pkg)
	beforeJSON := mustMetricsJSON(t, *pkg)

	m := ComputeMetrics([]RunRecord{{
		FindingID:       pkg.FindingID,
		IntakeAttempted: true,
		Stage0:          &s0,
		Decision:        pkg,
	}})
	_ = m

	after := canonicalDecisionHash(*pkg)
	if before != after {
		t.Fatalf("decision hash changed by metrics: %s -> %s", before, after)
	}
	if afterJSON := mustMetricsJSON(t, *pkg); afterJSON != beforeJSON {
		t.Fatal("decision bytes changed by metrics")
	}
	if pkg.MachineDisposition.Recommendation != RecommendationLowered || len(pkg.MachineDisposition.Demotions) != 2 {
		t.Fatalf("decision mutated: %+v", pkg.MachineDisposition)
	}
}

// TestMetricsWrittenArtifact: WriteMetrics persists the machine-readable
// aggregate and appends a batch metrics event to the top-level audit log —
// the metrics themselves never gate the run's decision artifacts.
func TestMetricsWrittenArtifact(t *testing.T) {
	dir := t.TempDir()
	records := []RunRecord{
		{FindingID: "f1", Decision: metricsDecision(RecommendationUnchanged, SupportLevelSubstantiated, AutomationWarn, 0, 0, false)},
		{FindingID: "f2", Failed: true, ErrorClass: RunStageAnalysis},
	}
	m, path, err := WriteMetrics(context.Background(), dir, records)
	if err != nil {
		t.Fatalf("WriteMetrics: %v", err)
	}
	if m.FindingsTotal != 2 || m.TechnicalErrorRate != 0.5 {
		t.Fatalf("metrics = %+v", m)
	}
	if filepath.Base(path) != "metrics.json" || filepath.Dir(path) != dir {
		t.Fatalf("metrics path = %s", path)
	}
	raw := mustRead(t, path)
	var doc struct {
		SchemaVersion string  `json:"schema_version"`
		Metrics       Metrics `json:"metrics"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("metrics.json does not parse: %v", err)
	}
	if doc.SchemaVersion != MetricsSchemaVersion {
		t.Fatalf("schema_version = %q", doc.SchemaVersion)
	}
	if doc.Metrics.FindingsTotal != 2 || len(doc.Metrics.MachineRecommendations) != 1 {
		t.Fatalf("persisted metrics = %+v", doc.Metrics)
	}
	// The batch audit event is append-only under <out>/audit/events.jsonl.
	auditBytes, err := os.ReadFile(filepath.Join(dir, "audit", "events.jsonl"))
	if err != nil {
		t.Fatalf("batch audit log missing: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(auditBytes)), "\n")
	if len(lines) != 1 {
		t.Fatalf("audit events = %d lines, want 1", len(lines))
	}
	var ev AuditEvent
	if err := json.Unmarshal([]byte(lines[0]), &ev); err != nil {
		t.Fatalf("audit event does not parse: %v", err)
	}
	if ev.Type != AuditEventMetrics || ev.Metrics == nil || ev.Metrics.FindingsTotal != 2 {
		t.Fatalf("metrics audit event = %+v", ev)
	}
}

func mustMetricsJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestMetricsFalsifierCounters(t *testing.T) {
	verified := *falsifierReport(FalsifierVerified, []string{"e1"}, "verified")
	unsupported := *falsifierReport(FalsifierUnknown, []string{"e2"}, "unsupported")
	demoted := *falsifierReport(FalsifierUnknown, []string{"e3"}, "demoted")
	demoted.Proofs[0].History = []FalsifierTransition{{From: FalsifierVerified, To: FalsifierUnknown, Reason: "scope widened"}}
	p := metricsDecision(RecommendationDismissed, SupportLevelProvedWithinScope, AutomationAllow, 0, 0, false)
	p.FalsifierProofs = verified.Proofs
	m := ComputeMetrics([]RunRecord{{Assessment: &Assessment{FalsifierProposals: []FalsifierProposal{{ID: "p1"}, {ID: "p2"}, {ID: "p3"}}}, Falsifiers: &FalsifierReport{Proofs: append(verified.Proofs, unsupported.Proofs[0], demoted.Proofs[0])}, Decision: p}})
	if m.AgentFalsifierProposalCount != 3 || m.VerifiedFalsifierCount != 1 || m.UnsupportedFalsifierCount != 2 || m.FalsifierDemotionCount != 1 || m.FalsifierDismissalCount != 1 {
		t.Fatalf("metrics = %+v", m)
	}
	if m.AgentFalsifierProposalCount == m.VerifiedFalsifierCount {
		t.Fatal("proposal count must not equal admission count")
	}
}

func TestMetricsUnsupportedIsNotDismissal(t *testing.T) {
	p := metricsDecision(RecommendationUnchanged, SupportLevelLimited, AutomationWarn, 0, 0, false)
	m := ComputeMetrics([]RunRecord{{Assessment: &Assessment{FalsifierProposals: []FalsifierProposal{{ID: "p"}}}, Falsifiers: falsifierReport(FalsifierUnknown, nil, "p"), Decision: p}})
	if m.UnsupportedFalsifierCount == 0 || m.FalsifierDismissalCount != 0 ||
		p.MachineDisposition.Recommendation != RecommendationUnchanged {
		t.Fatalf("metrics=%+v recommendation=%s", m, p.MachineDisposition.Recommendation)
	}
}

func TestMetricsDemotionCount(t *testing.T) {
	r := falsifierReport(FalsifierUnknown, nil, "p")
	r.Proofs[0].History = []FalsifierTransition{{From: FalsifierVerified, To: FalsifierUnknown, Reason: "retry mismatch"}}
	p := metricsDecision(RecommendationUnchanged, SupportLevelLimited, AutomationWarn, 0, 0, false)
	m := ComputeMetrics([]RunRecord{{Falsifiers: r, Decision: p}})
	if m.FalsifierDemotionCount != 1 || m.FalsifierDismissalCount != 0 {
		t.Fatalf("metrics=%+v", m)
	}
}

// TestBatchMeasurementRatio documents the controller-side ratio under
// triage-metrics.v3: verified proofs are divided by agent proposals,
// and an empty denominator is reported as zero rather than NaN.
func TestBatchMeasurementRatio(t *testing.T) {
	verified := *falsifierReport(FalsifierVerified, []string{"e1"}, "verified")
	p := metricsDecision(RecommendationDismissed, SupportLevelProvedWithinScope, AutomationAllow, 0, 0, false)
	p.FalsifierProofs = verified.Proofs
	m := ComputeMetrics([]RunRecord{{
		Assessment: &Assessment{FalsifierProposals: []FalsifierProposal{{ID: "p1"}, {ID: "p2"}}},
		Falsifiers: &verified,
		Decision:   p,
	}})
	if got := float64(m.VerifiedFalsifierCount) / float64(m.AgentFalsifierProposalCount); got != 0.5 {
		t.Fatalf("verified_proposal_ratio = %v, want 0.5", got)
	}
	empty := ComputeMetrics(nil)
	if empty.AgentFalsifierProposalCount != 0 || empty.VerifiedFalsifierCount != 0 {
		t.Fatalf("empty batch counters = %+v", empty)
	}
	// The controller calculation is rate(0, 0), whose contract is zero.
	if got := rate(empty.VerifiedFalsifierCount, empty.AgentFalsifierProposalCount); got != 0 {
		t.Fatalf("zero denominator ratio = %v, want 0", got)
	}
}

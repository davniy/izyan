package vexbench

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/fedorovmv/izyan/internal/productb/triage"
)

// TriageScoreSchemaVersion pins the triage score schema version.
const TriageScoreSchemaVersion = "triage-score.v1"

// TriageReviewEventSchemaVersion pins the triage review event schema version.
const TriageReviewEventSchemaVersion = "triage-review-event.v1"

// TriageReviewEvent is a blinded reviewer evaluation event bound to canonical decision package hash.
type TriageReviewEvent struct {
	SchemaVersion          string                        `json:"schema_version"`
	DecisionPackageHash    string                        `json:"decision_package_hash"`
	ReviewerSession        string                        `json:"reviewer_session,omitempty"`
	StartedAt              time.Time                     `json:"started_at"`
	FinishedAt             time.Time                     `json:"finished_at"`
	Accepted               bool                          `json:"accepted"`
	DecisionReadyConfirmed bool                          `json:"decision_ready_confirmed"`
	IdentityCorrect        *bool                         `json:"identity_correct,omitempty"`
	MechanismCorrect       *bool                         `json:"mechanism_correct,omitempty"`
	DecisiveFactualErrors  int                           `json:"decisive_factual_errors"`
	MandatoryFactRefsRead  []string                      `json:"mandatory_fact_refs_read,omitempty"`
	RepositoryOpenCount    int                           `json:"repository_open_count"`
	ToolRerunCount         int                           `json:"tool_rerun_count"`
	TechnicalFollowUpCount int                           `json:"technical_follow_up_count"`
	ReturnedForRemediation bool                          `json:"returned_for_remediation"`
	Reopened               bool                          `json:"reopened"`
	InitialBranchID        string                        `json:"initial_branch_id,omitempty"`
	SelectedBranchID       string                        `json:"selected_branch_id,omitempty"`
	EnvironmentAnswers     []triage.EnvironmentAssertion `json:"environment_answers,omitempty"`
}

// Validate checks event integrity.
func (e TriageReviewEvent) Validate() error {
	if strings.TrimSpace(e.DecisionPackageHash) == "" {
		return errors.New("decision_package_hash is required")
	}
	if e.FinishedAt.Before(e.StartedAt) {
		return errors.New("finished_at cannot precede started_at")
	}
	return nil
}

// ProductAMetrics isolates Product A authority and benchmark metrics.
type ProductAMetrics struct {
	TotalCases         int     `json:"total_cases"`
	Decided            int     `json:"decided"`
	ExternalDependency int     `json:"external_dependency"`
	AnalysisFailed     int     `json:"analysis_failed"`
	FalseSafe          int     `json:"false_safe"`
	FalsePositive      int     `json:"false_positive"`
	SafeClearRate      float64 `json:"safe_clear_rate"`
	ExploitableRecall  float64 `json:"exploitable_recall"`
	InconclusiveRate   float64 `json:"inconclusive_rate"`
	CompletionRate     float64 `json:"completion_rate"`
	StatusCorrect      int     `json:"status_correct"`
	ReasonCorrect      int     `json:"reason_correct"`
}

// SupportLevelCalibration records calibration for one support level.
type SupportLevelCalibration struct {
	Level           triage.SupportLevel `json:"level"`
	TotalAssessed   int                 `json:"total_assessed"`
	Consistent      int                 `json:"consistent"`
	Mismatches      int                 `json:"mismatches"`
	CalibrationRate *float64            `json:"calibration_rate"`
}

// SupportCalibrationMetrics records support-level calibration against assessed outcomes only.
type SupportCalibrationMetrics struct {
	AssessedCases   int                                             `json:"assessed_cases"`
	UnassessedCases int                                             `json:"unassessed_cases"`
	ByLevel         map[triage.SupportLevel]SupportLevelCalibration `json:"by_level"`
}

// ReviewTimeSummary holds statistical percentiles for human review duration.
type ReviewTimeSummary struct {
	Count  int      `json:"count"`
	Median *float64 `json:"median"`
	P75    *float64 `json:"p75"`
	P95    *float64 `json:"p95"`
}

func percentile(values []float64, q float64) float64 {
	if len(values) == 0 {
		return 0
	}
	if len(values) == 1 {
		return values[0]
	}
	xs := append([]float64(nil), values...)
	sort.Float64s(xs)
	idx := (float64(len(xs)-1) * q) / 100.0
	lo := int(math.Floor(idx))
	hi := int(math.Ceil(idx))
	if lo == hi {
		return xs[lo]
	}
	frac := idx - float64(lo)
	return xs[lo] + frac*(xs[hi]-xs[lo])
}

func summarizeTimes(durations []float64) ReviewTimeSummary {
	n := len(durations)
	if n == 0 {
		return ReviewTimeSummary{Count: 0}
	}
	med := percentile(durations, 50)
	p75 := percentile(durations, 75)
	p95 := percentile(durations, 95)
	return ReviewTimeSummary{
		Count:  n,
		Median: &med,
		P75:    &p75,
		P95:    &p95,
	}
}

// ProductBRecommendationMetrics isolates Product B human-work and recommendation quality.
type ProductBRecommendationMetrics struct {
	TotalPreparedCases                  int                       `json:"total_prepared_cases"`
	DeliveredPackages                   int                       `json:"delivered_packages"`
	DeliveredPackageRate                float64                   `json:"delivered_package_rate"`
	ReviewerConfirmedDecisionReady      int                       `json:"reviewer_confirmed_decision_ready"`
	ReviewerConfirmedDecisionReadyRate *float64                   `json:"reviewer_confirmed_decision_ready_rate"`
	UnreviewedPackages                  int                       `json:"unreviewed_packages"`
	IdentityCorrectReviews              int                       `json:"identity_correct_reviews"`
	IdentityAssessedReviews             int                       `json:"identity_assessed_reviews"`
	IdentityCorrectRate                 *float64                  `json:"identity_correct_rate"`
	MechanismCorrectReviews             int                       `json:"mechanism_correct_reviews"`
	MechanismAssessedReviews            int                       `json:"mechanism_assessed_reviews"`
	MechanismCorrectRate                *float64                  `json:"mechanism_correct_rate"`
	DecisiveFactualErrors               int                       `json:"decisive_factual_errors"`
	IncorrectNegativeJudgments          int                       `json:"incorrect_negative_judgments"`
	CloseOnExploitable                  int                       `json:"close_on_exploitable"`
	ReductionControlMismatches          int                       `json:"reduction_control_mismatches"`
	AdditionalRepoOpens                 int                       `json:"additional_repo_opens"`
	RepoOpenRate                        *float64                  `json:"repo_open_rate"`
	AdditionalToolReruns                int                       `json:"additional_tool_reruns"`
	ToolRerunRate                       *float64                  `json:"tool_rerun_rate"`
	TechnicalFollowUps                  int                       `json:"technical_follow_ups"`
	TechnicalFollowUpRate               *float64                  `json:"technical_follow_up_rate"`
	ReviewTimeSeconds                   ReviewTimeSummary         `json:"review_time_seconds"`
	DeclaredEnvironmentQuestions        int                       `json:"declared_environment_questions"`
	EnvironmentAnswers                  int                       `json:"environment_answers"`
	EnvironmentUnknownAnswers           int                       `json:"environment_unknown_answers"`
	BranchChangesAfterAnswer            int                       `json:"branch_changes_after_answer"`
	SupportCalibration                  SupportCalibrationMetrics `json:"support_calibration"`
}

// AutomationMetrics isolates machine disposition and execution cost.
type AutomationMetrics struct {
	TotalPackages            int      `json:"total_packages"`
	Reductions               int      `json:"reductions"`
	Unchanged                int      `json:"unchanged"`
	FalseSafe                int      `json:"false_safe"`
	UnverifiedReductions     int      `json:"unverified_reductions"`
	ReductionRate            float64  `json:"reduction_rate"`
	AutomationAllow          int      `json:"automation_allow"`
	AutomationWarn           int      `json:"automation_warn"`
	AutomationBlock          int      `json:"automation_block"`
	ObservedLatencySeconds   float64  `json:"observed_latency_seconds"`
	ObservedPromptTokens     int      `json:"observed_prompt_tokens"`
	ObservedCompletionTokens int      `json:"observed_completion_tokens"`
	ObservedTotalTokens      int      `json:"observed_total_tokens"`
	ObservedCost             *float64 `json:"observed_cost"`
	CostStatus               string   `json:"cost_status"`
}

// TriageScore is the complete triage-score.v1 aggregate.
type TriageScore struct {
	SchemaVersion   string                        `json:"schema_version"`
	ScoredAt        time.Time                     `json:"scored_at"`
	InputBundleHash string                        `json:"input_bundle_hash"`
	ProductA        ProductAMetrics               `json:"product_a"`
	ProductB        ProductBRecommendationMetrics `json:"product_b"`
	Automation      AutomationMetrics             `json:"automation"`
	Violations      []string                      `json:"violations,omitempty"`
}

// TriageScoreInput aggregates the inputs to be scored across independent axes.
type TriageScoreInput struct {
	InputBundleHash string
	PreparedCases   []PreparedCase
	Tasks           []Task
	PredictionsA    []Prediction
	PackagesB       []triage.DecisionPackage
	EvaluationsB    []triage.DecisionEvaluation
	RunsB           []VexTriageRun
	ReviewEvents    []TriageReviewEvent
	HumanDecisions  []triage.HumanDecisionRecord
}

// ComputeTriageScore computes metrics across Product A authority, Product B human recommendation,
// and Automation axes independently.
func ComputeTriageScore(in TriageScoreInput) (TriageScore, error) {
	score := TriageScore{
		SchemaVersion:   TriageScoreSchemaVersion,
		ScoredAt:        time.Now().UTC(),
		InputBundleHash: in.InputBundleHash,
		ProductB: ProductBRecommendationMetrics{
			SupportCalibration: SupportCalibrationMetrics{
				ByLevel: make(map[triage.SupportLevel]SupportLevelCalibration),
			},
		},
	}

	// 1. Compute Product A Authority Metrics independently
	if len(in.Tasks) > 0 {
		m := Compute(in.PredictionsA, in.Tasks)
		score.ProductA = ProductAMetrics{
			TotalCases:         m.Total,
			Decided:            m.Decided,
			ExternalDependency: m.ExternalDependency,
			AnalysisFailed:     m.AnalysisFailed,
			FalseSafe:          m.FalseSafe,
			FalsePositive:      m.FalsePositive,
			SafeClearRate:      m.SafeClearRate,
			ExploitableRecall:  m.ExploitableRecall,
			InconclusiveRate:   m.InconclusiveRate,
			CompletionRate:     m.CompletionRate,
			StatusCorrect:      m.StatusCorrect,
			ReasonCorrect:      m.ReasonCorrect,
		}
	}

	// Index packages by canonical hash and by finding ID
	pkgByHash := make(map[string]triage.DecisionPackage, len(in.PackagesB))
	pkgByFinding := make(map[string]triage.DecisionPackage, len(in.PackagesB))
	for _, p := range in.PackagesB {
		h := triage.CanonicalDecisionHash(p)
		pkgByHash[h] = p
		pkgByFinding[p.FindingID] = p
	}

	// 2. Compute Product B Recommendation & Human Metrics
	totalPrepared := len(in.PreparedCases)
	if totalPrepared == 0 {
		totalPrepared = len(in.PackagesB)
	}
	score.ProductB.TotalPreparedCases = totalPrepared
	score.ProductB.DeliveredPackages = len(in.PackagesB)
	if totalPrepared > 0 {
		score.ProductB.DeliveredPackageRate = float64(len(in.PackagesB)) / float64(totalPrepared)
	}

	// Build map of review events by package hash
	reviewsByHash := make(map[string][]TriageReviewEvent)
	for _, r := range in.ReviewEvents {
		if err := r.Validate(); err != nil {
			score.Violations = append(score.Violations, fmt.Sprintf("invalid review event: %v", err))
			continue
		}
		if _, ok := pkgByHash[r.DecisionPackageHash]; !ok {
			score.Violations = append(score.Violations, fmt.Sprintf("foreign package hash in review event: %s", r.DecisionPackageHash))
			continue
		}
		reviewsByHash[r.DecisionPackageHash] = append(reviewsByHash[r.DecisionPackageHash], r)
	}

	// Count unreviewed packages
	unreviewed := 0
	confirmedDR := 0
	for h := range pkgByHash {
		revs, ok := reviewsByHash[h]
		if !ok || len(revs) == 0 {
			unreviewed++
			continue
		}
		// Must have reviewer confirmation
		isDR := false
		for _, rev := range revs {
			if rev.DecisionReadyConfirmed {
				isDR = true
				break
			}
		}
		if isDR {
			confirmedDR++
		}
	}
	score.ProductB.UnreviewedPackages = unreviewed
	score.ProductB.ReviewerConfirmedDecisionReady = confirmedDR
	if len(in.PackagesB) > 0 && len(in.ReviewEvents) > 0 {
		rate := float64(confirmedDR) / float64(len(in.PackagesB))
		score.ProductB.ReviewerConfirmedDecisionReadyRate = &rate
	}

	// Aggregate reviewer observations
	var reviewDurations []float64
	totalRepoOpens := 0
	totalToolReruns := 0
	totalFollowUps := 0
	var totalReviews int

	for _, rev := range in.ReviewEvents {
		if _, ok := pkgByHash[rev.DecisionPackageHash]; !ok {
			continue
		}
		totalReviews++
		if rev.IdentityCorrect != nil {
			score.ProductB.IdentityAssessedReviews++
			if *rev.IdentityCorrect {
				score.ProductB.IdentityCorrectReviews++
			}
		}
		if rev.MechanismCorrect != nil {
			score.ProductB.MechanismAssessedReviews++
			if *rev.MechanismCorrect {
				score.ProductB.MechanismCorrectReviews++
			}
		}
		score.ProductB.DecisiveFactualErrors += rev.DecisiveFactualErrors
		if rev.RepositoryOpenCount > 0 {
			totalRepoOpens += rev.RepositoryOpenCount
		}
		if rev.ToolRerunCount > 0 {
			totalToolReruns += rev.ToolRerunCount
		}
		if rev.TechnicalFollowUpCount > 0 {
			totalFollowUps += rev.TechnicalFollowUpCount
		}
		if rev.FinishedAt.After(rev.StartedAt) {
			reviewDurations = append(reviewDurations, rev.FinishedAt.Sub(rev.StartedAt).Seconds())
		}
		if rev.InitialBranchID != "" && rev.SelectedBranchID != "" && rev.InitialBranchID != rev.SelectedBranchID {
			score.ProductB.BranchChangesAfterAnswer++
		}
	}

	if score.ProductB.IdentityAssessedReviews > 0 {
		rate := float64(score.ProductB.IdentityCorrectReviews) / float64(score.ProductB.IdentityAssessedReviews)
		score.ProductB.IdentityCorrectRate = &rate
	}
	if score.ProductB.MechanismAssessedReviews > 0 {
		rate := float64(score.ProductB.MechanismCorrectReviews) / float64(score.ProductB.MechanismAssessedReviews)
		score.ProductB.MechanismCorrectRate = &rate
	}

	score.ProductB.AdditionalRepoOpens = totalRepoOpens
	score.ProductB.AdditionalToolReruns = totalToolReruns
	score.ProductB.TechnicalFollowUps = totalFollowUps
	if totalReviews > 0 {
		roRate := float64(totalRepoOpens) / float64(totalReviews)
		score.ProductB.RepoOpenRate = &roRate
		trRate := float64(totalToolReruns) / float64(totalReviews)
		score.ProductB.ToolRerunRate = &trRate
		fuRate := float64(totalFollowUps) / float64(totalReviews)
		score.ProductB.TechnicalFollowUpRate = &fuRate
	}

	score.ProductB.ReviewTimeSeconds = summarizeTimes(reviewDurations)

	// Environment question metrics from packages
	for _, p := range in.PackagesB {
		if p.HumanReviewPlan != nil {
			score.ProductB.DeclaredEnvironmentQuestions += len(p.HumanReviewPlan.Variables)
		}
	}

	// Environment answers from HumanDecisionRecord and ReviewEvents
	for _, hd := range in.HumanDecisions {
		score.ProductB.EnvironmentAnswers += len(hd.AssertionIDs)
	}
	for _, rev := range in.ReviewEvents {
		score.ProductB.EnvironmentAnswers += len(rev.EnvironmentAnswers)
		for _, a := range rev.EnvironmentAnswers {
			if strings.EqualFold(a.Value, "unknown") {
				score.ProductB.EnvironmentUnknownAnswers++
			}
		}
	}

	// EvaluationsB aggregates: human mistakes vs machine safety vs support calibration
	for _, ev := range in.EvaluationsB {
		score.ProductB.IncorrectNegativeJudgments += int(ev.Human.IncorrectNegativeJudgments)
		score.ProductB.CloseOnExploitable += int(ev.Human.CloseOnExploitable)
		score.ProductB.ReductionControlMismatches += int(ev.Human.ReductionControlMismatches)

		// Automation metrics
		score.Automation.FalseSafe += int(ev.Machine.FalseSafe)
		score.Automation.UnverifiedReductions += int(ev.Machine.UnverifiedReductions)

		// Support Calibration
		lvl := ev.Support
		if lvl == "" {
			lvl = triage.SupportLevelInsufficient
		}
		entry := score.ProductB.SupportCalibration.ByLevel[lvl]
		entry.Level = lvl
		if ev.Coverage.ControlDisposition == triage.ComparisonAssessed {
			score.ProductB.SupportCalibration.AssessedCases++
			entry.TotalAssessed++
			if ev.Machine.FalseSafe == 0 && ev.Human.ReductionControlMismatches == 0 {
				entry.Consistent++
			} else {
				entry.Mismatches++
			}
		} else {
			score.ProductB.SupportCalibration.UnassessedCases++
		}
		if entry.TotalAssessed > 0 {
			rate := float64(entry.Consistent) / float64(entry.TotalAssessed)
			entry.CalibrationRate = &rate
		}
		score.ProductB.SupportCalibration.ByLevel[lvl] = entry
	}

	// 3. Automation Metrics
	score.Automation.TotalPackages = len(in.PackagesB)
	for _, p := range in.PackagesB {
		switch p.MachineDisposition.Recommendation {
		case triage.RecommendationDismissed, triage.RecommendationLowered:
			score.Automation.Reductions++
		default:
			score.Automation.Unchanged++
		}
		switch p.MachineDisposition.Automation {
		case triage.AutomationAllow:
			score.Automation.AutomationAllow++
		case triage.AutomationWarn:
			score.Automation.AutomationWarn++
		case triage.AutomationBlock:
			score.Automation.AutomationBlock++
		}
	}
	if score.Automation.TotalPackages > 0 {
		score.Automation.ReductionRate = float64(score.Automation.Reductions) / float64(score.Automation.TotalPackages)
	}

	// Runs observed usage
	costStatus := "unassessed"
	hasCost := false
	var totalCost float64
	for _, r := range in.RunsB {
		if r.TotalPromptTokens != nil {
			score.Automation.ObservedPromptTokens += int(*r.TotalPromptTokens)
		}
		if r.TotalCompletionTokens != nil {
			score.Automation.ObservedCompletionTokens += int(*r.TotalCompletionTokens)
		}
		if r.TotalTokens != nil {
			score.Automation.ObservedTotalTokens += int(*r.TotalTokens)
		}
		for _, ex := range r.Exchanges {
			score.Automation.ObservedLatencySeconds += ex.Duration.Seconds()
		}
		if r.CostUSD != nil {
			hasCost = true
			totalCost += *r.CostUSD
		}
	}
	if hasCost {
		score.Automation.ObservedCost = &totalCost
		costStatus = "measured"
	}
	score.Automation.CostStatus = costStatus

	return score, nil
}

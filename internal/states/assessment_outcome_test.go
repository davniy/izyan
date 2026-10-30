package states

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/evaluator"
	"github.com/davniy/izyan/internal/persistence/filesystem"
	"github.com/davniy/izyan/internal/rootcause"
	"github.com/davniy/izyan/internal/workflow"
)

// requireFailedAnalysis asserts the terminal assessment shape: no public
// verdict and at least the named typed cause. A failed assessment must never
// publish a stale INCONCLUSIVE verdict.
func requireFailedAnalysis(t *testing.T, c *domain.AnalysisCase, code domain.GapCode) {
	t.Helper()
	if c.Verdict != nil {
		t.Fatalf("verdict=%+v, want none for a failed assessment", c.Verdict)
	}
	for _, g := range c.AnalysisGaps {
		if g.Code == code {
			return
		}
	}
	t.Fatalf("missing analysis gap %s: %+v", code, c.AnalysisGaps)
}

func outcomeCase(id string, state domain.WorkflowState) *domain.AnalysisCase {
	return &domain.AnalysisCase{
		ID: domain.CaseID(id),
		Vulnerability: domain.Vulnerability{
			ID: "GO-TEST-OUTCOME", Module: "example.com/product", BaseSeverity: "HIGH",
		},
		Workflow: domain.WorkflowStatus{
			State:  state,
			Limits: domain.AnalysisLimits{MaxIterations: 8},
		},
	}
}

func runOutcomeEngine(t *testing.T, c *domain.AnalysisCase, caseDir string,
	handlers ...workflow.StateHandler) error {
	t.Helper()
	store := filesystem.New(caseDir)
	if err := store.Create(context.Background(), c); err != nil {
		t.Fatalf("create case: %v", err)
	}
	engine := workflow.New(store, handlers...)
	engine.FailureState = domain.StateBuildReport
	return engine.Run(context.Background(), c)
}

func requireReport(t *testing.T, dir string) {
	t.Helper()
	for _, name := range []string{"report.json", "report.md"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("failure report missing %s: %v", name, err)
		}
	}
}

type deadlineState struct{ state domain.WorkflowState }

func (h deadlineState) State() domain.WorkflowState { return h.state }

func (h deadlineState) Run(context.Context, *domain.AnalysisCase) (workflow.Transition, error) {
	return workflow.Transition{}, context.DeadlineExceeded
}

// TestPerimeterTrustBasis: exposure shape never selects a trusted actual
// profile. Only an admitted perimeter basis (deployment policy or explicit
// operator selection) may do so, and the hypothetical cluster-perimeter
// result stays conditional.
func TestPerimeterTrustBasis(t *testing.T) {
	peerCase := func(id string) *domain.AnalysisCase {
		return &domain.AnalysisCase{
			ID:            domain.CaseID(id),
			Vulnerability: domain.Vulnerability{ID: "GO-TEST-PERIMETER", BaseSeverity: "HIGH"},
			Affected:      &domain.AffectedResult{Scope: exactScope("GO-TEST-PERIMETER")},
			Exploit: &domain.ExploitModel{MandatoryConditions: []domain.Condition{{
				ID:        "C-PEER",
				Kind:      domain.ConditionAttackerControl,
				Mandatory: true,
				Params:    map[string]string{domain.ParamInputSource: domain.InputPeer},
			}}},
			Claims: []domain.Claim{{ConditionID: "C-PEER", Result: domain.ClaimUnknown}},
		}
	}
	run := func(t *testing.T, c *domain.AnalysisCase) {
		t.Helper()
		if _, err := (EvaluateVerdict{Evaluator: evaluator.VerdictEvaluator{}}).Run(context.Background(), c); err != nil {
			t.Fatalf("EvaluateVerdict: %v", err)
		}
	}

	t.Run("listener-locality basis selects zero-trust", func(t *testing.T) {
		c := peerCase("CASE-PERIMETER-LOCALITY")
		c.DetectedPerimeter = domain.PerimeterClusterInternal
		c.PerimeterAssessment = &domain.PerimeterAssessment{
			Perimeter: domain.PerimeterClusterInternal,
			Basis:     domain.PerimeterBasisListenerLocality,
			Limitations: []string{
				domain.PerimeterLocalityNotTrustLimitation,
			},
		}
		run(t, c)
		requireFailedAnalysis(t, c, domain.GapInputTraceIncomplete)
		if !c.Profiles[0].IsTargetActual || c.Profiles[1].IsTargetActual {
			t.Fatalf("locality selected the trusted profile: %+v", c.Profiles)
		}
	})

	t.Run("detected perimeter without a typed basis selects zero-trust", func(t *testing.T) {
		c := peerCase("CASE-PERIMETER-DETECTED")
		c.DetectedPerimeter = domain.PerimeterClusterInternal
		run(t, c)
		requireFailedAnalysis(t, c, domain.GapInputTraceIncomplete)
		if !c.Profiles[0].IsTargetActual || c.Profiles[1].IsTargetActual {
			t.Fatalf("legacy detected perimeter selected the trusted profile: %+v", c.Profiles)
		}
		if !strings.Contains(strings.Join(c.ProfileAssessments[1].Result.Limitations, "\n"), "hypothetical cluster-perimeter profile") {
			t.Fatalf("hypothetical profile is not marked conditional: %v", c.ProfileAssessments[1].Result.Limitations)
		}
	})

	t.Run("operator-declared basis selects the cluster profile", func(t *testing.T) {
		c := peerCase("CASE-PERIMETER-OPERATOR")
		c.PerimeterAssessment = &domain.PerimeterAssessment{
			Perimeter: domain.PerimeterClusterInternal,
			Basis:     domain.PerimeterBasisOperatorDeclared,
		}
		run(t, c)
		if c.Profiles[0].IsTargetActual || !c.Profiles[1].IsTargetActual {
			t.Fatalf("operator declaration did not select the cluster profile: %+v", c.Profiles)
		}
		// The operator rewrite turns the peer-input claim FALSE, grounding
		// NEPF on the declared trust boundary.
		if c.Verdict == nil || c.Verdict.Verdict != domain.VerdictNoExploitPathFound {
			t.Fatalf("verdict=%+v, want NEPF on the admitted trust boundary", c.Verdict)
		}
		if c.Verdict.GroundBasis != domain.BasisDeclaredTrust {
			t.Fatalf("ground basis=%q, want %q", c.Verdict.GroundBasis, domain.BasisDeclaredTrust)
		}
	})

	t.Run("deployment-policy basis selects the cluster profile", func(t *testing.T) {
		c := peerCase("CASE-PERIMETER-POLICY")
		c.PerimeterAssessment = &domain.PerimeterAssessment{
			Perimeter: domain.PerimeterClusterInternal,
			Basis:     domain.PerimeterBasisDeploymentPolicy,
		}
		run(t, c)
		if c.Profiles[0].IsTargetActual || !c.Profiles[1].IsTargetActual {
			t.Fatalf("deployment policy did not select the cluster profile: %+v", c.Profiles)
		}
		if c.Verdict == nil || c.Verdict.Verdict != domain.VerdictNoExploitPathFound {
			t.Fatalf("verdict=%+v, want NEPF on the admitted policy boundary", c.Verdict)
		}
	})

	t.Run("operator override is an explicit declared basis", func(t *testing.T) {
		dir := t.TempDir()
		c := &domain.AnalysisCase{
			ID: "CASE-PERIMETER-OVERRIDE",
			Product: domain.ProductSnapshot{
				Repository:        dir,
				PerimeterOverride: domain.PerimeterClusterInternal,
			},
		}
		(CollectEvidence{}).runExposure(context.Background(), c)
		if c.PerimeterAssessment == nil {
			t.Fatal("exposure classification was not recorded")
		}
		if c.PerimeterAssessment.Basis != domain.PerimeterBasisOperatorDeclared {
			t.Fatalf("basis=%s, want operator-declared", c.PerimeterAssessment.Basis)
		}
		if !c.PerimeterAssessment.AllowsTrustedPeerSelection() {
			t.Fatalf("explicit operator override did not admit trust: %+v", c.PerimeterAssessment)
		}
	})

	t.Run("loopback listener facts produce a non-trust basis", func(t *testing.T) {
		dir := t.TempDir()
		c := &domain.AnalysisCase{
			ID:      "CASE-PERIMETER-LISTENER",
			Product: domain.ProductSnapshot{Repository: dir},
		}
		c.EvidenceGraph.AddExposure(domain.ExposureFact{
			Direction: "inbound", Kind: "listener",
			Address: "127.0.0.1:8080", Scope: domain.ScopeLoopback,
		})
		(CollectEvidence{}).runExposure(context.Background(), c)
		if c.PerimeterAssessment == nil || !c.PerimeterAssessment.Basis.Valid() {
			t.Fatalf("exposure assessment missing: %+v", c.PerimeterAssessment)
		}
		if c.PerimeterAssessment.Basis.AdmitsTrust() {
			t.Fatalf("listener locality admitted trust: %+v", c.PerimeterAssessment)
		}
		if c.PerimeterAssessment.AllowsTrustedPeerSelection() {
			t.Fatalf("listener locality selected a trusted peer profile: %+v", c.PerimeterAssessment)
		}
	})
}

// TestAssessmentOutcomePolicy (states level): producers record structured
// causes, failures reach reports, and unresolved analysis never terminates as
// INCONCLUSIVE. Claim truth values stay UNKNOWN when the measurement that
// would have resolved them did not complete.
func TestAssessmentOutcomePolicy(t *testing.T) {
	t.Run("missing root cause fails with a report", func(t *testing.T) {
		caseDir := t.TempDir()
		reportDir := filepath.Join(caseDir, "report")
		c := outcomeCase("CASE-OUTCOME-RC", domain.StateResolveRootCause)
		if err := runOutcomeEngine(t, c, caseDir,
			ResolveRootCause{},
			EvaluateVerdict{Evaluator: evaluator.VerdictEvaluator{}},
			BuildReport{Dir: reportDir},
		); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if c.Workflow.State != domain.StateFailed {
			t.Fatalf("state=%s, want FAILED (reason: %s)", c.Workflow.State, c.Workflow.Reason)
		}
		requireFailedAnalysis(t, c, domain.GapRootCauseUnresolved)
		requireReport(t, reportDir)
	})

	t.Run("invalid exploit model fails with a report", func(t *testing.T) {
		caseDir := t.TempDir()
		reportDir := filepath.Join(caseDir, "report")
		c := outcomeCase("CASE-OUTCOME-MODEL", domain.StateBuildExploitModel)
		if err := runOutcomeEngine(t, c, caseDir,
			BuildExploitModel{ModelPath: filepath.Join(caseDir, "missing-model.json")},
			EvaluateVerdict{Evaluator: evaluator.VerdictEvaluator{}},
			BuildReport{Dir: reportDir},
		); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if c.Workflow.State != domain.StateFailed {
			t.Fatalf("state=%s, want FAILED", c.Workflow.State)
		}
		requireFailedAnalysis(t, c, domain.GapInputResolutionFailed)
		requireReport(t, reportDir)
	})

	t.Run("exhausted budget fails with a report", func(t *testing.T) {
		caseDir := t.TempDir()
		reportDir := filepath.Join(caseDir, "report")
		c := outcomeCase("CASE-OUTCOME-BUDGET", domain.StateCreated)
		c.Workflow.Limits.MaxIterations = 1
		if err := runOutcomeEngine(t, c, caseDir,
			Created{},
			EvaluateVerdict{Evaluator: evaluator.VerdictEvaluator{}},
			BuildReport{Dir: reportDir},
		); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if c.Workflow.State != domain.StateFailed {
			t.Fatalf("state=%s, want FAILED", c.Workflow.State)
		}
		requireFailedAnalysis(t, c, domain.GapAnalysisBudgetExhausted)
		requireReport(t, reportDir)
	})

	t.Run("timeout fails with a report", func(t *testing.T) {
		caseDir := t.TempDir()
		reportDir := filepath.Join(caseDir, "report")
		c := outcomeCase("CASE-OUTCOME-TIMEOUT", domain.StateCreated)
		if err := runOutcomeEngine(t, c, caseDir,
			deadlineState{state: domain.StateCreated},
			BuildReport{Dir: reportDir},
		); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if c.Workflow.State != domain.StateFailed {
			t.Fatalf("state=%s, want FAILED", c.Workflow.State)
		}
		requireFailedAnalysis(t, c, domain.GapAnalysisTimeout)
		requireReport(t, reportDir)
	})

	t.Run("pending mandatory criticism fails", func(t *testing.T) {
		c := &domain.AnalysisCase{
			ID:            "CASE-OUTCOME-REVIEW",
			Vulnerability: domain.Vulnerability{ID: "GO-TEST-REVIEW", BaseSeverity: "HIGH"},
			Exploit: &domain.ExploitModel{
				MandatoryConditions:     []domain.Condition{{ID: "C-REACH", Kind: domain.ConditionSymbolReachable, Mandatory: true}},
				PendingConditionReviews: []domain.ConditionID{"C-REACH"},
			},
			Claims: []domain.Claim{{ConditionID: "C-REACH", Result: domain.ClaimTrue}},
		}
		if _, err := (EvaluateVerdict{Evaluator: evaluator.VerdictEvaluator{}}).Run(context.Background(), c); err != nil {
			t.Fatalf("EvaluateVerdict: %v", err)
		}
		requireFailedAnalysis(t, c, domain.GapReviewUnresolved)
	})

	t.Run("failed negative verification fails", func(t *testing.T) {
		c := &domain.AnalysisCase{
			ID:            "CASE-OUTCOME-NEGATIVE",
			Vulnerability: domain.Vulnerability{ID: "GO-TEST-NEGATIVE", BaseSeverity: "HIGH"},
			Exploit: &domain.ExploitModel{
				MandatoryConditions: []domain.Condition{{ID: "C-REACH", Kind: domain.ConditionSymbolReachable, Mandatory: true}},
			},
			Claims: []domain.Claim{{
				ConditionID: "C-REACH", Result: domain.ClaimFalse,
				Falsifier: "guards",
			}},
		}
		if _, err := (NegativeCheck{}).Run(context.Background(), c); err != nil {
			t.Fatalf("NegativeCheck: %v", err)
		}
		if c.Claims[0].NegativeVerification == nil ||
			c.Claims[0].NegativeVerification.Status != domain.NegativeInsufficientScope {
			t.Fatalf("verification not refused: %+v", c.Claims[0].NegativeVerification)
		}
		if _, err := (EvaluateVerdict{Evaluator: evaluator.VerdictEvaluator{}}).Run(context.Background(), c); err != nil {
			t.Fatalf("EvaluateVerdict: %v", err)
		}
		requireFailedAnalysis(t, c, domain.GapNegativeVerificationIncomplete)
	})

	t.Run("skipped measurement fails and leaves the claim UNKNOWN", func(t *testing.T) {
		c := &domain.AnalysisCase{
			ID:            "CASE-OUTCOME-SKIPPED",
			Vulnerability: domain.Vulnerability{ID: "GO-TEST-SKIPPED", BaseSeverity: "HIGH"},
			Exploit: &domain.ExploitModel{
				MandatoryConditions: []domain.Condition{{ID: "C-REACH", Kind: domain.ConditionSymbolReachable, Mandatory: true}},
			},
			Claims: []domain.Claim{{ConditionID: "C-REACH", Result: domain.ClaimUnknown}},
		}
		(CollectEvidence{}).runGovulncheck(context.Background(), c)
		if _, err := (EvaluateVerdict{Evaluator: evaluator.VerdictEvaluator{}}).Run(context.Background(), c); err != nil {
			t.Fatalf("EvaluateVerdict: %v", err)
		}
		requireFailedAnalysis(t, c, domain.GapMeasurementNotCompleted)
		if c.Claims[0].Result != domain.ClaimUnknown {
			t.Fatalf("skipped measurement changed the claim: %+v", c.Claims[0])
		}
	})

	t.Run("missing proof artifact fails", func(t *testing.T) {
		c := &domain.AnalysisCase{
			ID:            "CASE-OUTCOME-SIDECAR",
			Vulnerability: domain.Vulnerability{ID: "GO-TEST-SIDECAR", Module: "example.com/dep", BaseSeverity: "HIGH"},
			RootCause:     &domain.RootCauseModel{Status: domain.RootCauseNotFound},
		}
		(rootcause.Verifier{}).Verify(context.Background(), c, c.RootCause, c.Vulnerability)
		if len(c.RootCause.AnalysisGaps) == 0 {
			t.Fatalf("root-cause verifier recorded no gap: %+v", c.RootCause)
		}
		if _, err := (EvaluateVerdict{Evaluator: evaluator.VerdictEvaluator{}}).Run(context.Background(), c); err != nil {
			t.Fatalf("EvaluateVerdict: %v", err)
		}
		requireFailedAnalysis(t, c, domain.GapProofArtifactMissing)
	})
}

package states

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/evaluator"
)

func TestEvaluateVerdict_DualTrack_ClusterPerimeter(t *testing.T) {
	c := &domain.AnalysisCase{
		ID: "CASE-DUAL-TRACK-1",
		Vulnerability: domain.Vulnerability{
			ID:           "CVE-2026-TEST1",
			BaseSeverity: "HIGH",
			BaseScore:    8.5,
		},
		Exploit: &domain.ExploitModel{
			MandatoryConditions: []domain.Condition{
				{
					ID:        "C-PEER-INPUT",
					Kind:      domain.ConditionAttackerControl,
					Mandatory: true,
					Params: map[string]string{
						domain.ParamInputSource: domain.InputPeer,
					},
					Description: "peer controlled input",
				},
			},
		},
		Claims: []domain.Claim{
			{
				ID:          "CL-01",
				ConditionID: "C-PEER-INPUT",
				Result:      domain.ClaimUnknown,
				Producer:    "test",
			},
		},
		DetectedPerimeter: domain.PerimeterClusterInternal,
	}

	h := EvaluateVerdict{Evaluator: evaluator.VerdictEvaluator{}}
	_, err := h.Run(context.Background(), c)
	if err != nil {
		t.Fatalf("EvaluateVerdict.Run returned error: %v", err)
	}

	if len(c.Profiles) != 2 {
		t.Fatalf("expected 2 profiles, got %d", len(c.Profiles))
	}
	if c.Profiles[0].Profile != domain.ProfileZeroTrust {
		t.Errorf("profile[0] = %s, want %s", c.Profiles[0].Profile, domain.ProfileZeroTrust)
	}
	if c.Profiles[0].IsTargetActual {
		t.Errorf("profile[0].IsTargetActual = true, want false")
	}
	if c.Profiles[1].Profile != domain.ProfileClusterPerimeter {
		t.Errorf("profile[1] = %s, want %s", c.Profiles[1].Profile, domain.ProfileClusterPerimeter)
	}
	if !c.Profiles[1].IsTargetActual {
		t.Errorf("profile[1].IsTargetActual = false, want true")
	}
	if c.Profiles[1].Falsifier != domain.FalsifierTrustedInfrastructure {
		t.Errorf("profile[1].Falsifier = %s, want %s", c.Profiles[1].Falsifier, domain.FalsifierTrustedInfrastructure)
	}
	if c.Verdict == nil || c.Verdict.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("c.Verdict = %v, want %s", c.Verdict, domain.VerdictNoExploitPathFound)
	}
	if c.ContextualRisk == nil || c.ContextualRisk.Priority != domain.PriorityDismissed {
		t.Fatalf("c.ContextualRisk.Priority = %v, want %s", c.ContextualRisk, domain.PriorityDismissed)
	}
}

func TestEvaluateVerdict_DualTrack_ZeroTrustDefault(t *testing.T) {
	c := &domain.AnalysisCase{
		ID: "CASE-DUAL-TRACK-2",
		Vulnerability: domain.Vulnerability{
			ID:           "CVE-2026-TEST2",
			BaseSeverity: "HIGH",
			BaseScore:    8.5,
		},
		Exploit: &domain.ExploitModel{
			MandatoryConditions: []domain.Condition{
				{
					ID:        "C-PEER-INPUT",
					Kind:      domain.ConditionAttackerControl,
					Mandatory: true,
					Params: map[string]string{
						domain.ParamInputSource: domain.InputPeer,
					},
					Description: "peer controlled input",
				},
			},
		},
		Claims: []domain.Claim{
			{
				ID:          "CL-01",
				ConditionID: "C-PEER-INPUT",
				Result:      domain.ClaimUnknown,
				Producer:    "test",
			},
		},
		DetectedPerimeter: domain.PerimeterUnknown,
	}

	h := EvaluateVerdict{Evaluator: evaluator.VerdictEvaluator{}}
	_, err := h.Run(context.Background(), c)
	if err != nil {
		t.Fatalf("EvaluateVerdict.Run returned error: %v", err)
	}

	if len(c.Profiles) != 2 {
		t.Fatalf("expected 2 profiles, got %d", len(c.Profiles))
	}
	if !c.Profiles[0].IsTargetActual {
		t.Errorf("profile[0].IsTargetActual = false, want true")
	}
	if c.Profiles[1].IsTargetActual {
		t.Errorf("profile[1].IsTargetActual = true, want false")
	}
	if c.Verdict == nil || c.Verdict.Verdict != domain.VerdictInconclusive {
		t.Fatalf("c.Verdict = %v, want %s", c.Verdict, domain.VerdictInconclusive)
	}
	if c.ContextualRisk == nil || c.ContextualRisk.Priority == domain.PriorityDismissed {
		t.Fatalf("c.ContextualRisk.Priority = %v, want != %s", c.ContextualRisk, domain.PriorityDismissed)
	}
}

func TestRunExposure_DeployScanAndPerimeterClassification(t *testing.T) {
	dir := t.TempDir()
	k8sDir := filepath.Join(dir, "deploy")
	if err := os.MkdirAll(k8sDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"),
		[]byte("module example.com/internal-service\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	svcYaml := `apiVersion: v1
kind: Service
metadata:
  name: internal-service
spec:
  type: ClusterIP
  ports:
  - port: 8080
`
	if err := os.WriteFile(filepath.Join(k8sDir, "svc.yaml"), []byte(svcYaml), 0o644); err != nil {
		t.Fatal(err)
	}

	c := &domain.AnalysisCase{
		ID: "CASE-PERIMETER-SCAN",
		Product: domain.ProductSnapshot{
			Repository: dir,
		},
	}

	h := CollectEvidence{}
	h.runExposure(context.Background(), c)

	if c.DetectedPerimeter != domain.PerimeterClusterInternal {
		t.Errorf("DetectedPerimeter = %q, want %q", c.DetectedPerimeter, domain.PerimeterClusterInternal)
	}
	if c.PerimeterRationale == "" {
		t.Errorf("PerimeterRationale is empty")
	}
}

func TestRunExposure_PerimeterOverride(t *testing.T) {
	dir := t.TempDir()
	c := &domain.AnalysisCase{
		ID: "CASE-PERIMETER-OVERRIDE",
		Product: domain.ProductSnapshot{
			Repository:        dir,
			PerimeterOverride: domain.PerimeterPublic,
		},
	}

	h := CollectEvidence{}
	h.runExposure(context.Background(), c)

	if c.DetectedPerimeter != domain.PerimeterPublic {
		t.Errorf("DetectedPerimeter = %q, want %q", c.DetectedPerimeter, domain.PerimeterPublic)
	}
	wantRationale := "perimeter overridden by configuration: " + domain.PerimeterPublic
	if c.PerimeterRationale != wantRationale {
		t.Errorf("PerimeterRationale = %q, want %q", c.PerimeterRationale, wantRationale)
	}
}

func TestEvaluateVerdict_OperatorAssertedIncompleteModelDemotes(t *testing.T) {
	// --trusted-peer rewrites the peer-input claim, but the exploit model
	// leaves an advisory-declared sink unresolved: the operator's
	// assertion cannot discharge an exploit shape we never modeled.
	c := &domain.AnalysisCase{
		ID: "CASE-GATE-1",
		Vulnerability: domain.Vulnerability{
			ID:           "CVE-2026-GATE1",
			BaseSeverity: "HIGH",
		},
		Product: domain.ProductSnapshot{
			TrustedPeer: true,
		},
		Exploit: &domain.ExploitModel{
			MandatoryConditions: []domain.Condition{
				{
					ID:        "C-PEER-INPUT",
					Kind:      domain.ConditionAttackerControl,
					Mandatory: true,
					Params: map[string]string{
						domain.ParamInputSource: domain.InputPeer,
					},
				},
			},
			UnresolvedSubjects: []domain.SymbolRef{
				{Package: "dep/pkg", Symbol: "Parse"},
			},
		},
		Claims: []domain.Claim{
			{
				ID:          "CL-01",
				ConditionID: "C-PEER-INPUT",
				Result:      domain.ClaimUnknown,
				Producer:    "test",
			},
		},
		DetectedPerimeter: domain.PerimeterUnknown,
	}

	h := EvaluateVerdict{Evaluator: evaluator.VerdictEvaluator{}}
	if _, err := h.Run(context.Background(), c); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if c.Verdict.Verdict != domain.VerdictInconclusive {
		t.Fatalf("verdict = %s, want %s", c.Verdict.Verdict, domain.VerdictInconclusive)
	}
}

func TestEvaluateVerdict_OperatorAssertedAbsentSubjectsNotDemoted(t *testing.T) {
	// Every unresolved subject is proven absent from the build graph:
	// absent defect code has no unexplored exploit shape, so the
	// declared-trust demotion must not fire — the perimeter-rewritten
	// FALSE still grounds NEPF.
	subj := domain.SymbolRef{Package: "dep/xds", Symbol: "RouteAndProcess"}
	c := &domain.AnalysisCase{
		ID: "CASE-GATE-1B",
		Vulnerability: domain.Vulnerability{
			ID:           "CVE-2026-GATE1B",
			BaseSeverity: "HIGH",
		},
		Product: domain.ProductSnapshot{
			TrustedPeer: true,
		},
		Exploit: &domain.ExploitModel{
			MandatoryConditions: []domain.Condition{
				{
					ID:        "C-PEER-INPUT",
					Kind:      domain.ConditionAttackerControl,
					Mandatory: true,
					Params: map[string]string{
						domain.ParamInputSource: domain.InputPeer,
					},
				},
			},
			UnresolvedSubjects: []domain.SymbolRef{subj},
			AbsentSubjects:     []domain.SymbolRef{subj},
		},
		Claims: []domain.Claim{
			{
				ID:          "CL-01",
				ConditionID: "C-PEER-INPUT",
				Result:      domain.ClaimUnknown,
				Producer:    "test",
			},
		},
		DetectedPerimeter: domain.PerimeterUnknown,
	}

	h := EvaluateVerdict{Evaluator: evaluator.VerdictEvaluator{}}
	if _, err := h.Run(context.Background(), c); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if c.Verdict.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("verdict = %s, want %s", c.Verdict.Verdict, domain.VerdictNoExploitPathFound)
	}
}

func TestEvaluateVerdict_OperatorAssertedMixedUnresolvedDemotes(t *testing.T) {
	// One absent subject + one genuinely unmodeled subject: the demotion
	// must still fire on the unmodeled remainder.
	absentSubj := domain.SymbolRef{Package: "dep/xds", Symbol: "RouteAndProcess"}
	c := &domain.AnalysisCase{
		ID: "CASE-GATE-1C",
		Vulnerability: domain.Vulnerability{
			ID:           "CVE-2026-GATE1C",
			BaseSeverity: "HIGH",
		},
		Product: domain.ProductSnapshot{
			TrustedPeer: true,
		},
		Exploit: &domain.ExploitModel{
			MandatoryConditions: []domain.Condition{
				{
					ID:        "C-PEER-INPUT",
					Kind:      domain.ConditionAttackerControl,
					Mandatory: true,
					Params: map[string]string{
						domain.ParamInputSource: domain.InputPeer,
					},
				},
			},
			UnresolvedSubjects: []domain.SymbolRef{absentSubj, {Package: "dep/pkg", Symbol: "Parse"}},
			AbsentSubjects:     []domain.SymbolRef{absentSubj},
		},
		Claims: []domain.Claim{
			{
				ID:          "CL-01",
				ConditionID: "C-PEER-INPUT",
				Result:      domain.ClaimUnknown,
				Producer:    "test",
			},
		},
		DetectedPerimeter: domain.PerimeterUnknown,
	}

	h := EvaluateVerdict{Evaluator: evaluator.VerdictEvaluator{}}
	if _, err := h.Run(context.Background(), c); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if c.Verdict.Verdict != domain.VerdictInconclusive {
		t.Fatalf("verdict = %s, want %s", c.Verdict.Verdict, domain.VerdictInconclusive)
	}
}

func TestEvaluateVerdict_OperatorAssertedCompleteModelStaysNEPF(t *testing.T) {
	c := &domain.AnalysisCase{
		ID: "CASE-GATE-2",
		Vulnerability: domain.Vulnerability{
			ID:           "CVE-2026-GATE2",
			BaseSeverity: "HIGH",
		},
		Product: domain.ProductSnapshot{
			TrustedPeer: true,
		},
		Exploit: &domain.ExploitModel{
			MandatoryConditions: []domain.Condition{
				{
					ID:        "C-PEER-INPUT",
					Kind:      domain.ConditionAttackerControl,
					Mandatory: true,
					Params: map[string]string{
						domain.ParamInputSource: domain.InputPeer,
					},
				},
			},
		},
		Claims: []domain.Claim{
			{
				ID:          "CL-01",
				ConditionID: "C-PEER-INPUT",
				Result:      domain.ClaimUnknown,
				Producer:    "test",
			},
		},
		DetectedPerimeter: domain.PerimeterUnknown,
	}

	h := EvaluateVerdict{Evaluator: evaluator.VerdictEvaluator{}}
	if _, err := h.Run(context.Background(), c); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if c.Verdict.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("verdict = %s, want %s", c.Verdict.Verdict, domain.VerdictNoExploitPathFound)
	}
	if c.Verdict.GroundBasis != domain.BasisDeclaredTrust {
		t.Errorf("GroundBasis = %q, want %q", c.Verdict.GroundBasis, domain.BasisDeclaredTrust)
	}
}

func TestEvaluateVerdict_AutoDetectedPerimeterGroundBasis(t *testing.T) {
	c := &domain.AnalysisCase{
		ID: "CASE-GATE-3",
		Vulnerability: domain.Vulnerability{
			ID:           "CVE-2026-GATE3",
			BaseSeverity: "HIGH",
		},
		Exploit: &domain.ExploitModel{
			MandatoryConditions: []domain.Condition{
				{
					ID:        "C-PEER-INPUT",
					Kind:      domain.ConditionAttackerControl,
					Mandatory: true,
					Params: map[string]string{
						domain.ParamInputSource: domain.InputPeer,
					},
				},
			},
		},
		Claims: []domain.Claim{
			{
				ID:          "CL-01",
				ConditionID: "C-PEER-INPUT",
				Result:      domain.ClaimUnknown,
				Producer:    "test",
			},
		},
		DetectedPerimeter: domain.PerimeterClusterInternal,
	}

	h := EvaluateVerdict{Evaluator: evaluator.VerdictEvaluator{}}
	if _, err := h.Run(context.Background(), c); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if c.Verdict.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("verdict = %s, want %s", c.Verdict.Verdict, domain.VerdictNoExploitPathFound)
	}
	if c.Verdict.GroundBasis != domain.BasisAutoPerimeter {
		t.Errorf("GroundBasis = %q, want %q", c.Verdict.GroundBasis, domain.BasisAutoPerimeter)
	}
}

func TestEvaluateVerdict_ConfigOriginDoesNotCoverUnresolved(t *testing.T) {
	// A config-origin trusted-infrastructure falsifier is proven against
	// the *resolved* sinks' traced inputs; it constrains nothing about an
	// unmodeled sink's inputs. On an incomplete model it must not ground
	// NEPF — unlike a declared/auto perimeter basis, which asserts the
	// trust boundary sink-agnostically.
	c := &domain.AnalysisCase{
		ID: "CASE-GATE-4",
		Vulnerability: domain.Vulnerability{
			ID:           "CVE-2026-GATE4",
			BaseSeverity: "HIGH",
		},
		Exploit: &domain.ExploitModel{
			MandatoryConditions: []domain.Condition{
				{
					ID:        "C-INPUT",
					Kind:      domain.ConditionAttackerControl,
					Mandatory: true,
					Params: map[string]string{
						domain.ParamInputSource: domain.InputPeer,
					},
				},
			},
			UnresolvedSubjects: []domain.SymbolRef{
				{Package: "dep/pkg", Symbol: "Parse"},
			},
		},
		Claims: []domain.Claim{
			{
				ID:             "CL-01",
				ConditionID:    "C-INPUT",
				Result:         domain.ClaimFalse,
				Falsifier:      domain.FalsifierTrustedInfrastructure,
				FalsifierBasis: domain.BasisConfigOrigin,
				NegativeVerification: &domain.NegativeVerification{
					Status: domain.NegativeVerified,
				},
				Producer: "test",
			},
		},
		DetectedPerimeter: domain.PerimeterUnknown,
	}

	h := EvaluateVerdict{Evaluator: evaluator.VerdictEvaluator{}}
	if _, err := h.Run(context.Background(), c); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if c.Verdict.Verdict != domain.VerdictInconclusive {
		t.Fatalf("verdict = %s, want %s", c.Verdict.Verdict, domain.VerdictInconclusive)
	}
}

func TestEvaluateVerdict_ConfigOriginCompleteModelStaysNEPF(t *testing.T) {
	c := &domain.AnalysisCase{
		ID: "CASE-GATE-5",
		Vulnerability: domain.Vulnerability{
			ID:           "CVE-2026-GATE5",
			BaseSeverity: "HIGH",
		},
		Exploit: &domain.ExploitModel{
			MandatoryConditions: []domain.Condition{
				{
					ID:        "C-INPUT",
					Kind:      domain.ConditionAttackerControl,
					Mandatory: true,
					Params: map[string]string{
						domain.ParamInputSource: domain.InputPeer,
					},
				},
			},
		},
		Claims: []domain.Claim{
			{
				ID:             "CL-01",
				ConditionID:    "C-INPUT",
				Result:         domain.ClaimFalse,
				Falsifier:      domain.FalsifierTrustedInfrastructure,
				FalsifierBasis: domain.BasisConfigOrigin,
				NegativeVerification: &domain.NegativeVerification{
					Status: domain.NegativeVerified,
				},
				Producer: "test",
			},
		},
		DetectedPerimeter: domain.PerimeterUnknown,
	}

	h := EvaluateVerdict{Evaluator: evaluator.VerdictEvaluator{}}
	if _, err := h.Run(context.Background(), c); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if c.Verdict.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("verdict = %s, want %s", c.Verdict.Verdict, domain.VerdictNoExploitPathFound)
	}
	if c.Verdict.GroundBasis != domain.BasisConfigOrigin {
		t.Errorf("GroundBasis = %q, want %q", c.Verdict.GroundBasis, domain.BasisConfigOrigin)
	}
}

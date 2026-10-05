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

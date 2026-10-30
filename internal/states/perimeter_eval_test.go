package states

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davniy/izyan/internal/domain"
	"github.com/davniy/izyan/internal/evaluator"
)

// exactScope is the only scope authority that allows a negative closure: an
// exact GO- identity whose single original affected[] entry is a Go module the
// loaded record fully represented. COMPLETE coverage alone is not closure
// authority (see TestEvaluateVerdictPartialScopeBothProfiles).
func exactScope(id string) *domain.AdvisoryScope {
	return &domain.AdvisoryScope{
		RequestedID: id, ResolvedID: id,
		Kind: domain.ScopeAdvisoryEntries, Coverage: domain.CoverageComplete,
		RecordExtent: domain.RecordExtentFullRecord,
		RecordInventory: &domain.RecordInventory{
			AdvisoryID:         id,
			DocumentDigest:     "sha256:" + strings.Repeat("ab", 32),
			AffectedEntryCount: 1,
			Entries:            []domain.RecordEntry{{Index: 0, Ecosystem: "Go", Module: "golang.org/x/net"}},
			RepresentedRefs:    []int{0},
		},
	}
}

// projectedScope is an exact identity whose loaded document represented only
// its Go entry: the omitted Maven entry keeps the requested scope uncovered
// even though the scope claims COMPLETE coverage of an exact record.
func projectedScope() *domain.AdvisoryScope {
	return &domain.AdvisoryScope{
		RequestedID: "GO-2026-GATE1", ResolvedID: "GO-2026-GATE1",
		Kind: domain.ScopeAdvisoryEntries, Coverage: domain.CoverageComplete,
		RecordExtent: domain.RecordExtentGoProjection,
		RecordInventory: &domain.RecordInventory{
			AdvisoryID: "GO-2026-GATE1", DocumentDigest: "sha256:" + strings.Repeat("cd", 32),
			AffectedEntryCount: 2,
			Entries: []domain.RecordEntry{
				{Index: 0, Ecosystem: "Go", Module: "golang.org/x/net"},
				{Index: 1, Ecosystem: "Maven", Module: "io.grpc:grpc-netty"},
			},
			RepresentedRefs: []int{0},
			OmittedRefs:     []int{1},
		},
	}
}

func TestEvaluateVerdict_DualTrack_ClusterPerimeter(t *testing.T) {
	c := &domain.AnalysisCase{
		ID:       "CASE-DUAL-TRACK-1",
		Affected: &domain.AffectedResult{Scope: exactScope("GO-2026-TEST1")},
		Vulnerability: domain.Vulnerability{
			ID:           "GO-2026-TEST1",
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
		PerimeterAssessment: &domain.PerimeterAssessment{
			Perimeter: domain.PerimeterClusterInternal,
			Basis:     domain.PerimeterBasisOperatorDeclared,
		},
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
	if c.Verdict != nil {
		t.Fatalf("c.Verdict = %+v, want no verdict: the unresolved analysis must FAIL", c.Verdict)
	}
	if len(c.ProfileAssessments) != 2 {
		t.Fatalf("profile assessments=%d, want 2", len(c.ProfileAssessments))
	}
	for i, pa := range c.ProfileAssessments {
		if pa.Result.Outcome != domain.OutcomeFailed {
			t.Fatalf("profile[%d] outcome=%s, want FAILED", i, pa.Result.Outcome)
		}
	}
	if c.ContextualRisk == nil || c.ContextualRisk.Priority == domain.PriorityDismissed {
		t.Fatalf("c.ContextualRisk.Priority = %v, want != %s", c.ContextualRisk, domain.PriorityDismissed)
	}
	if c.ContextualRisk.Status != domain.RiskStatusUnassessed {
		t.Fatalf("failed assessment risk status=%s, want UNASSESSED", c.ContextualRisk.Status)
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
		ID:       "CASE-GATE-1",
		Affected: &domain.AffectedResult{Scope: exactScope("GO-2026-GATE1")},
		Vulnerability: domain.Vulnerability{
			ID:           "GO-2026-GATE1",
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
	requireFailedAnalysis(t, c, domain.GapReachabilityProofIncomplete)
}

func TestEvaluateVerdict_OperatorAssertedAbsentSubjectsNotDemoted(t *testing.T) {
	// Every unresolved subject is proven absent from the build graph:
	// absent defect code has no unexplored exploit shape, so the
	// declared-trust demotion must not fire — the perimeter-rewritten
	// FALSE still grounds NEPF.
	subj := domain.SymbolRef{Package: "dep/xds", Symbol: "RouteAndProcess"}
	c := &domain.AnalysisCase{
		ID:       "CASE-GATE-1B",
		Affected: &domain.AffectedResult{Scope: exactScope("GO-2026-GATE1B")},
		Vulnerability: domain.Vulnerability{
			ID:           "GO-2026-GATE1B",
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
		ID:       "CASE-GATE-1C",
		Affected: &domain.AffectedResult{Scope: exactScope("GO-2026-GATE1C")},
		Vulnerability: domain.Vulnerability{
			ID:           "GO-2026-GATE1C",
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
	requireFailedAnalysis(t, c, domain.GapReachabilityProofIncomplete)
}

func TestEvaluateVerdict_OperatorAssertedCompleteModelStaysNEPF(t *testing.T) {
	c := &domain.AnalysisCase{
		ID:       "CASE-GATE-2",
		Affected: &domain.AffectedResult{Scope: exactScope("GO-2026-GATE2")},
		Vulnerability: domain.Vulnerability{
			ID:           "GO-2026-GATE2",
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

func TestEvaluateVerdict_AutoDetectedPerimeterDoesNotGroundTrust(t *testing.T) {
	// A recorded cluster-internal perimeter is exposure shape, not a trust
	// policy: it must not select the trusted-peer actual profile, must not
	// rewrite the peer-input claim to FALSE, and must not stamp an
	// auto-perimeter trust basis.
	c := &domain.AnalysisCase{
		ID:       "CASE-GATE-3",
		Affected: &domain.AffectedResult{Scope: exactScope("GO-2026-GATE3")},
		Vulnerability: domain.Vulnerability{
			ID:           "GO-2026-GATE3",
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
	requireFailedAnalysis(t, c, domain.GapInputTraceIncomplete)
	if !c.Profiles[0].IsTargetActual || c.Profiles[1].IsTargetActual {
		t.Fatalf("trusted-peer profile selected from locality: profiles=%+v", c.Profiles)
	}
	for _, prof := range c.Profiles {
		if prof.Verdict != "" {
			t.Fatalf("failed profile %s retained a verdict %s", prof.Profile, prof.Verdict)
		}
	}
	for _, cl := range c.Claims {
		if cl.FalsifierBasis == domain.BasisAutoPerimeter {
			t.Fatalf("claim %s was stamped with auto-perimeter trust from exposure shape", cl.ConditionID)
		}
	}
}

func TestEvaluateVerdict_ConfigOriginDoesNotCoverUnresolved(t *testing.T) {
	// A config-origin trusted-infrastructure falsifier is proven against
	// the *resolved* sinks' traced inputs; it constrains nothing about an
	// unmodeled sink's inputs. On an incomplete model it must not ground
	// NEPF — unlike a declared/auto perimeter basis, which asserts the
	// trust boundary sink-agnostically.
	c := &domain.AnalysisCase{
		ID:       "CASE-GATE-4",
		Affected: &domain.AffectedResult{Scope: exactScope("GO-2026-GATE4")},
		Vulnerability: domain.Vulnerability{
			ID:           "GO-2026-GATE4",
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
	requireFailedAnalysis(t, c, domain.GapReachabilityProofIncomplete)
}

func TestEvaluateVerdict_ConfigOriginCompleteModelStaysNEPF(t *testing.T) {
	build := domain.EffectiveBuildContext(declaredProduct())
	c := &domain.AnalysisCase{
		ID:       "CASE-GATE-5",
		Product:  declaredProduct(),
		Affected: &domain.AffectedResult{Scope: exactScope("GO-2026-GATE5")},
		Vulnerability: domain.Vulnerability{
			ID:           "GO-2026-GATE5",
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
					Status:       domain.NegativeVerified,
					BuildContext: &build,
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

func TestEvaluateVerdict_OutboundConfigOriginBasis(t *testing.T) {
	c := &domain.AnalysisCase{
		ID:       "CASE-DUAL-TRACK-CONFIG-ORIGIN",
		Product:  declaredProduct(),
		Affected: &domain.AffectedResult{Scope: exactScope("GO-2026-TEST3")},
		Vulnerability: domain.Vulnerability{
			ID:           "GO-2026-TEST3",
			Module:       "example.com/netmod",
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
	c.EvidenceGraph.AddExposure(domain.ExposureFact{
		Direction: "outbound",
		Kind:      "dial",
		Target:    "example.com/netmod.Dial",
		Scope:     domain.ScopeConfigured,
	})
	c.Product.TrustedPeer = true

	h := EvaluateVerdict{Evaluator: evaluator.VerdictEvaluator{}}
	_, err := h.Run(context.Background(), c)
	if err != nil {
		t.Fatalf("EvaluateVerdict.Run returned error: %v", err)
	}

	if c.Verdict == nil || c.Verdict.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("c.Verdict = %v, want %s", c.Verdict, domain.VerdictNoExploitPathFound)
	}
	if c.Verdict.GroundBasis != domain.BasisConfigOrigin {
		t.Errorf("c.Verdict.GroundBasis = %q, want %q", c.Verdict.GroundBasis, domain.BasisConfigOrigin)
	}
}

func TestEvaluateVerdict_OutboundMixedScopeStaysDeclaredTrust(t *testing.T) {
	c := &domain.AnalysisCase{
		ID:       "CASE-DUAL-TRACK-MIXED-SCOPE",
		Affected: &domain.AffectedResult{Scope: exactScope("GO-2026-TEST4")},
		Product:  domain.ProductSnapshot{TrustedPeer: true},
		Vulnerability: domain.Vulnerability{
			ID:           "GO-2026-TEST4",
			Module:       "example.com/netmod",
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
	c.EvidenceGraph.AddExposure(domain.ExposureFact{
		Direction: "outbound",
		Kind:      "dial",
		Target:    "example.com/netmod.Dial",
		Scope:     domain.ScopeConfigured,
	})
	c.EvidenceGraph.AddExposure(domain.ExposureFact{
		Direction: "outbound",
		Kind:      "dial",
		Target:    "example.com/netmod.Connect",
		Scope:     domain.ScopeUnknown,
	})

	h := EvaluateVerdict{Evaluator: evaluator.VerdictEvaluator{}}
	_, err := h.Run(context.Background(), c)
	if err != nil {
		t.Fatalf("EvaluateVerdict.Run returned error: %v", err)
	}

	if c.Verdict == nil || c.Verdict.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("c.Verdict = %v, want %s", c.Verdict, domain.VerdictNoExploitPathFound)
	}
	if c.Verdict.GroundBasis != domain.BasisDeclaredTrust {
		t.Errorf("c.Verdict.GroundBasis = %q, want %q (mixed scopes rest on the declared trust boundary)",
			c.Verdict.GroundBasis, domain.BasisDeclaredTrust)
	}
}

func TestEvaluateVerdictPartialScopeBothProfiles(t *testing.T) {
	scopes := map[string]*domain.AdvisoryScope{
		"cve-known-only":  {RequestedID: "CVE-2023-44487", ResolvedID: "GO-TEST-1", Kind: domain.ScopeCVE, Coverage: domain.CoverageKnownOnly},
		"exact-projected": projectedScope(),
	}
	for scopeName, scope := range scopes {
		for _, trustedPeer := range []bool{false, true} {
			for _, negative := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/trusted-peer=%t/negative=%t", scopeName, trustedPeer, negative), func(t *testing.T) {
					c := &domain.AnalysisCase{
						Product: domain.ProductSnapshot{TrustedPeer: trustedPeer},
						Affected: &domain.AffectedResult{
							Scope:           scope,
							ModulePresent:   domain.ClaimTrue,
							VersionAffected: domain.ClaimTrue,
							PackagePresent:  domain.ClaimTrue,
							BuildRelevant:   domain.ClaimTrue,
							CheckedModules:  []string{"golang.org/x/net"},
						},
						Exploit:           &domain.ExploitModel{MandatoryConditions: []domain.Condition{{ID: "C-PEER", Kind: domain.ConditionAttackerControl, Mandatory: true, Params: map[string]string{domain.ParamInputSource: domain.InputPeer}}}},
						Claims:            []domain.Claim{{ConditionID: "C-PEER", Result: domain.ClaimFalse, Falsifier: domain.FalsifierTrustedInfrastructure, NegativeVerification: &domain.NegativeVerification{Status: domain.NegativeVerified}}},
						DetectedPerimeter: domain.PerimeterClusterInternal,
					}
					if negative {
						c.Affected.VersionAffected = domain.ClaimFalse
					}
					if _, err := (EvaluateVerdict{Evaluator: evaluator.VerdictEvaluator{}}).Run(context.Background(), c); err != nil {
						t.Fatal(err)
					}
					// negative=false: the persisted trusted-infrastructure
					// negative is refused for lack of an identified build, and
					// the peer-input condition stays unresolved — both are
					// proof blockers. negative=true: the component negative
					// also cannot close the requested scope.
					if negative || trustedPeer {
						requireFailedAnalysis(t, c, domain.GapUnsupportedNegativeScope)
					} else {
						requireFailedAnalysis(t, c, domain.GapNegativeVerificationIncomplete)
					}
					if len(c.Profiles) != 2 ||
						c.Profiles[0].Profile != domain.ProfileZeroTrust || c.Profiles[1].Profile != domain.ProfileClusterPerimeter {
						t.Fatalf("scope=%s trusted-peer=%t negative=%t verdict=%+v profiles=%+v", scopeName, trustedPeer, negative, c.Verdict, c.Profiles)
					}
					if c.Profiles[0].IsTargetActual == trustedPeer {
						t.Fatalf("zero-trust actual=%t with trusted-peer=%t", c.Profiles[0].IsTargetActual, trustedPeer)
					}
					if c.Profiles[1].IsTargetActual != trustedPeer {
						t.Fatalf("cluster actual=%t with trusted-peer=%t", c.Profiles[1].IsTargetActual, trustedPeer)
					}
					for _, profile := range c.Profiles {
						if profile.Verdict != "" {
							t.Fatalf("scope-refused negative retained a verdict on profile %+v", profile)
						}
					}
					for _, pa := range c.ProfileAssessments {
						if pa.Result.Outcome != domain.OutcomeFailed {
							t.Fatalf("profile %s outcome=%s, want FAILED", pa.Profile, pa.Result.Outcome)
						}
					}
					c.Claims[0].Result = domain.ClaimUnknown
					c.Claims[0].Falsifier = ""
					c.Claims[0].NegativeVerification = nil
					if _, err := (EvaluateVerdict{Evaluator: evaluator.VerdictEvaluator{}}).Run(context.Background(), c); err != nil {
						t.Fatal(err)
					}
					if negative || trustedPeer {
						requireFailedAnalysis(t, c, domain.GapUnsupportedNegativeScope)
					} else {
						requireFailedAnalysis(t, c, domain.GapInputTraceIncomplete)
					}
					for _, profile := range c.Profiles {
						if profile.Verdict != "" {
							t.Fatalf("perimeter rewrite closed the refused scope: %+v", profile)
						}
					}
				})
			}
		}
	}
}

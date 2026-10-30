package risk

import (
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

func TestAssess_NotAffected_Dismissed(t *testing.T) {
	v := domain.Vulnerability{
		ID:           "CVE-2026-1000",
		BaseSeverity: "CRITICAL",
		BaseScore:    10.0,
	}
	c := &domain.AnalysisCase{}
	vr := domain.VerdictResult{
		Verdict: domain.VerdictNotAffected,
		Reason:  "package is not in build graph",
	}

	res := Assess(v, c, vr)
	if res.Priority != domain.PriorityDismissed {
		t.Fatalf("expected PriorityDismissed, got %s", res.Priority)
	}
	if res.ContextualLevel != domain.RiskLevelNone {
		t.Fatalf("expected RiskLevelNone, got %s", res.ContextualLevel)
	}
	if res.ContextualScore != 0.0 {
		t.Fatalf("expected score 0.0, got %v", res.ContextualScore)
	}
	if res.Status != domain.RiskStatusNotApplicable {
		t.Fatalf("expected RiskStatusNotApplicable, got %s", res.Status)
	}
}

func TestAssess_NoExploitPath_Dismissed(t *testing.T) {
	v := domain.Vulnerability{
		ID:           "CVE-2026-1001",
		BaseSeverity: "CRITICAL",
		BaseScore:    10.0,
	}
	c := &domain.AnalysisCase{}
	vr := domain.VerdictResult{
		Verdict: domain.VerdictNoExploitPathFound,
		Reason:  "mandatory condition is proven false",
	}

	res := Assess(v, c, vr)
	if res.Priority != domain.PriorityDismissed {
		t.Fatalf("expected PriorityDismissed, got %s", res.Priority)
	}
	if res.ContextualLevel != domain.RiskLevelNone {
		t.Fatalf("expected RiskLevelNone, got %s", res.ContextualLevel)
	}
	if res.ContextualScore != 0.0 {
		t.Fatalf("expected score 0.0, got %v", res.ContextualScore)
	}
	if res.Status != domain.RiskStatusAssessed {
		t.Fatalf("expected RiskStatusAssessed, got %s", res.Status)
	}
}

func TestAssess_Exploitable_PublicUnauth_BlockerP0(t *testing.T) {
	v := domain.Vulnerability{
		ID:           "CVE-2026-1002",
		BaseSeverity: "CRITICAL",
		BaseScore:    10.0,
	}
	c := &domain.AnalysisCase{
		EvidenceGraph: domain.EvidenceGraph{
			Exposures: []domain.ExposureFact{
				{
					Direction: "inbound",
					Kind:      "listener",
					Target:    "net.Listen",
					Address:   "0.0.0.0:8080",
					Scope:     domain.ScopeAllInterfaces,
				},
			},
		},
	}
	vr := domain.VerdictResult{
		Verdict: domain.VerdictExploitable,
		Reason:  "all mandatory conditions are satisfied",
	}

	res := Assess(v, c, vr)
	if res.Priority != domain.PriorityP0 {
		t.Fatalf("expected PriorityP0, got %s", res.Priority)
	}
	if res.ContextualLevel != domain.RiskLevelCritical {
		t.Fatalf("expected RiskLevelCritical, got %s", res.ContextualLevel)
	}
	if res.ContextualScore != 10.0 {
		t.Fatalf("expected score 10.0, got %v", res.ContextualScore)
	}
	if res.Factors.Exposure != "PUBLIC" {
		t.Fatalf("expected Exposure PUBLIC, got %s", res.Factors.Exposure)
	}
}

func TestAssess_Exploitable_MediumBase_SeverityNotElevated(t *testing.T) {
	v := domain.Vulnerability{
		ID:           "CVE-2022-0603",
		BaseSeverity: "MEDIUM",
		BaseScore:    5.0,
	}
	c := &domain.AnalysisCase{
		EvidenceGraph: domain.EvidenceGraph{
			Exposures: []domain.ExposureFact{
				{
					Direction: "inbound",
					Kind:      "listener",
					Target:    "net/http.ListenAndServe",
					Address:   ":8080",
					Scope:     domain.ScopeAllInterfaces,
				},
			},
		},
	}
	vr := domain.VerdictResult{
		Verdict: domain.VerdictExploitable,
		Reason:  "all mandatory exploit conditions are satisfied",
	}

	res := Assess(v, c, vr)
	// Crucial invariant: priority and severity level must NOT be inflated beyond nominal!
	// A Medium vulnerability unmitigated remains P2, NEVER escalated to P0.
	if res.Priority != domain.PriorityP2 {
		t.Fatalf("expected PriorityP2 (capped at nominal), got %s", res.Priority)
	}
	if res.ContextualLevel != domain.RiskLevelMedium {
		t.Fatalf("expected RiskLevelMedium, got %s (must not be elevated to CRITICAL)", res.ContextualLevel)
	}
	if res.ContextualScore != 5.0 {
		t.Fatalf("expected score 5.0, got %v (must not be elevated to 10.0)", res.ContextualScore)
	}
	if !strings.Contains(res.AdjustmentReason, "Повышение критичности не производится") {
		t.Fatalf("expected non-escalation rationale, got %q", res.AdjustmentReason)
	}
}

func TestAssess_Exploitable_PublicAuth_P1(t *testing.T) {
	v := domain.Vulnerability{
		ID:           "CVE-2026-1003",
		BaseSeverity: "CRITICAL",
		BaseScore:    10.0,
	}
	c := &domain.AnalysisCase{
		EvidenceGraph: domain.EvidenceGraph{
			Exposures: []domain.ExposureFact{
				{
					Direction: "inbound",
					Kind:      "listener",
					Target:    "tls.Listen",
					Address:   "0.0.0.0:443",
					Scope:     domain.ScopeAllInterfaces,
				},
				{
					Direction: "inbound",
					Kind:      "auth-middleware",
					Target:    "jwt.Middleware",
				},
			},
		},
		Claims: []domain.Claim{
			{
				ConditionID: "C-AUTH",
				Result:      domain.ClaimTrue,
			},
		},
	}
	vr := domain.VerdictResult{
		Verdict: domain.VerdictExploitable,
		Reason:  "all mandatory conditions are satisfied",
	}

	res := Assess(v, c, vr)
	if res.Priority != domain.PriorityP1 {
		t.Fatalf("expected PriorityP1, got %s", res.Priority)
	}
	if res.ContextualLevel != domain.RiskLevelHigh {
		t.Fatalf("expected RiskLevelHigh, got %s", res.ContextualLevel)
	}
	if res.ContextualScore != 7.5 {
		t.Fatalf("expected score 7.5, got %v", res.ContextualScore)
	}
	if res.SLA != "High Priority" {
		t.Fatalf("expected High Priority SLA, got %q", res.SLA)
	}
	if res.Factors.Authentication != "REQUIRED" {
		t.Fatalf("expected Authentication REQUIRED, got %s", res.Factors.Authentication)
	}
}

func TestAssess_Exploitable_InternalLoopback_P2(t *testing.T) {
	v := domain.Vulnerability{
		ID:           "CVE-2026-1004",
		BaseSeverity: "CRITICAL",
		BaseScore:    10.0,
	}
	c := &domain.AnalysisCase{
		EvidenceGraph: domain.EvidenceGraph{
			Exposures: []domain.ExposureFact{
				{
					Direction: "inbound",
					Kind:      "listener",
					Target:    "net.Listen",
					Address:   "127.0.0.1:9090",
					Scope:     domain.ScopeLoopback,
				},
			},
		},
	}
	vr := domain.VerdictResult{
		Verdict: domain.VerdictExploitable,
		Reason:  "all mandatory conditions are satisfied",
	}

	res := Assess(v, c, vr)
	if res.Priority != domain.PriorityP2 {
		t.Fatalf("expected PriorityP2, got %s", res.Priority)
	}
	if res.ContextualLevel != domain.RiskLevelMedium {
		t.Fatalf("expected RiskLevelMedium, got %s", res.ContextualLevel)
	}
	if res.ContextualScore != 5.0 {
		t.Fatalf("expected score 5.0, got %v", res.ContextualScore)
	}
	if res.SLA != "Scheduled" {
		t.Fatalf("expected Scheduled SLA, got %q", res.SLA)
	}
	if res.Factors.Exposure != "INTERNAL" {
		t.Fatalf("expected Exposure INTERNAL, got %s", res.Factors.Exposure)
	}
}

// TestRiskUnknownExposure pins the wording correction: an unresolved exposure
// question is UNKNOWN. "No listeners observed" is neither a perimeter nor proof
// of "no external exposure", so the baseline stands and no downgrade applies.
func TestRiskUnknownExposure(t *testing.T) {
	v := domain.Vulnerability{
		ID:           "CVE-2026-1005",
		BaseSeverity: "CRITICAL",
		BaseScore:    10.0,
	}
	c := &domain.AnalysisCase{}
	vr := domain.VerdictResult{
		Verdict: domain.VerdictExploitable,
		Reason:  "all mandatory conditions are satisfied",
	}

	res := Assess(v, c, vr)
	if res.Priority != domain.PriorityP0 {
		t.Fatalf("expected the nominal PriorityP0, got %s", res.Priority)
	}
	if res.ContextualLevel != domain.RiskLevelCritical {
		t.Fatalf("expected the baseline RiskLevelCritical, got %s", res.ContextualLevel)
	}
	if res.ContextualScore != 10.0 {
		t.Fatalf("expected the baseline score 10.0, got %v", res.ContextualScore)
	}
	if res.Factors.Exposure != "UNKNOWN" {
		t.Fatalf("expected Exposure UNKNOWN, got %s", res.Factors.Exposure)
	}
	if strings.Contains(res.AdjustmentReason, "сетевой доступ из внешней сети отсутствует") {
		t.Fatalf("unknown exposure was reported as no external exposure: %q", res.AdjustmentReason)
	}
	if res.Status != domain.RiskStatusAssessed {
		t.Fatalf("expected RiskStatusAssessed, got %s", res.Status)
	}
}

// TestRiskFailedOutcomeIsNotDismissed pins the failure/negative distinction: an
// assessment that earned no verdict carries no safe or dismissed disposition.
func TestRiskFailedOutcomeIsNotDismissed(t *testing.T) {
	v := domain.Vulnerability{ID: "CVE-2026-1008", BaseSeverity: "CRITICAL", BaseScore: 9.8}
	res := Assess(v, &domain.AnalysisCase{}, domain.VerdictResult{})
	if res.Priority != domain.PriorityP0 {
		t.Fatalf("expected the nominal PriorityP0, got %s", res.Priority)
	}
	if res.Status != domain.RiskStatusUnassessed {
		t.Fatalf("expected RiskStatusUnassessed, got %s", res.Status)
	}
	if res.ContextualLevel != domain.RiskLevelUnknown {
		t.Fatalf("expected RiskLevelUnknown, got %s", res.ContextualLevel)
	}
	if res.Priority == domain.PriorityDismissed {
		t.Fatal("a failed outcome was dismissed")
	}
}

func TestAssess_Inconclusive_CriticalBase_P1Provisional(t *testing.T) {
	v := domain.Vulnerability{
		ID:           "CVE-2026-1006",
		BaseSeverity: "CRITICAL",
		BaseScore:    10.0,
	}
	c := &domain.AnalysisCase{}
	vr := domain.VerdictResult{
		Verdict: domain.VerdictInconclusive,
		Reason:  "condition unresolved",
	}

	res := Assess(v, c, vr)
	if res.Priority != domain.PriorityP1 {
		t.Fatalf("expected PriorityP1, got %s", res.Priority)
	}
	if res.ContextualLevel != domain.RiskLevelCritical {
		t.Fatalf("expected RiskLevelCritical, got %s", res.ContextualLevel)
	}
	if res.Status != domain.RiskStatusProvisional {
		t.Fatalf("expected RiskStatusProvisional, got %s", res.Status)
	}
	if res.SLA != "Manual Triage" {
		t.Fatalf("expected Manual Triage SLA, got %q", res.SLA)
	}
}

func TestAssess_Inconclusive_MediumBase_P2(t *testing.T) {
	v := domain.Vulnerability{
		ID:           "CVE-2026-1007",
		BaseSeverity: "MEDIUM",
		BaseScore:    5.0,
	}
	c := &domain.AnalysisCase{}
	vr := domain.VerdictResult{
		Verdict: domain.VerdictInconclusive,
		Reason:  "condition unresolved",
	}

	res := Assess(v, c, vr)
	if res.Priority != domain.PriorityP2 {
		t.Fatalf("expected PriorityP2, got %s", res.Priority)
	}
	if res.ContextualLevel != domain.RiskLevelMedium {
		t.Fatalf("expected RiskLevelMedium, got %s", res.ContextualLevel)
	}
	if res.SLA != "Manual Triage" {
		t.Fatalf("expected Manual Triage SLA, got %q", res.SLA)
	}
}

func TestAssess_Defaults(t *testing.T) {
	// BaseSeverity only
	v1 := domain.Vulnerability{
		ID:           "CVE-2026-1008",
		BaseSeverity: "HIGH",
	}
	c := &domain.AnalysisCase{}
	vr := domain.VerdictResult{
		Verdict: domain.VerdictInconclusive,
	}
	res1 := Assess(v1, c, vr)
	if res1.BaseScore != 7.5 {
		t.Fatalf("expected 7.5 default base score, got %v", res1.BaseScore)
	}

	// BaseScore only
	v2 := domain.Vulnerability{
		ID:        "CVE-2026-1009",
		BaseScore: 9.8,
	}
	res2 := Assess(v2, c, vr)
	if res2.BaseSeverity != "CRITICAL" {
		t.Fatalf("expected CRITICAL default base severity, got %v", res2.BaseSeverity)
	}
}

// A library-shaped EXPLOITABLE verdict has no deployment perimeter of its
// own: the absence of listeners describes code that was never a server, so
// it must not downgrade the score the way an unreachable internal service is.
func TestAssessLibraryScopeKeepsBaselinePriority(t *testing.T) {
	v := domain.Vulnerability{BaseSeverity: "HIGH", BaseScore: 7.5}
	c := &domain.AnalysisCase{
		Vulnerability: v,
		Product: domain.ProductSnapshot{
			Shape: &domain.ProductShape{Kind: domain.ProductShapeLibrary, CensusComplete: true},
		},
	}
	vr := domain.VerdictResult{
		Verdict:             domain.VerdictExploitable,
		ExploitabilityScope: domain.ScopeLibraryAPI,
	}
	got := Assess(v, c, vr)
	if got.Priority != domain.PriorityP1 {
		t.Fatalf("library-scope EXPLOITABLE priority=%s, want P1 (baseline for HIGH)", got.Priority)
	}
	base := Assess(v, &domain.AnalysisCase{Vulnerability: v}, vr)
	if got.Priority != base.Priority || got.ContextualScore != base.ContextualScore {
		t.Fatalf("library scope changed the assessment: got %s/%v, plain scope %s/%v",
			got.Priority, got.ContextualScore, base.Priority, base.ContextualScore)
	}
	if !strings.Contains(got.AdjustmentReason, "библиотек") {
		t.Fatalf("reason must name the library boundary: %s", got.AdjustmentReason)
	}
}

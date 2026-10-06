package risk

import (
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
	if res.TriageDisposition != domain.TriageDismissed {
		t.Fatalf("expected TriageDismissed, got %s", res.TriageDisposition)
	}
	if res.BasePriority != domain.PriorityP0 {
		t.Fatalf("expected BasePriority P0, got %s", res.BasePriority)
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
	if res.TriageDisposition != domain.TriageDismissed {
		t.Fatalf("expected TriageDismissed, got %s", res.TriageDisposition)
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
	if res.TriageDisposition != domain.TriageUnchanged {
		t.Fatalf("expected TriageUnchanged, got %s", res.TriageDisposition)
	}
	if res.BasePriority != domain.PriorityP0 {
		t.Fatalf("expected BasePriority P0, got %s", res.BasePriority)
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
	if res.TriageDisposition != domain.TriageUnchanged {
		t.Fatalf("expected TriageUnchanged, got %s", res.TriageDisposition)
	}
	if res.BasePriority != domain.PriorityP2 {
		t.Fatalf("expected BasePriority P2, got %s", res.BasePriority)
	}
}

// Auth wiring is informational: middleware matched by name/position does not
// prove per-route coverage, so it must not lower the priority.
func TestAssess_Exploitable_PublicAuth_NotLowered(t *testing.T) {
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
	if res.Priority != domain.PriorityP0 {
		t.Fatalf("expected PriorityP0, got %s (auth wiring must not lower priority)", res.Priority)
	}
	if res.ContextualLevel != domain.RiskLevelCritical {
		t.Fatalf("expected RiskLevelCritical, got %s", res.ContextualLevel)
	}
	if res.ContextualScore != 10.0 {
		t.Fatalf("expected score 10.0, got %v", res.ContextualScore)
	}
	if res.TriageDisposition != domain.TriageUnchanged {
		t.Fatalf("expected TriageUnchanged, got %s", res.TriageDisposition)
	}
	if res.Factors.Authentication != "REQUIRED" {
		t.Fatalf("expected Authentication REQUIRED observed wiring, got %s", res.Factors.Authentication)
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
	if res.TriageDisposition != domain.TriageLowered {
		t.Fatalf("expected TriageLowered, got %s", res.TriageDisposition)
	}
	if res.BasePriority != domain.PriorityP0 {
		t.Fatalf("expected BasePriority P0, got %s", res.BasePriority)
	}
}

// No resolved listener fact is not proof of safety: the baseline is kept.
func TestAssess_Exploitable_NoListeners_BaselineKept(t *testing.T) {
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
		t.Fatalf("expected baseline PriorityP0, got %s", res.Priority)
	}
	if res.ContextualLevel != domain.RiskLevelCritical {
		t.Fatalf("expected RiskLevelCritical, got %s", res.ContextualLevel)
	}
	if res.ContextualScore != 10.0 {
		t.Fatalf("expected score 10.0, got %v", res.ContextualScore)
	}
	if res.Factors.Exposure != "NONE" {
		t.Fatalf("expected Exposure NONE, got %s", res.Factors.Exposure)
	}
	if res.TriageDisposition != domain.TriageUnchanged {
		t.Fatalf("expected TriageUnchanged, got %s", res.TriageDisposition)
	}
}

func TestAssess_Inconclusive_CriticalBase_BaselineRetained(t *testing.T) {
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
	if res.Priority != domain.PriorityP0 {
		t.Fatalf("expected baseline PriorityP0, got %s", res.Priority)
	}
	if res.BasePriority != domain.PriorityP0 {
		t.Fatalf("expected BasePriority P0, got %s", res.BasePriority)
	}
	if res.ContextualLevel != domain.RiskLevelCritical {
		t.Fatalf("expected RiskLevelCritical, got %s", res.ContextualLevel)
	}
	if res.ContextualScore != 10.0 {
		t.Fatalf("expected score 10.0, got %v", res.ContextualScore)
	}
	if res.Status != domain.RiskStatusProvisional {
		t.Fatalf("expected RiskStatusProvisional, got %s", res.Status)
	}
	if res.SLA != "Manual Triage" {
		t.Fatalf("expected Manual Triage SLA, got %q", res.SLA)
	}
	if res.TriageDisposition != domain.TriageInconclusive {
		t.Fatalf("expected TriageInconclusive, got %s", res.TriageDisposition)
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
	if res.TriageDisposition != domain.TriageInconclusive {
		t.Fatalf("expected TriageInconclusive, got %s", res.TriageDisposition)
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
	if res1.BasePriority != domain.PriorityP1 {
		t.Fatalf("expected BasePriority P1, got %s", res1.BasePriority)
	}
	if res1.ContextualLevel != domain.RiskLevelHigh {
		t.Fatalf("expected RiskLevelHigh, got %s", res1.ContextualLevel)
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
	if res2.TriageDisposition != domain.TriageInconclusive {
		t.Fatalf("expected TriageInconclusive, got %s", res2.TriageDisposition)
	}

	// Unknown verdict: baseline priority/level/score, no close, no lowering.
	v3 := domain.Vulnerability{
		ID:           "CVE-2026-1010",
		BaseSeverity: "CRITICAL",
		BaseScore:    10.0,
	}
	c3 := &domain.AnalysisCase{
		EvidenceGraph: domain.EvidenceGraph{
			Exposures: []domain.ExposureFact{
				{Direction: "inbound", Kind: "listener", Address: "127.0.0.1:1", Scope: domain.ScopeLoopback},
			},
		},
	}
	res3 := Assess(v3, c3, domain.VerdictResult{Verdict: "BOGUS"})
	if res3.Priority != domain.PriorityP0 || res3.ContextualLevel != domain.RiskLevelCritical || res3.ContextualScore != 10.0 {
		t.Fatalf("unknown verdict changed baseline: %s/%s/%v", res3.Priority, res3.ContextualLevel, res3.ContextualScore)
	}
	if res3.TriageDisposition != domain.TriageInconclusive {
		t.Fatalf("expected TriageInconclusive, got %s", res3.TriageDisposition)
	}
	if res3.Status != domain.RiskStatusProvisional {
		t.Fatalf("expected RiskStatusProvisional, got %s", res3.Status)
	}
}

// TestAssess_TriageMonotonicity is a property test over the full input grid:
// contextual triage can never produce a more urgent priority, a more severe
// level or a higher score than the advisory baseline. Ranks are computed by
// independent maps in this file — not by the production clamp helpers.
func TestAssess_TriageMonotonicity(t *testing.T) {
	severities := []string{"", "CRITICAL", "HIGH", "MEDIUM", "MODERATE", "LOW", "BLOCKER", "UNKNOWN", "NONE"}
	scores := []float64{0, 3.0, 4.0, 5.0, 7.5, 9.8, 10.0}
	verdicts := []domain.Verdict{
		domain.VerdictNotAffected,
		domain.VerdictNoExploitPathFound,
		domain.VerdictExploitable,
		domain.VerdictInconclusive,
		"",
		"BOGUS",
	}
	exposures := []struct {
		name string
		c    *domain.AnalysisCase
	}{
		{"nil-case", nil},
		{"empty-case", &domain.AnalysisCase{}},
		{"public", caseWithExposure(domain.ExposureFact{Direction: "inbound", Kind: "listener", Address: "0.0.0.0:8080", Scope: domain.ScopeAllInterfaces})},
		{"loopback", caseWithExposure(domain.ExposureFact{Direction: "inbound", Kind: "listener", Address: "127.0.0.1:9", Scope: domain.ScopeLoopback})},
		{"unix", caseWithExposure(domain.ExposureFact{Direction: "inbound", Kind: "listener", Address: "/run/app.sock", Scope: domain.ScopeUnix})},
		{"loopback+public", caseWithExposure(
			domain.ExposureFact{Direction: "inbound", Kind: "listener", Address: "127.0.0.1:9", Scope: domain.ScopeLoopback},
			domain.ExposureFact{Direction: "inbound", Kind: "listener", Address: "0.0.0.0:80", Scope: domain.ScopeAllInterfaces},
		)},
		{"loopback+unresolved", caseWithExposure(
			domain.ExposureFact{Direction: "inbound", Kind: "listener", Address: "127.0.0.1:9", Scope: domain.ScopeLoopback},
			domain.ExposureFact{Direction: "inbound", Kind: "listener", Address: "env:PORT"},
		)},
		{"loopback+cluster-internal", caseWithExposure(
			domain.ExposureFact{Direction: "inbound", Kind: "listener", Address: "127.0.0.1:9", Scope: domain.ScopeLoopback},
			domain.ExposureFact{Direction: "inbound", Kind: "listener", Address: "10.0.0.1:80", Scope: domain.ScopeClusterInternal},
		)},
		{"host-specific", caseWithExposure(domain.ExposureFact{Direction: "inbound", Kind: "listener", Address: "10.1.2.3:80", Scope: domain.ScopeHostSpecific})},
		{"loopback-prose-only", &domain.AnalysisCase{EvidenceGraph: domain.EvidenceGraph{
			Evidence: []domain.Evidence{{Kind: domain.EvidenceEntrypoint, Source: "listener probe", Content: "listen on 127.0.0.1 loopback"}},
		}}},
		{"public-prose", &domain.AnalysisCase{EvidenceGraph: domain.EvidenceGraph{
			Evidence: []domain.Evidence{{Kind: domain.EvidenceEntrypoint, Source: "exposure scan", Content: "bound to 0.0.0.0"}},
		}}},
	}

	for _, sev := range severities {
		for _, score := range scores {
			for _, verdict := range verdicts {
				for _, exp := range exposures {
					v := domain.Vulnerability{ID: "T", BaseSeverity: sev, BaseScore: score}
					res := Assess(v, exp.c, domain.VerdictResult{Verdict: verdict})

					baseRank, okBase := rankPriorityIndep(res.BasePriority)
					effRank, okEff := rankPriorityIndep(res.Priority)
					if !okBase || !okEff {
						t.Fatalf("%s/%v/%s:%s: unranked priority base=%q eff=%q", sev, score, verdict, exp.name, res.BasePriority, res.Priority)
					}
					if effRank < baseRank {
						t.Fatalf("%s/%v/%s:%s: effective priority %s more urgent than base %s", sev, score, verdict, exp.name, res.Priority, res.BasePriority)
					}
					if baseRank != nominalRankIndep(res.BaseSeverity, res.BaseScore) {
						t.Fatalf("%s/%v/%s:%s: BasePriority %s does not match advisory baseline", sev, score, verdict, exp.name, res.BasePriority)
					}

					baseLevel := baselineLevelIndep(res.BaseSeverity, res.BaseScore)
					if levelRankIndep(res.ContextualLevel) > levelRankIndep(baseLevel) {
						t.Fatalf("%s/%v/%s:%s: level %s more severe than baseline %s", sev, score, verdict, exp.name, res.ContextualLevel, baseLevel)
					}
					if res.ContextualScore > res.BaseScore+1e-9 {
						t.Fatalf("%s/%v/%s:%s: score %v above base %v", sev, score, verdict, exp.name, res.ContextualScore, res.BaseScore)
					}
					switch res.TriageDisposition {
					case domain.TriageUnchanged, domain.TriageLowered, domain.TriageDismissed, domain.TriageInconclusive:
					default:
						t.Fatalf("%s/%v/%s:%s: invalid disposition %q", sev, score, verdict, exp.name, res.TriageDisposition)
					}
					if verdict == domain.VerdictExploitable && res.TriageDisposition == domain.TriageDismissed {
						t.Fatalf("%s/%v/%s:%s: EXPLOITABLE must never be DISMISSED", sev, score, verdict, exp.name)
					}
					if verdict != domain.VerdictExploitable && verdict != domain.VerdictNotAffected && verdict != domain.VerdictNoExploitPathFound && verdict != domain.VerdictInconclusive {
						if res.Priority != res.BasePriority || res.ContextualScore != res.BaseScore {
							t.Fatalf("%s/%v/%s:%s: unknown verdict changed baseline", sev, score, verdict, exp.name)
						}
					}
				}
			}
		}
	}
}

func TestClampPriority(t *testing.T) {
	cases := []struct {
		candidate, base, want domain.TriagePriority
	}{
		{domain.PriorityP0, domain.PriorityP2, domain.PriorityP2}, // more urgent → base
		{domain.PriorityP1, domain.PriorityP2, domain.PriorityP2},
		{domain.PriorityP2, domain.PriorityP2, domain.PriorityP2},
		{domain.PriorityP3, domain.PriorityP2, domain.PriorityP3}, // less urgent → kept
		{domain.PriorityDismissed, domain.PriorityP0, domain.PriorityDismissed},
		{"P9", domain.PriorityP1, domain.PriorityP1}, // invalid candidate → base
		{"", domain.PriorityP1, domain.PriorityP1},
		{domain.PriorityP1, "BOGUS", "BOGUS"}, // invalid base → base
		{domain.PriorityP1, "", ""},
		{domain.PriorityP0, domain.PriorityDismissed, domain.PriorityDismissed},
	}
	for _, tc := range cases {
		if got := clampPriority(tc.candidate, tc.base); got != tc.want {
			t.Errorf("clampPriority(%q, %q) = %q, want %q", tc.candidate, tc.base, got, tc.want)
		}
	}
}

func TestClampSeverity(t *testing.T) {
	cases := []struct {
		candidate, base, want domain.RiskLevel
	}{
		{domain.RiskLevelCritical, domain.RiskLevelMedium, domain.RiskLevelMedium}, // more severe → base
		{domain.RiskLevelHigh, domain.RiskLevelMedium, domain.RiskLevelMedium},
		{domain.RiskLevelMedium, domain.RiskLevelMedium, domain.RiskLevelMedium},
		{domain.RiskLevelLow, domain.RiskLevelMedium, domain.RiskLevelLow}, // less severe → kept
		{domain.RiskLevelNone, domain.RiskLevelCritical, domain.RiskLevelNone},
		// Aliases resolve to canonical levels.
		{domain.RiskLevel("BLOCKER"), domain.RiskLevelHigh, domain.RiskLevelHigh},
		{domain.RiskLevel("BLOCKER"), domain.RiskLevelCritical, domain.RiskLevel("BLOCKER")},
		{domain.RiskLevel("MODERATE"), domain.RiskLevelMedium, domain.RiskLevel("MODERATE")},
		// UNKNOWN is unranked — never treated as CRITICAL and never overrides base.
		{domain.RiskLevelUnknown, domain.RiskLevelNone, domain.RiskLevelNone},
		{domain.RiskLevel("BOGUS"), domain.RiskLevelLow, domain.RiskLevelLow},
		// Invalid base is returned unchanged.
		{domain.RiskLevelLow, domain.RiskLevelUnknown, domain.RiskLevelUnknown},
		// Dismissal candidate stays NONE under a critical baseline.
		{domain.RiskLevelNone, domain.RiskLevelCritical, domain.RiskLevelNone},
	}
	for _, tc := range cases {
		if got := clampSeverity(tc.candidate, tc.base); got != tc.want {
			t.Errorf("clampSeverity(%q, %q) = %q, want %q", tc.candidate, tc.base, got, tc.want)
		}
	}
}

func TestDowngradePrioritySaturates(t *testing.T) {
	cases := []struct {
		in, want domain.TriagePriority
	}{
		{domain.PriorityP0, domain.PriorityP1},
		{domain.PriorityP1, domain.PriorityP2},
		{domain.PriorityP2, domain.PriorityP3},
		{domain.PriorityP3, domain.PriorityP3},               // saturates
		{domain.PriorityDismissed, domain.PriorityDismissed}, // stays dismissed
		{"P9", "P9"}, // invalid → unchanged, never DISMISSED
		{"", ""},
		{"BOGUS", "BOGUS"},
	}
	for _, tc := range cases {
		if got := DowngradePriority(tc.in); got != tc.want {
			t.Errorf("DowngradePriority(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// One loopback listener among other inbound surfaces is not isolation; the
// same holds when the only extra surface is a cluster-internal listener that
// no structural fact proves unreachable.
func TestAssess_InternalRequiresResolvedCoverage(t *testing.T) {
	v := domain.Vulnerability{ID: "T", BaseSeverity: "CRITICAL", BaseScore: 10.0}
	vr := domain.VerdictResult{Verdict: domain.VerdictExploitable}

	cases := []struct {
		name  string
		facts []domain.ExposureFact
	}{
		{"loopback+public", []domain.ExposureFact{
			{Direction: "inbound", Kind: "listener", Address: "127.0.0.1:9", Scope: domain.ScopeLoopback},
			{Direction: "inbound", Kind: "listener", Address: "0.0.0.0:80", Scope: domain.ScopeAllInterfaces},
		}},
		{"loopback+unresolved", []domain.ExposureFact{
			{Direction: "inbound", Kind: "listener", Address: "127.0.0.1:9", Scope: domain.ScopeLoopback},
			{Direction: "inbound", Kind: "listener", Address: "env:PORT"},
		}},
		{"loopback+cluster-internal", []domain.ExposureFact{
			{Direction: "inbound", Kind: "listener", Address: "127.0.0.1:9", Scope: domain.ScopeLoopback},
			{Direction: "inbound", Kind: "listener", Address: "10.0.0.1:80", Scope: domain.ScopeClusterInternal},
		}},
		{"loopback+loopback-prose", []domain.ExposureFact{
			{Direction: "inbound", Kind: "listener", Address: "127.0.0.1:9", Scope: domain.ScopeLoopback},
			{Direction: "inbound", Kind: "listener", Address: "127.0.0.1:10"},
		}},
	}
	for _, tc := range cases {
		res := Assess(v, caseWithExposure(tc.facts...), vr)
		if res.Factors.Exposure != "PUBLIC" && res.Factors.Exposure != "NONE" {
			t.Fatalf("%s: expected non-INTERNAL exposure, got %s", tc.name, res.Factors.Exposure)
		}
		if res.Priority != domain.PriorityP0 || res.ContextualScore != 10.0 {
			t.Fatalf("%s: baseline must be kept, got %s/%v", tc.name, res.Priority, res.ContextualScore)
		}
		if res.TriageDisposition == domain.TriageLowered {
			t.Fatalf("%s: must not report lowering without proven isolation", tc.name)
		}
	}

	// A lone loopback listener is the only shape that lowers.
	res := Assess(v, caseWithExposure(domain.ExposureFact{
		Direction: "inbound", Kind: "listener", Address: "127.0.0.1:9", Scope: domain.ScopeLoopback,
	}), vr)
	if res.Factors.Exposure != "INTERNAL" || res.TriageDisposition != domain.TriageLowered || res.Priority != domain.PriorityP2 {
		t.Fatalf("lone loopback listener must lower to P2/LOWERED, got %s/%s/%s", res.Factors.Exposure, res.Priority, res.TriageDisposition)
	}
}

// Observed auth wiring is reflected in Factors but is not a proven mitigating
// control: it must never lower the priority.
func TestAssess_AuthWiringDoesNotProveMitigation(t *testing.T) {
	v := domain.Vulnerability{ID: "T", BaseSeverity: "HIGH", BaseScore: 8.0}
	vr := domain.VerdictResult{Verdict: domain.VerdictExploitable}

	cases := []*domain.AnalysisCase{
		// auth-middleware fact next to a public listener
		{
			EvidenceGraph: domain.EvidenceGraph{Exposures: []domain.ExposureFact{
				{Direction: "inbound", Kind: "listener", Address: "0.0.0.0:80", Scope: domain.ScopeAllInterfaces},
				{Direction: "inbound", Kind: "auth-middleware", Target: "authMw"},
			}},
		},
		// auth-named claim verified TRUE
		{
			EvidenceGraph: domain.EvidenceGraph{Exposures: []domain.ExposureFact{
				{Direction: "inbound", Kind: "listener", Address: "0.0.0.0:80", Scope: domain.ScopeAllInterfaces},
			}},
			Claims: []domain.Claim{{ConditionID: "C-AUTH", Result: domain.ClaimTrue}},
		},
		// free-text "auth middleware" prose
		{
			EvidenceGraph: domain.EvidenceGraph{
				Exposures: []domain.ExposureFact{
					{Direction: "inbound", Kind: "listener", Address: "0.0.0.0:80", Scope: domain.ScopeAllInterfaces},
				},
				Evidence: []domain.Evidence{{Kind: domain.EvidenceEntrypoint, Source: "authwire", Content: "auth middleware wraps the handler"}},
			},
		},
	}
	for i, c := range cases {
		res := Assess(v, c, vr)
		if res.Priority != domain.PriorityP1 || res.ContextualScore != 8.0 {
			t.Fatalf("case %d: auth wiring lowered priority: %s/%v", i, res.Priority, res.ContextualScore)
		}
		if res.TriageDisposition != domain.TriageUnchanged {
			t.Fatalf("case %d: expected TriageUnchanged, got %s", i, res.TriageDisposition)
		}
	}
}

// Provenance travels from the advisory input to the triage result.
func TestAssess_SeverityProvenance(t *testing.T) {
	v := domain.Vulnerability{
		ID:             "CVE-2026-2000",
		BaseSeverity:   "HIGH",
		BaseScore:      8.0,
		SeveritySource: "OSV",
		ScoreSource:    "OSV",
	}
	res := Assess(v, &domain.AnalysisCase{}, domain.VerdictResult{Verdict: domain.VerdictInconclusive})
	if res.SeveritySource != "OSV" || res.ScoreSource != "OSV" {
		t.Fatalf("expected OSV provenance, got %q/%q", res.SeveritySource, res.ScoreSource)
	}

	blank := Assess(domain.Vulnerability{ID: "T", BaseSeverity: "HIGH", BaseScore: 8.0},
		&domain.AnalysisCase{}, domain.VerdictResult{Verdict: domain.VerdictInconclusive})
	if blank.SeveritySource != "" || blank.ScoreSource != "" {
		t.Fatalf("unknown provenance must stay empty, got %q/%q", blank.SeveritySource, blank.ScoreSource)
	}
}

func caseWithExposure(facts ...domain.ExposureFact) *domain.AnalysisCase {
	c := &domain.AnalysisCase{}
	for _, f := range facts {
		c.EvidenceGraph.Exposures = append(c.EvidenceGraph.Exposures, f)
	}
	return c
}

// Independent rank maps for the monotonicity property — intentionally not
// reusing the production clamp helpers.
func rankPriorityIndep(p domain.TriagePriority) (int, bool) {
	switch p {
	case domain.PriorityP0:
		return 0, true
	case domain.PriorityP1:
		return 1, true
	case domain.PriorityP2:
		return 2, true
	case domain.PriorityP3:
		return 3, true
	case domain.PriorityDismissed:
		return 4, true
	default:
		return 0, false
	}
}

func levelRankIndep(l domain.RiskLevel) int {
	switch string(l) {
	case "NONE":
		return 0
	case "LOW":
		return 1
	case "MEDIUM":
		return 2
	case "HIGH":
		return 3
	case "CRITICAL":
		return 4
	default:
		return -1
	}
}

func nominalRankIndep(severity string, score float64) int {
	sevRank := -1 // unknown severity contributes nothing
	switch severity {
	case "CRITICAL", "BLOCKER":
		sevRank = 0
	case "HIGH":
		sevRank = 1
	case "MEDIUM", "MODERATE":
		sevRank = 2
	case "LOW":
		sevRank = 3
	}
	scoreRank := 2
	switch {
	case score >= 9.0:
		scoreRank = 0
	case score >= 7.0:
		scoreRank = 1
	case score >= 4.0:
		scoreRank = 2
	case score > 0:
		scoreRank = 3
	}
	if sevRank >= 0 && sevRank < scoreRank {
		return sevRank
	}
	return scoreRank
}

func baselineLevelIndep(severity string, score float64) domain.RiskLevel {
	switch severity {
	case "CRITICAL", "BLOCKER":
		return domain.RiskLevelCritical
	case "HIGH":
		return domain.RiskLevelHigh
	case "MEDIUM", "MODERATE":
		return domain.RiskLevelMedium
	case "LOW":
		return domain.RiskLevelLow
	case "NONE":
		return domain.RiskLevelNone
	}
	switch {
	case score >= 9.0:
		return domain.RiskLevelCritical
	case score >= 7.0:
		return domain.RiskLevelHigh
	case score >= 4.0:
		return domain.RiskLevelMedium
	case score > 0:
		return domain.RiskLevelLow
	default:
		return domain.RiskLevelNone
	}
}
